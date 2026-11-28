//! Configuration validation, live baseline/port inspection, gateway export, and hot-reload tests.

use catcloud_core::config;
use catcloud_core::core_adapter::config_compiler::{
    CompileInput, GatewayExportProfile, compile_mihomo_config_with_runtime_dir,
    validate_compiled_yaml,
};
use catcloud_core::core_adapter::port_guard::AllocatedPorts;
use catcloud_core::core_adapter::ResolvedControllerEndpoint;
use catcloud_core::models::{
    AppConfig, PreAccelDispatchStrategy, PreAccelRelay, ProxyNode, SubscriptionKind,
    SubscriptionRecord, TunStackMode,
};
use catcloud_core::platform::{default_platform, get_process_start_time_unix};
use catcloud_core::AppPaths;
use chrono::Utc;
use serde_json::json;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use crate::commands::{Commands, ConfigCommand, PreaccelCommand, ReloadArgs, dispatch};
use crate::commands::config_reload::{
    ActiveCorePortState, build_config_validate_payload, build_live_baseline_config_from_runtime,
    execute_config_export_gateway, execute_config_reload, parse_gateway_export_profile,
    resolve_compile_and_preview_ports, run_config_reload_inner,
    run_config_reload_with_desktop_handoff,
};
use crate::commands::preaccel::read_tun_mtu_from_runtime_yaml;
use crate::commands::redact_helpers::open_storage;

#[tokio::test]
async fn issue2_config_reload_preserves_live_tun_and_rejects_l3_restart_with_real_baseline() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Reserve clean ports for mixed and dns so test never collides with host listeners.
    let tmp_mixed = std::net::TcpListener::bind("127.0.0.1:0").expect("mixed port");
    let mixed_port = tmp_mixed.local_addr().unwrap().port();
    drop(tmp_mixed);
    let tmp_dns = std::net::TcpListener::bind("127.0.0.1:0").expect("dns port");
    let dns_port = tmp_dns.local_addr().unwrap().port();
    drop(tmp_dns);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock controller");
    let mock_port = listener.local_addr().unwrap().port();
    let put_reload_count = Arc::new(AtomicUsize::new(0));
    let put_counter_srv = Arc::clone(&put_reload_count);

    let server_task = tokio::spawn(async move {
        for _ in 0..32 {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let mut req_buf = [0u8; 4096];
            let n = stream.read(&mut req_buf).await.unwrap_or(0);
            let req_str = String::from_utf8_lossy(&req_buf[..n]);
            let has_auth = req_str
                .to_ascii_lowercase()
                .contains("authorization: bearer test-issue2-secret");
            let (status_line, body) = if !has_auth {
                ("HTTP/1.1 401 Unauthorized", r#"{"message":"Unauthorized"}"#.to_string())
            } else if req_str.starts_with("GET /version ") {
                ("HTTP/1.1 200 OK", r#"{"version":"v1.19.1"}"#.to_string())
            } else if req_str.starts_with("GET /configs ") {
                (
                    "HTTP/1.1 200 OK",
                    format!(
                        r#"{{"tun":{{"enable":true}},"mixed-port":{},"port":0,"socks-port":0,"bind-address":"127.0.0.1","allow-lan":false,"mode":"rule"}}"#,
                        mixed_port
                    ),
                )
            } else if req_str.starts_with("PUT /configs") {
                put_counter_srv.fetch_add(1, Ordering::SeqCst);
                ("HTTP/1.1 204 No Content", String::new())
            } else if req_str.starts_with("PUT /proxies/") {
                ("HTTP/1.1 204 No Content", String::new())
            } else {
                ("HTTP/1.1 200 OK", r#"{}"#.to_string())
            };
            let resp = format!(
                "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes()).await;
        }
    });

    let temp_root = std::env::temp_dir().join(format!(
        "catcloud-cli-issue2-reload-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");

    let mut cfg = config::load_or_init(&paths).expect("init config");
    cfg.mixed_port = mixed_port;
    cfg.controller_port = mock_port;
    cfg.dns_listen_port = dns_port;
    cfg.controller_secret = Some("test-issue2-secret".to_string());
    cfg.tun.enabled = true;
    cfg.allow_lan = false;
    cfg.bind_address = "127.0.0.1".to_string();
    config::save(&paths, &cfg).expect("save config");

    let db = open_storage(&paths).expect("open db");
    db.upsert_subscription(&SubscriptionRecord {
        id: "sub-issue2".to_string(),
        name: "Issue2 Sub".to_string(),
        kind: SubscriptionKind::File,
        url_or_cmd: "issue2.yaml".to_string(),
        ..Default::default()
    })
    .unwrap();
    db.upsert_node(&ProxyNode {
        id: "n-issue2-1".to_string(),
        sub_id: "sub-issue2".to_string(),
        name: "JP-Issue2".to_string(),
        protocol: "trojan".to_string(),
        server: "203.0.113.10".to_string(),
        port: 443,
        enabled: true,
        raw_config: json!({
            "name": "JP-Issue2",
            "type": "trojan",
            "server": "203.0.113.10",
            "port": 443,
            "password": "demo-trojan-password"
        }),
        ..ProxyNode::default()
    })
    .unwrap();
    drop(db);

    // Seed realistic on-disk `run/runtime.yaml` reflecting the running elevated core.
    let initial_yaml = format!(
        "mixed-port: {mixed_port}\n\
             allow-lan: false\n\
             bind-address: 127.0.0.1\n\
             mode: rule\n\
             log-level: info\n\
             external-controller: 127.0.0.1:{mock_port}\n\
             secret: test-issue2-secret\n\
             dns:\n\
               enable: true\n\
               listen: 127.0.0.1:{dns_port}\n\
               ipv6: false\n\
             tun:\n\
               enable: true\n\
               stack: mixed\n\
               device: CatCloud\n\
               mtu: 1500\n\
               auto-route: true\n\
               auto-detect-interface: true\n\
               strict-route: true\n"
    );
    let runtime_yaml_path = paths.runtime_dir.join("runtime.yaml");
    std::fs::write(&runtime_yaml_path, &initial_yaml).unwrap();

    let mut unpriv_caps = default_platform().capabilities();
    unpriv_caps.is_elevated = false;

    // 1. Dry-run from unprivileged CLI must recognize live elevated TUN and keep allow_tun=true.
    let (dry_ok, dry_out, _) =
        run_config_reload_inner(&paths, true, Some(unpriv_caps.clone()), false)
            .await
            .expect("dry run");
    assert!(dry_ok, "dry run failed: {dry_out}");
    assert_eq!(dry_out["trusted_controller_endpoint"], json!(true));
    assert_eq!(dry_out["live_tun_enabled"], json!(true));
    assert_eq!(dry_out["allow_tun"], json!(true));
    assert_eq!(dry_out["tun_preserved_via_live_core"], json!(true));
    assert_eq!(dry_out["requires_l3_restart"], json!(false));

    // 2. Real L2 hot reload from unprivileged CLI must preserve `tun.enable: true` in runtime.yaml!
    let (reload_ok, reload_out, _) =
        run_config_reload_inner(&paths, false, Some(unpriv_caps.clone()), false)
            .await
            .expect("l2 reload");
    assert!(reload_ok, "l2 reload failed: {reload_out}");
    assert_eq!(reload_out["allow_tun"], json!(true));
    assert_eq!(reload_out["hot_reloaded"], json!(true));
    assert_eq!(put_reload_count.load(Ordering::SeqCst), 1);
    let updated_yaml = std::fs::read_to_string(&runtime_yaml_path).unwrap();
    assert!(
        updated_yaml.contains("tun:") && updated_yaml.contains("enable: true"),
        "L2 hot reload from unprivileged CLI must never silently disable live TUN"
    );

    // 3. Mutate an L3 field (`mixed_port`): dry-run must report `l3_core_restart`, and
    //    real reload must be hard-rejected without touching runtime.yaml or calling PUT /configs.
    let mut next_mixed = if mixed_port < 65000 {
        mixed_port + 1
    } else {
        mixed_port - 1
    };
    while next_mixed == mixed_port
        || next_mixed == cfg.controller_port
        || next_mixed == cfg.dns_listen_port
    {
        next_mixed = if next_mixed < 65000 {
            next_mixed + 1
        } else {
            20000
        };
    }
    cfg.mixed_port = next_mixed;
    config::save(&paths, &cfg).expect("save l3 port change");

    let (l3_dry_ok, l3_dry_out, _) =
        run_config_reload_inner(&paths, true, Some(unpriv_caps.clone()), false)
            .await
            .expect("l3 dry run");
    assert!(l3_dry_ok);
    assert_eq!(l3_dry_out["level"], json!("l3_core_restart"));
    assert_eq!(l3_dry_out["requires_l3_restart"], json!(true));
    assert!(
        l3_dry_out["diff_reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r.as_str().unwrap_or("").contains("mixed_port"))
    );

    let yaml_before_l3_reject = std::fs::read_to_string(&runtime_yaml_path).unwrap();
    let (l3_ok, l3_out, _) =
        run_config_reload_inner(&paths, false, Some(unpriv_caps), false)
            .await
            .expect("l3 reject outcome");
    assert!(!l3_ok, "L3 change must be rejected when allow_l3_restart=false");
    assert_eq!(l3_out["level"], json!("l3_core_restart"));
    assert_eq!(l3_out["outcome"]["rejected"], json!(true));
    assert!(
        l3_out["error"]
            .as_str()
            .unwrap_or("")
            .contains("桌面端")
    );
    assert_eq!(
        put_reload_count.load(Ordering::SeqCst),
        1,
        "rejected L3 reload must never call PUT /configs?force=true"
    );
    assert_eq!(
        std::fs::read_to_string(&runtime_yaml_path).unwrap(),
        yaml_before_l3_reject,
        "rejected L3 reload must leave runtime.yaml untouched"
    );

    server_task.abort();
    let _ = std::fs::remove_dir_all(&temp_root);
}

#[tokio::test]
async fn config_validate_separates_active_core_ports_from_new_instance_preview_and_detects_third_party_conflict()
{
    use catcloud_core::core_adapter::ControllerEndpointSource;

    fn reserve_tcp_udp_port() -> (u16, std::net::TcpListener, std::net::UdpSocket) {
        for _ in 0..64 {
            let tcp = std::net::TcpListener::bind("127.0.0.1:0").expect("bind tcp");
            let port = tcp.local_addr().unwrap().port();
            if let Ok(udp) = std::net::UdpSocket::bind(format!("127.0.0.1:{port}")) {
                return (port, tcp, udp);
            }
        }
        panic!("failed to reserve ephemeral tcp+udp port");
    }

    let (busy_mixed, _t1, _u1) = reserve_tcp_udp_port();
    let (busy_ctrl, _t2, _u2) = reserve_tcp_udp_port();
    let (busy_dns, _t3, _u3) = reserve_tcp_udp_port();

    let mut cfg = AppConfig::default();
    cfg.mixed_port = busy_mixed;
    cfg.controller_port = busy_ctrl;
    cfg.dns_listen_port = busy_dns;
    cfg.port_guard_auto_shift = true;

    // 1. When all three ports are owned by the active CatCloud core, compilation MUST reuse
    //    the active ports without false shifting, while `new_instance_preview_ports` shifts cleanly.
    let active_owned_state = ActiveCorePortState {
        core_running: true,
        core_version: Some("v1.19.1".to_string()),
        controller_auth_error: None,
        endpoint: ResolvedControllerEndpoint {
            host: "127.0.0.1".to_string(),
            port: busy_ctrl,
            secret: "demo-secret".to_string(),
            mixed_port: Some(busy_mixed),
            dns_port: Some(busy_dns),
            pid: Some(std::process::id()),
            process_start_time_unix: get_process_start_time_unix(std::process::id()),
            binary_path: None,
            source: ControllerEndpointSource::LiveRuntimeMeta,
        },
        live_config: None,
        effective_mixed_port: busy_mixed,
        effective_controller_port: busy_ctrl,
        effective_dns_port: busy_dns,
        mixed_free: false,
        controller_free: false,
        dns_free: false,
        mixed_owned_by_active_core: true,
        controller_owned_by_active_core: true,
        dns_owned_by_active_core: true,
        owners: Vec::new(),
    };
    let (compile_ports, preview_opt, conflicts) =
        resolve_compile_and_preview_ports(&cfg, &active_owned_state)
            .expect("resolve active core ports");
    assert!(conflicts.is_empty());
    assert!(compile_ports.shifted.is_empty());
    assert_eq!(compile_ports.mixed_port, busy_mixed);
    assert_eq!(compile_ports.controller_port, busy_ctrl);
    assert_eq!(compile_ports.dns_port, busy_dns);

    let preview = preview_opt.expect("new_instance_preview_ports");
    assert_ne!(preview.mixed_port, busy_mixed);
    assert_ne!(preview.controller_port, busy_ctrl);
    assert_ne!(preview.dns_port, busy_dns);
    assert_eq!(preview.shifted.len(), 3);

    // 2. When no CatCloud core is running and a real third-party listener holds `busy_mixed`,
    //    `config validate` must detect the genuine conflict!
    let temp_root = std::env::temp_dir().join(format!(
        "catcloud-cli-validate-conflict-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");

    let mut cfg_conflict = config::load_or_init(&paths).expect("init config");
    cfg_conflict.mixed_port = busy_mixed;
    cfg_conflict.port_guard_auto_shift = false;
    config::save(&paths, &cfg_conflict).expect("save conflict cfg");

    let (ok_no_shift, out_no_shift, _) = build_config_validate_payload(&paths)
        .await
        .expect("validate conflict no shift");
    assert!(!ok_no_shift, "third-party conflict with auto_shift=false must fail validation");
    assert!(out_no_shift["active_core_ports"].is_null());
    assert!(
        out_no_shift["third_party_port_conflicts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["port"] == json!(busy_mixed))
    );

    cfg_conflict.port_guard_auto_shift = true;
    config::save(&paths, &cfg_conflict).expect("save auto_shift cfg");
    let (ok_shift, out_shift, _) = build_config_validate_payload(&paths)
        .await
        .expect("validate conflict with shift");
    assert!(ok_shift);
    assert_ne!(out_shift["ports"]["mixed_port"], json!(busy_mixed));
    assert!(
        out_shift["third_party_port_conflicts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["port"] == json!(busy_mixed))
    );
    assert!(out_shift["new_instance_preview_ports"].is_object());

    let _ = std::fs::remove_dir_all(&temp_root);
}

#[test]
fn live_baseline_reads_tun_section_beyond_512_lines_of_fake_ip_filter() {
    use catcloud_core::core_adapter::ControllerEndpointSource;

    let temp_root = std::env::temp_dir().join(format!(
        "catcloud-cli-large-fake-ip-filter-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    std::fs::create_dir_all(&temp_root).unwrap();
    let runtime_yaml_path = temp_root.join("runtime.yaml");

    let mut yaml = String::from(concat!(
        "mixed-port: 17890\n",
        "allow-lan: false\n",
        "mode: rule\n",
        "dns:\n",
        "  enable: true\n",
        "  listen: 127.0.0.1:21053\n",
        "  ipv6: false\n",
        "  fake-ip-filter:\n",
    ));
    for idx in 0..700usize {
        yaml.push_str(&format!("    - 'node-{idx}.demo.example.invalid'\n"));
    }
    yaml.push_str(concat!(
        "tun:\n",
        "  enable: true\n",
        "  stack: gvisor\n",
        "  device: CatCloudBig\n",
        "  mtu: 1480\n",
        "  auto-route: true\n",
        "  auto-detect-interface: true\n",
        "  strict-route: false\n",
        "proxies:\n",
        "  - name: dummy\n",
        "    type: trojan\n",
        "    server: 203.0.113.10\n",
        "    port: 443\n",
    ));
    std::fs::write(&runtime_yaml_path, &yaml).unwrap();

    let mut cfg = AppConfig::default();
    cfg.tun.enabled = false;
    cfg.tun.stack_mode = TunStackMode::Mixed;
    cfg.tun.device_name = "CatCloud".to_string();
    cfg.tun.mtu = 1500;
    cfg.tun.strict_route = true;

    let ep = ResolvedControllerEndpoint {
        host: "127.0.0.1".to_string(),
        port: 19090,
        secret: "demo".to_string(),
        mixed_port: None,
        dns_port: None,
        pid: None,
        process_start_time_unix: None,
        binary_path: None,
        source: ControllerEndpointSource::ExplicitConfigSecret,
    };

    let baseline =
        build_live_baseline_config_from_runtime(&cfg, &runtime_yaml_path, None, &ep);
    assert_eq!(baseline.mixed_port, 17890);
    assert_eq!(baseline.dns_listen_port, 21053);
    assert!(baseline.tun.enabled, "tun.enable past >600 fake-ip-filter lines must be parsed");
    assert_eq!(baseline.tun.stack_mode, TunStackMode::Gvisor);
    assert_eq!(baseline.tun.device_name, "CatCloudBig");
    assert_eq!(baseline.tun.mtu, 1480);
    assert!(!baseline.tun.strict_route);

    let _ = std::fs::remove_dir_all(&temp_root);
}

#[test]
fn config_export_gateway_cli_parse_defaults_and_custom_flags() {
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct TestCli {
        #[command(subcommand)]
        command: Commands,
    }

    let parsed_default =
        TestCli::try_parse_from(["catcloud", "config", "export-gateway"]).expect("default parse");
    match parsed_default.command {
        Commands::Config {
            action:
                ConfigCommand::ExportGateway {
                    profile,
                    tproxy_port,
                    redir_port,
                    dns_port,
                    output,
                    reveal_secrets,
                },
        } => {
            assert_eq!(profile, "relay-fragment");
            assert_eq!(tproxy_port, 7893);
            assert_eq!(redir_port, 7892);
            assert_eq!(dns_port, 1053);
            assert!(output.is_none());
            assert!(!reveal_secrets, "must default to redacted mode");
        }
        other => panic!("unexpected parsed command: {other:?}"),
    }

    let parsed_custom = TestCli::try_parse_from([
        "catcloud",
        "config",
        "export-gateway",
        "--profile",
        "transparent-gateway",
        "--tproxy-port",
        "17893",
        "--redir-port",
        "17892",
        "--dns-port",
        "11053",
        "--output",
        "gateway.yaml",
        "--reveal-secrets",
    ])
    .expect("custom parse");
    match parsed_custom.command {
        Commands::Config {
            action:
                ConfigCommand::ExportGateway {
                    profile,
                    tproxy_port,
                    redir_port,
                    dns_port,
                    output,
                    reveal_secrets,
                },
        } => {
            assert_eq!(
                parse_gateway_export_profile(&profile).unwrap(),
                GatewayExportProfile::TransparentGateway
            );
            assert_eq!(tproxy_port, 17893);
            assert_eq!(redir_port, 17892);
            assert_eq!(dns_port, 11053);
            assert_eq!(output, Some(PathBuf::from("gateway.yaml")));
            assert!(reveal_secrets);
        }
        other => panic!("unexpected parsed command: {other:?}"),
    }

    assert_eq!(
        parse_gateway_export_profile("preferred-nodes").unwrap(),
        GatewayExportProfile::PreferredNodes
    );
    assert!(parse_gateway_export_profile("unknown-mode").is_err());
}

#[tokio::test]
async fn config_export_gateway_redacts_private_public_ips_and_secrets_by_default_and_writes_atomically()
{
    let temp_root = std::env::temp_dir().join(format!(
        "catcloud-cli-export-gateway-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");
    let mut cfg = config::load_or_init(&paths).expect("init config");
    cfg.preaccel.enabled = true;
    cfg.tun.enabled = true;
    cfg.controller_secret = Some("cli-gw-controller-secret-9988".to_string());
    cfg.rules_override.global_prepend_rules =
        vec!["IP-CIDR,10.23.45.67/32,DIRECT,no-resolve".to_string()];
    config::save(&paths, &cfg).expect("save config");

    let db = open_storage(&paths).expect("open db");
    db.upsert_subscription(&SubscriptionRecord {
        id: "sub-gw".to_string(),
        name: "Sub-GW".to_string(),
        kind: SubscriptionKind::File,
        url_or_cmd: "gw.yaml".to_string(),
        ..Default::default()
    })
    .expect("upsert subscription");
    db.upsert_preaccel_relay(&PreAccelRelay {
        id: "relay-gw-1".to_string(),
        name: "Relay-CN-East".to_string(),
        provider: "cloud-a".to_string(),
        region: "CN-East".to_string(),
        server: "203.0.113.88".to_string(),
        port: 443,
        protocol: "anytls".to_string(),
        password: "cli-gw-relay-secret-pw".to_string(),
        sni: None,
        skip_cert_verify: true,
        priority: 10,
        expires_at: None,
        enabled: true,
        supports_ipv6: false,
        last_probe_ms: None,
        last_mbps: None,
        last_up_mbps: None,
        last_down_mbps: None,
    })
    .expect("upsert relay");
    db.upsert_node(&ProxyNode {
        id: "node-gw-1".to_string(),
        sub_id: "sub-gw".to_string(),
        name: "Exit-LAN-192.168.88.12".to_string(),
        protocol: "ss".to_string(),
        server: "198.51.100.77".to_string(),
        port: 8443,
        is_443_native: false,
        preaccel_eligible: true,
        preaccel_override: None,
        enabled: true,
        raw_config: json!({
            "name": "Exit-LAN-192.168.88.12",
            "type": "ss",
            "server": "198.51.100.77",
            "port": 8443,
            "cipher": "aes-128-gcm",
            "password": "cli-gw-node-secret-pw"
        }),
        ..Default::default()
    })
    .expect("upsert node");

    // 1. Redacted export (default) must mask private & public IPs and all credentials while remaining valid YAML.
    let redacted_out = temp_root.join("gw-redacted.yaml");
    execute_config_export_gateway(
        &paths,
        true,
        "transparent-gateway",
        17893,
        17892,
        11053,
        Some(redacted_out.clone()),
        false,
    )
    .await
    .expect("redacted export succeeds");
    let redacted_yaml = std::fs::read_to_string(&redacted_out).expect("read redacted file");
    let redacted_report =
        validate_compiled_yaml(&redacted_yaml, &[]).expect("redacted YAML must parse cleanly");
    assert!(
        !redacted_report.issues.iter().any(|i| matches!(
            i.code.as_str(),
            "invalid_proxy_group" | "empty_proxy_group" | "group_cycle" | "unknown_rule_target"
        )),
        "redacted transparent gateway YAML had structural errors: {:?}",
        redacted_report.issues
    );
    assert!(redacted_yaml.contains("allow-lan: true"));
    assert!(redacted_yaml.contains("tproxy-port: 17893"));
    assert!(redacted_yaml.contains("redir-port: 17892"));
    assert!(redacted_yaml.contains("listen: 0.0.0.0:11053"));
    assert!(redacted_yaml.contains("tun:\n  enable: false"));

    for secret_val in [
        "10.23.45.67",
        "192.168.88.12",
        "203.0.113.88",
        "198.51.100.77",
        "cli-gw-controller-secret-9988",
        "cli-gw-relay-secret-pw",
        "cli-gw-node-secret-pw",
    ] {
        assert!(
            !redacted_yaml.contains(secret_val),
            "default redacted export leaked `{secret_val}`"
        );
    }

    // 2. Explicit `--reveal-secrets` emits deployable plaintext YAML with exact relay/node fields.
    let plain_out = temp_root.join("gw-plain.yaml");
    execute_config_export_gateway(
        &paths,
        true,
        "transparent-gateway",
        17893,
        17892,
        11053,
        Some(plain_out.clone()),
        true,
    )
    .await
    .expect("plaintext export succeeds");
    let plain_yaml = std::fs::read_to_string(&plain_out).expect("read plaintext file");
    let plain_report = validate_compiled_yaml(&plain_yaml, &["203.0.113.88".to_string()])
        .expect("plaintext YAML must parse cleanly");
    assert!(
        plain_report.ok,
        "plaintext transparent gateway YAML should pass static validation: {:?}",
        plain_report.issues
    );
    assert!(plain_yaml.contains("bind-address: '*'"));
    assert!(plain_yaml.contains("203.0.113.88"));
    assert!(plain_yaml.contains("198.51.100.77"));
    assert!(plain_yaml.contains("cli-gw-relay-secret-pw"));
    assert!(plain_yaml.contains("cli-gw-node-secret-pw"));
    assert!(plain_yaml.contains("cli-gw-controller-secret-9988"));

    let _ = std::fs::remove_dir_all(&temp_root);
}

#[tokio::test]
async fn stage22_cli_preaccel_add_dedup_bind_clears_active_relay_and_reload_dry_run_checks_mtu() {
    let temp_root = std::env::temp_dir().join(format!(
        "catcloud_cli_s22_test_{}_{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let paths = AppPaths::from_data_dir(temp_root.clone(), true).unwrap();

    // 1. `PreaccelCommand::Add` deduplicates by `(protocol, server, port)` and strips speed cache.
    let r1 = PreAccelRelay {
        id: "relay-dup-1".to_string(),
        name: "Aliyun-SH-A".to_string(),
        provider: "aliyun".to_string(),
        region: "CN-SH".to_string(),
        server: "198.51.100.40".to_string(),
        port: 443,
        protocol: "anytls".to_string(),
        password: "demo-password-a".to_string(),
        skip_cert_verify: true,
        enabled: true,
        last_probe_ms: Some(15.0),
        last_up_mbps: Some(99.0),
        ..Default::default()
    };
    let mut r2 = r1.clone();
    r2.id = "relay-dup-2".to_string();
    r2.name = "Aliyun-SH-Updated".to_string();
    let bundle_json = catcloud_core::preaccel::serialize_mmrelay_json(
        &catcloud_core::preaccel::bundle_from_relays(vec![r1, r2]),
    )
    .unwrap();

    dispatch(
        &paths,
        true,
        Commands::Preaccel {
            action: PreaccelCommand::Add {
                file: None,
                uri: Some(bundle_json),
            },
        },
    )
    .await
    .expect("preaccel add dedup succeeds");

    let db = open_storage(&paths).unwrap();
    let stored_relays = db.list_preaccel_relays(false).unwrap();
    assert_eq!(
        stored_relays.len(),
        1,
        "duplicate (protocol, server, port) relays must deduplicate to 1 row"
    );
    assert_eq!(stored_relays[0].name, "Aliyun-SH-Updated");
    assert_eq!(stored_relays[0].last_probe_ms, None);
    assert_eq!(stored_relays[0].last_up_mbps, None);
    drop(db);

    // 2. `PreaccelCommand::Bind --dispatch-strategy auto` clears pinned/dangling `active_relay_id`.
    let mut cfg = config::load_or_init(&paths).unwrap();
    cfg.preaccel.active_relay_id = Some("relay-dup-1".to_string());
    cfg.preaccel.dispatch_strategy = PreAccelDispatchStrategy::Fallback;
    config::save(&paths, &cfg).unwrap();

    dispatch(
        &paths,
        true,
        Commands::Preaccel {
            action: PreaccelCommand::Bind {
                enabled: Some(true),
                skip_443_native: None,
                probe_url: None,
                dispatch_strategy: Some("auto".to_string()),
                lb_strategy: None,
            },
        },
    )
    .await
    .expect("preaccel bind auto succeeds");
    let after_bind = config::load_or_init(&paths).unwrap();
    assert_eq!(after_bind.preaccel.dispatch_strategy, PreAccelDispatchStrategy::Auto);
    assert_eq!(after_bind.preaccel.active_relay_id, None);

    // 3. `run_config_reload_inner(..., dry_run=true)` escalates to L3 restart when live
    //    `runtime.yaml` TUN MTU (1500) differs from compiled effective TUN MTU (1400).
    let db = open_storage(&paths).unwrap();
    db.upsert_subscription(&SubscriptionRecord {
        id: "sub-mtu".to_string(),
        name: "MTU Sub".to_string(),
        ..Default::default()
    })
    .unwrap();
    db.upsert_node(&ProxyNode {
        id: "node-mtu-1".to_string(),
        sub_id: "sub-mtu".to_string(),
        name: "SG-Non443".to_string(),
        protocol: "vless".to_string(),
        server: "203.0.113.55".to_string(),
        port: 8443,
        is_443_native: false,
        preaccel_eligible: true,
        enabled: true,
        raw_config: serde_json::json!({
            "name": "SG-Non443",
            "type": "vless",
            "server": "203.0.113.55",
            "port": 8443,
            "uuid": "00000000-0000-4000-8000-000000000055",
            "tls": true,
            "network": "tcp"
        }),
        ..Default::default()
    })
    .unwrap();
    drop(db);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ctrl_port = listener.local_addr().unwrap().port();
    let secret = "cli-s22-mtu-secret".to_string();
    let mixed_port = 27890u16;
    let dns_port = 21053u16;
    let server_secret = secret.clone();
    let server_task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let expected_auth = format!("Bearer {server_secret}");
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let Ok(n) = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await else {
                    return;
                };
                let req = String::from_utf8_lossy(&buf[..n]);
                let first_line = req.lines().next().unwrap_or("");
                let authorized = req
                    .lines()
                    .any(|l| l.eq_ignore_ascii_case(&format!("Authorization: {expected_auth}")));
                let (status, body) = if !authorized {
                    ("401 Unauthorized", r#"{"message":"unauthorized"}"#.to_string())
                } else if first_line.starts_with("GET /version") {
                    ("200 OK", r#"{"version":"v1.19.10"}"#.to_string())
                } else if first_line.starts_with("GET /configs") {
                    (
                        "200 OK",
                        format!(
                            r#"{{"mixed-port":{mixed_port},"allow-lan":false,"bind-address":"127.0.0.1","mode":"rule","log-level":"info","ipv6":false,"tun":{{"enable":true,"stack":"mixed"}}}}"#
                        ),
                    )
                } else {
                    ("404 Not Found", "{}".to_string())
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, resp.as_bytes()).await;
            });
        }
    });

    let mut reload_cfg = config::load_or_init(&paths).unwrap();
    reload_cfg.mixed_port = mixed_port;
    reload_cfg.controller_port = ctrl_port;
    reload_cfg.dns_listen_port = dns_port;
    reload_cfg.controller_secret = Some(secret.clone());
    reload_cfg.tun.enabled = true;
    reload_cfg.tun.mtu = 1500;
    reload_cfg.preaccel.enabled = true;
    reload_cfg.preaccel.global_bypass_enabled = true;
    config::save(&paths, &reload_cfg).unwrap();

    let runtime_yaml_path = paths.runtime_dir.join("runtime.yaml");
    let live_yaml = format!(
        "mixed-port: {mixed_port}\nallow-lan: false\nbind-address: 127.0.0.1\nmode: rule\nexternal-controller: 127.0.0.1:{ctrl_port}\nsecret: \"{secret}\"\ndns:\n  enable: true\n  listen: 127.0.0.1:{dns_port}\ntun:\n  enable: true\n  stack: mixed\n  mtu: 1500\n"
    );
    std::fs::write(&runtime_yaml_path, live_yaml).unwrap();

    let mut priv_caps = default_platform().capabilities();
    priv_caps.is_elevated = true;

    let (dry_ok, dry_out, _) =
        run_config_reload_inner(&paths, true, Some(priv_caps), false)
            .await
            .expect("dry run with live MTU 1500 vs compiled 1400");
    assert!(dry_ok, "dry run failed: {dry_out}");
    assert_eq!(dry_out["level"], json!("l3_core_restart"));
    assert_eq!(dry_out["requires_l3_restart"], json!(true));
    assert!(
        dry_out["diff_reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r.as_str().unwrap_or("").contains("tun.effective_mtu")),
        "diff_reasons must mention tun.effective_mtu: {}",
        dry_out["diff_reasons"]
    );

    server_task.abort();
    let _ = std::fs::remove_dir_all(&temp_root);
}

#[test]
fn read_tun_mtu_from_runtime_yaml_checks_tun_enable_and_supports_flow_yaml() {
    let temp_root = std::env::temp_dir().join(format!(
        "catcloud-cli-tun-mtu-yaml-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    std::fs::create_dir_all(&temp_root).unwrap();

    let p_block_on = temp_root.join("block_on.yaml");
    std::fs::write(&p_block_on, "\u{feff}tun:\n  enable: true\n  mtu: 1400\n").unwrap();
    assert_eq!(read_tun_mtu_from_runtime_yaml(&p_block_on), Some(1400));

    let p_flow_on = temp_root.join("flow_on.yaml");
    std::fs::write(&p_flow_on, "tun: { enable: true, mtu: 1420 }\n").unwrap();
    assert_eq!(read_tun_mtu_from_runtime_yaml(&p_flow_on), Some(1420));

    let p_block_off = temp_root.join("block_off.yaml");
    std::fs::write(&p_block_off, "tun:\n  enable: false\n  mtu: 1400\n").unwrap();
    assert_eq!(read_tun_mtu_from_runtime_yaml(&p_block_off), None);

    let p_flow_off = temp_root.join("flow_off.yaml");
    std::fs::write(&p_flow_off, "tun: { enable: false, mtu: 1400 }\n").unwrap();
    assert_eq!(read_tun_mtu_from_runtime_yaml(&p_flow_off), None);

    let p_missing_enable = temp_root.join("missing_enable.yaml");
    std::fs::write(&p_missing_enable, "tun:\n  mtu: 1400\n").unwrap();
    assert_eq!(read_tun_mtu_from_runtime_yaml(&p_missing_enable), None);

    let _ = std::fs::remove_dir_all(&temp_root);
}

#[tokio::test]
async fn stage22_r25_cli_reload_dry_run_enforces_tun_disabled_and_detects_override_mtu_baseline() {
    let temp_root = std::env::temp_dir().join(format!(
        "catcloud_cli_r25_dry_run_tun_{}_{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let paths = AppPaths::from_data_dir(temp_root.clone(), true).unwrap();

    let db = open_storage(&paths).unwrap();
    db.upsert_subscription(&SubscriptionRecord {
        id: "sub-r25".to_string(),
        name: "R25 Sub".to_string(),
        ..Default::default()
    })
    .unwrap();
    db.upsert_node(&ProxyNode {
        id: "node-r25-1".to_string(),
        sub_id: "sub-r25".to_string(),
        name: "SG-Non443-R25".to_string(),
        protocol: "vless".to_string(),
        server: "203.0.113.88".to_string(),
        port: 8443,
        is_443_native: false,
        preaccel_eligible: true,
        enabled: true,
        raw_config: serde_json::json!({
            "name": "SG-Non443-R25",
            "type": "vless",
            "server": "203.0.113.88",
            "port": 8443,
            "uuid": "00000000-0000-4000-8000-000000000088",
            "tls": true,
            "network": "tcp"
        }),
        ..Default::default()
    })
    .unwrap();
    db.upsert_preaccel_relay(&PreAccelRelay {
        id: "relay-r25".to_string(),
        name: "Relay-R25".to_string(),
        provider: "aliyun".to_string(),
        region: "CN-SH".to_string(),
        server: "198.51.100.88".to_string(),
        port: 443,
        protocol: "anytls".to_string(),
        password: "demo-password-r25".to_string(),
        skip_cert_verify: true,
        enabled: true,
        ..Default::default()
    })
    .unwrap();
    drop(db);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ctrl_port = listener.local_addr().unwrap().port();
    let secret = "cli-r25-dry-tun-secret".to_string();
    let mixed_port = 27990u16;
    let dns_port = 21153u16;
    let server_secret = secret.clone();
    let server_task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let expected_auth = format!("Bearer {server_secret}");
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let Ok(n) = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await else {
                    return;
                };
                let req = String::from_utf8_lossy(&buf[..n]);
                let first_line = req.lines().next().unwrap_or("");
                let authorized = req
                    .lines()
                    .any(|l| l.eq_ignore_ascii_case(&format!("Authorization: {expected_auth}")));
                let (status, body) = if !authorized {
                    ("401 Unauthorized", r#"{"message":"unauthorized"}"#.to_string())
                } else if first_line.starts_with("GET /version") {
                    ("200 OK", r#"{"version":"v1.19.10"}"#.to_string())
                } else if first_line.starts_with("GET /configs") {
                    (
                        "200 OK",
                        format!(
                            r#"{{"mixed-port":{mixed_port},"allow-lan":false,"bind-address":"127.0.0.1","mode":"rule","log-level":"info","ipv6":false,"tun":{{"enable":true,"stack":"mixed"}}}}"#
                        ),
                    )
                } else {
                    ("404 Not Found", "{}".to_string())
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, resp.as_bytes()).await;
            });
        }
    });

    // Case 1: `config.json` has `tun.enabled = false`, while `inline_override_yaml` enables
    // `tun.enable: true`. Under `!allow_tun` (unprivileged), `dry_run` MUST invoke
    // `enforce_tun_disabled_on_compiled` so its `sha256` matches actual non-dry-run reload
    // and does NOT claim a TUN MTU change.
    let mut cfg = config::load_or_init(&paths).unwrap();
    cfg.mixed_port = mixed_port;
    cfg.controller_port = ctrl_port;
    cfg.dns_listen_port = dns_port;
    cfg.controller_secret = Some(secret.clone());
    cfg.tun.enabled = false;
    cfg.tun.mtu = 1500;
    cfg.preaccel.enabled = true;
    cfg.preaccel.global_bypass_enabled = true;
    cfg.rules_override.inline_override_yaml =
        Some("tun:\n  enable: true\n  stack: mixed\n".to_string());
    config::save(&paths, &cfg).unwrap();

    // Live runtime.yaml enables TUN but intentionally OMITS the `mtu` key so
    // `read_live_tun_mtu_from_path` returns `None`.
    let runtime_yaml_path = paths.runtime_dir.join("runtime.yaml");
    let live_yaml_no_mtu = format!(
        "mixed-port: {mixed_port}\nallow-lan: false\nbind-address: 127.0.0.1\nmode: rule\nexternal-controller: 127.0.0.1:{ctrl_port}\nsecret: \"{secret}\"\ndns:\n  enable: true\n  listen: 127.0.0.1:{dns_port}\ntun:\n  enable: true\n  stack: mixed\n"
    );
    std::fs::write(&runtime_yaml_path, &live_yaml_no_mtu).unwrap();
    assert_eq!(
        catcloud_core::core_adapter::read_live_tun_mtu_from_path(&runtime_yaml_path),
        None
    );

    let mut unpriv_caps = default_platform().capabilities();
    unpriv_caps.is_elevated = false;

    let (dry_unpriv_ok, dry_unpriv_out, _) =
        run_config_reload_inner(&paths, true, Some(unpriv_caps.clone()), false)
            .await
            .expect("unprivileged dry_run");
    assert!(dry_unpriv_ok, "unprivileged dry_run failed: {dry_unpriv_out}");
    assert_eq!(dry_unpriv_out["allow_tun"], json!(false));

    // Verify dry_run SHA-256 matches an offline real compile with `enforce_tun_disabled_on_compiled`.
    let mut expected_compiled = {
        let db = open_storage(&paths).unwrap();
        let nodes = db.list_nodes().unwrap();
        let groups = db.list_multi_groups().unwrap();
        let relays = db.list_preaccel_relays(false).unwrap();
        let ports = AllocatedPorts {
            bind_host: "127.0.0.1".to_string(),
            mixed_port,
            controller_port: ctrl_port,
            dns_port,
            shifted: Vec::new(),
        };
        let empty_filter = HashMap::new();
        compile_mihomo_config_with_runtime_dir(
            &CompileInput {
                config: &cfg,
                nodes: &nodes,
                groups: &groups,
                relays: &relays,
                controller_secret: &secret,
                allocated_ports: &ports,
                extra_prepend_rules: &[],
                extra_fake_ip_filters: &[],
                group_filtered_members: &empty_filter,
            },
            Some(&paths.runtime_dir),
        )
        .unwrap()
    };
    catcloud_core::core_adapter::enforce_tun_disabled_on_compiled(&mut expected_compiled)
        .unwrap();
    assert_eq!(
        dry_unpriv_out["sha256"].as_str(),
        Some(expected_compiled.sha256.as_str()),
        "dry_run under !allow_tun must enforce tun.enable=false before computing sha256"
    );
    assert!(
        !dry_unpriv_out["diff_reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r.as_str().unwrap_or("").contains("tun.effective_mtu")),
        "when TUN is forced off under !allow_tun, dry_run must not report tun.effective_mtu diff"
    );

    // Case 2: Under elevated privileges (`allow_tun == true`), `config.json` still has
    // `tun.enabled = false` but `inline_override_yaml` enables TUN (`compiled.value.tun.enable == true`)
    // while live `runtime.yaml` omits `mtu` (`live_tun_enabled == true`, `read_live_tun_mtu_from_path == None`).
    // Must fall back to 1500 baseline and detect `1500 -> 1400` L3 restart requirement!
    let mut priv_caps = default_platform().capabilities();
    priv_caps.is_elevated = true;

    let (dry_priv_ok, dry_priv_out, _) =
        run_config_reload_inner(&paths, true, Some(priv_caps), false)
            .await
            .expect("privileged dry_run with override TUN and omitted live mtu");
    assert!(dry_priv_ok, "privileged dry_run failed: {dry_priv_out}");
    assert_eq!(dry_priv_out["level"], json!("l3_core_restart"));
    assert_eq!(dry_priv_out["requires_l3_restart"], json!(true));
    assert!(
        dry_priv_out["diff_reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r.as_str().unwrap_or("").contains("tun.effective_mtu (1500 -> 1400)")),
        "expected tun.effective_mtu (1500 -> 1400) in diff_reasons: {}",
        dry_priv_out["diff_reasons"]
    );

    server_task.abort();
    let _ = std::fs::remove_dir_all(&temp_root);
}

#[tokio::test]
async fn stage23_reload_handoff_uses_desktop_ack_rejects_nonzero_and_falls_back_when_offline() {
    use catcloud_core::process_guard::{
        AcquireOutcome, ConfigReloadAck, SingleInstanceGuard, read_config_reload_request,
        write_config_reload_ack,
    };
    use std::sync::atomic::{AtomicBool, Ordering};

    let temp_root = std::env::temp_dir().join(format!(
        "catcloud_cli_s23_reload_{}_{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let paths = AppPaths::from_data_dir(temp_root.clone(), true).unwrap();

    // Seed one valid node so offline fallback compile succeeds cleanly.
    {
        let db = open_storage(&paths).unwrap();
        db.upsert_subscription(&SubscriptionRecord {
            id: "sub-s23-reload".to_string(),
            name: "S23 Reload Sub".to_string(),
            kind: SubscriptionKind::File,
            url_or_cmd: "https://example.invalid/s23.yaml".to_string(),
            enabled: true,
            ..Default::default()
        })
        .unwrap();
        db.upsert_node(&ProxyNode {
            id: "node-s23-reload-1".to_string(),
            sub_id: "sub-s23-reload".to_string(),
            name: "JP-Reload-1".to_string(),
            protocol: "anytls".to_string(),
            server: "198.51.100.21".to_string(),
            port: 443,
            raw_config: json!({
                "name": "JP-Reload-1",
                "type": "anytls",
                "server": "198.51.100.21",
                "port": 443,
                "password": "demo-password-reload"
            }),
            region_code: "JP".to_string(),
            multiplier: 1.0,
            is_443_native: true,
            preaccel_eligible: false,
            preaccel_override: None,
            tags: Vec::new(),
            enabled: true,
        })
        .unwrap();
    }

    let mut guard =
        match SingleInstanceGuard::acquire(&paths.root_data_dir, Duration::ZERO).unwrap() {
            AcquireOutcome::Primary(g) => g,
            AcquireOutcome::SecondaryWokePrimary => panic!("expected primary instance"),
        };
    let reject_mode = Arc::new(AtomicBool::new(false));
    let silence_mode = Arc::new(AtomicBool::new(false));
    let reject_c = Arc::clone(&reject_mode);
    let silence_c = Arc::clone(&silence_mode);
    let dir_cb = paths.root_data_dir.clone();
    guard
        .start_instance_listeners_with_reload(
            || {},
            || {},
            move || {
                if silence_c.load(Ordering::SeqCst) {
                    return;
                }
                if let Some(req) = read_config_reload_request(&dir_cb) {
                    let should_reject = reject_c.load(Ordering::SeqCst);
                    let ack = if should_reject {
                        ConfigReloadAck {
                            req_id: req.req_id,
                            applied: false,
                            rejected: true,
                            level: Some("l3_core_restart".to_string()),
                            error: Some("L3 restart requires --allow-restart".to_string()),
                            completed_at_ms: 1_700_000_001_000,
                        }
                    } else {
                        ConfigReloadAck {
                            req_id: req.req_id,
                            applied: true,
                            rejected: false,
                            level: Some("l2_hot_reload".to_string()),
                            error: None,
                            completed_at_ms: 1_700_000_000_500,
                        }
                    };
                    let _ = write_config_reload_ack(&dir_cb, &ack);
                }
            },
        )
        .unwrap();

    // 1. Live desktop accepts hot-reload -> ok=true, live_reload_signaled=true, via=desktop_live_hotswap.
    let args_ok = ReloadArgs {
        dry_run: false,
        force: true,
        allow_restart: false,
    };
    let (ok1, out1, _) = run_config_reload_with_desktop_handoff(
        &paths,
        &args_ok,
        Duration::from_secs(2),
        None,
        false,
    )
    .await
    .expect("live handoff ok");
    assert!(ok1, "expected ok=true from live ack: {out1}");
    assert_eq!(out1["ok"], json!(true));
    assert_eq!(out1["live_reload_signaled"], json!(true));
    assert_eq!(out1["via"], json!("desktop_live_hotswap"));
    assert_eq!(out1["applied"], json!(true));
    assert_eq!(out1["rejected"], json!(false));
    assert_eq!(out1["level"], json!("l2_hot_reload"));

    // 2. Live desktop rejects reload -> ok=false and execute_config_reload returns Err (non-zero exit).
    reject_mode.store(true, Ordering::SeqCst);
    let args_rej = ReloadArgs {
        dry_run: false,
        force: false,
        allow_restart: false,
    };
    let (ok2, out2, _) = run_config_reload_with_desktop_handoff(
        &paths,
        &args_rej,
        Duration::from_secs(2),
        None,
        false,
    )
    .await
    .expect("rejected handoff returns structured payload");
    assert!(!ok2);
    assert_eq!(out2["ok"], json!(false));
    assert_eq!(out2["live_reload_signaled"], json!(true));
    assert_eq!(out2["via"], json!("desktop_live_hotswap"));
    assert_eq!(out2["rejected"], json!(true));
    let cli_err = execute_config_reload(&paths, true, args_rej).await;
    assert!(
        cli_err.is_err(),
        "rejected desktop reload must return non-zero CLI error"
    );

    // 3. Live desktop times out without ack while still alive -> MUST refuse direct controller
    //    fallback (avoiding concurrent core writes), clean up request file, and report req_id.
    silence_mode.store(true, Ordering::SeqCst);
    let args_timeout = ReloadArgs {
        dry_run: false,
        force: false,
        allow_restart: true,
    };
    let (ok_to, out_to, human_to) = run_config_reload_with_desktop_handoff(
        &paths,
        &args_timeout,
        Duration::from_millis(160),
        None,
        false,
    )
    .await
    .expect("timed-out live handoff returns structured failure");
    assert!(!ok_to, "timed-out live desktop reload must fail non-zero");
    assert_eq!(out_to["ok"], json!(false));
    assert_eq!(out_to["timed_out"], json!(true));
    assert_eq!(out_to["desktop_alive"], json!(true));
    assert_eq!(out_to["via"], json!("desktop_live_hotswap"));
    let to_req_id = out_to["req_id"]
        .as_str()
        .expect("timed-out payload must include req_id");
    assert!(!to_req_id.is_empty());
    assert!(
        human_to.contains(to_req_id),
        "human timeout error must mention req_id: {human_to}"
    );
    assert_eq!(
        read_config_reload_request(&paths.root_data_dir),
        None,
        "timed-out reload must clean up stale allow_l3_restart request file"
    );

    // 4. Desktop offline -> falls back to direct controller path with live_reload_signaled=false.
    guard.release();
    let args_fallback = ReloadArgs {
        dry_run: false,
        force: false,
        allow_restart: false,
    };
    let (ok3, out3, _) = run_config_reload_with_desktop_handoff(
        &paths,
        &args_fallback,
        Duration::from_millis(200),
        None,
        false,
    )
    .await
    .expect("offline fallback succeeds");
    assert!(ok3, "offline fallback compile/write failed: {out3}");
    assert_eq!(out3["live_reload_signaled"], json!(false));
    assert_eq!(out3["via"], json!("direct_controller"));

    let _ = std::fs::remove_dir_all(&temp_root);
}
