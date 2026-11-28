//! Core CLI command tests: status, diag, node, sub, probe, group, preaccel, update, and redaction.

use catcloud_core::config;
use catcloud_core::core_adapter::{
    BinaryResolution, DownloadGuidance, ReloadOutcome, resolve_mihomo_binary,
};
use catcloud_core::models::{
    AppConfig, FallbackPolicy, MultiGroup, MultiGroupMode, PreAccelConfig, PreAccelRelay,
    ProxyNode, RouteTargetMode, SubscriptionKind, SubscriptionRecord, SwitchMode,
};
use catcloud_core::platform::default_platform;
use catcloud_core::preaccel::global_tunnel::GlobalPreAccelRuntimeMeta;
use catcloud_core::sanitize::sanitize_log_line;
use catcloud_core::updater::{MAX_ZIP_BYTES, parse_latest_manifest, resolve_asset_sha256};
use catcloud_core::AppPaths;
use chrono::Utc;
use serde_json::json;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use crate::commands::{
    Commands, GroupCreateArgs, GroupMembersArgs, GroupPolicyArgs, NodeCommand, NodeMigrateArgs,
    PreaccelCommand, SubCommand, dispatch,
};
use crate::commands::config_reload::{
    MAX_DIAG_LOG_LINES, build_diag_payload, inspect_active_core_ports,
};
use crate::commands::net_logs::build_net_doctor_payload;
use crate::commands::preaccel::{
    build_global_preaccel_status_payload, resolve_effective_preaccel_carrier,
    select_preaccel_speed_reference_node,
};
use crate::commands::probe_group::{
    build_group_eval_payload, build_probe_run_dry_run_payload,
    build_probe_run_missing_binary_payload, execute_group_create, execute_group_members,
    execute_group_policy,
};
use crate::commands::redact_helpers::{
    finalize_output_value, open_storage, read_file_with_limit, redact_preaccel_config_for_output,
    redact_reload_outcome, sync_active_single_node_after_mutation,
};
use crate::commands::status_docs_update::{
    find_manifest_asset_for_stage, is_cli_tun_privilege_ready, resolve_cli_effective_tun_state,
    resolve_cli_effective_tun_state_with_probe,
};

#[test]
fn sanitize_log_line_redacts_secrets_passwords_tokens_paths_and_ipv6_without_breaking_timestamps() {
    let raw = concat!(
        "2026-11-24T03:20:00Z INFO auth failed ",
        "controller_secret=deadbeef01234567 ",
        "\"password\": \"myS3cr3t!\", ",
        "url=https://sub.example.com/api?token=tok_999888&ok=1 ",
        "Authorization: Bearer eyJhbGci.payload.sig ",
        "path=C:\\Users\\Administrator\\CatCloud\\config.json ",
        "peer=[2001:db8:85a3::8a2e:370:7334]:443 ",
        "src=fe80::1 net=2001:db8::/48 local=::1 ",
        "mod=catcloud_core::config"
    );
    let sanitized = sanitize_log_line(raw);

    assert!(sanitized.contains("2026-11-24T03:20:00Z"));
    assert!(sanitized.contains("mod=catcloud_core::config"));
    assert!(sanitized.contains("ok=1"));
    assert!(sanitized.contains("local=::1"));

    assert!(!sanitized.contains("deadbeef01234567"));
    assert!(!sanitized.contains("myS3cr3t!"));
    assert!(!sanitized.contains("tok_999888"));
    assert!(!sanitized.contains("eyJhbGci.payload.sig"));
    assert!(!sanitized.contains("Administrator"));
    assert!(!sanitized.contains("8a2e:370:7334"));

    assert!(sanitized.contains("controller_secret=<REDACTED>"));
    assert!(sanitized.contains("\"password\": \"<REDACTED>\""));
    assert!(sanitized.contains("token=<REDACTED>&ok=1"));
    assert!(sanitized.contains("Authorization: Bearer <REDACTED>"));
    assert!(sanitized.contains("<USER>"));
    assert!(sanitized.contains("2001:db8::*"));
}

#[tokio::test]
async fn diag_payload_aligns_country_mmdb_and_supports_reveal_secrets() {
    let temp_root = std::env::temp_dir().join(format!(
        "catcloud-cli-diag-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");

    let unused_ctrl_port = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("ephemeral port")
        .local_addr()
        .unwrap()
        .port();

    let mut cfg = config::load_or_init(&paths).expect("init config");
    cfg.route_mode = RouteTargetMode::Single;
    cfg.active_group_id = Some("grp-tw".to_string());
    cfg.active_single_node_id = Some("node-tw-01".to_string());
    cfg.controller_port = unused_ctrl_port;
    cfg.system_proxy.enabled = true;
    cfg.tun.enabled = true;
    cfg.rules_override.domestic_direct_enabled = true;
    cfg.rules_override.block_quic_udp_443 = true;
    cfg.preaccel.enabled = true;
    cfg.controller_secret = Some("diag_secret_token_demo".to_string());
    config::save(&paths, &cfg).expect("save config");

    // country-lite.mmdb alone must NOT produce a false green for country_mmdb.
    std::fs::write(paths.runtime_dir.join("country-lite.mmdb"), b"stub-lite").unwrap();
    std::fs::write(paths.runtime_dir.join("geosite.dat"), b"stub-geosite").unwrap();
    let diag_before_mmdb = build_diag_payload(&paths, false)
        .await
        .expect("diag before Country.mmdb");
    assert_eq!(
        diag_before_mmdb["geodata_status"]["country_mmdb"]["exists"],
        json!(false)
    );
    assert_eq!(
        diag_before_mmdb["geodata_status"]["geosite_dat"]["exists"],
        json!(true)
    );

    // Once Country.mmdb is placed, country_mmdb reports exists=true.
    std::fs::write(paths.runtime_dir.join("Country.mmdb"), b"stub-mmdb").unwrap();

    let mut log_content = String::new();
    for idx in 1..=55 {
        log_content.push_str(&format!(
            "2026-11-24T03:00:{:02}Z INFO line={} secret=sec_{idx} token=tok_{idx} ip=203.0.113.{}\n",
            idx % 60,
            idx,
            idx % 200 + 1
        ));
    }
    std::fs::write(paths.logs_dir.join("catcloud.log"), log_content).unwrap();

    let diag = build_diag_payload(&paths, false)
        .await
        .expect("build sanitized diag payload");
    assert_eq!(diag["ok"], json!(true));
    assert_eq!(diag["sanitized"], json!(true));
    assert!(diag.get("controller_secret").is_none());
    assert_eq!(diag["route_mode"], json!("single"));
    assert_eq!(diag["active_group_id"], json!("grp-tw"));
    assert_eq!(diag["active_single_node_id"], json!("node-tw-01"));
    assert_eq!(diag["system_proxy_enabled"], json!(true));
    let expected_tun_ready = is_cli_tun_privilege_ready(
        &default_platform().capabilities(),
        resolve_mihomo_binary(&cfg, &paths, &[], false)
            .ok()
            .and_then(|r| r.path)
            .as_deref(),
    );
    assert_eq!(diag["tun_configured"], json!(true));
    assert_eq!(diag["tun_enabled"], json!(expected_tun_ready));
    assert_eq!(diag["tun_needs_elevation"], json!(!expected_tun_ready));
    assert_eq!(diag["domestic_direct_enabled"], json!(true));
    assert_eq!(diag["block_quic_udp_443"], json!(true));
    assert_eq!(diag["preaccel_enabled"], json!(true));

    assert_eq!(diag["geodata_status"]["country_mmdb"]["exists"], json!(true));
    assert_eq!(diag["geodata_status"]["geosite_dat"]["exists"], json!(true));
    assert_eq!(diag["geodata_status"]["geoip_dat"]["exists"], json!(false));

    let logs = diag["recent_logs"].as_array().expect("recent_logs array");
    assert_eq!(logs.len(), MAX_DIAG_LOG_LINES);
    assert!(logs[0].as_str().unwrap().contains("line=16"));
    assert!(logs[39].as_str().unwrap().contains("line=55"));
    for entry in logs {
        let s = entry.as_str().unwrap();
        assert!(!s.contains("sec_"));
        assert!(!s.contains("tok_"));
        assert!(s.contains("secret=<REDACTED>"));
        assert!(s.contains("token=<REDACTED>"));
        assert!(s.contains("203.0.113.*"));
    }

    let revealed = build_diag_payload(&paths, true)
        .await
        .expect("build revealed diag payload");
    assert_eq!(revealed["sanitized"], json!(false));
    assert_eq!(revealed["controller_secret"], json!("diag_secret_token_demo"));
    assert!(
        revealed["recent_logs"][0]
            .as_str()
            .unwrap()
            .contains("sec_16")
    );

    // When tun.enabled is disabled in config, all three TUN truth fields must be false.
    cfg.tun.enabled = false;
    config::save(&paths, &cfg).expect("save tun disabled config");
    let diag_tun_off = build_diag_payload(&paths, false)
        .await
        .expect("diag with tun off");
    assert_eq!(diag_tun_off["tun_configured"], json!(false));
    assert_eq!(diag_tun_off["tun_enabled"], json!(false));
    assert_eq!(diag_tun_off["tun_needs_elevation"], json!(false));

    let _ = std::fs::remove_dir_all(&temp_root);
}

#[tokio::test]
async fn status_and_diag_align_live_tun_state_when_core_running_without_elevation() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock controller");
    let mock_port = listener.local_addr().unwrap().port();

    let server_task = tokio::spawn(async move {
        for _ in 0..8 {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let mut req_buf = [0u8; 2048];
            let n = stream.read(&mut req_buf).await.unwrap_or(0);
            let req_str = String::from_utf8_lossy(&req_buf[..n]);
            let body = if req_str.starts_with("GET /version ") {
                r#"{"version":"v1.19.0"}"#
            } else if req_str.starts_with("GET /connections ") {
                r#"{"downloadTotal":0,"uploadTotal":0,"connections":[{"id":"c1","metadata":{"network":"tcp","type":"Tun","sourceIP":"198.18.0.1","destinationIP":"203.0.113.10","sourcePort":"51234","destinationPort":"443","host":"example.com","dnsMode":"fake-ip","processPath":""},"upload":10,"download":20,"start":"2026-11-25T00:00:00Z","chains":["DIRECT"],"rule":"MATCH","rulePayload":""}]}"#
            } else {
                r#"{}"#
            };
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes()).await;
        }
    });

    let temp_root = std::env::temp_dir().join(format!(
        "catcloud-cli-live-tun-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");
    let mut cfg = config::load_or_init(&paths).expect("init config");
    cfg.controller_port = mock_port;
    cfg.controller_secret = None;
    cfg.tun.enabled = true;
    config::save(&paths, &cfg).expect("save config");

    let mut unprivileged_caps = default_platform().capabilities();
    unprivileged_caps.is_elevated = false;

    let (tun_enabled, tun_needs_elevation, tun_source) =
        resolve_cli_effective_tun_state(&paths, &cfg, &unprivileged_caps, None).await;
    assert!(tun_enabled);
    assert!(!tun_needs_elevation);
    assert_eq!(tun_source, "live_tun_connections");

    let diag = build_diag_payload(&paths, false)
        .await
        .expect("build diag with live core");
    assert_eq!(diag["tun_configured"], json!(true));
    assert_eq!(diag["tun_enabled"], json!(true));
    assert_eq!(diag["tun_needs_elevation"], json!(false));
    assert_eq!(diag["tun_source"], json!("live_tun_connections"));

    server_task.abort();
    let _ = std::fs::remove_dir_all(&temp_root);
}

#[tokio::test]
async fn global_preaccel_status_payload_reports_config_and_windivert_readiness() {
    let temp_root = std::env::temp_dir().join(format!(
        "catcloud-cli-global-preaccel-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");

    let mut cfg = config::load_or_init(&paths).expect("init config");
    cfg.preaccel.global_bypass_enabled = true;
    config::save(&paths, &cfg).expect("save config");

    let (payload_before, human_before) = build_global_preaccel_status_payload(&paths)
        .await
        .expect("status before windivert");
    assert_eq!(payload_before["ok"], json!(true));
    assert_eq!(payload_before["global_bypass_enabled"], json!(true));
    assert_eq!(payload_before["global_scope"], json!("proxy_apps_only"));
    assert_eq!(payload_before["windivert_available"], json!(false));
    assert_eq!(payload_before["effective_carrier"], json!("off"));
    assert_eq!(payload_before["standalone_tunnel_running"], json!(false));
    assert_eq!(
        payload_before["standalone_tunnel_suspended_for_tun"],
        json!(false)
    );
    assert!(human_before.contains("enabled=true"));

    std::fs::write(paths.bin_dir.join("WinDivert64.dll"), b"stub-dll").unwrap();
    std::fs::write(paths.bin_dir.join("WinDivert64.sys"), b"stub-sys").unwrap();

    let (payload_after, _) = build_global_preaccel_status_payload(&paths)
        .await
        .expect("status after windivert");
    if !cfg!(all(target_os = "windows", not(target_arch = "aarch64"))) {
        assert_eq!(payload_after["windivert_available"], json!(false));
        assert!(payload_after["windivert_dll"].is_null());
        assert!(payload_after["windivert_sys"].is_null());
    } else {
        assert_eq!(payload_after["windivert_available"], json!(true));
        assert!(payload_after["windivert_dll"].as_str().is_some());
        assert!(payload_after["windivert_sys"].as_str().is_some());
    }

    let _ = std::fs::remove_dir_all(&temp_root);
}

#[tokio::test]
async fn node_migrate_supports_directory_display_name_and_unique_subscription_ids() {
    let temp_root = std::env::temp_dir().join(format!(
        "catcloud-cli-migrate-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    let data_dir = temp_root.join("data");
    let src_dir = temp_root.join("third_party");
    let profiles_dir = src_dir.join("profiles");
    std::fs::create_dir_all(&profiles_dir).unwrap();
    std::fs::write(
        profiles_dir.join("sub_a.yaml"),
        "proxies:\n  - name: \"HK Migrate Test 1x\"\n    type: trojan\n    server: 198.51.100.44\n    port: 443\n    password: \"placeholder-pass\"\n",
    )
    .unwrap();
    std::fs::write(
        src_dir.join("profiles.yaml"),
        "items:\n  - name: \"我的真实订阅\"\n    file: sub_a.yaml\n",
    )
    .unwrap();

    let paths = AppPaths::from_data_dir(data_dir, true).expect("init temp paths");
    for _ in 0..2 {
        dispatch(
            &paths,
            true,
            Commands::Node {
                action: NodeCommand::Migrate(NodeMigrateArgs {
                    scan: false,
                    file: Some(src_dir.clone()),
                    apply: true,
                    include_rules: false,
                }),
            },
        )
        .await
        .expect("apply migration from directory");
    }

    let db = open_storage(&paths).expect("open db");
    let subs = db.list_subscriptions().expect("list subs");
    let nodes = db.list_nodes().expect("list nodes");
    assert_eq!(subs.len(), 2, "repeated --apply must not overwrite previous migrated subscription");
    assert_eq!(nodes.len(), 2, "nodes from both imports must be preserved");
    assert_ne!(subs[0].id, subs[1].id);
    for sub in &subs {
        assert!(sub.id.starts_with("migrated-"));
        assert_eq!(sub.name, "我的真实订阅");
    }

    let _ = std::fs::remove_dir_all(&temp_root);
}

#[test]
fn update_stage_helpers_enforce_size_cap_and_cross_check_manifest_sha256() {
    let temp_root = std::env::temp_dir().join(format!(
        "catcloud-cli-stage-helpers-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    std::fs::create_dir_all(&temp_root).unwrap();

    let oversized = temp_root.join("oversized.zip");
    let f = std::fs::File::create(&oversized).unwrap();
    f.set_len(MAX_ZIP_BYTES as u64 + 1).unwrap();
    assert!(
        read_file_with_limit(&oversized, MAX_ZIP_BYTES, "update archive").is_err(),
        "archives larger than MAX_ZIP_BYTES must be rejected before reading"
    );

    let good_sha = "a".repeat(64);
    let bad_sha = "b".repeat(64);
    let manifest_bytes = serde_json::to_vec(&json!({
        "version": "0.2.0",
        "platforms": {
            "windows-x86_64-portable": {
                "url": "https://github.com/JuryBu/CatCloud/releases/download/v0.2.0/CatCloud-0.2.0-windows-x64-portable.zip",
                "filename": "CatCloud-0.2.0-windows-x64-portable.zip",
                "sha256": good_sha
            }
        }
    }))
    .unwrap();
    let manifest = parse_latest_manifest(&manifest_bytes).unwrap();
    let asset = find_manifest_asset_for_stage(
        &manifest,
        "CatCloud-0.2.0-windows-x64-portable.zip",
    )
    .expect("asset matched by filename");

    let mut matching_sums = HashMap::new();
    matching_sums.insert(
        "release-assets/CatCloud-0.2.0-windows-x64-portable.zip".to_string(),
        good_sha.clone(),
    );
    assert_eq!(
        resolve_asset_sha256(asset, Some(&matching_sums)).unwrap(),
        good_sha
    );

    let mut mismatched_sums = HashMap::new();
    mismatched_sums.insert(
        "CatCloud-0.2.0-windows-x64-portable.zip".to_string(),
        bad_sha,
    );
    assert!(
        resolve_asset_sha256(asset, Some(&mismatched_sums)).is_err(),
        "mismatched manifest sha256 vs SHA256SUMS must fail"
    );

    let _ = std::fs::remove_dir_all(&temp_root);
}

#[tokio::test]
async fn sub_merge_remaps_and_falls_back_active_single_node_id() {
    let temp_root = std::env::temp_dir().join(format!(
        "catcloud-cli-sub-merge-remap-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");
    let db = open_storage(&paths).expect("open db");

    db.upsert_subscription(&SubscriptionRecord {
        id: "sub-src".to_string(),
        name: "Source".to_string(),
        kind: SubscriptionKind::File,
        url_or_cmd: "src.yaml".to_string(),
        ..Default::default()
    })
    .unwrap();
    db.upsert_subscription(&SubscriptionRecord {
        id: "sub-dst".to_string(),
        name: "Target".to_string(),
        kind: SubscriptionKind::File,
        url_or_cmd: "dst.yaml".to_string(),
        ..Default::default()
    })
    .unwrap();

    let shared_raw = json!({
        "name": "JP Shared 1x",
        "type": "trojan",
        "server": "203.0.113.50",
        "port": 443,
        "password": "shared_demo_password"
    });
    db.upsert_node(&ProxyNode {
        id: "node-src-dup".to_string(),
        sub_id: "sub-src".to_string(),
        name: "JP Shared 1x".to_string(),
        protocol: "trojan".to_string(),
        server: "203.0.113.50".to_string(),
        port: 443,
        raw_config: shared_raw.clone(),
        region_code: "JP".to_string(),
        ..ProxyNode::default()
    })
    .unwrap();
    db.upsert_node(&ProxyNode {
        id: "node-dst-keep".to_string(),
        sub_id: "sub-dst".to_string(),
        name: "JP Shared 1x".to_string(),
        protocol: "trojan".to_string(),
        server: "203.0.113.50".to_string(),
        port: 443,
        raw_config: shared_raw,
        region_code: "JP".to_string(),
        ..ProxyNode::default()
    })
    .unwrap();

    let mut cfg = config::load_or_init(&paths).expect("init config");
    cfg.active_single_node_id = Some("node-src-dup".to_string());
    config::save(&paths, &cfg).expect("save config");
    drop(db);

    dispatch(
        &paths,
        true,
        Commands::Sub {
            action: SubCommand::Merge {
                source: "sub-src".to_string(),
                target: "sub-dst".to_string(),
                name: None,
                no_dedup: false,
            },
        },
    )
    .await
    .expect("sub merge must succeed");

    let updated = config::load_or_default(&paths).expect("reload config after merge");
    assert_eq!(
        updated.active_single_node_id.as_deref(),
        Some("node-dst-keep"),
        "sub merge must remap active_single_node_id to deduplicated target node ID"
    );

    // When active_single_node_id points to a deleted node and id_remap is empty,
    // sync_active_single_node_after_mutation must fall back to the first enabled node.
    let mut stale_cfg = updated;
    stale_cfg.active_single_node_id = Some("node-ghost-deleted".to_string());
    config::save(&paths, &stale_cfg).expect("save stale config");
    let db = open_storage(&paths).expect("reopen db");
    let changed = sync_active_single_node_after_mutation(&paths, &db, &HashMap::new())
        .expect("sync fallback");
    assert!(changed);
    let after_fallback = config::load_or_default(&paths).expect("reload config after fallback");
    assert_eq!(
        after_fallback.active_single_node_id.as_deref(),
        Some("node-dst-keep")
    );

    // When all nodes are gone, active_single_node_id must clear to None.
    let _ = db.delete_subscription("sub-dst").unwrap();
    let cleared = sync_active_single_node_after_mutation(&paths, &db, &HashMap::new())
        .expect("sync clear");
    assert!(cleared);
    let after_clear = config::load_or_default(&paths).expect("reload config after clear");
    assert_eq!(after_clear.active_single_node_id, None);

    let _ = std::fs::remove_dir_all(&temp_root);
}

#[test]
fn probe_run_dry_run_missing_binary_preaccel_bind_and_reload_outcome_are_redacted() {
    use catcloud_core::core_adapter::{BinarySource, ReloadLevel};
    use catcloud_core::models::CoreKind;

    let win_user_root = ["C:", "Users", "DemoAccount"].join("\\");
    let fake_bin = PathBuf::from(format!("{win_user_root}\\CatCloud\\bin\\mihomo.exe"));
    let fake_cand = PathBuf::from(r"D:\PrivateWorkspace\CatCloud\bin\mihomo.exe");
    let plan = json!({
        "tier": "l1",
        "node_count": 1,
        "probe_count": 2
    });
    let probe_ids = vec!["builtin_latency".to_string(), "builtin_google_cn".to_string()];

    let found_res = BinaryResolution {
        found: true,
        path: Some(fake_bin.clone()),
        source: BinarySource::UserDataBin,
        sha256: None,
        checked_candidates: vec![fake_bin.clone(), fake_cand.clone()],
        download_guidance: None,
    };
    let (dry_redacted, _) =
        build_probe_run_dry_run_payload("l1", 1, &probe_ids, &plan, &found_res, false);
    assert_eq!(dry_redacted["sanitized"], json!(true));
    let dry_json = serde_json::to_string(&dry_redacted).unwrap();
    assert!(!dry_json.contains("DemoAccount"));
    assert!(!dry_json.contains("PrivateWorkspace"));
    assert!(dry_json.contains("<USER>"));
    assert!(dry_json.contains("<LOCAL_PATH>"));

    let (dry_revealed, _) =
        build_probe_run_dry_run_payload("l1", 1, &probe_ids, &plan, &found_res, true);
    assert_eq!(dry_revealed["sanitized"], json!(false));
    assert!(
        dry_revealed["binary_path"]
            .as_str()
            .unwrap()
            .contains("DemoAccount")
    );

    let missing_res = BinaryResolution {
        found: false,
        path: None,
        source: BinarySource::NotFound,
        sha256: None,
        checked_candidates: vec![fake_bin.clone(), fake_cand.clone()],
        download_guidance: Some(DownloadGuidance {
            core_kind: CoreKind::Mihomo,
            platform_target: "windows-amd64".to_string(),
            recommended_asset_pattern: "mihomo-windows-amd64*.zip".to_string(),
            official_releases_url: "https://github.com/MetaCubeX/mihomo/releases".to_string(),
            target_install_path: fake_bin.clone(),
            verify_sha256_required: true,
            instructions: format!(
                "Install binary to {win_user_root}\\CatCloud\\bin\\mihomo.exe"
            ),
        }),
    };
    let (missing_out, missing_human) =
        build_probe_run_missing_binary_payload("l1", 1, &probe_ids, &plan, &missing_res, false);
    let missing_json = serde_json::to_string(&missing_out).unwrap();
    assert!(!missing_json.contains("DemoAccount"));
    assert!(!missing_json.contains("PrivateWorkspace"));
    assert!(!missing_human.contains("DemoAccount"));
    assert!(missing_human.contains("<USER>"));

    // PreAccelConfig windivert_dir redaction (preaccel bind)
    let mut preaccel_cfg = PreAccelConfig::default();
    preaccel_cfg.windivert_dir =
        Some(format!("{win_user_root}\\Tools\\WinDivert-2.2"));
    let masked_preaccel = redact_preaccel_config_for_output(&preaccel_cfg);
    let wd = masked_preaccel.windivert_dir.as_deref().unwrap();
    assert!(!wd.contains("DemoAccount"));
    assert!(wd.contains("<USER>"));

    // ReloadOutcome error & warnings redaction (config reload)
    let raw_outcome = ReloadOutcome {
        applied: false,
        level: ReloadLevel::L2HotReload,
        skipped_unchanged: false,
        rejected: true,
        config_hash: None,
        replayed_groups: 0,
        shifted_ports: Vec::new(),
        warnings: vec![format!(
            "warn path={win_user_root}\\CatCloud\\runtime.yaml token=secret_tok_99"
        )],
        error: Some(format!(
            "line1 failed at {win_user_root}\\runtime.yaml\nline2 peer=203.0.113.42 password=pw_demo"
        )),
        applied_at: "2026-11-25T00:00:00Z".to_string(),
    };
    let clean_outcome = redact_reload_outcome(&raw_outcome);
    let clean_err = clean_outcome.error.as_deref().unwrap();
    assert!(!clean_err.contains("DemoAccount"));
    assert!(!clean_err.contains("203.0.113.42"));
    assert!(!clean_err.contains("pw_demo"));
    assert!(clean_err.contains("<USER>"));
    assert!(clean_err.contains("203.0.113.*"));
    assert!(clean_err.contains("password=<REDACTED>"));
    assert!(!clean_outcome.warnings[0].contains("DemoAccount"));
    assert!(!clean_outcome.warnings[0].contains("secret_tok_99"));
}

#[test]
fn preaccel_speed_reference_node_prefers_homepage_skips_udp_and_falls_back_to_single_hop() {
    let mut cfg = AppConfig::default();
    cfg.route_mode = RouteTargetMode::Single;
    cfg.active_single_node_id = Some("n-udp".to_string());

    let udp_node = ProxyNode {
        id: "n-udp".to_string(),
        sub_id: "sub-1".to_string(),
        name: "JP HY2".to_string(),
        protocol: "hysteria2".to_string(),
        server: "198.51.100.10".to_string(),
        port: 443,
        enabled: true,
        ..ProxyNode::default()
    };
    let tcp_node = ProxyNode {
        id: "n-tcp".to_string(),
        sub_id: "sub-1".to_string(),
        name: "SG Trojan".to_string(),
        protocol: "trojan".to_string(),
        server: "198.51.100.20".to_string(),
        port: 8443,
        is_443_native: false,
        enabled: true,
        ..ProxyNode::default()
    };

    // Homepage UDP node is auto-skipped in favor of enabled TCP node.
    let (picked, note) = select_preaccel_speed_reference_node(
        &cfg,
        &[],
        &[udp_node.clone(), tcp_node.clone()],
        None,
        false,
    )
    .expect("auto-select tcp node");
    assert_eq!(picked.as_ref().map(|n| n.id.as_str()), Some("n-tcp"));
    assert!(note.is_some());

    // Explicit UDP node must fail with clear validation error.
    assert!(
        select_preaccel_speed_reference_node(
            &cfg,
            &[],
            &[udp_node.clone(), tcp_node],
            Some("n-udp"),
            false,
        )
        .is_err()
    );

    // When only UDP nodes exist, omit reference node for single-hop direct relay speed test.
    let (single_hop, single_note) =
        select_preaccel_speed_reference_node(&cfg, &[], &[udp_node], None, false)
            .expect("fallback to single-hop");
    assert!(single_hop.is_none());
    assert!(single_note.unwrap().contains("single-hop"));
}

#[test]
fn issue3_group_create_preserves_fields_and_group_members_and_policy_match_rules_work() {
    use catcloud_core::models::{DynamicFilterSpec, TriggerRule};

    let temp_root = std::env::temp_dir().join(format!(
        "catcloud-cli-issue3-group-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");
    let db = open_storage(&paths).expect("open db");

    let original = MultiGroup {
        id: "grp-issue3".to_string(),
        name: "AI Dedicated".to_string(),
        mode: MultiGroupMode::ConditionalPool,
        match_rules: vec!["DOMAIN-SUFFIX,openai.com".to_string()],
        member_node_ids: vec!["n1".to_string(), "n2".to_string()],
        dynamic_filter: Some(DynamicFilterSpec {
            region_codes: vec!["JP".to_string(), "SG".to_string()],
            max_multiplier: Some(1.0),
            ..DynamicFilterSpec::default()
        }),
        primary_probe_id: Some("probe-ai".to_string()),
        hard_gates: vec!["google_clean == 1".to_string(), "keepalive_ok == 1".to_string()],
        trigger_rules: vec![TriggerRule {
            expr: "ping_ms > 1500".to_string(),
            consecutive_failures: 3,
            bypass_cooldown_on_disconnect: true,
        }],
        formula_expr: "up_mbps * 40 - ping_ms * 0.1".to_string(),
        fallback_policy: FallbackPolicy::CrossPoolEscalate,
        fallback_pool_id: Some("grp-backup".to_string()),
        escalated_since: None,
        recover_probe_interval_sec: 90,
        switch_mode: SwitchMode::GracefulNewOnly,
        cooldown_sec: 120,
        hysteresis_pct: 35.0,
        active_node_id: Some("n1".to_string()),
        state: catcloud_core::models::MultiGroupState::Healthy,
        independent_routing: true,
    };
    db.upsert_multi_group(&original).unwrap();
    drop(db);

    // 1. Updating existing group via `group create` with only `--nodes` (omitting name/mode/fallback/switch_mode)
    //    must preserve ALL existing fields including `switch_mode` and keep `active_node_id` while still in pool.
    let (upd_out, _) = execute_group_create(
        &paths,
        GroupCreateArgs {
            id: "grp-issue3".to_string(),
            name: None,
            mode: None,
            formula: None,
            fallback: None,
            switch_mode: None,
            nodes: Some("n1,n3".to_string()),
            independent_routing: None,
            match_rules: None,
            add_match_rule: Vec::new(),
            hard_gate: Vec::new(),
        },
    )
    .expect("partial update existing group");
    assert_eq!(upd_out["created"], json!(false));
    assert_eq!(upd_out["updated"], json!(true));

    let db = open_storage(&paths).expect("reopen db");
    let after = db.get_multi_group("grp-issue3").unwrap().unwrap();
    assert_eq!(after.name, "AI Dedicated");
    assert_eq!(after.mode, MultiGroupMode::ConditionalPool);
    assert_eq!(after.fallback_policy, FallbackPolicy::CrossPoolEscalate);
    assert_eq!(after.switch_mode, SwitchMode::GracefulNewOnly);
    assert_eq!(after.hard_gates, original.hard_gates);
    assert_eq!(after.match_rules, original.match_rules);
    assert_eq!(after.trigger_rules, original.trigger_rules);
    assert_eq!(after.dynamic_filter, original.dynamic_filter);
    assert_eq!(after.primary_probe_id, original.primary_probe_id);
    assert_eq!(after.fallback_pool_id, original.fallback_pool_id);
    assert_eq!(after.independent_routing, true);
    assert_eq!(after.cooldown_sec, 120);
    assert!((after.hysteresis_pct - 35.0).abs() < 1e-6);
    assert_eq!(after.member_node_ids, vec!["n1", "n3"]);
    assert_eq!(after.active_node_id.as_deref(), Some("n1"));
    drop(db);

    // 2. `group members add / remove / set` mutates members safely without touching policy/rules.
    let (add_out, _) = execute_group_members(
        &paths,
        GroupMembersArgs {
            id: "grp-issue3".to_string(),
            action: "add".to_string(),
            nodes: "n3,n4".to_string(),
        },
    )
    .expect("members add");
    assert_eq!(add_out["added"], json!(["n4"]));
    assert_eq!(add_out["removed"], json!([]));
    assert_eq!(add_out["member_count"], json!(3));
    assert_eq!(add_out["active_node_id"], json!("n1"));

    let (rem_out, _) = execute_group_members(
        &paths,
        GroupMembersArgs {
            id: "grp-issue3".to_string(),
            action: "remove".to_string(),
            nodes: "n1".to_string(),
        },
    )
    .expect("members remove active node");
    assert_eq!(rem_out["removed"], json!(["n1"]));
    assert_eq!(rem_out["member_count"], json!(2));
    assert!(rem_out["active_node_id"].is_null());

    let (set_out, _) = execute_group_members(
        &paths,
        GroupMembersArgs {
            id: "grp-issue3".to_string(),
            action: "set".to_string(),
            nodes: "n4,n5".to_string(),
        },
    )
    .expect("members set");
    assert_eq!(set_out["added"], json!(["n5"]));
    assert_eq!(set_out["removed"], json!(["n3"]));
    assert_eq!(set_out["member_count"], json!(2));

    // 3. `group policy` match-rules add / replace / clear.
    let (pol_add, _) = execute_group_policy(
        &paths,
        GroupPolicyArgs {
            group_id: "grp-issue3".to_string(),
            formula: None,
            fallback: None,
            switch_mode: None,
            hard_gate: Vec::new(),
            match_rules: None,
            add_match_rule: vec!["DOMAIN-SUFFIX,claude.ai".to_string()],
            clear_match_rules: false,
            independent_routing: None,
        },
    )
    .expect("policy add match rule");
    assert_eq!(
        pol_add["group"]["match_rules"],
        json!(["DOMAIN-SUFFIX,openai.com", "DOMAIN-SUFFIX,claude.ai"])
    );

    let (pol_rep, _) = execute_group_policy(
        &paths,
        GroupPolicyArgs {
            group_id: "grp-issue3".to_string(),
            formula: None,
            fallback: None,
            switch_mode: None,
            hard_gate: Vec::new(),
            match_rules: Some("DOMAIN-SUFFIX,anthropic.com;DOMAIN,chatgpt.com".to_string()),
            add_match_rule: Vec::new(),
            clear_match_rules: false,
            independent_routing: None,
        },
    )
    .expect("policy replace match rules");
    assert_eq!(
        pol_rep["group"]["match_rules"],
        json!(["DOMAIN-SUFFIX,anthropic.com", "DOMAIN,chatgpt.com"])
    );

    let (pol_clr, _) = execute_group_policy(
        &paths,
        GroupPolicyArgs {
            group_id: "grp-issue3".to_string(),
            formula: None,
            fallback: None,
            switch_mode: None,
            hard_gate: Vec::new(),
            match_rules: None,
            add_match_rule: Vec::new(),
            clear_match_rules: true,
            independent_routing: None,
        },
    )
    .expect("policy clear match rules");
    assert_eq!(pol_clr["group"]["match_rules"], json!([]));

    // Verify policy/switch_mode/hard_gates remained intact throughout all mutations.
    let db = open_storage(&paths).expect("final check db");
    let final_grp = db.get_multi_group("grp-issue3").unwrap().unwrap();
    assert_eq!(final_grp.switch_mode, SwitchMode::GracefulNewOnly);
    assert_eq!(final_grp.hard_gates, original.hard_gates);
    assert_eq!(final_grp.fallback_policy, FallbackPolicy::CrossPoolEscalate);

    let _ = std::fs::remove_dir_all(&temp_root);
}

#[test]
fn emit_output_post_sanitization_masks_public_and_private_ips_while_preserving_api_openai_com() {
    let raw_sanitized = json!({
        "ok": true,
        "sanitized": true,
        "version": "0.1.0",
        "source_ip": "198.18.0.5",
        "destination_ip": "203.0.113.42",
        "host": "api.openai.com",
        "ip_host": { "host": "198.51.100.77:443" },
        "dns_note": "direct 223.5.5.5 and lan 10.20.30.40 and loopback 127.0.0.1",
        "nested": {
            "host": "github.com",
            "server": "192.168.1.99"
        }
    });
    let cleaned = finalize_output_value(&raw_sanitized);
    assert_eq!(cleaned["source_ip"], json!("198.18.0.*"));
    assert_eq!(cleaned["destination_ip"], json!("203.0.113.*"));
    assert_eq!(cleaned["host"], json!("api.openai.com"));
    assert_eq!(cleaned["nested"]["host"], json!("github.com"));
    assert_eq!(cleaned["ip_host"]["host"], json!("198.51.100.*:443"));
    assert_eq!(cleaned["nested"]["server"], json!("192.168.1.*"));
    let note = cleaned["dns_note"].as_str().unwrap();
    assert!(!note.contains("223.5.5.5"));
    assert!(!note.contains("10.20.30.40"));
    assert!(note.contains("223.5.5.*"));
    assert!(note.contains("10.20.30.*"));
    assert!(note.contains("127.0.0.1"));

    // When `sanitized` is false (`--reveal-secrets`), values must pass through untouched.
    let raw_revealed = json!({
        "ok": true,
        "sanitized": false,
        "source_ip": "198.18.0.5",
        "destination_ip": "203.0.113.42"
    });
    let revealed = finalize_output_value(&raw_revealed);
    assert_eq!(revealed["source_ip"], json!("198.18.0.5"));
    assert_eq!(revealed["destination_ip"], json!("203.0.113.42"));
}

#[tokio::test]
async fn group_eval_diag_and_global_preaccel_surface_observability_snapshots() {
    use catcloud_core::models::ProbeResultRecord;
    use catcloud_core::preaccel::global_tunnel::write_global_preaccel_runtime_meta;
    use catcloud_core::strategy::health_pool::{
        WatchdogDecisionEvent, WatchdogStateSnapshot, write_watchdog_state_snapshot,
    };

    let temp_root = std::env::temp_dir().join(format!(
        "catcloud-cli-stage19-obs-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");

    let db = open_storage(&paths).expect("open db");
    db.upsert_subscription(&SubscriptionRecord {
        id: "sub-obs".to_string(),
        name: "Obs Sub".to_string(),
        kind: SubscriptionKind::File,
        url_or_cmd: "obs.yaml".to_string(),
        ..Default::default()
    })
    .unwrap();
    db.upsert_node(&ProxyNode {
        id: "n-obs-1".to_string(),
        sub_id: "sub-obs".to_string(),
        name: "JP-Obs-1".to_string(),
        protocol: "trojan".to_string(),
        server: "203.0.113.20".to_string(),
        port: 443,
        enabled: true,
        ..ProxyNode::default()
    })
    .unwrap();
    db.insert_probe_result(&ProbeResultRecord {
        node_id: "n-obs-1".to_string(),
        probe_id: "builtin_latency".to_string(),
        tested_at: "2026-11-26T12:00:00Z".to_string(),
        ok: true,
        latency_ms: Some(45.0),
        up_mbps: Some(25.0),
        down_mbps: Some(120.0),
        google_clean: Some(true),
        keepalive_60s_ok: Some(true),
        ..ProbeResultRecord::default()
    })
    .unwrap();
    db.upsert_multi_group(&MultiGroup {
        id: "grp-obs".to_string(),
        name: "Obs Group".to_string(),
        member_node_ids: vec!["n-obs-1".to_string()],
        active_node_id: Some("n-obs-1".to_string()),
        ..MultiGroup::default()
    })
    .unwrap();
    drop(db);

    let mut wd = WatchdogStateSnapshot {
        updated_at: "2026-11-26T12:05:00Z".to_string(),
        ..WatchdogStateSnapshot::default()
    };
    wd.push_event(WatchdogDecisionEvent {
        timestamp: "2026-11-26T12:05:00Z".to_string(),
        group_id: "grp-obs".to_string(),
        group_name: "Obs Group".to_string(),
        trigger_reason: "manual_check".to_string(),
        action: "keep_active".to_string(),
        ..WatchdogDecisionEvent::default()
    });
    write_watchdog_state_snapshot(&paths.root_data_dir, &wd).unwrap();

    let (eval_out, _) = build_group_eval_payload(&paths, "grp-obs").expect("group eval");
    assert_eq!(eval_out["evaluation_mode"], json!("offline_dry_run"));
    assert_eq!(
        eval_out["evaluation"]["gate_passed"][0]["tested_at"],
        json!("2026-11-26T12:00:00.000000Z")
    );
    assert_eq!(
        eval_out["watchdog_snapshot"]["recent_events"][0]["group_id"],
        json!("grp-obs")
    );

    // Verify `config diag` and `net doctor` detect DNS TLS cert verification errors across `.1` + main log.
    std::fs::write(
        paths.logs_dir.join("catcloud.log.1"),
        "2026-11-26T03:44:51+08:00 WARN [DNS] direct-nameserver https://223.5.5.5/dns-query failed: x509: cannot validate certificate for 223.5.5.5 because it doesn't contain any IP SANs\n",
    )
    .unwrap();
    std::fs::write(paths.logs_dir.join("catcloud.log"), "").unwrap();

    let diag = build_diag_payload(&paths, false).await.expect("diag");
    assert_eq!(
        diag["dns_diagnostics"]["status"],
        json!("cert_verification_failed")
    );
    assert_eq!(diag["dns_diagnostics"]["tls_verification_preserved"], json!(true));
    assert!(!diag["warnings"].as_array().unwrap().is_empty());

    let (doctor, _) = build_net_doctor_payload(&paths).await.expect("net doctor");
    let dns_check = doctor["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "dns_tls_health")
        .expect("dns_tls_health check");
    assert_eq!(dns_check["status"], json!("fail"));
    assert_eq!(dns_check["data"]["failure_count"], json!(1));

    // Verify stale `global-preaccel-runtime.json` with a bogus dead PID does not report running=true.
    write_global_preaccel_runtime_meta(
        &paths.root_data_dir,
        &GlobalPreAccelRuntimeMeta {
            pid: Some(u32::MAX - 7),
            process_start_time_unix: Some(1_600_000_000),
            running: true,
            mode: "local_socks5".to_string(),
            effective_carrier: "standalone_socks5".to_string(),
            socks_port: Some(17999),
            updated_at: "2026-11-26T00:00:00Z".to_string(),
            ..GlobalPreAccelRuntimeMeta::default()
        },
    )
    .unwrap();
    let (gp_out, _) = build_global_preaccel_status_payload(&paths)
        .await
        .expect("global status");
    assert_eq!(gp_out["standalone_tunnel_running"], json!(false));
    assert_eq!(gp_out["runtime_meta_stale"], json!(true));
    assert_eq!(gp_out["effective_carrier"], json!("off"));

    let _ = std::fs::remove_dir_all(&temp_root);
}

#[test]
fn preaccel_global_status_carrier_aligns_with_desktop_for_zero_relays_direct_and_tun() {
    let mut cfg = AppConfig::default();
    cfg.preaccel.enabled = true;
    cfg.preaccel.global_bypass_enabled = false;

    // 1. Zero enabled relays MUST return `off` in both proxy-only and TUN modes.
    assert_eq!(
        resolve_effective_preaccel_carrier(&cfg, false, false, true, false, None, false),
        ("off", false, false, "off")
    );
    assert_eq!(
        resolve_effective_preaccel_carrier(&cfg, false, false, true, true, None, false),
        ("off", false, false, "off")
    );

    // 2. Direct proxy mode MUST return `off` in both proxy-only and TUN modes.
    assert_eq!(
        resolve_effective_preaccel_carrier(&cfg, true, true, true, false, None, false),
        ("off", false, false, "off")
    );
    assert_eq!(
        resolve_effective_preaccel_carrier(&cfg, true, true, true, true, None, false),
        ("off", false, false, "off")
    );

    // 3. Enabled relays + non-direct + live TUN reports `main_core_tun_suspended_standalone`
    //    even when `global_bypass_enabled == false` and `runtime_meta == None` (aligned with Desktop).
    assert_eq!(
        resolve_effective_preaccel_carrier(&cfg, true, false, true, true, None, false),
        (
            "main_core_tun_suspended_standalone",
            false,
            true,
            "suspended_for_tun"
        )
    );

    // 4. Enabled relays + non-direct + running core without TUN reports `main_core_proxy_only`.
    assert_eq!(
        resolve_effective_preaccel_carrier(&cfg, true, false, true, false, None, false),
        ("main_core_proxy_only", false, false, "off")
    );

    // 5. Live standalone tunnel processes report `standalone_windivert` / `standalone_socks5`.
    let wd_meta = GlobalPreAccelRuntimeMeta {
        running: true,
        mode: "windivert".to_string(),
        ..GlobalPreAccelRuntimeMeta::default()
    };
    assert_eq!(
        resolve_effective_preaccel_carrier(&cfg, true, false, false, false, Some(&wd_meta), true),
        ("standalone_windivert", true, false, "windivert")
    );
    let socks_meta = GlobalPreAccelRuntimeMeta {
        running: true,
        mode: "local_socks5".to_string(),
        ..GlobalPreAccelRuntimeMeta::default()
    };
    assert_eq!(
        resolve_effective_preaccel_carrier(&cfg, true, false, false, false, Some(&socks_meta), true),
        ("standalone_socks5", true, false, "local_socks5")
    );
}

#[test]
fn preaccel_speed_reference_node_skips_ipv6_only_for_ipv4_relay_without_breaking_dual_stack() {
    let ipv6_only = ProxyNode {
        id: "n-v6-only".to_string(),
        sub_id: "sub-1".to_string(),
        name: "JP Pure IPv6".to_string(),
        protocol: "vless".to_string(),
        server: "2001:db8:cafe::1".to_string(),
        port: 8443,
        is_443_native: false,
        enabled: true,
        ..ProxyNode::default()
    };
    let dual_stack_named_ipv6 = ProxyNode {
        id: "n-hk-dual".to_string(),
        sub_id: "sub-1".to_string(),
        name: "HK-01-IPv6".to_string(),
        protocol: "trojan".to_string(),
        server: "hk01.example.com".to_string(),
        port: 8443,
        is_443_native: false,
        enabled: true,
        ..ProxyNode::default()
    };
    let mut cfg = AppConfig::default();
    cfg.route_mode = RouteTargetMode::Single;
    cfg.active_single_node_id = Some("n-v6-only".to_string());

    // 1. Homepage IPv6-only node gracefully falls back to dual-stack `HK-01-IPv6` when relay is IPv4-only.
    let (picked, note) = select_preaccel_speed_reference_node(
        &cfg,
        &[],
        &[ipv6_only.clone(), dual_stack_named_ipv6.clone()],
        None,
        false,
    )
    .expect("fallback from IPv6-only homepage node");
    assert_eq!(picked.as_ref().map(|n| n.id.as_str()), Some("n-hk-dual"));
    assert!(note.as_deref().is_some_and(|n| n.contains("IPv6-only")));

    // 2. Dual-stack `HK-01-IPv6` is NOT skipped when selected on homepage.
    cfg.active_single_node_id = Some("n-hk-dual".to_string());
    let (picked_dual, note_dual) = select_preaccel_speed_reference_node(
        &cfg,
        &[],
        &[ipv6_only.clone(), dual_stack_named_ipv6.clone()],
        None,
        false,
    )
    .expect("dual-stack node kept");
    assert_eq!(picked_dual.as_ref().map(|n| n.id.as_str()), Some("n-hk-dual"));
    assert!(note_dual.is_none());

    // 3. When relay supports IPv6, IPv6-only homepage node is kept directly.
    cfg.active_single_node_id = Some("n-v6-only".to_string());
    let (picked_v6, note_v6) = select_preaccel_speed_reference_node(
        &cfg,
        &[],
        &[ipv6_only.clone(), dual_stack_named_ipv6.clone()],
        None,
        true,
    )
    .expect("IPv6-capable relay keeps IPv6-only node");
    assert_eq!(picked_v6.as_ref().map(|n| n.id.as_str()), Some("n-v6-only"));
    assert!(note_v6.is_none());

    // 4. Explicit requested_node_id honors user choice even for IPv6-only node.
    let (picked_explicit, note_explicit) = select_preaccel_speed_reference_node(
        &cfg,
        &[],
        &[ipv6_only.clone(), dual_stack_named_ipv6],
        Some("n-v6-only"),
        false,
    )
    .expect("explicit node honored");
    assert_eq!(picked_explicit.as_ref().map(|n| n.id.as_str()), Some("n-v6-only"));
    assert!(note_explicit.is_none());

    // 5. Only IPv6-only node with IPv4-only relay gracefully falls back to single-hop speed test.
    let (single_hop, single_note) =
        select_preaccel_speed_reference_node(&cfg, &[], &[ipv6_only], None, false)
            .expect("fallback to single-hop when only IPv6-only nodes exist");
    assert!(single_hop.is_none());
    assert!(single_note.as_deref().is_some_and(|n| n.contains("single-hop")));
}

#[tokio::test]
async fn cli_tun_state_does_not_misreport_enabled_when_live_core_reports_tun_disabled() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock controller");
    let mock_port = listener.local_addr().unwrap().port();
    let secret = "test-bp15-secret";

    let server_task = tokio::spawn(async move {
        for _ in 0..16 {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let mut req_buf = [0u8; 2048];
            let n = stream.read(&mut req_buf).await.unwrap_or(0);
            let req_str = String::from_utf8_lossy(&req_buf[..n]);
            let has_auth = req_str
                .to_ascii_lowercase()
                .contains("authorization: bearer test-bp15-secret");
            let (status_line, body) = if !has_auth {
                ("HTTP/1.1 401 Unauthorized", r#"{"message":"Unauthorized"}"#)
            } else if req_str.starts_with("GET /version ") {
                ("HTTP/1.1 200 OK", r#"{"version":"v1.19.1"}"#)
            } else if req_str.starts_with("GET /configs ") {
                (
                    "HTTP/1.1 200 OK",
                    r#"{"tun":{"enable":false},"mixed-port":17890,"port":0,"socks-port":0,"bind-address":"127.0.0.1","allow-lan":false,"mode":"rule"}"#,
                )
            } else if req_str.starts_with("GET /connections ") {
                ("HTTP/1.1 200 OK", r#"{"downloadTotal":0,"uploadTotal":0,"connections":[]}"#)
            } else {
                ("HTTP/1.1 200 OK", r#"{}"#)
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
        "catcloud-cli-live-tun-disabled-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");
    let mut cfg = config::load_or_init(&paths).expect("init config");
    cfg.controller_port = mock_port;
    cfg.controller_secret = Some(secret.to_string());
    cfg.tun.enabled = true;
    config::save(&paths, &cfg).expect("save config");

    let mut unpriv_caps = default_platform().capabilities();
    unpriv_caps.is_elevated = false;

    let active_ports = inspect_active_core_ports(&paths, &cfg).await;
    assert!(active_ports.core_running);
    assert_eq!(
        active_ports.live_config.as_ref().map(|lc| lc.tun_enable),
        Some(false)
    );

    let (tun_enabled, tun_needs_elevation, tun_source) =
        resolve_cli_effective_tun_state_with_probe(&cfg, &unpriv_caps, None, &active_ports)
            .await;
    assert!(!tun_enabled, "must NOT misreport tun_enabled=true when live /configs says false");
    assert!(tun_needs_elevation);
    assert_eq!(tun_source, "live_core_tun_disabled_needs_elevation");

    let (doctor, _) = build_net_doctor_payload(&paths).await.expect("net doctor");
    let tun_check = doctor["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "system_proxy_and_tun")
        .expect("system_proxy_and_tun check");
    assert_eq!(tun_check["data"]["tun_enabled"], json!(false));
    assert_ne!(
        tun_check["data"]["tun_runtime_source"],
        json!("live_core_with_tun_config")
    );

    server_task.abort();
    let _ = std::fs::remove_dir_all(&temp_root);
}

#[tokio::test]
async fn stage23_cli_sub_remove_syncs_active_single_node_and_signals_live_reload() {
    use catcloud_core::process_guard::{AcquireOutcome, SingleInstanceGuard};
    use std::sync::atomic::{AtomicUsize, Ordering};

    let temp_root = std::env::temp_dir().join(format!(
        "catcloud_cli_s23_subrm_{}_{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let paths = AppPaths::from_data_dir(temp_root.clone(), true).unwrap();

    {
        let db = open_storage(&paths).unwrap();
        for (sub_id, node_id, ip) in [
            ("sub-rm-1", "node-rm-1", "198.51.100.31"),
            ("sub-rm-2", "node-rm-2", "198.51.100.32"),
        ] {
            db.upsert_subscription(&SubscriptionRecord {
                id: sub_id.to_string(),
                name: format!("Sub {sub_id}"),
                kind: SubscriptionKind::File,
                url_or_cmd: format!("https://example.invalid/{sub_id}.yaml"),
                enabled: true,
                ..Default::default()
            })
            .unwrap();
            db.upsert_node(&ProxyNode {
                id: node_id.to_string(),
                sub_id: sub_id.to_string(),
                name: format!("Node {node_id}"),
                protocol: "anytls".to_string(),
                server: ip.to_string(),
                port: 443,
                raw_config: json!({
                    "name": format!("Node {node_id}"),
                    "type": "anytls",
                    "server": ip,
                    "port": 443,
                    "password": "demo-password-subrm"
                }),
                region_code: "SG".to_string(),
                multiplier: 1.0,
                is_443_native: true,
                preaccel_eligible: false,
                preaccel_override: None,
                tags: Vec::new(),
                enabled: true,
            })
            .unwrap();
        }
    }

    let mut cfg = config::load_or_init(&paths).unwrap();
    cfg.active_single_node_id = Some("node-rm-1".to_string());
    config::save(&paths, &cfg).unwrap();

    let mut guard =
        match SingleInstanceGuard::acquire(&paths.root_data_dir, Duration::ZERO).unwrap() {
            AcquireOutcome::Primary(g) => g,
            AcquireOutcome::SecondaryWokePrimary => panic!("expected primary instance"),
        };
    let reload_hits = Arc::new(AtomicUsize::new(0));
    let hits_c = Arc::clone(&reload_hits);
    guard
        .start_instance_listeners_with_reload(
            || {},
            || {},
            move || {
                hits_c.fetch_add(1, Ordering::SeqCst);
            },
        )
        .unwrap();

    // Removing `sub-rm-1` must remap `active_single_node_id` to surviving `node-rm-2` and signal reload.
    dispatch(
        &paths,
        true,
        Commands::Sub {
            action: SubCommand::Remove {
                sub_id: "sub-rm-1".to_string(),
            },
        },
    )
    .await
    .expect("sub remove #1 succeeds");

    let cfg_after_first = config::load_or_init(&paths).unwrap();
    assert_eq!(
        cfg_after_first.active_single_node_id.as_deref(),
        Some("node-rm-2")
    );
    let deadline1 = std::time::Instant::now() + Duration::from_secs(2);
    while reload_hits.load(Ordering::SeqCst) < 1 && std::time::Instant::now() < deadline1 {
        std::thread::sleep(Duration::from_millis(15));
    }
    assert!(reload_hits.load(Ordering::SeqCst) >= 1);

    // Removing the last subscription clears `active_single_node_id` to None and signals reload again.
    dispatch(
        &paths,
        true,
        Commands::Sub {
            action: SubCommand::Remove {
                sub_id: "sub-rm-2".to_string(),
            },
        },
    )
    .await
    .expect("sub remove #2 succeeds");

    let cfg_after_second = config::load_or_init(&paths).unwrap();
    assert_eq!(cfg_after_second.active_single_node_id, None);
    let deadline2 = std::time::Instant::now() + Duration::from_secs(2);
    while reload_hits.load(Ordering::SeqCst) < 2 && std::time::Instant::now() < deadline2 {
        std::thread::sleep(Duration::from_millis(15));
    }
    assert!(reload_hits.load(Ordering::SeqCst) >= 2);

    guard.release();
    let _ = std::fs::remove_dir_all(&temp_root);
}

#[tokio::test]
async fn stage23_cli_preaccel_bind_rejects_enable_when_zero_enabled_relays() {
    let temp_root = std::env::temp_dir().join(format!(
        "catcloud_cli_s23_preaccel_{}_{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let paths = AppPaths::from_data_dir(temp_root.clone(), true).unwrap();

    // Seed only a disabled relay so enabled relay count is 0.
    let mut relay = PreAccelRelay {
        id: "relay-disabled-1".to_string(),
        name: "Aliyun-SH-Disabled".to_string(),
        provider: "aliyun".to_string(),
        region: "CN-SH".to_string(),
        server: "198.51.100.44".to_string(),
        port: 443,
        protocol: "anytls".to_string(),
        password: "demo-password-preaccel".to_string(),
        skip_cert_verify: true,
        enabled: false,
        ..Default::default()
    };
    {
        let db = open_storage(&paths).unwrap();
        db.upsert_preaccel_relay(&relay).unwrap();
    }

    // 1. Attempting to enable preaccel with 0 enabled relays MUST fail with NO_ENABLED_RELAY.
    let err = dispatch(
        &paths,
        true,
        Commands::Preaccel {
            action: PreaccelCommand::Bind {
                enabled: Some(true),
                skip_443_native: None,
                probe_url: None,
                dispatch_strategy: None,
                lb_strategy: None,
            },
        },
    )
    .await
    .expect_err("enabling preaccel without enabled relays must fail");
    assert!(
        err.to_string().contains("NO_ENABLED_RELAY"),
        "expected NO_ENABLED_RELAY in error, got: {err}"
    );
    assert!(
        !config::load_or_init(&paths).unwrap().preaccel.enabled,
        "config.preaccel.enabled must stay false after rejected bind"
    );

    // 2. Disabling or adjusting non-enable flags with 0 enabled relays still succeeds.
    dispatch(
        &paths,
        true,
        Commands::Preaccel {
            action: PreaccelCommand::Bind {
                enabled: Some(false),
                skip_443_native: Some(false),
                probe_url: None,
                dispatch_strategy: None,
                lb_strategy: None,
            },
        },
    )
    .await
    .expect("disabling preaccel with 0 enabled relays must succeed");

    // 3. Once at least one relay is enabled, enabling preaccel succeeds cleanly.
    relay.enabled = true;
    {
        let db = open_storage(&paths).unwrap();
        db.upsert_preaccel_relay(&relay).unwrap();
    }
    dispatch(
        &paths,
        true,
        Commands::Preaccel {
            action: PreaccelCommand::Bind {
                enabled: Some(true),
                skip_443_native: None,
                probe_url: None,
                dispatch_strategy: None,
                lb_strategy: None,
            },
        },
    )
    .await
    .expect("enabling preaccel with >=1 enabled relay must succeed");
    assert!(config::load_or_init(&paths).unwrap().preaccel.enabled);

    let _ = std::fs::remove_dir_all(&temp_root);
}
