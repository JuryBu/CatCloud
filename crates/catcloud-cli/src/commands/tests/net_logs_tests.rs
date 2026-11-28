//! Network diagnostics (`net doctor`/`connections`/`match`), `logs tail`, and PID guard tests.

use catcloud_core::config;
use catcloud_core::core_adapter::config_compiler::PREACCEL_SELECT_GROUP_NAME;
use catcloud_core::core_adapter::{ActiveConnection, compute_file_sha256};
use catcloud_core::models::{
    MultiGroup, MultiGroupMode, PreAccelRelay, ProxyNode, SubscriptionKind, SubscriptionRecord,
};
use catcloud_core::platform::{PortListenerOwner, get_process_start_time_unix};
use catcloud_core::preaccel::global_tunnel::GlobalPreAccelRuntimeMeta;
use catcloud_core::subscription::process_attach::ProcessCandidate;
use catcloud_core::AppPaths;
use chrono::{DateTime, Local};
use serde_json::json;
use std::path::PathBuf;
use crate::commands::config_reload::is_port_owned_by_active_core;
use crate::commands::net_logs::{
    CatCloudManagedProcessFilter, build_logs_tail_payload, build_logs_tail_payload_with_options,
    build_net_doctor_payload, build_net_match_payload, classify_and_format_connections,
    collect_verified_listener_pids, evaluate_doctor_tun_state, is_catcloud_managed_proxy_process,
    is_catcloud_managed_proxy_process_with_start_time,
};
use crate::commands::preaccel::{
    evaluate_live_global_preaccel_pid, is_live_global_preaccel_pid,
    verify_managed_pid_with_start_time,
};
use crate::commands::redact_helpers::{open_storage, redact_connection_for_readonly};
use crate::commands::status_docs_update::build_status_payload;

#[test]
fn logs_tail_merges_archive_filters_by_level_and_sanitizes_output() {
    let temp_root = std::env::temp_dir().join(format!(
        "catcloud-cli-logs-tail-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");

    std::fs::write(
        paths.logs_dir.join("catcloud.log.1"),
        "2026-11-24T01:00:00Z WARN archive warn password=oldpass\n2026-11-24T01:01:00Z INFO archive info\n",
    )
    .unwrap();
    std::fs::write(
        paths.logs_dir.join("catcloud.log"),
        "2026-11-24T02:00:00Z INFO current info\n2026-11-24T02:01:00Z ERROR current err token=tok_abc host=198.51.100.77\n",
    )
    .unwrap();

    let (warn_out, _) = build_logs_tail_payload(&paths, 10, "warning").expect("warning tail");
    assert_eq!(warn_out["sanitized"], json!(true));
    let lines = warn_out["lines"].as_array().unwrap();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].as_str().unwrap().contains("password=<REDACTED>"));
    assert!(!lines[0].as_str().unwrap().contains("oldpass"));
    assert!(lines[1].as_str().unwrap().contains("token=<REDACTED>"));
    assert!(lines[1].as_str().unwrap().contains("198.51.100.*"));

    let (err_out, _) = build_logs_tail_payload(&paths, 10, "error").expect("error tail");
    assert_eq!(err_out["count"], json!(1));
    assert!(build_logs_tail_payload(&paths, 10, "invalid_lvl").is_err());

    let _ = std::fs::remove_dir_all(&temp_root);
}

#[tokio::test]
async fn net_match_and_net_doctor_work_offline_with_sanitized_output() {
    let temp_root = std::env::temp_dir().join(format!(
        "catcloud-cli-net-tools-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");

    let mut cfg = config::load_or_init(&paths).expect("init config");
    cfg.rules_override
        .global_prepend_rules
        .push("DOMAIN-SUFFIX,custom-direct.example,DIRECT".to_string());
    config::save(&paths, &cfg).expect("save config");

    let (match_direct, _) =
        build_net_match_payload(&paths, "api.custom-direct.example", "tcp", 443, None, None)
            .await
            .expect("match prepend rule");
    assert_eq!(match_direct["policy"], json!("DIRECT"));
    assert_eq!(match_direct["matched_rule_type"], json!("DOMAIN-SUFFIX"));

    let (match_quic_cn, _) =
        build_net_match_payload(&paths, "qq.com", "udp", 443, None, None)
            .await
            .expect("match domestic QUIC allow");
    assert_eq!(match_quic_cn["policy"], json!("DIRECT"));
    assert_eq!(match_quic_cn["bypass_fake_ip"], json!(true));

    let (match_quic_overseas, _) =
        build_net_match_payload(&paths, "api.openai.com", "udp", 443, None, None)
            .await
            .expect("match overseas QUIC reject");
    assert_eq!(match_quic_overseas["policy"], json!("REJECT"));

    let (doctor, _) = build_net_doctor_payload(&paths).await.expect("net doctor");
    assert_eq!(doctor["ok"], json!(true));
    assert_eq!(doctor["sanitized"], json!(true));
    let checks = doctor["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 8);
    assert!(checks.iter().any(|c| c["id"] == "dns_tls_health"));
    let geo_check = checks
        .iter()
        .find(|c| c["id"] == "geodata_status")
        .expect("geodata_status check");
    assert_eq!(
        geo_check["data"]["impact_scope"]["explicit_domain_rules_unaffected"],
        json!(true)
    );
    assert_eq!(
        match_direct["geodata_impact_scope"]["explicit_domain_rules_unaffected"],
        json!(true)
    );

    let _ = std::fs::remove_dir_all(&temp_root);
}

#[test]
fn net_doctor_tun_state_and_managed_mihomo_filter_prevent_false_positives() {
    // 1. Live Tun inbound connections or running core with tun_configured=true (when live
    //    `GET /configs` is unavailable) must not falsely claim tun_needs_elevation=true /
    //    tun_enabled=false on standard CLI; conversely, authoritative `Some(false)` MUST
    //    report `tun_enabled = false`.
    assert_eq!(
        evaluate_doctor_tun_state(true, false, true, true, None),
        (true, false, "live_tun_connections")
    );
    assert_eq!(
        evaluate_doctor_tun_state(true, false, true, false, None),
        (true, false, "live_core_with_tun_config")
    );
    assert_eq!(
        evaluate_doctor_tun_state(false, false, true, true, None),
        (true, false, "live_tun_connections")
    );
    assert_eq!(
        evaluate_doctor_tun_state(true, false, false, false, None),
        (false, true, "privilege_required")
    );
    assert_eq!(
        evaluate_doctor_tun_state(true, true, false, false, None),
        (true, false, "process_privilege")
    );
    assert_eq!(
        evaluate_doctor_tun_state(false, false, false, false, None),
        (false, false, "disabled")
    );
    assert_eq!(
        evaluate_doctor_tun_state(true, false, true, false, Some(false)),
        (false, true, "live_core_tun_disabled_needs_elevation")
    );
    assert_eq!(
        evaluate_doctor_tun_state(true, true, true, false, Some(false)),
        (false, false, "live_core_tun_disabled")
    );
    assert_eq!(
        evaluate_doctor_tun_state(true, false, true, false, Some(true)),
        (true, false, "live_core_configs")
    );

    // 2. Managed CatCloud mihomo.exe must be excluded by PID, binary path, or data dir,
    //    while genuine third-party proxy clients remain flagged as conflicts.
    let data_dir = PathBuf::from(r"C:\CatCloudPortable\data");
    let bin_dir = PathBuf::from(r"C:\CatCloudPortable\bin");
    let runtime_dir = data_dir.join("run");
    let filter = CatCloudManagedProcessFilter {
        managed_pid: Some(42420),
        managed_start_time_unix: Some(1_700_000_000),
        standalone_tunnel_pid: Some(42421),
        standalone_tunnel_start_time_unix: Some(1_700_000_100),
        mihomo_binary_path: Some(bin_dir.join("mihomo.exe")),
        owned_dirs: vec![bin_dir.clone(), runtime_dir.clone(), data_dir.clone()],
        live_controller_port: Some(19090),
        ..CatCloudManagedProcessFilter::default()
    };

    // Case A: Elevated mihomo.exe with inaccessible exe_path/cmdline matched via runtime PID + valid start time.
    let by_pid = ProcessCandidate {
        pid: 42420,
        name: "mihomo.exe".to_string(),
        exe_path: None,
        cmdline: Vec::new(),
        detected_config_dir: None,
        detected_config_file: None,
        detected_controller_addr: None,
        likely_proxy_client: true,
    };
    assert!(is_catcloud_managed_proxy_process_with_start_time(
        &by_pid,
        &filter,
        Some(1_700_000_001)
    ));
    // PID reuse guard: if OS start time drifts > 2s, the recycled PID must NOT be exempted!
    assert!(!is_catcloud_managed_proxy_process_with_start_time(
        &by_pid,
        &filter,
        Some(1_700_000_050)
    ));
    // Standalone 443 tunnel PID with valid start time is exempted.
    let standalone_tunnel = ProcessCandidate {
        pid: 42421,
        name: "mihomo.exe".to_string(),
        exe_path: None,
        cmdline: Vec::new(),
        detected_config_dir: None,
        detected_config_file: None,
        detected_controller_addr: None,
        likely_proxy_client: true,
    };
    assert!(is_catcloud_managed_proxy_process_with_start_time(
        &standalone_tunnel,
        &filter,
        Some(1_700_000_100)
    ));

    // Case B: Managed mihomo.exe matched via binary path in CatCloud bin dir.
    let by_exe = ProcessCandidate {
        pid: 55111,
        name: "mihomo.exe".to_string(),
        exe_path: Some(bin_dir.join("mihomo.exe")),
        cmdline: vec!["mihomo.exe".to_string()],
        detected_config_dir: None,
        detected_config_file: None,
        detected_controller_addr: None,
        likely_proxy_client: true,
    };
    assert!(is_catcloud_managed_proxy_process(&by_exe, &filter));

    // Case C: Managed mihomo.exe matched via `-d <data_dir>/run` config dir.
    let by_data_dir = ProcessCandidate {
        pid: 55112,
        name: "mihomo.exe".to_string(),
        exe_path: Some(PathBuf::from(r"C:\Tools\mihomo.exe")),
        cmdline: vec![
            "mihomo.exe".to_string(),
            "-d".to_string(),
            runtime_dir.to_string_lossy().to_string(),
        ],
        detected_config_dir: Some(runtime_dir.clone()),
        detected_config_file: Some(runtime_dir.join("runtime.yaml")),
        detected_controller_addr: None,
        likely_proxy_client: true,
    };
    assert!(is_catcloud_managed_proxy_process(&by_data_dir, &filter));

    // Case D: Unrelated third-party proxy client must NOT be excluded.
    let third_party = ProcessCandidate {
        pid: 66222,
        name: "clash-verge.exe".to_string(),
        exe_path: Some(PathBuf::from(r"C:\Program Files\Clash Verge\clash-verge.exe")),
        cmdline: vec!["clash-verge.exe".to_string()],
        detected_config_dir: Some(PathBuf::from(r"C:\ProgramData\ClashVerge")),
        detected_config_file: None,
        detected_controller_addr: Some("127.0.0.1:9097".to_string()),
        likely_proxy_client: true,
    };
    assert!(!is_catcloud_managed_proxy_process(&third_party, &filter));

    // Case E: Separate third-party mihomo.exe in another folder and controller port must stay flagged.
    let other_mihomo = ProcessCandidate {
        pid: 66223,
        name: "mihomo.exe".to_string(),
        exe_path: Some(PathBuf::from(r"C:\OtherClient\mihomo.exe")),
        cmdline: vec!["mihomo.exe".to_string(), "-d".to_string(), r"C:\OtherClient\cfg".to_string()],
        detected_config_dir: Some(PathBuf::from(r"C:\OtherClient\cfg")),
        detected_config_file: None,
        detected_controller_addr: Some("127.0.0.1:9099".to_string()),
        likely_proxy_client: true,
    };
    assert!(!is_catcloud_managed_proxy_process(&other_mihomo, &filter));
}

#[test]
fn net_connections_and_logs_tail_sanitize_numeric_account_dirs_and_dial_domains() {
    let raw_conn = ActiveConnection {
        id: "c-1".to_string(),
        host: "api.demo-service.com".to_string(),
        source_ip: "192.168.1.50".to_string(),
        destination_ip: "203.0.113.44".to_string(),
        process: "QQ.exe".to_string(),
        process_path: concat!(
            r"C:\",
            r"Users\Administrator\Documents\Tencent Files\0000008899\nt_qq\QQ.exe"
        )
        .to_string(),
        ..ActiveConnection::default()
    };
    let safe_conn = redact_connection_for_readonly(&raw_conn);
    assert_eq!(
        safe_conn.process_path,
        r"C:\Users\<USER>\Documents\Tencent Files\***\nt_qq\QQ.exe"
    );
    assert!(!safe_conn.process_path.contains("0000008899"));

    let temp_root = std::env::temp_dir().join(format!(
        "catcloud-cli-logs-dial-mask-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");
    std::fs::write(
        paths.logs_dir.join("catcloud.log"),
        "2026-11-26T01:05:00Z WARN dial tcp hk01.demo-vendor.com:443: i/o timeout\n\
             2026-11-26T01:05:01Z ERROR connect error: sg02.demo-node.net:8443: EOF\n",
    )
    .unwrap();

    let (tail_out, _) = build_logs_tail_payload(&paths, 10, "all").expect("logs tail");
    let lines = tail_out["lines"].as_array().unwrap();
    assert_eq!(lines.len(), 2);
    assert_eq!(
        lines[0].as_str().unwrap(),
        "2026-11-26T01:05:00Z WARN dial tcp ***.com:443: i/o timeout"
    );
    assert_eq!(
        lines[1].as_str().unwrap(),
        "2026-11-26T01:05:01Z ERROR connect error: ***.net:8443: EOF"
    );

    let _ = std::fs::remove_dir_all(&temp_root);
}

#[test]
fn logs_tail_supports_archive2_since_until_relative_and_reveal_secrets() {
    let temp_root = std::env::temp_dir().join(format!(
        "catcloud-cli-logs-since-until-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");

    std::fs::write(
        paths.logs_dir.join("catcloud.log.2"),
        "2026-11-26T01:00:00Z WARN oldest-archive2 secret=pw_arch2\n",
    )
    .unwrap();
    std::fs::write(
        paths.logs_dir.join("catcloud.log.1"),
        "2026-11-26T02:30:00Z WARN mid-archive1 ip=203.0.113.88\n",
    )
    .unwrap();
    std::fs::write(
        paths.logs_dir.join("catcloud.log"),
        "2026-11-26T03:45:00Z ERROR latest-main token=tok_live_99\n\
             2026-11-26T04:10:00Z INFO after-window\n",
    )
    .unwrap();

    let anchor_utc = DateTime::parse_from_rfc3339("2026-11-26T04:00:00Z")
        .unwrap()
        .with_timezone(&Local);

    // 1. Absolute RFC3339 window (`--since` + `--until`) reads `.2`/`.1`/primary in order and sanitizes by default.
    let (window_out, _) = build_logs_tail_payload_with_options(
        &paths,
        50,
        "all",
        Some("2026-11-26T02:00:00Z"),
        Some("2026-11-26T03:50:00Z"),
        false,
        anchor_utc,
    )
    .expect("since/until window");
    assert_eq!(
        window_out["sources"],
        json!(["catcloud.log.2", "catcloud.log.1", "catcloud.log"])
    );
    assert_eq!(window_out["sanitized"], json!(true));
    let lines = window_out["lines"].as_array().unwrap();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].as_str().unwrap().contains("mid-archive1"));
    assert!(lines[0].as_str().unwrap().contains("203.0.113.*"));
    assert!(lines[1].as_str().unwrap().contains("latest-main"));
    assert!(!lines[1].as_str().unwrap().contains("tok_live_99"));

    // 2. Relative `--since 30m` from anchor `04:00Z` -> `03:30Z..`, plus `--reveal-secrets`.
    let (rel_out, _) = build_logs_tail_payload_with_options(
        &paths,
        50,
        "error",
        Some("30m"),
        None,
        true,
        anchor_utc,
    )
    .expect("relative since + reveal");
    assert_eq!(rel_out["sanitized"], json!(false));
    let rel_lines = rel_out["lines"].as_array().unwrap();
    assert_eq!(rel_lines.len(), 1);
    assert!(rel_lines[0].as_str().unwrap().contains("tok_live_99"));

    // 3. Invalid inverted window (`since > until`) must error cleanly.
    assert!(
        build_logs_tail_payload_with_options(
            &paths,
            50,
            "all",
            Some("2026-11-26T05:00:00Z"),
            Some("2026-11-26T03:00:00Z"),
            false,
            anchor_utc,
        )
        .is_err()
    );

    let _ = std::fs::remove_dir_all(&temp_root);
}

#[test]
fn net_connections_separates_app_and_internal_connections_and_respects_reveal_secrets() {
    let conns = vec![
        ActiveConnection {
            id: "app-1".to_string(),
            conn_type: "Tun".to_string(),
            host: "api.openai.com".to_string(),
            source_ip: "198.18.0.1".to_string(),
            destination_ip: "203.0.113.55".to_string(),
            rule: "DomainSuffix".to_string(),
            chains: vec!["JP-01".to_string(), "AI-Group".to_string()],
            ..ActiveConnection::default()
        },
        ActiveConnection {
            id: "inner-1".to_string(),
            conn_type: "Inner".to_string(),
            host: "223.5.5.5".to_string(),
            source_ip: "127.0.0.1".to_string(),
            destination_ip: "223.5.5.5".to_string(),
            rule: "".to_string(),
            chains: vec!["DIRECT".to_string()],
            ..ActiveConnection::default()
        },
        ActiveConnection {
            id: "preaccel-1".to_string(),
            conn_type: "Socks5".to_string(),
            host: "198.51.100.10".to_string(),
            source_ip: "127.0.0.1".to_string(),
            destination_ip: "198.51.100.10".to_string(),
            rule: "MATCH".to_string(),
            chains: vec!["Relay-CN".to_string(), "⚖️ 预加速多云均衡".to_string()],
            ..ActiveConnection::default()
        },
    ];

    let (all_redacted, app, internal, app_count, internal_count) =
        classify_and_format_connections(&conns, 50, false);
    assert_eq!(all_redacted.len(), 3);
    assert_eq!(app_count, 1);
    assert_eq!(internal_count, 2);
    assert_eq!(app[0].id, "app-1");
    assert_eq!(app[0].host, "api.openai.com");
    assert_eq!(app[0].source_ip, "198.18.0.*");
    assert_eq!(app[0].destination_ip, "203.0.113.*");
    assert_eq!(internal[0].id, "inner-1");
    assert_eq!(internal[0].destination_ip, "223.5.5.*");
    assert_eq!(internal[1].id, "preaccel-1");
    assert_eq!(internal[1].host, "198.51.100.*");

    let (_, app_raw, _, _, _) = classify_and_format_connections(&conns, 50, true);
    assert_eq!(app_raw[0].source_ip, "198.18.0.1");
    assert_eq!(app_raw[0].destination_ip, "203.0.113.55");
}

#[test]
fn pid_reuse_guards_fail_closed_on_missing_start_time_self_pid_and_non_windows_process_name() {
    let self_pid = std::process::id();
    let other_pid = if self_pid == 42420 { 42421 } else { 42420 };

    // 1. `is_port_owned_by_active_core`: missing actual start time fails closed, self PID rejected.
    let owner_missing_ts = PortListenerOwner {
        port: 7890,
        protocol: "tcp".to_string(),
        pid: other_pid,
        process_start_time_unix: None,
    };
    assert!(!is_port_owned_by_active_core(
        7890,
        true,
        Some(other_pid),
        Some(1_700_000_000),
        &[owner_missing_ts],
        false,
    ));
    let owner_matching_ts = PortListenerOwner {
        port: 7890,
        protocol: "tcp".to_string(),
        pid: other_pid,
        process_start_time_unix: Some(1_700_000_001),
    };
    assert!(is_port_owned_by_active_core(
        7890,
        true,
        Some(other_pid),
        Some(1_700_000_000),
        &[owner_matching_ts],
        false,
    ));
    let owner_self = PortListenerOwner {
        port: 7890,
        protocol: "tcp".to_string(),
        pid: self_pid,
        process_start_time_unix: Some(1_700_000_000),
    };
    assert!(!is_port_owned_by_active_core(
        7890,
        true,
        Some(self_pid),
        Some(1_700_000_000),
        &[owner_self.clone()],
        false,
    ));

    // 2. `verify_managed_pid_with_start_time`: missing actual start time fails closed, self PID rejected.
    assert!(!verify_managed_pid_with_start_time(
        other_pid,
        "mihomo.exe",
        Some(other_pid),
        Some(1_700_000_000),
        None,
    ));
    assert!(!verify_managed_pid_with_start_time(
        self_pid,
        "mihomo.exe",
        Some(self_pid),
        Some(1_700_000_000),
        Some(1_700_000_000),
    ));
    assert!(verify_managed_pid_with_start_time(
        other_pid,
        "mihomo.exe",
        Some(other_pid),
        Some(1_700_000_000),
        Some(1_700_000_002),
    ));

    // 3. `collect_verified_listener_pids`: missing actual start time fails closed, self PID rejected.
    let verified_missing = collect_verified_listener_pids(
        &[PortListenerOwner {
            port: 19090,
            protocol: "tcp".to_string(),
            pid: other_pid,
            process_start_time_unix: None,
        }],
        Some(other_pid),
        Some(1_700_000_000),
        None,
        None,
    );
    assert!(verified_missing.is_empty());
    let verified_self = collect_verified_listener_pids(
        &[owner_self],
        Some(self_pid),
        Some(1_700_000_000),
        None,
        None,
    );
    assert!(verified_self.is_empty());
    let verified_ok = collect_verified_listener_pids(
        &[PortListenerOwner {
            port: 19090,
            protocol: "tcp".to_string(),
            pid: other_pid,
            process_start_time_unix: Some(1_700_000_002),
        }],
        Some(other_pid),
        Some(1_700_000_000),
        None,
        None,
    );
    assert!(verified_ok.contains(&other_pid));

    // 4. `is_live_global_preaccel_pid` & `evaluate_live_global_preaccel_pid`:
    //    reject self PID, fail closed on missing start time, and validate non-Windows process name.
    let self_meta = GlobalPreAccelRuntimeMeta {
        running: true,
        pid: Some(self_pid),
        process_start_time_unix: get_process_start_time_unix(self_pid),
        mode: "local_socks5".to_string(),
        ..GlobalPreAccelRuntimeMeta::default()
    };
    assert!(!is_live_global_preaccel_pid(&self_meta));

    let other_meta = GlobalPreAccelRuntimeMeta {
        running: true,
        pid: Some(other_pid),
        process_start_time_unix: Some(1_700_000_000),
        mode: "local_socks5".to_string(),
        ..GlobalPreAccelRuntimeMeta::default()
    };
    assert!(evaluate_live_global_preaccel_pid(
        &other_meta,
        Some(1_700_000_001),
        Some(Some("mihomo-linux-amd64")),
        None,
    ));
    assert!(!evaluate_live_global_preaccel_pid(
        &other_meta,
        Some(1_700_000_001),
        Some(Some("python3")),
        None,
    ));
    assert!(!evaluate_live_global_preaccel_pid(
        &other_meta,
        Some(1_700_000_001),
        Some(None),
        None,
    ));
    assert!(!evaluate_live_global_preaccel_pid(
        &other_meta,
        None,
        Some(Some("mihomo")),
        None,
    ));
}

#[tokio::test]
async fn status_and_net_doctor_emit_preaccel_transport_diagnostics_and_sanitize_private_and_public_ips()
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock controller");
    let mock_port = listener.local_addr().unwrap().port();
    let secret = "stage21-diag-secret-token";

    let proxies_body = serde_json::json!({
        "proxies": {
            PREACCEL_SELECT_GROUP_NAME: {
                "type": "Selector",
                "now": "🔄 预加速自动双活"
            },
            "🔄 预加速自动双活": {
                "type": "Fallback",
                "now": "Relay-Priv-10.23.45.67-Pub-203.0.113.88"
            },
            "AI-Stable": {
                "type": "Selector",
                "now": "Exit-Priv-192.168.88.12-Pub-198.51.100.77"
            }
        }
    })
    .to_string();

    let server_task = tokio::spawn(async move {
        for _ in 0..32 {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let mut req_buf = [0u8; 2048];
            let n = stream.read(&mut req_buf).await.unwrap_or(0);
            let req_str = String::from_utf8_lossy(&req_buf[..n]);
            let has_auth = req_str
                .to_ascii_lowercase()
                .contains("authorization: bearer stage21-diag-secret-token");
            let (status_line, body) = if !has_auth {
                ("HTTP/1.1 401 Unauthorized", r#"{"message":"Unauthorized"}"#.to_string())
            } else if req_str.starts_with("GET /version ") {
                ("HTTP/1.1 200 OK", r#"{"version":"v1.19.34"}"#.to_string())
            } else if req_str.starts_with("GET /configs ") {
                (
                    "HTTP/1.1 200 OK",
                    r#"{"tun":{"enable":true},"mixed-port":17890,"port":0,"socks-port":0,"bind-address":"127.0.0.1","allow-lan":false,"mode":"rule"}"#.to_string(),
                )
            } else if req_str.starts_with("GET /connections ") {
                (
                    "HTTP/1.1 200 OK",
                    r#"{"downloadTotal":0,"uploadTotal":0,"connections":[]}"#.to_string(),
                )
            } else if req_str.starts_with("GET /proxies ") {
                ("HTTP/1.1 200 OK", proxies_body.clone())
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
        "catcloud-cli-s21-transport-diag-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");
    let mut cfg = config::load_or_init(&paths).expect("init config");
    cfg.controller_port = mock_port;
    cfg.controller_secret = Some(secret.to_string());
    cfg.tun.enabled = true;
    cfg.tun.mtu = 1500;
    cfg.preaccel.enabled = true;
    cfg.active_group_id = Some("grp-ai".to_string());
    config::save(&paths, &cfg).expect("save config");

    let db = open_storage(&paths).expect("open db");
    db.upsert_subscription(&SubscriptionRecord {
        id: "sub-s21".to_string(),
        name: "Sub-S21".to_string(),
        kind: SubscriptionKind::File,
        url_or_cmd: "s21.yaml".to_string(),
        ..Default::default()
    })
    .expect("upsert subscription");
    db.upsert_preaccel_relay(&PreAccelRelay {
        id: "relay-s21".to_string(),
        name: "Relay-Priv-10.23.45.67-Pub-203.0.113.88".to_string(),
        provider: "cloud-a".to_string(),
        region: "CN-East".to_string(),
        server: "203.0.113.88".to_string(),
        port: 443,
        protocol: "anytls".to_string(),
        password: "demo-secret-relay-pw".to_string(),
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
        id: "node-s21".to_string(),
        sub_id: "sub-s21".to_string(),
        name: "Exit-Priv-192.168.88.12-Pub-198.51.100.77".to_string(),
        protocol: "ss".to_string(),
        server: "198.51.100.77".to_string(),
        port: 8443,
        is_443_native: false,
        preaccel_eligible: true,
        preaccel_override: None,
        enabled: true,
        raw_config: json!({
            "name": "Exit-Priv-192.168.88.12-Pub-198.51.100.77",
            "type": "ss",
            "server": "198.51.100.77",
            "port": 8443,
            "cipher": "aes-128-gcm",
            "password": "demo-secret-node-pw"
        }),
        ..Default::default()
    })
    .expect("upsert node");
    db.upsert_multi_group(&MultiGroup {
        id: "grp-ai".to_string(),
        name: "AI-Stable".to_string(),
        mode: MultiGroupMode::StickyBest,
        member_node_ids: vec!["node-s21".to_string()],
        active_node_id: Some("node-s21".to_string()),
        ..Default::default()
    })
    .expect("upsert multi group");

    let runtime_yaml_path = paths.runtime_dir.join("runtime.yaml");
    let runtime_yaml_body = "mixed-port: 17890\ntun:\n  enable: true\n  mtu: 1400\n";
    std::fs::write(&runtime_yaml_path, runtime_yaml_body).expect("write runtime.yaml");
    let expected_sha256 = compute_file_sha256(&runtime_yaml_path).expect("sha256");

    let (status_json, _) = build_status_payload(&paths).await.expect("status payload");
    let (doctor_json, _) = build_net_doctor_payload(&paths).await.expect("net doctor payload");

    for (label, payload) in [("status", &status_json), ("net_doctor", &doctor_json)] {
        let diag = &payload["preaccel_transport_diagnostics"];
        assert_eq!(diag["effective_mode"], json!("main-tun-core"), "{label}");
        assert_eq!(diag["effective_tun_mtu"], json!(1400), "{label}");
        assert_eq!(diag["anytls_tfo"], json!(false), "{label}");
        assert_eq!(diag["anytls_min_idle_session"], json!(0), "{label}");
        assert_eq!(diag["keep_alive_idle_sec"], json!(45), "{label}");
        assert_eq!(diag["keep_alive_interval_sec"], json!(15), "{label}");
        assert_eq!(diag["expected_probe_status"], json!("204"), "{label}");
        assert_eq!(diag["lb_strategy"], json!("consistent-hashing"), "{label}");
        assert_eq!(diag["probe_interval_sec"], json!(30), "{label}");

        assert_eq!(
            payload["runtime_config_sha256"],
            json!(expected_sha256),
            "{label} must preserve 64-hex runtime_config_sha256"
        );
        let relay_sel = payload["active_relay_selected"]
            .as_str()
            .expect("active_relay_selected present");
        let exit_sel = payload["active_exit_selected"]
            .as_str()
            .expect("active_exit_selected present");
        assert!(relay_sel.contains("10.23.45.*"), "{label}: {relay_sel}");
        assert!(relay_sel.contains("203.0.113.*"), "{label}: {relay_sel}");
        assert!(exit_sel.contains("192.168.88.*"), "{label}: {exit_sel}");
        assert!(exit_sel.contains("198.51.100.*"), "{label}: {exit_sel}");

        let serialized = serde_json::to_string(payload).expect("serialize payload");
        for leaked in [
            "10.23.45.67",
            "203.0.113.88",
            "192.168.88.12",
            "198.51.100.77",
            "stage21-diag-secret-token",
            "demo-secret-relay-pw",
            "demo-secret-node-pw",
        ] {
            assert!(
                !serialized.contains(leaked),
                "{label} leaked raw sensitive fixture `{leaked}`: {serialized}"
            );
        }
    }

    server_task.abort();
    let _ = std::fs::remove_dir_all(&temp_root);
}
