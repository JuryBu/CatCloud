#[allow(unused_imports)]
use super::prelude::*;

use catcloud_core::share_bundle::export_share_bundle_zip_bytes;
use catcloud_core::sync::{
    SyncRole, SyncUri, format_sync_uri, generate_random_key, plaintext_fingerprint,
    seal_with_key, seal_with_password,
};

#[test]
fn redacted_sync_preview_masks_credentials_and_exposes_group_names() {
    let node = ProxyNode {
        id: "n-secret".to_string(),
        sub_id: "sub-1".to_string(),
        name: "SG-01".to_string(),
        protocol: "vless".to_string(),
        server: "edge.demo-vendor.example".to_string(),
        port: 443,
        raw_config: serde_json::json!({
            "name": "SG-01",
            "type": "vless",
            "server": "edge.demo-vendor.example",
            "port": 443,
            "uuid": "00000000-0000-4000-8000-000000000077",
            "password": "plain_secret_password"
        }),
        ..ProxyNode::default()
    };
    let relay = PreAccelRelay {
        id: "r-secret".to_string(),
        name: "CN-Relay".to_string(),
        server: "198.51.100.88".to_string(),
        port: 443,
        protocol: "anytls".to_string(),
        password: "relay_secret_value".to_string(),
        ..PreAccelRelay::default()
    };
    let mut group = MultiGroup::default();
    group.id = "grp-ai".to_string();
    group.name = "AI Pool".to_string();
    group.member_node_ids = vec![node.id.clone()];

    let gb = build_share_groups_bundle(&[group], std::slice::from_ref(&node), Some("grp-ai"), Some("group"));
    let req = ShareBundleExportRequest {
        name: "Demo Pack".to_string(),
        description: None,
        nodes: vec![node],
        relays: vec![relay],
    };
    let (zip_bytes, _) =
        export_share_bundle_zip_bytes_with_groups(&req, Some(&gb)).expect("zip with groups");
    let fp = plaintext_fingerprint(&zip_bytes);
    let preview = preview_share_bundle_zip_bytes(&zip_bytes).expect("preview");
    let dto = build_redacted_sync_preview_dto(
        "sync-tok-1".to_string(),
        fp.clone(),
        "sync://pull".to_string(),
        preview,
    );

    assert_eq!(dto.pending_token, "sync-tok-1");
    assert_eq!(dto.fingerprint, fp);
    assert_eq!(dto.group_count, 1);
    assert_eq!(dto.group_names, vec!["AI Pool".to_string()]);
    assert_eq!(dto.preview.nodes[0].server, "***.example");
    assert_eq!(dto.preview.nodes[0].raw_config["uuid"], "<REDACTED>");
    assert_eq!(dto.preview.nodes[0].raw_config["password"], "<REDACTED>");
    assert_eq!(dto.preview.relays[0].server, "198.51.100.*");
    assert_eq!(dto.preview.relays[0].password, "<REDACTED>");
}

#[test]
fn open_ccsync_envelope_supports_file_key_uri_raw_b64_and_password() {
    let node = ProxyNode {
        id: "n-1".to_string(),
        sub_id: "sub-1".to_string(),
        name: "JP-01".to_string(),
        protocol: "vless".to_string(),
        server: "jp.example.invalid".to_string(),
        port: 443,
        raw_config: serde_json::json!({
            "name": "JP-01",
            "type": "vless",
            "server": "jp.example.invalid",
            "port": 443,
            "uuid": "00000000-0000-4000-8000-000000000002"
        }),
        ..ProxyNode::default()
    };
    let req = ShareBundleExportRequest {
        name: "Encrypted Pack".to_string(),
        description: None,
        nodes: vec![node],
        relays: Vec::new(),
    };
    let (zip_bytes, _) = export_share_bundle_zip_bytes(&req).expect("zip");
    let fp = plaintext_fingerprint(&zip_bytes);
    let key = generate_random_key().expect("key");
    let sealed = seal_with_key(&zip_bytes, &key, "").expect("seal");
    let key_uri = format_sync_uri(&SyncUri {
        role: SyncRole::FileKey,
        endpoint: None,
        hosts: Vec::new(),
        port: None,
        sid: None,
        url: None,
        fingerprint: Some(fp),
        key,
    })
    .expect("format uri");

    let opened_uri = open_ccsync_envelope_bytes(&sealed, Some(&key_uri), None)
        .expect("open via file_key uri");
    assert_eq!(opened_uri, zip_bytes);

    let key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key);
    let opened_b64 = open_ccsync_envelope_bytes(&sealed, Some(&key_b64), None)
        .expect("open via raw base64url");
    assert_eq!(opened_b64, zip_bytes);

    let sealed_pw = seal_with_password(&zip_bytes, "catcloud-test-pass", "", 2000).expect("pw");
    let opened_pw = open_ccsync_envelope_bytes(&sealed_pw, None, Some("catcloud-test-pass"))
        .expect("open via password");
    assert_eq!(opened_pw, zip_bytes);
}

#[tokio::test]
async fn relay_real_rtt_probe_detects_tls_protocols_and_never_returns_zero() {
    let tls_443 = PreAccelRelay {
        protocol: "anytls".to_string(),
        server: "198.51.100.1".to_string(),
        port: 443,
        sni: Some("ignored-on-443.example.com".to_string()),
        ..Default::default()
    };
    assert!(relay_uses_tls_probe(&tls_443));
    assert!(!relay_is_udp_quic_protocol(&tls_443));
    assert!(!relay_allows_plain_fallback(&tls_443));
    assert_eq!(resolve_relay_probe_sni_or_host(&tls_443), "198.51.100.1");

    let trojan_non443 = PreAccelRelay {
        protocol: "trojan".to_string(),
        server: "198.51.100.1".to_string(),
        port: 8443,
        sni: Some("relay.example.com".to_string()),
        ..Default::default()
    };
    assert!(relay_uses_tls_probe(&trojan_non443));
    assert!(!relay_allows_plain_fallback(&trojan_non443));
    assert_eq!(
        resolve_relay_probe_sni_or_host(&trojan_non443),
        "relay.example.com"
    );

    let ss_443 = PreAccelRelay {
        protocol: "ss".to_string(),
        server: "198.51.100.1".to_string(),
        port: 443,
        ..Default::default()
    };
    assert!(relay_uses_tls_probe(&ss_443));
    assert!(relay_allows_plain_fallback(&ss_443));

    let plain_ss = PreAccelRelay {
        protocol: "ss".to_string(),
        server: "198.51.100.1".to_string(),
        port: 8388,
        ..Default::default()
    };
    assert!(!relay_uses_tls_probe(&plain_ss));

    for udp_proto in ["tuic", "hysteria2", "hy2", "hysteria"] {
        let udp_relay = PreAccelRelay {
            protocol: udp_proto.to_string(),
            server: "198.51.100.1".to_string(),
            port: 443,
            ..Default::default()
        };
        assert!(
            relay_is_udp_quic_protocol(&udp_relay),
            "{udp_proto} must be classified as UDP/QUIC"
        );
        assert!(
            !relay_uses_tls_probe(&udp_relay),
            "{udp_proto} must never use TCP TLS probe even on port 443"
        );
    }

    let invalid = PreAccelRelay {
        protocol: "anytls".to_string(),
        server: "".to_string(),
        port: 443,
        ..Default::default()
    };
    assert!(measure_relay_real_rtt_ms(&invalid).await.is_err());

    // Local plain TCP listener should succeed and clamp to >= 0.1ms (never 0ms).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback test listener");
    let port = listener.local_addr().expect("listener addr").port();
    let accept_task = tokio::spawn(async move {
        let _ = listener.accept().await;
    });

    let local_plain = PreAccelRelay {
        protocol: "ss".to_string(),
        server: "127.0.0.1".to_string(),
        port,
        ..Default::default()
    };
    let rtt = measure_relay_real_rtt_ms(&local_plain)
        .await
        .expect("local plain tcp probe should succeed");
    assert!(rtt >= 0.1, "measured RTT must never be 0ms, got {rtt}");
    let _ = accept_task.await;

    // Local UDP listener simulates a QUIC Version Negotiation reply for Hysteria2/TUIC.
    let udp_server = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind loopback udp listener");
    let udp_port = udp_server.local_addr().expect("udp addr").port();
    let udp_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        if let Ok((_, peer)) = udp_server.recv_from(&mut buf).await {
            let _ = udp_server.send_to(b"\x80\x00\x00\x00\x00", peer).await;
        }
    });
    let local_hy2 = PreAccelRelay {
        protocol: "hysteria2".to_string(),
        server: "127.0.0.1".to_string(),
        port: udp_port,
        ..Default::default()
    };
    let udp_rtt = measure_relay_real_rtt_ms(&local_hy2)
        .await
        .expect("local udp/quic probe should succeed");
    assert!(udp_rtt >= 0.1, "measured UDP RTT must be >= 0.1ms, got {udp_rtt}");
    let _ = udp_task.await;
}

#[test]
fn runtime_info_preaccel_active_requires_running_core_or_global_engine() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_preaccel_status_test_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), true).expect("resolve test paths");
    let storage = Storage::open_in_memory().expect("open in-memory storage");
    let job_guard = Arc::new(JobGuard::new().expect("job guard"));

    let mut cfg = AppConfig::default();
    cfg.preaccel.enabled = true;

    let state = AppState::new(paths, cfg, storage, job_guard);

    // 1. Core stopped & standalone global engine off -> must NOT falsely report preaccel_active.
    let dto_idle = build_runtime_info_dto(&state).expect("build idle runtime dto");
    assert!(!dto_idle.running);
    assert!(dto_idle.preaccel_enabled);
    assert!(!dto_idle.preaccel_active);
    assert!(!dto_idle.global_preaccel_active);
    assert_eq!(dto_idle.global_preaccel_mode, "off");
    assert_eq!(dto_idle.global_preaccel_socks_port, None);
    assert_eq!(dto_idle.global_preaccel_connections, 0);
    assert_eq!(dto_idle.status, "idle");
    assert_eq!(build_tray_visual_state(&state).health, TrayHealthState::Idle);

    // 2. Core running in idle/mixed-port-only mode (system_proxy=false, tun=false) ->
    //    proxy_active is false, so preaccel_active stays false and tray remains Idle.
    state.update_cached_runtime(CoreRuntimeStatus {
        running: true,
        ..Default::default()
    });
    let dto_idle_core = build_runtime_info_dto(&state).expect("build idle-core runtime dto");
    assert!(dto_idle_core.running);
    assert!(dto_idle_core.preaccel_enabled);
    assert!(!dto_idle_core.preaccel_active);
    assert_eq!(dto_idle_core.status, "idle");
    assert_eq!(build_tray_visual_state(&state).health, TrayHealthState::Idle);

    // 3a. Core running with system proxy enabled & preaccel.enabled == true,
    //     but NO enabled preaccel relays exist -> must NOT falsely report preaccel_active.
    if let Ok(mut guard) = state.config.write() {
        let mut next = (**guard).clone();
        next.system_proxy.enabled = true;
        *guard = Arc::new(next);
    }
    let dto_no_relay = build_runtime_info_dto(&state).expect("build no-relay runtime dto");
    assert!(dto_no_relay.running);
    assert!(dto_no_relay.preaccel_enabled);
    assert!(!dto_no_relay.preaccel_active);
    assert_eq!(dto_no_relay.status, "ok");
    assert_eq!(build_tray_visual_state(&state).health, TrayHealthState::Ok);

    // 3b. Once at least one enabled preaccel relay exists ->
    //     proxy_active is true, preaccel_active is true, status == "preaccel", tray == PreAccel.
    {
        let db = state.storage.lock().expect("lock storage");
        db.upsert_preaccel_relay(&PreAccelRelay {
            id: "relay-test-1".to_string(),
            name: "国内测试中转".to_string(),
            server: "203.0.113.10".to_string(),
            port: 443,
            protocol: "trojan".to_string(),
            password: "secret".to_string(),
            enabled: true,
            ..Default::default()
        })
        .expect("insert enabled preaccel relay");
    }
    let dto_running = build_runtime_info_dto(&state).expect("build running runtime dto");
    assert!(dto_running.running);
    assert!(dto_running.preaccel_enabled);
    assert!(dto_running.preaccel_active);
    assert_eq!(dto_running.status, "preaccel");
    assert_eq!(
        build_tray_visual_state(&state).health,
        TrayHealthState::PreAccel
    );

    // 4. Core running with system proxy enabled & preaccel.enabled == false -> status == "ok".
    if let Ok(mut guard) = state.config.write() {
        let mut next = (**guard).clone();
        next.preaccel.enabled = false;
        *guard = Arc::new(next);
    }
    let dto_ok = build_runtime_info_dto(&state).expect("build ok runtime dto");
    assert!(!dto_ok.preaccel_active);
    assert_eq!(dto_ok.status, "ok");
    assert_eq!(build_tray_visual_state(&state).health, TrayHealthState::Ok);

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn relaunch_admin_args_supports_enable_global_preaccel_flag() {
    let raw = vec![
        std::ffi::OsString::from("--data-dir"),
        std::ffi::OsString::from("C:/CatCloud/data"),
    ];
    let args = collect_relaunch_admin_args_with_flags(&raw, None, false, true);
    assert!(args.iter().any(|a| a == "--restarting"));
    assert!(args.iter().any(|a| a == "--enable-global-preaccel"));
    assert!(!args.iter().any(|a| a == "--enable-tun"));
    assert!(args.iter().any(|a| a == "C:/CatCloud/data"));
}

#[test]
fn global_preaccel_settings_helpers_and_ui_dto_roundtrip() {
    assert_eq!(
        parse_global_preaccel_scope("proxy_apps_only").unwrap(),
        GlobalPreAccelScope::ProxyAppsOnly
    );
    assert_eq!(
        parse_global_preaccel_scope("all_non_443_tcp").unwrap(),
        GlobalPreAccelScope::AllNon443Tcp
    );
    assert_eq!(
        parse_global_preaccel_scope("ALL_NON_443_TCP").unwrap(),
        GlobalPreAccelScope::AllNon443Tcp
    );
    assert_eq!(
        parse_global_preaccel_scope("all_non443_tcp").unwrap(),
        GlobalPreAccelScope::AllNon443Tcp
    );
    assert_eq!(
        parse_global_preaccel_scope("ALL_NON443_TCP").unwrap(),
        GlobalPreAccelScope::AllNon443Tcp
    );
    assert!(parse_global_preaccel_scope("invalid_scope").is_err());

    let deduped = normalize_global_target_processes(vec![
        "  mihomo.exe ".to_string(),
        "".to_string(),
        "MIHOMO.EXE".to_string(),
        "scp.exe".to_string(),
    ]);
    assert_eq!(deduped, vec!["mihomo.exe".to_string(), "scp.exe".to_string()]);

    let mut cfg = AppConfig::default();
    cfg.preaccel.enabled = true;
    cfg.preaccel.campus_portal_guard = false;
    cfg.preaccel.global_bypass_enabled = true;
    cfg.preaccel.global_scope = GlobalPreAccelScope::AllNon443Tcp;
    cfg.preaccel.global_target_processes = vec!["xray.exe".to_string()];
    cfg.preaccel.windivert_dir = Some("C:/Custom/WinDivert".to_string());

    let dto = UiAppConfigDto::from(&cfg);
    assert_eq!(dto.preaccel.campus_portal_guard, Some(false));
    assert_eq!(dto.preaccel.global_bypass_enabled, Some(true));
    assert_eq!(
        dto.preaccel.global_scope,
        Some(GlobalPreAccelScope::AllNon443Tcp)
    );
    assert_eq!(
        dto.preaccel.global_target_processes,
        Some(vec!["xray.exe".to_string()])
    );
    assert_eq!(
        dto.preaccel.windivert_dir.as_deref(),
        Some("C:/Custom/WinDivert")
    );

    // Round-trip explicit `campus_portal_guard = Some(false)` onto a default config (which starts `true`).
    let mut roundtrip_cfg = AppConfig::default();
    assert!(roundtrip_cfg.preaccel.campus_portal_guard);
    apply_ui_dto(&mut roundtrip_cfg, &dto);
    assert!(!roundtrip_cfg.preaccel.campus_portal_guard);

    // Explicit empty `windivert_dir = Some("")` clears the configured path to `None`.
    let mut clear_dir_dto = dto.clone();
    clear_dir_dto.preaccel.windivert_dir = Some("".to_string());
    clear_dir_dto.preaccel.campus_portal_guard = Some(true);
    apply_ui_dto(&mut roundtrip_cfg, &clear_dir_dto);
    assert_eq!(roundtrip_cfg.preaccel.windivert_dir, None);
    assert!(roundtrip_cfg.preaccel.campus_portal_guard);

    // Legacy UI payload omitting the optional fields must preserve existing config values.
    let mut legacy_dto = dto;
    legacy_dto.preaccel.campus_portal_guard = None;
    legacy_dto.preaccel.global_bypass_enabled = None;
    legacy_dto.preaccel.global_scope = None;
    legacy_dto.preaccel.global_target_processes = None;
    legacy_dto.preaccel.windivert_dir = None;

    let mut target_cfg = cfg.clone();
    apply_ui_dto(&mut target_cfg, &legacy_dto);
    assert!(!target_cfg.preaccel.campus_portal_guard);
    assert!(target_cfg.preaccel.global_bypass_enabled);
    assert_eq!(
        target_cfg.preaccel.global_scope,
        GlobalPreAccelScope::AllNon443Tcp
    );
    assert_eq!(
        target_cfg.preaccel.global_target_processes,
        vec!["xray.exe".to_string()]
    );
    assert_eq!(
        target_cfg.preaccel.windivert_dir.as_deref(),
        Some("C:/Custom/WinDivert")
    );
}

#[test]
fn reconcile_saved_preaccel_switch_keeps_unified_master_switch_aligned() {
    let mut old = AppConfig::default();
    old.preaccel.enabled = false;
    old.preaccel.global_bypass_enabled = false;

    // Flipping `enabled` ON synchronizes `global_bypass_enabled`.
    let mut next = old.clone();
    next.preaccel.enabled = true;
    reconcile_saved_preaccel_switch(&old, &mut next);
    assert!(next.preaccel.enabled);
    assert!(next.preaccel.global_bypass_enabled);

    // Flipping legacy `global_bypass_enabled` ON while `enabled` unchanged also aligns both.
    let mut legacy_next = old.clone();
    legacy_next.preaccel.global_bypass_enabled = true;
    reconcile_saved_preaccel_switch(&old, &mut legacy_next);
    assert!(legacy_next.preaccel.enabled);
    assert!(legacy_next.preaccel.global_bypass_enabled);

    // Flipping `enabled` OFF from an active state clears both flags together.
    let mut active_old = AppConfig::default();
    active_old.preaccel.sync_unified_enabled(true);
    let mut turned_off = active_old.clone();
    turned_off.preaccel.enabled = false;
    reconcile_saved_preaccel_switch(&active_old, &mut turned_off);
    assert!(!turned_off.preaccel.enabled);
    assert!(!turned_off.preaccel.global_bypass_enabled);
}

#[test]
fn select_target_relays_ordered_preserves_request_order_and_deduplicates() {
    let make_relay = |id: &str, name: &str| PreAccelRelay {
        id: id.to_string(),
        name: name.to_string(),
        server: "198.51.100.10".to_string(),
        port: 443,
        protocol: "anytls".to_string(),
        enabled: true,
        ..Default::default()
    };
    let all = vec![
        make_relay("r1", "Relay-1"),
        make_relay("r2", "Relay-2"),
        make_relay("r3", "Relay-3"),
    ];

    let ordered = select_target_relays_ordered(
        all.clone(),
        Some(vec![
            "r3".to_string(),
            " ".to_string(),
            "r1".to_string(),
            "r3".to_string(),
            "missing".to_string(),
        ]),
    );
    let ids: Vec<&str> = ordered.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, vec!["r3", "r1"]);

    let all_default = select_target_relays_ordered(all, None);
    assert_eq!(all_default.len(), 3);
}

#[test]
fn relay_speed_latency_split_never_pollutes_last_probe_ms_with_two_hop_latency() {
    // Case 1: direct RTT failed (None), prior direct RTT was 35ms, two-hop overseas latency was 258.4ms.
    let (db_update, display_direct, chain_ms) =
        split_relay_direct_and_chain_latency(None, Some(35.0), Some(258.4));
    assert_eq!(db_update, None, "must not overwrite DB last_probe_ms with overseas latency");
    assert_eq!(display_direct, Some(35.0), "must retain prior direct RTT");
    assert_eq!(chain_ms, Some(258), "two-hop latency goes to chain_latency_ms");

    // Case 2: direct RTT failed and no prior RTT -> stays None (never 251ms).
    let (db_update2, display_direct2, chain_ms2) =
        split_relay_direct_and_chain_latency(None, None, Some(251.2));
    assert_eq!(db_update2, None);
    assert_eq!(display_direct2, None);
    assert_eq!(chain_ms2, Some(251));

    // Case 3: direct RTT succeeded (34.66ms) -> updates DB & display direct RTT cleanly.
    let (db_update3, display_direct3, chain_ms3) =
        split_relay_direct_and_chain_latency(Some(34.66), Some(50.0), Some(220.6));
    assert_eq!(db_update3, Some(34.7));
    assert_eq!(display_direct3, Some(34.7));
    assert_eq!(chain_ms3, Some(221));

    let dto = PreAccelRelaySpeedResultDto {
        relay_id: "r-1".to_string(),
        relay_name: "Relay-SH".to_string(),
        ok: true,
        latency_ms: display_direct3,
        chain_latency_ms: chain_ms3,
        up_mbps: Some(88.5),
        down_mbps: Some(172.0),
        mode: "via_node".to_string(),
        reference_node_name: Some("TW 台北 01".to_string()),
        error: None,
    };
    let serialized = serde_json::to_value(&dto).expect("serialize speed dto");
    assert_eq!(serialized["latency_ms"], 34.7);
    assert_eq!(serialized["chain_latency_ms"], 221);
}

#[test]
fn select_preaccel_relay_preserves_auto_failover_and_switches_lb_to_fallback() {
    let relay_a = PreAccelRelay {
        id: "r-ali".to_string(),
        name: "Aliyun-SH".to_string(),
        provider: "aliyun".to_string(),
        region: "CN-SH".to_string(),
        server: "198.51.100.10".to_string(),
        port: 443,
        protocol: "anytls".to_string(),
        password: "demo-password-1".to_string(),
        skip_cert_verify: true,
        priority: 10,
        enabled: true,
        ..Default::default()
    };
    let relay_b = PreAccelRelay {
        id: "r-tx".to_string(),
        name: "Tencent-GZ".to_string(),
        provider: "tencent".to_string(),
        region: "CN-GZ".to_string(),
        server: "203.0.113.20".to_string(),
        port: 443,
        protocol: "trojan".to_string(),
        password: "demo-password-2".to_string(),
        skip_cert_verify: true,
        priority: 20,
        enabled: true,
        ..Default::default()
    };

    let mut cfg = AppConfig::default();
    cfg.preaccel.enabled = true;
    cfg.preaccel.dispatch_strategy = PreAccelDispatchStrategy::LoadBalance;

    let switched_from_lb =
        apply_preaccel_relay_selection_to_config(&mut cfg, Some(&relay_b), None);
    assert!(switched_from_lb);
    assert_eq!(cfg.preaccel.dispatch_strategy, PreAccelDispatchStrategy::Fallback);
    assert_eq!(cfg.preaccel.active_relay_id.as_deref(), Some("r-tx"));
    assert!(cfg.preaccel.auto_failover);

    // Compiled plan must keep PREACCEL_FALLBACK_GROUP at index 0 of PREACCEL_SELECT_GROUP
    // and promote Tencent-GZ to index 0 of PREACCEL_FALLBACK_GROUP with Aliyun-SH + DIRECT backup.
    let plan = catcloud_core::preaccel::build_preaccel_compile_plan(
        &cfg.preaccel,
        &[relay_a.clone(), relay_b.clone()],
        &[],
    )
    .expect("compile fallback plan");
    let select_json =
        serde_json::to_value(&plan.proxy_groups[0]).expect("serialize select group");
    let select_proxies: Vec<&str> = select_json["proxies"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert_eq!(
        select_proxies[0],
        catcloud_core::core_adapter::PREACCEL_FALLBACK_GROUP_NAME
    );
    let fb_json =
        serde_json::to_value(&plan.proxy_groups[1]).expect("serialize fallback group");
    let fb_proxies: Vec<&str> = fb_json["proxies"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert_eq!(fb_proxies, vec!["Tencent-GZ", "Aliyun-SH", "DIRECT"]);

    // Switching back to Auto restores multi-cloud load-balance pool.
    let _ = apply_preaccel_relay_selection_to_config(
        &mut cfg,
        None,
        Some(PreAccelDispatchStrategy::Auto),
    );
    assert_eq!(cfg.preaccel.active_relay_id, None);
    assert_eq!(cfg.preaccel.dispatch_strategy, PreAccelDispatchStrategy::Auto);
    let lb_plan = catcloud_core::preaccel::build_preaccel_compile_plan(
        &cfg.preaccel,
        &[relay_a, relay_b],
        &[],
    )
    .expect("compile restored LB plan");
    assert!(lb_plan.lb_group_name.is_some());
}

#[test]
fn preaccel_active_relay_id_dto_roundtrip_and_auto_to_fallback_contract() {
    let relay_a = PreAccelRelay {
        id: "r-ali".to_string(),
        name: "Aliyun-SH".to_string(),
        provider: "aliyun".to_string(),
        region: "CN-SH".to_string(),
        server: "198.51.100.10".to_string(),
        port: 443,
        protocol: "anytls".to_string(),
        password: "demo-password-1".to_string(),
        priority: 10,
        enabled: true,
        ..Default::default()
    };
    let relay_b = PreAccelRelay {
        id: "r-tx".to_string(),
        name: "Tencent-GZ".to_string(),
        provider: "tencent".to_string(),
        region: "CN-GZ".to_string(),
        server: "203.0.113.20".to_string(),
        port: 443,
        protocol: "trojan".to_string(),
        password: "demo-password-2".to_string(),
        priority: 20,
        enabled: true,
        ..Default::default()
    };

    // 1. Selecting a pinned relay under `Auto` MUST switch dispatch_strategy to `Fallback`.
    let mut cfg = AppConfig::default();
    cfg.preaccel.enabled = true;
    cfg.preaccel.dispatch_strategy = PreAccelDispatchStrategy::Auto;
    cfg.preaccel.active_relay_id = None;
    let switched = apply_preaccel_relay_selection_to_config(&mut cfg, Some(&relay_a), None);
    assert!(switched, "switching from Auto multi-cloud pool to pinned relay marks switched_from_lb");
    assert_eq!(cfg.preaccel.dispatch_strategy, PreAccelDispatchStrategy::Fallback);
    assert_eq!(cfg.preaccel.active_relay_id.as_deref(), Some("r-ali"));

    // 2. UiAppConfigDto::from exposes `active_relay_id` cleanly.
    let dto_pinned = UiAppConfigDto::from(&cfg);
    assert_eq!(dto_pinned.preaccel.active_relay_id.as_deref(), Some("r-ali"));
    assert_eq!(
        dto_pinned.preaccel.dispatch_strategy,
        Some(PreAccelDispatchStrategy::Fallback)
    );

    // 3. Even if legacy stored config has `Auto + Some(id)`, `apply_ui_dto(Auto, None)` clears
    //    `active_relay_id` so multi-cloud LB activates cleanly; a dangling `active_relay_id`
    //    that does not exist in `enabled_relays` also never blocks multi-cloud LB.
    let enabled_pool = vec![relay_a.clone(), relay_b.clone()];
    let mut legacy_auto_pinned = AppConfig::default();
    legacy_auto_pinned.preaccel.enabled = true;
    legacy_auto_pinned.preaccel.dispatch_strategy = PreAccelDispatchStrategy::Auto;
    legacy_auto_pinned.preaccel.active_relay_id = Some("r-ali".to_string());

    assert!(
        !is_preaccel_pool_lb_effective(
            legacy_auto_pinned.preaccel.dispatch_strategy,
            legacy_auto_pinned.preaccel.active_relay_id.as_deref(),
            &enabled_pool,
            2
        ),
        "Auto + existing pinned active_relay_id must NOT report multi-cloud LB"
    );
    assert!(
        is_preaccel_pool_lb_effective(
            PreAccelDispatchStrategy::Auto,
            Some("r-deleted-dangling"),
            &enabled_pool,
            2
        ),
        "Auto + dangling active_relay_id MUST still activate multi-cloud LB"
    );

    let mut dto_restore_auto = UiAppConfigDto::from(&legacy_auto_pinned);
    dto_restore_auto.preaccel.dispatch_strategy = Some(PreAccelDispatchStrategy::Auto);
    dto_restore_auto.preaccel.active_relay_id = None;
    apply_ui_dto(&mut legacy_auto_pinned, &dto_restore_auto);
    assert_eq!(legacy_auto_pinned.preaccel.dispatch_strategy, PreAccelDispatchStrategy::Auto);
    assert_eq!(legacy_auto_pinned.preaccel.active_relay_id, None);
    assert!(is_preaccel_pool_lb_effective(
        legacy_auto_pinned.preaccel.dispatch_strategy,
        legacy_auto_pinned.preaccel.active_relay_id.as_deref(),
        &enabled_pool,
        2
    ));

    // Blank string `Some("  ")` under Auto also normalizes to `None`.
    legacy_auto_pinned.preaccel.active_relay_id = Some("r-ali".to_string());
    let mut dto_blank = UiAppConfigDto::from(&legacy_auto_pinned);
    dto_blank.preaccel.dispatch_strategy = Some(PreAccelDispatchStrategy::Auto);
    dto_blank.preaccel.active_relay_id = Some("   ".to_string());
    apply_ui_dto(&mut legacy_auto_pinned, &dto_blank);
    assert_eq!(legacy_auto_pinned.preaccel.active_relay_id, None);

    // 4. Fallback synchronizes `active_relay_id` (non-empty or None), while LoadBalance forces None.
    let mut dto_fb = UiAppConfigDto::from(&legacy_auto_pinned);
    dto_fb.preaccel.dispatch_strategy = Some(PreAccelDispatchStrategy::Fallback);
    dto_fb.preaccel.active_relay_id = Some(relay_b.id.clone());
    apply_ui_dto(&mut legacy_auto_pinned, &dto_fb);
    assert_eq!(legacy_auto_pinned.preaccel.dispatch_strategy, PreAccelDispatchStrategy::Fallback);
    assert_eq!(legacy_auto_pinned.preaccel.active_relay_id.as_deref(), Some("r-tx"));
    assert!(!is_preaccel_pool_lb_effective(
        legacy_auto_pinned.preaccel.dispatch_strategy,
        legacy_auto_pinned.preaccel.active_relay_id.as_deref(),
        &enabled_pool,
        2
    ));

    let mut dto_lb = UiAppConfigDto::from(&legacy_auto_pinned);
    dto_lb.preaccel.dispatch_strategy = Some(PreAccelDispatchStrategy::LoadBalance);
    dto_lb.preaccel.active_relay_id = Some("r-tx".to_string());
    apply_ui_dto(&mut legacy_auto_pinned, &dto_lb);
    assert_eq!(
        legacy_auto_pinned.preaccel.dispatch_strategy,
        PreAccelDispatchStrategy::LoadBalance
    );
    assert_eq!(legacy_auto_pinned.preaccel.active_relay_id, None);
    assert!(is_preaccel_pool_lb_effective(
        PreAccelDispatchStrategy::LoadBalance,
        Some("r-tx"),
        &enabled_pool,
        2
    ));
    assert!(!is_preaccel_pool_lb_effective(
        PreAccelDispatchStrategy::LoadBalance,
        None,
        &enabled_pool,
        1
    ));
}

#[test]
fn resolve_preaccel_effective_carrier_returns_off_in_direct_mode_including_eff_tun() {
    let mut st_susp = GlobalPreAccelStatus::default();
    st_susp.running = false;
    st_susp.mode = "suspended_for_tun".to_string();

    let st_off = GlobalPreAccelStatus::default();

    // Direct mode MUST return ("off", false) even when core is running with eff_tun=true
    // or global_status.mode == "suspended_for_tun".
    assert_eq!(
        resolve_preaccel_effective_carrier(true, true, true, true, true, true, &st_susp),
        ("off", false)
    );
    assert_eq!(
        resolve_preaccel_effective_carrier(true, true, true, true, true, true, &st_off),
        ("off", false)
    );
    assert_eq!(
        resolve_preaccel_effective_carrier(true, true, true, false, true, true, &st_off),
        ("off", false)
    );

    // Zero enabled relays also returns ("off", false) across both TUN and proxy-only modes.
    assert_eq!(
        resolve_preaccel_effective_carrier(true, false, true, true, true, false, &st_susp),
        ("off", false)
    );
    assert_eq!(
        resolve_preaccel_effective_carrier(true, false, true, false, true, false, &st_off),
        ("off", false)
    );
}

#[test]
fn select_comparison_overseas_node_skips_ipv6_only_for_ipv4_relay_without_breaking_dual_stack() {
    let ipv6_only = ProxyNode {
        id: "n-v6-only".to_string(),
        name: "🇯🇵 东京 纯IPv6".to_string(),
        protocol: "vless".to_string(),
        server: "2001:db8:cafe::1".to_string(),
        port: 8443,
        is_443_native: false,
        enabled: true,
        ..Default::default()
    };
    let dual_stack_named_ipv6 = ProxyNode {
        id: "n-hk-dual".to_string(),
        name: "HK-01-IPv6".to_string(),
        protocol: "trojan".to_string(),
        server: "hk01.example.com".to_string(),
        port: 8443,
        is_443_native: false,
        enabled: true,
        ..Default::default()
    };
    let all_nodes = vec![ipv6_only.clone(), dual_stack_named_ipv6.clone()];

    // 1. Homepage node is IPv6-only and relay does NOT support IPv6 -> gracefully falls back
    //    to dual-stack `HK-01-IPv6` without misclassifying it as IPv6-only.
    let (picked_fallback, reason_fallback) = select_comparison_overseas_node(
        &[],
        &all_nodes,
        RouteTargetMode::Single,
        Some("n-v6-only"),
        None,
        None,
        false,
    )
    .expect("IPv6-only homepage node must fallback to dual-stack node");
    assert_eq!(picked_fallback.id, "n-hk-dual");
    assert!(reason_fallback
        .as_deref()
        .is_some_and(|r| r.contains("纯 IPv6") && r.contains("HK-01-IPv6")));

    // 2. Dual-stack node named `HK-01-IPv6` is NOT skipped when selected on homepage.
    let (picked_dual, reason_dual) = select_comparison_overseas_node(
        &[],
        &all_nodes,
        RouteTargetMode::Single,
        Some("n-hk-dual"),
        None,
        None,
        false,
    )
    .expect("dual-stack node named HK-01-IPv6 must remain usable");
    assert_eq!(picked_dual.id, "n-hk-dual");
    assert!(reason_dual.is_none());

    // 3. When relay supports IPv6, IPv6-only homepage node is kept without fallback.
    let (picked_v6_supported, reason_v6_supported) = select_comparison_overseas_node(
        &[],
        &all_nodes,
        RouteTargetMode::Single,
        Some("n-v6-only"),
        None,
        None,
        true,
    )
    .expect("IPv6-capable relay should allow IPv6-only homepage node");
    assert_eq!(picked_v6_supported.id, "n-v6-only");
    assert!(reason_v6_supported.is_none());

    // 4. Explicit `requested_node_id` honors user choice even for IPv6-only node.
    let (picked_explicit, reason_explicit) = select_comparison_overseas_node(
        &[],
        &all_nodes,
        RouteTargetMode::Single,
        Some("n-hk-dual"),
        None,
        Some("n-v6-only"),
        false,
    )
    .expect("explicit requested_node_id must be honored");
    assert_eq!(picked_explicit.id, "n-v6-only");
    assert!(reason_explicit.is_none());

    // 5. Only IPv6-only nodes available with IPv4-only relay returns descriptive error.
    let err = select_comparison_overseas_node(
        &[],
        &[ipv6_only],
        RouteTargetMode::Single,
        Some("n-v6-only"),
        None,
        None,
        false,
    )
    .expect_err("only IPv6-only node with IPv4 relay should error");
    assert!(err.contains("IPv6"));
}

#[test]
fn r23_p1_3_stopped_core_infer_effective_tun_mtu_matches_should_apply_preaccel_and_ipv6() {
    let mut cfg = AppConfig::default();
    cfg.tun.mtu = 1500;
    cfg.preaccel.enabled = true;
    cfg.preaccel.skip_443_native = true;

    let ipv4_relay = PreAccelRelay {
        id: "relay-v4".to_string(),
        name: "CN-V4".to_string(),
        server: "203.0.113.10".to_string(),
        port: 443,
        protocol: "anytls".to_string(),
        password: "demo".to_string(),
        enabled: true,
        supports_ipv6: false,
        ..PreAccelRelay::default()
    };
    let ipv6_relay = PreAccelRelay {
        id: "relay-v6".to_string(),
        supports_ipv6: true,
        ..ipv4_relay.clone()
    };

    let hy2_node = ProxyNode {
        id: "n-hy2".to_string(),
        sub_id: "sub-1".to_string(),
        name: "HK-HY2".to_string(),
        protocol: "hysteria2".to_string(),
        server: "198.51.100.11".to_string(),
        port: 8443,
        enabled: true,
        ..ProxyNode::default()
    };
    let native_443_node = ProxyNode {
        id: "n-443".to_string(),
        sub_id: "sub-1".to_string(),
        name: "SG-443".to_string(),
        protocol: "vless".to_string(),
        server: "198.51.100.12".to_string(),
        port: 443,
        is_443_native: true,
        enabled: true,
        ..ProxyNode::default()
    };
    let override_off_node = ProxyNode {
        id: "n-off".to_string(),
        sub_id: "sub-1".to_string(),
        name: "JP-Off".to_string(),
        protocol: "ss".to_string(),
        server: "198.51.100.13".to_string(),
        port: 8388,
        preaccel_override: Some(false),
        enabled: true,
        ..ProxyNode::default()
    };
    let ipv6_only_node = ProxyNode {
        id: "n-v6".to_string(),
        sub_id: "sub-1".to_string(),
        name: "US-V6".to_string(),
        protocol: "vless".to_string(),
        server: "2001:db8::42".to_string(),
        port: 8443,
        enabled: true,
        ..ProxyNode::default()
    };
    let info_banner_node = ProxyNode {
        id: "n-info".to_string(),
        sub_id: "sub-1".to_string(),
        name: "剩余流量：100GB".to_string(),
        protocol: "ss".to_string(),
        server: "198.51.100.14".to_string(),
        port: 8388,
        enabled: true,
        ..ProxyNode::default()
    };

    // 1. All UDP-only / 443-native(skipped) / override-off / IPv6-only(without IPv6 relay) /
    //    info banner nodes -> NOT wrappable -> keep 1500.
    let unwrappable = vec![
        hy2_node.clone(),
        native_443_node.clone(),
        override_off_node.clone(),
        ipv6_only_node.clone(),
        info_banner_node,
    ];
    assert!(!has_preaccel_wrappable_nodes(
        &cfg,
        std::slice::from_ref(&ipv4_relay),
        &unwrappable
    ));
    assert_eq!(infer_effective_tun_mtu(&cfg, true, false), 1500);

    // 2. When relays support IPv6, IPv6-only node becomes wrappable -> clamp 1400.
    assert!(has_preaccel_wrappable_nodes(
        &cfg,
        std::slice::from_ref(&ipv6_relay),
        std::slice::from_ref(&ipv6_only_node)
    ));

    // 3. When mixed relays include one without IPv6, `relays_support_ipv6` is false -> 1500.
    assert!(!has_preaccel_wrappable_nodes(
        &cfg,
        &[ipv4_relay.clone(), ipv6_relay.clone()],
        std::slice::from_ref(&ipv6_only_node)
    ));

    // 4. Per-node `preaccel_override = Some(true)` overrides IPv6 exclusion -> wrappable.
    let mut forced_v6 = ipv6_only_node.clone();
    forced_v6.preaccel_override = Some(true);
    assert!(has_preaccel_wrappable_nodes(
        &cfg,
        std::slice::from_ref(&ipv4_relay),
        std::slice::from_ref(&forced_v6)
    ));

    // 5. Turning `skip_443_native` off wraps 443-native node -> clamp 1400.
    let mut cfg_no_skip_443 = cfg.clone();
    cfg_no_skip_443.preaccel.skip_443_native = false;
    assert!(has_preaccel_wrappable_nodes(
        &cfg_no_skip_443,
        std::slice::from_ref(&ipv4_relay),
        std::slice::from_ref(&native_443_node)
    ));

    // 6. End-to-end stopped-core `build_runtime_info_dto` reports 1500 instead of 1400 when
    //    all stored nodes are non-wrappable (HY2 + 443-native + IPv6-only over IPv4 relay).
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_r23_stopped_mtu_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), false).expect("create temp AppPaths");
    let storage = Storage::open_in_memory().expect("open memory storage");
    storage
        .upsert_subscription(&SubscriptionRecord {
            id: "sub-1".to_string(),
            name: "Demo".to_string(),
            ..SubscriptionRecord::default()
        })
        .expect("upsert sub");
    storage.upsert_node(&hy2_node).expect("upsert hy2");
    storage.upsert_node(&native_443_node).expect("upsert 443");
    storage.upsert_node(&ipv6_only_node).expect("upsert v6");
    storage
        .upsert_preaccel_relay(&ipv4_relay)
        .expect("upsert ipv4 relay");
    let state = AppState::new(
        paths,
        cfg,
        storage,
        Arc::new(JobGuard::new().expect("create JobGuard")),
    );
    let dto_unwrappable = build_runtime_info_dto(&state).expect("runtime dto unwrappable");
    assert_eq!(dto_unwrappable.effective_tun_mtu, Some(1500));

    // Upgrading the relay to IPv6-capable flips stopped-core inferred MTU to 1400.
    {
        let db = state.storage.lock().expect("lock storage");
        db.upsert_preaccel_relay(&PreAccelRelay {
            id: "relay-v4".to_string(),
            supports_ipv6: true,
            ..ipv4_relay
        })
        .expect("update relay supports_ipv6");
    }
    let dto_wrappable = build_runtime_info_dto(&state).expect("runtime dto wrappable");
    assert_eq!(dto_wrappable.effective_tun_mtu, Some(1400));

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn r23_p1_5_preaccel_config_diff_triggers_standalone_tunnel_sync_for_all_fields() {
    let base = AppConfig::default();

    // Unrelated non-preaccel config changes must NOT trigger standalone tunnel sync.
    let mut non_preaccel = base.clone();
    non_preaccel.mixed_port = base.mixed_port + 1;
    non_preaccel.personalization.language = "en".to_string();
    assert!(!should_sync_standalone_preaccel_on_config_change(
        &base,
        &non_preaccel
    ));

    // Previously missed 3 fields MUST trigger sync.
    let mut changed_interval = base.clone();
    changed_interval.preaccel.probe_interval_sec = base.preaccel.probe_interval_sec + 30;
    assert!(should_sync_standalone_preaccel_on_config_change(
        &base,
        &changed_interval
    ));

    let mut changed_failover = base.clone();
    changed_failover.preaccel.auto_failover = !base.preaccel.auto_failover;
    assert!(should_sync_standalone_preaccel_on_config_change(
        &base,
        &changed_failover
    ));

    let mut changed_fallback_probe = base.clone();
    changed_fallback_probe.preaccel.fallback_probe_url =
        "http://connect.rom.miui.com/generate_204?r23=1".to_string();
    assert!(should_sync_standalone_preaccel_on_config_change(
        &base,
        &changed_fallback_probe
    ));

    // Existing relay selection & WinDivert policy fields remain covered.
    let mut changed_strategy = base.clone();
    changed_strategy.preaccel.dispatch_strategy = PreAccelDispatchStrategy::Fallback;
    assert!(should_sync_standalone_preaccel_on_config_change(
        &base,
        &changed_strategy
    ));

    let mut changed_lb = base.clone();
    changed_lb.preaccel.lb_strategy = PreAccelLbStrategy::RoundRobin;
    assert!(should_sync_standalone_preaccel_on_config_change(
        &base,
        &changed_lb
    ));

    let mut changed_scope = base.clone();
    changed_scope.preaccel.global_scope = GlobalPreAccelScope::AllNon443Tcp;
    assert!(should_sync_standalone_preaccel_on_config_change(
        &base,
        &changed_scope
    ));

    let mut changed_dir = base.clone();
    changed_dir.preaccel.windivert_dir = Some("C:\\CustomWinDivert".to_string());
    assert!(should_sync_standalone_preaccel_on_config_change(
        &base,
        &changed_dir
    ));
}

#[test]
fn stage23_bug5_and_hotswap_zero_relay_convergence_and_tray_label() {
    // 1. Tray mode label must explicitly report `no_relay` when enabled with 0 enabled relays.
    assert_eq!(
        resolve_tray_preaccel_mode_label(true, false, false, false, false, "idle").as_deref(),
        Some("no_relay")
    );
    assert_eq!(
        resolve_tray_preaccel_mode_label(true, false, true, false, false, "ready").as_deref(),
        Some("no_relay")
    );
    assert_eq!(
        resolve_tray_preaccel_mode_label(false, false, false, false, false, "idle"),
        None
    );
    assert_eq!(
        resolve_tray_preaccel_mode_label(true, true, false, false, false, "idle").as_deref(),
        Some("standby")
    );

    // 2. Relay mutation zero-relay convergence disables unified preaccel & clears dangling ID.
    let mut cfg = AppConfig::default();
    cfg.preaccel.sync_unified_enabled(true);
    cfg.preaccel.active_relay_id = Some("relay-deleted".to_string());
    let empty_relays: HashSet<String> = HashSet::new();
    let (changed, auto_disabled) =
        converge_preaccel_after_relay_mutation(&mut cfg, &empty_relays);
    assert!(changed);
    assert!(auto_disabled);
    assert!(!cfg.preaccel.enabled);
    assert!(!cfg.preaccel.global_bypass_enabled);
    assert_eq!(cfg.preaccel.active_relay_id, None);

    // 3. Disk hot-reload in-memory reconciliation also enforces 0-relay convergence.
    let mut disk_cfg = AppConfig::default();
    disk_cfg.preaccel.enabled = true;
    disk_cfg.preaccel.global_bypass_enabled = false;
    disk_cfg.preaccel.active_relay_id = Some("missing-id".to_string());
    assert!(reconcile_disk_hot_reload_config(&mut disk_cfg, &empty_relays));
    assert!(!disk_cfg.preaccel.enabled);
    assert!(!disk_cfg.preaccel.global_bypass_enabled);
    assert_eq!(disk_cfg.preaccel.active_relay_id, None);

    // 4. With an enabled relay present, disk hot-reload preserves unified preaccel enabled.
    let mut one_relay = HashSet::new();
    one_relay.insert("relay-ok".to_string());
    let mut active_cfg = AppConfig::default();
    active_cfg.preaccel.enabled = true;
    active_cfg.preaccel.global_bypass_enabled = false;
    active_cfg.preaccel.active_relay_id = Some("relay-ok".to_string());
    assert!(reconcile_disk_hot_reload_config(&mut active_cfg, &one_relay));
    assert!(!reconcile_disk_hot_reload_config(&mut active_cfg, &one_relay));
    assert!(active_cfg.preaccel.enabled);
    assert!(active_cfg.preaccel.global_bypass_enabled);
    assert_eq!(active_cfg.preaccel.active_relay_id.as_deref(), Some("relay-ok"));
}

#[test]
fn wallpaper_encoder_resizes_and_caches_local_png_to_data_url() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_wp_test_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let cache = tmp.join("cache");
    std::fs::create_dir_all(&tmp).expect("mkdir tmp");
    let img_path = tmp.join("sample.png");
    let img = image::RgbImage::from_pixel(64, 48, image::Rgb([223, 183, 130]));
    img.save(&img_path).expect("save png");

    let url1 = encode_wallpaper_data_url_from_path(
        &img_path.display().to_string(),
        &cache,
    )
    .expect("encode first");
    assert!(url1.starts_with("data:image/jpeg;base64,"));
    let url2 = encode_wallpaper_data_url_from_path(
        &img_path.display().to_string(),
        &cache,
    )
    .expect("encode cached");
    assert_eq!(url1, url2);

    let remote = encode_wallpaper_data_url_from_path("https://example.invalid/bg.jpg", &cache)
        .expect("remote passthrough");
    assert_eq!(remote, "https://example.invalid/bg.jpg");

    assert!(
        encode_wallpaper_data_url_from_path("data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=", &cache)
            .is_err()
    );
    assert!(
        encode_wallpaper_data_url_from_path("data:image/png;base64,iVBORw0KGgo=", &cache)
            .is_ok()
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn stage21_5_save_extended_settings_rejects_invalid_or_oversized_inline_override_yaml() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_s21_5_inline_guard_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), false).expect("create temp AppPaths");
    let storage = Storage::open_in_memory().expect("open memory storage");
    let initial = AppConfig::default();
    let state = AppState::new(
        paths.clone(),
        initial.clone(),
        storage,
        Arc::new(JobGuard::new().expect("create JobGuard")),
    );

    // 1. Broken YAML syntax must be rejected with clear Chinese error.
    let bad_syntax = serde_json::json!({
        "rules_override": {
            "inline_override_yaml": "rule-providers: [\n  unclosed"
        }
    });
    let err_syntax = prepare_extended_settings_next(&state, &initial, &bad_syntax)
        .expect_err("invalid YAML syntax must fail validation");
    assert!(err_syntax.contains("内联 YAML"));

    // 2. Non-mapping top-level YAML (sequence) must be rejected.
    let bad_root = serde_json::json!({
        "rules_override": {
            "inline_override_yaml": "- DOMAIN-SUFFIX,example.invalid,DIRECT\n"
        }
    });
    let err_root = prepare_extended_settings_next(&state, &initial, &bad_root)
        .expect_err("non-mapping top-level YAML must fail validation");
    assert!(err_root.contains("内联 YAML"));

    // 3. Payload larger than 1 MiB must be rejected before disk save.
    let oversized_yaml = format!("# {}\ndns:\n  ipv6: false\n", "a".repeat(1024 * 1024));
    let bad_size = serde_json::json!({
        "rules_override": {
            "inline_override_yaml": oversized_yaml
        }
    });
    let err_size = prepare_extended_settings_next(&state, &initial, &bad_size)
        .expect_err("oversized inline YAML (> 1 MiB) must fail validation");
    assert!(err_size.contains("1 MiB"));

    // Ensure nothing dirty was written to disk or in-memory config.
    assert!(!paths.config_path.exists());
    assert_eq!(state.snapshot_config().rules_override.inline_override_yaml, None);

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn stage21_5_parse_bulk_rules_preview_ipc_wrapper_parses_and_skips_cleanly() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");

    rt.block_on(async {
        let raw = concat!(
            "# Sample Mihomo rules\n",
            "rules:\n",
            "  - 'DOMAIN-SUFFIX,example.com,DIRECT'\n",
            "  - RULE-SET,apple,DIRECT # inline comment\n",
            "  - DOMAIN-SUFFIX,example.com,DIRECT\n",
            "  - AND,((NETWORK,UDP),(DST-PORT,443)),REJECT\n",
            "  - INVALID-TYPE,foo,bar\n",
            "  - MATCH,DIRECT\n"
        );
        let parsed = parse_bulk_rules_preview(raw.to_string())
            .await
            .expect("bulk rules preview must succeed");
        assert_eq!(
            parsed.valid_rules,
            vec![
                "DOMAIN-SUFFIX,example.com,DIRECT".to_string(),
                "RULE-SET,apple,DIRECT".to_string(),
                "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT".to_string(),
                "MATCH,DIRECT".to_string(),
            ]
        );
        assert!(
            parsed
                .skipped_lines
                .iter()
                .any(|line| line.contains("INVALID-TYPE,foo,bar")),
            "invalid rule line should be recorded in skipped_lines: {:?}",
            parsed.skipped_lines
        );

        // Oversized (> 2 MiB) raw text must return friendly Chinese error.
        let huge = "DOMAIN,example.invalid,DIRECT\n".repeat(100_000);
        let err = parse_bulk_rules_preview(huge)
            .await
            .expect_err("oversized bulk rules payload should be rejected");
        assert!(err.contains("2 MiB"));
    });
}

#[test]
fn stage22_override_precheck_triggers_for_merge_patch_mode_even_without_inline_yaml() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_s22_merge_patch_precheck_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), true).unwrap();
    let storage = Storage::open_in_memory().unwrap();
    let broken_patch = tmp.join("broken_patch.yaml");
    std::fs::write(
        &broken_patch,
        "rules:\n  - DOMAIN-SUFFIX,example.invalid,NonExistentTarget\n  - MATCH,DIRECT\n",
    )
    .unwrap();

    let old = AppConfig::default();
    let state = AppState::new(
        paths,
        old.clone(),
        storage,
        Arc::new(JobGuard::new().unwrap()),
    );

    let mut next = old.clone();
    next.rules_override.override_mode = OverrideMode::MergePatch;
    next.rules_override.override_merge_path = Some(broken_patch.display().to_string());
    next.rules_override.inline_override_yaml = None;

    assert!(should_validate_inline_override_yaml(&old, &next, false));
    let err = prepare_full_config_next(&state, &old, next)
        .expect_err("MergePatch mode with broken patch file must reject even without inline YAML");
    assert!(
        err.contains("NonExistentTarget"),
        "unexpected error: {err}"
    );

    let patch_json = serde_json::json!({
        "rules_override": {
            "override_mode": "merge_patch",
            "override_merge_path": broken_patch.display().to_string()
        }
    });
    let ext_err = prepare_extended_settings_next(&state, &old, &patch_json)
        .expect_err("prepare_extended_settings_next must also reject broken MergePatch");
    assert!(
        ext_err.contains("NonExistentTarget"),
        "unexpected extended settings error: {ext_err}"
    );

    drop(state);
    let _ = std::fs::remove_dir_all(&tmp);
}
