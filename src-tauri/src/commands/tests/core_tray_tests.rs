#[allow(unused_imports)]
use super::prelude::*;

#[test]
fn ui_dto_preserves_auto_memory_tier_roundtrip() {
    let mut cfg = AppConfig::default();
    cfg.core_runtime.memory_tier = MemoryLimitTier::Auto;
    let dto = UiAppConfigDto::from(&cfg);
    assert_eq!(dto.gomemlimit_mb, 0);
    assert_eq!(dto.memory_tier, Some(MemoryLimitTier::Auto));

    let mut restored = AppConfig::default();
    restored.core_runtime.memory_tier = MemoryLimitTier::Mb96;
    apply_ui_dto(&mut restored, &dto);
    assert_eq!(restored.core_runtime.memory_tier, MemoryLimitTier::Auto);

    let mut legacy_dto = dto.clone();
    legacy_dto.memory_tier = None;
    legacy_dto.gomemlimit_mb = 64;
    apply_ui_dto(&mut restored, &legacy_dto);
    assert_eq!(restored.core_runtime.memory_tier, MemoryLimitTier::Mb64);
}

#[test]
fn mask_ip_redacts_last_segment_for_ipv4_and_ipv6() {
    assert_eq!(mask_ip_address("203.0.113.42"), "203.0.113.***");
    assert_eq!(mask_ip_address("2001:db8::1"), "2001:db8::***");
    assert_eq!(mask_ip_address(""), "--.--.--.***");
}

#[test]
fn json_deep_merge_replaces_nameserver_policy_and_empty_objects() {
    let mut base = serde_json::json!({
        "dns": {
            "ipv6": false,
            "nameserver_policy": {
                "old.example": ["1.1.1.1"],
                "keep.example": ["8.8.8.8"]
            }
        }
    });
    let patch = serde_json::json!({
        "dns": {
            "nameserver_policy": {
                "keep.example": ["9.9.9.9"]
            }
        }
    });
    json_deep_merge(&mut base, &patch);
    assert_eq!(base["dns"]["ipv6"], false);
    assert!(base["dns"]["nameserver_policy"].get("old.example").is_none());
    assert_eq!(base["dns"]["nameserver_policy"]["keep.example"][0], "9.9.9.9");

    let clear_patch = serde_json::json!({
        "dns": { "nameserver_policy": {} }
    });
    json_deep_merge(&mut base, &clear_patch);
    assert_eq!(
        base["dns"]["nameserver_policy"].as_object().map(|m| m.len()),
        Some(0)
    );
}

#[test]
fn controller_endpoint_and_secret_parser_handles_pipe_and_query_tokens() {
    assert_eq!(
        parse_controller_endpoint_and_secret("http://127.0.0.1:9090|secret=abc123"),
        ("http://127.0.0.1:9090/proxies".to_string(), Some("abc123".to_string()))
    );
    assert_eq!(
        parse_controller_endpoint_and_secret("http://127.0.0.1:9090/proxies?secret=xyz"),
        ("http://127.0.0.1:9090/proxies".to_string(), Some("xyz".to_string()))
    );
    assert_eq!(
        parse_controller_endpoint_and_secret("http://127.0.0.1:9090/"),
        ("http://127.0.0.1:9090/proxies".to_string(), None)
    );
}

#[test]
fn mihomo_error_formatter_extracts_clean_chinese_message() {
    let verbose = concat!(
        "Mihomo `-t` pre-flight check failed: ",
        "time=\"2026-11-23T09:10:12+08:00\" level=info msg=\"Start initial configuration in progress\"\n",
        "time=\"2026-11-23T09:10:12+08:00\" level=error msg=\"configuration file ",
        "C:\\\\Users\\\\<USER>\\\\runtime.yaml.tmp test failed: rules[18] [DOMAIN-SUFFIX] error: format invalid\""
    );
    let formatted = format_mihomo_error_for_user(verbose);
    assert!(formatted.contains("分流规则格式无效（DOMAIN-SUFFIX）"));
    assert!(!formatted.contains("level=info"));
    assert!(!formatted.contains("runtime.yaml.tmp"));
    assert!(!formatted.contains("time="));

    let missing_proxy = "time=\"2026-11-23T09:10:12+08:00\" level=error msg=\"configuration file C:\\\\tmp\\\\runtime-candidate.yaml test failed: proxy group Ghost not found\"";
    let formatted2 = format_mihomo_error_for_user(missing_proxy);
    assert!(formatted2.contains("不存在的代理节点或分组"));
    assert!(!formatted2.contains("runtime-candidate.yaml"));
}

#[test]
fn select_comparison_overseas_node_prefers_non443_tcp_and_skips_udp_only() {
    let udp_node = ProxyNode {
        id: "n-hy2".to_string(),
        name: "🇯🇵 HY2".to_string(),
        protocol: "hysteria2".to_string(),
        port: 8443,
        is_443_native: false,
        enabled: true,
        ..Default::default()
    };
    let native_443 = ProxyNode {
        id: "n-443".to_string(),
        name: "🇸🇬 Trojan 443".to_string(),
        protocol: "trojan".to_string(),
        port: 443,
        is_443_native: true,
        enabled: true,
        ..Default::default()
    };
    let high_port_tcp = ProxyNode {
        id: "n-8443".to_string(),
        name: "🇯🇵 VLESS 8443".to_string(),
        protocol: "vless".to_string(),
        port: 8443,
        is_443_native: false,
        enabled: true,
        ..Default::default()
    };
    let all_nodes = vec![udp_node.clone(), native_443.clone(), high_port_tcp.clone()];

    // 1. Single mode: strictly follows homepage node even if it is native 443 (no fallback).
    let (picked_single_443, reason_single_443) = select_comparison_overseas_node(
        &[],
        &all_nodes,
        RouteTargetMode::Single,
        Some("n-443"),
        None,
        None,
        false,
    )
    .expect("single mode must follow native 443 homepage node");
    assert_eq!(picked_single_443.id, "n-443");
    assert!(reason_single_443.is_none());

    // 2. Group mode: strictly follows active group's active_node_id even if native 443.
    let grp_443 = MultiGroup {
        id: "g-main".to_string(),
        name: "主力组".to_string(),
        member_node_ids: vec!["n-8443".into(), "n-443".into()],
        active_node_id: Some("n-443".to_string()),
        ..Default::default()
    };
    let (picked_grp_443, reason_grp_443) = select_comparison_overseas_node(
        &[grp_443],
        &all_nodes,
        RouteTargetMode::Group,
        None,
        Some("g-main"),
        None,
        false,
    )
    .expect("group mode must follow active_node_id even if native 443");
    assert_eq!(picked_grp_443.id, "n-443");
    assert!(reason_grp_443.is_none());

    // 3. Group mode fallback to first member when active_node_id is None.
    let grp_first_member = MultiGroup {
        id: "g-first".to_string(),
        name: "默认组".to_string(),
        member_node_ids: vec!["n-443".into(), "n-8443".into()],
        active_node_id: None,
        ..Default::default()
    };
    let (picked_first, reason_first) = select_comparison_overseas_node(
        &[grp_first_member],
        &all_nodes,
        RouteTargetMode::Group,
        None,
        Some("g-first"),
        None,
        false,
    )
    .expect("group mode should follow first member when active_node_id is None");
    assert_eq!(picked_first.id, "n-443");
    assert!(reason_first.is_none());

    // 4. Homepage node is UDP-only -> fallback to non-443 TCP node with clear Chinese reason.
    let (picked_udp_fallback, reason_udp_fallback) = select_comparison_overseas_node(
        &[],
        &all_nodes,
        RouteTargetMode::Single,
        Some("n-hy2"),
        None,
        None,
        false,
    )
    .expect("UDP-only homepage node must fallback to TCP node");
    assert_eq!(picked_udp_fallback.id, "n-8443");
    let reason_text = reason_udp_fallback.expect("UDP fallback must include reason");
    assert!(reason_text.contains("纯 UDP 协议"));
    assert!(reason_text.contains("🇯🇵 HY2"));
    assert!(reason_text.contains("🇯🇵 VLESS 8443"));

    // 5. Homepage node is UDP-only and only 443 TCP remains -> fallback to 443 TCP with reason.
    let grp_udp = MultiGroup {
        id: "g-udp".to_string(),
        name: "HY2 组".to_string(),
        member_node_ids: vec!["n-hy2".into(), "n-443".into()],
        active_node_id: Some("n-hy2".to_string()),
        ..Default::default()
    };
    let (picked_443_fallback, reason_443_fallback) = select_comparison_overseas_node(
        &[grp_udp],
        &[udp_node.clone(), native_443.clone()],
        RouteTargetMode::Group,
        None,
        Some("g-udp"),
        None,
        false,
    )
    .expect("should fallback to 443 TCP node when no non-443 TCP exists");
    assert_eq!(picked_443_fallback.id, "n-443");
    assert!(reason_443_fallback
        .as_deref()
        .is_some_and(|r| r.contains("纯 UDP 协议") && r.contains("🇸🇬 Trojan 443")));

    // 6. Reject UDP-only when explicitly requested; allow explicit 443 TCP node without fallback.
    assert!(
        select_comparison_overseas_node(
            &[],
            &[udp_node],
            RouteTargetMode::Group,
            None,
            None,
            Some("n-hy2"),
            false,
        )
        .is_err()
    );
    let (explicit_443, explicit_reason) = select_comparison_overseas_node(
        &[],
        &all_nodes,
        RouteTargetMode::Group,
        None,
        None,
        Some("n-443"),
        false,
    )
    .expect("explicit TCP node should succeed");
    assert_eq!(explicit_443.id, "n-443");
    assert!(explicit_reason.is_none());
}

#[test]
fn geoip_parsers_extract_isp_location_and_timezone() {
    let ipsb = serde_json::json!({
        "ip": "198.51.100.25",
        "isp": "NTT Communications",
        "organization": "NTT",
        "country": "Japan",
        "city": "Tokyo",
        "timezone": "Asia/Tokyo"
    });
    let r1 = parse_ipsb_geoip_json(&ipsb).expect("parse ip.sb");
    assert_eq!(r1.ip, "198.51.100.25");
    assert_eq!(r1.isp, "NTT Communications");
    assert_eq!(r1.location, "Tokyo, Japan");
    assert_eq!(r1.timezone, "Asia/Tokyo");

    let ipwho = serde_json::json!({
        "success": true,
        "ip": "203.0.113.9",
        "country": "Singapore",
        "city": "Singapore",
        "connection": { "isp": "DigitalOcean LLC", "org": "DO" },
        "timezone": { "id": "Asia/Singapore", "utc": "+08:00" }
    });
    let r2 = parse_ipwhois_json(&ipwho).expect("parse ipwho.is");
    assert_eq!(r2.location, "Singapore");
    assert_eq!(r2.isp, "DigitalOcean LLC");
    assert_eq!(r2.timezone, "Asia/Singapore");

    let trace = "fl=123\nip=203.0.113.88\nloc=JP\ncolo=NRT\n";
    let r3 = parse_cloudflare_trace(trace).expect("parse cf trace");
    assert_eq!(r3.ip, "203.0.113.88");
    assert_eq!(r3.location, "JP");
    assert!(r3.isp.contains("NRT"));
}

#[test]
fn relaunch_admin_args_preserves_data_dir_and_appends_flags() {
    let fallback = PathBuf::from("C:\\CatCloudFallback");
    let raw = vec![
        std::ffi::OsString::from("--silent"),
        std::ffi::OsString::from("--data-dir"),
        std::ffi::OsString::from("D:\\CatCloudData"),
    ];
    let args = collect_relaunch_admin_args(&raw, Some(&fallback), true);
    assert_eq!(
        args,
        vec![
            "--data-dir",
            "D:\\CatCloudData",
            "--restarting",
            "--enable-tun"
        ]
    );

    let raw_eq = vec![std::ffi::OsString::from("--data-dir=E:\\Data")];
    let args_no_tun = collect_relaunch_admin_args(&raw_eq, Some(&fallback), false);
    assert_eq!(args_no_tun, vec!["--data-dir=E:\\Data", "--restarting"]);

    let raw_no_dir = vec![std::ffi::OsString::from("--silent")];
    let args_with_fallback =
        collect_relaunch_admin_args(&raw_no_dir, Some(&fallback), true);
    assert_eq!(
        args_with_fallback,
        vec![
            "--data-dir",
            "C:\\CatCloudFallback",
            "--restarting",
            "--enable-tun"
        ]
    );
}

#[test]
fn system_proxy_ownership_check_protects_third_party_proxies() {
    let mut cfg = AppConfig::default();
    cfg.mixed_port = 7890;
    let mut rt = CoreRuntimeStatus::default();
    rt.running = true;
    rt.mixed_port = 17890;

    let own_runtime = SystemProxySpec {
        enabled: true,
        host: "127.0.0.1".to_string(),
        port: 17890,
        bypass: vec![],
        pac_url: None,
    };
    assert!(is_system_proxy_owned_by_us(&cfg, &rt, &own_runtime));

    let own_config_port = SystemProxySpec {
        enabled: true,
        host: "127.0.0.1".to_string(),
        port: 7890,
        bypass: vec![],
        pac_url: None,
    };
    assert!(is_system_proxy_owned_by_us(&cfg, &rt, &own_config_port));

    // Third-party capture proxy (e.g. Fiddler/Charles on port 8888) must NOT be cleared.
    let third_party_capture = SystemProxySpec {
        enabled: true,
        host: "127.0.0.1".to_string(),
        port: 8888,
        bypass: vec![],
        pac_url: None,
    };
    assert!(!is_system_proxy_owned_by_us(&cfg, &rt, &third_party_capture));

    // Corporate PAC must NOT be cleared even if fallback parsed host/port equals 127.0.0.1:7890.
    let corp_pac = SystemProxySpec {
        enabled: true,
        host: "127.0.0.1".to_string(),
        port: 7890,
        bypass: vec![],
        pac_url: Some("http://corp.example.invalid/wpad.dat".to_string()),
    };
    assert!(!is_system_proxy_owned_by_us(&cfg, &rt, &corp_pac));

    let own_pac = SystemProxySpec {
        enabled: true,
        host: "127.0.0.1".to_string(),
        port: 7890,
        bypass: vec![],
        pac_url: Some(format!("http://127.0.0.1:{}/proxy.pac", cfg.system_proxy.pac.port)),
    };
    // With local PAC disabled (`cfg.system_proxy.pac.enabled == false`), never claim a
    // same-port host PAC URL even while our core is running.
    assert!(!is_system_proxy_owned_by_us(&cfg, &rt, &own_pac));

    cfg.system_proxy.pac.enabled = true;
    assert!(is_system_proxy_owned_by_us(&cfg, &rt, &own_pac));
}

#[test]
fn format_tcp_host_port_brackets_ipv6_addresses() {
    assert_eq!(format_tcp_host_port("203.0.113.42", 443), "203.0.113.42:443");
    assert_eq!(
        format_tcp_host_port("relay.example.invalid", 8443),
        "relay.example.invalid:8443"
    );
    assert_eq!(
        format_tcp_host_port("2001:db8::1", 443),
        "[2001:db8::1]:443"
    );
    assert_eq!(
        format_tcp_host_port("[2001:db8::1]", 443),
        "[2001:db8::1]:443"
    );
}

#[test]
fn map_tray_click_distinguishes_all_five_actions() {
    assert_eq!(
        map_tray_click(&CoreTrayClickAction::ToggleMainWindow),
        TrayClickAction::ToggleMain
    );
    assert_eq!(
        map_tray_click(&CoreTrayClickAction::ToggleCapsule),
        TrayClickAction::ToggleCapsule
    );
    assert_eq!(
        map_tray_click(&CoreTrayClickAction::ToggleSystemProxy),
        TrayClickAction::ToggleSystemProxy
    );
    assert_eq!(
        map_tray_click(&CoreTrayClickAction::SwitchNextBest),
        TrayClickAction::SwitchNextBest
    );
    assert_eq!(
        map_tray_click(&CoreTrayClickAction::None),
        TrayClickAction::ShowMenu
    );
}

#[test]
fn build_runtime_info_dto_never_exposes_removed_ghost_active_node() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_ghost_dto_test_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), true).expect("resolve test paths");
    let storage = Storage::open_in_memory().expect("open in-memory storage");

    let sub = SubscriptionRecord {
        id: "sub-ghost".to_string(),
        name: "测试订阅".to_string(),
        kind: SubscriptionKind::Migrated,
        url_or_cmd: "local://test".to_string(),
        enabled: true,
        ..Default::default()
    };
    storage.upsert_subscription(&sub).expect("upsert sub");

    let ghost_ar = ProxyNode {
        id: "n-ar".to_string(),
        sub_id: "sub-ghost".to_string(),
        name: "🇦🇷 阿根廷幽灵".to_string(),
        region_code: "AR".to_string(),
        protocol: "trojan".to_string(),
        server: "198.51.100.1".to_string(),
        port: 443,
        enabled: true,
        ..Default::default()
    };
    let tw_member = ProxyNode {
        id: "n-tw".to_string(),
        sub_id: "sub-ghost".to_string(),
        name: "🇹🇼 台湾主力".to_string(),
        region_code: "TW".to_string(),
        protocol: "trojan".to_string(),
        server: "198.51.100.2".to_string(),
        port: 443,
        enabled: true,
        ..Default::default()
    };
    let jp_member = ProxyNode {
        id: "n-jp".to_string(),
        sub_id: "sub-ghost".to_string(),
        name: "🇯🇵 日本备用".to_string(),
        region_code: "JP".to_string(),
        protocol: "trojan".to_string(),
        server: "198.51.100.3".to_string(),
        port: 443,
        enabled: true,
        ..Default::default()
    };
    storage.upsert_node(&ghost_ar).expect("upsert ghost");
    storage.upsert_node(&tw_member).expect("upsert tw");
    storage.upsert_node(&jp_member).expect("upsert jp");

    // Persist a group whose active_node_id still points to the removed ghost node `n-ar`.
    let group = MultiGroup {
        id: "g-main".to_string(),
        name: "测试多选组".to_string(),
        mode: MultiGroupMode::StickyBest,
        member_node_ids: vec!["n-tw".to_string(), "n-jp".to_string()],
        active_node_id: Some("n-ar".to_string()),
        ..Default::default()
    };
    storage.upsert_multi_group(&group).expect("upsert group");

    let mut cfg = AppConfig::default();
    cfg.route_mode = RouteTargetMode::Group;
    cfg.active_group_id = Some("g-main".to_string());

    let job_guard = Arc::new(JobGuard::new().expect("job guard"));
    let state = AppState::new(paths, cfg, storage, job_guard);

    let dto = build_runtime_info_dto(&state).expect("build runtime dto");
    assert_ne!(dto.active_node_id, "n-ar");
    assert_ne!(dto.active_node_name, "🇦🇷 阿根廷幽灵");
    assert_eq!(dto.active_node_id, "n-tw");
    assert_eq!(dto.active_node_name, "🇹🇼 台湾主力");

    let visual = build_tray_visual_state(&state);
    assert!(!visual.tooltip.contains("阿根廷幽灵"));
    assert!(visual.tooltip.contains("台湾主力"));

    let nodes_slice = [ghost_ar, tw_member, jp_member];
    let node_by_id: HashMap<&str, &ProxyNode> =
        nodes_slice.iter().map(|n| (n.id.as_str(), n)).collect();
    let tray_candidates = select_tray_group_candidates(&group, &nodes_slice, &node_by_id, 8);
    assert!(!tray_candidates.iter().any(|n| n.id == "n-ar"));
    assert_eq!(tray_candidates[0].id, "n-tw");

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn summarize_connections_excludes_inner_tunnels_and_splits_direct_vs_proxied() {
    use catcloud_core::core_adapter::ActiveConnection;

    let conns = vec![
        ActiveConnection {
            id: "c1".to_string(),
            conn_type: "Inner".to_string(),
            chains: vec!["PreAccel-Relay".to_string()],
            ..Default::default()
        },
        ActiveConnection {
            id: "c2".to_string(),
            conn_type: "inner".to_string(),
            chains: vec!["PreAccel-Relay".to_string()],
            ..Default::default()
        },
        ActiveConnection {
            id: "c3".to_string(),
            conn_type: "HTTP".to_string(),
            chains: vec!["DIRECT".to_string()],
            rule: "GEOIP".to_string(),
            ..Default::default()
        },
        ActiveConnection {
            id: "c4".to_string(),
            conn_type: "TUN".to_string(),
            chains: vec!["Proxy".to_string(), "JP-01".to_string()],
            rule: "MATCH".to_string(),
            ..Default::default()
        },
        ActiveConnection {
            id: "c5".to_string(),
            conn_type: "SOCKS5".to_string(),
            chains: vec!["AI".to_string(), "US-01".to_string()],
            rule: "DOMAIN-SUFFIX".to_string(),
            ..Default::default()
        },
        ActiveConnection {
            id: "c6".to_string(),
            conn_type: "TUN".to_string(),
            chains: vec!["REJECT".to_string()],
            rule: "AND".to_string(),
            ..Default::default()
        },
        ActiveConnection {
            id: "c7".to_string(),
            conn_type: "TUN".to_string(),
            chains: vec!["REJECT-DROP".to_string()],
            rule: "REJECT-DROP".to_string(),
            ..Default::default()
        },
    ];

    let summary = summarize_connections(&conns);
    assert_eq!(summary.tunnel_connections, 2);
    assert_eq!(summary.app_connections, 5);
    assert_eq!(summary.direct_connections, 1);
    assert_eq!(summary.proxied_connections, 2);
}

#[test]
fn high_throughput_guard_protects_minimized_window_via_recent_ticks() {
    let threshold = WATCHDOG_HIGH_THROUGHPUT_THRESHOLD_BPS;
    let window_ms = WATCHDOG_HIGH_THROUGHPUT_WINDOW_MS;
    let now_ms: i64 = 1_700_000_050_000;

    // 1. Live cached metrics above threshold immediately protect.
    let active_cached = CachedRealtimeMetrics {
        up_bps: threshold,
        down_bps: 0,
        ..Default::default()
    };
    assert!(is_high_throughput_active(
        &active_cached,
        &[],
        now_ms,
        window_ms,
        threshold
    ));

    // 2. Window minimized -> cached metrics zeroed, but recent tick within 10s window was
    //    uploading at 4 MiB/s -> MUST still protect active upload.
    let zeroed_cached = CachedRealtimeMetrics::default();
    let recent_ticks = vec![
        TrafficTick {
            up: 16 * 1024,
            down: 32 * 1024,
            timestamp_ms: now_ms - 8_000,
        },
        TrafficTick {
            up: 4 * 1024 * 1024,
            down: 64 * 1024,
            timestamp_ms: now_ms - 4_000,
        },
    ];
    assert!(is_high_throughput_active(
        &zeroed_cached,
        &recent_ticks,
        now_ms,
        window_ms,
        threshold
    ));

    // 3. Stale high-throughput tick older than the 10s window does NOT block failover.
    let stale_ticks = vec![TrafficTick {
        up: 10 * 1024 * 1024,
        down: 10 * 1024 * 1024,
        timestamp_ms: now_ms - window_ms - 500,
    }];
    assert!(!is_high_throughput_active(
        &zeroed_cached,
        &stale_ticks,
        now_ms,
        window_ms,
        threshold
    ));

    // 4. Low idle heartbeat traffic inside window does NOT block failover.
    let idle_ticks = vec![TrafficTick {
        up: 12 * 1024,
        down: 48 * 1024,
        timestamp_ms: now_ms - 1_000,
    }];
    assert!(!is_high_throughput_active(
        &zeroed_cached,
        &idle_ticks,
        now_ms,
        window_ms,
        threshold
    ));
}

#[test]
fn is_proxy_takeover_active_requires_running_core_and_system_proxy_or_tun() {
    let mut cfg = AppConfig::default();
    cfg.system_proxy.enabled = false;
    cfg.tun.enabled = false;

    // Idle core (running without system proxy or TUN) must NOT count as active proxy takeover.
    assert!(!is_proxy_takeover_active(false, &cfg, true));
    assert!(!is_proxy_takeover_active(true, &cfg, true));

    // System proxy enabled -> active only while core is running (regardless of TUN privilege).
    cfg.system_proxy.enabled = true;
    assert!(!is_proxy_takeover_active(false, &cfg, false));
    assert!(is_proxy_takeover_active(true, &cfg, false));
    assert!(is_proxy_takeover_active(true, &cfg, true));

    // TUN enabled -> active ONLY when core is running AND TUN privileges are satisfied.
    cfg.system_proxy.enabled = false;
    cfg.tun.enabled = true;
    assert!(!is_proxy_takeover_active(false, &cfg, true));
    assert!(!is_proxy_takeover_active(true, &cfg, false));
    assert!(is_proxy_takeover_active(true, &cfg, true));

    // Both enabled -> active while core is running even if TUN lacks privilege (via system proxy).
    cfg.system_proxy.enabled = true;
    assert!(is_proxy_takeover_active(true, &cfg, false));
    assert!(is_proxy_takeover_active(true, &cfg, true));
}

#[test]
fn runtime_info_and_health_pool_latency_and_sub_refresh_guard_behave_accurately() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_stage12_runtime_pool_test_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), true).expect("resolve test paths");
    let storage = Storage::open_in_memory().expect("open in-memory storage");
    let job_guard = Arc::new(JobGuard::new().expect("job guard"));
    let state = AppState::new(paths, AppConfig::default(), storage, job_guard);

    let stale_snap = ProbeSnapshot {
        node_id: "n-1".to_string(),
        ok: true,
        latency_ms: Some(210.0),
        ..Default::default()
    };
    assert_eq!(state.resolve_node_latency_ms("n-1", Some(&stale_snap)), Some(210.0));

    // Live FullHealthy probe overrides stale SQLite latency and populates health hints.
    state.record_node_health_probe("n-1", RuntimeDualHealth::FullHealthy, Some(68.0));
    assert_eq!(state.resolve_node_latency_ms("n-1", Some(&stale_snap)), Some(68.0));

    let dto = build_runtime_info_dto(&state).expect("build runtime dto");
    assert!(!dto.global_windivert_active);
    assert!(!dto.preaccel_install_state.is_empty());
    let hint = dto
        .node_health_hints
        .get("n-1")
        .expect("node health hint should be exported");
    assert_eq!(hint.status, "healthy");
    assert_eq!(hint.latency_ms, Some(68.0));
    assert_eq!(hint.cooldown_remaining_sec, 0);

    // Confirmed Failed probe clears stale SQLite latency and marks cooldown in hints.
    state.record_node_health_probe("n-1", RuntimeDualHealth::Failed, None);
    assert_eq!(state.resolve_node_latency_ms("n-1", Some(&stale_snap)), None);
    let failed_hints = state.snapshot_node_health_hints();
    let failed_hint = failed_hints.get("n-1").expect("failed hint");
    assert_eq!(failed_hint.status, "cooldown");
    assert_eq!(failed_hint.latency_ms, None);
    assert!(failed_hint.cooldown_remaining_sec > 0);

    // SubRefreshGuard prevents concurrent duplicate refreshes for the same subscription ID.
    {
        let guard_a = SubRefreshGuard::try_acquire(&state.refreshing_sub_ids, "sub-1".into());
        assert!(guard_a.is_some());
        let guard_dup = SubRefreshGuard::try_acquire(&state.refreshing_sub_ids, "sub-1".into());
        assert!(guard_dup.is_none());
        let guard_other = SubRefreshGuard::try_acquire(&state.refreshing_sub_ids, "sub-2".into());
        assert!(guard_other.is_some());
    }
    assert!(
        SubRefreshGuard::try_acquire(&state.refreshing_sub_ids, "sub-1".into()).is_some(),
        "dropping previous guard must release subscription refresh lock"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn tray_visual_state_reflects_probing_and_degraded_verify_states() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_tray_verify_state_test_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), true).expect("resolve test paths");
    let storage = Storage::open_in_memory().expect("open in-memory storage");
    let job_guard = Arc::new(JobGuard::new().expect("job guard"));

    let mut cfg = AppConfig::default();
    cfg.preaccel.enabled = true;
    let state = AppState::new(paths, cfg, storage, job_guard);

    let degraded = build_tray_visual_state_with_verify_override(&state, Some(("degraded", None)));
    assert_eq!(degraded.health, TrayHealthState::Warn);
    assert_eq!(degraded.global_preaccel_verify_state, "degraded");
    assert!(degraded
        .tooltip
        .contains("已保护回退（请查看国内提速环境放行指引）"));

    let probing = build_tray_visual_state_with_verify_override(&state, Some(("probing", None)));
    assert_ne!(probing.health, TrayHealthState::PreAccel);
    assert_eq!(probing.global_preaccel_verify_state, "probing");
    assert!(probing.tooltip.contains("探测链路中…"));
    assert!(!probing.tooltip.contains("全局提速中"));

    let dto_degraded =
        build_runtime_info_dto_with_verify_override(&state, Some(("degraded", None)))
            .expect("build degraded dto");
    assert_eq!(dto_degraded.status, "warn");
    assert_eq!(dto_degraded.global_preaccel_verify_state, "degraded");

    let dto_probing =
        build_runtime_info_dto_with_verify_override(&state, Some(("probing", None)))
            .expect("build probing dto");
    assert!(!dto_probing.preaccel_active);
    assert_eq!(dto_probing.global_preaccel_verify_state, "probing");

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn global_to_rule_heap_reclaim_guard_enforces_all_safety_gates() {
    let base = HeapReclaimCheckInput {
        gen_matches: true,
        is_rule_mode: true,
        core_running: true,
        tun_enabled: false,
        proxied_connections: 0,
        direct_connections: 0,
        traffic_telemetry_fresh: true,
        total_bytes_per_sec: 1024,
        probing_active: false,
        memory_mb: 112.0,
        budget_mb: 64.0,
        cooldown_elapsed: true,
    };
    let threshold = evaluate_heap_reclaim_guard(&base).expect("base case should trigger");
    assert!((threshold - 96.0).abs() < 0.01);

    // Stepped retry schedule must stay strictly bounded (`[8s, 30s, 90s]`).
    assert_eq!(HEAP_RECLAIM_RETRY_DELAYS_SECS, [8, 30, 90]);

    // Generation changed (terminal skip)
    let err = evaluate_heap_reclaim_guard(&HeapReclaimCheckInput {
        gen_matches: false,
        ..base
    })
    .unwrap_err();
    assert_eq!(err, "config_generation_changed");
    assert!(!is_heap_reclaim_reason_deferrable(err));

    // TUN active must skip (terminal)
    let err = evaluate_heap_reclaim_guard(&HeapReclaimCheckInput {
        tun_enabled: true,
        ..base
    })
    .unwrap_err();
    assert_eq!(err, "tun_active");
    assert!(!is_heap_reclaim_reason_deferrable(err));

    // Even a single active proxied stream (e.g. Codex/AI SSE) MUST block and defer.
    let err = evaluate_heap_reclaim_guard(&HeapReclaimCheckInput {
        proxied_connections: 1,
        total_bytes_per_sec: 0,
        ..base
    })
    .unwrap_err();
    assert_eq!(err, "active_proxied_connections");
    assert!(is_heap_reclaim_reason_deferrable(err));

    // Throughput >= 8 KiB/s (8192 B/s) MUST block and defer; 8191 B/s is idle enough.
    let err = evaluate_heap_reclaim_guard(&HeapReclaimCheckInput {
        total_bytes_per_sec: HEAP_RECLAIM_MAX_TOTAL_BPS,
        ..base
    })
    .unwrap_err();
    assert_eq!(err, "throughput_above_idle_threshold");
    assert!(is_heap_reclaim_reason_deferrable(err));
    assert!(evaluate_heap_reclaim_guard(&HeapReclaimCheckInput {
        total_bytes_per_sec: HEAP_RECLAIM_MAX_TOTAL_BPS - 1,
        ..base
    })
    .is_ok());

    // Probing active must skip and defer
    let err = evaluate_heap_reclaim_guard(&HeapReclaimCheckInput {
        probing_active: true,
        ..base
    })
    .unwrap_err();
    assert_eq!(err, "probing_active");
    assert!(is_heap_reclaim_reason_deferrable(err));

    // Below max(budget * 1.5, 90.0) floor must skip (terminal)
    let err = evaluate_heap_reclaim_guard(&HeapReclaimCheckInput {
        budget_mb: 48.0,
        memory_mb: 89.5,
        ..base
    })
    .unwrap_err();
    assert_eq!(err, "memory_within_budget");
    assert!(!is_heap_reclaim_reason_deferrable(err));

    // Cooldown active must skip (terminal)
    let err = evaluate_heap_reclaim_guard(&HeapReclaimCheckInput {
        cooldown_elapsed: false,
        ..base
    })
    .unwrap_err();
    assert_eq!(err, "cooldown_active");
    assert!(!is_heap_reclaim_reason_deferrable(err));
}

#[test]
fn heap_reclaim_distinguishes_direct_qq_from_single_proxied_ai_stream_and_throughput() {
    use catcloud_core::core_adapter::ActiveConnection;

    let now_ms: i64 = 1_700_000_100_000;
    let base = HeapReclaimCheckInput {
        gen_matches: true,
        is_rule_mode: true,
        core_running: true,
        tun_enabled: false,
        proxied_connections: 0,
        direct_connections: 0,
        traffic_telemetry_fresh: true,
        total_bytes_per_sec: 0,
        probing_active: false,
        memory_mb: 120.0,
        budget_mb: 64.0,
        cooldown_elapsed: true,
    };

    // Case 1: Only DIRECT QQ + Inner tunnel + REJECT connections, 0 proxied streams, low rate
    // (< 8 KiB/s) -> MUST allow heap reclaim (never becomes dead code due to DIRECT QQ).
    let direct_only_conns = vec![
        ActiveConnection {
            id: "qq-1".to_string(),
            conn_type: "HTTP".to_string(),
            chains: vec!["DIRECT".to_string()],
            rule: "PROCESS-NAME".to_string(),
            process: "QQ.exe".to_string(),
            ..Default::default()
        },
        ActiveConnection {
            id: "qq-2".to_string(),
            conn_type: "TUN".to_string(),
            chains: vec!["国内直连".to_string(), "DIRECT".to_string()],
            rule: "GEOIP".to_string(),
            process: "QQ.exe".to_string(),
            ..Default::default()
        },
        ActiveConnection {
            id: "inner-1".to_string(),
            conn_type: "Inner".to_string(),
            chains: vec!["PreAccel-Relay".to_string()],
            ..Default::default()
        },
        ActiveConnection {
            id: "rej-1".to_string(),
            conn_type: "TUN".to_string(),
            chains: vec!["REJECT".to_string()],
            rule: "AND".to_string(),
            ..Default::default()
        },
    ];
    let direct_summary = summarize_connections(&direct_only_conns);
    assert_eq!(direct_summary.app_connections, 3);
    assert_eq!(direct_summary.tunnel_connections, 1);
    assert_eq!(direct_summary.direct_connections, 2);
    assert_eq!(direct_summary.proxied_connections, 0);

    let low_rate_cached = CachedRealtimeMetrics {
        up_bps: 1024,
        down_bps: 2048,
        ..Default::default()
    };
    let (low_rate_bps, low_rate_fresh) = resolve_recent_peak_total_bps_with_freshness(
        &low_rate_cached,
        &[TrafficTick {
            up: 512,
            down: 1536,
            timestamp_ms: now_ms - 2_000,
        }],
        now_ms,
        HEAP_RECLAIM_HIGH_THROUGHPUT_WINDOW_MS,
    );
    assert_eq!(low_rate_bps, 3072);
    assert!(low_rate_fresh);
    assert!(evaluate_heap_reclaim_guard(&HeapReclaimCheckInput {
        proxied_connections: direct_summary.proxied_connections,
        direct_connections: direct_summary.direct_connections,
        traffic_telemetry_fresh: low_rate_fresh,
        total_bytes_per_sec: low_rate_bps,
        ..base
    })
    .is_ok());

    // Case 2: A single active proxied AI/Codex SSE connection even at 0 B/s MUST be blocked.
    let mut with_codex_sse = direct_only_conns;
    with_codex_sse.push(ActiveConnection {
        id: "codex-sse-1".to_string(),
        conn_type: "HTTP".to_string(),
        chains: vec!["AI主力组".to_string(), "日本东京 01".to_string()],
        rule: "DOMAIN-SUFFIX".to_string(),
        host: "api.openai.com".to_string(),
        ..Default::default()
    });
    let sse_summary = summarize_connections(&with_codex_sse);
    assert_eq!(sse_summary.app_connections, 4);
    assert_eq!(sse_summary.direct_connections, 2);
    assert_eq!(sse_summary.proxied_connections, 1);
    assert_eq!(
        evaluate_heap_reclaim_guard(&HeapReclaimCheckInput {
            proxied_connections: sse_summary.proxied_connections,
            total_bytes_per_sec: 0,
            ..base
        }),
        Err("active_proxied_connections")
    );

    // Case 3: 0 proxied streams but combined (up + down) throughput >= 8 KiB/s in window MUST block.
    let combined_peak_bps = resolve_recent_peak_total_bps(
        &CachedRealtimeMetrics::default(),
        &[TrafficTick {
            up: 4096,
            down: 4096,
            timestamp_ms: now_ms - 3_000,
        }],
        now_ms,
        HEAP_RECLAIM_HIGH_THROUGHPUT_WINDOW_MS,
    );
    assert_eq!(combined_peak_bps, 8192);
    assert_eq!(
        evaluate_heap_reclaim_guard(&HeapReclaimCheckInput {
            proxied_connections: 0,
            total_bytes_per_sec: combined_peak_bps,
            ..base
        }),
        Err("throughput_above_idle_threshold")
    );
}

#[test]
fn ui_personalization_language_roundtrip_normalizes_locale() {
    let mut cfg = AppConfig::default();
    cfg.personalization.language = "ja-JP".to_string();
    let dto = UiAppConfigDto::from(&cfg);
    assert_eq!(dto.personalization.ui_language, "ja");

    let mut next_dto = dto.clone();
    next_dto.personalization.ui_language = "en-US".to_string();
    let mut updated = cfg.clone();
    apply_ui_dto(&mut updated, &next_dto);
    assert_eq!(updated.personalization.language, "en");
}

#[test]
fn tray_and_runtime_dto_reflect_circuit_open_backoff_direct_and_activity_flags() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_tray_stage14_test_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), true).expect("resolve test paths");
    let storage = Storage::open_in_memory().expect("open in-memory storage");

    let group = MultiGroup {
        id: "g-circuit".to_string(),
        name: "测试分组".to_string(),
        state: MultiGroupState::CircuitOpen,
        ..Default::default()
    };
    storage.upsert_multi_group(&group).expect("upsert group");

    let mut cfg = AppConfig::default();
    cfg.route_mode = RouteTargetMode::Group;
    cfg.active_group_id = Some("g-circuit".to_string());
    cfg.system_proxy.enabled = true;
    let job_guard = Arc::new(JobGuard::new().expect("job guard"));
    let state = AppState::new(paths, cfg, storage, job_guard);

    // Simulate active probing & switching flags plus CircuitOpen group state.
    state.probe_running.store(true, Ordering::SeqCst);
    state.switching_active.store(true, Ordering::SeqCst);
    if let Ok(mut rt) = state.cached_runtime.write() {
        rt.running = true;
    }

    let dto = build_runtime_info_dto(&state).expect("build runtime dto");
    assert!(dto.probing_active);
    assert!(dto.switching_active);
    assert!(dto.active_group_circuit_open);
    assert_eq!(dto.active_group_state.as_deref(), Some("circuit_open"));

    let vis = build_tray_visual_state(&state);
    assert_eq!(vis.health, TrayHealthState::Error);
    assert!(vis.tooltip.contains("熔断"));

    // Clear CircuitOpen -> verify group backoff triggers Warn.
    {
        let db = state.storage.lock().expect("lock db");
        let mut healthy_group = group.clone();
        healthy_group.state = MultiGroupState::Healthy;
        db.upsert_multi_group(&healthy_group)
            .expect("update healthy group");
    }
    state.set_group_backoff_until(
        "g-circuit",
        Some(Instant::now() + Duration::from_secs(60)),
    );
    let vis_backoff = build_tray_visual_state(&state);
    assert_eq!(vis_backoff.health, TrayHealthState::Warn);
    assert!(vis_backoff.tooltip.contains("退避"));

    // Direct mode without WinDivert -> Idle with direct-mode notice.
    state.clear_group_backoffs();
    state.probe_running.store(false, Ordering::SeqCst);
    state.switching_active.store(false, Ordering::SeqCst);
    if let Ok(mut c) = state.config.write() {
        let mut next = (**c).clone();
        next.proxy_mode = ProxyMode::Direct;
        *c = Arc::new(next);
    }
    if let Ok(mut rt) = state.cached_runtime.write() {
        rt.proxy_mode = ProxyMode::Direct;
    }
    let vis_direct = build_tray_visual_state(&state);
    assert_eq!(vis_direct.health, TrayHealthState::Idle);
    assert!(vis_direct.tooltip.contains("直连"));

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn stage20_resolve_apply_action_maps_all_platform_packages() {
    use catcloud_core::updater::StagedUpdateKind;

    for os in ["windows", "macos", "linux", "freebsd"] {
        assert_eq!(
            resolve_apply_action_for_os(StagedUpdateKind::PortableZip, None, os),
            "portable_restart"
        );
        assert_eq!(
            resolve_apply_action_for_os(
                StagedUpdateKind::PortableZip,
                Some("CatCloud-portable.zip"),
                os
            ),
            "portable_restart"
        );
    }

    for win_launch in [
        "CatCloud-0.2.0-windows-x64-setup.exe",
        "CatCloud-0.2.0-SETUP.EXE",
        "CatCloud-0.2.0-x64.msi",
        "CatCloud-0.2.0-x64.MSI",
    ] {
        assert_eq!(
            resolve_apply_action_for_os(
                StagedUpdateKind::InstallerPackage,
                Some(win_launch),
                "windows"
            ),
            "installer_launch",
            "expected windows installer_launch for {win_launch}"
        );
        assert_eq!(
            resolve_apply_action_for_os(
                StagedUpdateKind::InstallerPackage,
                Some(win_launch),
                "macos"
            ),
            "reveal_archive",
            "expected macos reveal_archive for windows package {win_launch}"
        );
        assert_eq!(
            resolve_apply_action_for_os(
                StagedUpdateKind::InstallerPackage,
                Some(win_launch),
                "linux"
            ),
            "reveal_archive",
            "expected linux reveal_archive for windows package {win_launch}"
        );
    }

    for mac_launch in ["CatCloud-0.2.0-aarch64.dmg", "CatCloud-0.2.0-X64.DMG"] {
        assert_eq!(
            resolve_apply_action_for_os(
                StagedUpdateKind::InstallerPackage,
                Some(mac_launch),
                "macos"
            ),
            "installer_launch",
            "expected macos installer_launch for {mac_launch}"
        );
        assert_eq!(
            resolve_apply_action_for_os(
                StagedUpdateKind::InstallerPackage,
                Some(mac_launch),
                "windows"
            ),
            "reveal_archive",
            "expected windows reveal_archive for mac package {mac_launch}"
        );
        assert_eq!(
            resolve_apply_action_for_os(
                StagedUpdateKind::InstallerPackage,
                Some(mac_launch),
                "linux"
            ),
            "reveal_archive",
            "expected linux reveal_archive for mac package {mac_launch}"
        );
    }

    for os in ["windows", "macos", "linux"] {
        for reveal in [
            Some("CatCloud-0.2.0-aarch64.app.tar.gz"),
            Some("CatCloud-0.2.0-amd64.AppImage"),
            Some("CatCloud-0.2.0-amd64.AppImage.tar.gz"),
            Some("CatCloud-0.2.0-amd64.deb"),
            Some("CatCloud-0.2.0-x86_64.rpm"),
            None,
        ] {
            assert_eq!(
                resolve_apply_action_for_os(StagedUpdateKind::InstallerPackage, reveal, os),
                "reveal_archive",
                "expected reveal_archive on {os} for {reveal:?}"
            );
        }
    }

    assert_eq!(
        resolve_apply_action(
            StagedUpdateKind::InstallerPackage,
            Some("CatCloud-0.2.0-windows-x64-setup.exe")
        ),
        resolve_apply_action_for_os(
            StagedUpdateKind::InstallerPackage,
            Some("CatCloud-0.2.0-windows-x64-setup.exe"),
            std::env::consts::OS
        )
    );
}

#[test]
fn stage20_emergency_cleanup_on_exit_is_idempotent_and_cancels_download() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_s20_exit_idempotent_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), true).expect("create temp AppPaths");
    let storage = Storage::open_in_memory().expect("open memory storage");
    let mut isolated_cfg = AppConfig::default();
    isolated_cfg.system_proxy.enabled = false;
    isolated_cfg.tun.enabled = false;
    isolated_cfg.preaccel.enabled = false;
    isolated_cfg.mixed_port = 59997;
    isolated_cfg.controller_port = 59998;
    isolated_cfg.dns_listen_port = 59999;
    let state = AppState::new(
        paths,
        isolated_cfg,
        storage,
        Arc::new(JobGuard::new().expect("create JobGuard")),
    );

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    *state.update_download_cancel.lock().unwrap() = Some(cancel_tx);

    assert!(!state.exit_cleanup_done.load(Ordering::SeqCst));
    emergency_cleanup_on_exit(&state);
    assert!(state.exit_cleanup_done.load(Ordering::SeqCst));
    assert!(state.shutting_down.load(Ordering::SeqCst));
    assert!(*cancel_rx.borrow());

    // Second invocation is a guaranteed no-op.
    emergency_cleanup_on_exit(&state);
    assert!(state.exit_cleanup_done.load(Ordering::SeqCst));

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn stage21_atomic_manual_stage_eliminates_toctou_and_respects_mid_download_skip() {
    use catcloud_core::updater::{compute_sha256_hex, stage_verified_installer_file};

    // 1. Decision helper truth table across background & manual download modes.
    assert!(!should_abort_stage_due_to_skip(true, "0.2.0", None, None));
    assert!(should_abort_stage_due_to_skip(
        true,
        "0.2.0",
        None,
        Some("0.2.0")
    ));
    assert!(should_abort_stage_due_to_skip(
        true,
        "0.2.0",
        Some("0.2.0"),
        Some("0.2.0")
    ));
    assert!(!should_abort_stage_due_to_skip(
        true,
        "0.2.0",
        None,
        Some("0.1.9")
    ));
    assert!(!should_abort_stage_due_to_skip(
        false,
        "0.2.0",
        Some("0.2.0"),
        Some("0.2.0")
    ));
    assert!(!should_abort_stage_due_to_skip(
        false,
        "0.2.0",
        Some("0.2.0"),
        None
    ));
    assert!(should_abort_stage_due_to_skip(
        false,
        "0.2.0",
        None,
        Some("0.2.0")
    ));
    assert!(should_abort_stage_due_to_skip(
        false,
        "0.2.0",
        Some("0.1.9"),
        Some("0.2.0")
    ));
    assert!(should_abort_stage_due_to_skip(
        false,
        "0.2.0",
        Some("0.2.0"),
        Some("0.3.0")
    ));

    let tmp = std::env::temp_dir().join(format!(
        "catcloud_s21_atomic_stage_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), false).expect("create temp AppPaths");
    let storage = Storage::open_in_memory().expect("open memory storage");
    let mut init_cfg = AppConfig::default();
    init_cfg.update.skipped_version = Some("99.0.0".to_string());
    config::save(&paths, &init_cfg).expect("persist initial config");
    let state = Arc::new(AppState::new(
        paths.clone(),
        init_cfg,
        storage,
        Arc::new(JobGuard::new().expect("create JobGuard")),
    ));
    *state.dismissed_update_prompt_version.write().unwrap() = Some("99.0.0".to_string());

    let installer_bytes = b"stage21-signed-installer-payload-bytes";
    let installer_sha = compute_sha256_hex(installer_bytes);
    let temp_download = tmp.join(".tmp_s21_installer.exe");
    std::fs::write(&temp_download, installer_bytes).expect("write temp installer");

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build multi-thread tokio runtime");

    rt.block_on(async {
        // 2a. Pre-hold `config_transition_lock` -> `update_staging_lock` while `skipped_version`
        // is still `Some("99.0.0")`, spawn a concurrent `get_pending_staged_update_internal`
        // waiter, then clear skip + commit the package before releasing locks.
        // The waiter MUST read config AFTER acquiring `update_staging_lock` and MUST NOT purge it.
        let pre_cfg_lock = state.config_transition_lock.lock().await;
        let pre_staging_lock = state.update_staging_lock.lock().await;
        let state_reader = Arc::clone(&state);
        let pending_waiter = tokio::spawn(async move {
            get_pending_staged_update_internal(&state_reader).await
        });
        tokio::time::sleep(Duration::from_millis(25)).await;
        let cleared = clear_skipped_for_manual_download_locked(&state, "99.0.0")
            .expect("clear skipped");
        assert!(cleared.is_some());
        stage_verified_installer_file(
            &temp_download,
            &installer_sha,
            "CatCloud-99.0.0-windows-x64-setup.exe",
            "0.1.0",
            "99.0.0",
            "## Stage 21",
            None,
            Some("windows-x86_64"),
            &paths.staging_dir,
        )
        .expect("stage installer under locks");
        drop(pre_staging_lock);
        drop(pre_cfg_lock);

        let prompt_after_wait = pending_waiter
            .await
            .expect("join pending waiter")
            .expect("get_pending_staged_update_internal ok")
            .expect("staged package must survive concurrent reader");
        assert_eq!(prompt_after_wait.target_version, "99.0.0");
        assert!(!prompt_after_wait.dismissed_in_session);
        assert!(paths.staging_dir.exists());

        // 2b. Full `commit_staged_update_atomically` in manual mode starting from
        // `skipped_version = Some("99.0.0")` alongside concurrent `get_pending_staged_update_internal`.
        let _ = catcloud_core::updater::purge_staged_update(&paths.staging_dir);
        {
            let _cfg_guard = state.config_transition_lock.lock().await;
            let mut cfg = state.clone_config();
            cfg.update.skipped_version = Some("99.0.0".to_string());
            config::save(&state.paths, &cfg).expect("save skipped 99.0.0");
            *state.config.write().unwrap() = Arc::new(cfg);
            *state.dismissed_update_prompt_version.write().unwrap() =
                Some("99.0.0".to_string());
        }
        std::fs::write(&temp_download, installer_bytes).expect("rewrite temp installer");

        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel::<()>();
        let temp_for_commit = temp_download.clone();
        let sha_for_commit = installer_sha.clone();
        let staging_for_commit = paths.staging_dir.clone();
        let commit_fut = commit_staged_update_atomically(
            &state,
            false,
            Some("99.0.0"),
            "99.0.0",
            move || {
                let _ = entered_tx.send(());
                std::thread::sleep(Duration::from_millis(30));
                stage_verified_installer_file(
                    &temp_for_commit,
                    &sha_for_commit,
                    "CatCloud-99.0.0-windows-x64-setup.exe",
                    "0.1.0",
                    "99.0.0",
                    "## Stage 21 atomic",
                    None,
                    Some("windows-x86_64"),
                    &staging_for_commit,
                )
                .map_err(|e| e.to_string())
            },
        );
        let inspect_fut = async {
            let _ = entered_rx.await;
            get_pending_staged_update_internal(&state).await
        };
        let (commit_res, inspect_res) = tokio::join!(commit_fut, inspect_fut);
        match commit_res.unwrap_or_else(|e| panic!("atomic commit failed: {}", e.message)) {
            CommitStagedOutcome::Staged {
                metadata,
                cleared_config,
            } => {
                assert_eq!(metadata.target_version, "99.0.0");
                assert_eq!(cleared_config.and_then(|c| c.update.skipped_version), None);
            }
            _ => panic!("expected CommitStagedOutcome::Staged"),
        }
        let prompt_concurrent = inspect_res
            .expect("concurrent get_pending ok")
            .expect("concurrent get_pending must see newly committed package");
        assert_eq!(prompt_concurrent.target_version, "99.0.0");
        assert!(!prompt_concurrent.dismissed_in_session);
        assert_eq!(state.snapshot_config().update.skipped_version, None);
        assert_eq!(
            config::load_or_init(&paths).unwrap().update.skipped_version,
            None
        );

        // 2c. Manual download aborted when user explicitly skips mid-download.
        let _ = skip_update_version_core(&state, "99.0.0")
            .await
            .expect("skip 99.0.0 mid-download");
        assert!(!paths.staging_dir.exists());
        let mid_skip_outcome = commit_staged_update_atomically(
            &state,
            false,
            None,
            "99.0.0",
            || panic!("stage_fn must not execute when mid-download skip wins"),
        )
        .await
        .unwrap_or_else(|e| panic!("unexpected error: {}", e.message));
        assert!(matches!(mid_skip_outcome, CommitStagedOutcome::Skipped));
        assert!(!paths.staging_dir.exists());
        assert_eq!(
            state.snapshot_config().update.skipped_version.as_deref(),
            Some("99.0.0")
        );

        // 2d. Silent background commit aborts when version is skipped.
        let bg_skip_outcome = commit_staged_update_atomically(
            &state,
            true,
            None,
            "99.0.0",
            || panic!("background stage_fn must not execute when version is skipped"),
        )
        .await
        .unwrap_or_else(|e| panic!("unexpected error: {}", e.message));
        assert!(matches!(bg_skip_outcome, CommitStagedOutcome::Skipped));
        assert!(!paths.staging_dir.exists());
    });

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn r23_p0_3_may_have_tun_includes_non_empty_inline_override_yaml() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_r23_may_have_tun_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), false).expect("create temp AppPaths");
    let storage = Storage::open_in_memory().expect("open memory storage");
    let mut cfg = AppConfig::default();
    cfg.tun.enabled = false;
    cfg.rules_override.override_mode = OverrideMode::Disabled;
    cfg.rules_override.inline_override_yaml = None;

    let state = AppState::new(
        paths,
        cfg.clone(),
        storage,
        Arc::new(JobGuard::new().expect("create JobGuard")),
    );

    assert!(!may_have_tun_for_teardown(false, &cfg));
    assert!(!config_may_have_tun(&state, &cfg));

    // Whitespace-only inline_override_yaml does not count as active override.
    cfg.rules_override.inline_override_yaml = Some("   \n\t  ".to_string());
    assert!(!may_have_tun_for_teardown(false, &cfg));
    assert!(!config_may_have_tun(&state, &cfg));

    // Non-empty inline_override_yaml MUST mark `may_have_tun = true` even when
    // `tun.enabled == false` and `override_mode == Disabled`.
    cfg.rules_override.inline_override_yaml = Some("tun:\n  enable: true\n".to_string());
    assert!(may_have_tun_for_teardown(false, &cfg));
    assert!(config_may_have_tun(&state, &cfg));

    // Legacy override_mode and effective_tun remain covered.
    cfg.rules_override.inline_override_yaml = None;
    cfg.rules_override.override_mode = OverrideMode::MergePatch;
    assert!(may_have_tun_for_teardown(false, &cfg));
    assert!(config_may_have_tun(&state, &cfg));

    cfg.rules_override.override_mode = OverrideMode::Disabled;
    assert!(may_have_tun_for_teardown(true, &cfg));

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn r23_p1_4_inline_override_yaml_compile_precheck_runs_on_combined_core_config_changes() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_r23_inline_combo_precheck_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), false).expect("create temp AppPaths");
    let storage = Storage::open_in_memory().expect("open memory storage");
    storage
        .upsert_subscription(&SubscriptionRecord {
            id: "sub-inline".to_string(),
            name: "Demo".to_string(),
            ..SubscriptionRecord::default()
        })
        .expect("upsert sub");
    storage
        .upsert_node(&ProxyNode {
            id: "node-inline-1".to_string(),
            sub_id: "sub-inline".to_string(),
            name: "SG-Inline-01".to_string(),
            protocol: "vless".to_string(),
            server: "198.51.100.77".to_string(),
            port: 8443,
            enabled: true,
            raw_config: serde_json::json!({
                "name": "SG-Inline-01",
                "type": "vless",
                "server": "198.51.100.77",
                "port": 8443,
                "uuid": "00000000-0000-4000-8000-000000000099",
                "tls": true,
                "network": "tcp"
            }),
            ..ProxyNode::default()
        })
        .expect("upsert node");

    let mut old = AppConfig::default();
    old.personalization.onboarding_completed = true;
    old.rules_override.inline_override_yaml = Some(
        "rules:\n  - DOMAIN-SUFFIX,example.invalid,Removed-Group\n  - MATCH,DIRECT\n"
            .to_string(),
    );
    let state = AppState::new(
        paths.clone(),
        old.clone(),
        storage,
        Arc::new(JobGuard::new().expect("create JobGuard")),
    );

    // 1. Pure UI-only change does NOT trigger inline YAML compile precheck when untouched.
    let mut ui_only_next = old.clone();
    ui_only_next.personalization.animations_enabled = !old.personalization.animations_enabled;
    assert!(!should_validate_inline_override_yaml(
        &old,
        &ui_only_next,
        false
    ));

    // 2. `save_full_config` path (`prepare_full_config_next`): core field changes
    //    (`route_mode`) while `inline_override_yaml` stays identical MUST run compile precheck
    //    and reject dangling target before writing disk.
    let mut core_changed_next = old.clone();
    core_changed_next.route_mode = RouteTargetMode::Single;
    assert!(should_validate_inline_override_yaml(
        &old,
        &core_changed_next,
        false
    ));
    let full_err = prepare_full_config_next(&state, &old, core_changed_next)
        .expect_err("save_full_config combined core change must reject invalid inline YAML");
    assert!(
        full_err.contains("内联 YAML") && full_err.contains("Removed-Group"),
        "unexpected error: {full_err}"
    );

    // 3. `save_extended_settings` path (`prepare_extended_settings_next`): patching a core
    //    field without touching `rules_override.inline_override_yaml` MUST also run precheck.
    let patch_core = serde_json::json!({
        "route_mode": "single",
        "core_ipv6": true
    });
    let ext_err = prepare_extended_settings_next(&state, &old, &patch_core)
        .expect_err("save_extended_settings combined core change must reject invalid inline YAML");
    assert!(
        ext_err.contains("内联 YAML") && ext_err.contains("Removed-Group"),
        "unexpected error: {ext_err}"
    );

    // 4. Positive case: when `inline_override_yaml` is valid, combined core config changes pass.
    let mut valid_old = old.clone();
    valid_old.rules_override.inline_override_yaml = Some(
        "rules:\n  - DOMAIN-SUFFIX,example.invalid,DIRECT\n  - MATCH,DIRECT\n".to_string(),
    );
    let mut valid_next = valid_old.clone();
    valid_next.route_mode = RouteTargetMode::Single;
    prepare_full_config_next(&state, &valid_old, valid_next)
        .expect("valid inline YAML with combined core change must pass save_full_config");
    prepare_extended_settings_next(&state, &valid_old, &patch_core)
        .expect("valid inline YAML with combined core change must pass save_extended_settings");

    // Nothing dirty written to disk.
    assert!(!paths.config_path.exists());

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn r23_p2_2_heap_reclaim_defers_when_traffic_telemetry_stale_with_direct_connections() {
    let now_ms: i64 = 1_700_000_200_000;
    let base = HeapReclaimCheckInput {
        gen_matches: true,
        is_rule_mode: true,
        core_running: true,
        tun_enabled: false,
        proxied_connections: 0,
        direct_connections: 0,
        traffic_telemetry_fresh: true,
        total_bytes_per_sec: 0,
        probing_active: false,
        memory_mb: 120.0,
        budget_mb: 64.0,
        cooldown_elapsed: true,
    };

    // 1. Empty `/traffic` ticks (minimized window) -> `fresh == false`.
    let (peak_empty, fresh_empty) = resolve_recent_peak_total_bps_with_freshness(
        &CachedRealtimeMetrics::default(),
        &[],
        now_ms,
        HEAP_RECLAIM_HIGH_THROUGHPUT_WINDOW_MS,
    );
    assert_eq!(peak_empty, 0);
    assert!(!fresh_empty);

    // 2. Only stale ticks older than 10s -> `fresh == false`.
    let (peak_stale, fresh_stale) = resolve_recent_peak_total_bps_with_freshness(
        &CachedRealtimeMetrics::default(),
        &[TrafficTick {
            up: 128,
            down: 256,
            timestamp_ms: now_ms - HEAP_RECLAIM_HIGH_THROUGHPUT_WINDOW_MS - 1_000,
        }],
        now_ms,
        HEAP_RECLAIM_HIGH_THROUGHPUT_WINDOW_MS,
    );
    assert_eq!(peak_stale, 0);
    assert!(!fresh_stale);

    // 3. Active DIRECT connections + stale telemetry MUST conservatively defer (never treat as 0 B/s idle).
    let err = evaluate_heap_reclaim_guard(&HeapReclaimCheckInput {
        direct_connections: 2,
        traffic_telemetry_fresh: fresh_stale,
        total_bytes_per_sec: peak_stale,
        ..base
    })
    .expect_err("stale telemetry with active DIRECT connections must defer");
    assert_eq!(err, "traffic_telemetry_stale_with_direct_connections");
    assert!(is_heap_reclaim_reason_deferrable(err));

    // 4. Zero DIRECT and zero proxied connections -> safe to reclaim even if `/traffic` is paused.
    assert!(evaluate_heap_reclaim_guard(&HeapReclaimCheckInput {
        direct_connections: 0,
        traffic_telemetry_fresh: false,
        total_bytes_per_sec: 0,
        ..base
    })
    .is_ok());

    // 5. Active DIRECT connections + fresh low-throughput tick inside 10s window -> safe to reclaim.
    let (peak_fresh, fresh_ok) = resolve_recent_peak_total_bps_with_freshness(
        &CachedRealtimeMetrics::default(),
        &[TrafficTick {
            up: 256,
            down: 512,
            timestamp_ms: now_ms - 4_000,
        }],
        now_ms,
        HEAP_RECLAIM_HIGH_THROUGHPUT_WINDOW_MS,
    );
    assert_eq!(peak_fresh, 768);
    assert!(fresh_ok);
    assert!(evaluate_heap_reclaim_guard(&HeapReclaimCheckInput {
        direct_connections: 2,
        traffic_telemetry_fresh: fresh_ok,
        total_bytes_per_sec: peak_fresh,
        ..base
    })
    .is_ok());
}

#[test]
fn stage22_system_proxy_ownership_protects_host_proxy_when_disabled_and_core_never_started() {
    let mut cfg = AppConfig::default();
    cfg.mixed_port = 7890;
    cfg.system_proxy.enabled = false;
    let rt = CoreRuntimeStatus::default(); // mixed_port == 0, never started core

    let host_portable_proxy = SystemProxySpec {
        enabled: true,
        host: "127.0.0.1".to_string(),
        port: 7890,
        bypass: vec![],
        pac_url: None,
    };
    assert!(
        !is_system_proxy_owned_by_us(&cfg, &rt, &host_portable_proxy),
        "sandbox/idle instance with system_proxy disabled and rt.mixed_port==0 must NEVER claim host port 7890"
    );

    let host_pac = SystemProxySpec {
        enabled: true,
        host: "127.0.0.1".to_string(),
        port: 7890,
        bypass: vec![],
        pac_url: Some(format!(
            "http://127.0.0.1:{}/proxy.pac",
            cfg.system_proxy.pac.port
        )),
    };
    assert!(
        !is_system_proxy_owned_by_us(&cfg, &rt, &host_pac),
        "sandbox/idle instance must NEVER claim host PAC when system_proxy disabled and rt.mixed_port==0"
    );

    // Once system_proxy is enabled in config, loopback proxy ownership returns true,
    // while PAC URL ownership strictly requires `cfg.system_proxy.pac.enabled == true`.
    cfg.system_proxy.enabled = true;
    assert!(is_system_proxy_owned_by_us(&cfg, &rt, &host_portable_proxy));
    assert!(
        !is_system_proxy_owned_by_us(&cfg, &rt, &host_pac),
        "PAC ownership must stay false when cfg.system_proxy.pac.enabled is false"
    );
    cfg.system_proxy.pac.enabled = true;
    assert!(is_system_proxy_owned_by_us(&cfg, &rt, &host_pac));
}

#[test]
fn stage22_r25_emergency_cleanup_bounded_and_proxy_lock_contended_never_stall() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_s22_r25_bounded_exit_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), true).unwrap();
    let storage = Storage::open_in_memory().unwrap();
    let mut cfg = AppConfig::default();
    cfg.system_proxy.enabled = false;
    cfg.preaccel.enabled = false;
    let state = AppState::new(
        paths,
        cfg,
        storage,
        Arc::new(JobGuard::new().unwrap()),
    );

    // Hold `system_proxy_lock` on the current thread to simulate a stalled background thread.
    let held_guard = state.system_proxy_lock.lock().unwrap();
    let start = Instant::now();
    let lock_err = clear_system_proxy_if_owned_bounded(&state, Duration::from_millis(40))
        .expect_err("contended system_proxy_lock must time out cleanly");
    assert!(lock_err.contains("超时"), "unexpected err: {lock_err}");
    assert!(
        start.elapsed() < Duration::from_millis(500),
        "bounded proxy lock wait took too long: {:?}",
        start.elapsed()
    );

    // `emergency_cleanup_on_exit_bounded` must also finish promptly even while `system_proxy_lock`
    // is contended, never hanging the caller before `JobGuard::terminate_all()`.
    let exit_start = Instant::now();
    emergency_cleanup_on_exit_bounded(&state, Duration::from_millis(700));
    assert!(
        exit_start.elapsed() < Duration::from_millis(1200),
        "emergency_cleanup_on_exit_bounded must remain strictly bounded: {:?}",
        exit_start.elapsed()
    );
    assert!(state.exit_cleanup_done.load(Ordering::SeqCst));
    assert!(state.shutting_down.load(Ordering::SeqCst));

    drop(held_guard);
    drop(state);
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn stage23_bug3_power_off_memory_and_takeover_plan_symmetry() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_s23_bug3_power_mem_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), true).unwrap();
    let storage = Storage::open_in_memory().unwrap();
    let state = AppState::new(
        paths,
        AppConfig::default(),
        storage,
        Arc::new(JobGuard::new().unwrap()),
    );

    // Cold startup starts with None (zero auto-start / zero stale memory).
    assert_eq!(state.take_power_off_takeover_memory(), None);

    // Default plan (no memory) -> system proxy only.
    assert_eq!(
        resolve_power_on_takeover_plan(None, true),
        PowerOnTakeoverPlan {
            enable_sys_proxy: true,
            enable_tun: false,
            degraded_from_tun_due_to_privilege: false,
        }
    );

    // Pure TUN memory with admin privilege -> symmetrically restores pure TUN without forcing system proxy.
    state.record_power_off_takeover_memory(false, true);
    let mem = state.take_power_off_takeover_memory();
    assert_eq!(mem, Some((false, true)));
    assert_eq!(state.take_power_off_takeover_memory(), None);
    assert_eq!(
        resolve_power_on_takeover_plan(mem, true),
        PowerOnTakeoverPlan {
            enable_sys_proxy: false,
            enable_tun: true,
            degraded_from_tun_due_to_privilege: false,
        }
    );

    // Dual (sys_proxy + TUN) memory with admin privilege -> restores both.
    assert_eq!(
        resolve_power_on_takeover_plan(Some((true, true)), true),
        PowerOnTakeoverPlan {
            enable_sys_proxy: true,
            enable_tun: true,
            degraded_from_tun_due_to_privilege: false,
        }
    );

    // TUN memory WITHOUT admin privilege -> safely degrades to system proxy and flags notice.
    assert_eq!(
        resolve_power_on_takeover_plan(Some((false, true)), false),
        PowerOnTakeoverPlan {
            enable_sys_proxy: true,
            enable_tun: false,
            degraded_from_tun_due_to_privilege: true,
        }
    );

    // Explicit clear erases memory; pending_nav is one-shot consumed.
    state.record_power_off_takeover_memory(false, true);
    state.clear_power_off_takeover_memory();
    assert_eq!(state.take_power_off_takeover_memory(), None);

    assert_eq!(state.take_pending_nav(), None);
    state.set_pending_nav(Some("preaccel"));
    assert_eq!(state.take_pending_nav().as_deref(), Some("preaccel"));
    assert_eq!(state.take_pending_nav(), None);
    state.set_pending_nav(Some("preaccel"));
    state.set_pending_nav(None);
    assert_eq!(state.take_pending_nav(), None);

    drop(state);
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn stage27_reload_req_ttl_and_power_on_tun_degraded_default() {
    assert!(!is_config_reload_request_expired(1_000_000, 1_000_000));
    assert!(!is_config_reload_request_expired(1_000_000, 1_015_000));
    assert!(is_config_reload_request_expired(1_000_000, 1_015_001));
    assert!(!is_config_reload_request_expired(1_020_000, 1_000_000));

    let tmp = std::env::temp_dir().join(format!(
        "catcloud_s27_dto_default_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), true).unwrap();
    let storage = Storage::open_in_memory().unwrap();
    let state = AppState::new(
        paths,
        AppConfig::default(),
        storage,
        Arc::new(JobGuard::new().unwrap()),
    );
    let dto = build_runtime_info_dto(&state).expect("build runtime dto");
    assert!(!dto.power_on_tun_degraded);

    let mut val = serde_json::to_value(&dto).expect("serialize runtime dto");
    val.as_object_mut().unwrap().remove("power_on_tun_degraded");
    let roundtrip: CoreRuntimeInfoDto =
        serde_json::from_value(val).expect("deserialize legacy dto without power_on_tun_degraded");
    assert!(!roundtrip.power_on_tun_degraded);

    drop(state);
    let _ = std::fs::remove_dir_all(&tmp);
}
