#[allow(unused_imports)]
use super::prelude::*;

#[test]
fn web_ui_url_builder_encodes_appends_bare_url_and_redacts_secret() {
    let secret = "p@ss%&+#=? 123";
    let (launch_tpl, safe_tpl) = build_web_ui_urls(
        "https://panel.example.invalid/#/setup?hostname={host}&port={port}&secret={secret}",
        "127.0.0.1",
        9090,
        secret,
    )
    .expect("template url");
    assert!(launch_tpl.contains("secret=p%40ss%25%26%2B%23%3D%3F%20123"));
    assert!(safe_tpl.ends_with("secret=***"));
    assert!(!safe_tpl.contains("p%40ss"));

    let (launch_bare, safe_bare) = build_web_ui_urls(
        "https://panel.example.invalid/#/setup",
        "127.0.0.1",
        9090,
        "s&1",
    )
    .expect("bare url");
    assert_eq!(
        launch_bare,
        "https://panel.example.invalid/#/setup?http=true&hostname=127.0.0.1&port=9090&secret=s%261"
    );
    assert_eq!(
        safe_bare,
        "https://panel.example.invalid/#/setup?http=true&hostname=127.0.0.1&port=9090&secret=***"
    );

    let (launch_with_q, safe_with_q) = build_web_ui_urls(
        "https://panel.example.invalid/#/setup?theme=dark",
        "127.0.0.1",
        9090,
        "abc",
    )
    .expect("bare url with existing query");
    assert_eq!(
        launch_with_q,
        "https://panel.example.invalid/#/setup?theme=dark&http=true&hostname=127.0.0.1&port=9090&secret=abc"
    );
    assert_eq!(
        safe_with_q,
        "https://panel.example.invalid/#/setup?theme=dark&http=true&hostname=127.0.0.1&port=9090&secret=***"
    );
}

#[test]
fn build_traffic_history_returns_buffered_ticks_with_cached_memory() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_traffic_history_test_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), true).expect("resolve test paths");
    let storage = Storage::open_in_memory().expect("open in-memory storage");
    let job_guard = Arc::new(JobGuard::new().expect("job guard"));
    let state = AppState::new(paths, AppConfig::default(), storage, job_guard);

    assert!(build_traffic_history(&state).is_empty());

    if let Ok(mut m) = state.cached_metrics.write() {
        m.core_mem_bytes = 32 * 1024 * 1024;
        m.up_total_bytes = 123_456;
        m.down_total_bytes = 987_654;
        m.app_connections = 7;
        m.tunnel_connections = 2;
    }
    state.telemetry.push_traffic(catcloud_core::core_adapter::TrafficTick {
        up: 1024,
        down: 4096,
        timestamp_ms: 1_700_000_001_000,
    });
    state.telemetry.push_traffic(catcloud_core::core_adapter::TrafficTick {
        up: 2048,
        down: 8192,
        timestamp_ms: 1_700_000_002_000,
    });

    let history = build_traffic_history(&state);
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].up_bps, 1024);
    assert_eq!(history[0].down_bps, 4096);
    assert_eq!(history[0].up_total_bytes, 0);
    assert_eq!(history[0].down_total_bytes, 0);
    assert_eq!(history[0].active_connections, 0);
    assert_eq!(history[0].tunnel_connections, 0);
    assert!((history[0].core_memory_mb - 32.0).abs() < 1e-6);
    assert_eq!(history[0].timestamp_ms, 1_700_000_001_000);
    assert_eq!(history[1].up_bps, 2048);
    assert_eq!(history[1].down_bps, 8192);
    assert_eq!(history[1].up_total_bytes, 123_456);
    assert_eq!(history[1].down_total_bytes, 987_654);
    assert_eq!(history[1].active_connections, 7);
    assert_eq!(history[1].tunnel_connections, 2);
    assert_eq!(history[1].timestamp_ms, 1_700_000_002_000);

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn build_sanitized_diagnostics_report_emits_rich_schema_redacted_logs_and_markdown() {
    use catcloud_core::core_adapter::ActiveConnection;

    let tmp = std::env::temp_dir().join(format!(
        "catcloud_diag_rich_test_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), true).expect("resolve test paths");
    std::fs::write(paths.runtime_dir.join("Country.mmdb"), b"mock-country-db")
        .expect("write mock mmdb");
    let storage = Storage::open_in_memory().expect("open in-memory storage");

    let sub = SubscriptionRecord {
        id: "sub-1".to_string(),
        name: "主力订阅".to_string(),
        kind: SubscriptionKind::Url,
        url_or_cmd: "https://user:pass@sub.example.com/api?token=secret_sub_tok".to_string(),
        enabled: true,
        ..Default::default()
    };
    storage.upsert_subscription(&sub).expect("upsert sub");
    let node = ProxyNode {
        id: "n-jp".to_string(),
        sub_id: "sub-1".to_string(),
        name: "日本东京 01".to_string(),
        region_code: "JP".to_string(),
        protocol: "trojan".to_string(),
        server: "198.51.100.88".to_string(),
        port: 443,
        enabled: true,
        ..Default::default()
    };
    storage.upsert_node(&node).expect("upsert node");
    let group = MultiGroup {
        id: "g-main".to_string(),
        name: "AI主力组".to_string(),
        member_node_ids: vec!["n-jp".to_string()],
        active_node_id: Some("n-jp".to_string()),
        ..Default::default()
    };
    storage.upsert_multi_group(&group).expect("upsert group");
    let relay = PreAccelRelay {
        id: "r-hz".to_string(),
        name: "杭州443中转".to_string(),
        server: "203.0.113.66".to_string(),
        port: 443,
        protocol: "anytls".to_string(),
        password: "relay_super_secret".to_string(),
        enabled: true,
        ..Default::default()
    };
    storage.upsert_preaccel_relay(&relay).expect("upsert relay");

    let mut cfg = AppConfig::default();
    cfg.active_group_id = Some("g-main".to_string());
    cfg.system_proxy.enabled = true;
    cfg.preaccel.enabled = true;
    cfg.preaccel.active_relay_id = Some("r-hz".to_string());

    let job_guard = Arc::new(JobGuard::new().expect("job guard"));
    let state = AppState::new(paths, cfg, storage, job_guard);

    for i in 0..70 {
        state.log_app_event(
            "info",
            "测试",
            &format!(
                "事件#{i:02} https://sub.example.com/get?token=tok_{i}&secret=sec_{i} 远端 203.0.113.66 [240e:390:abcd::99]:443"
            ),
        );
    }
    state.log_app_event(
        "error",
        "核心",
        "连接失败 trojan://test_secret_pw@203.0.113.45:443?key=k123",
    );

    let live_conns = ConnectionsSnapshot {
        memory: 42 * 1024 * 1024,
        connections: vec![
            ActiveConnection {
                id: "t1".to_string(),
                conn_type: "Inner".to_string(),
                ..Default::default()
            },
            ActiveConnection {
                id: "a1".to_string(),
                conn_type: "HTTP".to_string(),
                chains: vec!["DIRECT".to_string()],
                ..Default::default()
            },
            ActiveConnection {
                id: "a2".to_string(),
                conn_type: "TUN".to_string(),
                chains: vec!["AI主力组".to_string(), "日本东京 01".to_string()],
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let report = build_sanitized_diagnostics_report(&state, Some(&live_conns))
        .expect("build diagnostics report");

    // Backward-compatible legacy fields
    assert_eq!(report["sanitized"], true);
    assert_eq!(report["counts"]["subscriptions"], 1);
    assert_eq!(report["counts"]["nodes"], 1);
    assert_eq!(report["counts"]["multi_groups"], 1);
    assert_eq!(report["counts"]["preaccel_relays"], 1);

    // Rich new fields
    assert_eq!(report["route_summary"]["route_mode"], "group");
    assert_eq!(report["route_summary"]["active_group_name"], "AI主力组");
    assert_eq!(report["route_summary"]["active_node_name"], "日本东京 01");
    assert_eq!(report["route_summary"]["active_node_region"], "JP");
    assert_eq!(report["route_summary"]["system_proxy_enabled"], true);
    assert_eq!(report["route_summary"]["preaccel_active"], true);
    assert_eq!(report["route_summary"]["preaccel_relay_name"], "杭州443中转");
    assert_eq!(report["route_summary"]["domestic_direct_enabled"], true);
    assert_eq!(report["route_summary"]["block_quic_udp_443"], true);
    assert_eq!(report["geodata_status"]["country_mmdb"]["exists"], true);
    assert_eq!(report["connection_summary"]["app_connections"], 2);
    assert_eq!(report["connection_summary"]["tunnel_connections"], 1);
    assert_eq!(report["connection_summary"]["direct_connections"], 1);
    assert_eq!(report["connection_summary"]["proxied_connections"], 1);

    let last_err = report["last_error"].as_str().expect("last_error string");
    assert!(!last_err.contains("test_secret_pw"));
    assert!(!last_err.contains("k123"));
    assert!(!last_err.contains("203.0.113.45"));
    assert!(last_err.contains("203.0.113.*"));

    let recent_logs = report["recent_logs"].as_array().expect("recent_logs array");
    assert_eq!(recent_logs.len(), 60);
    let serialized_logs = serde_json::to_string(recent_logs).unwrap();
    assert!(!serialized_logs.contains("tok_69"));
    assert!(!serialized_logs.contains("sec_69"));
    assert!(!serialized_logs.contains("203.0.113.66"));
    assert!(!serialized_logs.contains("abcd::99"));
    assert!(serialized_logs.contains("203.0.113.*"));
    assert!(serialized_logs.contains("[240e:390::*]:443"));

    let md = report["ai_prompt_markdown"]
        .as_str()
        .expect("ai_prompt_markdown string");
    assert!(md.starts_with("请帮我排查猫猫云梯（CatCloud）当前问题"));
    assert!(md.contains("AI主力组"));
    assert!(md.contains("日本东京 01"));
    assert!(md.contains("杭州443中转"));
    assert!(md.contains("catcloud status --json"));
    assert!(md.contains("catcloud config diag --json"));
    assert!(!md.contains("test_secret_pw"));
    assert!(!md.contains("tok_69"));
    assert!(!md.contains("203.0.113.66"));

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn validate_external_https_url_accepts_clean_https_and_trims() {
    let ok = validate_external_https_url(
        "  https://github.com/JuryBu/CatCloud/releases/latest?tag=v0.2.0#assets  ",
    )
    .expect("valid https url should pass");
    assert_eq!(
        ok,
        "https://github.com/JuryBu/CatCloud/releases/latest?tag=v0.2.0#assets"
    );
    assert!(!ok.contains("secret="));
    assert!(!ok.contains("hostname="));
}

#[test]
fn validate_external_https_url_rejects_non_https_userinfo_and_control_chars() {
    for bad in [
        "",
        "   ",
        "http://github.com/JuryBu/CatCloud",
        "file:///C:/Windows/System32/calc.exe",
        "javascript:alert(1)",
        "https:///missing-host",
        "https://user:pass@github.com/JuryBu/CatCloud",
        "https://token@github.com/JuryBu/CatCloud",
        "https://github.com/JuryBu/CatCloud\r\nX-Injected: 1",
        "https://github.com/JuryBu/CatCloud\x00",
        "https://github.com/JuryBu/CatCloud\t",
        "not a url",
    ] {
        assert!(
            validate_external_https_url(bad).is_err(),
            "expected external URL validator to reject: {bad:?}"
        );
    }
}

#[test]
fn sample_diagnostic_logs_separates_key_events_from_routine_mihomo_traffic() {
    let mut logs = Vec::new();
    for i in 0..30 {
        logs.push(format!(
            "2026-11-24T12:00:{i:02}Z [info] [核心] 代理核心事件 #{i}"
        ));
    }
    logs.push(
        "2026-11-24T12:01:00Z [warning] [mihomo] [TCP] 127.0.0.1:50000 --> example.com:443 dial error"
            .to_string(),
    );
    for i in 0..60 {
        logs.push(format!(
            "2026-11-24T12:02:{:02}Z [info] [mihomo] [TCP] 127.0.0.1:{} --> example.invalid:443 match Match using Proxy",
            i % 60,
            40000 + i
        ));
        logs.push(format!(
            "2026-11-24T12:03:{:02}Z [info] [mihomo] [UDP] 127.0.0.1:{} --> 8.8.8.*:53 match GeoIP using DIRECT",
            i % 60,
            41000 + i
        ));
    }

    let (key_events, tail_logs) = sample_diagnostic_logs(&logs, 25, 35);
    assert_eq!(key_events.len(), 25);
    assert_eq!(tail_logs.len(), 35);
    assert!(key_events
        .last()
        .is_some_and(|l| l.contains("[warning] [mihomo] [TCP]")));
    assert!(key_events.iter().all(|l| !l.contains("[info] [mihomo] [TCP]")));
    assert!(key_events.iter().all(|l| !l.contains("[info] [mihomo] [UDP]")));
}

#[test]
fn onboarding_prompt_and_runtime_verify_fields_render_sanitized_chinese_guide() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_onboarding_verify_test_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), true).expect("resolve test paths");
    let storage = Storage::open_in_memory().expect("open in-memory storage");
    let job_guard = Arc::new(JobGuard::new().expect("job guard"));
    let state = AppState::new(paths, AppConfig::default(), storage, job_guard);

    let dto = build_runtime_info_dto(&state).expect("build runtime dto");
    assert_eq!(dto.global_preaccel_verify_state, "idle");
    assert_eq!(dto.global_preaccel_verify_ms, None);

    let mut cfg = state.clone_config();
    cfg.preaccel.enabled = true;

    let mut global_st = GlobalPreAccelStatus::default();
    global_st.running = true;
    global_st.mode = "windivert".to_string();
    global_st.is_windivert_active = true;
    global_st.verify_state = "verified".to_string();
    global_st.verify_latency_ms = Some(38);
    global_st.bound_physical_interface = Some("WLAN".to_string());
    global_st.detected_security_products = vec!["Windows 安全中心（Defender）".to_string()];
    global_st.security_guidance = Some(
        "请将目录 `D:\\SecretPortable\\CatCloud\\bin` 加入排除项".to_string(),
    );

    let sample_events = vec![
        "2026-11-24T12:00:00Z [info] [mihomo] Start initial compatible provider Proxy".to_string(),
        "2026-11-24T12:00:01Z [debug] [核心] 调试信息不应出现".to_string(),
        "2026-11-24T12:00:02Z [info] [应用/订阅] 事件一：已导入 5 个节点".to_string(),
        "2026-11-24T12:00:03Z [info] [应用/测速] 事件二：完成 3 个节点省流快测".to_string(),
        "2026-11-24T12:00:04Z [info] [应用/代理] 事件三：已开启系统代理".to_string(),
        "2026-11-24T12:00:05Z [info] [应用/分流] 事件四：已切换为规则分流模式".to_string(),
        "2026-11-24T12:00:06Z [info] [应用/路线] 事件五：已切换到低延迟节点".to_string(),
        "2026-11-24T12:00:07Z [info] [应用/环境] 事件六：检测到网卡状态更新".to_string(),
        "2026-11-24T12:00:08Z [info] [应用/国内提速] 事件七：探测通过 38 ms 内网 192.168.1.9".to_string(),
    ];

    let md = build_ai_onboarding_prompt_markdown(
        "0.1.0",
        "windows x86_64",
        true,
        &cfg,
        &state.snapshot_runtime(),
        Some(&dto),
        &global_st,
        (1, 5, 5, 3, 1, 1),
        Some("上次测试失败 trojan://secret_pw@203.0.113.88:443?token=abc123"),
        &sample_events,
    );
    assert!(md.contains("新手手把手上手导师"));
    assert!(md.contains("下一小步"));
    assert!(md.contains("Windows 电脑"));
    assert!(!md.contains("windows x86_64"));
    assert!(md.contains("已开启并在底层实测生效（38 ms）"));
    assert!(!md.contains("WinDivert 运行中"));
    assert!(!md.contains("SOCKS5 待命"));
    assert!(md.contains("已测速 3 个"));
    assert!(md.contains("WLAN"));
    assert!(md.contains("38 ms"));
    assert!(!md.contains("SecretPortable"));
    assert!(md.contains("<LOCAL_PATH>/bin"));
    assert!(!md.contains("secret_pw"));
    assert!(!md.contains("abc123"));
    assert!(!md.contains("203.0.113.88"));
    assert!(md.contains("203.0.113.*"));
    assert!(!md.contains("192.168.1.9"));
    assert!(md.contains("192.168.1.*"));
    assert!(!md.contains("Start initial compatible provider"));
    assert!(!md.contains("调试信息不应出现"));
    assert!(!md.contains("事件一"));
    assert!(md.contains("事件二"));
    assert!(md.contains("事件七"));

    // Verify degraded plain-Chinese wording without jargon.
    global_st.verify_state = "degraded".to_string();
    global_st.is_windivert_active = false;
    let degraded_md = build_ai_onboarding_prompt_markdown(
        "0.1.0",
        "macos aarch64",
        false,
        &cfg,
        &state.snapshot_runtime(),
        Some(&dto),
        &global_st,
        (1, 5, 5, 0, 1, 1),
        None,
        &[],
    );
    assert!(degraded_md.contains("macOS 电脑"));
    assert!(degraded_md.contains("已开启，底层探测未通过已自动保护回退"));
    assert!(degraded_md.contains("已测速 0 个"));

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn diagnostics_route_summary_sanitizes_sensitive_group_node_and_relay_names() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_diag_route_sanitize_test_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), true).expect("resolve test paths");
    let storage = Storage::open_in_memory().expect("open in-memory storage");

    storage
        .upsert_subscription(&SubscriptionRecord {
            id: "s-1".to_string(),
            name: "测试订阅".to_string(),
            kind: SubscriptionKind::Url,
            url_or_cmd: "https://sub.example.com/api".to_string(),
            enabled: true,
            ..Default::default()
        })
        .expect("upsert subscription");
    storage
        .upsert_node(&ProxyNode {
            id: "n-1".to_string(),
            sub_id: "s-1".to_string(),
            name: "日本节点 203.0.113.88 token=node_secret_99".to_string(),
            region_code: "JP".to_string(),
            protocol: "trojan".to_string(),
            server: "203.0.113.88".to_string(),
            port: 443,
            enabled: true,
            ..Default::default()
        })
        .expect("upsert node");
    storage
        .upsert_multi_group(&MultiGroup {
            id: "g-1".to_string(),
            name: "公司组 192.168.10.55 C:\\Users\\John Doe\\cfg".to_string(),
            member_node_ids: vec!["n-1".to_string()],
            active_node_id: Some("n-1".to_string()),
            ..Default::default()
        })
        .expect("upsert group");
    storage
        .upsert_preaccel_relay(&PreAccelRelay {
            id: "r-1".to_string(),
            name: "杭州中转 10.8.0.12 secret=relay_pw_1".to_string(),
            server: "198.51.100.12".to_string(),
            port: 443,
            protocol: "trojan".to_string(),
            password: "pw".to_string(),
            enabled: true,
            ..Default::default()
        })
        .expect("upsert relay");

    let mut cfg = AppConfig::default();
    cfg.active_group_id = Some("g-1".to_string());
    cfg.preaccel.enabled = true;
    cfg.preaccel.active_relay_id = Some("r-1".to_string());
    let job_guard = Arc::new(JobGuard::new().expect("job guard"));
    let state = AppState::new(paths, cfg, storage, job_guard);

    let report =
        build_sanitized_diagnostics_report(&state, None).expect("build diagnostics report");
    let route_summary = &report["route_summary"];
    let g_name = route_summary["active_group_name"].as_str().unwrap();
    let n_name = route_summary["active_node_name"].as_str().unwrap();
    let r_name = route_summary["preaccel_relay_name"].as_str().unwrap();

    assert!(!g_name.contains("192.168.10.55"));
    assert!(!g_name.contains("John Doe"));
    assert!(g_name.contains("192.168.10.*"));
    assert!(g_name.contains(r"C:\Users\<USER>\cfg"));

    assert!(!n_name.contains("203.0.113.88"));
    assert!(!n_name.contains("node_secret_99"));
    assert!(n_name.contains("203.0.113.*"));
    assert!(n_name.contains("token=<REDACTED>"));

    assert!(!r_name.contains("10.8.0.12"));
    assert!(!r_name.contains("relay_pw_1"));
    assert!(r_name.contains("10.8.0.*"));
    assert!(r_name.contains("secret=<REDACTED>"));

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn diagnostics_key_events_survive_tcp_flood_and_section5_uses_redacted_cli_json() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_diag_flood_test_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), true).expect("resolve test paths");
    let storage = Storage::open_in_memory().expect("open in-memory storage");
    let job_guard = Arc::new(JobGuard::new().expect("job guard"));
    let state = AppState::new(paths, AppConfig::default(), storage, job_guard);

    state.log_app_event(
        "info",
        "核心",
        "核心已启动，已按需加载节点 14 个（含中转 2 个，节点库共 796 个）",
    );
    state.log_app_event("warning", "分流", "检测到核心轻量重启触发条件");

    // Flood disk & telemetry with 1,800 routine Mihomo TCP forwarding entries.
    for i in 0..1800 {
        state.app_logger.append_formatted(
            "2026-11-25T01:00:00Z",
            "info",
            "mihomo",
            &format!("[TCP] 127.0.0.1:50000 --> example.com:443 match DomainSuffix using PROXY #{i}"),
        );
    }

    let report = build_sanitized_diagnostics_report(&state, None)
        .expect("build diagnostics report after flood");
    let key_events = report["key_event_logs"]
        .as_array()
        .expect("key_event_logs array");
    assert!(
        key_events.len() >= 2,
        "§4.1 key events must never collapse to 0 under heavy TCP traffic flood"
    );
    let joined_keys = serde_json::to_string(key_events).unwrap();
    assert!(joined_keys.contains("已按需加载节点 14 个（含中转 2 个，节点库共 796 个）"));
    assert!(joined_keys.contains("核心轻量重启"));

    let md = report["ai_prompt_markdown"]
        .as_str()
        .expect("ai_prompt_markdown");
    assert!(md.contains("--data-dir"));
    assert!(md.contains("docs export network_lifecycle --json"));
    assert!(!md.contains("--format json"));

    // Verify `format_global_preaccel_brief` never emits ambiguous `或` wording across states.
    let mut st_failed_driver = GlobalPreAccelStatus::default();
    st_failed_driver.verify_state = "failed".to_string();
    st_failed_driver.windivert_available = false;
    let brief_a = format_global_preaccel_brief(&st_failed_driver, true, false);
    assert!(!brief_a.contains('或'), "ambiguous brief: {brief_a}");
    assert!(brief_a.contains("底层提速驱动尚未就绪"));
    assert!(brief_a.contains("等待启动独立提速通道"));

    let mut st_tun = GlobalPreAccelStatus::default();
    st_tun.verify_state = "failed".to_string();
    st_tun.windivert_available = true;
    let brief_b = format_global_preaccel_brief(&st_tun, true, true);
    assert!(!brief_b.contains('或'), "ambiguous brief: {brief_b}");
    assert!(brief_b.contains("底层自动探测未通过"));
    assert!(brief_b.contains("由虚拟网卡主核心统一接管"));

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn github_issue_draft_enforces_600_char_body_and_strips_custom_labels() {
    let cfg = AppConfig::default();
    let rt = CoreRuntimeStatus {
        running: true,
        version: Some("v1.19.0".to_string()),
        ..Default::default()
    };
    let global_st = GlobalPreAccelStatus::default();
    let geodata = serde_json::json!({
        "country_mmdb": { "exists": true, "size_bytes": 4096, "updated_at": null },
        "geoip_dat": { "exists": false, "size_bytes": 0, "updated_at": null },
        "geosite_dat": { "exists": false, "size_bytes": 0, "updated_at": null },
        "asn_mmdb": { "exists": false, "size_bytes": 0, "updated_at": null }
    });
    let custom_labels = vec![
        "私人秘密香港节点01".to_string(),
        "我的专属AI多选组".to_string(),
        "寝室杭州中转机".to_string(),
        "神秘订阅源A".to_string(),
    ];
    let key_events = vec![
        "2026-11-25T01:00:00Z [warning] [应用/路线] 我的专属AI多选组 切换 私人秘密香港节点01 经 寝室杭州中转机 203.0.113.77 token=super_tok".to_string(),
    ];
    let long_summary = "连接私人秘密香港节点01和我的专属AI多选组时偶尔断流，请帮忙排查神秘订阅源A的日志，重复说明以触发长度截断验证，确保浏览器URL不会被ShellExecuteW截断导致丢失内容！".repeat(4);

    let sample_err = concat!(
        "连接 寝室杭州中转机 失败 ",
        "trojan",
        "://sample_test_pw@203.0.113.77:443"
    );
    let draft = build_github_issue_draft(
        "JuryBu/CatCloud",
        "0.1.0",
        "windows x86_64",
        false,
        false,
        true,
        &cfg,
        &rt,
        &global_st,
        (1, 12, 2, 1),
        &geodata,
        Some(sample_err),
        &key_events,
        &custom_labels,
        Some(&long_summary),
        "zh-CN",
    );

    assert!(draft
        .issue_url
        .starts_with("https://github.com/JuryBu/CatCloud/issues/new?title="));
    let encoded_body = draft
        .issue_url
        .split_once("&body=")
        .map(|(_, b)| b)
        .expect("issue_url must contain &body=");
    assert!(
        encoded_body.len() <= GITHUB_ISSUE_URL_BODY_MAX_CHARS,
        "encoded URL query body ({}) must be <= {}",
        encoded_body.len(),
        GITHUB_ISSUE_URL_BODY_MAX_CHARS
    );

    for secret_or_label in [
        "私人秘密香港节点01",
        "我的专属AI多选组",
        "寝室杭州中转机",
        "神秘订阅源A",
        "sample_test_pw",
        "super_tok",
        "203.0.113.77",
    ] {
        assert!(
            !draft.clipboard_markdown.contains(secret_or_label),
            "clipboard_markdown leaked `{secret_or_label}`"
        );
        assert!(
            !draft.title.contains(secret_or_label),
            "title leaked `{secret_or_label}`"
        );
        assert!(
            !draft.issue_url.contains(secret_or_label),
            "issue_url leaked `{secret_or_label}`"
        );
    }
    assert!(draft.clipboard_markdown.contains("203.0.113.*"));
    assert!(draft.clipboard_markdown.contains("CatCloud 版本"));
}

#[test]
fn github_issue_draft_ja_and_ru_emit_zero_simplified_chinese_and_strip_relay_provider() {
    let cfg = AppConfig::default();
    let rt = CoreRuntimeStatus {
        running: true,
        version: Some("v1.19.0".to_string()),
        ..Default::default()
    };
    let global_st = GlobalPreAccelStatus::default();
    let geodata = serde_json::json!({
        "country_mmdb": { "exists": true, "size_bytes": 4096, "updated_at": null },
        "geoip_dat": { "exists": false, "size_bytes": 0, "updated_at": null },
        "geosite_dat": { "exists": false, "size_bytes": 0, "updated_at": null },
        "asn_mmdb": { "exists": false, "size_bytes": 0, "updated_at": null }
    });
    let relay = PreAccelRelay {
        id: "r-priv".to_string(),
        name: "PrivateRelayNode01".to_string(),
        provider: "SecretRelayProviderXYZ".to_string(),
        server: "198.51.100.42".to_string(),
        port: 443,
        protocol: "anytls".to_string(),
        enabled: true,
        ..Default::default()
    };
    let custom_labels = collect_github_issue_custom_labels(&[], &[], &[], &[relay]);
    assert!(custom_labels.iter().any(|l| l == "PrivateRelayNode01"));
    assert!(custom_labels.iter().any(|l| l == "SecretRelayProviderXYZ"));

    let key_events = vec![
        "2026-11-25T01:00:00Z [warning] relay PrivateRelayNode01 from SecretRelayProviderXYZ failed via 198.51.100.42".to_string(),
    ];
    let sample_err =
        "handshake timeout on PrivateRelayNode01 (SecretRelayProviderXYZ) 198.51.100.42:443";

    let has_cjk_or_cn_punct = |text: &str| {
        text.chars().any(|c| {
            ('\u{4E00}'..='\u{9FFF}').contains(&c)
                || matches!(c, '（' | '）' | '，' | '。' | '：' | '！' | '、')
        })
    };

    for (lang, expected_title_prefix) in [
        ("ja", "[報告]"),
        ("ru", "[Отзыв]"),
        ("en", "[Feedback]"),
    ] {
        let draft = build_github_issue_draft(
            "JuryBu/CatCloud",
            "0.1.0",
            "windows x86_64",
            false,
            false,
            true,
            &cfg,
            &rt,
            &global_st,
            (1, 5, 1, 1),
            &geodata,
            Some(sample_err),
            &key_events,
            &custom_labels,
            Some("Timeout with SecretRelayProviderXYZ relay PrivateRelayNode01"),
            lang,
        );

        assert!(
            draft.title.starts_with(expected_title_prefix),
            "lang={lang} unexpected title: {}",
            draft.title
        );
        assert!(
            !has_cjk_or_cn_punct(&draft.clipboard_markdown),
            "lang={lang} clipboard_markdown must contain zero simplified Chinese: {}",
            draft.clipboard_markdown
        );
        assert!(draft.clipboard_markdown.contains("### Environment"));
        assert!(draft.clipboard_markdown.contains("Country.mmdb: ready"));
        assert!(draft.clipboard_markdown.contains("geoip.dat: missing"));

        let encoded_body = draft
            .issue_url
            .split_once("&body=")
            .map(|(_, b)| b)
            .expect("issue_url must contain &body=");
        assert!(encoded_body.len() <= GITHUB_ISSUE_URL_BODY_MAX_CHARS);
        assert!(
            encoded_body.contains("Sanitized%20Diagnostics")
                || encoded_body.contains("Paste%20sanitized%20report"),
            "lang={lang} url body must use English template, got: {encoded_body}"
        );
        assert!(
            !encoded_body.contains("%E8%AF%A6%E7%BB%86")
                && !encoded_body.contains("%E8%AF%B7%E7%AE%80%E8%BF%B0"),
            "lang={lang} url body leaked simplified Chinese: {encoded_body}"
        );

        for secret_label in ["SecretRelayProviderXYZ", "PrivateRelayNode01", "198.51.100.42"] {
            assert!(
                !draft.title.contains(secret_label),
                "lang={lang} title leaked {secret_label}"
            );
            assert!(
                !draft.issue_url.contains(secret_label),
                "lang={lang} issue_url leaked {secret_label}"
            );
            assert!(
                !draft.clipboard_markdown.contains(secret_label),
                "lang={lang} clipboard_markdown leaked {secret_label}"
            );
        }
    }
}

#[test]
fn runtime_dto_and_ai_diagnostics_expose_sanitized_preaccel_transport_summary() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_stage21_transport_diag_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), true).expect("resolve test paths");
    let storage = Storage::open_in_memory().expect("open in-memory storage");

    let sub = SubscriptionRecord {
        id: "sub-1".to_string(),
        name: "测试订阅".to_string(),
        ..Default::default()
    };
    storage.upsert_subscription(&sub).expect("upsert subscription");

    let node = ProxyNode {
        id: "n-sg".to_string(),
        sub_id: "sub-1".to_string(),
        name: "新加坡 01".to_string(),
        region_code: "SG".to_string(),
        protocol: "ss".to_string(),
        server: "198.51.100.20".to_string(),
        port: 8388,
        is_443_native: false,
        enabled: true,
        ..Default::default()
    };
    storage.upsert_node(&node).expect("upsert node");
    let relay = PreAccelRelay {
        id: "r-sh".to_string(),
        name: "上海中转 10.20.30.40".to_string(),
        server: "203.0.113.55".to_string(),
        port: 443,
        protocol: "anytls".to_string(),
        password: "super_secret_relay_pw".to_string(),
        enabled: true,
        ..Default::default()
    };
    storage.upsert_preaccel_relay(&relay).expect("upsert relay");

    let mut cfg = AppConfig::default();
    assert_eq!(cfg.preaccel.lb_strategy, PreAccelLbStrategy::ConsistentHashing);
    cfg.preaccel.enabled = false;
    let state = AppState::new(
        paths,
        cfg,
        storage,
        Arc::new(JobGuard::new().expect("job guard")),
    );

    // PreAccel off -> inferred effective TUN MTU stays at default 1500.
    let dto_off = build_runtime_info_dto(&state).expect("runtime dto with preaccel off");
    assert_eq!(dto_off.effective_tun_mtu, Some(1500));
    let tr_off = dto_off
        .preaccel_transport
        .expect("preaccel_transport populated");
    assert_eq!(tr_off.effective_tun_mtu, 1500);
    assert!(!tr_off.anytls_tfo);
    assert_eq!(tr_off.anytls_min_idle_session, 0);
    assert_eq!(tr_off.keep_alive_idle_sec, 45);

    // PreAccel on with enabled relay & wrappable node -> inferred effective TUN MTU clamps to 1400.
    if let Ok(mut g) = state.config.write() {
        let mut next = (**g).clone();
        next.preaccel.enabled = true;
        *g = Arc::new(next);
    }
    let dto_on = build_runtime_info_dto(&state).expect("runtime dto with preaccel on");
    assert_eq!(dto_on.effective_tun_mtu, Some(1400));
    let tr_on = dto_on
        .preaccel_transport
        .as_ref()
        .expect("preaccel_transport populated when enabled");
    assert_eq!(tr_on.effective_tun_mtu, 1400);
    assert!(!tr_on.anytls_tfo);
    assert_eq!(tr_on.anytls_min_idle_session, 0);
    assert_eq!(tr_on.keep_alive_idle_sec, 45);
    assert!(
        tr_on.lb_strategy == "consistent-hashing" || tr_on.lb_strategy == "consistent_hashing"
    );

    // When core is running and cached `CompileStats.effective_tun_mtu` is present, prefer cached value.
    state.update_cached_runtime(CoreRuntimeStatus {
        running: true,
        ..Default::default()
    });
    state.set_last_effective_tun_mtu(Some(1380));
    let dto_running = build_runtime_info_dto(&state).expect("runtime dto while running");
    assert_eq!(dto_running.effective_tun_mtu, Some(1380));
    assert_eq!(
        dto_running
            .preaccel_transport
            .as_ref()
            .map(|t| t.effective_tun_mtu),
        Some(1380)
    );

    // AI diagnostics report + Markdown must include sanitized transport summary with zero IP/secret leaks.
    let report = build_sanitized_diagnostics_report(&state, None).expect("diagnostics report");
    assert_eq!(report["effective_tun_mtu"], 1380);
    assert_eq!(report["preaccel_transport"]["anytls_tfo"], false);
    assert_eq!(report["preaccel_transport"]["anytls_min_idle_session"], 0);
    assert_eq!(report["preaccel_transport"]["keep_alive_idle_sec"], 45);

    let md = report["ai_prompt_markdown"]
        .as_str()
        .expect("ai_prompt_markdown");
    assert!(md.contains("国内提速传输参数摘要"));
    assert!(md.contains("effective_mode=`"));
    assert!(md.contains("effective_tun_mtu=`1380`"));
    assert!(md.contains("anytls_tfo=false"));
    assert!(md.contains("min_idle_session=0"));
    assert!(md.contains("keep_alive_idle=45s"));
    assert!(md.contains("expected_probe_status=`"));
    assert!(md.contains("lb_strategy=`"));
    assert!(!md.contains("203.0.113.55"));
    assert!(!md.contains("10.20.30.40"));
    assert!(!md.contains("super_secret_relay_pw"));

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn resolve_local_cli_path_finds_portable_installer_resource_dir_and_unix_layouts() {
    let cli_bin = if cfg!(target_os = "windows") {
        "catcloud.exe"
    } else {
        "catcloud"
    };
    let root = std::env::temp_dir().join(format!(
        "catcloud_cli_resolve_test_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let bin_dir = root.join("data").join("bin");
    let root_data = root.join("data");
    std::fs::create_dir_all(&bin_dir).unwrap();

    // 1. Portable layout: `<exe_dir>/cli/catcloud(.exe)`
    let portable_exe_dir = root.join("portable");
    let portable_cli = portable_exe_dir.join("cli").join(cli_bin);
    std::fs::create_dir_all(portable_cli.parent().unwrap()).unwrap();
    std::fs::write(&portable_cli, b"cli").unwrap();
    assert_eq!(
        resolve_local_cli_path_from(Some(&portable_exe_dir), None, &bin_dir, &root_data),
        catcloud_core::paths::normalize_os_path(&portable_cli)
    );

    // 2. Tauri `resource_dir`: `<res>/resources/cli/catcloud(.exe)` (Linux AppImage / macOS / MSI)
    let isolated_exe_dir = root.join("isolated_bin");
    let res_dir = root.join("tauri_res");
    let res_cli = res_dir.join("resources").join("cli").join(cli_bin);
    std::fs::create_dir_all(&isolated_exe_dir).unwrap();
    std::fs::create_dir_all(res_cli.parent().unwrap()).unwrap();
    std::fs::write(&res_cli, b"cli").unwrap();
    assert_eq!(
        resolve_local_cli_path_from(
            Some(&isolated_exe_dir),
            Some(&res_dir),
            &bin_dir,
            &root_data
        ),
        catcloud_core::paths::normalize_os_path(&res_cli)
    );

    // 3. macOS `.app` layout without explicit resource_dir: `Contents/MacOS -> ../Resources/resources/cli/catcloud`
    let mac_exe_dir = root.join("CatCloud.app").join("Contents").join("MacOS");
    let mac_cli = root
        .join("CatCloud.app")
        .join("Contents")
        .join("Resources")
        .join("resources")
        .join("cli")
        .join(cli_bin);
    std::fs::create_dir_all(&mac_exe_dir).unwrap();
    std::fs::create_dir_all(mac_cli.parent().unwrap()).unwrap();
    std::fs::write(&mac_cli, b"cli").unwrap();
    assert_eq!(
        resolve_local_cli_path_from(Some(&mac_exe_dir), None, &bin_dir, &root_data),
        catcloud_core::paths::normalize_os_path(&mac_cli)
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn legacy_onboarding_reconcile_ui_dto_roundtrip_and_five_carrier_states() {
    // 1. Fresh empty DB keeps onboarding_completed = false.
    let tmp_fresh = std::env::temp_dir().join(format!(
        "catcloud_onboard_fresh_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths_fresh = AppPaths::from_data_dir(tmp_fresh.clone(), true).unwrap();
    let storage_fresh = Storage::open_in_memory().unwrap();
    let state_fresh = AppState::new(
        paths_fresh,
        AppConfig::default(),
        storage_fresh,
        Arc::new(JobGuard::new().unwrap()),
    );
    assert!(!state_fresh.snapshot_config().personalization.onboarding_completed);

    // 2. Existing user with at least one relay automatically gets onboarding_completed = true.
    let tmp_legacy = std::env::temp_dir().join(format!(
        "catcloud_onboard_legacy_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths_legacy = AppPaths::from_data_dir(tmp_legacy.clone(), true).unwrap();
    let storage_legacy = Storage::open_in_memory().unwrap();
    storage_legacy
        .upsert_preaccel_relay(&PreAccelRelay {
            id: "r-legacy".to_string(),
            name: "Legacy-Relay".to_string(),
            server: "203.0.113.10".to_string(),
            port: 443,
            protocol: "anytls".to_string(),
            password: "pw".to_string(),
            enabled: true,
            ..Default::default()
        })
        .unwrap();
    let state_legacy = AppState::new(
        paths_legacy,
        AppConfig::default(),
        storage_legacy,
        Arc::new(JobGuard::new().unwrap()),
    );
    assert!(state_legacy.snapshot_config().personalization.onboarding_completed);

    // 3. UiAppConfigDto roundtrip preserves onboarding_completed, dispatch_strategy, lb_strategy
    //    (ConsistentHashing default + explicit RoundRobin toggle both preserved).
    let mut cfg = AppConfig::default();
    assert_eq!(cfg.preaccel.lb_strategy, PreAccelLbStrategy::ConsistentHashing);
    cfg.personalization.onboarding_completed = true;
    cfg.preaccel.dispatch_strategy = PreAccelDispatchStrategy::LoadBalance;
    cfg.preaccel.lb_strategy = PreAccelLbStrategy::ConsistentHashing;
    let dto = UiAppConfigDto::from(&cfg);
    assert!(dto.personalization.onboarding_completed);
    assert_eq!(
        dto.preaccel.dispatch_strategy,
        Some(PreAccelDispatchStrategy::LoadBalance)
    );
    assert_eq!(
        dto.preaccel.lb_strategy,
        Some(PreAccelLbStrategy::ConsistentHashing)
    );
    let mut applied = AppConfig::default();
    applied.preaccel.active_relay_id = Some("r-pinned".to_string());
    apply_ui_dto(&mut applied, &dto);
    assert!(applied.personalization.onboarding_completed);
    assert_eq!(
        applied.preaccel.dispatch_strategy,
        PreAccelDispatchStrategy::LoadBalance
    );
    assert_eq!(
        applied.preaccel.lb_strategy,
        PreAccelLbStrategy::ConsistentHashing
    );
    assert_eq!(
        applied.preaccel.active_relay_id, None,
        "switching strategy to LoadBalance clears pinned relay"
    );
    let mut rr_dto = dto.clone();
    rr_dto.preaccel.lb_strategy = Some(PreAccelLbStrategy::RoundRobin);
    apply_ui_dto(&mut applied, &rr_dto);
    assert_eq!(applied.preaccel.lb_strategy, PreAccelLbStrategy::RoundRobin);

    // 4. Five locked effective_carrier states.
    let mut st_wd = GlobalPreAccelStatus::default();
    st_wd.running = true;
    st_wd.mode = "windivert".to_string();
    st_wd.is_windivert_active = true;
    assert_eq!(
        resolve_preaccel_effective_carrier(true, true, false, false, false, false, &st_wd),
        ("standalone_windivert", false)
    );

    let mut st_socks = GlobalPreAccelStatus::default();
    st_socks.running = true;
    st_socks.mode = "local_socks5".to_string();
    assert_eq!(
        resolve_preaccel_effective_carrier(true, true, false, false, false, false, &st_socks),
        ("standalone_socks5", false)
    );

    let mut st_susp = GlobalPreAccelStatus::default();
    st_susp.running = false;
    st_susp.mode = "suspended_for_tun".to_string();
    assert_eq!(
        resolve_preaccel_effective_carrier(true, true, true, true, true, false, &st_susp),
        ("main_core_tun_suspended_standalone", true)
    );

    let st_off = GlobalPreAccelStatus::default();
    assert_eq!(
        resolve_preaccel_effective_carrier(true, true, true, false, true, false, &st_off),
        ("main_core_proxy_only", false)
    );
    assert_eq!(
        resolve_preaccel_effective_carrier(false, true, true, false, true, false, &st_off),
        ("off", false)
    );

    let _ = std::fs::remove_dir_all(&tmp_fresh);
    let _ = std::fs::remove_dir_all(&tmp_legacy);
}

#[test]
fn diagnostics_report_and_recent_logs_leak_zero_fictional_ips_and_include_dns_diagnostics() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_strict_diag_ip_test_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), true).expect("resolve test paths");
    let storage = Storage::open_in_memory().expect("open in-memory storage");
    let job_guard = Arc::new(JobGuard::new().expect("job guard"));
    let state = AppState::new(paths, AppConfig::default(), storage, job_guard);

    // Inject raw unsanitized log lines directly into telemetry ring buffer (simulating Mihomo WS stream)
    // AND DNS TLS certificate rejection lines into disk logger.
    state.telemetry.push_log(CoreLogLine {
        level: "warning".to_string(),
        payload: "[TCP] 192.168.77.66:51234 --> 203.0.113.42:443 dial error via 10.42.8.19 tun 198.18.0.15 corp 172.18.9.33".to_string(),
        timestamp: "2026-11-26T03:44:50Z".to_string(),
    });
    state.app_logger.append_formatted(
        "2026-11-26T03:44:51Z",
        "warning",
        "mihomo",
        r#"[DNS] direct-nameserver Post "https://223.5.5.5/dns-query": tls: failed to verify certificate: x509: cannot validate certificate for 223.5.5.5 because it doesn't contain any IP SANs"#,
    );
    state.app_logger.append_formatted(
        "2026-11-26T03:45:43Z",
        "warning",
        "mihomo",
        r#"[DNS] proxy-server-nameserver Post "https://1.12.12.12/dns-query": tls: failed to verify certificate: x509: cannot validate certificate for 1.12.12.12 because it doesn't contain any IP SANs"#,
    );

    // 1. `get_recent_logs` backing helper must strictly sanitize every emitted CoreLogLine.
    let recent = collect_sanitized_recent_log_lines(&state, Some(50));
    assert!(!recent.is_empty());
    let recent_joined = serde_json::to_string(&recent).unwrap();
    for leaked in [
        "192.168.77.66",
        "203.0.113.42",
        "10.42.8.19",
        "198.18.0.15",
        "172.18.9.33",
    ] {
        assert!(
            !recent_joined.contains(leaked),
            "get_recent_logs leaked full IP `{leaked}`: {recent_joined}"
        );
    }
    assert!(recent_joined.contains("192.168.77.*"));
    assert!(recent_joined.contains("203.0.113.*"));
    assert!(recent_joined.contains("198.18.0.*"));

    // 2. Runtime DTO surfaces non-healthy `dns_tls_diagnostics`.
    let rt_dto = build_runtime_info_dto(&state).expect("build runtime dto");
    let rt_dns = rt_dto
        .dns_tls_diagnostics
        .expect("runtime dto must expose dns_tls_diagnostics when failing");
    assert_eq!(rt_dns.status, "cert_verification_failed");
    assert!(rt_dns.tls_verification_preserved);
    assert_eq!(rt_dns.failure_count, 2);

    // 3. Full sanitized diagnostics report includes `dns_diagnostics` + Markdown section and leaks 0 full IPs.
    let report =
        build_sanitized_diagnostics_report(&state, None).expect("build diagnostics report");
    assert_eq!(report["sanitized"], true);
    assert_eq!(
        report["dns_diagnostics"]["status"],
        "cert_verification_failed"
    );
    assert_eq!(report["dns_diagnostics"]["tls_verification_preserved"], true);
    assert_eq!(report["dns_diagnostics"]["failure_count"], 2);

    let md = report["ai_prompt_markdown"].as_str().unwrap();
    assert!(md.contains("DNS 加密解析与证书校验诊断"));
    assert!(md.contains("AliDNS DoH/DoT (223.5.5.*)"));
    assert!(md.contains("DNSPod DoH/DoT (1.12.12.*)"));

    let whole_json = serde_json::to_string(&report).unwrap();
    for leaked in [
        "192.168.77.66",
        "203.0.113.42",
        "10.42.8.19",
        "198.18.0.15",
        "172.18.9.33",
        "223.5.5.5",
        "1.12.12.12",
    ] {
        assert!(
            !whole_json.contains(leaked),
            "sanitized diagnostics report leaked full IP `{leaked}`"
        );
    }

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn stage20_apply_ui_dto_protects_skipped_version_and_latches_onboarding_completed() {
    let mut cfg = AppConfig::default();
    cfg.update.skipped_version = Some("0.1.1".to_string());
    cfg.personalization.onboarding_completed = false;

    let mut dto = UiAppConfigDto::from(&cfg);
    assert_eq!(dto.update.skipped_version.as_deref(), Some("0.1.1"));
    assert!(!dto.personalization.onboarding_completed);

    // Saving UI DTO with cleared or altered `skipped_version` MUST NOT mutate `cfg.update.skipped_version`.
    dto.update.skipped_version = None;
    dto.personalization.onboarding_completed = true;
    apply_ui_dto(&mut cfg, &dto);
    assert_eq!(cfg.update.skipped_version.as_deref(), Some("0.1.1"));
    assert!(cfg.personalization.onboarding_completed);

    // Attempt to overwrite `skipped_version` or regress `onboarding_completed` back to `false` MUST be blocked.
    dto.update.skipped_version = Some("9.9.9".to_string());
    dto.personalization.onboarding_completed = false;
    apply_ui_dto(&mut cfg, &dto);
    assert_eq!(cfg.update.skipped_version.as_deref(), Some("0.1.1"));
    assert!(
        cfg.personalization.onboarding_completed,
        "onboarding_completed must stay one-way latched once true"
    );
}

#[test]
fn stage21_5_export_gateway_yaml_core_paths_cover_redacted_plaintext_and_transparent_gateway() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_s21_5_gw_export_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), false).expect("create temp AppPaths");
    let storage = Storage::open_in_memory().expect("open memory storage");

    let sub = SubscriptionRecord {
        id: "sub-gw-demo".to_string(),
        name: "Demo Sub".to_string(),
        ..SubscriptionRecord::default()
    };
    storage.upsert_subscription(&sub).expect("upsert sub");

    let node = ProxyNode {
        id: "node-gw-1".to_string(),
        sub_id: "sub-gw-demo".to_string(),
        name: "SG-Edge-01".to_string(),
        protocol: "vless".to_string(),
        server: "edge.demo-vendor.example".to_string(),
        port: 8443,
        enabled: true,
        raw_config: serde_json::json!({
            "name": "SG-Edge-01",
            "type": "vless",
            "server": "edge.demo-vendor.example",
            "port": 8443,
            "uuid": "00000000-0000-4000-8000-000000000088",
            "tls": true,
            "network": "tcp"
        }),
        ..ProxyNode::default()
    };
    storage.upsert_node(&node).expect("upsert node");

    let relay = PreAccelRelay {
        id: "relay-gw-1".to_string(),
        name: "CN-Relay-Demo".to_string(),
        server: "198.51.100.88".to_string(),
        port: 443,
        protocol: "anytls".to_string(),
        password: "relay_secret_token_demo".to_string(),
        enabled: true,
        ..PreAccelRelay::default()
    };
    storage
        .upsert_preaccel_relay(&relay)
        .expect("upsert relay");

    let mut cfg = AppConfig::default();
    cfg.tun.enabled = true;
    cfg.allow_lan = false;
    cfg.preaccel.enabled = true;

    let state = AppState::new(
        paths,
        cfg,
        storage,
        Arc::new(JobGuard::new().expect("create JobGuard")),
    );

    assert_eq!(
        default_gateway_yaml_filename(GatewayExportProfile::RelayFragment),
        "catcloud-relay-fragment.yaml"
    );
    assert_eq!(
        default_gateway_yaml_filename(GatewayExportProfile::TransparentGateway),
        "catcloud-transparent-gateway.yaml"
    );
    assert_eq!(
        default_gateway_yaml_filename(GatewayExportProfile::PreferredNodes),
        "catcloud-preferred-nodes.yaml"
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");

    rt.block_on(async {
        // 1. RelayFragment (redacted): secrets and relay server must be masked.
        let redacted = export_gateway_yaml_async(
            &state,
            GatewayExportOptions {
                profile: GatewayExportProfile::RelayFragment,
                tproxy_port: 7893,
                redir_port: 7892,
                dns_listen_port: 1053,
                redact_secrets: true,
            },
        )
        .await
        .expect("redacted relay fragment export");
        assert_eq!(redacted.profile, GatewayExportProfile::RelayFragment);
        assert!(redacted.redacted);
        assert_eq!(redacted.relay_count, 1);
        assert!(!redacted.yaml.contains("relay_secret_token_demo"));
        assert!(!redacted.yaml.contains("198.51.100.88"));
        assert!(!redacted.yaml.contains("edge.demo-vendor.example"));

        // 2. RelayFragment (plaintext): deploys real relay credentials/endpoints.
        let plaintext = export_gateway_yaml_async(
            &state,
            GatewayExportOptions {
                profile: GatewayExportProfile::RelayFragment,
                tproxy_port: 7893,
                redir_port: 7892,
                dns_listen_port: 1053,
                redact_secrets: false,
            },
        )
        .await
        .expect("plaintext relay fragment export");
        assert_eq!(plaintext.profile, GatewayExportProfile::RelayFragment);
        assert!(!plaintext.redacted);
        assert_eq!(plaintext.relay_count, 1);
        assert!(plaintext.yaml.contains("relay_secret_token_demo"));
        assert!(plaintext.yaml.contains("198.51.100.88"));

        // 3. TransparentGateway: forces desktop TUN off, sets allow-lan & tproxy/redir ports.
        let gw = export_gateway_yaml_async(
            &state,
            GatewayExportOptions {
                profile: GatewayExportProfile::TransparentGateway,
                tproxy_port: 7893,
                redir_port: 7892,
                dns_listen_port: 1053,
                redact_secrets: true,
            },
        )
        .await
        .expect("transparent gateway export");
        assert_eq!(gw.profile, GatewayExportProfile::TransparentGateway);
        assert!(gw.yaml.contains("allow-lan: true"));
        assert!(gw.yaml.contains("tproxy-port: 7893"));
        assert!(gw.yaml.contains("redir-port: 7892"));
        assert!(!gw.yaml.contains("relay_secret_token_demo"));
        assert!(!gw.yaml.contains("198.51.100.88"));
        assert!(!gw.yaml.contains("edge.demo-vendor.example"));
        assert!(!gw.yaml.contains("00000000-0000-4000-8000-000000000088"));

        let mut in_tun_section = false;
        let mut tun_lines: Vec<&str> = Vec::new();
        for line in gw.yaml.lines() {
            let trimmed_end = line.trim_end();
            if trimmed_end == "tun:" {
                in_tun_section = true;
                continue;
            }
            if in_tun_section {
                if !trimmed_end.is_empty()
                    && !trimmed_end.starts_with(' ')
                    && !trimmed_end.starts_with('#')
                {
                    break;
                }
                tun_lines.push(trimmed_end.trim());
            }
        }
        assert!(
            tun_lines.iter().any(|l| *l == "enable: false"),
            "transparent gateway export must disable desktop TUN, got tun block: {tun_lines:?}"
        );
        assert!(
            !tun_lines.iter().any(|l| *l == "enable: true"),
            "transparent gateway export must never leave desktop TUN enabled"
        );
    });

    let _ = std::fs::remove_dir_all(&tmp);
}
