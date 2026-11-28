#[allow(unused_imports)]
use super::prelude::*;

#[test]
fn tray_group_candidates_pins_active_node_at_index_zero() {
    let nodes: Vec<ProxyNode> = (0..12)
        .map(|i| ProxyNode {
            id: format!("n-{i}"),
            name: format!("Node {i}"),
            enabled: true,
            ..Default::default()
        })
        .collect();
    let node_by_id: HashMap<&str, &ProxyNode> =
        nodes.iter().map(|n| (n.id.as_str(), n)).collect();
    let group = MultiGroup {
        id: "g1".to_string(),
        name: "主力".to_string(),
        member_node_ids: nodes.iter().map(|n| n.id.clone()).collect(),
        active_node_id: Some("n-11".to_string()),
        ..Default::default()
    };
    let picked = select_tray_group_candidates(&group, &nodes, &node_by_id, 8);
    assert_eq!(picked.len(), 8);
    assert_eq!(picked[0].id, "n-11");
    assert_eq!(picked[1].id, "n-0");
    assert_eq!(picked.iter().filter(|n| n.id == "n-11").count(), 1);
}

#[test]
fn sanitize_group_active_node_clears_ghost_and_picks_best_scored_candidate() {
    let ghost_ar = ProxyNode {
        id: "n-ar".to_string(),
        sub_id: "sub-1".to_string(),
        name: "🇦🇷 阿根廷".to_string(),
        enabled: true,
        multiplier: 1.0,
        ..Default::default()
    };
    let tw_slow = ProxyNode {
        id: "n-tw".to_string(),
        sub_id: "sub-1".to_string(),
        name: "🇹🇼 台湾 01".to_string(),
        enabled: true,
        multiplier: 1.0,
        ..Default::default()
    };
    let jp_best = ProxyNode {
        id: "n-jp".to_string(),
        sub_id: "sub-1".to_string(),
        name: "🇯🇵 日本 02".to_string(),
        enabled: true,
        multiplier: 1.0,
        ..Default::default()
    };
    let us_disabled = ProxyNode {
        id: "n-us-off".to_string(),
        sub_id: "sub-1".to_string(),
        name: "🇺🇸 已禁用".to_string(),
        enabled: false,
        multiplier: 1.0,
        ..Default::default()
    };
    let nodes = vec![ghost_ar, tw_slow, jp_best, us_disabled];

    let mut snaps = HashMap::new();
    snaps.insert(
        "n-tw".to_string(),
        ProbeSnapshot {
            node_id: "n-tw".to_string(),
            ok: true,
            latency_ms: Some(120.0),
            up_mbps: Some(10.0),
            down_mbps: Some(50.0),
            google_clean: Some(true),
            ..Default::default()
        },
    );
    snaps.insert(
        "n-jp".to_string(),
        ProbeSnapshot {
            node_id: "n-jp".to_string(),
            ok: true,
            latency_ms: Some(55.0),
            up_mbps: Some(80.0),
            down_mbps: Some(200.0),
            google_clean: Some(true),
            ..Default::default()
        },
    );

    let mut group = MultiGroup {
        id: "g-ai".to_string(),
        name: "测试多选组".to_string(),
        mode: MultiGroupMode::StickyBest,
        hard_gates: vec!["google_clean == 1".to_string()],
        member_node_ids: vec![
            "n-us-off".to_string(),
            "n-tw".to_string(),
            "n-jp".to_string(),
        ],
        active_node_id: Some("n-ar".to_string()),
        ..Default::default()
    };

    // 1. Ghost active_node_id outside member_node_ids is replaced by top-scoring candidate.
    assert!(sanitize_group_active_node(&mut group, &nodes, &snaps));
    assert_eq!(group.active_node_id.as_deref(), Some("n-jp"));

    // 2. Calling again while active_node_id is valid and enabled makes no change.
    assert!(!sanitize_group_active_node(&mut group, &nodes, &snaps));
    assert_eq!(group.active_node_id.as_deref(), Some("n-jp"));

    // 3. When no members are probed yet, ghost active_node_id falls back to first enabled member.
    let empty_snaps = HashMap::new();
    group.active_node_id = Some("n-ar".to_string());
    assert!(sanitize_group_active_node(&mut group, &nodes, &empty_snaps));
    assert_eq!(group.active_node_id.as_deref(), Some("n-tw"));

    // 4. When only disabled members remain, ghost active_node_id is cleared to None.
    group.member_node_ids = vec!["n-us-off".to_string()];
    group.active_node_id = Some("n-ar".to_string());
    assert!(sanitize_group_active_node(&mut group, &nodes, &snaps));
    assert_eq!(group.active_node_id, None);
}

#[test]
fn reconcile_group_best_node_preserves_healthy_sticky_choice_and_switches_unprobed_or_failed() {
    let n1 = ProxyNode {
        id: "n-1".to_string(),
        sub_id: "sub-1".to_string(),
        name: "台湾 01".to_string(),
        enabled: true,
        multiplier: 1.0,
        ..Default::default()
    };
    let n2 = ProxyNode {
        id: "n-2".to_string(),
        sub_id: "sub-1".to_string(),
        name: "日本 02".to_string(),
        enabled: true,
        multiplier: 1.0,
        ..Default::default()
    };
    let nodes = vec![n1, n2];

    let mut snaps = HashMap::new();
    snaps.insert(
        "n-1".to_string(),
        ProbeSnapshot {
            node_id: "n-1".to_string(),
            ok: true,
            latency_ms: Some(90.0),
            up_mbps: Some(20.0),
            down_mbps: Some(100.0),
            google_clean: Some(true),
            ..Default::default()
        },
    );
    snaps.insert(
        "n-2".to_string(),
        ProbeSnapshot {
            node_id: "n-2".to_string(),
            ok: true,
            latency_ms: Some(45.0),
            up_mbps: Some(120.0),
            down_mbps: Some(300.0),
            google_clean: Some(true),
            ..Default::default()
        },
    );

    let mut group = MultiGroup {
        id: "g-sticky".to_string(),
        name: "粘性组".to_string(),
        mode: MultiGroupMode::StickyBest,
        hard_gates: vec!["google_clean == 1".to_string()],
        member_node_ids: vec!["n-1".to_string(), "n-2".to_string()],
        active_node_id: Some("n-1".to_string()),
        ..Default::default()
    };

    // 1. Healthy & gate-passing user selection must NOT drift even though n-2 scores higher.
    assert!(reconcile_group_best_node_in_memory(&mut group, &nodes, &snaps).is_none());
    assert_eq!(group.active_node_id.as_deref(), Some("n-1"));

    // 2. When active node fails a hard gate, auto-switch to gate-passing n-2.
    snaps.get_mut("n-1").unwrap().google_clean = Some(false);
    let dec_gate = reconcile_group_best_node_in_memory(&mut group, &nodes, &snaps)
        .expect("should switch when hard gate fails");
    assert_eq!(dec_gate.to_node_id, "n-2");
    assert_eq!(group.active_node_id.as_deref(), Some("n-2"));

    // 3. When active node is unprobed while another member is healthy, auto-switch to healthy.
    group.active_node_id = Some("n-1".to_string());
    snaps.remove("n-1");
    let dec_unprobed = reconcile_group_best_node_in_memory(&mut group, &nodes, &snaps)
        .expect("should switch when active node is unprobed");
    assert_eq!(dec_unprobed.to_node_id, "n-2");
    assert_eq!(group.active_node_id.as_deref(), Some("n-2"));
}

#[test]
fn normalize_quick_site_probe_url_rewrites_legacy_chatgpt_root() {
    assert_eq!(
        normalize_quick_site_probe_url("https://chatgpt.com"),
        "https://chatgpt.com/cdn-cgi/trace"
    );
    assert_eq!(
        normalize_quick_site_probe_url("HTTPS://CHATGPT.COM/"),
        "https://chatgpt.com/cdn-cgi/trace"
    );
    assert_eq!(
        normalize_quick_site_probe_url("https://chatgpt.com/cdn-cgi/trace"),
        "https://chatgpt.com/cdn-cgi/trace"
    );
    assert_eq!(
        normalize_quick_site_probe_url("https://www.google.com/generate_204"),
        "https://www.google.com/generate_204"
    );
}

#[test]
fn pick_best_group_candidate_ranks_gate_rejected_by_score_when_all_fail_gates() {
    let tw_slow = ProxyNode {
        id: "n-tw".to_string(),
        sub_id: "sub-1".to_string(),
        name: "台湾慢节点".to_string(),
        enabled: true,
        multiplier: 1.0,
        ..Default::default()
    };
    let jp_fast = ProxyNode {
        id: "n-jp".to_string(),
        sub_id: "sub-1".to_string(),
        name: "日本快节点".to_string(),
        enabled: true,
        multiplier: 1.0,
        ..Default::default()
    };
    let sg_disabled = ProxyNode {
        id: "n-sg-off".to_string(),
        sub_id: "sub-1".to_string(),
        name: "新加坡禁用".to_string(),
        enabled: false,
        multiplier: 0.5,
        ..Default::default()
    };
    let nodes = vec![tw_slow, jp_fast, sg_disabled];

    let mut snaps = HashMap::new();
    snaps.insert(
        "n-tw".to_string(),
        ProbeSnapshot {
            node_id: "n-tw".to_string(),
            ok: true,
            latency_ms: Some(140.0),
            up_mbps: Some(8.0),
            down_mbps: Some(40.0),
            keepalive_60s_ok: None,
            ..Default::default()
        },
    );
    snaps.insert(
        "n-jp".to_string(),
        ProbeSnapshot {
            node_id: "n-jp".to_string(),
            ok: true,
            latency_ms: Some(45.0),
            up_mbps: Some(95.0),
            down_mbps: Some(200.0),
            keepalive_60s_ok: None,
            ..Default::default()
        },
    );

    // Hard gate `keepalive_ok == 1` rejects all members when 60s keepalive hasn't been probed;
    // fallback must still pick the highest-scored enabled member (`n-jp`), not `member_node_ids[0]` (`n-tw`).
    let mut group = MultiGroup {
        id: "g-keepalive".to_string(),
        name: "长连接门禁组".to_string(),
        mode: MultiGroupMode::StickyBest,
        hard_gates: vec!["keepalive_ok == 1".to_string()],
        member_node_ids: vec![
            "n-sg-off".to_string(),
            "n-tw".to_string(),
            "n-jp".to_string(),
        ],
        active_node_id: Some("n-tw".to_string()),
        ..Default::default()
    };

    assert_eq!(
        pick_best_group_candidate(&group, &nodes, &snaps, None).as_deref(),
        Some("n-jp")
    );
    assert_eq!(
        pick_best_group_candidate(&group, &nodes, &snaps, Some("n-jp")).as_deref(),
        Some("n-tw")
    );

    // Sticky preservation: when active `n-tw` is already ok and no node passes hard gates, do not drift.
    assert!(reconcile_group_best_node_in_memory(&mut group, &nodes, &snaps).is_none());
    assert_eq!(group.active_node_id.as_deref(), Some("n-tw"));

    // When active `n-tw` is unprobed while `n-jp` is ok (even if gate-rejected), switch to `n-jp`.
    snaps.remove("n-tw");
    let switched = reconcile_group_best_node_in_memory(&mut group, &nodes, &snaps)
        .expect("should switch unprobed active node to highest-scored ok fallback");
    assert_eq!(switched.to_node_id, "n-jp");
    assert_eq!(group.active_node_id.as_deref(), Some("n-jp"));
}

#[test]
fn select_reconcilable_active_group_ids_respects_route_mode_and_compiled_set() {
    let g_active = MultiGroup {
        id: "g-active".to_string(),
        name: "主力组".to_string(),
        mode: MultiGroupMode::StickyBest,
        independent_routing: false,
        ..Default::default()
    };
    let g_indep = MultiGroup {
        id: "g-indep".to_string(),
        name: "独立AI组".to_string(),
        mode: MultiGroupMode::ConditionalPool,
        independent_routing: true,
        ..Default::default()
    };
    let g_inactive = MultiGroup {
        id: "g-inactive".to_string(),
        name: "未选中组".to_string(),
        mode: MultiGroupMode::StickyBest,
        independent_routing: false,
        ..Default::default()
    };
    let groups = vec![g_active, g_indep, g_inactive];

    // 1. Single-node route mode must never select any multi-group for post-probe reconciliation.
    let mut single_cfg = AppConfig::default();
    single_cfg.route_mode = RouteTargetMode::Single;
    single_cfg.active_group_id = Some("g-active".to_string());
    assert!(select_reconcilable_active_group_ids(&single_cfg, &groups, None).is_empty());

    // 2. Group route mode with no compiled filter includes primary + independent strategy groups only.
    let mut group_cfg = AppConfig::default();
    group_cfg.route_mode = RouteTargetMode::Group;
    group_cfg.active_group_id = Some("g-active".to_string());
    assert_eq!(
        select_reconcilable_active_group_ids(&group_cfg, &groups, None),
        vec!["g-active".to_string(), "g-indep".to_string()]
    );

    // 3. When running with a pruned compiled set, groups outside the compiled set are excluded.
    let compiled_only_active: HashSet<String> = ["g-active".to_string()].into_iter().collect();
    assert_eq!(
        select_reconcilable_active_group_ids(&group_cfg, &groups, Some(&compiled_only_active)),
        vec!["g-active".to_string()]
    );
}

#[test]
fn lookup_compiled_proxy_name_prevents_uncompiled_same_name_fallback() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_compiled_map_test_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), true).expect("resolve test paths");
    let storage = Storage::open_in_memory().expect("open in-memory storage");
    let job_guard = Arc::new(JobGuard::new().expect("job guard"));
    let state = AppState::new(paths, AppConfig::default(), storage, job_guard);

    let mut compiled_map = HashMap::new();
    compiled_map.insert("node-sub-a".to_string(), "香港 01".to_string());
    state.set_node_proxy_name_map(compiled_map);

    assert_eq!(
        state.lookup_compiled_proxy_name("node-sub-a").as_deref(),
        Some("香港 01")
    );
    assert_eq!(state.lookup_compiled_proxy_name("node-sub-b"), None);

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn summarize_throughput_probe_error_maps_causes_to_chinese() {
    assert_eq!(
        summarize_throughput_probe_error("上行测速", Some("operation timed out")),
        "上行测速超时"
    );
    assert!(
        summarize_throughput_probe_error(
            "下行测速",
            Some("fast_fuse_triggered: down_mbps=0.10 < 0.20")
        )
        .contains("保护熔断")
    );
    assert!(
        summarize_throughput_probe_error("上行测速", Some("unexpected upload HTTP status 502"))
            .contains("异常状态码")
    );
}

#[test]
fn pick_group_candidates_with_cooldown_excludes_and_falls_back_when_all_cooled() {
    let make_node = |id: &str, name: &str| ProxyNode {
        id: id.to_string(),
        sub_id: "sub-1".to_string(),
        name: name.to_string(),
        enabled: true,
        multiplier: 1.0,
        ..Default::default()
    };
    let nodes = vec![
        make_node("n-a", "节点A"),
        make_node("n-b", "节点B"),
        make_node("n-c", "节点C"),
        make_node("n-d", "节点D"),
    ];

    let mut snaps = HashMap::new();
    for (id, latency, up) in [
        ("n-a", 30.0, 120.0),
        ("n-b", 40.0, 100.0),
        ("n-c", 55.0, 80.0),
        ("n-d", 80.0, 50.0),
    ] {
        snaps.insert(
            id.to_string(),
            ProbeSnapshot {
                node_id: id.to_string(),
                ok: true,
                latency_ms: Some(latency),
                up_mbps: Some(up),
                down_mbps: Some(up * 2.0),
                ..Default::default()
            },
        );
    }

    let group = MultiGroup {
        id: "g-watch".to_string(),
        name: "主力组".to_string(),
        mode: MultiGroupMode::StickyBest,
        member_node_ids: vec![
            "n-a".to_string(),
            "n-b".to_string(),
            "n-c".to_string(),
            "n-d".to_string(),
        ],
        active_node_id: Some("n-a".to_string()),
        ..Default::default()
    };

    // Active is n-a, n-b is in 5-minute cooldown -> returns [n-c, n-d] in priority order.
    let mut cooldowns = HashSet::new();
    cooldowns.insert("n-b".to_string());
    let ranked = pick_group_candidates_with_cooldown(
        &group,
        &nodes,
        &snaps,
        Some("n-a"),
        &cooldowns,
        3,
    );
    assert_eq!(ranked, vec!["n-c".to_string(), "n-d".to_string()]);

    // All backup nodes (n-b, n-c, n-d) are in cooldown -> relaxes cooldowns as last resort
    // while still excluding active node `n-a`.
    cooldowns.insert("n-c".to_string());
    cooldowns.insert("n-d".to_string());
    let fallback = pick_group_candidates_with_cooldown(
        &group,
        &nodes,
        &snaps,
        Some("n-a"),
        &cooldowns,
        3,
    );
    assert_eq!(
        fallback,
        vec!["n-b".to_string(), "n-c".to_string(), "n-d".to_string()]
    );
    assert!(!fallback.contains(&"n-a".to_string()));
}

#[test]
fn apply_migration_nodes_rebinds_ids_without_primary_key_collision() {
    let mut storage = Storage::open_in_memory().expect("open in-memory storage");

    let sample_nodes = vec![
        ProxyNode {
            id: "node_duplicate_preview_1".to_string(),
            sub_id: "preview_local_profile".to_string(),
            name: "HK 01".to_string(),
            protocol: "trojan".to_string(),
            server: "203.0.113.10".to_string(),
            port: 443,
            raw_config: serde_json::json!({
                "name": "HK 01",
                "type": "trojan",
                "server": "203.0.113.10",
                "port": 443,
                "password": "placeholder-password"
            }),
            region_code: "HK".to_string(),
            multiplier: 1.0,
            is_443_native: true,
            preaccel_eligible: true,
            preaccel_override: None,
            tags: Vec::new(),
            enabled: true,
        },
        ProxyNode {
            id: "node_duplicate_preview_1".to_string(),
            sub_id: "preview_local_profile".to_string(),
            name: "HK 01".to_string(),
            protocol: "trojan".to_string(),
            server: "203.0.113.10".to_string(),
            port: 443,
            raw_config: serde_json::json!({
                "name": "HK 01",
                "type": "trojan",
                "server": "203.0.113.10",
                "port": 443,
                "password": "placeholder-password"
            }),
            region_code: "HK".to_string(),
            multiplier: 1.0,
            is_443_native: true,
            preaccel_eligible: true,
            preaccel_override: None,
            tags: Vec::new(),
            enabled: true,
        },
        ProxyNode {
            id: "node_duplicate_preview_2".to_string(),
            sub_id: "preview_local_profile".to_string(),
            name: "JP 01".to_string(),
            protocol: "vless".to_string(),
            server: "198.51.100.20".to_string(),
            port: 443,
            raw_config: serde_json::json!({
                "name": "JP 01",
                "type": "vless",
                "server": "198.51.100.20",
                "port": 443,
                "uuid": "00000000-0000-4000-8000-000000000099"
            }),
            region_code: "JP".to_string(),
            multiplier: 1.0,
            is_443_native: true,
            preaccel_eligible: true,
            preaccel_override: None,
            tags: Vec::new(),
            enabled: true,
        },
    ];

    assert!(persist_migration_nodes(&mut storage, "空导入".to_string(), Vec::new()).is_err());

    let (sub1, count1) =
        persist_migration_nodes(&mut storage, "迁移批次 A".to_string(), sample_nodes.clone())
            .expect("first migration import");
    let (sub2, count2) =
        persist_migration_nodes(&mut storage, "迁移批次 B".to_string(), sample_nodes)
            .expect("second migration import");

    assert_eq!(count1, 3);
    assert_eq!(count2, 3);
    assert_ne!(sub1, sub2);

    let all_nodes = storage.list_nodes().expect("list persisted nodes");
    assert_eq!(
        all_nodes.len(),
        6,
        "repeated migrations with identical node names must never collide or overwrite"
    );

    let unique_ids: HashSet<&str> = all_nodes.iter().map(|n| n.id.as_str()).collect();
    assert_eq!(unique_ids.len(), 6);
    assert!(all_nodes.iter().all(|n| n.id.starts_with("node_")));
    assert_eq!(all_nodes.iter().filter(|n| n.sub_id == sub1).count(), 3);
    assert_eq!(all_nodes.iter().filter(|n| n.sub_id == sub2).count(), 3);
}

#[test]
fn pick_group_candidates_with_runtime_pool_respects_cooldown_and_relaxes_when_all_cooled() {
    let make_node = |id: &str, name: &str| ProxyNode {
        id: id.to_string(),
        sub_id: "sub-1".to_string(),
        name: name.to_string(),
        enabled: true,
        multiplier: 1.0,
        ..Default::default()
    };
    let nodes = vec![
        make_node("n-a", "节点A"),
        make_node("n-b", "节点B"),
        make_node("n-c", "节点C"),
    ];
    let mut snaps = HashMap::new();
    for (id, latency) in [("n-a", 40.0), ("n-b", 45.0), ("n-c", 80.0)] {
        snaps.insert(
            id.to_string(),
            ProbeSnapshot {
                node_id: id.to_string(),
                ok: true,
                latency_ms: Some(latency),
                up_mbps: Some(100.0),
                down_mbps: Some(200.0),
                ..Default::default()
            },
        );
    }
    let group = MultiGroup {
        id: "g-pool".to_string(),
        name: "池化测试组".to_string(),
        mode: MultiGroupMode::StickyBest,
        member_node_ids: vec!["n-a".into(), "n-b".into(), "n-c".into()],
        active_node_id: Some("n-a".into()),
        ..Default::default()
    };

    let now = Instant::now();
    let mut pool = NodeHealthPool::new();
    pool.record_probe_result("n-b", RuntimeDualHealth::Failed, None, now);

    let empty_local = HashSet::new();
    let ranked = pick_group_candidates_with_cooldown_and_runtime(
        &group,
        &nodes,
        &snaps,
        Some("n-a"),
        &empty_local,
        Some(&pool),
        now,
        3,
    );
    assert_eq!(ranked, vec!["n-c".to_string()]);

    // When all backups are in runtime pool cooldown (with empty hard_gates), fallback honors
    // shortest remaining cooldown order (n-b failed earlier so expires sooner than n-c).
    let later = now + Duration::from_secs(20);
    pool.record_probe_result("n-c", RuntimeDualHealth::Failed, None, later);
    let fallback = pick_group_candidates_with_cooldown_and_runtime(
        &group,
        &nodes,
        &snaps,
        Some("n-a"),
        &empty_local,
        Some(&pool),
        later,
        3,
    );
    assert_eq!(fallback, vec!["n-b".to_string(), "n-c".to_string()]);
    assert!(!fallback.contains(&"n-a".to_string()));
}

#[test]
fn subscription_proxy_candidates_prefer_direct_then_core_then_distinct_local_sys_proxy() {
    let local_same = SystemProxySpec {
        enabled: true,
        host: "localhost".to_string(),
        port: 7890,
        bypass: Vec::new(),
        pac_url: None,
    };
    assert_eq!(
        build_subscription_proxy_candidates_from(Some(7890), Some(&local_same)),
        vec![None, Some("http://127.0.0.1:7890".to_string())]
    );

    let local_other = SystemProxySpec {
        enabled: true,
        host: "127.0.0.1".to_string(),
        port: 10809,
        bypass: Vec::new(),
        pac_url: None,
    };
    assert_eq!(
        build_subscription_proxy_candidates_from(Some(7890), Some(&local_other)),
        vec![
            None,
            Some("http://127.0.0.1:7890".to_string()),
            Some("http://127.0.0.1:10809".to_string()),
        ]
    );

    // Remote LAN/corporate proxy or PAC URL must be ignored for local fallback.
    let remote_proxy = SystemProxySpec {
        enabled: true,
        host: "192.168.1.20".to_string(),
        port: 8080,
        bypass: Vec::new(),
        pac_url: None,
    };
    let pac_proxy = SystemProxySpec {
        enabled: true,
        host: "127.0.0.1".to_string(),
        port: 10809,
        bypass: Vec::new(),
        pac_url: Some("http://127.0.0.1:10808/proxy.pac".to_string()),
    };
    assert_eq!(
        build_subscription_proxy_candidates_from(None, Some(&remote_proxy)),
        vec![None]
    );
    assert_eq!(
        build_subscription_proxy_candidates_from(None, Some(&pac_proxy)),
        vec![None]
    );
}

#[test]
fn format_subscription_error_zh_eliminates_all_english_error_residue() {
    let cases = [
        (
            "订阅链接格式不正确，请确认完整复制了链接（relative URL without a base）",
            "格式不正确",
        ),
        (
            "拉取订阅失败（invalid certificate: self signed）",
            "握手失败",
        ),
        (
            "解析失败：expected mapping at line 12 column 4",
            "格式无法解析",
        ),
        (
            "请求异常：dns error: failed to lookup address information",
            "域名解析失败",
        ),
        (
            "代理连接失败：tcp connect error: connection refused (os error 10061)",
            "被拒绝",
        ),
        (
            "拉取失败：operation timed out after 15s",
            "超时",
        ),
        (
            "上游响应错误：status 403 forbidden",
            "HTTP 403",
        ),
        (
            "上游响应错误：status 502 bad gateway",
            "HTTP 5xx",
        ),
        (
            "weird unknown upstream xyz failure without category",
            "拉取或解析订阅失败",
        ),
        (
            "网络请求失败（error sending request for url (https://secret:pw@sub.example.com/get)）",
            "无法连接到订阅服务器",
        ),
    ];

    for (raw, expected_substr) in cases {
        let formatted = format_subscription_error_zh(raw);
        assert!(
            formatted.contains(expected_substr),
            "expected `{expected_substr}` in `{formatted}` (from `{raw}`)"
        );
        assert!(
            !contains_english_error_residue(&formatted),
            "english residue leaked in `{formatted}` (from `{raw}`)"
        );
        assert!(!formatted.contains("weird unknown"));
        assert!(!formatted.contains("relative URL"));
        assert!(!formatted.contains("expected mapping"));
        assert!(!formatted.contains("secret:pw"));
    }

    // Clean pure-Chinese messages pass through unchanged.
    let clean_zh = "订阅认证失败（HTTP 401），链接里的访问令牌可能已失效或被重置";
    assert_eq!(format_subscription_error_zh(clean_zh), clean_zh);
}

#[test]
fn upsert_subscription_deduplicates_normalized_and_clash_wrapped_urls() {
    let db = Storage::open_in_memory().expect("open in-memory storage");

    let first = upsert_subscription_in_storage(
        &db,
        SubscriptionRecord {
            id: String::new(),
            name: "主力机场".to_string(),
            kind: SubscriptionKind::Url,
            url_or_cmd: "  https://Sub.Example.COM:443/api/sub?token=AbC123  ".to_string(),
            traffic_total_bytes: 100 * 1024 * 1024,
            traffic_used_bytes: 20 * 1024 * 1024,
            enabled: true,
            ..Default::default()
        },
    )
    .expect("insert first sub");
    assert!(!first.id.is_empty());

    // Same URL with different casing + new ID should reuse existing record instead of duplicating.
    let second = upsert_subscription_in_storage(
        &db,
        SubscriptionRecord {
            id: "sub-new-dup-id".to_string(),
            name: "主力机场（重命名）".to_string(),
            kind: SubscriptionKind::Url,
            url_or_cmd: "HTTPS://sub.example.com/api/sub?token=AbC123".to_string(),
            enabled: true,
            ..Default::default()
        },
    )
    .expect("dedup second sub");
    assert_eq!(second.id, first.id);
    assert_eq!(second.name, "主力机场（重命名）");
    assert_eq!(second.traffic_total_bytes, 100 * 1024 * 1024);
    assert_eq!(db.list_subscriptions().unwrap().len(), 1);

    // clash:// one-click install link wrapping the exact same URL also deduplicates & unwraps.
    let third = upsert_subscription_in_storage(
        &db,
        SubscriptionRecord {
            id: String::new(),
            name: String::new(),
            kind: SubscriptionKind::Url,
            url_or_cmd: "clash://install-config?url=https%3A%2F%2Fsub.example.com%2Fapi%2Fsub%3Ftoken%3DAbC123&name=Ignored".to_string(),
            enabled: true,
            ..Default::default()
        },
    )
    .expect("dedup clash wrapped sub");
    assert_eq!(third.id, first.id);
    assert_eq!(third.name, "主力机场（重命名）");
    assert_eq!(
        third.url_or_cmd,
        "https://sub.example.com/api/sub?token=AbC123"
    );
    assert_eq!(db.list_subscriptions().unwrap().len(), 1);

    // Explicit update of an existing ID updates that ID directly.
    let updated = upsert_subscription_in_storage(
        &db,
        SubscriptionRecord {
            id: first.id.clone(),
            name: "显式更新".to_string(),
            kind: SubscriptionKind::Url,
            url_or_cmd: "https://other.example.com/sub?token=xyz".to_string(),
            enabled: true,
            ..Default::default()
        },
    )
    .expect("explicit update by id");
    assert_eq!(updated.id, first.id);
    assert_eq!(updated.name, "显式更新");
    assert_eq!(db.list_subscriptions().unwrap().len(), 1);
}

#[test]
fn smart_default_node_and_comparison_node_avoid_obscure_high_mult_and_info_banners() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_smart_default_test_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), true).expect("resolve test paths");
    let storage = Storage::open_in_memory().expect("open in-memory storage");
    storage
        .upsert_subscription(&SubscriptionRecord {
            id: "sub-test".to_string(),
            name: "Test Sub".to_string(),
            ..Default::default()
        })
        .expect("upsert subscription");

    let info_node = ProxyNode {
        id: "n-info".to_string(),
        sub_id: "sub-test".to_string(),
        name: "剩余流量：120 GB · 到期 2027-01-01".to_string(),
        protocol: "trojan".to_string(),
        server: "info.example.invalid".to_string(),
        port: 443,
        region_code: "UNK".to_string(),
        multiplier: 1.0,
        enabled: true,
        ..Default::default()
    };
    let andorra_3x = ProxyNode {
        id: "n-ad".to_string(),
        sub_id: "sub-test".to_string(),
        name: "AD 安道尔 | 3x AD".to_string(),
        protocol: "vless".to_string(),
        server: "ad.example.invalid".to_string(),
        port: 8443,
        region_code: "AD".to_string(),
        multiplier: 3.0,
        is_443_native: false,
        enabled: true,
        ..Default::default()
    };
    let jp_1x = ProxyNode {
        id: "n-jp".to_string(),
        sub_id: "sub-test".to_string(),
        name: "JP 东京 01".to_string(),
        protocol: "vless".to_string(),
        server: "jp.example.invalid".to_string(),
        port: 8443,
        region_code: "JP".to_string(),
        multiplier: 1.0,
        is_443_native: false,
        enabled: true,
        ..Default::default()
    };
    let tw_1x = ProxyNode {
        id: "n-tw".to_string(),
        sub_id: "sub-test".to_string(),
        name: "TW 台北 01".to_string(),
        protocol: "trojan".to_string(),
        server: "tw.example.invalid".to_string(),
        port: 8443,
        region_code: "TW".to_string(),
        multiplier: 1.0,
        is_443_native: false,
        enabled: true,
        ..Default::default()
    };

    for n in [&info_node, &andorra_3x, &jp_1x, &tw_1x] {
        storage.upsert_node(n).expect("upsert node");
    }

    let mut cfg = AppConfig::default();
    cfg.active_single_node_id = Some("deleted-stale-node".to_string());
    let job_guard = Arc::new(JobGuard::new().expect("job guard"));
    let state = AppState::new(paths, cfg, storage, job_guard);

    // 1. Default group auto-creation must pick preferred low-multiplier node (TW), never AD 3x or info banner.
    assert!(ensure_default_group_if_empty(&state));
    let created_groups = state
        .storage
        .lock()
        .unwrap()
        .list_multi_groups()
        .expect("list groups");
    assert_eq!(created_groups.len(), 1);
    assert_eq!(created_groups[0].active_node_id.as_deref(), Some("n-tw"));

    // 2. Single-node stale fallback must also pick smart preferred node (TW), never AD 3x or info banner.
    let remapped = remap_active_single_node_id_if_needed(&state, &HashMap::new())
        .expect("remap stale single node");
    assert!(remapped);
    assert_eq!(
        state.snapshot_config().active_single_node_id.as_deref(),
        Some("n-tw")
    );

    // 3. Comparison node auto-selection must avoid obscure >= 3x homepage node and info banner,
    // while strictly honoring explicit user selection.
    let all_nodes = vec![
        info_node.clone(),
        andorra_3x.clone(),
        jp_1x.clone(),
        tw_1x.clone(),
    ];
    let (picked_auto, reason_auto) = select_comparison_overseas_node(
        &[],
        &all_nodes,
        RouteTargetMode::Single,
        Some("n-ad"),
        None,
        None,
        false,
    )
    .expect("auto comparison selection avoids obscure 3x node");
    assert_eq!(picked_auto.id, "n-tw");
    assert!(reason_auto
        .as_deref()
        .is_some_and(|r| r.contains("冷门高倍率") && r.contains("TW 台北 01")));

    let (picked_info_fallback, reason_info) = select_comparison_overseas_node(
        &[],
        &all_nodes,
        RouteTargetMode::Single,
        Some("n-info"),
        None,
        None,
        false,
    )
    .expect("auto comparison selection avoids info banner");
    assert_eq!(picked_info_fallback.id, "n-tw");
    assert!(reason_info
        .as_deref()
        .is_some_and(|r| r.contains("信息提示节点")));

    let (picked_explicit, reason_explicit) = select_comparison_overseas_node(
        &[],
        &all_nodes,
        RouteTargetMode::Single,
        Some("n-tw"),
        None,
        Some("n-ad"),
        false,
    )
    .expect("explicit selection must honor AD 3x");
    assert_eq!(picked_explicit.id, "n-ad");
    assert!(reason_explicit.is_none());

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn isolated_probe_batch_summary_splits_all_six_metrics_cleanly() {
    let mut run_snapshots = HashMap::new();
    let mut run_records = HashMap::new();
    let latency_ids: HashSet<String> = ["builtin_latency".to_string()].into_iter().collect();

    // Node 1: latency ok, both up & down ok, keepalive ok.
    run_snapshots.insert(
        "n1".to_string(),
        ProbeSnapshot {
            node_id: "n1".to_string(),
            ok: true,
            latency_ms: Some(45.0),
            up_mbps: Some(20.0),
            down_mbps: Some(150.0),
            keepalive_60s_ok: Some(true),
            ..Default::default()
        },
    );
    run_records.insert(
        "n1".to_string(),
        vec![catcloud_core::models::ProbeResultRecord {
            node_id: "n1".to_string(),
            probe_id: "builtin_latency".to_string(),
            ok: true,
            latency_ms: Some(45.0),
            ..Default::default()
        }],
    );

    // Node 2: latency ok, ONLY download ok (upload missing -> NOT bidirectional bandwidth ok).
    run_snapshots.insert(
        "n2".to_string(),
        ProbeSnapshot {
            node_id: "n2".to_string(),
            ok: true,
            latency_ms: Some(68.0),
            up_mbps: None,
            down_mbps: Some(90.0),
            keepalive_60s_ok: Some(false),
            ..Default::default()
        },
    );
    run_records.insert(
        "n2".to_string(),
        vec![catcloud_core::models::ProbeResultRecord {
            node_id: "n2".to_string(),
            probe_id: "builtin_latency".to_string(),
            ok: true,
            latency_ms: Some(68.0),
            ..Default::default()
        }],
    );

    // Node 3: latency failed.
    run_snapshots.insert(
        "n3".to_string(),
        ProbeSnapshot {
            node_id: "n3".to_string(),
            ok: false,
            ..Default::default()
        },
    );
    run_records.insert(
        "n3".to_string(),
        vec![catcloud_core::models::ProbeResultRecord {
            node_id: "n3".to_string(),
            probe_id: "builtin_latency".to_string(),
            ok: false,
            ..Default::default()
        }],
    );

    // Total 5 nodes, completed 4 (3 snapshots + 1 exec error), 1 untested.
    let summary =
        summarize_isolated_probe_run(5, 4, &run_snapshots, &run_records, &latency_ids, 1);
    assert_eq!(summary.latency_ok_count, 2);
    assert_eq!(summary.bandwidth_ok_count, 1);
    assert_eq!(summary.keepalive_ok_count, 1);
    assert_eq!(summary.failed_count, 1);
    assert_eq!(summary.exec_error_count, 1);
    assert_eq!(summary.untested_count, 1);
}

#[test]
fn stage22_isolated_probe_health_pool_and_throughput_ok_guards() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_s22_health_bw_{}",
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

    // Seed healthy node in runtime health pool.
    state.record_node_health_probe("n1", RuntimeDualHealth::FullHealthy, Some(42.0));
    let latency_ids: HashSet<String> = ["builtin_latency".to_string()].into_iter().collect();

    // 1. Running only Unlock/Upload probes (NO Latency record) MUST NOT wipe existing health pool!
    let unlock_rec = catcloud_core::models::ProbeResultRecord {
        node_id: "n1".to_string(),
        probe_id: "builtin_unlock_claude".to_string(),
        ok: false,
        ..Default::default()
    };
    let unlock_snap = ProbeSnapshot {
        node_id: "n1".to_string(),
        ok: false,
        ..Default::default()
    };
    update_node_health_pool_after_isolated_probe(
        &state,
        "n1",
        &[unlock_rec],
        &latency_ids,
        &unlock_snap,
    );
    assert_eq!(
        state.snapshot_node_health_pool().live_latency_ms("n1"),
        Some(42.0),
        "non-Latency probe run must preserve existing node_health_pool latency"
    );

    // 2. Running a Latency probe that FAILS MUST reset stale latency and mark node Failed.
    let fail_lat_rec = catcloud_core::models::ProbeResultRecord {
        node_id: "n1".to_string(),
        probe_id: "builtin_latency".to_string(),
        ok: false,
        ..Default::default()
    };
    let fail_snap = ProbeSnapshot {
        node_id: "n1".to_string(),
        ok: false,
        latency_ms: None,
        ..Default::default()
    };
    update_node_health_pool_after_isolated_probe(
        &state,
        "n1",
        &[fail_lat_rec],
        &latency_ids,
        &fail_snap,
    );
    let pool_after_fail = state.snapshot_node_health_pool();
    assert_eq!(pool_after_fail.live_latency_ms("n1"), None);
    assert_eq!(
        pool_after_fail.get("n1").and_then(|e| e.last_health),
        Some(RuntimeDualHealth::Failed)
    );

    // 3. Running a Latency probe that SUCCEEDS clears stale Failed/cooldown state via
    //    `reset_node_health` WITHOUT fabricating a background watchdog `FullHealthy` hint.
    let ok_lat_rec = catcloud_core::models::ProbeResultRecord {
        node_id: "n1".to_string(),
        probe_id: "builtin_latency".to_string(),
        ok: true,
        latency_ms: Some(36.0),
        ..Default::default()
    };
    let ok_snap = ProbeSnapshot {
        node_id: "n1".to_string(),
        ok: true,
        latency_ms: Some(36.0),
        ..Default::default()
    };
    update_node_health_pool_after_isolated_probe(
        &state,
        "n1",
        &[ok_lat_rec.clone()],
        &latency_ids,
        &ok_snap,
    );
    let pool_after_ok = state.snapshot_node_health_pool();
    assert!(
        pool_after_ok.get("n1").is_none(),
        "manual latency pass must clear cooldown via reset_node_health without faking watchdog entry"
    );
    assert!(
        state.snapshot_node_health_hints().get("n1").is_none(),
        "manual latency pass must NEVER fabricate a health_hint claiming background probe"
    );

    // 3b. Multiple Latency probes in one run: `builtin_latency` passes (40ms) while a
    //     secondary custom Latency probe fails; `merged_snap.ok == true` (matching
    //     `from_results_with_kinds` priority). Must clear old cooldown and NOT mark Failed!
    state.record_node_health_probe("n1", RuntimeDualHealth::Failed, None);
    let multi_latency_ids: HashSet<String> = [
        "builtin_latency".to_string(),
        "custom_latency_alt".to_string(),
    ]
    .into_iter()
    .collect();
    let builtin_ok_rec = catcloud_core::models::ProbeResultRecord {
        node_id: "n1".to_string(),
        probe_id: "builtin_latency".to_string(),
        ok: true,
        latency_ms: Some(40.0),
        ..Default::default()
    };
    let custom_fail_rec = catcloud_core::models::ProbeResultRecord {
        node_id: "n1".to_string(),
        probe_id: "custom_latency_alt".to_string(),
        ok: false,
        latency_ms: None,
        ..Default::default()
    };
    let merged_multi_snap = ProbeSnapshot {
        node_id: "n1".to_string(),
        ok: true,
        latency_ms: Some(40.0),
        ..Default::default()
    };
    update_node_health_pool_after_isolated_probe(
        &state,
        "n1",
        &[builtin_ok_rec, custom_fail_rec],
        &multi_latency_ids,
        &merged_multi_snap,
    );
    assert!(
        state.snapshot_node_health_pool().get("n1").is_none(),
        "passing builtin_latency must not be overridden by a trailing failed custom latency probe"
    );
    assert!(state.snapshot_node_health_hints().get("n1").is_none());

    // 4. `extract_verified_throughput_mbps` & `summarize_isolated_probe_run` strictly require `rec.ok == true`.
    let failed_up_rec = catcloud_core::models::ProbeResultRecord {
        node_id: "n1".to_string(),
        probe_id: "builtin_upload".to_string(),
        ok: false,
        up_mbps: Some(0.15),
        ..Default::default()
    };
    let ok_down_rec = catcloud_core::models::ProbeResultRecord {
        node_id: "n1".to_string(),
        probe_id: "builtin_download".to_string(),
        ok: true,
        down_mbps: Some(85.0),
        ..Default::default()
    };
    assert_eq!(extract_verified_throughput_mbps(&failed_up_rec, true), None);
    assert_eq!(
        extract_verified_throughput_mbps(&ok_down_rec, false),
        Some(85.0)
    );

    let mut run_snaps = HashMap::new();
    run_snaps.insert(
        "n1".to_string(),
        ProbeSnapshot {
            node_id: "n1".to_string(),
            ok: true,
            latency_ms: Some(36.0),
            up_mbps: Some(0.15),
            down_mbps: Some(85.0),
            ..Default::default()
        },
    );
    let mut run_recs = HashMap::new();
    run_recs.insert("n1".to_string(), vec![failed_up_rec, ok_down_rec]);
    let summary = summarize_isolated_probe_run(1, 1, &run_snaps, &run_recs, &HashSet::new(), 0);
    assert_eq!(
        summary.bandwidth_ok_count, 0,
        "failed upload record (ok=false) must NEVER count toward bandwidth_ok_count"
    );

    drop(state);
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn stage23_bug2_default_group_refill_and_single_node_remap_guards() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_s23_bug2_groups_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), true).unwrap();
    let storage = Storage::open(&paths.db_path).unwrap();

    // 1. Existing empty default static group (no match_rules) is refilled on re-import
    //    instead of leaving the user stuck with an empty group.
    let empty_default = MultiGroup {
        id: "grp-empty-default".to_string(),
        name: "默认路线".to_string(),
        mode: MultiGroupMode::StickyBest,
        member_node_ids: vec![],
        active_node_id: None,
        ..MultiGroup::default()
    };
    storage.upsert_multi_group(&empty_default).unwrap();

    storage
        .upsert_subscription(&SubscriptionRecord {
            id: "sub-new".to_string(),
            name: "测试主力订阅".to_string(),
            kind: SubscriptionKind::Migrated,
            url_or_cmd: "local://test-new".to_string(),
            enabled: true,
            ..Default::default()
        })
        .unwrap();
    storage
        .upsert_subscription(&SubscriptionRecord {
            id: "sub-dis".to_string(),
            name: "禁用节点订阅".to_string(),
            kind: SubscriptionKind::Migrated,
            url_or_cmd: "local://test-dis".to_string(),
            enabled: true,
            ..Default::default()
        })
        .unwrap();

    let n1 = ProxyNode {
        id: "n-sg-1".to_string(),
        sub_id: "sub-new".to_string(),
        name: "SG 新加坡 01".to_string(),
        protocol: "trojan".to_string(),
        server: "sg.example.invalid".to_string(),
        port: 443,
        region_code: "SG".to_string(),
        multiplier: 1.0,
        enabled: true,
        ..Default::default()
    };
    let n_disabled = ProxyNode {
        id: "n-disabled".to_string(),
        sub_id: "sub-dis".to_string(),
        name: "Disabled Node".to_string(),
        protocol: "trojan".to_string(),
        server: "dis.example.invalid".to_string(),
        port: 443,
        enabled: false,
        ..Default::default()
    };
    storage.upsert_node(&n1).unwrap();
    storage.upsert_node(&n_disabled).unwrap();

    let mut cfg = AppConfig::default();
    cfg.active_group_id = Some("grp-empty-default".to_string());
    cfg.active_single_node_id = Some("deleted-old-node".to_string());
    let state = AppState::new(
        paths.clone(),
        cfg,
        storage,
        Arc::new(JobGuard::new().unwrap()),
    );

    assert!(ensure_default_group_if_empty(&state));
    let groups_after = state.storage.lock().unwrap().list_multi_groups().unwrap();
    assert_eq!(groups_after.len(), 1);
    assert_eq!(groups_after[0].id, "grp-empty-default");
    assert_eq!(groups_after[0].member_node_ids, vec!["n-sg-1".to_string()]);
    assert_eq!(groups_after[0].active_node_id.as_deref(), Some("n-sg-1"));

    // Second call is a no-op because a static group now has valid enabled members.
    assert!(!ensure_default_group_if_empty(&state));

    // 2. Dynamic group presence suppresses auto-fill even when static groups are empty.
    {
        let db = state.storage.lock().unwrap();
        let mut empty_again = groups_after[0].clone();
        empty_again.member_node_ids.clear();
        empty_again.active_node_id = None;
        db.upsert_multi_group(&empty_again).unwrap();
        db.upsert_multi_group(&MultiGroup {
            id: "grp-dynamic".to_string(),
            name: "动态筛选组".to_string(),
            dynamic_filter: Some(catcloud_core::models::DynamicFilterSpec::default()),
            ..MultiGroup::default()
        })
        .unwrap();
    }
    assert!(!ensure_default_group_if_empty(&state));

    // 3. Static empty group WITH custom match_rules must NOT be polluted; a separate
    //    unconstrained "默认路线" group is created instead.
    {
        let db = state.storage.lock().unwrap();
        db.delete_multi_group("grp-dynamic").unwrap();
        db.delete_multi_group("grp-empty-default").unwrap();
        db.upsert_multi_group(&MultiGroup {
            id: "grp-custom-rules".to_string(),
            name: "AI 专用组".to_string(),
            match_rules: vec!["DOMAIN-SUFFIX,openai.com".to_string()],
            member_node_ids: vec![],
            ..MultiGroup::default()
        })
        .unwrap();
    }
    assert!(ensure_default_group_if_empty(&state));
    let groups_with_custom = state.storage.lock().unwrap().list_multi_groups().unwrap();
    let custom_grp = groups_with_custom
        .iter()
        .find(|g| g.id == "grp-custom-rules")
        .unwrap();
    assert!(
        custom_grp.member_node_ids.is_empty(),
        "custom match_rules group must stay untouched"
    );
    assert!(
        groups_with_custom
            .iter()
            .any(|g| g.name == "默认路线" && g.member_node_ids == vec!["n-sg-1".to_string()])
    );

    // 4. `remap_active_single_node_id_if_needed` remaps to enabled node, and clears to `None`
    //    when only disabled nodes remain (never selecting disabled nodes).
    assert!(remap_active_single_node_id_if_needed(&state, &HashMap::new()).unwrap());
    assert_eq!(
        state.snapshot_config().active_single_node_id.as_deref(),
        Some("n-sg-1")
    );
    {
        let db = state.storage.lock().unwrap();
        assert!(db.delete_subscription("sub-new").unwrap());
    }
    assert!(remap_active_single_node_id_if_needed(&state, &HashMap::new()).unwrap());
    assert_eq!(state.snapshot_config().active_single_node_id, None);

    drop(state);
    let _ = std::fs::remove_dir_all(&tmp);
}
