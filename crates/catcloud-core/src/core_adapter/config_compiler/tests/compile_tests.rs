use super::{sample_node, sample_ports, sample_relay};
use super::super::*;
use crate::core_adapter::port_guard::AllocatedPorts;
use crate::models::{
    AppConfig, FallbackPolicy, MultiGroup, MultiGroupMode, MultiGroupState, ProxyMode, ProxyNode,
    RouteTargetMode,
};
use serde_yaml_ng::Value;
use std::collections::HashMap;

#[test]
fn compiles_all_four_multi_group_modes_with_active_first_and_reject_slot() {
    let cfg = AppConfig::default();
    let ports = sample_ports();
    let nodes = vec![
        sample_node("n1", "Node-JP-01", 8443, false),
        sample_node("n2", "Node-SG-02", 443, true),
        sample_node("n3", "Node-US-03", 9443, false),
    ];

    let g_sticky = MultiGroup {
        id: "g-sticky".to_string(),
        name: "AI-Sticky".to_string(),
        mode: MultiGroupMode::StickyBest,
        match_rules: vec!["@ai_domains".to_string()],
        member_node_ids: vec!["n1".into(), "n2".into(), "n3".into()],
        active_node_id: Some("n3".to_string()),
        fallback_policy: FallbackPolicy::StrictCircuitBreak,
        ..Default::default()
    };

    let g_cond = MultiGroup {
        id: "g-cond".to_string(),
        name: "Cond-Pool".to_string(),
        mode: MultiGroupMode::ConditionalPool,
        match_rules: vec!["DOMAIN-SUFFIX,example.com".to_string()],
        member_node_ids: Vec::new(),
        active_node_id: Some("n2".to_string()),
        fallback_policy: FallbackPolicy::DegradeBestWarn,
        independent_routing: true,
        ..Default::default()
    };

    let g_lb_ch = MultiGroup {
        id: "g-lb-ch".to_string(),
        name: "LB-Consistent".to_string(),
        mode: MultiGroupMode::LoadBalanceConsistentHash,
        member_node_ids: vec!["n1".into(), "n2".into()],
        ..Default::default()
    };

    let g_lb_rr = MultiGroup {
        id: "g-lb-rr".to_string(),
        name: "LB-RoundRobin".to_string(),
        mode: MultiGroupMode::LoadBalanceRoundRobin,
        member_node_ids: vec!["n1".into(), "n3".into()],
        ..Default::default()
    };

    let mut filtered = HashMap::new();
    filtered.insert("g-lb-ch".to_string(), vec!["n2".to_string()]);

    let groups = vec![g_sticky, g_cond, g_lb_ch, g_lb_rr];
    let input = CompileInput {
        config: &cfg,
        nodes: &nodes,
        groups: &groups,
        relays: &[],
        controller_secret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &filtered,
    };

    let compiled = compile_mihomo_config(&input).expect("compile must succeed");
    assert!(compiled.validation.ok);

    let pg = compiled.value["proxy-groups"].as_sequence().unwrap();
    assert_eq!(pg.len(), 4);

    // 1. StickyBest: active_node_id (n3 -> Node-US-03) moved to index 0 + REJECT slot kept
    assert_eq!(pg[0]["name"], "AI-Sticky");
    assert_eq!(pg[0]["type"], "select");
    let sticky_members: Vec<&str> = pg[0]["proxies"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(sticky_members[0], "Node-US-03");
    assert!(sticky_members.contains(&"REJECT"));
    assert_eq!(
        compiled.active_selections.get("AI-Sticky").map(String::as_str),
        Some("Node-US-03")
    );

    // 2. ConditionalPool: active_node_id (n2 -> Node-SG-02) moved to index 0
    assert_eq!(pg[1]["name"], "Cond-Pool");
    assert_eq!(pg[1]["type"], "select");
    assert_eq!(pg[1]["proxies"][0], "Node-SG-02");

    // 3. LoadBalanceConsistentHash: respects hard-gate filtered members (only n2)
    assert_eq!(pg[2]["name"], "LB-Consistent");
    assert_eq!(pg[2]["type"], "load-balance");
    assert_eq!(pg[2]["strategy"], "consistent-hashing");
    assert_eq!(pg[2]["proxies"].as_sequence().unwrap().len(), 1);
    assert_eq!(pg[2]["proxies"][0], "Node-SG-02");

    // 4. LoadBalanceRoundRobin
    assert_eq!(pg[3]["name"], "LB-RoundRobin");
    assert_eq!(pg[3]["type"], "load-balance");
    assert_eq!(pg[3]["strategy"], "round-robin");

    // AI rules expanded from @ai_domains
    let rules: Vec<&str> = compiled.value["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(rules.iter().any(|r| *r == "DOMAIN-SUFFIX,openai.com,AI-Sticky"));
    assert!(rules.iter().any(|r| *r == "DOMAIN-SUFFIX,windsurf.com,AI-Sticky"));
    assert!(rules.iter().any(|r| *r == "DOMAIN-SUFFIX,example.com,Cond-Pool"));
}

#[test]
fn load_balance_strict_circuit_break_handles_healthy_empty_and_circuit_open() {
    let cfg = AppConfig::default();
    let ports = sample_ports();
    let nodes = vec![
        sample_node("n1", "Node-JP-01", 443, true),
        sample_node("n2", "Node-SG-02", 443, true),
    ];

    // 1. Healthy load-balance group with StrictCircuitBreak must NOT include REJECT.
    let lb_healthy = MultiGroup {
        id: "g-lb-healthy".to_string(),
        name: "LB-Healthy".to_string(),
        mode: MultiGroupMode::LoadBalanceConsistentHash,
        member_node_ids: vec!["n1".into(), "n2".into()],
        fallback_policy: FallbackPolicy::StrictCircuitBreak,
        state: MultiGroupState::Healthy,
        ..Default::default()
    };

    // 2. Load-balance group with empty filtered members must emit ["REJECT"].
    let lb_empty = MultiGroup {
        id: "g-lb-empty".to_string(),
        name: "LB-Empty".to_string(),
        mode: MultiGroupMode::LoadBalanceRoundRobin,
        member_node_ids: vec!["n1".into(), "n2".into()],
        fallback_policy: FallbackPolicy::StrictCircuitBreak,
        state: MultiGroupState::Healthy,
        ..Default::default()
    };

    // 3. Load-balance group in CircuitOpen state must emit ["REJECT"] even if nodes exist.
    let lb_open = MultiGroup {
        id: "g-lb-open".to_string(),
        name: "LB-Open".to_string(),
        mode: MultiGroupMode::LoadBalanceConsistentHash,
        member_node_ids: vec!["n1".into(), "n2".into()],
        fallback_policy: FallbackPolicy::StrictCircuitBreak,
        state: MultiGroupState::CircuitOpen,
        ..Default::default()
    };

    let mut filtered = HashMap::new();
    filtered.insert("g-lb-empty".to_string(), Vec::new());

    let groups = vec![lb_healthy, lb_empty, lb_open];
    let input = CompileInput {
        config: &cfg,
        nodes: &nodes,
        groups: &groups,
        relays: &[],
        controller_secret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &filtered,
    };

    let compiled = compile_mihomo_config(&input).expect("compile must succeed");
    assert!(compiled.validation.ok, "issues: {:?}", compiled.validation.issues);

    let pg = compiled.value["proxy-groups"].as_sequence().unwrap();
    let healthy_members: Vec<&str> = pg[0]["proxies"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(healthy_members, vec!["Node-JP-01", "Node-SG-02"]);
    assert!(!healthy_members.contains(&"REJECT"));

    let empty_members: Vec<&str> = pg[1]["proxies"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(empty_members, vec!["REJECT"]);

    let open_members: Vec<&str> = pg[2]["proxies"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(open_members, vec!["REJECT"]);
}

#[test]
fn compiles_geo_auto_update_false_and_honors_active_group_id_for_match() {
    let mut cfg = AppConfig::default();
    cfg.active_group_id = Some("grp-second".to_string());
    let node = sample_node("n1", "Node-JP", 443, true);
    let mut g1 = MultiGroup::default();
    g1.id = "grp-first".to_string();
    g1.name = "First-Group".to_string();
    g1.member_node_ids = vec![node.id.clone()];
    let mut g2 = MultiGroup::default();
    g2.id = "grp-second".to_string();
    g2.name = "Second-Group".to_string();
    g2.member_node_ids = vec![node.id.clone()];

    let ports = AllocatedPorts {
        bind_host: "127.0.0.1".to_string(),
        mixed_port: 27890,
        controller_port: 29090,
        dns_port: 21053,
        shifted: Vec::new(),
    };
    let empty = HashMap::new();
    let compiled = compile_mihomo_config(&CompileInput {
        config: &cfg,
        nodes: &[node],
        groups: &[g1, g2],
        relays: &[],
        controller_secret: "secret",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    })
    .expect("compile ok");

    assert_eq!(compiled.value["geo-auto-update"], Value::Bool(false));
    let rules = compiled.value["rules"].as_sequence().expect("rules seq");
    let last = rules.last().and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(last, "MATCH,Second-Group");
}

#[test]
fn compiles_single_node_route_mode_skips_group_rules_and_targets_selected_node() {
    let mut cfg = AppConfig::default();
    cfg.route_mode = RouteTargetMode::Single;
    cfg.active_single_node_id = Some("n2".to_string());
    cfg.active_group_id = Some("g-ai".to_string());
    cfg.preaccel.campus_direct_domains = vec![
        "portal.campus.test".to_string(),
        "DOMAIN-SUFFIX,".to_string(),
        "DOMAIN,auth.campus.test,DIRECT".to_string(),
    ];

    let nodes = vec![
        sample_node("n1", "Node-JP-01", 8443, false),
        sample_node("n2", "Node-SG-02", 443, true),
        sample_node("n3", "Node-US-03", 9443, false),
    ];
    let group = MultiGroup {
        id: "g-ai".to_string(),
        name: "AI-Sticky".to_string(),
        mode: MultiGroupMode::StickyBest,
        match_rules: vec![
            "@ai_domains".to_string(),
            "DOMAIN-SUFFIX,example.com".to_string(),
        ],
        member_node_ids: vec!["n1".into(), "n3".into()],
        active_node_id: Some("n1".to_string()),
        ..Default::default()
    };
    let ports = sample_ports();
    let empty = HashMap::new();

    let compiled = compile_mihomo_config(&CompileInput {
        config: &cfg,
        nodes: &nodes,
        groups: &[group],
        relays: &[],
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    })
    .expect("single-node compile must succeed");

    assert!(
        compiled.validation.ok,
        "issues: {:?}",
        compiled.validation.issues
    );

    let pg = compiled.value["proxy-groups"].as_sequence().unwrap();
    let single_group = pg
        .iter()
        .find(|g| g["name"] == SINGLE_NODE_GROUP_NAME)
        .expect("SINGLE_NODE_GROUP_NAME must be compiled");
    assert_eq!(single_group["type"], "select");

    let single_members: Vec<&str> = single_group["proxies"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(single_members, vec!["Node-SG-02", "Node-JP-01", "Node-US-03"]);
    assert_eq!(
        compiled
            .active_selections
            .get(SINGLE_NODE_GROUP_NAME)
            .map(String::as_str),
        Some("Node-SG-02")
    );

    let rules: Vec<&str> = compiled.value["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let expected_match = format!("MATCH,{SINGLE_NODE_GROUP_NAME}");
    assert_eq!(rules.last().copied(), Some(expected_match.as_str()));
    assert!(!rules.iter().any(|r| r.contains(",AI-Sticky")));
    assert!(rules.contains(&"DOMAIN-SUFFIX,portal.campus.test,DIRECT"));
    assert!(rules.contains(&"DOMAIN,auth.campus.test,DIRECT"));
    assert!(!rules.contains(&"DOMAIN-SUFFIX,"));
}

#[test]
fn compiles_with_runtime_dir_detects_geodata_and_gates_geosite_geoip() {
    let dir = std::env::temp_dir().join(format!(
        "catcloud-compiler-geo-test-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let cfg = AppConfig::default();
    let ports = sample_ports();
    let nodes = vec![sample_node("n1", "Node-JP-01", 443, true)];
    let empty = HashMap::new();
    let input = CompileInput {
        config: &cfg,
        nodes: &nodes,
        groups: &[],
        relays: &[],
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    };

    // 1. Empty runtime_dir -> no GEOSITE/GEOIP rules, fallback domestic domains emitted
    let without_geo = compile_mihomo_config_with_runtime_dir(&input, Some(&dir)).unwrap();
    assert!(without_geo.validation.ok);
    assert_eq!(
        without_geo.value["dns"]["fallback-filter"]["geoip"],
        Value::Bool(false)
    );
    assert!(without_geo.value["dns"]["fallback-filter"].get("geosite").is_none());
    assert!(
        without_geo.value["dns"]["nameserver-policy"]
            .get("geosite:cn,private")
            .is_none()
    );
    let rules_no_geo: Vec<&str> = without_geo.value["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(rules_no_geo.contains(&"IP-CIDR,127.0.0.0/8,DIRECT,no-resolve"));
    assert!(rules_no_geo.contains(&"IP-CIDR6,fe80::/10,DIRECT,no-resolve"));
    assert!(rules_no_geo.contains(&"AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"));
    assert!(rules_no_geo.contains(&"DOMAIN-SUFFIX,cn,DIRECT"));
    assert!(rules_no_geo.contains(&"DOMAIN-SUFFIX,qq.com,DIRECT"));
    assert!(rules_no_geo.contains(&"DOMAIN-SUFFIX,edu.cn,DIRECT"));
    assert!(!rules_no_geo.contains(&"GEOSITE,private,DIRECT"));
    assert!(!rules_no_geo.contains(&"GEOSITE,cn,DIRECT"));
    assert!(!rules_no_geo.contains(&"GEOIP,CN,DIRECT,no-resolve"));

    // 2. With geosite.dat + Country.mmdb -> enables GEOSITE/GEOIP rules & DNS policies
    std::fs::write(dir.join("geosite.dat"), b"stub").unwrap();
    std::fs::write(dir.join("Country.mmdb"), b"stub").unwrap();
    let with_geo = compile_mihomo_config_with_runtime_dir(&input, Some(&dir)).unwrap();
    assert!(with_geo.validation.ok);
    assert_eq!(
        with_geo.value["dns"]["fallback-filter"]["geoip"],
        Value::Bool(true)
    );
    // `fallback-filter.geosite` is intentionally omitted because Mihomo deprecates it
    // in favor of `nameserver-policy`.
    assert!(with_geo.value["dns"]["fallback-filter"].get("geosite").is_none());
    assert!(
        with_geo.value["dns"]["nameserver-policy"]
            .get("geosite:cn,private")
            .is_some()
    );
    let fake_filters: Vec<&str> = with_geo.value["dns"]["fake-ip-filter"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(fake_filters.contains(&"geosite:cn"));
    assert!(fake_filters.contains(&"geosite:private"));

    let rules_with_geo: Vec<&str> = with_geo.value["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(rules_with_geo.contains(&"GEOSITE,private,DIRECT"));
    assert!(rules_with_geo.contains(&"GEOSITE,cn,DIRECT"));
    assert!(rules_with_geo.contains(&"GEOIP,CN,DIRECT,no-resolve"));
    assert!(!rules_with_geo.contains(&"DOMAIN-SUFFIX,qq.com,DIRECT"));

    // 3. When geodata_mode == true, requires geoip.dat rather than Country.mmdb
    let mut cfg_dat = AppConfig::default();
    cfg_dat.geodata.geodata_mode = true;
    let input_dat = CompileInput {
        config: &cfg_dat,
        ..input
    };
    let without_geoip_dat =
        compile_mihomo_config_with_runtime_dir(&input_dat, Some(&dir)).unwrap();
    assert_eq!(
        without_geoip_dat.value["dns"]["fallback-filter"]["geoip"],
        Value::Bool(false)
    );
    std::fs::write(dir.join("geoip.dat"), b"stub").unwrap();
    let with_geoip_dat =
        compile_mihomo_config_with_runtime_dir(&input_dat, Some(&dir)).unwrap();
    assert_eq!(
        with_geoip_dat.value["dns"]["fallback-filter"]["geoip"],
        Value::Bool(true)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn dedup_proxy_names_strips_dangling_dialer_proxy_and_promotes_active_relay_with_autofailover() {
    let mut cfg = AppConfig::default();
    cfg.preaccel.enabled = true;
    cfg.preaccel.auto_failover = true;
    cfg.preaccel.active_relay_id = Some("r-second".to_string());
    cfg.preaccel.skip_443_native = true;

    let relays = vec![
        sample_relay("r-first", "Relay-First", "203.0.113.11", 10),
        sample_relay("r-second", "Relay-Second", "203.0.113.22", 20),
    ];

    // Two providers with identical node display names + domain server + dangling dialer-proxy
    let mut n1 = sample_node("sub-a-jp", "Tokyo-01", 443, true);
    n1.server = "jp-a.provider.test".to_string();
    n1.raw_config = serde_json::json!({
        "name": "Tokyo-01",
        "type": "trojan",
        "server": "jp-a.provider.test",
        "port": 443,
        "password": "p1",
        "dialer-proxy": "NonExistentUpstreamGroup"
    });

    let mut n2 = sample_node("sub-b-jp", "Tokyo-01", 443, true);
    n2.server = "198.51.100.88".to_string();
    n2.raw_config = serde_json::json!({
        "name": "Tokyo-01",
        "type": "trojan",
        "server": "198.51.100.88",
        "port": 443,
        "password": "p2",
        "dialer-proxy": "Relay-First"
    });

    let mut n3 = sample_node("sub-c-self", "SelfLoop-01", 443, true);
    n3.server = "198.51.100.99".to_string();
    n3.raw_config = serde_json::json!({
        "name": "SelfLoop-01",
        "type": "trojan",
        "server": "198.51.100.99",
        "port": 443,
        "password": "p3",
        "dialer-proxy": "SelfLoop-01"
    });

    let nodes = vec![n1, n2, n3];
    let ports = sample_ports();
    let empty = HashMap::new();
    let compiled = compile_mihomo_config(&CompileInput {
        config: &cfg,
        nodes: &nodes,
        groups: &[],
        relays: &relays,
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    })
    .expect("compile ok");
    assert!(compiled.validation.ok, "issues: {:?}", compiled.validation.issues);

    // Unique proxy names tracked in node_id_to_proxy_name
    assert_eq!(
        compiled.node_id_to_proxy_name.get("sub-a-jp").map(String::as_str),
        Some("Tokyo-01")
    );
    assert_eq!(
        compiled.node_id_to_proxy_name.get("sub-b-jp").map(String::as_str),
        Some("Tokyo-01 (2)")
    );

    // Dangling and self-referencing dialer-proxy stripped; valid relay target preserved on n2
    let proxies = compiled.value["proxies"].as_sequence().unwrap();
    let p1 = proxies.iter().find(|p| p["name"] == "Tokyo-01").unwrap();
    assert!(p1.get("dialer-proxy").is_none());
    let p2 = proxies.iter().find(|p| p["name"] == "Tokyo-01 (2)").unwrap();
    assert_eq!(p2["dialer-proxy"], "Relay-First");
    let p3 = proxies.iter().find(|p| p["name"] == "SelfLoop-01").unwrap();
    assert!(p3.get("dialer-proxy").is_none());

    // Domain node server enters fake-ip-filter, while pure-IP business node is NOT forced DIRECT
    let fake_filters: Vec<&str> = compiled.value["dns"]["fake-ip-filter"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(fake_filters.contains(&"jp-a.provider.test"));
    assert!(!fake_filters.contains(&"198.51.100.88"));

    let rules: Vec<&str> = compiled.value["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(!rules.contains(&"IP-CIDR,198.51.100.88/32,DIRECT,no-resolve"));
    assert!(rules.contains(&"IP-CIDR,203.0.113.11/32,DIRECT,no-resolve"));
    assert!(rules.contains(&"IP-CIDR,203.0.113.22/32,DIRECT,no-resolve"));

    // active_relay_id ("r-second" -> Relay-Second) is promoted to index 0 of fallback group
    // even when auto_failover == true
    let fallback_group = compiled.value["proxy-groups"]
        .as_sequence()
        .unwrap()
        .iter()
        .find(|g| g["name"] == PREACCEL_FALLBACK_GROUP_NAME)
        .unwrap();
    let fb_members: Vec<&str> = fallback_group["proxies"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(fb_members, vec!["Relay-Second", "Relay-First", "DIRECT"]);
}

#[test]
fn unselected_group_without_independent_routing_never_hijacks_traffic_and_active_group_wins_priority() {
    let mut cfg = AppConfig::default();
    cfg.active_group_id = Some("grp-test".to_string());

    let nodes = vec![
        sample_node("n-jp", "Node-JP-Good", 443, true),
        sample_node("n-bad", "Node-Bad", 443, true),
    ];

    // Listed FIRST in input.groups, unselected, independent_routing=false -> MUST NOT hijack!
    let g_ai_inactive = MultiGroup {
        id: "grp-ai-unselected".to_string(),
        name: "AI-Dedicated-Unselected".to_string(),
        mode: MultiGroupMode::StickyBest,
        match_rules: vec!["@ai_domains".to_string(), "DOMAIN-SUFFIX,google.com".to_string()],
        member_node_ids: vec!["n-bad".to_string()],
        active_node_id: Some("n-bad".to_string()),
        independent_routing: false,
        ..Default::default()
    };

    // Listed SECOND, explicitly opted into independent_routing=true -> allowed to emit rules,
    // but MUST rank AFTER the active home group's own match_rules.
    let g_split = MultiGroup {
        id: "grp-split".to_string(),
        name: "Split-Express".to_string(),
        mode: MultiGroupMode::StickyBest,
        match_rules: vec![
            "DOMAIN-SUFFIX,openai.com".to_string(),
            "DOMAIN-SUFFIX,claude.ai".to_string(),
        ],
        member_node_ids: vec!["n-jp".to_string()],
        active_node_id: Some("n-jp".to_string()),
        independent_routing: true,
        ..Default::default()
    };

    // Listed THIRD, selected as active home group -> its match_rules MUST come FIRST + MATCH target.
    let g_active = MultiGroup {
        id: "grp-test".to_string(),
        name: "Active-Test-Group".to_string(),
        mode: MultiGroupMode::StickyBest,
        match_rules: vec!["DOMAIN-SUFFIX,openai.com".to_string()],
        member_node_ids: vec!["n-jp".to_string()],
        active_node_id: Some("n-jp".to_string()),
        independent_routing: false,
        ..Default::default()
    };

    let ports = sample_ports();
    let empty = HashMap::new();
    let groups = vec![g_ai_inactive, g_split, g_active];
    let compiled = compile_mihomo_config(&CompileInput {
        config: &cfg,
        nodes: &nodes,
        groups: &groups,
        relays: &[],
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    })
    .expect("compile ok");
    assert!(compiled.validation.ok, "issues: {:?}", compiled.validation.issues);

    // All 3 proxy-groups are still compiled so instant switching remains available.
    let pg = compiled.value["proxy-groups"].as_sequence().unwrap();
    assert_eq!(pg.len(), 3);
    assert!(pg.iter().any(|g| g["name"] == "AI-Dedicated-Unselected"));

    let rules: Vec<&str> = compiled.value["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();

    // Unselected group without independent_routing must NOT emit ANY rules.
    assert!(
        !rules.iter().any(|r| r.contains(",AI-Dedicated-Unselected")),
        "unselected non-independent group hijacked rules: {rules:?}"
    );

    // Active group's rule MUST appear before independent split group's overlapping rule.
    let idx_active_openai = rules
        .iter()
        .position(|r| *r == "DOMAIN-SUFFIX,openai.com,Active-Test-Group")
        .expect("active group rule must be emitted");
    let idx_split_openai = rules
        .iter()
        .position(|r| *r == "DOMAIN-SUFFIX,openai.com,Split-Express")
        .expect("independent split group rule must be emitted");
    let idx_split_claude = rules
        .iter()
        .position(|r| *r == "DOMAIN-SUFFIX,claude.ai,Split-Express")
        .expect("independent split group non-overlapping rule must be emitted");
    assert!(idx_active_openai < idx_split_openai);
    assert!(idx_active_openai < idx_split_claude);

    // Final MATCH must point to active home group.
    assert_eq!(rules.last().copied(), Some("MATCH,Active-Test-Group"));
}

#[test]
fn discards_ghost_active_node_id_not_in_members_instead_of_reinjecting() {
    let cfg = AppConfig::default();
    let ports = sample_ports();
    let nodes = vec![
        sample_node("n-jp", "Node-JP-01", 443, true),
        sample_node("n-sg", "Node-SG-02", 443, true),
        sample_node("n-ar", "Node-AR-Ghost", 443, true),
    ];

    // 1. Removed ghost node (`n-ar`) still stored in `active_node_id`, absent from `member_node_ids`.
    let g_ghost_member = MultiGroup {
        id: "g-ghost".to_string(),
        name: "No-Ghost-Group".to_string(),
        mode: MultiGroupMode::StickyBest,
        member_node_ids: vec!["n-jp".into(), "n-sg".into()],
        active_node_id: Some("n-ar".to_string()),
        ..Default::default()
    };

    // 2. Active node (`n-jp`) excluded by hard-gate `group_filtered_members` -> must fall back to `n-sg`.
    let g_filtered_ghost = MultiGroup {
        id: "g-filtered".to_string(),
        name: "Filtered-Group".to_string(),
        mode: MultiGroupMode::StickyBest,
        member_node_ids: vec!["n-jp".into(), "n-sg".into()],
        active_node_id: Some("n-jp".to_string()),
        ..Default::default()
    };

    // 3. CircuitOpen + StrictCircuitBreak must still select REJECT cleanly.
    let g_circuit_open = MultiGroup {
        id: "g-circuit".to_string(),
        name: "Circuit-Group".to_string(),
        mode: MultiGroupMode::StickyBest,
        member_node_ids: vec!["n-jp".into()],
        active_node_id: Some("n-ar".to_string()),
        fallback_policy: FallbackPolicy::StrictCircuitBreak,
        state: MultiGroupState::CircuitOpen,
        ..Default::default()
    };

    let mut filtered = HashMap::new();
    filtered.insert("g-filtered".to_string(), vec!["n-sg".to_string()]);

    let groups = vec![g_ghost_member, g_filtered_ghost, g_circuit_open];
    let compiled = compile_mihomo_config(&CompileInput {
        config: &cfg,
        nodes: &nodes,
        groups: &groups,
        relays: &[],
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &filtered,
    })
    .expect("compile ok");
    assert!(compiled.validation.ok, "issues: {:?}", compiled.validation.issues);

    let pg = compiled.value["proxy-groups"].as_sequence().unwrap();

    let ghost_members: Vec<&str> = pg[0]["proxies"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(ghost_members, vec!["Node-JP-01", "Node-SG-02"]);
    assert!(!ghost_members.contains(&"Node-AR-Ghost"));
    assert_eq!(
        compiled.active_selections.get("No-Ghost-Group").map(String::as_str),
        Some("Node-JP-01")
    );

    let filtered_members: Vec<&str> = pg[1]["proxies"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(filtered_members, vec!["Node-SG-02"]);
    assert_eq!(
        compiled.active_selections.get("Filtered-Group").map(String::as_str),
        Some("Node-SG-02")
    );

    let circuit_members: Vec<&str> = pg[2]["proxies"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(circuit_members[0], "REJECT");
    assert!(!circuit_members.contains(&"Node-AR-Ghost"));
    assert_eq!(
        compiled.active_selections.get("Circuit-Group").map(String::as_str),
        Some("REJECT")
    );
}

#[test]
fn prunes_inactive_nodes_when_over_32_and_honors_compile_all_nodes_and_memory_tunings() {
    let mut nodes: Vec<ProxyNode> = Vec::with_capacity(40);
    for i in 0..40 {
        let id = format!("n-{i:02}");
        let name = format!("Node-{i:02}");
        let host = format!("node-{i:02}.provider.test");
        let mut n = sample_node(&id, &name, 443, true);
        n.server = host.clone();
        n.raw_config = serde_json::json!({
            "name": name,
            "type": "trojan",
            "server": host,
            "port": 443,
            "password": "demo-password",
            "udp": true
        });
        nodes.push(n);
    }

    let g_active = MultiGroup {
        id: "g-tw".to_string(),
        name: "TW-Active".to_string(),
        mode: MultiGroupMode::StickyBest,
        member_node_ids: vec!["n-00".into(), "n-01".into(), "n-02".into(), "n-03".into()],
        active_node_id: Some("n-01".to_string()),
        ..Default::default()
    };
    let g_idle = MultiGroup {
        id: "g-idle".to_string(),
        name: "Idle-Group".to_string(),
        mode: MultiGroupMode::StickyBest,
        member_node_ids: vec!["n-10".into(), "n-11".into(), "n-12".into()],
        independent_routing: false,
        ..Default::default()
    };
    let g_independent = MultiGroup {
        id: "g-ai".to_string(),
        name: "AI-Split".to_string(),
        mode: MultiGroupMode::StickyBest,
        match_rules: vec!["DOMAIN-SUFFIX,openai.com".to_string()],
        member_node_ids: vec!["n-04".into(), "n-05".into()],
        fallback_pool_id: Some("g-backup".to_string()),
        independent_routing: true,
        ..Default::default()
    };
    let g_backup = MultiGroup {
        id: "g-backup".to_string(),
        name: "AI-Backup".to_string(),
        mode: MultiGroupMode::StickyBest,
        member_node_ids: vec!["n-06".into()],
        independent_routing: false,
        ..Default::default()
    };

    let ports = sample_ports();
    let empty = HashMap::new();

    // 1. Pure active group (4 members out of 40 nodes) -> compiles strictly 4 proxies.
    let mut cfg_simple = AppConfig::default();
    cfg_simple.active_group_id = Some("g-tw".to_string());
    let simple_groups = vec![g_active.clone(), g_idle.clone()];
    let compiled_4 = compile_mihomo_config(&CompileInput {
        config: &cfg_simple,
        nodes: &nodes,
        groups: &simple_groups,
        relays: &[],
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    })
    .expect("pruned 4-node compile must succeed");
    assert!(compiled_4.validation.ok);
    assert_eq!(compiled_4.stats.total_proxies, 4);
    assert_eq!(compiled_4.value["proxies"].as_sequence().unwrap().len(), 4);

    // Unconditional memory tunings: geodata-loader=memconservative even when geodata_mode=false,
    // keep-alive-idle=45, keep-alive-interval=15; when GeoIP is absent while domestic_direct_enabled=true,
    // QUIC sniffer stays enabled so domestic IM UDP/443 can match DOMAIN-SUFFIX DIRECT before REJECT.
    assert_eq!(compiled_4.value["geodata-mode"], Value::Bool(false));
    assert_eq!(compiled_4.value["geodata-loader"], "memconservative");
    assert_eq!(compiled_4.value["keep-alive-idle"], 45);
    assert_eq!(compiled_4.value["keep-alive-interval"], 15);
    assert!(compiled_4.value["sniffer"]["sniff"].get("QUIC").is_some());
    assert!(compiled_4.value["sniffer"]["sniff"].get("TLS").is_some());

    // fake-ip-filter only includes domains of compiled active nodes, not pruned nodes.
    let fake_filters: Vec<&str> = compiled_4.value["dns"]["fake-ip-filter"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(fake_filters.contains(&"node-00.provider.test"));
    assert!(fake_filters.contains(&"node-03.provider.test"));
    assert!(!fake_filters.contains(&"node-10.provider.test"));
    assert!(!fake_filters.contains(&"node-39.provider.test"));

    // 2. Active group + independent_routing group + transitive fallback_pool_id group -> 7 nodes.
    let rich_groups = vec![g_active.clone(), g_idle.clone(), g_independent, g_backup];
    let compiled_7 = compile_mihomo_config(&CompileInput {
        config: &cfg_simple,
        nodes: &nodes,
        groups: &rich_groups,
        relays: &[],
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    })
    .expect("pruned 7-node compile must succeed");
    assert!(compiled_7.validation.ok);
    assert_eq!(compiled_7.stats.total_proxies, 7);
    let pg_names: Vec<&str> = compiled_7.value["proxy-groups"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(|g| g["name"].as_str())
        .collect();
    assert!(pg_names.contains(&"TW-Active"));
    assert!(pg_names.contains(&"AI-Split"));
    assert!(pg_names.contains(&"AI-Backup"));
    assert!(!pg_names.contains(&"Idle-Group"));

    // 3. compile_all_nodes == true compiles all 40 nodes (and block_quic_udp_443 == false keeps QUIC sniffer).
    let mut cfg_all = cfg_simple.clone();
    cfg_all.core_runtime.compile_all_nodes = true;
    cfg_all.rules_override.block_quic_udp_443 = false;
    let compiled_all = compile_mihomo_config(&CompileInput {
        config: &cfg_all,
        nodes: &nodes,
        groups: &simple_groups,
        relays: &[],
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    })
    .expect("compile_all_nodes=true must succeed");
    assert_eq!(compiled_all.stats.total_proxies, 40);
    assert!(compiled_all.value["sniffer"]["sniff"].get("QUIC").is_some());

    // 4. ProxyMode::Global compiles all 40 nodes even when compile_all_nodes == false.
    let mut cfg_global = cfg_simple.clone();
    cfg_global.proxy_mode = ProxyMode::Global;
    let compiled_global = compile_mihomo_config(&CompileInput {
        config: &cfg_global,
        nodes: &nodes,
        groups: &simple_groups,
        relays: &[],
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    })
    .expect("global mode compile must succeed");
    assert_eq!(compiled_global.stats.total_proxies, 40);

    // 5. Single route mode prunes down to only the selected single node.
    let mut cfg_single = cfg_simple.clone();
    cfg_single.route_mode = RouteTargetMode::Single;
    cfg_single.active_single_node_id = Some("n-15".to_string());
    let compiled_single = compile_mihomo_config(&CompileInput {
        config: &cfg_single,
        nodes: &nodes,
        groups: &simple_groups,
        relays: &[],
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    })
    .expect("pruned single mode compile must succeed");
    assert!(compiled_single.validation.ok);
    assert_eq!(compiled_single.stats.total_proxies, 1);
    assert_eq!(
        compiled_single.value["proxies"][0]["name"].as_str(),
        Some("Node-15")
    );

    // 6. Empty active reference set falls back safely to compiling all 40 enabled nodes.
    let compiled_fallback = compile_mihomo_config(&CompileInput {
        config: &cfg_simple,
        nodes: &nodes,
        groups: &[],
        relays: &[],
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    })
    .expect("empty ref fallback compile must succeed");
    assert_eq!(compiled_fallback.stats.total_proxies, 40);
}

#[test]
fn prunes_over_32_nodes_retains_global_rule_referenced_groups_in_single_and_group_modes() {
    let mut nodes: Vec<ProxyNode> = Vec::with_capacity(40);
    for i in 0..40 {
        let id = format!("n-{i:02}");
        let name = format!("Node-{i:02}");
        let host = format!("node-{i:02}.provider.test");
        let mut n = sample_node(&id, &name, 443, true);
        n.server = host.clone();
        let mut raw = serde_json::json!({
            "name": name,
            "type": "trojan",
            "server": host,
            "port": 443,
            "password": "demo-password",
            "udp": true
        });
        // Chain n-04 onto n-20 via dialer-proxy to verify transitive node dependencies stay intact.
        if i == 4 {
            raw["dialer-proxy"] = serde_json::Value::String("Node-20".to_string());
        }
        n.raw_config = raw;
        nodes.push(n);
    }

    let g_main_a = MultiGroup {
        id: "g-a".to_string(),
        name: "Main-A".to_string(),
        mode: MultiGroupMode::StickyBest,
        member_node_ids: vec!["n-00".into(), "n-01".into(), "n-02".into(), "n-03".into()],
        active_node_id: Some("n-00".to_string()),
        independent_routing: false,
        ..Default::default()
    };
    let g_ai_b = MultiGroup {
        id: "g-b".to_string(),
        name: "AI-Target-B".to_string(),
        mode: MultiGroupMode::StickyBest,
        member_node_ids: vec!["n-04".into(), "n-05".into()],
        fallback_pool_id: Some("g-b-fb".to_string()),
        independent_routing: false,
        ..Default::default()
    };
    let g_ai_b_fb = MultiGroup {
        id: "g-b-fb".to_string(),
        name: "AI-Backup-B".to_string(),
        mode: MultiGroupMode::StickyBest,
        member_node_ids: vec!["n-06".into()],
        independent_routing: false,
        ..Default::default()
    };
    let g_extra_c = MultiGroup {
        id: "g-c".to_string(),
        name: "Extra-Target-C".to_string(),
        mode: MultiGroupMode::StickyBest,
        member_node_ids: vec!["n-10".into(), "n-11".into()],
        independent_routing: false,
        ..Default::default()
    };
    let g_idle = MultiGroup {
        id: "g-idle".to_string(),
        name: "Unused-Idle".to_string(),
        mode: MultiGroupMode::StickyBest,
        member_node_ids: vec!["n-30".into(), "n-31".into()],
        independent_routing: false,
        ..Default::default()
    };

    let groups = vec![g_main_a, g_ai_b, g_ai_b_fb, g_extra_c, g_idle];
    let ports = sample_ports();
    let empty = HashMap::new();

    // 1. >32 nodes + !compile_all_nodes + Single mode + global_prepend_rules targeting AI-Target-B:
    //    must retain AI-Target-B, its fallback AI-Backup-B, their members, chained dialer Node-20,
    //    and selected single node Node-15, while pruning unrelated groups and passing validation.
    let mut cfg_single = AppConfig::default();
    cfg_single.proxy_mode = ProxyMode::Rule;
    cfg_single.core_runtime.compile_all_nodes = false;
    cfg_single.route_mode = RouteTargetMode::Single;
    cfg_single.active_single_node_id = Some("n-15".to_string());
    cfg_single.rules_override.global_prepend_rules = vec![
        "# user AI preset".to_string(),
        "DOMAIN,node-20.provider.test,DIRECT".to_string(),
        "DOMAIN-SUFFIX,openai.com,AI-Target-B".to_string(),
        "IP-CIDR,198.51.100.0/24,AI-Target-B,no-resolve".to_string(),
    ];

    let compiled_single = compile_mihomo_config(&CompileInput {
        config: &cfg_single,
        nodes: &nodes,
        groups: &groups,
        relays: &[],
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    })
    .expect("single mode with global_prepend_rules group ref must compile");
    assert!(
        compiled_single.validation.ok,
        "single mode validation failed: {:?}",
        compiled_single.validation.issues
    );

    let single_pg_names: Vec<&str> = compiled_single.value["proxy-groups"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(|g| g["name"].as_str())
        .collect();
    assert!(single_pg_names.contains(&SINGLE_NODE_GROUP_NAME));
    assert!(single_pg_names.contains(&"AI-Target-B"));
    assert!(single_pg_names.contains(&"AI-Backup-B"));
    assert!(!single_pg_names.contains(&"Main-A"));
    assert!(!single_pg_names.contains(&"Extra-Target-C"));
    assert!(!single_pg_names.contains(&"Unused-Idle"));

    let single_proxy_names: Vec<&str> = compiled_single.value["proxies"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(|p| p["name"].as_str())
        .collect();
    assert_eq!(single_proxy_names.len(), 5);
    for expected in ["Node-04", "Node-05", "Node-06", "Node-15", "Node-20"] {
        assert!(
            single_proxy_names.contains(&expected),
            "missing expected proxy `{expected}` in {single_proxy_names:?}"
        );
    }
    assert!(!single_proxy_names.contains(&"Node-00"));
    assert!(!single_proxy_names.contains(&"Node-30"));

    // 2. >32 nodes + !compile_all_nodes + Group mode switched to Main-A + global_append_rules
    //    targeting inactive AI-Target-B + extra_prepend_rules targeting inactive Extra-Target-C:
    //    must retain Main-A, AI-Target-B, AI-Backup-B, Extra-Target-C and all their members.
    let mut cfg_group = AppConfig::default();
    cfg_group.proxy_mode = ProxyMode::Rule;
    cfg_group.core_runtime.compile_all_nodes = false;
    cfg_group.route_mode = RouteTargetMode::Group;
    cfg_group.active_group_id = Some("g-a".to_string());
    cfg_group.rules_override.global_prepend_rules =
        vec!["DOMAIN,node-20.provider.test,DIRECT".to_string()];
    cfg_group.rules_override.global_append_rules =
        vec!["DOMAIN-SUFFIX,claude.ai,AI-Target-B".to_string()];
    let extra_rules = vec!["IP-CIDR,203.0.113.0/24,Extra-Target-C,no-resolve".to_string()];

    let compiled_group = compile_mihomo_config(&CompileInput {
        config: &cfg_group,
        nodes: &nodes,
        groups: &groups,
        relays: &[],
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &extra_rules,
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    })
    .expect("group mode with global_append_rules & extra_prepend_rules must compile");
    assert!(
        compiled_group.validation.ok,
        "group mode validation failed: {:?}",
        compiled_group.validation.issues
    );

    let group_pg_names: Vec<&str> = compiled_group.value["proxy-groups"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(|g| g["name"].as_str())
        .collect();
    assert!(group_pg_names.contains(&"Main-A"));
    assert!(group_pg_names.contains(&"AI-Target-B"));
    assert!(group_pg_names.contains(&"AI-Backup-B"));
    assert!(group_pg_names.contains(&"Extra-Target-C"));
    assert!(!group_pg_names.contains(&"Unused-Idle"));

    let group_proxy_names: Vec<&str> = compiled_group.value["proxies"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(|p| p["name"].as_str())
        .collect();
    assert_eq!(group_proxy_names.len(), 10);
    for expected in [
        "Node-00", "Node-01", "Node-02", "Node-03", "Node-04", "Node-05", "Node-06", "Node-10",
        "Node-11", "Node-20",
    ] {
        assert!(
            group_proxy_names.contains(&expected),
            "missing expected proxy `{expected}` in {group_proxy_names:?}"
        );
    }
    assert!(!group_proxy_names.contains(&"Node-30"));
}

#[test]
fn no_group_fallback_prefers_smart_default_node_over_andorra_and_info_banners() {
    let cfg = AppConfig::default();
    let ports = sample_ports();
    let empty = HashMap::new();

    let mut info_node = sample_node("n-info", "剩余流量：120GB", 443, true);
    info_node.region_code = "HK".to_string();

    let mut andorra = sample_node("n-ad", "AD 安道尔 01 3x", 443, true);
    andorra.region_code = "AD".to_string();
    andorra.multiplier = 3.0;

    let mut tw_node = sample_node("n-tw", "TW 台湾 01 1x", 443, true);
    tw_node.region_code = "TW".to_string();
    tw_node.multiplier = 1.0;

    let nodes = vec![info_node, andorra, tw_node];
    let compiled = compile_mihomo_config(&CompileInput {
        config: &cfg,
        nodes: &nodes,
        groups: &[],
        relays: &[],
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    })
    .expect("compile no-group smart fallback");

    assert_eq!(
        compiled
            .active_selections
            .get(DEFAULT_FALLBACK_GROUP_NAME)
            .map(String::as_str),
        Some("TW 台湾 01 1x")
    );
    let default_group = compiled.value["proxy-groups"]
        .as_sequence()
        .unwrap()
        .iter()
        .find(|g| g["name"] == DEFAULT_FALLBACK_GROUP_NAME)
        .expect("default fallback group");
    assert_eq!(
        default_group["proxies"][0].as_str(),
        Some("TW 台湾 01 1x")
    );
}

#[test]
fn post_override_mtu_reclamps_null_and_high_mtu_for_proxy_and_provider_dialers_and_sanitizes_tcp() {
    let mut cfg = AppConfig::default();
    cfg.tun.enabled = true;
    cfg.tun.mtu = 1500;
    cfg.preaccel.enabled = true;
    // 1. Override deletes `tun.mtu` via `null` and adds a proxy-provider with override.dialer-proxy.
    cfg.rules_override.inline_override_yaml = Some(
        r#"
tun:
  mtu: null
proxy-providers:
  corp_pool:
    type: http
    url: https://sub.private-corp.example/subscribe/AbcSecret999?flag=clash
    path: ./providers/corp.yaml
    override:
      dialer-proxy: "⚡ 国内预加速入口"
"#
        .to_string(),
    );

    let relays = vec![sample_relay("r1", "Relay-A", "203.0.113.10", 10)];

    let mut anytls_node = sample_node("n-any", "Node-AnyTLS #1", 8443, false);
    anytls_node.protocol = "anytls".to_string();
    anytls_node.raw_config = serde_json::json!({
        "name": "Node-AnyTLS #1",
        "type": "anytls",
        "server": "anytls.vendor.example",
        "port": 8443,
        "password": "pw",
        "tfo": true,
        "min-idle-session": 4
    });

    let mut hy2_node = sample_node("n-hy2", "Node-Hy2", 443, true);
    hy2_node.protocol = "hysteria2".to_string();
    hy2_node.raw_config = serde_json::json!({
        "name": "Node-Hy2",
        "type": "hysteria2",
        "server": "hy2.vendor.example",
        "port": 443,
        "password": "pw2",
        "tfo": true
    });

    let nodes = vec![anytls_node, hy2_node];
    let ports = sample_ports();
    let empty = HashMap::new();

    let compiled = compile_mihomo_config(&CompileInput {
        config: &cfg,
        nodes: &nodes,
        groups: &[],
        relays: &relays,
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    })
    .expect("compile with null mtu override");

    assert_eq!(compiled.value["tun"]["mtu"].as_u64(), Some(1400));
    assert_eq!(compiled.stats.effective_tun_mtu, 1400);
    // 1 wrapped proxy (anytls) + 1 proxy-provider with override.dialer-proxy = 2
    assert_eq!(compiled.stats.dialer_wrapped_proxies, 2);

    // Business node transport sanitizer: anytls normalized, hysteria2 untouched
    let proxies = compiled.value["proxies"].as_sequence().unwrap();
    let any_p = proxies
        .iter()
        .find(|p| p["name"] == "Node-AnyTLS #1")
        .unwrap();
    assert_eq!(any_p["tfo"].as_bool(), Some(false));
    assert_eq!(any_p["min-idle-session"].as_u64(), Some(0));
    assert_eq!(any_p["idle-session-check-interval"].as_u64(), Some(30));
    assert_eq!(any_p["idle-session-timeout"].as_u64(), Some(30));

    let hy2_p = proxies.iter().find(|p| p["name"] == "Node-Hy2").unwrap();
    assert_eq!(hy2_p["tfo"].as_bool(), Some(true));

    // 2. All 6 added Tencent/WeChat/QCloud domains exist in QUIC direct bypass rules
    let rules: Vec<&str> = compiled.value["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for dom in [
        "qcloud.com",
        "myqcloud.com",
        "wechat.com",
        "qcloudimg.com",
        "tencentcs.com",
        "tencent-cloud.net",
    ] {
        let expected = format!(
            "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,{dom})),DIRECT"
        );
        assert!(
            rules.contains(&expected.as_str()),
            "missing domestic QUIC direct rule for {dom}"
        );
    }

    // 3. Overriding tun.mtu to 9000 with proxy-provider-only dialer still re-clamps to 1400.
    cfg.preaccel.enabled = false;
    cfg.rules_override.inline_override_yaml = Some(
        r#"
tun:
  mtu: 9000
proxy-providers:
  ext_pool:
    type: http
    url: https://sub.private-corp.example/subscribe/SecretPath
    override:
      dialer-proxy: "Node-Hy2"
"#
        .to_string(),
    );
    let compiled_provider_only = compile_mihomo_config(&CompileInput {
        config: &cfg,
        nodes: &nodes,
        groups: &[],
        relays: &[],
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    })
    .expect("compile provider-only dialer with mtu 9000");
    assert_eq!(compiled_provider_only.value["tun"]["mtu"].as_u64(), Some(1400));
    assert_eq!(compiled_provider_only.stats.effective_tun_mtu, 1400);
    assert_eq!(compiled_provider_only.stats.dialer_wrapped_proxies, 1);
}
