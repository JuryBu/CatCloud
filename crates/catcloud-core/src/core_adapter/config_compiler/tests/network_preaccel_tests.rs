use super::{sample_node, sample_ports, sample_relay};
use super::super::*;
use super::super::proxies_net::build_tun_section;
use crate::models::{AppConfig, DnsMode, MultiGroup, MultiGroupMode, TunStackMode};
use serde_yaml_ng::Value;
use std::collections::HashMap;

#[test]
fn compiles_full_dns_tun_and_domestic_preaccel_chain_with_anti_loop() {
    let mut cfg = AppConfig::default();
    cfg.core_ipv6 = true;
    cfg.dns.ipv6 = false;
    cfg.dns.mode = DnsMode::FakeIp;
    cfg.dns.prefer_h3 = true;
    cfg.dns.respect_rules = true;
    cfg.dns
        .hosts
        .insert("intra.example.test".to_string(), "127.0.0.1".to_string());
    cfg.dns
        .nameserver_policy
        .insert("+.cn".to_string(), vec!["223.5.5.5".to_string()]);
    cfg.tun.enabled = true;
    cfg.tun.stack_mode = TunStackMode::Gvisor;
    cfg.tun.strict_route = true;
    cfg.geodata.geodata_mode = true;
    cfg.preaccel.enabled = true;
    cfg.preaccel.skip_443_native = true;
    cfg.preaccel
        .campus_direct_domains
        .push("portal.campus.test".to_string());

    let ports = sample_ports();
    let nodes = vec![
        sample_node("n-non443", "Node-8443", 8443, false),
        sample_node("n-443", "Node-443-Native", 443, true),
    ];
    let relays = vec![
        sample_relay("r-primary", "Relay-Primary", "203.0.113.10", 10),
        sample_relay("r-backup", "Relay-Backup", "relay-b.example.test", 20),
    ];
    let extra_rules = vec!["IP-CIDR,203.0.113.99/32,DIRECT,no-resolve".to_string()];
    let extra_fake = vec!["captive.campus.test".to_string()];
    let empty_filtered = HashMap::new();

    let input = CompileInput {
        config: &cfg,
        nodes: &nodes,
        groups: &[],
        relays: &relays,
        controller_secret: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        allocated_ports: &ports,
        extra_prepend_rules: &extra_rules,
        extra_fake_ip_filters: &extra_fake,
        group_filtered_members: &empty_filtered,
    };

    let compiled = compile_mihomo_config(&input).expect("compile full config");
    assert!(compiled.validation.ok, "issues: {:?}", compiled.validation.issues);

    // Core vs DNS IPv6 independent controls + geodata-loader enforced
    assert_eq!(compiled.value["ipv6"], Value::Bool(true));
    assert_eq!(compiled.value["dns"]["ipv6"], Value::Bool(false));
    assert_eq!(compiled.value["geodata-mode"], Value::Bool(true));
    assert_eq!(compiled.value["geodata-loader"], "memconservative");
    assert_eq!(compiled.value["bind-address"], "127.0.0.1");
    assert_eq!(compiled.value["profile"]["store-selected"], Value::Bool(false));
    assert_eq!(compiled.value["profile"]["store-fake-ip"], Value::Bool(false));

    // 7-screenshot DNS fields
    let dns = &compiled.value["dns"];
    assert_eq!(dns["enable"], Value::Bool(true));
    assert_eq!(dns["listen"], "127.0.0.1:21053");
    assert_eq!(dns["use-hosts"], Value::Bool(true));
    assert_eq!(dns["use-system-hosts"], Value::Bool(true));
    assert_eq!(dns["respect-rules"], Value::Bool(true));
    assert_eq!(dns["prefer-h3"], Value::Bool(true));
    assert_eq!(dns["enhanced-mode"], "fake-ip");
    assert_eq!(dns["fake-ip-range"], "198.18.0.1/16");
    let fake_filters: Vec<&str> = dns["fake-ip-filter"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(fake_filters.contains(&"relay-b.example.test"));
    assert!(fake_filters.contains(&"portal.campus.test"));
    assert!(fake_filters.contains(&"captive.campus.test"));
    // Without runtime_dir geodata files on disk, fallback-filter safely disables geoip & omits geosite.
    assert_eq!(dns["fallback-filter"]["geoip"], Value::Bool(false));
    assert_eq!(dns["fallback-filter"]["geoip-code"], "CN");
    assert!(dns["fallback-filter"].get("geosite").is_none());
    assert!(dns.get("direct-nameserver").is_some());
    assert!(dns["nameserver-policy"].get("+.anthropic.com").is_some());
    assert!(dns["nameserver-policy"].get("+.antigravity.google").is_some());
    assert!(dns["nameserver-policy"].get("+.cn").is_some());

    // Sniffer & geox-url sections
    assert_eq!(compiled.value["sniffer"]["enable"], Value::Bool(true));
    assert_eq!(
        compiled.value["sniffer"]["force-dns-mapping"],
        Value::Bool(true)
    );
    assert_eq!(
        compiled.value["sniffer"]["parse-pure-ip"],
        Value::Bool(true)
    );
    assert_eq!(
        compiled.value["sniffer"]["override-destination"],
        Value::Bool(false)
    );
    assert!(compiled.value["geox-url"].get("geoip").is_some());
    assert!(compiled.value["geox-url"].get("geosite").is_some());
    assert!(compiled.value["geox-url"].get("mmdb").is_some());
    assert!(compiled.value["geox-url"].get("asn").is_some());

    // Full TUN fields (effective MTU clamps to <=1400 when dialer-proxy wraps >=1 proxy,
    // without mutating `AppConfig.tun.mtu`).
    let tun = &compiled.value["tun"];
    assert_eq!(tun["enable"], Value::Bool(true));
    assert_eq!(tun["stack"], "gvisor");
    assert_eq!(tun["strict-route"], Value::Bool(true));
    assert_eq!(tun["endpoint-independent-nat"], Value::Bool(false));
    assert_eq!(tun["mtu"], 1400);
    assert_eq!(compiled.stats.effective_tun_mtu, 1400);
    assert_eq!(cfg.tun.mtu, 1500);

    // Pre-accel chain: pure-IP relay omits SNI; non-443 gets dialer-proxy; 443-native skipped
    let proxies = compiled.value["proxies"].as_sequence().unwrap();
    let relay_primary = proxies
        .iter()
        .find(|p| p["name"] == "Relay-Primary")
        .unwrap();
    assert!(relay_primary.get("sni").is_none());
    assert_eq!(relay_primary["skip-cert-verify"], Value::Bool(true));

    let node_8443 = proxies.iter().find(|p| p["name"] == "Node-8443").unwrap();
    assert_eq!(node_8443["dialer-proxy"], PREACCEL_SELECT_GROUP_NAME);

    let node_443 = proxies
        .iter()
        .find(|p| p["name"] == "Node-443-Native")
        .unwrap();
    assert!(node_443.get("dialer-proxy").is_none());

    assert_eq!(compiled.stats.dialer_wrapped_proxies, 1);
    assert_eq!(compiled.stats.skipped_443_native_proxies, 1);

    // Fallback group has lazy: false and domestic 204 URL
    let fallback_group = compiled.value["proxy-groups"]
        .as_sequence()
        .unwrap()
        .iter()
        .find(|g| g["name"] == PREACCEL_FALLBACK_GROUP_NAME)
        .unwrap();
    assert_eq!(fallback_group["lazy"], Value::Bool(false));
    assert!(fallback_group["url"].as_str().unwrap().contains("hicloud.com"));

    // Anti-loop DIRECT rules placed at top
    let rules: Vec<&str> = compiled.value["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(rules.contains(&"IP-CIDR,203.0.113.10/32,DIRECT,no-resolve"));
    assert!(rules.contains(&"DOMAIN,relay-b.example.test,DIRECT"));
    assert!(rules.contains(&"DOMAIN,connectivitycheck.platform.hicloud.com,DIRECT"));

    // Reverse check: without any dialer-wrapped proxy (preaccel disabled), TUN MTU stays 1500.
    let mut cfg_no_preaccel = cfg.clone();
    cfg_no_preaccel.preaccel.enabled = false;
    let compiled_no_preaccel = compile_mihomo_config(&CompileInput {
        config: &cfg_no_preaccel,
        nodes: &nodes,
        groups: &[],
        relays: &relays,
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty_filtered,
    })
    .expect("compile without preaccel");
    assert_eq!(compiled_no_preaccel.stats.dialer_wrapped_proxies, 0);
    assert_eq!(compiled_no_preaccel.value["tun"]["mtu"], 1500);
    assert_eq!(compiled_no_preaccel.stats.effective_tun_mtu, 1500);

    // User-configured MTU below 1400 (e.g. 1280) must never be raised when preaccel is active.
    let mut cfg_low_mtu = cfg.clone();
    cfg_low_mtu.tun.mtu = 1280;
    let compiled_low_mtu = compile_mihomo_config(&CompileInput {
        config: &cfg_low_mtu,
        nodes: &nodes,
        groups: &[],
        relays: &relays,
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty_filtered,
    })
    .expect("compile low mtu");
    assert_eq!(compiled_low_mtu.value["tun"]["mtu"], 1280);
    assert_eq!(compiled_low_mtu.stats.effective_tun_mtu, 1280);

    // Verify locked transport diagnostics snapshot helper.
    let diag = build_preaccel_transport_diagnostics(
        &cfg,
        compiled.stats.effective_tun_mtu,
        "main-tun-core",
    );
    assert_eq!(diag.effective_mode, "main-tun-core");
    assert_eq!(diag.effective_tun_mtu, 1400);
    assert!(!diag.anytls_tfo);
    assert_eq!(diag.anytls_min_idle_session, 0);
    assert_eq!(diag.keep_alive_idle_sec, 45);
    assert_eq!(diag.keep_alive_interval_sec, 15);
    assert_eq!(diag.expected_probe_status, "204");
    assert_eq!(diag.lb_strategy, "consistent-hashing");
    assert_eq!(diag.probe_interval_sec, 30);
}

#[test]
fn enforces_probe_bypass_domestic_dns_direct_tag_relay_delegation_and_quic_order() {
    let mut cfg = AppConfig::default();
    cfg.dns.respect_rules = true;
    cfg.dns.direct_nameserver = vec![
        "https://223.5.5.5/dns-query".to_string(),
        "https://1.12.12.12/dns-query#CUSTOM".to_string(),
        "system".to_string(),
    ];
    cfg.dns.nameserver = vec![
        "https://223.5.5.5/dns-query".to_string(),
        "https://1.12.12.12/dns-query".to_string(),
        "https://1.1.1.1/dns-query".to_string(),
        "https://223.6.6.6/dns-query#KEEP".to_string(),
    ];
    cfg.dns.fallback.clear();
    cfg.preaccel.enabled = true;
    cfg.rules_override.block_quic_udp_443 = true;
    cfg.rules_override.global_prepend_rules =
        vec!["DOMAIN,global-pre.example.test,DIRECT".to_string()];

    let mut vless_relay = sample_relay("r-vless", "Relay-VLESS-443", "203.0.113.30", 10);
    vless_relay.protocol = "vless".to_string();
    vless_relay.password = "11111111-2222-3333-4444-555555555555".to_string();
    vless_relay.port = 443;
    vless_relay.sni = Some("mistaken-sni.example.com".to_string());

    let mut anytls_relay = sample_relay("r-anytls", "Relay-AnyTLS-443", "203.0.113.31", 20);
    anytls_relay.protocol = "anytls".to_string();
    anytls_relay.port = 443;
    anytls_relay.sni = Some("mistaken-sni.example.com".to_string());

    let relays = vec![vless_relay, anytls_relay];
    let nodes = vec![sample_node("n1", "Node-JP-8443", 8443, false)];
    let group = MultiGroup {
        id: "g-ai".to_string(),
        name: "AI-Group".to_string(),
        match_rules: vec!["DOMAIN-SUFFIX,openai.com".to_string()],
        member_node_ids: vec!["n1".to_string()],
        ..Default::default()
    };
    let extra_prepend = vec!["DOMAIN,extra-pre.example.test,DIRECT".to_string()];
    let ports = sample_ports();
    let empty = HashMap::new();

    let compiled = compile_mihomo_config(&CompileInput {
        config: &cfg,
        nodes: &nodes,
        groups: &[group],
        relays: &relays,
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &extra_prepend,
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    })
    .expect("compile ok");
    assert!(compiled.validation.ok, "issues: {:?}", compiled.validation.issues);

    // 1. Rules ordering: anti-loop -> PROCESS-NAME probe bypass -> private LAN -> domestic DNS IPs ->
    //    extra_prepend -> global_prepend -> QUIC REJECT -> group match_rules
    let rules: Vec<&str> = compiled.value["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let probe_rule = format!(
        "PROCESS-NAME,{},DIRECT",
        crate::probe::isolated_runner::PROBE_CORE_PROCESS_NAME
    );
    let idx_anti_loop = rules
        .iter()
        .position(|r| *r == "IP-CIDR,203.0.113.30/32,DIRECT,no-resolve")
        .expect("relay anti-loop rule");
    let idx_probe = rules
        .iter()
        .position(|r| *r == probe_rule.as_str())
        .expect("probe core PROCESS-NAME bypass");
    let idx_lan = rules
        .iter()
        .position(|r| *r == "IP-CIDR6,fe80::/10,DIRECT,no-resolve")
        .expect("private LAN rule");
    let idx_dns_ali = rules
        .iter()
        .position(|r| *r == "IP-CIDR,223.5.5.5/32,DIRECT,no-resolve")
        .expect("223.5.5.5 direct rule");
    let idx_dns_dnspod = rules
        .iter()
        .position(|r| *r == "IP-CIDR,119.29.29.29/32,DIRECT,no-resolve")
        .expect("119.29.29.29 direct rule");
    let idx_extra_pre = rules
        .iter()
        .position(|r| *r == "DOMAIN,extra-pre.example.test,DIRECT")
        .expect("extra prepend rule");
    let idx_global_pre = rules
        .iter()
        .position(|r| *r == "DOMAIN,global-pre.example.test,DIRECT")
        .expect("global prepend rule");
    let idx_quic = rules
        .iter()
        .position(|r| *r == "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT")
        .expect("QUIC reject rule");
    let idx_group_rule = rules
        .iter()
        .position(|r| *r == "DOMAIN-SUFFIX,openai.com,AI-Group")
        .expect("group match rule");

    assert!(idx_anti_loop < idx_probe);
    assert!(idx_probe < idx_lan);
    assert!(idx_lan < idx_dns_ali);
    assert!(rules.contains(&"IP-CIDR,223.6.6.6/32,DIRECT,no-resolve"));
    assert!(rules.contains(&"IP-CIDR,1.12.12.12/32,DIRECT,no-resolve"));
    assert!(idx_dns_dnspod < idx_extra_pre);
    assert!(idx_extra_pre < idx_global_pre);
    assert!(idx_global_pre < idx_quic);
    assert!(idx_quic < idx_group_rule);

    // 2. DNS #DIRECT suffixes and effective_fallback fallback behavior
    let direct_ns: Vec<&str> = compiled.value["dns"]["direct-nameserver"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        direct_ns,
        vec![
            "https://223.5.5.5/dns-query#DIRECT",
            "https://1.12.12.12/dns-query#CUSTOM",
            "system",
        ]
    );

    let nameservers: Vec<&str> = compiled.value["dns"]["nameserver"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        nameservers,
        vec![
            "https://223.5.5.5/dns-query#DIRECT",
            "https://1.12.12.12/dns-query#DIRECT",
            "https://1.1.1.1/dns-query",
            "https://223.6.6.6/dns-query#KEEP",
        ]
    );

    let fallback_ns: Vec<&str> = compiled.value["dns"]["fallback"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        fallback_ns,
        vec![
            "https://1.1.1.1/dns-query",
            "https://8.8.8.8/dns-query",
        ]
    );

    // 3. Relay compilation delegates to preaccel::generator::compile_relay_to_mihomo_yaml
    let proxies = compiled.value["proxies"].as_sequence().unwrap();
    let compiled_vless = proxies
        .iter()
        .find(|p| p["name"] == "Relay-VLESS-443")
        .expect("compiled VLESS relay");
    assert_eq!(compiled_vless["type"], "vless");
    assert_eq!(compiled_vless["network"], "tcp");
    assert_eq!(compiled_vless["servername"], "");

    let compiled_anytls = proxies
        .iter()
        .find(|p| p["name"] == "Relay-AnyTLS-443")
        .expect("compiled AnyTLS relay");
    assert!(compiled_anytls.get("sni").is_none());

    // 4. When respect_rules == false, #DIRECT must NOT be appended
    let mut cfg_no_respect = cfg;
    cfg_no_respect.dns.respect_rules = false;
    let compiled_no_respect = compile_mihomo_config(&CompileInput {
        config: &cfg_no_respect,
        nodes: &nodes,
        groups: &[],
        relays: &[],
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    })
    .expect("compile ok");
    let direct_ns_off: Vec<&str> = compiled_no_respect.value["dns"]["direct-nameserver"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        direct_ns_off,
        vec![
            "https://223.5.5.5/dns-query",
            "https://1.12.12.12/dns-query#CUSTOM",
            "system",
        ]
    );
    let ns_off: Vec<&str> = compiled_no_respect.value["dns"]["nameserver"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(ns_off[0], "https://223.5.5.5/dns-query");
}

#[test]
fn hardens_preaccel_fallback_direct_domestic_dns_and_codex_twitter_doh() {
    let mut cfg = AppConfig::default();
    cfg.preaccel.enabled = true;
    cfg.preaccel.auto_failover = true;

    let relays = vec![sample_relay("r1", "Relay-SH", "203.0.113.44", 10)];
    let nodes = vec![sample_node("n1", "Node-TW-01", 8443, false)];
    let group = MultiGroup {
        id: "g-ai".to_string(),
        name: "AI-Codex".to_string(),
        mode: MultiGroupMode::StickyBest,
        match_rules: vec!["@ai_domains".to_string()],
        member_node_ids: vec!["n1".to_string()],
        active_node_id: Some("n1".to_string()),
        ..Default::default()
    };
    let ports = sample_ports();
    let empty = HashMap::new();

    let compiled = compile_mihomo_config(&CompileInput {
        config: &cfg,
        nodes: &nodes,
        groups: &[group],
        relays: &relays,
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    })
    .expect("compile ok");
    assert!(compiled.validation.ok, "issues: {:?}", compiled.validation.issues);

    // 1. Pre-accel fallback group ends with DIRECT safety net.
    let fallback_group = compiled.value["proxy-groups"]
        .as_sequence()
        .unwrap()
        .iter()
        .find(|g| g["name"] == PREACCEL_FALLBACK_GROUP_NAME)
        .expect("preaccel fallback group");
    let fb_members: Vec<&str> = fallback_group["proxies"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(fb_members, vec!["Relay-SH", "DIRECT"]);

    // 2. All domestic DNS IPs and DoH/DoT hostnames have DIRECT rules & fake-ip-filter entries.
    let rules: Vec<&str> = compiled.value["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for expected_dns_rule in [
        "IP-CIDR,223.5.5.5/32,DIRECT,no-resolve",
        "IP-CIDR,223.6.6.6/32,DIRECT,no-resolve",
        "IP-CIDR,1.12.12.12/32,DIRECT,no-resolve",
        "IP-CIDR,119.29.29.29/32,DIRECT,no-resolve",
        "IP-CIDR,119.28.28.28/32,DIRECT,no-resolve",
        "IP-CIDR,120.53.53.53/32,DIRECT,no-resolve",
        "IP-CIDR,114.114.114.114/32,DIRECT,no-resolve",
        "IP-CIDR,114.114.115.115/32,DIRECT,no-resolve",
        "IP-CIDR,180.76.76.76/32,DIRECT,no-resolve",
        "DOMAIN,dns.alidns.com,DIRECT",
        "DOMAIN,doh.pub,DIRECT",
        "DOMAIN,dot.pub,DIRECT",
    ] {
        assert!(
            rules.contains(&expected_dns_rule),
            "missing domestic DNS direct rule `{expected_dns_rule}`"
        );
    }

    let fake_filters: Vec<&str> = compiled.value["dns"]["fake-ip-filter"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for dns_host in ["dns.alidns.com", "doh.pub", "dot.pub"] {
        assert!(
            fake_filters.contains(&dns_host),
            "missing domestic DNS fake-ip-filter `{dns_host}`"
        );
    }

    // 3. Codex endpoints & Twitter/X domains are pinned to overseas DoH in nameserver-policy.
    let policy = &compiled.value["dns"]["nameserver-policy"];
    for doh_domain in [
        "ab.chatgpt.com",
        "ios.chat.openai.com",
        "api.openai.com",
        "+.x.com",
        "+.twitter.com",
        "+.twimg.com",
        "+.t.co",
    ] {
        let servers: Vec<&str> = policy
            .get(doh_domain)
            .and_then(Value::as_sequence)
            .unwrap_or_else(|| panic!("missing nameserver-policy for `{doh_domain}`"))
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(
            servers.contains(&"https://1.1.1.1/dns-query"),
            "`{doh_domain}` must route via overseas DoH fallback, got {servers:?}"
        );
    }

    // 4. build_default_ai_routing_rules / @ai_domains explicitly include Codex endpoints.
    let ai_rules = build_default_ai_routing_rules("AI-Codex");
    for codex_rule in [
        "DOMAIN-SUFFIX,ab.chatgpt.com,AI-Codex",
        "DOMAIN-SUFFIX,ios.chat.openai.com,AI-Codex",
        "DOMAIN-SUFFIX,api.openai.com,AI-Codex",
    ] {
        assert!(
            ai_rules.iter().any(|r| r == codex_rule),
            "build_default_ai_routing_rules missing `{codex_rule}`"
        );
        assert!(
            rules.contains(&codex_rule),
            "compiled @ai_domains rules missing `{codex_rule}`"
        );
    }
}

#[test]
fn compiles_country_lite_mmdb_and_conservative_domestic_direct_rules() {
    let dir = std::env::temp_dir().join(format!(
        "catcloud-compiler-country-lite-test-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let cfg = AppConfig::default();
    let ports = sample_ports();
    let nodes = vec![sample_node("n1", "Node-TW-01", 443, true)];
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

    // 1. country-lite.mmdb alone (geodata_mode == false) must NOT activate GeoIP rules or DNS filter
    //    because Mihomo only reads `Country.mmdb` / `country.mmdb`.
    std::fs::write(dir.join("country-lite.mmdb"), b"stub").unwrap();
    let lite_only = compile_mihomo_config_with_runtime_dir(&input, Some(&dir)).unwrap();
    assert!(lite_only.validation.ok);
    assert_eq!(
        lite_only.value["dns"]["fallback-filter"]["geoip"],
        Value::Bool(false)
    );
    let rules_no_geosite: Vec<&str> = lite_only.value["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(!rules_no_geosite.contains(&"GEOIP,CN,DIRECT,no-resolve"));

    // Unconditional private LAN / reserved CIDR / local domain / expanded domestic DNS rules.
    for expected in [
        "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
        "IP-CIDR,224.0.0.0/4,DIRECT,no-resolve",
        "IP-CIDR,255.255.255.255/32,DIRECT,no-resolve",
        "DOMAIN-SUFFIX,local,DIRECT",
        "DOMAIN-SUFFIX,localhost,DIRECT",
        "DOMAIN-SUFFIX,localdomain,DIRECT",
        "DOMAIN-SUFFIX,home.arpa,DIRECT",
        "DOMAIN-SUFFIX,lan,DIRECT",
        "DOMAIN-SUFFIX,internal,DIRECT",
        "IP-CIDR,180.184.1.1/32,DIRECT,no-resolve",
        "IP-CIDR,180.184.2.2/32,DIRECT,no-resolve",
        "IP-CIDR,1.2.4.8/32,DIRECT,no-resolve",
        "IP-CIDR,210.2.4.8/32,DIRECT,no-resolve",
        "DOMAIN,dns.pub,DIRECT",
    ] {
        assert!(
            rules_no_geosite.contains(&expected),
            "missing unconditional rule `{expected}`"
        );
    }
    // Strictly forbidden: never bypass CatCloud.exe so dashboard proxy checks stay routed via proxy.
    assert!(
        !rules_no_geosite.iter().any(|r| r.contains("CatCloud.exe")),
        "CatCloud.exe must never be added to DIRECT rules"
    );

    // Both Group A (system/download CDN) and Group B (fallback domestic sites) present without geosite.dat.
    for expected_domestic in [
        "DOMAIN-SUFFIX,msftconnecttest.com,DIRECT",
        "DOMAIN-SUFFIX,dl.delivery.mp.microsoft.com,DIRECT",
        "DOMAIN-SUFFIX,icloud.com.cn,DIRECT",
        "DOMAIN-SUFFIX,push.apple.com,DIRECT",
        "DOMAIN-SUFFIX,steamcontent.com,DIRECT",
        "DOMAIN-SUFFIX,dl.steam.clngaa.com,DIRECT",
        "DOMAIN-SUFFIX,ntp.aliyun.com,DIRECT",
        "DOMAIN-SUFFIX,gtimg.com,DIRECT",
        "DOMAIN-SUFFIX,alicdn.com,DIRECT",
        "DOMAIN-SUFFIX,bilivideo.com,DIRECT",
        "DOMAIN-SUFFIX,xiaohongshu.com,DIRECT",
        "DOMAIN-SUFFIX,npmmirror.com,DIRECT",
        "DOMAIN-SUFFIX,cainiao.com,DIRECT",
    ] {
        assert!(
            rules_no_geosite.contains(&expected_domestic),
            "missing domestic direct rule `{expected_domestic}`"
        );
    }

    // Conservative red line: overseas or hybrid root domains must NEVER appear as DIRECT rules.
    for forbidden in [
        "github.com",
        "google.com",
        "googleapis.com",
        "openai.com",
        "chatgpt.com",
        "anthropic.com",
        "claude.ai",
        "x.com",
        "twitter.com",
        "cloudflare.com",
        "microsoft.com",
        "live.com",
        "bing.com",
        "apple.com",
        "steampowered.com",
        "steamcommunity.com",
        "larksuite.com",
        "tiktok.com",
        "linux.do",
        "alibaba.com",
        "wps.com",
    ] {
        let suffix_rule = format!("DOMAIN-SUFFIX,{forbidden},DIRECT");
        let exact_rule = format!("DOMAIN,{forbidden},DIRECT");
        assert!(
            !rules_no_geosite.contains(&suffix_rule.as_str())
                && !rules_no_geosite.contains(&exact_rule.as_str()),
            "conservative red line violated by `{forbidden}`"
        );
    }

    // 2. With geosite.dat present: Group A stays BEFORE GEOSITE,cn,DIRECT while Group B is omitted.
    std::fs::write(dir.join("geosite.dat"), b"stub").unwrap();
    let with_geosite = compile_mihomo_config_with_runtime_dir(&input, Some(&dir)).unwrap();
    let rules_with_geosite: Vec<&str> = with_geosite.value["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let idx_steam_cdn = rules_with_geosite
        .iter()
        .position(|r| *r == "DOMAIN-SUFFIX,steamcontent.com,DIRECT")
        .expect("Group A system/CDN rule must still be emitted with geosite.dat");
    let idx_geosite_cn = rules_with_geosite
        .iter()
        .position(|r| *r == "GEOSITE,cn,DIRECT")
        .expect("GEOSITE,cn,DIRECT must be present");
    assert!(idx_steam_cdn < idx_geosite_cn);
    assert!(rules_with_geosite.contains(&"DOMAIN-SUFFIX,msftconnecttest.com,DIRECT"));
    assert!(rules_with_geosite.contains(&"DOMAIN-SUFFIX,icloud.com.cn,DIRECT"));
    assert!(!rules_with_geosite.contains(&"DOMAIN-SUFFIX,gtimg.com,DIRECT"));
    assert!(!rules_with_geosite.contains(&"DOMAIN-SUFFIX,bilivideo.com,DIRECT"));

    // 3. When domestic_direct_enabled == false, LAN & local domains remain while Groups A/B are omitted.
    let mut cfg_off = AppConfig::default();
    cfg_off.rules_override.domestic_direct_enabled = false;
    let input_off = CompileInput {
        config: &cfg_off,
        ..input
    };
    let off_compiled = compile_mihomo_config_with_runtime_dir(&input_off, Some(&dir)).unwrap();
    let rules_off: Vec<&str> = off_compiled.value["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(rules_off.contains(&"IP-CIDR,100.64.0.0/10,DIRECT,no-resolve"));
    assert!(rules_off.contains(&"DOMAIN-SUFFIX,local,DIRECT"));
    assert!(rules_off.contains(&"DOMAIN-SUFFIX,home.arpa,DIRECT"));
    assert!(!rules_off.contains(&"DOMAIN-SUFFIX,steamcontent.com,DIRECT"));
    assert!(!rules_off.contains(&"GEOSITE,cn,DIRECT"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn country_lite_mmdb_alone_does_not_enable_geoip_cn() {
    let dir = std::env::temp_dir().join(format!(
        "catcloud-compiler-mmdb-regression-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let cfg = AppConfig::default();
    let ports = sample_ports();
    let nodes = vec![sample_node("n1", "Node-TW-01", 443, true)];
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

    // 1. Only `country-lite.mmdb` present -> Mihomo will not load it as `Country.mmdb`,
    //    so `GEOIP,CN` and `fallback-filter.geoip` must stay disabled.
    std::fs::write(dir.join("country-lite.mmdb"), b"stub").unwrap();
    let compiled_lite = compile_mihomo_config_with_runtime_dir(&input, Some(&dir)).unwrap();
    assert!(compiled_lite.validation.ok);
    assert_eq!(
        compiled_lite.value["dns"]["fallback-filter"]["geoip"],
        Value::Bool(false)
    );
    let rules_lite: Vec<&str> = compiled_lite.value["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(!rules_lite.contains(&"GEOIP,CN,DIRECT,no-resolve"));

    // 2. Lowercase `country.mmdb` enables GeoIP cleanly.
    std::fs::write(dir.join("country.mmdb"), b"stub").unwrap();
    let compiled_lower = compile_mihomo_config_with_runtime_dir(&input, Some(&dir)).unwrap();
    assert!(compiled_lower.validation.ok);
    assert_eq!(
        compiled_lower.value["dns"]["fallback-filter"]["geoip"],
        Value::Bool(true)
    );
    let rules_lower: Vec<&str> = compiled_lower.value["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(rules_lower.contains(&"GEOIP,CN,DIRECT,no-resolve"));

    // 3. Canonical `Country.mmdb` enables GeoIP cleanly.
    let _ = std::fs::remove_file(dir.join("country.mmdb"));
    std::fs::write(dir.join("Country.mmdb"), b"stub").unwrap();
    let compiled_upper = compile_mihomo_config_with_runtime_dir(&input, Some(&dir)).unwrap();
    assert!(compiled_upper.validation.ok);
    assert_eq!(
        compiled_upper.value["dns"]["fallback-filter"]["geoip"],
        Value::Bool(true)
    );
    let rules_upper: Vec<&str> = compiled_upper.value["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(rules_upper.contains(&"GEOIP,CN,DIRECT,no-resolve"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn should_emit_tun_device_name_enforces_macos_utun_naming_and_allows_windows_linux() {
    assert!(!should_emit_tun_device_name("macos", "CatCloud"));
    assert!(!should_emit_tun_device_name("macos", "utun_bad"));
    assert!(!should_emit_tun_device_name("macos", "   "));
    assert!(should_emit_tun_device_name("macos", "utun9"));
    assert!(should_emit_tun_device_name("macos", "utun"));
    assert!(should_emit_tun_device_name("macos", "utun12"));

    assert!(should_emit_tun_device_name("windows", "CatCloud"));
    assert!(should_emit_tun_device_name("windows", "utun9"));
    assert!(should_emit_tun_device_name("linux", "CatCloud"));
    assert!(should_emit_tun_device_name("linux", "catcloud0"));
    assert!(!should_emit_tun_device_name("windows", ""));
    assert!(!should_emit_tun_device_name("linux", "  "));

    let mut cfg = AppConfig::default();
    cfg.tun.enabled = true;
    cfg.tun.device_name = "CatCloud".to_string();
    let tun_map = build_tun_section(&cfg, cfg.tun.mtu);
    if cfg!(target_os = "macos") {
        assert!(tun_map.get("device").is_none());
    } else {
        assert_eq!(tun_map.get("device").and_then(Value::as_str), Some("CatCloud"));
    }

    cfg.tun.device_name = "utun9".to_string();
    let tun_utun = build_tun_section(&cfg, cfg.tun.mtu);
    assert_eq!(tun_utun.get("device").and_then(Value::as_str), Some("utun9"));
}

#[test]
fn conservative_domestic_direct_includes_system_push_notification_domains() {
    let dir = std::env::temp_dir().join(format!(
        "catcloud-compiler-push-direct-{}",
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

    // Always emitted even without geosite.dat.
    let without_geosite = compile_mihomo_config_with_runtime_dir(&input, Some(&dir)).unwrap();
    assert!(without_geosite.validation.ok);
    let rules_no_geo: Vec<&str> = without_geosite.value["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for domain in ["wns.windows.com", "notify.windows.com", "push.apple.com"] {
        let expected = format!("DOMAIN-SUFFIX,{domain},DIRECT");
        assert!(
            rules_no_geo.contains(&expected.as_str()),
            "missing conservative system push direct rule `{expected}`"
        );
    }

    // Still emitted ahead of GEOSITE,cn,DIRECT when geosite.dat is present.
    std::fs::write(dir.join("geosite.dat"), b"stub").unwrap();
    let with_geosite = compile_mihomo_config_with_runtime_dir(&input, Some(&dir)).unwrap();
    let rules_with_geo: Vec<&str> = with_geosite.value["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let idx_geosite = rules_with_geo
        .iter()
        .position(|r| *r == "GEOSITE,cn,DIRECT")
        .expect("GEOSITE,cn,DIRECT must exist");
    for domain in ["wns.windows.com", "notify.windows.com", "push.apple.com"] {
        let expected = format!("DOMAIN-SUFFIX,{domain},DIRECT");
        let idx = rules_with_geo
            .iter()
            .position(|r| *r == expected)
            .unwrap_or_else(|| panic!("missing `{expected}` with geosite.dat"));
        assert!(idx < idx_geosite);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn allows_domestic_quic_udp_443_before_reject_and_always_adds_qq_fake_ip_filters() {
    let dir = std::env::temp_dir().join(format!(
        "catcloud-compiler-domestic-quic-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let cfg = AppConfig::default();
    let ports = sample_ports();
    let nodes = vec![sample_node("n1", "Node-JP-01", 443, true)];
    let group = MultiGroup {
        id: "g-ai".to_string(),
        name: "AI-Group".to_string(),
        match_rules: vec!["DOMAIN-SUFFIX,openai.com".to_string()],
        member_node_ids: vec!["n1".to_string()],
        ..Default::default()
    };
    let empty = HashMap::new();
    let input = CompileInput {
        config: &cfg,
        nodes: &nodes,
        groups: &[group],
        relays: &[],
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    };

    // 1. Without geosite/geoip files: domain-based domestic QUIC DIRECT rules precede QUIC REJECT,
    //    which still precedes group match rules; GEOSITE/GEOIP QUIC rules stay absent.
    let no_geo = compile_mihomo_config_with_runtime_dir(&input, Some(&dir)).unwrap();
    assert!(no_geo.validation.ok, "issues: {:?}", no_geo.validation.issues);
    let rules_no_geo: Vec<&str> = no_geo.value["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let idx_reject = rules_no_geo
        .iter()
        .position(|r| *r == "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT")
        .expect("QUIC reject rule");
    let idx_group = rules_no_geo
        .iter()
        .position(|r| *r == "DOMAIN-SUFFIX,openai.com,AI-Group")
        .expect("group match rule");
    assert!(idx_reject < idx_group);
    for domain in [
        "cn",
        "qq.com",
        "qpic.cn",
        "qlogo.cn",
        "gtimg.cn",
        "gtimg.com",
        "weixin.qq.com",
        "tencent.com",
        "bilibili.com",
        "bilivideo.com",
        "bilivideo.cn",
    ] {
        let expected =
            format!("AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,{domain})),DIRECT");
        let idx = rules_no_geo
            .iter()
            .position(|r| *r == expected)
            .unwrap_or_else(|| panic!("missing domestic QUIC allow rule `{expected}`"));
        assert!(idx < idx_reject, "`{expected}` must precede QUIC REJECT");
    }
    assert!(
        !rules_no_geo.contains(&"AND,((NETWORK,UDP),(DST-PORT,443),(GEOSITE,cn)),DIRECT")
    );
    assert!(
        !rules_no_geo
            .contains(&"AND,((NETWORK,UDP),(DST-PORT,443),(GEOIP,CN,no-resolve)),DIRECT")
    );

    // Unconditional QQ/WeChat/Tencent Cloud fake-ip-filter entries must always be present.
    let fake_filters: Vec<&str> = no_geo.value["dns"]["fake-ip-filter"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for pattern in [
        "+.qq.com",
        "+.qpic.cn",
        "+.qlogo.cn",
        "+.gtimg.cn",
        "+.gtimg.com",
        "+.nt.qq.com.cn",
        "+.weixin.qq.com",
        "+.tencent.com",
        "+.qcloud.com",
        "+.myqcloud.com",
    ] {
        assert!(
            fake_filters.contains(&pattern),
            "missing unconditional fake-ip-filter `{pattern}`"
        );
    }

    // 2. With geosite.dat + Country.mmdb: both GEOSITE & GEOIP domestic QUIC DIRECT rules precede REJECT.
    std::fs::write(dir.join("geosite.dat"), b"stub").unwrap();
    std::fs::write(dir.join("Country.mmdb"), b"stub").unwrap();
    let with_geo = compile_mihomo_config_with_runtime_dir(&input, Some(&dir)).unwrap();
    assert!(with_geo.validation.ok, "issues: {:?}", with_geo.validation.issues);
    let rules_geo: Vec<&str> = with_geo.value["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let idx_reject_geo = rules_geo
        .iter()
        .position(|r| *r == "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT")
        .expect("QUIC reject rule");
    let idx_geosite_quic = rules_geo
        .iter()
        .position(|r| *r == "AND,((NETWORK,UDP),(DST-PORT,443),(GEOSITE,cn)),DIRECT")
        .expect("GEOSITE cn QUIC allow rule");
    let idx_geoip_quic = rules_geo
        .iter()
        .position(|r| *r == "AND,((NETWORK,UDP),(DST-PORT,443),(GEOIP,CN,no-resolve)),DIRECT")
        .expect("GEOIP CN QUIC allow rule");
    assert!(idx_geosite_quic < idx_reject_geo);
    assert!(idx_geoip_quic < idx_reject_geo);

    // 3. When domestic_direct_enabled == false, domestic QUIC allow rules are omitted while REJECT stays.
    let mut cfg_no_dom = AppConfig::default();
    cfg_no_dom.rules_override.domestic_direct_enabled = false;
    let no_dom = compile_mihomo_config_with_runtime_dir(
        &CompileInput {
            config: &cfg_no_dom,
            ..input
        },
        Some(&dir),
    )
    .unwrap();
    let rules_no_dom: Vec<&str> = no_dom.value["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(rules_no_dom.contains(&"AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"));
    assert!(
        !rules_no_dom
            .contains(&"AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,qq.com)),DIRECT")
    );
    assert!(
        !rules_no_dom.contains(&"AND,((NETWORK,UDP),(DST-PORT,443),(GEOSITE,cn)),DIRECT")
    );

    // 4. `build_node_proxy_mapping` is public and produces valid proxy mapping.
    let mapped = build_node_proxy_mapping(&nodes[0], "Share-Node-01").expect("public mapping");
    assert_eq!(mapped.get("name").and_then(Value::as_str), Some("Share-Node-01"));
    assert_eq!(mapped.get("type").and_then(Value::as_str), Some("trojan"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn keeps_quic_sniffer_when_geoip_missing_and_omits_when_geoip_present_or_domestic_disabled() {
    let dir = std::env::temp_dir().join(format!(
        "catcloud-compiler-quic-sniffer-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let nodes = vec![sample_node("n1", "JP-Edge-01", 443, true)];
    let groups = vec![MultiGroup {
        id: "grp-main".to_string(),
        name: "Main-Group".to_string(),
        mode: MultiGroupMode::StickyBest,
        member_node_ids: vec!["n1".into()],
        ..Default::default()
    }];
    let ports = sample_ports();
    let empty = HashMap::new();

    // 1. Missing Country.mmdb (has_geoip = false) with block_quic_udp_443 = true and
    //    domestic_direct_enabled = true MUST retain QUIC sniffer so domestic IM packets
    //    carrying real IPs can still extract SNI and hit DOMAIN-SUFFIX DIRECT rules.
    let mut cfg = AppConfig::default();
    cfg.rules_override.block_quic_udp_443 = true;
    cfg.rules_override.domestic_direct_enabled = true;
    let input = CompileInput {
        config: &cfg,
        nodes: &nodes,
        groups: &groups,
        relays: &[],
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    };
    let without_geoip = compile_mihomo_config_with_runtime_dir(&input, Some(&dir)).unwrap();
    assert!(
        without_geoip.value["sniffer"]["sniff"].get("QUIC").is_some(),
        "QUIC sniffer must remain enabled when Country.mmdb is absent"
    );

    // 2. When domestic_direct_enabled = false and block_quic_udp_443 = true, QUIC sniffer is omitted.
    let mut cfg_no_dom = cfg.clone();
    cfg_no_dom.rules_override.domestic_direct_enabled = false;
    let no_dom = compile_mihomo_config_with_runtime_dir(
        &CompileInput {
            config: &cfg_no_dom,
            ..input
        },
        Some(&dir),
    )
    .unwrap();
    assert!(no_dom.value["sniffer"]["sniff"].get("QUIC").is_none());

    // 3. Once Country.mmdb exists (has_geoip = true), GEOIP,CN protects domestic QUIC and
    //    QUIC sniffer can be omitted when block_quic_udp_443 = true.
    std::fs::write(dir.join("Country.mmdb"), b"stub").unwrap();
    let with_geoip = compile_mihomo_config_with_runtime_dir(&input, Some(&dir)).unwrap();
    assert!(with_geoip.value["sniffer"]["sniff"].get("QUIC").is_none());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn campus_network_dns_defaults_fallbacks_and_intranet_system_policy() {
    let ports = sample_ports();
    let nodes = vec![sample_node("n1", "JP-Edge-01", 443, true)];
    let empty = HashMap::new();

    // 1. Default config compiles pure-IP DoH 443 across default/direct/proxy-server
    //    nameservers and injects `system` policy for campus/LAN suffixes + campus_direct_domains.
    let mut cfg = AppConfig::default();
    cfg.preaccel.campus_direct_domains = vec![
        "portal.campus.example.org".to_string(),
        "*.intranet.example.org".to_string(),
        "DOMAIN-SUFFIX,rule-campus.example.org,DIRECT".to_string(),
        "DOMAIN,auth.campus.example.org,DIRECT".to_string(),
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve".to_string(), // non-domain rule must not pollute DNS policy
        "172.28.255.155".to_string(), // IP must be ignored by nameserver-policy
    ];
    cfg.dns.nameserver_policy.insert(
        "+.lan".to_string(),
        vec!["10.0.0.53".to_string()], // User custom policy must never be overwritten
    );

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
    .expect("compile default campus-safe dns");

    let seq_to_vec = |v: &Value| -> Vec<String> {
        v.as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .map(ToString::to_string)
            .collect()
    };

    let expected_encrypted = vec![
        "https://223.5.5.5/dns-query".to_string(),
        "https://1.12.12.12/dns-query".to_string(),
        "tls://223.6.6.6:853".to_string(),
        "tls://120.53.53.53:853".to_string(),
    ];
    let expected_encrypted_direct = vec![
        "https://223.5.5.5/dns-query#DIRECT".to_string(),
        "https://1.12.12.12/dns-query#DIRECT".to_string(),
        "tls://223.6.6.6:853#DIRECT".to_string(),
        "tls://120.53.53.53:853#DIRECT".to_string(),
    ];

    assert_eq!(
        seq_to_vec(&compiled.value["dns"]["default-nameserver"]),
        expected_encrypted
    );
    assert_eq!(
        seq_to_vec(&compiled.value["dns"]["direct-nameserver"]),
        expected_encrypted_direct
    );
    assert_eq!(
        seq_to_vec(&compiled.value["dns"]["proxy-server-nameserver"]),
        expected_encrypted
    );

    let policy = &compiled.value["dns"]["nameserver-policy"];
    let expected_campus_policy = vec![
        "system".to_string(),
        "https://223.5.5.5/dns-query#DIRECT".to_string(),
        "https://1.12.12.12/dns-query#DIRECT".to_string(),
    ];
    assert!(
        expected_campus_policy.iter().all(|s| !s.contains(":853")),
        "campus policy must never include port 853 DoT"
    );
    for key in [
        "+.edu.cn",
        "+.local",
        "+.localdomain",
        "+.internal",
        "+.home.arpa",
        "portal.campus.example.org",
        "+.intranet.example.org",
        "+.rule-campus.example.org",
        "auth.campus.example.org",
    ] {
        assert_eq!(
            seq_to_vec(&policy[key]),
            expected_campus_policy,
            "unexpected nameserver-policy for `{key}`"
        );
    }
    // User-defined `+.lan` takes precedence; raw IP and non-domain/comma rules are excluded.
    assert_eq!(seq_to_vec(&policy["+.lan"]), vec!["10.0.0.53".to_string()]);
    assert!(policy.get("172.28.255.155").is_none());
    assert!(policy.get("ip-cidr,10.0.0.0/8,direct,no-resolve").is_none());
    assert!(policy.get("domain-suffix,rule-campus.example.org,direct").is_none());

    // 2. Empty arrays & legacy plaintext default_nameserver fall back to 4-endpoint encrypted pool.
    let mut cfg_empty = AppConfig::default();
    cfg_empty.dns.respect_rules = true;
    cfg_empty.dns.default_nameserver = vec!["223.5.5.5".to_string(), "119.29.29.29".to_string()];
    cfg_empty.dns.direct_nameserver.clear();
    cfg_empty.dns.proxy_server_nameserver.clear();
    let compiled_legacy_fallback = compile_mihomo_config(&CompileInput {
        config: &cfg_empty,
        nodes: &nodes,
        groups: &[],
        relays: &[],
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    })
    .expect("compile legacy fallback");
    assert_eq!(
        seq_to_vec(&compiled_legacy_fallback.value["dns"]["direct-nameserver"]),
        expected_encrypted_direct
    );
    assert_eq!(
        seq_to_vec(&compiled_legacy_fallback.value["dns"]["proxy-server-nameserver"]),
        expected_encrypted
    );

    // 3. Empty default_nameserver gets 4-endpoint encrypted fallback; custom non-legacy default_nameserver
    //    is reused by empty proxy-server-nameserver without appending `#DIRECT`.
    let mut cfg_custom_default = AppConfig::default();
    cfg_custom_default.dns.respect_rules = true;
    cfg_custom_default.dns.default_nameserver = vec!["https://1.12.12.12/dns-query".to_string()];
    cfg_custom_default.dns.proxy_server_nameserver.clear();
    let compiled_custom_default = compile_mihomo_config(&CompileInput {
        config: &cfg_custom_default,
        nodes: &nodes,
        groups: &[],
        relays: &[],
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    })
    .expect("compile custom default");
    assert_eq!(
        seq_to_vec(&compiled_custom_default.value["dns"]["proxy-server-nameserver"]),
        vec!["https://1.12.12.12/dns-query".to_string()]
    );

    let mut cfg_blank_default = AppConfig::default();
    cfg_blank_default.dns.respect_rules = false;
    cfg_blank_default.dns.default_nameserver.clear();
    let compiled_blank_default = compile_mihomo_config(&CompileInput {
        config: &cfg_blank_default,
        nodes: &nodes,
        groups: &[],
        relays: &[],
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    })
    .expect("compile blank default with respect_rules=false");
    assert_eq!(
        seq_to_vec(&compiled_blank_default.value["dns"]["default-nameserver"]),
        expected_encrypted
    );
    assert_eq!(
        seq_to_vec(&compiled_blank_default.value["dns"]["nameserver-policy"]["+.edu.cn"]),
        vec![
            "system".to_string(),
            "https://223.5.5.5/dns-query".to_string(),
            "https://1.12.12.12/dns-query".to_string(),
        ]
    );
}

#[test]
fn multi_cloud_preaccel_compiles_two_layer_nested_lb_and_rejects_direct_in_lb() {
    let mut cfg = AppConfig::default();
    cfg.preaccel.enabled = true;
    cfg.preaccel.auto_failover = true;
    cfg.preaccel.active_relay_id = None;
    cfg.preaccel.dispatch_strategy = crate::models::PreAccelDispatchStrategy::Auto;
    cfg.preaccel.lb_strategy = crate::models::PreAccelLbStrategy::RoundRobin;

    let relay_a_tcp = sample_relay("r-a-tcp", "CloudA-AnyTLS", "203.0.113.10", 10);
    let mut relay_a_udp = sample_relay("r-a-udp", "CloudA-HY2", "203.0.113.10", 20);
    relay_a_udp.protocol = "hysteria2".to_string();
    let mut relay_b_tcp = sample_relay("r-b-tcp", "CloudB-VLESS", "198.51.100.20", 30);
    relay_b_tcp.protocol = "vless".to_string();
    relay_b_tcp.password = "11111111-2222-4333-8444-555555555555".to_string();

    let relays = vec![relay_a_tcp, relay_a_udp, relay_b_tcp];
    let nodes = vec![sample_node("n1", "JP-8443", 8443, false)];
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
    .expect("compile multi-cloud nested lb");
    assert!(compiled.validation.ok, "issues: {:?}", compiled.validation.issues);

    let groups = compiled.value["proxy-groups"].as_sequence().unwrap();
    let lb_group = groups
        .iter()
        .find(|g| g["name"] == PREACCEL_LB_GROUP_NAME)
        .expect("inner preaccel lb group");
    assert_eq!(lb_group["type"], "load-balance");
    assert_eq!(lb_group["strategy"], "round-robin");
    assert_eq!(lb_group["lazy"], Value::Bool(false));
    let lb_members: Vec<&str> = lb_group["proxies"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(lb_members, vec!["CloudA-AnyTLS", "CloudB-VLESS"]);
    assert!(!lb_members.contains(&"DIRECT"));

    let fb_group = groups
        .iter()
        .find(|g| g["name"] == PREACCEL_FALLBACK_GROUP_NAME)
        .expect("outer preaccel fallback group");
    assert_eq!(fb_group["type"], "fallback");
    let fb_members: Vec<&str> = fb_group["proxies"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        fb_members,
        vec![PREACCEL_LB_GROUP_NAME, "CloudA-HY2", "DIRECT"]
    );

    // Static validator must reject any preaccel load-balance group containing DIRECT.
    let bad_yaml = format!(
        r#"
proxies:
  - name: Relay-A
    type: anytls
    server: 203.0.113.10
    port: 443
    password: secret
proxy-groups:
  - name: "{PREACCEL_LB_GROUP_NAME}"
    type: load-balance
    strategy: round-robin
    url: http://connectivitycheck.platform.hicloud.com/generate_204
    interval: 15
    lazy: false
    proxies:
      - Relay-A
      - DIRECT
rules:
  - IP-CIDR,203.0.113.10/32,DIRECT,no-resolve
  - MATCH,DIRECT
"#
    );
    let report = validate_compiled_yaml(&bad_yaml, &["203.0.113.10".to_string()]).unwrap();
    assert!(!report.ok);
    assert!(report
        .issues
        .iter()
        .any(|i| i.code == "preaccel_lb_contains_direct"));
}

#[test]
fn preaccel_skips_ipv6_only_nodes_preserves_dual_stack_and_honors_override_and_relay_ipv6() {
    let mut cfg = AppConfig::default();
    cfg.preaccel.enabled = true;
    cfg.preaccel.skip_443_native = true;

    let mut ipv6_only = sample_node("n-v6-only", "HK-IPv6-Only", 8443, false);
    ipv6_only.server = "2001:db8::10".to_string();
    ipv6_only.raw_config["server"] = serde_json::json!("2001:db8::10");

    let mut dual_stack = sample_node("n-dual", "HK-01-IPv6", 8443, false);
    dual_stack.server = "hk01.example.invalid".to_string();

    let mut ipv6_forced = sample_node("n-v6-force", "US-纯IPv6-Forced", 8443, false);
    ipv6_forced.server = "2001:db8::20".to_string();
    ipv6_forced.raw_config["server"] = serde_json::json!("2001:db8::20");
    ipv6_forced.preaccel_override = Some(true);

    let relay_v4 = sample_relay("r-v4", "Relay-V4", "203.0.113.10", 10);
    let nodes = vec![ipv6_only.clone(), dual_stack.clone(), ipv6_forced.clone()];
    let ports = sample_ports();
    let empty = HashMap::new();

    let compiled_v4 = compile_mihomo_config(&CompileInput {
        config: &cfg,
        nodes: &nodes,
        groups: &[],
        relays: &[relay_v4.clone()],
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    })
    .expect("compile with ipv4 relay");
    assert_eq!(compiled_v4.stats.skipped_ipv6_proxies, 1);
    assert_eq!(compiled_v4.stats.dialer_wrapped_proxies, 2);

    let proxies = compiled_v4.value["proxies"].as_sequence().unwrap();
    let p_v6 = proxies.iter().find(|p| p["name"] == "HK-IPv6-Only").unwrap();
    assert!(p_v6.get("dialer-proxy").is_none());
    let p_dual = proxies.iter().find(|p| p["name"] == "HK-01-IPv6").unwrap();
    assert_eq!(p_dual["dialer-proxy"], PREACCEL_SELECT_GROUP_NAME);
    let p_forced = proxies.iter().find(|p| p["name"] == "US-纯IPv6-Forced").unwrap();
    assert_eq!(p_forced["dialer-proxy"], PREACCEL_SELECT_GROUP_NAME);

    // Mixed multi-cloud pool (1 IPv4-only + 1 dual-stack) must still skip IPv6-only nodes
    // to avoid 50% blackhole routing through the IPv4-only relay.
    let mut relay_v6 = relay_v4.clone();
    relay_v6.id = "r-v6".to_string();
    relay_v6.name = "Relay-V6".to_string();
    relay_v6.server = "198.51.100.20".to_string();
    relay_v6.priority = 20;
    relay_v6.supports_ipv6 = true;
    let compiled_mixed = compile_mihomo_config(&CompileInput {
        config: &cfg,
        nodes: &nodes,
        groups: &[],
        relays: &[relay_v4.clone(), relay_v6.clone()],
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    })
    .expect("compile with mixed ipv4+ipv6 relay pool");
    assert_eq!(compiled_mixed.stats.skipped_ipv6_proxies, 1);
    assert_eq!(compiled_mixed.stats.dialer_wrapped_proxies, 2);
    let mixed_proxies = compiled_mixed.value["proxies"].as_sequence().unwrap();
    let mixed_v6 = mixed_proxies
        .iter()
        .find(|p| p["name"] == "HK-IPv6-Only")
        .unwrap();
    assert!(mixed_v6.get("dialer-proxy").is_none());

    // Only when every enabled relay declares supports_ipv6=true are IPv6-only nodes wrapped.
    let mut relay_v4_upgraded = relay_v4;
    relay_v4_upgraded.supports_ipv6 = true;
    let compiled_v6 = compile_mihomo_config(&CompileInput {
        config: &cfg,
        nodes: &nodes,
        groups: &[],
        relays: &[relay_v4_upgraded, relay_v6],
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    })
    .expect("compile with all-ipv6 relay pool");
    assert_eq!(compiled_v6.stats.skipped_ipv6_proxies, 0);
    assert_eq!(compiled_v6.stats.dialer_wrapped_proxies, 3);
}

#[test]
fn reserved_builtin_and_preaccel_group_names_prevent_relay_name_collisions() {
    let mut cfg = AppConfig::default();
    cfg.preaccel.enabled = true;
    cfg.preaccel.auto_failover = true;
    cfg.preaccel.active_relay_id = None;
    cfg.preaccel.dispatch_strategy = crate::models::PreAccelDispatchStrategy::Auto;

    let relay_direct = sample_relay("r-direct", "DIRECT", "203.0.113.10", 10);
    let relay_lb = sample_relay("r-lb", PREACCEL_LB_GROUP_NAME, "198.51.100.20", 20);
    let node_reject = sample_node("n-rej", "REJECT", 8443, false);
    let ports = sample_ports();
    let empty = HashMap::new();

    let compiled = compile_mihomo_config(&CompileInput {
        config: &cfg,
        nodes: &[node_reject],
        groups: &[],
        relays: &[relay_direct, relay_lb],
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    })
    .expect("compile with reserved-name relays and nodes");
    assert!(compiled.validation.ok, "issues: {:?}", compiled.validation.issues);

    let proxies = compiled.value["proxies"].as_sequence().unwrap();
    let proxy_names: Vec<&str> = proxies
        .iter()
        .filter_map(|p| p["name"].as_str())
        .collect();
    assert!(!proxy_names.contains(&"DIRECT"));
    assert!(!proxy_names.contains(&"REJECT"));
    assert!(!proxy_names.contains(&PREACCEL_LB_GROUP_NAME));
    assert!(proxy_names.contains(&"DIRECT (2)"));
    assert!(proxy_names.contains(&"REJECT (2)"));

    let groups = compiled.value["proxy-groups"].as_sequence().unwrap();
    let lb_group = groups
        .iter()
        .find(|g| g["name"] == PREACCEL_LB_GROUP_NAME)
        .expect("preaccel lb group");
    let lb_members: Vec<&str> = lb_group["proxies"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(lb_members.len(), 2);
    assert!(lb_members.contains(&"DIRECT (2)"));
    assert!(!lb_members.contains(&"DIRECT"));
}

#[test]
fn stage26_domestic_direct_fake_ip_filter_and_wsf_ai_dns_policies_are_complete() {
    let cfg = AppConfig::default();
    let ports = sample_ports();
    let nodes = vec![sample_node("n1", "Node-JP-01", 443, true)];
    let group = MultiGroup {
        id: "g-jp".to_string(),
        name: "AI (日本)".to_string(),
        match_rules: vec![
            "AND,((PROCESS-NAME,QQ.exe),(DST-PORT,15000)),DIRECT".to_string(),
            r"DOMAIN-REGEX,^a{1,3}\.com$".to_string(),
        ],
        member_node_ids: vec!["n1".to_string()],
        ..Default::default()
    };
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
    .expect("compile ok");
    assert!(
        compiled.validation.ok,
        "unexpected validation issues: {:?}",
        compiled.validation.issues
    );

    let rules: Vec<&str> = compiled.value["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for dom in ["gtimg.cn", "qcloudimg.com", "tencentcs.com", "tencent-cloud.net"] {
        let expected = format!("DOMAIN-SUFFIX,{dom},DIRECT");
        assert!(
            rules.contains(&expected.as_str()),
            "missing fallback domestic direct rule `{expected}`"
        );
    }
    assert!(rules.contains(&"AND,((PROCESS-NAME,QQ.exe),(DST-PORT,15000)),DIRECT"));
    assert!(rules.contains(&r"DOMAIN-REGEX,^a{1,3}\.com$,AI (日本)"));

    let fake_filters: Vec<&str> = compiled.value["dns"]["fake-ip-filter"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for pat in [
        "+.wechat.com",
        "+.wechatpay.com",
        "+.tenpay.com",
        "+.qcloudimg.com",
        "+.tencentcs.com",
        "+.tencent-cloud.net",
        "ctldl.windowsupdate.com",
    ] {
        assert!(
            fake_filters.contains(&pat),
            "missing fake-ip-filter entry `{pat}`"
        );
    }

    let ns_policy = compiled.value["dns"]["nameserver-policy"]
        .as_mapping()
        .expect("nameserver-policy mapping");
    for ai_dom in [
        "+.windsurf.com",
        "+.codeium.com",
        "+.codeiumdata.com",
        "+.devin.ai",
        "+.cognition.ai",
        "+.exafunction.com",
    ] {
        assert!(
            ns_policy.contains_key(Value::String(ai_dom.to_string())),
            "missing AI DNS policy domain `{ai_dom}`"
        );
    }
}
