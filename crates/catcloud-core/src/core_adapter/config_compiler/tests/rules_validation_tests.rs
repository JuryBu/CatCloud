use super::{sample_node, sample_ports, sample_relay};
use super::super::*;
use super::super::rules::{
    extract_mihomo_rule_raw_target, has_balanced_parens, is_plausible_global_rule,
};
use crate::models::{AppConfig, MultiGroup, MultiGroupMode, OverrideMode};
use serde_yaml_ng::Value;
use std::collections::HashMap;

#[test]
fn yaml_merge_patch_merges_recursively_and_rejects_broken_yaml_without_mutating_base() {
    let base: Value = serde_yaml_ng::from_str(
        r#"
mixed-port: 27890
dns:
  enable: true
  ipv6: false
  prefer-h3: false
"#,
    )
    .unwrap();
    let snapshot = base.clone();

    let patched = apply_yaml_merge_patch(
        &base,
        r#"
dns:
  prefer-h3: true
  ipv6: null
log-level: debug
"#,
    )
    .expect("valid merge patch must succeed");

    assert_eq!(patched["mixed-port"], 27890);
    assert_eq!(patched["dns"]["enable"], Value::Bool(true));
    assert_eq!(patched["dns"]["prefer-h3"], Value::Bool(true));
    assert!(patched["dns"].get("ipv6").is_none());
    assert_eq!(patched["log-level"], "debug");
    assert_eq!(base, snapshot);

    let err = apply_yaml_merge_patch(&base, "dns: [unclosed");
    assert!(err.is_err());
    assert_eq!(base, snapshot);
}

#[test]
fn static_validator_catches_empty_group_gstatic_probe_and_missing_relay_direct() {
    let broken_yaml = format!(
        r#"
proxies:
  - name: Relay-A
    type: anytls
    server: 203.0.113.20
    port: 443
    password: demo
  - name: Node-1
    type: trojan
    server: 203.0.113.55
    port: 8443
    password: demo
    dialer-proxy: "{PREACCEL_SELECT_GROUP_NAME}"
proxy-groups:
  - name: "{PREACCEL_SELECT_GROUP_NAME}"
    type: select
    proxies:
      - "{PREACCEL_FALLBACK_GROUP_NAME}"
  - name: "{PREACCEL_FALLBACK_GROUP_NAME}"
    type: fallback
    url: "https://www.gstatic.com/generate_204"
    proxies:
      - Relay-A
  - name: Empty-Group
    type: select
    proxies: []
rules:
  - MATCH,Empty-Group
"#
    );

    let report = validate_compiled_yaml(&broken_yaml, &["203.0.113.20".to_string()])
        .expect("syntax is valid so report returns findings");
    assert!(!report.ok);

    let codes: Vec<&str> = report.errors().iter().map(|i| i.code.as_str()).collect();
    assert!(codes.contains(&"empty_proxy_group"));
    assert!(codes.contains(&"forbidden_overseas_domestic_probe"));
    assert!(codes.contains(&"missing_relay_direct_rule"));
}

#[test]
fn static_validator_rejects_match_before_relay_direct_and_supports_ipv6_cidr() {
    // Merge patch inserting `MATCH,Proxy` before relay's DIRECT rule must be rejected.
    let shadowed_yaml = format!(
        r#"
proxies:
  - name: Relay-A
    type: anytls
    server: 203.0.113.20
    port: 443
    password: demo
  - name: Node-1
    type: trojan
    server: 203.0.113.55
    port: 8443
    password: demo
    dialer-proxy: "{PREACCEL_SELECT_GROUP_NAME}"
proxy-groups:
  - name: "{PREACCEL_SELECT_GROUP_NAME}"
    type: select
    proxies:
      - "{PREACCEL_FALLBACK_GROUP_NAME}"
  - name: "{PREACCEL_FALLBACK_GROUP_NAME}"
    type: fallback
    url: "https://connectivitycheck.platform.hicloud.com/generate_204"
    proxies:
      - Relay-A
  - name: Proxy
    type: select
    proxies:
      - Node-1
rules:
  - MATCH,Proxy
  - IP-CIDR,203.0.113.20/32,DIRECT,no-resolve
"#
    );

    let report = validate_compiled_yaml(&shadowed_yaml, &["203.0.113.20".to_string()])
        .expect("valid YAML syntax");
    assert!(!report.ok);
    let codes: Vec<&str> = report.errors().iter().map(|i| i.code.as_str()).collect();
    assert!(codes.contains(&"missing_relay_direct_rule"));

    // IPv6 subnet anti-loop rule (`IP-CIDR6,<prefix>/48,DIRECT`) must cover matching relay IPv6.
    let ipv6_subnet_yaml = format!(
        r#"
proxies:
  - name: Relay-V6
    type: anytls
    server: "2001:db8:abcd::42"
    port: 443
    password: demo
  - name: Node-1
    type: trojan
    server: 203.0.113.55
    port: 8443
    password: demo
    dialer-proxy: "{PREACCEL_SELECT_GROUP_NAME}"
proxy-groups:
  - name: "{PREACCEL_SELECT_GROUP_NAME}"
    type: select
    proxies:
      - "{PREACCEL_FALLBACK_GROUP_NAME}"
  - name: "{PREACCEL_FALLBACK_GROUP_NAME}"
    type: fallback
    url: "https://connectivitycheck.platform.hicloud.com/generate_204"
    proxies:
      - Relay-V6
  - name: Proxy
    type: select
    proxies:
      - Node-1
rules:
  - IP-CIDR6,2001:db8:abcd::/48,DIRECT,no-resolve
  - MATCH,Proxy
"#
    );

    let v6_ok = validate_compiled_yaml(&ipv6_subnet_yaml, &["2001:db8:abcd::42".to_string()])
        .expect("valid YAML syntax");
    assert!(v6_ok.ok, "issues: {:?}", v6_ok.issues);

    // Non-matching IPv6 relay outside the `/48` prefix must be rejected.
    let v6_miss =
        validate_compiled_yaml(&ipv6_subnet_yaml, &["2001:db8:9999::42".to_string()])
            .expect("valid YAML syntax");
    assert!(!v6_miss.ok);
    assert!(
        v6_miss
            .errors()
            .iter()
            .any(|i| i.code == "missing_relay_direct_rule")
    );
}

#[test]
fn expand_group_match_rule_sanitizes_malformed_and_bare_domain_entries() {
    // Bare rule types or malformed tokens must be safely dropped instead of breaking `mihomo -t`.
    assert!(expand_group_match_rule("DOMAIN-SUFFIX", "G").is_empty());
    assert!(expand_group_match_rule("  domain-suffix  ", "G").is_empty());
    assert!(expand_group_match_rule("MATCH", "G").is_empty());
    assert!(expand_group_match_rule("MATCH,DIRECT", "G").is_empty());
    assert!(expand_group_match_rule("DOMAIN-SUFFIX,", "G").is_empty());
    assert!(expand_group_match_rule("UNKNOWN-TYPE,anthropic.com", "G").is_empty());
    assert!(expand_group_match_rule("https://anthropic.com/v1", "G").is_empty());

    // Bare valid domains auto-complete to DOMAIN-SUFFIX,<domain>,<group>.
    assert_eq!(
        expand_group_match_rule("anthropic.com", "G"),
        vec!["DOMAIN-SUFFIX,anthropic.com,G".to_string()]
    );
    assert_eq!(
        expand_group_match_rule("*.openai.com", "G"),
        vec!["DOMAIN-SUFFIX,openai.com,G".to_string()]
    );

    // Valid 2-part / 3-part / 4-part rules expand and normalize cleanly.
    assert_eq!(
        expand_group_match_rule("domain-suffix,claude.ai", "G"),
        vec!["DOMAIN-SUFFIX,claude.ai,G".to_string()]
    );
    assert_eq!(
        expand_group_match_rule("IP-CIDR,203.0.113.0/24,no-resolve", "G"),
        vec!["IP-CIDR,203.0.113.0/24,G,no-resolve".to_string()]
    );
    assert_eq!(
        expand_group_match_rule("DOMAIN,example.com,DIRECT", "G"),
        vec!["DOMAIN,example.com,DIRECT".to_string()]
    );

    // Global prepend/append rules also drop bare broken tokens like `"DOMAIN-SUFFIX"`.
    let mut cfg = AppConfig::default();
    cfg.rules_override.global_prepend_rules = vec![
        "DOMAIN-SUFFIX".to_string(),
        "DOMAIN,ok.example,DIRECT".to_string(),
    ];
    cfg.rules_override.global_append_rules = vec!["GEOIP".to_string()];
    let node = sample_node("n1", "Node-JP", 443, true);
    let group = MultiGroup {
        id: "g-ai".to_string(),
        name: "AI".to_string(),
        match_rules: vec!["DOMAIN-SUFFIX".to_string(), "anthropic.com".to_string()],
        member_node_ids: vec!["n1".to_string()],
        ..Default::default()
    };
    let ports = sample_ports();
    let empty = HashMap::new();
    let compiled = compile_mihomo_config(&CompileInput {
        config: &cfg,
        nodes: &[node],
        groups: &[group],
        relays: &[],
        controller_secret: "secret",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    })
    .expect("compile ok");
    let compiled_rules: Vec<&str> = compiled.value["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(!compiled_rules.contains(&"DOMAIN-SUFFIX"));
    assert!(!compiled_rules.contains(&"GEOIP"));
    assert!(compiled_rules.contains(&"DOMAIN,ok.example,DIRECT"));
    assert!(compiled_rules.contains(&"DOMAIN-SUFFIX,anthropic.com,AI"));
}

#[test]
fn supports_logical_and_rules_and_honors_quic_and_domestic_direct_toggles() {
    assert!(is_plausible_global_rule(
        "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"
    ));
    assert!(!is_plausible_global_rule("AND,((NETWORK,UDP),REJECT"));
    assert_eq!(
        expand_group_match_rule("AND,((NETWORK,UDP),(DST-PORT,443)),REJECT", "AI"),
        vec!["AND,((NETWORK,UDP),(DST-PORT,443)),REJECT".to_string()]
    );

    let mut cfg = AppConfig::default();
    cfg.dns.respect_rules = true;
    cfg.dns.proxy_server_nameserver.clear();
    cfg.rules_override.block_quic_udp_443 = false;
    cfg.rules_override.domestic_direct_enabled = false;
    cfg.rules_override
        .global_prepend_rules
        .push("AND,((NETWORK,UDP),(DST-PORT,443)),REJECT".to_string());

    let ports = sample_ports();
    let nodes = vec![sample_node("n1", "Node-JP-01", 443, true)];
    let empty = HashMap::new();
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
    .unwrap();

    // respect_rules == true guarantees non-empty proxy-server-nameserver
    let ps_ns = compiled.value["dns"]["proxy-server-nameserver"]
        .as_sequence()
        .unwrap();
    assert!(!ps_ns.is_empty());

    let rules: Vec<&str> = compiled.value["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    // Explicit user global_prepend_rules logical rule passed through
    assert!(rules.contains(&"AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"));
    // Domestic direct rules disabled
    assert!(!rules.contains(&"DOMAIN-SUFFIX,cn,DIRECT"));
    assert!(!rules.contains(&"DOMAIN-SUFFIX,qq.com,DIRECT"));
}

#[test]
fn extract_mihomo_rule_target_and_static_validator_catch_unknown_rule_targets() {
    // Blank, comment, built-in actions, and SUB-RULE return None.
    assert_eq!(extract_mihomo_rule_target(""), None);
    assert_eq!(extract_mihomo_rule_target("   "), None);
    assert_eq!(extract_mihomo_rule_target("# DOMAIN-SUFFIX,openai.com,AI-Group"), None);
    assert_eq!(extract_mihomo_rule_target("DOMAIN-SUFFIX,cn,DIRECT"), None);
    assert_eq!(extract_mihomo_rule_target("DOMAIN-SUFFIX,cn,direct"), None);
    assert_eq!(extract_mihomo_rule_target("DOMAIN,ad.example,REJECT"), None);
    assert_eq!(extract_mihomo_rule_target("DOMAIN,ad.example,reject-drop"), None);
    assert_eq!(extract_mihomo_rule_target("DOMAIN,ok.example,PASS"), None);
    assert_eq!(extract_mihomo_rule_target("DOMAIN,ok.example,compatible"), None);
    assert_eq!(
        extract_mihomo_rule_target("AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"),
        None
    );
    assert_eq!(
        extract_mihomo_rule_target("SUB-RULE,((DOMAIN,example.com)),sub-chain"),
        None
    );
    assert_eq!(
        extract_mihomo_rule_target("IP-CIDR,198.51.100.0/24,no-resolve"),
        None
    );

    // Standard, flag-suffixed, logical, and MATCH rules extract custom targets accurately.
    assert_eq!(
        extract_mihomo_rule_target("MATCH, AI-Group "),
        Some("AI-Group")
    );
    assert_eq!(
        extract_mihomo_rule_target("DOMAIN-SUFFIX, openai.com , AI-Group"),
        Some("AI-Group")
    );
    assert_eq!(
        extract_mihomo_rule_target("IP-CIDR,198.51.100.0/24,AI-Group,no-resolve"),
        Some("AI-Group")
    );
    assert_eq!(
        extract_mihomo_rule_target("IP-CIDR,198.51.100.0/24,AI-Group,src"),
        Some("AI-Group")
    );
    assert_eq!(
        extract_mihomo_rule_target("IP-CIDR,198.51.100.0/24,AI-Group,no-resolve,src"),
        Some("AI-Group")
    );
    assert_eq!(
        extract_mihomo_rule_target("AND,((NETWORK,TCP),(DST-PORT,443)),AI-Group"),
        Some("AI-Group")
    );

    // Static validator rejects rules referencing missing proxy-groups while accepting proxies,
    // proxy-groups, and built-in actions.
    let yaml_with_missing_target = r#"
proxies:
  - name: Node-1
    type: trojan
    server: 203.0.113.55
    port: 443
    password: demo
proxy-groups:
  - name: Main-Group
    type: select
    proxies:
      - Node-1
rules:
  - DOMAIN-SUFFIX,openai.com,Missing-Group
  - IP-CIDR,198.51.100.0/24,Node-1,no-resolve
  - DOMAIN,ads.example,REJECT-DROP
  - MATCH,Main-Group
"#;
    let report_bad = validate_compiled_yaml(yaml_with_missing_target, &[]).unwrap();
    assert!(!report_bad.ok);
    let unknown_errors: Vec<&StaticCheckIssue> = report_bad
        .errors()
        .into_iter()
        .filter(|i| i.code == "unknown_rule_target")
        .collect();
    assert_eq!(unknown_errors.len(), 1);
    assert!(unknown_errors[0].message.contains("Missing-Group"));

    let yaml_valid = r#"
proxies:
  - name: Node-1
    type: trojan
    server: 203.0.113.55
    port: 443
    password: demo
proxy-groups:
  - name: Main-Group
    type: select
    proxies:
      - Node-1
rules:
  - IP-CIDR,198.51.100.0/24,Node-1,no-resolve
  - DOMAIN,ads.example,REJECT-DROP
  - DOMAIN,pass.example,PASS
  - DOMAIN,compat.example,COMPATIBLE
  - MATCH,Main-Group
"#;
    let report_ok = validate_compiled_yaml(yaml_valid, &[]).unwrap();
    assert!(report_ok.ok, "unexpected issues: {:?}", report_ok.issues);
}

#[test]
fn custom_rules_only_skips_builtin_rules_and_ai_dns_while_respecting_user_match() {
    let mut cfg = AppConfig::default();
    cfg.preaccel.enabled = true;
    cfg.rules_override.custom_rules_only = true;
    cfg.rules_override.block_quic_udp_443 = true;
    cfg.rules_override.domestic_direct_enabled = true;
    cfg.rules_override.global_prepend_rules = vec![
        "DOMAIN-SUFFIX,custom-direct.test,DIRECT".to_string(),
    ];
    cfg.rules_override.global_append_rules = vec![
        "DOMAIN-SUFFIX,custom-proxy.test,AI-Sticky".to_string(),
        "MATCH,DIRECT".to_string(),
    ];
    cfg.dns
        .nameserver_policy
        .insert("+.mycorp.internal".to_string(), vec!["10.0.0.53".to_string()]);

    let nodes = vec![sample_node("n1", "Node-JP-01", 8443, false)];
    let groups = vec![MultiGroup {
        id: "g-ai".to_string(),
        name: "AI-Sticky".to_string(),
        mode: MultiGroupMode::StickyBest,
        match_rules: vec!["@ai_domains".to_string()],
        member_node_ids: vec!["n1".to_string()],
        active_node_id: Some("n1".to_string()),
        independent_routing: true,
        ..Default::default()
    }];
    let relays = vec![sample_relay("r1", "Relay-East", "203.0.113.10", 10)];
    let extra = vec!["DOMAIN,extra-prepend.test,DIRECT".to_string()];
    let ports = sample_ports();
    let empty = HashMap::new();

    let compiled = compile_mihomo_config(&CompileInput {
        config: &cfg,
        nodes: &nodes,
        groups: &groups,
        relays: &relays,
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &extra,
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    })
    .expect("compile custom_rules_only with explicit MATCH");
    assert!(compiled.validation.ok, "issues: {:?}", compiled.validation.issues);

    let rules: Vec<&str> = compiled.value["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();

    // Mandatory anti-loop, probe process bypass, private LAN direct, and user rules are preserved.
    assert!(rules.contains(&"IP-CIDR,203.0.113.10/32,DIRECT,no-resolve"));
    assert!(rules.iter().any(|r| r.starts_with("PROCESS-NAME,") && r.ends_with(",DIRECT")));
    assert!(rules.contains(&"IP-CIDR,192.168.0.0/16,DIRECT,no-resolve"));
    assert!(rules.contains(&"DOMAIN,extra-prepend.test,DIRECT"));
    assert!(rules.contains(&"DOMAIN-SUFFIX,custom-direct.test,DIRECT"));
    assert!(rules.contains(&"DOMAIN-SUFFIX,custom-proxy.test,AI-Sticky"));

    // Built-in QUIC block, group auto match_rules, and built-in domestic direct lists are skipped.
    assert!(!rules.contains(&"AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"));
    assert!(!rules.iter().any(|r| r.contains("openai.com")));
    assert!(!rules.contains(&"DOMAIN-SUFFIX,cn,DIRECT"));
    assert!(!rules.contains(&"DOMAIN-SUFFIX,baidu.com,DIRECT"));
    assert!(!rules.contains(&"GEOSITE,cn,DIRECT"));
    assert!(!rules.contains(&"GEOIP,CN,DIRECT,no-resolve"));

    // User's own `MATCH,DIRECT` is respected 100% (no duplicate `MATCH,AI-Sticky` appended).
    let match_rules: Vec<&&str> = rules
        .iter()
        .filter(|r| r.to_ascii_uppercase().starts_with("MATCH,"))
        .collect();
    assert_eq!(match_rules, vec![&"MATCH,DIRECT"]);

    // Built-in `AI_DNS_POLICY_DOMAINS` are NOT injected when `custom_rules_only == true`,
    // while user `nameserver_policy` and intranet anti-loop remain intact.
    let policy = compiled.value["dns"]["nameserver-policy"].as_mapping().unwrap();
    assert!(policy.get("+.mycorp.internal").is_some());
    assert!(policy.get("+.edu.cn").is_some());
    assert!(policy.get("+.openai.com").is_none());
    assert!(policy.get("+.anthropic.com").is_none());

    // When user omits `MATCH,...`, compiler appends fallback `MATCH,{match_target}` automatically.
    cfg.rules_override.global_append_rules =
        vec!["DOMAIN-SUFFIX,custom-proxy.test,AI-Sticky".to_string()];
    let compiled_fallback = compile_mihomo_config(&CompileInput {
        config: &cfg,
        nodes: &nodes,
        groups: &groups,
        relays: &relays,
        controller_secret: "0123456789abcdef0123456789abcdef",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    })
    .expect("compile custom_rules_only without explicit MATCH");
    let rules_fb: Vec<&str> = compiled_fallback.value["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(rules_fb.last().copied(), Some("MATCH,AI-Sticky"));
}

#[test]
fn inline_override_yaml_injects_rule_providers_validates_rule_set_and_rejects_invalid_yaml() {
    let mut cfg = AppConfig::default();
    // Verify inline YAML merge patch runs even when `override_mode == OverrideMode::Disabled`.
    cfg.rules_override.override_mode = OverrideMode::Disabled;
    cfg.rules_override.global_prepend_rules = vec![
        "RULE-SET,custom_direct,DIRECT".to_string(),
        "RULE-SET,missing_set,DIRECT".to_string(),
    ];
    cfg.rules_override.inline_override_yaml = Some(
        r#"
rule-providers:
  custom_direct:
    type: http
    behavior: domain
    url: https://example.invalid/direct.yaml
    path: ./ruleset/custom_direct.yaml
    interval: 86400
"#
        .to_string(),
    );

    let nodes = vec![sample_node("n1", "Node-SG-01", 8443, false)];
    let ports = sample_ports();
    let empty = HashMap::new();

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
    .expect("compile with inline rule-providers override");
    assert!(compiled.validation.ok, "RULE-SET warnings must not fail validation");
    assert!(compiled.value["rule-providers"]["custom_direct"].is_mapping());

    let warnings = compiled.validation.warnings();
    assert!(
        warnings
            .iter()
            .any(|w| w.code == "missing_rule_provider" && w.message.contains("missing_set")),
        "expected missing_rule_provider warning for `missing_set`, got: {warnings:?}"
    );
    assert!(
        !warnings
            .iter()
            .any(|w| w.code == "missing_rule_provider" && w.message.contains("custom_direct")),
        "defined provider `custom_direct` must not trigger warning"
    );

    // Invalid YAML must be rejected cleanly with a Chinese diagnostic without panicking.
    cfg.rules_override.inline_override_yaml = Some("rule-providers: [\n  unclosed".to_string());
    let err = compile_mihomo_config(&CompileInput {
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
    .expect_err("malformed inline YAML must fail");
    let msg = err.to_string();
    assert!(msg.contains("内联 YAML"), "unexpected error: {msg}");

    // Oversized (> 1 MiB) inline YAML must be rejected cleanly.
    cfg.rules_override.inline_override_yaml = Some(format!(
        "rules:\n  - {}\n",
        "x".repeat(crate::models::MAX_INLINE_OVERRIDE_YAML_BYTES + 32)
    ));
    let err_oversized = compile_mihomo_config(&CompileInput {
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
    .expect_err("oversized inline YAML must fail");
    assert!(err_oversized.to_string().contains("1 MiB"));
}

#[test]
fn parse_bulk_rules_text_handles_yaml_bullets_quotes_comments_and_complex_rules() {
    let raw = r#"
# Top comment should be skipped
rules: # header comment

  - 'DOMAIN-SUFFIX,openai.com,AI-Group' # inline comment
  - "RULE-SET,private_cn,DIRECT" # provider rule
  - GEOSITE,cn,DIRECT
  - GEOIP,CN,DIRECT,no-resolve # geoip comment
  - AND,((NETWORK,UDP),(DST-PORT,443)),REJECT # quic block
  - OR,((DOMAIN-SUFFIX,a.test),(GEOIP,CN,no-resolve)),PROXY
  - AND,((NETWORK,UDP),(DST-PORT,443)),REJECT,no-resolve
  - NOT,((DST-PORT,80)),DIRECT
  - SUB-RULE,(NETWORK,TCP),sub-tcp-rules
  - DOMAIN-SUFFIX,openai.com,AI-Group
  - MATCH,DIRECT
  - INVALID-TYPE,foo,DIRECT
  - broken-line-without-comma
"#;

    let parsed = parse_bulk_rules_text(raw);
    assert_eq!(
        parsed.valid_rules,
        vec![
            "DOMAIN-SUFFIX,openai.com,AI-Group",
            "RULE-SET,private_cn,DIRECT",
            "GEOSITE,cn,DIRECT",
            "GEOIP,CN,DIRECT,no-resolve",
            "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT",
            "OR,((DOMAIN-SUFFIX,a.test),(GEOIP,CN,no-resolve)),PROXY",
            "NOT,((DST-PORT,80)),DIRECT",
            "SUB-RULE,(NETWORK,TCP),sub-tcp-rules",
            "MATCH,DIRECT",
        ]
    );
    assert_eq!(
        parsed.skipped_lines,
        vec![
            "- AND,((NETWORK,UDP),(DST-PORT,443)),REJECT,no-resolve",
            "- INVALID-TYPE,foo,DIRECT",
            "- broken-line-without-comma",
        ]
    );
}

#[test]
fn match_rule_whitespace_is_normalized_without_duplicate_match() {
    assert!(is_match_rule("MATCH,DIRECT"));
    assert!(is_match_rule("MATCH , DIRECT"));
    assert!(is_match_rule("  match , AI-Group  "));
    assert!(!is_match_rule("MATCH,"));
    assert!(!is_match_rule("MATCH,A,B"));
    assert!(!is_match_rule("DOMAIN-SUFFIX,example.com,DIRECT"));

    let bulk = parse_bulk_rules_text("  - 'MATCH , DIRECT'\n  - MATCH,DIRECT\n");
    assert_eq!(bulk.valid_rules, vec!["MATCH,DIRECT".to_string()]);
    assert!(bulk.skipped_lines.is_empty());

    let mut cfg = AppConfig::default();
    cfg.rules_override.custom_rules_only = true;
    cfg.rules_override.global_append_rules = vec!["MATCH , DIRECT".to_string()];
    let nodes = vec![sample_node("n1", "Node-JP-01", 8443, false)];
    let ports = sample_ports();
    let empty = HashMap::new();

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
    .expect("compile with spaced MATCH");
    let rules: Vec<&str> = compiled.value["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let match_rules: Vec<&str> = rules.iter().copied().filter(|r| is_match_rule(r)).collect();
    assert_eq!(match_rules, vec!["MATCH,DIRECT"]);
    assert!(
        !compiled
            .validation
            .warnings()
            .iter()
            .any(|w| w.code == "missing_match_rule")
    );
}

#[test]
fn stage26_composite_and_regex_rule_parsing_matches_mihomo_real_grammar() {
    // 1. `has_balanced_parens` rejects juxtaposed `(A),(B)` where depth hits 0 before end.
    assert!(has_balanced_parens("((NETWORK,UDP),(DST-PORT,443))"));
    assert!(!has_balanced_parens("(NETWORK,UDP),(DST-PORT,443)"));
    assert!(!has_balanced_parens("((NETWORK,UDP),(DST-PORT,443)"));

    // 2. Logical rules with parenthesized or asymmetric target names (`AI (日本)`, `Node (2)`, `Node :)`).
    let rule_jp = "AND,((PROCESS-NAME,QQ.exe),(DST-PORT,15000)),AI (日本)";
    let rule_smile = "AND,((NETWORK,TCP),(DST-PORT,443)),Node :)";
    let rule_direct = "AND,((PROCESS-NAME,QQ.exe),(DST-PORT,15000)),DIRECT";
    assert!(is_plausible_global_rule(rule_jp));
    assert!(is_plausible_global_rule(rule_smile));
    assert!(is_plausible_global_rule(rule_direct));
    assert_eq!(extract_mihomo_rule_target(rule_jp), Some("AI (日本)"));
    assert_eq!(extract_mihomo_rule_target(rule_smile), Some("Node :)"));
    assert_eq!(extract_mihomo_rule_target(rule_direct), None);
    assert_eq!(
        rewrite_mihomo_rule_target(rule_jp, "Node (2)").as_deref(),
        Some("AND,((PROCESS-NAME,QQ.exe),(DST-PORT,15000)),Node (2)")
    );
    assert_eq!(
        rewrite_mihomo_rule_target(rule_smile, "AI (日本)").as_deref(),
        Some("AND,((NETWORK,TCP),(DST-PORT,443)),AI (日本)")
    );
    assert_eq!(
        expand_group_match_rule("AND,((PROCESS-NAME,QQ.exe),(DST-PORT,15000))", "AI (日本)"),
        vec!["AND,((PROCESS-NAME,QQ.exe),(DST-PORT,15000)),AI (日本)".to_string()]
    );
    assert_eq!(
        expand_group_match_rule(rule_jp, "Other"),
        vec![rule_jp.to_string()]
    );

    // 3. Invalid juxtaposed parens, single-layer NOT, empty AND, and top-level trailing flags
    //    must all be rejected so they never break `mihomo -t`.
    for invalid in [
        "AND,(NETWORK,UDP),(DST-PORT,443),DIRECT",
        "AND,((NETWORK,UDP),(DST-PORT,443)),DIRECT,no-resolve",
        "AND,((NETWORK,UDP),(DST-PORT,443)),DIRECT,src",
        "AND,((NETWORK,UDP),(DST-PORT,443)),no-resolve",
        "AND,(),DIRECT",
        "AND,((DOMAIN,a.com),()),DIRECT",
        "NOT,(DOMAIN,a.com),DIRECT",
    ] {
        assert!(
            !is_plausible_global_rule(invalid),
            "expected invalid global rule to be rejected: {invalid}"
        );
        assert_eq!(
            extract_mihomo_rule_raw_target(invalid),
            None,
            "expected raw target None for invalid rule: {invalid}"
        );
        assert_eq!(
            rewrite_mihomo_rule_target(invalid, "AI"),
            None,
            "expected rewrite None for invalid rule: {invalid}"
        );
        assert!(
            expand_group_match_rule(invalid, "AI").is_empty(),
            "expected expand_group_match_rule empty for invalid rule: {invalid}"
        );
    }

    // Sub-clause `no-resolve` inside double parens remains valid!
    let valid_inner_flag = "AND,((NETWORK,UDP),(DST-PORT,443),(GEOIP,CN,no-resolve)),DIRECT";
    assert!(is_plausible_global_rule(valid_inner_flag));
    assert_eq!(
        expand_group_match_rule(valid_inner_flag, "AI"),
        vec![valid_inner_flag.to_string()]
    );

    // 4. `*-REGEX` rules preserve commas inside `{1,3}` quantifiers and escaped `\(bar` parens.
    let regex_global = r"DOMAIN-REGEX,^a{1,3}\.com$,DIRECT";
    let regex_paren_escaped = r"PROCESS-NAME-REGEX,foo\(bar,AI (日本)";
    assert!(is_plausible_global_rule(regex_global));
    assert!(is_plausible_global_rule(regex_paren_escaped));
    assert_eq!(extract_mihomo_rule_raw_target(regex_global), Some("DIRECT"));
    assert_eq!(extract_mihomo_rule_target(regex_global), None);
    assert_eq!(
        extract_mihomo_rule_target(regex_paren_escaped),
        Some("AI (日本)")
    );
    assert_eq!(
        rewrite_mihomo_rule_target(regex_paren_escaped, "Node (2)").as_deref(),
        Some(r"PROCESS-NAME-REGEX,foo\(bar,Node (2)")
    );
    // Group match_rules with `{1,3}` quantifier and no target must append `,group_name` intact!
    assert_eq!(
        expand_group_match_rule(r"DOMAIN-REGEX,^a{1,3}\.com$", "AI (日本)"),
        vec![r"DOMAIN-REGEX,^a{1,3}\.com$,AI (日本)".to_string()]
    );
    assert_eq!(
        expand_group_match_rule(regex_global, "AI (日本)"),
        vec![regex_global.to_string()]
    );
    assert_eq!(
        expand_group_match_rule(r"DOMAIN-REGEX,^a{1,3}\.com$,AI (日本)", "AI (日本)"),
        vec![r"DOMAIN-REGEX,^a{1,3}\.com$,AI (日本)".to_string()]
    );

    // 5. `SUB-RULE` allows single-layer parens and MUST keep returning `None` for target
    //    extraction and rewriting to avoid false-positive `unknown_rule_target` errors.
    let sub_single = "SUB-RULE,(NETWORK,TCP),sub-tcp";
    let sub_double = "SUB-RULE,((DOMAIN,example.com)),sub-chain";
    assert!(is_plausible_global_rule(sub_single));
    assert!(is_plausible_global_rule(sub_double));
    assert_eq!(extract_mihomo_rule_raw_target(sub_single), None);
    assert_eq!(extract_mihomo_rule_target(sub_single), None);
    assert_eq!(rewrite_mihomo_rule_target(sub_single, "AI"), None);
    assert_eq!(extract_mihomo_rule_raw_target(sub_double), None);
    assert_eq!(rewrite_mihomo_rule_target(sub_double, "AI"), None);
}
