use super::{sample_node, sample_ports, sample_relay};
use super::super::*;
use crate::models::{AppConfig, MultiGroup, MultiGroupMode, ProxyMode, ProxyNode, RouteTargetMode};
use serde_yaml_ng::{Number, Value};
use std::collections::HashMap;

#[test]
fn redact_compiled_yaml_for_preview_delegates_to_unified_sanitizer() {
    let mut cfg = AppConfig::default();
    cfg.preaccel.enabled = true;
    let relay = sample_relay("r-sec", "Relay-Secret", "203.0.113.55", 10);
    let node = sample_node("n-sec", "JP-Secret", 8443, false);
    let ports = sample_ports();
    let empty = HashMap::new();

    let compiled = compile_mihomo_config(&CompileInput {
        config: &cfg,
        nodes: &[node],
        groups: &[],
        relays: &[relay.clone()],
        controller_secret: "super-secret-controller-token-9999",
        allocated_ports: &ports,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty,
    })
    .expect("compile secret yaml");

    let redacted = redact_compiled_yaml_for_preview(&compiled, &[relay]).expect("redact yaml");
    assert!(!redacted.contains("relay-password"));
    assert!(!redacted.contains("super-secret-controller-token-9999"));
    assert!(!redacted.contains("203.0.113.55"));
    assert_eq!(redacted, crate::sanitize::redact_compiled_yaml(&compiled.yaml));
}

#[test]
fn export_gateway_yaml_covers_all_three_profiles_redaction_ports_and_disables_tun() {
    let mut cfg = AppConfig::default();
    cfg.preaccel.enabled = true;
    cfg.tun.enabled = true;
    cfg.controller_secret = Some("gw-test-controller-secret-12345".to_string());
    cfg.rules_override.custom_rules_only = true;
    cfg.rules_override.global_prepend_rules = vec![
        "RULE-SET,lan_direct,DIRECT".to_string(),
        "DOMAIN-SUFFIX,corp.example.test,DIRECT".to_string(),
    ];
    cfg.rules_override.inline_override_yaml = Some(
        "rule-providers:\n  lan_direct:\n    type: http\n    behavior: domain\n    url: https://example.invalid/lan.yaml\n    path: ./ruleset/lan.yaml\n"
            .to_string(),
    );

    let relays = vec![
        sample_relay("r1", "CloudA-443", "203.0.113.10", 10),
        sample_relay("r2", "CloudB-443", "198.51.100.20", 20),
    ];
    let nodes = vec![
        sample_node("n1", "Node-JP-8443", 8443, false),
        sample_node("n2", "Node-SG-443", 443, true),
    ];
    let groups = vec![MultiGroup {
        id: "g1".to_string(),
        name: "Main-Group".to_string(),
        mode: MultiGroupMode::StickyBest,
        member_node_ids: vec!["n2".to_string(), "n1".to_string()],
        active_node_id: Some("n1".to_string()),
        ..Default::default()
    }];

    // 1. RelayFragment: redacted vs plaintext + empty relays friendly fallback
    let frag_redacted = export_gateway_yaml(
        &cfg,
        &nodes,
        &groups,
        &relays,
        None,
        &GatewayExportOptions {
            profile: GatewayExportProfile::RelayFragment,
            redact_secrets: true,
            ..GatewayExportOptions::default()
        },
    )
    .expect("export relay fragment redacted");
    assert!(frag_redacted.redacted);
    assert_eq!(frag_redacted.relay_count, 2);
    assert_eq!(frag_redacted.node_count, 0);
    assert!(frag_redacted.rule_count >= 2);
    assert!(frag_redacted.yaml.contains(&format!("dialer-proxy: {PREACCEL_SELECT_GROUP_NAME}")));
    assert!(!frag_redacted.yaml.contains("relay-password"));
    assert!(!frag_redacted.yaml.contains("203.0.113.10"));
    let frag_val: Value =
        serde_yaml_ng::from_str(&frag_redacted.yaml).expect("redacted relay fragment valid YAML");
    let first_relay = &frag_val["proxies"][0];
    assert_eq!(first_relay["tfo"], Value::Bool(false));
    assert_eq!(first_relay["min-idle-session"], Value::Number(Number::from(0u64)));
    assert!(frag_val["dns"]["fake-ip-filter"].is_sequence());

    let frag_plain = export_gateway_yaml(
        &cfg,
        &nodes,
        &groups,
        &relays,
        None,
        &GatewayExportOptions {
            profile: GatewayExportProfile::RelayFragment,
            redact_secrets: false,
            ..GatewayExportOptions::default()
        },
    )
    .expect("export relay fragment plaintext");
    assert!(!frag_plain.redacted);
    assert!(frag_plain.yaml.contains("relay-password"));
    assert!(frag_plain.yaml.contains("203.0.113.10"));

    let frag_empty = export_gateway_yaml(
        &cfg,
        &nodes,
        &groups,
        &[],
        None,
        &GatewayExportOptions {
            profile: GatewayExportProfile::RelayFragment,
            redact_secrets: true,
            ..GatewayExportOptions::default()
        },
    )
    .expect("empty relays must not fail");
    assert_eq!(frag_empty.relay_count, 0);
    assert!(!frag_empty.warnings.is_empty());
    let _: Value = serde_yaml_ng::from_str(&frag_empty.yaml).expect("empty fragment valid YAML");

    // 2. TransparentGateway: allow-lan, bind-address="*", custom ports, tun disabled, inline rule-providers preserved
    let gw_plain = export_gateway_yaml(
        &cfg,
        &nodes,
        &groups,
        &relays,
        None,
        &GatewayExportOptions {
            profile: GatewayExportProfile::TransparentGateway,
            tproxy_port: 17893,
            redir_port: 17892,
            dns_listen_port: 11053,
            redact_secrets: false,
        },
    )
    .expect("export transparent gateway plaintext");
    assert!(!gw_plain.redacted);
    assert_eq!(gw_plain.relay_count, 2);
    assert_eq!(gw_plain.node_count, 2);
    let gw_val: Value =
        serde_yaml_ng::from_str(&gw_plain.yaml).expect("transparent gateway valid YAML");
    assert_eq!(gw_val["allow-lan"], Value::Bool(true));
    assert_eq!(gw_val["bind-address"], "*");
    assert_eq!(gw_val["tproxy-port"], Value::Number(Number::from(17893u64)));
    assert_eq!(gw_val["redir-port"], Value::Number(Number::from(17892u64)));
    assert_eq!(gw_val["tun"]["enable"], Value::Bool(false));
    assert_eq!(gw_val["dns"]["listen"], "0.0.0.0:11053");
    assert!(gw_val["rule-providers"]["lan_direct"].is_mapping());
    assert!(gw_plain.yaml.contains("gw-test-controller-secret-12345"));

    let gw_redacted = export_gateway_yaml(
        &cfg,
        &nodes,
        &groups,
        &relays,
        None,
        &GatewayExportOptions {
            profile: GatewayExportProfile::TransparentGateway,
            tproxy_port: 17893,
            redir_port: 17892,
            dns_listen_port: 11053,
            redact_secrets: true,
        },
    )
    .expect("export transparent gateway redacted");
    assert!(gw_redacted.redacted);
    assert!(!gw_redacted.yaml.contains("gw-test-controller-secret-12345"));
    assert!(!gw_redacted.yaml.contains("relay-password"));
    assert!(!gw_redacted.yaml.contains("203.0.113.10"));
    let _: Value =
        serde_yaml_ng::from_str(&gw_redacted.yaml).expect("redacted gateway valid YAML");

    // 3. PreferredNodes: ranks active healthy node first and keeps dialer-proxy on non-443 node
    let pref_plain = export_gateway_yaml(
        &cfg,
        &nodes,
        &groups,
        &relays,
        None,
        &GatewayExportOptions {
            profile: GatewayExportProfile::PreferredNodes,
            redact_secrets: false,
            ..GatewayExportOptions::default()
        },
    )
    .expect("export preferred nodes plaintext");
    assert_eq!(pref_plain.relay_count, 2);
    assert_eq!(pref_plain.node_count, 2);
    let pref_val: Value =
        serde_yaml_ng::from_str(&pref_plain.yaml).expect("preferred nodes valid YAML");
    let proxies = pref_val["proxies"].as_sequence().unwrap();
    let jp_node = proxies
        .iter()
        .find(|p| p["name"] == "Node-JP-8443")
        .expect("JP non-443 node present");
    assert_eq!(jp_node["dialer-proxy"], PREACCEL_SELECT_GROUP_NAME);
    let sg_node = proxies
        .iter()
        .find(|p| p["name"] == "Node-SG-443")
        .expect("SG 443-native node present");
    assert!(sg_node.get("dialer-proxy").is_none());

    let pref_redacted = export_gateway_yaml(
        &cfg,
        &nodes,
        &groups,
        &relays,
        None,
        &GatewayExportOptions {
            profile: GatewayExportProfile::PreferredNodes,
            redact_secrets: true,
            ..GatewayExportOptions::default()
        },
    )
    .expect("export preferred nodes redacted");
    assert!(!pref_redacted.yaml.contains("demo-password"));
    assert!(!pref_redacted.yaml.contains("relay-password"));
    let _: Value =
        serde_yaml_ng::from_str(&pref_redacted.yaml).expect("redacted preferred nodes valid YAML");
}

#[test]
fn redact_gateway_yaml_ast_redacts_special_passwords_headers_fake_ip_and_rules_as_valid_yaml() {
    let mut cfg = AppConfig::default();
    cfg.preaccel.enabled = true;
    cfg.controller_secret = Some("ctrl'sec;ret&val > )".to_string());
    cfg.rules_override.global_prepend_rules = vec![
        "DOMAIN,edge.demo-vendor.example,DIRECT".to_string(),
        "IP-CIDR,10.23.45.67/32,DIRECT,no-resolve".to_string(),
        "IP-CIDR,198.51.100.99/32,DIRECT,no-resolve".to_string(),
    ];
    let provider_url = format!(
        "{}?{}={}",
        "https://example.invalid/corp.yaml", "token", "url_tok_secret_99"
    );
    cfg.rules_override.inline_override_yaml = Some(format!(
        "rule-providers:\n  private_corp:\n    type: http\n    behavior: domain\n    url: {provider_url}\n    path: ./ruleset/corp.yaml\n    header:\n      Authorization:\n        - \"Bearer top-secret-provider-hdr\"\n      X-Custom-Auth: \"hdr-secret-value-42\"\n"
    ));

    let mut domain_relay =
        sample_relay("r-dom", "Relay-Domain", "relay.vendor-hop.example", 10);
    domain_relay.password = "pass'word;semi&amp>paren )\\".to_string();
    let relays = vec![domain_relay];

    let mut tricky_node = sample_node("n-tricky", "Node-Tricky", 8443, false);
    tricky_node.server = "edge.demo-vendor.example".to_string();
    tricky_node.raw_config = serde_json::json!({
        "name": "Node-Tricky",
        "type": "trojan",
        "server": "edge.demo-vendor.example",
        "port": 8443,
        "sni": "sni.demo-vendor.example",
        "password": "line1'secret\nline2;secret&tail > )\\",
        "uuid": "11111111-2222-3333-4444-555555555555",
        "reality-opts": {
            "public-key": "pub_key_real_secret_xyz",
            "short-id": "abcdef012345"
        },
        "ws-opts": {
            "headers": {
                "Host": "ws.demo-vendor.example"
            }
        }
    });
    let nodes = vec![tricky_node];

    for profile in [
        GatewayExportProfile::RelayFragment,
        GatewayExportProfile::TransparentGateway,
        GatewayExportProfile::PreferredNodes,
    ] {
        let exported = export_gateway_yaml(
            &cfg,
            &nodes,
            &[],
            &relays,
            None,
            &GatewayExportOptions {
                profile,
                tproxy_port: 17893,
                redir_port: 17892,
                dns_listen_port: 11053,
                redact_secrets: true,
            },
        )
        .expect("AST redacted gateway export must succeed");

        let parsed: Value = serde_yaml_ng::from_str(&exported.yaml)
            .expect("AST redacted gateway YAML must be 100% valid YAML");

        for leaked in [
            "relay.vendor-hop.example",
            "vendor-hop",
            "edge.demo-vendor.example",
            "demo-vendor",
            "sni.demo-vendor.example",
            "ws.demo-vendor.example",
            "pass'word",
            "semi&amp",
            "line1'secret",
            "line2;secret",
            "ctrl'sec",
            "11111111-2222-3333-4444-555555555555",
            "pub_key_real_secret_xyz",
            "abcdef012345",
            "top-secret-provider-hdr",
            "hdr-secret-value-42",
            "url_tok_secret_99",
            "10.23.45.67",
            "198.51.100.99",
        ] {
            assert!(
                !exported.yaml.contains(leaked),
                "profile {profile:?} leaked `{leaked}` in:\n{}",
                exported.yaml
            );
        }

        if profile == GatewayExportProfile::TransparentGateway {
            let hdr = &parsed["rule-providers"]["private_corp"]["header"];
            assert_eq!(hdr["Authorization"][0].as_str(), Some("<REDACTED>"));
            assert_eq!(hdr["X-Custom-Auth"].as_str(), Some("<REDACTED>"));
        }
    }
}

#[test]
fn inline_override_yaml_cannot_wipe_safety_rules_or_bypass_transparent_gateway_locks() {
    let mut cfg = AppConfig::default();
    cfg.preaccel.enabled = true;
    cfg.tun.enabled = true;
    cfg.rules_override.custom_rules_only = true;
    cfg.rules_override.inline_override_yaml = Some(
        r#"
tun:
  enable: true
allow-lan: false
bind-address: "127.0.0.1"
tproxy-port: 9999
redir-port: 9998
dns:
  listen: "127.0.0.1:5353"
rules:
  - DOMAIN-SUFFIX,custom-only.test,DIRECT
  - MATCH , DIRECT
"#
        .to_string(),
    );

    let relays = vec![sample_relay("r1", "Relay-A", "203.0.113.10", 10)];
    let nodes = vec![sample_node("n1", "Node-JP-8443", 8443, false)];
    let ports = sample_ports();
    let empty = HashMap::new();

    // 1. Direct compilation must keep anti-loop, probe bypass, and private LAN safety rules on top.
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
    .expect("compile with rules override");
    assert!(compiled.validation.ok, "unexpected errors: {:?}", compiled.validation.issues);
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
    assert!(rules.contains(&"IP-CIDR,203.0.113.10/32,DIRECT,no-resolve"));
    assert!(rules.contains(&probe_rule.as_str()));
    assert!(rules.contains(&"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve"));
    assert!(rules.contains(&"IP-CIDR,192.168.0.0/16,DIRECT,no-resolve"));
    assert!(rules.contains(&"DOMAIN-SUFFIX,custom-only.test,DIRECT"));
    assert_eq!(rules.last().copied(), Some("MATCH,DIRECT"));
    let lan_pos = rules
        .iter()
        .position(|r| *r == "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve")
        .unwrap();
    let custom_pos = rules
        .iter()
        .position(|r| *r == "DOMAIN-SUFFIX,custom-only.test,DIRECT")
        .unwrap();
    assert!(lan_pos < custom_pos, "safety base must precede overridden user rules");

    // 2. TransparentGateway locks allow-lan, bind-address="*", ports, dns.listen, and tun.enable=false.
    let gw = export_gateway_yaml(
        &cfg,
        &nodes,
        &[],
        &relays,
        None,
        &GatewayExportOptions {
            profile: GatewayExportProfile::TransparentGateway,
            tproxy_port: 17893,
            redir_port: 17892,
            dns_listen_port: 11053,
            redact_secrets: false,
        },
    )
    .expect("transparent gateway export with locked overrides");
    let gw_doc: Value = serde_yaml_ng::from_str(&gw.yaml).unwrap();
    assert_eq!(gw_doc["allow-lan"], Value::Bool(true));
    assert_eq!(gw_doc["bind-address"], "*");
    assert_eq!(gw_doc["tproxy-port"], Value::Number(Number::from(17893u64)));
    assert_eq!(gw_doc["redir-port"], Value::Number(Number::from(17892u64)));
    assert_eq!(gw_doc["tun"]["enable"], Value::Bool(false));
    assert_eq!(gw_doc["dns"]["listen"], "0.0.0.0:11053");

    // 3. StaticCheckSeverity::Error from invalid rule target in inline_override_yaml must return Err.
    cfg.rules_override.inline_override_yaml = Some(
        "rules:\n  - DOMAIN-SUFFIX,broken.test,NonExistentGroup\n  - MATCH,DIRECT\n".to_string(),
    );
    let err = export_gateway_yaml(
        &cfg,
        &nodes,
        &[],
        &relays,
        None,
        &GatewayExportOptions {
            profile: GatewayExportProfile::TransparentGateway,
            tproxy_port: 17893,
            redir_port: 17892,
            dns_listen_port: 11053,
            redact_secrets: false,
        },
    )
    .expect_err("transparent gateway must return Err when static validation has Error");
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("NonExistentGroup") && err_msg.contains("不存在的分组"),
        "expected aggregated zh-CN dangling target error, got: {err_msg}"
    );
}

#[test]
fn export_gateway_preferred_nodes_strips_dangling_dialer_keeps_clean_rules_and_handles_disabled_preaccel()
{
    let mut cfg = AppConfig::default();
    // Desktop switch off while enabled relays exist -> symmetric export with explanatory warning.
    cfg.preaccel.enabled = false;
    cfg.preaccel.skip_443_native = true;

    let relays = vec![sample_relay("r1", "Relay-A", "203.0.113.10", 10)];

    let mut node_dangling = sample_node("n-dangling", "Node-443-Dangling", 443, true);
    node_dangling.server = "biz-node.vendor-exit.example".to_string();
    node_dangling.raw_config = serde_json::json!({
        "name": "Node-443-Dangling",
        "type": "trojan",
        "server": "biz-node.vendor-exit.example",
        "port": 443,
        "password": "pw1",
        "dialer-proxy": "Other-Missing-Relay"
    });

    let mut node_self = sample_node("n-self", "Node-443-Self", 443, true);
    node_self.server = "self-node.vendor-exit.example".to_string();
    node_self.raw_config = serde_json::json!({
        "name": "Node-443-Self",
        "type": "trojan",
        "server": "self-node.vendor-exit.example",
        "port": 443,
        "password": "pw2",
        "dialer-proxy": "Node-443-Self"
    });

    let mut node_wrapped = sample_node("n-wrap", "Node-8443-Wrap", 8443, false);
    node_wrapped.server = "wrap-node.vendor-exit.example".to_string();
    node_wrapped.raw_config = serde_json::json!({
        "name": "Node-8443-Wrap",
        "type": "ss",
        "server": "wrap-node.vendor-exit.example",
        "port": 8443,
        "cipher": "aes-128-gcm",
        "password": "pw3"
    });

    let nodes = vec![node_dangling, node_self, node_wrapped];
    let exported = export_gateway_yaml(
        &cfg,
        &nodes,
        &[],
        &relays,
        None,
        &GatewayExportOptions {
            profile: GatewayExportProfile::PreferredNodes,
            redact_secrets: false,
            ..GatewayExportOptions::default()
        },
    )
    .expect("preferred nodes export");

    assert_eq!(exported.relay_count, 1);
    assert!(
        exported
            .warnings
            .iter()
            .any(|w| w.contains("当前桌面国内提速总开关关闭")),
        "expected disabled-switch symmetric export warning, got: {:?}",
        exported.warnings
    );

    let doc: Value = serde_yaml_ng::from_str(&exported.yaml).unwrap();
    let proxies = doc["proxies"].as_sequence().unwrap();
    let dangling_p = proxies
        .iter()
        .find(|p| p["name"] == "Node-443-Dangling")
        .unwrap();
    assert!(
        dangling_p.get("dialer-proxy").is_none(),
        "dangling dialer-proxy must be stripped"
    );
    let self_p = proxies
        .iter()
        .find(|p| p["name"] == "Node-443-Self")
        .unwrap();
    assert!(
        self_p.get("dialer-proxy").is_none(),
        "self-referencing dialer-proxy must be stripped"
    );
    let wrap_p = proxies
        .iter()
        .find(|p| p["name"] == "Node-8443-Wrap")
        .unwrap();
    assert_eq!(wrap_p["dialer-proxy"], PREACCEL_SELECT_GROUP_NAME);

    // Business node domains MUST enter dns.fake-ip-filter and MUST NOT enter rules: DIRECT.
    let rules: Vec<&str> = doc["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(rules.contains(&"IP-CIDR,203.0.113.10/32,DIRECT,no-resolve"));
    for biz_dom in [
        "biz-node.vendor-exit.example",
        "self-node.vendor-exit.example",
        "wrap-node.vendor-exit.example",
    ] {
        assert!(
            !rules.iter().any(|r| r.contains(biz_dom)),
            "business node domain `{biz_dom}` must NOT appear in PreferredNodes rules: {rules:?}"
        );
    }
    let fake_ip_filter: Vec<&str> = doc["dns"]["fake-ip-filter"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for biz_dom in [
        "biz-node.vendor-exit.example",
        "self-node.vendor-exit.example",
        "wrap-node.vendor-exit.example",
    ] {
        assert!(
            fake_ip_filter.contains(&biz_dom),
            "business node domain `{biz_dom}` must appear in dns.fake-ip-filter: {fake_ip_filter:?}"
        );
    }
}

#[test]
fn prune_over_32_nodes_preserves_inline_override_targets_and_transparent_gateway_exports_all_nodes()
{
    let mut cfg = AppConfig::default();
    cfg.core_runtime.compile_all_nodes = false;
    cfg.proxy_mode = ProxyMode::Rule;
    cfg.route_mode = RouteTargetMode::Single;
    cfg.active_single_node_id = Some("n-01".to_string());
    cfg.rules_override.inline_override_yaml = Some(
        r#"
rules:
  - DOMAIN-SUFFIX,ai-inline.test,Inline-AI-Group
  - DOMAIN-SUFFIX,direct-node.test,Node-35
  - MATCH,DIRECT
"#
        .to_string(),
    );

    let nodes: Vec<ProxyNode> = (1..=40)
        .map(|i| sample_node(&format!("n-{i:02}"), &format!("Node-{i:02}"), 8443, false))
        .collect();
    let groups = vec![MultiGroup {
        id: "g-inline".to_string(),
        name: "Inline-AI-Group".to_string(),
        mode: MultiGroupMode::StickyBest,
        member_node_ids: vec!["n-20".to_string(), "n-21".to_string()],
        active_node_id: Some("n-20".to_string()),
        ..Default::default()
    }];
    let ports = sample_ports();
    let empty = HashMap::new();

    // 1. >32 node pruning preserves groups & nodes referenced by inline_override_yaml rules.
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
    .expect("compile pruned config with inline_override_yaml targets");
    assert!(
        compiled.validation.ok,
        "inline_override_yaml targets must survive pruning without unknown_rule_target: {:?}",
        compiled.validation.issues
    );
    let compiled_names: Vec<&str> = compiled.value["proxies"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(|p| p.get("name").and_then(Value::as_str))
        .collect();
    assert!(compiled_names.contains(&"Node-01"));
    assert!(compiled_names.contains(&"Node-20"));
    assert!(compiled_names.contains(&"Node-21"));
    assert!(compiled_names.contains(&"Node-35"));
    assert!(
        compiled_names.len() < 40,
        "unreferenced nodes should still be pruned in desktop single mode"
    );

    // 2. TransparentGateway forces compile_all_nodes=true and exports all 40 enabled nodes.
    let gw = export_gateway_yaml(
        &cfg,
        &nodes,
        &groups,
        &[],
        None,
        &GatewayExportOptions {
            profile: GatewayExportProfile::TransparentGateway,
            tproxy_port: 17893,
            redir_port: 17892,
            dns_listen_port: 11053,
            redact_secrets: false,
        },
    )
    .expect("transparent gateway must export all nodes");
    assert_eq!(gw.node_count, 40);
}

#[test]
fn transparent_gateway_decouples_desktop_geodata_and_redacts_scoped_urls_and_wg_endpoints_only() {
    // Create a temporary fake desktop runtime_dir containing geosite.dat & Country.mmdb.
    let fake_runtime = std::env::temp_dir().join(format!(
        "catcloud-gw-geodata-decouple-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&fake_runtime).unwrap();
    std::fs::write(fake_runtime.join("geosite.dat"), b"fake").unwrap();
    std::fs::write(fake_runtime.join("Country.mmdb"), b"fake").unwrap();

    let mut cfg = AppConfig::default();
    cfg.geodata.geodata_mode = true;
    cfg.geodata.auto_update = true;
    cfg.preaccel.enabled = true;
    cfg.dns.nameserver = vec![
        "https://dns.alidns.com/dns-query#DIRECT".to_string(),
        "https://doh.pub/dns-query".to_string(),
        "https://doh.my-private-corp.example/secret-profile-7788/dns-query#DIRECT".to_string(),
        "dns.corp.internal:53".to_string(),
        "dns.alidns.com:53".to_string(),
        "system".to_string(),
        "dhcp://system".to_string(),
        "rcode://success".to_string(),
    ];
    cfg.rules_override.inline_override_yaml = Some(
        r#"
proxy-providers:
  corp_sub:
    type: http
    url: https://sub.private-airport.example/api/v1/client/subscribe/SuperSecretPath99?token=xyz
    path: ./providers/corp_sub.yaml
rule-providers:
  corp_rules:
    type: http
    behavior: domain
    url: https://rules.private-corp.example/internal/ListSecretPath.yaml
    path: ./rules/corp.yaml
geox-url:
  geoip: https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geoip.dat
"#
        .to_string(),
    );

    let relays = vec![sample_relay("r1", "Relay #1", "203.0.113.10", 10)];
    let mut wg_node = sample_node("n-wg", "WG Node #1", 51820, false);
    wg_node.protocol = "wireguard".to_string();
    wg_node.server = "wg-entry.private-wg.example".to_string();
    wg_node.raw_config = serde_json::json!({
        "name": "WG Node #1",
        "type": "wireguard",
        "server": "wg-entry.private-wg.example",
        "port": 51820,
        "private-key": "wg-priv-key-secret",
        "peers": [
            {
                "server": "peer-a.private-wg.example",
                "port": 51820,
                "endpoint": "wg-peer.private-wg.example:51820",
                "public-key": "wg-pub-key-secret"
            }
        ]
    });

    // Pass Some(&fake_runtime): TransparentGateway MUST still decouple from desktop GeoData.
    let gw_redacted = export_gateway_yaml(
        &cfg,
        &[wg_node],
        &[],
        &relays,
        Some(&fake_runtime),
        &GatewayExportOptions {
            profile: GatewayExportProfile::TransparentGateway,
            tproxy_port: 17893,
            redir_port: 17892,
            dns_listen_port: 11053,
            redact_secrets: true,
        },
    )
    .expect("export redacted transparent gateway");

    let _ = std::fs::remove_dir_all(&fake_runtime);

    // Must NOT emit GEOSITE,cn or GEOIP,CN despite desktop runtime_dir having GeoData files!
    assert!(!gw_redacted.yaml.contains("GEOSITE,cn,DIRECT"));
    assert!(!gw_redacted.yaml.contains("GEOIP,CN,DIRECT"));
    // Must still contain conservative domestic direct fallback rules.
    assert!(gw_redacted.yaml.contains("DOMAIN-SUFFIX,qq.com,DIRECT"));

    // Scoped secrets MUST be redacted:
    for leaked in [
        "private-airport",
        "SuperSecretPath99",
        "rules.private-corp.example",
        "ListSecretPath",
        "my-private-corp",
        "secret-profile-7788",
        "dns.corp.internal",
        "wg-peer.private-wg.example",
        "wg-priv-key-secret",
        "wg-pub-key-secret",
    ] {
        assert!(
            !gw_redacted.yaml.contains(leaked),
            "leaked `{leaked}` in redacted gateway YAML:\n{}",
            gw_redacted.yaml
        );
    }

    // Non-sensitive public endpoints, suffixes, and node `#1` names MUST remain intact!
    let parsed: Value = serde_yaml_ng::from_str(&gw_redacted.yaml).expect("valid YAML");
    assert_eq!(
        parsed["geodata-mode"],
        Value::Bool(false),
        "transparent gateway export must disable geodata-mode"
    );
    assert_eq!(
        parsed["geo-auto-update"],
        Value::Bool(false),
        "transparent gateway export must disable geo-auto-update"
    );
    let ns_list: Vec<&str> = parsed["dns"]["nameserver"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        ns_list.contains(&"https://dns.alidns.com/dns-query#DIRECT"),
        "public DoH with #DIRECT suffix must stay intact: {ns_list:?}"
    );
    assert!(
        ns_list.contains(&"https://doh.pub/dns-query#DIRECT")
            || ns_list.contains(&"https://doh.pub/dns-query"),
        "public DoH must stay intact: {ns_list:?}"
    );
    assert!(
        ns_list.contains(&"https://***.example/<REDACTED>#DIRECT"),
        "private DoH must redact host & path while keeping #DIRECT suffix: {ns_list:?}"
    );
    assert!(
        ns_list.contains(&"***.internal:53"),
        "bare private DNS domain with port must be redacted via redact_ip_or_host: {ns_list:?}"
    );
    assert!(
        ns_list.contains(&"dns.alidns.com:53#DIRECT")
            || ns_list.contains(&"dns.alidns.com:53"),
        "allowlisted public bare DNS domain with port must stay intact: {ns_list:?}"
    );
    assert!(
        ns_list.contains(&"system"),
        "system DNS entry must stay intact: {ns_list:?}"
    );
    assert!(
        ns_list.contains(&"dhcp://system"),
        "dhcp:// DNS entry must stay intact: {ns_list:?}"
    );
    assert!(
        ns_list.contains(&"rcode://success"),
        "rcode:// DNS entry must stay intact: {ns_list:?}"
    );
    assert_eq!(
        parsed["geox-url"]["geoip"].as_str(),
        Some("https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geoip.dat"),
        "geox-url must NOT be clobbered"
    );
    let group_urls: Vec<&str> = parsed["proxy-groups"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(|g| g.get("url").and_then(Value::as_str))
        .collect();
    assert!(
        group_urls
            .iter()
            .any(|u| u.contains("connectivitycheck.platform.hicloud.com")),
        "proxy-groups[].url must NOT be clobbered: {group_urls:?}"
    );
    assert!(
        gw_redacted.yaml.contains("WG Node #1"),
        "node name containing `#1` must NOT be corrupted"
    );
}
