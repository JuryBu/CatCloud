pub mod benchmark;
pub mod campus;
pub mod generator;
pub mod global_tunnel;
pub mod schema;
#[cfg(target_os = "windows")]
mod windivert_win;

pub use benchmark::{
    BandwidthThrottleReport, PortSpeedSample, ThrottleConfidence, analyze_443_throttle,
    analyze_mixed_port_samples,
};
pub use campus::{
    CampusBypassTracker, CampusBypassTransition, CampusPortalState, build_campus_probe_client,
    build_temporary_bypass_entries, classify_portal_response, extract_host_from_url,
    probe_campus_portal, probe_campus_portal_with_fallback,
};
pub use generator::{
    DEFAULT_DOMESTIC_204_FALLBACK, DEFAULT_DOMESTIC_204_PRIMARY, PREACCEL_FALLBACK_GROUP,
    PREACCEL_SELECT_GROUP, PreAccelCompilePlan, build_preaccel_compile_plan,
    compile_relay_to_mihomo_yaml, host_to_direct_rule, host_to_fake_ip_filter,
    is_disallowed_domestic_probe_host, validate_domestic_probe_url,
};
pub use global_tunnel::{
    GlobalPreAccelManager, GlobalPreAccelMetrics, GlobalPreAccelStatus, Ipv4TcpMeta,
    MAX_NAT_ENTRIES, NAT_CLOSING_GRACE, NAT_IDLE_TIMEOUT, NatEntry, NatKey, NatTable,
    SELF_TEST_DETECTED_BY, STANDALONE_TUNNEL_GOGC, STANDALONE_TUNNEL_GOMEMLIMIT,
    StandalonePreAccelTunnel, WINDIVERT_DOWNLOAD_URL, WINDIVERT_ZIP_SHA256, WinDivertAddress,
    WinDivertPaths, build_security_guidance, build_self_test_probe_urls, build_windivert_filter,
    clamp_tcp_syn_mss, classify_security_products_from_process_names,
    collect_enabled_relay_ipv4s, compile_standalone_preaccel_yaml,
    compile_standalone_preaccel_yaml_with_interface, detect_host_security_products,
    download_and_install_windivert, is_physical_nic_descriptor, locate_windivert_files,
    locate_windivert_files_with_exe_dir, locate_windivert_paths, normalize_process_basename,
    parse_ipv4_tcp_packet, rewrite_ipv4_tcp_dst, rewrite_ipv4_tcp_from_loopback,
    rewrite_ipv4_tcp_src, rewrite_ipv4_tcp_to_loopback, should_intercept_process,
    socks5_noauth_connect_ipv4, verify_and_extract_windivert_zip,
};
pub use schema::{
    EXPIRY_SOON_THRESHOLD_DAYS, MMRELAY_URI_PREFIX, RelayExpiryStatus, RelayProtocol,
    RelayValidationCode, RelayValidationIssue, RelayValidationSeverity, bundle_from_relays,
    days_until_expiry, decode_mmrelay_uri, encode_mmrelay_uri, evaluate_expiry,
    import_relays_dedup_into_storage, is_pure_ip_server, parse_expiry_timestamp,
    parse_mmrelay_clipboard, parse_mmrelay_json, parse_server_ip, sanitize_relay_for_domestic_443,
    serialize_mmrelay_json, serialize_mmrelay_json_compact, validate_bundle_envelope,
    validate_relay, validate_relay_at, validate_relay_strict, validate_relay_strict_at,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::group::{
        MMRELAY_ROLE_DOMESTIC_PRE_ACCEL, MMRELAY_SCHEMA_V1, MmRelayBundleV1, PreAccelRelay,
    };
    use crate::models::node::ProxyNode;
    use crate::models::settings::PreAccelConfig;
    use chrono::{DateTime, Utc};
    use serde_yaml_ng::Value;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const DEMO_UUID: &str = "11111111-2222-4333-8444-555555555555";

    fn sample_tencent_relay() -> PreAccelRelay {
        PreAccelRelay {
            id: "relay-tx-gz".to_string(),
            name: "Tencent-GZ-443".to_string(),
            provider: "tencent".to_string(),
            region: "CN-GZ".to_string(),
            server: "203.0.113.10".to_string(),
            port: 443,
            protocol: "anytls".to_string(),
            password: "demo-relay-pass-01".to_string(),
            sni: None,
            skip_cert_verify: true,
            priority: 10,
            expires_at: Some("2027-06-01T00:00:00Z".to_string()),
            enabled: true,
            last_probe_ms: None,
            last_mbps: None,
            last_up_mbps: None,
            last_down_mbps: None,
        }
    }

    fn sample_aliyun_vless_relay() -> PreAccelRelay {
        PreAccelRelay {
            id: "relay-ali-sh".to_string(),
            name: "Aliyun-SH-443".to_string(),
            provider: "aliyun".to_string(),
            region: "CN-SH".to_string(),
            server: "198.51.100.20".to_string(),
            port: 443,
            protocol: "vless".to_string(),
            password: DEMO_UUID.to_string(),
            sni: None,
            skip_cert_verify: true,
            priority: 20,
            expires_at: Some("2027-07-01T00:00:00Z".to_string()),
            enabled: true,
            last_probe_ms: None,
            last_mbps: None,
            last_up_mbps: None,
            last_down_mbps: None,
        }
    }

    fn sample_node(
        id: &str,
        server: &str,
        port: u16,
        is_443_native: bool,
        override_opt: Option<bool>,
    ) -> ProxyNode {
        ProxyNode {
            id: id.to_string(),
            sub_id: "sub-demo".to_string(),
            name: format!("Node-{id}"),
            protocol: "trojan".to_string(),
            server: server.to_string(),
            port,
            is_443_native,
            preaccel_eligible: true,
            preaccel_override: override_opt,
            enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn mmrelay_v1_json_and_uri_roundtrip_and_clipboard_detection() {
        let bundle = bundle_from_relays(vec![sample_tencent_relay(), sample_aliyun_vless_relay()]);
        assert_eq!(bundle.schema, MMRELAY_SCHEMA_V1);
        assert_eq!(bundle.role, MMRELAY_ROLE_DOMESTIC_PRE_ACCEL);

        let json_pretty = serialize_mmrelay_json(&bundle).expect("serialize pretty JSON");
        let parsed_json = parse_mmrelay_json(&json_pretty).expect("parse JSON");
        assert_eq!(parsed_json, bundle);

        let uri = encode_mmrelay_uri(&bundle).expect("encode mmrelay URI");
        assert!(uri.starts_with(MMRELAY_URI_PREFIX));
        assert!(!uri.contains('\n'));

        let decoded_uri = decode_mmrelay_uri(&uri).expect("decode mmrelay URI");
        assert_eq!(decoded_uri, bundle);

        // Tolerate optional base64 padding and surrounding text in clipboard input.
        let padded_clipboard = format!("Relay backup:\n  {uri}==  \n");
        let parsed_clip =
            parse_mmrelay_clipboard(&padded_clipboard).expect("auto-detect URI in clipboard");
        assert_eq!(parsed_clip, bundle);

        let parsed_clip_json =
            parse_mmrelay_clipboard(&json_pretty).expect("auto-detect JSON in clipboard");
        assert_eq!(parsed_clip_json, bundle);

        // Reject unknown schema or role.
        let bad_schema = MmRelayBundleV1 {
            schema: "mmrelay/v99".to_string(),
            ..bundle.clone()
        };
        assert!(serialize_mmrelay_json(&bad_schema).is_err());

        let bad_role = MmRelayBundleV1 {
            role: "unknown_role".to_string(),
            ..bundle
        };
        assert!(encode_mmrelay_uri(&bad_role).is_err());
    }

    #[test]
    fn validate_relay_no_sni_iron_rule_across_protocols_and_vless_servername() {
        let now = DateTime::parse_from_rfc3339("2026-11-23T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let tx = sample_tencent_relay();
        assert!(validate_relay_strict_at(&tx, now).is_ok());

        let ali = sample_aliyun_vless_relay();
        assert!(validate_relay_strict_at(&ali, now).is_ok());

        // Trojan :443 with third-party SNI must be rejected.
        let mut trojan_bad = tx.clone();
        trojan_bad.protocol = "trojan".to_string();
        trojan_bad.sni = Some("cdn.example.com".to_string());
        let issues = validate_relay_at(&trojan_bad, now);
        assert!(issues.iter().any(|i| {
            i.code == RelayValidationCode::ForbiddenSniOnDomestic443
                && i.field == "sni"
                && i.severity == RelayValidationSeverity::Error
        }));
        assert!(validate_relay_strict_at(&trojan_bad, now).is_err());

        // VLESS JSON with `servername` alias must deserialize into `sni` and trigger VLESS `servername` error.
        let vless_json = r#"{
            "id": "relay-vless-sni",
            "name": "Aliyun-VLESS-Bad",
            "provider": "aliyun",
            "region": "CN-SH",
            "server": "198.51.100.30",
            "port": 443,
            "protocol": "vless",
            "password": "11111111-2222-4333-8444-555555555555",
            "servername": "unfiled.example.com",
            "skip_cert_verify": true
        }"#;
        let vless_bad: PreAccelRelay = serde_json::from_str(vless_json).expect("deserialize VLESS");
        assert!(vless_bad.has_non_empty_sni());
        let vless_issues = validate_relay_at(&vless_bad, now);
        assert!(vless_issues.iter().any(|i| {
            i.code == RelayValidationCode::ForbiddenSniOnDomestic443
                && i.field == "servername"
                && i.severity == RelayValidationSeverity::Error
        }));
        assert!(validate_relay_strict_at(&vless_bad, now).is_err());

        // Sanitizer clears SNI and enables skip_cert_verify so strict validation passes.
        let fixed = sanitize_relay_for_domestic_443(&vless_bad);
        assert!(!fixed.has_non_empty_sni());
        assert!(validate_relay_strict_at(&fixed, now).is_ok());

        // Pure IP with skip_cert_verify=false must fail.
        let mut no_skip = tx.clone();
        no_skip.skip_cert_verify = false;
        let no_skip_issues = validate_relay_at(&no_skip, now);
        assert!(no_skip_issues
            .iter()
            .any(|i| i.code == RelayValidationCode::SkipCertVerifyDisabledOnPureIp));
        assert!(validate_relay_strict_at(&no_skip, now).is_err());

        // Invalid VLESS UUID and invalid port 0 must fail.
        let mut bad_vless = ali.clone();
        bad_vless.password = "not-a-valid-uuid".to_string();
        bad_vless.port = 0;
        let bad_issues = validate_relay_at(&bad_vless, now);
        assert!(bad_issues
            .iter()
            .any(|i| i.code == RelayValidationCode::InvalidVlessUuid));
        assert!(bad_issues
            .iter()
            .any(|i| i.code == RelayValidationCode::InvalidPort));
    }

    #[test]
    fn validate_relay_expiry_countdown_warnings() {
        let now = DateTime::parse_from_rfc3339("2026-11-23T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        // Active (> 3 days remaining)
        assert_eq!(
            evaluate_expiry(Some("2026-12-10T12:00:00Z"), now),
            RelayExpiryStatus::Active { days_remaining: 17 }
        );

        // Expiring soon (<= 3 days remaining, including sub-day remaining)
        let mut soon = sample_tencent_relay();
        soon.expires_at = Some("2026-11-25T12:00:00Z".to_string());
        assert_eq!(
            evaluate_expiry(soon.expires_at.as_deref(), now).tag(),
            "expiring_soon"
        );
        assert_eq!(days_until_expiry(soon.expires_at.as_deref(), now), Some(2));
        let soon_issues = validate_relay_at(&soon, now);
        assert!(soon_issues
            .iter()
            .any(|i| i.code == RelayValidationCode::ExpiringSoon));

        let two_hours_left = "2026-11-23T14:00:00Z";
        assert_eq!(evaluate_expiry(Some(two_hours_left), now).tag(), "expiring_soon");
        assert_eq!(days_until_expiry(Some(two_hours_left), now), Some(1));

        // Expired (<= 0 days)
        let mut expired = sample_tencent_relay();
        expired.expires_at = Some("2026-11-21T12:00:00Z".to_string());
        assert_eq!(
            evaluate_expiry(expired.expires_at.as_deref(), now).tag(),
            "expired"
        );
        assert_eq!(
            days_until_expiry(expired.expires_at.as_deref(), now),
            Some(-2)
        );
        let expired_issues = validate_relay_at(&expired, now);
        assert!(expired_issues
            .iter()
            .any(|i| i.code == RelayValidationCode::Expired));

        // Date-only format and invalid format
        assert_eq!(
            evaluate_expiry(Some("2026-11-24"), now).tag(),
            "expiring_soon"
        );
        let mut bad_date = sample_tencent_relay();
        bad_date.expires_at = Some("invalid-date".to_string());
        assert!(validate_relay_strict_at(&bad_date, now).is_err());
    }

    #[test]
    fn domestic_204_probe_rejects_overseas_domains_and_accepts_domestic() {
        assert!(validate_domestic_probe_url(DEFAULT_DOMESTIC_204_PRIMARY).is_ok());
        assert!(validate_domestic_probe_url(DEFAULT_DOMESTIC_204_FALLBACK).is_ok());
        assert!(validate_domestic_probe_url("http://127.0.0.1:18080/generate_204").is_ok());

        for forbidden in [
            "https://www.gstatic.com/generate_204",
            "http://connectivitycheck.gstatic.com/generate_204",
            "http://clients3.google.com/generate_204",
            "https://cp.cloudflare.com/generate_204",
            "http://captive.apple.com/hotspot-detect.html",
            "ftp://connectivitycheck.platform.hicloud.com/generate_204",
        ] {
            assert!(
                validate_domestic_probe_url(forbidden).is_err(),
                "expected `{forbidden}` to be rejected"
            );
        }

        let mut cfg = PreAccelConfig::default();
        cfg.enabled = true;
        cfg.probe_url = "https://www.gstatic.com/generate_204".to_string();
        let err = build_preaccel_compile_plan(&cfg, &[sample_tencent_relay()], &[])
            .expect_err("overseas probe must fail compilation");
        assert!(err.to_string().contains("gstatic.com"));
    }

    #[test]
    fn compile_plan_native_443_skip_and_per_node_override() {
        let mut cfg = PreAccelConfig::default();
        cfg.enabled = true;
        cfg.skip_443_native = true;

        let mut ineligible = sample_node("n-ineligible", "198.51.100.88", 8443, false, None);
        ineligible.preaccel_eligible = false;

        let nodes = vec![
            sample_node("n-highport", "entry-a.example.com", 2053, false, None),
            sample_node("n-native443", "entry-b.example.com", 443, true, None),
            sample_node("n-443-forced-on", "entry-c.example.com", 443, true, Some(true)),
            sample_node("n-high-forced-off", "entry-d.example.com", 8443, false, Some(false)),
            ineligible,
        ];

        let plan = build_preaccel_compile_plan(&cfg, &[sample_tencent_relay()], &nodes)
            .expect("compile plan with skip_443_native=true");
        assert!(plan.active);
        assert_eq!(plan.dialer_for_node("n-highport"), Some(PREACCEL_SELECT_GROUP));
        assert_eq!(plan.dialer_for_node("n-native443"), None);
        assert_eq!(
            plan.dialer_for_node("n-443-forced-on"),
            Some(PREACCEL_SELECT_GROUP)
        );
        assert_eq!(plan.dialer_for_node("n-high-forced-off"), None);
        assert_eq!(plan.dialer_for_node("n-ineligible"), None);

        // Verify YAML helper attaches dialer-proxy only for eligible nodes.
        let mut proxy_yaml = Value::Mapping(serde_yaml_ng::Mapping::new());
        assert!(plan.apply_dialer_to_proxy_yaml("n-highport", &mut proxy_yaml));
        assert_eq!(
            proxy_yaml.get("dialer-proxy").and_then(Value::as_str),
            Some(PREACCEL_SELECT_GROUP)
        );

        // Turning off global skip_443_native wraps native 443 nodes unless explicitly forced off.
        cfg.skip_443_native = false;
        let plan_all = build_preaccel_compile_plan(&cfg, &[sample_tencent_relay()], &nodes)
            .expect("compile plan with skip_443_native=false");
        assert_eq!(
            plan_all.dialer_for_node("n-native443"),
            Some(PREACCEL_SELECT_GROUP)
        );
        assert_eq!(plan_all.dialer_for_node("n-high-forced-off"), None);
    }

    #[test]
    fn compile_plan_dual_relay_fallback_lazy_false_and_anti_loop_rules() {
        let mut cfg = PreAccelConfig::default();
        cfg.enabled = true;
        cfg.probe_interval_sec = 3; // should clamp to 10
        cfg.campus_direct_domains = vec!["auth.campus.example.edu".to_string()];

        let mut disabled_relay = sample_tencent_relay();
        disabled_relay.id = "relay-disabled".to_string();
        disabled_relay.server = "192.0.2.99".to_string();
        disabled_relay.enabled = false;

        // Pass relays out of priority order (20 before 10) to verify sorting.
        let relays = vec![
            sample_aliyun_vless_relay(),
            disabled_relay,
            sample_tencent_relay(),
        ];
        let nodes = vec![
            sample_node("n1", "transit.example.com", 2053, false, None),
            sample_node("n2", "192.0.2.50", 443, true, None),
        ];

        let plan = build_preaccel_compile_plan(&cfg, &relays, &nodes).expect("build compile plan");
        assert!(plan.active);
        assert_eq!(plan.effective_probe_interval_sec, 10);
        assert_eq!(plan.ordered_relay_ids, vec!["relay-tx-gz", "relay-ali-sh"]);
        assert_eq!(
            plan.ordered_relay_names,
            vec!["Tencent-GZ-443", "Aliyun-SH-443"]
        );
        assert_eq!(plan.relay_proxies.len(), 2);

        // Check AnyTLS proxy YAML has no `sni`, `skip-cert-verify: true`, `tfo: true`, and session pool settings.
        let anytls_yaml = &plan.relay_proxies[0];
        assert_eq!(anytls_yaml.get("type").and_then(Value::as_str), Some("anytls"));
        assert_eq!(anytls_yaml.get("server").and_then(Value::as_str), Some("203.0.113.10"));
        assert_eq!(anytls_yaml.get("skip-cert-verify").and_then(Value::as_bool), Some(true));
        assert_eq!(anytls_yaml.get("tfo").and_then(Value::as_bool), Some(true));
        assert_eq!(anytls_yaml.get("min-idle-session").and_then(Value::as_u64), Some(2));
        assert!(anytls_yaml.get("sni").is_none());

        // Check VLESS proxy YAML explicitly writes empty `servername: ""`, `tfo: true`, and `skip-cert-verify: true`.
        let vless_yaml = &plan.relay_proxies[1];
        assert_eq!(vless_yaml.get("type").and_then(Value::as_str), Some("vless"));
        assert_eq!(vless_yaml.get("uuid").and_then(Value::as_str), Some(DEMO_UUID));
        assert_eq!(vless_yaml.get("servername").and_then(Value::as_str), Some(""));
        assert_eq!(vless_yaml.get("tfo").and_then(Value::as_bool), Some(true));
        assert_eq!(vless_yaml.get("skip-cert-verify").and_then(Value::as_bool), Some(true));

        // Check `select` group puts `PREACCEL_FALLBACK_GROUP` first by default.
        let select_group = &plan.proxy_groups[0];
        assert_eq!(
            select_group.get("name").and_then(Value::as_str),
            Some(PREACCEL_SELECT_GROUP)
        );
        let select_proxies: Vec<&str> = select_group
            .get("proxies")
            .and_then(Value::as_sequence)
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(
            select_proxies,
            vec![PREACCEL_FALLBACK_GROUP, "Tencent-GZ-443", "Aliyun-SH-443"]
        );

        // Check `fallback` group has explicit `lazy: false`, domestic 204 URL, clamped interval.
        let fallback_group = &plan.proxy_groups[1];
        assert_eq!(
            fallback_group.get("name").and_then(Value::as_str),
            Some(PREACCEL_FALLBACK_GROUP)
        );
        assert_eq!(
            fallback_group.get("type").and_then(Value::as_str),
            Some("fallback")
        );
        assert_eq!(fallback_group.get("lazy").and_then(Value::as_bool), Some(false));
        assert_eq!(
            fallback_group.get("url").and_then(Value::as_str),
            Some(DEFAULT_DOMESTIC_204_PRIMARY)
        );
        assert_eq!(fallback_group.get("interval").and_then(Value::as_u64), Some(10));

        // Check anti-loop rules and fake-ip-filter contents.
        assert!(plan
            .anti_loop_rules
            .contains(&"IP-CIDR,203.0.113.10/32,DIRECT,no-resolve".to_string()));
        assert!(plan
            .anti_loop_rules
            .contains(&"IP-CIDR,198.51.100.20/32,DIRECT,no-resolve".to_string()));
        assert!(!plan
            .anti_loop_rules
            .contains(&"IP-CIDR,192.0.2.99/32,DIRECT,no-resolve".to_string()));
        assert!(plan
            .anti_loop_rules
            .contains(&"DOMAIN,transit.example.com,DIRECT".to_string()));
        assert!(plan
            .anti_loop_rules
            .contains(&"IP-CIDR,192.0.2.50/32,DIRECT,no-resolve".to_string()));
        assert!(plan
            .anti_loop_rules
            .contains(&"DOMAIN,connectivitycheck.platform.hicloud.com,DIRECT".to_string()));
        assert!(plan
            .anti_loop_rules
            .contains(&"DOMAIN-SUFFIX,hicloud.com,DIRECT".to_string()));
        assert!(plan
            .anti_loop_rules
            .contains(&"DOMAIN-SUFFIX,miui.com,DIRECT".to_string()));
        assert!(plan
            .anti_loop_rules
            .contains(&"DOMAIN,auth.campus.example.edu,DIRECT".to_string()));

        assert!(plan
            .fake_ip_filter
            .contains(&"transit.example.com".to_string()));
        assert!(plan
            .fake_ip_filter
            .contains(&"connectivitycheck.platform.hicloud.com".to_string()));
        assert!(plan.fake_ip_filter.contains(&"+.hicloud.com".to_string()));
        assert!(plan.fake_ip_filter.contains(&"+.miui.com".to_string()));
        assert!(!plan.fake_ip_filter.contains(&"203.0.113.10".to_string()));

        // Selecting an explicit `active_relay_id` places it at position 0 of the `select` group.
        cfg.active_relay_id = Some("relay-ali-sh".to_string());
        cfg.probe_interval_sec = 999; // should clamp to 300
        let pinned_plan =
            build_preaccel_compile_plan(&cfg, &relays, &nodes).expect("pinned compile plan");
        assert_eq!(pinned_plan.effective_probe_interval_sec, 300);
        let pinned_select: Vec<&str> = pinned_plan.proxy_groups[0]
            .get("proxies")
            .and_then(Value::as_sequence)
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(
            pinned_select,
            vec!["Aliyun-SH-443", PREACCEL_FALLBACK_GROUP, "Tencent-GZ-443"]
        );

        // Disabled config or zero enabled relays must safely bypass without dangling dialer-proxy.
        cfg.enabled = false;
        let disabled_plan =
            build_preaccel_compile_plan(&cfg, &relays, &nodes).expect("disabled compile plan");
        assert!(!disabled_plan.active);
        assert!(disabled_plan.relay_proxies.is_empty());
        assert_eq!(disabled_plan.dialer_for_node("n1"), None);

        cfg.enabled = true;
        let empty_plan = build_preaccel_compile_plan(&cfg, &[], &nodes).expect("no-relay plan");
        assert!(!empty_plan.active);
        assert!(!empty_plan.warnings.is_empty());
        assert_eq!(empty_plan.dialer_for_node("n1"), None);
    }

    #[test]
    fn campus_portal_tracker_302_and_200_bypass_then_204_recovery() {
        let mut tracker = CampusBypassTracker::new();
        assert!(!tracker.has_temporary_bypass());

        // Step 1: 302 redirect to campus login host adds temporary DOMAIN + fake-ip-filter.
        let s1 = classify_portal_response(
            DEFAULT_DOMESTIC_204_PRIMARY,
            302,
            Some("http://portal.campus.example.edu/eportal/index.jsp"),
            None,
        );
        let t1 = tracker.apply_state(s1.clone());
        assert!(matches!(
            &s1,
            CampusPortalState::CaptivePortalRequired {
                status_code: 302,
                bypass_host: Some(h),
                ..
            } if h == "portal.campus.example.edu"
        ));
        assert!(t1.rules_changed);
        assert_eq!(
            t1.active_direct_rules,
            vec!["DOMAIN,portal.campus.example.edu,DIRECT"]
        );
        assert_eq!(
            t1.active_fake_ip_filter,
            vec!["portal.campus.example.edu"]
        );

        // Step 2: 200 HTML redirect pointing to an IP portal adds IP-CIDR direct rule without fake-ip-filter.
        let html = r#"<html><script>window.location.href="http://198.51.100.7/login";</script></html>"#;
        let s2 = classify_portal_response(DEFAULT_DOMESTIC_204_PRIMARY, 200, None, Some(html));
        let t2 = tracker.apply_state(s2);
        assert!(t2.rules_changed);
        assert_eq!(
            t2.active_direct_rules,
            vec![
                "DOMAIN,portal.campus.example.edu,DIRECT",
                "IP-CIDR,198.51.100.7/32,DIRECT,no-resolve",
            ]
        );
        assert_eq!(
            t2.active_fake_ip_filter,
            vec!["portal.campus.example.edu"]
        );

        // Step 3: HTTP 204 recovery withdraws every temporary rule cleanly.
        let s3 = classify_portal_response(DEFAULT_DOMESTIC_204_PRIMARY, 204, None, None);
        assert_eq!(s3, CampusPortalState::Connected);
        let t3 = tracker.apply_state(s3);
        assert!(t3.rules_changed);
        assert!(t3.active_direct_rules.is_empty());
        assert!(t3.active_fake_ip_filter.is_empty());
        assert!(!tracker.has_temporary_bypass());
    }

    #[tokio::test]
    async fn campus_portal_async_probe_local_127_0_0_1_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local test listener");
        let addr = listener.local_addr().expect("local addr");
        let request_count = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&request_count);

        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let step = counter.fetch_add(1, Ordering::SeqCst);
                let response = if step == 0 {
                    "HTTP/1.1 302 Found\r\nLocation: http://auth.campus.example.edu/login\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                } else {
                    "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
                };
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });

        let probe_url = format!("http://{addr}/generate_204");
        let mut tracker = CampusBypassTracker::new();

        // First probe captures 302 without following redirects and inserts temporary bypass.
        let first_state = probe_campus_portal(&probe_url, Duration::from_secs(3)).await;
        let first_tx = tracker.apply_state(first_state);
        assert!(matches!(
            &first_tx.state,
            CampusPortalState::CaptivePortalRequired {
                status_code: 302,
                bypass_host: Some(host),
                ..
            } if host == "auth.campus.example.edu"
        ));
        assert!(first_tx.rules_changed);
        assert_eq!(
            first_tx.active_direct_rules,
            vec!["DOMAIN,auth.campus.example.edu,DIRECT"]
        );

        // Second probe receives 204 and automatically withdraws temporary bypass rules.
        let second_state = probe_campus_portal(&probe_url, Duration::from_secs(3)).await;
        let second_tx = tracker.apply_state(second_state);
        assert_eq!(second_tx.state, CampusPortalState::Connected);
        assert!(second_tx.rules_changed);
        assert!(second_tx.active_direct_rules.is_empty());
        assert!(second_tx.active_fake_ip_filter.is_empty());

        let _ = server.await;
    }

    #[test]
    fn benchmark_443_vs_non_443_throttle_analysis() {
        let p443 = vec![
            PortSpeedSample::new("tx-443-1", 443, 118.0).with_latency(18.0),
            PortSpeedSample::new("tx-443-2", 443, 120.0).with_latency(19.0),
            PortSpeedSample::new("tx-443-3", 443, 280.0), // outlier absorbed by median
        ];
        let non443 = vec![
            PortSpeedSample::new("node-2053-1", 2053, 11.0),
            PortSpeedSample::new("node-8443-2", 8443, 12.0),
            PortSpeedSample::new("node-9443-3", 9443, 14.0),
        ];

        let throttled = analyze_443_throttle(&p443, &non443);
        assert!(throttled.throttled_detected);
        assert_eq!(throttled.port_443_mbps, 120.0);
        assert_eq!(throttled.non_443_mbps, 12.0);
        assert_eq!(throttled.speedup_ratio, 10.0);
        assert_eq!(throttled.confidence, ThrottleConfidence::High);
        assert!(throttled.recommendation_zh.contains("开启国内提速"));

        // Balanced ports should not flag throttling.
        let balanced = analyze_mixed_port_samples(&[
            PortSpeedSample::new("p443-a", 443, 95.0),
            PortSpeedSample::new("p443-b", 443, 97.0),
            PortSpeedSample::new("non443-a", 8443, 90.0),
            PortSpeedSample::new("non443-b", 2053, 92.0),
        ]);
        assert!(!balanced.throttled_detected);
        assert_eq!(balanced.confidence, ThrottleConfidence::Medium);

        // Missing or invalid samples return InsufficientData safely without NaN.
        let missing = analyze_443_throttle(
            &[PortSpeedSample::new("bad", 443, f64::NAN)],
            &non443,
        );
        assert!(!missing.throttled_detected);
        assert_eq!(missing.confidence, ThrottleConfidence::InsufficientData);
        assert!(missing.speedup_ratio.is_finite());

        // Near-zero non-443 throughput must still stay finite and detect throttling.
        let near_zero = analyze_443_throttle(
            &[PortSpeedSample::new("p443", 443, 80.0)],
            &[PortSpeedSample::new("non443", 8443, 0.01)],
        );
        assert!(near_zero.throttled_detected);
        assert!(near_zero.speedup_ratio.is_finite());
        assert!(near_zero.speedup_ratio > 10.0);
    }

    #[test]
    fn import_relays_dedup_reuses_fingerprint_id_and_avoids_id_collision() {
        let db = crate::storage::Storage::open_in_memory().expect("open in-memory storage");

        let mut initial = sample_tencent_relay();
        initial.last_probe_ms = Some(19.0);
        initial.last_mbps = Some(110.0);
        initial.last_up_mbps = Some(110.0);
        initial.last_down_mbps = Some(210.0);
        db.upsert_preaccel_relay(&initial).expect("seed initial relay");

        // 1. Same physical fingerprint (case-insensitive protocol) with a different incoming ID
        //    must reuse `relay-tx-gz` and clear all cached speed metrics.
        let mut same_fp = sample_tencent_relay();
        same_fp.id = "relay-incoming-dup".to_string();
        same_fp.name = "Tencent-GZ-Updated".to_string();
        same_fp.protocol = "AnyTLS".to_string();
        same_fp.last_probe_ms = Some(99.0);
        same_fp.last_mbps = Some(99.0);
        same_fp.last_up_mbps = Some(88.0);
        same_fp.last_down_mbps = Some(77.0);

        // 2. Different physical server reusing existing ID `relay-tx-gz` must NOT overwrite the
        //    original relay; instead it must receive a freshly generated `relay-...` ID.
        let mut colliding_id = sample_aliyun_vless_relay();
        colliding_id.id = "relay-tx-gz".to_string();
        colliding_id.name = "Aliyun-SH-Fresh".to_string();

        // 3. Invalid domestic :443 relay with non-empty SNI must be skipped with Chinese warning.
        let mut invalid_sni = sample_tencent_relay();
        invalid_sni.id = "relay-bad-sni".to_string();
        invalid_sni.name = "Bad-SNI-Relay".to_string();
        invalid_sni.server = "192.0.2.88".to_string();
        invalid_sni.sni = Some("forbidden.example.com".to_string());

        let (imported, warnings) = import_relays_dedup_into_storage(
            &db,
            vec![same_fp, colliding_id, invalid_sni],
        )
        .expect("import relays dedup");

        assert_eq!(imported, 2);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("已跳过无效中转「Bad-SNI-Relay」"));

        let stored = db.list_preaccel_relays(false).expect("list stored relays");
        assert_eq!(stored.len(), 2);

        let tx = db
            .get_preaccel_relay("relay-tx-gz")
            .unwrap()
            .expect("original relay-tx-gz preserved");
        assert_eq!(tx.server, "203.0.113.10");
        assert_eq!(tx.name, "Tencent-GZ-Updated");
        assert_eq!(tx.last_probe_ms, None);
        assert_eq!(tx.last_mbps, None);
        assert_eq!(tx.last_up_mbps, None);
        assert_eq!(tx.last_down_mbps, None);

        let ali = stored
            .iter()
            .find(|r| r.server == "198.51.100.20")
            .expect("colliding relay stored under regenerated id");
        assert_ne!(ali.id, "relay-tx-gz");
        assert!(ali.id.starts_with("relay-"));
        assert_eq!(ali.name, "Aliyun-SH-Fresh");
    }

    #[test]
    fn hysteria2_and_hy2_alias_compile_and_mmrelay_v1_roundtrip() {
        let now = DateTime::parse_from_rfc3339("2026-11-25T08:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let hy2_canonical = PreAccelRelay {
            id: "relay-hy2-1".to_string(),
            name: "CN-East-HY2-443".to_string(),
            provider: "cloud-a".to_string(),
            region: "CN-East".to_string(),
            server: "203.0.113.44".to_string(),
            port: 443,
            protocol: "hysteria2".to_string(),
            password: "demo-hy2-password-01".to_string(),
            sni: None,
            skip_cert_verify: true,
            priority: 10,
            expires_at: Some("2027-08-12".to_string()),
            enabled: true,
            last_probe_ms: None,
            last_mbps: None,
            last_up_mbps: None,
            last_down_mbps: None,
        };
        let hy2_alias = PreAccelRelay {
            id: "relay-hy2-2".to_string(),
            name: "CN-South-HY2-443".to_string(),
            provider: "cloud-b".to_string(),
            region: "CN-South".to_string(),
            server: "198.51.100.44".to_string(),
            port: 443,
            protocol: "hy2".to_string(),
            password: "demo-hy2-password-02".to_string(),
            sni: None,
            skip_cert_verify: true,
            priority: 20,
            expires_at: Some("2027-08-12".to_string()),
            enabled: true,
            last_probe_ms: None,
            last_mbps: None,
            last_up_mbps: None,
            last_down_mbps: None,
        };

        assert!(validate_relay_strict_at(&hy2_canonical, now).is_ok());
        assert!(validate_relay_strict_at(&hy2_alias, now).is_ok());

        // Domestic :443 Hysteria2 must still reject unfiled third-party SNI.
        let mut hy2_bad_sni = hy2_canonical.clone();
        hy2_bad_sni.sni = Some("forbidden.example.com".to_string());
        let bad_issues = validate_relay_at(&hy2_bad_sni, now);
        assert!(bad_issues.iter().any(|i| {
            i.code == RelayValidationCode::ForbiddenSniOnDomestic443
                && i.field == "sni"
                && i.severity == RelayValidationSeverity::Error
        }));

        // Compile both `hysteria2` and `hy2` alias to Mihomo YAML with conservative Brutal limits.
        for (relay, name) in [
            (&hy2_canonical, "CN-East-HY2-443"),
            (&hy2_alias, "CN-South-HY2-443"),
        ] {
            let yaml = compile_relay_to_mihomo_yaml(relay, name).expect("compile hy2 relay");
            assert_eq!(yaml.get("type").and_then(Value::as_str), Some("hysteria2"));
            assert_eq!(yaml.get("port").and_then(Value::as_u64), Some(443));
            assert_eq!(
                yaml.get("password").and_then(Value::as_str),
                Some(relay.password.as_str())
            );
            assert_eq!(yaml.get("up").and_then(Value::as_str), Some("100 Mbps"));
            assert_eq!(yaml.get("down").and_then(Value::as_str), Some("200 Mbps"));
            assert_eq!(yaml.get("skip-cert-verify").and_then(Value::as_bool), Some(true));
            assert!(yaml.get("sni").is_none());
        }

        // mmrelay/v1 JSON & URI roundtrip preserves both entries verbatim.
        let bundle = bundle_from_relays(vec![hy2_canonical.clone(), hy2_alias.clone()]);
        let uri = encode_mmrelay_uri(&bundle).expect("encode hy2 mmrelay URI");
        let decoded = decode_mmrelay_uri(&uri).expect("decode hy2 mmrelay URI");
        assert_eq!(decoded, bundle);

        // Full compile plan wires fallback + pure-IP anti-loop rules cleanly.
        let mut cfg = PreAccelConfig::default();
        cfg.enabled = true;
        let nodes = vec![sample_node("n-hy2-chain", "edge.example.invalid", 8443, false, None)];
        let plan = build_preaccel_compile_plan(&cfg, &decoded.relays, &nodes)
            .expect("compile hy2 preaccel plan");
        assert!(plan.active);
        assert_eq!(plan.relay_proxies.len(), 2);
        assert_eq!(plan.relay_proxies[0]["type"].as_str(), Some("hysteria2"));
        assert_eq!(plan.relay_proxies[0]["up"].as_str(), Some("100 Mbps"));
        assert_eq!(plan.relay_proxies[0]["down"].as_str(), Some("200 Mbps"));
        assert_eq!(plan.relay_proxies[1]["type"].as_str(), Some("hysteria2"));
        assert!(plan
            .anti_loop_rules
            .contains(&"IP-CIDR,203.0.113.44/32,DIRECT,no-resolve".to_string()));
        assert!(plan
            .anti_loop_rules
            .contains(&"IP-CIDR,198.51.100.44/32,DIRECT,no-resolve".to_string()));
    }
}
