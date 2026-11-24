pub mod adapter;
pub mod live_capture;
pub mod migrator;
pub mod parser;
pub mod process_attach;

pub use adapter::{
    ADAPTER_REASON_FAILOVER, ADAPTER_REASON_MANUAL, ADAPTER_REASON_SCHEDULED, ADAPTER_SCHEMA_V1,
    AdapterConfig, AdapterCooldownGuard, AdapterRequest, AdapterResponse,
    DEFAULT_ADAPTER_TIMEOUT_SEC, MAX_ADAPTER_STDERR_BYTES, MAX_ADAPTER_STDOUT_BYTES,
    MIN_ADAPTER_COOLDOWN_SEC, invoke_external_adapter, parse_adapter_response,
    render_adapter_template_script,
};
pub use live_capture::*;
pub use migrator::{
    MigrationImportOptions, MigrationImportReport, MigrationPreview, MigrationSourceKind,
    apply_migration_rules_to_config, discover_known_client_paths, import_migration_preview,
    preview_from_file, preview_from_text, scan_local_clients, scan_path_readonly,
};
pub use parser::{
    DEFAULT_SUBSCRIPTION_TIMEOUT, DEFAULT_SUBSCRIPTION_USER_AGENT, FetchOptions,
    FetchedSubscription, MAX_SUBSCRIPTION_BYTES, ParsedSubscription, SubscriptionPayloadFormat,
    SubscriptionUserInfo, apply_parsed_subscription, detect_is_443_native, detect_region_code,
    extract_auto_tags, extract_multiplier, fetch_and_parse_subscription,
    fetch_and_parse_subscription_with_fallback, fetch_and_parse_subscription_with_options,
    fetch_subscription_url, fetch_subscription_url_with_fallback,
    fetch_subscription_url_with_fallback_timeout, normalize_protocol, parse_subscription_payload,
    parse_userinfo_header,
};
pub use process_attach::{
    AttachRecommendation, DEFAULT_CONTROLLER_PROBE_TIMEOUT, ProcessCandidate,
    ProcessInspectionResult, inspect_process_source, inspect_process_source_with_timeout,
    list_process_candidates, normalize_loopback_controller_base_url,
    parse_controller_proxies_json, parse_process_cmdline,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AppConfig, SubscriptionKind, SubscriptionRecord};
    use crate::storage::Storage;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use uuid::Uuid;

    async fn spawn_mock_http_server(
        response_bytes: Vec<u8>,
        delay: Option<Duration>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local mock HTTP listener");
        let addr = listener.local_addr().expect("mock listener local_addr");
        let handle = tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut req_buf = [0u8; 2048];
                let _ = socket.read(&mut req_buf).await;
                if let Some(d) = delay {
                    tokio::time::sleep(d).await;
                }
                let _ = socket.write_all(&response_bytes).await;
                let _ = socket.shutdown().await;
            }
        });
        (format!("http://127.0.0.1:{}", addr.port()), handle)
    }

    #[test]
    fn clash_yaml_with_anchor_merge_and_metadata_inference() {
        let yaml = r#"
x-common-tls: &common_tls
  tls: true
  udp: true
  skip-cert-verify: false

proxies:
  - name: "🇯🇵 东京 0.5x AI"
    <<: *common_tls
    type: vless
    server: 203.0.113.10
    port: 443
    uuid: "00000000-0000-4000-8000-000000000001"
    servername: jp.example.invalid
  - name: "TW 台北 x3 家宽"
    <<: *common_tls
    type: trojan
    server: 203.0.113.11
    port: 443
    password: "placeholder-password"
    skip-cert-verify: true
  - name: "新加坡 1.5倍 中转"
    type: ss
    server: 198.51.100.20
    port: 8388
    cipher: aes-256-gcm
    password: "placeholder-ss-password"
  - name: "UK London 2x"
    type: anytls
    server: 198.51.100.21
    port: 443
    password: "placeholder-anytls"
  - name: "Custom-Relay-01"
    type: vmess
    server: 198.51.100.22
    port: 8080
    uuid: "00000000-0000-4000-8000-000000000002"
    alterId: 0
    cipher: auto
"#;

        let userinfo_hdr = "upload=1048576; download=2097152; total=10737418240; expire=1798761600";
        let parsed = parse_subscription_payload("sub-yaml", yaml.as_bytes(), Some(userinfo_hdr))
            .expect("parse YAML with anchors");

        assert_eq!(parsed.format, SubscriptionPayloadFormat::ClashYaml);
        assert_eq!(parsed.nodes.len(), 5);

        let ui = parsed.userinfo.as_ref().expect("userinfo parsed");
        assert_eq!(ui.upload_bytes, 1_048_576);
        assert_eq!(ui.download_bytes, 2_097_152);
        assert_eq!(ui.used_bytes(), 3_145_728);
        assert_eq!(ui.total_bytes, 10_737_418_240);
        assert_eq!(ui.expire_timestamp, Some(1_798_761_600));
        assert!(ui.expires_at.as_deref().unwrap_or("").starts_with("2027-01-01T00:00:00"));

        // Verify YAML anchor merge expanded `tls`, `udp`, and overridden `skip-cert-verify`
        let jp = &parsed.nodes[0];
        assert_eq!(jp.region_code, "JP");
        assert!((jp.multiplier - 0.5).abs() < 1e-6);
        assert!(jp.is_443_native);
        assert_eq!(jp.raw_config.get("tls").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            jp.raw_config.get("skip-cert-verify").and_then(|v| v.as_bool()),
            Some(false)
        );
        assert!(jp.tags.iter().any(|t| t == "ai"));

        let tw = &parsed.nodes[1];
        assert_eq!(tw.region_code, "TW");
        assert!((tw.multiplier - 3.0).abs() < 1e-6);
        assert!(tw.is_443_native);
        assert_eq!(
            tw.raw_config.get("skip-cert-verify").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert!(tw.tags.iter().any(|t| t == "residential"));

        let sg = &parsed.nodes[2];
        assert_eq!(sg.region_code, "SG");
        assert!((sg.multiplier - 1.5).abs() < 1e-6);
        assert!(!sg.is_443_native);

        let uk = &parsed.nodes[3];
        assert_eq!(uk.region_code, "UK");
        assert!((uk.multiplier - 2.0).abs() < 1e-6);
        assert!(uk.is_443_native);

        let unk = &parsed.nodes[4];
        assert_eq!(unk.region_code, "UNK");
        assert!((unk.multiplier - 1.0).abs() < 1e-6);
        assert!(!unk.is_443_native);
    }

    #[test]
    fn base64_and_plain_uri_all_eight_protocols() {
        let vmess_json = serde_json::json!({
            "v": "2",
            "ps": "HK 01 1.5倍",
            "add": "203.0.113.20",
            "port": "443",
            "id": "00000000-0000-4000-8000-000000000010",
            "aid": "0",
            "net": "ws",
            "host": "ws.example.invalid",
            "path": "/ws",
            "tls": "tls",
            "sni": "ws.example.invalid"
        });
        let vmess_uri = format!(
            "vmess://{}",
            STANDARD.encode(vmess_json.to_string().as_bytes())
        );
        let ss_sip002_cred = STANDARD.encode("aes-256-gcm:placeholder-ss-pass");
        let ss_legacy_body = STANDARD.encode("chacha20-ietf-poly1305:placeholder-pass@198.51.100.31:8388");

        let plain_lines = [
            "vless://00000000-0000-4000-8000-000000000011@203.0.113.21:443?security=reality&sni=edge.example.invalid&pbk=pubKeyPlaceholder&sid=ab12&fp=chrome&flow=xtls-rprx-vision#US%20San%20Jose%200.5x".to_string(),
            vmess_uri,
            "trojan://placeholder-tr@203.0.113.22:443?sni=tr.example.invalid&allowInsecure=1#DE%20Frankfurt%202x".to_string(),
            format!("ss://{ss_sip002_cred}@198.51.100.30:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dobfs.example.invalid#KR%20Seoul%201x"),
            format!("ss://{ss_legacy_body}#JP%20Legacy"),
            "hy2://placeholder-hy2@203.0.113.23:443?sni=hy2.example.invalid&insecure=1&obfs=salamander&obfs-password=obfspass#TW%20Hy2%20x2".to_string(),
            "hysteria2://placeholder-hy2b@203.0.113.24:8443?sni=hy2b.example.invalid#SG%20Hy2%20Non443".to_string(),
            "tuic://00000000-0000-4000-8000-000000000012:tuic-pass@203.0.113.25:443?sni=tuic.example.invalid&congestion_control=bbr&udp_relay_mode=native#UK%20TUIC".to_string(),
            "anytls://placeholder-anytls@203.0.113.26:443?sni=any.example.invalid&insecure=1#HK%20AnyTLS%200.5x".to_string(),
        ]
        .join("\n");

        // Plain URI list
        let parsed_plain = parse_subscription_payload("sub-uri", plain_lines.as_bytes(), None)
            .expect("parse plain URI list");
        assert_eq!(parsed_plain.format, SubscriptionPayloadFormat::PlainUriList);
        assert_eq!(parsed_plain.nodes.len(), 9);

        // Base64-encoded URI list
        let encoded = STANDARD.encode(plain_lines.as_bytes());
        let parsed_b64 = parse_subscription_payload("sub-uri", encoded.as_bytes(), None)
            .expect("parse base64 URI list");
        assert_eq!(parsed_b64.format, SubscriptionPayloadFormat::Base64UriList);
        assert_eq!(parsed_b64.nodes.len(), 9);

        let protos: Vec<&str> = parsed_b64
            .nodes
            .iter()
            .map(|n| n.protocol.as_str())
            .collect();
        assert_eq!(
            protos,
            vec![
                "vless",
                "vmess",
                "trojan",
                "ss",
                "ss",
                "hysteria2",
                "hysteria2",
                "tuic",
                "anytls"
            ]
        );

        // Spot check decoded fields
        let vless = &parsed_b64.nodes[0];
        assert_eq!(vless.region_code, "US");
        assert!((vless.multiplier - 0.5).abs() < 1e-6);
        assert!(vless.is_443_native);
        assert_eq!(
            vless
                .raw_config
                .get("reality-opts")
                .and_then(|r| r.get("public-key"))
                .and_then(|v| v.as_str()),
            Some("pubKeyPlaceholder")
        );

        let vmess = &parsed_b64.nodes[1];
        assert_eq!(vmess.region_code, "HK");
        assert!((vmess.multiplier - 1.5).abs() < 1e-6);
        assert!(vmess.is_443_native);

        let ss_sip = &parsed_b64.nodes[3];
        assert_eq!(ss_sip.region_code, "KR");
        assert!(!ss_sip.is_443_native);
        assert_eq!(
            ss_sip.raw_config.get("plugin").and_then(|v| v.as_str()),
            Some("obfs")
        );

        let hy2_non443 = &parsed_b64.nodes[6];
        assert_eq!(hy2_non443.region_code, "SG");
        assert!(!hy2_non443.is_443_native);

        let tuic = &parsed_b64.nodes[7];
        assert_eq!(tuic.region_code, "UK");
        assert!(tuic.is_443_native);
        assert_eq!(
            tuic.raw_config
                .get("congestion-controller")
                .and_then(|v| v.as_str()),
            Some("bbr")
        );

        let anytls = &parsed_b64.nodes[8];
        assert_eq!(anytls.region_code, "HK");
        assert!(anytls.is_443_native);
    }

    #[test]
    fn multiplier_region_and_443_edge_cases() {
        assert!((extract_multiplier("JP 0.5x") - 0.5).abs() < 1e-6);
        assert!((extract_multiplier("SG [2x]") - 2.0).abs() < 1e-6);
        assert!((extract_multiplier("TW x3 IPLC") - 3.0).abs() < 1e-6);
        assert!((extract_multiplier("HK 1.5倍") - 1.5).abs() < 1e-6);
        assert!((extract_multiplier("US 0.25倍率") - 0.25).abs() < 1e-6);
        assert!((extract_multiplier("Free 0x") - 0.0).abs() < 1e-6);
        assert!((extract_multiplier("HK 01") - 1.0).abs() < 1e-6);
        assert!((extract_multiplier("v2ray-node-2") - 1.0).abs() < 1e-6);

        assert_eq!(detect_region_code("🇹🇼 Node"), "TW");
        assert_eq!(detect_region_code("德国 法兰克福"), "DE");
        assert_eq!(detect_region_code("KR-Seoul-01"), "KR");
        assert_eq!(detect_region_code("Node-Custom-01"), "UNK");
        assert_eq!(detect_region_code("Dedicated-Edge-02"), "UNK");

        assert!(detect_is_443_native("vless", 443, &serde_json::json!({ "tls": true })));
        assert!(!detect_is_443_native("vless", 443, &serde_json::json!({ "tls": false })));
        assert!(detect_is_443_native("trojan", 443, &serde_json::json!({})));
        assert!(detect_is_443_native("anytls", 443, &serde_json::json!({})));
        assert!(!detect_is_443_native("ss", 443, &serde_json::json!({})));
        assert!(!detect_is_443_native("trojan", 8443, &serde_json::json!({})));

        let no_exp = parse_userinfo_header("upload=10; download=20; total=100; expire=0")
            .expect("userinfo without expire");
        assert_eq!(no_exp.used_bytes(), 30);
        assert_eq!(no_exp.expire_timestamp, None);
        assert_eq!(no_exp.expires_at, None);
        assert!(parse_userinfo_header("   ").is_none());
    }

    #[test]
    fn strict_refresh_protection_rejects_oversized_malformed_and_zero_nodes() {
        let oversized = vec![b'a'; MAX_SUBSCRIPTION_BYTES + 1];
        assert!(parse_subscription_payload("sub-big", &oversized, None).is_err());

        let malformed_yaml = b"proxies:\n  - name: [unterminated\n";
        assert!(parse_subscription_payload("sub-bad-yaml", malformed_yaml, None).is_err());

        let empty_proxies_yaml = b"proxies: []\nrules:\n  - MATCH,DIRECT\n";
        assert!(parse_subscription_payload("sub-empty", empty_proxies_yaml, None).is_err());

        let html_error_page = b"<html><body>Service Unavailable</body></html>";
        assert!(parse_subscription_payload("sub-html", html_error_page, None).is_err());
    }

    #[tokio::test]
    async fn async_fetch_http_success_non_2xx_zero_nodes_and_preserves_existing_db() {
        let valid_yaml = concat!(
            "proxies:\n",
            "  - name: \"JP Tokyo 1x\"\n",
            "    type: vless\n",
            "    server: 203.0.113.50\n",
            "    port: 443\n",
            "    uuid: \"00000000-0000-4000-8000-000000000050\"\n",
            "    tls: true\n"
        );
        let ok_resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/yaml\r\nETag: \"v1\"\r\nSubscription-Userinfo: upload=100; download=200; total=1000; expire=1798761600\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            valid_yaml.len(),
            valid_yaml
        );
        let (ok_url, h1) = spawn_mock_http_server(ok_resp.into_bytes(), None).await;

        let sub = SubscriptionRecord {
            id: "sub-remote".to_string(),
            name: "Remote Feed".to_string(),
            kind: SubscriptionKind::Url,
            url_or_cmd: ok_url,
            ..Default::default()
        };

        let parsed = fetch_and_parse_subscription(&sub, Duration::from_secs(3))
            .await
            .expect("HTTP 200 valid subscription");
        let _ = h1.await;
        assert_eq!(parsed.nodes.len(), 1);
        assert_eq!(parsed.etag.as_deref(), Some("\"v1\""));

        let mut storage = Storage::open_in_memory().expect("open in-memory storage");
        let applied = apply_parsed_subscription(&mut storage, &sub, &parsed).expect("apply nodes");
        assert_eq!(applied, 1);

        // Non-2xx HTTP 500 must fail and preserve existing SQLite nodes
        let err_resp = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 4\r\nConnection: close\r\n\r\nfail".to_vec();
        let (err_url, h2) = spawn_mock_http_server(err_resp, None).await;
        let sub_500 = SubscriptionRecord {
            url_or_cmd: err_url,
            ..sub.clone()
        };
        assert!(fetch_and_parse_subscription(&sub_500, Duration::from_secs(3)).await.is_err());
        let _ = h2.await;
        assert_eq!(storage.list_nodes().unwrap().len(), 1);

        // HTTP 200 with 0 valid nodes must fail and preserve existing SQLite nodes
        let zero_body = "proxies: []\n";
        let zero_resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            zero_body.len(),
            zero_body
        );
        let (zero_url, h3) = spawn_mock_http_server(zero_resp.into_bytes(), None).await;
        let sub_zero = SubscriptionRecord {
            url_or_cmd: zero_url,
            ..sub.clone()
        };
        assert!(fetch_and_parse_subscription(&sub_zero, Duration::from_secs(3)).await.is_err());
        let _ = h3.await;
        assert_eq!(storage.list_nodes().unwrap().len(), 1);

        // Oversized Content-Length (> 16 MiB) must be rejected immediately
        let oversized_hdr = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            MAX_SUBSCRIPTION_BYTES + 1
        );
        let (big_url, h4) = spawn_mock_http_server(oversized_hdr.into_bytes(), None).await;
        let sub_big = SubscriptionRecord {
            url_or_cmd: big_url,
            ..sub.clone()
        };
        assert!(fetch_and_parse_subscription(&sub_big, Duration::from_secs(3)).await.is_err());
        let _ = h4.await;

        // Timeout protection
        let (slow_url, h5) = spawn_mock_http_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
            Some(Duration::from_millis(600)),
        )
        .await;
        let sub_slow = SubscriptionRecord {
            url_or_cmd: slow_url,
            ..sub.clone()
        };
        assert!(
            fetch_and_parse_subscription(&sub_slow, Duration::from_millis(120))
                .await
                .is_err()
        );
        let _ = h5.await;
    }

    #[test]
    fn migrator_readonly_clash_verge_v2rayn_clipboard_and_import() {
        let dir = std::env::temp_dir().join(format!("catcloud-migrate-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create temp dir");

        let clash_file = dir.join("verge_profile.yaml");
        let clash_raw = r#"
proxies:
  - name: "SG 狮城 1x"
    type: trojan
    server: 203.0.113.60
    port: 443
    password: "placeholder-verge-pass"
prepend-rules:
  - DOMAIN-SUFFIX,local.example.invalid,DIRECT
rules:
  - PROCESS-NAME,sample-app.exe,DIRECT
  - DOMAIN-SUFFIX,openai.com,PROXY
  - MATCH,PROXY
"#;
        std::fs::write(&clash_file, clash_raw).expect("write clash fixture");

        let v2rayn_file = dir.join("config.json");
        let v2rayn_raw = serde_json::json!({
            "outbounds": [
                {
                    "tag": "JP V2RayN 0.5x",
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": "198.51.100.61",
                            "port": 443,
                            "users": [{
                                "id": "00000000-0000-4000-8000-000000000061",
                                "flow": "xtls-rprx-vision"
                            }]
                        }]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "serverName": "edge.example.invalid",
                            "fingerprint": "chrome",
                            "publicKey": "pbk-placeholder",
                            "shortId": "1234"
                        }
                    }
                },
                { "tag": "direct", "protocol": "freedom" },
                { "tag": "block", "protocol": "blackhole" }
            ],
            "routing": {
                "rules": [
                    {
                        "type": "field",
                        "domain": ["domain:direct.example.invalid"],
                        "outboundTag": "direct"
                    }
                ]
            }
        })
        .to_string();
        std::fs::write(&v2rayn_file, &v2rayn_raw).expect("write v2rayn fixture");

        // Scan read-only and verify zero third-party directory mutation
        let scanned = scan_path_readonly(MigrationSourceKind::ClashVerge, &dir);
        assert_eq!(scanned.len(), 2);
        assert_eq!(std::fs::read_to_string(&clash_file).unwrap(), clash_raw);
        assert_eq!(std::fs::read_to_string(&v2rayn_file).unwrap(), v2rayn_raw);

        let clash_preview =
            preview_from_file(&clash_file, Some(MigrationSourceKind::ClashVerge))
                .expect("preview clash file");
        assert_eq!(clash_preview.nodes.len(), 1);
        assert_eq!(clash_preview.nodes[0].region_code, "SG");
        assert!(
            clash_preview
                .prepend_rules
                .iter()
                .any(|r| r.contains("PROCESS-NAME,sample-app.exe,DIRECT"))
        );
        assert!(
            clash_preview
                .append_rules
                .iter()
                .any(|r| r.contains("DOMAIN-SUFFIX,openai.com,PROXY"))
        );
        assert!(clash_preview.warnings.iter().any(|w| w.contains("MATCH")));

        let v2_preview =
            preview_from_file(&v2rayn_file, Some(MigrationSourceKind::V2rayN))
                .expect("preview v2rayN JSON");
        assert_eq!(v2_preview.nodes.len(), 1);
        assert_eq!(v2_preview.nodes[0].region_code, "JP");
        assert!(v2_preview.nodes[0].is_443_native);
        assert!(
            v2_preview
                .prepend_rules
                .iter()
                .any(|r| r == "DOMAIN-SUFFIX,direct.example.invalid,DIRECT")
        );

        // Clipboard text preview
        let clip_preview = preview_from_text(
            "trojan://placeholder@203.0.113.62:443?sni=clip.example.invalid#TW%20Clipboard%201x",
        )
        .expect("preview clipboard URI");
        assert_eq!(clip_preview.source_kind, MigrationSourceKind::ClipboardText);
        assert_eq!(clip_preview.nodes.len(), 1);
        assert_eq!(clip_preview.nodes[0].region_code, "TW");

        // Import into SQLite storage and merge rules into AppConfig
        let mut storage = Storage::open_in_memory().expect("open in-memory storage");
        let report = import_migration_preview(
            &mut storage,
            &clash_preview,
            &MigrationImportOptions::new("sub-migrated-verge", "Migrated Verge"),
        )
        .expect("import preview");
        assert_eq!(report.imported_node_count, 1);

        let saved_sub = storage
            .get_subscription("sub-migrated-verge")
            .unwrap()
            .expect("migrated subscription saved");
        assert_eq!(saved_sub.kind, SubscriptionKind::Migrated);
        assert_eq!(storage.list_nodes().unwrap().len(), 1);

        let mut cfg = AppConfig::default();
        cfg.rules_override
            .global_prepend_rules
            .push("DOMAIN,keep-user-rule.example.invalid,DIRECT".to_string());
        let (added_pre, added_app) = apply_migration_rules_to_config(&mut cfg, &clash_preview);
        assert_eq!(added_pre, 2);
        assert_eq!(added_app, 1);
        assert!(
            cfg.rules_override
                .global_prepend_rules
                .iter()
                .any(|r| r.contains("keep-user-rule.example.invalid"))
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn process_attach_cmdline_parsing_and_three_recommendations() {
        let dir = std::env::temp_dir().join(format!("catcloud-proc-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let yaml_path = dir.join("runtime.yaml");
        std::fs::write(
            &yaml_path,
            "proxies:\n  - name: \"JP Local 1x\"\n    type: trojan\n    server: 203.0.113.70\n    port: 443\n    password: \"placeholder\"\n",
        )
        .expect("write local yaml");

        // 1. CLI parsing + priority 1 (readable plaintext YAML)
        let candidate_yaml = parse_process_cmdline(
            4242,
            "mihomo.exe".to_string(),
            Some(PathBuf::from("C:\\Tools\\mihomo.exe")),
            vec![
                "mihomo.exe".to_string(),
                "-d".to_string(),
                dir.to_string_lossy().into_owned(),
                "-f".to_string(),
                "runtime.yaml".to_string(),
                "-ext-ctl".to_string(),
                "0.0.0.0:19099".to_string(),
            ],
        );
        assert!(candidate_yaml.likely_proxy_client);
        assert_eq!(candidate_yaml.detected_config_dir.as_deref(), Some(dir.as_path()));
        assert_eq!(
            candidate_yaml.detected_config_file.as_deref(),
            Some(yaml_path.as_path())
        );
        assert_eq!(
            candidate_yaml.detected_controller_addr.as_deref(),
            Some("0.0.0.0:19099")
        );
        assert_eq!(
            normalize_loopback_controller_base_url("0.0.0.0:9090").as_deref(),
            Some("http://127.0.0.1:9090")
        );
        assert_eq!(
            normalize_loopback_controller_base_url(":9091").as_deref(),
            Some("http://127.0.0.1:9091")
        );
        assert!(normalize_loopback_controller_base_url("203.0.113.5:9090").is_none());

        let inspect_yaml =
            inspect_process_source_with_timeout(&candidate_yaml, Duration::from_millis(300)).await;
        match inspect_yaml.recommendation {
            AttachRecommendation::ReadOnlyLocalFile {
                ref path,
                node_count,
                ..
            } => {
                assert_eq!(path, &yaml_path);
                assert_eq!(node_count, 1);
            }
            other => panic!("expected ReadOnlyLocalFile recommendation, got {other:?}"),
        }

        // 2. Priority 2 (public local Mihomo REST controller /proxies)
        let proxies_body = serde_json::json!({
            "proxies": {
                "DIRECT": { "type": "Direct" },
                "GLOBAL": { "type": "Selector" },
                "JP-Edge-01": { "type": "Vless" },
                "SG-Edge-02": { "type": "Trojan" }
            }
        })
        .to_string();
        let ctrl_ok_resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            proxies_body.len(),
            proxies_body
        );
        let (ctrl_url, h_ok) = spawn_mock_http_server(ctrl_ok_resp.into_bytes(), None).await;
        let ctrl_addr = ctrl_url.trim_start_matches("http://").to_string();

        let candidate_ctrl = parse_process_cmdline(
            4243,
            "clash-meta".to_string(),
            None,
            vec![
                "clash-meta".to_string(),
                format!("--ext-ctl={ctrl_addr}"),
            ],
        );
        let inspect_ctrl =
            inspect_process_source_with_timeout(&candidate_ctrl, Duration::from_secs(2)).await;
        let _ = h_ok.await;
        match inspect_ctrl.recommendation {
            AttachRecommendation::PublicControllerApi {
                proxy_count,
                requires_secret,
                ..
            } => {
                assert_eq!(proxy_count, 2);
                assert!(!requires_secret);
            }
            other => panic!("expected PublicControllerApi recommendation, got {other:?}"),
        }

        // 2b. Controller requiring Bearer secret (HTTP 401)
        let ctrl_401 = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec();
        let (ctrl401_url, h_401) = spawn_mock_http_server(ctrl_401, None).await;
        let candidate_401 = parse_process_cmdline(
            4244,
            "mihomo".to_string(),
            None,
            vec![
                "mihomo".to_string(),
                "-ext-ctl".to_string(),
                ctrl401_url.trim_start_matches("http://").to_string(),
            ],
        );
        let inspect_401 =
            inspect_process_source_with_timeout(&candidate_401, Duration::from_secs(2)).await;
        let _ = h_401.await;
        match inspect_401.recommendation {
            AttachRecommendation::PublicControllerApi {
                requires_secret, ..
            } => assert!(requires_secret),
            other => panic!("expected secret-protected PublicControllerApi, got {other:?}"),
        }

        // 3. Priority 3 (fallback external catcloud-adapter/v1 template)
        let candidate_opaque = parse_process_cmdline(
            4245,
            "custom-client".to_string(),
            None,
            vec!["custom-client".to_string(), "--config=nonexistent.yaml".to_string()],
        );
        let inspect_fallback =
            inspect_process_source_with_timeout(&candidate_opaque, Duration::from_millis(200))
                .await;
        match inspect_fallback.recommendation {
            AttachRecommendation::ExternalAdapterTemplate {
                ref schema,
                ref template_script,
                ..
            } => {
                assert_eq!(schema, ADAPTER_SCHEMA_V1);
                assert!(template_script.contains(ADAPTER_SCHEMA_V1));
                assert!(template_script.contains("203.0.113.10"));
            }
            other => panic!("expected ExternalAdapterTemplate, got {other:?}"),
        }

        // Smoke test sysinfo process enumeration
        let running = list_process_candidates(false);
        assert!(!running.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn adapter_schema_validation_cooldown_and_end_to_end_execution() {
        // 1. Config validation & cooldown >= 60s enforcement
        let mut cfg = AdapterConfig::from_command_line(
            "\"C:\\Tools\\My Adapter\\adapter.exe\" --profile default",
        )
        .expect("parse quoted windows command line");
        assert_eq!(cfg.program, "C:\\Tools\\My Adapter\\adapter.exe");
        assert_eq!(cfg.args, vec!["--profile", "default"]);
        assert!(cfg.validate().is_ok());

        cfg.min_refresh_cooldown_sec = 59;
        assert!(cfg.validate().is_err());

        // 2. Cooldown guard deterministic window test
        let guard = AdapterCooldownGuard::new();
        let t0 = Instant::now();
        assert!(
            guard
                .check_and_mark_at("sub-adapt", Duration::from_secs(60), t0)
                .is_ok()
        );
        let blocked = guard
            .check_and_mark_at(
                "sub-adapt",
                Duration::from_secs(60),
                t0 + Duration::from_secs(25),
            )
            .expect_err("must reject within 60s cooldown");
        assert_eq!(blocked, Duration::from_secs(35));
        assert!(
            guard
                .check_and_mark_at(
                    "sub-adapt",
                    Duration::from_secs(60),
                    t0 + Duration::from_secs(60)
                )
                .is_ok()
        );

        // 3. Schema, YAML merge, zero-node, and 16 MiB bound checks
        let valid_resp = serde_json::json!({
            "schema": ADAPTER_SCHEMA_V1,
            "nodes": [
                {
                    "name": "JP Adapter 1x",
                    "type": "vless",
                    "server": "203.0.113.80",
                    "port": 443,
                    "uuid": "00000000-0000-4000-8000-000000000080",
                    "tls": true
                }
            ],
            "yaml": "proxies:\n  - name: \"TW Adapter 0.5x\"\n    type: trojan\n    server: 198.51.100.81\n    port: 443\n    password: \"placeholder\"\n"
        });
        let resp_bytes = serde_json::to_vec(&valid_resp).unwrap();
        let parsed_nodes =
            parse_adapter_response("sub-adapt", &resp_bytes).expect("parse valid adapter payload");
        assert_eq!(parsed_nodes.len(), 2);
        assert_eq!(parsed_nodes[0].region_code, "JP");
        assert_eq!(parsed_nodes[1].region_code, "TW");
        assert!((parsed_nodes[1].multiplier - 0.5).abs() < 1e-6);

        let bad_schema = serde_json::json!({
            "schema": "other-adapter/v0",
            "nodes": [{ "name": "X", "type": "trojan", "server": "203.0.113.82", "port": 443 }]
        });
        assert!(parse_adapter_response("sub-adapt", &serde_json::to_vec(&bad_schema).unwrap()).is_err());

        let empty_nodes = serde_json::json!({
            "schema": ADAPTER_SCHEMA_V1,
            "nodes": [],
            "yaml": null
        });
        assert!(parse_adapter_response("sub-adapt", &serde_json::to_vec(&empty_nodes).unwrap()).is_err());

        let oversized = vec![b' '; MAX_ADAPTER_STDOUT_BYTES + 1];
        assert!(parse_adapter_response("sub-adapt", &oversized).is_err());

        // 4. Real subprocess execution with stdin request, stdout response, and anti-storm cooldown
        let dir = std::env::temp_dir().join(format!("catcloud-adapter-e2e-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let resp_file = dir.join("adapter_out.json");
        std::fs::write(&resp_file, &resp_bytes).expect("write adapter response fixture");

        #[cfg(target_os = "windows")]
        let e2e_cfg = AdapterConfig {
            program: "cmd".to_string(),
            args: vec![
                "/C".to_string(),
                "type".to_string(),
                resp_file.to_string_lossy().into_owned(),
            ],
            timeout_sec: 10,
            min_refresh_cooldown_sec: 60,
            ..Default::default()
        };

        #[cfg(not(target_os = "windows"))]
        let e2e_cfg = AdapterConfig {
            program: "cat".to_string(),
            args: vec![resp_file.to_string_lossy().into_owned()],
            timeout_sec: 10,
            min_refresh_cooldown_sec: 60,
            ..Default::default()
        };

        let live_guard = AdapterCooldownGuard::new();
        let req = AdapterRequest::new(
            ADAPTER_REASON_FAILOVER,
            "sub-e2e",
            vec!["198.51.100.99".to_string()],
        );
        let live_nodes = invoke_external_adapter(&e2e_cfg, &req, Some(&live_guard))
            .await
            .expect("invoke external adapter");
        assert_eq!(live_nodes.len(), 2);

        // Second immediate call must be blocked by >= 60s anti-storm cooldown
        let err = invoke_external_adapter(&e2e_cfg, &req, Some(&live_guard))
            .await
            .expect_err("second call inside cooldown must fail");
        assert!(err.to_string().contains("cooldown"));

        // 5. Execution timeout kills hanging adapter cleanly
        #[cfg(target_os = "windows")]
        let slow_cfg = AdapterConfig {
            program: "ping".to_string(),
            args: vec!["-n".to_string(), "5".to_string(), "127.0.0.1".to_string()],
            timeout_sec: 1,
            min_refresh_cooldown_sec: 60,
            ..Default::default()
        };

        #[cfg(not(target_os = "windows"))]
        let slow_cfg = AdapterConfig {
            program: "sleep".to_string(),
            args: vec!["4".to_string()],
            timeout_sec: 1,
            min_refresh_cooldown_sec: 60,
            ..Default::default()
        };

        let timeout_err = invoke_external_adapter(&slow_cfg, &req, None)
            .await
            .expect_err("hanging adapter must time out");
        assert!(timeout_err.to_string().contains("timed out"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
