mod driver_and_tunnel;
mod nat_and_manager;

use crate::models::PreAccelRelay;

const TEST_UUID: &str = "11111111-2222-4333-8444-555555555555";

pub(super) fn sample_anytls_relay_with_dirty_sni() -> PreAccelRelay {
    PreAccelRelay {
        id: "relay-tx-443".to_string(),
        name: "Relay-TX-443".to_string(),
        provider: "tencent".to_string(),
        region: "CN-GZ".to_string(),
        server: "203.0.113.10".to_string(),
        port: 443,
        protocol: "anytls".to_string(),
        password: "demo-pass-01".to_string(),
        sni: Some("unfiled.example.com".to_string()),
        skip_cert_verify: false,
        priority: 10,
        expires_at: None,
        enabled: true,
        last_probe_ms: None,
        last_mbps: None,
        last_up_mbps: None,
        last_down_mbps: None,
        supports_ipv6: false,
    }
}

pub(super) fn sample_vless_relay_with_dirty_sni() -> PreAccelRelay {
    PreAccelRelay {
        id: "relay-ali-443".to_string(),
        name: "Relay-ALI-443".to_string(),
        provider: "aliyun".to_string(),
        region: "CN-SH".to_string(),
        server: "198.51.100.20".to_string(),
        port: 443,
        protocol: "vless".to_string(),
        password: TEST_UUID.to_string(),
        sni: Some("unfiled-vless.example.com".to_string()),
        skip_cert_verify: false,
        priority: 20,
        expires_at: None,
        enabled: true,
        last_probe_ms: None,
        last_mbps: None,
        last_up_mbps: None,
        last_down_mbps: None,
        supports_ipv6: false,
    }
}
