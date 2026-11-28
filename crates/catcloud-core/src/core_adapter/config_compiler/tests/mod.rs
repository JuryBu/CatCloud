//! Unit test suite for `config_compiler`, partitioned by domain with zero assertion changes.

mod compile_tests;
mod gateway_tests;
mod network_preaccel_tests;
mod rules_validation_tests;

use crate::core_adapter::port_guard::AllocatedPorts;
use crate::models::{PreAccelRelay, ProxyNode};

fn sample_ports() -> AllocatedPorts {
    AllocatedPorts {
        bind_host: "127.0.0.1".to_string(),
        mixed_port: 27890,
        controller_port: 29090,
        dns_port: 21053,
        shifted: Vec::new(),
    }
}

fn sample_node(id: &str, name: &str, port: u16, is_443: bool) -> ProxyNode {
    ProxyNode {
        id: id.to_string(),
        sub_id: "sub-test".to_string(),
        name: name.to_string(),
        protocol: "trojan".to_string(),
        server: "203.0.113.50".to_string(),
        port,
        raw_config: serde_json::json!({
            "name": name,
            "type": "trojan",
            "server": "203.0.113.50",
            "port": port,
            "password": "demo-password",
            "udp": true
        }),
        region_code: "JP".to_string(),
        multiplier: 1.0,
        is_443_native: is_443,
        preaccel_eligible: true,
        preaccel_override: None,
        tags: Vec::new(),
        enabled: true,
    }
}

fn sample_relay(id: &str, name: &str, server: &str, priority: i32) -> PreAccelRelay {
    PreAccelRelay {
        id: id.to_string(),
        name: name.to_string(),
        provider: "demo".to_string(),
        region: "CN-EAST".to_string(),
        server: server.to_string(),
        port: 443,
        protocol: "anytls".to_string(),
        password: "relay-password".to_string(),
        sni: None,
        skip_cert_verify: true,
        priority,
        expires_at: None,
        enabled: true,
        supports_ipv6: false,
        last_probe_ms: None,
        last_mbps: None,
        last_up_mbps: None,
        last_down_mbps: None,
    }
}
