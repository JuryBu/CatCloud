use crate::core_adapter::format_host_port;
use crate::error::{CatError, CatResult};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{TcpListener, UdpSocket};

/// Maximum number of upward probe attempts per port role when `auto_shift` is enabled.
const MAX_SHIFT_PROBES: u16 = 512;

/// Lowest safe fallback port used when upward probing wraps past 65535.
const WRAP_MIN_PORT: u16 = 10240;

/// Audit record describing a port that was shifted away from its configured value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortShiftNotice {
    pub role: String,
    pub desired_port: u16,
    pub actual_port: u16,
    pub reason: String,
}

/// Final collision-free port allocation for mixed proxy, controller REST, and DNS listeners.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllocatedPorts {
    pub bind_host: String,
    pub mixed_port: u16,
    pub controller_port: u16,
    pub dns_port: u16,
    pub shifted: Vec<PortShiftNotice>,
}

impl AllocatedPorts {
    pub fn has_shifts(&self) -> bool {
        !self.shifted.is_empty()
    }
}

/// Check whether `host:port` can be bound simultaneously on both TCP and UDP.
///
/// Both listeners are held concurrently inside the check scope so mixed-protocol
/// listeners (such as Mihomo `mixed-port` and DNS UDP/TCP) cannot collide silently.
pub fn is_port_available_tcp_udp(host: &str, port: u16) -> bool {
    if port == 0 {
        return false;
    }
    let normalized = normalize_bind_host(host);
    if normalized == "0.0.0.0" {
        // Probe loopback first (and drop) to catch Windows processes bound exclusively to 127.0.0.1.
        if !can_bind_both_protocols("127.0.0.1", port) {
            return false;
        }
        return can_bind_both_protocols("0.0.0.0", port);
    }
    can_bind_both_protocols(normalized, port)
}

fn can_bind_both_protocols(host: &str, port: u16) -> bool {
    let addr = format_host_port(host, port);
    let tcp_guard = match TcpListener::bind(&addr) {
        Ok(listener) => listener,
        Err(_) => return false,
    };
    let udp_guard = match UdpSocket::bind(&addr) {
        Ok(socket) => socket,
        Err(_) => {
            drop(tcp_guard);
            return false;
        }
    };
    drop(udp_guard);
    drop(tcp_guard);
    true
}

fn normalize_bind_host(host: &str) -> &str {
    let trimmed = host.trim();
    if trimmed.is_empty() || trimmed == "*" {
        "0.0.0.0"
    } else {
        trimmed
    }
}

/// Allocate three mutually distinct, TCP+UDP available ports on `bind_host`.
///
/// - If a desired port is free and distinct from previously allocated roles, it is kept verbatim.
/// - If a desired port is occupied or collides with another role and `auto_shift == true`,
///   probes upward until a free port is found and records a `PortShiftNotice`.
/// - If `auto_shift == false`, returns an explicit `CatError::Core`.
pub fn allocate_safe_ports(
    bind_host: &str,
    desired_mixed: u16,
    desired_controller: u16,
    desired_dns: u16,
    auto_shift: bool,
) -> CatResult<AllocatedPorts> {
    allocate_safe_ports_for_hosts(
        bind_host,
        bind_host,
        bind_host,
        desired_mixed,
        desired_controller,
        desired_dns,
        auto_shift,
    )
}

/// Variant of `allocate_safe_ports` allowing distinct bind hosts per listener role.
pub fn allocate_safe_ports_for_hosts(
    proxy_host: &str,
    controller_host: &str,
    dns_host: &str,
    desired_mixed: u16,
    desired_controller: u16,
    desired_dns: u16,
    auto_shift: bool,
) -> CatResult<AllocatedPorts> {
    let mut reserved = HashSet::with_capacity(3);
    let mut shifted = Vec::new();

    let mixed_port = allocate_single_role(
        "mixed",
        proxy_host,
        desired_mixed,
        auto_shift,
        &mut reserved,
        &mut shifted,
    )?;
    let controller_port = allocate_single_role(
        "controller",
        controller_host,
        desired_controller,
        auto_shift,
        &mut reserved,
        &mut shifted,
    )?;
    let dns_port = allocate_single_role(
        "dns",
        dns_host,
        desired_dns,
        auto_shift,
        &mut reserved,
        &mut shifted,
    )?;

    Ok(AllocatedPorts {
        bind_host: normalize_bind_host(proxy_host).to_string(),
        mixed_port,
        controller_port,
        dns_port,
        shifted,
    })
}

fn allocate_single_role(
    role: &str,
    host: &str,
    desired: u16,
    auto_shift: bool,
    reserved: &mut HashSet<u16>,
    shifted: &mut Vec<PortShiftNotice>,
) -> CatResult<u16> {
    if desired == 0 {
        return Err(CatError::Core(format!(
            "port_guard: desired {role} port cannot be 0"
        )));
    }

    let collision_reason = if reserved.contains(&desired) {
        Some(format!(
            "port {desired} collides with another CatCloud listener role"
        ))
    } else if !is_port_available_tcp_udp(host, desired) {
        Some(format!(
            "port {desired} on `{host}` is already occupied on TCP or UDP"
        ))
    } else {
        None
    };

    if collision_reason.is_none() {
        reserved.insert(desired);
        return Ok(desired);
    }

    let reason = collision_reason.unwrap_or_default();
    if !auto_shift {
        return Err(CatError::Core(format!(
            "port_guard: cannot bind {role} listener ({reason}); auto_shift is disabled"
        )));
    }

    let mut candidate = next_probe_port(desired);
    for _ in 0..MAX_SHIFT_PROBES {
        if !reserved.contains(&candidate) && is_port_available_tcp_udp(host, candidate) {
            reserved.insert(candidate);
            shifted.push(PortShiftNotice {
                role: role.to_string(),
                desired_port: desired,
                actual_port: candidate,
                reason,
            });
            return Ok(candidate);
        }
        candidate = next_probe_port(candidate);
    }

    Err(CatError::Core(format!(
        "port_guard: exhausted {MAX_SHIFT_PROBES} upward probes for {role} port starting from {desired} on `{host}`"
    )))
}

fn next_probe_port(current: u16) -> u16 {
    if current == u16::MAX {
        WRAP_MIN_PORT
    } else {
        current + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reserve_ephemeral_port_pair() -> (u16, TcpListener, UdpSocket) {
        for _ in 0..64 {
            let tcp = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral tcp");
            let port = tcp.local_addr().unwrap().port();
            if let Ok(udp) = UdpSocket::bind(format!("127.0.0.1:{port}")) {
                return (port, tcp, udp);
            }
        }
        panic!("could not reserve ephemeral TCP+UDP test port");
    }

    #[test]
    fn detects_tcp_or_udp_occupancy_accurately() {
        let tcp = TcpListener::bind("127.0.0.1:0").expect("bind tcp");
        let tcp_port = tcp.local_addr().unwrap().port();
        assert!(!is_port_available_tcp_udp("127.0.0.1", tcp_port));
        drop(tcp);

        let udp = UdpSocket::bind("127.0.0.1:0").expect("bind udp");
        let udp_port = udp.local_addr().unwrap().port();
        assert!(!is_port_available_tcp_udp("127.0.0.1", udp_port));
        drop(udp);

        assert!(!is_port_available_tcp_udp("127.0.0.1", 0));
    }

    #[test]
    fn auto_shifts_occupied_ports_and_prevents_role_collisions() {
        let (busy_mixed, _tcp1, _udp1) = reserve_ephemeral_port_pair();
        let (busy_ctrl, _tcp2, _udp2) = reserve_ephemeral_port_pair();
        let (busy_dns, _tcp3, _udp3) = reserve_ephemeral_port_pair();

        let allocated = allocate_safe_ports("127.0.0.1", busy_mixed, busy_ctrl, busy_dns, true)
            .expect("auto_shift must find safe replacement ports");

        assert_ne!(allocated.mixed_port, busy_mixed);
        assert_ne!(allocated.controller_port, busy_ctrl);
        assert_ne!(allocated.dns_port, busy_dns);

        let unique: HashSet<u16> = [
            allocated.mixed_port,
            allocated.controller_port,
            allocated.dns_port,
        ]
        .into_iter()
        .collect();
        assert_eq!(unique.len(), 3);
        assert_eq!(allocated.shifted.len(), 3);
        assert!(allocated.has_shifts());
    }

    #[test]
    fn errors_when_occupied_and_auto_shift_disabled() {
        let (busy_port, _tcp, _udp) = reserve_ephemeral_port_pair();
        let err = allocate_safe_ports("127.0.0.1", busy_port, busy_port, busy_port, false)
            .expect_err("must return error when auto_shift is disabled");
        assert!(matches!(err, CatError::Core(_)));
        assert!(err.to_string().contains("auto_shift is disabled"));
    }

    #[test]
    fn resolves_identical_desired_ports_into_distinct_ports_when_auto_shift_enabled() {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let free_port = probe.local_addr().unwrap().port();
        drop(probe);

        let allocated = allocate_safe_ports("127.0.0.1", free_port, free_port, free_port, true)
            .expect("identical desired ports should shift into 3 distinct ports");

        let unique: HashSet<u16> = [
            allocated.mixed_port,
            allocated.controller_port,
            allocated.dns_port,
        ]
        .into_iter()
        .collect();
        assert_eq!(unique.len(), 3);
        assert!(allocated.shifted.len() >= 2);
    }
}
