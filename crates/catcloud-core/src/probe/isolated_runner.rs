use crate::error::{CatError, CatResult};
use crate::models::{
    PreAccelDispatchStrategy, PreAccelLbStrategy, PreAccelRelay, ProxyNode, is_ipv6_only_node,
};
use crate::preaccel::{
    DEFAULT_DOMESTIC_204_PRIMARY, compile_relay_to_mihomo_yaml, host_to_direct_rule,
    relays_support_ipv6, select_physical_host_relays,
};
use crate::process_guard::JobGuard;
use serde::{Deserialize, Serialize};
use serde_yaml_ng::{Mapping, Value as YamlValue};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::{Child, Command};
use tokio::time::{Instant, sleep};
use uuid::Uuid;

/// Hardcoded loopback bind host for isolated probe cores (never expose `0.0.0.0` or `::`).
pub const ISOLATED_BIND_HOST: &str = "127.0.0.1";

/// Dedicated process filename used by isolated probe cores so the primary Mihomo core can
/// unconditionally bypass probe traffic via `PROCESS-NAME` without TUN hijacking/nesting.
pub const PROBE_CORE_PROCESS_NAME: &str = if cfg!(windows) {
    "catcloud-probe-core.exe"
} else {
    "catcloud-probe-core"
};

/// Pure-IP heterogeneous encrypted (TCP 443 DoH + TCP 853 DoT) bootstrap resolvers for
/// `dns.default-nameserver` inside isolated probe configs. Never include `"system"` here so an
/// active primary-core TUN `dns-hijack: any:53` cannot loop or return Fake-IPs, while remaining
/// resilient against campus networks blocking UDP 53 or throttling single DoH/DoT endpoints.
pub const DEFAULT_PROBE_BOOTSTRAP_NAMESERVERS: &[&str] = &[
    "https://223.5.5.5/dns-query",
    "https://1.12.12.12/dns-query",
    "tls://223.6.6.6:853",
    "tls://120.53.53.53:853",
];

/// Default pure-IP heterogeneous encrypted resolvers used for `proxy-server-nameserver` /
/// `nameserver` so isolated probe DNS completely avoids primary-core TUN `dns-hijack: any:53`.
pub const DEFAULT_PROBE_NAMESERVERS: &[&str] = &[
    "https://223.5.5.5/dns-query",
    "https://1.12.12.12/dns-query",
    "tls://223.6.6.6:853",
    "tls://120.53.53.53:853",
];

/// Memory limit injected into temporary isolated Mihomo probe instances.
pub const ISOLATED_CORE_GOMEMLIMIT: &str = "32MiB";

/// GC percentage injected into temporary isolated Mihomo probe instances.
pub const ISOLATED_CORE_GOGC: &str = "25";

/// Default maximum wait for the isolated Mihomo controller endpoint to become ready.
pub const DEFAULT_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// Local proxy transport scheme used by isolated probe HTTP clients.
/// Local DNS-leaking `socks5://` is intentionally omitted and forbidden.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum IsolatedProxyScheme {
    /// SOCKS5 with remote hostname resolution (`socks5h://127.0.0.1:<port>`).
    #[default]
    Socks5h,
    /// HTTP CONNECT proxy (`http://127.0.0.1:<port>`).
    HttpConnect,
}

impl IsolatedProxyScheme {
    pub fn format_url(&self, proxy_port: u16) -> String {
        match self {
            Self::Socks5h => format!("socks5h://{ISOLATED_BIND_HOST}:{proxy_port}"),
            Self::HttpConnect => format!("http://{ISOLATED_BIND_HOST}:{proxy_port}"),
        }
    }
}

/// Format the local isolated proxy URL for a given port and scheme.
/// Always emits `socks5h://127.0.0.1:<port>` or `http://127.0.0.1:<port>`, never `socks5://`.
pub fn isolated_proxy_url(proxy_port: u16, scheme: IsolatedProxyScheme) -> String {
    scheme.format_url(proxy_port)
}

/// Mapping between a logical `ProxyNode` and its dedicated ephemeral listener on `127.0.0.1`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeProbeBinding {
    pub node_id: String,
    pub proxy_name: String,
    pub listen_port: u16,
}

/// Allocate `count` distinct, collision-free ephemeral ports on `127.0.0.1`.
/// All sockets remain bound until the full batch is reserved so the OS cannot hand out
/// duplicate ports within the same allocation pass; UDP availability on each port is also checked.
pub fn allocate_ephemeral_ports(count: usize) -> CatResult<Vec<u16>> {
    if count == 0 {
        return Ok(Vec::new());
    }

    let mut held_tcp: Vec<TcpListener> = Vec::with_capacity(count);
    let mut held_udp: Vec<UdpSocket> = Vec::with_capacity(count);
    let mut ports: Vec<u16> = Vec::with_capacity(count);
    let mut seen: HashSet<u16> = HashSet::with_capacity(count);
    let max_attempts = count.saturating_mul(8).max(32);

    let mut attempts = 0usize;
    while ports.len() < count {
        attempts += 1;
        if attempts > max_attempts {
            return Err(CatError::Process(format!(
                "failed to allocate {count} collision-free loopback ports after {max_attempts} attempts"
            )));
        }

        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        if port == 0 || seen.contains(&port) {
            continue;
        }

        // Verify UDP availability on the same loopback port to avoid mixed-listener collisions.
        match UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)) {
            Ok(udp) => {
                seen.insert(port);
                ports.push(port);
                held_tcp.push(listener);
                held_udp.push(udp);
            }
            Err(_) => {
                // Keep retrying until we get a clean TCP+UDP port pair.
                continue;
            }
        }
    }

    drop(held_udp);
    drop(held_tcp);
    Ok(ports)
}

/// Canonical proxy name for the optional domestic pre-acceleration relay inside isolated probe cores.
pub const PROBE_RELAY_PROXY_NAME: &str = "catcloud-probe-relay";

/// Outer fallback group name used by multi-cloud pre-acceleration isolated probe pools.
pub const PROBE_RELAY_POOL_GROUP_NAME: &str = "catcloud-probe-relay-pool";

/// Inner load-balance group name used when 2+ distinct physical cloud relays are active in probe pools.
pub const PROBE_RELAY_LB_GROUP_NAME: &str = "catcloud-probe-relay-lb";

/// Resolve deterministic, collision-free proxy names for a slice of bound nodes.
pub fn resolve_unique_proxy_names(bindings: &[(u16, &ProxyNode)]) -> Vec<String> {
    resolve_unique_proxy_names_with_reserved(bindings, None)
}

fn resolve_unique_proxy_names_with_reserved(
    bindings: &[(u16, &ProxyNode)],
    reserved_name: Option<&str>,
) -> Vec<String> {
    let mut reserved: HashSet<String> = HashSet::new();
    if let Some(name) = reserved_name {
        reserved.insert(name.to_string());
    }
    resolve_unique_proxy_names_with_reserved_set(bindings, &reserved)
}

fn resolve_unique_proxy_names_with_reserved_set(
    bindings: &[(u16, &ProxyNode)],
    reserved_names: &HashSet<String>,
) -> Vec<String> {
    let mut used: HashSet<String> = HashSet::with_capacity(bindings.len() + reserved_names.len());
    for reserved in reserved_names {
        used.insert(reserved.clone());
    }
    let mut out = Vec::with_capacity(bindings.len());

    for (idx, (_, node)) in bindings.iter().enumerate() {
        let base = {
            let trimmed = node.name.trim();
            if !trimmed.is_empty() {
                trimmed.to_string()
            } else if !node.id.trim().is_empty() {
                format!("probe-node-{}", node.id.trim())
            } else {
                format!("probe-node-{idx}")
            }
        };

        let mut candidate = base.clone();
        let mut suffix = 1usize;
        while used.contains(&candidate) {
            candidate = format!("{base}#{suffix}");
            suffix += 1;
        }
        used.insert(candidate.clone());
        out.push(candidate);
    }

    out
}

/// Prepare a dedicated probe-core executable under `temp_root` named [`PROBE_CORE_PROCESS_NAME`]
/// so the primary Mihomo core can unconditionally bypass isolated probe traffic via `PROCESS-NAME`
/// without TUN hijacking or nesting.
///
/// Reuses an existing file when its size matches `mihomo_bin`; otherwise prefers a zero-copy
/// `hard_link` and falls back to an atomic copy.
pub fn prepare_probe_core_binary(mihomo_bin: &Path, temp_root: &Path) -> CatResult<PathBuf> {
    if !mihomo_bin.is_file() {
        return Err(CatError::NotFound(format!(
            "isolated probe mihomo binary not found: {}",
            mihomo_bin.display()
        )));
    }

    std::fs::create_dir_all(temp_root)?;
    let src_len = std::fs::metadata(mihomo_bin)?.len();
    let target = temp_root.join(PROBE_CORE_PROCESS_NAME);

    if let Ok(dst_meta) = std::fs::metadata(&target) {
        if dst_meta.is_file() && dst_meta.len() == src_len {
            return Ok(target);
        }
        let _ = std::fs::remove_file(&target);
    }

    if std::fs::hard_link(mihomo_bin, &target).is_ok() {
        return Ok(target);
    }

    // Check whether a concurrent probe spawn already created a matching binary.
    if let Ok(dst_meta) = std::fs::metadata(&target) {
        if dst_meta.is_file() && dst_meta.len() == src_len {
            return Ok(target);
        }
    }

    let tmp_path = temp_root.join(format!(".catcloud-probe-bin-{}.tmp", Uuid::new_v4()));
    if let Err(copy_err) = std::fs::copy(mihomo_bin, &tmp_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(CatError::Process(format!(
            "failed to copy isolated probe core binary `{}` to `{}`: {copy_err}",
            mihomo_bin.display(),
            tmp_path.display()
        )));
    }

    let _ = std::fs::remove_file(&target);
    match std::fs::rename(&tmp_path, &target) {
        Ok(()) => Ok(target),
        Err(rename_err) => {
            let _ = std::fs::remove_file(&tmp_path);
            if let Ok(dst_meta) = std::fs::metadata(&target) {
                if dst_meta.is_file() && dst_meta.len() == src_len {
                    return Ok(target);
                }
            }
            std::fs::copy(mihomo_bin, &target).map_err(|copy_err| {
                CatError::Process(format!(
                    "failed to prepare isolated probe core binary `{}` from `{}` (rename={rename_err}, copy={copy_err})",
                    target.display(),
                    mihomo_bin.display()
                ))
            })?;
            Ok(target)
        }
    }
}

/// Return `true` only for encrypted DNS URLs whose host is a literal IP address
/// (`https://223.5.5.5/dns-query`, `tls://1.12.12.12:853`, etc.) so isolated probe cores
/// never issue plain UDP :53 queries that an active TUN `dns-hijack: any:53` could turn into
/// Fake-IP (`198.18.x.x`) blackholes.
fn is_ip_host_encrypted_dns(raw: &str) -> bool {
    let trimmed = raw.trim();
    let lower = trimmed.to_ascii_lowercase();
    if !(lower.starts_with("https://")
        || lower.starts_with("tls://")
        || lower.starts_with("quic://")
        || lower.starts_with("h3://"))
    {
        return false;
    }
    url::Url::parse(trimmed)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.trim_matches(['[', ']']).to_string()))
        .map(|host| host.parse::<std::net::IpAddr>().is_ok())
        .unwrap_or(false)
}

fn sanitize_isolated_probe_nameservers(input: &[String]) -> Vec<String> {
    let filtered: Vec<String> = input
        .iter()
        .map(|s| s.trim())
        .filter(|s| is_ip_host_encrypted_dns(s))
        .map(ToString::to_string)
        .collect();
    if filtered.is_empty() {
        DEFAULT_PROBE_NAMESERVERS
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    } else {
        filtered
    }
}

/// Generate a strictly isolated, zero-interference Mihomo probe configuration YAML.
///
/// Enforced invariants:
/// - `mixed-port: 0`, `allow-lan: false`, `tun.enable: false`, `geodata-mode: false`
/// - `profile: { store-selected: false, store-fake-ip: false }`
/// - Every `listeners[]` entry forces `listen: 127.0.0.1`, `type: mixed`, and `proxy: <node_proxy_name>`
/// - Explicit `dns: { enable: true, enhanced-mode: redir-host, proxy-server-nameserver: [...], nameserver: [...] }`
///   to prevent active TUN Fake-IP (`198.18.x.x`) pollution.
pub fn build_isolated_probe_yaml(
    controller_port: u16,
    secret: &str,
    bindings: &[(u16, &ProxyNode)],
    proxy_nameservers: &[String],
) -> CatResult<String> {
    build_isolated_probe_yaml_with_preaccel(
        controller_port,
        secret,
        bindings,
        proxy_nameservers,
        None,
        true,
    )
}

/// Generate a strictly isolated, zero-interference Mihomo probe configuration YAML with optional
/// domestic `:443` pre-acceleration relay chaining (`dialer-proxy: catcloud-probe-relay`).
///
/// When `preaccel_relay` is `Some(relay)`:
/// - Compiles the relay into `proxies` as `catcloud-probe-relay`.
/// - Injects `dialer-proxy: catcloud-probe-relay` ONLY on nodes where
///   `node.should_apply_preaccel(skip_443_native)` is `true`; pure UDP transports and skipped
///   native-443 nodes keep `dialer-proxy` stripped.
/// - Prepends `host_to_direct_rule(&relay.server)` at the top of `rules` to prevent routing loops.
pub fn build_isolated_probe_yaml_with_preaccel(
    controller_port: u16,
    secret: &str,
    bindings: &[(u16, &ProxyNode)],
    proxy_nameservers: &[String],
    preaccel_relay: Option<&PreAccelRelay>,
    skip_443_native: bool,
) -> CatResult<String> {
    if controller_port == 0 {
        return Err(CatError::Validation(
            "isolated probe controller_port must be non-zero".into(),
        ));
    }
    if secret.trim().is_empty() {
        return Err(CatError::Validation(
            "isolated probe controller secret cannot be empty".into(),
        ));
    }
    if bindings.is_empty() {
        return Err(CatError::Validation(
            "isolated probe configuration requires at least one node binding".into(),
        ));
    }
    if let Some(relay) = preaccel_relay {
        if relay.server.trim().is_empty() || relay.port == 0 {
            return Err(CatError::Validation(
                "domestic pre-acceleration relay must specify a valid server and port".into(),
            ));
        }
    }

    let mut used_ports: HashSet<u16> = HashSet::with_capacity(bindings.len() + 1);
    used_ports.insert(controller_port);
    for (port, node) in bindings {
        if *port == 0 {
            return Err(CatError::Validation(format!(
                "listener port for node `{}` must be non-zero",
                node.id
            )));
        }
        if !used_ports.insert(*port) {
            return Err(CatError::Validation(format!(
                "duplicate port {port} in isolated probe configuration"
            )));
        }
    }

    let resolved_ns = sanitize_isolated_probe_nameservers(proxy_nameservers);
    let ns_yaml: Vec<YamlValue> = resolved_ns.iter().cloned().map(YamlValue::from).collect();
    let bootstrap_ns_yaml: Vec<YamlValue> = DEFAULT_PROBE_BOOTSTRAP_NAMESERVERS
        .iter()
        .map(|s| YamlValue::from(*s))
        .collect();

    let proxy_names = resolve_unique_proxy_names_with_reserved(
        bindings,
        preaccel_relay.map(|_| PROBE_RELAY_PROXY_NAME),
    );

    let mut root = Mapping::new();
    root.insert(YamlValue::from("mixed-port"), YamlValue::from(0u16));
    root.insert(YamlValue::from("allow-lan"), YamlValue::from(false));
    root.insert(
        YamlValue::from("bind-address"),
        YamlValue::from(ISOLATED_BIND_HOST),
    );
    root.insert(YamlValue::from("mode"), YamlValue::from("rule"));
    root.insert(YamlValue::from("log-level"), YamlValue::from("warning"));
    root.insert(YamlValue::from("ipv6"), YamlValue::from(false));
    root.insert(YamlValue::from("geodata-mode"), YamlValue::from(false));
    root.insert(
        YamlValue::from("external-controller"),
        YamlValue::from(format!("{ISOLATED_BIND_HOST}:{controller_port}")),
    );
    root.insert(YamlValue::from("secret"), YamlValue::from(secret));

    // profile: { store-selected: false, store-fake-ip: false }
    let mut profile = Mapping::new();
    profile.insert(YamlValue::from("store-selected"), YamlValue::from(false));
    profile.insert(YamlValue::from("store-fake-ip"), YamlValue::from(false));
    root.insert(YamlValue::from("profile"), YamlValue::Mapping(profile));

    // tun: { enable: false }
    let mut tun = Mapping::new();
    tun.insert(YamlValue::from("enable"), YamlValue::from(false));
    root.insert(YamlValue::from("tun"), YamlValue::Mapping(tun));

    // Explicit redir-host DNS with pure-IP DoH to defeat active TUN Fake-IP & dns-hijack: any:53
    let mut dns = Mapping::new();
    dns.insert(YamlValue::from("enable"), YamlValue::from(true));
    dns.insert(YamlValue::from("ipv6"), YamlValue::from(false));
    dns.insert(
        YamlValue::from("enhanced-mode"),
        YamlValue::from("redir-host"),
    );
    dns.insert(
        YamlValue::from("default-nameserver"),
        YamlValue::Sequence(bootstrap_ns_yaml),
    );
    dns.insert(
        YamlValue::from("proxy-server-nameserver"),
        YamlValue::Sequence(ns_yaml.clone()),
    );
    dns.insert(
        YamlValue::from("nameserver"),
        YamlValue::Sequence(ns_yaml),
    );
    root.insert(YamlValue::from("dns"), YamlValue::Mapping(dns));

    // proxies & listeners
    let mut proxies_seq: Vec<YamlValue> =
        Vec::with_capacity(bindings.len() + usize::from(preaccel_relay.is_some()));
    let mut listeners_seq: Vec<YamlValue> = Vec::with_capacity(bindings.len());

    if let Some(relay) = preaccel_relay {
        let relay_yaml = compile_relay_to_mihomo_yaml(relay, PROBE_RELAY_PROXY_NAME)?;
        proxies_seq.push(relay_yaml);
    }

    for (idx, ((listen_port, node), proxy_name)) in
        bindings.iter().zip(proxy_names.iter()).enumerate()
    {
        let mut proxy_map = match serde_yaml_ng::to_value(&node.raw_config)? {
            YamlValue::Mapping(map) => map,
            _ => Mapping::new(),
        };

        // Always strip stale `dialer-proxy` first so isolated probe instances never reference
        // groups absent from the minimal ephemeral probe configuration.
        proxy_map.remove("dialer-proxy");

        let skip_for_ipv6 = preaccel_relay.is_some_and(|relay| {
            !relay.supports_ipv6
                && is_ipv6_only_node(node)
                && node.preaccel_override != Some(true)
        });
        if preaccel_relay.is_some()
            && node.should_apply_preaccel(skip_443_native)
            && !skip_for_ipv6
        {
            proxy_map.insert(
                YamlValue::from("dialer-proxy"),
                YamlValue::from(PROBE_RELAY_PROXY_NAME),
            );
        }

        proxy_map.insert(
            YamlValue::from("name"),
            YamlValue::from(proxy_name.as_str()),
        );
        if !proxy_map.contains_key("type") && !node.protocol.trim().is_empty() {
            proxy_map.insert(
                YamlValue::from("type"),
                YamlValue::from(node.protocol.as_str()),
            );
        }
        if !proxy_map.contains_key("server") && !node.server.trim().is_empty() {
            proxy_map.insert(
                YamlValue::from("server"),
                YamlValue::from(node.server.as_str()),
            );
        }
        if !proxy_map.contains_key("port") && node.port > 0 {
            proxy_map.insert(YamlValue::from("port"), YamlValue::from(node.port));
        }

        proxies_seq.push(YamlValue::Mapping(proxy_map));

        let mut listener = Mapping::new();
        listener.insert(
            YamlValue::from("name"),
            YamlValue::from(format!("probe-listener-{idx}")),
        );
        listener.insert(YamlValue::from("type"), YamlValue::from("mixed"));
        listener.insert(YamlValue::from("port"), YamlValue::from(*listen_port));
        listener.insert(
            YamlValue::from("listen"),
            YamlValue::from(ISOLATED_BIND_HOST),
        );
        listener.insert(
            YamlValue::from("proxy"),
            YamlValue::from(proxy_name.as_str()),
        );
        listeners_seq.push(YamlValue::Mapping(listener));
    }

    root.insert(YamlValue::from("proxies"), YamlValue::Sequence(proxies_seq));
    root.insert(
        YamlValue::from("listeners"),
        YamlValue::Sequence(listeners_seq),
    );

    let mut rules_seq: Vec<YamlValue> = Vec::new();
    if let Some(relay) = preaccel_relay {
        if let Some(anti_loop) = host_to_direct_rule(&relay.server) {
            rules_seq.push(YamlValue::from(anti_loop));
        }
    }
    rules_seq.push(YamlValue::from("MATCH,DIRECT"));
    root.insert(YamlValue::from("rules"), YamlValue::Sequence(rules_seq));

    let yaml = serde_yaml_ng::to_string(&YamlValue::Mapping(root))?;
    Ok(yaml)
}

/// Generate a strictly isolated, zero-interference Mihomo probe configuration YAML backed by a
/// multi-cloud domestic `:443` pre-acceleration relay pool.
///
/// Enforced invariants:
/// - Enabled relays are sorted `(priority ASC, id ASC)` and deduplicated by physical cloud host
///   via [`select_physical_host_relays`].
/// - When `distinct_host_count >= 2` and `dispatch_strategy` is `Auto | LoadBalance`:
///   - Inner [`PROBE_RELAY_LB_GROUP_NAME`] (`type: load-balance`, `strategy: lb_strategy.as_str()`,
///     `proxies: [physical-host TCP reps]`, **NEVER contains `DIRECT`**);
///   - Outer [`PROBE_RELAY_POOL_GROUP_NAME`] (`type: fallback`,
///     `proxies: [PROBE_RELAY_LB_GROUP_NAME, same-host secondary protocols..., "DIRECT"]`).
/// - When only 1 physical host is enabled (or `dispatch_strategy == Fallback`):
///   - Single-layer [`PROBE_RELAY_POOL_GROUP_NAME`] (`type: fallback`,
///     `proxies: [catcloud-probe-relay-0..., "DIRECT"]`).
/// - Pure IPv6 business nodes automatically skip IPv4-only relays unless `preaccel_override == Some(true)`.
#[allow(clippy::too_many_arguments)]
pub fn build_isolated_probe_yaml_with_preaccel_pool(
    controller_port: u16,
    secret: &str,
    bindings: &[(u16, &ProxyNode)],
    proxy_nameservers: &[String],
    relays: &[PreAccelRelay],
    dispatch_strategy: PreAccelDispatchStrategy,
    lb_strategy: PreAccelLbStrategy,
    skip_443_native: bool,
) -> CatResult<String> {
    let mut enabled_relays: Vec<PreAccelRelay> =
        relays.iter().filter(|r| r.enabled).cloned().collect();
    if enabled_relays.is_empty() {
        return build_isolated_probe_yaml(controller_port, secret, bindings, proxy_nameservers);
    }
    enabled_relays.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));

    if controller_port == 0 {
        return Err(CatError::Validation(
            "isolated probe controller_port must be non-zero".into(),
        ));
    }
    if secret.trim().is_empty() {
        return Err(CatError::Validation(
            "isolated probe controller secret cannot be empty".into(),
        ));
    }
    if bindings.is_empty() {
        return Err(CatError::Validation(
            "isolated probe configuration requires at least one node binding".into(),
        ));
    }
    for relay in &enabled_relays {
        if relay.server.trim().is_empty() || relay.port == 0 {
            return Err(CatError::Validation(format!(
                "domestic pre-acceleration relay `{}` must specify a valid server and port",
                relay.id
            )));
        }
    }

    let mut used_ports: HashSet<u16> = HashSet::with_capacity(bindings.len() + 1);
    used_ports.insert(controller_port);
    for (port, node) in bindings {
        if *port == 0 {
            return Err(CatError::Validation(format!(
                "listener port for node `{}` must be non-zero",
                node.id
            )));
        }
        if !used_ports.insert(*port) {
            return Err(CatError::Validation(format!(
                "duplicate port {port} in isolated probe configuration"
            )));
        }
    }

    let resolved_ns = sanitize_isolated_probe_nameservers(proxy_nameservers);
    let ns_yaml: Vec<YamlValue> = resolved_ns.iter().cloned().map(YamlValue::from).collect();
    let bootstrap_ns_yaml: Vec<YamlValue> = DEFAULT_PROBE_BOOTSTRAP_NAMESERVERS
        .iter()
        .map(|s| YamlValue::from(*s))
        .collect();

    let mut relay_id_to_proxy_name: HashMap<String, String> =
        HashMap::with_capacity(enabled_relays.len());
    let mut relay_proxy_names_ordered: Vec<String> = Vec::with_capacity(enabled_relays.len());
    let mut reserved_names: HashSet<String> = HashSet::with_capacity(enabled_relays.len() + 2);
    reserved_names.insert(PROBE_RELAY_POOL_GROUP_NAME.to_string());
    reserved_names.insert(PROBE_RELAY_LB_GROUP_NAME.to_string());
    for (idx, relay) in enabled_relays.iter().enumerate() {
        let name = format!("catcloud-probe-relay-{idx}");
        reserved_names.insert(name.clone());
        relay_id_to_proxy_name.insert(relay.id.clone(), name.clone());
        relay_proxy_names_ordered.push(name);
    }

    let proxy_names = resolve_unique_proxy_names_with_reserved_set(bindings, &reserved_names);
    let all_relays_ipv6 = relays_support_ipv6(&enabled_relays);
    let selection = select_physical_host_relays(&enabled_relays);
    let use_two_layer_lb = selection.distinct_host_count >= 2
        && matches!(
            dispatch_strategy,
            PreAccelDispatchStrategy::Auto | PreAccelDispatchStrategy::LoadBalance
        );

    let mut root = Mapping::new();
    root.insert(YamlValue::from("mixed-port"), YamlValue::from(0u16));
    root.insert(YamlValue::from("allow-lan"), YamlValue::from(false));
    root.insert(
        YamlValue::from("bind-address"),
        YamlValue::from(ISOLATED_BIND_HOST),
    );
    root.insert(YamlValue::from("mode"), YamlValue::from("rule"));
    root.insert(YamlValue::from("log-level"), YamlValue::from("warning"));
    root.insert(YamlValue::from("ipv6"), YamlValue::from(false));
    root.insert(YamlValue::from("geodata-mode"), YamlValue::from(false));
    root.insert(
        YamlValue::from("external-controller"),
        YamlValue::from(format!("{ISOLATED_BIND_HOST}:{controller_port}")),
    );
    root.insert(YamlValue::from("secret"), YamlValue::from(secret));

    let mut profile = Mapping::new();
    profile.insert(YamlValue::from("store-selected"), YamlValue::from(false));
    profile.insert(YamlValue::from("store-fake-ip"), YamlValue::from(false));
    root.insert(YamlValue::from("profile"), YamlValue::Mapping(profile));

    let mut tun = Mapping::new();
    tun.insert(YamlValue::from("enable"), YamlValue::from(false));
    root.insert(YamlValue::from("tun"), YamlValue::Mapping(tun));

    let mut dns = Mapping::new();
    dns.insert(YamlValue::from("enable"), YamlValue::from(true));
    dns.insert(YamlValue::from("ipv6"), YamlValue::from(false));
    dns.insert(
        YamlValue::from("enhanced-mode"),
        YamlValue::from("redir-host"),
    );
    dns.insert(
        YamlValue::from("default-nameserver"),
        YamlValue::Sequence(bootstrap_ns_yaml),
    );
    dns.insert(
        YamlValue::from("proxy-server-nameserver"),
        YamlValue::Sequence(ns_yaml.clone()),
    );
    dns.insert(
        YamlValue::from("nameserver"),
        YamlValue::Sequence(ns_yaml),
    );
    root.insert(YamlValue::from("dns"), YamlValue::Mapping(dns));

    // Compile all enabled relays followed by business nodes.
    let mut proxies_seq: Vec<YamlValue> =
        Vec::with_capacity(enabled_relays.len() + bindings.len());
    for (relay, proxy_name) in enabled_relays.iter().zip(relay_proxy_names_ordered.iter()) {
        proxies_seq.push(compile_relay_to_mihomo_yaml(relay, proxy_name)?);
    }

    let mut listeners_seq: Vec<YamlValue> = Vec::with_capacity(bindings.len());
    for (idx, ((listen_port, node), proxy_name)) in
        bindings.iter().zip(proxy_names.iter()).enumerate()
    {
        let mut proxy_map = match serde_yaml_ng::to_value(&node.raw_config)? {
            YamlValue::Mapping(map) => map,
            _ => Mapping::new(),
        };
        proxy_map.remove("dialer-proxy");

        let skip_for_ipv6 =
            !all_relays_ipv6 && is_ipv6_only_node(node) && node.preaccel_override != Some(true);
        if node.should_apply_preaccel(skip_443_native) && !skip_for_ipv6 {
            proxy_map.insert(
                YamlValue::from("dialer-proxy"),
                YamlValue::from(PROBE_RELAY_POOL_GROUP_NAME),
            );
        }

        proxy_map.insert(
            YamlValue::from("name"),
            YamlValue::from(proxy_name.as_str()),
        );
        if !proxy_map.contains_key("type") && !node.protocol.trim().is_empty() {
            proxy_map.insert(
                YamlValue::from("type"),
                YamlValue::from(node.protocol.as_str()),
            );
        }
        if !proxy_map.contains_key("server") && !node.server.trim().is_empty() {
            proxy_map.insert(
                YamlValue::from("server"),
                YamlValue::from(node.server.as_str()),
            );
        }
        if !proxy_map.contains_key("port") && node.port > 0 {
            proxy_map.insert(YamlValue::from("port"), YamlValue::from(node.port));
        }

        proxies_seq.push(YamlValue::Mapping(proxy_map));

        let mut listener = Mapping::new();
        listener.insert(
            YamlValue::from("name"),
            YamlValue::from(format!("probe-listener-{idx}")),
        );
        listener.insert(YamlValue::from("type"), YamlValue::from("mixed"));
        listener.insert(YamlValue::from("port"), YamlValue::from(*listen_port));
        listener.insert(
            YamlValue::from("listen"),
            YamlValue::from(ISOLATED_BIND_HOST),
        );
        listener.insert(
            YamlValue::from("proxy"),
            YamlValue::from(proxy_name.as_str()),
        );
        listeners_seq.push(YamlValue::Mapping(listener));
    }

    // Build pre-acceleration pool proxy-groups (two-layer nested LB or single-layer fallback).
    let mut proxy_groups: Vec<YamlValue> = Vec::with_capacity(if use_two_layer_lb { 2 } else { 1 });
    if use_two_layer_lb {
        let lb_members: Vec<YamlValue> = selection
            .primary_host_relays
            .iter()
            .filter_map(|r| relay_id_to_proxy_name.get(&r.id))
            .filter(|name| !name.eq_ignore_ascii_case("DIRECT"))
            .map(|name| YamlValue::from(name.as_str()))
            .collect();

        let mut fb_members: Vec<YamlValue> = Vec::with_capacity(
            selection.secondary_protocol_relays.len() + 2,
        );
        fb_members.push(YamlValue::from(PROBE_RELAY_LB_GROUP_NAME));
        for relay in &selection.secondary_protocol_relays {
            if let Some(name) = relay_id_to_proxy_name.get(&relay.id) {
                fb_members.push(YamlValue::from(name.as_str()));
            }
        }
        fb_members.push(YamlValue::from("DIRECT"));

        let mut fb_group = Mapping::new();
        fb_group.insert(
            YamlValue::from("name"),
            YamlValue::from(PROBE_RELAY_POOL_GROUP_NAME),
        );
        fb_group.insert(YamlValue::from("type"), YamlValue::from("fallback"));
        fb_group.insert(YamlValue::from("proxies"), YamlValue::Sequence(fb_members));
        fb_group.insert(
            YamlValue::from("url"),
            YamlValue::from(DEFAULT_DOMESTIC_204_PRIMARY),
        );
        fb_group.insert(YamlValue::from("interval"), YamlValue::from(10u64));
        fb_group.insert(YamlValue::from("lazy"), YamlValue::from(false));

        let mut lb_group = Mapping::new();
        lb_group.insert(
            YamlValue::from("name"),
            YamlValue::from(PROBE_RELAY_LB_GROUP_NAME),
        );
        lb_group.insert(YamlValue::from("type"), YamlValue::from("load-balance"));
        lb_group.insert(
            YamlValue::from("strategy"),
            YamlValue::from(lb_strategy.as_str()),
        );
        lb_group.insert(YamlValue::from("proxies"), YamlValue::Sequence(lb_members));
        lb_group.insert(
            YamlValue::from("url"),
            YamlValue::from(DEFAULT_DOMESTIC_204_PRIMARY),
        );
        lb_group.insert(YamlValue::from("interval"), YamlValue::from(10u64));
        lb_group.insert(YamlValue::from("lazy"), YamlValue::from(false));

        proxy_groups.push(YamlValue::Mapping(fb_group));
        proxy_groups.push(YamlValue::Mapping(lb_group));
    } else {
        let mut fb_members: Vec<YamlValue> = relay_proxy_names_ordered
            .iter()
            .map(|name| YamlValue::from(name.as_str()))
            .collect();
        fb_members.push(YamlValue::from("DIRECT"));

        let mut fb_group = Mapping::new();
        fb_group.insert(
            YamlValue::from("name"),
            YamlValue::from(PROBE_RELAY_POOL_GROUP_NAME),
        );
        fb_group.insert(YamlValue::from("type"), YamlValue::from("fallback"));
        fb_group.insert(YamlValue::from("proxies"), YamlValue::Sequence(fb_members));
        fb_group.insert(
            YamlValue::from("url"),
            YamlValue::from(DEFAULT_DOMESTIC_204_PRIMARY),
        );
        fb_group.insert(YamlValue::from("interval"), YamlValue::from(10u64));
        fb_group.insert(YamlValue::from("lazy"), YamlValue::from(false));
        proxy_groups.push(YamlValue::Mapping(fb_group));
    }

    root.insert(YamlValue::from("proxies"), YamlValue::Sequence(proxies_seq));
    root.insert(
        YamlValue::from("proxy-groups"),
        YamlValue::Sequence(proxy_groups),
    );
    root.insert(
        YamlValue::from("listeners"),
        YamlValue::Sequence(listeners_seq),
    );

    let mut rules_seq: Vec<YamlValue> = Vec::new();
    let mut seen_rules: HashSet<String> = HashSet::new();
    for relay in &enabled_relays {
        if let Some(anti_loop) = host_to_direct_rule(&relay.server) {
            if seen_rules.insert(anti_loop.clone()) {
                rules_seq.push(YamlValue::from(anti_loop));
            }
        }
    }
    rules_seq.push(YamlValue::from("MATCH,DIRECT"));
    root.insert(YamlValue::from("rules"), YamlValue::Sequence(rules_seq));

    let yaml = serde_yaml_ng::to_string(&YamlValue::Mapping(root))?;
    Ok(yaml)
}

/// Canonical proxy names inside an ephemeral pre-acceleration A/B comparison Mihomo config.
pub const CMP_RELAY_PROXY_NAME: &str = "catcloud-cmp-relay";
pub const CMP_DIRECT_PROXY_NAME: &str = "catcloud-cmp-direct";
pub const CMP_ACCEL_PROXY_NAME: &str = "catcloud-cmp-accel";

/// Generate a strictly isolated, zero-interference Mihomo YAML configuration for real-world
/// side-by-side comparison benchmarking of domestic pre-acceleration (`dialer-proxy`) vs. direct access.
///
/// Enforced invariants:
/// - Loopback-only (`127.0.0.1`), `mixed-port: 0`, `allow-lan: false`, `tun.enable: false`, `geodata-mode: false`
/// - `dns.enhanced-mode: redir-host` with physical-NIC resolvers to prevent active TUN Fake-IP pollution
/// - `proxies`: 3 entries (`catcloud-cmp-relay`, `catcloud-cmp-direct`, `catcloud-cmp-accel` with `dialer-proxy`)
/// - `listeners`: 2 independent `mixed` listeners (`accel_port` -> `catcloud-cmp-accel`, `direct_port` -> `catcloud-cmp-direct`)
/// - `rules`: top-priority `DIRECT` anti-loop rule for `relay.server`, followed by `MATCH,DIRECT`
pub fn generate_preaccel_comparison_yaml(
    relay: &PreAccelRelay,
    target_node: &ProxyNode,
    accel_port: u16,
    direct_port: u16,
    controller_port: u16,
    secret: &str,
    dns_servers: &[String],
) -> CatResult<String> {
    if accel_port == 0 || direct_port == 0 || controller_port == 0 {
        return Err(CatError::Validation(
            "pre-acceleration comparison ports must all be non-zero".into(),
        ));
    }
    if accel_port == direct_port || accel_port == controller_port || direct_port == controller_port
    {
        return Err(CatError::Validation(
            "pre-acceleration comparison ports (accel, direct, controller) must be distinct".into(),
        ));
    }
    if secret.trim().is_empty() {
        return Err(CatError::Validation(
            "pre-acceleration comparison controller secret cannot be empty".into(),
        ));
    }
    if relay.server.trim().is_empty() || relay.port == 0 {
        return Err(CatError::Validation(
            "domestic pre-acceleration relay must specify a valid server and port".into(),
        ));
    }

    let resolved_ns = sanitize_isolated_probe_nameservers(dns_servers);
    let ns_yaml: Vec<YamlValue> = resolved_ns.iter().cloned().map(YamlValue::from).collect();
    let bootstrap_ns_yaml: Vec<YamlValue> = DEFAULT_PROBE_BOOTSTRAP_NAMESERVERS
        .iter()
        .map(|s| YamlValue::from(*s))
        .collect();

    let mut root = Mapping::new();
    root.insert(YamlValue::from("mixed-port"), YamlValue::from(0u16));
    root.insert(YamlValue::from("allow-lan"), YamlValue::from(false));
    root.insert(
        YamlValue::from("bind-address"),
        YamlValue::from(ISOLATED_BIND_HOST),
    );
    root.insert(YamlValue::from("mode"), YamlValue::from("rule"));
    root.insert(YamlValue::from("log-level"), YamlValue::from("warning"));
    root.insert(YamlValue::from("ipv6"), YamlValue::from(false));
    root.insert(YamlValue::from("geodata-mode"), YamlValue::from(false));
    root.insert(
        YamlValue::from("external-controller"),
        YamlValue::from(format!("{ISOLATED_BIND_HOST}:{controller_port}")),
    );
    root.insert(YamlValue::from("secret"), YamlValue::from(secret));

    let mut profile = Mapping::new();
    profile.insert(YamlValue::from("store-selected"), YamlValue::from(false));
    profile.insert(YamlValue::from("store-fake-ip"), YamlValue::from(false));
    root.insert(YamlValue::from("profile"), YamlValue::Mapping(profile));

    let mut tun = Mapping::new();
    tun.insert(YamlValue::from("enable"), YamlValue::from(false));
    root.insert(YamlValue::from("tun"), YamlValue::Mapping(tun));

    let mut dns = Mapping::new();
    dns.insert(YamlValue::from("enable"), YamlValue::from(true));
    dns.insert(YamlValue::from("ipv6"), YamlValue::from(false));
    dns.insert(
        YamlValue::from("enhanced-mode"),
        YamlValue::from("redir-host"),
    );
    dns.insert(
        YamlValue::from("default-nameserver"),
        YamlValue::Sequence(bootstrap_ns_yaml),
    );
    dns.insert(
        YamlValue::from("proxy-server-nameserver"),
        YamlValue::Sequence(ns_yaml.clone()),
    );
    dns.insert(
        YamlValue::from("nameserver"),
        YamlValue::Sequence(ns_yaml),
    );
    root.insert(YamlValue::from("dns"), YamlValue::Mapping(dns));

    // 1. Domestic relay proxy compiled via preaccel generator
    let relay_yaml = compile_relay_to_mihomo_yaml(relay, CMP_RELAY_PROXY_NAME)?;

    // 2. Direct overseas target node (strip any inherited dialer-proxy)
    let mut direct_map = match serde_yaml_ng::to_value(&target_node.raw_config)? {
        YamlValue::Mapping(map) => map,
        _ => Mapping::new(),
    };
    direct_map.remove("dialer-proxy");
    direct_map.insert(
        YamlValue::from("name"),
        YamlValue::from(CMP_DIRECT_PROXY_NAME),
    );
    if !direct_map.contains_key("type") && !target_node.protocol.trim().is_empty() {
        direct_map.insert(
            YamlValue::from("type"),
            YamlValue::from(target_node.protocol.as_str()),
        );
    }
    if !direct_map.contains_key("server") && !target_node.server.trim().is_empty() {
        direct_map.insert(
            YamlValue::from("server"),
            YamlValue::from(target_node.server.as_str()),
        );
    }
    if !direct_map.contains_key("port") && target_node.port > 0 {
        direct_map.insert(YamlValue::from("port"), YamlValue::from(target_node.port));
    }

    // 3. Accelerated overseas target node (cloned with dialer-proxy pointing to domestic relay)
    let mut accel_map = direct_map.clone();
    accel_map.insert(
        YamlValue::from("name"),
        YamlValue::from(CMP_ACCEL_PROXY_NAME),
    );
    accel_map.insert(
        YamlValue::from("dialer-proxy"),
        YamlValue::from(CMP_RELAY_PROXY_NAME),
    );

    root.insert(
        YamlValue::from("proxies"),
        YamlValue::Sequence(vec![
            relay_yaml,
            YamlValue::Mapping(direct_map),
            YamlValue::Mapping(accel_map),
        ]),
    );

    let mut accel_listener = Mapping::new();
    accel_listener.insert(
        YamlValue::from("name"),
        YamlValue::from("catcloud-cmp-listener-accel"),
    );
    accel_listener.insert(YamlValue::from("type"), YamlValue::from("mixed"));
    accel_listener.insert(YamlValue::from("port"), YamlValue::from(accel_port));
    accel_listener.insert(
        YamlValue::from("listen"),
        YamlValue::from(ISOLATED_BIND_HOST),
    );
    accel_listener.insert(
        YamlValue::from("proxy"),
        YamlValue::from(CMP_ACCEL_PROXY_NAME),
    );

    let mut direct_listener = Mapping::new();
    direct_listener.insert(
        YamlValue::from("name"),
        YamlValue::from("catcloud-cmp-listener-direct"),
    );
    direct_listener.insert(YamlValue::from("type"), YamlValue::from("mixed"));
    direct_listener.insert(YamlValue::from("port"), YamlValue::from(direct_port));
    direct_listener.insert(
        YamlValue::from("listen"),
        YamlValue::from(ISOLATED_BIND_HOST),
    );
    direct_listener.insert(
        YamlValue::from("proxy"),
        YamlValue::from(CMP_DIRECT_PROXY_NAME),
    );

    root.insert(
        YamlValue::from("listeners"),
        YamlValue::Sequence(vec![
            YamlValue::Mapping(accel_listener),
            YamlValue::Mapping(direct_listener),
        ]),
    );

    let mut rules_seq: Vec<YamlValue> = Vec::new();
    if let Some(anti_loop) = host_to_direct_rule(&relay.server) {
        rules_seq.push(YamlValue::from(anti_loop));
    }
    rules_seq.push(YamlValue::from("MATCH,DIRECT"));
    root.insert(YamlValue::from("rules"), YamlValue::Sequence(rules_seq));

    let yaml = serde_yaml_ng::to_string(&YamlValue::Mapping(root))?;
    Ok(yaml)
}

/// Generate a strictly isolated, zero-interference Mihomo YAML configuration for real upload and
/// download throughput measurement of one or more domestic `:443` pre-acceleration relays.
///
/// Enforced invariants:
/// - Loopback-only (`127.0.0.1`), `mixed-port: 0`, `allow-lan: false`, `tun.enable: false`, `geodata-mode: false`
/// - `dns.enhanced-mode: redir-host` with pure-IP DoH to prevent active TUN Fake-IP pollution
/// - Every relay is compiled via `compile_relay_to_mihomo_yaml` (enforcing empty SNI on domestic `:443`)
///   as `cc-rs-relay-{i}`
/// - When `reference_node` is `Some(node)`, `!node.is_udp_only_transport()`, and the relay can
///   reach the reference node (`relay.supports_ipv6 || !is_ipv6_only_node(node)`), that relay gets
///   a chained proxy `cc-rs-chain-{i}` (`dialer-proxy: cc-rs-relay-{i}`) bound to its dedicated
///   loopback listener; otherwise the listener binds directly to `cc-rs-relay-{i}`
/// - Prepends deduplicated anti-loop `DIRECT` rules for every relay server and chained `reference_node.server`
pub fn generate_preaccel_relay_speed_yaml(
    relays: &[PreAccelRelay],
    reference_node: Option<&ProxyNode>,
    relay_ports: &[(String, u16)],
    controller_port: u16,
    secret: &str,
    dns_servers: &[String],
) -> CatResult<String> {
    if controller_port == 0 {
        return Err(CatError::Validation(
            "relay speed test controller_port must be non-zero".into(),
        ));
    }
    if secret.trim().is_empty() {
        return Err(CatError::Validation(
            "relay speed test controller secret cannot be empty".into(),
        ));
    }
    if relays.is_empty() {
        return Err(CatError::Validation(
            "relay speed test requires at least one domestic relay".into(),
        ));
    }
    if relay_ports.len() != relays.len() {
        return Err(CatError::Validation(format!(
            "relay speed test port count ({}) must match relay count ({})",
            relay_ports.len(),
            relays.len()
        )));
    }

    let mut used_ports: HashSet<u16> = HashSet::with_capacity(relays.len() + 1);
    used_ports.insert(controller_port);
    for (rid, port) in relay_ports {
        if *port == 0 {
            return Err(CatError::Validation(format!(
                "listener port for relay `{rid}` must be non-zero"
            )));
        }
        if !used_ports.insert(*port) {
            return Err(CatError::Validation(format!(
                "duplicate port {port} in relay speed test configuration"
            )));
        }
    }

    let mut resolved_ports: Vec<u16> = Vec::with_capacity(relays.len());
    let mut consumed_port_indices: HashSet<usize> = HashSet::with_capacity(relays.len());
    for (idx, relay) in relays.iter().enumerate() {
        if relay.server.trim().is_empty() || relay.port == 0 {
            return Err(CatError::Validation(format!(
                "domestic relay `{}` must specify a valid server and port",
                relay.id
            )));
        }
        if relay_ports[idx].0 == relay.id && consumed_port_indices.insert(idx) {
            resolved_ports.push(relay_ports[idx].1);
        } else if let Some((found_idx, (_, port))) = relay_ports
            .iter()
            .enumerate()
            .find(|(p_idx, (rid, _))| !consumed_port_indices.contains(p_idx) && rid == &relay.id)
        {
            consumed_port_indices.insert(found_idx);
            resolved_ports.push(*port);
        } else {
            return Err(CatError::Validation(format!(
                "missing assigned listener port for relay `{}`",
                relay.id
            )));
        }
    }

    let resolved_ns = sanitize_isolated_probe_nameservers(dns_servers);
    let ns_yaml: Vec<YamlValue> = resolved_ns.iter().cloned().map(YamlValue::from).collect();
    let bootstrap_ns_yaml: Vec<YamlValue> = DEFAULT_PROBE_BOOTSTRAP_NAMESERVERS
        .iter()
        .map(|s| YamlValue::from(*s))
        .collect();

    let mut root = Mapping::new();
    root.insert(YamlValue::from("mixed-port"), YamlValue::from(0u16));
    root.insert(YamlValue::from("allow-lan"), YamlValue::from(false));
    root.insert(
        YamlValue::from("bind-address"),
        YamlValue::from(ISOLATED_BIND_HOST),
    );
    root.insert(YamlValue::from("mode"), YamlValue::from("rule"));
    root.insert(YamlValue::from("log-level"), YamlValue::from("warning"));
    root.insert(YamlValue::from("ipv6"), YamlValue::from(false));
    root.insert(YamlValue::from("geodata-mode"), YamlValue::from(false));
    root.insert(
        YamlValue::from("external-controller"),
        YamlValue::from(format!("{ISOLATED_BIND_HOST}:{controller_port}")),
    );
    root.insert(YamlValue::from("secret"), YamlValue::from(secret));

    let mut profile = Mapping::new();
    profile.insert(YamlValue::from("store-selected"), YamlValue::from(false));
    profile.insert(YamlValue::from("store-fake-ip"), YamlValue::from(false));
    root.insert(YamlValue::from("profile"), YamlValue::Mapping(profile));

    let mut tun = Mapping::new();
    tun.insert(YamlValue::from("enable"), YamlValue::from(false));
    root.insert(YamlValue::from("tun"), YamlValue::Mapping(tun));

    let mut dns = Mapping::new();
    dns.insert(YamlValue::from("enable"), YamlValue::from(true));
    dns.insert(YamlValue::from("ipv6"), YamlValue::from(false));
    dns.insert(
        YamlValue::from("enhanced-mode"),
        YamlValue::from("redir-host"),
    );
    dns.insert(
        YamlValue::from("default-nameserver"),
        YamlValue::Sequence(bootstrap_ns_yaml),
    );
    dns.insert(
        YamlValue::from("proxy-server-nameserver"),
        YamlValue::Sequence(ns_yaml.clone()),
    );
    dns.insert(
        YamlValue::from("nameserver"),
        YamlValue::Sequence(ns_yaml),
    );
    root.insert(YamlValue::from("dns"), YamlValue::Mapping(dns));

    let chain_ref_base: Option<Mapping> = reference_node
        .filter(|node| !node.is_udp_only_transport())
        .map(|node| -> CatResult<Mapping> {
            let mut base = match serde_yaml_ng::to_value(&node.raw_config)? {
                YamlValue::Mapping(map) => map,
                _ => Mapping::new(),
            };
            base.remove("dialer-proxy");
            base.remove("dialer_proxy");
            if !base.contains_key("type") && !node.protocol.trim().is_empty() {
                base.insert(
                    YamlValue::from("type"),
                    YamlValue::from(node.protocol.as_str()),
                );
            }
            if !base.contains_key("server") && !node.server.trim().is_empty() {
                base.insert(
                    YamlValue::from("server"),
                    YamlValue::from(node.server.as_str()),
                );
            }
            if !base.contains_key("port") && node.port > 0 {
                base.insert(YamlValue::from("port"), YamlValue::from(node.port));
            }
            Ok(base)
        })
        .transpose()?;

    let mut proxies_seq: Vec<YamlValue> = Vec::with_capacity(if chain_ref_base.is_some() {
        relays.len() * 2
    } else {
        relays.len()
    });
    let mut listeners_seq: Vec<YamlValue> = Vec::with_capacity(relays.len());
    let mut any_chained_ref = false;

    for (i, (relay, listen_port)) in relays.iter().zip(resolved_ports.into_iter()).enumerate() {
        let relay_name = format!("cc-rs-relay-{i}");
        let relay_yaml = compile_relay_to_mihomo_yaml(relay, &relay_name)?;
        proxies_seq.push(relay_yaml);

        let listener_proxy = if can_chain_relay_with_reference_node(relay, reference_node) {
            if let Some(ref base_map) = chain_ref_base {
                let chain_name = format!("cc-rs-chain-{i}");
                let mut chain_map = base_map.clone();
                chain_map.insert(
                    YamlValue::from("name"),
                    YamlValue::from(chain_name.as_str()),
                );
                chain_map.insert(
                    YamlValue::from("dialer-proxy"),
                    YamlValue::from(relay_name.as_str()),
                );
                proxies_seq.push(YamlValue::Mapping(chain_map));
                any_chained_ref = true;
                chain_name
            } else {
                relay_name
            }
        } else {
            relay_name
        };

        let mut listener = Mapping::new();
        listener.insert(
            YamlValue::from("name"),
            YamlValue::from(format!("cc-rs-listener-{i}")),
        );
        listener.insert(YamlValue::from("type"), YamlValue::from("mixed"));
        listener.insert(YamlValue::from("port"), YamlValue::from(listen_port));
        listener.insert(
            YamlValue::from("listen"),
            YamlValue::from(ISOLATED_BIND_HOST),
        );
        listener.insert(
            YamlValue::from("proxy"),
            YamlValue::from(listener_proxy.as_str()),
        );
        listeners_seq.push(YamlValue::Mapping(listener));
    }

    root.insert(YamlValue::from("proxies"), YamlValue::Sequence(proxies_seq));
    root.insert(
        YamlValue::from("listeners"),
        YamlValue::Sequence(listeners_seq),
    );

    let mut rules_seq: Vec<YamlValue> = Vec::new();
    let mut seen_rules: HashSet<String> = HashSet::new();
    for relay in relays {
        if let Some(rule) = host_to_direct_rule(&relay.server) {
            if seen_rules.insert(rule.to_ascii_lowercase()) {
                rules_seq.push(YamlValue::from(rule));
            }
        }
    }
    if any_chained_ref {
        if let Some(node) = reference_node {
            if let Some(rule) = host_to_direct_rule(&node.server) {
                if seen_rules.insert(rule.to_ascii_lowercase()) {
                    rules_seq.push(YamlValue::from(rule));
                }
            }
        }
    }
    rules_seq.push(YamlValue::from("MATCH,DIRECT"));
    root.insert(YamlValue::from("rules"), YamlValue::Sequence(rules_seq));

    let yaml = serde_yaml_ng::to_string(&YamlValue::Mapping(root))?;
    Ok(yaml)
}

fn can_chain_relay_with_reference_node(
    relay: &PreAccelRelay,
    reference_node: Option<&ProxyNode>,
) -> bool {
    reference_node.is_some_and(|node| {
        !node.is_udp_only_transport() && (relay.supports_ipv6 || !is_ipv6_only_node(node))
    })
}

/// Build an isolated `reqwest::Client` that strips all system/environment proxies (`.no_proxy()`)
/// and explicitly routes traffic through `socks5h://127.0.0.1:<proxy_port>` so DNS is always
/// resolved remotely by the isolated probe core rather than the local host.
pub fn build_isolated_http_client(
    proxy_port: u16,
    timeout: Duration,
) -> CatResult<reqwest::Client> {
    build_isolated_http_client_with_options(
        proxy_port,
        timeout,
        IsolatedProxyScheme::Socks5h,
        true,
        None,
    )
}

/// Build an isolated `reqwest::Client` with full control over proxy scheme (`socks5h://` or
/// HTTP CONNECT `http://`), redirect handling, and HTTP Keep-Alive pool retention.
pub fn build_isolated_http_client_with_options(
    proxy_port: u16,
    timeout: Duration,
    scheme: IsolatedProxyScheme,
    follow_redirects: bool,
    keepalive_idle: Option<Duration>,
) -> CatResult<reqwest::Client> {
    if proxy_port == 0 {
        return Err(CatError::Validation(
            "isolated HTTP client proxy_port must be non-zero".into(),
        ));
    }

    crate::init_crypto_provider();
    let proxy_url = isolated_proxy_url(proxy_port, scheme);
    let proxy = reqwest::Proxy::all(&proxy_url)?;

    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .proxy(proxy)
        .timeout(timeout)
        .connect_timeout(timeout.min(Duration::from_secs(10)));

    if !follow_redirects {
        builder = builder.redirect(reqwest::redirect::Policy::none());
    }

    if let Some(idle) = keepalive_idle {
        builder = builder
            .pool_max_idle_per_host(1)
            .pool_idle_timeout(Some(idle))
            .tcp_keepalive(Some(Duration::from_secs(15)));
    }

    Ok(builder.build()?)
}

/// Build a direct `.no_proxy()` HTTP client used for loopback control API calls and local tests.
pub fn build_direct_no_proxy_client(
    timeout: Duration,
    follow_redirects: bool,
    keepalive_idle: Option<Duration>,
) -> CatResult<reqwest::Client> {
    crate::init_crypto_provider();
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .timeout(timeout)
        .connect_timeout(timeout.min(Duration::from_secs(5)));

    if !follow_redirects {
        builder = builder.redirect(reqwest::redirect::Policy::none());
    }

    if let Some(idle) = keepalive_idle {
        builder = builder
            .pool_max_idle_per_host(1)
            .pool_idle_timeout(Some(idle))
            .tcp_keepalive(Some(Duration::from_secs(15)));
    }

    Ok(builder.build()?)
}

/// Generate a 32-byte (64 hex chars) cryptographic-quality random secret using UUID v4 entropy.
pub fn generate_controller_secret() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

/// RAII cleanup guard active during `IsolatedProbeCore::spawn_with_options`.
/// Ensures that if the spawn future is cancelled/dropped mid-flight (e.g., via `tokio::select!`),
/// any spawned child process is immediately killed and the temporary plaintext YAML/work_dir is removed.
struct SpawnCleanupGuard {
    config_path: PathBuf,
    work_dir: PathBuf,
    child: Option<Child>,
    armed: bool,
}

impl Drop for SpawnCleanupGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
            let _ = child.try_wait();
            drop(child);
        }
        cleanup_work_dir_nonblocking(&self.config_path, &self.work_dir);
        self.armed = false;
    }
}

/// Managed ephemeral Mihomo probe core process with guaranteed cleanup on `shutdown()` and `Drop`.
pub struct IsolatedProbeCore {
    child: Option<Child>,
    child_pid: Option<u32>,
    controller_port: u16,
    secret: String,
    config_path: PathBuf,
    work_dir: PathBuf,
    bindings_by_node: HashMap<String, NodeProbeBinding>,
    ordered_bindings: Vec<NodeProbeBinding>,
    cleaned_up: bool,
}

impl std::fmt::Debug for IsolatedProbeCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IsolatedProbeCore")
            .field("child_pid", &self.child_pid)
            .field("controller_port", &self.controller_port)
            .field("config_path", &self.config_path)
            .field("node_count", &self.ordered_bindings.len())
            .field("cleaned_up", &self.cleaned_up)
            .finish()
    }
}

impl IsolatedProbeCore {
    /// Spawn an isolated temporary Mihomo probe core with `GOMEMLIMIT=32MiB`, `GOGC=25`,
    /// `JobGuard` containment, and controller readiness verification.
    pub async fn spawn(
        mihomo_bin: &Path,
        temp_dir: &Path,
        job_guard: &JobGuard,
        nodes: &[ProxyNode],
    ) -> CatResult<Self> {
        Self::spawn_with_preaccel(mihomo_bin, temp_dir, job_guard, nodes, None, true).await
    }

    /// Spawn an isolated temporary Mihomo probe core optionally chained through a domestic `:443`
    /// pre-acceleration relay for eligible TCP nodes.
    pub async fn spawn_with_preaccel(
        mihomo_bin: &Path,
        temp_root: &Path,
        job_guard: &JobGuard,
        nodes: &[ProxyNode],
        preaccel_relay: Option<&PreAccelRelay>,
        skip_443_native: bool,
    ) -> CatResult<Self> {
        Self::spawn_with_options_and_preaccel(
            mihomo_bin,
            temp_root,
            job_guard,
            nodes,
            &[],
            DEFAULT_READY_TIMEOUT,
            preaccel_relay,
            skip_443_native,
        )
        .await
    }

    /// Spawn an isolated temporary Mihomo probe core with custom physical-NIC DNS nameservers
    /// and readiness timeout.
    pub async fn spawn_with_options(
        mihomo_bin: &Path,
        temp_dir: &Path,
        job_guard: &JobGuard,
        nodes: &[ProxyNode],
        proxy_nameservers: &[String],
        ready_timeout: Duration,
    ) -> CatResult<Self> {
        Self::spawn_with_options_and_preaccel(
            mihomo_bin,
            temp_dir,
            job_guard,
            nodes,
            proxy_nameservers,
            ready_timeout,
            None,
            true,
        )
        .await
    }

    /// Full-control isolated probe core spawn supporting custom DNS, readiness timeout, and
    /// optional domestic `:443` pre-acceleration relay chaining.
    #[allow(clippy::too_many_arguments)]
    pub async fn spawn_with_options_and_preaccel(
        mihomo_bin: &Path,
        temp_dir: &Path,
        job_guard: &JobGuard,
        nodes: &[ProxyNode],
        proxy_nameservers: &[String],
        ready_timeout: Duration,
        preaccel_relay: Option<&PreAccelRelay>,
        skip_443_native: bool,
    ) -> CatResult<Self> {
        if !mihomo_bin.is_file() {
            return Err(CatError::NotFound(format!(
                "isolated probe mihomo binary not found: {}",
                mihomo_bin.display()
            )));
        }
        if nodes.is_empty() {
            return Err(CatError::Validation(
                "cannot spawn IsolatedProbeCore with an empty node list".into(),
            ));
        }

        let ports = allocate_ephemeral_ports(nodes.len() + 1)?;
        let controller_port = ports[0];
        let node_ports = &ports[1..];
        let secret = generate_controller_secret();

        let pair_refs: Vec<(u16, &ProxyNode)> = node_ports
            .iter()
            .copied()
            .zip(nodes.iter())
            .collect();
        let proxy_names = resolve_unique_proxy_names_with_reserved(
            &pair_refs,
            preaccel_relay.map(|_| PROBE_RELAY_PROXY_NAME),
        );
        let yaml = build_isolated_probe_yaml_with_preaccel(
            controller_port,
            &secret,
            &pair_refs,
            proxy_nameservers,
            preaccel_relay,
            skip_443_native,
        )?;

        let work_dir = temp_dir.join(format!("catcloud-probe-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&work_dir)?;
        let config_path = work_dir.join("isolated-probe.yaml");
        let log_path = work_dir.join("probe-core.log");

        let mut cleanup_guard = SpawnCleanupGuard {
            config_path: config_path.clone(),
            work_dir: work_dir.clone(),
            child: None,
            armed: true,
        };

        std::fs::write(&config_path, yaml.as_bytes())?;

        let stderr_stdio = match std::fs::File::create(&log_path) {
            Ok(file) => Stdio::from(file),
            Err(_) => Stdio::null(),
        };

        let probe_bin = prepare_probe_core_binary(mihomo_bin, temp_dir)?;
        let norm_bin = crate::paths::normalize_os_path(&probe_bin);
        let norm_work = crate::paths::normalize_os_path(&work_dir);
        let norm_cfg = crate::paths::normalize_os_path(&config_path);

        let mut cmd = Command::new(&norm_bin);
        cmd.arg("-d")
            .arg(&norm_work)
            .arg("-f")
            .arg(&norm_cfg)
            .env("GOMEMLIMIT", ISOLATED_CORE_GOMEMLIMIT)
            .env("GOGC", ISOLATED_CORE_GOGC)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr_stdio)
            .kill_on_drop(true);
        JobGuard::configure_tokio_command(&mut cmd);

        let child = cmd.spawn().map_err(|err| {
            CatError::Process(format!(
                "failed to spawn isolated probe core `{}`: {err}",
                probe_bin.display()
            ))
        })?;
        cleanup_guard.child = Some(child);

        if let Err(err) = job_guard.assign_tokio_child(
            cleanup_guard
                .child
                .as_mut()
                .expect("child assigned to spawn cleanup guard"),
        ) {
            if let Some(mut c) = cleanup_guard.child.take() {
                let _ = c.kill().await;
                let _ = c.wait().await;
            }
            remove_work_dir_async(&config_path, &work_dir).await;
            cleanup_guard.armed = false;
            return Err(err);
        }

        let child_pid = cleanup_guard.child.as_ref().and_then(Child::id);

        if let Err(err) = wait_for_controller_ready(
            controller_port,
            &secret,
            cleanup_guard
                .child
                .as_mut()
                .expect("child held by spawn cleanup guard"),
            &log_path,
            ready_timeout,
        )
        .await
        {
            if let Some(mut c) = cleanup_guard.child.take() {
                let _ = c.kill().await;
                let _ = c.wait().await;
            }
            remove_work_dir_async(&config_path, &work_dir).await;
            cleanup_guard.armed = false;
            return Err(err);
        }

        let mut ordered_bindings = Vec::with_capacity(nodes.len());
        let mut bindings_by_node = HashMap::with_capacity(nodes.len());
        for ((port, node), proxy_name) in pair_refs.iter().zip(proxy_names.into_iter()) {
            let binding = NodeProbeBinding {
                node_id: node.id.clone(),
                proxy_name,
                listen_port: *port,
            };
            bindings_by_node.insert(node.id.clone(), binding.clone());
            ordered_bindings.push(binding);
        }

        let child = cleanup_guard.child.take();
        cleanup_guard.armed = false;

        Ok(Self {
            child,
            child_pid,
            controller_port,
            secret,
            config_path,
            work_dir,
            bindings_by_node,
            ordered_bindings,
            cleaned_up: false,
        })
    }

    /// Spawn an isolated temporary Mihomo instance backed by a multi-cloud domestic `:443`
    /// pre-acceleration relay pool (two-layer nested `load-balance` + outer `fallback` when 2+
    /// physical hosts are enabled).
    #[allow(clippy::too_many_arguments)]
    pub async fn spawn_with_options_and_preaccel_pool(
        mihomo_bin: &Path,
        temp_dir: &Path,
        job_guard: &JobGuard,
        nodes: &[ProxyNode],
        proxy_nameservers: &[String],
        ready_timeout: Duration,
        relays: &[PreAccelRelay],
        dispatch_strategy: PreAccelDispatchStrategy,
        lb_strategy: PreAccelLbStrategy,
        skip_443_native: bool,
    ) -> CatResult<Self> {
        let mut enabled_relays: Vec<PreAccelRelay> =
            relays.iter().filter(|r| r.enabled).cloned().collect();
        if enabled_relays.is_empty() {
            return Self::spawn_with_options_and_preaccel(
                mihomo_bin,
                temp_dir,
                job_guard,
                nodes,
                proxy_nameservers,
                ready_timeout,
                None,
                skip_443_native,
            )
            .await;
        }
        enabled_relays.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));

        if !mihomo_bin.is_file() {
            return Err(CatError::NotFound(format!(
                "isolated probe mihomo binary not found: {}",
                mihomo_bin.display()
            )));
        }
        if nodes.is_empty() {
            return Err(CatError::Validation(
                "cannot spawn IsolatedProbeCore with an empty node list".into(),
            ));
        }

        let ports = allocate_ephemeral_ports(nodes.len() + 1)?;
        let controller_port = ports[0];
        let node_ports = &ports[1..];
        let secret = generate_controller_secret();

        let pair_refs: Vec<(u16, &ProxyNode)> = node_ports
            .iter()
            .copied()
            .zip(nodes.iter())
            .collect();
        let mut reserved_names: HashSet<String> = HashSet::with_capacity(enabled_relays.len() + 2);
        reserved_names.insert(PROBE_RELAY_POOL_GROUP_NAME.to_string());
        reserved_names.insert(PROBE_RELAY_LB_GROUP_NAME.to_string());
        for idx in 0..enabled_relays.len() {
            reserved_names.insert(format!("catcloud-probe-relay-{idx}"));
        }
        let proxy_names = resolve_unique_proxy_names_with_reserved_set(&pair_refs, &reserved_names);
        let yaml = build_isolated_probe_yaml_with_preaccel_pool(
            controller_port,
            &secret,
            &pair_refs,
            proxy_nameservers,
            &enabled_relays,
            dispatch_strategy,
            lb_strategy,
            skip_443_native,
        )?;

        let work_dir = temp_dir.join(format!("catcloud-probe-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&work_dir)?;
        let config_path = work_dir.join("isolated-probe.yaml");
        let log_path = work_dir.join("probe-core.log");

        let mut cleanup_guard = SpawnCleanupGuard {
            config_path: config_path.clone(),
            work_dir: work_dir.clone(),
            child: None,
            armed: true,
        };

        std::fs::write(&config_path, yaml.as_bytes())?;

        let stderr_stdio = match std::fs::File::create(&log_path) {
            Ok(file) => Stdio::from(file),
            Err(_) => Stdio::null(),
        };

        let probe_bin = prepare_probe_core_binary(mihomo_bin, temp_dir)?;
        let norm_bin = crate::paths::normalize_os_path(&probe_bin);
        let norm_work = crate::paths::normalize_os_path(&work_dir);
        let norm_cfg = crate::paths::normalize_os_path(&config_path);

        let mut cmd = Command::new(&norm_bin);
        cmd.arg("-d")
            .arg(&norm_work)
            .arg("-f")
            .arg(&norm_cfg)
            .env("GOMEMLIMIT", ISOLATED_CORE_GOMEMLIMIT)
            .env("GOGC", ISOLATED_CORE_GOGC)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr_stdio)
            .kill_on_drop(true);
        JobGuard::configure_tokio_command(&mut cmd);

        let child = cmd.spawn().map_err(|err| {
            CatError::Process(format!(
                "failed to spawn isolated probe core `{}`: {err}",
                probe_bin.display()
            ))
        })?;
        cleanup_guard.child = Some(child);

        if let Err(err) = job_guard.assign_tokio_child(
            cleanup_guard
                .child
                .as_mut()
                .expect("child assigned to spawn cleanup guard"),
        ) {
            if let Some(mut c) = cleanup_guard.child.take() {
                let _ = c.kill().await;
                let _ = c.wait().await;
            }
            remove_work_dir_async(&config_path, &work_dir).await;
            cleanup_guard.armed = false;
            return Err(err);
        }

        let child_pid = cleanup_guard.child.as_ref().and_then(Child::id);

        if let Err(err) = wait_for_controller_ready(
            controller_port,
            &secret,
            cleanup_guard
                .child
                .as_mut()
                .expect("child held by spawn cleanup guard"),
            &log_path,
            ready_timeout,
        )
        .await
        {
            if let Some(mut c) = cleanup_guard.child.take() {
                let _ = c.kill().await;
                let _ = c.wait().await;
            }
            remove_work_dir_async(&config_path, &work_dir).await;
            cleanup_guard.armed = false;
            return Err(err);
        }

        let mut ordered_bindings = Vec::with_capacity(nodes.len());
        let mut bindings_by_node = HashMap::with_capacity(nodes.len());
        for ((port, node), proxy_name) in pair_refs.iter().zip(proxy_names.into_iter()) {
            let binding = NodeProbeBinding {
                node_id: node.id.clone(),
                proxy_name,
                listen_port: *port,
            };
            bindings_by_node.insert(node.id.clone(), binding.clone());
            ordered_bindings.push(binding);
        }

        let child = cleanup_guard.child.take();
        cleanup_guard.armed = false;

        Ok(Self {
            child,
            child_pid,
            controller_port,
            secret,
            config_path,
            work_dir,
            bindings_by_node,
            ordered_bindings,
            cleaned_up: false,
        })
    }

    /// Spawn an isolated temporary Mihomo instance wired for side-by-side domestic pre-acceleration
    /// comparison (`accel_port` -> target node via domestic relay; `direct_port` -> direct target node).
    /// Returns `(core, accel_port, direct_port)` with RAII process & work-dir cleanup guarantees.
    pub async fn spawn_for_preaccel_comparison(
        mihomo_bin: &Path,
        temp_dir: &Path,
        job_guard: &JobGuard,
        relay: &PreAccelRelay,
        target_node: &ProxyNode,
        dns_servers: &[String],
        ready_timeout: Duration,
    ) -> CatResult<(Self, u16, u16)> {
        if !mihomo_bin.is_file() {
            return Err(CatError::NotFound(format!(
                "isolated probe mihomo binary not found: {}",
                mihomo_bin.display()
            )));
        }

        let ports = allocate_ephemeral_ports(3)?;
        let controller_port = ports[0];
        let accel_port = ports[1];
        let direct_port = ports[2];
        let secret = generate_controller_secret();

        let yaml = generate_preaccel_comparison_yaml(
            relay,
            target_node,
            accel_port,
            direct_port,
            controller_port,
            &secret,
            dns_servers,
        )?;

        let work_dir = temp_dir.join(format!("catcloud-preaccel-cmp-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&work_dir)?;
        let config_path = work_dir.join("isolated-preaccel-cmp.yaml");
        let log_path = work_dir.join("probe-core.log");

        let mut cleanup_guard = SpawnCleanupGuard {
            config_path: config_path.clone(),
            work_dir: work_dir.clone(),
            child: None,
            armed: true,
        };

        std::fs::write(&config_path, yaml.as_bytes())?;

        let stderr_stdio = match std::fs::File::create(&log_path) {
            Ok(file) => Stdio::from(file),
            Err(_) => Stdio::null(),
        };

        let probe_bin = prepare_probe_core_binary(mihomo_bin, temp_dir)?;
        let norm_bin = crate::paths::normalize_os_path(&probe_bin);
        let norm_work = crate::paths::normalize_os_path(&work_dir);
        let norm_cfg = crate::paths::normalize_os_path(&config_path);

        let mut cmd = Command::new(&norm_bin);
        cmd.arg("-d")
            .arg(&norm_work)
            .arg("-f")
            .arg(&norm_cfg)
            .env("GOMEMLIMIT", ISOLATED_CORE_GOMEMLIMIT)
            .env("GOGC", ISOLATED_CORE_GOGC)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr_stdio)
            .kill_on_drop(true);
        JobGuard::configure_tokio_command(&mut cmd);

        let child = cmd.spawn().map_err(|err| {
            CatError::Process(format!(
                "failed to spawn isolated comparison core `{}`: {err}",
                probe_bin.display()
            ))
        })?;
        cleanup_guard.child = Some(child);

        if let Err(err) = job_guard.assign_tokio_child(
            cleanup_guard
                .child
                .as_mut()
                .expect("child assigned to spawn cleanup guard"),
        ) {
            if let Some(mut c) = cleanup_guard.child.take() {
                let _ = c.kill().await;
                let _ = c.wait().await;
            }
            remove_work_dir_async(&config_path, &work_dir).await;
            cleanup_guard.armed = false;
            return Err(err);
        }

        let child_pid = cleanup_guard.child.as_ref().and_then(Child::id);

        if let Err(err) = wait_for_controller_ready(
            controller_port,
            &secret,
            cleanup_guard
                .child
                .as_mut()
                .expect("child held by spawn cleanup guard"),
            &log_path,
            ready_timeout,
        )
        .await
        {
            if let Some(mut c) = cleanup_guard.child.take() {
                let _ = c.kill().await;
                let _ = c.wait().await;
            }
            remove_work_dir_async(&config_path, &work_dir).await;
            cleanup_guard.armed = false;
            return Err(err);
        }

        let accel_binding = NodeProbeBinding {
            node_id: CMP_ACCEL_PROXY_NAME.to_string(),
            proxy_name: CMP_ACCEL_PROXY_NAME.to_string(),
            listen_port: accel_port,
        };
        let direct_binding = NodeProbeBinding {
            node_id: CMP_DIRECT_PROXY_NAME.to_string(),
            proxy_name: CMP_DIRECT_PROXY_NAME.to_string(),
            listen_port: direct_port,
        };
        let mut bindings_by_node = HashMap::with_capacity(2);
        bindings_by_node.insert(CMP_ACCEL_PROXY_NAME.to_string(), accel_binding.clone());
        bindings_by_node.insert(CMP_DIRECT_PROXY_NAME.to_string(), direct_binding.clone());
        let ordered_bindings = vec![accel_binding, direct_binding];

        let child = cleanup_guard.child.take();
        cleanup_guard.armed = false;

        let core = Self {
            child,
            child_pid,
            controller_port,
            secret,
            config_path,
            work_dir,
            bindings_by_node,
            ordered_bindings,
            cleaned_up: false,
        };

        Ok((core, accel_port, direct_port))
    }

    /// Spawn an isolated temporary Mihomo instance wired for real upload/download speed testing
    /// across one or more domestic `:443` pre-acceleration relays (optionally chained to a TCP
    /// overseas `reference_node` via `dialer-proxy`).
    /// Returns `(core, relay_ports)` where `relay_ports` maps each `relay.id` to its dedicated
    /// `127.0.0.1` loopback mixed listener port, with full RAII process & work-dir cleanup.
    pub async fn spawn_for_preaccel_relay_speeds(
        mihomo_bin: &Path,
        temp_dir: &Path,
        job_guard: &JobGuard,
        relays: &[PreAccelRelay],
        reference_node: Option<&ProxyNode>,
        dns_servers: &[String],
        ready_timeout: Duration,
    ) -> CatResult<(Self, Vec<(String, u16)>)> {
        if !mihomo_bin.is_file() {
            return Err(CatError::NotFound(format!(
                "isolated probe mihomo binary not found: {}",
                mihomo_bin.display()
            )));
        }
        if relays.is_empty() {
            return Err(CatError::Validation(
                "cannot spawn relay speed probe core with an empty relay list".into(),
            ));
        }

        let ports = allocate_ephemeral_ports(relays.len() + 1)?;
        let controller_port = ports[0];
        let relay_ports: Vec<(String, u16)> = relays
            .iter()
            .zip(ports[1..].iter().copied())
            .map(|(relay, port)| (relay.id.clone(), port))
            .collect();
        let secret = generate_controller_secret();

        let yaml = generate_preaccel_relay_speed_yaml(
            relays,
            reference_node,
            &relay_ports,
            controller_port,
            &secret,
            dns_servers,
        )?;

        let work_dir = temp_dir.join(format!("catcloud-relay-speed-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&work_dir)?;
        let config_path = work_dir.join("isolated-relay-speed.yaml");
        let log_path = work_dir.join("probe-core.log");

        let mut cleanup_guard = SpawnCleanupGuard {
            config_path: config_path.clone(),
            work_dir: work_dir.clone(),
            child: None,
            armed: true,
        };

        std::fs::write(&config_path, yaml.as_bytes())?;

        let stderr_stdio = match std::fs::File::create(&log_path) {
            Ok(file) => Stdio::from(file),
            Err(_) => Stdio::null(),
        };

        let probe_bin = prepare_probe_core_binary(mihomo_bin, temp_dir)?;
        let norm_bin = crate::paths::normalize_os_path(&probe_bin);
        let norm_work = crate::paths::normalize_os_path(&work_dir);
        let norm_cfg = crate::paths::normalize_os_path(&config_path);

        let mut cmd = Command::new(&norm_bin);
        cmd.arg("-d")
            .arg(&norm_work)
            .arg("-f")
            .arg(&norm_cfg)
            .env("GOMEMLIMIT", ISOLATED_CORE_GOMEMLIMIT)
            .env("GOGC", ISOLATED_CORE_GOGC)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr_stdio)
            .kill_on_drop(true);
        JobGuard::configure_tokio_command(&mut cmd);

        let child = cmd.spawn().map_err(|err| {
            CatError::Process(format!(
                "failed to spawn isolated relay speed core `{}`: {err}",
                probe_bin.display()
            ))
        })?;
        cleanup_guard.child = Some(child);

        if let Err(err) = job_guard.assign_tokio_child(
            cleanup_guard
                .child
                .as_mut()
                .expect("child assigned to spawn cleanup guard"),
        ) {
            if let Some(mut c) = cleanup_guard.child.take() {
                let _ = c.kill().await;
                let _ = c.wait().await;
            }
            remove_work_dir_async(&config_path, &work_dir).await;
            cleanup_guard.armed = false;
            return Err(err);
        }

        let child_pid = cleanup_guard.child.as_ref().and_then(Child::id);

        if let Err(err) = wait_for_controller_ready(
            controller_port,
            &secret,
            cleanup_guard
                .child
                .as_mut()
                .expect("child held by spawn cleanup guard"),
            &log_path,
            ready_timeout,
        )
        .await
        {
            if let Some(mut c) = cleanup_guard.child.take() {
                let _ = c.kill().await;
                let _ = c.wait().await;
            }
            remove_work_dir_async(&config_path, &work_dir).await;
            cleanup_guard.armed = false;
            return Err(err);
        }

        let mut ordered_bindings = Vec::with_capacity(relay_ports.len());
        let mut bindings_by_node = HashMap::with_capacity(relay_ports.len());
        for (i, (relay, (relay_id, listen_port))) in
            relays.iter().zip(relay_ports.iter()).enumerate()
        {
            let use_chain = can_chain_relay_with_reference_node(relay, reference_node);
            let proxy_name = if use_chain {
                format!("cc-rs-chain-{i}")
            } else {
                format!("cc-rs-relay-{i}")
            };
            let binding = NodeProbeBinding {
                node_id: relay_id.clone(),
                proxy_name,
                listen_port: *listen_port,
            };
            bindings_by_node.insert(relay_id.clone(), binding.clone());
            ordered_bindings.push(binding);
        }

        let child = cleanup_guard.child.take();
        cleanup_guard.armed = false;

        let core = Self {
            child,
            child_pid,
            controller_port,
            secret,
            config_path,
            work_dir,
            bindings_by_node,
            ordered_bindings,
            cleaned_up: false,
        };

        Ok((core, relay_ports))
    }

    pub fn controller_port(&self) -> u16 {
        self.controller_port
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }

    pub fn child_pid(&self) -> Option<u32> {
        self.child_pid
    }

    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub fn work_dir(&self) -> &Path {
        &self.work_dir
    }

    pub fn port_for_node(&self, node_id: &str) -> Option<u16> {
        self.bindings_by_node.get(node_id).map(|b| b.listen_port)
    }

    pub fn binding_for_node(&self, node_id: &str) -> Option<&NodeProbeBinding> {
        self.bindings_by_node.get(node_id)
    }

    pub fn bindings(&self) -> &[NodeProbeBinding] {
        &self.ordered_bindings
    }

    /// Build an isolated `reqwest::Client` targeting a specific bound node via `socks5h://`.
    pub fn client_for_node(
        &self,
        node_id: &str,
        timeout: Duration,
    ) -> CatResult<reqwest::Client> {
        let port = self
            .port_for_node(node_id)
            .ok_or_else(|| CatError::NotFound(format!("node `{node_id}` is not bound in probe core")))?;
        build_isolated_http_client(port, timeout)
    }

    /// Deterministically terminate the isolated core child process, reap it, and remove all
    /// temporary YAML/log files leaving zero residue and zero interference with active traffic.
    pub async fn shutdown(mut self) -> CatResult<()> {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        remove_work_dir_async(&self.config_path, &self.work_dir).await;
        self.cleaned_up = true;
        Ok(())
    }
}

impl Drop for IsolatedProbeCore {
    fn drop(&mut self) {
        if self.cleaned_up {
            return;
        }
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
            let _ = child.try_wait();
            drop(child);
        }
        cleanup_work_dir_nonblocking(&self.config_path, &self.work_dir);
        self.cleaned_up = true;
    }
}

async fn wait_for_controller_ready(
    controller_port: u16,
    secret: &str,
    child: &mut Child,
    log_path: &Path,
    ready_timeout: Duration,
) -> CatResult<()> {
    let client = build_direct_no_proxy_client(Duration::from_millis(600), false, None)?;
    let url = format!("http://{ISOLATED_BIND_HOST}:{controller_port}/version");
    let auth_header = format!("Bearer {secret}");
    let deadline = Instant::now() + ready_timeout;

    loop {
        if let Some(status) = child.try_wait()? {
            let stderr_tail = read_log_tail(log_path);
            return Err(CatError::Process(format!(
                "isolated probe core exited prematurely with status {status}{stderr_tail}"
            )));
        }

        if let Ok(resp) = client
            .get(&url)
            .header(reqwest::header::AUTHORIZATION, &auth_header)
            .send()
            .await
        {
            if resp.status().is_success() {
                return Ok(());
            }
        }

        if Instant::now() >= deadline {
            let stderr_tail = read_log_tail(log_path);
            return Err(CatError::Process(format!(
                "isolated probe core controller 127.0.0.1:{controller_port} did not become ready within {:.1}s{stderr_tail}",
                ready_timeout.as_secs_f64()
            )));
        }

        sleep(Duration::from_millis(40)).await;
    }
}

fn read_log_tail(log_path: &Path) -> String {
    let Ok(content) = std::fs::read_to_string(log_path) else {
        return String::new();
    };
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let tail: String = trimmed
        .chars()
        .rev()
        .take(400)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("; stderr: {tail}")
}

async fn remove_work_dir_async(config_path: &Path, work_dir: &Path) {
    for attempt in 0..4 {
        let _ = std::fs::remove_file(config_path);
        match std::fs::remove_dir_all(work_dir) {
            Ok(()) => return,
            Err(_) if !work_dir.exists() => return,
            Err(_) if attempt < 3 => sleep(Duration::from_millis(25)).await,
            Err(_) => break,
        }
    }
    if work_dir.exists() {
        spawn_deferred_work_dir_cleanup(config_path.to_path_buf(), work_dir.to_path_buf());
    }
}

fn cleanup_work_dir_nonblocking(config_path: &Path, work_dir: &Path) {
    let _ = std::fs::remove_file(config_path);
    if std::fs::remove_dir_all(work_dir).is_ok() || !work_dir.exists() {
        return;
    }
    spawn_deferred_work_dir_cleanup(config_path.to_path_buf(), work_dir.to_path_buf());
}

fn spawn_deferred_work_dir_cleanup(config_path: PathBuf, work_dir: PathBuf) {
    let _ = std::thread::Builder::new()
        .name("catcloud-probe-cleanup".into())
        .spawn(move || {
            for attempt in 0..6 {
                std::thread::sleep(Duration::from_millis(30 * (attempt + 1)));
                let _ = std::fs::remove_file(&config_path);
                match std::fs::remove_dir_all(&work_dir) {
                    Ok(()) => return,
                    Err(_) if !work_dir.exists() => return,
                    Err(_) => {}
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_node(id: &str, name: &str) -> ProxyNode {
        ProxyNode {
            id: id.to_string(),
            sub_id: "sub-test".to_string(),
            name: name.to_string(),
            protocol: "trojan".to_string(),
            server: format!("{id}.example.invalid"),
            port: 443,
            raw_config: serde_json::json!({
                "name": name,
                "type": "trojan",
                "server": format!("{id}.example.invalid"),
                "port": 443,
                "password": "test-placeholder-password",
                "udp": true
            }),
            region_code: "JP".to_string(),
            multiplier: 1.0,
            is_443_native: true,
            preaccel_eligible: false,
            preaccel_override: None,
            tags: Vec::new(),
            enabled: true,
        }
    }

    #[test]
    fn ephemeral_ports_are_unique_and_non_zero() {
        let ports = allocate_ephemeral_ports(6).expect("allocate 6 ports");
        assert_eq!(ports.len(), 6);
        let unique: HashSet<u16> = ports.iter().copied().collect();
        assert_eq!(unique.len(), 6);
        assert!(ports.iter().all(|&p| p > 0));
    }

    #[test]
    fn isolated_yaml_enforces_all_zero_interference_invariants() {
        let node_a = sample_node("n1", "JP-Edge-01");
        let node_b = sample_node("n2", "JP-Edge-01"); // duplicate name tests deduplication
        let ports = allocate_ephemeral_ports(3).unwrap();
        let bindings = vec![(ports[1], &node_a), (ports[2], &node_b)];

        let yaml_text = build_isolated_probe_yaml(ports[0], "secret-token-32bytes", &bindings, &[])
            .expect("build isolated yaml");

        let parsed: YamlValue = serde_yaml_ng::from_str(&yaml_text).expect("valid yaml");
        assert_eq!(parsed["mixed-port"].as_u64(), Some(0));
        assert_eq!(parsed["allow-lan"].as_bool(), Some(false));
        assert_eq!(parsed["bind-address"].as_str(), Some("127.0.0.1"));
        assert_eq!(parsed["geodata-mode"].as_bool(), Some(false));
        assert_eq!(parsed["tun"]["enable"].as_bool(), Some(false));
        assert_eq!(parsed["profile"]["store-selected"].as_bool(), Some(false));
        assert_eq!(parsed["profile"]["store-fake-ip"].as_bool(), Some(false));
        assert_eq!(
            parsed["external-controller"].as_str(),
            Some(format!("127.0.0.1:{}", ports[0]).as_str())
        );

        // DNS must explicitly use redir-host with pure-IP bootstrap & pure-IP DoH to defeat
        // active TUN Fake-IP and `dns-hijack: any:53` interception
        assert_eq!(parsed["dns"]["enable"].as_bool(), Some(true));
        assert_eq!(parsed["dns"]["enhanced-mode"].as_str(), Some("redir-host"));
        let dns_bootstrap = parsed["dns"]["default-nameserver"]
            .as_sequence()
            .expect("default-nameserver sequence");
        assert_eq!(
            dns_bootstrap[0].as_str(),
            Some("https://223.5.5.5/dns-query")
        );
        assert_eq!(
            dns_bootstrap[1].as_str(),
            Some("https://1.12.12.12/dns-query")
        );
        assert!(
            !dns_bootstrap
                .iter()
                .any(|v| v.as_str() == Some("system")),
            "isolated probe default-nameserver must never include `system`"
        );
        let psn = parsed["dns"]["proxy-server-nameserver"]
            .as_sequence()
            .expect("proxy-server-nameserver sequence");
        assert_eq!(psn[0].as_str(), Some("https://223.5.5.5/dns-query"));
        assert_eq!(psn[1].as_str(), Some("https://1.12.12.12/dns-query"));
        let ns = parsed["dns"]["nameserver"]
            .as_sequence()
            .expect("nameserver sequence");
        assert_eq!(ns[0].as_str(), Some("https://223.5.5.5/dns-query"));
        assert_eq!(ns[1].as_str(), Some("https://1.12.12.12/dns-query"));

        // Every listener must bind 127.0.0.1 with type: mixed and match unique proxy names
        let listeners = parsed["listeners"].as_sequence().expect("listeners");
        let proxies = parsed["proxies"].as_sequence().expect("proxies");
        assert_eq!(listeners.len(), 2);
        assert_eq!(proxies.len(), 2);

        assert_eq!(listeners[0]["listen"].as_str(), Some("127.0.0.1"));
        assert_eq!(listeners[0]["type"].as_str(), Some("mixed"));
        assert_eq!(listeners[0]["port"].as_u64(), Some(u64::from(ports[1])));
        assert_eq!(listeners[0]["proxy"].as_str(), proxies[0]["name"].as_str());

        assert_eq!(listeners[1]["listen"].as_str(), Some("127.0.0.1"));
        assert_eq!(listeners[1]["type"].as_str(), Some("mixed"));
        assert_eq!(listeners[1]["port"].as_u64(), Some(u64::from(ports[2])));
        assert_eq!(listeners[1]["proxy"].as_str(), proxies[1]["name"].as_str());
        assert_ne!(proxies[0]["name"].as_str(), proxies[1]["name"].as_str());

        // Never expose wildcard bind addresses
        assert!(!yaml_text.contains("0.0.0.0"));
        assert!(!yaml_text.contains("\"::\""));
    }

    #[test]
    fn proxy_url_uses_socks5h_or_http_and_never_local_dns_socks5() {
        let s5h = isolated_proxy_url(19001, IsolatedProxyScheme::Socks5h);
        assert_eq!(s5h, "socks5h://127.0.0.1:19001");
        assert!(!s5h.starts_with("socks5://"));

        let http = isolated_proxy_url(19002, IsolatedProxyScheme::HttpConnect);
        assert_eq!(http, "http://127.0.0.1:19002");

        // Building isolated clients succeeds with both schemes
        let client_s5h = build_isolated_http_client(19001, Duration::from_secs(3));
        assert!(client_s5h.is_ok());
        let client_http = build_isolated_http_client_with_options(
            19002,
            Duration::from_secs(3),
            IsolatedProxyScheme::HttpConnect,
            false,
            Some(Duration::from_secs(70)),
        );
        assert!(client_http.is_ok());
        assert!(build_isolated_http_client(0, Duration::from_secs(3)).is_err());
    }

    #[test]
    fn isolated_yaml_strips_dialer_proxy_from_cloned_node_configs() {
        let mut node = sample_node("n-preaccel", "Node-With-Dialer");
        node.raw_config["dialer-proxy"] = serde_json::json!("⚡ 国内预加速入口");

        let ports = allocate_ephemeral_ports(2).unwrap();
        let bindings = vec![(ports[1], &node)];
        let yaml_text = build_isolated_probe_yaml(ports[0], "secret-token-32bytes", &bindings, &[])
            .expect("build isolated yaml");

        let parsed: YamlValue = serde_yaml_ng::from_str(&yaml_text).expect("valid yaml");
        let proxies = parsed["proxies"].as_sequence().expect("proxies");
        assert_eq!(proxies.len(), 1);
        assert!(
            proxies[0].get("dialer-proxy").is_none(),
            "dialer-proxy must be stripped in isolated probe YAML"
        );
        assert!(!yaml_text.contains("dialer-proxy"));
    }

    #[test]
    fn preaccel_comparison_yaml_wires_relay_direct_accel_listeners_and_antiloop() {
        let relay = PreAccelRelay {
            id: "relay-cmp-1".to_string(),
            name: "CN-Relay".to_string(),
            provider: "tencent".to_string(),
            region: "CN-GZ".to_string(),
            server: "203.0.113.10".to_string(),
            port: 443,
            protocol: "anytls".to_string(),
            password: "relay-pass".to_string(),
            sni: None,
            skip_cert_verify: true,
            priority: 10,
            expires_at: None,
            enabled: true,
            supports_ipv6: false,
            last_probe_ms: None,
            last_mbps: None,
            last_up_mbps: None,
            last_down_mbps: None,
        };
        let mut node = sample_node("n-overseas", "JP-8443");
        node.port = 8443;
        node.is_443_native = false;
        node.raw_config["port"] = serde_json::json!(8443);
        node.raw_config["dialer-proxy"] = serde_json::json!("stale-group");

        let ports = allocate_ephemeral_ports(3).unwrap();
        let yaml_text = generate_preaccel_comparison_yaml(
            &relay,
            &node,
            ports[1],
            ports[2],
            ports[0],
            "cmp-secret-0123456789",
            &[],
        )
        .expect("generate comparison yaml");

        let parsed: YamlValue = serde_yaml_ng::from_str(&yaml_text).expect("valid yaml");
        assert_eq!(parsed["mixed-port"].as_u64(), Some(0));
        assert_eq!(parsed["allow-lan"].as_bool(), Some(false));
        assert_eq!(parsed["bind-address"].as_str(), Some("127.0.0.1"));
        assert_eq!(parsed["geodata-mode"].as_bool(), Some(false));
        assert_eq!(parsed["tun"]["enable"].as_bool(), Some(false));
        assert_eq!(parsed["dns"]["enhanced-mode"].as_str(), Some("redir-host"));
        let cmp_bootstrap = parsed["dns"]["default-nameserver"]
            .as_sequence()
            .expect("comparison default-nameserver");
        assert_eq!(
            cmp_bootstrap[0].as_str(),
            Some("https://223.5.5.5/dns-query")
        );
        assert_eq!(
            cmp_bootstrap[1].as_str(),
            Some("https://1.12.12.12/dns-query")
        );
        let cmp_psn = parsed["dns"]["proxy-server-nameserver"]
            .as_sequence()
            .expect("comparison proxy-server-nameserver");
        assert_eq!(cmp_psn[0].as_str(), Some("https://223.5.5.5/dns-query"));
        assert_eq!(cmp_psn[1].as_str(), Some("https://1.12.12.12/dns-query"));
        let cmp_ns = parsed["dns"]["nameserver"]
            .as_sequence()
            .expect("comparison nameserver");
        assert_eq!(cmp_ns[0].as_str(), Some("https://223.5.5.5/dns-query"));
        assert_eq!(cmp_ns[1].as_str(), Some("https://1.12.12.12/dns-query"));

        let proxies = parsed["proxies"].as_sequence().expect("proxies");
        assert_eq!(proxies.len(), 3);
        assert_eq!(proxies[0]["name"].as_str(), Some(CMP_RELAY_PROXY_NAME));
        assert_eq!(proxies[1]["name"].as_str(), Some(CMP_DIRECT_PROXY_NAME));
        assert!(proxies[1].get("dialer-proxy").is_none());
        assert_eq!(proxies[2]["name"].as_str(), Some(CMP_ACCEL_PROXY_NAME));
        assert_eq!(
            proxies[2]["dialer-proxy"].as_str(),
            Some(CMP_RELAY_PROXY_NAME)
        );

        let listeners = parsed["listeners"].as_sequence().expect("listeners");
        assert_eq!(listeners.len(), 2);
        assert_eq!(listeners[0]["port"].as_u64(), Some(u64::from(ports[1])));
        assert_eq!(listeners[0]["proxy"].as_str(), Some(CMP_ACCEL_PROXY_NAME));
        assert_eq!(listeners[0]["listen"].as_str(), Some("127.0.0.1"));
        assert_eq!(listeners[1]["port"].as_u64(), Some(u64::from(ports[2])));
        assert_eq!(listeners[1]["proxy"].as_str(), Some(CMP_DIRECT_PROXY_NAME));
        assert_eq!(listeners[1]["listen"].as_str(), Some("127.0.0.1"));

        let rules = parsed["rules"].as_sequence().expect("rules");
        assert_eq!(
            rules[0].as_str(),
            Some("IP-CIDR,203.0.113.10/32,DIRECT,no-resolve")
        );
    }

    #[test]
    fn isolated_probe_yaml_with_preaccel_wires_tcp_nodes_skips_udp_and_adds_antiloop() {
        let relay = PreAccelRelay {
            id: "relay-probe-1".to_string(),
            name: "CN-Probe-Relay".to_string(),
            provider: "tencent".to_string(),
            region: "CN-GZ".to_string(),
            server: "198.51.100.42".to_string(),
            port: 443,
            protocol: "anytls".to_string(),
            password: "relay-probe-password".to_string(),
            sni: None,
            skip_cert_verify: true,
            priority: 10,
            expires_at: None,
            enabled: true,
            supports_ipv6: false,
            last_probe_ms: None,
            last_mbps: None,
            last_up_mbps: None,
            last_down_mbps: None,
        };

        // 1. Eligible non-443 TCP node -> MUST receive dialer-proxy: catcloud-probe-relay
        let mut tcp_non443 = sample_node("n-tcp-8443", "JP-TCP-8443");
        tcp_non443.port = 8443;
        tcp_non443.is_443_native = false;
        tcp_non443.preaccel_eligible = true;
        tcp_non443.raw_config["port"] = serde_json::json!(8443);
        tcp_non443.raw_config["dialer-proxy"] = serde_json::json!("stale-old-group");

        // 2. Pure UDP node (hysteria2) -> MUST skip preaccel and keep dialer-proxy stripped
        let mut udp_hy2 = sample_node("n-udp-hy2", "JP-HY2-8443");
        udp_hy2.protocol = "hysteria2".to_string();
        udp_hy2.port = 8443;
        udp_hy2.is_443_native = false;
        udp_hy2.preaccel_eligible = true;
        udp_hy2.raw_config = serde_json::json!({
            "name": "JP-HY2-8443",
            "type": "hysteria2",
            "server": "n-udp-hy2.example.invalid",
            "port": 8443,
            "password": "hy2-password",
            "dialer-proxy": "stale-udp-group"
        });

        // 3. Native 443 TCP node -> skipped when skip_443_native=true, accelerated when false
        let mut tcp_443 = sample_node("n-tcp-443", "SG-TCP-443");
        tcp_443.port = 443;
        tcp_443.is_443_native = true;
        tcp_443.preaccel_eligible = true;

        let ports = allocate_ephemeral_ports(4).unwrap();
        let bindings = vec![
            (ports[1], &tcp_non443),
            (ports[2], &udp_hy2),
            (ports[3], &tcp_443),
        ];

        // Case A: skip_443_native = true
        let yaml_skip443 = build_isolated_probe_yaml_with_preaccel(
            ports[0],
            "probe-secret-0123456789",
            &bindings,
            &[],
            Some(&relay),
            true,
        )
        .expect("build isolated preaccel yaml (skip_443_native=true)");

        let parsed: YamlValue = serde_yaml_ng::from_str(&yaml_skip443).expect("valid yaml");
        let proxies = parsed["proxies"].as_sequence().expect("proxies");
        assert_eq!(proxies.len(), 4); // relay + 3 nodes
        assert_eq!(proxies[0]["name"].as_str(), Some(PROBE_RELAY_PROXY_NAME));

        // tcp_non443 -> wired to catcloud-probe-relay
        assert_eq!(proxies[1]["name"].as_str(), Some("JP-TCP-8443"));
        assert_eq!(
            proxies[1]["dialer-proxy"].as_str(),
            Some(PROBE_RELAY_PROXY_NAME)
        );
        // udp_hy2 -> pure UDP skipped, stale dialer-proxy stripped
        assert_eq!(proxies[2]["name"].as_str(), Some("JP-HY2-8443"));
        assert!(proxies[2].get("dialer-proxy").is_none());
        // tcp_443 -> skipped because skip_443_native=true
        assert_eq!(proxies[3]["name"].as_str(), Some("SG-TCP-443"));
        assert!(proxies[3].get("dialer-proxy").is_none());

        // Listeners still map strictly to the 3 node proxies (never the relay itself)
        let listeners = parsed["listeners"].as_sequence().expect("listeners");
        assert_eq!(listeners.len(), 3);
        assert_eq!(listeners[0]["proxy"].as_str(), Some("JP-TCP-8443"));
        assert_eq!(listeners[1]["proxy"].as_str(), Some("JP-HY2-8443"));
        assert_eq!(listeners[2]["proxy"].as_str(), Some("SG-TCP-443"));

        // Rules must prepend anti-loop DIRECT rule for relay server, followed by MATCH,DIRECT
        let rules = parsed["rules"].as_sequence().expect("rules");
        assert_eq!(rules.len(), 2);
        assert_eq!(
            rules[0].as_str(),
            Some("IP-CIDR,198.51.100.42/32,DIRECT,no-resolve")
        );
        assert_eq!(rules[1].as_str(), Some("MATCH,DIRECT"));

        // Case B: skip_443_native = false -> native 443 TCP gets dialer-proxy, UDP still skipped
        let yaml_all_tcp = build_isolated_probe_yaml_with_preaccel(
            ports[0],
            "probe-secret-0123456789",
            &bindings,
            &[],
            Some(&relay),
            false,
        )
        .expect("build isolated preaccel yaml (skip_443_native=false)");

        let parsed_b: YamlValue = serde_yaml_ng::from_str(&yaml_all_tcp).expect("valid yaml");
        let proxies_b = parsed_b["proxies"].as_sequence().expect("proxies");
        assert_eq!(
            proxies_b[1]["dialer-proxy"].as_str(),
            Some(PROBE_RELAY_PROXY_NAME)
        );
        assert!(
            proxies_b[2].get("dialer-proxy").is_none(),
            "pure UDP node must still skip preaccel when skip_443_native=false"
        );
        assert_eq!(
            proxies_b[3]["dialer-proxy"].as_str(),
            Some(PROBE_RELAY_PROXY_NAME)
        );
    }

    #[test]
    fn prepare_probe_core_binary_links_reuses_and_refreshes_on_size_change() {
        let root = std::env::temp_dir().join(format!(
            "catcloud-probe-bin-test-{}",
            Uuid::new_v4()
        ));
        let src_dir = root.join("src");
        let tmp_dir = root.join("tmp");
        std::fs::create_dir_all(&src_dir).unwrap();

        let missing = src_dir.join("missing-mihomo.exe");
        assert!(prepare_probe_core_binary(&missing, &tmp_dir).is_err());

        let src_bin = src_dir.join("mihomo.exe");
        std::fs::write(&src_bin, b"mihomo-v1-bytes").unwrap();

        let prepared = prepare_probe_core_binary(&src_bin, &tmp_dir).expect("prepare probe bin");
        assert_eq!(prepared, tmp_dir.join(PROBE_CORE_PROCESS_NAME));
        assert_eq!(std::fs::read(&prepared).unwrap(), b"mihomo-v1-bytes");

        // Second call with identical size reuses existing binary without error.
        let reused = prepare_probe_core_binary(&src_bin, &tmp_dir).expect("reuse probe bin");
        assert_eq!(reused, prepared);

        // When source binary is atomically replaced with a different-sized upgrade, probe binary refreshes.
        std::fs::remove_file(&src_bin).unwrap();
        std::fs::write(&src_bin, b"mihomo-v2-upgraded-payload-bytes").unwrap();
        let refreshed = prepare_probe_core_binary(&src_bin, &tmp_dir).expect("refresh probe bin");
        assert_eq!(refreshed, prepared);
        assert_eq!(
            std::fs::read(&refreshed).unwrap(),
            b"mihomo-v2-upgraded-payload-bytes"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn isolated_probe_yaml_ignores_plain_udp_and_domain_doh_nameservers() {
        let node = sample_node("n-dns-guard", "TW-02");
        let ports = allocate_ephemeral_ports(2).unwrap();
        let bindings = vec![(ports[1], &node)];

        // Plain UDP :53 IPs and domain-hosted DoH (which require UDP :53 bootstrap) must be
        // rejected in favor of pure-IP DoH so active TUN `dns-hijack: any:53` never returns Fake-IP.
        let unsafe_ns = vec![
            "223.5.5.5".to_string(),
            "119.29.29.29".to_string(),
            "udp://223.5.5.5:53".to_string(),
            "https://dns.alidns.com/dns-query".to_string(),
        ];
        let yaml_text =
            build_isolated_probe_yaml(ports[0], "secret-token-32bytes", &bindings, &unsafe_ns)
                .expect("build isolated yaml with fallback doh");
        let parsed: YamlValue = serde_yaml_ng::from_str(&yaml_text).expect("valid yaml");
        let psn = parsed["dns"]["proxy-server-nameserver"]
            .as_sequence()
            .expect("proxy-server-nameserver");
        assert_eq!(psn[0].as_str(), Some("https://223.5.5.5/dns-query"));
        assert_eq!(psn[1].as_str(), Some("https://1.12.12.12/dns-query"));

        // Explicit pure-IP encrypted resolvers are preserved.
        let safe_ns = vec![
            "223.5.5.5".to_string(),
            "https://1.12.12.12/dns-query".to_string(),
            "tls://223.5.5.5:853".to_string(),
        ];
        let yaml_custom =
            build_isolated_probe_yaml(ports[0], "secret-token-32bytes", &bindings, &safe_ns)
                .expect("build isolated yaml with custom pure-ip doh");
        let parsed_custom: YamlValue = serde_yaml_ng::from_str(&yaml_custom).expect("valid yaml");
        let psn_custom = parsed_custom["dns"]["proxy-server-nameserver"]
            .as_sequence()
            .expect("custom proxy-server-nameserver");
        assert_eq!(psn_custom.len(), 2);
        assert_eq!(psn_custom[0].as_str(), Some("https://1.12.12.12/dns-query"));
        assert_eq!(psn_custom[1].as_str(), Some("tls://223.5.5.5:853"));
    }

    #[test]
    fn preaccel_relay_speed_yaml_supports_chained_and_direct_modes() {
        let relay_a = PreAccelRelay {
            id: "relay-spd-a".to_string(),
            name: "CN-GZ-443".to_string(),
            provider: "tencent".to_string(),
            region: "CN-GZ".to_string(),
            server: "203.0.113.10".to_string(),
            port: 443,
            protocol: "anytls".to_string(),
            password: "relay-spd-password-a".to_string(),
            sni: None,
            skip_cert_verify: true,
            priority: 10,
            expires_at: None,
            enabled: true,
            supports_ipv6: false,
            last_probe_ms: None,
            last_mbps: None,
            last_up_mbps: None,
            last_down_mbps: None,
        };
        let relay_b = PreAccelRelay {
            id: "relay-spd-b".to_string(),
            name: "CN-SH-443".to_string(),
            provider: "aliyun".to_string(),
            region: "CN-SH".to_string(),
            server: "198.51.100.20".to_string(),
            port: 443,
            protocol: "vless".to_string(),
            password: "11111111-2222-4333-8444-555555555555".to_string(),
            sni: None,
            skip_cert_verify: true,
            priority: 20,
            expires_at: None,
            enabled: true,
            supports_ipv6: false,
            last_probe_ms: None,
            last_mbps: None,
            last_up_mbps: None,
            last_down_mbps: None,
        };
        let relays = vec![relay_a, relay_b];

        let mut ref_tcp = sample_node("n-ref-jp", "JP-Ref-Node");
        ref_tcp.server = "ref-jp.example.invalid".to_string();
        ref_tcp.port = 8443;
        ref_tcp.raw_config["server"] = serde_json::json!("ref-jp.example.invalid");
        ref_tcp.raw_config["port"] = serde_json::json!(8443);
        ref_tcp.raw_config["dialer-proxy"] = serde_json::json!("stale-dialer");

        let ports = allocate_ephemeral_ports(3).unwrap();
        let relay_ports = vec![
            ("relay-spd-a".to_string(), ports[1]),
            ("relay-spd-b".to_string(), ports[2]),
        ];

        // Mode 1: Chained through a TCP reference node
        let chained_yaml = generate_preaccel_relay_speed_yaml(
            &relays,
            Some(&ref_tcp),
            &relay_ports,
            ports[0],
            "relay-speed-secret-0123456789",
            &[],
        )
        .expect("generate chained relay speed yaml");

        let parsed: YamlValue = serde_yaml_ng::from_str(&chained_yaml).expect("valid chained yaml");
        assert_eq!(parsed["mixed-port"].as_u64(), Some(0));
        assert_eq!(parsed["allow-lan"].as_bool(), Some(false));
        assert_eq!(parsed["bind-address"].as_str(), Some("127.0.0.1"));
        assert_eq!(parsed["tun"]["enable"].as_bool(), Some(false));
        assert_eq!(parsed["dns"]["enhanced-mode"].as_str(), Some("redir-host"));

        let proxies = parsed["proxies"].as_sequence().expect("proxies");
        assert_eq!(proxies.len(), 4);
        assert_eq!(proxies[0]["name"].as_str(), Some("cc-rs-relay-0"));
        assert!(proxies[0].get("sni").is_none());
        assert_eq!(proxies[1]["name"].as_str(), Some("cc-rs-chain-0"));
        assert_eq!(proxies[1]["dialer-proxy"].as_str(), Some("cc-rs-relay-0"));
        assert_eq!(proxies[2]["name"].as_str(), Some("cc-rs-relay-1"));
        assert_eq!(proxies[2]["servername"].as_str(), Some(""));
        assert_eq!(proxies[3]["name"].as_str(), Some("cc-rs-chain-1"));
        assert_eq!(proxies[3]["dialer-proxy"].as_str(), Some("cc-rs-relay-1"));

        let listeners = parsed["listeners"].as_sequence().expect("listeners");
        assert_eq!(listeners.len(), 2);
        assert_eq!(listeners[0]["listen"].as_str(), Some("127.0.0.1"));
        assert_eq!(listeners[0]["port"].as_u64(), Some(u64::from(ports[1])));
        assert_eq!(listeners[0]["proxy"].as_str(), Some("cc-rs-chain-0"));
        assert_eq!(listeners[1]["listen"].as_str(), Some("127.0.0.1"));
        assert_eq!(listeners[1]["port"].as_u64(), Some(u64::from(ports[2])));
        assert_eq!(listeners[1]["proxy"].as_str(), Some("cc-rs-chain-1"));

        let rules: Vec<&str> = parsed["rules"]
            .as_sequence()
            .expect("rules")
            .iter()
            .filter_map(YamlValue::as_str)
            .collect();
        assert!(rules.contains(&"IP-CIDR,203.0.113.10/32,DIRECT,no-resolve"));
        assert!(rules.contains(&"IP-CIDR,198.51.100.20/32,DIRECT,no-resolve"));
        assert!(rules.contains(&"DOMAIN,ref-jp.example.invalid,DIRECT"));
        assert_eq!(rules.last().copied(), Some("MATCH,DIRECT"));

        // Mode 2: Direct relay mode (reference_node = None)
        let direct_yaml = generate_preaccel_relay_speed_yaml(
            &relays,
            None,
            &relay_ports,
            ports[0],
            "relay-speed-secret-0123456789",
            &[],
        )
        .expect("generate direct relay speed yaml");

        let parsed_dir: YamlValue =
            serde_yaml_ng::from_str(&direct_yaml).expect("valid direct yaml");
        let dir_proxies = parsed_dir["proxies"].as_sequence().expect("dir proxies");
        assert_eq!(dir_proxies.len(), 2);
        assert_eq!(dir_proxies[0]["name"].as_str(), Some("cc-rs-relay-0"));
        assert!(dir_proxies[0].get("sni").is_none());
        assert_eq!(dir_proxies[1]["name"].as_str(), Some("cc-rs-relay-1"));
        assert_eq!(dir_proxies[1]["servername"].as_str(), Some(""));

        let dir_listeners = parsed_dir["listeners"]
            .as_sequence()
            .expect("dir listeners");
        assert_eq!(dir_listeners.len(), 2);
        assert_eq!(dir_listeners[0]["proxy"].as_str(), Some("cc-rs-relay-0"));
        assert_eq!(dir_listeners[1]["proxy"].as_str(), Some("cc-rs-relay-1"));
        assert!(!direct_yaml.contains("cc-rs-chain-"));

        // Mode 3: UDP-only reference node (e.g. hysteria2) falls back to direct relay listeners
        let mut ref_udp = sample_node("n-ref-hy2", "JP-HY2");
        ref_udp.protocol = "hysteria2".to_string();
        let udp_yaml = generate_preaccel_relay_speed_yaml(
            &relays,
            Some(&ref_udp),
            &relay_ports,
            ports[0],
            "relay-speed-secret-0123456789",
            &[],
        )
        .expect("generate udp-ref relay speed yaml");
        let parsed_udp: YamlValue = serde_yaml_ng::from_str(&udp_yaml).expect("valid udp yaml");
        assert_eq!(parsed_udp["proxies"].as_sequence().unwrap().len(), 2);
        assert_eq!(
            parsed_udp["listeners"][0]["proxy"].as_str(),
            Some("cc-rs-relay-0")
        );
    }

    #[test]
    fn isolated_probe_and_speed_yaml_compile_hysteria2_relay_with_bandwidth_and_pure_ip_doh() {
        let hy2_relay = PreAccelRelay {
            id: "relay-hy2-iso".to_string(),
            name: "CN-HY2-443".to_string(),
            provider: "cloud-a".to_string(),
            region: "CN-East".to_string(),
            server: "203.0.113.88".to_string(),
            port: 443,
            protocol: "hysteria2".to_string(),
            password: "hy2-iso-password".to_string(),
            sni: None,
            skip_cert_verify: true,
            priority: 10,
            expires_at: None,
            enabled: true,
            supports_ipv6: false,
            last_probe_ms: None,
            last_mbps: None,
            last_up_mbps: None,
            last_down_mbps: None,
        };
        let mut tcp_node = sample_node("n-hy2-tcp", "JP-TCP-8443");
        tcp_node.port = 8443;
        tcp_node.is_443_native = false;
        tcp_node.preaccel_eligible = true;
        tcp_node.raw_config["port"] = serde_json::json!(8443);

        let ports = allocate_ephemeral_ports(3).unwrap();
        let bindings = vec![(ports[1], &tcp_node)];

        // 1. Isolated node probe YAML with Hysteria2 preaccel relay
        let probe_yaml = build_isolated_probe_yaml_with_preaccel(
            ports[0],
            "hy2-probe-secret-0123456789",
            &bindings,
            &[],
            Some(&hy2_relay),
            true,
        )
        .expect("build isolated probe yaml with hysteria2 relay");
        let parsed_probe: YamlValue =
            serde_yaml_ng::from_str(&probe_yaml).expect("valid probe yaml");
        let probe_relay = &parsed_probe["proxies"][0];
        assert_eq!(probe_relay["name"].as_str(), Some(PROBE_RELAY_PROXY_NAME));
        assert_eq!(probe_relay["type"].as_str(), Some("hysteria2"));
        assert_eq!(probe_relay["up"].as_str(), Some("100 Mbps"));
        assert_eq!(probe_relay["down"].as_str(), Some("200 Mbps"));
        assert_eq!(probe_relay["skip-cert-verify"].as_bool(), Some(true));
        assert!(probe_relay.get("sni").is_none());
        assert_eq!(
            parsed_probe["proxies"][1]["dialer-proxy"].as_str(),
            Some(PROBE_RELAY_PROXY_NAME)
        );
        assert_eq!(
            parsed_probe["rules"][0].as_str(),
            Some("IP-CIDR,203.0.113.88/32,DIRECT,no-resolve")
        );
        let bootstrap = parsed_probe["dns"]["default-nameserver"]
            .as_sequence()
            .expect("probe bootstrap dns");
        assert_eq!(bootstrap[0].as_str(), Some("https://223.5.5.5/dns-query"));
        assert_eq!(bootstrap[1].as_str(), Some("https://1.12.12.12/dns-query"));
        assert!(!probe_yaml.contains("system"));

        // 2. Relay speed YAML with Hysteria2 relay chained to reference TCP node
        let speed_yaml = generate_preaccel_relay_speed_yaml(
            &[hy2_relay],
            Some(&tcp_node),
            &[("relay-hy2-iso".to_string(), ports[2])],
            ports[0],
            "hy2-speed-secret-0123456789",
            &[],
        )
        .expect("generate hysteria2 relay speed yaml");
        let parsed_speed: YamlValue =
            serde_yaml_ng::from_str(&speed_yaml).expect("valid speed yaml");
        let speed_relay = &parsed_speed["proxies"][0];
        assert_eq!(speed_relay["type"].as_str(), Some("hysteria2"));
        assert_eq!(speed_relay["up"].as_str(), Some("100 Mbps"));
        assert_eq!(speed_relay["down"].as_str(), Some("200 Mbps"));
        assert!(speed_relay.get("sni").is_none());
        let speed_bootstrap = parsed_speed["dns"]["default-nameserver"]
            .as_sequence()
            .expect("speed bootstrap dns");
        assert_eq!(
            speed_bootstrap[0].as_str(),
            Some("https://223.5.5.5/dns-query")
        );
        assert_eq!(
            speed_bootstrap[1].as_str(),
            Some("https://1.12.12.12/dns-query")
        );
        assert_eq!(speed_bootstrap[2].as_str(), Some("tls://223.6.6.6:853"));
        assert_eq!(speed_bootstrap[3].as_str(), Some("tls://120.53.53.53:853"));
    }

    #[test]
    fn isolated_probe_yaml_with_preaccel_pool_builds_two_layer_lb_single_fallback_and_skips_ipv6_only()
    {
        let relay_a_tcp = PreAccelRelay {
            id: "r-pool-a-tcp".to_string(),
            name: "CloudA-AnyTLS".to_string(),
            provider: "cloud-a".to_string(),
            region: "CN-East".to_string(),
            server: "203.0.113.10".to_string(),
            port: 443,
            protocol: "anytls".to_string(),
            password: "pass-a-tcp".to_string(),
            sni: None,
            skip_cert_verify: true,
            priority: 10,
            expires_at: None,
            enabled: true,
            supports_ipv6: false,
            last_probe_ms: None,
            last_mbps: None,
            last_up_mbps: None,
            last_down_mbps: None,
        };
        let mut relay_a_udp = relay_a_tcp.clone();
        relay_a_udp.id = "r-pool-a-udp".to_string();
        relay_a_udp.name = "CloudA-HY2".to_string();
        relay_a_udp.protocol = "hysteria2".to_string();
        relay_a_udp.priority = 20;

        let mut relay_b_tcp = relay_a_tcp.clone();
        relay_b_tcp.id = "r-pool-b-tcp".to_string();
        relay_b_tcp.name = "CloudB-VLESS".to_string();
        relay_b_tcp.server = "198.51.100.20".to_string();
        relay_b_tcp.protocol = "vless".to_string();
        relay_b_tcp.password = "11111111-2222-4333-8444-555555555555".to_string();
        relay_b_tcp.priority = 30;

        let mut node_tcp = sample_node("n-pool-tcp", "JP-8443");
        node_tcp.port = 8443;
        node_tcp.is_443_native = false;
        node_tcp.preaccel_eligible = true;
        node_tcp.raw_config["port"] = serde_json::json!(8443);

        let mut node_v6 = sample_node("n-pool-v6", "HK-IPv6-Only");
        node_v6.server = "2001:db8::99".to_string();
        node_v6.port = 8443;
        node_v6.is_443_native = false;
        node_v6.preaccel_eligible = true;
        node_v6.raw_config["server"] = serde_json::json!("2001:db8::99");
        node_v6.raw_config["port"] = serde_json::json!(8443);

        let mut node_dual = sample_node("n-pool-dual", "HK-01-IPv6");
        node_dual.port = 8443;
        node_dual.is_443_native = false;
        node_dual.preaccel_eligible = true;
        node_dual.raw_config["port"] = serde_json::json!(8443);

        let ports = allocate_ephemeral_ports(4).unwrap();
        let bindings = vec![
            (ports[1], &node_tcp),
            (ports[2], &node_v6),
            (ports[3], &node_dual),
        ];

        // 1. Two distinct physical hosts -> two-layer nested LB + outer fallback with DIRECT.
        let yaml_multi = build_isolated_probe_yaml_with_preaccel_pool(
            ports[0],
            "pool-secret-0123456789",
            &bindings,
            &[],
            &[relay_a_tcp.clone(), relay_a_udp.clone(), relay_b_tcp.clone()],
            PreAccelDispatchStrategy::Auto,
            PreAccelLbStrategy::RoundRobin,
            true,
        )
        .expect("build multi-cloud probe pool yaml");
        let parsed: YamlValue = serde_yaml_ng::from_str(&yaml_multi).expect("valid multi yaml");

        let dns_boot: Vec<&str> = parsed["dns"]["default-nameserver"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(YamlValue::as_str)
            .collect();
        assert_eq!(
            dns_boot,
            vec![
                "https://223.5.5.5/dns-query",
                "https://1.12.12.12/dns-query",
                "tls://223.6.6.6:853",
                "tls://120.53.53.53:853",
            ]
        );

        let groups = parsed["proxy-groups"].as_sequence().expect("proxy-groups");
        assert_eq!(groups.len(), 2);
        let fb = groups
            .iter()
            .find(|g| g["name"].as_str() == Some(PROBE_RELAY_POOL_GROUP_NAME))
            .expect("pool fallback group");
        let lb = groups
            .iter()
            .find(|g| g["name"].as_str() == Some(PROBE_RELAY_LB_GROUP_NAME))
            .expect("pool lb group");
        assert_eq!(lb["type"].as_str(), Some("load-balance"));
        assert_eq!(lb["strategy"].as_str(), Some("round-robin"));
        let lb_members: Vec<&str> = lb["proxies"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(YamlValue::as_str)
            .collect();
        assert_eq!(
            lb_members,
            vec!["catcloud-probe-relay-0", "catcloud-probe-relay-2"]
        );
        assert!(!lb_members.contains(&"DIRECT"));

        let fb_members: Vec<&str> = fb["proxies"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(YamlValue::as_str)
            .collect();
        assert_eq!(
            fb_members,
            vec![PROBE_RELAY_LB_GROUP_NAME, "catcloud-probe-relay-1", "DIRECT"]
        );

        // Node dialer-proxy: TCP & dual-stack wrapped; pure IPv6 skipped.
        let proxies = parsed["proxies"].as_sequence().unwrap();
        let p_tcp = proxies
            .iter()
            .find(|p| p["name"].as_str() == Some("JP-8443"))
            .unwrap();
        assert_eq!(
            p_tcp["dialer-proxy"].as_str(),
            Some(PROBE_RELAY_POOL_GROUP_NAME)
        );
        let p_v6 = proxies
            .iter()
            .find(|p| p["name"].as_str() == Some("HK-IPv6-Only"))
            .unwrap();
        assert!(p_v6.get("dialer-proxy").is_none());
        let p_dual = proxies
            .iter()
            .find(|p| p["name"].as_str() == Some("HK-01-IPv6"))
            .unwrap();
        assert_eq!(
            p_dual["dialer-proxy"].as_str(),
            Some(PROBE_RELAY_POOL_GROUP_NAME)
        );

        // Rules deduplicate same-host IPs and include both physical hosts.
        let rules: Vec<&str> = parsed["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(YamlValue::as_str)
            .collect();
        assert_eq!(
            rules,
            vec![
                "IP-CIDR,203.0.113.10/32,DIRECT,no-resolve",
                "IP-CIDR,198.51.100.20/32,DIRECT,no-resolve",
                "MATCH,DIRECT",
            ]
        );

        // 2. Single physical host -> single-layer fallback([catcloud-probe-relay-0, DIRECT]).
        let yaml_single = build_isolated_probe_yaml_with_preaccel_pool(
            ports[0],
            "pool-secret-0123456789",
            &bindings,
            &[],
            &[relay_a_tcp],
            PreAccelDispatchStrategy::Auto,
            PreAccelLbStrategy::RoundRobin,
            true,
        )
        .expect("build single-host probe pool yaml");
        let parsed_single: YamlValue =
            serde_yaml_ng::from_str(&yaml_single).expect("valid single yaml");
        let single_groups = parsed_single["proxy-groups"]
            .as_sequence()
            .expect("single proxy-groups");
        assert_eq!(single_groups.len(), 1);
        assert_eq!(
            single_groups[0]["name"].as_str(),
            Some(PROBE_RELAY_POOL_GROUP_NAME)
        );
        let single_members: Vec<&str> = single_groups[0]["proxies"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(YamlValue::as_str)
            .collect();
        assert_eq!(single_members, vec!["catcloud-probe-relay-0", "DIRECT"]);
    }

    #[test]
    fn mixed_ipv4_ipv6_relay_pool_skips_ipv6_only_node_and_relay_speed_skips_ipv6_only_reference() {
        let relay_v4 = PreAccelRelay {
            id: "r-mix-v4".to_string(),
            name: "CloudA-V4".to_string(),
            provider: "cloud-a".to_string(),
            region: "CN-East".to_string(),
            server: "203.0.113.10".to_string(),
            port: 443,
            protocol: "anytls".to_string(),
            password: "pass-v4".to_string(),
            sni: None,
            skip_cert_verify: true,
            priority: 10,
            expires_at: None,
            enabled: true,
            supports_ipv6: false,
            last_probe_ms: None,
            last_mbps: None,
            last_up_mbps: None,
            last_down_mbps: None,
        };
        let mut relay_v6 = relay_v4.clone();
        relay_v6.id = "r-mix-v6".to_string();
        relay_v6.name = "CloudB-V6".to_string();
        relay_v6.server = "198.51.100.20".to_string();
        relay_v6.priority = 20;
        relay_v6.supports_ipv6 = true;

        let mut node_v6 = sample_node("n-v6-only-ref", "HK-IPv6-Only");
        node_v6.server = "2001:db8::42".to_string();
        node_v6.port = 8443;
        node_v6.is_443_native = false;
        node_v6.preaccel_eligible = true;
        node_v6.raw_config["server"] = serde_json::json!("2001:db8::42");
        node_v6.raw_config["port"] = serde_json::json!(8443);

        // 1. Mixed relay pool (IPv4-only + dual-stack) must skip pure IPv6 node in probe pool YAML.
        let pool_ports = allocate_ephemeral_ports(2).unwrap();
        let bindings = vec![(pool_ports[1], &node_v6)];
        let mixed_yaml = build_isolated_probe_yaml_with_preaccel_pool(
            pool_ports[0],
            "mixed-pool-secret-0123456789",
            &bindings,
            &[],
            &[relay_v4.clone(), relay_v6.clone()],
            PreAccelDispatchStrategy::Auto,
            PreAccelLbStrategy::RoundRobin,
            true,
        )
        .expect("build mixed pool probe yaml");
        let parsed_mixed: YamlValue =
            serde_yaml_ng::from_str(&mixed_yaml).expect("valid mixed pool yaml");
        let p_v6_mixed = parsed_mixed["proxies"]
            .as_sequence()
            .unwrap()
            .iter()
            .find(|p| p["name"].as_str() == Some("HK-IPv6-Only"))
            .unwrap();
        assert!(
            p_v6_mixed.get("dialer-proxy").is_none(),
            "mixed IPv4+IPv6 pool must not wrap pure IPv6 node"
        );

        // 2. All-IPv6 relay pool wraps the pure IPv6 node normally.
        let mut relay_v4_upgraded = relay_v4.clone();
        relay_v4_upgraded.supports_ipv6 = true;
        let all_v6_yaml = build_isolated_probe_yaml_with_preaccel_pool(
            pool_ports[0],
            "all-v6-pool-secret-0123456789",
            &bindings,
            &[],
            &[relay_v4_upgraded, relay_v6.clone()],
            PreAccelDispatchStrategy::Auto,
            PreAccelLbStrategy::RoundRobin,
            true,
        )
        .expect("build all-v6 pool probe yaml");
        let parsed_all_v6: YamlValue =
            serde_yaml_ng::from_str(&all_v6_yaml).expect("valid all-v6 pool yaml");
        let p_v6_wrapped = parsed_all_v6["proxies"]
            .as_sequence()
            .unwrap()
            .iter()
            .find(|p| p["name"].as_str() == Some("HK-IPv6-Only"))
            .unwrap();
        assert_eq!(
            p_v6_wrapped["dialer-proxy"].as_str(),
            Some(PROBE_RELAY_POOL_GROUP_NAME)
        );

        // 3. Relay speed test with a pure IPv6 reference node skips chaining for IPv4-only relay
        //    (`cc-rs-relay-0`) while still chaining the dual-stack relay (`cc-rs-chain-1`).
        let speed_ports = allocate_ephemeral_ports(3).unwrap();
        let relay_ports = vec![
            (relay_v4.id.clone(), speed_ports[1]),
            (relay_v6.id.clone(), speed_ports[2]),
        ];
        let speed_yaml = generate_preaccel_relay_speed_yaml(
            &[relay_v4.clone(), relay_v6],
            Some(&node_v6),
            &relay_ports,
            speed_ports[0],
            "relay-speed-v6-ref-0123456789",
            &[],
        )
        .expect("generate relay speed yaml with ipv6-only reference node");
        let parsed_speed: YamlValue =
            serde_yaml_ng::from_str(&speed_yaml).expect("valid relay speed yaml");
        let speed_proxies = parsed_speed["proxies"].as_sequence().unwrap();
        let proxy_names: Vec<&str> = speed_proxies
            .iter()
            .filter_map(|p| p["name"].as_str())
            .collect();
        assert_eq!(proxy_names, vec!["cc-rs-relay-0", "cc-rs-relay-1", "cc-rs-chain-1"]);
        let speed_listeners = parsed_speed["listeners"].as_sequence().unwrap();
        assert_eq!(speed_listeners[0]["proxy"].as_str(), Some("cc-rs-relay-0"));
        assert_eq!(speed_listeners[1]["proxy"].as_str(), Some("cc-rs-chain-1"));

        // 4. Single IPv4-only relay with pure IPv6 reference node emits no chain proxy and no ref rule.
        let single_ports = allocate_ephemeral_ports(2).unwrap();
        let single_speed_yaml = generate_preaccel_relay_speed_yaml(
            &[relay_v4.clone()],
            Some(&node_v6),
            &[(relay_v4.id, single_ports[1])],
            single_ports[0],
            "relay-speed-v4-only-0123456789",
            &[],
        )
        .expect("generate v4-only relay speed yaml with ipv6-only ref");
        let parsed_single: YamlValue =
            serde_yaml_ng::from_str(&single_speed_yaml).expect("valid single speed yaml");
        assert_eq!(parsed_single["proxies"].as_sequence().unwrap().len(), 1);
        assert_eq!(
            parsed_single["listeners"][0]["proxy"].as_str(),
            Some("cc-rs-relay-0")
        );
        assert!(!single_speed_yaml.contains("cc-rs-chain-"));
        assert!(!single_speed_yaml.contains("2001:db8::42"));
    }
}
