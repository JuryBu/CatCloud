use crate::error::{CatError, CatResult};
use crate::models::{PreAccelRelay, ProxyNode};
use crate::preaccel::{compile_relay_to_mihomo_yaml, host_to_direct_rule};
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

/// Default physical-NIC DNS resolvers used to prevent active TUN Fake-IP (`198.18.x.x`) pollution.
pub const DEFAULT_PROBE_NAMESERVERS: &[&str] = &["223.5.5.5", "119.29.29.29"];

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

/// Resolve deterministic, collision-free proxy names for a slice of bound nodes.
pub fn resolve_unique_proxy_names(bindings: &[(u16, &ProxyNode)]) -> Vec<String> {
    let mut used: HashSet<String> = HashSet::with_capacity(bindings.len());
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

    let resolved_ns: Vec<String> = {
        let filtered: Vec<String> = proxy_nameservers
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if filtered.is_empty() {
            DEFAULT_PROBE_NAMESERVERS
                .iter()
                .map(|s| (*s).to_string())
                .collect()
        } else {
            filtered
        }
    };
    let ns_yaml: Vec<YamlValue> = resolved_ns.iter().cloned().map(YamlValue::from).collect();

    let proxy_names = resolve_unique_proxy_names(bindings);

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

    // Explicit redir-host DNS to defeat active TUN Fake-IP pollution
    let mut dns = Mapping::new();
    dns.insert(YamlValue::from("enable"), YamlValue::from(true));
    dns.insert(YamlValue::from("ipv6"), YamlValue::from(false));
    dns.insert(
        YamlValue::from("enhanced-mode"),
        YamlValue::from("redir-host"),
    );
    dns.insert(
        YamlValue::from("default-nameserver"),
        YamlValue::Sequence(ns_yaml.clone()),
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
    let mut proxies_seq: Vec<YamlValue> = Vec::with_capacity(bindings.len());
    let mut listeners_seq: Vec<YamlValue> = Vec::with_capacity(bindings.len());

    for (idx, ((listen_port, node), proxy_name)) in
        bindings.iter().zip(proxy_names.iter()).enumerate()
    {
        let mut proxy_map = match serde_yaml_ng::to_value(&node.raw_config)? {
            YamlValue::Mapping(map) => map,
            _ => Mapping::new(),
        };

        // Strip `dialer-proxy` so isolated probe instances never fail referencing groups absent
        // from the minimal ephemeral probe configuration.
        proxy_map.remove("dialer-proxy");

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
    root.insert(
        YamlValue::from("rules"),
        YamlValue::Sequence(vec![YamlValue::from("MATCH,DIRECT")]),
    );

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

    let resolved_ns: Vec<String> = {
        let filtered: Vec<String> = dns_servers
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if filtered.is_empty() {
            DEFAULT_PROBE_NAMESERVERS
                .iter()
                .map(|s| (*s).to_string())
                .collect()
        } else {
            filtered
        }
    };
    let ns_yaml: Vec<YamlValue> = resolved_ns.iter().cloned().map(YamlValue::from).collect();

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
        YamlValue::Sequence(ns_yaml.clone()),
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
        Self::spawn_with_options(
            mihomo_bin,
            temp_dir,
            job_guard,
            nodes,
            &[],
            DEFAULT_READY_TIMEOUT,
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
        let proxy_names = resolve_unique_proxy_names(&pair_refs);
        let yaml = build_isolated_probe_yaml(
            controller_port,
            &secret,
            &pair_refs,
            proxy_nameservers,
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

        let norm_bin = crate::paths::normalize_os_path(mihomo_bin);
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
                mihomo_bin.display()
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

        let norm_bin = crate::paths::normalize_os_path(mihomo_bin);
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
                mihomo_bin.display()
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

        // DNS must explicitly use redir-host and physical-NIC nameservers to defeat Fake-IP
        assert_eq!(parsed["dns"]["enable"].as_bool(), Some(true));
        assert_eq!(parsed["dns"]["enhanced-mode"].as_str(), Some("redir-host"));
        let psn = parsed["dns"]["proxy-server-nameserver"]
            .as_sequence()
            .expect("proxy-server-nameserver sequence");
        assert_eq!(psn[0].as_str(), Some("223.5.5.5"));
        assert_eq!(psn[1].as_str(), Some("119.29.29.29"));
        let ns = parsed["dns"]["nameserver"]
            .as_sequence()
            .expect("nameserver sequence");
        assert_eq!(ns[0].as_str(), Some("223.5.5.5"));
        assert_eq!(ns[1].as_str(), Some("119.29.29.29"));

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
            last_probe_ms: None,
            last_mbps: None,
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
}
