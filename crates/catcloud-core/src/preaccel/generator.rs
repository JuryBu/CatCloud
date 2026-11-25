use crate::config::is_forbidden_domestic_probe_host;
use crate::error::{CatError, CatResult};
use crate::models::group::PreAccelRelay;
use crate::models::node::ProxyNode;
use crate::models::settings::PreAccelConfig;
use crate::preaccel::schema::{
    RelayProtocol, RelayValidationSeverity, parse_server_ip, validate_relay,
};
use serde::{Deserialize, Serialize};
use serde_yaml_ng::{Mapping, Number, Value};
use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use url::Url;

/// Mihomo `select` proxy group name serving as the unified `dialer-proxy` target.
pub const PREACCEL_SELECT_GROUP: &str = "⚡ 国内预加速入口";

/// Mihomo `fallback` proxy group name providing active-standby dual-relay failover.
pub const PREACCEL_FALLBACK_GROUP: &str = "🔄 预加速自动双活";

/// Primary domestic 204 health-check URL (Huawei Cloud).
pub const DEFAULT_DOMESTIC_204_PRIMARY: &str =
    "http://connectivitycheck.platform.hicloud.com/generate_204";

/// Secondary domestic 204 health-check URL (Xiaomi MIUI).
pub const DEFAULT_DOMESTIC_204_FALLBACK: &str = "http://connect.rom.miui.com/generate_204";

/// Additional overseas captive/probe endpoints disallowed for domestic pre-acceleration probes.
const EXTRA_FORBIDDEN_OVERSEAS_PROBE_SUFFIXES: &[&str] = &[
    "captive.apple.com",
    "detectportal.firefox.com",
    "connectivitycheck.android.com",
    "msftconnecttest.com",
    "msftncsi.com",
];

/// Compiled domestic pre-acceleration artifacts ready to be merged into Mihomo YAML.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PreAccelCompilePlan {
    /// True when pre-acceleration is enabled and at least one enabled relay was compiled.
    pub active: bool,
    /// Name of the user-facing `select` entry group (`PREACCEL_SELECT_GROUP`).
    pub select_group_name: String,
    /// Name of the active-standby `fallback` group (`PREACCEL_FALLBACK_GROUP`).
    pub fallback_group_name: String,
    /// Validated domestic 204 probe URL used by the `fallback` group.
    pub effective_probe_url: String,
    /// Clamped probe interval in seconds (`10..=300`).
    pub effective_probe_interval_sec: u64,
    /// Ordered enabled relay IDs sorted by `(priority ASC, id ASC)`.
    pub ordered_relay_ids: Vec<String>,
    /// Unique Mihomo proxy names aligned 1-to-1 with `ordered_relay_ids`.
    pub ordered_relay_names: Vec<String>,
    /// Compiled Mihomo proxy YAML entries for enabled relays (pure IP, no SNI, skip-cert-verify).
    pub relay_proxies: Vec<Value>,
    /// Compiled Mihomo proxy-group YAML entries (`select` + `fallback`).
    pub proxy_groups: Vec<Value>,
    /// Per-node `dialer-proxy` assignment keyed by `node.id` (`Some(PREACCEL_SELECT_GROUP)` or `None`).
    pub node_dialer_map: BTreeMap<String, Option<String>>,
    /// Node IDs that will be routed through `PREACCEL_SELECT_GROUP`.
    pub dialer_node_ids: Vec<String>,
    /// Node IDs that bypass pre-acceleration (e.g. native 443 nodes or overridden off).
    pub skipped_node_ids: Vec<String>,
    /// Top-priority `DIRECT` anti-loop rules (deduplicated while preserving order).
    pub anti_loop_rules: Vec<String>,
    /// `dns.fake-ip-filter` entries for relay/node/probe/campus domains (deduplicated in order).
    pub fake_ip_filter: Vec<String>,
    /// Non-fatal warnings surfaced during compilation (e.g. expiring relay, fallback to auto group).
    pub warnings: Vec<String>,
}

impl PreAccelCompilePlan {
    /// Look up the `dialer-proxy` group name to attach to a given `node_id`, if any.
    pub fn dialer_for_node(&self, node_id: &str) -> Option<&str> {
        if !self.active {
            return None;
        }
        self.node_dialer_map
            .get(node_id)
            .and_then(|opt| opt.as_deref())
    }

    /// Inject `dialer-proxy` into a compiled Mihomo proxy YAML mapping if this node uses pre-accel.
    pub fn apply_dialer_to_proxy_yaml(&self, node_id: &str, proxy: &mut Value) -> bool {
        let Some(dialer) = self.dialer_for_node(node_id) else {
            return false;
        };
        if let Some(map) = proxy.as_mapping_mut() {
            map.insert(
                Value::String("dialer-proxy".to_string()),
                Value::String(dialer.to_string()),
            );
            return true;
        }
        false
    }
}

/// Strictly validate a domestic 204 health-check probe URL, rejecting overseas hosts such as
/// `gstatic.com`, `google.com`, `cloudflare.com`, and similar overseas endpoints.
pub fn validate_domestic_probe_url(raw_url: &str) -> CatResult<Url> {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() {
        return Err(CatError::Validation(
            "domestic pre-acceleration probe URL cannot be empty".to_string(),
        ));
    }

    let parsed = Url::parse(trimmed)
        .map_err(|e| CatError::Validation(format!("invalid domestic probe URL `{trimmed}`: {e}")))?;

    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(CatError::Validation(format!(
            "domestic probe URL `{trimmed}` must use http:// or https://"
        )));
    }

    let host = parsed
        .host_str()
        .map(|h| h.trim().trim_start_matches('[').trim_end_matches(']'))
        .filter(|h| !h.is_empty())
        .ok_or_else(|| {
            CatError::Validation(format!("domestic probe URL `{trimmed}` has no valid host"))
        })?;

    if is_disallowed_domestic_probe_host(host) {
        return Err(CatError::Validation(format!(
            "overseas host `{host}` is forbidden for domestic pre-acceleration probes; use a domestic 204 endpoint such as `{DEFAULT_DOMESTIC_204_PRIMARY}` or `{DEFAULT_DOMESTIC_204_FALLBACK}`"
        )));
    }

    Ok(parsed)
}

/// Check whether `host` belongs to overseas probe endpoints forbidden for domestic pre-accel checks.
pub fn is_disallowed_domestic_probe_host(host: &str) -> bool {
    if is_forbidden_domestic_probe_host(host) {
        return true;
    }
    let normalized = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }
    EXTRA_FORBIDDEN_OVERSEAS_PROBE_SUFFIXES
        .iter()
        .any(|suffix| normalized == *suffix || normalized.ends_with(&format!(".{suffix}")))
}

/// Convert a host/IP/wildcard string into a Mihomo `DIRECT` anti-loop rule.
/// - IPv4 -> `IP-CIDR,<ip>/32,DIRECT,no-resolve`
/// - IPv6 -> `IP-CIDR6,<ip>/128,DIRECT,no-resolve`
/// - `*.example.com` or `+.example.com` -> `DOMAIN-SUFFIX,example.com,DIRECT`
/// - `example.com` -> `DOMAIN,example.com,DIRECT`
pub fn host_to_direct_rule(raw_host: &str) -> Option<String> {
    let trimmed = raw_host.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(ip) = parse_server_ip(trimmed) {
        return Some(match ip {
            IpAddr::V4(v4) => format!("IP-CIDR,{v4}/32,DIRECT,no-resolve"),
            IpAddr::V6(v6) => format!("IP-CIDR6,{v6}/128,DIRECT,no-resolve"),
        });
    }

    let normalized = trimmed.trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    if let Some(suffix) = normalized
        .strip_prefix("*.")
        .or_else(|| normalized.strip_prefix("+."))
    {
        let clean = suffix.trim_start_matches('.');
        if clean.is_empty() {
            return None;
        }
        return Some(format!("DOMAIN-SUFFIX,{clean},DIRECT"));
    }
    Some(format!("DOMAIN,{normalized},DIRECT"))
}

/// Convert a host/wildcard string into a Mihomo `dns.fake-ip-filter` entry.
/// Bare IP addresses return `None` because they do not undergo DNS fake-ip mapping.
pub fn host_to_fake_ip_filter(raw_host: &str) -> Option<String> {
    let trimmed = raw_host.trim();
    if trimmed.is_empty() || parse_server_ip(trimmed).is_some() {
        return None;
    }
    let normalized = trimmed.trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    if let Some(suffix) = normalized
        .strip_prefix("*.")
        .or_else(|| normalized.strip_prefix("+."))
    {
        let clean = suffix.trim_start_matches('.');
        if clean.is_empty() {
            return None;
        }
        return Some(format!("+.{clean}"));
    }
    Some(normalized)
}

/// Build the complete domestic pre-acceleration compile plan for Mihomo config generation.
pub fn build_preaccel_compile_plan(
    cfg: &PreAccelConfig,
    relays: &[PreAccelRelay],
    nodes: &[ProxyNode],
) -> CatResult<PreAccelCompilePlan> {
    let primary_probe = validate_domestic_probe_url(&cfg.probe_url)?;
    let fallback_probe = if cfg.fallback_probe_url.trim().is_empty() {
        None
    } else {
        Some(validate_domestic_probe_url(&cfg.fallback_probe_url)?)
    };
    let effective_interval = cfg.probe_interval_sec.clamp(10, 300);

    let mut plan = PreAccelCompilePlan {
        active: false,
        select_group_name: PREACCEL_SELECT_GROUP.to_string(),
        fallback_group_name: PREACCEL_FALLBACK_GROUP.to_string(),
        effective_probe_url: primary_probe.as_str().to_string(),
        effective_probe_interval_sec: effective_interval,
        ordered_relay_ids: Vec::new(),
        ordered_relay_names: Vec::new(),
        relay_proxies: Vec::new(),
        proxy_groups: Vec::new(),
        node_dialer_map: BTreeMap::new(),
        dialer_node_ids: Vec::new(),
        skipped_node_ids: Vec::new(),
        anti_loop_rules: Vec::new(),
        fake_ip_filter: Vec::new(),
        warnings: Vec::new(),
    };

    if !cfg.enabled {
        for node in nodes {
            plan.node_dialer_map.insert(node.id.clone(), None);
            plan.skipped_node_ids.push(node.id.clone());
        }
        return Ok(plan);
    }

    let mut enabled_relays: Vec<&PreAccelRelay> = relays.iter().filter(|r| r.enabled).collect();
    if enabled_relays.is_empty() {
        plan.warnings.push(
            "domestic pre-acceleration is enabled, but no enabled relays are configured; bypassing dialer-proxy"
                .to_string(),
        );
        for node in nodes {
            plan.node_dialer_map.insert(node.id.clone(), None);
            plan.skipped_node_ids.push(node.id.clone());
        }
        return Ok(plan);
    }

    // Sort deterministically: lower numeric `priority` comes first, tie-broken by `id`.
    enabled_relays.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));

    let mut used_proxy_names: HashSet<String> = HashSet::new();
    let mut id_to_proxy_name: BTreeMap<String, String> = BTreeMap::new();

    for (idx, relay) in enabled_relays.iter().enumerate() {
        let issues = validate_relay(relay);
        let mut hard_errors = Vec::new();
        for issue in issues {
            match issue.severity {
                RelayValidationSeverity::Error => {
                    hard_errors.push(format!("{}: {}", issue.field, issue.message));
                }
                RelayValidationSeverity::Warning => {
                    let tag = if relay.name.trim().is_empty() {
                        relay.id.as_str()
                    } else {
                        relay.name.as_str()
                    };
                    plan.warnings
                        .push(format!("relay `{tag}` ({}): {}", issue.field, issue.message));
                }
                RelayValidationSeverity::Info => {}
            }
        }
        if !hard_errors.is_empty() {
            return Err(CatError::Validation(format!(
                "invalid pre-acceleration relay `{}`: {}",
                relay.id,
                hard_errors.join("; ")
            )));
        }

        let proxy_name = allocate_unique_relay_name(relay, idx, &mut used_proxy_names);
        let proxy_yaml = compile_relay_to_mihomo_yaml(relay, &proxy_name)?;

        plan.ordered_relay_ids.push(relay.id.clone());
        plan.ordered_relay_names.push(proxy_name.clone());
        plan.relay_proxies.push(proxy_yaml);
        id_to_proxy_name.insert(relay.id.clone(), proxy_name);
    }

    // Build `fallback` active-standby group (explicit `lazy: false`, domestic 204 URL, clamped interval).
    let fallback_group = build_fallback_group_yaml(
        &plan.ordered_relay_names,
        &plan.effective_probe_url,
        effective_interval,
    );

    // Build `select` entry group.
    let mut select_members: Vec<String> = Vec::with_capacity(plan.ordered_relay_names.len() + 1);
    let mut select_seen: HashSet<String> = HashSet::new();

    if let Some(active_id) = cfg
        .active_relay_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if let Some(active_name) = id_to_proxy_name.get(active_id) {
            push_unique_exact(&mut select_members, &mut select_seen, active_name.clone());
            push_unique_exact(
                &mut select_members,
                &mut select_seen,
                PREACCEL_FALLBACK_GROUP.to_string(),
            );
        } else {
            plan.warnings.push(format!(
                "configured active_relay_id `{active_id}` was not found among enabled relays; falling back to `{PREACCEL_FALLBACK_GROUP}`"
            ));
            push_unique_exact(
                &mut select_members,
                &mut select_seen,
                PREACCEL_FALLBACK_GROUP.to_string(),
            );
        }
    } else if cfg.auto_failover {
        push_unique_exact(
            &mut select_members,
            &mut select_seen,
            PREACCEL_FALLBACK_GROUP.to_string(),
        );
    } else if let Some(first_name) = plan.ordered_relay_names.first() {
        push_unique_exact(&mut select_members, &mut select_seen, first_name.clone());
        push_unique_exact(
            &mut select_members,
            &mut select_seen,
            PREACCEL_FALLBACK_GROUP.to_string(),
        );
    }

    for name in &plan.ordered_relay_names {
        push_unique_exact(&mut select_members, &mut select_seen, name.clone());
    }

    let select_group = build_select_group_yaml(&select_members);
    plan.proxy_groups.push(select_group);
    plan.proxy_groups.push(fallback_group);
    plan.active = true;

    // Determine per-node `dialer-proxy` wrapping via `ProxyNode::should_apply_preaccel`.
    for node in nodes {
        let apply = node.enabled && node.should_apply_preaccel(cfg.skip_443_native);
        if apply {
            plan.node_dialer_map
                .insert(node.id.clone(), Some(PREACCEL_SELECT_GROUP.to_string()));
            plan.dialer_node_ids.push(node.id.clone());
        } else {
            plan.node_dialer_map.insert(node.id.clone(), None);
            plan.skipped_node_ids.push(node.id.clone());
        }
    }

    // Build top-priority anti-loop DIRECT rules and `dns.fake-ip-filter` entries (deduplicated in order).
    let mut seen_rules: HashSet<String> = HashSet::new();
    let mut seen_filters: HashSet<String> = HashSet::new();

    // 1. All enabled relay servers (IP -> IP-CIDR,no-resolve; domain -> DOMAIN + fake-ip-filter).
    for relay in &enabled_relays {
        add_anti_loop_host(
            &relay.server,
            &mut plan.anti_loop_rules,
            &mut seen_rules,
            &mut plan.fake_ip_filter,
            &mut seen_filters,
        );
    }

    // 2. Enabled business node entry hosts/IPs to prevent local DNS fake-ip or routing loops.
    for node in nodes.iter().filter(|n| n.enabled) {
        add_anti_loop_host(
            &node.server,
            &mut plan.anti_loop_rules,
            &mut seen_rules,
            &mut plan.fake_ip_filter,
            &mut seen_filters,
        );
    }

    // 3. Domestic 204 probe endpoints (primary + fallback + standard hicloud/miui suffixes).
    if let Some(host) = primary_probe.host_str() {
        add_anti_loop_host(
            host,
            &mut plan.anti_loop_rules,
            &mut seen_rules,
            &mut plan.fake_ip_filter,
            &mut seen_filters,
        );
    }
    if let Some(fb) = fallback_probe.as_ref()
        && let Some(host) = fb.host_str()
    {
        add_anti_loop_host(
            host,
            &mut plan.anti_loop_rules,
            &mut seen_rules,
            &mut plan.fake_ip_filter,
            &mut seen_filters,
        );
    }
    push_unique_ci(
        &mut plan.anti_loop_rules,
        &mut seen_rules,
        "DOMAIN-SUFFIX,hicloud.com,DIRECT".to_string(),
    );
    push_unique_ci(
        &mut plan.anti_loop_rules,
        &mut seen_rules,
        "DOMAIN-SUFFIX,miui.com,DIRECT".to_string(),
    );
    push_unique_ci(
        &mut plan.fake_ip_filter,
        &mut seen_filters,
        "+.hicloud.com".to_string(),
    );
    push_unique_ci(
        &mut plan.fake_ip_filter,
        &mut seen_filters,
        "+.miui.com".to_string(),
    );

    // 4. Configured static campus direct domains (if any).
    for domain in &cfg.campus_direct_domains {
        add_anti_loop_host(
            domain,
            &mut plan.anti_loop_rules,
            &mut seen_rules,
            &mut plan.fake_ip_filter,
            &mut seen_filters,
        );
    }

    Ok(plan)
}

/// Compile a single validated `PreAccelRelay` into a Mihomo proxy YAML mapping.
/// Enforces pure-IP no-SNI (or empty VLESS `servername`) semantics for domestic `:443` relays.
pub fn compile_relay_to_mihomo_yaml(relay: &PreAccelRelay, proxy_name: &str) -> CatResult<Value> {
    let protocol = RelayProtocol::parse(&relay.protocol).ok_or_else(|| {
        CatError::Validation(format!("unsupported relay protocol `{}`", relay.protocol))
    })?;

    let mut map = Mapping::new();
    map.insert(
        Value::String("name".to_string()),
        Value::String(proxy_name.to_string()),
    );
    map.insert(
        Value::String("type".to_string()),
        Value::String(protocol.mihomo_type().to_string()),
    );
    let server_str = parse_server_ip(&relay.server)
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| relay.server.trim().to_string());
    map.insert(
        Value::String("server".to_string()),
        Value::String(server_str),
    );
    map.insert(
        Value::String("port".to_string()),
        Value::Number(Number::from(relay.port)),
    );

    match protocol {
        RelayProtocol::AnyTls => {
            map.insert(
                Value::String("password".to_string()),
                Value::String(relay.password.clone()),
            );
            map.insert(Value::String("udp".to_string()), Value::Bool(true));
            map.insert(Value::String("tfo".to_string()), Value::Bool(true));
            map.insert(
                Value::String("idle-session-check-interval".to_string()),
                Value::Number(Number::from(30u64)),
            );
            map.insert(
                Value::String("idle-session-timeout".to_string()),
                Value::Number(Number::from(30u64)),
            );
            map.insert(
                Value::String("min-idle-session".to_string()),
                Value::Number(Number::from(2u64)),
            );
            map.insert(
                Value::String("skip-cert-verify".to_string()),
                Value::Bool(relay.skip_cert_verify),
            );
            maybe_insert_non_443_sni(&mut map, relay);
        }
        RelayProtocol::Trojan => {
            map.insert(
                Value::String("password".to_string()),
                Value::String(relay.password.clone()),
            );
            map.insert(Value::String("udp".to_string()), Value::Bool(true));
            map.insert(Value::String("tfo".to_string()), Value::Bool(true));
            map.insert(
                Value::String("skip-cert-verify".to_string()),
                Value::Bool(relay.skip_cert_verify),
            );
            maybe_insert_non_443_sni(&mut map, relay);
        }
        RelayProtocol::Vless => {
            map.insert(
                Value::String("uuid".to_string()),
                Value::String(relay.password.trim().to_string()),
            );
            map.insert(
                Value::String("network".to_string()),
                Value::String("tcp".to_string()),
            );
            map.insert(Value::String("tls".to_string()), Value::Bool(true));
            map.insert(Value::String("udp".to_string()), Value::Bool(true));
            map.insert(Value::String("tfo".to_string()), Value::Bool(true));
            map.insert(
                Value::String("skip-cert-verify".to_string()),
                Value::Bool(relay.skip_cert_verify),
            );
            let servername = if relay.port == 443 {
                ""
            } else {
                relay.sni.as_deref().map(str::trim).unwrap_or("")
            };
            map.insert(
                Value::String("servername".to_string()),
                Value::String(servername.to_string()),
            );
        }
        RelayProtocol::Hysteria2 => {
            map.insert(
                Value::String("password".to_string()),
                Value::String(relay.password.clone()),
            );
            map.insert(
                Value::String("skip-cert-verify".to_string()),
                Value::Bool(relay.skip_cert_verify),
            );
            maybe_insert_non_443_sni(&mut map, relay);
        }
        RelayProtocol::Tuic => {
            map.insert(
                Value::String("token".to_string()),
                Value::String(relay.password.clone()),
            );
            map.insert(
                Value::String("udp-relay-mode".to_string()),
                Value::String("native".to_string()),
            );
            map.insert(
                Value::String("skip-cert-verify".to_string()),
                Value::Bool(relay.skip_cert_verify),
            );
            maybe_insert_non_443_sni(&mut map, relay);
        }
    }

    Ok(Value::Mapping(map))
}

fn maybe_insert_non_443_sni(map: &mut Mapping, relay: &PreAccelRelay) {
    if relay.port != 443
        && let Some(sni) = relay.sni.as_deref().map(str::trim).filter(|s| !s.is_empty())
    {
        map.insert(
            Value::String("sni".to_string()),
            Value::String(sni.to_string()),
        );
    }
}

fn build_select_group_yaml(members: &[String]) -> Value {
    let mut map = Mapping::new();
    map.insert(
        Value::String("name".to_string()),
        Value::String(PREACCEL_SELECT_GROUP.to_string()),
    );
    map.insert(
        Value::String("type".to_string()),
        Value::String("select".to_string()),
    );
    map.insert(
        Value::String("proxies".to_string()),
        Value::Sequence(members.iter().cloned().map(Value::String).collect()),
    );
    Value::Mapping(map)
}

fn build_fallback_group_yaml(
    relay_names: &[String],
    probe_url: &str,
    interval_sec: u64,
) -> Value {
    let mut map = Mapping::new();
    map.insert(
        Value::String("name".to_string()),
        Value::String(PREACCEL_FALLBACK_GROUP.to_string()),
    );
    map.insert(
        Value::String("type".to_string()),
        Value::String("fallback".to_string()),
    );
    map.insert(
        Value::String("proxies".to_string()),
        Value::Sequence(relay_names.iter().cloned().map(Value::String).collect()),
    );
    map.insert(
        Value::String("url".to_string()),
        Value::String(probe_url.to_string()),
    );
    map.insert(
        Value::String("interval".to_string()),
        Value::Number(Number::from(interval_sec)),
    );
    map.insert(Value::String("lazy".to_string()), Value::Bool(false));
    Value::Mapping(map)
}

fn allocate_unique_relay_name(
    relay: &PreAccelRelay,
    idx: usize,
    used: &mut HashSet<String>,
) -> String {
    let base = if !relay.name.trim().is_empty() {
        relay.name.trim().to_string()
    } else if !relay.id.trim().is_empty() {
        relay.id.trim().to_string()
    } else {
        format!("preaccel-relay-{}", idx + 1)
    };

    if used.insert(base.clone()) {
        return base;
    }

    if !relay.id.trim().is_empty() {
        let with_id = format!("{base} ({})", relay.id.trim());
        if used.insert(with_id.clone()) {
            return with_id;
        }
    }

    let mut suffix = 2usize;
    loop {
        let candidate = format!("{base} #{suffix}");
        if used.insert(candidate.clone()) {
            return candidate;
        }
        suffix += 1;
    }
}

fn add_anti_loop_host(
    raw_host: &str,
    rules: &mut Vec<String>,
    seen_rules: &mut HashSet<String>,
    filters: &mut Vec<String>,
    seen_filters: &mut HashSet<String>,
) {
    if let Some(rule) = host_to_direct_rule(raw_host) {
        push_unique_ci(rules, seen_rules, rule);
    }
    if let Some(filter) = host_to_fake_ip_filter(raw_host) {
        push_unique_ci(filters, seen_filters, filter);
    }
}

fn push_unique_exact(items: &mut Vec<String>, seen: &mut HashSet<String>, value: String) {
    if seen.insert(value.clone()) {
        items.push(value);
    }
}

fn push_unique_ci(items: &mut Vec<String>, seen: &mut HashSet<String>, value: String) {
    let key = value.to_ascii_lowercase();
    if seen.insert(key) {
        items.push(value);
    }
}
