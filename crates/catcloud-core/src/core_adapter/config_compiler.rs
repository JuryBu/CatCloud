use crate::config::{is_forbidden_domestic_probe_host, validate_config};
use crate::core_adapter::format_host_port;
use crate::core_adapter::port_guard::AllocatedPorts;
use crate::error::{CatError, CatResult};
use crate::models::{
    AppConfig, DEFAULT_AI_ROUTING_DOMAINS, FallbackPolicy, MultiGroup, MultiGroupMode,
    MultiGroupState, OverrideMode, PreAccelRelay, ProxyNode,
};
use serde::{Deserialize, Serialize};
use serde_yaml_ng::{Mapping, Number, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use url::Url;

/// Canonical Mihomo selector group name for domestic pre-acceleration entry.
pub const PREACCEL_SELECT_GROUP_NAME: &str = "⚡ 国内预加速入口";

/// Canonical Mihomo fallback group name for active-standby domestic pre-acceleration relays.
pub const PREACCEL_FALLBACK_GROUP_NAME: &str = "🔄 预加速自动双活";

/// Default top-level proxy selector group generated when no custom multi-groups exist.
pub const DEFAULT_FALLBACK_GROUP_NAME: &str = "🐱 猫猫云梯";

/// Hard upper bound (16 MiB) on parsed YAML payload sizes to defend against YAML bombs.
pub const MAX_YAML_BYTES: usize = 16 * 1024 * 1024;

/// Default health check URL used by `load-balance` groups (overseas proxy path).
const DEFAULT_LOAD_BALANCE_URL: &str = "https://cp.cloudflare.com/generate_204";

/// Inputs fed into the decoupled Mihomo YAML configuration compiler.
#[derive(Debug, Clone)]
pub struct CompileInput<'a> {
    pub config: &'a AppConfig,
    pub nodes: &'a [ProxyNode],
    pub groups: &'a [MultiGroup],
    pub relays: &'a [PreAccelRelay],
    pub controller_secret: &'a str,
    pub allocated_ports: &'a AllocatedPorts,
    pub extra_prepend_rules: &'a [String],
    pub extra_fake_ip_filters: &'a [String],
    /// Optional pre-filtered member node IDs keyed by `group.id` (or `group.name`)
    /// produced by external hard-gate evaluation.
    pub group_filtered_members: &'a HashMap<String, Vec<String>>,
}

/// Summary mapping for one compiled multi-group.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompiledGroupMapping {
    pub group_id: String,
    pub group_name: String,
    pub mihomo_type: String,
    pub active_proxy_name: Option<String>,
    pub member_proxy_names: Vec<String>,
    pub has_reject_slot: bool,
}

/// Compilation counters exposed to dashboards, CLI diagnostics, and memory tiering.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CompileStats {
    pub total_proxies: usize,
    pub relay_proxies: usize,
    pub dialer_wrapped_proxies: usize,
    pub skipped_443_native_proxies: usize,
    pub proxy_groups: usize,
    pub total_rules: usize,
    pub preaccel_active: bool,
}

/// Severity of a static pre-flight check finding.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StaticCheckSeverity {
    Error,
    Warning,
}

/// Single diagnostic produced by `validate_compiled_yaml`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StaticCheckIssue {
    pub code: String,
    pub severity: StaticCheckSeverity,
    pub message: String,
}

/// Aggregated result of static YAML syntax, loop-guard, and domestic-probe pre-flight checks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct StaticValidationReport {
    pub ok: bool,
    pub issues: Vec<StaticCheckIssue>,
}

impl StaticValidationReport {
    pub fn errors(&self) -> Vec<&StaticCheckIssue> {
        self.issues
            .iter()
            .filter(|i| i.severity == StaticCheckSeverity::Error)
            .collect()
    }

    pub fn warnings(&self) -> Vec<&StaticCheckIssue> {
        self.issues
            .iter()
            .filter(|i| i.severity == StaticCheckSeverity::Warning)
            .collect()
    }
}

/// Final output of `compile_mihomo_config`.
#[derive(Debug, Clone)]
pub struct CompiledCoreConfig {
    pub yaml: String,
    pub value: Value,
    pub group_mappings: Vec<CompiledGroupMapping>,
    /// Map of `select` group name -> active proxy name to replay after `PUT /configs?force=true`.
    pub active_selections: BTreeMap<String, String>,
    pub stats: CompileStats,
    pub validation: StaticValidationReport,
    pub sha256: String,
}

/// Build default `DOMAIN-SUFFIX` routing rules for CatCloud's built-in AI service domains.
pub fn build_default_ai_routing_rules(target_group: &str) -> Vec<String> {
    let target = target_group.trim();
    DEFAULT_AI_ROUTING_DOMAINS
        .iter()
        .map(|domain| format!("DOMAIN-SUFFIX,{domain},{target}"))
        .collect()
}

/// Built-in whitelist of standard Mihomo rule types accepted during rule expansion and validation.
const VALID_MIHOMO_RULE_TYPES: &[&str] = &[
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-REGEX",
    "DOMAIN-WILDCARD",
    "GEOSITE",
    "GEOIP",
    "IP-CIDR",
    "IP-CIDR6",
    "IP-SUFFIX",
    "IP-ASN",
    "SRC-IP-CIDR",
    "DST-PORT",
    "SRC-PORT",
    "PROCESS-NAME",
    "PROCESS-NAME-REGEX",
    "PROCESS-PATH",
    "PROCESS-PATH-REGEX",
    "NETWORK",
    "UID",
    "IN-TYPE",
    "IN-USER",
    "IN-NAME",
    "SUB-RULE",
    "RULE-SET",
    "AND",
    "OR",
    "NOT",
    "MATCH",
];

fn is_valid_mihomo_rule_type(raw: &str) -> bool {
    let upper = raw.trim().to_ascii_uppercase();
    VALID_MIHOMO_RULE_TYPES.contains(&upper.as_str())
}

fn normalize_bare_domain_candidate(raw: &str) -> Option<&str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || is_valid_mihomo_rule_type(trimmed) {
        return None;
    }
    let candidate = trimmed
        .strip_prefix("*.")
        .or_else(|| trimmed.strip_prefix("+."))
        .unwrap_or(trimmed);
    if candidate.is_empty()
        || !candidate.contains('.')
        || candidate.starts_with('.')
        || candidate.ends_with('.')
        || candidate.starts_with('-')
        || candidate.ends_with('-')
        || candidate.contains("..")
        || candidate.parse::<Ipv4Addr>().is_ok()
    {
        return None;
    }
    if candidate
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
        && candidate.chars().any(|c| c.is_ascii_alphabetic())
    {
        Some(candidate)
    } else {
        None
    }
}

fn is_plausible_global_rule(rule: &str) -> bool {
    let trimmed = rule.trim();
    if trimmed.is_empty() {
        return false;
    }
    let parts: Vec<&str> = trimmed.split(',').map(str::trim).collect();
    if parts.len() < 2 {
        return false;
    }
    let rule_type = parts[0];
    if !is_valid_mihomo_rule_type(rule_type) {
        return false;
    }
    if rule_type.eq_ignore_ascii_case("MATCH") {
        return parts.len() == 2 && !parts[1].is_empty();
    }
    parts.len() >= 3 && parts.iter().all(|p| !p.is_empty())
}

/// Expand a multi-group match rule into one or more Mihomo rule strings.
///
/// - `@ai_domains` or `PRESET:AI` expands into `DEFAULT_AI_ROUTING_DOMAINS` bound to `group_name`.
/// - Single-segment bare Mihomo rule type names (e.g. `"DOMAIN-SUFFIX"`) or malformed strings
///   are safely ignored (empty `Vec`) instead of breaking `mihomo -t`.
/// - Single-segment valid domains (e.g. `"anthropic.com"`) auto-expand to `DOMAIN-SUFFIX,<domain>,<group>`.
/// - 2-part shorthand rules (`DOMAIN-SUFFIX,openai.com`) with a valid non-`MATCH` rule type
///   and non-empty payload expand to `{RULE_TYPE_UPPER},{payload},{group_name}`.
/// - 3-part rules ending in `no-resolve` insert `group_name` before `no-resolve`; otherwise
///   kept only when `rule_type` is valid and all 3 segments are non-empty.
pub fn expand_group_match_rule(rule: &str, group_name: &str) -> Vec<String> {
    let trimmed = rule.trim();
    let target = group_name.trim();
    if trimmed.is_empty() || target.is_empty() {
        return Vec::new();
    }
    if trimmed.eq_ignore_ascii_case("@ai_domains") || trimmed.eq_ignore_ascii_case("PRESET:AI") {
        return build_default_ai_routing_rules(target);
    }

    let parts: Vec<&str> = trimmed.split(',').map(str::trim).collect();
    match parts.as_slice() {
        [single] => {
            if let Some(domain) = normalize_bare_domain_candidate(single) {
                vec![format!("DOMAIN-SUFFIX,{domain},{target}")]
            } else {
                Vec::new()
            }
        }
        [rule_type, payload] => {
            if is_valid_mihomo_rule_type(rule_type)
                && !rule_type.eq_ignore_ascii_case("MATCH")
                && !payload.is_empty()
            {
                vec![format!(
                    "{},{payload},{target}",
                    rule_type.to_ascii_uppercase()
                )]
            } else {
                Vec::new()
            }
        }
        [rule_type, payload, third] => {
            if !is_valid_mihomo_rule_type(rule_type)
                || rule_type.eq_ignore_ascii_case("MATCH")
                || payload.is_empty()
                || third.is_empty()
            {
                return Vec::new();
            }
            let rt = rule_type.to_ascii_uppercase();
            if third.eq_ignore_ascii_case("no-resolve") {
                vec![format!("{rt},{payload},{target},no-resolve")]
            } else {
                vec![format!("{rt},{payload},{third}")]
            }
        }
        [rule_type, payload, third, fourth] => {
            if is_valid_mihomo_rule_type(rule_type)
                && !rule_type.eq_ignore_ascii_case("MATCH")
                && !payload.is_empty()
                && !third.is_empty()
                && !fourth.is_empty()
            {
                vec![format!(
                    "{},{payload},{third},{fourth}",
                    rule_type.to_ascii_uppercase()
                )]
            } else {
                Vec::new()
            }
        }
        _ => Vec::new(),
    }
}

/// Compile a full Mihomo YAML configuration from CatCloud's strongly-typed configuration,
/// nodes, multi-groups, and domestic pre-acceleration relays.
pub fn compile_mihomo_config(input: &CompileInput<'_>) -> CatResult<CompiledCoreConfig> {
    let cfg = input.config;
    validate_config(cfg)?;

    let secret = input.controller_secret.trim();
    if secret.is_empty() {
        return Err(CatError::Validation(
            "controller_secret cannot be empty when compiling Mihomo config".into(),
        ));
    }

    // 1. Collect enabled domestic pre-acceleration relays sorted by (priority ASC, id ASC).
    let mut enabled_relays: Vec<&PreAccelRelay> =
        input.relays.iter().filter(|r| r.enabled).collect();
    enabled_relays.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));
    let preaccel_active = cfg.preaccel.enabled && !enabled_relays.is_empty();

    let mut root = Mapping::new();

    // 2. Core listener & runtime fields (covering all 7 settings screenshots).
    insert_u64(
        &mut root,
        "mixed-port",
        u64::from(input.allocated_ports.mixed_port),
    );
    if let Some(p) = cfg.socks_port.filter(|&p| p > 0) {
        insert_u64(&mut root, "socks-port", u64::from(p));
    }
    if let Some(p) = cfg.http_port.filter(|&p| p > 0) {
        insert_u64(&mut root, "port", u64::from(p));
    }
    if let Some(p) = cfg.redir_port.filter(|&p| p > 0) {
        insert_u64(&mut root, "redir-port", u64::from(p));
    }
    if let Some(p) = cfg.tproxy_port.filter(|&p| p > 0) {
        insert_u64(&mut root, "tproxy-port", u64::from(p));
    }

    insert_bool(&mut root, "allow-lan", cfg.allow_lan);
    let bind_address = if cfg.allow_lan {
        let configured = cfg.bind_address.trim();
        if configured.is_empty() || configured == "127.0.0.1" {
            "*".to_string()
        } else {
            configured.to_string()
        }
    } else {
        "127.0.0.1".to_string()
    };
    insert_str(&mut root, "bind-address", &bind_address);
    insert_str(&mut root, "mode", cfg.proxy_mode.as_str());
    insert_str(&mut root, "log-level", cfg.log_level.as_str());
    insert_bool(&mut root, "ipv6", cfg.core_ipv6);
    insert_bool(&mut root, "unified-delay", cfg.unified_delay);
    insert_bool(&mut root, "tcp-concurrent", cfg.tcp_concurrent);
    insert_str(
        &mut root,
        "find-process-mode",
        cfg.find_process_mode.as_str(),
    );

    let controller_host = if cfg.allow_lan {
        cfg.controller_host.trim()
    } else {
        "127.0.0.1"
    };
    insert_str(
        &mut root,
        "external-controller",
        &format_host_port(controller_host, input.allocated_ports.controller_port),
    );
    insert_str(&mut root, "secret", secret);

    let mut profile_map = Mapping::new();
    insert_bool(
        &mut profile_map,
        "store-selected",
        cfg.core_runtime.store_selected,
    );
    insert_bool(
        &mut profile_map,
        "store-fake-ip",
        cfg.core_runtime.store_fake_ip,
    );
    root.insert(str_val("profile"), Value::Mapping(profile_map));

    insert_bool(&mut root, "geodata-mode", cfg.geodata.geodata_mode);
    insert_bool(&mut root, "geo-auto-update", cfg.geodata.auto_update);
    if cfg.geodata.geodata_mode {
        // Hard rule: whenever geodata-mode is enabled, enforce memconservative streaming loader.
        insert_str(&mut root, "geodata-loader", "memconservative");
    }

    if cfg.dns.use_hosts && !cfg.dns.hosts.is_empty() {
        let mut hosts_map = Mapping::new();
        for (domain, target) in &cfg.dns.hosts {
            insert_str(&mut hosts_map, domain, target);
        }
        root.insert(str_val("hosts"), Value::Mapping(hosts_map));
    }

    // 3. Build domestic pre-acceleration loop-prevention entries (domains/IPs + fake-ip-filter).
    let mut anti_loop_rules: Vec<String> = Vec::new();
    let mut anti_loop_fake_ip_domains: Vec<String> = Vec::new();
    let mut relay_servers_for_validation: Vec<String> = Vec::new();

    if preaccel_active {
        for relay in &enabled_relays {
            let server = relay.server.trim();
            if server.is_empty() {
                continue;
            }
            relay_servers_for_validation.push(server.to_string());
            push_unique(&mut anti_loop_rules, direct_rule_for_host_or_ip(server));
            if server.parse::<IpAddr>().is_err() {
                push_unique(&mut anti_loop_fake_ip_domains, server.to_string());
            }
        }

        for probe_url in [&cfg.preaccel.probe_url, &cfg.preaccel.fallback_probe_url] {
            if let Some(host) = extract_url_host(probe_url) {
                push_unique(&mut anti_loop_rules, direct_rule_for_host_or_ip(&host));
                if host.parse::<IpAddr>().is_err() {
                    push_unique(&mut anti_loop_fake_ip_domains, host);
                }
            }
        }
    }

    // Merge campus direct domains into both anti-loop rules and fake-ip-filter.
    for raw_domain in &cfg.preaccel.campus_direct_domains {
        let entry = raw_domain.trim();
        if entry.is_empty() {
            continue;
        }
        if entry.contains(',') {
            push_unique(&mut anti_loop_rules, entry.to_string());
        } else if entry.parse::<IpAddr>().is_ok() {
            push_unique(&mut anti_loop_rules, direct_rule_for_host_or_ip(entry));
        } else {
            let normalized = entry.trim_start_matches("*.").trim_start_matches("+.");
            push_unique(
                &mut anti_loop_rules,
                format!("DOMAIN-SUFFIX,{normalized},DIRECT"),
            );
            push_unique(&mut anti_loop_fake_ip_domains, entry.to_string());
        }
    }

    // 4. Full 7-screenshot DNS section.
    let dns_map = build_dns_section(
        cfg,
        input.allocated_ports,
        &anti_loop_fake_ip_domains,
        input.extra_fake_ip_filters,
    );
    root.insert(str_val("dns"), Value::Mapping(dns_map));

    // 5. Full TUN section.
    let tun_map = build_tun_section(cfg);
    root.insert(str_val("tun"), Value::Mapping(tun_map));

    // 6. Compile proxies (domestic relays + business nodes with optional dialer-proxy).
    let mut used_proxy_names: HashSet<String> = HashSet::new();
    let mut compiled_proxies: Vec<Value> = Vec::new();
    let mut relay_id_to_name: HashMap<String, String> = HashMap::new();
    let mut relay_names_ordered: Vec<String> = Vec::new();

    if preaccel_active {
        for relay in &enabled_relays {
            let base_name = if relay.name.trim().is_empty() {
                format!("PreAccel-{}", relay.id)
            } else {
                relay.name.trim().to_string()
            };
            let unique_name = make_unique_name(&base_name, &mut used_proxy_names);
            let relay_yaml = build_relay_proxy_mapping(relay, &unique_name);
            compiled_proxies.push(Value::Mapping(relay_yaml));
            relay_id_to_name.insert(relay.id.clone(), unique_name.clone());
            relay_names_ordered.push(unique_name);
        }
    }

    let mut node_id_to_name: HashMap<String, String> = HashMap::new();
    let mut all_enabled_node_names: Vec<String> = Vec::new();
    let mut dialer_wrapped_proxies = 0usize;
    let mut skipped_443_native_proxies = 0usize;

    for node in input.nodes.iter().filter(|n| n.enabled) {
        let base_name = if node.name.trim().is_empty() {
            format!("Node-{}", node.id)
        } else {
            node.name.trim().to_string()
        };
        let unique_name = make_unique_name(&base_name, &mut used_proxy_names);
        let mut proxy_map = build_node_proxy_mapping(node, &unique_name)?;

        if preaccel_active {
            if node.should_apply_preaccel(cfg.preaccel.skip_443_native) {
                insert_str(&mut proxy_map, "dialer-proxy", PREACCEL_SELECT_GROUP_NAME);
                dialer_wrapped_proxies += 1;
            } else {
                if proxy_map.get("dialer-proxy").and_then(Value::as_str)
                    == Some(PREACCEL_SELECT_GROUP_NAME)
                {
                    proxy_map.shift_remove("dialer-proxy");
                }
                if cfg.preaccel.skip_443_native
                    && node.is_443_native
                    && node.preaccel_override.is_none()
                {
                    skipped_443_native_proxies += 1;
                }
            }
        } else if proxy_map.get("dialer-proxy").and_then(Value::as_str)
            == Some(PREACCEL_SELECT_GROUP_NAME)
        {
            proxy_map.shift_remove("dialer-proxy");
        }

        compiled_proxies.push(Value::Mapping(proxy_map));
        node_id_to_name.insert(node.id.clone(), unique_name.clone());
        all_enabled_node_names.push(unique_name);
    }

    root.insert(str_val("proxies"), Value::Sequence(compiled_proxies));

    // 7. Compile proxy-groups: pre-acceleration chain + all 4 MultiGroupMode variants.
    let mut proxy_groups: Vec<Value> = Vec::new();
    let mut group_mappings: Vec<CompiledGroupMapping> = Vec::new();
    let mut active_selections: BTreeMap<String, String> = BTreeMap::new();

    if preaccel_active {
        // Fallback group: active-standby domestic 204 health check with lazy: false.
        let mut fallback_group = Mapping::new();
        insert_str(&mut fallback_group, "name", PREACCEL_FALLBACK_GROUP_NAME);
        insert_str(&mut fallback_group, "type", "fallback");
        fallback_group.insert(
            str_val("proxies"),
            string_seq(relay_names_ordered.iter().map(String::as_str)),
        );
        insert_str(&mut fallback_group, "url", cfg.preaccel.probe_url.trim());
        insert_u64(&mut fallback_group, "interval", cfg.preaccel.probe_interval_sec);
        insert_bool(&mut fallback_group, "lazy", false);

        // Select group: entry point referenced by dialer-proxy.
        let mut select_members: Vec<String> = Vec::new();
        let active_relay_name = cfg
            .preaccel
            .active_relay_id
            .as_deref()
            .and_then(|id| relay_id_to_name.get(id))
            .cloned();

        if let Some(ref chosen) = active_relay_name {
            if !cfg.preaccel.auto_failover {
                push_unique(&mut select_members, chosen.clone());
            }
        }
        push_unique(
            &mut select_members,
            PREACCEL_FALLBACK_GROUP_NAME.to_string(),
        );
        if let Some(ref chosen) = active_relay_name {
            push_unique(&mut select_members, chosen.clone());
        }
        for name in &relay_names_ordered {
            push_unique(&mut select_members, name.clone());
        }
        push_unique(&mut select_members, "DIRECT".to_string());

        let selected_first = select_members
            .first()
            .cloned()
            .unwrap_or_else(|| PREACCEL_FALLBACK_GROUP_NAME.to_string());
        active_selections.insert(PREACCEL_SELECT_GROUP_NAME.to_string(), selected_first);

        let mut select_group = Mapping::new();
        insert_str(&mut select_group, "name", PREACCEL_SELECT_GROUP_NAME);
        insert_str(&mut select_group, "type", "select");
        select_group.insert(
            str_val("proxies"),
            string_seq(select_members.iter().map(String::as_str)),
        );

        proxy_groups.push(Value::Mapping(select_group));
        proxy_groups.push(Value::Mapping(fallback_group));
    }

    let mut default_match_target: Option<String> = None;
    let preferred_active_group_id = cfg
        .active_group_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    for group in input.groups {
        let group_name = if group.name.trim().is_empty() {
            group.id.trim().to_string()
        } else {
            group.name.trim().to_string()
        };
        if group_name.is_empty() {
            continue;
        }
        if preferred_active_group_id == Some(group.id.as_str()) {
            default_match_target = Some(group_name.clone());
        } else if default_match_target.is_none() {
            default_match_target = Some(group_name.clone());
        }

        // Resolve member list: honor hard-gate filtered override (including explicit empty list).
        let explicit_filtered = input
            .group_filtered_members
            .get(&group.id)
            .or_else(|| input.group_filtered_members.get(&group_name));

        let mut members: Vec<String> = Vec::new();
        if let Some(filtered_ids) = explicit_filtered {
            for nid in filtered_ids {
                if let Some(proxy_name) = node_id_to_name.get(nid) {
                    push_unique(&mut members, proxy_name.clone());
                } else if nid == "REJECT" || nid == "DIRECT" {
                    push_unique(&mut members, nid.clone());
                }
            }
        } else if !group.member_node_ids.is_empty() {
            for nid in &group.member_node_ids {
                if let Some(proxy_name) = node_id_to_name.get(nid) {
                    push_unique(&mut members, proxy_name.clone());
                } else if nid == "REJECT" || nid == "DIRECT" {
                    push_unique(&mut members, nid.clone());
                }
            }
        } else if group.mode == MultiGroupMode::ConditionalPool {
            for name in &all_enabled_node_names {
                push_unique(&mut members, name.clone());
            }
        }

        // Keep a REJECT slot on select groups when fallback_policy == StrictCircuitBreak.
        // For load-balance groups, NEVER mix REJECT alongside healthy nodes (Mihomo would
        // route a fraction of healthy traffic to REJECT); only emit ["REJECT"] when CircuitOpen
        // or when zero healthy members remain.
        let is_load_balance = matches!(
            group.mode,
            MultiGroupMode::LoadBalanceConsistentHash | MultiGroupMode::LoadBalanceRoundRobin
        );
        let has_reject_slot = group.fallback_policy == FallbackPolicy::StrictCircuitBreak;
        if has_reject_slot {
            if is_load_balance {
                if group.state == MultiGroupState::CircuitOpen || members.is_empty() {
                    members.clear();
                    members.push("REJECT".to_string());
                }
            } else {
                push_unique(&mut members, "REJECT".to_string());
            }
        }

        // Prevent Mihomo from failing on an empty group if no nodes exist yet.
        if members.is_empty() {
            members.push("DIRECT".to_string());
        }

        // Resolve active proxy name for sticky selection preservation.
        let resolved_active: Option<String> = if group.state == MultiGroupState::CircuitOpen
            && has_reject_slot
        {
            Some("REJECT".to_string())
        } else if let Some(ref active_id) = group.active_node_id {
            if active_id == "REJECT" && has_reject_slot {
                Some("REJECT".to_string())
            } else if active_id == "DIRECT" {
                Some("DIRECT".to_string())
            } else {
                node_id_to_name.get(active_id).cloned()
            }
        } else {
            None
        };

        let mut group_map = Mapping::new();
        insert_str(&mut group_map, "name", &group_name);

        let (mihomo_type, final_active) = match group.mode {
            MultiGroupMode::StickyBest | MultiGroupMode::ConditionalPool => {
                // Move active_node_id to index 0 so `store-selected: false` never resets it on reload.
                if let Some(ref active_name) = resolved_active {
                    if let Some(pos) = members.iter().position(|m| m == active_name) {
                        let chosen = members.remove(pos);
                        members.insert(0, chosen);
                    } else {
                        members.insert(0, active_name.clone());
                    }
                }
                insert_str(&mut group_map, "type", "select");
                group_map.insert(
                    str_val("proxies"),
                    string_seq(members.iter().map(String::as_str)),
                );
                let head = members.first().cloned();
                if let Some(ref h) = head {
                    active_selections.insert(group_name.clone(), h.clone());
                }
                ("select".to_string(), head)
            }
            MultiGroupMode::LoadBalanceConsistentHash => {
                insert_str(&mut group_map, "type", "load-balance");
                insert_str(&mut group_map, "strategy", "consistent-hashing");
                insert_str(&mut group_map, "url", DEFAULT_LOAD_BALANCE_URL);
                insert_u64(&mut group_map, "interval", 300);
                insert_bool(&mut group_map, "lazy", true);
                group_map.insert(
                    str_val("proxies"),
                    string_seq(members.iter().map(String::as_str)),
                );
                ("load-balance".to_string(), None)
            }
            MultiGroupMode::LoadBalanceRoundRobin => {
                insert_str(&mut group_map, "type", "load-balance");
                insert_str(&mut group_map, "strategy", "round-robin");
                insert_str(&mut group_map, "url", DEFAULT_LOAD_BALANCE_URL);
                insert_u64(&mut group_map, "interval", 300);
                insert_bool(&mut group_map, "lazy", true);
                group_map.insert(
                    str_val("proxies"),
                    string_seq(members.iter().map(String::as_str)),
                );
                ("load-balance".to_string(), None)
            }
        };

        group_mappings.push(CompiledGroupMapping {
            group_id: group.id.clone(),
            group_name: group_name.clone(),
            mihomo_type,
            active_proxy_name: final_active,
            member_proxy_names: members,
            has_reject_slot,
        });
        proxy_groups.push(Value::Mapping(group_map));
    }

    // Generate default fallback group when no custom MultiGroups are defined.
    let match_target = match default_match_target {
        Some(target) => target,
        None => {
            let mut default_members = all_enabled_node_names.clone();
            if default_members.is_empty() {
                default_members.push("DIRECT".to_string());
            }
            if let Some(first) = default_members.first() {
                active_selections.insert(DEFAULT_FALLBACK_GROUP_NAME.to_string(), first.clone());
            }
            let mut default_group = Mapping::new();
            insert_str(&mut default_group, "name", DEFAULT_FALLBACK_GROUP_NAME);
            insert_str(&mut default_group, "type", "select");
            default_group.insert(
                str_val("proxies"),
                string_seq(default_members.iter().map(String::as_str)),
            );
            proxy_groups.push(Value::Mapping(default_group));
            DEFAULT_FALLBACK_GROUP_NAME.to_string()
        }
    };

    root.insert(str_val("proxy-groups"), Value::Sequence(proxy_groups));

    // 8. Compile ordered rules chain:
    //    anti-loop -> extra_prepend_rules -> global_prepend_rules -> group match_rules -> global_append_rules -> MATCH
    let mut rules: Vec<String> = Vec::new();
    for r in anti_loop_rules {
        push_unique(&mut rules, r);
    }
    for r in input.extra_prepend_rules {
        let trimmed = r.trim();
        if is_plausible_global_rule(trimmed) {
            push_unique(&mut rules, trimmed.to_string());
        }
    }
    for r in &cfg.rules_override.global_prepend_rules {
        let trimmed = r.trim();
        if is_plausible_global_rule(trimmed) {
            push_unique(&mut rules, trimmed.to_string());
        }
    }
    for group in input.groups {
        let target = if group.name.trim().is_empty() {
            group.id.trim()
        } else {
            group.name.trim()
        };
        if target.is_empty() {
            continue;
        }
        for raw_rule in &group.match_rules {
            for expanded in expand_group_match_rule(raw_rule, target) {
                push_unique(&mut rules, expanded);
            }
        }
    }
    for r in &cfg.rules_override.global_append_rules {
        let trimmed = r.trim();
        if is_plausible_global_rule(trimmed) {
            push_unique(&mut rules, trimmed.to_string());
        }
    }
    let has_match_rule = rules
        .iter()
        .any(|r| r.to_ascii_uppercase().starts_with("MATCH,"));
    if !has_match_rule {
        rules.push(format!("MATCH,{match_target}"));
    }

    root.insert(
        str_val("rules"),
        string_seq(rules.iter().map(String::as_str)),
    );

    // 9. Apply optional declarative YAML Merge Patch override without mutating original on error.
    let mut final_value = Value::Mapping(root);
    if matches!(
        cfg.rules_override.override_mode,
        OverrideMode::MergePatch | OverrideMode::Both
    ) {
        if let Some(patch_path_str) = cfg
            .rules_override
            .override_merge_path
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let patch_path = Path::new(patch_path_str);
            let patch_yaml = std::fs::read_to_string(patch_path).map_err(|e| {
                CatError::Config(format!(
                    "failed to read YAML merge patch `{}`: {e}",
                    patch_path.display()
                ))
            })?;
            final_value = apply_yaml_merge_patch(&final_value, &patch_yaml)?;
        }
    }

    let yaml = serde_yaml_ng::to_string(&final_value)?;
    let validation = validate_compiled_yaml(&yaml, &relay_servers_for_validation)?;

    let total_proxies = final_value
        .get("proxies")
        .and_then(Value::as_sequence)
        .map_or(0, Vec::len);
    let total_groups = final_value
        .get("proxy-groups")
        .and_then(Value::as_sequence)
        .map_or(0, Vec::len);
    let total_rules = final_value
        .get("rules")
        .and_then(Value::as_sequence)
        .map_or(0, Vec::len);

    let stats = CompileStats {
        total_proxies,
        relay_proxies: relay_names_ordered.len(),
        dialer_wrapped_proxies,
        skipped_443_native_proxies,
        proxy_groups: total_groups,
        total_rules,
        preaccel_active,
    };

    let sha256 = sha256_hex(yaml.as_bytes());

    Ok(CompiledCoreConfig {
        yaml,
        value: final_value,
        group_mappings,
        active_selections,
        stats,
        validation,
        sha256,
    })
}

/// Redact sensitive credential fields (`password`, `uuid`, `token`, `private-key`, `auth-str`)
/// across all compiled `proxies` entries and mask domestic pre-acceleration relay `server`
/// addresses with `<REDACTED>` for safe UI/diagnostics preview.
pub fn redact_compiled_yaml_for_preview(
    compiled: &CompiledCoreConfig,
    relays: &[PreAccelRelay],
) -> CatResult<String> {
    const SENSITIVE_KEYS: &[&str] = &[
        "password",
        "uuid",
        "token",
        "private-key",
        "auth-str",
        "obfs-password",
    ];
    let relay_servers: HashSet<String> = relays
        .iter()
        .map(|r| r.server.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    let mut doc = compiled.value.clone();
    if let Some(root) = doc.as_mapping_mut() {
        let proxies_key = str_val("proxies");
        if let Some(proxies) = root.get_mut(&proxies_key).and_then(Value::as_sequence_mut) {
            let server_key = str_val("server");
            for (idx, item) in proxies.iter_mut().enumerate() {
                let Some(map) = item.as_mapping_mut() else {
                    continue;
                };
                for &key in SENSITIVE_KEYS {
                    let yaml_key = str_val(key);
                    if let Some(val) = map.get_mut(&yaml_key) {
                        if !val.is_null() {
                            *val = Value::String("<REDACTED>".to_string());
                        }
                    }
                }
                let is_relay = idx < compiled.stats.relay_proxies
                    || map
                        .get(&server_key)
                        .and_then(Value::as_str)
                        .is_some_and(|s| relay_servers.contains(&s.trim().to_ascii_lowercase()));
                if is_relay {
                    if let Some(server_val) = map.get_mut(&server_key) {
                        if !server_val.is_null() {
                            *server_val = Value::String("<REDACTED>".to_string());
                        }
                    }
                }
            }
        }
    }
    Ok(serde_yaml_ng::to_string(&doc)?)
}

/// Apply a declarative RFC 7396 style YAML Merge Patch onto a cloned copy of `base`.
///
/// - Enforces `MAX_YAML_BYTES` (16 MiB) and resolves YAML `<<` anchors via `apply_merge()`.
/// - Rejects syntax errors or non-mapping top-level patches and NEVER modifies `base` on failure.
/// - Inside mappings, a patch value of `null` deletes the corresponding key from the target.
pub fn apply_yaml_merge_patch(base: &Value, patch_yaml: &str) -> CatResult<Value> {
    if patch_yaml.len() > MAX_YAML_BYTES {
        return Err(CatError::Validation(format!(
            "YAML merge patch exceeds maximum allowed size ({} > {MAX_YAML_BYTES} bytes)",
            patch_yaml.len()
        )));
    }
    let mut patch_value: Value = serde_yaml_ng::from_str(patch_yaml)?;
    patch_value.apply_merge()?;

    if !patch_value.is_mapping() {
        return Err(CatError::Validation(
            "YAML merge patch root document must be a mapping".into(),
        ));
    }

    let mut cloned = base.clone();
    merge_yaml_values(&mut cloned, patch_value);
    Ok(cloned)
}

fn merge_yaml_values(target: &mut Value, patch: Value) {
    match (target, patch) {
        (Value::Mapping(target_map), Value::Mapping(patch_map)) => {
            for (k, v) in patch_map {
                if v.is_null() {
                    target_map.shift_remove(&k);
                } else if let Some(existing) = target_map.get_mut(&k) {
                    if existing.is_mapping() && v.is_mapping() {
                        merge_yaml_values(existing, v);
                    } else {
                        *existing = v;
                    }
                } else {
                    target_map.insert(k, v);
                }
            }
        }
        (target_slot, patch_val) => {
            *target_slot = patch_val;
        }
    }
}

/// Perform static pre-flight checks on compiled Mihomo YAML:
/// - YAML syntax validity & 16 MiB size cap (with `<<` anchor expansion)
/// - Empty or missing `proxies` list inside any `proxy-groups` entry
/// - Cyclic references between `proxy-groups`
/// - Overseas `gstatic`/`google`/`cloudflare` URLs mistakenly assigned to domestic pre-accel groups
/// - Missing `DIRECT` loop-prevention rules for pre-acceleration relay servers
pub fn validate_compiled_yaml(
    yaml_str: &str,
    relay_servers: &[String],
) -> CatResult<StaticValidationReport> {
    if yaml_str.len() > MAX_YAML_BYTES {
        return Err(CatError::Validation(format!(
            "compiled YAML exceeds maximum allowed size ({} > {MAX_YAML_BYTES} bytes)",
            yaml_str.len()
        )));
    }

    let mut doc: Value = serde_yaml_ng::from_str(yaml_str)?;
    doc.apply_merge()?;

    let Some(root) = doc.as_mapping() else {
        return Err(CatError::Validation(
            "compiled Mihomo YAML root must be a mapping".into(),
        ));
    };

    let mut issues: Vec<StaticCheckIssue> = Vec::new();

    // Map proxy name -> server for discovering relay servers referenced via dialer-proxy.
    let mut proxy_server_map: HashMap<String, String> = HashMap::new();
    let mut dialer_targets: HashSet<String> = HashSet::new();
    if let Some(proxies) = root.get("proxies").and_then(Value::as_sequence) {
        for item in proxies {
            if let Some(map) = item.as_mapping() {
                if let Some(name) = map.get("name").and_then(Value::as_str) {
                    if let Some(server) = map.get("server").and_then(Value::as_str) {
                        proxy_server_map.insert(name.to_string(), server.to_string());
                    }
                }
                if let Some(dp) = map.get("dialer-proxy").and_then(Value::as_str) {
                    if !dp.trim().is_empty() {
                        dialer_targets.insert(dp.trim().to_string());
                    }
                }
            }
        }
    }

    // Inspect proxy-groups for empty groups, cycles, and forbidden overseas domestic probe URLs.
    let mut group_members_map: HashMap<String, Vec<String>> = HashMap::new();
    if let Some(groups) = root.get("proxy-groups").and_then(Value::as_sequence) {
        for (idx, item) in groups.iter().enumerate() {
            let Some(map) = item.as_mapping() else {
                issues.push(StaticCheckIssue {
                    code: "invalid_proxy_group".to_string(),
                    severity: StaticCheckSeverity::Error,
                    message: format!("proxy-groups[{idx}] must be a YAML mapping"),
                });
                continue;
            };
            let group_name = map
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("<unnamed>")
                .to_string();

            let members: Vec<String> = map
                .get("proxies")
                .and_then(Value::as_sequence)
                .map(|seq| {
                    seq.iter()
                        .filter_map(Value::as_str)
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default();

            let has_use = map
                .get("use")
                .and_then(Value::as_sequence)
                .is_some_and(|s| !s.is_empty());

            if members.is_empty() && !has_use {
                issues.push(StaticCheckIssue {
                    code: "empty_proxy_group".to_string(),
                    severity: StaticCheckSeverity::Error,
                    message: format!("proxy group `{group_name}` has an empty `proxies` list"),
                });
            }

            // Detect forbidden overseas probe URLs on domestic pre-acceleration groups.
            if is_preaccel_group_name(&group_name, &dialer_targets) {
                if let Some(probe_url) = map.get("url").and_then(Value::as_str) {
                    if let Some(host) = extract_url_host(probe_url) {
                        if is_forbidden_domestic_probe_host(&host) {
                            issues.push(StaticCheckIssue {
                                code: "forbidden_overseas_domestic_probe".to_string(),
                                severity: StaticCheckSeverity::Error,
                                message: format!(
                                    "domestic pre-acceleration group `{group_name}` must not probe overseas host `{host}`"
                                ),
                            });
                        }
                    }
                }
            }

            group_members_map.insert(group_name, members);
        }
    }

    // Cycle detection across proxy-groups.
    for cycle in detect_group_cycles(&group_members_map) {
        issues.push(StaticCheckIssue {
            code: "group_cycle".to_string(),
            severity: StaticCheckSeverity::Error,
            message: format!("cyclic proxy-group reference detected: {}", cycle.join(" -> ")),
        });
    }

    // Gather all relay servers to verify DIRECT anti-loop rules:
    // explicit caller list + any proxies transitively reachable from dialer-proxy targets.
    let mut required_relay_servers: Vec<String> = Vec::new();
    for s in relay_servers {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            push_unique(&mut required_relay_servers, trimmed.to_string());
        }
    }
    for dp_target in &dialer_targets {
        let reachable = collect_transitive_proxies(dp_target, &group_members_map);
        for proxy_name in reachable {
            if let Some(server) = proxy_server_map.get(&proxy_name) {
                push_unique(&mut required_relay_servers, server.clone());
            }
        }
    }

    let rules: Vec<String> = root
        .get("rules")
        .and_then(Value::as_sequence)
        .map(|seq| {
            seq.iter()
                .filter_map(Value::as_str)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    for relay_server in &required_relay_servers {
        if !has_direct_anti_loop_rule(relay_server, &rules) {
            issues.push(StaticCheckIssue {
                code: "missing_relay_direct_rule".to_string(),
                severity: StaticCheckSeverity::Error,
                message: format!(
                    "pre-acceleration relay server `{relay_server}` is missing a top-level DIRECT loop-prevention rule"
                ),
            });
        }
    }

    if !rules
        .iter()
        .any(|r| r.to_ascii_uppercase().starts_with("MATCH,"))
    {
        issues.push(StaticCheckIssue {
            code: "missing_match_rule".to_string(),
            severity: StaticCheckSeverity::Warning,
            message: "rules section does not end with a fallback MATCH rule".to_string(),
        });
    }

    if root.get("external-controller").is_some() {
        let has_secret = root
            .get("secret")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.trim().is_empty());
        if !has_secret {
            issues.push(StaticCheckIssue {
                code: "missing_controller_secret".to_string(),
                severity: StaticCheckSeverity::Warning,
                message: "external-controller is enabled without a non-empty secret".to_string(),
            });
        }
    }

    let ok = issues
        .iter()
        .all(|issue| issue.severity != StaticCheckSeverity::Error);

    Ok(StaticValidationReport { ok, issues })
}

// ============================================================================
// Internal section builders & helpers
// ============================================================================

fn build_dns_section(
    cfg: &AppConfig,
    allocated_ports: &AllocatedPorts,
    anti_loop_fake_ip_domains: &[String],
    extra_fake_ip_filters: &[String],
) -> Mapping {
    let dns = &cfg.dns;
    let mut map = Mapping::new();

    let dns_host = if cfg.allow_lan {
        cfg.dns_listen_host.trim()
    } else {
        "127.0.0.1"
    };

    insert_bool(&mut map, "enable", dns.enable);
    insert_str(
        &mut map,
        "listen",
        &format_host_port(dns_host, allocated_ports.dns_port),
    );
    insert_bool(&mut map, "ipv6", dns.ipv6);
    insert_bool(&mut map, "use-hosts", dns.use_hosts);
    insert_bool(&mut map, "use-system-hosts", dns.use_system_hosts);
    insert_bool(&mut map, "respect-rules", dns.respect_rules);
    insert_bool(&mut map, "prefer-h3", dns.prefer_h3);
    insert_str(&mut map, "enhanced-mode", dns.mode.as_str());
    insert_str(&mut map, "fake-ip-range", &dns.fake_ip_range);

    let mut merged_fake_ip_filter: Vec<String> = Vec::new();
    for item in &dns.fake_ip_filter {
        let trimmed = item.trim();
        if !trimmed.is_empty() {
            push_unique(&mut merged_fake_ip_filter, trimmed.to_string());
        }
    }
    for item in anti_loop_fake_ip_domains {
        let trimmed = item.trim();
        if !trimmed.is_empty() {
            push_unique(&mut merged_fake_ip_filter, trimmed.to_string());
        }
    }
    for item in extra_fake_ip_filters {
        let trimmed = item.trim();
        if !trimmed.is_empty() {
            push_unique(&mut merged_fake_ip_filter, trimmed.to_string());
        }
    }
    map.insert(
        str_val("fake-ip-filter"),
        string_seq(merged_fake_ip_filter.iter().map(String::as_str)),
    );

    map.insert(
        str_val("default-nameserver"),
        string_seq(dns.default_nameserver.iter().map(String::as_str)),
    );

    let mut policy_map = Mapping::new();
    for (pattern, servers) in &dns.nameserver_policy {
        policy_map.insert(
            str_val(pattern),
            string_seq(servers.iter().map(String::as_str)),
        );
    }
    map.insert(str_val("nameserver-policy"), Value::Mapping(policy_map));

    map.insert(
        str_val("nameserver"),
        string_seq(dns.nameserver.iter().map(String::as_str)),
    );
    map.insert(
        str_val("fallback"),
        string_seq(dns.fallback.iter().map(String::as_str)),
    );
    map.insert(
        str_val("proxy-server-nameserver"),
        string_seq(dns.proxy_server_nameserver.iter().map(String::as_str)),
    );

    let mut ff_map = Mapping::new();
    insert_bool(&mut ff_map, "geoip", dns.fallback_filter.geoip);
    insert_str(&mut ff_map, "geoip-code", &dns.fallback_filter.geoip_code);
    ff_map.insert(
        str_val("geosite"),
        string_seq(dns.fallback_filter.geosite.iter().map(String::as_str)),
    );
    ff_map.insert(
        str_val("ipcidr"),
        string_seq(dns.fallback_filter.ipcidr.iter().map(String::as_str)),
    );
    ff_map.insert(
        str_val("domain"),
        string_seq(dns.fallback_filter.domain.iter().map(String::as_str)),
    );
    map.insert(str_val("fallback-filter"), Value::Mapping(ff_map));

    map
}

fn build_tun_section(cfg: &AppConfig) -> Mapping {
    let tun = &cfg.tun;
    let mut map = Mapping::new();
    insert_bool(&mut map, "enable", tun.enabled);
    insert_str(&mut map, "stack", tun.stack_mode.as_str());
    insert_str(&mut map, "device", &tun.device_name);
    insert_bool(&mut map, "auto-route", tun.auto_route);
    insert_bool(&mut map, "auto-detect-interface", tun.auto_detect_interface);
    insert_bool(&mut map, "strict-route", tun.strict_route);
    insert_u64(&mut map, "mtu", u64::from(tun.mtu));
    map.insert(
        str_val("dns-hijack"),
        string_seq(tun.dns_hijack.iter().map(String::as_str)),
    );
    map
}

fn build_relay_proxy_mapping(relay: &PreAccelRelay, unique_name: &str) -> Mapping {
    let proto = relay.protocol.trim().to_ascii_lowercase();
    let effective_proto = if proto.is_empty() {
        "anytls".to_string()
    } else {
        proto
    };

    let mut map = Mapping::new();
    insert_str(&mut map, "name", unique_name);
    insert_str(&mut map, "type", &effective_proto);
    insert_str(&mut map, "server", relay.server.trim());
    insert_u64(&mut map, "port", u64::from(relay.port));

    match effective_proto.as_str() {
        "vless" => {
            insert_str(&mut map, "uuid", &relay.password);
            insert_bool(&mut map, "tls", true);
            insert_bool(&mut map, "udp", true);
            // Pure-IP domestic relays MUST omit servername unless explicitly configured.
            if let Some(sni) = relay.sni.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                insert_str(&mut map, "servername", sni);
            }
            insert_bool(&mut map, "skip-cert-verify", relay.skip_cert_verify);
        }
        "trojan" | "anytls" => {
            insert_str(&mut map, "password", &relay.password);
            insert_bool(&mut map, "udp", true);
            // Pure-IP domestic relays MUST omit sni unless explicitly configured.
            if let Some(sni) = relay.sni.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                insert_str(&mut map, "sni", sni);
            }
            insert_bool(&mut map, "skip-cert-verify", relay.skip_cert_verify);
        }
        _ => {
            insert_str(&mut map, "password", &relay.password);
            insert_bool(&mut map, "udp", true);
            if let Some(sni) = relay.sni.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                insert_str(&mut map, "sni", sni);
            }
            insert_bool(&mut map, "skip-cert-verify", relay.skip_cert_verify);
        }
    }

    map
}

fn build_node_proxy_mapping(node: &ProxyNode, unique_name: &str) -> CatResult<Mapping> {
    let mut map = match serde_yaml_ng::to_value(&node.raw_config)? {
        Value::Mapping(m) => m,
        _ => Mapping::new(),
    };

    insert_str(&mut map, "name", unique_name);
    if !map.contains_key("type") && !node.protocol.trim().is_empty() {
        insert_str(&mut map, "type", &node.protocol.trim().to_ascii_lowercase());
    }
    if !map.contains_key("server") && !node.server.trim().is_empty() {
        insert_str(&mut map, "server", node.server.trim());
    }
    if !map.contains_key("port") && node.port > 0 {
        insert_u64(&mut map, "port", u64::from(node.port));
    }

    Ok(map)
}

fn direct_rule_for_host_or_ip(host_or_ip: &str) -> String {
    let trimmed = host_or_ip
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']');
    if let Ok(ip) = trimmed.parse::<Ipv4Addr>() {
        format!("IP-CIDR,{ip}/32,DIRECT,no-resolve")
    } else if let Ok(ip) = trimmed.parse::<Ipv6Addr>() {
        format!("IP-CIDR6,{ip}/128,DIRECT,no-resolve")
    } else {
        format!("DOMAIN,{trimmed},DIRECT")
    }
}

fn extract_url_host(raw_url: &str) -> Option<String> {
    Url::parse(raw_url.trim())
        .ok()
        .and_then(|u| u.host_str().map(|h| h.trim().to_string()))
        .filter(|h| !h.is_empty())
}

fn is_preaccel_group_name(name: &str, dialer_targets: &HashSet<String>) -> bool {
    if name == PREACCEL_FALLBACK_GROUP_NAME
        || name == PREACCEL_SELECT_GROUP_NAME
        || dialer_targets.contains(name)
    {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    lower.contains("preaccel") || name.contains("预加速")
}

fn detect_group_cycles(groups: &HashMap<String, Vec<String>>) -> Vec<Vec<String>> {
    let mut visited: HashSet<String> = HashSet::new();
    let mut in_stack: Vec<String> = Vec::new();
    let mut in_stack_set: HashSet<String> = HashSet::new();
    let mut cycles: Vec<Vec<String>> = Vec::new();

    fn dfs(
        node: &str,
        groups: &HashMap<String, Vec<String>>,
        visited: &mut HashSet<String>,
        in_stack: &mut Vec<String>,
        in_stack_set: &mut HashSet<String>,
        cycles: &mut Vec<Vec<String>>,
    ) {
        visited.insert(node.to_string());
        in_stack.push(node.to_string());
        in_stack_set.insert(node.to_string());

        if let Some(members) = groups.get(node) {
            for next in members {
                if !groups.contains_key(next) {
                    continue;
                }
                if in_stack_set.contains(next) {
                    if let Some(pos) = in_stack.iter().position(|n| n == next) {
                        let mut cycle = in_stack[pos..].to_vec();
                        cycle.push(next.clone());
                        cycles.push(cycle);
                    }
                } else if !visited.contains(next) {
                    dfs(next, groups, visited, in_stack, in_stack_set, cycles);
                }
            }
        }

        in_stack.pop();
        in_stack_set.remove(node);
    }

    let mut keys: Vec<&String> = groups.keys().collect();
    keys.sort();
    for key in keys {
        if !visited.contains(key) {
            dfs(
                key,
                groups,
                &mut visited,
                &mut in_stack,
                &mut in_stack_set,
                &mut cycles,
            );
        }
    }

    cycles
}

fn collect_transitive_proxies(
    start: &str,
    groups: &HashMap<String, Vec<String>>,
) -> HashSet<String> {
    let mut visited_groups: HashSet<String> = HashSet::new();
    let mut leaf_proxies: HashSet<String> = HashSet::new();
    let mut queue: Vec<String> = vec![start.to_string()];

    while let Some(curr) = queue.pop() {
        if let Some(members) = groups.get(&curr) {
            if visited_groups.insert(curr) {
                for m in members {
                    queue.push(m.clone());
                }
            }
        } else if curr != "DIRECT" && curr != "REJECT" {
            leaf_proxies.insert(curr);
        }
    }

    leaf_proxies
}

fn has_direct_anti_loop_rule(relay_server: &str, rules: &[String]) -> bool {
    let target = relay_server
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let target_ip = target.parse::<IpAddr>().ok();

    for rule in rules {
        let parts: Vec<&str> = rule.split(',').map(str::trim).collect();
        // Stop before a catch-all MATCH rule routes the relay into a proxy loop.
        // Note: `MATCH,<target>` has only 2 segments, so this check MUST precede `parts.len() < 3`.
        if parts.len() >= 2 && parts[0].eq_ignore_ascii_case("MATCH") {
            return false;
        }
        if parts.len() < 3 {
            continue;
        }
        let rule_type = parts[0].to_ascii_uppercase();
        let payload = parts[1].to_ascii_lowercase();
        let action = parts[2].to_ascii_uppercase();

        if action != "DIRECT" {
            continue;
        }

        match (target_ip, rule_type.as_str()) {
            (Some(IpAddr::V4(v4)), "IP-CIDR") => {
                if payload == format!("{v4}/32") || ipv4_in_cidr(v4, &payload) {
                    return true;
                }
            }
            (Some(IpAddr::V6(v6)), "IP-CIDR6") => {
                if payload == format!("{v6}/128") || ipv6_in_cidr(v6, &payload) {
                    return true;
                }
            }
            (None, "DOMAIN") => {
                if payload == target {
                    return true;
                }
            }
            (None, "DOMAIN-SUFFIX") => {
                if target == payload || target.ends_with(&format!(".{payload}")) {
                    return true;
                }
            }
            _ => {}
        }
    }

    false
}

fn ipv4_in_cidr(addr: Ipv4Addr, cidr: &str) -> bool {
    let Some((net_str, prefix_str)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(net) = net_str.parse::<Ipv4Addr>() else {
        return false;
    };
    let Ok(prefix) = prefix_str.parse::<u32>() else {
        return false;
    };
    if prefix > 32 {
        return false;
    }
    let mask = if prefix == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix)
    };
    (u32::from(addr) & mask) == (u32::from(net) & mask)
}

fn ipv6_in_cidr(addr: Ipv6Addr, cidr: &str) -> bool {
    let Some((net_str, prefix_str)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(net) = net_str.trim().parse::<Ipv6Addr>() else {
        return false;
    };
    let Ok(prefix) = prefix_str.trim().parse::<u32>() else {
        return false;
    };
    if prefix > 128 {
        return false;
    }
    let mask = if prefix == 0 {
        0u128
    } else {
        !0u128 << (128 - prefix)
    };
    (u128::from(addr) & mask) == (u128::from(net) & mask)
}

fn make_unique_name(base: &str, used: &mut HashSet<String>) -> String {
    if used.insert(base.to_string()) {
        return base.to_string();
    }
    let mut suffix = 2usize;
    loop {
        let candidate = format!("{base} ({suffix})");
        if used.insert(candidate.clone()) {
            return candidate;
        }
        suffix += 1;
    }
}

fn push_unique(list: &mut Vec<String>, item: String) {
    if !list.iter().any(|existing| existing == &item) {
        list.push(item);
    }
}

fn str_val(s: &str) -> Value {
    Value::String(s.to_string())
}

fn insert_str(map: &mut Mapping, key: &str, value: &str) {
    map.insert(str_val(key), str_val(value));
}

fn insert_bool(map: &mut Mapping, key: &str, value: bool) {
    map.insert(str_val(key), Value::Bool(value));
}

fn insert_u64(map: &mut Mapping, key: &str, value: u64) {
    map.insert(str_val(key), Value::Number(Number::from(value)));
}

fn string_seq<'a>(items: impl IntoIterator<Item = &'a str>) -> Value {
    Value::Sequence(items.into_iter().map(str_val).collect())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DnsMode, TunStackMode};

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
            last_probe_ms: None,
            last_mbps: None,
        }
    }

    #[test]
    fn compiles_all_four_multi_group_modes_with_active_first_and_reject_slot() {
        let cfg = AppConfig::default();
        let ports = sample_ports();
        let nodes = vec![
            sample_node("n1", "Node-JP-01", 8443, false),
            sample_node("n2", "Node-SG-02", 443, true),
            sample_node("n3", "Node-US-03", 9443, false),
        ];

        let g_sticky = MultiGroup {
            id: "g-sticky".to_string(),
            name: "AI-Sticky".to_string(),
            mode: MultiGroupMode::StickyBest,
            match_rules: vec!["@ai_domains".to_string()],
            member_node_ids: vec!["n1".into(), "n2".into(), "n3".into()],
            active_node_id: Some("n3".to_string()),
            fallback_policy: FallbackPolicy::StrictCircuitBreak,
            ..Default::default()
        };

        let g_cond = MultiGroup {
            id: "g-cond".to_string(),
            name: "Cond-Pool".to_string(),
            mode: MultiGroupMode::ConditionalPool,
            match_rules: vec!["DOMAIN-SUFFIX,example.com".to_string()],
            member_node_ids: Vec::new(),
            active_node_id: Some("n2".to_string()),
            fallback_policy: FallbackPolicy::DegradeBestWarn,
            ..Default::default()
        };

        let g_lb_ch = MultiGroup {
            id: "g-lb-ch".to_string(),
            name: "LB-Consistent".to_string(),
            mode: MultiGroupMode::LoadBalanceConsistentHash,
            member_node_ids: vec!["n1".into(), "n2".into()],
            ..Default::default()
        };

        let g_lb_rr = MultiGroup {
            id: "g-lb-rr".to_string(),
            name: "LB-RoundRobin".to_string(),
            mode: MultiGroupMode::LoadBalanceRoundRobin,
            member_node_ids: vec!["n1".into(), "n3".into()],
            ..Default::default()
        };

        let mut filtered = HashMap::new();
        filtered.insert("g-lb-ch".to_string(), vec!["n2".to_string()]);

        let groups = vec![g_sticky, g_cond, g_lb_ch, g_lb_rr];
        let input = CompileInput {
            config: &cfg,
            nodes: &nodes,
            groups: &groups,
            relays: &[],
            controller_secret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            allocated_ports: &ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &filtered,
        };

        let compiled = compile_mihomo_config(&input).expect("compile must succeed");
        assert!(compiled.validation.ok);

        let pg = compiled.value["proxy-groups"].as_sequence().unwrap();
        assert_eq!(pg.len(), 4);

        // 1. StickyBest: active_node_id (n3 -> Node-US-03) moved to index 0 + REJECT slot kept
        assert_eq!(pg[0]["name"], "AI-Sticky");
        assert_eq!(pg[0]["type"], "select");
        let sticky_members: Vec<&str> = pg[0]["proxies"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(sticky_members[0], "Node-US-03");
        assert!(sticky_members.contains(&"REJECT"));
        assert_eq!(
            compiled.active_selections.get("AI-Sticky").map(String::as_str),
            Some("Node-US-03")
        );

        // 2. ConditionalPool: active_node_id (n2 -> Node-SG-02) moved to index 0
        assert_eq!(pg[1]["name"], "Cond-Pool");
        assert_eq!(pg[1]["type"], "select");
        assert_eq!(pg[1]["proxies"][0], "Node-SG-02");

        // 3. LoadBalanceConsistentHash: respects hard-gate filtered members (only n2)
        assert_eq!(pg[2]["name"], "LB-Consistent");
        assert_eq!(pg[2]["type"], "load-balance");
        assert_eq!(pg[2]["strategy"], "consistent-hashing");
        assert_eq!(pg[2]["proxies"].as_sequence().unwrap().len(), 1);
        assert_eq!(pg[2]["proxies"][0], "Node-SG-02");

        // 4. LoadBalanceRoundRobin
        assert_eq!(pg[3]["name"], "LB-RoundRobin");
        assert_eq!(pg[3]["type"], "load-balance");
        assert_eq!(pg[3]["strategy"], "round-robin");

        // AI rules expanded from @ai_domains
        let rules: Vec<&str> = compiled.value["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(rules.iter().any(|r| *r == "DOMAIN-SUFFIX,openai.com,AI-Sticky"));
        assert!(rules.iter().any(|r| *r == "DOMAIN-SUFFIX,windsurf.com,AI-Sticky"));
        assert!(rules.iter().any(|r| *r == "DOMAIN-SUFFIX,example.com,Cond-Pool"));
    }

    #[test]
    fn compiles_full_dns_tun_and_domestic_preaccel_chain_with_anti_loop() {
        let mut cfg = AppConfig::default();
        cfg.core_ipv6 = true;
        cfg.dns.ipv6 = false;
        cfg.dns.mode = DnsMode::FakeIp;
        cfg.dns.prefer_h3 = true;
        cfg.dns.respect_rules = true;
        cfg.dns
            .hosts
            .insert("intra.example.test".to_string(), "127.0.0.1".to_string());
        cfg.dns
            .nameserver_policy
            .insert("+.cn".to_string(), vec!["223.5.5.5".to_string()]);
        cfg.tun.enabled = true;
        cfg.tun.stack_mode = TunStackMode::Gvisor;
        cfg.tun.strict_route = true;
        cfg.geodata.geodata_mode = true;
        cfg.preaccel.enabled = true;
        cfg.preaccel.skip_443_native = true;
        cfg.preaccel
            .campus_direct_domains
            .push("portal.campus.test".to_string());

        let ports = sample_ports();
        let nodes = vec![
            sample_node("n-non443", "Node-8443", 8443, false),
            sample_node("n-443", "Node-443-Native", 443, true),
        ];
        let relays = vec![
            sample_relay("r-primary", "Relay-Primary", "203.0.113.10", 10),
            sample_relay("r-backup", "Relay-Backup", "relay-b.example.test", 20),
        ];
        let extra_rules = vec!["IP-CIDR,203.0.113.99/32,DIRECT,no-resolve".to_string()];
        let extra_fake = vec!["captive.campus.test".to_string()];
        let empty_filtered = HashMap::new();

        let input = CompileInput {
            config: &cfg,
            nodes: &nodes,
            groups: &[],
            relays: &relays,
            controller_secret: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            allocated_ports: &ports,
            extra_prepend_rules: &extra_rules,
            extra_fake_ip_filters: &extra_fake,
            group_filtered_members: &empty_filtered,
        };

        let compiled = compile_mihomo_config(&input).expect("compile full config");
        assert!(compiled.validation.ok, "issues: {:?}", compiled.validation.issues);

        // Core vs DNS IPv6 independent controls + geodata-loader enforced
        assert_eq!(compiled.value["ipv6"], Value::Bool(true));
        assert_eq!(compiled.value["dns"]["ipv6"], Value::Bool(false));
        assert_eq!(compiled.value["geodata-mode"], Value::Bool(true));
        assert_eq!(compiled.value["geodata-loader"], "memconservative");
        assert_eq!(compiled.value["bind-address"], "127.0.0.1");
        assert_eq!(compiled.value["profile"]["store-selected"], Value::Bool(false));
        assert_eq!(compiled.value["profile"]["store-fake-ip"], Value::Bool(false));

        // 7-screenshot DNS fields
        let dns = &compiled.value["dns"];
        assert_eq!(dns["enable"], Value::Bool(true));
        assert_eq!(dns["listen"], "127.0.0.1:21053");
        assert_eq!(dns["use-hosts"], Value::Bool(true));
        assert_eq!(dns["use-system-hosts"], Value::Bool(true));
        assert_eq!(dns["respect-rules"], Value::Bool(true));
        assert_eq!(dns["prefer-h3"], Value::Bool(true));
        assert_eq!(dns["enhanced-mode"], "fake-ip");
        assert_eq!(dns["fake-ip-range"], "198.18.0.1/16");
        let fake_filters: Vec<&str> = dns["fake-ip-filter"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(fake_filters.contains(&"relay-b.example.test"));
        assert!(fake_filters.contains(&"portal.campus.test"));
        assert!(fake_filters.contains(&"captive.campus.test"));
        assert_eq!(dns["fallback-filter"]["geoip"], Value::Bool(true));
        assert_eq!(dns["fallback-filter"]["geoip-code"], "CN");

        // Full TUN fields
        let tun = &compiled.value["tun"];
        assert_eq!(tun["enable"], Value::Bool(true));
        assert_eq!(tun["stack"], "gvisor");
        assert_eq!(tun["strict-route"], Value::Bool(true));
        assert_eq!(tun["mtu"], 9000);

        // Pre-accel chain: pure-IP relay omits SNI; non-443 gets dialer-proxy; 443-native skipped
        let proxies = compiled.value["proxies"].as_sequence().unwrap();
        let relay_primary = proxies
            .iter()
            .find(|p| p["name"] == "Relay-Primary")
            .unwrap();
        assert!(relay_primary.get("sni").is_none());
        assert_eq!(relay_primary["skip-cert-verify"], Value::Bool(true));

        let node_8443 = proxies.iter().find(|p| p["name"] == "Node-8443").unwrap();
        assert_eq!(node_8443["dialer-proxy"], PREACCEL_SELECT_GROUP_NAME);

        let node_443 = proxies
            .iter()
            .find(|p| p["name"] == "Node-443-Native")
            .unwrap();
        assert!(node_443.get("dialer-proxy").is_none());

        assert_eq!(compiled.stats.dialer_wrapped_proxies, 1);
        assert_eq!(compiled.stats.skipped_443_native_proxies, 1);

        // Fallback group has lazy: false and domestic 204 URL
        let fallback_group = compiled.value["proxy-groups"]
            .as_sequence()
            .unwrap()
            .iter()
            .find(|g| g["name"] == PREACCEL_FALLBACK_GROUP_NAME)
            .unwrap();
        assert_eq!(fallback_group["lazy"], Value::Bool(false));
        assert!(fallback_group["url"].as_str().unwrap().contains("hicloud.com"));

        // Anti-loop DIRECT rules placed at top
        let rules: Vec<&str> = compiled.value["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(rules.contains(&"IP-CIDR,203.0.113.10/32,DIRECT,no-resolve"));
        assert!(rules.contains(&"DOMAIN,relay-b.example.test,DIRECT"));
        assert!(rules.contains(&"DOMAIN,connectivitycheck.platform.hicloud.com,DIRECT"));
    }

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
    fn load_balance_strict_circuit_break_handles_healthy_empty_and_circuit_open() {
        let cfg = AppConfig::default();
        let ports = sample_ports();
        let nodes = vec![
            sample_node("n1", "Node-JP-01", 443, true),
            sample_node("n2", "Node-SG-02", 443, true),
        ];

        // 1. Healthy load-balance group with StrictCircuitBreak must NOT include REJECT.
        let lb_healthy = MultiGroup {
            id: "g-lb-healthy".to_string(),
            name: "LB-Healthy".to_string(),
            mode: MultiGroupMode::LoadBalanceConsistentHash,
            member_node_ids: vec!["n1".into(), "n2".into()],
            fallback_policy: FallbackPolicy::StrictCircuitBreak,
            state: MultiGroupState::Healthy,
            ..Default::default()
        };

        // 2. Load-balance group with empty filtered members must emit ["REJECT"].
        let lb_empty = MultiGroup {
            id: "g-lb-empty".to_string(),
            name: "LB-Empty".to_string(),
            mode: MultiGroupMode::LoadBalanceRoundRobin,
            member_node_ids: vec!["n1".into(), "n2".into()],
            fallback_policy: FallbackPolicy::StrictCircuitBreak,
            state: MultiGroupState::Healthy,
            ..Default::default()
        };

        // 3. Load-balance group in CircuitOpen state must emit ["REJECT"] even if nodes exist.
        let lb_open = MultiGroup {
            id: "g-lb-open".to_string(),
            name: "LB-Open".to_string(),
            mode: MultiGroupMode::LoadBalanceConsistentHash,
            member_node_ids: vec!["n1".into(), "n2".into()],
            fallback_policy: FallbackPolicy::StrictCircuitBreak,
            state: MultiGroupState::CircuitOpen,
            ..Default::default()
        };

        let mut filtered = HashMap::new();
        filtered.insert("g-lb-empty".to_string(), Vec::new());

        let groups = vec![lb_healthy, lb_empty, lb_open];
        let input = CompileInput {
            config: &cfg,
            nodes: &nodes,
            groups: &groups,
            relays: &[],
            controller_secret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            allocated_ports: &ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &filtered,
        };

        let compiled = compile_mihomo_config(&input).expect("compile must succeed");
        assert!(compiled.validation.ok, "issues: {:?}", compiled.validation.issues);

        let pg = compiled.value["proxy-groups"].as_sequence().unwrap();
        let healthy_members: Vec<&str> = pg[0]["proxies"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(healthy_members, vec!["Node-JP-01", "Node-SG-02"]);
        assert!(!healthy_members.contains(&"REJECT"));

        let empty_members: Vec<&str> = pg[1]["proxies"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(empty_members, vec!["REJECT"]);

        let open_members: Vec<&str> = pg[2]["proxies"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(open_members, vec!["REJECT"]);
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
    fn compiles_geo_auto_update_false_and_honors_active_group_id_for_match() {
        let mut cfg = AppConfig::default();
        cfg.active_group_id = Some("grp-second".to_string());
        let node = sample_node("n1", "Node-JP", 443, true);
        let mut g1 = MultiGroup::default();
        g1.id = "grp-first".to_string();
        g1.name = "First-Group".to_string();
        g1.member_node_ids = vec![node.id.clone()];
        let mut g2 = MultiGroup::default();
        g2.id = "grp-second".to_string();
        g2.name = "Second-Group".to_string();
        g2.member_node_ids = vec![node.id.clone()];

        let ports = AllocatedPorts {
            bind_host: "127.0.0.1".to_string(),
            mixed_port: 27890,
            controller_port: 29090,
            dns_port: 21053,
            shifted: Vec::new(),
        };
        let empty = HashMap::new();
        let compiled = compile_mihomo_config(&CompileInput {
            config: &cfg,
            nodes: &[node],
            groups: &[g1, g2],
            relays: &[],
            controller_secret: "secret",
            allocated_ports: &ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &empty,
        })
        .expect("compile ok");

        assert_eq!(compiled.value["geo-auto-update"], Value::Bool(false));
        let rules = compiled.value["rules"].as_sequence().expect("rules seq");
        let last = rules.last().and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(last, "MATCH,Second-Group");
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
}
