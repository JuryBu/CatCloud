use crate::config::{is_forbidden_domestic_probe_host, validate_config};
use crate::core_adapter::format_host_port;
use crate::core_adapter::port_guard::AllocatedPorts;
use crate::error::{CatError, CatResult};
use crate::models::{
    AppConfig, DEFAULT_AI_ROUTING_DOMAINS, FallbackPolicy, MultiGroup, MultiGroupMode,
    MultiGroupState, OverrideMode, PreAccelRelay, ProxyMode, ProxyNode, RouteTargetMode,
};
use serde::{Deserialize, Serialize};
use serde_yaml_ng::{Mapping, Number, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use url::Url;

/// Canonical Mihomo selector group name for domestic pre-acceleration entry.
pub const PREACCEL_SELECT_GROUP_NAME: &str = "⚡ 国内预加速入口";

/// Canonical Mihomo fallback group name for active-standby domestic pre-acceleration relays.
pub const PREACCEL_FALLBACK_GROUP_NAME: &str = "🔄 预加速自动双活";

/// Default top-level proxy selector group generated when no custom multi-groups exist.
pub const DEFAULT_FALLBACK_GROUP_NAME: &str = "🐱 猫猫云梯";

/// Canonical Mihomo selector group name used in direct single-node routing mode.
pub const SINGLE_NODE_GROUP_NAME: &str = "单节点直选";

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
    /// Map of enabled `node.id` -> unique compiled proxy name (prevents cross-provider name collisions).
    pub node_id_to_proxy_name: HashMap<String, String>,
    pub stats: CompileStats,
    pub validation: StaticValidationReport,
    pub sha256: String,
}

/// Explicit Codex / OpenAI API / Statsig endpoints guaranteed to stay pinned to the same
/// AI routing group as `chatgpt.com` / `openai.com` so long-lived streams never split routes.
const EXPLICIT_AI_CODEX_ROUTING_DOMAINS: &[&str] = &[
    "ab.chatgpt.com",
    "ios.chat.openai.com",
    "api.openai.com",
];

/// Build default `DOMAIN-SUFFIX` routing rules for CatCloud's built-in AI service domains,
/// explicitly pinning Codex / OpenAI API endpoints (`ab.chatgpt.com`, `ios.chat.openai.com`,
/// `api.openai.com`) alongside `DEFAULT_AI_ROUTING_DOMAINS`.
pub fn build_default_ai_routing_rules(target_group: &str) -> Vec<String> {
    let target = target_group.trim();
    let mut rules: Vec<String> = Vec::with_capacity(
        EXPLICIT_AI_CODEX_ROUTING_DOMAINS.len() + DEFAULT_AI_ROUTING_DOMAINS.len(),
    );
    for domain in EXPLICIT_AI_CODEX_ROUTING_DOMAINS {
        push_unique(&mut rules, format!("DOMAIN-SUFFIX,{domain},{target}"));
    }
    for domain in DEFAULT_AI_ROUTING_DOMAINS {
        push_unique(&mut rules, format!("DOMAIN-SUFFIX,{domain},{target}"));
    }
    rules
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

fn has_balanced_parens(expr: &str) -> bool {
    let trimmed = expr.trim();
    if !trimmed.starts_with('(') || !trimmed.ends_with(')') {
        return false;
    }
    let mut depth: i32 = 0;
    for ch in trimmed.chars() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 0
}

fn is_logical_rule_type(rule_type: &str) -> bool {
    let upper = rule_type.trim().to_ascii_uppercase();
    matches!(upper.as_str(), "AND" | "OR" | "NOT")
}

fn is_plausible_global_rule(rule: &str) -> bool {
    let trimmed = rule.trim();
    if trimmed.is_empty() {
        return false;
    }
    let Some((raw_type, rest)) = trimmed.split_once(',') else {
        return false;
    };
    let rule_type = raw_type.trim();
    if !is_valid_mihomo_rule_type(rule_type) {
        return false;
    }
    if rule_type.eq_ignore_ascii_case("MATCH") {
        let target = rest.trim();
        return !target.is_empty() && !target.contains(',');
    }
    if is_logical_rule_type(rule_type) {
        // Logical composite rules look like: `AND,((NETWORK,UDP),(DST-PORT,443)),REJECT`
        let Some((expr, action)) = rest.rsplit_once(',') else {
            return false;
        };
        let action = action.trim();
        return !action.is_empty()
            && !action.contains('(')
            && !action.contains(')')
            && has_balanced_parens(expr);
    }
    let parts: Vec<&str> = trimmed.split(',').map(str::trim).collect();
    parts.len() >= 3 && parts.iter().all(|p| !p.is_empty())
}

fn is_builtin_rule_action(target: &str) -> bool {
    let upper = target.trim().to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "DIRECT" | "REJECT" | "REJECT-DROP" | "PASS" | "COMPATIBLE"
    )
}

fn is_mihomo_rule_flag(token: &str) -> bool {
    token.eq_ignore_ascii_case("no-resolve") || token.eq_ignore_ascii_case("src")
}

/// Extract the raw proxy or proxy-group target from a Mihomo rule line (including built-in
/// actions such as `DIRECT`/`REJECT`). Returns `None` for blank lines, `#` comments,
/// `SUB-RULE` entries, or malformed rules without a target segment.
fn extract_mihomo_rule_raw_target(rule: &str) -> Option<&str> {
    let trimmed = rule.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let (raw_type, rest) = trimmed.split_once(',')?;
    let rule_type = raw_type.trim();
    if rule_type.is_empty() || rule_type.eq_ignore_ascii_case("SUB-RULE") {
        return None;
    }
    if rule_type.eq_ignore_ascii_case("MATCH") {
        let target = rest.trim();
        if target.is_empty() || target.contains(',') {
            return None;
        }
        return Some(target);
    }
    if is_logical_rule_type(rule_type) {
        let mut remainder = rest.trim();
        while let Some((head, tail)) = remainder.rsplit_once(',') {
            let candidate = tail.trim();
            if candidate.is_empty() {
                return None;
            }
            if is_mihomo_rule_flag(candidate) {
                remainder = head.trim();
                continue;
            }
            if !candidate.contains('(')
                && !candidate.contains(')')
                && has_balanced_parens(head)
            {
                return Some(candidate);
            }
            return None;
        }
        return None;
    }

    let mut parts: Vec<&str> = trimmed.split(',').map(str::trim).collect();
    if parts.len() < 3 || parts[1].is_empty() {
        return None;
    }
    while parts.len() > 2 && parts.last().is_some_and(|tok| is_mihomo_rule_flag(tok)) {
        parts.pop();
    }
    if parts.len() < 3 {
        return None;
    }
    let target = *parts.last()?;
    if target.is_empty() {
        return None;
    }
    Some(target)
}

/// Extract a non-builtin proxy or proxy-group target name from a Mihomo rule line, ignoring
/// built-in actions (`DIRECT`, `REJECT`, `REJECT-DROP`, `PASS`, `COMPATIBLE`, case-insensitive).
fn extract_mihomo_rule_target(rule: &str) -> Option<&str> {
    extract_mihomo_rule_raw_target(rule).filter(|target| !is_builtin_rule_action(target))
}

/// Expand a multi-group match rule into one or more Mihomo rule strings.
///
/// - `@ai_domains` or `PRESET:AI` expands into `DEFAULT_AI_ROUTING_DOMAINS` bound to `group_name`.
/// - Single-segment bare Mihomo rule type names (e.g. `"DOMAIN-SUFFIX"`) or malformed strings
///   are safely ignored (empty `Vec`) instead of breaking `mihomo -t`.
/// - Single-segment valid domains (e.g. `"anthropic.com"`) auto-expand to `DOMAIN-SUFFIX,<domain>,<group>`.
/// - Logical composite rules (`AND`/`OR`/`NOT`) with balanced parentheses are preserved or bound to `group_name`.
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

    if let Some((raw_type, rest)) = trimmed.split_once(',') {
        if is_logical_rule_type(raw_type) {
            let rt = raw_type.trim().to_ascii_uppercase();
            let rest_trimmed = rest.trim();
            if has_balanced_parens(rest_trimmed) {
                return vec![format!("{rt},{rest_trimmed},{target}")];
            }
            if let Some((expr, action)) = rest_trimmed.rsplit_once(',') {
                let action = action.trim();
                if !action.is_empty()
                    && !action.contains('(')
                    && !action.contains(')')
                    && has_balanced_parens(expr)
                {
                    return vec![format!("{rt},{},{action}", expr.trim())];
                }
            }
            return Vec::new();
        }
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
/// nodes, multi-groups, and domestic pre-acceleration relays (without inspecting a runtime
/// directory for GeoData files; safe for offline/unit-test compilation).
pub fn compile_mihomo_config(input: &CompileInput<'_>) -> CatResult<CompiledCoreConfig> {
    compile_mihomo_config_with_runtime_dir(input, None)
}

/// Compile a full Mihomo YAML configuration while optionally inspecting `runtime_dir` for
/// locally installed `geosite.dat` / `geoip.dat` / `Country.mmdb` databases
/// so GeoSite/GeoIP rules and filters are only emitted when their backing files actually exist on disk.
pub fn compile_mihomo_config_with_runtime_dir(
    input: &CompileInput<'_>,
    runtime_dir: Option<&Path>,
) -> CatResult<CompiledCoreConfig> {
    let cfg = input.config;
    validate_config(cfg)?;

    let secret = input.controller_secret.trim();
    if secret.is_empty() {
        return Err(CatError::Validation(
            "controller_secret cannot be empty when compiling Mihomo config".into(),
        ));
    }

    let (has_geosite, has_geoip) = match runtime_dir {
        Some(dir) => {
            let geosite =
                dir.join("geosite.dat").is_file() || dir.join("GeoSite.dat").is_file();
            let geoip = if cfg.geodata.geodata_mode {
                dir.join("geoip.dat").is_file() || dir.join("GeoIP.dat").is_file()
            } else {
                dir.join("Country.mmdb").is_file() || dir.join("country.mmdb").is_file()
            };
            (geosite, geoip)
        }
        None => (false, false),
    };

    // 1. Collect enabled domestic pre-acceleration relays sorted by (priority ASC, id ASC).
    let mut enabled_relays: Vec<&PreAccelRelay> =
        input.relays.iter().filter(|r| r.enabled).collect();
    enabled_relays.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));
    let preaccel_active = cfg.preaccel.enabled && !enabled_relays.is_empty();

    // Determine which enabled business nodes (and optional active group subset) need compilation.
    let (compiled_nodes, allowed_group_ids) = select_nodes_and_groups_for_compile(input);

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
    insert_u64(&mut root, "keep-alive-idle", 15);
    insert_u64(&mut root, "keep-alive-interval", 15);
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
    // Unconditionally enforce memconservative streaming loader so geosite.dat never expands
    // fully onto the Go heap (even when geodata-mode is false and only geosite rules are loaded).
    insert_str(&mut root, "geodata-loader", "memconservative");

    let mut geox_url = Mapping::new();
    if !cfg.geodata.geoip_url.trim().is_empty() {
        insert_str(&mut geox_url, "geoip", cfg.geodata.geoip_url.trim());
    }
    if !cfg.geodata.geosite_url.trim().is_empty() {
        insert_str(&mut geox_url, "geosite", cfg.geodata.geosite_url.trim());
    }
    if !cfg.geodata.mmdb_url.trim().is_empty() {
        insert_str(&mut geox_url, "mmdb", cfg.geodata.mmdb_url.trim());
    }
    if !cfg.geodata.asn_url.trim().is_empty() {
        insert_str(&mut geox_url, "asn", cfg.geodata.asn_url.trim());
    }
    if !geox_url.is_empty() {
        root.insert(str_val("geox-url"), Value::Mapping(geox_url));
    }

    root.insert(
        str_val("sniffer"),
        Value::Mapping(build_sniffer_section(
            cfg.rules_override.block_quic_udp_443,
            cfg.rules_override.domestic_direct_enabled,
            has_geoip,
        )),
    );

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
            if is_plausible_global_rule(entry) {
                push_unique(&mut anti_loop_rules, entry.to_string());
            }
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

    // Add compiled business proxy node domain servers to fake-ip-filter to prevent TUN
    // Fake-IP resolution loops. Do NOT force DIRECT rules on business nodes (otherwise nodes
    // wrapped with domestic :443 relays would bypass pre-acceleration).
    for &node in &compiled_nodes {
        let server_candidate = {
            let s = node.server.trim();
            if !s.is_empty() {
                Some(s)
            } else {
                node.raw_config
                    .get("server")
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
            }
        };
        if let Some(raw_server) = server_candidate {
            let clean = raw_server.trim_start_matches('[').trim_end_matches(']');
            if !clean.is_empty() && clean.parse::<IpAddr>().is_err() {
                push_unique(&mut anti_loop_fake_ip_domains, clean.to_string());
            }
        }
    }

    // 4. Full 7-screenshot DNS section with anti-leak nameserver-policy & disk-aware GeoData gating.
    let dns_map = build_dns_section(
        cfg,
        input.allocated_ports,
        &anti_loop_fake_ip_domains,
        input.extra_fake_ip_filters,
        has_geosite,
        has_geoip,
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
            let relay_yaml = build_relay_proxy_mapping(relay, &unique_name)?;
            compiled_proxies.push(Value::Mapping(relay_yaml));
            relay_id_to_name.insert(relay.id.clone(), unique_name.clone());
            relay_names_ordered.push(unique_name);
        }
    }

    let mut node_id_to_name: HashMap<String, String> = HashMap::new();
    let mut all_enabled_node_names: Vec<String> = Vec::new();
    let mut dialer_wrapped_proxies = 0usize;
    let mut skipped_443_native_proxies = 0usize;

    for &node in &compiled_nodes {
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

    // 7. Compile proxy-groups: pre-acceleration chain + all 4 MultiGroupMode variants.
    let mut proxy_groups: Vec<Value> = Vec::new();
    let mut group_mappings: Vec<CompiledGroupMapping> = Vec::new();
    let mut active_selections: BTreeMap<String, String> = BTreeMap::new();

    if preaccel_active {
        let active_relay_name = cfg
            .preaccel
            .active_relay_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|id| relay_id_to_name.get(id))
            .cloned();

        // Always promote the user-selected relay to index 0 of `relay_names_ordered` so it becomes
        // the true primary relay even when `auto_failover == true`.
        if let Some(ref chosen) = active_relay_name {
            if let Some(pos) = relay_names_ordered.iter().position(|n| n == chosen) {
                let item = relay_names_ordered.remove(pos);
                relay_names_ordered.insert(0, item);
            }
        }

        // Fallback group: active-standby domestic 204 health check with lazy: false.
        // Append `DIRECT` at the end so all dialer-wrapped nodes fail open to direct dialing
        // instead of blackholing if every domestic relay fails simultaneously.
        let mut fallback_members = relay_names_ordered.clone();
        push_unique(&mut fallback_members, "DIRECT".to_string());

        let mut fallback_group = Mapping::new();
        insert_str(&mut fallback_group, "name", PREACCEL_FALLBACK_GROUP_NAME);
        insert_str(&mut fallback_group, "type", "fallback");
        fallback_group.insert(
            str_val("proxies"),
            string_seq(fallback_members.iter().map(String::as_str)),
        );
        insert_str(&mut fallback_group, "url", cfg.preaccel.probe_url.trim());
        insert_u64(&mut fallback_group, "interval", cfg.preaccel.probe_interval_sec);
        insert_bool(&mut fallback_group, "lazy", false);

        // Select group: entry point referenced by dialer-proxy.
        let mut select_members: Vec<String> = Vec::new();
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
    let mut effective_active_group_id: Option<String> = None;
    let preferred_active_group_id = cfg
        .active_group_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    for group in input.groups {
        if let Some(ref allowed_groups) = allowed_group_ids {
            if !allowed_groups.contains(group.id.trim()) {
                continue;
            }
        }
        let group_name = if group.name.trim().is_empty() {
            group.id.trim().to_string()
        } else {
            group.name.trim().to_string()
        };
        if group_name.is_empty() {
            continue;
        }
        if preferred_active_group_id == Some(group.id.trim()) {
            default_match_target = Some(group_name.clone());
            effective_active_group_id = Some(group.id.trim().to_string());
        } else if default_match_target.is_none() {
            default_match_target = Some(group_name.clone());
            effective_active_group_id = Some(group.id.trim().to_string());
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
        // Only accept a candidate that actually belongs to `members` (except explicit
        // `CircuitOpen` -> `REJECT`, which is already guaranteed present when `has_reject_slot`).
        // Never re-inject a removed/ghost `active_node_id` back into `members`.
        let resolved_active: Option<String> = if group.state == MultiGroupState::CircuitOpen
            && has_reject_slot
        {
            Some("REJECT".to_string())
        } else if let Some(ref active_id) = group.active_node_id {
            let candidate = if active_id == "REJECT" && has_reject_slot {
                Some("REJECT".to_string())
            } else if active_id == "DIRECT" {
                Some("DIRECT".to_string())
            } else {
                node_id_to_name.get(active_id).cloned()
            };
            candidate.filter(|name| members.iter().any(|m| m == name))
        } else {
            None
        };

        let mut group_map = Mapping::new();
        insert_str(&mut group_map, "name", &group_name);

        let (mihomo_type, final_active) = match group.mode {
            MultiGroupMode::StickyBest | MultiGroupMode::ConditionalPool => {
                // Move valid active_node_id to index 0 so `store-selected: false` never resets it
                // on reload. Ghost nodes absent from `members` are discarded above so `members[0]`
                // becomes the active selection cleanly.
                if let Some(ref active_name) = resolved_active {
                    if let Some(pos) = members.iter().position(|m| m == active_name) {
                        let chosen = members.remove(pos);
                        members.insert(0, chosen);
                    } else if group.state == MultiGroupState::CircuitOpen
                        && active_name == "REJECT"
                    {
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

    let resolved_single_proxy_name: Option<String> = if cfg.route_mode == RouteTargetMode::Single {
        cfg.active_single_node_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|nid| node_id_to_name.get(nid))
            .cloned()
    } else {
        None
    };

    // Compile direct single-node selector when active, otherwise fall back to multi-group / default.
    let single_mode_active = resolved_single_proxy_name.is_some();
    let match_target = if let Some(single_proxy_name) = resolved_single_proxy_name {
        let mut single_members: Vec<String> =
            Vec::with_capacity(all_enabled_node_names.len().max(1));
        single_members.push(single_proxy_name.clone());
        for name in &all_enabled_node_names {
            push_unique(&mut single_members, name.clone());
        }
        active_selections.insert(
            SINGLE_NODE_GROUP_NAME.to_string(),
            single_proxy_name.clone(),
        );
        let mut single_group = Mapping::new();
        insert_str(&mut single_group, "name", SINGLE_NODE_GROUP_NAME);
        insert_str(&mut single_group, "type", "select");
        single_group.insert(
            str_val("proxies"),
            string_seq(single_members.iter().map(String::as_str)),
        );
        proxy_groups.push(Value::Mapping(single_group));
        SINGLE_NODE_GROUP_NAME.to_string()
    } else {
        match default_match_target {
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
        }
    };

    // Strip dangling/invalid/self-referencing `dialer-proxy` entries inherited from raw
    // subscriptions unless their target exists in the compiled proxies or proxy-groups.
    let mut valid_dialer_targets: HashSet<String> = used_proxy_names.clone();
    for group_val in &proxy_groups {
        if let Some(name) = group_val
            .as_mapping()
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
        {
            let trimmed = name.trim();
            if !trimmed.is_empty() {
                valid_dialer_targets.insert(trimmed.to_string());
            }
        }
    }
    for proxy_val in &mut compiled_proxies {
        if let Some(map) = proxy_val.as_mapping_mut() {
            if !map.contains_key("dialer-proxy") {
                continue;
            }
            let self_name = map
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .map(ToString::to_string);
            let keep = map
                .get("dialer-proxy")
                .and_then(Value::as_str)
                .map(str::trim)
                .is_some_and(|target| {
                    !target.is_empty()
                        && self_name.as_deref() != Some(target)
                        && valid_dialer_targets.contains(target)
                });
            if !keep {
                map.shift_remove("dialer-proxy");
            }
        }
    }

    root.insert(str_val("proxies"), Value::Sequence(compiled_proxies));
    root.insert(str_val("proxy-groups"), Value::Sequence(proxy_groups));

    // 8. Compile ordered rules chain:
    //    (1) anti-loop -> (2) isolated probe core PROCESS-NAME bypass ->
    //    (3) private LAN/loopback direct -> (4) domestic public DNS IP direct ->
    //    (5) extra_prepend_rules + global_prepend_rules -> (6) QUIC UDP/443 reject ->
    //    (7) group match_rules (skipped in single mode) ->
    //    (8) global_append_rules -> (9) domestic direct rules -> (10) MATCH
    let mut rules: Vec<String> = Vec::new();
    for r in anti_loop_rules {
        push_unique(&mut rules, r);
    }
    push_unique(
        &mut rules,
        format!(
            "PROCESS-NAME,{},DIRECT",
            crate::probe::isolated_runner::PROBE_CORE_PROCESS_NAME
        ),
    );

    const PRIVATE_LAN_DIRECT_RULES: &[&str] = &[
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
        "IP-CIDR,224.0.0.0/4,DIRECT,no-resolve",
        "IP-CIDR,255.255.255.255/32,DIRECT,no-resolve",
        "IP-CIDR6,::1/128,DIRECT,no-resolve",
        "IP-CIDR6,fc00::/7,DIRECT,no-resolve",
        "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
    ];
    for r in PRIVATE_LAN_DIRECT_RULES {
        push_unique(&mut rules, (*r).to_string());
    }
    const PRIVATE_LOCAL_DOMAIN_DIRECT_RULES: &[&str] = &[
        "DOMAIN-SUFFIX,local,DIRECT",
        "DOMAIN-SUFFIX,localhost,DIRECT",
        "DOMAIN-SUFFIX,localdomain,DIRECT",
        "DOMAIN-SUFFIX,home.arpa,DIRECT",
        "DOMAIN-SUFFIX,lan,DIRECT",
        "DOMAIN-SUFFIX,internal,DIRECT",
    ];
    for r in PRIVATE_LOCAL_DOMAIN_DIRECT_RULES {
        push_unique(&mut rules, (*r).to_string());
    }
    if has_geosite {
        push_unique(&mut rules, "GEOSITE,private,DIRECT".to_string());
    }

    const DOMESTIC_PUBLIC_DNS_DIRECT_RULES: &[&str] = &[
        "IP-CIDR,223.5.5.5/32,DIRECT,no-resolve",
        "IP-CIDR,223.6.6.6/32,DIRECT,no-resolve",
        "IP-CIDR,1.12.12.12/32,DIRECT,no-resolve",
        "IP-CIDR,119.29.29.29/32,DIRECT,no-resolve",
        "IP-CIDR,119.28.28.28/32,DIRECT,no-resolve",
        "IP-CIDR,120.53.53.53/32,DIRECT,no-resolve",
        "IP-CIDR,114.114.114.114/32,DIRECT,no-resolve",
        "IP-CIDR,114.114.115.115/32,DIRECT,no-resolve",
        "IP-CIDR,180.76.76.76/32,DIRECT,no-resolve",
        "IP-CIDR,180.184.1.1/32,DIRECT,no-resolve",
        "IP-CIDR,180.184.2.2/32,DIRECT,no-resolve",
        "IP-CIDR,1.2.4.8/32,DIRECT,no-resolve",
        "IP-CIDR,210.2.4.8/32,DIRECT,no-resolve",
        "DOMAIN,dns.alidns.com,DIRECT",
        "DOMAIN,doh.pub,DIRECT",
        "DOMAIN,dot.pub,DIRECT",
        "DOMAIN,dns.pub,DIRECT",
    ];
    for r in DOMESTIC_PUBLIC_DNS_DIRECT_RULES {
        push_unique(&mut rules, (*r).to_string());
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

    const DOMESTIC_QUIC_DIRECT_DOMAINS: &[&str] = &[
        "cn",
        "qq.com",
        "qpic.cn",
        "qlogo.cn",
        "gtimg.cn",
        "gtimg.com",
        "weixin.qq.com",
        "tencent.com",
        "bilibili.com",
        "bilivideo.com",
        "bilivideo.cn",
    ];
    if cfg.rules_override.block_quic_udp_443 {
        if cfg.rules_override.domestic_direct_enabled {
            for domain in DOMESTIC_QUIC_DIRECT_DOMAINS {
                push_unique(
                    &mut rules,
                    format!(
                        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,{domain})),DIRECT"
                    ),
                );
            }
            if has_geosite {
                push_unique(
                    &mut rules,
                    "AND,((NETWORK,UDP),(DST-PORT,443),(GEOSITE,cn)),DIRECT".to_string(),
                );
            }
            if has_geoip {
                push_unique(
                    &mut rules,
                    "AND,((NETWORK,UDP),(DST-PORT,443),(GEOIP,CN,no-resolve)),DIRECT".to_string(),
                );
            }
        }
        push_unique(
            &mut rules,
            "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT".to_string(),
        );
    }
    if !single_mode_active {
        let active_group_id_ref = effective_active_group_id.as_deref();
        // Emit the active home group's match_rules FIRST for highest priority, followed ONLY by
        // other groups with `independent_routing == true`. Unselected groups with
        // `independent_routing == false` still keep their compiled `proxy-group` for instant
        // switching, but never inject match_rules that could silently hijack traffic.
        let active_first = input
            .groups
            .iter()
            .filter(|g| active_group_id_ref == Some(g.id.trim()));
        let independent_others = input
            .groups
            .iter()
            .filter(|g| active_group_id_ref != Some(g.id.trim()) && g.independent_routing);

        for group in active_first.chain(independent_others) {
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
    }
    for r in &cfg.rules_override.global_append_rules {
        let trimmed = r.trim();
        if is_plausible_global_rule(trimmed) {
            push_unique(&mut rules, trimmed.to_string());
        }
    }

    // Group A: Always-emitted strictly domestic / system download CDN & NTP whitelist
    // (placed before `GEOSITE,cn,DIRECT` even when `geosite.dat` is present).
    // Conservative red line: never include broad overseas/hybrid root domains such as
    // `microsoft.com`, `apple.com`, `steampowered.com`, `steamcommunity.com`, `github.com`, etc.
    const ALWAYS_DOMESTIC_AND_SYSTEM_CDN_DOMAINS: &[&str] = &[
        // Microsoft connectivity checks, Windows push notifications & Windows Update download CDNs
        "msftconnecttest.com",
        "msftncsi.com",
        "wns.windows.com",
        "notify.windows.com",
        "time.windows.com",
        "windowsupdate.com",
        "update.microsoft.com",
        "dl.delivery.mp.microsoft.com",
        "tlu.dl.delivery.mp.microsoft.com",
        // Apple China downloads, push notifications & NTP
        "icloud.com.cn",
        "push.apple.com",
        "time.apple.com",
        "swcdn.apple.com",
        "appldnld.apple.com",
        "mesu.apple.com",
        "updates-http.cdn-apple.com",
        "osxapps.itunes.apple.com",
        // Steam pure download CDNs (excluding store/community)
        "steamcontent.com",
        "steamserver.net",
        "dl.steam.clngaa.com",
        "dl.steam.ksyna.com",
        "st.dl.eccdnx.com",
        "st.dl.pinyuncloud.com",
        "st.dl.bscstorage.net",
        "xz.pphimalayanrt.com",
        // Domestic NTP
        "ntp.aliyun.com",
        "ntp.tencent.com",
        "cn.pool.ntp.org",
    ];

    // Group B: Expanded fallback whitelist for strictly domestic sites and core CDNs
    // used when `geosite.dat` is absent.
    const FALLBACK_DOMESTIC_DIRECT_DOMAINS: &[&str] = &[
        // Core domestic portals & Tencent / QQ / WeChat
        "qq.com",
        "weixin.qq.com",
        "gtimg.com",
        "qpic.cn",
        "qlogo.cn",
        "wechat.com",
        "wechatpay.com",
        "tenpay.com",
        "tencent.com",
        "myqcloud.com",
        "qcloud.com",
        // Taobao / Aliyun / Alipay / DingTalk / Amap (excluding international alibaba.com)
        "taobao.com",
        "tmall.com",
        "alicdn.com",
        "aliyuncs.com",
        "aliyun.com",
        "alipay.com",
        "alipayobjects.com",
        "dingtalk.com",
        "amap.com",
        "autonavi.com",
        // ByteDance / Douyin / Feishu (strictly domestic; never tiktok.com / larksuite.com)
        "douyin.com",
        "bytedance.com",
        "byteimg.com",
        "pstatp.com",
        "snssdk.com",
        "toutiao.com",
        "iesdouyin.com",
        "douyinvod.com",
        "volces.com",
        "volcengine.com",
        "feishu.cn",
        // Bilibili & video CDNs
        "bilibili.com",
        "bilivideo.com",
        "bilivideo.cn",
        "hdslb.com",
        "biliapi.com",
        "biliapi.net",
        "b23.tv",
        // NetEase / Youdao
        "163.com",
        "126.net",
        "126.com",
        "netease.com",
        "ydstatic.com",
        "youdao.com",
        // Baidu & Baidu Netdisk
        "baidu.com",
        "bdimg.com",
        "bdstatic.com",
        "bcebos.com",
        "baidupcs.com",
        // JD / Zhihu / Xiaohongshu / Weibo / Douban
        "jd.com",
        "360buyimg.com",
        "zhihu.com",
        "zhimg.com",
        "xiaohongshu.com",
        "xhscdn.com",
        "weibo.com",
        "sinaimg.cn",
        "douban.com",
        "doubanio.com",
        // Local services & e-commerce
        "meituan.com",
        "meituan.net",
        "dianping.com",
        "pinduoduo.com",
        // Domestic video / livestreaming
        "iqiyi.com",
        "youku.com",
        "mgtv.com",
        "huya.com",
        "douyu.com",
        "kuaishou.com",
        // Cloud drives & domestic developer mirrors (excluding international wps.com)
        "aliyundrive.com",
        "alipan.com",
        "quark.cn",
        "csdn.net",
        "gitee.com",
        "juejin.cn",
        "npmmirror.com",
        // OEMs, logistics & education
        "mi.com",
        "xiaomi.com",
        "miui.com",
        "huawei.com",
        "hicloud.com",
        "vmall.com",
        "sf-express.com",
        "cainiao.com",
        "edu.cn",
    ];
    if cfg.rules_override.domestic_direct_enabled {
        push_unique(&mut rules, "DOMAIN-SUFFIX,cn,DIRECT".to_string());
        for domain in ALWAYS_DOMESTIC_AND_SYSTEM_CDN_DOMAINS {
            push_unique(&mut rules, format!("DOMAIN-SUFFIX,{domain},DIRECT"));
        }
        if has_geosite {
            push_unique(&mut rules, "GEOSITE,cn,DIRECT".to_string());
        } else {
            for domain in FALLBACK_DOMESTIC_DIRECT_DOMAINS {
                push_unique(&mut rules, format!("DOMAIN-SUFFIX,{domain},DIRECT"));
            }
        }
        if has_geoip {
            push_unique(&mut rules, "GEOIP,CN,DIRECT,no-resolve".to_string());
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
        node_id_to_proxy_name: node_id_to_name,
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
/// - Rules referencing unknown proxies or proxy-groups outside built-in actions
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

    // Map proxy name -> server for discovering relay servers referenced via dialer-proxy,
    // and collect every valid proxy/proxy-group target name referenced by `rules`.
    let mut valid_rule_targets: HashSet<String> = HashSet::new();
    let mut proxy_server_map: HashMap<String, String> = HashMap::new();
    let mut dialer_targets: HashSet<String> = HashSet::new();
    if let Some(proxies) = root.get("proxies").and_then(Value::as_sequence) {
        for item in proxies {
            if let Some(map) = item.as_mapping() {
                if let Some(name) = map.get("name").and_then(Value::as_str) {
                    let trimmed_name = name.trim();
                    if !trimmed_name.is_empty() {
                        valid_rule_targets.insert(trimmed_name.to_string());
                    }
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
            let raw_group_name = map
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty());
            if let Some(name) = raw_group_name {
                valid_rule_targets.insert(name.to_string());
            }
            let group_name = raw_group_name.unwrap_or("<unnamed>").to_string();

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

    // Verify every rule target resolves to a built-in action or an existing proxy / proxy-group.
    for rule in &rules {
        if let Some(target) = extract_mihomo_rule_target(rule) {
            if !valid_rule_targets.contains(target) {
                issues.push(StaticCheckIssue {
                    code: "unknown_rule_target".to_string(),
                    severity: StaticCheckSeverity::Error,
                    message: format!(
                        "rule `{rule}` references unknown proxy or proxy-group `{target}`"
                    ),
                });
            }
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

/// Select enabled business nodes (and optional active group-ID subset) for compilation.
///
/// When `!compile_all_nodes`, `proxy_mode != ProxyMode::Global`, and `input.nodes.len() > 32`,
/// trims compiled proxies and `fake-ip-filter` entries down to nodes referenced by:
/// - `RouteTargetMode::Single`: `active_single_node_id` (if enabled), plus any user multi-groups
///   (and their transitive `fallback_pool_id` / members) or nodes referenced by global/extra rules;
/// - `RouteTargetMode::Group` (or Single fallback): the active home group, every
///   `independent_routing == true` group, any user multi-groups/nodes referenced by global/extra
///   rules or emitted group `match_rules`, and any transitive `fallback_pool_id` backup groups,
///   plus any chained `dialer-proxy` node references.
///
/// Safety fallback: if the active referenced set is empty (or an active `ConditionalPool`
/// consumes all enabled nodes dynamically), all enabled nodes and groups are preserved.
fn select_nodes_and_groups_for_compile<'a>(
    input: &CompileInput<'a>,
) -> (Vec<&'a ProxyNode>, Option<HashSet<String>>) {
    let cfg = input.config;
    let enabled_nodes: Vec<&'a ProxyNode> = input.nodes.iter().filter(|n| n.enabled).collect();
    let should_prune = !cfg.core_runtime.compile_all_nodes
        && cfg.proxy_mode != ProxyMode::Global
        && input.nodes.len() > 32;
    if !should_prune || enabled_nodes.is_empty() {
        return (enabled_nodes, None);
    }

    let enabled_node_ids: HashSet<&'a str> = enabled_nodes.iter().map(|n| n.id.as_str()).collect();
    let mut enabled_nodes_by_name: HashMap<&'a str, Vec<&'a str>> = HashMap::new();
    for &node in &enabled_nodes {
        let trimmed = node.name.trim();
        if !trimmed.is_empty() {
            enabled_nodes_by_name
                .entry(trimmed)
                .or_default()
                .push(node.id.as_str());
        }
    }

    let mut active_node_ids: HashSet<&'a str> = HashSet::new();

    // Index all valid user multi-groups by ID and compiled name, and resolve effective active group.
    let preferred_active_group_id = cfg
        .active_group_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let mut effective_active_group_id: Option<&'a str> = None;
    let mut group_by_id: HashMap<&'a str, &'a MultiGroup> = HashMap::new();
    let mut group_ids_by_name: HashMap<&'a str, Vec<&'a str>> = HashMap::new();
    for group in input.groups {
        let g_id = group.id.trim();
        let g_name = if group.name.trim().is_empty() {
            g_id
        } else {
            group.name.trim()
        };
        if g_name.is_empty() {
            continue;
        }
        group_by_id.insert(g_id, group);
        group_ids_by_name.entry(g_name).or_default().push(g_id);
        if preferred_active_group_id == Some(g_id) {
            effective_active_group_id = Some(g_id);
        } else if effective_active_group_id.is_none() {
            effective_active_group_id = Some(g_id);
        }
    }

    // 1. Determine whether direct single-node mode has a valid enabled single node selected.
    let single_mode_node_id: Option<&'a str> = if cfg.route_mode == RouteTargetMode::Single {
        cfg.active_single_node_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|single_id| enabled_node_ids.get(single_id).copied())
    } else {
        None
    };

    let mut active_group_ids: HashSet<String> = HashSet::new();
    let mut queue: Vec<&'a str> = Vec::new();

    if let Some(single_id) = single_mode_node_id {
        // Direct single-node mode: always keep the selected single node; unrelated groups are
        // pruned unless referenced by global/extra rules below.
        active_node_ids.insert(single_id);
    } else {
        // Group mode (or Single fallback when active_single_node_id is absent/disabled).
        if let Some(active_gid) = effective_active_group_id {
            queue.push(active_gid);
        }
        for group in input.groups {
            if group.independent_routing {
                let g_id = group.id.trim();
                if !g_id.is_empty() {
                    queue.push(g_id);
                }
            }
        }
    }

    // 2. Regardless of Single or Group mode, scan global/extra rules so AI preset and custom
    //    routing rules targeting any user multi-group (or proxy node) never become dangling.
    let global_rule_iter = input
        .extra_prepend_rules
        .iter()
        .chain(cfg.rules_override.global_prepend_rules.iter())
        .chain(cfg.rules_override.global_append_rules.iter())
        .chain(
            cfg.preaccel
                .campus_direct_domains
                .iter()
                .filter(|entry| entry.contains(',')),
        );
    for raw_rule in global_rule_iter {
        if let Some(target) = extract_mihomo_rule_target(raw_rule) {
            if let Some(gids) = group_ids_by_name.get(target) {
                for &gid in gids {
                    queue.push(gid);
                }
            }
            if let Some(nids) = enabled_nodes_by_name.get(target) {
                for &nid in nids {
                    active_node_ids.insert(nid);
                }
            }
        }
    }

    // 3. Transitively expand active groups via `fallback_pool_id` and emitted `match_rules`.
    while let Some(gid) = queue.pop() {
        if !active_group_ids.insert(gid.to_string()) {
            continue;
        }
        if let Some(group) = group_by_id.get(gid) {
            if let Some(fb_id) = group
                .fallback_pool_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                if !active_group_ids.contains(fb_id) {
                    queue.push(fb_id);
                }
            }
            if single_mode_node_id.is_none()
                && (effective_active_group_id == Some(gid) || group.independent_routing)
            {
                let g_name = if group.name.trim().is_empty() {
                    gid
                } else {
                    group.name.trim()
                };
                for raw_rule in &group.match_rules {
                    for expanded in expand_group_match_rule(raw_rule, g_name) {
                        if let Some(target) = extract_mihomo_rule_target(&expanded) {
                            if let Some(target_gids) = group_ids_by_name.get(target) {
                                for &target_gid in target_gids {
                                    if !active_group_ids.contains(target_gid) {
                                        queue.push(target_gid);
                                    }
                                }
                            }
                            if let Some(nids) = enabled_nodes_by_name.get(target) {
                                for &nid in nids {
                                    active_node_ids.insert(nid);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let mut need_all_enabled = false;
    for group in input.groups {
        let g_id = group.id.trim();
        if !active_group_ids.contains(g_id) {
            continue;
        }
        let group_name = if group.name.trim().is_empty() {
            g_id
        } else {
            group.name.trim()
        };
        let explicit_filtered = input
            .group_filtered_members
            .get(&group.id)
            .or_else(|| input.group_filtered_members.get(group_name));
        if let Some(filtered_ids) = explicit_filtered {
            for nid in filtered_ids {
                if let Some(&id_ref) = enabled_node_ids.get(nid.as_str()) {
                    active_node_ids.insert(id_ref);
                }
            }
        } else if !group.member_node_ids.is_empty() {
            for nid in &group.member_node_ids {
                if let Some(&id_ref) = enabled_node_ids.get(nid.as_str()) {
                    active_node_ids.insert(id_ref);
                }
            }
        } else if group.mode == MultiGroupMode::ConditionalPool {
            need_all_enabled = true;
            break;
        }
    }

    if need_all_enabled || active_node_ids.is_empty() {
        return (enabled_nodes, None);
    }

    expand_chained_dialer_nodes(&enabled_nodes, &mut active_node_ids);
    let selected: Vec<&'a ProxyNode> = enabled_nodes
        .into_iter()
        .filter(|n| active_node_ids.contains(n.id.as_str()))
        .collect();
    if selected.is_empty() {
        let all_enabled: Vec<&'a ProxyNode> = input.nodes.iter().filter(|n| n.enabled).collect();
        return (all_enabled, None);
    }
    (selected, Some(active_group_ids))
}

fn expand_chained_dialer_nodes<'a>(
    enabled_nodes: &[&'a ProxyNode],
    active_node_ids: &mut HashSet<&'a str>,
) {
    let mut by_name: HashMap<&str, Vec<&'a ProxyNode>> = HashMap::new();
    for &node in enabled_nodes {
        let trimmed = node.name.trim();
        if !trimmed.is_empty() {
            by_name.entry(trimmed).or_default().push(node);
        }
    }
    loop {
        let mut added = false;
        let snapshot: Vec<&'a str> = active_node_ids.iter().copied().collect();
        for &node in enabled_nodes {
            if !snapshot.contains(&node.id.as_str()) {
                continue;
            }
            let Some(dp) = node
                .raw_config
                .get("dialer-proxy")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty() && *s != PREACCEL_SELECT_GROUP_NAME)
            else {
                continue;
            };
            if let Some(targets) = by_name.get(dp) {
                for target in targets {
                    if active_node_ids.insert(target.id.as_str()) {
                        added = true;
                    }
                }
            }
        }
        if !added {
            break;
        }
    }
}

fn build_sniffer_section(
    block_quic_udp_443: bool,
    domestic_direct_enabled: bool,
    has_geoip: bool,
) -> Mapping {
    let mut map = Mapping::new();
    insert_bool(&mut map, "enable", true);
    insert_bool(&mut map, "force-dns-mapping", true);
    insert_bool(&mut map, "parse-pure-ip", true);
    insert_bool(&mut map, "override-destination", false);

    let mut sniff = Mapping::new();

    let mut http = Mapping::new();
    http.insert(
        str_val("ports"),
        Value::Sequence(vec![
            Value::Number(Number::from(80u64)),
            str_val("8080-8880"),
        ]),
    );
    insert_bool(&mut http, "override-destination", true);
    sniff.insert(str_val("HTTP"), Value::Mapping(http));

    let mut tls = Mapping::new();
    tls.insert(
        str_val("ports"),
        Value::Sequence(vec![
            Value::Number(Number::from(443u64)),
            Value::Number(Number::from(8443u64)),
        ]),
    );
    sniff.insert(str_val("TLS"), Value::Mapping(tls));

    // When `block_quic_udp_443` and `domestic_direct_enabled` are both active while GeoIP
    // (`Country.mmdb` / `geoip.dat`) is absent, keep QUIC sniffing enabled so Mihomo can extract
    // the SNI from QUIC ClientHello on real-IP (`fake-ip-filter`) packets and match domestic IM
    // `DOMAIN-SUFFIX` DIRECT rules (e.g. QQ/WeChat) before falling through to UDP/443 REJECT.
    if !block_quic_udp_443 || (domestic_direct_enabled && !has_geoip) {
        let mut quic = Mapping::new();
        quic.insert(
            str_val("ports"),
            Value::Sequence(vec![
                Value::Number(Number::from(443u64)),
                Value::Number(Number::from(8443u64)),
            ]),
        );
        sniff.insert(str_val("QUIC"), Value::Mapping(quic));
    }

    map.insert(str_val("sniff"), Value::Mapping(sniff));
    map.insert(
        str_val("skip-domain"),
        string_seq(["Mijia Cloud", "+.push.apple.com"]),
    );
    map
}

fn build_dns_section(
    cfg: &AppConfig,
    allocated_ports: &AllocatedPorts,
    anti_loop_fake_ip_domains: &[String],
    extra_fake_ip_filters: &[String],
    has_geosite: bool,
    has_geoip: bool,
) -> Mapping {
    let dns = &cfg.dns;
    let mut map = Mapping::new();

    let dns_host = if cfg.allow_lan {
        cfg.dns_listen_host.trim()
    } else {
        "127.0.0.1"
    };

    let mut effective_default_ns: Vec<String> = dns
        .default_nameserver
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect();
    if effective_default_ns.is_empty() {
        effective_default_ns = crate::config::DEFAULT_PURE_IP_DOH_NAMESERVERS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
    }

    let mut effective_direct_ns: Vec<String> = dns
        .direct_nameserver
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect();
    if effective_direct_ns.is_empty() {
        effective_direct_ns = crate::config::DEFAULT_PURE_IP_DOH_NAMESERVERS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
    }

    let mut effective_proxy_server_ns: Vec<String> = dns
        .proxy_server_nameserver
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect();
    if dns.respect_rules && effective_proxy_server_ns.is_empty() {
        let cleaned_default_ns: Vec<String> = dns
            .default_nameserver
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect();
        if !cleaned_default_ns.is_empty()
            && !crate::config::is_legacy_plaintext_domestic_dns_list(&cleaned_default_ns)
        {
            effective_proxy_server_ns = cleaned_default_ns;
        } else {
            effective_proxy_server_ns = crate::config::DEFAULT_PURE_IP_DOH_NAMESERVERS
                .iter()
                .map(|s| (*s).to_string())
                .collect();
        }
    }

    if dns.respect_rules {
        for entry in &mut effective_direct_ns {
            if !entry.contains('#') && !entry.eq_ignore_ascii_case("system") {
                entry.push_str("#DIRECT");
            }
        }
    }

    let effective_nameserver: Vec<String> = dns
        .nameserver
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|entry| {
            if dns.respect_rules
                && !entry.contains('#')
                && is_domestic_default_nameserver(entry)
            {
                format!("{entry}#DIRECT")
            } else {
                entry.to_string()
            }
        })
        .collect();

    let mut effective_fallback: Vec<String> = dns
        .fallback
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect();
    if effective_fallback.is_empty() {
        effective_fallback = vec![
            "https://1.1.1.1/dns-query".to_string(),
            "https://8.8.8.8/dns-query".to_string(),
        ];
    }

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
        if trimmed.is_empty() {
            continue;
        }
        if !has_geosite && trimmed.to_ascii_lowercase().starts_with("geosite:") {
            continue;
        }
        push_unique(&mut merged_fake_ip_filter, trimmed.to_string());
    }
    if has_geosite {
        push_unique(&mut merged_fake_ip_filter, "geosite:cn".to_string());
        push_unique(&mut merged_fake_ip_filter, "geosite:private".to_string());
    }
    const DOMESTIC_DNS_FAKE_IP_FILTERS: &[&str] =
        &["dns.alidns.com", "doh.pub", "dot.pub", "dns.pub"];
    for item in DOMESTIC_DNS_FAKE_IP_FILTERS {
        push_unique(&mut merged_fake_ip_filter, (*item).to_string());
    }
    const DOMESTIC_IM_FAKE_IP_FILTERS: &[&str] = &[
        "+.qq.com",
        "+.qpic.cn",
        "+.qlogo.cn",
        "+.gtimg.cn",
        "+.gtimg.com",
        "+.nt.qq.com.cn",
        "+.weixin.qq.com",
        "+.tencent.com",
        "+.qcloud.com",
        "+.myqcloud.com",
    ];
    for item in DOMESTIC_IM_FAKE_IP_FILTERS {
        push_unique(&mut merged_fake_ip_filter, (*item).to_string());
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
        string_seq(effective_default_ns.iter().map(String::as_str)),
    );
    map.insert(
        str_val("direct-nameserver"),
        string_seq(effective_direct_ns.iter().map(String::as_str)),
    );

    // Build nameserver-policy: user-configured patterns take precedence, then auto-route
    // sensitive AI / Google / GitHub / X domains through overseas DoH (`fallback`) to prevent
    // domestic DNS leakage/pollution, route campus/LAN intranet suffixes via `system` first
    // (preserving campus DHCP DNS without polluting public DoH 443 or causing TUN loops),
    // plus `geosite:cn,private -> direct-nameserver` when geosite exists.
    let mut policy_map = Mapping::new();
    let mut configured_policy_keys: HashSet<String> = HashSet::new();
    for (pattern, servers) in &dns.nameserver_policy {
        let pat_trimmed = pattern.trim();
        if pat_trimmed.is_empty() {
            continue;
        }
        if !has_geosite && pat_trimmed.to_ascii_lowercase().contains("geosite:") {
            continue;
        }
        policy_map.insert(
            str_val(pat_trimmed),
            string_seq(servers.iter().map(String::as_str)),
        );
        configured_policy_keys.insert(pat_trimmed.to_ascii_lowercase());
    }

    const AI_DNS_POLICY_DOMAINS: &[&str] = &[
        "+.anthropic.com",
        "+.claude.ai",
        "+.claude.com",
        "+.openai.com",
        "api.openai.com",
        "ios.chat.openai.com",
        "+.chatgpt.com",
        "ab.chatgpt.com",
        "+.google.com",
        "+.googleapis.com",
        "+.gstatic.com",
        "+.googleusercontent.com",
        "+.antigravity.google",
        "+.windsurf.com",
        "+.codeium.com",
        "+.github.com",
        "+.x.com",
        "+.twitter.com",
        "+.twimg.com",
        "+.t.co",
    ];
    for &domain in AI_DNS_POLICY_DOMAINS {
        let key_lower = domain.to_ascii_lowercase();
        if !configured_policy_keys.contains(&key_lower) {
            policy_map.insert(
                str_val(domain),
                string_seq(effective_fallback.iter().map(String::as_str)),
            );
            configured_policy_keys.insert(key_lower);
        }
    }

    let campus_policy_servers: [&str; 2] = if dns.respect_rules {
        ["system", "https://223.5.5.5/dns-query#DIRECT"]
    } else {
        ["system", "https://223.5.5.5/dns-query"]
    };
    const CAMPUS_INTRANET_DNS_POLICY_DOMAINS: &[&str] = &[
        "+.edu.cn",
        "+.lan",
        "+.local",
        "+.localdomain",
        "+.internal",
        "+.home.arpa",
    ];
    for &domain in CAMPUS_INTRANET_DNS_POLICY_DOMAINS {
        let key_lower = domain.to_ascii_lowercase();
        if !configured_policy_keys.contains(&key_lower) {
            policy_map.insert(
                str_val(domain),
                string_seq(campus_policy_servers.iter().copied()),
            );
            configured_policy_keys.insert(key_lower);
        }
    }
    for raw_domain in &cfg.preaccel.campus_direct_domains {
        if let Some(domain) = normalize_campus_policy_domain(raw_domain) {
            let key_lower = domain.to_ascii_lowercase();
            if !configured_policy_keys.contains(&key_lower) {
                policy_map.insert(
                    str_val(&domain),
                    string_seq(campus_policy_servers.iter().copied()),
                );
                configured_policy_keys.insert(key_lower);
            }
        }
    }

    if has_geosite && !configured_policy_keys.contains("geosite:cn,private") {
        policy_map.insert(
            str_val("geosite:cn,private"),
            string_seq(effective_direct_ns.iter().map(String::as_str)),
        );
    }
    map.insert(str_val("nameserver-policy"), Value::Mapping(policy_map));

    map.insert(
        str_val("nameserver"),
        string_seq(effective_nameserver.iter().map(String::as_str)),
    );
    map.insert(
        str_val("fallback"),
        string_seq(effective_fallback.iter().map(String::as_str)),
    );
    map.insert(
        str_val("proxy-server-nameserver"),
        string_seq(effective_proxy_server_ns.iter().map(String::as_str)),
    );

    let mut ff_map = Mapping::new();
    insert_bool(&mut ff_map, "geoip", dns.fallback_filter.geoip && has_geoip);
    insert_str(&mut ff_map, "geoip-code", &dns.fallback_filter.geoip_code);
    // `fallback-filter.geosite` is deprecated in Mihomo and triggers a warning on every start/reload;
    // geosite DNS routing is already handled by `nameserver-policy` above.
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

fn normalize_campus_policy_domain(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Campus direct entries may be Mihomo rule lines such as `DOMAIN-SUFFIX,campus.edu,DIRECT`
    // or `IP-CIDR,10.0.0.0/8,DIRECT,no-resolve`. Only extract domain payload from DOMAIN /
    // DOMAIN-SUFFIX rules; reject all other comma-bearing rules so Mihomo never splits them
    // into stray `nameserver-policy` keys.
    let candidate = if trimmed.contains(',') {
        let mut parts = trimmed.split(',').map(str::trim);
        let rule_type = parts.next().unwrap_or_default();
        let payload = parts.next().unwrap_or_default();
        if rule_type.eq_ignore_ascii_case("DOMAIN") {
            payload
        } else if rule_type.eq_ignore_ascii_case("DOMAIN-SUFFIX") {
            return normalize_campus_policy_domain(&format!("+.{payload}"));
        } else {
            return None;
        }
    } else {
        trimmed
    };
    if candidate.is_empty()
        || candidate.contains(',')
        || candidate.contains("://")
        || candidate.contains('/')
        || candidate.contains(':')
        || candidate.chars().any(char::is_whitespace)
        || crate::preaccel::parse_server_ip(candidate).is_some()
    {
        return None;
    }
    let normalized = candidate.trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    if let Some(suffix) = normalized
        .strip_prefix("*.")
        .or_else(|| normalized.strip_prefix("+."))
    {
        let clean = suffix.trim_start_matches('.');
        if clean.is_empty() || clean.starts_with("geosite:") {
            return None;
        }
        return Some(format!("+.{clean}"));
    }
    if normalized.starts_with("geosite:") {
        return None;
    }
    Some(normalized)
}

fn is_domestic_default_nameserver(entry: &str) -> bool {
    let raw = entry.split('#').next().unwrap_or(entry).trim();
    if raw.is_empty() {
        return false;
    }
    let host = if raw.contains("://") {
        match Url::parse(raw) {
            Ok(u) => u
                .host_str()
                .map(|h| {
                    h.trim_start_matches('[')
                        .trim_end_matches(']')
                        .to_ascii_lowercase()
                })
                .unwrap_or_default(),
            Err(_) => return false,
        }
    } else if let Ok(ip) = raw.parse::<IpAddr>() {
        ip.to_string()
    } else if let Ok(sock) = raw.parse::<SocketAddr>() {
        sock.ip().to_string()
    } else {
        raw.split(':').next().unwrap_or("").trim().to_ascii_lowercase()
    };

    matches!(
        host.as_str(),
        "223.5.5.5"
            | "223.6.6.6"
            | "1.12.12.12"
            | "119.29.29.29"
            | "119.28.28.28"
            | "120.53.53.53"
            | "114.114.114.114"
            | "114.114.115.115"
            | "180.76.76.76"
            | "180.184.1.1"
            | "180.184.2.2"
            | "1.2.4.8"
            | "210.2.4.8"
            | "dns.alidns.com"
            | "doh.pub"
            | "dot.pub"
            | "dns.pub"
    )
}

/// Decide whether `tun.device` should be emitted into Mihomo YAML for the given target OS.
///
/// On macOS, kernel utun interfaces strictly require `utun[0-9]*` naming (e.g. `utun9`).
/// Emitting non-utun names such as `"CatCloud"` causes Mihomo to fail loading the config on
/// macOS; omitting `device` lets Mihomo auto-allocate a valid `utun[0-9]*` device.
pub fn should_emit_tun_device_name(target_os: &str, device_name: &str) -> bool {
    let trimmed = device_name.trim();
    if trimmed.is_empty() {
        return false;
    }
    if target_os.eq_ignore_ascii_case("macos") {
        trimmed
            .strip_prefix("utun")
            .is_some_and(|rest| rest.bytes().all(|b| b.is_ascii_digit()))
    } else {
        true
    }
}

fn build_tun_section(cfg: &AppConfig) -> Mapping {
    let tun = &cfg.tun;
    let mut map = Mapping::new();
    insert_bool(&mut map, "enable", tun.enabled);
    insert_str(&mut map, "stack", tun.stack_mode.as_str());
    if should_emit_tun_device_name(std::env::consts::OS, &tun.device_name) {
        insert_str(&mut map, "device", tun.device_name.trim());
    }
    insert_bool(&mut map, "auto-route", tun.auto_route);
    insert_bool(&mut map, "auto-detect-interface", tun.auto_detect_interface);
    insert_bool(&mut map, "strict-route", tun.strict_route);
    insert_bool(&mut map, "endpoint-independent-nat", false);
    insert_u64(&mut map, "mtu", u64::from(tun.mtu));
    map.insert(
        str_val("dns-hijack"),
        string_seq(tun.dns_hijack.iter().map(String::as_str)),
    );
    map
}

fn build_relay_proxy_mapping(relay: &PreAccelRelay, unique_name: &str) -> CatResult<Mapping> {
    let value = crate::preaccel::generator::compile_relay_to_mihomo_yaml(relay, unique_name)?;
    match value {
        Value::Mapping(map) => Ok(map),
        _ => Err(CatError::Validation(format!(
            "compiled domestic pre-acceleration relay `{unique_name}` did not produce a YAML mapping"
        ))),
    }
}

pub fn build_node_proxy_mapping(node: &ProxyNode, unique_name: &str) -> CatResult<Mapping> {
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
            last_up_mbps: None,
            last_down_mbps: None,
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
            independent_routing: true,
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
        // Without runtime_dir geodata files on disk, fallback-filter safely disables geoip & omits geosite.
        assert_eq!(dns["fallback-filter"]["geoip"], Value::Bool(false));
        assert_eq!(dns["fallback-filter"]["geoip-code"], "CN");
        assert!(dns["fallback-filter"].get("geosite").is_none());
        assert!(dns.get("direct-nameserver").is_some());
        assert!(dns["nameserver-policy"].get("+.anthropic.com").is_some());
        assert!(dns["nameserver-policy"].get("+.antigravity.google").is_some());
        assert!(dns["nameserver-policy"].get("+.cn").is_some());

        // Sniffer & geox-url sections
        assert_eq!(compiled.value["sniffer"]["enable"], Value::Bool(true));
        assert_eq!(
            compiled.value["sniffer"]["force-dns-mapping"],
            Value::Bool(true)
        );
        assert_eq!(
            compiled.value["sniffer"]["parse-pure-ip"],
            Value::Bool(true)
        );
        assert_eq!(
            compiled.value["sniffer"]["override-destination"],
            Value::Bool(false)
        );
        assert!(compiled.value["geox-url"].get("geoip").is_some());
        assert!(compiled.value["geox-url"].get("geosite").is_some());
        assert!(compiled.value["geox-url"].get("mmdb").is_some());
        assert!(compiled.value["geox-url"].get("asn").is_some());

        // Full TUN fields
        let tun = &compiled.value["tun"];
        assert_eq!(tun["enable"], Value::Bool(true));
        assert_eq!(tun["stack"], "gvisor");
        assert_eq!(tun["strict-route"], Value::Bool(true));
        assert_eq!(tun["endpoint-independent-nat"], Value::Bool(false));
        assert_eq!(tun["mtu"], 1500);

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

    #[test]
    fn compiles_single_node_route_mode_skips_group_rules_and_targets_selected_node() {
        let mut cfg = AppConfig::default();
        cfg.route_mode = RouteTargetMode::Single;
        cfg.active_single_node_id = Some("n2".to_string());
        cfg.active_group_id = Some("g-ai".to_string());
        cfg.preaccel.campus_direct_domains = vec![
            "portal.campus.test".to_string(),
            "DOMAIN-SUFFIX,".to_string(),
            "DOMAIN,auth.campus.test,DIRECT".to_string(),
        ];

        let nodes = vec![
            sample_node("n1", "Node-JP-01", 8443, false),
            sample_node("n2", "Node-SG-02", 443, true),
            sample_node("n3", "Node-US-03", 9443, false),
        ];
        let group = MultiGroup {
            id: "g-ai".to_string(),
            name: "AI-Sticky".to_string(),
            mode: MultiGroupMode::StickyBest,
            match_rules: vec![
                "@ai_domains".to_string(),
                "DOMAIN-SUFFIX,example.com".to_string(),
            ],
            member_node_ids: vec!["n1".into(), "n3".into()],
            active_node_id: Some("n1".to_string()),
            ..Default::default()
        };
        let ports = sample_ports();
        let empty = HashMap::new();

        let compiled = compile_mihomo_config(&CompileInput {
            config: &cfg,
            nodes: &nodes,
            groups: &[group],
            relays: &[],
            controller_secret: "0123456789abcdef0123456789abcdef",
            allocated_ports: &ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &empty,
        })
        .expect("single-node compile must succeed");

        assert!(
            compiled.validation.ok,
            "issues: {:?}",
            compiled.validation.issues
        );

        let pg = compiled.value["proxy-groups"].as_sequence().unwrap();
        let single_group = pg
            .iter()
            .find(|g| g["name"] == SINGLE_NODE_GROUP_NAME)
            .expect("SINGLE_NODE_GROUP_NAME must be compiled");
        assert_eq!(single_group["type"], "select");

        let single_members: Vec<&str> = single_group["proxies"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(single_members, vec!["Node-SG-02", "Node-JP-01", "Node-US-03"]);
        assert_eq!(
            compiled
                .active_selections
                .get(SINGLE_NODE_GROUP_NAME)
                .map(String::as_str),
            Some("Node-SG-02")
        );

        let rules: Vec<&str> = compiled.value["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        let expected_match = format!("MATCH,{SINGLE_NODE_GROUP_NAME}");
        assert_eq!(rules.last().copied(), Some(expected_match.as_str()));
        assert!(!rules.iter().any(|r| r.contains(",AI-Sticky")));
        assert!(rules.contains(&"DOMAIN-SUFFIX,portal.campus.test,DIRECT"));
        assert!(rules.contains(&"DOMAIN,auth.campus.test,DIRECT"));
        assert!(!rules.contains(&"DOMAIN-SUFFIX,"));
    }

    #[test]
    fn compiles_with_runtime_dir_detects_geodata_and_gates_geosite_geoip() {
        let dir = std::env::temp_dir().join(format!(
            "catcloud-compiler-geo-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let cfg = AppConfig::default();
        let ports = sample_ports();
        let nodes = vec![sample_node("n1", "Node-JP-01", 443, true)];
        let empty = HashMap::new();
        let input = CompileInput {
            config: &cfg,
            nodes: &nodes,
            groups: &[],
            relays: &[],
            controller_secret: "0123456789abcdef0123456789abcdef",
            allocated_ports: &ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &empty,
        };

        // 1. Empty runtime_dir -> no GEOSITE/GEOIP rules, fallback domestic domains emitted
        let without_geo = compile_mihomo_config_with_runtime_dir(&input, Some(&dir)).unwrap();
        assert!(without_geo.validation.ok);
        assert_eq!(
            without_geo.value["dns"]["fallback-filter"]["geoip"],
            Value::Bool(false)
        );
        assert!(without_geo.value["dns"]["fallback-filter"].get("geosite").is_none());
        assert!(
            without_geo.value["dns"]["nameserver-policy"]
                .get("geosite:cn,private")
                .is_none()
        );
        let rules_no_geo: Vec<&str> = without_geo.value["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(rules_no_geo.contains(&"IP-CIDR,127.0.0.0/8,DIRECT,no-resolve"));
        assert!(rules_no_geo.contains(&"IP-CIDR6,fe80::/10,DIRECT,no-resolve"));
        assert!(rules_no_geo.contains(&"AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"));
        assert!(rules_no_geo.contains(&"DOMAIN-SUFFIX,cn,DIRECT"));
        assert!(rules_no_geo.contains(&"DOMAIN-SUFFIX,qq.com,DIRECT"));
        assert!(rules_no_geo.contains(&"DOMAIN-SUFFIX,edu.cn,DIRECT"));
        assert!(!rules_no_geo.contains(&"GEOSITE,private,DIRECT"));
        assert!(!rules_no_geo.contains(&"GEOSITE,cn,DIRECT"));
        assert!(!rules_no_geo.contains(&"GEOIP,CN,DIRECT,no-resolve"));

        // 2. With geosite.dat + Country.mmdb -> enables GEOSITE/GEOIP rules & DNS policies
        std::fs::write(dir.join("geosite.dat"), b"stub").unwrap();
        std::fs::write(dir.join("Country.mmdb"), b"stub").unwrap();
        let with_geo = compile_mihomo_config_with_runtime_dir(&input, Some(&dir)).unwrap();
        assert!(with_geo.validation.ok);
        assert_eq!(
            with_geo.value["dns"]["fallback-filter"]["geoip"],
            Value::Bool(true)
        );
        // `fallback-filter.geosite` is intentionally omitted because Mihomo deprecates it
        // in favor of `nameserver-policy`.
        assert!(with_geo.value["dns"]["fallback-filter"].get("geosite").is_none());
        assert!(
            with_geo.value["dns"]["nameserver-policy"]
                .get("geosite:cn,private")
                .is_some()
        );
        let fake_filters: Vec<&str> = with_geo.value["dns"]["fake-ip-filter"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(fake_filters.contains(&"geosite:cn"));
        assert!(fake_filters.contains(&"geosite:private"));

        let rules_with_geo: Vec<&str> = with_geo.value["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(rules_with_geo.contains(&"GEOSITE,private,DIRECT"));
        assert!(rules_with_geo.contains(&"GEOSITE,cn,DIRECT"));
        assert!(rules_with_geo.contains(&"GEOIP,CN,DIRECT,no-resolve"));
        assert!(!rules_with_geo.contains(&"DOMAIN-SUFFIX,qq.com,DIRECT"));

        // 3. When geodata_mode == true, requires geoip.dat rather than Country.mmdb
        let mut cfg_dat = AppConfig::default();
        cfg_dat.geodata.geodata_mode = true;
        let input_dat = CompileInput {
            config: &cfg_dat,
            ..input
        };
        let without_geoip_dat =
            compile_mihomo_config_with_runtime_dir(&input_dat, Some(&dir)).unwrap();
        assert_eq!(
            without_geoip_dat.value["dns"]["fallback-filter"]["geoip"],
            Value::Bool(false)
        );
        std::fs::write(dir.join("geoip.dat"), b"stub").unwrap();
        let with_geoip_dat =
            compile_mihomo_config_with_runtime_dir(&input_dat, Some(&dir)).unwrap();
        assert_eq!(
            with_geoip_dat.value["dns"]["fallback-filter"]["geoip"],
            Value::Bool(true)
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dedup_proxy_names_strips_dangling_dialer_proxy_and_promotes_active_relay_with_autofailover() {
        let mut cfg = AppConfig::default();
        cfg.preaccel.enabled = true;
        cfg.preaccel.auto_failover = true;
        cfg.preaccel.active_relay_id = Some("r-second".to_string());
        cfg.preaccel.skip_443_native = true;

        let relays = vec![
            sample_relay("r-first", "Relay-First", "203.0.113.11", 10),
            sample_relay("r-second", "Relay-Second", "203.0.113.22", 20),
        ];

        // Two providers with identical node display names + domain server + dangling dialer-proxy
        let mut n1 = sample_node("sub-a-jp", "Tokyo-01", 443, true);
        n1.server = "jp-a.provider.test".to_string();
        n1.raw_config = serde_json::json!({
            "name": "Tokyo-01",
            "type": "trojan",
            "server": "jp-a.provider.test",
            "port": 443,
            "password": "p1",
            "dialer-proxy": "NonExistentUpstreamGroup"
        });

        let mut n2 = sample_node("sub-b-jp", "Tokyo-01", 443, true);
        n2.server = "198.51.100.88".to_string();
        n2.raw_config = serde_json::json!({
            "name": "Tokyo-01",
            "type": "trojan",
            "server": "198.51.100.88",
            "port": 443,
            "password": "p2",
            "dialer-proxy": "Relay-First"
        });

        let mut n3 = sample_node("sub-c-self", "SelfLoop-01", 443, true);
        n3.server = "198.51.100.99".to_string();
        n3.raw_config = serde_json::json!({
            "name": "SelfLoop-01",
            "type": "trojan",
            "server": "198.51.100.99",
            "port": 443,
            "password": "p3",
            "dialer-proxy": "SelfLoop-01"
        });

        let nodes = vec![n1, n2, n3];
        let ports = sample_ports();
        let empty = HashMap::new();
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
        .expect("compile ok");
        assert!(compiled.validation.ok, "issues: {:?}", compiled.validation.issues);

        // Unique proxy names tracked in node_id_to_proxy_name
        assert_eq!(
            compiled.node_id_to_proxy_name.get("sub-a-jp").map(String::as_str),
            Some("Tokyo-01")
        );
        assert_eq!(
            compiled.node_id_to_proxy_name.get("sub-b-jp").map(String::as_str),
            Some("Tokyo-01 (2)")
        );

        // Dangling and self-referencing dialer-proxy stripped; valid relay target preserved on n2
        let proxies = compiled.value["proxies"].as_sequence().unwrap();
        let p1 = proxies.iter().find(|p| p["name"] == "Tokyo-01").unwrap();
        assert!(p1.get("dialer-proxy").is_none());
        let p2 = proxies.iter().find(|p| p["name"] == "Tokyo-01 (2)").unwrap();
        assert_eq!(p2["dialer-proxy"], "Relay-First");
        let p3 = proxies.iter().find(|p| p["name"] == "SelfLoop-01").unwrap();
        assert!(p3.get("dialer-proxy").is_none());

        // Domain node server enters fake-ip-filter, while pure-IP business node is NOT forced DIRECT
        let fake_filters: Vec<&str> = compiled.value["dns"]["fake-ip-filter"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(fake_filters.contains(&"jp-a.provider.test"));
        assert!(!fake_filters.contains(&"198.51.100.88"));

        let rules: Vec<&str> = compiled.value["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(!rules.contains(&"IP-CIDR,198.51.100.88/32,DIRECT,no-resolve"));
        assert!(rules.contains(&"IP-CIDR,203.0.113.11/32,DIRECT,no-resolve"));
        assert!(rules.contains(&"IP-CIDR,203.0.113.22/32,DIRECT,no-resolve"));

        // active_relay_id ("r-second" -> Relay-Second) is promoted to index 0 of fallback group
        // even when auto_failover == true
        let fallback_group = compiled.value["proxy-groups"]
            .as_sequence()
            .unwrap()
            .iter()
            .find(|g| g["name"] == PREACCEL_FALLBACK_GROUP_NAME)
            .unwrap();
        let fb_members: Vec<&str> = fallback_group["proxies"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(fb_members, vec!["Relay-Second", "Relay-First", "DIRECT"]);
    }

    #[test]
    fn supports_logical_and_rules_and_honors_quic_and_domestic_direct_toggles() {
        assert!(is_plausible_global_rule(
            "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"
        ));
        assert!(!is_plausible_global_rule("AND,((NETWORK,UDP),REJECT"));
        assert_eq!(
            expand_group_match_rule("AND,((NETWORK,UDP),(DST-PORT,443)),REJECT", "AI"),
            vec!["AND,((NETWORK,UDP),(DST-PORT,443)),REJECT".to_string()]
        );

        let mut cfg = AppConfig::default();
        cfg.dns.respect_rules = true;
        cfg.dns.proxy_server_nameserver.clear();
        cfg.rules_override.block_quic_udp_443 = false;
        cfg.rules_override.domestic_direct_enabled = false;
        cfg.rules_override
            .global_prepend_rules
            .push("AND,((NETWORK,UDP),(DST-PORT,443)),REJECT".to_string());

        let ports = sample_ports();
        let nodes = vec![sample_node("n1", "Node-JP-01", 443, true)];
        let empty = HashMap::new();
        let compiled = compile_mihomo_config(&CompileInput {
            config: &cfg,
            nodes: &nodes,
            groups: &[],
            relays: &[],
            controller_secret: "0123456789abcdef0123456789abcdef",
            allocated_ports: &ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &empty,
        })
        .unwrap();

        // respect_rules == true guarantees non-empty proxy-server-nameserver
        let ps_ns = compiled.value["dns"]["proxy-server-nameserver"]
            .as_sequence()
            .unwrap();
        assert!(!ps_ns.is_empty());

        let rules: Vec<&str> = compiled.value["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        // Explicit user global_prepend_rules logical rule passed through
        assert!(rules.contains(&"AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"));
        // Domestic direct rules disabled
        assert!(!rules.contains(&"DOMAIN-SUFFIX,cn,DIRECT"));
        assert!(!rules.contains(&"DOMAIN-SUFFIX,qq.com,DIRECT"));
    }

    #[test]
    fn enforces_probe_bypass_domestic_dns_direct_tag_relay_delegation_and_quic_order() {
        let mut cfg = AppConfig::default();
        cfg.dns.respect_rules = true;
        cfg.dns.direct_nameserver = vec![
            "https://223.5.5.5/dns-query".to_string(),
            "https://1.12.12.12/dns-query#CUSTOM".to_string(),
            "system".to_string(),
        ];
        cfg.dns.nameserver = vec![
            "https://223.5.5.5/dns-query".to_string(),
            "https://1.12.12.12/dns-query".to_string(),
            "https://1.1.1.1/dns-query".to_string(),
            "https://223.6.6.6/dns-query#KEEP".to_string(),
        ];
        cfg.dns.fallback.clear();
        cfg.preaccel.enabled = true;
        cfg.rules_override.block_quic_udp_443 = true;
        cfg.rules_override.global_prepend_rules =
            vec!["DOMAIN,global-pre.example.test,DIRECT".to_string()];

        let mut vless_relay = sample_relay("r-vless", "Relay-VLESS-443", "203.0.113.30", 10);
        vless_relay.protocol = "vless".to_string();
        vless_relay.password = "11111111-2222-3333-4444-555555555555".to_string();
        vless_relay.port = 443;
        vless_relay.sni = Some("mistaken-sni.example.com".to_string());

        let mut anytls_relay = sample_relay("r-anytls", "Relay-AnyTLS-443", "203.0.113.31", 20);
        anytls_relay.protocol = "anytls".to_string();
        anytls_relay.port = 443;
        anytls_relay.sni = Some("mistaken-sni.example.com".to_string());

        let relays = vec![vless_relay, anytls_relay];
        let nodes = vec![sample_node("n1", "Node-JP-8443", 8443, false)];
        let group = MultiGroup {
            id: "g-ai".to_string(),
            name: "AI-Group".to_string(),
            match_rules: vec!["DOMAIN-SUFFIX,openai.com".to_string()],
            member_node_ids: vec!["n1".to_string()],
            ..Default::default()
        };
        let extra_prepend = vec!["DOMAIN,extra-pre.example.test,DIRECT".to_string()];
        let ports = sample_ports();
        let empty = HashMap::new();

        let compiled = compile_mihomo_config(&CompileInput {
            config: &cfg,
            nodes: &nodes,
            groups: &[group],
            relays: &relays,
            controller_secret: "0123456789abcdef0123456789abcdef",
            allocated_ports: &ports,
            extra_prepend_rules: &extra_prepend,
            extra_fake_ip_filters: &[],
            group_filtered_members: &empty,
        })
        .expect("compile ok");
        assert!(compiled.validation.ok, "issues: {:?}", compiled.validation.issues);

        // 1. Rules ordering: anti-loop -> PROCESS-NAME probe bypass -> private LAN -> domestic DNS IPs ->
        //    extra_prepend -> global_prepend -> QUIC REJECT -> group match_rules
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
        let idx_anti_loop = rules
            .iter()
            .position(|r| *r == "IP-CIDR,203.0.113.30/32,DIRECT,no-resolve")
            .expect("relay anti-loop rule");
        let idx_probe = rules
            .iter()
            .position(|r| *r == probe_rule.as_str())
            .expect("probe core PROCESS-NAME bypass");
        let idx_lan = rules
            .iter()
            .position(|r| *r == "IP-CIDR6,fe80::/10,DIRECT,no-resolve")
            .expect("private LAN rule");
        let idx_dns_ali = rules
            .iter()
            .position(|r| *r == "IP-CIDR,223.5.5.5/32,DIRECT,no-resolve")
            .expect("223.5.5.5 direct rule");
        let idx_dns_dnspod = rules
            .iter()
            .position(|r| *r == "IP-CIDR,119.29.29.29/32,DIRECT,no-resolve")
            .expect("119.29.29.29 direct rule");
        let idx_extra_pre = rules
            .iter()
            .position(|r| *r == "DOMAIN,extra-pre.example.test,DIRECT")
            .expect("extra prepend rule");
        let idx_global_pre = rules
            .iter()
            .position(|r| *r == "DOMAIN,global-pre.example.test,DIRECT")
            .expect("global prepend rule");
        let idx_quic = rules
            .iter()
            .position(|r| *r == "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT")
            .expect("QUIC reject rule");
        let idx_group_rule = rules
            .iter()
            .position(|r| *r == "DOMAIN-SUFFIX,openai.com,AI-Group")
            .expect("group match rule");

        assert!(idx_anti_loop < idx_probe);
        assert!(idx_probe < idx_lan);
        assert!(idx_lan < idx_dns_ali);
        assert!(rules.contains(&"IP-CIDR,223.6.6.6/32,DIRECT,no-resolve"));
        assert!(rules.contains(&"IP-CIDR,1.12.12.12/32,DIRECT,no-resolve"));
        assert!(idx_dns_dnspod < idx_extra_pre);
        assert!(idx_extra_pre < idx_global_pre);
        assert!(idx_global_pre < idx_quic);
        assert!(idx_quic < idx_group_rule);

        // 2. DNS #DIRECT suffixes and effective_fallback fallback behavior
        let direct_ns: Vec<&str> = compiled.value["dns"]["direct-nameserver"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(
            direct_ns,
            vec![
                "https://223.5.5.5/dns-query#DIRECT",
                "https://1.12.12.12/dns-query#CUSTOM",
                "system",
            ]
        );

        let nameservers: Vec<&str> = compiled.value["dns"]["nameserver"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(
            nameservers,
            vec![
                "https://223.5.5.5/dns-query#DIRECT",
                "https://1.12.12.12/dns-query#DIRECT",
                "https://1.1.1.1/dns-query",
                "https://223.6.6.6/dns-query#KEEP",
            ]
        );

        let fallback_ns: Vec<&str> = compiled.value["dns"]["fallback"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(
            fallback_ns,
            vec![
                "https://1.1.1.1/dns-query",
                "https://8.8.8.8/dns-query",
            ]
        );

        // 3. Relay compilation delegates to preaccel::generator::compile_relay_to_mihomo_yaml
        let proxies = compiled.value["proxies"].as_sequence().unwrap();
        let compiled_vless = proxies
            .iter()
            .find(|p| p["name"] == "Relay-VLESS-443")
            .expect("compiled VLESS relay");
        assert_eq!(compiled_vless["type"], "vless");
        assert_eq!(compiled_vless["network"], "tcp");
        assert_eq!(compiled_vless["servername"], "");

        let compiled_anytls = proxies
            .iter()
            .find(|p| p["name"] == "Relay-AnyTLS-443")
            .expect("compiled AnyTLS relay");
        assert!(compiled_anytls.get("sni").is_none());

        // 4. When respect_rules == false, #DIRECT must NOT be appended
        let mut cfg_no_respect = cfg;
        cfg_no_respect.dns.respect_rules = false;
        let compiled_no_respect = compile_mihomo_config(&CompileInput {
            config: &cfg_no_respect,
            nodes: &nodes,
            groups: &[],
            relays: &[],
            controller_secret: "0123456789abcdef0123456789abcdef",
            allocated_ports: &ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &empty,
        })
        .expect("compile ok");
        let direct_ns_off: Vec<&str> = compiled_no_respect.value["dns"]["direct-nameserver"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(
            direct_ns_off,
            vec![
                "https://223.5.5.5/dns-query",
                "https://1.12.12.12/dns-query#CUSTOM",
                "system",
            ]
        );
        let ns_off: Vec<&str> = compiled_no_respect.value["dns"]["nameserver"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(ns_off[0], "https://223.5.5.5/dns-query");
    }

    #[test]
    fn unselected_group_without_independent_routing_never_hijacks_traffic_and_active_group_wins_priority() {
        let mut cfg = AppConfig::default();
        cfg.active_group_id = Some("grp-test".to_string());

        let nodes = vec![
            sample_node("n-jp", "Node-JP-Good", 443, true),
            sample_node("n-bad", "Node-Bad", 443, true),
        ];

        // Listed FIRST in input.groups, unselected, independent_routing=false -> MUST NOT hijack!
        let g_ai_inactive = MultiGroup {
            id: "grp-ai-unselected".to_string(),
            name: "AI-Dedicated-Unselected".to_string(),
            mode: MultiGroupMode::StickyBest,
            match_rules: vec!["@ai_domains".to_string(), "DOMAIN-SUFFIX,google.com".to_string()],
            member_node_ids: vec!["n-bad".to_string()],
            active_node_id: Some("n-bad".to_string()),
            independent_routing: false,
            ..Default::default()
        };

        // Listed SECOND, explicitly opted into independent_routing=true -> allowed to emit rules,
        // but MUST rank AFTER the active home group's own match_rules.
        let g_split = MultiGroup {
            id: "grp-split".to_string(),
            name: "Split-Express".to_string(),
            mode: MultiGroupMode::StickyBest,
            match_rules: vec![
                "DOMAIN-SUFFIX,openai.com".to_string(),
                "DOMAIN-SUFFIX,claude.ai".to_string(),
            ],
            member_node_ids: vec!["n-jp".to_string()],
            active_node_id: Some("n-jp".to_string()),
            independent_routing: true,
            ..Default::default()
        };

        // Listed THIRD, selected as active home group -> its match_rules MUST come FIRST + MATCH target.
        let g_active = MultiGroup {
            id: "grp-test".to_string(),
            name: "Active-Test-Group".to_string(),
            mode: MultiGroupMode::StickyBest,
            match_rules: vec!["DOMAIN-SUFFIX,openai.com".to_string()],
            member_node_ids: vec!["n-jp".to_string()],
            active_node_id: Some("n-jp".to_string()),
            independent_routing: false,
            ..Default::default()
        };

        let ports = sample_ports();
        let empty = HashMap::new();
        let groups = vec![g_ai_inactive, g_split, g_active];
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
        .expect("compile ok");
        assert!(compiled.validation.ok, "issues: {:?}", compiled.validation.issues);

        // All 3 proxy-groups are still compiled so instant switching remains available.
        let pg = compiled.value["proxy-groups"].as_sequence().unwrap();
        assert_eq!(pg.len(), 3);
        assert!(pg.iter().any(|g| g["name"] == "AI-Dedicated-Unselected"));

        let rules: Vec<&str> = compiled.value["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();

        // Unselected group without independent_routing must NOT emit ANY rules.
        assert!(
            !rules.iter().any(|r| r.contains(",AI-Dedicated-Unselected")),
            "unselected non-independent group hijacked rules: {rules:?}"
        );

        // Active group's rule MUST appear before independent split group's overlapping rule.
        let idx_active_openai = rules
            .iter()
            .position(|r| *r == "DOMAIN-SUFFIX,openai.com,Active-Test-Group")
            .expect("active group rule must be emitted");
        let idx_split_openai = rules
            .iter()
            .position(|r| *r == "DOMAIN-SUFFIX,openai.com,Split-Express")
            .expect("independent split group rule must be emitted");
        let idx_split_claude = rules
            .iter()
            .position(|r| *r == "DOMAIN-SUFFIX,claude.ai,Split-Express")
            .expect("independent split group non-overlapping rule must be emitted");
        assert!(idx_active_openai < idx_split_openai);
        assert!(idx_active_openai < idx_split_claude);

        // Final MATCH must point to active home group.
        assert_eq!(rules.last().copied(), Some("MATCH,Active-Test-Group"));
    }

    #[test]
    fn discards_ghost_active_node_id_not_in_members_instead_of_reinjecting() {
        let cfg = AppConfig::default();
        let ports = sample_ports();
        let nodes = vec![
            sample_node("n-jp", "Node-JP-01", 443, true),
            sample_node("n-sg", "Node-SG-02", 443, true),
            sample_node("n-ar", "Node-AR-Ghost", 443, true),
        ];

        // 1. Removed ghost node (`n-ar`) still stored in `active_node_id`, absent from `member_node_ids`.
        let g_ghost_member = MultiGroup {
            id: "g-ghost".to_string(),
            name: "No-Ghost-Group".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec!["n-jp".into(), "n-sg".into()],
            active_node_id: Some("n-ar".to_string()),
            ..Default::default()
        };

        // 2. Active node (`n-jp`) excluded by hard-gate `group_filtered_members` -> must fall back to `n-sg`.
        let g_filtered_ghost = MultiGroup {
            id: "g-filtered".to_string(),
            name: "Filtered-Group".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec!["n-jp".into(), "n-sg".into()],
            active_node_id: Some("n-jp".to_string()),
            ..Default::default()
        };

        // 3. CircuitOpen + StrictCircuitBreak must still select REJECT cleanly.
        let g_circuit_open = MultiGroup {
            id: "g-circuit".to_string(),
            name: "Circuit-Group".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec!["n-jp".into()],
            active_node_id: Some("n-ar".to_string()),
            fallback_policy: FallbackPolicy::StrictCircuitBreak,
            state: MultiGroupState::CircuitOpen,
            ..Default::default()
        };

        let mut filtered = HashMap::new();
        filtered.insert("g-filtered".to_string(), vec!["n-sg".to_string()]);

        let groups = vec![g_ghost_member, g_filtered_ghost, g_circuit_open];
        let compiled = compile_mihomo_config(&CompileInput {
            config: &cfg,
            nodes: &nodes,
            groups: &groups,
            relays: &[],
            controller_secret: "0123456789abcdef0123456789abcdef",
            allocated_ports: &ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &filtered,
        })
        .expect("compile ok");
        assert!(compiled.validation.ok, "issues: {:?}", compiled.validation.issues);

        let pg = compiled.value["proxy-groups"].as_sequence().unwrap();

        let ghost_members: Vec<&str> = pg[0]["proxies"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(ghost_members, vec!["Node-JP-01", "Node-SG-02"]);
        assert!(!ghost_members.contains(&"Node-AR-Ghost"));
        assert_eq!(
            compiled.active_selections.get("No-Ghost-Group").map(String::as_str),
            Some("Node-JP-01")
        );

        let filtered_members: Vec<&str> = pg[1]["proxies"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(filtered_members, vec!["Node-SG-02"]);
        assert_eq!(
            compiled.active_selections.get("Filtered-Group").map(String::as_str),
            Some("Node-SG-02")
        );

        let circuit_members: Vec<&str> = pg[2]["proxies"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(circuit_members[0], "REJECT");
        assert!(!circuit_members.contains(&"Node-AR-Ghost"));
        assert_eq!(
            compiled.active_selections.get("Circuit-Group").map(String::as_str),
            Some("REJECT")
        );
    }

    #[test]
    fn hardens_preaccel_fallback_direct_domestic_dns_and_codex_twitter_doh() {
        let mut cfg = AppConfig::default();
        cfg.preaccel.enabled = true;
        cfg.preaccel.auto_failover = true;

        let relays = vec![sample_relay("r1", "Relay-SH", "203.0.113.44", 10)];
        let nodes = vec![sample_node("n1", "Node-TW-01", 8443, false)];
        let group = MultiGroup {
            id: "g-ai".to_string(),
            name: "AI-Codex".to_string(),
            mode: MultiGroupMode::StickyBest,
            match_rules: vec!["@ai_domains".to_string()],
            member_node_ids: vec!["n1".to_string()],
            active_node_id: Some("n1".to_string()),
            ..Default::default()
        };
        let ports = sample_ports();
        let empty = HashMap::new();

        let compiled = compile_mihomo_config(&CompileInput {
            config: &cfg,
            nodes: &nodes,
            groups: &[group],
            relays: &relays,
            controller_secret: "0123456789abcdef0123456789abcdef",
            allocated_ports: &ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &empty,
        })
        .expect("compile ok");
        assert!(compiled.validation.ok, "issues: {:?}", compiled.validation.issues);

        // 1. Pre-accel fallback group ends with DIRECT safety net.
        let fallback_group = compiled.value["proxy-groups"]
            .as_sequence()
            .unwrap()
            .iter()
            .find(|g| g["name"] == PREACCEL_FALLBACK_GROUP_NAME)
            .expect("preaccel fallback group");
        let fb_members: Vec<&str> = fallback_group["proxies"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(fb_members, vec!["Relay-SH", "DIRECT"]);

        // 2. All domestic DNS IPs and DoH/DoT hostnames have DIRECT rules & fake-ip-filter entries.
        let rules: Vec<&str> = compiled.value["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        for expected_dns_rule in [
            "IP-CIDR,223.5.5.5/32,DIRECT,no-resolve",
            "IP-CIDR,223.6.6.6/32,DIRECT,no-resolve",
            "IP-CIDR,1.12.12.12/32,DIRECT,no-resolve",
            "IP-CIDR,119.29.29.29/32,DIRECT,no-resolve",
            "IP-CIDR,119.28.28.28/32,DIRECT,no-resolve",
            "IP-CIDR,120.53.53.53/32,DIRECT,no-resolve",
            "IP-CIDR,114.114.114.114/32,DIRECT,no-resolve",
            "IP-CIDR,114.114.115.115/32,DIRECT,no-resolve",
            "IP-CIDR,180.76.76.76/32,DIRECT,no-resolve",
            "DOMAIN,dns.alidns.com,DIRECT",
            "DOMAIN,doh.pub,DIRECT",
            "DOMAIN,dot.pub,DIRECT",
        ] {
            assert!(
                rules.contains(&expected_dns_rule),
                "missing domestic DNS direct rule `{expected_dns_rule}`"
            );
        }

        let fake_filters: Vec<&str> = compiled.value["dns"]["fake-ip-filter"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        for dns_host in ["dns.alidns.com", "doh.pub", "dot.pub"] {
            assert!(
                fake_filters.contains(&dns_host),
                "missing domestic DNS fake-ip-filter `{dns_host}`"
            );
        }

        // 3. Codex endpoints & Twitter/X domains are pinned to overseas DoH in nameserver-policy.
        let policy = &compiled.value["dns"]["nameserver-policy"];
        for doh_domain in [
            "ab.chatgpt.com",
            "ios.chat.openai.com",
            "api.openai.com",
            "+.x.com",
            "+.twitter.com",
            "+.twimg.com",
            "+.t.co",
        ] {
            let servers: Vec<&str> = policy
                .get(doh_domain)
                .and_then(Value::as_sequence)
                .unwrap_or_else(|| panic!("missing nameserver-policy for `{doh_domain}`"))
                .iter()
                .filter_map(Value::as_str)
                .collect();
            assert!(
                servers.contains(&"https://1.1.1.1/dns-query"),
                "`{doh_domain}` must route via overseas DoH fallback, got {servers:?}"
            );
        }

        // 4. build_default_ai_routing_rules / @ai_domains explicitly include Codex endpoints.
        let ai_rules = build_default_ai_routing_rules("AI-Codex");
        for codex_rule in [
            "DOMAIN-SUFFIX,ab.chatgpt.com,AI-Codex",
            "DOMAIN-SUFFIX,ios.chat.openai.com,AI-Codex",
            "DOMAIN-SUFFIX,api.openai.com,AI-Codex",
        ] {
            assert!(
                ai_rules.iter().any(|r| r == codex_rule),
                "build_default_ai_routing_rules missing `{codex_rule}`"
            );
            assert!(
                rules.contains(&codex_rule),
                "compiled @ai_domains rules missing `{codex_rule}`"
            );
        }
    }

    #[test]
    fn compiles_country_lite_mmdb_and_conservative_domestic_direct_rules() {
        let dir = std::env::temp_dir().join(format!(
            "catcloud-compiler-country-lite-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let cfg = AppConfig::default();
        let ports = sample_ports();
        let nodes = vec![sample_node("n1", "Node-TW-01", 443, true)];
        let empty = HashMap::new();
        let input = CompileInput {
            config: &cfg,
            nodes: &nodes,
            groups: &[],
            relays: &[],
            controller_secret: "0123456789abcdef0123456789abcdef",
            allocated_ports: &ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &empty,
        };

        // 1. country-lite.mmdb alone (geodata_mode == false) must NOT activate GeoIP rules or DNS filter
        //    because Mihomo only reads `Country.mmdb` / `country.mmdb`.
        std::fs::write(dir.join("country-lite.mmdb"), b"stub").unwrap();
        let lite_only = compile_mihomo_config_with_runtime_dir(&input, Some(&dir)).unwrap();
        assert!(lite_only.validation.ok);
        assert_eq!(
            lite_only.value["dns"]["fallback-filter"]["geoip"],
            Value::Bool(false)
        );
        let rules_no_geosite: Vec<&str> = lite_only.value["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(!rules_no_geosite.contains(&"GEOIP,CN,DIRECT,no-resolve"));

        // Unconditional private LAN / reserved CIDR / local domain / expanded domestic DNS rules.
        for expected in [
            "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
            "IP-CIDR,224.0.0.0/4,DIRECT,no-resolve",
            "IP-CIDR,255.255.255.255/32,DIRECT,no-resolve",
            "DOMAIN-SUFFIX,local,DIRECT",
            "DOMAIN-SUFFIX,localhost,DIRECT",
            "DOMAIN-SUFFIX,localdomain,DIRECT",
            "DOMAIN-SUFFIX,home.arpa,DIRECT",
            "DOMAIN-SUFFIX,lan,DIRECT",
            "DOMAIN-SUFFIX,internal,DIRECT",
            "IP-CIDR,180.184.1.1/32,DIRECT,no-resolve",
            "IP-CIDR,180.184.2.2/32,DIRECT,no-resolve",
            "IP-CIDR,1.2.4.8/32,DIRECT,no-resolve",
            "IP-CIDR,210.2.4.8/32,DIRECT,no-resolve",
            "DOMAIN,dns.pub,DIRECT",
        ] {
            assert!(
                rules_no_geosite.contains(&expected),
                "missing unconditional rule `{expected}`"
            );
        }
        // Strictly forbidden: never bypass CatCloud.exe so dashboard proxy checks stay routed via proxy.
        assert!(
            !rules_no_geosite.iter().any(|r| r.contains("CatCloud.exe")),
            "CatCloud.exe must never be added to DIRECT rules"
        );

        // Both Group A (system/download CDN) and Group B (fallback domestic sites) present without geosite.dat.
        for expected_domestic in [
            "DOMAIN-SUFFIX,msftconnecttest.com,DIRECT",
            "DOMAIN-SUFFIX,dl.delivery.mp.microsoft.com,DIRECT",
            "DOMAIN-SUFFIX,icloud.com.cn,DIRECT",
            "DOMAIN-SUFFIX,push.apple.com,DIRECT",
            "DOMAIN-SUFFIX,steamcontent.com,DIRECT",
            "DOMAIN-SUFFIX,dl.steam.clngaa.com,DIRECT",
            "DOMAIN-SUFFIX,ntp.aliyun.com,DIRECT",
            "DOMAIN-SUFFIX,gtimg.com,DIRECT",
            "DOMAIN-SUFFIX,alicdn.com,DIRECT",
            "DOMAIN-SUFFIX,bilivideo.com,DIRECT",
            "DOMAIN-SUFFIX,xiaohongshu.com,DIRECT",
            "DOMAIN-SUFFIX,npmmirror.com,DIRECT",
            "DOMAIN-SUFFIX,cainiao.com,DIRECT",
        ] {
            assert!(
                rules_no_geosite.contains(&expected_domestic),
                "missing domestic direct rule `{expected_domestic}`"
            );
        }

        // Conservative red line: overseas or hybrid root domains must NEVER appear as DIRECT rules.
        for forbidden in [
            "github.com",
            "google.com",
            "googleapis.com",
            "openai.com",
            "chatgpt.com",
            "anthropic.com",
            "claude.ai",
            "x.com",
            "twitter.com",
            "cloudflare.com",
            "microsoft.com",
            "live.com",
            "bing.com",
            "apple.com",
            "steampowered.com",
            "steamcommunity.com",
            "larksuite.com",
            "tiktok.com",
            "linux.do",
            "alibaba.com",
            "wps.com",
        ] {
            let suffix_rule = format!("DOMAIN-SUFFIX,{forbidden},DIRECT");
            let exact_rule = format!("DOMAIN,{forbidden},DIRECT");
            assert!(
                !rules_no_geosite.contains(&suffix_rule.as_str())
                    && !rules_no_geosite.contains(&exact_rule.as_str()),
                "conservative red line violated by `{forbidden}`"
            );
        }

        // 2. With geosite.dat present: Group A stays BEFORE GEOSITE,cn,DIRECT while Group B is omitted.
        std::fs::write(dir.join("geosite.dat"), b"stub").unwrap();
        let with_geosite = compile_mihomo_config_with_runtime_dir(&input, Some(&dir)).unwrap();
        let rules_with_geosite: Vec<&str> = with_geosite.value["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        let idx_steam_cdn = rules_with_geosite
            .iter()
            .position(|r| *r == "DOMAIN-SUFFIX,steamcontent.com,DIRECT")
            .expect("Group A system/CDN rule must still be emitted with geosite.dat");
        let idx_geosite_cn = rules_with_geosite
            .iter()
            .position(|r| *r == "GEOSITE,cn,DIRECT")
            .expect("GEOSITE,cn,DIRECT must be present");
        assert!(idx_steam_cdn < idx_geosite_cn);
        assert!(rules_with_geosite.contains(&"DOMAIN-SUFFIX,msftconnecttest.com,DIRECT"));
        assert!(rules_with_geosite.contains(&"DOMAIN-SUFFIX,icloud.com.cn,DIRECT"));
        assert!(!rules_with_geosite.contains(&"DOMAIN-SUFFIX,gtimg.com,DIRECT"));
        assert!(!rules_with_geosite.contains(&"DOMAIN-SUFFIX,bilivideo.com,DIRECT"));

        // 3. When domestic_direct_enabled == false, LAN & local domains remain while Groups A/B are omitted.
        let mut cfg_off = AppConfig::default();
        cfg_off.rules_override.domestic_direct_enabled = false;
        let input_off = CompileInput {
            config: &cfg_off,
            ..input
        };
        let off_compiled = compile_mihomo_config_with_runtime_dir(&input_off, Some(&dir)).unwrap();
        let rules_off: Vec<&str> = off_compiled.value["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(rules_off.contains(&"IP-CIDR,100.64.0.0/10,DIRECT,no-resolve"));
        assert!(rules_off.contains(&"DOMAIN-SUFFIX,local,DIRECT"));
        assert!(rules_off.contains(&"DOMAIN-SUFFIX,home.arpa,DIRECT"));
        assert!(!rules_off.contains(&"DOMAIN-SUFFIX,steamcontent.com,DIRECT"));
        assert!(!rules_off.contains(&"GEOSITE,cn,DIRECT"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prunes_inactive_nodes_when_over_32_and_honors_compile_all_nodes_and_memory_tunings() {
        let mut nodes: Vec<ProxyNode> = Vec::with_capacity(40);
        for i in 0..40 {
            let id = format!("n-{i:02}");
            let name = format!("Node-{i:02}");
            let host = format!("node-{i:02}.provider.test");
            let mut n = sample_node(&id, &name, 443, true);
            n.server = host.clone();
            n.raw_config = serde_json::json!({
                "name": name,
                "type": "trojan",
                "server": host,
                "port": 443,
                "password": "demo-password",
                "udp": true
            });
            nodes.push(n);
        }

        let g_active = MultiGroup {
            id: "g-tw".to_string(),
            name: "TW-Active".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec!["n-00".into(), "n-01".into(), "n-02".into(), "n-03".into()],
            active_node_id: Some("n-01".to_string()),
            ..Default::default()
        };
        let g_idle = MultiGroup {
            id: "g-idle".to_string(),
            name: "Idle-Group".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec!["n-10".into(), "n-11".into(), "n-12".into()],
            independent_routing: false,
            ..Default::default()
        };
        let g_independent = MultiGroup {
            id: "g-ai".to_string(),
            name: "AI-Split".to_string(),
            mode: MultiGroupMode::StickyBest,
            match_rules: vec!["DOMAIN-SUFFIX,openai.com".to_string()],
            member_node_ids: vec!["n-04".into(), "n-05".into()],
            fallback_pool_id: Some("g-backup".to_string()),
            independent_routing: true,
            ..Default::default()
        };
        let g_backup = MultiGroup {
            id: "g-backup".to_string(),
            name: "AI-Backup".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec!["n-06".into()],
            independent_routing: false,
            ..Default::default()
        };

        let ports = sample_ports();
        let empty = HashMap::new();

        // 1. Pure active group (4 members out of 40 nodes) -> compiles strictly 4 proxies.
        let mut cfg_simple = AppConfig::default();
        cfg_simple.active_group_id = Some("g-tw".to_string());
        let simple_groups = vec![g_active.clone(), g_idle.clone()];
        let compiled_4 = compile_mihomo_config(&CompileInput {
            config: &cfg_simple,
            nodes: &nodes,
            groups: &simple_groups,
            relays: &[],
            controller_secret: "0123456789abcdef0123456789abcdef",
            allocated_ports: &ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &empty,
        })
        .expect("pruned 4-node compile must succeed");
        assert!(compiled_4.validation.ok);
        assert_eq!(compiled_4.stats.total_proxies, 4);
        assert_eq!(compiled_4.value["proxies"].as_sequence().unwrap().len(), 4);

        // Unconditional memory tunings: geodata-loader=memconservative even when geodata_mode=false,
        // keep-alive-idle=15, keep-alive-interval=15; when GeoIP is absent while domestic_direct_enabled=true,
        // QUIC sniffer stays enabled so domestic IM UDP/443 can match DOMAIN-SUFFIX DIRECT before REJECT.
        assert_eq!(compiled_4.value["geodata-mode"], Value::Bool(false));
        assert_eq!(compiled_4.value["geodata-loader"], "memconservative");
        assert_eq!(compiled_4.value["keep-alive-idle"], 15);
        assert_eq!(compiled_4.value["keep-alive-interval"], 15);
        assert!(compiled_4.value["sniffer"]["sniff"].get("QUIC").is_some());
        assert!(compiled_4.value["sniffer"]["sniff"].get("TLS").is_some());

        // fake-ip-filter only includes domains of compiled active nodes, not pruned nodes.
        let fake_filters: Vec<&str> = compiled_4.value["dns"]["fake-ip-filter"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(fake_filters.contains(&"node-00.provider.test"));
        assert!(fake_filters.contains(&"node-03.provider.test"));
        assert!(!fake_filters.contains(&"node-10.provider.test"));
        assert!(!fake_filters.contains(&"node-39.provider.test"));

        // 2. Active group + independent_routing group + transitive fallback_pool_id group -> 7 nodes.
        let rich_groups = vec![g_active.clone(), g_idle.clone(), g_independent, g_backup];
        let compiled_7 = compile_mihomo_config(&CompileInput {
            config: &cfg_simple,
            nodes: &nodes,
            groups: &rich_groups,
            relays: &[],
            controller_secret: "0123456789abcdef0123456789abcdef",
            allocated_ports: &ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &empty,
        })
        .expect("pruned 7-node compile must succeed");
        assert!(compiled_7.validation.ok);
        assert_eq!(compiled_7.stats.total_proxies, 7);
        let pg_names: Vec<&str> = compiled_7.value["proxy-groups"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(|g| g["name"].as_str())
            .collect();
        assert!(pg_names.contains(&"TW-Active"));
        assert!(pg_names.contains(&"AI-Split"));
        assert!(pg_names.contains(&"AI-Backup"));
        assert!(!pg_names.contains(&"Idle-Group"));

        // 3. compile_all_nodes == true compiles all 40 nodes (and block_quic_udp_443 == false keeps QUIC sniffer).
        let mut cfg_all = cfg_simple.clone();
        cfg_all.core_runtime.compile_all_nodes = true;
        cfg_all.rules_override.block_quic_udp_443 = false;
        let compiled_all = compile_mihomo_config(&CompileInput {
            config: &cfg_all,
            nodes: &nodes,
            groups: &simple_groups,
            relays: &[],
            controller_secret: "0123456789abcdef0123456789abcdef",
            allocated_ports: &ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &empty,
        })
        .expect("compile_all_nodes=true must succeed");
        assert_eq!(compiled_all.stats.total_proxies, 40);
        assert!(compiled_all.value["sniffer"]["sniff"].get("QUIC").is_some());

        // 4. ProxyMode::Global compiles all 40 nodes even when compile_all_nodes == false.
        let mut cfg_global = cfg_simple.clone();
        cfg_global.proxy_mode = ProxyMode::Global;
        let compiled_global = compile_mihomo_config(&CompileInput {
            config: &cfg_global,
            nodes: &nodes,
            groups: &simple_groups,
            relays: &[],
            controller_secret: "0123456789abcdef0123456789abcdef",
            allocated_ports: &ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &empty,
        })
        .expect("global mode compile must succeed");
        assert_eq!(compiled_global.stats.total_proxies, 40);

        // 5. Single route mode prunes down to only the selected single node.
        let mut cfg_single = cfg_simple.clone();
        cfg_single.route_mode = RouteTargetMode::Single;
        cfg_single.active_single_node_id = Some("n-15".to_string());
        let compiled_single = compile_mihomo_config(&CompileInput {
            config: &cfg_single,
            nodes: &nodes,
            groups: &simple_groups,
            relays: &[],
            controller_secret: "0123456789abcdef0123456789abcdef",
            allocated_ports: &ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &empty,
        })
        .expect("pruned single mode compile must succeed");
        assert!(compiled_single.validation.ok);
        assert_eq!(compiled_single.stats.total_proxies, 1);
        assert_eq!(
            compiled_single.value["proxies"][0]["name"].as_str(),
            Some("Node-15")
        );

        // 6. Empty active reference set falls back safely to compiling all 40 enabled nodes.
        let compiled_fallback = compile_mihomo_config(&CompileInput {
            config: &cfg_simple,
            nodes: &nodes,
            groups: &[],
            relays: &[],
            controller_secret: "0123456789abcdef0123456789abcdef",
            allocated_ports: &ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &empty,
        })
        .expect("empty ref fallback compile must succeed");
        assert_eq!(compiled_fallback.stats.total_proxies, 40);
    }

    #[test]
    fn extract_mihomo_rule_target_and_static_validator_catch_unknown_rule_targets() {
        // Blank, comment, built-in actions, and SUB-RULE return None.
        assert_eq!(extract_mihomo_rule_target(""), None);
        assert_eq!(extract_mihomo_rule_target("   "), None);
        assert_eq!(extract_mihomo_rule_target("# DOMAIN-SUFFIX,openai.com,AI-Group"), None);
        assert_eq!(extract_mihomo_rule_target("DOMAIN-SUFFIX,cn,DIRECT"), None);
        assert_eq!(extract_mihomo_rule_target("DOMAIN-SUFFIX,cn,direct"), None);
        assert_eq!(extract_mihomo_rule_target("DOMAIN,ad.example,REJECT"), None);
        assert_eq!(extract_mihomo_rule_target("DOMAIN,ad.example,reject-drop"), None);
        assert_eq!(extract_mihomo_rule_target("DOMAIN,ok.example,PASS"), None);
        assert_eq!(extract_mihomo_rule_target("DOMAIN,ok.example,compatible"), None);
        assert_eq!(
            extract_mihomo_rule_target("AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"),
            None
        );
        assert_eq!(
            extract_mihomo_rule_target("SUB-RULE,((DOMAIN,example.com)),sub-chain"),
            None
        );
        assert_eq!(
            extract_mihomo_rule_target("IP-CIDR,198.51.100.0/24,no-resolve"),
            None
        );

        // Standard, flag-suffixed, logical, and MATCH rules extract custom targets accurately.
        assert_eq!(
            extract_mihomo_rule_target("MATCH, AI-Group "),
            Some("AI-Group")
        );
        assert_eq!(
            extract_mihomo_rule_target("DOMAIN-SUFFIX, openai.com , AI-Group"),
            Some("AI-Group")
        );
        assert_eq!(
            extract_mihomo_rule_target("IP-CIDR,198.51.100.0/24,AI-Group,no-resolve"),
            Some("AI-Group")
        );
        assert_eq!(
            extract_mihomo_rule_target("IP-CIDR,198.51.100.0/24,AI-Group,src"),
            Some("AI-Group")
        );
        assert_eq!(
            extract_mihomo_rule_target("IP-CIDR,198.51.100.0/24,AI-Group,no-resolve,src"),
            Some("AI-Group")
        );
        assert_eq!(
            extract_mihomo_rule_target("AND,((NETWORK,TCP),(DST-PORT,443)),AI-Group"),
            Some("AI-Group")
        );

        // Static validator rejects rules referencing missing proxy-groups while accepting proxies,
        // proxy-groups, and built-in actions.
        let yaml_with_missing_target = r#"
proxies:
  - name: Node-1
    type: trojan
    server: 203.0.113.55
    port: 443
    password: demo
proxy-groups:
  - name: Main-Group
    type: select
    proxies:
      - Node-1
rules:
  - DOMAIN-SUFFIX,openai.com,Missing-Group
  - IP-CIDR,198.51.100.0/24,Node-1,no-resolve
  - DOMAIN,ads.example,REJECT-DROP
  - MATCH,Main-Group
"#;
        let report_bad = validate_compiled_yaml(yaml_with_missing_target, &[]).unwrap();
        assert!(!report_bad.ok);
        let unknown_errors: Vec<&StaticCheckIssue> = report_bad
            .errors()
            .into_iter()
            .filter(|i| i.code == "unknown_rule_target")
            .collect();
        assert_eq!(unknown_errors.len(), 1);
        assert!(unknown_errors[0].message.contains("Missing-Group"));

        let yaml_valid = r#"
proxies:
  - name: Node-1
    type: trojan
    server: 203.0.113.55
    port: 443
    password: demo
proxy-groups:
  - name: Main-Group
    type: select
    proxies:
      - Node-1
rules:
  - IP-CIDR,198.51.100.0/24,Node-1,no-resolve
  - DOMAIN,ads.example,REJECT-DROP
  - DOMAIN,pass.example,PASS
  - DOMAIN,compat.example,COMPATIBLE
  - MATCH,Main-Group
"#;
        let report_ok = validate_compiled_yaml(yaml_valid, &[]).unwrap();
        assert!(report_ok.ok, "unexpected issues: {:?}", report_ok.issues);
    }

    #[test]
    fn prunes_over_32_nodes_retains_global_rule_referenced_groups_in_single_and_group_modes() {
        let mut nodes: Vec<ProxyNode> = Vec::with_capacity(40);
        for i in 0..40 {
            let id = format!("n-{i:02}");
            let name = format!("Node-{i:02}");
            let host = format!("node-{i:02}.provider.test");
            let mut n = sample_node(&id, &name, 443, true);
            n.server = host.clone();
            let mut raw = serde_json::json!({
                "name": name,
                "type": "trojan",
                "server": host,
                "port": 443,
                "password": "demo-password",
                "udp": true
            });
            // Chain n-04 onto n-20 via dialer-proxy to verify transitive node dependencies stay intact.
            if i == 4 {
                raw["dialer-proxy"] = serde_json::Value::String("Node-20".to_string());
            }
            n.raw_config = raw;
            nodes.push(n);
        }

        let g_main_a = MultiGroup {
            id: "g-a".to_string(),
            name: "Main-A".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec!["n-00".into(), "n-01".into(), "n-02".into(), "n-03".into()],
            active_node_id: Some("n-00".to_string()),
            independent_routing: false,
            ..Default::default()
        };
        let g_ai_b = MultiGroup {
            id: "g-b".to_string(),
            name: "AI-Target-B".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec!["n-04".into(), "n-05".into()],
            fallback_pool_id: Some("g-b-fb".to_string()),
            independent_routing: false,
            ..Default::default()
        };
        let g_ai_b_fb = MultiGroup {
            id: "g-b-fb".to_string(),
            name: "AI-Backup-B".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec!["n-06".into()],
            independent_routing: false,
            ..Default::default()
        };
        let g_extra_c = MultiGroup {
            id: "g-c".to_string(),
            name: "Extra-Target-C".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec!["n-10".into(), "n-11".into()],
            independent_routing: false,
            ..Default::default()
        };
        let g_idle = MultiGroup {
            id: "g-idle".to_string(),
            name: "Unused-Idle".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec!["n-30".into(), "n-31".into()],
            independent_routing: false,
            ..Default::default()
        };

        let groups = vec![g_main_a, g_ai_b, g_ai_b_fb, g_extra_c, g_idle];
        let ports = sample_ports();
        let empty = HashMap::new();

        // 1. >32 nodes + !compile_all_nodes + Single mode + global_prepend_rules targeting AI-Target-B:
        //    must retain AI-Target-B, its fallback AI-Backup-B, their members, chained dialer Node-20,
        //    and selected single node Node-15, while pruning unrelated groups and passing validation.
        let mut cfg_single = AppConfig::default();
        cfg_single.proxy_mode = ProxyMode::Rule;
        cfg_single.core_runtime.compile_all_nodes = false;
        cfg_single.route_mode = RouteTargetMode::Single;
        cfg_single.active_single_node_id = Some("n-15".to_string());
        cfg_single.rules_override.global_prepend_rules = vec![
            "# user AI preset".to_string(),
            "DOMAIN,node-20.provider.test,DIRECT".to_string(),
            "DOMAIN-SUFFIX,openai.com,AI-Target-B".to_string(),
            "IP-CIDR,198.51.100.0/24,AI-Target-B,no-resolve".to_string(),
        ];

        let compiled_single = compile_mihomo_config(&CompileInput {
            config: &cfg_single,
            nodes: &nodes,
            groups: &groups,
            relays: &[],
            controller_secret: "0123456789abcdef0123456789abcdef",
            allocated_ports: &ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &empty,
        })
        .expect("single mode with global_prepend_rules group ref must compile");
        assert!(
            compiled_single.validation.ok,
            "single mode validation failed: {:?}",
            compiled_single.validation.issues
        );

        let single_pg_names: Vec<&str> = compiled_single.value["proxy-groups"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(|g| g["name"].as_str())
            .collect();
        assert!(single_pg_names.contains(&SINGLE_NODE_GROUP_NAME));
        assert!(single_pg_names.contains(&"AI-Target-B"));
        assert!(single_pg_names.contains(&"AI-Backup-B"));
        assert!(!single_pg_names.contains(&"Main-A"));
        assert!(!single_pg_names.contains(&"Extra-Target-C"));
        assert!(!single_pg_names.contains(&"Unused-Idle"));

        let single_proxy_names: Vec<&str> = compiled_single.value["proxies"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(|p| p["name"].as_str())
            .collect();
        assert_eq!(single_proxy_names.len(), 5);
        for expected in ["Node-04", "Node-05", "Node-06", "Node-15", "Node-20"] {
            assert!(
                single_proxy_names.contains(&expected),
                "missing expected proxy `{expected}` in {single_proxy_names:?}"
            );
        }
        assert!(!single_proxy_names.contains(&"Node-00"));
        assert!(!single_proxy_names.contains(&"Node-30"));

        // 2. >32 nodes + !compile_all_nodes + Group mode switched to Main-A + global_append_rules
        //    targeting inactive AI-Target-B + extra_prepend_rules targeting inactive Extra-Target-C:
        //    must retain Main-A, AI-Target-B, AI-Backup-B, Extra-Target-C and all their members.
        let mut cfg_group = AppConfig::default();
        cfg_group.proxy_mode = ProxyMode::Rule;
        cfg_group.core_runtime.compile_all_nodes = false;
        cfg_group.route_mode = RouteTargetMode::Group;
        cfg_group.active_group_id = Some("g-a".to_string());
        cfg_group.rules_override.global_prepend_rules =
            vec!["DOMAIN,node-20.provider.test,DIRECT".to_string()];
        cfg_group.rules_override.global_append_rules =
            vec!["DOMAIN-SUFFIX,claude.ai,AI-Target-B".to_string()];
        let extra_rules = vec!["IP-CIDR,203.0.113.0/24,Extra-Target-C,no-resolve".to_string()];

        let compiled_group = compile_mihomo_config(&CompileInput {
            config: &cfg_group,
            nodes: &nodes,
            groups: &groups,
            relays: &[],
            controller_secret: "0123456789abcdef0123456789abcdef",
            allocated_ports: &ports,
            extra_prepend_rules: &extra_rules,
            extra_fake_ip_filters: &[],
            group_filtered_members: &empty,
        })
        .expect("group mode with global_append_rules & extra_prepend_rules must compile");
        assert!(
            compiled_group.validation.ok,
            "group mode validation failed: {:?}",
            compiled_group.validation.issues
        );

        let group_pg_names: Vec<&str> = compiled_group.value["proxy-groups"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(|g| g["name"].as_str())
            .collect();
        assert!(group_pg_names.contains(&"Main-A"));
        assert!(group_pg_names.contains(&"AI-Target-B"));
        assert!(group_pg_names.contains(&"AI-Backup-B"));
        assert!(group_pg_names.contains(&"Extra-Target-C"));
        assert!(!group_pg_names.contains(&"Unused-Idle"));

        let group_proxy_names: Vec<&str> = compiled_group.value["proxies"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(|p| p["name"].as_str())
            .collect();
        assert_eq!(group_proxy_names.len(), 10);
        for expected in [
            "Node-00", "Node-01", "Node-02", "Node-03", "Node-04", "Node-05", "Node-06", "Node-10",
            "Node-11", "Node-20",
        ] {
            assert!(
                group_proxy_names.contains(&expected),
                "missing expected proxy `{expected}` in {group_proxy_names:?}"
            );
        }
        assert!(!group_proxy_names.contains(&"Node-30"));
    }

    #[test]
    fn country_lite_mmdb_alone_does_not_enable_geoip_cn() {
        let dir = std::env::temp_dir().join(format!(
            "catcloud-compiler-mmdb-regression-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let cfg = AppConfig::default();
        let ports = sample_ports();
        let nodes = vec![sample_node("n1", "Node-TW-01", 443, true)];
        let empty = HashMap::new();
        let input = CompileInput {
            config: &cfg,
            nodes: &nodes,
            groups: &[],
            relays: &[],
            controller_secret: "0123456789abcdef0123456789abcdef",
            allocated_ports: &ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &empty,
        };

        // 1. Only `country-lite.mmdb` present -> Mihomo will not load it as `Country.mmdb`,
        //    so `GEOIP,CN` and `fallback-filter.geoip` must stay disabled.
        std::fs::write(dir.join("country-lite.mmdb"), b"stub").unwrap();
        let compiled_lite = compile_mihomo_config_with_runtime_dir(&input, Some(&dir)).unwrap();
        assert!(compiled_lite.validation.ok);
        assert_eq!(
            compiled_lite.value["dns"]["fallback-filter"]["geoip"],
            Value::Bool(false)
        );
        let rules_lite: Vec<&str> = compiled_lite.value["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(!rules_lite.contains(&"GEOIP,CN,DIRECT,no-resolve"));

        // 2. Lowercase `country.mmdb` enables GeoIP cleanly.
        std::fs::write(dir.join("country.mmdb"), b"stub").unwrap();
        let compiled_lower = compile_mihomo_config_with_runtime_dir(&input, Some(&dir)).unwrap();
        assert!(compiled_lower.validation.ok);
        assert_eq!(
            compiled_lower.value["dns"]["fallback-filter"]["geoip"],
            Value::Bool(true)
        );
        let rules_lower: Vec<&str> = compiled_lower.value["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(rules_lower.contains(&"GEOIP,CN,DIRECT,no-resolve"));

        // 3. Canonical `Country.mmdb` enables GeoIP cleanly.
        let _ = std::fs::remove_file(dir.join("country.mmdb"));
        std::fs::write(dir.join("Country.mmdb"), b"stub").unwrap();
        let compiled_upper = compile_mihomo_config_with_runtime_dir(&input, Some(&dir)).unwrap();
        assert!(compiled_upper.validation.ok);
        assert_eq!(
            compiled_upper.value["dns"]["fallback-filter"]["geoip"],
            Value::Bool(true)
        );
        let rules_upper: Vec<&str> = compiled_upper.value["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(rules_upper.contains(&"GEOIP,CN,DIRECT,no-resolve"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn should_emit_tun_device_name_enforces_macos_utun_naming_and_allows_windows_linux() {
        assert!(!should_emit_tun_device_name("macos", "CatCloud"));
        assert!(!should_emit_tun_device_name("macos", "utun_bad"));
        assert!(!should_emit_tun_device_name("macos", "   "));
        assert!(should_emit_tun_device_name("macos", "utun9"));
        assert!(should_emit_tun_device_name("macos", "utun"));
        assert!(should_emit_tun_device_name("macos", "utun12"));

        assert!(should_emit_tun_device_name("windows", "CatCloud"));
        assert!(should_emit_tun_device_name("windows", "utun9"));
        assert!(should_emit_tun_device_name("linux", "CatCloud"));
        assert!(should_emit_tun_device_name("linux", "catcloud0"));
        assert!(!should_emit_tun_device_name("windows", ""));
        assert!(!should_emit_tun_device_name("linux", "  "));

        let mut cfg = AppConfig::default();
        cfg.tun.enabled = true;
        cfg.tun.device_name = "CatCloud".to_string();
        let tun_map = build_tun_section(&cfg);
        if cfg!(target_os = "macos") {
            assert!(tun_map.get("device").is_none());
        } else {
            assert_eq!(tun_map.get("device").and_then(Value::as_str), Some("CatCloud"));
        }

        cfg.tun.device_name = "utun9".to_string();
        let tun_utun = build_tun_section(&cfg);
        assert_eq!(tun_utun.get("device").and_then(Value::as_str), Some("utun9"));
    }

    #[test]
    fn conservative_domestic_direct_includes_system_push_notification_domains() {
        let dir = std::env::temp_dir().join(format!(
            "catcloud-compiler-push-direct-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let cfg = AppConfig::default();
        let ports = sample_ports();
        let nodes = vec![sample_node("n1", "Node-JP-01", 443, true)];
        let empty = HashMap::new();
        let input = CompileInput {
            config: &cfg,
            nodes: &nodes,
            groups: &[],
            relays: &[],
            controller_secret: "0123456789abcdef0123456789abcdef",
            allocated_ports: &ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &empty,
        };

        // Always emitted even without geosite.dat.
        let without_geosite = compile_mihomo_config_with_runtime_dir(&input, Some(&dir)).unwrap();
        assert!(without_geosite.validation.ok);
        let rules_no_geo: Vec<&str> = without_geosite.value["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        for domain in ["wns.windows.com", "notify.windows.com", "push.apple.com"] {
            let expected = format!("DOMAIN-SUFFIX,{domain},DIRECT");
            assert!(
                rules_no_geo.contains(&expected.as_str()),
                "missing conservative system push direct rule `{expected}`"
            );
        }

        // Still emitted ahead of GEOSITE,cn,DIRECT when geosite.dat is present.
        std::fs::write(dir.join("geosite.dat"), b"stub").unwrap();
        let with_geosite = compile_mihomo_config_with_runtime_dir(&input, Some(&dir)).unwrap();
        let rules_with_geo: Vec<&str> = with_geosite.value["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        let idx_geosite = rules_with_geo
            .iter()
            .position(|r| *r == "GEOSITE,cn,DIRECT")
            .expect("GEOSITE,cn,DIRECT must exist");
        for domain in ["wns.windows.com", "notify.windows.com", "push.apple.com"] {
            let expected = format!("DOMAIN-SUFFIX,{domain},DIRECT");
            let idx = rules_with_geo
                .iter()
                .position(|r| *r == expected)
                .unwrap_or_else(|| panic!("missing `{expected}` with geosite.dat"));
            assert!(idx < idx_geosite);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn allows_domestic_quic_udp_443_before_reject_and_always_adds_qq_fake_ip_filters() {
        let dir = std::env::temp_dir().join(format!(
            "catcloud-compiler-domestic-quic-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let cfg = AppConfig::default();
        let ports = sample_ports();
        let nodes = vec![sample_node("n1", "Node-JP-01", 443, true)];
        let group = MultiGroup {
            id: "g-ai".to_string(),
            name: "AI-Group".to_string(),
            match_rules: vec!["DOMAIN-SUFFIX,openai.com".to_string()],
            member_node_ids: vec!["n1".to_string()],
            ..Default::default()
        };
        let empty = HashMap::new();
        let input = CompileInput {
            config: &cfg,
            nodes: &nodes,
            groups: &[group],
            relays: &[],
            controller_secret: "0123456789abcdef0123456789abcdef",
            allocated_ports: &ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &empty,
        };

        // 1. Without geosite/geoip files: domain-based domestic QUIC DIRECT rules precede QUIC REJECT,
        //    which still precedes group match rules; GEOSITE/GEOIP QUIC rules stay absent.
        let no_geo = compile_mihomo_config_with_runtime_dir(&input, Some(&dir)).unwrap();
        assert!(no_geo.validation.ok, "issues: {:?}", no_geo.validation.issues);
        let rules_no_geo: Vec<&str> = no_geo.value["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        let idx_reject = rules_no_geo
            .iter()
            .position(|r| *r == "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT")
            .expect("QUIC reject rule");
        let idx_group = rules_no_geo
            .iter()
            .position(|r| *r == "DOMAIN-SUFFIX,openai.com,AI-Group")
            .expect("group match rule");
        assert!(idx_reject < idx_group);
        for domain in [
            "cn",
            "qq.com",
            "qpic.cn",
            "qlogo.cn",
            "gtimg.cn",
            "gtimg.com",
            "weixin.qq.com",
            "tencent.com",
            "bilibili.com",
            "bilivideo.com",
            "bilivideo.cn",
        ] {
            let expected =
                format!("AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,{domain})),DIRECT");
            let idx = rules_no_geo
                .iter()
                .position(|r| *r == expected)
                .unwrap_or_else(|| panic!("missing domestic QUIC allow rule `{expected}`"));
            assert!(idx < idx_reject, "`{expected}` must precede QUIC REJECT");
        }
        assert!(
            !rules_no_geo.contains(&"AND,((NETWORK,UDP),(DST-PORT,443),(GEOSITE,cn)),DIRECT")
        );
        assert!(
            !rules_no_geo
                .contains(&"AND,((NETWORK,UDP),(DST-PORT,443),(GEOIP,CN,no-resolve)),DIRECT")
        );

        // Unconditional QQ/WeChat/Tencent Cloud fake-ip-filter entries must always be present.
        let fake_filters: Vec<&str> = no_geo.value["dns"]["fake-ip-filter"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        for pattern in [
            "+.qq.com",
            "+.qpic.cn",
            "+.qlogo.cn",
            "+.gtimg.cn",
            "+.gtimg.com",
            "+.nt.qq.com.cn",
            "+.weixin.qq.com",
            "+.tencent.com",
            "+.qcloud.com",
            "+.myqcloud.com",
        ] {
            assert!(
                fake_filters.contains(&pattern),
                "missing unconditional fake-ip-filter `{pattern}`"
            );
        }

        // 2. With geosite.dat + Country.mmdb: both GEOSITE & GEOIP domestic QUIC DIRECT rules precede REJECT.
        std::fs::write(dir.join("geosite.dat"), b"stub").unwrap();
        std::fs::write(dir.join("Country.mmdb"), b"stub").unwrap();
        let with_geo = compile_mihomo_config_with_runtime_dir(&input, Some(&dir)).unwrap();
        assert!(with_geo.validation.ok, "issues: {:?}", with_geo.validation.issues);
        let rules_geo: Vec<&str> = with_geo.value["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        let idx_reject_geo = rules_geo
            .iter()
            .position(|r| *r == "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT")
            .expect("QUIC reject rule");
        let idx_geosite_quic = rules_geo
            .iter()
            .position(|r| *r == "AND,((NETWORK,UDP),(DST-PORT,443),(GEOSITE,cn)),DIRECT")
            .expect("GEOSITE cn QUIC allow rule");
        let idx_geoip_quic = rules_geo
            .iter()
            .position(|r| *r == "AND,((NETWORK,UDP),(DST-PORT,443),(GEOIP,CN,no-resolve)),DIRECT")
            .expect("GEOIP CN QUIC allow rule");
        assert!(idx_geosite_quic < idx_reject_geo);
        assert!(idx_geoip_quic < idx_reject_geo);

        // 3. When domestic_direct_enabled == false, domestic QUIC allow rules are omitted while REJECT stays.
        let mut cfg_no_dom = AppConfig::default();
        cfg_no_dom.rules_override.domestic_direct_enabled = false;
        let no_dom = compile_mihomo_config_with_runtime_dir(
            &CompileInput {
                config: &cfg_no_dom,
                ..input
            },
            Some(&dir),
        )
        .unwrap();
        let rules_no_dom: Vec<&str> = no_dom.value["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(rules_no_dom.contains(&"AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"));
        assert!(
            !rules_no_dom
                .contains(&"AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,qq.com)),DIRECT")
        );
        assert!(
            !rules_no_dom.contains(&"AND,((NETWORK,UDP),(DST-PORT,443),(GEOSITE,cn)),DIRECT")
        );

        // 4. `build_node_proxy_mapping` is public and produces valid proxy mapping.
        let mapped = build_node_proxy_mapping(&nodes[0], "Share-Node-01").expect("public mapping");
        assert_eq!(mapped.get("name").and_then(Value::as_str), Some("Share-Node-01"));
        assert_eq!(mapped.get("type").and_then(Value::as_str), Some("trojan"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keeps_quic_sniffer_when_geoip_missing_and_omits_when_geoip_present_or_domestic_disabled() {
        let dir = std::env::temp_dir().join(format!(
            "catcloud-compiler-quic-sniffer-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let nodes = vec![sample_node("n1", "JP-Edge-01", 443, true)];
        let groups = vec![MultiGroup {
            id: "grp-main".to_string(),
            name: "Main-Group".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec!["n1".into()],
            ..Default::default()
        }];
        let ports = sample_ports();
        let empty = HashMap::new();

        // 1. Missing Country.mmdb (has_geoip = false) with block_quic_udp_443 = true and
        //    domestic_direct_enabled = true MUST retain QUIC sniffer so domestic IM packets
        //    carrying real IPs can still extract SNI and hit DOMAIN-SUFFIX DIRECT rules.
        let mut cfg = AppConfig::default();
        cfg.rules_override.block_quic_udp_443 = true;
        cfg.rules_override.domestic_direct_enabled = true;
        let input = CompileInput {
            config: &cfg,
            nodes: &nodes,
            groups: &groups,
            relays: &[],
            controller_secret: "0123456789abcdef0123456789abcdef",
            allocated_ports: &ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &empty,
        };
        let without_geoip = compile_mihomo_config_with_runtime_dir(&input, Some(&dir)).unwrap();
        assert!(
            without_geoip.value["sniffer"]["sniff"].get("QUIC").is_some(),
            "QUIC sniffer must remain enabled when Country.mmdb is absent"
        );

        // 2. When domestic_direct_enabled = false and block_quic_udp_443 = true, QUIC sniffer is omitted.
        let mut cfg_no_dom = cfg.clone();
        cfg_no_dom.rules_override.domestic_direct_enabled = false;
        let no_dom = compile_mihomo_config_with_runtime_dir(
            &CompileInput {
                config: &cfg_no_dom,
                ..input
            },
            Some(&dir),
        )
        .unwrap();
        assert!(no_dom.value["sniffer"]["sniff"].get("QUIC").is_none());

        // 3. Once Country.mmdb exists (has_geoip = true), GEOIP,CN protects domestic QUIC and
        //    QUIC sniffer can be omitted when block_quic_udp_443 = true.
        std::fs::write(dir.join("Country.mmdb"), b"stub").unwrap();
        let with_geoip = compile_mihomo_config_with_runtime_dir(&input, Some(&dir)).unwrap();
        assert!(with_geoip.value["sniffer"]["sniff"].get("QUIC").is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn campus_network_dns_defaults_fallbacks_and_intranet_system_policy() {
        let ports = sample_ports();
        let nodes = vec![sample_node("n1", "JP-Edge-01", 443, true)];
        let empty = HashMap::new();

        // 1. Default config compiles pure-IP DoH 443 across default/direct/proxy-server
        //    nameservers and injects `system` policy for campus/LAN suffixes + campus_direct_domains.
        let mut cfg = AppConfig::default();
        cfg.preaccel.campus_direct_domains = vec![
            "portal.campus.example.org".to_string(),
            "*.intranet.example.org".to_string(),
            "DOMAIN-SUFFIX,rule-campus.example.org,DIRECT".to_string(),
            "DOMAIN,auth.campus.example.org,DIRECT".to_string(),
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve".to_string(), // non-domain rule must not pollute DNS policy
            "172.28.255.155".to_string(), // IP must be ignored by nameserver-policy
        ];
        cfg.dns.nameserver_policy.insert(
            "+.lan".to_string(),
            vec!["10.0.0.53".to_string()], // User custom policy must never be overwritten
        );

        let compiled = compile_mihomo_config(&CompileInput {
            config: &cfg,
            nodes: &nodes,
            groups: &[],
            relays: &[],
            controller_secret: "0123456789abcdef0123456789abcdef",
            allocated_ports: &ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &empty,
        })
        .expect("compile default campus-safe dns");

        let seq_to_vec = |v: &Value| -> Vec<String> {
            v.as_sequence()
                .unwrap()
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect()
        };

        let expected_doh = vec![
            "https://223.5.5.5/dns-query".to_string(),
            "https://1.12.12.12/dns-query".to_string(),
        ];
        let expected_doh_direct = vec![
            "https://223.5.5.5/dns-query#DIRECT".to_string(),
            "https://1.12.12.12/dns-query#DIRECT".to_string(),
        ];

        assert_eq!(seq_to_vec(&compiled.value["dns"]["default-nameserver"]), expected_doh);
        assert_eq!(seq_to_vec(&compiled.value["dns"]["direct-nameserver"]), expected_doh_direct);
        assert_eq!(
            seq_to_vec(&compiled.value["dns"]["proxy-server-nameserver"]),
            expected_doh
        );

        let policy = &compiled.value["dns"]["nameserver-policy"];
        let expected_campus_policy = vec![
            "system".to_string(),
            "https://223.5.5.5/dns-query#DIRECT".to_string(),
        ];
        for key in [
            "+.edu.cn",
            "+.local",
            "+.localdomain",
            "+.internal",
            "+.home.arpa",
            "portal.campus.example.org",
            "+.intranet.example.org",
            "+.rule-campus.example.org",
            "auth.campus.example.org",
        ] {
            assert_eq!(
                seq_to_vec(&policy[key]),
                expected_campus_policy,
                "unexpected nameserver-policy for `{key}`"
            );
        }
        // User-defined `+.lan` takes precedence; raw IP and non-domain/comma rules are excluded.
        assert_eq!(seq_to_vec(&policy["+.lan"]), vec!["10.0.0.53".to_string()]);
        assert!(policy.get("172.28.255.155").is_none());
        assert!(policy.get("ip-cidr,10.0.0.0/8,direct,no-resolve").is_none());
        assert!(policy.get("domain-suffix,rule-campus.example.org,direct").is_none());

        // 2. Empty arrays & legacy plaintext default_nameserver fall back to pure-IP DoH 443.
        let mut cfg_empty = AppConfig::default();
        cfg_empty.dns.respect_rules = true;
        cfg_empty.dns.default_nameserver = vec!["223.5.5.5".to_string(), "119.29.29.29".to_string()];
        cfg_empty.dns.direct_nameserver.clear();
        cfg_empty.dns.proxy_server_nameserver.clear();
        let compiled_legacy_fallback = compile_mihomo_config(&CompileInput {
            config: &cfg_empty,
            nodes: &nodes,
            groups: &[],
            relays: &[],
            controller_secret: "0123456789abcdef0123456789abcdef",
            allocated_ports: &ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &empty,
        })
        .expect("compile legacy fallback");
        assert_eq!(
            seq_to_vec(&compiled_legacy_fallback.value["dns"]["direct-nameserver"]),
            expected_doh_direct
        );
        assert_eq!(
            seq_to_vec(&compiled_legacy_fallback.value["dns"]["proxy-server-nameserver"]),
            expected_doh
        );

        // 3. Empty default_nameserver gets DoH 443 fallback; custom non-legacy default_nameserver
        //    is reused by empty proxy-server-nameserver without appending `#DIRECT`.
        let mut cfg_custom_default = AppConfig::default();
        cfg_custom_default.dns.respect_rules = true;
        cfg_custom_default.dns.default_nameserver = vec!["https://1.12.12.12/dns-query".to_string()];
        cfg_custom_default.dns.proxy_server_nameserver.clear();
        let compiled_custom_default = compile_mihomo_config(&CompileInput {
            config: &cfg_custom_default,
            nodes: &nodes,
            groups: &[],
            relays: &[],
            controller_secret: "0123456789abcdef0123456789abcdef",
            allocated_ports: &ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &empty,
        })
        .expect("compile custom default");
        assert_eq!(
            seq_to_vec(&compiled_custom_default.value["dns"]["proxy-server-nameserver"]),
            vec!["https://1.12.12.12/dns-query".to_string()]
        );

        let mut cfg_blank_default = AppConfig::default();
        cfg_blank_default.dns.respect_rules = false;
        cfg_blank_default.dns.default_nameserver.clear();
        let compiled_blank_default = compile_mihomo_config(&CompileInput {
            config: &cfg_blank_default,
            nodes: &nodes,
            groups: &[],
            relays: &[],
            controller_secret: "0123456789abcdef0123456789abcdef",
            allocated_ports: &ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &empty,
        })
        .expect("compile blank default with respect_rules=false");
        assert_eq!(
            seq_to_vec(&compiled_blank_default.value["dns"]["default-nameserver"]),
            expected_doh
        );
        assert_eq!(
            seq_to_vec(&compiled_blank_default.value["dns"]["nameserver-policy"]["+.edu.cn"]),
            vec![
                "system".to_string(),
                "https://223.5.5.5/dns-query".to_string(),
            ]
        );
    }
}
