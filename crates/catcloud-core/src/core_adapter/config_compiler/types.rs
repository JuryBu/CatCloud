//! Core DTOs, constants, and low-level YAML/SHA-256 helpers for the Mihomo config compiler.

use crate::core_adapter::port_guard::AllocatedPorts;
use crate::models::{AppConfig, MultiGroup, PreAccelRelay, ProxyNode};
use serde::{Deserialize, Serialize};
use serde_yaml_ng::{Mapping, Number, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use url::Url;

/// Canonical Mihomo selector group name for domestic pre-acceleration entry.
pub const PREACCEL_SELECT_GROUP_NAME: &str = "⚡ 国内预加速入口";

/// Canonical Mihomo fallback group name for active-standby domestic pre-acceleration relays.
pub const PREACCEL_FALLBACK_GROUP_NAME: &str = "🔄 预加速自动双活";

/// Canonical Mihomo inner load-balance group name for multi-cloud physical host aggregation.
pub use crate::preaccel::schema::PREACCEL_LB_GROUP_NAME;

/// Default top-level proxy selector group generated when no custom multi-groups exist.
pub const DEFAULT_FALLBACK_GROUP_NAME: &str = "🐱 猫猫云梯";

/// Canonical Mihomo selector group name used in direct single-node routing mode.
pub const SINGLE_NODE_GROUP_NAME: &str = "单节点直选";

/// Hard upper bound (16 MiB) on parsed YAML payload sizes to defend against YAML bombs.
pub const MAX_YAML_BYTES: usize = 16 * 1024 * 1024;

/// Default health check URL used by `load-balance` groups (overseas proxy path).
pub(super) const DEFAULT_LOAD_BALANCE_URL: &str = "https://cp.cloudflare.com/generate_204";

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
    #[serde(default)]
    pub skipped_ipv6_proxies: usize,
    pub proxy_groups: usize,
    pub total_rules: usize,
    pub preaccel_active: bool,
    #[serde(default)]
    pub effective_tun_mtu: u16,
}

/// Structured transport-layer diagnostics for domestic pre-acceleration stability inspection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreAccelTransportDiagnostics {
    pub effective_mode: String,
    pub effective_tun_mtu: u16,
    pub anytls_tfo: bool,
    pub anytls_min_idle_session: u16,
    pub keep_alive_idle_sec: u16,
    pub keep_alive_interval_sec: u16,
    pub expected_probe_status: String,
    pub lb_strategy: String,
    pub probe_interval_sec: u16,
}

/// Build a structured [`PreAccelTransportDiagnostics`] snapshot from the active [`AppConfig`],
/// compiled effective TUN MTU, and resolved effective pre-acceleration mode.
pub fn build_preaccel_transport_diagnostics(
    cfg: &AppConfig,
    effective_tun_mtu: u16,
    effective_mode: &str,
) -> PreAccelTransportDiagnostics {
    let probe_interval_sec = cfg.preaccel.probe_interval_sec.clamp(20, 300) as u16;
    PreAccelTransportDiagnostics {
        effective_mode: effective_mode.trim().to_string(),
        effective_tun_mtu,
        anytls_tfo: false,
        anytls_min_idle_session: 0,
        keep_alive_idle_sec: 45,
        keep_alive_interval_sec: 15,
        expected_probe_status: crate::preaccel::generator::expected_probe_status_for_url(
            &cfg.preaccel.probe_url,
        )
        .to_string(),
        lb_strategy: cfg.preaccel.lb_strategy.as_str().to_string(),
        probe_interval_sec,
    }
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

/// Summary of dangling global rules pointing to one non-existent proxy or proxy-group name.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DanglingRuleGroupSummary {
    pub target: String,
    pub count: usize,
    pub sample_rules: Vec<String>,
}

/// Read-only audit of global prepend/append rules referencing non-existent proxy/group targets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DanglingRulesAudit {
    pub total_dangling: usize,
    pub groups: Vec<DanglingRuleGroupSummary>,
    pub default_fallback_group: String,
}

/// Self-healing repair strategy for dangling global rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum DanglingRuleRepairAction {
    Remove,
    RewriteToGroup { target_group: String },
}

/// Structured outcome after repairing dangling global rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DanglingRuleRepairReport {
    pub removed_count: usize,
    pub rewritten_count: usize,
    pub target_group: Option<String>,
    pub affected_targets: Vec<String>,
}

/// Target profile for transparent gateway / soft-router Mihomo YAML export.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayExportProfile {
    RelayFragment,
    TransparentGateway,
    PreferredNodes,
}

fn default_gateway_tproxy_port() -> u16 {
    7893
}

fn default_gateway_redir_port() -> u16 {
    7892
}

fn default_gateway_dns_port() -> u16 {
    1053
}

fn default_true_bool() -> bool {
    true
}

/// Options controlling transparent gateway / soft-router YAML export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayExportOptions {
    pub profile: GatewayExportProfile,
    #[serde(default = "default_gateway_tproxy_port")]
    pub tproxy_port: u16,
    #[serde(default = "default_gateway_redir_port")]
    pub redir_port: u16,
    #[serde(default = "default_gateway_dns_port")]
    pub dns_listen_port: u16,
    #[serde(default = "default_true_bool")]
    pub redact_secrets: bool,
}

impl Default for GatewayExportOptions {
    fn default() -> Self {
        Self {
            profile: GatewayExportProfile::RelayFragment,
            tproxy_port: default_gateway_tproxy_port(),
            redir_port: default_gateway_redir_port(),
            dns_listen_port: default_gateway_dns_port(),
            redact_secrets: true,
        }
    }
}

/// Structured output returned by [`export_gateway_yaml`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayExportOutput {
    pub profile: GatewayExportProfile,
    pub yaml: String,
    pub redacted: bool,
    pub relay_count: usize,
    pub node_count: usize,
    pub rule_count: usize,
    pub warnings: Vec<String>,
    pub integration_hint: String,
}

/// Result of parsing pasted raw Mihomo/Clash rule text via [`parse_bulk_rules_text`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkRulesParseResult {
    pub valid_rules: Vec<String>,
    pub skipped_lines: Vec<String>,
}

pub(super) fn direct_rule_for_host_or_ip(host_or_ip: &str) -> String {
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

pub(super) fn extract_url_host(raw_url: &str) -> Option<String> {
    Url::parse(raw_url.trim())
        .ok()
        .and_then(|u| u.host_str().map(|h| h.trim().to_string()))
        .filter(|h| !h.is_empty())
}

pub(super) fn is_preaccel_group_name(name: &str, dialer_targets: &HashSet<String>) -> bool {
    if name == PREACCEL_FALLBACK_GROUP_NAME
        || name == PREACCEL_SELECT_GROUP_NAME
        || name == PREACCEL_LB_GROUP_NAME
        || dialer_targets.contains(name)
    {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    lower.contains("preaccel") || name.contains("预加速")
}

pub(super) fn make_unique_name(base: &str, used: &mut HashSet<String>) -> String {
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

pub(super) fn push_unique(list: &mut Vec<String>, item: String) {
    if !list.iter().any(|existing| existing == &item) {
        list.push(item);
    }
}

pub(super) fn str_val(s: &str) -> Value {
    Value::String(s.to_string())
}

pub(super) fn insert_str(map: &mut Mapping, key: &str, value: &str) {
    map.insert(str_val(key), str_val(value));
}

pub(super) fn insert_bool(map: &mut Mapping, key: &str, value: bool) {
    map.insert(str_val(key), Value::Bool(value));
}

pub(super) fn insert_u64(map: &mut Mapping, key: &str, value: u64) {
    map.insert(str_val(key), Value::Number(Number::from(value)));
}

pub(super) fn string_seq<'a>(items: impl IntoIterator<Item = &'a str>) -> Value {
    Value::Sequence(items.into_iter().map(str_val).collect())
}

pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}
