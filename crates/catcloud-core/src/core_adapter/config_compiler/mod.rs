//! Mihomo YAML configuration compiler, static validator, rule analyzer, and gateway exporter.
//!
//! ## Module Architecture (Acyclic DAG)
//! - `types`: Public constants, DTOs (`CompileInput`, `CompiledCoreConfig`, `CompileStats`,
//!   `StaticValidationReport`, `GatewayExport*`, `BulkRulesParseResult`, etc.), and YAML/SHA-256 helpers.
//! - `rules`: Mihomo rule grammar checks, AI routing defaults, target rewriting, dangling-rule
//!   auditing/repair, bulk rule parsing, and mandatory safety-rule pinning.
//! - `proxies_net`: Node/group compile pruning, chained `dialer-proxy` expansion, dangling dialer
//!   stripping, Sniffer/DNS/TUN builders, and proxy YAML mapping.
//! - `validation`: RFC 7396 YAML Merge Patch, `validate_compiled_yaml`, group cycle detection,
//!   and IPv4/IPv6 anti-loop CIDR checks.
//! - `compiler`: `compile_mihomo_config*` orchestration, post-override MTU/dialer reconciliation,
//!   and preview redaction.
//! - `gateway_redact`: AST-level YAML redaction engine for exported gateway configurations.
//! - `gateway_export`: Transparent gateway, relay fragment, and preferred-node YAML exporters.

mod compiler;
mod gateway_export;
mod gateway_redact;
mod proxies_net;
mod rules;
mod types;
mod validation;

#[cfg(test)]
mod tests;

pub use types::{
    BulkRulesParseResult, CompileInput, CompileStats, CompiledCoreConfig, CompiledGroupMapping,
    DEFAULT_FALLBACK_GROUP_NAME, DanglingRuleGroupSummary, DanglingRuleRepairAction,
    DanglingRuleRepairReport, DanglingRulesAudit, GatewayExportOptions, GatewayExportOutput,
    GatewayExportProfile, MAX_YAML_BYTES, PREACCEL_FALLBACK_GROUP_NAME, PREACCEL_LB_GROUP_NAME,
    PREACCEL_SELECT_GROUP_NAME, PreAccelTransportDiagnostics, SINGLE_NODE_GROUP_NAME,
    StaticCheckIssue, StaticCheckSeverity, StaticValidationReport,
    build_preaccel_transport_diagnostics,
};
pub use rules::{
    audit_dangling_global_rules, build_default_ai_routing_rules,
    cascade_group_name_change_in_global_rules, collect_valid_rule_target_names,
    expand_group_match_rule, extract_mihomo_rule_target, is_builtin_mihomo_rule_target,
    parse_bulk_rules_text, repair_dangling_global_rules, resolve_default_fallback_group_name,
    rewrite_mihomo_rule_target,
};
pub use proxies_net::{
    build_node_proxy_mapping, sanitize_business_node_transport, should_emit_tun_device_name,
};
pub use validation::{
    apply_yaml_merge_patch, format_static_validation_summary_zh, validate_compiled_yaml,
};
pub use compiler::{
    compile_mihomo_config, compile_mihomo_config_with_runtime_dir, redact_compiled_yaml_for_preview,
};
pub use gateway_export::export_gateway_yaml;
#[cfg(test)]
use rules::is_match_rule;
