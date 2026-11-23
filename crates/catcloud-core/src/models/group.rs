use serde::{Deserialize, Serialize};

/// Default cost-effective weighting formula favoring upload throughput and low billing multiplier.
pub const DEFAULT_COST_EFFECTIVE_FORMULA: &str =
    "(up_mbps * 35 + min(down_mbps, 200) * 0.25 - ping_ms * 0.08 - jitter_ms * 0.15) / max(multiplier, 0.25)";

/// Default raw-performance weighting formula ignoring billing multiplier.
pub const DEFAULT_MAX_PERF_FORMULA: &str =
    "up_mbps * 45 + min(down_mbps, 200) * 0.35 - ping_ms * 0.1";

/// Standard schema identifier for domestic pre-acceleration relay bundles.
pub const MMRELAY_SCHEMA_V1: &str = "mmrelay/v1";

/// Standard role tag for domestic pre-acceleration relay bundles.
pub const MMRELAY_ROLE_DOMESTIC_PRE_ACCEL: &str = "domestic_pre_accel";

/// Selection and routing mode for a smart multi-node group.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MultiGroupMode {
    #[default]
    StickyBest,
    ConditionalPool,
    LoadBalanceConsistentHash,
    LoadBalanceRoundRobin,
}

impl MultiGroupMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::StickyBest => "sticky_best",
            Self::ConditionalPool => "conditional_pool",
            Self::LoadBalanceConsistentHash => "load_balance_consistent_hash",
            Self::LoadBalanceRoundRobin => "load_balance_round_robin",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "sticky_best" => Self::StickyBest,
            "conditional_pool" => Self::ConditionalPool,
            "load_balance_consistent_hash" => Self::LoadBalanceConsistentHash,
            "load_balance_round_robin" => Self::LoadBalanceRoundRobin,
            _ => Self::StickyBest,
        }
    }
}

/// Three-way fallback policy when all candidates fall below trigger thresholds or hard gates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum FallbackPolicy {
    /// Keep connectivity using the highest-scoring gate-passing node and raise a warning.
    #[default]
    DegradeBestWarn,
    /// Temporarily borrow a node from `fallback_pool_id` and probe primary pool for auto recovery.
    CrossPoolEscalate,
    /// Switch group to `REJECT` and sever old connections when hard gates fail across all nodes.
    StrictCircuitBreak,
}

impl FallbackPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DegradeBestWarn => "degrade_best_warn",
            Self::CrossPoolEscalate => "cross_pool_escalate",
            Self::StrictCircuitBreak => "strict_circuit_break",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "degrade_best_warn" => Self::DegradeBestWarn,
            "cross_pool_escalate" => Self::CrossPoolEscalate,
            "strict_circuit_break" => Self::StrictCircuitBreak,
            _ => Self::DegradeBestWarn,
        }
    }
}

/// Connection teardown strategy when switching the active node of a group.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SwitchMode {
    /// Actively close existing connections bound to the previous node in this group.
    #[default]
    ForceCloseOld,
    /// Let existing connections finish naturally; route new connections to the new node.
    GracefulNewOnly,
}

impl SwitchMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ForceCloseOld => "force_close_old",
            Self::GracefulNewOnly => "graceful_new_only",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "force_close_old" => Self::ForceCloseOld,
            "graceful_new_only" => Self::GracefulNewOnly,
            _ => Self::ForceCloseOld,
        }
    }
}

/// Operational health state tracked per multi-group.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MultiGroupState {
    #[default]
    Idle,
    Healthy,
    DegradedWarn,
    Escalated,
    CircuitOpen,
}

impl MultiGroupState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Healthy => "healthy",
            Self::DegradedWarn => "degraded_warn",
            Self::Escalated => "escalated",
            Self::CircuitOpen => "circuit_open",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "idle" => Self::Idle,
            "healthy" => Self::Healthy,
            "degraded_warn" => Self::DegradedWarn,
            "escalated" => Self::Escalated,
            "circuit_open" => Self::CircuitOpen,
            _ => Self::Idle,
        }
    }
}

/// Threshold trigger rule causing the arbiter to re-evaluate and switch active nodes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct TriggerRule {
    /// Safe AST boolean expression, e.g. `probe_up("ai") < 1.0 || latency_ms > 1500`.
    pub expr: String,
    /// Consecutive evaluations matching `expr` required before switching.
    pub consecutive_failures: u32,
    /// When true, hard disconnect (`ok == false`) bypasses `cooldown_sec`.
    pub bypass_cooldown_on_disconnect: bool,
}

impl Default for TriggerRule {
    fn default() -> Self {
        Self {
            expr: String::new(),
            consecutive_failures: 2,
            bypass_cooldown_on_disconnect: true,
        }
    }
}

/// Dynamic membership filter for `ConditionalPool` and filtered load-balance groups.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct DynamicFilterSpec {
    /// Optional safe AST expression evaluated per node (e.g. `multiplier <= 1 && google_clean == 1`).
    pub expr: Option<String>,
    pub sub_ids: Vec<String>,
    pub region_codes: Vec<String>,
    pub max_multiplier: Option<f64>,
    pub protocols: Vec<String>,
    pub require_google_clean: bool,
    pub require_443_native: Option<bool>,
}

/// Orchestrated multi-node selection/balancing group persisted in `multi_groups`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct MultiGroup {
    pub id: String,
    pub name: String,
    pub mode: MultiGroupMode,
    pub match_rules: Vec<String>,
    pub member_node_ids: Vec<String>,
    pub dynamic_filter: Option<DynamicFilterSpec>,
    pub primary_probe_id: Option<String>,
    pub hard_gates: Vec<String>,
    pub trigger_rules: Vec<TriggerRule>,
    pub formula_expr: String,
    pub fallback_policy: FallbackPolicy,
    pub fallback_pool_id: Option<String>,
    /// RFC3339 timestamp recorded when cross-pool escalation started; cleared on recovery.
    pub escalated_since: Option<String>,
    /// Background recovery probe interval (seconds) while escalated to a fallback pool.
    pub recover_probe_interval_sec: u64,
    pub switch_mode: SwitchMode,
    pub cooldown_sec: u64,
    pub hysteresis_pct: f64,
    pub active_node_id: Option<String>,
    pub state: MultiGroupState,
    /// When `true`, this group's `match_rules` remain active for split routing even if it is not
    /// the currently selected active home group. Defaults to `false` to prevent unselected groups
    /// from silently hijacking traffic.
    #[serde(default)]
    pub independent_routing: bool,
}

impl Default for MultiGroup {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            mode: MultiGroupMode::StickyBest,
            match_rules: Vec::new(),
            member_node_ids: Vec::new(),
            dynamic_filter: None,
            primary_probe_id: None,
            hard_gates: Vec::new(),
            trigger_rules: Vec::new(),
            formula_expr: DEFAULT_COST_EFFECTIVE_FORMULA.to_string(),
            fallback_policy: FallbackPolicy::DegradeBestWarn,
            fallback_pool_id: None,
            escalated_since: None,
            recover_probe_interval_sec: 120,
            switch_mode: SwitchMode::ForceCloseOld,
            cooldown_sec: 60,
            hysteresis_pct: 20.0,
            active_node_id: None,
            state: MultiGroupState::Idle,
            independent_routing: false,
        }
    }
}

/// Domestic pre-acceleration relay entry aligned with `mmrelay/v1` and `preaccel_relays`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct PreAccelRelay {
    pub id: String,
    pub name: String,
    pub provider: String,
    pub region: String,
    pub server: String,
    pub port: u16,
    pub protocol: String,
    pub password: String,
    /// Optional TLS SNI / VLESS `servername`. Must remain empty for pure-IP domestic :443 relays.
    #[serde(alias = "servername")]
    pub sni: Option<String>,
    pub skip_cert_verify: bool,
    /// Lower numeric value means higher priority in active-standby fallback ordering.
    pub priority: i32,
    pub expires_at: Option<String>,
    pub enabled: bool,
    pub last_probe_ms: Option<f64>,
    pub last_mbps: Option<f64>,
}

impl Default for PreAccelRelay {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            provider: String::new(),
            region: String::new(),
            server: String::new(),
            port: 443,
            protocol: "anytls".to_string(),
            password: String::new(),
            sni: None,
            skip_cert_verify: true,
            priority: 100,
            expires_at: None,
            enabled: true,
            last_probe_ms: None,
            last_mbps: None,
        }
    }
}

impl PreAccelRelay {
    /// Returns true if a non-empty SNI / servername is configured.
    pub fn has_non_empty_sni(&self) -> bool {
        self.sni
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
    }
}

/// Interchange envelope for `mmrelay/v1` domestic pre-acceleration relay lists.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct MmRelayBundleV1 {
    pub schema: String,
    pub role: String,
    pub relays: Vec<PreAccelRelay>,
}

impl Default for MmRelayBundleV1 {
    fn default() -> Self {
        Self {
            schema: MMRELAY_SCHEMA_V1.to_string(),
            role: MMRELAY_ROLE_DOMESTIC_PRE_ACCEL.to_string(),
            relays: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_group_independent_routing_defaults_false_and_deserializes_legacy_json() {
        let def = MultiGroup::default();
        assert!(!def.independent_routing);

        let legacy: MultiGroup =
            serde_json::from_str(r#"{"id":"grp-legacy","name":"Legacy AI"}"#).unwrap();
        assert_eq!(legacy.id, "grp-legacy");
        assert!(!legacy.independent_routing);

        let enabled: MultiGroup = serde_json::from_str(
            r#"{"id":"grp-split","name":"Split AI","independent_routing":true}"#,
        )
        .unwrap();
        assert!(enabled.independent_routing);
    }
}
