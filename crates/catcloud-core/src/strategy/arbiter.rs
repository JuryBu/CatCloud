//! Stateful multi-group arbitration engine: debouncing, cooldown, disconnect cooldown bypass,
//! hysteresis switching, controlled load-balance pool purification, and three-way fallback
//! (`DegradeBestWarn`, `CrossPoolEscalate` with automatic primary recovery, `StrictCircuitBreak`).

use crate::error::CatResult;
use crate::models::{
    FallbackPolicy, MultiGroup, MultiGroupMode, MultiGroupState, ProbeSnapshot, ProxyNode,
    SwitchMode,
};
use crate::strategy::evaluator::{
    EvaluatedCandidate, GroupEvaluationReport, build_eval_context_for_probe,
    evaluate_group_candidates, evaluate_hard_gates, score_node_with_group_formula,
};
use crate::strategy::formula::FormulaExpr;
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Built-in circuit-breaker target slot name wired into Mihomo group compilation.
pub const BUILTIN_REJECT_TARGET: &str = "REJECT";

/// Consecutive healthy primary-pool evaluations required before recovering from escalation.
pub const DEFAULT_RECOVERY_STREAK_REQUIRED: u32 = 2;

/// Default maximum top-K healthy primary candidates recomputed for an escalated load-balance group
/// whose in-memory `last_balance_pool` was cleared across a process restart.
const DEFAULT_LB_RECOVERY_TOP_K: usize = 5;

/// Mutable per-group runtime state tracked across periodic arbitration ticks.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ArbiterGroupMemory {
    /// Consecutive threshold violations observed on the currently active node.
    pub consecutive_failures: u32,
    /// Unix epoch seconds when this group last switched active node or circuit-broke.
    pub last_switched_at: Option<i64>,
    /// Unix epoch seconds when cross-pool escalation began (`None` when not escalated).
    pub escalated_since: Option<i64>,
    /// Consecutive ticks where the primary pool recovered above hysteresis while escalated.
    pub primary_recovery_streak: u32,
    /// Last active node ID observed by the arbiter (used to detect external manual switches).
    pub last_observed_active_node: Option<String>,
    /// Last emitted candidate list for load-balance groups.
    pub last_balance_pool: Vec<String>,
}

/// Concrete action emitted by [`decide_group_action`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArbiterAction {
    /// Retain current active node or current balance candidate set.
    KeepCurrent,
    /// Switch active node to `target_node_id` within the primary pool.
    SwitchNode,
    /// Keep connectivity with the highest-scoring gate-passing node and raise a degradation alert.
    DegradeToBest,
    /// Temporarily borrow a gate-passing node (or balance set) from `fallback_pool_id`.
    EscalateToFallbackPool,
    /// Automatically return from an escalated fallback pool to the recovered primary pool.
    RecoverToPrimaryPool,
    /// Hard-gate circuit break: switch group to built-in `REJECT` slot and sever old connections.
    CircuitBreakToReject,
    /// Apply an updated gate-filtered candidate list to a load-balance group.
    UpdateBalancePool,
    /// No eligible candidate exists under current filters/gates.
    NoEligibleCandidate,
}

/// Structured arbitration decision consumed by the core controller and persistence layer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArbiterDecision {
    pub group_id: String,
    pub action: ArbiterAction,
    pub next_state: MultiGroupState,
    /// Target node ID for sticky/conditional/escalated switches, or `"REJECT"` on circuit break.
    pub target_node_id: Option<String>,
    /// Gate-filtered ordered candidate node IDs for load-balance modes.
    pub balance_candidate_ids: Vec<String>,
    /// Strictly mirrors `group.switch_mode` (`ForceCloseOld => true`, `GracefulNewOnly => false`),
    /// except `CircuitBreakToReject` which is unconditionally `true` and `KeepCurrent` (`false`).
    pub should_close_old_connections: bool,
    /// Signals background scheduler to shorten re-probe cadence (degraded / escalated / circuit open).
    pub shorten_reprobe_interval: bool,
    /// Signals adapter controller to trigger an external source refresh (subject to adapter cooldown).
    pub trigger_adapter_refresh: bool,
    /// Updated RFC3339 escalation timestamp (`Some(...)` while `Escalated`, `None` otherwise).
    pub escalated_since_rfc3339: Option<String>,
    /// Human-readable diagnostic reason for logging, CLI `--json`, and UI tooltips.
    pub reason: String,
}

/// Multi-group stateful arbitration facade holding [`ArbiterGroupMemory`] per group ID.
#[derive(Debug, Default)]
pub struct StrategyArbiter {
    memories: HashMap<String, ArbiterGroupMemory>,
}

impl StrategyArbiter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn memory(&self, group_id: &str) -> Option<&ArbiterGroupMemory> {
        self.memories.get(group_id)
    }

    pub fn memory_mut(&mut self, group_id: &str) -> &mut ArbiterGroupMemory {
        self.memories.entry(group_id.to_string()).or_default()
    }

    pub fn reset_group(&mut self, group_id: &str) {
        self.memories.remove(group_id);
    }

    /// Evaluate and decide the next action for `group`, automatically resolving `fallback_pool_id`
    /// from `all_groups`.
    pub fn decide(
        &mut self,
        group: &MultiGroup,
        all_groups: &[MultiGroup],
        nodes: &[ProxyNode],
        snapshots: &HashMap<String, ProbeSnapshot>,
        now_unix_sec: i64,
    ) -> CatResult<ArbiterDecision> {
        let memory = self.memories.entry(group.id.clone()).or_default();
        decide_group_action_with_registry(group, all_groups, nodes, snapshots, memory, now_unix_sec)
    }
}

/// Apply an [`ArbiterDecision`] back onto a mutable [`MultiGroup`] runtime view
/// (mirroring fields persisted via `Storage::update_multi_group_runtime`).
pub fn apply_decision_to_group(group: &mut MultiGroup, decision: &ArbiterDecision) {
    group.state = decision.next_state.clone();
    group.escalated_since = decision.escalated_since_rfc3339.clone();
    match decision.action {
        ArbiterAction::SwitchNode
        | ArbiterAction::DegradeToBest
        | ArbiterAction::EscalateToFallbackPool
        | ArbiterAction::RecoverToPrimaryPool
        | ArbiterAction::CircuitBreakToReject => {
            if let Some(ref target) = decision.target_node_id {
                group.active_node_id = Some(target.clone());
            }
        }
        ArbiterAction::KeepCurrent
        | ArbiterAction::UpdateBalancePool
        | ArbiterAction::NoEligibleCandidate => {}
    }
}

/// Check whether `candidate_score` exceeds `current_score` by at least `hysteresis_pct`%.
///
/// Uses `current_score.abs()` for the percentage margin so negative scores remain strictly
/// monotonic and never invert the comparison direction.
pub fn exceeds_hysteresis(candidate_score: f64, current_score: f64, hysteresis_pct: f64) -> bool {
    if !candidate_score.is_finite() {
        return false;
    }
    if !current_score.is_finite() {
        return true;
    }
    let pct = hysteresis_pct.max(0.0) / 100.0;
    if pct <= 0.0 {
        return candidate_score > current_score;
    }
    let margin = if current_score.abs() > 1e-6 {
        current_score.abs() * pct
    } else {
        pct
    };
    candidate_score >= current_score + margin
}

/// Parse an RFC3339 timestamp into Unix epoch seconds.
pub fn parse_rfc3339_ts(ts: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(ts.trim())
        .ok()
        .map(|dt| dt.timestamp())
}

/// Format Unix epoch seconds as an UTC RFC3339 string.
pub fn format_rfc3339_ts(epoch_sec: i64) -> String {
    Utc.timestamp_opt(epoch_sec, 0)
        .single()
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| Utc::now().to_rfc3339())
}

/// Convenience wrapper around [`decide_group_action`] that resolves `group.fallback_pool_id`
/// from `all_groups` (ignoring self-references).
pub fn decide_group_action_with_registry(
    group: &MultiGroup,
    all_groups: &[MultiGroup],
    nodes: &[ProxyNode],
    snapshots: &HashMap<String, ProbeSnapshot>,
    memory: &mut ArbiterGroupMemory,
    now_unix_sec: i64,
) -> CatResult<ArbiterDecision> {
    let fallback_group = group
        .fallback_pool_id
        .as_deref()
        .map(str::trim)
        .filter(|fid| !fid.is_empty() && *fid != group.id.as_str())
        .and_then(|fid| all_groups.iter().find(|g| g.id == fid));

    decide_group_action(group, nodes, snapshots, fallback_group, memory, now_unix_sec)
}

/// Core arbitration entry point for a single [`MultiGroup`].
///
/// Handles all four [`MultiGroupMode`] variants, hard-gate enforcement, consecutive-failure
/// debouncing, cooldown enforcement with disconnect bypass, hysteresis switching, three-way
/// fallback (`DegradeBestWarn` / `CrossPoolEscalate` / `StrictCircuitBreak`), automatic primary
/// pool hysteresis recovery, and `SwitchMode` old-connection disposal flags.
pub fn decide_group_action(
    group: &MultiGroup,
    nodes: &[ProxyNode],
    snapshots: &HashMap<String, ProbeSnapshot>,
    fallback_group: Option<&MultiGroup>,
    memory: &mut ArbiterGroupMemory,
    now_unix_sec: i64,
) -> CatResult<ArbiterDecision> {
    // Rehydrate escalation timestamp after restart when persisted group state is `Escalated`.
    if group.state == MultiGroupState::Escalated && memory.escalated_since.is_none() {
        memory.escalated_since = group
            .escalated_since
            .as_deref()
            .and_then(parse_rfc3339_ts)
            .or(Some(now_unix_sec));
    }

    // Reset per-node failure streak if active_node_id was modified externally.
    if group.active_node_id != memory.last_observed_active_node {
        memory.consecutive_failures = 0;
        memory.last_observed_active_node = group.active_node_id.clone();
    }

    let report = evaluate_group_candidates(group, nodes, snapshots)?;

    match group.mode {
        MultiGroupMode::LoadBalanceConsistentHash | MultiGroupMode::LoadBalanceRoundRobin => {
            decide_load_balance_mode(
                group,
                &report,
                nodes,
                snapshots,
                fallback_group,
                memory,
                now_unix_sec,
            )
        }
        MultiGroupMode::StickyBest | MultiGroupMode::ConditionalPool => decide_sticky_mode(
            group,
            &report,
            nodes,
            snapshots,
            fallback_group,
            memory,
            now_unix_sec,
        ),
    }
}

// ============================================================================
// Load-balance modes (consistent-hash / round-robin)
// ============================================================================

#[allow(clippy::too_many_arguments)]
fn decide_load_balance_mode(
    group: &MultiGroup,
    report: &GroupEvaluationReport,
    nodes: &[ProxyNode],
    snapshots: &HashMap<String, ProbeSnapshot>,
    fallback_group: Option<&MultiGroup>,
    memory: &mut ArbiterGroupMemory,
    now_unix_sec: i64,
) -> CatResult<ArbiterDecision> {
    let is_escalated =
        group.state == MultiGroupState::Escalated || memory.escalated_since.is_some();

    if !report.healthy_candidates.is_empty() {
        let purified_ids: Vec<String> = report
            .healthy_candidates
            .iter()
            .map(|c| c.node_id.clone())
            .collect();

        if is_escalated {
            let escalated_ts = memory.escalated_since.unwrap_or(now_unix_sec);
            memory.primary_recovery_streak = memory.primary_recovery_streak.saturating_add(1);
            if memory.primary_recovery_streak >= DEFAULT_RECOVERY_STREAK_REQUIRED
                && !is_in_cooldown(memory, group, now_unix_sec)
            {
                memory.escalated_since = None;
                memory.primary_recovery_streak = 0;
                memory.consecutive_failures = 0;
                memory.last_switched_at = Some(now_unix_sec);
                memory.last_balance_pool = purified_ids.clone();
                return Ok(ArbiterDecision {
                    group_id: group.id.clone(),
                    action: ArbiterAction::RecoverToPrimaryPool,
                    next_state: MultiGroupState::Healthy,
                    target_node_id: None,
                    balance_candidate_ids: purified_ids,
                    should_close_old_connections: force_close_flag(group),
                    shorten_reprobe_interval: false,
                    trigger_adapter_refresh: false,
                    escalated_since_rfc3339: None,
                    reason: "primary load-balance pool recovered for 2 consecutive checks; returning from fallback pool".into(),
                });
            }
            let active_balance_pool = if memory.last_balance_pool.is_empty() {
                // If the process restarted while this load-balance group was `Escalated`, the
                // in-memory `last_balance_pool` is empty. Recompute top-K healthy primary
                // candidates (already ranked by score descending) so downstream compilation never
                // receives an empty pool while awaiting the recovery streak or cooldown.
                let recomputed: Vec<String> = purified_ids
                    .iter()
                    .take(DEFAULT_LB_RECOVERY_TOP_K)
                    .cloned()
                    .collect();
                memory.last_balance_pool = recomputed.clone();
                recomputed
            } else {
                memory.last_balance_pool.clone()
            };
            return Ok(ArbiterDecision {
                group_id: group.id.clone(),
                action: ArbiterAction::KeepCurrent,
                next_state: MultiGroupState::Escalated,
                target_node_id: None,
                balance_candidate_ids: active_balance_pool,
                should_close_old_connections: false,
                shorten_reprobe_interval: true,
                trigger_adapter_refresh: false,
                escalated_since_rfc3339: Some(format_rfc3339_ts(escalated_ts)),
                reason: format!(
                    "primary load-balance pool recovery streak {}/{}; staying escalated",
                    memory.primary_recovery_streak, DEFAULT_RECOVERY_STREAK_REQUIRED
                ),
            });
        }

        memory.consecutive_failures = 0;
        let changed =
            memory.last_balance_pool != purified_ids || group.state != MultiGroupState::Healthy;
        if !changed {
            return Ok(ArbiterDecision {
                group_id: group.id.clone(),
                action: ArbiterAction::KeepCurrent,
                next_state: MultiGroupState::Healthy,
                target_node_id: None,
                balance_candidate_ids: purified_ids,
                should_close_old_connections: false,
                shorten_reprobe_interval: false,
                trigger_adapter_refresh: false,
                escalated_since_rfc3339: None,
                reason: "load-balance candidate pool unchanged and healthy".into(),
            });
        }

        memory.last_balance_pool = purified_ids.clone();
        memory.last_switched_at = Some(now_unix_sec);
        return Ok(ArbiterDecision {
            group_id: group.id.clone(),
            action: ArbiterAction::UpdateBalancePool,
            next_state: MultiGroupState::Healthy,
            target_node_id: None,
            balance_candidate_ids: purified_ids,
            should_close_old_connections: force_close_flag(group),
            shorten_reprobe_interval: false,
            trigger_adapter_refresh: false,
            escalated_since_rfc3339: None,
            reason: "updated gate-filtered load-balance candidate pool".into(),
        });
    }

    // All primary load-balance candidates failed hard gates or fell below threshold -> 3-way fallback.
    memory.primary_recovery_streak = 0;
    match group.fallback_policy {
        FallbackPolicy::StrictCircuitBreak => {
            if report.all_failed_hard_gates {
                return Ok(emit_circuit_break(
                    group,
                    memory,
                    now_unix_sec,
                    "all load-balance candidates failed hard gates; circuit-breaking to REJECT",
                ));
            }
            let degraded_ids: Vec<String> = report
                .gate_passed
                .iter()
                .map(|c| c.node_id.clone())
                .collect();
            let changed = memory.last_balance_pool != degraded_ids;
            memory.last_balance_pool = degraded_ids.clone();
            if changed {
                memory.last_switched_at = Some(now_unix_sec);
            }
            Ok(ArbiterDecision {
                group_id: group.id.clone(),
                action: ArbiterAction::DegradeToBest,
                next_state: MultiGroupState::DegradedWarn,
                target_node_id: None,
                balance_candidate_ids: degraded_ids,
                should_close_old_connections: changed && force_close_flag(group),
                shorten_reprobe_interval: true,
                trigger_adapter_refresh: true,
                escalated_since_rfc3339: None,
                reason: "all load-balance candidates below threshold while passing hard gates; degraded with alert".into(),
            })
        }
        FallbackPolicy::DegradeBestWarn => {
            if report.gate_passed.is_empty() {
                memory.last_balance_pool.clear();
                return Ok(ArbiterDecision {
                    group_id: group.id.clone(),
                    action: ArbiterAction::NoEligibleCandidate,
                    next_state: MultiGroupState::DegradedWarn,
                    target_node_id: None,
                    balance_candidate_ids: Vec::new(),
                    should_close_old_connections: false,
                    shorten_reprobe_interval: true,
                    trigger_adapter_refresh: true,
                    escalated_since_rfc3339: None,
                    reason: "no load-balance candidates passed hard gates".into(),
                });
            }
            let degraded_ids: Vec<String> = report
                .gate_passed
                .iter()
                .map(|c| c.node_id.clone())
                .collect();
            let changed = memory.last_balance_pool != degraded_ids;
            memory.last_balance_pool = degraded_ids.clone();
            if changed {
                memory.last_switched_at = Some(now_unix_sec);
            }
            Ok(ArbiterDecision {
                group_id: group.id.clone(),
                action: ArbiterAction::DegradeToBest,
                next_state: MultiGroupState::DegradedWarn,
                target_node_id: None,
                balance_candidate_ids: degraded_ids,
                should_close_old_connections: changed && force_close_flag(group),
                shorten_reprobe_interval: true,
                trigger_adapter_refresh: true,
                escalated_since_rfc3339: None,
                reason: "all load-balance candidates below threshold; degrading to best gate-passing set with alert".into(),
            })
        }
        FallbackPolicy::CrossPoolEscalate => {
            if let Some(fb_group) = fallback_group {
                let fb_report = evaluate_fallback_pool(group, fb_group, nodes, snapshots)?;
                let chosen = if !fb_report.healthy_candidates.is_empty() {
                    &fb_report.healthy_candidates
                } else {
                    &fb_report.gate_passed
                };
                if !chosen.is_empty() {
                    let escalated_ids: Vec<String> =
                        chosen.iter().map(|c| c.node_id.clone()).collect();
                    let escalated_ts = memory.escalated_since.unwrap_or(now_unix_sec);
                    memory.escalated_since = Some(escalated_ts);
                    memory.primary_recovery_streak = 0;
                    let changed = memory.last_balance_pool != escalated_ids || !is_escalated;
                    memory.last_balance_pool = escalated_ids.clone();
                    if changed {
                        memory.last_switched_at = Some(now_unix_sec);
                    }
                    return Ok(ArbiterDecision {
                        group_id: group.id.clone(),
                        action: if changed {
                            ArbiterAction::EscalateToFallbackPool
                        } else {
                            ArbiterAction::KeepCurrent
                        },
                        next_state: MultiGroupState::Escalated,
                        target_node_id: None,
                        balance_candidate_ids: escalated_ids,
                        should_close_old_connections: changed && force_close_flag(group),
                        shorten_reprobe_interval: true,
                        trigger_adapter_refresh: false,
                        escalated_since_rfc3339: Some(format_rfc3339_ts(escalated_ts)),
                        reason: format!(
                            "primary load-balance pool below threshold; borrowing gate-passing pool from `{}`",
                            fb_group.id
                        ),
                    });
                }
            }

            // Fallback pool unavailable or empty -> gracefully degrade to primary gate-passing set.
            memory.escalated_since = None;
            if report.gate_passed.is_empty() {
                memory.last_balance_pool.clear();
                Ok(ArbiterDecision {
                    group_id: group.id.clone(),
                    action: ArbiterAction::NoEligibleCandidate,
                    next_state: MultiGroupState::DegradedWarn,
                    target_node_id: None,
                    balance_candidate_ids: Vec::new(),
                    should_close_old_connections: false,
                    shorten_reprobe_interval: true,
                    trigger_adapter_refresh: true,
                    escalated_since_rfc3339: None,
                    reason: "primary and fallback pools have no gate-passing candidates".into(),
                })
            } else {
                let degraded_ids: Vec<String> = report
                    .gate_passed
                    .iter()
                    .map(|c| c.node_id.clone())
                    .collect();
                let changed = memory.last_balance_pool != degraded_ids;
                memory.last_balance_pool = degraded_ids.clone();
                if changed {
                    memory.last_switched_at = Some(now_unix_sec);
                }
                Ok(ArbiterDecision {
                    group_id: group.id.clone(),
                    action: ArbiterAction::DegradeToBest,
                    next_state: MultiGroupState::DegradedWarn,
                    target_node_id: None,
                    balance_candidate_ids: degraded_ids,
                    should_close_old_connections: changed && force_close_flag(group),
                    shorten_reprobe_interval: true,
                    trigger_adapter_refresh: true,
                    escalated_since_rfc3339: None,
                    reason: "fallback pool unavailable; degraded to primary gate-passing load-balance set".into(),
                })
            }
        }
    }
}

// ============================================================================
// Sticky-best & ConditionalPool modes
// ============================================================================

#[allow(clippy::too_many_arguments)]
fn decide_sticky_mode(
    group: &MultiGroup,
    report: &GroupEvaluationReport,
    nodes: &[ProxyNode],
    snapshots: &HashMap<String, ProbeSnapshot>,
    fallback_group: Option<&MultiGroup>,
    memory: &mut ArbiterGroupMemory,
    now_unix_sec: i64,
) -> CatResult<ArbiterDecision> {
    let is_escalated =
        group.state == MultiGroupState::Escalated || memory.escalated_since.is_some();

    // 1. Escalated state: check automatic hysteresis return to primary pool first.
    if is_escalated {
        return decide_while_escalated(
            group,
            report,
            nodes,
            snapshots,
            fallback_group,
            memory,
            now_unix_sec,
        );
    }

    // 2. All primary candidates failed hard gates or fell below threshold -> 3-way fallback.
    if report.healthy_candidates.is_empty() {
        return decide_all_below_threshold_sticky(
            group,
            report,
            nodes,
            snapshots,
            fallback_group,
            memory,
            now_unix_sec,
        );
    }

    // 3. Primary pool has at least one healthy candidate.
    let best = &report.healthy_candidates[0];
    let Some(ref active) = report.active_assessment else {
        // No active node selected yet -> select the top healthy candidate immediately.
        memory.consecutive_failures = 0;
        memory.last_switched_at = Some(now_unix_sec);
        memory.last_observed_active_node = Some(best.node_id.clone());
        return Ok(ArbiterDecision {
            group_id: group.id.clone(),
            action: ArbiterAction::SwitchNode,
            next_state: MultiGroupState::Healthy,
            target_node_id: Some(best.node_id.clone()),
            balance_candidate_ids: Vec::new(),
            should_close_old_connections: false,
            shorten_reprobe_interval: false,
            trigger_adapter_refresh: false,
            escalated_since_rfc3339: None,
            reason: format!("initial selection of top healthy node `{}`", best.node_id),
        });
    };

    // 3a. Active node dropped out of candidate pool or violated a hard gate -> immediate switch.
    if !active.in_candidate_pool || !active.passed_hard_gates {
        memory.consecutive_failures = 0;
        memory.last_switched_at = Some(now_unix_sec);
        memory.last_observed_active_node = Some(best.node_id.clone());
        return Ok(ArbiterDecision {
            group_id: group.id.clone(),
            action: ArbiterAction::SwitchNode,
            next_state: MultiGroupState::Healthy,
            target_node_id: Some(best.node_id.clone()),
            balance_candidate_ids: Vec::new(),
            should_close_old_connections: force_close_flag(group),
            shorten_reprobe_interval: false,
            trigger_adapter_refresh: false,
            escalated_since_rfc3339: None,
            reason: format!(
                "active node `{}` left pool or failed hard gates; switching immediately to `{}`",
                active.node_id, best.node_id
            ),
        });
    }

    // 3b. Active node hard-disconnected (`ok == false`).
    if active.is_disconnected {
        memory.consecutive_failures = memory.consecutive_failures.saturating_add(1);
        if active.bypass_cooldown {
            memory.consecutive_failures = 0;
            memory.last_switched_at = Some(now_unix_sec);
            memory.last_observed_active_node = Some(best.node_id.clone());
            return Ok(ArbiterDecision {
                group_id: group.id.clone(),
                action: ArbiterAction::SwitchNode,
                next_state: MultiGroupState::Healthy,
                target_node_id: Some(best.node_id.clone()),
                balance_candidate_ids: Vec::new(),
                should_close_old_connections: force_close_flag(group),
                shorten_reprobe_interval: false,
                trigger_adapter_refresh: false,
                escalated_since_rfc3339: None,
                reason: format!(
                    "active node `{}` hard-disconnected; bypassed cooldown and switched to `{}`",
                    active.node_id, best.node_id
                ),
            });
        }

        let required = active.required_consecutive_failures.max(1);
        if memory.consecutive_failures < required {
            return Ok(keep_current_decision(
                group,
                keep_non_idle_state(group),
                format!(
                    "active node `{}` disconnected ({}/{} failures, cooldown bypass disabled)",
                    active.node_id, memory.consecutive_failures, required
                ),
            ));
        }
        if is_in_cooldown(memory, group, now_unix_sec) {
            return Ok(keep_current_decision(
                group,
                keep_non_idle_state(group),
                format!(
                    "active node `{}` disconnected but cooldown bypass is disabled and cooldown is active",
                    active.node_id
                ),
            ));
        }

        memory.consecutive_failures = 0;
        memory.last_switched_at = Some(now_unix_sec);
        memory.last_observed_active_node = Some(best.node_id.clone());
        return Ok(ArbiterDecision {
            group_id: group.id.clone(),
            action: ArbiterAction::SwitchNode,
            next_state: MultiGroupState::Healthy,
            target_node_id: Some(best.node_id.clone()),
            balance_candidate_ids: Vec::new(),
            should_close_old_connections: force_close_flag(group),
            shorten_reprobe_interval: false,
            trigger_adapter_refresh: false,
            escalated_since_rfc3339: None,
            reason: format!(
                "active node `{}` disconnected past threshold & cooldown; switched to `{}`",
                active.node_id, best.node_id
            ),
        });
    }

    // 3c. Active node is reachable (`ok == true`) but tripped a threshold trigger rule.
    if active.any_rule_triggered {
        memory.consecutive_failures = memory.consecutive_failures.saturating_add(1);
        let required = active.required_consecutive_failures.max(1);

        if memory.consecutive_failures < required {
            return Ok(keep_current_decision(
                group,
                keep_non_idle_state(group),
                format!(
                    "active node `{}` triggered threshold rule ({}/{} consecutive violations)",
                    active.node_id, memory.consecutive_failures, required
                ),
            ));
        }

        if is_in_cooldown(memory, group, now_unix_sec) {
            return Ok(keep_current_decision(
                group,
                keep_non_idle_state(group),
                format!(
                    "active node `{}` met {} consecutive violations but cooldown ({}s) is still active",
                    active.node_id, required, group.cooldown_sec
                ),
            ));
        }

        memory.consecutive_failures = 0;
        memory.last_switched_at = Some(now_unix_sec);
        memory.last_observed_active_node = Some(best.node_id.clone());
        return Ok(ArbiterDecision {
            group_id: group.id.clone(),
            action: ArbiterAction::SwitchNode,
            next_state: MultiGroupState::Healthy,
            target_node_id: Some(best.node_id.clone()),
            balance_candidate_ids: Vec::new(),
            should_close_old_connections: force_close_flag(group),
            shorten_reprobe_interval: false,
            trigger_adapter_refresh: false,
            escalated_since_rfc3339: None,
            reason: format!(
                "active node `{}` breached threshold for {} consecutive ticks; switched to `{}`",
                active.node_id, required, best.node_id
            ),
        });
    }

    // 3d. Active node is healthy and satisfies all gates & trigger thresholds.
    memory.consecutive_failures = 0;

    if best.node_id == active.node_id {
        return Ok(keep_current_decision(
            group,
            MultiGroupState::Healthy,
            format!("active node `{}` remains top healthy candidate", active.node_id),
        ));
    }

    // Another healthy candidate has a higher score -> enforce hysteresis and cooldown.
    let current_score = active.score.unwrap_or(f64::NEG_INFINITY);
    if !exceeds_hysteresis(best.score, current_score, group.hysteresis_pct) {
        return Ok(keep_current_decision(
            group,
            MultiGroupState::Healthy,
            format!(
                "candidate `{}` ({:.2}) does not exceed active `{}` ({:.2}) by hysteresis {:.1}%",
                best.node_id, best.score, active.node_id, current_score, group.hysteresis_pct
            ),
        ));
    }

    if is_in_cooldown(memory, group, now_unix_sec) {
        return Ok(keep_current_decision(
            group,
            MultiGroupState::Healthy,
            format!(
                "candidate `{}` beats hysteresis but switch is deferred by cooldown ({}s)",
                best.node_id, group.cooldown_sec
            ),
        ));
    }

    memory.last_switched_at = Some(now_unix_sec);
    memory.last_observed_active_node = Some(best.node_id.clone());
    Ok(ArbiterDecision {
        group_id: group.id.clone(),
        action: ArbiterAction::SwitchNode,
        next_state: MultiGroupState::Healthy,
        target_node_id: Some(best.node_id.clone()),
        balance_candidate_ids: Vec::new(),
        should_close_old_connections: force_close_flag(group),
        shorten_reprobe_interval: false,
        trigger_adapter_refresh: false,
        escalated_since_rfc3339: None,
        reason: format!(
            "candidate `{}` ({:.2}) exceeded active `{}` ({:.2}) past {:.1}% hysteresis; switching",
            best.node_id, best.score, active.node_id, current_score, group.hysteresis_pct
        ),
    })
}

/// Arbitration while `group` is in `MultiGroupState::Escalated` (borrowing from `fallback_pool_id`).
#[allow(clippy::too_many_arguments)]
fn decide_while_escalated(
    group: &MultiGroup,
    primary_report: &GroupEvaluationReport,
    nodes: &[ProxyNode],
    snapshots: &HashMap<String, ProbeSnapshot>,
    fallback_group: Option<&MultiGroup>,
    memory: &mut ArbiterGroupMemory,
    now_unix_sec: i64,
) -> CatResult<ArbiterDecision> {
    let escalated_ts = memory.escalated_since.unwrap_or(now_unix_sec);
    memory.escalated_since = Some(escalated_ts);
    let escalated_rfc3339 = format_rfc3339_ts(escalated_ts);

    let fallback_active_info =
        inspect_escalated_active_node(group, fallback_group, nodes, snapshots)?;
    let fallback_active_healthy = fallback_active_info
        .as_ref()
        .is_some_and(|info| info.ok && info.passed_hard_gates);

    if let Some(primary_best) = primary_report.healthy_candidates.first() {
        // If the borrowed fallback node itself failed/violated hard gates, recover immediately.
        if !fallback_active_healthy {
            memory.escalated_since = None;
            memory.primary_recovery_streak = 0;
            memory.consecutive_failures = 0;
            memory.last_switched_at = Some(now_unix_sec);
            memory.last_observed_active_node = Some(primary_best.node_id.clone());
            return Ok(ArbiterDecision {
                group_id: group.id.clone(),
                action: ArbiterAction::RecoverToPrimaryPool,
                next_state: MultiGroupState::Healthy,
                target_node_id: Some(primary_best.node_id.clone()),
                balance_candidate_ids: Vec::new(),
                should_close_old_connections: force_close_flag(group),
                shorten_reprobe_interval: false,
                trigger_adapter_refresh: false,
                escalated_since_rfc3339: None,
                reason: format!(
                    "borrowed fallback node unhealthy while primary `{}` recovered; returning immediately",
                    primary_best.node_id
                ),
            });
        }

        // Compare primary recovery candidate against the active borrowed node using hysteresis.
        let beats_hysteresis = match fallback_active_info {
            Some(ref fb_info) => {
                let effective_fb_score = if !fb_info.formula_uses_multiplier
                    && fb_info.multiplier > primary_best.multiplier
                    && fb_info.multiplier.is_finite()
                    && fb_info.multiplier > 0.0
                {
                    let ratio =
                        (primary_best.multiplier.max(0.25) / fb_info.multiplier).clamp(0.05, 1.0);
                    discount_borrowed_score(fb_info.score, ratio)
                } else {
                    fb_info.score
                };
                exceeds_hysteresis(primary_best.score, effective_fb_score, group.hysteresis_pct)
            }
            None => true,
        };

        if !beats_hysteresis {
            memory.primary_recovery_streak = 0;
            return Ok(ArbiterDecision {
                group_id: group.id.clone(),
                action: ArbiterAction::KeepCurrent,
                next_state: MultiGroupState::Escalated,
                target_node_id: group.active_node_id.clone(),
                balance_candidate_ids: Vec::new(),
                should_close_old_connections: false,
                shorten_reprobe_interval: true,
                trigger_adapter_refresh: false,
                escalated_since_rfc3339: Some(escalated_rfc3339),
                reason: format!(
                    "primary candidate `{}` healthy but below {:.1}% hysteresis margin; staying escalated",
                    primary_best.node_id, group.hysteresis_pct
                ),
            });
        }

        memory.primary_recovery_streak = memory.primary_recovery_streak.saturating_add(1);
        if memory.primary_recovery_streak < DEFAULT_RECOVERY_STREAK_REQUIRED {
            return Ok(ArbiterDecision {
                group_id: group.id.clone(),
                action: ArbiterAction::KeepCurrent,
                next_state: MultiGroupState::Escalated,
                target_node_id: group.active_node_id.clone(),
                balance_candidate_ids: Vec::new(),
                should_close_old_connections: false,
                shorten_reprobe_interval: true,
                trigger_adapter_refresh: false,
                escalated_since_rfc3339: Some(escalated_rfc3339),
                reason: format!(
                    "primary candidate `{}` met hysteresis ({}/{} consecutive recovery checks)",
                    primary_best.node_id,
                    memory.primary_recovery_streak,
                    DEFAULT_RECOVERY_STREAK_REQUIRED
                ),
            });
        }

        if is_in_cooldown(memory, group, now_unix_sec) {
            return Ok(ArbiterDecision {
                group_id: group.id.clone(),
                action: ArbiterAction::KeepCurrent,
                next_state: MultiGroupState::Escalated,
                target_node_id: group.active_node_id.clone(),
                balance_candidate_ids: Vec::new(),
                should_close_old_connections: false,
                shorten_reprobe_interval: true,
                trigger_adapter_refresh: false,
                escalated_since_rfc3339: Some(escalated_rfc3339),
                reason: format!(
                    "primary candidate `{}` ready to recover after {} checks, waiting for cooldown ({}s)",
                    primary_best.node_id, memory.primary_recovery_streak, group.cooldown_sec
                ),
            });
        }

        // Confirmed recovery -> return to primary low-multiplier pool and clear `escalated_since`.
        memory.escalated_since = None;
        memory.primary_recovery_streak = 0;
        memory.consecutive_failures = 0;
        memory.last_switched_at = Some(now_unix_sec);
        memory.last_observed_active_node = Some(primary_best.node_id.clone());
        return Ok(ArbiterDecision {
            group_id: group.id.clone(),
            action: ArbiterAction::RecoverToPrimaryPool,
            next_state: MultiGroupState::Healthy,
            target_node_id: Some(primary_best.node_id.clone()),
            balance_candidate_ids: Vec::new(),
            should_close_old_connections: force_close_flag(group),
            shorten_reprobe_interval: false,
            trigger_adapter_refresh: false,
            escalated_since_rfc3339: None,
            reason: format!(
                "primary pool recovered for {} consecutive checks above hysteresis; returned to `{}`",
                DEFAULT_RECOVERY_STREAK_REQUIRED, primary_best.node_id
            ),
        });
    }

    // Primary pool is still below threshold -> reset recovery streak and keep/re-pick fallback node.
    memory.primary_recovery_streak = 0;
    if fallback_active_healthy {
        return Ok(ArbiterDecision {
            group_id: group.id.clone(),
            action: ArbiterAction::KeepCurrent,
            next_state: MultiGroupState::Escalated,
            target_node_id: group.active_node_id.clone(),
            balance_candidate_ids: Vec::new(),
            should_close_old_connections: false,
            shorten_reprobe_interval: true,
            trigger_adapter_refresh: false,
            escalated_since_rfc3339: Some(escalated_rfc3339),
            reason: "primary pool still below threshold; maintaining active fallback node".into(),
        });
    }

    // Borrowed fallback node degraded/failed -> try picking another healthy fallback candidate.
    if let Some(fb_group) = fallback_group {
        let fb_report = evaluate_fallback_pool(group, fb_group, nodes, snapshots)?;
        if let Some(fb_best) = pick_best_candidate(&fb_report) {
            let changed = group.active_node_id.as_deref() != Some(fb_best.node_id.as_str());
            if changed {
                memory.last_switched_at = Some(now_unix_sec);
                memory.last_observed_active_node = Some(fb_best.node_id.clone());
            }
            return Ok(ArbiterDecision {
                group_id: group.id.clone(),
                action: if changed {
                    ArbiterAction::EscalateToFallbackPool
                } else {
                    ArbiterAction::KeepCurrent
                },
                next_state: MultiGroupState::Escalated,
                target_node_id: Some(fb_best.node_id.clone()),
                balance_candidate_ids: Vec::new(),
                should_close_old_connections: changed && force_close_flag(group),
                shorten_reprobe_interval: true,
                trigger_adapter_refresh: false,
                escalated_since_rfc3339: Some(escalated_rfc3339),
                reason: format!(
                    "previous fallback node unavailable; switched to fallback candidate `{}`",
                    fb_best.node_id
                ),
            });
        }
    }

    // Both primary and fallback pools failed -> drop escalation and fall back cleanly.
    memory.escalated_since = None;
    if group.fallback_policy == FallbackPolicy::StrictCircuitBreak
        && primary_report.all_failed_hard_gates
    {
        return Ok(emit_circuit_break(
            group,
            memory,
            now_unix_sec,
            "fallback pool exhausted and all primary candidates failed hard gates; circuit-breaking to REJECT",
        ));
    }

    if let Some(best_primary) = primary_report.gate_passed.first() {
        let changed = group.active_node_id.as_deref() != Some(best_primary.node_id.as_str());
        if changed {
            memory.last_switched_at = Some(now_unix_sec);
            memory.last_observed_active_node = Some(best_primary.node_id.clone());
        }
        Ok(ArbiterDecision {
            group_id: group.id.clone(),
            action: ArbiterAction::DegradeToBest,
            next_state: MultiGroupState::DegradedWarn,
            target_node_id: Some(best_primary.node_id.clone()),
            balance_candidate_ids: Vec::new(),
            should_close_old_connections: changed && force_close_flag(group),
            shorten_reprobe_interval: true,
            trigger_adapter_refresh: true,
            escalated_since_rfc3339: None,
            reason: format!(
                "fallback pool exhausted; degraded to best gate-passing primary node `{}`",
                best_primary.node_id
            ),
        })
    } else {
        Ok(ArbiterDecision {
            group_id: group.id.clone(),
            action: ArbiterAction::NoEligibleCandidate,
            next_state: MultiGroupState::DegradedWarn,
            target_node_id: None,
            balance_candidate_ids: Vec::new(),
            should_close_old_connections: false,
            shorten_reprobe_interval: true,
            trigger_adapter_refresh: true,
            escalated_since_rfc3339: None,
            reason: "fallback pool exhausted and no primary node passed hard gates".into(),
        })
    }
}

/// Three-way fallback for sticky/conditional modes when no primary candidate meets thresholds.
#[allow(clippy::too_many_arguments)]
fn decide_all_below_threshold_sticky(
    group: &MultiGroup,
    report: &GroupEvaluationReport,
    nodes: &[ProxyNode],
    snapshots: &HashMap<String, ProbeSnapshot>,
    fallback_group: Option<&MultiGroup>,
    memory: &mut ArbiterGroupMemory,
    now_unix_sec: i64,
) -> CatResult<ArbiterDecision> {
    // Hard-gate wipeout (e.g. every node failed anti-region-lock / cleanliness gate) is immediate.
    if report.all_failed_hard_gates {
        return match group.fallback_policy {
            FallbackPolicy::StrictCircuitBreak => Ok(emit_circuit_break(
                group,
                memory,
                now_unix_sec,
                "all candidates failed hard gates; strict circuit break to REJECT",
            )),
            FallbackPolicy::CrossPoolEscalate => {
                if let Some(fb_group) = fallback_group {
                    let fb_report = evaluate_fallback_pool(group, fb_group, nodes, snapshots)?;
                    if let Some(fb_best) = pick_best_candidate(&fb_report) {
                        return Ok(emit_escalate_sticky(
                            group,
                            fb_group,
                            fb_best,
                            memory,
                            now_unix_sec,
                            "all primary candidates failed hard gates",
                        ));
                    }
                }
                Ok(ArbiterDecision {
                    group_id: group.id.clone(),
                    action: ArbiterAction::NoEligibleCandidate,
                    next_state: MultiGroupState::DegradedWarn,
                    target_node_id: None,
                    balance_candidate_ids: Vec::new(),
                    should_close_old_connections: false,
                    shorten_reprobe_interval: true,
                    trigger_adapter_refresh: true,
                    escalated_since_rfc3339: None,
                    reason: "all primary candidates failed hard gates and no fallback candidate passed hard gates".into(),
                })
            }
            FallbackPolicy::DegradeBestWarn => Ok(ArbiterDecision {
                group_id: group.id.clone(),
                action: ArbiterAction::NoEligibleCandidate,
                next_state: MultiGroupState::DegradedWarn,
                target_node_id: None,
                balance_candidate_ids: Vec::new(),
                should_close_old_connections: false,
                shorten_reprobe_interval: true,
                trigger_adapter_refresh: true,
                escalated_since_rfc3339: None,
                reason: "all candidates failed hard gates; refusing to route through blocked nodes".into(),
            }),
        };
    }

    // Some nodes pass hard gates, but all are below trigger thresholds (or disconnected).
    // Respect consecutive-failure debouncing & cooldown if the active node is still gate-passing
    // and reachable (and group is not already in `DegradedWarn`).
    if group.state != MultiGroupState::DegradedWarn {
        if let Some(ref active) = report.active_assessment {
            if active.in_candidate_pool && active.passed_hard_gates {
                if active.is_disconnected {
                    memory.consecutive_failures = memory.consecutive_failures.saturating_add(1);
                    if !active.bypass_cooldown {
                        let required = active.required_consecutive_failures.max(1);
                        if memory.consecutive_failures < required {
                            return Ok(keep_current_decision(
                                group,
                                keep_non_idle_state(group),
                                format!(
                                    "all candidates below threshold; active `{}` disconnect debounce {}/{}",
                                    active.node_id, memory.consecutive_failures, required
                                ),
                            ));
                        }
                        if is_in_cooldown(memory, group, now_unix_sec) {
                            return Ok(keep_current_decision(
                                group,
                                keep_non_idle_state(group),
                                format!(
                                    "all candidates below threshold; fallback deferred by cooldown ({}s)",
                                    group.cooldown_sec
                                ),
                            ));
                        }
                    }
                } else if active.any_rule_triggered {
                    memory.consecutive_failures = memory.consecutive_failures.saturating_add(1);
                    let required = active.required_consecutive_failures.max(1);
                    if memory.consecutive_failures < required {
                        return Ok(keep_current_decision(
                            group,
                            keep_non_idle_state(group),
                            format!(
                                "all candidates below threshold; awaiting {}/{} consecutive failures before fallback",
                                memory.consecutive_failures, required
                            ),
                        ));
                    }
                    if is_in_cooldown(memory, group, now_unix_sec) {
                        return Ok(keep_current_decision(
                            group,
                            keep_non_idle_state(group),
                            format!(
                                "all candidates below threshold; fallback deferred by cooldown ({}s)",
                                group.cooldown_sec
                            ),
                        ));
                    }
                }
            }
        }
    }

    // Debounce & cooldown cleared -> execute the configured 3-way fallback policy.
    match group.fallback_policy {
        FallbackPolicy::DegradeBestWarn => {
            let best = &report.gate_passed[0];
            Ok(emit_degrade_sticky(
                group,
                best,
                memory,
                now_unix_sec,
                "all candidates below threshold; degraded to best gate-passing node with alert",
            ))
        }
        FallbackPolicy::CrossPoolEscalate => {
            if let Some(fb_group) = fallback_group {
                let fb_report = evaluate_fallback_pool(group, fb_group, nodes, snapshots)?;
                if let Some(fb_best) = pick_best_candidate(&fb_report) {
                    return Ok(emit_escalate_sticky(
                        group,
                        fb_group,
                        fb_best,
                        memory,
                        now_unix_sec,
                        "all primary candidates below threshold",
                    ));
                }
            }
            let best = &report.gate_passed[0];
            Ok(emit_degrade_sticky(
                group,
                best,
                memory,
                now_unix_sec,
                "fallback pool unavailable or empty; degraded to best gate-passing primary node",
            ))
        }
        FallbackPolicy::StrictCircuitBreak => {
            // Hard gates passed across `gate_passed`; only performance thresholds missed.
            // Preserve connectivity using best gate-passing node while raising warning alerts.
            let best = &report.gate_passed[0];
            Ok(emit_degrade_sticky(
                group,
                best,
                memory,
                now_unix_sec,
                "all candidates below performance threshold while satisfying hard gates; degraded with alert",
            ))
        }
    }
}

// ============================================================================
// Internal helpers
// ============================================================================

struct EscalatedActiveInfo {
    ok: bool,
    passed_hard_gates: bool,
    score: f64,
    multiplier: f64,
    formula_uses_multiplier: bool,
}

fn compile_hard_gates(raw_gates: &[String]) -> CatResult<Vec<(String, FormulaExpr)>> {
    let mut compiled = Vec::with_capacity(raw_gates.len());
    for raw in raw_gates {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            compiled.push((trimmed.to_string(), FormulaExpr::parse(trimmed)?));
        }
    }
    Ok(compiled)
}

fn inspect_escalated_active_node(
    group: &MultiGroup,
    fallback_group: Option<&MultiGroup>,
    nodes: &[ProxyNode],
    snapshots: &HashMap<String, ProbeSnapshot>,
) -> CatResult<Option<EscalatedActiveInfo>> {
    let Some(active_id) = group.active_node_id.as_deref().map(str::trim) else {
        return Ok(None);
    };
    if active_id.is_empty() || active_id == BUILTIN_REJECT_TARGET {
        return Ok(None);
    }
    let Some(node) = nodes.iter().find(|n| n.id == active_id && n.enabled) else {
        return Ok(None);
    };

    let snap = snapshots.get(&node.id);
    let ctx = build_eval_context_for_probe(node, snap, group.primary_probe_id.as_deref());
    let primary_gates = compile_hard_gates(&group.hard_gates)?;
    let mut passed_hard_gates = evaluate_hard_gates(&primary_gates, &ctx, snap)?.is_empty();
    if passed_hard_gates {
        if let Some(fb_group) = fallback_group {
            let fb_ctx =
                build_eval_context_for_probe(node, snap, fb_group.primary_probe_id.as_deref());
            let fb_gates = compile_hard_gates(&fb_group.hard_gates)?;
            passed_hard_gates = evaluate_hard_gates(&fb_gates, &fb_ctx, snap)?.is_empty();
        }
    }
    let (score, formula_uses_multiplier) = score_node_with_group_formula(group, node, snap)?;

    Ok(Some(EscalatedActiveInfo {
        ok: ctx.ok,
        passed_hard_gates,
        score,
        multiplier: ctx.multiplier,
        formula_uses_multiplier,
    }))
}

/// Evaluate a fallback pool while inheriting primary hard gates so red-line rules are never bypassed.
fn evaluate_fallback_pool(
    primary: &MultiGroup,
    fallback: &MultiGroup,
    nodes: &[ProxyNode],
    snapshots: &HashMap<String, ProbeSnapshot>,
) -> CatResult<GroupEvaluationReport> {
    let mut effective = fallback.clone();
    for gate in &primary.hard_gates {
        let trimmed = gate.trim();
        if !trimmed.is_empty() && !effective.hard_gates.iter().any(|g| g.trim() == trimmed) {
            effective.hard_gates.push(trimmed.to_string());
        }
    }
    if effective.formula_expr.trim().is_empty() {
        effective.formula_expr = primary.formula_expr.clone();
    }
    if effective.primary_probe_id.is_none() {
        effective.primary_probe_id = primary.primary_probe_id.clone();
    }
    evaluate_group_candidates(&effective, nodes, snapshots)
}

fn pick_best_candidate(report: &GroupEvaluationReport) -> Option<&EvaluatedCandidate> {
    report
        .healthy_candidates
        .first()
        .or_else(|| report.gate_passed.first())
}

fn emit_degrade_sticky(
    group: &MultiGroup,
    best: &EvaluatedCandidate,
    memory: &mut ArbiterGroupMemory,
    now_unix_sec: i64,
    reason: &str,
) -> ArbiterDecision {
    let target_changed = group.active_node_id.as_deref() != Some(best.node_id.as_str());
    memory.consecutive_failures = 0;
    if target_changed {
        memory.last_switched_at = Some(now_unix_sec);
        memory.last_observed_active_node = Some(best.node_id.clone());
    }
    ArbiterDecision {
        group_id: group.id.clone(),
        action: ArbiterAction::DegradeToBest,
        next_state: MultiGroupState::DegradedWarn,
        target_node_id: Some(best.node_id.clone()),
        balance_candidate_ids: Vec::new(),
        should_close_old_connections: target_changed && force_close_flag(group),
        shorten_reprobe_interval: true,
        trigger_adapter_refresh: true,
        escalated_since_rfc3339: None,
        reason: format!("{} (`{}`)", reason, best.node_id),
    }
}

fn emit_escalate_sticky(
    group: &MultiGroup,
    fb_group: &MultiGroup,
    fb_best: &EvaluatedCandidate,
    memory: &mut ArbiterGroupMemory,
    now_unix_sec: i64,
    cause: &str,
) -> ArbiterDecision {
    let target_changed = group.active_node_id.as_deref() != Some(fb_best.node_id.as_str());
    memory.escalated_since = Some(now_unix_sec);
    memory.primary_recovery_streak = 0;
    memory.consecutive_failures = 0;
    memory.last_switched_at = Some(now_unix_sec);
    memory.last_observed_active_node = Some(fb_best.node_id.clone());

    ArbiterDecision {
        group_id: group.id.clone(),
        action: ArbiterAction::EscalateToFallbackPool,
        next_state: MultiGroupState::Escalated,
        target_node_id: Some(fb_best.node_id.clone()),
        balance_candidate_ids: Vec::new(),
        should_close_old_connections: target_changed && force_close_flag(group),
        shorten_reprobe_interval: true,
        trigger_adapter_refresh: false,
        escalated_since_rfc3339: Some(format_rfc3339_ts(now_unix_sec)),
        reason: format!(
            "{}; escalated to `{}` from fallback pool `{}`",
            cause, fb_best.node_id, fb_group.id
        ),
    }
}

/// Apply a cost-multiplier discount ratio (`0 < ratio <= 1`) to a borrowed fallback node's score.
/// Positive scores scale down by `* ratio`; negative scores amplify the penalty via `/ ratio`
/// so cost penalization remains strictly monotonic and never inverts for negative-scoring formulas.
fn discount_borrowed_score(score: f64, ratio: f64) -> f64 {
    if !score.is_finite() {
        return score;
    }
    let clamped = ratio.clamp(0.05, 1.0);
    if score > 0.0 {
        score * clamped
    } else if score < 0.0 {
        score / clamped.max(0.01)
    } else {
        // Normalize both +0.0 and -0.0 cleanly at the zero boundary.
        0.0
    }
}

fn emit_circuit_break(
    group: &MultiGroup,
    memory: &mut ArbiterGroupMemory,
    now_unix_sec: i64,
    reason: &str,
) -> ArbiterDecision {
    let is_load_balance = matches!(
        group.mode,
        MultiGroupMode::LoadBalanceConsistentHash | MultiGroupMode::LoadBalanceRoundRobin
    );
    let already_circuit_open = group.state == MultiGroupState::CircuitOpen
        && (is_load_balance || group.active_node_id.as_deref() == Some(BUILTIN_REJECT_TARGET));

    memory.escalated_since = None;
    memory.primary_recovery_streak = 0;
    memory.consecutive_failures = 0;
    memory.last_observed_active_node = Some(BUILTIN_REJECT_TARGET.to_string());
    memory.last_balance_pool.clear();

    if already_circuit_open {
        // Steady-state CircuitOpen: keep REJECT active without repeatedly tearing down
        // connections or flooding adapter refreshes on every arbitration tick.
        return ArbiterDecision {
            group_id: group.id.clone(),
            action: ArbiterAction::KeepCurrent,
            next_state: MultiGroupState::CircuitOpen,
            target_node_id: Some(BUILTIN_REJECT_TARGET.to_string()),
            balance_candidate_ids: Vec::new(),
            should_close_old_connections: false,
            shorten_reprobe_interval: true,
            trigger_adapter_refresh: false,
            escalated_since_rfc3339: None,
            reason: format!("circuit breaker remains open: {reason}"),
        };
    }

    memory.last_switched_at = Some(now_unix_sec);

    ArbiterDecision {
        group_id: group.id.clone(),
        action: ArbiterAction::CircuitBreakToReject,
        next_state: MultiGroupState::CircuitOpen,
        target_node_id: Some(BUILTIN_REJECT_TARGET.to_string()),
        balance_candidate_ids: Vec::new(),
        // Entering hard circuit break ALWAYS severs old connections regardless of `switch_mode`.
        should_close_old_connections: true,
        shorten_reprobe_interval: true,
        trigger_adapter_refresh: true,
        escalated_since_rfc3339: None,
        reason: reason.to_string(),
    }
}

fn keep_current_decision(
    group: &MultiGroup,
    next_state: MultiGroupState,
    reason: String,
) -> ArbiterDecision {
    ArbiterDecision {
        group_id: group.id.clone(),
        action: ArbiterAction::KeepCurrent,
        next_state,
        target_node_id: group.active_node_id.clone(),
        balance_candidate_ids: Vec::new(),
        should_close_old_connections: false,
        shorten_reprobe_interval: false,
        trigger_adapter_refresh: false,
        escalated_since_rfc3339: None,
        reason,
    }
}

#[inline]
fn keep_non_idle_state(group: &MultiGroup) -> MultiGroupState {
    if group.state == MultiGroupState::Idle {
        MultiGroupState::Healthy
    } else {
        group.state.clone()
    }
}

#[inline]
fn force_close_flag(group: &MultiGroup) -> bool {
    matches!(group.switch_mode, SwitchMode::ForceCloseOld)
}

#[inline]
fn is_in_cooldown(memory: &ArbiterGroupMemory, group: &MultiGroup, now_unix_sec: i64) -> bool {
    if group.cooldown_sec == 0 {
        return false;
    }
    match memory.last_switched_at {
        Some(last) => {
            let elapsed = now_unix_sec.saturating_sub(last);
            elapsed >= 0 && (elapsed as u64) < group.cooldown_sec
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        FallbackPolicy, MultiGroup, MultiGroupMode, MultiGroupState, ProbeSnapshot, ProxyNode,
        SwitchMode,
    };

    fn test_node(id: &str, multiplier: f64) -> ProxyNode {
        ProxyNode {
            id: id.to_string(),
            sub_id: "sub-1".to_string(),
            name: format!("Node-{id}"),
            protocol: "trojan".to_string(),
            server: "198.51.100.10".to_string(),
            port: 443,
            region_code: "JP".to_string(),
            multiplier,
            is_443_native: true,
            enabled: true,
            ..Default::default()
        }
    }

    fn test_snap(node_id: &str, ok: bool, ping_ms: f64, google_clean: bool) -> ProbeSnapshot {
        ProbeSnapshot {
            node_id: node_id.to_string(),
            tested_at: "2026-11-22T00:00:00Z".to_string(),
            ok,
            latency_ms: Some(ping_ms),
            jitter_ms: Some(2.0),
            loss_pct: Some(if ok { 0.0 } else { 100.0 }),
            up_mbps: Some(if ok { 20.0 } else { 0.0 }),
            down_mbps: Some(if ok { 100.0 } else { 0.0 }),
            google_clean: Some(google_clean),
            keepalive_60s_ok: Some(ok),
            ..Default::default()
        }
    }

    #[test]
    fn negative_score_discount_penalizes_monotonically_without_inversion() {
        // Positive scores decrease under ratio < 1.
        assert!((discount_borrowed_score(90.0, 1.0 / 3.0) - 30.0).abs() < 1e-9);
        // Zero boundary stays cleanly at +0.0.
        assert_eq!(discount_borrowed_score(0.0, 0.25), 0.0);
        assert_eq!(discount_borrowed_score(-0.0, 0.25).to_bits(), 0.0f64.to_bits());
        // Negative scores amplify penalty (become more negative, never higher).
        assert!((discount_borrowed_score(-90.0, 1.0 / 3.0) - (-270.0)).abs() < 1e-9);
        assert!(discount_borrowed_score(-90.0, 0.5) < -90.0);

        // End-to-end escalated recovery with a negative-scoring custom formula (`-ping_ms`):
        // primary 1x node (-60) must beat borrowed 3x node (-50, penalized to -150).
        let nodes = vec![test_node("p1", 1.0), test_node("fb1", 3.0)];
        let mut snaps = HashMap::new();
        snaps.insert("p1".into(), test_snap("p1", true, 60.0, true));
        snaps.insert("fb1".into(), test_snap("fb1", true, 50.0, true));

        let primary = MultiGroup {
            id: "grp-neg".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec!["p1".into()],
            formula_expr: "-ping_ms".to_string(),
            fallback_policy: FallbackPolicy::CrossPoolEscalate,
            fallback_pool_id: Some("grp-fb".into()),
            hysteresis_pct: 20.0,
            cooldown_sec: 0,
            active_node_id: Some("fb1".into()),
            state: MultiGroupState::Escalated,
            escalated_since: Some("2026-11-22T00:00:00Z".into()),
            ..Default::default()
        };
        let fallback = MultiGroup {
            id: "grp-fb".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec!["fb1".into()],
            formula_expr: "-ping_ms".to_string(),
            ..Default::default()
        };

        let mut mem = ArbiterGroupMemory {
            escalated_since: Some(1000),
            last_observed_active_node: Some("fb1".into()),
            ..Default::default()
        };

        let d1 = decide_group_action(&primary, &nodes, &snaps, Some(&fallback), &mut mem, 1100)
            .unwrap();
        assert_eq!(d1.action, ArbiterAction::KeepCurrent);
        assert_eq!(mem.primary_recovery_streak, 1);

        let d2 = decide_group_action(&primary, &nodes, &snaps, Some(&fallback), &mut mem, 1160)
            .unwrap();
        assert_eq!(d2.action, ArbiterAction::RecoverToPrimaryPool);
        assert_eq!(d2.next_state, MultiGroupState::Healthy);
        assert_eq!(d2.target_node_id.as_deref(), Some("p1"));
    }

    #[test]
    fn restarted_escalated_load_balance_recomputes_top_k_instead_of_empty_pool() {
        let nodes = vec![
            test_node("p1", 1.0),
            test_node("p2", 1.0),
            test_node("p3", 1.0),
            test_node("p4", 1.0),
            test_node("p5", 1.0),
            test_node("p6", 1.0),
        ];
        let mut snaps = HashMap::new();
        // Lower ping -> higher score under `-ping_ms`: p3 (10ms) > p1 (20ms) > p6 (30ms) > p2 (40ms) > p5 (50ms) > p4 (60ms)
        snaps.insert("p1".into(), test_snap("p1", true, 20.0, true));
        snaps.insert("p2".into(), test_snap("p2", true, 40.0, true));
        snaps.insert("p3".into(), test_snap("p3", true, 10.0, true));
        snaps.insert("p4".into(), test_snap("p4", true, 60.0, true));
        snaps.insert("p5".into(), test_snap("p5", true, 50.0, true));
        snaps.insert("p6".into(), test_snap("p6", true, 30.0, true));

        let lb_group = MultiGroup {
            id: "grp-lb-restarted".to_string(),
            mode: MultiGroupMode::LoadBalanceConsistentHash,
            member_node_ids: vec![
                "p1".into(),
                "p2".into(),
                "p3".into(),
                "p4".into(),
                "p5".into(),
                "p6".into(),
            ],
            formula_expr: "-ping_ms".to_string(),
            fallback_policy: FallbackPolicy::CrossPoolEscalate,
            state: MultiGroupState::Escalated,
            escalated_since: Some("2026-11-22T00:00:00Z".into()),
            cooldown_sec: 0,
            ..Default::default()
        };

        // Fresh memory simulates process restart (`last_balance_pool` is empty).
        let mut mem = ArbiterGroupMemory::default();
        let d1 = decide_group_action(&lb_group, &nodes, &snaps, None, &mut mem, 2000).unwrap();
        assert_eq!(d1.action, ArbiterAction::KeepCurrent);
        assert_eq!(d1.next_state, MultiGroupState::Escalated);
        assert_eq!(
            d1.balance_candidate_ids,
            vec!["p3", "p1", "p6", "p2", "p5"],
            "restarted escalated LB group must emit top-K healthy primary candidates instead of an empty list"
        );
    }

    #[test]
    fn steady_state_circuit_open_suppresses_repeated_connection_kicks_and_adapter_refreshes() {
        let nodes = vec![test_node("n1", 1.0), test_node("n2", 1.0)];
        let mut snaps = HashMap::new();
        snaps.insert("n1".into(), test_snap("n1", true, 30.0, false));
        snaps.insert("n2".into(), test_snap("n2", true, 35.0, false));

        // 1. StickyBest: first entry triggers kick + refresh; steady-state tick suppresses both.
        let mut sticky = MultiGroup {
            id: "grp-strict-sticky".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec!["n1".into(), "n2".into()],
            hard_gates: vec!["google_clean == 1".into()],
            fallback_policy: FallbackPolicy::StrictCircuitBreak,
            switch_mode: SwitchMode::GracefulNewOnly,
            active_node_id: Some("n1".into()),
            state: MultiGroupState::Healthy,
            ..Default::default()
        };

        let mut mem = ArbiterGroupMemory::default();
        let enter = decide_group_action(&sticky, &nodes, &snaps, None, &mut mem, 3000).unwrap();
        assert_eq!(enter.action, ArbiterAction::CircuitBreakToReject);
        assert_eq!(enter.next_state, MultiGroupState::CircuitOpen);
        assert!(enter.should_close_old_connections);
        assert!(enter.trigger_adapter_refresh);
        assert!(enter.shorten_reprobe_interval);
        assert_eq!(mem.last_switched_at, Some(3000));
        apply_decision_to_group(&mut sticky, &enter);

        let steady = decide_group_action(&sticky, &nodes, &snaps, None, &mut mem, 3010).unwrap();
        assert_eq!(steady.action, ArbiterAction::KeepCurrent);
        assert_eq!(steady.next_state, MultiGroupState::CircuitOpen);
        assert_eq!(steady.target_node_id.as_deref(), Some(BUILTIN_REJECT_TARGET));
        assert!(!steady.should_close_old_connections);
        assert!(!steady.trigger_adapter_refresh);
        assert!(steady.shorten_reprobe_interval);
        assert_eq!(mem.last_switched_at, Some(3000));

        // 2. LoadBalance: first entry triggers kick + refresh; steady-state tick suppresses both.
        let mut lb = MultiGroup {
            id: "grp-strict-lb".to_string(),
            mode: MultiGroupMode::LoadBalanceRoundRobin,
            member_node_ids: vec!["n1".into(), "n2".into()],
            hard_gates: vec!["google_clean == 1".into()],
            fallback_policy: FallbackPolicy::StrictCircuitBreak,
            switch_mode: SwitchMode::ForceCloseOld,
            state: MultiGroupState::Healthy,
            ..Default::default()
        };

        let mut lb_mem = ArbiterGroupMemory::default();
        let lb_enter = decide_group_action(&lb, &nodes, &snaps, None, &mut lb_mem, 4000).unwrap();
        assert_eq!(lb_enter.action, ArbiterAction::CircuitBreakToReject);
        assert!(lb_enter.should_close_old_connections);
        assert!(lb_enter.trigger_adapter_refresh);
        apply_decision_to_group(&mut lb, &lb_enter);

        let lb_steady = decide_group_action(&lb, &nodes, &snaps, None, &mut lb_mem, 4010).unwrap();
        assert_eq!(lb_steady.action, ArbiterAction::KeepCurrent);
        assert_eq!(lb_steady.next_state, MultiGroupState::CircuitOpen);
        assert!(!lb_steady.should_close_old_connections);
        assert!(!lb_steady.trigger_adapter_refresh);
        assert!(lb_steady.shorten_reprobe_interval);
    }

    #[test]
    fn escalated_active_node_inspection_uses_shared_hard_gate_untested_semantics() {
        let nodes = vec![test_node("p1", 1.0), test_node("fb1", 3.0)];

        // Case 1: Borrowed fallback node `fb1` has never been tested for `keepalive_60s_ok` or
        // `ip_clean` (both `None`). Shared `evaluate_hard_gates` must NOT falsely reject it.
        let mut snaps_untested = HashMap::new();
        snaps_untested.insert("p1".into(), test_snap("p1", false, 999.0, true));
        let mut fb_untested = test_snap("fb1", true, 40.0, true);
        fb_untested.keepalive_60s_ok = None;
        fb_untested.ip_clean = None;
        snaps_untested.insert("fb1".into(), fb_untested);

        let primary = MultiGroup {
            id: "grp-wsf-main".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec!["p1".into()],
            hard_gates: vec!["keepalive_ok == 1 && ip_clean == 1".to_string()],
            formula_expr: "-ping_ms".to_string(),
            fallback_policy: FallbackPolicy::CrossPoolEscalate,
            fallback_pool_id: Some("grp-wsf-fb".into()),
            active_node_id: Some("fb1".into()),
            state: MultiGroupState::Escalated,
            escalated_since: Some("2026-11-28T00:00:00Z".into()),
            cooldown_sec: 0,
            ..Default::default()
        };
        let fallback = MultiGroup {
            id: "grp-wsf-fb".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec!["fb1".into()],
            hard_gates: vec!["google_clean == 1 && ip_clean == 1".to_string()],
            formula_expr: "-ping_ms".to_string(),
            ..Default::default()
        };

        let info_untested = inspect_escalated_active_node(
            &primary,
            Some(&fallback),
            &nodes,
            &snaps_untested,
        )
        .unwrap()
        .expect("active fallback node info");
        assert!(
            info_untested.passed_hard_gates,
            "untested keepalive_60s_ok/ip_clean must pass via shared evaluate_hard_gates"
        );

        // Case 2: Once `ip_clean` is measured `Some(false)`, shared `evaluate_hard_gates` MUST
        // reject the escalated active node strictly.
        let mut snaps_dirty_ip = snaps_untested;
        snaps_dirty_ip.get_mut("fb1").unwrap().ip_clean = Some(false);
        let info_dirty = inspect_escalated_active_node(
            &primary,
            Some(&fallback),
            &nodes,
            &snaps_dirty_ip,
        )
        .unwrap()
        .expect("active fallback node info");
        assert!(
            !info_dirty.passed_hard_gates,
            "explicit ip_clean == Some(false) must fail shared hard-gate evaluation"
        );
    }
}
