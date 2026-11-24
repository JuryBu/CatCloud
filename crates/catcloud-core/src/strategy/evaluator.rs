//! Per-node evaluation context builder, dynamic filter engine, and multi-group candidate evaluator.

use crate::error::CatResult;
use crate::models::{
    DEFAULT_COST_EFFECTIVE_FORMULA, DynamicFilterSpec, MultiGroup, MultiGroupMode, ProbeSnapshot,
    ProxyNode, TriggerRule,
};
use crate::strategy::formula::{DEFAULT_MISSING_PING_MS, EvalContext, FormulaExpr};
use crate::strategy::health_pool::{NodeHealthPool, RuntimeDualHealth, RuntimeNodeHealth};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::time::Instant;

/// Build a formula [`EvalContext`] from a node record and its optional latest probe snapshot.
pub fn build_eval_context(node: &ProxyNode, snapshot: Option<&ProbeSnapshot>) -> EvalContext {
    build_eval_context_for_probe(node, snapshot, None)
}

/// Build a formula [`EvalContext`] while prioritizing a group's `primary_probe_id` when present.
pub fn build_eval_context_for_probe(
    node: &ProxyNode,
    snapshot: Option<&ProbeSnapshot>,
    primary_probe_id: Option<&str>,
) -> EvalContext {
    let multiplier = if node.multiplier.is_finite() && node.multiplier >= 0.0 {
        node.multiplier
    } else {
        1.0
    };

    let Some(snap) = snapshot else {
        return EvalContext {
            up_mbps: 0.0,
            down_mbps: 0.0,
            ping_ms: DEFAULT_MISSING_PING_MS,
            jitter_ms: 0.0,
            loss_pct: 100.0,
            multiplier,
            keepalive_ok: false,
            google_clean: false,
            unlocked: false,
            is_443_native: node.is_443_native,
            ok: false,
            per_probe_up_mbps: HashMap::new(),
            per_probe_down_mbps: HashMap::new(),
            per_probe_ping_ms: HashMap::new(),
            per_probe_ok: HashMap::new(),
            unlocked_sites: HashMap::new(),
        };
    };

    let primary_id = primary_probe_id
        .map(str::trim)
        .filter(|id| !id.is_empty());

    let ok = primary_id
        .and_then(|pid| snap.per_probe_ok.get(pid).copied())
        .unwrap_or(snap.ok);

    let up_mbps = primary_id
        .and_then(|pid| snap.per_probe_up_mbps.get(pid).copied())
        .filter(|v| v.is_finite())
        .or_else(|| snap.up_mbps.filter(|v| v.is_finite()))
        .unwrap_or(0.0);

    let down_mbps = primary_id
        .and_then(|pid| snap.per_probe_down_mbps.get(pid).copied())
        .filter(|v| v.is_finite())
        .or_else(|| snap.down_mbps.filter(|v| v.is_finite()))
        .unwrap_or(0.0);

    let ping_ms = primary_id
        .and_then(|pid| snap.per_probe_ping_ms.get(pid).copied())
        .filter(|v| v.is_finite())
        .or_else(|| snap.latency_ms.filter(|v| v.is_finite()))
        .unwrap_or(if ok { 0.0 } else { DEFAULT_MISSING_PING_MS });

    let jitter_ms = snap.jitter_ms.filter(|v| v.is_finite()).unwrap_or(0.0);
    let loss_pct = snap
        .loss_pct
        .filter(|v| v.is_finite())
        .unwrap_or(if ok { 0.0 } else { 100.0 });

    let keepalive_ok = snap.keepalive_60s_ok.unwrap_or(false);
    let google_clean = snap.google_clean.unwrap_or(false);
    let unlocked = !snap.unlocked_sites.is_empty() && snap.unlocked_sites.values().all(|&v| v);

    EvalContext {
        up_mbps,
        down_mbps,
        ping_ms,
        jitter_ms,
        loss_pct,
        multiplier,
        keepalive_ok,
        google_clean,
        unlocked,
        is_443_native: node.is_443_native,
        ok,
        per_probe_up_mbps: snap.per_probe_up_mbps.clone(),
        per_probe_down_mbps: snap.per_probe_down_mbps.clone(),
        per_probe_ping_ms: snap.per_probe_ping_ms.clone(),
        per_probe_ok: snap.per_probe_ok.clone(),
        unlocked_sites: snap.unlocked_sites.clone(),
    }
}

/// Evaluate whether a node matches all constraints in a [`DynamicFilterSpec`].
pub fn evaluate_dynamic_filter(
    node: &ProxyNode,
    snap: Option<&ProbeSnapshot>,
    filter: &DynamicFilterSpec,
) -> CatResult<bool> {
    let parsed_expr = match filter.expr.as_deref().map(str::trim) {
        Some(raw) if !raw.is_empty() => Some(FormulaExpr::parse(raw)?),
        _ => None,
    };
    let ctx = build_eval_context(node, snap);
    evaluate_dynamic_filter_preparsed(node, snap, filter, parsed_expr.as_ref(), &ctx)
}

fn evaluate_dynamic_filter_preparsed(
    node: &ProxyNode,
    snap: Option<&ProbeSnapshot>,
    filter: &DynamicFilterSpec,
    parsed_expr: Option<&FormulaExpr>,
    ctx: &EvalContext,
) -> CatResult<bool> {
    if !node.enabled {
        return Ok(false);
    }

    if !filter.sub_ids.is_empty() {
        let matched = filter
            .sub_ids
            .iter()
            .any(|sid| sid.trim() == node.sub_id.as_str());
        if !matched {
            return Ok(false);
        }
    }

    if !filter.region_codes.is_empty() {
        let matched = filter
            .region_codes
            .iter()
            .any(|rc| rc.trim().eq_ignore_ascii_case(node.region_code.trim()));
        if !matched {
            return Ok(false);
        }
    }

    if let Some(max_mult) = filter.max_multiplier {
        if max_mult.is_finite() && (!node.multiplier.is_finite() || node.multiplier > max_mult + 1e-9) {
            return Ok(false);
        }
    }

    if !filter.protocols.is_empty() {
        let matched = filter
            .protocols
            .iter()
            .any(|p| p.trim().eq_ignore_ascii_case(node.protocol.trim()));
        if !matched {
            return Ok(false);
        }
    }

    if filter.require_google_clean {
        let clean = snap.and_then(|s| s.google_clean).unwrap_or(false);
        if !clean {
            return Ok(false);
        }
    }

    if let Some(req_443) = filter.require_443_native {
        if node.is_443_native != req_443 {
            return Ok(false);
        }
    }

    if let Some(expr) = parsed_expr {
        if !expr.eval_bool(ctx)? {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Evaluation outcome for one candidate node within a multi-group.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvaluatedCandidate {
    pub node_id: String,
    pub node_name: String,
    pub region_code: String,
    pub multiplier: f64,
    pub ok: bool,
    pub passed_hard_gates: bool,
    pub failed_hard_gates: Vec<String>,
    /// True when the candidate is `ok == true` and does not trip any `trigger_rules`.
    pub meets_thresholds: bool,
    /// Indices into `group.trigger_rules` that evaluated to `true` for this node.
    pub triggered_rule_indices: Vec<usize>,
    pub score: f64,
}

/// Evaluation record of a single [`TriggerRule`] against the currently active node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TriggerRuleHit {
    pub rule_index: usize,
    pub expr: String,
    pub triggered: bool,
    pub consecutive_failures_required: u32,
    pub bypass_cooldown_on_disconnect: bool,
}

/// Detailed health & threshold assessment for the currently active node of a group.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActiveNodeAssessment {
    pub node_id: String,
    pub in_candidate_pool: bool,
    pub passed_hard_gates: bool,
    pub failed_hard_gates: Vec<String>,
    pub score: Option<f64>,
    pub is_disconnected: bool,
    pub triggered_rules: Vec<TriggerRuleHit>,
    pub any_rule_triggered: bool,
    /// Minimum `consecutive_failures` across triggered rules (clamped to `>= 1`).
    pub required_consecutive_failures: u32,
    /// True when disconnected and disconnect cooldown bypass is enabled.
    pub bypass_cooldown: bool,
}

/// Complete candidate ranking and active-node diagnostic report for a [`MultiGroup`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GroupEvaluationReport {
    pub group_id: String,
    pub mode: MultiGroupMode,
    /// Number of nodes entering this group after membership and dynamic filter selection.
    pub pool_size: usize,
    /// Candidates passing all hard gates, sorted by score descending (NaN last, tie-break by `node_id` asc).
    pub gate_passed: Vec<EvaluatedCandidate>,
    /// Subset of `gate_passed` that are `ok` and pass all threshold trigger rules, sorted identically.
    pub healthy_candidates: Vec<EvaluatedCandidate>,
    /// Pool candidates rejected by one or more hard gates (for diagnostics / UI).
    pub gate_rejected: Vec<EvaluatedCandidate>,
    /// Assessment of `group.active_node_id`, when configured.
    pub active_assessment: Option<ActiveNodeAssessment>,
    /// True when no candidate passed all hard gates.
    pub all_failed_hard_gates: bool,
    /// True when no candidate is both gate-passing and above all trigger thresholds.
    pub all_below_threshold: bool,
}

struct CompiledTrigger<'a> {
    index: usize,
    rule: &'a TriggerRule,
    expr: FormulaExpr,
}

/// Evaluate a [`MultiGroup`] against the current node inventory and latest probe snapshots.
///
/// Steps performed:
/// 1. Pre-parse dynamic filter expression, all `hard_gates`, `formula_expr`, and `trigger_rules`.
/// 2. Assemble the group candidate pool according to `group.mode` (`StickyBest`, `ConditionalPool`,
///    `LoadBalanceConsistentHash`, `LoadBalanceRoundRobin`).
/// 3. Enforce every hard gate expression (all must evaluate to `true`).
/// 4. Score passing candidates using `group.formula_expr` and sort descending with NaN pushed to the
///    bottom and deterministic `node_id` tie-breaking.
/// 5. Evaluate `trigger_rules` for every gate-passing candidate and produce a full assessment for
///    `group.active_node_id` (even if the active node has fallen out of the pool or failed gates).
pub fn evaluate_group_candidates(
    group: &MultiGroup,
    nodes: &[ProxyNode],
    snapshots: &HashMap<String, ProbeSnapshot>,
) -> CatResult<GroupEvaluationReport> {
    evaluate_group_candidates_with_runtime(group, nodes, snapshots, None, Instant::now())
}

/// Evaluate a [`MultiGroup`] while fusing live runtime health signals from [`NodeHealthPool`]:
/// - Injects fresh EWMA smoothed latency into `EvalContext.ping_ms`;
/// - Subtracts `penalty_score` for degraded or probation nodes so recovering nodes do not
///   immediately steal the #1 slot;
/// - Ranks actively cooling / unrecovered failed nodes behind healthy candidates while keeping
///   them at the tail of `gate_passed` as last-resort fallbacks (never permanently banned).
pub fn evaluate_group_candidates_with_runtime(
    group: &MultiGroup,
    nodes: &[ProxyNode],
    snapshots: &HashMap<String, ProbeSnapshot>,
    health_pool: Option<&NodeHealthPool>,
    now: Instant,
) -> CatResult<GroupEvaluationReport> {
    let formula_str = if group.formula_expr.trim().is_empty() {
        DEFAULT_COST_EFFECTIVE_FORMULA
    } else {
        group.formula_expr.as_str()
    };
    let score_formula = FormulaExpr::parse(formula_str)?;

    let filter_expr = match group
        .dynamic_filter
        .as_ref()
        .and_then(|f| f.expr.as_deref())
        .map(str::trim)
    {
        Some(raw) if !raw.is_empty() => Some(FormulaExpr::parse(raw)?),
        _ => None,
    };

    let mut hard_gates = Vec::with_capacity(group.hard_gates.len());
    for raw in &group.hard_gates {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            hard_gates.push((trimmed.to_string(), FormulaExpr::parse(trimmed)?));
        }
    }

    let mut compiled_triggers = Vec::with_capacity(group.trigger_rules.len());
    for (idx, rule) in group.trigger_rules.iter().enumerate() {
        let trimmed = rule.expr.trim();
        if !trimmed.is_empty() {
            compiled_triggers.push(CompiledTrigger {
                index: idx,
                rule,
                expr: FormulaExpr::parse(trimmed)?,
            });
        }
    }

    let member_set: HashSet<&str> = group
        .member_node_ids
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    let primary_probe = group.primary_probe_id.as_deref();

    let mut pool_node_ids = HashSet::new();
    let mut gate_passed = Vec::new();
    let mut healthy_candidates = Vec::new();
    let mut gate_rejected = Vec::new();

    for node in nodes {
        if !node.enabled {
            continue;
        }
        let snap = snapshots.get(&node.id);
        let runtime_health = health_pool.and_then(|pool| pool.get(&node.id));
        let mut ctx = build_eval_context_for_probe(node, snap, primary_probe);
        if let Some(rt) = runtime_health {
            apply_runtime_health_to_context(&mut ctx, snap, rt, now);
        }

        let in_pool = match group.mode {
            MultiGroupMode::ConditionalPool => {
                let in_base = member_set.is_empty() || member_set.contains(node.id.as_str());
                if !in_base {
                    false
                } else if let Some(ref filter) = group.dynamic_filter {
                    evaluate_dynamic_filter_preparsed(node, snap, filter, filter_expr.as_ref(), &ctx)?
                } else {
                    true
                }
            }
            MultiGroupMode::StickyBest
            | MultiGroupMode::LoadBalanceConsistentHash
            | MultiGroupMode::LoadBalanceRoundRobin => {
                if !member_set.is_empty() {
                    if !member_set.contains(node.id.as_str()) {
                        false
                    } else if let Some(ref filter) = group.dynamic_filter {
                        evaluate_dynamic_filter_preparsed(
                            node,
                            snap,
                            filter,
                            filter_expr.as_ref(),
                            &ctx,
                        )?
                    } else {
                        true
                    }
                } else if let Some(ref filter) = group.dynamic_filter {
                    evaluate_dynamic_filter_preparsed(node, snap, filter, filter_expr.as_ref(), &ctx)?
                } else {
                    false
                }
            }
        };

        if !in_pool {
            continue;
        }

        pool_node_ids.insert(node.id.as_str());

        let failed_gates = evaluate_hard_gates(&hard_gates, &ctx, snap)?;
        let passed_hard_gates = failed_gates.is_empty();
        let raw_score = score_formula.eval_f64(&ctx)?;
        let score = apply_runtime_penalty(raw_score, runtime_health);

        let mut triggered_indices = Vec::new();
        for trig in &compiled_triggers {
            if trig.expr.eval_bool(&ctx)? {
                triggered_indices.push(trig.index);
            }
        }

        let meets_thresholds = passed_hard_gates && ctx.ok && triggered_indices.is_empty();

        let candidate = EvaluatedCandidate {
            node_id: node.id.clone(),
            node_name: node.name.clone(),
            region_code: node.region_code.clone(),
            multiplier: ctx.multiplier,
            ok: ctx.ok,
            passed_hard_gates,
            failed_hard_gates: failed_gates,
            meets_thresholds,
            triggered_rule_indices: triggered_indices,
            score,
        };

        if passed_hard_gates {
            if meets_thresholds {
                healthy_candidates.push(candidate.clone());
            }
            gate_passed.push(candidate);
        } else {
            gate_rejected.push(candidate);
        }
    }

    gate_passed.sort_by(|a, b| {
        compare_candidates_with_runtime_desc(a, b, snapshots, health_pool, now)
    });
    healthy_candidates.sort_by(|a, b| {
        compare_candidates_with_runtime_desc(a, b, snapshots, health_pool, now)
    });
    gate_rejected.sort_by(|a, b| {
        compare_candidates_with_runtime_desc(a, b, snapshots, health_pool, now)
    });

    let active_assessment = match group.active_node_id.as_deref().map(str::trim) {
        Some(active_id) if !active_id.is_empty() => Some(assess_active_node(
            active_id,
            nodes,
            snapshots,
            health_pool,
            now,
            primary_probe,
            pool_node_ids.contains(active_id),
            &hard_gates,
            &score_formula,
            &group.trigger_rules,
            &compiled_triggers,
        )?),
        _ => None,
    };

    let all_failed_hard_gates = gate_passed.is_empty();
    let all_below_threshold = healthy_candidates.is_empty();

    Ok(GroupEvaluationReport {
        group_id: group.id.clone(),
        mode: group.mode.clone(),
        pool_size: pool_node_ids.len(),
        gate_passed,
        healthy_candidates,
        gate_rejected,
        active_assessment,
        all_failed_hard_gates,
        all_below_threshold,
    })
}

fn apply_runtime_health_to_context(
    ctx: &mut EvalContext,
    snap: Option<&ProbeSnapshot>,
    rt: &RuntimeNodeHealth,
    now: Instant,
) {
    if let Some(ewma) = rt.ewma_latency_ms.filter(|v| v.is_finite() && *v > 0.0) {
        ctx.ping_ms = ewma;
    }

    if rt.is_in_cooldown(now)
        || rt.backoff_stage > 0
        || rt.last_health == Some(RuntimeDualHealth::Failed)
    {
        ctx.ok = false;
    } else if rt.last_health == Some(RuntimeDualHealth::FullHealthy) {
        ctx.ok = true;
    } else if rt.last_health == Some(RuntimeDualHealth::Degraded) && snap.is_none() {
        ctx.ok = true;
    }
}

fn apply_runtime_penalty(raw_score: f64, runtime_health: Option<&RuntimeNodeHealth>) -> f64 {
    match runtime_health {
        Some(rt)
            if raw_score.is_finite()
                && rt.penalty_score.is_finite()
                && rt.penalty_score > 0.0 =>
        {
            raw_score - rt.penalty_score
        }
        _ => raw_score,
    }
}

/// Evaluate a single node's score under a group's scoring formula (using the group's `primary_probe_id`).
pub(crate) fn score_node_with_group_formula(
    group: &MultiGroup,
    node: &ProxyNode,
    snapshot: Option<&ProbeSnapshot>,
) -> CatResult<(f64, bool)> {
    let formula_str = if group.formula_expr.trim().is_empty() {
        DEFAULT_COST_EFFECTIVE_FORMULA
    } else {
        group.formula_expr.as_str()
    };
    let formula = FormulaExpr::parse(formula_str)?;
    let ctx = build_eval_context_for_probe(node, snapshot, group.primary_probe_id.as_deref());
    let score = formula.eval_f64(&ctx)?;
    Ok((score, formula.uses_multiplier()))
}

fn evaluate_hard_gates(
    hard_gates: &[(String, FormulaExpr)],
    ctx: &EvalContext,
    snapshot: Option<&ProbeSnapshot>,
) -> CatResult<Vec<String>> {
    let keepalive_untested = snapshot.and_then(|s| s.keepalive_60s_ok).is_none();
    let mut failed = Vec::new();
    for (raw, expr) in hard_gates {
        let passed = if keepalive_untested && expr.uses_keepalive_ok() {
            // Node has never been tested for 60s keep-alive (`keepalive_60s_ok == None`):
            // treat `keepalive_ok` as pass within hard gates so untested nodes are not falsely
            // eliminated while still enforcing all other predicates in compound expressions.
            let mut gate_ctx = ctx.clone();
            gate_ctx.keepalive_ok = true;
            expr.eval_bool(&gate_ctx)?
        } else {
            expr.eval_bool(ctx)?
        };
        if !passed {
            failed.push(raw.clone());
        }
    }
    Ok(failed)
}

#[allow(clippy::too_many_arguments)]
fn assess_active_node(
    active_id: &str,
    nodes: &[ProxyNode],
    snapshots: &HashMap<String, ProbeSnapshot>,
    health_pool: Option<&NodeHealthPool>,
    now: Instant,
    primary_probe: Option<&str>,
    in_candidate_pool: bool,
    hard_gates: &[(String, FormulaExpr)],
    score_formula: &FormulaExpr,
    all_rules: &[TriggerRule],
    compiled_triggers: &[CompiledTrigger<'_>],
) -> CatResult<ActiveNodeAssessment> {
    let Some(node) = nodes.iter().find(|n| n.id == active_id) else {
        let allow_bypass = all_rules.is_empty()
            || all_rules.iter().any(|r| r.bypass_cooldown_on_disconnect);
        return Ok(ActiveNodeAssessment {
            node_id: active_id.to_string(),
            in_candidate_pool: false,
            passed_hard_gates: false,
            failed_hard_gates: vec!["active node missing from inventory".to_string()],
            score: None,
            is_disconnected: true,
            triggered_rules: Vec::new(),
            any_rule_triggered: false,
            required_consecutive_failures: 1,
            bypass_cooldown: allow_bypass,
        });
    };

    let snap = snapshots.get(&node.id);
    let runtime_health = health_pool.and_then(|pool| pool.get(&node.id));
    let mut ctx = build_eval_context_for_probe(node, snap, primary_probe);
    if let Some(rt) = runtime_health {
        apply_runtime_health_to_context(&mut ctx, snap, rt, now);
    }
    let failed_hard_gates = evaluate_hard_gates(hard_gates, &ctx, snap)?;
    let passed_hard_gates = failed_hard_gates.is_empty();
    let raw_score = score_formula.eval_f64(&ctx)?;
    let score = apply_runtime_penalty(raw_score, runtime_health);
    let is_disconnected = !ctx.ok;

    let mut triggered_rules = Vec::with_capacity(compiled_triggers.len());
    let mut any_rule_triggered = false;
    let mut min_required: Option<u32> = None;

    for trig in compiled_triggers {
        let triggered = trig.expr.eval_bool(&ctx)?;
        let req = trig.rule.consecutive_failures.max(1);
        if triggered {
            any_rule_triggered = true;
            min_required = Some(match min_required {
                Some(cur) => cur.min(req),
                None => req,
            });
        }
        triggered_rules.push(TriggerRuleHit {
            rule_index: trig.index,
            expr: trig.rule.expr.clone(),
            triggered,
            consecutive_failures_required: req,
            bypass_cooldown_on_disconnect: trig.rule.bypass_cooldown_on_disconnect,
        });
    }

    let required_consecutive_failures = min_required.unwrap_or_else(|| {
        all_rules
            .iter()
            .map(|r| r.consecutive_failures.max(1))
            .min()
            .unwrap_or(1)
    });

    let bypass_cooldown = is_disconnected
        && (all_rules.is_empty() || all_rules.iter().any(|r| r.bypass_cooldown_on_disconnect));

    Ok(ActiveNodeAssessment {
        node_id: node.id.clone(),
        in_candidate_pool,
        passed_hard_gates,
        failed_hard_gates,
        score: Some(score),
        is_disconnected,
        triggered_rules,
        any_rule_triggered,
        required_consecutive_failures,
        bypass_cooldown,
    })
}

fn has_probe_data(snap: Option<&ProbeSnapshot>) -> bool {
    let Some(s) = snap else {
        return false;
    };
    !s.tested_at.trim().is_empty()
        || s.ok
        || s.latency_ms.is_some()
        || s.up_mbps.is_some()
        || s.down_mbps.is_some()
        || s.google_clean.is_some()
        || s.keepalive_60s_ok.is_some()
        || !s.per_probe_ok.is_empty()
        || !s.unlocked_sites.is_empty()
}

fn runtime_ranking_tier(rt: Option<&RuntimeNodeHealth>, now: Instant) -> u8 {
    let Some(h) = rt else {
        return 0;
    };
    if h.is_in_cooldown(now) {
        2
    } else if h.backoff_stage > 0 || h.last_health == Some(RuntimeDualHealth::Failed) {
        1
    } else {
        0
    }
}

fn compare_candidates_with_runtime_desc(
    a: &EvaluatedCandidate,
    b: &EvaluatedCandidate,
    snapshots: &HashMap<String, ProbeSnapshot>,
    health_pool: Option<&NodeHealthPool>,
    now: Instant,
) -> Ordering {
    let a_rt = health_pool.and_then(|pool| pool.get(&a.node_id));
    let b_rt = health_pool.and_then(|pool| pool.get(&b.node_id));

    let a_tier = runtime_ranking_tier(a_rt, now);
    let b_tier = runtime_ranking_tier(b_rt, now);
    if a_tier != b_tier {
        return a_tier.cmp(&b_tier);
    }

    // When both candidates are in active cooldown (all-failed fallback), prefer whichever
    // expires sooner before falling back to score ordering.
    if a_tier == 2 {
        let a_rem = a_rt.map(|h| h.cooldown_remaining_sec(now)).unwrap_or(0);
        let b_rem = b_rt.map(|h| h.cooldown_remaining_sec(now)).unwrap_or(0);
        let rem_ord = a_rem.cmp(&b_rem);
        if rem_ord != Ordering::Equal {
            return rem_ord;
        }
    }

    let a_probed = has_probe_data(snapshots.get(&a.node_id))
        || a_rt.is_some_and(|h| h.last_probed_at.is_some());
    let b_probed = has_probe_data(snapshots.get(&b.node_id))
        || b_rt.is_some_and(|h| h.last_probed_at.is_some());

    b.meets_thresholds
        .cmp(&a.meets_thresholds)
        .then_with(|| b.ok.cmp(&a.ok))
        .then_with(|| b_probed.cmp(&a_probed))
        .then_with(|| compare_candidates_desc(a, b))
}

/// Descending candidate comparator:
/// 1. `meets_thresholds == true` before `false`
/// 2. healthy (`ok == true`) before failed/untested (`ok == false`)
/// 3. finite higher scores before lower scores (non-finite/NaN last)
/// 4. deterministic `node_id` ascending tie-break.
pub(crate) fn compare_candidates_desc(a: &EvaluatedCandidate, b: &EvaluatedCandidate) -> Ordering {
    b.meets_thresholds
        .cmp(&a.meets_thresholds)
        .then_with(|| b.ok.cmp(&a.ok))
        .then_with(|| match (a.score.is_finite(), b.score.is_finite()) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => Ordering::Equal,
            (true, true) => b.score.total_cmp(&a.score),
        })
        .then_with(|| a.node_id.cmp(&b.node_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{FallbackPolicy, MultiGroup, MultiGroupMode, ProbeSnapshot, ProxyNode, TriggerRule};

    fn test_node(id: &str, name: &str, region: &str) -> ProxyNode {
        ProxyNode {
            id: id.to_string(),
            sub_id: "sub-test".to_string(),
            name: name.to_string(),
            protocol: "trojan".to_string(),
            server: "198.51.100.10".to_string(),
            port: 443,
            region_code: region.to_string(),
            multiplier: 1.0,
            is_443_native: true,
            enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn keepalive_hard_gate_allows_untested_none_and_rejects_explicit_false() {
        let nodes = vec![
            test_node("tw-untested-clean", "TW-Untested-Clean", "TW"),
            test_node("tw-tested-ok", "TW-Tested-Ok", "TW"),
            test_node("tw-tested-fail", "TW-Tested-Fail", "TW"),
            test_node("tw-untested-dirty", "TW-Untested-Dirty", "TW"),
        ];

        let mut snaps = HashMap::new();
        snaps.insert(
            "tw-untested-clean".to_string(),
            ProbeSnapshot {
                node_id: "tw-untested-clean".to_string(),
                tested_at: "2026-11-23T00:00:00Z".to_string(),
                ok: true,
                latency_ms: Some(40.0),
                up_mbps: Some(25.0),
                down_mbps: Some(150.0),
                google_clean: Some(true),
                keepalive_60s_ok: None,
                ..Default::default()
            },
        );
        snaps.insert(
            "tw-tested-ok".to_string(),
            ProbeSnapshot {
                node_id: "tw-tested-ok".to_string(),
                tested_at: "2026-11-23T00:00:00Z".to_string(),
                ok: true,
                latency_ms: Some(50.0),
                up_mbps: Some(15.0),
                down_mbps: Some(120.0),
                google_clean: Some(true),
                keepalive_60s_ok: Some(true),
                ..Default::default()
            },
        );
        snaps.insert(
            "tw-tested-fail".to_string(),
            ProbeSnapshot {
                node_id: "tw-tested-fail".to_string(),
                tested_at: "2026-11-23T00:00:00Z".to_string(),
                ok: true,
                latency_ms: Some(25.0),
                up_mbps: Some(50.0),
                down_mbps: Some(200.0),
                google_clean: Some(true),
                keepalive_60s_ok: Some(false),
                ..Default::default()
            },
        );
        snaps.insert(
            "tw-untested-dirty".to_string(),
            ProbeSnapshot {
                node_id: "tw-untested-dirty".to_string(),
                tested_at: "2026-11-23T00:00:00Z".to_string(),
                ok: true,
                latency_ms: Some(30.0),
                up_mbps: Some(40.0),
                down_mbps: Some(180.0),
                google_clean: Some(false),
                keepalive_60s_ok: None,
                ..Default::default()
            },
        );

        let group = MultiGroup {
            id: "grp-tw".to_string(),
            name: "测试多选组".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec![
                "tw-untested-clean".to_string(),
                "tw-tested-ok".to_string(),
                "tw-tested-fail".to_string(),
                "tw-untested-dirty".to_string(),
            ],
            hard_gates: vec![
                "keepalive_ok == 1".to_string(),
                "google_clean == 1 && keepalive_ok == 1".to_string(),
            ],
            active_node_id: Some("tw-untested-clean".to_string()),
            ..Default::default()
        };

        let report = evaluate_group_candidates(&group, &nodes, &snaps).unwrap();
        assert!(!report.all_failed_hard_gates);
        let passed_ids: Vec<&str> = report.gate_passed.iter().map(|c| c.node_id.as_str()).collect();
        assert_eq!(passed_ids, vec!["tw-untested-clean", "tw-tested-ok"]);
        assert_eq!(report.healthy_candidates.len(), 2);
        assert_eq!(report.healthy_candidates[0].node_id, "tw-untested-clean");

        // Explicit keepalive_60s_ok == Some(false) and compound google_clean == false must be rejected.
        let rejected_fail = report
            .gate_rejected
            .iter()
            .find(|c| c.node_id == "tw-tested-fail")
            .expect("explicit Some(false) must be rejected");
        assert!(rejected_fail
            .failed_hard_gates
            .iter()
            .any(|g| g == "keepalive_ok == 1"));

        let rejected_dirty = report
            .gate_rejected
            .iter()
            .find(|c| c.node_id == "tw-untested-dirty")
            .expect("google_clean == false must still fail compound keepalive gate");
        assert!(rejected_dirty
            .failed_hard_gates
            .iter()
            .any(|g| g == "google_clean == 1 && keepalive_ok == 1"));

        // Active node assessment must match candidate evaluation semantics.
        let active = report.active_assessment.as_ref().expect("active assessment");
        assert!(active.passed_hard_gates);

        let group_active_fail = MultiGroup {
            active_node_id: Some("tw-tested-fail".to_string()),
            ..group
        };
        let report_active_fail =
            evaluate_group_candidates(&group_active_fail, &nodes, &snaps).unwrap();
        assert!(
            !report_active_fail
                .active_assessment
                .as_ref()
                .expect("active assessment")
                .passed_hard_gates
        );
    }

    #[test]
    fn fallback_and_rejected_rankings_prioritize_healthy_then_probed_then_score() {
        let nodes = vec![
            // Lexicographically smallest ID to prove ordering is driven by probe presence, not tie-break.
            test_node("a-unprobed", "Unprobed", "JP"),
            test_node("n-failed-probed", "Failed-Probed", "JP"),
            test_node("n-ok-low", "Ok-Low", "JP"),
            test_node("n-ok-high", "Ok-High", "JP"),
        ];

        let mut snaps = HashMap::new();
        // Healthy with lower (negative) score from latency penalty alone.
        snaps.insert(
            "n-ok-low".to_string(),
            ProbeSnapshot {
                node_id: "n-ok-low".to_string(),
                tested_at: "2026-11-23T00:00:00Z".to_string(),
                ok: true,
                latency_ms: Some(200.0),
                up_mbps: Some(0.0),
                down_mbps: Some(0.0),
                google_clean: Some(true),
                ..Default::default()
            },
        );
        // Healthy with high score.
        snaps.insert(
            "n-ok-high".to_string(),
            ProbeSnapshot {
                node_id: "n-ok-high".to_string(),
                tested_at: "2026-11-23T00:00:00Z".to_string(),
                ok: true,
                latency_ms: Some(40.0),
                up_mbps: Some(12.0),
                down_mbps: Some(100.0),
                google_clean: Some(true),
                ..Default::default()
            },
        );
        // Probed but failed (`ok == false`); even with `latency_ms = Some(0.0)` yielding a
        // higher raw numeric score (0.0) than `n-ok-low` (-16.0), it MUST rank behind healthy nodes,
        // and MUST rank ahead of `a-unprobed` despite lexicographically larger ID.
        snaps.insert(
            "n-failed-probed".to_string(),
            ProbeSnapshot {
                node_id: "n-failed-probed".to_string(),
                tested_at: "2026-11-23T00:00:00Z".to_string(),
                ok: false,
                latency_ms: Some(0.0),
                up_mbps: Some(0.0),
                down_mbps: Some(0.0),
                google_clean: Some(true),
                ..Default::default()
            },
        );
        // `a-unprobed` intentionally omitted from `snaps`.

        // 1. Trigger fallback (`healthy_candidates` empty): `gate_passed` must still rank
        //    healthy high -> healthy low -> probed failed -> unprobed.
        let fallback_group = MultiGroup {
            id: "grp-fallback".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec![
                "a-unprobed".to_string(),
                "n-failed-probed".to_string(),
                "n-ok-low".to_string(),
                "n-ok-high".to_string(),
            ],
            trigger_rules: vec![TriggerRule {
                expr: "up_mbps < 100.0".to_string(),
                consecutive_failures: 1,
                bypass_cooldown_on_disconnect: true,
            }],
            fallback_policy: FallbackPolicy::DegradeBestWarn,
            ..Default::default()
        };

        let rep = evaluate_group_candidates(&fallback_group, &nodes, &snaps).unwrap();
        assert!(rep.healthy_candidates.is_empty());
        assert!(rep.all_below_threshold);
        let passed_order: Vec<&str> = rep.gate_passed.iter().map(|c| c.node_id.as_str()).collect();
        assert_eq!(
            passed_order,
            vec!["n-ok-high", "n-ok-low", "n-failed-probed", "a-unprobed"]
        );

        // 2. When all candidates fail hard gates, `gate_rejected` follows the exact same ranking.
        let strict_group = MultiGroup {
            hard_gates: vec!["site_unlocked(\"nonexistent\") == 1".to_string()],
            ..fallback_group
        };
        let strict_rep = evaluate_group_candidates(&strict_group, &nodes, &snaps).unwrap();
        assert!(strict_rep.all_failed_hard_gates);
        let rejected_order: Vec<&str> = strict_rep
            .gate_rejected
            .iter()
            .map(|c| c.node_id.as_str())
            .collect();
        assert_eq!(
            rejected_order,
            vec!["n-ok-high", "n-ok-low", "n-failed-probed", "a-unprobed"]
        );
    }

    #[test]
    fn legacy_probe_up_trigger_rule_uses_generic_snapshot_fallback() {
        let nodes = vec![test_node("n-tw", "TW-Gold", "TW")];
        let mut snaps = HashMap::new();
        let mut snap = ProbeSnapshot {
            node_id: "n-tw".to_string(),
            tested_at: "2026-11-23T00:00:00Z".to_string(),
            ok: true,
            latency_ms: Some(45.0),
            up_mbps: Some(16.0),
            down_mbps: Some(150.0),
            google_clean: Some(true),
            ..Default::default()
        };
        snap.per_probe_up_mbps.insert("builtin_upload".to_string(), 16.0);
        snaps.insert("n-tw".to_string(), snap);

        let group = MultiGroup {
            id: "grp-legacy".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec!["n-tw".to_string()],
            trigger_rules: vec![TriggerRule {
                expr: r#"probe_up("antigravity") < 2.0"#.to_string(),
                consecutive_failures: 2,
                bypass_cooldown_on_disconnect: true,
            }],
            ..Default::default()
        };

        let rep = evaluate_group_candidates(&group, &nodes, &snaps).unwrap();
        assert_eq!(rep.healthy_candidates.len(), 1);
        assert!(rep.healthy_candidates[0].meets_thresholds);
        assert!(rep.healthy_candidates[0].triggered_rule_indices.is_empty());
    }

    #[test]
    fn runtime_health_pool_fuses_ewma_cooldown_probation_and_all_failed_fallback() {
        use std::time::Duration;

        let nodes = vec![
            test_node("n-fast", "JP-Fast", "JP"),
            test_node("n-steady", "SG-Steady", "SG"),
            test_node("n-backup", "TW-Backup", "TW"),
        ];

        // `n-fast` has higher static throughput so it leads when healthy.
        let mut snaps = HashMap::new();
        snaps.insert(
            "n-fast".to_string(),
            ProbeSnapshot {
                node_id: "n-fast".to_string(),
                tested_at: "2026-11-24T00:00:00Z".to_string(),
                ok: true,
                latency_ms: Some(40.0),
                up_mbps: Some(2.0),
                down_mbps: Some(100.0),
                google_clean: Some(true),
                ..Default::default()
            },
        );
        snaps.insert(
            "n-steady".to_string(),
            ProbeSnapshot {
                node_id: "n-steady".to_string(),
                tested_at: "2026-11-24T00:00:00Z".to_string(),
                ok: true,
                latency_ms: Some(60.0),
                up_mbps: Some(1.6),
                down_mbps: Some(100.0),
                google_clean: Some(true),
                ..Default::default()
            },
        );
        snaps.insert(
            "n-backup".to_string(),
            ProbeSnapshot {
                node_id: "n-backup".to_string(),
                tested_at: "2026-11-24T00:00:00Z".to_string(),
                ok: true,
                latency_ms: Some(80.0),
                up_mbps: Some(1.2),
                down_mbps: Some(80.0),
                google_clean: Some(true),
                ..Default::default()
            },
        );

        let group = MultiGroup {
            id: "grp-rt".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec![
                "n-fast".to_string(),
                "n-steady".to_string(),
                "n-backup".to_string(),
            ],
            // Simple linear formula where penalty & EWMA ping visibly govern ranking.
            formula_expr: "up_mbps * 100 - ping_ms * 0.5".to_string(),
            ..Default::default()
        };

        let mut pool = NodeHealthPool::new();
        let t0 = Instant::now();

        // 1. Baseline: `n-fast` (200 - 20 = 180) > `n-steady` (160 - 30 = 130) > `n-backup` (120 - 40 = 80).
        let rep0 = evaluate_group_candidates_with_runtime(&group, &nodes, &snaps, Some(&pool), t0)
            .unwrap();
        assert_eq!(rep0.healthy_candidates[0].node_id, "n-fast");

        // 2. Live EWMA latency spike on `n-fast` + single Degraded does NOT permanently ban it,
        //    but drops its score below `n-steady` without entering cooldown.
        pool.record_probe_result("n-fast", RuntimeDualHealth::FullHealthy, Some(200.0), t0);
        pool.record_probe_result(
            "n-fast",
            RuntimeDualHealth::Degraded,
            Some(220.0),
            t0 + Duration::from_secs(10),
        );
        pool.record_probe_result(
            "n-steady",
            RuntimeDualHealth::FullHealthy,
            Some(40.0),
            t0 + Duration::from_secs(10),
        );
        let t1 = t0 + Duration::from_secs(15);
        assert!(!pool.is_in_cooldown("n-fast", t1));
        let rep1 = evaluate_group_candidates_with_runtime(&group, &nodes, &snaps, Some(&pool), t1)
            .unwrap();
        assert_eq!(rep1.healthy_candidates[0].node_id, "n-steady");
        // `n-fast` still present and not permanently banned
        assert!(rep1.gate_passed.iter().any(|c| c.node_id == "n-fast"));

        // 3. Confirmed Failed on `n-fast`: enters 60s cooldown and drops behind all healthy nodes,
        //    but remains at tail of `gate_passed`.
        let t2 = t1 + Duration::from_secs(10);
        pool.record_probe_result("n-fast", RuntimeDualHealth::Failed, None, t2);
        assert!(pool.is_in_cooldown("n-fast", t2 + Duration::from_secs(1)));
        let rep2 = evaluate_group_candidates_with_runtime(
            &group,
            &nodes,
            &snaps,
            Some(&pool),
            t2 + Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(rep2.healthy_candidates[0].node_id, "n-steady");
        assert!(!rep2.healthy_candidates.iter().any(|c| c.node_id == "n-fast"));
        assert_eq!(
            rep2.gate_passed.last().map(|c| c.node_id.as_str()),
            Some("n-fast")
        );

        // 4. Cooldown expires (65s): 1st FullHealthy is NOT enough to reclaim top rank.
        let t3 = t2 + Duration::from_secs(65);
        pool.record_probe_result("n-fast", RuntimeDualHealth::FullHealthy, Some(30.0), t3);
        let rep3 = evaluate_group_candidates_with_runtime(&group, &nodes, &snaps, Some(&pool), t3)
            .unwrap();
        assert_eq!(rep3.healthy_candidates[0].node_id, "n-steady");
        assert!(!rep3.healthy_candidates.iter().any(|c| c.node_id == "n-fast"));

        // 5. 2nd consecutive FullHealthy lifts cooldown into half-penalty probation (penalty = 80.0):
        //    `n-fast` re-enters healthy_candidates, yet stays behind `n-steady` so it does not flap!
        let t4 = t3 + Duration::from_secs(65);
        pool.record_probe_result("n-fast", RuntimeDualHealth::FullHealthy, Some(30.0), t4);
        assert_eq!(pool.get("n-fast").unwrap().probation_remaining, 1);
        let rep4 = evaluate_group_candidates_with_runtime(&group, &nodes, &snaps, Some(&pool), t4)
            .unwrap();
        assert!(rep4.healthy_candidates.iter().any(|c| c.node_id == "n-fast"));
        assert_eq!(rep4.healthy_candidates[0].node_id, "n-steady");

        // 6. 3rd FullHealthy clears probation -> `n-fast` recovers full weight and retakes #1.
        let t5 = t4 + Duration::from_secs(65);
        pool.record_probe_result("n-fast", RuntimeDualHealth::FullHealthy, Some(30.0), t5);
        pool.record_probe_result("n-fast", RuntimeDualHealth::FullHealthy, Some(30.0), t5 + Duration::from_secs(20));
        let rep5 = evaluate_group_candidates_with_runtime(
            &group,
            &nodes,
            &snaps,
            Some(&pool),
            t5 + Duration::from_secs(25),
        )
        .unwrap();
        assert_eq!(rep5.healthy_candidates[0].node_id, "n-fast");

        // 7. All nodes fail into cooldown simultaneously -> `gate_passed` MUST still return all 3
        //    as last-resort fallbacks, ordering the soonest-expiring cooldown first!
        let t6_pre = t5 + Duration::from_secs(40);
        pool.record_probe_result("n-fast", RuntimeDualHealth::Failed, None, t6_pre); // stage 1 -> 60s
        let t6 = t6_pre + Duration::from_secs(65);
        pool.record_probe_result("n-fast", RuntimeDualHealth::Failed, None, t6); // cooldown expired -> stage 2 -> 180s
        pool.record_probe_result("n-steady", RuntimeDualHealth::Failed, None, t6); // stage 1 -> 60s
        pool.record_probe_result("n-backup", RuntimeDualHealth::Failed, None, t6 + Duration::from_secs(5)); // stage 1 -> 60s (expires later than n-steady)

        let rep_all_down = evaluate_group_candidates_with_runtime(
            &group,
            &nodes,
            &snaps,
            Some(&pool),
            t6 + Duration::from_secs(10),
        )
        .unwrap();
        assert!(rep_all_down.healthy_candidates.is_empty());
        assert_eq!(rep_all_down.gate_passed.len(), 3);
        assert_eq!(rep_all_down.gate_passed[0].node_id, "n-steady");
        assert_eq!(rep_all_down.gate_passed[2].node_id, "n-fast");
    }
}
