//! Per-node evaluation context builder, dynamic filter engine, and multi-group candidate evaluator.

use crate::error::CatResult;
use crate::models::{
    DEFAULT_COST_EFFECTIVE_FORMULA, DynamicFilterSpec, MultiGroup, MultiGroupMode, ProbeSnapshot,
    ProxyNode, TriggerRule,
};
use crate::strategy::formula::{DEFAULT_MISSING_PING_MS, EvalContext, FormulaExpr};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

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
        let ctx = build_eval_context_for_probe(node, snap, primary_probe);

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

        let failed_gates = evaluate_hard_gates(&hard_gates, &ctx)?;
        let passed_hard_gates = failed_gates.is_empty();
        let score = score_formula.eval_f64(&ctx)?;

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

    gate_passed.sort_by(compare_candidates_desc);
    healthy_candidates.sort_by(compare_candidates_desc);
    gate_rejected.sort_by(compare_candidates_desc);

    let active_assessment = match group.active_node_id.as_deref().map(str::trim) {
        Some(active_id) if !active_id.is_empty() => Some(assess_active_node(
            active_id,
            nodes,
            snapshots,
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
) -> CatResult<Vec<String>> {
    let mut failed = Vec::new();
    for (raw, expr) in hard_gates {
        if !expr.eval_bool(ctx)? {
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
    let ctx = build_eval_context_for_probe(node, snap, primary_probe);
    let failed_hard_gates = evaluate_hard_gates(hard_gates, &ctx)?;
    let passed_hard_gates = failed_hard_gates.is_empty();
    let score = score_formula.eval_f64(&ctx)?;
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

/// Descending score comparator: finite scores rank above non-finite/NaN, ties break by `node_id` ascending.
pub(crate) fn compare_candidates_desc(a: &EvaluatedCandidate, b: &EvaluatedCandidate) -> Ordering {
    match (a.score.is_finite(), b.score.is_finite()) {
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => a.node_id.cmp(&b.node_id),
        (true, true) => b
            .score
            .total_cmp(&a.score)
            .then_with(|| a.node_id.cmp(&b.node_id)),
    }
}
