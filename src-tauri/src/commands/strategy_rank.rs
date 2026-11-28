use std::collections::HashMap;
use std::collections::HashSet;
use std::time::Instant;
use catcloud_core::core_adapter::TrafficTick;
use catcloud_core::models::MultiGroup;
use catcloud_core::models::MultiGroupMode;
use catcloud_core::models::NodeSummary;
use catcloud_core::models::ProbeSnapshot;
use catcloud_core::models::ProxyNode;
use catcloud_core::strategy::evaluator::evaluate_group_candidates_with_runtime;
use catcloud_core::strategy::health_pool::NodeHealthPool;
use catcloud_core::strategy::health_pool::RuntimeDualHealth;

use crate::commands::state::CachedRealtimeMetrics;

/// Return whether `node_id` is an enabled, valid member of `group`.
/// When `group.member_node_ids` is non-empty, the node MUST appear in `member_node_ids`.
pub(in crate::commands) fn is_valid_group_member(group: &MultiGroup, node_id: &str, nodes: &[ProxyNode]) -> bool {
    let trimmed = node_id.trim();
    if trimmed.is_empty() {
        return false;
    }
    if !group.member_node_ids.is_empty()
        && !group.member_node_ids.iter().any(|id| id == trimmed)
    {
        return false;
    }
    nodes.iter().any(|n| n.id == trimmed && n.enabled)
}


/// Count distinct enabled nodes eligible inside `group`.
pub fn count_enabled_group_members(group: &MultiGroup, nodes: &[ProxyNode]) -> usize {
    let mut seen = std::collections::HashSet::new();
    if !group.member_node_ids.is_empty() {
        for mid in &group.member_node_ids {
            if let Some(n) = nodes.iter().find(|n| &n.id == mid && n.enabled) {
                seen.insert(n.id.as_str());
            }
        }
    } else if matches!(group.mode, MultiGroupMode::ConditionalPool) || group.dynamic_filter.is_some()
    {
        for n in nodes.iter().filter(|n| n.enabled) {
            seen.insert(n.id.as_str());
        }
    }
    seen.len()
}


/// Lightweight equivalent of `count_enabled_group_members` operating on `NodeSummary` rows
/// without deserializing `raw_json`.
pub fn count_enabled_group_members_from_summaries(
    group: &MultiGroup,
    nodes: &[NodeSummary],
) -> usize {
    let mut seen = std::collections::HashSet::new();
    if !group.member_node_ids.is_empty() {
        for mid in &group.member_node_ids {
            if let Some(n) = nodes.iter().find(|n| &n.id == mid && n.enabled) {
                seen.insert(n.id.as_str());
            }
        }
    } else if matches!(group.mode, MultiGroupMode::ConditionalPool) || group.dynamic_filter.is_some()
    {
        for n in nodes.iter().filter(|n| n.enabled) {
            seen.insert(n.id.as_str());
        }
    }
    seen.len()
}


/// Resolve the consecutive failure threshold for runtime watchdog failover (`>= 2`).
pub fn group_watchdog_failure_threshold(group: &MultiGroup) -> u32 {
    group
        .trigger_rules
        .iter()
        .map(|r| r.consecutive_failures)
        .min()
        .unwrap_or(2)
        .max(2)
}


/// Resolve the displayable active node for `group`, strictly rejecting ghost `active_node_id`
/// values that have been removed from `group.member_node_ids`.
pub fn resolve_valid_group_active_node<'a>(
    group: &MultiGroup,
    nodes: &'a [ProxyNode],
) -> Option<&'a ProxyNode> {
    if !group.member_node_ids.is_empty() {
        if let Some(active_id) = group
            .active_node_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if group.member_node_ids.iter().any(|m| m == active_id) {
                if let Some(node) = nodes.iter().find(|n| n.id == active_id && n.enabled) {
                    return Some(node);
                }
            }
        }
        return group
            .member_node_ids
            .iter()
            .filter_map(|id| nodes.iter().find(|n| &n.id == id && n.enabled))
            .next()
            .or_else(|| {
                group
                    .member_node_ids
                    .iter()
                    .filter_map(|id| nodes.iter().find(|n| &n.id == id))
                    .next()
            });
    }

    if let Some(active_id) = group
        .active_node_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if let Some(node) = nodes.iter().find(|n| n.id == active_id && n.enabled) {
            return Some(node);
        }
    }
    nodes
        .iter()
        .find(|n| n.enabled)
        .or_else(|| nodes.first())
}


/// Pick the best enabled member node in `group` according to `evaluate_group_candidates`:
/// 1. Highest-scoring healthy candidate (`healthy_candidates`);
/// 2. Highest-scoring `ok` gate-passing candidate (`gate_passed`);
/// 3. Highest-scoring gate-passing candidate when static `hard_gates` are configured;
/// 4. When all members are rejected by `hard_gates` (`gate_passed` empty), keep honoring
///    `evaluate_group_candidates`'s descending score ranking (`gate_rejected`) — preferring
///    `ok` candidates first, then probed/score-distinguished candidates — instead of blindly
///    picking `member_node_ids[0]`;
/// 5. Finally fall back to the next enabled member in group order.
pub fn pick_best_group_candidate(
    group: &MultiGroup,
    nodes: &[ProxyNode],
    snaps: &HashMap<String, ProbeSnapshot>,
    exclude_node_id: Option<&str>,
) -> Option<String> {
    pick_best_group_candidate_with_runtime(
        group,
        nodes,
        snaps,
        exclude_node_id,
        None,
        Instant::now(),
    )
}


pub fn pick_best_group_candidate_with_runtime(
    group: &MultiGroup,
    nodes: &[ProxyNode],
    snaps: &HashMap<String, ProbeSnapshot>,
    exclude_node_id: Option<&str>,
    health_pool: Option<&NodeHealthPool>,
    now: Instant,
) -> Option<String> {
    let excluded = exclude_node_id.map(str::trim).filter(|s| !s.is_empty());
    let allowed = |id: &str| excluded != Some(id) && is_valid_group_member(group, id, nodes);

    if let Ok(report) = evaluate_group_candidates_with_runtime(group, nodes, snaps, health_pool, now)
    {
        if let Some(best) = report
            .healthy_candidates
            .iter()
            .find(|c| allowed(&c.node_id))
        {
            return Some(best.node_id.clone());
        }
        if let Some(best) = report
            .gate_passed
            .iter()
            .find(|c| c.ok && allowed(&c.node_id))
        {
            return Some(best.node_id.clone());
        }
        if !group.hard_gates.is_empty() || health_pool.is_some() {
            if let Some(best) = report.gate_passed.iter().find(|c| allowed(&c.node_id)) {
                return Some(best.node_id.clone());
            }
        }
        // Fallback when all candidates failed hard gates (e.g. unprobed `keepalive_ok == 1`):
        // keep honoring the descending score list (`gate_rejected`) rather than skipping scoring
        // and blindly falling back to `member_node_ids[0]`.
        if let Some(best) = report
            .gate_rejected
            .iter()
            .find(|c| c.ok && allowed(&c.node_id))
        {
            return Some(best.node_id.clone());
        }
        let allowed_rejected: Vec<_> = report
            .gate_rejected
            .iter()
            .filter(|c| allowed(&c.node_id))
            .collect();
        if let Some(best) = allowed_rejected
            .iter()
            .find(|c| snaps.contains_key(&c.node_id) && c.score.is_finite())
        {
            return Some(best.node_id.clone());
        }
        if let (Some(first), Some(last)) = (allowed_rejected.first(), allowed_rejected.last()) {
            if first.score.is_finite()
                && (!last.score.is_finite() || (first.score - last.score).abs() > 1e-9)
            {
                return Some(first.node_id.clone());
            }
        }
    }

    let mut enabled_members: Vec<&str> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    if !group.member_node_ids.is_empty() {
        for mid in &group.member_node_ids {
            if let Some(n) = nodes.iter().find(|n| &n.id == mid && n.enabled) {
                if seen.insert(n.id.as_str()) {
                    enabled_members.push(n.id.as_str());
                }
            }
        }
    } else {
        for n in nodes.iter().filter(|n| n.enabled) {
            if seen.insert(n.id.as_str()) {
                enabled_members.push(n.id.as_str());
            }
        }
    }

    if enabled_members.is_empty() {
        return None;
    }

    if let Some(ex) = excluded {
        if let Some(idx) = enabled_members.iter().position(|&id| id == ex) {
            if enabled_members.len() <= 1 {
                return None;
            }
            return Some(enabled_members[(idx + 1) % enabled_members.len()].to_string());
        }
    }

    enabled_members
        .into_iter()
        .find(|&id| excluded != Some(id))
        .map(str::to_string)
}


/// Default sliding window (10 s) for high-throughput failover suppression.
pub(crate) const WATCHDOG_HIGH_THROUGHPUT_WINDOW_MS: i64 = 10_000;

/// Default throughput guard threshold (256 KiB/s) protecting active uploads/downloads.
pub(crate) const WATCHDOG_HIGH_THROUGHPUT_THRESHOLD_BPS: u64 = 256 * 1024;


/// Return `true` when active transfer throughput meets or exceeds `threshold_bps`, checking both
/// the cached real-time rate and the peak rate within `window_ms` of `now_ms` inside
/// `recent_ticks` (so minimizing/hiding the GUI window, which zeroes `cached` on quiet ticks,
/// never disables active transfer protection).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn is_high_throughput_active(
    cached: &CachedRealtimeMetrics,
    recent_ticks: &[TrafficTick],
    now_ms: i64,
    window_ms: i64,
    threshold_bps: u64,
) -> bool {
    if cached.up_bps.max(cached.down_bps) >= threshold_bps {
        return true;
    }
    let cutoff_ms = now_ms.saturating_sub(window_ms.max(0));
    let upper_ms = now_ms.saturating_add(5_000);
    for tick in recent_ticks {
        if tick.timestamp_ms >= cutoff_ms && tick.timestamp_ms <= upper_ms {
            if tick.up.max(tick.down) >= threshold_bps {
                return true;
            }
        }
    }
    false
}


fn collect_ranked_group_candidates(
    group: &MultiGroup,
    nodes: &[ProxyNode],
    snaps: &HashMap<String, ProbeSnapshot>,
    active_node_id: Option<&str>,
    cooldown_node_ids: &HashSet<String>,
    health_pool: Option<&NodeHealthPool>,
    now: Instant,
    exclude_pool_cooldowns: bool,
    max_candidates: usize,
) -> Vec<String> {
    if max_candidates == 0 {
        return Vec::new();
    }
    let active_trimmed = active_node_id.map(str::trim).filter(|s| !s.is_empty());
    let allowed = |id: &str| {
        active_trimmed != Some(id)
            && !cooldown_node_ids.contains(id)
            && !(exclude_pool_cooldowns && health_pool.is_some_and(|p| p.is_in_cooldown(id, now)))
            && is_valid_group_member(group, id, nodes)
    };

    let mut out: Vec<String> = Vec::with_capacity(max_candidates);
    let mut seen: HashSet<String> = HashSet::new();
    let mut push_if_allowed = |id: &str| -> bool {
        if out.len() >= max_candidates {
            return true;
        }
        if allowed(id) && seen.insert(id.to_string()) {
            out.push(id.to_string());
        }
        out.len() >= max_candidates
    };

    if let Ok(report) = evaluate_group_candidates_with_runtime(group, nodes, snaps, health_pool, now)
    {
        // Tier 1: highest-scoring healthy candidates.
        for c in &report.healthy_candidates {
            if push_if_allowed(&c.node_id) {
                return out;
            }
        }
        // Tier 2: highest-scoring ok gate-passing candidates.
        for c in report.gate_passed.iter().filter(|c| c.ok) {
            if push_if_allowed(&c.node_id) {
                return out;
            }
        }
        // Tier 3: remaining gate-passing candidates when static hard gates are configured
        // or a runtime health pool is active (preserving shortest-cooldown fallback order).
        if !group.hard_gates.is_empty() || health_pool.is_some() {
            for c in &report.gate_passed {
                if push_if_allowed(&c.node_id) {
                    return out;
                }
            }
        }
        // Tier 4: gate-rejected candidates preserving ok -> probed finite score -> distinct score order.
        for c in report.gate_rejected.iter().filter(|c| c.ok) {
            if push_if_allowed(&c.node_id) {
                return out;
            }
        }
        let allowed_rejected: Vec<_> = report
            .gate_rejected
            .iter()
            .filter(|c| allowed(&c.node_id))
            .collect();
        for c in allowed_rejected
            .iter()
            .filter(|c| snaps.contains_key(&c.node_id) && c.score.is_finite())
        {
            if push_if_allowed(&c.node_id) {
                return out;
            }
        }
        if let (Some(first), Some(last)) = (allowed_rejected.first(), allowed_rejected.last()) {
            if first.score.is_finite()
                && (!last.score.is_finite() || (first.score - last.score).abs() > 1e-9)
            {
                for c in &allowed_rejected {
                    if c.score.is_finite() && push_if_allowed(&c.node_id) {
                        return out;
                    }
                }
            }
        }
    }

    // Tier 5: fall back to enabled member order starting right after `active_node_id`.
    let mut enabled_members: Vec<&str> = Vec::new();
    let mut member_seen: HashSet<&str> = HashSet::new();
    if !group.member_node_ids.is_empty() {
        for mid in &group.member_node_ids {
            if let Some(n) = nodes.iter().find(|n| &n.id == mid && n.enabled) {
                if member_seen.insert(n.id.as_str()) {
                    enabled_members.push(n.id.as_str());
                }
            }
        }
    } else {
        for n in nodes.iter().filter(|n| n.enabled) {
            if member_seen.insert(n.id.as_str()) {
                enabled_members.push(n.id.as_str());
            }
        }
    }

    if enabled_members.is_empty() {
        return out;
    }

    let start_idx = active_trimmed
        .and_then(|aid| enabled_members.iter().position(|&id| id == aid))
        .map(|idx| (idx + 1) % enabled_members.len())
        .unwrap_or(0);
    for offset in 0..enabled_members.len() {
        let id = enabled_members[(start_idx + offset) % enabled_members.len()];
        if push_if_allowed(id) {
            break;
        }
    }

    out
}


/// Rank up to `max_candidates` backup nodes for watchdog failover using the same 5-tier priority
/// order as `pick_best_group_candidate`, excluding both `active_node_id` and nodes currently in
/// `cooldown_node_ids` or active runtime cooldown in `health_pool`. If every non-active member is
/// in cooldown, relaxes the cooldown filter as a last resort while still excluding `active_node_id`.
pub(crate) fn pick_group_candidates_with_cooldown_and_runtime(
    group: &MultiGroup,
    nodes: &[ProxyNode],
    snaps: &HashMap<String, ProbeSnapshot>,
    active_node_id: Option<&str>,
    cooldown_node_ids: &HashSet<String>,
    health_pool: Option<&NodeHealthPool>,
    now: Instant,
    max_candidates: usize,
) -> Vec<String> {
    let ranked = collect_ranked_group_candidates(
        group,
        nodes,
        snaps,
        active_node_id,
        cooldown_node_ids,
        health_pool,
        now,
        true,
        max_candidates,
    );
    if !ranked.is_empty() {
        return ranked;
    }
    let has_any_cooldown = !cooldown_node_ids.is_empty()
        || health_pool.is_some_and(|p| !p.is_empty());
    if !has_any_cooldown {
        return ranked;
    }
    let empty = HashSet::new();
    collect_ranked_group_candidates(
        group,
        nodes,
        snaps,
        active_node_id,
        &empty,
        health_pool,
        now,
        false,
        max_candidates,
    )
}


#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn pick_group_candidates_with_cooldown(
    group: &MultiGroup,
    nodes: &[ProxyNode],
    snaps: &HashMap<String, ProbeSnapshot>,
    active_node_id: Option<&str>,
    cooldown_node_ids: &HashSet<String>,
    max_candidates: usize,
) -> Vec<String> {
    pick_group_candidates_with_cooldown_and_runtime(
        group,
        nodes,
        snaps,
        active_node_id,
        cooldown_node_ids,
        None,
        Instant::now(),
        max_candidates,
    )
}


/// Sanitize a group's `active_node_id`: when `!group.member_node_ids.is_empty()` and
/// `group.active_node_id` is missing, removed from `member_node_ids`, or disabled, replace it
/// with the highest-scoring gate-passing candidate via `evaluate_group_candidates_with_runtime`
/// (falling back to the first enabled member, or `None` if no enabled member exists).
/// Returns `true` if `group.active_node_id` was modified.
pub fn sanitize_group_active_node(
    group: &mut MultiGroup,
    nodes: &[ProxyNode],
    snaps: &HashMap<String, ProbeSnapshot>,
) -> bool {
    sanitize_group_active_node_with_runtime(group, nodes, snaps, None, Instant::now())
}


pub fn sanitize_group_active_node_with_runtime(
    group: &mut MultiGroup,
    nodes: &[ProxyNode],
    snaps: &HashMap<String, ProbeSnapshot>,
    health_pool: Option<&NodeHealthPool>,
    now: Instant,
) -> bool {
    if !group.member_node_ids.is_empty() {
        let current_valid = group
            .active_node_id
            .as_deref()
            .is_some_and(|id| is_valid_group_member(group, id, nodes));
        if current_valid {
            return false;
        }
        let next = pick_best_group_candidate_with_runtime(group, nodes, snaps, None, health_pool, now);
        if group.active_node_id != next {
            group.active_node_id = next;
            return true;
        }
        return false;
    }

    // Even for dynamic/empty-member groups, clear stale references to deleted or disabled nodes.
    if let Some(active_id) = group.active_node_id.as_deref() {
        if !is_valid_group_member(group, active_id, nodes) {
            let next =
                pick_best_group_candidate_with_runtime(group, nodes, snaps, None, health_pool, now);
            if group.active_node_id != next {
                group.active_node_id = next;
                return true;
            }
        }
    }
    false
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commands) struct ReconcileSwitchDecision {
    pub(in crate::commands) from_node_id: Option<String>,
    pub(in crate::commands) from_node_name: String,
    pub(in crate::commands) to_node_id: String,
    pub(in crate::commands) to_node_name: String,
    pub(in crate::commands) reason: String,
}


/// Pure strategy reconciler for a multi-group:
/// 1. Always clears ghost/invalid `active_node_id` via `sanitize_group_active_node_with_runtime`.
/// 2. For `StickyBest` / `ConditionalPool` groups, if the current active node is unprobed,
///    failed/disconnected, or violates hard gates while a gate-passing healthy candidate exists,
///    switches to the top-ranked candidate.
/// 3. Respects sticky user choice: if the current active node is already in-group, probed,
///    connected, and passes all hard gates, leaves it untouched to prevent IP drift.
#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::commands) fn reconcile_group_best_node_in_memory(
    group: &mut MultiGroup,
    nodes: &[ProxyNode],
    snaps: &HashMap<String, ProbeSnapshot>,
) -> Option<ReconcileSwitchDecision> {
    reconcile_group_best_node_in_memory_with_runtime(group, nodes, snaps, None, Instant::now())
}


pub(in crate::commands) fn reconcile_group_best_node_in_memory_with_runtime(
    group: &mut MultiGroup,
    nodes: &[ProxyNode],
    snaps: &HashMap<String, ProbeSnapshot>,
    health_pool: Option<&NodeHealthPool>,
    now: Instant,
) -> Option<ReconcileSwitchDecision> {
    let prev_id = group.active_node_id.clone();
    let prev_name = prev_id
        .as_deref()
        .and_then(|id| nodes.iter().find(|n| n.id == id))
        .map(|n| n.name.clone())
        .or_else(|| prev_id.clone())
        .unwrap_or_else(|| "未选定".to_string());

    let current_valid = prev_id
        .as_deref()
        .is_some_and(|id| is_valid_group_member(group, id, nodes));

    if !current_valid {
        sanitize_group_active_node_with_runtime(group, nodes, snaps, health_pool, now);
        if let Some(to_id) = group.active_node_id.clone() {
            if prev_id.as_deref() != Some(to_id.as_str()) {
                let to_name = nodes
                    .iter()
                    .find(|n| n.id == to_id)
                    .map(|n| n.name.clone())
                    .unwrap_or_else(|| to_id.clone());
                return Some(ReconcileSwitchDecision {
                    from_node_id: prev_id,
                    from_node_name: prev_name,
                    to_node_id: to_id,
                    to_node_name: to_name,
                    reason: "原节点已不在本组或已停用，已自动切换至最优候选节点".to_string(),
                });
            }
        }
        return None;
    }

    if !matches!(
        group.mode,
        MultiGroupMode::StickyBest | MultiGroupMode::ConditionalPool
    ) {
        return None;
    }

    let cur_id = prev_id.as_deref()?;
    let Ok(report) =
        evaluate_group_candidates_with_runtime(group, nodes, snaps, health_pool, now)
    else {
        return None;
    };

    let best = report
        .healthy_candidates
        .iter()
        .find(|c| is_valid_group_member(group, &c.node_id, nodes))
        .or_else(|| {
            report
                .gate_passed
                .iter()
                .find(|c| c.ok && is_valid_group_member(group, &c.node_id, nodes))
        })
        .or_else(|| {
            report
                .gate_rejected
                .iter()
                .find(|c| c.ok && is_valid_group_member(group, &c.node_id, nodes))
        })?;

    if best.node_id == cur_id {
        return None;
    }

    let cur_snap = snaps.get(cur_id);
    let cur_runtime_healthy = health_pool
        .and_then(|p| p.get(cur_id))
        .is_some_and(|h| {
            h.last_health == Some(RuntimeDualHealth::FullHealthy) && !h.is_in_cooldown(now)
        });
    let assessment = report.active_assessment.as_ref();

    let reason = if cur_snap.is_none() && !cur_runtime_healthy {
        "当前节点尚未测速，已自动选用组内最优合格节点"
    } else if assessment.map_or(cur_snap.is_some_and(|s| !s.ok), |a| a.is_disconnected) {
        "当前节点测速未通过，已自动切换至组内最优健康节点"
    } else if best.passed_hard_gates && assessment.is_some_and(|a| !a.passed_hard_gates) {
        "当前节点未满足本组硬性门禁条件，已自动切换至达标最优节点"
    } else if best.meets_thresholds && assessment.is_some_and(|a| a.any_rule_triggered) {
        "当前节点已触发本组自动切换条件，已切换至达标最优节点"
    } else {
        // Current active node is in-group, probed, healthy, passes all hard gates, and triggers no rules:
        // preserve sticky selection to avoid IP drift.
        return None;
    };

    group.active_node_id = Some(best.node_id.clone());
    Some(ReconcileSwitchDecision {
        from_node_id: prev_id,
        from_node_name: prev_name,
        to_node_id: best.node_id.clone(),
        to_node_name: best.node_name.clone(),
        reason: reason.to_string(),
    })
}


pub(in crate::commands) fn validate_group_hard_gates(hard_gates: &[String]) -> Result<(), String> {
    for (idx, gate) in hard_gates.iter().enumerate() {
        let trimmed = gate.trim();
        if trimmed.is_empty() {
            continue;
        }
        catcloud_core::strategy::formula::validate_formula(trimmed).map_err(|e| {
            format!(
                "分组第 {} 条硬门禁表达式无效（{trimmed}）：{e}",
                idx + 1
            )
        })?;
    }
    Ok(())
}

