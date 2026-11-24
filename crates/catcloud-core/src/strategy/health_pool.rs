//! Lightweight runtime node health pool for multi-select groups.
//!
//! Tracks per-node EWMA smoothed latency, latest raw RTT, gradual penalty & exponential
//! cooldown backoff (`60s -> 180s -> 600s`, never permanently banning a node), background
//! round-robin sweep cursors, and two-consecutive-full-healthy recovery with a half-penalty
//! probation stage to prevent flapping.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// EWMA smoothing factor (`alpha = 0.35`): responsive to real shifts while damping spikes.
pub const EWMA_ALPHA: f64 = 0.35;

/// Score penalty added on each confirmed `Degraded` (1/2) dual probe.
pub const DEGRADED_PENALTY_STEP: f64 = 18.0;

/// Maximum cumulative penalty applied solely from `Degraded` probes.
pub const DEGRADED_PENALTY_CAP: f64 = 45.0;

/// Base score penalty when a node enters confirmed `Failed` (0/2) backoff.
pub const FAILED_PENALTY_BASE: f64 = 120.0;

/// Additional penalty per backoff stage (`1..=3`).
pub const FAILED_PENALTY_STAGE_STEP: f64 = 40.0;

/// Maximum exponential backoff stage (`1 -> 60s`, `2 -> 180s`, `3 -> 600s`).
pub const MAX_BACKOFF_STAGE: u8 = 3;

/// Exponential cooldown ladder in seconds for backoff stages `1`, `2`, and `3`.
pub const BACKOFF_COOLDOWN_SECS: [u64; 3] = [60, 180, 600];

/// Consecutive 2/2 `FullHealthy` probes required to lift cooldown / backoff.
pub const RECOVERY_STREAK_REQUIRED: u32 = 2;

/// Minimum interval between routine lightweight background sweeps of the same node.
pub const BACKGROUND_SWEEP_MIN_INTERVAL: Duration = Duration::from_secs(45);

/// Minimum interval between low-frequency recovery probes of the same penalized node.
pub const RECOVERY_CHECK_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// Dual-endpoint 204 health probe outcome recorded into [`NodeHealthPool`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeDualHealth {
    /// Both independent probe targets succeeded (2/2).
    FullHealthy,
    /// Exactly one probe target succeeded (1/2) or soft degradation confirmed.
    Degraded,
    /// Confirmed failure (0/2) after retry-before-penalize verification.
    Failed,
}

/// Compact runtime health hint DTO exposed to the UI via `RuntimeInfoDto.node_health_hints`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeHealthHintDto {
    pub latency_ms: Option<f64>,
    /// One of `"healthy"`, `"degraded"`, `"cooldown"`, or `"probation"`.
    pub status: String,
    pub cooldown_remaining_sec: u64,
}

/// Per-node runtime health metrics, penalty, cooldown, and recovery state.
#[derive(Debug, Clone, Default)]
pub struct RuntimeNodeHealth {
    pub ewma_latency_ms: Option<f64>,
    pub last_raw_latency_ms: Option<f64>,
    pub last_health: Option<RuntimeDualHealth>,
    pub penalty_score: f64,
    pub backoff_stage: u8,
    pub cooldown_until: Option<Instant>,
    pub recovery_streak: u32,
    pub probation_remaining: u8,
    pub last_probed_at: Option<Instant>,
    pub last_recovery_check_at: Option<Instant>,
}

impl RuntimeNodeHealth {
    /// Returns `true` while the node is actively inside its backoff cooldown window.
    pub fn is_in_cooldown(&self, now: Instant) -> bool {
        self.cooldown_until.is_some_and(|until| until > now)
    }

    /// Remaining cooldown duration in whole seconds (rounded up to at least 1s while active).
    pub fn cooldown_remaining_sec(&self, now: Instant) -> u64 {
        let Some(until) = self.cooldown_until else {
            return 0;
        };
        let Some(rem) = until.checked_duration_since(now) else {
            return 0;
        };
        if rem.is_zero() {
            return 0;
        }
        let secs = rem.as_secs();
        if rem.subsec_nanos() > 0 {
            secs.saturating_add(1)
        } else {
            secs
        }
    }

    /// Returns `true` if this node still carries any active cooldown, backoff, penalty, or probation.
    pub fn needs_recovery_attention(&self) -> bool {
        self.cooldown_until.is_some()
            || self.backoff_stage > 0
            || self.penalty_score > 1e-6
            || self.probation_remaining > 0
    }

    /// Categorize runtime status for UI hints (`"healthy" | "degraded" | "cooldown" | "probation"`).
    pub fn status_label(&self, now: Instant) -> &'static str {
        if self.is_in_cooldown(now) {
            "cooldown"
        } else if self.probation_remaining > 0 {
            "probation"
        } else if self.backoff_stage > 0
            || self.penalty_score > 1e-6
            || matches!(
                self.last_health,
                Some(RuntimeDualHealth::Degraded | RuntimeDualHealth::Failed)
            )
        {
            "degraded"
        } else {
            "healthy"
        }
    }
}

/// Convert a backoff stage (`1..=3`) to its cooldown duration in seconds (`60 -> 180 -> 600`).
pub fn backoff_cooldown_secs(stage: u8) -> u64 {
    if stage == 0 {
        return 0;
    }
    let idx = (stage.saturating_sub(1) as usize).min(BACKOFF_COOLDOWN_SECS.len() - 1);
    BACKOFF_COOLDOWN_SECS[idx]
}

/// In-memory runtime health pool shared by the background watchdog and strategy evaluator.
#[derive(Debug, Default, Clone)]
pub struct NodeHealthPool {
    nodes: HashMap<String, RuntimeNodeHealth>,
    group_cursors: HashMap<String, usize>,
}

impl NodeHealthPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrow runtime health state for a node if tracked.
    pub fn get(&self, node_id: &str) -> Option<&RuntimeNodeHealth> {
        self.nodes.get(node_id)
    }

    /// Number of currently tracked nodes.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns `true` when no nodes are tracked.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Record a confirmed dual-probe outcome at monotonic timestamp `now`.
    ///
    /// Callers should perform retry-before-penalize (e.g. an immediate 1.5s re-check on first
    /// failure) before recording `RuntimeDualHealth::Failed` so transient jitter never triggers
    /// heavy backoff.
    pub fn record_probe_result(
        &mut self,
        node_id: &str,
        health: RuntimeDualHealth,
        raw_latency_ms: Option<f64>,
        now: Instant,
    ) {
        let trimmed = node_id.trim();
        if trimmed.is_empty() {
            return;
        }
        let entry = self.nodes.entry(trimmed.to_string()).or_default();
        let was_needing_recovery = entry.needs_recovery_attention();

        entry.last_probed_at = Some(now);
        if was_needing_recovery {
            entry.last_recovery_check_at = Some(now);
        }

        if let Some(ms) = raw_latency_ms.filter(|v| v.is_finite() && *v > 0.0) {
            entry.last_raw_latency_ms = Some(ms);
            entry.ewma_latency_ms = Some(match entry.ewma_latency_ms {
                Some(prev) if prev.is_finite() && prev > 0.0 => {
                    EWMA_ALPHA * ms + (1.0 - EWMA_ALPHA) * prev
                }
                _ => ms,
            });
        }

        match health {
            RuntimeDualHealth::FullHealthy => {
                entry.last_health = Some(RuntimeDualHealth::FullHealthy);

                let in_cooldown_or_unrecovered = entry.cooldown_until.is_some()
                    || entry.backoff_stage > 0
                    || (entry.penalty_score > 1e-6 && entry.probation_remaining == 0);

                if in_cooldown_or_unrecovered {
                    entry.recovery_streak = entry.recovery_streak.saturating_add(1);
                    if entry.recovery_streak >= RECOVERY_STREAK_REQUIRED {
                        entry.cooldown_until = None;
                        entry.backoff_stage = 0;
                        entry.recovery_streak = 0;
                        let halved = (entry.penalty_score * 0.5).max(0.0);
                        if halved > 1e-6 {
                            entry.penalty_score = halved;
                            entry.probation_remaining = 1;
                        } else {
                            entry.penalty_score = 0.0;
                            entry.probation_remaining = 0;
                        }
                    }
                } else if entry.probation_remaining > 0 {
                    entry.probation_remaining = entry.probation_remaining.saturating_sub(1);
                    if entry.probation_remaining == 0 {
                        entry.penalty_score = 0.0;
                        entry.recovery_streak = 0;
                    }
                } else {
                    entry.penalty_score = 0.0;
                    entry.backoff_stage = 0;
                    entry.cooldown_until = None;
                    entry.recovery_streak = 0;
                    entry.probation_remaining = 0;
                }
            }
            RuntimeDualHealth::Degraded => {
                entry.last_health = Some(RuntimeDualHealth::Degraded);
                entry.recovery_streak = 0;

                if entry.backoff_stage > 0 || entry.cooldown_until.is_some() {
                    // Still recovering from a hard failure: do not clear backoff and do not
                    // reduce existing heavy penalty below what it already carries.
                    if !entry.is_in_cooldown(now) && entry.backoff_stage > 0 {
                        let secs = backoff_cooldown_secs(entry.backoff_stage);
                        entry.cooldown_until = Some(now + Duration::from_secs(secs));
                    }
                } else {
                    entry.probation_remaining = 0;
                    if entry.penalty_score < DEGRADED_PENALTY_CAP {
                        entry.penalty_score = (entry.penalty_score + DEGRADED_PENALTY_STEP)
                            .min(DEGRADED_PENALTY_CAP);
                    }
                }
            }
            RuntimeDualHealth::Failed => {
                entry.last_health = Some(RuntimeDualHealth::Failed);
                if !(entry.is_in_cooldown(now) && entry.backoff_stage > 0) {
                    entry.backoff_stage = entry
                        .backoff_stage
                        .saturating_add(1)
                        .min(MAX_BACKOFF_STAGE);
                }
                let cooldown_sec = backoff_cooldown_secs(entry.backoff_stage);
                entry.cooldown_until = Some(now + Duration::from_secs(cooldown_sec));
                entry.penalty_score =
                    FAILED_PENALTY_BASE + (entry.backoff_stage as f64) * FAILED_PENALTY_STAGE_STEP;
                entry.recovery_streak = 0;
                entry.probation_remaining = 0;
            }
        }
    }

    /// Round-robin selector for lightweight background 204 sweeps of non-cooling group members.
    ///
    /// Picks up to `batch_size` distinct members (excluding `exclude_active` and any node in
    /// active cooldown) whose last probe was at least 45 seconds ago (or never probed).
    /// Advances the per-group cursor so consecutive ticks rotate smoothly without rescanning
    /// the same prefix.
    pub fn select_background_sweep_ids(
        &mut self,
        group_id: &str,
        member_ids: &[String],
        exclude_active: Option<&str>,
        batch_size: usize,
        now: Instant,
    ) -> Vec<String> {
        if member_ids.is_empty() || batch_size == 0 {
            return Vec::new();
        }
        let excluded = exclude_active.map(str::trim).filter(|s| !s.is_empty());
        let len = member_ids.len();
        let start_cursor = self.group_cursors.get(group_id).copied().unwrap_or(0) % len;

        let mut picked = Vec::with_capacity(batch_size.min(len));
        let mut seen = HashSet::with_capacity(batch_size.min(len));
        let mut next_cursor = start_cursor;

        for step in 0..len {
            let idx = (start_cursor + step) % len;
            next_cursor = (idx + 1) % len;
            let raw_id = member_ids[idx].trim();
            if raw_id.is_empty() || excluded == Some(raw_id) || !seen.insert(raw_id) {
                continue;
            }
            if let Some(entry) = self.nodes.get(raw_id) {
                if entry.is_in_cooldown(now) {
                    continue;
                }
                if let Some(last) = entry.last_probed_at {
                    if now.saturating_duration_since(last) < BACKGROUND_SWEEP_MIN_INTERVAL {
                        continue;
                    }
                }
            }
            picked.push(raw_id.to_string());
            if picked.len() >= batch_size {
                break;
            }
        }

        self.group_cursors.insert(group_id.to_string(), next_cursor);
        picked
    }

    /// Select up to `limit` penalized or cooldown-expired members eligible for low-frequency
    /// recovery confirmation (`>= 60s` since the previous recovery check / probe).
    pub fn select_recovery_check_ids(
        &self,
        member_ids: &[String],
        limit: usize,
        now: Instant,
    ) -> Vec<String> {
        if member_ids.is_empty() || limit == 0 {
            return Vec::new();
        }

        let mut seen = HashSet::new();
        let mut eligible: Vec<(Option<Instant>, usize, String)> = Vec::new();

        for (order_idx, raw_id) in member_ids.iter().enumerate() {
            let id = raw_id.trim();
            if id.is_empty() || !seen.insert(id) {
                continue;
            }
            let Some(entry) = self.nodes.get(id) else {
                continue;
            };
            if !entry.needs_recovery_attention() || entry.is_in_cooldown(now) {
                continue;
            }
            let last_check = entry.last_recovery_check_at.or(entry.last_probed_at);
            if let Some(prev) = last_check {
                if now.saturating_duration_since(prev) < RECOVERY_CHECK_MIN_INTERVAL {
                    continue;
                }
            }
            eligible.push((last_check, order_idx, id.to_string()));
        }

        // Oldest checked (or never checked) recovery candidates go first.
        eligible.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        eligible.into_iter().take(limit).map(|(_, _, id)| id).collect()
    }

    /// Build a serializable snapshot of runtime health hints for UI display.
    pub fn build_hints_snapshot(&self, now: Instant) -> HashMap<String, NodeHealthHintDto> {
        let mut out = HashMap::with_capacity(self.nodes.len());
        for (id, entry) in &self.nodes {
            let status = entry.status_label(now);
            let latency_ms = if status == "cooldown"
                || entry.last_health == Some(RuntimeDualHealth::Failed)
            {
                None
            } else {
                entry.last_raw_latency_ms.or(entry.ewma_latency_ms)
            };
            out.insert(
                id.clone(),
                NodeHealthHintDto {
                    latency_ms,
                    status: status.to_string(),
                    cooldown_remaining_sec: entry.cooldown_remaining_sec(now),
                },
            );
        }
        out
    }

    /// Return the freshest live latency (raw RTT preferred, EWMA fallback) for a healthy/degraded node.
    /// Returns `None` if the node is unprobed or its latest confirmed probe was `Failed`.
    pub fn live_latency_ms(&self, node_id: &str) -> Option<f64> {
        let entry = self.nodes.get(node_id)?;
        if entry.last_health == Some(RuntimeDualHealth::Failed) {
            return None;
        }
        entry.last_raw_latency_ms.or(entry.ewma_latency_ms)
    }

    /// Return EWMA smoothed latency for a node when available.
    pub fn ewma_latency_ms(&self, node_id: &str) -> Option<f64> {
        self.nodes.get(node_id)?.ewma_latency_ms
    }

    /// Returns `true` when `node_id` is currently inside an active backoff cooldown window.
    pub fn is_in_cooldown(&self, node_id: &str, now: Instant) -> bool {
        self.nodes
            .get(node_id)
            .is_some_and(|entry| entry.is_in_cooldown(now))
    }

    /// Drop entries for node IDs that no longer exist in inventory.
    pub fn prune_missing_nodes(&mut self, valid_ids: &HashSet<String>) {
        self.nodes.retain(|id, _| valid_ids.contains(id));
    }

    /// Remove the round-robin sweep cursor for a deleted or renamed multi-select group.
    pub fn remove_group_cursor(&mut self, group_id: &str) {
        self.group_cursors.remove(group_id);
    }

    /// Drop round-robin sweep cursors for group IDs that no longer exist in inventory.
    pub fn prune_missing_groups(&mut self, valid_group_ids: &HashSet<String>) {
        self.group_cursors
            .retain(|group_id, _| valid_group_ids.contains(group_id));
    }

    /// Clear runtime penalty/cooldown for a node (e.g. after an explicit manual full-green probe).
    pub fn reset_node(&mut self, node_id: &str) {
        self.nodes.remove(node_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ewma_smoothing_and_live_latency_updates() {
        let mut pool = NodeHealthPool::new();
        let t0 = Instant::now();

        pool.record_probe_result("n1", RuntimeDualHealth::FullHealthy, Some(100.0), t0);
        let h1 = pool.get("n1").expect("n1 tracked");
        assert!((h1.ewma_latency_ms.unwrap() - 100.0).abs() < 1e-6);
        assert!((h1.last_raw_latency_ms.unwrap() - 100.0).abs() < 1e-6);
        assert_eq!(pool.live_latency_ms("n1"), Some(100.0));

        // Second probe with spike 200ms -> 0.35 * 200 + 0.65 * 100 = 135.0ms
        pool.record_probe_result(
            "n1",
            RuntimeDualHealth::FullHealthy,
            Some(200.0),
            t0 + Duration::from_secs(25),
        );
        let h2 = pool.get("n1").expect("n1 tracked");
        assert!((h2.ewma_latency_ms.unwrap() - 135.0).abs() < 1e-6);
        assert!((h2.last_raw_latency_ms.unwrap() - 200.0).abs() < 1e-6);
        assert_eq!(pool.live_latency_ms("n1"), Some(200.0));
    }

    #[test]
    fn degraded_applies_mild_capped_penalty_without_cooldown() {
        let mut pool = NodeHealthPool::new();
        let t0 = Instant::now();

        pool.record_probe_result("n1", RuntimeDualHealth::Degraded, Some(140.0), t0);
        let h1 = pool.get("n1").unwrap();
        assert!(!pool.is_in_cooldown("n1", t0));
        assert_eq!(h1.backoff_stage, 0);
        assert!((h1.penalty_score - 18.0).abs() < 1e-6);

        pool.record_probe_result(
            "n1",
            RuntimeDualHealth::Degraded,
            Some(150.0),
            t0 + Duration::from_secs(20),
        );
        assert!((pool.get("n1").unwrap().penalty_score - 36.0).abs() < 1e-6);

        pool.record_probe_result(
            "n1",
            RuntimeDualHealth::Degraded,
            Some(160.0),
            t0 + Duration::from_secs(40),
        );
        let h3 = pool.get("n1").unwrap();
        assert!((h3.penalty_score - 45.0).abs() < 1e-6);
        assert!(!pool.is_in_cooldown("n1", t0 + Duration::from_secs(40)));
    }

    #[test]
    fn exponential_backoff_ladder_and_two_streak_recovery_with_probation() {
        let mut pool = NodeHealthPool::new();
        let t0 = Instant::now();

        // Failure 1 -> stage 1, 60s cooldown, penalty 160
        pool.record_probe_result("n1", RuntimeDualHealth::Failed, None, t0);
        let h1 = pool.get("n1").unwrap();
        assert_eq!(h1.backoff_stage, 1);
        assert!((h1.penalty_score - 160.0).abs() < 1e-6);
        assert!(pool.is_in_cooldown("n1", t0 + Duration::from_secs(59)));
        assert!(!pool.is_in_cooldown("n1", t0 + Duration::from_secs(60)));
        assert_eq!(pool.live_latency_ms("n1"), None);

        // Failure 2 -> stage 2, 180s cooldown, penalty 200
        let t1 = t0 + Duration::from_secs(65);
        pool.record_probe_result("n1", RuntimeDualHealth::Failed, None, t1);
        let h2 = pool.get("n1").unwrap();
        assert_eq!(h2.backoff_stage, 2);
        assert!((h2.penalty_score - 200.0).abs() < 1e-6);
        assert!(pool.is_in_cooldown("n1", t1 + Duration::from_secs(179)));
        assert!(!pool.is_in_cooldown("n1", t1 + Duration::from_secs(180)));

        // Failure 3 -> stage 3, 600s cooldown, penalty 240
        let t2 = t1 + Duration::from_secs(190);
        pool.record_probe_result("n1", RuntimeDualHealth::Failed, None, t2);
        let h3 = pool.get("n1").unwrap();
        assert_eq!(h3.backoff_stage, 3);
        assert!((h3.penalty_score - 240.0).abs() < 1e-6);
        assert!(pool.is_in_cooldown("n1", t2 + Duration::from_secs(599)));
        assert!(!pool.is_in_cooldown("n1", t2 + Duration::from_secs(600)));

        // Failure 4 -> remains capped at stage 3 (600s, never permanently banned)
        let t3 = t2 + Duration::from_secs(610);
        pool.record_probe_result("n1", RuntimeDualHealth::Failed, None, t3);
        assert_eq!(pool.get("n1").unwrap().backoff_stage, 3);
        assert!((pool.get("n1").unwrap().penalty_score - 240.0).abs() < 1e-6);

        // Cooldown expires -> 1st FullHealthy builds recovery_streak=1, still NOT fully cleared
        let t4 = t3 + Duration::from_secs(605);
        let members = vec!["n1".to_string()];
        assert_eq!(pool.select_recovery_check_ids(&members, 2, t4), vec!["n1"]);

        pool.record_probe_result("n1", RuntimeDualHealth::FullHealthy, Some(75.0), t4);
        let h_rec1 = pool.get("n1").unwrap();
        assert_eq!(h_rec1.recovery_streak, 1);
        assert_eq!(h_rec1.backoff_stage, 3);
        assert!((h_rec1.penalty_score - 240.0).abs() < 1e-6);
        // Too soon (< 60s) for second recovery check
        assert!(
            pool.select_recovery_check_ids(&members, 2, t4 + Duration::from_secs(30))
                .is_empty()
        );

        // 2nd consecutive FullHealthy (>= 60s later) lifts cooldown into half-penalty probation!
        let t5 = t4 + Duration::from_secs(65);
        assert_eq!(pool.select_recovery_check_ids(&members, 2, t5), vec!["n1"]);
        pool.record_probe_result("n1", RuntimeDualHealth::FullHealthy, Some(70.0), t5);
        let h_prob = pool.get("n1").unwrap();
        assert_eq!(h_prob.backoff_stage, 0);
        assert_eq!(h_prob.cooldown_until, None);
        assert_eq!(h_prob.probation_remaining, 1);
        assert!((h_prob.penalty_score - 120.0).abs() < 1e-6);
        let hints_prob = pool.build_hints_snapshot(t5);
        assert_eq!(hints_prob["n1"].status, "probation");
        assert_eq!(hints_prob["n1"].cooldown_remaining_sec, 0);

        // 3rd FullHealthy clears probation completely to full weight (penalty = 0.0)
        let t6 = t5 + Duration::from_secs(65);
        pool.record_probe_result("n1", RuntimeDualHealth::FullHealthy, Some(65.0), t6);
        let h_full = pool.get("n1").unwrap();
        assert_eq!(h_full.probation_remaining, 0);
        assert!((h_full.penalty_score - 0.0).abs() < 1e-6);
        assert_eq!(pool.build_hints_snapshot(t6)["n1"].status, "healthy");
    }

    #[test]
    fn round_robin_sweep_rotates_without_duplicating_or_rescanning_fresh_nodes() {
        let mut pool = NodeHealthPool::new();
        let t0 = Instant::now();
        let members = vec![
            "active".to_string(),
            "n1".to_string(),
            "n2".to_string(),
            "n3".to_string(),
            "n4".to_string(),
            "cooling".to_string(),
        ];

        pool.record_probe_result("cooling", RuntimeDualHealth::Failed, None, t0);

        // Tick 1: picks n1, n2 (skips active & cooling)
        let batch1 = pool.select_background_sweep_ids("g1", &members, Some("active"), 2, t0);
        assert_eq!(batch1, vec!["n1", "n2"]);
        for id in &batch1 {
            pool.record_probe_result(id, RuntimeDualHealth::FullHealthy, Some(50.0), t0);
        }

        // Tick 2 (+20s): picks n3, n4 (does NOT repeat n1/n2)
        let t1 = t0 + Duration::from_secs(20);
        let batch2 = pool.select_background_sweep_ids("g1", &members, Some("active"), 2, t1);
        assert_eq!(batch2, vec!["n3", "n4"]);
        for id in &batch2 {
            pool.record_probe_result(id, RuntimeDualHealth::FullHealthy, Some(60.0), t1);
        }

        // Tick 3 (+30s): all non-cooling members probed < 45s ago -> returns empty
        let t2 = t0 + Duration::from_secs(30);
        let batch3 = pool.select_background_sweep_ids("g1", &members, Some("active"), 2, t2);
        assert!(batch3.is_empty());

        // Tick 4 (+50s): n1, n2 now >= 45s old -> eligible again
        let t3 = t0 + Duration::from_secs(50);
        let batch4 = pool.select_background_sweep_ids("g1", &members, Some("active"), 2, t3);
        assert_eq!(batch4, vec!["n1", "n2"]);

        // Prune removes vanished IDs
        let valid: HashSet<String> = ["n1".to_string(), "n2".to_string()].into_iter().collect();
        pool.prune_missing_nodes(&valid);
        assert_eq!(pool.len(), 2);
        assert!(pool.get("cooling").is_none());
    }

    #[test]
    fn failed_within_active_cooldown_holds_stage_and_refreshes_deadline() {
        let mut pool = NodeHealthPool::new();
        let t0 = Instant::now();

        // First confirmed failure enters Stage 1 (60s cooldown, penalty 160).
        pool.record_probe_result("n1", RuntimeDualHealth::Failed, None, t0);
        let h1 = pool.get("n1").unwrap();
        assert_eq!(h1.backoff_stage, 1);
        assert!((h1.penalty_score - 160.0).abs() < 1e-6);
        assert!(pool.is_in_cooldown("n1", t0 + Duration::from_secs(25)));

        // Re-failing inside the active 60s window (e.g. +25s) must NOT jump to Stage 2 (180s);
        // it holds Stage 1 and refreshes cooldown_until to t0 + 25s + 60s = t0 + 85s.
        let t_retry = t0 + Duration::from_secs(25);
        pool.record_probe_result("n1", RuntimeDualHealth::Failed, None, t_retry);
        let h2 = pool.get("n1").unwrap();
        assert_eq!(h2.backoff_stage, 1);
        assert!((h2.penalty_score - 160.0).abs() < 1e-6);
        assert!(pool.is_in_cooldown("n1", t_retry + Duration::from_secs(59)));
        assert!(!pool.is_in_cooldown("n1", t_retry + Duration::from_secs(60)));

        // Failing again AFTER the refreshed cooldown expires escalates to Stage 2 (180s, penalty 200).
        let t_expired = t_retry + Duration::from_secs(61);
        pool.record_probe_result("n1", RuntimeDualHealth::Failed, None, t_expired);
        let h3 = pool.get("n1").unwrap();
        assert_eq!(h3.backoff_stage, 2);
        assert!((h3.penalty_score - 200.0).abs() < 1e-6);
        assert!(pool.is_in_cooldown("n1", t_expired + Duration::from_secs(179)));

        // Another failure inside the Stage 2 window holds Stage 2 and refreshes the 180s window.
        let t_stage2_retry = t_expired + Duration::from_secs(100);
        pool.record_probe_result("n1", RuntimeDualHealth::Failed, None, t_stage2_retry);
        let h4 = pool.get("n1").unwrap();
        assert_eq!(h4.backoff_stage, 2);
        assert!((h4.penalty_score - 200.0).abs() < 1e-6);
        assert!(pool.is_in_cooldown("n1", t_stage2_retry + Duration::from_secs(179)));
        assert!(!pool.is_in_cooldown("n1", t_stage2_retry + Duration::from_secs(180)));
    }

    #[test]
    fn group_cursor_removal_and_pruning_clears_stale_groups() {
        let mut pool = NodeHealthPool::new();
        let t0 = Instant::now();
        let members = vec!["n1".to_string(), "n2".to_string(), "n3".to_string()];

        assert_eq!(
            pool.select_background_sweep_ids("g1", &members, None, 1, t0),
            vec!["n1"]
        );
        assert_eq!(
            pool.select_background_sweep_ids("g2", &members, None, 1, t0),
            vec!["n1"]
        );
        assert_eq!(
            pool.select_background_sweep_ids("g3", &members, None, 1, t0),
            vec!["n1"]
        );

        pool.remove_group_cursor("g2");
        assert_eq!(
            pool.select_background_sweep_ids("g2", &members, None, 1, t0),
            vec!["n1"]
        );
        assert_eq!(
            pool.select_background_sweep_ids("g1", &members, None, 1, t0),
            vec!["n2"]
        );

        let valid_groups: HashSet<String> = ["g1".to_string()].into_iter().collect();
        pool.prune_missing_groups(&valid_groups);
        assert_eq!(
            pool.select_background_sweep_ids("g1", &members, None, 1, t0),
            vec!["n3"]
        );
        // g3 cursor was pruned, so scanning starts from index 0 again.
        assert_eq!(
            pool.select_background_sweep_ids("g3", &members, None, 1, t0),
            vec!["n1"]
        );
    }
}
