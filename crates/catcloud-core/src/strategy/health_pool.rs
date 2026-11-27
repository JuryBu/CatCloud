//! Lightweight runtime node health pool for multi-select groups.
//!
//! Tracks per-node EWMA smoothed latency, latest raw RTT, gradual penalty & exponential
//! cooldown backoff (`60s -> 180s -> 600s`, never permanently banning a node), background
//! round-robin sweep cursors, and two-consecutive-full-healthy recovery with a half-penalty
//! probation stage to prevent flapping.

use crate::error::CatResult;
use crate::paths::AppPaths;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
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
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct NodeHealthHintDto {
    pub latency_ms: Option<f64>,
    /// One of `"healthy"`, `"degraded"`, `"cooldown"`, or `"probation"`.
    pub status: String,
    pub cooldown_remaining_sec: u64,
    /// Human-readable Chinese reason explaining current runtime health / penalty status.
    #[serde(default)]
    pub reason: String,
    /// Structured lifecycle stage (`"healthy"`, `"degraded"`, `"cooldown_s1"`, `"cooldown_s2"`,
    /// `"cooldown_s3"`, `"recovery_pending"`, or `"probation"`).
    #[serde(default)]
    pub stage: String,
    /// UTC Unix timestamp in milliseconds of the latest confirmed background health probe.
    #[serde(default)]
    pub probed_at_ms: Option<i64>,
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
    pub last_probed_at_utc_ms: Option<i64>,
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

    /// Return a structured stage identifier for observability & diagnostics.
    pub fn stage_label(&self, now: Instant) -> String {
        if self.is_in_cooldown(now) {
            format!("cooldown_s{}", self.backoff_stage.max(1))
        } else if self.probation_remaining > 0 {
            "probation".to_string()
        } else if self.backoff_stage > 0 || self.cooldown_until.is_some() {
            "recovery_pending".to_string()
        } else if self.penalty_score > 1e-6
            || matches!(
                self.last_health,
                Some(RuntimeDualHealth::Degraded | RuntimeDualHealth::Failed)
            )
        {
            "degraded".to_string()
        } else {
            "healthy".to_string()
        }
    }

    /// Return a concise, user-facing Chinese explanation of the current health state.
    pub fn reason_zh(&self, now: Instant) -> String {
        if self.is_in_cooldown(now) {
            let rem = self.cooldown_remaining_sec(now);
            let stage = self.backoff_stage.max(1);
            format!("连续探测超时，冷却退避中（第 {stage} 阶，剩余 {rem}s）")
        } else if self.probation_remaining > 0 {
            "恢复观察中（半罚分保护，避免抖动回切）".to_string()
        } else if self.backoff_stage > 0 || self.cooldown_until.is_some() {
            if self.recovery_streak > 0 {
                format!(
                    "恢复观察中（已连续通过 {}/{} 次双源检测）",
                    self.recovery_streak, RECOVERY_STREAK_REQUIRED
                )
            } else {
                "连续探测超时，冷却到期等待恢复复测".to_string()
            }
        } else if matches!(self.last_health, Some(RuntimeDualHealth::Degraded))
            || self.penalty_score > 1e-6
        {
            "双源半残降权（仅单侧探测通过）".to_string()
        } else if matches!(self.last_health, Some(RuntimeDualHealth::Failed)) {
            "连续探测超时，降权待恢复".to_string()
        } else {
            "双源探测正常".to_string()
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

    /// Record a confirmed dual-probe outcome at monotonic timestamp `now`, stamping the current
    /// UTC Unix millisecond wall-clock time for cross-source freshness comparison.
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
        self.record_probe_result_at_utc(
            node_id,
            health,
            raw_latency_ms,
            now,
            chrono::Utc::now().timestamp_millis(),
        );
    }

    /// Record a confirmed dual-probe outcome at monotonic timestamp `now` with an explicit UTC
    /// Unix millisecond timestamp `probed_at_ms`.
    pub fn record_probe_result_at_utc(
        &mut self,
        node_id: &str,
        health: RuntimeDualHealth,
        raw_latency_ms: Option<f64>,
        now: Instant,
        probed_at_ms: i64,
    ) {
        let trimmed = node_id.trim();
        if trimmed.is_empty() {
            return;
        }
        let entry = self.nodes.entry(trimmed.to_string()).or_default();
        let was_needing_recovery = entry.needs_recovery_attention();

        entry.last_probed_at = Some(now);
        entry.last_probed_at_utc_ms = Some(probed_at_ms);
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
                entry
                    .ewma_latency_ms
                    .filter(|v| v.is_finite() && *v > 0.0)
                    .or_else(|| {
                        entry
                            .last_raw_latency_ms
                            .filter(|v| v.is_finite() && *v > 0.0)
                    })
            };
            out.insert(
                id.clone(),
                NodeHealthHintDto {
                    latency_ms,
                    status: status.to_string(),
                    cooldown_remaining_sec: entry.cooldown_remaining_sec(now),
                    reason: entry.reason_zh(now),
                    stage: entry.stage_label(now),
                    probed_at_ms: entry.last_probed_at_utc_ms,
                },
            );
        }
        out
    }

    /// Return the smoothed live latency (EWMA preferred, raw RTT fallback) for a healthy/degraded node,
    /// aligned with `evaluator.rs::apply_runtime_health_to_context` so UI and scoring see the same value.
    /// Returns `None` if the node is unprobed or its latest confirmed probe was `Failed`.
    pub fn live_latency_ms(&self, node_id: &str) -> Option<f64> {
        let entry = self.nodes.get(node_id)?;
        if entry.last_health == Some(RuntimeDualHealth::Failed) {
            return None;
        }
        entry
            .ewma_latency_ms
            .filter(|v| v.is_finite() && *v > 0.0)
            .or_else(|| {
                entry
                    .last_raw_latency_ms
                    .filter(|v| v.is_finite() && *v > 0.0)
            })
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

/// Maximum number of recent watchdog decision events retained in [`WatchdogStateSnapshot`].
pub const MAX_WATCHDOG_RECENT_EVENTS: usize = 20;

/// Relative filename under `<data_dir>/run/` for persisted watchdog observability snapshots.
pub const WATCHDOG_STATE_FILENAME: &str = "watchdog-state.json";

/// Per-candidate evaluation trace captured inside a [`WatchdogDecisionEvent`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct WatchdogCandidateTrace {
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub node_name: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub score: Option<f64>,
    #[serde(default)]
    pub latency_ms: Option<f64>,
    #[serde(default)]
    pub reason: String,
}

/// Structured record of a single watchdog evaluation or automatic switch decision.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct WatchdogDecisionEvent {
    #[serde(default)]
    pub timestamp: String,
    #[serde(default)]
    pub group_id: String,
    #[serde(default)]
    pub group_name: String,
    #[serde(default)]
    pub trigger_reason: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub from_node_id: Option<String>,
    #[serde(default)]
    pub from_node_name: Option<String>,
    #[serde(default)]
    pub to_node_id: Option<String>,
    #[serde(default)]
    pub to_node_name: Option<String>,
    #[serde(default)]
    pub current_probe_summary: String,
    #[serde(default)]
    pub candidates: Vec<WatchdogCandidateTrace>,
    #[serde(default)]
    pub next_recheck_at: Option<String>,
    #[serde(default)]
    pub keep_existing_connections: bool,
}

/// Active group-level backoff summary exposed inside [`WatchdogStateSnapshot`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WatchdogGroupBackoffEntry {
    #[serde(default)]
    pub group_id: String,
    #[serde(default)]
    pub group_name: String,
    #[serde(default)]
    pub consecutive_failures: u32,
    #[serde(default)]
    pub backoff_until: Option<String>,
    #[serde(default)]
    pub reason: String,
}

/// Active node cooldown/probation summary exposed inside [`WatchdogStateSnapshot`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WatchdogCooldownNodeEntry {
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub node_name: String,
    #[serde(default)]
    pub stage: String,
    #[serde(default)]
    pub cooldown_remaining_sec: u64,
    #[serde(default)]
    pub reason: String,
}

/// Persisted observability snapshot of background watchdog state and recent decisions.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct WatchdogStateSnapshot {
    #[serde(default)]
    pub updated_at: String,
    #[serde(default)]
    pub active_backoffs: Vec<WatchdogGroupBackoffEntry>,
    #[serde(default)]
    pub cooldown_nodes: Vec<WatchdogCooldownNodeEntry>,
    /// Most recent watchdog decision events, capped at [`MAX_WATCHDOG_RECENT_EVENTS`] (20).
    #[serde(default)]
    pub recent_events: Vec<WatchdogDecisionEvent>,
}

impl WatchdogStateSnapshot {
    /// Append a watchdog decision event while keeping at most [`MAX_WATCHDOG_RECENT_EVENTS`] items.
    pub fn push_event(&mut self, event: WatchdogDecisionEvent) {
        self.recent_events.push(event);
        self.trim_recent_events();
    }

    /// Retain only the newest [`MAX_WATCHDOG_RECENT_EVENTS`] decision events.
    pub fn trim_recent_events(&mut self) {
        if self.recent_events.len() > MAX_WATCHDOG_RECENT_EVENTS {
            let drain_count = self.recent_events.len() - MAX_WATCHDOG_RECENT_EVENTS;
            self.recent_events.drain(0..drain_count);
        }
    }
}

/// Canonical path to the persisted watchdog state snapshot (`<data_dir>/run/watchdog-state.json`).
pub fn watchdog_state_snapshot_path(data_dir: &Path) -> PathBuf {
    data_dir.join("run").join(WATCHDOG_STATE_FILENAME)
}

/// Atomically persist [`WatchdogStateSnapshot`] to `<data_dir>/run/watchdog-state.json`,
/// enforcing the 20-event cap and `0o600` permissions on Unix.
pub fn write_watchdog_state_snapshot(
    data_dir: &Path,
    snapshot: &WatchdogStateSnapshot,
) -> CatResult<()> {
    let path = watchdog_state_snapshot_path(data_dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut normalized = snapshot.clone();
    normalized.trim_recent_events();
    let payload = serde_json::to_vec_pretty(&normalized)?;
    AppPaths::atomic_write(&path, &payload)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Read the latest persisted [`WatchdogStateSnapshot`] from `<data_dir>/run/watchdog-state.json`.
pub fn read_watchdog_state_snapshot(data_dir: &Path) -> Option<WatchdogStateSnapshot> {
    let primary = watchdog_state_snapshot_path(data_dir);
    let bytes = std::fs::read(&primary)
        .or_else(|_| std::fs::read(data_dir.join(WATCHDOG_STATE_FILENAME)))
        .ok()?;
    let mut snapshot: WatchdogStateSnapshot = serde_json::from_slice(&bytes).ok()?;
    snapshot.trim_recent_events();
    Some(snapshot)
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
        assert!((pool.live_latency_ms("n1").unwrap() - 135.0).abs() < 1e-6);
        let hints = pool.build_hints_snapshot(t0 + Duration::from_secs(25));
        assert!((hints["n1"].latency_ms.unwrap() - 135.0).abs() < 1e-6);
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

    #[test]
    fn hints_snapshot_populates_chinese_reason_and_stage_across_states() {
        let mut pool = NodeHealthPool::new();
        let t0 = Instant::now();

        pool.record_probe_result("n-ok", RuntimeDualHealth::FullHealthy, Some(65.0), t0);
        pool.record_probe_result("n-deg", RuntimeDualHealth::Degraded, Some(120.0), t0);
        pool.record_probe_result("n-cool", RuntimeDualHealth::Failed, None, t0);

        let snap1 = pool.build_hints_snapshot(t0 + Duration::from_secs(5));
        assert_eq!(snap1["n-ok"].stage, "healthy");
        assert!(snap1["n-ok"].reason.contains("正常"));

        assert_eq!(snap1["n-deg"].stage, "degraded");
        assert!(snap1["n-deg"].reason.contains("双源半残降权"));

        assert_eq!(snap1["n-cool"].stage, "cooldown_s1");
        assert!(snap1["n-cool"].reason.contains("连续探测超时"));
        assert!(snap1["n-cool"].cooldown_remaining_sec > 0);

        // After cooldown expires and two consecutive full-healthy probes, enters probation.
        let t1 = t0 + Duration::from_secs(65);
        pool.record_probe_result("n-cool", RuntimeDualHealth::FullHealthy, Some(70.0), t1);
        let snap_recovering = pool.build_hints_snapshot(t1);
        assert_eq!(snap_recovering["n-cool"].stage, "recovery_pending");
        assert!(snap_recovering["n-cool"].reason.contains("恢复观察中"));

        let t2 = t1 + Duration::from_secs(65);
        pool.record_probe_result("n-cool", RuntimeDualHealth::FullHealthy, Some(68.0), t2);
        let snap_probation = pool.build_hints_snapshot(t2);
        assert_eq!(snap_probation["n-cool"].stage, "probation");
        assert!(snap_probation["n-cool"].reason.contains("恢复观察中"));
    }

    #[test]
    fn watchdog_state_snapshot_roundtrip_and_caps_recent_events_to_twenty() {
        let dir = std::env::temp_dir().join(format!(
            "catcloud-watchdog-snap-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let mut snapshot = WatchdogStateSnapshot {
            updated_at: "2026-11-27T01:30:00Z".to_string(),
            active_backoffs: vec![WatchdogGroupBackoffEntry {
                group_id: "g-ai".to_string(),
                group_name: "AI-主力".to_string(),
                consecutive_failures: 2,
                backoff_until: Some("2026-11-27T01:35:00Z".to_string()),
                reason: "连续探测超时".to_string(),
            }],
            cooldown_nodes: vec![WatchdogCooldownNodeEntry {
                node_id: "n-bad".to_string(),
                node_name: "JP-01".to_string(),
                stage: "cooldown_s1".to_string(),
                cooldown_remaining_sec: 55,
                reason: "连续探测超时，冷却退避中（第 1 阶，剩余 55s）".to_string(),
            }],
            recent_events: Vec::new(),
        };

        for idx in 0..25 {
            snapshot.recent_events.push(WatchdogDecisionEvent {
                timestamp: format!("2026-11-27T01:{idx:02}:00Z"),
                group_id: "g-ai".to_string(),
                group_name: "AI-主力".to_string(),
                trigger_reason: format!("event-{idx}"),
                action: "switch".to_string(),
                from_node_id: Some("n-old".to_string()),
                from_node_name: Some("JP-Old".to_string()),
                to_node_id: Some("n-new".to_string()),
                to_node_name: Some("TW-New".to_string()),
                current_probe_summary: "0/2 timeout".to_string(),
                candidates: vec![WatchdogCandidateTrace {
                    node_id: "n-new".to_string(),
                    node_name: "TW-New".to_string(),
                    status: "healthy".to_string(),
                    score: Some(88.5),
                    latency_ms: Some(42.0),
                    reason: "双源探测正常".to_string(),
                }],
                next_recheck_at: Some("2026-11-27T01:31:00Z".to_string()),
                keep_existing_connections: true,
            });
        }

        write_watchdog_state_snapshot(&dir, &snapshot).expect("write watchdog snapshot");
        assert!(watchdog_state_snapshot_path(&dir).is_file());

        let loaded = read_watchdog_state_snapshot(&dir).expect("read watchdog snapshot");
        assert_eq!(loaded.recent_events.len(), MAX_WATCHDOG_RECENT_EVENTS);
        assert_eq!(loaded.recent_events[0].trigger_reason, "event-5");
        assert_eq!(
            loaded.recent_events.last().unwrap().trigger_reason,
            "event-24"
        );
        assert!(loaded.recent_events[0].keep_existing_connections);
        assert_eq!(loaded.active_backoffs.len(), 1);
        assert_eq!(loaded.cooldown_nodes.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hints_snapshot_exposes_utc_probed_at_ms_and_handles_unprobed_and_serde_default() {
        let mut pool = NodeHealthPool::new();
        let t0 = Instant::now();

        // 1. Default unprobed entry has probed_at_ms == None.
        pool.nodes
            .insert("n-unprobed".to_string(), RuntimeNodeHealth::default());
        let hints0 = pool.build_hints_snapshot(t0);
        assert_eq!(hints0["n-unprobed"].probed_at_ms, None);

        // 2. Real probe via `record_probe_result` stamps current UTC Unix ms.
        let before_ms = chrono::Utc::now().timestamp_millis();
        pool.record_probe_result("n-live", RuntimeDualHealth::FullHealthy, Some(48.0), t0);
        let after_ms = chrono::Utc::now().timestamp_millis();
        let live_ts = pool
            .build_hints_snapshot(t0)
            .get("n-live")
            .and_then(|h| h.probed_at_ms)
            .expect("probed_at_ms must be populated after record_probe_result");
        assert!(
            live_ts >= before_ms && live_ts <= after_ms,
            "probed_at_ms ({live_ts}) must lie within [{before_ms}, {after_ms}]"
        );

        // 3. Explicit UTC timestamp helper preserves exact value and survives serde roundtrip.
        let fixed_ts = 1_795_750_000_123_i64;
        pool.record_probe_result_at_utc(
            "n-fixed",
            RuntimeDualHealth::Degraded,
            Some(92.0),
            t0,
            fixed_ts,
        );
        let hint = pool.build_hints_snapshot(t0).remove("n-fixed").unwrap();
        assert_eq!(hint.probed_at_ms, Some(fixed_ts));
        let json = serde_json::to_string(&hint).unwrap();
        let roundtrip: NodeHealthHintDto = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.probed_at_ms, Some(fixed_ts));

        // 4. Legacy JSON without `probed_at_ms` deserializes safely with `None`.
        let legacy: NodeHealthHintDto = serde_json::from_str(
            r#"{"latency_ms":55.0,"status":"healthy","cooldown_remaining_sec":0}"#,
        )
        .unwrap();
        assert_eq!(legacy.probed_at_ms, None);
    }
}
