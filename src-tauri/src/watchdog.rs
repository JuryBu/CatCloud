//! Multi-group health watchdog and automatic failover engine.
//!
//! Periodically probes active nodes and round-robin backup candidates via dual independent
//! 204 origins (Google + Cloudflare), enforcing retry-before-penalize, high-throughput
//! transfer suppression, exponential backoff cooldowns, anti-ping-pong protection, and
//! atomic `watchdog-state.json` persistence.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use catcloud_core::models::{
    MultiGroup, MultiGroupMode, NodeSummary, ProbeSnapshot, ProxyMode, ProxyNode, RouteTargetMode,
    SwitchMode,
};
use catcloud_core::strategy::evaluator::evaluate_group_candidates_with_runtime;
use catcloud_core::strategy::health_pool::{
    NodeHealthPool, RuntimeDualHealth, WatchdogCandidateTrace, WatchdogCooldownNodeEntry,
    WatchdogDecisionEvent, WatchdogGroupBackoffEntry, WatchdogStateSnapshot,
    read_watchdog_state_snapshot, write_watchdog_state_snapshot,
};
use tauri::{Emitter, Manager};

use crate::commands::{self, AppState};

const WATCHDOG_PROBE_PRIMARY_URL: &str = "https://www.gstatic.com/generate_204";
const WATCHDOG_PROBE_SECONDARY_URL: &str = "https://cp.cloudflare.com/generate_204";
const WATCHDOG_DEGRADED_THRESHOLD_ROUNDS: u32 = 4;
const WATCHDOG_INTERVAL_SECS: u64 = 25;
const WATCHDOG_RETRY_DELAY_MS: u64 = 1500;
const WATCHDOG_ACTIVE_PROBE_TIMEOUT_MS: u64 = 4500;
const WATCHDOG_CANDIDATE_PROBE_TIMEOUT_MS: u64 = 3500;
const WATCHDOG_SWEEP_BATCH_SIZE: usize = 3;
const WATCHDOG_SWEEP_TIMEOUT_MS: u64 = 3000;
const WATCHDOG_RECOVERY_LIMIT: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DualProbeHealth {
    /// Both independent origins (Google + Cloudflare) succeeded.
    FullHealthy(u64),
    /// Exactly one origin succeeded while the other timed out / errored (partial outage or
    /// probabilistic packet loss such as 50% broken new-connection routing).
    Degraded {
        passed_delay_ms: u64,
        failed_source: &'static str,
    },
    /// Both independent origins failed — confirmed true outage.
    TotalFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatchdogFailoverTrigger {
    TotalOutage {
        fail_count: u32,
    },
    SustainedDegraded {
        degraded_rounds: u32,
        failed_source: &'static str,
    },
}

fn classify_dual_probe_health(
    primary_google_ms: Option<u64>,
    secondary_cf_ms: Option<u64>,
) -> DualProbeHealth {
    match (primary_google_ms, secondary_cf_ms) {
        (Some(g), Some(c)) => DualProbeHealth::FullHealthy((g.saturating_add(c)) / 2),
        (Some(g), None) => DualProbeHealth::Degraded {
            passed_delay_ms: g,
            failed_source: "Cloudflare",
        },
        (None, Some(c)) => DualProbeHealth::Degraded {
            passed_delay_ms: c,
            failed_source: "Google",
        },
        (None, None) => DualProbeHealth::TotalFailure,
    }
}

fn dual_health_to_runtime(health: DualProbeHealth) -> (RuntimeDualHealth, Option<f64>) {
    match health {
        DualProbeHealth::FullHealthy(avg_ms) => {
            (RuntimeDualHealth::FullHealthy, Some(avg_ms as f64))
        }
        DualProbeHealth::Degraded {
            passed_delay_ms, ..
        } => (RuntimeDualHealth::Degraded, Some(passed_delay_ms as f64)),
        DualProbeHealth::TotalFailure => (RuntimeDualHealth::Failed, None),
    }
}

fn collect_enabled_group_member_ids(group: &MultiGroup, nodes: &[ProxyNode]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    if !group.member_node_ids.is_empty() {
        for mid in &group.member_node_ids {
            if let Some(n) = nodes.iter().find(|n| &n.id == mid && n.enabled) {
                if seen.insert(n.id.as_str()) {
                    out.push(n.id.clone());
                }
            }
        }
    } else if matches!(group.mode, MultiGroupMode::ConditionalPool)
        || group.dynamic_filter.is_some()
    {
        for n in nodes.iter().filter(|n| n.enabled) {
            if seen.insert(n.id.as_str()) {
                out.push(n.id.clone());
            }
        }
    }
    out
}

fn collect_enabled_group_member_ids_from_summaries(
    group: &MultiGroup,
    nodes: &[NodeSummary],
) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    if !group.member_node_ids.is_empty() {
        for mid in &group.member_node_ids {
            if let Some(n) = nodes.iter().find(|n| &n.id == mid && n.enabled) {
                if seen.insert(n.id.as_str()) {
                    out.push(n.id.clone());
                }
            }
        }
    } else if matches!(group.mode, MultiGroupMode::ConditionalPool)
        || group.dynamic_filter.is_some()
    {
        for n in nodes.iter().filter(|n| n.enabled) {
            if seen.insert(n.id.as_str()) {
                out.push(n.id.clone());
            }
        }
    }
    out
}

fn resolve_node_compiled_proxy(st: &AppState, nodes: &[NodeSummary], node_id: &str) -> String {
    let fallback = nodes
        .iter()
        .find(|n| n.id == node_id)
        .map(|n| n.name.as_str())
        .unwrap_or(node_id);
    st.resolve_compiled_proxy_name(node_id, fallback)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatchdogTickDecision {
    HoldHealthy,
    HoldTransient { count: u32, threshold: u32 },
    HoldCooldown,
    Trigger(WatchdogFailoverTrigger),
}

/// Pure watchdog state-transition evaluator for one active-node dual-probe tick:
/// - `FullHealthy`: clears both failure/degraded counters and holds sticky.
/// - `TotalFailure`: increments `consecutive_failures`, clears `consecutive_degraded`; triggers
///   only when `count >= required_failures` AND `cooldown_elapsed`.
/// - `Degraded`: increments `consecutive_degraded`, clears `consecutive_failures`; triggers
///   only when `count >= WATCHDOG_DEGRADED_THRESHOLD_ROUNDS` AND `cooldown_elapsed`.
fn evaluate_watchdog_active_health_tick(
    health: DualProbeHealth,
    consecutive_failures: &mut u32,
    consecutive_degraded: &mut u32,
    required_failures: u32,
    cooldown_elapsed: bool,
) -> WatchdogTickDecision {
    let min_failures = required_failures.max(2);
    match health {
        DualProbeHealth::FullHealthy(_) => {
            *consecutive_failures = 0;
            *consecutive_degraded = 0;
            WatchdogTickDecision::HoldHealthy
        }
        DualProbeHealth::TotalFailure => {
            *consecutive_degraded = 0;
            *consecutive_failures = consecutive_failures.saturating_add(1);
            let fail_count = *consecutive_failures;
            if fail_count < min_failures {
                WatchdogTickDecision::HoldTransient {
                    count: fail_count,
                    threshold: min_failures,
                }
            } else if !cooldown_elapsed {
                WatchdogTickDecision::HoldCooldown
            } else {
                WatchdogTickDecision::Trigger(WatchdogFailoverTrigger::TotalOutage { fail_count })
            }
        }
        DualProbeHealth::Degraded { failed_source, .. } => {
            *consecutive_failures = 0;
            *consecutive_degraded = consecutive_degraded.saturating_add(1);
            let degraded_rounds = *consecutive_degraded;
            if degraded_rounds < WATCHDOG_DEGRADED_THRESHOLD_ROUNDS {
                WatchdogTickDecision::HoldTransient {
                    count: degraded_rounds,
                    threshold: WATCHDOG_DEGRADED_THRESHOLD_ROUNDS,
                }
            } else if !cooldown_elapsed {
                WatchdogTickDecision::HoldCooldown
            } else {
                WatchdogTickDecision::Trigger(WatchdogFailoverTrigger::SustainedDegraded {
                    degraded_rounds,
                    failed_source,
                })
            }
        }
    }
}

fn format_dual_probe_summary(health: DualProbeHealth) -> String {
    match health {
        DualProbeHealth::FullHealthy(ms) => format!("双源全绿（均 {ms} ms）"),
        DualProbeHealth::Degraded {
            passed_delay_ms,
            failed_source,
        } => format!("单源超时（{failed_source} 失败，另一侧通过 {passed_delay_ms} ms）"),
        DualProbeHealth::TotalFailure => "双源全挂（Google 与 Cloudflare 均失败）".to_string(),
    }
}

fn format_trigger_reason(trigger: WatchdogFailoverTrigger) -> String {
    match trigger {
        WatchdogFailoverTrigger::TotalOutage { fail_count } => {
            format!("当前节点连续 {fail_count} 次双源健康探活全挂")
        }
        WatchdogFailoverTrigger::SustainedDegraded {
            degraded_rounds,
            failed_source,
        } => {
            format!("当前节点连续 {degraded_rounds} 轮对 {failed_source} 单源超时（持续半残）")
        }
    }
}

/// Resolve `(close_old_override, keep_existing_connections)` for multi-group watchdog failover:
/// - `SustainedDegraded` (partial outage) always preserves live streams (`Some(false)`, `true`).
/// - `TotalOutage` strictly preserves the group's `SwitchMode::{ForceCloseOld, GracefulNewOnly}`
///   policy without mutating or simplifying user-selected switch semantics.
fn resolve_watchdog_switch_close_policy(
    trigger: WatchdogFailoverTrigger,
    switch_mode: &SwitchMode,
) -> (Option<bool>, bool) {
    let close_old_override = match trigger {
        WatchdogFailoverTrigger::SustainedDegraded { .. } => Some(false),
        WatchdogFailoverTrigger::TotalOutage { .. } => None,
    };
    let keep_existing_connections = match close_old_override {
        Some(close_old) => !close_old,
        None => matches!(switch_mode, SwitchMode::GracefulNewOnly),
    };
    (close_old_override, keep_existing_connections)
}

/// Build per-candidate decision traces across every enabled member in `group`, recording why each
/// candidate was selected, passed/degraded/failed live probing, or skipped due to cooldown,
/// recent switch-out anti-ping-pong protection, hard gates, or lower rank.
#[allow(clippy::too_many_arguments)]
fn build_watchdog_candidate_traces(
    group: &MultiGroup,
    nodes: &[ProxyNode],
    snaps: &HashMap<String, ProbeSnapshot>,
    health_pool: &NodeHealthPool,
    now: Instant,
    active_node_id: &str,
    recently_switched_out: &HashSet<String>,
    probed_results: &[((String, String), DualProbeHealth)],
    selected_node_id: Option<&str>,
) -> Vec<WatchdogCandidateTrace> {
    let member_ids = collect_enabled_group_member_ids(group, nodes);
    let eval_report = evaluate_group_candidates_with_runtime(
        group,
        nodes,
        snaps,
        Some(health_pool),
        now,
    )
    .ok();

    let mut score_map: HashMap<&str, (Option<f64>, bool, Vec<String>)> = HashMap::new();
    if let Some(ref rep) = eval_report {
        for c in rep.gate_passed.iter().chain(rep.gate_rejected.iter()) {
            score_map.insert(
                c.node_id.as_str(),
                (
                    c.score.is_finite().then_some(c.score),
                    c.passed_hard_gates,
                    c.failed_hard_gates.clone(),
                ),
            );
        }
    }

    let probed_map: HashMap<&str, DualProbeHealth> = probed_results
        .iter()
        .map(|((id, _), h)| (id.as_str(), *h))
        .collect();

    let mut traces = Vec::with_capacity(member_ids.len());
    for mid in member_ids {
        let node_name = nodes
            .iter()
            .find(|n| n.id == mid)
            .map(|n| n.name.clone())
            .unwrap_or_else(|| mid.clone());
        let (score, passed_gates, failed_gates) = score_map
            .get(mid.as_str())
            .cloned()
            .unwrap_or((None, true, Vec::new()));

        if mid == active_node_id {
            traces.push(WatchdogCandidateTrace {
                node_id: mid,
                node_name,
                status: "active_current".to_string(),
                score,
                latency_ms: health_pool.live_latency_ms(active_node_id),
                reason: "触发切换的原当前节点".to_string(),
            });
            continue;
        }

        if let Some(&cand_health) = probed_map.get(mid.as_str()) {
            let is_selected = selected_node_id == Some(mid.as_str());
            let (status, latency_ms, reason) = match cand_health {
                DualProbeHealth::FullHealthy(ms) => (
                    if is_selected { "selected" } else { "probed_passed" },
                    Some(ms as f64),
                    if is_selected {
                        format!("双源实测通过（{ms} ms），已选为切换目标")
                    } else {
                        format!("双源实测通过（{ms} ms）")
                    },
                ),
                DualProbeHealth::Degraded {
                    passed_delay_ms,
                    failed_source,
                } => (
                    if is_selected {
                        "selected_degraded_fallback"
                    } else {
                        "probed_degraded"
                    },
                    Some(passed_delay_ms as f64),
                    if is_selected {
                        format!(
                            "无双源全绿备用，仅 {failed_source} 单侧超时（{passed_delay_ms} ms），作为全挂兜底切换目标"
                        )
                    } else {
                        format!("单源半残（{failed_source} 超时，另一侧 {passed_delay_ms} ms），未达到双源全绿标准")
                    },
                ),
                DualProbeHealth::TotalFailure => (
                    "probed_failed",
                    None,
                    "实测双源探测均失败，已记入退避冷却".to_string(),
                ),
            };
            traces.push(WatchdogCandidateTrace {
                node_id: mid,
                node_name,
                status: status.to_string(),
                score,
                latency_ms,
                reason,
            });
            continue;
        }

        let live_latency = health_pool.live_latency_ms(&mid);

        if recently_switched_out.contains(&mid) {
            traces.push(WatchdogCandidateTrace {
                node_id: mid,
                node_name,
                status: "skipped_recently_switched_out".to_string(),
                score,
                latency_ms: live_latency,
                reason: "刚切出的旧节点处于冷却防乒乓保护窗内，本次跳过切回".to_string(),
            });
            continue;
        }

        if let Some(entry) = health_pool.get(&mid) {
            if entry.is_in_cooldown(now) {
                traces.push(WatchdogCandidateTrace {
                    node_id: mid,
                    node_name,
                    status: "skipped_cooldown".to_string(),
                    score,
                    latency_ms: None,
                    reason: entry.reason_zh(now),
                });
                continue;
            }
        }

        if !passed_gates {
            let gate_desc = if failed_gates.is_empty() {
                "未通过硬门槛约束".to_string()
            } else {
                format!("未通过硬门槛：{}", failed_gates.join("；"))
            };
            traces.push(WatchdogCandidateTrace {
                node_id: mid,
                node_name,
                status: "skipped_hard_gate".to_string(),
                score,
                latency_ms: live_latency,
                reason: gate_desc,
            });
            continue;
        }

        traces.push(WatchdogCandidateTrace {
            node_id: mid,
            node_name,
            status: "skipped_unprobed".to_string(),
            score,
            latency_ms: live_latency,
            reason: if selected_node_id.is_some() {
                "顺位靠后，更高顺位备用已实测通过".to_string()
            } else {
                "顺位超出本轮探活上限（前 4 名）".to_string()
            },
        });
    }

    traces
}

fn build_watchdog_cooldown_entries(
    health_pool: &NodeHealthPool,
    nodes: &[ProxyNode],
    now: Instant,
) -> Vec<WatchdogCooldownNodeEntry> {
    let name_map: HashMap<&str, &str> = nodes
        .iter()
        .map(|n| (n.id.as_str(), n.name.as_str()))
        .collect();
    let hints = health_pool.build_hints_snapshot(now);
    let mut entries: Vec<WatchdogCooldownNodeEntry> = hints
        .into_iter()
        .filter(|(_, h)| h.status != "healthy" || h.cooldown_remaining_sec > 0)
        .map(|(node_id, h)| {
            let node_name = name_map
                .get(node_id.as_str())
                .copied()
                .unwrap_or(node_id.as_str())
                .to_string();
            WatchdogCooldownNodeEntry {
                node_id,
                node_name,
                stage: h.stage,
                cooldown_remaining_sec: h.cooldown_remaining_sec,
                reason: h.reason,
            }
        })
        .collect();
    entries.sort_by(|a, b| {
        b.cooldown_remaining_sec
            .cmp(&a.cooldown_remaining_sec)
            .then_with(|| a.node_id.cmp(&b.node_id))
    });
    entries
}

fn build_watchdog_backoff_entries(
    failed_group_backoff_until: &HashMap<String, Instant>,
    groups: &[MultiGroup],
    consecutive_fail_counts: &HashMap<String, u32>,
    now: Instant,
    now_utc: chrono::DateTime<chrono::Utc>,
) -> Vec<WatchdogGroupBackoffEntry> {
    let mut out = Vec::new();
    for (gid, until) in failed_group_backoff_until {
        if let Some(rem) = until.checked_duration_since(now) {
            if rem.is_zero() {
                continue;
            }
            let gname = groups
                .iter()
                .find(|g| &g.id == gid)
                .map(|g| g.name.clone())
                .unwrap_or_else(|| gid.clone());
            let backoff_at = now_utc
                + chrono::Duration::seconds(rem.as_secs().min(i64::MAX as u64) as i64);
            out.push(WatchdogGroupBackoffEntry {
                group_id: gid.clone(),
                group_name: gname,
                consecutive_failures: consecutive_fail_counts.get(gid).copied().unwrap_or(0),
                backoff_until: Some(backoff_at.to_rfc3339()),
                reason: "全组顺位候选实测未通过，进入 180 秒退避保护".to_string(),
            });
        }
    }
    out.sort_by(|a, b| a.group_id.cmp(&b.group_id));
    out
}

fn format_watchdog_decision_log_line(event: &WatchdogDecisionEvent) -> String {
    let target_desc = match (&event.from_node_name, &event.to_node_name) {
        (Some(from), Some(to)) => format!("{from} -> {to}"),
        (Some(from), None) => format!("保持 {from}（进入退避）"),
        _ => event.action.clone(),
    };
    let cand_briefs: Vec<String> = event
        .candidates
        .iter()
        .filter(|c| c.status != "active_current")
        .take(8)
        .map(|c| {
            let score_txt = c
                .score
                .map(|s| format!(" score={s:.1}"))
                .unwrap_or_default();
            let lat_txt = c
                .latency_ms
                .map(|ms| format!(" {ms:.0}ms"))
                .unwrap_or_default();
            format!("{}[{}]{score_txt}{lat_txt}:{}", c.node_name, c.status, c.reason)
        })
        .collect();
    let cand_section = if cand_briefs.is_empty() {
        "无备选".to_string()
    } else {
        cand_briefs.join(" | ")
    };
    let next_check = event.next_recheck_at.as_deref().unwrap_or("下轮周期");
    let conn_policy = if event.keep_existing_connections {
        "保留存量连接"
    } else {
        "断开旧节点存量连接"
    };
    format!(
        "分组「{}」调度决策[{}]：{} ｜ 触发：{} ｜ 当前探测：{} ｜ 存量连接：{} ｜ 下次复检：{} ｜ 备选轨迹：[{}]",
        event.group_name,
        event.action,
        target_desc,
        event.trigger_reason,
        event.current_probe_summary,
        conn_policy,
        next_check,
        cand_section,
    )
}

fn record_watchdog_decision_event_and_persist(
    data_dir: &std::path::Path,
    state_snapshot: &mut WatchdogStateSnapshot,
    event: WatchdogDecisionEvent,
    active_backoffs: Vec<WatchdogGroupBackoffEntry>,
    cooldown_nodes: Vec<WatchdogCooldownNodeEntry>,
) -> Result<(), String> {
    state_snapshot.updated_at = chrono::Utc::now().to_rfc3339();
    state_snapshot.active_backoffs = active_backoffs;
    state_snapshot.cooldown_nodes = cooldown_nodes;
    state_snapshot.push_event(event);
    write_watchdog_state_snapshot(data_dir, state_snapshot).map_err(|e| e.to_string())
}

/// Decide whether a probed backup candidate should be accepted for the given trigger.
/// - For `SustainedDegraded`, ONLY a `FullHealthy` (2/2) candidate may replace a degraded node
///   so two half-broken nodes never ping-pong into each other.
/// - For `TotalOutage`, a `FullHealthy` candidate always wins immediately; a `Degraded` (1/2)
///   candidate is only kept as last-resort fallback if no `FullHealthy` backup exists.
fn choose_verified_candidate_from_probes<T: Clone>(
    trigger: WatchdogFailoverTrigger,
    probed: &[(T, DualProbeHealth)],
) -> Option<(T, u64, bool)> {
    let mut degraded_fallback: Option<(T, u64)> = None;
    for (cand, health) in probed {
        match *health {
            DualProbeHealth::FullHealthy(avg_ms) => {
                return Some((cand.clone(), avg_ms, true));
            }
            DualProbeHealth::Degraded { passed_delay_ms, .. } => {
                if matches!(trigger, WatchdogFailoverTrigger::TotalOutage { .. })
                    && degraded_fallback.is_none()
                {
                    degraded_fallback = Some((cand.clone(), passed_delay_ms));
                }
            }
            DualProbeHealth::TotalFailure => {}
        }
    }
    degraded_fallback.map(|(cand, ms)| (cand, ms, false))
}

async fn probe_compiled_proxy_delay_url(
    http_client: &reqwest::Client,
    ctrl_host: &str,
    port: u16,
    secret: &str,
    compiled_proxy: &str,
    probe_url: &str,
    timeout_ms: u64,
) -> Option<u64> {
    let encoded_proxy = commands::percent_encode_path_segment(compiled_proxy);
    let encoded_url = commands::percent_encode_path_segment(probe_url);
    let delay_url = format!(
        "http://{ctrl_host}:{port}/proxies/{encoded_proxy}/delay?url={encoded_url}&timeout={timeout_ms}"
    );
    let mut req = http_client.get(&delay_url);
    if !secret.trim().is_empty() {
        req = req.bearer_auth(secret);
    }
    match req.send().await {
        Ok(resp) if resp.status().is_success() => resp
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|v| v.get("delay").and_then(|d| d.as_u64()))
            .filter(|&delay| delay > 0),
        _ => None,
    }
}

async fn probe_compiled_proxy_dual_health(
    http_client: &reqwest::Client,
    ctrl_host: &str,
    port: u16,
    secret: &str,
    compiled_proxy: &str,
    timeout_ms: u64,
) -> DualProbeHealth {
    let (primary_ms, secondary_ms) = tokio::join!(
        probe_compiled_proxy_delay_url(
            http_client,
            ctrl_host,
            port,
            secret,
            compiled_proxy,
            WATCHDOG_PROBE_PRIMARY_URL,
            timeout_ms,
        ),
        probe_compiled_proxy_delay_url(
            http_client,
            ctrl_host,
            port,
            secret,
            compiled_proxy,
            WATCHDOG_PROBE_SECONDARY_URL,
            timeout_ms,
        ),
    );
    classify_dual_probe_health(primary_ms, secondary_ms)
}

/// Retry-before-penalize dual 204 health check:
/// - If the initial probe returns `FullHealthy`, return immediately.
/// - If the initial probe returns `Degraded` or `TotalFailure`, wait 1500ms and re-verify once.
///   A 2/2 `FullHealthy` re-check is treated as transient jitter (refreshes latency, zero penalty).
async fn probe_compiled_proxy_dual_health_with_retry(
    http_client: &reqwest::Client,
    ctrl_host: &str,
    port: u16,
    secret: &str,
    compiled_proxy: &str,
    timeout_ms: u64,
    shutting_down: &std::sync::atomic::AtomicBool,
) -> DualProbeHealth {
    let first = probe_compiled_proxy_dual_health(
        http_client,
        ctrl_host,
        port,
        secret,
        compiled_proxy,
        timeout_ms,
    )
    .await;
    if matches!(first, DualProbeHealth::FullHealthy(_)) || shutting_down.load(Ordering::SeqCst) {
        return first;
    }
    tokio::time::sleep(Duration::from_millis(WATCHDOG_RETRY_DELAY_MS)).await;
    if shutting_down.load(Ordering::SeqCst) {
        return first;
    }
    probe_compiled_proxy_dual_health(
        http_client,
        ctrl_host,
        port,
        secret,
        compiled_proxy,
        timeout_ms,
    )
    .await
}

/// Probe a small batch of member nodes with bounded concurrency (<= 2) and retry-before-penalize,
/// aborting immediately if shutdown, isolated speed probes, or high-throughput traffic starts.
#[allow(clippy::too_many_arguments)]
async fn probe_node_batch_bounded(
    st: &AppState,
    http_client: &reqwest::Client,
    ctrl_host: &str,
    port: u16,
    secret: &str,
    targets: &[(String, String)],
    timeout_ms: u64,
) -> Vec<(String, DualProbeHealth)> {
    let mut results = Vec::with_capacity(targets.len());
    for chunk in targets.chunks(2) {
        if st.shutting_down.load(Ordering::SeqCst)
            || st.probe_running.load(Ordering::SeqCst)
            || is_watchdog_high_throughput(st)
        {
            break;
        }
        match chunk {
            [(id0, proxy0)] => {
                let h0 = probe_compiled_proxy_dual_health_with_retry(
                    http_client,
                    ctrl_host,
                    port,
                    secret,
                    proxy0,
                    timeout_ms,
                    &st.shutting_down,
                )
                .await;
                if !st.shutting_down.load(Ordering::SeqCst)
                    && !st.probe_running.load(Ordering::SeqCst)
                    && !is_watchdog_high_throughput(st)
                {
                    results.push((id0.clone(), h0));
                }
            }
            [(id0, proxy0), (id1, proxy1)] => {
                let (h0, h1) = tokio::join!(
                    probe_compiled_proxy_dual_health_with_retry(
                        http_client,
                        ctrl_host,
                        port,
                        secret,
                        proxy0,
                        timeout_ms,
                        &st.shutting_down,
                    ),
                    probe_compiled_proxy_dual_health_with_retry(
                        http_client,
                        ctrl_host,
                        port,
                        secret,
                        proxy1,
                        timeout_ms,
                        &st.shutting_down,
                    ),
                );
                if !st.shutting_down.load(Ordering::SeqCst)
                    && !st.probe_running.load(Ordering::SeqCst)
                    && !is_watchdog_high_throughput(st)
                {
                    results.push((id0.clone(), h0));
                    results.push((id1.clone(), h1));
                }
            }
            _ => {}
        }
    }
    results
}

fn is_watchdog_high_throughput(st: &AppState) -> bool {
    let cached = st
        .cached_metrics
        .read()
        .map(|m| *m)
        .unwrap_or_default();
    let threshold = commands::WATCHDOG_HIGH_THROUGHPUT_THRESHOLD_BPS;
    if cached.up_bps.max(cached.down_bps) >= threshold {
        return true;
    }
    let now_ms = chrono::Utc::now().timestamp_millis();
    let cutoff_ms = now_ms.saturating_sub(commands::WATCHDOG_HIGH_THROUGHPUT_WINDOW_MS.max(0));
    let (peak_up, peak_down) = st.telemetry.traffic_peak_since(cutoff_ms);
    peak_up.max(peak_down) >= threshold
}

pub(crate) fn spawn_group_strategy_watchdog(app: &tauri::AppHandle) {
    let app_h = app.clone();
    tauri::async_runtime::spawn(async move {
        let Ok(http_client) = reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(6))
            .build()
        else {
            tracing::warn!("failed to initialize multi-group strategy watchdog HTTP client");
            return;
        };

        const ALL_CANDIDATES_FAILED_BACKOFF: Duration = Duration::from_secs(180);
        const MAX_FAILOVER_CANDIDATES: usize = 4;

        let mut consecutive_fail_counts: HashMap<String, u32> = HashMap::new();
        let mut consecutive_degraded_counts: HashMap<String, u32> = HashMap::new();
        let mut last_auto_switch_at: HashMap<String, Instant> = HashMap::new();
        let mut failed_group_backoff_until: HashMap<String, Instant> = HashMap::new();
        let mut last_checked_node: HashMap<String, String> = HashMap::new();
        let mut recently_switched_out_until: HashMap<(String, String), Instant> = HashMap::new();
        let mut watchdog_snapshot: Option<WatchdogStateSnapshot> = None;

        loop {
            tokio::time::sleep(Duration::from_secs(WATCHDOG_INTERVAL_SECS)).await;

            let Some(st) = app_h.try_state::<AppState>() else {
                break;
            };
            if st.shutting_down.load(Ordering::SeqCst) {
                break;
            }
            // Skip health checks while isolated speed probes are saturating local bandwidth.
            if st.probe_running.load(Ordering::SeqCst) {
                continue;
            }

            let cfg = st.snapshot_config();
            if cfg.proxy_mode == ProxyMode::Direct {
                consecutive_fail_counts.clear();
                consecutive_degraded_counts.clear();
                continue;
            }

            if !st.adapter.has_live_controller().await {
                consecutive_fail_counts.clear();
                consecutive_degraded_counts.clear();
                continue;
            }
            let rt = st.adapter.runtime_status().await;
            if !rt.running {
                consecutive_fail_counts.clear();
                consecutive_degraded_counts.clear();
                continue;
            }

            // Guard #1: suppress probing & reset failure counters whenever sustained high-throughput
            // traffic (>= 256 KiB/s within the 10s sliding window) is active, protecting large
            // uploads/downloads from spurious mid-transfer failover even while minimized.
            if is_watchdog_high_throughput(&st) {
                consecutive_fail_counts.clear();
                consecutive_degraded_counts.clear();
                tracing::debug!(
                    "group strategy watchdog skipped round: active high-throughput transfer detected"
                );
                continue;
            }

            let secret = st.adapter.controller_secret().await;
            let ctrl_host = match rt.controller_host.trim() {
                "" | "0.0.0.0" | "::" => "127.0.0.1".to_string(),
                h if h.contains(':') && !h.starts_with('[') => format!("[{h}]"),
                h => h.to_string(),
            };

            // Single-node mode: run one read-only dual 204 health check (no failover) so the
            // home page and floating capsule always receive fresh real-time latency.
            if cfg.route_mode == RouteTargetMode::Single {
                consecutive_fail_counts.clear();
                consecutive_degraded_counts.clear();
                let single_target: Option<(String, String)> = st.storage.lock().ok().and_then(|db| {
                    let nodes = db.list_node_summaries().ok()?;
                    let active = cfg
                        .active_single_node_id
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .and_then(|id| nodes.iter().find(|n| n.id == id && n.enabled))
                        .or_else(|| nodes.iter().find(|n| n.enabled))?;
                    let compiled = st.resolve_compiled_proxy_name(&active.id, &active.name);
                    Some((active.id.clone(), compiled))
                });
                if let Some((node_id, compiled_proxy)) = single_target {
                    let health = probe_compiled_proxy_dual_health_with_retry(
                        &http_client,
                        &ctrl_host,
                        rt.controller_port,
                        &secret,
                        &compiled_proxy,
                        WATCHDOG_ACTIVE_PROBE_TIMEOUT_MS,
                        &st.shutting_down,
                    )
                    .await;
                    if !st.shutting_down.load(Ordering::SeqCst)
                        && !st.probe_running.load(Ordering::SeqCst)
                        && !is_watchdog_high_throughput(&st)
                    {
                        let (rt_h, rt_ms) = dual_health_to_runtime(health);
                        st.record_node_health_probe(&node_id, rt_h, rt_ms);
                        commands::emit_runtime_snapshot(&app_h, &st);
                    }
                }
                continue;
            }

            // Snapshot groups & lightweight node summaries under a brief sync lock; NEVER hold across `.await`.
            let snapshot_res = st.storage.lock().ok().map(|db| {
                (
                    db.list_multi_groups().unwrap_or_default(),
                    db.list_node_summaries().unwrap_or_default(),
                )
            });
            let Some((groups, nodes)) = snapshot_res else {
                continue;
            };
            if groups.is_empty() || nodes.is_empty() {
                continue;
            }

            let primary_gid = cfg
                .active_group_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .and_then(|aid| groups.iter().find(|g| g.id == aid).map(|g| g.id.clone()))
                .or_else(|| groups.first().map(|g| g.id.clone()));

            let mut failover_groups: Vec<MultiGroup> = Vec::new();
            let mut readonly_groups: Vec<MultiGroup> = Vec::new();
            for g in &groups {
                let is_primary = primary_gid.as_deref() == Some(g.id.as_str());
                if !(is_primary || g.independent_routing) {
                    continue;
                }
                let supports_failover = matches!(
                    g.mode,
                    MultiGroupMode::StickyBest | MultiGroupMode::ConditionalPool
                ) && commands::count_enabled_group_members_from_summaries(g, &nodes) >= 2;
                if supports_failover {
                    if !failover_groups.iter().any(|existing| existing.id == g.id) {
                        failover_groups.push(g.clone());
                    }
                } else if !readonly_groups.iter().any(|existing| existing.id == g.id) {
                    readonly_groups.push(g.clone());
                }
            }

            consecutive_fail_counts
                .retain(|gid, _| failover_groups.iter().any(|g| &g.id == gid));
            consecutive_degraded_counts
                .retain(|gid, _| failover_groups.iter().any(|g| &g.id == gid));
            last_auto_switch_at.retain(|gid, _| failover_groups.iter().any(|g| &g.id == gid));
            failed_group_backoff_until.retain(|gid, until| {
                Instant::now() < *until && failover_groups.iter().any(|g| &g.id == gid)
            });
            last_checked_node.retain(|gid, _| failover_groups.iter().any(|g| &g.id == gid));
            let retain_now = Instant::now();
            recently_switched_out_until.retain(|(gid, _), until| {
                retain_now < *until && failover_groups.iter().any(|g| &g.id == gid)
            });

            if failover_groups.is_empty() && readonly_groups.is_empty() {
                continue;
            }

            let mut should_emit_runtime = false;

            // Read-only latency refresh for single-member groups and non-failover active groups.
            for group in &readonly_groups {
                if st.shutting_down.load(Ordering::SeqCst)
                    || st.probe_running.load(Ordering::SeqCst)
                    || is_watchdog_high_throughput(&st)
                {
                    break;
                }
                let Some(active_node) =
                    commands::resolve_valid_group_active_node_summary(group, &nodes)
                else {
                    continue;
                };
                let compiled_proxy =
                    st.resolve_compiled_proxy_name(&active_node.id, &active_node.name);
                let health = probe_compiled_proxy_dual_health_with_retry(
                    &http_client,
                    &ctrl_host,
                    rt.controller_port,
                    &secret,
                    &compiled_proxy,
                    WATCHDOG_ACTIVE_PROBE_TIMEOUT_MS,
                    &st.shutting_down,
                )
                .await;
                if !st.shutting_down.load(Ordering::SeqCst)
                    && !st.probe_running.load(Ordering::SeqCst)
                    && !is_watchdog_high_throughput(&st)
                {
                    let (rt_h, rt_ms) = dual_health_to_runtime(health);
                    st.record_node_health_probe(&active_node.id, rt_h, rt_ms);
                    commands::emit_runtime_snapshot(&app_h, &st);
                }
            }

            for group in failover_groups {
                if st.shutting_down.load(Ordering::SeqCst)
                    || st.probe_running.load(Ordering::SeqCst)
                {
                    break;
                }
                if is_watchdog_high_throughput(&st) {
                    consecutive_fail_counts.clear();
                    consecutive_degraded_counts.clear();
                    break;
                }
                let Some(active_node) =
                    commands::resolve_valid_group_active_node_summary(&group, &nodes)
                else {
                    continue;
                };
                if last_checked_node.get(&group.id).map(String::as_str)
                    != Some(active_node.id.as_str())
                {
                    consecutive_fail_counts.remove(&group.id);
                    consecutive_degraded_counts.remove(&group.id);
                    failed_group_backoff_until.remove(&group.id);
                    st.set_group_backoff_until(&group.id, None);
                    last_checked_node.insert(group.id.clone(), active_node.id.clone());
                }

                let mut effective_active_id = active_node.id.clone();
                let mut probed_this_round: HashSet<String> = HashSet::new();
                let in_group_backoff = failed_group_backoff_until
                    .get(&group.id)
                    .is_some_and(|until| Instant::now() < *until);

                // Step 1: Active node dual 204 health check with retry-before-penalize (1500ms)
                // and runtime-health-aware failover when confirmed outage / sustained degradation.
                if !in_group_backoff {
                    let compiled_proxy =
                        st.resolve_compiled_proxy_name(&active_node.id, &active_node.name);
                    let health = probe_compiled_proxy_dual_health_with_retry(
                        &http_client,
                        &ctrl_host,
                        rt.controller_port,
                        &secret,
                        &compiled_proxy,
                        WATCHDOG_ACTIVE_PROBE_TIMEOUT_MS,
                        &st.shutting_down,
                    )
                    .await;
                    probed_this_round.insert(active_node.id.clone());

                    if st.shutting_down.load(Ordering::SeqCst)
                        || st.probe_running.load(Ordering::SeqCst)
                    {
                        break;
                    }
                    // Guard #1 (re-check): abort penalty & failover if high-throughput transfer
                    // started during the probe.
                    if is_watchdog_high_throughput(&st) {
                        consecutive_fail_counts.clear();
                        consecutive_degraded_counts.clear();
                        tracing::debug!(
                            group = %group.name,
                            "group strategy watchdog aborted penalty/failover: high-throughput transfer active"
                        );
                        break;
                    }

                    let (rt_health, rt_ms) = dual_health_to_runtime(health);
                    st.record_node_health_probe(&active_node.id, rt_health, rt_ms);
                    should_emit_runtime = true;

                    let cooldown = Duration::from_secs(group.cooldown_sec.max(45));
                    let cooldown_elapsed = last_auto_switch_at
                        .get(&group.id)
                        .is_none_or(|last| last.elapsed() >= cooldown);
                    let required_failures = commands::group_watchdog_failure_threshold(&group);

                    let mut cur_fails = consecutive_fail_counts.get(&group.id).copied().unwrap_or(0);
                    let mut cur_degraded = consecutive_degraded_counts
                        .get(&group.id)
                        .copied()
                        .unwrap_or(0);
                    let tick_decision = evaluate_watchdog_active_health_tick(
                        health,
                        &mut cur_fails,
                        &mut cur_degraded,
                        required_failures,
                        cooldown_elapsed,
                    );
                    if cur_fails == 0 {
                        consecutive_fail_counts.remove(&group.id);
                    } else {
                        consecutive_fail_counts.insert(group.id.clone(), cur_fails);
                    }
                    if cur_degraded == 0 {
                        consecutive_degraded_counts.remove(&group.id);
                    } else {
                        consecutive_degraded_counts.insert(group.id.clone(), cur_degraded);
                    }

                    let failover_trigger = match tick_decision {
                        WatchdogTickDecision::HoldHealthy => None,
                        WatchdogTickDecision::HoldTransient { count, threshold } => {
                            tracing::debug!(
                                group = %group.name,
                                node = %active_node.name,
                                count,
                                threshold,
                                "group strategy watchdog observed transient anomaly (holding)"
                            );
                            None
                        }
                        WatchdogTickDecision::HoldCooldown => {
                            tracing::debug!(
                                group = %group.name,
                                node = %active_node.name,
                                "group strategy watchdog holding failover during cooldown"
                            );
                            None
                        }
                        WatchdogTickDecision::Trigger(trigger) => Some(trigger),
                    };

                    if let Some(trigger) = failover_trigger {
                        // Guard #2: combine `NodeHealthPool` exponential backoff with per-group
                        // recently-switched-out anti-ping-pong cooldowns inside `cooldown_sec`.
                        let rank_now = Instant::now();
                        let switch_out_cooldowns: HashSet<String> = recently_switched_out_until
                            .iter()
                            .filter(|((gid, _), until)| gid == &group.id && rank_now < **until)
                            .map(|((_, nid), _)| nid.clone())
                            .collect();
                        let health_pool_snap = st.snapshot_node_health_pool();

                        // Re-read latest group, nodes, and probe snapshots under a brief sync lock
                        // before ranking up to 4 backup candidates fused with runtime health pool.
                        let candidate_plan = st.storage.lock().ok().and_then(|db| {
                            let latest_group = db.get_multi_group(&group.id).ok().flatten()?;
                            let latest_nodes = db.list_nodes().ok()?;
                            let latest_active = commands::resolve_valid_group_active_node(
                                &latest_group,
                                &latest_nodes,
                            )?;
                            if latest_active.id != active_node.id {
                                return None;
                            }
                            let node_ids: Vec<String> =
                                latest_nodes.iter().map(|n| n.id.clone()).collect();
                            let snaps = db
                                .get_probe_snapshots_batch(
                                    &node_ids,
                                    latest_group.primary_probe_id.as_deref(),
                                )
                                .unwrap_or_default();
                            let candidate_ids =
                                commands::pick_group_candidates_with_cooldown_and_runtime(
                                    &latest_group,
                                    &latest_nodes,
                                    &snaps,
                                    Some(&active_node.id),
                                    &switch_out_cooldowns,
                                    Some(&health_pool_snap),
                                    rank_now,
                                    MAX_FAILOVER_CANDIDATES,
                                );
                            if candidate_ids.is_empty() {
                                return None;
                            }
                            let candidates: Vec<(String, String, String)> = candidate_ids
                                .into_iter()
                                .map(|cid| {
                                    let cname = latest_nodes
                                        .iter()
                                        .find(|n| n.id == cid)
                                        .map(|n| n.name.clone())
                                        .unwrap_or_else(|| cid.clone());
                                    let compiled = st.resolve_compiled_proxy_name(&cid, &cname);
                                    (cid, cname, compiled)
                                })
                                .collect();
                            Some((latest_group, latest_nodes, snaps, candidates))
                        });

                        if let Some((latest_group, latest_nodes, latest_snaps, candidates)) =
                            candidate_plan
                        {
                            let gid = latest_group.id.clone();
                            let gname = latest_group.name.clone();
                            let current_probe_summary = format_dual_probe_summary(health);
                            let trigger_reason_text = format_trigger_reason(trigger);

                            // Guard #3: sequentially dual-probe top 4 candidates outside sync locks
                            // with retry-before-penalize (`timeout=3500ms`).
                            let probed_total = candidates.len();
                            let mut probed_results: Vec<((String, String), DualProbeHealth)> =
                                Vec::with_capacity(probed_total);
                            for (cand_id, cand_name, cand_compiled) in candidates {
                                if st.shutting_down.load(Ordering::SeqCst)
                                    || st.probe_running.load(Ordering::SeqCst)
                                    || is_watchdog_high_throughput(&st)
                                {
                                    break;
                                }
                                let cand_health = probe_compiled_proxy_dual_health_with_retry(
                                    &http_client,
                                    &ctrl_host,
                                    rt.controller_port,
                                    &secret,
                                    &cand_compiled,
                                    WATCHDOG_CANDIDATE_PROBE_TIMEOUT_MS,
                                    &st.shutting_down,
                                )
                                .await;
                                probed_this_round.insert(cand_id.clone());
                                if st.shutting_down.load(Ordering::SeqCst)
                                    || st.probe_running.load(Ordering::SeqCst)
                                    || is_watchdog_high_throughput(&st)
                                {
                                    break;
                                }
                                let (cand_rt_h, cand_rt_ms) = dual_health_to_runtime(cand_health);
                                st.record_node_health_probe(&cand_id, cand_rt_h, cand_rt_ms);
                                should_emit_runtime = true;

                                let is_full = matches!(cand_health, DualProbeHealth::FullHealthy(_));
                                probed_results.push(((cand_id, cand_name), cand_health));
                                if is_full {
                                    break;
                                }
                            }

                            if let Some(((next_id, next_name), verified_delay_ms, is_full_healthy)) =
                                choose_verified_candidate_from_probes(trigger, &probed_results)
                            {
                                // Re-check latest user config and high-throughput state right
                                // before failover so we never interrupt active transfers or mode changes.
                                let latest_cfg = st.snapshot_config();
                                let aborted_by_env = latest_cfg.route_mode != RouteTargetMode::Group
                                    || latest_cfg.proxy_mode == ProxyMode::Direct
                                    || st.probe_running.load(Ordering::SeqCst)
                                    || is_watchdog_high_throughput(&st);
                                if aborted_by_env {
                                    if is_watchdog_high_throughput(&st) {
                                        consecutive_fail_counts.clear();
                                        consecutive_degraded_counts.clear();
                                    }
                                } else {
                                    // Guard #4: briefly re-verify DB `active_node_id` right before
                                    // switching so we never overwrite a manual node selection.
                                    let still_same_active = st
                                        .storage
                                        .lock()
                                        .ok()
                                        .and_then(|db| db.get_multi_group(&gid).ok().flatten())
                                        .map(|db_group| {
                                            let unchanged_explicit =
                                                db_group.active_node_id.as_deref()
                                                    == Some(active_node.id.as_str());
                                            let unchanged_implicit = group.active_node_id.is_none()
                                                && db_group.active_node_id.is_none();
                                            unchanged_explicit || unchanged_implicit
                                        })
                                        .unwrap_or(false);
                                    if !still_same_active {
                                        consecutive_fail_counts.remove(&gid);
                                        consecutive_degraded_counts.remove(&gid);
                                        failed_group_backoff_until.remove(&gid);
                                        st.set_group_backoff_until(&gid, None);
                                        st.log_app_event(
                                            "info",
                                            "自动切优",
                                            &format!(
                                                "分组「{gname}」在备用候选探活期间已被手动切换节点，后台守护已放弃本次自动覆盖（原探测节点：{}）",
                                                active_node.name
                                            ),
                                        );
                                    } else {
                                        // Guard #5: smooth migration on partial degradation never
                                        // force-kills live streams; total outage respects group's switch_mode.
                                        let (close_old_override, keep_existing_connections) =
                                            resolve_watchdog_switch_close_policy(
                                                trigger,
                                                &latest_group.switch_mode,
                                            );
                                        let switch_res = commands::select_group_node_in_place_internal(
                                            &app_h,
                                            &st,
                                            gid.clone(),
                                            next_id.clone(),
                                            close_old_override,
                                            Some(active_node.name.clone()),
                                        )
                                        .await;

                                        match switch_res {
                                            Ok(_) => {
                                                let now_inst = Instant::now();
                                                let now_utc = chrono::Utc::now();
                                                consecutive_fail_counts.remove(&gid);
                                                consecutive_degraded_counts.remove(&gid);
                                                failed_group_backoff_until.remove(&gid);
                                                st.set_group_backoff_until(&gid, None);
                                                last_auto_switch_at.insert(gid.clone(), now_inst);
                                                // Anti-ping-pong protection: shield the switched-out
                                                // old node from immediate re-selection inside cooldown_sec.
                                                recently_switched_out_until.insert(
                                                    (gid.clone(), active_node.id.clone()),
                                                    now_inst + cooldown,
                                                );
                                                last_checked_node
                                                    .insert(gid.clone(), next_id.clone());
                                                effective_active_id = next_id.clone();
                                                should_emit_runtime = true;

                                                let health_tag = if is_full_healthy {
                                                    "双源全绿"
                                                } else {
                                                    "单源兜底"
                                                };
                                                let reason = match trigger {
                                                    WatchdogFailoverTrigger::TotalOutage {
                                                        fail_count,
                                                    } => format!(
                                                        "原节点连续 {fail_count} 次双源健康探活失败，已自动切换至{health_tag}备用节点（{verified_delay_ms} ms）"
                                                    ),
                                                    WatchdogFailoverTrigger::SustainedDegraded {
                                                        degraded_rounds,
                                                        failed_source,
                                                    } => format!(
                                                        "原节点连续 {degraded_rounds} 轮对 {failed_source} 单源超时（部分丢包），已平滑切换至{health_tag}节点（{verified_delay_ms} ms，不断开存量连接）"
                                                    ),
                                                };

                                                let updated_pool = st.snapshot_node_health_pool();
                                                let candidate_traces = build_watchdog_candidate_traces(
                                                    &latest_group,
                                                    &latest_nodes,
                                                    &latest_snaps,
                                                    &updated_pool,
                                                    now_inst,
                                                    &active_node.id,
                                                    &switch_out_cooldowns,
                                                    &probed_results,
                                                    Some(&next_id),
                                                );
                                                let next_recheck_at = (now_utc
                                                    + chrono::Duration::seconds(
                                                        cooldown.as_secs().min(i64::MAX as u64)
                                                            as i64,
                                                    ))
                                                .to_rfc3339();
                                                let decision_event = WatchdogDecisionEvent {
                                                    timestamp: now_utc.to_rfc3339(),
                                                    group_id: gid.clone(),
                                                    group_name: gname.clone(),
                                                    trigger_reason: trigger_reason_text.clone(),
                                                    action: "switch_node".to_string(),
                                                    from_node_id: Some(active_node.id.clone()),
                                                    from_node_name: Some(active_node.name.clone()),
                                                    to_node_id: Some(next_id.clone()),
                                                    to_node_name: Some(next_name.clone()),
                                                    current_probe_summary: current_probe_summary
                                                        .clone(),
                                                    candidates: candidate_traces,
                                                    next_recheck_at: Some(next_recheck_at),
                                                    keep_existing_connections,
                                                };
                                                let structured_log =
                                                    format_watchdog_decision_log_line(
                                                        &decision_event,
                                                    );
                                                st.log_app_event(
                                                    "warning",
                                                    "自动切优",
                                                    &structured_log,
                                                );
                                                let snap_mut = watchdog_snapshot.get_or_insert_with(
                                                    || {
                                                        read_watchdog_state_snapshot(
                                                            &st.paths.root_data_dir,
                                                        )
                                                        .unwrap_or_default()
                                                    },
                                                );
                                                let active_backoffs = build_watchdog_backoff_entries(
                                                    &failed_group_backoff_until,
                                                    &groups,
                                                    &consecutive_fail_counts,
                                                    now_inst,
                                                    now_utc,
                                                );
                                                let cooldown_entries =
                                                    build_watchdog_cooldown_entries(
                                                        &updated_pool,
                                                        &latest_nodes,
                                                        now_inst,
                                                    );
                                                let _ = record_watchdog_decision_event_and_persist(
                                                    &st.paths.root_data_dir,
                                                    snap_mut,
                                                    decision_event,
                                                    active_backoffs,
                                                    cooldown_entries,
                                                );
                                                let _ = app_h.emit(
                                                    commands::EVENT_STRATEGY_SWITCH,
                                                    serde_json::json!({
                                                        "group_name": gname,
                                                        "from_node": active_node.name,
                                                        "to_node": next_name,
                                                        "reason": reason,
                                                    }),
                                                );
                                            }
                                            Err(err) => {
                                                st.log_app_event(
                                                    "error",
                                                    "自动切优",
                                                    &format!(
                                                        "分组「{gname}」后台自动切优失败（{} -> {}）：{err}",
                                                        active_node.name, next_name
                                                    ),
                                                );
                                            }
                                        }
                                    }
                                }
                            } else if !probed_results.is_empty() {
                                consecutive_fail_counts.remove(&gid);
                                consecutive_degraded_counts.remove(&gid);
                                let now = Instant::now();
                                let now_utc = chrono::Utc::now();
                                let backoff_until = now + ALL_CANDIDATES_FAILED_BACKOFF;
                                last_auto_switch_at.insert(gid.clone(), now);
                                failed_group_backoff_until.insert(gid.clone(), backoff_until);
                                st.set_group_backoff_until(&gid, Some(backoff_until));
                                should_emit_runtime = true;
                                commands::refresh_tray(&app_h, &st);

                                let updated_pool = st.snapshot_node_health_pool();
                                let candidate_traces = build_watchdog_candidate_traces(
                                    &latest_group,
                                    &latest_nodes,
                                    &latest_snaps,
                                    &updated_pool,
                                    now,
                                    &active_node.id,
                                    &switch_out_cooldowns,
                                    &probed_results,
                                    None,
                                );
                                let next_recheck_at = (now_utc
                                    + chrono::Duration::seconds(
                                        ALL_CANDIDATES_FAILED_BACKOFF.as_secs() as i64,
                                    ))
                                .to_rfc3339();
                                let decision_event = WatchdogDecisionEvent {
                                    timestamp: now_utc.to_rfc3339(),
                                    group_id: gid.clone(),
                                    group_name: gname.clone(),
                                    trigger_reason: format!(
                                        "{trigger_reason_text}（顺位前 {probed_total} 个备选均未通过实测，进入 180 秒退避）"
                                    ),
                                    action: "backoff_all_candidates_failed".to_string(),
                                    from_node_id: Some(active_node.id.clone()),
                                    from_node_name: Some(active_node.name.clone()),
                                    to_node_id: None,
                                    to_node_name: None,
                                    current_probe_summary,
                                    candidates: candidate_traces,
                                    next_recheck_at: Some(next_recheck_at),
                                    keep_existing_connections: true,
                                };
                                let structured_log =
                                    format_watchdog_decision_log_line(&decision_event);
                                st.log_app_event("warning", "自动切优", &structured_log);
                                let snap_mut = watchdog_snapshot.get_or_insert_with(|| {
                                    read_watchdog_state_snapshot(&st.paths.root_data_dir)
                                        .unwrap_or_default()
                                });
                                let active_backoffs = build_watchdog_backoff_entries(
                                    &failed_group_backoff_until,
                                    &groups,
                                    &consecutive_fail_counts,
                                    now,
                                    now_utc,
                                );
                                let cooldown_entries = build_watchdog_cooldown_entries(
                                    &updated_pool,
                                    &latest_nodes,
                                    now,
                                );
                                let _ = record_watchdog_decision_event_and_persist(
                                    &st.paths.root_data_dir,
                                    snap_mut,
                                    decision_event,
                                    active_backoffs,
                                    cooldown_entries,
                                );
                            }
                        }
                    }
                }

                // Step 2: Lightweight round-robin background 204 sweep of 2-3 non-cooling backup
                // members (bounded concurrency <= 2, 3000ms timeout, retry-before-penalize).
                if st.shutting_down.load(Ordering::SeqCst)
                    || st.probe_running.load(Ordering::SeqCst)
                    || is_watchdog_high_throughput(&st)
                {
                    break;
                }
                let member_ids = collect_enabled_group_member_ids_from_summaries(&group, &nodes);
                let sweep_ids: Vec<String> = {
                    let now = Instant::now();
                    st.node_health_pool
                        .write()
                        .map(|mut pool| {
                            pool.select_background_sweep_ids(
                                &group.id,
                                &member_ids,
                                Some(&effective_active_id),
                                WATCHDOG_SWEEP_BATCH_SIZE,
                                now,
                            )
                        })
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|id| !probed_this_round.contains(id))
                        .collect()
                };
                if !sweep_ids.is_empty() {
                    let sweep_targets: Vec<(String, String)> = sweep_ids
                        .iter()
                        .map(|id| (id.clone(), resolve_node_compiled_proxy(&st, &nodes, id)))
                        .collect();
                    let sweep_results = probe_node_batch_bounded(
                        &st,
                        &http_client,
                        &ctrl_host,
                        rt.controller_port,
                        &secret,
                        &sweep_targets,
                        WATCHDOG_SWEEP_TIMEOUT_MS,
                    )
                    .await;
                    for (node_id, health) in sweep_results {
                        let (rt_h, rt_ms) = dual_health_to_runtime(health);
                        st.record_node_health_probe(&node_id, rt_h, rt_ms);
                        probed_this_round.insert(node_id);
                        should_emit_runtime = true;
                    }
                }

                // Step 3: Low-frequency background recovery check for 1-2 cooldown-expired or
                // penalized members (two consecutive 2/2 probes lift cooldown into probation,
                // never permanently banning any node).
                if st.shutting_down.load(Ordering::SeqCst)
                    || st.probe_running.load(Ordering::SeqCst)
                    || is_watchdog_high_throughput(&st)
                {
                    break;
                }
                let recovery_ids: Vec<String> = {
                    let now = Instant::now();
                    st.node_health_pool
                        .read()
                        .map(|pool| {
                            pool.select_recovery_check_ids(
                                &member_ids,
                                WATCHDOG_RECOVERY_LIMIT,
                                now,
                            )
                        })
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|id| !probed_this_round.contains(id))
                        .collect()
                };
                if !recovery_ids.is_empty() {
                    let recovery_targets: Vec<(String, String)> = recovery_ids
                        .iter()
                        .map(|id| (id.clone(), resolve_node_compiled_proxy(&st, &nodes, id)))
                        .collect();
                    let recovery_results = probe_node_batch_bounded(
                        &st,
                        &http_client,
                        &ctrl_host,
                        rt.controller_port,
                        &secret,
                        &recovery_targets,
                        WATCHDOG_SWEEP_TIMEOUT_MS,
                    )
                    .await;
                    for (node_id, health) in recovery_results {
                        let (rt_h, rt_ms) = dual_health_to_runtime(health);
                        st.record_node_health_probe(&node_id, rt_h, rt_ms);
                        should_emit_runtime = true;
                    }
                }
            }

            if should_emit_runtime && !st.shutting_down.load(Ordering::SeqCst) {
                commands::emit_runtime_snapshot(&app_h, &st);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dual_probe_watchdog_classifies_health_and_blocks_half_broken_ping_pong() {
        assert_eq!(
            classify_dual_probe_health(Some(60), Some(80)),
            DualProbeHealth::FullHealthy(70)
        );
        assert_eq!(
            classify_dual_probe_health(Some(64), None),
            DualProbeHealth::Degraded {
                passed_delay_ms: 64,
                failed_source: "Cloudflare",
            }
        );
        assert_eq!(
            classify_dual_probe_health(None, Some(65)),
            DualProbeHealth::Degraded {
                passed_delay_ms: 65,
                failed_source: "Google",
            }
        );
        assert_eq!(
            classify_dual_probe_health(None, None),
            DualProbeHealth::TotalFailure
        );

        let degraded_trigger = WatchdogFailoverTrigger::SustainedDegraded {
            degraded_rounds: WATCHDOG_DEGRADED_THRESHOLD_ROUNDS,
            failed_source: "Cloudflare",
        };
        let outage_trigger = WatchdogFailoverTrigger::TotalOutage { fail_count: 2 };

        // Sustained degraded node must SKIP another degraded candidate and pick the verified 2/2 node.
        let mixed_candidates = vec![
            (
                "tw-02",
                DualProbeHealth::Degraded {
                    passed_delay_ms: 64,
                    failed_source: "Google",
                },
            ),
            ("tw-05", DualProbeHealth::FullHealthy(108)),
        ];
        assert_eq!(
            choose_verified_candidate_from_probes(degraded_trigger, &mixed_candidates),
            Some(("tw-05", 108, true))
        );

        // If NO 2/2 healthy candidate exists, a degraded node must NOT ping-pong into another degraded node.
        let only_degraded = vec![
            (
                "tw-02",
                DualProbeHealth::Degraded {
                    passed_delay_ms: 64,
                    failed_source: "Google",
                },
            ),
            ("tw-04", DualProbeHealth::TotalFailure),
        ];
        assert_eq!(
            choose_verified_candidate_from_probes(degraded_trigger, &only_degraded),
            None
        );

        // On total outage (0/2), a full-healthy backup still wins, and degraded is only last-resort fallback.
        assert_eq!(
            choose_verified_candidate_from_probes(outage_trigger, &mixed_candidates),
            Some(("tw-05", 108, true))
        );
        assert_eq!(
            choose_verified_candidate_from_probes(outage_trigger, &only_degraded),
            Some(("tw-02", 64, false))
        );
    }


    #[test]
    fn dual_health_to_runtime_and_member_collection_behave_accurately() {
        assert_eq!(
            dual_health_to_runtime(DualProbeHealth::FullHealthy(82)),
            (RuntimeDualHealth::FullHealthy, Some(82.0))
        );
        assert_eq!(
            dual_health_to_runtime(DualProbeHealth::Degraded {
                passed_delay_ms: 95,
                failed_source: "Google",
            }),
            (RuntimeDualHealth::Degraded, Some(95.0))
        );
        assert_eq!(
            dual_health_to_runtime(DualProbeHealth::TotalFailure),
            (RuntimeDualHealth::Failed, None)
        );

        let make_node = |id: &str, enabled: bool| ProxyNode {
            id: id.to_string(),
            name: format!("node-{id}"),
            enabled,
            ..Default::default()
        };
        let nodes = vec![
            make_node("a", true),
            make_node("b", false),
            make_node("c", true),
        ];
        let explicit_group = MultiGroup {
            id: "g1".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec!["a".into(), "b".into(), "a".into(), "c".into()],
            ..Default::default()
        };
        assert_eq!(
            collect_enabled_group_member_ids(&explicit_group, &nodes),
            vec!["a".to_string(), "c".to_string()]
        );

        let dynamic_pool = MultiGroup {
            id: "g2".to_string(),
            mode: MultiGroupMode::ConditionalPool,
            member_node_ids: Vec::new(),
            ..Default::default()
        };
        assert_eq!(
            collect_enabled_group_member_ids(&dynamic_pool, &nodes),
            vec!["a".to_string(), "c".to_string()]
        );

        let summaries: Vec<NodeSummary> = nodes
            .iter()
            .map(|n| NodeSummary {
                id: n.id.clone(),
                sub_id: n.sub_id.clone(),
                name: n.name.clone(),
                region_code: n.region_code.clone(),
                protocol: n.protocol.clone(),
                server: n.server.clone(),
                port: n.port,
                multiplier: n.multiplier,
                enabled: n.enabled,
                ..Default::default()
            })
            .collect();
        assert_eq!(
            collect_enabled_group_member_ids_from_summaries(&explicit_group, &summaries),
            vec!["a".to_string(), "c".to_string()]
        );
        assert_eq!(
            collect_enabled_group_member_ids_from_summaries(&dynamic_pool, &summaries),
            vec!["a".to_string(), "c".to_string()]
        );
        assert_eq!(
            commands::count_enabled_group_members_from_summaries(&explicit_group, &summaries),
            2
        );
    }


    #[test]
    fn watchdog_does_not_flap_when_business_healthy_or_single_transient_jitter() {
        let mut fails = 0u32;
        let mut degraded = 0u32;
        let required_failures = 2u32;

        // 1. Healthy dual-origin probe -> stays sticky, zero switch.
        assert_eq!(
            evaluate_watchdog_active_health_tick(
                DualProbeHealth::FullHealthy(62),
                &mut fails,
                &mut degraded,
                required_failures,
                true,
            ),
            WatchdogTickDecision::HoldHealthy
        );
        assert_eq!(fails, 0);
        assert_eq!(degraded, 0);

        // 2. Single transient total failure (1 < 2) followed by recovery -> holds and resets, never flaps.
        assert_eq!(
            evaluate_watchdog_active_health_tick(
                DualProbeHealth::TotalFailure,
                &mut fails,
                &mut degraded,
                required_failures,
                true,
            ),
            WatchdogTickDecision::HoldTransient {
                count: 1,
                threshold: 2,
            }
        );
        assert_eq!(
            evaluate_watchdog_active_health_tick(
                DualProbeHealth::FullHealthy(68),
                &mut fails,
                &mut degraded,
                required_failures,
                true,
            ),
            WatchdogTickDecision::HoldHealthy
        );
        assert_eq!(fails, 0);

        // 3. Partial single-origin timeouts (business still reachable on the other origin) for 1..3 rounds
        //    followed by recovery -> holds and resets without spurious switching.
        for round in 1..WATCHDOG_DEGRADED_THRESHOLD_ROUNDS {
            assert_eq!(
                evaluate_watchdog_active_health_tick(
                    DualProbeHealth::Degraded {
                        passed_delay_ms: 74,
                        failed_source: "Cloudflare",
                    },
                    &mut fails,
                    &mut degraded,
                    required_failures,
                    true,
                ),
                WatchdogTickDecision::HoldTransient {
                    count: round,
                    threshold: WATCHDOG_DEGRADED_THRESHOLD_ROUNDS,
                }
            );
        }
        assert_eq!(
            evaluate_watchdog_active_health_tick(
                DualProbeHealth::FullHealthy(70),
                &mut fails,
                &mut degraded,
                required_failures,
                true,
            ),
            WatchdogTickDecision::HoldHealthy
        );
        assert_eq!(degraded, 0);

        // 4. Inside cooldown window, even consecutive total failures hold to prevent ping-pong.
        let _ = evaluate_watchdog_active_health_tick(
            DualProbeHealth::TotalFailure,
            &mut fails,
            &mut degraded,
            required_failures,
            false,
        );
        assert_eq!(
            evaluate_watchdog_active_health_tick(
                DualProbeHealth::TotalFailure,
                &mut fails,
                &mut degraded,
                required_failures,
                false,
            ),
            WatchdogTickDecision::HoldCooldown
        );
    }


    #[test]
    fn watchdog_switches_to_verified_backup_and_persists_structured_event_on_sustained_outage() {
        let tmp = std::env::temp_dir().join(format!(
            "catcloud_watchdog_event_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&tmp).expect("create temp dir");

        let make_node = |id: &str, name: &str| ProxyNode {
            id: id.to_string(),
            name: name.to_string(),
            region_code: "TW".to_string(),
            protocol: "vless".to_string(),
            server: "203.0.113.10".to_string(),
            port: 443,
            multiplier: 1.0,
            enabled: true,
            ..Default::default()
        };
        let nodes = vec![
            make_node("n-active", "TW-Primary"),
            make_node("n-old-cool", "JP-RecentlySwitchedOut"),
            make_node("n-bad-bak", "SG-Backup-Down"),
            make_node("n-good-bak", "HK-Backup-Healthy"),
        ];
        let group = MultiGroup {
            id: "grp-ai".to_string(),
            name: "AI主力组".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec![
                "n-active".into(),
                "n-old-cool".into(),
                "n-bad-bak".into(),
                "n-good-bak".into(),
            ],
            active_node_id: Some("n-active".to_string()),
            switch_mode: SwitchMode::GracefulNewOnly,
            cooldown_sec: 60,
            ..Default::default()
        };
        let mut snaps = HashMap::new();
        for (nid, up, lat) in [
            ("n-active", 12.0, 50.0),
            ("n-old-cool", 18.0, 45.0),
            ("n-bad-bak", 15.0, 55.0),
            ("n-good-bak", 14.0, 60.0),
        ] {
            snaps.insert(
                nid.to_string(),
                ProbeSnapshot {
                    node_id: nid.to_string(),
                    ok: true,
                    up_mbps: Some(up),
                    down_mbps: Some(120.0),
                    latency_ms: Some(lat),
                    google_clean: Some(true),
                    keepalive_60s_ok: Some(true),
                    ..Default::default()
                },
            );
        }

        // 1. Sustained dual-origin outage hits threshold (2/2) with cooldown elapsed -> triggers failover.
        let mut fails = 0u32;
        let mut degraded = 0u32;
        assert_eq!(
            evaluate_watchdog_active_health_tick(
                DualProbeHealth::TotalFailure,
                &mut fails,
                &mut degraded,
                2,
                true,
            ),
            WatchdogTickDecision::HoldTransient {
                count: 1,
                threshold: 2,
            }
        );
        let trigger = match evaluate_watchdog_active_health_tick(
            DualProbeHealth::TotalFailure,
            &mut fails,
            &mut degraded,
            2,
            true,
        ) {
            WatchdogTickDecision::Trigger(t) => t,
            other => panic!("expected Trigger on 2nd failure, got {other:?}"),
        };
        assert_eq!(trigger, WatchdogFailoverTrigger::TotalOutage { fail_count: 2 });

        // 2. Recently switched-out old node is shielded from ping-pong candidate ranking.
        let now = Instant::now();
        let mut pool = NodeHealthPool::new();
        pool.record_probe_result("n-active", RuntimeDualHealth::Failed, None, now);
        let switch_out_cooldowns: HashSet<String> =
            ["n-old-cool".to_string()].into_iter().collect();
        let ranked = commands::pick_group_candidates_with_cooldown_and_runtime(
            &group,
            &nodes,
            &snaps,
            Some("n-active"),
            &switch_out_cooldowns,
            Some(&pool),
            now,
            4,
        );
        assert!(
            !ranked.contains(&"n-old-cool".to_string()),
            "recently switched-out node must be excluded during cooldown window: {ranked:?}"
        );
        assert_eq!(ranked, vec!["n-bad-bak".to_string(), "n-good-bak".to_string()]);

        // 3. Live probing: n-bad-bak fails, n-good-bak passes 2/2 -> decisively selects n-good-bak.
        pool.record_probe_result("n-bad-bak", RuntimeDualHealth::Failed, None, now);
        pool.record_probe_result("n-good-bak", RuntimeDualHealth::FullHealthy, Some(58.0), now);
        let probed_results = vec![
            (
                ("n-bad-bak".to_string(), "SG-Backup-Down".to_string()),
                DualProbeHealth::TotalFailure,
            ),
            (
                ("n-good-bak".to_string(), "HK-Backup-Healthy".to_string()),
                DualProbeHealth::FullHealthy(58),
            ),
        ];
        let ((chosen_id, chosen_name), delay_ms, full_healthy) =
            choose_verified_candidate_from_probes(trigger, &probed_results)
                .expect("verified backup must be selected");
        assert_eq!(chosen_id, "n-good-bak");
        assert_eq!(chosen_name, "HK-Backup-Healthy");
        assert_eq!(delay_ms, 58);
        assert!(full_healthy);

        // 4. Construct structured decision event and atomically persist `watchdog-state.json`.
        let traces = build_watchdog_candidate_traces(
            &group,
            &nodes,
            &snaps,
            &pool,
            now,
            "n-active",
            &switch_out_cooldowns,
            &probed_results,
            Some(&chosen_id),
        );
        assert_eq!(traces.len(), 4);
        assert_eq!(
            traces
                .iter()
                .find(|t| t.node_id == "n-old-cool")
                .map(|t| t.status.as_str()),
            Some("skipped_recently_switched_out")
        );
        assert_eq!(
            traces
                .iter()
                .find(|t| t.node_id == "n-bad-bak")
                .map(|t| t.status.as_str()),
            Some("probed_failed")
        );
        assert_eq!(
            traces
                .iter()
                .find(|t| t.node_id == "n-good-bak")
                .map(|t| t.status.as_str()),
            Some("selected")
        );

        let event = WatchdogDecisionEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            group_id: group.id.clone(),
            group_name: group.name.clone(),
            trigger_reason: format_trigger_reason(trigger),
            action: "switch_node".to_string(),
            from_node_id: Some("n-active".to_string()),
            from_node_name: Some("TW-Primary".to_string()),
            to_node_id: Some(chosen_id.clone()),
            to_node_name: Some(chosen_name.clone()),
            current_probe_summary: format_dual_probe_summary(DualProbeHealth::TotalFailure),
            candidates: traces,
            next_recheck_at: Some((chrono::Utc::now() + chrono::Duration::seconds(60)).to_rfc3339()),
            keep_existing_connections: true,
        };
        let log_line = format_watchdog_decision_log_line(&event);
        assert!(log_line.contains("AI主力组"));
        assert!(log_line.contains("TW-Primary -> HK-Backup-Healthy"));
        assert!(log_line.contains("skipped_recently_switched_out"));

        let mut snapshot = WatchdogStateSnapshot::default();
        let cooldown_entries = build_watchdog_cooldown_entries(&pool, &nodes, now);
        assert!(cooldown_entries.iter().any(|c| c.node_id == "n-active"));
        assert!(cooldown_entries.iter().any(|c| c.node_id == "n-bad-bak"));

        // Persist 22 events to verify atomic disk persistence + 20-event ring cap.
        for _ in 0..22 {
            record_watchdog_decision_event_and_persist(
                &tmp,
                &mut snapshot,
                event.clone(),
                Vec::new(),
                cooldown_entries.clone(),
            )
            .expect("persist watchdog-state.json");
        }
        let reloaded =
            read_watchdog_state_snapshot(&tmp).expect("read persisted watchdog-state.json");
        assert_eq!(reloaded.recent_events.len(), 20);
        let last = reloaded.recent_events.last().unwrap();
        assert_eq!(last.action, "switch_node");
        assert_eq!(last.from_node_id.as_deref(), Some("n-active"));
        assert_eq!(last.to_node_id.as_deref(), Some("n-good-bak"));
        assert!(last.keep_existing_connections);
        assert!(last.next_recheck_at.is_some());
        assert_eq!(last.candidates.len(), 4);
        assert!(!reloaded.cooldown_nodes.is_empty());

        let _ = std::fs::remove_dir_all(&tmp);
    }


    #[test]
    fn watchdog_switch_policy_preserves_both_switch_modes_and_failure_threshold_floor() {
        use catcloud_core::models::TriggerRule;

        let degraded = WatchdogFailoverTrigger::SustainedDegraded {
            degraded_rounds: 4,
            failed_source: "Google",
        };
        let outage = WatchdogFailoverTrigger::TotalOutage { fail_count: 2 };

        // Partial degradation always keeps existing live connections regardless of switch_mode.
        assert_eq!(
            resolve_watchdog_switch_close_policy(degraded, &SwitchMode::ForceCloseOld),
            (Some(false), true)
        );
        assert_eq!(
            resolve_watchdog_switch_close_policy(degraded, &SwitchMode::GracefulNewOnly),
            (Some(false), true)
        );

        // Total outage strictly preserves both SwitchMode options without regression.
        assert_eq!(
            resolve_watchdog_switch_close_policy(outage, &SwitchMode::ForceCloseOld),
            (None, false)
        );
        assert_eq!(
            resolve_watchdog_switch_close_policy(outage, &SwitchMode::GracefulNewOnly),
            (None, true)
        );

        // SwitchMode serialization contract remains untouched.
        assert_eq!(
            serde_json::to_string(&SwitchMode::ForceCloseOld).unwrap(),
            "\"force_close_old\""
        );
        assert_eq!(
            serde_json::to_string(&SwitchMode::GracefulNewOnly).unwrap(),
            "\"graceful_new_only\""
        );

        // Failure threshold guard stays clamped at >= 2.
        let mut group = MultiGroup::default();
        assert!(commands::group_watchdog_failure_threshold(&group) >= 2);
        group.trigger_rules = vec![TriggerRule {
            expr: "ok == 0".to_string(),
            consecutive_failures: 1,
            bypass_cooldown_on_disconnect: true,
        }];
        assert_eq!(commands::group_watchdog_failure_threshold(&group), 2);
        group.trigger_rules = vec![TriggerRule {
            expr: "ok == 0".to_string(),
            consecutive_failures: 3,
            bypass_cooldown_on_disconnect: true,
        }];
        assert_eq!(commands::group_watchdog_failure_threshold(&group), 3);
    }

}
