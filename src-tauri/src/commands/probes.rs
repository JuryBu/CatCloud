use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use catcloud_core::core_adapter::binary_resolver::resolve_mihomo_binary;
use catcloud_core::models::PreAccelDispatchStrategy;
use catcloud_core::models::PreAccelRelay;
use catcloud_core::models::ProbeDefinition;
use catcloud_core::models::ProbeSnapshot;
use catcloud_core::models::ProxyNode;
use catcloud_core::models::RouteTargetMode;
use catcloud_core::probe::DEFAULT_READY_TIMEOUT;
use catcloud_core::probe::FunnelOptions;
use catcloud_core::probe::FunnelTier;
use catcloud_core::probe::IsolatedProbeCore;
use catcloud_core::probe::ProbeRegistry;
use catcloud_core::probe::run_funnel_for_node;
use catcloud_core::strategy::health_pool::RuntimeDualHealth;
use serde::Deserialize;
use serde::Serialize;
use tauri::AppHandle;
use tauri::Emitter;
use tauri::State;

use crate::commands::core_lifecycle::refresh_node_proxy_name_map;
use crate::commands::groups_strategy::reconcile_group_best_node_internal;
use crate::commands::groups_strategy::select_reconcilable_active_group_ids;
use crate::commands::state::AppState;
use crate::commands::state::EVENT_PROBE_PROGRESS;
use crate::commands::tray_runtime::ProbeRunningGuard;
use crate::commands::tray_runtime::has_existing_enabled_active_relay;
use crate::commands::tray_runtime::is_preaccel_pool_lb_effective;
use crate::commands::tray_runtime::sync_tray_and_window_side_effects;

#[tauri::command]
pub fn list_probe_definitions(state: State<'_, AppState>) -> Result<Vec<ProbeDefinition>, String> {
    let db = state.storage.lock().map_err(|e| e.to_string())?;
    db.list_probe_definitions().map_err(|e| e.to_string())
}


#[tauri::command]
pub fn upsert_probe_definition(
    state: State<'_, AppState>,
    mut probe: ProbeDefinition,
) -> Result<ProbeDefinition, String> {
    if probe.id.trim().is_empty() {
        probe.id = format!("probe-{}", uuid::Uuid::new_v4().simple());
    }
    catcloud_core::probe::validate_definition(&probe).map_err(|e| e.to_string())?;
    let db = state.storage.lock().map_err(|e| e.to_string())?;
    db.upsert_probe_definition(&probe).map_err(|e| e.to_string())?;
    Ok(probe)
}


#[tauri::command]
pub fn delete_probe_definition(
    state: State<'_, AppState>,
    probe_id: String,
) -> Result<bool, String> {
    let db = state.storage.lock().map_err(|e| e.to_string())?;
    db.delete_probe_definition(&probe_id).map_err(|e| e.to_string())
}


#[tauri::command]
pub fn list_probe_snapshots(
    state: State<'_, AppState>,
) -> Result<HashMap<String, ProbeSnapshot>, String> {
    let db = state.storage.lock().map_err(|e| e.to_string())?;
    let ids = db.list_node_ids().map_err(|e| e.to_string())?;
    db.get_probe_snapshots_batch(&ids, None)
        .map_err(|e| e.to_string())
}


#[tauri::command]
pub fn cancel_isolated_probes(state: State<'_, AppState>) -> Result<bool, String> {
    let was_running = state.probe_running.load(Ordering::SeqCst);
    if let Ok(guard) = state.probe_cancel_tx.lock() {
        if let Some(ref tx) = *guard {
            let _ = tx.send(true);
        }
    }
    Ok(was_running)
}


#[tauri::command]
pub async fn run_isolated_probes(
    app: AppHandle,
    state: State<'_, AppState>,
    node_ids: Vec<String>,
    probe_ids: Vec<String>,
    max_tier: Option<String>,
    include_keepalive: Option<bool>,
    use_preaccel: Option<bool>,
) -> Result<serde_json::Value, String> {
    let (cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);
    if state
        .probe_running
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("已有测速任务正在进行，请先暂停或等待完成".to_string());
    }
    if let Ok(mut guard) = state.probe_cancel_tx.lock() {
        *guard = Some(cancel_tx);
    }
    let _running_guard = ProbeRunningGuard::enter(&app, &state);

    let cfg = state.snapshot_config();
    let extra_candidates = state.extra_binary_candidates();
    let resolution = resolve_mihomo_binary(&cfg, &state.paths, &extra_candidates, false)
        .map_err(|e| format!("查找代理核心失败：{e}"))?;
    let Some(mihomo_bin) = resolution.path else {
        return Err("未找到 Mihomo 内核文件，无法执行后台测速".to_string());
    };

    let resolved_tier = match max_tier
        .as_deref()
        .map(str::trim)
        .unwrap_or("full")
        .to_ascii_lowercase()
        .as_str()
    {
        "latency" | "fast" | "l0" => FunnelTier::L0Connectivity,
        "unlock" | "clean" | "lite" | "l1" => FunnelTier::L1CleanAndUnlock,
        _ => FunnelTier::L2ThroughputAndKeepalive,
    };
    let keepalive_enabled = include_keepalive.unwrap_or(false);
    let want_preaccel = use_preaccel.unwrap_or(cfg.preaccel.enabled);

    let (target_nodes, probe_defs, preaccel_relays) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let all_nodes = db.list_nodes().map_err(|e| e.to_string())?;
        let target_nodes: Vec<ProxyNode> = if node_ids.is_empty() {
            all_nodes.into_iter().filter(|n| n.enabled).collect()
        } else {
            let id_map: HashMap<&str, &ProxyNode> =
                all_nodes.iter().map(|n| (n.id.as_str(), n)).collect();
            let mut seen_ids: std::collections::HashSet<&str> =
                std::collections::HashSet::with_capacity(node_ids.len());
            node_ids
                .iter()
                .filter(|id| seen_ids.insert(id.as_str()))
                .filter_map(|id| id_map.get(id.as_str()).map(|n| (*n).clone()))
                .collect()
        };
        let all_defs = db.list_probe_definitions().map_err(|e| e.to_string())?;
        let selected_defs: Vec<ProbeDefinition> = if probe_ids.is_empty() {
            all_defs
        } else {
            all_defs
                .into_iter()
                .filter(|d| probe_ids.contains(&d.id))
                .collect()
        };
        let filtered_defs: Vec<ProbeDefinition> = selected_defs
            .into_iter()
            .filter(|d| keepalive_enabled || d.kind != catcloud_core::models::ProbeKind::Keepalive)
            .collect();
        let preaccel_relays: Vec<PreAccelRelay> = if want_preaccel {
            let mut enabled_relays = db.list_preaccel_relays(true).unwrap_or_default();
            enabled_relays.retain(|r| !r.server.trim().is_empty() && r.port > 0);
            enabled_relays.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));
            if let Some(aid) = cfg
                .preaccel
                .active_relay_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                if let Some(pos) = enabled_relays.iter().position(|r| r.id == aid) {
                    let chosen = enabled_relays.remove(pos);
                    enabled_relays.insert(0, chosen);
                }
            }
            enabled_relays
        } else {
            Vec::new()
        };
        (target_nodes, filtered_defs, preaccel_relays)
    };

    let used_preaccel = !preaccel_relays.is_empty();
    let preaccel_host_selection = catcloud_core::preaccel::select_physical_host_relays(&preaccel_relays);
    let has_valid_active_relay = has_existing_enabled_active_relay(
        cfg.preaccel.active_relay_id.as_deref(),
        &preaccel_relays,
    );
    let preaccel_lb_active = is_preaccel_pool_lb_effective(
        cfg.preaccel.dispatch_strategy,
        cfg.preaccel.active_relay_id.as_deref(),
        &preaccel_relays,
        preaccel_host_selection.distinct_host_count,
    );
    let effective_probe_dispatch_strategy = if preaccel_lb_active {
        cfg.preaccel.dispatch_strategy
    } else if cfg.preaccel.dispatch_strategy == PreAccelDispatchStrategy::Auto
        && has_valid_active_relay
    {
        PreAccelDispatchStrategy::Fallback
    } else {
        cfg.preaccel.dispatch_strategy
    };
    let preaccel_relay_name = if preaccel_relays.is_empty() {
        None
    } else if preaccel_relays.len() == 1 {
        Some(preaccel_relays[0].name.clone())
    } else if preaccel_lb_active {
        Some(format!(
            "多云均衡池（{} 台物理云 / {} 条中转）",
            preaccel_host_selection.distinct_host_count,
            preaccel_relays.len()
        ))
    } else {
        Some(format!(
            "{}（自动主备共 {} 条）",
            preaccel_relays[0].name,
            preaccel_relays.len()
        ))
    };

    if target_nodes.is_empty() {
        return Err("请先选择至少一个节点后再开始测速".to_string());
    }
    if probe_defs.is_empty() {
        return Err("当前没有可用的测速项目".to_string());
    }

    let latency_probe_ids: HashSet<String> = probe_defs
        .iter()
        .filter(|d| d.kind == catcloud_core::models::ProbeKind::Latency)
        .map(|d| d.id.clone())
        .collect();

    let mut registry = ProbeRegistry::new();
    for def in probe_defs {
        registry.register(def).map_err(|e| e.to_string())?;
    }
    let registry = Arc::new(registry);

    let temp_root = state.paths.runtime_dir.join("probe_sandbox");
    std::fs::create_dir_all(&temp_root).map_err(|e| e.to_string())?;

    let options = Arc::new(FunnelOptions {
        max_tier: resolved_tier,
        ..FunnelOptions::default()
    });

    let total_count = target_nodes.len();
    let mut completed_count: usize = 0;
    let mut cancelled = false;
    let mut snapshots: HashMap<String, ProbeSnapshot> = HashMap::new();
    let mut summary_acc = IsolatedProbeRunAccumulator::default();
    let mut errors: Vec<String> = Vec::new();
    state.log_app_event(
        "info",
        "后台测速",
        &format!(
            "开始后台测速：目标节点 {} 个，档位 {}，国内提速 {}",
            total_count,
            max_tier.as_deref().unwrap_or("full"),
            if used_preaccel {
                preaccel_relay_name.as_deref().unwrap_or("已开启")
            } else {
                "关闭"
            }
        ),
    );

    const BATCH_SIZE: usize = 12;
    const CONCURRENCY: usize = 4;

    for chunk in target_nodes.chunks(BATCH_SIZE) {
        if *cancel_rx.borrow() {
            cancelled = true;
            break;
        }

        let probe_core = match tokio::select! {
            biased;
            _ = cancel_rx.wait_for(|&c| c) => Err("cancelled".to_string()),
            res = IsolatedProbeCore::spawn_with_options_and_preaccel_pool(
                &mihomo_bin,
                &temp_root,
                &state.job_guard,
                chunk,
                &[],
                DEFAULT_READY_TIMEOUT,
                &preaccel_relays,
                effective_probe_dispatch_strategy,
                cfg.preaccel.lb_strategy,
                cfg.preaccel.skip_443_native,
            ) => {
                res.map_err(|e| e.to_string())
            }
        } {
            Ok(core) => core,
            Err(err) if err == "cancelled" => {
                cancelled = true;
                break;
            }
            Err(err) => {
                errors.push(format!("后台测速核心启动失败：{err}"));
                break;
            }
        };

        let sem = Arc::new(tokio::sync::Semaphore::new(CONCURRENCY));
        let (tx, mut rx) = tokio::sync::mpsc::channel::<(
            String,
            String,
            Result<catcloud_core::probe::FunnelRunReport, String>,
        )>(chunk.len().max(1));

        let mut spawned = 0usize;
        let mut join_handles = Vec::with_capacity(chunk.len());
        for node in chunk {
            let Some(port) = probe_core.port_for_node(&node.id) else {
                continue;
            };
            spawned += 1;
            let sem_ref = Arc::clone(&sem);
            let reg_ref = Arc::clone(&registry);
            let opt_ref = Arc::clone(&options);
            let job_ref = Arc::clone(&state.job_guard);
            let mut worker_cancel_rx = cancel_rx.clone();
            let tx_ref = tx.clone();
            let nid = node.id.clone();
            let nname = node.name.clone();

            join_handles.push(tokio::spawn(async move {
                let permit = tokio::select! {
                    biased;
                    _ = worker_cancel_rx.wait_for(|&c| c) => return,
                    p = sem_ref.acquire_owned() => match p {
                        Ok(p) => p,
                        Err(_) => return,
                    }
                };
                if *worker_cancel_rx.borrow() {
                    drop(permit);
                    return;
                }
                let res = tokio::select! {
                    biased;
                    _ = worker_cancel_rx.wait_for(|&c| c) => {
                        drop(permit);
                        return;
                    }
                    r = run_funnel_for_node(&reg_ref, &nid, port, &opt_ref, Some(&job_ref), None) => {
                        r.map_err(|e| e.to_string())
                    }
                };
                drop(permit);
                let _ = tx_ref.send((nid, nname, res)).await;
            }));
        }
        drop(tx);

        let mut batch_received = 0usize;
        while batch_received < spawned {
            let recv_item = tokio::select! {
                biased;
                _ = cancel_rx.wait_for(|&c| c) => {
                    cancelled = true;
                    break;
                }
                item = rx.recv() => item,
            };
            let Some((nid, nname, outcome)) = recv_item else {
                cancelled |= *cancel_rx.borrow();
                break;
            };
            batch_received += 1;
            completed_count += 1;

            match outcome {
                Ok(report) => {
                    summary_acc.record_node(
                        &report.snapshot,
                        Some(&report.records),
                        &latency_probe_ids,
                    );
                    // Persist new probe records then read back the merged full snapshot from SQLite
                    // so fast latency checks never wipe previously measured upload/download/unlock data.
                    let snap = if let Ok(mut db) = state.storage.lock() {
                        if !report.records.is_empty() {
                            let _ = db.insert_probe_results_batch(&report.records);
                        }
                        db.get_probe_snapshot(&nid, None)
                            .ok()
                            .flatten()
                            .unwrap_or(report.snapshot)
                    } else {
                        report.snapshot
                    };
                    update_node_health_pool_after_isolated_probe(
                        &state,
                        &nid,
                        &report.records,
                        &latency_probe_ids,
                        &snap,
                    );
                    snapshots.insert(nid.clone(), snap.clone());
                    let _ = app.emit(
                        EVENT_PROBE_PROGRESS,
                        serde_json::json!({
                            "node_id": nid,
                            "node_name": nname,
                            "completed": completed_count,
                            "total": total_count,
                            "cancelled": false,
                            "done": false,
                            "snapshot": snap,
                            "error": null
                        }),
                    );
                }
                Err(err) => {
                    errors.push(format!("{nname}: {err}"));
                    let _ = app.emit(
                        EVENT_PROBE_PROGRESS,
                        serde_json::json!({
                            "node_id": nid,
                            "node_name": nname,
                            "completed": completed_count,
                            "total": total_count,
                            "cancelled": false,
                            "done": false,
                            "snapshot": null,
                            "error": err
                        }),
                    );
                }
            }

            if *cancel_rx.borrow() {
                cancelled = true;
                break;
            }
        }

        if cancelled {
            for h in &join_handles {
                h.abort();
            }
            let _ = tokio::time::timeout(Duration::from_millis(150), async {
                for h in join_handles {
                    let _ = h.await;
                }
            })
            .await;
        } else {
            for h in join_handles {
                let _ = h.await;
            }
        }
        let _ = probe_core.shutdown().await;
        if cancelled {
            break;
        }
    }

    let summary = summary_acc.finish(total_count, completed_count, errors.len());
    let ok_count = snapshots.values().filter(|s| s.ok).count();

    let _ = app.emit(
        EVENT_PROBE_PROGRESS,
        serde_json::json!({
            "node_id": null,
            "node_name": null,
            "completed": completed_count,
            "total": total_count,
            "cancelled": cancelled,
            "done": true,
            "snapshot": null,
            "error": null,
            "ok_count": ok_count,
            "latency_ok_count": summary.latency_ok_count,
            "bandwidth_ok_count": summary.bandwidth_ok_count,
            "keepalive_ok_count": summary.keepalive_ok_count,
            "failed_count": summary.failed_count,
            "exec_error_count": summary.exec_error_count,
            "untested_count": summary.untested_count
        }),
    );

    // Bound historical `probe_results` growth and reclaim SQLite page cache in the background
    // after `done: true` is emitted so UI completion state is never delayed by old DB pruning.
    if completed_count > 0 {
        let storage_for_prune = Arc::clone(&state.storage);
        tauri::async_runtime::spawn(async move {
            let _ = tokio::task::spawn_blocking(move || {
                if let Ok(db) = storage_for_prune.lock() {
                    if let Err(err) = db.prune_old_probe_results(20) {
                        tracing::debug!("post-probe prune_old_probe_results skipped: {err}");
                    }
                    db.compact_memory();
                }
            })
            .await;
        });
    }

    // Engage strategy engine immediately after fresh probe snapshots are persisted:
    // only reconcile when in Group route mode and the target group is in the active compiled set,
    // so Single-node mode or pruned inactive groups never emit phantom switch toasts.
    let latest_cfg = state.snapshot_config();
    if !snapshots.is_empty() && latest_cfg.route_mode == RouteTargetMode::Group {
        let core_running = state.snapshot_runtime().running;
        let compiled_group_ids = if core_running {
            let existing = state.snapshot_compiled_group_ids();
            if existing.is_some() {
                existing
            } else {
                refresh_node_proxy_name_map(&state);
                state.snapshot_compiled_group_ids()
            }
        } else {
            None
        };
        let target_group_ids: Vec<String> = state
            .storage
            .lock()
            .ok()
            .and_then(|db| db.list_multi_groups().ok())
            .map(|groups| {
                select_reconcilable_active_group_ids(
                    &latest_cfg,
                    &groups,
                    compiled_group_ids.as_ref(),
                )
            })
            .unwrap_or_default();

        for gid in target_group_ids {
            let _ =
                reconcile_group_best_node_internal(&app, &state, &gid, core_running, core_running)
                    .await;
        }
    }

    let latest_cfg = state.snapshot_config();
    sync_tray_and_window_side_effects(&app, &state, &latest_cfg);

    let status_text = if cancelled { "已手动取消" } else { "已完成" };
    let summary_level = if summary.exec_error_count == 0 {
        "info"
    } else {
        "warning"
    };
    state.log_app_event(
        summary_level,
        "后台测速",
        &format!(
            "后台测速{status_text}：完成 {completed_count}/{total_count}，延迟可达 {}，双向带宽通过 {}，60秒保活通过 {}，未通过 {}，执行异常 {}，未测 {}",
            summary.latency_ok_count,
            summary.bandwidth_ok_count,
            summary.keepalive_ok_count,
            summary.failed_count,
            summary.exec_error_count,
            summary.untested_count,
        ),
    );

    Ok(serde_json::json!({
        "probed_count": snapshots.len(),
        "total_count": total_count,
        "cancelled": cancelled,
        "ok_count": ok_count,
        "latency_ok_count": summary.latency_ok_count,
        "bandwidth_ok_count": summary.bandwidth_ok_count,
        "keepalive_ok_count": summary.keepalive_ok_count,
        "failed_count": summary.failed_count,
        "exec_error_count": summary.exec_error_count,
        "untested_count": summary.untested_count,
        "snapshots": snapshots,
        "errors": errors,
        "core_available": true,
        "used_preaccel": used_preaccel,
        "preaccel_relay_name": preaccel_relay_name
    }))
}


#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::commands) struct IsolatedProbeBatchSummary {
    pub(in crate::commands) latency_ok_count: usize,
    pub(in crate::commands) bandwidth_ok_count: usize,
    pub(in crate::commands) keepalive_ok_count: usize,
    pub(in crate::commands) failed_count: usize,
    pub(in crate::commands) exec_error_count: usize,
    pub(in crate::commands) untested_count: usize,
}


/// Update the runtime `node_health_pool` after an isolated probe run ONLY when this run actually
/// executed at least one `ProbeKind::Latency` probe:
/// - Latency ran and passed (matching `ProbeSnapshot::from_results_with_kinds` priority:
///   `builtin_latency` first, then last latency record) -> clear stale failure/cooldown penalties
///   via `reset_node_health` WITHOUT fabricating a background watchdog `FullHealthy` entry.
/// - Latency ran and failed -> reset stale healthy state and mark node `Failed` into cooldown.
/// - No Latency probe ran (e.g. unlock-only or bandwidth-only run) -> leave existing health pool
///   untouched so healthy nodes are never wiped.
pub(in crate::commands) fn update_node_health_pool_after_isolated_probe(
    state: &AppState,
    node_id: &str,
    records: &[catcloud_core::models::ProbeResultRecord],
    latency_probe_ids: &HashSet<String>,
    merged_snap: &ProbeSnapshot,
) {
    if latency_probe_ids.is_empty() {
        return;
    }
    let latency_records: Vec<&catcloud_core::models::ProbeResultRecord> = records
        .iter()
        .filter(|r| latency_probe_ids.contains(&r.probe_id))
        .collect();
    if latency_records.is_empty() {
        return;
    }
    let chosen_latency = latency_records
        .iter()
        .rev()
        .copied()
        .find(|r| r.probe_id == "builtin_latency")
        .or_else(|| latency_records.last().copied());
    let latency_passed = chosen_latency.is_some_and(|r| r.ok) && merged_snap.ok;
    if latency_passed {
        state.reset_node_health(node_id);
    } else {
        state.reset_node_health(node_id);
        state.record_node_health_probe(node_id, RuntimeDualHealth::Failed, None);
    }
}


#[derive(Debug, Default)]
struct IsolatedProbeRunAccumulator {
    latency_ok_count: usize,
    bandwidth_ok_count: usize,
    keepalive_ok_count: usize,
    failed_count: usize,
}

impl IsolatedProbeRunAccumulator {
    fn record_node(
        &mut self,
        snap: &ProbeSnapshot,
        node_recs: Option<&[catcloud_core::models::ProbeResultRecord]>,
        latency_probe_ids: &HashSet<String>,
    ) {
        let latency_ok = if !latency_probe_ids.is_empty() {
            node_recs.is_some_and(|recs| {
                recs.iter()
                    .any(|r| latency_probe_ids.contains(&r.probe_id) && r.ok)
            })
        } else {
            snap.ok && snap.latency_ms.is_some_and(|v| v.is_finite() && v > 0.0)
        };
        if latency_ok {
            self.latency_ok_count += 1;
        }
        let up_ok = match node_recs {
            Some(recs)
                if recs
                    .iter()
                    .any(|r| r.up_mbps.is_some() || r.probe_id == "builtin_upload") =>
            {
                recs.iter()
                    .any(|r| r.ok && r.up_mbps.is_some_and(|v| v.is_finite() && v > 0.0))
            }
            _ => snap.up_mbps.is_some_and(|v| v.is_finite() && v > 0.0),
        };
        let down_ok = match node_recs {
            Some(recs)
                if recs
                    .iter()
                    .any(|r| r.down_mbps.is_some() || r.probe_id == "builtin_download") =>
            {
                recs.iter()
                    .any(|r| r.ok && r.down_mbps.is_some_and(|v| v.is_finite() && v > 0.0))
            }
            _ => snap.down_mbps.is_some_and(|v| v.is_finite() && v > 0.0),
        };
        if up_ok && down_ok {
            self.bandwidth_ok_count += 1;
        }
        if snap.keepalive_60s_ok == Some(true) {
            self.keepalive_ok_count += 1;
        }
        if !snap.ok && !latency_ok {
            self.failed_count += 1;
        }
    }

    fn finish(
        self,
        total_count: usize,
        completed_count: usize,
        exec_error_count: usize,
    ) -> IsolatedProbeBatchSummary {
        IsolatedProbeBatchSummary {
            latency_ok_count: self.latency_ok_count,
            bandwidth_ok_count: self.bandwidth_ok_count,
            keepalive_ok_count: self.keepalive_ok_count,
            failed_count: self.failed_count,
            exec_error_count,
            untested_count: total_count.saturating_sub(completed_count),
        }
    }
}

/// Split isolated batch probe results into distinct, non-conflated metrics:
/// latency reachability, bidirectional bandwidth pass, 60s keepalive pass, failed probes,
/// execution errors, and untested nodes.
#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::commands) fn summarize_isolated_probe_run(
    total_count: usize,
    completed_count: usize,
    run_snapshots: &HashMap<String, ProbeSnapshot>,
    run_records_by_node: &HashMap<String, Vec<catcloud_core::models::ProbeResultRecord>>,
    latency_probe_ids: &HashSet<String>,
    exec_error_count: usize,
) -> IsolatedProbeBatchSummary {
    let mut acc = IsolatedProbeRunAccumulator::default();
    for (node_id, snap) in run_snapshots {
        acc.record_node(
            snap,
            run_records_by_node.get(node_id).map(Vec::as_slice),
            latency_probe_ids,
        );
    }
    acc.finish(total_count, completed_count, exec_error_count)
}

