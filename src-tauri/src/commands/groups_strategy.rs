use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;
use catcloud_core::config;
use catcloud_core::core_adapter::SINGLE_NODE_GROUP_NAME;
use catcloud_core::models::AppConfig;
use catcloud_core::models::MultiGroup;
use catcloud_core::models::MultiGroupMode;
use catcloud_core::models::ProxyNode;
use catcloud_core::models::RouteTargetMode;
use catcloud_core::models::SwitchMode;
use catcloud_core::strategy::evaluator::evaluate_group_candidates_with_runtime;
use catcloud_core::strategy::health_pool::RuntimeDualHealth;
use tauri::AppHandle;
use tauri::Emitter;
use tauri::State;

use crate::commands::core_lifecycle::trigger_reload_if_running;
use crate::commands::state::AppState;
use crate::commands::state::CoreRuntimeInfoDto;
use crate::commands::state::EVENT_STRATEGY_SWITCH;
use crate::commands::state::SwitchResultDto;
use crate::commands::strategy_rank::is_valid_group_member;
use crate::commands::strategy_rank::reconcile_group_best_node_in_memory_with_runtime;
use crate::commands::strategy_rank::sanitize_group_active_node_with_runtime;
use crate::commands::strategy_rank::validate_group_hard_gates;
use crate::commands::tray_runtime::SwitchingActiveGuard;
use crate::commands::tray_runtime::build_runtime_info_dto;
use crate::commands::tray_runtime::emit_config_updated;
use crate::commands::tray_runtime::emit_groups_updated;
use crate::commands::tray_runtime::format_mihomo_error_for_user;
use crate::commands::tray_runtime::sync_tray_and_window_side_effects;

/// Auto-create or refill a default "默认路线" multi-group when enabled nodes exist and either no
/// group exists yet or there are no dynamic groups and all existing static groups have 0 valid
/// enabled members (delegating to `Storage::ensure_default_group_if_empty`, strictly preserving
/// dynamic groups, independent-routing groups, and custom groups with non-blank `match_rules`).
/// Returns `true` when a default group was created or refilled and persisted as active.
pub(in crate::commands) fn ensure_default_group_if_empty(state: &AppState) -> bool {
    let target_group_id = {
        let Ok(db) = state.storage.lock() else {
            return false;
        };
        match db.ensure_default_group_if_empty() {
            Ok(Some(id)) => id,
            _ => return false,
        }
    };

    let mut cfg = state.clone_config();
    cfg.active_group_id = Some(target_group_id);
    if config::save(&state.paths, &cfg).is_ok() {
        if let Ok(mut guard) = state.config.write() {
            *guard = Arc::new(cfg);
        }
    }
    true
}


/// Switch a multi-group (or active single node) to the next best healthy node without polluting SQLite.
pub async fn switch_next_best_internal(
    app: &AppHandle,
    state: &AppState,
    group_id: String,
) -> Result<SwitchResultDto, String> {
    let _switching_guard = SwitchingActiveGuard::enter(app, state);
    let cfg = state.snapshot_config();
    let requested_id = group_id.trim();
    if cfg.route_mode == RouteTargetMode::Single
        && (requested_id.is_empty()
            || requested_id == "default"
            || requested_id == "single"
            || requested_id == "__single__"
            || requested_id == SINGLE_NODE_GROUP_NAME)
    {
        let (nodes, snaps) = {
            let db = state.storage.lock().map_err(|e| e.to_string())?;
            let nodes = db.list_nodes().map_err(|e| e.to_string())?;
            if nodes.is_empty() {
                return Err("暂无可用节点，请先导入订阅".to_string());
            }
            let ids: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
            let snaps = db
                .get_probe_snapshots_batch(&ids, None)
                .map_err(|e| e.to_string())?;
            (nodes, snaps)
        };

        let prev_id = cfg.active_single_node_id.clone();
        let (next_id, next_name, next_region, latency_ms, up_mbps) = {
            let mut enabled_nodes: Vec<(usize, &ProxyNode)> = nodes
                .iter()
                .enumerate()
                .filter(|(_, n)| n.enabled)
                .collect();
            if enabled_nodes.is_empty() {
                return Err("暂无已启用的可用节点".to_string());
            }

            let health_pool = state.snapshot_node_health_pool();
            let now = Instant::now();
            enabled_nodes.sort_by(|(idx_a, a), (idx_b, b)| {
                let rank = |n: &ProxyNode| -> (u8, f64, f64) {
                    if let Some(rt) = health_pool.get(&n.id) {
                        if rt.is_in_cooldown(now) || rt.last_health == Some(RuntimeDualHealth::Failed)
                        {
                            return (2, f64::INFINITY, 0.0);
                        }
                        if let Some(live_ms) = health_pool.live_latency_ms(&n.id) {
                            let up = snaps
                                .get(&n.id)
                                .and_then(|s| s.up_mbps)
                                .filter(|v| v.is_finite())
                                .unwrap_or(0.0);
                            return (0, live_ms + rt.penalty_score, -up);
                        }
                    }
                    match snaps.get(&n.id) {
                        Some(s) if s.ok => (
                            0,
                            s.latency_ms.filter(|v| v.is_finite()).unwrap_or(f64::INFINITY),
                            -s.up_mbps.filter(|v| v.is_finite()).unwrap_or(0.0),
                        ),
                        None => (1, f64::INFINITY, 0.0),
                        Some(_) => (2, f64::INFINITY, 0.0),
                    }
                };
                let ra = rank(a);
                let rb = rank(b);
                ra.0.cmp(&rb.0)
                    .then_with(|| ra.1.total_cmp(&rb.1))
                    .then_with(|| ra.2.total_cmp(&rb.2))
                    .then_with(|| idx_a.cmp(idx_b))
            });

            let next = match prev_id
                .as_deref()
                .and_then(|id| enabled_nodes.iter().position(|(_, n)| n.id == id))
            {
                Some(idx) => enabled_nodes[(idx + 1) % enabled_nodes.len()].1,
                None => enabled_nodes[0].1,
            };
            let next_snap = snaps.get(&next.id);
            (
                next.id.clone(),
                next.name.clone(),
                next.region_code.clone(),
                state.resolve_node_latency_ms(&next.id, next_snap),
                next_snap.and_then(|s| s.up_mbps),
            )
        };

        let (_dto, closed_connections) =
            select_single_node_with_closed(app, state, next_id.clone()).await?;
        return Ok(SwitchResultDto {
            group_id: SINGLE_NODE_GROUP_NAME.to_string(),
            previous_node_id: prev_id,
            active_node_id: next_id,
            active_node_name: next_name,
            active_node_region: next_region,
            latency_ms,
            up_mbps,
            closed_connections,
        });
    }

    let (group, nodes, snaps) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let nodes = db.list_nodes().map_err(|e| e.to_string())?;
        if nodes.is_empty() {
            return Err("暂无可用节点，请先导入订阅".to_string());
        }
        let active_gid = cfg
            .active_group_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let found_group = if !requested_id.is_empty() && requested_id != "default" {
            db.get_multi_group(requested_id)
                .map_err(|e| e.to_string())?
                .or_else(|| active_gid.and_then(|aid| db.get_multi_group(aid).ok().flatten()))
                .or_else(|| db.list_multi_groups().ok().and_then(|mut v| v.drain(..).next()))
        } else {
            active_gid
                .and_then(|aid| db.get_multi_group(aid).ok().flatten())
                .or_else(|| db.get_multi_group("default").ok().flatten())
                .or_else(|| db.list_multi_groups().ok().and_then(|mut v| v.drain(..).next()))
        };
        let Some(group) = found_group else {
            return Err("暂无可切换的路线分组，请先创建分组".to_string());
        };
        let ids: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
        let snaps = db
            .get_probe_snapshots_batch(&ids, group.primary_probe_id.as_deref())
            .map_err(|e| e.to_string())?;
        (group, nodes, snaps)
    };

    let prev_id = group.active_node_id.clone();
    let prev_node_name = prev_id
        .as_deref()
        .and_then(|id| nodes.iter().find(|n| n.id == id))
        .map(|n| n.name.clone());

    // Rank candidates using the real strategy formula evaluator fused with runtime health pool;
    // when all members fail hard gates, keep honoring probed-ok scores in `gate_rejected` before
    // falling back to enabled member order.
    let health_pool = state.snapshot_node_health_pool();
    let ranked_ids: Vec<String> = match evaluate_group_candidates_with_runtime(
        &group,
        &nodes,
        &snaps,
        Some(&health_pool),
        Instant::now(),
    ) {
        Ok(report) => {
            if !report.healthy_candidates.is_empty() {
                report
                    .healthy_candidates
                    .iter()
                    .map(|c| c.node_id.clone())
                    .collect()
            } else if !report.gate_passed.is_empty() {
                report
                    .gate_passed
                    .iter()
                    .map(|c| c.node_id.clone())
                    .collect()
            } else {
                report
                    .gate_rejected
                    .iter()
                    .filter(|c| c.ok)
                    .map(|c| c.node_id.clone())
                    .collect()
            }
        }
        Err(_) => Vec::new(),
    };

    let ordered_candidates: Vec<&ProxyNode> = if !ranked_ids.is_empty() {
        ranked_ids
            .iter()
            .filter_map(|id| nodes.iter().find(|n| &n.id == id && n.enabled))
            .collect()
    } else if group.member_node_ids.is_empty() {
        nodes.iter().filter(|n| n.enabled).collect()
    } else {
        nodes
            .iter()
            .filter(|n| n.enabled && group.member_node_ids.contains(&n.id))
            .collect()
    };

    if ordered_candidates.is_empty() {
        return Err("该分组下暂无已启用的候选节点".to_string());
    }

    let next = match prev_id
        .as_deref()
        .and_then(|id| ordered_candidates.iter().position(|n| n.id == id))
    {
        Some(idx) => ordered_candidates[(idx + 1) % ordered_candidates.len()],
        None => ordered_candidates[0],
    };

    select_group_node_internal(
        app,
        state,
        group.id.clone(),
        next.id.clone(),
        Some(matches!(group.switch_mode, SwitchMode::ForceCloseOld)),
        prev_node_name,
    )
    .await
}


async fn select_single_node_with_closed(
    app: &AppHandle,
    state: &AppState,
    node_id: String,
) -> Result<(CoreRuntimeInfoDto, usize), String> {
    let _switching_guard = SwitchingActiveGuard::enter(app, state);
    let trimmed = node_id.trim();
    if trimmed.is_empty() {
        return Err("节点标识不能为空".to_string());
    }
    let _cfg_guard = state.config_transition_lock.lock().await;

    let prev_cfg = state.snapshot_config();
    let prev_single_id = if prev_cfg.route_mode == RouteTargetMode::Single {
        prev_cfg
            .active_single_node_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    } else {
        None
    };

    let (node, prev_node_fallback_name) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let node = db
            .get_node(trimmed)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("未找到指定节点（{trimmed}）"))?;
        let prev_name = prev_single_id
            .as_deref()
            .and_then(|pid| db.get_node(pid).ok().flatten())
            .map(|n| n.name);
        (node, prev_name)
    };
    if !node.enabled {
        return Err("该节点已停用，请先启用或选择其它节点".to_string());
    }

    let was_single = prev_single_id.is_some();
    let switched_node = prev_single_id.as_deref() != Some(node.id.as_str());
    let prev_proxy_name = if switched_node {
        prev_single_id
            .as_deref()
            .map(|pid| {
                let fallback = prev_node_fallback_name.as_deref().unwrap_or("");
                state.resolve_compiled_proxy_name(pid, fallback)
            })
            .filter(|s| !s.is_empty())
            .or(prev_node_fallback_name)
    } else {
        None
    };

    let mut cfg = (*prev_cfg).clone();
    cfg.route_mode = RouteTargetMode::Single;
    cfg.active_single_node_id = Some(node.id.clone());
    config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
    if let Ok(mut guard) = state.config.write() {
        *guard = Arc::new(cfg.clone());
    }

    let mut closed_connections = 0usize;
    if state.adapter.has_live_controller().await {
        let mut needs_reload = !was_single;
        if was_single {
            if let Some(proxy_name) = state.lookup_compiled_proxy_name(&node.id) {
                if state
                    .adapter
                    .select_group_proxy(SINGLE_NODE_GROUP_NAME, &proxy_name)
                    .await
                    .is_err()
                {
                    needs_reload = true;
                }
            } else {
                // Target node is not present in the currently compiled (possibly pruned) config:
                // force an L2 reload instead of falling back to raw `node.name`, which would either
                // trigger an avoidable HTTP 400 or silently switch to a same-named node from another sub.
                needs_reload = true;
            }
        }
        if needs_reload {
            if let Some(outcome) = trigger_reload_if_running(app, state, true).await {
                if outcome.rejected {
                    let _ = config::save(&state.paths, &prev_cfg);
                    if let Ok(mut guard) = state.config.write() {
                        *guard = Arc::clone(&prev_cfg);
                    }
                    sync_tray_and_window_side_effects(app, state, &prev_cfg);
                    let detail = outcome
                        .error
                        .as_deref()
                        .map(format_mihomo_error_for_user)
                        .unwrap_or_else(|| "未知原因".to_string());
                    return Err(format!(
                        "切换到单节点「{}」失败，核心配置重载未通过：{detail}",
                        node.name
                    ));
                }
            }
        }
        // Close lingering long-lived connections from the previous node so AI IDEs / browsers
        // immediately bind to the newly selected single node.
        if switched_node {
            if let Ok(closed) = state
                .adapter
                .close_connections_for_group_or_node(
                    Some(SINGLE_NODE_GROUP_NAME),
                    prev_proxy_name.as_deref(),
                )
                .await
            {
                closed_connections = closed;
            }
        }
    }

    state.log_app_event(
        "info",
        "节点切换",
        &format!(
            "单节点直选切换至「{}」（地区 {}，断开旧连接 {} 条）",
            node.name, node.region_code, closed_connections
        ),
    );
    sync_tray_and_window_side_effects(app, state, &cfg);
    Ok((build_runtime_info_dto(state)?, closed_connections))
}


pub async fn select_single_node_internal(
    app: &AppHandle,
    state: &AppState,
    node_id: String,
) -> Result<CoreRuntimeInfoDto, String> {
    let (dto, _) = select_single_node_with_closed(app, state, node_id).await?;
    Ok(dto)
}


async fn select_group_node_core(
    app: &AppHandle,
    state: &AppState,
    group_id: String,
    node_id: String,
    close_old: Option<bool>,
    prev_node_name_hint: Option<String>,
    activate_group: Option<bool>,
) -> Result<SwitchResultDto, String> {
    let _switching_guard = SwitchingActiveGuard::enter(app, state);
    let _cfg_guard = state.config_transition_lock.lock().await;
    let (mut group, prev_group, target_node, prev_id, prev_node_name, snap) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let group = db
            .get_multi_group(&group_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("未找到指定路线分组（{group_id}）"))?;
        let prev_group = group.clone();
        let target_node = db
            .get_node(&node_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("未找到指定节点（{node_id}）"))?;
        let prev_id = group.active_node_id.clone();
        let prev_node_name = prev_node_name_hint.or_else(|| {
            prev_id
                .as_deref()
                .and_then(|id| db.get_node(id).ok().flatten())
                .map(|n| n.name)
        });
        let snap = db
            .get_probe_snapshot(&target_node.id, group.primary_probe_id.as_deref())
            .map_err(|e| e.to_string())?;
        (group, prev_group, target_node, prev_id, prev_node_name, snap)
    };

    let mut members_changed = false;
    let is_dynamic_unpinned_pool = group.member_node_ids.is_empty()
        && (group.mode == MultiGroupMode::ConditionalPool || group.dynamic_filter.is_some());
    if !is_dynamic_unpinned_pool && !group.member_node_ids.iter().any(|id| id == &target_node.id) {
        group.member_node_ids.push(target_node.id.clone());
        members_changed = true;
    }
    group.active_node_id = Some(target_node.id.clone());
    {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        db.upsert_multi_group(&group).map_err(|e| e.to_string())?;
    }

    let prev_cfg = state.snapshot_config();
    let effective_activate_group = should_activate_group_on_node_select(
        activate_group,
        group.independent_routing,
        &group.id,
        prev_cfg.route_mode,
        prev_cfg.active_group_id.as_deref(),
    );
    let mut cfg = (*prev_cfg).clone();
    let was_single = cfg.route_mode == RouteTargetMode::Single;
    let active_group_changed = cfg.active_group_id.as_deref() != Some(group.id.as_str());
    let route_cfg_changed = effective_activate_group && (was_single || active_group_changed);
    if route_cfg_changed {
        cfg.route_mode = RouteTargetMode::Group;
        cfg.active_group_id = Some(group.id.clone());
        config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
        if let Ok(mut guard) = state.config.write() {
            *guard = Arc::new(cfg.clone());
        }
    }

    let mut closed_connections = 0usize;
    if state.adapter.has_live_controller().await {
        if members_changed || route_cfg_changed {
            if let Some(outcome) = trigger_reload_if_running(
                app,
                state,
                (effective_activate_group && was_single) || members_changed,
            )
            .await
            {
                if outcome.rejected {
                    if let Ok(db) = state.storage.lock() {
                        let _ = db.upsert_multi_group(&prev_group);
                    }
                    if route_cfg_changed {
                        let _ = config::save(&state.paths, &prev_cfg);
                        if let Ok(mut guard) = state.config.write() {
                            *guard = Arc::clone(&prev_cfg);
                        }
                    }
                    sync_tray_and_window_side_effects(app, state, &prev_cfg);
                    let detail = outcome
                        .error
                        .as_deref()
                        .map(format_mihomo_error_for_user)
                        .unwrap_or_else(|| "未知原因".to_string());
                    return Err(format!(
                        "已将节点「{}」加入分组「{}」，但重载核心配置失败：{detail}",
                        target_node.name, group.name
                    ));
                }
            }
        }
        let target_proxy_name =
            state.resolve_compiled_proxy_name(&target_node.id, &target_node.name);
        state
            .adapter
            .select_group_proxy(&group.name, &target_proxy_name)
            .await
            .map_err(|e| {
                format!(
                    "切换核心节点「{}」失败，请确认该节点已启用且核心运行正常：{e}",
                    target_node.name
                )
            })?;
        let should_close =
            close_old.unwrap_or_else(|| matches!(group.switch_mode, SwitchMode::ForceCloseOld));
        if should_close {
            let prev_compiled_name = prev_id.as_deref().map(|pid| {
                let fallback = prev_node_name.as_deref().unwrap_or("");
                state.resolve_compiled_proxy_name(pid, fallback)
            });
            let prev_target = prev_compiled_name
                .as_deref()
                .filter(|s| !s.is_empty())
                .or(prev_node_name.as_deref());
            if let Ok(closed) = state
                .adapter
                .close_connections_for_group_or_node(Some(&group.name), prev_target)
                .await
            {
                closed_connections = closed;
            }
        }
    }

    let cfg = state.snapshot_config();
    state.set_group_backoff_until(&group.id, None);
    let from_label = prev_node_name.as_deref().unwrap_or("未选");
    if effective_activate_group {
        state.log_app_event(
            "info",
            "节点切换",
            &format!(
                "分组「{}」切换节点：{} -> {}（断开旧连接 {} 条）",
                group.name, from_label, target_node.name, closed_connections
            ),
        );
    } else if group.independent_routing {
        state.log_app_event(
            "info",
            "节点切换",
            &format!(
                "独立分流组「{}」原地切换节点：{} -> {}（主兜底组保持不变，断开旧连接 {} 条）",
                group.name, from_label, target_node.name, closed_connections
            ),
        );
    }
    sync_tray_and_window_side_effects(app, state, &cfg);
    emit_groups_updated(app);

    let resolved_latency_ms = state.resolve_node_latency_ms(&target_node.id, snap.as_ref());
    Ok(SwitchResultDto {
        group_id: group.id,
        previous_node_id: prev_id,
        active_node_id: target_node.id,
        active_node_name: target_node.name,
        active_node_region: target_node.region_code,
        latency_ms: resolved_latency_ms,
        up_mbps: snap.as_ref().and_then(|s| s.up_mbps),
        closed_connections,
    })
}


pub async fn select_group_node_internal(
    app: &AppHandle,
    state: &AppState,
    group_id: String,
    node_id: String,
    close_old: Option<bool>,
    prev_node_name_hint: Option<String>,
) -> Result<SwitchResultDto, String> {
    select_group_node_core(
        app,
        state,
        group_id,
        node_id,
        close_old,
        prev_node_name_hint,
        Some(true),
    )
    .await
}


/// Switch a group's active node in Mihomo and SQLite WITHOUT changing `config.active_group_id`
/// (used by background watchdog failover for non-primary `independent_routing` groups).
pub async fn select_group_node_in_place_internal(
    app: &AppHandle,
    state: &AppState,
    group_id: String,
    node_id: String,
    close_old: Option<bool>,
    prev_node_name_hint: Option<String>,
) -> Result<SwitchResultDto, String> {
    select_group_node_core(
        app,
        state,
        group_id,
        node_id,
        close_old,
        prev_node_name_hint,
        Some(false),
    )
    .await
}


/// Select group IDs eligible for post-probe auto-reconciliation and switch toast emission.
/// - Never selects any group while `cfg.route_mode != RouteTargetMode::Group` (Single-node mode).
/// - When `compiled_group_ids` is provided (running core), filters out groups that were pruned
///   from the active compiled Mihomo configuration.
pub(in crate::commands) fn select_reconcilable_active_group_ids(
    cfg: &AppConfig,
    groups: &[MultiGroup],
    compiled_group_ids: Option<&HashSet<String>>,
) -> Vec<String> {
    if cfg.route_mode != RouteTargetMode::Group || groups.is_empty() {
        return Vec::new();
    }

    let active_gid = cfg
        .active_group_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|aid| groups.iter().find(|g| g.id == aid).map(|g| g.id.clone()))
        .or_else(|| groups.first().map(|g| g.id.clone()));

    let mut ids = Vec::new();
    for g in groups {
        let is_primary = active_gid.as_deref() == Some(g.id.as_str());
        let is_strategy_mode = matches!(
            g.mode,
            MultiGroupMode::StickyBest | MultiGroupMode::ConditionalPool
        );
        if !(is_primary || (g.independent_routing && is_strategy_mode)) {
            continue;
        }
        if let Some(compiled) = compiled_group_ids {
            if !compiled.contains(g.id.trim()) {
                continue;
            }
        }
        if !ids.iter().any(|existing| existing == &g.id) {
            ids.push(g.id.clone());
        }
    }
    ids
}


/// Reconcile a single multi-group against current membership, hard gates, and probe snapshots.
/// Persists any `active_node_id` update to SQLite, optionally hot-switches Mihomo & closes stale
/// connections when `sync_live_core` is true, and optionally emits `catcloud://strategy-switch`.
pub async fn reconcile_group_best_node_internal(
    app: &AppHandle,
    state: &AppState,
    group_id: &str,
    sync_live_core: bool,
    emit_notification: bool,
) -> Result<Option<SwitchResultDto>, String> {
    let (group_name, switch_mode, decision, target_node_region, target_snap) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let Some(mut group) = db
            .get_multi_group(group_id)
            .map_err(|e| e.to_string())?
        else {
            return Ok(None);
        };
        let nodes = db.list_nodes().map_err(|e| e.to_string())?;
        let node_ids: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
        let snaps = db
            .get_probe_snapshots_batch(&node_ids, group.primary_probe_id.as_deref())
            .map_err(|e| e.to_string())?;

        let prev_active = group.active_node_id.clone();
        let health_pool = state.snapshot_node_health_pool();
        let decision = reconcile_group_best_node_in_memory_with_runtime(
            &mut group,
            &nodes,
            &snaps,
            Some(&health_pool),
            Instant::now(),
        );
        if group.active_node_id != prev_active {
            db.upsert_multi_group(&group).map_err(|e| e.to_string())?;
        }

        let Some(dec) = decision else {
            return Ok(None);
        };
        let target_region = nodes
            .iter()
            .find(|n| n.id == dec.to_node_id)
            .map(|n| n.region_code.clone())
            .unwrap_or_else(|| "--".to_string());
        let snap = snaps.get(&dec.to_node_id).cloned();
        (group.name, group.switch_mode, dec, target_region, snap)
    };

    let mut closed_connections = 0usize;
    let mut live_switch_ok = true;
    if sync_live_core && state.adapter.has_live_controller().await {
        let target_proxy_name =
            state.resolve_compiled_proxy_name(&decision.to_node_id, &decision.to_node_name);
        if let Err(err) = state
            .adapter
            .select_group_proxy(&group_name, &target_proxy_name)
            .await
        {
            live_switch_ok = false;
            tracing::debug!(
                group = %group_name,
                proxy = %target_proxy_name,
                "reconcile_group_best_node_internal hot-switch skipped: {err}"
            );
        } else if matches!(switch_mode, SwitchMode::ForceCloseOld) {
            let prev_compiled_name = decision.from_node_id.as_deref().map(|pid| {
                state.resolve_compiled_proxy_name(pid, &decision.from_node_name)
            });
            let prev_target = prev_compiled_name
                .as_deref()
                .filter(|s| !s.is_empty())
                .or(Some(decision.from_node_name.as_str()));
            if let Ok(closed) = state
                .adapter
                .close_connections_for_group_or_node(Some(&group_name), prev_target)
                .await
            {
                closed_connections = closed;
            }
        }
    }

    state.log_app_event(
        "info",
        "策略择优",
        &format!(
            "分组「{}」自动择优切换：{} -> {}（{}，断开旧连接 {} 条）",
            group_name,
            decision.from_node_name,
            decision.to_node_name,
            decision.reason,
            closed_connections
        ),
    );

    if emit_notification && live_switch_ok {
        let _ = app.emit(
            EVENT_STRATEGY_SWITCH,
            serde_json::json!({
                "group_name": group_name,
                "from_node": decision.from_node_name,
                "to_node": decision.to_node_name,
                "reason": decision.reason,
            }),
        );
    }
    emit_groups_updated(app);

    let resolved_latency_ms =
        state.resolve_node_latency_ms(&decision.to_node_id, target_snap.as_ref());
    Ok(Some(SwitchResultDto {
        group_id: group_id.to_string(),
        previous_node_id: decision.from_node_id,
        active_node_id: decision.to_node_id,
        active_node_name: decision.to_node_name,
        active_node_region: target_node_region,
        latency_ms: resolved_latency_ms,
        up_mbps: target_snap.as_ref().and_then(|s| s.up_mbps),
        closed_connections,
    }))
}


#[tauri::command]
pub async fn switch_next_best_node(
    app: AppHandle,
    state: State<'_, AppState>,
    group_id: String,
) -> Result<SwitchResultDto, String> {
    switch_next_best_internal(&app, &state, group_id).await
}


pub(in crate::commands) fn should_activate_group_on_node_select(
    explicit: Option<bool>,
    group_independent_routing: bool,
    group_id: &str,
    current_route_mode: RouteTargetMode,
    current_active_group_id: Option<&str>,
) -> bool {
    if let Some(flag) = explicit {
        return flag;
    }
    if group_independent_routing
        && current_route_mode == RouteTargetMode::Group
        && current_active_group_id.is_some_and(|active| !active.is_empty() && active != group_id)
    {
        return false;
    }
    true
}


#[tauri::command]
pub async fn select_group_node(
    app: AppHandle,
    state: State<'_, AppState>,
    group_id: String,
    node_id: String,
    close_old: Option<bool>,
    activate_group: Option<bool>,
) -> Result<SwitchResultDto, String> {
    select_group_node_core(
        &app,
        &state,
        group_id,
        node_id,
        close_old,
        None,
        activate_group,
    )
    .await
}


#[tauri::command]
pub async fn set_active_group(
    app: AppHandle,
    state: State<'_, AppState>,
    group_id: String,
) -> Result<CoreRuntimeInfoDto, String> {
    let _switching_guard = SwitchingActiveGuard::enter(&app, &state);
    let trimmed = group_id.trim().to_string();
    if trimmed.is_empty() {
        return Err("路线分组标识不能为空".to_string());
    }
    let group_name = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let Some(group) = db
            .get_multi_group(&trimmed)
            .map_err(|e| e.to_string())?
        else {
            return Err(format!("未找到指定路线分组（{trimmed}）"));
        };
        group.name
    };

    // Sanitize ghost active_node_id and auto-pick best healthy candidate before activating group.
    let reconciled = reconcile_group_best_node_internal(&app, &state, &trimmed, false, false).await?;

    let _cfg_guard = state.config_transition_lock.lock().await;
    let prev_cfg = state.snapshot_config();
    let was_single = prev_cfg.route_mode == RouteTargetMode::Single;
    let group_changed = prev_cfg.active_group_id.as_deref() != Some(trimmed.as_str());
    let changed = was_single || group_changed;

    let mut cfg = (*prev_cfg).clone();
    cfg.route_mode = RouteTargetMode::Group;
    cfg.active_group_id = Some(trimmed);
    config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
    if let Ok(mut guard) = state.config.write() {
        *guard = Arc::new(cfg.clone());
    }
    if changed {
        if let Some(outcome) = trigger_reload_if_running(&app, &state, was_single).await {
            if outcome.rejected {
                let _ = config::save(&state.paths, &prev_cfg);
                if let Ok(mut guard) = state.config.write() {
                    *guard = Arc::clone(&prev_cfg);
                }
                sync_tray_and_window_side_effects(&app, &state, &prev_cfg);
                let detail = outcome
                    .error
                    .as_deref()
                    .map(format_mihomo_error_for_user)
                    .unwrap_or_else(|| "未知原因".to_string());
                return Err(format!("切换活跃路线分组失败，核心配置重载未通过：{detail}"));
            }
        }
    } else if let Some(ref sw) = reconciled {
        if state.adapter.has_live_controller().await {
            let target_proxy =
                state.resolve_compiled_proxy_name(&sw.active_node_id, &sw.active_node_name);
            let _ = state
                .adapter
                .select_group_proxy(&group_name, &target_proxy)
                .await;
        }
    }
    if changed {
        state.log_app_event(
            "info",
            "路线组",
            &format!("已切换活跃路线分组至「{group_name}」"),
        );
    }
    sync_tray_and_window_side_effects(&app, &state, &cfg);
    if changed || reconciled.is_some() {
        emit_groups_updated(&app);
    }
    build_runtime_info_dto(&state)
}


#[tauri::command]
pub async fn select_single_node(
    app: AppHandle,
    state: State<'_, AppState>,
    node_id: String,
) -> Result<CoreRuntimeInfoDto, String> {
    select_single_node_internal(&app, &state, node_id).await
}


#[tauri::command]
pub fn list_multi_groups(state: State<'_, AppState>) -> Result<Vec<MultiGroup>, String> {
    let health_pool = state.snapshot_node_health_pool();
    let now = Instant::now();
    let db = state.storage.lock().map_err(|e| e.to_string())?;
    let mut groups = db.list_multi_groups().map_err(|e| e.to_string())?;
    if let Ok(nodes) = db.list_nodes() {
        let node_ids: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
        for g in &mut groups {
            let needs_sanitize = match g.active_node_id.as_deref() {
                Some(aid) => !is_valid_group_member(g, aid, &nodes),
                None => !g.member_node_ids.is_empty(),
            };
            if needs_sanitize {
                let snaps = db
                    .get_probe_snapshots_batch(&node_ids, g.primary_probe_id.as_deref())
                    .unwrap_or_default();
                let _ = sanitize_group_active_node_with_runtime(
                    g,
                    &nodes,
                    &snaps,
                    Some(&health_pool),
                    now,
                );
            }
        }
    }
    Ok(groups)
}


#[tauri::command]
pub async fn upsert_multi_group(
    app: AppHandle,
    state: State<'_, AppState>,
    mut group: MultiGroup,
) -> Result<MultiGroup, String> {
    if group.id.trim().is_empty() {
        group.id = format!("grp-{}", uuid::Uuid::new_v4().simple());
    }
    catcloud_core::strategy::formula::validate_formula(&group.formula_expr)
        .map_err(|e| format!("分组排序公式无效：{e}"))?;
    group.hard_gates = group
        .hard_gates
        .into_iter()
        .map(|g| g.trim().to_string())
        .filter(|g| !g.is_empty())
        .collect();
    validate_group_hard_gates(&group.hard_gates)?;
    let (prev_group, prev_active_id, prev_active_name, next_active_name) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let existing_group = db.get_multi_group(&group.id).map_err(|e| e.to_string())?;
        let existing_prev = existing_group
            .as_ref()
            .and_then(|g| g.active_node_id.clone())
            .or_else(|| group.active_node_id.clone());
        let nodes = db.list_nodes().map_err(|e| e.to_string())?;
        let node_ids: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
        let snaps = db
            .get_probe_snapshots_batch(&node_ids, group.primary_probe_id.as_deref())
            .unwrap_or_default();
        let prev_name = existing_prev
            .as_deref()
            .and_then(|id| nodes.iter().find(|n| n.id == id))
            .map(|n| n.name.clone());

        // Sanitize ghost active_node_id and re-pick best healthy candidate if current violates
        // updated hard gates/membership while preserving healthy in-group selection.
        let health_pool = state.snapshot_node_health_pool();
        let now = Instant::now();
        let _ = sanitize_group_active_node_with_runtime(
            &mut group,
            &nodes,
            &snaps,
            Some(&health_pool),
            now,
        );
        let _ = reconcile_group_best_node_in_memory_with_runtime(
            &mut group,
            &nodes,
            &snaps,
            Some(&health_pool),
            now,
        );

        let next_name = group
            .active_node_id
            .as_deref()
            .and_then(|id| nodes.iter().find(|n| n.id == id))
            .map(|n| n.name.clone());
        db.upsert_multi_group(&group).map_err(|e| e.to_string())?;
        (existing_group, existing_prev, prev_name, next_name)
    };
    let prev_cfg_before_rename = state.snapshot_config();
    let mut cfg_rules_cascaded = false;
    if let Some(ref old_g) = prev_group {
        if old_g.name.trim() != group.name.trim() {
            let mut next_cfg = (*prev_cfg_before_rename).clone();
            let touched = catcloud_core::core_adapter::cascade_group_name_change_in_global_rules(
                &mut next_cfg,
                &old_g.name,
                Some(&group.name),
            );
            if touched > 0 {
                config::save(&state.paths, &next_cfg).map_err(|e| e.to_string())?;
                if let Ok(mut guard) = state.config.write() {
                    *guard = Arc::new(next_cfg);
                }
                cfg_rules_cascaded = true;
            }
        }
    }
    if let Some(outcome) = trigger_reload_if_running(&app, &state, false).await {
        if outcome.rejected {
            if let Ok(db) = state.storage.lock() {
                match prev_group {
                    Some(ref old_group) => {
                        let _ = db.upsert_multi_group(old_group);
                    }
                    None => {
                        let _ = db.delete_multi_group(&group.id);
                    }
                }
            }
            if cfg_rules_cascaded {
                let _ = config::save(&state.paths, &prev_cfg_before_rename);
                if let Ok(mut guard) = state.config.write() {
                    *guard = Arc::clone(&prev_cfg_before_rename);
                }
            }
            let cfg = state.snapshot_config();
            sync_tray_and_window_side_effects(&app, &state, &cfg);
            let detail = outcome
                .error
                .as_deref()
                .map(format_mihomo_error_for_user)
                .unwrap_or_else(|| "未知原因".to_string());
            return Err(format!(
                "保存路线分组「{}」失败，核心配置重载未通过：{detail}",
                group.name
            ));
        }
    }
    if group.active_node_id != prev_active_id && state.adapter.has_live_controller().await {
        if let Some(ref next_id) = group.active_node_id {
            let fallback = next_active_name.as_deref().unwrap_or(next_id.as_str());
            let target_proxy = state.resolve_compiled_proxy_name(next_id, fallback);
            let _ = state
                .adapter
                .select_group_proxy(&group.name, &target_proxy)
                .await;
        }
        if matches!(group.switch_mode, SwitchMode::ForceCloseOld)
            || prev_active_id
                .as_deref()
                .is_some_and(|pid| !group.member_node_ids.iter().any(|m| m == pid))
        {
            let prev_compiled = prev_active_id.as_deref().map(|pid| {
                let fb = prev_active_name.as_deref().unwrap_or("");
                state.resolve_compiled_proxy_name(pid, fb)
            });
            let prev_target = prev_compiled
                .as_deref()
                .filter(|s| !s.is_empty())
                .or(prev_active_name.as_deref());
            let _ = state
                .adapter
                .close_connections_for_group_or_node(Some(&group.name), prev_target)
                .await;
        }
    }
    let cfg = state.snapshot_config();
    sync_tray_and_window_side_effects(&app, &state, &cfg);
    emit_groups_updated(&app);
    Ok(group)
}


#[tauri::command]
pub async fn delete_multi_group(
    app: AppHandle,
    state: State<'_, AppState>,
    group_id: String,
) -> Result<bool, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    let prev_cfg = state.snapshot_config();
    let (prev_group, deleted, next_fallback_group_id) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let prev_group = db.get_multi_group(&group_id).map_err(|e| e.to_string())?;
        let deleted = db.delete_multi_group(&group_id).map_err(|e| e.to_string())?;
        let next_id = if deleted {
            db.list_multi_groups()
                .ok()
                .and_then(|v| v.into_iter().next())
                .map(|g| g.id)
        } else {
            None
        };
        (prev_group, deleted, next_id)
    };
    if deleted {
        let mut cfg = (*prev_cfg).clone();
        let active_changed = cfg.active_group_id.as_deref() == Some(group_id.as_str());
        if active_changed {
            cfg.active_group_id = next_fallback_group_id;
        }
        let cascaded_rules = prev_group.as_ref().map_or(0, |old_g| {
            catcloud_core::core_adapter::cascade_group_name_change_in_global_rules(
                &mut cfg,
                &old_g.name,
                None,
            )
        });
        let cfg_mutated = active_changed || cascaded_rules > 0;
        if cfg_mutated {
            config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
            if let Ok(mut guard) = state.config.write() {
                *guard = Arc::new(cfg.clone());
            }
        }
        if let Some(outcome) = trigger_reload_if_running(&app, &state, false).await {
            if outcome.rejected {
                if let Some(ref old_group) = prev_group {
                    if let Ok(db) = state.storage.lock() {
                        let _ = db.upsert_multi_group(old_group);
                    }
                }
                if cfg_mutated {
                    let _ = config::save(&state.paths, &prev_cfg);
                    if let Ok(mut guard) = state.config.write() {
                        *guard = Arc::clone(&prev_cfg);
                    }
                }
                sync_tray_and_window_side_effects(&app, &state, &prev_cfg);
                let detail = outcome
                    .error
                    .as_deref()
                    .map(format_mihomo_error_for_user)
                    .unwrap_or_else(|| "未知原因".to_string());
                return Err(format!("删除路线分组失败，核心配置重载未通过：{detail}"));
            }
        }
        if let Ok(mut pool) = state.node_health_pool.write() {
            pool.remove_group_cursor(&group_id);
        }
        let latest_cfg = state.snapshot_config();
        emit_config_updated(&app, &latest_cfg);
        emit_groups_updated(&app);
        sync_tray_and_window_side_effects(&app, &state, &latest_cfg);
    }
    Ok(deleted)
}


#[tauri::command]
pub async fn update_multi_group_members(
    app: AppHandle,
    state: State<'_, AppState>,
    group_id: String,
    member_node_ids: Vec<String>,
) -> Result<MultiGroup, String> {
    let (updated, prev_group, prev_active_id, prev_active_name, next_active_name) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let mut group = db
            .get_multi_group(&group_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("未找到指定路线分组（{group_id}）"))?;
        let prev_group = group.clone();
        let prev_active = group.active_node_id.clone();
        let nodes = db.list_nodes().map_err(|e| e.to_string())?;
        let node_ids: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
        let snaps = db
            .get_probe_snapshots_batch(&node_ids, group.primary_probe_id.as_deref())
            .unwrap_or_default();
        let prev_name = prev_active
            .as_deref()
            .and_then(|id| nodes.iter().find(|n| n.id == id))
            .map(|n| n.name.clone());

        group.member_node_ids = member_node_ids;
        let health_pool = state.snapshot_node_health_pool();
        let now = Instant::now();
        let _ = sanitize_group_active_node_with_runtime(
            &mut group,
            &nodes,
            &snaps,
            Some(&health_pool),
            now,
        );
        let _ = reconcile_group_best_node_in_memory_with_runtime(
            &mut group,
            &nodes,
            &snaps,
            Some(&health_pool),
            now,
        );

        let next_name = group
            .active_node_id
            .as_deref()
            .and_then(|id| nodes.iter().find(|n| n.id == id))
            .map(|n| n.name.clone());
        db.upsert_multi_group(&group).map_err(|e| e.to_string())?;
        (group, prev_group, prev_active, prev_name, next_name)
    };
    if let Some(outcome) = trigger_reload_if_running(&app, &state, false).await {
        if outcome.rejected {
            if let Ok(db) = state.storage.lock() {
                let _ = db.upsert_multi_group(&prev_group);
            }
            let cfg = state.snapshot_config();
            sync_tray_and_window_side_effects(&app, &state, &cfg);
            let detail = outcome
                .error
                .as_deref()
                .map(format_mihomo_error_for_user)
                .unwrap_or_else(|| "未知原因".to_string());
            return Err(format!(
                "更新路线分组「{}」成员失败，核心配置重载未通过：{detail}",
                updated.name
            ));
        }
    }
    if updated.active_node_id != prev_active_id && state.adapter.has_live_controller().await {
        if let Some(ref next_id) = updated.active_node_id {
            let fallback = next_active_name.as_deref().unwrap_or(next_id.as_str());
            let target_proxy = state.resolve_compiled_proxy_name(next_id, fallback);
            let _ = state
                .adapter
                .select_group_proxy(&updated.name, &target_proxy)
                .await;
        }
        let prev_compiled = prev_active_id.as_deref().map(|pid| {
            let fb = prev_active_name.as_deref().unwrap_or("");
            state.resolve_compiled_proxy_name(pid, fb)
        });
        let prev_target = prev_compiled
            .as_deref()
            .filter(|s| !s.is_empty())
            .or(prev_active_name.as_deref());
        let _ = state
            .adapter
            .close_connections_for_group_or_node(Some(&updated.name), prev_target)
            .await;
    }
    let cfg = state.snapshot_config();
    sync_tray_and_window_side_effects(&app, &state, &cfg);
    emit_groups_updated(&app);
    Ok(updated)
}


#[tauri::command]
pub fn validate_formula_expr(expr: String) -> Result<bool, String> {
    catcloud_core::strategy::formula::validate_formula(&expr)
        .map(|_| true)
        .map_err(|e| e.to_string())
}


#[tauri::command]
pub fn evaluate_multi_group(
    state: State<'_, AppState>,
    group_id: String,
) -> Result<catcloud_core::strategy::evaluator::GroupEvaluationReport, String> {
    let db = state.storage.lock().map_err(|e| e.to_string())?;
    let group = db
        .get_multi_group(&group_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("未找到指定路线分组（{group_id}）"))?;
    let nodes = db.list_nodes().map_err(|e| e.to_string())?;
    let ids: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
    let snaps = db
        .get_probe_snapshots_batch(&ids, group.primary_probe_id.as_deref())
        .map_err(|e| e.to_string())?;
    let health_pool = state.snapshot_node_health_pool();
    evaluate_group_candidates_with_runtime(&group, &nodes, &snaps, Some(&health_pool), Instant::now())
        .map_err(|e| e.to_string())
}

