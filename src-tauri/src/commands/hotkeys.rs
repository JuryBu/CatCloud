use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use catcloud_core::config;
use catcloud_core::core_adapter::ReloadLevel;
use catcloud_core::models::AppConfig;
use catcloud_core::models::RouteTargetMode;
use catcloud_core::process_guard::ConfigReloadAck;
use catcloud_core::process_guard::clear_config_reload_request_if_matching;
use catcloud_core::process_guard::read_config_reload_request;
use catcloud_core::process_guard::write_config_reload_ack;
use tauri::AppHandle;
use tauri::Manager;
use crate::lifecycle;
use crate::shortcuts;
use crate::shortcuts::ShortcutAction;
use crate::shortcuts::ShortcutBindings;

use crate::commands::core_lifecycle::apply_system_proxy_internal;
use crate::commands::core_lifecycle::set_tun_enabled_internal;
use crate::commands::core_lifecycle::start_core_internal;
use crate::commands::core_lifecycle::stop_core_locked;
use crate::commands::core_lifecycle::trigger_reload_if_running_with_options;
use crate::commands::groups_strategy::switch_next_best_internal;
use crate::commands::state::AppState;
use crate::commands::state::current_unix_ms;
use crate::commands::state::prune_node_health_pool_from_db;
use crate::commands::state::sync_autostart_if_changed;
use crate::commands::system_proxy::apply_system_proxy_if_still_enabled;
use crate::commands::system_proxy::clear_system_proxy_if_owned_with_hint;
use crate::commands::system_proxy::coordinate_global_preaccel_on_tun_transition;
use crate::commands::system_proxy::load_enabled_preaccel_relays;
use crate::commands::system_proxy::start_global_preaccel_engine;
use crate::commands::system_proxy::sync_running_global_preaccel_if_active;
use crate::commands::tray_runtime::effective_tun_enabled;
use crate::commands::tray_runtime::emit_config_updated;
use crate::commands::tray_runtime::emit_groups_updated;
use crate::commands::tray_runtime::emit_nodes_updated;
use crate::commands::tray_runtime::emit_relays_updated;
use crate::commands::tray_runtime::format_mihomo_error_for_user;
use crate::commands::tray_runtime::handle_tun_toggle_error;
use crate::commands::tray_runtime::has_enabled_nodes;
use crate::commands::tray_runtime::is_tun_privilege_ready;
use crate::commands::tray_runtime::sync_tray_and_window_side_effects;
use crate::commands::updater::handle_cross_process_portable_self_update;

fn shortcut_bindings_from_config(cfg: &AppConfig) -> ShortcutBindings {
    if !cfg.behavior.hotkeys.enabled {
        return ShortcutBindings {
            switch_next_best: None,
            toggle_capsule: None,
            toggle_main_window: None,
            toggle_system_proxy: None,
            toggle_tun: None,
        };
    }
    ShortcutBindings {
        switch_next_best: cfg.behavior.hotkeys.switch_next_best.clone(),
        toggle_capsule: cfg.behavior.hotkeys.toggle_capsule.clone(),
        toggle_main_window: cfg.behavior.hotkeys.show_main_window.clone(),
        toggle_system_proxy: cfg.behavior.hotkeys.toggle_system_proxy.clone(),
        toggle_tun: cfg.behavior.hotkeys.toggle_tun.clone(),
    }
}


pub fn apply_configured_shortcuts(
    app: &AppHandle,
    state: &AppState,
    cfg: &AppConfig,
    force: bool,
) {
    let bindings = shortcut_bindings_from_config(cfg);
    if !force {
        if let Ok(guard) = state.last_hotkey_bindings.lock() {
            if guard.as_ref() == Some(&bindings) {
                return;
            }
        }
    }
    let _ = shortcuts::register_shortcuts(app, &bindings, |app_h, action| {
        let app_async = app_h.clone();
        match action {
            ShortcutAction::ToggleCapsule => lifecycle::toggle_capsule_window(app_h),
            ShortcutAction::ToggleMainWindow => {
                if lifecycle::is_main_window_visible(app_h) {
                    lifecycle::hide_or_enter_windowless_main_window(app_h);
                } else {
                    lifecycle::show_or_rebuild_main_window(app_h);
                }
            }
            ShortcutAction::ToggleSystemProxy => {
                tauri::async_runtime::spawn(async move {
                    if let Some(st) = app_async.try_state::<AppState>() {
                        let next = !st.snapshot_config().system_proxy.enabled;
                        let _ = apply_system_proxy_internal(&app_async, &st, next).await;
                    }
                });
            }
            ShortcutAction::ToggleTun => {
                tauri::async_runtime::spawn(async move {
                    if let Some(st) = app_async.try_state::<AppState>() {
                        let cfg = st.snapshot_config();
                        let next = !effective_tun_enabled(&st, &cfg);
                        if let Err(err) = set_tun_enabled_internal(&app_async, &st, next).await {
                            handle_tun_toggle_error(&app_async, &err);
                        }
                    }
                });
            }
            ShortcutAction::SwitchNextBestNode => {
                tauri::async_runtime::spawn(async move {
                    if let Some(st) = app_async.try_state::<AppState>() {
                        let cfg = st.snapshot_config();
                        let target_group = if cfg.route_mode == RouteTargetMode::Single {
                            String::new()
                        } else {
                            cfg.active_group_id.clone().unwrap_or_else(|| "default".to_string())
                        };
                        let _ = switch_next_best_internal(&app_async, &st, target_group).await;
                    }
                });
            }
        }
    });
    if let Ok(mut guard) = state.last_hotkey_bindings.lock() {
        *guard = Some(bindings);
    }
}


pub fn sync_app_side_effects(app: &AppHandle, state: &AppState, cfg: &AppConfig) {
    apply_configured_shortcuts(app, state, cfg, false);
    sync_tray_and_window_side_effects(app, state, cfg);
}


/// Pure in-memory reconciliation applied to disk configs during live hot-reload (without writing
/// back to disk): normalizes unified preaccel flags, clears dangling `active_relay_id`, and forces
/// `preaccel.enabled = false` whenever zero enabled domestic relays exist.
pub(in crate::commands) fn reconcile_disk_hot_reload_config(
    cfg: &mut AppConfig,
    enabled_relay_ids: &HashSet<String>,
) -> bool {
    let before_enabled = cfg.preaccel.enabled;
    let before_global = cfg.preaccel.global_bypass_enabled;
    cfg.preaccel.reconcile_unified_enabled();
    let mut changed =
        cfg.preaccel.enabled != before_enabled || cfg.preaccel.global_bypass_enabled != before_global;
    if config::reconcile_dangling_active_relay(cfg, enabled_relay_ids) {
        changed = true;
    }
    if enabled_relay_ids.is_empty()
        && (cfg.preaccel.enabled || cfg.preaccel.global_bypass_enabled)
    {
        cfg.preaccel.sync_unified_enabled(false);
        changed = true;
    }
    changed
}


const CONFIG_RELOAD_REQ_TTL_MS: u64 = 15_000;


pub(in crate::commands) fn is_config_reload_request_expired(created_at_ms: u64, now_ms: u64) -> bool {
    now_ms.saturating_sub(created_at_ms) > CONFIG_RELOAD_REQ_TTL_MS
}


/// Cross-process zero-disruption live hot-reload entry point triggered by `SingleInstanceGuard`
/// whenever CLI, share import, or sync updates disk config / SQLite state while desktop is running.
pub async fn apply_disk_config_hot_reload_internal(
    app: &AppHandle,
    state: &AppState,
) -> Result<ConfigReloadAck, String> {
    let cfg_guard = state.config_transition_lock.lock().await;

    let now_ms = current_unix_ms();
    let req_opt = read_config_reload_request(&state.paths.root_data_dir);
    let (req_id, allow_l3_restart, apply_staged_update, silent_relaunch) = match req_opt {
        Some(req) => {
            let trimmed_id = req.req_id.trim().to_string();
            if is_config_reload_request_expired(req.created_at_ms, now_ms) {
                if !trimmed_id.is_empty() {
                    let _ = clear_config_reload_request_if_matching(
                        &state.paths.root_data_dir,
                        &trimmed_id,
                    );
                }
                tracing::warn!(
                    req_id = %trimmed_id,
                    created_at_ms = req.created_at_ms,
                    now_ms,
                    "忽略过期的跨进程热重载请求（超过 15000ms TTL），已清理残留请求并强制 allow_l3_restart=false"
                );
                (String::new(), false, false, false)
            } else {
                (
                    trimmed_id,
                    req.allow_l3_restart,
                    req.apply_staged_update,
                    req.silent_relaunch,
                )
            }
        }
        None => (String::new(), false, false, false),
    };

    let persist_ack = |ack: &ConfigReloadAck| {
        if !ack.req_id.is_empty() {
            if let Err(err) = write_config_reload_ack(&state.paths.root_data_dir, ack) {
                tracing::warn!("写入跨进程热重载回执失败：{err}");
            }
        }
    };

    if state.shutting_down.load(Ordering::SeqCst) {
        let ack = ConfigReloadAck {
            req_id,
            applied: false,
            rejected: true,
            level: None,
            error: Some("shutting_down".to_string()),
            completed_at_ms: current_unix_ms(),
        };
        persist_ack(&ack);
        return Ok(ack);
    }

    if apply_staged_update {
        drop(cfg_guard);
        return handle_cross_process_portable_self_update(app, state, req_id, silent_relaunch)
            .await;
    }

    let mut next_cfg = match config::load_or_default(&state.paths) {
        Ok(cfg) => cfg,
        Err(err) => {
            let msg = format!("读取或校验磁盘配置文件失败，已保留原运行配置：{err}");
            state.log_app_event("error", "热重载", &msg);
            let ack = ConfigReloadAck {
                req_id,
                applied: false,
                rejected: true,
                level: None,
                error: Some(msg),
                completed_at_ms: current_unix_ms(),
            };
            persist_ack(&ack);
            return Ok(ack);
        }
    };

    let old_cfg = state.snapshot_config();
    let enabled_relay_ids: HashSet<String> = state
        .storage
        .lock()
        .ok()
        .and_then(|db| db.list_preaccel_relays(true).ok())
        .unwrap_or_default()
        .into_iter()
        .map(|r| r.id)
        .collect();
    let _ = reconcile_disk_hot_reload_config(&mut next_cfg, &enabled_relay_ids);

    let tun_ready = is_tun_privilege_ready(state);
    let was_core_running =
        state.snapshot_runtime().running || state.adapter.has_live_controller().await;
    let old_eff_tun = old_cfg.tun.enabled && tun_ready;
    let was_tun_active = was_core_running && old_eff_tun;
    let next_eff_tun = next_cfg.tun.enabled && tun_ready;
    let wants_core_running = next_cfg.system_proxy.enabled || next_eff_tun;
    let has_nodes = has_enabled_nodes(state).unwrap_or(false);

    let ack_applied: bool;
    let ack_level: Option<String>;

    if was_core_running {
        if !wants_core_running {
            if was_tun_active && state.adapter.has_live_controller().await {
                let _ = state.adapter.disable_tun_gracefully().await;
            }
            if old_cfg.system_proxy.enabled {
                let _ = clear_system_proxy_if_owned_with_hint(state, true);
            }
            if let Ok(mut guard) = state.config.write() {
                *guard = Arc::new(next_cfg.clone());
            }
            let stop_res = {
                let _lifecycle_guard = state.core_lifecycle_lock.lock().await;
                stop_core_locked(app, state, !next_cfg.tun.enabled).await
            };
            if let Err(err) = stop_res {
                if let Ok(mut guard) = state.config.write() {
                    *guard = Arc::clone(&old_cfg);
                }
                let msg = format!("外部配置关闭代理但停止核心失败：{err}");
                state.log_app_event("error", "热重载", &msg);
                let ack = ConfigReloadAck {
                    req_id,
                    applied: false,
                    rejected: true,
                    level: Some("core_stop".to_string()),
                    error: Some(msg),
                    completed_at_ms: current_unix_ms(),
                };
                persist_ack(&ack);
                return Ok(ack);
            }
            state.bump_config_generation();
            ack_applied = true;
            ack_level = Some("core_stopped".to_string());
        } else {
            let mut pre_suspended_global_preaccel = false;
            if allow_l3_restart {
                if !old_eff_tun && next_eff_tun {
                    // Suspend standalone WinDivert 443 tunnel BEFORE L3 core restart brings up TUN
                    // so WinDivert and Wintun never run concurrently for even a transient window.
                    if state.global_preaccel.status().running {
                        let active_relays: Vec<String> = load_enabled_preaccel_relays(state)
                            .unwrap_or_default()
                            .into_iter()
                            .map(|r| r.name)
                            .collect();
                        let _ = state.global_preaccel.suspend_for_tun(active_relays).await;
                        pre_suspended_global_preaccel = true;
                    }
                } else if old_eff_tun
                    && !next_eff_tun
                    && state.adapter.has_live_controller().await
                {
                    // Gracefully release Wintun virtual NIC & OS routes BEFORE L3 restart disables TUN.
                    let _ = state.adapter.disable_tun_gracefully().await;
                }
            }

            let reload_outcome =
                trigger_reload_if_running_with_options(app, state, false, allow_l3_restart).await;
            match reload_outcome {
                Some(outcome) if outcome.rejected => {
                    if pre_suspended_global_preaccel && !state.shutting_down.load(Ordering::SeqCst)
                    {
                        if old_cfg.preaccel.enabled && !enabled_relay_ids.is_empty() {
                            if let Err(err) = start_global_preaccel_engine(state, &old_cfg).await {
                                state.log_app_event(
                                    "warning",
                                    "国内提速",
                                    &format!(
                                        "磁盘热重载开启虚拟网卡被拒绝后恢复独立底层国内提速失败：{err}"
                                    ),
                                );
                            }
                        } else if state.global_preaccel.status().mode == "suspended_for_tun" {
                            let _ = state.global_preaccel.stop().await;
                        }
                    }
                    let detail = if outcome.level == ReloadLevel::L3CoreRestart && !allow_l3_restart {
                        "检测到端口、虚拟网卡或内核等需重启项变更；为保护现役长连接已默认拒绝外部 L3 重启，原运行配置未受影响".to_string()
                    } else {
                        outcome
                            .error
                            .as_deref()
                            .map(format_mihomo_error_for_user)
                            .unwrap_or_else(|| "磁盘配置预检未通过，已保留原运行配置".to_string())
                    };
                    state.log_app_event("warning", "热重载", &detail);
                    let ack = ConfigReloadAck {
                        req_id,
                        applied: false,
                        rejected: true,
                        level: Some(outcome.level.as_str().to_string()),
                        error: Some(detail),
                        completed_at_ms: current_unix_ms(),
                    };
                    persist_ack(&ack);
                    return Ok(ack);
                }
                other => {
                    if let Ok(mut guard) = state.config.write() {
                        *guard = Arc::new(next_cfg.clone());
                    }
                    state.bump_config_generation();
                    if old_cfg.log_level != next_cfg.log_level {
                        let cur_rt = state.snapshot_runtime();
                        if cur_rt.running {
                            let cur_secret = state.adapter.controller_secret().await;
                            state.attach_streams(
                                &cur_rt.controller_host,
                                cur_rt.controller_port,
                                &cur_secret,
                                next_cfg.log_level.clone(),
                            );
                        }
                    }
                    let sys_proxy_changed = old_cfg.system_proxy.enabled
                        != next_cfg.system_proxy.enabled
                        || (next_cfg.system_proxy.enabled
                            && (old_cfg.system_proxy != next_cfg.system_proxy
                                || old_cfg.mixed_port != next_cfg.mixed_port));
                    if sys_proxy_changed {
                        if next_cfg.system_proxy.enabled {
                            let effective_port = {
                                let rt = state.snapshot_runtime();
                                if rt.running {
                                    rt.mixed_port
                                } else {
                                    next_cfg.mixed_port
                                }
                            };
                            if let Err(err) =
                                apply_system_proxy_if_still_enabled(state, effective_port)
                            {
                                state.log_app_event(
                                    "warning",
                                    "热重载",
                                    &format!("外部热重载同步操作系统代理失败：{err}"),
                                );
                            }
                        } else if let Err(err) = clear_system_proxy_if_owned_with_hint(
                            state,
                            old_cfg.system_proxy.enabled,
                        ) {
                            state.log_app_event(
                                "warning",
                                "热重载",
                                &format!("外部热重载清除操作系统代理失败：{err}"),
                            );
                        }
                    }

                    let now_core_running = state.snapshot_runtime().running
                        || state.adapter.has_live_controller().await;
                    let now_tun_active =
                        now_core_running && effective_tun_enabled(state, &next_cfg);
                    if pre_suspended_global_preaccel && now_tun_active && next_cfg.preaccel.enabled
                    {
                        state.log_app_event(
                            "info",
                            "国内提速",
                            "磁盘热重载已启用虚拟网卡接管全机流量，重启前已暂挂独立底层 443 隧道以避免双跑 443，改由主核心统一提供国内提速",
                        );
                    }
                    coordinate_global_preaccel_on_tun_transition(
                        app,
                        state,
                        &next_cfg,
                        was_tun_active,
                        now_tun_active,
                        "磁盘热重载",
                    )
                    .await;

                    ack_applied = true;
                    ack_level = Some(
                        other
                            .map(|o| o.level.as_str().to_string())
                            .unwrap_or_else(|| "state_synced".to_string()),
                    );
                }
            }
        }
    } else {
        if let Ok(mut guard) = state.config.write() {
            *guard = Arc::new(next_cfg.clone());
        }
        if wants_core_running && has_nodes {
            if let Err(err) = start_core_internal(app, state).await {
                if let Ok(mut guard) = state.config.write() {
                    *guard = Arc::clone(&old_cfg);
                }
                sync_app_side_effects(app, state, &old_cfg);
                let msg = format!("外部配置开启代理但启动核心失败：{err}");
                state.log_app_event("error", "热重载", &msg);
                let ack = ConfigReloadAck {
                    req_id,
                    applied: false,
                    rejected: true,
                    level: Some("core_start".to_string()),
                    error: Some(msg),
                    completed_at_ms: current_unix_ms(),
                };
                persist_ack(&ack);
                return Ok(ack);
            }
            state.bump_config_generation();
            ack_applied = true;
            ack_level = Some("core_started".to_string());
        } else {
            if old_cfg.system_proxy.enabled && !next_cfg.system_proxy.enabled {
                let _ = clear_system_proxy_if_owned_with_hint(state, true);
            }
            state.bump_config_generation();
            ack_applied = true;
            ack_level = Some("state_synced".to_string());
        }
    }

    // Clear power-off takeover memory ONLY after a committed hot-reload explicitly disables TUN.
    if ack_applied && old_cfg.tun.enabled && !next_cfg.tun.enabled {
        state.clear_power_off_takeover_memory();
    }

    // Synchronize standalone domestic pre-acceleration 443 tunnel (never spawning WinDivert at 0 relays).
    let final_cfg = state.snapshot_config();
    let now_core_running =
        state.snapshot_runtime().running || state.adapter.has_live_controller().await;
    let now_tun_active = now_core_running && effective_tun_enabled(state, &final_cfg);
    if !final_cfg.preaccel.enabled || enabled_relay_ids.is_empty() {
        if state.global_preaccel.status().running
            || state.global_preaccel.status().mode == "suspended_for_tun"
        {
            let _ = state.global_preaccel.stop().await;
        }
    } else if !now_tun_active {
        if state.global_preaccel.status().running {
            sync_running_global_preaccel_if_active(state, &final_cfg).await;
        } else if let Err(err) = start_global_preaccel_engine(state, &final_cfg).await {
            state.log_app_event(
                "warning",
                "国内提速",
                &format!("磁盘热重载后拉起独立底层国内提速失败：{err}"),
            );
        }
    }

    prune_node_health_pool_from_db(state);
    sync_autostart_if_changed(&old_cfg, &final_cfg);
    sync_app_side_effects(app, state, &final_cfg);
    emit_config_updated(app, &final_cfg);
    emit_groups_updated(app);
    emit_relays_updated(app);
    emit_nodes_updated(app);
    state.log_app_event(
        "info",
        "热重载",
        &format!(
            "已接收外部动态配置热切并同步界面（级别：{}）",
            ack_level.as_deref().unwrap_or("synced")
        ),
    );

    let ack = ConfigReloadAck {
        req_id,
        applied: ack_applied,
        rejected: false,
        level: ack_level,
        error: None,
        completed_at_ms: current_unix_ms(),
    };
    persist_ack(&ack);
    Ok(ack)
}

