use std::collections::HashSet;
#[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
use std::sync::atomic::Ordering;
use std::sync::Arc;
use catcloud_core::config;
use catcloud_core::models::AppConfig;
use catcloud_core::models::GlobalPreAccelScope;
use catcloud_core::models::PreAccelDispatchStrategy;
use catcloud_core::models::PreAccelRelay;
use catcloud_core::platform::default_platform;
use catcloud_core::preaccel::global_tunnel::GlobalPreAccelStatus;
#[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
use catcloud_core::preaccel::global_tunnel::build_default_windivert_proxy_candidates;
#[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
use catcloud_core::preaccel::global_tunnel::download_and_install_windivert_with_fallbacks;
#[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
use catcloud_core::preaccel::global_tunnel::locate_windivert_files;
use tauri::AppHandle;
use tauri::Emitter;
use tauri::State;

use crate::commands::core_lifecycle::trigger_reload_if_running;
use crate::commands::state::AppState;
#[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
use crate::commands::state::AtomicFlagResetGuard;
use crate::commands::state::EVENT_CONFIG_UPDATED;
use crate::commands::state::NO_ENABLED_RELAY_ERROR;
use crate::commands::state::UiAppConfigDto;
use crate::commands::system_proxy::collect_excluded_pids_for_global_preaccel;
use crate::commands::system_proxy::load_enabled_preaccel_relays;
use crate::commands::system_proxy::log_global_preaccel_verify_status;
use crate::commands::system_proxy::maybe_spawn_auto_windivert_download;
#[cfg(target_os = "windows")]
use crate::commands::system_proxy::relaunch_self_with_elevation_flags;
use crate::commands::system_proxy::start_global_preaccel_engine;
use crate::commands::system_proxy::sync_running_global_preaccel_if_active;
use crate::commands::tray_runtime::effective_tun_enabled;
use crate::commands::tray_runtime::emit_config_updated;
use crate::commands::tray_runtime::emit_preaccel_verify_override_snapshots;
use crate::commands::tray_runtime::emit_relays_updated;
use crate::commands::tray_runtime::emit_runtime_snapshot;
use crate::commands::tray_runtime::format_mihomo_error_for_user;
use crate::commands::tray_runtime::is_proxy_takeover_active;
use crate::commands::tray_runtime::is_tun_privilege_ready;
use crate::commands::tray_runtime::refresh_tray;
use crate::commands::tray_runtime::sync_tray_and_window_side_effects;

#[tauri::command]
pub fn list_preaccel_relays(state: State<'_, AppState>) -> Result<Vec<PreAccelRelay>, String> {
    let db = state.storage.lock().map_err(|e| e.to_string())?;
    db.list_preaccel_relays(false).map_err(|e| e.to_string())
}


pub(in crate::commands) fn parse_global_preaccel_scope(raw: &str) -> Result<GlobalPreAccelScope, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "proxy_apps_only" => Ok(GlobalPreAccelScope::ProxyAppsOnly),
        "all_non_443_tcp" | "all_non443_tcp" => Ok(GlobalPreAccelScope::AllNon443Tcp),
        other => Err(format!(
            "未知的全局底层预代理范围 `{other}`，仅支持 `proxy_apps_only` 或 `all_non_443_tcp`"
        )),
    }
}


pub(in crate::commands) fn normalize_global_target_processes(processes: Vec<String>) -> Vec<String> {
    let mut out = Vec::with_capacity(processes.len());
    let mut seen: HashSet<String> = HashSet::new();
    for raw in processes {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if seen.insert(lower) {
            out.push(trimmed.to_string());
        }
    }
    out
}


/// Reconcile active relay and enforce zero-relay auto-convergence after mutating `preaccel_relays`:
/// returns `(cfg_changed, auto_disabled_preaccel)`.
pub(in crate::commands) fn converge_preaccel_after_relay_mutation(
    cfg: &mut AppConfig,
    enabled_relay_ids: &HashSet<String>,
) -> (bool, bool) {
    let mut cfg_changed = config::reconcile_dangling_active_relay(cfg, enabled_relay_ids);
    let auto_disabled_preaccel = enabled_relay_ids.is_empty()
        && (cfg.preaccel.enabled || cfg.preaccel.global_bypass_enabled);
    if auto_disabled_preaccel {
        cfg.preaccel.sync_unified_enabled(false);
        cfg_changed = true;
    }
    (cfg_changed, auto_disabled_preaccel)
}


#[tauri::command]
pub async fn upsert_preaccel_relay(
    app: AppHandle,
    state: State<'_, AppState>,
    mut relay: PreAccelRelay,
) -> Result<PreAccelRelay, String> {
    if relay.id.trim().is_empty() {
        relay.id = format!("relay-{}", uuid::Uuid::new_v4().simple());
    }
    catcloud_core::preaccel::schema::validate_relay_strict(&relay).map_err(|e| e.to_string())?;
    let _cfg_guard = state.config_transition_lock.lock().await;
    let prev_cfg = state.snapshot_config();
    let (prev_relay, enabled_relay_ids) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let prev = db
            .get_preaccel_relay(&relay.id)
            .map_err(|e| e.to_string())?;
        db.upsert_preaccel_relay(&relay).map_err(|e| e.to_string())?;
        let enabled_ids: HashSet<String> = db
            .list_preaccel_relays(true)
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|r| r.id)
            .collect();
        (prev, enabled_ids)
    };
    let mut cfg = (*prev_cfg).clone();
    let (cfg_changed, auto_disabled_preaccel) =
        converge_preaccel_after_relay_mutation(&mut cfg, &enabled_relay_ids);
    if cfg_changed {
        config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
        if let Ok(mut guard) = state.config.write() {
            *guard = Arc::new(cfg.clone());
        }
    }
    if let Some(outcome) = trigger_reload_if_running(&app, &state, false).await {
        if outcome.rejected {
            if let Ok(db) = state.storage.lock() {
                match prev_relay {
                    Some(ref old_relay) => {
                        let _ = db.upsert_preaccel_relay(old_relay);
                    }
                    None => {
                        let _ = db.delete_preaccel_relay(&relay.id);
                    }
                }
            }
            if cfg_changed {
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
            return Err(format!(
                "保存国内中转「{}」失败，核心配置重载未通过：{detail}",
                relay.name
            ));
        }
    }
    let cfg = state.snapshot_config();
    if auto_disabled_preaccel {
        if state.global_preaccel.status().running
            || state.global_preaccel.status().mode == "suspended_for_tun"
        {
            let _ = state.global_preaccel.stop().await;
        }
        state.log_app_event(
            "info",
            "国内提速",
            "已无已启用的国内提速线路，已自动关闭国内提速开关并停止独立 443 隧道",
        );
    } else {
        sync_running_global_preaccel_if_active(&state, &cfg).await;
    }
    sync_tray_and_window_side_effects(&app, &state, &cfg);
    emit_config_updated(&app, &cfg);
    emit_relays_updated(&app);
    Ok(relay)
}


#[tauri::command]
pub async fn delete_preaccel_relay(
    app: AppHandle,
    state: State<'_, AppState>,
    relay_id: String,
) -> Result<bool, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    let prev_cfg = state.snapshot_config();
    let (prev_relay, deleted, enabled_relay_ids) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let prev = db
            .get_preaccel_relay(&relay_id)
            .map_err(|e| e.to_string())?;
        let deleted = db
            .delete_preaccel_relay(&relay_id)
            .map_err(|e| e.to_string())?;
        let enabled_ids: HashSet<String> = db
            .list_preaccel_relays(true)
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|r| r.id)
            .collect();
        (prev, deleted, enabled_ids)
    };
    if deleted {
        let mut cfg = (*prev_cfg).clone();
        let (cfg_changed, auto_disabled_preaccel) =
            converge_preaccel_after_relay_mutation(&mut cfg, &enabled_relay_ids);
        if cfg_changed {
            config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
            if let Ok(mut guard) = state.config.write() {
                *guard = Arc::new(cfg.clone());
            }
        }
        if let Some(outcome) = trigger_reload_if_running(&app, &state, false).await {
            if outcome.rejected {
                if let Some(ref old_relay) = prev_relay {
                    if let Ok(db) = state.storage.lock() {
                        let _ = db.upsert_preaccel_relay(old_relay);
                    }
                }
                if cfg_changed {
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
                return Err(format!("删除国内中转失败，核心配置重载未通过：{detail}"));
            }
        }
        let cfg = state.snapshot_config();
        if auto_disabled_preaccel {
            if state.global_preaccel.status().running
                || state.global_preaccel.status().mode == "suspended_for_tun"
            {
                let _ = state.global_preaccel.stop().await;
            }
            state.log_app_event(
                "info",
                "国内提速",
                "删除中转后已无已启用的国内提速线路，已自动关闭国内提速开关并停止独立 443 隧道",
            );
        } else {
            sync_running_global_preaccel_if_active(&state, &cfg).await;
        }
        sync_tray_and_window_side_effects(&app, &state, &cfg);
        emit_config_updated(&app, &cfg);
        emit_relays_updated(&app);
    }
    Ok(deleted)
}


/// Single authoritative entry point for the app-wide unified "国内提速" master switch.
/// Keeps `preaccel.enabled` and `preaccel.global_bypass_enabled` strictly synchronized, reloads
/// the running main core when active, coordinates standalone 443 / WinDivert acceleration, and
/// automatically downloads + hot-upgrades WinDivert in the background on Windows x64 when missing.
pub async fn toggle_preaccel_internal(
    app: &AppHandle,
    state: &AppState,
    enabled: bool,
) -> Result<bool, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    let old_cfg = state.snapshot_config();
    let old_preaccel_enabled = old_cfg.preaccel.enabled;
    let old_preaccel_global = old_cfg.preaccel.global_bypass_enabled;
    let mut cfg = (*old_cfg).clone();
    let core_running =
        state.snapshot_runtime().running || state.adapter.has_live_controller().await;
    let tun_ready = is_tun_privilege_ready(state);
    let proxy_active = is_proxy_takeover_active(core_running, &cfg, tun_ready);
    let tun_active = core_running && cfg.tun.enabled && tun_ready;

    if enabled {
        // Hard zero-relay gate: NEVER persist `preaccel.enabled = true` or spawn WinDivert
        // when no enabled domestic relay exists in SQLite.
        let enabled_relays = load_enabled_preaccel_relays(state)?;
        if enabled_relays.is_empty() {
            if cfg.preaccel.enabled || cfg.preaccel.global_bypass_enabled {
                cfg.preaccel.sync_unified_enabled(false);
                let _ = config::save(&state.paths, &cfg);
                if let Ok(mut guard) = state.config.write() {
                    *guard = Arc::new(cfg.clone());
                }
                sync_tray_and_window_side_effects(app, state, &cfg);
                emit_config_updated(app, &cfg);
            }
            state.log_app_event(
                "warning",
                "国内提速",
                "尝试开启国内提速但尚未添加已启用的国内提速线路，已拒绝开启",
            );
            return Err(NO_ENABLED_RELAY_ERROR.to_string());
        }

        cfg.preaccel.sync_unified_enabled(true);
        config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
        if let Ok(mut guard) = state.config.write() {
            *guard = Arc::new(cfg.clone());
        }

        // 1. If main proxy core is running, reload it to compile in-core 443 pre-acceleration.
        if core_running {
            let _ = trigger_reload_if_running(app, state, false).await;
        }

        // 2. When TUN is not already taking over all host traffic, ensure the standalone
        //    lightweight 443 engine is running (WinDivert excludes CatCloud's full PID tree
        //    so running alongside system-proxy mode has zero self-loop).
        if !tun_active {
            #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
            let wd_present =
                locate_windivert_files(&state.paths, cfg.preaccel.windivert_dir.as_deref())
                    .is_some();
            #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
            let is_elevated = default_platform().capabilities().is_elevated;

            let cur_global = state.snapshot_global_preaccel();
            let engine_res: Result<GlobalPreAccelStatus, String> = if cur_global.running {
                #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
                {
                    if wd_present && is_elevated && !cur_global.is_windivert_active {
                        let excluded_pids = collect_excluded_pids_for_global_preaccel(state);
                        state
                            .global_preaccel
                            .upgrade_to_windivert_in_place(&cfg, &enabled_relays, &excluded_pids)
                            .await
                            .map_err(|e| e.to_string())
                    } else {
                        if wd_present && !is_elevated {
                            state.global_preaccel.set_install_state("need_elevation");
                        }
                        Ok(state.snapshot_global_preaccel())
                    }
                }
                #[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
                {
                    Ok(cur_global)
                }
            } else {
                start_global_preaccel_engine(state, &cfg).await
            };

            match engine_res {
                Ok(global_st) => {
                    let detail = if global_st.is_windivert_active {
                        if proxy_active {
                            "已开启国内提速（猫猫代理 + WinDivert 底层透明加速同时运行）".to_string()
                        } else {
                            "已开启国内提速（WinDivert 底层透明加速运行中）".to_string()
                        }
                    } else if proxy_active {
                        "已开启国内提速（主代理核心已生效，独立通道待命中）".to_string()
                    } else if global_st.install_state == "need_elevation" {
                        "已开启国内提速（本地 443 通道待命，需管理员权限启用底层透明加速）"
                            .to_string()
                    } else if matches!(
                        global_st.install_state.as_str(),
                        "downloading" | "verifying"
                    ) {
                        "已开启国内提速（本地 443 通道已就绪，正在后台自动准备提速组件）"
                            .to_string()
                    } else {
                        match global_st.socks_port {
                            Some(port) => format!(
                                "已开启国内提速并启动本地独立 443 通道（127.0.0.1:{port}）"
                            ),
                            None => "已开启国内提速并启动本地独立 443 通道".to_string(),
                        }
                    };
                    state.log_app_event("info", "国内提速", &detail);
                }
                Err(err) => {
                    if proxy_active {
                        state.log_app_event(
                            "warning",
                            "国内提速",
                            &format!(
                                "猫猫代理内 443 提速已开启，但伴随独立底层通道启动失败：{err}"
                            ),
                        );
                    } else {
                        let mut rollback = state.clone_config();
                        rollback.preaccel.enabled = old_preaccel_enabled;
                        rollback.preaccel.global_bypass_enabled = old_preaccel_global;
                        rollback.preaccel.reconcile_unified_enabled();
                        let _ = config::save(&state.paths, &rollback);
                        if let Ok(mut guard) = state.config.write() {
                            *guard = Arc::new(rollback.clone());
                        }
                        state.log_app_event(
                            "error",
                            "国内提速",
                            &format!("启动独立底层国内提速失败：{err}"),
                        );
                        sync_tray_and_window_side_effects(app, state, &rollback);
                        let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&rollback));
                        return Err(err);
                    }
                }
            }

            #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
            {
                if !wd_present {
                    maybe_spawn_auto_windivert_download(app, state, &cfg);
                } else if !is_elevated {
                    state.global_preaccel.set_install_state("need_elevation");
                }
            }
        } else {
            let active_relays: Vec<String> = load_enabled_preaccel_relays(state)
                .unwrap_or_default()
                .into_iter()
                .map(|r| r.name)
                .collect();
            let _ = state.global_preaccel.suspend_for_tun(active_relays).await;
            state.log_app_event("info", "国内提速", "已开启国内 443 提速（虚拟网卡主核心统一生效）");
            maybe_spawn_auto_windivert_download(app, state, &cfg);
        }
    } else {
        cfg.preaccel.sync_unified_enabled(false);
        config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
        if let Ok(mut guard) = state.config.write() {
            *guard = Arc::new(cfg.clone());
        }
        if state.global_preaccel.status().running
            || state.global_preaccel.status().mode == "suspended_for_tun"
        {
            let _ = state.global_preaccel.stop().await;
        }
        if core_running {
            let _ = trigger_reload_if_running(app, state, false).await;
        }
        state.log_app_event("info", "国内提速", "已关闭国内 443 提速");
    }

    sync_tray_and_window_side_effects(app, state, &cfg);
    let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&cfg));
    Ok(enabled)
}


#[tauri::command]
pub async fn toggle_preaccel(
    app: AppHandle,
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<bool, String> {
    toggle_preaccel_internal(&app, &state, enabled).await
}


#[tauri::command]
pub fn get_global_preaccel_status(
    state: State<'_, AppState>,
) -> Result<GlobalPreAccelStatus, String> {
    Ok(state.snapshot_global_preaccel())
}


/// Compatibility entry point delegating strictly to the single unified `toggle_preaccel_internal`.
pub async fn toggle_global_preaccel_internal(
    app: &AppHandle,
    state: &AppState,
    enabled: bool,
) -> Result<GlobalPreAccelStatus, String> {
    toggle_preaccel_internal(app, state, enabled).await?;
    Ok(state.snapshot_global_preaccel())
}


#[tauri::command]
pub async fn toggle_global_preaccel(
    app: AppHandle,
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<GlobalPreAccelStatus, String> {
    toggle_global_preaccel_internal(&app, &state, enabled).await
}


#[tauri::command]
pub async fn update_global_preaccel_settings(
    app: AppHandle,
    state: State<'_, AppState>,
    scope: String,
    target_processes: Vec<String>,
    windivert_dir: Option<String>,
) -> Result<GlobalPreAccelStatus, String> {
    let parsed_scope = parse_global_preaccel_scope(&scope)?;
    let normalized_processes = normalize_global_target_processes(target_processes);
    let normalized_dir = windivert_dir
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let _cfg_guard = state.config_transition_lock.lock().await;
    let mut cfg = state.clone_config();
    cfg.preaccel.global_scope = parsed_scope;
    cfg.preaccel.global_target_processes = normalized_processes;
    cfg.preaccel.windivert_dir = normalized_dir;

    config::save(&state.paths, &cfg).map_err(|e| format!("保存底层全局提速设置失败：{e}"))?;
    if let Ok(mut guard) = state.config.write() {
        *guard = Arc::new(cfg.clone());
    }

    let was_running = state.global_preaccel.status().running;
    let core_running =
        state.snapshot_runtime().running || state.adapter.has_live_controller().await;
    let tun_active = core_running && effective_tun_enabled(&state, &cfg);
    let status = if was_running && cfg.preaccel.enabled && !tun_active {
        let relays = load_enabled_preaccel_relays(&state)?;
        if relays.is_empty() {
            state.snapshot_global_preaccel()
        } else {
            let excluded_pids = collect_excluded_pids_for_global_preaccel(&state);
            match state
                .global_preaccel
                .restart_windivert_if_running(&cfg, &relays, &excluded_pids)
                .await
            {
                Ok(st) => {
                    log_global_preaccel_verify_status(&state, "底层提速设置热重建", &st);
                    st
                }
                Err(err) => {
                    state.log_app_event(
                        "warning",
                        "国内提速",
                        &format!("更新底层全局提速设置后热重建引擎失败：{err}"),
                    );
                    sync_tray_and_window_side_effects(&app, &state, &cfg);
                    let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&cfg));
                    return Err(err.to_string());
                }
            }
        }
    } else {
        state.snapshot_global_preaccel()
    };

    state.log_app_event(
        "info",
        "国内提速",
        &format!(
            "已更新底层全局提速设置（范围：{}，目标进程 {} 个）",
            cfg.preaccel.global_scope.as_str(),
            cfg.preaccel.global_target_processes.len()
        ),
    );
    sync_tray_and_window_side_effects(&app, &state, &cfg);
    let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&cfg));
    Ok(status)
}


#[tauri::command]
pub async fn install_windivert_driver(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<GlobalPreAccelStatus, String> {
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (&app, &state);
        return Err(
            "WinDivert 驱动仅适用于 Windows 平台，当前系统请直接使用内置的本地独立 443 SOCKS5 通道"
                .to_string(),
        );
    }

    #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
    {
        let _ = (&app, &state);
        return Err(
            "当前为 Windows ARM64 架构，官方 WinDivert v2.2.2 未提供原生 ARM64 内核驱动；请使用内置的「本地独立 443 通道 (SOCKS5)」为其它软件提速"
                .to_string(),
        );
    }

    #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
    {
        if state
            .windivert_installing
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err("WinDivert 驱动正在下载安装中，请稍候片刻".to_string());
        }
        let _flag_guard = AtomicFlagResetGuard(Arc::clone(&state.windivert_installing));

        let cfg = state.snapshot_config();
        state.global_preaccel.set_install_state("downloading");
        sync_tray_and_window_side_effects(&app, &state, &cfg);

        let rt = state.snapshot_runtime();
        let active_mixed_port = if rt.running && rt.mixed_port > 0 {
            Some(rt.mixed_port)
        } else {
            None
        };
        let proxy_candidates = build_default_windivert_proxy_candidates(active_mixed_port);

        let installed_dir = match download_and_install_windivert_with_fallbacks(
            &state.paths,
            &proxy_candidates,
        )
        .await
        {
            Ok(dir) => dir,
            Err(e) => {
                let msg = e.to_string();
                state.global_preaccel.set_install_state("failed");
                state.log_app_event("error", "国内提速", &format!("安装 WinDivert 驱动失败：{msg}"));
                let latest_cfg = state.snapshot_config();
                sync_tray_and_window_side_effects(&app, &state, &latest_cfg);
                return Err(msg);
            }
        };

        state.global_preaccel.set_install_state("verifying");
        let latest_cfg = state.snapshot_config();
        sync_tray_and_window_side_effects(&app, &state, &latest_cfg);

        state.log_app_event(
            "info",
            "国内提速",
            &format!(
                "已下载并通过 SHA-256 校验安装官方 WinDivert v2.2.2 驱动至 {}",
                installed_dir.display()
            ),
        );

        if default_platform().capabilities().is_elevated {
            // Acquire outer `config_transition_lock` before checking latest config/TUN and
            // upgrading/starting WinDivert so TUN and WinDivert can never race open.
            let _cfg_guard = state.config_transition_lock.lock().await;
            let latest_cfg = state.snapshot_config();
            let latest_rt = state.snapshot_runtime();
            let tun_active = (latest_rt.running || state.adapter.has_live_controller().await)
                && effective_tun_enabled(&state, &latest_cfg);
            let current = state.snapshot_global_preaccel();
            if !state.shutting_down.load(Ordering::SeqCst)
                && latest_cfg.preaccel.enabled
                && !tun_active
            {
                if current.running && !current.is_windivert_active {
                    match load_enabled_preaccel_relays(&state) {
                        Ok(relays) if !relays.is_empty() => {
                            let excluded_pids = collect_excluded_pids_for_global_preaccel(&state);
                            match state
                                .global_preaccel
                                .upgrade_to_windivert_in_place(&latest_cfg, &relays, &excluded_pids)
                                .await
                            {
                                Ok(upgraded) if upgraded.is_windivert_active => {
                                    log_global_preaccel_verify_status(
                                        &state,
                                        "WinDivert 安装后原地热升格",
                                        &upgraded,
                                    );
                                }
                                Ok(upgraded) => {
                                    if upgraded.install_state == "verifying" {
                                        state.global_preaccel.set_install_state(
                                            if upgraded.windivert_available {
                                                "ready"
                                            } else {
                                                "idle"
                                            },
                                        );
                                    }
                                    let final_upgraded = state.snapshot_global_preaccel();
                                    log_global_preaccel_verify_status(
                                        &state,
                                        "WinDivert 安装后热升格探测",
                                        &final_upgraded,
                                    );
                                }
                                Err(err) => {
                                    if state.snapshot_global_preaccel().install_state == "verifying"
                                    {
                                        state.global_preaccel.set_install_state("failed");
                                    }
                                    let failed_st = state.snapshot_global_preaccel();
                                    log_global_preaccel_verify_status(
                                        &state,
                                        "WinDivert 安装后原地热升格失败",
                                        &failed_st,
                                    );
                                    state.log_app_event(
                                        "warning",
                                        "国内提速",
                                        &format!(
                                            "驱动就绪后原地热升格 WinDivert 透明模式失败：{err}"
                                        ),
                                    );
                                }
                            }
                        }
                        _ => {
                            state.global_preaccel.set_install_state("ready");
                        }
                    }
                } else if !current.running {
                    if load_enabled_preaccel_relays(&state).is_ok_and(|relays| !relays.is_empty()) {
                        match start_global_preaccel_engine(&state, &latest_cfg).await {
                            Ok(_) => {
                                if state.snapshot_global_preaccel().install_state == "verifying" {
                                    state.global_preaccel.set_install_state("ready");
                                }
                            }
                            Err(err) => {
                                state.global_preaccel.set_install_state("ready");
                                state.log_app_event(
                                    "warning",
                                    "国内提速",
                                    &format!("驱动就绪后自动启动 WinDivert 透明模式失败：{err}"),
                                );
                            }
                        }
                    } else {
                        state.global_preaccel.set_install_state("ready");
                    }
                } else {
                    state.global_preaccel.set_install_state("ready");
                }
            } else {
                state.global_preaccel.set_install_state("ready");
            }
            drop(_cfg_guard);
        } else {
            state.global_preaccel.set_install_state("need_elevation");
        }

        let final_cfg = state.snapshot_config();
        sync_tray_and_window_side_effects(&app, &state, &final_cfg);
        let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&final_cfg));
        Ok(state.snapshot_global_preaccel())
    }
}


#[tauri::command]
pub async fn verify_global_preaccel(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<GlobalPreAccelStatus, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    let cfg = state.snapshot_config();
    let rt = state.snapshot_runtime();
    let core_running = rt.running || state.adapter.has_live_controller().await;
    let tun_active = core_running && effective_tun_enabled(&state, &cfg);
    if !cfg.preaccel.enabled || tun_active {
        return Ok(state.snapshot_global_preaccel());
    }

    let main_core_pid = if rt.running {
        rt.pid.filter(|&p| p > 0)
    } else {
        None
    };
    let is_admin = default_platform().capabilities().is_elevated;
    let relays = load_enabled_preaccel_relays(&state).unwrap_or_default();
    let excluded_pids = collect_excluded_pids_for_global_preaccel(&state);

    state.global_preaccel.sync_main_core_pid(main_core_pid);
    tracing::debug!(
        is_admin,
        ?main_core_pid,
        bin_dir = %state.paths.bin_dir.display(),
        preaccel_enabled = cfg.preaccel.enabled,
        "running on-demand WinDivert dataplane reverification"
    );

    // Push immediate `probing` runtime & tray snapshot before starting dataplane verification so
    // the UI and system tray never falsely show active status while probing is in flight.
    if cfg!(all(target_os = "windows", not(target_arch = "aarch64")))
        && state.snapshot_global_preaccel().running
    {
        emit_preaccel_verify_override_snapshots(&app, &state, "probing", None);
    }

    match state
        .global_preaccel
        .reverify_windivert(&cfg, &relays, &excluded_pids)
        .await
    {
        Ok(status) => {
            log_global_preaccel_verify_status(&state, "手动重新探测底层提速", &status);
            emit_runtime_snapshot(&app, &state);
            refresh_tray(&app, &state);
            Ok(status)
        }
        Err(err) => {
            let err_msg = err.to_string();
            let latest = state.snapshot_global_preaccel();
            log_global_preaccel_verify_status(&state, "手动重新探测底层提速失败", &latest);
            state.log_app_event(
                "warning",
                "国内提速",
                &format!(
                    "手动重新探测底层提速异常（权限：{}）：{err_msg}",
                    if is_admin { "管理员" } else { "普通用户" }
                ),
            );
            emit_runtime_snapshot(&app, &state);
            refresh_tray(&app, &state);
            Err(err_msg)
        }
    }
}


#[tauri::command]
pub async fn relaunch_as_admin_for_global_preaccel(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (&app, &state);
        Err(
            "当前系统无需 Windows 管理员提权，可直接使用内置「本地独立 443 通道」为其它软件提速"
                .to_string(),
        )
    }

    #[cfg(target_os = "windows")]
    {
        // Never dirty-write `preaccel.enabled` / `global_bypass_enabled` to disk before UAC
        // succeeds. The elevated replacement instance receives `--enable-global-preaccel` and
        // persists config only after `toggle_global_preaccel_internal(..., true)` starts cleanly.
        relaunch_self_with_elevation_flags(&app, &state, false, true).await
    }
}


/// Apply a manual domestic pre-acceleration relay selection without bypassing the automatic
/// failover pool:
/// - Selecting `""` / `"auto"` / `"load_balance"` clears `active_relay_id` and restores multi-cloud
///   automatic dispatch (`Auto` or `LoadBalance`).
/// - Selecting a concrete relay sets `active_relay_id` with `auto_failover = true` so
///   `PREACCEL_SELECT_GROUP` continues pointing to `PREACCEL_FALLBACK_GROUP` (promoting this relay
///   to index 0 while retaining automatic failover + `DIRECT` safety net), and ALWAYS sets
///   `dispatch_strategy` to `PreAccelDispatchStrategy::Fallback` so strategy enum and actual
///   behavior remain 100% consistent (never leaving a misleading `Auto + Some(id)` pair).
pub(in crate::commands) fn apply_preaccel_relay_selection_to_config(
    cfg: &mut AppConfig,
    relay: Option<&PreAccelRelay>,
    explicit_auto_strategy: Option<PreAccelDispatchStrategy>,
) -> bool {
    cfg.preaccel.auto_failover = true;
    if let Some(target) = relay {
        let had_active_relay = cfg
            .preaccel
            .active_relay_id
            .as_deref()
            .map(str::trim)
            .is_some_and(|s| !s.is_empty());
        let switched_from_lb = cfg.preaccel.dispatch_strategy
            == PreAccelDispatchStrategy::LoadBalance
            || (cfg.preaccel.dispatch_strategy == PreAccelDispatchStrategy::Auto
                && !had_active_relay);
        cfg.preaccel.active_relay_id = Some(target.id.clone());
        cfg.preaccel.dispatch_strategy = PreAccelDispatchStrategy::Fallback;
        switched_from_lb
    } else {
        cfg.preaccel.active_relay_id = None;
        cfg.preaccel.dispatch_strategy =
            explicit_auto_strategy.unwrap_or(PreAccelDispatchStrategy::Auto);
        false
    }
}


/// Switch active pre-acceleration relay while strictly preserving automatic failover fallback.
/// Caller MUST already hold outer `state.config_transition_lock`.
async fn select_preaccel_relay_locked(
    app: &AppHandle,
    state: &AppState,
    relay_id: String,
) -> Result<String, String> {
    let trimmed_id = relay_id.trim();
    let restore_auto_mode = trimmed_id.is_empty()
        || trimmed_id.eq_ignore_ascii_case("auto")
        || trimmed_id.eq_ignore_ascii_case("load_balance");

    if restore_auto_mode {
        let target_strategy = if trimmed_id.eq_ignore_ascii_case("load_balance") {
            PreAccelDispatchStrategy::LoadBalance
        } else {
            PreAccelDispatchStrategy::Auto
        };
        let prev_cfg = state.snapshot_config();
        let mut cfg = (*prev_cfg).clone();
        apply_preaccel_relay_selection_to_config(&mut cfg, None, Some(target_strategy));
        config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
        if let Ok(mut guard) = state.config.write() {
            *guard = Arc::new(cfg.clone());
        }
        if state.adapter.has_live_controller().await {
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
                        "切换国内提速自动调度模式失败，核心配置重载未通过：{detail}"
                    ));
                }
            }
            let _ = state
                .adapter
                .select_group_proxy(
                    catcloud_core::core_adapter::PREACCEL_SELECT_GROUP_NAME,
                    catcloud_core::core_adapter::PREACCEL_FALLBACK_GROUP_NAME,
                )
                .await;
        }
        sync_running_global_preaccel_if_active(state, &cfg).await;
        state.log_app_event(
            "info",
            "国内提速",
            &format!(
                "已恢复国内提速自动多云调度（模式：{}，入口保持指向自动容灾池）",
                target_strategy.as_str()
            ),
        );
        sync_tray_and_window_side_effects(app, state, &cfg);
        emit_config_updated(app, &cfg);
        emit_relays_updated(app);
        return Ok(target_strategy.as_str().to_string());
    }

    let relay = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        db.get_preaccel_relay(trimmed_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("未找到指定国内中转（{trimmed_id}）"))?
    };
    let prev_cfg = state.snapshot_config();
    let mut cfg = (*prev_cfg).clone();
    let switched_from_lb = apply_preaccel_relay_selection_to_config(&mut cfg, Some(&relay), None);
    config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
    if let Ok(mut guard) = state.config.write() {
        *guard = Arc::new(cfg.clone());
    }
    if state.adapter.has_live_controller().await {
        // Trigger L2 hot reload so `PREACCEL_FALLBACK_GROUP` promotes this relay to index 0
        // while `PREACCEL_SELECT_GROUP` continues pointing to `PREACCEL_FALLBACK_GROUP` for
        // automatic failover + DIRECT safety net (never locking a single relay bare).
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
                    "切换国内中转「{}」失败，核心配置重载未通过：{detail}",
                    relay.name
                ));
            }
        }
        let _ = state
            .adapter
            .select_group_proxy(
                catcloud_core::core_adapter::PREACCEL_SELECT_GROUP_NAME,
                catcloud_core::core_adapter::PREACCEL_FALLBACK_GROUP_NAME,
            )
            .await;
    }
    sync_running_global_preaccel_if_active(state, &cfg).await;
    let mode_note = if switched_from_lb {
        "（已从多云均衡切为主备置顶模式，保留其余中转与直连自动兜底；可随时一键切回多云均衡）"
    } else {
        "（已置顶至主备优先顺位，保留其余中转与直连自动故障转移兜底）"
    };
    state.log_app_event(
        "info",
        "国内提速",
        &format!("已切换国内提速优先中转至「{}」{mode_note}", relay.name),
    );
    sync_tray_and_window_side_effects(app, state, &cfg);
    emit_config_updated(app, &cfg);
    emit_relays_updated(app);
    Ok(relay.id)
}


#[tauri::command]
pub async fn select_preaccel_relay(
    app: AppHandle,
    state: State<'_, AppState>,
    relay_id: String,
) -> Result<String, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    select_preaccel_relay_locked(&app, &state, relay_id).await
}


#[tauri::command]
pub async fn failover_preaccel(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Option<String>, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    let relays = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        db.list_preaccel_relays(true).map_err(|e| e.to_string())?
    };
    if relays.is_empty() {
        return Ok(None);
    }
    let cfg = state.snapshot_config();
    let cur_idx = cfg
        .preaccel
        .active_relay_id
        .as_deref()
        .and_then(|id| relays.iter().position(|r| r.id == id))
        .unwrap_or(relays.len() - 1);
    let next = &relays[(cur_idx + 1) % relays.len()];
    let selected = select_preaccel_relay_locked(&app, &state, next.id.clone()).await?;
    Ok(Some(selected))
}


#[tauri::command]
pub async fn import_mmrelay_input(
    app: AppHandle,
    state: State<'_, AppState>,
    raw: String,
) -> Result<Vec<PreAccelRelay>, String> {
    let bundle =
        catcloud_core::preaccel::schema::parse_mmrelay_clipboard(&raw).map_err(|e| e.to_string())?;
    let expected_fps: HashSet<(String, String, u16)> = bundle
        .relays
        .iter()
        .map(|r| {
            let proto = catcloud_core::preaccel::schema::RelayProtocol::parse(&r.protocol)
                .map(|p| p.mihomo_type().to_string())
                .unwrap_or_else(|| r.protocol.trim().to_ascii_lowercase());
            (proto, r.server.trim().to_ascii_lowercase(), r.port)
        })
        .collect();
    let (imported_count, warnings, persisted) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let (count, warnings) =
            catcloud_core::preaccel::import_relays_dedup_into_storage(&db, bundle.relays)
                .map_err(|e| e.to_string())?;
        if count == 0 && !warnings.is_empty() {
            return Err(warnings.join("；"));
        }
        let all = db.list_preaccel_relays(false).map_err(|e| e.to_string())?;
        let matched: Vec<PreAccelRelay> = all
            .into_iter()
            .filter(|r| {
                let proto = catcloud_core::preaccel::schema::RelayProtocol::parse(&r.protocol)
                    .map(|p| p.mihomo_type().to_string())
                    .unwrap_or_else(|| r.protocol.trim().to_ascii_lowercase());
                expected_fps.contains(&(proto, r.server.trim().to_ascii_lowercase(), r.port))
            })
            .collect();
        (count, warnings, matched)
    };
    if !warnings.is_empty() {
        state.log_app_event(
            "warning",
            "国内提速",
            &format!("导入国内中转存在跳过项：{}", warnings.join("；")),
        );
    }
    if let Some(outcome) = trigger_reload_if_running(&app, &state, false).await {
        if outcome.rejected {
            let detail = outcome
                .error
                .as_deref()
                .map(format_mihomo_error_for_user)
                .unwrap_or_else(|| "未知原因".to_string());
            let cfg = state.snapshot_config();
            sync_tray_and_window_side_effects(&app, &state, &cfg);
            emit_relays_updated(&app);
            return Err(format!(
                "已去重导入 {imported_count} 条国内中转，但核心配置热重载未通过：{detail}"
            ));
        }
    }
    let latest_cfg = state.snapshot_config();
    sync_running_global_preaccel_if_active(&state, &latest_cfg).await;
    sync_tray_and_window_side_effects(&app, &state, &latest_cfg);
    emit_config_updated(&app, &latest_cfg);
    emit_relays_updated(&app);
    Ok(persisted)
}

