pub mod app_log;
pub mod commands;
pub mod lifecycle;
pub mod shortcuts;
pub mod tray;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use catcloud_core::config;
use catcloud_core::models::{
    MultiGroup, MultiGroupMode, ProxyMode, RouteTargetMode, UpdateApplyMode, UpdateConfig,
};
use catcloud_core::platform::default_platform;
use catcloud_core::process_guard::{
    AcquireOutcome, JobGuard, SingleInstanceGuard, spawn_detached_self,
};
use catcloud_core::storage::Storage;
use catcloud_core::AppPaths;
use tauri::{Emitter, Manager};

use crate::commands::{AppState, TrafficEventPayload};
use crate::lifecycle::WindowLifecycleState;
use crate::tray::{TrayAction, TrayOpenDirKind, TrayProxyMode};

/// Default entry point used when launched without pre-resolved `AppPaths`.
pub fn run() {
    catcloud_core::init_crypto_provider();
    let cli_data_dir = AppPaths::parse_cli_data_dir_from_args();
    let paths =
        AppPaths::resolve(cli_data_dir).expect("failed to resolve CatCloud runtime paths");
    // SAFETY: Fallback entrypoint before Tauri threads spawn.
    #[cfg(target_os = "windows")]
    unsafe {
        lifecycle::set_webview2_user_data_env(&paths);
    }
    run_with_paths(paths);
}

/// Build the Tauri context from a single `tauri::generate_context!()` macro expansion
/// crate-wide so macOS builds never emit duplicate `_EMBED_INFO_PLIST` symbols during tests.
pub(crate) fn build_app_context() -> tauri::Context<tauri::Wry> {
    tauri::generate_context!()
}

fn has_cli_flag(flag: &str) -> bool {
    std::env::args().skip(1).any(|a| a == flag)
}

fn try_apply_staged_portable_update(paths: &AppPaths) -> bool {
    if !paths.is_self_updatable_portable() {
        return false;
    }
    let Ok(current_exe) = std::env::current_exe() else {
        return false;
    };
    let Some(app_root) = current_exe.parent() else {
        return false;
    };
    match catcloud_core::updater::apply_staged_portable_update(
        app_root,
        &current_exe,
        &paths.staging_dir,
        &paths.backup_dir,
    ) {
        Ok(outcome) if outcome.applied && outcome.needs_post_update_cleanup_relaunch => {
            let mut relaunch_args = outcome.relaunch_args;
            if !relaunch_args.iter().any(|a| a == "--post-update-cleanup") {
                relaunch_args.push("--post-update-cleanup".to_string());
            }
            if !relaunch_args.iter().any(|a| a == "--restarting") {
                relaunch_args.push("--restarting".to_string());
            }
            if let Err(err) = spawn_detached_self(&current_exe, &relaunch_args, app_root) {
                tracing::error!("portable update applied but relaunch failed: {err}");
                return false;
            }
            tracing::info!(
                from = %outcome.from_version,
                to = %outcome.to_version,
                "portable update applied; handed off to updated binary"
            );
            true
        }
        Ok(_) => false,
        Err(err) => {
            tracing::warn!("staged portable update skipped/rolled back: {err}");
            false
        }
    }
}

/// Primary desktop bootstrap accepting pre-resolved portable/sandbox/standard `AppPaths`.
pub fn run_with_paths(paths: AppPaths) {
    catcloud_core::init_crypto_provider();

    let restarting = has_cli_flag("--restarting");
    let silent_flag = has_cli_flag("--silent");
    let post_update_cleanup = has_cli_flag("--post-update-cleanup");
    let enable_tun_flag = has_cli_flag("--enable-tun");
    let enable_global_preaccel_flag = has_cli_flag("--enable-global-preaccel");

    if post_update_cleanup {
        let _ = catcloud_core::updater::run_post_update_cleanup(&paths.backup_dir);
    }

    let instance_guard: Option<SingleInstanceGuard> =
        match SingleInstanceGuard::acquire_for_paths(&paths, restarting) {
            Ok(AcquireOutcome::Primary(guard)) => Some(guard),
            Ok(AcquireOutcome::SecondaryWokePrimary) => {
                tracing::info!(
                    "another CatCloud instance owns this data_dir; signaled primary and exiting"
                );
                return;
            }
            Err(err) => {
                tracing::warn!("single-instance guard fallback ({err}); continuing launch");
                None
            }
        };

    // Apply any verified staged portable update before starting core or opening SQLite.
    if !post_update_cleanup
        && paths.is_self_updatable_portable()
        && try_apply_staged_portable_update(&paths)
    {
        if let Some(mut guard) = instance_guard {
            guard.release();
        }
        return;
    }

    let job_guard = Arc::new(
        JobGuard::with_pid_file(Some(paths.runtime_dir.join("core.pid")))
            .expect("failed to initialize process JobGuard"),
    );
    let cfg = config::load_or_init(&paths).unwrap_or_default();
    let mut storage = Storage::open(&paths.db_path).expect("failed to open CatCloud SQLite store");
    let _ = storage.seed_builtin_probes();

    let destroy_on_close = cfg.behavior.minimize_to_tray_on_close;
    let silent_start = silent_flag || cfg.behavior.silent_start;
    let tray_click = commands::map_tray_click(&cfg.behavior.tray_click_action);

    let app_state = AppState::new(paths.clone(), cfg, storage, Arc::clone(&job_guard));
    app_state.log_app_event(
        "info",
        "应用",
        &format!(
            "猫猫云梯桌面端已启动（v{}，便携模式：{}，权限：{}）",
            env!("CARGO_PKG_VERSION"),
            if paths.is_portable { "是" } else { "否" },
            if default_platform().capabilities().is_elevated {
                "管理员"
            } else {
                "普通用户"
            }
        ),
    );

    let mut context = build_app_context();
    lifecycle::apply_portable_overrides(&mut context, &paths);
    #[cfg(target_os = "macos")]
    {
        for win_cfg in &mut context.config_mut().app.windows {
            if win_cfg.label == lifecycle::MAIN_WINDOW_LABEL {
                win_cfg.decorations = true;
                win_cfg.title_bar_style = tauri::TitleBarStyle::Overlay;
                win_cfg.hidden_title = true;
            }
        }
    }

    let instance_guard_slot = Arc::new(Mutex::new(instance_guard));
    let wake_guard_ref = Arc::clone(&instance_guard_slot);
    let exit_guard_ref = Arc::clone(&instance_guard_slot);
    let exit_job_ref = Arc::clone(&job_guard);

    // Best-effort cleanup of any stale ephemeral probe sandboxes left by prior hard crashes.
    let stale_sandbox_dir = paths.runtime_dir.join("probe_sandbox");
    if stale_sandbox_dir.exists() {
        let _ = std::fs::remove_dir_all(&stale_sandbox_dir);
    }

    let has_updater_plugin_cfg = context
        .config()
        .plugins
        .0
        .get("updater")
        .is_some_and(|v| v.is_object());

    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(shortcuts::build_plugin());

    if has_updater_plugin_cfg {
        builder = builder.plugin(tauri_plugin_updater::Builder::new().build());
    }

    let app = builder
        .manage(WindowLifecycleState::new(destroy_on_close))
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            commands::get_app_config,
            commands::save_app_config,
            commands::get_full_config,
            commands::save_full_config,
            commands::save_extended_settings,
            commands::get_runtime_info,
            commands::start_core,
            commands::stop_core,
            commands::restart_core,
            commands::reload_core_config,
            commands::set_proxy_mode,
            commands::set_system_proxy,
            commands::set_tun_enabled,
            commands::relaunch_as_admin,
            commands::switch_next_best_node,
            commands::select_group_node,
            commands::set_active_group,
            commands::select_single_node,
            commands::toggle_capsule_window,
            commands::show_main_window,
            commands::enter_windowless_mode,
            commands::list_multi_groups,
            commands::upsert_multi_group,
            commands::delete_multi_group,
            commands::update_multi_group_members,
            commands::list_nodes,
            commands::set_nodes_preaccel_override,
            commands::list_probe_definitions,
            commands::upsert_probe_definition,
            commands::delete_probe_definition,
            commands::list_probe_snapshots,
            commands::run_isolated_probes,
            commands::cancel_isolated_probes,
            commands::pick_wallpaper_image,
            commands::resolve_wallpaper_data_url,
            commands::list_subscriptions,
            commands::upsert_subscription,
            commands::delete_subscription,
            commands::refresh_subscription,
            commands::refresh_all_subscriptions,
            commands::list_preaccel_relays,
            commands::upsert_preaccel_relay,
            commands::delete_preaccel_relay,
            commands::toggle_preaccel,
            commands::get_global_preaccel_status,
            commands::toggle_global_preaccel,
            commands::update_global_preaccel_settings,
            commands::install_windivert_driver,
            commands::relaunch_as_admin_for_global_preaccel,
            commands::select_preaccel_relay,
            commands::failover_preaccel,
            commands::test_preaccel_relays,
            commands::benchmark_preaccel_comparison,
            commands::check_campus_portal,
            commands::get_exit_ip_info,
            commands::check_quick_sites,
            commands::get_active_connections,
            commands::close_connection,
            commands::close_group_connections,
            commands::close_all_connections,
            commands::get_recent_logs,
            commands::get_traffic_history,
            commands::list_agent_docs,
            commands::export_agent_docs,
            commands::validate_formula_expr,
            commands::evaluate_multi_group,
            commands::compile_preview_yaml,
            commands::import_mmrelay_input,
            commands::scan_local_migrations,
            commands::scan_migration_path,
            commands::preview_migration_from_text,
            commands::apply_migration_nodes,
            commands::list_running_processes,
            commands::inspect_process_source,
            commands::export_shell_env,
            commands::export_sanitized_diagnostics,
            commands::get_geodata_status,
            commands::refresh_geo_db,
            commands::check_app_update,
            commands::download_and_stage_update,
            commands::export_backup_bundle,
            commands::import_backup_bundle,
            commands::launch_uwp_loopback,
            commands::hot_swap_core,
            commands::open_app_dir,
            commands::open_web_ui,
            commands::open_external_url,
        ])
        .on_window_event(lifecycle::handle_window_event_with_state)
        .setup(move |app| {
            let handle = app.handle().clone();

            #[cfg(target_os = "macos")]
            if let Err(err) = install_macos_native_menu(&handle) {
                tracing::warn!("failed to install macOS native application menu: {err}");
            }

            // Inject Tauri bundle resource_dir into AppState for cross-platform bundled Mihomo lookup.
            let state = handle.state::<AppState>();
            state.set_resource_dir(app.path().resource_dir().ok());

            // Wakeup listener: when a secondary launch targets the same data_dir,
            // rebuild or focus the primary main window.
            if let Ok(guard_lock) = wake_guard_ref.lock() {
                if let Some(ref si) = *guard_lock {
                    let wake_handle = handle.clone();
                    let _ = si.start_wakeup_listener(move || {
                        lifecycle::show_or_rebuild_main_window(&wake_handle);
                    });
                }
            }

            // Spawn background telemetry event forwarders feeding frontend sparklines, logs, and tray tooltip.
            spawn_telemetry_forwarders(&handle, &state);
            // Spawn background cross-platform ProxyGuard watchdog preventing third-party proxy hijacking.
            spawn_proxy_guard(&handle);
            // Spawn background multi-group health watchdog driving automatic failover for StickyBest/ConditionalPool.
            spawn_group_strategy_watchdog(&handle);
            // Spawn background auto-update checker & portable staging loop (45s cold-start silence).
            spawn_auto_update_loop(&handle);

            let initial_menu = commands::build_tray_menu_state(&handle, &state);
            let initial_visual = commands::build_tray_visual_state(&state);

            tray::setup_tray(&handle, initial_menu, initial_visual, tray_click, |app_h, action| {
                if tray::handle_builtin_tray_action(app_h, &action) {
                    if let Some(st) = app_h.try_state::<AppState>() {
                        let _ = tray::sync_tray_menu(
                            app_h,
                            &commands::build_tray_menu_state(app_h, &st),
                        );
                    }
                    return;
                }
                let app_async = app_h.clone();
                match action {
                    TrayAction::SetProxyMode(mode) => {
                        let core_mode = match mode {
                            TrayProxyMode::Rule => ProxyMode::Rule,
                            TrayProxyMode::Global => ProxyMode::Global,
                            TrayProxyMode::Direct => ProxyMode::Direct,
                        };
                        tauri::async_runtime::spawn(async move {
                            if let Some(st) = app_async.try_state::<AppState>() {
                                let _ = commands::set_proxy_mode(
                                    app_async.clone(),
                                    st,
                                    core_mode,
                                )
                                .await;
                            }
                        });
                    }
                    TrayAction::ToggleSystemProxy => {
                        tauri::async_runtime::spawn(async move {
                            if let Some(st) = app_async.try_state::<AppState>() {
                                let next_enabled = !st.snapshot_config().system_proxy.enabled;
                                let _ = commands::apply_system_proxy_internal(
                                    &app_async,
                                    &st,
                                    next_enabled,
                                )
                                .await;
                            }
                        });
                    }
                    TrayAction::ToggleTun => {
                        tauri::async_runtime::spawn(async move {
                            if let Some(st) = app_async.try_state::<AppState>() {
                                let next_enabled = !st.snapshot_config().tun.enabled;
                                if let Err(err) = commands::set_tun_enabled_internal(
                                    &app_async,
                                    &st,
                                    next_enabled,
                                )
                                .await
                                {
                                    commands::handle_tun_toggle_error(&app_async, &err);
                                }
                            }
                        });
                    }
                    TrayAction::QuickSwitchNextBest { group_id } => {
                        tauri::async_runtime::spawn(async move {
                            if let Some(st) = app_async.try_state::<AppState>() {
                                let _ = commands::switch_next_best_internal(
                                    &app_async,
                                    &st,
                                    group_id,
                                )
                                .await;
                            }
                        });
                    }
                    TrayAction::SelectGroupNode { group_id, node_id } => {
                        tauri::async_runtime::spawn(async move {
                            if let Some(st) = app_async.try_state::<AppState>() {
                                let _ = commands::select_group_node_internal(
                                    &app_async,
                                    &st,
                                    group_id,
                                    node_id,
                                    None,
                                    None,
                                )
                                .await;
                            }
                        });
                    }
                    TrayAction::TogglePreAccel => {
                        tauri::async_runtime::spawn(async move {
                            if let Some(st) = app_async.try_state::<AppState>() {
                                let next = !st.snapshot_config().preaccel.enabled;
                                let _ = commands::toggle_preaccel_internal(&app_async, &st, next).await;
                            }
                        });
                    }
                    TrayAction::ToggleGlobalPreAccel => {
                        tauri::async_runtime::spawn(async move {
                            if let Some(st) = app_async.try_state::<AppState>() {
                                let currently_on = st.snapshot_global_preaccel().running
                                    || st.snapshot_config().preaccel.global_bypass_enabled;
                                let _ = commands::toggle_global_preaccel_internal(
                                    &app_async,
                                    &st,
                                    !currently_on,
                                )
                                .await;
                            }
                        });
                    }
                    TrayAction::FailoverPreAccel => {
                        tauri::async_runtime::spawn(async move {
                            if let Some(st) = app_async.try_state::<AppState>() {
                                let _ = commands::failover_preaccel(app_async.clone(), st).await;
                            }
                        });
                    }
                    TrayAction::SelectPreAccelRelay { relay_id } => {
                        tauri::async_runtime::spawn(async move {
                            if let Some(st) = app_async.try_state::<AppState>() {
                                let _ = commands::select_preaccel_relay(
                                    app_async.clone(),
                                    st,
                                    relay_id,
                                )
                                .await;
                            }
                        });
                    }
                    TrayAction::RefreshSubscriptions => {
                        tauri::async_runtime::spawn(async move {
                            if let Some(st) = app_async.try_state::<AppState>() {
                                let _ =
                                    commands::refresh_all_subscriptions(app_async.clone(), st)
                                        .await;
                            }
                        });
                    }
                    TrayAction::CopyShellEnv => {
                        if let Some(st) = app_h.try_state::<AppState>() {
                            #[cfg(target_os = "windows")]
                            let default_shell = "powershell";
                            #[cfg(not(target_os = "windows"))]
                            let default_shell = "bash";
                            let snippet =
                                commands::export_shell_env(st, default_shell.to_string());
                            let _ = commands::copy_text_to_clipboard(&snippet);
                        }
                    }
                    TrayAction::ToggleAutostart => {
                        tauri::async_runtime::spawn(async move {
                            if let Some(st) = app_async.try_state::<AppState>() {
                                let mut next = st.snapshot_config();
                                next.behavior.autostart = !next.behavior.autostart;
                                let _ = commands::save_full_config(app_async.clone(), st, next)
                                    .await;
                            }
                        });
                    }
                    TrayAction::OpenDir(kind) => {
                        if let Some(st) = app_h.try_state::<AppState>() {
                            let dir = match kind {
                                TrayOpenDirKind::DataRoot => &st.paths.root_data_dir,
                                TrayOpenDirKind::Config => &st.paths.config_dir,
                                TrayOpenDirKind::Logs => &st.paths.logs_dir,
                                TrayOpenDirKind::Bin => &st.paths.bin_dir,
                            };
                            let _ = commands::open_directory_in_os(dir);
                        }
                    }
                    TrayAction::RestartCore => {
                        tauri::async_runtime::spawn(async move {
                            if let Some(st) = app_async.try_state::<AppState>() {
                                let _ = commands::restart_core(app_async.clone(), st).await;
                            }
                        });
                    }
                    TrayAction::OpenMain
                    | TrayAction::ToggleCapsule
                    | TrayAction::ToggleWindowless
                    | TrayAction::Quit => {}
                }
            })?;

            let initial_cfg = state.snapshot_config();
            commands::apply_configured_shortcuts(&handle, &state, &initial_cfg, true);

            if silent_start {
                lifecycle::enter_pure_windowless_mode(&handle);
            }

            // Asynchronously start the managed proxy core when `--enable-tun` elevation handoff
            // is requested OR when system proxy / TUN is enabled in config and nodes exist,
            // guaranteeing 0 background traffic on idle startup.
            {
                let auto_handle = handle.clone();
                tauri::async_runtime::spawn(async move {
                    if let Some(st) = auto_handle.try_state::<AppState>() {
                        if enable_tun_flag && default_platform().capabilities().is_elevated {
                            let has_enabled = commands::has_enabled_nodes(&st).unwrap_or(false);
                            if !has_enabled {
                                st.log_app_event(
                                    "warning",
                                    "虚拟网卡",
                                    "--enable-tun 启动跳过：暂无可用节点，请先导入订阅",
                                );
                                return;
                            }
                            let old_cfg = st.snapshot_config();
                            let mut next_cfg = old_cfg.clone();
                            next_cfg.tun.enabled = true;
                            if let Err(err) = config::save(&st.paths, &next_cfg) {
                                st.log_app_event(
                                    "error",
                                    "虚拟网卡",
                                    &format!("--enable-tun 保存配置失败：{err}"),
                                );
                                return;
                            }
                            if let Ok(mut guard) = st.config.write() {
                                *guard = next_cfg.clone();
                            }
                            commands::sync_app_side_effects(&auto_handle, &st, &next_cfg);
                            if let Err(err) = commands::start_core_internal(&auto_handle, &st).await {
                                st.log_app_event(
                                    "error",
                                    "虚拟网卡",
                                    &format!("--enable-tun 提权启动核心失败，已回滚 TUN 开关：{err}"),
                                );
                                let _ = config::save(&st.paths, &old_cfg);
                                if let Ok(mut guard) = st.config.write() {
                                    *guard = old_cfg.clone();
                                }
                                commands::sync_app_side_effects(&auto_handle, &st, &old_cfg);
                            } else {
                                st.log_app_event(
                                    "info",
                                    "虚拟网卡",
                                    "已通过管理员提权自动开启虚拟网卡（TUN）并启动核心",
                                );
                            }
                            return;
                        }

                        if enable_global_preaccel_flag {
                            match commands::toggle_global_preaccel_internal(&auto_handle, &st, true)
                                .await
                            {
                                Ok(global_st) => {
                                    st.log_app_event(
                                        "info",
                                        "国内提速",
                                        &format!(
                                            "已通过提权启动参数自动启用独立底层全局国内提速（模式：{}）",
                                            global_st.mode
                                        ),
                                    );
                                }
                                Err(err) => {
                                    st.log_app_event(
                                        "error",
                                        "国内提速",
                                        &format!("--enable-global-preaccel 启动底层全局提速失败：{err}"),
                                    );
                                }
                            }
                        }

                        let cfg = st.snapshot_config();
                        if !(cfg.system_proxy.enabled || cfg.tun.enabled) {
                            tracing::info!(
                                "auto-start core skipped: system_proxy and tun are both disabled"
                            );
                            if !enable_global_preaccel_flag
                                && cfg.preaccel.enabled
                                && cfg.preaccel.global_bypass_enabled
                                && !st.global_preaccel.status().running
                            {
                                match commands::toggle_global_preaccel_internal(
                                    &auto_handle,
                                    &st,
                                    true,
                                )
                                .await
                                {
                                    Ok(global_st) => {
                                        st.log_app_event(
                                            "info",
                                            "国内提速",
                                            &format!(
                                                "启动时自动恢复独立底层全局国内提速（模式：{}）",
                                                global_st.mode
                                            ),
                                        );
                                    }
                                    Err(err) => {
                                        tracing::info!(
                                            "auto-start standalone global preaccel skipped: {err}"
                                        );
                                    }
                                }
                            }
                            return;
                        }
                        let has_nodes = commands::has_enabled_nodes(&st).unwrap_or(false);
                        if has_nodes {
                            if let Err(err) = commands::start_core_internal(&auto_handle, &st).await {
                                tracing::info!("auto-start core skipped: {err}");
                            }
                        }
                    }
                });
            }

            Ok(())
        })
        .build(context)
        .expect("failed to build CatCloud desktop application");

    let exit_app_handle = app.handle().clone();
    let mut cleanup = Some(move || {
        if let Some(st) = exit_app_handle.try_state::<AppState>() {
            commands::emergency_cleanup_on_exit(&st);
        }
        let _ = exit_job_ref.terminate_all();
        if let Ok(mut guard_lock) = exit_guard_ref.lock() {
            if let Some(mut si) = guard_lock.take() {
                si.release();
            }
        }
    });

    app.run(move |app_handle, event| {
        lifecycle::handle_run_event(app_handle, event, &mut cleanup);
    });
}

#[cfg(target_os = "macos")]
fn install_macos_native_menu(app: &tauri::AppHandle) -> tauri::Result<()> {
    use tauri::menu::{Menu, PredefinedMenuItem, Submenu};

    let app_menu = Submenu::with_items(
        app,
        "CatCloud",
        true,
        &[
            &PredefinedMenuItem::about(app, Some("关于 猫猫云梯"), None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::services(app, None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::hide(app, None)?,
            &PredefinedMenuItem::hide_others(app, None)?,
            &PredefinedMenuItem::show_all(app, None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::quit(app, None)?,
        ],
    )?;

    let edit_menu = Submenu::with_items(
        app,
        "Edit",
        true,
        &[
            &PredefinedMenuItem::undo(app, None)?,
            &PredefinedMenuItem::redo(app, None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::cut(app, None)?,
            &PredefinedMenuItem::copy(app, None)?,
            &PredefinedMenuItem::paste(app, None)?,
            &PredefinedMenuItem::select_all(app, None)?,
        ],
    )?;

    let window_menu = Submenu::with_items(
        app,
        "Window",
        true,
        &[
            &PredefinedMenuItem::minimize(app, None)?,
            &PredefinedMenuItem::maximize(app, None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::close_window(app, None)?,
        ],
    )?;

    let menu = Menu::with_items(app, &[&app_menu, &edit_menu, &window_menu])?;
    let _ = app.set_menu(menu)?;
    Ok(())
}

fn spawn_proxy_guard(app: &tauri::AppHandle) {
    let app_h = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            let interval_sec = {
                let Some(st) = app_h.try_state::<AppState>() else {
                    break;
                };
                if st.shutting_down.load(Ordering::SeqCst) {
                    break;
                }
                st.snapshot_config()
                    .system_proxy
                    .proxy_guard
                    .interval_sec
                    .clamp(5, 120)
            };

            tokio::time::sleep(Duration::from_secs(interval_sec)).await;

            let Some(st) = app_h.try_state::<AppState>() else {
                break;
            };
            if st.shutting_down.load(Ordering::SeqCst) {
                break;
            }
            let cfg = st.snapshot_config();
            if !(cfg.system_proxy.enabled && cfg.system_proxy.proxy_guard.enabled) {
                continue;
            }
            if !st.adapter.has_live_controller().await {
                continue;
            }

            let app_blocking = app_h.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let Some(st) = app_blocking.try_state::<AppState>() else {
                    return;
                };
                let _proxy_guard = st
                    .system_proxy_lock
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if st.shutting_down.load(Ordering::SeqCst) {
                    return;
                }
                let latest_cfg = st.snapshot_config();
                if !(latest_cfg.system_proxy.enabled
                    && latest_cfg.system_proxy.proxy_guard.enabled)
                {
                    return;
                }
                let rt = st.snapshot_runtime();
                let port = if rt.running {
                    rt.mixed_port
                } else {
                    latest_cfg.mixed_port
                };
                let expected = latest_cfg.system_proxy.to_platform_spec("127.0.0.1", port);

                #[cfg(target_os = "windows")]
                {
                    let plat = catcloud_core::platform::windows::WindowsPlatform::new();
                    match plat.proxy_guard_tick(&expected) {
                        Ok(report) if report.drifted => {
                            let reason = report
                                .reason
                                .unwrap_or_else(|| "检测到外部程序篡改系统代理".to_string());
                            st.log_app_event(
                                "warning",
                                "代理守护",
                                &format!(
                                    "ProxyGuard 检测到系统代理偏离（{reason}），已自动恢复至 127.0.0.1:{port}"
                                ),
                            );
                        }
                        Ok(_) => {}
                        Err(err) => {
                            tracing::debug!("proxy_guard_tick failed: {err}");
                        }
                    }
                }

                #[cfg(not(target_os = "windows"))]
                {
                    let plat = default_platform();
                    match plat.read_system_proxy() {
                        Ok(observed) => {
                            let drifted = observed.enabled != expected.enabled
                                || (expected.enabled
                                    && (observed.pac_url != expected.pac_url
                                        || (expected.pac_url.is_none()
                                            && (observed.host != expected.host
                                                || observed.port != expected.port))));
                            if drifted {
                                if let Err(err) = plat.apply_system_proxy(&expected) {
                                    tracing::debug!("proxy_guard_tick repair failed: {err}");
                                } else {
                                    st.log_app_event(
                                        "warning",
                                        "代理守护",
                                        &format!(
                                            "ProxyGuard 检测到系统代理偏离，已自动恢复至 127.0.0.1:{port}"
                                        ),
                                    );
                                }
                            }
                        }
                        Err(err) => {
                            tracing::debug!("proxy_guard_tick read failed: {err}");
                        }
                    }
                }
            })
            .await;
        }
    });
}

async fn probe_compiled_proxy_delay(
    http_client: &reqwest::Client,
    ctrl_host: &str,
    port: u16,
    secret: &str,
    compiled_proxy: &str,
    timeout_ms: u64,
) -> Option<u64> {
    let encoded_proxy = commands::percent_encode_path_segment(compiled_proxy);
    let delay_url = format!(
        "http://{ctrl_host}:{port}/proxies/{encoded_proxy}/delay?url=https%3A%2F%2Fcp.cloudflare.com%2Fgenerate_204&timeout={timeout_ms}"
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

fn is_watchdog_high_throughput(st: &AppState) -> bool {
    let cached = st
        .cached_metrics
        .read()
        .map(|m| *m)
        .unwrap_or_default();
    let recent_ticks = st.telemetry.traffic_snapshot();
    let now_ms = chrono::Utc::now().timestamp_millis();
    commands::is_high_throughput_active(
        &cached,
        &recent_ticks,
        now_ms,
        commands::WATCHDOG_HIGH_THROUGHPUT_WINDOW_MS,
        commands::WATCHDOG_HIGH_THROUGHPUT_THRESHOLD_BPS,
    )
}

fn spawn_group_strategy_watchdog(app: &tauri::AppHandle) {
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

        const FAILED_NODE_COOLDOWN: Duration = Duration::from_secs(300);
        const ALL_CANDIDATES_FAILED_BACKOFF: Duration = Duration::from_secs(180);
        const MAX_FAILOVER_CANDIDATES: usize = 3;
        const CANDIDATE_PROBE_TIMEOUT_MS: u64 = 3500;

        let mut consecutive_fail_counts: HashMap<String, u32> = HashMap::new();
        let mut last_auto_switch_at: HashMap<String, Instant> = HashMap::new();
        let mut failed_group_backoff_until: HashMap<String, Instant> = HashMap::new();
        let mut last_checked_node: HashMap<String, String> = HashMap::new();
        let mut failed_node_cooldowns: HashMap<String, Instant> = HashMap::new();

        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;

            // Purge expired 5-minute bounce-back cooldowns at the start of every cycle.
            failed_node_cooldowns.retain(|_, t| t.elapsed() < FAILED_NODE_COOLDOWN);

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
            if cfg.route_mode != RouteTargetMode::Group || cfg.proxy_mode == ProxyMode::Direct {
                consecutive_fail_counts.clear();
                continue;
            }

            if !st.adapter.has_live_controller().await {
                consecutive_fail_counts.clear();
                continue;
            }
            let rt = st.adapter.runtime_status().await;
            if !rt.running {
                consecutive_fail_counts.clear();
                continue;
            }

            // Guard #1: suppress probing & reset failure counters whenever sustained high-throughput
            // traffic (>= 256 KiB/s within the 10s sliding window) is active, protecting large
            // uploads/downloads from spurious mid-transfer failover even while minimized.
            if is_watchdog_high_throughput(&st) {
                consecutive_fail_counts.clear();
                tracing::debug!(
                    "group strategy watchdog skipped round: active high-throughput transfer detected"
                );
                continue;
            }

            let secret = st.adapter.controller_secret().await;

            // Snapshot groups & nodes under a brief sync lock; NEVER hold across `.await`.
            let snapshot_res = st.storage.lock().ok().map(|db| {
                (
                    db.list_multi_groups().unwrap_or_default(),
                    db.list_nodes().unwrap_or_default(),
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

            let mut target_groups: Vec<(MultiGroup, bool)> = Vec::new();
            for g in &groups {
                let is_primary = primary_gid.as_deref() == Some(g.id.as_str());
                if !(is_primary || g.independent_routing) {
                    continue;
                }
                if !matches!(
                    g.mode,
                    MultiGroupMode::StickyBest | MultiGroupMode::ConditionalPool
                ) {
                    continue;
                }
                if commands::count_enabled_group_members(g, &nodes) < 2 {
                    continue;
                }
                if !target_groups.iter().any(|(existing, _)| existing.id == g.id) {
                    target_groups.push((g.clone(), is_primary));
                }
            }

            consecutive_fail_counts
                .retain(|gid, _| target_groups.iter().any(|(g, _)| &g.id == gid));
            last_auto_switch_at.retain(|gid, _| target_groups.iter().any(|(g, _)| &g.id == gid));
            failed_group_backoff_until
                .retain(|gid, until| Instant::now() < *until && target_groups.iter().any(|(g, _)| &g.id == gid));
            last_checked_node.retain(|gid, _| target_groups.iter().any(|(g, _)| &g.id == gid));

            if target_groups.is_empty() {
                continue;
            }

            let ctrl_host = match rt.controller_host.trim() {
                "" | "0.0.0.0" | "::" => "127.0.0.1".to_string(),
                h if h.contains(':') && !h.starts_with('[') => format!("[{h}]"),
                h => h.to_string(),
            };

            for (group, is_primary) in target_groups {
                if st.shutting_down.load(Ordering::SeqCst) {
                    break;
                }
                if is_watchdog_high_throughput(&st) {
                    consecutive_fail_counts.clear();
                    break;
                }
                let Some(active_node) = commands::resolve_valid_group_active_node(&group, &nodes)
                else {
                    continue;
                };
                if last_checked_node.get(&group.id).map(String::as_str)
                    != Some(active_node.id.as_str())
                {
                    consecutive_fail_counts.remove(&group.id);
                    failed_group_backoff_until.remove(&group.id);
                    last_checked_node.insert(group.id.clone(), active_node.id.clone());
                }

                if failed_group_backoff_until
                    .get(&group.id)
                    .is_some_and(|until| Instant::now() < *until)
                {
                    continue;
                }

                let compiled_proxy =
                    st.resolve_compiled_proxy_name(&active_node.id, &active_node.name);
                let healthy = probe_compiled_proxy_delay(
                    &http_client,
                    &ctrl_host,
                    rt.controller_port,
                    &secret,
                    &compiled_proxy,
                    4500,
                )
                .await
                .is_some();

                if healthy {
                    // Healthy active node: reset failure counter and stay sticky (zero IP drift).
                    consecutive_fail_counts.remove(&group.id);
                    continue;
                }

                let fail_count = {
                    let entry = consecutive_fail_counts.entry(group.id.clone()).or_insert(0);
                    *entry = entry.saturating_add(1);
                    *entry
                };
                let required_failures = commands::group_watchdog_failure_threshold(&group);
                let cooldown = Duration::from_secs(group.cooldown_sec.max(45));
                let cooldown_elapsed = last_auto_switch_at
                    .get(&group.id)
                    .is_none_or(|last| last.elapsed() >= cooldown);

                if fail_count < required_failures || !cooldown_elapsed {
                    tracing::debug!(
                        group = %group.name,
                        node = %active_node.name,
                        fail_count,
                        required_failures,
                        cooldown_elapsed,
                        "group strategy watchdog recorded probe failure (holding)"
                    );
                    continue;
                }

                // Guard #1 (re-check): abort failover if high-throughput transfer started during probe.
                if is_watchdog_high_throughput(&st) {
                    consecutive_fail_counts.clear();
                    tracing::debug!(
                        group = %group.name,
                        "group strategy watchdog aborted failover: high-throughput transfer active"
                    );
                    continue;
                }

                // Guard #2: record the just-failed active node into 5-minute bounce-back cooldown.
                failed_node_cooldowns.retain(|_, t| t.elapsed() < FAILED_NODE_COOLDOWN);
                failed_node_cooldowns.insert(active_node.id.clone(), Instant::now());
                let cooldown_ids: HashSet<String> =
                    failed_node_cooldowns.keys().cloned().collect();

                // Re-read latest group, nodes, and probe snapshots under a brief sync lock before
                // ranking up to 3 backup candidates (excluding active & 5-minute cooldown nodes).
                let candidate_plan = st.storage.lock().ok().and_then(|db| {
                    let latest_group = db.get_multi_group(&group.id).ok().flatten()?;
                    let latest_nodes = db.list_nodes().ok()?;
                    let latest_active =
                        commands::resolve_valid_group_active_node(&latest_group, &latest_nodes)?;
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
                    let candidate_ids = commands::pick_group_candidates_with_cooldown(
                        &latest_group,
                        &latest_nodes,
                        &snaps,
                        Some(&active_node.id),
                        &cooldown_ids,
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
                    Some((latest_group.id, latest_group.name, candidates))
                });

                let Some((gid, gname, candidates)) = candidate_plan else {
                    continue;
                };

                // Guard #3: sequentially live-probe top 3 candidates outside sync locks (`timeout=3500ms`),
                // placing any failed candidate immediately into 5-minute cooldown and refusing blind switches.
                let mut verified_candidate: Option<(String, String, u64)> = None;
                let probed_total = candidates.len();
                for (cand_id, cand_name, cand_compiled) in candidates {
                    if st.shutting_down.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Some(delay_ms) = probe_compiled_proxy_delay(
                        &http_client,
                        &ctrl_host,
                        rt.controller_port,
                        &secret,
                        &cand_compiled,
                        CANDIDATE_PROBE_TIMEOUT_MS,
                    )
                    .await
                    {
                        verified_candidate = Some((cand_id, cand_name, delay_ms));
                        break;
                    }
                    failed_node_cooldowns.insert(cand_id, Instant::now());
                }

                let Some((next_id, next_name, verified_delay_ms)) = verified_candidate else {
                    consecutive_fail_counts.remove(&gid);
                    let now = Instant::now();
                    last_auto_switch_at.insert(gid.clone(), now);
                    failed_group_backoff_until
                        .insert(gid.clone(), now + ALL_CANDIDATES_FAILED_BACKOFF);
                    st.log_app_event(
                        "warning",
                        "自动切优",
                        &format!(
                            "分组「{gname}」原节点「{}」连续 {fail_count} 次健康探活失败，但顺位前 {probed_total} 个备用候选实测探活均未通过，已记入 5 分钟冷却并进入 180 秒分组退避，放弃盲切",
                            active_node.name
                        ),
                    );
                    continue;
                };

                // Re-check latest user config and high-throughput state right before failover: if
                // user switched to Single/Direct mode or started a large transfer during probing,
                // abort cleanly without interrupting active connections.
                let latest_cfg = st.snapshot_config();
                if latest_cfg.route_mode != RouteTargetMode::Group
                    || latest_cfg.proxy_mode == ProxyMode::Direct
                {
                    continue;
                }
                if is_watchdog_high_throughput(&st) {
                    consecutive_fail_counts.clear();
                    continue;
                }
                // Guard #4: briefly re-verify DB `active_node_id` right before switching so we
                // never overwrite a manual node selection made while backup candidates were probed.
                let still_same_active = st
                    .storage
                    .lock()
                    .ok()
                    .and_then(|db| db.get_multi_group(&gid).ok().flatten())
                    .map(|latest_group| {
                        let unchanged_explicit = latest_group.active_node_id.as_deref()
                            == Some(active_node.id.as_str());
                        let unchanged_implicit = group.active_node_id.is_none()
                            && latest_group.active_node_id.is_none();
                        unchanged_explicit || unchanged_implicit
                    })
                    .unwrap_or(false);
                if !still_same_active {
                    consecutive_fail_counts.remove(&gid);
                    failed_group_backoff_until.remove(&gid);
                    st.log_app_event(
                        "info",
                        "自动切优",
                        &format!(
                            "分组「{gname}」在备用候选探活期间已被手动切换节点，后台守护已放弃本次自动覆盖（原探测节点：{}）",
                            active_node.name
                        ),
                    );
                    continue;
                }
                let _ = is_primary;
                let switch_res = commands::select_group_node_in_place_internal(
                    &app_h,
                    &st,
                    gid.clone(),
                    next_id.clone(),
                    Some(true),
                    Some(active_node.name.clone()),
                )
                .await;

                match switch_res {
                    Ok(_) => {
                        consecutive_fail_counts.remove(&gid);
                        last_auto_switch_at.insert(gid.clone(), Instant::now());
                        last_checked_node.insert(gid.clone(), next_id.clone());
                        let reason = format!(
                            "原节点连续 {fail_count} 次健康探活失败，已验证并自动切换至可用备用节点（{verified_delay_ms} ms）"
                        );
                        st.log_app_event(
                            "warning",
                            "自动切优",
                            &format!(
                                "分组「{gname}」后台健康守护自动切换：{} -> {}（{reason}）",
                                active_node.name, next_name
                            ),
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
    });
}

struct TelemetryForwarderState {
    observed_gen: u64,
    auth_up_total: u64,
    auth_down_total: u64,
    delta_up_since_snap: u64,
    delta_down_since_snap: u64,
    core_mem_bytes: u64,
    active_connections: usize,
    tunnel_connections: usize,
    last_traffic_at: Option<Instant>,
}

impl TelemetryForwarderState {
    fn new(observed_gen: u64) -> Self {
        Self {
            observed_gen,
            auth_up_total: 0,
            auth_down_total: 0,
            delta_up_since_snap: 0,
            delta_down_since_snap: 0,
            core_mem_bytes: 0,
            active_connections: 0,
            tunnel_connections: 0,
            last_traffic_at: None,
        }
    }

    fn reset_if_gen_changed(&mut self, cur_gen: u64) {
        if cur_gen != self.observed_gen {
            self.observed_gen = cur_gen;
            self.auth_up_total = 0;
            self.auth_down_total = 0;
            self.delta_up_since_snap = 0;
            self.delta_down_since_snap = 0;
            self.core_mem_bytes = 0;
            self.active_connections = 0;
            self.tunnel_connections = 0;
            self.last_traffic_at = None;
        }
    }
}

fn spawn_telemetry_forwarders(app: &tauri::AppHandle, state: &AppState) {
    // 1. Traffic & memory forwarder -> emits `catcloud://traffic` only while a GUI window is
    // visible & unminimized, pauses `/connections` polling while hidden/minimized, and updates
    // throttled tray tooltip.
    {
        let app_h = app.clone();
        let mut rx_traffic = state.telemetry.subscribe_traffic();
        let mut rx_memory = state.telemetry.subscribe_memory();
        let initial_gen: u64 = state.core_session_generation();
        tauri::async_runtime::spawn(async move {
            // Track Mihomo's authoritative cumulative totals from `/connections` separately from
            // intra-poll 1Hz `/traffic` deltas so the two sources NEVER double-count each other.
            let mut session = TelemetryForwarderState::new(initial_gen);
            let mut last_tray_sync = Instant::now();
            let mut conn_poll = tokio::time::interval(Duration::from_secs(2));
            conn_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = conn_poll.tick() => {
                        let has_visible_window = lifecycle::has_visible_gui_window(&app_h);
                        if let Some(st) = app_h.try_state::<AppState>() {
                            session.reset_if_gen_changed(st.core_session_generation());
                            let traffic_quiet = session
                                .last_traffic_at
                                .is_none_or(|t| t.elapsed() >= Duration::from_secs(3));
                            if !has_visible_window {
                                if traffic_quiet {
                                    let mut cleared_rate = false;
                                    if let Ok(mut m) = st.cached_metrics.write() {
                                        if m.up_bps != 0 || m.down_bps != 0 {
                                            m.up_bps = 0;
                                            m.down_bps = 0;
                                            cleared_rate = true;
                                        }
                                    }
                                    if cleared_rate {
                                        let _ = tray::sync_tray_visual(
                                            &app_h,
                                            &commands::build_tray_visual_state(&st),
                                        );
                                    }
                                }
                                continue;
                            }
                            if st.adapter.has_live_controller().await && st.snapshot_runtime().running {
                                let req_gen = st.core_session_generation();
                                if let Ok(snap) = st.adapter.list_connections().await {
                                    let cur_gen = st.core_session_generation();
                                    if cur_gen != req_gen || !st.snapshot_runtime().running {
                                        session.reset_if_gen_changed(cur_gen);
                                        continue;
                                    }
                                    session.reset_if_gen_changed(cur_gen);
                                    let conn_summary =
                                        commands::summarize_connections(&snap.connections);
                                    session.active_connections = conn_summary.app_connections;
                                    session.tunnel_connections = conn_summary.tunnel_connections;
                                    if snap.memory > 0 {
                                        session.core_mem_bytes = snap.memory;
                                    }
                                    // Reconcile strictly to Mihomo's authoritative session totals and reset
                                    // the intra-poll delta accumulator to prevent double-counting drift.
                                    if snap.upload_total >= session.auth_up_total {
                                        session.auth_up_total = snap.upload_total;
                                    }
                                    if snap.download_total >= session.auth_down_total {
                                        session.auth_down_total = snap.download_total;
                                    }
                                    session.delta_up_since_snap = 0;
                                    session.delta_down_since_snap = 0;
                                    let quiet_now = session
                                        .last_traffic_at
                                        .is_none_or(|t| t.elapsed() >= Duration::from_secs(3));
                                    if let Ok(mut m) = st.cached_metrics.write() {
                                        m.up_total_bytes = session.auth_up_total;
                                        m.down_total_bytes = session.auth_down_total;
                                        m.core_mem_bytes = session.core_mem_bytes;
                                        m.app_connections = conn_summary.app_connections;
                                        m.tunnel_connections = conn_summary.tunnel_connections;
                                        m.direct_connections = conn_summary.direct_connections;
                                        m.proxied_connections = conn_summary.proxied_connections;
                                        if quiet_now {
                                            m.up_bps = 0;
                                            m.down_bps = 0;
                                        }
                                    }
                                    // Only emit a zero-rate heartbeat if `/traffic` WS has been quiet,
                                    // avoiding duplicate points or replaying stale spike rates.
                                    if quiet_now && lifecycle::has_visible_gui_window(&app_h) {
                                        let payload = TrafficEventPayload {
                                            up_bps: 0,
                                            down_bps: 0,
                                            up_total_bytes: session.auth_up_total,
                                            down_total_bytes: session.auth_down_total,
                                            active_connections: session.active_connections,
                                            tunnel_connections: session.tunnel_connections,
                                            core_memory_mb: (session.core_mem_bytes as f64) / (1024.0 * 1024.0),
                                            timestamp_ms: chrono::Utc::now().timestamp_millis(),
                                        };
                                        let _ = app_h.emit(commands::EVENT_TRAFFIC, payload);
                                        if last_tray_sync.elapsed() >= Duration::from_secs(3) {
                                            last_tray_sync = Instant::now();
                                            let _ = tray::sync_tray_visual(
                                                &app_h,
                                                &commands::build_tray_visual_state(&st),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    res = rx_memory.recv() => match res {
                        Ok(mem) => {
                            if let Some(st) = app_h.try_state::<AppState>() {
                                session.reset_if_gen_changed(st.core_session_generation());
                                if mem.inuse > 0 {
                                    session.core_mem_bytes = mem.inuse;
                                }
                                if let Ok(mut m) = st.cached_metrics.write() {
                                    m.core_mem_bytes = session.core_mem_bytes;
                                }
                            } else if mem.inuse > 0 {
                                session.core_mem_bytes = mem.inuse;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    },
                    res = rx_traffic.recv() => match res {
                        Ok(tick) => {
                            if let Some(st) = app_h.try_state::<AppState>() {
                                session.reset_if_gen_changed(st.core_session_generation());
                                if !st.snapshot_runtime().running {
                                    continue;
                                }
                                session.last_traffic_at = Some(Instant::now());
                                session.delta_up_since_snap = session.delta_up_since_snap.saturating_add(tick.up);
                                session.delta_down_since_snap = session.delta_down_since_snap.saturating_add(tick.down);
                                if let Ok(mut m) = st.cached_metrics.write() {
                                    m.up_bps = tick.up;
                                    m.down_bps = tick.down;
                                    m.up_total_bytes = session
                                        .auth_up_total
                                        .saturating_add(session.delta_up_since_snap);
                                    m.down_total_bytes = session
                                        .auth_down_total
                                        .saturating_add(session.delta_down_since_snap);
                                    m.core_mem_bytes = session.core_mem_bytes;
                                }
                                if lifecycle::has_visible_gui_window(&app_h) {
                                    let payload = TrafficEventPayload {
                                        up_bps: tick.up,
                                        down_bps: tick.down,
                                        up_total_bytes: session.auth_up_total.saturating_add(session.delta_up_since_snap),
                                        down_total_bytes: session.auth_down_total.saturating_add(session.delta_down_since_snap),
                                        active_connections: session.active_connections,
                                        tunnel_connections: session.tunnel_connections,
                                        core_memory_mb: (session.core_mem_bytes as f64) / (1024.0 * 1024.0),
                                        timestamp_ms: tick.timestamp_ms,
                                    };
                                    let _ = app_h.emit(commands::EVENT_TRAFFIC, payload);
                                }
                                if last_tray_sync.elapsed() >= Duration::from_secs(3) {
                                    last_tray_sync = Instant::now();
                                    let _ = tray::sync_tray_visual(&app_h, &commands::build_tray_visual_state(&st));
                                }
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    },
                }
            }
        });
    }

    // 2. Core log forwarder -> persists Mihomo warn/error and throttled info lines to rotating
    // `catcloud.log`, and emits `catcloud://core-log` only while the main window is visible.
    {
        let app_h = app.clone();
        let mut rx_logs = state.telemetry.subscribe_logs();
        tauri::async_runtime::spawn(async move {
            let mut last_info_persisted: Option<Instant> = None;
            loop {
                match rx_logs.recv().await {
                    Ok(line) => {
                        if let Some(st) = app_h.try_state::<AppState>() {
                            let now = Instant::now();
                            if app_log::should_persist_mihomo_log(
                                &line.level,
                                &line.payload,
                                last_info_persisted,
                                now,
                            ) {
                                if app_log::normalize_log_level(&line.level) == "info" {
                                    last_info_persisted = Some(now);
                                }
                                st.app_logger.append_formatted(
                                    &line.timestamp,
                                    &line.level,
                                    "mihomo",
                                    &line.payload,
                                );
                            }
                        }
                        if lifecycle::is_main_window_visible(&app_h) {
                            let _ = app_h.emit(commands::EVENT_CORE_LOG, line);
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }
}

/// Decide whether the background auto-update loop should run a remote check at `now`.
fn should_run_auto_update_check(
    cfg: &UpdateConfig,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    if cfg.mode == UpdateApplyMode::Manual {
        return false;
    }
    let min_interval_min = cfg.check_interval_min.clamp(30, 365 * 24 * 60) as i64;
    let Some(raw_last) = cfg
        .last_checked_at
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return true;
    };
    let Ok(parsed_last) = chrono::DateTime::parse_from_rfc3339(raw_last) else {
        return true;
    };
    let elapsed = now.signed_duration_since(parsed_last.with_timezone(&chrono::Utc));
    elapsed >= chrono::Duration::minutes(min_interval_min)
}

fn spawn_auto_update_loop(app: &tauri::AppHandle) {
    let app_h = app.clone();
    tauri::async_runtime::spawn(async move {
        // Strict cold-start zero-traffic guard: stay completely silent for 45 seconds after launch
        // so 5s idle GUI startup audits observe 0 outbound update requests.
        const INITIAL_SILENT_DELAY: Duration = Duration::from_secs(45);
        const WAKE_INTERVAL: Duration = Duration::from_secs(15 * 60);

        tokio::time::sleep(INITIAL_SILENT_DELAY).await;

        loop {
            let Some(st) = app_h.try_state::<AppState>() else {
                break;
            };
            if st.shutting_down.load(Ordering::SeqCst) {
                break;
            }

            let cfg = st.snapshot_config();
            if should_run_auto_update_check(&cfg.update, chrono::Utc::now()) {
                let allow_auto_stage =
                    cfg.update.auto_download && cfg.update.mode != UpdateApplyMode::Manual;
                match commands::check_and_optionally_stage_update_internal(
                    &app_h,
                    &st,
                    allow_auto_stage,
                )
                .await
                {
                    Ok(res) => {
                        if let Some(err) = res.get("error").and_then(|v| v.as_str()) {
                            tracing::debug!("background auto-update check skipped/failed: {err}");
                        } else if res
                            .get("has_update")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false)
                        {
                            let latest = res
                                .get("latest_version")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let auto_staged = res
                                .get("auto_staged")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            let staged_ver = res.get("staged_version").and_then(|v| v.as_str());
                            if !auto_staged && staged_ver.is_none() && !latest.is_empty() {
                                st.log_app_event(
                                    "info",
                                    "软件更新",
                                    &format!(
                                        "后台自动检查发现新版本 v{latest}（当前 v{}），可在设置页查看并更新",
                                        env!("CARGO_PKG_VERSION")
                                    ),
                                );
                            }
                        }
                        commands::emit_runtime_snapshot(&app_h, &st);
                    }
                    Err(err) => {
                        tracing::debug!("background auto-update loop error: {err}");
                    }
                }
            }

            tokio::time::sleep(WAKE_INTERVAL).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_run_auto_update_check_respects_manual_mode_and_min_interval() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-11-24T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let mut cfg = UpdateConfig::default();
        cfg.mode = UpdateApplyMode::Manual;
        cfg.last_checked_at = None;
        assert!(!should_run_auto_update_check(&cfg, now));

        cfg.mode = UpdateApplyMode::NextLaunch;
        assert!(should_run_auto_update_check(&cfg, now));

        // Check interval enforces a 30-minute minimum floor even if configured smaller.
        cfg.check_interval_min = 5;
        cfg.last_checked_at = Some("2026-11-24T11:31:00Z".to_string());
        assert!(!should_run_auto_update_check(&cfg, now));
        cfg.last_checked_at = Some("2026-11-24T11:30:00Z".to_string());
        assert!(should_run_auto_update_check(&cfg, now));

        // Standard 360-minute interval boundary.
        cfg.check_interval_min = 360;
        cfg.last_checked_at = Some("2026-11-24T06:01:00Z".to_string());
        assert!(!should_run_auto_update_check(&cfg, now));
        cfg.last_checked_at = Some("2026-11-24T06:00:00Z".to_string());
        assert!(should_run_auto_update_check(&cfg, now));

        // Future timestamp (clock skew) must not storm checks; malformed timestamp falls back to due.
        cfg.last_checked_at = Some("2026-11-24T13:00:00Z".to_string());
        assert!(!should_run_auto_update_check(&cfg, now));
        cfg.last_checked_at = Some("not-a-timestamp".to_string());
        assert!(should_run_auto_update_check(&cfg, now));
    }
}
