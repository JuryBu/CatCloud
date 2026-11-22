pub mod commands;
pub mod lifecycle;
pub mod shortcuts;
pub mod tray;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use catcloud_core::config;
use catcloud_core::models::{AppConfig, ProxyMode, TrayClickAction as CoreTrayClickAction};
use catcloud_core::process_guard::{
    AcquireOutcome, JobGuard, SingleInstanceGuard, spawn_detached_self,
};
use catcloud_core::storage::Storage;
use catcloud_core::AppPaths;
use tauri::{Emitter, Manager};

use crate::commands::{AppState, TrafficEventPayload};
use crate::lifecycle::WindowLifecycleState;
use crate::shortcuts::{ShortcutAction, ShortcutBindings};
use crate::tray::{TrayAction, TrayClickAction, TrayOpenDirKind, TrayProxyMode};

/// Default entry point used when launched without pre-resolved `AppPaths`.
pub fn run() {
    catcloud_core::init_crypto_provider();
    let cli_data_dir = AppPaths::parse_cli_data_dir_from_args();
    let paths =
        AppPaths::resolve(cli_data_dir).expect("failed to resolve CatCloud runtime paths");
    // SAFETY: Fallback entrypoint before Tauri threads spawn.
    unsafe {
        lifecycle::set_webview2_user_data_env(&paths);
    }
    run_with_paths(paths);
}

fn has_cli_flag(flag: &str) -> bool {
    std::env::args().skip(1).any(|a| a == flag)
}

fn map_tray_click(action: &CoreTrayClickAction) -> TrayClickAction {
    match action {
        CoreTrayClickAction::ToggleCapsule => TrayClickAction::ToggleCapsule,
        CoreTrayClickAction::None => TrayClickAction::ShowMenu,
        _ => TrayClickAction::ToggleMain,
    }
}

fn shortcut_bindings_from_config(cfg: &AppConfig) -> ShortcutBindings {
    if !cfg.behavior.hotkeys.enabled {
        return ShortcutBindings {
            switch_next_best: None,
            toggle_capsule: None,
            toggle_main_window: None,
            toggle_system_proxy: None,
        };
    }
    ShortcutBindings {
        switch_next_best: cfg.behavior.hotkeys.switch_next_best.clone(),
        toggle_capsule: cfg.behavior.hotkeys.toggle_capsule.clone(),
        toggle_main_window: cfg.behavior.hotkeys.show_main_window.clone(),
        toggle_system_proxy: cfg.behavior.hotkeys.toggle_system_proxy.clone(),
    }
}

fn try_apply_staged_portable_update(paths: &AppPaths) -> bool {
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
    if !post_update_cleanup && paths.is_portable && try_apply_staged_portable_update(&paths) {
        if let Some(mut guard) = instance_guard {
            guard.release();
        }
        return;
    }

    let job_guard = Arc::new(JobGuard::new().expect("failed to initialize process JobGuard"));
    let cfg = config::load_or_init(&paths).unwrap_or_default();
    let mut storage = Storage::open(&paths.db_path).expect("failed to open CatCloud SQLite store");
    let _ = storage.seed_builtin_probes();

    let destroy_on_close = cfg.behavior.minimize_to_tray_on_close;
    let silent_start = silent_flag || cfg.behavior.silent_start;
    let tray_click = map_tray_click(&cfg.behavior.tray_click_action);
    let hotkey_bindings = shortcut_bindings_from_config(&cfg);

    let app_state = AppState::new(paths.clone(), cfg, storage, Arc::clone(&job_guard));

    let mut context = tauri::generate_context!();
    lifecycle::apply_portable_overrides(&mut context, &paths);

    let instance_guard_slot = Arc::new(Mutex::new(instance_guard));
    let wake_guard_ref = Arc::clone(&instance_guard_slot);
    let exit_guard_ref = Arc::clone(&instance_guard_slot);
    let exit_job_ref = Arc::clone(&job_guard);

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--silent"]),
        ))
        .plugin(shortcuts::build_plugin())
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
            commands::switch_next_best_node,
            commands::select_group_node,
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
            commands::list_subscriptions,
            commands::upsert_subscription,
            commands::delete_subscription,
            commands::refresh_subscription,
            commands::refresh_all_subscriptions,
            commands::list_preaccel_relays,
            commands::upsert_preaccel_relay,
            commands::delete_preaccel_relay,
            commands::toggle_preaccel,
            commands::select_preaccel_relay,
            commands::failover_preaccel,
            commands::test_preaccel_relays,
            commands::check_campus_portal,
            commands::get_exit_ip_info,
            commands::check_quick_sites,
            commands::get_active_connections,
            commands::close_connection,
            commands::close_group_connections,
            commands::close_all_connections,
            commands::get_recent_logs,
            commands::list_agent_docs,
            commands::export_agent_docs,
            commands::validate_formula_expr,
            commands::evaluate_multi_group,
            commands::compile_preview_yaml,
            commands::import_mmrelay_input,
            commands::scan_local_migrations,
            commands::preview_migration_from_text,
            commands::apply_migration_nodes,
            commands::list_running_processes,
            commands::inspect_process_source,
            commands::export_shell_env,
            commands::export_sanitized_diagnostics,
            commands::refresh_geo_db,
            commands::check_app_update,
            commands::export_backup_bundle,
            commands::import_backup_bundle,
            commands::launch_uwp_loopback,
            commands::hot_swap_core,
            commands::open_app_dir,
            commands::open_web_ui,
        ])
        .on_window_event(lifecycle::handle_window_event_with_state)
        .setup(move |app| {
            let handle = app.handle().clone();

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
                                let _ = commands::set_tun_enabled(
                                    app_async.clone(),
                                    st,
                                    next_enabled,
                                )
                                .await;
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
                                let _ = commands::toggle_preaccel(app_async.clone(), st, next).await;
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
                            let snippet =
                                commands::export_shell_env(st, "powershell".to_string());
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

            let _ = shortcuts::register_shortcuts(&handle, &hotkey_bindings, |app_h, action| {
                let app_async = app_h.clone();
                match action {
                    ShortcutAction::ToggleCapsule => lifecycle::toggle_capsule_window(app_h),
                    ShortcutAction::ToggleMainWindow => {
                        if lifecycle::window_mode_snapshot(app_h).main_open {
                            lifecycle::enter_windowless_mode(app_h);
                        } else {
                            lifecycle::show_or_rebuild_main_window(app_h);
                        }
                    }
                    ShortcutAction::ToggleSystemProxy => {
                        tauri::async_runtime::spawn(async move {
                            if let Some(st) = app_async.try_state::<AppState>() {
                                let next = !st.snapshot_config().system_proxy.enabled;
                                let _ = commands::apply_system_proxy_internal(
                                    &app_async, &st, next,
                                )
                                .await;
                            }
                        });
                    }
                    ShortcutAction::SwitchNextBestNode => {
                        tauri::async_runtime::spawn(async move {
                            if let Some(st) = app_async.try_state::<AppState>() {
                                let _ = commands::switch_next_best_internal(
                                    &app_async,
                                    &st,
                                    "default".to_string(),
                                )
                                .await;
                            }
                        });
                    }
                }
            });

            if silent_start {
                lifecycle::enter_pure_windowless_mode(&handle);
            }

            Ok(())
        })
        .build(context)
        .expect("failed to build CatCloud desktop application");

    let mut cleanup = Some(move || {
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

fn spawn_telemetry_forwarders(app: &tauri::AppHandle, state: &AppState) {
    // 1. Traffic & memory forwarder -> emits `catcloud://traffic` and updates throttled tray tooltip.
    {
        let app_h = app.clone();
        let mut rx_traffic = state.telemetry.subscribe_traffic();
        let mut rx_memory = state.telemetry.subscribe_memory();
        tauri::async_runtime::spawn(async move {
            let mut up_total: u64 = 0;
            let mut down_total: u64 = 0;
            let mut core_mem_bytes: u64 = 0;
            let mut last_tray_sync = Instant::now();

            loop {
                tokio::select! {
                    res = rx_memory.recv() => match res {
                        Ok(mem) => {
                            core_mem_bytes = mem.inuse;
                            if let Some(st) = app_h.try_state::<AppState>() {
                                if let Ok(mut m) = st.cached_metrics.write() {
                                    m.core_mem_bytes = core_mem_bytes;
                                }
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    },
                    res = rx_traffic.recv() => match res {
                        Ok(tick) => {
                            up_total = up_total.saturating_add(tick.up);
                            down_total = down_total.saturating_add(tick.down);
                            if let Some(st) = app_h.try_state::<AppState>() {
                                if let Ok(mut m) = st.cached_metrics.write() {
                                    m.up_bps = tick.up;
                                    m.down_bps = tick.down;
                                    m.core_mem_bytes = core_mem_bytes;
                                }
                                let payload = TrafficEventPayload {
                                    up_bps: tick.up,
                                    down_bps: tick.down,
                                    up_total_bytes: up_total,
                                    down_total_bytes: down_total,
                                    active_connections: 0,
                                    core_memory_mb: (core_mem_bytes as f64) / (1024.0 * 1024.0),
                                    timestamp_ms: tick.timestamp_ms,
                                };
                                let _ = app_h.emit(commands::EVENT_TRAFFIC, payload);
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

    // 2. Core log forwarder -> emits `catcloud://core-log` only while main window is open.
    {
        let app_h = app.clone();
        let mut rx_logs = state.telemetry.subscribe_logs();
        tauri::async_runtime::spawn(async move {
            loop {
                match rx_logs.recv().await {
                    Ok(line) => {
                        if lifecycle::window_mode_snapshot(&app_h).main_open {
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
