pub mod app_log;
pub mod commands;
pub mod lan_sync;
pub mod lifecycle;
pub mod shortcuts;
pub mod tray;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use catcloud_core::config;
use catcloud_core::models::{
    MultiGroup, MultiGroupMode, ProbeSnapshot, ProxyMode, ProxyNode, RouteTargetMode, SwitchMode,
    UpdateApplyMode, UpdateConfig,
};
use catcloud_core::platform::default_platform;
use catcloud_core::process_guard::{
    AcquireOutcome, JobGuard, SingleInstanceGuard, spawn_detached_self,
};
use catcloud_core::storage::Storage;
use catcloud_core::strategy::evaluator::evaluate_group_candidates_with_runtime;
use catcloud_core::strategy::health_pool::{
    NodeHealthPool, RuntimeDualHealth, WatchdogCandidateTrace, WatchdogCooldownNodeEntry,
    WatchdogDecisionEvent, WatchdogGroupBackoffEntry, WatchdogStateSnapshot,
    read_watchdog_state_snapshot, write_watchdog_state_snapshot,
};
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

fn is_one_shot_launch_flag(arg: &str) -> bool {
    matches!(
        arg,
        "--apply-staged-update" | "--silent" | "--enable-tun" | "--enable-global-preaccel"
    )
}

fn build_post_update_cleanup_relaunch_args(
    outcome_args: &[String],
    current_raw_args: &[std::ffi::OsString],
) -> Vec<String> {
    let mut relaunch_args: Vec<String> = Vec::new();
    let mut has_data_dir = false;

    let mut i = 0usize;
    while i < outcome_args.len() {
        let arg = outcome_args[i].as_str();
        if is_one_shot_launch_flag(arg) {
            i += 1;
            continue;
        }
        if arg == "--data-dir" {
            if let Some(val) = outcome_args.get(i + 1) {
                if !val.trim().is_empty() {
                    relaunch_args.push("--data-dir".to_string());
                    relaunch_args.push(val.clone());
                    has_data_dir = true;
                }
                i += 2;
            } else {
                // Drop a dangling trailing `--data-dir` without a value argument.
                i += 1;
            }
            continue;
        } else if let Some(rest) = arg.strip_prefix("--data-dir=") {
            if !rest.trim().is_empty() {
                relaunch_args.push(arg.to_string());
                has_data_dir = true;
            }
            i += 1;
            continue;
        }
        if !relaunch_args.iter().any(|existing| existing == arg) {
            relaunch_args.push(arg.to_string());
        }
        i += 1;
    }

    if !has_data_dir {
        let mut j = 0usize;
        while j < current_raw_args.len() {
            let arg = current_raw_args[j].to_string_lossy();
            if arg == "--data-dir" {
                if let Some(val) = current_raw_args.get(j + 1) {
                    let val_str = val.to_string_lossy().into_owned();
                    if !val_str.trim().is_empty() {
                        relaunch_args.push("--data-dir".to_string());
                        relaunch_args.push(val_str);
                        break;
                    }
                }
                j += 2;
                continue;
            } else if let Some(rest) = arg.strip_prefix("--data-dir=") {
                if !rest.trim().is_empty() {
                    relaunch_args.push(arg.into_owned());
                    break;
                }
            }
            j += 1;
        }
    }

    if !relaunch_args.iter().any(|a| a == "--post-update-cleanup") {
        relaunch_args.push("--post-update-cleanup".to_string());
    }
    if !relaunch_args.iter().any(|a| a == "--restarting") {
        relaunch_args.push("--restarting".to_string());
    }

    relaunch_args
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
            let current_raw_args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
            let relaunch_args = build_post_update_cleanup_relaunch_args(
                &outcome.relaunch_args,
                &current_raw_args,
            );
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
    let apply_staged_update_flag = has_cli_flag("--apply-staged-update");
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

    // Apply any verified staged portable update ONLY when explicitly invoked via
    // `--apply-staged-update` (after user confirmation in the update prompt or settings).
    if apply_staged_update_flag
        && !post_update_cleanup
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
    let mut cfg = config::load_or_init(&paths).unwrap_or_default();
    cfg.preaccel.reconcile_unified_enabled();
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
            commands::disable_all_proxy_and_stop_core,
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
            commands::capsule_drag_start,
            commands::capsule_drag_step,
            commands::capsule_drag_end,
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
            commands::rename_subscription,
            commands::apply_nodes_to_existing_subscription,
            commands::merge_subscriptions,
            commands::export_share_bundle_dialog,
            commands::pick_and_preview_share_bundle,
            commands::import_share_bundle,
            commands::start_sync_send_session,
            commands::cancel_sync_send_session,
            commands::export_encrypted_sync_file,
            commands::start_sync_receive_listener,
            commands::cancel_sync_receive_session,
            commands::preview_sync_source,
            commands::apply_sync_import,
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
            commands::verify_global_preaccel,
            commands::relaunch_as_admin_for_global_preaccel,
            commands::select_preaccel_relay,
            commands::failover_preaccel,
            commands::test_preaccel_relays,
            commands::test_preaccel_relay_speeds,
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
            commands::build_agent_bootstrap_prompt,
            commands::export_agent_doc_file_dialog,
            commands::build_github_issue_url,
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
            commands::list_desktop_app_candidates,
            commands::start_live_capture_session,
            commands::poll_live_capture_session,
            commands::finish_live_capture_session,
            commands::cancel_live_capture_session,
            commands::export_shell_env,
            commands::export_sanitized_diagnostics,
            commands::build_ai_onboarding_prompt,
            commands::get_geodata_status,
            commands::refresh_geo_db,
            commands::check_app_update,
            commands::download_and_stage_update,
            commands::get_pending_staged_update,
            commands::dismiss_update_prompt_for_session,
            commands::skip_update_version,
            commands::clear_skipped_update_version,
            commands::apply_staged_update_and_restart,
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

            // Asynchronously synchronize multi-language authoritative Agent manuals into
            // `<data_dir>/agent_docs/` with `.manifest_hash` idempotent short-circuiting
            // so desktop cold startup is never blocked by disk I/O.
            {
                let docs_root_data_dir = state.paths.root_data_dir.clone();
                tauri::async_runtime::spawn(async move {
                    let res = tokio::task::spawn_blocking(move || {
                        catcloud_core::agent_docs::sync_agent_docs_to_disk(&docs_root_data_dir)
                    })
                    .await;
                    match res {
                        Ok(Ok(_)) => {}
                        Ok(Err(err)) => {
                            tracing::debug!("background agent_docs sync skipped/failed: {err}");
                        }
                        Err(err) => {
                            tracing::debug!("background agent_docs sync task join failed: {err}");
                        }
                    }
                });
            }

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
                                let cfg = st.snapshot_config();
                                // Use effective (privileged) TUN state so clicking TUN while unprivileged
                                // triggers NEEDS_ADMIN elevation flow instead of silently disabling intent.
                                let next_enabled = !commands::effective_tun_enabled(&st, &cfg);
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
                    TrayAction::TogglePreAccel | TrayAction::ToggleGlobalPreAccel => {
                        tauri::async_runtime::spawn(async move {
                            if let Some(st) = app_async.try_state::<AppState>() {
                                let next = !st.snapshot_config().preaccel.enabled;
                                let _ =
                                    commands::toggle_preaccel_internal(&app_async, &st, next).await;
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
                            let _cfg_guard = st.config_transition_lock.lock().await;
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
                        let eff_tun = commands::effective_tun_enabled(&st, &cfg);
                        if cfg.tun.enabled && !eff_tun {
                            st.log_app_event(
                                "warning",
                                "虚拟网卡",
                                "配置已启用虚拟网卡（TUN），但当前为普通用户权限未生效（依赖虚拟网卡的桌面应用/终端可能无法走代理）；如需启用请在界面点击「以管理员重启」",
                            );
                        }
                        if !(cfg.system_proxy.enabled || eff_tun) {
                            tracing::info!(
                                "auto-start core skipped: system_proxy and effective tun are both disabled"
                            );
                            if !enable_global_preaccel_flag
                                && cfg.preaccel.enabled
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
                                                "启动时自动恢复独立底层国内提速（模式：{}）",
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
                            let _cfg_guard = st.config_transition_lock.lock().await;
                            let latest_cfg = st.snapshot_config();
                            let latest_eff_tun = commands::effective_tun_enabled(&st, &latest_cfg);
                            if (latest_cfg.system_proxy.enabled || latest_eff_tun)
                                && !st.adapter.has_live_controller().await
                            {
                                if let Err(err) = commands::start_core_internal(&auto_handle, &st).await {
                                    tracing::info!("auto-start core skipped: {err}");
                                }
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
            // Skip tick while a config/proxy/TUN transition or core reload is in progress so
            // ProxyGuard never reports spurious drift mid-transition.
            let Ok(_cfg_guard) = Arc::clone(&st.config_transition_lock).try_lock_owned() else {
                continue;
            };
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

fn resolve_node_compiled_proxy(st: &AppState, nodes: &[ProxyNode], node_id: &str) -> String {
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
                    let nodes = db.list_nodes().ok()?;
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
                ) && commands::count_enabled_group_members(g, &nodes) >= 2;
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
                let Some(active_node) = commands::resolve_valid_group_active_node(group, &nodes)
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
                let Some(active_node) = commands::resolve_valid_group_active_node(&group, &nodes)
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
                                        let close_old_override = match trigger {
                                            WatchdogFailoverTrigger::SustainedDegraded { .. } => {
                                                Some(false)
                                            }
                                            WatchdogFailoverTrigger::TotalOutage { .. } => None,
                                        };
                                        let keep_existing_connections = match close_old_override {
                                            Some(close_old) => !close_old,
                                            None => matches!(
                                                latest_group.switch_mode,
                                                SwitchMode::GracefulNewOnly
                                            ),
                                        };
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
                let member_ids = collect_enabled_group_member_ids(&group, &nodes);
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
                            let sanitized_line = commands::sanitize_core_log_line(line);
                            let _ = app_h.emit(commands::EVENT_CORE_LOG, sanitized_line);
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
                    true,
                )
                .await
                {
                    Ok(res) => {
                        let is_skipped = res
                            .get("skipped")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        if let Some(err) = res.get("error").and_then(|v| v.as_str()) {
                            tracing::debug!("background auto-update check skipped/failed: {err}");
                        } else if is_skipped {
                            tracing::debug!("background auto-update check matched skipped version");
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
                            let auto_stage_reused = res
                                .get("auto_stage_reused")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            let staged_ver = res.get("staged_version").and_then(|v| v.as_str());
                            if auto_staged && !auto_stage_reused {
                                if !st.shutting_down.load(Ordering::SeqCst) {
                                    if let Ok(Some(prompt_dto)) =
                                        commands::get_pending_staged_update_internal(&st).await
                                    {
                                        let _ = app_h.emit(
                                            commands::EVENT_UPDATE_READY,
                                            &prompt_dto,
                                        );
                                    }
                                }
                            } else if !auto_staged && staged_ver.is_none() && !latest.is_empty() {
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
    fn event_core_log_sanitizer_masks_fictional_ips_and_secrets() {
        let raw = catcloud_core::core_adapter::CoreLogLine {
            level: "warning".to_string(),
            payload: "[TCP] 192.168.10.22:54321 --> 203.0.113.88:443 via 198.18.0.9 dns 223.5.5.5 token=super_secret_xyz".to_string(),
            timestamp: "2026-11-26T04:00:00Z".to_string(),
        };
        let sanitized = commands::sanitize_core_log_line(raw);
        for leaked in [
            "192.168.10.22",
            "203.0.113.88",
            "198.18.0.9",
            "223.5.5.5",
            "super_secret_xyz",
        ] {
            assert!(
                !sanitized.payload.contains(leaked),
                "EVENT_CORE_LOG sanitizer leaked `{leaked}`: {}",
                sanitized.payload
            );
        }
        assert!(sanitized.payload.contains("192.168.10.*"));
        assert!(sanitized.payload.contains("203.0.113.*"));
        assert!(sanitized.payload.contains("198.18.0.*"));
        assert!(sanitized.payload.contains("223.5.5.*"));
        assert!(sanitized.payload.contains("token=<REDACTED>"));
    }

    #[test]
    fn post_update_cleanup_relaunch_args_preserves_data_dir_and_strips_one_shot_flags() {
        use std::ffi::OsString;

        let current_args = vec![
            OsString::from("--data-dir"),
            OsString::from(r"D:\CustomData\CatCloud"),
            OsString::from("--apply-staged-update"),
            OsString::from("--silent"),
            OsString::from("--enable-tun"),
            OsString::from("--enable-global-preaccel"),
            OsString::from("--restarting"),
        ];
        let outcome_args = vec![
            "--apply-staged-update".to_string(),
            "--silent".to_string(),
            "--enable-tun".to_string(),
            "--enable-global-preaccel".to_string(),
            "--post-update-cleanup".to_string(),
        ];

        let built = build_post_update_cleanup_relaunch_args(&outcome_args, &current_args);
        assert_eq!(
            built,
            vec![
                "--post-update-cleanup".to_string(),
                "--data-dir".to_string(),
                r"D:\CustomData\CatCloud".to_string(),
                "--restarting".to_string(),
            ]
        );

        // Supports `--data-dir=<path>` form as well and never duplicates `--data-dir`.
        let eq_current_args = vec![OsString::from("--data-dir=/tmp/catcloud-portable")];
        let built_eq = build_post_update_cleanup_relaunch_args(&[], &eq_current_args);
        assert_eq!(
            built_eq,
            vec![
                "--data-dir=/tmp/catcloud-portable".to_string(),
                "--post-update-cleanup".to_string(),
                "--restarting".to_string(),
            ]
        );

        // When outcome_args already carries `--data-dir`, current_args must not append a duplicate.
        let outcome_with_dir = vec![
            "--data-dir".to_string(),
            "/var/lib/catcloud".to_string(),
        ];
        let built_dedup =
            build_post_update_cleanup_relaunch_args(&outcome_with_dir, &eq_current_args);
        assert_eq!(
            built_dedup,
            vec![
                "--data-dir".to_string(),
                "/var/lib/catcloud".to_string(),
                "--post-update-cleanup".to_string(),
                "--restarting".to_string(),
            ]
        );

        // A dangling trailing `--data-dir` without a following value must be dropped rather than
        // forwarded verbatim (and still allows fallback to `current_raw_args` when available).
        let dangling_outcome = vec!["--post-update-cleanup".to_string(), "--data-dir".to_string()];
        let built_dangling_empty = build_post_update_cleanup_relaunch_args(&dangling_outcome, &[]);
        assert_eq!(
            built_dangling_empty,
            vec![
                "--post-update-cleanup".to_string(),
                "--restarting".to_string(),
            ]
        );
        let built_dangling_fallback =
            build_post_update_cleanup_relaunch_args(&dangling_outcome, &eq_current_args);
        assert_eq!(
            built_dangling_fallback,
            vec![
                "--post-update-cleanup".to_string(),
                "--data-dir=/tmp/catcloud-portable".to_string(),
                "--restarting".to_string(),
            ]
        );
    }
}
