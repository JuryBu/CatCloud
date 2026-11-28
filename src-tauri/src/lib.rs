pub mod app_log;
pub mod commands;
pub mod lan_sync;
pub mod lifecycle;
pub mod shortcuts;
mod telemetry_loop;
pub mod tray;
mod watchdog;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use catcloud_core::config;
use catcloud_core::models::{ProxyMode, UpdateApplyMode, UpdateConfig};
use catcloud_core::platform::default_platform;
use catcloud_core::process_guard::{
    AcquireOutcome, JobGuard, SingleInstanceGuard, spawn_detached_self,
};
use catcloud_core::storage::Storage;
use catcloud_core::AppPaths;
use tauri::{Emitter, Manager};

use crate::commands::AppState;
use crate::lifecycle::WindowLifecycleState;
use crate::tray::{TrayAction, TrayOpenDirKind, TrayProxyMode};

/// Default entry point used when launched without pre-resolved `AppPaths`.
pub fn run() {
    if has_shutdown_existing_cli_flag() {
        let _ = handle_shutdown_existing_readonly();
        return;
    }
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

/// Return `true` when the process was launched with `--shutdown-existing`.
pub fn has_shutdown_existing_cli_flag() -> bool {
    has_cli_flag("--shutdown-existing")
}

fn standard_os_data_dir_readonly() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            if !appdata.trim().is_empty() {
                return PathBuf::from(appdata).join("CatCloud");
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            if !home.trim().is_empty() {
                return PathBuf::from(home)
                    .join("Library")
                    .join("Application Support")
                    .join("CatCloud");
            }
        }
    }
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        if !xdg.trim().is_empty() {
            return PathBuf::from(xdg).join("catcloud");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.trim().is_empty() {
            return PathBuf::from(home).join(".local").join("share").join("catcloud");
        }
    }
    PathBuf::from("data")
}

fn canonical_or_normalized_readonly(path: &Path) -> PathBuf {
    if let Ok(canon) = std::fs::canonicalize(path) {
        return catcloud_core::paths::normalize_os_path(&canon);
    }
    if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
        if let Ok(canon_parent) = std::fs::canonicalize(parent) {
            return catcloud_core::paths::normalize_os_path(&canon_parent.join(name));
        }
    }
    catcloud_core::paths::normalize_os_path(path)
}

fn paths_equal_normalized_readonly(a: &Path, b: &Path) -> bool {
    #[cfg(target_os = "windows")]
    {
        use std::path::Component;
        let a_comps: Vec<Component<'_>> = a.components().collect();
        let b_comps: Vec<Component<'_>> = b.components().collect();
        if a_comps.is_empty() || a_comps.len() != b_comps.len() {
            return false;
        }
        a_comps.iter().zip(b_comps.iter()).all(|(ac, bc)| match (ac, bc) {
            (Component::Normal(x), Component::Normal(y)) => {
                x.to_string_lossy().eq_ignore_ascii_case(&y.to_string_lossy())
            }
            (Component::Prefix(x), Component::Prefix(y)) => x
                .as_os_str()
                .to_string_lossy()
                .eq_ignore_ascii_case(&y.as_os_str().to_string_lossy()),
            (x, y) => x == y,
        })
    }
    #[cfg(not(target_os = "windows"))]
    {
        !a.as_os_str().is_empty() && a == b
    }
}

fn path_is_within_dir_readonly(child: &Path, parent: &Path) -> bool {
    #[cfg(target_os = "windows")]
    {
        use std::path::Component;
        let parent_comps: Vec<Component<'_>> = parent.components().collect();
        if parent_comps.is_empty() {
            return false;
        }
        let child_comps: Vec<Component<'_>> = child.components().collect();
        if child_comps.len() < parent_comps.len() {
            return false;
        }
        parent_comps
            .iter()
            .zip(child_comps.iter())
            .all(|(p, c)| match (p, c) {
                (Component::Normal(a), Component::Normal(b)) => {
                    a.to_string_lossy().eq_ignore_ascii_case(&b.to_string_lossy())
                }
                (Component::Prefix(a), Component::Prefix(b)) => a
                    .as_os_str()
                    .to_string_lossy()
                    .eq_ignore_ascii_case(&b.as_os_str().to_string_lossy()),
                (a, b) => a == b,
            })
    }
    #[cfg(not(target_os = "windows"))]
    {
        !parent.as_os_str().is_empty() && child.starts_with(parent)
    }
}

fn detect_portable_or_standard_readonly(exe_dir: &Path, standard_dir: &Path) -> (PathBuf, bool) {
    let flag = exe_dir.join("portable.flag");
    let sibling_data = exe_dir.join("data");
    if flag.is_file() || sibling_data.is_dir() {
        return (sibling_data, true);
    }
    let is_cli_subdir = exe_dir
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("cli"));
    if is_cli_subdir {
        if let Some(parent) = exe_dir.parent() {
            if parent.parent().is_some() && parent.join("portable.flag").is_file() {
                return (parent.join("data"), true);
            }
        }
    }
    (standard_dir.to_path_buf(), false)
}

fn resolve_data_dir_readonly_for(
    cli_data_dir: Option<PathBuf>,
    env_data_dir: Option<&str>,
    exe_dir: &Path,
    standard_dir: &Path,
) -> (PathBuf, bool) {
    if let Some(dir) = cli_data_dir {
        (dir, true)
    } else if let Some(env_dir) = env_data_dir.filter(|v| !v.trim().is_empty()) {
        (PathBuf::from(env_dir), true)
    } else {
        detect_portable_or_standard_readonly(exe_dir, standard_dir)
    }
}

fn is_standard_installed_readonly_for(
    root_data_dir: &Path,
    is_portable: bool,
    exe_dir: &Path,
    standard_dir: &Path,
) -> bool {
    if is_portable {
        let flag = exe_dir.join("portable.flag");
        let sibling_data = exe_dir.join("data");
        if flag.is_file() || sibling_data.is_dir() {
            let norm_exe_dir = canonical_or_normalized_readonly(exe_dir);
            let norm_root = canonical_or_normalized_readonly(root_data_dir);
            if path_is_within_dir_readonly(&norm_root, &norm_exe_dir) {
                return false;
            }
        }
    }
    let norm_root = canonical_or_normalized_readonly(root_data_dir);
    let norm_std = canonical_or_normalized_readonly(standard_dir);
    paths_equal_normalized_readonly(&norm_root, &norm_std)
}

fn handle_shutdown_existing_for_target(
    root_data_dir: &Path,
    is_standard_installed: bool,
) -> bool {
    let signaled_dir =
        catcloud_core::process_guard::signal_graceful_exit_for_data_dir(root_data_dir);
    let signaled_installed = if !signaled_dir && is_standard_installed {
        catcloud_core::process_guard::signal_graceful_exit_installed()
    } else {
        false
    };
    let signaled = signaled_dir || signaled_installed;
    tracing::info!(
        data_dir = %root_data_dir.display(),
        is_standard_installed,
        signaled_dir,
        signaled_installed,
        signaled,
        "--shutdown-existing dispatched prior to single-instance acquisition"
    );
    signaled
}

/// Dispatch `--shutdown-existing` using purely read-only path resolution so no directories,
/// write probes, or WebView2 user-data folders are created on disk.
pub fn handle_shutdown_existing_readonly() -> bool {
    let cli_data_dir = AppPaths::parse_cli_data_dir_from_args();
    let env_data_dir = std::env::var("CATCLOUD_DATA_DIR").ok();
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."));
    let standard_dir = standard_os_data_dir_readonly();
    let (root_data_dir, is_portable) = resolve_data_dir_readonly_for(
        cli_data_dir,
        env_data_dir.as_deref(),
        &exe_dir,
        &standard_dir,
    );
    let is_standard_installed =
        is_standard_installed_readonly_for(&root_data_dir, is_portable, &exe_dir, &standard_dir);
    handle_shutdown_existing_for_target(&root_data_dir, is_standard_installed)
}

fn is_one_shot_launch_flag(arg: &str) -> bool {
    matches!(
        arg,
        "--apply-staged-update"
            | "--silent"
            | "--enable-tun"
            | "--enable-global-preaccel"
            | "--shutdown-existing"
    )
}

fn handle_shutdown_existing_flag(paths: &AppPaths) -> bool {
    handle_shutdown_existing_for_target(
        &paths.root_data_dir,
        paths.is_standard_installed_instance(),
    )
}

fn reconcile_startup_config_with_storage(
    paths: &AppPaths,
    cfg: &mut catcloud_core::models::AppConfig,
    storage: &Storage,
) -> bool {
    let enabled_relay_ids: HashSet<String> = storage
        .list_preaccel_relays(true)
        .unwrap_or_default()
        .into_iter()
        .map(|r| r.id)
        .collect();
    let mut changed = config::reconcile_dangling_active_relay(cfg, &enabled_relay_ids);
    if enabled_relay_ids.is_empty()
        && (cfg.preaccel.enabled || cfg.preaccel.global_bypass_enabled)
    {
        cfg.preaccel.sync_unified_enabled(false);
        changed = true;
    }
    if changed {
        let _ = config::save(paths, cfg);
    }
    changed
}

fn apply_next_launch_silent_badge_policy(
    state: &AppState,
    prompt_dto: &mut commands::PendingUpdatePromptDto,
) -> bool {
    if state.snapshot_config().update.mode == UpdateApplyMode::NextLaunch {
        prompt_dto.silent_badge_only = true;
        prompt_dto.dismissed_in_session = true;
        let _ = commands::dismiss_update_prompt_for_session_internal(
            state,
            &prompt_dto.target_version,
        );
        true
    } else {
        false
    }
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

    if current_raw_args
        .iter()
        .any(|a| a.to_string_lossy() == "--silent-relaunch")
        && !relaunch_args.iter().any(|a| a == "--silent-relaunch")
    {
        relaunch_args.push("--silent-relaunch".to_string());
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
    let silent_flag = has_cli_flag("--silent") || has_cli_flag("--silent-relaunch");
    let post_update_cleanup = has_cli_flag("--post-update-cleanup");
    let apply_staged_update_flag = has_cli_flag("--apply-staged-update");
    let enable_tun_flag = has_cli_flag("--enable-tun");
    let enable_global_preaccel_flag = has_cli_flag("--enable-global-preaccel");

    // Must run strictly BEFORE `SingleInstanceGuard::acquire_for_paths` so `--shutdown-existing`
    // triggers cross-IL graceful shutdown without waking/raising an existing window first.
    if has_cli_flag("--shutdown-existing") {
        let _ = handle_shutdown_existing_flag(&paths);
        return;
    }

    if post_update_cleanup {
        let _ = catcloud_core::updater::run_post_update_cleanup(&paths.backup_dir);
    }

    let instance_guard: Option<SingleInstanceGuard> =
        match SingleInstanceGuard::acquire_for_paths(&paths, restarting) {
            Ok(AcquireOutcome::Primary(guard)) => Some(guard),
            Ok(AcquireOutcome::SecondaryWokePrimary) => {
                if restarting {
                    tracing::warn!(
                        timeout_secs = catcloud_core::process_guard::RESTART_WAIT_TIMEOUT.as_secs(),
                        data_dir = %paths.root_data_dir.display(),
                        "RESTART_WAIT_TIMEOUT elapsed while waiting for previous CatCloud instance to release single-instance lock; signaled primary and exiting"
                    );
                } else {
                    tracing::info!(
                        "another CatCloud instance owns this data_dir; signaled primary and exiting"
                    );
                }
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
    let _ = reconcile_startup_config_with_storage(&paths, &mut cfg, &storage);

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
    let end_session_guard_ref = Arc::clone(&instance_guard_slot);
    let end_session_job_ref = Arc::clone(&job_guard);
    let exit_guard_ref = Arc::clone(&instance_guard_slot);
    let exit_job_ref = Arc::clone(&job_guard);

    // Best-effort cleanup of any stale ephemeral probe sandboxes left by prior hard crashes.
    for stale_dir_name in ["probe_sandbox", "probe-tmp"] {
        let stale_dir = paths.runtime_dir.join(stale_dir_name);
        if stale_dir.exists() {
            let _ = std::fs::remove_dir_all(&stale_dir);
        }
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
            commands::mark_onboarding_completed,
            commands::get_runtime_info,
            commands::start_core,
            commands::stop_core,
            commands::disable_all_proxy_and_stop_core,
            commands::enable_proxy_power,
            commands::consume_pending_nav,
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
            commands::export_gateway_yaml,
            commands::save_gateway_yaml_dialog,
            commands::parse_bulk_rules_preview,
            commands::import_mmrelay_input,
            commands::scan_local_migrations,
            commands::scan_migration_path,
            commands::preview_migration_from_text,
            commands::apply_migration_nodes,
            commands::apply_migration_nodes_with_meta,
            commands::audit_dangling_rules,
            commands::repair_dangling_rules,
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

            // Unified single-instance listener:
            // - secondary launch -> rebuild or focus the primary main window
            // - cross-IL graceful-exit event -> mark shutting down and run full graceful exit
            // - cross-process config-reload event -> debounced live hot-reload worker
            let config_reload_notify = Arc::new(tokio::sync::Notify::new());
            spawn_disk_config_hot_reload_worker(&handle, Arc::clone(&config_reload_notify));

            if let Ok(guard_lock) = wake_guard_ref.lock() {
                if let Some(ref si) = *guard_lock {
                    let wake_handle = handle.clone();
                    let exit_handle = handle.clone();
                    let exit_reload_notify = Arc::clone(&config_reload_notify);
                    let reload_notify_cb = Arc::clone(&config_reload_notify);
                    if let Err(err) = si.start_instance_listeners_with_reload(
                        move || {
                            lifecycle::show_or_rebuild_main_window(&wake_handle);
                        },
                        move || {
                            tracing::info!(
                                "received cross-IL graceful-exit event; triggering clean shutdown"
                            );
                            if let Some(st) = exit_handle.try_state::<AppState>() {
                                st.shutting_down.store(true, Ordering::SeqCst);
                            }
                            exit_reload_notify.notify_one();
                            lifecycle::request_graceful_exit(&exit_handle);
                        },
                        move || {
                            reload_notify_cb.notify_one();
                        },
                    ) {
                        tracing::warn!("failed to start single-instance listeners: {err}");
                    }
                }
            }

            // Windows WM_QUERYENDSESSION / WM_ENDSESSION subclass guard on tao's resident hidden
            // event window: synchronously executes <=3000ms bounded cleanup before tao calls exit(0).
            {
                let end_session_app = handle.clone();
                let end_session_job = Arc::clone(&end_session_job_ref);
                let end_session_guard = Arc::clone(&end_session_guard_ref);
                lifecycle::install_tao_end_session_guard(move || {
                    if let Some(st) = end_session_app.try_state::<AppState>() {
                        commands::emergency_cleanup_on_exit_bounded(
                            &st,
                            Duration::from_millis(3000),
                        );
                    }
                    let _ = end_session_job.terminate_all();
                    match end_session_guard.try_lock() {
                        Ok(mut guard_lock) => {
                            if let Some(mut si) = guard_lock.take() {
                                si.release();
                            }
                        }
                        Err(std::sync::TryLockError::Poisoned(e)) => {
                            let mut guard_lock = e.into_inner();
                            if let Some(mut si) = guard_lock.take() {
                                si.release();
                            }
                        }
                        Err(std::sync::TryLockError::WouldBlock) => {}
                    }
                });
            }

            // Spawn background telemetry event forwarders feeding frontend sparklines, logs, and tray tooltip.
            telemetry_loop::spawn_telemetry_forwarders(&handle, &state);
            // Spawn background cross-platform ProxyGuard watchdog preventing third-party proxy hijacking.
            telemetry_loop::spawn_proxy_guard(&handle);
            // Spawn background multi-group health watchdog driving automatic failover for StickyBest/ConditionalPool.
            watchdog::spawn_group_strategy_watchdog(&handle);
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
                                if let Err(err) =
                                    commands::toggle_preaccel_internal(&app_async, &st, next).await
                                {
                                    if err.contains("NO_ENABLED_RELAY") {
                                        if lifecycle::window_mode_snapshot(&app_async).main_open {
                                            st.set_pending_nav(None);
                                            lifecycle::show_or_rebuild_main_window(&app_async);
                                            let _ = app_async
                                                .emit(commands::EVENT_NAVIGATE, "preaccel");
                                        } else {
                                            st.set_pending_nav(Some("preaccel"));
                                            lifecycle::show_or_rebuild_main_window(&app_async);
                                        }
                                    }
                                }
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
                                let mut next = st.clone_config();
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
                            let mut next_cfg = (*old_cfg).clone();
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
                                *guard = Arc::new(next_cfg.clone());
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
                                    *guard = Arc::clone(&old_cfg);
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

fn spawn_disk_config_hot_reload_worker(
    app: &tauri::AppHandle,
    notify: Arc<tokio::sync::Notify>,
) {
    let app_h = app.clone();
    tauri::async_runtime::spawn(async move {
        const DEBOUNCE_WINDOW: Duration = Duration::from_millis(250);
        const MAX_COALESCE_WINDOW: Duration = Duration::from_secs(1);

        loop {
            notify.notified().await;

            let Some(st) = app_h.try_state::<AppState>() else {
                break;
            };
            if st.shutting_down.load(Ordering::SeqCst) {
                break;
            }

            let batch_deadline = Instant::now() + MAX_COALESCE_WINDOW;
            loop {
                if st.shutting_down.load(Ordering::SeqCst) {
                    return;
                }
                let now = Instant::now();
                if now >= batch_deadline {
                    break;
                }
                let wait_dur = DEBOUNCE_WINDOW.min(batch_deadline.saturating_duration_since(now));
                match tokio::time::timeout(wait_dur, notify.notified()).await {
                    Ok(()) => continue,
                    Err(_) => break,
                }
            }

            if st.shutting_down.load(Ordering::SeqCst) {
                break;
            }

            match commands::apply_disk_config_hot_reload_internal(&app_h, &st).await {
                Ok(ack) => {
                    tracing::debug!(
                        req_id = %ack.req_id,
                        applied = ack.applied,
                        rejected = ack.rejected,
                        level = ?ack.level,
                        "cross-process disk config hot-reload finished"
                    );
                }
                Err(err) => {
                    tracing::warn!("cross-process disk config hot-reload failed: {err}");
                }
            }
        }
    });
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
                                    if let Ok(Some(mut prompt_dto)) =
                                        commands::get_pending_staged_update_internal(&st).await
                                    {
                                        apply_next_launch_silent_badge_policy(&st, &mut prompt_dto);
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

        // Explicitly propagates `--silent-relaunch` for cross-process silent self-update.
        let silent_relaunch_args = vec![
            OsString::from("--data-dir=/tmp/catcloud-portable"),
            OsString::from("--apply-staged-update"),
            OsString::from("--silent-relaunch"),
        ];
        let built_silent = build_post_update_cleanup_relaunch_args(&[], &silent_relaunch_args);
        assert_eq!(
            built_silent,
            vec![
                "--data-dir=/tmp/catcloud-portable".to_string(),
                "--silent-relaunch".to_string(),
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


    #[test]
    fn shutdown_existing_signals_without_waking_and_startup_reconciles_dangling_relay() {
        use std::sync::atomic::AtomicBool;

        let tmp = std::env::temp_dir().join(format!(
            "catcloud_lib_s22_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let paths = AppPaths::from_data_dir(tmp.clone(), true).expect("create temp AppPaths");

        // 1. `--shutdown-existing` flag triggers graceful exit listener WITHOUT triggering wakeup.
        let guard = match SingleInstanceGuard::acquire_for_paths(&paths, false)
            .expect("acquire primary guard")
        {
            AcquireOutcome::Primary(g) => g,
            AcquireOutcome::SecondaryWokePrimary => panic!("expected primary ownership"),
        };
        let woke = Arc::new(AtomicBool::new(false));
        let exited = Arc::new(AtomicBool::new(false));
        let woke_cb = Arc::clone(&woke);
        let exited_cb = Arc::clone(&exited);
        guard
            .start_instance_listeners(
                move || woke_cb.store(true, Ordering::SeqCst),
                move || exited_cb.store(true, Ordering::SeqCst),
            )
            .expect("start instance listeners");

        assert!(handle_shutdown_existing_flag(&paths));
        let deadline = Instant::now() + Duration::from_secs(3);
        while !exited.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(exited.load(Ordering::SeqCst), "graceful exit callback must fire");
        assert!(!woke.load(Ordering::SeqCst), "wakeup callback must NOT fire");
        drop(guard);

        // 2. Startup config reconciliation clears dangling `active_relay_id` and persists it.
        let storage = Storage::open(&paths.db_path).expect("open sqlite");
        let mut cfg = catcloud_core::models::AppConfig::default();
        cfg.preaccel.active_relay_id = Some("deleted-relay-id".to_string());
        config::save(&paths, &cfg).expect("save initial config");
        assert!(reconcile_startup_config_with_storage(&paths, &mut cfg, &storage));
        assert_eq!(cfg.preaccel.active_relay_id, None);
        let persisted = config::load_or_init(&paths).expect("reload config");
        assert_eq!(persisted.preaccel.active_relay_id, None);

        // 3. `UpdateApplyMode::NextLaunch` marks silent_badge_only=true and records session dismissal.
        cfg.update.mode = UpdateApplyMode::NextLaunch;
        let state = AppState::new(
            paths.clone(),
            cfg,
            storage,
            Arc::new(JobGuard::new().expect("job guard")),
        );
        let mut dto = commands::PendingUpdatePromptDto {
            current_version: "0.1.1".to_string(),
            target_version: "0.1.2".to_string(),
            kind: "portable_zip".to_string(),
            apply_action: "portable_restart".to_string(),
            archive_sha256: "a".repeat(64),
            package_size_bytes: 1024,
            staged_at: "2026-11-27T00:00:00Z".to_string(),
            release_notes: String::new(),
            release_url: None,
            platform_key: None,
            installer_filename: None,
            dismissed_in_session: false,
            silent_badge_only: false,
            is_elevated: false,
        };
        assert!(apply_next_launch_silent_badge_policy(&state, &mut dto));
        assert!(dto.silent_badge_only);
        assert!(dto.dismissed_in_session);
        assert_eq!(
            state
                .dismissed_update_prompt_version
                .read()
                .unwrap()
                .as_deref(),
            Some("0.1.2")
        );
        assert!(is_one_shot_launch_flag("--shutdown-existing"));

        drop(state);
        let _ = std::fs::remove_dir_all(&tmp);
    }


    #[test]
    fn stage22_r25_shutdown_existing_readonly_creates_zero_directories_and_targets_accurately() {
        use std::sync::atomic::AtomicBool;

        let root = std::env::temp_dir().join(format!(
            "catcloud_lib_r25_shutdown_ro_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let installed_exe_dir = root.join("ProgramFiles").join("CatCloud");
        let portable_exe_dir = root.join("PortableApp");
        let std_appdata_dir = root.join("Roaming").join("CatCloud");
        let nonexistent_sandbox = root.join("NonexistentSandbox");
        std::fs::create_dir_all(&installed_exe_dir).unwrap();
        std::fs::create_dir_all(&portable_exe_dir).unwrap();
        std::fs::write(portable_exe_dir.join("portable.flag"), b"1").unwrap();

        // 1. Nonexistent `--data-dir` MUST remain completely absent after readonly resolution & signal.
        let (resolved_nonexistent, is_port_nonexistent) = resolve_data_dir_readonly_for(
            Some(nonexistent_sandbox.clone()),
            None,
            &installed_exe_dir,
            &std_appdata_dir,
        );
        assert_eq!(resolved_nonexistent, nonexistent_sandbox);
        assert!(is_port_nonexistent);
        let is_std_nonexistent = is_standard_installed_readonly_for(
            &resolved_nonexistent,
            is_port_nonexistent,
            &installed_exe_dir,
            &std_appdata_dir,
        );
        assert!(!is_std_nonexistent);
        let _ = handle_shutdown_existing_for_target(&resolved_nonexistent, is_std_nonexistent);
        assert!(
            !nonexistent_sandbox.exists(),
            "--shutdown-existing readonly path must NOT create nonexistent data directories"
        );

        // 2. Standard installed (default & UAC-elevated `--data-dir %APPDATA%\CatCloud`) vs portable.
        let (resolved_std, is_port_std) =
            resolve_data_dir_readonly_for(None, None, &installed_exe_dir, &std_appdata_dir);
        assert_eq!(resolved_std, std_appdata_dir);
        assert!(!is_port_std);
        assert!(is_standard_installed_readonly_for(
            &resolved_std,
            is_port_std,
            &installed_exe_dir,
            &std_appdata_dir
        ));
        assert!(
            !std_appdata_dir.exists(),
            "readonly standard installed detection must not create APPDATA dir"
        );

        let (resolved_uac_std, is_port_uac_std) = resolve_data_dir_readonly_for(
            Some(std_appdata_dir.clone()),
            None,
            &installed_exe_dir,
            &std_appdata_dir,
        );
        assert!(is_port_uac_std);
        assert!(is_standard_installed_readonly_for(
            &resolved_uac_std,
            is_port_uac_std,
            &installed_exe_dir,
            &std_appdata_dir
        ));

        let (resolved_portable, is_port_portable) =
            resolve_data_dir_readonly_for(None, None, &portable_exe_dir, &std_appdata_dir);
        assert_eq!(resolved_portable, portable_exe_dir.join("data"));
        assert!(is_port_portable);
        assert!(!is_standard_installed_readonly_for(
            &resolved_portable,
            is_port_portable,
            &portable_exe_dir,
            &std_appdata_dir
        ));
        assert!(!portable_exe_dir.join("data").exists());

        // 3. Existing running isolated `--data-dir` is hit accurately via readonly path without wakeup.
        let live_sandbox = root.join("LiveSandbox");
        let live_paths = AppPaths::from_data_dir(live_sandbox.clone(), true).unwrap();
        let guard = match SingleInstanceGuard::acquire_for_paths(&live_paths, false).unwrap() {
            AcquireOutcome::Primary(g) => g,
            AcquireOutcome::SecondaryWokePrimary => panic!("expected primary ownership"),
        };
        let woke = Arc::new(AtomicBool::new(false));
        let exited = Arc::new(AtomicBool::new(false));
        let woke_cb = Arc::clone(&woke);
        let exited_cb = Arc::clone(&exited);
        guard
            .start_instance_listeners(
                move || woke_cb.store(true, Ordering::SeqCst),
                move || exited_cb.store(true, Ordering::SeqCst),
            )
            .unwrap();

        let (resolved_live, is_port_live) = resolve_data_dir_readonly_for(
            Some(live_sandbox.clone()),
            None,
            &installed_exe_dir,
            &std_appdata_dir,
        );
        let is_std_live = is_standard_installed_readonly_for(
            &resolved_live,
            is_port_live,
            &installed_exe_dir,
            &std_appdata_dir,
        );
        assert!(!is_std_live);
        assert!(handle_shutdown_existing_for_target(&resolved_live, is_std_live));

        let deadline = Instant::now() + Duration::from_secs(3);
        while !exited.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(exited.load(Ordering::SeqCst));
        assert!(!woke.load(Ordering::SeqCst));

        drop(guard);
        let _ = std::fs::remove_dir_all(&root);
    }


    #[test]
    fn stage23_startup_reconcile_converges_preaccel_to_false_when_zero_enabled_relays() {
        let tmp = std::env::temp_dir().join(format!(
            "catcloud_s23_startup_zero_relay_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let paths = AppPaths::from_data_dir(tmp.clone(), true).unwrap();
        let storage = Storage::open(&paths.db_path).unwrap();

        let mut cfg = catcloud_core::models::AppConfig::default();
        cfg.preaccel.sync_unified_enabled(true);
        cfg.preaccel.active_relay_id = Some("missing-relay".to_string());
        config::save(&paths, &cfg).unwrap();

        assert!(reconcile_startup_config_with_storage(&paths, &mut cfg, &storage));
        assert!(!cfg.preaccel.enabled);
        assert!(!cfg.preaccel.global_bypass_enabled);
        assert_eq!(cfg.preaccel.active_relay_id, None);

        let persisted = config::load_or_default(&paths).unwrap();
        assert!(!persisted.preaccel.enabled);
        assert!(!persisted.preaccel.global_bypass_enabled);

        // Once an enabled relay exists, startup reconciliation preserves preaccel.enabled = true.
        storage
            .upsert_preaccel_relay(&catcloud_core::models::PreAccelRelay {
                id: "relay-1".to_string(),
                name: "杭州443".to_string(),
                server: "203.0.113.10".to_string(),
                port: 443,
                protocol: "trojan".to_string(),
                password: "demo".to_string(),
                enabled: true,
                ..Default::default()
            })
            .unwrap();
        cfg.preaccel.sync_unified_enabled(true);
        cfg.preaccel.active_relay_id = Some("relay-1".to_string());
        config::save(&paths, &cfg).unwrap();
        assert!(!reconcile_startup_config_with_storage(&paths, &mut cfg, &storage));
        assert!(cfg.preaccel.enabled);
        assert_eq!(cfg.preaccel.active_relay_id.as_deref(), Some("relay-1"));

        drop(storage);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
