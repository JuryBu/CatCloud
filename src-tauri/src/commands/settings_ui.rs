use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use base64::Engine as _;
use catcloud_core::config;
use catcloud_core::core_adapter::config_compiler::CompileInput;
use catcloud_core::core_adapter::config_compiler::compile_mihomo_config_with_runtime_dir;
use catcloud_core::core_adapter::hot_reload::has_core_config_changes;
use catcloud_core::core_adapter::port_guard::AllocatedPorts;
use catcloud_core::models::AppConfig;
use catcloud_core::models::OverrideMode;
use catcloud_core::models::ProxyMode;
use catcloud_core::models::normalize_ui_language;
use tauri::AppHandle;
use tauri::Emitter;
#[cfg(target_os = "windows")]
use tauri::Manager;
use tauri::State;
use crate::lifecycle;

use crate::commands::core_lifecycle::schedule_global_to_rule_heap_reclaim;
use crate::commands::core_lifecycle::start_core_internal;
use crate::commands::core_lifecycle::stop_core_internal;
use crate::commands::core_lifecycle::stop_core_preserving_tun_intent_internal;
use crate::commands::core_lifecycle::trigger_reload_if_running;
use crate::commands::hotkeys::sync_app_side_effects;
use crate::commands::state::AppState;
#[cfg(target_os = "windows")]
use crate::commands::state::CapsuleDragAnchor;
use crate::commands::state::EVENT_CONFIG_UPDATED;
use crate::commands::state::MAX_INLINE_OVERRIDE_YAML_BYTES;
use crate::commands::state::NO_ENABLED_RELAY_ERROR;
use crate::commands::state::UiAppConfigDto;
use crate::commands::state::apply_ui_dto;
use crate::commands::state::normalize_inline_override_yaml;
use crate::commands::state::open_directory_in_os;
use crate::commands::state::percent_encode_query_value;
use crate::commands::state::reconcile_legacy_onboarding_completed;
use crate::commands::state::sync_autostart_if_changed;
use crate::commands::system_proxy::apply_system_proxy_if_still_enabled;
use crate::commands::system_proxy::clear_system_proxy_if_owned_with_hint;
use crate::commands::system_proxy::coordinate_global_preaccel_on_tun_transition;
use crate::commands::system_proxy::load_enabled_preaccel_relays;
use crate::commands::system_proxy::sync_running_global_preaccel_if_active;
use crate::commands::tray_runtime::effective_tun_enabled;
use crate::commands::tray_runtime::emit_config_updated;
use crate::commands::tray_runtime::format_mihomo_error_for_user;
use crate::commands::tray_runtime::has_enabled_nodes;
use crate::commands::tray_runtime::has_non_empty_inline_override_yaml;
use crate::commands::tray_runtime::is_tun_privilege_ready;
use crate::commands::tray_runtime::tun_needs_admin_error_message;

#[tauri::command]
pub fn get_app_config(state: State<'_, AppState>) -> Result<UiAppConfigDto, String> {
    let mut cfg = state.clone_config();
    if !cfg.personalization.onboarding_completed {
        if let Ok(db) = state.storage.lock() {
            if reconcile_legacy_onboarding_completed(&mut cfg, &db) {
                let _ = config::save(&state.paths, &cfg);
                if let Ok(mut guard) = state.config.write() {
                    *guard = Arc::new(cfg.clone());
                }
            }
        }
    }
    Ok(UiAppConfigDto::from(&cfg))
}


pub(in crate::commands) fn reconcile_saved_preaccel_switch(old: &AppConfig, next: &mut AppConfig) {
    if old.preaccel.enabled != next.preaccel.enabled {
        next.preaccel.sync_unified_enabled(next.preaccel.enabled);
    } else if old.preaccel.global_bypass_enabled != next.preaccel.global_bypass_enabled {
        next.preaccel
            .sync_unified_enabled(next.preaccel.global_bypass_enabled);
    } else {
        next.preaccel.reconcile_unified_enabled();
    }
}


async fn apply_and_save_config_transition<F>(
    app: &AppHandle,
    state: &AppState,
    explicit_tun_disable: bool,
    build_next: F,
) -> Result<AppConfig, String>
where
    F: FnOnce(&AppConfig) -> Result<AppConfig, String>,
{
    let _cfg_guard = state.config_transition_lock.lock().await;
    let old = state.snapshot_config();
    let mut next = build_next(&old)?;
    next.personalization.language = if next.personalization.language.trim().is_empty() {
        old.personalization.normalized_ui_language().to_string()
    } else {
        normalize_ui_language(&next.personalization.language).to_string()
    };

    let tun_ready = is_tun_privilege_ready(state);
    let old_eff_tun = old.tun.enabled && tun_ready;
    let next_eff_tun = next.tun.enabled && tun_ready;
    let was_core_running =
        state.snapshot_runtime().running || state.adapter.has_live_controller().await;
    let was_tun_active = was_core_running && old_eff_tun;

    if !old.tun.enabled && next.tun.enabled && !tun_ready {
        return Err(tun_needs_admin_error_message());
    }

    if next.preaccel.enabled {
        let has_enabled_relays = !load_enabled_preaccel_relays(state)?.is_empty();
        if !has_enabled_relays {
            if !old.preaccel.enabled {
                return Err(NO_ENABLED_RELAY_ERROR.to_string());
            }
            next.preaccel.sync_unified_enabled(false);
        }
    }

    if (!old.system_proxy.enabled && next.system_proxy.enabled)
        || (!old.tun.enabled && next.tun.enabled)
    {
        if !has_enabled_nodes(state)? {
            return Err("暂无可用节点，请先导入订阅".to_string());
        }
    }

    let disabling_all_proxy = (old.system_proxy.enabled || old_eff_tun)
        && !next.system_proxy.enabled
        && !next_eff_tun;

    if old_eff_tun && !next.tun.enabled && state.adapter.has_live_controller().await {
        let _ = state.adapter.disable_tun_gracefully().await;
    }

    config::save(&state.paths, &next).map_err(|e| format!("保存配置文件失败：{e}"))?;
    if let Ok(mut guard) = state.config.write() {
        *guard = Arc::new(next.clone());
    }

    let needs_core_boot = ((!old.system_proxy.enabled && next.system_proxy.enabled)
        || (!old_eff_tun && next_eff_tun))
        && !state.adapter.has_live_controller().await;

    let latest_before_stop = state.snapshot_config();
    let latest_eff_tun = effective_tun_enabled(state, &latest_before_stop);
    if disabling_all_proxy
        && was_core_running
        && !latest_before_stop.system_proxy.enabled
        && !latest_eff_tun
    {
        // Clear OS proxy before stopping main core so host internet is never blackholed.
        if old.system_proxy.enabled {
            let _ = clear_system_proxy_if_owned_with_hint(state, true);
        }
        if next.tun.enabled {
            stop_core_preserving_tun_intent_internal(app, state).await?;
        } else {
            stop_core_internal(app, state).await?;
        }
        if (old.tun.enabled || explicit_tun_disable) && !next.tun.enabled {
            state.clear_power_off_takeover_memory();
        }
        if old.preaccel.enabled
            && !next.preaccel.enabled
            && (state.global_preaccel.status().running
                || state.global_preaccel.status().mode == "suspended_for_tun")
        {
            let _ = state.global_preaccel.stop().await;
        }
        state.bump_config_generation();
        sync_autostart_if_changed(&old, &next);
        let latest = state.snapshot_config();
        sync_app_side_effects(app, state, &latest);
        let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&latest));
        return Ok((*latest).clone());
    }

    let mut started_core_here = false;
    if needs_core_boot {
        if let Err(err) = start_core_internal(app, state).await {
            let _ = config::save(&state.paths, &old);
            if let Ok(mut guard) = state.config.write() {
                *guard = Arc::clone(&old);
            }
            sync_app_side_effects(app, state, &old);
            return Err(format!("保存配置后启动代理核心失败：{err}"));
        }
        started_core_here = true;
    } else if has_core_config_changes(&old, &next) {
        if let Some(outcome) = trigger_reload_if_running(app, state, false).await {
            if outcome.rejected {
                let _ = config::save(&state.paths, &old);
                if let Ok(mut guard) = state.config.write() {
                    *guard = Arc::clone(&old);
                }
                sync_app_side_effects(app, state, &old);
                let raw_err = outcome
                    .error
                    .unwrap_or_else(|| "配置预检未通过，已恢复原配置运行".to_string());
                return Err(format_mihomo_error_for_user(&raw_err));
            }
        }
    }

    let sys_proxy_changed = old.system_proxy != next.system_proxy
        || (next.system_proxy.enabled && old.mixed_port != next.mixed_port);
    if sys_proxy_changed {
        let apply_res = if next.system_proxy.enabled {
            let effective_port = {
                let rt = state.snapshot_runtime();
                if rt.running { rt.mixed_port } else { next.mixed_port }
            };
            apply_system_proxy_if_still_enabled(state, effective_port).map(|_| ())
        } else {
            clear_system_proxy_if_owned_with_hint(state, old.system_proxy.enabled).map(|_| ())
        };
        if let Err(err) = apply_res {
            let _ = config::save(&state.paths, &old);
            if let Ok(mut guard) = state.config.write() {
                *guard = Arc::clone(&old);
            }
            if started_core_here && !old.system_proxy.enabled && !old_eff_tun {
                // Lock order: already holding outer `config_transition_lock` -> inner `core_lifecycle_lock`.
                if let Err(stop_err) = stop_core_preserving_tun_intent_internal(app, state).await {
                    tracing::warn!("配置切换写入系统代理失败回滚后停止新拉起核心异常：{stop_err}");
                }
            }
            let latest = state.snapshot_config();
            sync_app_side_effects(app, state, &latest);
            let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&latest));
            return Err(err);
        }
    }

    let now_core_running =
        state.snapshot_runtime().running || state.adapter.has_live_controller().await;
    let now_tun_active = now_core_running && effective_tun_enabled(state, &next);
    let preaccel_changed = should_sync_standalone_preaccel_on_config_change(&old, &next);

    if !next.preaccel.enabled
        && (state.global_preaccel.status().running
            || state.global_preaccel.status().mode == "suspended_for_tun")
    {
        let _ = state.global_preaccel.stop().await;
    } else if was_tun_active != now_tun_active || (old.preaccel.enabled != next.preaccel.enabled) {
        coordinate_global_preaccel_on_tun_transition(
            app,
            state,
            &next,
            was_tun_active,
            now_tun_active,
            "代理配置",
        )
        .await;
    } else if !now_tun_active
        && next.preaccel.enabled
        && state.global_preaccel.status().running
        && preaccel_changed
    {
        sync_running_global_preaccel_if_active(state, &next).await;
    }

    if (old.tun.enabled || explicit_tun_disable) && !next.tun.enabled {
        state.clear_power_off_takeover_memory();
    }

    let next_gen = state.bump_config_generation();
    if old.proxy_mode == ProxyMode::Global && next.proxy_mode == ProxyMode::Rule && now_core_running
    {
        schedule_global_to_rule_heap_reclaim(app, next_gen);
    }

    sync_autostart_if_changed(&old, &next);
    sync_app_side_effects(app, state, &next);
    let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&next));
    Ok(next)
}


#[tauri::command]
pub async fn save_app_config(
    app: AppHandle,
    state: State<'_, AppState>,
    config: UiAppConfigDto,
) -> Result<UiAppConfigDto, String> {
    let explicit_tun_disable = !config.tun_enabled;
    let cfg = apply_and_save_config_transition(&app, &state, explicit_tun_disable, |old| {
        let mut cfg = (*old).clone();
        apply_ui_dto(&mut cfg, &config);
        cfg.preaccel.sync_unified_enabled(config.preaccel.enabled);
        Ok(cfg)
    })
    .await?;
    Ok(UiAppConfigDto::from(&cfg))
}


#[tauri::command]
pub fn get_full_config(state: State<'_, AppState>) -> Result<AppConfig, String> {
    Ok(state.clone_config())
}


fn format_inline_override_validation_error(raw: &str) -> String {
    let detail = format_mihomo_error_for_user(raw);
    let lower = detail.to_ascii_lowercase();
    if lower.contains("root document must be a mapping") {
        return "内联 YAML 覆写根节点必须是键值对映射（例如 rule-providers: / rules: / dns:），不能是纯列表或纯文本，已拒绝保存".to_string();
    }
    if lower.contains("exceeds maximum allowed size") {
        return "内联 YAML 覆写体积超过 1 MiB 上限，已拒绝保存".to_string();
    }
    if detail.contains("内联 YAML") {
        detail
    } else {
        format!("内联 YAML 覆写编译校验失败，未保存修改：{detail}")
    }
}


fn has_active_yaml_override(cfg: &AppConfig) -> bool {
    matches!(
        cfg.rules_override.override_mode,
        OverrideMode::MergePatch | OverrideMode::Both
    ) || has_non_empty_inline_override_yaml(cfg)
}


fn validate_inline_override_yaml_compile(
    state: &AppState,
    candidate_cfg: &AppConfig,
) -> Result<(), String> {
    if !has_active_yaml_override(candidate_cfg) {
        return Ok(());
    }
    let has_inline = has_non_empty_inline_override_yaml(candidate_cfg);
    if let Some(full_raw) = candidate_cfg.rules_override.inline_override_yaml.as_deref() {
        if !full_raw.trim().is_empty() && full_raw.len() > MAX_INLINE_OVERRIDE_YAML_BYTES {
            return Err(format!(
                "内联 YAML 覆写体积超过 1 MiB 上限（当前 {} 字节），已拒绝保存",
                full_raw.len()
            ));
        }
    }

    let (nodes, groups, relays) = {
        let db = state
            .storage
            .lock()
            .map_err(|e| format!("读取本地配置数据库失败：{e}"))?;
        (
            db.list_nodes()
                .map_err(|e| format!("读取代理节点列表失败：{e}"))?,
            db.list_multi_groups()
                .map_err(|e| format!("读取智能多选组列表失败：{e}"))?,
            db.list_preaccel_relays(false)
                .map_err(|e| format!("读取国内中转线路失败：{e}"))?,
        )
    };

    let allocated = AllocatedPorts {
        bind_host: candidate_cfg.bind_address.clone(),
        mixed_port: candidate_cfg.mixed_port,
        controller_port: candidate_cfg.controller_port,
        dns_port: candidate_cfg.dns_listen_port,
        shifted: Vec::new(),
    };
    let empty_filter = HashMap::new();
    let input = CompileInput {
        config: candidate_cfg,
        nodes: &nodes,
        groups: &groups,
        relays: &relays,
        controller_secret: "inline-override-validation-secret",
        allocated_ports: &allocated,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty_filter,
    };

    let compiled =
        compile_mihomo_config_with_runtime_dir(&input, Some(&state.paths.runtime_dir)).map_err(
            |e| {
                if has_inline {
                    format_inline_override_validation_error(&e.to_string())
                } else {
                    format!(
                        "YAML 覆写合并编译校验失败，未保存修改：{}",
                        format_mihomo_error_for_user(&e.to_string())
                    )
                }
            },
        )?;

    let errors = compiled.validation.errors();
    if !errors.is_empty() {
        let fallback_hint =
            catcloud_core::core_adapter::resolve_default_fallback_group_name(candidate_cfg, &groups);
        let summary = catcloud_core::core_adapter::format_static_validation_summary_zh(
            &compiled.validation,
            Some(&fallback_hint),
        );
        return Err(if has_inline {
            format!("内联 YAML 覆写合并后静态校验未通过，未保存修改：{summary}")
        } else {
            format!("YAML 覆写合并后静态校验未通过，未保存修改：{summary}")
        });
    }

    Ok(())
}


pub(in crate::commands) fn should_sync_standalone_preaccel_on_config_change(old: &AppConfig, next: &AppConfig) -> bool {
    old.preaccel != next.preaccel
}


pub(in crate::commands) fn should_validate_inline_override_yaml(
    old: &AppConfig,
    next: &AppConfig,
    inline_override_touched: bool,
) -> bool {
    has_active_yaml_override(next)
        && (inline_override_touched
            || old.rules_override != next.rules_override
            || has_core_config_changes(old, next))
}


pub(in crate::commands) fn prepare_full_config_next(
    state: &AppState,
    old: &AppConfig,
    mut next: AppConfig,
) -> Result<AppConfig, String> {
    normalize_inline_override_yaml(&mut next);
    reconcile_saved_preaccel_switch(old, &mut next);
    if should_validate_inline_override_yaml(old, &next, false) {
        validate_inline_override_yaml_compile(state, &next)?;
    }
    Ok(next)
}


#[tauri::command]
pub async fn save_full_config(
    app: AppHandle,
    state: State<'_, AppState>,
    next: AppConfig,
) -> Result<AppConfig, String> {
    let explicit_tun_disable = !next.tun.enabled;
    let state_ref: &AppState = &state;
    apply_and_save_config_transition(&app, state_ref, explicit_tun_disable, move |old| {
        prepare_full_config_next(state_ref, old, next)
    })
    .await
}


fn is_replace_map_path(path: &str) -> bool {
    matches!(path, "dns.nameserver_policy" | "dns.hosts")
}


fn json_deep_merge_inner(
    target: &mut serde_json::Value,
    patch: &serde_json::Value,
    path: &str,
) {
    match (target, patch) {
        (serde_json::Value::Object(t_map), serde_json::Value::Object(p_map)) => {
            if !path.is_empty() && (is_replace_map_path(path) || p_map.is_empty()) {
                *t_map = p_map.clone();
                return;
            }
            for (k, v) in p_map {
                let child_path = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                if let Some(existing) = t_map.get_mut(k) {
                    json_deep_merge_inner(existing, v, &child_path);
                } else {
                    t_map.insert(k.clone(), v.clone());
                }
            }
        }
        (slot, new_val) => {
            *slot = new_val.clone();
        }
    }
}


pub(in crate::commands) fn json_deep_merge(target: &mut serde_json::Value, patch: &serde_json::Value) {
    json_deep_merge_inner(target, patch, "");
}


pub(in crate::commands) fn prepare_extended_settings_next(
    state: &AppState,
    old: &AppConfig,
    patch: &serde_json::Value,
) -> Result<AppConfig, String> {
    let mut base_val = serde_json::to_value(old).map_err(|e| e.to_string())?;
    json_deep_merge(&mut base_val, patch);
    let mut next: AppConfig = serde_json::from_value(base_val)
        .map_err(|e| format!("配置字段格式无效：{e}"))?;
    normalize_inline_override_yaml(&mut next);
    reconcile_saved_preaccel_switch(old, &mut next);

    let override_touched = patch.get("rules_override").is_some_and(|ro| {
        ro.get("inline_override_yaml").is_some()
            || ro.get("override_mode").is_some()
            || ro.get("override_merge_path").is_some()
    });
    if should_validate_inline_override_yaml(old, &next, override_touched) {
        validate_inline_override_yaml_compile(state, &next)?;
    }

    Ok(next)
}


pub(in crate::commands) async fn mark_onboarding_completed_core(state: &AppState) -> Result<AppConfig, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    let mut cfg = state.clone_config();
    if cfg.personalization.onboarding_completed {
        return Ok(cfg);
    }
    cfg.personalization.onboarding_completed = true;
    config::save(&state.paths, &cfg).map_err(|e| format!("保存首次引导完成状态失败：{e}"))?;
    if let Ok(mut guard) = state.config.write() {
        *guard = Arc::new(cfg.clone());
    }
    state.bump_config_generation();
    Ok(cfg)
}


#[tauri::command]
pub async fn mark_onboarding_completed(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let cfg = mark_onboarding_completed_core(&state).await?;
    emit_config_updated(&app, &cfg);
    Ok(())
}


#[tauri::command]
pub async fn save_extended_settings(
    app: AppHandle,
    state: State<'_, AppState>,
    patch: serde_json::Value,
) -> Result<AppConfig, String> {
    let explicit_tun_disable = patch
        .get("tun")
        .and_then(|t| t.get("enabled"))
        .and_then(|v| v.as_bool())
        == Some(false);
    let state_ref: &AppState = &state;
    let saved = apply_and_save_config_transition(&app, state_ref, explicit_tun_disable, |old| {
        prepare_extended_settings_next(state_ref, old, &patch)
    })
    .await?;
    Ok(saved)
}


#[tauri::command]
pub fn toggle_capsule_window(app: AppHandle) -> Result<bool, String> {
    let was_open = lifecycle::window_mode_snapshot(&app).capsule_open;
    lifecycle::toggle_capsule_window(&app);
    Ok(!was_open)
}


#[tauri::command]
pub fn show_main_window(app: AppHandle) -> Result<(), String> {
    lifecycle::show_or_rebuild_main_window(&app);
    Ok(())
}


#[tauri::command]
pub fn enter_windowless_mode(app: AppHandle) -> Result<(), String> {
    lifecycle::destroy_capsule_window(&app);
    lifecycle::hide_or_enter_windowless_main_window(&app);
    Ok(())
}


/// Begin custom Win32 physical-coordinate dragging of the floating capsule window (no `HTCAPTION`,
/// zero Windows Aero Snap preview / maximize glitches, smooth across mixed-DPI multi-monitors).
#[tauri::command]
pub fn capsule_drag_start(app: AppHandle, state: State<'_, AppState>) -> Result<bool, String> {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::Foundation::{HWND, POINT, RECT};
        use windows_sys::Win32::UI::WindowsAndMessaging::{GetCursorPos, GetWindowRect, IsWindow};

        let Some(win) = app.get_webview_window(lifecycle::CAPSULE_WINDOW_LABEL) else {
            return Ok(false);
        };
        let Ok(raw_hwnd) = win.hwnd() else {
            return Ok(false);
        };
        let hwnd = raw_hwnd.0 as HWND;
        if hwnd.is_null() || unsafe { IsWindow(hwnd) == 0 } {
            return Ok(false);
        }

        let mut pt = POINT { x: 0, y: 0 };
        let mut rect = RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        // SAFETY: Valid HWND and stack-allocated Win32 structs.
        let ok = unsafe { GetCursorPos(&mut pt) != 0 && GetWindowRect(hwnd, &mut rect) != 0 };
        if !ok {
            return Ok(false);
        }
        let width = rect.right.saturating_sub(rect.left).max(1);
        let height = rect.bottom.saturating_sub(rect.top).max(1);
        let offset_x = pt.x.saturating_sub(rect.left);
        let offset_y = pt.y.saturating_sub(rect.top);
        let rx = ((offset_x as f64) / (width as f64)).clamp(0.0, 1.0);
        let ry = ((offset_y as f64) / (height as f64)).clamp(0.0, 1.0);

        let mut guard = state
            .capsule_drag
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *guard = Some(CapsuleDragAnchor {
            rx,
            ry,
            offset_x,
            offset_y,
            width,
            height,
        });
        Ok(true)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (&app, &state);
        Ok(false)
    }
}


/// Advance custom Win32 physical-coordinate dragging of the floating capsule window by one frame,
/// automatically rescaling the anchor offset if `WM_DPICHANGED` alters physical window dimensions
/// across mixed-DPI monitors.
#[tauri::command]
pub fn capsule_drag_step(app: AppHandle, state: State<'_, AppState>) -> Result<bool, String> {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::Foundation::{HWND, POINT, RECT};
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            GetCursorPos, GetWindowRect, IsWindow, SWP_NOACTIVATE, SWP_NOSIZE, SWP_NOZORDER,
            SetWindowPos,
        };

        let Some(win) = app.get_webview_window(lifecycle::CAPSULE_WINDOW_LABEL) else {
            return Ok(false);
        };
        let Ok(raw_hwnd) = win.hwnd() else {
            return Ok(false);
        };
        let hwnd = raw_hwnd.0 as HWND;
        if hwnd.is_null() || unsafe { IsWindow(hwnd) == 0 } {
            return Ok(false);
        }

        let mut pt = POINT { x: 0, y: 0 };
        let mut rect = RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        // SAFETY: Valid HWND and stack-allocated Win32 structs.
        let ok = unsafe { GetCursorPos(&mut pt) != 0 && GetWindowRect(hwnd, &mut rect) != 0 };
        if !ok {
            return Ok(false);
        }

        let cur_w = rect.right.saturating_sub(rect.left).max(1);
        let cur_h = rect.bottom.saturating_sub(rect.top).max(1);
        let next_pos = {
            let mut guard = state
                .capsule_drag
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let Some(anchor) = guard.as_mut() else {
                return Ok(false);
            };
            if cur_w != anchor.width || cur_h != anchor.height {
                anchor.width = cur_w;
                anchor.height = cur_h;
                anchor.offset_x = (anchor.rx * (cur_w as f64)).round() as i32;
                anchor.offset_y = (anchor.ry * (cur_h as f64)).round() as i32;
            }
            (
                pt.x.saturating_sub(anchor.offset_x),
                pt.y.saturating_sub(anchor.offset_y),
            )
        };

        if next_pos.0 == rect.left && next_pos.1 == rect.top {
            return Ok(true);
        }

        // SAFETY: Valid HWND; `SetWindowPos` moves in physical screen coordinates without
        // resizing, reordering, activating, or entering OS `HTCAPTION` Aero Snap modal loops.
        let moved = unsafe {
            SetWindowPos(
                hwnd,
                std::ptr::null_mut(),
                next_pos.0,
                next_pos.1,
                0,
                0,
                SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE,
            ) != 0
        };
        Ok(moved)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (&app, &state);
        Ok(false)
    }
}


/// Clear active custom floating capsule drag anchor state on pointer release / cancel.
#[tauri::command]
pub fn capsule_drag_end(state: State<'_, AppState>) -> Result<bool, String> {
    let mut guard = state
        .capsule_drag
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    *guard = None;
    #[cfg(target_os = "windows")]
    {
        Ok(true)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(false)
    }
}


fn prune_wallpaper_cache(cache_dir: &std::path::Path, max_files: usize) {
    let Ok(entries) = std::fs::read_dir(cache_dir) else {
        return;
    };
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            if !path.is_file() {
                return None;
            }
            let name = path.file_name()?.to_str()?;
            if !name.starts_with("wp_") || !name.ends_with(".jpg") {
                return None;
            }
            let modified = entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .unwrap_or(std::time::UNIX_EPOCH);
            Some((modified, path))
        })
        .collect();
    if files.len() <= max_files {
        return;
    }
    files.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, old_path) in files.into_iter().skip(max_files) {
        let _ = std::fs::remove_file(old_path);
    }
}


pub(in crate::commands) fn encode_wallpaper_data_url_from_path(
    raw_path: &str,
    cache_dir: &std::path::Path,
) -> Result<String, String> {
    let trimmed = raw_path.trim();
    if trimmed.is_empty() {
        return Err("壁纸图片路径不能为空".to_string());
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return Ok(trimmed.to_string());
    }
    if lower.starts_with("data:") {
        const ALLOWED_BITMAP_PREFIXES: &[&str] = &[
            "data:image/png;",
            "data:image/png,",
            "data:image/jpeg;",
            "data:image/jpeg,",
            "data:image/jpg;",
            "data:image/jpg,",
            "data:image/webp;",
            "data:image/webp,",
            "data:image/gif;",
            "data:image/gif,",
            "data:image/bmp;",
            "data:image/bmp,",
        ];
        if ALLOWED_BITMAP_PREFIXES.iter().any(|p| lower.starts_with(p)) {
            return Ok(trimmed.to_string());
        }
        return Err(
            "不支持的图片数据格式：仅允许 PNG/JPEG/WebP/GIF/BMP 位图，已拒绝 SVG 等非位图数据"
                .to_string(),
        );
    }
    let src_path = PathBuf::from(trimmed);
    if !src_path.is_file() {
        return Err(format!("找不到壁纸图片：{trimmed}"));
    }
    let meta = std::fs::metadata(&src_path).map_err(|e| format!("无法读取壁纸文件：{e}"))?;
    if meta.len() > 32 * 1024 * 1024 {
        return Err("壁纸图片超过 32 MB 上限，请选择更轻量的图片".to_string());
    }
    let mtime_secs = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(trimmed.as_bytes());
    hasher.update(mtime_secs.to_le_bytes());
    hasher.update(meta.len().to_le_bytes());
    let key = hex::encode(hasher.finalize());
    let cached_jpg = cache_dir.join(format!("wp_{}.jpg", &key[..16]));

    if cached_jpg.is_file() {
        if let Ok(bytes) = std::fs::read(&cached_jpg) {
            let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
            return Ok(format!("data:image/jpeg;base64,{b64}"));
        }
    }

    let mut reader = image::ImageReader::open(&src_path)
        .map_err(|e| format!("无法打开壁纸图片：{e}"))?
        .with_guessed_format()
        .map_err(|e| format!("无法识别壁纸图片格式：{e}"))?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(8192);
    limits.max_image_height = Some(8192);
    limits.max_alloc = Some(128 * 1024 * 1024);
    reader.limits(limits);
    let img = reader
        .decode()
        .map_err(|e| format!("无法解析图片格式（或超出 8192×8192 / 128 MiB 安全上限）：{e}"))?;

    let resized = if img.width() > 1920 || img.height() > 1920 {
        img.thumbnail(1920, 1920)
    } else {
        img
    };

    let rgb = if resized.color().has_alpha() {
        // Composite transparent pixels over a warm neutral cream matte (#F7F2EA)
        // so transparent PNG/WebP wallpapers never turn solid black in JPEG output.
        const BG_R: u32 = 247;
        const BG_G: u32 = 242;
        const BG_B: u32 = 234;
        let rgba = resized.to_rgba8();
        let (w, h) = rgba.dimensions();
        let mut out = image::RgbImage::new(w, h);
        for (x, y, px) in rgba.enumerate_pixels() {
            let a = u32::from(px[3]);
            let inv = 255 - a;
            let r = ((u32::from(px[0]) * a + BG_R * inv + 127) / 255) as u8;
            let g = ((u32::from(px[1]) * a + BG_G * inv + 127) / 255) as u8;
            let b = ((u32::from(px[2]) * a + BG_B * inv + 127) / 255) as u8;
            out.put_pixel(x, y, image::Rgb([r, g, b]));
        }
        out
    } else {
        resized.to_rgb8()
    };

    let mut out_bytes = Vec::new();
    let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out_bytes, 86);
    encoder
        .encode_image(&rgb)
        .map_err(|e| format!("壁纸编码失败：{e}"))?;

    let _ = std::fs::create_dir_all(cache_dir);
    let tmp_jpg = cache_dir.join(format!(
        "wp_{}.{}.tmp",
        &key[..16],
        uuid::Uuid::new_v4().simple()
    ));
    if std::fs::write(&tmp_jpg, &out_bytes).is_ok() {
        #[cfg(target_os = "windows")]
        {
            if cached_jpg.exists() {
                let _ = std::fs::remove_file(&cached_jpg);
            }
        }
        if std::fs::rename(&tmp_jpg, &cached_jpg).is_err() {
            let _ = std::fs::remove_file(&tmp_jpg);
        } else {
            prune_wallpaper_cache(cache_dir, 16);
        }
    }

    let b64 = base64::engine::general_purpose::STANDARD.encode(&out_bytes);
    Ok(format!("data:image/jpeg;base64,{b64}"))
}


#[tauri::command]
pub async fn pick_wallpaper_image(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    use tauri_plugin_dialog::DialogExt;

    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_title("选择背景壁纸图片")
        .add_filter("图片文件", &["png", "jpg", "jpeg", "webp"])
        .pick_file(move |file_path| {
            let _ = tx.send(file_path);
        });

    let picked = rx.await.map_err(|_| "文件选择已取消".to_string())?;
    let Some(file_path) = picked else {
        return Ok(serde_json::json!({
            "cancelled": true,
            "path": null,
            "data_url": null
        }));
    };
    let path_buf = file_path
        .into_path()
        .map_err(|e| format!("无法获取所选图片路径：{e}"))?;
    let path_str = path_buf.display().to_string();
    let path_for_encode = path_str.clone();
    let cache_dir = state.paths.root_data_dir.join("wallpaper_cache");
    let data_url = tokio::task::spawn_blocking(move || {
        encode_wallpaper_data_url_from_path(&path_for_encode, &cache_dir)
    })
    .await
    .map_err(|e| format!("壁纸后台解码任务异常中止：{e}"))??;

    let mut cfg = state.clone_config();
    cfg.personalization.wallpaper_path = Some(path_str.clone());
    config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
    if let Ok(mut guard) = state.config.write() {
        *guard = Arc::new(cfg.clone());
    }
    sync_app_side_effects(&app, &state, &cfg);

    Ok(serde_json::json!({
        "cancelled": false,
        "path": path_str,
        "data_url": data_url
    }))
}


#[tauri::command]
pub async fn resolve_wallpaper_data_url(
    state: State<'_, AppState>,
    path: String,
) -> Result<Option<String>, String> {
    let trimmed = path.trim().to_string();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let cache_dir = state.paths.root_data_dir.join("wallpaper_cache");
    let url = tokio::task::spawn_blocking(move || {
        encode_wallpaper_data_url_from_path(&trimmed, &cache_dir)
    })
    .await
    .map_err(|e| format!("壁纸后台解码任务异常中止：{e}"))??;
    Ok(Some(url))
}


#[tauri::command]
pub fn open_app_dir(state: State<'_, AppState>, kind: String) -> Result<String, String> {
    let path = match kind.trim().to_ascii_lowercase().as_str() {
        "data" | "root" | "data_root" => &state.paths.root_data_dir,
        "config" => &state.paths.config_dir,
        "logs" | "log" => &state.paths.logs_dir,
        "bin" | "core" => &state.paths.bin_dir,
        "backup" | "backups" => &state.paths.backup_dir,
        other => return Err(format!("未知的目录类型「{other}」")),
    };
    open_directory_in_os(path)
}


fn redact_web_ui_secret_in_url(url: &str) -> String {
    let mut out = String::with_capacity(url.len());
    let mut rest = url;
    while let Some(pos) = rest.find("secret=") {
        let prefix_ok =
            pos == 0 || matches!(rest.as_bytes()[pos - 1], b'?' | b'&' | b'#' | b';');
        if !prefix_ok {
            out.push_str(&rest[..pos + "secret=".len()]);
            rest = &rest[pos + "secret=".len()..];
            continue;
        }
        out.push_str(&rest[..pos + "secret=".len()]);
        let after = &rest[pos + "secret=".len()..];
        let val_end = after
            .find(|c| c == '&' || c == '#')
            .unwrap_or(after.len());
        out.push_str("***");
        rest = &after[val_end..];
    }
    out.push_str(rest);
    out
}


pub(in crate::commands) fn build_web_ui_urls(
    template: &str,
    host: &str,
    port: u16,
    secret: &str,
) -> Result<(String, String), String> {
    let trimmed = template.trim();
    let encoded_secret = percent_encode_query_value(secret);
    let port_str = port.to_string();
    let has_placeholder = trimmed.contains("{host}")
        || trimmed.contains("{port}")
        || trimmed.contains("{secret}");
    let launch_url = if has_placeholder {
        trimmed
            .replace("{host}", host)
            .replace("{port}", &port_str)
            .replace("{secret}", &encoded_secret)
    } else {
        let sep = if trimmed.ends_with('?') || trimmed.ends_with('&') {
            ""
        } else if trimmed.contains('?') {
            "&"
        } else {
            "?"
        };
        let encoded_host = percent_encode_query_value(host);
        format!(
            "{trimmed}{sep}http=true&hostname={encoded_host}&port={port_str}&secret={encoded_secret}"
        )
    };
    if !launch_url.starts_with("https://") && !launch_url.starts_with("http://") {
        return Err("控制面板地址必须以 http:// 或 https:// 开头".to_string());
    }
    let display_url = redact_web_ui_secret_in_url(&launch_url);
    Ok((launch_url, display_url))
}


#[tauri::command]
pub async fn open_web_ui(
    state: State<'_, AppState>,
    url: Option<String>,
) -> Result<String, String> {
    let cfg = state.snapshot_config();
    let rt = state.snapshot_runtime();
    let host = if rt.running && rt.controller_host != "0.0.0.0" {
        rt.controller_host.as_str()
    } else {
        "127.0.0.1"
    };
    let port = if rt.running {
        rt.controller_port
    } else {
        cfg.controller_port
    };
    let live_secret = if state.adapter.has_live_controller().await {
        state.adapter.controller_secret().await
    } else {
        String::new()
    };
    let secret = if !live_secret.trim().is_empty() {
        live_secret
    } else {
        cfg.controller_secret.clone().unwrap_or_default()
    };
    let template = url
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| cfg.webui_urls.first().map(|w| w.url_template.clone()))
        .unwrap_or_else(|| {
            "https://metacubex.github.io/metacubexd/#/setup?http=true&hostname={host}&port={port}&secret={secret}".to_string()
        });
    let (launch_url, sanitized_url) = build_web_ui_urls(&template, host, port, &secret)?;
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(&launch_url)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(&launch_url)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(&launch_url)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    Ok(sanitized_url)
}


/// Validate an external HTTPS URL for OS browser launch:
/// strictly trims whitespace, rejects control characters, requires `https://`,
/// forbids embedded userinfo credentials, and never appends controller host/port/secret.
pub(in crate::commands) fn validate_external_https_url(raw: &str) -> Result<String, String> {
    if raw.chars().any(|c| c.is_control()) {
        return Err("外部链接包含非法控制字符，已拒绝打开".to_string());
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("外部链接不能为空".to_string());
    }
    if trimmed.len() <= 8 || !trimmed[..8].eq_ignore_ascii_case("https://") {
        return Err("仅允许打开安全的 https:// 外部链接".to_string());
    }
    if matches!(trimmed.as_bytes().get(8), Some(b'/' | b'\\')) {
        return Err("外部链接缺少有效主机名".to_string());
    }
    let parsed = reqwest::Url::parse(trimmed)
        .map_err(|e| format!("外部链接格式无效：{e}"))?;
    if parsed.scheme() != "https" {
        return Err("仅允许打开安全的 https:// 外部链接".to_string());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("外部链接不允许包含账号或密码凭据".to_string());
    }
    let host = parsed.host_str().map(str::trim).unwrap_or("");
    if host.is_empty() {
        return Err("外部链接缺少有效主机名".to_string());
    }
    Ok(parsed.to_string())
}


#[tauri::command]
pub async fn open_external_url(url: String) -> Result<String, String> {
    let safe_url = validate_external_https_url(&url)?;
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(&safe_url)
            .spawn()
            .map_err(|e| format!("无法打开外部链接：{e}"))?;
        Ok(safe_url)
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(&safe_url)
            .spawn()
            .map_err(|e| format!("无法打开外部链接：{e}"))?;
        Ok(safe_url)
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(&safe_url)
            .spawn()
            .map_err(|e| format!("无法打开外部链接：{e}"))?;
        Ok(safe_url)
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = safe_url;
        Err("当前操作系统暂不支持自动打开外部链接，请手动复制链接后在浏览器打开".to_string())
    }
}

