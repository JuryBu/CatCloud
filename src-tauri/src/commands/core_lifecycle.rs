use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use catcloud_core::config;
use catcloud_core::core_adapter::binary_resolver::compute_file_sha256;
use catcloud_core::core_adapter::binary_resolver::resolve_mihomo_binary;
use catcloud_core::core_adapter::config_compiler::CompileInput;
use catcloud_core::core_adapter::config_compiler::compile_mihomo_config_with_runtime_dir;
use catcloud_core::core_adapter::hot_reload::DiskReloadOptions;
use catcloud_core::core_adapter::mihomo::generate_controller_secret;
use catcloud_core::core_adapter::mihomo::verify_config_with_binary;
use catcloud_core::core_adapter::port_guard::AllocatedPorts;
use catcloud_core::core_adapter::port_guard::allocate_safe_ports;
use catcloud_core::core_adapter::CoreAdapter;
use catcloud_core::core_adapter::CoreStartRequest;
use catcloud_core::core_adapter::ReloadLevel;
use catcloud_core::core_adapter::ReloadOutcome;
use catcloud_core::core_adapter::TrafficTick;
use catcloud_core::models::ProxyMode;
use catcloud_core::AppPaths;
use chrono::Utc;
use tauri::AppHandle;
use tauri::Emitter;
use tauri::Manager;
use tauri::State;

use crate::commands::state::AppState;
use crate::commands::state::CachedRealtimeMetrics;
use crate::commands::state::CoreRuntimeInfoDto;
use crate::commands::state::EVENT_CONFIG_UPDATED;
use crate::commands::state::EVENT_TRAFFIC;
use crate::commands::state::TrafficEventPayload;
use crate::commands::state::UiAppConfigDto;
use crate::commands::state::summarize_connections;
use crate::commands::strategy_rank::reconcile_group_best_node_in_memory_with_runtime;
use crate::commands::strategy_rank::sanitize_group_active_node_with_runtime;
use crate::commands::system_proxy::apply_system_proxy_if_still_enabled;
use crate::commands::system_proxy::clear_system_proxy_if_owned_with_hint;
use crate::commands::system_proxy::coordinate_global_preaccel_on_tun_transition;
use crate::commands::system_proxy::load_enabled_preaccel_relays;
use crate::commands::system_proxy::maybe_spawn_auto_windivert_download;
#[cfg(target_os = "windows")]
use crate::commands::system_proxy::relaunch_self_with_elevation_flags;
use crate::commands::system_proxy::start_global_preaccel_engine;
use crate::commands::tray_runtime::build_runtime_info_dto;
use crate::commands::tray_runtime::config_may_have_tun;
use crate::commands::tray_runtime::effective_config_for_runtime;
use crate::commands::tray_runtime::effective_tun_enabled;
use crate::commands::tray_runtime::emit_config_updated;
use crate::commands::tray_runtime::format_mihomo_error_for_user;
use crate::commands::tray_runtime::has_enabled_nodes;
use crate::commands::tray_runtime::is_tun_privilege_ready;
use crate::commands::tray_runtime::sync_tray_and_window_side_effects;
use crate::commands::tray_runtime::tun_needs_admin_error_message;

pub(in crate::commands) fn refresh_node_proxy_name_map(state: &AppState) {
    let cfg = state.snapshot_config();
    let rt = state.snapshot_runtime();
    let Ok((nodes, groups, relays)) = state.storage.lock().map(|db| {
        (
            db.list_nodes().unwrap_or_default(),
            db.list_multi_groups().unwrap_or_default(),
            db.list_preaccel_relays(false).unwrap_or_default(),
        )
    }) else {
        return;
    };
    let (extra_rules, extra_filters) = state
        .campus_tracker
        .lock()
        .map(|t| {
            (
                t.active_direct_rules().to_vec(),
                t.active_fake_ip_filters().to_vec(),
            )
        })
        .unwrap_or_default();
    let allocated = AllocatedPorts {
        bind_host: if cfg.allow_lan {
            cfg.bind_address.clone()
        } else {
            "127.0.0.1".to_string()
        },
        mixed_port: if rt.running { rt.mixed_port } else { cfg.mixed_port },
        controller_port: if rt.running {
            rt.controller_port
        } else {
            cfg.controller_port
        },
        dns_port: if rt.running {
            rt.dns_listen_port
        } else {
            cfg.dns_listen_port
        },
        shifted: Vec::new(),
    };
    let empty_filter = HashMap::new();
    let input = CompileInput {
        config: &cfg,
        nodes: &nodes,
        groups: &groups,
        relays: &relays,
        controller_secret: "map-sync",
        allocated_ports: &allocated,
        extra_prepend_rules: &extra_rules,
        extra_fake_ip_filters: &extra_filters,
        group_filtered_members: &empty_filter,
    };
    if let Ok(compiled) =
        compile_mihomo_config_with_runtime_dir(&input, Some(&state.paths.runtime_dir))
    {
        state.set_last_effective_tun_mtu(Some(compiled.stats.effective_tun_mtu));
        state.set_node_proxy_name_map(compiled.node_id_to_proxy_name);
        state.set_compiled_group_ids(Some(
            compiled
                .group_mappings
                .iter()
                .map(|g| g.group_id.clone())
                .collect(),
        ));
    }
}


/// Start the managed Mihomo core subprocess (caller must hold `state.core_lifecycle_lock`).
async fn start_core_locked(app: &AppHandle, state: &AppState) -> Result<CoreRuntimeInfoDto, String> {
    if state.shutting_down.load(Ordering::SeqCst) {
        return Err("应用正在退出，已取消启动代理核心".to_string());
    }

    let cfg = state.snapshot_config();
    let extra_candidates = state.extra_binary_candidates();
    let resolution = resolve_mihomo_binary(&cfg, &state.paths, &extra_candidates, false)
        .map_err(|e| {
            let msg = format!("查找代理核心失败：{e}");
            state.log_app_event("error", "核心", &msg);
            msg
        })?;
    let binary_path = resolution.path.ok_or_else(|| {
        let msg = "未找到 Mihomo 代理核心文件，请将内核放入 bin 目录或在设置中指定内核路径".to_string();
        state.log_app_event("error", "核心", &msg);
        msg
    })?;

    let (nodes, groups, relays) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let nodes = db.list_nodes().map_err(|e| e.to_string())?;
        let mut groups = db.list_multi_groups().map_err(|e| e.to_string())?;
        let relays = db.list_preaccel_relays(false).map_err(|e| e.to_string())?;

        // Before compiling runtime YAML, sanitize ghost active_node_id on all groups and
        // reconcile best healthy candidates for the active group & independent-routing groups.
        if !nodes.is_empty() && !groups.is_empty() {
            let node_ids: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
            let default_snaps = db
                .get_probe_snapshots_batch(&node_ids, None)
                .unwrap_or_default();
            let primary_gid = cfg
                .active_group_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .and_then(|aid| groups.iter().find(|g| g.id == aid).map(|g| g.id.clone()))
                .or_else(|| groups.first().map(|g| g.id.clone()));

            let health_pool = state.snapshot_node_health_pool();
            let now = Instant::now();
            for group in &mut groups {
                let prev_active = group.active_node_id.clone();
                let is_target =
                    primary_gid.as_deref() == Some(group.id.as_str()) || group.independent_routing;
                if let Some(ref probe_id) = group.primary_probe_id {
                    let group_snaps = db
                        .get_probe_snapshots_batch(&node_ids, Some(probe_id.as_str()))
                        .unwrap_or_else(|_| default_snaps.clone());
                    if is_target {
                        let _ = reconcile_group_best_node_in_memory_with_runtime(
                            group,
                            &nodes,
                            &group_snaps,
                            Some(&health_pool),
                            now,
                        );
                    } else {
                        let _ = sanitize_group_active_node_with_runtime(
                            group,
                            &nodes,
                            &group_snaps,
                            Some(&health_pool),
                            now,
                        );
                    }
                } else if is_target {
                    let _ = reconcile_group_best_node_in_memory_with_runtime(
                        group,
                        &nodes,
                        &default_snaps,
                        Some(&health_pool),
                        now,
                    );
                } else {
                    let _ = sanitize_group_active_node_with_runtime(
                        group,
                        &nodes,
                        &default_snaps,
                        Some(&health_pool),
                        now,
                    );
                }
                if group.active_node_id != prev_active {
                    let _ = db.upsert_multi_group(group);
                }
            }
        }
        (nodes, groups, relays)
    };
    let (extra_rules, extra_filters) = {
        let tracker = state.campus_tracker.lock().map_err(|e| e.to_string())?;
        (
            tracker.active_direct_rules().to_vec(),
            tracker.active_fake_ip_filters().to_vec(),
        )
    };

    let bind_host = if cfg.allow_lan {
        cfg.bind_address.as_str()
    } else {
        "127.0.0.1"
    };
    let controller_host = if cfg.allow_lan {
        cfg.controller_host.clone()
    } else {
        "127.0.0.1".to_string()
    };
    let allocated = allocate_safe_ports(
        bind_host,
        cfg.mixed_port,
        cfg.controller_port,
        cfg.dns_listen_port,
        cfg.port_guard_auto_shift,
    )
    .map_err(|e| format!("分配本地代理端口失败：{e}"))?;

    let secret = cfg
        .controller_secret
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(generate_controller_secret);

    let tun_ready = is_tun_privilege_ready(state);
    let eff_cfg = effective_config_for_runtime(state, &cfg);
    let eff_tun = eff_cfg.tun.enabled;
    let tun_need_elev = cfg.tun.enabled && !tun_ready;
    let empty_filter = HashMap::new();
    let input = CompileInput {
        config: &eff_cfg,
        nodes: &nodes,
        groups: &groups,
        relays: &relays,
        controller_secret: &secret,
        allocated_ports: &allocated,
        extra_prepend_rules: &extra_rules,
        extra_fake_ip_filters: &extra_filters,
        group_filtered_members: &empty_filter,
    };
    let mut compiled = compile_mihomo_config_with_runtime_dir(&input, Some(&state.paths.runtime_dir))
        .map_err(|e| {
            let msg = format_mihomo_error_for_user(&format!("生成代理配置失败：{e}"));
            state.log_app_event("error", "核心", &msg);
            msg
        })?;
    if !tun_ready {
        catcloud_core::core_adapter::enforce_tun_disabled_on_compiled(&mut compiled).map_err(
            |e| {
                let msg = format_mihomo_error_for_user(&format!("非提权模式强制关闭覆写 TUN 失败：{e}"));
                state.log_app_event("error", "核心", &msg);
                msg
            },
        )?;
    }
    if !compiled.validation.ok {
        let fallback_hint =
            catcloud_core::core_adapter::resolve_default_fallback_group_name(&eff_cfg, &groups);
        let summary = catcloud_core::core_adapter::format_static_validation_summary_zh(
            &compiled.validation,
            Some(&fallback_hint),
        );
        let msg = format!("代理配置静态预检未通过：{summary}");
        state.log_app_event("error", "核心", &msg);
        return Err(msg);
    }

    let runtime_yaml = state.hot_reload.runtime_yaml_path();
    if let Some(parent) = runtime_yaml.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("创建运行时配置目录失败：{e}"))?;
    }
    let tmp_yaml = state.paths.runtime_dir.join(format!(
        "runtime.{}.yaml.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::write(&tmp_yaml, compiled.yaml.as_bytes())
        .map_err(|e| format!("写入临时核心配置失败：{e}"))?;
    verify_config_with_binary(
        &binary_path,
        &state.paths.runtime_dir,
        &tmp_yaml,
        Duration::from_secs(8),
    )
    .await
    .map_err(|e| {
        let _ = std::fs::remove_file(&tmp_yaml);
        let msg = format_mihomo_error_for_user(&e.to_string());
        state.log_app_event("error", "核心", &format!("内核配置预检失败：{msg}"));
        msg
    })?;
    AppPaths::atomic_write(&runtime_yaml, compiled.yaml.as_bytes()).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_yaml);
        format!("写入运行时核心配置失败：{e}")
    })?;
    let _ = std::fs::remove_file(&tmp_yaml);

    let start_req = CoreStartRequest {
        binary_path,
        working_dir: state.paths.runtime_dir.clone(),
        config_path: runtime_yaml,
        config: eff_cfg.clone(),
        allocated_ports: allocated.clone(),
        controller_host,
        controller_secret: secret.clone(),
        node_count: compiled.stats.total_proxies,
        rule_count: compiled.stats.total_rules,
        active_selections: compiled.active_selections.clone(),
    };

    let status = state.adapter.start(start_req).await.map_err(|e| {
        let msg = format_mihomo_error_for_user(&format!("启动代理核心失败：{e}"));
        state.log_app_event("error", "核心", &msg);
        msg
    })?;

    let loaded_nodes_count = compiled.stats.total_proxies;
    let loaded_relays_count = compiled.stats.relay_proxies;
    let effective_tun_mtu = compiled.stats.effective_tun_mtu;
    let total_library_nodes = nodes.len();
    state.set_last_effective_tun_mtu(Some(effective_tun_mtu));
    state.set_node_proxy_name_map(compiled.node_id_to_proxy_name);
    state.set_compiled_group_ids(Some(
        compiled
            .group_mappings
            .iter()
            .map(|g| g.group_id.clone())
            .collect(),
    ));
    state
        .hot_reload
        .seed_active_state(eff_cfg.clone(), compiled.sha256, allocated.clone(), secret.clone())
        .await;
    state.bump_core_session_generation();
    state.clear_group_backoffs();
    state.update_cached_runtime(status.clone());
    state.clear_app_error();
    let tun_start_label = if eff_tun {
        "开启"
    } else if tun_need_elev {
        "未生效（需管理员权限）"
    } else {
        "关闭"
    };
    state.log_app_event(
        "info",
        "核心",
        &format!(
            "代理核心已启动（模式 {}，混合端口 {}，已按需加载节点 {} 个（含中转 {} 个，节点库共 {} 个），规则 {} 条，虚拟网卡 {}，国内提速 {}）",
            cfg.proxy_mode.as_str(),
            status.mixed_port,
            loaded_nodes_count,
            loaded_relays_count,
            total_library_nodes,
            status.rule_count,
            tun_start_label,
            if cfg.preaccel.enabled { "开启" } else { "关闭" }
        ),
    );
    if tun_need_elev {
        state.log_app_event(
            "warning",
            "虚拟网卡",
            "配置已勾选虚拟网卡（TUN），但当前为普通用户权限，虚拟网卡未生效（仅系统代理生效，部分桌面应用/终端可能无法走代理）；请点击一键以管理员身份重启",
        );
    }

    // Attach bounded background telemetry streams (`/traffic`, `/memory`, `/logs`).
    state.attach_streams(
        &status.controller_host,
        status.controller_port,
        &secret,
        cfg.log_level.clone(),
    );

    // Re-sync OS system proxy to the actual bound mixed_port under `system_proxy_lock`.
    if let Err(err) = apply_system_proxy_if_still_enabled(state, status.mixed_port) {
        tracing::warn!("核心启动后同步系统代理端口失败：{err}");
    }

    // Coordinate with standalone global pre-acceleration using the SAME launch-time effective TUN
    // state so unprivileged startup never falsely pauses the standalone 443 engine.
    let tun_active = status.running && eff_tun;
    if tun_active {
        if cfg.preaccel.enabled {
            let active_relays: Vec<String> = load_enabled_preaccel_relays(state)
                .unwrap_or_default()
                .into_iter()
                .map(|r| r.name)
                .collect();
            let was_running = state.global_preaccel.status().running;
            if was_running || !active_relays.is_empty() {
                let _ = state.global_preaccel.suspend_for_tun(active_relays).await;
                if was_running {
                    state.log_app_event(
                        "info",
                        "国内提速",
                        "虚拟网卡（TUN）已启动接管全机流量，已暂挂独立底层 443 隧道以避免重复占用内存，改由主核心统一提供国内提速",
                    );
                }
            }
        } else if state.global_preaccel.status().running
            || state.global_preaccel.status().mode == "suspended_for_tun"
        {
            let _ = state.global_preaccel.stop().await;
        }
    } else {
        let main_pid = if status.running {
            status.pid.filter(|&p| p > 0)
        } else {
            None
        };
        state.global_preaccel.sync_main_core_pid(main_pid);
        if !state.shutting_down.load(Ordering::SeqCst)
            && cfg.preaccel.enabled
            && !tun_active
            && load_enabled_preaccel_relays(state).is_ok_and(|relays| !relays.is_empty())
        {
            if !state.global_preaccel.status().running {
                if let Err(err) = start_global_preaccel_engine(state, &cfg).await {
                    tracing::debug!(
                        "start_core_locked standalone global preaccel sync skipped: {err}"
                    );
                }
            }
            maybe_spawn_auto_windivert_download(app, state, &cfg);
        }
    }

    sync_tray_and_window_side_effects(app, state, &cfg);
    build_runtime_info_dto(state)
}


/// Start the managed Mihomo core subprocess (if not running) and attach background telemetry streams.
pub async fn start_core_internal(
    app: &AppHandle,
    state: &AppState,
) -> Result<CoreRuntimeInfoDto, String> {
    let _lifecycle_guard = state.core_lifecycle_lock.lock().await;
    start_core_locked(app, state).await
}


/// Stop managed core temporarily for a restart WITHOUT clearing persisted system_proxy/tun toggles.
/// Caller must hold `state.core_lifecycle_lock`.
async fn stop_core_for_restart_locked(state: &AppState) -> Result<(), String> {
    let cfg = state.snapshot_config();
    let may_have_tun = config_may_have_tun(state, &cfg);
    if may_have_tun && state.adapter.has_live_controller().await {
        let _ = state.adapter.disable_tun_gracefully().await;
    }
    state.stop_streams();
    state
        .adapter
        .stop()
        .await
        .map_err(|e| format!("停止旧代理核心失败：{e}"))?;
    state.global_preaccel.sync_main_core_pid(None);
    state.clear_node_health_pool();
    state.clear_group_backoffs();
    state.bump_core_session_generation();
    state.telemetry.clear_traffic();
    state.set_node_proxy_name_map(HashMap::new());
    state.set_compiled_group_ids(None);
    state.set_last_effective_tun_mtu(None);
    let status = state.adapter.status().await;
    state.update_cached_runtime(status);
    if let Ok(mut m) = state.cached_metrics.write() {
        *m = CachedRealtimeMetrics::default();
    }
    Ok(())
}


/// Stop managed core cleanly (caller must hold `state.core_lifecycle_lock`):
/// 1. Flip in-memory `system_proxy.enabled` / `tun.enabled` to false immediately so ProxyGuard
///    cannot re-enable system proxy concurrently.
/// 2. Clear OS system proxy under `system_proxy_lock` (only when owned by CatCloud).
/// 3. Persist updated `config.json`.
/// 4. Gracefully disable TUN and stop the core subprocess.
pub(in crate::commands) async fn stop_core_locked(
    app: &AppHandle,
    state: &AppState,
    clear_tun_intent: bool,
) -> Result<CoreRuntimeInfoDto, String> {
    let old_cfg = state.snapshot_config();
    let was_sys_proxy_enabled = old_cfg.system_proxy.enabled;
    let may_have_tun = config_may_have_tun(state, &old_cfg);
    let mut cfg = (*old_cfg).clone();
    let flags_changed = cfg.system_proxy.enabled || (clear_tun_intent && cfg.tun.enabled);

    if flags_changed {
        cfg.system_proxy.enabled = false;
        if clear_tun_intent {
            cfg.tun.enabled = false;
        }
        if let Ok(mut guard) = state.config.write() {
            *guard = Arc::new(cfg.clone());
        }
    }

    let mut clear_proxy_err: Option<String> = None;
    if let Err(first_err) = clear_system_proxy_if_owned_with_hint(state, was_sys_proxy_enabled) {
        tracing::warn!("停止核心前首次清除系统代理失败，将在 150ms 后重试：{first_err}");
        tokio::time::sleep(Duration::from_millis(150)).await;
        if let Err(retry_err) =
            clear_system_proxy_if_owned_with_hint(state, was_sys_proxy_enabled)
        {
            state.log_app_event(
                "error",
                "系统代理",
                &format!(
                    "停止核心前清除操作系统代理失败（已重试 1 次），请检查系统代理设置：{retry_err}"
                ),
            );
            clear_proxy_err = Some(retry_err);
        }
    }

    let save_err = if flags_changed {
        config::save(&state.paths, &cfg).err()
    } else {
        None
    };

    if may_have_tun && state.adapter.has_live_controller().await {
        let _ = state.adapter.disable_tun_gracefully().await;
    }

    state.stop_streams();
    state.adapter.stop().await.map_err(|e| {
        let msg = format!("停止代理核心失败：{e}");
        state.log_app_event("error", "核心", &msg);
        msg
    })?;
    state.global_preaccel.sync_main_core_pid(None);
    state.clear_node_health_pool();
    state.clear_group_backoffs();
    state.bump_core_session_generation();
    state.telemetry.clear_traffic();
    state.set_node_proxy_name_map(HashMap::new());
    state.set_compiled_group_ids(None);
    state.set_last_effective_tun_mtu(None);
    let mut status = state.adapter.status().await;
    if let Some(ref proxy_err) = clear_proxy_err {
        if !state.shutting_down.load(Ordering::SeqCst) {
            status.last_error = Some(format!("停止核心后清除系统代理失败：{proxy_err}"));
        }
    }
    state.update_cached_runtime(status);
    if let Ok(mut m) = state.cached_metrics.write() {
        *m = CachedRealtimeMetrics::default();
    }
    let _ = app.emit(
        EVENT_TRAFFIC,
        TrafficEventPayload {
            up_bps: 0,
            down_bps: 0,
            up_total_bytes: 0,
            down_total_bytes: 0,
            active_connections: 0,
            tunnel_connections: 0,
            core_memory_mb: 0.0,
            timestamp_ms: Utc::now().timestamp_millis(),
        },
    );
    if let Some(ref proxy_err) = clear_proxy_err {
        state.log_app_event(
            "warning",
            "核心",
            &format!("代理核心已停止，但自动清除系统代理失败，请检查系统代理设置：{proxy_err}"),
        );
    } else {
        state.log_app_event("info", "核心", "代理核心已停止，系统代理与虚拟网卡状态已复位");
    }

    // If the unified domestic pre-acceleration switch remains enabled while stopping CatCloud's
    // main proxy core, seamlessly keep or resume the lightweight standalone 443 tunnel.
    if !state.shutting_down.load(Ordering::SeqCst)
        && cfg.preaccel.enabled
        && load_enabled_preaccel_relays(state).is_ok_and(|relays| !relays.is_empty())
    {
        if !state.global_preaccel.status().running {
            match start_global_preaccel_engine(state, &cfg).await {
                Ok(global_st) => {
                    state.log_app_event(
                        "info",
                        "国内提速",
                        &format!(
                            "主代理核心已停止，已自动保持独立底层国内提速接棒（模式：{}）",
                            global_st.mode
                        ),
                    );
                }
                Err(err) => {
                    state.log_app_event(
                        "warning",
                        "国内提速",
                        &format!("主核心停止后自动切回独立底层国内提速失败：{err}"),
                    );
                }
            }
        }
        maybe_spawn_auto_windivert_download(app, state, &cfg);
    }

    sync_tray_and_window_side_effects(app, state, &cfg);
    let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&cfg));
    if let Some(err) = save_err {
        return Err(format!("保存配置失败：{err}"));
    }
    build_runtime_info_dto(state)
}


/// Stop managed core cleanly, gracefully tearing down TUN and OS system proxy to prevent
/// blackholing host internet access.
pub async fn stop_core_internal(
    app: &AppHandle,
    state: &AppState,
) -> Result<CoreRuntimeInfoDto, String> {
    let _lifecycle_guard = state.core_lifecycle_lock.lock().await;
    stop_core_locked(app, state, true).await
}


/// Stop managed core when disabling system proxy under unprivileged mode while preserving
/// any persisted `tun.enabled` user intent on disk.
pub(in crate::commands) async fn stop_core_preserving_tun_intent_internal(
    app: &AppHandle,
    state: &AppState,
) -> Result<CoreRuntimeInfoDto, String> {
    let _lifecycle_guard = state.core_lifecycle_lock.lock().await;
    stop_core_locked(app, state, false).await
}


/// Atomically disable OS system proxy and TUN virtual NIC, persist both flags as `false`, and
/// terminate the main `mihomo` core with zero port/memory/connection residue (while keeping the
/// lightweight standalone 443 pre-acceleration tunnel active if the unified switch is enabled).
/// Captures `(was_sys_proxy, was_eff_tun)` in transient memory so `enable_proxy_power` can
/// symmetrically restore the user's prior takeover combination without ever persisting auto-start.
pub async fn disable_all_proxy_and_stop_core_internal(
    app: &AppHandle,
    state: &AppState,
) -> Result<CoreRuntimeInfoDto, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    let old_cfg = state.snapshot_config();
    let sys_proxy_was_on = old_cfg.system_proxy.enabled;
    let eff_tun_was_on = effective_tun_enabled(state, &old_cfg);
    state.record_power_off_takeover_memory(sys_proxy_was_on, eff_tun_was_on);
    let _lifecycle_guard = state.core_lifecycle_lock.lock().await;
    stop_core_locked(app, state, true).await
}


pub(in crate::commands) fn format_reload_level_zh(level: ReloadLevel) -> &'static str {
    match level {
        ReloadLevel::L1Rest => "毫秒级热切换（L1）",
        ReloadLevel::L2HotReload => "热重载（L2）",
        ReloadLevel::L3CoreRestart => "核心轻量重启",
    }
}


/// Reload core configuration from disk via `HotReloadCoordinator` when running, allowing callers
/// to explicitly control whether L3 subprocess restarts are permitted (e.g., cross-process live
/// hot-reload defaults `allow_l3_restart = false` to protect active TUN/long-lived connections).
/// Acquires `core_lifecycle_lock` and re-checks shutdown/live-controller state so an in-flight
/// reload can never resurrect the core after `stop_core`.
pub async fn trigger_reload_if_running_with_options(
    app: &AppHandle,
    state: &AppState,
    force: bool,
    allow_l3_restart: bool,
) -> Option<ReloadOutcome> {
    let _lifecycle_guard = state.core_lifecycle_lock.lock().await;
    if state.shutting_down.load(Ordering::SeqCst) || !state.adapter.has_live_controller().await {
        return None;
    }
    let prev_status = state.adapter.status().await;
    let prev_secret = state.adapter.controller_secret().await;
    let prev_log_level = state
        .last_log_level
        .read()
        .map(|g| g.clone())
        .unwrap_or_else(|_| state.snapshot_config().log_level.clone());

    let (extra_rules, extra_filters) = state
        .campus_tracker
        .lock()
        .map(|t| {
            (
                t.active_direct_rules().to_vec(),
                t.active_fake_ip_filters().to_vec(),
            )
        })
        .unwrap_or_default();

    let outcome = state
        .hot_reload
        .apply_disk_reload(DiskReloadOptions {
            force,
            verify_with_binary: true,
            allow_l3_restart,
            allow_tun: is_tun_privilege_ready(state),
            extra_prepend_rules: extra_rules,
            extra_fake_ip_filters: extra_filters,
            ..DiskReloadOptions::default()
        })
        .await;

    let status = state.adapter.status().await;
    let new_secret = state.adapter.controller_secret().await;
    state.update_cached_runtime(status.clone());
    let cfg = state.snapshot_config();

    if outcome.applied {
        refresh_node_proxy_name_map(state);
        state.clear_app_error();
        state.log_app_event(
            "info",
            "热重载",
            &format!(
                "配置热重载成功（级别：{}，回放分组 {} 个）",
                format_reload_level_zh(outcome.level),
                outcome.replayed_groups
            ),
        );
    } else if outcome.rejected {
        let detail = outcome
            .error
            .as_deref()
            .map(format_mihomo_error_for_user)
            .unwrap_or_else(|| "未知原因".to_string());
        state.log_app_event(
            "error",
            "热重载",
            &format!("配置热重载被拒绝，已保留原运行配置：{detail}"),
        );
    }

    let endpoint_changed = prev_status.controller_host != status.controller_host
        || prev_status.controller_port != status.controller_port;
    let secret_changed = prev_secret != new_secret;
    let log_level_changed = prev_log_level != cfg.log_level;
    let is_l3_restart = outcome.level == ReloadLevel::L3CoreRestart;

    if outcome.applied
        && status.running
        && (is_l3_restart || endpoint_changed || secret_changed || log_level_changed)
    {
        if is_l3_restart {
            state.bump_core_session_generation();
        }
        state.attach_streams(
            &status.controller_host,
            status.controller_port,
            &new_secret,
            cfg.log_level.clone(),
        );
    }

    // Re-sync OS system proxy after L3 core restart under `system_proxy_lock`.
    if outcome.applied && is_l3_restart && status.running {
        if let Err(err) = apply_system_proxy_if_still_enabled(state, status.mixed_port) {
            tracing::warn!("核心轻量重启后同步系统代理端口失败：{err}");
        }
    }

    // Keep WinDivert main-core PID exclusion in sync across L3 restarts or unexpected exits.
    if (is_l3_restart || !status.running) && state.global_preaccel.status().running {
        let main_pid = if status.running {
            status.pid.filter(|&p| p > 0)
        } else {
            None
        };
        state.global_preaccel.sync_main_core_pid(main_pid);
    }

    sync_tray_and_window_side_effects(app, state, &cfg);
    Some(outcome)
}


/// Reload core configuration from disk via `HotReloadCoordinator` when running (allowing L3 core
/// restarts by default for explicit in-app operations).
pub async fn trigger_reload_if_running(
    app: &AppHandle,
    state: &AppState,
    force: bool,
) -> Option<ReloadOutcome> {
    trigger_reload_if_running_with_options(app, state, force, true).await
}


/// Apply system proxy state safely:
/// - Turning ON checks for enabled nodes, auto-starts the core when stopped, validates reload,
///   and rolls back `config.json` on any failure so Windows is never left with a dead proxy.
/// - Turning OFF updates in-memory config first, clears owned OS proxy under `system_proxy_lock`,
///   and stops the main core cleanly when TUN is also disabled (zero port/memory/connection residue).
pub async fn apply_system_proxy_internal(
    app: &AppHandle,
    state: &AppState,
    enabled: bool,
) -> Result<bool, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    let old_cfg = state.snapshot_config();
    let old_sys_proxy_enabled = old_cfg.system_proxy.enabled;
    let was_core_running =
        state.snapshot_runtime().running || state.adapter.has_live_controller().await;
    let was_tun_active = was_core_running && effective_tun_enabled(state, &old_cfg);

    if !enabled {
        let was_enabled = old_sys_proxy_enabled;
        let mut cfg = (*old_cfg).clone();
        cfg.system_proxy.enabled = false;
        if let Ok(mut guard) = state.config.write() {
            *guard = Arc::new(cfg.clone());
        }
        if let Err(err) = clear_system_proxy_if_owned_with_hint(state, was_enabled) {
            let mut rollback = state.clone_config();
            rollback.system_proxy.enabled = was_enabled;
            if let Ok(mut guard) = state.config.write() {
                *guard = Arc::new(rollback.clone());
            }
            return Err(err);
        }
        config::save(&state.paths, &cfg).map_err(|e| format!("保存系统代理状态失败：{e}"))?;

        let latest_before_stop = state.snapshot_config();
        let now_core_running =
            state.snapshot_runtime().running || state.adapter.has_live_controller().await;
        let latest_eff_tun = effective_tun_enabled(state, &latest_before_stop);
        if !latest_before_stop.system_proxy.enabled && !latest_eff_tun && now_core_running {
            stop_core_preserving_tun_intent_internal(app, state).await?;
            state.log_app_event(
                "info",
                "系统代理",
                "已关闭系统代理并停止主代理核心（已释放监听端口与内存）",
            );
            return Ok(false);
        }

        let now_tun_active = now_core_running && latest_eff_tun;
        coordinate_global_preaccel_on_tun_transition(
            app,
            state,
            &latest_before_stop,
            was_tun_active,
            now_tun_active,
            "系统代理",
        )
        .await;
        state.log_app_event("info", "系统代理", "已关闭系统代理");
        let latest_cfg = state.snapshot_config();
        sync_tray_and_window_side_effects(app, state, &latest_cfg);
        let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&latest_cfg));
        return Ok(false);
    }

    // 1. Refuse turning ON system proxy when no enabled proxy nodes exist.
    if !has_enabled_nodes(state)? {
        return Err("暂无可用节点，请先导入订阅".to_string());
    }

    // 2. Re-read disk config so external Agent edits take effect on toggle ON.
    let mut disk_cfg = config::load_or_init(&state.paths)
        .map_err(|e| format!("读取配置文件失败：{e}"))?;
    disk_cfg.preaccel.reconcile_unified_enabled();

    let mut started_core_here = false;
    let mut cfg = disk_cfg.clone();
    if !state.adapter.has_live_controller().await {
        // Boot core first WITHOUT dirty-writing `system_proxy.enabled = true` to disk.
        let mut boot_cfg = disk_cfg.clone();
        boot_cfg.system_proxy.enabled = false;
        if let Ok(mut guard) = state.config.write() {
            *guard = Arc::new(boot_cfg);
        }
        if let Err(err) = start_core_internal(app, state).await {
            let mut rollback = state.clone_config();
            rollback.system_proxy.enabled = old_sys_proxy_enabled;
            if let Ok(mut guard) = state.config.write() {
                *guard = Arc::new(rollback.clone());
            }
            sync_tray_and_window_side_effects(app, state, &rollback);
            return Err(format!("开启系统代理前启动核心失败：{err}"));
        }
        started_core_here = true;
        cfg = state.clone_config();
        cfg.system_proxy.enabled = true;
        if let Err(e) = config::save(&state.paths, &cfg) {
            let mut rollback = state.clone_config();
            rollback.system_proxy.enabled = old_sys_proxy_enabled;
            if let Ok(mut guard) = state.config.write() {
                *guard = Arc::new(rollback.clone());
            }
            if started_core_here
                && !rollback.system_proxy.enabled
                && !effective_tun_enabled(state, &rollback)
            {
                if let Err(stop_err) = stop_core_preserving_tun_intent_internal(app, state).await {
                    tracing::warn!("保存系统代理配置失败回滚后停止新拉起核心异常：{stop_err}");
                }
            }
            let latest = state.snapshot_config();
            sync_tray_and_window_side_effects(app, state, &latest);
            return Err(format!("保存系统代理配置失败：{e}"));
        }
        if let Ok(mut guard) = state.config.write() {
            *guard = Arc::new(cfg.clone());
        }
    } else {
        cfg.system_proxy.enabled = true;
        config::save(&state.paths, &cfg).map_err(|e| format!("保存系统代理配置失败：{e}"))?;
        if let Ok(mut guard) = state.config.write() {
            *guard = Arc::new(cfg.clone());
        }
        // Pass `force = false` so SHA-256 deduplication skips redundant Mihomo reloads when the
        // core is already running and only the OS system proxy toggle changed, while still picking
        // up any external disk/SQLite changes cleanly.
        if let Some(outcome) = trigger_reload_if_running(app, state, false).await {
            if outcome.rejected {
                let mut rollback = state.clone_config();
                rollback.system_proxy.enabled = old_sys_proxy_enabled;
                let _ = config::save(&state.paths, &rollback);
                if let Ok(mut guard) = state.config.write() {
                    *guard = Arc::new(rollback.clone());
                }
                sync_tray_and_window_side_effects(app, state, &rollback);
                let raw_err = outcome
                    .error
                    .unwrap_or_else(|| "配置预检未通过，已保持原配置运行".to_string());
                return Err(format_mihomo_error_for_user(&raw_err));
            }
        }
    }

    // 3. Apply WinINet system proxy under `system_proxy_lock` using live mixed_port; rollback on failure.
    let effective_port = {
        let rt = state.snapshot_runtime();
        if rt.running { rt.mixed_port } else { cfg.mixed_port }
    };
    match apply_system_proxy_if_still_enabled(state, effective_port) {
        Ok(true) => {}
        Ok(false) => {
            // Concurrent stop_core or shutdown disabled system proxy while we were enabling.
            let latest = state.snapshot_config();
            if started_core_here
                && !latest.system_proxy.enabled
                && !effective_tun_enabled(state, &latest)
            {
                if let Err(stop_err) = stop_core_preserving_tun_intent_internal(app, state).await {
                    tracing::warn!("系统代理取消后停止新拉起核心异常：{stop_err}");
                }
            }
            let latest = state.snapshot_config();
            sync_tray_and_window_side_effects(app, state, &latest);
            let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&latest));
            return Ok(false);
        }
        Err(err) => {
            let mut rollback = state.clone_config();
            rollback.system_proxy.enabled = old_sys_proxy_enabled;
            let _ = config::save(&state.paths, &rollback);
            if let Ok(mut guard) = state.config.write() {
                *guard = Arc::new(rollback.clone());
            }
            if started_core_here
                && !rollback.system_proxy.enabled
                && !effective_tun_enabled(state, &rollback)
            {
                // Lock order: already holding outer `config_transition_lock` -> inner `core_lifecycle_lock`.
                if let Err(stop_err) = stop_core_preserving_tun_intent_internal(app, state).await {
                    tracing::warn!("写入操作系统代理失败回滚后停止新拉起核心异常：{stop_err}");
                }
            }
            state.log_app_event(
                "error",
                "系统代理",
                &format!("写入操作系统代理失败，已回滚配置：{err}"),
            );
            let latest = state.snapshot_config();
            sync_tray_and_window_side_effects(app, state, &latest);
            let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&latest));
            return Err(err);
        }
    }

    let latest_cfg = state.snapshot_config();
    let now_core_running =
        state.snapshot_runtime().running || state.adapter.has_live_controller().await;
    let now_tun_active = now_core_running && effective_tun_enabled(state, &latest_cfg);
    coordinate_global_preaccel_on_tun_transition(
        app,
        state,
        &latest_cfg,
        was_tun_active,
        now_tun_active,
        "系统代理",
    )
    .await;

    state.clear_power_off_takeover_memory();
    state.log_app_event(
        "info",
        "系统代理",
        &format!("已开启系统代理（127.0.0.1:{effective_port}）"),
    );
    let latest_cfg = state.snapshot_config();
    sync_tray_and_window_side_effects(app, state, &latest_cfg);
    let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&latest_cfg));
    Ok(true)
}


/// Bounded stepped retry delays (seconds) before inspecting Go heap after switching `Global -> Rule`.
/// At most 3 attempts (`8s`, `30s`, `90s`), ensuring active proxy flows defer reclaim safely
/// without looping indefinitely or leaking background tasks.
pub(in crate::commands) const HEAP_RECLAIM_RETRY_DELAYS_SECS: [u64; 3] = [8, 30, 90];

/// Strictly skip L3 heap-reclaim restart whenever any active proxied stream exists (excluding
/// `Inner` tunnels, `DIRECT` apps such as QQ, and `REJECT` flows), protecting low-connection
/// long-lived AI/Codex SSE sessions from forced disconnects.
const HEAP_RECLAIM_MAX_PROXIED_CONNS: usize = 0;

/// Sliding window (10 s) for heap-reclaim idle throughput guard.
pub(in crate::commands) const HEAP_RECLAIM_HIGH_THROUGHPUT_WINDOW_MS: i64 = 10_000;

/// Combined upload + download throughput ceiling (`8 KiB/s`) below which core is considered idle.
pub(in crate::commands) const HEAP_RECLAIM_MAX_TOTAL_BPS: u64 = 8 * 1024;

/// Minimum cooldown between consecutive automatic heap-reclaim restarts (10 minutes).
const HEAP_RECLAIM_COOLDOWN_SECS: u64 = 10 * 60;

/// Floor memory threshold in MiB below which Go heap reclaim is skipped.
const HEAP_RECLAIM_MIN_MEMORY_MB: f64 = 90.0;


#[derive(Debug, Clone, Copy, PartialEq)]
pub(in crate::commands) struct HeapReclaimCheckInput {
    pub(in crate::commands) gen_matches: bool,
    pub(in crate::commands) is_rule_mode: bool,
    pub(in crate::commands) core_running: bool,
    pub(in crate::commands) tun_enabled: bool,
    pub(in crate::commands) proxied_connections: usize,
    pub(in crate::commands) direct_connections: usize,
    pub(in crate::commands) traffic_telemetry_fresh: bool,
    pub(in crate::commands) total_bytes_per_sec: u64,
    pub(in crate::commands) probing_active: bool,
    pub(in crate::commands) memory_mb: f64,
    pub(in crate::commands) budget_mb: f64,
    pub(in crate::commands) cooldown_elapsed: bool,
}


/// Compute peak combined (`up + down`) throughput in B/s across the cached real-time rate and
/// recent `/traffic` ticks inside `window_ms` of `now_ms`, together with whether at least one
/// fresh `/traffic` sample was observed in that window.
pub(in crate::commands) fn resolve_recent_peak_total_bps_with_freshness(
    cached: &CachedRealtimeMetrics,
    recent_ticks: &[TrafficTick],
    now_ms: i64,
    window_ms: i64,
) -> (u64, bool) {
    let mut peak = cached.up_bps.saturating_add(cached.down_bps);
    let mut has_fresh_tick = false;
    let cutoff_ms = now_ms.saturating_sub(window_ms.max(0));
    let upper_ms = now_ms.saturating_add(5_000);
    for tick in recent_ticks {
        if tick.timestamp_ms >= cutoff_ms && tick.timestamp_ms <= upper_ms {
            has_fresh_tick = true;
            peak = peak.max(tick.up.saturating_add(tick.down));
        }
    }
    (peak, has_fresh_tick)
}


/// Compute peak combined (`up + down`) throughput in B/s across the cached real-time rate and
/// recent `/traffic` ticks inside `window_ms` of `now_ms`.
#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::commands) fn resolve_recent_peak_total_bps(
    cached: &CachedRealtimeMetrics,
    recent_ticks: &[TrafficTick],
    now_ms: i64,
    window_ms: i64,
) -> u64 {
    resolve_recent_peak_total_bps_with_freshness(cached, recent_ticks, now_ms, window_ms).0
}


/// Pure guardrail evaluator for `Global -> Rule` delayed Go heap reclaim.
/// Returns `Ok(threshold_mb)` only when every safety invariant passes, including zero active
/// proxied connections (`proxied_connections == 0`), idle total throughput (`< 8 KiB/s`), and
/// fresh `/traffic` telemetry whenever `DIRECT` connections are present.
pub(in crate::commands) fn evaluate_heap_reclaim_guard(input: &HeapReclaimCheckInput) -> Result<f64, &'static str> {
    if !input.gen_matches {
        return Err("config_generation_changed");
    }
    if !input.is_rule_mode || !input.core_running {
        return Err("not_rule_or_core_stopped");
    }
    if input.tun_enabled {
        return Err("tun_active");
    }
    let threshold_mb = (input.budget_mb * 1.5).max(HEAP_RECLAIM_MIN_MEMORY_MB);
    if !input.memory_mb.is_finite() || input.memory_mb <= threshold_mb {
        return Err("memory_within_budget");
    }
    if !input.cooldown_elapsed {
        return Err("cooldown_active");
    }
    if input.proxied_connections > HEAP_RECLAIM_MAX_PROXIED_CONNS {
        return Err("active_proxied_connections");
    }
    if input.total_bytes_per_sec >= HEAP_RECLAIM_MAX_TOTAL_BPS {
        return Err("throughput_above_idle_threshold");
    }
    if input.direct_connections > 0 && !input.traffic_telemetry_fresh {
        return Err("traffic_telemetry_stale_with_direct_connections");
    }
    if input.probing_active {
        return Err("probing_active");
    }
    Ok(threshold_mb)
}


/// Return `true` if a heap-reclaim skip reason is transient and worth retrying on the next
/// bounded backoff step (`[8s, 30s, 90s]`).
pub(in crate::commands) fn is_heap_reclaim_reason_deferrable(reason: &str) -> bool {
    matches!(
        reason,
        "active_proxied_connections"
            | "throughput_above_idle_threshold"
            | "traffic_telemetry_stale_with_direct_connections"
            | "probing_active"
    )
}


/// Sleep for `delay_secs` while aborting promptly if the app shuts down or `config_generation`
/// advances past `expected_gen`.
async fn wait_heap_reclaim_delay(app: &AppHandle, expected_gen: u64, delay_secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(delay_secs);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return true;
        }
        tokio::time::sleep(remaining.min(Duration::from_secs(2))).await;
        let Some(st) = app.try_state::<AppState>() else {
            return false;
        };
        if st.shutting_down.load(Ordering::SeqCst) || st.config_generation() != expected_gen {
            return false;
        }
    }
}


pub(in crate::commands) fn schedule_global_to_rule_heap_reclaim(app: &AppHandle, expected_gen: u64) {
    let app_h = app.clone();
    tauri::async_runtime::spawn(async move {
        let total_attempts = HEAP_RECLAIM_RETRY_DELAYS_SECS.len();
        for (attempt_idx, &delay_secs) in HEAP_RECLAIM_RETRY_DELAYS_SECS.iter().enumerate() {
            if !wait_heap_reclaim_delay(&app_h, expected_gen, delay_secs).await {
                return;
            }

            let Some(st) = app_h.try_state::<AppState>() else {
                return;
            };
            if st.shutting_down.load(Ordering::SeqCst) || st.config_generation() != expected_gen {
                return;
            }

            // Never block or contend with active user config transitions; guard is dropped before
            // sleeping for any subsequent retry tier.
            let Ok(_cfg_guard) = st.config_transition_lock.try_lock() else {
                tracing::debug!(
                    attempt = attempt_idx + 1,
                    total_attempts,
                    "Global -> Rule delayed Go heap reclaim deferred: config transition busy"
                );
                continue;
            };
            if st.shutting_down.load(Ordering::SeqCst) || st.config_generation() != expected_gen {
                return;
            }

            let cfg = st.snapshot_config();
            let core_running =
                st.snapshot_runtime().running && st.adapter.has_live_controller().await;
            if cfg.proxy_mode != ProxyMode::Rule || !core_running {
                return;
            }

            let live_snap = tokio::time::timeout(
                Duration::from_millis(1000),
                st.adapter.list_connections(),
            )
            .await
            .ok()
            .and_then(|res| res.ok());
            // Never assume zero proxied streams when `/connections` snapshot is unavailable
            // (cached metrics may be stale when the GUI window is minimized).
            let Some(snap) = live_snap else {
                tracing::debug!(
                    attempt = attempt_idx + 1,
                    total_attempts,
                    "Global -> Rule delayed Go heap reclaim deferred: live /connections unavailable"
                );
                continue;
            };

            let cached = st
                .cached_metrics
                .read()
                .map(|m| *m)
                .unwrap_or_default();
            let summary = summarize_connections(&snap.connections);
            let mem_bytes = if snap.memory > 0 {
                snap.memory
            } else {
                cached.core_mem_bytes
            };

            let recent_ticks = st.telemetry.traffic_snapshot();
            let now_ms = Utc::now().timestamp_millis();
            let (total_bytes_per_sec, traffic_telemetry_fresh) =
                resolve_recent_peak_total_bps_with_freshness(
                    &cached,
                    &recent_ticks,
                    now_ms,
                    HEAP_RECLAIM_HIGH_THROUGHPUT_WINDOW_MS,
                );
            let rt = st.snapshot_runtime();
            let budget_mb = cfg
                .core_runtime
                .memory_tier
                .resolve_mib(rt.node_count, rt.rule_count) as f64;
            let memory_mb = (mem_bytes as f64) / (1024.0 * 1024.0);
            let cooldown_elapsed = st
                .last_heap_reclaim_at
                .lock()
                .ok()
                .and_then(|g| *g)
                .is_none_or(|last| last.elapsed() >= Duration::from_secs(HEAP_RECLAIM_COOLDOWN_SECS));

            let check = HeapReclaimCheckInput {
                gen_matches: st.config_generation() == expected_gen,
                is_rule_mode: cfg.proxy_mode == ProxyMode::Rule,
                core_running,
                tun_enabled: effective_tun_enabled(&st, &cfg),
                proxied_connections: summary.proxied_connections,
                direct_connections: summary.direct_connections,
                traffic_telemetry_fresh,
                total_bytes_per_sec,
                probing_active: st.probe_running.load(Ordering::SeqCst),
                memory_mb,
                budget_mb,
                cooldown_elapsed,
            };

            let threshold_mb = match evaluate_heap_reclaim_guard(&check) {
                Ok(threshold) => threshold,
                Err(reason) => {
                    let deferrable = is_heap_reclaim_reason_deferrable(reason);
                    let has_next = attempt_idx + 1 < total_attempts;
                    tracing::debug!(
                        reason,
                        attempt = attempt_idx + 1,
                        total_attempts,
                        deferred = deferrable && has_next,
                        memory_mb,
                        budget_mb,
                        proxied_connections = summary.proxied_connections,
                        direct_connections = summary.direct_connections,
                        app_connections = summary.app_connections,
                        traffic_telemetry_fresh,
                        total_bytes_per_sec,
                        "Global -> Rule delayed Go heap reclaim skipped"
                    );
                    if deferrable && has_next {
                        continue;
                    }
                    return;
                }
            };

            if let Ok(mut guard) = st.last_heap_reclaim_at.lock() {
                *guard = Some(Instant::now());
            }
            st.log_app_event(
                "info",
                "内存",
                &format!(
                    "从全局模式切回规则分流后核心内存偏高（{memory_mb:.1} MiB > 阈值 {threshold_mb:.1} MiB，当前无活跃代理流，直连 {} 条，总速率 {} B/s），正在执行核心轻量重启以回收 Go 堆内存",
                    summary.direct_connections, total_bytes_per_sec
                ),
            );

            match restart_core_locked(&app_h, &st).await {
                Ok(_) => {
                    st.log_app_event(
                        "info",
                        "内存",
                        "已完成核心轻量重启并回收 Go 堆内存（代理与规则分流状态保持正常）",
                    );
                }
                Err(err) => {
                    st.log_app_event(
                        "warning",
                        "内存",
                        &format!("延迟内存回收触发核心轻量重启未成功，已自动回滚保护：{err}"),
                    );
                }
            }
            return;
        }
    });
}


#[tauri::command]
pub async fn start_core(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CoreRuntimeInfoDto, String> {
    // Strictly uphold lock ordering: outer `config_transition_lock` -> inner `core_lifecycle_lock`.
    let _cfg_guard = state.config_transition_lock.lock().await;
    start_core_internal(&app, &state).await
}


#[tauri::command]
pub async fn stop_core(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CoreRuntimeInfoDto, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    stop_core_internal(&app, &state).await
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::commands) struct PowerOnTakeoverPlan {
    pub(in crate::commands) enable_sys_proxy: bool,
    pub(in crate::commands) enable_tun: bool,
    pub(in crate::commands) degraded_from_tun_due_to_privilege: bool,
}


pub(in crate::commands) fn resolve_power_on_takeover_plan(
    memory: Option<(bool, bool)>,
    tun_privilege_ready: bool,
) -> PowerOnTakeoverPlan {
    let (mem_sys, mem_tun) = memory.unwrap_or((true, false));
    if mem_tun {
        if tun_privilege_ready {
            PowerOnTakeoverPlan {
                enable_sys_proxy: mem_sys,
                enable_tun: true,
                degraded_from_tun_due_to_privilege: false,
            }
        } else {
            PowerOnTakeoverPlan {
                enable_sys_proxy: true,
                enable_tun: false,
                degraded_from_tun_due_to_privilege: true,
            }
        }
    } else {
        PowerOnTakeoverPlan {
            enable_sys_proxy: true,
            enable_tun: false,
            degraded_from_tun_due_to_privilege: false,
        }
    }
}


/// Atomically power ON the main proxy core and restore the prior `(system_proxy, tun)` takeover
/// combination captured before power-off (defaulting to `(true, false)` on cold start or when
/// cleared; safely degrading TUN to system proxy if administrator privileges are unavailable).
pub async fn enable_proxy_power_internal(
    app: &AppHandle,
    state: &AppState,
) -> Result<CoreRuntimeInfoDto, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    if !has_enabled_nodes(state)? {
        return Err("暂无可用节点，请先导入订阅".to_string());
    }

    let saved_memory = state.take_power_off_takeover_memory();
    let tun_ready = is_tun_privilege_ready(state);
    let plan = resolve_power_on_takeover_plan(saved_memory, tun_ready);

    let old_cfg = state.snapshot_config();
    let was_core_running =
        state.snapshot_runtime().running || state.adapter.has_live_controller().await;
    let was_tun_active = was_core_running && effective_tun_enabled(state, &old_cfg);

    let mut next_cfg = (*old_cfg).clone();
    next_cfg.system_proxy.enabled = plan.enable_sys_proxy;
    next_cfg.tun.enabled = plan.enable_tun;

    let mut started_core_here = false;
    let mut reloaded_tun_on_running_core = false;
    if !state.adapter.has_live_controller().await {
        // Boot core without dirty-writing `system_proxy.enabled = true` to disk first.
        let mut boot_cfg = next_cfg.clone();
        boot_cfg.system_proxy.enabled = false;
        if let Ok(mut guard) = state.config.write() {
            *guard = Arc::new(boot_cfg);
        }
        if let Err(err) = start_core_internal(app, state).await {
            if let Ok(mut guard) = state.config.write() {
                *guard = Arc::clone(&old_cfg);
            }
            state.restore_power_off_takeover_memory(saved_memory);
            sync_tray_and_window_side_effects(app, state, &old_cfg);
            return Err(format!("开启代理核心失败：{err}"));
        }
        started_core_here = true;
        let mut persisted_cfg = state.clone_config();
        persisted_cfg.system_proxy.enabled = plan.enable_sys_proxy;
        persisted_cfg.tun.enabled = plan.enable_tun;
        if let Err(e) = config::save(&state.paths, &persisted_cfg) {
            if let Ok(mut guard) = state.config.write() {
                *guard = Arc::clone(&old_cfg);
            }
            if !old_cfg.system_proxy.enabled && !effective_tun_enabled(state, &old_cfg) {
                let _ = stop_core_preserving_tun_intent_internal(app, state).await;
            }
            state.restore_power_off_takeover_memory(saved_memory);
            sync_tray_and_window_side_effects(app, state, &old_cfg);
            return Err(format!("保存代理开启状态失败：{e}"));
        }
        if let Ok(mut guard) = state.config.write() {
            *guard = Arc::new(persisted_cfg);
        }
    } else {
        if let Err(e) = config::save(&state.paths, &next_cfg) {
            state.restore_power_off_takeover_memory(saved_memory);
            return Err(format!("保存代理开启状态失败：{e}"));
        }
        if let Ok(mut guard) = state.config.write() {
            *guard = Arc::new(next_cfg.clone());
        }
        if old_cfg.tun.enabled != next_cfg.tun.enabled {
            if let Some(outcome) = trigger_reload_if_running(app, state, true).await {
                if outcome.rejected {
                    let _ = config::save(&state.paths, &old_cfg);
                    if let Ok(mut guard) = state.config.write() {
                        *guard = Arc::clone(&old_cfg);
                    }
                    state.restore_power_off_takeover_memory(saved_memory);
                    sync_tray_and_window_side_effects(app, state, &old_cfg);
                    let detail = outcome
                        .error
                        .as_deref()
                        .map(format_mihomo_error_for_user)
                        .unwrap_or_else(|| "配置重载未通过，已保持原状态".to_string());
                    return Err(detail);
                }
            }
            reloaded_tun_on_running_core = true;
        }
    }

    if plan.enable_sys_proxy {
        let effective_port = {
            let rt = state.snapshot_runtime();
            if rt.running {
                rt.mixed_port
            } else {
                next_cfg.mixed_port
            }
        };
        if let Err(err) = apply_system_proxy_if_still_enabled(state, effective_port) {
            let _ = config::save(&state.paths, &old_cfg);
            if let Ok(mut guard) = state.config.write() {
                *guard = Arc::clone(&old_cfg);
            }
            if started_core_here
                && !old_cfg.system_proxy.enabled
                && !effective_tun_enabled(state, &old_cfg)
            {
                let _ = stop_core_preserving_tun_intent_internal(app, state).await;
            } else if !started_core_here && reloaded_tun_on_running_core {
                if next_cfg.tun.enabled
                    && !old_cfg.tun.enabled
                    && state.adapter.has_live_controller().await
                {
                    let _ = state.adapter.disable_tun_gracefully().await;
                }
                let _ = trigger_reload_if_running(app, state, true).await;
            }
            state.restore_power_off_takeover_memory(saved_memory);
            sync_tray_and_window_side_effects(app, state, &old_cfg);
            emit_config_updated(app, &old_cfg);
            return Err(err);
        }
    } else if old_cfg.system_proxy.enabled {
        let _ = clear_system_proxy_if_owned_with_hint(state, true);
    }

    let latest_cfg = state.snapshot_config();
    let now_core_running =
        state.snapshot_runtime().running || state.adapter.has_live_controller().await;
    let now_tun_active = now_core_running && effective_tun_enabled(state, &latest_cfg);
    coordinate_global_preaccel_on_tun_transition(
        app,
        state,
        &latest_cfg,
        was_tun_active,
        now_tun_active,
        "代理总开关",
    )
    .await;

    if plan.degraded_from_tun_due_to_privilege {
        state.log_app_event(
            "warning",
            "虚拟网卡",
            "上次关闭前为虚拟网卡（TUN）模式，但当前非管理员权限，已自动降级为系统代理开启；如需恢复虚拟网卡请点击「以管理员重启」",
        );
    } else {
        let mode_desc = match (plan.enable_sys_proxy, plan.enable_tun) {
            (true, true) => "系统代理 + 虚拟网卡（TUN）",
            (false, true) => "虚拟网卡（TUN）",
            _ => "系统代理",
        };
        state.log_app_event("info", "核心", &format!("已通过总开关一键开启代理（{mode_desc}）"));
    }

    let final_cfg = state.snapshot_config();
    sync_tray_and_window_side_effects(app, state, &final_cfg);
    emit_config_updated(app, &final_cfg);
    let mut dto = build_runtime_info_dto(state)?;
    if plan.degraded_from_tun_due_to_privilege {
        dto.power_on_tun_degraded = true;
    }
    Ok(dto)
}


#[tauri::command]
pub async fn disable_all_proxy_and_stop_core(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CoreRuntimeInfoDto, String> {
    disable_all_proxy_and_stop_core_internal(&app, &state).await
}


#[tauri::command]
pub async fn enable_proxy_power(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CoreRuntimeInfoDto, String> {
    enable_proxy_power_internal(&app, &state).await
}


#[tauri::command]
pub fn consume_pending_nav(state: State<'_, AppState>) -> Result<Option<String>, String> {
    Ok(state.take_pending_nav())
}


/// Restart managed core cleanly. Caller MUST already hold outer `state.config_transition_lock`.
/// Internally acquires inner `state.core_lifecycle_lock` to preserve strict lock ordering.
async fn restart_core_locked(
    app: &AppHandle,
    state: &AppState,
) -> Result<CoreRuntimeInfoDto, String> {
    let _lifecycle_guard = state.core_lifecycle_lock.lock().await;
    stop_core_for_restart_locked(state).await?;
    match start_core_locked(app, state).await {
        Ok(dto) => Ok(dto),
        Err(err) => {
            // If restart fails, flip in-memory flags first, then clear owned OS proxy & save
            // so ProxyGuard cannot race back to `ProxyEnable=1` and host internet is never blackholed.
            let mut cfg = state.clone_config();
            let was_sys_proxy_enabled = cfg.system_proxy.enabled;
            let clear_tun = effective_tun_enabled(state, &cfg);
            let flags_changed = cfg.system_proxy.enabled || clear_tun;
            if flags_changed {
                cfg.system_proxy.enabled = false;
                if clear_tun {
                    cfg.tun.enabled = false;
                }
                if let Ok(mut guard) = state.config.write() {
                    *guard = Arc::new(cfg.clone());
                }
            }
            let _ = clear_system_proxy_if_owned_with_hint(state, was_sys_proxy_enabled);
            if flags_changed {
                let _ = config::save(&state.paths, &cfg);
            }
            sync_tray_and_window_side_effects(app, state, &cfg);
            state.log_app_event(
                "error",
                "核心",
                &format!("重启代理核心失败，已自动回滚代理开关：{err}"),
            );
            Err(err)
        }
    }
}


#[tauri::command]
pub async fn restart_core(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CoreRuntimeInfoDto, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    restart_core_locked(&app, &state).await
}


#[tauri::command]
pub async fn reload_core_config(
    app: AppHandle,
    state: State<'_, AppState>,
    force_disk_reload: Option<bool>,
) -> Result<ReloadOutcome, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    let force = force_disk_reload.unwrap_or(true);
    let mut disk_cfg = config::load_or_init(&state.paths).map_err(|e| e.to_string())?;
    disk_cfg.preaccel.reconcile_unified_enabled();
    if let Ok(mut guard) = state.config.write() {
        *guard = Arc::new(disk_cfg.clone());
    }
    if let Some(mut outcome) = trigger_reload_if_running(&app, &state, force).await {
        if outcome.rejected {
            if let Some(err) = outcome.error.take() {
                outcome.error = Some(format_mihomo_error_for_user(&err));
            }
        }
        return Ok(outcome);
    }
    // Core is stopped: still validate & compile candidate YAML so agents get real pre-flight feedback.
    let mut outcome = {
        let _lifecycle_guard = state.core_lifecycle_lock.lock().await;
        state
            .hot_reload
            .apply_disk_reload(DiskReloadOptions {
                force,
                verify_with_binary: true,
                allow_l3_restart: false,
                allow_tun: is_tun_privilege_ready(&state),
                ..DiskReloadOptions::default()
            })
            .await
    };
    if outcome.rejected {
        if let Some(err) = outcome.error.take() {
            let formatted = format_mihomo_error_for_user(&err);
            state.log_app_event("warning", "热重载", &format!("离线配置预检未通过：{formatted}"));
            outcome.error = Some(formatted);
        }
    }
    sync_tray_and_window_side_effects(&app, &state, &disk_cfg);
    Ok(outcome)
}


#[tauri::command]
pub async fn set_proxy_mode(
    app: AppHandle,
    state: State<'_, AppState>,
    mode: ProxyMode,
) -> Result<ProxyMode, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    let prev_cfg = state.snapshot_config();
    let prev_mode = prev_cfg.proxy_mode.clone();
    let mut cfg = (*prev_cfg).clone();
    cfg.proxy_mode = mode.clone();
    config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
    if let Ok(mut guard) = state.config.write() {
        *guard = Arc::new(cfg);
    }
    if let Some(outcome) = trigger_reload_if_running(&app, &state, false).await {
        if outcome.rejected {
            let mut rollback_cfg = state.clone_config();
            rollback_cfg.proxy_mode = prev_mode;
            let _ = config::save(&state.paths, &rollback_cfg);
            if let Ok(mut guard) = state.config.write() {
                *guard = Arc::new(rollback_cfg.clone());
            }
            sync_tray_and_window_side_effects(&app, &state, &rollback_cfg);
            let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&rollback_cfg));
            let detail = outcome
                .error
                .as_deref()
                .map(format_mihomo_error_for_user)
                .unwrap_or_else(|| "未知原因".to_string());
            return Err(format!("切换代理模式为 {} 失败：{detail}", mode.as_str()));
        }
    }
    let next_gen = state.bump_config_generation();
    if prev_mode == ProxyMode::Global
        && mode == ProxyMode::Rule
        && (state.snapshot_runtime().running || state.adapter.has_live_controller().await)
    {
        schedule_global_to_rule_heap_reclaim(&app, next_gen);
    }
    state.log_app_event(
        "info",
        "模式",
        &format!("代理模式已切换为 {}", mode.as_str()),
    );
    let latest_cfg = state.snapshot_config();
    sync_tray_and_window_side_effects(&app, &state, &latest_cfg);
    let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&latest_cfg));
    Ok(mode)
}


#[tauri::command]
pub async fn set_system_proxy(
    app: AppHandle,
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<bool, String> {
    apply_system_proxy_internal(&app, &state, enabled).await
}


/// Enable or disable TUN virtual NIC mode safely:
/// - Enabling checks administrator elevation first (`NEEDS_ADMIN:...` without dirty writes),
///   auto-starts or L3-reloads the core, and rolls back `config.json` on any failure.
/// - Disabling calls `disable_tun_gracefully()` before saving; if system proxy is also disabled,
///   stops the main core directly with zero port/memory/connection residue instead of reloading.
pub async fn set_tun_enabled_internal(
    app: &AppHandle,
    state: &AppState,
    enabled: bool,
) -> Result<bool, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    let old_cfg = state.snapshot_config();
    let old_tun_enabled = old_cfg.tun.enabled;
    let was_core_running =
        state.snapshot_runtime().running || state.adapter.has_live_controller().await;
    let was_tun_active = was_core_running && effective_tun_enabled(state, &old_cfg);

    if enabled {
        if !is_tun_privilege_ready(state) {
            state.log_app_event(
                "warning",
                "虚拟网卡",
                if cfg!(target_os = "linux") {
                    "尝试开启虚拟网卡（TUN）但 Mihomo 内核尚未授予 cap_net_admin 权限，需执行 setcap 授权"
                } else if cfg!(target_os = "macos") {
                    "尝试开启虚拟网卡（TUN）但当前非管理员权限，请通过管理员终端启动应用或完成系统授权后再启用"
                } else {
                    "尝试开启虚拟网卡（TUN）但当前非管理员权限，需提权重启"
                },
            );
            return Err(tun_needs_admin_error_message());
        }

        if !has_enabled_nodes(state)? {
            return Err("暂无可用节点，请先导入订阅".to_string());
        }

        let mut cfg = (*old_cfg).clone();
        cfg.tun.enabled = true;
        config::save(&state.paths, &cfg).map_err(|e| format!("保存虚拟网卡配置失败：{e}"))?;
        if let Ok(mut guard) = state.config.write() {
            *guard = Arc::new(cfg.clone());
        }

        if !state.adapter.has_live_controller().await {
            if let Err(err) = start_core_internal(app, state).await {
                let mut rollback = state.clone_config();
                rollback.tun.enabled = old_tun_enabled;
                let _ = config::save(&state.paths, &rollback);
                if let Ok(mut guard) = state.config.write() {
                    *guard = Arc::new(rollback.clone());
                }
                state.log_app_event(
                    "error",
                    "虚拟网卡",
                    &format!("开启虚拟网卡并启动核心失败，已回滚：{err}"),
                );
                sync_tray_and_window_side_effects(app, state, &rollback);
                return Err(format!("开启虚拟网卡并启动代理核心失败：{err}"));
            }
        } else {
            let reload_res = trigger_reload_if_running(app, state, true).await;
            let failed_detail = match reload_res {
                Some(outcome) if outcome.rejected => Some(
                    outcome
                        .error
                        .as_deref()
                        .map(format_mihomo_error_for_user)
                        .unwrap_or_else(|| "虚拟网卡配置重载未通过，已保持原状态".to_string()),
                ),
                None => Some("代理核心未响应，无法启用虚拟网卡".to_string()),
                _ => {
                    if !state.adapter.has_live_controller().await {
                        Some("核心重启以启用虚拟网卡后意外退出，请检查权限或 Wintun 组件".to_string())
                    } else {
                        None
                    }
                }
            };
            if let Some(detail) = failed_detail {
                let mut rollback = state.clone_config();
                rollback.tun.enabled = old_tun_enabled;
                let _ = config::save(&state.paths, &rollback);
                if let Ok(mut guard) = state.config.write() {
                    *guard = Arc::new(rollback.clone());
                }
                state.log_app_event(
                    "error",
                    "虚拟网卡",
                    &format!("开启虚拟网卡失败，已回滚配置：{detail}"),
                );
                sync_tray_and_window_side_effects(app, state, &rollback);
                return Err(detail);
            }
        }

        let latest_cfg = state.snapshot_config();
        let now_core_running =
            state.snapshot_runtime().running || state.adapter.has_live_controller().await;
        let now_tun_active = now_core_running && effective_tun_enabled(state, &latest_cfg);
        coordinate_global_preaccel_on_tun_transition(
            app,
            state,
            &latest_cfg,
            was_tun_active,
            now_tun_active,
            "虚拟网卡（TUN）",
        )
        .await;

        state.clear_power_off_takeover_memory();
        state.log_app_event(
            "info",
            "虚拟网卡",
            &format!(
                "已开启虚拟网卡（TUN 协议栈：{}）",
                latest_cfg.tun.stack_mode.as_str()
            ),
        );
        let latest_cfg = state.snapshot_config();
        sync_tray_and_window_side_effects(app, state, &latest_cfg);
        let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&latest_cfg));
        return Ok(true);
    }

    // Explicit manual TUN disable clears any pending power-off TUN recovery memory.
    state.clear_power_off_takeover_memory();

    // Disabling TUN: gracefully release Wintun adapter & OS routes first (only if actually active), then save.
    if was_tun_active && state.adapter.has_live_controller().await {
        let _ = state.adapter.disable_tun_gracefully().await;
    }

    let mut cfg = state.clone_config();
    cfg.tun.enabled = false;
    config::save(&state.paths, &cfg).map_err(|e| format!("保存虚拟网卡配置失败：{e}"))?;
    if let Ok(mut guard) = state.config.write() {
        *guard = Arc::new(cfg);
    }

    // Re-read latest config before deciding whether to stop the main core.
    let latest_before_stop = state.snapshot_config();
    if !latest_before_stop.system_proxy.enabled && !latest_before_stop.tun.enabled {
        let now_core_running =
            state.snapshot_runtime().running || state.adapter.has_live_controller().await;
        if now_core_running {
            stop_core_internal(app, state).await?;
            state.log_app_event(
                "info",
                "虚拟网卡",
                "已关闭虚拟网卡（TUN）并停止主代理核心（已释放监听端口与内存）",
            );
            return Ok(false);
        }
        coordinate_global_preaccel_on_tun_transition(
            app,
            state,
            &latest_before_stop,
            was_tun_active,
            false,
            "虚拟网卡（TUN）",
        )
        .await;
        state.log_app_event("info", "虚拟网卡", "已关闭虚拟网卡（TUN）");
        let latest_cfg = state.snapshot_config();
        sync_tray_and_window_side_effects(app, state, &latest_cfg);
        let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&latest_cfg));
        return Ok(false);
    }

    if was_tun_active {
        if let Some(outcome) = trigger_reload_if_running(app, state, true).await {
            if outcome.rejected {
                let detail = outcome
                    .error
                    .as_deref()
                    .map(format_mihomo_error_for_user)
                    .unwrap_or_else(|| "关闭虚拟网卡时重载核心失败".to_string());
                state.log_app_event("error", "虚拟网卡", &format!("关闭虚拟网卡重载失败：{detail}"));
                return Err(detail);
            }
        }
    }

    let latest_cfg = state.snapshot_config();
    let now_core_running =
        state.snapshot_runtime().running || state.adapter.has_live_controller().await;
    let now_tun_active = now_core_running && effective_tun_enabled(state, &latest_cfg);
    coordinate_global_preaccel_on_tun_transition(
        app,
        state,
        &latest_cfg,
        was_tun_active,
        now_tun_active,
        "虚拟网卡（TUN）",
    )
    .await;

    state.log_app_event("info", "虚拟网卡", "已关闭虚拟网卡（TUN）");
    let latest_cfg = state.snapshot_config();
    sync_tray_and_window_side_effects(app, state, &latest_cfg);
    let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&latest_cfg));
    Ok(false)
}


#[tauri::command]
pub async fn set_tun_enabled(
    app: AppHandle,
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<bool, String> {
    set_tun_enabled_internal(&app, &state, enabled).await
}


#[tauri::command]
pub async fn relaunch_as_admin(
    app: AppHandle,
    state: State<'_, AppState>,
    enable_tun: Option<bool>,
) -> Result<bool, String> {
    let want_tun = enable_tun.unwrap_or(true);

    #[cfg(target_os = "linux")]
    {
        // On Linux, grant minimal `cap_net_admin,cap_net_bind_service` strictly to the Mihomo
        // binary via `pkexec setcap` instead of running the entire GUI process as root.
        let cfg = state.snapshot_config();
        let extra = state.extra_binary_candidates();
        let resolution = resolve_mihomo_binary(&cfg, &state.paths, &extra, false)
            .map_err(|e| format!("查找代理核心失败：{e}"))?;
        let binary_path = resolution.path.ok_or_else(|| {
            "未找到 Mihomo 代理核心文件，请先将内核放入 bin 目录或在设置中指定路径".to_string()
        })?;
        let bin_for_cap = binary_path.clone();
        let granted = tokio::task::spawn_blocking(move || {
            catcloud_core::platform::linux::grant_mihomo_tun_capability(&bin_for_cap)
        })
        .await
        .map_err(|e| format!("Linux TUN 授权任务异常中止：{e}"))?
        .map_err(|e| format!("为代理核心授予 Linux TUN 网络权限失败：{e}"))?;

        if !granted {
            state.log_app_event("warning", "提权", "用户取消了 Linux TUN 核心网络权限授权");
            return Ok(false);
        }

        state.log_app_event(
            "info",
            "提权",
            &format!(
                "已为代理核心授予 Linux TUN 网络权限（{}），桌面界面保持普通用户运行",
                binary_path.display()
            ),
        );

        if want_tun && has_enabled_nodes(&state).unwrap_or(false) {
            if let Err(err) = set_tun_enabled_internal(&app, &state, true).await {
                state.log_app_event(
                    "warning",
                    "虚拟网卡",
                    &format!("Linux 核心已获授权，但自动开启虚拟网卡失败：{err}"),
                );
                let latest_cfg = state.snapshot_config();
                sync_tray_and_window_side_effects(&app, &state, &latest_cfg);
                let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&latest_cfg));
                return Err(err);
            }
        }

        let latest_cfg = state.snapshot_config();
        sync_tray_and_window_side_effects(&app, &state, &latest_cfg);
        let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&latest_cfg));
        Ok(true)
    }

    #[cfg(target_os = "macos")]
    {
        let _ = (&app, &state, want_tun);
        Err(
            "macOS 暂不支持一键弹窗提权重启，请通过管理员终端启动猫猫云梯或在完成后续系统授权后启用虚拟网卡（TUN）"
                .to_string(),
        )
    }

    #[cfg(target_os = "windows")]
    {
        relaunch_self_with_elevation_flags(&app, &state, want_tun, false).await
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = (&app, &state, want_tun);
        Err("当前系统暂不支持一键管理员提权重启，请以具备网络管理权限的账户启动应用".to_string())
    }
}


#[tauri::command]
pub fn launch_uwp_loopback() -> Result<serde_json::Value, String> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let output = std::process::Command::new("CheckNetIsolation.exe")
            .args(["LoopbackExempt", "-s"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&output.stdout).to_string();
        let exempt_count = text.lines().filter(|l| l.contains("Name:")).count();
        Ok(serde_json::json!({
            "supported": true,
            "launched": output.status.success(),
            "exempt_count": exempt_count,
            "message": format!("已检查 Windows 应用本地回环放行状态（当前已放行 {exempt_count} 项）")
        }))
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(serde_json::json!({
            "supported": false,
            "launched": false,
            "message": "应用本地回环放行仅支持 Windows 系统"
        }))
    }
}


#[tauri::command]
pub async fn hot_swap_core(
    app: AppHandle,
    state: State<'_, AppState>,
    binary_path: String,
) -> Result<serde_json::Value, String> {
    let trimmed = binary_path.trim();
    let candidate = PathBuf::from(trimmed);
    if !candidate.is_file() {
        return Err(format!("所选内核文件不存在：{trimmed}"));
    }
    let sha256 = compute_file_sha256(&candidate).map_err(|e| e.to_string())?;
    let _cfg_guard = state.config_transition_lock.lock().await;
    let mut cfg = state.clone_config();
    cfg.core_runtime.custom_binary_path = Some(candidate.display().to_string());
    config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
    if let Ok(mut guard) = state.config.write() {
        *guard = Arc::new(cfg);
    }
    let version = if state.adapter.has_live_controller().await {
        let rt = restart_core_locked(&app, &state).await?;
        rt.core_version
    } else {
        "已配置".to_string()
    };
    Ok(serde_json::json!({
        "ok": true,
        "version": version,
        "sha256": sha256,
        "binary_path": candidate.display().to_string(),
        "message": "代理核心文件已更新"
    }))
}

