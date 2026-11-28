//! Background telemetry event forwarders and OS ProxyGuard loop.
//!
//! Forwards Mihomo `/traffic`, `/memory`, `/connections`, and `/logs` streams to visible GUI
//! windows and throttled tray visuals, pauses `/connections` polling while hidden/windowless,
//! and runs the periodic cross-platform system-proxy drift guard.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(not(target_os = "windows"))]
use catcloud_core::platform::default_platform;
use tauri::{Emitter, Manager};

use crate::app_log;
use crate::commands::{self, AppState, TrafficEventPayload};
use crate::lifecycle;
use crate::tray;

pub(crate) fn spawn_proxy_guard(app: &tauri::AppHandle) {
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

pub(crate) fn spawn_telemetry_forwarders(app: &tauri::AppHandle, state: &AppState) {
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
