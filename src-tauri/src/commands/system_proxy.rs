use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use catcloud_core::core_adapter::CoreAdapter;
use catcloud_core::core_adapter::CoreRuntimeStatus;
use catcloud_core::models::AppConfig;
use catcloud_core::models::PreAccelRelay;
use catcloud_core::platform::SystemProxySpec;
use catcloud_core::platform::default_platform;
use catcloud_core::preaccel::global_tunnel::GlobalPreAccelStatus;
#[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
use catcloud_core::preaccel::global_tunnel::build_default_windivert_proxy_candidates;
#[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
use catcloud_core::preaccel::global_tunnel::download_and_install_windivert_with_fallbacks;
#[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
use catcloud_core::preaccel::global_tunnel::locate_windivert_files;
#[cfg(target_os = "windows")]
use catcloud_core::process_guard::relaunch_self_as_admin;
use tauri::AppHandle;
#[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
use tauri::Emitter;
#[cfg(target_os = "windows")]
use tauri::Manager;
#[cfg(target_os = "windows")]
use crate::lifecycle;

use crate::commands::state::AppState;
#[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
use crate::commands::state::AtomicFlagResetGuard;
#[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
use crate::commands::state::EVENT_CONFIG_UPDATED;
#[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
use crate::commands::state::UiAppConfigDto;
#[cfg(target_os = "windows")]
use crate::commands::tray_runtime::config_may_have_tun;
#[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
use crate::commands::tray_runtime::effective_tun_enabled;
#[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
use crate::commands::tray_runtime::sync_tray_and_window_side_effects;

fn is_loopback_host(host: &str) -> bool {
    let trimmed = host.trim();
    trimmed == "127.0.0.1"
        || trimmed.eq_ignore_ascii_case("localhost")
        || trimmed == "::1"
        || trimmed == "[::1]"
}


/// Determine whether the OS system proxy registry currently points to CatCloud's own loopback
/// listener (or CatCloud's own local PAC URL), preventing accidental removal of corporate PACs
/// or third-party capture proxies (Fiddler/Charles) when CatCloud's system proxy was never enabled.
pub(in crate::commands) fn is_system_proxy_owned_by_us(
    cfg: &AppConfig,
    rt: &CoreRuntimeStatus,
    observed: &SystemProxySpec,
) -> bool {
    if !observed.enabled {
        return false;
    }
    // If this instance neither has system proxy enabled nor has a live running core listener,
    // never guess ownership by default port (CoreRuntimeStatus::default() carries mixed_port=7890
    // with running=false, which must never clear a concurrent host portable CatCloud proxy).
    if !cfg.system_proxy.enabled && (!rt.running || rt.mixed_port == 0) {
        return false;
    }
    if let Some(pac) = observed
        .pac_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let expected_pac = format!("http://127.0.0.1:{}/proxy.pac", cfg.system_proxy.pac.port);
        return cfg.system_proxy.pac.enabled && pac.eq_ignore_ascii_case(&expected_pac);
    }
    if !is_loopback_host(&observed.host) {
        return false;
    }
    observed.port == cfg.mixed_port || (rt.mixed_port > 0 && observed.port == rt.mixed_port)
}


fn disable_system_proxy_os_only(cfg: &AppConfig) -> Result<(), String> {
    let mut disabled = cfg.system_proxy.clone();
    disabled.enabled = false;
    disabled.pac.enabled = false;
    let spec = disabled.to_platform_spec("127.0.0.1", cfg.mixed_port);
    default_platform()
        .apply_system_proxy(&spec)
        .map_err(|e| format!("清除系统代理失败：{e}"))
}


/// Clear OS system proxy under `state.system_proxy_lock` ONLY when CatCloud owns it
/// (`previously_enabled || cfg.system_proxy.enabled`, or current OS `ProxyServer` points to
/// `127.0.0.1:<runtime_or_config_port>` / our local PAC).
///
/// When `lock_wait_budget` is `Some(dur)` (shutdown / `WM_ENDSESSION` path), uses non-blocking
/// `try_lock` with bounded polling so a stalled background thread can never block teardown or skip
/// `JobGuard::terminate_all()`.
fn clear_system_proxy_if_owned_with_hint_bounded(
    state: &AppState,
    previously_enabled: bool,
    lock_wait_budget: Option<Duration>,
) -> Result<bool, String> {
    let _proxy_guard = match lock_wait_budget {
        None => state
            .system_proxy_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner()),
        Some(budget) => {
            let deadline = Instant::now() + budget;
            loop {
                match state.system_proxy_lock.try_lock() {
                    Ok(guard) => break guard,
                    Err(std::sync::TryLockError::Poisoned(err)) => break err.into_inner(),
                    Err(std::sync::TryLockError::WouldBlock) => {
                        if Instant::now() >= deadline {
                            return Err(
                                "退出时等待系统代理锁超时，已跳过代理清理以保障有界关机"
                                    .to_string(),
                            );
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
            }
        }
    };
    let cfg = state.snapshot_config();
    let rt = state.snapshot_runtime();
    let owned = previously_enabled || cfg.system_proxy.enabled || {
        match default_platform().read_system_proxy() {
            Ok(observed) => is_system_proxy_owned_by_us(&cfg, &rt, &observed),
            Err(err) => {
                tracing::debug!("读取当前系统代理状态失败，跳过猜测性清理：{err}");
                false
            }
        }
    };
    if !owned {
        return Ok(false);
    }
    disable_system_proxy_os_only(&cfg)?;
    Ok(true)
}


pub(in crate::commands) fn clear_system_proxy_if_owned_with_hint(
    state: &AppState,
    previously_enabled: bool,
) -> Result<bool, String> {
    clear_system_proxy_if_owned_with_hint_bounded(state, previously_enabled, None)
}


/// Clear OS system proxy under `state.system_proxy_lock` if owned by CatCloud.
pub fn clear_system_proxy_if_owned(state: &AppState) -> Result<bool, String> {
    clear_system_proxy_if_owned_with_hint_bounded(state, false, None)
}


/// Bounded-wait variant of `clear_system_proxy_if_owned` used during shutdown / `WM_ENDSESSION`.
pub fn clear_system_proxy_if_owned_bounded(
    state: &AppState,
    lock_wait_budget: Duration,
) -> Result<bool, String> {
    clear_system_proxy_if_owned_with_hint_bounded(state, false, Some(lock_wait_budget))
}


/// Apply OS system proxy (`ProxyEnable=1`) under `state.system_proxy_lock`, re-checking
/// `!shutting_down && state.snapshot_config().system_proxy.enabled` inside the lock so a racing
/// shutdown or `stop_core` can never be overwritten back to `ProxyEnable=1`.
pub(in crate::commands) fn apply_system_proxy_if_still_enabled(state: &AppState, port: u16) -> Result<bool, String> {
    let _proxy_guard = state
        .system_proxy_lock
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if state.shutting_down.load(Ordering::SeqCst) {
        return Ok(false);
    }
    let latest_cfg = state.snapshot_config();
    if !latest_cfg.system_proxy.enabled {
        return Ok(false);
    }
    let spec = latest_cfg.system_proxy.to_platform_spec("127.0.0.1", port);
    default_platform()
        .apply_system_proxy(&spec)
        .map_err(|e| format!("应用系统代理设置失败：{e}"))?;
    Ok(true)
}


/// Best-effort bounded stop of the `WinDivert` kernel driver service via Windows SCM when
/// `emergency_cleanup_on_exit` runs during a 4s dataplane self-test window and `stop()` times out.
///
/// Intentionally NEVER calls `DeleteService` to prevent Win32 `1072` races on rapid relaunch.
#[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
fn emergency_stop_windivert_service_fallback_bounded(max_wait: Duration) -> bool {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QueryServiceStatus,
        SC_HANDLE, SC_MANAGER_CONNECT, SERVICE_CONTROL_STOP, SERVICE_QUERY_STATUS, SERVICE_STATUS,
        SERVICE_STOP, SERVICE_STOPPED,
    };

    struct ScopedScHandle(SC_HANDLE);
    impl Drop for ScopedScHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: Valid SCM or Service handle owned exclusively by this guard.
                unsafe {
                    let _ = CloseServiceHandle(self.0);
                }
                self.0 = std::ptr::null_mut();
            }
        }
    }

    // SAFETY: Read-only connect to local SCM; deterministically closed by `ScopedScHandle`.
    let scm_raw =
        unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if scm_raw.is_null() {
        return false;
    }
    let scm = ScopedScHandle(scm_raw);

    let service_wide: Vec<u16> = "WinDivert"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `scm.0` is valid and `service_wide` is NUL-terminated UTF-16.
    let svc_raw = unsafe {
        OpenServiceW(
            scm.0,
            service_wide.as_ptr(),
            SERVICE_STOP | SERVICE_QUERY_STATUS,
        )
    };
    if svc_raw.is_null() {
        return false;
    }
    let svc = ScopedScHandle(svc_raw);

    let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
    if unsafe { QueryServiceStatus(svc.0, &mut status) } != 0
        && status.dwCurrentState == SERVICE_STOPPED
    {
        return true;
    }

    const ERROR_SERVICE_CANNOT_ACCEPT_CTRL: u32 = 1061;
    const ERROR_SERVICE_NOT_ACTIVE: u32 = 1062;

    let ctrl_ok = unsafe { ControlService(svc.0, SERVICE_CONTROL_STOP, &mut status) };
    if ctrl_ok == 0 {
        let err = unsafe { GetLastError() };
        if err == ERROR_SERVICE_NOT_ACTIVE {
            return true;
        }
        if err != ERROR_SERVICE_CANNOT_ACCEPT_CTRL {
            return false;
        }
    } else if status.dwCurrentState == SERVICE_STOPPED {
        return true;
    }

    let deadline = Instant::now() + max_wait.min(Duration::from_millis(500));
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
        let mut cur: SERVICE_STATUS = unsafe { std::mem::zeroed() };
        if unsafe { QueryServiceStatus(svc.0, &mut cur) } == 0 {
            return false;
        }
        if cur.dwCurrentState == SERVICE_STOPPED {
            return true;
        }
    }
    false
}


/// Deterministic, idempotent exit safety hook invoked before `JobGuard::terminate_all()` on `RunEvent::Exit`.
pub fn emergency_cleanup_on_exit(state: &AppState) {
    emergency_cleanup_on_exit_bounded(state, Duration::from_millis(5300));
}


/// Bounded-deadline variant of `emergency_cleanup_on_exit` (e.g. `<= 3000ms` for synchronous
/// Windows `WM_ENDSESSION` cleanup before `tao` calls `std::process::exit(0)`).
///
/// 1. Atomically guards against duplicate execution via `exit_cleanup_done`.
/// 2. Stops background `ProxyGuard` ticks and cancels any in-flight update download immediately.
/// 3. Gracefully stops domestic global acceleration whenever enabled, running, or mid-probing,
///    with a bounded Windows SCM fallback stopping the `WinDivert` service if needed.
/// 4. Idempotently calls `disable_tun_gracefully()` on any live Mihomo controller, and ALWAYS
///    stops the live Mihomo core within the shared deadline budget via a hard-bounded helper thread.
/// 5. Always clears Windows WinINet system proxy under bounded `system_proxy_lock` acquisition
///    (only if owned by CatCloud) WITHOUT mutating `config.json` remembered preferences.
pub fn emergency_cleanup_on_exit_bounded(state: &AppState, max_budget: Duration) {
    if state.exit_cleanup_done.swap(true, Ordering::SeqCst) {
        return;
    }
    state.shutting_down.store(true, Ordering::SeqCst);
    state.cancel_in_flight_update_download();
    state.stop_streams();
    state.lan_sync.shutdown_all();

    let overall_deadline = Instant::now() + max_budget.max(Duration::from_millis(600));
    // Reserve tail budget for `clear_system_proxy_if_owned_bounded` + metadata removal + caller's JobGuard.
    let proxy_reserve = if max_budget <= Duration::from_millis(3000) {
        Duration::from_millis(450)
    } else {
        Duration::from_millis(300)
    };
    let teardown_budget = max_budget
        .saturating_sub(proxy_reserve)
        .max(Duration::from_millis(400));
    let tight_budget = max_budget <= Duration::from_millis(3000);
    let step_global_cap = if tight_budget {
        Duration::from_millis(900)
    } else {
        Duration::from_millis(2000)
    };
    let step_tun_cap = if tight_budget {
        Duration::from_millis(800)
    } else {
        Duration::from_millis(1500)
    };
    let step_stop_cap = if tight_budget {
        Duration::from_millis(900)
    } else {
        Duration::from_millis(1500)
    };

    let cfg = state.snapshot_config();
    let global_status = state.global_preaccel.status();
    let may_have_global_preaccel = cfg.preaccel.enabled
        || global_status.running
        || global_status.verify_state == "probing";

    {
        let adapter = Arc::clone(&state.adapter);
        let global_preaccel = Arc::clone(&state.global_preaccel);
        let global_stop_succeeded = Arc::new(AtomicBool::new(false));
        let global_stop_ok_flag = Arc::clone(&global_stop_succeeded);
        let run_teardown = move || {
            let teardown_deadline = Instant::now() + teardown_budget;
            tauri::async_runtime::block_on(async move {
                let _ = tokio::time::timeout(teardown_budget, async move {
                    if may_have_global_preaccel {
                        let rem = teardown_deadline.saturating_duration_since(Instant::now());
                        if !rem.is_zero() {
                            let step = rem.min(step_global_cap);
                            match tokio::time::timeout(step, global_preaccel.stop()).await {
                                Ok(Ok(_)) => {
                                    global_stop_ok_flag.store(true, Ordering::SeqCst);
                                }
                                Ok(Err(err)) => {
                                    tracing::warn!(
                                        "退出时停止国内提速失败，准备触发 WinDivert 兜底清理：{err}"
                                    );
                                }
                                Err(_) => {
                                    tracing::warn!(
                                        "退出时等待国内提速停止超时（{}ms，可能处于自检窗口），准备触发 WinDivert 兜底清理",
                                        step.as_millis()
                                    );
                                }
                            }
                        }
                    }
                    let core_alive = adapter.has_live_controller().await;
                    if core_alive {
                        // Always call `disable_tun_gracefully()` idempotently on any live controller
                        // so TUN adapters and routes are never left behind even under overrides.
                        let rem = teardown_deadline.saturating_duration_since(Instant::now());
                        if !rem.is_zero() {
                            let _ = tokio::time::timeout(rem.min(step_tun_cap), async {
                                let _ = adapter.disable_tun_gracefully().await;
                            })
                            .await;
                        }
                        let rem = teardown_deadline.saturating_duration_since(Instant::now());
                        if !rem.is_zero() {
                            let _ = tokio::time::timeout(rem.min(step_stop_cap), async {
                                let _ = adapter.stop().await;
                            })
                            .await;
                        }
                    }
                })
                .await;
            });
        };

        // Always offload async teardown onto a dedicated thread with a hard channel timeout on
        // BOTH the main UI thread (`WM_ENDSESSION`) and Tokio worker threads so a stalled runtime
        // or blocked call can never overrun the shutdown budget.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            run_teardown();
            let _ = tx.send(());
        });
        let teardown_timed_out = rx
            .recv_timeout(teardown_budget + Duration::from_millis(50))
            .is_err();
        if teardown_timed_out {
            tracing::warn!(
                budget_ms = teardown_budget.as_millis(),
                "退出有界清理超过预算上限，已强硬截断并继续执行代理清理与子进程终止"
            );
        }

        // Only trigger Windows SCM `ControlService` fallback when domestic preaccel might be active
        // AND `global_preaccel.stop()` did NOT confirm success (avoiding wasted 500ms SCM calls
        // when `global_preaccel.stop()` already succeeded before `adapter.stop()` timed out).
        let need_fallback =
            may_have_global_preaccel && !global_stop_succeeded.load(Ordering::SeqCst);
        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        if need_fallback {
            let rem_for_scm = overall_deadline
                .saturating_duration_since(Instant::now())
                .saturating_sub(Duration::from_millis(150));
            if !rem_for_scm.is_zero() {
                let stopped = emergency_stop_windivert_service_fallback_bounded(rem_for_scm);
                if stopped {
                    tracing::info!("退出兜底：已通过 Windows SCM 安全停止 WinDivert 内核服务");
                } else {
                    tracing::warn!(
                        "退出兜底：尝试通过 Windows SCM 停止 WinDivert 内核服务未确认完成（可能未加载或无权限）"
                    );
                }
            }
        }
        #[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
        let _ = need_fallback;
    }

    let proxy_lock_wait = overall_deadline
        .saturating_duration_since(Instant::now())
        .min(if tight_budget {
            Duration::from_millis(100)
        } else {
            Duration::from_millis(200)
        });
    if let Err(err) = clear_system_proxy_if_owned_bounded(state, proxy_lock_wait) {
        tracing::warn!("退出时清除系统代理失败：{err}");
    }
    catcloud_core::core_adapter::remove_runtime_controller_meta(&state.paths.runtime_dir);
}


/// Coordinate standalone global pre-acceleration whenever TUN virtual NIC takeover transitions
/// between inactive and active:
/// - `false -> true`: suspend a running standalone 443 tunnel because TUN already routes host
///   traffic through the main core's in-core 443 pre-acceleration (avoiding two 443 tunnels).
/// - `true -> false`: seamlessly resume the standalone global pre-acceleration engine when the
///   unified `cfg.preaccel.enabled` switch is true and enabled relays exist.
/// When only OS system proxy is active (without TUN), standalone WinDivert excludes CatCloud's
/// full PID tree and stays active to accelerate third-party apps simultaneously.
pub(in crate::commands) async fn coordinate_global_preaccel_on_tun_transition(
    app: &AppHandle,
    state: &AppState,
    cfg: &AppConfig,
    was_tun_active: bool,
    now_tun_active: bool,
    trigger_label: &str,
) {
    if state.shutting_down.load(Ordering::SeqCst) {
        return;
    }
    if !was_tun_active && now_tun_active {
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
                        &format!(
                            "{trigger_label}已生效接管全机流量，已暂挂独立底层 443 隧道以避免双跑 443，改由主核心统一提供国内提速"
                        ),
                    );
                }
            }
        } else if state.global_preaccel.status().running
            || state.global_preaccel.status().mode == "suspended_for_tun"
        {
            let _ = state.global_preaccel.stop().await;
        }
    } else if !now_tun_active && cfg.preaccel.enabled {
        let has_relays = load_enabled_preaccel_relays(state).is_ok_and(|relays| !relays.is_empty());
        if has_relays && !state.global_preaccel.status().running {
            match start_global_preaccel_engine(state, cfg).await {
                Ok(global_st) => {
                    if was_tun_active {
                        state.log_app_event(
                            "info",
                            "国内提速",
                            &format!(
                                "{trigger_label}已关闭，已自动恢复独立底层国内提速（模式：{}）",
                                global_st.mode
                            ),
                        );
                    }
                }
                Err(err) => {
                    state.log_app_event(
                        "warning",
                        "国内提速",
                        &format!("{trigger_label}切换后自动恢复独立底层国内提速失败：{err}"),
                    );
                }
            }
        }
        if has_relays {
            maybe_spawn_auto_windivert_download(app, state, cfg);
        }
    }
}


#[cfg(any(target_os = "windows", test))]
pub(in crate::commands) fn collect_relaunch_admin_args_with_flags(
    raw_args: &[std::ffi::OsString],
    fallback_data_dir: Option<&std::path::Path>,
    enable_tun: bool,
    enable_global_preaccel: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut has_data_dir = false;
    let mut i = 0usize;
    while i < raw_args.len() {
        let arg = raw_args[i].to_string_lossy();
        if arg == "--data-dir" {
            if let Some(val) = raw_args.get(i + 1) {
                let val_str = val.to_string_lossy().into_owned();
                if !val_str.trim().is_empty() {
                    out.push("--data-dir".to_string());
                    out.push(val_str);
                    has_data_dir = true;
                }
                i += 2;
                continue;
            }
        } else if let Some(rest) = arg.strip_prefix("--data-dir=") {
            if !rest.trim().is_empty() {
                out.push(arg.into_owned());
                has_data_dir = true;
            }
        }
        i += 1;
    }
    if !has_data_dir {
        if let Some(dir) = fallback_data_dir {
            let rendered = dir.to_string_lossy().into_owned();
            if !rendered.trim().is_empty() {
                out.push("--data-dir".to_string());
                out.push(rendered);
            }
        }
    }
    out.push("--restarting".to_string());
    if enable_tun {
        out.push("--enable-tun".to_string());
    }
    if enable_global_preaccel {
        out.push("--enable-global-preaccel".to_string());
    }
    out
}


#[cfg(test)]
pub(in crate::commands) fn collect_relaunch_admin_args(
    raw_args: &[std::ffi::OsString],
    fallback_data_dir: Option<&std::path::Path>,
    enable_tun: bool,
) -> Vec<String> {
    collect_relaunch_admin_args_with_flags(raw_args, fallback_data_dir, enable_tun, false)
}


#[cfg(target_os = "windows")]
pub(in crate::commands) async fn relaunch_self_with_elevation_flags(
    app: &AppHandle,
    state: &AppState,
    enable_tun: bool,
    enable_global_preaccel: bool,
) -> Result<bool, String> {
    let exe = std::env::current_exe().map_err(|e| format!("无法获取当前程序路径：{e}"))?;
    let workdir = exe
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| state.paths.root_data_dir.clone());
    let raw_args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let args = collect_relaunch_admin_args_with_flags(
        &raw_args,
        Some(&state.paths.root_data_dir),
        enable_tun,
        enable_global_preaccel,
    );

    let exe_clone = exe.clone();
    let workdir_clone = workdir.clone();
    let launched = tokio::task::spawn_blocking(move || {
        relaunch_self_as_admin(&exe_clone, &args, &workdir_clone)
    })
    .await
    .map_err(|e| format!("提权重启后台任务异常中止：{e}"))?
    .map_err(|e| format!("以管理员身份重启失败：{e}"))?;

    if !launched {
        // User cancelled the UAC elevation prompt: keep current process running untouched.
        state.log_app_event("warning", "提权", "用户取消了管理员权限提权重启");
        return Ok(false);
    }

    state.log_app_event(
        "info",
        "提权",
        "已以管理员身份拉起新实例，当前进程准备优雅退出并交接",
    );

    // Elevated replacement instance spawned successfully: release TUN, owned proxy, WebView
    // window handles, and single-instance lock before exiting cleanly.
    let app_exit = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Some(st) = app_exit.try_state::<AppState>() {
            st.shutting_down.store(true, Ordering::SeqCst);
            st.stop_streams();
            if st.global_preaccel.status().running {
                let _ = tokio::time::timeout(
                    Duration::from_millis(1200),
                    st.global_preaccel.stop(),
                )
                .await;
            }
            let cfg = st.snapshot_config();
            let may_have_tun = config_may_have_tun(&st, &cfg);
            if may_have_tun && st.adapter.has_live_controller().await {
                let _ = tokio::time::timeout(
                    Duration::from_millis(1200),
                    st.adapter.disable_tun_gracefully(),
                )
                .await;
            }
            let _ = clear_system_proxy_if_owned(&st);
        }
        lifecycle::enter_pure_windowless_mode(&app_exit);
        tokio::time::sleep(Duration::from_millis(250)).await;
        lifecycle::request_graceful_exit(&app_exit);
    });

    Ok(true)
}


pub(in crate::commands) fn collect_excluded_pids_for_global_preaccel(state: &AppState) -> Vec<u32> {
    let mut pids = Vec::with_capacity(2);
    let rt = state.snapshot_runtime();
    if rt.running {
        if let Some(pid) = rt.pid.filter(|&p| p > 0) {
            pids.push(pid);
        }
    }
    pids
}


pub(in crate::commands) fn load_enabled_preaccel_relays(state: &AppState) -> Result<Vec<PreAccelRelay>, String> {
    let db = state.storage.lock().map_err(|e| e.to_string())?;
    db.list_preaccel_relays(true).map_err(|e| e.to_string())
}


pub(in crate::commands) fn log_global_preaccel_verify_status(
    state: &AppState,
    stage_label: &str,
    status: &GlobalPreAccelStatus,
) {
    let iface = status
        .bound_physical_interface
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("未绑定/自动路由");
    let security = if status.detected_security_products.is_empty() {
        "未检出拦截类安全软件".to_string()
    } else {
        status.detected_security_products.join(" / ")
    };
    let perm = if status.is_elevated {
        "管理员"
    } else {
        "普通用户"
    };
    let detail_reason = status
        .verify_message
        .as_deref()
        .or(status.last_error.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("无附加说明");

    match status.verify_state.as_str() {
        "verified" => {
            let latency_text = status
                .verify_latency_ms
                .map(|ms| format!("{ms} ms"))
                .unwrap_or_else(|| "--".to_string());
            state.log_app_event(
                "info",
                "国内提速",
                &format!(
                    "{stage_label}：底层透明加速自动探测通过（模式：{}，物理网卡：{iface}，探测耗时：{latency_text}，安全环境：{security}，权限：{perm}）— {detail_reason}",
                    status.mode
                ),
            );
        }
        "degraded" => {
            state.log_app_event(
                "warning",
                "国内提速",
                &format!(
                    "{stage_label}：底层透明加速自动探测触发保护熔断，已安全退回本地独立 443 通道（模式：{}，物理网卡：{iface}，安全环境：{security}，权限：{perm}）— {detail_reason}",
                    status.mode
                ),
            );
        }
        "failed" => {
            state.log_app_event(
                "warning",
                "国内提速",
                &format!(
                    "{stage_label}：底层透明加速组件加载或探测失败（模式：{}，物理网卡：{iface}，安全环境：{security}，权限：{perm}）— {detail_reason}",
                    status.mode
                ),
            );
        }
        "probing" => {
            state.log_app_event(
                "info",
                "国内提速",
                &format!(
                    "{stage_label}：底层透明加速链路正在探测中（模式：{}，物理网卡：{iface}，安全环境：{security}）",
                    status.mode
                ),
            );
        }
        other => {
            let state_desc = if !status.running {
                "独立底层引擎未运行"
            } else if status.is_windivert_active {
                "底层透明加速运行中（待探测）"
            } else {
                "运行于本地独立 443 通道（未进入底层透明拦截）"
            };
            state.log_app_event(
                "info",
                "国内提速",
                &format!(
                    "{stage_label}：{state_desc}（模式：{}，探测状态：{other}，物理网卡：{iface}，安全环境：{security}，权限：{perm}）— {detail_reason}",
                    status.mode
                ),
            );
        }
    }
}


pub(in crate::commands) async fn start_global_preaccel_engine(
    state: &AppState,
    cfg: &AppConfig,
) -> Result<GlobalPreAccelStatus, String> {
    let relays = load_enabled_preaccel_relays(state)?;
    if relays.is_empty() {
        return Err("尚未配置已启用的国内 443 中转线路，请先添加并启用至少一条中转".to_string());
    }
    let excluded_pids = collect_excluded_pids_for_global_preaccel(state);
    state
        .global_preaccel
        .sync_main_core_pid(excluded_pids.first().copied());
    let status = state
        .global_preaccel
        .start(cfg, &relays, &excluded_pids)
        .await
        .map_err(|e| e.to_string())?;
    log_global_preaccel_verify_status(state, "启动底层提速引擎", &status);
    Ok(status)
}


pub(in crate::commands) async fn sync_running_global_preaccel_if_active(state: &AppState, cfg: &AppConfig) {
    if !state.global_preaccel.status().running {
        return;
    }
    match load_enabled_preaccel_relays(state) {
        Ok(relays) if !relays.is_empty() => {
            let excluded_pids = collect_excluded_pids_for_global_preaccel(state);
            match state
                .global_preaccel
                .restart_windivert_if_running(cfg, &relays, &excluded_pids)
                .await
            {
                Ok(st) => {
                    log_global_preaccel_verify_status(state, "中转变更热重建底层 443 隧道", &st);
                }
                Err(err) => {
                    state.log_app_event(
                        "warning",
                        "国内提速",
                        &format!("中转配置变更后热重建独立底层 443 隧道失败：{err}"),
                    );
                }
            }
        }
        _ => {
            let _ = state.global_preaccel.stop().await;
            state.log_app_event(
                "info",
                "国内提速",
                "已无可用的国内中转线路，独立底层 443 隧道已自动停止",
            );
        }
    }
}


/// Spawn an asynchronous background WinDivert v2.2.2 auto-download (3-tier proxy fallback:
/// CatCloud main core -> active Windows system proxy -> direct) and in-place hot-upgrade whenever
/// running on non-ARM64 Windows without installed driver files.
pub(in crate::commands) fn maybe_spawn_auto_windivert_download(app: &AppHandle, state: &AppState, cfg: &AppConfig) {
    #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
    {
        if state.shutting_down.load(Ordering::SeqCst) {
            return;
        }
        if locate_windivert_files(&state.paths, cfg.preaccel.windivert_dir.as_deref()).is_some() {
            return;
        }
        if state
            .windivert_installing
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }

        state.global_preaccel.set_install_state("downloading");
        sync_tray_and_window_side_effects(app, state, cfg);

        let app_h = app.clone();
        let install_flag = Arc::clone(&state.windivert_installing);
        tauri::async_runtime::spawn(async move {
            let _flag_guard = AtomicFlagResetGuard(install_flag);
            let Some(st) = app_h.try_state::<AppState>() else {
                return;
            };
            if st.shutting_down.load(Ordering::SeqCst) {
                return;
            }

            let rt = st.snapshot_runtime();
            let active_mixed_port = if rt.running && rt.mixed_port > 0 {
                Some(rt.mixed_port)
            } else {
                None
            };
            let proxy_candidates = build_default_windivert_proxy_candidates(active_mixed_port);

            match download_and_install_windivert_with_fallbacks(&st.paths, &proxy_candidates).await
            {
                Ok(installed_dir) => {
                    st.global_preaccel.set_install_state("verifying");
                    let latest_cfg = st.snapshot_config();
                    sync_tray_and_window_side_effects(&app_h, &st, &latest_cfg);
                    st.log_app_event(
                        "info",
                        "国内提速",
                        &format!(
                            "已自动下载并通过 SHA-256 校验安装官方 WinDivert v2.2.2 驱动至 {}",
                            installed_dir.display()
                        ),
                    );

                    if default_platform().capabilities().is_elevated {
                        // Acquire outer `config_transition_lock` before checking latest config/TUN
                        // and upgrading/starting WinDivert so TUN and WinDivert can never race open.
                        let _cfg_guard = st.config_transition_lock.lock().await;
                        let latest_cfg = st.snapshot_config();
                        let latest_rt = st.snapshot_runtime();
                        let tun_active = (latest_rt.running
                            || st.adapter.has_live_controller().await)
                            && effective_tun_enabled(&st, &latest_cfg);
                        if !st.shutting_down.load(Ordering::SeqCst)
                            && latest_cfg.preaccel.enabled
                            && !tun_active
                        {
                            let cur_global = st.snapshot_global_preaccel();
                            if cur_global.running && !cur_global.is_windivert_active {
                                match load_enabled_preaccel_relays(&st) {
                                    Ok(relays) if !relays.is_empty() => {
                                        let excluded_pids =
                                            collect_excluded_pids_for_global_preaccel(&st);
                                        match st
                                            .global_preaccel
                                            .upgrade_to_windivert_in_place(
                                                &latest_cfg,
                                                &relays,
                                                &excluded_pids,
                                            )
                                            .await
                                        {
                                            Ok(upgraded) if upgraded.is_windivert_active => {
                                                log_global_preaccel_verify_status(
                                                    &st,
                                                    "WinDivert 自动安装后原地热升格",
                                                    &upgraded,
                                                );
                                            }
                                            Ok(upgraded) => {
                                                if upgraded.install_state == "verifying" {
                                                    st.global_preaccel.set_install_state(
                                                        if upgraded.windivert_available {
                                                            "ready"
                                                        } else {
                                                            "idle"
                                                        },
                                                    );
                                                }
                                                let final_upgraded = st.snapshot_global_preaccel();
                                                log_global_preaccel_verify_status(
                                                    &st,
                                                    "WinDivert 自动安装后热升格探测",
                                                    &final_upgraded,
                                                );
                                            }
                                            Err(err) => {
                                                if st.snapshot_global_preaccel().install_state
                                                    == "verifying"
                                                {
                                                    st.global_preaccel.set_install_state("failed");
                                                }
                                                let failed_st = st.snapshot_global_preaccel();
                                                log_global_preaccel_verify_status(
                                                    &st,
                                                    "WinDivert 自动安装后原地热升格失败",
                                                    &failed_st,
                                                );
                                                st.log_app_event(
                                                    "warning",
                                                    "国内提速",
                                                    &format!(
                                                        "WinDivert 驱动就绪后自动热升格失败：{err}"
                                                    ),
                                                );
                                            }
                                        }
                                    }
                                    _ => {
                                        st.global_preaccel.set_install_state("ready");
                                    }
                                }
                            } else if !cur_global.running {
                                if load_enabled_preaccel_relays(&st)
                                    .is_ok_and(|relays| !relays.is_empty())
                                {
                                    match start_global_preaccel_engine(&st, &latest_cfg).await {
                                        Ok(_) => {
                                            if st.snapshot_global_preaccel().install_state
                                                == "verifying"
                                            {
                                                st.global_preaccel.set_install_state("ready");
                                            }
                                        }
                                        Err(err) => {
                                            st.global_preaccel.set_install_state("ready");
                                            st.log_app_event(
                                                "warning",
                                                "国内提速",
                                                &format!(
                                                    "WinDivert 驱动就绪后自动拉起底层透明提速失败：{err}"
                                                ),
                                            );
                                        }
                                    }
                                } else {
                                    st.global_preaccel.set_install_state("ready");
                                }
                            } else {
                                st.global_preaccel.set_install_state("ready");
                            }
                        } else {
                            st.global_preaccel.set_install_state("ready");
                        }
                        drop(_cfg_guard);
                    } else {
                        st.global_preaccel.set_install_state("need_elevation");
                        st.log_app_event(
                            "info",
                            "国内提速",
                            "官方 WinDivert 驱动已自动安装就绪，当前非管理员权限，点击「以管理员重启生效」即可自动加速其它软件",
                        );
                    }
                }
                Err(err) => {
                    st.global_preaccel.set_install_state("failed");
                    st.log_app_event(
                        "warning",
                        "国内提速",
                        &format!("后台自动下载官方 WinDivert 驱动失败（本地 443 通道仍待命）：{err}"),
                    );
                }
            }

            let final_cfg = st.snapshot_config();
            sync_tray_and_window_side_effects(&app_h, &st, &final_cfg);
            let _ = app_h.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&final_cfg));
        });
    }
    #[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
    {
        let _ = (app, state, cfg);
    }
}

