use std::path::{Component, Path};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use catcloud_core::AppPaths;
use serde::{Deserialize, Serialize};
use tauri::utils::config::{AppDirectoriesOverride, AppDirectoryOverrides};
use tauri::{AppHandle, Emitter, Manager, RunEvent, Runtime, WebviewWindowBuilder, WindowEvent};

/// Label of the primary application window defined in `tauri.conf.json`.
pub const MAIN_WINDOW_LABEL: &str = "main";
/// Label of the lightweight floating capsule window defined in `tauri.conf.json`.
pub const CAPSULE_WINDOW_LABEL: &str = "capsule";
/// Event emitted whenever main/capsule window presence transitions.
pub const EVENT_WINDOW_MODE_CHANGED: &str = "catcloud://window-mode-changed";
/// Lightweight Chromium/WebView2 arguments injected only when the user has not set
/// `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS`, trimming resident disk/media caches and unused
/// browser features without degrading rendering quality or interactivity.
pub const DEFAULT_WEBVIEW2_BROWSER_ARGS: &str = "--disk-cache-size=10485760 --media-cache-size=1048576 --disable-features=msWebOOUI,msPdfOOUI,Translate,BackForwardCache";

/// Minimum cooldown between destroying a WebView2 window and rebuilding it, preventing
/// Windows `EBWebView` UserData directory lock contention during rapid toggle loops.
const REBUILD_COOLDOWN_MS: u64 = 220;
/// Maximum wait budget when a rebuild collides with an in-flight destroy.
const MAX_DESTROY_WAIT_MS: u64 = 650;
const DESTROY_POLL_INTERVAL_MS: u64 = 25;
/// Minimum interval between consecutive OS working-set trims to coalesce bursty minimize/hide events.
const WORKING_SET_TRIM_COOLDOWN_MS: u64 = 1500;

static REBUILDING_MAIN: AtomicBool = AtomicBool::new(false);
static DESTROYING_MAIN: AtomicBool = AtomicBool::new(false);
static LAST_MAIN_DESTROY_MS: AtomicU64 = AtomicU64::new(0);

static TOGGLING_CAPSULE: AtomicBool = AtomicBool::new(false);
static DESTROYING_CAPSULE: AtomicBool = AtomicBool::new(false);
static LAST_CAPSULE_DESTROY_MS: AtomicU64 = AtomicU64::new(0);
static LAST_WORKING_SET_TRIM_MS: AtomicU64 = AtomicU64::new(0);

static START_INSTANT: OnceLock<Instant> = OnceLock::new();

fn monotonic_now_ms() -> u64 {
    let origin = START_INSTANT.get_or_init(Instant::now);
    origin.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

/// RAII guard that releases an `AtomicBool` lock even on early return or panic.
struct AtomicFlagGuard(&'static AtomicBool);

impl AtomicFlagGuard {
    fn try_acquire(flag: &'static AtomicBool) -> Option<Self> {
        flag.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .ok()
            .map(|_| Self(flag))
    }
}

impl Drop for AtomicFlagGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Runtime toggle for window close behavior, intended for `app.manage(WindowLifecycleState::default())`.
#[derive(Debug)]
pub struct WindowLifecycleState {
    destroy_on_close: AtomicBool,
}

impl Default for WindowLifecycleState {
    fn default() -> Self {
        Self::new(true)
    }
}

impl WindowLifecycleState {
    pub fn new(destroy_on_close: bool) -> Self {
        Self {
            destroy_on_close: AtomicBool::new(destroy_on_close),
        }
    }

    pub fn destroy_on_close(&self) -> bool {
        self.destroy_on_close.load(Ordering::Relaxed)
    }

    pub fn set_destroy_on_close(&self, enabled: bool) {
        self.destroy_on_close.store(enabled, Ordering::Relaxed);
    }
}

/// Snapshot of currently alive GUI windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowModeSnapshot {
    pub main_open: bool,
    pub capsule_open: bool,
    pub windowless: bool,
}

/// Construct Tauri 2.10+ `AppDirectoryOverrides` pointing strictly to subdirectories
/// under `paths.root_data_dir` (never exposing `./` or the executable's sibling root).
pub fn build_portable_directory_overrides(paths: &AppPaths) -> AppDirectoryOverrides {
    let base = &paths.root_data_dir;
    AppDirectoryOverrides {
        config: Some(paths.config_dir.clone()),
        data: Some(base.join("app_data")),
        local_data: Some(base.join("local")),
        cache: Some(base.join("cache")),
        log: Some(paths.logs_dir.clone()),
    }
}

fn is_safe_override_root(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    let mut has_normal = false;
    for comp in path.components() {
        match comp {
            Component::CurDir | Component::ParentDir => return false,
            Component::Normal(_) => has_normal = true,
            Component::Prefix(_) | Component::RootDir => {}
        }
    }
    has_normal
}

/// Apply Tauri `AppDirectoriesOverride::Directories` onto a mutable `tauri::Context`
/// whenever `paths.is_portable` is true.
///
/// Guarantees all overridden paths reside in dedicated subdirectories under
/// `paths.root_data_dir` and creates them proactively.
pub fn apply_portable_overrides<R: Runtime>(context: &mut tauri::Context<R>, paths: &AppPaths) {
    if !paths.is_portable {
        return;
    }
    apply_directory_overrides_always(context, paths);
}

/// Unconditionally apply directory overrides under `paths.root_data_dir` (useful for
/// isolated sandboxes or tests where all Tauri app directories should be co-located).
pub fn apply_directory_overrides_always<R: Runtime>(
    context: &mut tauri::Context<R>,
    paths: &AppPaths,
) {
    if !is_safe_override_root(&paths.root_data_dir) {
        tracing::warn!(
            root = %paths.root_data_dir.display(),
            "refusing to apply AppDirectoriesOverride for non-absolute or relative root path"
        );
        return;
    }

    let overrides = build_portable_directory_overrides(paths);
    for dir in [
        overrides.config.as_ref(),
        overrides.data.as_ref(),
        overrides.local_data.as_ref(),
        overrides.cache.as_ref(),
        overrides.log.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        if let Err(err) = std::fs::create_dir_all(dir) {
            tracing::warn!(path = %dir.display(), "failed to pre-create override dir: {err}");
        }
    }

    context.config_mut().app.app_directories_override =
        Some(AppDirectoriesOverride::Directories(overrides));
}

/// Resolve default lightweight WebView2 browser arguments unless the caller already provided
/// a non-empty custom `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS` override.
pub fn resolve_webview2_browser_args(existing: Option<&str>) -> Option<&'static str> {
    if existing.is_some_and(|v| !v.trim().is_empty()) {
        None
    } else {
        Some(DEFAULT_WEBVIEW2_BROWSER_ARGS)
    }
}

/// Helper for single-threaded bootstrap paths to set `WEBVIEW2_USER_DATA_FOLDER` and lightweight
/// WebView2 browser arguments before Tauri initializes. Elevated processes always receive an
/// isolated `webview2_elevated` directory so High IL and Medium IL WebView2 instances never
/// contend on `EBWebView` locks or ACLs.
///
/// # Safety
/// Must only be invoked while the process is single-threaded prior to spawning threads.
pub unsafe fn set_webview2_user_data_env(paths: &AppPaths) {
    let is_elevated = catcloud_core::platform::default_platform()
        .capabilities()
        .is_elevated;
    let webview_dir = paths.effective_webview_dir(is_elevated);
    let _ = std::fs::create_dir_all(&webview_dir);
    if is_elevated || paths.is_portable || std::env::var_os("WEBVIEW2_USER_DATA_FOLDER").is_none() {
        unsafe {
            std::env::set_var("WEBVIEW2_USER_DATA_FOLDER", &webview_dir);
        }
    }
    let existing_args = std::env::var("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS").ok();
    if let Some(default_args) = resolve_webview2_browser_args(existing_args.as_deref()) {
        unsafe {
            std::env::set_var("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", default_args);
        }
    }
}

/// Ask Windows to reclaim idle working-set pages for the current process so background/tray
/// residency returns unused RAM to the OS immediately.
#[cfg(target_os = "windows")]
pub fn trim_process_working_set() -> bool {
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, SetProcessWorkingSetSize};
    let ok = unsafe { SetProcessWorkingSetSize(GetCurrentProcess(), usize::MAX, usize::MAX) };
    ok != 0
}

#[cfg(not(target_os = "windows"))]
pub fn trim_process_working_set() -> bool {
    false
}

fn trim_process_working_set_throttled() {
    let now = monotonic_now_ms();
    let prev = LAST_WORKING_SET_TRIM_MS.load(Ordering::Relaxed);
    if prev != 0 && now.saturating_sub(prev) < WORKING_SET_TRIM_COOLDOWN_MS {
        return;
    }
    if LAST_WORKING_SET_TRIM_MS
        .compare_exchange(prev, now, Ordering::SeqCst, Ordering::Relaxed)
        .is_ok()
    {
        let _ = trim_process_working_set();
    }
}

/// Query current live window state, excluding windows that are actively being destroyed.
pub fn window_mode_snapshot<R: Runtime>(app: &AppHandle<R>) -> WindowModeSnapshot {
    let main_open = !DESTROYING_MAIN.load(Ordering::SeqCst)
        && app.get_webview_window(MAIN_WINDOW_LABEL).is_some();
    let capsule_open = !DESTROYING_CAPSULE.load(Ordering::SeqCst)
        && app.get_webview_window(CAPSULE_WINDOW_LABEL).is_some();
    WindowModeSnapshot {
        main_open,
        capsule_open,
        windowless: !main_open && !capsule_open,
    }
}

/// Returns `true` when the main window exists, is visible, and is not minimized.
pub fn is_main_window_visible<R: Runtime>(app: &AppHandle<R>) -> bool {
    if DESTROYING_MAIN.load(Ordering::SeqCst) {
        return false;
    }
    app.get_webview_window(MAIN_WINDOW_LABEL).is_some_and(|win| {
        win.is_visible().unwrap_or(false) && !win.is_minimized().unwrap_or(false)
    })
}

/// Returns `true` when the floating capsule window exists and is visible.
pub fn is_capsule_window_visible<R: Runtime>(app: &AppHandle<R>) -> bool {
    if DESTROYING_CAPSULE.load(Ordering::SeqCst) {
        return false;
    }
    app.get_webview_window(CAPSULE_WINDOW_LABEL)
        .is_some_and(|win| {
            win.is_visible().unwrap_or(false) && !win.is_minimized().unwrap_or(false)
        })
}

/// Returns `true` when at least one GUI window (main or capsule) is currently visible and not minimized.
pub fn has_visible_gui_window<R: Runtime>(app: &AppHandle<R>) -> bool {
    is_main_window_visible(app) || is_capsule_window_visible(app)
}

/// Returns `true` when neither main nor capsule WebView window exists (pure windowless mode).
pub fn is_windowless_mode<R: Runtime>(app: &AppHandle<R>) -> bool {
    window_mode_snapshot(app).windowless
}

fn emit_window_mode_changed<R: Runtime>(app: &AppHandle<R>) {
    let snapshot = window_mode_snapshot(app);
    let _ = app.emit(EVENT_WINDOW_MODE_CHANGED, snapshot);
}

#[cfg(target_os = "macos")]
fn sync_macos_activation_policy<R: Runtime>(app: &AppHandle<R>) {
    let snapshot = window_mode_snapshot(app);
    let policy = if snapshot.main_open {
        tauri::ActivationPolicy::Regular
    } else {
        tauri::ActivationPolicy::Accessory
    };
    let _ = app.set_activation_policy(policy);
}

#[cfg(not(target_os = "macos"))]
fn sync_macos_activation_policy<R: Runtime>(_app: &AppHandle<R>) {}

async fn wait_for_destroy_settle<R: Runtime>(
    app: &AppHandle<R>,
    label: &str,
    destroying_flag: &AtomicBool,
    last_destroy_ms: &AtomicU64,
) {
    let deadline = Instant::now() + Duration::from_millis(MAX_DESTROY_WAIT_MS);
    loop {
        let in_flight = destroying_flag.load(Ordering::SeqCst);
        let still_registered = app.get_webview_window(label).is_some();
        let last = last_destroy_ms.load(Ordering::SeqCst);
        let elapsed_since_destroy = if last == 0 {
            REBUILD_COOLDOWN_MS
        } else {
            monotonic_now_ms().saturating_sub(last)
        };

        if !in_flight && !still_registered && elapsed_since_destroy >= REBUILD_COOLDOWN_MS {
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(DESTROY_POLL_INTERVAL_MS)).await;
    }
}

/// Show and focus the main window, or rebuild it asynchronously from `tauri.conf.json`
/// after it was destroyed in windowless low-memory mode.
pub fn show_or_rebuild_main_window<R: Runtime>(app: &AppHandle<R>) {
    let app_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        if !DESTROYING_MAIN.load(Ordering::SeqCst) {
            if let Some(win) = app_handle.get_webview_window(MAIN_WINDOW_LABEL) {
                let _ = win.unminimize();
                let _ = win.show();
                let _ = win.set_focus();
                sync_macos_activation_policy(&app_handle);
                return;
            }
        }

        let Some(_rebuild_guard) = AtomicFlagGuard::try_acquire(&REBUILDING_MAIN) else {
            tracing::debug!("main window rebuild already in progress; debouncing duplicate trigger");
            return;
        };

        wait_for_destroy_settle(
            &app_handle,
            MAIN_WINDOW_LABEL,
            &DESTROYING_MAIN,
            &LAST_MAIN_DESTROY_MS,
        )
        .await;

        // Re-check after settling in case another caller restored the window.
        if let Some(win) = app_handle.get_webview_window(MAIN_WINDOW_LABEL) {
            let _ = win.unminimize();
            let _ = win.show();
            let _ = win.set_focus();
            sync_macos_activation_policy(&app_handle);
            return;
        }

        let Some(cfg) = app_handle
            .config()
            .app
            .windows
            .iter()
            .find(|w| w.label == MAIN_WINDOW_LABEL)
            .cloned()
        else {
            tracing::error!("window config `{MAIN_WINDOW_LABEL}` missing in tauri.conf.json");
            return;
        };

        #[cfg(target_os = "macos")]
        let _ = app_handle.set_activation_policy(tauri::ActivationPolicy::Regular);

        match WebviewWindowBuilder::from_config(&app_handle, &cfg).and_then(|b| b.build()) {
            Ok(win) => {
                let _ = win.show();
                let _ = win.set_focus();
                emit_window_mode_changed(&app_handle);
            }
            Err(err) => {
                tracing::error!("failed to rebuild main window: {err}");
                sync_macos_activation_policy(&app_handle);
            }
        }
    });
}

fn schedule_destroy_flag_clear<R: Runtime>(
    app: &AppHandle<R>,
    label: &'static str,
    flag: &'static AtomicBool,
) {
    let app_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let deadline = Instant::now() + Duration::from_millis(MAX_DESTROY_WAIT_MS);
        while app_handle.get_webview_window(label).is_some() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(DESTROY_POLL_INTERVAL_MS)).await;
        }
        flag.store(false, Ordering::SeqCst);
        sync_macos_activation_policy(&app_handle);
        emit_window_mode_changed(&app_handle);
        if is_windowless_mode(&app_handle) || label == MAIN_WINDOW_LABEL {
            trim_process_working_set_throttled();
        }
    });
}

/// Destroy the main WebView window completely so Windows releases `msedgewebview2.exe`
/// memory immediately. If the floating capsule is closed, the app enters pure windowless mode.
pub fn enter_windowless_mode<R: Runtime>(app: &AppHandle<R>) {
    if let Some(win) = app.get_webview_window(MAIN_WINDOW_LABEL) {
        DESTROYING_MAIN.store(true, Ordering::SeqCst);
        LAST_MAIN_DESTROY_MS.store(monotonic_now_ms(), Ordering::SeqCst);
        if let Err(err) = win.destroy() {
            tracing::warn!("failed to destroy main window cleanly: {err}");
            DESTROYING_MAIN.store(false, Ordering::SeqCst);
        } else {
            schedule_destroy_flag_clear(app, MAIN_WINDOW_LABEL, &DESTROYING_MAIN);
        }
    }
    sync_macos_activation_policy(app);
    emit_window_mode_changed(app);
    trim_process_working_set_throttled();
}

/// Destroy both main and capsule WebView windows to reach the minimal pure windowless footprint.
pub fn enter_pure_windowless_mode<R: Runtime>(app: &AppHandle<R>) {
    destroy_capsule_window(app);
    enter_windowless_mode(app);
}

/// Destroy the floating capsule window if open so its WebView2 process exits immediately.
pub fn destroy_capsule_window<R: Runtime>(app: &AppHandle<R>) {
    if let Some(win) = app.get_webview_window(CAPSULE_WINDOW_LABEL) {
        DESTROYING_CAPSULE.store(true, Ordering::SeqCst);
        LAST_CAPSULE_DESTROY_MS.store(monotonic_now_ms(), Ordering::SeqCst);
        if let Err(err) = win.destroy() {
            tracing::warn!("failed to destroy capsule window cleanly: {err}");
            DESTROYING_CAPSULE.store(false, Ordering::SeqCst);
        } else {
            schedule_destroy_flag_clear(app, CAPSULE_WINDOW_LABEL, &DESTROYING_CAPSULE);
        }
    }
    sync_macos_activation_policy(app);
    emit_window_mode_changed(app);
}

/// Ensure the floating capsule window is created and visible.
pub fn show_capsule_window<R: Runtime>(app: &AppHandle<R>) {
    let app_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        if !DESTROYING_CAPSULE.load(Ordering::SeqCst) {
            if let Some(win) = app_handle.get_webview_window(CAPSULE_WINDOW_LABEL) {
                let _ = win.show();
                let _ = win.set_focus();
                return;
            }
        }

        let Some(_toggle_guard) = AtomicFlagGuard::try_acquire(&TOGGLING_CAPSULE) else {
            return;
        };

        wait_for_destroy_settle(
            &app_handle,
            CAPSULE_WINDOW_LABEL,
            &DESTROYING_CAPSULE,
            &LAST_CAPSULE_DESTROY_MS,
        )
        .await;

        if let Some(win) = app_handle.get_webview_window(CAPSULE_WINDOW_LABEL) {
            let _ = win.show();
            return;
        }

        let Some(cfg) = app_handle
            .config()
            .app
            .windows
            .iter()
            .find(|w| w.label == CAPSULE_WINDOW_LABEL)
            .cloned()
        else {
            tracing::error!("window config `{CAPSULE_WINDOW_LABEL}` missing in tauri.conf.json");
            return;
        };

        match WebviewWindowBuilder::from_config(&app_handle, &cfg).and_then(|b| b.build()) {
            Ok(win) => {
                let _ = win.show();
                emit_window_mode_changed(&app_handle);
            }
            Err(err) => {
                tracing::error!("failed to build capsule window: {err}");
            }
        }
    });
}

/// Toggle the floating capsule window: destroys it completely when open, or builds it on demand.
pub fn toggle_capsule_window<R: Runtime>(app: &AppHandle<R>) {
    let app_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let Some(_toggle_guard) = AtomicFlagGuard::try_acquire(&TOGGLING_CAPSULE) else {
            tracing::debug!("capsule toggle already in progress; debouncing duplicate trigger");
            return;
        };

        if let Some(win) = app_handle.get_webview_window(CAPSULE_WINDOW_LABEL) {
            DESTROYING_CAPSULE.store(true, Ordering::SeqCst);
            LAST_CAPSULE_DESTROY_MS.store(monotonic_now_ms(), Ordering::SeqCst);
            if let Err(err) = win.destroy() {
                tracing::warn!("failed to destroy capsule window: {err}");
                DESTROYING_CAPSULE.store(false, Ordering::SeqCst);
            } else {
                schedule_destroy_flag_clear(&app_handle, CAPSULE_WINDOW_LABEL, &DESTROYING_CAPSULE);
            }
            sync_macos_activation_policy(&app_handle);
            emit_window_mode_changed(&app_handle);
            return;
        }

        wait_for_destroy_settle(
            &app_handle,
            CAPSULE_WINDOW_LABEL,
            &DESTROYING_CAPSULE,
            &LAST_CAPSULE_DESTROY_MS,
        )
        .await;

        let Some(cfg) = app_handle
            .config()
            .app
            .windows
            .iter()
            .find(|w| w.label == CAPSULE_WINDOW_LABEL)
            .cloned()
        else {
            tracing::error!("window config `{CAPSULE_WINDOW_LABEL}` missing in tauri.conf.json");
            return;
        };

        match WebviewWindowBuilder::from_config(&app_handle, &cfg).and_then(|b| b.build()) {
            Ok(win) => {
                let _ = win.show();
                emit_window_mode_changed(&app_handle);
            }
            Err(err) => {
                tracing::error!("failed to rebuild capsule window: {err}");
            }
        }
    });
}

/// Handle `Builder::on_window_event`: intercepts main/capsule `CloseRequested`, prevents default
/// close, and asynchronously destroys the WebView to free memory safely outside the event stack.
pub fn handle_window_event<R: Runtime>(
    window: &tauri::Window<R>,
    event: &WindowEvent,
    destroy_on_close: bool,
) {
    match event {
        WindowEvent::CloseRequested { api, .. } => match window.label() {
            MAIN_WINDOW_LABEL if destroy_on_close => {
                api.prevent_close();
                let app = window.app_handle().clone();
                tauri::async_runtime::spawn(async move {
                    enter_windowless_mode(&app);
                });
            }
            CAPSULE_WINDOW_LABEL => {
                api.prevent_close();
                let app = window.app_handle().clone();
                tauri::async_runtime::spawn(async move {
                    destroy_capsule_window(&app);
                });
            }
            _ => {}
        },
        WindowEvent::Resized(size) => {
            if window.label() == MAIN_WINDOW_LABEL
                && ((size.width == 0 && size.height == 0)
                    || window.is_minimized().unwrap_or(false))
            {
                trim_process_working_set_throttled();
            }
        }
        WindowEvent::Focused(false) => {
            if window.label() == MAIN_WINDOW_LABEL
                && (!window.is_visible().unwrap_or(true)
                    || window.is_minimized().unwrap_or(false))
            {
                trim_process_working_set_throttled();
            }
        }
        WindowEvent::Destroyed => match window.label() {
            MAIN_WINDOW_LABEL => {
                DESTROYING_MAIN.store(false, Ordering::SeqCst);
                let app = window.app_handle();
                sync_macos_activation_policy(app);
                emit_window_mode_changed(app);
                trim_process_working_set_throttled();
            }
            CAPSULE_WINDOW_LABEL => {
                DESTROYING_CAPSULE.store(false, Ordering::SeqCst);
                let app = window.app_handle();
                sync_macos_activation_policy(app);
                emit_window_mode_changed(app);
                if is_windowless_mode(app) {
                    trim_process_working_set_throttled();
                }
            }
            _ => {}
        },
        _ => {}
    }
}

/// Convenience wrapper for `Builder::on_window_event` that reads `WindowLifecycleState`
/// from managed Tauri state (defaulting to `destroy_on_close = true`).
pub fn handle_window_event_with_state<R: Runtime>(
    window: &tauri::Window<R>,
    event: &WindowEvent,
) {
    let destroy_on_close = window
        .app_handle()
        .try_state::<WindowLifecycleState>()
        .map(|s| s.destroy_on_close())
        .unwrap_or(true);
    handle_window_event(window, event, destroy_on_close);
}

/// Pure decision helper: only intercept implicit exit caused by all windows closing (`None`),
/// never block explicit `app.exit(code)` or `app.restart()` (`Some(_)`).
#[inline]
pub fn should_prevent_exit(code: Option<i32>) -> bool {
    code.is_none()
}

/// Decision helper combining exit code with the user's `destroy_on_close` (minimize-to-tray)
/// preference. Only intercepts implicit `None` exit when tray persistence is enabled.
#[inline]
pub fn should_prevent_exit_for_mode(code: Option<i32>, destroy_on_close: bool) -> bool {
    code.is_none() && destroy_on_close
}

/// Handle `App::run` events in an `FnMut`-compatible way.
///
/// - `RunEvent::ExitRequested { code, api, .. }`: reads `WindowLifecycleState::destroy_on_close()`
///   and calls `api.prevent_exit()` **only** when `code.is_none() && destroy_on_close`, so turning
///   off minimize-to-tray allows closing the last window to exit cleanly and trigger `RunEvent::Exit`.
/// - `RunEvent::Exit`: consumes `cleanup.take()` exactly once for deterministic teardown.
pub fn handle_run_event<R: Runtime, F: FnOnce()>(
    app: &AppHandle<R>,
    event: RunEvent,
    cleanup: &mut Option<F>,
) {
    match event {
        RunEvent::ExitRequested { code, api, .. } => {
            let destroy_on_close = app
                .try_state::<WindowLifecycleState>()
                .map(|s| s.destroy_on_close())
                .unwrap_or(true);
            if should_prevent_exit_for_mode(code, destroy_on_close) {
                api.prevent_exit();
            }
        }
        RunEvent::Exit => {
            crate::tray::cleanup_tray(app);
            crate::shortcuts::unregister_all_shortcuts(app);
            if let Some(cleanup_fn) = cleanup.take() {
                cleanup_fn();
            }
        }
        _ => {}
    }
}

/// Perform orderly UI/tray/shortcut teardown and trigger an explicit `app.exit(0)` that
/// bypasses windowless exit prevention and runs the `RunEvent::Exit` cleanup closure.
pub fn request_graceful_exit<R: Runtime>(app: &AppHandle<R>) {
    crate::tray::cleanup_tray(app);
    crate::shortcuts::unregister_all_shortcuts(app);
    app.exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_temp_paths(tag: &str, is_portable: bool) -> AppPaths {
        let dir = std::env::temp_dir().join(format!(
            "catcloud_lifecycle_test_{}_{}",
            tag,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        AppPaths::from_data_dir(dir, is_portable).expect("create temp AppPaths")
    }

    #[test]
    fn portable_overrides_stay_strictly_inside_root_data_dir() {
        let paths = make_temp_paths("overrides", true);
        let overrides = build_portable_directory_overrides(&paths);

        let all = [
            overrides.config.as_ref().expect("config override"),
            overrides.data.as_ref().expect("data override"),
            overrides.local_data.as_ref().expect("local_data override"),
            overrides.cache.as_ref().expect("cache override"),
            overrides.log.as_ref().expect("log override"),
        ];

        for path in all {
            assert!(path.is_absolute(), "path must be absolute: {path:?}");
            assert!(
                path.starts_with(&paths.root_data_dir),
                "path must stay under root_data_dir: {path:?}"
            );
            assert_ne!(
                path, &paths.root_data_dir,
                "override must point to a dedicated subdir, not root itself: {path:?}"
            );
            assert_ne!(path, &PathBuf::from("./"));
            assert_ne!(path, &PathBuf::from("."));
        }

        let _ = std::fs::remove_dir_all(&paths.root_data_dir);
    }

    #[test]
    fn reject_relative_override_roots() {
        assert!(!is_safe_override_root(Path::new(".")));
        assert!(!is_safe_override_root(Path::new("./")));
        assert!(!is_safe_override_root(Path::new("./data")));
        assert!(!is_safe_override_root(Path::new("data")));
        assert!(!is_safe_override_root(Path::new("/data/sub/../cache")));
    }

    #[test]
    fn exit_prevention_only_blocks_windowless_none_code() {
        assert!(should_prevent_exit(None));
        assert!(!should_prevent_exit(Some(0)));
        assert!(!should_prevent_exit(Some(1)));
        assert!(!should_prevent_exit(Some(tauri::RESTART_EXIT_CODE)));

        assert!(should_prevent_exit_for_mode(None, true));
        assert!(!should_prevent_exit_for_mode(None, false));
        assert!(!should_prevent_exit_for_mode(Some(0), true));
        assert!(!should_prevent_exit_for_mode(Some(0), false));
    }

    #[test]
    fn apply_portable_overrides_updates_tauri_context_only_when_portable() {
        let portable_paths = make_temp_paths("ctx_portable", true);
        let mut ctx: tauri::Context<tauri::Wry> = tauri::generate_context!();
        apply_portable_overrides(&mut ctx, &portable_paths);

        match ctx.config().app.app_directories_override.as_ref() {
            Some(AppDirectoriesOverride::Directories(dirs)) => {
                assert_eq!(dirs.config.as_ref(), Some(&portable_paths.config_dir));
                assert_eq!(dirs.log.as_ref(), Some(&portable_paths.logs_dir));
                assert_eq!(
                    dirs.data.as_ref(),
                    Some(&portable_paths.root_data_dir.join("app_data"))
                );
                assert_eq!(
                    dirs.local_data.as_ref(),
                    Some(&portable_paths.root_data_dir.join("local"))
                );
                assert_eq!(
                    dirs.cache.as_ref(),
                    Some(&portable_paths.root_data_dir.join("cache"))
                );
                assert!(portable_paths.root_data_dir.join("cache").is_dir());
            }
            other => panic!("expected Directories override, got {other:?}"),
        }

        let standard_paths = make_temp_paths("ctx_standard", false);
        let mut std_ctx: tauri::Context<tauri::Wry> = tauri::generate_context!();
        apply_portable_overrides(&mut std_ctx, &standard_paths);
        assert!(std_ctx.config().app.app_directories_override.is_none());

        let _ = std::fs::remove_dir_all(&portable_paths.root_data_dir);
        let _ = std::fs::remove_dir_all(&standard_paths.root_data_dir);
    }

    #[test]
    fn cleanup_option_executes_fn_once_exactly_once() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicUsize;

        let called = Arc::new(AtomicUsize::new(0));
        let called_clone = Arc::clone(&called);
        let owned_resource = String::from("one-shot-guard");
        let mut cleanup = Some(move || {
            let _consumed = owned_resource;
            called_clone.fetch_add(1, Ordering::SeqCst);
        });

        if let Some(f) = cleanup.take() {
            f();
        }
        if let Some(f) = cleanup.take() {
            f();
        }

        assert_eq!(called.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn atomic_flag_guard_releases_on_drop() {
        static TEST_FLAG: AtomicBool = AtomicBool::new(false);
        {
            let guard = AtomicFlagGuard::try_acquire(&TEST_FLAG);
            assert!(guard.is_some());
            assert!(AtomicFlagGuard::try_acquire(&TEST_FLAG).is_none());
        }
        assert!(!TEST_FLAG.load(Ordering::SeqCst));
        assert!(AtomicFlagGuard::try_acquire(&TEST_FLAG).is_some());
    }

    #[test]
    fn resolve_webview2_browser_args_injects_defaults_only_when_unset() {
        assert_eq!(
            resolve_webview2_browser_args(None),
            Some(DEFAULT_WEBVIEW2_BROWSER_ARGS)
        );
        assert_eq!(
            resolve_webview2_browser_args(Some("   ")),
            Some(DEFAULT_WEBVIEW2_BROWSER_ARGS)
        );
        assert_eq!(
            resolve_webview2_browser_args(Some("--remote-debugging-port=9222")),
            None
        );
    }

    #[test]
    fn trim_process_working_set_executes_safely() {
        let trimmed = trim_process_working_set();
        #[cfg(target_os = "windows")]
        assert!(trimmed);
        #[cfg(not(target_os = "windows"))]
        assert!(!trimmed);
    }
}
