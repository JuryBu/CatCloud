use crate::error::{CatError, CatResult};
use crate::models::ProxyNode;
use crate::paths::normalize_os_path;
use crate::subscription::parser::{
    MAX_SUBSCRIPTION_BYTES, build_proxy_node, json_to_u16, node_from_clash_json,
    normalize_protocol, parse_subscription_payload,
};
use crate::subscription::process_attach::{
    normalize_loopback_controller_base_url, parse_controller_proxies_json, parse_process_cmdline,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System, UpdateKind};
use uuid::Uuid;

/// Unified user-facing hint returned whenever no plaintext nodes could be captured.
pub const CAPTURE_UNSUPPORTED_REASON: &str =
    "该软件暂不支持直接抓取，建议尝试其它支持的软件或前往官网查看是否提供标准订阅链接";

const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(450);
const DEFAULT_MAX_SESSION_DURATION: Duration = Duration::from_secs(180);
const MAX_WATCH_DEPTH: usize = 3;
const MAX_TEMP_DEPTH: usize = 2;
const MAX_SCAN_ENTRIES_PER_ROOT: usize = 1600;
const MAX_EVENTS_RETAINED: usize = 80;
const MAX_PREVIEW_NODES: usize = 20;
const MAX_CONTROLLER_HTTP_BYTES: usize = 8 * 1024 * 1024;
const CONTROLLER_PROBE_COOLDOWN: Duration = Duration::from_secs(3);

const IGNORED_WATCH_DIRS: &[&str] = &[
    "cache", "code cache", "gpucache", "dawngraphitecache", "dawnwebgpucache",
    "crashpad", "logs", "webview2", "ebwebview", "node_modules", ".git",
];
const GENERIC_DIR_TOKENS: &[&str] = &[
    "app", "application", "bin", "client", "core", "desktop", "electron", "helper",
    "launcher", "microsoft", "proxy", "service", "system", "update", "updater", "webview", "windows",
];
#[cfg(target_os = "windows")]
const WINDOWS_SHELL_PROCESSES: &[&str] = &[
    "applicationframehost.exe", "textinputhost.exe", "explorer.exe",
    "searchhost.exe", "shellexperiencehost.exe",
];
#[cfg(not(target_os = "windows"))]
const NON_WINDOWS_SYSTEM_PROCESSES: &[&str] = &[
    "systemd", "launchd", "init", "dbus-daemon", "windowserver",
    "loginwindow", "finder", "dock", "sshd", "cron",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DesktopAppCandidate {
    pub pid: u32,
    pub window_title: String,
    pub friendly_name: String,
    pub process_name: String,
    pub exe_path: Option<String>,
    pub working_dir: Option<String>,
    pub related_pids: Vec<u32>,
    pub is_newly_opened: bool,
    pub likely_proxy_client: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LiveCaptureStartDto {
    pub session_id: String,
    pub target_pid: u32,
    pub target_name: String,
    pub watch_dirs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LiveCaptureEventItem {
    pub timestamp_ms: u64,
    pub kind: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LiveCaptureStatusDto {
    pub session_id: String,
    pub active: bool,
    pub step_app_ready: bool,
    pub step_activity_seen: bool,
    pub step_nodes_ready: bool,
    pub elapsed_sec: u64,
    pub captured_node_count: usize,
    pub opaque_change_detected: bool,
    pub target_name: String,
    pub watch_dirs: Vec<String>,
    pub events: Vec<LiveCaptureEventItem>,
    pub preview_nodes: Vec<ProxyNode>,
    pub unsupported_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LiveCaptureOutcomeDto {
    pub session_id: String,
    pub supported: bool,
    pub target_name: String,
    pub source_kind: String,
    pub source_path: Option<String>,
    pub is_ephemeral_source: bool,
    pub nodes: Vec<ProxyNode>,
    pub unsupported_reason: Option<String>,
}

/// Recursively collect the current process PID and its entire descendant PID tree.
pub fn collect_self_pid_tree(system: &sysinfo::System) -> HashSet<u32> {
    collect_descendant_pids(system, std::process::id())
}

fn collect_descendant_pids(system: &System, root_pid: u32) -> HashSet<u32> {
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for (pid, p) in system.processes() {
        if let Some(parent) = p.parent() {
            children.entry(parent.as_u32()).or_default().push(pid.as_u32());
        }
    }
    let mut visited = HashSet::from([root_pid]);
    let mut queue = VecDeque::from([root_pid]);
    while let Some(curr) = queue.pop_front() {
        if let Some(list) = children.get(&curr) {
            for &child in list {
                if visited.insert(child) {
                    queue.push_back(child);
                }
            }
        }
    }
    visited
}

fn process_refresh_kind() -> ProcessRefreshKind {
    ProcessRefreshKind::nothing()
        .with_cmd(UpdateKind::Always)
        .with_exe(UpdateKind::Always)
        .with_cwd(UpdateKind::Always)
        .without_tasks()
}

fn snapshot_processes() -> System {
    System::new_with_specifics(RefreshKind::nothing().with_processes(process_refresh_kind()))
}

fn norm_path_key(path: &Path) -> String {
    let norm = normalize_os_path(path);
    #[cfg(target_os = "windows")]
    {
        norm.to_string_lossy().replace('/', "\\").trim_end_matches('\\').to_ascii_lowercase()
    }
    #[cfg(not(target_os = "windows"))]
    {
        norm.to_string_lossy().trim_end_matches('/').to_string()
    }
}

fn path_starts_with_dir(path: &Path, dir: &Path) -> bool {
    let (p, d) = (norm_path_key(path), norm_path_key(dir));
    if d.is_empty() {
        return false;
    }
    if p == d {
        return true;
    }
    let sep = if cfg!(target_os = "windows") { b'\\' } else { b'/' };
    p.starts_with(&d) && p.as_bytes().get(d.len()) == Some(&sep)
}

fn is_self_process(
    pid: u32,
    exe: Option<&Path>,
    name: &str,
    self_pids: &HashSet<u32>,
    self_exe: Option<&Path>,
    self_data_dir: Option<&Path>,
) -> bool {
    if self_pids.contains(&pid) || name.to_ascii_lowercase().contains("catcloud") {
        return true;
    }
    exe.is_some_and(|e| {
        self_exe.is_some_and(|cur| norm_path_key(e) == norm_path_key(cur))
            || self_data_dir.is_some_and(|d| path_starts_with_dir(e, d))
    })
}

fn is_shared_system_dir(dir: &Path) -> bool {
    let key = norm_path_key(dir);
    if key.len() <= 3 {
        return true;
    }
    #[cfg(target_os = "windows")]
    {
        let t = key.trim_end_matches('\\');
        [
            "\\windows", "\\system32", "\\syswow64", "\\program files",
            "\\program files (x86)", "\\programdata", "\\appdata\\roaming", "\\appdata\\local",
        ]
        .iter()
        .any(|s| t.ends_with(s))
    }
    #[cfg(not(target_os = "windows"))]
    {
        matches!(key.as_str(), "/" | "/bin" | "/sbin" | "/usr" | "/usr/bin" | "/usr/local/bin" | "/opt" | "/etc")
    }
}

fn collect_related_pids(
    system: &System,
    root_pid: u32,
    exe_dir: Option<&Path>,
    self_pids: &HashSet<u32>,
) -> Vec<u32> {
    let mut related = collect_descendant_pids(system, root_pid);
    if let Some(dir) = exe_dir.filter(|d| !is_shared_system_dir(d)) {
        let dir_key = norm_path_key(dir);
        for (pid, p) in system.processes() {
            let u = pid.as_u32();
            if !self_pids.contains(&u)
                && p.exe().and_then(Path::parent).is_some_and(|pd| norm_path_key(pd) == dir_key)
            {
                related.insert(u);
            }
        }
    }
    related.retain(|p| !self_pids.contains(p));
    let mut out: Vec<u32> = related.into_iter().collect();
    out.sort_unstable();
    out
}

fn derive_friendly_name(window_title: &str, process_name: &str) -> String {
    let trimmed = window_title.trim();
    if !trimmed.is_empty() {
        return trimmed.to_string();
    }
    let stem = process_name
        .strip_suffix(".exe")
        .or_else(|| process_name.strip_suffix(".EXE"))
        .unwrap_or(process_name)
        .trim();
    if stem.is_empty() { process_name.to_string() } else { stem.to_string() }
}

fn check_group_likely_proxy(system: &System, related_pids: &[u32], title: &str) -> bool {
    let lower = title.to_ascii_lowercase();
    if ["mihomo", "clash", "sing-box", "xray", "v2ray", "hysteria", "tuic", "proxy"]
        .iter()
        .any(|kw| lower.contains(kw))
    {
        return true;
    }
    related_pids.iter().any(|&pid| {
        system.process(Pid::from_u32(pid)).is_some_and(|p| {
            let cmd = p.cmd().iter().map(|a| a.to_string_lossy().into_owned()).collect();
            parse_process_cmdline(pid, p.name().to_string_lossy().into_owned(), p.exe().map(Path::to_path_buf), cmd)
                .likely_proxy_client
        })
    })
}

fn build_desktop_candidate(
    system: &System,
    pid: u32,
    proc_info: &sysinfo::Process,
    window_title: String,
    process_name: String,
    self_pids: &HashSet<u32>,
    baseline_pids: Option<&HashSet<u32>>,
) -> DesktopAppCandidate {
    let related_pids = collect_related_pids(system, pid, proc_info.exe().and_then(Path::parent), self_pids);
    let friendly_name = derive_friendly_name(&window_title, &process_name);
    let likely_proxy_client = check_group_likely_proxy(system, &related_pids, &friendly_name);
    let display_title = if window_title.is_empty() { friendly_name.clone() } else { window_title };
    DesktopAppCandidate {
        pid,
        window_title: display_title,
        friendly_name,
        process_name,
        exe_path: proc_info.exe().map(|p| normalize_os_path(p).to_string_lossy().into_owned()),
        working_dir: proc_info.cwd().map(|p| normalize_os_path(p).to_string_lossy().into_owned()),
        related_pids,
        is_newly_opened: baseline_pids.is_some_and(|base| !base.contains(&pid)),
        likely_proxy_client,
    }
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn enum_visible_windows_proc(
    hwnd: windows_sys::Win32::Foundation::HWND,
    lparam: windows_sys::Win32::Foundation::LPARAM,
) -> windows_sys::Win32::Foundation::BOOL {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            GWL_EXSTYLE, GetWindowLongW, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible,
            WS_EX_TOOLWINDOW,
        };
        if unsafe { IsWindowVisible(hwnd) } == 0 {
            return 1;
        }
        if ((unsafe { GetWindowLongW(hwnd, GWL_EXSTYLE) } as u32) & WS_EX_TOOLWINDOW) != 0 {
            return 1;
        }
        let mut buf = [0u16; 512];
        let len = unsafe { GetWindowTextW(hwnd, buf.as_mut_ptr(), buf.len() as i32) };
        if len <= 0 {
            return 1;
        }
        let title = String::from_utf16_lossy(&buf[..(len as usize).min(buf.len())]).trim().to_string();
        if title.is_empty() {
            return 1;
        }
        let mut pid: u32 = 0;
        unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };
        if pid != 0 && lparam != 0 {
            let out = unsafe { &mut *(lparam as *mut Vec<(u32, String)>) };
            out.push((pid, title));
        }
        1
    }))
    .unwrap_or(0)
}

#[cfg(target_os = "windows")]
fn collect_visible_windows_by_pid() -> HashMap<u32, String> {
    use windows_sys::Win32::Foundation::LPARAM;
    use windows_sys::Win32::UI::WindowsAndMessaging::EnumWindows;
    let mut raw: Vec<(u32, String)> = Vec::new();
    unsafe { EnumWindows(Some(enum_visible_windows_proc), (&mut raw as *mut Vec<(u32, String)>) as LPARAM) };
    let mut by_pid: HashMap<u32, String> = HashMap::new();
    for (pid, title) in raw {
        by_pid
            .entry(pid)
            .and_modify(|cur| {
                if title.chars().count() > cur.chars().count() {
                    *cur = title.clone();
                }
            })
            .or_insert(title);
    }
    by_pid
}

/// Enumerate visible desktop application candidates excluding CatCloud itself, its process tree,
/// its data directory, and OS shell hosts.
pub fn list_desktop_app_candidates(
    baseline_pids: Option<&HashSet<u32>>,
    self_data_dir: Option<&Path>,
) -> Vec<DesktopAppCandidate> {
    let system = snapshot_processes();
    let self_pids = collect_self_pid_tree(&system);
    let self_exe = std::env::current_exe().ok();
    let mut candidates = Vec::new();

    #[cfg(target_os = "windows")]
    for (pid, title) in collect_visible_windows_by_pid() {
        let Some(p) = system.process(Pid::from_u32(pid)) else { continue };
        let pname = p.name().to_string_lossy().into_owned();
        if WINDOWS_SHELL_PROCESSES.contains(&pname.to_ascii_lowercase().as_str())
            || title.to_ascii_lowercase().contains("catcloud")
            || title.contains("猫猫云梯")
            || is_self_process(pid, p.exe(), &pname, &self_pids, self_exe.as_deref(), self_data_dir)
        {
            continue;
        }
        candidates.push(build_desktop_candidate(&system, pid, p, title, pname, &self_pids, baseline_pids));
    }

    #[cfg(not(target_os = "windows"))]
    for (pid_val, p) in system.processes() {
        let pid = pid_val.as_u32();
        let pname = p.name().to_string_lossy().into_owned();
        let plower = pname.to_ascii_lowercase();
        if pname.trim().is_empty()
            || p.exe().is_none()
            || NON_WINDOWS_SYSTEM_PROCESSES.contains(&plower.as_str())
            || plower.starts_with("kworker")
            || plower.starts_with("ksoftirqd")
            || is_self_process(pid, p.exe(), &pname, &self_pids, self_exe.as_deref(), self_data_dir)
        {
            continue;
        }
        candidates.push(build_desktop_candidate(&system, pid, p, String::new(), pname, &self_pids, baseline_pids));
    }

    candidates.sort_by(|a, b| {
        b.is_newly_opened
            .cmp(&a.is_newly_opened)
            .then_with(|| b.likely_proxy_client.cmp(&a.likely_proxy_client))
            .then_with(|| a.friendly_name.to_ascii_lowercase().cmp(&b.friendly_name.to_ascii_lowercase()))
            .then_with(|| a.pid.cmp(&b.pid))
    });
    candidates
}

#[derive(Debug)]
struct SessionState {
    session_id: String,
    active: bool,
    step_app_ready: bool,
    step_activity_seen: bool,
    step_nodes_ready: bool,
    started_at: Instant,
    opaque_change_detected: bool,
    target_name: String,
    watch_dirs: Vec<PathBuf>,
    events: Vec<LiveCaptureEventItem>,
    captured_nodes: Vec<ProxyNode>,
    seen_node_keys: HashSet<(String, String, u16, String)>,
    hit_source_kind: Option<String>,
    hit_source_path: Option<PathBuf>,
    hit_ephemeral: bool,
}

impl SessionState {
    fn push_event(&mut self, kind: &str, message: String) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
            .unwrap_or(0);
        if self.events.last().is_some_and(|e| e.kind == kind && e.message == message) {
            return;
        }
        if self.events.len() >= MAX_EVENTS_RETAINED {
            self.events.remove(0);
        }
        self.events.push(LiveCaptureEventItem { timestamp_ms: ts, kind: kind.to_string(), message });
    }

    fn merge_nodes(
        &mut self,
        incoming: Vec<ProxyNode>,
        source_kind: &str,
        source_path: Option<PathBuf>,
        is_ephemeral: bool,
    ) -> usize {
        let mut added = 0usize;
        for node in incoming {
            let key = (node.protocol.to_ascii_lowercase(), node.server.to_ascii_lowercase(), node.port, node.name.clone());
            if self.seen_node_keys.insert(key) {
                self.captured_nodes.push(node);
                added += 1;
            }
        }
        if !self.captured_nodes.is_empty() {
            self.step_activity_seen = true;
            self.step_nodes_ready = true;
            if self.hit_source_kind.is_none() || added > 0 {
                self.hit_source_kind = Some(source_kind.to_string());
                self.hit_source_path = source_path;
                self.hit_ephemeral = is_ephemeral;
            }
        }
        added
    }

    fn to_status_dto(&self) -> LiveCaptureStatusDto {
        let unsupported_reason = (self.captured_nodes.is_empty() && (self.opaque_change_detected || !self.active))
            .then(|| CAPTURE_UNSUPPORTED_REASON.to_string());
        LiveCaptureStatusDto {
            session_id: self.session_id.clone(),
            active: self.active,
            step_app_ready: self.step_app_ready,
            step_activity_seen: self.step_activity_seen,
            step_nodes_ready: self.step_nodes_ready,
            elapsed_sec: self.started_at.elapsed().as_secs(),
            captured_node_count: self.captured_nodes.len(),
            opaque_change_detected: self.opaque_change_detected,
            target_name: self.target_name.clone(),
            watch_dirs: self.watch_dirs.iter().map(|p| p.to_string_lossy().into_owned()).collect(),
            events: self.events.clone(),
            preview_nodes: self.captured_nodes.iter().take(MAX_PREVIEW_NODES).cloned().collect(),
            unsupported_reason,
        }
    }
}

struct ActiveSession {
    session_id: String,
    stop_flag: Arc<AtomicBool>,
    state: Arc<Mutex<SessionState>>,
    worker: Option<JoinHandle<()>>,
}

impl ActiveSession {
    fn stop_and_join(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(handle) = self.worker.take() {
            let _ = handle.join();
        }
        if let Ok(mut g) = self.state.lock() {
            g.active = false;
        }
    }
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }
}

/// Thread-safe manager owning at most one active live capture background session.
#[derive(Default)]
pub struct LiveCaptureManager {
    op_lock: Mutex<()>,
    active: Mutex<Option<ActiveSession>>,
}

impl std::fmt::Debug for LiveCaptureManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sid = self.active.lock().ok().and_then(|g| g.as_ref().map(|s| s.session_id.clone()));
        f.debug_struct("LiveCaptureManager").field("active_session_id", &sid).finish()
    }
}

impl Drop for LiveCaptureManager {
    fn drop(&mut self) {
        if let Ok(mut g) = self.active.lock() {
            if let Some(mut s) = g.take() {
                s.stop_and_join();
            }
        }
    }
}

impl LiveCaptureManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn has_active_session(&self) -> bool {
        let Ok(guard) = self.active.lock() else {
            return false;
        };
        let Some(session) = guard.as_ref() else {
            return false;
        };
        if session.stop_flag.load(Ordering::Relaxed) {
            return false;
        }
        session
            .state
            .lock()
            .map(|state| state.active)
            .unwrap_or(false)
    }

    pub fn start_session(
        &self,
        target_pid: u32,
        self_data_dir: Option<PathBuf>,
    ) -> CatResult<LiveCaptureStartDto> {
        if target_pid == 0 {
            return Err(CatError::Validation("目标进程 PID 无效".to_string()));
        }
        let system = snapshot_processes();
        let self_pids = collect_self_pid_tree(&system);
        if self_pids.contains(&target_pid) {
            return Err(CatError::Validation("不能选择猫猫云梯自身进程进行抓取".to_string()));
        }
        let Some(p) = system.process(Pid::from_u32(target_pid)) else {
            return Err(CatError::NotFound(format!("未找到运行中的目标进程 PID {target_pid}")));
        };
        let proc_name = p.name().to_string_lossy().into_owned();
        let target_exe_dir = p.exe().and_then(Path::parent).map(normalize_os_path);
        #[cfg(target_os = "windows")]
        let window_title = collect_visible_windows_by_pid().remove(&target_pid).unwrap_or_default();
        #[cfg(not(target_os = "windows"))]
        let window_title = String::new();
        let target_name = derive_friendly_name(&window_title, &proc_name);
        let related = collect_related_pids(&system, target_pid, target_exe_dir.as_deref(), &self_pids);
        let watch_dirs = collect_initial_watch_dirs(&system, &related, &proc_name, &target_name, self_data_dir.as_deref());
        self.start_session_inner(
            target_pid, target_name, target_exe_dir, watch_dirs, self_data_dir,
            DEFAULT_POLL_INTERVAL, DEFAULT_MAX_SESSION_DURATION, true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn start_session_inner(
        &self,
        target_pid: u32,
        target_name: String,
        target_exe_dir: Option<PathBuf>,
        watch_dirs: Vec<PathBuf>,
        self_data_dir: Option<PathBuf>,
        poll_interval: Duration,
        max_duration: Duration,
        scan_system_temp: bool,
    ) -> CatResult<LiveCaptureStartDto> {
        let _op = self.op_lock.lock().unwrap_or_else(|e| e.into_inner());
        let prev = self.active.lock().map_err(|_| CatError::Process("捕捉状态锁异常".into()))?.take();
        if let Some(mut old) = prev {
            old.stop_and_join();
        }
        let session_id = format!("cap-{}", Uuid::new_v4());
        let stop_flag = Arc::new(AtomicBool::new(false));
        let mut init_state = SessionState {
            session_id: session_id.clone(),
            active: true,
            step_app_ready: true,
            step_activity_seen: false,
            step_nodes_ready: false,
            started_at: Instant::now(),
            opaque_change_detected: false,
            target_name: target_name.clone(),
            watch_dirs: watch_dirs.clone(),
            events: Vec::new(),
            captured_nodes: Vec::new(),
            seen_node_keys: HashSet::new(),
            hit_source_kind: None,
            hit_source_path: None,
            hit_ephemeral: false,
        };
        init_state.push_event("ready", format!("已锁定目标软件「{target_name}」，开始监听配置变更"));
        let state = Arc::new(Mutex::new(init_state));
        let (w_stop, w_state, w_dirs) = (Arc::clone(&stop_flag), Arc::clone(&state), watch_dirs.clone());
        let worker = std::thread::Builder::new()
            .name(format!("cap-{}", &session_id[4..12]))
            .spawn(move || {
                run_capture_loop(
                    target_pid, target_exe_dir, w_dirs, self_data_dir,
                    poll_interval, max_duration, scan_system_temp, w_stop, w_state,
                );
            })
            .map_err(|e| CatError::Process(format!("启动实时捕捉后台线程失败：{e}")))?;

        let dto = LiveCaptureStartDto {
            session_id: session_id.clone(),
            target_pid,
            target_name,
            watch_dirs: watch_dirs.iter().map(|p| p.to_string_lossy().into_owned()).collect(),
        };
        let new_session = ActiveSession {
            session_id,
            stop_flag,
            state,
            worker: Some(worker),
        };
        let replaced = {
            let mut guard = self.active.lock().map_err(|_| CatError::Process("捕捉状态锁异常".into()))?;
            guard.replace(new_session)
        };
        if let Some(mut stale) = replaced {
            stale.stop_and_join();
        }
        Ok(dto)
    }

    pub fn poll_session(&self, session_id: &str) -> CatResult<LiveCaptureStatusDto> {
        let guard = self.active.lock().map_err(|_| CatError::Process("捕捉状态锁异常".into()))?;
        let Some(s) = guard.as_ref().filter(|s| s.session_id == session_id) else {
            return Err(CatError::NotFound(format!("实时捕捉会话不存在：{session_id}")));
        };
        let state = s.state.lock().map_err(|_| CatError::Process("读取捕捉进度失败".into()))?;
        Ok(state.to_status_dto())
    }

    pub fn finish_session(&self, session_id: &str) -> CatResult<LiveCaptureOutcomeDto> {
        let _op = self.op_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut session = {
            let mut guard = self.active.lock().map_err(|_| CatError::Process("捕捉状态锁异常".into()))?;
            if !guard.as_ref().is_some_and(|s| s.session_id == session_id) {
                return Err(CatError::NotFound(format!("实时捕捉会话不存在：{session_id}")));
            }
            guard.take().expect("checked above")
        };
        session.stop_and_join();
        let state = session.state.lock().map_err(|_| CatError::Process("读取捕捉结果失败".into()))?;

        let mut nodes = Vec::with_capacity(state.captured_nodes.len());
        let mut dedup = HashSet::with_capacity(state.captured_nodes.len());
        for node in &state.captured_nodes {
            let key = (node.protocol.to_ascii_lowercase(), node.server.to_ascii_lowercase(), node.port, node.name.clone());
            if dedup.insert(key) {
                nodes.push(node.clone());
            }
        }
        if nodes.is_empty() {
            return Ok(LiveCaptureOutcomeDto {
                session_id: state.session_id.clone(),
                supported: false,
                target_name: state.target_name.clone(),
                source_kind: "none".to_string(),
                source_path: None,
                is_ephemeral_source: false,
                nodes: Vec::new(),
                unsupported_reason: Some(CAPTURE_UNSUPPORTED_REASON.to_string()),
            });
        }
        let path_in_temp = state.hit_source_path.as_deref().is_some_and(is_path_in_temp_dir);
        let vanished = state.hit_source_path.as_deref().is_some_and(|p| !p.exists());
        let is_ephemeral_source = state.hit_ephemeral || path_in_temp || vanished;
        let source_kind = if path_in_temp || is_ephemeral_source {
            "migrated".to_string()
        } else {
            state.hit_source_kind.clone().unwrap_or_else(|| "file".to_string())
        };
        Ok(LiveCaptureOutcomeDto {
            session_id: state.session_id.clone(),
            supported: true,
            target_name: state.target_name.clone(),
            source_kind,
            source_path: state.hit_source_path.as_ref().map(|p| p.to_string_lossy().into_owned()),
            is_ephemeral_source,
            nodes,
            unsupported_reason: None,
        })
    }

    pub fn cancel_session(&self, session_id: &str) -> bool {
        let _op = self.op_lock.lock().unwrap_or_else(|e| e.into_inner());
        let taken = self.active.lock().ok().and_then(|mut g| {
            if g.as_ref().is_some_and(|s| s.session_id == session_id) {
                g.take()
            } else {
                None
            }
        });
        if let Some(mut session) = taken {
            session.stop_and_join();
            true
        } else {
            false
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_capture_loop(
    target_pid: u32,
    target_exe_dir: Option<PathBuf>,
    mut watch_dirs: Vec<PathBuf>,
    self_data_dir: Option<PathBuf>,
    poll_interval: Duration,
    max_duration: Duration,
    scan_system_temp: bool,
    stop_flag: Arc<AtomicBool>,
    state: Arc<Mutex<SessionState>>,
) {
    let started_wall = SystemTime::now().checked_sub(Duration::from_secs(1)).unwrap_or(SystemTime::now());
    let started_mono = Instant::now();
    let mut system = System::new();
    let mut seen_pids: HashSet<u32> = HashSet::new();
    let mut seen_files: HashMap<PathBuf, (u64, u128)> = HashMap::new();
    let mut controller_urls: HashSet<String> = HashSet::new();
    let mut last_ctrl_probe: HashMap<String, Instant> = HashMap::new();
    let mut explicit_files: HashSet<PathBuf> = HashSet::new();
    let temp_root = normalize_os_path(&std::env::temp_dir());

    while !stop_flag.load(Ordering::SeqCst) {
        if started_mono.elapsed() >= max_duration {
            if let Ok(mut g) = state.lock() {
                g.push_event("timeout", "实时捕捉已达最长等待时间并自动停止".to_string());
                g.active = false;
            }
            break;
        }

        // 1. Track target process tree and sibling processes in the same executable directory
        if target_pid > 0 {
            system.refresh_processes_specifics(ProcessesToUpdate::All, true, process_refresh_kind());
            let self_pids = collect_self_pid_tree(&system);
            for pid in collect_related_pids(&system, target_pid, target_exe_dir.as_deref(), &self_pids) {
                let Some(p) = system.process(Pid::from_u32(pid)) else { continue };
                let pname = p.name().to_string_lossy().into_owned();
                if seen_pids.insert(pid) && pid != target_pid {
                    if let Ok(mut g) = state.lock() {
                        g.step_activity_seen = true;
                        g.push_event("process", format!("检测到关联进程启动：{pname} (PID {pid})"));
                    }
                }
                let cmd = p.cmd().iter().map(|a| a.to_string_lossy().into_owned()).collect();
                let parsed = parse_process_cmdline(pid, pname, p.exe().map(Path::to_path_buf), cmd);
                if let Some(d) = parsed.detected_config_dir {
                    push_safe_watch_dir(&mut watch_dirs, &d, self_data_dir.as_deref(), &state);
                }
                if let Some(f) = parsed.detected_config_file {
                    let norm = normalize_os_path(&f);
                    if !self_data_dir.as_deref().is_some_and(|d| path_starts_with_dir(&norm, d)) {
                        if let Some(parent) = norm.parent() {
                            push_safe_watch_dir(&mut watch_dirs, parent, self_data_dir.as_deref(), &state);
                        }
                        explicit_files.insert(norm);
                    }
                }
                if let Some(ctl) = parsed.detected_controller_addr.as_deref().and_then(normalize_loopback_controller_base_url) {
                    controller_urls.insert(ctl);
                }
            }
        }

        // 2. Scan watch_dirs + explicit cmdline files + temp_dir for modified config files
        let mut candidates: Vec<(PathBuf, bool)> = explicit_files.iter().filter(|f| f.is_file()).map(|f| (f.clone(), false)).collect();
        for dir in &watch_dirs {
            if stop_flag.load(Ordering::Relaxed) {
                break;
            }
            collect_recent_config_files(
                dir,
                MAX_WATCH_DEPTH,
                started_wall,
                self_data_dir.as_deref(),
                &stop_flag,
                &mut candidates,
            );
        }
        if scan_system_temp && !stop_flag.load(Ordering::Relaxed) && temp_root.is_dir() {
            collect_recent_config_files(
                &temp_root,
                MAX_TEMP_DEPTH,
                started_wall,
                self_data_dir.as_deref(),
                &stop_flag,
                &mut candidates,
            );
        }

        for (file_path, require_recent) in candidates {
            if stop_flag.load(Ordering::SeqCst) {
                break;
            }
            let Ok(meta) = std::fs::metadata(&file_path) else { continue };
            let len = meta.len();
            if len == 0 || len > MAX_SUBSCRIPTION_BYTES as u64 {
                continue;
            }
            let modified = meta.modified().unwrap_or(UNIX_EPOCH);
            if require_recent && modified < started_wall {
                continue;
            }
            let fp = (len, modified.duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0));
            if seen_files.get(&file_path) == Some(&fp) {
                continue;
            }
            let Some(bytes) = read_file_with_short_retry(&file_path) else { continue };
            seen_files.insert(file_path.clone(), fp);
            let is_temp = is_path_in_temp_dir(&file_path);
            let fname = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("配置文件");
            match parse_captured_bytes("live_capture", &bytes, &mut controller_urls) {
                CapturedBytesOutcome::Nodes(nodes) => {
                    if let Ok(mut g) = state.lock() {
                        let added = g.merge_nodes(nodes, if is_temp { "migrated" } else { "file" }, Some(file_path.clone()), is_temp);
                        if added > 0 {
                            g.push_event("nodes", format!("已从「{fname}」解析出 {added} 个可用节点"));
                        }
                    }
                }
                CapturedBytesOutcome::Opaque => {
                    if let Ok(mut g) = state.lock() {
                        g.step_activity_seen = true;
                        g.opaque_change_detected = true;
                        if g.captured_nodes.is_empty() {
                            g.push_event("opaque", format!("检测到「{fname}」变更，但内容为非明文/受保护格式"));
                        }
                    }
                }
                CapturedBytesOutcome::Ignored => {}
            }
        }

        // 3. Probe discovered loopback controller endpoints synchronously without Tokio
        for base_url in &controller_urls {
            if stop_flag.load(Ordering::SeqCst) {
                break;
            }
            if last_ctrl_probe.get(base_url).is_some_and(|t| t.elapsed() < CONTROLLER_PROBE_COOLDOWN) {
                continue;
            }
            last_ctrl_probe.insert(base_url.clone(), Instant::now());
            if let Some(body) =
                fetch_loopback_proxies_sync(base_url, Duration::from_millis(1200), &stop_flag)
            {
                if let Ok((nodes, _, _, _)) = parse_controller_proxies_json("live_capture", &body) {
                    if !nodes.is_empty() {
                        if let Ok(mut g) = state.lock() {
                            let added = g.merge_nodes(nodes, "migrated", None, true);
                            if added > 0 {
                                g.push_event("nodes", format!("已从本地控制口捕获 {added} 个可直连节点"));
                            }
                        }
                    }
                }
            }
        }

        let mut remaining = poll_interval;
        while !remaining.is_zero() && !stop_flag.load(Ordering::SeqCst) {
            let step = remaining.min(Duration::from_millis(50));
            std::thread::sleep(step);
            remaining = remaining.saturating_sub(step);
        }
    }
    if let Ok(mut g) = state.lock() {
        g.active = false;
    }
}

fn collect_initial_watch_dirs(
    system: &System,
    related_pids: &[u32],
    proc_name: &str,
    target_name: &str,
    self_data_dir: Option<&Path>,
) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let mut seen = HashSet::new();
    let mut add = |candidate: &Path| {
        let norm = normalize_os_path(candidate);
        if norm.is_dir()
            && !is_shared_system_dir(&norm)
            && !self_data_dir.is_some_and(|s| path_starts_with_dir(&norm, s))
            && seen.insert(norm_path_key(&norm))
        {
            dirs.push(norm);
        }
    };

    for &pid in related_pids {
        let Some(p) = system.process(Pid::from_u32(pid)) else { continue };
        if let Some(exe_dir) = p.exe().and_then(Path::parent) { add(exe_dir); }
        if let Some(cwd) = p.cwd() { add(cwd); }
        let cmd = p.cmd().iter().map(|a| a.to_string_lossy().into_owned()).collect();
        let parsed = parse_process_cmdline(pid, p.name().to_string_lossy().into_owned(), p.exe().map(Path::to_path_buf), cmd);
        if let Some(d) = parsed.detected_config_dir { add(&d); }
        if let Some(parent) = parsed.detected_config_file.as_deref().and_then(Path::parent) { add(parent); }
    }

    let tokens = extract_safe_app_tokens(proc_name, target_name);
    if !tokens.is_empty() {
        for base in user_appdata_roots() {
            let Ok(entries) = std::fs::read_dir(&base) else { continue };
            for entry in entries.filter_map(Result::ok) {
                let p = entry.path();
                if !p.is_dir() { continue; }
                let Some(name) = p.file_name().and_then(|n| n.to_str()) else { continue };
                let norm = normalize_alnum(name);
                if norm.len() >= 3 && tokens.iter().any(|t| norm == *t || (t.len() >= 4 && norm.contains(t))) {
                    add(&p);
                }
            }
        }
    }
    dirs
}

fn push_safe_watch_dir(
    watch_dirs: &mut Vec<PathBuf>,
    candidate: &Path,
    self_data_dir: Option<&Path>,
    state: &Arc<Mutex<SessionState>>,
) {
    let norm = normalize_os_path(candidate);
    if !norm.is_dir()
        || is_shared_system_dir(&norm)
        || self_data_dir.is_some_and(|s| path_starts_with_dir(&norm, s))
    {
        return;
    }
    let key = norm_path_key(&norm);
    if !watch_dirs.iter().any(|d| norm_path_key(d) == key) {
        watch_dirs.push(norm.clone());
        if let Ok(mut g) = state.lock() {
            g.watch_dirs.push(norm);
        }
    }
}

fn user_appdata_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    #[cfg(target_os = "windows")]
    for key in ["APPDATA", "LOCALAPPDATA"] {
        if let Ok(v) = std::env::var(key) {
            let p = PathBuf::from(v);
            if p.is_dir() { roots.push(p); }
        }
    }
    #[cfg(target_os = "macos")]
    if let Ok(home) = std::env::var("HOME") {
        let p = PathBuf::from(home).join("Library").join("Application Support");
        if p.is_dir() { roots.push(p); }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    if let Ok(home) = std::env::var("HOME") {
        let h = PathBuf::from(home);
        for rel in [".config", ".local/share"] {
            let p = h.join(rel);
            if p.is_dir() { roots.push(p); }
        }
    }
    roots
}

fn normalize_alnum(raw: &str) -> String {
    raw.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_lowercase()).collect()
}

fn extract_safe_app_tokens(proc_name: &str, target_name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let stem = proc_name.strip_suffix(".exe").or_else(|| proc_name.strip_suffix(".EXE")).unwrap_or(proc_name);
    for raw in [stem, target_name] {
        let joined = normalize_alnum(raw);
        if joined.len() >= 3 && !GENERIC_DIR_TOKENS.contains(&joined.as_str()) && !out.contains(&joined) {
            out.push(joined);
        }
        for piece in raw.split(|c: char| !c.is_ascii_alphanumeric()) {
            let tok = piece.to_ascii_lowercase();
            if tok.len() >= 4 && !GENERIC_DIR_TOKENS.contains(&tok.as_str()) && !out.contains(&tok) {
                out.push(tok);
            }
        }
    }
    out
}

fn collect_recent_config_files(
    root: &Path,
    max_depth: usize,
    since: SystemTime,
    self_data_dir: Option<&Path>,
    stop_flag: &AtomicBool,
    out: &mut Vec<(PathBuf, bool)>,
) {
    let mut queue = VecDeque::from([(root.to_path_buf(), 0usize)]);
    let mut visited = 0usize;
    while let Some((dir, depth)) = queue.pop_front() {
        if stop_flag.load(Ordering::Relaxed) || visited >= MAX_SCAN_ENTRIES_PER_ROOT {
            break;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.filter_map(Result::ok) {
            if stop_flag.load(Ordering::Relaxed) {
                return;
            }
            visited += 1;
            if visited >= MAX_SCAN_ENTRIES_PER_ROOT { break; }
            let path = entry.path();
            if self_data_dir.is_some_and(|s| path_starts_with_dir(&path, s)) { continue; }
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                let lower = entry.file_name().to_string_lossy().to_ascii_lowercase();
                if depth < max_depth && !IGNORED_WATCH_DIRS.contains(&lower.as_str()) {
                    queue.push_back((path, depth + 1));
                }
                continue;
            }
            if !ft.is_file() || !is_capture_config_ext(&path) { continue; }
            if let Ok(meta) = entry.metadata() {
                if meta.len() > 0 && meta.len() <= MAX_SUBSCRIPTION_BYTES as u64 && meta.modified().is_ok_and(|m| m >= since) {
                    out.push((normalize_os_path(&path), true));
                }
            }
        }
    }
}

fn is_capture_config_ext(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .is_some_and(|ext| matches!(ext.as_str(), "yaml" | "yml" | "json" | "txt" | "conf"))
}

fn is_path_in_temp_dir(path: &Path) -> bool {
    path_starts_with_dir(path, &normalize_os_path(&std::env::temp_dir()))
}

fn read_file_with_short_retry(path: &Path) -> Option<Vec<u8>> {
    for attempt in 0..3 {
        match std::fs::read(path) {
            Ok(b) if !b.is_empty() && b.len() <= MAX_SUBSCRIPTION_BYTES => return Some(b),
            Ok(_) => return None,
            Err(_) if attempt < 2 => std::thread::sleep(Duration::from_millis(25)),
            Err(_) => return None,
        }
    }
    None
}

enum CapturedBytesOutcome {
    Nodes(Vec<ProxyNode>),
    Opaque,
    Ignored,
}

fn parse_captured_bytes(
    sub_id: &str,
    bytes: &[u8],
    controller_urls: &mut HashSet<String>,
) -> CapturedBytesOutcome {
    if bytes.is_empty() || bytes.len() > MAX_SUBSCRIPTION_BYTES {
        return CapturedBytesOutcome::Ignored;
    }
    let has_nul = bytes[..bytes.len().min(4096)].contains(&0);
    let Ok(raw_text) = std::str::from_utf8(bytes) else {
        return if bytes.len() >= 16 { CapturedBytesOutcome::Opaque } else { CapturedBytesOutcome::Ignored };
    };
    if has_nul {
        return CapturedBytesOutcome::Opaque;
    }
    let text = raw_text.strip_prefix('\u{FEFF}').unwrap_or(raw_text).trim();
    if text.is_empty() {
        return CapturedBytesOutcome::Ignored;
    }

    for line in text.lines().take(200) {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("external-controller:").or_else(|| l.strip_prefix("\"external-controller\":")) {
            if let Some(url) = normalize_loopback_controller_base_url(rest.trim().trim_matches([',', '"', '\''])) {
                controller_urls.insert(url);
            }
        }
    }

    if text.starts_with('{') {
        if let Some(nodes) = parse_json_config_nodes(sub_id, text) {
            return CapturedBytesOutcome::Nodes(nodes);
        }
    }
    if let Ok(parsed) = parse_subscription_payload(sub_id, bytes, None) {
        if !parsed.nodes.is_empty() {
            return CapturedBytesOutcome::Nodes(parsed.nodes);
        }
    }

    let ctrl_count = text.chars().take(1024).filter(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t')).count();
    let structured_plaintext = serde_json::from_str::<serde_json::Value>(text).is_ok()
        || serde_yaml_ng::from_str::<serde_yaml_ng::Value>(text).is_ok_and(|v| v.is_mapping() || v.is_sequence());
    if ctrl_count >= 4 || (!structured_plaintext && bytes.len() >= 32) {
        CapturedBytesOutcome::Opaque
    } else {
        CapturedBytesOutcome::Ignored
    }
}

fn parse_json_config_nodes(sub_id: &str, text: &str) -> Option<Vec<ProxyNode>> {
    let val: serde_json::Value = serde_json::from_str(text).ok()?;
    let mut nodes = Vec::new();
    let mut used_ids = HashSet::new();

    if let Some(proxies_val) = val.get("proxies") {
        if let Some(arr) = proxies_val.as_array() {
            for obj in arr.iter().filter_map(serde_json::Value::as_object) {
                if let Ok(node) = node_from_clash_json(sub_id, obj, &mut used_ids) {
                    nodes.push(node);
                }
            }
        } else if proxies_val.is_object() {
            if let Ok((ctrl_nodes, _, _, _)) = parse_controller_proxies_json(sub_id, text.as_bytes()) {
                nodes.extend(ctrl_nodes);
            }
        }
    }
    if let Some(outbounds) = val.get("outbounds").and_then(serde_json::Value::as_array) {
        for obj in outbounds.iter().filter_map(serde_json::Value::as_object) {
            let proto = obj
                .get("protocol")
                .or_else(|| obj.get("type"))
                .and_then(serde_json::Value::as_str)
                .map(|s| s.trim().to_ascii_lowercase())
                .unwrap_or_default();
            if matches!(proto.as_str(), "" | "freedom" | "blackhole" | "dns" | "direct" | "block" | "selector" | "urltest" | "loopback") {
                continue;
            }
            if let Some(node) = parse_json_outbound(sub_id, &proto, obj, &mut used_ids) {
                nodes.push(node);
            }
        }
    }
    (!nodes.is_empty()).then_some(nodes)
}

fn parse_json_outbound(
    sub_id: &str,
    raw_proto: &str,
    obj: &serde_json::Map<String, serde_json::Value>,
    used_ids: &mut HashSet<String>,
) -> Option<ProxyNode> {
    let protocol = normalize_protocol(raw_proto);
    let tag = obj.get("tag").and_then(serde_json::Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(ToOwned::to_owned);

    if let (Some(server), Some(port)) = (
        obj.get("server").and_then(serde_json::Value::as_str).map(str::trim).filter(|s| !s.is_empty()),
        obj.get("server_port").and_then(json_to_u16).filter(|&p| p > 0),
    ) {
        let name = tag.unwrap_or_else(|| format!("{protocol}-{server}:{port}"));
        let mut cfg = obj.clone();
        cfg.insert("name".into(), serde_json::json!(name));
        cfg.insert("type".into(), serde_json::json!(protocol));
        cfg.insert("server".into(), serde_json::json!(server));
        cfg.insert("port".into(), serde_json::json!(port));
        return Some(build_proxy_node(sub_id, name, protocol, server.to_string(), port, serde_json::Value::Object(cfg), used_ids));
    }

    let settings = obj.get("settings").and_then(serde_json::Value::as_object)?;
    let (server, port, mut cfg) = if let Some(vnext) = settings.get("vnext").and_then(serde_json::Value::as_array).and_then(|a| a.first()).and_then(serde_json::Value::as_object) {
        let srv = vnext.get("address").and_then(serde_json::Value::as_str)?.trim().to_string();
        let port = vnext.get("port").and_then(json_to_u16).filter(|&p| p > 0)?;
        let mut map = serde_json::Map::new();
        if let Some(u) = vnext.get("users").and_then(serde_json::Value::as_array).and_then(|a| a.first()).and_then(serde_json::Value::as_object) {
            if let Some(id) = u.get("id").and_then(serde_json::Value::as_str) { map.insert("uuid".into(), serde_json::json!(id)); }
            if let Some(flow) = u.get("flow").and_then(serde_json::Value::as_str) { map.insert("flow".into(), serde_json::json!(flow)); }
            if let Some(sec) = u.get("security").and_then(serde_json::Value::as_str) { map.insert("cipher".into(), serde_json::json!(sec)); }
            if let Some(aid) = u.get("alterId").and_then(serde_json::Value::as_u64) { map.insert("alterId".into(), serde_json::json!(aid)); }
        }
        (srv, port, map)
    } else if let Some(s) = settings.get("servers").and_then(serde_json::Value::as_array).and_then(|a| a.first()).and_then(serde_json::Value::as_object) {
        let srv = s.get("address").and_then(serde_json::Value::as_str)?.trim().to_string();
        let port = s.get("port").and_then(json_to_u16).filter(|&p| p > 0)?;
        let mut map = serde_json::Map::new();
        if let Some(pw) = s.get("password").and_then(serde_json::Value::as_str) { map.insert("password".into(), serde_json::json!(pw)); }
        if let Some(m) = s.get("method").and_then(serde_json::Value::as_str) { map.insert("cipher".into(), serde_json::json!(m)); }
        (srv, port, map)
    } else {
        return None;
    };
    if server.is_empty() { return None; }
    let name = tag.unwrap_or_else(|| format!("{protocol}-{server}:{port}"));
    cfg.insert("name".into(), serde_json::json!(name));
    cfg.insert("type".into(), serde_json::json!(protocol));
    cfg.insert("server".into(), serde_json::json!(server));
    cfg.insert("port".into(), serde_json::json!(port));
    if let Some(ss) = obj.get("streamSettings").and_then(serde_json::Value::as_object) {
        if let Some(net) = ss.get("network").and_then(serde_json::Value::as_str).filter(|n| !n.eq_ignore_ascii_case("tcp")) {
            cfg.insert("network".into(), serde_json::json!(net));
        }
        if let Some(sec) = ss.get("security").and_then(serde_json::Value::as_str) {
            if matches!(sec.to_ascii_lowercase().as_str(), "tls" | "reality") {
                cfg.insert("tls".into(), serde_json::json!(true));
                let sni = ss.get("tlsSettings").or_else(|| ss.get("realitySettings")).and_then(|t| t.get("serverName")).and_then(serde_json::Value::as_str);
                if let Some(sni) = sni.filter(|s| !s.is_empty()) {
                    cfg.insert("servername".into(), serde_json::json!(sni));
                }
            }
        }
    }
    Some(build_proxy_node(sub_id, name, protocol, server, port, serde_json::Value::Object(cfg), used_ids))
}

fn fetch_loopback_proxies_sync(
    base_url: &str,
    timeout: Duration,
    stop_flag: &AtomicBool,
) -> Option<Vec<u8>> {
    if stop_flag.load(Ordering::Relaxed) {
        return None;
    }
    let host_port = base_url.strip_prefix("http://")?;
    let addr: SocketAddr = host_port.parse().ok()?;
    if !addr.ip().is_loopback() { return None; }
    let total_deadline = Instant::now() + Duration::from_millis(2500);
    let connect_timeout = timeout.min(Duration::from_millis(2500));
    let mut stream = TcpStream::connect_timeout(&addr, connect_timeout).ok()?;
    if stop_flag.load(Ordering::Relaxed) || Instant::now() >= total_deadline {
        return None;
    }
    let write_timeout = timeout.min(total_deadline.saturating_duration_since(Instant::now()));
    if write_timeout.is_zero() {
        return None;
    }
    let _ = stream.set_write_timeout(Some(write_timeout));
    stream.write_all(format!("GET /proxies HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n\r\n").as_bytes()).ok()?;

    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    let mut idle_since = Instant::now();
    let base_slice = timeout.min(Duration::from_millis(200)).max(Duration::from_millis(20));
    let _ = stream.set_read_timeout(Some(base_slice));
    loop {
        if stop_flag.load(Ordering::Relaxed) {
            return None;
        }
        let now = Instant::now();
        if now >= total_deadline {
            return None;
        }
        let remaining_total = total_deadline.saturating_duration_since(now);
        if remaining_total.is_zero() {
            return None;
        }
        if remaining_total < base_slice {
            let _ = stream.set_read_timeout(Some(remaining_total));
        }
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) if raw.len().saturating_add(n) <= MAX_CONTROLLER_HTTP_BYTES => {
                raw.extend_from_slice(&buf[..n]);
                idle_since = Instant::now();
            }
            Ok(_) => return None,
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                if stop_flag.load(Ordering::Relaxed) || Instant::now() >= total_deadline {
                    return None;
                }
                if idle_since.elapsed() >= timeout {
                    break;
                }
                continue;
            }
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let header = std::str::from_utf8(&raw[..split]).ok()?;
    let status = header.lines().next()?;
    if !(status.starts_with("HTTP/") && status.split_whitespace().nth(1) == Some("200")) {
        return None;
    }
    let body = &raw[split + 4..];
    if header.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        decode_http_chunked(body)
    } else {
        Some(body.to_vec())
    }
}

fn decode_http_chunked(mut data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let crlf = data.windows(2).position(|w| w == b"\r\n")?;
        let size = usize::from_str_radix(std::str::from_utf8(&data[..crlf]).ok()?.split(';').next()?.trim(), 16).ok()?;
        data = &data[crlf + 2..];
        if size == 0 { break; }
        if data.len() < size + 2 || out.len().saturating_add(size) > MAX_CONTROLLER_HTTP_BYTES { return None; }
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::SubscriptionRecord;
    use crate::subscription::process_attach::list_process_candidates;

    #[test]
    fn live_capture_manager_traits_and_subscription_record_serde_regression() {
        fn assert_state_bounds<T: Send + Sync + Default + std::fmt::Debug>() {}
        assert_state_bounds::<LiveCaptureManager>();

        let primary: SubscriptionRecord = serde_json::from_str(
            r#"{"id":"s1","name":"Primary","url_or_cmd":"https://example.invalid/sub"}"#,
        ).expect("url_or_cmd alone must deserialize");
        assert_eq!(primary.url_or_cmd, "https://example.invalid/sub");

        let alias: SubscriptionRecord = serde_json::from_str(
            r#"{"id":"s2","name":"Alias","source":"https://example.invalid/alias"}"#,
        ).expect("source alias alone must deserialize");
        assert_eq!(alias.url_or_cmd, "https://example.invalid/alias");

        let err = serde_json::from_str::<SubscriptionRecord>(
            r#"{"id":"s3","url_or_cmd":"https://a.invalid","source":"https://b.invalid"}"#,
        ).expect_err("providing both url_or_cmd and source must fail");
        assert!(err.to_string().contains("duplicate field"), "unexpected error: {err}");
    }

    #[test]
    fn collect_self_pid_tree_excludes_current_process_everywhere() {
        let self_pid = std::process::id();
        let tree = collect_self_pid_tree(&snapshot_processes());
        assert!(tree.contains(&self_pid));
        assert!(list_process_candidates(false).iter().all(|c| c.pid != self_pid));
        assert!(list_desktop_app_candidates(None, None).iter().all(|c| c.pid != self_pid && !c.related_pids.contains(&self_pid)));
    }

    #[test]
    fn live_capture_grabs_ephemeral_plaintext_yaml_before_deletion() {
        let temp_dir = std::env::temp_dir().join(format!("catcloud-livecap-ok-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).expect("create temp capture dir");
        let mgr = LiveCaptureManager::new();
        let start = mgr.start_session_inner(
            0, "MockClient".to_string(), None, vec![temp_dir.clone()], None,
            Duration::from_millis(40), Duration::from_secs(10), false,
        ).expect("start mock capture session");

        let ephemeral = temp_dir.join("ephemeral_runtime.yaml");
        std::fs::write(&ephemeral, concat!(
            "proxies:\n",
            "  - name: \"JP Live 1x\"\n    type: vless\n    server: 203.0.113.10\n    port: 443\n    uuid: \"00000000-0000-4000-8000-000000000091\"\n    tls: true\n",
            "  - name: \"SG Live 0.5x\"\n    type: trojan\n    server: 198.51.100.20\n    port: 443\n    password: \"placeholder-secret\"\n"
        )).expect("write ephemeral yaml");

        let deadline = Instant::now() + Duration::from_secs(3);
        let mut captured = false;
        while Instant::now() < deadline {
            let st = mgr.poll_session(&start.session_id).expect("poll session");
            if st.step_nodes_ready && st.captured_node_count == 2 {
                captured = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        assert!(captured, "expected worker to capture ephemeral YAML");
        let _ = std::fs::remove_file(&ephemeral);

        let outcome = mgr.finish_session(&start.session_id).expect("finish session");
        assert!(outcome.supported);
        assert!(outcome.is_ephemeral_source);
        assert_eq!(outcome.source_kind, "migrated");
        assert_eq!(outcome.nodes.len(), 2);
        assert!(outcome.unsupported_reason.is_none());
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn live_capture_opaque_encrypted_change_returns_unsupported_reason() {
        let temp_dir = std::env::temp_dir().join(format!("catcloud-livecap-opaque-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).expect("create temp opaque dir");
        let mgr = LiveCaptureManager::new();
        let start = mgr.start_session_inner(
            0, "OpaqueClient".to_string(), None, vec![temp_dir.clone()], None,
            Duration::from_millis(40), Duration::from_secs(10), false,
        ).expect("start opaque capture session");

        let opaque = temp_dir.join("protected.yaml");
        std::fs::write(&opaque, [0x00u8, 0xFF, 0xFE, 0xA1, 0x9C, 0x8B, 0x7D, 0xE2, 0x13, 0x88, 0xC4, 0x00, 0x91, 0xDE, 0xAD, 0xBE, 0xEF, 0x77, 0x66, 0x55]).expect("write opaque file");

        let deadline = Instant::now() + Duration::from_secs(3);
        let mut saw_opaque = false;
        while Instant::now() < deadline {
            let st = mgr.poll_session(&start.session_id).expect("poll opaque session");
            if st.step_activity_seen && st.opaque_change_detected && !st.step_nodes_ready {
                saw_opaque = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        assert!(saw_opaque, "expected opaque_change_detected to become true");

        let outcome = mgr.finish_session(&start.session_id).expect("finish opaque session");
        assert!(!outcome.supported);
        assert_eq!(outcome.source_kind, "none");
        assert!(outcome.nodes.is_empty());
        assert_eq!(outcome.unsupported_reason.as_deref(), Some(CAPTURE_UNSUPPORTED_REASON));
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn live_capture_has_active_session_and_respects_stop_flag_short_circuit() {
        let temp_dir = std::env::temp_dir().join(format!("catcloud-livecap-active-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).expect("create temp active dir");
        std::fs::write(temp_dir.join("probe.yaml"), "proxies: []\n").expect("write probe yaml");

        let stopped = AtomicBool::new(true);
        let mut out = Vec::new();
        collect_recent_config_files(&temp_dir, 2, UNIX_EPOCH, None, &stopped, &mut out);
        assert!(out.is_empty(), "pre-stopped flag must abort directory scan immediately");
        assert!(
            fetch_loopback_proxies_sync("http://127.0.0.1:1", Duration::from_millis(200), &stopped)
                .is_none()
        );

        let mgr = LiveCaptureManager::new();
        assert!(!mgr.has_active_session());
        let start = mgr
            .start_session_inner(
                0,
                "MockActiveClient".to_string(),
                None,
                vec![temp_dir.clone()],
                None,
                Duration::from_millis(40),
                Duration::from_secs(10),
                false,
            )
            .expect("start active capture session");
        assert!(mgr.has_active_session());
        assert!(mgr.cancel_session(&start.session_id));
        assert!(!mgr.has_active_session());
        assert!(!mgr.cancel_session(&start.session_id));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
