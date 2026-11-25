use crate::error::{CatError, CatResult};
use crate::models::ProxyNode;
use crate::paths::normalize_os_path;
use crate::subscription::parser::{
    MAX_SUBSCRIPTION_BYTES, build_proxy_node, json_to_u16, node_from_clash_json,
    node_from_singbox_outbound, normalize_protocol, normalize_ws_headers_map,
    parse_subscription_payload,
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
#[cfg(target_os = "windows")]
use std::sync::OnceLock;
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
const EXISTING_CONFIG_FALLBACK_WINDOW: Duration = Duration::from_secs(7 * 24 * 3600);
const MAX_WATCH_DEPTH: usize = 3;
const MAX_SCAN_ENTRIES_PER_ROOT: usize = 1600;
const MAX_TEMP_TOP_ENTRIES: usize = 12_000;
const MAX_TEMP_FRESH_SUBDIRS: usize = 64;
const MAX_TEMP_WARM_SUBDIRS: usize = 32;
const MAX_EVENTS_RETAINED: usize = 80;
const MAX_PREVIEW_NODES: usize = 20;
const MAX_CONTROLLER_HTTP_BYTES: usize = 8 * 1024 * 1024;
const CONTROLLER_PROBE_COOLDOWN: Duration = Duration::from_secs(3);
#[cfg(target_os = "windows")]
const MAX_PE_VERSION_INFO_BYTES: usize = 4 * 1024 * 1024;
#[cfg(any(target_os = "windows", test))]
const MAX_PE_NAME_CACHE_ENTRIES: usize = 128;

/// Generic shell/runtime/placeholder window titles and tokens that should yield to a real
/// PE FileDescription/ProductName when available. Contains zero proprietary vendor names.
const GENERIC_SHELL_OR_RUNTIME_TITLES: &[&str] = &[
    "electron",
    "tauri",
    "webview2",
    "webview",
    "flclash",
    "clash",
    "mihomo",
    "sing-box",
    "singbox",
    "mainwindow",
    "main",
    "home",
    "index",
    "index.html",
    "client",
    "desktop",
    "app",
    "application",
    "window",
    "untitled",
    "about:blank",
    "localhost",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "flutter",
    "chromium",
    "msedgewebview2",
    "nwjs",
    "launcher",
    "helper",
    "service",
    "tray",
    "gui",
    "ui",
];

/// Known non-proxy database / OS service TCP ports excluded when inferring background proxy listeners.
#[cfg(any(target_os = "windows", test))]
const KNOWN_EXCLUDED_LISTENER_PORTS: &[u16] = &[
    1433,  // MS SQL Server
    1434,  // MS SQL Monitor
    1521,  // Oracle DB
    3306,  // MySQL / MariaDB
    33060, // MySQL X Protocol
    3389,  // RDP
    5040,  // Windows Connected Devices Platform
    5432,  // PostgreSQL
    5985,  // WinRM HTTP
    5986,  // WinRM HTTPS
    6379,  // Redis
    7680,  // Windows Delivery Optimization
    9200,  // Elasticsearch HTTP
    9300,  // Elasticsearch Transport
    11211, // Memcached
    27017, // MongoDB
    27018, // MongoDB shard
    27019, // MongoDB config
];

const IGNORED_WATCH_DIRS: &[&str] = &[
    "cache", "code cache", "gpucache", "dawngraphitecache", "dawnwebgpucache",
    "crashpad", "logs", "webview2", "ebwebview", "node_modules", ".git",
];
const GENERIC_DIR_TOKENS: &[&str] = &[
    "app", "application", "bin", "client", "core", "desktop", "electron", "helper",
    "launcher", "microsoft", "proxy", "service", "system", "update", "updater", "webview", "windows",
];
const GENERIC_PROXY_KEYWORDS: &[&str] = &[
    "nekobox",
    "nekoray",
    "hiddify",
    "karing",
    "sparkle",
    "v2box",
    "flclash",
    "sing-box",
    "singbox",
    "mihomo",
    "clash",
    "v2ray",
    "xray",
    "shadowsocks",
    "trojan",
    "hysteria",
    "tuic",
    "proxy",
    "vpn",
];

#[cfg(target_os = "windows")]
const WINDOWS_SHELL_PROCESSES: &[&str] = &[
    "applicationframehost.exe", "textinputhost.exe", "explorer.exe",
    "searchhost.exe", "shellexperiencehost.exe",
];
#[cfg(target_os = "windows")]
const WINDOWS_BACKGROUND_SYSTEM_PROCESSES: &[&str] = &[
    "system",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "winlogon.exe",
    "dwm.exe",
    "spoolsv.exe",
    "sihost.exe",
    "taskhostw.exe",
    "ctfmon.exe",
    "fontdrvhost.exe",
    "conhost.exe",
    "dllhost.exe",
    "runtimebroker.exe",
    "backgroundtaskhost.exe",
    "searchindexer.exe",
    "wmiprvse.exe",
    "msiexec.exe",
    "trustedinstaller.exe",
    "tiworker.exe",
    "msmpeng.exe",
    "nissrv.exe",
    "securityhealthservice.exe",
    "dashost.exe",
    "audiodg.exe",
    "smartscreen.exe",
    "msedgewebview2.exe",
    "webviewhost.exe",
    "crashpad_handler.exe",
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
    #[serde(default)]
    pub timed_out: bool,
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
        norm.to_string_lossy()
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_ascii_lowercase()
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
    #[cfg(target_os = "windows")]
    {
        let user_home = std::env::var_os("USERPROFILE").map(PathBuf::from);
        if is_shared_system_dir_with_home(dir, user_home.as_deref()) {
            return true;
        }
        if let Some(od) = std::env::var_os("OneDrive") {
            let t = norm_path_key(dir);
            let od_key = norm_path_key(Path::new(&od));
            if !od_key.is_empty()
                && (t == od_key
                    || t.strip_prefix(&od_key)
                        .and_then(|rest| rest.strip_prefix('\\'))
                        .is_some_and(|rel| matches!(rel, "desktop" | "downloads" | "documents")))
            {
                return true;
            }
        }
        false
    }
    #[cfg(not(target_os = "windows"))]
    {
        let user_home = std::env::var_os("HOME").map(PathBuf::from);
        is_shared_system_dir_with_home(dir, user_home.as_deref())
    }
}

fn is_shared_system_dir_with_home(dir: &Path, user_home: Option<&Path>) -> bool {
    let key = norm_path_key(dir);
    if key.len() <= 3 {
        return true;
    }
    #[cfg(target_os = "windows")]
    {
        let t = key.trim_end_matches('\\');
        if [
            "\\windows",
            "\\system32",
            "\\syswow64",
            "\\program files",
            "\\program files (x86)",
            "\\programdata",
            "\\appdata\\roaming",
            "\\appdata\\local",
            "\\appdata\\local\\programs",
        ]
        .iter()
        .any(|s| t.ends_with(s))
        {
            return true;
        }

        let is_direct_user_shared_rel = |rel: &str| {
            matches!(
                rel,
                "desktop"
                    | "downloads"
                    | "documents"
                    | "onedrive"
                    | "onedrive\\desktop"
                    | "onedrive\\downloads"
                    | "onedrive\\documents"
            )
        };
        if let Some(home) = user_home {
            let home_key = norm_path_key(home);
            if !home_key.is_empty() {
                if t == home_key {
                    return true;
                }
                if let Some(rel) = t
                    .strip_prefix(&home_key)
                    .and_then(|rest| rest.strip_prefix('\\'))
                {
                    if is_direct_user_shared_rel(rel) {
                        return true;
                    }
                }
            }
        }

        // Also match standard `<drive>:\users\<name>` roots and their direct shared folders
        // (case-insensitive because `norm_path_key` lowercases Windows paths).
        let parts: Vec<&str> = t.split('\\').collect();
        if parts.len() >= 2 && parts[1] == "users" {
            if parts.len() == 2 || (parts.len() == 3 && !parts[2].is_empty()) {
                return true;
            }
            if parts.len() == 4
                && !parts[2].is_empty()
                && matches!(parts[3], "desktop" | "downloads" | "documents" | "onedrive")
            {
                return true;
            }
            if parts.len() == 5
                && !parts[2].is_empty()
                && parts[3] == "onedrive"
                && matches!(parts[4], "desktop" | "downloads" | "documents")
            {
                return true;
            }
        }
        false
    }
    #[cfg(not(target_os = "windows"))]
    {
        if matches!(
            key.as_str(),
            "/" | "/bin" | "/sbin" | "/usr" | "/usr/bin" | "/usr/local/bin" | "/opt" | "/etc"
        ) {
            return true;
        }
        if let Some(home) = user_home {
            let home_key = norm_path_key(home);
            if !home_key.is_empty() {
                if key == home_key {
                    return true;
                }
                if let Some(rel) = key
                    .strip_prefix(&home_key)
                    .and_then(|rest| rest.strip_prefix('/'))
                {
                    if !rel.contains('/')
                        && (rel.eq_ignore_ascii_case("desktop")
                            || rel.eq_ignore_ascii_case("downloads")
                            || rel.eq_ignore_ascii_case("documents"))
                    {
                        return true;
                    }
                }
            }
        }
        let parts: Vec<&str> = key.split('/').filter(|p| !p.is_empty()).collect();
        if matches!(parts.first().copied(), Some("home" | "Users")) {
            if parts.len() == 1 || parts.len() == 2 {
                return true;
            }
            if parts.len() == 3
                && (parts[2].eq_ignore_ascii_case("desktop")
                    || parts[2].eq_ignore_ascii_case("downloads")
                    || parts[2].eq_ignore_ascii_case("documents"))
            {
                return true;
            }
        }
        false
    }
}

fn collect_related_pids(
    system: &System,
    root_pid: u32,
    exe_dir: Option<&Path>,
    self_pids: &HashSet<u32>,
    self_exe: Option<&Path>,
    self_data_dir: Option<&Path>,
) -> Vec<u32> {
    let mut related = collect_descendant_pids(system, root_pid);
    if let Some(dir) = exe_dir.filter(|d| !is_shared_system_dir(d)) {
        let dir_key = norm_path_key(dir);
        for (pid, p) in system.processes() {
            let u = pid.as_u32();
            let pname = p.name().to_string_lossy();
            if !is_self_process(u, p.exe(), &pname, self_pids, self_exe, self_data_dir)
                && p.exe()
                    .and_then(Path::parent)
                    .is_some_and(|pd| norm_path_key(pd) == dir_key)
            {
                related.insert(u);
            }
        }
    }
    related.retain(|&u| {
        if self_pids.contains(&u) {
            return false;
        }
        system.process(Pid::from_u32(u)).map_or(true, |p| {
            let pname = p.name().to_string_lossy();
            !is_self_process(u, p.exe(), &pname, self_pids, self_exe, self_data_dir)
        })
    });
    let mut out: Vec<u32> = related.into_iter().collect();
    out.sort_unstable();
    out
}

#[cfg(any(target_os = "windows", test))]
type PeNameCacheKey = (String, u64, u128);

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Default)]
struct PeNameCache {
    entries: HashMap<PeNameCacheKey, Option<String>>,
    order: VecDeque<PeNameCacheKey>,
}

#[cfg(any(target_os = "windows", test))]
impl PeNameCache {
    fn get(&self, key: &PeNameCacheKey) -> Option<Option<String>> {
        self.entries.get(key).cloned()
    }

    fn insert(&mut self, key: PeNameCacheKey, value: Option<String>) {
        if self.entries.contains_key(&key) {
            self.entries.insert(key, value);
            return;
        }
        while self.entries.len() >= MAX_PE_NAME_CACHE_ENTRIES {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            } else {
                break;
            }
        }
        self.order.push_back(key.clone());
        self.entries.insert(key, value);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Returns `true` when `raw` is empty, a blank/loopback URL, or solely composed of generic
/// cross-platform runtime/shell/placeholder tokens (e.g., `Electron`, `Tauri`, `WebView2`,
/// `FlClash`, `MainWindow`, `Untitled`, `about:blank`, `localhost`, `127.0.0.1`).
pub fn is_generic_shell_or_runtime_title(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    if GENERIC_SHELL_OR_RUNTIME_TITLES.contains(&lower.as_str()) {
        return true;
    }
    if lower.starts_with("about:")
        || lower.starts_with("file://")
        || lower.starts_with("http://localhost")
        || lower.starts_with("https://localhost")
        || lower.starts_with("http://127.0.0.1")
        || lower.starts_with("https://127.0.0.1")
        || lower.starts_with("localhost:")
        || lower.starts_with("127.0.0.1:")
    {
        return true;
    }

    // Check normalized whitespace/punctuation-separated tokens (keeping `sing-box` intact).
    let collapsed = lower.replace("sing-box", "singbox");
    let tokens: Vec<&str> = collapsed
        .split(|c: char| !c.is_alphanumeric() && c != '.' && c != ':')
        .filter(|tok| !tok.is_empty())
        .collect();
    if tokens.is_empty() {
        return true;
    }
    tokens.iter().all(|tok| {
        GENERIC_SHELL_OR_RUNTIME_TITLES.contains(tok)
            || tok
                .strip_prefix('v')
                .unwrap_or(tok)
                .chars()
                .all(|c| c.is_ascii_digit() || c == '.')
    })
}

#[cfg(any(target_os = "windows", test))]
fn select_best_pe_name_from_pairs(pairs: &[(Option<String>, Option<String>)]) -> Option<String> {
    let mut non_generic_product: Option<String> = None;
    let mut fallback_any: Option<String> = None;

    for (desc, prod) in pairs {
        if let Some(d) = desc.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            if !is_generic_shell_or_runtime_title(d) {
                return Some(d.to_string());
            }
            if fallback_any.is_none() {
                fallback_any = Some(d.to_string());
            }
        }
        if let Some(p) = prod.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            if !is_generic_shell_or_runtime_title(p) && non_generic_product.is_none() {
                non_generic_product = Some(p.to_string());
            }
            if fallback_any.is_none() {
                fallback_any = Some(p.to_string());
            }
        }
    }

    non_generic_product.or(fallback_any)
}

#[cfg(target_os = "windows")]
fn pe_name_cache() -> &'static Mutex<PeNameCache> {
    static CACHE: OnceLock<Mutex<PeNameCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(PeNameCache::default()))
}

#[cfg(target_os = "windows")]
fn encode_wide_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
fn query_pe_version_string(buf: &[u8], subblock: &str) -> Option<String> {
    use windows_sys::Win32::Storage::FileSystem::VerQueryValueW;

    let sub_w = encode_wide_nul(subblock);
    let mut val_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
    let mut val_len: u32 = 0;

    // SAFETY: `buf` is a version-info resource block populated by `GetFileVersionInfoW`;
    // `sub_w` is NUL-terminated UTF-16. Returned pointer and length are bounds-checked below.
    let ok = unsafe {
        VerQueryValueW(
            buf.as_ptr().cast(),
            sub_w.as_ptr(),
            &mut val_ptr,
            &mut val_len,
        )
    };
    if ok == 0 || val_ptr.is_null() || val_len == 0 {
        return None;
    }

    let base = buf.as_ptr() as usize;
    let end = base.saturating_add(buf.len());
    let ptr_addr = val_ptr as usize;
    if ptr_addr < base || ptr_addr >= end {
        return None;
    }
    let avail_u16 = (end - ptr_addr) / 2;
    let count = (val_len as usize).min(avail_u16);
    if count == 0 {
        return None;
    }

    let mut units = Vec::with_capacity(count);
    let u16_ptr = val_ptr as *const u16;
    for idx in 0..count {
        // SAFETY: `ptr_addr + (idx + 1) * 2 <= end`, verified above; `read_unaligned` tolerates any alignment.
        let unit = unsafe { std::ptr::read_unaligned(u16_ptr.add(idx)) };
        if unit == 0 {
            break;
        }
        units.push(unit);
    }

    let decoded = String::from_utf16_lossy(&units);
    let cleaned: String = decoded.chars().filter(|c| !c.is_control()).collect();
    let trimmed = cleaned.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

#[cfg(target_os = "windows")]
fn read_pe_translation_pairs(buf: &[u8]) -> Vec<(u16, u16)> {
    use windows_sys::Win32::Storage::FileSystem::VerQueryValueW;

    let mut pairs: Vec<(u16, u16)> = Vec::new();
    let sub_w = encode_wide_nul("\\VarFileInfo\\Translation");
    let mut ptr: *mut core::ffi::c_void = std::ptr::null_mut();
    let mut byte_len: u32 = 0;

    // SAFETY: `buf` is a version-info resource block populated by `GetFileVersionInfoW`;
    // pointer and byte length are validated against `buf` bounds before reading.
    let ok = unsafe {
        VerQueryValueW(
            buf.as_ptr().cast(),
            sub_w.as_ptr(),
            &mut ptr,
            &mut byte_len,
        )
    };
    if ok != 0 && !ptr.is_null() && byte_len >= 4 {
        let base = buf.as_ptr() as usize;
        let end = base.saturating_add(buf.len());
        let ptr_addr = ptr as usize;
        if ptr_addr >= base && ptr_addr < end {
            let avail_bytes = (end - ptr_addr).min(byte_len as usize);
            let pair_count = (avail_bytes / 4).min(32);
            let raw_u16 = ptr as *const u16;
            for idx in 0..pair_count {
                // SAFETY: `(idx + 1) * 4 <= avail_bytes <= end - ptr_addr`.
                let lang = unsafe { std::ptr::read_unaligned(raw_u16.add(idx * 2)) };
                let cp = unsafe { std::ptr::read_unaligned(raw_u16.add(idx * 2 + 1)) };
                if !pairs.contains(&(lang, cp)) {
                    pairs.push((lang, cp));
                }
            }
        }
    }

    for fallback in [
        (0x0804u16, 0x04B0u16),
        (0x0409u16, 0x04B0u16),
        (0x0409u16, 0x04E4u16),
        (0x0000u16, 0x04B0u16),
    ] {
        if !pairs.contains(&fallback) {
            pairs.push(fallback);
        }
    }
    pairs
}

/// Extract a human-friendly application name (`FileDescription` / `ProductName`) from a Windows
/// PE executable's `VS_VERSION_INFO` resource block, using dynamic `\VarFileInfo\Translation`
/// discovery with common locale fallbacks and a bounded 128-entry `(path, len, mtime_ms)` cache.
///
/// The 4 MiB anti-malformed guard applies strictly to the version-info buffer size returned by
/// `GetFileVersionInfoSizeW`, never to the `.exe` file size itself.
#[cfg(target_os = "windows")]
pub fn extract_pe_app_friendly_name(exe_path: &Path) -> Option<String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW};

    let meta = std::fs::metadata(exe_path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let file_len = meta.len();
    let mtime_ms = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_millis());
    let cache_key: PeNameCacheKey = (norm_path_key(exe_path), file_len, mtime_ms);

    if let Ok(guard) = pe_name_cache().lock() {
        if let Some(cached) = guard.get(&cache_key) {
            return cached;
        }
    }

    let path_w: Vec<u16> = exe_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut handle: u32 = 0;
    // SAFETY: `path_w` is a valid NUL-terminated UTF-16 path string.
    let ver_size = unsafe { GetFileVersionInfoSizeW(path_w.as_ptr(), &mut handle) };
    let extracted = if ver_size == 0 || (ver_size as usize) > MAX_PE_VERSION_INFO_BYTES {
        None
    } else {
        let mut buf = vec![0u8; ver_size as usize];
        // SAFETY: `buf` is allocated with `ver_size` bytes matching `dwlen`.
        let ok = unsafe {
            GetFileVersionInfoW(
                path_w.as_ptr(),
                handle,
                ver_size,
                buf.as_mut_ptr().cast(),
            )
        };
        if ok == 0 {
            None
        } else {
            let pairs = read_pe_translation_pairs(&buf);
            let mut candidates: Vec<(Option<String>, Option<String>)> =
                Vec::with_capacity(pairs.len());
            for (lang, cp) in pairs {
                let desc = query_pe_version_string(
                    &buf,
                    &format!("\\StringFileInfo\\{lang:04X}{cp:04X}\\FileDescription"),
                );
                let prod = query_pe_version_string(
                    &buf,
                    &format!("\\StringFileInfo\\{lang:04X}{cp:04X}\\ProductName"),
                );
                if desc.is_some() || prod.is_some() {
                    candidates.push((desc, prod));
                }
            }
            select_best_pe_name_from_pairs(&candidates)
        }
    };

    if let Ok(mut guard) = pe_name_cache().lock() {
        guard.insert(cache_key, extracted.clone());
    }
    extracted
}

fn lookup_pe_app_friendly_name(exe_path: Option<&Path>) -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        exe_path.and_then(extract_pe_app_friendly_name)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = exe_path;
        None
    }
}

fn strip_exe_stem(process_name: &str) -> &str {
    process_name
        .strip_suffix(".exe")
        .or_else(|| process_name.strip_suffix(".EXE"))
        .unwrap_or(process_name)
        .trim()
}

fn derive_friendly_name(window_title: &str, process_name: &str) -> String {
    let trimmed = window_title.trim();
    if !trimmed.is_empty() {
        return trimmed.to_string();
    }
    let stem = strip_exe_stem(process_name);
    if stem.is_empty() {
        process_name.to_string()
    } else {
        stem.to_string()
    }
}

/// Derive a user-facing application display name preferring a non-generic PE `FileDescription` /
/// `ProductName` whenever `window_title` is empty or matches a generic shell/runtime title.
fn derive_friendly_name_with_pe(
    window_title: &str,
    process_name: &str,
    pe_name: Option<&str>,
) -> String {
    let title = window_title.trim();
    let pe = pe_name.map(str::trim).filter(|s| !s.is_empty());
    let pe_non_generic = pe.filter(|p| !is_generic_shell_or_runtime_title(p));

    if title.is_empty() {
        if let Some(p) = pe_non_generic {
            return p.to_string();
        }
        let stem = strip_exe_stem(process_name);
        if !stem.is_empty() && !is_generic_shell_or_runtime_title(stem) {
            return stem.to_string();
        }
        if let Some(p) = pe {
            return p.to_string();
        }
        return derive_friendly_name("", process_name);
    }

    if is_generic_shell_or_runtime_title(title) {
        if let Some(p) = pe_non_generic {
            return p.to_string();
        }
    }

    title.to_string()
}

#[cfg(any(target_os = "windows", test))]
fn format_tray_background_labels(base_name: &str, ports: &[u16]) -> (String, String) {
    let friendly = format!("{base_name}（托盘/后台运行中）");
    let title = if ports.is_empty() {
        friendly.clone()
    } else {
        let preview: Vec<String> = ports.iter().take(2).map(ToString::to_string).collect();
        let suffix = if ports.len() > 2 { " 等" } else { "" };
        format!(
            "{base_name}（托盘/后台运行中 · 端口 {}{suffix}）",
            preview.join("/")
        )
    };
    (friendly, title)
}

/// Filter out kernel/system PIDs (`<= 4`), privileged ports (`< 1024`), and well-known
/// database or OS service listener ports when identifying background proxy candidates.
#[cfg(any(target_os = "windows", test))]
fn is_eligible_proxy_listener(pid: u32, port: u16) -> bool {
    pid > 4 && port >= 1024 && !KNOWN_EXCLUDED_LISTENER_PORTS.contains(&port)
}

/// Pure eligibility gate for promoting a windowless tray/background process into Step 1.
#[cfg(any(target_os = "windows", test))]
fn is_tray_background_proxy_eligible(
    pid: u32,
    has_loopback_listener: bool,
    has_proxy_hint: bool,
    already_covered: bool,
    is_system_or_self: bool,
) -> bool {
    pid > 4 && !already_covered && !is_system_or_self && (has_loopback_listener || has_proxy_hint)
}

/// Pure gate ensuring pre-existing target/related PIDs never trigger Step 2 on initial startup.
fn should_trigger_process_activity(
    pid: u32,
    target_pid: u32,
    initial_pids: &HashSet<u32>,
    seen_pids: &mut HashSet<u32>,
) -> bool {
    seen_pids.insert(pid) && pid != target_pid && !initial_pids.contains(&pid)
}

fn matches_generic_proxy_keyword(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    GENERIC_PROXY_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

fn check_group_likely_proxy(
    system: &System,
    related_pids: &[u32],
    friendly_name: &str,
    window_title: &str,
    pe_name: Option<&str>,
) -> bool {
    if matches_generic_proxy_keyword(friendly_name)
        || matches_generic_proxy_keyword(window_title)
        || pe_name.is_some_and(matches_generic_proxy_keyword)
    {
        return true;
    }
    related_pids.iter().any(|&pid| {
        system.process(Pid::from_u32(pid)).is_some_and(|p| {
            let pname = p.name().to_string_lossy().into_owned();
            if matches_generic_proxy_keyword(&pname) {
                return true;
            }
            if p.exe()
                .is_some_and(|e| matches_generic_proxy_keyword(&e.to_string_lossy()))
            {
                return true;
            }
            let cmd = p
                .cmd()
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            parse_process_cmdline(pid, pname, p.exe().map(Path::to_path_buf), cmd)
                .likely_proxy_client
        })
    })
}

#[allow(clippy::too_many_arguments)]
fn build_desktop_candidate(
    system: &System,
    pid: u32,
    proc_info: &sysinfo::Process,
    window_title: String,
    process_name: String,
    self_pids: &HashSet<u32>,
    self_exe: Option<&Path>,
    self_data_dir: Option<&Path>,
    baseline_pids: Option<&HashSet<u32>>,
) -> DesktopAppCandidate {
    let related_pids = collect_related_pids(
        system,
        pid,
        proc_info.exe().and_then(Path::parent),
        self_pids,
        self_exe,
        self_data_dir,
    );
    let pe_name = lookup_pe_app_friendly_name(proc_info.exe());
    let friendly_name =
        derive_friendly_name_with_pe(&window_title, &process_name, pe_name.as_deref());
    let likely_proxy_client = check_group_likely_proxy(
        system,
        &related_pids,
        &friendly_name,
        &window_title,
        pe_name.as_deref(),
    );
    let display_title = if window_title.trim().is_empty() {
        friendly_name.clone()
    } else {
        window_title
    };
    DesktopAppCandidate {
        pid,
        window_title: display_title,
        friendly_name,
        process_name,
        exe_path: proc_info
            .exe()
            .map(|p| normalize_os_path(p).to_string_lossy().into_owned()),
        working_dir: proc_info
            .cwd()
            .map(|p| normalize_os_path(p).to_string_lossy().into_owned()),
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
        let title = String::from_utf16_lossy(&buf[..(len as usize).min(buf.len())])
            .trim()
            .to_string();
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
    unsafe {
        EnumWindows(
            Some(enum_visible_windows_proc),
            (&mut raw as *mut Vec<(u32, String)>) as LPARAM,
        )
    };
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

#[cfg(target_os = "windows")]
fn fetch_extended_tcp_table_bytes(family: u32) -> Option<(Vec<u64>, usize)> {
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, TCP_TABLE_OWNER_PID_LISTENER,
    };

    let mut size: u32 = 16 * 1024;
    let mut aligned_buf: Vec<u64> = Vec::new();

    for _ in 0..4 {
        let alloc_bytes = (size as usize).max(4096);
        aligned_buf.resize(alloc_bytes.div_ceil(8), 0u64);
        let mut buf_size =
            u32::try_from(aligned_buf.len().saturating_mul(8)).unwrap_or(u32::MAX);

        // SAFETY: `aligned_buf` is 8-byte aligned and holds at least `buf_size` bytes.
        let status = unsafe {
            GetExtendedTcpTable(
                aligned_buf.as_mut_ptr().cast(),
                &mut buf_size,
                0,
                family,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        if status == NO_ERROR {
            let valid_bytes = aligned_buf
                .len()
                .saturating_mul(8)
                .min(buf_size as usize);
            return Some((aligned_buf, valid_bytes));
        }
        if status == ERROR_INSUFFICIENT_BUFFER {
            size = buf_size.saturating_add(4096);
            continue;
        }
        return None;
    }

    None
}

#[cfg(target_os = "windows")]
fn collect_loopback_listener_pids() -> HashMap<u32, Vec<u16>> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID,
        MIB_TCPTABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    let mut by_pid: HashMap<u32, Vec<u16>> = HashMap::new();
    let mut record = |pid: u32, port: u16| {
        if is_eligible_proxy_listener(pid, port) {
            let entry = by_pid.entry(pid).or_default();
            if !entry.contains(&port) {
                entry.push(port);
            }
        }
    };

    // 1. IPv4 loopback / wildcard listeners (127.0.0.0/8 or 0.0.0.0)
    if let Some((buf, total_bytes)) = fetch_extended_tcp_table_bytes(u32::from(AF_INET)) {
        if total_bytes >= std::mem::size_of::<u32>() {
            let base_ptr = buf.as_ptr().cast::<u8>();
            // SAFETY: `total_bytes >= size_of::<u32>()` checked above; `dwNumEntries` is at offset 0.
            let num_entries = unsafe { std::ptr::read_unaligned(base_ptr.cast::<u32>()) } as usize;
            let table_offset = std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table);
            let row_size = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();

            for idx in 0..num_entries {
                let Some(end_offset) =
                    table_offset.checked_add(idx.saturating_add(1).saturating_mul(row_size))
                else {
                    break;
                };
                if end_offset > total_bytes {
                    break;
                }
                // SAFETY: Bounds checked above; `MIB_TCPROW_OWNER_PID` is `Copy` and `repr(C)`.
                let row = unsafe {
                    std::ptr::read_unaligned(
                        base_ptr
                            .add(table_offset + idx * row_size)
                            .cast::<MIB_TCPROW_OWNER_PID>(),
                    )
                };
                let local_ip = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
                if !local_ip.is_loopback() && !local_ip.is_unspecified() {
                    continue;
                }
                let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
                record(row.dwOwningPid, local_port);
            }
        }
    }

    // 2. IPv6 loopback / wildcard listeners (::1 or ::)
    if let Some((buf, total_bytes)) = fetch_extended_tcp_table_bytes(u32::from(AF_INET6)) {
        if total_bytes >= std::mem::size_of::<u32>() {
            let base_ptr = buf.as_ptr().cast::<u8>();
            // SAFETY: `total_bytes >= size_of::<u32>()` checked above; `dwNumEntries` is at offset 0.
            let num_entries = unsafe { std::ptr::read_unaligned(base_ptr.cast::<u32>()) } as usize;
            let table_offset = std::mem::offset_of!(MIB_TCP6TABLE_OWNER_PID, table);
            let row_size = std::mem::size_of::<MIB_TCP6ROW_OWNER_PID>();

            for idx in 0..num_entries {
                let Some(end_offset) =
                    table_offset.checked_add(idx.saturating_add(1).saturating_mul(row_size))
                else {
                    break;
                };
                if end_offset > total_bytes {
                    break;
                }
                // SAFETY: Bounds checked above; `MIB_TCP6ROW_OWNER_PID` is `Copy` and `repr(C)`.
                let row = unsafe {
                    std::ptr::read_unaligned(
                        base_ptr
                            .add(table_offset + idx * row_size)
                            .cast::<MIB_TCP6ROW_OWNER_PID>(),
                    )
                };
                let local_ip = Ipv6Addr::from(row.ucLocalAddr);
                if !local_ip.is_loopback() && !local_ip.is_unspecified() {
                    continue;
                }
                let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
                record(row.dwOwningPid, local_port);
            }
        }
    }

    for ports in by_pid.values_mut() {
        ports.sort_unstable();
    }
    by_pid
}

#[cfg(target_os = "windows")]
fn is_windows_system_background_process(pname_lower: &str, exe: Option<&Path>) -> bool {
    if WINDOWS_SHELL_PROCESSES.contains(&pname_lower)
        || WINDOWS_BACKGROUND_SYSTEM_PROCESSES.contains(&pname_lower)
    {
        return true;
    }
    if let Some(e) = exe {
        let key = norm_path_key(e);
        if key.contains("\\windows\\system32\\")
            || key.contains("\\windows\\syswow64\\")
            || key.contains("\\windows\\systemapps\\")
            || key.contains("\\windows\\immersivecontrolpanel\\")
        {
            return true;
        }
    }
    false
}

/// Enumerate visible desktop application candidates (plus Windows tray/background proxy processes
/// holding loopback listener ports or matching proxy keywords), excluding CatCloud itself,
/// its process tree, its data directory, and OS shell/system hosts.
pub fn list_desktop_app_candidates(
    baseline_pids: Option<&HashSet<u32>>,
    self_data_dir: Option<&Path>,
) -> Vec<DesktopAppCandidate> {
    let system = snapshot_processes();
    let self_pids = collect_self_pid_tree(&system);
    let self_exe = std::env::current_exe().ok();
    let mut candidates = Vec::new();

    #[cfg(target_os = "windows")]
    {
        let mut covered_pids: HashSet<u32> = HashSet::new();
        let mut covered_dirs: HashSet<String> = HashSet::new();
        for (pid, title) in collect_visible_windows_by_pid() {
            let Some(p) = system.process(Pid::from_u32(pid)) else {
                continue;
            };
            let pname = p.name().to_string_lossy().into_owned();
            if WINDOWS_SHELL_PROCESSES.contains(&pname.to_ascii_lowercase().as_str())
                || title.to_ascii_lowercase().contains("catcloud")
                || title.contains("猫猫云梯")
                || is_self_process(
                    pid,
                    p.exe(),
                    &pname,
                    &self_pids,
                    self_exe.as_deref(),
                    self_data_dir,
                )
            {
                continue;
            }
            let cand = build_desktop_candidate(
                &system,
                pid,
                p,
                title,
                pname,
                &self_pids,
                self_exe.as_deref(),
                self_data_dir,
                baseline_pids,
            );
            covered_pids.insert(cand.pid);
            covered_pids.extend(cand.related_pids.iter().copied());
            if let Some(dir) = p
                .exe()
                .and_then(Path::parent)
                .filter(|d| !is_shared_system_dir(d))
            {
                covered_dirs.insert(norm_path_key(dir));
            }
            candidates.push(cand);
        }

        // Supplement tray-minimized / background proxy processes that have no visible top-level window.
        let loopback_listeners = collect_loopback_listener_pids();
        let mut bg_eligible: Vec<(bool, bool, u32)> = Vec::new();
        for (pid_val, p) in system.processes() {
            let pid = pid_val.as_u32();
            let exe_dir_key = p
                .exe()
                .and_then(Path::parent)
                .filter(|d| !is_shared_system_dir(d))
                .map(norm_path_key);
            let already_covered = covered_pids.contains(&pid)
                || exe_dir_key
                    .as_ref()
                    .is_some_and(|k| covered_dirs.contains(k));
            let pname = p.name().to_string_lossy().into_owned();
            let plower = pname.to_ascii_lowercase();
            let is_system_or_self = pname.trim().is_empty()
                || is_windows_system_background_process(&plower, p.exe())
                || is_self_process(
                    pid,
                    p.exe(),
                    &pname,
                    &self_pids,
                    self_exe.as_deref(),
                    self_data_dir,
                );
            if already_covered || is_system_or_self || pid <= 4 {
                continue;
            }
            let has_loopback = loopback_listeners.contains_key(&pid);
            let cmd: Vec<String> = p
                .cmd()
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            let has_proxy_hint = matches_generic_proxy_keyword(&pname)
                || p.exe()
                    .is_some_and(|e| matches_generic_proxy_keyword(&e.to_string_lossy()))
                || parse_process_cmdline(pid, pname, p.exe().map(Path::to_path_buf), cmd)
                    .likely_proxy_client;
            if is_tray_background_proxy_eligible(
                pid,
                has_loopback,
                has_proxy_hint,
                already_covered,
                is_system_or_self,
            ) {
                // Prefer processes whose parent is not another process in the same non-system dir
                // so a multi-process tray app collapses cleanly to its main/root process.
                let is_root_in_dir = p.parent().map_or(true, |parent_pid| {
                    let Some(parent_proc) = system.process(parent_pid) else {
                        return true;
                    };
                    match (
                        p.exe().and_then(Path::parent),
                        parent_proc.exe().and_then(Path::parent),
                    ) {
                        (Some(d1), Some(d2)) if !is_shared_system_dir(d1) => {
                            norm_path_key(d1) != norm_path_key(d2)
                        }
                        _ => true,
                    }
                });
                bg_eligible.push((is_root_in_dir, has_proxy_hint, pid));
            }
        }
        bg_eligible.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)).then_with(|| a.2.cmp(&b.2)));

        for (_, _, pid) in bg_eligible {
            if covered_pids.contains(&pid) {
                continue;
            }
            let Some(p) = system.process(Pid::from_u32(pid)) else {
                continue;
            };
            let exe_dir_key = p
                .exe()
                .and_then(Path::parent)
                .filter(|d| !is_shared_system_dir(d))
                .map(norm_path_key);
            if exe_dir_key
                .as_ref()
                .is_some_and(|k| covered_dirs.contains(k))
            {
                continue;
            }
            let pname = p.name().to_string_lossy().into_owned();
            let related_pids = collect_related_pids(
                &system,
                pid,
                p.exe().and_then(Path::parent),
                &self_pids,
                self_exe.as_deref(),
                self_data_dir,
            );
            let mut ports: Vec<u16> = Vec::new();
            for &rpid in &related_pids {
                if let Some(p_list) = loopback_listeners.get(&rpid) {
                    for &port in p_list {
                        if !ports.contains(&port) {
                            ports.push(port);
                        }
                    }
                }
            }
            ports.sort_unstable();

            let pe_name = lookup_pe_app_friendly_name(p.exe());
            let base_name = derive_friendly_name_with_pe("", &pname, pe_name.as_deref());
            let (friendly_name, window_title) = format_tray_background_labels(&base_name, &ports);
            let cand = DesktopAppCandidate {
                pid,
                window_title,
                friendly_name,
                process_name: pname,
                exe_path: p
                    .exe()
                    .map(|e| normalize_os_path(e).to_string_lossy().into_owned()),
                working_dir: p
                    .cwd()
                    .map(|c| normalize_os_path(c).to_string_lossy().into_owned()),
                related_pids,
                is_newly_opened: baseline_pids.is_some_and(|base| !base.contains(&pid)),
                likely_proxy_client: true,
            };
            covered_pids.insert(cand.pid);
            covered_pids.extend(cand.related_pids.iter().copied());
            if let Some(k) = exe_dir_key {
                covered_dirs.insert(k);
            }
            candidates.push(cand);
        }
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
            || is_self_process(
                pid,
                p.exe(),
                &pname,
                &self_pids,
                self_exe.as_deref(),
                self_data_dir,
            )
        {
            continue;
        }
        candidates.push(build_desktop_candidate(
            &system,
            pid,
            p,
            String::new(),
            pname,
            &self_pids,
            self_exe.as_deref(),
            self_data_dir,
            baseline_pids,
        ));
    }

    candidates.sort_by(|a, b| {
        b.is_newly_opened
            .cmp(&a.is_newly_opened)
            .then_with(|| b.likely_proxy_client.cmp(&a.likely_proxy_client))
            .then_with(|| {
                a.friendly_name
                    .to_ascii_lowercase()
                    .cmp(&b.friendly_name.to_ascii_lowercase())
            })
            .then_with(|| a.pid.cmp(&b.pid))
    });
    candidates
}

#[derive(Debug)]
struct SessionState {
    session_id: String,
    active: bool,
    timed_out: bool,
    step_app_ready: bool,
    step_activity_seen: bool,
    step_nodes_ready: bool,
    started_at: Instant,
    frozen_elapsed_sec: Option<u64>,
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
        if self
            .events
            .last()
            .is_some_and(|e| e.kind == kind && e.message == message)
        {
            return;
        }
        if self.events.len() >= MAX_EVENTS_RETAINED {
            self.events.remove(0);
        }
        self.events.push(LiveCaptureEventItem {
            timestamp_ms: ts,
            kind: kind.to_string(),
            message,
        });
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
            let key = (
                node.protocol.to_ascii_lowercase(),
                node.server.to_ascii_lowercase(),
                node.port,
                node.name.clone(),
            );
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
        let unsupported_reason = (self.captured_nodes.is_empty()
            && (self.opaque_change_detected || !self.active))
            .then(|| CAPTURE_UNSUPPORTED_REASON.to_string());
        LiveCaptureStatusDto {
            session_id: self.session_id.clone(),
            active: self.active,
            timed_out: self.timed_out,
            step_app_ready: self.step_app_ready,
            step_activity_seen: self.step_activity_seen,
            step_nodes_ready: self.step_nodes_ready,
            elapsed_sec: self
                .frozen_elapsed_sec
                .unwrap_or_else(|| self.started_at.elapsed().as_secs()),
            captured_node_count: self.captured_nodes.len(),
            opaque_change_detected: self.opaque_change_detected,
            target_name: self.target_name.clone(),
            watch_dirs: self
                .watch_dirs
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect(),
            events: self.events.clone(),
            preview_nodes: self
                .captured_nodes
                .iter()
                .take(MAX_PREVIEW_NODES)
                .cloned()
                .collect(),
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
            if g.frozen_elapsed_sec.is_none() {
                g.frozen_elapsed_sec = Some(g.started_at.elapsed().as_secs());
            }
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
        let sid = self
            .active
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|s| s.session_id.clone()));
        f.debug_struct("LiveCaptureManager")
            .field("active_session_id", &sid)
            .finish()
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
        let self_exe = std::env::current_exe().ok();
        if self_pids.contains(&target_pid) {
            return Err(CatError::Validation(
                "不能选择猫猫云梯自身进程进行抓取".to_string(),
            ));
        }
        let Some(p) = system.process(Pid::from_u32(target_pid)) else {
            return Err(CatError::NotFound(format!(
                "未找到运行中的目标进程 PID {target_pid}"
            )));
        };
        let proc_name = p.name().to_string_lossy().into_owned();
        if is_self_process(
            target_pid,
            p.exe(),
            &proc_name,
            &self_pids,
            self_exe.as_deref(),
            self_data_dir.as_deref(),
        ) {
            return Err(CatError::Validation(
                "不能选择猫猫云梯自身进程进行抓取".to_string(),
            ));
        }
        let target_exe_dir = p.exe().and_then(Path::parent).map(normalize_os_path);
        #[cfg(target_os = "windows")]
        let window_title = collect_visible_windows_by_pid()
            .remove(&target_pid)
            .unwrap_or_default();
        #[cfg(not(target_os = "windows"))]
        let window_title = String::new();
        let pe_name = lookup_pe_app_friendly_name(p.exe());
        let target_name =
            derive_friendly_name_with_pe(&window_title, &proc_name, pe_name.as_deref());
        let related = collect_related_pids(
            &system,
            target_pid,
            target_exe_dir.as_deref(),
            &self_pids,
            self_exe.as_deref(),
            self_data_dir.as_deref(),
        );
        let mut initial_pids: HashSet<u32> = related.iter().copied().collect();
        initial_pids.insert(target_pid);
        let watch_dirs = collect_initial_watch_dirs(
            &system,
            &related,
            &proc_name,
            &target_name,
            self_data_dir.as_deref(),
        );
        self.start_session_inner(
            target_pid,
            target_name,
            target_exe_dir,
            watch_dirs,
            self_data_dir,
            initial_pids,
            DEFAULT_POLL_INTERVAL,
            DEFAULT_MAX_SESSION_DURATION,
            true,
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
        initial_pids: HashSet<u32>,
        poll_interval: Duration,
        max_duration: Duration,
        scan_system_temp: bool,
    ) -> CatResult<LiveCaptureStartDto> {
        let _op = self.op_lock.lock().unwrap_or_else(|e| e.into_inner());
        let prev = self
            .active
            .lock()
            .map_err(|_| CatError::Process("捕捉状态锁异常".into()))?
            .take();
        if let Some(mut old) = prev {
            old.stop_and_join();
        }
        let session_id = format!("cap-{}", Uuid::new_v4());
        let stop_flag = Arc::new(AtomicBool::new(false));
        let mut init_state = SessionState {
            session_id: session_id.clone(),
            active: true,
            timed_out: false,
            step_app_ready: true,
            step_activity_seen: false,
            step_nodes_ready: false,
            started_at: Instant::now(),
            frozen_elapsed_sec: None,
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
        init_state.push_event(
            "ready",
            format!("已锁定目标软件「{target_name}」，开始监听配置变更"),
        );
        let state = Arc::new(Mutex::new(init_state));
        let (w_stop, w_state, w_dirs) = (
            Arc::clone(&stop_flag),
            Arc::clone(&state),
            watch_dirs.clone(),
        );
        let worker = std::thread::Builder::new()
            .name(format!("cap-{}", &session_id[4..12]))
            .spawn(move || {
                run_capture_loop(
                    target_pid,
                    target_exe_dir,
                    w_dirs,
                    self_data_dir,
                    initial_pids,
                    poll_interval,
                    max_duration,
                    scan_system_temp,
                    w_stop,
                    w_state,
                );
            })
            .map_err(|e| CatError::Process(format!("启动实时捕捉后台线程失败：{e}")))?;

        let dto = LiveCaptureStartDto {
            session_id: session_id.clone(),
            target_pid,
            target_name,
            watch_dirs: watch_dirs
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect(),
        };
        let new_session = ActiveSession {
            session_id,
            stop_flag,
            state,
            worker: Some(worker),
        };
        let replaced = {
            let mut guard = self
                .active
                .lock()
                .map_err(|_| CatError::Process("捕捉状态锁异常".into()))?;
            guard.replace(new_session)
        };
        if let Some(mut stale) = replaced {
            stale.stop_and_join();
        }
        Ok(dto)
    }

    pub fn poll_session(&self, session_id: &str) -> CatResult<LiveCaptureStatusDto> {
        let guard = self
            .active
            .lock()
            .map_err(|_| CatError::Process("捕捉状态锁异常".into()))?;
        let Some(s) = guard.as_ref().filter(|s| s.session_id == session_id) else {
            return Err(CatError::NotFound(format!(
                "实时捕捉会话不存在：{session_id}"
            )));
        };
        let state = s
            .state
            .lock()
            .map_err(|_| CatError::Process("读取捕捉进度失败".into()))?;
        Ok(state.to_status_dto())
    }

    pub fn finish_session(&self, session_id: &str) -> CatResult<LiveCaptureOutcomeDto> {
        let _op = self.op_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut session = {
            let mut guard = self
                .active
                .lock()
                .map_err(|_| CatError::Process("捕捉状态锁异常".into()))?;
            if !guard.as_ref().is_some_and(|s| s.session_id == session_id) {
                return Err(CatError::NotFound(format!(
                    "实时捕捉会话不存在：{session_id}"
                )));
            }
            guard.take().expect("checked above")
        };
        session.stop_and_join();
        let state = session
            .state
            .lock()
            .map_err(|_| CatError::Process("读取捕捉结果失败".into()))?;

        let mut nodes = Vec::with_capacity(state.captured_nodes.len());
        let mut dedup = HashSet::with_capacity(state.captured_nodes.len());
        for node in &state.captured_nodes {
            let key = (
                node.protocol.to_ascii_lowercase(),
                node.server.to_ascii_lowercase(),
                node.port,
                node.name.clone(),
            );
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
        let path_in_temp = state
            .hit_source_path
            .as_deref()
            .is_some_and(is_path_in_temp_dir);
        let vanished = state
            .hit_source_path
            .as_deref()
            .is_some_and(|p| !p.exists());
        let is_ephemeral_source = state.hit_ephemeral || path_in_temp || vanished;
        let source_kind = if path_in_temp || is_ephemeral_source {
            "migrated".to_string()
        } else {
            state
                .hit_source_kind
                .clone()
                .unwrap_or_else(|| "file".to_string())
        };
        Ok(LiveCaptureOutcomeDto {
            session_id: state.session_id.clone(),
            supported: true,
            target_name: state.target_name.clone(),
            source_kind,
            source_path: state
                .hit_source_path
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
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

#[derive(Debug, Clone)]
struct ConfigFileCandidate {
    path: PathBuf,
    preexisting_fallback: bool,
    modified: SystemTime,
}

#[allow(clippy::too_many_arguments)]
fn run_capture_loop(
    target_pid: u32,
    target_exe_dir: Option<PathBuf>,
    mut watch_dirs: Vec<PathBuf>,
    self_data_dir: Option<PathBuf>,
    initial_pids: HashSet<u32>,
    poll_interval: Duration,
    max_duration: Duration,
    scan_system_temp: bool,
    stop_flag: Arc<AtomicBool>,
    state: Arc<Mutex<SessionState>>,
) {
    let started_wall = SystemTime::now()
        .checked_sub(Duration::from_secs(1))
        .unwrap_or(SystemTime::now());
    let started_mono = Instant::now();
    let self_exe = std::env::current_exe().ok();
    let mut system = System::new();
    let mut seen_pids: HashSet<u32> = initial_pids.clone();
    let mut seen_files: HashMap<PathBuf, (u64, u128)> = HashMap::new();
    let mut controller_endpoints: HashMap<String, Option<String>> = HashMap::new();
    let mut discovered_secrets: Vec<String> = Vec::new();
    let mut last_ctrl_probe: HashMap<String, Instant> = HashMap::new();
    let mut warned_meta_only_controllers: HashSet<String> = HashSet::new();
    let mut explicit_files: HashSet<PathBuf> = HashSet::new();
    let temp_root = normalize_os_path(&std::env::temp_dir());

    while !stop_flag.load(Ordering::SeqCst) {
        if started_mono.elapsed() >= max_duration {
            if let Ok(mut g) = state.lock() {
                g.active = false;
                g.timed_out = true;
                if g.frozen_elapsed_sec.is_none() {
                    g.frozen_elapsed_sec = Some(g.started_at.elapsed().as_secs());
                }
                g.push_event(
                    "timeout",
                    "已达 3 分钟捕捉上限并自动暂停监控；若已捕捉到配置可直接点击「整理并查看结果」"
                        .to_string(),
                );
            }
            break;
        }

        // 1. Track target process tree and sibling processes in the same executable directory.
        // Only newly launched processes (`!initial_pids.contains(&pid)`) light up Step 2 activity.
        if target_pid > 0 {
            system.refresh_processes_specifics(ProcessesToUpdate::All, true, process_refresh_kind());
            let self_pids = collect_self_pid_tree(&system);
            for pid in collect_related_pids(
                &system,
                target_pid,
                target_exe_dir.as_deref(),
                &self_pids,
                self_exe.as_deref(),
                self_data_dir.as_deref(),
            ) {
                let Some(p) = system.process(Pid::from_u32(pid)) else {
                    continue;
                };
                let pname = p.name().to_string_lossy().into_owned();
                if should_trigger_process_activity(pid, target_pid, &initial_pids, &mut seen_pids) {
                    if let Ok(mut g) = state.lock() {
                        g.step_activity_seen = true;
                        g.push_event("process", format!("检测到关联进程启动：{pname} (PID {pid})"));
                    }
                }
                let cmd: Vec<String> = p
                    .cmd()
                    .iter()
                    .map(|a| a.to_string_lossy().into_owned())
                    .collect();
                let cmd_secret = extract_controller_secret_from_cmdline(&cmd);
                if let Some(ref sec) = cmd_secret {
                    push_unique_secret(&mut discovered_secrets, sec);
                }
                let parsed = parse_process_cmdline(pid, pname, p.exe().map(Path::to_path_buf), cmd);
                if let Some(d) = parsed.detected_config_dir {
                    push_safe_watch_dir(&mut watch_dirs, &d, self_data_dir.as_deref(), &state);
                }
                if let Some(f) = parsed.detected_config_file {
                    let norm = normalize_os_path(&f);
                    if !self_data_dir
                        .as_deref()
                        .is_some_and(|d| path_starts_with_dir(&norm, d))
                    {
                        if let Some(parent) = norm.parent() {
                            push_safe_watch_dir(
                                &mut watch_dirs,
                                parent,
                                self_data_dir.as_deref(),
                                &state,
                            );
                        }
                        explicit_files.insert(norm);
                    }
                }
                if let Some(ctl) = parsed
                    .detected_controller_addr
                    .as_deref()
                    .and_then(normalize_loopback_controller_base_url)
                {
                    register_controller_endpoint(&mut controller_endpoints, ctl, cmd_secret);
                }
            }
        }

        // 2. Scan watch_dirs (realtime + 7-day plaintext fallback for dedicated app dirs while
        //    no valid nodes have been captured yet) + explicit cmdline files + prioritized temp scan.
        let mut has_captured_nodes = state
            .lock()
            .map(|g| !g.captured_nodes.is_empty())
            .unwrap_or(false);
        let mut raw_candidates: Vec<ConfigFileCandidate> = Vec::new();
        for f in &explicit_files {
            if let Ok(meta) = std::fs::metadata(f) {
                if meta.is_file() {
                    let modified = meta.modified().unwrap_or(UNIX_EPOCH);
                    raw_candidates.push(ConfigFileCandidate {
                        path: f.clone(),
                        preexisting_fallback: modified < started_wall,
                        modified,
                    });
                }
            }
        }
        for dir in &watch_dirs {
            if stop_flag.load(Ordering::Relaxed) {
                break;
            }
            let allow_existing_fallback =
                !has_captured_nodes && !is_path_in_temp_dir(dir) && !is_shared_system_dir(dir);
            collect_recent_config_files(
                dir,
                MAX_WATCH_DEPTH,
                started_wall,
                allow_existing_fallback,
                self_data_dir.as_deref(),
                &stop_flag,
                &mut raw_candidates,
            );
        }
        if scan_system_temp && !stop_flag.load(Ordering::Relaxed) && temp_root.is_dir() {
            collect_recent_temp_config_files(
                &temp_root,
                started_wall,
                self_data_dir.as_deref(),
                &stop_flag,
                &mut raw_candidates,
            );
        }

        // Deduplicate by normalized path key, prioritizing realtime-modified files over fallback ones.
        let mut dedup_map: HashMap<String, ConfigFileCandidate> = HashMap::new();
        for cand in raw_candidates {
            let key = norm_path_key(&cand.path);
            dedup_map
                .entry(key)
                .and_modify(|cur| {
                    if !cand.preexisting_fallback && cur.preexisting_fallback {
                        *cur = cand.clone();
                    } else if cand.modified > cur.modified {
                        cur.modified = cand.modified;
                    }
                })
                .or_insert(cand);
        }
        let mut candidates: Vec<ConfigFileCandidate> = dedup_map.into_values().collect();
        candidates.sort_by(|a, b| {
            a.preexisting_fallback
                .cmp(&b.preexisting_fallback)
                .then_with(|| b.modified.cmp(&a.modified))
        });

        for cand in candidates {
            if stop_flag.load(Ordering::SeqCst) {
                break;
            }
            // Once valid plaintext nodes are captured, skip preexisting historical fallback files
            // so stale historical profiles in the same app folder do not pollute fresh results.
            if cand.preexisting_fallback && has_captured_nodes {
                continue;
            }
            let Ok(meta) = std::fs::metadata(&cand.path) else {
                continue;
            };
            let len = meta.len();
            if len == 0 || len > MAX_SUBSCRIPTION_BYTES as u64 {
                continue;
            }
            let modified = meta.modified().unwrap_or(UNIX_EPOCH);
            let fp = (
                len,
                modified
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0),
            );
            if seen_files.get(&cand.path) == Some(&fp) {
                continue;
            }
            let Some(bytes) = read_file_with_short_retry(&cand.path) else {
                continue;
            };
            seen_files.insert(cand.path.clone(), fp);
            let is_temp = is_path_in_temp_dir(&cand.path);
            let fname = cand
                .path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("配置文件");
            match parse_captured_bytes(
                "live_capture",
                &bytes,
                &mut controller_endpoints,
                &mut discovered_secrets,
            ) {
                CapturedBytesOutcome::Nodes(nodes) => {
                    if let Ok(mut g) = state.lock() {
                        let added = g.merge_nodes(
                            nodes,
                            if is_temp { "migrated" } else { "file" },
                            Some(cand.path.clone()),
                            is_temp,
                        );
                        if !g.captured_nodes.is_empty() {
                            has_captured_nodes = true;
                        }
                        if added > 0 {
                            let msg = if cand.preexisting_fallback {
                                format!("已从现存配置「{fname}」读取到 {added} 个可用节点")
                            } else {
                                format!("已从「{fname}」解析出 {added} 个可用节点")
                            };
                            g.push_event("nodes", msg);
                        }
                    }
                }
                CapturedBytesOutcome::Opaque => {
                    // Only freshly written/modified opaque files count as Step 2 activity;
                    // untouched historical files inside the app folder must never trigger false alarms.
                    if !cand.preexisting_fallback {
                        if let Ok(mut g) = state.lock() {
                            g.step_activity_seen = true;
                            g.opaque_change_detected = true;
                            if g.captured_nodes.is_empty() {
                                g.push_event(
                                    "opaque",
                                    format!("检测到「{fname}」变更，但内容为非明文/受保护格式"),
                                );
                            }
                        }
                    }
                }
                CapturedBytesOutcome::Ignored => {}
            }
        }

        // 3. Probe discovered loopback controller endpoints synchronously (with Bearer secret if known)
        let endpoints_snapshot: Vec<(String, Option<String>)> = controller_endpoints
            .iter()
            .map(|(u, s)| (u.clone(), s.clone()))
            .collect();
        for (base_url, endpoint_secret) in endpoints_snapshot {
            if stop_flag.load(Ordering::SeqCst) {
                break;
            }
            if last_ctrl_probe
                .get(&base_url)
                .is_some_and(|t| t.elapsed() < CONTROLLER_PROBE_COOLDOWN)
            {
                continue;
            }
            last_ctrl_probe.insert(base_url.clone(), Instant::now());

            let fetched_body = probe_loopback_proxies_with_secrets(
                &base_url,
                endpoint_secret.as_deref(),
                &discovered_secrets,
                Duration::from_millis(1200),
                &stop_flag,
            );

            if let Some(body) = fetched_body {
                if let Ok((nodes, meta_only_count, _, _)) =
                    parse_controller_proxies_json("live_capture", &body)
                {
                    if !nodes.is_empty() {
                        if let Ok(mut g) = state.lock() {
                            let added = g.merge_nodes(nodes, "migrated", None, true);
                            if added > 0 {
                                g.push_event(
                                    "nodes",
                                    format!("已从本地控制口捕获 {added} 个可直连节点"),
                                );
                            }
                        }
                    } else if meta_only_count > 0
                        && warned_meta_only_controllers.insert(base_url.clone())
                    {
                        if let Ok(mut g) = state.lock() {
                            g.step_activity_seen = true;
                            if g.captured_nodes.is_empty() {
                                g.push_event(
                                    "controller",
                                    "检测到受控内核运行中但未暴露明文节点地址，继续监听配置文件变动或建议改用订阅链接"
                                        .to_string(),
                                );
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
        if g.frozen_elapsed_sec.is_none() {
            g.frozen_elapsed_sec = Some(g.started_at.elapsed().as_secs());
        }
    }
}

fn push_unique_secret(secrets: &mut Vec<String>, secret: &str) {
    let cleaned = secret.trim();
    if !cleaned.is_empty() && !secrets.iter().any(|s| s == cleaned) && secrets.len() < 8 {
        secrets.push(cleaned.to_string());
    }
}

fn register_controller_endpoint(
    endpoints: &mut HashMap<String, Option<String>>,
    base_url: String,
    secret: Option<String>,
) {
    let clean_secret = secret
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    endpoints
        .entry(base_url)
        .and_modify(|cur| {
            if cur.is_none() && clean_secret.is_some() {
                *cur = clean_secret.clone();
            }
        })
        .or_insert(clean_secret);
}

fn strip_quotes(s: &str) -> &str {
    let trimmed = s.trim();
    if trimmed.len() >= 2
        && ((trimmed.starts_with('"') && trimmed.ends_with('"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\'')))
    {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    }
}

fn extract_controller_secret_from_cmdline(cmdline: &[String]) -> Option<String> {
    let mut idx = 0usize;
    while idx < cmdline.len() {
        let arg = cmdline[idx].trim();
        let next_val = cmdline
            .get(idx + 1)
            .map(|s| s.trim())
            .filter(|s| !s.is_empty());
        if matches!(
            arg,
            "-secret"
                | "--secret"
                | "-ext-ctl-secret"
                | "--ext-ctl-secret"
                | "-external-controller-secret"
                | "--external-controller-secret"
        ) {
            if let Some(v) = next_val {
                let cleaned = strip_quotes(v);
                if !cleaned.is_empty() {
                    return Some(cleaned.to_string());
                }
            }
            idx += 2;
            continue;
        }
        if let Some(v) = arg
            .strip_prefix("-secret=")
            .or_else(|| arg.strip_prefix("--secret="))
            .or_else(|| arg.strip_prefix("-ext-ctl-secret="))
            .or_else(|| arg.strip_prefix("--ext-ctl-secret="))
            .or_else(|| arg.strip_prefix("-external-controller-secret="))
            .or_else(|| arg.strip_prefix("--external-controller-secret="))
        {
            let cleaned = strip_quotes(v);
            if !cleaned.is_empty() {
                return Some(cleaned.to_string());
            }
        }
        idx += 1;
    }
    None
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
        let Some(p) = system.process(Pid::from_u32(pid)) else {
            continue;
        };
        if let Some(exe_dir) = p.exe().and_then(Path::parent) {
            add(exe_dir);
        }
        if let Some(cwd) = p.cwd() {
            add(cwd);
        }
        let cmd = p
            .cmd()
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let parsed = parse_process_cmdline(
            pid,
            p.name().to_string_lossy().into_owned(),
            p.exe().map(Path::to_path_buf),
            cmd,
        );
        if let Some(d) = parsed.detected_config_dir {
            add(&d);
        }
        if let Some(parent) = parsed.detected_config_file.as_deref().and_then(Path::parent) {
            add(parent);
        }
    }

    let tokens = extract_safe_app_tokens(proc_name, target_name);
    if !tokens.is_empty() {
        for base in user_appdata_roots() {
            let Ok(entries) = std::fs::read_dir(&base) else {
                continue;
            };
            for entry in entries.filter_map(Result::ok) {
                let p = entry.path();
                if !p.is_dir() {
                    continue;
                }
                let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                let norm = normalize_alnum(name);
                if norm.len() >= 3
                    && tokens
                        .iter()
                        .any(|t| norm == *t || (t.len() >= 4 && norm.contains(t)))
                {
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
    let mut seen = HashSet::new();
    let mut push_dir = |p: PathBuf| {
        if p.is_dir() {
            let norm = normalize_os_path(&p);
            if seen.insert(norm_path_key(&norm)) {
                roots.push(norm);
            }
        }
    };
    #[cfg(target_os = "windows")]
    {
        for key in ["APPDATA", "LOCALAPPDATA"] {
            if let Ok(v) = std::env::var(key) {
                push_dir(PathBuf::from(v));
            }
        }
        if let Ok(profile) = std::env::var("USERPROFILE") {
            push_dir(PathBuf::from(profile).join(".config"));
        }
    }
    #[cfg(target_os = "macos")]
    if let Ok(home) = std::env::var("HOME") {
        let h = PathBuf::from(home);
        for p in [
            h.join("Library").join("Application Support"),
            h.join(".config"),
        ] {
            push_dir(p);
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    if let Ok(home) = std::env::var("HOME") {
        let h = PathBuf::from(home);
        for rel in [".config", ".local/share"] {
            push_dir(h.join(rel));
        }
    }
    roots
}

fn normalize_alnum(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn extract_safe_app_tokens(proc_name: &str, target_name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let stem = proc_name
        .strip_suffix(".exe")
        .or_else(|| proc_name.strip_suffix(".EXE"))
        .unwrap_or(proc_name);
    for raw in [stem, target_name] {
        let joined = normalize_alnum(raw);
        if joined.len() >= 3
            && !GENERIC_DIR_TOKENS.contains(&joined.as_str())
            && !out.contains(&joined)
        {
            out.push(joined);
        }
        for piece in raw.split(|c: char| !c.is_ascii_alphanumeric()) {
            let tok = piece.to_ascii_lowercase();
            if tok.len() >= 4
                && !GENERIC_DIR_TOKENS.contains(&tok.as_str())
                && !out.contains(&tok)
            {
                out.push(tok);
            }
        }
    }
    out
}

fn collect_recent_config_files(
    root: &Path,
    max_depth: usize,
    started_wall: SystemTime,
    allow_existing_fallback: bool,
    self_data_dir: Option<&Path>,
    stop_flag: &AtomicBool,
    out: &mut Vec<ConfigFileCandidate>,
) {
    let min_mtime = if allow_existing_fallback {
        started_wall
            .checked_sub(EXISTING_CONFIG_FALLBACK_WINDOW)
            .unwrap_or(UNIX_EPOCH)
    } else {
        started_wall
    };

    let mut queue = VecDeque::from([(root.to_path_buf(), 0usize)]);
    let mut visited = 0usize;
    while let Some((dir, depth)) = queue.pop_front() {
        if stop_flag.load(Ordering::Relaxed) || visited >= MAX_SCAN_ENTRIES_PER_ROOT {
            break;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            if stop_flag.load(Ordering::Relaxed) {
                return;
            }
            visited += 1;
            if visited >= MAX_SCAN_ENTRIES_PER_ROOT {
                break;
            }
            let path = entry.path();
            if self_data_dir.is_some_and(|s| path_starts_with_dir(&path, s)) {
                continue;
            }
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_dir() {
                let lower = entry.file_name().to_string_lossy().to_ascii_lowercase();
                if depth < max_depth && !IGNORED_WATCH_DIRS.contains(&lower.as_str()) {
                    queue.push_back((path, depth + 1));
                }
                continue;
            }
            if !ft.is_file() || !is_capture_config_ext(&path) {
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                if meta.len() > 0 && meta.len() <= MAX_SUBSCRIPTION_BYTES as u64 {
                    if let Ok(modified) = meta.modified() {
                        if modified >= min_mtime {
                            let preexisting_fallback = modified < started_wall;
                            if preexisting_fallback && !is_fallback_plaintext_config_ext(&path) {
                                continue;
                            }
                            out.push(ConfigFileCandidate {
                                path: normalize_os_path(&path),
                                preexisting_fallback,
                                modified,
                            });
                        }
                    }
                }
            }
        }
    }
}

/// Prioritized `%TEMP%` scanner: scans top-level entries up to a wide budget first,
/// then prioritizes freshly-modified 1st-level subdirectories (`mtime >= started_wall`, depth 1)
/// plus the most recent warm subdirectories (depth 0) so newly written ephemeral configs
/// are never starved by thousands of stale temporary files.
fn collect_recent_temp_config_files(
    temp_root: &Path,
    started_wall: SystemTime,
    self_data_dir: Option<&Path>,
    stop_flag: &AtomicBool,
    out: &mut Vec<ConfigFileCandidate>,
) {
    if stop_flag.load(Ordering::Relaxed) {
        return;
    }
    let Ok(entries) = std::fs::read_dir(temp_root) else {
        return;
    };

    let mut top_hits: Vec<ConfigFileCandidate> = Vec::new();
    let mut fresh_subdirs: Vec<(SystemTime, PathBuf)> = Vec::new();
    let mut warm_subdirs: Vec<(SystemTime, PathBuf)> = Vec::new();
    let mut top_visited = 0usize;

    for entry in entries.filter_map(Result::ok) {
        if stop_flag.load(Ordering::Relaxed) || top_visited >= MAX_TEMP_TOP_ENTRIES {
            break;
        }
        top_visited += 1;
        let path = entry.path();
        if self_data_dir.is_some_and(|s| path_starts_with_dir(&path, s)) {
            continue;
        }
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_file() {
            if !is_capture_config_ext(&path) {
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                if meta.len() > 0 && meta.len() <= MAX_SUBSCRIPTION_BYTES as u64 {
                    if let Ok(modified) = meta.modified() {
                        if modified >= started_wall {
                            top_hits.push(ConfigFileCandidate {
                                path: normalize_os_path(&path),
                                preexisting_fallback: false,
                                modified,
                            });
                        }
                    }
                }
            }
        } else if ft.is_dir() {
            let lower = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if !IGNORED_WATCH_DIRS.contains(&lower.as_str()) {
                let mtime = entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(UNIX_EPOCH);
                if mtime >= started_wall {
                    fresh_subdirs.push((mtime, path));
                } else {
                    warm_subdirs.push((mtime, path));
                }
            }
        }
    }

    fresh_subdirs.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, sub_path) in fresh_subdirs.into_iter().take(MAX_TEMP_FRESH_SUBDIRS) {
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }
        collect_recent_config_files(
            &sub_path,
            1,
            started_wall,
            false,
            self_data_dir,
            stop_flag,
            &mut top_hits,
        );
    }

    warm_subdirs.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, sub_path) in warm_subdirs.into_iter().take(MAX_TEMP_WARM_SUBDIRS) {
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }
        collect_recent_config_files(
            &sub_path,
            0,
            started_wall,
            false,
            self_data_dir,
            stop_flag,
            &mut top_hits,
        );
    }

    top_hits.sort_by(|a, b| b.modified.cmp(&a.modified));
    out.extend(top_hits);
}

fn is_capture_config_ext(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .is_some_and(|ext| matches!(ext.as_str(), "yaml" | "yml" | "json" | "txt" | "conf"))
}

fn is_fallback_plaintext_config_ext(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .is_some_and(|ext| matches!(ext.as_str(), "yaml" | "yml" | "json"))
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

#[derive(Debug, PartialEq)]
enum CapturedBytesOutcome {
    Nodes(Vec<ProxyNode>),
    Opaque,
    Ignored,
}

fn parse_captured_bytes(
    sub_id: &str,
    bytes: &[u8],
    controller_endpoints: &mut HashMap<String, Option<String>>,
    discovered_secrets: &mut Vec<String>,
) -> CapturedBytesOutcome {
    if bytes.is_empty() || bytes.len() > MAX_SUBSCRIPTION_BYTES {
        return CapturedBytesOutcome::Ignored;
    }
    let has_nul = bytes[..bytes.len().min(4096)].contains(&0);
    let Ok(raw_text) = std::str::from_utf8(bytes) else {
        return if bytes.len() >= 16 {
            CapturedBytesOutcome::Opaque
        } else {
            CapturedBytesOutcome::Ignored
        };
    };
    if has_nul {
        return CapturedBytesOutcome::Opaque;
    }
    let text = raw_text.strip_prefix('\u{FEFF}').unwrap_or(raw_text).trim();
    if text.is_empty() {
        return CapturedBytesOutcome::Ignored;
    }

    // Extract loopback controller URL and optional secret from top-level YAML/JSON lines.
    let mut found_ctrl_urls: Vec<String> = Vec::new();
    let mut found_secret: Option<String> = None;
    for line in text.lines().take(2000) {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if let Some(rest) = l
            .strip_prefix("external-controller:")
            .or_else(|| l.strip_prefix("\"external-controller\":"))
            .or_else(|| l.strip_prefix("\"external_controller\":"))
        {
            let cleaned = strip_yaml_inline_value(rest);
            if let Some(url) = normalize_loopback_controller_base_url(cleaned) {
                if !found_ctrl_urls.contains(&url) {
                    found_ctrl_urls.push(url);
                }
            }
        }
        // Only match unindented top-level YAML `secret:`; JSON controller secrets are extracted
        // structurally by `extract_json_controller_hints` so nested `"secret"` keys never pollute slots.
        let is_top_level_yaml_secret =
            !line.starts_with(' ') && !line.starts_with('\t') && line.starts_with("secret:");
        if is_top_level_yaml_secret {
            if let Some(rest) = line.strip_prefix("secret:") {
                let cleaned = strip_yaml_inline_value(rest);
                if !cleaned.is_empty() && !cleaned.eq_ignore_ascii_case("null") {
                    found_secret = Some(cleaned.to_string());
                }
            }
        }
    }
    if let Some(ref sec) = found_secret {
        push_unique_secret(discovered_secrets, sec);
    }
    for url in found_ctrl_urls {
        register_controller_endpoint(controller_endpoints, url, found_secret.clone());
    }

    let mut parsed_json_value: Option<serde_json::Value> = None;
    if text.starts_with('{') || text.starts_with('[') {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(text) {
            extract_json_controller_hints(&val, controller_endpoints, discovered_secrets);
            if let Some(nodes) = parse_json_config_nodes_from_val(sub_id, &val, text) {
                return CapturedBytesOutcome::Nodes(nodes);
            }
            parsed_json_value = Some(val);
        }
    }
    if let Ok(parsed) = parse_subscription_payload(sub_id, bytes, None) {
        if !parsed.nodes.is_empty() {
            return CapturedBytesOutcome::Nodes(parsed.nodes);
        }
    }

    if let Some(ref val) = parsed_json_value {
        if looks_like_encrypted_json(val) {
            return CapturedBytesOutcome::Opaque;
        }
    }

    let ctrl_count = text
        .chars()
        .take(1024)
        .filter(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
        .count();
    let structured_plaintext = parsed_json_value.is_some()
        || serde_yaml_ng::from_str::<serde_yaml_ng::Value>(text)
            .is_ok_and(|v| v.is_mapping() || v.is_sequence());
    if ctrl_count >= 4 || (!structured_plaintext && bytes.len() >= 32) {
        CapturedBytesOutcome::Opaque
    } else {
        CapturedBytesOutcome::Ignored
    }
}

fn extract_json_controller_hints(
    val: &serde_json::Value,
    controller_endpoints: &mut HashMap<String, Option<String>>,
    discovered_secrets: &mut Vec<String>,
) {
    let clash_api = val
        .get("experimental")
        .and_then(|e| e.get("clash_api"))
        .and_then(serde_json::Value::as_object);
    let mut secret = val
        .get("secret")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);
    if secret.is_none() {
        secret = clash_api
            .and_then(|c| c.get("secret"))
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned);
    }
    if let Some(ref sec) = secret {
        push_unique_secret(discovered_secrets, sec);
    }
    for raw_addr in [
        val.get("external-controller")
            .and_then(serde_json::Value::as_str),
        val.get("external_controller")
            .and_then(serde_json::Value::as_str),
        clash_api
            .and_then(|c| c.get("external_controller"))
            .and_then(serde_json::Value::as_str),
        clash_api
            .and_then(|c| c.get("external-controller"))
            .and_then(serde_json::Value::as_str),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(url) = normalize_loopback_controller_base_url(raw_addr) {
            register_controller_endpoint(controller_endpoints, url, secret.clone());
        }
    }
}

fn strip_yaml_inline_value(raw: &str) -> &str {
    let s = raw.trim().trim_end_matches(',').trim();
    if let Some(first) = s.chars().next() {
        if first == '"' || first == '\'' {
            let rest = &s[first.len_utf8()..];
            if let Some(end) = rest.find(first) {
                return rest[..end].trim();
            }
            return strip_quotes(s);
        }
    }
    let no_comment = s
        .split_once(" #")
        .or_else(|| s.split_once("\t#"))
        .map(|(head, _)| head)
        .unwrap_or(s);
    strip_quotes(no_comment.trim().trim_end_matches(',').trim())
}

fn looks_like_encrypted_json(val: &serde_json::Value) -> bool {
    fn has_plaintext_proxy_entries(root: &serde_json::Map<String, serde_json::Value>) -> bool {
        for key in ["proxies", "outbounds"] {
            if let Some(arr) = root.get(key).and_then(serde_json::Value::as_array) {
                let has_typed_obj = arr.iter().any(|item| {
                    item.as_object().is_some_and(|o| {
                        o.get("type").or_else(|| o.get("protocol")).is_some()
                    })
                });
                if has_typed_obj {
                    return true;
                }
            }
        }
        false
    }

    fn has_crypto_fields_in_map(map: &serde_json::Map<String, serde_json::Value>) -> bool {
        const STRONG_CRYPTO_KEYS: &[&str] = &[
            "ciphertext",
            "cipher_text",
            "encrypted_data",
            "encrypted_payload",
            "enc_data",
            "iv",
            "nonce",
            "salt",
            "auth_tag",
            "authtag",
            "gcm_tag",
        ];
        let is_plain_proxy_entry = map.contains_key("server")
            && (map.contains_key("port") || map.contains_key("server_port"));
        if is_plain_proxy_entry {
            return false;
        }
        for (k, v) in map {
            let kl = k.to_ascii_lowercase();
            if kl == "encrypted" {
                if v.as_bool() == Some(true)
                    || v.as_str().is_some_and(|s| !s.trim().is_empty())
                {
                    return true;
                }
            }
            if kl == "cipher" {
                let non_trivial = v.as_str().is_some_and(|s| {
                    let t = s.trim();
                    !t.is_empty()
                        && !t.eq_ignore_ascii_case("none")
                        && !t.eq_ignore_ascii_case("plain")
                        && !t.eq_ignore_ascii_case("auto")
                }) || v.as_array().is_some_and(|a| !a.is_empty())
                    || v.as_object().is_some_and(|o| !o.is_empty());
                if non_trivial {
                    return true;
                }
            }
            if STRONG_CRYPTO_KEYS.contains(&kl.as_str()) {
                let non_empty = v.as_str().is_some_and(|s| !s.trim().is_empty())
                    || v.as_array().is_some_and(|a| !a.is_empty());
                if non_empty {
                    return true;
                }
            }
        }
        false
    }

    fn inspect_value(v: &serde_json::Value, depth: usize) -> bool {
        if depth > 3 {
            return false;
        }
        match v {
            serde_json::Value::Object(map) => {
                if has_crypto_fields_in_map(map) {
                    return true;
                }
                map.values().any(|child| inspect_value(child, depth + 1))
            }
            serde_json::Value::Array(arr) => arr
                .iter()
                .take(16)
                .any(|child| inspect_value(child, depth + 1)),
            _ => false,
        }
    }

    if let Some(root) = val.as_object() {
        if has_plaintext_proxy_entries(root) {
            return false;
        }
    }
    inspect_value(val, 0)
}

fn parse_json_config_nodes_from_val(
    sub_id: &str,
    val: &serde_json::Value,
    raw_text: &str,
) -> Option<Vec<ProxyNode>> {
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
            if let Ok((ctrl_nodes, _, _, _)) =
                parse_controller_proxies_json(sub_id, raw_text.as_bytes())
            {
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
            if matches!(
                proto.as_str(),
                "" | "freedom"
                    | "blackhole"
                    | "dns"
                    | "direct"
                    | "block"
                    | "selector"
                    | "urltest"
                    | "loopback"
            ) {
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
    // 1. sing-box JSON outbound (`server` + `server_port`) -> convert strictly to Mihomo-compatible fields.
    if obj.get("server").is_some() && (obj.get("server_port").is_some() || obj.get("port").is_some())
    {
        return node_from_singbox_outbound(sub_id, obj, used_ids);
    }

    // 2. V2Ray / Xray JSON outbound (`settings.vnext` / `settings.servers` + `streamSettings`).
    let protocol = normalize_protocol(raw_proto);
    if !matches!(
        protocol.as_str(),
        "ss" | "vmess" | "vless" | "trojan" | "hysteria2" | "tuic" | "anytls" | "socks5" | "http"
    ) {
        tracing::debug!(
            outbound_type = %raw_proto,
            "skipping unsupported V2Ray/Xray outbound protocol"
        );
        return None;
    }
    let tag = obj
        .get("tag")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);

    let settings = obj.get("settings").and_then(serde_json::Value::as_object)?;
    let (server, port, mut cfg) = if let Some(vnext) = settings
        .get("vnext")
        .and_then(serde_json::Value::as_array)
        .and_then(|a| a.first())
        .and_then(serde_json::Value::as_object)
    {
        let srv = vnext
            .get("address")
            .and_then(serde_json::Value::as_str)?
            .trim()
            .to_string();
        let port = vnext.get("port").and_then(json_to_u16).filter(|&p| p > 0)?;
        let mut map = serde_json::Map::new();
        if let Some(u) = vnext
            .get("users")
            .and_then(serde_json::Value::as_array)
            .and_then(|a| a.first())
            .and_then(serde_json::Value::as_object)
        {
            if let Some(id) = u
                .get("id")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                map.insert("uuid".into(), serde_json::json!(id));
            }
            if let Some(flow) = u.get("flow").and_then(serde_json::Value::as_str) {
                if !flow.trim().is_empty() {
                    map.insert("flow".into(), serde_json::json!(flow.trim()));
                }
            }
            if let Some(sec) = u
                .get("security")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                map.insert("cipher".into(), serde_json::json!(sec));
            }
            if let Some(aid) = u.get("alterId").and_then(serde_json::Value::as_u64) {
                map.insert("alterId".into(), serde_json::json!(aid));
            }
        }
        (srv, port, map)
    } else if let Some(s) = settings
        .get("servers")
        .and_then(serde_json::Value::as_array)
        .and_then(|a| a.first())
        .and_then(serde_json::Value::as_object)
    {
        let srv = s
            .get("address")
            .and_then(serde_json::Value::as_str)?
            .trim()
            .to_string();
        let port = s.get("port").and_then(json_to_u16).filter(|&p| p > 0)?;
        let mut map = serde_json::Map::new();
        if let Some(pw) = s
            .get("password")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            map.insert("password".into(), serde_json::json!(pw));
        }
        if let Some(m) = s
            .get("method")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            map.insert("cipher".into(), serde_json::json!(m));
        }
        (srv, port, map)
    } else {
        return None;
    };
    if server.is_empty() {
        return None;
    }

    // Enforce required protocol credentials aligned with sing-box outbound validation.
    let has_uuid = cfg
        .get("uuid")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|s| !s.trim().is_empty());
    let has_password = cfg
        .get("password")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|s| !s.trim().is_empty());
    let has_cipher = cfg
        .get("cipher")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|s| !s.trim().is_empty());
    match protocol.as_str() {
        "ss" if !has_cipher || !has_password => {
            tracing::debug!(
                protocol = %protocol,
                has_cipher = has_cipher,
                has_password = has_password,
                "skipping V2Ray/Xray ss outbound missing required cipher or password"
            );
            return None;
        }
        "vless" | "vmess" | "tuic" if !has_uuid => {
            tracing::debug!(
                protocol = %protocol,
                "skipping V2Ray/Xray outbound missing required uuid"
            );
            return None;
        }
        "trojan" | "hysteria2" | "anytls" if !has_password => {
            tracing::debug!(
                protocol = %protocol,
                "skipping V2Ray/Xray outbound missing required password"
            );
            return None;
        }
        _ => {}
    }

    let name = tag.unwrap_or_else(|| format!("{protocol}-{server}:{port}"));
    cfg.insert("name".into(), serde_json::json!(name));
    cfg.insert("type".into(), serde_json::json!(protocol));
    cfg.insert("server".into(), serde_json::json!(server));
    cfg.insert("port".into(), serde_json::json!(port));
    cfg.insert("udp".into(), serde_json::json!(true));
    if let Some(ss) = obj
        .get("streamSettings")
        .and_then(serde_json::Value::as_object)
    {
        if let Some(net) = ss
            .get("network")
            .and_then(serde_json::Value::as_str)
            .map(|n| n.trim().to_ascii_lowercase())
        {
            if !net.is_empty() && net != "tcp" {
                cfg.insert("network".into(), serde_json::json!(net));
            }
            if net == "ws" {
                if let Some(ws) = ss.get("wsSettings").and_then(serde_json::Value::as_object) {
                    let mut ws_opts = serde_json::Map::new();
                    if let Some(path) = ws
                        .get("path")
                        .and_then(serde_json::Value::as_str)
                        .filter(|s| !s.is_empty())
                    {
                        ws_opts.insert("path".into(), serde_json::json!(path));
                    }
                    if let Some(headers) = ws.get("headers").and_then(serde_json::Value::as_object)
                    {
                        let norm_headers = normalize_ws_headers_map(headers);
                        if !norm_headers.is_empty() {
                            ws_opts.insert(
                                "headers".into(),
                                serde_json::Value::Object(norm_headers),
                            );
                        }
                    }
                    if !ws_opts.is_empty() {
                        cfg.insert("ws-opts".into(), serde_json::Value::Object(ws_opts));
                    }
                }
            } else if net == "grpc" {
                if let Some(svc) = ss
                    .get("grpcSettings")
                    .and_then(|g| g.get("serviceName"))
                    .and_then(serde_json::Value::as_str)
                    .filter(|s| !s.is_empty())
                {
                    cfg.insert(
                        "grpc-opts".into(),
                        serde_json::json!({ "grpc-service-name": svc }),
                    );
                }
            }
        }
        if let Some(sec) = ss.get("security").and_then(serde_json::Value::as_str) {
            let sec_lower = sec.to_ascii_lowercase();
            if matches!(sec_lower.as_str(), "tls" | "reality") {
                let uses_sni = matches!(
                    protocol.as_str(),
                    "trojan" | "hysteria2" | "tuic" | "anytls"
                );
                if !uses_sni {
                    cfg.insert("tls".into(), serde_json::json!(true));
                }
                let tls_block = ss.get("tlsSettings").or_else(|| ss.get("realitySettings"));
                if let Some(sni) = tls_block
                    .and_then(|t| t.get("serverName"))
                    .and_then(serde_json::Value::as_str)
                    .filter(|s| !s.is_empty())
                {
                    cfg.insert(
                        if uses_sni { "sni" } else { "servername" }.into(),
                        serde_json::json!(sni),
                    );
                }
                if let Some(allow_insecure) = tls_block
                    .and_then(|t| t.get("allowInsecure"))
                    .and_then(serde_json::Value::as_bool)
                {
                    cfg.insert("skip-cert-verify".into(), serde_json::json!(allow_insecure));
                }
                if let Some(fp) = tls_block
                    .and_then(|t| t.get("fingerprint"))
                    .and_then(serde_json::Value::as_str)
                    .filter(|s| !s.is_empty())
                {
                    cfg.insert("client-fingerprint".into(), serde_json::json!(fp));
                }
                if let Some(alpn_arr) = tls_block
                    .and_then(|t| t.get("alpn"))
                    .and_then(serde_json::Value::as_array)
                {
                    let alpn_list: Vec<String> = alpn_arr
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(ToOwned::to_owned)
                        .collect();
                    if !alpn_list.is_empty() {
                        cfg.insert("alpn".into(), serde_json::json!(alpn_list));
                    }
                }
                if sec_lower == "reality" {
                    if let Some(r) = ss
                        .get("realitySettings")
                        .and_then(serde_json::Value::as_object)
                    {
                        let mut rmap = serde_json::Map::new();
                        if let Some(pbk) = r
                            .get("publicKey")
                            .and_then(serde_json::Value::as_str)
                            .filter(|s| !s.is_empty())
                        {
                            rmap.insert("public-key".into(), serde_json::json!(pbk));
                        }
                        if let Some(sid) = r
                            .get("shortId")
                            .and_then(serde_json::Value::as_str)
                            .filter(|s| !s.is_empty())
                        {
                            rmap.insert("short-id".into(), serde_json::json!(sid));
                        }
                        if !rmap.is_empty() {
                            cfg.insert("reality-opts".into(), serde_json::Value::Object(rmap));
                        }
                    }
                }
            }
        }
    }
    Some(build_proxy_node(
        sub_id,
        name,
        protocol,
        server,
        port,
        serde_json::Value::Object(cfg),
        used_ids,
    ))
}

#[derive(Debug, PartialEq, Eq)]
enum ControllerProbeOutcome {
    Ok(Vec<u8>),
    Unauthorized,
    TransportErr,
}

fn probe_loopback_proxies_with_secrets(
    base_url: &str,
    endpoint_secret: Option<&str>,
    discovered_secrets: &[String],
    timeout: Duration,
    stop_flag: &AtomicBool,
) -> Option<Vec<u8>> {
    let mut secret_attempts: Vec<Option<&str>> = Vec::new();
    if let Some(sec) = endpoint_secret {
        secret_attempts.push(Some(sec));
    }
    secret_attempts.push(None);
    for sec in discovered_secrets {
        if endpoint_secret != Some(sec.as_str()) {
            secret_attempts.push(Some(sec.as_str()));
        }
    }

    for sec in secret_attempts {
        if stop_flag.load(Ordering::SeqCst) {
            break;
        }
        match fetch_loopback_proxies_sync(base_url, sec, timeout, stop_flag) {
            ControllerProbeOutcome::Ok(body) => return Some(body),
            ControllerProbeOutcome::Unauthorized => continue,
            ControllerProbeOutcome::TransportErr => break,
        }
    }
    None
}

fn fetch_loopback_proxies_sync(
    base_url: &str,
    secret: Option<&str>,
    timeout: Duration,
    stop_flag: &AtomicBool,
) -> ControllerProbeOutcome {
    if stop_flag.load(Ordering::Relaxed) {
        return ControllerProbeOutcome::TransportErr;
    }
    let Some(host_port) = base_url.strip_prefix("http://") else {
        return ControllerProbeOutcome::TransportErr;
    };
    let Ok(addr) = host_port.parse::<SocketAddr>() else {
        return ControllerProbeOutcome::TransportErr;
    };
    if !addr.ip().is_loopback() {
        return ControllerProbeOutcome::TransportErr;
    }
    let total_deadline = Instant::now() + Duration::from_millis(2500);
    let connect_timeout = timeout.min(Duration::from_millis(2500));
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, connect_timeout) else {
        return ControllerProbeOutcome::TransportErr;
    };
    if stop_flag.load(Ordering::Relaxed) || Instant::now() >= total_deadline {
        return ControllerProbeOutcome::TransportErr;
    }
    let write_timeout = timeout.min(total_deadline.saturating_duration_since(Instant::now()));
    if write_timeout.is_zero() {
        return ControllerProbeOutcome::TransportErr;
    }
    let _ = stream.set_write_timeout(Some(write_timeout));

    let mut req = format!("GET /proxies HTTP/1.1\r\nHost: {host_port}\r\n");
    if let Some(sec) = secret {
        let clean: String = sec
            .trim()
            .chars()
            .filter(|c| !matches!(c, '\r' | '\n'))
            .collect();
        if !clean.is_empty() {
            req.push_str(&format!("Authorization: Bearer {clean}\r\n"));
        }
    }
    req.push_str("Connection: close\r\n\r\n");
    if stream.write_all(req.as_bytes()).is_err() {
        return ControllerProbeOutcome::TransportErr;
    }

    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    let mut idle_since = Instant::now();
    let base_slice = timeout
        .min(Duration::from_millis(200))
        .max(Duration::from_millis(20));
    let _ = stream.set_read_timeout(Some(base_slice));
    loop {
        if stop_flag.load(Ordering::Relaxed) {
            return ControllerProbeOutcome::TransportErr;
        }
        let now = Instant::now();
        if now >= total_deadline {
            return ControllerProbeOutcome::TransportErr;
        }
        let remaining_total = total_deadline.saturating_duration_since(now);
        if remaining_total.is_zero() {
            return ControllerProbeOutcome::TransportErr;
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
            Ok(_) => return ControllerProbeOutcome::TransportErr,
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                if stop_flag.load(Ordering::Relaxed) || Instant::now() >= total_deadline {
                    return ControllerProbeOutcome::TransportErr;
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
    let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return ControllerProbeOutcome::TransportErr;
    };
    let Ok(header) = std::str::from_utf8(&raw[..split]) else {
        return ControllerProbeOutcome::TransportErr;
    };
    let Some(status) = header.lines().next() else {
        return ControllerProbeOutcome::TransportErr;
    };
    if !status.starts_with("HTTP/") {
        return ControllerProbeOutcome::TransportErr;
    }
    match status.split_whitespace().nth(1) {
        Some("200") => {}
        Some("401" | "403") => return ControllerProbeOutcome::Unauthorized,
        _ => return ControllerProbeOutcome::TransportErr,
    }
    let body = &raw[split + 4..];
    if header
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        match decode_http_chunked(body) {
            Some(decoded) => ControllerProbeOutcome::Ok(decoded),
            None => ControllerProbeOutcome::TransportErr,
        }
    } else {
        ControllerProbeOutcome::Ok(body.to_vec())
    }
}

fn decode_http_chunked(mut data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let crlf = data.windows(2).position(|w| w == b"\r\n")?;
        let size = usize::from_str_radix(
            std::str::from_utf8(&data[..crlf])
                .ok()?
                .split(';')
                .next()?
                .trim(),
            16,
        )
        .ok()?;
        data = &data[crlf + 2..];
        if size == 0 {
            break;
        }
        if data.len() < size + 2 || out.len().saturating_add(size) > MAX_CONTROLLER_HTTP_BYTES {
            return None;
        }
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
        )
        .expect("url_or_cmd alone must deserialize");
        assert_eq!(primary.url_or_cmd, "https://example.invalid/sub");

        let alias: SubscriptionRecord = serde_json::from_str(
            r#"{"id":"s2","name":"Alias","source":"https://example.invalid/alias"}"#,
        )
        .expect("source alias alone must deserialize");
        assert_eq!(alias.url_or_cmd, "https://example.invalid/alias");

        let err = serde_json::from_str::<SubscriptionRecord>(
            r#"{"id":"s3","url_or_cmd":"https://a.invalid","source":"https://b.invalid"}"#,
        )
        .expect_err("providing both url_or_cmd and source must fail");
        assert!(
            err.to_string().contains("duplicate field"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn collect_self_pid_tree_excludes_current_process_everywhere() {
        let self_pid = std::process::id();
        let tree = collect_self_pid_tree(&snapshot_processes());
        assert!(tree.contains(&self_pid));
        assert!(list_process_candidates(false).iter().all(|c| c.pid != self_pid));
        assert!(
            list_desktop_app_candidates(None, None)
                .iter()
                .all(|c| c.pid != self_pid && !c.related_pids.contains(&self_pid))
        );
    }

    #[test]
    fn live_capture_grabs_ephemeral_plaintext_yaml_before_deletion() {
        let temp_dir =
            std::env::temp_dir().join(format!("catcloud-livecap-ok-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).expect("create temp capture dir");
        let mgr = LiveCaptureManager::new();
        let start = mgr
            .start_session_inner(
                0,
                "MockClient".to_string(),
                None,
                vec![temp_dir.clone()],
                None,
                HashSet::new(),
                Duration::from_millis(40),
                Duration::from_secs(10),
                false,
            )
            .expect("start mock capture session");

        let ephemeral = temp_dir.join("ephemeral_runtime.yaml");
        std::fs::write(
            &ephemeral,
            concat!(
                "proxies:\n",
                "  - name: \"JP Live 1x\"\n    type: vless\n    server: 203.0.113.10\n    port: 443\n    uuid: \"00000000-0000-4000-8000-000000000091\"\n    tls: true\n",
                "  - name: \"SG Live 0.5x\"\n    type: trojan\n    server: 198.51.100.20\n    port: 443\n    password: \"placeholder-secret\"\n"
            ),
        )
        .expect("write ephemeral yaml");

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

        let outcome = mgr
            .finish_session(&start.session_id)
            .expect("finish session");
        assert!(outcome.supported);
        assert!(outcome.is_ephemeral_source);
        assert_eq!(outcome.source_kind, "migrated");
        assert_eq!(outcome.nodes.len(), 2);
        assert!(outcome.unsupported_reason.is_none());
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn live_capture_opaque_encrypted_change_returns_unsupported_reason() {
        let temp_dir =
            std::env::temp_dir().join(format!("catcloud-livecap-opaque-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).expect("create temp opaque dir");
        let mgr = LiveCaptureManager::new();
        let start = mgr
            .start_session_inner(
                0,
                "OpaqueClient".to_string(),
                None,
                vec![temp_dir.clone()],
                None,
                HashSet::new(),
                Duration::from_millis(40),
                Duration::from_secs(10),
                false,
            )
            .expect("start opaque capture session");

        let opaque = temp_dir.join("protected.yaml");
        std::fs::write(
            &opaque,
            [
                0x00u8, 0xFF, 0xFE, 0xA1, 0x9C, 0x8B, 0x7D, 0xE2, 0x13, 0x88, 0xC4, 0x00, 0x91,
                0xDE, 0xAD, 0xBE, 0xEF, 0x77, 0x66, 0x55,
            ],
        )
        .expect("write opaque file");

        let deadline = Instant::now() + Duration::from_secs(3);
        let mut saw_opaque = false;
        while Instant::now() < deadline {
            let st = mgr
                .poll_session(&start.session_id)
                .expect("poll opaque session");
            if st.step_activity_seen && st.opaque_change_detected && !st.step_nodes_ready {
                saw_opaque = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        assert!(saw_opaque, "expected opaque_change_detected to become true");

        let outcome = mgr
            .finish_session(&start.session_id)
            .expect("finish opaque session");
        assert!(!outcome.supported);
        assert_eq!(outcome.source_kind, "none");
        assert!(outcome.nodes.is_empty());
        assert_eq!(
            outcome.unsupported_reason.as_deref(),
            Some(CAPTURE_UNSUPPORTED_REASON)
        );
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn live_capture_timeout_sets_timed_out_and_preserves_snapshot_for_finish() {
        let temp_dir =
            std::env::temp_dir().join(format!("catcloud-livecap-timeout-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).expect("create temp timeout dir");
        let mgr = LiveCaptureManager::new();
        let start = mgr
            .start_session_inner(
                0,
                "TimeoutClient".to_string(),
                None,
                vec![temp_dir.clone()],
                None,
                HashSet::new(),
                Duration::from_millis(30),
                Duration::from_millis(260),
                false,
            )
            .expect("start timeout capture session");

        std::fs::write(
            temp_dir.join("runtime.yaml"),
            "proxies:\n  - name: \"TW TimeoutKeep 1x\"\n    type: trojan\n    server: 203.0.113.55\n    port: 443\n    password: \"placeholder\"\n",
        )
        .expect("write yaml");

        let deadline = Instant::now() + Duration::from_secs(3);
        let mut saw_timeout = false;
        while Instant::now() < deadline {
            let st = mgr.poll_session(&start.session_id).expect("poll timeout session");
            if !st.active && st.timed_out {
                assert_eq!(st.captured_node_count, 1);
                assert!(st.unsupported_reason.is_none());
                assert!(st.events.iter().any(|e| {
                    e.kind == "timeout"
                        && e.message.contains("已达 3 分钟捕捉上限并自动暂停监控")
                        && e.message.contains("整理并查看结果")
                }));
                saw_timeout = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        assert!(saw_timeout, "expected timed_out=true after max_duration");

        // `timed_out` must default to `false` when deserializing legacy status payloads.
        let legacy_status: LiveCaptureStatusDto = serde_json::from_value(serde_json::json!({
            "session_id": "cap-legacy",
            "active": true,
            "step_app_ready": true,
            "step_activity_seen": false,
            "step_nodes_ready": false,
            "elapsed_sec": 5,
            "captured_node_count": 0,
            "opaque_change_detected": false,
            "target_name": "LegacyClient",
            "watch_dirs": [],
            "events": [],
            "preview_nodes": [],
            "unsupported_reason": null
        }))
        .expect("deserialize legacy LiveCaptureStatusDto without timed_out");
        assert!(!legacy_status.timed_out);

        // Session must still allow `finish_session` to extract captured nodes after timeout.
        let outcome = mgr
            .finish_session(&start.session_id)
            .expect("finish after timeout must retain captured nodes");
        assert!(outcome.supported);
        assert_eq!(outcome.nodes.len(), 1);
        assert_eq!(outcome.nodes[0].name, "TW TimeoutKeep 1x");
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn live_capture_singbox_conversion_encrypted_json_and_controller_secret_bearer() {
        let mut endpoints: HashMap<String, Option<String>> = HashMap::new();
        let mut secrets: Vec<String> = Vec::new();

        // 1. sing-box JSON converts object `tls` / `transport` / `reality` / `utls` / `alpn`
        //    cleanly into Mihomo-compatible fields (no raw object `tls` or `transport` or `server_port`).
        let singbox_json = serde_json::json!({
            "experimental": {
                "clash_api": {
                    "external_controller": "127.0.0.1:19091",
                    "secret": "sb-secret-token"
                }
            },
            "outbounds": [
                {
                    "type": "vless",
                    "tag": "JP SingBox WS 1x",
                    "server": "203.0.113.88",
                    "server_port": 443,
                    "uuid": "00000000-0000-4000-8000-000000000888",
                    "flow": "xtls-rprx-vision",
                    "tls": {
                        "enabled": true,
                        "server_name": "sb.example.invalid",
                        "insecure": true,
                        "alpn": ["h2", "http/1.1"],
                        "utls": { "enabled": true, "fingerprint": "chrome" },
                        "reality": {
                            "enabled": true,
                            "public_key": "pbk-sample-value",
                            "short_id": "a1b2"
                        }
                    },
                    "transport": {
                        "type": "ws",
                        "path": "/ws",
                        "headers": { "Host": "cdn.example.invalid" }
                    }
                },
                {
                    "type": "trojan",
                    "tag": "SG SingBox gRPC 0.5x",
                    "server": "198.51.100.89",
                    "server_port": 8443,
                    "password": "tr-placeholder-password",
                    "tls": {
                        "enabled": true,
                        "server_name": "tr.example.invalid"
                    },
                    "transport": {
                        "type": "grpc",
                        "service_name": "grpc-svc"
                    }
                },
                {
                    "type": "shadowsocks",
                    "tag": "US SingBox SS 1x",
                    "server": "198.51.100.90",
                    "server_port": 8388,
                    "method": "aes-256-gcm",
                    "password": "ss-placeholder-password"
                }
            ]
        })
        .to_string();
        match parse_captured_bytes(
            "live_capture",
            singbox_json.as_bytes(),
            &mut endpoints,
            &mut secrets,
        ) {
            CapturedBytesOutcome::Nodes(nodes) => {
                assert_eq!(nodes.len(), 3);
                let vless_cfg = &nodes[0].raw_config;
                assert_eq!(vless_cfg.get("port").and_then(|v| v.as_u64()), Some(443));
                assert_eq!(vless_cfg.get("tls").and_then(|v| v.as_bool()), Some(true));
                assert!(vless_cfg.get("server_port").is_none());
                assert!(vless_cfg.get("transport").is_none());
                assert_eq!(
                    vless_cfg.get("servername").and_then(|v| v.as_str()),
                    Some("sb.example.invalid")
                );
                assert_eq!(
                    vless_cfg.get("skip-cert-verify").and_then(|v| v.as_bool()),
                    Some(true)
                );
                assert_eq!(
                    vless_cfg.get("client-fingerprint").and_then(|v| v.as_str()),
                    Some("chrome")
                );
                assert_eq!(
                    vless_cfg
                        .get("alpn")
                        .and_then(|v| v.as_array())
                        .map(|a| a.len()),
                    Some(2)
                );
                assert_eq!(
                    vless_cfg
                        .get("reality-opts")
                        .and_then(|r| r.get("public-key"))
                        .and_then(|v| v.as_str()),
                    Some("pbk-sample-value")
                );
                assert_eq!(vless_cfg.get("network").and_then(|v| v.as_str()), Some("ws"));
                assert_eq!(
                    vless_cfg
                        .get("ws-opts")
                        .and_then(|w| w.get("path"))
                        .and_then(|v| v.as_str()),
                    Some("/ws")
                );

                let trojan_cfg = &nodes[1].raw_config;
                assert_eq!(
                    trojan_cfg.get("sni").and_then(|v| v.as_str()),
                    Some("tr.example.invalid")
                );
                assert_eq!(trojan_cfg.get("network").and_then(|v| v.as_str()), Some("grpc"));
                assert_eq!(
                    trojan_cfg
                        .get("grpc-opts")
                        .and_then(|g| g.get("grpc-service-name"))
                        .and_then(|v| v.as_str()),
                    Some("grpc-svc")
                );

                let ss_cfg = &nodes[2].raw_config;
                assert_eq!(ss_cfg.get("type").and_then(|v| v.as_str()), Some("ss"));
                assert_eq!(
                    ss_cfg.get("cipher").and_then(|v| v.as_str()),
                    Some("aes-256-gcm")
                );
            }
            other => panic!("expected Nodes from sing-box JSON, got {other:?}"),
        }
        assert_eq!(
            endpoints.get("http://127.0.0.1:19091").and_then(|s| s.as_deref()),
            Some("sb-secret-token")
        );

        // 2. Encrypted JSON with encrypted/ciphertext/cipher/iv/salt must classify as Opaque (not Ignored)
        for encrypted_sample in [
            br#"{"encrypted":true,"ciphertext":"YWJjZGVm","iv":"MTIzNDU2"}"#.as_slice(),
            br#"{"cipher":"aes-256-gcm","payload":"U2FsdGVkX1+abc"}"#.as_slice(),
            br#"{"salt":"9f86d081","data":"YmFzZTY0"}"#.as_slice(),
            br#"{"profile":{"iv":"aabbccdd","blob":"123456"}}"#.as_slice(),
            br#"[{"ciphertext":"ZW5j","iv":"MTIz"}]"#.as_slice(),
        ] {
            assert_eq!(
                parse_captured_bytes("live_capture", encrypted_sample, &mut endpoints, &mut secrets),
                CapturedBytesOutcome::Opaque,
                "expected encrypted JSON sample to be classified as Opaque"
            );
        }
        for plain_ignored in [
            br#"{"version":"1.0","theme":"dark"}"#.as_slice(),
            br#"{"outbounds":[{"type":"direct","tag":"direct"},{"type":"block","tag":"block"}]}"#
                .as_slice(),
        ] {
            assert_eq!(
                parse_captured_bytes("live_capture", plain_ignored, &mut endpoints, &mut secrets),
                CapturedBytesOutcome::Ignored,
                "expected non-encrypted metadata JSON to be Ignored"
            );
        }

        // 3. YAML inline comment stripping + Cmdline secret extraction + Bearer header on probe
        let yaml_with_comments = concat!(
            "external-controller: 127.0.0.1:19092 # local api\n",
            "secret: \"yaml-sec-99\" # bearer token\n",
            "proxies: []\n"
        );
        let _ = parse_captured_bytes(
            "live_capture",
            yaml_with_comments.as_bytes(),
            &mut endpoints,
            &mut secrets,
        );
        assert_eq!(
            endpoints.get("http://127.0.0.1:19092").and_then(|s| s.as_deref()),
            Some("yaml-sec-99")
        );

        assert_eq!(
            extract_controller_secret_from_cmdline(&[
                "mihomo.exe".to_string(),
                "-secret".to_string(),
                "my-bearer-sec".to_string(),
            ])
            .as_deref(),
            Some("my-bearer-sec")
        );
        assert_eq!(
            extract_controller_secret_from_cmdline(&["--ext-ctl-secret=tok123".to_string()])
                .as_deref(),
            Some("tok123")
        );
        assert_eq!(
            extract_controller_secret_from_cmdline(&[
                "--external-controller-secret=tok456".to_string()
            ])
            .as_deref(),
            Some("tok456")
        );

        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind mock controller listener");
        let port = listener.local_addr().expect("mock controller addr").port();
        let server_handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut req_buf = [0u8; 2048];
                let n = stream.read(&mut req_buf).unwrap_or(0);
                let req_str = String::from_utf8_lossy(&req_buf[..n]);
                if req_str.contains("Authorization: Bearer top-sec-42") {
                    let body = r#"{"proxies":{"JP-Meta-Only":{"type":"Vless"}}}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                } else {
                    let _ = stream.write_all(
                        b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                }
            }
        });
        let stop = AtomicBool::new(false);
        let body = match fetch_loopback_proxies_sync(
            &format!("http://127.0.0.1:{port}"),
            Some("top-sec-42"),
            Duration::from_secs(2),
            &stop,
        ) {
            ControllerProbeOutcome::Ok(body) => body,
            other => panic!("controller with matching Bearer secret must return 200, got {other:?}"),
        };
        let _ = server_handle.join();
        let (nodes, meta_only, _, _) =
            parse_controller_proxies_json("live_capture", &body).expect("parse proxies json");
        assert!(nodes.is_empty());
        assert_eq!(meta_only, 1);
    }

    #[test]
    fn live_capture_proxy_keywords_and_tray_candidate_classification() {
        for kw in [
            "NekoBox",
            "NekoRay",
            "Hiddify",
            "Karing",
            "Sparkle",
            "V2Box",
            "FlClash",
            "Clash",
            "mihomo",
            "sing-box",
            "v2ray",
            "xray",
            "shadowsocks",
            "trojan",
            "hysteria",
            "tuic",
            "my-proxy",
            "OpenVPN",
        ] {
            assert!(
                matches_generic_proxy_keyword(kw),
                "expected `{kw}` to match generic proxy keywords"
            );
        }
        assert!(!matches_generic_proxy_keyword("notepad.exe"));

        // System PIDs (`<= 4`), privileged ports (`< 1024`), and known DB/OS ports must be skipped.
        assert!(!is_eligible_proxy_listener(0, 7890));
        assert!(!is_eligible_proxy_listener(4, 7890));
        assert!(!is_eligible_proxy_listener(1234, 443));
        for excluded_port in [1433u16, 3306, 3389, 5432, 6379, 27017] {
            assert!(
                !is_eligible_proxy_listener(1234, excluded_port),
                "known DB/system port {excluded_port} must be excluded"
            );
        }
        for proxy_port in [7890u16, 7897, 9090, 10808, 10809, 20170] {
            assert!(
                is_eligible_proxy_listener(1234, proxy_port),
                "loopback proxy port {proxy_port} must be eligible"
            );
        }

        // Tray/background candidate eligibility gate
        assert!(is_tray_background_proxy_eligible(1234, true, false, false, false));
        assert!(is_tray_background_proxy_eligible(1234, false, true, false, false));
        assert!(!is_tray_background_proxy_eligible(4, true, true, false, false));
        assert!(!is_tray_background_proxy_eligible(1234, true, true, true, false));
        assert!(!is_tray_background_proxy_eligible(1234, true, true, false, true));
        assert!(!is_tray_background_proxy_eligible(1234, false, false, false, false));

        let (friendly, title) = format_tray_background_labels("FlClash", &[7890, 9090]);
        assert!(friendly.contains("（托盘/后台运行中）"));
        assert!(title.contains("7890/9090"));
    }

    #[test]
    fn live_capture_initial_pids_do_not_trigger_step2_until_new_child_appears() {
        let target_pid = 4000u32;
        let initial_pids = HashSet::from([target_pid, 4001u32, 4002u32]);
        let mut seen_pids = initial_pids.clone();

        // Pre-existing target and sibling/child PIDs must NEVER trigger Step 2 on startup.
        assert!(!should_trigger_process_activity(
            target_pid,
            target_pid,
            &initial_pids,
            &mut seen_pids
        ));
        assert!(!should_trigger_process_activity(
            4001,
            target_pid,
            &initial_pids,
            &mut seen_pids
        ));
        assert!(!should_trigger_process_activity(
            4002,
            target_pid,
            &initial_pids,
            &mut seen_pids
        ));

        // Only a genuinely newly spawned related PID triggers Step 2 once.
        assert!(should_trigger_process_activity(
            4099,
            target_pid,
            &initial_pids,
            &mut seen_pids
        ));
        assert!(!should_trigger_process_activity(
            4099,
            target_pid,
            &initial_pids,
            &mut seen_pids
        ));

        // End-to-end session startup check: with initial_pids recorded and no new activity,
        // Step 1 is ready while Step 2 and Step 3 stay dark.
        let temp_dir =
            std::env::temp_dir().join(format!("catcloud-livecap-initpid-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).expect("create initpid temp dir");
        let mgr = LiveCaptureManager::new();
        let start = mgr
            .start_session_inner(
                0,
                "IdleClient".to_string(),
                None,
                vec![temp_dir.clone()],
                None,
                initial_pids,
                Duration::from_millis(40),
                Duration::from_secs(10),
                false,
            )
            .expect("start idle capture session");
        std::thread::sleep(Duration::from_millis(120));
        let st = mgr.poll_session(&start.session_id).expect("poll idle session");
        assert!(st.step_app_ready);
        assert!(!st.step_activity_seen, "Step 2 must remain false before new activity");
        assert!(!st.step_nodes_ready);
        assert!(mgr.cancel_session(&start.session_id));
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn live_capture_preexisting_fallback_and_prioritized_temp_scan() {
        let base_dir =
            std::env::temp_dir().join(format!("catcloud-livecap-fallback-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&base_dir).expect("create fallback dir");
        let yaml_path = base_dir.join("existing_profile.yaml");
        let json_path = base_dir.join("existing_singbox.json");
        let txt_path = base_dir.join("readme.txt");
        std::fs::write(&yaml_path, "proxies: []\n").expect("write yaml");
        std::fs::write(&json_path, "{\"outbounds\":[]}\n").expect("write json");
        std::fs::write(&txt_path, "notes\n").expect("write txt");

        let stop = AtomicBool::new(false);
        // Simulate files written 1 hour before `started_wall` (within 7-day fallback window).
        let started_after_1h = SystemTime::now() + Duration::from_secs(3600);
        let mut with_fallback = Vec::new();
        collect_recent_config_files(
            &base_dir,
            2,
            started_after_1h,
            true,
            None,
            &stop,
            &mut with_fallback,
        );
        assert!(
            with_fallback
                .iter()
                .any(|c| c.path == normalize_os_path(&yaml_path) && c.preexisting_fallback),
            "existing YAML within 7 days must be discovered when fallback is enabled"
        );
        assert!(
            with_fallback
                .iter()
                .any(|c| c.path == normalize_os_path(&json_path) && c.preexisting_fallback),
            "existing JSON within 7 days must be discovered when fallback is enabled"
        );
        assert!(
            with_fallback
                .iter()
                .all(|c| c.path != normalize_os_path(&txt_path)),
            "preexisting fallback must ignore non-YAML/JSON txt files"
        );

        let mut without_fallback = Vec::new();
        collect_recent_config_files(
            &base_dir,
            2,
            started_after_1h,
            false,
            None,
            &stop,
            &mut without_fallback,
        );
        assert!(
            without_fallback.is_empty(),
            "disabling fallback must skip files older than started_wall"
        );

        // Simulate files older than 7 days (10 days before `started_wall`).
        let started_after_10d = SystemTime::now() + Duration::from_secs(10 * 24 * 3600);
        let mut expired = Vec::new();
        collect_recent_config_files(
            &base_dir,
            2,
            started_after_10d,
            true,
            None,
            &stop,
            &mut expired,
        );
        assert!(
            expired.is_empty(),
            "files older than 7 days must not be picked up by fallback"
        );
        let _ = std::fs::remove_dir_all(&base_dir);

        // Prioritized %TEMP% scan must not truncate freshly written configs behind >1600 junk files.
        let mock_temp =
            std::env::temp_dir().join(format!("catcloud-livecap-temp-prio-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&mock_temp).expect("create mock temp root");
        for idx in 0..(MAX_SCAN_ENTRIES_PER_ROOT + 120) {
            let junk = mock_temp.join(format!("junk_{idx:04}.tmp"));
            let _ = std::fs::write(&junk, b"x");
        }
        let fresh_top = mock_temp.join("zzz_ephemeral_top.yaml");
        let fresh_sub = mock_temp.join("zzz_fresh_subdir");
        std::fs::create_dir_all(&fresh_sub).expect("create fresh subdir");
        let fresh_nested = fresh_sub.join("runtime.yaml");
        let started_wall = SystemTime::now()
            .checked_sub(Duration::from_secs(2))
            .unwrap_or(UNIX_EPOCH);
        std::fs::write(&fresh_top, "proxies: []\n").expect("write fresh top yaml");
        std::fs::write(&fresh_nested, "proxies: []\n").expect("write fresh nested yaml");

        let mut temp_hits = Vec::new();
        collect_recent_temp_config_files(&mock_temp, started_wall, None, &stop, &mut temp_hits);
        assert!(
            temp_hits
                .iter()
                .any(|c| c.path == normalize_os_path(&fresh_top)),
            "fresh top-level temp YAML must survive >1600 sibling entries"
        );
        assert!(
            temp_hits
                .iter()
                .any(|c| c.path == normalize_os_path(&fresh_nested)),
            "fresh 1st-level temp subdir YAML must survive >1600 sibling entries"
        );
        let _ = std::fs::remove_dir_all(&mock_temp);
    }

    #[test]
    fn live_capture_has_active_session_and_respects_stop_flag_short_circuit() {
        let temp_dir =
            std::env::temp_dir().join(format!("catcloud-livecap-active-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).expect("create temp active dir");
        std::fs::write(temp_dir.join("probe.yaml"), "proxies: []\n").expect("write probe yaml");

        let stopped = AtomicBool::new(true);
        let mut out = Vec::new();
        collect_recent_config_files(&temp_dir, 2, UNIX_EPOCH, false, None, &stopped, &mut out);
        assert!(
            out.is_empty(),
            "pre-stopped flag must abort directory scan immediately"
        );
        assert_eq!(
            fetch_loopback_proxies_sync(
                "http://127.0.0.1:1",
                None,
                Duration::from_millis(200),
                &stopped
            ),
            ControllerProbeOutcome::TransportErr
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
                HashSet::new(),
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

    #[test]
    fn is_shared_system_dir_excludes_user_shared_roots_but_allows_dedicated_app_subdirs() {
        #[cfg(target_os = "windows")]
        {
            let home = Path::new(r"D:\Profiles\DemoUser");
            for excluded in [
                r"D:\Profiles\DemoUser",
                r"D:\Profiles\DemoUser\Desktop",
                r"d:\profiles\demouser\DESKTOP",
                r"D:\Profiles\DemoUser\Downloads",
                r"D:\Profiles\DemoUser\Documents",
                r"D:\Profiles\DemoUser\OneDrive",
                r"D:\Profiles\DemoUser\OneDrive\Desktop",
                r"C:\Users\runner",
                r"C:\Users\runner\Desktop",
                r"C:\Users\runner\DOWNLOADS",
                r"C:\Users\runner\Documents",
                r"C:\Users\runner\OneDrive",
            ] {
                assert!(
                    is_shared_system_dir_with_home(Path::new(excluded), Some(home)),
                    "expected Windows shared user dir `{excluded}` to be excluded"
                );
            }
            for allowed in [
                r"D:\Profiles\DemoUser\Desktop\PortableProxy",
                r"D:\Profiles\DemoUser\Downloads\FlClash",
                r"C:\Users\runner\AppData\Roaming\clash-verge",
                r"C:\Tools\MihomoPortable",
            ] {
                assert!(
                    !is_shared_system_dir_with_home(Path::new(allowed), Some(home)),
                    "expected dedicated app subdir `{allowed}` to remain watchable"
                );
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            let home = Path::new("/data/demouser");
            for excluded in [
                "/data/demouser",
                "/data/demouser/Desktop",
                "/data/demouser/downloads",
                "/data/demouser/Documents",
                "/home/catcloud",
                "/home/catcloud/Desktop",
                "/home/catcloud/Downloads",
                "/home/catcloud/Documents",
                "/Users/catcloud/Desktop",
            ] {
                assert!(
                    is_shared_system_dir_with_home(Path::new(excluded), Some(home)),
                    "expected Unix shared user dir `{excluded}` to be excluded"
                );
            }
            for allowed in [
                "/data/demouser/Desktop/PortableProxy",
                "/home/catcloud/Downloads/mihomo-dir",
                "/home/catcloud/.config/mihomo",
            ] {
                assert!(
                    !is_shared_system_dir_with_home(Path::new(allowed), Some(home)),
                    "expected dedicated app subdir `{allowed}` to remain watchable"
                );
            }
        }
    }

    #[test]
    fn controller_probe_retries_only_on_401_403_and_aborts_immediately_on_transport_error() {
        let stop = AtomicBool::new(false);

        // 1. 401/403 continues trying candidate secrets until the valid secret succeeds.
        //    Attempt order: endpoint_secret("stale-sec") -> None -> "wrong-sec" -> "right-sec" (4 attempts).
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind auth retry controller");
        let port = listener.local_addr().expect("addr").port();
        let auth_server = std::thread::spawn(move || {
            let mut hits = 0usize;
            for incoming in listener.incoming().take(4) {
                let Ok(mut stream) = incoming else {
                    break;
                };
                hits += 1;
                let mut req_buf = [0u8; 2048];
                let n = stream.read(&mut req_buf).unwrap_or(0);
                let req_str = String::from_utf8_lossy(&req_buf[..n]);
                if req_str.contains("Authorization: Bearer right-sec") {
                    let body = r#"{"proxies":{"JP-Auth":{"type":"Vless"}}}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    break;
                } else if hits % 2 == 1 {
                    let _ = stream.write_all(
                        b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                } else {
                    let _ = stream.write_all(
                        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                }
            }
            hits
        });

        let secrets = vec!["wrong-sec".to_string(), "right-sec".to_string()];
        let body = probe_loopback_proxies_with_secrets(
            &format!("http://127.0.0.1:{port}"),
            Some("stale-sec"),
            &secrets,
            Duration::from_secs(2),
            &stop,
        )
        .expect("probe must continue across 401/403 until matching secret succeeds");
        let auth_hits = auth_server.join().expect("join auth server");
        assert_eq!(auth_hits, 4, "expected 4 attempts across 401/403 until right-sec");
        assert!(String::from_utf8_lossy(&body).contains("JP-Auth"));

        // Verify direct Unauthorized classification for both HTTP 401 and 403.
        for status_line in ["HTTP/1.1 401 Unauthorized", "HTTP/1.1 403 Forbidden"] {
            let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind status mock");
            let p = l.local_addr().expect("status mock addr").port();
            let resp = format!("{status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let h = std::thread::spawn(move || {
                if let Ok((mut s, _)) = l.accept() {
                    let mut b = [0u8; 512];
                    let _ = s.read(&mut b);
                    let _ = s.write_all(resp.as_bytes());
                }
            });
            assert_eq!(
                fetch_loopback_proxies_sync(
                    &format!("http://127.0.0.1:{p}"),
                    None,
                    Duration::from_secs(1),
                    &stop,
                ),
                ControllerProbeOutcome::Unauthorized
            );
            let _ = h.join();
        }

        // 2. Non-auth error (HTTP 500) must abort immediately after 1 attempt without burning secrets.
        let err_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind 500 controller");
        let err_port = err_listener.local_addr().expect("err addr").port();
        err_listener
            .set_nonblocking(false)
            .expect("blocking listener");
        let err_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let err_hits_srv = Arc::clone(&err_hits);
        let err_server = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = err_listener.accept() {
                err_hits_srv.fetch_add(1, Ordering::SeqCst);
                let mut req_buf = [0u8; 1024];
                let _ = stream.read(&mut req_buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        });
        let many_secrets: Vec<String> = (1..=6).map(|i| format!("cand-sec-{i}")).collect();
        let none_body = probe_loopback_proxies_with_secrets(
            &format!("http://127.0.0.1:{err_port}"),
            Some("init-sec"),
            &many_secrets,
            Duration::from_millis(500),
            &stop,
        );
        let _ = err_server.join();
        assert!(none_body.is_none());
        assert_eq!(
            err_hits.load(Ordering::SeqCst),
            1,
            "transport/500 error must abort secret polling immediately after first attempt"
        );

        // 3. Closed loopback port returns TransportErr and aborts immediately.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("bind temp closed port");
        let closed_port = closed.local_addr().expect("closed addr").port();
        drop(closed);
        assert_eq!(
            fetch_loopback_proxies_sync(
                &format!("http://127.0.0.1:{closed_port}"),
                None,
                Duration::from_millis(300),
                &stop,
            ),
            ControllerProbeOutcome::TransportErr
        );
    }

    #[test]
    fn nested_json_secret_keys_never_pollute_controller_secrets_and_json_outbounds_align_validation()
    {
        let mut endpoints: HashMap<String, Option<String>> = HashMap::new();
        let mut secrets: Vec<String> = Vec::new();

        // Pretty-printed JSON containing 10 nested `"secret": "..."` fields inside unrelated objects
        // plus one real structured `experimental.clash_api.secret`.
        let mut nested_items = Vec::new();
        for i in 0..10 {
            nested_items.push(serde_json::json!({
                "name": format!("junk-{i}"),
                "secret": format!("nested-junk-secret-{i}")
            }));
        }
        let doc = serde_json::json!({
            "experimental": {
                "clash_api": {
                    "external_controller": "127.0.0.1:19095",
                    "secret": "real-clash-api-secret"
                }
            },
            "metadata": nested_items,
            "outbounds": [
                // Unsupported sing-box type -> must be skipped
                { "type": "wireguard", "tag": "WG-Ignored", "server": "203.0.113.40", "server_port": 51820 },
                // Missing ss password -> must be skipped
                { "type": "shadowsocks", "tag": "SS-Incomplete", "server": "203.0.113.41", "server_port": 8388, "method": "aes-256-gcm" },
                // Missing V2Ray/Xray vless uuid -> must be skipped
                {
                    "tag": "Xray-NoUUID",
                    "protocol": "vless",
                    "settings": { "vnext": [{ "address": "203.0.113.42", "port": 443, "users": [{}] }] }
                },
                // Valid V2Ray/Xray WS node with array header -> normalized to scalar String
                {
                    "tag": "JP Xray Valid",
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": "203.0.113.43",
                            "port": 443,
                            "users": [{ "id": "00000000-0000-4000-8000-000000000901" }]
                        }]
                    },
                    "streamSettings": {
                        "network": "ws",
                        "wsSettings": {
                            "path": "/xws",
                            "headers": { "Host": ["xray.example.invalid"] }
                        }
                    }
                },
                // Valid sing-box hy2 with 0 bandwidth and utls.enabled=false
                {
                    "type": "hysteria2",
                    "tag": "SG Hy2 Strict",
                    "server": "203.0.113.44",
                    "server_port": 443,
                    "password": "placeholder-hy2-secret",
                    "up_mbps": 0,
                    "down_mbps": 100,
                    "tls": {
                        "enabled": true,
                        "server_name": "hy2.example.invalid",
                        "utls": { "enabled": false, "fingerprint": "chrome" }
                    }
                }
            ]
        });
        let pretty = serde_json::to_string_pretty(&doc).expect("pretty json");

        match parse_captured_bytes("live_capture", pretty.as_bytes(), &mut endpoints, &mut secrets)
        {
            CapturedBytesOutcome::Nodes(nodes) => {
                assert_eq!(nodes.len(), 2);
                assert_eq!(nodes[0].name, "JP Xray Valid");
                assert_eq!(
                    nodes[0]
                        .raw_config
                        .get("ws-opts")
                        .and_then(|w| w.get("headers"))
                        .and_then(|h| h.get("Host"))
                        .and_then(serde_json::Value::as_str),
                    Some("xray.example.invalid")
                );
                assert_eq!(nodes[1].name, "SG Hy2 Strict");
                assert!(nodes[1].raw_config.get("up").is_none());
                assert_eq!(
                    nodes[1].raw_config.get("down").and_then(serde_json::Value::as_str),
                    Some("100 Mbps")
                );
                assert!(nodes[1].raw_config.get("client-fingerprint").is_none());
            }
            other => panic!("expected 2 validated nodes, got {other:?}"),
        }

        assert_eq!(secrets, vec!["real-clash-api-secret".to_string()]);
        assert_eq!(
            endpoints
                .get("http://127.0.0.1:19095")
                .and_then(|s| s.as_deref()),
            Some("real-clash-api-secret")
        );
    }

    #[test]
    fn pe_friendly_name_generic_shell_filtering_and_cache_eviction() {
        // Generic shell/runtime/placeholder titles must be filtered out.
        for generic in [
            "",
            "   ",
            "Electron",
            "tauri",
            "WebView2",
            "FlClash",
            "clash",
            "mihomo",
            "sing-box",
            "MainWindow",
            "Main Window",
            "main",
            "home",
            "index",
            "client",
            "desktop",
            "app",
            "window",
            "Untitled",
            "about:blank",
            "localhost",
            "127.0.0.1",
            "http://127.0.0.1:8080/index.html",
            "Electron App",
            "Tauri Desktop v2.0",
        ] {
            assert!(
                is_generic_shell_or_runtime_title(generic),
                "expected `{generic}` to be treated as generic shell/runtime title"
            );
        }

        // Genuine application titles must NOT be misclassified as generic.
        for genuine in [
            "Clash Verge Rev",
            "NekoBox for Windows",
            "Hiddify Next",
            "Sparkle Proxy",
            "Acme VPN Client",
            "V2RayN",
        ] {
            assert!(
                !is_generic_shell_or_runtime_title(genuine),
                "expected `{genuine}` to be preserved as non-generic app title"
            );
        }

        // Backward-compatible 2-arg signature remains unchanged.
        assert_eq!(derive_friendly_name("FlClash", "app.exe"), "FlClash");
        assert_eq!(derive_friendly_name("", "myclient.exe"), "myclient");

        // PE name wins when window_title is empty or generic and PE name is non-generic.
        assert_eq!(
            derive_friendly_name_with_pe("FlClash", "app.exe", Some("Acme Network Client")),
            "Acme Network Client"
        );
        assert_eq!(
            derive_friendly_name_with_pe("Electron", "client.exe", Some("Sample Proxy Studio")),
            "Sample Proxy Studio"
        );
        assert_eq!(
            derive_friendly_name_with_pe("", "client.exe", Some("Sample Tray VPN")),
            "Sample Tray VPN"
        );

        // Non-generic window_title takes precedence over PE name.
        assert_eq!(
            derive_friendly_name_with_pe("Clash Verge Rev", "clash-verge.exe", Some("Verge")),
            "Clash Verge Rev"
        );

        // When PE name is itself generic or missing, fall back cleanly to window_title or process stem.
        assert_eq!(
            derive_friendly_name_with_pe("FlClash", "FlClash.exe", Some("Electron")),
            "FlClash"
        );
        assert_eq!(
            derive_friendly_name_with_pe("", "nekobox.exe", Some("WebView2")),
            "nekobox"
        );
        assert_eq!(
            derive_friendly_name_with_pe("", "client.exe", Some("FlClash")),
            "FlClash"
        );

        // Translation candidate selector prefers non-generic FileDescription, then ProductName.
        let pairs = vec![
            (Some("Electron".to_string()), Some("Acme Proxy".to_string())),
            (
                Some("Acme Proxy Desktop".to_string()),
                Some("Acme".to_string()),
            ),
        ];
        assert_eq!(
            select_best_pe_name_from_pairs(&pairs).as_deref(),
            Some("Acme Proxy Desktop")
        );
        let fallback_prod = vec![(Some("MainWindow".to_string()), Some("Nimbus VPN".to_string()))];
        assert_eq!(
            select_best_pe_name_from_pairs(&fallback_prod).as_deref(),
            Some("Nimbus VPN")
        );

        // check_group_likely_proxy incorporates friendly_name, window_title subtitle, and pe_name.
        let empty_sys = System::new();
        assert!(check_group_likely_proxy(
            &empty_sys,
            &[],
            "Acme Client",
            "FlClash",
            Some("Acme Client")
        ));
        assert!(check_group_likely_proxy(
            &empty_sys,
            &[],
            "Acme Client",
            "MainWindow",
            Some("Acme VPN Helper")
        ));
        assert!(!check_group_likely_proxy(
            &empty_sys,
            &[],
            "Notes Editor",
            "Untitled",
            Some("Notes Editor")
        ));

        // Bounded 128-entry PE cache evicts oldest entries and keys by (path, len, mtime).
        let mut cache = PeNameCache::default();
        for i in 0..(MAX_PE_NAME_CACHE_ENTRIES + 10) {
            let key = (format!("app_{i}.exe"), 1024 + i as u64, 1_700_000_000u128);
            cache.insert(key, Some(format!("App {i}")));
        }
        assert_eq!(cache.len(), MAX_PE_NAME_CACHE_ENTRIES);
        assert_eq!(
            cache.get(&("app_0.exe".to_string(), 1024, 1_700_000_000u128)),
            None
        );
        assert_eq!(
            cache.get(&(
                format!("app_{}.exe", MAX_PE_NAME_CACHE_ENTRIES + 9),
                1024 + (MAX_PE_NAME_CACHE_ENTRIES + 9) as u64,
                1_700_000_000u128
            )),
            Some(Some(format!("App {}", MAX_PE_NAME_CACHE_ENTRIES + 9)))
        );
        // Same path with updated mtime is a distinct cache key.
        assert_eq!(
            cache.get(&(
                format!("app_{}.exe", MAX_PE_NAME_CACHE_ENTRIES + 9),
                1024 + (MAX_PE_NAME_CACHE_ENTRIES + 9) as u64,
                1_700_000_999u128
            )),
            None
        );
    }
}
