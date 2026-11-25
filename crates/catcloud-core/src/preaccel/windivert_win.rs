#![cfg_attr(target_arch = "aarch64", allow(dead_code, unused_imports))]

use crate::error::{CatError, CatResult};
use crate::models::GlobalPreAccelScope;
use crate::platform::windows::WindowsPlatform;
use crate::platform::{PlatformAdapter as _, SystemProxySpec};
use crate::preaccel::global_tunnel::{
    ExcludedPidTracker, GlobalPreAccelMetrics, Ipv4TcpMeta, MAX_NAT_ENTRIES, NAT_IDLE_TIMEOUT,
    NatEntry, NatPacketView, NatTable, SELF_TEST_DETECTED_BY, WinDivertAddress,
    build_security_guidance, build_windivert_filter_with_options, clamp_tcp_syn_mss,
    classify_intercept_process, classify_security_products_from_process_names,
    forward_redirected_stream, is_domestic_ipv4, is_non_proxy_communication_process,
    is_open_source_proxy_core_name, is_physical_nic_descriptor, is_system_or_self_excluded_process,
    normalize_process_basename, parse_ipv4_tcp_packet, rewrite_ipv4_tcp_from_loopback,
    rewrite_ipv4_tcp_to_loopback, should_intercept_port_443,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::{CString, OsStr, c_void};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawSocket;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, UdpSocket};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinHandle as TokioJoinHandle;
use url::Url;
use windows_sys::Win32::Foundation::{
    BOOL, CloseHandle, ERROR_BUFFER_OVERFLOW, ERROR_INSUFFICIENT_BUFFER, FreeLibrary,
    GetLastError, HANDLE, HMODULE, INVALID_HANDLE_VALUE, NO_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses,
    GetExtendedTcpTable, GetIfTable, GetIpForwardTable, IP_ADAPTER_ADDRESSES_LH, MIB_IFROW,
    MIB_IFTABLE, MIB_IPFORWARDROW, MIB_IPFORWARDTABLE, MIB_TCPROW_OWNER_PID,
    MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_CONNECTIONS, TCP_TABLE_OWNER_PID_LISTENER,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, IP_UNICAST_IF, IPPROTO_IP, SOCKADDR_IN, SOCKET, WSAGetLastError, setsockopt,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_WITH_ALTERED_SEARCH_PATH, LoadLibraryExW, LoadLibraryW,
};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QueryServiceStatus,
    SC_HANDLE, SC_MANAGER_CONNECT, SERVICE_CONTROL_STOP, SERVICE_QUERY_STATUS, SERVICE_STATUS,
    SERVICE_STOP, SERVICE_STOPPED,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

const WINDIVERT_LAYER_NETWORK: i32 = 0;
const WINDIVERT_SHUTDOWN_BOTH: i32 = 3;
const WINDIVERT_PARAM_QUEUE_LENGTH: i32 = 0;
const WINDIVERT_PARAM_QUEUE_TIME: i32 = 1;
const WINDIVERT_PARAM_QUEUE_SIZE: i32 = 2;
const WINDIVERT_QUEUE_LENGTH: u64 = 8192;
const WINDIVERT_QUEUE_SIZE_BYTES: u64 = 16 * 1024 * 1024;
const WINDIVERT_SERVICE_NAME: &str = "WinDivert";
const WINDIVERT_SERVICE_STOP_TIMEOUT: Duration = Duration::from_millis(700);
const WINDIVERT_SERVICE_STOP_POLL_INTERVAL: Duration = Duration::from_millis(50);
const STANDARD_ETHERNET_TCP_MSS: u16 = 1460;
const ERROR_SERVICE_MARKED_FOR_DELETE: u32 = 1072;
const MIB_TCP_STATE_SYN_SENT: u32 = 3;

const MAX_BYPASS_CACHE_ENTRIES: usize = 4096;
const BYPASS_CACHE_TTL: Duration = Duration::from_secs(30);
const MAX_PID_CACHE_ENTRIES: usize = 512;
const PID_CACHE_TTL: Duration = Duration::from_secs(10);
const RUNTIME_TABLE_REFRESH_INTERVAL: Duration = Duration::from_secs(2);
const MAX_CONCURRENT_REDIRECT_CONNS: usize = 512;

/// Well-known non-proxy system, database, remote-desktop, and local service ports ignored
/// when auto-detecting local proxy listener PIDs (unless explicitly configured as the live
/// Windows system proxy port).
const EXCLUDED_NON_PROXY_LISTENER_PORTS: &[u16] = &[
    1433,  // MSSQL
    1434,  // MSSQL Browser
    1521,  // Oracle DB
    2179,  // Hyper-V VMConnect
    3306,  // MySQL / MariaDB
    3389,  // RDP
    5040,  // Windows Connected Devices Platform
    5357,  // WSDAPI
    5432,  // PostgreSQL
    5985,  // WinRM HTTP
    5986,  // WinRM HTTPS
    6379,  // Redis
    7680,  // Windows Delivery Optimization
    11211, // Memcached
    14588, // Known non-proxy local service port
    27017, // MongoDB
];

/// Well-known non-proxy database and OS background service executables ignored when
/// labeling `local_proxy_listener` PIDs.
const EXCLUDED_NON_PROXY_LISTENER_PROCESSES: &[&str] = &[
    "mysqld.exe",
    "mariadbd.exe",
    "postgres.exe",
    "redis-server.exe",
    "mongod.exe",
    "sqlservr.exe",
    "spoolsv.exe",
    "dllhost.exe",
    "dashost.exe",
    "sihost.exe",
    "searchindexer.exe",
    "dwm.exe",
    "mpdefendercoreservice.exe",
    "msmpeng.exe",
    "vsserv.exe",
    "hipsdaemon.exe",
    "qqpcsvc.exe",
    "itunes.exe",
    "ituneshelper.exe",
    "gamingservices.exe",
    "gamingservicesnet.exe",
    "wslservice.exe",
    "vmware-authd.exe",
    "vmware-hostd.exe",
];

struct ScopedHandle(HANDLE);

impl Drop for ScopedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: Valid Win32 handle owned exclusively by this guard.
            unsafe {
                let _ = CloseHandle(self.0);
            }
            self.0 = std::ptr::null_mut();
        }
    }
}

type FnWinDivertOpen = unsafe extern "system" fn(*const u8, i32, i16, u64) -> HANDLE;
type FnWinDivertRecv =
    unsafe extern "system" fn(HANDLE, *mut c_void, u32, *mut u32, *mut WinDivertAddress) -> BOOL;
type FnWinDivertSend =
    unsafe extern "system" fn(HANDLE, *const c_void, u32, *mut u32, *const WinDivertAddress) -> BOOL;
type FnWinDivertShutdown = unsafe extern "system" fn(HANDLE, i32) -> BOOL;
type FnWinDivertClose = unsafe extern "system" fn(HANDLE) -> BOOL;
type FnWinDivertSetParam = unsafe extern "system" fn(HANDLE, i32, u64) -> BOOL;
type FnWinDivertHelperCalcChecksums =
    unsafe extern "system" fn(*mut c_void, u32, *mut WinDivertAddress, u64) -> BOOL;

struct SendHandle(HANDLE);
// SAFETY: WinDivert kernel handles are explicitly documented thread-safe for concurrent
// `WinDivertShutdown` wakeup from control thread while worker blocks on `WinDivertRecv`.
unsafe impl Send for SendHandle {}
unsafe impl Sync for SendHandle {}

/// Dynamically loaded `WinDivert64.dll` / `WinDivert.dll` symbol table (zero external crates).
struct WinDivertLib {
    module: HMODULE,
    open: FnWinDivertOpen,
    recv: FnWinDivertRecv,
    send: FnWinDivertSend,
    shutdown: FnWinDivertShutdown,
    close: FnWinDivertClose,
    set_param: Option<FnWinDivertSetParam>,
    calc_checksums: FnWinDivertHelperCalcChecksums,
}

// SAFETY: Loaded DLL module handle and immutable resolved C function pointers are safe to share
// across threads while `WinDivertLib` stays alive via `Arc`.
unsafe impl Send for WinDivertLib {}
unsafe impl Sync for WinDivertLib {}

impl WinDivertLib {
    fn load(dll_path: &Path) -> CatResult<Self> {
        let wide: Vec<u16> = OsStr::new(dll_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // SAFETY: `wide` is a valid NUL-terminated UTF-16 path.
        let mut module =
            unsafe { LoadLibraryExW(wide.as_ptr(), std::ptr::null_mut(), LOAD_WITH_ALTERED_SEARCH_PATH) };
        if module.is_null() {
            module = unsafe { LoadLibraryW(wide.as_ptr()) };
        }
        if module.is_null() {
            let err = unsafe { GetLastError() };
            return Err(CatError::Core(format!(
                "加载 WinDivert DLL 失败 (`{}`, win32_err={err})，请检查文件是否被安全软件隔离",
                dll_path.display()
            )));
        }

        let resolve_required = |symbol: &str| -> CatResult<unsafe extern "system" fn() -> isize> {
            let cname = CString::new(symbol)
                .map_err(|e| CatError::Core(format!("invalid symbol `{symbol}`: {e}")))?;
            // SAFETY: `module` is valid and `cname` is NUL-terminated ASCII.
            let proc = unsafe { GetProcAddress(module, cname.as_ptr().cast()) };
            proc.ok_or_else(|| {
                CatError::Core(format!(
                    "WinDivert DLL 缺少导出函数 `{symbol}`，请确认使用官方 v2.2.2 版本"
                ))
            })
        };

        let open_raw = match resolve_required("WinDivertOpen") {
            Ok(p) => p,
            Err(e) => {
                unsafe {
                    let _ = FreeLibrary(module);
                }
                return Err(e);
            }
        };
        let recv_raw = match resolve_required("WinDivertRecv") {
            Ok(p) => p,
            Err(e) => {
                unsafe {
                    let _ = FreeLibrary(module);
                }
                return Err(e);
            }
        };
        let send_raw = match resolve_required("WinDivertSend") {
            Ok(p) => p,
            Err(e) => {
                unsafe {
                    let _ = FreeLibrary(module);
                }
                return Err(e);
            }
        };
        let shutdown_raw = match resolve_required("WinDivertShutdown") {
            Ok(p) => p,
            Err(e) => {
                unsafe {
                    let _ = FreeLibrary(module);
                }
                return Err(e);
            }
        };
        let close_raw = match resolve_required("WinDivertClose") {
            Ok(p) => p,
            Err(e) => {
                unsafe {
                    let _ = FreeLibrary(module);
                }
                return Err(e);
            }
        };
        let checksum_raw = match resolve_required("WinDivertHelperCalcChecksums") {
            Ok(p) => p,
            Err(e) => {
                unsafe {
                    let _ = FreeLibrary(module);
                }
                return Err(e);
            }
        };

        let set_param = {
            let cname = CString::new("WinDivertSetParam").expect("static ascii");
            // SAFETY: Optional symbol lookup on valid `module`.
            unsafe { GetProcAddress(module, cname.as_ptr().cast()) }.map(|p| {
                // SAFETY: Matches official WinDivert v2.2.2 `WinDivertSetParam` ABI.
                unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, FnWinDivertSetParam>(p) }
            })
        };

        // SAFETY: All function signatures match official `basil00/Divert` v2.2.2 `windivert.h`.
        let (open, recv, send, shutdown, close, calc_checksums) = unsafe {
            (
                std::mem::transmute::<unsafe extern "system" fn() -> isize, FnWinDivertOpen>(open_raw),
                std::mem::transmute::<unsafe extern "system" fn() -> isize, FnWinDivertRecv>(recv_raw),
                std::mem::transmute::<unsafe extern "system" fn() -> isize, FnWinDivertSend>(send_raw),
                std::mem::transmute::<unsafe extern "system" fn() -> isize, FnWinDivertShutdown>(shutdown_raw),
                std::mem::transmute::<unsafe extern "system" fn() -> isize, FnWinDivertClose>(close_raw),
                std::mem::transmute::<unsafe extern "system" fn() -> isize, FnWinDivertHelperCalcChecksums>(checksum_raw),
            )
        };

        Ok(Self {
            module,
            open,
            recv,
            send,
            shutdown,
            close,
            set_param,
            calc_checksums,
        })
    }
}

impl Drop for WinDivertLib {
    fn drop(&mut self) {
        if !self.module.is_null() {
            // SAFETY: All WinDivert handles and worker threads have already been closed/joined.
            unsafe {
                let _ = FreeLibrary(self.module);
            }
            self.module = std::ptr::null_mut();
        }
    }
}

struct ScopedScHandle(SC_HANDLE);

impl Drop for ScopedScHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Valid Service Control Manager or Service handle owned exclusively by this guard.
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
            self.0 = std::ptr::null_mut();
        }
    }
}

/// Best-effort bounded stop of the `WinDivert` kernel driver service via Windows SCM
/// (`ControlService(SERVICE_CONTROL_STOP)` + 50ms poll up to 700ms).
///
/// Intentionally NEVER calls `DeleteService` to prevent `ERROR_SERVICE_MARKED_FOR_DELETE (1072)`
/// races on rapid re-enable and to avoid disrupting unrelated tools sharing WinDivert on the host.
pub(super) fn stop_windivert_kernel_service() -> bool {
    // SAFETY: Read-only connect to local SCM; deterministically closed by `ScopedScHandle`.
    let scm_raw =
        unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if scm_raw.is_null() {
        return false;
    }
    let scm = ScopedScHandle(scm_raw);

    let service_wide: Vec<u16> = WINDIVERT_SERVICE_NAME
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
        // Only fall through to bounded status polling when SCM reports the service is already
        // mid-transition (1061); fail fast on access-denied or external-handle refusal so
        // shutdown never stalls for 700ms unnecessarily.
        if err != ERROR_SERVICE_CANNOT_ACCEPT_CTRL {
            return false;
        }
    } else if status.dwCurrentState == SERVICE_STOPPED {
        return true;
    }

    let deadline = Instant::now() + WINDIVERT_SERVICE_STOP_TIMEOUT;
    while Instant::now() < deadline {
        std::thread::sleep(WINDIVERT_SERVICE_STOP_POLL_INTERVAL);
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

/// Runtime parameters passed to start the Windows transparent WinDivert TCP NAT engine.
pub struct WinDivertEngineConfig {
    pub dll_path: std::path::PathBuf,
    pub socks_port: u16,
    pub relay_ipv4s: Vec<Ipv4Addr>,
    pub skip_443_native: bool,
    pub scope: GlobalPreAccelScope,
    pub target_processes: Vec<String>,
    pub excluded_pids: HashSet<u32>,
    pub tunnel_pid: Option<u32>,
    pub main_core_pid: Option<u32>,
    pub metrics: Arc<GlobalPreAccelMetrics>,
}

/// Confirmed active physical Ethernet/Wi-Fi exit adapter metadata (excluding Wintun/TUN/VPN).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PhysicalExitInterface {
    pub if_idx: u32,
    pub friendly_name: String,
    pub local_ipv4: Ipv4Addr,
}

/// Outcome of the built-in end-to-end WinDivert loopback dataplane self-test probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum WinDivertSelfTestOutcome {
    Passed {
        latency_ms: u64,
        probe_host: String,
        status_code: u16,
    },
    BlockedAtDataplane {
        intercepted: u64,
        accepted: u64,
        send_errors: u64,
        detail: String,
    },
    NoPacketIntercepted {
        detail: String,
    },
    TunnelUnreachable {
        detail: String,
    },
}

/// RAII guard resetting `self_test_src_port` back to `0` on scope exit or cancellation.
struct SelfTestPortGuard {
    slot: Arc<AtomicU16>,
}

impl Drop for SelfTestPortGuard {
    fn drop(&mut self) {
        self.slot.store(0, Ordering::SeqCst);
    }
}

/// Active Windows WinDivert kernel transparent TCP interceptor + local loopback SOCKS5 forwarder.
pub struct WinDivertEngine {
    lib: Arc<WinDivertLib>,
    handle: SendHandle,
    stop_flag: Arc<AtomicBool>,
    shutdown_tx: watch::Sender<bool>,
    excluded_pid_tracker: Arc<ExcludedPidTracker>,
    physical_ifs: Arc<RwLock<HashSet<u32>>>,
    self_test_src_port: Arc<AtomicU16>,
    self_test_intercepted: Arc<AtomicU64>,
    self_test_accepted: Arc<AtomicU64>,
    send_errors: Arc<AtomicU64>,
    worker_thread: Option<JoinHandle<()>>,
    accept_task: Option<TokioJoinHandle<()>>,
    refresh_task: Option<TokioJoinHandle<()>>,
    redirect_port: u16,
    stopped: bool,
    service_torn_down: bool,
}

impl std::fmt::Debug for WinDivertEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WinDivertEngine")
            .field("redirect_port", &self.redirect_port)
            .field("running", &(!self.stop_flag.load(Ordering::Relaxed)))
            .field("send_errors", &self.send_errors.load(Ordering::Relaxed))
            .finish()
    }
}

impl WinDivertEngine {
    /// Start the local `127.0.0.1:0` loopback TCP redirector and open the WinDivert kernel filter.
    pub async fn start(cfg: WinDivertEngineConfig) -> CatResult<Self> {
        #[cfg(target_arch = "aarch64")]
        {
            let _ = cfg;
            return Err(CatError::Validation(
                crate::preaccel::global_tunnel::WINDIVERT_ARM64_UNSUPPORTED_MSG.to_string(),
            ));
        }

        #[cfg(not(target_arch = "aarch64"))]
        {
            let lib = Arc::new(WinDivertLib::load(&cfg.dll_path)?);

            // Bind strictly to `127.0.0.1:0` loopback so Windows Defender / third-party firewalls
            // allow redirected connections natively with zero LAN exposure and zero firewall popups.
            let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
                .await
                .map_err(|e| CatError::Process(format!("绑定本地透明重定向监听端口失败: {e}")))?;
            let redirect_port = listener.local_addr()?.port();

            let target_processes_lower: HashSet<String> = cfg
                .target_processes
                .iter()
                .map(|p| normalize_process_basename(p))
                .filter(|p| !p.is_empty())
                .collect();

            let excluded_pid_tracker = Arc::new(ExcludedPidTracker::new(
                std::process::id(),
                cfg.tunnel_pid,
                cfg.excluded_pids,
                cfg.main_core_pid,
            ));
            let detected_proxy_pids: Arc<RwLock<HashMap<u32, &'static str>>> =
                Arc::new(RwLock::new(HashMap::new()));
            let physical_ifs: Arc<RwLock<HashSet<u32>>> =
                Arc::new(RwLock::new(HashSet::new()));

            // Perform one initial background-pool scan BEFORE opening the WinDivert kernel handle
            // so (1) full CatCloud descendant PIDs, active proxy hosts, and physical NICs are ready
            // from the very first SYN packet, (2) zero packets queue in the kernel while scanning,
            // and (3) no raw Win32 `HANDLE` is ever held across an `.await` point.
            {
                let tracker_init = Arc::clone(&excluded_pid_tracker);
                let detected_init = Arc::clone(&detected_proxy_pids);
                let ifs_init = Arc::clone(&physical_ifs);
                let _ = tokio::task::spawn_blocking(move || {
                    let mut init_cache: HashMap<u32, (String, Instant)> = HashMap::with_capacity(64);
                    refresh_runtime_tables(
                        &tracker_init,
                        &detected_init,
                        &ifs_init,
                        &mut init_cache,
                    );
                })
                .await;
            }

            let filter_str = build_windivert_filter_with_options(
                &cfg.relay_ipv4s,
                redirect_port,
                cfg.skip_443_native,
            );
            let filter_cstr = CString::new(filter_str.as_str()).map_err(|e| {
                CatError::Validation(format!("WinDivert 过滤表达式包含非法字符: {e}"))
            })?;

            // Retry briefly if Windows reports `ERROR_SERVICE_MARKED_FOR_DELETE (1072)` right after
            // a prior WinDivert service teardown. Wrap handle in `SendHandle` so the `async` future
            // remains strictly `Send` across the retry `sleep().await`.
            let mut opened_handle = SendHandle(INVALID_HANDLE_VALUE);
            let mut open_err: u32 = 0;
            for attempt in 0..4 {
                let attempt_res: Result<SendHandle, u32> = {
                    // SAFETY: `filter_cstr` is a valid NUL-terminated ASCII filter for `WINDIVERT_LAYER_NETWORK`.
                    let h = unsafe {
                        (lib.open)(
                            filter_cstr.as_ptr().cast(),
                            WINDIVERT_LAYER_NETWORK,
                            0,
                            0,
                        )
                    };
                    if !h.is_null() && h != INVALID_HANDLE_VALUE {
                        Ok(SendHandle(h))
                    } else {
                        Err(unsafe { GetLastError() })
                    }
                };
                match attempt_res {
                    Ok(valid) => {
                        opened_handle = valid;
                        open_err = 0;
                        break;
                    }
                    Err(err) => {
                        open_err = err;
                        if open_err == ERROR_SERVICE_MARKED_FOR_DELETE && attempt < 3 {
                            tokio::time::sleep(Duration::from_millis(250)).await;
                            continue;
                        }
                        break;
                    }
                }
            }
            let raw_handle: HANDLE = opened_handle.0;

            if raw_handle.is_null() || raw_handle == INVALID_HANDLE_VALUE {
                let detected_products = detect_windows_security_products();
                let bin_dir = cfg.dll_path.parent();
                let sec_hint =
                    build_security_guidance(&detected_products, bin_dir, "driver_load");
                let hint = match open_err {
                    5 => "权限不足（错误码 5），请以管理员身份运行猫猫云梯".to_string(),
                    2 => format!("未找到 WinDivert64.sys 驱动文件（错误码 2，可能被安全软件隔离）。{sec_hint}"),
                    577 => format!("Windows 驱动签名或安全策略拦截了 WinDivert64.sys（错误码 577）。{sec_hint}"),
                    1072 => "旧版 WinDivert 驱动服务仍在卸载中（错误码 1072），请稍等几秒重试或重启电脑".to_string(),
                    1275 => format!("驱动加载被安全软件或系统策略拦截（错误码 1275）。{sec_hint}"),
                    _ => format!("请确认已管理员运行且安全软件未拦截 WinDivert64.sys。{sec_hint}"),
                };
                return Err(CatError::Core(format!(
                    "WinDivertOpen 启动失败 (win32_err={open_err}): {hint}"
                )));
            }

            if let Some(set_param) = lib.set_param {
                // SAFETY: `raw_handle` is a newly opened valid WinDivert handle.
                unsafe {
                    let _ = set_param(raw_handle, WINDIVERT_PARAM_QUEUE_LENGTH, WINDIVERT_QUEUE_LENGTH);
                    let _ = set_param(raw_handle, WINDIVERT_PARAM_QUEUE_TIME, 2000);
                    let _ = set_param(
                        raw_handle,
                        WINDIVERT_PARAM_QUEUE_SIZE,
                        WINDIVERT_QUEUE_SIZE_BYTES,
                    );
                }
            }

            let nat_table = Arc::new(NatTable::new(MAX_NAT_ENTRIES, NAT_IDLE_TIMEOUT));
            let stop_flag = Arc::new(AtomicBool::new(false));
            let (shutdown_tx, mut accept_shutdown_rx) = watch::channel(false);
            let self_test_src_port = Arc::new(AtomicU16::new(0));
            let self_test_intercepted = Arc::new(AtomicU64::new(0));
            let self_test_accepted = Arc::new(AtomicU64::new(0));
            let send_errors = Arc::new(AtomicU64::new(0));

            // Spawn Tokio accept loop forwarding NAT-verified loopback flows to the standalone 443
            // SOCKS5 tunnel, capped at `MAX_CONCURRENT_REDIRECT_CONNS` concurrent forwarder tasks.
            let nat_for_accept = Arc::clone(&nat_table);
            let metrics_for_accept = Arc::clone(&cfg.metrics);
            let self_test_accepted_for_accept = Arc::clone(&self_test_accepted);
            let socks_port = cfg.socks_port;
            let conn_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_REDIRECT_CONNS));
            let accept_task = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        changed = accept_shutdown_rx.changed() => {
                            if changed.is_err() || *accept_shutdown_rx.borrow() {
                                break;
                            }
                        }
                        accepted = listener.accept() => {
                            match accepted {
                                Ok((stream, peer_addr)) => {
                                    let Ok(permit) = Arc::clone(&conn_semaphore).try_acquire_owned() else {
                                        tracing::debug!(
                                            "global preaccel redirector concurrency limit ({MAX_CONCURRENT_REDIRECT_CONNS}) reached; dropping connection from {peer_addr}"
                                        );
                                        drop(stream);
                                        continue;
                                    };
                                    let nat_ref = Arc::clone(&nat_for_accept);
                                    let metrics_ref = Arc::clone(&metrics_for_accept);
                                    let self_test_acc_ref = Arc::clone(&self_test_accepted_for_accept);
                                    let conn_shutdown = accept_shutdown_rx.clone();
                                    tokio::spawn(async move {
                                        let _permit = permit;
                                        forward_redirected_stream(
                                            stream,
                                            peer_addr,
                                            socks_port,
                                            nat_ref,
                                            metrics_ref,
                                            conn_shutdown,
                                            Some(self_test_acc_ref),
                                        ).await;
                                    });
                                }
                                Err(err) => {
                                    tracing::debug!("global preaccel redirector accept error: {err}");
                                    if *accept_shutdown_rx.borrow() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            });

            // Spawn periodic 2s background table refresher completely off the WinDivert packet
            // worker hot path.
            let mut refresh_shutdown_rx = shutdown_tx.subscribe();
            let tracker_refresh = Arc::clone(&excluded_pid_tracker);
            let detected_refresh = Arc::clone(&detected_proxy_pids);
            let ifs_refresh = Arc::clone(&physical_ifs);
            let refresh_task = tokio::spawn(async move {
                let mut ticker = tokio::time::interval(RUNTIME_TABLE_REFRESH_INTERVAL);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                // Consume immediate first tick (already scanned synchronously above).
                ticker.tick().await;
                let mut shared_name_cache: Option<HashMap<u32, (String, Instant)>> =
                    Some(HashMap::with_capacity(64));

                loop {
                    tokio::select! {
                        changed = refresh_shutdown_rx.changed() => {
                            if changed.is_err() || *refresh_shutdown_rx.borrow() {
                                break;
                            }
                        }
                        _ = ticker.tick() => {
                            if *refresh_shutdown_rx.borrow() {
                                break;
                            }
                            let tracker = Arc::clone(&tracker_refresh);
                            let detected = Arc::clone(&detected_refresh);
                            let ifs = Arc::clone(&ifs_refresh);
                            let mut cache = shared_name_cache
                                .take()
                                .unwrap_or_else(|| HashMap::with_capacity(64));
                            let res = tokio::task::spawn_blocking(move || {
                                refresh_runtime_tables(&tracker, &detected, &ifs, &mut cache);
                                cache
                            })
                            .await;
                            if let Ok(returned_cache) = res {
                                shared_name_cache = Some(returned_cache);
                            }
                        }
                    }
                }
            });

            let worker_ctx = PacketWorkerContext {
                lib: Arc::clone(&lib),
                handle: SendHandle(raw_handle),
                stop_flag: Arc::clone(&stop_flag),
                nat_table,
                redirect_port,
                skip_443_native: cfg.skip_443_native,
                scope: cfg.scope,
                target_processes_lower,
                excluded_pids: excluded_pid_tracker.shared_set(),
                detected_proxy_pids,
                physical_ifs: Arc::clone(&physical_ifs),
                self_test_src_port: Arc::clone(&self_test_src_port),
                self_test_intercepted: Arc::clone(&self_test_intercepted),
                send_errors: Arc::clone(&send_errors),
            };

            let worker_thread = std::thread::Builder::new()
                .name("catcloud-windivert".to_string())
                .spawn(move || run_packet_worker(worker_ctx))
                .map_err(|e| {
                    let _ = shutdown_tx.send(true);
                    accept_task.abort();
                    refresh_task.abort();
                    unsafe {
                        let _ = (lib.shutdown)(raw_handle, WINDIVERT_SHUTDOWN_BOTH);
                        let _ = (lib.close)(raw_handle);
                    }
                    CatError::Process(format!("启动 WinDivert 抓包线程失败: {e}"))
                })?;

            tracing::info!(
                "WinDivert loopback transparent redirector started on 127.0.0.1:{redirect_port} -> standalone SOCKS5 127.0.0.1:{socks_port}"
            );

            Ok(Self {
                lib,
                handle: SendHandle(raw_handle),
                stop_flag,
                shutdown_tx,
                excluded_pid_tracker,
                physical_ifs,
                self_test_src_port,
                self_test_intercepted,
                self_test_accepted,
                send_errors,
                worker_thread: Some(worker_thread),
                accept_task: Some(accept_task),
                refresh_task: Some(refresh_task),
                redirect_port,
                stopped: false,
                service_torn_down: false,
            })
        }
    }

    /// Execute an active end-to-end dataplane self-test verifying that a real outbound non-443
    /// TCP connection bound to the primary physical NIC is (1) intercepted by WinDivert,
    /// (2) reflected cleanly across loopback into our local `127.0.0.1:<redirect_port>` listener,
    /// (3) forwarded through the standalone `:443` SOCKS5 tunnel, and (4) returns a valid HTTP
    /// response back to the originating client socket.
    pub(super) async fn run_self_test(
        &self,
        probe_urls: &[&str],
        timeout: Duration,
    ) -> WinDivertSelfTestOutcome {
        let physical = match tokio::task::spawn_blocking(detect_primary_physical_interface)
            .await
            .ok()
            .flatten()
        {
            Some(nic) => nic,
            None => {
                return WinDivertSelfTestOutcome::NoPacketIntercepted {
                    detail: "未检测到已连接的物理以太网或 Wi-Fi 出口网卡（请检查网络连接）"
                        .to_string(),
                };
            }
        };

        // Ensure the confirmed primary physical interface index is present in `physical_ifs`.
        {
            let mut guard = self
                .physical_ifs
                .write()
                .unwrap_or_else(|e| e.into_inner());
            guard.insert(physical.if_idx);
        }

        let mut last_failure: Option<WinDivertSelfTestOutcome> = None;

        for &raw_url in probe_urls {
            let Ok(parsed) = Url::parse(raw_url.trim()) else {
                continue;
            };
            let Some(host) = parsed.host_str().map(ToString::to_string) else {
                continue;
            };
            let port = parsed.port_or_known_default().unwrap_or(80);
            if port == 443 || port == 53 {
                continue;
            }
            let path = if parsed.path().is_empty() {
                "/"
            } else {
                parsed.path()
            };

            // Resolve a real public IPv4 (bypassing third-party TUN Fake-IP 198.18.0.0/15 DNS
            // hijacking by querying domestic public DNS directly over the physical NIC if needed).
            let Some(target_ip) = resolve_public_ipv4_for_self_test(
                &host,
                port,
                physical.local_ipv4,
                physical.if_idx,
            )
            .await
            else {
                last_failure = Some(WinDivertSelfTestOutcome::TunnelUnreachable {
                    detail: format!("无法解析国内探测域名 {host} 的真实公网 IPv4"),
                });
                continue;
            };

            let before_intercepted = self.self_test_intercepted.load(Ordering::SeqCst);
            let before_accepted = self.self_test_accepted.load(Ordering::SeqCst);
            let before_send_err = self.send_errors.load(Ordering::SeqCst);

            let sock = match TcpSocket::new_v4() {
                Ok(s) => s,
                Err(e) => {
                    last_failure = Some(WinDivertSelfTestOutcome::NoPacketIntercepted {
                        detail: format!("创建探测套接字失败: {e}"),
                    });
                    continue;
                }
            };
            if let Err(e) = sock.bind(SocketAddr::V4(SocketAddrV4::new(physical.local_ipv4, 0))) {
                last_failure = Some(WinDivertSelfTestOutcome::NoPacketIntercepted {
                    detail: format!("绑定物理网卡本机地址 {} 失败: {e}", physical.local_ipv4),
                });
                continue;
            }
            if let Err(e) =
                set_ipv4_unicast_interface(sock.as_raw_socket() as usize, physical.if_idx)
            {
                last_failure = Some(WinDivertSelfTestOutcome::NoPacketIntercepted {
                    detail: format!(
                        "绑定物理网卡出站接口 IP_UNICAST_IF (if_idx={}) 失败: {e}",
                        physical.if_idx
                    ),
                });
                continue;
            }
            let local_port = match sock.local_addr() {
                Ok(SocketAddr::V4(v4)) => v4.port(),
                _ => continue,
            };

            self.self_test_src_port.store(local_port, Ordering::SeqCst);
            let _port_guard = SelfTestPortGuard {
                slot: Arc::clone(&self.self_test_src_port),
            };

            let started = Instant::now();
            let probe_io = tokio::time::timeout(timeout, async {
                let mut stream = sock
                    .connect(SocketAddr::V4(SocketAddrV4::new(target_ip, port)))
                    .await?;
                let _ = stream.set_nodelay(true);
                let req = format!(
                    "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: CatCloud-SelfTest/1.0\r\nConnection: close\r\n\r\n"
                );
                stream.write_all(req.as_bytes()).await?;
                read_http_status_code_from_stream(&mut stream).await
            })
            .await;

            // Give the accept/worker threads a brief 40ms window to flush atomic counters.
            tokio::time::sleep(Duration::from_millis(40)).await;
            let intercepted_delta = self
                .self_test_intercepted
                .load(Ordering::SeqCst)
                .saturating_sub(before_intercepted);
            let accepted_delta = self
                .self_test_accepted
                .load(Ordering::SeqCst)
                .saturating_sub(before_accepted);
            let send_err_delta = self
                .send_errors
                .load(Ordering::SeqCst)
                .saturating_sub(before_send_err);
            let latency_ms = started.elapsed().as_millis().max(1) as u64;

            match probe_io {
                Ok(Ok(Some(status_code))) => {
                    if intercepted_delta > 0 && accepted_delta > 0 {
                        tracing::info!(
                            "WinDivert dataplane self-test PASSED via {}:{} ({host}, HTTP {status_code}, {latency_ms}ms, nic={}, intercepted={intercepted_delta}, accepted={accepted_delta})",
                            target_ip,
                            port,
                            physical.friendly_name
                        );
                        return WinDivertSelfTestOutcome::Passed {
                            latency_ms,
                            probe_host: host,
                            status_code,
                        };
                    }
                    last_failure = Some(WinDivertSelfTestOutcome::NoPacketIntercepted {
                        detail: format!(
                            "测试连接虽连通 {host}，但未命中底层抓包路径（nic={}，intercepted={intercepted_delta}，accepted={accepted_delta}）",
                            physical.friendly_name
                        ),
                    });
                }
                Ok(Ok(None)) | Ok(Err(_)) | Err(_) => {
                    let err_note = match probe_io {
                        Err(_) => format!("连接或读取 {host} 超时（{} ms）", timeout.as_millis()),
                        Ok(Err(e)) => format!("连接 {host} 失败：{e}"),
                        Ok(Ok(None)) => format!("{host} 返回了非标准 HTTP 响应"),
                        Ok(Ok(Some(code))) => format!("{host} 返回 HTTP {code}"),
                    };
                    if intercepted_delta > 0 && accepted_delta == 0 {
                        // Definitive dataplane/firewall block: do not retry other URLs needlessly.
                        tracing::warn!(
                            "WinDivert dataplane self-test BLOCKED: {err_note} (intercepted={intercepted_delta}, accepted=0, send_errors={send_err_delta})"
                        );
                        return WinDivertSelfTestOutcome::BlockedAtDataplane {
                            intercepted: intercepted_delta,
                            accepted: accepted_delta,
                            send_errors: send_err_delta,
                            detail: format!(
                                "数据包已拦截但未到达本机 127.0.0.1 转发口（{err_note}）"
                            ),
                        };
                    } else if intercepted_delta > 0 && accepted_delta > 0 {
                        tracing::warn!(
                            "WinDivert self-test reached local listener but upstream 443 tunnel failed for {host}: {err_note}"
                        );
                        last_failure = Some(WinDivertSelfTestOutcome::TunnelUnreachable {
                            detail: err_note,
                        });
                    } else {
                        tracing::warn!(
                            "WinDivert self-test saw zero intercepted packets on nic `{}`: {err_note}",
                            physical.friendly_name
                        );
                        last_failure = Some(WinDivertSelfTestOutcome::NoPacketIntercepted {
                            detail: format!("物理网卡「{}」未捕获到出站探测包（{err_note}）", physical.friendly_name),
                        });
                    }
                }
            }
        }

        last_failure.unwrap_or_else(|| WinDivertSelfTestOutcome::NoPacketIntercepted {
            detail: "未找到可用的国内非 443 HTTP 探测地址".to_string(),
        })
    }

    /// Dynamically update or clear the external main Mihomo core PID excluded from
    /// transparent WinDivert interception while always preserving self and tunnel PIDs.
    pub fn sync_main_core_pid(&self, main_core_pid: Option<u32>) {
        self.excluded_pid_tracker.sync_main_core_pid(main_core_pid);
    }

    #[allow(dead_code)]
    pub fn redirect_port(&self) -> u16 {
        self.redirect_port
    }

    /// Deterministically stop packet interception, close the kernel handle, abort background
    /// tasks, and cleanly stop the `WinDivert` kernel driver service (`teardown_service = true`).
    ///
    /// For hot rebuilds that will immediately reopen WinDivert, call
    /// [`Self::stop_sync_with_teardown`]`(false)` instead to avoid Win32 error 1072 races.
    #[allow(dead_code)]
    pub fn stop_sync(&mut self) {
        self.stop_sync_with_teardown(true);
    }

    /// Deterministically stop packet interception, close the kernel handle, abort background tasks,
    /// and when `teardown_service == true` issue a bounded `ControlService(STOP)` (<= 700ms) on
    /// the `WinDivert` kernel service without calling `DeleteService`.
    pub fn stop_sync_with_teardown(&mut self, teardown_service: bool) {
        self.stopped = true;
        self.stop_flag.store(true, Ordering::SeqCst);
        let _ = self.shutdown_tx.send(true);

        if let Some(task) = self.refresh_task.take() {
            task.abort();
        }

        if !self.handle.0.is_null() && self.handle.0 != INVALID_HANDLE_VALUE {
            // Wake up blocking `WinDivertRecv` immediately before joining worker thread.
            // SAFETY: Valid WinDivert handle owned by `self`.
            unsafe {
                let _ = (self.lib.shutdown)(self.handle.0, WINDIVERT_SHUTDOWN_BOTH);
            }
        }

        if let Some(worker) = self.worker_thread.take() {
            let _ = worker.join();
        }

        if !self.handle.0.is_null() && self.handle.0 != INVALID_HANDLE_VALUE {
            // SAFETY: Worker thread has exited, so no concurrent `Recv`/`Send` can touch this handle.
            unsafe {
                let _ = (self.lib.close)(self.handle.0);
            }
            self.handle.0 = std::ptr::null_mut();
        }

        if let Some(task) = self.accept_task.take() {
            task.abort();
        }

        if teardown_service && !self.service_torn_down {
            self.service_torn_down = true;
            let _ = stop_windivert_kernel_service();
        }
    }
}

impl Drop for WinDivertEngine {
    fn drop(&mut self) {
        // When dropped without an explicit `stop_sync_with_teardown(false)` hot-reload call,
        // perform full teardown including cleanly stopping the `WinDivert` kernel service.
        if !self.stopped {
            self.stop_sync_with_teardown(true);
        }
    }
}

struct PacketWorkerContext {
    lib: Arc<WinDivertLib>,
    handle: SendHandle,
    stop_flag: Arc<AtomicBool>,
    nat_table: Arc<NatTable>,
    redirect_port: u16,
    skip_443_native: bool,
    scope: GlobalPreAccelScope,
    target_processes_lower: HashSet<String>,
    excluded_pids: Arc<RwLock<HashSet<u32>>>,
    detected_proxy_pids: Arc<RwLock<HashMap<u32, &'static str>>>,
    physical_ifs: Arc<RwLock<HashSet<u32>>>,
    self_test_src_port: Arc<AtomicU16>,
    self_test_intercepted: Arc<AtomicU64>,
    send_errors: Arc<AtomicU64>,
}

fn run_packet_worker(ctx: PacketWorkerContext) {
    let mut pkt_buf = vec![0u8; 65535];
    let mut tcp_table_buf: Vec<u64> = Vec::with_capacity(2048);
    let self_pid = std::process::id();

    let mut pid_cache: HashMap<u32, (String, Instant)> = HashMap::with_capacity(64);
    let mut bypass_cache: HashMap<(Ipv4Addr, u16, Ipv4Addr, u16), Instant> =
        HashMap::with_capacity(256);
    let mut logged_processes: HashSet<String> = HashSet::with_capacity(16);

    while !ctx.stop_flag.load(Ordering::Relaxed) {
        let mut addr = WinDivertAddress::default();
        let mut recv_len: u32 = 0;

        // SAFETY: `pkt_buf` has capacity 65535 and `addr` is an exact 80-byte `WinDivertAddress`.
        let ok = unsafe {
            (ctx.lib.recv)(
                ctx.handle.0,
                pkt_buf.as_mut_ptr().cast(),
                pkt_buf.len() as u32,
                &mut recv_len,
                &mut addr,
            )
        };
        if ok == 0 {
            if ctx.stop_flag.load(Ordering::Relaxed) {
                break;
            }
            let err = unsafe { GetLastError() };
            // `ERROR_NO_DATA` (232) or `ERROR_OPERATION_ABORTED` (995) signals clean shutdown.
            if err == 232 || err == 995 || err == 6 {
                break;
            }
            continue;
        }

        let pkt_len = (recv_len as usize).min(pkt_buf.len());
        if pkt_len < 40 {
            reinject_raw(&ctx.lib, ctx.handle.0, &pkt_buf[..pkt_len], &addr);
            continue;
        }

        let Some(meta) = parse_ipv4_tcp_packet(&pkt_buf[..pkt_len]) else {
            reinject_raw(&ctx.lib, ctx.handle.0, &pkt_buf[..pkt_len], &addr);
            continue;
        };

        // Branch 1: Return packet from local loopback redirector (`127.0.0.1:redirect_port -> 127.0.0.1:orig_src_port`).
        if meta.src_port == ctx.redirect_port
            && meta.src_ip == Ipv4Addr::LOCALHOST
            && meta.dst_ip == Ipv4Addr::LOCALHOST
        {
            if let Some(entry) = ctx
                .nat_table
                .get_packet_view_and_touch(&(Ipv4Addr::LOCALHOST, meta.dst_port))
            {
                if rewrite_ipv4_tcp_from_loopback(
                    &mut pkt_buf[..pkt_len],
                    meta.ihl_bytes,
                    entry.orig_dst_ip,
                    entry.orig_dst_port,
                    entry.orig_src_ip,
                ) {
                    if (meta.tcp_flags & (Ipv4TcpMeta::FLAG_SYN | Ipv4TcpMeta::FLAG_ACK))
                        == (Ipv4TcpMeta::FLAG_SYN | Ipv4TcpMeta::FLAG_ACK)
                    {
                        let _ = clamp_tcp_syn_mss(
                            &mut pkt_buf[..pkt_len],
                            meta.ihl_bytes,
                            STANDARD_ETHERNET_TCP_MSS,
                        );
                    }
                    addr.set_outbound(false);
                    addr.set_loopback(false);
                    addr.set_impostor(false);
                    addr.set_network_if_idx(entry.if_idx);
                    addr.set_network_sub_if_idx(entry.sub_if_idx);
                    calc_and_inject(
                        &ctx.lib,
                        ctx.handle.0,
                        &mut pkt_buf[..pkt_len],
                        &mut addr,
                        &ctx.send_errors,
                    );
                    continue;
                }
            }
            reinject_raw(&ctx.lib, ctx.handle.0, &pkt_buf[..pkt_len], &addr);
            continue;
        }

        // Guard against an unlikely ephemeral client port collision with our own `redirect_port`.
        if meta.src_port == ctx.redirect_port {
            reinject_raw(&ctx.lib, ctx.handle.0, &pkt_buf[..pkt_len], &addr);
            continue;
        }

        // Branch 2: Outbound public TCP packet.
        // Strict fail-closed: only intercept traffic leaving confirmed physical interfaces
        // refreshed asynchronously in the background (when physical NIC set is empty or does not
        // contain `if_idx`, pass through untouched so virtual Wintun/VPN adapters are never hijacked).
        let now = Instant::now();
        let if_idx = addr.network_if_idx();
        let is_physical_if = {
            let guard = ctx
                .physical_ifs
                .read()
                .unwrap_or_else(|e| e.into_inner());
            guard.contains(&if_idx)
        };
        if !is_physical_if {
            reinject_raw(&ctx.lib, ctx.handle.0, &pkt_buf[..pkt_len], &addr);
            continue;
        }

        let nat_key = (Ipv4Addr::LOCALHOST, meta.src_port);
        let flow_key = (meta.src_ip, meta.src_port, meta.dst_ip, meta.dst_port);

        // Fast path: non-SYN packets check the O(1) lock-free 64K source-port bitmap first to
        // bypass untracked flows without ever acquiring the NAT table mutex.
        if !meta.is_syn_only() {
            if !ctx.nat_table.may_contain_port(meta.src_port) {
                reinject_raw(&ctx.lib, ctx.handle.0, &pkt_buf[..pkt_len], &addr);
                continue;
            }
            if let Some(existing) = ctx.nat_table.get_packet_view_and_touch(&nat_key) {
                if existing.orig_src_ip == meta.src_ip
                    && existing.orig_dst_ip == meta.dst_ip
                    && existing.orig_dst_port == meta.dst_port
                {
                    if rewrite_ipv4_tcp_to_loopback(
                        &mut pkt_buf[..pkt_len],
                        meta.ihl_bytes,
                        ctx.redirect_port,
                    ) {
                        // Loopback packets MUST be injected outbound with loopback metadata aligned.
                        configure_loopback_outbound_addr(&mut addr);
                        calc_and_inject(
                            &ctx.lib,
                            ctx.handle.0,
                            &mut pkt_buf[..pkt_len],
                            &mut addr,
                            &ctx.send_errors,
                        );
                        continue;
                    }
                }
            }
            // Never hijack mid-stream packets for connections established before engine startup.
            reinject_raw(&ctx.lib, ctx.handle.0, &pkt_buf[..pkt_len], &addr);
            continue;
        }

        // Idempotent client SYN retransmission path: if an active (non-closing) NAT entry already
        // exists for the exact same `(orig_src_ip, orig_dst_ip, orig_dst_port)`, immediately rewrite
        // and inject without re-running `lookup_tcp_owner_pid` (preventing race-induced deletion).
        if let Some(existing) = ctx.nat_table.get_packet_view_and_touch(&nat_key) {
            if is_matching_active_syn_retransmit_view(
                &existing,
                meta.src_ip,
                meta.dst_ip,
                meta.dst_port,
            ) {
                if rewrite_ipv4_tcp_to_loopback(
                    &mut pkt_buf[..pkt_len],
                    meta.ihl_bytes,
                    ctx.redirect_port,
                ) {
                    if existing.is_self_test {
                        ctx.self_test_intercepted.fetch_add(1, Ordering::SeqCst);
                    }
                    let _ = clamp_tcp_syn_mss(
                        &mut pkt_buf[..pkt_len],
                        meta.ihl_bytes,
                        STANDARD_ETHERNET_TCP_MSS,
                    );
                    configure_loopback_outbound_addr(&mut addr);
                    calc_and_inject(
                        &ctx.lib,
                        ctx.handle.0,
                        &mut pkt_buf[..pkt_len],
                        &mut addr,
                        &ctx.send_errors,
                    );
                    continue;
                }
                reinject_raw(&ctx.lib, ctx.handle.0, &pkt_buf[..pkt_len], &addr);
                continue;
            }
        }

        // Built-in end-to-end dataplane self-test probe: intercept ONLY the exact ephemeral
        // source port owned by our own PID during active self-test verification.
        let active_self_test_port = ctx.self_test_src_port.load(Ordering::SeqCst);
        if active_self_test_port != 0 && meta.src_port == active_self_test_port {
            let owner_pid = lookup_tcp_owner_pid(
                meta.src_ip,
                meta.src_port,
                meta.dst_ip,
                meta.dst_port,
                &mut tcp_table_buf,
            );
            if owner_pid == Some(self_pid) {
                ctx.nat_table.insert(
                    nat_key,
                    NatEntry {
                        orig_src_ip: meta.src_ip,
                        orig_dst_ip: meta.dst_ip,
                        orig_dst_port: meta.dst_port,
                        if_idx,
                        sub_if_idx: addr.network_sub_if_idx(),
                        owner_pid: self_pid,
                        process_name: "catcloud-self-test".to_string(),
                        detected_by: SELF_TEST_DETECTED_BY.to_string(),
                        last_seen: now,
                        closing_since: None,
                    },
                );
                if rewrite_ipv4_tcp_to_loopback(
                    &mut pkt_buf[..pkt_len],
                    meta.ihl_bytes,
                    ctx.redirect_port,
                ) {
                    let _ = clamp_tcp_syn_mss(
                        &mut pkt_buf[..pkt_len],
                        meta.ihl_bytes,
                        STANDARD_ETHERNET_TCP_MSS,
                    );
                    ctx.self_test_intercepted.fetch_add(1, Ordering::SeqCst);
                    configure_loopback_outbound_addr(&mut addr);
                    calc_and_inject(
                        &ctx.lib,
                        ctx.handle.0,
                        &mut pkt_buf[..pkt_len],
                        &mut addr,
                        &ctx.send_errors,
                    );
                    continue;
                }
                let _ = ctx.nat_table.remove_active_if_matching(
                    &nat_key,
                    meta.src_ip,
                    meta.dst_ip,
                    meta.dst_port,
                );
                reinject_raw(&ctx.lib, ctx.handle.0, &pkt_buf[..pkt_len], &addr);
                continue;
            }
        }

        // Bypass plain domestic HTTP :80 connections (and domestic/skipped :443 connections)
        // directly after self-test 204 probe handling and BEFORE `lookup_tcp_owner_pid` so
        // ordinary domestic web/IM traffic never pays a TCP table scan or detours through relays.
        if should_bypass_domestic_http_80(meta.dst_port, meta.dst_ip)
            || should_fast_bypass_port_443(meta.dst_port, ctx.skip_443_native, meta.dst_ip)
        {
            reinject_raw(&ctx.lib, ctx.handle.0, &pkt_buf[..pkt_len], &addr);
            continue;
        }

        // Guard against ephemeral port collisions (distinct source IPs on active entries, or any
        // different 4-tuple reusing a port whose prior entry is still inside the closing grace window).
        if ctx
            .nat_table
            .has_active_conflict(&nat_key, meta.src_ip, meta.dst_ip, meta.dst_port)
        {
            reinject_raw(&ctx.lib, ctx.handle.0, &pkt_buf[..pkt_len], &addr);
            continue;
        }

        // New outbound TCP SYN: check short bypass cache first, clearing only a matching active
        // NAT entry for the same 4-tuple without touching other flows or closing-grace entries.
        if let Some(&cached_at) = bypass_cache.get(&flow_key) {
            if now.saturating_duration_since(cached_at) < BYPASS_CACHE_TTL {
                let _ = ctx.nat_table.remove_active_if_matching(
                    &nat_key,
                    meta.src_ip,
                    meta.dst_ip,
                    meta.dst_port,
                );
                reinject_raw(&ctx.lib, ctx.handle.0, &pkt_buf[..pkt_len], &addr);
                continue;
            }
            bypass_cache.remove(&flow_key);
        }

        // Resolve owning PID (compatible with LocalSystem services) and executable basename,
        // consulting background-refreshed CatCloud PID tree exclusions & dynamic proxy host map.
        let owner_pid = lookup_tcp_owner_pid(
            meta.src_ip,
            meta.src_port,
            meta.dst_ip,
            meta.dst_port,
            &mut tcp_table_buf,
        );
        let intercept_match: Option<(u32, String, &'static str)> = match owner_pid {
            Some(pid) => {
                let proc_name = lookup_process_name_cached(pid, &mut pid_cache, now);
                let detected_by = {
                    let excluded_guard = ctx
                        .excluded_pids
                        .read()
                        .unwrap_or_else(|e| e.into_inner());
                    let detected_guard = ctx
                        .detected_proxy_pids
                        .read()
                        .unwrap_or_else(|e| e.into_inner());
                    classify_intercept_process(
                        pid,
                        proc_name.as_deref(),
                        ctx.scope,
                        &ctx.target_processes_lower,
                        &excluded_guard,
                        &detected_guard,
                    )
                };
                detected_by
                    .filter(|reason| {
                        meta.dst_port != 443
                            || should_intercept_port_443(reason, ctx.skip_443_native, meta.dst_ip)
                    })
                    .map(|reason| {
                        (
                            pid,
                            proc_name.unwrap_or_else(|| format!("pid:{pid}")),
                            reason,
                        )
                    })
            }
            None => None,
        };

        if let Some((owner_pid, process_name, detected_by)) = intercept_match {
            if logged_processes.len() < 32 && logged_processes.insert(process_name.clone()) {
                tracing::info!(
                    "WinDivert transparently accelerating process `{process_name}` (pid={owner_pid}, matched_by={detected_by}, if_idx={if_idx})"
                );
            }
            ctx.nat_table.insert(
                nat_key,
                NatEntry {
                    orig_src_ip: meta.src_ip,
                    orig_dst_ip: meta.dst_ip,
                    orig_dst_port: meta.dst_port,
                    if_idx,
                    sub_if_idx: addr.network_sub_if_idx(),
                    owner_pid,
                    process_name,
                    detected_by: detected_by.to_string(),
                    last_seen: now,
                    closing_since: None,
                },
            );
            if rewrite_ipv4_tcp_to_loopback(
                &mut pkt_buf[..pkt_len],
                meta.ihl_bytes,
                ctx.redirect_port,
            ) {
                let _ = clamp_tcp_syn_mss(
                    &mut pkt_buf[..pkt_len],
                    meta.ihl_bytes,
                    STANDARD_ETHERNET_TCP_MSS,
                );
                configure_loopback_outbound_addr(&mut addr);
                calc_and_inject(
                    &ctx.lib,
                    ctx.handle.0,
                    &mut pkt_buf[..pkt_len],
                    &mut addr,
                    &ctx.send_errors,
                );
                continue;
            }
            // Rewrite failed unexpectedly: clear only this newly inserted active entry.
            let _ = ctx.nat_table.remove_active_if_matching(
                &nat_key,
                meta.src_ip,
                meta.dst_ip,
                meta.dst_port,
            );
        } else {
            let _ = ctx.nat_table.remove_active_if_matching(
                &nat_key,
                meta.src_ip,
                meta.dst_ip,
                meta.dst_port,
            );
            insert_bounded_bypass(&mut bypass_cache, flow_key, now);
        }

        reinject_raw(&ctx.lib, ctx.handle.0, &pkt_buf[..pkt_len], &addr);
    }
}

/// Periodically refresh the full CatCloud descendant PID tree, dynamically detected local proxy
/// listeners / system proxy host PIDs, and active physical NIC indices off the packet hot path.
fn refresh_runtime_tables(
    excluded_pid_tracker: &ExcludedPidTracker,
    detected_proxy_pids: &RwLock<HashMap<u32, &'static str>>,
    physical_ifs: &RwLock<HashSet<u32>>,
    name_cache: &mut HashMap<u32, (String, Instant)>,
) {
    let now = Instant::now();

    // 1. Enumerate process parent-child edges via ToolHelp and merge CatCloud's full descendant
    //    tree (WebView2, main mihomo core, standalone tunnel, probe core, etc.) into exclusions.
    let parent_edges = query_process_parent_edges();
    if !parent_edges.is_empty() {
        let roots = excluded_pid_tracker.current_root_pids();
        let descendants = collect_descendant_pids_from_roots(&roots, &parent_edges);
        excluded_pid_tracker.sync_descendant_pids(descendants);
    }

    // 2. Scan local IPv4 TCP listeners and cross-reference active Windows system proxy port.
    let excluded_snapshot = excluded_pid_tracker.snapshot_active();
    let sys_proxy_port = WindowsPlatform::new()
        .read_system_proxy()
        .ok()
        .and_then(|spec| extract_local_system_proxy_port(&spec));
    let listeners = query_local_tcp_listeners();

    let mut listener_names: HashMap<u32, String> = HashMap::new();
    for &(_, _, pid) in &listeners {
        if pid == 0 || pid == 4 || excluded_snapshot.contains(&pid) {
            continue;
        }
        if listener_names.contains_key(&pid) {
            continue;
        }
        if let Some(name) = lookup_process_name_cached(pid, name_cache, now) {
            listener_names.insert(pid, name);
        }
    }

    let next_detected = classify_local_proxy_listeners(
        &listeners,
        sys_proxy_port,
        &excluded_snapshot,
        &listener_names,
    );
    {
        let mut guard = detected_proxy_pids
            .write()
            .unwrap_or_else(|e| e.into_inner());
        *guard = next_detected;
    }

    // 3. Refresh active physical NIC indices while keeping the prior set on transient query failure.
    let refreshed_ifs = query_physical_interface_indices();
    if !refreshed_ifs.is_empty() {
        let mut guard = physical_ifs.write().unwrap_or_else(|e| e.into_inner());
        *guard = refreshed_ifs;
    }
}

/// Compute the full descendant PID tree reachable from `root_pids` via `(pid, parent_pid)` edges
/// using BFS with cycle protection against Windows PID reuse loops.
fn collect_descendant_pids_from_roots(
    root_pids: &[u32],
    parent_edges: &[(u32, u32)],
) -> HashSet<u32> {
    let mut children_by_parent: HashMap<u32, Vec<u32>> = HashMap::new();
    for &(pid, ppid) in parent_edges {
        if pid == 0 || pid == ppid {
            continue;
        }
        children_by_parent.entry(ppid).or_default().push(pid);
    }

    let mut visited: HashSet<u32> = HashSet::new();
    let mut queue: VecDeque<u32> = VecDeque::new();
    for &root in root_pids {
        if root > 0 && visited.insert(root) {
            queue.push_back(root);
        }
    }

    while let Some(current) = queue.pop_front() {
        if let Some(children) = children_by_parent.get(&current) {
            for &child in children {
                if child > 0 && visited.insert(child) {
                    queue.push_back(child);
                }
            }
        }
    }

    visited
}

/// Extract the local port pointed to by an enabled, non-PAC Windows system proxy configuration.
fn extract_local_system_proxy_port(spec: &SystemProxySpec) -> Option<u16> {
    if !spec.enabled || spec.port == 0 {
        return None;
    }
    if spec
        .pac_url
        .as_deref()
        .map(str::trim)
        .is_some_and(|s| !s.is_empty())
    {
        return None;
    }
    let host = spec.host.trim().to_ascii_lowercase();
    if host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "0.0.0.0" {
        Some(spec.port)
    } else {
        None
    }
}

fn is_excluded_non_proxy_listener_port(port: u16) -> bool {
    port < 1024 || EXCLUDED_NON_PROXY_LISTENER_PORTS.contains(&port)
}

fn is_excluded_non_proxy_listener_process(name: &str) -> bool {
    if is_system_or_self_excluded_process(name) || is_non_proxy_communication_process(name) {
        return true;
    }
    let lower = normalize_process_basename(name);
    EXCLUDED_NON_PROXY_LISTENER_PROCESSES
        .iter()
        .any(|p| *p == lower)
}

fn is_common_proxy_listener_port(port: u16) -> bool {
    matches!(
        port,
        1080 | 1081 | 2080 | 2081 | 7890..=7899 | 10808 | 10809 | 17890..=17899 | 20170..=20172
    )
}

fn has_generic_proxy_process_stem(name: &str) -> bool {
    if is_open_source_proxy_core_name(name) {
        return true;
    }
    let lower = normalize_process_basename(name);
    if lower.is_empty() || is_excluded_non_proxy_listener_process(&lower) {
        return false;
    }
    const GENERIC_PROXY_STEMS: &[&str] = &[
        "proxy",
        "socks",
        "privoxy",
        "gost",
        "brook",
        "juicity",
        "mieru",
        "tun",
        "core",
        "serv",
    ];
    GENERIC_PROXY_STEMS.iter().any(|stem| lower.contains(stem))
}

#[inline]
fn should_bypass_domestic_http_80(dst_port: u16, dst_ip: Ipv4Addr) -> bool {
    dst_port == 80 && is_domestic_ipv4(dst_ip)
}

#[inline]
fn should_fast_bypass_port_443(dst_port: u16, skip_443_native: bool, dst_ip: Ipv4Addr) -> bool {
    dst_port == 443 && (skip_443_native || is_domestic_ipv4(dst_ip))
}

/// Classify local IPv4 TCP listeners on `127.0.0.1`/`0.0.0.0` ports `1024..=65535`:
/// - PID hosting the live Windows system proxy port -> `"system_proxy_host"` (highest priority).
/// - Non-system-proxy listeners are NEVER blindly tagged: they must not belong to excluded OS,
///   database, or communication/desktop processes, AND must match either a generic proxy stem
///   or a standard local proxy port (`1080/1081/2080/2081/7890..=7899/10808/10809/17890..=17899/20170..=20172`).
/// - Always excludes `pid == 0`, `pid == 4`, `excluded_pids`, and core OS / CatCloud binaries.
fn classify_local_proxy_listeners(
    listeners: &[(Ipv4Addr, u16, u32)],
    system_proxy_port: Option<u16>,
    excluded_pids: &HashSet<u32>,
    pid_names: &HashMap<u32, String>,
) -> HashMap<u32, &'static str> {
    let mut detected: HashMap<u32, &'static str> = HashMap::new();

    for &(local_ip, port, pid) in listeners {
        if pid == 0 || pid == 4 || excluded_pids.contains(&pid) {
            continue;
        }
        if !local_ip.is_loopback() && !local_ip.is_unspecified() {
            continue;
        }
        if port < 1024 {
            continue;
        }
        let name_opt = pid_names.get(&pid).map(String::as_str);
        if let Some(name) = name_opt {
            if is_system_or_self_excluded_process(name) {
                continue;
            }
        }

        if system_proxy_port == Some(port) {
            detected.insert(pid, "system_proxy_host");
            continue;
        }

        if is_excluded_non_proxy_listener_port(port) {
            continue;
        }
        if let Some(name) = name_opt {
            if is_excluded_non_proxy_listener_process(name) {
                continue;
            }
        }

        let matches_proxy_signal = is_common_proxy_listener_port(port)
            || name_opt.is_some_and(has_generic_proxy_process_stem);
        if !matches_proxy_signal {
            continue;
        }

        detected.entry(pid).or_insert("local_proxy_listener");
    }

    detected
}

/// Snapshot all running Windows process `(pid, parent_pid)` pairs via
/// `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)`.
fn query_process_parent_edges() -> Vec<(u32, u32)> {
    // SAFETY: Read-only snapshot of system processes; deterministically closed by `ScopedHandle`.
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Vec::new();
    }
    let snapshot = ScopedHandle(raw);

    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    let mut edges: Vec<(u32, u32)> = Vec::with_capacity(256);
    // SAFETY: `snapshot.0` is valid and `entry.dwSize` equals `size_of::<PROCESSENTRY32W>()`.
    if unsafe { Process32FirstW(snapshot.0, &mut entry) } == 0 {
        return edges;
    }
    loop {
        if entry.th32ProcessID > 0 {
            edges.push((entry.th32ProcessID, entry.th32ParentProcessID));
        }
        // SAFETY: Continuing enumeration on the same valid snapshot handle.
        if unsafe { Process32NextW(snapshot.0, &mut entry) } == 0 {
            break;
        }
    }
    edges
}

/// Enumerate active IPv4 TCP listeners bound to loopback (`127.0.0.1`) or unspecified (`0.0.0.0`)
/// on non-privileged ports (`1024..=65535`) via `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_LISTENER)`.
fn query_local_tcp_listeners() -> Vec<(Ipv4Addr, u16, u32)> {
    let mut size: u32 = 16 * 1024;
    let mut aligned_buf: Vec<u64> = Vec::new();
    let mut ok = false;

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
                u32::from(AF_INET),
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        if status == NO_ERROR {
            size = buf_size;
            ok = true;
            break;
        }
        if status == ERROR_INSUFFICIENT_BUFFER {
            size = buf_size.saturating_add(4096);
            continue;
        }
        return Vec::new();
    }

    if !ok {
        return Vec::new();
    }

    let total_bytes = aligned_buf.len().saturating_mul(8).min(size as usize);
    let base_ptr = aligned_buf.as_ptr().cast::<u8>();
    if total_bytes < std::mem::size_of::<u32>() {
        return Vec::new();
    }

    let num_entries = unsafe { (*(base_ptr.cast::<MIB_TCPTABLE_OWNER_PID>())).dwNumEntries } as usize;
    let table_offset = std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table);
    let row_size = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();

    let mut listeners = Vec::with_capacity(num_entries.min(256));
    for idx in 0..num_entries {
        let Some(end_offset) = table_offset
            .checked_add(idx.saturating_add(1).saturating_mul(row_size))
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
        if local_port >= 1024 && row.dwOwningPid > 0 {
            listeners.push((local_ip, local_port, row.dwOwningPid));
        }
    }

    listeners
}

/// Align `WinDivertAddress` metadata for outbound loopback reflection (`127.0.0.1 -> 127.0.0.1`).
fn configure_loopback_outbound_addr(addr: &mut WinDivertAddress) {
    addr.set_outbound(true);
    addr.set_loopback(true);
    addr.set_impostor(false);
    addr.set_network_if_idx(0);
    addr.set_network_sub_if_idx(0);
}

/// Return `true` when an existing `Copy` NAT packet view represents an active (non-closing) flow
/// matching the exact 4-tuple of a retransmitted client TCP `SYN`.
#[inline]
fn is_matching_active_syn_retransmit_view(
    view: &NatPacketView,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    dst_port: u16,
) -> bool {
    !view.is_closing
        && view.orig_src_ip == src_ip
        && view.orig_dst_ip == dst_ip
        && view.orig_dst_port == dst_port
}

/// Return `true` when an existing NAT entry represents an active (non-closing) flow matching the
/// exact 4-tuple of a retransmitted client TCP `SYN`.
#[cfg(test)]
fn is_matching_active_syn_retransmit(
    entry: &NatEntry,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    dst_port: u16,
) -> bool {
    entry.closing_since.is_none()
        && entry.orig_src_ip == src_ip
        && entry.orig_dst_ip == dst_ip
        && entry.orig_dst_port == dst_port
}

fn calc_and_inject(
    lib: &WinDivertLib,
    handle: HANDLE,
    pkt: &mut [u8],
    addr: &mut WinDivertAddress,
    send_errors: &AtomicU64,
) {
    // SAFETY: `pkt` and `addr` point to valid initialized buffers of exact lengths.
    unsafe {
        let csum_ok = (lib.calc_checksums)(pkt.as_mut_ptr().cast(), pkt.len() as u32, addr, 0);
        if csum_ok == 0 {
            let err = GetLastError();
            let count = send_errors.fetch_add(1, Ordering::Relaxed) + 1;
            if count <= 5 {
                tracing::warn!(
                    "WinDivertHelperCalcChecksums failed (count={count}, win32_err={err}, pkt_len={}, if_idx={}); skipping WinDivertSend",
                    pkt.len(),
                    addr.network_if_idx()
                );
            }
            return;
        }
        let mut sent: u32 = 0;
        let ok = (lib.send)(handle, pkt.as_ptr().cast(), pkt.len() as u32, &mut sent, addr);
        if ok == 0 {
            let err = GetLastError();
            let count = send_errors.fetch_add(1, Ordering::Relaxed) + 1;
            if count <= 5 {
                tracing::warn!(
                    "WinDivertSend 注入失败 (count={count}, win32_err={err}, if_idx={})",
                    addr.network_if_idx()
                );
            }
        }
    }
}

fn reinject_raw(lib: &WinDivertLib, handle: HANDLE, pkt: &[u8], addr: &WinDivertAddress) {
    // SAFETY: Pass-through reinjection preserving original packet bytes and address metadata.
    unsafe {
        let mut sent: u32 = 0;
        let _ = (lib.send)(handle, pkt.as_ptr().cast(), pkt.len() as u32, &mut sent, addr);
    }
}

fn insert_bounded_bypass(
    cache: &mut HashMap<(Ipv4Addr, u16, Ipv4Addr, u16), Instant>,
    key: (Ipv4Addr, u16, Ipv4Addr, u16),
    now: Instant,
) {
    if cache.len() >= MAX_BYPASS_CACHE_ENTRIES {
        cache.retain(|_, ts| now.saturating_duration_since(*ts) < BYPASS_CACHE_TTL);
        if cache.len() >= MAX_BYPASS_CACHE_ENTRIES {
            cache.clear();
        }
    }
    cache.insert(key, now);
}

/// Enumerate active physical Ethernet/Wi-Fi interface indices via `GetIfTable`,
/// filtering out TUN/TAP/Hyper-V/VMware/Loopback/VPN virtual adapters.
fn query_physical_interface_indices() -> HashSet<u32> {
    let mut indices = HashSet::new();
    let mut size: u32 = 0;

    // SAFETY: First probe call determines required buffer length.
    let probe = unsafe { GetIfTable(std::ptr::null_mut(), &mut size, 0) };
    if probe != ERROR_INSUFFICIENT_BUFFER && probe != NO_ERROR {
        return indices;
    }
    if size == 0 {
        return indices;
    }

    let alloc_bytes = (size as usize).saturating_add(std::mem::size_of::<MIB_IFROW>() * 4);
    let mut aligned_buf = vec![0u64; alloc_bytes.div_ceil(8)];
    let mut actual_size =
        u32::try_from(aligned_buf.len().saturating_mul(8)).unwrap_or(u32::MAX);

    // SAFETY: `aligned_buf` is 8-byte aligned and holds at least `actual_size` bytes.
    let status = unsafe { GetIfTable(aligned_buf.as_mut_ptr().cast::<MIB_IFTABLE>(), &mut actual_size, 0) };
    if status != NO_ERROR {
        return indices;
    }

    let base_ptr = aligned_buf.as_ptr().cast::<u8>();
    let total_bytes = aligned_buf
        .len()
        .saturating_mul(8)
        .min(actual_size as usize);
    if total_bytes < std::mem::size_of::<MIB_IFTABLE>() {
        return indices;
    }

    let num_entries = unsafe { (*(base_ptr.cast::<MIB_IFTABLE>())).dwNumEntries } as usize;
    let table_offset = std::mem::offset_of!(MIB_IFTABLE, table);
    let row_size = std::mem::size_of::<MIB_IFROW>();

    for idx in 0..num_entries {
        let Some(end_offset) = table_offset
            .checked_add(idx.saturating_add(1).saturating_mul(row_size))
        else {
            break;
        };
        if end_offset > total_bytes {
            break;
        }
        // SAFETY: Bounds checked above; `MIB_IFROW` is `Copy` and `repr(C)`.
        let row = unsafe {
            std::ptr::read_unaligned(
                base_ptr
                    .add(table_offset + idx * row_size)
                    .cast::<MIB_IFROW>(),
            )
        };
        let descr_len = (row.dwDescrLen as usize).min(row.bDescr.len());
        let raw_slice = &row.bDescr[..descr_len];
        let nul_pos = raw_slice
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(raw_slice.len());
        let descr = String::from_utf8_lossy(&raw_slice[..nul_pos]);

        if is_physical_nic_descriptor(row.dwType, row.dwOperStatus, &descr) {
            indices.insert(row.dwIndex);
        }
    }

    indices
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpOwnerRowMatch {
    Exact(u32),
    SynSentSameRemote(u32),
    None,
}

/// Strictly match a single `MIB_TCPROW_OWNER_PID` row against an outbound SYN 4-tuple.
///
/// Only accepts:
/// 1. Exact 4-tuple match (`local_ip`/`0.0.0.0`, `src_port`, `dst_ip`, `dst_port`); OR
/// 2. Same `(local_ip/0.0.0.0, src_port, dst_ip)` while the socket is in `MIB_TCP_STATE_SYN_SENT (3)`.
///
/// Never falls back to loose `local_port`-only matching across unrelated remote destinations.
fn classify_tcp_owner_row(
    row: &MIB_TCPROW_OWNER_PID,
    target_local_ip: u32,
    src_port: u16,
    target_remote_ip: u32,
    dst_port: u16,
) -> TcpOwnerRowMatch {
    let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
    if local_port != src_port {
        return TcpOwnerRowMatch::None;
    }
    let local_ip_ok = row.dwLocalAddr == target_local_ip || row.dwLocalAddr == 0;
    if !local_ip_ok {
        return TcpOwnerRowMatch::None;
    }
    let remote_port = u16::from_be((row.dwRemotePort & 0xFFFF) as u16);
    if row.dwRemoteAddr == target_remote_ip && remote_port == dst_port {
        return TcpOwnerRowMatch::Exact(row.dwOwningPid);
    }
    if row.dwRemoteAddr == target_remote_ip && row.dwState == MIB_TCP_STATE_SYN_SENT {
        return TcpOwnerRowMatch::SynSentSameRemote(row.dwOwningPid);
    }
    TcpOwnerRowMatch::None
}

/// Query the owning PID of an active IPv4 TCP connection via
/// `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_CONNECTIONS)`, reusing caller-provided `aligned_buf`
/// to avoid per-SYN heap allocations on the packet worker hot path.
fn lookup_tcp_owner_pid(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    aligned_buf: &mut Vec<u64>,
) -> Option<u32> {
    let mut size: u32 = u32::try_from(aligned_buf.len().saturating_mul(8))
        .unwrap_or(u32::MAX)
        .max(16 * 1024);
    let mut ok = false;

    for _ in 0..4 {
        let alloc_bytes = (size as usize).max(4096);
        let needed_words = alloc_bytes.div_ceil(8);
        if aligned_buf.len() < needed_words {
            aligned_buf.resize(needed_words, 0u64);
        }
        let mut buf_size =
            u32::try_from(aligned_buf.len().saturating_mul(8)).unwrap_or(u32::MAX);

        // SAFETY: `aligned_buf` is 8-byte aligned and large enough for `buf_size` bytes.
        let status = unsafe {
            GetExtendedTcpTable(
                aligned_buf.as_mut_ptr().cast(),
                &mut buf_size,
                0,
                u32::from(AF_INET),
                TCP_TABLE_OWNER_PID_CONNECTIONS,
                0,
            )
        };
        if status == NO_ERROR {
            size = buf_size;
            ok = true;
            break;
        }
        if status == ERROR_INSUFFICIENT_BUFFER {
            size = buf_size.saturating_add(4096);
            continue;
        }
        return None;
    }

    if !ok {
        return None;
    }

    let total_bytes = aligned_buf.len().saturating_mul(8).min(size as usize);
    let base_ptr = aligned_buf.as_ptr().cast::<u8>();
    if total_bytes < std::mem::size_of::<u32>() {
        return None;
    }

    let num_entries = unsafe { (*(base_ptr.cast::<MIB_TCPTABLE_OWNER_PID>())).dwNumEntries } as usize;
    let table_offset = std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table);
    let row_size = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();

    let target_local_ip = u32::from_ne_bytes(src_ip.octets());
    let target_remote_ip = u32::from_ne_bytes(dst_ip.octets());

    let mut syn_sent_pid: Option<u32> = None;

    for idx in 0..num_entries {
        let Some(end_offset) = table_offset
            .checked_add(idx.saturating_add(1).saturating_mul(row_size))
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

        match classify_tcp_owner_row(&row, target_local_ip, src_port, target_remote_ip, dst_port) {
            TcpOwnerRowMatch::Exact(pid) => return Some(pid),
            TcpOwnerRowMatch::SynSentSameRemote(pid) => {
                if syn_sent_pid.is_none() {
                    syn_sent_pid = Some(pid);
                }
            }
            TcpOwnerRowMatch::None => {}
        }
    }

    syn_sent_pid
}

fn lookup_process_name_cached(
    pid: u32,
    cache: &mut HashMap<u32, (String, Instant)>,
    now: Instant,
) -> Option<String> {
    if let Some((name, ts)) = cache.get(&pid) {
        if now.saturating_duration_since(*ts) < PID_CACHE_TTL {
            return Some(name.clone());
        }
    }

    let resolved = query_process_filename(pid)?;
    if cache.len() >= MAX_PID_CACHE_ENTRIES {
        cache.retain(|_, (_, ts)| now.saturating_duration_since(*ts) < PID_CACHE_TTL);
        if cache.len() >= MAX_PID_CACHE_ENTRIES {
            cache.clear();
        }
    }
    cache.insert(pid, (resolved.clone(), now));
    Some(resolved)
}

/// Query executable filename for `pid` using `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` +
/// `QueryFullProcessImageNameW` (works cleanly for `LocalSystem` Windows services when elevated).
fn query_process_filename(pid: u32) -> Option<String> {
    if pid == 0 {
        return Some("Idle".to_string());
    }
    if pid == 4 {
        return Some("System".to_string());
    }

    // SAFETY: Opening process handle with minimum read-only query privilege; always closed below.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }

    let mut buf = [0u16; 1024];
    let mut len = buf.len() as u32;
    // SAFETY: `handle` is valid, `buf` has capacity `len`.
    let ok = unsafe { QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) };
    unsafe {
        let _ = CloseHandle(handle);
    }

    if ok == 0 || len == 0 {
        return None;
    }

    let full_path = String::from_utf16_lossy(&buf[..(len as usize).min(buf.len())]);
    let basename = full_path
        .rsplit(|c| c == '\\' || c == '/')
        .next()
        .unwrap_or(&full_path)
        .trim();
    if basename.is_empty() {
        None
    } else {
        Some(basename.to_string())
    }
}

/// Safely decode a NUL-terminated Win32 UTF-16 `PWSTR` pointer with an upper bound to avoid
/// unbounded reads on malformed buffers.
unsafe fn wide_ptr_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    const MAX_WIDE_LEN: usize = 512;
    let mut len = 0usize;
    while len < MAX_WIDE_LEN {
        // SAFETY: Caller guarantees `ptr` points to a valid NUL-terminated UTF-16 string.
        if unsafe { *ptr.add(len) } == 0 {
            break;
        }
        len += 1;
    }
    if len == 0 {
        return String::new();
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf16_lossy(slice).trim().to_string()
}

/// Check whether an IPv4 address is a usable host unicast address on a physical NIC
/// (excluding unspecified `0.0.0.0`, loopback `127.0.0.0/8`, link-local `169.254.0.0/16`,
/// multicast/broadcast, and third-party TUN Fake-IP `198.18.0.0/15`).
fn is_usable_local_nic_ipv4(ip: Ipv4Addr) -> bool {
    let oct = ip.octets();
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
    {
        return false;
    }
    // Exclude RFC 2544 / Mihomo / Clash TUN Fake-IP range `198.18.0.0/15`.
    if oct[0] == 198 && (oct[1] == 18 || oct[1] == 19) {
        return false;
    }
    true
}

/// Check whether an IPv4 address is a globally routable public destination suitable for our
/// WinDivert dataplane self-test (rejecting RFC 1918 LAN, loopback, CGNAT, and TUN Fake-IP).
fn is_routable_public_ipv4(ip: Ipv4Addr) -> bool {
    let oct = ip.octets();
    if ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
    {
        return false;
    }
    // Exclude CGNAT `100.64.0.0/10`.
    if oct[0] == 100 && (oct[1] & 0xC0) == 64 {
        return false;
    }
    // Exclude Fake-IP `198.18.0.0/15`.
    if oct[0] == 198 && (oct[1] == 18 || oct[1] == 19) {
        return false;
    }
    true
}

/// Query IPv4 default routes (`0.0.0.0/0` with non-zero gateway) via `GetIpForwardTable`,
/// returning a map of `if_idx -> minimum route metric`.
fn query_default_ipv4_route_metrics() -> HashMap<u32, u32> {
    let mut metrics: HashMap<u32, u32> = HashMap::new();
    let mut size: u32 = 16 * 1024;
    let mut aligned_buf: Vec<u64> = Vec::new();
    let mut ok = false;

    for _ in 0..4 {
        let alloc_bytes = (size as usize).max(4096);
        aligned_buf.resize(alloc_bytes.div_ceil(8), 0u64);
        let mut buf_size =
            u32::try_from(aligned_buf.len().saturating_mul(8)).unwrap_or(u32::MAX);

        // SAFETY: `aligned_buf` is 8-byte aligned and holds at least `buf_size` bytes.
        let status = unsafe {
            GetIpForwardTable(
                aligned_buf.as_mut_ptr().cast::<MIB_IPFORWARDTABLE>(),
                &mut buf_size,
                0,
            )
        };
        if status == NO_ERROR {
            size = buf_size;
            ok = true;
            break;
        }
        if status == ERROR_INSUFFICIENT_BUFFER {
            size = buf_size.saturating_add(4096);
            continue;
        }
        return metrics;
    }

    if !ok {
        return metrics;
    }

    let total_bytes = aligned_buf.len().saturating_mul(8).min(size as usize);
    let base_ptr = aligned_buf.as_ptr().cast::<u8>();
    if total_bytes < std::mem::size_of::<u32>() {
        return metrics;
    }

    let num_entries = unsafe { (*(base_ptr.cast::<MIB_IPFORWARDTABLE>())).dwNumEntries } as usize;
    let table_offset = std::mem::offset_of!(MIB_IPFORWARDTABLE, table);
    let row_size = std::mem::size_of::<MIB_IPFORWARDROW>();

    for idx in 0..num_entries {
        let Some(end_offset) = table_offset
            .checked_add(idx.saturating_add(1).saturating_mul(row_size))
        else {
            break;
        };
        if end_offset > total_bytes {
            break;
        }
        // SAFETY: Bounds checked above; `MIB_IPFORWARDROW` is `Copy` and `repr(C)`.
        let row = unsafe {
            std::ptr::read_unaligned(
                base_ptr
                    .add(table_offset + idx * row_size)
                    .cast::<MIB_IPFORWARDROW>(),
            )
        };
        if row.dwForwardDest == 0 && row.dwForwardMask == 0 && row.dwForwardNextHop != 0 {
            metrics
                .entry(row.dwForwardIfIndex)
                .and_modify(|m| {
                    if row.dwForwardMetric1 < *m {
                        *m = row.dwForwardMetric1;
                    }
                })
                .or_insert(row.dwForwardMetric1);
        }
    }

    metrics
}

/// Detect the primary active physical Ethernet or Wi-Fi exit adapter on Windows using
/// `GetAdaptersAddresses(AF_INET)` crossed with IPv4 default route metrics.
///
/// Virtual/TUN/Wintun/VPN adapters (including third-party Clash/Mihomo TUN adapters) are strictly
/// excluded so the standalone `:443` tunnel and dataplane self-test always egress via the host's
/// real physical NIC.
pub(super) fn detect_primary_physical_interface() -> Option<PhysicalExitInterface> {
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 32 * 1024;
    let mut aligned_buf: Vec<u64> = Vec::new();
    let mut ok = false;

    for _ in 0..4 {
        let alloc_bytes = (size as usize).max(16 * 1024);
        aligned_buf.resize(alloc_bytes.div_ceil(8), 0u64);
        let mut buf_size =
            u32::try_from(aligned_buf.len().saturating_mul(8)).unwrap_or(u32::MAX);

        // SAFETY: `aligned_buf` is 8-byte aligned and holds at least `buf_size` bytes.
        let status = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_INET),
                flags,
                std::ptr::null_mut(),
                aligned_buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                &mut buf_size,
            )
        };
        if status == NO_ERROR {
            ok = true;
            break;
        }
        if status == ERROR_BUFFER_OVERFLOW || status == ERROR_INSUFFICIENT_BUFFER {
            size = buf_size.saturating_add(8192);
            continue;
        }
        return None;
    }

    if !ok || aligned_buf.is_empty() {
        return None;
    }

    let route_metrics = query_default_ipv4_route_metrics();
    let mut candidates: Vec<(u8, u32, u32, PhysicalExitInterface)> = Vec::new();

    let mut cur = aligned_buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    let mut steps = 0usize;
    while !cur.is_null() && steps < 256 {
        steps += 1;
        // SAFETY: Linked list entries reside inside `aligned_buf` populated by Windows.
        let adapter = unsafe { &*cur };
        cur = adapter.Next;

        if adapter.OperStatus != IfOperStatusUp {
            continue;
        }

        let if_idx = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
        if if_idx == 0 {
            continue;
        }

        let friendly_name = unsafe { wide_ptr_to_string(adapter.FriendlyName) };
        let description = unsafe { wide_ptr_to_string(adapter.Description) };
        if friendly_name.is_empty() {
            continue;
        }

        // Cross-check both adapter description and friendly name against virtual/TUN keywords.
        // Pass `oper_status = 5` (MIB operational) because `OperStatus == IfOperStatusUp` is
        // already verified above.
        let combined_label = format!("{description} {friendly_name}");
        if !is_physical_nic_descriptor(adapter.IfType, 5, &combined_label) {
            continue;
        }

        // Locate the first usable non-loopback / non-APIPA / non-Fake-IP unicast IPv4 address.
        let mut local_ipv4: Option<Ipv4Addr> = None;
        let mut u_cur = adapter.FirstUnicastAddress;
        let mut u_steps = 0usize;
        while !u_cur.is_null() && u_steps < 32 {
            u_steps += 1;
            let unicast = unsafe { &*u_cur };
            u_cur = unicast.Next;

            let sa = unicast.Address;
            if !sa.lpSockaddr.is_null()
                && usize::try_from(sa.iSockaddrLength)
                    .is_ok_and(|n| n >= std::mem::size_of::<SOCKADDR_IN>())
            {
                let sin = unsafe { std::ptr::read_unaligned(sa.lpSockaddr.cast::<SOCKADDR_IN>()) };
                if sin.sin_family == AF_INET {
                    let ip = Ipv4Addr::from(unsafe { sin.sin_addr.S_un.S_addr }.to_ne_bytes());
                    if is_usable_local_nic_ipv4(ip) {
                        local_ipv4 = Some(ip);
                        break;
                    }
                }
            }
        }

        let Some(local_ipv4) = local_ipv4 else {
            continue;
        };

        // Rank adapters with an active IPv4 default route ahead of those without one
        // (while still allowing fallback when a third-party TUN hijacks the 0.0.0.0/0 table).
        let (tier, primary_metric) = match route_metrics.get(&if_idx).copied() {
            Some(m) => (0u8, m),
            None => (1u8, adapter.Ipv4Metric),
        };

        candidates.push((
            tier,
            primary_metric,
            adapter.Ipv4Metric,
            PhysicalExitInterface {
                if_idx,
                friendly_name,
                local_ipv4,
            },
        ));
    }

    candidates.sort_by_key(|(tier, m1, m2, iface)| (*tier, *m1, *m2, iface.if_idx));
    candidates.into_iter().next().map(|(_, _, _, iface)| iface)
}

/// Read-only scan of running Windows process executable names to identify installed security /
/// firewall products (Huorong, 360, Tencent PC Manager, Windows Defender, etc.) for tailored
/// user-facing allowlist guidance.
pub(super) fn detect_windows_security_products() -> Vec<String> {
    // SAFETY: Read-only ToolHelp process snapshot deterministically closed by `ScopedHandle`.
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Vec::new();
    }
    let snapshot = ScopedHandle(raw);

    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    let mut names: Vec<String> = Vec::with_capacity(128);
    if unsafe { Process32FirstW(snapshot.0, &mut entry) } == 0 {
        return Vec::new();
    }
    loop {
        let nul_pos = entry
            .szExeFile
            .iter()
            .position(|&ch| ch == 0)
            .unwrap_or(entry.szExeFile.len());
        if nul_pos > 0 {
            names.push(String::from_utf16_lossy(&entry.szExeFile[..nul_pos]));
        }
        if unsafe { Process32NextW(snapshot.0, &mut entry) } == 0 {
            break;
        }
    }

    classify_security_products_from_process_names(&names)
}

/// Build a minimal RFC 1035 DNS A-record query packet for `host`.
fn build_dns_a_query(host: &str, txid: u16) -> Option<Vec<u8>> {
    let trimmed = host.trim().trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > 253 {
        return None;
    }

    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&txid.to_be_bytes());
    // Standard query with RD=1 (recursion desired).
    pkt.extend_from_slice(&0x0100u16.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    for label in trimmed.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return None;
        }
        pkt.push(bytes.len() as u8);
        pkt.extend_from_slice(bytes);
    }
    pkt.push(0); // Root label terminator
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A (1)
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN (1)
    Some(pkt)
}

/// Skip a DNS wire-format domain name starting at `offset` (handling compression pointers safely).
fn skip_dns_name(pkt: &[u8], mut offset: usize) -> Option<usize> {
    let mut jumps = 0usize;
    while offset < pkt.len() && jumps < 64 {
        let len = pkt[offset];
        if len == 0 {
            return Some(offset + 1);
        }
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= pkt.len() {
                return None;
            }
            return Some(offset + 2);
        }
        if (len & 0xC0) != 0 {
            return None;
        }
        let next = offset.checked_add(1)?.checked_add(len as usize)?;
        if next > pkt.len() {
            return None;
        }
        offset = next;
        jumps += 1;
    }
    None
}

/// Parse the first globally routable IPv4 A-record from a DNS response matching `expected_txid`.
fn parse_dns_a_response(pkt: &[u8], expected_txid: u16) -> Option<Ipv4Addr> {
    if pkt.len() < 12 {
        return None;
    }
    let txid = u16::from_be_bytes([pkt[0], pkt[1]]);
    if txid != expected_txid {
        return None;
    }
    let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
    // Must be a response (QR=1) with RCODE=0 (no error).
    if (flags & 0x8000) == 0 || (flags & 0x000F) != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let ancount = u16::from_be_bytes([pkt[6], pkt[7]]) as usize;

    let mut offset = 12usize;
    for _ in 0..qdcount {
        offset = skip_dns_name(pkt, offset)?;
        offset = offset.checked_add(4)?;
        if offset > pkt.len() {
            return None;
        }
    }

    for _ in 0..ancount {
        offset = skip_dns_name(pkt, offset)?;
        if offset.checked_add(10)? > pkt.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([pkt[offset], pkt[offset + 1]]);
        let rclass = u16::from_be_bytes([pkt[offset + 2], pkt[offset + 3]]);
        let rdlength = u16::from_be_bytes([pkt[offset + 8], pkt[offset + 9]]) as usize;
        let rdata_start = offset + 10;
        let rdata_end = rdata_start.checked_add(rdlength)?;
        if rdata_end > pkt.len() {
            return None;
        }
        if rtype == 1 && rclass == 1 && rdlength == 4 {
            let ip = Ipv4Addr::new(
                pkt[rdata_start],
                pkt[rdata_start + 1],
                pkt[rdata_start + 2],
                pkt[rdata_start + 3],
            );
            if is_routable_public_ipv4(ip) {
                return Some(ip);
            }
        }
        offset = rdata_end;
    }

    None
}

/// Pin an IPv4 TCP/UDP socket's outbound routing interface via `setsockopt(IPPROTO_IP, IP_UNICAST_IF)`.
///
/// Windows requires IPv4 interface indices passed to `IP_UNICAST_IF` in network byte order
/// (`if_idx.to_be()`). Binding `IP_UNICAST_IF` alongside the physical local IP guarantees third-party
/// Wintun/Clash/Mihomo default routes cannot hijack self-test probes or anti-Fake-IP DNS queries.
fn set_ipv4_unicast_interface(raw_sock: usize, if_idx: u32) -> std::io::Result<()> {
    let idx_be: u32 = if_idx.to_be();
    // SAFETY: `raw_sock` is a valid Winsock IPv4 socket owned by the caller, and `idx_be` is a
    // 4-byte network-byte-order interface index buffer as required by `IP_UNICAST_IF`.
    let rc = unsafe {
        setsockopt(
            raw_sock as SOCKET,
            IPPROTO_IP,
            IP_UNICAST_IF,
            (&idx_be as *const u32).cast::<u8>(),
            std::mem::size_of::<u32>() as i32,
        )
    };
    if rc != 0 {
        let wsa_err = unsafe { WSAGetLastError() };
        return Err(std::io::Error::from_raw_os_error(wsa_err));
    }
    Ok(())
}

/// Resolve `host` to a real globally routable public IPv4 address for the WinDivert self-test.
///
/// When a third-party VPN/TUN adapter hijacks system DNS into `198.18.0.0/15` Fake-IPs, this falls
/// back to a direct UDP A-record query pinned to `(local_ipv4, if_idx)` via `IP_UNICAST_IF`
/// against public domestic resolvers (`223.5.5.5:53` / `119.29.29.29:53`).
async fn resolve_public_ipv4_for_self_test(
    host: &str,
    port: u16,
    local_ipv4: Ipv4Addr,
    if_idx: u32,
) -> Option<Ipv4Addr> {
    if let Ok(ip) = host.trim().parse::<Ipv4Addr>() {
        return is_routable_public_ipv4(ip).then_some(ip);
    }

    // Fast path: system resolver when it returns a genuine public IPv4 (no Fake-IP hijacking).
    if let Ok(Ok(addrs)) = tokio::time::timeout(
        Duration::from_millis(1200),
        tokio::net::lookup_host((host, port)),
    )
    .await
    {
        for addr in addrs {
            if let IpAddr::V4(v4) = addr.ip() {
                if is_routable_public_ipv4(v4) {
                    return Some(v4);
                }
            }
        }
    }

    // Fallback: direct UDP DNS query bound to the physical NIC and pinned via `IP_UNICAST_IF`
    // against domestic public DNS.
    const DOMESTIC_DNS_SERVERS: &[(Ipv4Addr, u16)] = &[
        (Ipv4Addr::new(223, 5, 5, 5), 53),
        (Ipv4Addr::new(119, 29, 29, 29), 53),
    ];

    for (idx, &(dns_ip, dns_port)) in DOMESTIC_DNS_SERVERS.iter().enumerate() {
        let txid = 0x4343u16.wrapping_add(idx as u16);
        let Some(query) = build_dns_a_query(host, txid) else {
            return None;
        };
        let Ok(udp) = UdpSocket::bind(SocketAddrV4::new(local_ipv4, 0)).await else {
            continue;
        };
        if let Err(e) = set_ipv4_unicast_interface(udp.as_raw_socket() as usize, if_idx) {
            tracing::warn!(
                "WinDivert self-test DNS socket failed to bind IP_UNICAST_IF (if_idx={if_idx}): {e}"
            );
            continue;
        }
        let dns_addr = SocketAddr::V4(SocketAddrV4::new(dns_ip, dns_port));
        let Ok(Ok(_)) =
            tokio::time::timeout(Duration::from_millis(1200), udp.send_to(&query, dns_addr)).await
        else {
            continue;
        };
        let mut resp = [0u8; 512];
        if let Ok(Ok((n, _))) =
            tokio::time::timeout(Duration::from_millis(1200), udp.recv_from(&mut resp)).await
        {
            if let Some(ip) = parse_dns_a_response(&resp[..n], txid) {
                return Some(ip);
            }
        }
    }

    None
}

/// Read an HTTP/1.x status line from `stream` in a loop until `\r\n`, buffer saturation, or EOF,
/// preventing false negatives when TCP segmentation splits the status line across multiple reads.
async fn read_http_status_code_from_stream<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> std::io::Result<Option<u16>> {
    let mut resp = [0u8; 256];
    let mut filled = 0usize;
    while filled < resp.len() {
        let n = stream.read(&mut resp[filled..]).await?;
        if n == 0 {
            break;
        }
        filled += n;
        if resp[..filled].windows(2).any(|w| w == b"\r\n") {
            break;
        }
    }
    Ok(parse_http_status_code(&resp[..filled]))
}

/// Extract the 3-digit HTTP status code from the status line of a raw HTTP/1.x response buffer.
fn parse_http_status_code(buf: &[u8]) -> Option<u16> {
    let line_end = buf
        .windows(2)
        .position(|w| w == b"\r\n")
        .or_else(|| buf.iter().position(|&b| b == b'\n'))
        .unwrap_or(buf.len());
    let first_line = std::str::from_utf8(&buf[..line_end]).ok()?.trim();
    if !first_line.starts_with("HTTP/") {
        return None;
    }
    let code_token = first_line.split_whitespace().nth(1)?;
    if code_token.len() != 3 {
        return None;
    }
    let code = code_token.parse::<u16>().ok()?;
    (100..=599).contains(&code).then_some(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_descendant_pids_recursively_includes_full_tree_and_survives_cycles() {
        // Simulated process tree:
        //   100 (catcloud) -> 200 (webview2) -> 201 (renderer), 202 (gpu)
        //   100 (catcloud) -> 300 (main mihomo)
        //   100 (catcloud) -> 400 (standalone 443 tunnel) -> 401 (helper)
        //   100 (catcloud) -> 500 (catcloud-probe-core)
        //   900 (external proxy core) -> 901 (external worker)
        //   700 <-> 701 (artificial PID-reuse cycle rooted under 401)
        let edges = vec![
            (100, 50),
            (200, 100),
            (201, 200),
            (202, 200),
            (300, 100),
            (400, 100),
            (401, 400),
            (500, 100),
            (700, 401),
            (701, 700),
            (700, 701),
            (900, 1),
            (901, 900),
        ];

        let tree = collect_descendant_pids_from_roots(&[100], &edges);
        for expected in [100, 200, 201, 202, 300, 400, 401, 500, 700, 701] {
            assert!(tree.contains(&expected), "missing expected descendant {expected}");
        }
        assert!(!tree.contains(&50));
        assert!(!tree.contains(&900));
        assert!(!tree.contains(&901));
        assert!(!tree.contains(&0));
    }

    #[test]
    fn classify_local_proxy_listeners_labels_system_proxy_host_and_filters_databases_and_excluded() {
        let excluded: HashSet<u32> = [100, 300, 400].into_iter().collect();
        let mut names: HashMap<u32, String> = HashMap::new();
        names.insert(300, "mihomo.exe".to_string()); // CatCloud own main core (in excluded)
        names.insert(1001, "custom-proxy-core.exe".to_string()); // system proxy host
        names.insert(1002, "proxy-engine.exe".to_string()); // secondary local proxy listener
        names.insert(1003, "mysqld.exe".to_string()); // DB process on custom port
        names.insert(1004, "db-daemon.exe".to_string()); // generic process on known DB port
        names.insert(1005, "svchost.exe".to_string()); // OS system service
        names.insert(1006, "catcloud-helper.exe".to_string()); // CatCloud self name
        names.insert(1007, "lan-only-app.exe".to_string()); // non-loopback LAN bind

        let listeners = vec![
            // Excluded CatCloud PID listening on system proxy port must never be marked.
            (Ipv4Addr::LOCALHOST, 7897, 300),
            // Active system proxy host listening on both 7897 and 9091 keeps "system_proxy_host".
            (Ipv4Addr::LOCALHOST, 9091, 1001),
            (Ipv4Addr::LOCALHOST, 7897, 1001),
            // Independent third-party proxy core listening on 0.0.0.0:10808.
            (Ipv4Addr::UNSPECIFIED, 10808, 1002),
            // Privileged port (<1024) must be ignored.
            (Ipv4Addr::LOCALHOST, 443, 1002),
            // Known database executable on non-default port must be ignored.
            (Ipv4Addr::LOCALHOST, 13306, 1003),
            // Known non-proxy system/database ports must be ignored.
            (Ipv4Addr::LOCALHOST, 1433, 1004),
            (Ipv4Addr::LOCALHOST, 3306, 1004),
            (Ipv4Addr::LOCALHOST, 5432, 1004),
            (Ipv4Addr::LOCALHOST, 6379, 1004),
            (Ipv4Addr::LOCALHOST, 14588, 1004),
            (Ipv4Addr::LOCALHOST, 27017, 1004),
            // System & CatCloud binaries must be ignored even on normal ports.
            (Ipv4Addr::LOCALHOST, 7890, 1005),
            (Ipv4Addr::LOCALHOST, 7891, 1006),
            // Non-loopback / non-unspecified interface bind must be ignored.
            (Ipv4Addr::new(192, 0, 2, 10), 7890, 1007),
        ];

        let detected = classify_local_proxy_listeners(&listeners, Some(7897), &excluded, &names);
        assert_eq!(detected.get(&1001).copied(), Some("system_proxy_host"));
        assert_eq!(detected.get(&1002).copied(), Some("local_proxy_listener"));
        assert!(!detected.contains_key(&300));
        assert!(!detected.contains_key(&1003));
        assert!(!detected.contains_key(&1004));
        assert!(!detected.contains_key(&1005));
        assert!(!detected.contains_key(&1006));
        assert!(!detected.contains_key(&1007));
        assert_eq!(detected.len(), 2);
    }

    #[test]
    fn extract_local_system_proxy_port_handles_loopback_remote_and_pac() {
        let loopback = SystemProxySpec {
            enabled: true,
            host: "127.0.0.1".to_string(),
            port: 7897,
            bypass: Vec::new(),
            pac_url: None,
        };
        assert_eq!(extract_local_system_proxy_port(&loopback), Some(7897));

        let localhost = SystemProxySpec {
            host: "LOCALHOST".to_string(),
            port: 10809,
            ..loopback.clone()
        };
        assert_eq!(extract_local_system_proxy_port(&localhost), Some(10809));

        let remote = SystemProxySpec {
            host: "198.51.100.10".to_string(),
            ..loopback.clone()
        };
        assert_eq!(extract_local_system_proxy_port(&remote), None);

        let pac = SystemProxySpec {
            pac_url: Some("http://127.0.0.1:17891/proxy.pac".to_string()),
            ..loopback.clone()
        };
        assert_eq!(extract_local_system_proxy_port(&pac), None);

        let disabled = SystemProxySpec {
            enabled: false,
            ..loopback
        };
        assert_eq!(extract_local_system_proxy_port(&disabled), None);
    }

    #[test]
    fn end_to_end_listener_classification_feeds_intercept_policy_and_excludes_self_tree() {
        let edges = vec![
            (100, 1),   // catcloud.exe
            (101, 100), // msedgewebview2.exe
            (102, 100), // mihomo.exe (CatCloud main core)
            (103, 100), // catcloud-probe-core.exe
            (888, 1),   // arbitrary third-party proxy core
        ];
        let excluded = collect_descendant_pids_from_roots(&[100], &edges);
        let mut names = HashMap::new();
        names.insert(102, "mihomo.exe".to_string());
        names.insert(888, "opaque-proxy-bin.exe".to_string());

        let listeners = vec![
            (Ipv4Addr::LOCALHOST, 27890, 102),
            (Ipv4Addr::LOCALHOST, 7897, 888),
        ];
        let detected = classify_local_proxy_listeners(&listeners, Some(7897), &excluded, &names);
        let manual_targets: HashSet<String> = HashSet::new();

        // CatCloud's own main mihomo core & WebView2 & probe core are excluded even under AllNon443Tcp.
        assert_eq!(
            classify_intercept_process(
                102,
                Some("mihomo.exe"),
                GlobalPreAccelScope::AllNon443Tcp,
                &manual_targets,
                &excluded,
                &detected,
            ),
            None
        );
        assert_eq!(
            classify_intercept_process(
                101,
                Some("msedgewebview2.exe"),
                GlobalPreAccelScope::AllNon443Tcp,
                &manual_targets,
                &excluded,
                &detected,
            ),
            None
        );
        assert_eq!(
            classify_intercept_process(
                103,
                Some("catcloud-probe-core.exe"),
                GlobalPreAccelScope::AllNon443Tcp,
                &manual_targets,
                &excluded,
                &detected,
            ),
            None
        );

        // Unknown third-party proxy binary is auto-detected & intercepted in ProxyAppsOnly mode.
        assert_eq!(
            classify_intercept_process(
                888,
                Some("opaque-proxy-bin.exe"),
                GlobalPreAccelScope::ProxyAppsOnly,
                &manual_targets,
                &excluded,
                &detected,
            ),
            Some("system_proxy_host")
        );
    }

    #[test]
    fn routable_public_ipv4_rejects_fake_ip_and_private_ranges() {
        assert!(!is_routable_public_ipv4(Ipv4Addr::new(198, 18, 0, 12)));
        assert!(!is_routable_public_ipv4(Ipv4Addr::new(198, 19, 255, 254)));
        assert!(!is_routable_public_ipv4(Ipv4Addr::new(192, 168, 1, 10)));
        assert!(!is_routable_public_ipv4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!is_routable_public_ipv4(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(!is_routable_public_ipv4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_routable_public_ipv4(Ipv4Addr::new(169, 254, 1, 5)));
        assert!(is_routable_public_ipv4(Ipv4Addr::new(223, 5, 5, 5)));
        assert!(is_routable_public_ipv4(Ipv4Addr::new(119, 29, 29, 29)));

        assert!(is_usable_local_nic_ipv4(Ipv4Addr::new(192, 168, 2, 100)));
        assert!(is_usable_local_nic_ipv4(Ipv4Addr::new(10, 0, 1, 5)));
        assert!(!is_usable_local_nic_ipv4(Ipv4Addr::new(198, 18, 0, 1)));
        assert!(!is_usable_local_nic_ipv4(Ipv4Addr::new(169, 254, 10, 2)));
        assert!(!is_usable_local_nic_ipv4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn dns_a_query_and_response_parser_skips_fake_ip_and_handles_compression() {
        let query = build_dns_a_query("connect.rom.miui.com", 0x1234).expect("valid query");
        assert!(query.len() > 16);
        assert_eq!(&query[0..2], &[0x12, 0x34]);

        // Synthetic response echoing question + 2 A answers: first is Fake-IP 198.18.0.5 (must skip),
        // second is public 119.29.29.29 (must select), both using 0xC00C compression pointers.
        let mut resp = query.clone();
        resp[2] = 0x81; // QR=1, RD=1
        resp[3] = 0x80; // RA=1, RCODE=0
        resp[7] = 2; // ANCOUNT=2
        // Answer 1: pointer 0xC00C, type A, class IN, TTL 60, len 4, 198.18.0.5
        resp.extend_from_slice(&[
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 198, 18, 0, 5,
        ]);
        // Answer 2: pointer 0xC00C, type A, class IN, TTL 60, len 4, 119.29.29.29
        resp.extend_from_slice(&[
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 119, 29, 29,
            29,
        ]);

        assert_eq!(
            parse_dns_a_response(&resp, 0x1234),
            Some(Ipv4Addr::new(119, 29, 29, 29))
        );
        assert_eq!(parse_dns_a_response(&resp, 0x9999), None);
    }

    #[test]
    fn parse_http_status_code_accepts_valid_lines_and_rejects_garbage() {
        assert_eq!(
            parse_http_status_code(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"),
            Some(204)
        );
        assert_eq!(
            parse_http_status_code(b"HTTP/1.0 200 OK\r\n"),
            Some(200)
        );
        assert_eq!(parse_http_status_code(b"NOT_HTTP 200 OK"), None);
        assert_eq!(parse_http_status_code(b"HTTP/1.1 999 Invalid"), None);
        assert_eq!(parse_http_status_code(b""), None);
    }

    #[test]
    fn host_readonly_physical_nic_and_security_product_detection_do_not_panic() {
        if let Some(nic) = detect_primary_physical_interface() {
            assert!(nic.if_idx > 0);
            assert!(!nic.friendly_name.trim().is_empty());
            assert!(is_usable_local_nic_ipv4(nic.local_ipv4));
        }
        let products = detect_windows_security_products();
        assert!(products.len() <= 16);
    }

    #[tokio::test]
    async fn set_ipv4_unicast_interface_binds_tcp_and_udp_sockets_and_rejects_invalid_handle() {
        // Invalid socket handle must return a real WinSock error.
        assert!(set_ipv4_unicast_interface(usize::MAX, 1).is_err());

        // Binding `if_idx = 0` (system default) works cleanly on both IPv4 TCP & UDP sockets.
        let tcp_lo = TcpSocket::new_v4().expect("create IPv4 TcpSocket");
        tcp_lo
            .bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
            .expect("bind loopback TCP");
        set_ipv4_unicast_interface(tcp_lo.as_raw_socket() as usize, 0)
            .expect("set IP_UNICAST_IF=0 on TCP socket");

        let udp_lo = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind loopback UDP");
        set_ipv4_unicast_interface(udp_lo.as_raw_socket() as usize, 0)
            .expect("set IP_UNICAST_IF=0 on UDP socket");

        // When a live physical NIC exists on the test host, also verify real `IP_UNICAST_IF`
        // pinning with its network-byte-order `if_idx` on both TCP and UDP sockets.
        if let Some(nic) = detect_primary_physical_interface() {
            let tcp_nic = TcpSocket::new_v4().expect("create IPv4 TcpSocket");
            tcp_nic
                .bind(SocketAddr::V4(SocketAddrV4::new(nic.local_ipv4, 0)))
                .expect("bind physical NIC TCP");
            set_ipv4_unicast_interface(tcp_nic.as_raw_socket() as usize, nic.if_idx)
                .expect("set IP_UNICAST_IF on physical NIC TCP socket");

            let udp_nic = UdpSocket::bind(SocketAddrV4::new(nic.local_ipv4, 0))
                .await
                .expect("bind physical NIC UDP");
            set_ipv4_unicast_interface(udp_nic.as_raw_socket() as usize, nic.if_idx)
                .expect("set IP_UNICAST_IF on physical NIC UDP socket");
        }
    }

    #[test]
    fn configure_loopback_outbound_addr_aligns_flags_and_zeroes_interface_indices() {
        let mut addr = WinDivertAddress::default();
        addr.set_outbound(false);
        addr.set_loopback(false);
        addr.set_impostor(true);
        addr.set_network_if_idx(14);
        addr.set_network_sub_if_idx(2);

        configure_loopback_outbound_addr(&mut addr);

        assert!(addr.outbound());
        assert!(addr.loopback());
        assert!(!addr.impostor());
        assert_eq!(addr.network_if_idx(), 0);
        assert_eq!(addr.network_sub_if_idx(), 0);
    }

    #[test]
    fn calc_and_inject_skips_send_when_checksum_fails_and_sends_when_checksum_succeeds() {
        static SEND_CALLS_FAIL_CASE: AtomicU64 = AtomicU64::new(0);
        static SEND_CALLS_OK_CASE: AtomicU64 = AtomicU64::new(0);

        unsafe extern "system" fn mock_open(
            _: *const u8,
            _: i32,
            _: i16,
            _: u64,
        ) -> HANDLE {
            std::ptr::null_mut()
        }
        unsafe extern "system" fn mock_recv(
            _: HANDLE,
            _: *mut c_void,
            _: u32,
            _: *mut u32,
            _: *mut WinDivertAddress,
        ) -> BOOL {
            0
        }
        unsafe extern "system" fn mock_shutdown(_: HANDLE, _: i32) -> BOOL {
            1
        }
        unsafe extern "system" fn mock_close(_: HANDLE) -> BOOL {
            1
        }
        unsafe extern "system" fn mock_csum_fail(
            _: *mut c_void,
            _: u32,
            _: *mut WinDivertAddress,
            _: u64,
        ) -> BOOL {
            0
        }
        unsafe extern "system" fn mock_csum_ok(
            _: *mut c_void,
            _: u32,
            _: *mut WinDivertAddress,
            _: u64,
        ) -> BOOL {
            1
        }
        unsafe extern "system" fn mock_send_fail_case(
            _: HANDLE,
            _: *const c_void,
            len: u32,
            sent: *mut u32,
            _: *const WinDivertAddress,
        ) -> BOOL {
            SEND_CALLS_FAIL_CASE.fetch_add(1, Ordering::SeqCst);
            if !sent.is_null() {
                unsafe {
                    *sent = len;
                }
            }
            1
        }
        unsafe extern "system" fn mock_send_ok_case(
            _: HANDLE,
            _: *const c_void,
            len: u32,
            sent: *mut u32,
            _: *const WinDivertAddress,
        ) -> BOOL {
            SEND_CALLS_OK_CASE.fetch_add(1, Ordering::SeqCst);
            if !sent.is_null() {
                unsafe {
                    *sent = len;
                }
            }
            1
        }

        let lib_fail = WinDivertLib {
            module: std::ptr::null_mut(),
            open: mock_open,
            recv: mock_recv,
            send: mock_send_fail_case,
            shutdown: mock_shutdown,
            close: mock_close,
            set_param: None,
            calc_checksums: mock_csum_fail,
        };
        let lib_ok = WinDivertLib {
            module: std::ptr::null_mut(),
            open: mock_open,
            recv: mock_recv,
            send: mock_send_ok_case,
            shutdown: mock_shutdown,
            close: mock_close,
            set_param: None,
            calc_checksums: mock_csum_ok,
        };

        let mut pkt = [0u8; 40];
        let mut addr = WinDivertAddress::default();
        let errors = AtomicU64::new(0);

        let before_fail_sends = SEND_CALLS_FAIL_CASE.load(Ordering::SeqCst);
        calc_and_inject(&lib_fail, std::ptr::null_mut(), &mut pkt, &mut addr, &errors);
        assert_eq!(errors.load(Ordering::Relaxed), 1);
        assert_eq!(
            SEND_CALLS_FAIL_CASE.load(Ordering::SeqCst),
            before_fail_sends,
            "WinDivertSend must NOT be called when WinDivertHelperCalcChecksums returns 0"
        );

        let before_ok_sends = SEND_CALLS_OK_CASE.load(Ordering::SeqCst);
        calc_and_inject(&lib_ok, std::ptr::null_mut(), &mut pkt, &mut addr, &errors);
        assert_eq!(errors.load(Ordering::Relaxed), 1);
        assert_eq!(
            SEND_CALLS_OK_CASE.load(Ordering::SeqCst),
            before_ok_sends + 1
        );
    }

    #[test]
    fn syn_retransmit_idempotency_and_client_syn_mss_clamp_work() {
        let now = Instant::now();
        let src_ip = Ipv4Addr::new(192, 0, 2, 10);
        let dst_ip = Ipv4Addr::new(203, 0, 113, 44);
        let active_entry = NatEntry {
            orig_src_ip: src_ip,
            orig_dst_ip: dst_ip,
            orig_dst_port: 8443,
            if_idx: 5,
            sub_if_idx: 0,
            owner_pid: 4321,
            process_name: "mihomo.exe".to_string(),
            detected_by: "open_core_name".to_string(),
            last_seen: now,
            closing_since: None,
        };

        assert!(is_matching_active_syn_retransmit(
            &active_entry,
            src_ip,
            dst_ip,
            8443
        ));
        assert!(!is_matching_active_syn_retransmit(
            &active_entry,
            Ipv4Addr::new(192, 0, 2, 11),
            dst_ip,
            8443
        ));
        assert!(!is_matching_active_syn_retransmit(
            &active_entry,
            src_ip,
            Ipv4Addr::new(203, 0, 113, 99),
            8443
        ));
        assert!(!is_matching_active_syn_retransmit(
            &active_entry,
            src_ip,
            dst_ip,
            9443
        ));

        let mut closing_entry = active_entry;
        closing_entry.closing_since = Some(now);
        assert!(!is_matching_active_syn_retransmit(
            &closing_entry,
            src_ip,
            dst_ip,
            8443
        ));

        // Client SYN packet with oversized MSS (65495) must be clamped to STANDARD_ETHERNET_TCP_MSS.
        let mut syn_pkt = [0u8; 44];
        syn_pkt[0] = 0x45;
        syn_pkt[9] = 6;
        syn_pkt[12..16].copy_from_slice(&src_ip.octets());
        syn_pkt[16..20].copy_from_slice(&dst_ip.octets());
        syn_pkt[20..22].copy_from_slice(&51111u16.to_be_bytes());
        syn_pkt[22..24].copy_from_slice(&8443u16.to_be_bytes());
        syn_pkt[32] = 6 << 4;
        syn_pkt[33] = Ipv4TcpMeta::FLAG_SYN;
        syn_pkt[40] = 2;
        syn_pkt[41] = 4;
        syn_pkt[42..44].copy_from_slice(&65495u16.to_be_bytes());

        let meta = parse_ipv4_tcp_packet(&syn_pkt).expect("parse client SYN");
        assert!(meta.is_syn_only());
        assert!(rewrite_ipv4_tcp_to_loopback(&mut syn_pkt, meta.ihl_bytes, 49000));
        assert!(clamp_tcp_syn_mss(
            &mut syn_pkt,
            meta.ihl_bytes,
            STANDARD_ETHERNET_TCP_MSS
        ));
        assert_eq!(
            u16::from_be_bytes([syn_pkt[42], syn_pkt[43]]),
            STANDARD_ETHERNET_TCP_MSS
        );
    }

    #[test]
    fn classify_tcp_owner_row_rejects_loose_port_only_fallback_and_accepts_exact_or_syn_sent() {
        let local_ip = Ipv4Addr::new(192, 0, 2, 10);
        let remote_ip = Ipv4Addr::new(203, 0, 113, 50);
        let other_remote_ip = Ipv4Addr::new(203, 0, 113, 99);
        let target_local = u32::from_ne_bytes(local_ip.octets());
        let target_remote = u32::from_ne_bytes(remote_ip.octets());
        let other_remote = u32::from_ne_bytes(other_remote_ip.octets());

        let make_row = |state: u32, laddr: u32, lport: u16, raddr: u32, rport: u16, pid: u32| {
            MIB_TCPROW_OWNER_PID {
                dwState: state,
                dwLocalAddr: laddr,
                dwLocalPort: u32::from(lport.to_be()),
                dwRemoteAddr: raddr,
                dwRemotePort: u32::from(rport.to_be()),
                dwOwningPid: pid,
            }
        };

        // Exact 4-tuple match wins regardless of state.
        let exact = make_row(5, target_local, 50000, target_remote, 8443, 1001);
        assert_eq!(
            classify_tcp_owner_row(&exact, target_local, 50000, target_remote, 8443),
            TcpOwnerRowMatch::Exact(1001)
        );

        // Unspecified local IP (`0.0.0.0`) with exact remote tuple also matches.
        let exact_wildcard = make_row(3, 0, 50000, target_remote, 8443, 1002);
        assert_eq!(
            classify_tcp_owner_row(&exact_wildcard, target_local, 50000, target_remote, 8443),
            TcpOwnerRowMatch::Exact(1002)
        );

        // Same remote IP in `MIB_TCP_STATE_SYN_SENT (3)` is accepted even if remote port differs.
        let syn_sent_same_remote =
            make_row(MIB_TCP_STATE_SYN_SENT, target_local, 50000, target_remote, 0, 1003);
        assert_eq!(
            classify_tcp_owner_row(
                &syn_sent_same_remote,
                target_local,
                50000,
                target_remote,
                8443
            ),
            TcpOwnerRowMatch::SynSentSameRemote(1003)
        );

        // Loose local_port-only rows pointing to a DIFFERENT remote IP must NEVER match.
        let diff_remote_estab = make_row(5, target_local, 50000, other_remote, 8443, 2001);
        assert_eq!(
            classify_tcp_owner_row(&diff_remote_estab, target_local, 50000, target_remote, 8443),
            TcpOwnerRowMatch::None
        );
        let diff_remote_syn = make_row(
            MIB_TCP_STATE_SYN_SENT,
            target_local,
            50000,
            other_remote,
            8443,
            2002,
        );
        assert_eq!(
            classify_tcp_owner_row(&diff_remote_syn, target_local, 50000, target_remote, 8443),
            TcpOwnerRowMatch::None
        );

        // Same remote IP but different port and NOT in SYN_SENT (e.g. ESTABLISHED=5 / TIME_WAIT=11) must NOT match.
        let same_remote_diff_port_estab =
            make_row(5, target_local, 50000, target_remote, 9443, 2003);
        assert_eq!(
            classify_tcp_owner_row(
                &same_remote_diff_port_estab,
                target_local,
                50000,
                target_remote,
                8443
            ),
            TcpOwnerRowMatch::None
        );
    }

    #[tokio::test]
    async fn read_http_status_code_from_stream_handles_tcp_segmentation_and_eof() {
        // 1. Heavily segmented HTTP status line arriving in tiny chunks + trailing binary bytes.
        let (mut client, mut server) = tokio::io::duplex(64);
        let writer = tokio::spawn(async move {
            for chunk in [
                &b"HT"[..],
                &b"TP/1."[..],
                &b"1 2"[..],
                &b"04 No Con"[..],
                &b"tent\r\n"[..],
                &[0xFFu8, 0xFE, 0x00][..],
            ] {
                server.write_all(chunk).await.unwrap();
                tokio::task::yield_now().await;
            }
            let _ = server.shutdown().await;
        });

        let code = read_http_status_code_from_stream(&mut client)
            .await
            .expect("segmented read ok");
        assert_eq!(code, Some(204));
        let _ = writer.await;

        // 2. Truncated stream hitting EOF without `\r\n` still exits cleanly without hanging.
        let (mut client2, mut server2) = tokio::io::duplex(64);
        let writer2 = tokio::spawn(async move {
            server2.write_all(b"HTTP/1.1 20").await.unwrap();
            let _ = server2.shutdown().await;
        });
        let code2 = read_http_status_code_from_stream(&mut client2)
            .await
            .expect("eof read ok");
        assert_eq!(code2, None);
        let _ = writer2.await;
    }

    #[test]
    fn classify_local_proxy_listeners_rejects_im_and_random_ports_while_keeping_proxy_stems_and_common_ports()
    {
        let excluded: HashSet<u32> = HashSet::new();
        let mut names: HashMap<u32, String> = HashMap::new();
        names.insert(2001, "QQ.exe".to_string());
        names.insert(2002, "WeChat.exe".to_string());
        names.insert(2003, "Code.exe".to_string());
        names.insert(2004, "random-desktop-app.exe".to_string());
        names.insert(2005, "opaque-app.exe".to_string());
        names.insert(2006, "custom-socks-daemon.exe".to_string());
        names.insert(2007, "proxy-engine.exe".to_string());
        names.insert(2008, "custom-tun-helper.exe".to_string());
        names.insert(2009, "custom-core.exe".to_string());
        names.insert(2010, "custom-serv.exe".to_string());
        names.insert(2011, "MpDefenderCoreService.exe".to_string());
        names.insert(2012, "iTunes.exe".to_string());
        names.insert(2013, "chrome.exe".to_string());
        names.insert(2014, "steam.exe".to_string());
        names.insert(2015, "opaque-local.exe".to_string());

        let listeners = vec![
            // IM / IDE / browser / gaming apps must NEVER be tagged even on standard proxy ports.
            (Ipv4Addr::LOCALHOST, 4301, 2001),
            (Ipv4Addr::LOCALHOST, 7890, 2001),
            (Ipv4Addr::LOCALHOST, 10808, 2002),
            (Ipv4Addr::LOCALHOST, 20170, 2003),
            (Ipv4Addr::LOCALHOST, 17890, 2013),
            (Ipv4Addr::LOCALHOST, 7891, 2014),
            // Non-proxy OS/AV/media binaries containing `core`/`serv`/`tun` must NOT be tagged.
            (Ipv4Addr::LOCALHOST, 18900, 2011),
            (Ipv4Addr::LOCALHOST, 18901, 2012),
            // Generic unknown desktop app on a random non-proxy port must NOT be blindly tagged.
            (Ipv4Addr::LOCALHOST, 54321, 2004),
            // Unknown binaries on standard proxy ports (`7897`, `17890`) ARE tagged as local_proxy_listener.
            (Ipv4Addr::LOCALHOST, 7897, 2005),
            (Ipv4Addr::LOCALHOST, 17890, 2015),
            // Generic proxy stems (`socks`, `proxy`, `tun`, `core`, `serv`) on custom high ports ARE tagged.
            (Ipv4Addr::LOCALHOST, 18888, 2006),
            (Ipv4Addr::UNSPECIFIED, 10808, 2007),
            (Ipv4Addr::LOCALHOST, 19901, 2008),
            (Ipv4Addr::LOCALHOST, 19902, 2009),
            (Ipv4Addr::LOCALHOST, 19903, 2010),
        ];

        let detected = classify_local_proxy_listeners(&listeners, None, &excluded, &names);
        for rejected in [2001, 2002, 2003, 2004, 2011, 2012, 2013, 2014] {
            assert!(
                !detected.contains_key(&rejected),
                "pid {rejected} must NOT be tagged as local_proxy_listener"
            );
        }
        for accepted in [2005, 2006, 2007, 2008, 2009, 2010, 2015] {
            assert_eq!(
                detected.get(&accepted).copied(),
                Some("local_proxy_listener"),
                "pid {accepted} should be tagged as local_proxy_listener"
            );
        }
        assert_eq!(detected.len(), 7);
    }

    #[test]
    fn domestic_http_80_bypass_and_443_gate_decisions_work_accurately() {
        let cn_ip = Ipv4Addr::from(0xDCB5_2694u32);
        let overseas_ip = Ipv4Addr::from(0x6812_0001u32);

        // Domestic HTTP :80 bypasses directly; overseas :80 and domestic non-80 (e.g. airport entry) do not.
        assert!(should_bypass_domestic_http_80(80, cn_ip));
        assert!(!should_bypass_domestic_http_80(80, overseas_ip));
        assert!(!should_bypass_domestic_http_80(8443, cn_ip));
        assert!(!should_bypass_domestic_http_80(443, cn_ip));

        // Fast-path 443 bypass rejects skipped or domestic 443 before PID lookup, while letting
        // overseas 443 proceed to proxy-core identity verification when `skip_443_native == false`.
        assert!(should_fast_bypass_port_443(443, true, overseas_ip));
        assert!(should_fast_bypass_port_443(443, false, cn_ip));
        assert!(!should_fast_bypass_port_443(443, false, overseas_ip));
        assert!(!should_fast_bypass_port_443(8443, false, cn_ip));

        // Port 443 gate respects skip_443_native, exact proxy labels, and non-domestic destination.
        assert!(!should_intercept_port_443("open_core_name", true, overseas_ip));
        assert!(should_intercept_port_443("open_core_name", false, overseas_ip));
        assert!(!should_intercept_port_443("open_core_name", false, cn_ip));
        assert!(!should_intercept_port_443("manual", false, overseas_ip));
        assert!(!should_intercept_port_443("scope_all", false, overseas_ip));
    }
}
