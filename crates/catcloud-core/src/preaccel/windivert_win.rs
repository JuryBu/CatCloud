#![cfg_attr(target_arch = "aarch64", allow(dead_code, unused_imports))]

use crate::error::{CatError, CatResult};
use crate::models::GlobalPreAccelScope;
use crate::preaccel::global_tunnel::{
    ExcludedPidTracker, GlobalPreAccelMetrics, MAX_NAT_ENTRIES, NAT_IDLE_TIMEOUT, NatEntry,
    NatTable, WinDivertAddress, build_windivert_filter, forward_redirected_stream,
    is_physical_nic_descriptor, normalize_process_basename, parse_ipv4_tcp_packet,
    rewrite_ipv4_tcp_dst, rewrite_ipv4_tcp_src, should_intercept_process,
};
use std::collections::{HashMap, HashSet};
use std::ffi::{CString, OsStr, c_void};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinHandle as TokioJoinHandle;
use windows_sys::Win32::Foundation::{
    BOOL, CloseHandle, ERROR_INSUFFICIENT_BUFFER, FreeLibrary, GetLastError, HANDLE, HMODULE,
    INVALID_HANDLE_VALUE, NO_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetIfTable, MIB_IFROW, MIB_IFTABLE, MIB_TCPROW_OWNER_PID,
    MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_CONNECTIONS,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_WITH_ALTERED_SEARCH_PATH, LoadLibraryExW, LoadLibraryW,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

const WINDIVERT_LAYER_NETWORK: i32 = 0;
const WINDIVERT_SHUTDOWN_BOTH: i32 = 3;
const WINDIVERT_PARAM_QUEUE_LENGTH: i32 = 0;
const WINDIVERT_PARAM_QUEUE_TIME: i32 = 1;
const WINDIVERT_PARAM_QUEUE_SIZE: i32 = 2;

const MAX_BYPASS_CACHE_ENTRIES: usize = 4096;
const BYPASS_CACHE_TTL: Duration = Duration::from_secs(30);
const MAX_PID_CACHE_ENTRIES: usize = 512;
const PID_CACHE_TTL: Duration = Duration::from_secs(10);
const NIC_CACHE_REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const MAX_CONCURRENT_REDIRECT_CONNS: usize = 512;

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

/// Runtime parameters passed to start the Windows transparent WinDivert TCP NAT engine.
pub struct WinDivertEngineConfig {
    pub dll_path: std::path::PathBuf,
    pub socks_port: u16,
    pub relay_ipv4s: Vec<Ipv4Addr>,
    pub scope: GlobalPreAccelScope,
    pub target_processes: Vec<String>,
    pub excluded_pids: HashSet<u32>,
    pub tunnel_pid: Option<u32>,
    pub main_core_pid: Option<u32>,
    pub metrics: Arc<GlobalPreAccelMetrics>,
}

/// Active Windows WinDivert kernel transparent TCP interceptor + local self-loop SOCKS5 forwarder.
pub struct WinDivertEngine {
    lib: Arc<WinDivertLib>,
    handle: SendHandle,
    stop_flag: Arc<AtomicBool>,
    shutdown_tx: watch::Sender<bool>,
    excluded_pid_tracker: ExcludedPidTracker,
    worker_thread: Option<JoinHandle<()>>,
    accept_task: Option<TokioJoinHandle<()>>,
    redirect_port: u16,
}

impl std::fmt::Debug for WinDivertEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WinDivertEngine")
            .field("redirect_port", &self.redirect_port)
            .field("running", &(!self.stop_flag.load(Ordering::Relaxed)))
            .finish()
    }
}

impl WinDivertEngine {
    /// Start the local `0.0.0.0:0` self-loop TCP redirector and open the WinDivert kernel filter.
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

            // Bind local self-loop redirector on `0.0.0.0:0`; unregistered peers are dropped immediately.
            let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
                .await
                .map_err(|e| CatError::Process(format!("绑定本地透明重定向监听端口失败: {e}")))?;
            let redirect_port = listener.local_addr()?.port();

            let filter_str = build_windivert_filter(&cfg.relay_ipv4s, redirect_port);
            let filter_cstr = CString::new(filter_str.as_str()).map_err(|e| {
                CatError::Validation(format!("WinDivert 过滤表达式包含非法字符: {e}"))
            })?;

            // SAFETY: `filter_cstr` is a valid NUL-terminated ASCII filter for `WINDIVERT_LAYER_NETWORK`.
            let raw_handle = unsafe {
                (lib.open)(
                    filter_cstr.as_ptr().cast(),
                    WINDIVERT_LAYER_NETWORK,
                    0,
                    0,
                )
            };
            if raw_handle.is_null() || raw_handle == INVALID_HANDLE_VALUE {
                let err = unsafe { GetLastError() };
                let hint = match err {
                    5 => "权限不足（错误码 5），请以管理员身份运行猫猫云梯",
                    2 => "未找到 WinDivert64.sys 驱动文件（错误码 2）",
                    577 => "Windows 驱动签名校验拦截了 WinDivert64.sys（错误码 577）",
                    1275 => "驱动加载被安全策略/安全软件拦截（错误码 1275）",
                    _ => "请确认已管理员运行且安全软件未拦截 WinDivert64.sys",
                };
                return Err(CatError::Core(format!(
                    "WinDivertOpen 启动失败 (win32_err={err}): {hint}"
                )));
            }

            if let Some(set_param) = lib.set_param {
                // SAFETY: `raw_handle` is a newly opened valid WinDivert handle.
                unsafe {
                    let _ = set_param(raw_handle, WINDIVERT_PARAM_QUEUE_LENGTH, 4096);
                    let _ = set_param(raw_handle, WINDIVERT_PARAM_QUEUE_TIME, 2000);
                    let _ = set_param(raw_handle, WINDIVERT_PARAM_QUEUE_SIZE, 8 * 1024 * 1024);
                }
            }

            let nat_table = Arc::new(NatTable::new(MAX_NAT_ENTRIES, NAT_IDLE_TIMEOUT));
            let stop_flag = Arc::new(AtomicBool::new(false));
            let (shutdown_tx, mut accept_shutdown_rx) = watch::channel(false);

            // Spawn Tokio accept loop forwarding NAT-verified flows to the standalone 443 SOCKS5 tunnel,
            // capped at `MAX_CONCURRENT_REDIRECT_CONNS` concurrent forwarder tasks.
            let nat_for_accept = Arc::clone(&nat_table);
            let metrics_for_accept = Arc::clone(&cfg.metrics);
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

            let target_processes_lower: HashSet<String> = cfg
                .target_processes
                .iter()
                .map(|p| normalize_process_basename(p))
                .filter(|p| !p.is_empty())
                .collect();

            let excluded_pid_tracker = ExcludedPidTracker::new(
                std::process::id(),
                cfg.tunnel_pid,
                cfg.excluded_pids,
                cfg.main_core_pid,
            );

            let worker_ctx = PacketWorkerContext {
                lib: Arc::clone(&lib),
                handle: SendHandle(raw_handle),
                stop_flag: Arc::clone(&stop_flag),
                nat_table,
                redirect_port,
                scope: cfg.scope,
                target_processes_lower,
                excluded_pids: excluded_pid_tracker.shared_set(),
            };

            let worker_thread = std::thread::Builder::new()
                .name("catcloud-windivert".to_string())
                .spawn(move || run_packet_worker(worker_ctx))
                .map_err(|e| {
                    let _ = shutdown_tx.send(true);
                    accept_task.abort();
                    unsafe {
                        let _ = (lib.shutdown)(raw_handle, WINDIVERT_SHUTDOWN_BOTH);
                        let _ = (lib.close)(raw_handle);
                    }
                    CatError::Process(format!("启动 WinDivert 抓包线程失败: {e}"))
                })?;

            Ok(Self {
                lib,
                handle: SendHandle(raw_handle),
                stop_flag,
                shutdown_tx,
                excluded_pid_tracker,
                worker_thread: Some(worker_thread),
                accept_task: Some(accept_task),
                redirect_port,
            })
        }
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

    /// Deterministically stop packet interception, close the kernel handle, and abort forwarder tasks.
    pub fn stop_sync(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        let _ = self.shutdown_tx.send(true);

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
    }
}

impl Drop for WinDivertEngine {
    fn drop(&mut self) {
        self.stop_sync();
    }
}

struct PacketWorkerContext {
    lib: Arc<WinDivertLib>,
    handle: SendHandle,
    stop_flag: Arc<AtomicBool>,
    nat_table: Arc<NatTable>,
    redirect_port: u16,
    scope: GlobalPreAccelScope,
    target_processes_lower: HashSet<String>,
    excluded_pids: Arc<RwLock<HashSet<u32>>>,
}

fn run_packet_worker(ctx: PacketWorkerContext) {
    let mut pkt_buf = vec![0u8; 65535];

    let mut physical_ifs = query_physical_interface_indices();
    let mut last_nic_refresh = Instant::now();
    let mut pid_cache: HashMap<u32, (String, Instant)> = HashMap::with_capacity(64);
    let mut bypass_cache: HashMap<(Ipv4Addr, u16, Ipv4Addr, u16), Instant> =
        HashMap::with_capacity(256);

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

        // Branch 1: Return packet from local self-loop redirector (`tcp.SrcPort == redirect_port`).
        if meta.src_port == ctx.redirect_port {
            if let Some(entry) = ctx.nat_table.get_and_touch(&(meta.dst_ip, meta.dst_port)) {
                if rewrite_ipv4_tcp_src(
                    &mut pkt_buf[..pkt_len],
                    meta.ihl_bytes,
                    entry.orig_dst_ip,
                    entry.orig_dst_port,
                ) {
                    addr.set_outbound(false);
                    addr.set_loopback(false);
                    addr.set_impostor(false);
                    addr.set_network_if_idx(entry.if_idx);
                    addr.set_network_sub_if_idx(entry.sub_if_idx);
                    calc_and_inject(&ctx.lib, ctx.handle.0, &mut pkt_buf[..pkt_len], &mut addr);
                    continue;
                }
            }
            reinject_raw(&ctx.lib, ctx.handle.0, &pkt_buf[..pkt_len], &addr);
            continue;
        }

        // Branch 2: Outbound public non-443/non-53 TCP packet.
        // Strict fail-closed: only intercept traffic leaving confirmed physical interfaces
        // (when physical NIC set is empty or does not contain `if_idx`, pass through untouched
        // so virtual Wintun/VPN adapters are never blindly hijacked).
        let now = Instant::now();
        if now.saturating_duration_since(last_nic_refresh) >= NIC_CACHE_REFRESH_INTERVAL {
            let refreshed = query_physical_interface_indices();
            if !refreshed.is_empty() {
                physical_ifs = refreshed;
            }
            last_nic_refresh = now;
        }

        let if_idx = addr.network_if_idx();
        if !physical_ifs.contains(&if_idx) {
            reinject_raw(&ctx.lib, ctx.handle.0, &pkt_buf[..pkt_len], &addr);
            continue;
        }

        let nat_key = (meta.src_ip, meta.src_port);
        let flow_key = (meta.src_ip, meta.src_port, meta.dst_ip, meta.dst_port);

        // Fast path: already tracked in NAT table for the same destination.
        if !meta.is_syn_only() {
            if let Some(existing) = ctx.nat_table.get_and_touch(&nat_key) {
                if existing.orig_dst_ip == meta.dst_ip && existing.orig_dst_port == meta.dst_port {
                    if rewrite_ipv4_tcp_dst(
                        &mut pkt_buf[..pkt_len],
                        meta.ihl_bytes,
                        meta.src_ip,
                        ctx.redirect_port,
                    ) {
                        addr.set_outbound(false);
                        addr.set_loopback(false);
                        addr.set_impostor(false);
                        calc_and_inject(&ctx.lib, ctx.handle.0, &mut pkt_buf[..pkt_len], &mut addr);
                        continue;
                    }
                }
            }
            // Never hijack mid-stream packets for connections established before engine startup.
            reinject_raw(&ctx.lib, ctx.handle.0, &pkt_buf[..pkt_len], &addr);
            continue;
        }

        // New outbound TCP SYN: check short bypass cache first, clearing any stale NAT entry
        // for the same local ephemeral port before passing through.
        if let Some(&cached_at) = bypass_cache.get(&flow_key) {
            if now.saturating_duration_since(cached_at) < BYPASS_CACHE_TTL {
                ctx.nat_table.remove(&nat_key);
                reinject_raw(&ctx.lib, ctx.handle.0, &pkt_buf[..pkt_len], &addr);
                continue;
            }
            bypass_cache.remove(&flow_key);
        }

        // Resolve owning PID (compatible with LocalSystem services) and executable basename.
        let owner_pid = lookup_tcp_owner_pid(meta.src_ip, meta.src_port, meta.dst_ip, meta.dst_port);
        let intercept_proc: Option<String> = match owner_pid {
            Some(pid) => {
                let proc_name = lookup_process_name_cached(pid, &mut pid_cache, now);
                let should_intercept = {
                    let excluded_guard = ctx
                        .excluded_pids
                        .read()
                        .unwrap_or_else(|e| e.into_inner());
                    should_intercept_process(
                        pid,
                        proc_name.as_deref(),
                        ctx.scope,
                        &ctx.target_processes_lower,
                        &excluded_guard,
                    )
                };
                if should_intercept {
                    Some(proc_name.unwrap_or_else(|| format!("pid:{pid}")))
                } else {
                    None
                }
            }
            None => None,
        };

        if let Some(process_name) = intercept_proc {
            ctx.nat_table.insert(
                nat_key,
                NatEntry {
                    orig_dst_ip: meta.dst_ip,
                    orig_dst_port: meta.dst_port,
                    if_idx,
                    sub_if_idx: addr.network_sub_if_idx(),
                    process_name,
                    last_seen: now,
                },
            );
            if rewrite_ipv4_tcp_dst(
                &mut pkt_buf[..pkt_len],
                meta.ihl_bytes,
                meta.src_ip,
                ctx.redirect_port,
            ) {
                addr.set_outbound(false);
                addr.set_loopback(false);
                addr.set_impostor(false);
                calc_and_inject(&ctx.lib, ctx.handle.0, &mut pkt_buf[..pkt_len], &mut addr);
                continue;
            }
            // Rewrite failed unexpectedly: clear the NAT entry before falling through to pass-through.
            ctx.nat_table.remove(&nat_key);
        } else {
            ctx.nat_table.remove(&nat_key);
            insert_bounded_bypass(&mut bypass_cache, flow_key, now);
        }

        reinject_raw(&ctx.lib, ctx.handle.0, &pkt_buf[..pkt_len], &addr);
    }
}

fn calc_and_inject(lib: &WinDivertLib, handle: HANDLE, pkt: &mut [u8], addr: &mut WinDivertAddress) {
    // SAFETY: `pkt` and `addr` point to valid initialized buffers of exact lengths.
    unsafe {
        let _ = (lib.calc_checksums)(pkt.as_mut_ptr().cast(), pkt.len() as u32, addr, 0);
        let mut sent: u32 = 0;
        let _ = (lib.send)(handle, pkt.as_ptr().cast(), pkt.len() as u32, &mut sent, addr);
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
    let mut actual_size = (aligned_buf.len() * 8) as u32;

    // SAFETY: `aligned_buf` is 8-byte aligned and holds at least `actual_size` bytes.
    let status = unsafe { GetIfTable(aligned_buf.as_mut_ptr().cast::<MIB_IFTABLE>(), &mut actual_size, 0) };
    if status != NO_ERROR {
        return indices;
    }

    let base_ptr = aligned_buf.as_ptr().cast::<u8>();
    let total_bytes = aligned_buf.len() * 8;
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

/// Query the owning PID of an active IPv4 TCP connection via
/// `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_CONNECTIONS)`.
fn lookup_tcp_owner_pid(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
) -> Option<u32> {
    let mut size: u32 = 16 * 1024;
    let mut aligned_buf: Vec<u64> = Vec::new();

    for _ in 0..4 {
        let alloc_bytes = (size as usize).max(4096);
        aligned_buf.resize(alloc_bytes.div_ceil(8), 0u64);
        let mut buf_size = (aligned_buf.len() * 8) as u32;

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
            break;
        }
        if status == ERROR_INSUFFICIENT_BUFFER {
            size = buf_size.saturating_add(4096);
            continue;
        }
        return None;
    }

    let total_bytes = (aligned_buf.len() * 8).min(size as usize);
    let base_ptr = aligned_buf.as_ptr().cast::<u8>();
    if total_bytes < std::mem::size_of::<u32>() {
        return None;
    }

    let num_entries = unsafe { (*(base_ptr.cast::<MIB_TCPTABLE_OWNER_PID>())).dwNumEntries } as usize;
    let table_offset = std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table);
    let row_size = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();

    let target_local_ip = u32::from_ne_bytes(src_ip.octets());
    let target_remote_ip = u32::from_ne_bytes(dst_ip.octets());

    let mut fallback_pid: Option<u32> = None;

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

        let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
        if local_port != src_port {
            continue;
        }
        let local_ip_ok = row.dwLocalAddr == target_local_ip || row.dwLocalAddr == 0;
        if !local_ip_ok {
            continue;
        }

        let remote_port = u16::from_be((row.dwRemotePort & 0xFFFF) as u16);
        if row.dwRemoteAddr == target_remote_ip && remote_port == dst_port {
            return Some(row.dwOwningPid);
        }

        if fallback_pid.is_none() {
            fallback_pid = Some(row.dwOwningPid);
        }
    }

    fallback_pid
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
