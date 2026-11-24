use crate::core_adapter::resolve_mihomo_binary;
use crate::error::{CatError, CatResult};
use crate::models::{AppConfig, GlobalPreAccelScope, PreAccelConfig, PreAccelRelay};
use crate::paths::{AppPaths, normalize_os_path};
use crate::platform::default_platform;
use crate::preaccel::generator::{PREACCEL_SELECT_GROUP, build_preaccel_compile_plan};
use crate::preaccel::schema::{parse_server_ip, sanitize_relay_for_domestic_443};
use crate::process_guard::JobGuard;
use serde::{Deserialize, Serialize};
use serde_yaml_ng::{Mapping, Number, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::io::{Cursor, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener as StdTcpListener};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use url::Url;
use zip::ZipArchive;

/// Official WinDivert v2.2.2 release archive download URL (`basil00/Divert`).
pub const WINDIVERT_DOWNLOAD_URL: &str =
    "https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip";

/// Verified SHA-256 checksum of official `WinDivert-2.2.2-A.zip`.
pub const WINDIVERT_ZIP_SHA256: &str =
    "63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15";

/// Hard upper bound for downloaded WinDivert ZIP archive (16 MiB).
#[cfg_attr(
    all(target_os = "windows", target_arch = "aarch64"),
    allow(dead_code)
)]
const MAX_WINDIVERT_ZIP_BYTES: usize = 16 * 1024 * 1024;

/// Hard upper bound for a single extracted WinDivert binary file (8 MiB).
const MAX_WINDIVERT_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// Allowed HTTPS redirect hosts when downloading official WinDivert releases.
#[cfg_attr(
    all(target_os = "windows", target_arch = "aarch64"),
    allow(dead_code)
)]
const ALLOWED_WINDIVERT_HOSTS: &[&str] = &[
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "raw.githubusercontent.com",
];

/// Actionable Chinese notice returned when WinDivert is requested on Windows ARM64,
/// where official WinDivert v2.2.2 provides no native ARM64 kernel driver.
#[cfg_attr(
    not(all(target_os = "windows", target_arch = "aarch64")),
    allow(dead_code)
)]
pub(super) const WINDIVERT_ARM64_UNSUPPORTED_MSG: &str = "当前为 Windows ARM64 架构，官方 WinDivert v2.2.2 未提供原生 ARM64 内核驱动；请使用内置的「本地独立 443 通道 (SOCKS5)」为其它软件提速";

/// Maximum number of concurrent/recent NAT entries tracked by the transparent TCP NAT table.
pub const MAX_NAT_ENTRIES: usize = 4096;

/// Idle eviction timeout for stale NAT table entries.
pub const NAT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum number of distinct recent accelerated process names retained in status snapshots.
const MAX_RECENT_PROCESSES: usize = 32;

/// Maximum number of distinct per-process telemetry buckets tracked simultaneously.
const MAX_PROCESS_STATS: usize = 64;

/// Generic open-source proxy core / tunnel executable stems recognized dynamically
/// without hardcoding any proprietary or commercial client names.
const OPEN_SOURCE_PROXY_CORE_STEMS: &[&str] = &[
    "mihomo",
    "clash",
    "xray",
    "v2ray",
    "sing-box",
    "singbox",
    "hysteria",
    "tuic",
    "trojan",
    "tun2socks",
    "naive",
    "shadowsocks",
    "sslocal",
    "ss-local",
];

/// Maximum startup readiness wait for the standalone lightweight 443 Mihomo tunnel.
const STANDALONE_TUNNEL_READY_TIMEOUT: Duration = Duration::from_secs(6);

/// Polling interval while waiting for the standalone 443 tunnel SOCKS5 port.
const STANDALONE_TUNNEL_POLL_INTERVAL: Duration = Duration::from_millis(80);

/// Dedicated memory budget for the lightweight standalone 443 tunnel subprocess.
pub const STANDALONE_TUNNEL_GOMEMLIMIT: &str = "24MiB";

/// Dedicated GC target for the lightweight standalone 443 tunnel subprocess.
pub const STANDALONE_TUNNEL_GOGC: &str = "25";

/// Built-in core OS and CatCloud process names unconditionally excluded from transparent
/// WinDivert interception (case-insensitive) to guarantee system stability and zero loops.
const SYSTEM_AND_SELF_EXCLUDED_PROCESSES: &[&str] = &[
    "system",
    "idle",
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "smss.exe",
    "services.exe",
    "wininit.exe",
    "winlogon.exe",
    "catcloud.exe",
    "catcloud-desktop.exe",
    "catcloud-probe-core.exe",
];

// ============================================================================
// A. Standalone Lightweight Domestic :443 Dual-Active Tunnel (Cross-Platform)
// ============================================================================

/// Compile a minimal, zero-TUN, zero-DNS, zero-controller Mihomo YAML configuration for
/// the standalone domestic :443 active-standby pre-acceleration SOCKS5 tunnel.
///
/// Guarantees:
/// - Only enabled domestic relays are included; `:443` relays have unfiled third-party SNI
///   stripped (`sanitize_relay_for_domestic_443`) and `skip-cert-verify: true` for pure IPs.
/// - Reuses `preaccel::generator::build_preaccel_compile_plan` to emit `⚡ 国内预加速入口`
///   (`select`) -> `🔄 预加速自动双活` (`fallback`, domestic 204 probe, `lazy: false`).
/// - Listens strictly on `127.0.0.1:<socks_port>` (`allow-lan: false`), never sets
///   `external-controller`, never writes system proxy, disables `tun` and `dns`.
/// - Pins all relay public IPs, domestic 204 probe hosts, and private/loopback CIDRs as
///   top-priority `DIRECT,no-resolve` rules ahead of `MATCH,⚡ 国内预加速入口` to prevent loops.
pub fn compile_standalone_preaccel_yaml(
    cfg: &AppConfig,
    relays: &[PreAccelRelay],
    socks_port: u16,
) -> CatResult<String> {
    if socks_port == 0 {
        return Err(CatError::Validation(
            "standalone pre-acceleration socks_port must be within 1..=65535".to_string(),
        ));
    }

    let sanitized_relays: Vec<PreAccelRelay> = relays
        .iter()
        .filter(|r| r.enabled)
        .map(|r| {
            if r.port == 443 {
                sanitize_relay_for_domestic_443(r)
            } else {
                r.clone()
            }
        })
        .collect();

    if sanitized_relays.is_empty() {
        return Err(CatError::Validation(
            "没有已启用的国内 443 中转节点，无法编译独立预加速隧道配置".to_string(),
        ));
    }

    // Force `enabled = true` on a cloned config so standalone pre-accel can run independently
    // even while CatCloud's primary proxy or dialer-proxy toggle is off.
    let mut standalone_preaccel: PreAccelConfig = cfg.preaccel.clone();
    standalone_preaccel.enabled = true;

    let plan = build_preaccel_compile_plan(&standalone_preaccel, &sanitized_relays, &[])?;
    if !plan.active || plan.relay_proxies.is_empty() {
        return Err(CatError::Validation(
            "独立 443 预加速隧道未能生成有效中转节点配置".to_string(),
        ));
    }

    let mut root = Mapping::new();
    root.insert(
        Value::String("socks-port".to_string()),
        Value::Number(Number::from(socks_port)),
    );
    root.insert(
        Value::String("bind-address".to_string()),
        Value::String("127.0.0.1".to_string()),
    );
    root.insert(Value::String("allow-lan".to_string()), Value::Bool(false));
    root.insert(
        Value::String("mode".to_string()),
        Value::String("rule".to_string()),
    );
    root.insert(
        Value::String("log-level".to_string()),
        Value::String("warning".to_string()),
    );
    root.insert(Value::String("ipv6".to_string()), Value::Bool(false));
    root.insert(
        Value::String("find-process-mode".to_string()),
        Value::String("off".to_string()),
    );
    root.insert(
        Value::String("keep-alive-idle".to_string()),
        Value::Number(Number::from(15u64)),
    );
    root.insert(
        Value::String("keep-alive-interval".to_string()),
        Value::Number(Number::from(15u64)),
    );
    root.insert(
        Value::String("geo-auto-update".to_string()),
        Value::Bool(false),
    );
    root.insert(
        Value::String("geodata-mode".to_string()),
        Value::Bool(false),
    );
    root.insert(
        Value::String("geodata-loader".to_string()),
        Value::String("memconservative".to_string()),
    );

    let mut profile_map = Mapping::new();
    profile_map.insert(
        Value::String("store-selected".to_string()),
        Value::Bool(false),
    );
    profile_map.insert(
        Value::String("store-fake-ip".to_string()),
        Value::Bool(false),
    );
    root.insert(
        Value::String("profile".to_string()),
        Value::Mapping(profile_map),
    );

    let mut tun_map = Mapping::new();
    tun_map.insert(Value::String("enable".to_string()), Value::Bool(false));
    root.insert(Value::String("tun".to_string()), Value::Mapping(tun_map));

    let mut dns_map = Mapping::new();
    dns_map.insert(Value::String("enable".to_string()), Value::Bool(false));
    root.insert(Value::String("dns".to_string()), Value::Mapping(dns_map));

    root.insert(
        Value::String("proxies".to_string()),
        Value::Sequence(plan.relay_proxies),
    );
    root.insert(
        Value::String("proxy-groups".to_string()),
        Value::Sequence(plan.proxy_groups),
    );

    let mut rules: Vec<String> = Vec::with_capacity(plan.anti_loop_rules.len() + 12);
    let mut seen: HashSet<String> = HashSet::new();

    for rule in plan.anti_loop_rules {
        let key = rule.to_ascii_lowercase();
        if seen.insert(key) {
            rules.push(rule);
        }
    }

    const PRIVATE_DIRECT_RULES: &[&str] = &[
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
        "IP-CIDR6,::1/128,DIRECT,no-resolve",
        "IP-CIDR6,fc00::/7,DIRECT,no-resolve",
        "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
    ];
    for rule in PRIVATE_DIRECT_RULES {
        let key = rule.to_ascii_lowercase();
        if seen.insert(key) {
            rules.push((*rule).to_string());
        }
    }

    rules.push(format!("MATCH,{PREACCEL_SELECT_GROUP}"));

    root.insert(
        Value::String("rules".to_string()),
        Value::Sequence(rules.into_iter().map(Value::String).collect()),
    );

    let yaml = serde_yaml_ng::to_string(&Value::Mapping(root))?;
    Ok(yaml)
}

/// Managed lightweight Mihomo subprocess serving the standalone domestic :443 dual-active
/// SOCKS5 tunnel on `127.0.0.1:<socks_port>`.
///
/// Enforces `GOMEMLIMIT=24MiB`, `GOGC=25`, `GODEBUG=madvdontneed=1`, `CREATE_NO_WINDOW` on
/// Windows, `JobGuard` registration, and deterministic termination on `stop()` and `Drop`.
#[derive(Debug)]
pub struct StandalonePreAccelTunnel {
    child: Option<Child>,
    pid: Option<u32>,
    socks_port: u16,
    work_dir: PathBuf,
    config_path: PathBuf,
    active_relays: Vec<String>,
    job_guard: Arc<JobGuard>,
}

impl StandalonePreAccelTunnel {
    /// Compile and launch an isolated standalone :443 pre-acceleration Mihomo subprocess.
    pub async fn start(
        paths: &AppPaths,
        cfg: &AppConfig,
        relays: &[PreAccelRelay],
        job_guard: Arc<JobGuard>,
        preferred_socks_port: Option<u16>,
    ) -> CatResult<Self> {
        let bin_res = resolve_mihomo_binary(cfg, paths, &[], false)?;
        let mihomo_bin = bin_res.path.ok_or_else(|| {
            CatError::NotFound(
                "未找到 Mihomo 内核二进制文件，无法启动独立 443 预加速隧道".to_string(),
            )
        })?;

        let socks_port = allocate_loopback_tcp_port(preferred_socks_port, cfg)?;
        let yaml = compile_standalone_preaccel_yaml(cfg, relays, socks_port)?;

        let active_relays: Vec<String> = {
            let mut enabled: Vec<&PreAccelRelay> = relays.iter().filter(|r| r.enabled).collect();
            enabled.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));
            enabled
                .into_iter()
                .map(|r| {
                    if !r.name.trim().is_empty() {
                        r.name.trim().to_string()
                    } else {
                        r.id.trim().to_string()
                    }
                })
                .collect()
        };

        let work_dir = paths.runtime_dir.join("global-preaccel");
        std::fs::create_dir_all(&work_dir)?;
        let config_path = work_dir.join("standalone-preaccel.yaml");
        AppPaths::atomic_write(&config_path, yaml.as_bytes())?;

        let stderr_path = work_dir.join("standalone-preaccel-stderr.log");
        let stderr_stdio = std::fs::File::create(&stderr_path)
            .map(Stdio::from)
            .unwrap_or_else(|_| Stdio::null());

        let norm_bin = normalize_os_path(&mihomo_bin);
        let norm_work = normalize_os_path(&work_dir);
        let norm_cfg = normalize_os_path(&config_path);

        let mut cmd = Command::new(&norm_bin);
        cmd.arg("-d")
            .arg(&norm_work)
            .arg("-f")
            .arg(&norm_cfg)
            .env("GOMEMLIMIT", STANDALONE_TUNNEL_GOMEMLIMIT)
            .env("GOGC", STANDALONE_TUNNEL_GOGC)
            .env("GODEBUG", "madvdontneed=1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr_stdio)
            .kill_on_drop(true);
        JobGuard::configure_tokio_command(&mut cmd);

        let mut child = cmd.spawn().map_err(|e| {
            CatError::Process(format!(
                "启动独立 443 预加速隧道 Mihomo 进程失败 ({}): {e}",
                mihomo_bin.display()
            ))
        })?;

        if let Err(err) = job_guard.assign_tokio_child(&mut child) {
            let _ = child.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
            return Err(err);
        }

        let pid = child.id();
        let deadline = Instant::now() + STANDALONE_TUNNEL_READY_TIMEOUT;
        let target_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, socks_port);

        while Instant::now() < deadline {
            if let Ok(Some(status)) = child.try_wait() {
                if let Some(p) = pid {
                    job_guard.unregister_pid(p);
                }
                let detail = read_stderr_tail(&stderr_path, 2048);
                let msg = if detail.is_empty() {
                    format!("独立 443 预加速隧道启动失败并提前退出 ({status})")
                } else {
                    format!("独立 443 预加速隧道启动失败并提前退出 ({status}): {detail}")
                };
                return Err(CatError::Core(msg));
            }

            if tokio::time::timeout(
                Duration::from_millis(250),
                TcpStream::connect(target_addr),
            )
            .await
            .is_ok_and(|res| res.is_ok())
            {
                return Ok(Self {
                    child: Some(child),
                    pid,
                    socks_port,
                    work_dir,
                    config_path,
                    active_relays,
                    job_guard,
                });
            }

            tokio::time::sleep(STANDALONE_TUNNEL_POLL_INTERVAL).await;
        }

        let _ = child.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
        if let Some(p) = pid {
            job_guard.unregister_pid(p);
        }
        let detail = read_stderr_tail(&stderr_path, 2048);
        let msg = if detail.is_empty() {
            format!("独立 443 预加速隧道在超时前未能在 127.0.0.1:{socks_port} 就绪")
        } else {
            format!("独立 443 预加速隧道未能在 127.0.0.1:{socks_port} 就绪: {detail}")
        };
        Err(CatError::Core(msg))
    }

    pub fn pid(&self) -> Option<u32> {
        self.pid
    }

    pub fn socks_port(&self) -> u16 {
        self.socks_port
    }

    pub fn active_relays(&self) -> &[String] {
        &self.active_relays
    }

    pub fn work_dir(&self) -> &Path {
        &self.work_dir
    }

    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Gracefully terminate the standalone Mihomo subprocess and reap its handle.
    pub async fn stop(&mut self) {
        let exited_pid = self.pid.take();
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(3), child.wait()).await;
        }
        if let Some(pid) = exited_pid {
            #[cfg(unix)]
            {
                let pgid = pid as i32;
                if pgid > 1 {
                    // SAFETY: Terminating the dedicated process group created via `setpgid(0, 0)`.
                    unsafe {
                        let _ = libc::kill(-pgid, libc::SIGTERM);
                    }
                    tokio::time::sleep(Duration::from_millis(60)).await;
                    unsafe {
                        let _ = libc::kill(-pgid, libc::SIGKILL);
                    }
                }
            }
            self.job_guard.unregister_pid(pid);
        }
    }
}

impl Drop for StandalonePreAccelTunnel {
    fn drop(&mut self) {
        let exited_pid = self.pid.take();
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
        }
        if let Some(pid) = exited_pid {
            #[cfg(unix)]
            {
                let pgid = pid as i32;
                if pgid > 1 {
                    // SAFETY: Synchronous fallback kill for the child process group on Drop.
                    unsafe {
                        let _ = libc::kill(-pgid, libc::SIGKILL);
                    }
                }
            }
            self.job_guard.unregister_pid(pid);
        }
    }
}

fn allocate_loopback_tcp_port(preferred: Option<u16>, cfg: &AppConfig) -> CatResult<u16> {
    let avoid: HashSet<u16> = [
        cfg.mixed_port,
        cfg.controller_port,
        cfg.dns_listen_port,
        cfg.socks_port.unwrap_or(0),
        cfg.http_port.unwrap_or(0),
        cfg.redir_port.unwrap_or(0),
        cfg.tproxy_port.unwrap_or(0),
    ]
    .into_iter()
    .filter(|&p| p > 0)
    .collect();

    if let Some(port) = preferred.filter(|&p| p > 0 && !avoid.contains(&p)) {
        if StdTcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)).is_ok() {
            return Ok(port);
        }
    }

    for _ in 0..32 {
        let listener = StdTcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        drop(listener);
        if port > 0 && !avoid.contains(&port) {
            return Ok(port);
        }
    }

    Err(CatError::Process(
        "无法为独立 443 预加速隧道分配空闲本地回环 TCP 端口".to_string(),
    ))
}

fn read_stderr_tail(path: &Path, max_bytes: usize) -> String {
    let Ok(bytes) = std::fs::read(path) else {
        return String::new();
    };
    let slice = if bytes.len() > max_bytes {
        &bytes[bytes.len() - max_bytes..]
    } else {
        &bytes[..]
    };
    String::from_utf8_lossy(slice).trim().to_string()
}

// ============================================================================
// B. WinDivert v2.2.2 ABI, Locator, Verified Downloader, Filter & NAT Helpers
// ============================================================================

/// Exact 80-byte binary layout matching official `basil00/Divert` v2.2.2 `WINDIVERT_ADDRESS`.
///
/// Layout (little-endian Windows x64 ABI):
/// - `timestamp`: `i64` (bytes 0..8)
/// - `flags_lo`: `u32` (bytes 8..12) packing:
///   - bits `0..=7`: `Layer` (8 bits)
///   - bits `8..=15`: `Event` (8 bits)
///   - bit `16`: `Sniffed`
///   - bit `17`: `Outbound`
///   - bit `18`: `Loopback`
///   - bit `19`: `Impostor`
///   - bit `20`: `IPv6`
///   - bit `21`: `IPChecksum`
///   - bit `22`: `TCPChecksum`
///   - bit `23`: `UDPChecksum`
///   - bits `24..=31`: `Reserved1`
/// - `reserved2`: `u32` (bytes 12..16)
/// - `data`: `[u8; 64]` (bytes 16..80), union beginning with `WINDIVERT_DATA_NETWORK { IfIdx: u32, SubIfIdx: u32 }`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WinDivertAddress {
    pub timestamp: i64,
    pub flags_lo: u32,
    pub reserved2: u32,
    pub data: [u8; 64],
}

const _: () = assert!(std::mem::size_of::<WinDivertAddress>() == 80);

impl Default for WinDivertAddress {
    fn default() -> Self {
        Self {
            timestamp: 0,
            flags_lo: 0,
            reserved2: 0,
            data: [0u8; 64],
        }
    }
}

impl WinDivertAddress {
    const BIT_SNIFFED: u32 = 1 << 16;
    const BIT_OUTBOUND: u32 = 1 << 17;
    const BIT_LOOPBACK: u32 = 1 << 18;
    const BIT_IMPOSTOR: u32 = 1 << 19;
    const BIT_IPV6: u32 = 1 << 20;
    const BIT_IP_CHECKSUM: u32 = 1 << 21;
    const BIT_TCP_CHECKSUM: u32 = 1 << 22;
    const BIT_UDP_CHECKSUM: u32 = 1 << 23;

    pub fn layer(&self) -> u8 {
        (self.flags_lo & 0xFF) as u8
    }

    pub fn set_layer(&mut self, layer: u8) {
        self.flags_lo = (self.flags_lo & !0xFF) | u32::from(layer);
    }

    pub fn event(&self) -> u8 {
        ((self.flags_lo >> 8) & 0xFF) as u8
    }

    pub fn set_event(&mut self, event: u8) {
        self.flags_lo = (self.flags_lo & !(0xFF << 8)) | (u32::from(event) << 8);
    }

    pub fn sniffed(&self) -> bool {
        (self.flags_lo & Self::BIT_SNIFFED) != 0
    }

    pub fn set_sniffed(&mut self, value: bool) {
        self.set_bit(Self::BIT_SNIFFED, value);
    }

    pub fn outbound(&self) -> bool {
        (self.flags_lo & Self::BIT_OUTBOUND) != 0
    }

    pub fn set_outbound(&mut self, value: bool) {
        self.set_bit(Self::BIT_OUTBOUND, value);
    }

    pub fn loopback(&self) -> bool {
        (self.flags_lo & Self::BIT_LOOPBACK) != 0
    }

    pub fn set_loopback(&mut self, value: bool) {
        self.set_bit(Self::BIT_LOOPBACK, value);
    }

    pub fn impostor(&self) -> bool {
        (self.flags_lo & Self::BIT_IMPOSTOR) != 0
    }

    pub fn set_impostor(&mut self, value: bool) {
        self.set_bit(Self::BIT_IMPOSTOR, value);
    }

    pub fn ipv6(&self) -> bool {
        (self.flags_lo & Self::BIT_IPV6) != 0
    }

    pub fn set_ipv6(&mut self, value: bool) {
        self.set_bit(Self::BIT_IPV6, value);
    }

    pub fn ip_checksum(&self) -> bool {
        (self.flags_lo & Self::BIT_IP_CHECKSUM) != 0
    }

    pub fn set_ip_checksum(&mut self, value: bool) {
        self.set_bit(Self::BIT_IP_CHECKSUM, value);
    }

    pub fn tcp_checksum(&self) -> bool {
        (self.flags_lo & Self::BIT_TCP_CHECKSUM) != 0
    }

    pub fn set_tcp_checksum(&mut self, value: bool) {
        self.set_bit(Self::BIT_TCP_CHECKSUM, value);
    }

    pub fn udp_checksum(&self) -> bool {
        (self.flags_lo & Self::BIT_UDP_CHECKSUM) != 0
    }

    pub fn set_udp_checksum(&mut self, value: bool) {
        self.set_bit(Self::BIT_UDP_CHECKSUM, value);
    }

    pub fn network_if_idx(&self) -> u32 {
        u32::from_ne_bytes([self.data[0], self.data[1], self.data[2], self.data[3]])
    }

    pub fn set_network_if_idx(&mut self, if_idx: u32) {
        let bytes = if_idx.to_ne_bytes();
        self.data[0..4].copy_from_slice(&bytes);
    }

    pub fn network_sub_if_idx(&self) -> u32 {
        u32::from_ne_bytes([self.data[4], self.data[5], self.data[6], self.data[7]])
    }

    pub fn set_network_sub_if_idx(&mut self, sub_if_idx: u32) {
        let bytes = sub_if_idx.to_ne_bytes();
        self.data[4..8].copy_from_slice(&bytes);
    }

    fn set_bit(&mut self, mask: u32, value: bool) {
        if value {
            self.flags_lo |= mask;
        } else {
            self.flags_lo &= !mask;
        }
    }
}

/// Co-located WinDivert user-mode DLL and kernel-mode `.sys` driver paths.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WinDivertPaths {
    pub dll_path: PathBuf,
    pub sys_path: PathBuf,
}

/// Locate co-located `WinDivert64.dll` (or `WinDivert.dll`) and `WinDivert64.sys` in strict
/// priority order: `custom_dir` -> `paths.bin_dir` -> `<exe_dir>/resources/bin` -> `<exe_dir>`.
///
/// Always returns `None` on Windows ARM64 because official WinDivert v2.2.2 provides no native
/// ARM64 kernel driver.
pub fn locate_windivert_files(
    paths: &AppPaths,
    custom_dir: Option<&str>,
) -> Option<(PathBuf, PathBuf)> {
    #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
    {
        let _ = (paths, custom_dir);
        None
    }
    #[cfg(not(all(target_os = "windows", target_arch = "aarch64")))]
    {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf));
        locate_windivert_files_with_exe_dir(paths, custom_dir, exe_dir.as_deref())
    }
}

/// Convenience wrapper returning a structured `WinDivertPaths` from `locate_windivert_files`.
pub fn locate_windivert_paths(
    paths: &AppPaths,
    custom_dir: Option<&str>,
) -> Option<WinDivertPaths> {
    locate_windivert_files(paths, custom_dir).map(|(dll_path, sys_path)| WinDivertPaths {
        dll_path,
        sys_path,
    })
}

/// Deterministic variant of `locate_windivert_files` accepting an explicit `exe_dir`.
pub fn locate_windivert_files_with_exe_dir(
    paths: &AppPaths,
    custom_dir: Option<&str>,
    exe_dir: Option<&Path>,
) -> Option<(PathBuf, PathBuf)> {
    #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
    {
        let _ = (paths, custom_dir, exe_dir);
        None
    }
    #[cfg(not(all(target_os = "windows", target_arch = "aarch64")))]
    {
        let mut candidate_dirs: Vec<PathBuf> = Vec::with_capacity(4);

        if let Some(raw_custom) = custom_dir.map(str::trim).filter(|s| !s.is_empty()) {
            let custom_path = PathBuf::from(raw_custom);
            if custom_path.is_file() {
                if let Some(parent) = custom_path.parent() {
                    candidate_dirs.push(parent.to_path_buf());
                }
            } else {
                candidate_dirs.push(custom_path);
            }
        }

        candidate_dirs.push(paths.bin_dir.clone());

        if let Some(dir) = exe_dir {
            candidate_dirs.push(dir.join("resources").join("bin"));
            candidate_dirs.push(dir.to_path_buf());
        }

        for dir in candidate_dirs {
            let sys_path = dir.join("WinDivert64.sys");
            if !sys_path.is_file() {
                continue;
            }
            for dll_name in ["WinDivert64.dll", "WinDivert.dll"] {
                let dll_path = dir.join(dll_name);
                if dll_path.is_file() {
                    return Some((normalize_os_path(&dll_path), normalize_os_path(&sys_path)));
                }
            }
        }

        None
    }
}

/// Normalize and deduplicate ordered proxy candidates (`Some("http://...")` / `None` direct),
/// preserving first-seen priority. Empty input defaults to `[None]` (direct connection).
pub fn normalize_windivert_proxy_candidates(
    raw_candidates: &[Option<String>],
) -> Vec<Option<String>> {
    if raw_candidates.is_empty() {
        return vec![None];
    }

    let mut out: Vec<Option<String>> = Vec::with_capacity(raw_candidates.len());
    let mut seen_direct = false;
    let mut seen_proxies: HashSet<String> = HashSet::new();

    for candidate in raw_candidates {
        match candidate
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(proxy) => {
                let key = proxy.trim_end_matches('/').to_ascii_lowercase();
                if seen_proxies.insert(key) {
                    out.push(Some(proxy.to_string()));
                }
            }
            None => {
                if !seen_direct {
                    seen_direct = true;
                    out.push(None);
                }
            }
        }
    }

    if out.is_empty() {
        out.push(None);
    }
    out
}

/// Convert an active, non-PAC `SystemProxySpec` into an HTTP proxy URL suitable for `reqwest::Proxy`.
pub fn format_system_proxy_url(spec: &crate::platform::SystemProxySpec) -> Option<String> {
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
    let host = spec.host.trim();
    if host.is_empty() {
        return None;
    }
    if host.contains("://") {
        return Some(host.to_string());
    }
    if host.contains(':') && !host.starts_with('[') {
        Some(format!("http://[{host}]:{}", spec.port))
    } else {
        Some(format!("http://{host}:{}", spec.port))
    }
}

/// Build the standard 3-tier WinDivert download proxy fallback chain:
/// 1. CatCloud main core local mixed port (when running)
/// 2. Current OS active system proxy (e.g. an active third-party proxy on Windows)
/// 3. Direct connection (`None`)
pub fn build_default_windivert_proxy_candidates(
    catcloud_mixed_port: Option<u16>,
) -> Vec<Option<String>> {
    let mut raw: Vec<Option<String>> = Vec::with_capacity(3);
    if let Some(port) = catcloud_mixed_port.filter(|&p| p > 0) {
        raw.push(Some(format!("http://127.0.0.1:{port}")));
    }
    if let Ok(spec) = default_platform().read_system_proxy() {
        if let Some(url) = format_system_proxy_url(&spec) {
            raw.push(Some(url));
        }
    }
    raw.push(None);
    normalize_windivert_proxy_candidates(&raw)
}

/// Download official WinDivert v2.2.2 (`WinDivert-2.2.2-A.zip`) trying each proxy candidate in
/// deduplicated priority order (for example: CatCloud core -> active Windows system proxy ->
/// direct), strictly enforcing `ALLOWED_WINDIVERT_HOSTS` and `WINDIVERT_ZIP_SHA256` on every
/// attempt before extracting into `paths.bin_dir`.
///
/// Never writes to Windows system directories. Returns actionable Chinese guidance if an
/// antivirus or Windows Defender quarantines the driver binary, or if running on Windows ARM64.
pub async fn download_and_install_windivert_with_fallbacks(
    paths: &AppPaths,
    proxy_candidates: &[Option<String>],
) -> CatResult<PathBuf> {
    #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
    {
        let _ = (paths, proxy_candidates);
        Err(CatError::Validation(
            WINDIVERT_ARM64_UNSUPPORTED_MSG.to_string(),
        ))
    }

    #[cfg(not(all(target_os = "windows", target_arch = "aarch64")))]
    {
        crate::init_crypto_provider();

        let candidates = normalize_windivert_proxy_candidates(proxy_candidates);
        let total_attempts = candidates.len();
        let mut attempt_errors: Vec<String> = Vec::with_capacity(total_attempts);
        let mut last_err: Option<CatError> = None;

        for (idx, candidate) in candidates.iter().enumerate() {
            let has_more = idx + 1 < total_attempts;
            let connect_timeout = if has_more && candidate.is_some() {
                Duration::from_secs(8)
            } else {
                Duration::from_secs(15)
            };
            let total_timeout = if has_more && candidate.is_some() {
                Duration::from_secs(45)
            } else {
                Duration::from_secs(90)
            };

            let route_label = candidate.as_deref().unwrap_or("direct");
            match download_windivert_archive_once(
                candidate.as_deref(),
                connect_timeout,
                total_timeout,
            )
            .await
            {
                Ok(archive_bytes) => {
                    match verify_and_extract_windivert_zip(
                        &archive_bytes,
                        WINDIVERT_ZIP_SHA256,
                        &paths.bin_dir,
                    ) {
                        Ok(_) => return Ok(paths.bin_dir.clone()),
                        Err(err) => {
                            // Local disk / AV write interception cannot be solved by switching proxies.
                            let is_local_write_block = matches!(&err, CatError::Io(_))
                                || matches!(
                                    &err,
                                    CatError::Security(msg)
                                        if msg.contains("杀毒软件") || msg.contains("安全软件")
                                );
                            if is_local_write_block {
                                return Err(err);
                            }
                            attempt_errors.push(format!("[{route_label}] {err}"));
                            last_err = Some(err);
                        }
                    }
                }
                Err(err) => {
                    attempt_errors.push(format!("[{route_label}] {err}"));
                    last_err = Some(err);
                }
            }
        }

        if total_attempts == 1 {
            if let Some(err) = last_err {
                return Err(err);
            }
        }

        Err(CatError::Core(format!(
            "尝试 {total_attempts} 条下载通道后仍未能安装官方 WinDivert v2.2.2：{}",
            attempt_errors.join("；")
        )))
    }
}

/// Download official WinDivert v2.2.2 (`WinDivert-2.2.2-A.zip`), strictly verify its SHA-256
/// against `WINDIVERT_ZIP_SHA256`, and extract only `x64/WinDivert.dll` (installed as both
/// `WinDivert.dll` and `WinDivert64.dll`) and `x64/WinDivert64.sys` into `paths.bin_dir`.
///
/// Backward-compatible single-route wrapper delegating to
/// [`download_and_install_windivert_with_fallbacks`].
pub async fn download_and_install_windivert(
    paths: &AppPaths,
    proxy_url: Option<&str>,
) -> CatResult<PathBuf> {
    let candidate = proxy_url
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);
    download_and_install_windivert_with_fallbacks(paths, &[candidate]).await
}

#[cfg(not(all(target_os = "windows", target_arch = "aarch64")))]
async fn download_windivert_archive_once(
    proxy_url: Option<&str>,
    connect_timeout: Duration,
    total_timeout: Duration,
) -> CatResult<Vec<u8>> {
    let redirect_policy = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() > 5 {
            return attempt.error(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "WinDivert 下载重定向次数超限",
            ));
        }
        match validate_windivert_https_url(attempt.url().as_str()) {
            Ok(()) => attempt.follow(),
            Err(err) => attempt.error(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                err.to_string(),
            )),
        }
    });

    let mut builder = reqwest::Client::builder()
        .redirect(redirect_policy)
        .connect_timeout(connect_timeout)
        .timeout(total_timeout)
        .user_agent(format!("CatCloud/{}", env!("CARGO_PKG_VERSION")));

    if let Some(proxy) = proxy_url.map(str::trim).filter(|s| !s.is_empty()) {
        let parsed = reqwest::Proxy::all(proxy).map_err(|e| {
            CatError::Validation(format!("无效的 WinDivert 下载代理地址 `{proxy}`: {e}"))
        })?;
        builder = builder.proxy(parsed);
    } else {
        builder = builder.no_proxy();
    }

    let client = builder.build()?;
    let mut resp = client
        .get(WINDIVERT_DOWNLOAD_URL)
        .send()
        .await
        .map_err(|e| CatError::Core(format!("下载官方 WinDivert v2.2.2 失败: {e}")))?;

    if !resp.status().is_success() {
        return Err(CatError::Core(format!(
            "下载官方 WinDivert v2.2.2 失败，HTTP 状态码: {}",
            resp.status()
        )));
    }

    let mut archive_bytes: Vec<u8> = Vec::with_capacity(512 * 1024);
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| CatError::Core(format!("读取 WinDivert 下载流失败: {e}")))?
    {
        if archive_bytes.len().saturating_add(chunk.len()) > MAX_WINDIVERT_ZIP_BYTES {
            return Err(CatError::Security(format!(
                "WinDivert 压缩包超出安全体积上限 ({MAX_WINDIVERT_ZIP_BYTES} bytes)"
            )));
        }
        archive_bytes.extend_from_slice(&chunk);
    }

    Ok(archive_bytes)
}

#[cfg_attr(
    all(target_os = "windows", target_arch = "aarch64"),
    allow(dead_code)
)]
fn validate_windivert_https_url(raw: &str) -> CatResult<()> {
    let parsed = Url::parse(raw.trim())
        .map_err(|e| CatError::Security(format!("非法 WinDivert 下载地址: {e}")))?;
    if !parsed.scheme().eq_ignore_ascii_case("https") {
        return Err(CatError::Security(
            "WinDivert 下载仅允许 HTTPS 协议".to_string(),
        ));
    }
    let host = parsed
        .host_str()
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if !ALLOWED_WINDIVERT_HOSTS.iter().any(|h| *h == host) {
        return Err(CatError::Security(format!(
            "拦截了未授权的 WinDivert 下载域名: {host}"
        )));
    }
    Ok(())
}

/// Verify SHA-256 of a WinDivert ZIP archive and safely extract `x64/WinDivert.dll` (saved as
/// both `WinDivert.dll` and `WinDivert64.dll`) and `x64/WinDivert64.sys` into `dest_dir`.
pub fn verify_and_extract_windivert_zip(
    zip_bytes: &[u8],
    expected_sha256: &str,
    dest_dir: &Path,
) -> CatResult<WinDivertPaths> {
    let mut hasher = Sha256::new();
    hasher.update(zip_bytes);
    let actual_sha256 = hex::encode(hasher.finalize());
    if !actual_sha256.eq_ignore_ascii_case(expected_sha256.trim()) {
        return Err(CatError::Security(format!(
            "WinDivert 安装包 SHA-256 校验失败（期望 {}，实际 {}），已拒绝安装",
            expected_sha256.trim(),
            actual_sha256
        )));
    }

    let mut archive = ZipArchive::new(Cursor::new(zip_bytes))
        .map_err(|e| CatError::Validation(format!("WinDivert ZIP 压缩包损坏: {e}")))?;

    let mut dll_bytes: Option<Vec<u8>> = None;
    let mut sys_bytes: Option<Vec<u8>> = None;

    for idx in 0..archive.len() {
        let entry = archive
            .by_index(idx)
            .map_err(|e| CatError::Validation(format!("读取 WinDivert ZIP 条目失败: {e}")))?;
        if entry.is_dir() {
            continue;
        }
        let normalized = entry.name().replace('\\', "/");
        if normalized.starts_with('/')
            || normalized.contains("..")
            || normalized.contains(':')
        {
            return Err(CatError::Security(format!(
                "WinDivert ZIP 包含非法路径穿越条目: `{normalized}`"
            )));
        }

        let lower = normalized.to_ascii_lowercase();
        let is_target_dll = lower == "x64/windivert.dll" || lower.ends_with("/x64/windivert.dll");
        let is_target_sys =
            lower == "x64/windivert64.sys" || lower.ends_with("/x64/windivert64.sys");
        if !is_target_dll && !is_target_sys {
            continue;
        }

        if entry.size() > MAX_WINDIVERT_FILE_BYTES {
            return Err(CatError::Security(format!(
                "WinDivert 解压条目 `{normalized}` 超出大小限制"
            )));
        }

        let mut buf = Vec::with_capacity((entry.size() as usize).min(2 * 1024 * 1024));
        let mut limited = entry.take(MAX_WINDIVERT_FILE_BYTES + 1);
        limited.read_to_end(&mut buf)?;
        if (buf.len() as u64) > MAX_WINDIVERT_FILE_BYTES {
            return Err(CatError::Security(format!(
                "WinDivert 解压条目 `{normalized}` 实际大小超出限制"
            )));
        }

        if is_target_dll {
            dll_bytes = Some(buf);
        } else if is_target_sys {
            sys_bytes = Some(buf);
        }
    }

    let dll_data = dll_bytes.ok_or_else(|| {
        CatError::Validation("WinDivert ZIP 中缺少 `x64/WinDivert.dll`".to_string())
    })?;
    let sys_data = sys_bytes.ok_or_else(|| {
        CatError::Validation("WinDivert ZIP 中缺少 `x64/WinDivert64.sys`".to_string())
    })?;

    std::fs::create_dir_all(dest_dir)?;
    let dll_plain = dest_dir.join("WinDivert.dll");
    let dll_64 = dest_dir.join("WinDivert64.dll");
    let sys_64 = dest_dir.join("WinDivert64.sys");

    write_windivert_binary_with_av_hint(&dll_plain, &dll_data, dest_dir)?;
    write_windivert_binary_with_av_hint(&dll_64, &dll_data, dest_dir)?;
    write_windivert_binary_with_av_hint(&sys_64, &sys_data, dest_dir)?;

    if !dll_64.is_file() || !sys_64.is_file() {
        return Err(CatError::Security(format!(
            "WinDivert 驱动文件写入后被安全软件移除或隔离。该文件为官方签名开源驱动 WinDivert v2.2.2（已通过 SHA-256 校验），请将目录 `{}` 加入 Windows 安全中心/杀毒软件排除项后重试。",
            dest_dir.display()
        )));
    }

    Ok(WinDivertPaths {
        dll_path: normalize_os_path(&dll_64),
        sys_path: normalize_os_path(&sys_64),
    })
}

fn write_windivert_binary_with_av_hint(
    target: &Path,
    bytes: &[u8],
    bin_dir: &Path,
) -> CatResult<()> {
    match AppPaths::atomic_write(target, bytes) {
        Ok(()) => Ok(()),
        Err(CatError::Io(io_err)) => {
            let av_blocked = io_err.kind() == std::io::ErrorKind::PermissionDenied
                || matches!(io_err.raw_os_error(), Some(5 | 225 | 226));
            if av_blocked {
                Err(CatError::Security(format!(
                    "写入 `{}` 时被杀毒软件或 Windows Defender 拦截（{}）。WinDivert v2.2.2 为官方开源网络过滤驱动（已通过 SHA-256 校验），请将目录 `{}` 添加到安全软件白名单后重试。",
                    target.display(),
                    io_err,
                    bin_dir.display()
                )))
            } else {
                Err(CatError::Io(io_err))
            }
        }
        Err(other) => Err(other),
    }
}

/// Build the high-precision WinDivert v2.2.2 kernel-mode packet filter string.
///
/// Design invariants:
/// - Matches only IPv4 TCP traffic (`ip and tcp`).
/// - Outbound public interception excludes loopback (`!loopback`), ports `443` & `53`, all
///   private/loopback/CGNAT/link-local/Fake-IP/multicast ranges, and every domestic :443
///   relay public IPv4 address (to guarantee zero loops).
/// - Also captures return packets from the local self-loop redirector (`outbound and
///   tcp.SrcPort == <local_redirect_port>`) without excluding loopback on the return branch,
///   because same-NIC self-loop replies traverse Windows loopback on outbound.
/// - NEVER bypasses GeoIP CN so domestic-transit airport entry IPs are 100% accelerated!
pub fn build_windivert_filter(relay_ipv4s: &[Ipv4Addr], local_redirect_port: u16) -> String {
    let mut outbound_terms: Vec<String> = vec![
        "!loopback".to_string(),
        "outbound".to_string(),
        "tcp.DstPort != 443".to_string(),
        "tcp.DstPort != 53".to_string(),
        // Exclude 0.0.0.0/8 (this network) and 224.0.0.0/3 (multicast/reserved/broadcast)
        "ip.DstAddr > 0.255.255.255".to_string(),
        "ip.DstAddr < 224.0.0.0".to_string(),
        // Exclude 10.0.0.0/8 (RFC 1918)
        "(ip.DstAddr < 10.0.0.0 or ip.DstAddr > 10.255.255.255)".to_string(),
        // Exclude 100.64.0.0/10 (RFC 6598 CGNAT)
        "(ip.DstAddr < 100.64.0.0 or ip.DstAddr > 100.127.255.255)".to_string(),
        // Exclude 127.0.0.0/8 (loopback)
        "(ip.DstAddr < 127.0.0.0 or ip.DstAddr > 127.255.255.255)".to_string(),
        // Exclude 169.254.0.0/16 (link-local APIPA)
        "(ip.DstAddr < 169.254.0.0 or ip.DstAddr > 169.254.255.255)".to_string(),
        // Exclude 172.16.0.0/12 (RFC 1918)
        "(ip.DstAddr < 172.16.0.0 or ip.DstAddr > 172.31.255.255)".to_string(),
        // Exclude 192.168.0.0/16 (RFC 1918)
        "(ip.DstAddr < 192.168.0.0 or ip.DstAddr > 192.168.255.255)".to_string(),
        // Exclude 198.18.0.0/15 (Fake-IP / RFC 2544 benchmark range)
        "(ip.DstAddr < 198.18.0.0 or ip.DstAddr > 198.19.255.255)".to_string(),
    ];

    let unique_relays: BTreeSet<Ipv4Addr> = relay_ipv4s
        .iter()
        .copied()
        .filter(|ip| !ip.is_unspecified() && !ip.is_loopback())
        .collect();

    for ip in unique_relays {
        outbound_terms.push(format!("ip.DstAddr != {ip}"));
    }

    format!(
        "ip and tcp and (({}) or (outbound and tcp.SrcPort == {}))",
        outbound_terms.join(" and "),
        local_redirect_port
    )
}

/// Extract distinct IPv4 addresses of enabled domestic relays (resolving domain relays on a
/// best-effort basis so kernel-level anti-loop exclusions stay complete).
pub fn collect_enabled_relay_ipv4s(relays: &[PreAccelRelay]) -> Vec<Ipv4Addr> {
    let mut set = BTreeSet::new();
    for relay in relays.iter().filter(|r| r.enabled) {
        let server = relay.server.trim();
        if server.is_empty() {
            continue;
        }
        if let Some(ip) = parse_server_ip(server) {
            if let IpAddr::V4(v4) = ip {
                set.insert(v4);
            }
            continue;
        }
        use std::net::ToSocketAddrs as _;
        if let Ok(addrs) = (server, relay.port).to_socket_addrs() {
            for addr in addrs {
                if let SocketAddr::V4(v4) = addr {
                    set.insert(*v4.ip());
                }
            }
        }
    }
    set.into_iter().collect()
}

/// Decide whether a Windows network interface row describes a real physical Ethernet/Wi-Fi NIC
/// (excluding TUN/TAP, Hyper-V, VMware, VirtualBox, Loopback, VPN, and virtual adapters).
pub fn is_physical_nic_descriptor(if_type: u32, oper_status: i32, descr: &str) -> bool {
    const IF_TYPE_ETHERNET: u32 = 6;
    const IF_TYPE_WIFI: u32 = 71;
    const OPER_CONNECTED: i32 = 4;
    const OPER_OPERATIONAL: i32 = 5;

    if if_type != IF_TYPE_ETHERNET && if_type != IF_TYPE_WIFI {
        return false;
    }
    if oper_status != OPER_OPERATIONAL && oper_status != OPER_CONNECTED {
        return false;
    }

    let lower = descr.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return true;
    }

    const VIRTUAL_NIC_KEYWORDS: &[&str] = &[
        "wintun",
        "wireguard",
        "tap-windows",
        "tap-",
        "sing-tun",
        "mihomo",
        "clash",
        "hyper-v",
        "vethernet",
        "vmware",
        "virtualbox",
        "vbox",
        "zerotier",
        "tailscale",
        "radmin",
        "loopback",
        "teredo",
        "isatap",
        "pseudo",
        "wan miniport",
        "bluetooth",
        "km-test",
        "virtual",
        "tunnel",
        "vpn",
        "npcap",
        "wsl",
        "docker",
    ];
    !VIRTUAL_NIC_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

/// Normalize a process path or executable name down to lowercase basename (e.g. `"mihomo.exe"`).
pub fn normalize_process_basename(raw: &str) -> String {
    let trimmed = raw.trim();
    let base = trimmed
        .rsplit(|c| c == '\\' || c == '/')
        .next()
        .unwrap_or(trimmed);
    base.to_ascii_lowercase()
}

/// Return `true` when `raw` resolves to an empty name, a core Windows OS process, or any
/// CatCloud self executable that must never be transparently intercepted.
pub fn is_system_or_self_excluded_process(raw: &str) -> bool {
    let lower = normalize_process_basename(raw);
    lower.is_empty()
        || lower.starts_with("catcloud")
        || SYSTEM_AND_SELF_EXCLUDED_PROCESSES
            .iter()
            .any(|sys| *sys == lower)
}

/// Return `true` when an executable path or basename matches a generic open-source
/// proxy core stem (case-insensitive, never matching core OS processes or CatCloud self binaries).
pub fn is_open_source_proxy_core_name(raw: &str) -> bool {
    let lower = normalize_process_basename(raw);
    if is_system_or_self_excluded_process(&lower) {
        return false;
    }
    OPEN_SOURCE_PROXY_CORE_STEMS
        .iter()
        .any(|stem| lower.contains(stem))
}

/// Classify whether an outbound TCP flow from `(pid, process_name)` should be transparently
/// redirected into the standalone `:443` pre-acceleration tunnel, returning the detection label
/// when approved (`"system_proxy_host"`, `"local_proxy_listener"`, `"open_core_name"`, `"manual"`,
/// or `"scope_all"`), or `None` when bypassed.
///
/// Safety precedence:
/// 1. Unconditionally exclude `pid == 0`, `pid == 4`, every PID in `excluded_pids` (CatCloud full
///    descendant tree, standalone tunnel, main core), unresolvable/empty process names, and
///    `SYSTEM_AND_SELF_EXCLUDED_PROCESSES` / `catcloud*`.
/// 2. Accept dynamic runtime proxy hosts (`detected_proxy_pids`).
/// 3. Accept generic open-source proxy core stems (`OPEN_SOURCE_PROXY_CORE_STEMS`).
/// 4. Accept explicitly configured user target executables (`target_processes_lower`).
/// 5. In `AllNon443Tcp` scope, accept remaining public non-443 TCP flows as `"scope_all"`.
pub fn classify_intercept_process(
    pid: u32,
    process_name: Option<&str>,
    scope: GlobalPreAccelScope,
    target_processes_lower: &HashSet<String>,
    excluded_pids: &HashSet<u32>,
    detected_proxy_pids: &HashMap<u32, &'static str>,
) -> Option<&'static str> {
    if pid == 0 || pid == 4 || excluded_pids.contains(&pid) {
        return None;
    }
    let name = process_name?;
    // Conservatively bypass processes whose executable name cannot be resolved (such as
    // Windows PPL protected system processes) so they never bypass system exclusions.
    let lower = normalize_process_basename(name);
    if is_system_or_self_excluded_process(&lower) {
        return None;
    }
    if let Some(&detected_reason) = detected_proxy_pids.get(&pid) {
        return Some(detected_reason);
    }
    if is_open_source_proxy_core_name(&lower) {
        return Some("open_core_name");
    }
    if target_processes_lower.contains(&lower) {
        return Some("manual");
    }
    match scope {
        GlobalPreAccelScope::ProxyAppsOnly => None,
        GlobalPreAccelScope::AllNon443Tcp => Some("scope_all"),
    }
}

/// Pure policy check deciding whether an outbound TCP flow from `(pid, process_name)` should
/// be transparently redirected into the standalone :443 pre-acceleration tunnel.
///
/// Backward-compatible wrapper delegating to [`classify_intercept_process`] with an empty
/// dynamic runtime detection map.
pub fn should_intercept_process(
    pid: u32,
    process_name: Option<&str>,
    scope: GlobalPreAccelScope,
    target_processes_lower: &HashSet<String>,
    excluded_pids: &HashSet<u32>,
) -> bool {
    let empty_detected: HashMap<u32, &'static str> = HashMap::new();
    classify_intercept_process(
        pid,
        process_name,
        scope,
        target_processes_lower,
        excluded_pids,
        &empty_detected,
    )
    .is_some()
}

/// Thread-safe excluded-PID tracker shared between the control plane (`GlobalPreAccelManager` /
/// `WinDivertEngine`) and the packet worker thread (`Arc<std::sync::RwLock<HashSet<u32>>>`).
///
/// Always retains CatCloud's own PID, the standalone :443 tunnel subprocess PID, any static
/// startup exclusions, the dynamic full CatCloud descendant PID tree, and the external main core
/// PID slot using a strict lock order (`main_core_pid -> descendant_pids -> active`).
#[cfg_attr(
    any(not(target_os = "windows"), target_arch = "aarch64"),
    allow(dead_code)
)]
#[derive(Debug)]
pub(super) struct ExcludedPidTracker {
    pinned: HashSet<u32>,
    main_core_pid: Mutex<Option<u32>>,
    descendant_pids: Mutex<HashSet<u32>>,
    active: Arc<std::sync::RwLock<HashSet<u32>>>,
}

#[cfg_attr(
    any(not(target_os = "windows"), target_arch = "aarch64"),
    allow(dead_code)
)]
impl ExcludedPidTracker {
    pub(super) fn new(
        self_pid: u32,
        tunnel_pid: Option<u32>,
        static_extra_pids: impl IntoIterator<Item = u32>,
        initial_main_core_pid: Option<u32>,
    ) -> Self {
        let mut pinned = HashSet::new();
        if self_pid > 0 {
            pinned.insert(self_pid);
        }
        if let Some(pid) = tunnel_pid.filter(|&p| p > 0) {
            pinned.insert(pid);
        }
        for pid in static_extra_pids {
            if pid > 0 {
                pinned.insert(pid);
            }
        }
        let initial_main = initial_main_core_pid.filter(|&p| p > 0);
        let mut initial_set = pinned.clone();
        if let Some(pid) = initial_main {
            initial_set.insert(pid);
        }
        Self {
            pinned,
            main_core_pid: Mutex::new(initial_main),
            descendant_pids: Mutex::new(HashSet::new()),
            active: Arc::new(std::sync::RwLock::new(initial_set)),
        }
    }

    pub(super) fn shared_set(&self) -> Arc<std::sync::RwLock<HashSet<u32>>> {
        Arc::clone(&self.active)
    }

    pub(super) fn snapshot_active(&self) -> HashSet<u32> {
        self.active
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Return the current deduplicated root PIDs whose full Windows descendant subtrees
    /// must be excluded (always includes `std::process::id()`, pinned PIDs, and `main_core_pid`).
    pub(super) fn current_root_pids(&self) -> Vec<u32> {
        let main_pid = *self.main_core_pid.lock().unwrap_or_else(|e| e.into_inner());
        let mut roots: HashSet<u32> = self.pinned.clone();
        let current_self_pid = std::process::id();
        if current_self_pid > 0 {
            roots.insert(current_self_pid);
        }
        if let Some(pid) = main_pid {
            roots.insert(pid);
        }
        roots.into_iter().collect()
    }

    /// Replace or clear only the external main core PID slot while unconditionally preserving
    /// `std::process::id()`, the standalone tunnel PID, all pinned exclusions, and the dynamic
    /// descendant PID tree.
    pub(super) fn sync_main_core_pid(&self, main_core_pid: Option<u32>) {
        let next_pid = main_core_pid.filter(|&p| p > 0);
        let mut main_slot = self.main_core_pid.lock().unwrap_or_else(|e| e.into_inner());
        *main_slot = next_pid;
        let descendants = self
            .descendant_pids
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        self.rebuild_active_locked(*main_slot, &descendants);
    }

    /// Replace the dynamically scanned CatCloud descendant PID tree while unconditionally
    /// preserving pinned exclusions and the external main core PID slot.
    pub(super) fn sync_descendant_pids(&self, descendants: HashSet<u32>) {
        let cleaned: HashSet<u32> = descendants.into_iter().filter(|&p| p > 0).collect();
        let main_slot = self.main_core_pid.lock().unwrap_or_else(|e| e.into_inner());
        let mut desc_slot = self
            .descendant_pids
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *desc_slot = cleaned;
        self.rebuild_active_locked(*main_slot, &desc_slot);
    }

    fn rebuild_active_locked(&self, main_core_pid: Option<u32>, descendants: &HashSet<u32>) {
        let mut set = self.active.write().unwrap_or_else(|e| e.into_inner());
        set.clear();
        for &pid in &self.pinned {
            set.insert(pid);
        }
        let current_self_pid = std::process::id();
        if current_self_pid > 0 {
            set.insert(current_self_pid);
        }
        if let Some(pid) = main_core_pid {
            set.insert(pid);
        }
        for &pid in descendants {
            set.insert(pid);
        }
    }
}

/// Key identifying a local client TCP endpoint in the self-loop NAT table.
pub type NatKey = (Ipv4Addr, u16);

/// Recorded original remote endpoint, process identity, & interface metadata for one transparently
/// redirected flow.
#[derive(Debug, Clone)]
pub struct NatEntry {
    pub orig_dst_ip: Ipv4Addr,
    pub orig_dst_port: u16,
    pub if_idx: u32,
    pub sub_if_idx: u32,
    pub owner_pid: u32,
    pub process_name: String,
    pub detected_by: String,
    pub last_seen: Instant,
}

/// Bounded-capacity transparent TCP NAT table with idle timeout and oldest-access LRU eviction.
#[derive(Debug)]
pub struct NatTable {
    max_entries: usize,
    idle_timeout: Duration,
    entries: Mutex<HashMap<NatKey, NatEntry>>,
}

impl NatTable {
    pub fn new(max_entries: usize, idle_timeout: Duration) -> Self {
        Self {
            max_entries: max_entries.max(1),
            idle_timeout,
            entries: Mutex::new(HashMap::with_capacity(max_entries.min(512))),
        }
    }

    /// Insert or update a NAT mapping, evicting expired or least-recently-used entries if full.
    pub fn insert(&self, key: NatKey, entry: NatEntry) {
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let now = entry.last_seen;
        if !guard.contains_key(&key) && guard.len() >= self.max_entries {
            let timeout = self.idle_timeout;
            guard.retain(|_, v| now.saturating_duration_since(v.last_seen) < timeout);
            while guard.len() >= self.max_entries {
                if let Some(oldest_key) = guard
                    .iter()
                    .min_by_key(|(_, v)| v.last_seen)
                    .map(|(k, _)| *k)
                {
                    guard.remove(&oldest_key);
                } else {
                    break;
                }
            }
        }
        guard.insert(key, entry);
    }

    /// Look up a NAT mapping and refresh its `last_seen` timestamp.
    pub fn get_and_touch(&self, key: &NatKey) -> Option<NatEntry> {
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let entry = guard.get_mut(key)?;
        let now = Instant::now();
        if now.saturating_duration_since(entry.last_seen) >= self.idle_timeout {
            guard.remove(key);
            return None;
        }
        entry.last_seen = now;
        Some(entry.clone())
    }

    /// Remove and return the NAT entry for `key`, if present.
    pub fn remove(&self, key: &NatKey) -> Option<NatEntry> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key)
    }

    /// Remove the NAT entry for `key` only when its recorded original destination matches
    /// `(orig_dst_ip, orig_dst_port)`, preventing a closing older connection from evicting
    /// a newer mapping created after local ephemeral port reuse.
    pub fn remove_if_matching(
        &self,
        key: &NatKey,
        orig_dst_ip: Ipv4Addr,
        orig_dst_port: u16,
    ) -> bool {
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let matches = guard.get(key).is_some_and(|entry| {
            entry.orig_dst_ip == orig_dst_ip && entry.orig_dst_port == orig_dst_port
        });
        if matches {
            guard.remove(key);
            true
        } else {
            false
        }
    }

    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Parsed IPv4 + TCP header metadata extracted from a raw L3 packet buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4TcpMeta {
    pub ihl_bytes: usize,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: u8,
}

impl Ipv4TcpMeta {
    pub const FLAG_FIN: u8 = 0x01;
    pub const FLAG_SYN: u8 = 0x02;
    pub const FLAG_RST: u8 = 0x04;
    pub const FLAG_ACK: u8 = 0x10;

    pub fn is_syn_only(self) -> bool {
        (self.tcp_flags & Self::FLAG_SYN) != 0 && (self.tcp_flags & Self::FLAG_ACK) == 0
    }
}

/// Parse minimal IPv4 + TCP header metadata from raw packet bytes.
pub fn parse_ipv4_tcp_packet(buf: &[u8]) -> Option<Ipv4TcpMeta> {
    if buf.len() < 20 {
        return None;
    }
    let version = buf[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl = (buf[0] & 0x0F) as usize;
    if ihl < 5 {
        return None;
    }
    let ihl_bytes = ihl * 4;
    if buf[9] != 6 || buf.len() < ihl_bytes + 20 {
        return None;
    }

    let src_ip = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let dst_ip = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    let src_port = u16::from_be_bytes([buf[ihl_bytes], buf[ihl_bytes + 1]]);
    let dst_port = u16::from_be_bytes([buf[ihl_bytes + 2], buf[ihl_bytes + 3]]);
    let tcp_flags = buf[ihl_bytes + 13];

    Some(Ipv4TcpMeta {
        ihl_bytes,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        tcp_flags,
    })
}

/// Rewrite the IPv4 destination IP and TCP destination port in-place.
pub fn rewrite_ipv4_tcp_dst(
    buf: &mut [u8],
    ihl_bytes: usize,
    new_dst_ip: Ipv4Addr,
    new_dst_port: u16,
) -> bool {
    if ihl_bytes < 20 || buf.len() < ihl_bytes + 20 {
        return false;
    }
    buf[16..20].copy_from_slice(&new_dst_ip.octets());
    buf[ihl_bytes + 2..ihl_bytes + 4].copy_from_slice(&new_dst_port.to_be_bytes());
    true
}

/// Rewrite the IPv4 source IP and TCP source port in-place.
pub fn rewrite_ipv4_tcp_src(
    buf: &mut [u8],
    ihl_bytes: usize,
    new_src_ip: Ipv4Addr,
    new_src_port: u16,
) -> bool {
    if ihl_bytes < 20 || buf.len() < ihl_bytes + 20 {
        return false;
    }
    buf[12..16].copy_from_slice(&new_src_ip.octets());
    buf[ihl_bytes..ihl_bytes + 2].copy_from_slice(&new_src_port.to_be_bytes());
    true
}

/// Structured per-process live acceleration telemetry entry reported in `GlobalPreAccelStatus`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcceleratedProcessStat {
    pub process_name: String,
    pub pid: u32,
    pub detected_by: String,
    pub active_connections: usize,
    pub total_connections: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub last_seen_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ProcessStatKey {
    process_name_lower: String,
    pid: u32,
    detected_by: String,
}

#[derive(Debug)]
struct ProcessCounters {
    process_name: String,
    pid: u32,
    detected_by: String,
    active_connections: AtomicUsize,
    total_connections: AtomicU64,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    last_seen_ms: AtomicU64,
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn decrement_atomic_usize_saturating(counter: &AtomicUsize) {
    let mut cur = counter.load(Ordering::Relaxed);
    while let Err(actual) = counter.compare_exchange_weak(
        cur,
        cur.saturating_sub(1),
        Ordering::Relaxed,
        Ordering::Relaxed,
    ) {
        cur = actual;
    }
}

#[cfg_attr(
    any(not(target_os = "windows"), target_arch = "aarch64"),
    allow(dead_code)
)]
fn decrement_atomic_u64_saturating(counter: &AtomicU64) {
    let mut cur = counter.load(Ordering::Relaxed);
    while let Err(actual) = counter.compare_exchange_weak(
        cur,
        cur.saturating_sub(1),
        Ordering::Relaxed,
        Ordering::Relaxed,
    ) {
        cur = actual;
    }
}

/// Shared lock-free telemetry counters for the standalone global :443 pre-acceleration engine.
#[derive(Debug, Default)]
pub struct GlobalPreAccelMetrics {
    pub active_connections: AtomicU64,
    pub total_connections: AtomicU64,
    pub up_bytes: AtomicU64,
    pub down_bytes: AtomicU64,
    recent_processes: Mutex<VecDeque<String>>,
    process_stats: Mutex<HashMap<ProcessStatKey, Arc<ProcessCounters>>>,
}

impl GlobalPreAccelMetrics {
    pub fn reset(&self) {
        self.active_connections.store(0, Ordering::Relaxed);
        self.total_connections.store(0, Ordering::Relaxed);
        self.up_bytes.store(0, Ordering::Relaxed);
        self.down_bytes.store(0, Ordering::Relaxed);
        if let Ok(mut guard) = self.recent_processes.lock() {
            guard.clear();
        }
        if let Ok(mut guard) = self.process_stats.lock() {
            guard.clear();
        }
    }

    /// Zero out active connection gauges across both global and per-process counters (used on stop).
    pub fn clear_active_connections(&self) {
        self.active_connections.store(0, Ordering::Relaxed);
        if let Ok(guard) = self.process_stats.lock() {
            for pc in guard.values() {
                pc.active_connections.store(0, Ordering::Relaxed);
            }
        }
    }

    pub fn record_process(&self, name: &str) {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return;
        }
        let mut guard = self
            .recent_processes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(pos) = guard.iter().position(|p| p.eq_ignore_ascii_case(trimmed)) {
            guard.remove(pos);
        }
        guard.push_front(trimmed.to_string());
        while guard.len() > MAX_RECENT_PROCESSES {
            guard.pop_back();
        }
    }

    pub fn recent_processes_snapshot(&self) -> Vec<String> {
        self.recent_processes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    fn acquire_process_counters(
        &self,
        pid: u32,
        process_name: &str,
        detected_by: &str,
    ) -> Option<Arc<ProcessCounters>> {
        let display_name = {
            let trimmed = process_name.trim();
            if !trimmed.is_empty() {
                trimmed.to_string()
            } else if pid > 0 {
                format!("pid:{pid}")
            } else {
                return None;
            }
        };
        let reason = {
            let trimmed = detected_by.trim();
            if trimmed.is_empty() {
                "unknown"
            } else {
                trimmed
            }
        };
        let key = ProcessStatKey {
            process_name_lower: display_name.to_ascii_lowercase(),
            pid,
            detected_by: reason.to_string(),
        };

        let mut guard = self
            .process_stats
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = guard.get(&key) {
            return Some(Arc::clone(existing));
        }

        if guard.len() >= MAX_PROCESS_STATS {
            // Evict the oldest idle process bucket first to maintain a hard memory bound.
            let evict_key = guard
                .iter()
                .filter(|(_, pc)| pc.active_connections.load(Ordering::Relaxed) == 0)
                .min_by_key(|(_, pc)| pc.last_seen_ms.load(Ordering::Relaxed))
                .map(|(k, _)| k.clone());
            if let Some(stale) = evict_key {
                guard.remove(&stale);
            } else {
                // All 64 tracked buckets are actively transferring; skip inserting a 65th bucket.
                return None;
            }
        }

        let counters = Arc::new(ProcessCounters {
            process_name: display_name,
            pid,
            detected_by: reason.to_string(),
            active_connections: AtomicUsize::new(0),
            total_connections: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            last_seen_ms: AtomicU64::new(now_epoch_ms()),
        });
        guard.insert(key, Arc::clone(&counters));
        Some(counters)
    }

    /// Record a new redirected connection opening for `(pid, process_name, detected_by)`.
    pub fn record_process_connection_open(
        &self,
        pid: u32,
        process_name: &str,
        detected_by: &str,
    ) {
        self.record_process(process_name);
        if let Some(pc) = self.acquire_process_counters(pid, process_name, detected_by) {
            pc.active_connections.fetch_add(1, Ordering::Relaxed);
            pc.total_connections.fetch_add(1, Ordering::Relaxed);
            pc.last_seen_ms.store(now_epoch_ms(), Ordering::Relaxed);
        }
    }

    /// Record a redirected connection closing for `(pid, process_name, detected_by)`.
    pub fn record_process_connection_close(
        &self,
        pid: u32,
        process_name: &str,
        detected_by: &str,
    ) {
        let display_name = {
            let trimmed = process_name.trim();
            if !trimmed.is_empty() {
                trimmed.to_string()
            } else if pid > 0 {
                format!("pid:{pid}")
            } else {
                return;
            }
        };
        let reason = {
            let trimmed = detected_by.trim();
            if trimmed.is_empty() {
                "unknown"
            } else {
                trimmed
            }
        };
        let key = ProcessStatKey {
            process_name_lower: display_name.to_ascii_lowercase(),
            pid,
            detected_by: reason.to_string(),
        };
        let guard = self
            .process_stats
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(pc) = guard.get(&key) {
            decrement_atomic_usize_saturating(&pc.active_connections);
            pc.last_seen_ms.store(now_epoch_ms(), Ordering::Relaxed);
        }
    }

    /// Accumulate transmitted (`tx_delta`) and received (`rx_delta`) bytes for a process bucket.
    pub fn record_process_bytes(
        &self,
        pid: u32,
        process_name: &str,
        detected_by: &str,
        tx_delta: u64,
        rx_delta: u64,
    ) {
        if tx_delta == 0 && rx_delta == 0 {
            return;
        }
        if let Some(pc) = self.acquire_process_counters(pid, process_name, detected_by) {
            if tx_delta > 0 {
                pc.tx_bytes.fetch_add(tx_delta, Ordering::Relaxed);
            }
            if rx_delta > 0 {
                pc.rx_bytes.fetch_add(rx_delta, Ordering::Relaxed);
            }
            pc.last_seen_ms.store(now_epoch_ms(), Ordering::Relaxed);
        }
    }

    /// Snapshot per-process acceleration telemetry sorted by active connections descending,
    /// then total transferred bytes (`tx_bytes + rx_bytes`) descending, then total connections.
    pub fn process_stats_snapshot(&self) -> Vec<AcceleratedProcessStat> {
        let guard = self
            .process_stats
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut stats: Vec<AcceleratedProcessStat> = guard
            .values()
            .map(|pc| AcceleratedProcessStat {
                process_name: pc.process_name.clone(),
                pid: pc.pid,
                detected_by: pc.detected_by.clone(),
                active_connections: pc.active_connections.load(Ordering::Relaxed),
                total_connections: pc.total_connections.load(Ordering::Relaxed),
                tx_bytes: pc.tx_bytes.load(Ordering::Relaxed),
                rx_bytes: pc.rx_bytes.load(Ordering::Relaxed),
                last_seen_ms: pc.last_seen_ms.load(Ordering::Relaxed),
            })
            .collect();
        drop(guard);

        stats.sort_by(|a, b| {
            b.active_connections
                .cmp(&a.active_connections)
                .then_with(|| {
                    b.tx_bytes
                        .saturating_add(b.rx_bytes)
                        .cmp(&a.tx_bytes.saturating_add(a.rx_bytes))
                })
                .then_with(|| b.total_connections.cmp(&a.total_connections))
                .then_with(|| b.last_seen_ms.cmp(&a.last_seen_ms))
                .then_with(|| a.process_name.cmp(&b.process_name))
                .then_with(|| a.pid.cmp(&b.pid))
        });
        stats
    }

    /// Alias for [`Self::process_stats_snapshot`] returning sorted per-process telemetry.
    pub fn snapshot(&self) -> Vec<AcceleratedProcessStat> {
        self.process_stats_snapshot()
    }
}

/// RAII guard decrementing global and per-process `active_connections` when a forwarded TCP
/// stream terminates.
#[cfg_attr(
    any(not(target_os = "windows"), target_arch = "aarch64"),
    allow(dead_code)
)]
struct ActiveConnGuard {
    metrics: Arc<GlobalPreAccelMetrics>,
    process_counters: Option<Arc<ProcessCounters>>,
}

#[cfg_attr(
    any(not(target_os = "windows"), target_arch = "aarch64"),
    allow(dead_code)
)]
impl ActiveConnGuard {
    fn acquire_for_process(
        metrics: Arc<GlobalPreAccelMetrics>,
        pid: u32,
        process_name: &str,
        detected_by: &str,
    ) -> Self {
        metrics.active_connections.fetch_add(1, Ordering::Relaxed);
        metrics.total_connections.fetch_add(1, Ordering::Relaxed);
        metrics.record_process(process_name);
        let process_counters = metrics.acquire_process_counters(pid, process_name, detected_by);
        if let Some(ref pc) = process_counters {
            pc.active_connections.fetch_add(1, Ordering::Relaxed);
            pc.total_connections.fetch_add(1, Ordering::Relaxed);
            pc.last_seen_ms.store(now_epoch_ms(), Ordering::Relaxed);
        }
        Self {
            metrics,
            process_counters,
        }
    }

    fn process_counters(&self) -> Option<Arc<ProcessCounters>> {
        self.process_counters.clone()
    }
}

impl Drop for ActiveConnGuard {
    fn drop(&mut self) {
        decrement_atomic_u64_saturating(&self.metrics.active_connections);
        if let Some(ref pc) = self.process_counters {
            decrement_atomic_usize_saturating(&pc.active_connections);
            pc.last_seen_ms.store(now_epoch_ms(), Ordering::Relaxed);
        }
    }
}

/// RAII guard releasing a flow's NAT table entry on exit only if it still maps to the
/// original destination, preventing stale port-reuse hijacking while protecting newer flows.
#[cfg_attr(
    any(not(target_os = "windows"), target_arch = "aarch64"),
    allow(dead_code)
)]
struct NatEntryCleanupGuard {
    nat_table: Arc<NatTable>,
    key: NatKey,
    orig_dst_ip: Ipv4Addr,
    orig_dst_port: u16,
}

impl Drop for NatEntryCleanupGuard {
    fn drop(&mut self) {
        self.nat_table
            .remove_if_matching(&self.key, self.orig_dst_ip, self.orig_dst_port);
    }
}

/// Zero-copy `TcpStream` wrapper that atomically tracks real-time upload/download bytes
/// from the client side (`read` = upload/tx, `write` = download/rx) across both global and
/// per-process telemetry buckets without taking any mutex on the data path.
#[cfg_attr(
    any(not(target_os = "windows"), target_arch = "aarch64"),
    allow(dead_code)
)]
struct CountingTcpStream {
    inner: TcpStream,
    metrics: Arc<GlobalPreAccelMetrics>,
    process_counters: Option<Arc<ProcessCounters>>,
}

#[cfg_attr(
    any(not(target_os = "windows"), target_arch = "aarch64"),
    allow(dead_code)
)]
impl CountingTcpStream {
    fn client_side(
        inner: TcpStream,
        metrics: Arc<GlobalPreAccelMetrics>,
        process_counters: Option<Arc<ProcessCounters>>,
    ) -> Self {
        Self {
            inner,
            metrics,
            process_counters,
        }
    }
}

impl AsyncRead for CountingTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let res = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            let delta = buf.filled().len().saturating_sub(before) as u64;
            if delta > 0 {
                this.metrics.up_bytes.fetch_add(delta, Ordering::Relaxed);
                if let Some(ref pc) = this.process_counters {
                    pc.tx_bytes.fetch_add(delta, Ordering::Relaxed);
                    pc.last_seen_ms.store(now_epoch_ms(), Ordering::Relaxed);
                }
            }
        }
        res
    }
}

impl AsyncWrite for CountingTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let res = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &res {
            if *n > 0 {
                let delta = *n as u64;
                this.metrics
                    .down_bytes
                    .fetch_add(delta, Ordering::Relaxed);
                if let Some(ref pc) = this.process_counters {
                    pc.rx_bytes.fetch_add(delta, Ordering::Relaxed);
                    pc.last_seen_ms.store(now_epoch_ms(), Ordering::Relaxed);
                }
            }
        }
        res
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Perform a standard RFC 1928 SOCKS5 NOAUTH CONNECT handshake to `(dst_ip, dst_port)`.
pub async fn socks5_noauth_connect_ipv4(
    stream: &mut TcpStream,
    dst_ip: Ipv4Addr,
    dst_port: u16,
) -> CatResult<()> {
    // 1. Greeting: VER=5, NMETHODS=1, METHOD=0x00 (No Auth)
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method_resp = [0u8; 2];
    stream.read_exact(&mut method_resp).await?;
    if method_resp[0] != 0x05 || method_resp[1] != 0x00 {
        return Err(CatError::Core(format!(
            "SOCKS5 隧道握手认证失败: {:?}",
            method_resp
        )));
    }

    // 2. Request: VER=5, CMD=CONNECT(1), RSV=0, ATYP=IPv4(1), DST.ADDR, DST.PORT
    let octets = dst_ip.octets();
    let port_be = dst_port.to_be_bytes();
    let req = [
        0x05, 0x01, 0x00, 0x01, octets[0], octets[1], octets[2], octets[3], port_be[0], port_be[1],
    ];
    stream.write_all(&req).await?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return Err(CatError::Core(format!(
            "SOCKS5 CONNECT 到 {dst_ip}:{dst_port} 被拒绝 (rep=0x{:02x})",
            head[1]
        )));
    }

    match head[3] {
        0x01 => {
            let mut tail = [0u8; 6];
            stream.read_exact(&mut tail).await?;
        }
        0x03 => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let mut tail = vec![0u8; usize::from(len_buf[0]) + 2];
            stream.read_exact(&mut tail).await?;
        }
        0x04 => {
            let mut tail = [0u8; 18];
            stream.read_exact(&mut tail).await?;
        }
        other => {
            return Err(CatError::Core(format!(
                "SOCKS5 响应包含未知地址类型 ATYP=0x{other:02x}"
            )));
        }
    }

    Ok(())
}

/// Forward an accepted self-loop TCP connection through the standalone :443 SOCKS5 tunnel.
///
/// Security invariant: any connection whose `(peer_ip, peer_port)` is not registered in
/// `nat_table` is dropped immediately without opening an upstream socket, ensuring the
/// temporary `0.0.0.0:<redirect_port>` listener never exposes an open proxy to the LAN.
#[cfg_attr(
    any(not(target_os = "windows"), target_arch = "aarch64"),
    allow(dead_code)
)]
pub(super) async fn forward_redirected_stream(
    client_stream: TcpStream,
    peer_addr: SocketAddr,
    socks_port: u16,
    nat_table: Arc<NatTable>,
    metrics: Arc<GlobalPreAccelMetrics>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    if *shutdown_rx.borrow() {
        return;
    }
    let SocketAddr::V4(peer_v4) = peer_addr else {
        return;
    };
    let key = (*peer_v4.ip(), peer_v4.port());
    let Some(entry) = nat_table.get_and_touch(&key) else {
        // Unregistered external/local scanner: close immediately.
        return;
    };
    let _nat_cleanup = NatEntryCleanupGuard {
        nat_table,
        key,
        orig_dst_ip: entry.orig_dst_ip,
        orig_dst_port: entry.orig_dst_port,
    };

    let _ = client_stream.set_nodelay(true);
    let active_guard = ActiveConnGuard::acquire_for_process(
        Arc::clone(&metrics),
        entry.owner_pid,
        &entry.process_name,
        &entry.detected_by,
    );
    let process_counters = active_guard.process_counters();

    let socks_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, socks_port);
    let connect_res = tokio::select! {
        _ = shutdown_rx.changed() => return,
        res = tokio::time::timeout(
            Duration::from_secs(10),
            TcpStream::connect(socks_addr),
        ) => res,
    };
    let Ok(Ok(mut upstream)) = connect_res else {
        return;
    };
    let _ = upstream.set_nodelay(true);

    if *shutdown_rx.borrow() {
        return;
    }
    let handshake_res = tokio::select! {
        _ = shutdown_rx.changed() => return,
        res = tokio::time::timeout(
            Duration::from_secs(10),
            socks5_noauth_connect_ipv4(&mut upstream, entry.orig_dst_ip, entry.orig_dst_port),
        ) => res,
    };
    if !matches!(handshake_res, Ok(Ok(()))) {
        return;
    }

    if *shutdown_rx.borrow() {
        return;
    }
    let mut counting_client =
        CountingTcpStream::client_side(client_stream, metrics, process_counters);
    tokio::select! {
        _ = tokio::io::copy_bidirectional(&mut counting_client, &mut upstream) => {}
        _ = shutdown_rx.changed() => {}
    }
}

// ============================================================================
// C. Unified Cross-Platform GlobalPreAccelManager & Status Snapshot
// ============================================================================

fn default_install_state() -> String {
    "idle".to_string()
}

fn normalize_install_state(raw: &str) -> &'static str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "downloading" => "downloading",
        "verifying" => "verifying",
        "ready" => "ready",
        "need_elevation" => "need_elevation",
        "failed" => "failed",
        _ => "idle",
    }
}

/// Live status snapshot of the standalone global domestic :443 pre-acceleration engine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GlobalPreAccelStatus {
    pub running: bool,
    /// Active engine mode: `"off"`, `"windivert"` (Windows transparent kernel NAT), or
    /// `"local_socks5"` (cross-platform standalone 127.0.0.1 :443 dual-active SOCKS5 entry).
    pub mode: String,
    /// Strictly `true` only when `running && mode == "windivert"`.
    #[serde(default)]
    pub is_windivert_active: bool,
    /// Driver installation / elevation lifecycle state:
    /// `"idle" | "downloading" | "verifying" | "ready" | "need_elevation" | "failed"`.
    #[serde(default = "default_install_state")]
    pub install_state: String,
    pub socks_port: Option<u16>,
    pub windivert_available: bool,
    pub windivert_path: Option<String>,
    pub is_elevated: bool,
    pub active_connections: u64,
    pub total_connections: u64,
    pub up_bytes: u64,
    pub down_bytes: u64,
    pub accelerated_processes: Vec<String>,
    #[serde(default)]
    pub process_stats: Vec<AcceleratedProcessStat>,
    pub active_relays: Vec<String>,
    pub last_error: Option<String>,
}

impl Default for GlobalPreAccelStatus {
    fn default() -> Self {
        Self {
            running: false,
            mode: "off".to_string(),
            is_windivert_active: false,
            install_state: default_install_state(),
            socks_port: None,
            windivert_available: false,
            windivert_path: None,
            is_elevated: false,
            active_connections: 0,
            total_connections: 0,
            up_bytes: 0,
            down_bytes: 0,
            accelerated_processes: Vec::new(),
            process_stats: Vec::new(),
            active_relays: Vec::new(),
            last_error: None,
        }
    }
}

#[derive(Debug)]
struct ActiveGlobalRuntime {
    #[cfg(target_os = "windows")]
    engine: Option<super::windivert_win::WinDivertEngine>,
    tunnel: StandalonePreAccelTunnel,
    mode: String,
    socks_port: u16,
    active_relays: Vec<String>,
}

impl ActiveGlobalRuntime {
    async fn stop(mut self) {
        // Stop WinDivert kernel interception BEFORE tearing down the standalone 443 tunnel so
        // native network flow resumes immediately with zero packet drops.
        #[cfg(target_os = "windows")]
        if let Some(mut engine) = self.engine.take() {
            let _ = tokio::task::spawn_blocking(move || engine.stop_sync()).await;
        }
        self.tunnel.stop().await;
    }
}

/// Cross-platform manager orchestrating the standalone lightweight :443 dual-active tunnel
/// and (on elevated Windows with WinDivert v2.2.2) the native kernel transparent TCP NAT engine.
#[derive(Debug)]
pub struct GlobalPreAccelManager {
    paths: AppPaths,
    job_guard: Arc<JobGuard>,
    op_lock: tokio::sync::Mutex<()>,
    runtime: Mutex<Option<ActiveGlobalRuntime>>,
    metrics: Arc<GlobalPreAccelMetrics>,
    last_error: Mutex<Option<String>>,
    install_state: Mutex<String>,
    custom_windivert_dir: Mutex<Option<String>>,
    synced_main_core_pid: Mutex<Option<u32>>,
}

impl GlobalPreAccelManager {
    pub fn new(paths: AppPaths, job_guard: Arc<JobGuard>) -> Self {
        Self {
            paths,
            job_guard,
            op_lock: tokio::sync::Mutex::new(()),
            runtime: Mutex::new(None),
            metrics: Arc::new(GlobalPreAccelMetrics::default()),
            last_error: Mutex::new(None),
            install_state: Mutex::new(default_install_state()),
            custom_windivert_dir: Mutex::new(None),
            synced_main_core_pid: Mutex::new(None),
        }
    }

    /// Update the driver installation / elevation lifecycle state exposed in `GlobalPreAccelStatus`.
    /// Accepted values: `"idle" | "downloading" | "verifying" | "ready" | "need_elevation" | "failed"`.
    pub fn set_install_state(&self, state: &str) {
        let normalized = normalize_install_state(state);
        let mut guard = self
            .install_state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *guard = normalized.to_string();
    }

    /// Read the currently stored driver installation / elevation lifecycle state.
    pub fn install_state(&self) -> String {
        self.install_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Dynamically synchronize the external main Mihomo core PID excluded from Windows
    /// transparent WinDivert interception (for example when the main core starts, restarts,
    /// or stops while operating in mixed-port-only mode without system proxy / TUN takeover).
    ///
    /// Always preserves CatCloud's own PID and the standalone :443 tunnel subprocess PID.
    pub fn sync_main_core_pid(&self, main_core_pid: Option<u32>) {
        let normalized = main_core_pid.filter(|&pid| pid > 0);
        let mut slot = self
            .synced_main_core_pid
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *slot = normalized;

        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        {
            let rt_guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(rt) = rt_guard.as_ref() {
                if let Some(engine) = rt.engine.as_ref() {
                    engine.sync_main_core_pid(normalized);
                }
            }
        }
    }

    /// Start (or restart) the standalone global domestic :443 pre-acceleration engine.
    ///
    /// - Launches the standalone lightweight `:443` dual-active SOCKS5 tunnel on all platforms.
    /// - On x64 Windows, when running elevated with `WinDivert64.dll` + `WinDivert64.sys` present,
    ///   engages the transparent kernel TCP NAT engine (`mode = "windivert"`) while excluding
    ///   CatCloud itself, the standalone tunnel PID, and any `extra_excluded_pids` (such as
    ///   CatCloud's main Mihomo core PID).
    /// - Falls back cleanly to `mode = "local_socks5"` on macOS/Linux, Windows ARM64, or
    ///   non-elevated/missing-driver Windows environments without ever disrupting network connectivity.
    pub async fn start(
        &self,
        cfg: &AppConfig,
        relays: &[PreAccelRelay],
        extra_excluded_pids: &[u32],
    ) -> CatResult<GlobalPreAccelStatus> {
        let _op = self.op_lock.lock().await;

        {
            let mut dir_guard = self
                .custom_windivert_dir
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *dir_guard = cfg.preaccel.windivert_dir.clone();
        }

        // Cleanly stop any previous runtime before starting a fresh instance.
        let previous = {
            let mut rt_guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
            rt_guard.take()
        };
        if let Some(prev) = previous {
            prev.stop().await;
        }
        self.metrics.reset();
        self.set_last_error(None);

        let tunnel = match StandalonePreAccelTunnel::start(
            &self.paths,
            cfg,
            relays,
            Arc::clone(&self.job_guard),
            None,
        )
        .await
        {
            Ok(t) => t,
            Err(err) => {
                self.set_last_error(Some(err.to_string()));
                return Err(err);
            }
        };

        let socks_port = tunnel.socks_port();
        let active_relays = tunnel.active_relays().to_vec();
        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        let mut mode = "local_socks5".to_string();
        #[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
        let mode = "local_socks5".to_string();

        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        let mut win_engine: Option<super::windivert_win::WinDivertEngine> = None;
        #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
        let win_engine: Option<super::windivert_win::WinDivertEngine> = None;

        #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
        {
            let _ = extra_excluded_pids;
            self.set_last_error(Some(WINDIVERT_ARM64_UNSUPPORTED_MSG.to_string()));
        }

        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        {
            let is_elevated = default_platform().capabilities().is_elevated;
            let wd_files =
                locate_windivert_files(&self.paths, cfg.preaccel.windivert_dir.as_deref());

            if !is_elevated {
                if wd_files.is_some() {
                    self.set_install_state("need_elevation");
                } else {
                    let cur_state = self.install_state();
                    if cur_state != "downloading" && cur_state != "verifying" {
                        self.set_install_state("idle");
                    }
                }
                self.set_last_error(Some(
                    "当前非管理员权限，已自动运行在本地独立 443 SOCKS5 隧道模式；如需透明加速其它软件请以管理员身份运行"
                        .to_string(),
                ));
            } else if let Some((dll_path, _sys_path)) = wd_files {
                let synced_main_pid = *self
                    .synced_main_core_pid
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let mut static_excluded_pids: HashSet<u32> = HashSet::new();
                for &pid in extra_excluded_pids {
                    if pid > 0 && Some(pid) != synced_main_pid {
                        static_excluded_pids.insert(pid);
                    }
                }

                let relay_ipv4s = collect_enabled_relay_ipv4s(relays);
                let engine_cfg = super::windivert_win::WinDivertEngineConfig {
                    dll_path,
                    socks_port,
                    relay_ipv4s,
                    scope: cfg.preaccel.global_scope,
                    target_processes: cfg.preaccel.global_target_processes.clone(),
                    excluded_pids: static_excluded_pids,
                    tunnel_pid: tunnel.pid(),
                    main_core_pid: synced_main_pid,
                    metrics: Arc::clone(&self.metrics),
                };

                match super::windivert_win::WinDivertEngine::start(engine_cfg).await {
                    Ok(engine) => {
                        win_engine = Some(engine);
                        mode = "windivert".to_string();
                        self.set_install_state("ready");
                        self.set_last_error(None);
                    }
                    Err(err) => {
                        self.set_install_state("failed");
                        self.set_last_error(Some(format!(
                            "WinDivert 透明内核引擎启动失败，已降级为本地独立 443 SOCKS5 隧道 ({err})"
                        )));
                    }
                }
            } else {
                let cur_state = self.install_state();
                if cur_state != "downloading" && cur_state != "verifying" {
                    self.set_install_state("idle");
                }
                self.set_last_error(Some(
                    "尚未安装 WinDivert v2.2.2 驱动组件，已自动运行在本地独立 443 SOCKS5 隧道模式"
                        .to_string(),
                ));
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = extra_excluded_pids;
        }

        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        {
            let synced_guard = self
                .synced_main_core_pid
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(ref engine) = win_engine {
                engine.sync_main_core_pid(*synced_guard);
            }
            let mut rt_guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
            *rt_guard = Some(ActiveGlobalRuntime {
                engine: win_engine,
                tunnel,
                mode,
                socks_port,
                active_relays,
            });
        }

        #[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
        {
            let mut rt_guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
            *rt_guard = Some(ActiveGlobalRuntime {
                #[cfg(target_os = "windows")]
                engine: win_engine,
                tunnel,
                mode,
                socks_port,
                active_relays,
            });
        }

        Ok(self.status())
    }

    /// Hot-upgrade a running `"local_socks5"` runtime in place to `"windivert"` transparent kernel
    /// interception once WinDivert driver files are ready, without stopping or interrupting the
    /// active standalone `:443` SOCKS5 tunnel.
    pub async fn upgrade_to_windivert_in_place(
        &self,
        cfg: &AppConfig,
        relays: &[PreAccelRelay],
        extra_excluded_pids: &[u32],
    ) -> CatResult<GlobalPreAccelStatus> {
        let _op = self.op_lock.lock().await;

        {
            let mut dir_guard = self
                .custom_windivert_dir
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *dir_guard = cfg.preaccel.windivert_dir.clone();
        }

        #[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
        {
            let _ = (relays, extra_excluded_pids);
            #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
            {
                self.set_last_error(Some(WINDIVERT_ARM64_UNSUPPORTED_MSG.to_string()));
            }
            Ok(self.status())
        }

        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        {
            let running_snapshot = {
                let rt_guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
                rt_guard
                    .as_ref()
                    .map(|rt| (rt.mode == "windivert", rt.socks_port, rt.tunnel.pid()))
            };

            let Some((already_windivert, socks_port, tunnel_pid)) = running_snapshot else {
                // Not running: reflect readiness/elevation accurately without starting a new tunnel.
                let wd_ready =
                    locate_windivert_files(&self.paths, cfg.preaccel.windivert_dir.as_deref())
                        .is_some();
                if wd_ready {
                    if default_platform().capabilities().is_elevated {
                        self.set_install_state("ready");
                    } else {
                        self.set_install_state("need_elevation");
                    }
                } else {
                    self.set_install_state("idle");
                }
                return Ok(self.status());
            };

            if already_windivert {
                self.set_install_state("ready");
                self.set_last_error(None);
                return Ok(self.status());
            }

            let Some((dll_path, _sys_path)) =
                locate_windivert_files(&self.paths, cfg.preaccel.windivert_dir.as_deref())
            else {
                self.set_install_state("failed");
                self.set_last_error(Some(
                    "未找到 WinDivert v2.2.2 驱动文件（WinDivert64.dll / WinDivert64.sys），继续保持本地独立 443 通道"
                        .to_string(),
                ));
                return Ok(self.status());
            };

            let is_elevated = default_platform().capabilities().is_elevated;
            if !is_elevated {
                self.set_install_state("need_elevation");
                self.set_last_error(Some(
                    "WinDivert 驱动已就绪，请以管理员身份重启猫猫云梯以启用底层透明提速"
                        .to_string(),
                ));
                return Ok(self.status());
            }

            let synced_main_pid = *self
                .synced_main_core_pid
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let mut static_excluded_pids: HashSet<u32> = HashSet::new();
            for &pid in extra_excluded_pids {
                if pid > 0 && Some(pid) != synced_main_pid {
                    static_excluded_pids.insert(pid);
                }
            }

            let relay_ipv4s = collect_enabled_relay_ipv4s(relays);
            let engine_cfg = super::windivert_win::WinDivertEngineConfig {
                dll_path,
                socks_port,
                relay_ipv4s,
                scope: cfg.preaccel.global_scope,
                target_processes: cfg.preaccel.global_target_processes.clone(),
                excluded_pids: static_excluded_pids,
                tunnel_pid,
                main_core_pid: synced_main_pid,
                metrics: Arc::clone(&self.metrics),
            };

            match super::windivert_win::WinDivertEngine::start(engine_cfg).await {
                Ok(engine) => {
                    let (installed, displaced_engine) = {
                        let synced_guard = self
                            .synced_main_core_pid
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        engine.sync_main_core_pid(*synced_guard);
                        let mut rt_guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
                        if let Some(rt) = rt_guard.as_mut() {
                            let old = rt.engine.replace(engine);
                            rt.mode = "windivert".to_string();
                            (true, old)
                        } else {
                            (false, Some(engine))
                        }
                    };
                    if let Some(mut stale) = displaced_engine {
                        let _ = tokio::task::spawn_blocking(move || stale.stop_sync()).await;
                    }
                    if installed {
                        self.set_install_state("ready");
                        self.set_last_error(None);
                    } else {
                        let wd_ready = locate_windivert_files(
                            &self.paths,
                            cfg.preaccel.windivert_dir.as_deref(),
                        )
                        .is_some();
                        if wd_ready && is_elevated {
                            self.set_install_state("ready");
                        } else if wd_ready {
                            self.set_install_state("need_elevation");
                        } else {
                            self.set_install_state("idle");
                        }
                    }
                    Ok(self.status())
                }
                Err(err) => {
                    self.set_install_state("failed");
                    self.set_last_error(Some(format!(
                        "WinDivert 驱动就绪后原地热升格失败，继续保持本地独立 443 通道 ({err})"
                    )));
                    Err(err)
                }
            }
        }
    }

    /// Deterministically stop transparent interception and terminate the standalone :443 tunnel.
    pub async fn stop(&self) -> CatResult<GlobalPreAccelStatus> {
        let _op = self.op_lock.lock().await;
        let current = {
            let mut rt_guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
            rt_guard.take()
        };
        if let Some(rt) = current {
            rt.stop().await;
        }
        self.metrics.clear_active_connections();
        Ok(self.status())
    }

    /// Capture an up-to-date status snapshot without blocking asynchronous callers.
    pub fn status(&self) -> GlobalPreAccelStatus {
        let custom_dir = self
            .custom_windivert_dir
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        self.status_with_custom_dir(custom_dir.as_deref())
    }

    /// Capture an up-to-date status snapshot evaluating WinDivert presence against `custom_dir`.
    pub fn status_with_custom_dir(&self, custom_dir: Option<&str>) -> GlobalPreAccelStatus {
        let is_elevated = default_platform().capabilities().is_elevated;
        let wd_files = locate_windivert_files(&self.paths, custom_dir);
        let windivert_available = wd_files.is_some();
        let windivert_path = wd_files.map(|(dll, _)| dll.to_string_lossy().to_string());

        let (running, mode, socks_port, active_relays) = {
            let guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(rt) => (
                    true,
                    rt.mode.clone(),
                    Some(rt.socks_port),
                    rt.active_relays.clone(),
                ),
                None => (false, "off".to_string(), None, Vec::new()),
            }
        };

        let is_windivert_active = running && mode == "windivert";
        let stored_install_state = self
            .install_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let install_state = match stored_install_state.as_str() {
            "downloading" | "verifying" | "failed" => stored_install_state,
            _ => {
                #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
                {
                    if !windivert_available {
                        "idle".to_string()
                    } else if is_windivert_active || is_elevated {
                        "ready".to_string()
                    } else {
                        "need_elevation".to_string()
                    }
                }
                #[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
                {
                    stored_install_state
                }
            }
        };

        let last_error = self
            .last_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

        GlobalPreAccelStatus {
            running,
            mode,
            is_windivert_active,
            install_state,
            socks_port,
            windivert_available,
            windivert_path,
            is_elevated,
            active_connections: self.metrics.active_connections.load(Ordering::Relaxed),
            total_connections: self.metrics.total_connections.load(Ordering::Relaxed),
            up_bytes: self.metrics.up_bytes.load(Ordering::Relaxed),
            down_bytes: self.metrics.down_bytes.load(Ordering::Relaxed),
            accelerated_processes: self.metrics.recent_processes_snapshot(),
            process_stats: self.metrics.process_stats_snapshot(),
            active_relays,
            last_error,
        }
    }

    fn set_last_error(&self, err: Option<String>) {
        if let Ok(mut guard) = self.last_error.lock() {
            *guard = err;
        }
    }
}

impl Drop for GlobalPreAccelManager {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.runtime.lock() {
            if let Some(rt) = guard.take() {
                // Dropping `ActiveGlobalRuntime` runs `WinDivertEngine::drop` first (field order),
                // then `StandalonePreAccelTunnel::drop`, ensuring zero leaks and zero network hang.
                drop(rt);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::preaccel::generator::PREACCEL_FALLBACK_GROUP;
    use std::io::Write as _;
    use tokio::net::TcpListener;
    use zip::CompressionMethod;
    use zip::write::SimpleFileOptions;

    const TEST_UUID: &str = "11111111-2222-4333-8444-555555555555";

    fn sample_anytls_relay_with_dirty_sni() -> PreAccelRelay {
        PreAccelRelay {
            id: "relay-tx-443".to_string(),
            name: "Relay-TX-443".to_string(),
            provider: "tencent".to_string(),
            region: "CN-GZ".to_string(),
            server: "203.0.113.10".to_string(),
            port: 443,
            protocol: "anytls".to_string(),
            password: "demo-pass-01".to_string(),
            sni: Some("unfiled.example.com".to_string()),
            skip_cert_verify: false,
            priority: 10,
            expires_at: None,
            enabled: true,
            last_probe_ms: None,
            last_mbps: None,
        }
    }

    fn sample_vless_relay_with_dirty_sni() -> PreAccelRelay {
        PreAccelRelay {
            id: "relay-ali-443".to_string(),
            name: "Relay-ALI-443".to_string(),
            provider: "aliyun".to_string(),
            region: "CN-SH".to_string(),
            server: "198.51.100.20".to_string(),
            port: 443,
            protocol: "vless".to_string(),
            password: TEST_UUID.to_string(),
            sni: Some("unfiled-vless.example.com".to_string()),
            skip_cert_verify: false,
            priority: 20,
            expires_at: None,
            enabled: true,
            last_probe_ms: None,
            last_mbps: None,
        }
    }

    #[test]
    fn windivert_address_is_exact_80_bytes_and_bitfield_roundtrips() {
        assert_eq!(std::mem::size_of::<WinDivertAddress>(), 80);

        let mut addr = WinDivertAddress::default();
        addr.timestamp = 1_700_000_000;
        addr.set_layer(0);
        addr.set_event(1);
        addr.set_sniffed(true);
        addr.set_outbound(true);
        addr.set_loopback(true);
        addr.set_impostor(true);
        addr.set_ipv6(true);
        addr.set_ip_checksum(true);
        addr.set_tcp_checksum(true);
        addr.set_udp_checksum(true);
        addr.set_network_if_idx(17);
        addr.set_network_sub_if_idx(3);

        assert_eq!(addr.layer(), 0);
        assert_eq!(addr.event(), 1);
        assert!(addr.sniffed());
        assert!(addr.outbound());
        assert!(addr.loopback());
        assert!(addr.impostor());
        assert!(addr.ipv6());
        assert!(addr.ip_checksum());
        assert!(addr.tcp_checksum());
        assert!(addr.udp_checksum());
        assert_eq!(addr.network_if_idx(), 17);
        assert_eq!(addr.network_sub_if_idx(), 3);

        // Clearing Outbound and Loopback must not disturb sibling bitfield flags.
        addr.set_outbound(false);
        addr.set_loopback(false);
        addr.set_layer(2);
        assert_eq!(addr.layer(), 2);
        assert_eq!(addr.event(), 1);
        assert!(addr.sniffed());
        assert!(!addr.outbound());
        assert!(!addr.loopback());
        assert!(addr.impostor());
        assert!(addr.ip_checksum());
        assert!(addr.tcp_checksum());
        assert!(addr.udp_checksum());
    }

    #[test]
    fn build_windivert_filter_excludes_relays_ports_private_ranges_and_never_geoip_cn() {
        let relays = [
            Ipv4Addr::new(203, 0, 113, 10),
            Ipv4Addr::new(198, 51, 100, 20),
            Ipv4Addr::new(203, 0, 113, 10), // duplicate must deduplicate
        ];
        let filter = build_windivert_filter(&relays, 54321);

        assert!(filter.starts_with("ip and tcp and ("));
        assert!(filter.contains("!loopback"));
        assert!(filter.contains("tcp.DstPort != 443"));
        assert!(filter.contains("tcp.DstPort != 53"));
        assert!(filter.contains("ip.DstAddr != 203.0.113.10"));
        assert!(filter.contains("ip.DstAddr != 198.51.100.20"));
        assert!(filter.contains("(ip.DstAddr < 10.0.0.0 or ip.DstAddr > 10.255.255.255)"));
        assert!(filter.contains("(ip.DstAddr < 100.64.0.0 or ip.DstAddr > 100.127.255.255)"));
        assert!(filter.contains("(ip.DstAddr < 127.0.0.0 or ip.DstAddr > 127.255.255.255)"));
        assert!(filter.contains("(ip.DstAddr < 169.254.0.0 or ip.DstAddr > 169.254.255.255)"));
        assert!(filter.contains("(ip.DstAddr < 172.16.0.0 or ip.DstAddr > 172.31.255.255)"));
        assert!(filter.contains("(ip.DstAddr < 192.168.0.0 or ip.DstAddr > 192.168.255.255)"));
        assert!(filter.contains("(ip.DstAddr < 198.18.0.0 or ip.DstAddr > 198.19.255.255)"));
        assert!(filter.contains("ip.DstAddr < 224.0.0.0"));
        assert!(filter.contains("(outbound and tcp.SrcPort == 54321)"));

        // Must never contain CIDR syntax (invalid in WinDivert) or GeoIP CN bypass.
        assert!(!filter.contains('/'));
        let lower = filter.to_ascii_lowercase();
        assert!(!lower.contains("geoip"));
        assert!(!lower.contains("cn"));
    }

    #[test]
    fn compile_standalone_preaccel_yaml_enforces_zero_tun_zero_dns_no_sni_domestic_204_and_anti_loop()
    {
        let mut cfg = AppConfig::default();
        cfg.preaccel.enabled = false; // standalone mode must still compile cleanly when main preaccel is off
        let mut disabled = sample_anytls_relay_with_dirty_sni();
        disabled.id = "relay-disabled".to_string();
        disabled.server = "192.0.2.99".to_string();
        disabled.enabled = false;

        let relays = vec![
            sample_vless_relay_with_dirty_sni(),
            disabled,
            sample_anytls_relay_with_dirty_sni(),
        ];

        let yaml_str =
            compile_standalone_preaccel_yaml(&cfg, &relays, 17908).expect("compile standalone");
        let doc: Value = serde_yaml_ng::from_str(&yaml_str).expect("valid YAML");

        assert_eq!(doc["socks-port"].as_u64(), Some(17908));
        assert_eq!(doc["bind-address"].as_str(), Some("127.0.0.1"));
        assert_eq!(doc["allow-lan"].as_bool(), Some(false));
        assert_eq!(doc["tun"]["enable"].as_bool(), Some(false));
        assert_eq!(doc["dns"]["enable"].as_bool(), Some(false));
        assert!(doc.get("external-controller").is_none());
        assert_eq!(doc["geo-auto-update"].as_bool(), Some(false));
        assert_eq!(doc["geodata-loader"].as_str(), Some("memconservative"));
        assert_eq!(doc["keep-alive-idle"].as_u64(), Some(15));
        assert_eq!(doc["keep-alive-interval"].as_u64(), Some(15));

        // Verify 443 relays had unfiled third-party SNI stripped and skip-cert-verify enforced.
        let proxies = doc["proxies"].as_sequence().unwrap();
        assert_eq!(proxies.len(), 2);
        let anytls = &proxies[0];
        assert_eq!(anytls["type"].as_str(), Some("anytls"));
        assert_eq!(anytls["server"].as_str(), Some("203.0.113.10"));
        assert!(anytls.get("sni").is_none());
        assert_eq!(anytls["skip-cert-verify"].as_bool(), Some(true));

        let vless = &proxies[1];
        assert_eq!(vless["type"].as_str(), Some("vless"));
        assert_eq!(vless["server"].as_str(), Some("198.51.100.20"));
        assert_eq!(vless["servername"].as_str(), Some(""));
        assert_eq!(vless["skip-cert-verify"].as_bool(), Some(true));

        // Verify fallback group uses domestic 204 probe and lazy: false.
        let groups = doc["proxy-groups"].as_sequence().unwrap();
        let fallback = groups
            .iter()
            .find(|g| g["name"].as_str() == Some(PREACCEL_FALLBACK_GROUP))
            .expect("fallback group");
        assert_eq!(fallback["lazy"].as_bool(), Some(false));
        assert!(fallback["url"].as_str().unwrap().contains("hicloud.com"));

        // Verify top-level DIRECT anti-loop rules precede MATCH.
        let rules: Vec<&str> = doc["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        let idx_tx = rules
            .iter()
            .position(|r| *r == "IP-CIDR,203.0.113.10/32,DIRECT,no-resolve")
            .expect("relay 1 direct rule");
        let idx_ali = rules
            .iter()
            .position(|r| *r == "IP-CIDR,198.51.100.20/32,DIRECT,no-resolve")
            .expect("relay 2 direct rule");
        let idx_probe = rules
            .iter()
            .position(|r| *r == "DOMAIN,connectivitycheck.platform.hicloud.com,DIRECT")
            .expect("domestic 204 direct rule");
        let idx_match = rules
            .iter()
            .position(|r| *r == format!("MATCH,{PREACCEL_SELECT_GROUP}"))
            .expect("MATCH preaccel select group");
        assert!(idx_tx < idx_match);
        assert!(idx_ali < idx_match);
        assert!(idx_probe < idx_match);
        assert!(!rules.contains(&"IP-CIDR,192.0.2.99/32,DIRECT,no-resolve"));
    }

    #[cfg(not(all(target_os = "windows", target_arch = "aarch64")))]
    #[test]
    fn locate_windivert_files_respects_priority_and_requires_colocated_sys() {
        let root = std::env::temp_dir().join(format!(
            "catcloud-wd-locate-{}",
            uuid::Uuid::new_v4()
        ));
        let paths = AppPaths::from_data_dir(root.join("data"), true).unwrap();
        let exe_dir = root.join("app");
        let res_bin = exe_dir.join("resources").join("bin");
        let custom_dir = root.join("custom_wd");
        std::fs::create_dir_all(&res_bin).unwrap();
        std::fs::create_dir_all(&custom_dir).unwrap();

        // Missing `.sys` in custom_dir must be skipped even when `.dll` exists.
        std::fs::write(custom_dir.join("WinDivert64.dll"), b"dll-only").unwrap();
        std::fs::write(exe_dir.join("WinDivert.dll"), b"exe-dll").unwrap();
        std::fs::write(exe_dir.join("WinDivert64.sys"), b"exe-sys").unwrap();

        let found_exe = locate_windivert_files_with_exe_dir(
            &paths,
            Some(custom_dir.to_str().unwrap()),
            Some(&exe_dir),
        )
        .expect("should fall back to exe_dir");
        assert_eq!(found_exe.0, normalize_os_path(&exe_dir.join("WinDivert.dll")));

        // Placing pair in resources/bin overrides exe_dir.
        std::fs::write(res_bin.join("WinDivert64.dll"), b"res-dll").unwrap();
        std::fs::write(res_bin.join("WinDivert64.sys"), b"res-sys").unwrap();
        let found_res = locate_windivert_files_with_exe_dir(&paths, None, Some(&exe_dir)).unwrap();
        assert_eq!(found_res.0, normalize_os_path(&res_bin.join("WinDivert64.dll")));

        // Placing pair in paths.bin_dir overrides resources/bin.
        std::fs::write(paths.bin_dir.join("WinDivert64.dll"), b"bin-dll").unwrap();
        std::fs::write(paths.bin_dir.join("WinDivert64.sys"), b"bin-sys").unwrap();
        let found_bin = locate_windivert_files_with_exe_dir(&paths, None, Some(&exe_dir)).unwrap();
        assert_eq!(
            found_bin.0,
            normalize_os_path(&paths.bin_dir.join("WinDivert64.dll"))
        );

        // Adding `.sys` to custom_dir makes custom_dir highest priority.
        std::fs::write(custom_dir.join("WinDivert64.sys"), b"custom-sys").unwrap();
        let found_custom = locate_windivert_files_with_exe_dir(
            &paths,
            Some(custom_dir.to_str().unwrap()),
            Some(&exe_dir),
        )
        .unwrap();
        assert_eq!(
            found_custom.0,
            normalize_os_path(&custom_dir.join("WinDivert64.dll"))
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn verify_and_extract_windivert_zip_validates_sha256_and_blocks_traversal() {
        let root = std::env::temp_dir().join(format!(
            "catcloud-wd-zip-{}",
            uuid::Uuid::new_v4()
        ));
        let dest = root.join("bin");

        let make_zip = |entries: &[(&str, &[u8])]| -> Vec<u8> {
            let mut cursor = Cursor::new(Vec::new());
            {
                let mut zw = zip::ZipWriter::new(&mut cursor);
                let opts = SimpleFileOptions::default()
                    .compression_method(CompressionMethod::Stored);
                for (name, body) in entries {
                    zw.start_file(*name, opts).unwrap();
                    zw.write_all(body).unwrap();
                }
                zw.finish().unwrap();
            }
            cursor.into_inner()
        };

        let good_zip = make_zip(&[
            ("WinDivert-2.2.2-A/x64/WinDivert.dll", b"fake-dll-bytes"),
            ("WinDivert-2.2.2-A/x64/WinDivert64.sys", b"fake-sys-bytes"),
            ("WinDivert-2.2.2-A/README", b"ignored"),
        ]);
        let good_sha = hex::encode(Sha256::digest(&good_zip));

        // Mismatched SHA-256 must fail.
        assert!(verify_and_extract_windivert_zip(&good_zip, "0000", &dest).is_err());

        // Matching SHA-256 installs WinDivert.dll, WinDivert64.dll, and WinDivert64.sys only.
        let installed =
            verify_and_extract_windivert_zip(&good_zip, &good_sha, &dest).expect("install ok");
        assert!(installed.dll_path.is_file());
        assert!(installed.sys_path.is_file());
        assert!(dest.join("WinDivert.dll").is_file());
        assert!(!dest.join("README").exists());

        // Path traversal entry must be rejected even when SHA-256 matches.
        let evil_zip = make_zip(&[("../evil.dll", b"nope")]);
        let evil_sha = hex::encode(Sha256::digest(&evil_zip));
        assert!(verify_and_extract_windivert_zip(&evil_zip, &evil_sha, &dest).is_err());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn nat_table_ipv4_tcp_rewrite_nic_filter_and_process_policy_work() {
        let table = NatTable::new(2, Duration::from_secs(60));
        let now = Instant::now();
        table.insert(
            (Ipv4Addr::new(192, 0, 2, 10), 40001),
            NatEntry {
                orig_dst_ip: Ipv4Addr::new(203, 0, 113, 50),
                orig_dst_port: 8443,
                if_idx: 7,
                sub_if_idx: 0,
                owner_pid: 2001,
                process_name: "mihomo.exe".to_string(),
                detected_by: "open_core_name".to_string(),
                last_seen: now - Duration::from_secs(10),
            },
        );
        table.insert(
            (Ipv4Addr::new(192, 0, 2, 10), 40002),
            NatEntry {
                orig_dst_ip: Ipv4Addr::new(203, 0, 113, 51),
                orig_dst_port: 9443,
                if_idx: 7,
                sub_if_idx: 0,
                owner_pid: 2002,
                process_name: "xray.exe".to_string(),
                detected_by: "open_core_name".to_string(),
                last_seen: now - Duration::from_secs(5),
            },
        );
        // Third entry evicts oldest (40001).
        table.insert(
            (Ipv4Addr::new(192, 0, 2, 10), 40003),
            NatEntry {
                orig_dst_ip: Ipv4Addr::new(203, 0, 113, 52),
                orig_dst_port: 2053,
                if_idx: 7,
                sub_if_idx: 0,
                owner_pid: 2003,
                process_name: "ssh.exe".to_string(),
                detected_by: "manual".to_string(),
                last_seen: now,
            },
        );
        assert_eq!(table.len(), 2);
        assert!(table.get_and_touch(&(Ipv4Addr::new(192, 0, 2, 10), 40001)).is_none());
        assert!(table.get_and_touch(&(Ipv4Addr::new(192, 0, 2, 10), 40003)).is_some());

        // Build minimal 40-byte IPv4 + TCP SYN packet and test parse + dst/src rewrite.
        let mut pkt = [0u8; 40];
        pkt[0] = 0x45; // IPv4, IHL=5
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&[192, 0, 2, 10]);
        pkt[16..20].copy_from_slice(&[203, 0, 113, 88]);
        pkt[20..22].copy_from_slice(&50000u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&8443u16.to_be_bytes());
        pkt[33] = Ipv4TcpMeta::FLAG_SYN;

        let meta = parse_ipv4_tcp_packet(&pkt).expect("parse ipv4 tcp");
        assert!(meta.is_syn_only());
        assert_eq!(meta.src_ip, Ipv4Addr::new(192, 0, 2, 10));
        assert_eq!(meta.dst_ip, Ipv4Addr::new(203, 0, 113, 88));
        assert_eq!(meta.src_port, 50000);
        assert_eq!(meta.dst_port, 8443);

        assert!(rewrite_ipv4_tcp_dst(
            &mut pkt,
            meta.ihl_bytes,
            Ipv4Addr::new(192, 0, 2, 10),
            61000
        ));
        let rewritten = parse_ipv4_tcp_packet(&pkt).unwrap();
        assert_eq!(rewritten.dst_ip, Ipv4Addr::new(192, 0, 2, 10));
        assert_eq!(rewritten.dst_port, 61000);

        assert!(rewrite_ipv4_tcp_src(
            &mut pkt,
            meta.ihl_bytes,
            Ipv4Addr::new(203, 0, 113, 88),
            8443
        ));
        let restored = parse_ipv4_tcp_packet(&pkt).unwrap();
        assert_eq!(restored.src_ip, Ipv4Addr::new(203, 0, 113, 88));
        assert_eq!(restored.src_port, 8443);

        // Physical NIC descriptor filter
        assert!(is_physical_nic_descriptor(6, 5, "Realtek PCIe GbE Family Controller"));
        assert!(is_physical_nic_descriptor(71, 5, "Intel(R) Wi-Fi 6E AX211 160MHz"));
        assert!(!is_physical_nic_descriptor(53, 5, "Wintun Userspace Tunnel"));
        assert!(!is_physical_nic_descriptor(6, 5, "Hyper-V Virtual Ethernet Adapter"));
        assert!(!is_physical_nic_descriptor(6, 5, "Meta Wintun Tunnel"));
        assert!(!is_physical_nic_descriptor(24, 5, "Software Loopback Interface 1"));

        // Process interception scope & anti-loop exclusions
        let targets: HashSet<String> = ["ssh.exe", "custom-tool.exe"]
            .into_iter()
            .map(String::from)
            .collect();
        let excluded: HashSet<u32> = [1001, 1002].into_iter().collect();

        assert!(should_intercept_process(
            2000,
            Some(r"C:\Tools\ProxyCore\mihomo.exe"),
            GlobalPreAccelScope::ProxyAppsOnly,
            &targets,
            &excluded
        ));
        assert!(should_intercept_process(
            2005,
            Some(r"C:\Tools\OpenCore\custom-xray-runner.exe"),
            GlobalPreAccelScope::ProxyAppsOnly,
            &targets,
            &excluded
        ));
        assert!(should_intercept_process(
            2006,
            Some("ssh.exe"),
            GlobalPreAccelScope::ProxyAppsOnly,
            &targets,
            &excluded
        ));
        assert!(!should_intercept_process(
            1002,
            Some("mihomo.exe"),
            GlobalPreAccelScope::AllNon443Tcp,
            &targets,
            &excluded
        ));
        assert!(!should_intercept_process(
            3000,
            Some("svchost.exe"),
            GlobalPreAccelScope::AllNon443Tcp,
            &targets,
            &excluded
        ));
        assert!(!should_intercept_process(
            3002,
            Some("catcloud-probe-core.exe"),
            GlobalPreAccelScope::AllNon443Tcp,
            &targets,
            &excluded
        ));
        assert!(!should_intercept_process(
            3001,
            Some("chrome.exe"),
            GlobalPreAccelScope::ProxyAppsOnly,
            &targets,
            &excluded
        ));
        assert!(should_intercept_process(
            3001,
            Some("chrome.exe"),
            GlobalPreAccelScope::AllNon443Tcp,
            &targets,
            &excluded
        ));
    }

    #[tokio::test]
    async fn forward_redirected_stream_drops_unregistered_peers_and_relays_socks5_with_metrics() {
        // 1. Spawn mock SOCKS5 server expecting NOAUTH + CONNECT 203.0.113.77:8443 then echoing payload.
        let mock_socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = mock_socks.local_addr().unwrap().port();

        let socks_task = tokio::spawn(async move {
            let (mut sock, _) = mock_socks.accept().await.unwrap();
            let mut greet = [0u8; 3];
            sock.read_exact(&mut greet).await.unwrap();
            assert_eq!(greet, [0x05, 0x01, 0x00]);
            sock.write_all(&[0x05, 0x00]).await.unwrap();

            let mut req = [0u8; 10];
            sock.read_exact(&mut req).await.unwrap();
            assert_eq!(req[0..4], [0x05, 0x01, 0x00, 0x01]);
            assert_eq!(req[4..8], [203, 0, 113, 77]);
            assert_eq!(u16::from_be_bytes([req[8], req[9]]), 8443);
            sock.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();

            let mut data = [0u8; 5];
            sock.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"hello");
            sock.write_all(b"world!").await.unwrap();
            let _ = sock.shutdown().await;
        });

        // 2. Spawn local redirector listener backed by NatTable + GlobalPreAccelMetrics.
        let redir_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let redir_addr = redir_listener.local_addr().unwrap();
        let nat_table = Arc::new(NatTable::new(64, Duration::from_secs(60)));
        let metrics = Arc::new(GlobalPreAccelMetrics::default());
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let nat_clone = Arc::clone(&nat_table);
        let metrics_clone = Arc::clone(&metrics);
        let accept_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, peer) = redir_listener.accept().await.unwrap();
                let n = Arc::clone(&nat_clone);
                let m = Arc::clone(&metrics_clone);
                let rx = shutdown_rx.clone();
                tokio::spawn(async move {
                    forward_redirected_stream(stream, peer, socks_port, n, m, rx).await;
                });
            }
        });

        // Unregistered client must be dropped immediately without touching SOCKS5 or metrics.
        let mut rogue = TcpStream::connect(redir_addr).await.unwrap();
        let mut rogue_buf = [0u8; 8];
        let n_rogue = rogue.read(&mut rogue_buf).await.unwrap();
        assert_eq!(n_rogue, 0);
        assert_eq!(metrics.total_connections.load(Ordering::Relaxed), 0);

        // Registered client connects via pre-bound local port so NatTable key matches exact peer.
        let client_sock = tokio::net::TcpSocket::new_v4().unwrap();
        client_sock
            .bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
            .unwrap();
        let local_ep = match client_sock.local_addr().unwrap() {
            SocketAddr::V4(v4) => (*v4.ip(), v4.port()),
            _ => unreachable!(),
        };
        nat_table.insert(
            local_ep,
            NatEntry {
                orig_dst_ip: Ipv4Addr::new(203, 0, 113, 77),
                orig_dst_port: 8443,
                if_idx: 1,
                sub_if_idx: 0,
                owner_pid: 4242,
                process_name: "sing-box.exe".to_string(),
                detected_by: "system_proxy_host".to_string(),
                last_seen: Instant::now(),
            },
        );

        let mut client = client_sock.connect(redir_addr).await.unwrap();
        client.write_all(b"hello").await.unwrap();
        let mut reply = [0u8; 6];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"world!");
        drop(client);

        let _ = socks_task.await;
        let _ = accept_task.await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = shutdown_tx.send(true);

        assert_eq!(metrics.total_connections.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 0);
        assert!(nat_table.is_empty());
        assert!(metrics.up_bytes.load(Ordering::Relaxed) >= 5);
        assert!(metrics.down_bytes.load(Ordering::Relaxed) >= 6);
        assert_eq!(
            metrics.recent_processes_snapshot(),
            vec!["sing-box.exe".to_string()]
        );

        let proc_stats = metrics.snapshot();
        assert_eq!(proc_stats.len(), 1);
        assert_eq!(proc_stats[0].process_name, "sing-box.exe");
        assert_eq!(proc_stats[0].pid, 4242);
        assert_eq!(proc_stats[0].detected_by, "system_proxy_host");
        assert_eq!(proc_stats[0].active_connections, 0);
        assert_eq!(proc_stats[0].total_connections, 1);
        assert!(proc_stats[0].tx_bytes >= 5);
        assert!(proc_stats[0].rx_bytes >= 6);
        assert!(proc_stats[0].last_seen_ms > 0);
    }

    #[test]
    fn nat_table_remove_and_remove_if_matching_guard_port_reuse() {
        let table = NatTable::new(16, Duration::from_secs(60));
        let now = Instant::now();
        let key_a = (Ipv4Addr::new(192, 0, 2, 10), 41000);
        let key_b = (Ipv4Addr::new(192, 0, 2, 10), 41001);

        table.insert(
            key_a,
            NatEntry {
                orig_dst_ip: Ipv4Addr::new(203, 0, 113, 10),
                orig_dst_port: 8443,
                if_idx: 3,
                sub_if_idx: 0,
                owner_pid: 5100,
                process_name: "app-a.exe".to_string(),
                detected_by: "manual".to_string(),
                last_seen: now,
            },
        );
        table.insert(
            key_b,
            NatEntry {
                orig_dst_ip: Ipv4Addr::new(203, 0, 113, 20),
                orig_dst_port: 2053,
                if_idx: 3,
                sub_if_idx: 0,
                owner_pid: 5101,
                process_name: "app-b.exe".to_string(),
                detected_by: "local_proxy_listener".to_string(),
                last_seen: now,
            },
        );

        // Mismatched destination IP or port must leave the newer mapping intact.
        assert!(!table.remove_if_matching(&key_a, Ipv4Addr::new(203, 0, 113, 99), 8443));
        assert!(!table.remove_if_matching(&key_a, Ipv4Addr::new(203, 0, 113, 10), 9443));
        assert!(table.get_and_touch(&key_a).is_some());

        // Exact destination match removes the entry cleanly.
        assert!(table.remove_if_matching(&key_a, Ipv4Addr::new(203, 0, 113, 10), 8443));
        assert!(table.get_and_touch(&key_a).is_none());
        assert!(!table.remove_if_matching(&key_a, Ipv4Addr::new(203, 0, 113, 10), 8443));

        // Direct `remove` returns the evicted entry once, then `None`.
        let removed = table.remove(&key_b).expect("remove existing key_b");
        assert_eq!(removed.orig_dst_ip, Ipv4Addr::new(203, 0, 113, 20));
        assert_eq!(removed.orig_dst_port, 2053);
        assert!(table.remove(&key_b).is_none());
        assert!(table.is_empty());
    }

    #[test]
    fn should_intercept_process_conservatively_bypasses_unknown_process_names() {
        let targets: HashSet<String> = ["mihomo.exe"].into_iter().map(String::from).collect();
        let excluded: HashSet<u32> = HashSet::new();

        assert!(!should_intercept_process(
            4001,
            None,
            GlobalPreAccelScope::AllNon443Tcp,
            &targets,
            &excluded
        ));
        assert!(!should_intercept_process(
            4001,
            None,
            GlobalPreAccelScope::ProxyAppsOnly,
            &targets,
            &excluded
        ));
        assert!(!should_intercept_process(
            4002,
            Some("   "),
            GlobalPreAccelScope::AllNon443Tcp,
            &targets,
            &excluded
        ));
    }

    #[test]
    fn sync_main_core_pid_dynamically_updates_and_preserves_self_and_tunnel() {
        let self_pid = std::process::id();
        let tunnel_pid = self_pid.wrapping_add(10_001).max(100);
        let static_pid = self_pid.wrapping_add(10_002).max(101);
        let main_pid_v1 = self_pid.wrapping_add(20_001).max(200);
        let main_pid_v2 = self_pid.wrapping_add(20_002).max(201);

        let tracker = ExcludedPidTracker::new(self_pid, Some(tunnel_pid), [static_pid], None);
        let shared = tracker.shared_set();

        {
            let guard = shared.read().unwrap();
            assert!(guard.contains(&self_pid));
            assert!(guard.contains(&tunnel_pid));
            assert!(guard.contains(&static_pid));
            assert!(!guard.contains(&main_pid_v1));
        }

        // First sync adds external main core PID.
        tracker.sync_main_core_pid(Some(main_pid_v1));
        {
            let guard = shared.read().unwrap();
            assert!(guard.contains(&self_pid));
            assert!(guard.contains(&tunnel_pid));
            assert!(guard.contains(&static_pid));
            assert!(guard.contains(&main_pid_v1));
        }

        // Restarting main core replaces only the main core slot, evicting old PID.
        tracker.sync_main_core_pid(Some(main_pid_v2));
        {
            let guard = shared.read().unwrap();
            assert!(guard.contains(&self_pid));
            assert!(guard.contains(&tunnel_pid));
            assert!(guard.contains(&static_pid));
            assert!(!guard.contains(&main_pid_v1));
            assert!(guard.contains(&main_pid_v2));
        }

        // Setting slot to a pinned PID and clearing must never drop self or tunnel PIDs.
        tracker.sync_main_core_pid(Some(tunnel_pid));
        tracker.sync_main_core_pid(None);
        {
            let guard = shared.read().unwrap();
            assert!(guard.contains(&self_pid));
            assert!(guard.contains(&tunnel_pid));
            assert!(guard.contains(&static_pid));
            assert!(!guard.contains(&main_pid_v2));
        }

        // Verify `GlobalPreAccelManager::sync_main_core_pid` tracks live slot updates cleanly.
        let root = std::env::temp_dir().join(format!(
            "catcloud-sync-pid-{}",
            uuid::Uuid::new_v4()
        ));
        let paths = AppPaths::from_data_dir(root.join("data"), true).unwrap();
        let job_guard = Arc::new(JobGuard::new().unwrap());
        let manager = GlobalPreAccelManager::new(paths, job_guard);

        manager.sync_main_core_pid(Some(main_pid_v1));
        assert_eq!(*manager.synced_main_core_pid.lock().unwrap(), Some(main_pid_v1));
        manager.sync_main_core_pid(Some(0));
        assert_eq!(*manager.synced_main_core_pid.lock().unwrap(), None);
        manager.sync_main_core_pid(Some(main_pid_v2));
        assert_eq!(*manager.synced_main_core_pid.lock().unwrap(), Some(main_pid_v2));
        manager.sync_main_core_pid(None);
        assert_eq!(*manager.synced_main_core_pid.lock().unwrap(), None);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn forward_redirected_stream_exits_promptly_on_shutdown_during_socks5_handshake() {
        // Stalled mock SOCKS5 server that accepts the TCP connection, signals readiness, and never replies.
        let stalled_socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = stalled_socks.local_addr().unwrap().port();
        let (connected_tx, connected_rx) = tokio::sync::oneshot::channel::<()>();
        let socks_hold = tokio::spawn(async move {
            let (_conn, _) = stalled_socks.accept().await.unwrap();
            let _ = connected_tx.send(());
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let redir_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let redir_addr = redir_listener.local_addr().unwrap();
        let nat_table = Arc::new(NatTable::new(16, Duration::from_secs(60)));
        let metrics = Arc::new(GlobalPreAccelMetrics::default());
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let client_sock = tokio::net::TcpSocket::new_v4().unwrap();
        client_sock
            .bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
            .unwrap();
        let local_ep = match client_sock.local_addr().unwrap() {
            SocketAddr::V4(v4) => (*v4.ip(), v4.port()),
            _ => unreachable!(),
        };
        nat_table.insert(
            local_ep,
            NatEntry {
                orig_dst_ip: Ipv4Addr::new(203, 0, 113, 88),
                orig_dst_port: 8443,
                if_idx: 1,
                sub_if_idx: 0,
                owner_pid: 6001,
                process_name: "stalled.exe".to_string(),
                detected_by: "manual".to_string(),
                last_seen: Instant::now(),
            },
        );

        let nat_ref = Arc::clone(&nat_table);
        let metrics_ref = Arc::clone(&metrics);
        let fwd_task = tokio::spawn(async move {
            let (stream, peer) = redir_listener.accept().await.unwrap();
            forward_redirected_stream(stream, peer, socks_port, nat_ref, metrics_ref, shutdown_rx)
                .await;
        });

        let _client = client_sock.connect(redir_addr).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), connected_rx)
            .await
            .expect("upstream SOCKS5 socket should connect promptly")
            .expect("connected signal ok");
        let _ = shutdown_tx.send(true);

        tokio::time::timeout(Duration::from_secs(2), fwd_task)
            .await
            .expect("forward_redirected_stream must exit promptly on shutdown")
            .expect("forward task join ok");

        socks_hold.abort();
        assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 0);
        assert!(nat_table.is_empty());
    }

    #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
    #[tokio::test]
    async fn windows_arm64_windivert_guards_return_none_and_validation_error() {
        let root = std::env::temp_dir().join(format!(
            "catcloud-wd-arm64-{}",
            uuid::Uuid::new_v4()
        ));
        let paths = AppPaths::from_data_dir(root.join("data"), true).unwrap();
        std::fs::write(paths.bin_dir.join("WinDivert64.dll"), b"x64-dll").unwrap();
        std::fs::write(paths.bin_dir.join("WinDivert64.sys"), b"x64-sys").unwrap();

        assert!(locate_windivert_files(&paths, None).is_none());
        assert!(locate_windivert_files_with_exe_dir(&paths, None, None).is_none());

        let err = download_and_install_windivert(&paths, None)
            .await
            .expect_err("ARM64 must reject WinDivert download");
        match err {
            CatError::Validation(msg) => {
                assert!(msg.contains("Windows ARM64"));
                assert!(msg.contains("本地独立 443 通道"));
            }
            other => panic!("expected CatError::Validation, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn classify_intercept_process_respects_exclusions_dynamic_hosts_open_stems_and_manual() {
        let targets: HashSet<String> = ["ssh.exe", "custom-sync.exe"]
            .into_iter()
            .map(String::from)
            .collect();
        let excluded: HashSet<u32> = [1001, 1002, 2001].into_iter().collect();
        let mut detected: HashMap<u32, &'static str> = HashMap::new();
        detected.insert(2001, "system_proxy_host"); // must still be blocked by `excluded`
        detected.insert(2002, "system_proxy_host");
        detected.insert(2003, "local_proxy_listener");

        // 1. Excluded PIDs and system/self binaries ALWAYS win over dynamic detection or scope.
        assert_eq!(
            classify_intercept_process(
                2001,
                Some("mihomo.exe"),
                GlobalPreAccelScope::AllNon443Tcp,
                &targets,
                &excluded,
                &detected,
            ),
            None
        );
        assert_eq!(
            classify_intercept_process(
                2002,
                Some("catcloud.exe"),
                GlobalPreAccelScope::AllNon443Tcp,
                &targets,
                &excluded,
                &detected,
            ),
            None
        );
        assert_eq!(
            classify_intercept_process(
                2002,
                Some("catcloud-helper.exe"),
                GlobalPreAccelScope::AllNon443Tcp,
                &targets,
                &excluded,
                &detected,
            ),
            None
        );
        assert_eq!(
            classify_intercept_process(
                2002,
                Some("svchost.exe"),
                GlobalPreAccelScope::AllNon443Tcp,
                &targets,
                &excluded,
                &detected,
            ),
            None
        );

        // 2. Dynamic runtime detections classify arbitrary executable names without hardcoded lists.
        assert_eq!(
            classify_intercept_process(
                2002,
                Some("third-party-proxy-engine.exe"),
                GlobalPreAccelScope::ProxyAppsOnly,
                &targets,
                &excluded,
                &detected,
            ),
            Some("system_proxy_host")
        );
        assert_eq!(
            classify_intercept_process(
                2003,
                Some("proxy-daemon.exe"),
                GlobalPreAccelScope::ProxyAppsOnly,
                &targets,
                &excluded,
                &detected,
            ),
            Some("local_proxy_listener")
        );

        // 3. Generic open-source core stems match even when not explicitly listed in `targets`.
        assert_eq!(
            classify_intercept_process(
                3001,
                Some(r"D:\Tools\sing-box-core.exe"),
                GlobalPreAccelScope::ProxyAppsOnly,
                &targets,
                &excluded,
                &detected,
            ),
            Some("open_core_name")
        );
        assert_eq!(
            classify_intercept_process(
                3002,
                Some("tun2socks-win64.exe"),
                GlobalPreAccelScope::ProxyAppsOnly,
                &targets,
                &excluded,
                &detected,
            ),
            Some("open_core_name")
        );

        // 4. Explicit manual target names match as `"manual"`.
        assert_eq!(
            classify_intercept_process(
                3003,
                Some("custom-sync.exe"),
                GlobalPreAccelScope::ProxyAppsOnly,
                &targets,
                &excluded,
                &detected,
            ),
            Some("manual")
        );

        // 5. Unrelated apps bypass in `ProxyAppsOnly`, match `"scope_all"` in `AllNon443Tcp`.
        assert_eq!(
            classify_intercept_process(
                3004,
                Some("browser.exe"),
                GlobalPreAccelScope::ProxyAppsOnly,
                &targets,
                &excluded,
                &detected,
            ),
            None
        );
        assert_eq!(
            classify_intercept_process(
                3004,
                Some("browser.exe"),
                GlobalPreAccelScope::AllNon443Tcp,
                &targets,
                &excluded,
                &detected,
            ),
            Some("scope_all")
        );
    }

    #[test]
    fn metrics_process_stats_aggregates_sorts_and_evicts_bounded_capacity() {
        let metrics = GlobalPreAccelMetrics::default();

        // Process A: 1 active connection, 100 bytes total.
        metrics.record_process_connection_open(100, "mihomo.exe", "system_proxy_host");
        metrics.record_process_bytes(100, "mihomo.exe", "system_proxy_host", 40, 60);

        // Process B: 2 active connections, 50 bytes total -> ranks first by active_connections.
        metrics.record_process_connection_open(200, "xray.exe", "local_proxy_listener");
        metrics.record_process_connection_open(200, "xray.exe", "local_proxy_listener");
        metrics.record_process_bytes(200, "xray.exe", "local_proxy_listener", 20, 30);

        // Process C: 0 active connections, 5000 bytes total -> ranks behind active processes.
        metrics.record_process_connection_open(300, "ssh.exe", "manual");
        metrics.record_process_bytes(300, "ssh.exe", "manual", 2000, 3000);
        metrics.record_process_connection_close(300, "ssh.exe", "manual");

        let snap = metrics.snapshot();
        assert_eq!(snap.len(), 3);
        assert_eq!(snap[0].process_name, "xray.exe");
        assert_eq!(snap[0].active_connections, 2);
        assert_eq!(snap[0].total_connections, 2);
        assert_eq!(snap[1].process_name, "mihomo.exe");
        assert_eq!(snap[1].active_connections, 1);
        assert_eq!(snap[2].process_name, "ssh.exe");
        assert_eq!(snap[2].active_connections, 0);
        assert_eq!(snap[2].tx_bytes, 2000);
        assert_eq!(snap[2].rx_bytes, 3000);

        // Clearing active connections zeroes active gauges while preserving historical bytes.
        metrics.clear_active_connections();
        let after_clear = metrics.snapshot();
        assert!(after_clear.iter().all(|s| s.active_connections == 0));
        // With all active == 0, highest total bytes (`ssh.exe`, 5000 B) moves to rank 0.
        assert_eq!(after_clear[0].process_name, "ssh.exe");

        // Bounded capacity test: insert > MAX_PROCESS_STATS idle processes and assert hard cap.
        for idx in 0..(MAX_PROCESS_STATS as u32 + 12) {
            let pid = 10_000 + idx;
            let name = format!("worker-{idx}.exe");
            metrics.record_process_connection_open(pid, &name, "open_core_name");
            metrics.record_process_connection_close(pid, &name, "open_core_name");
        }
        assert!(metrics.snapshot().len() <= MAX_PROCESS_STATS);

        metrics.reset();
        assert!(metrics.snapshot().is_empty());
    }

    #[test]
    fn global_preaccel_status_backcompat_serde_and_install_state_transitions() {
        // Legacy JSON missing new Stage 12 fields must deserialize cleanly with safe defaults.
        let legacy_json = r#"{
            "running": true,
            "mode": "local_socks5",
            "socks_port": 17908,
            "windivert_available": false,
            "windivert_path": null,
            "is_elevated": false,
            "active_connections": 0,
            "total_connections": 0,
            "up_bytes": 0,
            "down_bytes": 0,
            "accelerated_processes": [],
            "active_relays": ["Relay-A"],
            "last_error": null
        }"#;
        let parsed: GlobalPreAccelStatus =
            serde_json::from_str(legacy_json).expect("deserialize legacy GlobalPreAccelStatus");
        assert!(!parsed.is_windivert_active);
        assert_eq!(parsed.install_state, "idle");
        assert!(parsed.process_stats.is_empty());

        // Manager install state normalization and reporting.
        let root = std::env::temp_dir().join(format!(
            "catcloud-install-state-{}",
            uuid::Uuid::new_v4()
        ));
        let paths = AppPaths::from_data_dir(root.join("data"), true).unwrap();
        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        let bin_dir = paths.bin_dir.clone();
        let job_guard = Arc::new(JobGuard::new().unwrap());
        let manager = GlobalPreAccelManager::new(paths, job_guard);

        manager.set_install_state("downloading");
        assert_eq!(manager.status().install_state, "downloading");
        assert!(!manager.status().is_windivert_active);

        manager.set_install_state("VERIFYING");
        assert_eq!(manager.status().install_state, "verifying");

        manager.set_install_state("need_elevation");
        assert_eq!(manager.install_state(), "need_elevation");
        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        {
            let st_missing = manager.status();
            if !st_missing.windivert_available {
                assert_eq!(st_missing.install_state, "idle");
            }
            let dll_path = bin_dir.join("WinDivert64.dll");
            let sys_path = bin_dir.join("WinDivert64.sys");
            std::fs::write(&dll_path, b"stub-dll").unwrap();
            std::fs::write(&sys_path, b"stub-sys").unwrap();
            let st_present = manager.status();
            assert!(st_present.windivert_available);
            assert_eq!(
                st_present.install_state,
                if st_present.is_elevated {
                    "ready"
                } else {
                    "need_elevation"
                }
            );
            manager.set_install_state("ready");
            let _ = std::fs::remove_file(&dll_path);
            let _ = std::fs::remove_file(&sys_path);
            let st_removed = manager.status();
            if !st_removed.windivert_available {
                assert_eq!(st_removed.install_state, "idle");
            }
        }
        #[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
        assert_eq!(manager.status().install_state, "need_elevation");

        manager.set_install_state("failed");
        assert_eq!(manager.status().install_state, "failed");

        manager.set_install_state("unknown-bogus");
        assert_eq!(manager.install_state(), "idle");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn windivert_proxy_candidates_dedup_and_system_proxy_url_formatting() {
        assert_eq!(normalize_windivert_proxy_candidates(&[]), vec![None]);

        let raw = vec![
            Some(" http://127.0.0.1:7890/ ".to_string()),
            Some("HTTP://127.0.0.1:7890".to_string()),
            Some("http://127.0.0.1:7897".to_string()),
            None,
            Some("   ".to_string()),
            None,
        ];
        assert_eq!(
            normalize_windivert_proxy_candidates(&raw),
            vec![
                Some("http://127.0.0.1:7890/".to_string()),
                Some("http://127.0.0.1:7897".to_string()),
                None,
            ]
        );

        let enabled_v4 = crate::platform::SystemProxySpec {
            enabled: true,
            host: "127.0.0.1".to_string(),
            port: 10809,
            bypass: Vec::new(),
            pac_url: None,
        };
        assert_eq!(
            format_system_proxy_url(&enabled_v4).as_deref(),
            Some("http://127.0.0.1:10809")
        );

        let enabled_v6 = crate::platform::SystemProxySpec {
            enabled: true,
            host: "::1".to_string(),
            port: 10809,
            bypass: Vec::new(),
            pac_url: None,
        };
        assert_eq!(
            format_system_proxy_url(&enabled_v6).as_deref(),
            Some("http://[::1]:10809")
        );

        let pac_only = crate::platform::SystemProxySpec {
            enabled: true,
            host: "127.0.0.1".to_string(),
            port: 7890,
            bypass: Vec::new(),
            pac_url: Some("http://127.0.0.1:17891/proxy.pac".to_string()),
        };
        assert_eq!(format_system_proxy_url(&pac_only), None);

        let disabled = crate::platform::SystemProxySpec {
            enabled: false,
            host: "127.0.0.1".to_string(),
            port: 7890,
            bypass: Vec::new(),
            pac_url: None,
        };
        assert_eq!(format_system_proxy_url(&disabled), None);
    }

    #[test]
    fn excluded_pid_tracker_merges_descendant_tree_and_main_core_without_clobbering() {
        let self_pid = std::process::id();
        let tunnel_pid = self_pid.wrapping_add(11_001).max(100);
        let main_pid = self_pid.wrapping_add(22_001).max(200);
        let webview_pid = self_pid.wrapping_add(33_001).max(300);
        let probe_pid = self_pid.wrapping_add(33_002).max(301);

        let tracker = ExcludedPidTracker::new(self_pid, Some(tunnel_pid), [], Some(main_pid));
        tracker.sync_descendant_pids([webview_pid, probe_pid, 0].into_iter().collect());

        let snap1 = tracker.snapshot_active();
        assert!(snap1.contains(&self_pid));
        assert!(snap1.contains(&tunnel_pid));
        assert!(snap1.contains(&main_pid));
        assert!(snap1.contains(&webview_pid));
        assert!(snap1.contains(&probe_pid));
        assert!(!snap1.contains(&0));

        // Clearing main_core_pid must keep descendant tree and pinned PIDs intact.
        tracker.sync_main_core_pid(None);
        let snap2 = tracker.snapshot_active();
        assert!(snap2.contains(&self_pid));
        assert!(snap2.contains(&tunnel_pid));
        assert!(snap2.contains(&webview_pid));
        assert!(snap2.contains(&probe_pid));
        assert!(!snap2.contains(&main_pid));

        // Refreshing descendant tree replaces stale descendants while retaining pinned PIDs.
        tracker.sync_descendant_pids([webview_pid].into_iter().collect());
        let snap3 = tracker.snapshot_active();
        assert!(snap3.contains(&self_pid));
        assert!(snap3.contains(&tunnel_pid));
        assert!(snap3.contains(&webview_pid));
        assert!(!snap3.contains(&probe_pid));
    }
}
