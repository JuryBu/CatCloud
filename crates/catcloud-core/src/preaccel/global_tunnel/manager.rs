#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
use super::driver_guard::WINDIVERT_ARM64_UNSUPPORTED_MSG;
#[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
use super::driver_guard::{build_security_guidance, locate_windivert_paths};
use super::driver_guard::{detect_host_security_products, locate_windivert_files};
#[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
use super::nat_packet::{collect_enabled_relay_ipv4s, now_epoch_ms};
use super::nat_packet::{
    AcceleratedProcessStat, GlobalPreAccelMetrics, normalize_process_basename,
};
use super::{
    GlobalPreAccelRuntimeMeta, remove_global_preaccel_runtime_meta,
    write_global_preaccel_runtime_meta,
};
use crate::core_adapter::resolve_mihomo_binary;
use crate::error::{CatError, CatResult};
use crate::models::{AppConfig, GlobalPreAccelScope, PreAccelConfig, PreAccelRelay};
use crate::paths::{AppPaths, normalize_os_path};
use crate::platform::default_platform;
use crate::preaccel::generator::{
    PREACCEL_SELECT_GROUP, build_preaccel_compile_plan, host_to_direct_rule,
};
use crate::preaccel::schema::sanitize_relay_for_domestic_443;
use crate::process_guard::JobGuard;
use serde::{Deserialize, Serialize};
use serde_yaml_ng::{Mapping, Number, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener as StdTcpListener};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use url::Url;

/// Maximum startup readiness wait for the standalone lightweight 443 Mihomo tunnel.
const STANDALONE_TUNNEL_READY_TIMEOUT: Duration = Duration::from_secs(6);

/// Polling interval while waiting for the standalone 443 tunnel SOCKS5 port.
const STANDALONE_TUNNEL_POLL_INTERVAL: Duration = Duration::from_millis(80);

/// Dedicated memory budget for the lightweight standalone 443 tunnel subprocess.
pub const STANDALONE_TUNNEL_GOMEMLIMIT: &str = "48MiB";

/// Dedicated GC target for the lightweight standalone 443 tunnel subprocess.
pub const STANDALONE_TUNNEL_GOGC: &str = "25";


// ============================================================================
// A. Standalone Lightweight Domestic :443 Dual-Active Tunnel (Cross-Platform)
// ============================================================================

/// Compile a minimal, zero-TUN, zero-DNS, zero-controller Mihomo YAML configuration for
/// the standalone domestic :443 active-standby pre-acceleration SOCKS5 tunnel.
///
/// Backward-compatible wrapper compiling without explicit `interface-name` binding.
pub fn compile_standalone_preaccel_yaml(
    cfg: &AppConfig,
    relays: &[PreAccelRelay],
    socks_port: u16,
) -> CatResult<String> {
    compile_standalone_preaccel_yaml_with_interface(cfg, relays, socks_port, None)
}

/// Compile the standalone domestic `:443` dual-active SOCKS5 tunnel YAML, optionally pinning
/// outbound sockets to a confirmed physical exit NIC (`interface-name`) so third-party VPN/TUN
/// adapters cannot hijack or loop CatCloud's domestic `:443` relay connections.
pub fn compile_standalone_preaccel_yaml_with_interface(
    cfg: &AppConfig,
    relays: &[PreAccelRelay],
    socks_port: u16,
    physical_interface: Option<&str>,
) -> CatResult<String> {
    if socks_port == 0 {
        return Err(CatError::Validation(
            "standalone pre-acceleration socks_port must be within 1..=65535".to_string(),
        ));
    }

    let mut sanitized_relays: Vec<PreAccelRelay> = relays
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
    sanitized_relays.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));

    if sanitized_relays.is_empty() {
        return Err(CatError::Validation(
            "没有已启用的国内 443 中转节点，无法编译独立国内提速隧道配置".to_string(),
        ));
    }

    // Force `enabled = true` on a cloned config so standalone pre-accel can run independently
    // even while CatCloud's primary proxy or dialer-proxy toggle is off.
    let mut standalone_preaccel: PreAccelConfig = cfg.preaccel.clone();
    standalone_preaccel.enabled = true;

    let plan = build_preaccel_compile_plan(&standalone_preaccel, &sanitized_relays, &[])?;
    if !plan.active || plan.relay_proxies.is_empty() {
        return Err(CatError::Validation(
            "独立 443 国内提速隧道未能生成有效中转节点配置".to_string(),
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
    if let Some(iface) = physical_interface.map(str::trim).filter(|s| !s.is_empty()) {
        root.insert(
            Value::String("interface-name".to_string()),
            Value::String(iface.to_string()),
        );
    }
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
        Value::Number(Number::from(45u64)),
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

    let mut rules: Vec<String> = Vec::with_capacity(sanitized_relays.len() + 12);
    let mut seen: HashSet<String> = HashSet::new();

    // Only emit anti-loop DIRECT rules for the enabled domestic relay endpoints themselves
    // (explicitly excluding `probe_url` / domestic 204 endpoints) so dataplane self-test
    // probes arriving over SOCKS5 must traverse the :443 relay group instead of bypassing via DIRECT.
    for relay in &sanitized_relays {
        if let Some(rule) = host_to_direct_rule(&relay.server) {
            let key = rule.to_ascii_lowercase();
            if seen.insert(key) {
                rules.push(rule);
            }
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
/// Enforces `GOMEMLIMIT=48MiB`, `GOGC=25`, `GODEBUG=madvdontneed=1`, `CREATE_NO_WINDOW` on
/// Windows, `JobGuard` registration, and deterministic termination on `stop()` and `Drop`.
#[derive(Debug)]
pub struct StandalonePreAccelTunnel {
    child: Option<Child>,
    pid: Option<u32>,
    process_start_time_unix: Option<u64>,
    binary_path: PathBuf,
    socks_port: u16,
    work_dir: PathBuf,
    config_path: PathBuf,
    config_sha256: String,
    active_relays: Vec<String>,
    bound_physical_interface: Option<String>,
    job_guard: Arc<JobGuard>,
}

impl StandalonePreAccelTunnel {
    /// Compile and launch an isolated standalone :443 pre-acceleration Mihomo subprocess.
    ///
    /// On Windows, automatically detects the primary active physical exit NIC (e.g. `WLAN` or
    /// `以太网`) and pins `interface-name` so third-party proxy TUN adapters cannot hijack
    /// CatCloud's domestic `:443` relay connections; if binding that interface fails on an
    /// unusual adapter setup, automatically retries once without `interface-name`.
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
                "未找到 Mihomo 内核二进制文件，无法启动独立 443 国内提速隧道".to_string(),
            )
        })?;

        #[cfg(target_os = "windows")]
        let detected_physical_if: Option<String> = tokio::task::spawn_blocking(|| {
            crate::preaccel::windivert_win::detect_primary_physical_interface().map(|i| i.friendly_name)
        })
        .await
        .ok()
        .flatten();
        #[cfg(not(target_os = "windows"))]
        let detected_physical_if: Option<String> = None;

        if let Some(ref iface) = detected_physical_if {
            match Self::start_with_interface(
                paths,
                &mihomo_bin,
                cfg,
                relays,
                Arc::clone(&job_guard),
                preferred_socks_port,
                Some(iface.as_str()),
            )
            .await
            {
                Ok(tunnel) => return Ok(tunnel),
                Err(err) => {
                    tracing::warn!(
                        "standalone 443 tunnel failed with interface-name `{iface}` ({err}); retrying without explicit interface binding"
                    );
                }
            }
        }

        Self::start_with_interface(
            paths,
            &mihomo_bin,
            cfg,
            relays,
            job_guard,
            preferred_socks_port,
            None,
        )
        .await
    }

    async fn start_with_interface(
        paths: &AppPaths,
        mihomo_bin: &Path,
        cfg: &AppConfig,
        relays: &[PreAccelRelay],
        job_guard: Arc<JobGuard>,
        preferred_socks_port: Option<u16>,
        physical_interface: Option<&str>,
    ) -> CatResult<Self> {
        let socks_port = allocate_loopback_tcp_port(preferred_socks_port, cfg)?;
        let yaml = compile_standalone_preaccel_yaml_with_interface(
            cfg,
            relays,
            socks_port,
            physical_interface,
        )?;
        let bound_physical_interface = physical_interface
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string);

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
        let config_sha256 = hex::encode(Sha256::digest(yaml.as_bytes()));
        AppPaths::atomic_write(&config_path, yaml.as_bytes())?;

        let stderr_path = work_dir.join("standalone-preaccel-stderr.log");
        let stderr_stdio = std::fs::File::create(&stderr_path)
            .map(Stdio::from)
            .unwrap_or_else(|_| Stdio::null());

        let norm_bin = normalize_os_path(mihomo_bin);
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
                "启动独立 443 国内提速隧道 Mihomo 进程失败 ({}): {e}",
                mihomo_bin.display()
            ))
        })?;

        if let Err(err) = job_guard.assign_tokio_child(&mut child) {
            let _ = child.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
            return Err(err);
        }

        let pid = child.id();
        let process_start_time_unix = pid
            .and_then(crate::platform::get_process_start_time_unix)
            .or_else(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .ok()
                    .map(|d| d.as_secs())
            });
        let deadline = Instant::now() + STANDALONE_TUNNEL_READY_TIMEOUT;
        let target_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, socks_port);

        while Instant::now() < deadline {
            if let Ok(Some(status)) = child.try_wait() {
                if let Some(p) = pid {
                    job_guard.unregister_pid(p);
                }
                let detail = read_stderr_tail(&stderr_path, 2048);
                let msg = if detail.is_empty() {
                    format!("独立 443 国内提速隧道启动失败并提前退出 ({status})")
                } else {
                    format!("独立 443 国内提速隧道启动失败并提前退出 ({status}): {detail}")
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
                    process_start_time_unix,
                    binary_path: norm_bin,
                    socks_port,
                    work_dir,
                    config_path,
                    config_sha256,
                    active_relays,
                    bound_physical_interface,
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
            format!("独立 443 国内提速隧道在超时前未能在 127.0.0.1:{socks_port} 就绪")
        } else {
            format!("独立 443 国内提速隧道未能在 127.0.0.1:{socks_port} 就绪: {detail}")
        };
        Err(CatError::Core(msg))
    }

    pub fn pid(&self) -> Option<u32> {
        self.pid
    }

    pub fn process_start_time_unix(&self) -> Option<u64> {
        self.process_start_time_unix
    }

    pub fn binary_path(&self) -> &Path {
        &self.binary_path
    }

    pub fn socks_port(&self) -> u16 {
        self.socks_port
    }

    pub fn active_relays(&self) -> &[String] {
        &self.active_relays
    }

    pub fn bound_physical_interface(&self) -> Option<&str> {
        self.bound_physical_interface.as_deref()
    }

    pub fn work_dir(&self) -> &Path {
        &self.work_dir
    }

    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub fn config_sha256(&self) -> &str {
        &self.config_sha256
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
        "无法为独立 443 国内提速隧道分配空闲本地回环 TCP 端口".to_string(),
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
// C. Unified Cross-Platform GlobalPreAccelManager & Status Snapshot
// ============================================================================

fn default_install_state() -> String {
    "idle".to_string()
}

fn default_verify_state() -> String {
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

fn normalize_verify_state(raw: &str) -> &'static str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "probing" => "probing",
        "verified" => "verified",
        "degraded" => "degraded",
        "failed" => "failed",
        _ => "idle",
    }
}

/// Live status snapshot of the standalone global domestic :443 pre-acceleration engine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GlobalPreAccelStatus {
    pub running: bool,
    /// Active engine mode: `"off"`, `"windivert"` (Windows transparent kernel NAT),
    /// `"local_socks5"` (cross-platform standalone 127.0.0.1 :443 dual-active SOCKS5 entry),
    /// or `"suspended_for_tun"` (standalone tunnel paused while main-core TUN carries preaccel).
    pub mode: String,
    /// Strictly `true` only when `running && mode == "windivert"`.
    #[serde(default)]
    pub is_windivert_active: bool,
    /// Driver installation / elevation lifecycle state:
    /// `"idle" | "downloading" | "verifying" | "ready" | "need_elevation" | "failed"`.
    #[serde(default = "default_install_state")]
    pub install_state: String,
    /// Live dataplane self-test verification state:
    /// `"idle" | "probing" | "verified" | "degraded" | "failed"`.
    #[serde(default = "default_verify_state")]
    pub verify_state: String,
    /// End-to-end latency (ms) measured during the last successful WinDivert dataplane self-test.
    #[serde(default)]
    pub verify_latency_ms: Option<u64>,
    /// Plain-Chinese summary of the last dataplane self-test outcome.
    #[serde(default)]
    pub verify_message: Option<String>,
    /// Unix epoch timestamp (ms) of the last completed dataplane self-test.
    #[serde(default)]
    pub verify_checked_at_ms: Option<u64>,
    /// Security / firewall products detected read-only on this host (e.g. Huorong, Defender, 360).
    #[serde(default)]
    pub detected_security_products: Vec<String>,
    /// Actionable Chinese guidance tailored to the host's security products when blocked/degraded.
    #[serde(default)]
    pub security_guidance: Option<String>,
    /// Physical exit NIC friendly name bound by the standalone `:443` tunnel (e.g. `"WLAN"`).
    #[serde(default)]
    pub bound_physical_interface: Option<String>,
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
            verify_state: default_verify_state(),
            verify_latency_ms: None,
            verify_message: None,
            verify_checked_at_ms: None,
            detected_security_products: Vec::new(),
            security_guidance: None,
            bound_physical_interface: None,
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

#[derive(Debug, Clone)]
struct VerifySnapshot {
    state: String,
    latency_ms: Option<u64>,
    message: Option<String>,
    checked_at_ms: Option<u64>,
    security_guidance: Option<String>,
}

impl Default for VerifySnapshot {
    fn default() -> Self {
        Self {
            state: default_verify_state(),
            latency_ms: None,
            message: None,
            checked_at_ms: None,
            security_guidance: None,
        }
    }
}

/// Normalized static configuration fingerprint of a running WinDivert engine, intentionally
/// excluding dynamically hot-synced `main_core_pid` so unrelated config reloads keep existing
/// intercepted flows alive without tearing down WinDivert.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub(super) struct WinDivertRuntimeFingerprint {
    dll_path: PathBuf,
    sys_path: Option<PathBuf>,
    relay_ipv4s: Vec<Ipv4Addr>,
    skip_443_native: bool,
    scope: GlobalPreAccelScope,
    target_processes: Vec<String>,
    static_excluded_pids: Vec<u32>,
}

#[allow(dead_code)]
impl WinDivertRuntimeFingerprint {
    pub(super) fn from_inputs(
        dll_path: PathBuf,
        sys_path: Option<PathBuf>,
        relay_ipv4s: &[Ipv4Addr],
        skip_443_native: bool,
        scope: GlobalPreAccelScope,
        target_processes: &[String],
        static_excluded_pids: &HashSet<u32>,
    ) -> Self {
        let mut sorted_relays: Vec<Ipv4Addr> = relay_ipv4s.to_vec();
        sorted_relays.sort_unstable();
        sorted_relays.dedup();

        let mut normalized_procs: Vec<String> = target_processes
            .iter()
            .map(|p| normalize_process_basename(p))
            .filter(|p| !p.is_empty())
            .collect();
        normalized_procs.sort();
        normalized_procs.dedup();

        let mut sorted_pids: Vec<u32> = static_excluded_pids.iter().copied().collect();
        sorted_pids.sort_unstable();
        sorted_pids.dedup();

        Self {
            dll_path,
            sys_path,
            relay_ipv4s: sorted_relays,
            skip_443_native,
            scope,
            target_processes: normalized_procs,
            static_excluded_pids: sorted_pids,
        }
    }
}

#[allow(dead_code)]
pub(super) fn should_skip_windivert_restart(
    tunnel_changed: bool,
    old_fp: Option<&WinDivertRuntimeFingerprint>,
    next_fp: Option<&WinDivertRuntimeFingerprint>,
) -> bool {
    !tunnel_changed && old_fp.is_some() && old_fp == next_fp
}

/// Strict HTTP 204 validator for WinDivert dataplane self-test results (rejects captive-portal
/// 200/302 responses, 4xx/5xx gateway errors, and empty/truncated non-HTTP replies).
#[allow(dead_code)]
pub(crate) fn validate_self_test_http_status(status_code: Option<u16>) -> Result<u16, String> {
    match status_code {
        Some(204) => Ok(204),
        Some(code) => Err(format!(
            "返回非预期 HTTP {code}（期望 HTTP 204，疑似被门户劫持或上游异常）"
        )),
        None => Err("返回空响应或非标准 HTTP 报文（期望 HTTP 204）".to_string()),
    }
}

#[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
pub(super) fn enforce_self_test_strict_204(
    outcome: crate::preaccel::windivert_win::WinDivertSelfTestOutcome,
) -> crate::preaccel::windivert_win::WinDivertSelfTestOutcome {
    match outcome {
        crate::preaccel::windivert_win::WinDivertSelfTestOutcome::Passed {
            latency_ms,
            probe_host,
            status_code,
        } => match validate_self_test_http_status(Some(status_code)) {
            Ok(code) => crate::preaccel::windivert_win::WinDivertSelfTestOutcome::Passed {
                latency_ms,
                probe_host,
                status_code: code,
            },
            Err(reason) => crate::preaccel::windivert_win::WinDivertSelfTestOutcome::TunnelUnreachable {
                detail: format!("{probe_host} {reason}"),
            },
        },
        other => other,
    }
}

#[derive(Debug)]
struct ActiveGlobalRuntime {
    #[cfg(target_os = "windows")]
    engine: Option<crate::preaccel::windivert_win::WinDivertEngine>,
    #[allow(dead_code)]
    windivert_fp: Option<WinDivertRuntimeFingerprint>,
    tunnel: StandalonePreAccelTunnel,
    mode: String,
    socks_port: u16,
    active_relays: Vec<String>,
    bound_physical_interface: Option<String>,
}

impl ActiveGlobalRuntime {
    async fn stop(mut self, teardown_service: bool) {
        // Stop WinDivert kernel interception BEFORE tearing down the standalone 443 tunnel so
        // native network flow resumes immediately with zero packet drops.
        #[cfg(target_os = "windows")]
        if let Some(mut engine) = self.engine.take() {
            let _ = tokio::task::spawn_blocking(move || {
                engine.stop_sync_with_teardown(teardown_service);
            })
            .await;
        }
        #[cfg(not(target_os = "windows"))]
        let _ = teardown_service;
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
    pub(super) metrics: Arc<GlobalPreAccelMetrics>,
    last_error: Mutex<Option<String>>,
    install_state: Mutex<String>,
    verify_snapshot: Mutex<VerifySnapshot>,
    detected_security_products: Mutex<Vec<String>>,
    custom_windivert_dir: Mutex<Option<String>>,
    pub(super) synced_main_core_pid: Mutex<Option<u32>>,
    suspended_for_tun_relays: Mutex<Option<Vec<String>>>,
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
            verify_snapshot: Mutex::new(VerifySnapshot::default()),
            detected_security_products: Mutex::new(Vec::new()),
            custom_windivert_dir: Mutex::new(None),
            synced_main_core_pid: Mutex::new(None),
            suspended_for_tun_relays: Mutex::new(None),
        }
    }

    fn persist_current_runtime_meta(&self) {
        let running_meta = {
            let guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
            guard.as_ref().map(|rt| {
                let effective_carrier = if rt.mode == "windivert" {
                    "standalone_windivert"
                } else {
                    "standalone_socks5"
                };
                GlobalPreAccelRuntimeMeta {
                    pid: rt.tunnel.pid(),
                    process_start_time_unix: rt.tunnel.process_start_time_unix(),
                    binary_path: Some(rt.tunnel.binary_path().to_string_lossy().to_string()),
                    running: true,
                    mode: rt.mode.clone(),
                    effective_carrier: effective_carrier.to_string(),
                    socks_port: Some(rt.socks_port),
                    active_relays: rt.active_relays.clone(),
                    updated_at: chrono::Utc::now().to_rfc3339(),
                }
            })
        };

        if let Some(meta) = running_meta {
            let _ = write_global_preaccel_runtime_meta(&self.paths.root_data_dir, &meta);
            return;
        }

        let suspended_relays = self
            .suspended_for_tun_relays
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(active_relays) = suspended_relays {
            let meta = GlobalPreAccelRuntimeMeta {
                pid: None,
                process_start_time_unix: None,
                binary_path: None,
                running: false,
                mode: "suspended_for_tun".to_string(),
                effective_carrier: "main_core_tun_suspended_standalone".to_string(),
                socks_port: None,
                active_relays,
                updated_at: chrono::Utc::now().to_rfc3339(),
            };
            let _ = write_global_preaccel_runtime_meta(&self.paths.root_data_dir, &meta);
        } else {
            remove_global_preaccel_runtime_meta(&self.paths.root_data_dir);
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

    fn set_verify_snapshot(&self, snapshot: VerifySnapshot) {
        if let Ok(mut guard) = self.verify_snapshot.lock() {
            *guard = VerifySnapshot {
                state: normalize_verify_state(&snapshot.state).to_string(),
                ..snapshot
            };
        }
    }

    fn reset_verify_snapshot(&self) {
        self.set_verify_snapshot(VerifySnapshot::default());
    }

    fn refresh_detected_security_products(&self) -> Vec<String> {
        let products = detect_host_security_products();
        if let Ok(mut guard) = self.detected_security_products.lock() {
            *guard = products.clone();
        }
        products
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
        self.start_locked(cfg, relays, extra_excluded_pids, &_op)
            .await
    }

    async fn start_locked(
        &self,
        cfg: &AppConfig,
        relays: &[PreAccelRelay],
        extra_excluded_pids: &[u32],
        _op_guard: &tokio::sync::MutexGuard<'_, ()>,
    ) -> CatResult<GlobalPreAccelStatus> {
        {
            let mut dir_guard = self
                .custom_windivert_dir
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *dir_guard = cfg.preaccel.windivert_dir.clone();
        }

        // Clear any prior TUN-suspension state before starting a live standalone tunnel.
        {
            let mut susp_guard = self
                .suspended_for_tun_relays
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *susp_guard = None;
        }

        // Cleanly stop any previous runtime before starting a fresh instance (hot rebuild:
        // keep the WinDivert kernel service loaded to avoid Win32 error 1072 races).
        let previous = {
            let mut rt_guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
            rt_guard.take()
        };
        if let Some(prev) = previous {
            prev.stop(false).await;
        }
        remove_global_preaccel_runtime_meta(&self.paths.root_data_dir);
        self.metrics.reset();
        self.set_last_error(None);
        self.reset_verify_snapshot();
        let detected_products = self.refresh_detected_security_products();

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
        let bound_physical_interface = tunnel.bound_physical_interface().map(ToString::to_string);
        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        let mut mode = "local_socks5".to_string();
        #[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
        let mode = "local_socks5".to_string();

        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        let mut win_engine: Option<crate::preaccel::windivert_win::WinDivertEngine> = None;
        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        let mut win_engine_fp: Option<WinDivertRuntimeFingerprint> = None;
        #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
        let win_engine: Option<crate::preaccel::windivert_win::WinDivertEngine> = None;

        #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
        {
            let _ = (extra_excluded_pids, detected_products);
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
            } else if let Some((dll_path, sys_path)) = wd_files {
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
                let wd_fp = WinDivertRuntimeFingerprint::from_inputs(
                    dll_path.clone(),
                    Some(sys_path),
                    &relay_ipv4s,
                    cfg.preaccel.skip_443_native,
                    cfg.preaccel.global_scope,
                    &cfg.preaccel.global_target_processes,
                    &static_excluded_pids,
                );
                let bin_dir = dll_path.parent().map(Path::to_path_buf);
                let engine_cfg = crate::preaccel::windivert_win::WinDivertEngineConfig {
                    dll_path,
                    socks_port,
                    relay_ipv4s,
                    skip_443_native: cfg.preaccel.skip_443_native,
                    scope: cfg.preaccel.global_scope,
                    target_processes: cfg.preaccel.global_target_processes.clone(),
                    excluded_pids: static_excluded_pids,
                    tunnel_pid: tunnel.pid(),
                    main_core_pid: synced_main_pid,
                    metrics: Arc::clone(&self.metrics),
                };

                match crate::preaccel::windivert_win::WinDivertEngine::start(engine_cfg).await {
                    Ok(mut engine) => {
                        self.set_verify_snapshot(VerifySnapshot {
                            state: "probing".to_string(),
                            latency_ms: None,
                            message: Some("正在自动探测底层透明加速链路…".to_string()),
                            checked_at_ms: None,
                            security_guidance: None,
                        });
                        let probe_urls = build_self_test_probe_urls(&cfg.preaccel.probe_url);
                        let probe_refs: Vec<&str> = probe_urls.iter().map(String::as_str).collect();
                        let outcome = enforce_self_test_strict_204(
                            engine
                                .run_self_test(&probe_refs, Duration::from_secs(4))
                                .await,
                        );
                        match outcome {
                            crate::preaccel::windivert_win::WinDivertSelfTestOutcome::Passed {
                                latency_ms,
                                probe_host,
                                status_code,
                            } => {
                                win_engine = Some(engine);
                                win_engine_fp = Some(wd_fp);
                                mode = "windivert".to_string();
                                self.set_install_state("ready");
                                self.set_last_error(None);
                                self.set_verify_snapshot(VerifySnapshot {
                                    state: "verified".to_string(),
                                    latency_ms: Some(latency_ms),
                                    message: Some(format!(
                                        "自动探测畅通：经由底层透明拦截与国内 443 中转连通 {probe_host}（HTTP {status_code}，{latency_ms} ms）"
                                    )),
                                    checked_at_ms: Some(now_epoch_ms()),
                                    security_guidance: None,
                                });
                            }
                            other => {
                                // Fail-safe circuit breaker: immediately tear down WinDivert
                                // interception and stop its kernel service so broken packet
                                // injection never blackholes the host.
                                let _ = tokio::task::spawn_blocking(move || {
                                    engine.stop_sync_with_teardown(true);
                                })
                                .await;
                                let (msg, guidance) = classify_self_test_failure(
                                    &other,
                                    &detected_products,
                                    bin_dir.as_deref(),
                                );
                                self.set_install_state("ready");
                                self.set_last_error(Some(msg.clone()));
                                self.set_verify_snapshot(VerifySnapshot {
                                    state: "degraded".to_string(),
                                    latency_ms: None,
                                    message: Some(msg),
                                    checked_at_ms: Some(now_epoch_ms()),
                                    security_guidance: guidance,
                                });
                            }
                        }
                    }
                    Err(err) => {
                        let guidance = build_security_guidance(
                            &detected_products,
                            bin_dir.as_deref(),
                            "driver_load",
                        );
                        self.set_install_state("failed");
                        self.set_last_error(Some(format!(
                            "WinDivert 透明内核引擎启动失败，已降级为本地独立 443 SOCKS5 隧道（{err}）"
                        )));
                        self.set_verify_snapshot(VerifySnapshot {
                            state: "failed".to_string(),
                            latency_ms: None,
                            message: Some(err.to_string()),
                            checked_at_ms: Some(now_epoch_ms()),
                            security_guidance: Some(guidance),
                        });
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
            let _ = (extra_excluded_pids, detected_products);
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
                windivert_fp: win_engine_fp,
                tunnel,
                mode,
                socks_port,
                active_relays,
                bound_physical_interface,
            });
        }

        #[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
        {
            let mut rt_guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
            *rt_guard = Some(ActiveGlobalRuntime {
                #[cfg(target_os = "windows")]
                engine: win_engine,
                windivert_fp: None,
                tunnel,
                mode,
                socks_port,
                active_relays,
                bound_physical_interface,
            });
        }

        self.persist_current_runtime_meta();
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
        self.upgrade_to_windivert_in_place_locked(cfg, relays, extra_excluded_pids, &_op)
            .await
    }

    async fn upgrade_to_windivert_in_place_locked(
        &self,
        cfg: &AppConfig,
        relays: &[PreAccelRelay],
        extra_excluded_pids: &[u32],
        _op_guard: &tokio::sync::MutexGuard<'_, ()>,
    ) -> CatResult<GlobalPreAccelStatus> {
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

            let Some((dll_path, sys_path)) =
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
            let wd_fp = WinDivertRuntimeFingerprint::from_inputs(
                dll_path.clone(),
                Some(sys_path),
                &relay_ipv4s,
                cfg.preaccel.skip_443_native,
                cfg.preaccel.global_scope,
                &cfg.preaccel.global_target_processes,
                &static_excluded_pids,
            );
            let bin_dir = dll_path.parent().map(Path::to_path_buf);
            let detected_products = self.refresh_detected_security_products();
            let engine_cfg = crate::preaccel::windivert_win::WinDivertEngineConfig {
                dll_path,
                socks_port,
                relay_ipv4s,
                skip_443_native: cfg.preaccel.skip_443_native,
                scope: cfg.preaccel.global_scope,
                target_processes: cfg.preaccel.global_target_processes.clone(),
                excluded_pids: static_excluded_pids,
                tunnel_pid,
                main_core_pid: synced_main_pid,
                metrics: Arc::clone(&self.metrics),
            };

            match crate::preaccel::windivert_win::WinDivertEngine::start(engine_cfg).await {
                Ok(mut engine) => {
                    self.set_verify_snapshot(VerifySnapshot {
                        state: "probing".to_string(),
                        latency_ms: None,
                        message: Some("正在自动探测底层透明加速链路…".to_string()),
                        checked_at_ms: None,
                        security_guidance: None,
                    });
                    let probe_urls = build_self_test_probe_urls(&cfg.preaccel.probe_url);
                    let probe_refs: Vec<&str> = probe_urls.iter().map(String::as_str).collect();
                    let outcome = enforce_self_test_strict_204(
                        engine
                            .run_self_test(&probe_refs, Duration::from_secs(4))
                            .await,
                    );
                    match outcome {
                        crate::preaccel::windivert_win::WinDivertSelfTestOutcome::Passed {
                            latency_ms,
                            probe_host,
                            status_code,
                        } => {
                            let (installed, displaced_engine) = {
                                let synced_guard = self
                                    .synced_main_core_pid
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner());
                                engine.sync_main_core_pid(*synced_guard);
                                let mut rt_guard =
                                    self.runtime.lock().unwrap_or_else(|e| e.into_inner());
                                if let Some(rt) = rt_guard.as_mut() {
                                    let old = rt.engine.replace(engine);
                                    rt.windivert_fp = Some(wd_fp);
                                    rt.mode = "windivert".to_string();
                                    (true, old)
                                } else {
                                    (false, Some(engine))
                                }
                            };
                            if let Some(mut stale) = displaced_engine {
                                let teardown_service = !installed;
                                let _ = tokio::task::spawn_blocking(move || {
                                    stale.stop_sync_with_teardown(teardown_service);
                                })
                                .await;
                            }
                            if installed {
                                self.set_install_state("ready");
                                self.set_last_error(None);
                                self.set_verify_snapshot(VerifySnapshot {
                                    state: "verified".to_string(),
                                    latency_ms: Some(latency_ms),
                                    message: Some(format!(
                                        "自动探测畅通：经由底层透明拦截与国内 443 中转连通 {probe_host}（HTTP {status_code}，{latency_ms} ms）"
                                    )),
                                    checked_at_ms: Some(now_epoch_ms()),
                                    security_guidance: None,
                                });
                                self.persist_current_runtime_meta();
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
                                self.reset_verify_snapshot();
                            }
                            Ok(self.status())
                        }
                        other => {
                            let _ = tokio::task::spawn_blocking(move || {
                                engine.stop_sync_with_teardown(true);
                            })
                            .await;
                            let (msg, guidance) = classify_self_test_failure(
                                &other,
                                &detected_products,
                                bin_dir.as_deref(),
                            );
                            self.set_install_state("ready");
                            self.set_last_error(Some(msg.clone()));
                            self.set_verify_snapshot(VerifySnapshot {
                                state: "degraded".to_string(),
                                latency_ms: None,
                                message: Some(msg),
                                checked_at_ms: Some(now_epoch_ms()),
                                security_guidance: guidance,
                            });
                            Ok(self.status())
                        }
                    }
                }
                Err(err) => {
                    let guidance = build_security_guidance(
                        &detected_products,
                        bin_dir.as_deref(),
                        "driver_load",
                    );
                    self.set_install_state("failed");
                    self.set_last_error(Some(format!(
                        "WinDivert 驱动就绪后原地热升格失败，继续保持本地独立 443 通道（{err}）"
                    )));
                    self.set_verify_snapshot(VerifySnapshot {
                        state: "failed".to_string(),
                        latency_ms: None,
                        message: Some(err.to_string()),
                        checked_at_ms: Some(now_epoch_ms()),
                        security_guidance: Some(guidance),
                    });
                    Err(err)
                }
            }
        }
    }

    /// Re-verify live transparent WinDivert dataplane connectivity on demand (e.g. after
    /// switching Wi-Fi/Ethernet, toggling a third-party TUN, or allowlisting CatCloud in
    /// Huorong / Windows Defender / 360).
    ///
    /// - When already running in `windivert` mode, runs an active non-disruptive dataplane
    ///   self-test and triggers automatic fail-safe downgrade to `local_socks5` if blocked.
    /// - When previously degraded to `local_socks5` (with driver + admin privileges available),
    ///   re-detects the current primary physical NIC and attempts a clean upgrade + self-test.
    pub async fn reverify_windivert(
        &self,
        cfg: &AppConfig,
        relays: &[PreAccelRelay],
        extra_excluded_pids: &[u32],
    ) -> CatResult<GlobalPreAccelStatus> {
        #[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
        {
            let _ = (cfg, relays, extra_excluded_pids);
            return Ok(self.status());
        }

        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        {
            let _op = self.op_lock.lock().await;
            let detected_products = self.refresh_detected_security_products();

            let (running, is_windivert, bound_if, bin_dir) = {
                let wd_dir =
                    locate_windivert_files(&self.paths, cfg.preaccel.windivert_dir.as_deref())
                        .and_then(|(dll, _)| dll.parent().map(Path::to_path_buf));
                let guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
                match guard.as_ref() {
                    Some(rt) => (
                        true,
                        rt.mode == "windivert" && rt.engine.is_some(),
                        rt.bound_physical_interface.clone(),
                        wd_dir,
                    ),
                    None => (false, false, None, wd_dir),
                }
            };

            if !running {
                return Ok(self.status());
            }

            if is_windivert {
                self.set_verify_snapshot(VerifySnapshot {
                    state: "probing".to_string(),
                    latency_ms: None,
                    message: Some("正在重新探测底层透明加速链路…".to_string()),
                    checked_at_ms: None,
                    security_guidance: None,
                });

                // Temporarily take the engine handle out of the mutex while running the async probe
                // so status snapshots never block and `op_lock` guarantees exclusive lifecycle control.
                let engine_opt = {
                    let mut guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
                    guard.as_mut().and_then(|rt| rt.engine.take())
                };
                if let Some(mut engine) = engine_opt {
                    let probe_urls = build_self_test_probe_urls(&cfg.preaccel.probe_url);
                    let probe_refs: Vec<&str> = probe_urls.iter().map(String::as_str).collect();
                    let outcome = enforce_self_test_strict_204(
                        engine
                            .run_self_test(&probe_refs, Duration::from_secs(4))
                            .await,
                    );
                    match outcome {
                        crate::preaccel::windivert_win::WinDivertSelfTestOutcome::Passed {
                            latency_ms,
                            probe_host,
                            status_code,
                        } => {
                            let leftover_engine = {
                                let mut guard =
                                    self.runtime.lock().unwrap_or_else(|e| e.into_inner());
                                if let Some(rt) = guard.as_mut() {
                                    rt.engine = Some(engine);
                                    rt.mode = "windivert".to_string();
                                    None
                                } else {
                                    Some(engine)
                                }
                            };
                            if let Some(mut orphan) = leftover_engine {
                                let _ = tokio::task::spawn_blocking(move || {
                                    orphan.stop_sync_with_teardown(true);
                                })
                                .await;
                                return Ok(self.status());
                            }
                            self.set_last_error(None);
                            self.set_verify_snapshot(VerifySnapshot {
                                state: "verified".to_string(),
                                latency_ms: Some(latency_ms),
                                message: Some(format!(
                                    "自动探测畅通：经由底层透明拦截与国内 443 中转连通 {probe_host}（HTTP {status_code}，{latency_ms} ms）"
                                )),
                                checked_at_ms: Some(now_epoch_ms()),
                                security_guidance: None,
                            });
                            self.persist_current_runtime_meta();
                            return Ok(self.status());
                        }
                        other => {
                            let _ = tokio::task::spawn_blocking(move || {
                                engine.stop_sync_with_teardown(true);
                            })
                            .await;
                            {
                                let mut guard =
                                    self.runtime.lock().unwrap_or_else(|e| e.into_inner());
                                if let Some(rt) = guard.as_mut() {
                                    rt.windivert_fp = None;
                                    rt.mode = "local_socks5".to_string();
                                }
                            }
                            self.persist_current_runtime_meta();
                            let (msg, guidance) = classify_self_test_failure(
                                &other,
                                &detected_products,
                                bin_dir.as_deref(),
                            );
                            self.set_last_error(Some(msg.clone()));
                            self.set_verify_snapshot(VerifySnapshot {
                                state: "degraded".to_string(),
                                latency_ms: None,
                                message: Some(msg),
                                checked_at_ms: Some(now_epoch_ms()),
                                security_guidance: guidance,
                            });
                            return Ok(self.status());
                        }
                    }
                }
            }

            // Currently running in `local_socks5`: check if primary physical NIC changed
            // (e.g. switched Ethernet <-> Wi-Fi) and retry full start or in-place upgrade
            // while holding the SAME `_op` lock so a concurrent `stop()` can never be resurrected.
            let latest_physical_if = tokio::task::spawn_blocking(|| {
                crate::preaccel::windivert_win::detect_primary_physical_interface().map(|i| i.friendly_name)
            })
            .await
            .ok()
            .flatten();
            let need_tunnel_rebuild = latest_physical_if != bound_if;

            if need_tunnel_rebuild {
                self.start_locked(cfg, relays, extra_excluded_pids, &_op)
                    .await
            } else {
                self.upgrade_to_windivert_in_place_locked(cfg, relays, extra_excluded_pids, &_op)
                    .await
            }
        }
    }

    /// Stop only the active WinDivert packet-interception handle for an imminent hot reload
    /// without stopping the `WinDivert` kernel driver service (avoiding Win32 error 1072 races)
    /// and without interrupting the standalone `:443` SOCKS5 tunnel.
    pub async fn stop_windivert_for_reload(&self) -> CatResult<GlobalPreAccelStatus> {
        let _op = self.op_lock.lock().await;
        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        {
            let engine_opt = {
                let mut rt_guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(rt) = rt_guard.as_mut() {
                    let taken = rt.engine.take();
                    if taken.is_some() {
                        rt.windivert_fp = None;
                        rt.mode = "local_socks5".to_string();
                    }
                    taken
                } else {
                    None
                }
            };
            if let Some(mut engine) = engine_opt {
                let _ = tokio::task::spawn_blocking(move || {
                    engine.stop_sync_with_teardown(false);
                })
                .await;
                self.metrics.clear_active_connections();
                self.persist_current_runtime_meta();
            }
        }
        Ok(self.status())
    }

    /// Hot-rebuild the running WinDivert transparent engine (and, when relay/probe settings
    /// changed, the standalone `:443` tunnel) using `stop_sync_with_teardown(false)` so the
    /// `WinDivert` kernel service stays loaded across reloads without triggering Win32 1072 errors.
    ///
    /// Returns the current idle status without launching anything if the manager is not running.
    pub async fn restart_windivert_if_running(
        &self,
        cfg: &AppConfig,
        relays: &[PreAccelRelay],
        extra_excluded_pids: &[u32],
    ) -> CatResult<GlobalPreAccelStatus> {
        let _op = self.op_lock.lock().await;
        let runtime_info = {
            let rt_guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
            rt_guard.as_ref().map(|rt| {
                #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
                let has_engine = rt.engine.is_some();
                #[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
                let has_engine = false;
                (
                    rt.socks_port,
                    rt.bound_physical_interface.clone(),
                    rt.tunnel.config_sha256().to_string(),
                    has_engine,
                    rt.windivert_fp.clone(),
                )
            })
        };
        let Some((socks_port, bound_if, current_yaml_sha, has_windivert_engine, old_wd_fp)) =
            runtime_info
        else {
            return Ok(self.status());
        };

        let next_yaml_sha = compile_standalone_preaccel_yaml_with_interface(
            cfg,
            relays,
            socks_port,
            bound_if.as_deref(),
        )
        .ok()
        .map(|yaml| hex::encode(Sha256::digest(yaml.as_bytes())));
        let tunnel_changed = next_yaml_sha.as_deref() != Some(current_yaml_sha.as_str());

        if tunnel_changed {
            return self
                .start_locked(cfg, relays, extra_excluded_pids, &_op)
                .await;
        }

        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        {
            if has_windivert_engine {
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
                let next_wd_fp =
                    locate_windivert_files(&self.paths, cfg.preaccel.windivert_dir.as_deref()).map(
                        |(dll_path, sys_path)| {
                            let relay_ipv4s = collect_enabled_relay_ipv4s(relays);
                            WinDivertRuntimeFingerprint::from_inputs(
                                dll_path,
                                Some(sys_path),
                                &relay_ipv4s,
                                cfg.preaccel.skip_443_native,
                                cfg.preaccel.global_scope,
                                &cfg.preaccel.global_target_processes,
                                &static_excluded_pids,
                            )
                        },
                    );
                if should_skip_windivert_restart(
                    tunnel_changed,
                    old_wd_fp.as_ref(),
                    next_wd_fp.as_ref(),
                ) {
                    let mut dir_guard = self
                        .custom_windivert_dir
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    *dir_guard = cfg.preaccel.windivert_dir.clone();
                    return Ok(self.status());
                }

                let old_engine = {
                    let mut rt_guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(rt) = rt_guard.as_mut() {
                        let taken = rt.engine.take();
                        if taken.is_some() {
                            rt.windivert_fp = None;
                            rt.mode = "local_socks5".to_string();
                        }
                        taken
                    } else {
                        None
                    }
                };
                if let Some(mut engine) = old_engine {
                    let _ = tokio::task::spawn_blocking(move || {
                        engine.stop_sync_with_teardown(false);
                    })
                    .await;
                    self.metrics.clear_active_connections();
                }
                return self
                    .upgrade_to_windivert_in_place_locked(cfg, relays, extra_excluded_pids, &_op)
                    .await;
            }
        }
        #[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
        let _ = old_wd_fp;

        {
            let mut dir_guard = self
                .custom_windivert_dir
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *dir_guard = cfg.preaccel.windivert_dir.clone();
        }

        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        {
            if !has_windivert_engine
                && default_platform().capabilities().is_elevated
                && locate_windivert_paths(&self.paths, cfg.preaccel.windivert_dir.as_deref())
                    .is_some()
            {
                return self
                    .upgrade_to_windivert_in_place_locked(cfg, relays, extra_excluded_pids, &_op)
                    .await;
            }
        }

        #[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
        let _ = (extra_excluded_pids, has_windivert_engine);

        Ok(self.status())
    }

    /// Suspend the standalone `:443` tunnel cleanly while the primary Mihomo core's TUN virtual NIC
    /// carries domestic pre-acceleration, recording `mode = "suspended_for_tun"` and
    /// `effective_carrier = "main_core_tun_suspended_standalone"` both in memory and on disk
    /// (`run/global-preaccel-runtime.json`) instead of conflating with `"off"`.
    pub async fn suspend_for_tun(
        &self,
        active_relays: Vec<String>,
    ) -> CatResult<GlobalPreAccelStatus> {
        let _op = self.op_lock.lock().await;
        let current = {
            let mut rt_guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
            rt_guard.take()
        };
        if let Some(rt) = current {
            rt.stop(true).await;
        }
        self.metrics.reset();
        self.reset_verify_snapshot();
        self.set_last_error(None);
        {
            let mut susp_guard = self
                .suspended_for_tun_relays
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *susp_guard = Some(active_relays);
        }
        self.persist_current_runtime_meta();
        Ok(self.status())
    }

    /// Deterministically stop transparent interception (including stopping the WinDivert kernel
    /// service cleanly) and terminate the standalone :443 tunnel, clearing stale process cards
    /// and removing `run/global-preaccel-runtime.json`.
    pub async fn stop(&self) -> CatResult<GlobalPreAccelStatus> {
        let _op = self.op_lock.lock().await;
        {
            let mut susp_guard = self
                .suspended_for_tun_relays
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *susp_guard = None;
        }
        let current = {
            let mut rt_guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
            rt_guard.take()
        };
        if let Some(rt) = current {
            rt.stop(true).await;
        }
        self.metrics.reset();
        self.reset_verify_snapshot();
        self.set_last_error(None);
        remove_global_preaccel_runtime_meta(&self.paths.root_data_dir);
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

        let (running, mode, socks_port, active_relays, bound_physical_interface) = {
            let guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(rt) => (
                    true,
                    rt.mode.clone(),
                    Some(rt.socks_port),
                    rt.active_relays.clone(),
                    rt.bound_physical_interface.clone(),
                ),
                None => {
                    let susp = self
                        .suspended_for_tun_relays
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone();
                    if let Some(relays) = susp {
                        (false, "suspended_for_tun".to_string(), None, relays, None)
                    } else {
                        (false, "off".to_string(), None, Vec::new(), None)
                    }
                }
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

        let verify_snap = self
            .verify_snapshot
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let detected_security_products = self
            .detected_security_products
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

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
            verify_state: verify_snap.state,
            verify_latency_ms: verify_snap.latency_ms,
            verify_message: verify_snap.message,
            verify_checked_at_ms: verify_snap.checked_at_ms,
            detected_security_products,
            security_guidance: verify_snap.security_guidance,
            bound_physical_interface,
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

/// Build an ordered list of non-443 domestic HTTP 204 probe URLs for verifying WinDivert dataplane
/// transparent interception end-to-end: prioritizes the configured URL when it is a strict 204
/// endpoint, and always falls back to authoritative Huawei & MIUI HTTP 204 endpoints.
#[cfg_attr(
    any(not(target_os = "windows"), target_arch = "aarch64"),
    allow(dead_code)
)]
pub fn build_self_test_probe_urls(configured_probe_url: &str) -> Vec<String> {
    let mut urls: Vec<String> = Vec::with_capacity(3);
    let mut push_unique_http_204 = |raw: &str| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return;
        }
        let Ok(parsed) = Url::parse(trimmed) else {
            return;
        };
        if !parsed.scheme().eq_ignore_ascii_case("http") {
            return;
        }
        if parsed.port_or_known_default() == Some(443) {
            return;
        }
        if crate::preaccel::generator::expected_probe_status_for_url(trimmed) != "204" {
            return;
        }
        if !urls.iter().any(|u| u.eq_ignore_ascii_case(trimmed)) {
            urls.push(trimmed.to_string());
        }
    };

    push_unique_http_204(configured_probe_url);
    push_unique_http_204(crate::preaccel::generator::DEFAULT_DOMESTIC_204_PRIMARY);
    push_unique_http_204(crate::preaccel::generator::DEFAULT_DOMESTIC_204_FALLBACK);
    urls
}

#[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
fn classify_self_test_failure(
    outcome: &crate::preaccel::windivert_win::WinDivertSelfTestOutcome,
    detected_products: &[String],
    bin_dir: Option<&Path>,
) -> (String, Option<String>) {
    match outcome {
        crate::preaccel::windivert_win::WinDivertSelfTestOutcome::Passed { .. } => {
            ("底层透明加速探测已通过".to_string(), None)
        }
        crate::preaccel::windivert_win::WinDivertSelfTestOutcome::BlockedAtDataplane {
            intercepted,
            accepted,
            send_errors,
            detail,
        } => {
            let msg = format!(
                "底层透明加速自动探测未通过（拦截 {intercepted} 包、到达本地转发 {accepted} 次、注入异常 {send_errors} 次）：{detail}。已自动停止拦截以防断网，并安全退回本地独立 443 通道"
            );
            let guidance =
                build_security_guidance(detected_products, bin_dir, "self_test_blocked");
            (msg, Some(guidance))
        }
        crate::preaccel::windivert_win::WinDivertSelfTestOutcome::NoPacketIntercepted { detail } => {
            let msg = format!(
                "底层透明加速自动探测未捕获到物理网卡出站测试包：{detail}。已自动停止拦截并安全退回本地独立 443 通道"
            );
            let guidance =
                build_security_guidance(detected_products, bin_dir, "self_test_blocked");
            (msg, Some(guidance))
        }
        crate::preaccel::windivert_win::WinDivertSelfTestOutcome::TunnelUnreachable { detail } => {
            let msg = format!(
                "底层透明拦截已送达本机转发口，但经由国内 443 中转访问探测地址失败：{detail}。已自动停止拦截防止其它软件超时，请先测速确认国内中转线路畅通后点击「重新探测」"
            );
            (msg, None)
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
        remove_global_preaccel_runtime_meta(&self.paths.root_data_dir);
    }
}
