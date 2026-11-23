use super::common::{
    LinuxDesktopHint, classify_linux_desktop, format_gsettings_bypass_list,
    format_kde_no_proxy_for, format_kde_proxy_url, format_shell_env_snippet, gsettings_quote,
    is_pkexec_user_cancelled, parse_getcap_has_net_admin, parse_kde_proxy_endpoint,
    render_linux_desktop_entry,
};
pub use super::common::resolve_persistent_linux_exe_path;
use super::{PlatformAdapter, PlatformCapabilities, SystemProxySpec};
use crate::error::{CatError, CatResult};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const DESKTOP_ENTRY_FILENAME: &str = "catcloud.desktop";
const GNOME_PROXY_SCHEMA: &str = "org.gnome.system.proxy";
const KDE_KIO_CONFIG_FILE: &str = "kioslaverc";
const KDE_PROXY_GROUP: &str = "Proxy Settings";

const HEADLESS_PROXY_HINT: &str = "当前 Linux 环境未检测到受支持的图形桌面系统代理服务（GNOME gsettings 或 KDE Plasma kwriteconfig6/kwriteconfig5），无法写入系统代理；如在无桌面/纯终端或独立窗口管理器环境中，请改用终端代理环境变量（http_proxy/https_proxy/all_proxy）或开启 TUN 虚拟网卡模式。";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinuxProxyBackend {
    Kde {
        write_bin: Option<&'static str>,
        read_bin: Option<&'static str>,
    },
    Gnome,
    None,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxPlatform;

impl LinuxPlatform {
    pub fn new() -> Self {
        Self
    }

    /// Reconcile live Linux desktop proxy settings against `expected`.
    /// Returns `Ok(true)` if drift was detected and repaired.
    pub fn proxy_guard_tick(&self, expected: &SystemProxySpec) -> CatResult<bool> {
        let observed = self.read_system_proxy()?;
        let drifted = observed.enabled != expected.enabled
            || (expected.enabled
                && (observed.pac_url != expected.pac_url
                    || (expected.pac_url.is_none()
                        && (observed.host != expected.host || observed.port != expected.port))));
        if drifted {
            self.apply_system_proxy(expected)?;
            return Ok(true);
        }
        Ok(false)
    }

    pub fn set_autostart_in_dir(
        &self,
        autostart_dir: &Path,
        enabled: bool,
        exe_path: &Path,
        args: &[String],
    ) -> CatResult<()> {
        let desktop_path = autostart_dir.join(DESKTOP_ENTRY_FILENAME);
        if !enabled {
            if desktop_path.exists() {
                std::fs::remove_file(&desktop_path)?;
            }
            return Ok(());
        }

        std::fs::create_dir_all(autostart_dir)?;
        let persistent_exe = resolve_persistent_linux_exe_path(exe_path);
        let content = render_desktop_entry(&persistent_exe, args);
        crate::paths::AppPaths::atomic_write(&desktop_path, content.as_bytes())?;
        Ok(())
    }

    pub fn is_autostart_enabled_in_dir(&self, autostart_dir: &Path) -> bool {
        autostart_dir.join(DESKTOP_ENTRY_FILENAME).is_file()
    }
}

/// Inspect whether the Mihomo binary at `mihomo_path` already possesses effective `cap_net_admin`
/// Linux file capabilities (allowing TUN mode without running the GUI as root).
pub fn has_mihomo_tun_capability(mihomo_path: &Path) -> bool {
    if !mihomo_path.is_file() {
        return false;
    }
    let canonical = std::fs::canonicalize(mihomo_path).unwrap_or_else(|_| mihomo_path.to_path_buf());
    let getcap_bin = find_unix_sbin_tool("getcap");
    let Ok(out) = Command::new(&getcap_bin).arg(&canonical).output() else {
        return false;
    };
    if !out.status.success() {
        return false;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    parse_getcap_has_net_admin(&stdout)
}

/// Grant minimal Linux network capabilities (`cap_net_admin,cap_net_bind_service=+ep`) strictly
/// to the Mihomo core binary via `pkexec setcap`, keeping the desktop GUI running as the normal
/// user so `~/.local/share/catcloud` and `instance.lock` are never polluted with root ownership.
///
/// - Returns `Ok(true)` if capabilities are already present or newly granted.
/// - Returns `Ok(false)` if the user cancelled / dismissed the Polkit authentication prompt.
pub fn grant_mihomo_tun_capability(mihomo_path: &Path) -> CatResult<bool> {
    if !mihomo_path.is_file() {
        return Err(CatError::NotFound(format!(
            "未找到 Mihomo 内核文件，无法授予 Linux TUN 权限：{}",
            mihomo_path.display()
        )));
    }
    let canonical = std::fs::canonicalize(mihomo_path).unwrap_or_else(|_| mihomo_path.to_path_buf());
    if has_mihomo_tun_capability(&canonical) {
        return Ok(true);
    }

    if !command_exists("pkexec") {
        return Err(CatError::Process(format!(
            "当前系统未检测到 Polkit 提权工具 pkexec，请在终端手动执行：sudo setcap cap_net_admin,cap_net_bind_service=+ep \"{}\"",
            canonical.display()
        )));
    }

    let setcap_bin = find_unix_sbin_tool("setcap");
    let out = Command::new("pkexec")
        .arg(&setcap_bin)
        .arg("cap_net_admin,cap_net_bind_service=+ep")
        .arg(&canonical)
        .output()
        .map_err(|e| CatError::Process(format!("调用 pkexec 为 Mihomo 授权 TUN 权限失败：{e}")))?;

    if out.status.success() {
        return Ok(true);
    }

    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if is_pkexec_user_cancelled(out.status.code(), &stderr) {
        return Ok(false);
    }

    let lower = stderr.to_ascii_lowercase();
    if lower.contains("no such file") || lower.contains("not found") {
        return Err(CatError::Process(format!(
            "系统缺少 setcap 工具（通常位于 libcap2-bin / libcap 软件包），请先安装后再重试（详情：{stderr}）"
        )));
    }
    if lower.contains("read-only") || lower.contains("operation not supported") {
        return Err(CatError::Process(format!(
            "当前内核所在文件系统不支持写入文件权限（可能位于只读挂载目录），请将 mihomo 放入用户数据目录 bin/ 后重试（详情：{stderr}）"
        )));
    }

    Err(CatError::Process(format!(
        "为 Mihomo 授予 Linux TUN 网络权限失败（退出码 {:?}）：{}",
        out.status.code(),
        if stderr.is_empty() {
            "未知错误"
        } else {
            stderr.as_str()
        }
    )))
}

impl PlatformAdapter for LinuxPlatform {
    fn capabilities(&self) -> PlatformCapabilities {
        // SAFETY: `geteuid()` is a standard POSIX syscall with no preconditions.
        let is_elevated = unsafe { libc::geteuid() == 0 };
        PlatformCapabilities {
            os: "linux".into(),
            arch: std::env::consts::ARCH.into(),
            supports_uwp_loopback: false,
            supports_tun_service: true,
            is_elevated,
        }
    }

    fn apply_system_proxy(&self, spec: &SystemProxySpec) -> CatResult<()> {
        match detect_linux_proxy_backend() {
            LinuxProxyBackend::Kde {
                write_bin: Some(write_bin),
                ..
            } => apply_kde_system_proxy(write_bin, spec),
            LinuxProxyBackend::Kde { write_bin: None, .. } => {
                if has_gnome_proxy_schema() {
                    apply_gnome_system_proxy(spec)
                } else {
                    Err(CatError::Process(HEADLESS_PROXY_HINT.into()))
                }
            }
            LinuxProxyBackend::Gnome => apply_gnome_system_proxy(spec),
            LinuxProxyBackend::None => Err(CatError::Process(HEADLESS_PROXY_HINT.into())),
        }
    }

    fn read_system_proxy(&self) -> CatResult<SystemProxySpec> {
        match detect_linux_proxy_backend() {
            LinuxProxyBackend::Kde {
                read_bin: Some(read_bin),
                ..
            } => read_kde_system_proxy(read_bin),
            LinuxProxyBackend::Kde { read_bin: None, .. } => {
                if has_gnome_proxy_schema() {
                    read_gnome_system_proxy()
                } else {
                    Ok(default_disabled_proxy_spec())
                }
            }
            LinuxProxyBackend::Gnome => read_gnome_system_proxy(),
            LinuxProxyBackend::None => Ok(default_disabled_proxy_spec()),
        }
    }

    fn set_autostart(&self, enabled: bool, exe_path: &Path, args: &[String]) -> CatResult<()> {
        let dir = xdg_autostart_dir()?;
        let persistent_exe = resolve_persistent_linux_exe_path(exe_path);
        self.set_autostart_in_dir(&dir, enabled, &persistent_exe, args)
    }

    fn is_autostart_enabled(&self) -> CatResult<bool> {
        let dir = xdg_autostart_dir()?;
        Ok(self.is_autostart_enabled_in_dir(&dir))
    }

    fn flush_dns(&self) -> CatResult<()> {
        let candidates: &[(&str, &[&str])] = &[
            ("resolvectl", &["flush-caches"]),
            ("systemd-resolve", &["--flush-caches"]),
            ("nscd", &["-i", "hosts"]),
        ];
        for (bin, args) in candidates {
            if let Ok(status) = Command::new(bin).args(*args).status() {
                if status.success() {
                    return Ok(());
                }
            }
        }
        // Systems without a local DNS cache daemon succeed cleanly as a no-op.
        Ok(())
    }

    fn export_shell_env_snippet(
        &self,
        shell: &str,
        host: &str,
        http_port: u16,
        socks_port: u16,
    ) -> String {
        format_shell_env_snippet(shell, host, http_port, socks_port, true)
    }
}

fn default_disabled_proxy_spec() -> SystemProxySpec {
    SystemProxySpec {
        enabled: false,
        host: "127.0.0.1".into(),
        port: 7890,
        bypass: Vec::new(),
        pac_url: None,
    }
}

fn is_executable_file(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|m| m.is_file() && (m.permissions().mode() & 0o111) != 0)
        .unwrap_or(false)
}

fn command_exists(name: &str) -> bool {
    let Some(path_var) = std::env::var_os("PATH") else {
        return false;
    };
    for dir in std::env::split_paths(&path_var) {
        if !dir.as_os_str().is_empty() && is_executable_file(&dir.join(name)) {
            return true;
        }
    }
    false
}

fn find_unix_sbin_tool(name: &str) -> PathBuf {
    for dir in ["/usr/sbin", "/sbin", "/usr/bin", "/bin"] {
        let candidate = Path::new(dir).join(name);
        if is_executable_file(&candidate) {
            return candidate;
        }
    }
    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(name);
            if is_executable_file(&candidate) {
                return candidate;
            }
        }
    }
    PathBuf::from(name)
}

fn detect_kde_tools() -> Option<(Option<&'static str>, Option<&'static str>)> {
    let write_bin = if command_exists("kwriteconfig6") {
        Some("kwriteconfig6")
    } else if command_exists("kwriteconfig5") {
        Some("kwriteconfig5")
    } else {
        None
    };
    let read_bin = if command_exists("kreadconfig6") {
        Some("kreadconfig6")
    } else if command_exists("kreadconfig5") {
        Some("kreadconfig5")
    } else {
        None
    };
    if write_bin.is_some() || read_bin.is_some() {
        Some((write_bin, read_bin))
    } else {
        None
    }
}

fn has_gnome_proxy_schema() -> bool {
    command_exists("gsettings") && run_gsettings(&["get", GNOME_PROXY_SCHEMA, "mode"]).is_ok()
}

fn detect_linux_proxy_backend() -> LinuxProxyBackend {
    let xdg = std::env::var("XDG_CURRENT_DESKTOP").ok();
    let kde_sess = std::env::var("KDE_FULL_SESSION").ok();
    match classify_linux_desktop(xdg.as_deref(), kde_sess.as_deref()) {
        LinuxDesktopHint::Kde => {
            if let Some((write_bin, read_bin)) = detect_kde_tools() {
                LinuxProxyBackend::Kde {
                    write_bin,
                    read_bin,
                }
            } else if has_gnome_proxy_schema() {
                LinuxProxyBackend::Gnome
            } else {
                LinuxProxyBackend::None
            }
        }
        LinuxDesktopHint::Gnome => {
            if has_gnome_proxy_schema() {
                LinuxProxyBackend::Gnome
            } else if let Some((write_bin, read_bin)) = detect_kde_tools() {
                LinuxProxyBackend::Kde {
                    write_bin,
                    read_bin,
                }
            } else {
                LinuxProxyBackend::None
            }
        }
        LinuxDesktopHint::Unknown => {
            if has_gnome_proxy_schema() {
                LinuxProxyBackend::Gnome
            } else if let Some((write_bin, read_bin)) = detect_kde_tools() {
                LinuxProxyBackend::Kde {
                    write_bin,
                    read_bin,
                }
            } else {
                LinuxProxyBackend::None
            }
        }
    }
}

fn apply_gnome_system_proxy(spec: &SystemProxySpec) -> CatResult<()> {
    let pac = spec
        .pac_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    if !spec.enabled {
        run_gsettings(&["set", GNOME_PROXY_SCHEMA, "mode", "'none'"])?;
        return Ok(());
    }

    if let Some(pac_url) = pac {
        let quoted_url = gsettings_quote(pac_url);
        run_gsettings(&["set", GNOME_PROXY_SCHEMA, "autoconfig-url", &quoted_url])?;
        run_gsettings(&["set", GNOME_PROXY_SCHEMA, "mode", "'auto'"])?;
        return Ok(());
    }

    let quoted_host = gsettings_quote(&spec.host);
    let port_str = spec.port.to_string();

    run_gsettings(&["set", "org.gnome.system.proxy.http", "host", &quoted_host])?;
    run_gsettings(&["set", "org.gnome.system.proxy.http", "port", &port_str])?;
    run_gsettings(&["set", "org.gnome.system.proxy.https", "host", &quoted_host])?;
    run_gsettings(&["set", "org.gnome.system.proxy.https", "port", &port_str])?;
    run_gsettings(&["set", "org.gnome.system.proxy.socks", "host", &quoted_host])?;
    run_gsettings(&["set", "org.gnome.system.proxy.socks", "port", &port_str])?;

    let formatted_list = format_gsettings_bypass_list(&spec.bypass);
    run_gsettings(&["set", GNOME_PROXY_SCHEMA, "ignore-hosts", &formatted_list])?;
    run_gsettings(&["set", GNOME_PROXY_SCHEMA, "mode", "'manual'"])?;
    Ok(())
}

fn read_gnome_system_proxy() -> CatResult<SystemProxySpec> {
    let mode = match run_gsettings(&["get", GNOME_PROXY_SCHEMA, "mode"]) {
        Ok(val) => strip_gsettings_quotes(&val),
        Err(_) => return Ok(default_disabled_proxy_spec()),
    };

    let host = run_gsettings(&["get", "org.gnome.system.proxy.http", "host"])
        .map(|v| strip_gsettings_quotes(&v))
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "127.0.0.1".into());
    let port = run_gsettings(&["get", "org.gnome.system.proxy.http", "port"])
        .ok()
        .and_then(|v| v.trim().parse::<u16>().ok())
        .filter(|&p| p > 0)
        .unwrap_or(7890);
    let pac_url = if mode == "auto" {
        run_gsettings(&["get", GNOME_PROXY_SCHEMA, "autoconfig-url"])
            .ok()
            .map(|v| strip_gsettings_quotes(&v))
            .filter(|v| !v.is_empty())
    } else {
        None
    };
    let bypass = run_gsettings(&["get", GNOME_PROXY_SCHEMA, "ignore-hosts"])
        .ok()
        .map(|v| parse_gsettings_str_list(&v))
        .unwrap_or_default();

    Ok(SystemProxySpec {
        enabled: mode == "manual" || (mode == "auto" && pac_url.is_some()),
        host,
        port,
        bypass,
        pac_url,
    })
}

fn run_kwriteconfig(bin: &str, key: &str, value: &str) -> CatResult<()> {
    let out = Command::new(bin)
        .args([
            "--file",
            KDE_KIO_CONFIG_FILE,
            "--group",
            KDE_PROXY_GROUP,
            "--key",
            key,
            value,
        ])
        .output()
        .map_err(|e| CatError::Process(format!("调用 KDE {bin} 写入系统代理失败：{e}")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(CatError::Process(format!(
            "KDE {bin} 写入 {key} 失败（{}）：{stderr}",
            out.status
        )));
    }
    Ok(())
}

fn run_kreadconfig(bin: &str, key: &str) -> Option<String> {
    let out = Command::new(bin)
        .args([
            "--file",
            KDE_KIO_CONFIG_FILE,
            "--group",
            KDE_PROXY_GROUP,
            "--key",
            key,
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn notify_kde_kio_reparse() {
    let _ = Command::new("dbus-send")
        .args([
            "--type=signal",
            "/KIO/Scheduler",
            "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
            "string:",
        ])
        .status();
}

fn apply_kde_system_proxy(write_bin: &str, spec: &SystemProxySpec) -> CatResult<()> {
    let pac = spec
        .pac_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    if !spec.enabled {
        run_kwriteconfig(write_bin, "ProxyType", "0")?;
        notify_kde_kio_reparse();
        return Ok(());
    }

    if let Some(pac_url) = pac {
        run_kwriteconfig(write_bin, "Proxy Config Script", pac_url)?;
        run_kwriteconfig(write_bin, "ProxyType", "2")?;
        notify_kde_kio_reparse();
        return Ok(());
    }

    let http_url = format_kde_proxy_url("http", &spec.host, spec.port);
    let socks_url = format_kde_proxy_url("socks", &spec.host, spec.port);
    let no_proxy = format_kde_no_proxy_for(&spec.bypass);

    run_kwriteconfig(write_bin, "httpProxy", &http_url)?;
    run_kwriteconfig(write_bin, "httpsProxy", &http_url)?;
    run_kwriteconfig(write_bin, "socksProxy", &socks_url)?;
    run_kwriteconfig(write_bin, "NoProxyFor", &no_proxy)?;
    run_kwriteconfig(write_bin, "ReversedException", "false")?;
    run_kwriteconfig(write_bin, "ProxyType", "1")?;
    notify_kde_kio_reparse();
    Ok(())
}

fn read_kde_system_proxy(read_bin: &str) -> CatResult<SystemProxySpec> {
    let proxy_type = run_kreadconfig(read_bin, "ProxyType")
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(0);

    let (host, port) = run_kreadconfig(read_bin, "httpProxy")
        .and_then(|v| parse_kde_proxy_endpoint(&v))
        .or_else(|| {
            run_kreadconfig(read_bin, "httpsProxy").and_then(|v| parse_kde_proxy_endpoint(&v))
        })
        .or_else(|| {
            run_kreadconfig(read_bin, "socksProxy").and_then(|v| parse_kde_proxy_endpoint(&v))
        })
        .unwrap_or_else(|| ("127.0.0.1".into(), 7890));

    let pac_url = if proxy_type == 2 {
        run_kreadconfig(read_bin, "Proxy Config Script").filter(|v| !v.is_empty())
    } else {
        None
    };

    let bypass = run_kreadconfig(read_bin, "NoProxyFor")
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default();

    Ok(SystemProxySpec {
        enabled: proxy_type == 1 || (proxy_type == 2 && pac_url.is_some()),
        host,
        port,
        bypass,
        pac_url,
    })
}

fn xdg_autostart_dir() -> CatResult<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.trim().is_empty() {
            return Ok(PathBuf::from(xdg).join("autostart"));
        }
    }
    let home = std::env::var("HOME")
        .map_err(|_| CatError::Config("HOME environment variable not set".into()))?;
    Ok(PathBuf::from(home).join(".config").join("autostart"))
}

fn run_gsettings(args: &[&str]) -> CatResult<String> {
    let out = Command::new("gsettings")
        .args(args)
        .output()
        .map_err(|e| CatError::Process(format!("failed to invoke gsettings: {e}")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(CatError::Process(format!(
            "gsettings {:?} failed ({}): {stderr}",
            args, out.status
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn strip_gsettings_quotes(val: &str) -> String {
    let s = val.trim();
    if let Some(inner) = s.strip_prefix('\'').and_then(|r| r.strip_suffix('\'')) {
        inner.to_string()
    } else if let Some(inner) = s.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
        inner.to_string()
    } else {
        s.to_string()
    }
}

fn parse_gsettings_str_list(raw: &str) -> Vec<String> {
    let trimmed = raw.trim().trim_start_matches("@as ").trim();
    let inner = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or("");
    inner
        .split(',')
        .map(strip_gsettings_quotes)
        .filter(|s| !s.is_empty())
        .collect()
}

fn render_desktop_entry(exe_path: &Path, args: &[String]) -> String {
    render_linux_desktop_entry(exe_path, args)
}
