use super::{PlatformAdapter, PlatformCapabilities, SystemProxySpec};
use crate::error::{CatError, CatResult};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, GetLastError, HANDLE,
};
use windows_sys::Win32::Networking::WinInet::{
    INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED, InternetSetOptionW,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_DWORD, REG_EXPAND_SZ,
    REG_OPTION_NON_VOLATILE, REG_SZ, REG_VALUE_TYPE, RegCloseKey, RegCreateKeyExW,
    RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, GetCurrentProcess, OpenProcessToken,
};

const INTERNET_SETTINGS_SUBKEY: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const STARTUP_SHORTCUT_NAME: &str = "CatCloud.lnk";
const DEFAULT_PROXY_BYPASS: &str =
    "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>";

/// Outcome of a Proxy Guard reconciliation tick.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyGuardReport {
    pub drifted: bool,
    pub repaired: bool,
    pub observed: SystemProxySpec,
    pub reason: Option<String>,
}

/// Outcome of invoking the Windows UWP loopback exemption helper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UwpLoopbackResult {
    pub launched_gui_helper: bool,
    pub helper_path: Option<PathBuf>,
    pub detail: String,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsPlatform;

impl WindowsPlatform {
    pub fn new() -> Self {
        Self
    }

    /// Reconcile the live Windows WinINet proxy settings against `expected`.
    /// If another program modified or cleared the system proxy, restore `expected` immediately.
    pub fn proxy_guard_tick(&self, expected: &SystemProxySpec) -> CatResult<ProxyGuardReport> {
        let observed = self.read_system_proxy()?;
        if let Some(reason) = detect_proxy_drift(&observed, expected) {
            tracing::warn!(reason = %reason, "system proxy drift detected; restoring expected proxy");
            self.apply_system_proxy(expected)?;
            return Ok(ProxyGuardReport {
                drifted: true,
                repaired: true,
                observed,
                reason: Some(reason),
            });
        }
        Ok(ProxyGuardReport {
            drifted: false,
            repaired: false,
            observed,
            reason: None,
        })
    }

    /// Launch a bundled UWP Loopback Exemption GUI utility if present, or fall back to
    /// inspecting loopback status via Windows built-in `CheckNetIsolation.exe`.
    pub fn launch_uwp_loopback_helper(&self) -> CatResult<UwpLoopbackResult> {
        let mut search_dirs = Vec::new();
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                search_dirs.push(dir.join("resources").join("bin"));
                search_dirs.push(dir.join("bin"));
                search_dirs.push(dir.to_path_buf());
            }
        }
        self.launch_uwp_loopback_helper_in_dirs(&search_dirs)
    }

    /// Search `search_dirs` for an `EnableLoopback.exe` binary and spawn it; otherwise query
    /// `CheckNetIsolation.exe LoopbackExempt -s` cleanly without popping a console window.
    pub fn launch_uwp_loopback_helper_in_dirs(
        &self,
        search_dirs: &[PathBuf],
    ) -> CatResult<UwpLoopbackResult> {
        for dir in search_dirs {
            for candidate_name in ["EnableLoopback.exe", "enableLoopback.exe"] {
                let candidate = dir.join(candidate_name);
                if candidate.is_file() {
                    Command::new(&candidate)
                        .current_dir(dir)
                        .spawn()
                        .map_err(|e| {
                            CatError::Process(format!(
                                "failed to launch UWP loopback helper {}: {e}",
                                candidate.display()
                            ))
                        })?;
                    return Ok(UwpLoopbackResult {
                        launched_gui_helper: true,
                        helper_path: Some(candidate),
                        detail: "Launched bundled EnableLoopback GUI utility".into(),
                    });
                }
            }
        }

        let check_exe = system32_exe("CheckNetIsolation.exe");
        let output = Command::new(&check_exe)
            .args(["LoopbackExempt", "-s"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| {
                CatError::Process(format!(
                    "EnableLoopback.exe not found and CheckNetIsolation failed: {e}"
                ))
            })?;

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if !output.status.success() {
            return Err(CatError::Process(format!(
                "CheckNetIsolation exited with {}: {}",
                output.status,
                if stderr.is_empty() { stdout } else { stderr }
            )));
        }

        Ok(UwpLoopbackResult {
            launched_gui_helper: false,
            helper_path: Some(check_exe),
            detail: if stdout.is_empty() {
                "Queried UWP loopback exemptions via CheckNetIsolation.exe (none listed)".into()
            } else {
                stdout
            },
        })
    }

    /// Add a specific UWP package family name to the Windows loopback exemption list.
    pub fn exempt_uwp_package(&self, package_family_name: &str) -> CatResult<()> {
        let pfn = package_family_name.trim();
        if pfn.is_empty()
            || pfn
                .chars()
                .any(|c| c.is_control() || c.is_whitespace() || c == '&' || c == '|' || c == ';')
        {
            return Err(CatError::Validation(
                "invalid UWP package family name".into(),
            ));
        }
        let check_exe = system32_exe("CheckNetIsolation.exe");
        let arg = format!("-n={pfn}");
        let output = Command::new(check_exe)
            .args(["LoopbackExempt", "-a", &arg])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| CatError::Process(format!("failed to invoke CheckNetIsolation: {e}")))?;
        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(CatError::Process(format!(
                "CheckNetIsolation exemption failed (may require administrator elevation): {err}"
            )));
        }
        Ok(())
    }

    /// Create or delete `CatCloud.lnk` inside an explicit Startup directory (zero registry writes).
    pub fn set_autostart_in_dir(
        &self,
        startup_dir: &Path,
        enabled: bool,
        exe_path: &Path,
        args: &[String],
    ) -> CatResult<()> {
        let lnk_path = startup_dir.join(STARTUP_SHORTCUT_NAME);
        if !enabled {
            if lnk_path.exists() {
                std::fs::remove_file(&lnk_path)?;
            }
            return Ok(());
        }

        if !exe_path.exists() {
            return Err(CatError::Validation(format!(
                "autostart target executable does not exist: {}",
                exe_path.display()
            )));
        }

        std::fs::create_dir_all(startup_dir)?;
        let canonical_exe = std::fs::canonicalize(exe_path).unwrap_or_else(|_| exe_path.to_path_buf());
        // Strip Windows verbatim prefix `\\?\` so WScript.Shell CreateShortcut handles paths cleanly.
        let clean_exe = strip_verbatim_prefix(&canonical_exe);
        let work_dir = clean_exe
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let clean_lnk = strip_verbatim_prefix(&lnk_path);
        let joined_args = format_windows_args(args);
        let icon_loc = format!("{},0", clean_exe.display());

        let ps_script = format!(
            "$ErrorActionPreference = 'Stop'\n\
             $ws = New-Object -ComObject WScript.Shell\n\
             $sc = $ws.CreateShortcut({lnk})\n\
             $sc.TargetPath = {target}\n\
             $sc.Arguments = {arguments}\n\
             $sc.WorkingDirectory = {workdir}\n\
             $sc.Description = 'CatCloud Intelligent Proxy'\n\
             $sc.IconLocation = {icon}\n\
             $sc.Save()\n",
            lnk = ps_quote(&clean_lnk.to_string_lossy()),
            target = ps_quote(&clean_exe.to_string_lossy()),
            arguments = ps_quote(&joined_args),
            workdir = ps_quote(&work_dir.to_string_lossy()),
            icon = ps_quote(&icon_loc),
        );

        let encoded = encode_powershell_utf16le(&ps_script);
        let ps_exe = powershell_exe();
        let output = Command::new(ps_exe)
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-WindowStyle",
                "Hidden",
                "-EncodedCommand",
                &encoded,
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| CatError::Process(format!("failed to execute PowerShell for .lnk: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let detail = if !stderr.is_empty() { stderr } else { stdout };
            return Err(CatError::Process(format!(
                "failed to create startup shortcut {}: {detail}",
                lnk_path.display()
            )));
        }
        Ok(())
    }

    pub fn is_autostart_enabled_in_dir(&self, startup_dir: &Path) -> bool {
        startup_dir.join(STARTUP_SHORTCUT_NAME).is_file()
    }
}

impl PlatformAdapter for WindowsPlatform {
    fn capabilities(&self) -> PlatformCapabilities {
        PlatformCapabilities {
            os: "windows".into(),
            arch: std::env::consts::ARCH.into(),
            supports_uwp_loopback: true,
            supports_tun_service: true,
            is_elevated: is_current_process_elevated(),
        }
    }

    fn apply_system_proxy(&self, spec: &SystemProxySpec) -> CatResult<()> {
        validate_proxy_spec(spec)?;

        let key = RegKeyGuard::create_hkcu(INTERNET_SETTINGS_SUBKEY, KEY_SET_VALUE | KEY_QUERY_VALUE)?;
        let pac = spec
            .pac_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());

        if !spec.enabled {
            key.set_dword("ProxyEnable", 0)?;
            key.delete_value_if_exists("AutoConfigURL")?;
        } else if let Some(pac_url) = pac {
            key.set_dword("ProxyEnable", 0)?;
            key.set_sz("AutoConfigURL", pac_url)?;
        } else {
            key.delete_value_if_exists("AutoConfigURL")?;
            let server = format_proxy_server(&spec.host, spec.port);
            let override_val = if spec.bypass.is_empty() {
                DEFAULT_PROXY_BYPASS.to_string()
            } else {
                spec.bypass
                    .iter()
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join(";")
            };
            key.set_sz("ProxyServer", &server)?;
            key.set_sz("ProxyOverride", &override_val)?;
            key.set_dword("ProxyEnable", 1)?;
        }

        notify_wininet_proxy_changed()?;
        Ok(())
    }

    fn read_system_proxy(&self) -> CatResult<SystemProxySpec> {
        let key = RegKeyGuard::open_hkcu(INTERNET_SETTINGS_SUBKEY, KEY_QUERY_VALUE)?;
        let proxy_enable = key.query_dword("ProxyEnable")?.unwrap_or(0);
        let proxy_server = key.query_sz("ProxyServer")?.unwrap_or_default();
        let proxy_override = key.query_sz("ProxyOverride")?.unwrap_or_default();
        let auto_config = key
            .query_sz("AutoConfigURL")?
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let (host, port) = parse_proxy_server(&proxy_server);
        let bypass = proxy_override
            .split(';')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect();

        let enabled = proxy_enable != 0 || auto_config.is_some();
        Ok(SystemProxySpec {
            enabled,
            host,
            port,
            bypass,
            pac_url: auto_config,
        })
    }

    fn set_autostart(&self, enabled: bool, exe_path: &Path, args: &[String]) -> CatResult<()> {
        let startup_dir = windows_startup_dir()?;
        self.set_autostart_in_dir(&startup_dir, enabled, exe_path, args)
    }

    fn is_autostart_enabled(&self) -> CatResult<bool> {
        let startup_dir = windows_startup_dir()?;
        Ok(self.is_autostart_enabled_in_dir(&startup_dir))
    }

    fn flush_dns(&self) -> CatResult<()> {
        let ipconfig = system32_exe("ipconfig.exe");
        let output = Command::new(ipconfig)
            .arg("/flushdns")
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| CatError::Process(format!("failed to run ipconfig /flushdns: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let detail = if !stderr.is_empty() { stderr } else { stdout };
            return Err(CatError::Process(format!(
                "ipconfig /flushdns exited with {}: {detail}",
                output.status
            )));
        }
        Ok(())
    }

    fn export_shell_env_snippet(
        &self,
        shell: &str,
        host: &str,
        http_port: u16,
        socks_port: u16,
    ) -> String {
        export_env_snippet_common(shell, host, http_port, socks_port)
    }
}

/// Shared multi-shell proxy environment snippet formatter (PowerShell / CMD / Bash / Fish).
pub fn export_env_snippet_common(
    shell: &str,
    host: &str,
    http_port: u16,
    socks_port: u16,
) -> String {
    let clean_host = sanitize_host(host);
    let http_url = format!("http://{clean_host}:{http_port}");
    let socks_url = format!("socks5h://{clean_host}:{socks_port}");
    let no_proxy = "localhost,127.0.0.1,::1";

    match shell.trim().to_ascii_lowercase().as_str() {
        "cmd" | "bat" | "commandprompt" => format!(
            "set HTTP_PROXY={http_url}\r\nset HTTPS_PROXY={http_url}\r\nset ALL_PROXY={socks_url}\r\nset NO_PROXY={no_proxy}"
        ),
        "bash" | "zsh" | "sh" | "gitbash" => format!(
            "export HTTP_PROXY=\"{http_url}\"\nexport HTTPS_PROXY=\"{http_url}\"\nexport ALL_PROXY=\"{socks_url}\"\nexport NO_PROXY=\"{no_proxy}\""
        ),
        "fish" => format!(
            "set -gx HTTP_PROXY \"{http_url}\"\nset -gx HTTPS_PROXY \"{http_url}\"\nset -gx ALL_PROXY \"{socks_url}\"\nset -gx NO_PROXY \"{no_proxy}\""
        ),
        // Default on Windows: PowerShell (`powershell`, `pwsh`, `ps`)
        _ => format!(
            "$env:HTTP_PROXY=\"{http_url}\"\n$env:HTTPS_PROXY=\"{http_url}\"\n$env:ALL_PROXY=\"{socks_url}\"\n$env:NO_PROXY=\"{no_proxy}\""
        ),
    }
}

fn sanitize_host(host: &str) -> String {
    let trimmed = host.trim();
    if trimmed.is_empty()
        || trimmed
            .chars()
            .any(|c| c.is_control() || matches!(c, '"' | '\'' | ';' | '\n' | '\r' | ' ' | '$'))
    {
        return "127.0.0.1".into();
    }
    if trimmed.contains(':') && !trimmed.starts_with('[') {
        format!("[{trimmed}]")
    } else {
        trimmed.to_string()
    }
}

fn format_proxy_server(host: &str, port: u16) -> String {
    let clean = sanitize_host(host);
    format!("{clean}:{port}")
}

/// Parse WinINet `ProxyServer` value (plain `host:port`, `[ipv6]:port`, or protocol-prefixed
/// `http=127.0.0.1:7890;https=127.0.0.1:7890`).
pub fn parse_proxy_server(raw: &str) -> (String, u16) {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return ("127.0.0.1".into(), 7890);
    }

    let selected = if trimmed.contains('=') {
        let mut chosen = None;
        for part in trimmed.split(';') {
            let part = part.trim();
            if let Some(rest) = part
                .strip_prefix("http=")
                .or_else(|| part.strip_prefix("HTTP="))
            {
                chosen = Some(rest.trim());
                break;
            }
            if chosen.is_none() {
                if let Some((_, rhs)) = part.split_once('=') {
                    chosen = Some(rhs.trim());
                }
            }
        }
        chosen.unwrap_or(trimmed)
    } else {
        trimmed
    };

    let without_scheme = selected
        .strip_prefix("http://")
        .or_else(|| selected.strip_prefix("https://"))
        .unwrap_or(selected);

    if let Some(rest) = without_scheme.strip_prefix('[') {
        if let Some((ip, port_part)) = rest.split_once("]:") {
            if let Ok(port) = port_part.trim().parse::<u16>() {
                return (ip.to_string(), port);
            }
        }
    }

    if let Some((h, p)) = without_scheme.rsplit_once(':') {
        if let Ok(port) = p.trim().parse::<u16>() {
            let host = if h.trim().is_empty() {
                "127.0.0.1"
            } else {
                h.trim()
            };
            return (host.to_string(), port);
        }
    }

    ("127.0.0.1".into(), 7890)
}

/// Compare observed system proxy against expected spec; returns `Some(reason)` on drift.
pub fn detect_proxy_drift(
    observed: &SystemProxySpec,
    expected: &SystemProxySpec,
) -> Option<String> {
    if observed.enabled != expected.enabled {
        return Some(format!(
            "enabled state mismatch (observed={}, expected={})",
            observed.enabled, expected.enabled
        ));
    }
    if !expected.enabled {
        return None;
    }

    let exp_pac = expected
        .pac_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let obs_pac = observed
        .pac_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    if exp_pac != obs_pac {
        return Some(format!(
            "PAC URL mismatch (observed={obs_pac:?}, expected={exp_pac:?})"
        ));
    }
    if exp_pac.is_some() {
        return None;
    }

    if !observed.host.eq_ignore_ascii_case(expected.host.trim()) || observed.port != expected.port {
        return Some(format!(
            "proxy endpoint mismatch (observed={}:{}, expected={}:{})",
            observed.host, observed.port, expected.host, expected.port
        ));
    }

    if !expected.bypass.is_empty() {
        let mut obs_norm: Vec<String> = observed
            .bypass
            .iter()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        let mut exp_norm: Vec<String> = expected
            .bypass
            .iter()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        obs_norm.sort();
        obs_norm.dedup();
        exp_norm.sort();
        exp_norm.dedup();
        if obs_norm != exp_norm {
            return Some("proxy bypass list modified externally".into());
        }
    }

    None
}

fn validate_proxy_spec(spec: &SystemProxySpec) -> CatResult<()> {
    if !spec.enabled {
        return Ok(());
    }
    if let Some(pac) = spec.pac_url.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        if !(pac.starts_with("http://") || pac.starts_with("https://"))
            || pac.chars().any(char::is_control)
        {
            return Err(CatError::Validation(format!(
                "invalid PAC URL for system proxy: {pac}"
            )));
        }
        return Ok(());
    }
    let host = spec.host.trim();
    if host.is_empty()
        || host
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == ';')
    {
        return Err(CatError::Validation(format!(
            "invalid proxy host: {:?}",
            spec.host
        )));
    }
    if spec.port == 0 {
        return Err(CatError::Validation("proxy port must be non-zero".into()));
    }
    Ok(())
}

fn notify_wininet_proxy_changed() -> CatResult<()> {
    // SAFETY: Calling WinINet InternetSetOptionW with NULL handle and zero-length buffer
    // notifies the system that Internet settings changed and must be refreshed.
    unsafe {
        let ok1 = InternetSetOptionW(
            std::ptr::null(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null(),
            0,
        );
        let ok2 = InternetSetOptionW(
            std::ptr::null(),
            INTERNET_OPTION_REFRESH,
            std::ptr::null(),
            0,
        );
        if ok1 == 0 || ok2 == 0 {
            let code = GetLastError();
            return Err(CatError::Process(format!(
                "InternetSetOptionW refresh failed (settings_changed={ok1}, refresh={ok2}, win32_err={code})"
            )));
        }
    }
    Ok(())
}

fn is_current_process_elevated() -> bool {
    // SAFETY: OpenProcessToken & GetTokenInformation operate on the current process pseudo-handle;
    // the returned token handle is unconditionally closed before returning.
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 || token.is_null() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut ret_len: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        let _ = CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

fn windows_startup_dir() -> CatResult<PathBuf> {
    if let Ok(appdata) = std::env::var("APPDATA") {
        if !appdata.trim().is_empty() {
            return Ok(PathBuf::from(appdata)
                .join("Microsoft")
                .join("Windows")
                .join("Start Menu")
                .join("Programs")
                .join("Startup"));
        }
    }
    if let Ok(profile) = std::env::var("USERPROFILE") {
        if !profile.trim().is_empty() {
            return Ok(PathBuf::from(profile)
                .join("AppData")
                .join("Roaming")
                .join("Microsoft")
                .join("Windows")
                .join("Start Menu")
                .join("Programs")
                .join("Startup"));
        }
    }
    Err(CatError::Config(
        "cannot determine Windows Startup folder (APPDATA/USERPROFILE missing)".into(),
    ))
}

fn system32_exe(name: &str) -> PathBuf {
    if let Ok(root) = std::env::var("SystemRoot") {
        let candidate = PathBuf::from(root).join("System32").join(name);
        if candidate.is_file() {
            return candidate;
        }
    }
    PathBuf::from(name)
}

fn powershell_exe() -> PathBuf {
    if let Ok(root) = std::env::var("SystemRoot") {
        let candidate = PathBuf::from(root)
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        if candidate.is_file() {
            return candidate;
        }
    }
    PathBuf::from("powershell.exe")
}

fn ps_quote(text: &str) -> String {
    let mut out = text.to_string();
    for ch in ['\'', '\u{2018}', '\u{2019}', '\u{201a}', '\u{201b}'] {
        if out.contains(ch) {
            let s = ch.to_string();
            let doubled = format!("{ch}{ch}");
            out = out.replace(&s, &doubled);
        }
    }
    format!("'{out}'")
}

fn encode_powershell_utf16le(script: &str) -> String {
    let mut bytes = Vec::with_capacity(script.len() * 2);
    for unit in script.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn format_windows_args(args: &[String]) -> String {
    args.iter()
        .map(|arg| {
            if arg.is_empty() || arg.chars().any(|c| c.is_whitespace() || c == '"') {
                let escaped = arg.replace('"', "\\\"");
                format!("\"{escaped}\"")
            } else {
                arg.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn strip_verbatim_prefix(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{rest}"))
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        path.to_path_buf()
    }
}

fn to_wide_null(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

struct RegKeyGuard(HKEY);

impl RegKeyGuard {
    fn open_hkcu(subkey: &str, access: u32) -> CatResult<Self> {
        let wide = to_wide_null(subkey);
        let mut hkey: HKEY = std::ptr::null_mut();
        // SAFETY: Valid null-terminated UTF-16 subkey path and out-pointer.
        let status = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, wide.as_ptr(), 0, access, &mut hkey) };
        if status != ERROR_SUCCESS {
            return Err(CatError::Process(format!(
                "RegOpenKeyExW(HKCU\\{subkey}) failed with code {status}"
            )));
        }
        Ok(Self(hkey))
    }

    fn create_hkcu(subkey: &str, access: u32) -> CatResult<Self> {
        let wide = to_wide_null(subkey);
        let mut hkey: HKEY = std::ptr::null_mut();
        let mut disposition: u32 = 0;
        // SAFETY: Valid null-terminated UTF-16 subkey path and valid out-pointers.
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                wide.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                access,
                std::ptr::null(),
                &mut hkey,
                &mut disposition,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(CatError::Process(format!(
                "RegCreateKeyExW(HKCU\\{subkey}) failed with code {status}"
            )));
        }
        Ok(Self(hkey))
    }

    fn set_dword(&self, name: &str, value: u32) -> CatResult<()> {
        let wide_name = to_wide_null(name);
        let bytes = value.to_le_bytes();
        // SAFETY: Key handle is valid; bytes pointer covers 4 bytes of REG_DWORD.
        let status = unsafe {
            RegSetValueExW(
                self.0,
                wide_name.as_ptr(),
                0,
                REG_DWORD,
                bytes.as_ptr(),
                bytes.len() as u32,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(CatError::Process(format!(
                "RegSetValueExW({name}) failed with code {status}"
            )));
        }
        Ok(())
    }

    fn set_sz(&self, name: &str, value: &str) -> CatResult<()> {
        let wide_name = to_wide_null(name);
        let wide_val = to_wide_null(value);
        let byte_len = (wide_val.len() * std::mem::size_of::<u16>()) as u32;
        // SAFETY: Key handle is valid; wide_val is null-terminated UTF-16 buffer.
        let status = unsafe {
            RegSetValueExW(
                self.0,
                wide_name.as_ptr(),
                0,
                REG_SZ,
                wide_val.as_ptr().cast(),
                byte_len,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(CatError::Process(format!(
                "RegSetValueExW({name}) failed with code {status}"
            )));
        }
        Ok(())
    }

    fn delete_value_if_exists(&self, name: &str) -> CatResult<()> {
        let wide_name = to_wide_null(name);
        // SAFETY: Key handle is valid; wide_name is null-terminated UTF-16 string.
        let status = unsafe { RegDeleteValueW(self.0, wide_name.as_ptr()) };
        if status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND {
            return Ok(());
        }
        Err(CatError::Process(format!(
            "RegDeleteValueW({name}) failed with code {status}"
        )))
    }

    fn query_dword(&self, name: &str) -> CatResult<Option<u32>> {
        let wide_name = to_wide_null(name);
        let mut reg_type: REG_VALUE_TYPE = 0;
        let mut data: u32 = 0;
        let mut size: u32 = std::mem::size_of::<u32>() as u32;
        // SAFETY: Valid pointers matching `size`.
        let status = unsafe {
            RegQueryValueExW(
                self.0,
                wide_name.as_ptr(),
                std::ptr::null(),
                &mut reg_type,
                (&mut data as *mut u32).cast(),
                &mut size,
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            return Err(CatError::Process(format!(
                "RegQueryValueExW({name}) failed with code {status}"
            )));
        }
        if reg_type != REG_DWORD {
            return Ok(None);
        }
        Ok(Some(data))
    }

    fn query_sz(&self, name: &str) -> CatResult<Option<String>> {
        let wide_name = to_wide_null(name);
        let mut reg_type: REG_VALUE_TYPE = 0;
        let mut size_bytes: u32 = 0;
        // SAFETY: First call queries required byte size.
        let status = unsafe {
            RegQueryValueExW(
                self.0,
                wide_name.as_ptr(),
                std::ptr::null(),
                &mut reg_type,
                std::ptr::null_mut(),
                &mut size_bytes,
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            return Err(CatError::Process(format!(
                "RegQueryValueExW({name}) size query failed with code {status}"
            )));
        }
        if reg_type != REG_SZ && reg_type != REG_EXPAND_SZ {
            return Ok(None);
        }
        if size_bytes == 0 {
            return Ok(Some(String::new()));
        }

        let wide_len = (size_bytes as usize).div_ceil(2);
        let mut buf = vec![0u16; wide_len];
        let mut actual_bytes = (buf.len() * 2) as u32;
        // SAFETY: `buf` holds at least `actual_bytes` bytes.
        let status2 = unsafe {
            RegQueryValueExW(
                self.0,
                wide_name.as_ptr(),
                std::ptr::null(),
                &mut reg_type,
                buf.as_mut_ptr().cast(),
                &mut actual_bytes,
            )
        };
        if status2 != ERROR_SUCCESS {
            return Err(CatError::Process(format!(
                "RegQueryValueExW({name}) read failed with code {status2}"
            )));
        }
        let unit_count = (actual_bytes as usize) / 2;
        buf.truncate(unit_count);
        while buf.last() == Some(&0) {
            buf.pop();
        }
        Ok(Some(String::from_utf16_lossy(&buf)))
    }
}

impl Drop for RegKeyGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Handle was obtained via RegOpenKeyExW / RegCreateKeyExW.
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_proxy_server_variants() {
        assert_eq!(parse_proxy_server("127.0.0.1:7890"), ("127.0.0.1".into(), 7890));
        assert_eq!(
            parse_proxy_server("http=127.0.0.1:27890;https=127.0.0.1:27890"),
            ("127.0.0.1".into(), 27890)
        );
        assert_eq!(parse_proxy_server("[::1]:10808"), ("::1".into(), 10808));
        assert_eq!(parse_proxy_server(""), ("127.0.0.1".into(), 7890));
    }

    #[test]
    fn detect_proxy_drift_catches_tampering() {
        let expected = SystemProxySpec {
            enabled: true,
            host: "127.0.0.1".into(),
            port: 27890,
            bypass: vec!["localhost".into(), "127.*".into(), "<local>".into()],
            pac_url: None,
        };
        let matching = SystemProxySpec {
            enabled: true,
            host: "127.0.0.1".into(),
            port: 27890,
            bypass: vec!["<local>".into(), "localhost".into(), "127.*".into()],
            pac_url: None,
        };
        assert!(detect_proxy_drift(&matching, &expected).is_none());

        let changed_port = SystemProxySpec {
            port: 10809,
            ..matching.clone()
        };
        assert!(detect_proxy_drift(&changed_port, &expected).is_some());

        let disabled = SystemProxySpec {
            enabled: false,
            ..matching
        };
        assert!(detect_proxy_drift(&disabled, &expected).is_some());
    }

    #[test]
    fn export_shell_snippets_cover_all_shells() {
        let p = WindowsPlatform::new();
        let ps = p.export_shell_env_snippet("powershell", "127.0.0.1", 7890, 7891);
        assert!(ps.contains("$env:HTTP_PROXY=\"http://127.0.0.1:7890\""));
        assert!(ps.contains("$env:ALL_PROXY=\"socks5h://127.0.0.1:7891\""));

        let cmd = p.export_shell_env_snippet("cmd", "127.0.0.1", 7890, 7891);
        assert!(cmd.contains("set HTTP_PROXY=http://127.0.0.1:7890"));
        assert!(cmd.contains("set ALL_PROXY=socks5h://127.0.0.1:7891"));

        let bash = p.export_shell_env_snippet("bash", "127.0.0.1", 7890, 7891);
        assert!(bash.contains("export HTTP_PROXY=\"http://127.0.0.1:7890\""));
        assert!(bash.contains("export ALL_PROXY=\"socks5h://127.0.0.1:7891\""));
    }

    #[test]
    fn read_system_proxy_readonly_succeeds() {
        let p = WindowsPlatform::new();
        // Pure read-only check: must never modify the live user registry.
        let spec = p.read_system_proxy().expect("read HKCU Internet Settings");
        assert!(!spec.host.is_empty());
    }

    #[test]
    fn autostart_lnk_roundtrip_in_temp_dir() {
        let p = WindowsPlatform::new();
        let tmp_dir = std::env::temp_dir().join(format!(
            "catcloud-lnk-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let exe = std::env::current_exe().unwrap();

        assert!(!p.is_autostart_enabled_in_dir(&tmp_dir));
        p.set_autostart_in_dir(&tmp_dir, true, &exe, &["--minimized".into()])
            .expect("create .lnk in temp dir");
        assert!(p.is_autostart_enabled_in_dir(&tmp_dir));
        let meta = std::fs::metadata(tmp_dir.join(STARTUP_SHORTCUT_NAME)).unwrap();
        assert!(meta.len() > 64, "created .lnk should be a non-empty shortcut");

        p.set_autostart_in_dir(&tmp_dir, false, &exe, &[])
            .expect("remove .lnk in temp dir");
        assert!(!p.is_autostart_enabled_in_dir(&tmp_dir));

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
