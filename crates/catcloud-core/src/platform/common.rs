use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Listener socket ownership entry mapping a listening local port and protocol to its owning PID.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortListenerOwner {
    pub port: u16,
    pub protocol: String,
    pub pid: u32,
    pub process_start_time_unix: Option<u64>,
}

/// Query local TCP and UDP listening socket owners matching `ports`.
///
/// - Windows: queries both `GetExtendedTcpTable` (`TCP_TABLE_OWNER_PID_LISTENER`) and
///   `GetExtendedUdpTable` (`UDP_TABLE_OWNER_PID`) across IPv4 and IPv6.
/// - Non-Windows: returns an empty vector as a safe cross-platform fallback.
pub fn list_listening_port_owners(ports: &[u16]) -> Vec<PortListenerOwner> {
    if ports.is_empty() {
        return Vec::new();
    }
    #[cfg(target_os = "windows")]
    {
        super::windows::list_listening_port_owners_windows(ports)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = ports;
        Vec::new()
    }
}

/// Return the process creation timestamp (Unix epoch seconds) for `pid`, or `None` if the process
/// does not exist or cannot be queried.
///
/// - Windows: uses `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `GetProcessTimes`.
/// - Non-Windows: lightweight `sysinfo` single-PID query fallback.
pub fn get_process_start_time_unix(pid: u32) -> Option<u64> {
    if pid == 0 {
        return None;
    }
    #[cfg(target_os = "windows")]
    {
        super::windows::get_process_start_time_unix_windows(pid)
    }
    #[cfg(not(target_os = "windows"))]
    {
        use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};
        let target = Pid::from_u32(pid);
        let mut system = System::new_with_specifics(RefreshKind::nothing());
        system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[target]),
            true,
            ProcessRefreshKind::nothing(),
        );
        let proc_info = system.process(target)?;
        let start = proc_info.start_time();
        (start > 0).then_some(start)
    }
}

pub const LAUNCH_AGENT_LABEL: &str = "io.catcloud.app";

/// Default Windows WinINet `ProxyOverride` string with explicit `127.0.0.1` and `[::1]`
/// right after `localhost` so Rust/CLI HTTP clients that ignore `127.*` wildcards stay direct
/// while remaining 100% valid for `WinHttpOpen` / Schannel (bare `::1` triggers Win32 Error 87).
pub const DEFAULT_WINDOWS_PROXY_BYPASS: &str = "localhost;127.0.0.1;[::1];127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>";

/// Default Linux desktop bypass list with explicit `127.0.0.1` and `::1` right after `localhost`.
pub const DEFAULT_LINUX_PROXY_BYPASS: &[&str] = &[
    "localhost",
    "127.0.0.1",
    "::1",
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "*.local",
];

/// Default macOS `networksetup` bypass list with explicit `127.0.0.1` and `::1` right after `localhost`.
pub const DEFAULT_MACOS_PROXY_BYPASS: &[&str] = &[
    "localhost",
    "127.0.0.1",
    "::1",
    "127.*",
    "10.*",
    "172.16.*",
    "192.168.*",
    "*.local",
];

/// Classified Linux desktop environment hint derived from `XDG_CURRENT_DESKTOP` / `KDE_FULL_SESSION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxDesktopHint {
    Kde,
    Gnome,
    Unknown,
}

/// Sanitize a proxy bind host for shell snippets or proxy URLs, wrapping bare IPv6 literals in `[...]`.
pub fn sanitize_shell_host(host: &str) -> String {
    let trimmed = host.trim();
    if trimmed.is_empty()
        || trimmed.chars().any(|c| {
            c.is_control()
                || matches!(c, '"' | '\'' | ';' | '\n' | '\r' | ' ' | '$' | '`' | '\\')
        })
    {
        return "127.0.0.1".into();
    }
    if let Some(inner) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        if !inner.is_empty() && !inner.contains('[') && !inner.contains(']') {
            return trimmed.to_string();
        }
        return "127.0.0.1".into();
    }
    if trimmed.contains('[') || trimmed.contains(']') {
        return "127.0.0.1".into();
    }
    if trimmed.contains(':') {
        format!("[{trimmed}]")
    } else {
        trimmed.to_string()
    }
}

/// Format shell proxy environment variable export commands across `bash`, `zsh`, `sh`, `fish`,
/// `powershell`, and `cmd`.
///
/// - Automatically wraps bare IPv6 hosts in `[...]`.
/// - Always emits both `NO_PROXY` and `no_proxy` (`localhost,127.0.0.1,::1`) across every shell
///   so CLI/Rust/Node/Python HTTP clients never route loopback traffic through the mixed proxy port.
/// - Emits both uppercase and lowercase proxy variables for POSIX shells (`bash`/`zsh`/`sh`) and `fish`.
/// - When `default_posix` is `true`, unknown shell names fall back to POSIX `export` syntax;
///   otherwise they fall back to PowerShell syntax.
pub fn format_shell_env_snippet(
    shell: &str,
    host: &str,
    http_port: u16,
    socks_port: u16,
    default_posix: bool,
) -> String {
    let clean_host = sanitize_shell_host(host);
    let http_url = format!("http://{clean_host}:{http_port}");
    let socks_url = format!("socks5h://{clean_host}:{socks_port}");
    let no_proxy = "localhost,127.0.0.1,::1";

    let lowered = shell
        .trim()
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(shell)
        .trim()
        .to_ascii_lowercase();
    let normalized = lowered.strip_suffix(".exe").unwrap_or(&lowered);

    let render_posix = || {
        format!(
            "export HTTP_PROXY=\"{http_url}\"\n\
             export HTTPS_PROXY=\"{http_url}\"\n\
             export ALL_PROXY=\"{socks_url}\"\n\
             export NO_PROXY=\"{no_proxy}\"\n\
             export http_proxy=\"{http_url}\"\n\
             export https_proxy=\"{http_url}\"\n\
             export all_proxy=\"{socks_url}\"\n\
             export no_proxy=\"{no_proxy}\""
        )
    };

    let render_powershell = || {
        format!(
            "$env:HTTP_PROXY=\"{http_url}\"\n\
             $env:HTTPS_PROXY=\"{http_url}\"\n\
             $env:ALL_PROXY=\"{socks_url}\"\n\
             $env:NO_PROXY=\"{no_proxy}\"\n\
             $env:no_proxy=\"{no_proxy}\""
        )
    };

    match normalized {
        "fish" => format!(
            "set -gx HTTP_PROXY \"{http_url}\"\n\
             set -gx HTTPS_PROXY \"{http_url}\"\n\
             set -gx ALL_PROXY \"{socks_url}\"\n\
             set -gx NO_PROXY \"{no_proxy}\"\n\
             set -gx http_proxy \"{http_url}\"\n\
             set -gx https_proxy \"{http_url}\"\n\
             set -gx all_proxy \"{socks_url}\"\n\
             set -gx no_proxy \"{no_proxy}\""
        ),
        "cmd" | "bat" | "commandprompt" => format!(
            "set HTTP_PROXY={http_url}\r\n\
             set HTTPS_PROXY={http_url}\r\n\
             set ALL_PROXY={socks_url}\r\n\
             set NO_PROXY={no_proxy}\r\n\
             set no_proxy={no_proxy}"
        ),
        "powershell" | "pwsh" | "ps" => render_powershell(),
        "bash" | "zsh" | "sh" | "gitbash" => render_posix(),
        _ if default_posix => render_posix(),
        _ => render_powershell(),
    }
}

/// Classify the active Linux desktop environment from `XDG_CURRENT_DESKTOP` and `KDE_FULL_SESSION`.
pub fn classify_linux_desktop(
    xdg_current_desktop: Option<&str>,
    kde_full_session: Option<&str>,
) -> LinuxDesktopHint {
    if let Some(raw) = xdg_current_desktop {
        for token in raw.split([':', ';']) {
            let upper = token.trim().to_ascii_uppercase();
            if upper.is_empty() {
                continue;
            }
            if upper.contains("KDE") || upper.contains("PLASMA") {
                return LinuxDesktopHint::Kde;
            }
            if upper.contains("GNOME")
                || upper.contains("UBUNTU")
                || upper.contains("CINNAMON")
                || upper.contains("MATE")
                || upper.contains("BUDGIE")
                || upper.contains("UNITY")
                || upper.contains("PANTHEON")
            {
                return LinuxDesktopHint::Gnome;
            }
        }
    }
    if let Some(kde_session) = kde_full_session {
        let trimmed = kde_session.trim();
        if trimmed.eq_ignore_ascii_case("true") || trimmed == "1" {
            return LinuxDesktopHint::Kde;
        }
    }
    LinuxDesktopHint::Unknown
}

fn push_unique_ci(out: &mut Vec<String>, candidate: &str) {
    if !out
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(candidate))
    {
        out.push(candidate.to_string());
    }
}

fn is_bare_ipv6_entry(entry: &str) -> bool {
    if entry.contains("://") || entry.contains('/') {
        return false;
    }
    if entry.starts_with('[') && (entry.ends_with(']') || entry.contains("]:")) {
        return false;
    }
    entry.bytes().filter(|&b| b == b':').count() >= 2
}

fn has_invalid_slash_in_windows_bypass(entry: &str) -> bool {
    if let Some((_, after_scheme)) = entry.split_once("://") {
        after_scheme.contains('/')
    } else {
        entry.contains('/')
    }
}

fn strip_pure_ipv6_brackets(entry: &str) -> &str {
    if let Some(inner) = entry.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        if !inner.is_empty()
            && !inner.contains('[')
            && !inner.contains(']')
            && inner.bytes().filter(|&b| b == b':').count() >= 2
        {
            return inner;
        }
    }
    entry
}

/// Inspect a raw Windows `ProxyOverride` registry value (semicolon-delimited) and return all
/// entries that will cause `WinHttpOpen` / Schannel (`cryptnet.dll`) to fail with Win32 Error 87
/// (`ERROR_INVALID_PARAMETER`), such as bare unbracketed IPv6 literals (`::1`, `fe80::*`) or
/// slash-delimited CIDR blocks (`10.0.0.0/8`, `fe80::/10`).
pub fn find_invalid_windows_proxy_override_entries(raw: &str) -> Vec<String> {
    let mut invalid = Vec::new();
    for part in raw.split(';') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let has_scheme_bare_v6 = trimmed
            .split_once("://")
            .is_some_and(|(_, after)| is_bare_ipv6_entry(after));
        if trimmed.chars().any(char::is_control)
            || is_bare_ipv6_entry(trimmed)
            || has_invalid_slash_in_windows_bypass(trimmed)
            || has_scheme_bare_v6
        {
            invalid.push(trimmed.to_string());
        }
    }
    invalid
}

fn normalize_windows_bypass_entry(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
        return Vec::new();
    }

    match trimmed {
        "127.0.0.0/8" => return vec!["127.*".to_string()],
        "10.0.0.0/8" => return vec!["10.*".to_string()],
        "192.168.0.0/16" => return vec!["192.168.*".to_string()],
        "172.16.0.0/12" => {
            return (16..=31).map(|octet| format!("172.{octet}.*")).collect();
        }
        _ => {}
    }

    if has_invalid_slash_in_windows_bypass(trimmed) {
        return Vec::new();
    }

    if let Some((scheme, after)) = trimmed.split_once("://") {
        if is_bare_ipv6_entry(after) {
            let inner = after.trim_matches(|c| c == '[' || c == ']');
            if inner.is_empty() {
                return Vec::new();
            }
            return vec![format!("{scheme}://[{inner}]")];
        }
        return vec![trimmed.to_string()];
    }

    if is_bare_ipv6_entry(trimmed) {
        let inner = trimmed.trim_matches(|c| c == '[' || c == ']');
        if inner.is_empty() {
            return Vec::new();
        }
        return vec![format!("[{inner}]")];
    }

    vec![trimmed.to_string()]
}

/// Sanitize a Windows WinINet / WinHTTP bypass list:
/// - Wraps bare IPv6 literals/wildcards (`::1`, `fe80::*`, etc.) in `[...]` so `WinHttpOpen` /
///   Schannel revocation checks never fail with `ERROR_INVALID_PARAMETER (87)`;
/// - Converts common private IPv4 CIDRs (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`,
///   `192.168.0.0/16`) into valid Windows wildcard entries and strips unconvertible `/` CIDRs
///   (such as `fe80::/10`);
/// - Preserves valid `host:port` entries (single colon);
/// - Falls back to `DEFAULT_WINDOWS_PROXY_BYPASS` when empty, and ensures explicit `127.0.0.1`
///   and `[::1]` follow `localhost` (deduplicated case-insensitively).
pub fn sanitize_windows_bypass_list(items: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut has_loopback_rule = false;
    for item in items {
        for entry in normalize_windows_bypass_entry(item) {
            push_unique_ci(&mut out, &entry);
            if entry.eq_ignore_ascii_case("localhost") {
                has_loopback_rule = true;
                push_unique_ci(&mut out, "127.0.0.1");
                push_unique_ci(&mut out, "[::1]");
            } else if entry == "127.*" || entry.eq_ignore_ascii_case("<local>") {
                has_loopback_rule = true;
            }
        }
    }

    if out.is_empty() {
        return DEFAULT_WINDOWS_PROXY_BYPASS
            .split(';')
            .map(ToString::to_string)
            .collect();
    }

    if has_loopback_rule {
        push_unique_ci(&mut out, "127.0.0.1");
        push_unique_ci(&mut out, "[::1]");
    }
    out
}

/// Sanitize a system proxy bypass list for Linux desktop environments (GNOME & KDE Plasma).
/// Replaces Windows WinINet `<local>` syntax with `localhost`, `127.0.0.1`, `::1`, and `127.0.0.0/8`,
/// strips pure IPv6 brackets (`[::1]` -> `::1`) to prevent cross-platform duplication,
/// ensures explicit `127.0.0.1` and `::1` follow `localhost` for loopback lists,
/// and deduplicates case-insensitively while preserving order.
pub fn sanitize_linux_bypass_list(items: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut has_loopback_rule = false;
    for item in items {
        let trimmed = item.trim();
        if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
            continue;
        }
        let normalized = strip_pure_ipv6_brackets(trimmed);
        if normalized.eq_ignore_ascii_case("<local>") {
            has_loopback_rule = true;
            push_unique_ci(&mut out, "localhost");
            push_unique_ci(&mut out, "127.0.0.1");
            push_unique_ci(&mut out, "::1");
            push_unique_ci(&mut out, "127.0.0.0/8");
        } else {
            push_unique_ci(&mut out, normalized);
            if normalized.eq_ignore_ascii_case("localhost") {
                has_loopback_rule = true;
                push_unique_ci(&mut out, "127.0.0.1");
                push_unique_ci(&mut out, "::1");
            } else if normalized == "127.*" || normalized == "127.0.0.0/8" {
                has_loopback_rule = true;
            }
        }
    }
    if has_loopback_rule {
        push_unique_ci(&mut out, "127.0.0.1");
        push_unique_ci(&mut out, "::1");
    }
    out
}

pub fn gsettings_quote(val: &str) -> String {
    let escaped = val.replace('\\', "\\\\").replace('\'', "\\'");
    format!("'{escaped}'")
}

/// Format a sanitized bypass list as a GNOME `gsettings` `as` string array literal.
pub fn format_gsettings_bypass_list(items: &[String]) -> String {
    let sanitized = sanitize_linux_bypass_list(items);
    let quoted: Vec<String> = sanitized.iter().map(|s| gsettings_quote(s)).collect();
    format!("[{}]", quoted.join(", "))
}

/// Format a sanitized bypass list for KDE `kioslaverc` `[Proxy Settings] NoProxyFor`.
pub fn format_kde_no_proxy_for(items: &[String]) -> String {
    sanitize_linux_bypass_list(items).join(",")
}

/// Format a KDE `kioslaverc` proxy URL (`httpProxy` / `httpsProxy` / `socksProxy`).
pub fn format_kde_proxy_url(scheme: &str, host: &str, port: u16) -> String {
    let clean_host = sanitize_shell_host(host);
    format!("{scheme}://{clean_host}:{port}")
}

/// Parse a KDE `kioslaverc` proxy endpoint string such as `http://127.0.0.1:7890`,
/// legacy space-separated `http://127.0.0.1 7890`, or IPv6 `http://[::1]:7890`.
pub fn parse_kde_proxy_endpoint(raw: &str) -> Option<(String, u16)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let without_scheme = match trimmed.split_once("://") {
        Some((_, rest)) => rest.trim(),
        None => trimmed,
    };
    let without_path = without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme)
        .trim();
    if without_path.is_empty() {
        return None;
    }

    if let Some(rest) = without_path.strip_prefix('[') {
        if let Some((ip, tail)) = rest.split_once(']') {
            let port_str = tail.trim().trim_start_matches(':').trim();
            let port = port_str.parse::<u16>().ok().filter(|&p| p > 0)?;
            let host = ip.trim();
            if !host.is_empty() {
                return Some((host.to_string(), port));
            }
        }
        return None;
    }

    let (host_raw, port_raw) = without_path
        .rsplit_once(':')
        .or_else(|| without_path.rsplit_once(' '))?;
    let host = host_raw.trim();
    let port = port_raw.trim().parse::<u16>().ok().filter(|&p| p > 0)?;
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port))
}

/// Parse `getcap <binary>` output to check whether `cap_net_admin` is effective and permitted (`ep`).
pub fn parse_getcap_has_net_admin(output: &str) -> bool {
    for token in output.split_whitespace() {
        let lower = token.to_ascii_lowercase();
        if !lower.contains("cap_net_admin") {
            continue;
        }
        if let Some(pos) = lower.rfind(['=', '+']) {
            let flags = &lower[pos + 1..];
            if flags.contains('e') && flags.contains('p') {
                return true;
            }
        }
    }
    false
}

/// Determine whether a non-zero `pkexec` exit indicates user cancellation / Polkit dismissal.
pub fn is_pkexec_user_cancelled(exit_code: Option<i32>, stderr: &str) -> bool {
    if exit_code == Some(126) {
        return true;
    }
    let lower = stderr.to_ascii_lowercase();
    lower.contains("dismissed")
        || lower.contains("canceled")
        || lower.contains("cancelled")
        || lower.contains("not authorized")
}

/// Resolve the persistent Linux executable path, preferring a valid existing `$APPIMAGE`
/// file over an ephemeral `/tmp/.mount_*` FUSE mountpoint.
pub fn resolve_persistent_linux_exe_path(exe_path: &Path) -> PathBuf {
    let appimage = std::env::var_os("APPIMAGE");
    resolve_persistent_linux_exe_path_with_env(exe_path, appimage.as_deref())
}

/// Deterministic helper for `resolve_persistent_linux_exe_path` accepting an explicit `APPIMAGE` value.
pub fn resolve_persistent_linux_exe_path_with_env(
    exe_path: &Path,
    appimage_env: Option<&OsStr>,
) -> PathBuf {
    if let Some(raw) = appimage_env {
        let raw_str = raw.to_string_lossy();
        let trimmed = raw_str.trim();
        if !trimmed.is_empty() && !is_ephemeral_appimage_mount(trimmed) {
            let candidate = PathBuf::from(raw);
            if candidate.is_absolute() && candidate.is_file() {
                return candidate;
            }
        }
    }
    exe_path.to_path_buf()
}

fn is_ephemeral_appimage_mount(path_str: &str) -> bool {
    let normalized = path_str.replace('\\', "/");
    normalized.starts_with("/tmp/.mount_") || normalized.contains("/.mount_")
}

pub fn escape_desktop_exec_arg(arg: &str) -> String {
    if arg.is_empty()
        || arg
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '"' | '\\' | '$' | '`'))
    {
        let escaped = arg
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('$', "\\$")
            .replace('`', "\\`");
        format!("\"{escaped}\"")
    } else {
        arg.to_string()
    }
}

/// Render an XDG autostart `.desktop` entry using the persistent Linux executable path (`$APPIMAGE`-aware).
pub fn render_linux_desktop_entry(exe_path: &Path, args: &[String]) -> String {
    let appimage = std::env::var_os("APPIMAGE");
    render_linux_desktop_entry_with_env(exe_path, args, appimage.as_deref())
}

/// Deterministic helper for `render_linux_desktop_entry` accepting an explicit `APPIMAGE` env value.
pub fn render_linux_desktop_entry_with_env(
    exe_path: &Path,
    args: &[String],
    appimage_env: Option<&OsStr>,
) -> String {
    let persistent_exe = resolve_persistent_linux_exe_path_with_env(exe_path, appimage_env);
    let mut parts = Vec::with_capacity(args.len() + 1);
    parts.push(escape_desktop_exec_arg(&persistent_exe.to_string_lossy()));
    for arg in args {
        parts.push(escape_desktop_exec_arg(arg));
    }
    let exec_line = parts.join(" ");
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Version=1.0\n\
         Name=CatCloud\n\
         Comment=CatCloud Intelligent Proxy\n\
         Exec={exec_line}\n\
         Terminal=false\n\
         X-GNOME-Autostart-enabled=true\n"
    )
}

/// Clean a bypass domain list for macOS `networksetup -setproxybypassdomains`,
/// removing Windows WinINet `<local>` syntax and blank/control entries, stripping pure IPv6
/// brackets (`[::1]` -> `::1`) to prevent cross-platform duplication, and ensuring
/// explicit `127.0.0.1` and `::1` follow `localhost` whenever loopback entries are present.
pub fn sanitize_macos_bypass_list(items: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut has_loopback_rule = false;
    for item in items {
        let trimmed = item.trim();
        if trimmed.is_empty()
            || trimmed.chars().any(char::is_control)
            || trimmed.eq_ignore_ascii_case("<local>")
        {
            continue;
        }
        let normalized = strip_pure_ipv6_brackets(trimmed);
        push_unique_ci(&mut out, normalized);
        if normalized.eq_ignore_ascii_case("localhost") {
            has_loopback_rule = true;
            push_unique_ci(&mut out, "127.0.0.1");
            push_unique_ci(&mut out, "::1");
        } else if normalized == "127.*" || normalized == "127.0.0.0/8" {
            has_loopback_rule = true;
        }
    }
    if has_loopback_rule {
        push_unique_ci(&mut out, "127.0.0.1");
        push_unique_ci(&mut out, "::1");
    }
    out
}

/// Build arguments for `networksetup -setproxybypassdomains <service> ...`.
/// When the sanitized bypass list is empty, emits `["Empty"]` so macOS genuinely clears prior rules.
pub fn macos_bypass_command_args(items: &[String]) -> Vec<String> {
    let cleaned = sanitize_macos_bypass_list(items);
    if cleaned.is_empty() {
        vec!["Empty".to_string()]
    } else {
        cleaned
    }
}

/// Identify virtual / non-internet macOS network services that should be skipped by default
/// (such as `Thunderbolt Bridge` and `Bluetooth PAN`).
pub fn is_macos_ignored_network_service(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    lower == "thunderbolt bridge"
        || lower == "bluetooth pan"
        || lower == "bluetooth dun"
        || lower == "bluetooth-modem"
        || lower == "firewire"
        || lower == "firewire bridge"
        || lower.starts_with("bluetooth ")
}

/// Parse `networksetup -listallnetworkservices` output, filter disabled (`*`) and virtual
/// non-internet services (falling back to all enabled services if none remain), and prioritize
/// `Wi-Fi` / `Ethernet` / `LAN` at the front.
pub fn parse_macos_network_services(raw: &str) -> Vec<String> {
    let enabled_all: Vec<String> = raw
        .lines()
        .skip(1)
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('*'))
        .map(ToString::to_string)
        .collect();

    let mut filtered: Vec<String> = enabled_all
        .iter()
        .filter(|name| !is_macos_ignored_network_service(name))
        .cloned()
        .collect();

    if filtered.is_empty() {
        filtered = enabled_all;
    }

    filtered.sort_by_key(|name| {
        let lower = name.to_ascii_lowercase();
        if lower == "wi-fi" || lower == "airport" {
            0
        } else if lower.contains("ethernet") || lower.contains("lan") {
            1
        } else {
            2
        }
    });
    filtered
}

pub fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Render a macOS `~/Library/LaunchAgents/io.catcloud.app.plist` with `LimitLoadToSessionType=Aqua`.
pub fn render_macos_launch_agent_plist(exe_path: &Path, args: &[String]) -> String {
    let mut prog_args = String::new();
    prog_args.push_str(&format!(
        "        <string>{}</string>\n",
        xml_escape(&exe_path.to_string_lossy())
    ));
    for arg in args {
        prog_args.push_str(&format!("        <string>{}</string>\n", xml_escape(arg)));
    }

    format!(
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
            "<plist version=\"1.0\">\n",
            "<dict>\n",
            "    <key>Label</key>\n",
            "    <string>{label}</string>\n",
            "    <key>ProgramArguments</key>\n",
            "    <array>\n",
            "{prog_args}",
            "    </array>\n",
            "    <key>LimitLoadToSessionType</key>\n",
            "    <string>Aqua</string>\n",
            "    <key>RunAtLoad</key>\n",
            "    <true/>\n",
            "    <key>KeepAlive</key>\n",
            "    <false/>\n",
            "</dict>\n",
            "</plist>\n"
        ),
        label = LAUNCH_AGENT_LABEL,
        prog_args = prog_args,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_bypass_constants_explicitly_include_loopback_after_localhost() {
        assert!(DEFAULT_WINDOWS_PROXY_BYPASS.starts_with("localhost;127.0.0.1;[::1];127.*;"));
        assert!(find_invalid_windows_proxy_override_entries(DEFAULT_WINDOWS_PROXY_BYPASS).is_empty());
        assert_eq!(&DEFAULT_LINUX_PROXY_BYPASS[..3], &["localhost", "127.0.0.1", "::1"]);
        assert_eq!(&DEFAULT_MACOS_PROXY_BYPASS[..3], &["localhost", "127.0.0.1", "::1"]);

        let win_upgraded = sanitize_windows_bypass_list(&[
            "localhost".to_string(),
            "127.*".to_string(),
            "<local>".to_string(),
        ]);
        assert_eq!(
            win_upgraded,
            vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "[::1]".to_string(),
                "127.*".to_string(),
                "<local>".to_string(),
            ]
        );
        let win_default = sanitize_windows_bypass_list(&[]);
        assert_eq!(
            &win_default[..4],
            &["localhost", "127.0.0.1", "[::1]", "127.*"]
        );

        // Windows sanitization wraps bare IPv6, expands private IPv4 CIDRs, drops unconvertible
        // CIDRs (like fe80::/10), deduplicates `::1` vs `[::1]`, and preserves `host:port`.
        let win_dirty = sanitize_windows_bypass_list(&[
            "localhost".to_string(),
            "::1".to_string(),
            "[::1]".to_string(),
            "fe80::*".to_string(),
            "127.0.0.0/8".to_string(),
            "10.0.0.0/8".to_string(),
            "192.168.0.0/16".to_string(),
            "172.16.0.0/12".to_string(),
            "fe80::/10".to_string(),
            "100.64.0.0/10".to_string(),
            "example.com:8080".to_string(),
            "<local>".to_string(),
        ]);
        assert_eq!(win_dirty.iter().filter(|s| s.as_str() == "[::1]").count(), 1);
        assert!(!win_dirty.iter().any(|s| s == "::1"));
        assert!(win_dirty.contains(&"[fe80::*]".to_string()));
        assert!(win_dirty.contains(&"127.*".to_string()));
        assert!(win_dirty.contains(&"10.*".to_string()));
        assert!(win_dirty.contains(&"192.168.*".to_string()));
        assert!(win_dirty.contains(&"172.16.*".to_string()));
        assert!(win_dirty.contains(&"172.31.*".to_string()));
        assert!(win_dirty.contains(&"example.com:8080".to_string()));
        assert!(!win_dirty.iter().any(|s| s.contains('/')));
        assert!(find_invalid_windows_proxy_override_entries(&win_dirty.join(";")).is_empty());

        let invalid = find_invalid_windows_proxy_override_entries(
            "localhost;127.0.0.1;::1;10.0.0.0/8;fe80::/10;fe80::*;example.com:8080;[::1];<local>",
        );
        assert_eq!(
            invalid,
            vec![
                "::1".to_string(),
                "10.0.0.0/8".to_string(),
                "fe80::/10".to_string(),
                "fe80::*".to_string(),
            ]
        );

        // Linux & macOS sanitizers strip brackets from pure IPv6 (`[::1]` -> `::1`) without duplication.
        let cross_platform = vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "[::1]".to_string(),
            "127.*".to_string(),
        ];
        let linux_clean = sanitize_linux_bypass_list(&cross_platform);
        assert_eq!(linux_clean, vec!["localhost", "127.0.0.1", "::1", "127.*"]);
        let macos_clean = sanitize_macos_bypass_list(&cross_platform);
        assert_eq!(macos_clean, vec!["localhost", "127.0.0.1", "::1", "127.*"]);
    }

    #[test]
    fn linux_bypass_sanitization_replaces_local_and_ensures_explicit_loopback() {
        let input = vec![
            "localhost".to_string(),
            " 192.168.* ".to_string(),
            "<local>".to_string(),
            "LOCALHOST".to_string(),
            "".to_string(),
            "<LOCAL>".to_string(),
        ];
        let cleaned = sanitize_linux_bypass_list(&input);
        assert_eq!(
            cleaned,
            vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "::1".to_string(),
                "192.168.*".to_string(),
                "127.0.0.0/8".to_string(),
            ]
        );
        assert_eq!(
            format_gsettings_bypass_list(&input),
            "['localhost', '127.0.0.1', '::1', '192.168.*', '127.0.0.0/8']"
        );
        assert_eq!(
            format_kde_no_proxy_for(&input),
            "localhost,127.0.0.1,::1,192.168.*,127.0.0.0/8"
        );
        assert_eq!(format_gsettings_bypass_list(&[]), "[]");
        assert_eq!(format_kde_no_proxy_for(&[]), "");
    }

    #[test]
    fn macos_bypass_sanitization_strips_local_adds_loopback_and_emits_empty_when_cleared() {
        let mixed = vec![
            "localhost".to_string(),
            "127.*".to_string(),
            "*.local".to_string(),
            "<local>".to_string(),
            "LOCALHOST".to_string(),
        ];
        assert_eq!(
            sanitize_macos_bypass_list(&mixed),
            vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "::1".to_string(),
                "127.*".to_string(),
                "*.local".to_string(),
            ]
        );
        assert_eq!(
            macos_bypass_command_args(&mixed),
            vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "::1".to_string(),
                "127.*".to_string(),
                "*.local".to_string(),
            ]
        );

        assert_eq!(macos_bypass_command_args(&[]), vec!["Empty".to_string()]);
        assert_eq!(
            macos_bypass_command_args(&["<local>".to_string(), "   ".to_string()]),
            vec!["Empty".to_string()]
        );
    }

    #[test]
    fn shell_env_snippets_support_all_shells_ipv6_and_no_proxy_both_cases() {
        let fish_v6 = format_shell_env_snippet("fish", "::1", 7890, 7891, true);
        assert!(fish_v6.contains("set -gx HTTP_PROXY \"http://[::1]:7890\""));
        assert!(fish_v6.contains("set -gx http_proxy \"http://[::1]:7890\""));
        assert!(fish_v6.contains("set -gx HTTPS_PROXY \"http://[::1]:7890\""));
        assert!(fish_v6.contains("set -gx https_proxy \"http://[::1]:7890\""));
        assert!(fish_v6.contains("set -gx ALL_PROXY \"socks5h://[::1]:7891\""));
        assert!(fish_v6.contains("set -gx all_proxy \"socks5h://[::1]:7891\""));
        assert!(fish_v6.contains("set -gx NO_PROXY \"localhost,127.0.0.1,::1\""));
        assert!(fish_v6.contains("set -gx no_proxy \"localhost,127.0.0.1,::1\""));

        let zsh_v6 = format_shell_env_snippet("/bin/zsh", "2001:db8::1", 27890, 27890, true);
        assert!(zsh_v6.contains("export HTTP_PROXY=\"http://[2001:db8::1]:27890\""));
        assert!(zsh_v6.contains("export http_proxy=\"http://[2001:db8::1]:27890\""));
        assert!(zsh_v6.contains("export ALL_PROXY=\"socks5h://[2001:db8::1]:27890\""));
        assert!(zsh_v6.contains("export all_proxy=\"socks5h://[2001:db8::1]:27890\""));
        assert!(zsh_v6.contains("export NO_PROXY=\"localhost,127.0.0.1,::1\""));
        assert!(zsh_v6.contains("export no_proxy=\"localhost,127.0.0.1,::1\""));

        let ps = format_shell_env_snippet("powershell", "127.0.0.1", 7890, 7891, false);
        assert!(ps.contains("$env:NO_PROXY=\"localhost,127.0.0.1,::1\""));
        assert!(ps.contains("$env:no_proxy=\"localhost,127.0.0.1,::1\""));

        let cmd = format_shell_env_snippet("cmd", "127.0.0.1", 7890, 7891, false);
        assert!(cmd.contains("set NO_PROXY=localhost,127.0.0.1,::1"));
        assert!(cmd.contains("set no_proxy=localhost,127.0.0.1,::1"));

        // Already-bracketed IPv6 must not be double-bracketed.
        let bash_bracketed = format_shell_env_snippet("bash", "[::1]", 7890, 7890, true);
        assert!(bash_bracketed.contains("http://[::1]:7890"));
        assert!(!bash_bracketed.contains("[[::1]]"));
        assert!(bash_bracketed.contains("export NO_PROXY=\"localhost,127.0.0.1,::1\""));
        assert!(bash_bracketed.contains("export no_proxy=\"localhost,127.0.0.1,::1\""));

        // Injection characters fall back to loopback.
        assert_eq!(sanitize_shell_host("127.0.0.1; rm -rf /"), "127.0.0.1");
    }

    #[test]
    fn appimage_path_resolution_prefers_real_existing_appimage_over_mountpoint() {
        let mount_exe = Path::new("/tmp/.mount_CatCloABCDEF/usr/bin/catcloud-desktop");
        let tmp_appimage = std::env::temp_dir().join(format!(
            "catcloud-test-{}.AppImage",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&tmp_appimage, b"stub-appimage").unwrap();

        let resolved =
            resolve_persistent_linux_exe_path_with_env(mount_exe, Some(tmp_appimage.as_os_str()));
        assert_eq!(resolved, tmp_appimage);

        let desktop = render_linux_desktop_entry_with_env(
            mount_exe,
            &["--minimized".to_string()],
            Some(tmp_appimage.as_os_str()),
        );
        let expected_exec = escape_desktop_exec_arg(&tmp_appimage.to_string_lossy());
        assert!(
            desktop.contains(&expected_exec),
            "expected escaped AppImage path `{expected_exec}` in desktop entry:\n{desktop}"
        );
        assert!(!desktop.contains("/tmp/.mount_"));
        assert!(desktop.contains("--minimized"));

        // Missing or ephemeral $APPIMAGE falls back safely to exe_path.
        let missing = std::env::temp_dir().join("catcloud-does-not-exist.AppImage");
        assert_eq!(
            resolve_persistent_linux_exe_path_with_env(mount_exe, Some(missing.as_os_str())),
            mount_exe
        );
        assert_eq!(
            resolve_persistent_linux_exe_path_with_env(
                mount_exe,
                Some(OsStr::new("/tmp/.mount_CatCloABCDEF/CatCloud.AppImage"))
            ),
            mount_exe
        );
        assert_eq!(
            resolve_persistent_linux_exe_path_with_env(mount_exe, None),
            mount_exe
        );

        let _ = std::fs::remove_file(&tmp_appimage);
    }

    #[test]
    fn macos_launch_agent_plist_includes_aqua_session_type_and_escapes_xml() {
        let plist = render_macos_launch_agent_plist(
            Path::new("/Applications/CatCloud.app/Contents/MacOS/CatCloud"),
            &["--data-dir".to_string(), "/Users/catcloud/A&B".to_string()],
        );
        assert!(plist.contains("<key>Label</key>\n    <string>io.catcloud.app</string>"));
        assert!(
            plist.contains("<key>LimitLoadToSessionType</key>\n    <string>Aqua</string>"),
            "LaunchAgent plist must restrict loading to Aqua GUI session: {plist}"
        );
        assert!(plist.contains("/Applications/CatCloud.app/Contents/MacOS/CatCloud"));
        assert!(plist.contains("/Users/catcloud/A&amp;B"));
    }

    #[test]
    fn linux_desktop_classification_kde_endpoint_and_getcap_parsing() {
        assert_eq!(
            classify_linux_desktop(Some("KDE"), None),
            LinuxDesktopHint::Kde
        );
        assert_eq!(
            classify_linux_desktop(Some("ubuntu:GNOME"), None),
            LinuxDesktopHint::Gnome
        );
        assert_eq!(
            classify_linux_desktop(None, Some("true")),
            LinuxDesktopHint::Kde
        );
        assert_eq!(classify_linux_desktop(None, None), LinuxDesktopHint::Unknown);

        assert_eq!(
            parse_kde_proxy_endpoint("http://127.0.0.1:7890"),
            Some(("127.0.0.1".to_string(), 7890))
        );
        assert_eq!(
            parse_kde_proxy_endpoint("http://127.0.0.1 27890"),
            Some(("127.0.0.1".to_string(), 27890))
        );
        assert_eq!(
            parse_kde_proxy_endpoint("http://[::1]:7890"),
            Some(("::1".to_string(), 7890))
        );
        assert_eq!(
            parse_kde_proxy_endpoint("socks://[::1] 7891"),
            Some(("::1".to_string(), 7891))
        );
        assert_eq!(parse_kde_proxy_endpoint(""), None);

        assert!(parse_getcap_has_net_admin(
            "/home/catcloud/.local/share/catcloud/bin/mihomo cap_net_bind_service,cap_net_admin=ep"
        ));
        assert!(parse_getcap_has_net_admin(
            "/home/catcloud/mihomo = cap_net_admin,cap_net_bind_service+ep"
        ));
        assert!(!parse_getcap_has_net_admin(
            "/home/catcloud/mihomo cap_net_admin=p"
        ));
        assert!(!parse_getcap_has_net_admin(""));

        assert!(is_pkexec_user_cancelled(Some(126), ""));
        assert!(is_pkexec_user_cancelled(
            Some(127),
            "Error executing command as another user: Request dismissed"
        ));
        assert!(!is_pkexec_user_cancelled(
            Some(1),
            "Failed to set capabilities on file"
        ));
    }

    #[test]
    fn macos_network_services_filters_virtual_bridges_and_prioritizes_wifi() {
        let sample = "\
An asterisk (*) denotes that a network service is disabled.
Thunderbolt Bridge
Bluetooth PAN
USB 10/100/1000 LAN
Wi-Fi
*Disabled VPN
";
        let services = parse_macos_network_services(sample);
        assert_eq!(
            services,
            vec!["Wi-Fi".to_string(), "USB 10/100/1000 LAN".to_string()]
        );

        // Fallback keeps virtual service if it is the sole enabled service.
        let only_bt = "An asterisk (*) denotes that a network service is disabled.\nBluetooth PAN\n";
        assert_eq!(
            parse_macos_network_services(only_bt),
            vec!["Bluetooth PAN".to_string()]
        );
    }
}
