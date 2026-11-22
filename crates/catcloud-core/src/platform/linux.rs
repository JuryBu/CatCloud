use super::{PlatformAdapter, PlatformCapabilities, SystemProxySpec};
use crate::error::{CatError, CatResult};
use std::path::{Path, PathBuf};
use std::process::Command;

const DESKTOP_ENTRY_FILENAME: &str = "catcloud.desktop";
const GNOME_PROXY_SCHEMA: &str = "org.gnome.system.proxy";

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
        let content = render_desktop_entry(exe_path, args);
        crate::paths::AppPaths::atomic_write(&desktop_path, content.as_bytes())?;
        Ok(())
    }

    pub fn is_autostart_enabled_in_dir(&self, autostart_dir: &Path) -> bool {
        autostart_dir.join(DESKTOP_ENTRY_FILENAME).is_file()
    }
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

        if !spec.bypass.is_empty() {
            let formatted_list = format_gsettings_str_list(&spec.bypass);
            run_gsettings(&["set", GNOME_PROXY_SCHEMA, "ignore-hosts", &formatted_list])?;
        }

        run_gsettings(&["set", GNOME_PROXY_SCHEMA, "mode", "'manual'"])?;
        Ok(())
    }

    fn read_system_proxy(&self) -> CatResult<SystemProxySpec> {
        let mode = match run_gsettings(&["get", GNOME_PROXY_SCHEMA, "mode"]) {
            Ok(val) => strip_gsettings_quotes(&val),
            Err(_) => {
                // Headless or non-GNOME environment without gsettings schema.
                return Ok(SystemProxySpec {
                    enabled: false,
                    host: "127.0.0.1".into(),
                    port: 7890,
                    bypass: Vec::new(),
                    pac_url: None,
                });
            }
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

    fn set_autostart(&self, enabled: bool, exe_path: &Path, args: &[String]) -> CatResult<()> {
        let dir = xdg_autostart_dir()?;
        self.set_autostart_in_dir(&dir, enabled, exe_path, args)
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
        let http_url = format!("http://{host}:{http_port}");
        let socks_url = format!("socks5h://{host}:{socks_port}");
        let no_proxy = "localhost,127.0.0.1,::1";
        match shell.trim().to_ascii_lowercase().as_str() {
            "fish" => format!(
                "set -gx HTTP_PROXY \"{http_url}\"\nset -gx HTTPS_PROXY \"{http_url}\"\nset -gx ALL_PROXY \"{socks_url}\"\nset -gx NO_PROXY \"{no_proxy}\""
            ),
            "powershell" | "pwsh" | "ps" => format!(
                "$env:HTTP_PROXY=\"{http_url}\"\n$env:HTTPS_PROXY=\"{http_url}\"\n$env:ALL_PROXY=\"{socks_url}\"\n$env:NO_PROXY=\"{no_proxy}\""
            ),
            "cmd" | "bat" => format!(
                "set HTTP_PROXY={http_url}\nset HTTPS_PROXY={http_url}\nset ALL_PROXY={socks_url}\nset NO_PROXY={no_proxy}"
            ),
            _ => format!(
                "export HTTP_PROXY=\"{http_url}\"\nexport HTTPS_PROXY=\"{http_url}\"\nexport ALL_PROXY=\"{socks_url}\"\nexport NO_PROXY=\"{no_proxy}\""
            ),
        }
    }
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

fn gsettings_quote(val: &str) -> String {
    let escaped = val.replace('\\', "\\\\").replace('\'', "\\'");
    format!("'{escaped}'")
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

fn format_gsettings_str_list(items: &[String]) -> String {
    let quoted: Vec<String> = items
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(gsettings_quote)
        .collect();
    format!("[{}]", quoted.join(", "))
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

fn escape_desktop_exec_arg(arg: &str) -> String {
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

fn render_desktop_entry(exe_path: &Path, args: &[String]) -> String {
    let mut parts = Vec::with_capacity(args.len() + 1);
    parts.push(escape_desktop_exec_arg(&exe_path.to_string_lossy()));
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
