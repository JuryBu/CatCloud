use super::common::{
    format_shell_env_snippet, macos_bypass_command_args, parse_macos_network_services,
    render_macos_launch_agent_plist,
};
use super::{PlatformAdapter, PlatformCapabilities, SystemProxySpec};
use crate::error::{CatError, CatResult};
use std::path::{Path, PathBuf};
use std::process::Command;

const LAUNCH_AGENT_FILENAME: &str = "io.catcloud.app.plist";

#[derive(Debug, Default, Clone, Copy)]
pub struct MacosPlatform;

impl MacosPlatform {
    pub fn new() -> Self {
        Self
    }

    /// Reconcile live macOS networksetup proxy configuration against `expected`.
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
        agents_dir: &Path,
        enabled: bool,
        exe_path: &Path,
        args: &[String],
    ) -> CatResult<()> {
        let plist_path = agents_dir.join(LAUNCH_AGENT_FILENAME);
        if !enabled {
            if plist_path.exists() {
                std::fs::remove_file(&plist_path)?;
            }
            return Ok(());
        }

        std::fs::create_dir_all(agents_dir)?;
        let plist = render_launch_agent_plist(exe_path, args);
        crate::paths::AppPaths::atomic_write(&plist_path, plist.as_bytes())?;
        Ok(())
    }

    pub fn is_autostart_enabled_in_dir(&self, agents_dir: &Path) -> bool {
        agents_dir.join(LAUNCH_AGENT_FILENAME).is_file()
    }
}

impl PlatformAdapter for MacosPlatform {
    fn capabilities(&self) -> PlatformCapabilities {
        // SAFETY: `geteuid()` is a standard POSIX syscall with no preconditions.
        let is_elevated = unsafe { libc::geteuid() == 0 };
        PlatformCapabilities {
            os: "macos".into(),
            arch: std::env::consts::ARCH.into(),
            supports_uwp_loopback: false,
            supports_tun_service: true,
            is_elevated,
        }
    }

    fn apply_system_proxy(&self, spec: &SystemProxySpec) -> CatResult<()> {
        let services = list_active_network_services()?;
        if services.is_empty() {
            return Err(CatError::Process(
                "no active macOS network services found via networksetup".into(),
            ));
        }

        let pac = spec
            .pac_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());

        let mut applied_count = 0usize;
        let mut last_err: Option<CatError> = None;

        for service in &services {
            match apply_proxy_to_service(service, spec, pac) {
                Ok(()) => applied_count += 1,
                Err(err) => {
                    tracing::warn!(
                        service = %service,
                        error = %err,
                        "failed to update macOS system proxy on network service; continuing to next interface"
                    );
                    last_err = Some(err);
                }
            }
        }

        if applied_count > 0 {
            return Ok(());
        }

        Err(last_err.unwrap_or_else(|| {
            CatError::Process(
                "failed to apply macOS system proxy to any active network service".into(),
            )
        }))
    }

    fn read_system_proxy(&self) -> CatResult<SystemProxySpec> {
        let services = list_active_network_services()?;
        if services.is_empty() {
            return Ok(default_disabled_proxy_spec());
        }

        let mut first_ok: Option<SystemProxySpec> = None;
        for service in &services {
            match read_service_system_proxy(service) {
                Ok(spec) => {
                    if spec.enabled {
                        return Ok(spec);
                    }
                    if first_ok.is_none() {
                        first_ok = Some(spec);
                    }
                }
                Err(err) => {
                    tracing::debug!(
                        service = %service,
                        error = %err,
                        "skipping unreadable macOS network service during read_system_proxy"
                    );
                }
            }
        }

        Ok(first_ok.unwrap_or_else(default_disabled_proxy_spec))
    }

    fn set_autostart(&self, enabled: bool, exe_path: &Path, args: &[String]) -> CatResult<()> {
        let agents_dir = launch_agents_dir()?;
        self.set_autostart_in_dir(&agents_dir, enabled, exe_path, args)
    }

    fn is_autostart_enabled(&self) -> CatResult<bool> {
        let agents_dir = launch_agents_dir()?;
        Ok(self.is_autostart_enabled_in_dir(&agents_dir))
    }

    fn flush_dns(&self) -> CatResult<()> {
        let status = Command::new("dscacheutil")
            .arg("-flushcache")
            .status()
            .map_err(|e| CatError::Process(format!("dscacheutil failed: {e}")))?;
        if !status.success() {
            return Err(CatError::Process(format!(
                "dscacheutil -flushcache exited with {status}"
            )));
        }
        // Best-effort mDNSResponder reload (may require elevated privileges on macOS).
        let _ = Command::new("killall")
            .args(["-HUP", "mDNSResponder"])
            .status();
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

fn apply_proxy_to_service(
    service: &str,
    spec: &SystemProxySpec,
    pac: Option<&str>,
) -> CatResult<()> {
    if !spec.enabled {
        run_networksetup(&["-setwebproxystate", service, "off"])?;
        run_networksetup(&["-setsecurewebproxystate", service, "off"])?;
        run_networksetup(&["-setsocksfirewallproxystate", service, "off"])?;
        run_networksetup(&["-setautoproxystate", service, "off"])?;
        return Ok(());
    }

    if let Some(pac_url) = pac {
        run_networksetup(&["-setwebproxystate", service, "off"])?;
        run_networksetup(&["-setsecurewebproxystate", service, "off"])?;
        run_networksetup(&["-setsocksfirewallproxystate", service, "off"])?;
        run_networksetup(&["-setautoproxyurl", service, pac_url])?;
        run_networksetup(&["-setautoproxystate", service, "on"])?;
        return Ok(());
    }

    let port_str = spec.port.to_string();
    run_networksetup(&["-setautoproxystate", service, "off"])?;
    run_networksetup(&["-setwebproxy", service, &spec.host, &port_str])?;
    run_networksetup(&["-setsecurewebproxy", service, &spec.host, &port_str])?;
    run_networksetup(&["-setsocksfirewallproxy", service, &spec.host, &port_str])?;
    run_networksetup(&["-setwebproxystate", service, "on"])?;
    run_networksetup(&["-setsecurewebproxystate", service, "on"])?;
    run_networksetup(&["-setsocksfirewallproxystate", service, "on"])?;

    let bypass_args = macos_bypass_command_args(&spec.bypass);
    let mut cmd_args: Vec<&str> = Vec::with_capacity(bypass_args.len() + 2);
    cmd_args.push("-setproxybypassdomains");
    cmd_args.push(service);
    for domain in &bypass_args {
        cmd_args.push(domain.as_str());
    }
    run_networksetup(&cmd_args)?;
    Ok(())
}

fn read_service_system_proxy(service: &str) -> CatResult<SystemProxySpec> {
    let web_out = run_networksetup(&["-getwebproxy", service])?;
    let socks_out = run_networksetup(&["-getsocksfirewallproxy", service]).unwrap_or_default();
    let auto_out = run_networksetup(&["-getautoproxyurl", service]).unwrap_or_default();
    let bypass_out = run_networksetup(&["-getproxybypassdomains", service]).unwrap_or_default();

    let web_enabled = parse_kv_field(&web_out, "Enabled")
        .map(|v| v.eq_ignore_ascii_case("yes"))
        .unwrap_or(false);
    let socks_enabled = parse_kv_field(&socks_out, "Enabled")
        .map(|v| v.eq_ignore_ascii_case("yes"))
        .unwrap_or(false);

    let endpoint_source = if web_enabled || !socks_enabled {
        &web_out
    } else {
        &socks_out
    };

    let host = parse_kv_field(endpoint_source, "Server")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "127.0.0.1".into());
    let port = parse_kv_field(endpoint_source, "Port")
        .and_then(|v| v.parse::<u16>().ok())
        .filter(|&p| p > 0)
        .unwrap_or(7890);

    let auto_enabled = parse_kv_field(&auto_out, "Enabled")
        .map(|v| v.eq_ignore_ascii_case("yes"))
        .unwrap_or(false);
    let pac_url = if auto_enabled {
        parse_kv_field(&auto_out, "URL").filter(|v| !v.is_empty() && v != "(null)")
    } else {
        None
    };

    let bypass = bypass_out
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("There aren't any"))
        .map(ToString::to_string)
        .collect();

    Ok(SystemProxySpec {
        enabled: web_enabled || socks_enabled || pac_url.is_some(),
        host,
        port,
        bypass,
        pac_url,
    })
}

fn launch_agents_dir() -> CatResult<PathBuf> {
    let home = std::env::var("HOME")
        .map_err(|_| CatError::Config("HOME environment variable not set".into()))?;
    Ok(PathBuf::from(home).join("Library").join("LaunchAgents"))
}

fn run_networksetup(args: &[&str]) -> CatResult<String> {
    let out = Command::new("networksetup")
        .args(args)
        .output()
        .map_err(|e| CatError::Process(format!("failed to invoke networksetup: {e}")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(CatError::Process(format!(
            "networksetup {:?} failed ({}): {stderr}",
            args, out.status
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn list_active_network_services() -> CatResult<Vec<String>> {
    let raw = run_networksetup(&["-listallnetworkservices"])?;
    Ok(parse_macos_network_services(&raw))
}

fn parse_kv_field(output: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}:");
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(&prefix) {
            return Some(rest.trim().to_string());
        }
    }
    None
}

fn render_launch_agent_plist(exe_path: &Path, args: &[String]) -> String {
    render_macos_launch_agent_plist(exe_path, args)
}
