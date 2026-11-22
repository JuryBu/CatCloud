use super::{PlatformAdapter, PlatformCapabilities, SystemProxySpec};
use crate::error::{CatError, CatResult};
use std::path::{Path, PathBuf};
use std::process::Command;

const LAUNCH_AGENT_LABEL: &str = "io.catcloud.app";
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

        for service in &services {
            if !spec.enabled {
                run_networksetup(&["-setwebproxystate", service, "off"])?;
                run_networksetup(&["-setsecurewebproxystate", service, "off"])?;
                run_networksetup(&["-setautoproxystate", service, "off"])?;
            } else if let Some(pac_url) = pac {
                run_networksetup(&["-setwebproxystate", service, "off"])?;
                run_networksetup(&["-setsecurewebproxystate", service, "off"])?;
                run_networksetup(&["-setautoproxyurl", service, pac_url])?;
                run_networksetup(&["-setautoproxystate", service, "on"])?;
            } else {
                let port_str = spec.port.to_string();
                run_networksetup(&["-setautoproxystate", service, "off"])?;
                run_networksetup(&["-setwebproxy", service, &spec.host, &port_str])?;
                run_networksetup(&["-setsecurewebproxy", service, &spec.host, &port_str])?;
                run_networksetup(&["-setwebproxystate", service, "on"])?;
                run_networksetup(&["-setsecurewebproxystate", service, "on"])?;
                if !spec.bypass.is_empty() {
                    let mut cmd_args: Vec<&str> = Vec::with_capacity(spec.bypass.len() + 2);
                    cmd_args.push("-setproxybypassdomains");
                    cmd_args.push(service);
                    for domain in &spec.bypass {
                        if !domain.trim().is_empty() {
                            cmd_args.push(domain.trim());
                        }
                    }
                    run_networksetup(&cmd_args)?;
                }
            }
        }
        Ok(())
    }

    fn read_system_proxy(&self) -> CatResult<SystemProxySpec> {
        let services = list_active_network_services()?;
        let Some(primary) = services.first() else {
            return Ok(SystemProxySpec {
                enabled: false,
                host: "127.0.0.1".into(),
                port: 7890,
                bypass: Vec::new(),
                pac_url: None,
            });
        };

        let web_out = run_networksetup(&["-getwebproxy", primary])?;
        let auto_out = run_networksetup(&["-getautoproxyurl", primary]).unwrap_or_default();
        let bypass_out = run_networksetup(&["-getproxybypassdomains", primary]).unwrap_or_default();

        let web_enabled = parse_kv_field(&web_out, "Enabled")
            .map(|v| v.eq_ignore_ascii_case("yes"))
            .unwrap_or(false);
        let host = parse_kv_field(&web_out, "Server")
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "127.0.0.1".into());
        let port = parse_kv_field(&web_out, "Port")
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
            enabled: web_enabled || pac_url.is_some(),
            host,
            port,
            bypass,
            pac_url,
        })
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
    let mut services: Vec<String> = raw
        .lines()
        .skip(1)
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('*'))
        .map(ToString::to_string)
        .collect();
    // Prioritize Wi-Fi / Ethernet at front so read_system_proxy inspects the primary interface.
    services.sort_by_key(|name| {
        if name.eq_ignore_ascii_case("Wi-Fi") {
            0
        } else if name.contains("Ethernet") || name.contains("LAN") {
            1
        } else {
            2
        }
    });
    Ok(services)
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

fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn render_launch_agent_plist(exe_path: &Path, args: &[String]) -> String {
    let mut prog_args = String::new();
    prog_args.push_str(&format!(
        "        <string>{}</string>\n",
        xml_escape(&exe_path.to_string_lossy())
    ));
    for arg in args {
        prog_args.push_str(&format!("        <string>{}</string>\n", xml_escape(arg)));
    }

    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
             <key>Label</key>\n\
             <string>{LAUNCH_AGENT_LABEL}</string>\n\
             <key>ProgramArguments</key>\n\
             <array>\n\
         {prog_args}\
             </array>\n\
             <key>RunAtLoad</key>\n\
             <true/>\n\
             <key>KeepAlive</key>\n\
             <false/>\n\
         </dict>\n\
         </plist>\n"
    )
}
