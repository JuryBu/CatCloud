use crate::error::CatResult;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub mod common;
#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "linux")]
pub mod linux;

pub use common::{
    DEFAULT_LINUX_PROXY_BYPASS, DEFAULT_MACOS_PROXY_BYPASS, DEFAULT_WINDOWS_PROXY_BYPASS,
    LinuxDesktopHint, classify_linux_desktop, format_gsettings_bypass_list,
    format_kde_no_proxy_for, format_kde_proxy_url, format_shell_env_snippet,
    is_macos_ignored_network_service, is_pkexec_user_cancelled, macos_bypass_command_args,
    parse_getcap_has_net_admin, parse_kde_proxy_endpoint, parse_macos_network_services,
    render_linux_desktop_entry, render_linux_desktop_entry_with_env,
    render_macos_launch_agent_plist, resolve_persistent_linux_exe_path,
    resolve_persistent_linux_exe_path_with_env, sanitize_linux_bypass_list,
    sanitize_macos_bypass_list, sanitize_shell_host, sanitize_windows_bypass_list,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemProxySpec {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub bypass: Vec<String>,
    pub pac_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformCapabilities {
    pub os: String,
    pub arch: String,
    pub supports_uwp_loopback: bool,
    pub supports_tun_service: bool,
    pub is_elevated: bool,
}

pub trait PlatformAdapter: Send + Sync {
    fn capabilities(&self) -> PlatformCapabilities;
    fn apply_system_proxy(&self, spec: &SystemProxySpec) -> CatResult<()>;
    fn read_system_proxy(&self) -> CatResult<SystemProxySpec>;
    fn set_autostart(&self, enabled: bool, exe_path: &Path, args: &[String]) -> CatResult<()>;
    fn is_autostart_enabled(&self) -> CatResult<bool>;
    fn flush_dns(&self) -> CatResult<()>;
    fn export_shell_env_snippet(&self, shell: &str, host: &str, http_port: u16, socks_port: u16) -> String;
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
#[derive(Debug, Default, Clone, Copy)]
struct FallbackPlatform;

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
impl PlatformAdapter for FallbackPlatform {
    fn capabilities(&self) -> PlatformCapabilities {
        PlatformCapabilities {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            supports_uwp_loopback: false,
            supports_tun_service: false,
            is_elevated: false,
        }
    }

    fn apply_system_proxy(&self, _spec: &SystemProxySpec) -> CatResult<()> {
        Err(crate::error::CatError::Process(format!(
            "system proxy configuration is not supported on target OS `{}`",
            std::env::consts::OS
        )))
    }

    fn read_system_proxy(&self) -> CatResult<SystemProxySpec> {
        Ok(SystemProxySpec {
            enabled: false,
            host: "127.0.0.1".to_string(),
            port: 7890,
            bypass: Vec::new(),
            pac_url: None,
        })
    }

    fn set_autostart(
        &self,
        _enabled: bool,
        _exe_path: &Path,
        _args: &[String],
    ) -> CatResult<()> {
        Err(crate::error::CatError::Process(format!(
            "autostart configuration is not supported on target OS `{}`",
            std::env::consts::OS
        )))
    }

    fn is_autostart_enabled(&self) -> CatResult<bool> {
        Ok(false)
    }

    fn flush_dns(&self) -> CatResult<()> {
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

pub fn default_platform() -> Box<dyn PlatformAdapter> {
    #[cfg(target_os = "windows")]
    {
        Box::new(windows::WindowsPlatform::new())
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacosPlatform::new())
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxPlatform::new())
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        Box::new(FallbackPlatform)
    }
}
