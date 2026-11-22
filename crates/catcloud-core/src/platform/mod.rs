use crate::error::CatResult;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "linux")]
pub mod linux;

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
}
