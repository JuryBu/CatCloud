mod driver_guard;
mod manager;
mod nat_packet;
#[cfg(test)]
mod tests;

#[cfg(unix)]
use crate::error::CatError;
use crate::error::CatResult;
#[cfg(not(unix))]
use crate::paths::AppPaths;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub use driver_guard::{
    WINDIVERT_DOWNLOAD_URL, WINDIVERT_ZIP_SHA256, WinDivertAddress, WinDivertPaths,
    build_default_windivert_proxy_candidates, build_security_guidance,
    classify_security_products_from_process_names, detect_host_security_products,
    download_and_install_windivert, download_and_install_windivert_with_fallbacks,
    format_system_proxy_url, locate_windivert_files, locate_windivert_files_with_exe_dir,
    locate_windivert_paths, normalize_windivert_proxy_candidates,
    verify_and_extract_windivert_zip,
};
#[cfg_attr(
    not(all(target_os = "windows", target_arch = "aarch64")),
    allow(unused_imports)
)]
pub(super) use driver_guard::WINDIVERT_ARM64_UNSUPPORTED_MSG;

pub use nat_packet::{
    AcceleratedProcessStat, DOMESTIC_PUBLIC_DNS_IPV4S, GlobalPreAccelMetrics, Ipv4TcpMeta,
    MAX_NAT_ENTRIES, NAT_CLOSING_GRACE, NAT_IDLE_TIMEOUT, NatEntry, NatKey, NatPacketView,
    NatTable, SELF_TEST_DETECTED_BY, build_windivert_filter, build_windivert_filter_with_options,
    clamp_tcp_syn_mss, classify_intercept_process, collect_enabled_relay_ipv4s, is_domestic_ipv4,
    is_non_proxy_communication_process, is_open_source_proxy_core_name,
    is_physical_nic_descriptor, is_system_or_self_excluded_process, normalize_process_basename,
    parse_ipv4_tcp_packet, rewrite_ipv4_tcp_dst, rewrite_ipv4_tcp_from_loopback,
    rewrite_ipv4_tcp_src, rewrite_ipv4_tcp_to_loopback, should_intercept_port_443,
    should_intercept_process, socks5_noauth_connect_ipv4,
};
#[cfg(test)]
use nat_packet::MAX_PROCESS_STATS;
#[cfg_attr(
    any(not(target_os = "windows"), target_arch = "aarch64"),
    allow(unused_imports)
)]
pub(super) use nat_packet::{ExcludedPidTracker, forward_redirected_stream};

pub use manager::{
    GlobalPreAccelManager, GlobalPreAccelStatus, STANDALONE_TUNNEL_GOGC,
    STANDALONE_TUNNEL_GOMEMLIMIT, StandalonePreAccelTunnel, build_self_test_probe_urls,
    compile_standalone_preaccel_yaml, compile_standalone_preaccel_yaml_with_interface,
};
#[cfg_attr(
    any(not(target_os = "windows"), target_arch = "aarch64"),
    allow(unused_imports)
)]
pub(crate) use manager::validate_self_test_http_status;

/// Filename of the persisted standalone global `:443` pre-acceleration runtime metadata snapshot
/// under `<data_dir>/run/`.
pub const GLOBAL_PREACCEL_RUNTIME_META_FILENAME: &str = "global-preaccel-runtime.json";

/// Persisted runtime metadata snapshot for the standalone global domestic `:443`
/// pre-acceleration engine, atomically written to `<data_dir>/run/global-preaccel-runtime.json`
/// (with Unix `0o600` permissions) for CLI and diagnostic self-recognition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct GlobalPreAccelRuntimeMeta {
    pub pid: Option<u32>,
    pub process_start_time_unix: Option<u64>,
    pub binary_path: Option<String>,
    pub running: bool,
    /// Active or suspended mode: `"off" | "windivert" | "local_socks5" | "suspended_for_tun"`.
    pub mode: String,
    /// Unified carrier label: `"standalone_windivert" | "standalone_socks5" | "main_core_tun_suspended_standalone" | "main_core_proxy_only" | "off"`.
    pub effective_carrier: String,
    pub socks_port: Option<u16>,
    pub active_relays: Vec<String>,
    pub updated_at: String,
}

impl Default for GlobalPreAccelRuntimeMeta {
    fn default() -> Self {
        Self {
            pid: None,
            process_start_time_unix: None,
            binary_path: None,
            running: false,
            mode: "off".to_string(),
            effective_carrier: "off".to_string(),
            socks_port: None,
            active_relays: Vec::new(),
            updated_at: String::new(),
        }
    }
}

/// Resolve the canonical runtime metadata file path `<data_dir>/run/global-preaccel-runtime.json`.
pub fn global_preaccel_runtime_meta_path(data_dir: &Path) -> PathBuf {
    data_dir
        .join("run")
        .join(GLOBAL_PREACCEL_RUNTIME_META_FILENAME)
}

fn write_restricted_runtime_meta_file(target: &Path, bytes: &[u8]) -> CatResult<()> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let parent = target.parent().unwrap_or_else(|| Path::new("."));
        let file_name = target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(GLOBAL_PREACCEL_RUNTIME_META_FILENAME);
        let tmp = parent.join(format!(
            ".{file_name}.tmp.{}.{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        if let Err(err) = f.write_all(bytes).and_then(|()| f.sync_all()) {
            drop(f);
            let _ = std::fs::remove_file(&tmp);
            return Err(CatError::Io(err));
        }
        drop(f);
        if let Err(err) = std::fs::rename(&tmp, target) {
            let _ = std::fs::remove_file(&tmp);
            return Err(CatError::Io(err));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        AppPaths::atomic_write(target, bytes)
    }
}

/// Atomically persist `GlobalPreAccelRuntimeMeta` to `<data_dir>/run/global-preaccel-runtime.json`
/// (creating with mode `0o600` on Unix).
pub fn write_global_preaccel_runtime_meta(
    data_dir: &Path,
    meta: &GlobalPreAccelRuntimeMeta,
) -> CatResult<()> {
    let target = global_preaccel_runtime_meta_path(data_dir);
    let bytes = serde_json::to_vec_pretty(meta)?;
    write_restricted_runtime_meta_file(&target, &bytes)
}

/// Read `<data_dir>/run/global-preaccel-runtime.json` if present and valid JSON.
/// Also falls back to `<data_dir>/global-preaccel-runtime.json` when the caller passes `run/` directly.
pub fn read_global_preaccel_runtime_meta(data_dir: &Path) -> Option<GlobalPreAccelRuntimeMeta> {
    let primary = global_preaccel_runtime_meta_path(data_dir);
    let candidate = if primary.is_file() {
        primary
    } else if data_dir
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.eq_ignore_ascii_case("run"))
    {
        let direct = data_dir.join(GLOBAL_PREACCEL_RUNTIME_META_FILENAME);
        if direct.is_file() {
            direct
        } else {
            return None;
        }
    } else {
        return None;
    };

    let raw = std::fs::read_to_string(candidate).ok()?;
    serde_json::from_str::<GlobalPreAccelRuntimeMeta>(&raw).ok()
}

/// Remove `<data_dir>/run/global-preaccel-runtime.json` cleanly when the tunnel stops or exits.
pub fn remove_global_preaccel_runtime_meta(data_dir: &Path) {
    let target = global_preaccel_runtime_meta_path(data_dir);
    let _ = std::fs::remove_file(target);
}
