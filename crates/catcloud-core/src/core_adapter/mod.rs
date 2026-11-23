pub mod binary_resolver;
pub mod config_compiler;
pub mod hot_reload;
pub mod mihomo;
pub mod port_guard;
pub mod stream_client;

use crate::error::CatResult;
use crate::models::{AppConfig, CoreKind, ProxyMode};
use port_guard::{AllocatedPorts, PortShiftNotice};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

pub use binary_resolver::{
    BinaryResolution, BinarySource, DownloadGuidance, build_mihomo_download_guidance,
    compute_file_sha256, mihomo_binary_name, resolve_mihomo_binary,
    resolve_mihomo_binary_with_exe_dir,
};
pub use config_compiler::{
    CompileInput, CompileStats, CompiledCoreConfig, CompiledGroupMapping,
    DEFAULT_FALLBACK_GROUP_NAME, MAX_YAML_BYTES, PREACCEL_FALLBACK_GROUP_NAME,
    PREACCEL_SELECT_GROUP_NAME, StaticCheckIssue, StaticCheckSeverity, StaticValidationReport,
    apply_yaml_merge_patch, build_default_ai_routing_rules, compile_mihomo_config,
    expand_group_match_rule, redact_compiled_yaml_for_preview, validate_compiled_yaml,
};
pub use hot_reload::{
    ConfigWatcherHandle, DEFAULT_DEBOUNCE_WINDOW, DebounceDecision, DiskReloadOptions,
    DiskReloadSnapshot, HotReloadCoordinator, HotReloadDebouncer, classify_config_diff,
    has_core_config_changes,
};
pub use mihomo::{MihomoAdapter, generate_controller_secret, verify_config_with_binary};
pub use port_guard::{
    AllocatedPorts as CoreAllocatedPorts, PortShiftNotice as CorePortShiftNotice,
    allocate_safe_ports, allocate_safe_ports_for_hosts, is_port_available_tcp_udp,
};
pub use stream_client::{
    BoundedRingBuffer, CoreTelemetryStore, DEFAULT_MAX_LOG_ENTRIES, DEFAULT_MAX_MEMORY_SAMPLES,
    DEFAULT_MAX_TRAFFIC_SAMPLES, MihomoStreamClient, NdjsonLineFramer, StreamCancelToken,
    StreamSessionHandle,
};

/// Object-safe boxed future alias used by `CoreAdapter` without requiring `async-trait`.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Three-tier reload classification for CatCloud configuration updates.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReloadLevel {
    /// Millisecond zero-disruption REST API update (mode switch, proxy selection, connection kick).
    L1Rest,
    /// Validated hot config reload via `PUT /configs?force=true` plus group selection replay.
    L2HotReload,
    /// Controlled core child-process restart (listening ports, TUN stack, core binary, or Go GC/memory tier).
    L3CoreRestart,
}

impl ReloadLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::L1Rest => "l1_rest",
            Self::L2HotReload => "l2_hot_reload",
            Self::L3CoreRestart => "l3_core_restart",
        }
    }
}

impl fmt::Display for ReloadLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Structured outcome produced by the three-tier hot-reload pipeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReloadOutcome {
    pub applied: bool,
    pub level: ReloadLevel,
    pub skipped_unchanged: bool,
    pub rejected: bool,
    pub config_hash: Option<String>,
    pub replayed_groups: usize,
    pub shifted_ports: Vec<PortShiftNotice>,
    pub warnings: Vec<String>,
    pub error: Option<String>,
    pub applied_at: String,
}

/// Runtime status snapshot of the active proxy core process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoreRuntimeStatus {
    pub running: bool,
    pub kind: CoreKind,
    pub pid: Option<u32>,
    pub version: Option<String>,
    pub binary_path: Option<PathBuf>,
    pub config_path: Option<PathBuf>,
    pub bind_host: String,
    pub mixed_port: u16,
    pub controller_host: String,
    pub controller_port: u16,
    pub dns_listen_port: u16,
    pub proxy_mode: ProxyMode,
    pub started_at: Option<String>,
    pub uptime_sec: u64,
    pub rule_count: usize,
    pub node_count: usize,
    pub shifted_ports: Vec<PortShiftNotice>,
    pub last_reload_at: Option<String>,
    pub last_reload_level: Option<ReloadLevel>,
    pub last_error: Option<String>,
}

impl Default for CoreRuntimeStatus {
    fn default() -> Self {
        Self {
            running: false,
            kind: CoreKind::Mihomo,
            pid: None,
            version: None,
            binary_path: None,
            config_path: None,
            bind_host: "127.0.0.1".to_string(),
            mixed_port: 7890,
            controller_host: "127.0.0.1".to_string(),
            controller_port: 9090,
            dns_listen_port: 1053,
            proxy_mode: ProxyMode::Rule,
            started_at: None,
            uptime_sec: 0,
            rule_count: 0,
            node_count: 0,
            shifted_ports: Vec::new(),
            last_reload_at: None,
            last_reload_level: None,
            last_error: None,
        }
    }
}

/// Flattened representation of an active proxied connection returned by Mihomo `/connections`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct ActiveConnection {
    pub id: String,
    pub upload: u64,
    pub download: u64,
    pub start: String,
    pub chains: Vec<String>,
    pub rule: String,
    pub rule_payload: String,
    pub network: String,
    pub conn_type: String,
    pub source_ip: String,
    pub source_port: String,
    pub destination_ip: String,
    pub destination_port: String,
    pub host: String,
    pub process: String,
    pub process_path: String,
}

impl ActiveConnection {
    /// Returns true if this connection belongs to the specified group and/or node chain.
    ///
    /// When both `group_name` and `node_name` are provided, both must appear in `self.chains`
    /// so tearing down stale connections for one group never affects other groups sharing a node.
    pub fn matches_group_or_node(
        &self,
        group_name: Option<&str>,
        node_name: Option<&str>,
    ) -> bool {
        let group = group_name.map(str::trim).filter(|s| !s.is_empty());
        let node = node_name.map(str::trim).filter(|s| !s.is_empty());
        match (group, node) {
            (Some(g), Some(n)) => {
                self.chains.iter().any(|c| c == g) && self.chains.iter().any(|c| c == n)
            }
            (Some(g), None) => self.chains.iter().any(|c| c == g),
            (None, Some(n)) => self.chains.iter().any(|c| c == n),
            (None, None) => false,
        }
    }
}

/// Aggregated snapshot returned by `GET /connections`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct ConnectionsSnapshot {
    pub download_total: u64,
    pub upload_total: u64,
    pub memory: u64,
    pub connections: Vec<ActiveConnection>,
}

/// Real-time throughput sample streamed from Mihomo `/traffic`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct TrafficTick {
    pub up: u64,
    pub down: u64,
    pub timestamp_ms: i64,
}

/// Real-time core memory sample streamed from Mihomo `/memory`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct MemoryTick {
    pub inuse: u64,
    pub oslimit: u64,
    pub timestamp_ms: i64,
}

/// Single log line streamed from Mihomo `/logs`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct CoreLogLine {
    #[serde(alias = "type")]
    pub level: String,
    pub payload: String,
    pub timestamp: String,
}

/// Parameters required to launch a core subprocess.
#[derive(Debug, Clone)]
pub struct CoreStartRequest {
    pub binary_path: PathBuf,
    pub working_dir: PathBuf,
    pub config_path: PathBuf,
    pub config: AppConfig,
    pub allocated_ports: AllocatedPorts,
    pub controller_host: String,
    pub controller_secret: String,
    pub node_count: usize,
    pub rule_count: usize,
    pub active_selections: BTreeMap<String, String>,
}

/// Unified asynchronous proxy core adapter contract (implemented by Mihomo; extensible to sing-box/Xray).
pub trait CoreAdapter: Send + Sync {
    fn kind(&self) -> CoreKind;

    fn start(&self, req: CoreStartRequest) -> BoxFuture<'_, CatResult<CoreRuntimeStatus>>;

    fn stop(&self) -> BoxFuture<'_, CatResult<()>>;

    fn status(&self) -> BoxFuture<'_, CoreRuntimeStatus>;

    fn reload_config<'a>(
        &'a self,
        config_path: &'a Path,
        active_selections: &'a BTreeMap<String, String>,
    ) -> BoxFuture<'a, CatResult<usize>>;

    fn set_proxy_mode(&self, mode: ProxyMode) -> BoxFuture<'_, CatResult<()>>;

    fn select_group_proxy<'a>(
        &'a self,
        group_name: &'a str,
        proxy_name: &'a str,
    ) -> BoxFuture<'a, CatResult<()>>;

    fn list_connections(&self) -> BoxFuture<'_, CatResult<ConnectionsSnapshot>>;

    fn close_connection<'a>(&'a self, id: &'a str) -> BoxFuture<'a, CatResult<()>>;

    fn close_connections_for_group_or_node<'a>(
        &'a self,
        group_name: Option<&'a str>,
        node_name: Option<&'a str>,
    ) -> BoxFuture<'a, CatResult<usize>>;

    fn trigger_group_delay_check<'a>(
        &'a self,
        group_name: &'a str,
        url: &'a str,
        timeout_ms: u64,
    ) -> BoxFuture<'a, CatResult<HashMap<String, u64>>>;

    fn fetch_version(&self) -> BoxFuture<'_, CatResult<String>>;

    fn verify_config_file<'a>(
        &'a self,
        binary_path: &'a Path,
        working_dir: &'a Path,
        config_path: &'a Path,
    ) -> BoxFuture<'a, CatResult<()>>;
}

/// RFC 3986 percent-encoding for a single URL path segment (safe for UTF-8 group names and emojis).
pub(crate) fn percent_encode_path_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.as_bytes() {
        let unreserved = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~');
        if unreserved {
            out.push(*byte as char);
        } else {
            out.push('%');
            let hi = byte >> 4;
            let lo = byte & 0x0f;
            out.push(hex_upper(hi));
            out.push(hex_upper(lo));
        }
    }
    out
}

fn hex_upper(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'A' + (nibble - 10)) as char,
        _ => '0',
    }
}

/// Format an `http://host:port` base URL with bracketed IPv6 support.
pub(crate) fn format_http_base_url(host: &str, port: u16) -> String {
    let trimmed = host.trim();
    let effective = if trimmed.is_empty() || trimmed == "0.0.0.0" || trimmed == "*" {
        "127.0.0.1"
    } else if trimmed == "::" || trimmed == "[::]" {
        "::1"
    } else {
        trimmed.trim_start_matches('[').trim_end_matches(']')
    };
    if effective.contains(':') {
        format!("http://[{effective}]:{port}")
    } else {
        format!("http://{effective}:{port}")
    }
}

/// Format a `host:port` socket bind address with bracketed IPv6 support.
pub(crate) fn format_host_port(host: &str, port: u16) -> String {
    let trimmed = host.trim().trim_start_matches('[').trim_end_matches(']');
    if trimmed.contains(':') {
        format!("[{trimmed}]:{port}")
    } else {
        format!("{trimmed}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_connection_matching_is_precise() {
        let conn = ActiveConnection {
            id: "c1".to_string(),
            chains: vec!["Node-JP-01".to_string(), "AI-Group".to_string()],
            ..Default::default()
        };

        assert!(conn.matches_group_or_node(Some("AI-Group"), Some("Node-JP-01")));
        assert!(!conn.matches_group_or_node(Some("Other-Group"), Some("Node-JP-01")));
        assert!(conn.matches_group_or_node(Some("AI-Group"), None));
        assert!(conn.matches_group_or_node(None, Some("Node-JP-01")));
        assert!(!conn.matches_group_or_node(None, None));
    }

    #[test]
    fn path_segment_encoding_handles_unicode_and_reserved_chars() {
        let encoded = percent_encode_path_segment("AI/Group #1");
        assert_eq!(encoded, "AI%2FGroup%20%231");
        let unicode = percent_encode_path_segment("⚡ 国内预加速入口");
        assert!(unicode.contains("%20"));
        assert!(!unicode.contains(' '));
    }

    #[test]
    fn base_url_formatting_normalizes_wildcard_and_ipv6() {
        assert_eq!(format_http_base_url("0.0.0.0", 9090), "http://127.0.0.1:9090");
        assert_eq!(format_http_base_url("127.0.0.1", 29090), "http://127.0.0.1:29090");
        assert_eq!(format_http_base_url("::1", 9090), "http://[::1]:9090");
    }
}
