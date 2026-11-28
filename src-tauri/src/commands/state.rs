use std::collections::HashMap;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;
use std::time::Instant;
use catcloud_core::config;
use catcloud_core::core_adapter::binary_resolver::mihomo_binary_name;
use catcloud_core::core_adapter::config_compiler::PreAccelTransportDiagnostics;
use catcloud_core::core_adapter::hot_reload::HotReloadCoordinator;
use catcloud_core::core_adapter::mihomo::MihomoAdapter;
use catcloud_core::core_adapter::stream_client::CoreTelemetryStore;
use catcloud_core::core_adapter::stream_client::MihomoStreamClient;
use catcloud_core::core_adapter::stream_client::StreamSessionHandle;
use catcloud_core::core_adapter::CoreLogLine;
use catcloud_core::core_adapter::CoreRuntimeStatus;
use catcloud_core::core_adapter::DnsTlsDiagnostics;
use catcloud_core::core_adapter::analyze_dns_tls_diagnostics_from_log_file;
use catcloud_core::models::AppConfig;
use catcloud_core::models::CoreLogLevel;
use catcloud_core::models::GlobalPreAccelScope;
use catcloud_core::models::MemoryLimitTier;
use catcloud_core::models::PersonalizationConfig;
use catcloud_core::models::PreAccelConfig;
use catcloud_core::models::PreAccelDispatchStrategy;
use catcloud_core::models::PreAccelLbStrategy;
use catcloud_core::models::ProbeSnapshot;
use catcloud_core::models::ProxyMode;
use catcloud_core::models::ThemeDaySchedule;
use catcloud_core::models::ThemeMode;
use catcloud_core::models::TrayIconMode;
use catcloud_core::models::TunStackMode;
use catcloud_core::models::UpdateApplyMode;
use catcloud_core::models::UpdateConfig;
use catcloud_core::models::normalize_ui_language;
use catcloud_core::platform::default_platform;
use catcloud_core::preaccel::campus::CampusBypassTracker;
use catcloud_core::preaccel::global_tunnel::GlobalPreAccelManager;
use catcloud_core::preaccel::global_tunnel::GlobalPreAccelStatus;
use catcloud_core::process_guard::JobGuard;
use catcloud_core::storage::Storage;
use catcloud_core::strategy::health_pool::NodeHealthHintDto;
use catcloud_core::strategy::health_pool::NodeHealthPool;
use catcloud_core::strategy::health_pool::RuntimeDualHealth;
use catcloud_core::subscription::live_capture::LiveCaptureManager;
use catcloud_core::subscription::AdapterCooldownGuard;
use catcloud_core::AppPaths;
use chrono::Utc;
use serde::Deserialize;
use serde::Serialize;
use crate::app_log;
use crate::app_log::APP_EVENT_PREFIX;
use crate::app_log::RotatingAppLogger;
use crate::lan_sync::LanSyncManager;
use crate::shortcuts::ShortcutBindings;

pub const EVENT_TRAFFIC: &str = "catcloud://traffic";

pub const EVENT_RUNTIME: &str = "catcloud://runtime";

pub const EVENT_CORE_LOG: &str = "catcloud://core-log";

pub const EVENT_PROBE_PROGRESS: &str = "catcloud://probe-progress";

pub const EVENT_TUN_NEEDS_ADMIN: &str = "catcloud://tun-needs-admin";

pub const EVENT_STRATEGY_SWITCH: &str = "catcloud://strategy-switch";

pub const EVENT_CONFIG_UPDATED: &str = "catcloud://config-updated";

pub const EVENT_UPDATE_READY: &str = "catcloud://update-ready";

pub const EVENT_GROUPS_UPDATED: &str = "catcloud://groups-updated";

pub const EVENT_RELAYS_UPDATED: &str = "catcloud://relays-updated";

pub const EVENT_NODES_UPDATED: &str = "catcloud://nodes-updated";

pub const EVENT_NAVIGATE: &str = "catcloud://navigate";


pub const NO_ENABLED_RELAY_ERROR: &str = "NO_ENABLED_RELAY: 请先添加并启用至少一条国内提速线路";


/// Physical-pixel anchor tracked during custom Win32 floating capsule dragging (zero HTCAPTION / Aero Snap).
#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub struct CapsuleDragAnchor {
    pub rx: f64,
    pub ry: f64,
    pub offset_x: i32,
    pub offset_y: i32,
    pub width: i32,
    pub height: i32,
}


/// Shared backend state managed by Tauri across commands, tray callbacks, streams, and shortcuts.
pub struct AppState {
    pub paths: AppPaths,
    pub config: RwLock<Arc<AppConfig>>,
    pub storage: Arc<Mutex<Storage>>,
    pub job_guard: Arc<JobGuard>,
    pub global_preaccel: Arc<GlobalPreAccelManager>,
    pub live_capture: Arc<LiveCaptureManager>,
    pub lan_sync: Arc<LanSyncManager>,
    pub refreshing_sub_ids: Mutex<HashSet<String>>,
    pub capsule_drag: Mutex<Option<CapsuleDragAnchor>>,
    pub node_health_pool: Arc<RwLock<NodeHealthPool>>,
    pub windivert_installing: Arc<AtomicBool>,
    pub adapter: Arc<MihomoAdapter>,
    pub hot_reload: Arc<HotReloadCoordinator>,
    pub telemetry: Arc<CoreTelemetryStore>,
    pub stream_session: Mutex<Option<StreamSessionHandle>>,
    pub campus_tracker: Mutex<CampusBypassTracker>,
    pub resource_dir: RwLock<Option<PathBuf>>,
    pub cached_runtime: RwLock<CoreRuntimeStatus>,
    pub cached_metrics: RwLock<CachedRealtimeMetrics>,
    pub probe_running: Arc<AtomicBool>,
    pub probe_cancel_tx: Arc<Mutex<Option<tokio::sync::watch::Sender<bool>>>>,
    pub switching_active: Arc<AtomicBool>,
    pub switching_depth: Arc<AtomicUsize>,
    pub core_session_gen: Arc<AtomicU64>,
    pub config_generation: Arc<AtomicU64>,
    pub last_heap_reclaim_at: Mutex<Option<Instant>>,
    pub group_backoff_until: RwLock<HashMap<String, Instant>>,
    pub last_hotkey_bindings: Mutex<Option<ShortcutBindings>>,
    pub adapter_cooldown: Arc<AdapterCooldownGuard>,
    pub shutting_down: Arc<AtomicBool>,
    pub config_transition_lock: Arc<tokio::sync::Mutex<()>>,
    pub core_lifecycle_lock: Arc<tokio::sync::Mutex<()>>,
    pub update_staging_lock: Arc<tokio::sync::Mutex<()>>,
    pub update_download_lock: Arc<tokio::sync::Mutex<()>>,
    pub update_download_cancel: Mutex<Option<tokio::sync::watch::Sender<bool>>>,
    pub dismissed_update_prompt_version: RwLock<Option<String>>,
    pub update_apply_in_progress: AtomicBool,
    pub exit_cleanup_done: AtomicBool,
    pub system_proxy_lock: Arc<std::sync::Mutex<()>>,
    pub node_proxy_name_map: RwLock<HashMap<String, String>>,
    pub compiled_group_ids: RwLock<Option<HashSet<String>>>,
    pub last_effective_tun_mtu: RwLock<Option<u16>>,
    pub last_log_level: RwLock<CoreLogLevel>,
    pub app_logger: Arc<RotatingAppLogger>,
    pub last_app_error: RwLock<Option<String>>,
    pub started_at: Instant,
    /// In-memory `(was_sys_proxy, was_eff_tun)` takeover combination captured before power-off
    /// (never persisted to disk; cold startup always begins with `None`).
    pub power_off_takeover_memory: Mutex<Option<(bool, bool)>>,
    /// Pending route queued when a tray/background action rebuilds the main window from windowless mode.
    pub pending_nav: Mutex<Option<String>>,
    /// Cached `(modified_ms, file_len, tail_bytes, diagnostics)` for `catcloud.log` DNS/TLS health scan.
    pub dns_tls_log_cache: Mutex<Option<(u128, u64, usize, DnsTlsDiagnostics)>>,
}


#[derive(Debug, Clone, Copy, Default)]
pub struct CachedRealtimeMetrics {
    pub up_bps: u64,
    pub down_bps: u64,
    pub up_total_bytes: u64,
    pub down_total_bytes: u64,
    pub core_mem_bytes: u64,
    pub app_connections: usize,
    pub tunnel_connections: usize,
    pub direct_connections: usize,
    pub proxied_connections: usize,
}


#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionSummaryCounts {
    pub app_connections: usize,
    pub tunnel_connections: usize,
    pub direct_connections: usize,
    pub proxied_connections: usize,
}


/// Split Mihomo `/connections` snapshot into real application connections vs internal
/// pre-acceleration `Inner` tunnels, and classify application connections into direct vs proxied
/// (excluding `REJECT` / `REJECT-DROP` blocked connections from proxied counts).
pub fn summarize_connections(
    conns: &[catcloud_core::core_adapter::ActiveConnection],
) -> ConnectionSummaryCounts {
    let mut out = ConnectionSummaryCounts::default();
    for conn in conns {
        if conn.conn_type.eq_ignore_ascii_case("Inner") {
            out.tunnel_connections += 1;
            continue;
        }
        out.app_connections += 1;
        let is_reject = conn.chains.iter().any(|c| {
            c.eq_ignore_ascii_case("REJECT") || c.eq_ignore_ascii_case("REJECT-DROP")
        }) || conn.rule.eq_ignore_ascii_case("REJECT")
            || conn.rule.eq_ignore_ascii_case("REJECT-DROP");
        if is_reject {
            continue;
        }
        let is_direct = conn
            .chains
            .iter()
            .any(|c| c.eq_ignore_ascii_case("DIRECT"))
            || conn.rule.eq_ignore_ascii_case("DIRECT");
        if is_direct {
            out.direct_connections += 1;
        } else {
            out.proxied_connections += 1;
        }
    }
    out
}


/// Auto-mark `onboarding_completed = true` for existing users upgrading from prior versions
/// whose SQLite store already holds any nodes, subscriptions, domestic relays, or multi-groups.
pub(in crate::commands) fn reconcile_legacy_onboarding_completed(cfg: &mut AppConfig, storage: &Storage) -> bool {
    if cfg.personalization.onboarding_completed {
        return false;
    }
    let has_existing_assets = storage.list_node_ids().is_ok_and(|v| !v.is_empty())
        || storage.list_subscriptions().is_ok_and(|v| !v.is_empty())
        || storage.list_preaccel_relays(false).is_ok_and(|v| !v.is_empty())
        || storage.list_multi_groups().is_ok_and(|v| !v.is_empty());
    if has_existing_assets {
        cfg.personalization.onboarding_completed = true;
        return true;
    }
    false
}


impl AppState {
    pub fn new(
        paths: AppPaths,
        mut cfg: AppConfig,
        storage: Storage,
        job_guard: Arc<JobGuard>,
    ) -> Self {
        cfg.preaccel.reconcile_unified_enabled();
        if reconcile_legacy_onboarding_completed(&mut cfg, &storage) {
            let _ = config::save(&paths, &cfg);
        }
        let adapter = Arc::new(
            MihomoAdapter::new(Arc::clone(&job_guard))
                .expect("failed to initialize MihomoAdapter"),
        );
        let global_preaccel = Arc::new(GlobalPreAccelManager::new(
            paths.clone(),
            Arc::clone(&job_guard),
        ));
        let live_capture = Arc::new(LiveCaptureManager::new());
        let lan_sync = Arc::new(LanSyncManager::new());
        let hot_reload = Arc::new(HotReloadCoordinator::new(paths.clone(), Arc::clone(&adapter)));
        let telemetry = Arc::new(CoreTelemetryStore::default());
        let app_logger = Arc::new(RotatingAppLogger::new(paths.logs_dir.clone()));
        let initial_log_level = cfg.log_level.clone();
        Self {
            paths,
            config: RwLock::new(Arc::new(cfg)),
            storage: Arc::new(Mutex::new(storage)),
            job_guard,
            global_preaccel,
            live_capture,
            lan_sync,
            refreshing_sub_ids: Mutex::new(HashSet::new()),
            capsule_drag: Mutex::new(None),
            node_health_pool: Arc::new(RwLock::new(NodeHealthPool::new())),
            windivert_installing: Arc::new(AtomicBool::new(false)),
            adapter,
            hot_reload,
            telemetry,
            stream_session: Mutex::new(None),
            campus_tracker: Mutex::new(CampusBypassTracker::new()),
            resource_dir: RwLock::new(None),
            cached_runtime: RwLock::new(CoreRuntimeStatus::default()),
            cached_metrics: RwLock::new(CachedRealtimeMetrics::default()),
            probe_running: Arc::new(AtomicBool::new(false)),
            probe_cancel_tx: Arc::new(Mutex::new(None)),
            switching_active: Arc::new(AtomicBool::new(false)),
            switching_depth: Arc::new(AtomicUsize::new(0)),
            core_session_gen: Arc::new(AtomicU64::new(0)),
            config_generation: Arc::new(AtomicU64::new(0)),
            last_heap_reclaim_at: Mutex::new(None),
            group_backoff_until: RwLock::new(HashMap::new()),
            last_hotkey_bindings: Mutex::new(None),
            adapter_cooldown: Arc::new(AdapterCooldownGuard::new()),
            shutting_down: Arc::new(AtomicBool::new(false)),
            config_transition_lock: Arc::new(tokio::sync::Mutex::new(())),
            core_lifecycle_lock: Arc::new(tokio::sync::Mutex::new(())),
            update_staging_lock: Arc::new(tokio::sync::Mutex::new(())),
            update_download_lock: Arc::new(tokio::sync::Mutex::new(())),
            update_download_cancel: Mutex::new(None),
            dismissed_update_prompt_version: RwLock::new(None),
            update_apply_in_progress: AtomicBool::new(false),
            exit_cleanup_done: AtomicBool::new(false),
            system_proxy_lock: Arc::new(std::sync::Mutex::new(())),
            node_proxy_name_map: RwLock::new(HashMap::new()),
            compiled_group_ids: RwLock::new(None),
            last_effective_tun_mtu: RwLock::new(None),
            last_log_level: RwLock::new(initial_log_level),
            app_logger,
            last_app_error: RwLock::new(None),
            started_at: Instant::now(),
            power_off_takeover_memory: Mutex::new(None),
            pending_nav: Mutex::new(None),
            dns_tls_log_cache: Mutex::new(None),
        }
    }

    /// Signal any in-flight update package download to abort immediately.
    pub fn cancel_in_flight_update_download(&self) {
        if let Ok(guard) = self.update_download_cancel.lock() {
            if let Some(tx) = guard.as_ref() {
                let _ = tx.send(true);
            }
        }
    }

    /// Persist a sanitized application-level event into `catcloud.log` and push it into
    /// `CoreTelemetryStore` (which automatically emits `catcloud://core-log` when the main window
    /// is visible via the log forwarder).
    pub fn log_app_event(&self, level: &str, category: &str, message: &str) {
        let lvl = app_log::normalize_log_level(level);
        let sanitized = app_log::sanitize_log_line(message)
            .replace(['\r', '\n'], " ")
            .trim()
            .to_string();
        if sanitized.is_empty() {
            return;
        }
        let cat = category.trim();
        let ts = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        self.app_logger
            .append_formatted(&ts, lvl, cat, &sanitized);

        if lvl == "error" {
            let err_summary = if cat.is_empty() {
                sanitized.clone()
            } else {
                format!("[{cat}] {sanitized}")
            };
            if let Ok(mut guard) = self.last_app_error.write() {
                *guard = Some(err_summary);
            }
        }

        let payload = if cat.is_empty() {
            format!("{APP_EVENT_PREFIX}通用] {sanitized}")
        } else {
            format!("{APP_EVENT_PREFIX}{cat}] {sanitized}")
        };
        self.telemetry.push_log(CoreLogLine {
            level: lvl.to_string(),
            payload,
            timestamp: ts,
        });

        match lvl {
            "error" => tracing::error!(category = %cat, "{sanitized}"),
            "warning" => tracing::warn!(category = %cat, "{sanitized}"),
            "debug" => tracing::debug!(category = %cat, "{sanitized}"),
            _ => tracing::info!(category = %cat, "{sanitized}"),
        }
    }

    pub fn clear_app_error(&self) {
        if let Ok(mut guard) = self.last_app_error.write() {
            *guard = None;
        }
    }

    pub fn snapshot_global_preaccel(&self) -> GlobalPreAccelStatus {
        let custom_dir = self.snapshot_config().preaccel.windivert_dir.clone();
        self.global_preaccel
            .status_with_custom_dir(custom_dir.as_deref())
    }

    pub fn last_app_error_snapshot(&self) -> Option<String> {
        self.last_app_error
            .read()
            .ok()
            .and_then(|g| g.clone())
    }

    pub fn core_session_generation(&self) -> u64 {
        self.core_session_gen.load(Ordering::SeqCst)
    }

    pub fn bump_core_session_generation(&self) -> u64 {
        self.core_session_gen
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1)
    }

    pub fn config_generation(&self) -> u64 {
        self.config_generation.load(Ordering::SeqCst)
    }

    pub fn bump_config_generation(&self) -> u64 {
        self.config_generation
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1)
    }

    pub fn is_switching_active(&self) -> bool {
        self.switching_active.load(Ordering::SeqCst)
    }

    pub fn set_group_backoff_until(&self, group_id: &str, until: Option<Instant>) {
        let trimmed = group_id.trim();
        if trimmed.is_empty() {
            return;
        }
        if let Ok(mut guard) = self.group_backoff_until.write() {
            match until {
                Some(ts) => {
                    guard.insert(trimmed.to_string(), ts);
                }
                None => {
                    guard.remove(trimmed);
                }
            }
        }
    }

    pub fn is_group_in_backoff(&self, group_id: &str) -> bool {
        let trimmed = group_id.trim();
        if trimmed.is_empty() {
            return false;
        }
        let now = Instant::now();
        self.group_backoff_until
            .read()
            .ok()
            .and_then(|guard| guard.get(trimmed).copied())
            .is_some_and(|until| now < until)
    }

    pub fn clear_group_backoffs(&self) {
        if let Ok(mut guard) = self.group_backoff_until.write() {
            guard.clear();
        }
    }

    pub fn set_node_proxy_name_map(&self, map: HashMap<String, String>) {
        if let Ok(mut guard) = self.node_proxy_name_map.write() {
            *guard = map;
        }
    }

    pub fn lookup_compiled_proxy_name(&self, node_id: &str) -> Option<String> {
        let guard = self.node_proxy_name_map.read().ok()?;
        let mapped = guard.get(node_id)?;
        let trimmed = mapped.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }

    pub fn resolve_compiled_proxy_name(&self, node_id: &str, fallback_name: &str) -> String {
        self.lookup_compiled_proxy_name(node_id)
            .unwrap_or_else(|| fallback_name.to_string())
    }

    pub fn set_compiled_group_ids(&self, ids: Option<HashSet<String>>) {
        if let Ok(mut guard) = self.compiled_group_ids.write() {
            *guard = ids;
        }
    }

    pub fn snapshot_compiled_group_ids(&self) -> Option<HashSet<String>> {
        self.compiled_group_ids
            .read()
            .ok()
            .and_then(|g| g.clone())
    }

    pub fn set_last_effective_tun_mtu(&self, mtu: Option<u16>) {
        if let Ok(mut guard) = self.last_effective_tun_mtu.write() {
            *guard = mtu.filter(|&v| v > 0);
        }
    }

    pub fn snapshot_last_effective_tun_mtu(&self) -> Option<u16> {
        self.last_effective_tun_mtu
            .read()
            .ok()
            .and_then(|g| *g)
            .filter(|&v| v > 0)
    }

    pub fn attach_streams(
        &self,
        controller_host: &str,
        controller_port: u16,
        secret: &str,
        log_level: CoreLogLevel,
    ) {
        self.stop_streams();
        if let Ok(mut guard) = self.last_log_level.write() {
            *guard = log_level.clone();
        }
        if let Ok(stream_client) =
            MihomoStreamClient::new(controller_host, controller_port, secret)
        {
            let session = stream_client
                .spawn_background_streams(log_level, Arc::clone(&self.telemetry));
            if let Ok(mut guard) = self.stream_session.lock() {
                *guard = Some(session);
            }
        }
    }

    pub fn set_resource_dir(&self, dir: Option<PathBuf>) {
        if let Ok(mut guard) = self.resource_dir.write() {
            *guard = dir;
        }
        self.hot_reload
            .set_extra_binary_candidates(self.extra_binary_candidates());
    }

    pub fn extra_binary_candidates(&self) -> Vec<PathBuf> {
        let bin_name = mihomo_binary_name();
        let mut out = Vec::new();
        if let Ok(guard) = self.resource_dir.read() {
            if let Some(ref res_dir) = *guard {
                out.push(res_dir.join("resources").join("bin").join(bin_name));
                out.push(res_dir.join("bin").join(bin_name));
                out.push(res_dir.join(bin_name));
            }
        }
        out
    }

    pub fn snapshot_config(&self) -> Arc<AppConfig> {
        self.config
            .read()
            .map(|g| Arc::clone(&*g))
            .unwrap_or_else(|_| Arc::new(AppConfig::default()))
    }

    pub fn clone_config(&self) -> AppConfig {
        (*self.snapshot_config()).clone()
    }

    /// Analyze DNS/TLS health from `catcloud.log` with `(modified_ms, file_len)` memoization
    /// so repeated runtime/tray queries skip disk reads whenever the log file has not changed.
    pub fn analyze_dns_tls_diagnostics_cached(&self, tail_bytes: usize) -> DnsTlsDiagnostics {
        let log_path = self.app_logger.active_log_path();
        if let Ok(meta) = std::fs::metadata(&log_path) {
            let file_len = meta.len();
            let modified_ms = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis())
                .unwrap_or(0);
            if modified_ms > 0 {
                if let Ok(guard) = self.dns_tls_log_cache.lock() {
                    if let Some((cached_ms, cached_len, cached_tail, ref cached_diag)) = *guard {
                        if cached_ms == modified_ms
                            && cached_len == file_len
                            && cached_tail == tail_bytes
                        {
                            return cached_diag.clone();
                        }
                    }
                }
            }
            let diag = analyze_dns_tls_diagnostics_from_log_file(&log_path, tail_bytes);
            if modified_ms > 0 {
                if let Ok(mut guard) = self.dns_tls_log_cache.lock() {
                    *guard = Some((modified_ms, file_len, tail_bytes, diag.clone()));
                }
            }
            return diag;
        }
        if let Ok(mut guard) = self.dns_tls_log_cache.lock() {
            *guard = None;
        }
        analyze_dns_tls_diagnostics_from_log_file(&log_path, tail_bytes)
    }

    pub fn snapshot_runtime(&self) -> CoreRuntimeStatus {
        self.cached_runtime
            .read()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    pub fn update_cached_runtime(&self, status: CoreRuntimeStatus) {
        if let Ok(mut guard) = self.cached_runtime.write() {
            *guard = status;
        }
    }

    pub fn stop_streams(&self) {
        if let Ok(mut guard) = self.stream_session.lock() {
            if let Some(handle) = guard.take() {
                handle.stop();
            }
        }
    }

    pub fn record_node_health_probe(
        &self,
        node_id: &str,
        health: RuntimeDualHealth,
        raw_latency_ms: Option<f64>,
    ) {
        if let Ok(mut pool) = self.node_health_pool.write() {
            pool.record_probe_result(node_id, health, raw_latency_ms, Instant::now());
        }
    }

    pub fn reset_node_health(&self, node_id: &str) {
        if let Ok(mut pool) = self.node_health_pool.write() {
            pool.reset_node(node_id);
        }
    }

    /// Resolve the freshest latency for `node_id`: prefers live runtime probes in `node_health_pool`
    /// (while clearing stale DB latency when the latest confirmed runtime check failed), falling back
    /// to SQLite `ProbeSnapshot.latency_ms` when untracked.
    pub fn resolve_node_latency_ms(
        &self,
        node_id: &str,
        snap: Option<&ProbeSnapshot>,
    ) -> Option<f64> {
        let trimmed = node_id.trim();
        if !trimmed.is_empty() {
            if let Ok(pool) = self.node_health_pool.read() {
                if let Some(entry) = pool.get(trimmed) {
                    if entry.last_health == Some(RuntimeDualHealth::Failed) {
                        return None;
                    }
                    if let Some(live_ms) = pool.live_latency_ms(trimmed) {
                        return Some(live_ms);
                    }
                }
            }
        }
        snap.and_then(|s| s.latency_ms)
    }

    pub fn snapshot_node_health_pool(&self) -> NodeHealthPool {
        self.node_health_pool
            .read()
            .map(|pool| pool.clone())
            .unwrap_or_default()
    }

    pub fn snapshot_node_health_hints(&self) -> HashMap<String, NodeHealthHintDto> {
        self.node_health_pool
            .read()
            .map(|pool| pool.build_hints_snapshot(Instant::now()))
            .unwrap_or_default()
    }

    pub fn clear_node_health_pool(&self) {
        if let Ok(mut pool) = self.node_health_pool.write() {
            *pool = NodeHealthPool::new();
        }
    }

    pub fn prune_node_health_pool(&self, valid_ids: &HashSet<String>) {
        if let Ok(mut pool) = self.node_health_pool.write() {
            pool.prune_missing_nodes(valid_ids);
        }
    }

    pub fn record_power_off_takeover_memory(&self, was_sys_proxy: bool, was_eff_tun: bool) {
        if let Ok(mut guard) = self.power_off_takeover_memory.lock() {
            *guard = if was_sys_proxy || was_eff_tun {
                Some((was_sys_proxy, was_eff_tun))
            } else {
                None
            };
        }
    }

    pub fn take_power_off_takeover_memory(&self) -> Option<(bool, bool)> {
        self.power_off_takeover_memory
            .lock()
            .ok()
            .and_then(|mut guard| guard.take())
    }

    pub fn restore_power_off_takeover_memory(&self, memory: Option<(bool, bool)>) {
        if let Ok(mut guard) = self.power_off_takeover_memory.lock() {
            *guard = memory;
        }
    }

    pub fn clear_power_off_takeover_memory(&self) {
        if let Ok(mut guard) = self.power_off_takeover_memory.lock() {
            *guard = None;
        }
    }

    pub fn set_pending_nav(&self, route: Option<&str>) {
        let normalized = route
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        if let Ok(mut guard) = self.pending_nav.lock() {
            *guard = normalized;
        }
    }

    pub fn take_pending_nav(&self) -> Option<String> {
        self.pending_nav.lock().ok().and_then(|mut guard| guard.take())
    }
}


/// RAII guard preventing concurrent duplicate refreshes of the same subscription ID.
pub(in crate::commands) struct SubRefreshGuard<'a> {
    pub(in crate::commands) set: &'a Mutex<HashSet<String>>,
    pub(in crate::commands) sub_id: String,
}

impl<'a> SubRefreshGuard<'a> {
    pub(in crate::commands) fn try_acquire(
        set: &'a Mutex<HashSet<String>>,
        sub_id: String,
    ) -> Option<Self> {
        let mut guard = set.lock().unwrap_or_else(|e| e.into_inner());
        if guard.insert(sub_id.clone()) {
            Some(Self { set, sub_id })
        } else {
            None
        }
    }
}


impl Drop for SubRefreshGuard<'_> {
    fn drop(&mut self) {
        let mut guard = self.set.lock().unwrap_or_else(|e| e.into_inner());
        guard.remove(&self.sub_id);
    }
}

/// RAII guard clearing an `Arc<AtomicBool>` flag on drop (even on early return or panic).
#[cfg_attr(
    not(all(target_os = "windows", not(target_arch = "aarch64"))),
    allow(dead_code)
)]
pub(in crate::commands) struct AtomicFlagResetGuard(pub(in crate::commands) Arc<AtomicBool>);


impl Drop for AtomicFlagResetGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}


pub(in crate::commands) fn prune_node_health_pool_from_db(state: &AppState) {
    let valid: Option<(Option<HashSet<String>>, Option<HashSet<String>>)> =
        state.storage.lock().ok().map(|db| {
            let node_ids = db
                .list_node_ids()
                .ok()
                .map(|ids| ids.into_iter().collect());
            let group_ids = db
                .list_multi_groups()
                .ok()
                .map(|groups| groups.into_iter().map(|g| g.id).collect());
            (node_ids, group_ids)
        });
    if let Some((node_ids, group_ids)) = valid {
        if let Ok(mut pool) = state.node_health_pool.write() {
            if let Some(ids) = node_ids {
                pool.prune_missing_nodes(&ids);
            }
            if let Some(gids) = group_ids {
                pool.prune_missing_groups(&gids);
            }
        }
    }
}


/// Compact frontend-facing config DTO bidirectionally mapped onto full `AppConfig`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiAppConfigDto {
    pub mixed_port: u16,
    pub controller_port: u16,
    pub dns_listen_port: u16,
    pub proxy_mode: ProxyMode,
    pub system_proxy_enabled: bool,
    pub proxy_guard_enabled: bool,
    pub proxy_guard_interval_sec: u64,
    pub tun_enabled: bool,
    pub tun_stack_mode: TunStackMode,
    pub unified_delay: bool,
    pub ipv6_core_enabled: bool,
    pub ipv6_dns_enabled: bool,
    pub autostart_enabled: bool,
    pub silent_start: bool,
    /// `0` encodes `MemoryLimitTier::Auto`; `48`/`64`/`96` encode explicit tiers.
    pub gomemlimit_mb: u16,
    #[serde(default)]
    pub memory_tier: Option<MemoryLimitTier>,
    pub preaccel: UiPreAccelDto,
    pub personalization: UiPersonalizationDto,
    pub update: UiUpdateDto,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiPreAccelDto {
    pub enabled: bool,
    pub skip_443_native: bool,
    pub probe_url: String,
    pub fallback_probe_url: String,
    #[serde(default)]
    pub campus_portal_guard: Option<bool>,
    #[serde(default)]
    pub global_bypass_enabled: Option<bool>,
    #[serde(default)]
    pub global_scope: Option<GlobalPreAccelScope>,
    #[serde(default)]
    pub global_target_processes: Option<Vec<String>>,
    #[serde(default)]
    pub windivert_dir: Option<String>,
    #[serde(default)]
    pub active_relay_id: Option<String>,
    #[serde(default)]
    pub dispatch_strategy: Option<PreAccelDispatchStrategy>,
    #[serde(default)]
    pub lb_strategy: Option<PreAccelLbStrategy>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiThemeScheduleDto {
    pub light_start: String,
    pub warm_dark_start: String,
    pub midnight_start: String,
}


fn default_ui_language() -> String {
    "zh-CN".to_string()
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiPersonalizationDto {
    #[serde(default = "default_ui_language")]
    pub ui_language: String,
    pub theme_mode: ThemeMode,
    pub theme_schedule: UiThemeScheduleDto,
    pub wallpaper_path: Option<String>,
    pub wallpaper_opacity: f32,
    pub glass_blur_px: u32,
    pub animations_enabled: bool,
    pub mascot_enabled: bool,
    pub sparkline_enabled: bool,
    pub tray_icon_mode: TrayIconMode,
    #[serde(default)]
    pub onboarding_completed: bool,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiUpdateDto {
    pub repo: String,
    pub mode: UpdateApplyMode,
    pub check_interval_min: u64,
    pub include_prerelease: bool,
    #[serde(default)]
    pub auto_download: Option<bool>,
    #[serde(default)]
    pub skipped_version: Option<String>,
}


impl From<&AppConfig> for UiAppConfigDto {
    fn from(cfg: &AppConfig) -> Self {
        let gomemlimit_mb = match cfg.core_runtime.memory_tier {
            MemoryLimitTier::Auto => 0,
            MemoryLimitTier::Mb48 => 48,
            MemoryLimitTier::Mb64 => 64,
            MemoryLimitTier::Mb96 => 96,
        };
        Self {
            mixed_port: cfg.mixed_port,
            controller_port: cfg.controller_port,
            dns_listen_port: cfg.dns_listen_port,
            proxy_mode: cfg.proxy_mode.clone(),
            system_proxy_enabled: cfg.system_proxy.enabled,
            proxy_guard_enabled: cfg.system_proxy.proxy_guard.enabled,
            proxy_guard_interval_sec: cfg.system_proxy.proxy_guard.interval_sec,
            tun_enabled: cfg.tun.enabled,
            tun_stack_mode: cfg.tun.stack_mode.clone(),
            unified_delay: cfg.unified_delay,
            ipv6_core_enabled: cfg.core_ipv6,
            ipv6_dns_enabled: cfg.dns.ipv6,
            autostart_enabled: cfg.behavior.autostart,
            silent_start: cfg.behavior.silent_start,
            gomemlimit_mb,
            memory_tier: Some(cfg.core_runtime.memory_tier.clone()),
            preaccel: UiPreAccelDto {
                enabled: cfg.preaccel.enabled,
                skip_443_native: cfg.preaccel.skip_443_native,
                probe_url: cfg.preaccel.probe_url.clone(),
                fallback_probe_url: cfg.preaccel.fallback_probe_url.clone(),
                campus_portal_guard: Some(cfg.preaccel.campus_portal_guard),
                global_bypass_enabled: Some(cfg.preaccel.enabled),
                global_scope: Some(cfg.preaccel.global_scope),
                global_target_processes: Some(cfg.preaccel.global_target_processes.clone()),
                windivert_dir: cfg.preaccel.windivert_dir.clone(),
                active_relay_id: cfg.preaccel.active_relay_id.clone(),
                dispatch_strategy: Some(cfg.preaccel.dispatch_strategy),
                lb_strategy: Some(cfg.preaccel.lb_strategy),
            },
            personalization: UiPersonalizationDto {
                ui_language: cfg.personalization.normalized_ui_language().to_string(),
                theme_mode: cfg.personalization.theme_mode.clone(),
                theme_schedule: UiThemeScheduleDto {
                    light_start: cfg.personalization.day_schedule.light_start.clone(),
                    warm_dark_start: cfg.personalization.day_schedule.warm_dark_start.clone(),
                    midnight_start: cfg.personalization.day_schedule.midnight_blue_start.clone(),
                },
                wallpaper_path: cfg.personalization.wallpaper_path.clone(),
                wallpaper_opacity: cfg.personalization.wallpaper_opacity,
                glass_blur_px: cfg.personalization.wallpaper_blur,
                animations_enabled: cfg.personalization.animations_enabled,
                mascot_enabled: cfg.personalization.mascot_enabled,
                sparkline_enabled: cfg.personalization.sparkline_enabled,
                tray_icon_mode: cfg.personalization.tray_icon_mode.clone(),
                onboarding_completed: cfg.personalization.onboarding_completed,
            },
            update: UiUpdateDto {
                repo: cfg.update.repo.clone(),
                mode: cfg.update.mode.clone(),
                check_interval_min: cfg.update.check_interval_min,
                include_prerelease: cfg.update.include_prerelease,
                auto_download: Some(cfg.update.auto_download),
                skipped_version: cfg.update.skipped_version.clone(),
            },
        }
    }
}

impl From<&Arc<AppConfig>> for UiAppConfigDto {
    fn from(cfg: &Arc<AppConfig>) -> Self {
        Self::from(cfg.as_ref())
    }
}


pub(in crate::commands) fn apply_ui_dto(cfg: &mut AppConfig, dto: &UiAppConfigDto) {
    cfg.mixed_port = dto.mixed_port;
    cfg.controller_port = dto.controller_port;
    cfg.dns_listen_port = dto.dns_listen_port;
    cfg.proxy_mode = dto.proxy_mode.clone();
    cfg.system_proxy.enabled = dto.system_proxy_enabled;
    cfg.system_proxy.proxy_guard.enabled = dto.proxy_guard_enabled;
    cfg.system_proxy.proxy_guard.interval_sec = dto.proxy_guard_interval_sec;
    cfg.tun.enabled = dto.tun_enabled;
    cfg.tun.stack_mode = dto.tun_stack_mode.clone();
    cfg.unified_delay = dto.unified_delay;
    cfg.core_ipv6 = dto.ipv6_core_enabled;
    cfg.dns.ipv6 = dto.ipv6_dns_enabled;
    cfg.behavior.autostart = dto.autostart_enabled;
    cfg.behavior.silent_start = dto.silent_start;
    cfg.core_runtime.memory_tier = if let Some(ref tier) = dto.memory_tier {
        tier.clone()
    } else {
        match dto.gomemlimit_mb {
            0 => MemoryLimitTier::Auto,
            1..=48 => MemoryLimitTier::Mb48,
            49..=64 => MemoryLimitTier::Mb64,
            _ => MemoryLimitTier::Mb96,
        }
    };
    let next_dispatch_strategy = dto
        .preaccel
        .dispatch_strategy
        .unwrap_or(cfg.preaccel.dispatch_strategy);
    let next_lb_strategy = dto
        .preaccel
        .lb_strategy
        .unwrap_or(cfg.preaccel.lb_strategy);
    let normalized_dto_active_relay_id = dto
        .preaccel
        .active_relay_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    // Keep `active_relay_id` strictly synchronized with `dispatch_strategy`:
    // - `LoadBalance` always clears `active_relay_id` to `None`.
    // - `Auto` / `Fallback` synchronize the normalized `dto.preaccel.active_relay_id` (empty -> `None`)
    //   so returning to multi-cloud LB via `(Auto, None)` clears a pinned relay even if the stored
    //   strategy was already `Auto`; legacy payloads omitting both fields retain the prior value.
    let next_active_relay_id = match next_dispatch_strategy {
        PreAccelDispatchStrategy::LoadBalance => None,
        PreAccelDispatchStrategy::Auto | PreAccelDispatchStrategy::Fallback => {
            if dto.preaccel.dispatch_strategy.is_some() || dto.preaccel.active_relay_id.is_some() {
                normalized_dto_active_relay_id
            } else {
                cfg.preaccel.active_relay_id.clone()
            }
        }
    };
    cfg.preaccel = PreAccelConfig {
        enabled: dto.preaccel.enabled,
        skip_443_native: dto.preaccel.skip_443_native,
        probe_url: dto.preaccel.probe_url.clone(),
        fallback_probe_url: dto.preaccel.fallback_probe_url.clone(),
        active_relay_id: next_active_relay_id,
        dispatch_strategy: next_dispatch_strategy,
        lb_strategy: next_lb_strategy,
        campus_portal_guard: dto
            .preaccel
            .campus_portal_guard
            .unwrap_or(cfg.preaccel.campus_portal_guard),
        global_bypass_enabled: dto.preaccel.enabled,
        global_scope: dto
            .preaccel
            .global_scope
            .unwrap_or(cfg.preaccel.global_scope),
        global_target_processes: dto
            .preaccel
            .global_target_processes
            .clone()
            .unwrap_or_else(|| cfg.preaccel.global_target_processes.clone()),
        windivert_dir: match dto.preaccel.windivert_dir.as_deref() {
            Some(raw) => {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            }
            None => cfg.preaccel.windivert_dir.clone(),
        },
        ..cfg.preaccel.clone()
    };
    cfg.preaccel.sync_unified_enabled(dto.preaccel.enabled);
    let resolved_ui_language = if dto.personalization.ui_language.trim().is_empty() {
        cfg.personalization.normalized_ui_language().to_string()
    } else {
        normalize_ui_language(&dto.personalization.ui_language).to_string()
    };
    cfg.personalization = PersonalizationConfig {
        theme_mode: dto.personalization.theme_mode.clone(),
        day_schedule: ThemeDaySchedule {
            light_start: dto.personalization.theme_schedule.light_start.clone(),
            warm_dark_start: dto.personalization.theme_schedule.warm_dark_start.clone(),
            midnight_blue_start: dto.personalization.theme_schedule.midnight_start.clone(),
        },
        wallpaper_path: dto.personalization.wallpaper_path.clone(),
        wallpaper_opacity: dto.personalization.wallpaper_opacity,
        wallpaper_blur: dto.personalization.glass_blur_px,
        animations_enabled: dto.personalization.animations_enabled,
        mascot_enabled: dto.personalization.mascot_enabled,
        sparkline_enabled: dto.personalization.sparkline_enabled,
        tray_icon_mode: dto.personalization.tray_icon_mode.clone(),
        language: resolved_ui_language,
        onboarding_completed: cfg.personalization.onboarding_completed
            || dto.personalization.onboarding_completed,
        ..cfg.personalization.clone()
    };
    // NOTE: `skipped_version` and `last_checked_at` are intentionally NOT copied from `dto.update`;
    // `skipped_version` may only be mutated via dedicated `skip_update_version` /
    // `clear_skipped_update_version` IPCs (or cleared upon explicit manual download).
    cfg.update = UpdateConfig {
        repo: dto.update.repo.clone(),
        mode: dto.update.mode.clone(),
        check_interval_min: dto.update.check_interval_min,
        include_prerelease: dto.update.include_prerelease,
        auto_download: dto
            .update
            .auto_download
            .unwrap_or(cfg.update.auto_download),
        ..cfg.update.clone()
    };
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreRuntimeInfoDto {
    pub running: bool,
    pub status: String,
    pub core_name: String,
    pub core_version: String,
    pub proxy_mode: ProxyMode,
    pub route_mode: String,
    pub mixed_port: u16,
    pub controller_addr: String,
    pub uptime_sec: u64,
    pub rule_count: usize,
    pub active_group_id: String,
    pub active_group_name: String,
    pub active_node_id: String,
    pub active_node_name: String,
    pub active_node_region: String,
    pub active_node_latency_ms: Option<f64>,
    pub active_node_up_mbps: Option<f64>,
    pub preaccel_active: bool,
    #[serde(default)]
    pub preaccel_enabled: bool,
    #[serde(default)]
    pub preaccel_effective_carrier: String,
    #[serde(default)]
    pub standalone_tunnel_suspended_for_tun: bool,
    #[serde(default)]
    pub global_preaccel_active: bool,
    #[serde(default)]
    pub global_preaccel_mode: String,
    #[serde(default)]
    pub global_preaccel_socks_port: Option<u16>,
    #[serde(default)]
    pub global_preaccel_connections: u64,
    #[serde(default)]
    pub global_windivert_active: bool,
    #[serde(default)]
    pub preaccel_install_state: String,
    #[serde(default)]
    pub global_preaccel_verify_state: String,
    #[serde(default)]
    pub global_preaccel_verify_ms: Option<u64>,
    #[serde(default)]
    pub dns_tls_diagnostics: Option<DnsTlsDiagnostics>,
    #[serde(default)]
    pub node_health_hints: HashMap<String, NodeHealthHintDto>,
    #[serde(default)]
    pub probing_active: bool,
    #[serde(default)]
    pub switching_active: bool,
    #[serde(default)]
    pub active_group_circuit_open: bool,
    #[serde(default)]
    pub active_group_state: Option<String>,
    pub preaccel_relay_name: Option<String>,
    pub captive_portal_required: bool,
    pub system_proxy_enabled: bool,
    pub tun_enabled: bool,
    pub tun_configured: bool,
    pub tun_needs_elevation: bool,
    #[serde(default)]
    pub power_on_tun_degraded: bool,
    pub tun_admin_ready: bool,
    #[serde(default)]
    pub effective_tun_mtu: Option<u16>,
    #[serde(default)]
    pub preaccel_transport: Option<PreAccelTransportDiagnostics>,
    pub app_version: String,
    pub os_label: String,
    pub autostart_enabled: bool,
    pub portable_mode: bool,
    pub last_update_check: Option<String>,
    #[serde(default)]
    pub last_error: Option<String>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwitchResultDto {
    pub group_id: String,
    pub previous_node_id: Option<String>,
    pub active_node_id: String,
    pub active_node_name: String,
    pub active_node_region: String,
    pub latency_ms: Option<f64>,
    pub up_mbps: Option<f64>,
    pub closed_connections: usize,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitIpInfoDto {
    pub ip_masked: String,
    pub ip_raw: Option<String>,
    pub isp: String,
    pub location: String,
    pub timezone: String,
    pub google_clean: Option<bool>,
    pub core_running: bool,
    #[serde(default)]
    pub ip_clean: Option<bool>,
    #[serde(default)]
    pub ip_risk_level: Option<String>,
    #[serde(default)]
    pub ip_asn: Option<String>,
    #[serde(default)]
    pub ip_risk_flags: Option<String>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteCheckItemDto {
    pub id: String,
    pub name: String,
    pub url: String,
    pub latency_ms: Option<u64>,
    pub ok: Option<bool>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficEventPayload {
    pub up_bps: u64,
    pub down_bps: u64,
    pub up_total_bytes: u64,
    pub down_total_bytes: u64,
    pub active_connections: usize,
    #[serde(default)]
    pub tunnel_connections: usize,
    pub core_memory_mb: f64,
    pub timestamp_ms: i64,
}


pub(in crate::commands) fn format_bytes_human(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.1} GB", b / GB)
    } else if b >= MB {
        format!("{:.1} MB", b / MB)
    } else if b >= KB {
        format!("{:.0} KB", b / KB)
    } else {
        format!("{bytes} B")
    }
}


pub(in crate::commands) fn format_speed_compact(bps: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    let v = bps as f64;
    if v >= MB {
        format!("{:.2} MB/s", v / MB)
    } else if v >= KB {
        format!("{:.0} KB/s", v / KB)
    } else {
        format!("{bps} B/s")
    }
}


pub(in crate::commands) fn mask_ip_address(ip: &str) -> String {
    let trimmed = ip.trim();
    if let Some((prefix, _last)) = trimmed.rsplit_once('.') {
        return format!("{prefix}.***");
    }
    if let Some((prefix, _last)) = trimmed.rsplit_once(':') {
        return format!("{prefix}:***");
    }
    "--.--.--.***".to_string()
}


pub(in crate::commands) fn sync_autostart_if_changed(old: &AppConfig, cfg: &AppConfig) {
    let autostart_changed = old.behavior.autostart != cfg.behavior.autostart;
    let silent_changed_while_enabled =
        cfg.behavior.autostart && old.behavior.silent_start != cfg.behavior.silent_start;
    if !autostart_changed && !silent_changed_while_enabled {
        return;
    }
    if let Ok(exe) = std::env::current_exe() {
        let mut args = Vec::new();
        if cfg.behavior.silent_start {
            args.push("--silent".to_string());
        }
        let plat = default_platform();
        let _ = plat.set_autostart(cfg.behavior.autostart, &exe, &args);
    }
}


pub(in crate::commands) fn current_unix_ms() -> u64 {
    Utc::now().timestamp_millis().max(0) as u64
}


pub fn open_directory_in_os(path: &std::path::Path) -> Result<String, String> {
    std::fs::create_dir_all(path).map_err(|e| e.to_string())?;
    let display = path.display().to_string();
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(path)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(path)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(path)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    Ok(display)
}


pub fn copy_text_to_clipboard(text: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use std::io::Write;
        use std::os::windows::process::CommandExt;
        use std::process::{Command, Stdio};
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        // `clip.exe` natively decodes UTF-16LE with BOM (0xFF 0xFE) as CF_UNICODETEXT without
        // passing through legacy OEM code pages, eliminating Chinese mojibake on Windows.
        let mut utf16_bytes = Vec::with_capacity(2 + text.len().saturating_mul(2));
        utf16_bytes.extend_from_slice(&[0xFF, 0xFE]);
        for unit in text.encode_utf16() {
            utf16_bytes.extend_from_slice(&unit.to_le_bytes());
        }

        let clip_ok = Command::new("clip")
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .and_then(|mut child| {
                if let Some(mut stdin) = child.stdin.take() {
                    stdin.write_all(&utf16_bytes)?;
                }
                child.wait()
            })
            .is_ok_and(|status| status.success());

        if clip_ok {
            return Ok(());
        }

        // Fallback to PowerShell `Set-Clipboard` with explicit UTF-8 stdin decoding.
        let mut child = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "[Console]::InputEncoding = [System.Text.Encoding]::UTF8; Set-Clipboard -Value ([Console]::In.ReadToEnd())",
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("无法写入 Windows 剪贴板：{e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(text.as_bytes())
                .map_err(|e| format!("写入剪贴板数据失败：{e}"))?;
        }
        let status = child
            .wait()
            .map_err(|e| format!("等待剪贴板写入完成失败：{e}"))?;
        if !status.success() {
            return Err(format!("写入 Windows 剪贴板失败（退出码：{status}）"));
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut child = Command::new("pbcopy")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("无法调用 pbcopy 写入剪贴板：{e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(text.as_bytes())
                .map_err(|e| format!("写入 pbcopy 失败：{e}"))?;
        }
        let status = child
            .wait()
            .map_err(|e| format!("等待 pbcopy 完成失败：{e}"))?;
        if !status.success() {
            return Err(format!("pbcopy 返回失败状态：{status}"));
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let is_wayland = std::env::var_os("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty());
        let candidates: &[(&str, &[&str])] = if is_wayland {
            &[
                ("wl-copy", &[]),
                ("xclip", &["-selection", "clipboard"]),
                ("xsel", &["--clipboard", "--input"]),
            ]
        } else {
            &[
                ("xclip", &["-selection", "clipboard"]),
                ("xsel", &["--clipboard", "--input"]),
                ("wl-copy", &[]),
            ]
        };

        let mut last_err: Option<String> = None;
        for (bin, args) in candidates {
            // Always redirect stdout/stderr to null so backgrounded clipboard daemons (`xclip`,
            // `wl-copy`) never inherit parent pipes and hang callers.
            let spawn_res = Command::new(bin)
                .args(*args)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();
            match spawn_res {
                Ok(mut child) => {
                    let write_res = if let Some(mut stdin) = child.stdin.take() {
                        stdin.write_all(text.as_bytes())
                    } else {
                        Ok(())
                    };
                    if let Err(err) = write_res {
                        last_err = Some(format!("{bin} 写入失败：{err}"));
                        let _ = child.kill();
                        let _ = child.wait();
                        continue;
                    }
                    match child.wait() {
                        Ok(status) if status.success() => return Ok(()),
                        Ok(status) => {
                            last_err = Some(format!("{bin} 退出状态异常：{status}"));
                        }
                        Err(err) => {
                            last_err = Some(format!("等待 {bin} 结束失败：{err}"));
                        }
                    }
                }
                Err(err) => {
                    last_err = Some(format!("{bin} 不可用：{err}"));
                }
            }
        }

        Err(format!(
            "Linux 剪贴板写入失败，请安装 wl-clipboard（Wayland）或 xclip / xsel（X11）：{}",
            last_err.unwrap_or_else(|| "未找到可用剪贴板工具".to_string())
        ))
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = text;
        Err("当前操作系统暂不支持内置剪贴板写入，请手动复制内容".to_string())
    }
}

// ============================================================================
// Tauri IPC Commands (Complete Aligned Contract)
// ============================================================================


pub(in crate::commands) const MAX_INLINE_OVERRIDE_YAML_BYTES: usize = 1024 * 1024;


pub(in crate::commands) fn normalize_inline_override_yaml(cfg: &mut AppConfig) {
    if let Some(raw) = cfg.rules_override.inline_override_yaml.as_deref() {
        if raw.trim().is_empty() {
            cfg.rules_override.inline_override_yaml = None;
        }
    }
}


pub(in crate::commands) fn sanitize_dialog_filename_stem(raw: &str, fallback: &str) -> String {
    let cleaned: String = raw
        .trim()
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
                '-'
            } else {
                c
            }
        })
        .collect();
    let trimmed = cleaned.trim().trim_matches('.');
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.chars().take(64).collect()
    }
}


pub(crate) fn percent_encode_path_segment(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for &b in raw.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}


pub(in crate::commands) fn percent_encode_query_value(raw: &str) -> String {
    percent_encode_path_segment(raw)
}

