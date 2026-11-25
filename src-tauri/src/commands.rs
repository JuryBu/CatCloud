use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use catcloud_core::config;
use catcloud_core::core_adapter::binary_resolver::{
    compute_file_sha256, mihomo_binary_name, resolve_mihomo_binary,
};
use catcloud_core::core_adapter::config_compiler::{
    CompileInput, CompileStats, StaticValidationReport, compile_mihomo_config_with_runtime_dir,
    redact_compiled_yaml_for_preview,
};
use catcloud_core::core_adapter::hot_reload::{
    DiskReloadOptions, HotReloadCoordinator, has_core_config_changes,
};
use catcloud_core::core_adapter::mihomo::{
    MihomoAdapter, generate_controller_secret, verify_config_with_binary,
};
use catcloud_core::core_adapter::port_guard::{AllocatedPorts, allocate_safe_ports};
use catcloud_core::core_adapter::stream_client::{
    CoreTelemetryStore, MihomoStreamClient, StreamSessionHandle,
};
use catcloud_core::core_adapter::{
    ConnectionsSnapshot, CoreAdapter, CoreLogLine, CoreRuntimeStatus, CoreStartRequest,
    ReloadLevel, ReloadOutcome, SINGLE_NODE_GROUP_NAME, TrafficTick,
};
use catcloud_core::models::{
    AppConfig, CoreLogLevel, GlobalPreAccelScope, MemoryLimitTier, MultiGroup, MultiGroupMode,
    MultiGroupState, OverrideMode, PersonalizationConfig, PreAccelConfig, PreAccelRelay,
    ProbeDefinition, ProbeSnapshot, ProxyMode, ProxyNode, RouteTargetMode, SubscriptionKind,
    SubscriptionRecord, SwitchMode, ThemeDaySchedule, ThemeMode,
    TrayClickAction as CoreTrayClickAction, TrayIconMode, TunStackMode, UpdateApplyMode,
    UpdateConfig, normalize_ui_language,
};
use catcloud_core::platform::{SystemProxySpec, default_platform};
use catcloud_core::preaccel::campus::{
    CampusBypassTracker, CampusPortalState, probe_campus_portal_with_fallback,
};
use catcloud_core::preaccel::global_tunnel::{GlobalPreAccelManager, GlobalPreAccelStatus};
#[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
use catcloud_core::preaccel::global_tunnel::{
    build_default_windivert_proxy_candidates, download_and_install_windivert_with_fallbacks,
    locate_windivert_files,
};
use catcloud_core::probe::{
    DEFAULT_READY_TIMEOUT, FunnelOptions, FunnelTier, IsolatedProbeCore, ProbeRegistry,
    ThroughputProbeConfig, build_isolated_http_client, probe_live_google_cleanliness,
    run_download_probe_with_config, run_funnel_for_node, run_latency_probe,
    run_upload_probe_with_config,
};
use catcloud_core::process_guard::JobGuard;
#[cfg(target_os = "windows")]
use catcloud_core::process_guard::relaunch_self_as_admin;
use catcloud_core::share_bundle::{
    ShareBundleExportRequest, ShareBundleManifest, export_share_bundle_zip_file,
    preview_share_bundle_zip_file,
};
use catcloud_core::storage::{
    MergeSubscriptionsResult, Storage, SubscriptionNodesUpdateResult, SubscriptionUpdateMode,
};
use catcloud_core::strategy::evaluator::evaluate_group_candidates_with_runtime;
use catcloud_core::strategy::health_pool::{NodeHealthHintDto, NodeHealthPool, RuntimeDualHealth};
use catcloud_core::subscription::live_capture::{
    DesktopAppCandidate, LiveCaptureManager, LiveCaptureOutcomeDto, LiveCaptureStartDto,
    LiveCaptureStatusDto, list_desktop_app_candidates as core_list_desktop_app_candidates,
};
use catcloud_core::subscription::{
    ADAPTER_REASON_MANUAL, AdapterConfig, AdapterCooldownGuard, AdapterRequest, FetchOptions,
    ParsedSubscription, SubscriptionPayloadFormat, apply_parsed_subscription,
    inspect_process_source as core_inspect_process_source, invoke_external_adapter,
    parse_controller_proxies_json, parse_subscription_payload,
    preview_from_text as core_preview_from_text,
};
use catcloud_core::updater::Updater;
use catcloud_core::AppPaths;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::app_log::{self, APP_EVENT_PREFIX, RotatingAppLogger};
use crate::lifecycle;
use crate::shortcuts::{self, ShortcutAction, ShortcutBindings};
use crate::tray::{
    self, TrayClickAction, TrayGroupSummary, TrayHealthState, TrayMenuState, TrayNodeCandidate,
    TrayPreAccelRelayItem, TrayPreAccelSummary, TrayProxyMode, TraySubscriptionItem,
    TraySubscriptionSummary, TrayVisualState,
};

pub const EVENT_TRAFFIC: &str = "catcloud://traffic";
pub const EVENT_RUNTIME: &str = "catcloud://runtime";
pub const EVENT_CORE_LOG: &str = "catcloud://core-log";
pub const EVENT_PROBE_PROGRESS: &str = "catcloud://probe-progress";
pub const EVENT_TUN_NEEDS_ADMIN: &str = "catcloud://tun-needs-admin";
pub const EVENT_STRATEGY_SWITCH: &str = "catcloud://strategy-switch";
pub const EVENT_CONFIG_UPDATED: &str = "catcloud://config-updated";

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
    pub config: RwLock<AppConfig>,
    pub storage: Mutex<Storage>,
    pub job_guard: Arc<JobGuard>,
    pub global_preaccel: Arc<GlobalPreAccelManager>,
    pub live_capture: Arc<LiveCaptureManager>,
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
    pub system_proxy_lock: Arc<std::sync::Mutex<()>>,
    pub node_proxy_name_map: RwLock<HashMap<String, String>>,
    pub compiled_group_ids: RwLock<Option<HashSet<String>>>,
    pub last_log_level: RwLock<CoreLogLevel>,
    pub app_logger: Arc<RotatingAppLogger>,
    pub last_app_error: RwLock<Option<String>>,
    pub started_at: Instant,
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

impl AppState {
    pub fn new(
        paths: AppPaths,
        mut cfg: AppConfig,
        storage: Storage,
        job_guard: Arc<JobGuard>,
    ) -> Self {
        cfg.preaccel.reconcile_unified_enabled();
        let adapter = Arc::new(
            MihomoAdapter::new(Arc::clone(&job_guard))
                .expect("failed to initialize MihomoAdapter"),
        );
        let global_preaccel = Arc::new(GlobalPreAccelManager::new(
            paths.clone(),
            Arc::clone(&job_guard),
        ));
        let live_capture = Arc::new(LiveCaptureManager::new());
        let hot_reload = Arc::new(HotReloadCoordinator::new(paths.clone(), Arc::clone(&adapter)));
        let telemetry = Arc::new(CoreTelemetryStore::default());
        let app_logger = Arc::new(RotatingAppLogger::new(paths.logs_dir.clone()));
        let initial_log_level = cfg.log_level.clone();
        Self {
            paths,
            config: RwLock::new(cfg),
            storage: Mutex::new(storage),
            job_guard,
            global_preaccel,
            live_capture,
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
            system_proxy_lock: Arc::new(std::sync::Mutex::new(())),
            node_proxy_name_map: RwLock::new(HashMap::new()),
            compiled_group_ids: RwLock::new(None),
            last_log_level: RwLock::new(initial_log_level),
            app_logger,
            last_app_error: RwLock::new(None),
            started_at: Instant::now(),
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
        let custom_dir = self.snapshot_config().preaccel.windivert_dir;
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

    pub fn snapshot_config(&self) -> AppConfig {
        self.config
            .read()
            .map(|g| g.clone())
            .unwrap_or_default()
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
}

/// RAII guard preventing concurrent duplicate refreshes of the same subscription ID.
struct SubRefreshGuard<'a> {
    set: &'a Mutex<HashSet<String>>,
    sub_id: String,
}

impl<'a> SubRefreshGuard<'a> {
    fn try_acquire(set: &'a Mutex<HashSet<String>>, sub_id: String) -> Option<Self> {
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
struct AtomicFlagResetGuard(Arc<AtomicBool>);

impl Drop for AtomicFlagResetGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Nesting-safe RAII guard tracking active node/group switching and broadcasting
/// `catcloud://runtime` + tray visual updates on transitions so the floating capsule
/// and tray reflect live switching state across WebViews.
struct SwitchingActiveGuard {
    active: Arc<AtomicBool>,
    depth: Arc<AtomicUsize>,
    app: AppHandle,
}

impl SwitchingActiveGuard {
    fn enter(app: &AppHandle, state: &AppState) -> Self {
        let prev = state.switching_depth.fetch_add(1, Ordering::SeqCst);
        state.switching_active.store(true, Ordering::SeqCst);
        if prev == 0 {
            emit_runtime_snapshot(app, state);
            let _ = tray::sync_tray_visual(app, &build_tray_visual_state(state));
        }
        Self {
            active: Arc::clone(&state.switching_active),
            depth: Arc::clone(&state.switching_depth),
            app: app.clone(),
        }
    }
}

impl Drop for SwitchingActiveGuard {
    fn drop(&mut self) {
        let prev = self.depth.fetch_sub(1, Ordering::SeqCst);
        if prev <= 1 {
            self.active.store(false, Ordering::SeqCst);
            if let Some(st) = self.app.try_state::<AppState>() {
                emit_runtime_snapshot(&self.app, &st);
                let _ = tray::sync_tray_visual(&self.app, &build_tray_visual_state(&st));
            }
        }
    }
}

fn prune_node_health_pool_from_db(state: &AppState) {
    let valid: Option<(Option<HashSet<String>>, Option<HashSet<String>>)> =
        state.storage.lock().ok().map(|db| {
            let node_ids = db
                .list_nodes()
                .ok()
                .map(|nodes| nodes.into_iter().map(|n| n.id).collect());
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiUpdateDto {
    pub repo: String,
    pub mode: UpdateApplyMode,
    pub check_interval_min: u64,
    pub include_prerelease: bool,
    #[serde(default)]
    pub auto_download: Option<bool>,
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
            },
            update: UiUpdateDto {
                repo: cfg.update.repo.clone(),
                mode: cfg.update.mode.clone(),
                check_interval_min: cfg.update.check_interval_min,
                include_prerelease: cfg.update.include_prerelease,
                auto_download: Some(cfg.update.auto_download),
            },
        }
    }
}

fn apply_ui_dto(cfg: &mut AppConfig, dto: &UiAppConfigDto) {
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
    cfg.preaccel = PreAccelConfig {
        enabled: dto.preaccel.enabled,
        skip_443_native: dto.preaccel.skip_443_native,
        probe_url: dto.preaccel.probe_url.clone(),
        fallback_probe_url: dto.preaccel.fallback_probe_url.clone(),
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
        ..cfg.personalization.clone()
    };
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
    pub tun_admin_ready: bool,
    pub app_version: String,
    pub os_label: String,
    pub autostart_enabled: bool,
    pub portable_mode: bool,
    pub last_update_check: Option<String>,
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

fn format_bytes_human(bytes: u64) -> String {
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

fn format_speed_compact(bps: u64) -> String {
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

fn mask_ip_address(ip: &str) -> String {
    let trimmed = ip.trim();
    if let Some((prefix, _last)) = trimmed.rsplit_once('.') {
        return format!("{prefix}.***");
    }
    if let Some((prefix, _last)) = trimmed.rsplit_once(':') {
        return format!("{prefix}:***");
    }
    "--.--.--.***".to_string()
}

/// Return whether `node_id` is an enabled, valid member of `group`.
/// When `group.member_node_ids` is non-empty, the node MUST appear in `member_node_ids`.
fn is_valid_group_member(group: &MultiGroup, node_id: &str, nodes: &[ProxyNode]) -> bool {
    let trimmed = node_id.trim();
    if trimmed.is_empty() {
        return false;
    }
    if !group.member_node_ids.is_empty()
        && !group.member_node_ids.iter().any(|id| id == trimmed)
    {
        return false;
    }
    nodes.iter().any(|n| n.id == trimmed && n.enabled)
}

/// Count distinct enabled nodes eligible inside `group`.
pub fn count_enabled_group_members(group: &MultiGroup, nodes: &[ProxyNode]) -> usize {
    let mut seen = std::collections::HashSet::new();
    if !group.member_node_ids.is_empty() {
        for mid in &group.member_node_ids {
            if let Some(n) = nodes.iter().find(|n| &n.id == mid && n.enabled) {
                seen.insert(n.id.as_str());
            }
        }
    } else if matches!(group.mode, MultiGroupMode::ConditionalPool) || group.dynamic_filter.is_some()
    {
        for n in nodes.iter().filter(|n| n.enabled) {
            seen.insert(n.id.as_str());
        }
    }
    seen.len()
}

/// Resolve the consecutive failure threshold for runtime watchdog failover (`>= 2`).
pub fn group_watchdog_failure_threshold(group: &MultiGroup) -> u32 {
    group
        .trigger_rules
        .iter()
        .map(|r| r.consecutive_failures)
        .min()
        .unwrap_or(2)
        .max(2)
}

/// Resolve the displayable active node for `group`, strictly rejecting ghost `active_node_id`
/// values that have been removed from `group.member_node_ids`.
pub fn resolve_valid_group_active_node<'a>(
    group: &MultiGroup,
    nodes: &'a [ProxyNode],
) -> Option<&'a ProxyNode> {
    if !group.member_node_ids.is_empty() {
        if let Some(active_id) = group
            .active_node_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if group.member_node_ids.iter().any(|m| m == active_id) {
                if let Some(node) = nodes.iter().find(|n| n.id == active_id && n.enabled) {
                    return Some(node);
                }
            }
        }
        return group
            .member_node_ids
            .iter()
            .filter_map(|id| nodes.iter().find(|n| &n.id == id && n.enabled))
            .next()
            .or_else(|| {
                group
                    .member_node_ids
                    .iter()
                    .filter_map(|id| nodes.iter().find(|n| &n.id == id))
                    .next()
            });
    }

    if let Some(active_id) = group
        .active_node_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if let Some(node) = nodes.iter().find(|n| n.id == active_id && n.enabled) {
            return Some(node);
        }
    }
    nodes
        .iter()
        .find(|n| n.enabled)
        .or_else(|| nodes.first())
}

/// Pick the best enabled member node in `group` according to `evaluate_group_candidates`:
/// 1. Highest-scoring healthy candidate (`healthy_candidates`);
/// 2. Highest-scoring `ok` gate-passing candidate (`gate_passed`);
/// 3. Highest-scoring gate-passing candidate when static `hard_gates` are configured;
/// 4. When all members are rejected by `hard_gates` (`gate_passed` empty), keep honoring
///    `evaluate_group_candidates`'s descending score ranking (`gate_rejected`) — preferring
///    `ok` candidates first, then probed/score-distinguished candidates — instead of blindly
///    picking `member_node_ids[0]`;
/// 5. Finally fall back to the next enabled member in group order.
pub fn pick_best_group_candidate(
    group: &MultiGroup,
    nodes: &[ProxyNode],
    snaps: &HashMap<String, ProbeSnapshot>,
    exclude_node_id: Option<&str>,
) -> Option<String> {
    pick_best_group_candidate_with_runtime(
        group,
        nodes,
        snaps,
        exclude_node_id,
        None,
        Instant::now(),
    )
}

pub fn pick_best_group_candidate_with_runtime(
    group: &MultiGroup,
    nodes: &[ProxyNode],
    snaps: &HashMap<String, ProbeSnapshot>,
    exclude_node_id: Option<&str>,
    health_pool: Option<&NodeHealthPool>,
    now: Instant,
) -> Option<String> {
    let excluded = exclude_node_id.map(str::trim).filter(|s| !s.is_empty());
    let allowed = |id: &str| excluded != Some(id) && is_valid_group_member(group, id, nodes);

    if let Ok(report) = evaluate_group_candidates_with_runtime(group, nodes, snaps, health_pool, now)
    {
        if let Some(best) = report
            .healthy_candidates
            .iter()
            .find(|c| allowed(&c.node_id))
        {
            return Some(best.node_id.clone());
        }
        if let Some(best) = report
            .gate_passed
            .iter()
            .find(|c| c.ok && allowed(&c.node_id))
        {
            return Some(best.node_id.clone());
        }
        if !group.hard_gates.is_empty() || health_pool.is_some() {
            if let Some(best) = report.gate_passed.iter().find(|c| allowed(&c.node_id)) {
                return Some(best.node_id.clone());
            }
        }
        // Fallback when all candidates failed hard gates (e.g. unprobed `keepalive_ok == 1`):
        // keep honoring the descending score list (`gate_rejected`) rather than skipping scoring
        // and blindly falling back to `member_node_ids[0]`.
        if let Some(best) = report
            .gate_rejected
            .iter()
            .find(|c| c.ok && allowed(&c.node_id))
        {
            return Some(best.node_id.clone());
        }
        let allowed_rejected: Vec<_> = report
            .gate_rejected
            .iter()
            .filter(|c| allowed(&c.node_id))
            .collect();
        if let Some(best) = allowed_rejected
            .iter()
            .find(|c| snaps.contains_key(&c.node_id) && c.score.is_finite())
        {
            return Some(best.node_id.clone());
        }
        if let (Some(first), Some(last)) = (allowed_rejected.first(), allowed_rejected.last()) {
            if first.score.is_finite()
                && (!last.score.is_finite() || (first.score - last.score).abs() > 1e-9)
            {
                return Some(first.node_id.clone());
            }
        }
    }

    let mut enabled_members: Vec<&str> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    if !group.member_node_ids.is_empty() {
        for mid in &group.member_node_ids {
            if let Some(n) = nodes.iter().find(|n| &n.id == mid && n.enabled) {
                if seen.insert(n.id.as_str()) {
                    enabled_members.push(n.id.as_str());
                }
            }
        }
    } else {
        for n in nodes.iter().filter(|n| n.enabled) {
            if seen.insert(n.id.as_str()) {
                enabled_members.push(n.id.as_str());
            }
        }
    }

    if enabled_members.is_empty() {
        return None;
    }

    if let Some(ex) = excluded {
        if let Some(idx) = enabled_members.iter().position(|&id| id == ex) {
            if enabled_members.len() <= 1 {
                return None;
            }
            return Some(enabled_members[(idx + 1) % enabled_members.len()].to_string());
        }
    }

    enabled_members
        .into_iter()
        .find(|&id| excluded != Some(id))
        .map(str::to_string)
}

/// Default sliding window (10 s) for high-throughput failover suppression.
pub(crate) const WATCHDOG_HIGH_THROUGHPUT_WINDOW_MS: i64 = 10_000;
/// Default throughput guard threshold (256 KiB/s) protecting active uploads/downloads.
pub(crate) const WATCHDOG_HIGH_THROUGHPUT_THRESHOLD_BPS: u64 = 256 * 1024;

/// Return `true` when active transfer throughput meets or exceeds `threshold_bps`, checking both
/// the cached real-time rate and the peak rate within `window_ms` of `now_ms` inside
/// `recent_ticks` (so minimizing/hiding the GUI window, which zeroes `cached` on quiet ticks,
/// never disables active transfer protection).
pub(crate) fn is_high_throughput_active(
    cached: &CachedRealtimeMetrics,
    recent_ticks: &[TrafficTick],
    now_ms: i64,
    window_ms: i64,
    threshold_bps: u64,
) -> bool {
    if cached.up_bps.max(cached.down_bps) >= threshold_bps {
        return true;
    }
    let cutoff_ms = now_ms.saturating_sub(window_ms.max(0));
    let upper_ms = now_ms.saturating_add(5_000);
    for tick in recent_ticks {
        if tick.timestamp_ms >= cutoff_ms && tick.timestamp_ms <= upper_ms {
            if tick.up.max(tick.down) >= threshold_bps {
                return true;
            }
        }
    }
    false
}

fn collect_ranked_group_candidates(
    group: &MultiGroup,
    nodes: &[ProxyNode],
    snaps: &HashMap<String, ProbeSnapshot>,
    active_node_id: Option<&str>,
    cooldown_node_ids: &HashSet<String>,
    health_pool: Option<&NodeHealthPool>,
    now: Instant,
    exclude_pool_cooldowns: bool,
    max_candidates: usize,
) -> Vec<String> {
    if max_candidates == 0 {
        return Vec::new();
    }
    let active_trimmed = active_node_id.map(str::trim).filter(|s| !s.is_empty());
    let allowed = |id: &str| {
        active_trimmed != Some(id)
            && !cooldown_node_ids.contains(id)
            && !(exclude_pool_cooldowns && health_pool.is_some_and(|p| p.is_in_cooldown(id, now)))
            && is_valid_group_member(group, id, nodes)
    };

    let mut out: Vec<String> = Vec::with_capacity(max_candidates);
    let mut seen: HashSet<String> = HashSet::new();
    let mut push_if_allowed = |id: &str| -> bool {
        if out.len() >= max_candidates {
            return true;
        }
        if allowed(id) && seen.insert(id.to_string()) {
            out.push(id.to_string());
        }
        out.len() >= max_candidates
    };

    if let Ok(report) = evaluate_group_candidates_with_runtime(group, nodes, snaps, health_pool, now)
    {
        // Tier 1: highest-scoring healthy candidates.
        for c in &report.healthy_candidates {
            if push_if_allowed(&c.node_id) {
                return out;
            }
        }
        // Tier 2: highest-scoring ok gate-passing candidates.
        for c in report.gate_passed.iter().filter(|c| c.ok) {
            if push_if_allowed(&c.node_id) {
                return out;
            }
        }
        // Tier 3: remaining gate-passing candidates when static hard gates are configured
        // or a runtime health pool is active (preserving shortest-cooldown fallback order).
        if !group.hard_gates.is_empty() || health_pool.is_some() {
            for c in &report.gate_passed {
                if push_if_allowed(&c.node_id) {
                    return out;
                }
            }
        }
        // Tier 4: gate-rejected candidates preserving ok -> probed finite score -> distinct score order.
        for c in report.gate_rejected.iter().filter(|c| c.ok) {
            if push_if_allowed(&c.node_id) {
                return out;
            }
        }
        let allowed_rejected: Vec<_> = report
            .gate_rejected
            .iter()
            .filter(|c| allowed(&c.node_id))
            .collect();
        for c in allowed_rejected
            .iter()
            .filter(|c| snaps.contains_key(&c.node_id) && c.score.is_finite())
        {
            if push_if_allowed(&c.node_id) {
                return out;
            }
        }
        if let (Some(first), Some(last)) = (allowed_rejected.first(), allowed_rejected.last()) {
            if first.score.is_finite()
                && (!last.score.is_finite() || (first.score - last.score).abs() > 1e-9)
            {
                for c in &allowed_rejected {
                    if c.score.is_finite() && push_if_allowed(&c.node_id) {
                        return out;
                    }
                }
            }
        }
    }

    // Tier 5: fall back to enabled member order starting right after `active_node_id`.
    let mut enabled_members: Vec<&str> = Vec::new();
    let mut member_seen: HashSet<&str> = HashSet::new();
    if !group.member_node_ids.is_empty() {
        for mid in &group.member_node_ids {
            if let Some(n) = nodes.iter().find(|n| &n.id == mid && n.enabled) {
                if member_seen.insert(n.id.as_str()) {
                    enabled_members.push(n.id.as_str());
                }
            }
        }
    } else {
        for n in nodes.iter().filter(|n| n.enabled) {
            if member_seen.insert(n.id.as_str()) {
                enabled_members.push(n.id.as_str());
            }
        }
    }

    if enabled_members.is_empty() {
        return out;
    }

    let start_idx = active_trimmed
        .and_then(|aid| enabled_members.iter().position(|&id| id == aid))
        .map(|idx| (idx + 1) % enabled_members.len())
        .unwrap_or(0);
    for offset in 0..enabled_members.len() {
        let id = enabled_members[(start_idx + offset) % enabled_members.len()];
        if push_if_allowed(id) {
            break;
        }
    }

    out
}

/// Rank up to `max_candidates` backup nodes for watchdog failover using the same 5-tier priority
/// order as `pick_best_group_candidate`, excluding both `active_node_id` and nodes currently in
/// `cooldown_node_ids` or active runtime cooldown in `health_pool`. If every non-active member is
/// in cooldown, relaxes the cooldown filter as a last resort while still excluding `active_node_id`.
pub(crate) fn pick_group_candidates_with_cooldown_and_runtime(
    group: &MultiGroup,
    nodes: &[ProxyNode],
    snaps: &HashMap<String, ProbeSnapshot>,
    active_node_id: Option<&str>,
    cooldown_node_ids: &HashSet<String>,
    health_pool: Option<&NodeHealthPool>,
    now: Instant,
    max_candidates: usize,
) -> Vec<String> {
    let ranked = collect_ranked_group_candidates(
        group,
        nodes,
        snaps,
        active_node_id,
        cooldown_node_ids,
        health_pool,
        now,
        true,
        max_candidates,
    );
    if !ranked.is_empty() {
        return ranked;
    }
    let has_any_cooldown = !cooldown_node_ids.is_empty()
        || health_pool.is_some_and(|p| !p.is_empty());
    if !has_any_cooldown {
        return ranked;
    }
    let empty = HashSet::new();
    collect_ranked_group_candidates(
        group,
        nodes,
        snaps,
        active_node_id,
        &empty,
        health_pool,
        now,
        false,
        max_candidates,
    )
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn pick_group_candidates_with_cooldown(
    group: &MultiGroup,
    nodes: &[ProxyNode],
    snaps: &HashMap<String, ProbeSnapshot>,
    active_node_id: Option<&str>,
    cooldown_node_ids: &HashSet<String>,
    max_candidates: usize,
) -> Vec<String> {
    pick_group_candidates_with_cooldown_and_runtime(
        group,
        nodes,
        snaps,
        active_node_id,
        cooldown_node_ids,
        None,
        Instant::now(),
        max_candidates,
    )
}

/// Sanitize a group's `active_node_id`: when `!group.member_node_ids.is_empty()` and
/// `group.active_node_id` is missing, removed from `member_node_ids`, or disabled, replace it
/// with the highest-scoring gate-passing candidate via `evaluate_group_candidates_with_runtime`
/// (falling back to the first enabled member, or `None` if no enabled member exists).
/// Returns `true` if `group.active_node_id` was modified.
pub fn sanitize_group_active_node(
    group: &mut MultiGroup,
    nodes: &[ProxyNode],
    snaps: &HashMap<String, ProbeSnapshot>,
) -> bool {
    sanitize_group_active_node_with_runtime(group, nodes, snaps, None, Instant::now())
}

pub fn sanitize_group_active_node_with_runtime(
    group: &mut MultiGroup,
    nodes: &[ProxyNode],
    snaps: &HashMap<String, ProbeSnapshot>,
    health_pool: Option<&NodeHealthPool>,
    now: Instant,
) -> bool {
    if !group.member_node_ids.is_empty() {
        let current_valid = group
            .active_node_id
            .as_deref()
            .is_some_and(|id| is_valid_group_member(group, id, nodes));
        if current_valid {
            return false;
        }
        let next = pick_best_group_candidate_with_runtime(group, nodes, snaps, None, health_pool, now);
        if group.active_node_id != next {
            group.active_node_id = next;
            return true;
        }
        return false;
    }

    // Even for dynamic/empty-member groups, clear stale references to deleted or disabled nodes.
    if let Some(active_id) = group.active_node_id.as_deref() {
        if !is_valid_group_member(group, active_id, nodes) {
            let next =
                pick_best_group_candidate_with_runtime(group, nodes, snaps, None, health_pool, now);
            if group.active_node_id != next {
                group.active_node_id = next;
                return true;
            }
        }
    }
    false
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReconcileSwitchDecision {
    from_node_id: Option<String>,
    from_node_name: String,
    to_node_id: String,
    to_node_name: String,
    reason: String,
}

/// Pure strategy reconciler for a multi-group:
/// 1. Always clears ghost/invalid `active_node_id` via `sanitize_group_active_node_with_runtime`.
/// 2. For `StickyBest` / `ConditionalPool` groups, if the current active node is unprobed,
///    failed/disconnected, or violates hard gates while a gate-passing healthy candidate exists,
///    switches to the top-ranked candidate.
/// 3. Respects sticky user choice: if the current active node is already in-group, probed,
///    connected, and passes all hard gates, leaves it untouched to prevent IP drift.
#[cfg_attr(not(test), allow(dead_code))]
fn reconcile_group_best_node_in_memory(
    group: &mut MultiGroup,
    nodes: &[ProxyNode],
    snaps: &HashMap<String, ProbeSnapshot>,
) -> Option<ReconcileSwitchDecision> {
    reconcile_group_best_node_in_memory_with_runtime(group, nodes, snaps, None, Instant::now())
}

fn reconcile_group_best_node_in_memory_with_runtime(
    group: &mut MultiGroup,
    nodes: &[ProxyNode],
    snaps: &HashMap<String, ProbeSnapshot>,
    health_pool: Option<&NodeHealthPool>,
    now: Instant,
) -> Option<ReconcileSwitchDecision> {
    let prev_id = group.active_node_id.clone();
    let prev_name = prev_id
        .as_deref()
        .and_then(|id| nodes.iter().find(|n| n.id == id))
        .map(|n| n.name.clone())
        .or_else(|| prev_id.clone())
        .unwrap_or_else(|| "未选定".to_string());

    let current_valid = prev_id
        .as_deref()
        .is_some_and(|id| is_valid_group_member(group, id, nodes));

    if !current_valid {
        sanitize_group_active_node_with_runtime(group, nodes, snaps, health_pool, now);
        if let Some(to_id) = group.active_node_id.clone() {
            if prev_id.as_deref() != Some(to_id.as_str()) {
                let to_name = nodes
                    .iter()
                    .find(|n| n.id == to_id)
                    .map(|n| n.name.clone())
                    .unwrap_or_else(|| to_id.clone());
                return Some(ReconcileSwitchDecision {
                    from_node_id: prev_id,
                    from_node_name: prev_name,
                    to_node_id: to_id,
                    to_node_name: to_name,
                    reason: "原节点已不在本组或已停用，已自动切换至最优候选节点".to_string(),
                });
            }
        }
        return None;
    }

    if !matches!(
        group.mode,
        MultiGroupMode::StickyBest | MultiGroupMode::ConditionalPool
    ) {
        return None;
    }

    let cur_id = prev_id.as_deref()?;
    let Ok(report) =
        evaluate_group_candidates_with_runtime(group, nodes, snaps, health_pool, now)
    else {
        return None;
    };

    let best = report
        .healthy_candidates
        .iter()
        .find(|c| is_valid_group_member(group, &c.node_id, nodes))
        .or_else(|| {
            report
                .gate_passed
                .iter()
                .find(|c| c.ok && is_valid_group_member(group, &c.node_id, nodes))
        })
        .or_else(|| {
            report
                .gate_rejected
                .iter()
                .find(|c| c.ok && is_valid_group_member(group, &c.node_id, nodes))
        })?;

    if best.node_id == cur_id {
        return None;
    }

    let cur_snap = snaps.get(cur_id);
    let cur_runtime_healthy = health_pool
        .and_then(|p| p.get(cur_id))
        .is_some_and(|h| {
            h.last_health == Some(RuntimeDualHealth::FullHealthy) && !h.is_in_cooldown(now)
        });
    let assessment = report.active_assessment.as_ref();

    let reason = if cur_snap.is_none() && !cur_runtime_healthy {
        "当前节点尚未测速，已自动选用组内最优合格节点"
    } else if assessment.map_or(cur_snap.is_some_and(|s| !s.ok), |a| a.is_disconnected) {
        "当前节点测速未通过，已自动切换至组内最优健康节点"
    } else if best.passed_hard_gates && assessment.is_some_and(|a| !a.passed_hard_gates) {
        "当前节点未满足本组硬性门禁条件，已自动切换至达标最优节点"
    } else if best.meets_thresholds && assessment.is_some_and(|a| a.any_rule_triggered) {
        "当前节点已触发本组自动切换条件，已切换至达标最优节点"
    } else {
        // Current active node is in-group, probed, healthy, passes all hard gates, and triggers no rules:
        // preserve sticky selection to avoid IP drift.
        return None;
    };

    group.active_node_id = Some(best.node_id.clone());
    Some(ReconcileSwitchDecision {
        from_node_id: prev_id,
        from_node_name: prev_name,
        to_node_id: best.node_id.clone(),
        to_node_name: best.node_name.clone(),
        reason: reason.to_string(),
    })
}

fn select_tray_group_candidates<'a>(
    group: &MultiGroup,
    nodes: &'a [ProxyNode],
    node_by_id: &HashMap<&str, &'a ProxyNode>,
    limit: usize,
) -> Vec<&'a ProxyNode> {
    let raw_members: Vec<&'a ProxyNode> = if group.member_node_ids.is_empty() {
        nodes.iter().filter(|n| n.enabled).collect()
    } else {
        group
            .member_node_ids
            .iter()
            .filter_map(|id| node_by_id.get(id.as_str()).copied())
            .filter(|n| n.enabled)
            .collect()
    };
    let mut ordered = Vec::with_capacity(limit.min(raw_members.len().saturating_add(1)));
    if let Some(active_id) = group.active_node_id.as_deref() {
        let in_group = group.member_node_ids.is_empty()
            || group.member_node_ids.iter().any(|m| m == active_id);
        if in_group {
            if let Some(active_node) = node_by_id.get(active_id).copied().filter(|n| n.enabled) {
                ordered.push(active_node);
            }
        }
    }
    for n in raw_members {
        if ordered.len() >= limit {
            break;
        }
        if ordered.iter().any(|existing| existing.id == n.id) {
            continue;
        }
        ordered.push(n);
    }
    ordered
}

/// Return `true` only when the main proxy core is genuinely taking over host traffic
/// (core process is running AND either OS system proxy or effective privileged TUN is enabled).
pub(crate) fn is_proxy_takeover_active(
    core_running: bool,
    cfg: &AppConfig,
    tun_admin_ready: bool,
) -> bool {
    let eff_tun = cfg.tun.enabled && tun_admin_ready;
    core_running && (cfg.system_proxy.enabled || eff_tun)
}

/// Return `true` only when TUN is configured ON AND the current process/binary holds TUN privileges.
pub fn effective_tun_enabled(state: &AppState, cfg: &AppConfig) -> bool {
    cfg.tun.enabled && is_tun_privilege_ready(state)
}

/// Return `true` when the user configured TUN ON (`cfg.tun.enabled == true`) but current privileges
/// are insufficient so TUN cannot genuinely take effect.
pub fn tun_needs_elevation(state: &AppState, cfg: &AppConfig) -> bool {
    cfg.tun.enabled && !is_tun_privilege_ready(state)
}

/// Build a runtime copy of `cfg` with `tun.enabled` clamped to `false` when TUN privileges are absent,
/// without ever mutating the persisted `config.json` intent.
fn effective_config_for_runtime(state: &AppState, cfg: &AppConfig) -> AppConfig {
    let mut eff = cfg.clone();
    if eff.tun.enabled && !is_tun_privilege_ready(state) {
        eff.tun.enabled = false;
    }
    eff
}

pub fn build_tray_menu_state(app: &AppHandle, state: &AppState) -> TrayMenuState {
    build_tray_menu_state_with_verify_override(app, state, None)
}

fn build_tray_menu_state_with_verify_override(
    app: &AppHandle,
    state: &AppState,
    verify_override: Option<(&str, Option<u64>)>,
) -> TrayMenuState {
    let cfg = state.snapshot_config();
    let win = lifecycle::window_mode_snapshot(app);

    let (groups, nodes, relays, subs, snaps) = state
        .storage
        .lock()
        .map(|db| {
            let groups = db.list_multi_groups().unwrap_or_default();
            let nodes = db.list_nodes().unwrap_or_default();
            let relays = db.list_preaccel_relays(false).unwrap_or_default();
            let subs = db.list_subscriptions().unwrap_or_default();
            let ids: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
            let snaps = db.get_probe_snapshots_batch(&ids, None).unwrap_or_default();
            (groups, nodes, relays, subs, snaps)
        })
        .unwrap_or_default();

    let node_by_id: HashMap<&str, &ProxyNode> =
        nodes.iter().map(|n| (n.id.as_str(), n)).collect();

    let active_single_node_label = if cfg.route_mode == RouteTargetMode::Single {
        cfg.active_single_node_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|id| node_by_id.get(id))
            .map(|n| n.name.clone())
    } else {
        None
    };
    let in_single_mode = active_single_node_label.is_some();

    let primary_idx = cfg
        .active_group_id
        .as_deref()
        .and_then(|aid| groups.iter().position(|g| g.id == aid))
        .unwrap_or(0);
    let mut ordered_groups: Vec<&MultiGroup> = Vec::with_capacity(groups.len().min(6));
    if let Some(primary) = groups.get(primary_idx) {
        ordered_groups.push(primary);
    }
    for (idx, g) in groups.iter().enumerate() {
        if idx != primary_idx && ordered_groups.len() < 6 {
            ordered_groups.push(g);
        }
    }

    let mut group_summaries: Vec<TrayGroupSummary> = Vec::new();
    for g in ordered_groups {
        let member_nodes = select_tray_group_candidates(g, &nodes, &node_by_id, 8);
        let valid_active_id = g.active_node_id.as_deref().filter(|id| {
            (g.member_node_ids.is_empty() || g.member_node_ids.iter().any(|m| m == id))
                && node_by_id.get(id).is_some_and(|n| n.enabled)
        });
        let active_label = valid_active_id
            .and_then(|id| node_by_id.get(id))
            .map(|n| n.name.clone())
            .or_else(|| member_nodes.first().map(|n| n.name.clone()))
            .unwrap_or_else(|| "自动择优".to_string());
        let effective_selected_id =
            valid_active_id.or_else(|| member_nodes.first().map(|n| n.id.as_str()));
        let candidates = member_nodes
            .into_iter()
            .map(|n| {
                let snap = snaps.get(&n.id);
                TrayNodeCandidate {
                    node_id: n.id.clone(),
                    label: n.name.clone(),
                    up_mbps_x100: snap
                        .and_then(|s| s.up_mbps)
                        .map(|v| (v.max(0.0) * 100.0).round() as u32),
                    ping_ms: state
                        .resolve_node_latency_ms(&n.id, snap)
                        .map(|v| v.max(0.0).round() as u32),
                    selected: !in_single_mode && effective_selected_id == Some(n.id.as_str()),
                }
            })
            .collect();
        group_summaries.push(TrayGroupSummary {
            group_id: g.id.clone(),
            group_name: g.name.clone(),
            active_node_label: active_label,
            candidates,
        });
    }

    let primary_group = if group_summaries.is_empty() {
        None
    } else {
        Some(group_summaries.remove(0))
    };

    let active_relay_label = cfg
        .preaccel
        .active_relay_id
        .as_deref()
        .and_then(|id| relays.iter().find(|r| r.id == id))
        .or_else(|| relays.iter().find(|r| r.enabled))
        .map(|r| r.name.clone());

    let tray_relays: Vec<TrayPreAccelRelayItem> = relays
        .iter()
        .take(8)
        .map(|r| TrayPreAccelRelayItem {
            relay_id: r.id.clone(),
            label: format!("{} ({})", r.name, r.region),
            mbps: r.last_up_mbps.or(r.last_mbps).map(|v| v.max(0.0).round() as u32),
            ping_ms: r.last_probe_ms.map(|v| v.max(0.0).round() as u32),
            selected: cfg.preaccel.active_relay_id.as_deref() == Some(r.id.as_str()),
        })
        .collect();

    let mut sub_node_counts: HashMap<&str, usize> = HashMap::new();
    for n in &nodes {
        *sub_node_counts.entry(n.sub_id.as_str()).or_insert(0) += 1;
    }
    let total_remaining: u64 = subs.iter().map(|s| s.remaining_bytes()).sum();
    let tray_sub_items: Vec<TraySubscriptionItem> = subs
        .iter()
        .take(8)
        .map(|s| TraySubscriptionItem {
            sub_id: s.id.clone(),
            name: s.name.clone(),
            remaining_label: if s.traffic_total_bytes > 0 {
                format!("余 {}", format_bytes_human(s.remaining_bytes()))
            } else {
                "本地/未上报".to_string()
            },
            node_count: *sub_node_counts.get(s.id.as_str()).unwrap_or(&0),
        })
        .collect();

    let rt = state.snapshot_runtime();
    let global_status = state.snapshot_global_preaccel();
    let verify_state = verify_override
        .map(|(s, _)| s.to_string())
        .unwrap_or_else(|| global_status.verify_state.clone());
    let verify_ms = verify_override
        .map(|(_, ms)| ms)
        .unwrap_or(global_status.verify_latency_ms);
    let tun_ready = is_tun_privilege_ready(state);
    let eff_tun = cfg.tun.enabled && tun_ready;
    let tun_need_elev = cfg.tun.enabled && !tun_ready;
    let proxy_active = is_proxy_takeover_active(rt.running, &cfg, tun_ready);
    let global_mode_label = if !cfg.preaccel.enabled && !global_status.running {
        None
    } else if proxy_active && cfg.preaccel.enabled {
        if global_status.is_windivert_active {
            Some("dual".to_string())
        } else {
            None
        }
    } else if global_status.is_windivert_active {
        Some("windivert".to_string())
    } else if matches!(
        global_status.install_state.as_str(),
        "downloading" | "verifying"
    ) {
        Some("downloading".to_string())
    } else if global_status.install_state == "need_elevation" {
        Some("need_elevation".to_string())
    } else if global_status.running {
        Some("local_socks5".to_string())
    } else if cfg.preaccel.enabled {
        Some("standby".to_string())
    } else {
        None
    };

    TrayMenuState {
        proxy_mode: match cfg.proxy_mode {
            ProxyMode::Rule => TrayProxyMode::Rule,
            ProxyMode::Global => TrayProxyMode::Global,
            ProxyMode::Direct => TrayProxyMode::Direct,
        },
        system_proxy_enabled: cfg.system_proxy.enabled,
        tun_enabled: eff_tun,
        tun_needs_elevation: tun_need_elev,
        windowless_mode: win.windowless,
        capsule_open: win.capsule_open,
        autostart_enabled: cfg.behavior.autostart,
        active_single_node_label,
        primary_group,
        extra_groups: group_summaries,
        preaccel: TrayPreAccelSummary {
            enabled: cfg.preaccel.enabled,
            active_label: active_relay_label,
            relays: tray_relays,
            global_enabled: cfg.preaccel.enabled,
            global_running: global_status.is_windivert_active,
            global_mode_label,
            global_preaccel_verify_state: verify_state,
            global_preaccel_verify_ms: verify_ms,
        },
        subscriptions: TraySubscriptionSummary {
            total_remaining_label: if total_remaining > 0 {
                Some(format_bytes_human(total_remaining))
            } else {
                None
            },
            items: tray_sub_items,
        },
    }
}

pub fn build_tray_visual_state(state: &AppState) -> TrayVisualState {
    build_tray_visual_state_with_verify_override(state, None)
}

fn build_tray_visual_state_with_verify_override(
    state: &AppState,
    verify_override: Option<(&str, Option<u64>)>,
) -> TrayVisualState {
    let cfg = state.snapshot_config();
    let rt = state.snapshot_runtime();
    let global_status = state.snapshot_global_preaccel();
    let metrics = state
        .cached_metrics
        .read()
        .map(|g| *g)
        .unwrap_or_default();
    let portal_required = state
        .campus_tracker
        .lock()
        .map(|t| matches!(t.state(), CampusPortalState::CaptivePortalRequired { .. }))
        .unwrap_or(false);

    let icon_mode = match cfg.personalization.tray_icon_mode {
        TrayIconMode::AutoAc => tray::TrayIconMode::AutoAc,
        TrayIconMode::AlwaysA => tray::TrayIconMode::AlwaysA,
        TrayIconMode::AlwaysC => tray::TrayIconMode::AlwaysC,
        TrayIconMode::AlwaysPixel => tray::TrayIconMode::AlwaysPixel,
    };
    let (
        primary_group_summary,
        configured_relay_name,
        has_enabled_relays,
        active_group_circuit_open,
        active_group_degraded_warn,
        active_group_in_backoff,
    ) = state
        .storage
        .lock()
        .ok()
        .map(|db| {
            let relays = db.list_preaccel_relays(true).unwrap_or_default();
            let has_relays = !relays.is_empty();
            let relay_name = cfg
                .preaccel
                .active_relay_id
                .as_deref()
                .and_then(|id| relays.iter().find(|r| r.id == id))
                .or_else(|| relays.first())
                .map(|r| r.name.clone());

            let (group_summary, circuit_open, degraded_warn, in_backoff) = (|| {
                if cfg.route_mode == RouteTargetMode::Single {
                    if let Some(node) = cfg
                        .active_single_node_id
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .and_then(|id| db.get_node(id).ok().flatten())
                    {
                        return (Some(format!("单节点 · {}", node.name)), false, false, false);
                    }
                }
                let Ok(groups) = db.list_multi_groups() else {
                    return (None, false, false, false);
                };
                let nodes = db.list_nodes().unwrap_or_default();
                let Some(g) = cfg
                    .active_group_id
                    .as_deref()
                    .and_then(|gid| groups.iter().find(|g| g.id == gid))
                    .or_else(|| groups.first())
                else {
                    return (None, false, false, false);
                };
                let node_name = resolve_valid_group_active_node(g, &nodes)
                    .map(|n| n.name.clone())
                    .unwrap_or_else(|| "自动择优".to_string());
                let is_circuit_open = matches!(g.state, MultiGroupState::CircuitOpen);
                let is_degraded = matches!(g.state, MultiGroupState::DegradedWarn);
                let is_backoff = state.is_group_in_backoff(&g.id);
                (
                    Some(format!("{} -> {}", g.name, node_name)),
                    is_circuit_open,
                    is_degraded,
                    is_backoff,
                )
            })();
            (
                group_summary,
                relay_name,
                has_relays,
                circuit_open,
                degraded_warn,
                in_backoff,
            )
        })
        .unwrap_or((None, None, false, false, false, false));

    let effective_proxy_mode = if rt.running {
        rt.proxy_mode.clone()
    } else {
        cfg.proxy_mode.clone()
    };
    let is_direct_mode = effective_proxy_mode == ProxyMode::Direct;
    let tun_ready = is_tun_privilege_ready(state);
    let eff_tun = cfg.tun.enabled && tun_ready;
    let tun_need_elev = cfg.tun.enabled && !tun_ready;
    let proxy_active = is_proxy_takeover_active(rt.running, &cfg, tun_ready);
    let verify_state = verify_override
        .map(|(s, _)| s.to_string())
        .unwrap_or_else(|| global_status.verify_state.clone());
    let verify_ms = verify_override
        .map(|(_, ms)| ms)
        .unwrap_or(global_status.verify_latency_ms);
    let verify_state_trimmed = verify_state.trim();
    let preaccel_verify_degraded = cfg.preaccel.enabled && verify_state_trimmed == "degraded";
    let preaccel_verify_probing = cfg.preaccel.enabled && verify_state_trimmed == "probing";
    let preaccel_active = !preaccel_verify_degraded
        && !preaccel_verify_probing
        && ((!is_direct_mode && proxy_active && cfg.preaccel.enabled && has_enabled_relays)
            || global_status.is_windivert_active);
    let health = if rt.last_error.is_some() || active_group_circuit_open {
        TrayHealthState::Error
    } else if portal_required
        || preaccel_verify_degraded
        || active_group_in_backoff
        || active_group_degraded_warn
    {
        TrayHealthState::Warn
    } else if is_direct_mode {
        if !preaccel_verify_probing && global_status.is_windivert_active {
            TrayHealthState::PreAccel
        } else {
            TrayHealthState::Idle
        }
    } else if preaccel_active {
        TrayHealthState::PreAccel
    } else if proxy_active {
        TrayHealthState::Ok
    } else {
        TrayHealthState::Idle
    };

    let probing_active = state.probe_running.load(Ordering::SeqCst);
    let switching_active = state.is_switching_active();
    let status_notice = if active_group_circuit_open {
        Some("活跃分组已熔断 (REJECT)".to_string())
    } else if active_group_in_backoff {
        Some("活跃分组全组退避冷却中".to_string())
    } else if active_group_degraded_warn {
        Some("活跃分组已降级告警".to_string())
    } else if probing_active {
        Some("测速进行中…".to_string())
    } else if switching_active {
        Some("切换节点中…".to_string())
    } else if is_direct_mode && proxy_active {
        Some("直连模式（不走海外代理）".to_string())
    } else {
        None
    };

    let active_relay_name = global_status
        .active_relays
        .first()
        .cloned()
        .or(configured_relay_name);

    let preaccel_summary = if preaccel_verify_degraded {
        Some("已保护回退（请查看国内提速环境放行指引）".to_string())
    } else if preaccel_verify_probing {
        Some("探测链路中…".to_string())
    } else if proxy_active && cfg.preaccel.enabled && has_enabled_relays {
        let prefix = if global_status.is_windivert_active {
            match verify_ms.filter(|_| verify_state_trimmed == "verified") {
                Some(ms) => format!("全局+代理提速中 ({ms} ms)"),
                None => "全局+代理提速中".to_string(),
            }
        } else {
            "国内提速中".to_string()
        };
        match active_relay_name.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(relay) => Some(format!("{prefix} · {relay}")),
            None => Some(prefix),
        }
    } else if global_status.is_windivert_active {
        let prefix = match verify_ms.filter(|_| verify_state_trimmed == "verified") {
            Some(ms) => format!("全局提速中 ({ms} ms)"),
            None => "全局提速中".to_string(),
        };
        match active_relay_name.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(relay) => Some(format!("{prefix} · {relay}")),
            None => Some(prefix),
        }
    } else if cfg.preaccel.enabled
        && matches!(
            global_status.install_state.as_str(),
            "downloading" | "verifying"
        )
    {
        Some("正在准备提速组件…".to_string())
    } else if cfg.preaccel.enabled && global_status.install_state == "need_elevation" {
        Some("需管理员权限启用全局提速".to_string())
    } else if global_status.running {
        match global_status.socks_port {
            Some(port) => Some(format!("本地443通道待命 (127.0.0.1:{port})")),
            None => Some("本地443通道待命".to_string()),
        }
    } else if cfg.preaccel.enabled {
        Some("国内提速已开启（待启动）".to_string())
    } else {
        None
    };

    let realtime_speed = if rt.running {
        Some(format!(
            "↑{} ↓{}",
            format_speed_compact(metrics.up_bps),
            format_speed_compact(metrics.down_bps)
        ))
    } else {
        None
    };

    let info = tray::TrayTooltipInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        runtime_mode_label: if state.paths.is_portable {
            "便携模式".to_string()
        } else {
            "标准模式".to_string()
        },
        proxy_mode: match effective_proxy_mode {
            ProxyMode::Rule => TrayProxyMode::Rule,
            ProxyMode::Global => TrayProxyMode::Global,
            ProxyMode::Direct => TrayProxyMode::Direct,
        },
        tun_enabled: eff_tun,
        tun_needs_elevation: tun_need_elev,
        system_proxy_enabled: cfg.system_proxy.enabled,
        preaccel_summary,
        primary_group_summary,
        realtime_speed,
        status_notice,
    };
    TrayVisualState {
        icon_mode,
        health,
        tooltip: info.format_tooltip(),
        global_preaccel_verify_state: verify_state,
        global_preaccel_verify_ms: verify_ms,
    }
}

/// Return `true` when TUN virtual NIC privileges are satisfied on the current OS:
/// - Windows/macOS: current process is elevated (`is_elevated`).
/// - Linux: process is root OR the resolved Mihomo core binary carries `cap_net_admin` file
///   capabilities so TUN works without running the desktop GUI as root.
pub fn is_tun_privilege_ready(state: &AppState) -> bool {
    let _ = state;
    if default_platform().capabilities().is_elevated {
        return true;
    }
    #[cfg(target_os = "linux")]
    {
        let cfg = state.snapshot_config();
        let extra = state.extra_binary_candidates();
        if let Ok(res) = resolve_mihomo_binary(&cfg, &state.paths, &extra, false) {
            if let Some(bin_path) = res.path {
                return catcloud_core::platform::linux::has_mihomo_tun_capability(&bin_path);
            }
        }
    }
    false
}

fn tun_needs_admin_error_message() -> String {
    #[cfg(target_os = "linux")]
    {
        "NEEDS_ADMIN:开启虚拟网卡（TUN）需要为代理核心授予 Linux 网络权限（setcap），请点击「立即授权」一键启用"
            .to_string()
    }
    #[cfg(target_os = "macos")]
    {
        "NEEDS_ADMIN:macOS 开启虚拟网卡（TUN）需要管理员权限，请通过管理员终端启动应用或在后续系统授权后启用 TUN"
            .to_string()
    }
    #[cfg(target_os = "windows")]
    {
        "NEEDS_ADMIN:开启虚拟网卡（TUN）需要管理员权限，请点击「以管理员身份重启」一键开启"
            .to_string()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "NEEDS_ADMIN:开启虚拟网卡（TUN）需要管理员权限，请使用具备网络管理权限的账户启动应用"
            .to_string()
    }
}

pub fn build_runtime_info_dto(state: &AppState) -> Result<CoreRuntimeInfoDto, String> {
    build_runtime_info_dto_with_verify_override(state, None)
}

fn build_runtime_info_dto_with_verify_override(
    state: &AppState,
    verify_override: Option<(&str, Option<u64>)>,
) -> Result<CoreRuntimeInfoDto, String> {
    let cfg = state.snapshot_config();
    let rt = state.snapshot_runtime();
    let plat = default_platform();
    let caps = plat.capabilities();
    let portal_required = state
        .campus_tracker
        .lock()
        .map(|t| matches!(t.state(), CampusPortalState::CaptivePortalRequired { .. }))
        .unwrap_or(false);

    let (
        effective_route_mode,
        active_group_id,
        active_group_name,
        active_group_circuit_open,
        active_group_degraded_warn,
        active_group_in_backoff,
        active_group_state,
        active_node_id,
        active_node_name,
        active_node_region,
        relays,
        active_snap,
    ) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let groups = db.list_multi_groups().unwrap_or_default();
        let nodes = db.list_nodes().unwrap_or_default();
        let relays = db.list_preaccel_relays(true).unwrap_or_default();
        let primary_group = cfg
            .active_group_id
            .as_deref()
            .and_then(|gid| groups.iter().find(|g| g.id == gid))
            .or_else(|| groups.first());
        let single_node = if cfg.route_mode == RouteTargetMode::Single {
            cfg.active_single_node_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .and_then(|id| nodes.iter().find(|n| n.id == id))
        } else {
            None
        };
        let (mode, active_node, probe_id_hint) = if let Some(sn) = single_node {
            (RouteTargetMode::Single, Some(sn), None)
        } else {
            let group_node = match primary_group {
                Some(g) => resolve_valid_group_active_node(g, &nodes),
                None => nodes.iter().find(|n| n.enabled).or_else(|| nodes.first()),
            };
            (
                RouteTargetMode::Group,
                group_node,
                primary_group.and_then(|g| g.primary_probe_id.as_deref()),
            )
        };
        let (group_circuit_open, group_degraded_warn, group_in_backoff, group_state_label) =
            if mode == RouteTargetMode::Group {
                if let Some(g) = primary_group {
                    let circuit_open = matches!(g.state, MultiGroupState::CircuitOpen);
                    let degraded_warn = matches!(g.state, MultiGroupState::DegradedWarn);
                    let in_backoff = state.is_group_in_backoff(&g.id);
                    let label = if in_backoff && !circuit_open {
                        Some("backoff".to_string())
                    } else {
                        Some(g.state.as_str().to_string())
                    };
                    (circuit_open, degraded_warn, in_backoff, label)
                } else {
                    (false, false, false, None)
                }
            } else {
                (false, false, false, None)
            };
        let snap = active_node.and_then(|n| {
            db.get_probe_snapshot(&n.id, probe_id_hint)
                .ok()
                .flatten()
        });
        (
            mode,
            primary_group.map(|g| g.id.clone()).unwrap_or_default(),
            primary_group
                .map(|g| g.name.clone())
                .unwrap_or_else(|| "默认路线".to_string()),
            group_circuit_open,
            group_degraded_warn,
            group_in_backoff,
            group_state_label,
            active_node.map(|n| n.id.clone()).unwrap_or_default(),
            active_node
                .map(|n| n.name.clone())
                .unwrap_or_else(|| "待导入节点".to_string()),
            active_node
                .map(|n| n.region_code.clone())
                .unwrap_or_else(|| "--".to_string()),
            relays,
            snap,
        )
    };

    let global_status = state.snapshot_global_preaccel();
    let verify_state = verify_override
        .map(|(s, _)| s.to_string())
        .unwrap_or_else(|| global_status.verify_state.clone());
    let verify_ms = verify_override
        .map(|(_, ms)| ms)
        .unwrap_or(global_status.verify_latency_ms);
    let verify_state_trimmed = verify_state.trim();
    let effective_proxy_mode = if rt.running {
        rt.proxy_mode.clone()
    } else {
        cfg.proxy_mode.clone()
    };
    let is_direct_mode = effective_proxy_mode == ProxyMode::Direct;
    let preaccel_verify_degraded = cfg.preaccel.enabled && verify_state_trimmed == "degraded";
    let preaccel_verify_probing = cfg.preaccel.enabled && verify_state_trimmed == "probing";
    let tun_admin_ready = is_tun_privilege_ready(state);
    let eff_tun = cfg.tun.enabled && tun_admin_ready;
    let tun_need_elev = cfg.tun.enabled && !tun_admin_ready;
    let proxy_active = is_proxy_takeover_active(rt.running, &cfg, tun_admin_ready);
    let has_enabled_relays = !relays.is_empty();
    let preaccel_active = !preaccel_verify_degraded
        && !preaccel_verify_probing
        && ((!is_direct_mode && proxy_active && cfg.preaccel.enabled && has_enabled_relays)
            || global_status.is_windivert_active);
    let active_node_latency_ms =
        state.resolve_node_latency_ms(&active_node_id, active_snap.as_ref());
    let node_health_hints = state.snapshot_node_health_hints();
    let probing_active = state.probe_running.load(Ordering::SeqCst);
    let switching_active = state.is_switching_active();

    let active_relay_name = global_status
        .active_relays
        .first()
        .cloned()
        .or_else(|| {
            cfg.preaccel
                .active_relay_id
                .as_deref()
                .and_then(|id| relays.iter().find(|r| r.id == id))
                .or_else(|| relays.first())
                .map(|r| r.name.clone())
        });

    let status_label = if rt.last_error.is_some() || active_group_circuit_open {
        "error".to_string()
    } else if portal_required
        || preaccel_verify_degraded
        || active_group_in_backoff
        || active_group_degraded_warn
    {
        "warn".to_string()
    } else if is_direct_mode {
        if !preaccel_verify_probing && global_status.is_windivert_active {
            "preaccel".to_string()
        } else {
            "idle".to_string()
        }
    } else if preaccel_active {
        "preaccel".to_string()
    } else if proxy_active {
        "ok".to_string()
    } else {
        "idle".to_string()
    };

    Ok(CoreRuntimeInfoDto {
        running: rt.running,
        status: status_label,
        core_name: "Mihomo Meta".to_string(),
        core_version: rt
            .version
            .clone()
            .unwrap_or_else(|| if rt.running { "running".to_string() } else { "stopped".to_string() }),
        proxy_mode: effective_proxy_mode,
        route_mode: effective_route_mode.as_str().to_string(),
        mixed_port: if rt.running { rt.mixed_port } else { cfg.mixed_port },
        controller_addr: if rt.running {
            format!("{}:{}", rt.controller_host, rt.controller_port)
        } else {
            cfg.controller_addr()
        },
        uptime_sec: if rt.running {
            rt.uptime_sec
        } else {
            state.started_at.elapsed().as_secs()
        },
        rule_count: if rt.running && rt.rule_count > 0 {
            rt.rule_count
        } else {
            cfg.rules_override.global_append_rules.len()
                + cfg.rules_override.global_prepend_rules.len()
        },
        active_group_id,
        active_group_name,
        active_node_id,
        active_node_name,
        active_node_region,
        active_node_latency_ms,
        active_node_up_mbps: active_snap.as_ref().and_then(|s| s.up_mbps),
        preaccel_active,
        preaccel_enabled: cfg.preaccel.enabled,
        global_preaccel_active: global_status.running,
        global_preaccel_mode: global_status.mode,
        global_preaccel_socks_port: global_status.socks_port,
        global_preaccel_connections: global_status.active_connections,
        global_windivert_active: global_status.is_windivert_active,
        preaccel_install_state: global_status.install_state,
        global_preaccel_verify_state: verify_state,
        global_preaccel_verify_ms: verify_ms,
        node_health_hints,
        probing_active,
        switching_active,
        active_group_circuit_open,
        active_group_state,
        preaccel_relay_name: active_relay_name,
        captive_portal_required: portal_required,
        system_proxy_enabled: cfg.system_proxy.enabled,
        tun_enabled: eff_tun,
        tun_configured: cfg.tun.enabled,
        tun_needs_elevation: tun_need_elev,
        tun_admin_ready,
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        os_label: format!("{} {}", caps.os, caps.arch),
        autostart_enabled: cfg.behavior.autostart,
        portable_mode: state.paths.is_portable,
        last_update_check: cfg.update.last_checked_at.clone(),
    })
}

pub fn emit_runtime_snapshot(app: &AppHandle, state: &AppState) {
    if let Ok(dto) = build_runtime_info_dto(state) {
        let _ = app.emit(EVENT_RUNTIME, dto);
    }
}

pub fn emit_config_updated(app: &AppHandle, cfg: &AppConfig) {
    let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(cfg));
}

pub fn refresh_tray(app: &AppHandle, state: &AppState) {
    let _ = tray::sync_tray_menu(app, &build_tray_menu_state(app, state));
    let _ = tray::sync_tray_visual(app, &build_tray_visual_state(state));
}

fn emit_preaccel_verify_override_snapshots(
    app: &AppHandle,
    state: &AppState,
    verify_state: &str,
    verify_ms: Option<u64>,
) {
    let override_val = Some((verify_state, verify_ms));
    if let Ok(dto) = build_runtime_info_dto_with_verify_override(state, override_val) {
        let _ = app.emit(EVENT_RUNTIME, dto);
    }
    let _ = tray::sync_tray_menu(
        app,
        &build_tray_menu_state_with_verify_override(app, state, override_val),
    );
    let _ = tray::sync_tray_visual(
        app,
        &build_tray_visual_state_with_verify_override(state, override_val),
    );
}

pub fn map_tray_click(action: &CoreTrayClickAction) -> TrayClickAction {
    match action {
        CoreTrayClickAction::ToggleMainWindow | CoreTrayClickAction::OpenMainWindow => {
            TrayClickAction::ToggleMain
        }
        CoreTrayClickAction::ToggleCapsule => TrayClickAction::ToggleCapsule,
        CoreTrayClickAction::ToggleSystemProxy => TrayClickAction::ToggleSystemProxy,
        CoreTrayClickAction::SwitchNextBest => TrayClickAction::SwitchNextBest,
        CoreTrayClickAction::None => TrayClickAction::ShowMenu,
    }
}

fn shortcut_bindings_from_config(cfg: &AppConfig) -> ShortcutBindings {
    if !cfg.behavior.hotkeys.enabled {
        return ShortcutBindings {
            switch_next_best: None,
            toggle_capsule: None,
            toggle_main_window: None,
            toggle_system_proxy: None,
            toggle_tun: None,
        };
    }
    ShortcutBindings {
        switch_next_best: cfg.behavior.hotkeys.switch_next_best.clone(),
        toggle_capsule: cfg.behavior.hotkeys.toggle_capsule.clone(),
        toggle_main_window: cfg.behavior.hotkeys.show_main_window.clone(),
        toggle_system_proxy: cfg.behavior.hotkeys.toggle_system_proxy.clone(),
        toggle_tun: cfg.behavior.hotkeys.toggle_tun.clone(),
    }
}

pub fn apply_configured_shortcuts(
    app: &AppHandle,
    state: &AppState,
    cfg: &AppConfig,
    force: bool,
) {
    let bindings = shortcut_bindings_from_config(cfg);
    if !force {
        if let Ok(guard) = state.last_hotkey_bindings.lock() {
            if guard.as_ref() == Some(&bindings) {
                return;
            }
        }
    }
    let _ = shortcuts::register_shortcuts(app, &bindings, |app_h, action| {
        let app_async = app_h.clone();
        match action {
            ShortcutAction::ToggleCapsule => lifecycle::toggle_capsule_window(app_h),
            ShortcutAction::ToggleMainWindow => {
                if lifecycle::window_mode_snapshot(app_h).main_open {
                    lifecycle::enter_windowless_mode(app_h);
                } else {
                    lifecycle::show_or_rebuild_main_window(app_h);
                }
            }
            ShortcutAction::ToggleSystemProxy => {
                tauri::async_runtime::spawn(async move {
                    if let Some(st) = app_async.try_state::<AppState>() {
                        let next = !st.snapshot_config().system_proxy.enabled;
                        let _ = apply_system_proxy_internal(&app_async, &st, next).await;
                    }
                });
            }
            ShortcutAction::ToggleTun => {
                tauri::async_runtime::spawn(async move {
                    if let Some(st) = app_async.try_state::<AppState>() {
                        let cfg = st.snapshot_config();
                        let next = !effective_tun_enabled(&st, &cfg);
                        if let Err(err) = set_tun_enabled_internal(&app_async, &st, next).await {
                            handle_tun_toggle_error(&app_async, &err);
                        }
                    }
                });
            }
            ShortcutAction::SwitchNextBestNode => {
                tauri::async_runtime::spawn(async move {
                    if let Some(st) = app_async.try_state::<AppState>() {
                        let cfg = st.snapshot_config();
                        let target_group = if cfg.route_mode == RouteTargetMode::Single {
                            String::new()
                        } else {
                            cfg.active_group_id.unwrap_or_else(|| "default".to_string())
                        };
                        let _ = switch_next_best_internal(&app_async, &st, target_group).await;
                    }
                });
            }
        }
    });
    if let Ok(mut guard) = state.last_hotkey_bindings.lock() {
        *guard = Some(bindings);
    }
}

/// Auto-create a default "默认路线" multi-group when nodes exist but no multi-group is configured yet.
/// Returns `true` when a new default group was created and persisted into config.
fn ensure_default_group_if_empty(state: &AppState) -> bool {
    let created_group_id = {
        let Ok(db) = state.storage.lock() else {
            return false;
        };
        let Ok(groups) = db.list_multi_groups() else {
            return false;
        };
        if !groups.is_empty() {
            return false;
        }
        let Ok(nodes) = db.list_nodes() else {
            return false;
        };
        if nodes.is_empty() {
            return false;
        }
        let member_node_ids: Vec<String> = nodes
            .iter()
            .filter(|n| n.enabled)
            .map(|n| n.id.clone())
            .collect();
        let active_node_id = member_node_ids.first().cloned();
        let group = MultiGroup {
            id: format!("grp-{}", uuid::Uuid::new_v4().simple()),
            name: "默认路线".to_string(),
            mode: MultiGroupMode::StickyBest,
            hard_gates: Vec::new(),
            member_node_ids,
            active_node_id,
            ..MultiGroup::default()
        };
        if db.upsert_multi_group(&group).is_err() {
            return false;
        }
        group.id
    };

    let mut cfg = state.snapshot_config();
    cfg.active_group_id = Some(created_group_id);
    if config::save(&state.paths, &cfg).is_ok() {
        if let Ok(mut guard) = state.config.write() {
            *guard = cfg;
        }
    }
    true
}

pub fn sync_app_side_effects(app: &AppHandle, state: &AppState, cfg: &AppConfig) {
    if let Some(win_state) = app.try_state::<lifecycle::WindowLifecycleState>() {
        win_state.set_destroy_on_close(cfg.behavior.minimize_to_tray_on_close);
    }
    tray::set_tray_left_click_action(app, map_tray_click(&cfg.behavior.tray_click_action));
    apply_configured_shortcuts(app, state, cfg, false);
    let _ = tray::sync_tray_menu(app, &build_tray_menu_state(app, state));
    let _ = tray::sync_tray_visual(app, &build_tray_visual_state(state));
    emit_runtime_snapshot(app, state);
}

fn sync_autostart_if_changed(old: &AppConfig, cfg: &AppConfig) {
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

fn extract_logfmt_msg(line: &str) -> Option<String> {
    let idx = line.find("msg=")?;
    let rest = &line[idx + 4..];
    if let Some(quoted) = rest.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = quoted.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                if let Some(next) = chars.next() {
                    out.push(next);
                }
            } else if c == '"' {
                break;
            } else {
                out.push(c);
            }
        }
        let trimmed = out.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    } else {
        let trimmed = rest.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    None
}

fn strip_config_file_test_failed_prefix(msg: &str) -> String {
    let lower = msg.to_ascii_lowercase();
    if let Some(pos) = lower.rfind("test failed:") {
        let after = msg[pos + "test failed:".len()..].trim();
        if !after.is_empty() {
            return after.to_string();
        }
    }
    msg.trim().to_string()
}

fn extract_rule_snippet(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let start = lower.find("rules[")?;
    let after_rules = &text[start + "rules[".len()..];
    let close_idx = after_rules.find(']')?;
    let rest = after_rules[close_idx + 1..].trim_start();
    if let Some(inner) = rest.strip_prefix('[') {
        if let Some(end) = inner.find(']') {
            let snippet = inner[..end].trim();
            if !snippet.is_empty() {
                return Some(snippet.to_string());
            }
        }
    }
    None
}

/// Condense verbose Mihomo `-t` / core stderr output into a concise, readable Chinese message
/// suitable for UI toasts (extracting `level=error msg="..."` and stripping `time=... level=info`
/// log prefixes as well as temporary `.tmp` absolute file paths).
fn format_mihomo_error_for_user(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return "核心配置校验未通过，请检查节点与分流规则配置".to_string();
    }

    let mut extracted_msg: Option<String> = None;
    for line in trimmed.lines() {
        let l = line.trim();
        let lower = l.to_ascii_lowercase();
        if lower.contains("level=error") || lower.contains("level=fatal") {
            if let Some(msg) = extract_logfmt_msg(l) {
                extracted_msg = Some(msg);
            }
        }
    }

    let core_detail = if let Some(msg) = extracted_msg {
        msg
    } else if let Some(idx) = trimmed.to_ascii_lowercase().rfind("test failed:") {
        trimmed[idx + "test failed:".len()..].trim().to_string()
    } else if let Some((_, after)) = trimmed.split_once("Mihomo `-t` pre-flight check failed:") {
        let after_trimmed = after.trim();
        after_trimmed
            .lines()
            .rev()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.to_ascii_lowercase().contains("level=info"))
            .map(|l| extract_logfmt_msg(l).unwrap_or_else(|| l.to_string()))
            .unwrap_or_else(|| after_trimmed.to_string())
    } else if trimmed.to_ascii_lowercase().contains("`mihomo -t` verification timed out") {
        return "代理核心配置校验超时，请稍后重试".to_string();
    } else {
        return trimmed.to_string();
    };

    let cleaned = strip_config_file_test_failed_prefix(&core_detail);
    let lower = cleaned.to_ascii_lowercase();

    if lower.contains("rules[") && lower.contains("format invalid") {
        if let Some(rule_snippet) = extract_rule_snippet(&cleaned) {
            return format!("分流规则格式无效（{rule_snippet}），请检查多选组或自定义规则后重试");
        }
        return "分流规则格式无效，请检查多选组或自定义规则后重试".to_string();
    }
    if lower.contains("rules[") && lower.contains("not found") {
        return format!("分流规则引用了不存在的策略组：{cleaned}");
    }
    if lower.contains("proxy") && lower.contains("not found") {
        return format!("配置引用了不存在的代理节点或分组：{cleaned}");
    }
    if lower.contains("address already in use") || lower.contains("bind:") {
        return format!("本地代理端口已被占用，请在设置中更换端口或开启端口自动避让（{cleaned}）");
    }
    if lower.contains("timed out") {
        return "代理核心配置校验超时，请稍后重试".to_string();
    }
    if cleaned.is_empty() {
        return "代理核心配置校验未通过，请检查节点与分流规则".to_string();
    }
    format!("代理核心配置校验未通过：{cleaned}")
}

/// Return whether SQLite currently contains at least one enabled proxy node.
pub fn has_enabled_nodes(state: &AppState) -> Result<bool, String> {
    let db = state
        .storage
        .lock()
        .map_err(|e| format!("读取本地节点库失败：{e}"))?;
    Ok(db
        .list_nodes()
        .map_err(|e| format!("读取节点列表失败：{e}"))?
        .iter()
        .any(|n| n.enabled))
}

/// Handle errors returned when toggling TUN from non-IPC triggers (tray menu / global shortcut).
/// If administrator privileges are required (`NEEDS_ADMIN:...`), raise/rebuild the main window
/// and emit `catcloud://tun-needs-admin` so the elevation guidance modal opens automatically.
pub fn handle_tun_toggle_error(app: &AppHandle, err: &str) {
    const ADMIN_PREFIX: &str = "NEEDS_ADMIN:";
    if let Some(idx) = err.find(ADMIN_PREFIX) {
        let reason = err[idx + ADMIN_PREFIX.len()..].trim().to_string();
        let was_main_open = lifecycle::window_mode_snapshot(app).main_open;
        lifecycle::show_or_rebuild_main_window(app);
        let _ = app.emit(EVENT_TUN_NEEDS_ADMIN, reason.clone());
        if !was_main_open {
            // Main window is rebuilding asynchronously from windowless mode;
            // wait for it to mount and replay once so the frontend listener receives the prompt.
            let app_replay = app.clone();
            tauri::async_runtime::spawn(async move {
                let deadline = Instant::now() + Duration::from_secs(3);
                while !lifecycle::window_mode_snapshot(&app_replay).main_open
                    && Instant::now() < deadline
                {
                    tokio::time::sleep(Duration::from_millis(60)).await;
                }
                if lifecycle::window_mode_snapshot(&app_replay).main_open {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    let _ = app_replay.emit(EVENT_TUN_NEEDS_ADMIN, reason);
                }
            });
        }
    } else {
        tracing::warn!("切换虚拟网卡失败：{err}");
    }
}

fn is_loopback_host(host: &str) -> bool {
    let trimmed = host.trim();
    trimmed == "127.0.0.1"
        || trimmed.eq_ignore_ascii_case("localhost")
        || trimmed == "::1"
        || trimmed == "[::1]"
}

/// Determine whether the OS system proxy registry currently points to CatCloud's own loopback
/// listener (or CatCloud's own local PAC URL), preventing accidental removal of corporate PACs
/// or third-party capture proxies (Fiddler/Charles) when CatCloud's system proxy was never enabled.
fn is_system_proxy_owned_by_us(
    cfg: &AppConfig,
    rt: &CoreRuntimeStatus,
    observed: &SystemProxySpec,
) -> bool {
    if !observed.enabled {
        return false;
    }
    if let Some(pac) = observed
        .pac_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let expected_pac = format!("http://127.0.0.1:{}/proxy.pac", cfg.system_proxy.pac.port);
        return pac.eq_ignore_ascii_case(&expected_pac);
    }
    if !is_loopback_host(&observed.host) {
        return false;
    }
    observed.port == cfg.mixed_port || (rt.mixed_port > 0 && observed.port == rt.mixed_port)
}

fn disable_system_proxy_os_only(cfg: &AppConfig) -> Result<(), String> {
    let mut disabled = cfg.system_proxy.clone();
    disabled.enabled = false;
    disabled.pac.enabled = false;
    let spec = disabled.to_platform_spec("127.0.0.1", cfg.mixed_port);
    default_platform()
        .apply_system_proxy(&spec)
        .map_err(|e| format!("清除系统代理失败：{e}"))
}

/// Clear OS system proxy under `state.system_proxy_lock` ONLY when CatCloud owns it
/// (`previously_enabled || cfg.system_proxy.enabled`, or current OS `ProxyServer` points to
/// `127.0.0.1:<runtime_or_config_port>` / our local PAC).
fn clear_system_proxy_if_owned_with_hint(
    state: &AppState,
    previously_enabled: bool,
) -> Result<bool, String> {
    let _proxy_guard = state
        .system_proxy_lock
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let cfg = state.snapshot_config();
    let rt = state.snapshot_runtime();
    let owned = previously_enabled || cfg.system_proxy.enabled || {
        match default_platform().read_system_proxy() {
            Ok(observed) => is_system_proxy_owned_by_us(&cfg, &rt, &observed),
            Err(err) => {
                tracing::debug!("读取当前系统代理状态失败，跳过猜测性清理：{err}");
                false
            }
        }
    };
    if !owned {
        return Ok(false);
    }
    disable_system_proxy_os_only(&cfg)?;
    Ok(true)
}

/// Clear OS system proxy under `state.system_proxy_lock` if owned by CatCloud.
pub fn clear_system_proxy_if_owned(state: &AppState) -> Result<bool, String> {
    clear_system_proxy_if_owned_with_hint(state, false)
}

/// Apply OS system proxy (`ProxyEnable=1`) under `state.system_proxy_lock`, re-checking
/// `!shutting_down && state.snapshot_config().system_proxy.enabled` inside the lock so a racing
/// shutdown or `stop_core` can never be overwritten back to `ProxyEnable=1`.
fn apply_system_proxy_if_still_enabled(state: &AppState, port: u16) -> Result<bool, String> {
    let _proxy_guard = state
        .system_proxy_lock
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if state.shutting_down.load(Ordering::SeqCst) {
        return Ok(false);
    }
    let latest_cfg = state.snapshot_config();
    if !latest_cfg.system_proxy.enabled {
        return Ok(false);
    }
    let spec = latest_cfg.system_proxy.to_platform_spec("127.0.0.1", port);
    default_platform()
        .apply_system_proxy(&spec)
        .map_err(|e| format!("应用系统代理设置失败：{e}"))?;
    Ok(true)
}

/// Best-effort bounded stop of the `WinDivert` kernel driver service via Windows SCM when
/// `emergency_cleanup_on_exit` runs during a 4s dataplane self-test window and `stop()` times out.
///
/// Intentionally NEVER calls `DeleteService` to prevent Win32 `1072` races on rapid relaunch.
#[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
fn emergency_stop_windivert_service_fallback() -> bool {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QueryServiceStatus,
        SC_HANDLE, SC_MANAGER_CONNECT, SERVICE_CONTROL_STOP, SERVICE_QUERY_STATUS, SERVICE_STATUS,
        SERVICE_STOP, SERVICE_STOPPED,
    };

    struct ScopedScHandle(SC_HANDLE);
    impl Drop for ScopedScHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: Valid SCM or Service handle owned exclusively by this guard.
                unsafe {
                    let _ = CloseServiceHandle(self.0);
                }
                self.0 = std::ptr::null_mut();
            }
        }
    }

    // SAFETY: Read-only connect to local SCM; deterministically closed by `ScopedScHandle`.
    let scm_raw =
        unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if scm_raw.is_null() {
        return false;
    }
    let scm = ScopedScHandle(scm_raw);

    let service_wide: Vec<u16> = "WinDivert"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `scm.0` is valid and `service_wide` is NUL-terminated UTF-16.
    let svc_raw = unsafe {
        OpenServiceW(
            scm.0,
            service_wide.as_ptr(),
            SERVICE_STOP | SERVICE_QUERY_STATUS,
        )
    };
    if svc_raw.is_null() {
        return false;
    }
    let svc = ScopedScHandle(svc_raw);

    let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
    if unsafe { QueryServiceStatus(svc.0, &mut status) } != 0
        && status.dwCurrentState == SERVICE_STOPPED
    {
        return true;
    }

    const ERROR_SERVICE_CANNOT_ACCEPT_CTRL: u32 = 1061;
    const ERROR_SERVICE_NOT_ACTIVE: u32 = 1062;

    let ctrl_ok = unsafe { ControlService(svc.0, SERVICE_CONTROL_STOP, &mut status) };
    if ctrl_ok == 0 {
        let err = unsafe { GetLastError() };
        if err == ERROR_SERVICE_NOT_ACTIVE {
            return true;
        }
        if err != ERROR_SERVICE_CANNOT_ACCEPT_CTRL {
            return false;
        }
    } else if status.dwCurrentState == SERVICE_STOPPED {
        return true;
    }

    let deadline = Instant::now() + Duration::from_millis(500);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
        let mut cur: SERVICE_STATUS = unsafe { std::mem::zeroed() };
        if unsafe { QueryServiceStatus(svc.0, &mut cur) } == 0 {
            return false;
        }
        if cur.dwCurrentState == SERVICE_STOPPED {
            return true;
        }
    }
    false
}

/// Deterministic exit safety hook invoked before `JobGuard::terminate_all()` on `RunEvent::Exit`.
///
/// 1. Stops background `ProxyGuard` ticks immediately via `shutting_down`.
/// 2. Gracefully stops domestic global acceleration (2.0s bounded timeout) whenever enabled,
///    running, or mid-probing, with a Windows SCM fallback stopping the `WinDivert` service if
///    exit occurs during the 4s self-test window.
/// 3. Gracefully disables TUN (1.5s bounded timeout) whenever TUN or external overrides may have
///    activated Wintun & OS routes, so they are released cleanly.
/// 4. Clears Windows WinINet system proxy under `system_proxy_lock` (only if owned by CatCloud)
///    WITHOUT mutating `config.json` remembered preferences.
pub fn emergency_cleanup_on_exit(state: &AppState) {
    state.shutting_down.store(true, Ordering::SeqCst);
    state.stop_streams();

    let cfg = state.snapshot_config();
    let may_have_tun = effective_tun_enabled(state, &cfg)
        || cfg.rules_override.override_mode != OverrideMode::Disabled;
    let global_status = state.global_preaccel.status();
    let may_have_global_preaccel = cfg.preaccel.enabled
        || global_status.running
        || global_status.verify_state == "probing";

    if may_have_tun || may_have_global_preaccel {
        let adapter = Arc::clone(&state.adapter);
        let global_preaccel = Arc::clone(&state.global_preaccel);
        let global_stop_needs_fallback = Arc::new(AtomicBool::new(false));
        let fallback_flag = Arc::clone(&global_stop_needs_fallback);
        let run_teardown = move || {
            tauri::async_runtime::block_on(async move {
                if may_have_global_preaccel {
                    match tokio::time::timeout(Duration::from_millis(2000), global_preaccel.stop())
                        .await
                    {
                        Ok(Ok(_)) => {}
                        Ok(Err(err)) => {
                            fallback_flag.store(true, Ordering::SeqCst);
                            tracing::warn!(
                                "退出时停止国内提速失败，准备触发 WinDivert 兜底清理：{err}"
                            );
                        }
                        Err(_) => {
                            fallback_flag.store(true, Ordering::SeqCst);
                            tracing::warn!(
                                "退出时等待国内提速停止超时（2000ms，可能处于自检窗口），准备触发 WinDivert 兜底清理"
                            );
                        }
                    }
                }
                if may_have_tun {
                    let _ = tokio::time::timeout(Duration::from_millis(1500), async {
                        if adapter.has_live_controller().await {
                            let _ = adapter.disable_tun_gracefully().await;
                        }
                    })
                    .await;
                }
            });
        };
        let teardown_timed_out = if tokio::runtime::Handle::try_current().is_ok() {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                run_teardown();
                let _ = tx.send(());
            });
            rx.recv_timeout(Duration::from_millis(3800)).is_err()
        } else {
            run_teardown();
            false
        };

        let need_fallback =
            may_have_global_preaccel && (teardown_timed_out || global_stop_needs_fallback.load(Ordering::SeqCst));
        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        if need_fallback {
            let stopped = emergency_stop_windivert_service_fallback();
            if stopped {
                tracing::info!("退出兜底：已通过 Windows SCM 安全停止 WinDivert 内核服务");
            } else {
                tracing::warn!(
                    "退出兜底：尝试通过 Windows SCM 停止 WinDivert 内核服务未确认完成（可能未加载或无权限）"
                );
            }
        }
        #[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
        let _ = need_fallback;
    }

    if let Err(err) = clear_system_proxy_if_owned(state) {
        tracing::warn!("退出时清除系统代理失败：{err}");
    }
    catcloud_core::core_adapter::remove_runtime_controller_meta(&state.paths.runtime_dir);
}

fn refresh_node_proxy_name_map(state: &AppState) {
    let cfg = state.snapshot_config();
    let rt = state.snapshot_runtime();
    let Ok((nodes, groups, relays)) = state.storage.lock().map(|db| {
        (
            db.list_nodes().unwrap_or_default(),
            db.list_multi_groups().unwrap_or_default(),
            db.list_preaccel_relays(false).unwrap_or_default(),
        )
    }) else {
        return;
    };
    let (extra_rules, extra_filters) = state
        .campus_tracker
        .lock()
        .map(|t| {
            (
                t.active_direct_rules().to_vec(),
                t.active_fake_ip_filters().to_vec(),
            )
        })
        .unwrap_or_default();
    let allocated = AllocatedPorts {
        bind_host: if cfg.allow_lan {
            cfg.bind_address.clone()
        } else {
            "127.0.0.1".to_string()
        },
        mixed_port: if rt.running { rt.mixed_port } else { cfg.mixed_port },
        controller_port: if rt.running {
            rt.controller_port
        } else {
            cfg.controller_port
        },
        dns_port: if rt.running {
            rt.dns_listen_port
        } else {
            cfg.dns_listen_port
        },
        shifted: Vec::new(),
    };
    let empty_filter = HashMap::new();
    let input = CompileInput {
        config: &cfg,
        nodes: &nodes,
        groups: &groups,
        relays: &relays,
        controller_secret: "map-sync",
        allocated_ports: &allocated,
        extra_prepend_rules: &extra_rules,
        extra_fake_ip_filters: &extra_filters,
        group_filtered_members: &empty_filter,
    };
    if let Ok(compiled) =
        compile_mihomo_config_with_runtime_dir(&input, Some(&state.paths.runtime_dir))
    {
        state.set_node_proxy_name_map(compiled.node_id_to_proxy_name);
        state.set_compiled_group_ids(Some(
            compiled
                .group_mappings
                .iter()
                .map(|g| g.group_id.clone())
                .collect(),
        ));
    }
}

/// Start the managed Mihomo core subprocess (caller must hold `state.core_lifecycle_lock`).
async fn start_core_locked(app: &AppHandle, state: &AppState) -> Result<CoreRuntimeInfoDto, String> {
    if state.shutting_down.load(Ordering::SeqCst) {
        return Err("应用正在退出，已取消启动代理核心".to_string());
    }

    let cfg = state.snapshot_config();
    let extra_candidates = state.extra_binary_candidates();
    let resolution = resolve_mihomo_binary(&cfg, &state.paths, &extra_candidates, false)
        .map_err(|e| {
            let msg = format!("查找代理核心失败：{e}");
            state.log_app_event("error", "核心", &msg);
            msg
        })?;
    let binary_path = resolution.path.ok_or_else(|| {
        let msg = "未找到 Mihomo 代理核心文件，请将内核放入 bin 目录或在设置中指定内核路径".to_string();
        state.log_app_event("error", "核心", &msg);
        msg
    })?;

    let (nodes, groups, relays) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let nodes = db.list_nodes().map_err(|e| e.to_string())?;
        let mut groups = db.list_multi_groups().map_err(|e| e.to_string())?;
        let relays = db.list_preaccel_relays(false).map_err(|e| e.to_string())?;

        // Before compiling runtime YAML, sanitize ghost active_node_id on all groups and
        // reconcile best healthy candidates for the active group & independent-routing groups.
        if !nodes.is_empty() && !groups.is_empty() {
            let node_ids: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
            let default_snaps = db
                .get_probe_snapshots_batch(&node_ids, None)
                .unwrap_or_default();
            let primary_gid = cfg
                .active_group_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .and_then(|aid| groups.iter().find(|g| g.id == aid).map(|g| g.id.clone()))
                .or_else(|| groups.first().map(|g| g.id.clone()));

            let health_pool = state.snapshot_node_health_pool();
            let now = Instant::now();
            for group in &mut groups {
                let prev_active = group.active_node_id.clone();
                let is_target =
                    primary_gid.as_deref() == Some(group.id.as_str()) || group.independent_routing;
                if let Some(ref probe_id) = group.primary_probe_id {
                    let group_snaps = db
                        .get_probe_snapshots_batch(&node_ids, Some(probe_id.as_str()))
                        .unwrap_or_else(|_| default_snaps.clone());
                    if is_target {
                        let _ = reconcile_group_best_node_in_memory_with_runtime(
                            group,
                            &nodes,
                            &group_snaps,
                            Some(&health_pool),
                            now,
                        );
                    } else {
                        let _ = sanitize_group_active_node_with_runtime(
                            group,
                            &nodes,
                            &group_snaps,
                            Some(&health_pool),
                            now,
                        );
                    }
                } else if is_target {
                    let _ = reconcile_group_best_node_in_memory_with_runtime(
                        group,
                        &nodes,
                        &default_snaps,
                        Some(&health_pool),
                        now,
                    );
                } else {
                    let _ = sanitize_group_active_node_with_runtime(
                        group,
                        &nodes,
                        &default_snaps,
                        Some(&health_pool),
                        now,
                    );
                }
                if group.active_node_id != prev_active {
                    let _ = db.upsert_multi_group(group);
                }
            }
        }
        (nodes, groups, relays)
    };
    let (extra_rules, extra_filters) = {
        let tracker = state.campus_tracker.lock().map_err(|e| e.to_string())?;
        (
            tracker.active_direct_rules().to_vec(),
            tracker.active_fake_ip_filters().to_vec(),
        )
    };

    let bind_host = if cfg.allow_lan {
        cfg.bind_address.as_str()
    } else {
        "127.0.0.1"
    };
    let controller_host = if cfg.allow_lan {
        cfg.controller_host.clone()
    } else {
        "127.0.0.1".to_string()
    };
    let allocated = allocate_safe_ports(
        bind_host,
        cfg.mixed_port,
        cfg.controller_port,
        cfg.dns_listen_port,
        cfg.port_guard_auto_shift,
    )
    .map_err(|e| format!("分配本地代理端口失败：{e}"))?;

    let secret = cfg
        .controller_secret
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(generate_controller_secret);

    let tun_ready = is_tun_privilege_ready(state);
    let eff_cfg = effective_config_for_runtime(state, &cfg);
    let eff_tun = eff_cfg.tun.enabled;
    let tun_need_elev = cfg.tun.enabled && !tun_ready;
    let empty_filter = HashMap::new();
    let input = CompileInput {
        config: &eff_cfg,
        nodes: &nodes,
        groups: &groups,
        relays: &relays,
        controller_secret: &secret,
        allocated_ports: &allocated,
        extra_prepend_rules: &extra_rules,
        extra_fake_ip_filters: &extra_filters,
        group_filtered_members: &empty_filter,
    };
    let compiled = compile_mihomo_config_with_runtime_dir(&input, Some(&state.paths.runtime_dir))
        .map_err(|e| {
            let msg = format_mihomo_error_for_user(&format!("生成代理配置失败：{e}"));
            state.log_app_event("error", "核心", &msg);
            msg
        })?;
    if !compiled.validation.ok {
        let summary = compiled
            .validation
            .issues
            .iter()
            .map(|i| i.message.as_str())
            .collect::<Vec<_>>()
            .join("；");
        let msg = format!("代理配置静态预检未通过：{summary}");
        state.log_app_event("error", "核心", &msg);
        return Err(msg);
    }

    let runtime_yaml = state.hot_reload.runtime_yaml_path();
    if let Some(parent) = runtime_yaml.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("创建运行时配置目录失败：{e}"))?;
    }
    let tmp_yaml = state.paths.runtime_dir.join(format!(
        "runtime.{}.yaml.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::write(&tmp_yaml, compiled.yaml.as_bytes())
        .map_err(|e| format!("写入临时核心配置失败：{e}"))?;
    verify_config_with_binary(
        &binary_path,
        &state.paths.runtime_dir,
        &tmp_yaml,
        Duration::from_secs(8),
    )
    .await
    .map_err(|e| {
        let _ = std::fs::remove_file(&tmp_yaml);
        let msg = format_mihomo_error_for_user(&e.to_string());
        state.log_app_event("error", "核心", &format!("内核配置预检失败：{msg}"));
        msg
    })?;
    AppPaths::atomic_write(&runtime_yaml, compiled.yaml.as_bytes()).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_yaml);
        format!("写入运行时核心配置失败：{e}")
    })?;
    let _ = std::fs::remove_file(&tmp_yaml);

    let start_req = CoreStartRequest {
        binary_path,
        working_dir: state.paths.runtime_dir.clone(),
        config_path: runtime_yaml,
        config: eff_cfg.clone(),
        allocated_ports: allocated.clone(),
        controller_host,
        controller_secret: secret.clone(),
        node_count: compiled.stats.total_proxies,
        rule_count: compiled.stats.total_rules,
        active_selections: compiled.active_selections.clone(),
    };

    let status = state.adapter.start(start_req).await.map_err(|e| {
        let msg = format_mihomo_error_for_user(&format!("启动代理核心失败：{e}"));
        state.log_app_event("error", "核心", &msg);
        msg
    })?;

    let loaded_nodes_count = compiled.stats.total_proxies;
    let loaded_relays_count = compiled.stats.relay_proxies;
    let total_library_nodes = nodes.len();
    state.set_node_proxy_name_map(compiled.node_id_to_proxy_name);
    state.set_compiled_group_ids(Some(
        compiled
            .group_mappings
            .iter()
            .map(|g| g.group_id.clone())
            .collect(),
    ));
    state
        .hot_reload
        .seed_active_state(eff_cfg.clone(), compiled.sha256, allocated.clone(), secret.clone())
        .await;
    state.bump_core_session_generation();
    state.clear_group_backoffs();
    state.update_cached_runtime(status.clone());
    state.clear_app_error();
    let tun_start_label = if eff_tun {
        "开启"
    } else if tun_need_elev {
        "未生效（需管理员权限）"
    } else {
        "关闭"
    };
    state.log_app_event(
        "info",
        "核心",
        &format!(
            "代理核心已启动（模式 {}，混合端口 {}，已按需加载节点 {} 个（含中转 {} 个，节点库共 {} 个），规则 {} 条，虚拟网卡 {}，国内提速 {}）",
            cfg.proxy_mode.as_str(),
            status.mixed_port,
            loaded_nodes_count,
            loaded_relays_count,
            total_library_nodes,
            status.rule_count,
            tun_start_label,
            if cfg.preaccel.enabled { "开启" } else { "关闭" }
        ),
    );
    if tun_need_elev {
        state.log_app_event(
            "warning",
            "虚拟网卡",
            "配置已勾选虚拟网卡（TUN），但当前为普通用户权限，虚拟网卡未生效（仅系统代理生效，部分桌面应用/终端可能无法走代理）；请点击一键以管理员身份重启",
        );
    }

    // Attach bounded background telemetry streams (`/traffic`, `/memory`, `/logs`).
    state.attach_streams(
        &status.controller_host,
        status.controller_port,
        &secret,
        cfg.log_level.clone(),
    );

    // Re-sync OS system proxy to the actual bound mixed_port under `system_proxy_lock`.
    if let Err(err) = apply_system_proxy_if_still_enabled(state, status.mixed_port) {
        tracing::warn!("核心启动后同步系统代理端口失败：{err}");
    }

    // Coordinate with standalone global pre-acceleration using the SAME launch-time effective TUN
    // state so unprivileged startup never falsely pauses the standalone 443 engine.
    let tun_active = status.running && eff_tun;
    if tun_active && state.global_preaccel.status().running {
        let _ = state.global_preaccel.stop().await;
        state.log_app_event(
            "info",
            "国内提速",
            "虚拟网卡（TUN）已启动接管全机流量，已暂挂独立底层 443 隧道以避免重复占用内存，改由主核心统一提供国内提速",
        );
    } else {
        let main_pid = if status.running {
            status.pid.filter(|&p| p > 0)
        } else {
            None
        };
        state.global_preaccel.sync_main_core_pid(main_pid);
        if !state.shutting_down.load(Ordering::SeqCst)
            && cfg.preaccel.enabled
            && !tun_active
            && load_enabled_preaccel_relays(state).is_ok_and(|relays| !relays.is_empty())
        {
            if !state.global_preaccel.status().running {
                if let Err(err) = start_global_preaccel_engine(state, &cfg).await {
                    tracing::debug!(
                        "start_core_locked standalone global preaccel sync skipped: {err}"
                    );
                }
            }
            maybe_spawn_auto_windivert_download(app, state, &cfg);
        }
    }

    sync_app_side_effects(app, state, &cfg);
    build_runtime_info_dto(state)
}

/// Start the managed Mihomo core subprocess (if not running) and attach background telemetry streams.
pub async fn start_core_internal(
    app: &AppHandle,
    state: &AppState,
) -> Result<CoreRuntimeInfoDto, String> {
    let _lifecycle_guard = state.core_lifecycle_lock.lock().await;
    start_core_locked(app, state).await
}

/// Stop managed core temporarily for a restart WITHOUT clearing persisted system_proxy/tun toggles.
/// Caller must hold `state.core_lifecycle_lock`.
async fn stop_core_for_restart_locked(state: &AppState) -> Result<(), String> {
    let cfg = state.snapshot_config();
    let may_have_tun = effective_tun_enabled(state, &cfg)
        || cfg.rules_override.override_mode != OverrideMode::Disabled;
    if may_have_tun && state.adapter.has_live_controller().await {
        let _ = state.adapter.disable_tun_gracefully().await;
    }
    state.stop_streams();
    state
        .adapter
        .stop()
        .await
        .map_err(|e| format!("停止旧代理核心失败：{e}"))?;
    state.global_preaccel.sync_main_core_pid(None);
    state.clear_node_health_pool();
    state.clear_group_backoffs();
    state.bump_core_session_generation();
    state.telemetry.clear_traffic();
    state.set_node_proxy_name_map(HashMap::new());
    state.set_compiled_group_ids(None);
    let status = state.adapter.status().await;
    state.update_cached_runtime(status);
    if let Ok(mut m) = state.cached_metrics.write() {
        *m = CachedRealtimeMetrics::default();
    }
    Ok(())
}

/// Stop managed core cleanly (caller must hold `state.core_lifecycle_lock`):
/// 1. Flip in-memory `system_proxy.enabled` / `tun.enabled` to false immediately so ProxyGuard
///    cannot re-enable system proxy concurrently.
/// 2. Clear OS system proxy under `system_proxy_lock` (only when owned by CatCloud).
/// 3. Persist updated `config.json`.
/// 4. Gracefully disable TUN and stop the core subprocess.
async fn stop_core_locked(
    app: &AppHandle,
    state: &AppState,
    clear_tun_intent: bool,
) -> Result<CoreRuntimeInfoDto, String> {
    let old_cfg = state.snapshot_config();
    let was_sys_proxy_enabled = old_cfg.system_proxy.enabled;
    let may_have_tun = effective_tun_enabled(state, &old_cfg)
        || old_cfg.rules_override.override_mode != OverrideMode::Disabled;
    let mut cfg = old_cfg;
    let flags_changed = cfg.system_proxy.enabled || (clear_tun_intent && cfg.tun.enabled);

    if flags_changed {
        cfg.system_proxy.enabled = false;
        if clear_tun_intent {
            cfg.tun.enabled = false;
        }
        if let Ok(mut guard) = state.config.write() {
            *guard = cfg.clone();
        }
    }

    let mut clear_proxy_err: Option<String> = None;
    if let Err(first_err) = clear_system_proxy_if_owned_with_hint(state, was_sys_proxy_enabled) {
        tracing::warn!("停止核心前首次清除系统代理失败，将在 150ms 后重试：{first_err}");
        tokio::time::sleep(Duration::from_millis(150)).await;
        if let Err(retry_err) =
            clear_system_proxy_if_owned_with_hint(state, was_sys_proxy_enabled)
        {
            state.log_app_event(
                "error",
                "系统代理",
                &format!(
                    "停止核心前清除操作系统代理失败（已重试 1 次），请检查系统代理设置：{retry_err}"
                ),
            );
            clear_proxy_err = Some(retry_err);
        }
    }

    let save_err = if flags_changed {
        config::save(&state.paths, &cfg).err()
    } else {
        None
    };

    if may_have_tun && state.adapter.has_live_controller().await {
        let _ = state.adapter.disable_tun_gracefully().await;
    }

    state.stop_streams();
    state.adapter.stop().await.map_err(|e| {
        let msg = format!("停止代理核心失败：{e}");
        state.log_app_event("error", "核心", &msg);
        msg
    })?;
    state.global_preaccel.sync_main_core_pid(None);
    state.clear_node_health_pool();
    state.clear_group_backoffs();
    state.bump_core_session_generation();
    state.telemetry.clear_traffic();
    state.set_node_proxy_name_map(HashMap::new());
    state.set_compiled_group_ids(None);
    let mut status = state.adapter.status().await;
    if let Some(ref proxy_err) = clear_proxy_err {
        if !state.shutting_down.load(Ordering::SeqCst) {
            status.last_error = Some(format!("停止核心后清除系统代理失败：{proxy_err}"));
        }
    }
    state.update_cached_runtime(status);
    if let Ok(mut m) = state.cached_metrics.write() {
        *m = CachedRealtimeMetrics::default();
    }
    let _ = app.emit(
        EVENT_TRAFFIC,
        TrafficEventPayload {
            up_bps: 0,
            down_bps: 0,
            up_total_bytes: 0,
            down_total_bytes: 0,
            active_connections: 0,
            tunnel_connections: 0,
            core_memory_mb: 0.0,
            timestamp_ms: Utc::now().timestamp_millis(),
        },
    );
    if let Some(ref proxy_err) = clear_proxy_err {
        state.log_app_event(
            "warning",
            "核心",
            &format!("代理核心已停止，但自动清除系统代理失败，请检查系统代理设置：{proxy_err}"),
        );
    } else {
        state.log_app_event("info", "核心", "代理核心已停止，系统代理与虚拟网卡状态已复位");
    }

    // If the unified domestic pre-acceleration switch remains enabled while stopping CatCloud's
    // main proxy core, seamlessly keep or resume the lightweight standalone 443 tunnel.
    if !state.shutting_down.load(Ordering::SeqCst)
        && cfg.preaccel.enabled
        && load_enabled_preaccel_relays(state).is_ok_and(|relays| !relays.is_empty())
    {
        if !state.global_preaccel.status().running {
            match start_global_preaccel_engine(state, &cfg).await {
                Ok(global_st) => {
                    state.log_app_event(
                        "info",
                        "国内提速",
                        &format!(
                            "主代理核心已停止，已自动保持独立底层国内提速接棒（模式：{}）",
                            global_st.mode
                        ),
                    );
                }
                Err(err) => {
                    state.log_app_event(
                        "warning",
                        "国内提速",
                        &format!("主核心停止后自动切回独立底层国内提速失败：{err}"),
                    );
                }
            }
        }
        maybe_spawn_auto_windivert_download(app, state, &cfg);
    }

    sync_app_side_effects(app, state, &cfg);
    let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&cfg));
    if let Some(err) = save_err {
        return Err(format!("保存配置失败：{err}"));
    }
    build_runtime_info_dto(state)
}

/// Stop managed core cleanly, gracefully tearing down TUN and OS system proxy to prevent
/// blackholing host internet access.
pub async fn stop_core_internal(
    app: &AppHandle,
    state: &AppState,
) -> Result<CoreRuntimeInfoDto, String> {
    let _lifecycle_guard = state.core_lifecycle_lock.lock().await;
    stop_core_locked(app, state, true).await
}

/// Stop managed core when disabling system proxy under unprivileged mode while preserving
/// any persisted `tun.enabled` user intent on disk.
async fn stop_core_preserving_tun_intent_internal(
    app: &AppHandle,
    state: &AppState,
) -> Result<CoreRuntimeInfoDto, String> {
    let _lifecycle_guard = state.core_lifecycle_lock.lock().await;
    stop_core_locked(app, state, false).await
}

/// Atomically disable OS system proxy and TUN virtual NIC, persist both flags as `false`, and
/// terminate the main `mihomo` core with zero port/memory/connection residue (while keeping the
/// lightweight standalone 443 pre-acceleration tunnel active if the unified switch is enabled).
pub async fn disable_all_proxy_and_stop_core_internal(
    app: &AppHandle,
    state: &AppState,
) -> Result<CoreRuntimeInfoDto, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    let _lifecycle_guard = state.core_lifecycle_lock.lock().await;
    stop_core_locked(app, state, true).await
}

fn format_reload_level_zh(level: ReloadLevel) -> &'static str {
    match level {
        ReloadLevel::L1Rest => "毫秒级热切换（L1）",
        ReloadLevel::L2HotReload => "热重载（L2）",
        ReloadLevel::L3CoreRestart => "核心轻量重启",
    }
}

/// Reload core configuration from disk via `HotReloadCoordinator` when running.
/// Acquires `core_lifecycle_lock` and re-checks shutdown/live-controller state so an in-flight
/// reload can never resurrect the core after `stop_core`.
pub async fn trigger_reload_if_running(
    app: &AppHandle,
    state: &AppState,
    force: bool,
) -> Option<ReloadOutcome> {
    let _lifecycle_guard = state.core_lifecycle_lock.lock().await;
    if state.shutting_down.load(Ordering::SeqCst) || !state.adapter.has_live_controller().await {
        return None;
    }
    let prev_status = state.adapter.status().await;
    let prev_secret = state.adapter.controller_secret().await;
    let prev_log_level = state
        .last_log_level
        .read()
        .map(|g| g.clone())
        .unwrap_or_else(|_| state.snapshot_config().log_level);

    let (extra_rules, extra_filters) = state
        .campus_tracker
        .lock()
        .map(|t| {
            (
                t.active_direct_rules().to_vec(),
                t.active_fake_ip_filters().to_vec(),
            )
        })
        .unwrap_or_default();

    let outcome = state
        .hot_reload
        .apply_disk_reload(DiskReloadOptions {
            force,
            verify_with_binary: true,
            allow_l3_restart: true,
            allow_tun: is_tun_privilege_ready(state),
            extra_prepend_rules: extra_rules,
            extra_fake_ip_filters: extra_filters,
            ..DiskReloadOptions::default()
        })
        .await;

    let status = state.adapter.status().await;
    let new_secret = state.adapter.controller_secret().await;
    state.update_cached_runtime(status.clone());
    let cfg = state.snapshot_config();

    if outcome.applied {
        refresh_node_proxy_name_map(state);
        state.clear_app_error();
        state.log_app_event(
            "info",
            "热重载",
            &format!(
                "配置热重载成功（级别：{}，回放分组 {} 个）",
                format_reload_level_zh(outcome.level),
                outcome.replayed_groups
            ),
        );
    } else if outcome.rejected {
        let detail = outcome
            .error
            .as_deref()
            .map(format_mihomo_error_for_user)
            .unwrap_or_else(|| "未知原因".to_string());
        state.log_app_event(
            "error",
            "热重载",
            &format!("配置热重载被拒绝，已保留原运行配置：{detail}"),
        );
    }

    let endpoint_changed = prev_status.controller_host != status.controller_host
        || prev_status.controller_port != status.controller_port;
    let secret_changed = prev_secret != new_secret;
    let log_level_changed = prev_log_level != cfg.log_level;
    let is_l3_restart = outcome.level == ReloadLevel::L3CoreRestart;

    if outcome.applied
        && status.running
        && (is_l3_restart || endpoint_changed || secret_changed || log_level_changed)
    {
        if is_l3_restart {
            state.bump_core_session_generation();
        }
        state.attach_streams(
            &status.controller_host,
            status.controller_port,
            &new_secret,
            cfg.log_level.clone(),
        );
    }

    // Re-sync OS system proxy after L3 core restart under `system_proxy_lock`.
    if outcome.applied && is_l3_restart && status.running {
        if let Err(err) = apply_system_proxy_if_still_enabled(state, status.mixed_port) {
            tracing::warn!("核心轻量重启后同步系统代理端口失败：{err}");
        }
    }

    // Keep WinDivert main-core PID exclusion in sync across L3 restarts or unexpected exits.
    if (is_l3_restart || !status.running) && state.global_preaccel.status().running {
        let main_pid = if status.running {
            status.pid.filter(|&p| p > 0)
        } else {
            None
        };
        state.global_preaccel.sync_main_core_pid(main_pid);
    }

    sync_app_side_effects(app, state, &cfg);
    Some(outcome)
}

/// Coordinate standalone global pre-acceleration whenever TUN virtual NIC takeover transitions
/// between inactive and active:
/// - `false -> true`: suspend a running standalone 443 tunnel because TUN already routes host
///   traffic through the main core's in-core 443 pre-acceleration (avoiding two 443 tunnels).
/// - `true -> false`: seamlessly resume the standalone global pre-acceleration engine when the
///   unified `cfg.preaccel.enabled` switch is true and enabled relays exist.
/// When only OS system proxy is active (without TUN), standalone WinDivert excludes CatCloud's
/// full PID tree and stays active to accelerate third-party apps simultaneously.
async fn coordinate_global_preaccel_on_tun_transition(
    app: &AppHandle,
    state: &AppState,
    cfg: &AppConfig,
    was_tun_active: bool,
    now_tun_active: bool,
    trigger_label: &str,
) {
    if state.shutting_down.load(Ordering::SeqCst) {
        return;
    }
    if !was_tun_active && now_tun_active {
        if state.global_preaccel.status().running {
            let _ = state.global_preaccel.stop().await;
            state.log_app_event(
                "info",
                "国内提速",
                &format!(
                    "{trigger_label}已生效接管全机流量，已暂挂独立底层 443 隧道以避免双跑 443，改由主核心统一提供国内提速"
                ),
            );
        }
    } else if !now_tun_active && cfg.preaccel.enabled {
        let has_relays = load_enabled_preaccel_relays(state).is_ok_and(|relays| !relays.is_empty());
        if has_relays && !state.global_preaccel.status().running {
            match start_global_preaccel_engine(state, cfg).await {
                Ok(global_st) => {
                    if was_tun_active {
                        state.log_app_event(
                            "info",
                            "国内提速",
                            &format!(
                                "{trigger_label}已关闭，已自动恢复独立底层国内提速（模式：{}）",
                                global_st.mode
                            ),
                        );
                    }
                }
                Err(err) => {
                    state.log_app_event(
                        "warning",
                        "国内提速",
                        &format!("{trigger_label}切换后自动恢复独立底层国内提速失败：{err}"),
                    );
                }
            }
        }
        if has_relays {
            maybe_spawn_auto_windivert_download(app, state, cfg);
        }
    }
}

/// Apply system proxy state safely:
/// - Turning ON checks for enabled nodes, auto-starts the core when stopped, validates reload,
///   and rolls back `config.json` on any failure so Windows is never left with a dead proxy.
/// - Turning OFF updates in-memory config first, clears owned OS proxy under `system_proxy_lock`,
///   and stops the main core cleanly when TUN is also disabled (zero port/memory/connection residue).
pub async fn apply_system_proxy_internal(
    app: &AppHandle,
    state: &AppState,
    enabled: bool,
) -> Result<bool, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    let old_cfg = state.snapshot_config();
    let old_sys_proxy_enabled = old_cfg.system_proxy.enabled;
    let was_core_running =
        state.snapshot_runtime().running || state.adapter.has_live_controller().await;
    let was_tun_active = was_core_running && effective_tun_enabled(state, &old_cfg);

    if !enabled {
        let was_enabled = old_sys_proxy_enabled;
        let mut cfg = old_cfg.clone();
        cfg.system_proxy.enabled = false;
        if let Ok(mut guard) = state.config.write() {
            *guard = cfg.clone();
        }
        if let Err(err) = clear_system_proxy_if_owned_with_hint(state, was_enabled) {
            let mut rollback = state.snapshot_config();
            rollback.system_proxy.enabled = was_enabled;
            if let Ok(mut guard) = state.config.write() {
                *guard = rollback;
            }
            return Err(err);
        }
        config::save(&state.paths, &cfg).map_err(|e| format!("保存系统代理状态失败：{e}"))?;

        let latest_before_stop = state.snapshot_config();
        let now_core_running =
            state.snapshot_runtime().running || state.adapter.has_live_controller().await;
        let latest_eff_tun = effective_tun_enabled(state, &latest_before_stop);
        if !latest_before_stop.system_proxy.enabled && !latest_eff_tun && now_core_running {
            stop_core_preserving_tun_intent_internal(app, state).await?;
            state.log_app_event(
                "info",
                "系统代理",
                "已关闭系统代理并停止主代理核心（已释放监听端口与内存）",
            );
            return Ok(false);
        }

        let now_tun_active = now_core_running && latest_eff_tun;
        coordinate_global_preaccel_on_tun_transition(
            app,
            state,
            &latest_before_stop,
            was_tun_active,
            now_tun_active,
            "系统代理",
        )
        .await;
        state.log_app_event("info", "系统代理", "已关闭系统代理");
        let latest_cfg = state.snapshot_config();
        sync_app_side_effects(app, state, &latest_cfg);
        let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&latest_cfg));
        return Ok(false);
    }

    // 1. Refuse turning ON system proxy when no enabled proxy nodes exist.
    if !has_enabled_nodes(state)? {
        return Err("暂无可用节点，请先导入订阅".to_string());
    }

    // 2. Re-read disk config so external Agent edits take effect on toggle ON.
    let mut disk_cfg = config::load_or_init(&state.paths)
        .map_err(|e| format!("读取配置文件失败：{e}"))?;
    disk_cfg.preaccel.reconcile_unified_enabled();

    let mut started_core_here = false;
    let mut cfg = disk_cfg.clone();
    if !state.adapter.has_live_controller().await {
        // Boot core first WITHOUT dirty-writing `system_proxy.enabled = true` to disk.
        let mut boot_cfg = disk_cfg.clone();
        boot_cfg.system_proxy.enabled = false;
        if let Ok(mut guard) = state.config.write() {
            *guard = boot_cfg;
        }
        if let Err(err) = start_core_internal(app, state).await {
            let mut rollback = state.snapshot_config();
            rollback.system_proxy.enabled = old_sys_proxy_enabled;
            if let Ok(mut guard) = state.config.write() {
                *guard = rollback.clone();
            }
            sync_app_side_effects(app, state, &rollback);
            return Err(format!("开启系统代理前启动核心失败：{err}"));
        }
        started_core_here = true;
        cfg = state.snapshot_config();
        cfg.system_proxy.enabled = true;
        if let Err(e) = config::save(&state.paths, &cfg) {
            let mut rollback = state.snapshot_config();
            rollback.system_proxy.enabled = old_sys_proxy_enabled;
            if let Ok(mut guard) = state.config.write() {
                *guard = rollback.clone();
            }
            if started_core_here
                && !rollback.system_proxy.enabled
                && !effective_tun_enabled(state, &rollback)
            {
                if let Err(stop_err) = stop_core_preserving_tun_intent_internal(app, state).await {
                    tracing::warn!("保存系统代理配置失败回滚后停止新拉起核心异常：{stop_err}");
                }
            }
            let latest = state.snapshot_config();
            sync_app_side_effects(app, state, &latest);
            return Err(format!("保存系统代理配置失败：{e}"));
        }
        if let Ok(mut guard) = state.config.write() {
            *guard = cfg.clone();
        }
    } else {
        cfg.system_proxy.enabled = true;
        config::save(&state.paths, &cfg).map_err(|e| format!("保存系统代理配置失败：{e}"))?;
        if let Ok(mut guard) = state.config.write() {
            *guard = cfg.clone();
        }
        // Pass `force = false` so SHA-256 deduplication skips redundant Mihomo reloads when the
        // core is already running and only the OS system proxy toggle changed, while still picking
        // up any external disk/SQLite changes cleanly.
        if let Some(outcome) = trigger_reload_if_running(app, state, false).await {
            if outcome.rejected {
                let mut rollback = state.snapshot_config();
                rollback.system_proxy.enabled = old_sys_proxy_enabled;
                let _ = config::save(&state.paths, &rollback);
                if let Ok(mut guard) = state.config.write() {
                    *guard = rollback.clone();
                }
                sync_app_side_effects(app, state, &rollback);
                let raw_err = outcome
                    .error
                    .unwrap_or_else(|| "配置预检未通过，已保持原配置运行".to_string());
                return Err(format_mihomo_error_for_user(&raw_err));
            }
        }
    }

    // 3. Apply WinINet system proxy under `system_proxy_lock` using live mixed_port; rollback on failure.
    let effective_port = {
        let rt = state.snapshot_runtime();
        if rt.running { rt.mixed_port } else { cfg.mixed_port }
    };
    match apply_system_proxy_if_still_enabled(state, effective_port) {
        Ok(true) => {}
        Ok(false) => {
            // Concurrent stop_core or shutdown disabled system proxy while we were enabling.
            let latest = state.snapshot_config();
            if started_core_here
                && !latest.system_proxy.enabled
                && !effective_tun_enabled(state, &latest)
            {
                if let Err(stop_err) = stop_core_preserving_tun_intent_internal(app, state).await {
                    tracing::warn!("系统代理取消后停止新拉起核心异常：{stop_err}");
                }
            }
            let latest = state.snapshot_config();
            sync_app_side_effects(app, state, &latest);
            let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&latest));
            return Ok(false);
        }
        Err(err) => {
            let mut rollback = state.snapshot_config();
            rollback.system_proxy.enabled = old_sys_proxy_enabled;
            let _ = config::save(&state.paths, &rollback);
            if let Ok(mut guard) = state.config.write() {
                *guard = rollback.clone();
            }
            if started_core_here
                && !rollback.system_proxy.enabled
                && !effective_tun_enabled(state, &rollback)
            {
                // Lock order: already holding outer `config_transition_lock` -> inner `core_lifecycle_lock`.
                if let Err(stop_err) = stop_core_preserving_tun_intent_internal(app, state).await {
                    tracing::warn!("写入操作系统代理失败回滚后停止新拉起核心异常：{stop_err}");
                }
            }
            state.log_app_event(
                "error",
                "系统代理",
                &format!("写入操作系统代理失败，已回滚配置：{err}"),
            );
            let latest = state.snapshot_config();
            sync_app_side_effects(app, state, &latest);
            let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&latest));
            return Err(err);
        }
    }

    let latest_cfg = state.snapshot_config();
    let now_core_running =
        state.snapshot_runtime().running || state.adapter.has_live_controller().await;
    let now_tun_active = now_core_running && effective_tun_enabled(state, &latest_cfg);
    coordinate_global_preaccel_on_tun_transition(
        app,
        state,
        &latest_cfg,
        was_tun_active,
        now_tun_active,
        "系统代理",
    )
    .await;

    state.log_app_event(
        "info",
        "系统代理",
        &format!("已开启系统代理（127.0.0.1:{effective_port}）"),
    );
    let latest_cfg = state.snapshot_config();
    sync_app_side_effects(app, state, &latest_cfg);
    let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&latest_cfg));
    Ok(true)
}

/// Switch a multi-group (or active single node) to the next best healthy node without polluting SQLite.
pub async fn switch_next_best_internal(
    app: &AppHandle,
    state: &AppState,
    group_id: String,
) -> Result<SwitchResultDto, String> {
    let _switching_guard = SwitchingActiveGuard::enter(app, state);
    let cfg = state.snapshot_config();
    let requested_id = group_id.trim();
    if cfg.route_mode == RouteTargetMode::Single
        && (requested_id.is_empty()
            || requested_id == "default"
            || requested_id == "single"
            || requested_id == "__single__"
            || requested_id == SINGLE_NODE_GROUP_NAME)
    {
        let (nodes, snaps) = {
            let db = state.storage.lock().map_err(|e| e.to_string())?;
            let nodes = db.list_nodes().map_err(|e| e.to_string())?;
            if nodes.is_empty() {
                return Err("暂无可用节点，请先导入订阅".to_string());
            }
            let ids: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
            let snaps = db
                .get_probe_snapshots_batch(&ids, None)
                .map_err(|e| e.to_string())?;
            (nodes, snaps)
        };

        let prev_id = cfg.active_single_node_id.clone();
        let (next_id, next_name, next_region, latency_ms, up_mbps) = {
            let mut enabled_nodes: Vec<(usize, &ProxyNode)> = nodes
                .iter()
                .enumerate()
                .filter(|(_, n)| n.enabled)
                .collect();
            if enabled_nodes.is_empty() {
                return Err("暂无已启用的可用节点".to_string());
            }

            let health_pool = state.snapshot_node_health_pool();
            let now = Instant::now();
            enabled_nodes.sort_by(|(idx_a, a), (idx_b, b)| {
                let rank = |n: &ProxyNode| -> (u8, f64, f64) {
                    if let Some(rt) = health_pool.get(&n.id) {
                        if rt.is_in_cooldown(now) || rt.last_health == Some(RuntimeDualHealth::Failed)
                        {
                            return (2, f64::INFINITY, 0.0);
                        }
                        if let Some(live_ms) = health_pool.live_latency_ms(&n.id) {
                            let up = snaps
                                .get(&n.id)
                                .and_then(|s| s.up_mbps)
                                .filter(|v| v.is_finite())
                                .unwrap_or(0.0);
                            return (0, live_ms + rt.penalty_score, -up);
                        }
                    }
                    match snaps.get(&n.id) {
                        Some(s) if s.ok => (
                            0,
                            s.latency_ms.filter(|v| v.is_finite()).unwrap_or(f64::INFINITY),
                            -s.up_mbps.filter(|v| v.is_finite()).unwrap_or(0.0),
                        ),
                        None => (1, f64::INFINITY, 0.0),
                        Some(_) => (2, f64::INFINITY, 0.0),
                    }
                };
                let ra = rank(a);
                let rb = rank(b);
                ra.0.cmp(&rb.0)
                    .then_with(|| ra.1.total_cmp(&rb.1))
                    .then_with(|| ra.2.total_cmp(&rb.2))
                    .then_with(|| idx_a.cmp(idx_b))
            });

            let next = match prev_id
                .as_deref()
                .and_then(|id| enabled_nodes.iter().position(|(_, n)| n.id == id))
            {
                Some(idx) => enabled_nodes[(idx + 1) % enabled_nodes.len()].1,
                None => enabled_nodes[0].1,
            };
            let next_snap = snaps.get(&next.id);
            (
                next.id.clone(),
                next.name.clone(),
                next.region_code.clone(),
                state.resolve_node_latency_ms(&next.id, next_snap),
                next_snap.and_then(|s| s.up_mbps),
            )
        };

        let (_dto, closed_connections) =
            select_single_node_with_closed(app, state, next_id.clone()).await?;
        return Ok(SwitchResultDto {
            group_id: SINGLE_NODE_GROUP_NAME.to_string(),
            previous_node_id: prev_id,
            active_node_id: next_id,
            active_node_name: next_name,
            active_node_region: next_region,
            latency_ms,
            up_mbps,
            closed_connections,
        });
    }

    let (group, nodes, snaps) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let nodes = db.list_nodes().map_err(|e| e.to_string())?;
        if nodes.is_empty() {
            return Err("暂无可用节点，请先导入订阅".to_string());
        }
        let active_gid = cfg
            .active_group_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let found_group = if !requested_id.is_empty() && requested_id != "default" {
            db.get_multi_group(requested_id)
                .map_err(|e| e.to_string())?
                .or_else(|| active_gid.and_then(|aid| db.get_multi_group(aid).ok().flatten()))
                .or_else(|| db.list_multi_groups().ok().and_then(|mut v| v.drain(..).next()))
        } else {
            active_gid
                .and_then(|aid| db.get_multi_group(aid).ok().flatten())
                .or_else(|| db.get_multi_group("default").ok().flatten())
                .or_else(|| db.list_multi_groups().ok().and_then(|mut v| v.drain(..).next()))
        };
        let Some(group) = found_group else {
            return Err("暂无可切换的路线分组，请先创建分组".to_string());
        };
        let ids: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
        let snaps = db
            .get_probe_snapshots_batch(&ids, group.primary_probe_id.as_deref())
            .map_err(|e| e.to_string())?;
        (group, nodes, snaps)
    };

    let prev_id = group.active_node_id.clone();
    let prev_node_name = prev_id
        .as_deref()
        .and_then(|id| nodes.iter().find(|n| n.id == id))
        .map(|n| n.name.clone());

    // Rank candidates using the real strategy formula evaluator fused with runtime health pool;
    // when all members fail hard gates, keep honoring probed-ok scores in `gate_rejected` before
    // falling back to enabled member order.
    let health_pool = state.snapshot_node_health_pool();
    let ranked_ids: Vec<String> = match evaluate_group_candidates_with_runtime(
        &group,
        &nodes,
        &snaps,
        Some(&health_pool),
        Instant::now(),
    ) {
        Ok(report) => {
            if !report.healthy_candidates.is_empty() {
                report
                    .healthy_candidates
                    .iter()
                    .map(|c| c.node_id.clone())
                    .collect()
            } else if !report.gate_passed.is_empty() {
                report
                    .gate_passed
                    .iter()
                    .map(|c| c.node_id.clone())
                    .collect()
            } else {
                report
                    .gate_rejected
                    .iter()
                    .filter(|c| c.ok)
                    .map(|c| c.node_id.clone())
                    .collect()
            }
        }
        Err(_) => Vec::new(),
    };

    let ordered_candidates: Vec<&ProxyNode> = if !ranked_ids.is_empty() {
        ranked_ids
            .iter()
            .filter_map(|id| nodes.iter().find(|n| &n.id == id && n.enabled))
            .collect()
    } else if group.member_node_ids.is_empty() {
        nodes.iter().filter(|n| n.enabled).collect()
    } else {
        nodes
            .iter()
            .filter(|n| n.enabled && group.member_node_ids.contains(&n.id))
            .collect()
    };

    if ordered_candidates.is_empty() {
        return Err("该分组下暂无已启用的候选节点".to_string());
    }

    let next = match prev_id
        .as_deref()
        .and_then(|id| ordered_candidates.iter().position(|n| n.id == id))
    {
        Some(idx) => ordered_candidates[(idx + 1) % ordered_candidates.len()],
        None => ordered_candidates[0],
    };

    select_group_node_internal(
        app,
        state,
        group.id.clone(),
        next.id.clone(),
        Some(matches!(group.switch_mode, SwitchMode::ForceCloseOld)),
        prev_node_name,
    )
    .await
}

async fn select_single_node_with_closed(
    app: &AppHandle,
    state: &AppState,
    node_id: String,
) -> Result<(CoreRuntimeInfoDto, usize), String> {
    let _switching_guard = SwitchingActiveGuard::enter(app, state);
    let trimmed = node_id.trim();
    if trimmed.is_empty() {
        return Err("节点标识不能为空".to_string());
    }
    let _cfg_guard = state.config_transition_lock.lock().await;

    let prev_cfg = state.snapshot_config();
    let prev_single_id = if prev_cfg.route_mode == RouteTargetMode::Single {
        prev_cfg
            .active_single_node_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    } else {
        None
    };

    let (node, prev_node_fallback_name) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let node = db
            .get_node(trimmed)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("未找到指定节点（{trimmed}）"))?;
        let prev_name = prev_single_id
            .as_deref()
            .and_then(|pid| db.get_node(pid).ok().flatten())
            .map(|n| n.name);
        (node, prev_name)
    };
    if !node.enabled {
        return Err("该节点已停用，请先启用或选择其它节点".to_string());
    }

    let was_single = prev_single_id.is_some();
    let switched_node = prev_single_id.as_deref() != Some(node.id.as_str());
    let prev_proxy_name = if switched_node {
        prev_single_id
            .as_deref()
            .map(|pid| {
                let fallback = prev_node_fallback_name.as_deref().unwrap_or("");
                state.resolve_compiled_proxy_name(pid, fallback)
            })
            .filter(|s| !s.is_empty())
            .or(prev_node_fallback_name)
    } else {
        None
    };

    let mut cfg = prev_cfg.clone();
    cfg.route_mode = RouteTargetMode::Single;
    cfg.active_single_node_id = Some(node.id.clone());
    config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
    if let Ok(mut guard) = state.config.write() {
        *guard = cfg.clone();
    }

    let mut closed_connections = 0usize;
    if state.adapter.has_live_controller().await {
        let mut needs_reload = !was_single;
        if was_single {
            if let Some(proxy_name) = state.lookup_compiled_proxy_name(&node.id) {
                if state
                    .adapter
                    .select_group_proxy(SINGLE_NODE_GROUP_NAME, &proxy_name)
                    .await
                    .is_err()
                {
                    needs_reload = true;
                }
            } else {
                // Target node is not present in the currently compiled (possibly pruned) config:
                // force an L2 reload instead of falling back to raw `node.name`, which would either
                // trigger an avoidable HTTP 400 or silently switch to a same-named node from another sub.
                needs_reload = true;
            }
        }
        if needs_reload {
            if let Some(outcome) = trigger_reload_if_running(app, state, true).await {
                if outcome.rejected {
                    let _ = config::save(&state.paths, &prev_cfg);
                    if let Ok(mut guard) = state.config.write() {
                        *guard = prev_cfg.clone();
                    }
                    sync_app_side_effects(app, state, &prev_cfg);
                    let detail = outcome
                        .error
                        .as_deref()
                        .map(format_mihomo_error_for_user)
                        .unwrap_or_else(|| "未知原因".to_string());
                    return Err(format!(
                        "切换到单节点「{}」失败，核心配置重载未通过：{detail}",
                        node.name
                    ));
                }
            }
        }
        // Close lingering long-lived connections from the previous node so AI IDEs / browsers
        // immediately bind to the newly selected single node.
        if switched_node {
            if let Ok(closed) = state
                .adapter
                .close_connections_for_group_or_node(
                    Some(SINGLE_NODE_GROUP_NAME),
                    prev_proxy_name.as_deref(),
                )
                .await
            {
                closed_connections = closed;
            }
        }
    }

    state.log_app_event(
        "info",
        "节点切换",
        &format!(
            "单节点直选切换至「{}」（地区 {}，断开旧连接 {} 条）",
            node.name, node.region_code, closed_connections
        ),
    );
    sync_app_side_effects(app, state, &cfg);
    Ok((build_runtime_info_dto(state)?, closed_connections))
}

pub async fn select_single_node_internal(
    app: &AppHandle,
    state: &AppState,
    node_id: String,
) -> Result<CoreRuntimeInfoDto, String> {
    let (dto, _) = select_single_node_with_closed(app, state, node_id).await?;
    Ok(dto)
}

async fn select_group_node_core(
    app: &AppHandle,
    state: &AppState,
    group_id: String,
    node_id: String,
    close_old: Option<bool>,
    prev_node_name_hint: Option<String>,
    activate_group: bool,
) -> Result<SwitchResultDto, String> {
    let _switching_guard = SwitchingActiveGuard::enter(app, state);
    let _cfg_guard = state.config_transition_lock.lock().await;
    let (mut group, target_node, prev_id, prev_node_name, snap) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let group = db
            .get_multi_group(&group_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("未找到指定路线分组（{group_id}）"))?;
        let target_node = db
            .get_node(&node_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("未找到指定节点（{node_id}）"))?;
        let prev_id = group.active_node_id.clone();
        let prev_node_name = prev_node_name_hint.or_else(|| {
            prev_id
                .as_deref()
                .and_then(|id| db.get_node(id).ok().flatten())
                .map(|n| n.name)
        });
        let snap = db
            .get_probe_snapshot(&target_node.id, group.primary_probe_id.as_deref())
            .map_err(|e| e.to_string())?;
        (group, target_node, prev_id, prev_node_name, snap)
    };

    let mut members_changed = false;
    let is_dynamic_unpinned_pool = group.member_node_ids.is_empty()
        && (group.mode == MultiGroupMode::ConditionalPool || group.dynamic_filter.is_some());
    if !is_dynamic_unpinned_pool && !group.member_node_ids.iter().any(|id| id == &target_node.id) {
        group.member_node_ids.push(target_node.id.clone());
        members_changed = true;
    }
    group.active_node_id = Some(target_node.id.clone());
    {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        db.upsert_multi_group(&group).map_err(|e| e.to_string())?;
    }

    let mut cfg = state.snapshot_config();
    let was_single = cfg.route_mode == RouteTargetMode::Single;
    let active_group_changed = cfg.active_group_id.as_deref() != Some(group.id.as_str());
    let route_cfg_changed = activate_group && (was_single || active_group_changed);
    if route_cfg_changed {
        cfg.route_mode = RouteTargetMode::Group;
        cfg.active_group_id = Some(group.id.clone());
        config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
        if let Ok(mut guard) = state.config.write() {
            *guard = cfg.clone();
        }
    }

    let mut closed_connections = 0usize;
    if state.adapter.has_live_controller().await {
        if members_changed || route_cfg_changed {
            if let Some(outcome) =
                trigger_reload_if_running(app, state, (activate_group && was_single) || members_changed)
                    .await
            {
                if outcome.rejected {
                    let detail = outcome
                        .error
                        .as_deref()
                        .map(format_mihomo_error_for_user)
                        .unwrap_or_else(|| "未知原因".to_string());
                    return Err(format!(
                        "已将节点「{}」加入分组「{}」，但重载核心配置失败：{detail}",
                        target_node.name, group.name
                    ));
                }
            }
        }
        let target_proxy_name =
            state.resolve_compiled_proxy_name(&target_node.id, &target_node.name);
        state
            .adapter
            .select_group_proxy(&group.name, &target_proxy_name)
            .await
            .map_err(|e| {
                format!(
                    "切换核心节点「{}」失败，请确认该节点已启用且核心运行正常：{e}",
                    target_node.name
                )
            })?;
        let should_close =
            close_old.unwrap_or_else(|| matches!(group.switch_mode, SwitchMode::ForceCloseOld));
        if should_close {
            let prev_compiled_name = prev_id.as_deref().map(|pid| {
                let fallback = prev_node_name.as_deref().unwrap_or("");
                state.resolve_compiled_proxy_name(pid, fallback)
            });
            let prev_target = prev_compiled_name
                .as_deref()
                .filter(|s| !s.is_empty())
                .or(prev_node_name.as_deref());
            if let Ok(closed) = state
                .adapter
                .close_connections_for_group_or_node(Some(&group.name), prev_target)
                .await
            {
                closed_connections = closed;
            }
        }
    }

    let cfg = state.snapshot_config();
    state.set_group_backoff_until(&group.id, None);
    if activate_group {
        let from_label = prev_node_name.as_deref().unwrap_or("未选");
        state.log_app_event(
            "info",
            "节点切换",
            &format!(
                "分组「{}」切换节点：{} -> {}（断开旧连接 {} 条）",
                group.name, from_label, target_node.name, closed_connections
            ),
        );
    }
    sync_app_side_effects(app, state, &cfg);

    let resolved_latency_ms = state.resolve_node_latency_ms(&target_node.id, snap.as_ref());
    Ok(SwitchResultDto {
        group_id: group.id,
        previous_node_id: prev_id,
        active_node_id: target_node.id,
        active_node_name: target_node.name,
        active_node_region: target_node.region_code,
        latency_ms: resolved_latency_ms,
        up_mbps: snap.as_ref().and_then(|s| s.up_mbps),
        closed_connections,
    })
}

pub async fn select_group_node_internal(
    app: &AppHandle,
    state: &AppState,
    group_id: String,
    node_id: String,
    close_old: Option<bool>,
    prev_node_name_hint: Option<String>,
) -> Result<SwitchResultDto, String> {
    select_group_node_core(
        app,
        state,
        group_id,
        node_id,
        close_old,
        prev_node_name_hint,
        true,
    )
    .await
}

/// Switch a group's active node in Mihomo and SQLite WITHOUT changing `config.active_group_id`
/// (used by background watchdog failover for non-primary `independent_routing` groups).
pub async fn select_group_node_in_place_internal(
    app: &AppHandle,
    state: &AppState,
    group_id: String,
    node_id: String,
    close_old: Option<bool>,
    prev_node_name_hint: Option<String>,
) -> Result<SwitchResultDto, String> {
    select_group_node_core(
        app,
        state,
        group_id,
        node_id,
        close_old,
        prev_node_name_hint,
        false,
    )
    .await
}

/// Select group IDs eligible for post-probe auto-reconciliation and switch toast emission.
/// - Never selects any group while `cfg.route_mode != RouteTargetMode::Group` (Single-node mode).
/// - When `compiled_group_ids` is provided (running core), filters out groups that were pruned
///   from the active compiled Mihomo configuration.
fn select_reconcilable_active_group_ids(
    cfg: &AppConfig,
    groups: &[MultiGroup],
    compiled_group_ids: Option<&HashSet<String>>,
) -> Vec<String> {
    if cfg.route_mode != RouteTargetMode::Group || groups.is_empty() {
        return Vec::new();
    }

    let active_gid = cfg
        .active_group_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|aid| groups.iter().find(|g| g.id == aid).map(|g| g.id.clone()))
        .or_else(|| groups.first().map(|g| g.id.clone()));

    let mut ids = Vec::new();
    for g in groups {
        let is_primary = active_gid.as_deref() == Some(g.id.as_str());
        let is_strategy_mode = matches!(
            g.mode,
            MultiGroupMode::StickyBest | MultiGroupMode::ConditionalPool
        );
        if !(is_primary || (g.independent_routing && is_strategy_mode)) {
            continue;
        }
        if let Some(compiled) = compiled_group_ids {
            if !compiled.contains(g.id.trim()) {
                continue;
            }
        }
        if !ids.iter().any(|existing| existing == &g.id) {
            ids.push(g.id.clone());
        }
    }
    ids
}

/// Reconcile a single multi-group against current membership, hard gates, and probe snapshots.
/// Persists any `active_node_id` update to SQLite, optionally hot-switches Mihomo & closes stale
/// connections when `sync_live_core` is true, and optionally emits `catcloud://strategy-switch`.
pub async fn reconcile_group_best_node_internal(
    app: &AppHandle,
    state: &AppState,
    group_id: &str,
    sync_live_core: bool,
    emit_notification: bool,
) -> Result<Option<SwitchResultDto>, String> {
    let (group_name, switch_mode, decision, target_node_region, target_snap) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let Some(mut group) = db
            .get_multi_group(group_id)
            .map_err(|e| e.to_string())?
        else {
            return Ok(None);
        };
        let nodes = db.list_nodes().map_err(|e| e.to_string())?;
        let node_ids: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
        let snaps = db
            .get_probe_snapshots_batch(&node_ids, group.primary_probe_id.as_deref())
            .map_err(|e| e.to_string())?;

        let prev_active = group.active_node_id.clone();
        let health_pool = state.snapshot_node_health_pool();
        let decision = reconcile_group_best_node_in_memory_with_runtime(
            &mut group,
            &nodes,
            &snaps,
            Some(&health_pool),
            Instant::now(),
        );
        if group.active_node_id != prev_active {
            db.upsert_multi_group(&group).map_err(|e| e.to_string())?;
        }

        let Some(dec) = decision else {
            return Ok(None);
        };
        let target_region = nodes
            .iter()
            .find(|n| n.id == dec.to_node_id)
            .map(|n| n.region_code.clone())
            .unwrap_or_else(|| "--".to_string());
        let snap = snaps.get(&dec.to_node_id).cloned();
        (group.name, group.switch_mode, dec, target_region, snap)
    };

    let mut closed_connections = 0usize;
    let mut live_switch_ok = true;
    if sync_live_core && state.adapter.has_live_controller().await {
        let target_proxy_name =
            state.resolve_compiled_proxy_name(&decision.to_node_id, &decision.to_node_name);
        if let Err(err) = state
            .adapter
            .select_group_proxy(&group_name, &target_proxy_name)
            .await
        {
            live_switch_ok = false;
            tracing::debug!(
                group = %group_name,
                proxy = %target_proxy_name,
                "reconcile_group_best_node_internal hot-switch skipped: {err}"
            );
        } else if matches!(switch_mode, SwitchMode::ForceCloseOld) {
            let prev_compiled_name = decision.from_node_id.as_deref().map(|pid| {
                state.resolve_compiled_proxy_name(pid, &decision.from_node_name)
            });
            let prev_target = prev_compiled_name
                .as_deref()
                .filter(|s| !s.is_empty())
                .or(Some(decision.from_node_name.as_str()));
            if let Ok(closed) = state
                .adapter
                .close_connections_for_group_or_node(Some(&group_name), prev_target)
                .await
            {
                closed_connections = closed;
            }
        }
    }

    state.log_app_event(
        "info",
        "策略择优",
        &format!(
            "分组「{}」自动择优切换：{} -> {}（{}，断开旧连接 {} 条）",
            group_name,
            decision.from_node_name,
            decision.to_node_name,
            decision.reason,
            closed_connections
        ),
    );

    if emit_notification && live_switch_ok {
        let _ = app.emit(
            EVENT_STRATEGY_SWITCH,
            serde_json::json!({
                "group_name": group_name,
                "from_node": decision.from_node_name,
                "to_node": decision.to_node_name,
                "reason": decision.reason,
            }),
        );
    }

    let resolved_latency_ms =
        state.resolve_node_latency_ms(&decision.to_node_id, target_snap.as_ref());
    Ok(Some(SwitchResultDto {
        group_id: group_id.to_string(),
        previous_node_id: decision.from_node_id,
        active_node_id: decision.to_node_id,
        active_node_name: decision.to_node_name,
        active_node_region: target_node_region,
        latency_ms: resolved_latency_ms,
        up_mbps: target_snap.as_ref().and_then(|s| s.up_mbps),
        closed_connections,
    }))
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

#[tauri::command]
pub fn get_app_config(state: State<'_, AppState>) -> Result<UiAppConfigDto, String> {
    let cfg = state.snapshot_config();
    Ok(UiAppConfigDto::from(&cfg))
}

fn reconcile_saved_preaccel_switch(old: &AppConfig, next: &mut AppConfig) {
    if old.preaccel.enabled != next.preaccel.enabled {
        next.preaccel.sync_unified_enabled(next.preaccel.enabled);
    } else if old.preaccel.global_bypass_enabled != next.preaccel.global_bypass_enabled {
        next.preaccel
            .sync_unified_enabled(next.preaccel.global_bypass_enabled);
    } else {
        next.preaccel.reconcile_unified_enabled();
    }
}

/// Delay before inspecting Go heap after switching `Global -> Rule` so idle memory settles.
const HEAP_RECLAIM_DELAY_SECS: u64 = 8;
/// Skip heap-reclaim restart when active application connections exceed this count.
const HEAP_RECLAIM_MAX_ACTIVE_CONNS: usize = 8;
/// Sliding window (10 s) for heap-reclaim high-throughput guard.
const HEAP_RECLAIM_HIGH_THROUGHPUT_WINDOW_MS: i64 = 10_000;
/// Throughput threshold (128 KiB/s) protecting ongoing transfers from heap-reclaim restart.
const HEAP_RECLAIM_HIGH_THROUGHPUT_THRESHOLD_BPS: u64 = 128 * 1024;
/// Minimum cooldown between consecutive automatic heap-reclaim restarts (10 minutes).
const HEAP_RECLAIM_COOLDOWN_SECS: u64 = 10 * 60;
/// Floor memory threshold in MiB below which Go heap reclaim is skipped.
const HEAP_RECLAIM_MIN_MEMORY_MB: f64 = 90.0;

#[derive(Debug, Clone, PartialEq)]
struct HeapReclaimCheckInput {
    gen_matches: bool,
    is_rule_mode: bool,
    core_running: bool,
    tun_enabled: bool,
    active_connections: usize,
    high_throughput: bool,
    probing_active: bool,
    memory_mb: f64,
    budget_mb: f64,
    cooldown_elapsed: bool,
}

/// Pure guardrail evaluator for `Global -> Rule` delayed Go heap reclaim.
/// Returns `Ok(threshold_mb)` only when every safety invariant passes.
fn evaluate_heap_reclaim_guard(input: &HeapReclaimCheckInput) -> Result<f64, &'static str> {
    if !input.gen_matches {
        return Err("config_generation_changed");
    }
    if !input.is_rule_mode || !input.core_running {
        return Err("not_rule_or_core_stopped");
    }
    if input.tun_enabled {
        return Err("tun_active");
    }
    if input.active_connections > HEAP_RECLAIM_MAX_ACTIVE_CONNS {
        return Err("too_many_active_connections");
    }
    if input.high_throughput {
        return Err("high_throughput_active");
    }
    if input.probing_active {
        return Err("probing_active");
    }
    let threshold_mb = (input.budget_mb * 1.5).max(HEAP_RECLAIM_MIN_MEMORY_MB);
    if !input.memory_mb.is_finite() || input.memory_mb <= threshold_mb {
        return Err("memory_within_budget");
    }
    if !input.cooldown_elapsed {
        return Err("cooldown_active");
    }
    Ok(threshold_mb)
}

fn schedule_global_to_rule_heap_reclaim(app: &AppHandle, expected_gen: u64) {
    let app_h = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(HEAP_RECLAIM_DELAY_SECS)).await;

        let Some(st) = app_h.try_state::<AppState>() else {
            return;
        };
        if st.shutting_down.load(Ordering::SeqCst) {
            return;
        }
        // Never block or contend with active user config transitions.
        let Ok(_cfg_guard) = st.config_transition_lock.try_lock() else {
            return;
        };
        if st.shutting_down.load(Ordering::SeqCst) || st.config_generation() != expected_gen {
            return;
        }

        let cfg = st.snapshot_config();
        let core_running =
            st.snapshot_runtime().running && st.adapter.has_live_controller().await;
        if cfg.proxy_mode != ProxyMode::Rule || !core_running {
            return;
        }

        let live_snap =
            tokio::time::timeout(Duration::from_millis(800), st.adapter.list_connections())
                .await
                .ok()
                .and_then(|res| res.ok());
        let cached = st
            .cached_metrics
            .read()
            .map(|m| *m)
            .unwrap_or_default();
        let (active_connections, mem_bytes) = if let Some(ref snap) = live_snap {
            let summary = summarize_connections(&snap.connections);
            let mem = if snap.memory > 0 {
                snap.memory
            } else {
                cached.core_mem_bytes
            };
            (summary.app_connections, mem)
        } else {
            (cached.app_connections, cached.core_mem_bytes)
        };

        let recent_ticks = st.telemetry.traffic_snapshot();
        let now_ms = Utc::now().timestamp_millis();
        let high_throughput = is_high_throughput_active(
            &cached,
            &recent_ticks,
            now_ms,
            HEAP_RECLAIM_HIGH_THROUGHPUT_WINDOW_MS,
            HEAP_RECLAIM_HIGH_THROUGHPUT_THRESHOLD_BPS,
        );
        let rt = st.snapshot_runtime();
        let budget_mb = cfg
            .core_runtime
            .memory_tier
            .resolve_mib(rt.node_count, rt.rule_count) as f64;
        let memory_mb = (mem_bytes as f64) / (1024.0 * 1024.0);
        let cooldown_elapsed = st
            .last_heap_reclaim_at
            .lock()
            .ok()
            .and_then(|g| *g)
            .is_none_or(|last| last.elapsed() >= Duration::from_secs(HEAP_RECLAIM_COOLDOWN_SECS));

        let check = HeapReclaimCheckInput {
            gen_matches: st.config_generation() == expected_gen,
            is_rule_mode: cfg.proxy_mode == ProxyMode::Rule,
            core_running,
            tun_enabled: effective_tun_enabled(&st, &cfg),
            active_connections,
            high_throughput,
            probing_active: st.probe_running.load(Ordering::SeqCst),
            memory_mb,
            budget_mb,
            cooldown_elapsed,
        };

        let threshold_mb = match evaluate_heap_reclaim_guard(&check) {
            Ok(threshold) => threshold,
            Err(reason) => {
                tracing::debug!(
                    reason,
                    memory_mb,
                    budget_mb,
                    active_connections,
                    "Global -> Rule delayed Go heap reclaim skipped"
                );
                return;
            }
        };

        if let Ok(mut guard) = st.last_heap_reclaim_at.lock() {
            *guard = Some(Instant::now());
        }
        st.log_app_event(
            "info",
            "内存",
            &format!(
                "从全局模式切回规则分流后核心内存偏高（{memory_mb:.1} MiB > 阈值 {threshold_mb:.1} MiB，活跃连接 {active_connections} 条），正在执行核心轻量重启以回收 Go 堆内存"
            ),
        );

        match restart_core_locked(&app_h, &st).await {
            Ok(_) => {
                st.log_app_event(
                    "info",
                    "内存",
                    "已完成核心轻量重启并回收 Go 堆内存（代理与规则分流状态保持正常）",
                );
            }
            Err(err) => {
                st.log_app_event(
                    "warning",
                    "内存",
                    &format!("延迟内存回收触发核心轻量重启未成功，已自动回滚保护：{err}"),
                );
            }
        }
    });
}

async fn apply_and_save_config_transition<F>(
    app: &AppHandle,
    state: &AppState,
    build_next: F,
) -> Result<AppConfig, String>
where
    F: FnOnce(&AppConfig) -> Result<AppConfig, String>,
{
    let _cfg_guard = state.config_transition_lock.lock().await;
    let old = state.snapshot_config();
    let mut next = build_next(&old)?;
    next.personalization.language = if next.personalization.language.trim().is_empty() {
        old.personalization.normalized_ui_language().to_string()
    } else {
        normalize_ui_language(&next.personalization.language).to_string()
    };

    let tun_ready = is_tun_privilege_ready(state);
    let old_eff_tun = old.tun.enabled && tun_ready;
    let next_eff_tun = next.tun.enabled && tun_ready;
    let was_core_running =
        state.snapshot_runtime().running || state.adapter.has_live_controller().await;
    let was_tun_active = was_core_running && old_eff_tun;

    if !old.tun.enabled && next.tun.enabled && !tun_ready {
        return Err(tun_needs_admin_error_message());
    }

    if (!old.system_proxy.enabled && next.system_proxy.enabled)
        || (!old.tun.enabled && next.tun.enabled)
    {
        if !has_enabled_nodes(state)? {
            return Err("暂无可用节点，请先导入订阅".to_string());
        }
    }

    let disabling_all_proxy = (old.system_proxy.enabled || old_eff_tun)
        && !next.system_proxy.enabled
        && !next_eff_tun;

    if old_eff_tun && !next.tun.enabled && state.adapter.has_live_controller().await {
        let _ = state.adapter.disable_tun_gracefully().await;
    }

    config::save(&state.paths, &next).map_err(|e| format!("保存配置文件失败：{e}"))?;
    if let Ok(mut guard) = state.config.write() {
        *guard = next.clone();
    }

    let needs_core_boot = ((!old.system_proxy.enabled && next.system_proxy.enabled)
        || (!old_eff_tun && next_eff_tun))
        && !state.adapter.has_live_controller().await;

    let latest_before_stop = state.snapshot_config();
    let latest_eff_tun = effective_tun_enabled(state, &latest_before_stop);
    if disabling_all_proxy
        && was_core_running
        && !latest_before_stop.system_proxy.enabled
        && !latest_eff_tun
    {
        // Clear OS proxy before stopping main core so host internet is never blackholed.
        if old.system_proxy.enabled {
            let _ = clear_system_proxy_if_owned_with_hint(state, true);
        }
        if next.tun.enabled {
            stop_core_preserving_tun_intent_internal(app, state).await?;
        } else {
            stop_core_internal(app, state).await?;
        }
        if old.preaccel.enabled && !next.preaccel.enabled && state.global_preaccel.status().running
        {
            let _ = state.global_preaccel.stop().await;
        }
        state.bump_config_generation();
        sync_autostart_if_changed(&old, &next);
        let latest = state.snapshot_config();
        sync_app_side_effects(app, state, &latest);
        let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&latest));
        return Ok(latest);
    }

    let mut started_core_here = false;
    if needs_core_boot {
        if let Err(err) = start_core_internal(app, state).await {
            let _ = config::save(&state.paths, &old);
            if let Ok(mut guard) = state.config.write() {
                *guard = old.clone();
            }
            sync_app_side_effects(app, state, &old);
            return Err(format!("保存配置后启动代理核心失败：{err}"));
        }
        started_core_here = true;
    } else if has_core_config_changes(&old, &next) {
        if let Some(outcome) = trigger_reload_if_running(app, state, false).await {
            if outcome.rejected {
                let _ = config::save(&state.paths, &old);
                if let Ok(mut guard) = state.config.write() {
                    *guard = old.clone();
                }
                sync_app_side_effects(app, state, &old);
                let raw_err = outcome
                    .error
                    .unwrap_or_else(|| "配置预检未通过，已恢复原配置运行".to_string());
                return Err(format_mihomo_error_for_user(&raw_err));
            }
        }
    }

    let sys_proxy_changed = old.system_proxy != next.system_proxy
        || (next.system_proxy.enabled && old.mixed_port != next.mixed_port);
    if sys_proxy_changed {
        let apply_res = if next.system_proxy.enabled {
            let effective_port = {
                let rt = state.snapshot_runtime();
                if rt.running { rt.mixed_port } else { next.mixed_port }
            };
            apply_system_proxy_if_still_enabled(state, effective_port).map(|_| ())
        } else {
            clear_system_proxy_if_owned_with_hint(state, old.system_proxy.enabled).map(|_| ())
        };
        if let Err(err) = apply_res {
            let _ = config::save(&state.paths, &old);
            if let Ok(mut guard) = state.config.write() {
                *guard = old.clone();
            }
            if started_core_here && !old.system_proxy.enabled && !old_eff_tun {
                // Lock order: already holding outer `config_transition_lock` -> inner `core_lifecycle_lock`.
                if let Err(stop_err) = stop_core_preserving_tun_intent_internal(app, state).await {
                    tracing::warn!("配置切换写入系统代理失败回滚后停止新拉起核心异常：{stop_err}");
                }
            }
            let latest = state.snapshot_config();
            sync_app_side_effects(app, state, &latest);
            let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&latest));
            return Err(err);
        }
    }

    let now_core_running =
        state.snapshot_runtime().running || state.adapter.has_live_controller().await;
    let now_tun_active = now_core_running && effective_tun_enabled(state, &next);
    let relay_selection_changed = old.preaccel.active_relay_id != next.preaccel.active_relay_id;
    let windivert_policy_changed = old.preaccel.skip_443_native != next.preaccel.skip_443_native
        || old.preaccel.probe_url != next.preaccel.probe_url
        || old.preaccel.global_scope != next.preaccel.global_scope
        || old.preaccel.global_target_processes != next.preaccel.global_target_processes
        || old.preaccel.windivert_dir != next.preaccel.windivert_dir;

    if !next.preaccel.enabled && state.global_preaccel.status().running {
        let _ = state.global_preaccel.stop().await;
    } else if was_tun_active != now_tun_active || (old.preaccel.enabled != next.preaccel.enabled) {
        coordinate_global_preaccel_on_tun_transition(
            app,
            state,
            &next,
            was_tun_active,
            now_tun_active,
            "代理配置",
        )
        .await;
    } else if !now_tun_active && next.preaccel.enabled && state.global_preaccel.status().running {
        if relay_selection_changed {
            sync_running_global_preaccel_if_active(state, &next).await;
        } else if windivert_policy_changed {
            if let Ok(relays) = load_enabled_preaccel_relays(state) {
                if !relays.is_empty() {
                    let excluded_pids = collect_excluded_pids_for_global_preaccel(state);
                    match state
                        .global_preaccel
                        .restart_windivert_if_running(&next, &relays, &excluded_pids)
                        .await
                    {
                        Ok(rebuilt_st) => {
                            log_global_preaccel_verify_status(
                                state,
                                "提速参数变更热重建 WinDivert",
                                &rebuilt_st,
                            );
                        }
                        Err(err) => {
                            state.log_app_event(
                                "warning",
                                "国内提速",
                                &format!("提速策略变更后热重建 WinDivert 失败：{err}"),
                            );
                        }
                    }
                }
            }
        }
    }

    let next_gen = state.bump_config_generation();
    if old.proxy_mode == ProxyMode::Global && next.proxy_mode == ProxyMode::Rule && now_core_running
    {
        schedule_global_to_rule_heap_reclaim(app, next_gen);
    }

    sync_autostart_if_changed(&old, &next);
    sync_app_side_effects(app, state, &next);
    let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&next));
    Ok(next)
}

#[tauri::command]
pub async fn save_app_config(
    app: AppHandle,
    state: State<'_, AppState>,
    config: UiAppConfigDto,
) -> Result<UiAppConfigDto, String> {
    let cfg = apply_and_save_config_transition(&app, &state, |old| {
        let mut cfg = old.clone();
        apply_ui_dto(&mut cfg, &config);
        cfg.preaccel.sync_unified_enabled(config.preaccel.enabled);
        Ok(cfg)
    })
    .await?;
    Ok(UiAppConfigDto::from(&cfg))
}

#[tauri::command]
pub fn get_full_config(state: State<'_, AppState>) -> Result<AppConfig, String> {
    Ok(state.snapshot_config())
}

#[tauri::command]
pub async fn save_full_config(
    app: AppHandle,
    state: State<'_, AppState>,
    mut next: AppConfig,
) -> Result<AppConfig, String> {
    apply_and_save_config_transition(&app, &state, move |old| {
        reconcile_saved_preaccel_switch(old, &mut next);
        Ok(next)
    })
    .await
}

fn is_replace_map_path(path: &str) -> bool {
    matches!(path, "dns.nameserver_policy" | "dns.hosts")
}

fn json_deep_merge_inner(
    target: &mut serde_json::Value,
    patch: &serde_json::Value,
    path: &str,
) {
    match (target, patch) {
        (serde_json::Value::Object(t_map), serde_json::Value::Object(p_map)) => {
            if !path.is_empty() && (is_replace_map_path(path) || p_map.is_empty()) {
                *t_map = p_map.clone();
                return;
            }
            for (k, v) in p_map {
                let child_path = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                if let Some(existing) = t_map.get_mut(k) {
                    json_deep_merge_inner(existing, v, &child_path);
                } else {
                    t_map.insert(k.clone(), v.clone());
                }
            }
        }
        (slot, new_val) => {
            *slot = new_val.clone();
        }
    }
}

fn json_deep_merge(target: &mut serde_json::Value, patch: &serde_json::Value) {
    json_deep_merge_inner(target, patch, "");
}

#[tauri::command]
pub async fn save_extended_settings(
    app: AppHandle,
    state: State<'_, AppState>,
    patch: serde_json::Value,
) -> Result<AppConfig, String> {
    apply_and_save_config_transition(&app, &state, |old| {
        let mut base_val = serde_json::to_value(old).map_err(|e| e.to_string())?;
        json_deep_merge(&mut base_val, &patch);
        let mut next: AppConfig = serde_json::from_value(base_val)
            .map_err(|e| format!("配置字段格式无效：{e}"))?;
        reconcile_saved_preaccel_switch(old, &mut next);
        Ok(next)
    })
    .await
}

#[tauri::command]
pub async fn get_runtime_info(state: State<'_, AppState>) -> Result<CoreRuntimeInfoDto, String> {
    let live = state.adapter.status().await;
    state.update_cached_runtime(live);
    build_runtime_info_dto(&state)
}

#[tauri::command]
pub async fn start_core(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CoreRuntimeInfoDto, String> {
    // Strictly uphold lock ordering: outer `config_transition_lock` -> inner `core_lifecycle_lock`.
    let _cfg_guard = state.config_transition_lock.lock().await;
    start_core_internal(&app, &state).await
}

#[tauri::command]
pub async fn stop_core(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CoreRuntimeInfoDto, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    stop_core_internal(&app, &state).await
}

#[tauri::command]
pub async fn disable_all_proxy_and_stop_core(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CoreRuntimeInfoDto, String> {
    disable_all_proxy_and_stop_core_internal(&app, &state).await
}

/// Restart managed core cleanly. Caller MUST already hold outer `state.config_transition_lock`.
/// Internally acquires inner `state.core_lifecycle_lock` to preserve strict lock ordering.
async fn restart_core_locked(
    app: &AppHandle,
    state: &AppState,
) -> Result<CoreRuntimeInfoDto, String> {
    let _lifecycle_guard = state.core_lifecycle_lock.lock().await;
    stop_core_for_restart_locked(state).await?;
    match start_core_locked(app, state).await {
        Ok(dto) => Ok(dto),
        Err(err) => {
            // If restart fails, flip in-memory flags first, then clear owned OS proxy & save
            // so ProxyGuard cannot race back to `ProxyEnable=1` and host internet is never blackholed.
            let mut cfg = state.snapshot_config();
            let was_sys_proxy_enabled = cfg.system_proxy.enabled;
            let clear_tun = effective_tun_enabled(state, &cfg);
            let flags_changed = cfg.system_proxy.enabled || clear_tun;
            if flags_changed {
                cfg.system_proxy.enabled = false;
                if clear_tun {
                    cfg.tun.enabled = false;
                }
                if let Ok(mut guard) = state.config.write() {
                    *guard = cfg.clone();
                }
            }
            let _ = clear_system_proxy_if_owned_with_hint(state, was_sys_proxy_enabled);
            if flags_changed {
                let _ = config::save(&state.paths, &cfg);
            }
            sync_app_side_effects(app, state, &cfg);
            state.log_app_event(
                "error",
                "核心",
                &format!("重启代理核心失败，已自动回滚代理开关：{err}"),
            );
            Err(err)
        }
    }
}

#[tauri::command]
pub async fn restart_core(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CoreRuntimeInfoDto, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    restart_core_locked(&app, &state).await
}

#[tauri::command]
pub async fn reload_core_config(
    app: AppHandle,
    state: State<'_, AppState>,
    force_disk_reload: Option<bool>,
) -> Result<ReloadOutcome, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    let force = force_disk_reload.unwrap_or(true);
    let mut disk_cfg = config::load_or_init(&state.paths).map_err(|e| e.to_string())?;
    disk_cfg.preaccel.reconcile_unified_enabled();
    if let Ok(mut guard) = state.config.write() {
        *guard = disk_cfg.clone();
    }
    if let Some(mut outcome) = trigger_reload_if_running(&app, &state, force).await {
        if outcome.rejected {
            if let Some(err) = outcome.error.take() {
                outcome.error = Some(format_mihomo_error_for_user(&err));
            }
        }
        return Ok(outcome);
    }
    // Core is stopped: still validate & compile candidate YAML so agents get real pre-flight feedback.
    let mut outcome = {
        let _lifecycle_guard = state.core_lifecycle_lock.lock().await;
        state
            .hot_reload
            .apply_disk_reload(DiskReloadOptions {
                force,
                verify_with_binary: true,
                allow_l3_restart: false,
                allow_tun: is_tun_privilege_ready(&state),
                ..DiskReloadOptions::default()
            })
            .await
    };
    if outcome.rejected {
        if let Some(err) = outcome.error.take() {
            let formatted = format_mihomo_error_for_user(&err);
            state.log_app_event("warning", "热重载", &format!("离线配置预检未通过：{formatted}"));
            outcome.error = Some(formatted);
        }
    }
    sync_app_side_effects(&app, &state, &disk_cfg);
    Ok(outcome)
}

#[tauri::command]
pub async fn set_proxy_mode(
    app: AppHandle,
    state: State<'_, AppState>,
    mode: ProxyMode,
) -> Result<ProxyMode, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    let prev_cfg = state.snapshot_config();
    let prev_mode = prev_cfg.proxy_mode.clone();
    let mut cfg = prev_cfg;
    cfg.proxy_mode = mode.clone();
    config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
    if let Ok(mut guard) = state.config.write() {
        *guard = cfg.clone();
    }
    if let Some(outcome) = trigger_reload_if_running(&app, &state, false).await {
        if outcome.rejected {
            let mut rollback_cfg = state.snapshot_config();
            rollback_cfg.proxy_mode = prev_mode;
            let _ = config::save(&state.paths, &rollback_cfg);
            if let Ok(mut guard) = state.config.write() {
                *guard = rollback_cfg.clone();
            }
            sync_app_side_effects(&app, &state, &rollback_cfg);
            let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&rollback_cfg));
            let detail = outcome
                .error
                .as_deref()
                .map(format_mihomo_error_for_user)
                .unwrap_or_else(|| "未知原因".to_string());
            return Err(format!("切换代理模式为 {} 失败：{detail}", mode.as_str()));
        }
    }
    let next_gen = state.bump_config_generation();
    if prev_mode == ProxyMode::Global
        && mode == ProxyMode::Rule
        && (state.snapshot_runtime().running || state.adapter.has_live_controller().await)
    {
        schedule_global_to_rule_heap_reclaim(&app, next_gen);
    }
    state.log_app_event(
        "info",
        "模式",
        &format!("代理模式已切换为 {}", mode.as_str()),
    );
    let latest_cfg = state.snapshot_config();
    sync_app_side_effects(&app, &state, &latest_cfg);
    let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&latest_cfg));
    Ok(mode)
}

#[tauri::command]
pub async fn set_system_proxy(
    app: AppHandle,
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<bool, String> {
    apply_system_proxy_internal(&app, &state, enabled).await
}

/// Enable or disable TUN virtual NIC mode safely:
/// - Enabling checks administrator elevation first (`NEEDS_ADMIN:...` without dirty writes),
///   auto-starts or L3-reloads the core, and rolls back `config.json` on any failure.
/// - Disabling calls `disable_tun_gracefully()` before saving; if system proxy is also disabled,
///   stops the main core directly with zero port/memory/connection residue instead of reloading.
pub async fn set_tun_enabled_internal(
    app: &AppHandle,
    state: &AppState,
    enabled: bool,
) -> Result<bool, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    let old_cfg = state.snapshot_config();
    let old_tun_enabled = old_cfg.tun.enabled;
    let was_core_running =
        state.snapshot_runtime().running || state.adapter.has_live_controller().await;
    let was_tun_active = was_core_running && effective_tun_enabled(state, &old_cfg);

    if enabled {
        if !is_tun_privilege_ready(state) {
            state.log_app_event(
                "warning",
                "虚拟网卡",
                if cfg!(target_os = "linux") {
                    "尝试开启虚拟网卡（TUN）但 Mihomo 内核尚未授予 cap_net_admin 权限，需执行 setcap 授权"
                } else if cfg!(target_os = "macos") {
                    "尝试开启虚拟网卡（TUN）但当前非管理员权限，请通过管理员终端启动应用或完成系统授权后再启用"
                } else {
                    "尝试开启虚拟网卡（TUN）但当前非管理员权限，需提权重启"
                },
            );
            return Err(tun_needs_admin_error_message());
        }

        if !has_enabled_nodes(state)? {
            return Err("暂无可用节点，请先导入订阅".to_string());
        }

        let mut cfg = old_cfg.clone();
        cfg.tun.enabled = true;
        config::save(&state.paths, &cfg).map_err(|e| format!("保存虚拟网卡配置失败：{e}"))?;
        if let Ok(mut guard) = state.config.write() {
            *guard = cfg.clone();
        }

        if !state.adapter.has_live_controller().await {
            if let Err(err) = start_core_internal(app, state).await {
                let mut rollback = state.snapshot_config();
                rollback.tun.enabled = old_tun_enabled;
                let _ = config::save(&state.paths, &rollback);
                if let Ok(mut guard) = state.config.write() {
                    *guard = rollback.clone();
                }
                state.log_app_event(
                    "error",
                    "虚拟网卡",
                    &format!("开启虚拟网卡并启动核心失败，已回滚：{err}"),
                );
                sync_app_side_effects(app, state, &rollback);
                return Err(format!("开启虚拟网卡并启动代理核心失败：{err}"));
            }
        } else {
            let reload_res = trigger_reload_if_running(app, state, true).await;
            let failed_detail = match reload_res {
                Some(outcome) if outcome.rejected => Some(
                    outcome
                        .error
                        .as_deref()
                        .map(format_mihomo_error_for_user)
                        .unwrap_or_else(|| "虚拟网卡配置重载未通过，已保持原状态".to_string()),
                ),
                None => Some("代理核心未响应，无法启用虚拟网卡".to_string()),
                _ => {
                    if !state.adapter.has_live_controller().await {
                        Some("核心重启以启用虚拟网卡后意外退出，请检查权限或 Wintun 组件".to_string())
                    } else {
                        None
                    }
                }
            };
            if let Some(detail) = failed_detail {
                let mut rollback = state.snapshot_config();
                rollback.tun.enabled = old_tun_enabled;
                let _ = config::save(&state.paths, &rollback);
                if let Ok(mut guard) = state.config.write() {
                    *guard = rollback.clone();
                }
                state.log_app_event(
                    "error",
                    "虚拟网卡",
                    &format!("开启虚拟网卡失败，已回滚配置：{detail}"),
                );
                sync_app_side_effects(app, state, &rollback);
                return Err(detail);
            }
        }

        let latest_cfg = state.snapshot_config();
        let now_core_running =
            state.snapshot_runtime().running || state.adapter.has_live_controller().await;
        let now_tun_active = now_core_running && effective_tun_enabled(state, &latest_cfg);
        coordinate_global_preaccel_on_tun_transition(
            app,
            state,
            &latest_cfg,
            was_tun_active,
            now_tun_active,
            "虚拟网卡（TUN）",
        )
        .await;

        state.log_app_event(
            "info",
            "虚拟网卡",
            &format!(
                "已开启虚拟网卡（TUN 协议栈：{}）",
                latest_cfg.tun.stack_mode.as_str()
            ),
        );
        let latest_cfg = state.snapshot_config();
        sync_app_side_effects(app, state, &latest_cfg);
        let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&latest_cfg));
        return Ok(true);
    }

    // Disabling TUN: gracefully release Wintun adapter & OS routes first (only if actually active), then save.
    if was_tun_active && state.adapter.has_live_controller().await {
        let _ = state.adapter.disable_tun_gracefully().await;
    }

    let mut cfg = state.snapshot_config();
    cfg.tun.enabled = false;
    config::save(&state.paths, &cfg).map_err(|e| format!("保存虚拟网卡配置失败：{e}"))?;
    if let Ok(mut guard) = state.config.write() {
        *guard = cfg.clone();
    }

    // Re-read latest config before deciding whether to stop the main core.
    let latest_before_stop = state.snapshot_config();
    if !latest_before_stop.system_proxy.enabled && !latest_before_stop.tun.enabled {
        let now_core_running =
            state.snapshot_runtime().running || state.adapter.has_live_controller().await;
        if now_core_running {
            stop_core_internal(app, state).await?;
            state.log_app_event(
                "info",
                "虚拟网卡",
                "已关闭虚拟网卡（TUN）并停止主代理核心（已释放监听端口与内存）",
            );
            return Ok(false);
        }
        coordinate_global_preaccel_on_tun_transition(
            app,
            state,
            &latest_before_stop,
            was_tun_active,
            false,
            "虚拟网卡（TUN）",
        )
        .await;
        state.log_app_event("info", "虚拟网卡", "已关闭虚拟网卡（TUN）");
        let latest_cfg = state.snapshot_config();
        sync_app_side_effects(app, state, &latest_cfg);
        let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&latest_cfg));
        return Ok(false);
    }

    if was_tun_active {
        if let Some(outcome) = trigger_reload_if_running(app, state, true).await {
            if outcome.rejected {
                let detail = outcome
                    .error
                    .as_deref()
                    .map(format_mihomo_error_for_user)
                    .unwrap_or_else(|| "关闭虚拟网卡时重载核心失败".to_string());
                state.log_app_event("error", "虚拟网卡", &format!("关闭虚拟网卡重载失败：{detail}"));
                return Err(detail);
            }
        }
    }

    let latest_cfg = state.snapshot_config();
    let now_core_running =
        state.snapshot_runtime().running || state.adapter.has_live_controller().await;
    let now_tun_active = now_core_running && effective_tun_enabled(state, &latest_cfg);
    coordinate_global_preaccel_on_tun_transition(
        app,
        state,
        &latest_cfg,
        was_tun_active,
        now_tun_active,
        "虚拟网卡（TUN）",
    )
    .await;

    state.log_app_event("info", "虚拟网卡", "已关闭虚拟网卡（TUN）");
    let latest_cfg = state.snapshot_config();
    sync_app_side_effects(app, state, &latest_cfg);
    let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&latest_cfg));
    Ok(false)
}

#[tauri::command]
pub async fn set_tun_enabled(
    app: AppHandle,
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<bool, String> {
    set_tun_enabled_internal(&app, &state, enabled).await
}

#[cfg(any(target_os = "windows", test))]
fn collect_relaunch_admin_args_with_flags(
    raw_args: &[std::ffi::OsString],
    fallback_data_dir: Option<&std::path::Path>,
    enable_tun: bool,
    enable_global_preaccel: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut has_data_dir = false;
    let mut i = 0usize;
    while i < raw_args.len() {
        let arg = raw_args[i].to_string_lossy();
        if arg == "--data-dir" {
            if let Some(val) = raw_args.get(i + 1) {
                let val_str = val.to_string_lossy().into_owned();
                if !val_str.trim().is_empty() {
                    out.push("--data-dir".to_string());
                    out.push(val_str);
                    has_data_dir = true;
                }
                i += 2;
                continue;
            }
        } else if let Some(rest) = arg.strip_prefix("--data-dir=") {
            if !rest.trim().is_empty() {
                out.push(arg.into_owned());
                has_data_dir = true;
            }
        }
        i += 1;
    }
    if !has_data_dir {
        if let Some(dir) = fallback_data_dir {
            let rendered = dir.to_string_lossy().into_owned();
            if !rendered.trim().is_empty() {
                out.push("--data-dir".to_string());
                out.push(rendered);
            }
        }
    }
    out.push("--restarting".to_string());
    if enable_tun {
        out.push("--enable-tun".to_string());
    }
    if enable_global_preaccel {
        out.push("--enable-global-preaccel".to_string());
    }
    out
}

#[cfg(test)]
fn collect_relaunch_admin_args(
    raw_args: &[std::ffi::OsString],
    fallback_data_dir: Option<&std::path::Path>,
    enable_tun: bool,
) -> Vec<String> {
    collect_relaunch_admin_args_with_flags(raw_args, fallback_data_dir, enable_tun, false)
}

#[tauri::command]
pub async fn relaunch_as_admin(
    app: AppHandle,
    state: State<'_, AppState>,
    enable_tun: Option<bool>,
) -> Result<bool, String> {
    let want_tun = enable_tun.unwrap_or(true);

    #[cfg(target_os = "linux")]
    {
        // On Linux, grant minimal `cap_net_admin,cap_net_bind_service` strictly to the Mihomo
        // binary via `pkexec setcap` instead of running the entire GUI process as root.
        let cfg = state.snapshot_config();
        let extra = state.extra_binary_candidates();
        let resolution = resolve_mihomo_binary(&cfg, &state.paths, &extra, false)
            .map_err(|e| format!("查找代理核心失败：{e}"))?;
        let binary_path = resolution.path.ok_or_else(|| {
            "未找到 Mihomo 代理核心文件，请先将内核放入 bin 目录或在设置中指定路径".to_string()
        })?;
        let bin_for_cap = binary_path.clone();
        let granted = tokio::task::spawn_blocking(move || {
            catcloud_core::platform::linux::grant_mihomo_tun_capability(&bin_for_cap)
        })
        .await
        .map_err(|e| format!("Linux TUN 授权任务异常中止：{e}"))?
        .map_err(|e| format!("为代理核心授予 Linux TUN 网络权限失败：{e}"))?;

        if !granted {
            state.log_app_event("warning", "提权", "用户取消了 Linux TUN 核心网络权限授权");
            return Ok(false);
        }

        state.log_app_event(
            "info",
            "提权",
            &format!(
                "已为代理核心授予 Linux TUN 网络权限（{}），桌面界面保持普通用户运行",
                binary_path.display()
            ),
        );

        if want_tun && has_enabled_nodes(&state).unwrap_or(false) {
            if let Err(err) = set_tun_enabled_internal(&app, &state, true).await {
                state.log_app_event(
                    "warning",
                    "虚拟网卡",
                    &format!("Linux 核心已获授权，但自动开启虚拟网卡失败：{err}"),
                );
                let latest_cfg = state.snapshot_config();
                sync_app_side_effects(&app, &state, &latest_cfg);
                let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&latest_cfg));
                return Err(err);
            }
        }

        let latest_cfg = state.snapshot_config();
        sync_app_side_effects(&app, &state, &latest_cfg);
        let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&latest_cfg));
        Ok(true)
    }

    #[cfg(target_os = "macos")]
    {
        let _ = (&app, &state, want_tun);
        Err(
            "macOS 暂不支持一键弹窗提权重启，请通过管理员终端启动猫猫云梯或在完成后续系统授权后启用虚拟网卡（TUN）"
                .to_string(),
        )
    }

    #[cfg(target_os = "windows")]
    {
        relaunch_self_with_elevation_flags(&app, &state, want_tun, false).await
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = (&app, &state, want_tun);
        Err("当前系统暂不支持一键管理员提权重启，请以具备网络管理权限的账户启动应用".to_string())
    }
}

#[cfg(target_os = "windows")]
async fn relaunch_self_with_elevation_flags(
    app: &AppHandle,
    state: &AppState,
    enable_tun: bool,
    enable_global_preaccel: bool,
) -> Result<bool, String> {
    let exe = std::env::current_exe().map_err(|e| format!("无法获取当前程序路径：{e}"))?;
    let workdir = exe
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| state.paths.root_data_dir.clone());
    let raw_args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let args = collect_relaunch_admin_args_with_flags(
        &raw_args,
        Some(&state.paths.root_data_dir),
        enable_tun,
        enable_global_preaccel,
    );

    let exe_clone = exe.clone();
    let workdir_clone = workdir.clone();
    let launched = tokio::task::spawn_blocking(move || {
        relaunch_self_as_admin(&exe_clone, &args, &workdir_clone)
    })
    .await
    .map_err(|e| format!("提权重启后台任务异常中止：{e}"))?
    .map_err(|e| format!("以管理员身份重启失败：{e}"))?;

    if !launched {
        // User cancelled the UAC elevation prompt: keep current process running untouched.
        state.log_app_event("warning", "提权", "用户取消了管理员权限提权重启");
        return Ok(false);
    }

    state.log_app_event(
        "info",
        "提权",
        "已以管理员身份拉起新实例，当前进程准备优雅退出并交接",
    );

    // Elevated replacement instance spawned successfully: release TUN, owned proxy, WebView
    // window handles, and single-instance lock before exiting cleanly.
    let app_exit = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Some(st) = app_exit.try_state::<AppState>() {
            st.shutting_down.store(true, Ordering::SeqCst);
            st.stop_streams();
            if st.global_preaccel.status().running {
                let _ = tokio::time::timeout(
                    Duration::from_millis(1200),
                    st.global_preaccel.stop(),
                )
                .await;
            }
            let cfg = st.snapshot_config();
            let may_have_tun = effective_tun_enabled(&st, &cfg)
                || cfg.rules_override.override_mode != OverrideMode::Disabled;
            if may_have_tun && st.adapter.has_live_controller().await {
                let _ = tokio::time::timeout(
                    Duration::from_millis(1200),
                    st.adapter.disable_tun_gracefully(),
                )
                .await;
            }
            let _ = clear_system_proxy_if_owned(&st);
        }
        lifecycle::enter_pure_windowless_mode(&app_exit);
        tokio::time::sleep(Duration::from_millis(250)).await;
        lifecycle::request_graceful_exit(&app_exit);
    });

    Ok(true)
}

#[tauri::command]
pub async fn switch_next_best_node(
    app: AppHandle,
    state: State<'_, AppState>,
    group_id: String,
) -> Result<SwitchResultDto, String> {
    switch_next_best_internal(&app, &state, group_id).await
}

#[tauri::command]
pub async fn select_group_node(
    app: AppHandle,
    state: State<'_, AppState>,
    group_id: String,
    node_id: String,
    close_old: Option<bool>,
) -> Result<SwitchResultDto, String> {
    select_group_node_internal(&app, &state, group_id, node_id, close_old, None).await
}

#[tauri::command]
pub async fn set_active_group(
    app: AppHandle,
    state: State<'_, AppState>,
    group_id: String,
) -> Result<CoreRuntimeInfoDto, String> {
    let _switching_guard = SwitchingActiveGuard::enter(&app, &state);
    let trimmed = group_id.trim().to_string();
    if trimmed.is_empty() {
        return Err("路线分组标识不能为空".to_string());
    }
    let group_name = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let Some(group) = db
            .get_multi_group(&trimmed)
            .map_err(|e| e.to_string())?
        else {
            return Err(format!("未找到指定路线分组（{trimmed}）"));
        };
        group.name
    };

    // Sanitize ghost active_node_id and auto-pick best healthy candidate before activating group.
    let reconciled = reconcile_group_best_node_internal(&app, &state, &trimmed, false, false).await?;

    let _cfg_guard = state.config_transition_lock.lock().await;
    let prev_cfg = state.snapshot_config();
    let was_single = prev_cfg.route_mode == RouteTargetMode::Single;
    let group_changed = prev_cfg.active_group_id.as_deref() != Some(trimmed.as_str());
    let changed = was_single || group_changed;

    let mut cfg = prev_cfg.clone();
    cfg.route_mode = RouteTargetMode::Group;
    cfg.active_group_id = Some(trimmed);
    config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
    if let Ok(mut guard) = state.config.write() {
        *guard = cfg.clone();
    }
    if changed {
        if let Some(outcome) = trigger_reload_if_running(&app, &state, was_single).await {
            if outcome.rejected {
                let _ = config::save(&state.paths, &prev_cfg);
                if let Ok(mut guard) = state.config.write() {
                    *guard = prev_cfg.clone();
                }
                sync_app_side_effects(&app, &state, &prev_cfg);
                let detail = outcome
                    .error
                    .as_deref()
                    .map(format_mihomo_error_for_user)
                    .unwrap_or_else(|| "未知原因".to_string());
                return Err(format!("切换活跃路线分组失败，核心配置重载未通过：{detail}"));
            }
        }
    } else if let Some(ref sw) = reconciled {
        if state.adapter.has_live_controller().await {
            let target_proxy =
                state.resolve_compiled_proxy_name(&sw.active_node_id, &sw.active_node_name);
            let _ = state
                .adapter
                .select_group_proxy(&group_name, &target_proxy)
                .await;
        }
    }
    if changed {
        state.log_app_event(
            "info",
            "路线组",
            &format!("已切换活跃路线分组至「{group_name}」"),
        );
    }
    sync_app_side_effects(&app, &state, &cfg);
    build_runtime_info_dto(&state)
}

#[tauri::command]
pub async fn select_single_node(
    app: AppHandle,
    state: State<'_, AppState>,
    node_id: String,
) -> Result<CoreRuntimeInfoDto, String> {
    select_single_node_internal(&app, &state, node_id).await
}

#[tauri::command]
pub fn toggle_capsule_window(app: AppHandle) -> Result<bool, String> {
    let was_open = lifecycle::window_mode_snapshot(&app).capsule_open;
    lifecycle::toggle_capsule_window(&app);
    Ok(!was_open)
}

#[tauri::command]
pub fn show_main_window(app: AppHandle) -> Result<(), String> {
    lifecycle::show_or_rebuild_main_window(&app);
    Ok(())
}

#[tauri::command]
pub fn enter_windowless_mode(app: AppHandle) -> Result<(), String> {
    lifecycle::enter_pure_windowless_mode(&app);
    Ok(())
}

/// Begin custom Win32 physical-coordinate dragging of the floating capsule window (no `HTCAPTION`,
/// zero Windows Aero Snap preview / maximize glitches, smooth across mixed-DPI multi-monitors).
#[tauri::command]
pub fn capsule_drag_start(app: AppHandle, state: State<'_, AppState>) -> Result<bool, String> {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::Foundation::{HWND, POINT, RECT};
        use windows_sys::Win32::UI::WindowsAndMessaging::{GetCursorPos, GetWindowRect, IsWindow};

        let Some(win) = app.get_webview_window(lifecycle::CAPSULE_WINDOW_LABEL) else {
            return Ok(false);
        };
        let Ok(raw_hwnd) = win.hwnd() else {
            return Ok(false);
        };
        let hwnd = raw_hwnd.0 as HWND;
        if hwnd.is_null() || unsafe { IsWindow(hwnd) == 0 } {
            return Ok(false);
        }

        let mut pt = POINT { x: 0, y: 0 };
        let mut rect = RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        // SAFETY: Valid HWND and stack-allocated Win32 structs.
        let ok = unsafe { GetCursorPos(&mut pt) != 0 && GetWindowRect(hwnd, &mut rect) != 0 };
        if !ok {
            return Ok(false);
        }
        let width = rect.right.saturating_sub(rect.left).max(1);
        let height = rect.bottom.saturating_sub(rect.top).max(1);
        let offset_x = pt.x.saturating_sub(rect.left);
        let offset_y = pt.y.saturating_sub(rect.top);
        let rx = ((offset_x as f64) / (width as f64)).clamp(0.0, 1.0);
        let ry = ((offset_y as f64) / (height as f64)).clamp(0.0, 1.0);

        let mut guard = state
            .capsule_drag
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *guard = Some(CapsuleDragAnchor {
            rx,
            ry,
            offset_x,
            offset_y,
            width,
            height,
        });
        Ok(true)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (&app, &state);
        Ok(false)
    }
}

/// Advance custom Win32 physical-coordinate dragging of the floating capsule window by one frame,
/// automatically rescaling the anchor offset if `WM_DPICHANGED` alters physical window dimensions
/// across mixed-DPI monitors.
#[tauri::command]
pub fn capsule_drag_step(app: AppHandle, state: State<'_, AppState>) -> Result<bool, String> {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::Foundation::{HWND, POINT, RECT};
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            GetCursorPos, GetWindowRect, IsWindow, SWP_NOACTIVATE, SWP_NOSIZE, SWP_NOZORDER,
            SetWindowPos,
        };

        let Some(win) = app.get_webview_window(lifecycle::CAPSULE_WINDOW_LABEL) else {
            return Ok(false);
        };
        let Ok(raw_hwnd) = win.hwnd() else {
            return Ok(false);
        };
        let hwnd = raw_hwnd.0 as HWND;
        if hwnd.is_null() || unsafe { IsWindow(hwnd) == 0 } {
            return Ok(false);
        }

        let mut pt = POINT { x: 0, y: 0 };
        let mut rect = RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        // SAFETY: Valid HWND and stack-allocated Win32 structs.
        let ok = unsafe { GetCursorPos(&mut pt) != 0 && GetWindowRect(hwnd, &mut rect) != 0 };
        if !ok {
            return Ok(false);
        }

        let cur_w = rect.right.saturating_sub(rect.left).max(1);
        let cur_h = rect.bottom.saturating_sub(rect.top).max(1);
        let next_pos = {
            let mut guard = state
                .capsule_drag
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let Some(anchor) = guard.as_mut() else {
                return Ok(false);
            };
            if cur_w != anchor.width || cur_h != anchor.height {
                anchor.width = cur_w;
                anchor.height = cur_h;
                anchor.offset_x = (anchor.rx * (cur_w as f64)).round() as i32;
                anchor.offset_y = (anchor.ry * (cur_h as f64)).round() as i32;
            }
            (
                pt.x.saturating_sub(anchor.offset_x),
                pt.y.saturating_sub(anchor.offset_y),
            )
        };

        if next_pos.0 == rect.left && next_pos.1 == rect.top {
            return Ok(true);
        }

        // SAFETY: Valid HWND; `SetWindowPos` moves in physical screen coordinates without
        // resizing, reordering, activating, or entering OS `HTCAPTION` Aero Snap modal loops.
        let moved = unsafe {
            SetWindowPos(
                hwnd,
                std::ptr::null_mut(),
                next_pos.0,
                next_pos.1,
                0,
                0,
                SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE,
            ) != 0
        };
        Ok(moved)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (&app, &state);
        Ok(false)
    }
}

/// Clear active custom floating capsule drag anchor state on pointer release / cancel.
#[tauri::command]
pub fn capsule_drag_end(state: State<'_, AppState>) -> Result<bool, String> {
    let mut guard = state
        .capsule_drag
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    *guard = None;
    #[cfg(target_os = "windows")]
    {
        Ok(true)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(false)
    }
}

#[tauri::command]
pub fn list_multi_groups(state: State<'_, AppState>) -> Result<Vec<MultiGroup>, String> {
    let health_pool = state.snapshot_node_health_pool();
    let now = Instant::now();
    let db = state.storage.lock().map_err(|e| e.to_string())?;
    let mut groups = db.list_multi_groups().map_err(|e| e.to_string())?;
    if let Ok(nodes) = db.list_nodes() {
        let node_ids: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
        for g in &mut groups {
            let needs_sanitize = match g.active_node_id.as_deref() {
                Some(aid) => !is_valid_group_member(g, aid, &nodes),
                None => !g.member_node_ids.is_empty(),
            };
            if needs_sanitize {
                let snaps = db
                    .get_probe_snapshots_batch(&node_ids, g.primary_probe_id.as_deref())
                    .unwrap_or_default();
                let _ = sanitize_group_active_node_with_runtime(
                    g,
                    &nodes,
                    &snaps,
                    Some(&health_pool),
                    now,
                );
            }
        }
    }
    Ok(groups)
}

#[tauri::command]
pub async fn upsert_multi_group(
    app: AppHandle,
    state: State<'_, AppState>,
    mut group: MultiGroup,
) -> Result<MultiGroup, String> {
    if group.id.trim().is_empty() {
        group.id = format!("grp-{}", uuid::Uuid::new_v4().simple());
    }
    catcloud_core::strategy::formula::validate_formula(&group.formula_expr)
        .map_err(|e| format!("分组排序公式无效：{e}"))?;
    let (prev_group, prev_active_id, prev_active_name, next_active_name) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let existing_group = db.get_multi_group(&group.id).map_err(|e| e.to_string())?;
        let existing_prev = existing_group
            .as_ref()
            .and_then(|g| g.active_node_id.clone())
            .or_else(|| group.active_node_id.clone());
        let nodes = db.list_nodes().map_err(|e| e.to_string())?;
        let node_ids: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
        let snaps = db
            .get_probe_snapshots_batch(&node_ids, group.primary_probe_id.as_deref())
            .unwrap_or_default();
        let prev_name = existing_prev
            .as_deref()
            .and_then(|id| nodes.iter().find(|n| n.id == id))
            .map(|n| n.name.clone());

        // Sanitize ghost active_node_id and re-pick best healthy candidate if current violates
        // updated hard gates/membership while preserving healthy in-group selection.
        let health_pool = state.snapshot_node_health_pool();
        let now = Instant::now();
        let _ = sanitize_group_active_node_with_runtime(
            &mut group,
            &nodes,
            &snaps,
            Some(&health_pool),
            now,
        );
        let _ = reconcile_group_best_node_in_memory_with_runtime(
            &mut group,
            &nodes,
            &snaps,
            Some(&health_pool),
            now,
        );

        let next_name = group
            .active_node_id
            .as_deref()
            .and_then(|id| nodes.iter().find(|n| n.id == id))
            .map(|n| n.name.clone());
        db.upsert_multi_group(&group).map_err(|e| e.to_string())?;
        (existing_group, existing_prev, prev_name, next_name)
    };
    if let Some(outcome) = trigger_reload_if_running(&app, &state, false).await {
        if outcome.rejected {
            if let Ok(db) = state.storage.lock() {
                match prev_group {
                    Some(ref old_group) => {
                        let _ = db.upsert_multi_group(old_group);
                    }
                    None => {
                        let _ = db.delete_multi_group(&group.id);
                    }
                }
            }
            let cfg = state.snapshot_config();
            sync_app_side_effects(&app, &state, &cfg);
            let detail = outcome
                .error
                .as_deref()
                .map(format_mihomo_error_for_user)
                .unwrap_or_else(|| "未知原因".to_string());
            return Err(format!(
                "保存路线分组「{}」失败，核心配置重载未通过：{detail}",
                group.name
            ));
        }
    }
    if group.active_node_id != prev_active_id && state.adapter.has_live_controller().await {
        if let Some(ref next_id) = group.active_node_id {
            let fallback = next_active_name.as_deref().unwrap_or(next_id.as_str());
            let target_proxy = state.resolve_compiled_proxy_name(next_id, fallback);
            let _ = state
                .adapter
                .select_group_proxy(&group.name, &target_proxy)
                .await;
        }
        if matches!(group.switch_mode, SwitchMode::ForceCloseOld)
            || prev_active_id
                .as_deref()
                .is_some_and(|pid| !group.member_node_ids.iter().any(|m| m == pid))
        {
            let prev_compiled = prev_active_id.as_deref().map(|pid| {
                let fb = prev_active_name.as_deref().unwrap_or("");
                state.resolve_compiled_proxy_name(pid, fb)
            });
            let prev_target = prev_compiled
                .as_deref()
                .filter(|s| !s.is_empty())
                .or(prev_active_name.as_deref());
            let _ = state
                .adapter
                .close_connections_for_group_or_node(Some(&group.name), prev_target)
                .await;
        }
    }
    let cfg = state.snapshot_config();
    sync_app_side_effects(&app, &state, &cfg);
    Ok(group)
}

#[tauri::command]
pub async fn delete_multi_group(
    app: AppHandle,
    state: State<'_, AppState>,
    group_id: String,
) -> Result<bool, String> {
    let (deleted, next_fallback_group_id) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let deleted = db.delete_multi_group(&group_id).map_err(|e| e.to_string())?;
        let next_id = if deleted {
            db.list_multi_groups()
                .ok()
                .and_then(|v| v.into_iter().next())
                .map(|g| g.id)
        } else {
            None
        };
        (deleted, next_id)
    };
    if deleted {
        if let Ok(mut pool) = state.node_health_pool.write() {
            pool.remove_group_cursor(&group_id);
        }
        let mut cfg = state.snapshot_config();
        if cfg.active_group_id.as_deref() == Some(group_id.as_str()) {
            cfg.active_group_id = next_fallback_group_id;
            config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
            if let Ok(mut guard) = state.config.write() {
                *guard = cfg.clone();
            }
        }
        let _ = trigger_reload_if_running(&app, &state, false).await;
        let latest_cfg = state.snapshot_config();
        emit_config_updated(&app, &latest_cfg);
        sync_app_side_effects(&app, &state, &latest_cfg);
    }
    Ok(deleted)
}

#[tauri::command]
pub async fn update_multi_group_members(
    app: AppHandle,
    state: State<'_, AppState>,
    group_id: String,
    member_node_ids: Vec<String>,
) -> Result<MultiGroup, String> {
    let (updated, prev_group, prev_active_id, prev_active_name, next_active_name) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let mut group = db
            .get_multi_group(&group_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("未找到指定路线分组（{group_id}）"))?;
        let prev_group = group.clone();
        let prev_active = group.active_node_id.clone();
        let nodes = db.list_nodes().map_err(|e| e.to_string())?;
        let node_ids: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
        let snaps = db
            .get_probe_snapshots_batch(&node_ids, group.primary_probe_id.as_deref())
            .unwrap_or_default();
        let prev_name = prev_active
            .as_deref()
            .and_then(|id| nodes.iter().find(|n| n.id == id))
            .map(|n| n.name.clone());

        group.member_node_ids = member_node_ids;
        let health_pool = state.snapshot_node_health_pool();
        let now = Instant::now();
        let _ = sanitize_group_active_node_with_runtime(
            &mut group,
            &nodes,
            &snaps,
            Some(&health_pool),
            now,
        );
        let _ = reconcile_group_best_node_in_memory_with_runtime(
            &mut group,
            &nodes,
            &snaps,
            Some(&health_pool),
            now,
        );

        let next_name = group
            .active_node_id
            .as_deref()
            .and_then(|id| nodes.iter().find(|n| n.id == id))
            .map(|n| n.name.clone());
        db.upsert_multi_group(&group).map_err(|e| e.to_string())?;
        (group, prev_group, prev_active, prev_name, next_name)
    };
    if let Some(outcome) = trigger_reload_if_running(&app, &state, false).await {
        if outcome.rejected {
            if let Ok(db) = state.storage.lock() {
                let _ = db.upsert_multi_group(&prev_group);
            }
            let cfg = state.snapshot_config();
            sync_app_side_effects(&app, &state, &cfg);
            let detail = outcome
                .error
                .as_deref()
                .map(format_mihomo_error_for_user)
                .unwrap_or_else(|| "未知原因".to_string());
            return Err(format!(
                "更新路线分组「{}」成员失败，核心配置重载未通过：{detail}",
                updated.name
            ));
        }
    }
    if updated.active_node_id != prev_active_id && state.adapter.has_live_controller().await {
        if let Some(ref next_id) = updated.active_node_id {
            let fallback = next_active_name.as_deref().unwrap_or(next_id.as_str());
            let target_proxy = state.resolve_compiled_proxy_name(next_id, fallback);
            let _ = state
                .adapter
                .select_group_proxy(&updated.name, &target_proxy)
                .await;
        }
        let prev_compiled = prev_active_id.as_deref().map(|pid| {
            let fb = prev_active_name.as_deref().unwrap_or("");
            state.resolve_compiled_proxy_name(pid, fb)
        });
        let prev_target = prev_compiled
            .as_deref()
            .filter(|s| !s.is_empty())
            .or(prev_active_name.as_deref());
        let _ = state
            .adapter
            .close_connections_for_group_or_node(Some(&updated.name), prev_target)
            .await;
    }
    let cfg = state.snapshot_config();
    sync_app_side_effects(&app, &state, &cfg);
    Ok(updated)
}

#[tauri::command]
pub fn list_nodes(state: State<'_, AppState>) -> Result<Vec<ProxyNode>, String> {
    let db = state.storage.lock().map_err(|e| e.to_string())?;
    db.list_nodes().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn set_nodes_preaccel_override(
    app: AppHandle,
    state: State<'_, AppState>,
    node_ids: Vec<String>,
    override_mode: String,
) -> Result<usize, String> {
    let parsed: Option<bool> = match override_mode.trim().to_ascii_lowercase().as_str() {
        "inherit" | "auto" | "default" => None,
        "force_on" | "on" | "true" => Some(true),
        "force_off" | "off" | "false" => Some(false),
        other => {
            return Err(format!(
                "不支持的提速覆写模式「{other}」（仅支持 inherit / force_on / force_off）"
            ))
        }
    };
    let count = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let mut changed = 0usize;
        for nid in &node_ids {
            if let Some(mut node) = db.get_node(nid).map_err(|e| e.to_string())? {
                node.preaccel_override = parsed;
                db.upsert_node(&node).map_err(|e| e.to_string())?;
                changed += 1;
            }
        }
        changed
    };
    if count > 0 {
        let _ = trigger_reload_if_running(&app, &state, false).await;
    }
    Ok(count)
}

#[tauri::command]
pub fn list_probe_definitions(state: State<'_, AppState>) -> Result<Vec<ProbeDefinition>, String> {
    let db = state.storage.lock().map_err(|e| e.to_string())?;
    db.list_probe_definitions().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn upsert_probe_definition(
    state: State<'_, AppState>,
    mut probe: ProbeDefinition,
) -> Result<ProbeDefinition, String> {
    if probe.id.trim().is_empty() {
        probe.id = format!("probe-{}", uuid::Uuid::new_v4().simple());
    }
    catcloud_core::probe::validate_definition(&probe).map_err(|e| e.to_string())?;
    let db = state.storage.lock().map_err(|e| e.to_string())?;
    db.upsert_probe_definition(&probe).map_err(|e| e.to_string())?;
    Ok(probe)
}

#[tauri::command]
pub fn delete_probe_definition(
    state: State<'_, AppState>,
    probe_id: String,
) -> Result<bool, String> {
    let db = state.storage.lock().map_err(|e| e.to_string())?;
    db.delete_probe_definition(&probe_id).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn list_probe_snapshots(
    state: State<'_, AppState>,
) -> Result<HashMap<String, ProbeSnapshot>, String> {
    let db = state.storage.lock().map_err(|e| e.to_string())?;
    let nodes = db.list_nodes().map_err(|e| e.to_string())?;
    let ids: Vec<String> = nodes.into_iter().map(|n| n.id).collect();
    db.get_probe_snapshots_batch(&ids, None)
        .map_err(|e| e.to_string())
}

struct ProbeRunningGuard {
    running: Arc<AtomicBool>,
    cancel_tx: Arc<Mutex<Option<tokio::sync::watch::Sender<bool>>>>,
    app: AppHandle,
}

impl ProbeRunningGuard {
    fn enter(app: &AppHandle, state: &AppState) -> Self {
        emit_runtime_snapshot(app, state);
        let _ = tray::sync_tray_visual(app, &build_tray_visual_state(state));
        Self {
            running: Arc::clone(&state.probe_running),
            cancel_tx: Arc::clone(&state.probe_cancel_tx),
            app: app.clone(),
        }
    }
}

impl Drop for ProbeRunningGuard {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.cancel_tx.lock() {
            *guard = None;
        }
        self.running.store(false, Ordering::SeqCst);
        if let Some(st) = self.app.try_state::<AppState>() {
            emit_runtime_snapshot(&self.app, &st);
            let _ = tray::sync_tray_visual(&self.app, &build_tray_visual_state(&st));
        }
    }
}

#[tauri::command]
pub fn cancel_isolated_probes(state: State<'_, AppState>) -> Result<bool, String> {
    let was_running = state.probe_running.load(Ordering::SeqCst);
    if let Ok(guard) = state.probe_cancel_tx.lock() {
        if let Some(ref tx) = *guard {
            let _ = tx.send(true);
        }
    }
    Ok(was_running)
}

#[tauri::command]
pub async fn run_isolated_probes(
    app: AppHandle,
    state: State<'_, AppState>,
    node_ids: Vec<String>,
    probe_ids: Vec<String>,
    max_tier: Option<String>,
    include_keepalive: Option<bool>,
    use_preaccel: Option<bool>,
) -> Result<serde_json::Value, String> {
    let (cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);
    if state
        .probe_running
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("已有测速任务正在进行，请先暂停或等待完成".to_string());
    }
    if let Ok(mut guard) = state.probe_cancel_tx.lock() {
        *guard = Some(cancel_tx);
    }
    let _running_guard = ProbeRunningGuard::enter(&app, &state);

    let cfg = state.snapshot_config();
    let extra_candidates = state.extra_binary_candidates();
    let resolution = resolve_mihomo_binary(&cfg, &state.paths, &extra_candidates, false)
        .map_err(|e| format!("查找代理核心失败：{e}"))?;
    let Some(mihomo_bin) = resolution.path else {
        return Err("未找到 Mihomo 内核文件，无法执行后台测速".to_string());
    };

    let resolved_tier = match max_tier
        .as_deref()
        .map(str::trim)
        .unwrap_or("full")
        .to_ascii_lowercase()
        .as_str()
    {
        "latency" | "fast" | "l0" => FunnelTier::L0Connectivity,
        "unlock" | "clean" | "lite" | "l1" => FunnelTier::L1CleanAndUnlock,
        _ => FunnelTier::L2ThroughputAndKeepalive,
    };
    let keepalive_enabled = include_keepalive.unwrap_or(false);
    let want_preaccel = use_preaccel.unwrap_or(cfg.preaccel.enabled);

    let (target_nodes, probe_defs, active_relay) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let all_nodes = db.list_nodes().map_err(|e| e.to_string())?;
        let target_nodes: Vec<ProxyNode> = if node_ids.is_empty() {
            all_nodes.into_iter().filter(|n| n.enabled).collect()
        } else {
            let id_map: HashMap<&str, &ProxyNode> =
                all_nodes.iter().map(|n| (n.id.as_str(), n)).collect();
            node_ids
                .iter()
                .filter_map(|id| id_map.get(id.as_str()).map(|n| (*n).clone()))
                .collect()
        };
        let all_defs = db.list_probe_definitions().map_err(|e| e.to_string())?;
        let selected_defs: Vec<ProbeDefinition> = if probe_ids.is_empty() {
            all_defs
        } else {
            all_defs
                .into_iter()
                .filter(|d| probe_ids.contains(&d.id))
                .collect()
        };
        let filtered_defs: Vec<ProbeDefinition> = selected_defs
            .into_iter()
            .filter(|d| keepalive_enabled || d.kind != catcloud_core::models::ProbeKind::Keepalive)
            .collect();
        let active_relay = if want_preaccel {
            let enabled_relays = db.list_preaccel_relays(true).unwrap_or_default();
            cfg.preaccel
                .active_relay_id
                .as_deref()
                .and_then(|aid| enabled_relays.iter().find(|r| r.id == aid).cloned())
                .or_else(|| enabled_relays.into_iter().next())
                .filter(|r| !r.server.trim().is_empty() && r.port > 0)
        } else {
            None
        };
        (target_nodes, filtered_defs, active_relay)
    };

    let used_preaccel = active_relay.is_some();
    let preaccel_relay_name = active_relay.as_ref().map(|r| r.name.clone());

    if target_nodes.is_empty() {
        return Err("请先选择至少一个节点后再开始测速".to_string());
    }
    if probe_defs.is_empty() {
        return Err("当前没有可用的测速项目".to_string());
    }

    let mut registry = ProbeRegistry::new();
    for def in probe_defs {
        registry.register(def).map_err(|e| e.to_string())?;
    }
    let registry = Arc::new(registry);

    let temp_root = state.paths.runtime_dir.join("probe_sandbox");
    std::fs::create_dir_all(&temp_root).map_err(|e| e.to_string())?;

    let options = Arc::new(FunnelOptions {
        max_tier: resolved_tier,
        ..FunnelOptions::default()
    });

    let total_count = target_nodes.len();
    let mut completed_count: usize = 0;
    let mut cancelled = false;
    let mut snapshots: HashMap<String, ProbeSnapshot> = HashMap::new();
    let mut errors: Vec<String> = Vec::new();
    state.log_app_event(
        "info",
        "后台测速",
        &format!(
            "开始后台测速：目标节点 {} 个，档位 {}，国内提速 {}",
            total_count,
            max_tier.as_deref().unwrap_or("full"),
            if used_preaccel {
                preaccel_relay_name.as_deref().unwrap_or("已开启")
            } else {
                "关闭"
            }
        ),
    );

    const BATCH_SIZE: usize = 12;
    const CONCURRENCY: usize = 4;

    for chunk in target_nodes.chunks(BATCH_SIZE) {
        if *cancel_rx.borrow() {
            cancelled = true;
            break;
        }

        let probe_core = match tokio::select! {
            biased;
            _ = cancel_rx.wait_for(|&c| c) => Err("cancelled".to_string()),
            res = IsolatedProbeCore::spawn_with_preaccel(
                &mihomo_bin,
                &temp_root,
                &state.job_guard,
                chunk,
                active_relay.as_ref(),
                cfg.preaccel.skip_443_native,
            ) => {
                res.map_err(|e| e.to_string())
            }
        } {
            Ok(core) => core,
            Err(err) if err == "cancelled" => {
                cancelled = true;
                break;
            }
            Err(err) => {
                errors.push(format!("后台测速核心启动失败：{err}"));
                break;
            }
        };

        let sem = Arc::new(tokio::sync::Semaphore::new(CONCURRENCY));
        let (tx, mut rx) = tokio::sync::mpsc::channel::<(
            String,
            String,
            Result<catcloud_core::probe::FunnelRunReport, String>,
        )>(chunk.len().max(1));

        let mut spawned = 0usize;
        let mut join_handles = Vec::with_capacity(chunk.len());
        for node in chunk {
            let Some(port) = probe_core.port_for_node(&node.id) else {
                continue;
            };
            spawned += 1;
            let sem_ref = Arc::clone(&sem);
            let reg_ref = Arc::clone(&registry);
            let opt_ref = Arc::clone(&options);
            let job_ref = Arc::clone(&state.job_guard);
            let mut worker_cancel_rx = cancel_rx.clone();
            let tx_ref = tx.clone();
            let nid = node.id.clone();
            let nname = node.name.clone();

            join_handles.push(tokio::spawn(async move {
                let permit = tokio::select! {
                    biased;
                    _ = worker_cancel_rx.wait_for(|&c| c) => return,
                    p = sem_ref.acquire_owned() => match p {
                        Ok(p) => p,
                        Err(_) => return,
                    }
                };
                if *worker_cancel_rx.borrow() {
                    drop(permit);
                    return;
                }
                let res = tokio::select! {
                    biased;
                    _ = worker_cancel_rx.wait_for(|&c| c) => {
                        drop(permit);
                        return;
                    }
                    r = run_funnel_for_node(&reg_ref, &nid, port, &opt_ref, Some(&job_ref), None) => {
                        r.map_err(|e| e.to_string())
                    }
                };
                drop(permit);
                let _ = tx_ref.send((nid, nname, res)).await;
            }));
        }
        drop(tx);

        let mut batch_received = 0usize;
        while batch_received < spawned {
            let recv_item = tokio::select! {
                biased;
                _ = cancel_rx.wait_for(|&c| c) => {
                    cancelled = true;
                    break;
                }
                item = rx.recv() => item,
            };
            let Some((nid, nname, outcome)) = recv_item else {
                cancelled |= *cancel_rx.borrow();
                break;
            };
            batch_received += 1;
            completed_count += 1;

            match outcome {
                Ok(report) => {
                    // Persist new probe records then read back the merged full snapshot from SQLite
                    // so fast latency checks never wipe previously measured upload/download/unlock data.
                    let snap = if let Ok(mut db) = state.storage.lock() {
                        if !report.records.is_empty() {
                            let _ = db.insert_probe_results_batch(&report.records);
                        }
                        db.get_probe_snapshot(&nid, None)
                            .ok()
                            .flatten()
                            .unwrap_or(report.snapshot)
                    } else {
                        report.snapshot
                    };
                    if snap.ok {
                        if let Some(ms) = snap.latency_ms.filter(|v| v.is_finite() && *v > 0.0) {
                            state.reset_node_health(&nid);
                            state.record_node_health_probe(
                                &nid,
                                RuntimeDualHealth::FullHealthy,
                                Some(ms),
                            );
                        }
                    } else {
                        state.reset_node_health(&nid);
                    }
                    snapshots.insert(nid.clone(), snap.clone());
                    let _ = app.emit(
                        EVENT_PROBE_PROGRESS,
                        serde_json::json!({
                            "node_id": nid,
                            "node_name": nname,
                            "completed": completed_count,
                            "total": total_count,
                            "cancelled": false,
                            "done": false,
                            "snapshot": snap,
                            "error": null
                        }),
                    );
                }
                Err(err) => {
                    errors.push(format!("{nname}: {err}"));
                    let _ = app.emit(
                        EVENT_PROBE_PROGRESS,
                        serde_json::json!({
                            "node_id": nid,
                            "node_name": nname,
                            "completed": completed_count,
                            "total": total_count,
                            "cancelled": false,
                            "done": false,
                            "snapshot": null,
                            "error": err
                        }),
                    );
                }
            }

            if *cancel_rx.borrow() {
                cancelled = true;
                break;
            }
        }

        if cancelled {
            for h in &join_handles {
                h.abort();
            }
            let _ = tokio::time::timeout(Duration::from_millis(150), async {
                for h in join_handles {
                    let _ = h.await;
                }
            })
            .await;
        } else {
            for h in join_handles {
                let _ = h.await;
            }
        }
        let _ = probe_core.shutdown().await;
        if cancelled {
            break;
        }
    }

    let _ = app.emit(
        EVENT_PROBE_PROGRESS,
        serde_json::json!({
            "node_id": null,
            "node_name": null,
            "completed": completed_count,
            "total": total_count,
            "cancelled": cancelled,
            "done": true,
            "snapshot": null,
            "error": null
        }),
    );

    // Engage strategy engine immediately after fresh probe snapshots are persisted:
    // only reconcile when in Group route mode and the target group is in the active compiled set,
    // so Single-node mode or pruned inactive groups never emit phantom switch toasts.
    let latest_cfg = state.snapshot_config();
    if !snapshots.is_empty() && latest_cfg.route_mode == RouteTargetMode::Group {
        let core_running = state.snapshot_runtime().running;
        let compiled_group_ids = if core_running {
            let existing = state.snapshot_compiled_group_ids();
            if existing.is_some() {
                existing
            } else {
                refresh_node_proxy_name_map(&state);
                state.snapshot_compiled_group_ids()
            }
        } else {
            None
        };
        let target_group_ids: Vec<String> = state
            .storage
            .lock()
            .ok()
            .and_then(|db| db.list_multi_groups().ok())
            .map(|groups| {
                select_reconcilable_active_group_ids(
                    &latest_cfg,
                    &groups,
                    compiled_group_ids.as_ref(),
                )
            })
            .unwrap_or_default();

        for gid in target_group_ids {
            let _ =
                reconcile_group_best_node_internal(&app, &state, &gid, core_running, core_running)
                    .await;
        }
    }

    let latest_cfg = state.snapshot_config();
    sync_app_side_effects(&app, &state, &latest_cfg);

    let ok_count = snapshots.values().filter(|s| s.ok).count();
    let status_text = if cancelled { "已手动取消" } else { "已完成" };
    let summary_level = if errors.is_empty() { "info" } else { "warning" };
    state.log_app_event(
        summary_level,
        "后台测速",
        &format!(
            "后台测速{status_text}：完成 {completed_count}/{total_count}，可用 {ok_count} 个，异常 {} 条",
            errors.len()
        ),
    );

    Ok(serde_json::json!({
        "probed_count": snapshots.len(),
        "total_count": total_count,
        "cancelled": cancelled,
        "snapshots": snapshots,
        "errors": errors,
        "core_available": true,
        "used_preaccel": used_preaccel,
        "preaccel_relay_name": preaccel_relay_name
    }))
}

fn prune_wallpaper_cache(cache_dir: &std::path::Path, max_files: usize) {
    let Ok(entries) = std::fs::read_dir(cache_dir) else {
        return;
    };
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            if !path.is_file() {
                return None;
            }
            let name = path.file_name()?.to_str()?;
            if !name.starts_with("wp_") || !name.ends_with(".jpg") {
                return None;
            }
            let modified = entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .unwrap_or(std::time::UNIX_EPOCH);
            Some((modified, path))
        })
        .collect();
    if files.len() <= max_files {
        return;
    }
    files.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, old_path) in files.into_iter().skip(max_files) {
        let _ = std::fs::remove_file(old_path);
    }
}

fn encode_wallpaper_data_url_from_path(
    raw_path: &str,
    cache_dir: &std::path::Path,
) -> Result<String, String> {
    let trimmed = raw_path.trim();
    if trimmed.is_empty() {
        return Err("壁纸图片路径不能为空".to_string());
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return Ok(trimmed.to_string());
    }
    if lower.starts_with("data:") {
        const ALLOWED_BITMAP_PREFIXES: &[&str] = &[
            "data:image/png;",
            "data:image/png,",
            "data:image/jpeg;",
            "data:image/jpeg,",
            "data:image/jpg;",
            "data:image/jpg,",
            "data:image/webp;",
            "data:image/webp,",
            "data:image/gif;",
            "data:image/gif,",
            "data:image/bmp;",
            "data:image/bmp,",
        ];
        if ALLOWED_BITMAP_PREFIXES.iter().any(|p| lower.starts_with(p)) {
            return Ok(trimmed.to_string());
        }
        return Err(
            "不支持的图片数据格式：仅允许 PNG/JPEG/WebP/GIF/BMP 位图，已拒绝 SVG 等非位图数据"
                .to_string(),
        );
    }
    let src_path = PathBuf::from(trimmed);
    if !src_path.is_file() {
        return Err(format!("找不到壁纸图片：{trimmed}"));
    }
    let meta = std::fs::metadata(&src_path).map_err(|e| format!("无法读取壁纸文件：{e}"))?;
    if meta.len() > 32 * 1024 * 1024 {
        return Err("壁纸图片超过 32 MB 上限，请选择更轻量的图片".to_string());
    }
    let mtime_secs = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(trimmed.as_bytes());
    hasher.update(mtime_secs.to_le_bytes());
    hasher.update(meta.len().to_le_bytes());
    let key = hex::encode(hasher.finalize());
    let cached_jpg = cache_dir.join(format!("wp_{}.jpg", &key[..16]));

    if cached_jpg.is_file() {
        if let Ok(bytes) = std::fs::read(&cached_jpg) {
            let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
            return Ok(format!("data:image/jpeg;base64,{b64}"));
        }
    }

    let mut reader = image::ImageReader::open(&src_path)
        .map_err(|e| format!("无法打开壁纸图片：{e}"))?
        .with_guessed_format()
        .map_err(|e| format!("无法识别壁纸图片格式：{e}"))?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(8192);
    limits.max_image_height = Some(8192);
    limits.max_alloc = Some(128 * 1024 * 1024);
    reader.limits(limits);
    let img = reader
        .decode()
        .map_err(|e| format!("无法解析图片格式（或超出 8192×8192 / 128 MiB 安全上限）：{e}"))?;

    let resized = if img.width() > 1920 || img.height() > 1920 {
        img.thumbnail(1920, 1920)
    } else {
        img
    };

    let rgb = if resized.color().has_alpha() {
        // Composite transparent pixels over a warm neutral cream matte (#F7F2EA)
        // so transparent PNG/WebP wallpapers never turn solid black in JPEG output.
        const BG_R: u32 = 247;
        const BG_G: u32 = 242;
        const BG_B: u32 = 234;
        let rgba = resized.to_rgba8();
        let (w, h) = rgba.dimensions();
        let mut out = image::RgbImage::new(w, h);
        for (x, y, px) in rgba.enumerate_pixels() {
            let a = u32::from(px[3]);
            let inv = 255 - a;
            let r = ((u32::from(px[0]) * a + BG_R * inv + 127) / 255) as u8;
            let g = ((u32::from(px[1]) * a + BG_G * inv + 127) / 255) as u8;
            let b = ((u32::from(px[2]) * a + BG_B * inv + 127) / 255) as u8;
            out.put_pixel(x, y, image::Rgb([r, g, b]));
        }
        out
    } else {
        resized.to_rgb8()
    };

    let mut out_bytes = Vec::new();
    let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out_bytes, 86);
    encoder
        .encode_image(&rgb)
        .map_err(|e| format!("壁纸编码失败：{e}"))?;

    let _ = std::fs::create_dir_all(cache_dir);
    let tmp_jpg = cache_dir.join(format!(
        "wp_{}.{}.tmp",
        &key[..16],
        uuid::Uuid::new_v4().simple()
    ));
    if std::fs::write(&tmp_jpg, &out_bytes).is_ok() {
        #[cfg(target_os = "windows")]
        {
            if cached_jpg.exists() {
                let _ = std::fs::remove_file(&cached_jpg);
            }
        }
        if std::fs::rename(&tmp_jpg, &cached_jpg).is_err() {
            let _ = std::fs::remove_file(&tmp_jpg);
        } else {
            prune_wallpaper_cache(cache_dir, 16);
        }
    }

    let b64 = base64::engine::general_purpose::STANDARD.encode(&out_bytes);
    Ok(format!("data:image/jpeg;base64,{b64}"))
}

#[tauri::command]
pub async fn pick_wallpaper_image(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    use tauri_plugin_dialog::DialogExt;

    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_title("选择背景壁纸图片")
        .add_filter("图片文件", &["png", "jpg", "jpeg", "webp"])
        .pick_file(move |file_path| {
            let _ = tx.send(file_path);
        });

    let picked = rx.await.map_err(|_| "文件选择已取消".to_string())?;
    let Some(file_path) = picked else {
        return Ok(serde_json::json!({
            "cancelled": true,
            "path": null,
            "data_url": null
        }));
    };
    let path_buf = file_path
        .into_path()
        .map_err(|e| format!("无法获取所选图片路径：{e}"))?;
    let path_str = path_buf.display().to_string();
    let path_for_encode = path_str.clone();
    let cache_dir = state.paths.root_data_dir.join("wallpaper_cache");
    let data_url = tokio::task::spawn_blocking(move || {
        encode_wallpaper_data_url_from_path(&path_for_encode, &cache_dir)
    })
    .await
    .map_err(|e| format!("壁纸后台解码任务异常中止：{e}"))??;

    let mut cfg = state.snapshot_config();
    cfg.personalization.wallpaper_path = Some(path_str.clone());
    config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
    if let Ok(mut guard) = state.config.write() {
        *guard = cfg.clone();
    }
    sync_app_side_effects(&app, &state, &cfg);

    Ok(serde_json::json!({
        "cancelled": false,
        "path": path_str,
        "data_url": data_url
    }))
}

#[tauri::command]
pub async fn resolve_wallpaper_data_url(
    state: State<'_, AppState>,
    path: String,
) -> Result<Option<String>, String> {
    let trimmed = path.trim().to_string();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let cache_dir = state.paths.root_data_dir.join("wallpaper_cache");
    let url = tokio::task::spawn_blocking(move || {
        encode_wallpaper_data_url_from_path(&trimmed, &cache_dir)
    })
    .await
    .map_err(|e| format!("壁纸后台解码任务异常中止：{e}"))??;
    Ok(Some(url))
}

#[tauri::command]
pub fn list_subscriptions(state: State<'_, AppState>) -> Result<Vec<SubscriptionRecord>, String> {
    let db = state.storage.lock().map_err(|e| e.to_string())?;
    db.list_subscriptions().map_err(|e| e.to_string())
}

fn unwrap_clash_subscription_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let parsed = reqwest::Url::parse(trimmed).ok()?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    if !matches!(scheme.as_str(), "clash" | "clashmeta" | "mihomo") {
        return None;
    }
    for (k, v) in parsed.query_pairs() {
        if k.eq_ignore_ascii_case("url") {
            let candidate = v.trim();
            let lower = candidate.to_ascii_lowercase();
            if lower.starts_with("http://") || lower.starts_with("https://") {
                return Some(candidate.to_string());
            }
        }
    }
    None
}

fn normalize_subscription_url_for_dedup(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let effective = unwrap_clash_subscription_url(trimmed).unwrap_or_else(|| trimmed.to_string());
    let eff_trimmed = effective.trim();
    if let Ok(mut parsed) = reqwest::Url::parse(eff_trimmed) {
        parsed.set_fragment(None);
        return Some(parsed.to_string());
    }
    if let Some((scheme, rest)) = eff_trimmed.split_once("://") {
        let (host_port, tail) = match rest.find(['/', '?', '#']) {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, ""),
        };
        let tail_no_frag = tail.split('#').next().unwrap_or(tail);
        return Some(format!(
            "{}://{}{}",
            scheme.to_ascii_lowercase(),
            host_port.to_ascii_lowercase(),
            tail_no_frag
        ));
    }
    Some(eff_trimmed.to_string())
}

fn upsert_subscription_in_storage(
    db: &Storage,
    mut record: SubscriptionRecord,
) -> Result<SubscriptionRecord, String> {
    let requested_id = record.id.trim().to_string();
    if record.kind == SubscriptionKind::Url {
        let trimmed_url = record.url_or_cmd.trim().to_string();
        record.url_or_cmd = unwrap_clash_subscription_url(&trimmed_url).unwrap_or(trimmed_url);
    }

    let existing_by_id = if requested_id.is_empty() {
        None
    } else {
        db.get_subscription(&requested_id)
            .map_err(|e| e.to_string())?
    };

    if existing_by_id.is_some() {
        // Explicit update of an existing subscription ID: update in place without cross-ID merging.
        record.id = requested_id;
        db.upsert_subscription(&record).map_err(|e| e.to_string())?;
        return Ok(record);
    }

    // New or empty ID for a URL subscription: deduplicate by normalized URL to prevent duplicate
    // subscriptions and doubled nodes.
    if record.kind == SubscriptionKind::Url {
        if let Some(target_key) = normalize_subscription_url_for_dedup(&record.url_or_cmd) {
            let existing_subs = db.list_subscriptions().map_err(|e| e.to_string())?;
            if let Some(matched) = existing_subs.into_iter().find(|s| {
                s.kind == SubscriptionKind::Url
                    && normalize_subscription_url_for_dedup(&s.url_or_cmd).as_deref()
                        == Some(target_key.as_str())
            }) {
                record.id = matched.id;
                if record.name.trim().is_empty() {
                    record.name = matched.name;
                }
                if record.traffic_total_bytes == 0 && record.traffic_used_bytes == 0 {
                    record.traffic_used_bytes = matched.traffic_used_bytes;
                    record.traffic_total_bytes = matched.traffic_total_bytes;
                }
                if record.expires_at.is_none() {
                    record.expires_at = matched.expires_at;
                }
                if record.etag.is_none() {
                    record.etag = matched.etag;
                }
                if record.last_ok_at.is_none() {
                    record.last_ok_at = matched.last_ok_at;
                }
                if record.last_error.is_none() {
                    record.last_error = matched.last_error;
                }
                db.upsert_subscription(&record).map_err(|e| e.to_string())?;
                return Ok(record);
            }
        }
    }

    if requested_id.is_empty() {
        record.id = format!("sub-{}", uuid::Uuid::new_v4().simple());
    } else {
        record.id = requested_id;
    }
    db.upsert_subscription(&record).map_err(|e| e.to_string())?;
    Ok(record)
}

#[tauri::command]
pub fn upsert_subscription(
    app: AppHandle,
    state: State<'_, AppState>,
    record: SubscriptionRecord,
) -> Result<SubscriptionRecord, String> {
    let saved = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        upsert_subscription_in_storage(&db, record)?
    };
    let created_default_group = ensure_default_group_if_empty(&state);
    let cfg = state.snapshot_config();
    if created_default_group {
        emit_config_updated(&app, &cfg);
    }
    sync_app_side_effects(&app, &state, &cfg);
    Ok(saved)
}

#[tauri::command]
pub async fn delete_subscription(
    app: AppHandle,
    state: State<'_, AppState>,
    sub_id: String,
) -> Result<bool, String> {
    let deleted = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        db.delete_subscription(&sub_id).map_err(|e| e.to_string())?
    };
    if deleted {
        prune_node_health_pool_from_db(&state);
        let _ = trigger_reload_if_running(&app, &state, false).await;
        let cfg = state.snapshot_config();
        sync_app_side_effects(&app, &state, &cfg);
    }
    Ok(deleted)
}

fn parse_subscription_update_mode(raw: &str) -> Result<SubscriptionUpdateMode, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "replace_latest" => Ok(SubscriptionUpdateMode::ReplaceLatest),
        "merge_dedup" => Ok(SubscriptionUpdateMode::MergeDedup),
        other => Err(format!(
            "不支持的节点更新方式 `{other}`，仅支持 `replace_latest` 或 `merge_dedup`"
        )),
    }
}

/// Synchronize `AppConfig.active_single_node_id` whenever subscription node updates or merges
/// remap deduplicated node IDs or remove stale nodes.
fn remap_active_single_node_id_if_needed(
    state: &AppState,
    id_remap: &HashMap<String, String>,
) -> Result<bool, String> {
    let mut cfg = state.snapshot_config();
    let Some(current_id) = cfg
        .active_single_node_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
    else {
        return Ok(false);
    };

    let next_id = if let Some(remapped) = id_remap.get(&current_id) {
        Some(remapped.clone())
    } else {
        let still_exists = state
            .storage
            .lock()
            .ok()
            .and_then(|db| db.get_node(&current_id).ok())
            .flatten()
            .is_some();
        if still_exists {
            return Ok(false);
        }
        state
            .storage
            .lock()
            .ok()
            .and_then(|db| db.list_nodes().ok())
            .and_then(|nodes| {
                nodes
                    .iter()
                    .find(|n| n.enabled)
                    .or_else(|| nodes.first())
                    .map(|n| n.id.clone())
            })
    };

    if cfg.active_single_node_id == next_id {
        return Ok(false);
    }
    cfg.active_single_node_id = next_id;
    config::save(&state.paths, &cfg).map_err(|e| format!("保存配置失败：{e}"))?;
    if let Ok(mut guard) = state.config.write() {
        *guard = cfg;
    }
    state.bump_config_generation();
    Ok(true)
}

#[tauri::command]
pub async fn rename_subscription(
    app: AppHandle,
    state: State<'_, AppState>,
    sub_id: String,
    new_name: String,
) -> Result<SubscriptionRecord, String> {
    let updated = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        db.rename_subscription(&sub_id, &new_name)
            .map_err(|e| e.to_string())?
    };
    state.log_app_event(
        "info",
        "订阅",
        &format!("已将订阅组重命名为「{}」", updated.name),
    );
    let cfg = state.snapshot_config();
    sync_app_side_effects(&app, &state, &cfg);
    emit_config_updated(&app, &cfg);
    Ok(updated)
}

#[tauri::command]
pub async fn apply_nodes_to_existing_subscription(
    app: AppHandle,
    state: State<'_, AppState>,
    target_sub_id: String,
    nodes: Vec<ProxyNode>,
    mode: String,
) -> Result<SubscriptionNodesUpdateResult, String> {
    let update_mode = parse_subscription_update_mode(&mode)?;
    let outcome = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        db.update_subscription_nodes_with_mode(&target_sub_id, &nodes, update_mode)
            .map_err(|e| e.to_string())?
    };
    let _ = remap_active_single_node_id_if_needed(&state, &outcome.id_remap)?;
    prune_node_health_pool_from_db(&state);
    let _ = ensure_default_group_if_empty(&state);
    let _ = trigger_reload_if_running(&app, &state, false).await;
    state.log_app_event(
        "info",
        "订阅",
        &format!(
            "已按 {} 模式更新已有订阅组：保留 {} 个，新增 {} 个，替换/更新 {} 个，当前共 {} 个节点",
            mode.trim(),
            outcome.kept_count,
            outcome.added_count,
            outcome.replaced_count,
            outcome.total_count
        ),
    );
    let cfg = state.snapshot_config();
    emit_config_updated(&app, &cfg);
    sync_app_side_effects(&app, &state, &cfg);
    Ok(outcome)
}

#[tauri::command]
pub async fn merge_subscriptions(
    app: AppHandle,
    state: State<'_, AppState>,
    source_sub_id: String,
    target_sub_id: String,
    new_target_name: Option<String>,
    deduplicate: Option<bool>,
    convert_target_to_migrated: Option<bool>,
) -> Result<MergeSubscriptionsResult, String> {
    let clean_name = new_target_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let outcome = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        db.merge_subscriptions(
            &source_sub_id,
            &target_sub_id,
            clean_name.as_deref(),
            deduplicate.unwrap_or(true),
            convert_target_to_migrated.unwrap_or(false),
        )
        .map_err(|e| e.to_string())?
    };
    let _ = remap_active_single_node_id_if_needed(&state, &outcome.id_remap)?;
    prune_node_health_pool_from_db(&state);
    let _ = trigger_reload_if_running(&app, &state, false).await;
    state.log_app_event(
        "info",
        "订阅",
        &format!(
            "已整合合并订阅组：迁入 {} 个节点，去重 {} 个，合并后目标组共 {} 个节点",
            outcome.moved_count, outcome.deduplicated_count, outcome.total_count
        ),
    );
    let cfg = state.snapshot_config();
    emit_config_updated(&app, &cfg);
    sync_app_side_effects(&app, &state, &cfg);
    Ok(outcome)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareBundleExportOutcome {
    pub cancelled: bool,
    pub path: Option<String>,
    pub manifest: Option<ShareBundleManifest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareBundlePreviewDto {
    pub zip_path: String,
    pub manifest: ShareBundleManifest,
    pub nodes: Vec<ProxyNode>,
    pub relays: Vec<PreAccelRelay>,
    pub warnings: Vec<String>,
    pub has_readme: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareBundleImportOutcome {
    pub imported_nodes: usize,
    pub imported_relays: usize,
    pub target_sub_id: Option<String>,
    pub target_sub_name: Option<String>,
    pub warnings: Vec<String>,
}

fn sanitize_dialog_filename_stem(raw: &str, fallback: &str) -> String {
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

#[tauri::command]
pub async fn export_share_bundle_dialog(
    app: AppHandle,
    state: State<'_, AppState>,
    name: String,
    description: Option<String>,
    node_ids: Vec<String>,
    relay_ids: Vec<String>,
) -> Result<ShareBundleExportOutcome, String> {
    use tauri_plugin_dialog::DialogExt;

    let (selected_nodes, selected_relays) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let all_nodes = db.list_nodes().map_err(|e| e.to_string())?;
        let all_relays = db.list_preaccel_relays(false).map_err(|e| e.to_string())?;
        let node_map: HashMap<&str, &ProxyNode> =
            all_nodes.iter().map(|n| (n.id.as_str(), n)).collect();
        let relay_map: HashMap<&str, &PreAccelRelay> =
            all_relays.iter().map(|r| (r.id.as_str(), r)).collect();

        let mut seen_nodes: HashSet<String> = HashSet::new();
        let mut nodes_out: Vec<ProxyNode> = Vec::new();
        for id in &node_ids {
            let trimmed = id.trim();
            if !trimmed.is_empty() && seen_nodes.insert(trimmed.to_string()) {
                if let Some(node) = node_map.get(trimmed) {
                    nodes_out.push((*node).clone());
                }
            }
        }

        let mut seen_relays: HashSet<String> = HashSet::new();
        let mut relays_out: Vec<PreAccelRelay> = Vec::new();
        for id in &relay_ids {
            let trimmed = id.trim();
            if !trimmed.is_empty() && seen_relays.insert(trimmed.to_string()) {
                if let Some(relay) = relay_map.get(trimmed) {
                    relays_out.push((*relay).clone());
                }
            }
        }
        (nodes_out, relays_out)
    };

    if selected_nodes.is_empty() && selected_relays.is_empty() {
        return Err("请至少勾选 1 个节点或 1 条国内中转线路后再导出分享包".to_string());
    }

    let bundle_name = {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            "CatCloud 分享包".to_string()
        } else {
            trimmed.to_string()
        }
    };
    let default_filename = format!(
        "{}.zip",
        sanitize_dialog_filename_stem(&bundle_name, "catcloud-share")
    );

    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_title("导出猫猫云梯分享包 (.zip)")
        .set_file_name(&default_filename)
        .add_filter("CatCloud 分享包", &["zip"])
        .save_file(move |file_path| {
            let _ = tx.send(file_path);
        });

    let picked = rx.await.map_err(|_| "文件保存已取消".to_string())?;
    let Some(file_path) = picked else {
        return Ok(ShareBundleExportOutcome {
            cancelled: true,
            path: None,
            manifest: None,
        });
    };
    let mut target_path = file_path
        .into_path()
        .map_err(|e| format!("无法解析所选保存路径：{e}"))?;
    if target_path
        .extension()
        .and_then(|e| e.to_str())
        .is_none_or(|ext| !ext.eq_ignore_ascii_case("zip"))
    {
        target_path.set_extension("zip");
    }

    let req = ShareBundleExportRequest {
        name: bundle_name,
        description: description
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        nodes: selected_nodes,
        relays: selected_relays,
    };
    let path_for_write = target_path.clone();
    let manifest = tokio::task::spawn_blocking(move || {
        export_share_bundle_zip_file(&req, &path_for_write)
    })
    .await
    .map_err(|e| format!("后台导出分享包任务异常中止：{e}"))?
    .map_err(|e| e.to_string())?;

    let path_str = catcloud_core::paths::normalize_os_path(&target_path)
        .display()
        .to_string();
    state.log_app_event(
        "info",
        "分享包",
        &format!(
            "已导出分享包（节点 {} 个，国内中转 {} 条）",
            manifest.node_count, manifest.relay_count
        ),
    );
    Ok(ShareBundleExportOutcome {
        cancelled: false,
        path: Some(path_str),
        manifest: Some(manifest),
    })
}

#[tauri::command]
pub async fn pick_and_preview_share_bundle(
    app: AppHandle,
) -> Result<Option<ShareBundlePreviewDto>, String> {
    use tauri_plugin_dialog::DialogExt;

    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_title("选择猫猫云梯分享包 (.zip)")
        .add_filter("CatCloud 分享包", &["zip"])
        .pick_file(move |file_path| {
            let _ = tx.send(file_path);
        });

    let picked = rx.await.map_err(|_| "文件选择已取消".to_string())?;
    let Some(file_path) = picked else {
        return Ok(None);
    };
    let zip_path_buf = file_path
        .into_path()
        .map_err(|e| format!("无法获取所选分享包路径：{e}"))?;
    let zip_path_str = catcloud_core::paths::normalize_os_path(&zip_path_buf)
        .display()
        .to_string();
    let preview = tokio::task::spawn_blocking(move || preview_share_bundle_zip_file(&zip_path_buf))
        .await
        .map_err(|e| format!("解析分享包任务异常中止：{e}"))?
        .map_err(|e| e.to_string())?;

    // Redact plaintext credentials and server addresses before crossing IPC into WebView preview;
    // `import_share_bundle` re-parses the verified archive on disk using the selected IDs.
    let redacted_nodes: Vec<ProxyNode> = preview
        .nodes
        .iter()
        .map(catcloud_core::sanitize::redact_node_for_readonly)
        .collect();
    let redacted_relays: Vec<PreAccelRelay> = preview
        .relays
        .iter()
        .map(catcloud_core::sanitize::redact_relay_for_readonly)
        .collect();

    Ok(Some(ShareBundlePreviewDto {
        zip_path: zip_path_str,
        manifest: preview.manifest,
        nodes: redacted_nodes,
        relays: redacted_relays,
        warnings: preview.warnings,
        has_readme: preview.has_readme,
    }))
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn import_share_bundle(
    app: AppHandle,
    state: State<'_, AppState>,
    zip_path: String,
    selected_node_ids: Vec<String>,
    selected_relay_ids: Vec<String>,
    target_sub_id: Option<String>,
    new_sub_name: Option<String>,
    update_mode: Option<String>,
) -> Result<ShareBundleImportOutcome, String> {
    let trimmed_zip = zip_path.trim().to_string();
    if trimmed_zip.is_empty() {
        return Err("分享包文件路径不能为空".to_string());
    }
    let path_for_read = PathBuf::from(&trimmed_zip);
    let preview = tokio::task::spawn_blocking(move || preview_share_bundle_zip_file(&path_for_read))
        .await
        .map_err(|e| format!("解析分享包任务异常中止：{e}"))?
        .map_err(|e| e.to_string())?;

    let node_filter: HashSet<&str> = selected_node_ids
        .iter()
        .map(String::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let relay_filter: HashSet<&str> = selected_relay_ids
        .iter()
        .map(String::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    let chosen_nodes: Vec<ProxyNode> = preview
        .nodes
        .into_iter()
        .filter(|n| node_filter.contains(n.id.as_str()))
        .collect();
    let chosen_relays: Vec<PreAccelRelay> = preview
        .relays
        .into_iter()
        .filter(|r| relay_filter.contains(r.id.as_str()))
        .collect();

    if chosen_nodes.is_empty() && chosen_relays.is_empty() {
        return Err("请至少勾选 1 个节点或 1 条国内中转线路后再导入".to_string());
    }

    let mut warnings = preview.warnings;
    let mut imported_nodes: usize = 0;
    let mut resolved_sub_id: Option<String> = None;
    let mut resolved_sub_name: Option<String> = None;
    let mut id_remap: HashMap<String, String> = HashMap::new();

    if !chosen_nodes.is_empty() {
        let existing_target_id = target_sub_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        if let Some(tid) = existing_target_id {
            let mode = parse_subscription_update_mode(
                update_mode.as_deref().unwrap_or("merge_dedup"),
            )?;
            let (update_res, sub_name) = {
                let db = state.storage.lock().map_err(|e| e.to_string())?;
                let res = db
                    .update_subscription_nodes_with_mode(&tid, &chosen_nodes, mode)
                    .map_err(|e| e.to_string())?;
                let name = db
                    .get_subscription(&tid)
                    .ok()
                    .flatten()
                    .map(|s| s.name);
                (res, name)
            };
            imported_nodes = chosen_nodes.len();
            id_remap = update_res.id_remap;
            resolved_sub_id = Some(tid);
            resolved_sub_name = sub_name;
        } else {
            let sub_name = new_sub_name
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| {
                    let manifest_name = preview.manifest.name.trim();
                    if manifest_name.is_empty() {
                        "分享包导入".to_string()
                    } else {
                        manifest_name.to_string()
                    }
                });
            let (sub_id, count) = {
                let mut db = state.storage.lock().map_err(|e| e.to_string())?;
                persist_migration_nodes(&mut db, sub_name.clone(), chosen_nodes)?
            };
            imported_nodes = count;
            resolved_sub_id = Some(sub_id);
            resolved_sub_name = Some(sub_name);
        }
    }

    let mut imported_relays: usize = 0;
    if !chosen_relays.is_empty() {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let (count, relay_warnings) =
            catcloud_core::preaccel::import_relays_dedup_into_storage(&db, chosen_relays)
                .map_err(|e| e.to_string())?;
        imported_relays = count;
        warnings.extend(relay_warnings);
    }

    if imported_nodes > 0 {
        let _ = remap_active_single_node_id_if_needed(&state, &id_remap)?;
        prune_node_health_pool_from_db(&state);
        let _ = ensure_default_group_if_empty(&state);
    }
    let _ = trigger_reload_if_running(&app, &state, false).await;
    let latest_cfg = state.snapshot_config();
    if imported_relays > 0 {
        sync_running_global_preaccel_if_active(&state, &latest_cfg).await;
    }
    state.log_app_event(
        "info",
        "分享包",
        &format!(
            "已从分享包导入节点 {} 个、国内中转 {} 条",
            imported_nodes, imported_relays
        ),
    );
    emit_config_updated(&app, &latest_cfg);
    sync_app_side_effects(&app, &state, &latest_cfg);

    Ok(ShareBundleImportOutcome {
        imported_nodes,
        imported_relays,
        target_sub_id: resolved_sub_id,
        target_sub_name: resolved_sub_name,
        warnings,
    })
}

fn parse_controller_endpoint_and_secret(raw: &str) -> (String, Option<String>) {
    let trimmed = raw.trim();
    let (url_part, pipe_secret) = if let Some((left, right)) = trimmed.split_once("|secret=") {
        let sec = right.trim();
        (
            left.trim().to_string(),
            (!sec.is_empty()).then(|| sec.to_string()),
        )
    } else {
        (trimmed.to_string(), None)
    };

    let (clean_url, query_secret) = if let Some((base, query)) = url_part.split_once('?') {
        let mut kept_pairs = Vec::new();
        let mut found_secret = None;
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            if let Some((k, v)) = pair.split_once('=') {
                if k.eq_ignore_ascii_case("secret") {
                    let val = v.trim();
                    if !val.is_empty() {
                        found_secret = Some(val.to_string());
                    }
                    continue;
                }
            }
            kept_pairs.push(pair);
        }
        let rebuilt = if kept_pairs.is_empty() {
            base.to_string()
        } else {
            format!("{base}?{}", kept_pairs.join("&"))
        };
        (rebuilt, found_secret)
    } else {
        (url_part, None)
    };

    let base_no_slash = clean_url.trim_end_matches('/');
    let endpoint = if let Some((path_only, query)) = base_no_slash.split_once('?') {
        let p = path_only.trim_end_matches('/');
        if p.ends_with("/proxies") {
            format!("{p}?{query}")
        } else {
            format!("{p}/proxies?{query}")
        }
    } else if base_no_slash.ends_with("/proxies") {
        base_no_slash.to_string()
    } else {
        format!("{base_no_slash}/proxies")
    };

    (endpoint, pipe_secret.or(query_secret))
}

async fn refresh_process_adapter_subscription(
    state: &AppState,
    sub: &SubscriptionRecord,
) -> Result<ParsedSubscription, String> {
    let raw = sub.url_or_cmd.trim();
    if raw.is_empty() {
        return Err("来源地址或外部脚本命令不能为空，请先填写公开控制接口地址或适配器命令".to_string());
    }
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        let (endpoint, secret) = parse_controller_endpoint_and_secret(raw);
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| {
                tracing::warn!(
                    sub_id = %sub.id,
                    error = %app_log::sanitize_log_line(&e.to_string()),
                    "初始化控制接口请求客户端失败"
                );
                "初始化控制接口请求客户端失败，请稍后重试".to_string()
            })?;
        let mut req = client.get(&endpoint);
        if let Some(ref sec) = secret {
            req = req.bearer_auth(sec);
        }
        let mut resp = req.send().await.map_err(|e| {
            tracing::warn!(
                sub_id = %sub.id,
                endpoint = %app_log::sanitize_log_line(&endpoint),
                error = %app_log::sanitize_log_line(&e.to_string()),
                "连接代理控制接口失败"
            );
            if e.is_timeout() {
                "连接控制接口超时，请确认目标代理软件正在运行".to_string()
            } else {
                "无法连接到控制接口，请确认地址端口正确且目标代理软件已启动".to_string()
            }
        })?;
        let status = resp.status();
        if status.as_u16() == 401 || status.as_u16() == 403 {
            return Err(format!(
                "控制接口需要口令认证（HTTP {}），请在地址末尾附加 |secret=你的口令 后重试",
                status.as_u16()
            ));
        }
        if !status.is_success() {
            return Err(format!(
                "控制接口返回异常状态（HTTP {}），请确认该地址为有效的代理控制接口",
                status.as_u16()
            ));
        }
        const MAX_CTRL_BYTES: usize = 16 * 1024 * 1024;
        if let Some(len) = resp.content_length() {
            if len > MAX_CTRL_BYTES as u64 {
                return Err("控制接口返回数据超过 16 MiB 上限，已安全终止读取".to_string());
            }
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| {
            tracing::warn!(
                sub_id = %sub.id,
                error = %app_log::sanitize_log_line(&e.to_string()),
                "读取控制接口响应失败"
            );
            "读取控制接口响应失败，请确认目标代理软件运行正常后重试".to_string()
        })? {
            if body.len().saturating_add(chunk.len()) > MAX_CTRL_BYTES {
                return Err("控制接口返回数据超过 16 MiB 上限，已安全终止读取".to_string());
            }
            body.extend_from_slice(&chunk);
        }

        let (nodes, meta_only_count, total_entries, mut warnings) =
            parse_controller_proxies_json(&sub.id, &body)
                .map_err(|e| format_subscription_error_zh(&e.to_string()))?;
        if nodes.is_empty() {
            if meta_only_count > 0 {
                return Err(format!(
                    "已连通控制接口并识别到 {meta_only_count} 个节点名称，但该接口未公开服务器地址与端口（缺少 server/port），无法直接抓取可连接节点；请改用目标软件的本地 YAML 配置文件或外挂脚本适配器导入"
                ));
            }
            return Err(format!(
                "已连通控制接口，但未发现可用代理节点（共 {total_entries} 项均为内置项或分组）"
            ));
        }
        if meta_only_count > 0 {
            warnings.push(format!(
                "另有 {meta_only_count} 个节点因控制接口未公开 server/port 已跳过"
            ));
        }
        return Ok(ParsedSubscription {
            format: SubscriptionPayloadFormat::ClashYaml,
            nodes,
            userinfo: None,
            etag: None,
            warnings,
        });
    }

    let adapter_cfg = AdapterConfig::from_command_line(raw).map_err(|e| {
        tracing::warn!(
            sub_id = %sub.id,
            error = %app_log::sanitize_log_line(&e.to_string()),
            "外部适配器命令格式不正确"
        );
        "外部适配器命令格式不正确，请检查路径与引号配对".to_string()
    })?;
    let req = AdapterRequest::new(ADAPTER_REASON_MANUAL, sub.id.clone(), Vec::new());
    let nodes = invoke_external_adapter(&adapter_cfg, &req, Some(&state.adapter_cooldown))
        .await
        .map_err(|e| {
            let msg = e.to_string();
            tracing::warn!(
                sub_id = %sub.id,
                program = %app_log::sanitize_log_line(&adapter_cfg.program),
                error = %app_log::sanitize_log_line(&msg),
                "外部适配器执行失败"
            );
            if !msg.contains("cooldown") {
                state.adapter_cooldown.reset(&sub.id);
            }
            if msg.contains("cooldown") {
                "外部适配器刷新过于频繁，请稍候片刻再试".to_string()
            } else if msg.contains("failed to spawn") {
                "无法启动外部适配器程序，请确认命令路径正确且具有可执行权限".to_string()
            } else if msg.contains("timed out") {
                format!(
                    "外部适配器执行超时（超过 {} 秒），请检查脚本是否卡住",
                    adapter_cfg.timeout_sec
                )
            } else {
                "外部适配器未能返回有效节点，请确认脚本输出格式符合要求".to_string()
            }
        })?;
    Ok(ParsedSubscription {
        format: SubscriptionPayloadFormat::ClashYaml,
        nodes,
        userinfo: None,
        etag: None,
        warnings: Vec::new(),
    })
}

fn extract_local_system_proxy_url(spec: &SystemProxySpec) -> Option<String> {
    if !spec.enabled || spec.port == 0 {
        return None;
    }
    if spec
        .pac_url
        .as_deref()
        .map(str::trim)
        .is_some_and(|s| !s.is_empty())
    {
        return None;
    }
    let host_raw = spec.host.trim();
    if host_raw.is_empty() {
        return None;
    }
    if host_raw.contains("://") {
        let parsed = reqwest::Url::parse(host_raw).ok()?;
        let scheme = match parsed.scheme().to_ascii_lowercase().as_str() {
            "http" => "http",
            "https" => "https",
            "socks5" => "socks5",
            "socks5h" => "socks5h",
            _ => return None,
        };
        let port = parsed.port().unwrap_or(spec.port);
        if port == 0 {
            return None;
        }
        let host = parsed.host_str()?.trim();
        if host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" {
            return Some(format!("{scheme}://127.0.0.1:{port}"));
        }
        if host == "::1" || host == "[::1]" {
            return Some(format!("{scheme}://[::1]:{port}"));
        }
        return None;
    }
    let bare = host_raw.trim_start_matches('[').trim_end_matches(']');
    if bare.eq_ignore_ascii_case("localhost") || bare == "127.0.0.1" {
        Some(format!("http://127.0.0.1:{}", spec.port))
    } else if bare == "::1" {
        Some(format!("http://[::1]:{}", spec.port))
    } else {
        None
    }
}

/// Build deduplicated proxy fallback candidates for subscription fetching:
/// 1. Direct (`None`) first so domestic-accessible feeds refresh at full speed without detour.
/// 2. CatCloud main core local mixed port (`http://127.0.0.1:<mixed_port>`) when running.
/// 3. Active OS local loopback system proxy (`127.0.0.1` / `localhost` / `[::1]`) when distinct.
fn build_subscription_proxy_candidates_from(
    catcloud_mixed_port: Option<u16>,
    sys_proxy: Option<&SystemProxySpec>,
) -> Vec<Option<String>> {
    let mut out: Vec<Option<String>> = Vec::with_capacity(3);
    let mut seen: HashSet<String> = HashSet::new();

    // Always try direct first.
    out.push(None);

    let mut push_unique = |url: String| {
        let key = url.trim().trim_end_matches('/').to_ascii_lowercase();
        if !key.is_empty() && seen.insert(key) {
            out.push(Some(url));
        }
    };

    if let Some(port) = catcloud_mixed_port.filter(|&p| p > 0) {
        push_unique(format!("http://127.0.0.1:{port}"));
    }

    if let Some(spec) = sys_proxy {
        if let Some(local_proxy) = extract_local_system_proxy_url(spec) {
            push_unique(local_proxy);
        }
    }

    out
}

fn contains_cjk_char(text: &str) -> bool {
    text.chars().any(|c| ('\u{4E00}'..='\u{9FFF}').contains(&c))
}

const SAFE_SUBSCRIPTION_ZH_ASCII_TOKENS: &[&str] = &[
    "http",
    "https",
    "tls",
    "utf-8",
    "utf8",
    "yaml",
    "json",
    "mib",
    "kb",
    "mb",
    "gb",
    "base64",
    "uri",
    "url",
    "proxies",
    "outbounds",
    "sing-box",
    "clash",
    "mihomo",
    "server",
    "port",
    "secret",
    "4xx",
    "5xx",
];

fn has_embedded_http_url(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    for pat in ["http://", "https://"] {
        let mut rest = lower.as_str();
        while let Some(pos) = rest.find(pat) {
            let after = &rest[pos + pat.len()..];
            if after
                .as_bytes()
                .first()
                .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'[')
            {
                return true;
            }
            rest = after;
        }
    }
    false
}

/// Detect whether an error string still contains raw English exception tails (e.g. `（invalid ...）`,
/// `expected ...`, `dns error`, `connection refused`, `timed out`, `status 4xx/5xx`, OS errors, or
/// embedded URLs) so they are never leaked into user-facing prompts or SQLite `last_error`.
fn contains_english_error_residue(text: &str) -> bool {
    if has_embedded_http_url(text) {
        return true;
    }
    for token in text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-')) {
        let trimmed = token.trim_matches('-');
        let alpha_count = trimmed.bytes().filter(u8::is_ascii_alphabetic).count();
        if alpha_count < 2 {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if !SAFE_SUBSCRIPTION_ZH_ASCII_TOKENS.contains(&lower.as_str()) {
            return true;
        }
    }
    false
}

fn contains_http_status_code(text: &str, code: &str) -> bool {
    let bytes = text.as_bytes();
    let code_len = code.len();
    let mut offset = 0usize;
    while let Some(rel) = text[offset..].find(code) {
        let idx = offset + rel;
        let prev_ok = idx == 0 || !bytes[idx - 1].is_ascii_digit();
        let next_idx = idx + code_len;
        let next_ok = next_idx == bytes.len() || !bytes[next_idx].is_ascii_digit();
        if prev_ok && next_ok {
            return true;
        }
        offset = idx + 1;
    }
    false
}

/// Ensure subscription fetch/parse error strings persisted to SQLite and surfaced to users are
/// strictly clean, actionable plain Chinese. Any raw English error or mixed-language exception tail
/// is logged (sanitized) via `tracing::warn!` and mapped to a pure-Chinese category message.
fn format_subscription_error_zh(raw: &str) -> String {
    let cleaned = raw.replace(['\r', '\n'], " ").trim().to_string();
    if cleaned.is_empty() {
        return "拉取或解析订阅失败，请检查订阅链接是否有效".to_string();
    }
    if contains_cjk_char(&cleaned) && !contains_english_error_residue(&cleaned) {
        return cleaned;
    }

    tracing::warn!(
        raw_error = %app_log::sanitize_log_line(&cleaned),
        "订阅错误包含原始英文或未归类异常详情，已转为纯中文提示"
    );

    let lower = cleaned.to_ascii_lowercase();
    if lower.contains("timed out") || lower.contains("timeout") || cleaned.contains("超时") {
        "拉取订阅超时：直连与本机代理均未在规定时间内响应，请检查网络连接或开启代理后重试"
            .to_string()
    } else if lower.contains("dns")
        || lower.contains("failed to lookup")
        || lower.contains("no such host")
        || lower.contains("name or service not known")
        || cleaned.contains("域名无法解析")
    {
        "订阅域名解析失败：无法解析该订阅地址，请检查网络或开启代理后重试".to_string()
    } else if lower.contains("connection refused")
        || lower.contains("actively refused")
        || cleaned.contains("拒绝连接")
    {
        "连接订阅服务器或本地代理被拒绝，请确认订阅链接可用且本地代理正常运行".to_string()
    } else if lower.contains("connection reset")
        || lower.contains("forcibly closed")
        || lower.contains("unexpected eof")
        || lower.contains("broken pipe")
        || cleaned.contains("被对方重置")
        || cleaned.contains("意外中断")
    {
        "拉取订阅时连接被远端中断，可能需要通过代理访问该订阅链接".to_string()
    } else if lower.contains("certificate")
        || lower.contains("tls")
        || lower.contains("ssl")
        || lower.contains("handshake")
        || lower.contains("rustls")
        || lower.contains("openssl")
    {
        "拉取订阅时安全连接（TLS）握手失败，请检查系统时间或网络环境后重试".to_string()
    } else if lower.contains("too many redirects")
        || lower.contains("redirect")
        || cleaned.contains("重定向")
    {
        "订阅链接重定向次数过多，可能存在循环跳转，请检查订阅地址".to_string()
    } else if lower.contains("relative url")
        || lower.contains("empty host")
        || lower.contains("invalid url")
        || lower.contains("invalid port")
        || lower.contains("invalid domain")
        || lower.contains("invalid ipv")
        || lower.contains("invalid proxy")
        || cleaned.contains("链接格式不正确")
        || cleaned.contains("代理地址")
    {
        "订阅链接或代理地址格式不正确，请确认完整复制了 http:// 或 https:// 订阅地址".to_string()
    } else if contains_http_status_code(&lower, "401") || lower.contains("unauthorized") {
        "订阅认证失败（HTTP 401），链接里的访问令牌可能已失效或被重置".to_string()
    } else if contains_http_status_code(&lower, "403") || lower.contains("forbidden") {
        "订阅服务器拒绝访问（HTTP 403），可能被防火墙拦截、需要通过代理拉取或链接已失效"
            .to_string()
    } else if contains_http_status_code(&lower, "404") || lower.contains("not found") {
        "订阅地址不存在（HTTP 404），请确认复制了完整的订阅链接".to_string()
    } else if contains_http_status_code(&lower, "410") {
        "该订阅链接已被服务商下线（HTTP 410），请重新获取最新订阅地址".to_string()
    } else if contains_http_status_code(&lower, "429") || lower.contains("too many requests") {
        "订阅请求过于频繁（HTTP 429），请稍候片刻再试".to_string()
    } else if contains_http_status_code(&lower, "500")
        || contains_http_status_code(&lower, "502")
        || contains_http_status_code(&lower, "503")
        || contains_http_status_code(&lower, "504")
        || lower.contains("status 5")
        || lower.contains("5xx")
    {
        "订阅服务器暂时异常（HTTP 5xx），请稍后再试".to_string()
    } else if contains_http_status_code(&lower, "400")
        || lower.contains("status 4")
        || lower.contains("4xx")
    {
        "订阅服务器拒绝了本次请求（HTTP 4xx），请确认订阅链接有效且未失效".to_string()
    } else if lower.contains("no such file")
        || lower.contains("cannot find the file")
        || lower.contains("os error 2")
    {
        "未找到本地订阅文件，请确认文件未被移动或删除".to_string()
    } else if lower.contains("permission denied")
        || lower.contains("access is denied")
        || lower.contains("os error 5")
        || lower.contains("os error 13")
    {
        "无权限读取订阅来源，请检查文件或程序访问权限".to_string()
    } else if lower.contains("cooldown") {
        "订阅刷新过于频繁，请稍候片刻再试".to_string()
    } else if lower.contains("expected ")
        || lower.contains("invalid ")
        || lower.contains("missing field")
        || lower.contains("unknown variant")
        || lower.contains("yaml")
        || lower.contains("json")
        || lower.contains("base64")
        || lower.contains("utf-8")
        || lower.contains("decode")
        || lower.contains("parse")
        || cleaned.contains("解析")
    {
        "订阅内容格式无法解析，请确认该链接返回的是有效的节点订阅配置".to_string()
    } else if lower.contains("error sending request") || lower.contains("connect") {
        "无法连接到订阅服务器，请检查网络连接或开启代理后重试".to_string()
    } else {
        "拉取或解析订阅失败，请检查订阅链接是否有效或稍后重试".to_string()
    }
}

async fn refresh_single_subscription_inner(
    state: &AppState,
    sub: &SubscriptionRecord,
) -> Result<serde_json::Value, String> {
    let parsed = match sub.kind {
        SubscriptionKind::Url => {
            let live_rt = state.adapter.status().await;
            let catcloud_mixed_port = if live_rt.running && live_rt.mixed_port > 0 {
                Some(live_rt.mixed_port)
            } else {
                None
            };
            let sys_proxy = tokio::task::spawn_blocking(|| {
                default_platform().read_system_proxy().ok()
            })
            .await
            .ok()
            .flatten();
            let proxy_candidates = build_subscription_proxy_candidates_from(
                catcloud_mixed_port,
                sys_proxy.as_ref(),
            );
            let fetched = catcloud_core::subscription::parser::fetch_subscription_url_with_fallback(
                &sub.url_or_cmd,
                &proxy_candidates,
                &FetchOptions::default(),
            )
            .await
            .map_err(|e| format_subscription_error_zh(&e.to_string()))?;

            if let Some(ref used_proxy) = fetched.used_proxy {
                state.log_app_event(
                    "info",
                    "订阅",
                    &format!(
                        "订阅「{}」直连未通，已自动通过本地代理（{used_proxy}）拉取成功",
                        sub.name
                    ),
                );
            }

            let mut parsed = fetched
                .parse(&sub.id)
                .map_err(|e| format_subscription_error_zh(&e.to_string()))?;
            if parsed.etag.is_none() {
                parsed.etag = fetched.etag;
            }
            parsed
        }
        SubscriptionKind::File | SubscriptionKind::Migrated => {
            let raw = std::fs::read(&sub.url_or_cmd).map_err(|e| {
                tracing::warn!(
                    sub_id = %sub.id,
                    path = %app_log::sanitize_log_line(&sub.url_or_cmd),
                    error = %app_log::sanitize_log_line(&e.to_string()),
                    "读取本地订阅文件失败"
                );
                match e.kind() {
                    std::io::ErrorKind::NotFound => {
                        "未找到本地订阅文件，请确认文件未被移动或删除".to_string()
                    }
                    std::io::ErrorKind::PermissionDenied => {
                        "无权限读取本地订阅文件，请检查文件访问权限".to_string()
                    }
                    _ => "无法读取本地订阅文件，请确认文件路径有效且未被其它程序占用".to_string(),
                }
            })?;
            parse_subscription_payload(&sub.id, &raw, None)
                .map_err(|e| format_subscription_error_zh(&e.to_string()))?
        }
        SubscriptionKind::ProcessAdapter => {
            refresh_process_adapter_subscription(state, sub).await?
        }
    };

    let node_count = {
        let mut db = state.storage.lock().map_err(|e| {
            tracing::warn!(error = %app_log::sanitize_log_line(&e.to_string()), "锁定订阅数据库失败");
            "本地数据库繁忙，请稍后重试".to_string()
        })?;
        apply_parsed_subscription(&mut db, sub, &parsed)
            .map_err(|e| format_subscription_error_zh(&e.to_string()))?
    };
    let _ = ensure_default_group_if_empty(state);
    Ok(serde_json::json!({
        "sub_id": sub.id,
        "node_count": node_count,
        "updated_at": Utc::now().to_rfc3339(),
        "warnings": parsed.warnings
    }))
}

#[tauri::command]
pub async fn refresh_subscription(
    app: AppHandle,
    state: State<'_, AppState>,
    sub_id: String,
) -> Result<serde_json::Value, String> {
    let Some(_refresh_guard) = SubRefreshGuard::try_acquire(&state.refreshing_sub_ids, sub_id.clone())
    else {
        return Err("该订阅正在刷新中，请稍候完成后再试".to_string());
    };
    let sub = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        db.get_subscription(&sub_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("未找到指定订阅（{sub_id}）"))?
    };
    let result = refresh_single_subscription_inner(&state, &sub).await;
    match result {
        Err(err) => {
            let sanitized_err = app_log::sanitize_log_line(&format_subscription_error_zh(&err));
            if let Ok(db) = state.storage.lock() {
                let _ = db.update_subscription_refresh_status(
                    &sub.id,
                    None,
                    None,
                    Some(sanitized_err.as_str()),
                    None,
                    None,
                    None,
                );
            }
            state.log_app_event(
                "warn",
                "订阅",
                &format!("刷新订阅「{}」失败：{sanitized_err}", sub.name),
            );
            Err(sanitized_err)
        }
        Ok(val) => {
            prune_node_health_pool_from_db(&state);
            let _ = trigger_reload_if_running(&app, &state, false).await;
            let cfg = state.snapshot_config();
            emit_config_updated(&app, &cfg);
            sync_app_side_effects(&app, &state, &cfg);
            Ok(val)
        }
    }
}

#[tauri::command]
pub async fn refresh_all_subscriptions(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let subs = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        db.list_subscriptions().map_err(|e| e.to_string())?
    };
    let mut refreshed = 0usize;
    let mut total_nodes = 0usize;
    let mut errors = Vec::new();
    for sub in subs.into_iter().filter(|s| s.enabled) {
        let Some(_refresh_guard) =
            SubRefreshGuard::try_acquire(&state.refreshing_sub_ids, sub.id.clone())
        else {
            continue;
        };
        match refresh_single_subscription_inner(&state, &sub).await {
            Ok(v) => {
                refreshed += 1;
                total_nodes += v.get("node_count").and_then(|c| c.as_u64()).unwrap_or(0) as usize;
            }
            Err(err) => {
                let sanitized_err = app_log::sanitize_log_line(&format_subscription_error_zh(&err));
                if let Ok(db) = state.storage.lock() {
                    let _ = db.update_subscription_refresh_status(
                        &sub.id,
                        None,
                        None,
                        Some(sanitized_err.as_str()),
                        None,
                        None,
                        None,
                    );
                }
                state.log_app_event(
                    "warn",
                    "订阅",
                    &format!("批量刷新订阅「{}」失败：{sanitized_err}", sub.name),
                );
                errors.push(format!("{}: {sanitized_err}", sub.name));
            }
        }
    }
    if refreshed > 0 {
        prune_node_health_pool_from_db(&state);
        let _ = trigger_reload_if_running(&app, &state, false).await;
        let cfg = state.snapshot_config();
        emit_config_updated(&app, &cfg);
        sync_app_side_effects(&app, &state, &cfg);
    }
    Ok(serde_json::json!({
        "refreshed": refreshed,
        "total_nodes": total_nodes,
        "errors": errors
    }))
}

#[tauri::command]
pub fn list_preaccel_relays(state: State<'_, AppState>) -> Result<Vec<PreAccelRelay>, String> {
    let db = state.storage.lock().map_err(|e| e.to_string())?;
    db.list_preaccel_relays(false).map_err(|e| e.to_string())
}

fn collect_excluded_pids_for_global_preaccel(state: &AppState) -> Vec<u32> {
    let mut pids = Vec::with_capacity(2);
    let rt = state.snapshot_runtime();
    if rt.running {
        if let Some(pid) = rt.pid.filter(|&p| p > 0) {
            pids.push(pid);
        }
    }
    pids
}

fn load_enabled_preaccel_relays(state: &AppState) -> Result<Vec<PreAccelRelay>, String> {
    let db = state.storage.lock().map_err(|e| e.to_string())?;
    db.list_preaccel_relays(true).map_err(|e| e.to_string())
}

fn log_global_preaccel_verify_status(
    state: &AppState,
    stage_label: &str,
    status: &GlobalPreAccelStatus,
) {
    let iface = status
        .bound_physical_interface
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("未绑定/自动路由");
    let security = if status.detected_security_products.is_empty() {
        "未检出拦截类安全软件".to_string()
    } else {
        status.detected_security_products.join(" / ")
    };
    let perm = if status.is_elevated {
        "管理员"
    } else {
        "普通用户"
    };
    let detail_reason = status
        .verify_message
        .as_deref()
        .or(status.last_error.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("无附加说明");

    match status.verify_state.as_str() {
        "verified" => {
            let latency_text = status
                .verify_latency_ms
                .map(|ms| format!("{ms} ms"))
                .unwrap_or_else(|| "--".to_string());
            state.log_app_event(
                "info",
                "国内提速",
                &format!(
                    "{stage_label}：底层透明加速自动探测通过（模式：{}，物理网卡：{iface}，探测耗时：{latency_text}，安全环境：{security}，权限：{perm}）— {detail_reason}",
                    status.mode
                ),
            );
        }
        "degraded" => {
            state.log_app_event(
                "warning",
                "国内提速",
                &format!(
                    "{stage_label}：底层透明加速自动探测触发保护熔断，已安全退回本地独立 443 通道（模式：{}，物理网卡：{iface}，安全环境：{security}，权限：{perm}）— {detail_reason}",
                    status.mode
                ),
            );
        }
        "failed" => {
            state.log_app_event(
                "warning",
                "国内提速",
                &format!(
                    "{stage_label}：底层透明加速组件加载或探测失败（模式：{}，物理网卡：{iface}，安全环境：{security}，权限：{perm}）— {detail_reason}",
                    status.mode
                ),
            );
        }
        "probing" => {
            state.log_app_event(
                "info",
                "国内提速",
                &format!(
                    "{stage_label}：底层透明加速链路正在探测中（模式：{}，物理网卡：{iface}，安全环境：{security}）",
                    status.mode
                ),
            );
        }
        other => {
            let state_desc = if !status.running {
                "独立底层引擎未运行"
            } else if status.is_windivert_active {
                "底层透明加速运行中（待探测）"
            } else {
                "运行于本地独立 443 通道（未进入底层透明拦截）"
            };
            state.log_app_event(
                "info",
                "国内提速",
                &format!(
                    "{stage_label}：{state_desc}（模式：{}，探测状态：{other}，物理网卡：{iface}，安全环境：{security}，权限：{perm}）— {detail_reason}",
                    status.mode
                ),
            );
        }
    }
}

async fn start_global_preaccel_engine(
    state: &AppState,
    cfg: &AppConfig,
) -> Result<GlobalPreAccelStatus, String> {
    let relays = load_enabled_preaccel_relays(state)?;
    if relays.is_empty() {
        return Err("尚未配置已启用的国内 443 中转线路，请先添加并启用至少一条中转".to_string());
    }
    let excluded_pids = collect_excluded_pids_for_global_preaccel(state);
    state
        .global_preaccel
        .sync_main_core_pid(excluded_pids.first().copied());
    let status = state
        .global_preaccel
        .start(cfg, &relays, &excluded_pids)
        .await
        .map_err(|e| e.to_string())?;
    log_global_preaccel_verify_status(state, "启动底层提速引擎", &status);
    Ok(status)
}

async fn sync_running_global_preaccel_if_active(state: &AppState, cfg: &AppConfig) {
    if !state.global_preaccel.status().running {
        return;
    }
    match load_enabled_preaccel_relays(state) {
        Ok(relays) if !relays.is_empty() => {
            let excluded_pids = collect_excluded_pids_for_global_preaccel(state);
            match state
                .global_preaccel
                .restart_windivert_if_running(cfg, &relays, &excluded_pids)
                .await
            {
                Ok(st) => {
                    log_global_preaccel_verify_status(state, "中转变更热重建底层 443 隧道", &st);
                }
                Err(err) => {
                    state.log_app_event(
                        "warning",
                        "国内提速",
                        &format!("中转配置变更后热重建独立底层 443 隧道失败：{err}"),
                    );
                }
            }
        }
        _ => {
            let _ = state.global_preaccel.stop().await;
            state.log_app_event(
                "info",
                "国内提速",
                "已无可用的国内中转线路，独立底层 443 隧道已自动停止",
            );
        }
    }
}

fn parse_global_preaccel_scope(raw: &str) -> Result<GlobalPreAccelScope, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "proxy_apps_only" => Ok(GlobalPreAccelScope::ProxyAppsOnly),
        "all_non_443_tcp" | "all_non443_tcp" => Ok(GlobalPreAccelScope::AllNon443Tcp),
        other => Err(format!(
            "未知的全局底层预代理范围 `{other}`，仅支持 `proxy_apps_only` 或 `all_non_443_tcp`"
        )),
    }
}

fn normalize_global_target_processes(processes: Vec<String>) -> Vec<String> {
    let mut out = Vec::with_capacity(processes.len());
    let mut seen: HashSet<String> = HashSet::new();
    for raw in processes {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if seen.insert(lower) {
            out.push(trimmed.to_string());
        }
    }
    out
}

#[tauri::command]
pub async fn upsert_preaccel_relay(
    app: AppHandle,
    state: State<'_, AppState>,
    mut relay: PreAccelRelay,
) -> Result<PreAccelRelay, String> {
    if relay.id.trim().is_empty() {
        relay.id = format!("relay-{}", uuid::Uuid::new_v4().simple());
    }
    catcloud_core::preaccel::schema::validate_relay_strict(&relay).map_err(|e| e.to_string())?;
    {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        db.upsert_preaccel_relay(&relay).map_err(|e| e.to_string())?;
    }
    let _ = trigger_reload_if_running(&app, &state, false).await;
    let cfg = state.snapshot_config();
    sync_running_global_preaccel_if_active(&state, &cfg).await;
    sync_app_side_effects(&app, &state, &cfg);
    let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&cfg));
    Ok(relay)
}

#[tauri::command]
pub async fn delete_preaccel_relay(
    app: AppHandle,
    state: State<'_, AppState>,
    relay_id: String,
) -> Result<bool, String> {
    let deleted = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        db.delete_preaccel_relay(&relay_id)
            .map_err(|e| e.to_string())?
    };
    if deleted {
        let _ = trigger_reload_if_running(&app, &state, false).await;
        let cfg = state.snapshot_config();
        sync_running_global_preaccel_if_active(&state, &cfg).await;
        sync_app_side_effects(&app, &state, &cfg);
        let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&cfg));
    }
    Ok(deleted)
}

/// Spawn an asynchronous background WinDivert v2.2.2 auto-download (3-tier proxy fallback:
/// CatCloud main core -> active Windows system proxy -> direct) and in-place hot-upgrade whenever
/// running on non-ARM64 Windows without installed driver files.
fn maybe_spawn_auto_windivert_download(app: &AppHandle, state: &AppState, cfg: &AppConfig) {
    #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
    {
        if state.shutting_down.load(Ordering::SeqCst) {
            return;
        }
        if locate_windivert_files(&state.paths, cfg.preaccel.windivert_dir.as_deref()).is_some() {
            return;
        }
        if state
            .windivert_installing
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }

        state.global_preaccel.set_install_state("downloading");
        sync_app_side_effects(app, state, cfg);

        let app_h = app.clone();
        let install_flag = Arc::clone(&state.windivert_installing);
        tauri::async_runtime::spawn(async move {
            let _flag_guard = AtomicFlagResetGuard(install_flag);
            let Some(st) = app_h.try_state::<AppState>() else {
                return;
            };
            if st.shutting_down.load(Ordering::SeqCst) {
                return;
            }

            let rt = st.snapshot_runtime();
            let active_mixed_port = if rt.running && rt.mixed_port > 0 {
                Some(rt.mixed_port)
            } else {
                None
            };
            let proxy_candidates = build_default_windivert_proxy_candidates(active_mixed_port);

            match download_and_install_windivert_with_fallbacks(&st.paths, &proxy_candidates).await
            {
                Ok(installed_dir) => {
                    st.global_preaccel.set_install_state("verifying");
                    let latest_cfg = st.snapshot_config();
                    sync_app_side_effects(&app_h, &st, &latest_cfg);
                    st.log_app_event(
                        "info",
                        "国内提速",
                        &format!(
                            "已自动下载并通过 SHA-256 校验安装官方 WinDivert v2.2.2 驱动至 {}",
                            installed_dir.display()
                        ),
                    );

                    if default_platform().capabilities().is_elevated {
                        // Acquire outer `config_transition_lock` before checking latest config/TUN
                        // and upgrading/starting WinDivert so TUN and WinDivert can never race open.
                        let _cfg_guard = st.config_transition_lock.lock().await;
                        let latest_cfg = st.snapshot_config();
                        let latest_rt = st.snapshot_runtime();
                        let tun_active = (latest_rt.running
                            || st.adapter.has_live_controller().await)
                            && effective_tun_enabled(&st, &latest_cfg);
                        if !st.shutting_down.load(Ordering::SeqCst)
                            && latest_cfg.preaccel.enabled
                            && !tun_active
                        {
                            let cur_global = st.snapshot_global_preaccel();
                            if cur_global.running && !cur_global.is_windivert_active {
                                match load_enabled_preaccel_relays(&st) {
                                    Ok(relays) if !relays.is_empty() => {
                                        let excluded_pids =
                                            collect_excluded_pids_for_global_preaccel(&st);
                                        match st
                                            .global_preaccel
                                            .upgrade_to_windivert_in_place(
                                                &latest_cfg,
                                                &relays,
                                                &excluded_pids,
                                            )
                                            .await
                                        {
                                            Ok(upgraded) if upgraded.is_windivert_active => {
                                                log_global_preaccel_verify_status(
                                                    &st,
                                                    "WinDivert 自动安装后原地热升格",
                                                    &upgraded,
                                                );
                                            }
                                            Ok(upgraded) => {
                                                if upgraded.install_state == "verifying" {
                                                    st.global_preaccel.set_install_state(
                                                        if upgraded.windivert_available {
                                                            "ready"
                                                        } else {
                                                            "idle"
                                                        },
                                                    );
                                                }
                                                let final_upgraded = st.snapshot_global_preaccel();
                                                log_global_preaccel_verify_status(
                                                    &st,
                                                    "WinDivert 自动安装后热升格探测",
                                                    &final_upgraded,
                                                );
                                            }
                                            Err(err) => {
                                                if st.snapshot_global_preaccel().install_state
                                                    == "verifying"
                                                {
                                                    st.global_preaccel.set_install_state("failed");
                                                }
                                                let failed_st = st.snapshot_global_preaccel();
                                                log_global_preaccel_verify_status(
                                                    &st,
                                                    "WinDivert 自动安装后原地热升格失败",
                                                    &failed_st,
                                                );
                                                st.log_app_event(
                                                    "warning",
                                                    "国内提速",
                                                    &format!(
                                                        "WinDivert 驱动就绪后自动热升格失败：{err}"
                                                    ),
                                                );
                                            }
                                        }
                                    }
                                    _ => {
                                        st.global_preaccel.set_install_state("ready");
                                    }
                                }
                            } else if !cur_global.running {
                                if load_enabled_preaccel_relays(&st)
                                    .is_ok_and(|relays| !relays.is_empty())
                                {
                                    match start_global_preaccel_engine(&st, &latest_cfg).await {
                                        Ok(_) => {
                                            if st.snapshot_global_preaccel().install_state
                                                == "verifying"
                                            {
                                                st.global_preaccel.set_install_state("ready");
                                            }
                                        }
                                        Err(err) => {
                                            st.global_preaccel.set_install_state("ready");
                                            st.log_app_event(
                                                "warning",
                                                "国内提速",
                                                &format!(
                                                    "WinDivert 驱动就绪后自动拉起底层透明提速失败：{err}"
                                                ),
                                            );
                                        }
                                    }
                                } else {
                                    st.global_preaccel.set_install_state("ready");
                                }
                            } else {
                                st.global_preaccel.set_install_state("ready");
                            }
                        } else {
                            st.global_preaccel.set_install_state("ready");
                        }
                        drop(_cfg_guard);
                    } else {
                        st.global_preaccel.set_install_state("need_elevation");
                        st.log_app_event(
                            "info",
                            "国内提速",
                            "官方 WinDivert 驱动已自动安装就绪，当前非管理员权限，点击「以管理员重启生效」即可自动加速其它软件",
                        );
                    }
                }
                Err(err) => {
                    st.global_preaccel.set_install_state("failed");
                    st.log_app_event(
                        "warning",
                        "国内提速",
                        &format!("后台自动下载官方 WinDivert 驱动失败（本地 443 通道仍待命）：{err}"),
                    );
                }
            }

            let final_cfg = st.snapshot_config();
            sync_app_side_effects(&app_h, &st, &final_cfg);
            let _ = app_h.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&final_cfg));
        });
    }
    #[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
    {
        let _ = (app, state, cfg);
    }
}

/// Single authoritative entry point for the app-wide unified "国内提速" master switch.
/// Keeps `preaccel.enabled` and `preaccel.global_bypass_enabled` strictly synchronized, reloads
/// the running main core when active, coordinates standalone 443 / WinDivert acceleration, and
/// automatically downloads + hot-upgrades WinDivert in the background on Windows x64 when missing.
pub async fn toggle_preaccel_internal(
    app: &AppHandle,
    state: &AppState,
    enabled: bool,
) -> Result<bool, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    let old_cfg = state.snapshot_config();
    let old_preaccel_enabled = old_cfg.preaccel.enabled;
    let old_preaccel_global = old_cfg.preaccel.global_bypass_enabled;
    let mut cfg = old_cfg.clone();
    let core_running =
        state.snapshot_runtime().running || state.adapter.has_live_controller().await;
    let tun_ready = is_tun_privilege_ready(state);
    let proxy_active = is_proxy_takeover_active(core_running, &cfg, tun_ready);
    let tun_active = core_running && cfg.tun.enabled && tun_ready;

    if enabled {
        cfg.preaccel.sync_unified_enabled(true);
        config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
        if let Ok(mut guard) = state.config.write() {
            *guard = cfg.clone();
        }

        let enabled_relays = load_enabled_preaccel_relays(state)?;
        if enabled_relays.is_empty() {
            state.log_app_event(
                "warning",
                "国内提速",
                "已打开国内提速开关，但尚未配置可用的国内 443 中转线路",
            );
            sync_app_side_effects(app, state, &cfg);
            let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&cfg));
            return Ok(true);
        }

        // 1. If main proxy core is running, reload it to compile in-core 443 pre-acceleration.
        if core_running {
            let _ = trigger_reload_if_running(app, state, false).await;
        }

        // 2. When TUN is not already taking over all host traffic, ensure the standalone
        //    lightweight 443 engine is running (WinDivert excludes CatCloud's full PID tree
        //    so running alongside system-proxy mode has zero self-loop).
        if !tun_active {
            #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
            let wd_present =
                locate_windivert_files(&state.paths, cfg.preaccel.windivert_dir.as_deref())
                    .is_some();
            #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
            let is_elevated = default_platform().capabilities().is_elevated;

            let cur_global = state.snapshot_global_preaccel();
            let engine_res: Result<GlobalPreAccelStatus, String> = if cur_global.running {
                #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
                {
                    if wd_present && is_elevated && !cur_global.is_windivert_active {
                        let excluded_pids = collect_excluded_pids_for_global_preaccel(state);
                        state
                            .global_preaccel
                            .upgrade_to_windivert_in_place(&cfg, &enabled_relays, &excluded_pids)
                            .await
                            .map_err(|e| e.to_string())
                    } else {
                        if wd_present && !is_elevated {
                            state.global_preaccel.set_install_state("need_elevation");
                        }
                        Ok(state.snapshot_global_preaccel())
                    }
                }
                #[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
                {
                    Ok(cur_global)
                }
            } else {
                start_global_preaccel_engine(state, &cfg).await
            };

            match engine_res {
                Ok(global_st) => {
                    let detail = if global_st.is_windivert_active {
                        if proxy_active {
                            "已开启国内提速（猫猫代理 + WinDivert 底层透明加速同时运行）".to_string()
                        } else {
                            "已开启国内提速（WinDivert 底层透明加速运行中）".to_string()
                        }
                    } else if proxy_active {
                        "已开启国内提速（主代理核心已生效，独立通道待命中）".to_string()
                    } else if global_st.install_state == "need_elevation" {
                        "已开启国内提速（本地 443 通道待命，需管理员权限启用底层透明加速）"
                            .to_string()
                    } else if matches!(
                        global_st.install_state.as_str(),
                        "downloading" | "verifying"
                    ) {
                        "已开启国内提速（本地 443 通道已就绪，正在后台自动准备提速组件）"
                            .to_string()
                    } else {
                        match global_st.socks_port {
                            Some(port) => format!(
                                "已开启国内提速并启动本地独立 443 通道（127.0.0.1:{port}）"
                            ),
                            None => "已开启国内提速并启动本地独立 443 通道".to_string(),
                        }
                    };
                    state.log_app_event("info", "国内提速", &detail);
                }
                Err(err) => {
                    if proxy_active {
                        state.log_app_event(
                            "warning",
                            "国内提速",
                            &format!(
                                "猫猫代理内 443 提速已开启，但伴随独立底层通道启动失败：{err}"
                            ),
                        );
                    } else {
                        let mut rollback = state.snapshot_config();
                        rollback.preaccel.enabled = old_preaccel_enabled;
                        rollback.preaccel.global_bypass_enabled = old_preaccel_global;
                        rollback.preaccel.reconcile_unified_enabled();
                        let _ = config::save(&state.paths, &rollback);
                        if let Ok(mut guard) = state.config.write() {
                            *guard = rollback.clone();
                        }
                        state.log_app_event(
                            "error",
                            "国内提速",
                            &format!("启动独立底层国内提速失败：{err}"),
                        );
                        sync_app_side_effects(app, state, &rollback);
                        let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&rollback));
                        return Err(err);
                    }
                }
            }

            #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
            {
                if !wd_present {
                    maybe_spawn_auto_windivert_download(app, state, &cfg);
                } else if !is_elevated {
                    state.global_preaccel.set_install_state("need_elevation");
                }
            }
        } else {
            state.log_app_event("info", "国内提速", "已开启国内 443 提速（虚拟网卡主核心统一生效）");
            maybe_spawn_auto_windivert_download(app, state, &cfg);
        }
    } else {
        cfg.preaccel.sync_unified_enabled(false);
        config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
        if let Ok(mut guard) = state.config.write() {
            *guard = cfg.clone();
        }
        if state.global_preaccel.status().running {
            let _ = state.global_preaccel.stop().await;
        }
        if core_running {
            let _ = trigger_reload_if_running(app, state, false).await;
        }
        state.log_app_event("info", "国内提速", "已关闭国内 443 提速");
    }

    sync_app_side_effects(app, state, &cfg);
    let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&cfg));
    Ok(enabled)
}

#[tauri::command]
pub async fn toggle_preaccel(
    app: AppHandle,
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<bool, String> {
    toggle_preaccel_internal(&app, &state, enabled).await
}

#[tauri::command]
pub fn get_global_preaccel_status(
    state: State<'_, AppState>,
) -> Result<GlobalPreAccelStatus, String> {
    Ok(state.snapshot_global_preaccel())
}

/// Compatibility entry point delegating strictly to the single unified `toggle_preaccel_internal`.
pub async fn toggle_global_preaccel_internal(
    app: &AppHandle,
    state: &AppState,
    enabled: bool,
) -> Result<GlobalPreAccelStatus, String> {
    toggle_preaccel_internal(app, state, enabled).await?;
    Ok(state.snapshot_global_preaccel())
}

#[tauri::command]
pub async fn toggle_global_preaccel(
    app: AppHandle,
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<GlobalPreAccelStatus, String> {
    toggle_global_preaccel_internal(&app, &state, enabled).await
}

#[tauri::command]
pub async fn update_global_preaccel_settings(
    app: AppHandle,
    state: State<'_, AppState>,
    scope: String,
    target_processes: Vec<String>,
    windivert_dir: Option<String>,
) -> Result<GlobalPreAccelStatus, String> {
    let parsed_scope = parse_global_preaccel_scope(&scope)?;
    let normalized_processes = normalize_global_target_processes(target_processes);
    let normalized_dir = windivert_dir
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let _cfg_guard = state.config_transition_lock.lock().await;
    let mut cfg = state.snapshot_config();
    cfg.preaccel.global_scope = parsed_scope;
    cfg.preaccel.global_target_processes = normalized_processes;
    cfg.preaccel.windivert_dir = normalized_dir;

    config::save(&state.paths, &cfg).map_err(|e| format!("保存底层全局提速设置失败：{e}"))?;
    if let Ok(mut guard) = state.config.write() {
        *guard = cfg.clone();
    }

    let was_running = state.global_preaccel.status().running;
    let core_running =
        state.snapshot_runtime().running || state.adapter.has_live_controller().await;
    let tun_active = core_running && effective_tun_enabled(&state, &cfg);
    let status = if was_running && cfg.preaccel.enabled && !tun_active {
        let relays = load_enabled_preaccel_relays(&state)?;
        if relays.is_empty() {
            state.snapshot_global_preaccel()
        } else {
            let excluded_pids = collect_excluded_pids_for_global_preaccel(&state);
            match state
                .global_preaccel
                .restart_windivert_if_running(&cfg, &relays, &excluded_pids)
                .await
            {
                Ok(st) => {
                    log_global_preaccel_verify_status(&state, "底层提速设置热重建", &st);
                    st
                }
                Err(err) => {
                    state.log_app_event(
                        "warning",
                        "国内提速",
                        &format!("更新底层全局提速设置后热重建引擎失败：{err}"),
                    );
                    sync_app_side_effects(&app, &state, &cfg);
                    let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&cfg));
                    return Err(err.to_string());
                }
            }
        }
    } else {
        state.snapshot_global_preaccel()
    };

    state.log_app_event(
        "info",
        "国内提速",
        &format!(
            "已更新底层全局提速设置（范围：{}，目标进程 {} 个）",
            cfg.preaccel.global_scope.as_str(),
            cfg.preaccel.global_target_processes.len()
        ),
    );
    sync_app_side_effects(&app, &state, &cfg);
    let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&cfg));
    Ok(status)
}

#[tauri::command]
pub async fn install_windivert_driver(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<GlobalPreAccelStatus, String> {
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (&app, &state);
        return Err(
            "WinDivert 驱动仅适用于 Windows 平台，当前系统请直接使用内置的本地独立 443 SOCKS5 通道"
                .to_string(),
        );
    }

    #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
    {
        let _ = (&app, &state);
        return Err(
            "当前为 Windows ARM64 架构，官方 WinDivert v2.2.2 未提供原生 ARM64 内核驱动；请使用内置的「本地独立 443 通道 (SOCKS5)」为其它软件提速"
                .to_string(),
        );
    }

    #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
    {
        if state
            .windivert_installing
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err("WinDivert 驱动正在下载安装中，请稍候片刻".to_string());
        }
        let _flag_guard = AtomicFlagResetGuard(Arc::clone(&state.windivert_installing));

        let cfg = state.snapshot_config();
        state.global_preaccel.set_install_state("downloading");
        sync_app_side_effects(&app, &state, &cfg);

        let rt = state.snapshot_runtime();
        let active_mixed_port = if rt.running && rt.mixed_port > 0 {
            Some(rt.mixed_port)
        } else {
            None
        };
        let proxy_candidates = build_default_windivert_proxy_candidates(active_mixed_port);

        let installed_dir = match download_and_install_windivert_with_fallbacks(
            &state.paths,
            &proxy_candidates,
        )
        .await
        {
            Ok(dir) => dir,
            Err(e) => {
                let msg = e.to_string();
                state.global_preaccel.set_install_state("failed");
                state.log_app_event("error", "国内提速", &format!("安装 WinDivert 驱动失败：{msg}"));
                let latest_cfg = state.snapshot_config();
                sync_app_side_effects(&app, &state, &latest_cfg);
                return Err(msg);
            }
        };

        state.global_preaccel.set_install_state("verifying");
        let latest_cfg = state.snapshot_config();
        sync_app_side_effects(&app, &state, &latest_cfg);

        state.log_app_event(
            "info",
            "国内提速",
            &format!(
                "已下载并通过 SHA-256 校验安装官方 WinDivert v2.2.2 驱动至 {}",
                installed_dir.display()
            ),
        );

        if default_platform().capabilities().is_elevated {
            // Acquire outer `config_transition_lock` before checking latest config/TUN and
            // upgrading/starting WinDivert so TUN and WinDivert can never race open.
            let _cfg_guard = state.config_transition_lock.lock().await;
            let latest_cfg = state.snapshot_config();
            let latest_rt = state.snapshot_runtime();
            let tun_active = (latest_rt.running || state.adapter.has_live_controller().await)
                && effective_tun_enabled(&state, &latest_cfg);
            let current = state.snapshot_global_preaccel();
            if !state.shutting_down.load(Ordering::SeqCst)
                && latest_cfg.preaccel.enabled
                && !tun_active
            {
                if current.running && !current.is_windivert_active {
                    match load_enabled_preaccel_relays(&state) {
                        Ok(relays) if !relays.is_empty() => {
                            let excluded_pids = collect_excluded_pids_for_global_preaccel(&state);
                            match state
                                .global_preaccel
                                .upgrade_to_windivert_in_place(&latest_cfg, &relays, &excluded_pids)
                                .await
                            {
                                Ok(upgraded) if upgraded.is_windivert_active => {
                                    log_global_preaccel_verify_status(
                                        &state,
                                        "WinDivert 安装后原地热升格",
                                        &upgraded,
                                    );
                                }
                                Ok(upgraded) => {
                                    if upgraded.install_state == "verifying" {
                                        state.global_preaccel.set_install_state(
                                            if upgraded.windivert_available {
                                                "ready"
                                            } else {
                                                "idle"
                                            },
                                        );
                                    }
                                    let final_upgraded = state.snapshot_global_preaccel();
                                    log_global_preaccel_verify_status(
                                        &state,
                                        "WinDivert 安装后热升格探测",
                                        &final_upgraded,
                                    );
                                }
                                Err(err) => {
                                    if state.snapshot_global_preaccel().install_state == "verifying"
                                    {
                                        state.global_preaccel.set_install_state("failed");
                                    }
                                    let failed_st = state.snapshot_global_preaccel();
                                    log_global_preaccel_verify_status(
                                        &state,
                                        "WinDivert 安装后原地热升格失败",
                                        &failed_st,
                                    );
                                    state.log_app_event(
                                        "warning",
                                        "国内提速",
                                        &format!(
                                            "驱动就绪后原地热升格 WinDivert 透明模式失败：{err}"
                                        ),
                                    );
                                }
                            }
                        }
                        _ => {
                            state.global_preaccel.set_install_state("ready");
                        }
                    }
                } else if !current.running {
                    if load_enabled_preaccel_relays(&state).is_ok_and(|relays| !relays.is_empty()) {
                        match start_global_preaccel_engine(&state, &latest_cfg).await {
                            Ok(_) => {
                                if state.snapshot_global_preaccel().install_state == "verifying" {
                                    state.global_preaccel.set_install_state("ready");
                                }
                            }
                            Err(err) => {
                                state.global_preaccel.set_install_state("ready");
                                state.log_app_event(
                                    "warning",
                                    "国内提速",
                                    &format!("驱动就绪后自动启动 WinDivert 透明模式失败：{err}"),
                                );
                            }
                        }
                    } else {
                        state.global_preaccel.set_install_state("ready");
                    }
                } else {
                    state.global_preaccel.set_install_state("ready");
                }
            } else {
                state.global_preaccel.set_install_state("ready");
            }
            drop(_cfg_guard);
        } else {
            state.global_preaccel.set_install_state("need_elevation");
        }

        let final_cfg = state.snapshot_config();
        sync_app_side_effects(&app, &state, &final_cfg);
        let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&final_cfg));
        Ok(state.snapshot_global_preaccel())
    }
}

#[tauri::command]
pub async fn verify_global_preaccel(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<GlobalPreAccelStatus, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    let cfg = state.snapshot_config();
    let rt = state.snapshot_runtime();
    let core_running = rt.running || state.adapter.has_live_controller().await;
    let tun_active = core_running && effective_tun_enabled(&state, &cfg);
    if !cfg.preaccel.enabled || tun_active {
        return Ok(state.snapshot_global_preaccel());
    }

    let main_core_pid = if rt.running {
        rt.pid.filter(|&p| p > 0)
    } else {
        None
    };
    let is_admin = default_platform().capabilities().is_elevated;
    let relays = load_enabled_preaccel_relays(&state).unwrap_or_default();
    let excluded_pids = collect_excluded_pids_for_global_preaccel(&state);

    state.global_preaccel.sync_main_core_pid(main_core_pid);
    tracing::debug!(
        is_admin,
        ?main_core_pid,
        bin_dir = %state.paths.bin_dir.display(),
        preaccel_enabled = cfg.preaccel.enabled,
        "running on-demand WinDivert dataplane reverification"
    );

    // Push immediate `probing` runtime & tray snapshot before starting dataplane verification so
    // the UI and system tray never falsely show active status while probing is in flight.
    if cfg!(all(target_os = "windows", not(target_arch = "aarch64")))
        && state.snapshot_global_preaccel().running
    {
        emit_preaccel_verify_override_snapshots(&app, &state, "probing", None);
    }

    match state
        .global_preaccel
        .reverify_windivert(&cfg, &relays, &excluded_pids)
        .await
    {
        Ok(status) => {
            log_global_preaccel_verify_status(&state, "手动重新探测底层提速", &status);
            emit_runtime_snapshot(&app, &state);
            refresh_tray(&app, &state);
            Ok(status)
        }
        Err(err) => {
            let err_msg = err.to_string();
            let latest = state.snapshot_global_preaccel();
            log_global_preaccel_verify_status(&state, "手动重新探测底层提速失败", &latest);
            state.log_app_event(
                "warning",
                "国内提速",
                &format!(
                    "手动重新探测底层提速异常（权限：{}）：{err_msg}",
                    if is_admin { "管理员" } else { "普通用户" }
                ),
            );
            emit_runtime_snapshot(&app, &state);
            refresh_tray(&app, &state);
            Err(err_msg)
        }
    }
}

#[tauri::command]
pub async fn relaunch_as_admin_for_global_preaccel(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (&app, &state);
        Err(
            "当前系统无需 Windows 管理员提权，可直接使用内置「本地独立 443 通道」为其它软件提速"
                .to_string(),
        )
    }

    #[cfg(target_os = "windows")]
    {
        // Never dirty-write `preaccel.enabled` / `global_bypass_enabled` to disk before UAC
        // succeeds. The elevated replacement instance receives `--enable-global-preaccel` and
        // persists config only after `toggle_global_preaccel_internal(..., true)` starts cleanly.
        relaunch_self_with_elevation_flags(&app, &state, false, true).await
    }
}

/// Switch active pre-acceleration relay. Caller MUST already hold outer `state.config_transition_lock`.
async fn select_preaccel_relay_locked(
    app: &AppHandle,
    state: &AppState,
    relay_id: String,
) -> Result<String, String> {
    let relay = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        db.get_preaccel_relay(&relay_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("未找到指定国内中转（{relay_id}）"))?
    };
    let mut cfg = state.snapshot_config();
    cfg.preaccel.active_relay_id = Some(relay.id.clone());
    config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
    if let Ok(mut guard) = state.config.write() {
        *guard = cfg.clone();
    }
    if state.adapter.has_live_controller().await {
        let _ = state
            .adapter
            .select_group_proxy(
                catcloud_core::core_adapter::PREACCEL_SELECT_GROUP_NAME,
                &relay.name,
            )
            .await;
    }
    sync_running_global_preaccel_if_active(state, &cfg).await;
    state.log_app_event(
        "info",
        "国内提速",
        &format!("已切换国内提速中转至「{}」", relay.name),
    );
    sync_app_side_effects(app, state, &cfg);
    let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&cfg));
    Ok(relay.id)
}

#[tauri::command]
pub async fn select_preaccel_relay(
    app: AppHandle,
    state: State<'_, AppState>,
    relay_id: String,
) -> Result<String, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    select_preaccel_relay_locked(&app, &state, relay_id).await
}

#[tauri::command]
pub async fn failover_preaccel(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Option<String>, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    let relays = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        db.list_preaccel_relays(true).map_err(|e| e.to_string())?
    };
    if relays.is_empty() {
        return Ok(None);
    }
    let cfg = state.snapshot_config();
    let cur_idx = cfg
        .preaccel
        .active_relay_id
        .as_deref()
        .and_then(|id| relays.iter().position(|r| r.id == id))
        .unwrap_or(relays.len() - 1);
    let next = &relays[(cur_idx + 1) % relays.len()];
    let selected = select_preaccel_relay_locked(&app, &state, next.id.clone()).await?;
    Ok(Some(selected))
}

fn format_tcp_host_port(host: &str, port: u16) -> String {
    let trimmed = host.trim();
    if trimmed.contains(':') && !(trimmed.starts_with('[') && trimmed.ends_with(']')) {
        format!("[{trimmed}]:{port}")
    } else {
        format!("{trimmed}:{port}")
    }
}

#[derive(Debug)]
struct RelayProbeNoCertVerify;

impl rustls::client::danger::ServerCertVerifier for RelayProbeNoCertVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

fn relay_probe_tls_config() -> Arc<rustls::ClientConfig> {
    static TLS_CFG: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    TLS_CFG
        .get_or_init(|| {
            catcloud_core::init_crypto_provider();
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let cfg = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("valid ring TLS protocol versions")
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(RelayProbeNoCertVerify))
                .with_no_client_auth();
            Arc::new(cfg)
        })
        .clone()
}

fn relay_is_udp_quic_protocol(relay: &PreAccelRelay) -> bool {
    matches!(
        relay.protocol.trim().to_ascii_lowercase().as_str(),
        "tuic" | "hysteria2" | "hy2" | "hysteria"
    )
}

fn relay_uses_tls_probe(relay: &PreAccelRelay) -> bool {
    if relay_is_udp_quic_protocol(relay) {
        return false;
    }
    if relay.port == 443 {
        return true;
    }
    matches!(
        relay.protocol.trim().to_ascii_lowercase().as_str(),
        "trojan" | "anytls" | "vless" | "vmess"
    )
}

fn relay_allows_plain_fallback(relay: &PreAccelRelay) -> bool {
    !matches!(
        relay.protocol.trim().to_ascii_lowercase().as_str(),
        "trojan" | "anytls"
    )
}

/// Align relay TLS probe SNI with `preaccel/generator.rs` compilation rules:
/// domestic `:443` relays always strip `relay.sni` and probe with bare host/IP (`relay.server`),
/// while non-443 relays prefer configured `relay.sni` when present.
fn resolve_relay_probe_sni_or_host(relay: &PreAccelRelay) -> String {
    let bare_host = relay
        .server
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']');
    if relay.port == 443 {
        return bare_host.to_string();
    }
    relay
        .sni
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(bare_host)
        .to_string()
}

fn is_local_or_private_host(host: &str) -> bool {
    let bare = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']');
    if bare.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match bare.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
        }
        Err(_) => false,
    }
}

async fn measure_relay_tls_handshake_ms(
    addr: &str,
    sni_or_host: &str,
    timeout: Duration,
) -> Result<f64, String> {
    let server_name = rustls::pki_types::ServerName::try_from(sni_or_host.to_string())
        .or_else(|_| rustls::pki_types::ServerName::try_from("localhost".to_string()))
        .map_err(|e| format!("解析中转主机名失败：{e}"))?;
    let tls_cfg = relay_probe_tls_config();

    let handshake_fut = async move {
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("连接国内中转失败：{e}"))?;
        let _ = stream.set_nodelay(true);

        // Start timing right before TLS ClientHello: even when Wintun/TUN proxies TCP SYN-ACK
        // locally in <1ms, the TLS ServerHello MUST arrive from the remote relay server.
        let tls_started = Instant::now();
        let mut conn = rustls::ClientConnection::new(tls_cfg, server_name)
            .map_err(|e| format!("初始化 TLS 探测失败：{e}"))?;
        let mut write_buf = Vec::with_capacity(2048);
        let mut read_buf = [0u8; 4096];

        while conn.is_handshaking() {
            while conn.wants_write() {
                write_buf.clear();
                conn.write_tls(&mut write_buf)
                    .map_err(|e| format!("构造 TLS 握手包失败：{e}"))?;
                if !write_buf.is_empty() {
                    stream
                        .write_all(&write_buf)
                        .await
                        .map_err(|e| format!("发送 TLS 握手包失败：{e}"))?;
                }
            }
            if !conn.is_handshaking() {
                break;
            }
            if conn.wants_read() {
                let n = stream
                    .read(&mut read_buf)
                    .await
                    .map_err(|e| format!("读取远端 TLS 响应失败：{e}"))?;
                if n == 0 {
                    return Err("远端在 TLS 握手完成前关闭了连接".to_string());
                }
                let mut slice = &read_buf[..n];
                while !slice.is_empty() {
                    let read_in = conn
                        .read_tls(&mut slice)
                        .map_err(|e| format!("解析远端 TLS 响应失败：{e}"))?;
                    if read_in == 0 {
                        break;
                    }
                    conn.process_new_packets()
                        .map_err(|e| format!("TLS 握手未通过：{e}"))?;
                }
            } else if !conn.wants_write() {
                break;
            }
        }

        let ms = (tls_started.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0;
        Ok(ms.max(0.1))
    };

    match tokio::time::timeout(timeout, handshake_fut).await {
        Ok(res) => res,
        Err(_) => Err("中转 TLS 握手超时（4 秒）".to_string()),
    }
}

async fn measure_relay_plain_rtt_ms(relay: &PreAccelRelay) -> Result<f64, String> {
    let addr = format_tcp_host_port(&relay.server, relay.port);
    let started = Instant::now();
    match tokio::time::timeout(Duration::from_secs(4), TcpStream::connect(&addr)).await {
        Ok(Ok(_stream)) => {
            let ms = started.elapsed().as_secs_f64() * 1000.0;
            if !is_local_or_private_host(&relay.server) && ms < 2.0 {
                // Likely synthetic local SYN-ACK from Wintun TUN; try an end-to-end HTTP probe.
                if let Ok(client) = reqwest::Client::builder()
                    .no_proxy()
                    .danger_accept_invalid_certs(true)
                    .connect_timeout(Duration::from_secs(3))
                    .timeout(Duration::from_secs(3))
                    .build()
                {
                    let http_url = format!("http://{addr}/");
                    let http_started = Instant::now();
                    match client.get(&http_url).send().await {
                        Ok(_resp) => {
                            let h_ms = http_started.elapsed().as_secs_f64() * 1000.0;
                            if h_ms >= 2.0 {
                                return Ok(((h_ms * 10.0).round() / 10.0).max(0.1));
                            }
                        }
                        Err(err) if !err.is_timeout() && !err.is_connect() => {
                            let h_ms = http_started.elapsed().as_secs_f64() * 1000.0;
                            if h_ms >= 2.0 {
                                return Ok(((h_ms * 10.0).round() / 10.0).max(0.1));
                            }
                        }
                        Err(_) => {}
                    }
                }
                return Err(
                    "虚拟网卡接管了明文 TCP 握手，无法测得真实延迟（建议改用 443/TLS 中转或关闭虚拟网卡后重试）"
                        .to_string(),
                );
            }
            Ok(((ms * 10.0).round() / 10.0).max(0.1))
        }
        Ok(Err(err)) => Err(format!("TCP 连接中转失败：{err}")),
        Err(_) => Err("TCP 连接超时（4 秒）".to_string()),
    }
}

/// Native UDP/QUIC end-to-end RTT probe for pure UDP/QUIC relays (`tuic`, `hysteria2`, `hy2`,
/// `hysteria`), avoiding meaningless 4s TCP TLS handshake failures against UDP-only endpoints.
/// Sends an RFC 9000 QUIC Version Negotiation trigger (1200-byte Long Header with GREASE version)
/// so compliant QUIC servers reply statelessly in 1 RTT without credentials.
async fn measure_relay_udp_quic_rtt_ms(relay: &PreAccelRelay) -> Result<f64, String> {
    let addr = format_tcp_host_port(relay.server.trim(), relay.port);
    let target = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::lookup_host(addr.as_str()),
    )
    .await
    .map_err(|_| "解析 UDP/QUIC 中转地址超时（2 秒）".to_string())?
    .map_err(|e| format!("解析 UDP/QUIC 中转地址失败：{e}"))?
    .next()
    .ok_or_else(|| "未能解析到有效的 UDP/QUIC 中转 IP 地址".to_string())?;

    let bind_addr = if target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = tokio::net::UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| format!("创建本地 UDP 探测套接字失败：{e}"))?;
    socket
        .connect(target)
        .await
        .map_err(|e| format!("绑定 UDP/QUIC 中转目标失败：{e}"))?;

    let mut probe_pkt = vec![0u8; 1200];
    probe_pkt[0] = 0xc0; // QUIC Long Header | Fixed Bit
    probe_pkt[1..5].copy_from_slice(&[0x0a, 0x0a, 0x0a, 0x0a]); // GREASE version
    probe_pkt[5] = 8; // DCID len
    probe_pkt[6..14].copy_from_slice(b"CATCLOUD");
    probe_pkt[14] = 8; // SCID len
    probe_pkt[15..23].copy_from_slice(b"PROBE001");

    let started = Instant::now();
    socket
        .send(&probe_pkt)
        .await
        .map_err(|e| format!("发送 UDP/QUIC 探测包失败：{e}"))?;

    let mut recv_buf = [0u8; 2048];
    match tokio::time::timeout(Duration::from_millis(2500), socket.recv(&mut recv_buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let ms = (started.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0;
            Ok(ms.max(0.1))
        }
        Ok(Ok(_)) => Err("UDP/QUIC 中转返回了空响应".to_string()),
        Ok(Err(err)) => Err(format!("UDP/QUIC 中转端口不可达或被拒绝：{err}")),
        Err(_) => Err(
            "UDP/QUIC 中转探测超时（2.5 秒，服务端可能未开放 UDP 端口或启用了静默防探测）"
                .to_string(),
        ),
    }
}

/// Measure real end-to-end RTT to a domestic pre-acceleration relay without falling prey to
/// Wintun/TUN synthetic `<1ms` local TCP SYN-ACK responses.
async fn measure_relay_real_rtt_ms(relay: &PreAccelRelay) -> Result<f64, String> {
    let host = relay.server.trim();
    if host.is_empty() || relay.port == 0 {
        return Err("中转服务器地址或端口无效".to_string());
    }
    if relay_is_udp_quic_protocol(relay) {
        return measure_relay_udp_quic_rtt_ms(relay).await;
    }
    let addr = format_tcp_host_port(host, relay.port);
    if relay_uses_tls_probe(relay) {
        let sni_or_host = resolve_relay_probe_sni_or_host(relay);
        match measure_relay_tls_handshake_ms(&addr, &sni_or_host, Duration::from_secs(4)).await {
            Ok(ms) => Ok(ms),
            Err(tls_err) => {
                if relay_allows_plain_fallback(relay) {
                    measure_relay_plain_rtt_ms(relay).await.or(Err(tls_err))
                } else {
                    Err(tls_err)
                }
            }
        }
    } else {
        measure_relay_plain_rtt_ms(relay).await
    }
}

#[tauri::command]
pub async fn test_preaccel_relays(
    state: State<'_, AppState>,
    relay_ids: Option<Vec<String>>,
) -> Result<serde_json::Value, String> {
    const MAX_RELAY_PROBE_CONCURRENCY: usize = 4;

    let relays = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let all = db.list_preaccel_relays(false).map_err(|e| e.to_string())?;
        if let Some(ids) = relay_ids {
            all.into_iter().filter(|r| ids.contains(&r.id)).collect()
        } else {
            all
        }
    };

    let total_count = relays.len();
    let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_RELAY_PROBE_CONCURRENCY));
    let mut join_set = tokio::task::JoinSet::new();

    for (idx, relay) in relays.into_iter().enumerate() {
        let sem = Arc::clone(&semaphore);
        join_set.spawn(async move {
            let _permit = sem.acquire_owned().await.ok();
            let probe_res = measure_relay_real_rtt_ms(&relay).await;
            (idx, relay, probe_res)
        });
    }

    let mut ordered_outcomes: Vec<(usize, PreAccelRelay, Result<f64, String>)> =
        Vec::with_capacity(total_count);
    while let Some(joined) = join_set.join_next().await {
        if let Ok(item) = joined {
            ordered_outcomes.push(item);
        }
    }
    ordered_outcomes.sort_by_key(|(idx, _, _)| *idx);

    let mut results = Vec::with_capacity(total_count);
    let mut ok_count = 0usize;
    let mut metrics_updates: Vec<(String, f64, Option<f64>, Option<f64>)> = Vec::new();
    for (_idx, relay, probe_res) in ordered_outcomes {
        match probe_res {
            Ok(ms) if ms.is_finite() && ms > 0.0 => {
                ok_count += 1;
                let rounded = ((ms * 10.0).round() / 10.0).max(0.1);
                metrics_updates.push((
                    relay.id.clone(),
                    rounded,
                    relay.last_up_mbps.or(relay.last_mbps),
                    relay.last_down_mbps,
                ));
                results.push(serde_json::json!({
                    "relay_id": relay.id,
                    "ok": true,
                    "latency_ms": rounded,
                    "error": null
                }));
            }
            Ok(_) => {
                results.push(serde_json::json!({
                    "relay_id": relay.id,
                    "ok": false,
                    "latency_ms": null,
                    "error": "未测得有效的端到端延迟"
                }));
            }
            Err(err) => {
                results.push(serde_json::json!({
                    "relay_id": relay.id,
                    "ok": false,
                    "latency_ms": null,
                    "error": err
                }));
            }
        }
    }
    if !metrics_updates.is_empty() {
        if let Ok(db) = state.storage.lock() {
            for (relay_id, rounded, last_up_mbps, last_down_mbps) in metrics_updates {
                let _ = db.update_preaccel_speed_metrics(
                    &relay_id,
                    Some(rounded),
                    last_up_mbps,
                    last_down_mbps,
                );
            }
        }
    }
    state.log_app_event(
        if ok_count == total_count { "info" } else { "warning" },
        "国内提速",
        &format!("国内中转真实 RTT 测速完成：可用 {ok_count}/{total_count}"),
    );
    Ok(serde_json::Value::Array(results))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PreAccelSideSpeedDto {
    ok: bool,
    latency_ms: Option<f64>,
    up_mbps: Option<f64>,
    down_mbps: Option<f64>,
    error: Option<String>,
}

fn is_info_placeholder_node(node: &ProxyNode) -> bool {
    const HINTS: &[&str] = &[
        "剩余流量",
        "剩餘流量",
        "过期时间",
        "過期時間",
        "到期",
        "套餐",
        "官网",
        "官網",
        "重置",
        "距离下次",
        "更新订阅",
    ];
    HINTS.iter().any(|h| node.name.contains(h))
}

fn resolve_homepage_node<'a>(
    groups: &'a [MultiGroup],
    nodes: &'a [ProxyNode],
    route_mode: RouteTargetMode,
    active_single_node_id: Option<&str>,
    active_group_id: Option<&str>,
) -> Option<&'a ProxyNode> {
    if route_mode == RouteTargetMode::Single {
        if let Some(node) = active_single_node_id
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|nid| nodes.iter().find(|n| n.id == nid))
        {
            return Some(node);
        }
    }

    let primary_group = active_group_id
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|gid| groups.iter().find(|g| g.id == gid))
        .or_else(|| groups.first());

    match primary_group {
        Some(g) => resolve_valid_group_active_node(g, nodes),
        None => nodes.iter().find(|n| n.enabled).or_else(|| nodes.first()),
    }
}

fn select_comparison_overseas_node(
    groups: &[MultiGroup],
    nodes: &[ProxyNode],
    route_mode: RouteTargetMode,
    active_single_node_id: Option<&str>,
    active_group_id: Option<&str>,
    requested_node_id: Option<&str>,
) -> Result<(ProxyNode, Option<String>), String> {
    if let Some(nid) = requested_node_id.map(str::trim).filter(|s| !s.is_empty()) {
        let node = nodes
            .iter()
            .find(|n| n.id == nid)
            .cloned()
            .ok_or_else(|| "未找到指定的海外节点，请刷新节点列表后重试".to_string())?;
        if node.is_udp_only_transport() {
            return Err(
                "所选海外节点为纯 UDP 协议（Hysteria2/TUIC/WireGuard），暂不支持走国内 TCP 中转对比，请改选 VLESS/Trojan/SS/VMess 节点"
                    .to_string(),
            );
        }
        return Ok((node, None));
    }

    let homepage_node = resolve_homepage_node(
        groups,
        nodes,
        route_mode,
        active_single_node_id,
        active_group_id,
    );

    if let Some(home) = homepage_node {
        if home.enabled && !home.is_udp_only_transport() {
            return Ok((home.clone(), None));
        }
    }

    let mut seen = std::collections::HashSet::new();
    let mut ordered: Vec<&ProxyNode> = Vec::with_capacity(nodes.len());

    let primary_group = active_group_id
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|gid| groups.iter().find(|g| g.id == gid))
        .or_else(|| groups.first());

    if let Some(group) = primary_group {
        if let Some(ref aid) = group.active_node_id {
            let in_group = group.member_node_ids.is_empty()
                || group.member_node_ids.iter().any(|m| m == aid);
            if in_group {
                if let Some(n) = nodes.iter().find(|n| &n.id == aid) {
                    if seen.insert(n.id.as_str()) {
                        ordered.push(n);
                    }
                }
            }
        }
        for mid in &group.member_node_ids {
            if let Some(n) = nodes.iter().find(|n| &n.id == mid) {
                if seen.insert(n.id.as_str()) {
                    ordered.push(n);
                }
            }
        }
    }
    for n in nodes {
        if seen.insert(n.id.as_str()) {
            ordered.push(n);
        }
    }

    let tcp_enabled: Vec<&ProxyNode> = ordered
        .into_iter()
        .filter(|n| n.enabled && !n.is_udp_only_transport())
        .collect();

    let picked = tcp_enabled
        .iter()
        .find(|n| !n.is_443_native && !is_info_placeholder_node(n))
        .or_else(|| tcp_enabled.iter().find(|n| !n.is_443_native))
        .or_else(|| tcp_enabled.iter().find(|n| !is_info_placeholder_node(n)))
        .or_else(|| tcp_enabled.first())
        .copied()
        .cloned()
        .ok_or_else(|| {
            "暂无可用于对比测速的海外节点（请先导入至少 1 个已启用的非纯 UDP 海外节点）"
                .to_string()
        })?;

    let fallback_reason = match homepage_node {
        Some(home) if home.is_udp_only_transport() => Some(format!(
            "首页当前节点「{}」是纯 UDP 协议无法套 TCP 中转，已自动改测「{}」",
            home.name, picked.name
        )),
        Some(home) if !home.enabled => Some(format!(
            "首页当前节点「{}」已禁用，已自动改测「{}」",
            home.name, picked.name
        )),
        _ => None,
    };

    Ok((picked, fallback_reason))
}

fn calc_boost_ratio(accel: Option<f64>, direct: Option<f64>) -> Option<f64> {
    let a = accel?;
    let d = direct?;
    if !a.is_finite() || !d.is_finite() || a <= 0.0 || d <= 0.01 {
        return None;
    }
    Some(((a / d) * 100.0).round() / 100.0)
}

fn summarize_throughput_probe_error(direction: &str, detail: Option<&str>) -> String {
    let raw = detail.unwrap_or("").trim();
    if raw.is_empty() {
        return format!("{direction}未返回有效速率");
    }
    let lower = raw.to_ascii_lowercase();
    if lower.contains("timed out") || lower.contains("timeout") {
        format!("{direction}超时")
    } else if lower.contains("fast_fuse_triggered") {
        format!("{direction}速率过低触发保护熔断（<0.2 Mbps）")
    } else if lower.contains("unexpected upload http status")
        || lower.contains("unexpected download http status")
    {
        format!("{direction}测速节点返回异常状态码（{raw}）")
    } else if lower.contains("connection reset")
        || lower.contains("broken pipe")
        || lower.contains("unexpected eof")
        || lower.contains("closed")
    {
        format!("{direction}连接被远端中途断开")
    } else if lower.contains("error sending request") || lower.contains("connect") {
        format!("{direction}建连失败（线路握手超时或受阻）")
    } else {
        format!("{direction}失败（{raw}）")
    }
}

fn format_side_log_summary(side: &PreAccelSideSpeedDto) -> String {
    let lat = side
        .latency_ms
        .map(|v| format!("{v:.1}ms"))
        .unwrap_or_else(|| "--".to_string());
    let up = side
        .up_mbps
        .map(|v| format!("{v:.2}Mbps"))
        .unwrap_or_else(|| "--".to_string());
    let down = side
        .down_mbps
        .map(|v| format!("{v:.2}Mbps"))
        .unwrap_or_else(|| "--".to_string());
    match side.error.as_deref() {
        Some(err) if !err.trim().is_empty() => {
            format!("ok={} 延迟={} 上行={} 下行={} 备注={}", side.ok, lat, up, down, err)
        }
        _ => format!("ok={} 延迟={} 上行={} 下行={}", side.ok, lat, up, down),
    }
}

async fn run_preaccel_comparison_side(
    proxy_port: u16,
    node_id: &str,
    label: &str,
) -> PreAccelSideSpeedDto {
    let measured_latency: Arc<Mutex<Option<f64>>> = Arc::new(Mutex::new(None));
    let measured_up: Arc<Mutex<Option<f64>>> = Arc::new(Mutex::new(None));
    let measured_down: Arc<Mutex<Option<f64>>> = Arc::new(Mutex::new(None));
    let measured_latency_ref = Arc::clone(&measured_latency);
    let measured_up_ref = Arc::clone(&measured_up);
    let measured_down_ref = Arc::clone(&measured_down);

    let side_fut = async move {
        let client = match build_isolated_http_client(proxy_port, Duration::from_secs(12)) {
            Ok(c) => c,
            Err(e) => {
                return PreAccelSideSpeedDto {
                    ok: false,
                    latency_ms: None,
                    up_mbps: None,
                    down_mbps: None,
                    error: Some(format!("{label}初始化测速通道失败：{e}")),
                };
            }
        };

        let latency_def = ProbeDefinition {
            id: "preaccel_cmp_latency".to_string(),
            name: "Comparison Latency".to_string(),
            kind: catcloud_core::models::ProbeKind::Latency,
            target_url: "https://cp.cloudflare.com/generate_204".to_string(),
            method: "GET".to_string(),
            expected_status: Some(204),
            body_regex: None,
            payload_bytes: None,
            timeout_ms: 3500,
            builtin: false,
        };
        let lat_rec = match tokio::time::timeout(
            Duration::from_secs(6),
            run_latency_probe(&client, node_id, &latency_def, 2),
        )
        .await
        {
            Ok(rec) => rec,
            Err(_) => {
                return PreAccelSideSpeedDto {
                    ok: false,
                    latency_ms: None,
                    up_mbps: None,
                    down_mbps: None,
                    error: Some(format!("{label}延迟探测超时（6 秒）")),
                };
            }
        };
        if let Some(lat_ms) = lat_rec.latency_ms.filter(|v| v.is_finite() && *v > 0.0) {
            if let Ok(mut guard) = measured_latency_ref.lock() {
                *guard = Some(lat_ms);
            }
        }
        if !lat_rec.ok {
            let reason = lat_rec
                .detail
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|d| format!("{label}连通测试失败：{d}"))
                .unwrap_or_else(|| format!("{label}连通测试失败，请检查中转或海外节点是否可用"));
            return PreAccelSideSpeedDto {
                ok: false,
                latency_ms: lat_rec.latency_ms,
                up_mbps: None,
                down_mbps: None,
                error: Some(reason),
            };
        }

        // Lightweight Keep-Alive warmup against speed.cloudflare.com so dual-hop cold TLS
        // handshake does not burn upload/download timeout budget on fresh proxy start.
        let _ = tokio::time::timeout(Duration::from_secs(4), async {
            if let Ok(resp) = client
                .get("https://speed.cloudflare.com/__down?bytes=1")
                .timeout(Duration::from_secs(4))
                .send()
                .await
            {
                let _ = resp.bytes().await;
            }
        })
        .await;

        let tp_cfg = ThroughputProbeConfig {
            fuse_bytes: 512 * 1024,
            fuse_min_mbps: 0.2,
            max_payload_bytes: 2 * 1024 * 1024,
        };

        let upload_def = ProbeDefinition {
            id: "preaccel_cmp_upload".to_string(),
            name: "Comparison Upload".to_string(),
            kind: catcloud_core::models::ProbeKind::Upload,
            target_url: "https://speed.cloudflare.com/__up".to_string(),
            method: "POST".to_string(),
            expected_status: Some(200),
            body_regex: None,
            payload_bytes: Some(2 * 1024 * 1024),
            timeout_ms: 9000,
            builtin: false,
        };
        let (up_mbps, up_err): (Option<f64>, Option<String>) = match tokio::time::timeout(
            Duration::from_secs(20),
            run_upload_probe_with_config(&client, node_id, &upload_def, &tp_cfg),
        )
        .await
        {
            Ok(rec) => {
                let speed = rec.up_mbps.filter(|&v| v.is_finite() && v > 0.0);
                if speed.is_some() {
                    (speed, None)
                } else {
                    (
                        None,
                        Some(summarize_throughput_probe_error(
                            "上行测速",
                            rec.detail.as_deref(),
                        )),
                    )
                }
            }
            Err(_) => (None, Some("上行测速超时（20 秒）".to_string())),
        };
        if let Some(speed) = up_mbps {
            if let Ok(mut guard) = measured_up_ref.lock() {
                *guard = Some(speed);
            }
        }

        let download_def = ProbeDefinition {
            id: "preaccel_cmp_download".to_string(),
            name: "Comparison Download".to_string(),
            kind: catcloud_core::models::ProbeKind::Download,
            target_url: "https://speed.cloudflare.com/__down?bytes=2097152".to_string(),
            method: "GET".to_string(),
            expected_status: Some(200),
            body_regex: None,
            payload_bytes: Some(2 * 1024 * 1024),
            timeout_ms: 8000,
            builtin: false,
        };
        let (down_mbps, down_err): (Option<f64>, Option<String>) = match tokio::time::timeout(
            Duration::from_secs(18),
            run_download_probe_with_config(&client, node_id, &download_def, &tp_cfg),
        )
        .await
        {
            Ok(rec) => {
                let speed = rec.down_mbps.filter(|&v| v.is_finite() && v > 0.0);
                if speed.is_some() {
                    (speed, None)
                } else {
                    (
                        None,
                        Some(summarize_throughput_probe_error(
                            "下行测速",
                            rec.detail.as_deref(),
                        )),
                    )
                }
            }
            Err(_) => (None, Some("下行测速超时（18 秒）".to_string())),
        };
        if let Some(speed) = down_mbps {
            if let Ok(mut guard) = measured_down_ref.lock() {
                *guard = Some(speed);
            }
        }

        let ok = up_mbps.is_some() || down_mbps.is_some();
        let error = match (up_mbps.is_some(), down_mbps.is_some()) {
            (true, true) => None,
            (true, false) => Some(format!(
                "{}（上行正常）",
                down_err.unwrap_or_else(|| "下行测速超时".to_string())
            )),
            (false, true) => Some(format!(
                "{}（下行正常）",
                up_err.unwrap_or_else(|| "上行测速超时".to_string())
            )),
            (false, false) => Some(format!(
                "{label}上下行测速均未通过（{}；{}）",
                up_err.unwrap_or_else(|| "上行超时".to_string()),
                down_err.unwrap_or_else(|| "下行超时".to_string())
            )),
        };

        PreAccelSideSpeedDto {
            ok,
            latency_ms: lat_rec.latency_ms,
            up_mbps,
            down_mbps,
            error,
        }
    };

    match tokio::time::timeout(Duration::from_secs(44), side_fut).await {
        Ok(res) => res,
        Err(_) => {
            let preserved_latency = measured_latency.lock().ok().and_then(|g| *g);
            let preserved_up = measured_up.lock().ok().and_then(|g| *g);
            let preserved_down = measured_down.lock().ok().and_then(|g| *g);
            let ok = preserved_up.is_some() || preserved_down.is_some();
            PreAccelSideSpeedDto {
                ok,
                latency_ms: preserved_latency,
                up_mbps: preserved_up,
                down_mbps: preserved_down,
                error: Some(format!("{label}测速超过 44 秒已自动中止")),
            }
        }
    }
}

#[tauri::command]
pub async fn benchmark_preaccel_comparison(
    app: AppHandle,
    state: State<'_, AppState>,
    relay_id: Option<String>,
    node_id: Option<String>,
) -> Result<serde_json::Value, String> {
    if state
        .probe_running
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("当前已有测速任务正在进行，请等待完成或先暂停后再开始对比测速".to_string());
    }
    let _running_guard = ProbeRunningGuard::enter(&app, &state);

    let cfg = state.snapshot_config();
    let extra_candidates = state.extra_binary_candidates();
    let resolution = resolve_mihomo_binary(&cfg, &state.paths, &extra_candidates, false)
        .map_err(|e| format!("查找代理核心失败：{e}"))?;
    let Some(mihomo_bin) = resolution.path else {
        return Err("未找到 Mihomo 核心文件，无法执行国内提速对比测速".to_string());
    };

    let (relay, target_node, fallback_reason) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let relay = if let Some(rid) = relay_id.as_deref().map(str::trim).filter(|s| !s.is_empty())
        {
            db.get_preaccel_relay(rid)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "未找到指定的国内中转节点，请刷新页面后重试".to_string())?
        } else {
            let enabled_relays = db.list_preaccel_relays(true).map_err(|e| e.to_string())?;
            if enabled_relays.is_empty() {
                return Err(
                    "暂无已启用的国内中转节点，请先添加并启用至少 1 个国内中转".to_string(),
                );
            }
            cfg.preaccel
                .active_relay_id
                .as_deref()
                .and_then(|aid| enabled_relays.iter().find(|r| r.id == aid).cloned())
                .unwrap_or_else(|| enabled_relays[0].clone())
        };

        if relay.server.trim().is_empty() || relay.port == 0 {
            return Err("所选国内中转缺少有效的服务器地址或端口".to_string());
        }

        let groups = db.list_multi_groups().map_err(|e| e.to_string())?;
        let nodes = db.list_nodes().map_err(|e| e.to_string())?;
        let (target_node, fallback_reason) = select_comparison_overseas_node(
            &groups,
            &nodes,
            cfg.route_mode,
            cfg.active_single_node_id.as_deref(),
            cfg.active_group_id.as_deref(),
            node_id.as_deref(),
        )?;
        (relay, target_node, fallback_reason)
    };

    state.log_app_event(
        "info",
        "对比测速",
        &format!(
            "开始国内提速对比测速：中转「{}」+ 海外节点「{}」",
            relay.name, target_node.name
        ),
    );

    // Measure true end-to-end RTT to the domestic relay (immune to Wintun synthetic 0~1ms TCP ACK).
    let relay_real_rtt_ms = measure_relay_real_rtt_ms(&relay)
        .await
        .ok()
        .filter(|&v| v.is_finite() && v > 0.0);

    let temp_root = state.paths.runtime_dir.join("probe_sandbox");
    std::fs::create_dir_all(&temp_root).map_err(|e| format!("创建后台测速目录失败：{e}"))?;

    let (probe_core, accel_port, direct_port) = IsolatedProbeCore::spawn_for_preaccel_comparison(
        &mihomo_bin,
        &temp_root,
        &state.job_guard,
        &relay,
        &target_node,
        &[],
        DEFAULT_READY_TIMEOUT,
    )
    .await
    .map_err(|e| {
        let msg = format_mihomo_error_for_user(&format!("启动对比测速核心失败：{e}"));
        state.log_app_event("error", "对比测速", &msg);
        msg
    })?;

    // Run sequentially so accelerated and direct sides do not compete for local uplink bandwidth.
    let accelerated =
        run_preaccel_comparison_side(accel_port, &target_node.id, "国内提速通道").await;
    let direct = run_preaccel_comparison_side(direct_port, &target_node.id, "普通直连通道").await;

    let _ = probe_core.shutdown().await;

    let recorded_relay_ms = relay_real_rtt_ms
        .or(accelerated.latency_ms.filter(|&v| v.is_finite() && v > 0.0))
        .or(relay.last_probe_ms.filter(|&v| v.is_finite() && v > 0.0));
    let recorded_up_mbps = accelerated
        .up_mbps
        .filter(|&v| v.is_finite() && v > 0.0)
        .or(relay.last_up_mbps)
        .or(relay.last_mbps);
    let recorded_down_mbps = accelerated
        .down_mbps
        .filter(|&v| v.is_finite() && v > 0.0)
        .or(relay.last_down_mbps);
    if recorded_relay_ms.is_some() || recorded_up_mbps.is_some() || recorded_down_mbps.is_some() {
        if let Ok(db) = state.storage.lock() {
            let _ = db.update_preaccel_speed_metrics(
                &relay.id,
                recorded_relay_ms,
                recorded_up_mbps,
                recorded_down_mbps,
            );
        }
    }

    let up_boost_ratio = calc_boost_ratio(accelerated.up_mbps, direct.up_mbps);
    let down_boost_ratio = calc_boost_ratio(accelerated.down_mbps, direct.down_mbps);

    let overall_ok = accelerated.ok || direct.ok;
    let log_level = if accelerated.ok { "info" } else { "warning" };
    let direct_note = if accelerated.ok && !direct.ok {
        let reason = direct
            .error
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("直连对照通道超时或不可达");
        format!(" | 说明：提速边实测畅通，普通直连对照组未完成（{reason}，常见于运营商对海外非 443 端口限速或丢包）")
    } else if accelerated.ok && direct.error.is_some() {
        let reason = direct
            .error
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("部分阶段超时");
        format!(" | 说明：提速边实测畅通，直连对照组存在部分超时（{reason}）")
    } else {
        String::new()
    };
    let relay_rtt_text = relay_real_rtt_ms
        .map(|v| format!("{v:.1}ms"))
        .unwrap_or_else(|| "--".to_string());
    state.log_app_event(
        log_level,
        "对比测速",
        &format!(
            "对比测速完成：中转「{}」(真实RTT={relay_rtt_text}) / 节点「{}」| 提速边[{}] | 直连边[{}] | 上行倍率={:?} 下行倍率={:?}{direct_note}",
            relay.name,
            target_node.name,
            format_side_log_summary(&accelerated),
            format_side_log_summary(&direct),
            up_boost_ratio,
            down_boost_ratio
        ),
    );

    Ok(serde_json::json!({
        "ok": overall_ok,
        "relay_id": relay.id,
        "relay_name": relay.name,
        "node_id": target_node.id,
        "node_name": target_node.name,
        "fallback_reason": fallback_reason,
        "accelerated": accelerated,
        "direct": direct,
        "up_boost_ratio": up_boost_ratio,
        "down_boost_ratio": down_boost_ratio,
        "tested_at": Utc::now().to_rfc3339()
    }))
}

fn select_target_relays_ordered(
    all_relays: Vec<PreAccelRelay>,
    relay_ids: Option<Vec<String>>,
) -> Vec<PreAccelRelay> {
    let Some(ids) = relay_ids else {
        return all_relays;
    };
    let by_id: HashMap<&str, &PreAccelRelay> =
        all_relays.iter().map(|r| (r.id.as_str(), r)).collect();
    let mut seen: HashSet<String> = HashSet::new();
    ids.into_iter()
        .filter_map(|raw_id| {
            let trimmed = raw_id.trim();
            if trimmed.is_empty() || !seen.insert(trimmed.to_string()) {
                return None;
            }
            by_id.get(trimmed).map(|r| (*r).clone())
        })
        .collect()
}

#[tauri::command]
pub async fn test_preaccel_relay_speeds(
    app: AppHandle,
    state: State<'_, AppState>,
    relay_ids: Option<Vec<String>>,
    node_id: Option<String>,
) -> Result<serde_json::Value, String> {
    if state
        .probe_running
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("当前已有测速任务正在进行，请等待完成后再测中转上下行".to_string());
    }
    let _running_guard = ProbeRunningGuard::enter(&app, &state);

    let cfg = state.snapshot_config();
    let extra_candidates = state.extra_binary_candidates();
    let resolution = resolve_mihomo_binary(&cfg, &state.paths, &extra_candidates, false)
        .map_err(|e| format!("查找代理核心失败：{e}"))?;
    let Some(mihomo_bin) = resolution.path else {
        return Err("未找到 Mihomo 核心文件，无法执行国内中转上下行测速".to_string());
    };

    let (target_relays, reference_node) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let all_relays = db.list_preaccel_relays(false).map_err(|e| e.to_string())?;
        let target_relays = select_target_relays_ordered(all_relays, relay_ids);
        if target_relays.is_empty() {
            return Ok(serde_json::Value::Array(Vec::new()));
        }

        let groups = db.list_multi_groups().map_err(|e| e.to_string())?;
        let nodes = db.list_nodes().map_err(|e| e.to_string())?;
        let reference_node = select_comparison_overseas_node(
            &groups,
            &nodes,
            cfg.route_mode,
            cfg.active_single_node_id.as_deref(),
            cfg.active_group_id.as_deref(),
            node_id.as_deref(),
        )
        .ok()
        .or_else(|| {
            if node_id
                .as_deref()
                .map(str::trim)
                .is_some_and(|s| !s.is_empty())
            {
                select_comparison_overseas_node(
                    &groups,
                    &nodes,
                    cfg.route_mode,
                    cfg.active_single_node_id.as_deref(),
                    cfg.active_group_id.as_deref(),
                    None,
                )
                .ok()
            } else {
                None
            }
        })
        .map(|(node, _)| node);

        (target_relays, reference_node)
    };

    let mode_str = if reference_node.is_some() {
        "via_node"
    } else {
        "relay_direct"
    };
    let reference_node_name = reference_node.as_ref().map(|n| n.name.clone());

    let valid_relays: Vec<PreAccelRelay> = target_relays
        .iter()
        .filter(|r| !r.server.trim().is_empty() && r.port > 0)
        .cloned()
        .collect();

    if valid_relays.is_empty() {
        let results: Vec<serde_json::Value> = target_relays
            .iter()
            .map(|relay| {
                serde_json::json!({
                    "relay_id": relay.id,
                    "relay_name": relay.name,
                    "ok": false,
                    "latency_ms": null,
                    "up_mbps": null,
                    "down_mbps": null,
                    "mode": mode_str,
                    "reference_node_name": reference_node_name,
                    "error": "中转缺少有效的服务器地址或端口"
                })
            })
            .collect();
        state.log_app_event(
            "warning",
            "国内提速",
            &format!(
                "国内中转真实上下行测速已跳过：{} 条中转均缺少有效的服务器地址或端口",
                target_relays.len()
            ),
        );
        return Ok(serde_json::Value::Array(results));
    }

    let mode_desc = match reference_node_name.as_deref() {
        Some(name) => format!("经海外对照节点「{name}」"),
        None => "单跳直测中转本身".to_string(),
    };
    state.log_app_event(
        "info",
        "国内提速",
        &format!(
            "开始国内中转真实上下行测速：共 {} 条（有效 {} 条，模式：{mode_desc}）",
            target_relays.len(),
            valid_relays.len()
        ),
    );

    let temp_root = state.paths.runtime_dir.join("probe_sandbox");
    std::fs::create_dir_all(&temp_root).map_err(|e| format!("创建后台测速目录失败：{e}"))?;

    let (probe_core, relay_ports) = IsolatedProbeCore::spawn_for_preaccel_relay_speeds(
        &mihomo_bin,
        &temp_root,
        &state.job_guard,
        &valid_relays,
        reference_node.as_ref(),
        &[],
        DEFAULT_READY_TIMEOUT,
    )
    .await
    .map_err(|e| {
        let msg = format_mihomo_error_for_user(&format!("启动中转上下行测速核心失败：{e}"));
        state.log_app_event("error", "国内提速", &msg);
        msg
    })?;
    let port_map: HashMap<String, u16> = relay_ports.into_iter().collect();

    let total_count = target_relays.len();
    let mut ok_count = 0usize;
    let mut results = Vec::with_capacity(total_count);

    // Run strictly sequentially per relay to prevent local uplink bandwidth contention.
    for relay in &target_relays {
        if relay.server.trim().is_empty() || relay.port == 0 {
            results.push(serde_json::json!({
                "relay_id": relay.id,
                "relay_name": relay.name,
                "ok": false,
                "latency_ms": null,
                "up_mbps": null,
                "down_mbps": null,
                "mode": mode_str,
                "reference_node_name": reference_node_name,
                "error": "中转缺少有效的服务器地址或端口"
            }));
            continue;
        }
        let Some(&port) = port_map.get(&relay.id) else {
            results.push(serde_json::json!({
                "relay_id": relay.id,
                "relay_name": relay.name,
                "ok": false,
                "latency_ms": null,
                "up_mbps": null,
                "down_mbps": null,
                "mode": mode_str,
                "reference_node_name": reference_node_name,
                "error": "未能为该中转分配测速通道，请检查协议与参数配置"
            }));
            continue;
        };

        let relay_real_rtt_ms = measure_relay_real_rtt_ms(relay)
            .await
            .ok()
            .filter(|v| v.is_finite() && *v > 0.0)
            .map(|ms| ((ms * 10.0).round() / 10.0).max(0.1));

        let side = run_preaccel_comparison_side(
            port,
            &relay.id,
            &format!("中转「{}」", relay.name),
        )
        .await;

        let side_latency_ms = side
            .latency_ms
            .filter(|v| v.is_finite() && *v > 0.0)
            .map(|ms| ((ms * 10.0).round() / 10.0).max(0.1));
        let recorded_ms = relay_real_rtt_ms.or(side_latency_ms);
        let recorded_up = side.up_mbps.filter(|v| v.is_finite() && *v > 0.0);
        let recorded_down = side.down_mbps.filter(|v| v.is_finite() && *v > 0.0);
        let ok = side.ok;
        if ok {
            ok_count += 1;
        }

        if recorded_ms.is_some() || recorded_up.is_some() || recorded_down.is_some() {
            if let Ok(db) = state.storage.lock() {
                let _ = db.update_preaccel_speed_metrics(
                    &relay.id,
                    recorded_ms,
                    recorded_up,
                    recorded_down,
                );
            }
        }

        results.push(serde_json::json!({
            "relay_id": relay.id,
            "relay_name": relay.name,
            "ok": ok,
            "latency_ms": recorded_ms,
            "up_mbps": recorded_up,
            "down_mbps": recorded_down,
            "mode": mode_str,
            "reference_node_name": reference_node_name,
            "error": side.error
        }));
    }

    let _ = probe_core.shutdown().await;

    state.log_app_event(
        if ok_count == total_count {
            "info"
        } else {
            "warning"
        },
        "国内提速",
        &format!(
            "国内中转真实上下行测速完成：可用 {ok_count}/{total_count}（模式：{mode_desc}）"
        ),
    );

    Ok(serde_json::Value::Array(results))
}

#[tauri::command]
pub async fn check_campus_portal(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let cfg = state.snapshot_config();
    let observed = probe_campus_portal_with_fallback(
        &cfg.preaccel.probe_url,
        Some(cfg.preaccel.fallback_probe_url.as_str()),
        Duration::from_secs(5),
    )
    .await;

    let transition = {
        let mut tracker = state.campus_tracker.lock().map_err(|e| e.to_string())?;
        tracker.apply_state(observed.clone())
    };
    if transition.rules_changed {
        let _ = trigger_reload_if_running(&app, &state, true).await;
    }
    sync_app_side_effects(&app, &state, &cfg);

    let (required, status_code, redirect_location) = match &observed {
        CampusPortalState::Connected => (false, Some(204u16), None),
        CampusPortalState::CaptivePortalRequired {
            portal_url,
            status_code,
            ..
        } => (true, Some(*status_code), Some(portal_url.clone())),
        CampusPortalState::Offline { .. } => (false, None, None),
    };

    Ok(serde_json::json!({
        "captive_portal_required": required,
        "state": observed,
        "status_code": status_code,
        "redirect_location": redirect_location,
        "bypass_hosts": transition.active_fake_ip_filter,
        "direct_rules": transition.active_direct_rules,
        "checked_at": Utc::now().to_rfc3339()
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GeoIpLookupResult {
    ip: String,
    isp: String,
    location: String,
    timezone: String,
}

fn join_location_parts(city: Option<&str>, country: Option<&str>) -> String {
    let c = city.map(str::trim).filter(|s| !s.is_empty());
    let co = country.map(str::trim).filter(|s| !s.is_empty());
    match (c, co) {
        (Some(city_s), Some(country_s)) if !city_s.eq_ignore_ascii_case(country_s) => {
            format!("{city_s}, {country_s}")
        }
        (Some(city_s), _) => city_s.to_string(),
        (None, Some(country_s)) => country_s.to_string(),
        (None, None) => "未知地区".to_string(),
    }
}

fn parse_ipsb_geoip_json(val: &serde_json::Value) -> Option<GeoIpLookupResult> {
    let ip = val.get("ip").and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty())?;
    let isp = val
        .get("isp")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            val.get("organization")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
        })
        .unwrap_or("未知运营商")
        .to_string();
    let city = val.get("city").and_then(|v| v.as_str());
    let country = val.get("country").and_then(|v| v.as_str());
    let location = join_location_parts(city, country);
    let timezone = val
        .get("timezone")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("未知时区")
        .to_string();
    Some(GeoIpLookupResult {
        ip: ip.to_string(),
        isp,
        location,
        timezone,
    })
}

fn parse_ipwhois_json(val: &serde_json::Value) -> Option<GeoIpLookupResult> {
    if val.get("success").and_then(|v| v.as_bool()) == Some(false) {
        return None;
    }
    let ip = val.get("ip").and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty())?;
    let conn = val.get("connection");
    let isp = conn
        .and_then(|c| c.get("isp"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            conn.and_then(|c| c.get("org"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
        })
        .unwrap_or("未知运营商")
        .to_string();
    let city = val.get("city").and_then(|v| v.as_str());
    let country = val.get("country").and_then(|v| v.as_str());
    let location = join_location_parts(city, country);
    let tz = val.get("timezone");
    let timezone = tz
        .and_then(|t| t.get("id"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            tz.and_then(|t| t.get("utc"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
        })
        .unwrap_or("未知时区")
        .to_string();
    Some(GeoIpLookupResult {
        ip: ip.to_string(),
        isp,
        location,
        timezone,
    })
}

fn parse_cloudflare_trace(body: &str) -> Option<GeoIpLookupResult> {
    let mut ip = String::new();
    let mut loc = String::new();
    let mut colo = String::new();
    for line in body.lines() {
        if let Some(v) = line.strip_prefix("ip=") {
            ip = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("loc=") {
            loc = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("colo=") {
            colo = v.trim().to_string();
        }
    }
    if ip.is_empty() {
        return None;
    }
    Some(GeoIpLookupResult {
        ip,
        isp: if colo.is_empty() {
            "Cloudflare 出口已连通".to_string()
        } else {
            format!("Cloudflare 接入节点 {colo}")
        },
        location: if loc.is_empty() {
            "未知地区".to_string()
        } else {
            loc
        },
        timezone: "未知时区".to_string(),
    })
}

const MAX_GEOIP_RESPONSE_BYTES: usize = 64 * 1024;

async fn read_bounded_response_bytes(
    mut resp: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    if let Some(len) = resp.content_length() {
        if len > max_bytes as u64 {
            return Err(format!(
                "出口检测响应体过大（{len} 字节，超出 {max_bytes} 字节上限）"
            ));
        }
    }
    let initial_cap = resp
        .content_length()
        .map(|n| (n as usize).min(max_bytes))
        .unwrap_or(4096);
    let mut buf = Vec::with_capacity(initial_cap);
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("读取出口检测响应失败：{e}"))?
    {
        if buf.len().saturating_add(chunk.len()) > max_bytes {
            return Err(format!("出口检测响应体超出 {max_bytes} 字节安全上限"));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

async fn query_exit_geoip(client: &reqwest::Client) -> Result<GeoIpLookupResult, String> {
    let mut last_err = String::new();

    // 1. Primary: api.ip.sb/geoip
    match client.get("https://api.ip.sb/geoip").send().await {
        Ok(resp) if resp.status().is_success() => {
            match read_bounded_response_bytes(resp, MAX_GEOIP_RESPONSE_BYTES).await {
                Ok(bytes) => {
                    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        if let Some(parsed) = parse_ipsb_geoip_json(&val) {
                            return Ok(parsed);
                        }
                    }
                }
                Err(err) => {
                    last_err = err;
                }
            }
        }
        Ok(resp) => {
            last_err = format!("出口检测响应异常（HTTP {}）", resp.status().as_u16());
        }
        Err(err) => {
            last_err = if err.is_timeout() {
                "出口检测超时，请检查当前路线是否可用".to_string()
            } else {
                "无法连接出口检测服务，请切换路线后重试".to_string()
            };
        }
    }

    // 2. Fallback: ipwho.is
    match client.get("https://ipwho.is/").send().await {
        Ok(resp) if resp.status().is_success() => {
            match read_bounded_response_bytes(resp, MAX_GEOIP_RESPONSE_BYTES).await {
                Ok(bytes) => {
                    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        if let Some(parsed) = parse_ipwhois_json(&val) {
                            return Ok(parsed);
                        }
                    }
                }
                Err(err) => {
                    if last_err.is_empty() {
                        last_err = err;
                    }
                }
            }
        }
        Ok(resp) => {
            if last_err.is_empty() {
                last_err = format!("出口检测响应异常（HTTP {}）", resp.status().as_u16());
            }
        }
        Err(err) => {
            if last_err.is_empty() {
                last_err = if err.is_timeout() {
                    "出口检测超时，请检查当前路线是否可用".to_string()
                } else {
                    "无法连接出口检测服务，请切换路线后重试".to_string()
                };
            }
        }
    }

    // 3. Final fallback: Cloudflare trace
    match client
        .get("https://www.cloudflare.com/cdn-cgi/trace")
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            match read_bounded_response_bytes(resp, MAX_GEOIP_RESPONSE_BYTES).await {
                Ok(bytes) => {
                    let body = String::from_utf8_lossy(&bytes);
                    if let Some(parsed) = parse_cloudflare_trace(&body) {
                        return Ok(parsed);
                    }
                }
                Err(err) => {
                    if last_err.is_empty() {
                        last_err = err;
                    }
                }
            }
        }
        Ok(resp) => {
            if last_err.is_empty() {
                last_err = format!("出口检测响应异常（HTTP {}）", resp.status().as_u16());
            }
        }
        Err(err) => {
            if last_err.is_empty() {
                last_err = if err.is_timeout() {
                    "出口检测超时，请检查当前路线是否可用".to_string()
                } else {
                    "无法连接出口检测服务，请切换路线后重试".to_string()
                };
            }
        }
    }

    if last_err.is_empty() {
        Err("未能解析出口 IP 信息，请稍后重试".to_string())
    } else {
        Err(last_err)
    }
}

#[tauri::command]
pub async fn get_exit_ip_info(state: State<'_, AppState>) -> Result<ExitIpInfoDto, String> {
    let cfg = state.snapshot_config();
    let rt = state.adapter.status().await;
    state.update_cached_runtime(rt.clone());
    if !rt.running {
        return Ok(ExitIpInfoDto {
            ip_masked: "--.--.--.***".to_string(),
            ip_raw: None,
            isp: "核心未启动".to_string(),
            location: "未连接".to_string(),
            timezone: "UTC+8".to_string(),
            google_clean: None,
            core_running: false,
        });
    }

    if rt.proxy_mode == ProxyMode::Direct || cfg.proxy_mode == ProxyMode::Direct {
        return Ok(ExitIpInfoDto {
            ip_masked: "--.--.--.***".to_string(),
            ip_raw: None,
            isp: "当前处于直连模式（不经代理节点）".to_string(),
            location: "本地直连".to_string(),
            timezone: "UTC+8".to_string(),
            google_clean: None,
            core_running: true,
        });
    }

    let proxy_url = format!("socks5h://127.0.0.1:{}", rt.mixed_port);
    let geo_proxy = reqwest::Proxy::all(&proxy_url)
        .map_err(|e| format!("初始化出口检测代理通道失败：{e}"))?;
    let geo_client = reqwest::Client::builder()
        .no_proxy()
        .proxy(geo_proxy)
        .user_agent("CatCloud/1.0")
        .timeout(Duration::from_secs(6))
        .build()
        .map_err(|e| format!("初始化出口检测客户端失败：{e}"))?;

    let google_proxy = reqwest::Proxy::all(&proxy_url)
        .map_err(|e| format!("初始化谷歌送中检测代理通道失败：{e}"))?;
    let google_client = reqwest::Client::builder()
        .no_proxy()
        .proxy(google_proxy)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| format!("初始化谷歌送中检测客户端失败：{e}"))?;

    let (geo_res, google_assessment) = tokio::join!(
        query_exit_geoip(&geo_client),
        probe_live_google_cleanliness(&google_client, Duration::from_secs(5))
    );

    let live_google_clean = if google_assessment
        .reasons
        .iter()
        .any(|r| r == "no_google_ground_truth")
    {
        None
    } else {
        Some(google_assessment.google_clean)
    };

    match geo_res {
        Ok(info) => Ok(ExitIpInfoDto {
            ip_masked: mask_ip_address(&info.ip),
            ip_raw: Some(info.ip),
            isp: info.isp,
            location: info.location,
            timezone: info.timezone,
            google_clean: live_google_clean,
            core_running: true,
        }),
        Err(reason) => Ok(ExitIpInfoDto {
            ip_masked: "--.--.--.***".to_string(),
            ip_raw: None,
            isp: reason,
            location: "暂未获取到位置".to_string(),
            timezone: "未知时区".to_string(),
            google_clean: live_google_clean,
            core_running: true,
        }),
    }
}

fn normalize_quick_site_probe_url(raw: &str) -> String {
    let trimmed = raw.trim();
    let stripped = trimmed.trim_end_matches('/');
    if stripped.eq_ignore_ascii_case("https://chatgpt.com")
        || stripped.eq_ignore_ascii_case("http://chatgpt.com")
        || stripped.eq_ignore_ascii_case("https://www.chatgpt.com")
        || stripped.eq_ignore_ascii_case("http://www.chatgpt.com")
    {
        return "https://chatgpt.com/cdn-cgi/trace".to_string();
    }
    trimmed.to_string()
}

#[tauri::command]
pub async fn check_quick_sites(state: State<'_, AppState>) -> Result<Vec<SiteCheckItemDto>, String> {
    let cfg = state.snapshot_config();
    let rt = state.adapter.status().await;
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(7))
        .pool_max_idle_per_host(8)
        .redirect(reqwest::redirect::Policy::none());
    if rt.running {
        let proxy_url = format!("socks5h://127.0.0.1:{}", rt.mixed_port);
        if let Ok(proxy) = reqwest::Proxy::all(&proxy_url) {
            builder = builder.proxy(proxy);
        }
    }
    let client = builder
        .build()
        .map_err(|e| format!("初始化网站测活客户端失败：{e}"))?;

    let mut handles = Vec::new();
    for site in cfg.core_runtime.quick_check_sites {
        let cli = client.clone();
        handles.push(tokio::spawn(async move {
            let probe_url = normalize_quick_site_probe_url(&site.url);
            let expected_status = site.expected_status;
            let check_status = |status: u16| {
                expected_status
                    .map(|exp| status == exp)
                    .unwrap_or((200..300).contains(&status))
            };

            // 1. Warmup connection (establish SOCKS5 + TLS tunnel and drain small body for Keep-Alive reuse).
            let t0 = Instant::now();
            let first = match cli.get(&probe_url).send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let _ = read_bounded_response_bytes(resp, 16 * 1024).await;
                    let ms = t0.elapsed().as_millis() as u64;
                    (ms, check_status(status))
                }
                Err(_) => {
                    return SiteCheckItemDto {
                        id: site.id,
                        name: site.name,
                        url: site.url,
                        latency_ms: None,
                        ok: Some(false),
                    };
                }
            };

            // 2. Measure true warm RTT over the reused connection (still strictly checking expected_status).
            let t1 = Instant::now();
            let (final_ms, final_ok) = match cli.get(&probe_url).send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let _ = read_bounded_response_bytes(resp, 16 * 1024).await;
                    let ms = t1.elapsed().as_millis() as u64;
                    (ms, check_status(status))
                }
                Err(_) => first,
            };

            SiteCheckItemDto {
                id: site.id,
                name: site.name,
                url: site.url,
                latency_ms: Some(final_ms),
                ok: Some(final_ok),
            }
        }));
    }

    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        if let Ok(item) = h.await {
            out.push(item);
        }
    }
    Ok(out)
}

#[tauri::command]
pub async fn get_active_connections(
    state: State<'_, AppState>,
) -> Result<ConnectionsSnapshot, String> {
    if !state.adapter.has_live_controller().await {
        return Ok(ConnectionsSnapshot::default());
    }
    state
        .adapter
        .list_connections()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn close_connection(state: State<'_, AppState>, id: String) -> Result<bool, String> {
    if !state.adapter.has_live_controller().await {
        return Err("代理核心尚未运行，无法操作连接".to_string());
    }
    state
        .adapter
        .close_connection(&id)
        .await
        .map_err(|e| format!("断开指定连接失败：{e}"))?;
    Ok(true)
}

#[tauri::command]
pub async fn close_group_connections(
    state: State<'_, AppState>,
    group_name: String,
) -> Result<usize, String> {
    if !state.adapter.has_live_controller().await {
        return Err("代理核心尚未运行，无法操作连接".to_string());
    }
    state
        .adapter
        .close_connections_for_group_or_node(Some(&group_name), None)
        .await
        .map_err(|e| format!("断开分组连接失败：{e}"))
}

#[tauri::command]
pub async fn close_all_connections(state: State<'_, AppState>) -> Result<usize, String> {
    if !state.adapter.has_live_controller().await {
        return Err("代理核心尚未运行，无法操作连接".to_string());
    }
    let count = state
        .adapter
        .list_connections()
        .await
        .map(|s| summarize_connections(&s.connections).app_connections)
        .unwrap_or(0);
    state
        .adapter
        .close_all_connections()
        .await
        .map_err(|e| format!("断开全部连接失败：{e}"))?;
    Ok(count)
}

#[tauri::command]
pub fn get_recent_logs(
    state: State<'_, AppState>,
    limit: Option<usize>,
) -> Result<Vec<CoreLogLine>, String> {
    let mut logs = state.telemetry.logs_snapshot();
    if let Some(lim) = limit {
        if logs.len() > lim {
            logs = logs.split_off(logs.len() - lim);
        }
    }
    Ok(logs)
}

fn build_traffic_history(state: &AppState) -> Vec<TrafficEventPayload> {
    let ticks = state.telemetry.traffic_snapshot();
    if ticks.is_empty() {
        return Vec::new();
    }
    let metrics = state
        .cached_metrics
        .read()
        .map(|m| *m)
        .unwrap_or_default();
    let core_memory_mb = (metrics.core_mem_bytes as f64) / (1024.0 * 1024.0);
    let mut points: Vec<TrafficEventPayload> = ticks
        .into_iter()
        .map(|t| TrafficEventPayload {
            up_bps: t.up,
            down_bps: t.down,
            up_total_bytes: 0,
            down_total_bytes: 0,
            active_connections: 0,
            tunnel_connections: 0,
            core_memory_mb,
            timestamp_ms: t.timestamp_ms,
        })
        .collect();
    if let Some(last) = points.last_mut() {
        last.up_total_bytes = metrics.up_total_bytes;
        last.down_total_bytes = metrics.down_total_bytes;
        last.active_connections = metrics.app_connections;
        last.tunnel_connections = metrics.tunnel_connections;
    }
    points
}

#[tauri::command]
pub fn get_traffic_history(state: State<'_, AppState>) -> Vec<TrafficEventPayload> {
    if !state.snapshot_runtime().running {
        return Vec::new();
    }
    build_traffic_history(&state)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentModuleDocDto {
    pub id: String,
    pub module_id: String,
    pub file_name: String,
    pub lang: String,
    pub title: String,
    pub summary: String,
    pub when_to_use_and_signals: Vec<String>,
    pub external_prereqs_and_schema: Vec<String>,
    pub gui_and_cli_verification: Vec<String>,
    pub rollback_and_troubleshooting: Vec<String>,
    pub contract_example: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentBootstrapPromptDto {
    pub prompt: String,
    pub cli_path: String,
    pub data_dir: String,
    pub docs_index_path: String,
    pub lang: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportAgentDocOutcome {
    pub cancelled: bool,
    pub path: Option<String>,
    pub bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GithubIssueDraftDto {
    pub issue_url: String,
    pub clipboard_markdown: String,
    pub title: String,
}

fn canonical_agent_doc_filename(module_id: &str) -> &'static str {
    match catcloud_core::agent_docs::resolve_canonical_doc_id(module_id)
        .unwrap_or(module_id)
    {
        catcloud_core::agent_docs::TROUBLESHOOTING_DOC_ID => "00-general-troubleshooting.md",
        catcloud_core::agent_docs::ONBOARDING_DOC_ID => "01-onboarding.md",
        catcloud_core::agent_docs::PREACCEL_DOC_ID => "02-domestic-preaccel.md",
        catcloud_core::agent_docs::MULTIGROUP_DOC_ID => "03-multigroup.md",
        catcloud_core::agent_docs::NODES_PROBES_DOC_ID => "04-nodes-and-probes.md",
        catcloud_core::agent_docs::ROUTING_CONNS_DOC_ID => "05-routing-and-connections.md",
        catcloud_core::agent_docs::NETWORK_LIFECYCLE_DOC_ID => "06-network-and-lifecycle.md",
        catcloud_core::agent_docs::SHARE_BUNDLE_DOC_ID => "07-share-bundle.md",
        _ => "00-general-troubleshooting.md",
    }
}

fn resolve_effective_doc_lang(state: &AppState, lang: Option<&str>) -> &'static str {
    if let Some(explicit) = lang.map(str::trim).filter(|s| !s.is_empty()) {
        catcloud_core::agent_docs::normalize_doc_lang(Some(explicit))
    } else {
        let cfg = state.snapshot_config();
        catcloud_core::agent_docs::normalize_doc_lang(Some(&cfg.personalization.language))
    }
}

fn resolve_local_cli_path_from(
    exe_dir: Option<&std::path::Path>,
    resource_dir: Option<&std::path::Path>,
    bin_dir: &std::path::Path,
    root_data_dir: &std::path::Path,
) -> std::path::PathBuf {
    let cli_bin = if cfg!(target_os = "windows") {
        "catcloud.exe"
    } else {
        "catcloud"
    };
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    let norm_exe_dir = exe_dir.map(catcloud_core::paths::normalize_os_path);

    if let Some(ref dir) = norm_exe_dir {
        candidates.push(dir.join("cli").join(cli_bin));
        candidates.push(dir.join("resources").join("cli").join(cli_bin));
        candidates.push(dir.join(cli_bin));
    }
    if let Some(res_dir) = resource_dir {
        let norm_res = catcloud_core::paths::normalize_os_path(res_dir);
        candidates.push(norm_res.join("resources").join("cli").join(cli_bin));
        candidates.push(norm_res.join("cli").join(cli_bin));
        candidates.push(norm_res.join(cli_bin));
    }
    let norm_bin_dir = catcloud_core::paths::normalize_os_path(bin_dir);
    candidates.push(norm_bin_dir.join(cli_bin));
    let norm_root_data = catcloud_core::paths::normalize_os_path(root_data_dir);
    candidates.push(norm_root_data.join("cli").join(cli_bin));
    if let Some(ref dir) = norm_exe_dir {
        if let Some(parent) = dir.parent() {
            candidates.push(parent.join("cli").join(cli_bin));
            candidates.push(parent.join("Resources").join("resources").join("cli").join(cli_bin));
            candidates.push(parent.join("Resources").join("cli").join(cli_bin));
            candidates.push(parent.join("lib").join("CatCloud").join("resources").join("cli").join(cli_bin));
            candidates.push(parent.join("share").join("CatCloud").join("resources").join("cli").join(cli_bin));
            candidates.push(parent.join("share").join("catcloud").join("resources").join("cli").join(cli_bin));
        }
    }
    #[cfg(target_os = "linux")]
    {
        candidates.push(std::path::PathBuf::from("/usr/lib/CatCloud/resources/cli").join(cli_bin));
        candidates.push(std::path::PathBuf::from("/usr/share/CatCloud/resources/cli").join(cli_bin));
    }

    for candidate in &candidates {
        if candidate.is_file() {
            return catcloud_core::paths::normalize_os_path(candidate);
        }
    }

    if let Some(dir) = norm_exe_dir {
        catcloud_core::paths::normalize_os_path(&dir.join("cli").join(cli_bin))
    } else {
        catcloud_core::paths::normalize_os_path(&norm_bin_dir.join(cli_bin))
    }
}

fn resolve_local_cli_path(state: &AppState) -> std::path::PathBuf {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(std::path::Path::to_path_buf));
    let resource_dir = state
        .resource_dir
        .read()
        .ok()
        .and_then(|guard| guard.clone());
    resolve_local_cli_path_from(
        exe_dir.as_deref(),
        resource_dir.as_deref(),
        &state.paths.bin_dir,
        &state.paths.root_data_dir,
    )
}

#[tauri::command]
pub fn list_agent_docs(
    state: State<'_, AppState>,
    lang: Option<String>,
) -> Vec<AgentModuleDocDto> {
    let norm_lang = resolve_effective_doc_lang(&state, lang.as_deref());
    catcloud_core::agent_docs::list_agent_docs_for_lang(norm_lang)
        .into_iter()
        .map(|doc| {
            let file_name = canonical_agent_doc_filename(&doc.module_id).to_string();
            AgentModuleDocDto {
                id: doc.module_id.clone(),
                module_id: doc.module_id,
                file_name,
                lang: norm_lang.to_string(),
                title: doc.title,
                summary: doc.summary,
                when_to_use_and_signals: doc.when_to_use_and_signals,
                external_prereqs_and_schema: doc.external_prereqs_and_schema,
                gui_and_cli_verification: doc.gui_and_cli_verification,
                rollback_and_troubleshooting: doc.rollback_and_troubleshooting,
                contract_example: doc.contract_example,
            }
        })
        .collect()
}

#[tauri::command]
pub fn export_agent_docs(
    state: State<'_, AppState>,
    module_id: String,
    as_json: bool,
    lang: Option<String>,
) -> Result<String, String> {
    let norm_lang = resolve_effective_doc_lang(&state, lang.as_deref());
    catcloud_core::agent_docs::export_agent_docs_with_lang(&module_id, as_json, norm_lang)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn build_agent_bootstrap_prompt(
    state: State<'_, AppState>,
    lang: Option<String>,
    current_page: Option<String>,
) -> Result<AgentBootstrapPromptDto, String> {
    let norm_lang = resolve_effective_doc_lang(&state, lang.as_deref());
    let cli_path = resolve_local_cli_path(&state).to_string_lossy().to_string();
    let data_dir_pb = catcloud_core::paths::normalize_os_path(&state.paths.root_data_dir);
    let data_dir = data_dir_pb.to_string_lossy().to_string();
    let docs_index_pb = data_dir_pb.join("agent_docs").join(norm_lang).join("INDEX.md");

    if !docs_index_pb.is_file() {
        let sync_root = data_dir_pb.clone();
        let _ = tokio::task::spawn_blocking(move || {
            catcloud_core::agent_docs::sync_agent_docs_to_disk(&sync_root)
        })
        .await;
    }

    let docs_index_path = docs_index_pb.to_string_lossy().to_string();
    let page = current_page.as_deref().unwrap_or("overview");
    let prompt = catcloud_core::agent_docs::render_agent_bootstrap_prompt(
        &cli_path,
        &data_dir,
        &docs_index_path,
        page,
        norm_lang,
    );

    Ok(AgentBootstrapPromptDto {
        prompt,
        cli_path,
        data_dir,
        docs_index_path,
        lang: norm_lang.to_string(),
    })
}

#[tauri::command]
pub async fn export_agent_doc_file_dialog(
    app: AppHandle,
    state: State<'_, AppState>,
    module_id: String,
    lang: Option<String>,
) -> Result<ExportAgentDocOutcome, String> {
    use tauri_plugin_dialog::DialogExt;

    let norm_lang = resolve_effective_doc_lang(&state, lang.as_deref());
    let content = catcloud_core::agent_docs::export_agent_docs_with_lang(
        &module_id,
        false,
        norm_lang,
    )
    .map_err(|e| e.to_string())?;

    let trimmed_mod = module_id.trim().to_ascii_lowercase();
    let default_filename = if trimmed_mod.is_empty() || trimmed_mod == "all" {
        format!("catcloud-guide-all-{norm_lang}.md")
    } else if let Some(canonical) = catcloud_core::agent_docs::resolve_canonical_doc_id(&trimmed_mod)
    {
        canonical_agent_doc_filename(canonical).to_string()
    } else {
        format!(
            "catcloud-guide-{}-{norm_lang}.md",
            sanitize_dialog_filename_stem(&trimmed_mod, "doc")
        )
    };

    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_title("导出猫猫云梯权威手册 (.md)")
        .set_file_name(&default_filename)
        .add_filter("Markdown 文档", &["md"])
        .save_file(move |file_path| {
            let _ = tx.send(file_path);
        });

    let picked = rx.await.map_err(|_| "导出手册已取消".to_string())?;
    let Some(file_path) = picked else {
        return Ok(ExportAgentDocOutcome {
            cancelled: true,
            path: None,
            bytes: 0,
        });
    };
    let mut target_path = file_path
        .into_path()
        .map_err(|e| format!("无法解析所选保存路径：{e}"))?;
    if target_path
        .extension()
        .and_then(|e| e.to_str())
        .is_none_or(|ext| !ext.eq_ignore_ascii_case("md"))
    {
        target_path.set_extension("md");
    }

    let bytes = content.len();
    let write_path = target_path.clone();
    tokio::task::spawn_blocking(move || AppPaths::atomic_write(&write_path, content.as_bytes()))
        .await
        .map_err(|e| format!("保存手册文件任务异常：{e}"))?
        .map_err(|e| format!("写入手册文件失败：{e}"))?;

    Ok(ExportAgentDocOutcome {
        cancelled: false,
        path: Some(target_path.to_string_lossy().to_string()),
        bytes,
    })
}

const GITHUB_ISSUE_URL_BODY_MAX_CHARS: usize = 600;
const GITHUB_ISSUE_KEY_EVENTS_LIMIT: usize = 12;

fn is_generic_protocol_or_mode_token(token: &str) -> bool {
    matches!(
        token.trim().to_ascii_lowercase().as_str(),
        "rule"
            | "global"
            | "direct"
            | "reject"
            | "proxy"
            | "auto"
            | "default"
            | "group"
            | "single"
            | "ok"
            | "warn"
            | "error"
            | "idle"
            | "http"
            | "https"
            | "socks"
            | "socks5"
            | "tcp"
            | "udp"
            | "tun"
            | "dns"
            | "ip"
            | "cn"
            | "us"
            | "jp"
            | "hk"
            | "sg"
            | "tw"
            | "uk"
            | "de"
            | "fr"
            | "kr"
            | "mihomo"
            | "catcloud"
            | "windows"
            | "macos"
            | "linux"
    )
}

fn replace_ascii_case_insensitive(haystack: &str, needle: &str, replacement: &str) -> String {
    if needle.is_empty() || !needle.is_ascii() {
        return haystack.replace(needle, replacement);
    }
    let needle_bytes = needle.as_bytes();
    let h_bytes = haystack.as_bytes();
    if needle_bytes.len() > h_bytes.len() {
        return haystack.to_string();
    }
    let mut out = String::with_capacity(haystack.len());
    let mut i = 0;
    while i < h_bytes.len() {
        if i + needle_bytes.len() <= h_bytes.len()
            && h_bytes[i..i + needle_bytes.len()].eq_ignore_ascii_case(needle_bytes)
        {
            out.push_str(replacement);
            i += needle_bytes.len();
        } else {
            let ch = haystack[i..].chars().next().unwrap_or(' ');
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// Strip all user-defined node / multi-group / relay / subscription remark names from text
/// and apply full `sanitize_log_line` redaction so public GitHub Issues never leak private names.
fn strip_user_custom_labels(raw: &str, custom_labels: &[String]) -> String {
    let mut labels: Vec<String> = Vec::with_capacity(custom_labels.len() * 2);
    let mut seen: HashSet<String> = HashSet::new();
    for raw_label in custom_labels {
        let trimmed = raw_label.trim();
        if trimmed.chars().count() < 2 || is_generic_protocol_or_mode_token(trimmed) {
            continue;
        }
        if seen.insert(trimmed.to_string()) {
            labels.push(trimmed.to_string());
        }
        let sanitized_variant = app_log::sanitize_log_line(trimmed);
        let sv_trim = sanitized_variant.trim();
        if sv_trim.chars().count() >= 2
            && !is_generic_protocol_or_mode_token(sv_trim)
            && seen.insert(sv_trim.to_string())
        {
            labels.push(sv_trim.to_string());
        }
    }
    labels.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));

    let mut out = raw.to_string();
    for label in &labels {
        if label.is_ascii() {
            out = replace_ascii_case_insensitive(&out, label, "<REDACTED_NAME>");
        } else {
            out = out.replace(label.as_str(), "<REDACTED_NAME>");
        }
    }
    sanitize_log_text(&out)
}

fn sanitize_github_repo_slug(raw: &str) -> String {
    let trimmed = raw.trim().trim_matches('/');
    let mut parts = trimmed.split('/');
    let owner = parts.next().unwrap_or("");
    let repo = parts.next().unwrap_or("");
    let extra = parts.next();
    let valid_part = |s: &str| {
        !s.is_empty()
            && s.len() <= 80
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    };
    if extra.is_none() && valid_part(owner) && valid_part(repo) {
        format!("{owner}/{repo}")
    } else {
        "JuryBu/CatCloud".to_string()
    }
}

fn truncate_chars_with_ellipsis(raw: &str, max_chars: usize) -> String {
    let count = raw.chars().count();
    if count <= max_chars {
        return raw.to_string();
    }
    if max_chars <= 1 {
        return "…".to_string();
    }
    let prefix: String = raw.chars().take(max_chars - 1).collect();
    format!("{prefix}…")
}

#[allow(clippy::too_many_arguments)]
fn build_github_issue_draft(
    repo_slug: &str,
    app_version: &str,
    os_label: &str,
    is_elevated: bool,
    tun_privilege_ready: bool,
    is_portable: bool,
    cfg: &AppConfig,
    rt: &CoreRuntimeStatus,
    global_status: &GlobalPreAccelStatus,
    counts: (usize, usize, usize, usize),
    geodata_status: &serde_json::Value,
    last_error: Option<&str>,
    key_event_logs: &[String],
    custom_labels: &[String],
    summary: Option<&str>,
    lang: &str,
) -> GithubIssueDraftDto {
    let norm_lang = catcloud_core::agent_docs::normalize_doc_lang(Some(lang));
    let repo = sanitize_github_repo_slug(repo_slug);
    let (sub_count, node_count, group_count, relay_count) = counts;

    let clean_summary = summary
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            strip_user_custom_labels(s, custom_labels)
                .replace(['\r', '\n'], " ")
                .trim()
                .to_string()
        })
        .filter(|s| !s.is_empty());

    let title = match (&clean_summary, norm_lang) {
        (Some(s), "en") => format!("[Feedback] {}", truncate_chars_with_ellipsis(s, 64)),
        (Some(s), "ja") => format!("[報告] {}", truncate_chars_with_ellipsis(s, 64)),
        (Some(s), "ru") => format!("[Отзыв] {}", truncate_chars_with_ellipsis(s, 64)),
        (Some(s), _) => format!("[反馈] {}", truncate_chars_with_ellipsis(s, 64)),
        (None, "en") => "[Feedback] CatCloud issue report".to_string(),
        (None, "ja") => "[報告] CatCloud 不具合・質問レポート".to_string(),
        (None, "ru") => "[Отзыв] Сообщение о проблеме CatCloud".to_string(),
        (None, _) => "[反馈] 猫猫云梯使用问题反馈".to_string(),
    };

    let eff_tun = cfg.tun.enabled && tun_privilege_ready;
    let tun_need_elev = cfg.tun.enabled && !tun_privilege_ready;
    let tun_active = rt.running && eff_tun;
    let tun_display_zh = if eff_tun {
        "true"
    } else if tun_need_elev {
        "false (已勾选但需管理员权限)"
    } else {
        "false"
    };
    let tun_display_en = if eff_tun {
        "true"
    } else if tun_need_elev {
        "false (configured, needs_elevation)"
    } else {
        "false"
    };
    let tun_url_flag = if eff_tun {
        "true"
    } else if tun_need_elev {
        "needs_elevation"
    } else {
        "false"
    };
    let preaccel_state = if !cfg.preaccel.enabled && !global_status.running {
        "off"
    } else if global_status.is_windivert_active {
        "windivert_active"
    } else if global_status.running {
        "socks5_running"
    } else if tun_active {
        "managed_by_tun"
    } else {
        "enabled_idle"
    };
    let core_version = rt.version.as_deref().unwrap_or("unknown");
    let clean_last_error = last_error
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| strip_user_custom_labels(s, custom_labels))
        .unwrap_or_else(|| "none".to_string());

    let clean_events: Vec<String> = key_event_logs
        .iter()
        .rev()
        .take(GITHUB_ISSUE_KEY_EVENTS_LIMIT)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|line| strip_user_custom_labels(line, custom_labels))
        .collect();
    let events_block = if clean_events.is_empty() {
        "(no recent non-traffic key events)".to_string()
    } else {
        clean_events.join("\n")
    };
    let is_zh = norm_lang == "zh-CN";
    let geodata_brief = format_geodata_brief_localized(geodata_status, is_zh);
    let core_state = if rt.running { "running" } else { "stopped" };

    let clipboard_markdown = if is_zh {
        let summary_section = clean_summary
            .as_deref()
            .unwrap_or("（请简述遇到的问题、预期结果与复现步骤）");
        format!(
            "### 环境信息（已自动脱敏，已剥离自定义节点/分组/中转备注名）\n\
             - CatCloud 版本：`v{app_version}`（便携模式：`{is_portable}` · 管理员权限：`{is_elevated}`）\n\
             - 操作系统：`{os_label}`\n\
             - 代理核心：`{core_state}`（Mihomo `{core_version}`）\n\
             - 代理模式 / 路由方式：`{}` / `{}`\n\
             - 流量接管：系统代理=`{}` · 虚拟网卡(TUN)=`{}`（协议栈 `{}`）\n\
             - 国内提速：开关=`{}` · 状态=`{preaccel_state}` · 探测=`{}`\n\
             - 本地资产数量：订阅 `{sub_count}` · 节点 `{node_count}` · 多选组 `{group_count}` · 中转 `{relay_count}`\n\
             - GeoData：{geodata_brief}\n\
             \n\
             ### 问题描述与复现步骤\n\
             {summary_section}\n\
             \n\
             ### 最近脱敏异常\n\
             ```text\n\
             {clean_last_error}\n\
             ```\n\
             \n\
             ### 最近关键事件（最多 {GITHUB_ISSUE_KEY_EVENTS_LIMIT} 条，已脱敏并剥离自定义备注名）\n\
             ```text\n\
             {events_block}\n\
             ```\n",
            cfg.proxy_mode.as_str(),
            cfg.route_mode.as_str(),
            cfg.system_proxy.enabled,
            tun_display_zh,
            cfg.tun.stack_mode.as_str(),
            cfg.preaccel.enabled,
            global_status.verify_state,
        )
    } else {
        let summary_section = clean_summary
            .as_deref()
            .unwrap_or("(Please describe the issue, expected behavior, and reproduction steps)");
        format!(
            "### Environment (auto-sanitized; custom node/group/relay/provider labels stripped)\n\
             - CatCloud version: `v{app_version}` (portable: `{is_portable}`, elevated: `{is_elevated}`)\n\
             - OS: `{os_label}`\n\
             - Proxy core: `{core_state}` (Mihomo `{core_version}`)\n\
             - Proxy / Route mode: `{}` / `{}`\n\
             - Traffic takeover: system_proxy=`{}` · TUN=`{}` (stack `{}`)\n\
             - Domestic acceleration: enabled=`{}` · state=`{preaccel_state}` · verify=`{}`\n\
             - Local asset counts: subscriptions `{sub_count}` · nodes `{node_count}` · groups `{group_count}` · relays `{relay_count}`\n\
             - GeoData: {geodata_brief}\n\
             \n\
             ### Issue Summary & Reproduction Steps\n\
             {summary_section}\n\
             \n\
             ### Recent Sanitized Error\n\
             ```text\n\
             {clean_last_error}\n\
             ```\n\
             \n\
             ### Recent Key Events (up to {GITHUB_ISSUE_KEY_EVENTS_LIMIT}, sanitized & stripped of custom labels)\n\
             ```text\n\
             {events_block}\n\
             ```\n",
            cfg.proxy_mode.as_str(),
            cfg.route_mode.as_str(),
            cfg.system_proxy.enabled,
            tun_display_en,
            cfg.tun.stack_mode.as_str(),
            cfg.preaccel.enabled,
            global_status.verify_state,
        )
    };

    // Keep URL `body` strictly <= 600 chars (both raw char count and URL-encoded length)
    // to prevent Windows ShellExecuteW URL truncation.
    let build_short_url_body = |sum_limit: usize| -> String {
        let sum_line = match &clean_summary {
            Some(s) if sum_limit > 0 => truncate_chars_with_ellipsis(s, sum_limit),
            _ => {
                if is_zh {
                    "(请简述复现步骤)".to_string()
                } else {
                    "(Briefly describe steps to reproduce)".to_string()
                }
            }
        };
        let env_line = format!(
            "Env: CatCloud v{app_version} | {os_label} | mode={} | core={core_state} | tun={} | preaccel={preaccel_state}",
            cfg.proxy_mode.as_str(),
            tun_url_flag,
        );
        if is_zh {
            format!(
                "### Issue\n{sum_line}\n\n### Diagnostics\n{env_line}\n(详细脱敏摘要已复制到剪贴板，请直接 Ctrl+V 粘贴)"
            )
        } else {
            format!(
                "### Summary\n{sum_line}\n\n### Sanitized Diagnostics\n{env_line}\n(Detailed sanitized report copied to clipboard - press Ctrl+V here)"
            )
        }
    };

    let mut sum_limit = 40usize;
    let mut url_body = build_short_url_body(sum_limit);
    while url_body.chars().count() > GITHUB_ISSUE_URL_BODY_MAX_CHARS
        || percent_encode_query_value(&url_body).len() > GITHUB_ISSUE_URL_BODY_MAX_CHARS
    {
        if sum_limit == 0 {
            url_body = format!(
                "Env: CatCloud v{app_version} | {os_label} | mode={} | core={}\n(Paste sanitized report from clipboard via Ctrl+V)",
                cfg.proxy_mode.as_str(),
                if rt.running { "running" } else { "stopped" },
            );
            if url_body.chars().count() > GITHUB_ISSUE_URL_BODY_MAX_CHARS {
                url_body = truncate_chars_with_ellipsis(&url_body, GITHUB_ISSUE_URL_BODY_MAX_CHARS);
            }
            break;
        }
        sum_limit = sum_limit.saturating_sub(8);
        url_body = build_short_url_body(sum_limit);
    }

    let issue_url = format!(
        "https://github.com/{repo}/issues/new?title={}&body={}",
        percent_encode_query_value(&title),
        percent_encode_query_value(&url_body),
    );

    GithubIssueDraftDto {
        issue_url,
        clipboard_markdown,
        title,
    }
}

fn collect_github_issue_custom_labels(
    subs: &[SubscriptionRecord],
    nodes: &[ProxyNode],
    groups: &[MultiGroup],
    relays: &[PreAccelRelay],
) -> Vec<String> {
    let mut labels: Vec<String> = Vec::with_capacity(
        subs.len() + nodes.len() + groups.len() + relays.len() * 2,
    );
    labels.extend(subs.iter().map(|s| s.name.clone()));
    labels.extend(nodes.iter().map(|n| n.name.clone()));
    labels.extend(groups.iter().map(|g| g.name.clone()));
    labels.extend(relays.iter().map(|r| r.name.clone()));
    labels.extend(
        relays
            .iter()
            .map(|r| r.provider.trim())
            .filter(|p| !p.is_empty())
            .map(str::to_string),
    );
    labels
}

#[tauri::command]
pub async fn build_github_issue_url(
    state: State<'_, AppState>,
    summary: Option<String>,
    lang: Option<String>,
) -> Result<GithubIssueDraftDto, String> {
    let norm_lang = resolve_effective_doc_lang(&state, lang.as_deref());
    let cfg = state.snapshot_config();
    let rt = state.snapshot_runtime();
    let plat = default_platform();
    let caps = plat.capabilities();
    let global_status = state.snapshot_global_preaccel();
    let geodata_status = collect_geodata_status(&state.paths.runtime_dir);

    let (counts, custom_labels) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let subs = db.list_subscriptions().unwrap_or_default();
        let nodes = db.list_nodes().unwrap_or_default();
        let groups = db.list_multi_groups().unwrap_or_default();
        let relays = db.list_preaccel_relays(false).unwrap_or_default();

        let labels = collect_github_issue_custom_labels(&subs, &nodes, &groups, &relays);
        ((subs.len(), nodes.len(), groups.len(), relays.len()), labels)
    };

    let last_error = rt
        .last_error
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(app_log::sanitize_log_line)
        .or_else(|| state.last_app_error_snapshot());

    let ring_events = state
        .app_logger
        .read_recent_key_events(app_log::MAX_KEY_EVENT_RING_LEN);
    let logger = Arc::clone(&state.app_logger);
    let disk_logs = tokio::task::spawn_blocking(move || {
        logger.read_recent_lines(DIAGNOSTICS_DISK_SCAN_LIMIT)
    })
    .await
    .unwrap_or_default();
    let mem_logs = state.telemetry.logs_snapshot();
    let merged_logs = merge_sanitized_recent_logs(disk_logs, mem_logs, DIAGNOSTICS_DISK_SCAN_LIMIT);
    let key_events =
        merge_diagnostic_key_events(ring_events, &merged_logs, GITHUB_ISSUE_KEY_EVENTS_LIMIT);

    let os_label = format!("{} {}", caps.os, caps.arch);
    let tun_privilege_ready = is_tun_privilege_ready(&state);
    Ok(build_github_issue_draft(
        &cfg.update.repo,
        env!("CARGO_PKG_VERSION"),
        &os_label,
        caps.is_elevated,
        tun_privilege_ready,
        state.paths.is_portable,
        &cfg,
        &rt,
        &global_status,
        counts,
        &geodata_status,
        last_error.as_deref(),
        &key_events,
        &custom_labels,
        summary.as_deref(),
        norm_lang,
    ))
}

#[tauri::command]
pub fn validate_formula_expr(expr: String) -> Result<bool, String> {
    catcloud_core::strategy::formula::validate_formula(&expr)
        .map(|_| true)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn evaluate_multi_group(
    state: State<'_, AppState>,
    group_id: String,
) -> Result<catcloud_core::strategy::evaluator::GroupEvaluationReport, String> {
    let db = state.storage.lock().map_err(|e| e.to_string())?;
    let group = db
        .get_multi_group(&group_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("未找到指定路线分组（{group_id}）"))?;
    let nodes = db.list_nodes().map_err(|e| e.to_string())?;
    let ids: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
    let snaps = db
        .get_probe_snapshots_batch(&ids, group.primary_probe_id.as_deref())
        .map_err(|e| e.to_string())?;
    let health_pool = state.snapshot_node_health_pool();
    evaluate_group_candidates_with_runtime(&group, &nodes, &snaps, Some(&health_pool), Instant::now())
        .map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledYamlPreviewDto {
    pub yaml: String,
    pub sha256: String,
    pub stats: CompileStats,
    pub validation: StaticValidationReport,
}

#[tauri::command]
pub fn compile_preview_yaml(state: State<'_, AppState>) -> Result<CompiledYamlPreviewDto, String> {
    let cfg = state.snapshot_config();
    let (nodes, groups, relays) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        (
            db.list_nodes().map_err(|e| e.to_string())?,
            db.list_multi_groups().map_err(|e| e.to_string())?,
            db.list_preaccel_relays(false).map_err(|e| e.to_string())?,
        )
    };
    let allocated = AllocatedPorts {
        bind_host: cfg.bind_address.clone(),
        mixed_port: cfg.mixed_port,
        controller_port: cfg.controller_port,
        dns_port: cfg.dns_listen_port,
        shifted: Vec::new(),
    };
    let empty_filter = HashMap::new();
    let input = CompileInput {
        config: &cfg,
        nodes: &nodes,
        groups: &groups,
        relays: &relays,
        controller_secret: "preview-redacted-secret",
        allocated_ports: &allocated,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty_filter,
    };
    let compiled = compile_mihomo_config_with_runtime_dir(&input, Some(&state.paths.runtime_dir))
        .map_err(|e| e.to_string())?;
    let redacted_yaml =
        redact_compiled_yaml_for_preview(&compiled, &relays).map_err(|e| e.to_string())?;
    Ok(CompiledYamlPreviewDto {
        yaml: redacted_yaml,
        sha256: compiled.sha256,
        stats: compiled.stats,
        validation: compiled.validation,
    })
}

#[tauri::command]
pub async fn import_mmrelay_input(
    app: AppHandle,
    state: State<'_, AppState>,
    raw: String,
) -> Result<Vec<PreAccelRelay>, String> {
    let bundle =
        catcloud_core::preaccel::schema::parse_mmrelay_clipboard(&raw).map_err(|e| e.to_string())?;
    {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        for relay in &bundle.relays {
            catcloud_core::preaccel::schema::validate_relay_strict(relay)
                .map_err(|e| e.to_string())?;
            db.upsert_preaccel_relay(relay).map_err(|e| e.to_string())?;
        }
    }
    let _ = trigger_reload_if_running(&app, &state, false).await;
    let latest_cfg = state.snapshot_config();
    sync_running_global_preaccel_if_active(&state, &latest_cfg).await;
    sync_app_side_effects(&app, &state, &latest_cfg);
    let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&latest_cfg));
    Ok(bundle.relays)
}

#[tauri::command]
pub async fn scan_local_migrations(
) -> Result<Vec<catcloud_core::subscription::migrator::MigrationPreview>, String> {
    tauri::async_runtime::spawn_blocking(catcloud_core::subscription::migrator::scan_local_clients)
        .await
        .map_err(|e| format!("扫描本地客户端配置任务异常中止：{e}"))
}

#[tauri::command]
pub async fn scan_migration_path(
    path: String,
) -> Result<Vec<catcloud_core::subscription::migrator::MigrationPreview>, String> {
    let trimmed = path.trim().to_string();
    if trimmed.is_empty() {
        return Err("请先选择需要扫描的配置文件或目录路径".to_string());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let target = std::path::Path::new(&trimmed);
        if !target.exists() {
            return Err(format!("指定路径不存在：{trimmed}"));
        }
        Ok(catcloud_core::subscription::migrator::scan_custom_path_readonly(target))
    })
    .await
    .map_err(|e| format!("扫描指定迁移路径任务异常中止：{e}"))?
}

#[tauri::command]
pub fn preview_migration_from_text(
    name: String,
    raw_yaml: String,
) -> Result<serde_json::Value, String> {
    let preview = core_preview_from_text(&raw_yaml).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "name": name,
        "node_count": preview.nodes.len(),
        "nodes": preview.nodes,
        "prepend_rules": preview.prepend_rules,
        "append_rules": preview.append_rules,
        "warnings": preview.warnings
    }))
}

fn persist_migration_nodes(
    storage: &mut Storage,
    source_name: String,
    mut nodes: Vec<ProxyNode>,
) -> Result<(String, usize), String> {
    if nodes.is_empty() {
        return Err("未解析到可导入的节点，已取消导入".to_string());
    }
    let sub_id = format!("migrated-{}", uuid::Uuid::new_v4().simple());
    catcloud_core::subscription::migrator::rebind_migration_nodes(&sub_id, &mut nodes);
    let sub = SubscriptionRecord {
        id: sub_id.clone(),
        name: if source_name.trim().is_empty() {
            "迁移导入".to_string()
        } else {
            source_name
        },
        kind: SubscriptionKind::Migrated,
        url_or_cmd: "local://migrated".to_string(),
        last_ok_at: Some(Utc::now().to_rfc3339()),
        enabled: true,
        ..SubscriptionRecord::default()
    };
    storage.upsert_subscription(&sub).map_err(|e| e.to_string())?;
    let count = storage.upsert_nodes_batch(&nodes).map_err(|e| e.to_string())?;
    Ok((sub_id, count))
}

#[tauri::command]
pub async fn apply_migration_nodes(
    app: AppHandle,
    state: State<'_, AppState>,
    source_name: String,
    nodes: Vec<ProxyNode>,
) -> Result<usize, String> {
    let (_sub_id, count) = {
        let mut db = state.storage.lock().map_err(|e| e.to_string())?;
        persist_migration_nodes(&mut db, source_name, nodes)?
    };
    prune_node_health_pool_from_db(&state);
    let _ = ensure_default_group_if_empty(&state);
    let _ = trigger_reload_if_running(&app, &state, false).await;
    let cfg = state.snapshot_config();
    emit_config_updated(&app, &cfg);
    sync_app_side_effects(&app, &state, &cfg);
    Ok(count)
}

#[tauri::command]
pub fn list_running_processes(
    only_likely_proxy: bool,
) -> Vec<catcloud_core::subscription::process_attach::ProcessCandidate> {
    catcloud_core::subscription::process_attach::list_process_candidates(only_likely_proxy)
}

#[tauri::command]
pub async fn inspect_process_source(pid: u32) -> Result<serde_json::Value, String> {
    let candidates = catcloud_core::subscription::process_attach::list_process_candidates(false);
    let candidate = candidates
        .into_iter()
        .find(|p| p.pid == pid)
        .ok_or_else(|| format!("未找到对应进程（PID {pid}）"))?;
    let report = core_inspect_process_source(&candidate).await;
    serde_json::to_value(report).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_desktop_app_candidates(
    state: State<'_, AppState>,
    baseline_pids: Option<Vec<u32>>,
) -> Result<Vec<DesktopAppCandidate>, String> {
    let baseline: Option<HashSet<u32>> = baseline_pids.map(|v| v.into_iter().collect());
    let self_data_dir = state.paths.root_data_dir.clone();
    tauri::async_runtime::spawn_blocking(move || {
        core_list_desktop_app_candidates(baseline.as_ref(), Some(self_data_dir.as_path()))
    })
    .await
    .map_err(|e| format!("枚举桌面软件列表失败：{e}"))
}

#[tauri::command]
pub async fn start_live_capture_session(
    state: State<'_, AppState>,
    target_pid: u32,
) -> Result<LiveCaptureStartDto, String> {
    let mgr = Arc::clone(&state.live_capture);
    let self_data_dir = state.paths.root_data_dir.clone();
    tauri::async_runtime::spawn_blocking(move || mgr.start_session(target_pid, Some(self_data_dir)))
        .await
        .map_err(|e| format!("启动实时捕捉会话失败：{e}"))?
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn poll_live_capture_session(
    state: State<'_, AppState>,
    session_id: String,
) -> Result<LiveCaptureStatusDto, String> {
    state
        .live_capture
        .poll_session(&session_id)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn finish_live_capture_session(
    state: State<'_, AppState>,
    session_id: String,
) -> Result<LiveCaptureOutcomeDto, String> {
    let mgr = Arc::clone(&state.live_capture);
    tauri::async_runtime::spawn_blocking(move || mgr.finish_session(&session_id))
        .await
        .map_err(|e| format!("整理实时捕捉结果失败：{e}"))?
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn cancel_live_capture_session(
    state: State<'_, AppState>,
    session_id: String,
) -> Result<bool, String> {
    let mgr = Arc::clone(&state.live_capture);
    tauri::async_runtime::spawn_blocking(move || mgr.cancel_session(&session_id))
        .await
        .map_err(|e| format!("取消实时捕捉失败: {e}"))
}

#[tauri::command]
pub fn export_shell_env(state: State<'_, AppState>, shell: String) -> String {
    let cfg = state.snapshot_config();
    let rt = state.snapshot_runtime();
    let port = if rt.running { rt.mixed_port } else { cfg.mixed_port };
    let plat = default_platform();
    plat.export_shell_env_snippet(&shell, "127.0.0.1", port, port)
}

fn format_memory_tier_label(tier: &MemoryLimitTier) -> &'static str {
    match tier {
        MemoryLimitTier::Auto => "auto",
        MemoryLimitTier::Mb48 => "48MiB",
        MemoryLimitTier::Mb64 => "64MiB",
        MemoryLimitTier::Mb96 => "96MiB",
    }
}

fn log_dedupe_key(timestamp: &str, body: &str) -> String {
    let ts_sec = timestamp.get(..19).unwrap_or(timestamp);
    format!("{ts_sec}|{}", body.trim())
}

fn extract_disk_log_dedupe_key(line: &str) -> String {
    let trimmed = line.trim();
    let (ts_sec, mut rest) = match trimmed.split_once(' ') {
        Some((ts, r)) => (ts, r.trim_start()),
        None => ("", trimmed),
    };
    let ts_key = ts_sec.get(..19).unwrap_or(ts_sec);
    // Strip `[level] ` and optional `[category] ` strictly from the left so brackets inside the
    // message body never break deduplication against `CoreTelemetryStore`.
    for _ in 0..2 {
        if rest.starts_with('[') {
            if let Some((_, after)) = rest.split_once("] ") {
                rest = after.trim_start();
                continue;
            }
        }
        break;
    }
    format!("{ts_key}|{rest}")
}

fn merge_sanitized_recent_logs(
    disk_lines: Vec<String>,
    mem_logs: Vec<CoreLogLine>,
    limit: usize,
) -> Vec<String> {
    if limit == 0 {
        return Vec::new();
    }
    let mut merged: Vec<String> = Vec::with_capacity(limit.saturating_mul(2));
    let mut seen: HashSet<String> = HashSet::new();

    for disk_line in disk_lines {
        let clean = app_log::sanitize_log_line(&disk_line);
        let key = extract_disk_log_dedupe_key(&clean);
        if seen.insert(key) {
            merged.push(clean);
        }
    }

    let start_idx = mem_logs.len().saturating_sub(limit);
    for entry in &mem_logs[start_idx..] {
        let clean_payload = app_log::sanitize_log_line(&entry.payload)
            .replace(['\r', '\n'], " ")
            .trim()
            .to_string();
        if clean_payload.is_empty() {
            continue;
        }
        let body_for_key = clean_payload
            .strip_prefix(APP_EVENT_PREFIX)
            .and_then(|rest| rest.split_once("] ").map(|(_, msg)| msg))
            .unwrap_or(clean_payload.as_str());
        let key = log_dedupe_key(&entry.timestamp, body_for_key);
        if seen.insert(key) {
            let lvl = app_log::normalize_log_level(&entry.level);
            merged.push(format!("{} [{lvl}] {clean_payload}", entry.timestamp));
        }
    }

    if merged.len() > limit {
        merged.split_off(merged.len() - limit)
    } else {
        merged
    }
}

const DIAGNOSTICS_DISK_SCAN_LIMIT: usize = 1500;
const DIAGNOSTICS_KEY_EVENTS_LIMIT: usize = 25;
const DIAGNOSTICS_TAIL_LOGS_LIMIT: usize = 35;
const DIAGNOSTICS_JSON_RECENT_LOGS_LIMIT: usize = 60;
const ONBOARDING_KEY_EVENTS_LIMIT: usize = 6;

/// Sanitize arbitrary single-line or multi-line text before embedding into AI prompts or logs.
fn sanitize_log_text(raw: &str) -> String {
    raw.lines()
        .map(app_log::sanitize_log_line)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Return `true` when a formatted log line is a routine `[mihomo] [TCP]` / `[mihomo] [UDP]`
/// connection forwarding line at `info`/`debug` level (never filtering out `warning` or `error`
/// lines or application lifecycle/reload/switch/preaccel/ProxyGuard events).
fn is_routine_mihomo_traffic_log_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    if lower.contains(" [warning] ")
        || lower.contains(" [warn] ")
        || lower.contains(" [error] ")
    {
        return false;
    }
    lower.contains("[mihomo] [tcp]")
        || lower.contains("[mihomo] [udp]")
        || lower.contains(" [info] [tcp]")
        || lower.contains(" [info] [udp]")
        || lower.contains(" [debug] [tcp]")
        || lower.contains(" [debug] [udp]")
        || (lower.contains("[mihomo]") && (lower.contains(" match ") || lower.contains(" using ")))
}

/// Merge key events from the dedicated 256-entry ring buffer (immune to routine TCP/UDP floods)
/// with non-routine events found in the scanned disk + memory logs, deduplicated and capped to
/// the newest `limit` entries.
fn merge_diagnostic_key_events(
    ring_events: Vec<String>,
    all_logs: &[String],
    limit: usize,
) -> Vec<String> {
    if limit == 0 {
        return Vec::new();
    }
    let mut merged: Vec<String> = Vec::with_capacity(ring_events.len() + limit);
    let mut seen: HashSet<String> = HashSet::new();

    for raw in ring_events {
        let clean = app_log::sanitize_log_line(&raw)
            .replace(['\r', '\n'], " ")
            .trim()
            .to_string();
        if clean.is_empty() || is_routine_mihomo_traffic_log_line(&clean) {
            continue;
        }
        let key = extract_disk_log_dedupe_key(&clean);
        if seen.insert(key) {
            merged.push(clean);
        }
    }

    for line in all_logs {
        if is_routine_mihomo_traffic_log_line(line) {
            continue;
        }
        let clean = app_log::sanitize_log_line(line)
            .replace(['\r', '\n'], " ")
            .trim()
            .to_string();
        if clean.is_empty() {
            continue;
        }
        let key = extract_disk_log_dedupe_key(&clean);
        if seen.insert(key) {
            merged.push(clean);
        }
    }

    if merged.len() > limit {
        merged.split_off(merged.len() - limit)
    } else {
        merged
    }
}

/// Smart diagnostic log sampler returning:
/// 1. Up to `key_limit` most recent key non-traffic events (excluding routine TCP/UDP forwarding)
/// 2. Up to `tail_limit` most recent raw tail log lines
fn sample_diagnostic_logs(
    all_logs: &[String],
    key_limit: usize,
    tail_limit: usize,
) -> (Vec<String>, Vec<String>) {
    let key_events = merge_diagnostic_key_events(Vec::new(), all_logs, key_limit);

    let tail_logs = if tail_limit == 0 {
        Vec::new()
    } else {
        let start = all_logs.len().saturating_sub(tail_limit);
        all_logs[start..].to_vec()
    };

    (key_events, tail_logs)
}

fn collect_sanitized_recent_logs(state: &AppState, limit: usize) -> Vec<String> {
    if limit == 0 {
        return Vec::new();
    }
    let disk_lines = state.app_logger.read_recent_lines(limit);
    let mem_logs = state.telemetry.logs_snapshot();
    merge_sanitized_recent_logs(disk_lines, mem_logs, limit)
}

fn format_geodata_brief_localized(geodata: &serde_json::Value, is_zh: bool) -> String {
    let item = |key: &str, label: &str| -> String {
        let exists = geodata
            .get(key)
            .and_then(|v| v.get("exists"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let size = geodata
            .get(key)
            .and_then(|v| v.get("size_bytes"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if exists {
            if is_zh {
                format!("{label}: 已就绪 ({})", format_bytes_human(size))
            } else {
                format!("{label}: ready ({})", format_bytes_human(size))
            }
        } else if is_zh {
            format!("{label}: 缺失")
        } else {
            format!("{label}: missing")
        }
    };
    [
        item("country_mmdb", "Country.mmdb"),
        item("geoip_dat", "geoip.dat"),
        item("geosite_dat", "geosite.dat"),
        item("asn_mmdb", "ASN.mmdb"),
    ]
    .join(" / ")
}

fn format_geodata_brief(geodata: &serde_json::Value) -> String {
    format_geodata_brief_localized(geodata, true)
}

fn format_global_preaccel_brief(
    global_status: &GlobalPreAccelStatus,
    enabled: bool,
    tun_active: bool,
) -> String {
    let iface = global_status
        .bound_physical_interface
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(app_log::sanitize_log_line)
        .unwrap_or_else(|| "自动路由（未绑定固定网卡）".to_string());
    let security = if global_status.detected_security_products.is_empty() {
        "未检出拦截类安全软件".to_string()
    } else {
        app_log::sanitize_log_line(&global_status.detected_security_products.join(" / "))
    };
    let verify_desc = match global_status.verify_state.as_str() {
        "verified" => match global_status.verify_latency_ms {
            Some(ms) => format!("自动探测畅通（{ms} ms）"),
            None => "自动探测畅通".to_string(),
        },
        "probing" => "正在自动探测链路".to_string(),
        "degraded" => "已触发保护熔断并退回本地 443 通道".to_string(),
        "failed" => {
            if !global_status.windivert_available
                || global_status.install_state == "need_elevation"
            {
                "底层提速驱动尚未就绪".to_string()
            } else {
                "底层自动探测未通过".to_string()
            }
        }
        _ => "尚未探测".to_string(),
    };
    let mode_desc = if !enabled && !global_status.running {
        "未开启"
    } else if global_status.is_windivert_active {
        "底层透明加速（WinDivert 运行中）"
    } else if global_status.running {
        "本地独立 443 通道（SOCKS5 运行中）"
    } else if tun_active {
        "已开启（由虚拟网卡主核心统一接管）"
    } else if global_status.mode == "suspended_for_tun" {
        "已挂起（等待主核心接管）"
    } else {
        "已开启（等待启动独立提速通道）"
    };
    format!("{mode_desc} ｜ 探测状态：{verify_desc} ｜ 物理出口网卡：{iface} ｜ 安全环境：{security}")
}

#[allow(clippy::too_many_arguments)]
fn build_ai_diagnostics_markdown(
    app_version: &str,
    os_label: &str,
    is_elevated: bool,
    is_portable: bool,
    cfg: &AppConfig,
    rt: &CoreRuntimeStatus,
    runtime_dto: Option<&CoreRuntimeInfoDto>,
    global_status: &GlobalPreAccelStatus,
    counts: (usize, usize, usize, usize),
    conn_summary: ConnectionSummaryCounts,
    core_mem_bytes: u64,
    geodata_status: &serde_json::Value,
    last_error: Option<&str>,
    key_event_logs: &[String],
    tail_logs: &[String],
    cli_path_display: &str,
    data_dir_display: &str,
) -> String {
    let (sub_count, node_count, group_count, relay_count) = counts;
    let route_mode = runtime_dto
        .map(|d| d.route_mode.as_str())
        .unwrap_or_else(|| cfg.route_mode.as_str());
    let active_group_name = app_log::sanitize_log_line(
        runtime_dto
            .map(|d| d.active_group_name.as_str())
            .unwrap_or("默认路线"),
    );
    let active_node_name = app_log::sanitize_log_line(
        runtime_dto
            .map(|d| d.active_node_name.as_str())
            .unwrap_or("未选择"),
    );
    let active_node_region = runtime_dto
        .map(|d| d.active_node_region.as_str())
        .unwrap_or("--");
    let preaccel_relay_name = app_log::sanitize_log_line(
        runtime_dto
            .and_then(|d| d.preaccel_relay_name.as_deref())
            .unwrap_or("未配置"),
    );
    let mixed_port = if rt.running { rt.mixed_port } else { cfg.mixed_port };
    let controller_port = if rt.running {
        rt.controller_port
    } else {
        cfg.controller_port
    };
    let dns_port = if rt.running {
        rt.dns_listen_port
    } else {
        cfg.dns_listen_port
    };
    let core_version = rt.version.as_deref().unwrap_or("未知");
    let core_mem_text = if core_mem_bytes > 0 {
        format!("{:.1} MiB", (core_mem_bytes as f64) / (1024.0 * 1024.0))
    } else {
        "--".to_string()
    };
    let last_err_text = last_error
        .map(sanitize_log_text)
        .unwrap_or_else(|| "无".to_string());

    let key_events_block = if key_event_logs.is_empty() {
        "（暂无关键非连接流水事件）".to_string()
    } else {
        key_event_logs.join("\n")
    };
    let tail_logs_block = if tail_logs.is_empty() {
        "（暂无运行日志记录）".to_string()
    } else {
        tail_logs.join("\n")
    };
    let is_windows_cli = cfg!(target_os = "windows") || os_label.starts_with("windows");
    let cli_fence_lang = if is_windows_cli {
        "powershell"
    } else {
        "bash"
    };
    let cli_invoke_prefix = if is_windows_cli {
        format!("& \"{cli_path_display}\" --data-dir \"{data_dir_display}\"")
    } else {
        format!("\"{cli_path_display}\" --data-dir \"{data_dir_display}\"")
    };

    let elevated_label = if is_elevated { "是" } else { "否" };
    let portable_label = if is_portable { "是" } else { "否" };
    let core_state_label = if rt.running { "运行中" } else { "已停止" };
    let proxy_mode_label = cfg.proxy_mode.as_str();
    let sys_proxy_label = if cfg.system_proxy.enabled {
        "已开启"
    } else {
        "关闭"
    };
    let eff_tun = runtime_dto
        .map(|d| d.tun_enabled)
        .unwrap_or(cfg.tun.enabled && is_elevated);
    let tun_need_elev = runtime_dto
        .map(|d| d.tun_needs_elevation)
        .unwrap_or(cfg.tun.enabled && !is_elevated);
    let tun_label = if eff_tun {
        "已开启"
    } else if tun_need_elev {
        "未生效（已勾选但需管理员权限）"
    } else {
        "关闭"
    };
    let tun_stack_label = cfg.tun.stack_mode.as_str();
    let mem_tier_label = format_memory_tier_label(&cfg.core_runtime.memory_tier);
    let gogc_val = cfg.core_runtime.gogc;
    let domestic_direct_label = if cfg.rules_override.domestic_direct_enabled {
        "开启"
    } else {
        "关闭"
    };
    let block_quic_label = if cfg.rules_override.block_quic_udp_443 {
        "开启"
    } else {
        "关闭"
    };
    let preaccel_label = if cfg.preaccel.enabled {
        "已开启"
    } else {
        "关闭"
    };
    let skip_443_label = if cfg.preaccel.skip_443_native {
        "是"
    } else {
        "否"
    };
    let tun_active = rt.running && eff_tun;
    let global_preaccel_brief =
        format_global_preaccel_brief(global_status, cfg.preaccel.enabled, tun_active);
    let ipv6_core_label = if cfg.core_ipv6 { "开启" } else { "关闭" };
    let ipv6_dns_label = if cfg.dns.ipv6 { "开启" } else { "关闭" };
    let geodata_brief = format_geodata_brief(geodata_status);
    let app_conns = conn_summary.app_connections;
    let direct_conns = conn_summary.direct_connections;
    let proxied_conns = conn_summary.proxied_connections;
    let tunnel_conns = conn_summary.tunnel_connections;
    let key_count = key_event_logs.len();
    let tail_count = tail_logs.len();

    format!(
        "请帮我排查猫猫云梯（CatCloud）当前问题。\n\
\n\
> 以下诊断包已自动完成隐私脱敏（订阅凭据、密码、Token、Secret 与公网 IP 末段均已隐藏），请先基于状态与关键事件日志定位根因并给出清晰步骤。\n\
\n\
## 1. 运行状态摘要\n\
\n\
| 项目 | 当前状态 |\n\
| --- | --- |\n\
| 应用版本 / 环境 | CatCloud v{app_version} · {os_label} · 管理员权限：{elevated_label} · 便携模式：{portable_label} |\n\
| 代理核心 | {core_state_label}（Mihomo {core_version}，内核内存：{core_mem_text}） |\n\
| 代理模式 / 路由方式 | `{proxy_mode_label}` / `{route_mode}` |\n\
| 当前路线组 / 节点 | 分组「{active_group_name}」 → 节点「{active_node_name}」（地区：{active_node_region}） |\n\
| 本地端口 | 混合端口 `{mixed_port}` / 控制端口 `{controller_port}` / DNS `{dns_port}` |\n\
| 流量接管 | 系统代理：{sys_proxy_label} · 虚拟网卡（TUN）：{tun_label}（协议栈 `{tun_stack_label}`） |\n\
| 内存档位 | `{mem_tier_label}`（GOGC={gogc_val}） |\n\
| 最近异常 | {last_err_text} |\n\
\n\
## 2. 分流与加速配置要点\n\
\n\
- 国内直连规则：{domestic_direct_label} ｜ 阻断 QUIC（UDP/443）：{block_quic_label}\n\
- 国内 443 提速：{preaccel_label}（当前中转：{preaccel_relay_name}，跳过 443 原生节点：{skip_443_label}）\n\
- 底层提速诊断：{global_preaccel_brief}\n\
- IPv6 开关：核心数据面 {ipv6_core_label} ｜ DNS 解析 {ipv6_dns_label}\n\
- GeoData 状态：{geodata_brief}\n\
- 本地资产统计：订阅 {sub_count} 个 · 节点 {node_count} 个 · 智能多选组 {group_count} 个 · 国内中转 {relay_count} 个\n\
\n\
## 3. 当前连接分布\n\
\n\
- 真实应用连接：{app_conns} 条（直连 {direct_conns} 条 · 代理 {proxied_conns} 条）\n\
- 底层提速隧道（`Inner`）：{tunnel_conns} 条（已从应用连接数中排除）\n\
\n\
## 4. 脱敏运行日志（智能采样：近 {key_count} 条关键事件 + 近 {tail_count} 条全量尾日志）\n\
\n\
### 4.1 关键非连接流水事件（近 {key_count} 条，已排除普通 TCP/UDP 转发）\n\
\n\
```text\n\
{key_events_block}\n\
```\n\
\n\
### 4.2 最新全量尾日志（近 {tail_count} 条）\n\
\n\
```text\n\
{tail_logs_block}\n\
```\n\
\n\
## 5. 本机只读 `catcloud` CLI 进一步排查指引\n\
\n\
- 当前实例 CLI 路径（已脱敏）：`{cli_path_display}`\n\
- 当前实例数据目录（已脱敏）：`{data_dir_display}`\n\
\n\
如果你可以直接在本机终端执行命令，请**优先使用以下只读命令**补充信息（修改配置前请先征得我同意，所有命令统一携带 `--json`）：\n\
\n\
```{cli_fence_lang}\n\
{cli_invoke_prefix} status --json\n\
{cli_invoke_prefix} config diag --json\n\
{cli_invoke_prefix} config validate --json\n\
{cli_invoke_prefix} net doctor --json\n\
{cli_invoke_prefix} group list --json\n\
{cli_invoke_prefix} node list --json\n\
{cli_invoke_prefix} preaccel pool --json\n\
{cli_invoke_prefix} docs export network_lifecycle --json\n\
```\n\
\n\
> 若已将 `catcloud` 加入系统 PATH，也可直接执行简写命令（如 `catcloud status --json`、`catcloud config diag --json`）。\n"
    )
}

fn format_onboarding_os_label_zh(os_raw: &str) -> &'static str {
    let lower = os_raw.trim().to_ascii_lowercase();
    if lower.contains("windows") || lower.contains("win") {
        "Windows 电脑"
    } else if lower.contains("macos") || lower.contains("darwin") || lower.contains("mac") {
        "macOS 电脑"
    } else if lower.contains("linux") {
        "Linux 电脑"
    } else {
        "桌面电脑"
    }
}

fn format_onboarding_preaccel_plain_zh(
    global_status: &GlobalPreAccelStatus,
    enabled: bool,
    tun_enabled: bool,
    core_running: bool,
) -> String {
    let main_desc = if !enabled && !global_status.running {
        "已关闭".to_string()
    } else {
        match global_status.verify_state.as_str() {
            "verified" => match global_status.verify_latency_ms {
                Some(ms) => format!("已开启并在底层实测生效（{ms} ms）"),
                None => "已开启并在底层实测生效".to_string(),
            },
            "probing" => "已开启，正在自动探测链路".to_string(),
            "degraded" => "已开启，底层探测未通过已自动保护回退".to_string(),
            "failed" => "已开启，底层提速组件暂未就绪".to_string(),
            _ => {
                if global_status.is_windivert_active {
                    "已开启并在底层运行中（等待自动探测）".to_string()
                } else if core_running && tun_enabled {
                    "已开启（由全局代理模式统一接管提速）".to_string()
                } else if matches!(
                    global_status.install_state.as_str(),
                    "downloading" | "verifying"
                ) {
                    "已开启，正在后台自动准备提速组件".to_string()
                } else if global_status.install_state == "need_elevation" {
                    "已开启，需以管理员身份重启后为其它软件自动提速".to_string()
                } else if global_status.running {
                    "已开启（本机独立提速通道待命中）".to_string()
                } else {
                    "已开启（待启动）".to_string()
                }
            }
        }
    };

    let mut parts = vec![main_desc];
    if let Some(iface) = global_status
        .bound_physical_interface
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        parts.push(format!("当前上网网卡：{}", app_log::sanitize_log_line(iface)));
    }
    if global_status.detected_security_products.is_empty() {
        parts.push("安全软件环境：未发现常见拦截类安全软件".to_string());
    } else {
        parts.push(format!(
            "检测到安全软件：{}",
            app_log::sanitize_log_line(&global_status.detected_security_products.join(" / "))
        ));
    }
    parts.join(" ｜ ")
}

fn strip_log_timestamp_and_level_prefix(line: &str) -> &str {
    let mut s = line.trim();
    // Strip leading ISO-8601 timestamp token such as `2026-11-24T12:00:00Z `
    if let Some((first, rest)) = s.split_once(' ') {
        if first.len() >= 19 && first.as_bytes().get(4) == Some(&b'-') && first.contains(':') {
            s = rest.trim_start();
        }
    }
    // Strip leading `[info]` / `[warning]` / `[error]` / `[warn]` tag
    if s.starts_with('[') {
        if let Some(close) = s.find(']') {
            let tag = &s[1..close];
            if matches!(
                tag.to_ascii_lowercase().as_str(),
                "info" | "warn" | "warning" | "error" | "debug" | "trace"
            ) {
                s = s[close + 1..].trim_start();
            }
        }
    }
    s
}

/// Keep at most `limit` high-value, sanitized Chinese status events suitable for onboarding
/// beginners (dropping routine traffic lines, debug/trace noise, and heavy English low-level logs).
fn filter_onboarding_key_events(all_logs: &[String], limit: usize) -> Vec<String> {
    if limit == 0 {
        return Vec::new();
    }
    let filtered: Vec<String> = all_logs
        .iter()
        .filter(|line| {
            if is_routine_mihomo_traffic_log_line(line) {
                return false;
            }
            let lower = line.to_ascii_lowercase();
            if lower.contains(" [debug] ") || lower.contains(" [trace] ") {
                return false;
            }
            let body = strip_log_timestamp_and_level_prefix(line);
            let cjk_count = body
                .chars()
                .filter(|c| ('\u{4E00}'..='\u{9FFF}').contains(c))
                .count();
            if cjk_count < 2 {
                return false;
            }
            let ascii_letters = body.bytes().filter(u8::is_ascii_alphabetic).count();
            !(ascii_letters > 24 && ascii_letters > cjk_count * 3)
        })
        .map(|line| sanitize_log_text(line))
        .collect();
    let start = filtered.len().saturating_sub(limit);
    filtered[start..].to_vec()
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn build_ai_onboarding_prompt_markdown(
    app_version: &str,
    os_label: &str,
    is_elevated: bool,
    cfg: &AppConfig,
    rt: &CoreRuntimeStatus,
    runtime_dto: Option<&CoreRuntimeInfoDto>,
    global_status: &GlobalPreAccelStatus,
    counts: (usize, usize, usize, usize, usize, usize),
    last_error: Option<&str>,
    key_event_logs: &[String],
) -> String {
    let (sub_count, total_nodes, enabled_nodes, tested_nodes, group_count, relay_count) = counts;
    let os_label_zh = format_onboarding_os_label_zh(os_label);
    let route_mode = runtime_dto
        .map(|d| d.route_mode.as_str())
        .unwrap_or_else(|| cfg.route_mode.as_str());
    let route_mode_zh = if route_mode == "single" {
        "单节点直选"
    } else {
        "智能多选组"
    };
    let active_group_name = app_log::sanitize_log_line(
        runtime_dto
            .map(|d| d.active_group_name.as_str())
            .unwrap_or("尚未创建"),
    );
    let active_node_name = app_log::sanitize_log_line(
        runtime_dto
            .map(|d| d.active_node_name.as_str())
            .unwrap_or("待导入节点"),
    );
    let active_node_region = runtime_dto
        .map(|d| d.active_node_region.as_str())
        .unwrap_or("--");
    let selection_desc = if total_nodes == 0 {
        "尚未导入任何节点".to_string()
    } else if route_mode == "single" {
        format!("单节点「{active_node_name}」（地区：{active_node_region}）")
    } else {
        format!("智能多选组「{active_group_name}」 → 当前生效节点「{active_node_name}」（地区：{active_node_region}）")
    };

    let core_state = if rt.running { "运行中" } else { "未启动" };
    let proxy_mode_zh = match cfg.proxy_mode {
        ProxyMode::Rule => "规则分流（国内外自动分流）",
        ProxyMode::Global => "全局代理",
        ProxyMode::Direct => "全部直连",
    };
    let sys_proxy_zh = if cfg.system_proxy.enabled {
        "已开启"
    } else {
        "未开启"
    };
    let eff_tun = runtime_dto
        .map(|d| d.tun_enabled)
        .unwrap_or(cfg.tun.enabled && is_elevated);
    let tun_need_elev = runtime_dto
        .map(|d| d.tun_needs_elevation)
        .unwrap_or(cfg.tun.enabled && !is_elevated);
    let tun_zh = if eff_tun {
        "已开启"
    } else if tun_need_elev {
        "未生效（需管理员权限）"
    } else {
        "未开启"
    };
    let admin_zh = if is_elevated {
        "已是管理员权限"
    } else {
        "普通用户权限"
    };
    let preaccel_brief = format_onboarding_preaccel_plain_zh(
        global_status,
        cfg.preaccel.enabled,
        eff_tun,
        rt.running,
    );
    let security_guidance_line = global_status
        .security_guidance
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|g| format!("- 安全软件放行提示：{}\n", sanitize_log_text(g)))
        .unwrap_or_default();
    let last_err_line = last_error
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|e| format!("- 最近异常提示：{}\n", sanitize_log_text(e)))
        .unwrap_or_else(|| "- 最近异常提示：无\n".to_string());

    let filtered_events = filter_onboarding_key_events(key_event_logs, ONBOARDING_KEY_EVENTS_LIMIT);
    let events_block = if filtered_events.is_empty() {
        "（暂无近期关键状态事件）".to_string()
    } else {
        filtered_events.join("\n")
    };

    let onboarding_guide = catcloud_core::agent_docs::render_zh_onboarding_guide().trim();

    format!(
        "# 请做我的「猫猫云梯（CatCloud）」新手手把手上手导师\n\
\n\
## 给 AI 导师的对话说明\n\
\n\
你好！我正在使用桌面代理管理工具「猫猫云梯（CatCloud）」，我可能是完全不懂代理、协议或网络术语的新手。\n\
请你严格按照以下方式一步一步带我上手：\n\
\n\
1. **先看现状，再带下一步**：请仔细阅读最下方「我当前的实时脱敏状态快照」，先用 1～2 句大白话告诉我我现在走到了哪一步。\n\
2. **一次只教当下最该做的下一小步**：千万不要一口气把所有教程全倒出来！每次只给我 1 个具体、马上能点的小操作，等我回复做完后再继续带我走下一步。\n\
3. **严格用界面上的准确中文按钮名指路**：请对照下方官方上手总纲中的页面名称和按钮名告诉我“点左边哪一页 → 点哪个按钮”，**不要甩源码、配置文件字段名或命令行/终端黑话**（除非我主动要求了解高级用法）。\n\
4. **遇异常优先解卡**：如果我的状态快照里显示有报错、未导入节点、或安全软件拦截提示，请先优先帮我把这个卡点解决掉。\n\
\n\
---\n\
\n\
{onboarding_guide}\n\
\n\
---\n\
\n\
## 我当前的实时脱敏状态快照\n\
\n\
> 以下信息已自动完成隐私脱敏（订阅链接凭据、密码、Token、本地用户名与非系统盘路径、私网及公网 IP 末段均已隐藏），可直接安全发给 AI。\n\
\n\
- 软件版本与环境：猫猫云梯 v{app_version} · {os_label_zh} · {admin_zh}\n\
- 资产进度：订阅 {sub_count} 个 · 节点共 {total_nodes} 个（已启用 {enabled_nodes} 个，已测速 {tested_nodes} 个） · 智能多选组 {group_count} 个 · 国内中转 {relay_count} 条\n\
- 当前路线方式与选中项：{route_mode_zh} ｜ {selection_desc}\n\
- 代理与网络接管：代理核心「{core_state}」 ｜ 分流模式「{proxy_mode_zh}」 ｜ 系统代理「{sys_proxy_zh}」 ｜ 虚拟网卡「{tun_zh}」\n\
- 国内提速与本机环境：{preaccel_brief}\n\
{security_guidance_line}{last_err_line}\
\n\
### 最近关键事件（最多 {ONBOARDING_KEY_EVENTS_LIMIT} 条，已过滤普通连接与底层调试信息）\n\
\n\
```text\n\
{events_block}\n\
```\n\
\n\
请根据我上面当前的真实进度，告诉我现在最先应该做的**下一小步**是什么吧！\n"
    )
}

#[allow(clippy::too_many_arguments)]
fn build_web_ai_realtime_snapshot_section(
    lang: &str,
    app_version: &str,
    os_label: &str,
    is_elevated: bool,
    cfg: &AppConfig,
    rt: &CoreRuntimeStatus,
    runtime_dto: Option<&CoreRuntimeInfoDto>,
    global_status: &GlobalPreAccelStatus,
    counts: (usize, usize, usize, usize, usize, usize),
    last_error: Option<&str>,
    key_event_logs: &[String],
) -> String {
    let norm_lang = catcloud_core::agent_docs::normalize_doc_lang(Some(lang));
    let (sub_count, total_nodes, enabled_nodes, tested_nodes, group_count, relay_count) = counts;
    let route_mode = runtime_dto
        .map(|d| d.route_mode.as_str())
        .unwrap_or_else(|| cfg.route_mode.as_str());
    let active_group_name = app_log::sanitize_log_line(
        runtime_dto
            .map(|d| d.active_group_name.as_str())
            .unwrap_or("--"),
    );
    let active_node_name = app_log::sanitize_log_line(
        runtime_dto
            .map(|d| d.active_node_name.as_str())
            .unwrap_or("--"),
    );
    let active_node_region = runtime_dto
        .map(|d| d.active_node_region.as_str())
        .unwrap_or("--");
    let clean_err = last_error
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(sanitize_log_text);
    let security_guidance = global_status
        .security_guidance
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(sanitize_log_text);

    if norm_lang == "zh-CN" {
        let os_label_zh = format_onboarding_os_label_zh(os_label);
        let route_mode_zh = if route_mode == "single" {
            "单节点直选"
        } else {
            "智能多选组"
        };
        let selection_desc = if total_nodes == 0 {
            "尚未导入任何节点".to_string()
        } else if route_mode == "single" {
            format!("单节点「{active_node_name}」（地区：{active_node_region}）")
        } else {
            format!("智能多选组「{active_group_name}」 → 当前生效节点「{active_node_name}」（地区：{active_node_region}）")
        };
        let core_state = if rt.running { "运行中" } else { "未启动" };
        let proxy_mode_zh = match cfg.proxy_mode {
            ProxyMode::Rule => "规则分流（国内外自动分流）",
            ProxyMode::Global => "全局代理",
            ProxyMode::Direct => "全部直连",
        };
        let sys_proxy_zh = if cfg.system_proxy.enabled {
            "已开启"
        } else {
            "未开启"
        };
        let eff_tun = runtime_dto
            .map(|d| d.tun_enabled)
            .unwrap_or(cfg.tun.enabled && is_elevated);
        let tun_need_elev = runtime_dto
            .map(|d| d.tun_needs_elevation)
            .unwrap_or(cfg.tun.enabled && !is_elevated);
        let tun_zh = if eff_tun {
            "已开启"
        } else if tun_need_elev {
            "未生效（需管理员权限）"
        } else {
            "未开启"
        };
        let admin_zh = if is_elevated {
            "已是管理员权限"
        } else {
            "普通用户权限"
        };
        let preaccel_brief = format_onboarding_preaccel_plain_zh(
            global_status,
            cfg.preaccel.enabled,
            eff_tun,
            rt.running,
        );
        let filtered_events =
            filter_onboarding_key_events(key_event_logs, ONBOARDING_KEY_EVENTS_LIMIT);
        let events_block = if filtered_events.is_empty() {
            "（暂无近期关键状态事件）".to_string()
        } else {
            filtered_events.join("\n")
        };
        let security_line = security_guidance
            .map(|g| format!("- 安全软件放行提示：{g}\n"))
            .unwrap_or_default();
        let err_line = clean_err
            .map(|e| format!("- 最近异常提示：{e}\n"))
            .unwrap_or_else(|| "- 最近异常提示：无\n".to_string());
        format!(
            "## 我当前的实时脱敏进度快照\n\
\n\
> 以下信息已自动完成隐私脱敏（订阅链接凭据、密码、Token、本地路径及公私网 IP 末段均已隐藏），可直接安全发给 AI。\n\
\n\
- 软件版本与环境：猫猫云梯 v{app_version} · {os_label_zh} · {admin_zh}\n\
- 资产进度：订阅 {sub_count} 个 · 节点共 {total_nodes} 个（已启用 {enabled_nodes} 个，已测速 {tested_nodes} 个） · 智能多选组 {group_count} 个 · 国内中转 {relay_count} 条\n\
- 当前路线方式与选中项：{route_mode_zh} ｜ {selection_desc}\n\
- 代理与网络接管：代理核心「{core_state}」 ｜ 分流模式「{proxy_mode_zh}」 ｜ 系统代理「{sys_proxy_zh}」 ｜ 虚拟网卡「{tun_zh}」\n\
- 国内提速与本机环境：{preaccel_brief}\n\
{security_line}{err_line}\
\n\
### 最近关键事件（最多 {ONBOARDING_KEY_EVENTS_LIMIT} 条）\n\
\n\
```text\n\
{events_block}\n\
```\n\
\n\
请结合我上面当前的真实进度，告诉我现在最先应该做的**下一小步**是什么吧！"
        )
    } else {
        let events_sanitized: Vec<String> = key_event_logs
            .iter()
            .rev()
            .take(ONBOARDING_KEY_EVENTS_LIMIT)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .map(|l| sanitize_log_text(l))
            .collect();
        let events_block = if events_sanitized.is_empty() {
            "(no recent key events)".to_string()
        } else {
            events_sanitized.join("\n")
        };
        let err_text = clean_err.unwrap_or_else(|| "none".to_string());
        let eff_tun = runtime_dto
            .map(|d| d.tun_enabled)
            .unwrap_or(cfg.tun.enabled && is_elevated);
        let tun_need_elev = runtime_dto
            .map(|d| d.tun_needs_elevation)
            .unwrap_or(cfg.tun.enabled && !is_elevated);
        let tun_active = rt.running && eff_tun;
        let tun_en = if eff_tun {
            "true"
        } else if tun_need_elev {
            "false (needs_elevation)"
        } else {
            "false"
        };
        let preaccel_brief =
            format_global_preaccel_brief(global_status, cfg.preaccel.enabled, tun_active);
        let (heading, ask_line) = match norm_lang {
            "ja" => (
                "## 現在のリアルタイム状態スナップショット（自動マスキング済み）",
                "上記の状態を踏まえて、今すぐ実行すべき**次の 1 ステップ**を教えてください。",
            ),
            "ru" => (
                "## Текущий снимок состояния (автоматически обезличен)",
                "Исходя из текущего состояния выше, подскажи **один следующий конкретный шаг**.",
            ),
            _ => (
                "## My Current Sanitized Progress Snapshot",
                "Based on my current state above, please tell me the **single next step** I should take right now.",
            ),
        };
        format!(
            "{heading}\n\
\n\
- App / OS: CatCloud v{app_version} · {os_label} · elevated={is_elevated}\n\
- Inventory: subscriptions={sub_count}, nodes={total_nodes} (enabled={enabled_nodes}, tested={tested_nodes}), groups={group_count}, relays={relay_count}\n\
- Routing: route_mode={route_mode}, group={active_group_name}, node={active_node_name} ({active_node_region})\n\
- Core & Takeover: core_running={}, proxy_mode={}, system_proxy={}, tun={}\n\
- Domestic Boost: {preaccel_brief}\n\
- Last Error: {err_text}\n\
\n\
### Recent Key Events (up to {ONBOARDING_KEY_EVENTS_LIMIT})\n\
\n\
```text\n\
{events_block}\n\
```\n\
\n\
{ask_line}",
            rt.running,
            cfg.proxy_mode.as_str(),
            cfg.system_proxy.enabled,
            tun_en,
        )
    }
}

#[tauri::command]
pub async fn build_ai_onboarding_prompt(
    state: State<'_, AppState>,
    lang: Option<String>,
    module_id: Option<String>,
) -> Result<String, String> {
    let norm_lang = resolve_effective_doc_lang(&state, lang.as_deref());
    let target_module = module_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(catcloud_core::agent_docs::ONBOARDING_DOC_ID);
    let guide = catcloud_core::agent_docs::render_web_ai_guide(target_module, norm_lang)
        .map_err(|e| e.to_string())?;

    let cfg = state.snapshot_config();
    let rt = state.snapshot_runtime();
    let plat = default_platform();
    let caps = plat.capabilities();
    let runtime_dto = build_runtime_info_dto(&state).ok();
    let global_status = state.snapshot_global_preaccel();

    let (sub_count, total_nodes, enabled_nodes, tested_nodes, group_count, relay_count) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let subs = db.list_subscriptions().map(|v| v.len()).unwrap_or(0);
        let nodes = db.list_nodes().unwrap_or_default();
        let total = nodes.len();
        let enabled = nodes.iter().filter(|n| n.enabled).count();
        let tested = if nodes.is_empty() {
            0
        } else {
            let node_ids: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
            db.get_probe_snapshots_batch(&node_ids, None)
                .map(|snaps| {
                    snaps
                        .values()
                        .filter(|s| {
                            s.latency_ms.is_some_and(|ms| ms.is_finite() && ms > 0.0)
                                || s.up_mbps.is_some_and(|v| v.is_finite() && v > 0.0)
                                || s.down_mbps.is_some_and(|v| v.is_finite() && v > 0.0)
                                || s.ok
                        })
                        .count()
                })
                .unwrap_or(0)
        };
        let groups = db.list_multi_groups().map(|v| v.len()).unwrap_or(0);
        let relays = db.list_preaccel_relays(false).map(|v| v.len()).unwrap_or(0);
        (subs, total, enabled, tested, groups, relays)
    };

    let last_error = rt
        .last_error
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(app_log::sanitize_log_line)
        .or_else(|| state.last_app_error_snapshot());

    let ring_events = state
        .app_logger
        .read_recent_key_events(app_log::MAX_KEY_EVENT_RING_LEN);
    let logger = Arc::clone(&state.app_logger);
    let disk_logs = tokio::task::spawn_blocking(move || {
        logger.read_recent_lines(DIAGNOSTICS_DISK_SCAN_LIMIT)
    })
    .await
    .unwrap_or_default();
    let mem_logs = state.telemetry.logs_snapshot();
    let merged_logs = merge_sanitized_recent_logs(disk_logs, mem_logs, DIAGNOSTICS_DISK_SCAN_LIMIT);
    let merged_key_events =
        merge_diagnostic_key_events(ring_events, &merged_logs, DIAGNOSTICS_KEY_EVENTS_LIMIT);

    let snapshot = build_web_ai_realtime_snapshot_section(
        norm_lang,
        env!("CARGO_PKG_VERSION"),
        &caps.os,
        caps.is_elevated,
        &cfg,
        &rt,
        runtime_dto.as_ref(),
        &global_status,
        (
            sub_count,
            total_nodes,
            enabled_nodes,
            tested_nodes,
            group_count,
            relay_count,
        ),
        last_error.as_deref(),
        &merged_key_events,
    );

    Ok(format!("{}\n\n---\n\n{snapshot}\n", guide.trim()))
}

#[cfg(test)]
fn build_sanitized_diagnostics_report(
    state: &AppState,
    live_conns: Option<&ConnectionsSnapshot>,
) -> Result<serde_json::Value, String> {
    build_sanitized_diagnostics_report_with_disk_logs(state, live_conns, None)
}

fn build_sanitized_diagnostics_report_with_disk_logs(
    state: &AppState,
    live_conns: Option<&ConnectionsSnapshot>,
    preloaded_disk_logs: Option<Vec<String>>,
) -> Result<serde_json::Value, String> {
    let cfg = state.snapshot_config();
    let rt = state.snapshot_runtime();
    let plat = default_platform();
    let caps = plat.capabilities();
    let runtime_dto = build_runtime_info_dto(state).ok();
    let global_status = state.snapshot_global_preaccel();
    let (sub_count, node_count, group_count, relay_count) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        (
            db.list_subscriptions().map(|v| v.len()).unwrap_or(0),
            db.list_nodes().map(|v| v.len()).unwrap_or(0),
            db.list_multi_groups().map(|v| v.len()).unwrap_or(0),
            db.list_preaccel_relays(false).map(|v| v.len()).unwrap_or(0),
        )
    };

    let (conn_summary, core_mem_bytes) = if let Some(snap) = live_conns {
        let summary = summarize_connections(&snap.connections);
        let mem = if snap.memory > 0 {
            snap.memory
        } else {
            state
                .cached_metrics
                .read()
                .map(|m| m.core_mem_bytes)
                .unwrap_or(0)
        };
        (summary, mem)
    } else if let Ok(m) = state.cached_metrics.read() {
        (
            ConnectionSummaryCounts {
                app_connections: m.app_connections,
                tunnel_connections: m.tunnel_connections,
                direct_connections: m.direct_connections,
                proxied_connections: m.proxied_connections,
            },
            m.core_mem_bytes,
        )
    } else {
        (ConnectionSummaryCounts::default(), 0)
    };

    let geodata_status = collect_geodata_status(&state.paths.runtime_dir);
    let last_error = rt
        .last_error
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(app_log::sanitize_log_line)
        .or_else(|| state.last_app_error_snapshot());
    let ring_key_events = state
        .app_logger
        .read_recent_key_events(app_log::MAX_KEY_EVENT_RING_LEN);
    let all_merged_logs = match preloaded_disk_logs {
        Some(disk_lines) => {
            let mem_logs = state.telemetry.logs_snapshot();
            merge_sanitized_recent_logs(disk_lines, mem_logs, DIAGNOSTICS_DISK_SCAN_LIMIT)
        }
        None => collect_sanitized_recent_logs(state, DIAGNOSTICS_DISK_SCAN_LIMIT),
    };
    let key_event_logs = merge_diagnostic_key_events(
        ring_key_events,
        &all_merged_logs,
        DIAGNOSTICS_KEY_EVENTS_LIMIT,
    );
    let (_, tail_logs) = sample_diagnostic_logs(&all_merged_logs, 0, DIAGNOSTICS_TAIL_LOGS_LIMIT);
    let recent_logs = {
        let start = all_merged_logs
            .len()
            .saturating_sub(DIAGNOSTICS_JSON_RECENT_LOGS_LIMIT);
        all_merged_logs[start..].to_vec()
    };

    let route_mode = runtime_dto
        .as_ref()
        .map(|d| d.route_mode.clone())
        .unwrap_or_else(|| cfg.route_mode.as_str().to_string());
    let active_group_name = app_log::sanitize_log_line(
        runtime_dto
            .as_ref()
            .map(|d| d.active_group_name.as_str())
            .unwrap_or("默认路线"),
    );
    let active_node_name = app_log::sanitize_log_line(
        runtime_dto
            .as_ref()
            .map(|d| d.active_node_name.as_str())
            .unwrap_or("待导入节点"),
    );
    let active_node_region = runtime_dto
        .as_ref()
        .map(|d| d.active_node_region.clone())
        .unwrap_or_else(|| "--".to_string());
    let preaccel_relay_name = runtime_dto
        .as_ref()
        .and_then(|d| d.preaccel_relay_name.as_deref())
        .map(app_log::sanitize_log_line);

    let cli_path_display = catcloud_core::sanitize::redact_path_for_display(
        &resolve_local_cli_path(state).to_string_lossy(),
    );
    let data_dir_display = catcloud_core::sanitize::redact_path_for_display(
        &catcloud_core::paths::normalize_os_path(&state.paths.root_data_dir).to_string_lossy(),
    );

    let os_label = format!("{} {}", caps.os, caps.arch);
    let ai_prompt_markdown = build_ai_diagnostics_markdown(
        env!("CARGO_PKG_VERSION"),
        &os_label,
        caps.is_elevated,
        state.paths.is_portable,
        &cfg,
        &rt,
        runtime_dto.as_ref(),
        &global_status,
        (sub_count, node_count, group_count, relay_count),
        conn_summary,
        core_mem_bytes,
        &geodata_status,
        last_error.as_deref(),
        &key_event_logs,
        &tail_logs,
        &cli_path_display,
        &data_dir_display,
    );

    let eff_tun = runtime_dto
        .as_ref()
        .map(|d| d.tun_enabled)
        .unwrap_or(effective_tun_enabled(state, &cfg));
    let tun_need_elev = runtime_dto
        .as_ref()
        .map(|d| d.tun_needs_elevation)
        .unwrap_or(tun_needs_elevation(state, &cfg));
    Ok(serde_json::json!({
        "app_version": env!("CARGO_PKG_VERSION"),
        "os": caps.os,
        "arch": caps.arch,
        "is_elevated": caps.is_elevated,
        "is_portable": state.paths.is_portable,
        "instance_hash": state.paths.instance_hash,
        "cli_path": cli_path_display,
        "data_dir": data_dir_display,
        "core_running": rt.running,
        "core_version": rt.version,
        "proxy_mode": cfg.proxy_mode,
        "mixed_port": if rt.running { rt.mixed_port } else { cfg.mixed_port },
        "controller_port": if rt.running { rt.controller_port } else { cfg.controller_port },
        "dns_listen_port": if rt.running { rt.dns_listen_port } else { cfg.dns_listen_port },
        "core_ipv6": cfg.core_ipv6,
        "dns_ipv6": cfg.dns.ipv6,
        "tun_enabled": eff_tun,
        "tun_configured": cfg.tun.enabled,
        "tun_needs_elevation": tun_need_elev,
        "tun_stack": cfg.tun.stack_mode,
        "preaccel_enabled": cfg.preaccel.enabled,
        "skip_443_native": cfg.preaccel.skip_443_native,
        "counts": {
            "subscriptions": sub_count,
            "nodes": node_count,
            "multi_groups": group_count,
            "preaccel_relays": relay_count,
        },
        "route_summary": {
            "route_mode": route_mode,
            "active_group_name": active_group_name,
            "active_node_name": active_node_name,
            "active_node_region": active_node_region,
            "system_proxy_enabled": cfg.system_proxy.enabled,
            "tun_enabled": eff_tun,
            "tun_configured": cfg.tun.enabled,
            "tun_needs_elevation": tun_need_elev,
            "preaccel_active": cfg.preaccel.enabled,
            "preaccel_relay_name": preaccel_relay_name,
            "domestic_direct_enabled": cfg.rules_override.domestic_direct_enabled,
            "block_quic_udp_443": cfg.rules_override.block_quic_udp_443,
            "memory_tier": cfg.core_runtime.memory_tier,
        },
        "geodata_status": geodata_status,
        "connection_summary": {
            "app_connections": conn_summary.app_connections,
            "tunnel_connections": conn_summary.tunnel_connections,
            "direct_connections": conn_summary.direct_connections,
            "proxied_connections": conn_summary.proxied_connections,
        },
        "last_error": last_error,
        "key_event_logs": key_event_logs,
        "recent_logs": recent_logs,
        "ai_prompt_markdown": ai_prompt_markdown,
        "sanitized": true
    }))
}

#[tauri::command]
pub async fn export_sanitized_diagnostics(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let live_snap = if state.snapshot_runtime().running && state.adapter.has_live_controller().await
    {
        tokio::time::timeout(Duration::from_millis(600), state.adapter.list_connections())
            .await
            .ok()
            .and_then(|res| res.ok())
    } else {
        None
    };

    if let Some(ref snap) = live_snap {
        let summary = summarize_connections(&snap.connections);
        if let Ok(mut m) = state.cached_metrics.write() {
            m.app_connections = summary.app_connections;
            m.tunnel_connections = summary.tunnel_connections;
            m.direct_connections = summary.direct_connections;
            m.proxied_connections = summary.proxied_connections;
            if snap.upload_total > m.up_total_bytes {
                m.up_total_bytes = snap.upload_total;
            }
            if snap.download_total > m.down_total_bytes {
                m.down_total_bytes = snap.download_total;
            }
            if snap.memory > 0 {
                m.core_mem_bytes = snap.memory;
            }
        }
    }

    let logger = Arc::clone(&state.app_logger);
    let disk_logs = tokio::task::spawn_blocking(move || {
        logger.read_recent_lines(DIAGNOSTICS_DISK_SCAN_LIMIT)
    })
    .await
    .unwrap_or_default();

    build_sanitized_diagnostics_report_with_disk_logs(&state, live_snap.as_ref(), Some(disk_logs))
}

fn inspect_geodata_file(runtime_dir: &std::path::Path, candidates: &[&str]) -> serde_json::Value {
    for name in candidates {
        let path = runtime_dir.join(name);
        if let Ok(meta) = std::fs::metadata(&path) {
            if meta.is_file() {
                let updated_at = meta
                    .modified()
                    .ok()
                    .map(|t| chrono::DateTime::<Utc>::from(t).to_rfc3339());
                return serde_json::json!({
                    "exists": true,
                    "size_bytes": meta.len(),
                    "updated_at": updated_at
                });
            }
        }
    }
    serde_json::json!({
        "exists": false,
        "size_bytes": 0u64,
        "updated_at": null
    })
}

fn collect_geodata_status(runtime_dir: &std::path::Path) -> serde_json::Value {
    serde_json::json!({
        "country_mmdb": inspect_geodata_file(runtime_dir, &["Country.mmdb", "country.mmdb"]),
        "geoip_dat": inspect_geodata_file(runtime_dir, &["geoip.dat", "GeoIP.dat"]),
        "geosite_dat": inspect_geodata_file(runtime_dir, &["geosite.dat", "GeoSite.dat"]),
        "asn_mmdb": inspect_geodata_file(runtime_dir, &["GeoLite2-ASN.mmdb", "geolite2-asn.mmdb", "asn.mmdb"]),
    })
}

#[tauri::command]
pub fn get_geodata_status(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    Ok(collect_geodata_status(&state.paths.runtime_dir))
}

const MAX_GEODATA_DOWNLOAD_BYTES: usize = 64 * 1024 * 1024;

fn resolve_geodata_target_spec<'a>(
    target: &str,
    geodata: &'a catcloud_core::models::GeoDataConfig,
) -> Option<(&'static str, &'a str, &'static str)> {
    match target.trim().to_ascii_lowercase().as_str() {
        "mmdb" | "country" | "country_mmdb" | "country-lite" => {
            Some(("mmdb", geodata.mmdb_url.as_str(), "Country.mmdb"))
        }
        "geoip" | "geoip_dat" => Some(("geoip", geodata.geoip_url.as_str(), "geoip.dat")),
        "geosite" | "geosite_dat" => {
            Some(("geosite", geodata.geosite_url.as_str(), "geosite.dat"))
        }
        "asn" | "asn_mmdb" => Some(("asn", geodata.asn_url.as_str(), "GeoLite2-ASN.mmdb")),
        _ => None,
    }
}

async fn fetch_geodata_bytes_once(
    url: &str,
    proxy_port: Option<u16>,
) -> Result<Vec<u8>, String> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(90))
        .user_agent(format!("CatCloud/{}", env!("CARGO_PKG_VERSION")));
    if let Some(port) = proxy_port {
        let proxy_url = format!("http://127.0.0.1:{port}");
        let proxy = reqwest::Proxy::all(&proxy_url)
            .map_err(|e| format!("构造本地代理客户端失败：{e}"))?;
        builder = builder.proxy(proxy);
    } else {
        builder = builder.no_proxy();
    }
    let client = builder
        .build()
        .map_err(|e| format!("初始化地理数据库下载客户端失败：{e}"))?;
    let mut resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("下载地理数据库失败：{e}"))?;
    if !resp.status().is_success() {
        return Err(format!("下载地理数据库返回 HTTP {}", resp.status().as_u16()));
    }
    if let Some(len) = resp.content_length() {
        if len > MAX_GEODATA_DOWNLOAD_BYTES as u64 {
            return Err("地理数据库文件超过安全体积上限（64 MiB）".to_string());
        }
    }
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("读取地理数据库响应流失败：{e}"))?
    {
        if buf.len().saturating_add(chunk.len()) > MAX_GEODATA_DOWNLOAD_BYTES {
            return Err("地理数据库文件超过安全体积上限（64 MiB）".to_string());
        }
        buf.extend_from_slice(&chunk);
    }
    if buf.len() < 1024 {
        return Err("下载到的地理数据库体积异常偏小，已放弃覆盖".to_string());
    }
    let head = String::from_utf8_lossy(&buf[..buf.len().min(256)]).to_ascii_lowercase();
    if head.contains("<!doctype html") || head.contains("<html") {
        return Err("地理数据库源返回了网页内容而非二进制数据，已放弃覆盖".to_string());
    }
    Ok(buf)
}

async fn download_geodata_file_atomic(
    url: &str,
    dest: &std::path::Path,
    local_proxy_port: Option<u16>,
) -> Result<usize, String> {
    let trimmed = url.trim();
    if !(trimmed.starts_with("https://") || trimmed.starts_with("http://")) {
        return Err("地理数据库下载地址必须是 http:// 或 https:// 链接".to_string());
    }
    let bytes = if let Some(port) = local_proxy_port {
        match fetch_geodata_bytes_once(trimmed, Some(port)).await {
            Ok(b) => b,
            Err(_) => fetch_geodata_bytes_once(trimmed, None).await?,
        }
    } else {
        fetch_geodata_bytes_once(trimmed, None).await?
    };
    let len = bytes.len();
    let dest_owned = dest.to_path_buf();
    tokio::task::spawn_blocking(move || AppPaths::atomic_write(&dest_owned, &bytes))
        .await
        .map_err(|e| format!("写入地理数据库任务异常：{e}"))?
        .map_err(|e| format!("原子落盘地理数据库失败：{e}"))?;
    Ok(len)
}

#[tauri::command]
pub async fn refresh_geo_db(
    state: State<'_, AppState>,
    targets: Option<Vec<String>>,
) -> Result<serde_json::Value, String> {
    let cfg = state.snapshot_config();
    let requested_targets = targets
        .filter(|list| !list.is_empty())
        .unwrap_or_else(|| {
            vec![
                "geoip".to_string(),
                "geosite".to_string(),
                "mmdb".to_string(),
                "asn".to_string(),
            ]
        });

    let core_live = state.adapter.has_live_controller().await;
    let rt = if core_live {
        Some(state.adapter.status().await)
    } else {
        None
    };
    let local_proxy_port = rt
        .as_ref()
        .filter(|r| r.running && r.mixed_port > 0)
        .map(|r| r.mixed_port);

    // When the core is running and user asked for a full refresh (or non-mmdb dat files),
    // trigger Mihomo's `/configs/geo` first, then ensure canonical `Country.mmdb` (and any
    // explicitly requested files missing or served from `country-lite.mmdb`) are atomically written.
    let mut core_geo_ok = false;
    let mut core_geo_err: Option<String> = None;
    if let Some(ref rt_live) = rt {
        let secret = state.adapter.controller_secret().await;
        let url = format!(
            "http://{}:{}/configs/geo",
            if rt_live.controller_host == "0.0.0.0" {
                "127.0.0.1"
            } else {
                rt_live.controller_host.as_str()
            },
            rt_live.controller_port
        );
        if let Ok(client) = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(60))
            .build()
        {
            match client.post(&url).bearer_auth(&secret).send().await {
                Ok(resp) if resp.status().is_success() => {
                    core_geo_ok = true;
                }
                Ok(resp) => {
                    core_geo_err = Some(format!(
                        "核心地理数据库更新返回 HTTP {}",
                        resp.status().as_u16()
                    ));
                }
                Err(e) => {
                    core_geo_err = Some(format!("请求核心地理数据库更新失败：{e}"));
                }
            }
        }
    }

    let mut updated_targets: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut seen_keys: HashSet<&'static str> = HashSet::new();

    for target in &requested_targets {
        let Some((canon_key, dl_url, filename)) =
            resolve_geodata_target_spec(target, &cfg.geodata)
        else {
            continue;
        };
        if !seen_keys.insert(canon_key) {
            continue;
        }
        let dest = state.paths.runtime_dir.join(filename);
        let need_atomic_download = if canon_key == "mmdb" {
            // Always download lightweight `mmdb_url` atomically to canonical `Country.mmdb`
            // whenever core is stopped, `/configs/geo` failed, or `Country.mmdb` is absent.
            !core_geo_ok || !dest.is_file() || requested_targets.len() == 1
        } else {
            !core_geo_ok || !dest.is_file()
        };

        if need_atomic_download {
            match download_geodata_file_atomic(dl_url, &dest, local_proxy_port).await {
                Ok(bytes) => {
                    updated_targets.push(canon_key.to_string());
                    state.log_app_event(
                        "info",
                        "地理库",
                        &format!(
                            "已原子更新 {filename}（{}）",
                            format_bytes_human(bytes as u64)
                        ),
                    );
                }
                Err(err) => {
                    errors.push(format!("{filename}: {err}"));
                }
            }
        } else {
            updated_targets.push(canon_key.to_string());
        }
    }

    if updated_targets.is_empty() {
        let detail = if !errors.is_empty() {
            errors.join("；")
        } else if let Some(err) = core_geo_err {
            err
        } else {
            "未指定可更新的地理数据库目标".to_string()
        };
        return Err(detail);
    }

    let message = if errors.is_empty() {
        if core_geo_ok {
            "地理数据库已更新并原子写入运行目录".to_string()
        } else {
            "地理数据库已直接下载并原子写入运行目录".to_string()
        }
    } else {
        format!(
            "部分地理数据库已更新（成功：{}；未完成：{}）",
            updated_targets.join(", "),
            errors.join("；")
        )
    };

    Ok(serde_json::json!({
        "ok": true,
        "updated_targets": updated_targets,
        "message": message
    }))
}

fn can_auto_stage_portable_update(is_portable_install: bool) -> bool {
    is_portable_install && cfg!(target_os = "windows")
}

fn manifest_asset_is_zip(asset: &catcloud_core::updater::PlatformAsset) -> bool {
    let candidate = asset
        .filename
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(asset.url.as_str());
    let without_query = candidate.split(['?', '#']).next().unwrap_or(candidate);
    without_query.to_ascii_lowercase().ends_with(".zip")
}

fn resolve_can_auto_stage_for_manifest(
    is_portable_install: bool,
    platform_key: Option<&str>,
    manifest: Option<&catcloud_core::updater::LatestManifest>,
) -> bool {
    if !can_auto_stage_portable_update(is_portable_install) {
        return false;
    }
    let Some(key) = platform_key else {
        return false;
    };
    manifest
        .and_then(|m| m.platforms.get(key))
        .is_some_and(manifest_asset_is_zip)
}

fn resolve_staged_update_version(
    staging_dir: &std::path::Path,
    current_version: &str,
    include_prerelease: bool,
) -> Option<String> {
    let pending = catcloud_core::updater::verify_staged_payload_integrity(staging_dir).ok()?;
    if catcloud_core::updater::is_update_available_for_channel(
        &pending.target_version,
        current_version,
        include_prerelease,
    )
    .unwrap_or(false)
    {
        Some(pending.target_version)
    } else {
        None
    }
}

fn persist_last_update_check_time(app: &AppHandle, state: &AppState, checked_at: &str) {
    let updated_cfg = if let Ok(mut guard) = state.config.write() {
        guard.update.last_checked_at = Some(checked_at.to_string());
        guard.clone()
    } else {
        let mut fallback = state.snapshot_config();
        fallback.update.last_checked_at = Some(checked_at.to_string());
        fallback
    };
    let _ = config::save(&state.paths, &updated_cfg);
    emit_runtime_snapshot(app, state);
}

async fn resolve_expected_archive_sha256(
    updater: &Updater,
    manifest: &catcloud_core::updater::LatestManifest,
    asset: &catcloud_core::updater::PlatformAsset,
) -> Option<String> {
    if let Ok(inline_sha) = catcloud_core::updater::resolve_asset_sha256(asset, None) {
        return Some(inline_sha);
    }
    let sums_url = manifest
        .sha256sums_url
        .clone()
        .unwrap_or_else(|| updater.default_sha256sums_url());
    if catcloud_core::updater::validate_https_url(&sums_url).is_err() {
        return None;
    }
    let client = catcloud_core::updater::build_safe_http_client(
        catcloud_core::updater::METADATA_REQUEST_TIMEOUT,
    )
    .ok()?;
    let mut resp = client.get(&sums_url).send().await.ok()?;
    if catcloud_core::updater::validate_https_url(resp.url().as_str()).is_err()
        || !resp.status().is_success()
    {
        return None;
    }
    if resp
        .content_length()
        .is_some_and(|cl| cl > catcloud_core::updater::MAX_METADATA_BYTES as u64)
    {
        return None;
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await.ok()? {
        if buf.len().saturating_add(chunk.len()) > catcloud_core::updater::MAX_METADATA_BYTES {
            return None;
        }
        buf.extend_from_slice(&chunk);
    }
    let sums_text = String::from_utf8(buf).ok()?;
    let sums_map = catcloud_core::updater::parse_sha256sums(&sums_text).ok()?;
    catcloud_core::updater::resolve_asset_sha256(asset, Some(&sums_map)).ok()
}

/// Download, SHA256-verify, and stage a portable update archive from an already-fetched manifest.
/// Caller MUST hold `state.update_staging_lock`.
#[allow(clippy::too_many_arguments)]
async fn stage_update_from_manifest_locked(
    app: &AppHandle,
    state: &AppState,
    updater: &Updater,
    res: &catcloud_core::updater::UpdateCheckResult,
    update_available: bool,
    is_portable_install: bool,
    platform_key: Option<&'static str>,
    release_url: &str,
    silent_background: bool,
) -> Result<serde_json::Value, String> {
    let can_auto_stage =
        resolve_can_auto_stage_for_manifest(is_portable_install, platform_key, Some(&res.manifest));
    let download_url = platform_key
        .and_then(|key| res.manifest.platforms.get(key))
        .map(|asset| asset.url.clone());

    if !update_available {
        return Ok(serde_json::json!({
            "staged": false,
            "reused": false,
            "already_latest": true,
            "can_auto_stage": can_auto_stage,
            "current_version": res.current_version,
            "latest_version": res.latest_version,
            "target_version": null,
            "archive_sha256": null,
            "platform_key": platform_key,
            "release_url": release_url,
            "download_url": download_url,
            "message": format!("当前已是最新版本 v{}", res.current_version),
        }));
    }

    let (Some(key), Some(asset)) = (
        platform_key,
        platform_key.and_then(|k| res.manifest.platforms.get(k)),
    ) else {
        let guide_msg = format!(
            "当前系统架构暂未提供自动预置更新包，请前往官方 Release 页面下载 v{} 安装包",
            res.latest_version
        );
        if !silent_background {
            state.log_app_event("info", "软件更新", &guide_msg);
        }
        return Ok(serde_json::json!({
            "staged": false,
            "reused": false,
            "already_latest": false,
            "can_auto_stage": false,
            "current_version": res.current_version,
            "latest_version": res.latest_version,
            "target_version": res.latest_version,
            "archive_sha256": null,
            "platform_key": platform_key,
            "release_url": release_url,
            "download_url": download_url,
            "message": guide_msg,
        }));
    };

    if !can_auto_stage {
        let guide_msg = if cfg!(target_os = "windows") {
            format!(
                "当前为安装版或未提供便携 ZIP 更新包，请前往官方 Release 页面下载 v{} 安装包",
                res.latest_version
            )
        } else {
            format!(
                "当前平台（{key}）请前往官方 Release 页面下载 v{} 安装包完成更新",
                res.latest_version
            )
        };
        if !silent_background {
            state.log_app_event("info", "软件更新", &guide_msg);
        }
        return Ok(serde_json::json!({
            "staged": false,
            "reused": false,
            "already_latest": false,
            "can_auto_stage": false,
            "current_version": res.current_version,
            "latest_version": res.latest_version,
            "target_version": res.latest_version,
            "archive_sha256": null,
            "platform_key": Some(key),
            "release_url": release_url,
            "download_url": download_url,
            "message": guide_msg,
        }));
    }

    let expected_sha = resolve_expected_archive_sha256(updater, &res.manifest, asset).await;
    if state.paths.staging_dir.exists() {
        match catcloud_core::updater::verify_staged_payload_integrity(&state.paths.staging_dir) {
            Ok(existing) => {
                let version_matches = existing.target_version == res.latest_version;
                let sha_matches = expected_sha
                    .as_deref()
                    .is_some_and(|exp| existing.archive_sha256.eq_ignore_ascii_case(exp));
                if version_matches && sha_matches {
                    let msg = format!(
                        "v{} 更新包已在本地完成校验，下次重启猫猫云梯时自动生效",
                        existing.target_version
                    );
                    if !silent_background {
                        state.log_app_event("info", "软件更新", &msg);
                    }
                    return Ok(serde_json::json!({
                        "staged": true,
                        "reused": true,
                        "already_latest": false,
                        "can_auto_stage": true,
                        "current_version": res.current_version,
                        "latest_version": res.latest_version,
                        "target_version": existing.target_version,
                        "archive_sha256": existing.archive_sha256,
                        "platform_key": Some(key),
                        "release_url": release_url,
                        "download_url": download_url,
                        "message": msg,
                    }));
                }
                if version_matches && expected_sha.is_some() && !sha_matches {
                    state.log_app_event(
                        "warning",
                        "软件更新",
                        &format!(
                            "检测到本地预置的 v{} 更新包摘要与最新清单不一致，已清理缓存并重新下载校验",
                            existing.target_version
                        ),
                    );
                    let _ = std::fs::remove_dir_all(&state.paths.staging_dir);
                }
            }
            Err(err) => {
                state.log_app_event(
                    "warning",
                    "软件更新",
                    &format!("检测到本地预置更新包损坏或缺失（{err}），已清理并重新下载"),
                );
                let _ = std::fs::remove_dir_all(&state.paths.staging_dir);
            }
        }
    }

    if state.shutting_down.load(Ordering::SeqCst) {
        return Err("应用正在退出，已取消更新包下载".to_string());
    }

    state.log_app_event(
        "info",
        "软件更新",
        &format!(
            "{}下载并校验 v{} 便携更新包（平台：{key}）",
            if silent_background { "后台自动" } else { "开始" },
            res.latest_version
        ),
    );

    let staged = updater
        .download_and_stage(&res.manifest, key, &state.paths.staging_dir)
        .await
        .map_err(|e| {
            let err_msg = format!("下载或校验 v{} 更新包失败：{e}", res.latest_version);
            state.log_app_event(
                if silent_background { "warning" } else { "error" },
                "软件更新",
                &err_msg,
            );
            err_msg
        })?;

    let short_sha: String = staged.archive_sha256.chars().take(12).collect();
    let ok_msg = format!(
        "已{}下载并完成 SHA256 校验 v{}（{short_sha}），下次重启猫猫云梯时自动替换生效",
        if silent_background { "在后台自动" } else { "" },
        staged.target_version
    );
    state.log_app_event("info", "软件更新", &ok_msg);
    emit_runtime_snapshot(app, state);

    Ok(serde_json::json!({
        "staged": true,
        "reused": false,
        "already_latest": false,
        "can_auto_stage": true,
        "current_version": res.current_version,
        "latest_version": res.latest_version,
        "target_version": staged.target_version,
        "archive_sha256": staged.archive_sha256,
        "platform_key": Some(key),
        "release_url": release_url,
        "download_url": download_url,
        "message": ok_msg,
    }))
}

pub(crate) async fn check_and_optionally_stage_update_internal(
    app: &AppHandle,
    state: &AppState,
    allow_auto_stage: bool,
) -> Result<serde_json::Value, String> {
    let cfg = state.snapshot_config();
    let current = env!("CARGO_PKG_VERSION").to_string();
    let checked_at = Utc::now().to_rfc3339();
    let repo_clean = cfg.update.repo.trim().trim_matches('/');
    let release_url = format!("https://github.com/{repo_clean}/releases/latest");
    let is_portable_install = state.paths.is_self_updatable_portable();
    let platform_key = catcloud_core::updater::current_update_platform_key_opt(is_portable_install);

    let updater = Updater::new(cfg.update.repo.clone(), current.clone())
        .map_err(|e| e.to_string())?;
    match updater.check_latest(None).await {
        Ok(res) => {
            persist_last_update_check_time(app, state, &checked_at);

            let latest_cfg = state.snapshot_config();
            let update_available = catcloud_core::updater::is_update_available_for_channel(
                &res.latest_version,
                &current,
                latest_cfg.update.include_prerelease,
            )
            .unwrap_or(false);
            let can_auto_stage = resolve_can_auto_stage_for_manifest(
                is_portable_install,
                platform_key,
                Some(&res.manifest),
            );
            let download_url = platform_key
                .and_then(|key| res.manifest.platforms.get(key))
                .map(|asset| asset.url.clone());

            let mut staged_version = if let Ok(_guard) = state.update_staging_lock.try_lock() {
                resolve_staged_update_version(
                    &state.paths.staging_dir,
                    &current,
                    latest_cfg.update.include_prerelease,
                )
            } else {
                None
            };

            let mut auto_staged = false;
            let mut auto_stage_reused = false;
            if allow_auto_stage && update_available && can_auto_stage {
                let _staging_guard = state.update_staging_lock.lock().await;
                if !state.shutting_down.load(Ordering::SeqCst) {
                    match stage_update_from_manifest_locked(
                        app,
                        state,
                        &updater,
                        &res,
                        update_available,
                        is_portable_install,
                        platform_key,
                        &release_url,
                        true,
                    )
                    .await
                    {
                        Ok(stage_val) => {
                            if stage_val
                                .get("staged")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false)
                            {
                                auto_staged = true;
                                auto_stage_reused = stage_val
                                    .get("reused")
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false);
                                staged_version = stage_val
                                    .get("target_version")
                                    .and_then(|v| v.as_str())
                                    .map(str::to_string)
                                    .or(staged_version);
                            }
                        }
                        Err(err) => {
                            tracing::warn!("background auto-stage update failed: {err}");
                        }
                    }
                }
            }

            Ok(serde_json::json!({
                "has_update": update_available,
                "current_version": res.current_version,
                "latest_version": res.latest_version,
                "release_url": release_url,
                "notes": res.notes,
                "checked_at": checked_at,
                "staged_version": staged_version,
                "platform_key": platform_key,
                "can_auto_stage": can_auto_stage,
                "download_url": download_url,
                "auto_staged": auto_staged,
                "auto_stage_reused": auto_stage_reused,
                "error": null
            }))
        }
        Err(err) => {
            let staged_version = if let Ok(_guard) = state.update_staging_lock.try_lock() {
                resolve_staged_update_version(
                    &state.paths.staging_dir,
                    &current,
                    cfg.update.include_prerelease,
                )
            } else {
                None
            };
            Ok(serde_json::json!({
                "has_update": false,
                "current_version": current,
                "latest_version": current,
                "release_url": release_url,
                "notes": "",
                "checked_at": checked_at,
                "staged_version": staged_version,
                "platform_key": platform_key,
                "can_auto_stage": false,
                "download_url": null,
                "auto_staged": false,
                "auto_stage_reused": false,
                "error": err.to_string()
            }))
        }
    }
}

pub(crate) async fn download_and_stage_update_internal(
    app: &AppHandle,
    state: &AppState,
) -> Result<serde_json::Value, String> {
    let _staging_guard = state.update_staging_lock.lock().await;
    if state.shutting_down.load(Ordering::SeqCst) {
        return Err("应用正在退出，已取消下载更新".to_string());
    }

    let cfg = state.snapshot_config();
    let current = env!("CARGO_PKG_VERSION").to_string();
    let checked_at = Utc::now().to_rfc3339();
    let repo_clean = cfg.update.repo.trim().trim_matches('/');
    let release_url = format!("https://github.com/{repo_clean}/releases/latest");
    let is_portable_install = state.paths.is_self_updatable_portable();
    let platform_key = catcloud_core::updater::current_update_platform_key_opt(is_portable_install);

    let updater = Updater::new(cfg.update.repo.clone(), current.clone())
        .map_err(|e| e.to_string())?;
    let res = updater.check_latest(None).await.map_err(|e| {
        let msg = format!("检查最新版本失败：{e}");
        state.log_app_event("warning", "软件更新", &msg);
        msg
    })?;

    persist_last_update_check_time(app, state, &checked_at);

    let latest_cfg = state.snapshot_config();
    let update_available = catcloud_core::updater::is_update_available_for_channel(
        &res.latest_version,
        &current,
        latest_cfg.update.include_prerelease,
    )
    .unwrap_or(false);

    stage_update_from_manifest_locked(
        app,
        state,
        &updater,
        &res,
        update_available,
        is_portable_install,
        platform_key,
        &release_url,
        false,
    )
    .await
}

#[tauri::command]
pub async fn check_app_update(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    check_and_optionally_stage_update_internal(&app, &state, false).await
}

#[tauri::command]
pub async fn download_and_stage_update(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    download_and_stage_update_internal(&app, &state).await
}

#[tauri::command]
pub fn export_backup_bundle(
    state: State<'_, AppState>,
    target_path: Option<String>,
) -> Result<serde_json::Value, String> {
    let mut cfg = state.snapshot_config();
    if cfg
        .controller_secret
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty())
    {
        cfg.controller_secret = Some("<REDACTED>".to_string());
    }
    let (groups, mut relays, probes) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        (
            db.list_multi_groups().map_err(|e| e.to_string())?,
            db.list_preaccel_relays(false).map_err(|e| e.to_string())?,
            db.list_probe_definitions().map_err(|e| e.to_string())?,
        )
    };
    for relay in &mut relays {
        if !relay.server.trim().is_empty() {
            relay.server = "<REDACTED>".to_string();
        }
        if !relay.password.trim().is_empty() {
            relay.password = "<REDACTED>".to_string();
        }
    }
    let exported_at = Utc::now().to_rfc3339();
    let bundle = serde_json::json!({
        "schema": "catcloud-backup/v1",
        "exported_at": exported_at,
        "app_version": env!("CARGO_PKG_VERSION"),
        "sanitized": true,
        "config": cfg,
        "multi_groups": groups,
        "preaccel_relays": relays,
        "probe_definitions": probes
    });
    let bytes = serde_json::to_vec_pretty(&bundle).map_err(|e| e.to_string())?;
    let out_path = match target_path.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        Some(p) => PathBuf::from(p),
        None => {
            std::fs::create_dir_all(&state.paths.backup_dir).map_err(|e| e.to_string())?;
            state.paths.backup_dir.join(format!(
                "catcloud-backup-{}.json",
                Utc::now().format("%Y%m%d-%H%M%S")
            ))
        }
    };
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(&out_path, &bytes).map_err(|e| e.to_string())?;
    let sha256 = compute_file_sha256(&out_path).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "path": out_path.display().to_string(),
        "bytes": bytes.len(),
        "sha256": sha256,
        "exported_at": exported_at
    }))
}

const REDACTED_PLACEHOLDER: &str = "<REDACTED>";

fn is_redacted_placeholder(s: &str) -> bool {
    s.trim() == REDACTED_PLACEHOLDER
}

fn preserve_local_secrets_in_config(existing: &AppConfig, incoming: &mut AppConfig) {
    if incoming
        .controller_secret
        .as_deref()
        .is_some_and(is_redacted_placeholder)
    {
        incoming.controller_secret = existing
            .controller_secret
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty() && !is_redacted_placeholder(s))
            .map(str::to_string);
    }
}

/// Merge a deserialized backup relay with any existing local relay of the same ID so
/// `"<REDACTED>"` placeholders never overwrite real local credentials or fail validation.
/// Returns `false` if a required redacted field has no local value to preserve (caller skips).
fn merge_redacted_backup_relay(
    existing: Option<&PreAccelRelay>,
    incoming: &mut PreAccelRelay,
) -> bool {
    if is_redacted_placeholder(&incoming.server) {
        if let Some(local_server) = existing
            .map(|r| r.server.trim())
            .filter(|s| !s.is_empty() && !is_redacted_placeholder(s))
        {
            incoming.server = local_server.to_string();
        } else {
            return false;
        }
    }
    if is_redacted_placeholder(&incoming.password) {
        if let Some(local_pw) = existing
            .map(|r| r.password.trim())
            .filter(|s| !s.is_empty() && !is_redacted_placeholder(s))
        {
            incoming.password = local_pw.to_string();
        } else {
            return false;
        }
    }
    true
}

#[tauri::command]
pub async fn import_backup_bundle(
    app: AppHandle,
    state: State<'_, AppState>,
    bundle_json: String,
) -> Result<serde_json::Value, String> {
    let parsed: serde_json::Value = serde_json::from_str(&bundle_json)
        .map_err(|e| format!("备份文件 JSON 格式无效：{e}"))?;
    let mut restored_config = false;
    let mut restored_groups = 0usize;
    let mut restored_relays = 0usize;
    let mut skipped_redacted_relays = 0usize;

    let old_cfg = state.snapshot_config();
    if let Some(cfg_val) = parsed.get("config") {
        let mut next: AppConfig = serde_json::from_value(cfg_val.clone())
            .map_err(|e| format!("备份中的配置格式无效：{e}"))?;
        preserve_local_secrets_in_config(&old_cfg, &mut next);
        next.preaccel.reconcile_unified_enabled();
        config::save(&state.paths, &next).map_err(|e| format!("写入恢复配置失败：{e}"))?;
        if let Ok(mut guard) = state.config.write() {
            *guard = next;
        }
        restored_config = true;
    }

    {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        if let Some(arr) = parsed.get("multi_groups").and_then(|v| v.as_array()) {
            for item in arr {
                if let Ok(g) = serde_json::from_value::<MultiGroup>(item.clone()) {
                    db.upsert_multi_group(&g).map_err(|e| e.to_string())?;
                    restored_groups += 1;
                }
            }
        }
        if let Some(arr) = parsed.get("preaccel_relays").and_then(|v| v.as_array()) {
            for item in arr {
                if let Ok(mut r) = serde_json::from_value::<PreAccelRelay>(item.clone()) {
                    let existing = db.get_preaccel_relay(&r.id).ok().flatten();
                    if !merge_redacted_backup_relay(existing.as_ref(), &mut r) {
                        skipped_redacted_relays += 1;
                        continue;
                    }
                    catcloud_core::preaccel::schema::validate_relay_strict(&r)
                        .map_err(|e| format!("备份中的国内中转校验未通过：{e}"))?;
                    db.upsert_preaccel_relay(&r).map_err(|e| e.to_string())?;
                    restored_relays += 1;
                }
            }
        }
        if let Some(arr) = parsed.get("probe_definitions").and_then(|v| v.as_array()) {
            for item in arr {
                if let Ok(p) = serde_json::from_value::<ProbeDefinition>(item.clone()) {
                    let _ = db.upsert_probe_definition(&p);
                }
            }
        }
    }

    prune_node_health_pool_from_db(&state);
    let _ = trigger_reload_if_running(&app, &state, true).await;
    let cfg = state.snapshot_config();
    emit_config_updated(&app, &cfg);
    sync_app_side_effects(&app, &state, &cfg);

    let message = if skipped_redacted_relays > 0 {
        format!(
            "备份已成功恢复（已跳过 {skipped_redacted_relays} 条脱敏中转占位项，保留本地密钥未受损）"
        )
    } else {
        "备份已成功恢复".to_string()
    };

    Ok(serde_json::json!({
        "restored_config": restored_config,
        "restored_groups": restored_groups,
        "restored_relays": restored_relays,
        "skipped_redacted_relays": skipped_redacted_relays,
        "message": message
    }))
}

#[tauri::command]
pub fn launch_uwp_loopback() -> Result<serde_json::Value, String> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let output = std::process::Command::new("CheckNetIsolation.exe")
            .args(["LoopbackExempt", "-s"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&output.stdout).to_string();
        let exempt_count = text.lines().filter(|l| l.contains("Name:")).count();
        Ok(serde_json::json!({
            "supported": true,
            "launched": output.status.success(),
            "exempt_count": exempt_count,
            "message": format!("已检查 Windows 应用本地回环放行状态（当前已放行 {exempt_count} 项）")
        }))
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(serde_json::json!({
            "supported": false,
            "launched": false,
            "message": "应用本地回环放行仅支持 Windows 系统"
        }))
    }
}

#[tauri::command]
pub async fn hot_swap_core(
    app: AppHandle,
    state: State<'_, AppState>,
    binary_path: String,
) -> Result<serde_json::Value, String> {
    let trimmed = binary_path.trim();
    let candidate = PathBuf::from(trimmed);
    if !candidate.is_file() {
        return Err(format!("所选内核文件不存在：{trimmed}"));
    }
    let sha256 = compute_file_sha256(&candidate).map_err(|e| e.to_string())?;
    let _cfg_guard = state.config_transition_lock.lock().await;
    let mut cfg = state.snapshot_config();
    cfg.core_runtime.custom_binary_path = Some(candidate.display().to_string());
    config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
    if let Ok(mut guard) = state.config.write() {
        *guard = cfg.clone();
    }
    let version = if state.adapter.has_live_controller().await {
        let rt = restart_core_locked(&app, &state).await?;
        rt.core_version
    } else {
        "已配置".to_string()
    };
    Ok(serde_json::json!({
        "ok": true,
        "version": version,
        "sha256": sha256,
        "binary_path": candidate.display().to_string(),
        "message": "代理核心文件已更新"
    }))
}

#[tauri::command]
pub fn open_app_dir(state: State<'_, AppState>, kind: String) -> Result<String, String> {
    let path = match kind.trim().to_ascii_lowercase().as_str() {
        "data" | "root" | "data_root" => &state.paths.root_data_dir,
        "config" => &state.paths.config_dir,
        "logs" | "log" => &state.paths.logs_dir,
        "bin" | "core" => &state.paths.bin_dir,
        "backup" | "backups" => &state.paths.backup_dir,
        other => return Err(format!("未知的目录类型「{other}」")),
    };
    open_directory_in_os(path)
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

fn percent_encode_query_value(raw: &str) -> String {
    percent_encode_path_segment(raw)
}

fn redact_web_ui_secret_in_url(url: &str) -> String {
    let mut out = String::with_capacity(url.len());
    let mut rest = url;
    while let Some(pos) = rest.find("secret=") {
        let prefix_ok =
            pos == 0 || matches!(rest.as_bytes()[pos - 1], b'?' | b'&' | b'#' | b';');
        if !prefix_ok {
            out.push_str(&rest[..pos + "secret=".len()]);
            rest = &rest[pos + "secret=".len()..];
            continue;
        }
        out.push_str(&rest[..pos + "secret=".len()]);
        let after = &rest[pos + "secret=".len()..];
        let val_end = after
            .find(|c| c == '&' || c == '#')
            .unwrap_or(after.len());
        out.push_str("***");
        rest = &after[val_end..];
    }
    out.push_str(rest);
    out
}

fn build_web_ui_urls(
    template: &str,
    host: &str,
    port: u16,
    secret: &str,
) -> Result<(String, String), String> {
    let trimmed = template.trim();
    let encoded_secret = percent_encode_query_value(secret);
    let port_str = port.to_string();
    let has_placeholder = trimmed.contains("{host}")
        || trimmed.contains("{port}")
        || trimmed.contains("{secret}");
    let launch_url = if has_placeholder {
        trimmed
            .replace("{host}", host)
            .replace("{port}", &port_str)
            .replace("{secret}", &encoded_secret)
    } else {
        let sep = if trimmed.ends_with('?') || trimmed.ends_with('&') {
            ""
        } else if trimmed.contains('?') {
            "&"
        } else {
            "?"
        };
        let encoded_host = percent_encode_query_value(host);
        format!(
            "{trimmed}{sep}http=true&hostname={encoded_host}&port={port_str}&secret={encoded_secret}"
        )
    };
    if !launch_url.starts_with("https://") && !launch_url.starts_with("http://") {
        return Err("控制面板地址必须以 http:// 或 https:// 开头".to_string());
    }
    let display_url = redact_web_ui_secret_in_url(&launch_url);
    Ok((launch_url, display_url))
}

#[tauri::command]
pub async fn open_web_ui(
    state: State<'_, AppState>,
    url: Option<String>,
) -> Result<String, String> {
    let cfg = state.snapshot_config();
    let rt = state.snapshot_runtime();
    let host = if rt.running && rt.controller_host != "0.0.0.0" {
        rt.controller_host.as_str()
    } else {
        "127.0.0.1"
    };
    let port = if rt.running {
        rt.controller_port
    } else {
        cfg.controller_port
    };
    let live_secret = if state.adapter.has_live_controller().await {
        state.adapter.controller_secret().await
    } else {
        String::new()
    };
    let secret = if !live_secret.trim().is_empty() {
        live_secret
    } else {
        cfg.controller_secret.clone().unwrap_or_default()
    };
    let template = url
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| cfg.webui_urls.first().map(|w| w.url_template.clone()))
        .unwrap_or_else(|| {
            "https://metacubex.github.io/metacubexd/#/setup?http=true&hostname={host}&port={port}&secret={secret}".to_string()
        });
    let (launch_url, sanitized_url) = build_web_ui_urls(&template, host, port, &secret)?;
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(&launch_url)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(&launch_url)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(&launch_url)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    Ok(sanitized_url)
}

/// Validate an external HTTPS URL for OS browser launch:
/// strictly trims whitespace, rejects control characters, requires `https://`,
/// forbids embedded userinfo credentials, and never appends controller host/port/secret.
fn validate_external_https_url(raw: &str) -> Result<String, String> {
    if raw.chars().any(|c| c.is_control()) {
        return Err("外部链接包含非法控制字符，已拒绝打开".to_string());
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("外部链接不能为空".to_string());
    }
    if trimmed.len() <= 8 || !trimmed[..8].eq_ignore_ascii_case("https://") {
        return Err("仅允许打开安全的 https:// 外部链接".to_string());
    }
    if matches!(trimmed.as_bytes().get(8), Some(b'/' | b'\\')) {
        return Err("外部链接缺少有效主机名".to_string());
    }
    let parsed = reqwest::Url::parse(trimmed)
        .map_err(|e| format!("外部链接格式无效：{e}"))?;
    if parsed.scheme() != "https" {
        return Err("仅允许打开安全的 https:// 外部链接".to_string());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("外部链接不允许包含账号或密码凭据".to_string());
    }
    let host = parsed.host_str().map(str::trim).unwrap_or("");
    if host.is_empty() {
        return Err("外部链接缺少有效主机名".to_string());
    }
    Ok(parsed.to_string())
}

#[tauri::command]
pub async fn open_external_url(url: String) -> Result<String, String> {
    let safe_url = validate_external_https_url(&url)?;
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(&safe_url)
            .spawn()
            .map_err(|e| format!("无法打开外部链接：{e}"))?;
        Ok(safe_url)
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(&safe_url)
            .spawn()
            .map_err(|e| format!("无法打开外部链接：{e}"))?;
        Ok(safe_url)
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(&safe_url)
            .spawn()
            .map_err(|e| format!("无法打开外部链接：{e}"))?;
        Ok(safe_url)
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = safe_url;
        Err("当前操作系统暂不支持自动打开外部链接，请手动复制链接后在浏览器打开".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ui_dto_preserves_auto_memory_tier_roundtrip() {
        let mut cfg = AppConfig::default();
        cfg.core_runtime.memory_tier = MemoryLimitTier::Auto;
        let dto = UiAppConfigDto::from(&cfg);
        assert_eq!(dto.gomemlimit_mb, 0);
        assert_eq!(dto.memory_tier, Some(MemoryLimitTier::Auto));

        let mut restored = AppConfig::default();
        restored.core_runtime.memory_tier = MemoryLimitTier::Mb96;
        apply_ui_dto(&mut restored, &dto);
        assert_eq!(restored.core_runtime.memory_tier, MemoryLimitTier::Auto);

        let mut legacy_dto = dto.clone();
        legacy_dto.memory_tier = None;
        legacy_dto.gomemlimit_mb = 64;
        apply_ui_dto(&mut restored, &legacy_dto);
        assert_eq!(restored.core_runtime.memory_tier, MemoryLimitTier::Mb64);
    }

    #[test]
    fn json_deep_merge_updates_nested_fields_without_clobbering_siblings() {
        let mut base = serde_json::json!({
            "dns": { "ipv6": false, "prefer_h3": false },
            "mixed_port": 7890
        });
        let patch = serde_json::json!({
            "dns": { "prefer_h3": true }
        });
        json_deep_merge(&mut base, &patch);
        assert_eq!(base["dns"]["ipv6"], false);
        assert_eq!(base["dns"]["prefer_h3"], true);
        assert_eq!(base["mixed_port"], 7890);
    }

    #[test]
    fn mask_ip_redacts_last_segment_for_ipv4_and_ipv6() {
        assert_eq!(mask_ip_address("203.0.113.42"), "203.0.113.***");
        assert_eq!(mask_ip_address("2001:db8::1"), "2001:db8::***");
        assert_eq!(mask_ip_address(""), "--.--.--.***");
    }

    #[test]
    fn wallpaper_encoder_resizes_and_caches_local_png_to_data_url() {
        let tmp = std::env::temp_dir().join(format!(
            "catcloud_wp_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let cache = tmp.join("cache");
        std::fs::create_dir_all(&tmp).expect("mkdir tmp");
        let img_path = tmp.join("sample.png");
        let img = image::RgbImage::from_pixel(64, 48, image::Rgb([223, 183, 130]));
        img.save(&img_path).expect("save png");

        let url1 = encode_wallpaper_data_url_from_path(
            &img_path.display().to_string(),
            &cache,
        )
        .expect("encode first");
        assert!(url1.starts_with("data:image/jpeg;base64,"));
        let url2 = encode_wallpaper_data_url_from_path(
            &img_path.display().to_string(),
            &cache,
        )
        .expect("encode cached");
        assert_eq!(url1, url2);

        let remote = encode_wallpaper_data_url_from_path("https://example.invalid/bg.jpg", &cache)
            .expect("remote passthrough");
        assert_eq!(remote, "https://example.invalid/bg.jpg");

        assert!(
            encode_wallpaper_data_url_from_path("data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=", &cache)
                .is_err()
        );
        assert!(
            encode_wallpaper_data_url_from_path("data:image/png;base64,iVBORw0KGgo=", &cache)
                .is_ok()
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn json_deep_merge_replaces_nameserver_policy_and_empty_objects() {
        let mut base = serde_json::json!({
            "dns": {
                "ipv6": false,
                "nameserver_policy": {
                    "old.example": ["1.1.1.1"],
                    "keep.example": ["8.8.8.8"]
                }
            }
        });
        let patch = serde_json::json!({
            "dns": {
                "nameserver_policy": {
                    "keep.example": ["9.9.9.9"]
                }
            }
        });
        json_deep_merge(&mut base, &patch);
        assert_eq!(base["dns"]["ipv6"], false);
        assert!(base["dns"]["nameserver_policy"].get("old.example").is_none());
        assert_eq!(base["dns"]["nameserver_policy"]["keep.example"][0], "9.9.9.9");

        let clear_patch = serde_json::json!({
            "dns": { "nameserver_policy": {} }
        });
        json_deep_merge(&mut base, &clear_patch);
        assert_eq!(
            base["dns"]["nameserver_policy"].as_object().map(|m| m.len()),
            Some(0)
        );
    }

    #[test]
    fn controller_endpoint_and_secret_parser_handles_pipe_and_query_tokens() {
        assert_eq!(
            parse_controller_endpoint_and_secret("http://127.0.0.1:9090|secret=abc123"),
            ("http://127.0.0.1:9090/proxies".to_string(), Some("abc123".to_string()))
        );
        assert_eq!(
            parse_controller_endpoint_and_secret("http://127.0.0.1:9090/proxies?secret=xyz"),
            ("http://127.0.0.1:9090/proxies".to_string(), Some("xyz".to_string()))
        );
        assert_eq!(
            parse_controller_endpoint_and_secret("http://127.0.0.1:9090/"),
            ("http://127.0.0.1:9090/proxies".to_string(), None)
        );
    }

    #[test]
    fn mihomo_error_formatter_extracts_clean_chinese_message() {
        let verbose = concat!(
            "Mihomo `-t` pre-flight check failed: ",
            "time=\"2026-11-23T09:10:12+08:00\" level=info msg=\"Start initial configuration in progress\"\n",
            "time=\"2026-11-23T09:10:12+08:00\" level=error msg=\"configuration file ",
            "C:\\\\Users\\\\<USER>\\\\runtime.yaml.tmp test failed: rules[18] [DOMAIN-SUFFIX] error: format invalid\""
        );
        let formatted = format_mihomo_error_for_user(verbose);
        assert!(formatted.contains("分流规则格式无效（DOMAIN-SUFFIX）"));
        assert!(!formatted.contains("level=info"));
        assert!(!formatted.contains("runtime.yaml.tmp"));
        assert!(!formatted.contains("time="));

        let missing_proxy = "time=\"2026-11-23T09:10:12+08:00\" level=error msg=\"configuration file C:\\\\tmp\\\\runtime-candidate.yaml test failed: proxy group Ghost not found\"";
        let formatted2 = format_mihomo_error_for_user(missing_proxy);
        assert!(formatted2.contains("不存在的代理节点或分组"));
        assert!(!formatted2.contains("runtime-candidate.yaml"));
    }

    #[test]
    fn select_comparison_overseas_node_prefers_non443_tcp_and_skips_udp_only() {
        let udp_node = ProxyNode {
            id: "n-hy2".to_string(),
            name: "🇯🇵 HY2".to_string(),
            protocol: "hysteria2".to_string(),
            port: 8443,
            is_443_native: false,
            enabled: true,
            ..Default::default()
        };
        let native_443 = ProxyNode {
            id: "n-443".to_string(),
            name: "🇸🇬 Trojan 443".to_string(),
            protocol: "trojan".to_string(),
            port: 443,
            is_443_native: true,
            enabled: true,
            ..Default::default()
        };
        let high_port_tcp = ProxyNode {
            id: "n-8443".to_string(),
            name: "🇯🇵 VLESS 8443".to_string(),
            protocol: "vless".to_string(),
            port: 8443,
            is_443_native: false,
            enabled: true,
            ..Default::default()
        };
        let all_nodes = vec![udp_node.clone(), native_443.clone(), high_port_tcp.clone()];

        // 1. Single mode: strictly follows homepage node even if it is native 443 (no fallback).
        let (picked_single_443, reason_single_443) = select_comparison_overseas_node(
            &[],
            &all_nodes,
            RouteTargetMode::Single,
            Some("n-443"),
            None,
            None,
        )
        .expect("single mode must follow native 443 homepage node");
        assert_eq!(picked_single_443.id, "n-443");
        assert!(reason_single_443.is_none());

        // 2. Group mode: strictly follows active group's active_node_id even if native 443.
        let grp_443 = MultiGroup {
            id: "g-main".to_string(),
            name: "主力组".to_string(),
            member_node_ids: vec!["n-8443".into(), "n-443".into()],
            active_node_id: Some("n-443".to_string()),
            ..Default::default()
        };
        let (picked_grp_443, reason_grp_443) = select_comparison_overseas_node(
            &[grp_443],
            &all_nodes,
            RouteTargetMode::Group,
            None,
            Some("g-main"),
            None,
        )
        .expect("group mode must follow active_node_id even if native 443");
        assert_eq!(picked_grp_443.id, "n-443");
        assert!(reason_grp_443.is_none());

        // 3. Group mode fallback to first member when active_node_id is None.
        let grp_first_member = MultiGroup {
            id: "g-first".to_string(),
            name: "默认组".to_string(),
            member_node_ids: vec!["n-443".into(), "n-8443".into()],
            active_node_id: None,
            ..Default::default()
        };
        let (picked_first, reason_first) = select_comparison_overseas_node(
            &[grp_first_member],
            &all_nodes,
            RouteTargetMode::Group,
            None,
            Some("g-first"),
            None,
        )
        .expect("group mode should follow first member when active_node_id is None");
        assert_eq!(picked_first.id, "n-443");
        assert!(reason_first.is_none());

        // 4. Homepage node is UDP-only -> fallback to non-443 TCP node with clear Chinese reason.
        let (picked_udp_fallback, reason_udp_fallback) = select_comparison_overseas_node(
            &[],
            &all_nodes,
            RouteTargetMode::Single,
            Some("n-hy2"),
            None,
            None,
        )
        .expect("UDP-only homepage node must fallback to TCP node");
        assert_eq!(picked_udp_fallback.id, "n-8443");
        let reason_text = reason_udp_fallback.expect("UDP fallback must include reason");
        assert!(reason_text.contains("纯 UDP 协议"));
        assert!(reason_text.contains("🇯🇵 HY2"));
        assert!(reason_text.contains("🇯🇵 VLESS 8443"));

        // 5. Homepage node is UDP-only and only 443 TCP remains -> fallback to 443 TCP with reason.
        let grp_udp = MultiGroup {
            id: "g-udp".to_string(),
            name: "HY2 组".to_string(),
            member_node_ids: vec!["n-hy2".into(), "n-443".into()],
            active_node_id: Some("n-hy2".to_string()),
            ..Default::default()
        };
        let (picked_443_fallback, reason_443_fallback) = select_comparison_overseas_node(
            &[grp_udp],
            &[udp_node.clone(), native_443.clone()],
            RouteTargetMode::Group,
            None,
            Some("g-udp"),
            None,
        )
        .expect("should fallback to 443 TCP node when no non-443 TCP exists");
        assert_eq!(picked_443_fallback.id, "n-443");
        assert!(reason_443_fallback
            .as_deref()
            .is_some_and(|r| r.contains("纯 UDP 协议") && r.contains("🇸🇬 Trojan 443")));

        // 6. Reject UDP-only when explicitly requested; allow explicit 443 TCP node without fallback.
        assert!(
            select_comparison_overseas_node(
                &[],
                &[udp_node],
                RouteTargetMode::Group,
                None,
                None,
                Some("n-hy2"),
            )
            .is_err()
        );
        let (explicit_443, explicit_reason) = select_comparison_overseas_node(
            &[],
            &all_nodes,
            RouteTargetMode::Group,
            None,
            None,
            Some("n-443"),
        )
        .expect("explicit TCP node should succeed");
        assert_eq!(explicit_443.id, "n-443");
        assert!(explicit_reason.is_none());
    }

    #[test]
    fn tray_group_candidates_pins_active_node_at_index_zero() {
        let nodes: Vec<ProxyNode> = (0..12)
            .map(|i| ProxyNode {
                id: format!("n-{i}"),
                name: format!("Node {i}"),
                enabled: true,
                ..Default::default()
            })
            .collect();
        let node_by_id: HashMap<&str, &ProxyNode> =
            nodes.iter().map(|n| (n.id.as_str(), n)).collect();
        let group = MultiGroup {
            id: "g1".to_string(),
            name: "主力".to_string(),
            member_node_ids: nodes.iter().map(|n| n.id.clone()).collect(),
            active_node_id: Some("n-11".to_string()),
            ..Default::default()
        };
        let picked = select_tray_group_candidates(&group, &nodes, &node_by_id, 8);
        assert_eq!(picked.len(), 8);
        assert_eq!(picked[0].id, "n-11");
        assert_eq!(picked[1].id, "n-0");
        assert_eq!(picked.iter().filter(|n| n.id == "n-11").count(), 1);
    }

    #[test]
    fn geoip_parsers_extract_isp_location_and_timezone() {
        let ipsb = serde_json::json!({
            "ip": "198.51.100.25",
            "isp": "NTT Communications",
            "organization": "NTT",
            "country": "Japan",
            "city": "Tokyo",
            "timezone": "Asia/Tokyo"
        });
        let r1 = parse_ipsb_geoip_json(&ipsb).expect("parse ip.sb");
        assert_eq!(r1.ip, "198.51.100.25");
        assert_eq!(r1.isp, "NTT Communications");
        assert_eq!(r1.location, "Tokyo, Japan");
        assert_eq!(r1.timezone, "Asia/Tokyo");

        let ipwho = serde_json::json!({
            "success": true,
            "ip": "203.0.113.9",
            "country": "Singapore",
            "city": "Singapore",
            "connection": { "isp": "DigitalOcean LLC", "org": "DO" },
            "timezone": { "id": "Asia/Singapore", "utc": "+08:00" }
        });
        let r2 = parse_ipwhois_json(&ipwho).expect("parse ipwho.is");
        assert_eq!(r2.location, "Singapore");
        assert_eq!(r2.isp, "DigitalOcean LLC");
        assert_eq!(r2.timezone, "Asia/Singapore");

        let trace = "fl=123\nip=203.0.113.88\nloc=JP\ncolo=NRT\n";
        let r3 = parse_cloudflare_trace(trace).expect("parse cf trace");
        assert_eq!(r3.ip, "203.0.113.88");
        assert_eq!(r3.location, "JP");
        assert!(r3.isp.contains("NRT"));
    }

    #[test]
    fn redacted_backup_merge_preserves_local_secrets_and_skips_orphaned_placeholders() {
        let mut local_cfg = AppConfig::default();
        local_cfg.controller_secret = Some("real-secret-xyz".to_string());
        let mut incoming_cfg = AppConfig::default();
        incoming_cfg.controller_secret = Some("<REDACTED>".to_string());
        preserve_local_secrets_in_config(&local_cfg, &mut incoming_cfg);
        assert_eq!(
            incoming_cfg.controller_secret.as_deref(),
            Some("real-secret-xyz")
        );

        let existing_relay = PreAccelRelay {
            id: "r1".to_string(),
            server: "203.0.113.42".to_string(),
            password: "real-password".to_string(),
            ..Default::default()
        };
        let mut incoming_relay = PreAccelRelay {
            id: "r1".to_string(),
            server: "<REDACTED>".to_string(),
            password: "<REDACTED>".to_string(),
            ..Default::default()
        };
        assert!(merge_redacted_backup_relay(
            Some(&existing_relay),
            &mut incoming_relay
        ));
        assert_eq!(incoming_relay.server, "203.0.113.42");
        assert_eq!(incoming_relay.password, "real-password");

        let mut orphan_relay = PreAccelRelay {
            id: "r2".to_string(),
            server: "<REDACTED>".to_string(),
            password: "<REDACTED>".to_string(),
            ..Default::default()
        };
        assert!(!merge_redacted_backup_relay(None, &mut orphan_relay));
    }

    #[test]
    fn collect_geodata_status_detects_present_and_missing_files() {
        let tmp = std::env::temp_dir().join(format!(
            "catcloud_geo_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&tmp).expect("mkdir tmp");
        // `country-lite.mmdb` alone must NEVER report a false-green `country_mmdb.exists == true`.
        std::fs::write(tmp.join("country-lite.mmdb"), b"legacy-lite-bytes")
            .expect("write legacy country-lite");
        let lite_only = collect_geodata_status(&tmp);
        assert_eq!(lite_only["country_mmdb"]["exists"], false);
        assert_eq!(lite_only["country_mmdb"]["size_bytes"], 0);

        std::fs::write(tmp.join("Country.mmdb"), b"mock-mmdb-bytes").expect("write mmdb");
        std::fs::write(tmp.join("geosite.dat"), b"mock-geosite").expect("write geosite");

        let status = collect_geodata_status(&tmp);
        assert_eq!(status["country_mmdb"]["exists"], true);
        assert_eq!(status["country_mmdb"]["size_bytes"], 15);
        assert!(status["country_mmdb"]["updated_at"].is_string());
        assert_eq!(status["geosite_dat"]["exists"], true);
        assert_eq!(status["geoip_dat"]["exists"], false);
        assert_eq!(status["asn_mmdb"]["exists"], false);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn relaunch_admin_args_preserves_data_dir_and_appends_flags() {
        let fallback = PathBuf::from("C:\\CatCloudFallback");
        let raw = vec![
            std::ffi::OsString::from("--silent"),
            std::ffi::OsString::from("--data-dir"),
            std::ffi::OsString::from("D:\\CatCloudData"),
        ];
        let args = collect_relaunch_admin_args(&raw, Some(&fallback), true);
        assert_eq!(
            args,
            vec![
                "--data-dir",
                "D:\\CatCloudData",
                "--restarting",
                "--enable-tun"
            ]
        );

        let raw_eq = vec![std::ffi::OsString::from("--data-dir=E:\\Data")];
        let args_no_tun = collect_relaunch_admin_args(&raw_eq, Some(&fallback), false);
        assert_eq!(args_no_tun, vec!["--data-dir=E:\\Data", "--restarting"]);

        let raw_no_dir = vec![std::ffi::OsString::from("--silent")];
        let args_with_fallback =
            collect_relaunch_admin_args(&raw_no_dir, Some(&fallback), true);
        assert_eq!(
            args_with_fallback,
            vec![
                "--data-dir",
                "C:\\CatCloudFallback",
                "--restarting",
                "--enable-tun"
            ]
        );
    }

    #[test]
    fn system_proxy_ownership_check_protects_third_party_proxies() {
        let mut cfg = AppConfig::default();
        cfg.mixed_port = 7890;
        let mut rt = CoreRuntimeStatus::default();
        rt.running = true;
        rt.mixed_port = 17890;

        let own_runtime = SystemProxySpec {
            enabled: true,
            host: "127.0.0.1".to_string(),
            port: 17890,
            bypass: vec![],
            pac_url: None,
        };
        assert!(is_system_proxy_owned_by_us(&cfg, &rt, &own_runtime));

        let own_config_port = SystemProxySpec {
            enabled: true,
            host: "127.0.0.1".to_string(),
            port: 7890,
            bypass: vec![],
            pac_url: None,
        };
        assert!(is_system_proxy_owned_by_us(&cfg, &rt, &own_config_port));

        // Third-party capture proxy (e.g. Fiddler/Charles on port 8888) must NOT be cleared.
        let third_party_capture = SystemProxySpec {
            enabled: true,
            host: "127.0.0.1".to_string(),
            port: 8888,
            bypass: vec![],
            pac_url: None,
        };
        assert!(!is_system_proxy_owned_by_us(&cfg, &rt, &third_party_capture));

        // Corporate PAC must NOT be cleared even if fallback parsed host/port equals 127.0.0.1:7890.
        let corp_pac = SystemProxySpec {
            enabled: true,
            host: "127.0.0.1".to_string(),
            port: 7890,
            bypass: vec![],
            pac_url: Some("http://corp.example.invalid/wpad.dat".to_string()),
        };
        assert!(!is_system_proxy_owned_by_us(&cfg, &rt, &corp_pac));

        let own_pac = SystemProxySpec {
            enabled: true,
            host: "127.0.0.1".to_string(),
            port: 7890,
            bypass: vec![],
            pac_url: Some(format!("http://127.0.0.1:{}/proxy.pac", cfg.system_proxy.pac.port)),
        };
        assert!(is_system_proxy_owned_by_us(&cfg, &rt, &own_pac));
    }

    #[test]
    fn web_ui_url_builder_encodes_appends_bare_url_and_redacts_secret() {
        let secret = "p@ss%&+#=? 123";
        let (launch_tpl, safe_tpl) = build_web_ui_urls(
            "https://panel.example.invalid/#/setup?hostname={host}&port={port}&secret={secret}",
            "127.0.0.1",
            9090,
            secret,
        )
        .expect("template url");
        assert!(launch_tpl.contains("secret=p%40ss%25%26%2B%23%3D%3F%20123"));
        assert!(safe_tpl.ends_with("secret=***"));
        assert!(!safe_tpl.contains("p%40ss"));

        let (launch_bare, safe_bare) = build_web_ui_urls(
            "https://panel.example.invalid/#/setup",
            "127.0.0.1",
            9090,
            "s&1",
        )
        .expect("bare url");
        assert_eq!(
            launch_bare,
            "https://panel.example.invalid/#/setup?http=true&hostname=127.0.0.1&port=9090&secret=s%261"
        );
        assert_eq!(
            safe_bare,
            "https://panel.example.invalid/#/setup?http=true&hostname=127.0.0.1&port=9090&secret=***"
        );

        let (launch_with_q, safe_with_q) = build_web_ui_urls(
            "https://panel.example.invalid/#/setup?theme=dark",
            "127.0.0.1",
            9090,
            "abc",
        )
        .expect("bare url with existing query");
        assert_eq!(
            launch_with_q,
            "https://panel.example.invalid/#/setup?theme=dark&http=true&hostname=127.0.0.1&port=9090&secret=abc"
        );
        assert_eq!(
            safe_with_q,
            "https://panel.example.invalid/#/setup?theme=dark&http=true&hostname=127.0.0.1&port=9090&secret=***"
        );
    }

    #[test]
    fn format_tcp_host_port_brackets_ipv6_addresses() {
        assert_eq!(format_tcp_host_port("203.0.113.42", 443), "203.0.113.42:443");
        assert_eq!(
            format_tcp_host_port("relay.example.invalid", 8443),
            "relay.example.invalid:8443"
        );
        assert_eq!(
            format_tcp_host_port("2001:db8::1", 443),
            "[2001:db8::1]:443"
        );
        assert_eq!(
            format_tcp_host_port("[2001:db8::1]", 443),
            "[2001:db8::1]:443"
        );
    }

    #[test]
    fn map_tray_click_distinguishes_all_five_actions() {
        assert_eq!(
            map_tray_click(&CoreTrayClickAction::ToggleMainWindow),
            TrayClickAction::ToggleMain
        );
        assert_eq!(
            map_tray_click(&CoreTrayClickAction::ToggleCapsule),
            TrayClickAction::ToggleCapsule
        );
        assert_eq!(
            map_tray_click(&CoreTrayClickAction::ToggleSystemProxy),
            TrayClickAction::ToggleSystemProxy
        );
        assert_eq!(
            map_tray_click(&CoreTrayClickAction::SwitchNextBest),
            TrayClickAction::SwitchNextBest
        );
        assert_eq!(
            map_tray_click(&CoreTrayClickAction::None),
            TrayClickAction::ShowMenu
        );
    }

    #[test]
    fn sanitize_group_active_node_clears_ghost_and_picks_best_scored_candidate() {
        let ghost_ar = ProxyNode {
            id: "n-ar".to_string(),
            sub_id: "sub-1".to_string(),
            name: "🇦🇷 阿根廷".to_string(),
            enabled: true,
            multiplier: 1.0,
            ..Default::default()
        };
        let tw_slow = ProxyNode {
            id: "n-tw".to_string(),
            sub_id: "sub-1".to_string(),
            name: "🇹🇼 台湾 01".to_string(),
            enabled: true,
            multiplier: 1.0,
            ..Default::default()
        };
        let jp_best = ProxyNode {
            id: "n-jp".to_string(),
            sub_id: "sub-1".to_string(),
            name: "🇯🇵 日本 02".to_string(),
            enabled: true,
            multiplier: 1.0,
            ..Default::default()
        };
        let us_disabled = ProxyNode {
            id: "n-us-off".to_string(),
            sub_id: "sub-1".to_string(),
            name: "🇺🇸 已禁用".to_string(),
            enabled: false,
            multiplier: 1.0,
            ..Default::default()
        };
        let nodes = vec![ghost_ar, tw_slow, jp_best, us_disabled];

        let mut snaps = HashMap::new();
        snaps.insert(
            "n-tw".to_string(),
            ProbeSnapshot {
                node_id: "n-tw".to_string(),
                ok: true,
                latency_ms: Some(120.0),
                up_mbps: Some(10.0),
                down_mbps: Some(50.0),
                google_clean: Some(true),
                ..Default::default()
            },
        );
        snaps.insert(
            "n-jp".to_string(),
            ProbeSnapshot {
                node_id: "n-jp".to_string(),
                ok: true,
                latency_ms: Some(55.0),
                up_mbps: Some(80.0),
                down_mbps: Some(200.0),
                google_clean: Some(true),
                ..Default::default()
            },
        );

        let mut group = MultiGroup {
            id: "g-ai".to_string(),
            name: "测试多选组".to_string(),
            mode: MultiGroupMode::StickyBest,
            hard_gates: vec!["google_clean == 1".to_string()],
            member_node_ids: vec![
                "n-us-off".to_string(),
                "n-tw".to_string(),
                "n-jp".to_string(),
            ],
            active_node_id: Some("n-ar".to_string()),
            ..Default::default()
        };

        // 1. Ghost active_node_id outside member_node_ids is replaced by top-scoring candidate.
        assert!(sanitize_group_active_node(&mut group, &nodes, &snaps));
        assert_eq!(group.active_node_id.as_deref(), Some("n-jp"));

        // 2. Calling again while active_node_id is valid and enabled makes no change.
        assert!(!sanitize_group_active_node(&mut group, &nodes, &snaps));
        assert_eq!(group.active_node_id.as_deref(), Some("n-jp"));

        // 3. When no members are probed yet, ghost active_node_id falls back to first enabled member.
        let empty_snaps = HashMap::new();
        group.active_node_id = Some("n-ar".to_string());
        assert!(sanitize_group_active_node(&mut group, &nodes, &empty_snaps));
        assert_eq!(group.active_node_id.as_deref(), Some("n-tw"));

        // 4. When only disabled members remain, ghost active_node_id is cleared to None.
        group.member_node_ids = vec!["n-us-off".to_string()];
        group.active_node_id = Some("n-ar".to_string());
        assert!(sanitize_group_active_node(&mut group, &nodes, &snaps));
        assert_eq!(group.active_node_id, None);
    }

    #[test]
    fn build_runtime_info_dto_never_exposes_removed_ghost_active_node() {
        let tmp = std::env::temp_dir().join(format!(
            "catcloud_ghost_dto_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let paths = AppPaths::from_data_dir(tmp.clone(), true).expect("resolve test paths");
        let storage = Storage::open_in_memory().expect("open in-memory storage");

        let sub = SubscriptionRecord {
            id: "sub-ghost".to_string(),
            name: "测试订阅".to_string(),
            kind: SubscriptionKind::Migrated,
            url_or_cmd: "local://test".to_string(),
            enabled: true,
            ..Default::default()
        };
        storage.upsert_subscription(&sub).expect("upsert sub");

        let ghost_ar = ProxyNode {
            id: "n-ar".to_string(),
            sub_id: "sub-ghost".to_string(),
            name: "🇦🇷 阿根廷幽灵".to_string(),
            region_code: "AR".to_string(),
            protocol: "trojan".to_string(),
            server: "198.51.100.1".to_string(),
            port: 443,
            enabled: true,
            ..Default::default()
        };
        let tw_member = ProxyNode {
            id: "n-tw".to_string(),
            sub_id: "sub-ghost".to_string(),
            name: "🇹🇼 台湾主力".to_string(),
            region_code: "TW".to_string(),
            protocol: "trojan".to_string(),
            server: "198.51.100.2".to_string(),
            port: 443,
            enabled: true,
            ..Default::default()
        };
        let jp_member = ProxyNode {
            id: "n-jp".to_string(),
            sub_id: "sub-ghost".to_string(),
            name: "🇯🇵 日本备用".to_string(),
            region_code: "JP".to_string(),
            protocol: "trojan".to_string(),
            server: "198.51.100.3".to_string(),
            port: 443,
            enabled: true,
            ..Default::default()
        };
        storage.upsert_node(&ghost_ar).expect("upsert ghost");
        storage.upsert_node(&tw_member).expect("upsert tw");
        storage.upsert_node(&jp_member).expect("upsert jp");

        // Persist a group whose active_node_id still points to the removed ghost node `n-ar`.
        let group = MultiGroup {
            id: "g-main".to_string(),
            name: "测试多选组".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec!["n-tw".to_string(), "n-jp".to_string()],
            active_node_id: Some("n-ar".to_string()),
            ..Default::default()
        };
        storage.upsert_multi_group(&group).expect("upsert group");

        let mut cfg = AppConfig::default();
        cfg.route_mode = RouteTargetMode::Group;
        cfg.active_group_id = Some("g-main".to_string());

        let job_guard = Arc::new(JobGuard::new().expect("job guard"));
        let state = AppState::new(paths, cfg, storage, job_guard);

        let dto = build_runtime_info_dto(&state).expect("build runtime dto");
        assert_ne!(dto.active_node_id, "n-ar");
        assert_ne!(dto.active_node_name, "🇦🇷 阿根廷幽灵");
        assert_eq!(dto.active_node_id, "n-tw");
        assert_eq!(dto.active_node_name, "🇹🇼 台湾主力");

        let visual = build_tray_visual_state(&state);
        assert!(!visual.tooltip.contains("阿根廷幽灵"));
        assert!(visual.tooltip.contains("台湾主力"));

        let nodes_slice = [ghost_ar, tw_member, jp_member];
        let node_by_id: HashMap<&str, &ProxyNode> =
            nodes_slice.iter().map(|n| (n.id.as_str(), n)).collect();
        let tray_candidates = select_tray_group_candidates(&group, &nodes_slice, &node_by_id, 8);
        assert!(!tray_candidates.iter().any(|n| n.id == "n-ar"));
        assert_eq!(tray_candidates[0].id, "n-tw");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn reconcile_group_best_node_preserves_healthy_sticky_choice_and_switches_unprobed_or_failed() {
        let n1 = ProxyNode {
            id: "n-1".to_string(),
            sub_id: "sub-1".to_string(),
            name: "台湾 01".to_string(),
            enabled: true,
            multiplier: 1.0,
            ..Default::default()
        };
        let n2 = ProxyNode {
            id: "n-2".to_string(),
            sub_id: "sub-1".to_string(),
            name: "日本 02".to_string(),
            enabled: true,
            multiplier: 1.0,
            ..Default::default()
        };
        let nodes = vec![n1, n2];

        let mut snaps = HashMap::new();
        snaps.insert(
            "n-1".to_string(),
            ProbeSnapshot {
                node_id: "n-1".to_string(),
                ok: true,
                latency_ms: Some(90.0),
                up_mbps: Some(20.0),
                down_mbps: Some(100.0),
                google_clean: Some(true),
                ..Default::default()
            },
        );
        snaps.insert(
            "n-2".to_string(),
            ProbeSnapshot {
                node_id: "n-2".to_string(),
                ok: true,
                latency_ms: Some(45.0),
                up_mbps: Some(120.0),
                down_mbps: Some(300.0),
                google_clean: Some(true),
                ..Default::default()
            },
        );

        let mut group = MultiGroup {
            id: "g-sticky".to_string(),
            name: "粘性组".to_string(),
            mode: MultiGroupMode::StickyBest,
            hard_gates: vec!["google_clean == 1".to_string()],
            member_node_ids: vec!["n-1".to_string(), "n-2".to_string()],
            active_node_id: Some("n-1".to_string()),
            ..Default::default()
        };

        // 1. Healthy & gate-passing user selection must NOT drift even though n-2 scores higher.
        assert!(reconcile_group_best_node_in_memory(&mut group, &nodes, &snaps).is_none());
        assert_eq!(group.active_node_id.as_deref(), Some("n-1"));

        // 2. When active node fails a hard gate, auto-switch to gate-passing n-2.
        snaps.get_mut("n-1").unwrap().google_clean = Some(false);
        let dec_gate = reconcile_group_best_node_in_memory(&mut group, &nodes, &snaps)
            .expect("should switch when hard gate fails");
        assert_eq!(dec_gate.to_node_id, "n-2");
        assert_eq!(group.active_node_id.as_deref(), Some("n-2"));

        // 3. When active node is unprobed while another member is healthy, auto-switch to healthy.
        group.active_node_id = Some("n-1".to_string());
        snaps.remove("n-1");
        let dec_unprobed = reconcile_group_best_node_in_memory(&mut group, &nodes, &snaps)
            .expect("should switch when active node is unprobed");
        assert_eq!(dec_unprobed.to_node_id, "n-2");
        assert_eq!(group.active_node_id.as_deref(), Some("n-2"));
    }

    #[test]
    fn normalize_quick_site_probe_url_rewrites_legacy_chatgpt_root() {
        assert_eq!(
            normalize_quick_site_probe_url("https://chatgpt.com"),
            "https://chatgpt.com/cdn-cgi/trace"
        );
        assert_eq!(
            normalize_quick_site_probe_url("HTTPS://CHATGPT.COM/"),
            "https://chatgpt.com/cdn-cgi/trace"
        );
        assert_eq!(
            normalize_quick_site_probe_url("https://chatgpt.com/cdn-cgi/trace"),
            "https://chatgpt.com/cdn-cgi/trace"
        );
        assert_eq!(
            normalize_quick_site_probe_url("https://www.google.com/generate_204"),
            "https://www.google.com/generate_204"
        );
    }

    #[test]
    fn pick_best_group_candidate_ranks_gate_rejected_by_score_when_all_fail_gates() {
        let tw_slow = ProxyNode {
            id: "n-tw".to_string(),
            sub_id: "sub-1".to_string(),
            name: "台湾慢节点".to_string(),
            enabled: true,
            multiplier: 1.0,
            ..Default::default()
        };
        let jp_fast = ProxyNode {
            id: "n-jp".to_string(),
            sub_id: "sub-1".to_string(),
            name: "日本快节点".to_string(),
            enabled: true,
            multiplier: 1.0,
            ..Default::default()
        };
        let sg_disabled = ProxyNode {
            id: "n-sg-off".to_string(),
            sub_id: "sub-1".to_string(),
            name: "新加坡禁用".to_string(),
            enabled: false,
            multiplier: 0.5,
            ..Default::default()
        };
        let nodes = vec![tw_slow, jp_fast, sg_disabled];

        let mut snaps = HashMap::new();
        snaps.insert(
            "n-tw".to_string(),
            ProbeSnapshot {
                node_id: "n-tw".to_string(),
                ok: true,
                latency_ms: Some(140.0),
                up_mbps: Some(8.0),
                down_mbps: Some(40.0),
                keepalive_60s_ok: None,
                ..Default::default()
            },
        );
        snaps.insert(
            "n-jp".to_string(),
            ProbeSnapshot {
                node_id: "n-jp".to_string(),
                ok: true,
                latency_ms: Some(45.0),
                up_mbps: Some(95.0),
                down_mbps: Some(200.0),
                keepalive_60s_ok: None,
                ..Default::default()
            },
        );

        // Hard gate `keepalive_ok == 1` rejects all members when 60s keepalive hasn't been probed;
        // fallback must still pick the highest-scored enabled member (`n-jp`), not `member_node_ids[0]` (`n-tw`).
        let mut group = MultiGroup {
            id: "g-keepalive".to_string(),
            name: "长连接门禁组".to_string(),
            mode: MultiGroupMode::StickyBest,
            hard_gates: vec!["keepalive_ok == 1".to_string()],
            member_node_ids: vec![
                "n-sg-off".to_string(),
                "n-tw".to_string(),
                "n-jp".to_string(),
            ],
            active_node_id: Some("n-tw".to_string()),
            ..Default::default()
        };

        assert_eq!(
            pick_best_group_candidate(&group, &nodes, &snaps, None).as_deref(),
            Some("n-jp")
        );
        assert_eq!(
            pick_best_group_candidate(&group, &nodes, &snaps, Some("n-jp")).as_deref(),
            Some("n-tw")
        );

        // Sticky preservation: when active `n-tw` is already ok and no node passes hard gates, do not drift.
        assert!(reconcile_group_best_node_in_memory(&mut group, &nodes, &snaps).is_none());
        assert_eq!(group.active_node_id.as_deref(), Some("n-tw"));

        // When active `n-tw` is unprobed while `n-jp` is ok (even if gate-rejected), switch to `n-jp`.
        snaps.remove("n-tw");
        let switched = reconcile_group_best_node_in_memory(&mut group, &nodes, &snaps)
            .expect("should switch unprobed active node to highest-scored ok fallback");
        assert_eq!(switched.to_node_id, "n-jp");
        assert_eq!(group.active_node_id.as_deref(), Some("n-jp"));
    }

    #[test]
    fn build_traffic_history_returns_buffered_ticks_with_cached_memory() {
        let tmp = std::env::temp_dir().join(format!(
            "catcloud_traffic_history_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let paths = AppPaths::from_data_dir(tmp.clone(), true).expect("resolve test paths");
        let storage = Storage::open_in_memory().expect("open in-memory storage");
        let job_guard = Arc::new(JobGuard::new().expect("job guard"));
        let state = AppState::new(paths, AppConfig::default(), storage, job_guard);

        assert!(build_traffic_history(&state).is_empty());

        if let Ok(mut m) = state.cached_metrics.write() {
            m.core_mem_bytes = 32 * 1024 * 1024;
            m.up_total_bytes = 123_456;
            m.down_total_bytes = 987_654;
            m.app_connections = 7;
            m.tunnel_connections = 2;
        }
        state.telemetry.push_traffic(catcloud_core::core_adapter::TrafficTick {
            up: 1024,
            down: 4096,
            timestamp_ms: 1_700_000_001_000,
        });
        state.telemetry.push_traffic(catcloud_core::core_adapter::TrafficTick {
            up: 2048,
            down: 8192,
            timestamp_ms: 1_700_000_002_000,
        });

        let history = build_traffic_history(&state);
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].up_bps, 1024);
        assert_eq!(history[0].down_bps, 4096);
        assert_eq!(history[0].up_total_bytes, 0);
        assert_eq!(history[0].down_total_bytes, 0);
        assert_eq!(history[0].active_connections, 0);
        assert_eq!(history[0].tunnel_connections, 0);
        assert!((history[0].core_memory_mb - 32.0).abs() < 1e-6);
        assert_eq!(history[0].timestamp_ms, 1_700_000_001_000);
        assert_eq!(history[1].up_bps, 2048);
        assert_eq!(history[1].down_bps, 8192);
        assert_eq!(history[1].up_total_bytes, 123_456);
        assert_eq!(history[1].down_total_bytes, 987_654);
        assert_eq!(history[1].active_connections, 7);
        assert_eq!(history[1].tunnel_connections, 2);
        assert_eq!(history[1].timestamp_ms, 1_700_000_002_000);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn summarize_connections_excludes_inner_tunnels_and_splits_direct_vs_proxied() {
        use catcloud_core::core_adapter::ActiveConnection;

        let conns = vec![
            ActiveConnection {
                id: "c1".to_string(),
                conn_type: "Inner".to_string(),
                chains: vec!["PreAccel-Relay".to_string()],
                ..Default::default()
            },
            ActiveConnection {
                id: "c2".to_string(),
                conn_type: "inner".to_string(),
                chains: vec!["PreAccel-Relay".to_string()],
                ..Default::default()
            },
            ActiveConnection {
                id: "c3".to_string(),
                conn_type: "HTTP".to_string(),
                chains: vec!["DIRECT".to_string()],
                rule: "GEOIP".to_string(),
                ..Default::default()
            },
            ActiveConnection {
                id: "c4".to_string(),
                conn_type: "TUN".to_string(),
                chains: vec!["Proxy".to_string(), "JP-01".to_string()],
                rule: "MATCH".to_string(),
                ..Default::default()
            },
            ActiveConnection {
                id: "c5".to_string(),
                conn_type: "SOCKS5".to_string(),
                chains: vec!["AI".to_string(), "US-01".to_string()],
                rule: "DOMAIN-SUFFIX".to_string(),
                ..Default::default()
            },
            ActiveConnection {
                id: "c6".to_string(),
                conn_type: "TUN".to_string(),
                chains: vec!["REJECT".to_string()],
                rule: "AND".to_string(),
                ..Default::default()
            },
            ActiveConnection {
                id: "c7".to_string(),
                conn_type: "TUN".to_string(),
                chains: vec!["REJECT-DROP".to_string()],
                rule: "REJECT-DROP".to_string(),
                ..Default::default()
            },
        ];

        let summary = summarize_connections(&conns);
        assert_eq!(summary.tunnel_connections, 2);
        assert_eq!(summary.app_connections, 5);
        assert_eq!(summary.direct_connections, 1);
        assert_eq!(summary.proxied_connections, 2);
    }

    #[tokio::test]
    async fn relay_real_rtt_probe_detects_tls_protocols_and_never_returns_zero() {
        let tls_443 = PreAccelRelay {
            protocol: "anytls".to_string(),
            server: "198.51.100.1".to_string(),
            port: 443,
            sni: Some("ignored-on-443.example.com".to_string()),
            ..Default::default()
        };
        assert!(relay_uses_tls_probe(&tls_443));
        assert!(!relay_is_udp_quic_protocol(&tls_443));
        assert!(!relay_allows_plain_fallback(&tls_443));
        assert_eq!(resolve_relay_probe_sni_or_host(&tls_443), "198.51.100.1");

        let trojan_non443 = PreAccelRelay {
            protocol: "trojan".to_string(),
            server: "198.51.100.1".to_string(),
            port: 8443,
            sni: Some("relay.example.com".to_string()),
            ..Default::default()
        };
        assert!(relay_uses_tls_probe(&trojan_non443));
        assert!(!relay_allows_plain_fallback(&trojan_non443));
        assert_eq!(
            resolve_relay_probe_sni_or_host(&trojan_non443),
            "relay.example.com"
        );

        let ss_443 = PreAccelRelay {
            protocol: "ss".to_string(),
            server: "198.51.100.1".to_string(),
            port: 443,
            ..Default::default()
        };
        assert!(relay_uses_tls_probe(&ss_443));
        assert!(relay_allows_plain_fallback(&ss_443));

        let plain_ss = PreAccelRelay {
            protocol: "ss".to_string(),
            server: "198.51.100.1".to_string(),
            port: 8388,
            ..Default::default()
        };
        assert!(!relay_uses_tls_probe(&plain_ss));

        for udp_proto in ["tuic", "hysteria2", "hy2", "hysteria"] {
            let udp_relay = PreAccelRelay {
                protocol: udp_proto.to_string(),
                server: "198.51.100.1".to_string(),
                port: 443,
                ..Default::default()
            };
            assert!(
                relay_is_udp_quic_protocol(&udp_relay),
                "{udp_proto} must be classified as UDP/QUIC"
            );
            assert!(
                !relay_uses_tls_probe(&udp_relay),
                "{udp_proto} must never use TCP TLS probe even on port 443"
            );
        }

        let invalid = PreAccelRelay {
            protocol: "anytls".to_string(),
            server: "".to_string(),
            port: 443,
            ..Default::default()
        };
        assert!(measure_relay_real_rtt_ms(&invalid).await.is_err());

        // Local plain TCP listener should succeed and clamp to >= 0.1ms (never 0ms).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback test listener");
        let port = listener.local_addr().expect("listener addr").port();
        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let local_plain = PreAccelRelay {
            protocol: "ss".to_string(),
            server: "127.0.0.1".to_string(),
            port,
            ..Default::default()
        };
        let rtt = measure_relay_real_rtt_ms(&local_plain)
            .await
            .expect("local plain tcp probe should succeed");
        assert!(rtt >= 0.1, "measured RTT must never be 0ms, got {rtt}");
        let _ = accept_task.await;

        // Local UDP listener simulates a QUIC Version Negotiation reply for Hysteria2/TUIC.
        let udp_server = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind loopback udp listener");
        let udp_port = udp_server.local_addr().expect("udp addr").port();
        let udp_task = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            if let Ok((_, peer)) = udp_server.recv_from(&mut buf).await {
                let _ = udp_server.send_to(b"\x80\x00\x00\x00\x00", peer).await;
            }
        });
        let local_hy2 = PreAccelRelay {
            protocol: "hysteria2".to_string(),
            server: "127.0.0.1".to_string(),
            port: udp_port,
            ..Default::default()
        };
        let udp_rtt = measure_relay_real_rtt_ms(&local_hy2)
            .await
            .expect("local udp/quic probe should succeed");
        assert!(udp_rtt >= 0.1, "measured UDP RTT must be >= 0.1ms, got {udp_rtt}");
        let _ = udp_task.await;
    }

    #[test]
    fn select_reconcilable_active_group_ids_respects_route_mode_and_compiled_set() {
        let g_active = MultiGroup {
            id: "g-active".to_string(),
            name: "主力组".to_string(),
            mode: MultiGroupMode::StickyBest,
            independent_routing: false,
            ..Default::default()
        };
        let g_indep = MultiGroup {
            id: "g-indep".to_string(),
            name: "独立AI组".to_string(),
            mode: MultiGroupMode::ConditionalPool,
            independent_routing: true,
            ..Default::default()
        };
        let g_inactive = MultiGroup {
            id: "g-inactive".to_string(),
            name: "未选中组".to_string(),
            mode: MultiGroupMode::StickyBest,
            independent_routing: false,
            ..Default::default()
        };
        let groups = vec![g_active, g_indep, g_inactive];

        // 1. Single-node route mode must never select any multi-group for post-probe reconciliation.
        let mut single_cfg = AppConfig::default();
        single_cfg.route_mode = RouteTargetMode::Single;
        single_cfg.active_group_id = Some("g-active".to_string());
        assert!(select_reconcilable_active_group_ids(&single_cfg, &groups, None).is_empty());

        // 2. Group route mode with no compiled filter includes primary + independent strategy groups only.
        let mut group_cfg = AppConfig::default();
        group_cfg.route_mode = RouteTargetMode::Group;
        group_cfg.active_group_id = Some("g-active".to_string());
        assert_eq!(
            select_reconcilable_active_group_ids(&group_cfg, &groups, None),
            vec!["g-active".to_string(), "g-indep".to_string()]
        );

        // 3. When running with a pruned compiled set, groups outside the compiled set are excluded.
        let compiled_only_active: HashSet<String> = ["g-active".to_string()].into_iter().collect();
        assert_eq!(
            select_reconcilable_active_group_ids(&group_cfg, &groups, Some(&compiled_only_active)),
            vec!["g-active".to_string()]
        );
    }

    #[test]
    fn lookup_compiled_proxy_name_prevents_uncompiled_same_name_fallback() {
        let tmp = std::env::temp_dir().join(format!(
            "catcloud_compiled_map_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let paths = AppPaths::from_data_dir(tmp.clone(), true).expect("resolve test paths");
        let storage = Storage::open_in_memory().expect("open in-memory storage");
        let job_guard = Arc::new(JobGuard::new().expect("job guard"));
        let state = AppState::new(paths, AppConfig::default(), storage, job_guard);

        let mut compiled_map = HashMap::new();
        compiled_map.insert("node-sub-a".to_string(), "香港 01".to_string());
        state.set_node_proxy_name_map(compiled_map);

        assert_eq!(
            state.lookup_compiled_proxy_name("node-sub-a").as_deref(),
            Some("香港 01")
        );
        assert_eq!(state.lookup_compiled_proxy_name("node-sub-b"), None);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn summarize_throughput_probe_error_maps_causes_to_chinese() {
        assert_eq!(
            summarize_throughput_probe_error("上行测速", Some("operation timed out")),
            "上行测速超时"
        );
        assert!(
            summarize_throughput_probe_error(
                "下行测速",
                Some("fast_fuse_triggered: down_mbps=0.10 < 0.20")
            )
            .contains("保护熔断")
        );
        assert!(
            summarize_throughput_probe_error("上行测速", Some("unexpected upload HTTP status 502"))
                .contains("异常状态码")
        );
    }

    #[test]
    fn build_sanitized_diagnostics_report_emits_rich_schema_redacted_logs_and_markdown() {
        use catcloud_core::core_adapter::ActiveConnection;

        let tmp = std::env::temp_dir().join(format!(
            "catcloud_diag_rich_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let paths = AppPaths::from_data_dir(tmp.clone(), true).expect("resolve test paths");
        std::fs::write(paths.runtime_dir.join("Country.mmdb"), b"mock-country-db")
            .expect("write mock mmdb");
        let storage = Storage::open_in_memory().expect("open in-memory storage");

        let sub = SubscriptionRecord {
            id: "sub-1".to_string(),
            name: "主力订阅".to_string(),
            kind: SubscriptionKind::Url,
            url_or_cmd: "https://user:pass@sub.example.com/api?token=secret_sub_tok".to_string(),
            enabled: true,
            ..Default::default()
        };
        storage.upsert_subscription(&sub).expect("upsert sub");
        let node = ProxyNode {
            id: "n-jp".to_string(),
            sub_id: "sub-1".to_string(),
            name: "日本东京 01".to_string(),
            region_code: "JP".to_string(),
            protocol: "trojan".to_string(),
            server: "198.51.100.88".to_string(),
            port: 443,
            enabled: true,
            ..Default::default()
        };
        storage.upsert_node(&node).expect("upsert node");
        let group = MultiGroup {
            id: "g-main".to_string(),
            name: "AI主力组".to_string(),
            member_node_ids: vec!["n-jp".to_string()],
            active_node_id: Some("n-jp".to_string()),
            ..Default::default()
        };
        storage.upsert_multi_group(&group).expect("upsert group");
        let relay = PreAccelRelay {
            id: "r-hz".to_string(),
            name: "杭州443中转".to_string(),
            server: "203.0.113.66".to_string(),
            port: 443,
            protocol: "anytls".to_string(),
            password: "relay_super_secret".to_string(),
            enabled: true,
            ..Default::default()
        };
        storage.upsert_preaccel_relay(&relay).expect("upsert relay");

        let mut cfg = AppConfig::default();
        cfg.active_group_id = Some("g-main".to_string());
        cfg.system_proxy.enabled = true;
        cfg.preaccel.enabled = true;
        cfg.preaccel.active_relay_id = Some("r-hz".to_string());

        let job_guard = Arc::new(JobGuard::new().expect("job guard"));
        let state = AppState::new(paths, cfg, storage, job_guard);

        for i in 0..70 {
            state.log_app_event(
                "info",
                "测试",
                &format!(
                    "事件#{i:02} https://sub.example.com/get?token=tok_{i}&secret=sec_{i} 远端 203.0.113.66 [240e:390:abcd::99]:443"
                ),
            );
        }
        state.log_app_event(
            "error",
            "核心",
            "连接失败 trojan://test_secret_pw@203.0.113.45:443?key=k123",
        );

        let live_conns = ConnectionsSnapshot {
            memory: 42 * 1024 * 1024,
            connections: vec![
                ActiveConnection {
                    id: "t1".to_string(),
                    conn_type: "Inner".to_string(),
                    ..Default::default()
                },
                ActiveConnection {
                    id: "a1".to_string(),
                    conn_type: "HTTP".to_string(),
                    chains: vec!["DIRECT".to_string()],
                    ..Default::default()
                },
                ActiveConnection {
                    id: "a2".to_string(),
                    conn_type: "TUN".to_string(),
                    chains: vec!["AI主力组".to_string(), "日本东京 01".to_string()],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        let report = build_sanitized_diagnostics_report(&state, Some(&live_conns))
            .expect("build diagnostics report");

        // Backward-compatible legacy fields
        assert_eq!(report["sanitized"], true);
        assert_eq!(report["counts"]["subscriptions"], 1);
        assert_eq!(report["counts"]["nodes"], 1);
        assert_eq!(report["counts"]["multi_groups"], 1);
        assert_eq!(report["counts"]["preaccel_relays"], 1);

        // Rich new fields
        assert_eq!(report["route_summary"]["route_mode"], "group");
        assert_eq!(report["route_summary"]["active_group_name"], "AI主力组");
        assert_eq!(report["route_summary"]["active_node_name"], "日本东京 01");
        assert_eq!(report["route_summary"]["active_node_region"], "JP");
        assert_eq!(report["route_summary"]["system_proxy_enabled"], true);
        assert_eq!(report["route_summary"]["preaccel_active"], true);
        assert_eq!(report["route_summary"]["preaccel_relay_name"], "杭州443中转");
        assert_eq!(report["route_summary"]["domestic_direct_enabled"], true);
        assert_eq!(report["route_summary"]["block_quic_udp_443"], true);
        assert_eq!(report["geodata_status"]["country_mmdb"]["exists"], true);
        assert_eq!(report["connection_summary"]["app_connections"], 2);
        assert_eq!(report["connection_summary"]["tunnel_connections"], 1);
        assert_eq!(report["connection_summary"]["direct_connections"], 1);
        assert_eq!(report["connection_summary"]["proxied_connections"], 1);

        let last_err = report["last_error"].as_str().expect("last_error string");
        assert!(!last_err.contains("test_secret_pw"));
        assert!(!last_err.contains("k123"));
        assert!(!last_err.contains("203.0.113.45"));
        assert!(last_err.contains("203.0.113.*"));

        let recent_logs = report["recent_logs"].as_array().expect("recent_logs array");
        assert_eq!(recent_logs.len(), 60);
        let serialized_logs = serde_json::to_string(recent_logs).unwrap();
        assert!(!serialized_logs.contains("tok_69"));
        assert!(!serialized_logs.contains("sec_69"));
        assert!(!serialized_logs.contains("203.0.113.66"));
        assert!(!serialized_logs.contains("abcd::99"));
        assert!(serialized_logs.contains("203.0.113.*"));
        assert!(serialized_logs.contains("[240e:390::*]:443"));

        let md = report["ai_prompt_markdown"]
            .as_str()
            .expect("ai_prompt_markdown string");
        assert!(md.starts_with("请帮我排查猫猫云梯（CatCloud）当前问题"));
        assert!(md.contains("AI主力组"));
        assert!(md.contains("日本东京 01"));
        assert!(md.contains("杭州443中转"));
        assert!(md.contains("catcloud status --json"));
        assert!(md.contains("catcloud config diag --json"));
        assert!(!md.contains("test_secret_pw"));
        assert!(!md.contains("tok_69"));
        assert!(!md.contains("203.0.113.66"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn high_throughput_guard_protects_minimized_window_via_recent_ticks() {
        let threshold = WATCHDOG_HIGH_THROUGHPUT_THRESHOLD_BPS;
        let window_ms = WATCHDOG_HIGH_THROUGHPUT_WINDOW_MS;
        let now_ms: i64 = 1_700_000_050_000;

        // 1. Live cached metrics above threshold immediately protect.
        let active_cached = CachedRealtimeMetrics {
            up_bps: threshold,
            down_bps: 0,
            ..Default::default()
        };
        assert!(is_high_throughput_active(
            &active_cached,
            &[],
            now_ms,
            window_ms,
            threshold
        ));

        // 2. Window minimized -> cached metrics zeroed, but recent tick within 10s window was
        //    uploading at 4 MiB/s -> MUST still protect active upload.
        let zeroed_cached = CachedRealtimeMetrics::default();
        let recent_ticks = vec![
            TrafficTick {
                up: 16 * 1024,
                down: 32 * 1024,
                timestamp_ms: now_ms - 8_000,
            },
            TrafficTick {
                up: 4 * 1024 * 1024,
                down: 64 * 1024,
                timestamp_ms: now_ms - 4_000,
            },
        ];
        assert!(is_high_throughput_active(
            &zeroed_cached,
            &recent_ticks,
            now_ms,
            window_ms,
            threshold
        ));

        // 3. Stale high-throughput tick older than the 10s window does NOT block failover.
        let stale_ticks = vec![TrafficTick {
            up: 10 * 1024 * 1024,
            down: 10 * 1024 * 1024,
            timestamp_ms: now_ms - window_ms - 500,
        }];
        assert!(!is_high_throughput_active(
            &zeroed_cached,
            &stale_ticks,
            now_ms,
            window_ms,
            threshold
        ));

        // 4. Low idle heartbeat traffic inside window does NOT block failover.
        let idle_ticks = vec![TrafficTick {
            up: 12 * 1024,
            down: 48 * 1024,
            timestamp_ms: now_ms - 1_000,
        }];
        assert!(!is_high_throughput_active(
            &zeroed_cached,
            &idle_ticks,
            now_ms,
            window_ms,
            threshold
        ));
    }

    #[test]
    fn pick_group_candidates_with_cooldown_excludes_and_falls_back_when_all_cooled() {
        let make_node = |id: &str, name: &str| ProxyNode {
            id: id.to_string(),
            sub_id: "sub-1".to_string(),
            name: name.to_string(),
            enabled: true,
            multiplier: 1.0,
            ..Default::default()
        };
        let nodes = vec![
            make_node("n-a", "节点A"),
            make_node("n-b", "节点B"),
            make_node("n-c", "节点C"),
            make_node("n-d", "节点D"),
        ];

        let mut snaps = HashMap::new();
        for (id, latency, up) in [
            ("n-a", 30.0, 120.0),
            ("n-b", 40.0, 100.0),
            ("n-c", 55.0, 80.0),
            ("n-d", 80.0, 50.0),
        ] {
            snaps.insert(
                id.to_string(),
                ProbeSnapshot {
                    node_id: id.to_string(),
                    ok: true,
                    latency_ms: Some(latency),
                    up_mbps: Some(up),
                    down_mbps: Some(up * 2.0),
                    ..Default::default()
                },
            );
        }

        let group = MultiGroup {
            id: "g-watch".to_string(),
            name: "主力组".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec![
                "n-a".to_string(),
                "n-b".to_string(),
                "n-c".to_string(),
                "n-d".to_string(),
            ],
            active_node_id: Some("n-a".to_string()),
            ..Default::default()
        };

        // Active is n-a, n-b is in 5-minute cooldown -> returns [n-c, n-d] in priority order.
        let mut cooldowns = HashSet::new();
        cooldowns.insert("n-b".to_string());
        let ranked = pick_group_candidates_with_cooldown(
            &group,
            &nodes,
            &snaps,
            Some("n-a"),
            &cooldowns,
            3,
        );
        assert_eq!(ranked, vec!["n-c".to_string(), "n-d".to_string()]);

        // All backup nodes (n-b, n-c, n-d) are in cooldown -> relaxes cooldowns as last resort
        // while still excluding active node `n-a`.
        cooldowns.insert("n-c".to_string());
        cooldowns.insert("n-d".to_string());
        let fallback = pick_group_candidates_with_cooldown(
            &group,
            &nodes,
            &snaps,
            Some("n-a"),
            &cooldowns,
            3,
        );
        assert_eq!(
            fallback,
            vec!["n-b".to_string(), "n-c".to_string(), "n-d".to_string()]
        );
        assert!(!fallback.contains(&"n-a".to_string()));
    }

    #[test]
    fn is_proxy_takeover_active_requires_running_core_and_system_proxy_or_tun() {
        let mut cfg = AppConfig::default();
        cfg.system_proxy.enabled = false;
        cfg.tun.enabled = false;

        // Idle core (running without system proxy or TUN) must NOT count as active proxy takeover.
        assert!(!is_proxy_takeover_active(false, &cfg, true));
        assert!(!is_proxy_takeover_active(true, &cfg, true));

        // System proxy enabled -> active only while core is running (regardless of TUN privilege).
        cfg.system_proxy.enabled = true;
        assert!(!is_proxy_takeover_active(false, &cfg, false));
        assert!(is_proxy_takeover_active(true, &cfg, false));
        assert!(is_proxy_takeover_active(true, &cfg, true));

        // TUN enabled -> active ONLY when core is running AND TUN privileges are satisfied.
        cfg.system_proxy.enabled = false;
        cfg.tun.enabled = true;
        assert!(!is_proxy_takeover_active(false, &cfg, true));
        assert!(!is_proxy_takeover_active(true, &cfg, false));
        assert!(is_proxy_takeover_active(true, &cfg, true));

        // Both enabled -> active while core is running even if TUN lacks privilege (via system proxy).
        cfg.system_proxy.enabled = true;
        assert!(is_proxy_takeover_active(true, &cfg, false));
        assert!(is_proxy_takeover_active(true, &cfg, true));
    }

    #[test]
    fn runtime_info_preaccel_active_requires_running_core_or_global_engine() {
        let tmp = std::env::temp_dir().join(format!(
            "catcloud_preaccel_status_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let paths = AppPaths::from_data_dir(tmp.clone(), true).expect("resolve test paths");
        let storage = Storage::open_in_memory().expect("open in-memory storage");
        let job_guard = Arc::new(JobGuard::new().expect("job guard"));

        let mut cfg = AppConfig::default();
        cfg.preaccel.enabled = true;

        let state = AppState::new(paths, cfg, storage, job_guard);

        // 1. Core stopped & standalone global engine off -> must NOT falsely report preaccel_active.
        let dto_idle = build_runtime_info_dto(&state).expect("build idle runtime dto");
        assert!(!dto_idle.running);
        assert!(dto_idle.preaccel_enabled);
        assert!(!dto_idle.preaccel_active);
        assert!(!dto_idle.global_preaccel_active);
        assert_eq!(dto_idle.global_preaccel_mode, "off");
        assert_eq!(dto_idle.global_preaccel_socks_port, None);
        assert_eq!(dto_idle.global_preaccel_connections, 0);
        assert_eq!(dto_idle.status, "idle");
        assert_eq!(build_tray_visual_state(&state).health, TrayHealthState::Idle);

        // 2. Core running in idle/mixed-port-only mode (system_proxy=false, tun=false) ->
        //    proxy_active is false, so preaccel_active stays false and tray remains Idle.
        state.update_cached_runtime(CoreRuntimeStatus {
            running: true,
            ..Default::default()
        });
        let dto_idle_core = build_runtime_info_dto(&state).expect("build idle-core runtime dto");
        assert!(dto_idle_core.running);
        assert!(dto_idle_core.preaccel_enabled);
        assert!(!dto_idle_core.preaccel_active);
        assert_eq!(dto_idle_core.status, "idle");
        assert_eq!(build_tray_visual_state(&state).health, TrayHealthState::Idle);

        // 3a. Core running with system proxy enabled & preaccel.enabled == true,
        //     but NO enabled preaccel relays exist -> must NOT falsely report preaccel_active.
        if let Ok(mut guard) = state.config.write() {
            guard.system_proxy.enabled = true;
        }
        let dto_no_relay = build_runtime_info_dto(&state).expect("build no-relay runtime dto");
        assert!(dto_no_relay.running);
        assert!(dto_no_relay.preaccel_enabled);
        assert!(!dto_no_relay.preaccel_active);
        assert_eq!(dto_no_relay.status, "ok");
        assert_eq!(build_tray_visual_state(&state).health, TrayHealthState::Ok);

        // 3b. Once at least one enabled preaccel relay exists ->
        //     proxy_active is true, preaccel_active is true, status == "preaccel", tray == PreAccel.
        {
            let db = state.storage.lock().expect("lock storage");
            db.upsert_preaccel_relay(&PreAccelRelay {
                id: "relay-test-1".to_string(),
                name: "国内测试中转".to_string(),
                server: "203.0.113.10".to_string(),
                port: 443,
                protocol: "trojan".to_string(),
                password: "secret".to_string(),
                enabled: true,
                ..Default::default()
            })
            .expect("insert enabled preaccel relay");
        }
        let dto_running = build_runtime_info_dto(&state).expect("build running runtime dto");
        assert!(dto_running.running);
        assert!(dto_running.preaccel_enabled);
        assert!(dto_running.preaccel_active);
        assert_eq!(dto_running.status, "preaccel");
        assert_eq!(
            build_tray_visual_state(&state).health,
            TrayHealthState::PreAccel
        );

        // 4. Core running with system proxy enabled & preaccel.enabled == false -> status == "ok".
        if let Ok(mut guard) = state.config.write() {
            guard.preaccel.enabled = false;
        }
        let dto_ok = build_runtime_info_dto(&state).expect("build ok runtime dto");
        assert!(!dto_ok.preaccel_active);
        assert_eq!(dto_ok.status, "ok");
        assert_eq!(build_tray_visual_state(&state).health, TrayHealthState::Ok);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn relaunch_admin_args_supports_enable_global_preaccel_flag() {
        let raw = vec![
            std::ffi::OsString::from("--data-dir"),
            std::ffi::OsString::from("C:/CatCloud/data"),
        ];
        let args = collect_relaunch_admin_args_with_flags(&raw, None, false, true);
        assert!(args.iter().any(|a| a == "--restarting"));
        assert!(args.iter().any(|a| a == "--enable-global-preaccel"));
        assert!(!args.iter().any(|a| a == "--enable-tun"));
        assert!(args.iter().any(|a| a == "C:/CatCloud/data"));
    }

    #[test]
    fn global_preaccel_settings_helpers_and_ui_dto_roundtrip() {
        assert_eq!(
            parse_global_preaccel_scope("proxy_apps_only").unwrap(),
            GlobalPreAccelScope::ProxyAppsOnly
        );
        assert_eq!(
            parse_global_preaccel_scope("all_non_443_tcp").unwrap(),
            GlobalPreAccelScope::AllNon443Tcp
        );
        assert_eq!(
            parse_global_preaccel_scope("ALL_NON_443_TCP").unwrap(),
            GlobalPreAccelScope::AllNon443Tcp
        );
        assert_eq!(
            parse_global_preaccel_scope("all_non443_tcp").unwrap(),
            GlobalPreAccelScope::AllNon443Tcp
        );
        assert_eq!(
            parse_global_preaccel_scope("ALL_NON443_TCP").unwrap(),
            GlobalPreAccelScope::AllNon443Tcp
        );
        assert!(parse_global_preaccel_scope("invalid_scope").is_err());

        let deduped = normalize_global_target_processes(vec![
            "  mihomo.exe ".to_string(),
            "".to_string(),
            "MIHOMO.EXE".to_string(),
            "scp.exe".to_string(),
        ]);
        assert_eq!(deduped, vec!["mihomo.exe".to_string(), "scp.exe".to_string()]);

        let mut cfg = AppConfig::default();
        cfg.preaccel.enabled = true;
        cfg.preaccel.campus_portal_guard = false;
        cfg.preaccel.global_bypass_enabled = true;
        cfg.preaccel.global_scope = GlobalPreAccelScope::AllNon443Tcp;
        cfg.preaccel.global_target_processes = vec!["xray.exe".to_string()];
        cfg.preaccel.windivert_dir = Some("C:/Custom/WinDivert".to_string());

        let dto = UiAppConfigDto::from(&cfg);
        assert_eq!(dto.preaccel.campus_portal_guard, Some(false));
        assert_eq!(dto.preaccel.global_bypass_enabled, Some(true));
        assert_eq!(
            dto.preaccel.global_scope,
            Some(GlobalPreAccelScope::AllNon443Tcp)
        );
        assert_eq!(
            dto.preaccel.global_target_processes,
            Some(vec!["xray.exe".to_string()])
        );
        assert_eq!(
            dto.preaccel.windivert_dir.as_deref(),
            Some("C:/Custom/WinDivert")
        );

        // Round-trip explicit `campus_portal_guard = Some(false)` onto a default config (which starts `true`).
        let mut roundtrip_cfg = AppConfig::default();
        assert!(roundtrip_cfg.preaccel.campus_portal_guard);
        apply_ui_dto(&mut roundtrip_cfg, &dto);
        assert!(!roundtrip_cfg.preaccel.campus_portal_guard);

        // Explicit empty `windivert_dir = Some("")` clears the configured path to `None`.
        let mut clear_dir_dto = dto.clone();
        clear_dir_dto.preaccel.windivert_dir = Some("".to_string());
        clear_dir_dto.preaccel.campus_portal_guard = Some(true);
        apply_ui_dto(&mut roundtrip_cfg, &clear_dir_dto);
        assert_eq!(roundtrip_cfg.preaccel.windivert_dir, None);
        assert!(roundtrip_cfg.preaccel.campus_portal_guard);

        // Legacy UI payload omitting the optional fields must preserve existing config values.
        let mut legacy_dto = dto;
        legacy_dto.preaccel.campus_portal_guard = None;
        legacy_dto.preaccel.global_bypass_enabled = None;
        legacy_dto.preaccel.global_scope = None;
        legacy_dto.preaccel.global_target_processes = None;
        legacy_dto.preaccel.windivert_dir = None;

        let mut target_cfg = cfg.clone();
        apply_ui_dto(&mut target_cfg, &legacy_dto);
        assert!(!target_cfg.preaccel.campus_portal_guard);
        assert!(target_cfg.preaccel.global_bypass_enabled);
        assert_eq!(
            target_cfg.preaccel.global_scope,
            GlobalPreAccelScope::AllNon443Tcp
        );
        assert_eq!(
            target_cfg.preaccel.global_target_processes,
            vec!["xray.exe".to_string()]
        );
        assert_eq!(
            target_cfg.preaccel.windivert_dir.as_deref(),
            Some("C:/Custom/WinDivert")
        );
    }

    #[test]
    fn apply_migration_nodes_rebinds_ids_without_primary_key_collision() {
        let mut storage = Storage::open_in_memory().expect("open in-memory storage");

        let sample_nodes = vec![
            ProxyNode {
                id: "node_duplicate_preview_1".to_string(),
                sub_id: "preview_local_profile".to_string(),
                name: "HK 01".to_string(),
                protocol: "trojan".to_string(),
                server: "203.0.113.10".to_string(),
                port: 443,
                raw_config: serde_json::json!({
                    "name": "HK 01",
                    "type": "trojan",
                    "server": "203.0.113.10",
                    "port": 443,
                    "password": "placeholder-password"
                }),
                region_code: "HK".to_string(),
                multiplier: 1.0,
                is_443_native: true,
                preaccel_eligible: true,
                preaccel_override: None,
                tags: Vec::new(),
                enabled: true,
            },
            ProxyNode {
                id: "node_duplicate_preview_1".to_string(),
                sub_id: "preview_local_profile".to_string(),
                name: "HK 01".to_string(),
                protocol: "trojan".to_string(),
                server: "203.0.113.10".to_string(),
                port: 443,
                raw_config: serde_json::json!({
                    "name": "HK 01",
                    "type": "trojan",
                    "server": "203.0.113.10",
                    "port": 443,
                    "password": "placeholder-password"
                }),
                region_code: "HK".to_string(),
                multiplier: 1.0,
                is_443_native: true,
                preaccel_eligible: true,
                preaccel_override: None,
                tags: Vec::new(),
                enabled: true,
            },
            ProxyNode {
                id: "node_duplicate_preview_2".to_string(),
                sub_id: "preview_local_profile".to_string(),
                name: "JP 01".to_string(),
                protocol: "vless".to_string(),
                server: "198.51.100.20".to_string(),
                port: 443,
                raw_config: serde_json::json!({
                    "name": "JP 01",
                    "type": "vless",
                    "server": "198.51.100.20",
                    "port": 443,
                    "uuid": "00000000-0000-4000-8000-000000000099"
                }),
                region_code: "JP".to_string(),
                multiplier: 1.0,
                is_443_native: true,
                preaccel_eligible: true,
                preaccel_override: None,
                tags: Vec::new(),
                enabled: true,
            },
        ];

        assert!(persist_migration_nodes(&mut storage, "空导入".to_string(), Vec::new()).is_err());

        let (sub1, count1) =
            persist_migration_nodes(&mut storage, "迁移批次 A".to_string(), sample_nodes.clone())
                .expect("first migration import");
        let (sub2, count2) =
            persist_migration_nodes(&mut storage, "迁移批次 B".to_string(), sample_nodes)
                .expect("second migration import");

        assert_eq!(count1, 3);
        assert_eq!(count2, 3);
        assert_ne!(sub1, sub2);

        let all_nodes = storage.list_nodes().expect("list persisted nodes");
        assert_eq!(
            all_nodes.len(),
            6,
            "repeated migrations with identical node names must never collide or overwrite"
        );

        let unique_ids: HashSet<&str> = all_nodes.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(unique_ids.len(), 6);
        assert!(all_nodes.iter().all(|n| n.id.starts_with("node_")));
        assert_eq!(all_nodes.iter().filter(|n| n.sub_id == sub1).count(), 3);
        assert_eq!(all_nodes.iter().filter(|n| n.sub_id == sub2).count(), 3);
    }

    #[test]
    fn update_platform_keys_and_staging_status_helpers_align() {
        assert_eq!(
            catcloud_core::updater::update_platform_key_for("windows", "x86_64", true),
            "windows-x86_64-portable"
        );
        assert_eq!(
            catcloud_core::updater::update_platform_key_for("windows", "x86_64", false),
            "windows-x86_64"
        );
        assert_eq!(
            catcloud_core::updater::update_platform_key_for("windows", "aarch64", true),
            "windows-aarch64-portable"
        );
        assert_eq!(
            catcloud_core::updater::update_platform_key_for("windows", "aarch64", false),
            "windows-aarch64"
        );
        assert_eq!(
            catcloud_core::updater::update_platform_key_for("macos", "aarch64", false),
            "darwin-aarch64"
        );
        assert_eq!(
            catcloud_core::updater::update_platform_key_for("macos", "x86_64", false),
            "darwin-x86_64"
        );
        assert_eq!(
            catcloud_core::updater::update_platform_key_for("linux", "x86_64", false),
            "linux-x86_64"
        );

        assert_eq!(
            can_auto_stage_portable_update(true),
            cfg!(target_os = "windows")
        );
        assert!(!can_auto_stage_portable_update(false));

        let current_portable_key = catcloud_core::updater::current_update_platform_key_opt(true);
        let current_standard_key = catcloud_core::updater::current_update_platform_key_opt(false);
        if cfg!(target_os = "windows") {
            assert!(current_portable_key.is_some_and(|k| k.ends_with("-portable")));
            assert!(current_standard_key.is_some_and(|k| !k.ends_with("-portable")));
        } else {
            assert_eq!(current_portable_key, current_standard_key);
        }

        // Verify unified `can_auto_stage` rules across `check_app_update` and `download_and_stage_update`.
        let mut platforms = HashMap::new();
        platforms.insert(
            "windows-x86_64-portable".to_string(),
            catcloud_core::updater::PlatformAsset {
                url: "https://github.com/JuryBu/CatCloud/releases/download/v0.2.0/CatCloud-portable.zip"
                    .to_string(),
                signature: None,
                sha256: Some("a".repeat(64)),
                filename: Some("CatCloud-portable.zip".to_string()),
            },
        );
        platforms.insert(
            "windows-x86_64".to_string(),
            catcloud_core::updater::PlatformAsset {
                url: "https://github.com/JuryBu/CatCloud/releases/download/v0.2.0/CatCloud-setup.exe"
                    .to_string(),
                signature: None,
                sha256: Some("b".repeat(64)),
                filename: Some("CatCloud-setup.exe".to_string()),
            },
        );
        let manifest = catcloud_core::updater::LatestManifest {
            version: "0.2.0".to_string(),
            notes: String::new(),
            pub_date: None,
            sha256sums_url: None,
            platforms,
        };
        assert_eq!(
            resolve_can_auto_stage_for_manifest(
                true,
                Some("windows-x86_64-portable"),
                Some(&manifest)
            ),
            cfg!(target_os = "windows")
        );
        assert!(!resolve_can_auto_stage_for_manifest(
            false,
            Some("windows-x86_64-portable"),
            Some(&manifest)
        ));
        assert!(!resolve_can_auto_stage_for_manifest(
            true,
            Some("windows-x86_64"),
            Some(&manifest)
        ));
        assert!(!resolve_can_auto_stage_for_manifest(
            true,
            None,
            Some(&manifest)
        ));
        assert!(!resolve_can_auto_stage_for_manifest(
            true,
            Some("windows-x86_64-portable"),
            None
        ));

        let tmp = std::env::temp_dir().join(format!(
            "catcloud_upd_helper_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let staging_dir = tmp.join(".update_staging");
        let payload_dir = staging_dir.join(catcloud_core::updater::STAGING_PAYLOAD_DIR);
        std::fs::create_dir_all(&payload_dir).expect("create staging payload dir");

        assert_eq!(
            resolve_staged_update_version(&staging_dir, "0.1.0", false),
            None
        );

        let version_payload = br#"{"version":"0.2.0"}"#;
        let version_sha = catcloud_core::updater::compute_sha256_hex(version_payload);
        std::fs::write(payload_dir.join("version.json"), version_payload)
            .expect("write staged payload file");

        let pending = catcloud_core::updater::PendingUpdateMetadata {
            from_version: "0.1.0".to_string(),
            target_version: "0.2.0".to_string(),
            archive_sha256: "a".repeat(64),
            staged_at: Utc::now().to_rfc3339(),
            files: vec![catcloud_core::updater::StagedFileEntry {
                rel_path: "version.json".to_string(),
                sha256: version_sha.clone(),
                size_bytes: version_payload.len() as u64,
            }],
        };
        let bytes = serde_json::to_vec_pretty(&pending).expect("serialize pending manifest");
        std::fs::write(
            staging_dir.join(catcloud_core::updater::PENDING_APPLY_MANIFEST),
            bytes,
        )
        .expect("write pending manifest");

        assert_eq!(
            resolve_staged_update_version(&staging_dir, "0.1.0", false).as_deref(),
            Some("0.2.0")
        );
        assert_eq!(
            resolve_staged_update_version(&staging_dir, "0.2.0", false),
            None
        );

        // Prerelease staged target is gated on `include_prerelease`.
        let pre_pending = catcloud_core::updater::PendingUpdateMetadata {
            target_version: "0.2.0-rc.1".to_string(),
            ..pending
        };
        std::fs::write(
            staging_dir.join(catcloud_core::updater::PENDING_APPLY_MANIFEST),
            serde_json::to_vec_pretty(&pre_pending).expect("serialize prerelease manifest"),
        )
        .expect("write prerelease manifest");
        assert_eq!(
            resolve_staged_update_version(&staging_dir, "0.1.0", false),
            None
        );
        assert_eq!(
            resolve_staged_update_version(&staging_dir, "0.1.0", true).as_deref(),
            Some("0.2.0-rc.1")
        );

        // Tampering with staged payload must fail integrity verification and return None.
        std::fs::write(payload_dir.join("version.json"), b"CORRUPTED_BYTES")
            .expect("corrupt staged payload");
        assert_eq!(
            resolve_staged_update_version(&staging_dir, "0.1.0", true),
            None
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn validate_external_https_url_accepts_clean_https_and_trims() {
        let ok = validate_external_https_url(
            "  https://github.com/JuryBu/CatCloud/releases/latest?tag=v0.2.0#assets  ",
        )
        .expect("valid https url should pass");
        assert_eq!(
            ok,
            "https://github.com/JuryBu/CatCloud/releases/latest?tag=v0.2.0#assets"
        );
        assert!(!ok.contains("secret="));
        assert!(!ok.contains("hostname="));
    }

    #[test]
    fn validate_external_https_url_rejects_non_https_userinfo_and_control_chars() {
        for bad in [
            "",
            "   ",
            "http://github.com/JuryBu/CatCloud",
            "file:///C:/Windows/System32/calc.exe",
            "javascript:alert(1)",
            "https:///missing-host",
            "https://user:pass@github.com/JuryBu/CatCloud",
            "https://token@github.com/JuryBu/CatCloud",
            "https://github.com/JuryBu/CatCloud\r\nX-Injected: 1",
            "https://github.com/JuryBu/CatCloud\x00",
            "https://github.com/JuryBu/CatCloud\t",
            "not a url",
        ] {
            assert!(
                validate_external_https_url(bad).is_err(),
                "expected external URL validator to reject: {bad:?}"
            );
        }
    }

    #[test]
    fn ui_update_dto_roundtrips_auto_download_and_preserves_legacy_none() {
        let mut cfg = AppConfig::default();
        cfg.update.auto_download = false;
        cfg.update.include_prerelease = true;
        cfg.update.check_interval_min = 120;
        cfg.update.mode = UpdateApplyMode::Manual;

        let dto = UiAppConfigDto::from(&cfg);
        assert_eq!(dto.update.auto_download, Some(false));
        assert!(dto.update.include_prerelease);
        assert_eq!(dto.update.check_interval_min, 120);
        assert_eq!(dto.update.mode, UpdateApplyMode::Manual);

        let mut target = AppConfig::default();
        assert!(target.update.auto_download);
        apply_ui_dto(&mut target, &dto);
        assert!(!target.update.auto_download);
        assert!(target.update.include_prerelease);
        assert_eq!(target.update.check_interval_min, 120);
        assert_eq!(target.update.mode, UpdateApplyMode::Manual);

        let mut enable_dto = dto.clone();
        enable_dto.update.auto_download = Some(true);
        apply_ui_dto(&mut target, &enable_dto);
        assert!(target.update.auto_download);

        // Legacy payload omitting `auto_download` deserializes as `None` and preserves current value.
        let mut raw_val = serde_json::to_value(&dto).expect("serialize dto");
        raw_val["update"]
            .as_object_mut()
            .expect("update object")
            .remove("auto_download");
        let legacy_dto: UiAppConfigDto =
            serde_json::from_value(raw_val).expect("deserialize legacy dto without auto_download");
        assert_eq!(legacy_dto.update.auto_download, None);

        target.update.auto_download = true;
        apply_ui_dto(&mut target, &legacy_dto);
        assert!(target.update.auto_download);

        target.update.auto_download = false;
        apply_ui_dto(&mut target, &legacy_dto);
        assert!(!target.update.auto_download);
    }

    #[test]
    fn reconcile_saved_preaccel_switch_keeps_unified_master_switch_aligned() {
        let mut old = AppConfig::default();
        old.preaccel.enabled = false;
        old.preaccel.global_bypass_enabled = false;

        // Flipping `enabled` ON synchronizes `global_bypass_enabled`.
        let mut next = old.clone();
        next.preaccel.enabled = true;
        reconcile_saved_preaccel_switch(&old, &mut next);
        assert!(next.preaccel.enabled);
        assert!(next.preaccel.global_bypass_enabled);

        // Flipping legacy `global_bypass_enabled` ON while `enabled` unchanged also aligns both.
        let mut legacy_next = old.clone();
        legacy_next.preaccel.global_bypass_enabled = true;
        reconcile_saved_preaccel_switch(&old, &mut legacy_next);
        assert!(legacy_next.preaccel.enabled);
        assert!(legacy_next.preaccel.global_bypass_enabled);

        // Flipping `enabled` OFF from an active state clears both flags together.
        let mut active_old = AppConfig::default();
        active_old.preaccel.sync_unified_enabled(true);
        let mut turned_off = active_old.clone();
        turned_off.preaccel.enabled = false;
        reconcile_saved_preaccel_switch(&active_old, &mut turned_off);
        assert!(!turned_off.preaccel.enabled);
        assert!(!turned_off.preaccel.global_bypass_enabled);
    }

    #[test]
    fn runtime_info_and_health_pool_latency_and_sub_refresh_guard_behave_accurately() {
        let tmp = std::env::temp_dir().join(format!(
            "catcloud_stage12_runtime_pool_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let paths = AppPaths::from_data_dir(tmp.clone(), true).expect("resolve test paths");
        let storage = Storage::open_in_memory().expect("open in-memory storage");
        let job_guard = Arc::new(JobGuard::new().expect("job guard"));
        let state = AppState::new(paths, AppConfig::default(), storage, job_guard);

        let stale_snap = ProbeSnapshot {
            node_id: "n-1".to_string(),
            ok: true,
            latency_ms: Some(210.0),
            ..Default::default()
        };
        assert_eq!(state.resolve_node_latency_ms("n-1", Some(&stale_snap)), Some(210.0));

        // Live FullHealthy probe overrides stale SQLite latency and populates health hints.
        state.record_node_health_probe("n-1", RuntimeDualHealth::FullHealthy, Some(68.0));
        assert_eq!(state.resolve_node_latency_ms("n-1", Some(&stale_snap)), Some(68.0));

        let dto = build_runtime_info_dto(&state).expect("build runtime dto");
        assert!(!dto.global_windivert_active);
        assert!(!dto.preaccel_install_state.is_empty());
        let hint = dto
            .node_health_hints
            .get("n-1")
            .expect("node health hint should be exported");
        assert_eq!(hint.status, "healthy");
        assert_eq!(hint.latency_ms, Some(68.0));
        assert_eq!(hint.cooldown_remaining_sec, 0);

        // Confirmed Failed probe clears stale SQLite latency and marks cooldown in hints.
        state.record_node_health_probe("n-1", RuntimeDualHealth::Failed, None);
        assert_eq!(state.resolve_node_latency_ms("n-1", Some(&stale_snap)), None);
        let failed_hints = state.snapshot_node_health_hints();
        let failed_hint = failed_hints.get("n-1").expect("failed hint");
        assert_eq!(failed_hint.status, "cooldown");
        assert_eq!(failed_hint.latency_ms, None);
        assert!(failed_hint.cooldown_remaining_sec > 0);

        // SubRefreshGuard prevents concurrent duplicate refreshes for the same subscription ID.
        {
            let guard_a = SubRefreshGuard::try_acquire(&state.refreshing_sub_ids, "sub-1".into());
            assert!(guard_a.is_some());
            let guard_dup = SubRefreshGuard::try_acquire(&state.refreshing_sub_ids, "sub-1".into());
            assert!(guard_dup.is_none());
            let guard_other = SubRefreshGuard::try_acquire(&state.refreshing_sub_ids, "sub-2".into());
            assert!(guard_other.is_some());
        }
        assert!(
            SubRefreshGuard::try_acquire(&state.refreshing_sub_ids, "sub-1".into()).is_some(),
            "dropping previous guard must release subscription refresh lock"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn pick_group_candidates_with_runtime_pool_respects_cooldown_and_relaxes_when_all_cooled() {
        let make_node = |id: &str, name: &str| ProxyNode {
            id: id.to_string(),
            sub_id: "sub-1".to_string(),
            name: name.to_string(),
            enabled: true,
            multiplier: 1.0,
            ..Default::default()
        };
        let nodes = vec![
            make_node("n-a", "节点A"),
            make_node("n-b", "节点B"),
            make_node("n-c", "节点C"),
        ];
        let mut snaps = HashMap::new();
        for (id, latency) in [("n-a", 40.0), ("n-b", 45.0), ("n-c", 80.0)] {
            snaps.insert(
                id.to_string(),
                ProbeSnapshot {
                    node_id: id.to_string(),
                    ok: true,
                    latency_ms: Some(latency),
                    up_mbps: Some(100.0),
                    down_mbps: Some(200.0),
                    ..Default::default()
                },
            );
        }
        let group = MultiGroup {
            id: "g-pool".to_string(),
            name: "池化测试组".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec!["n-a".into(), "n-b".into(), "n-c".into()],
            active_node_id: Some("n-a".into()),
            ..Default::default()
        };

        let now = Instant::now();
        let mut pool = NodeHealthPool::new();
        pool.record_probe_result("n-b", RuntimeDualHealth::Failed, None, now);

        let empty_local = HashSet::new();
        let ranked = pick_group_candidates_with_cooldown_and_runtime(
            &group,
            &nodes,
            &snaps,
            Some("n-a"),
            &empty_local,
            Some(&pool),
            now,
            3,
        );
        assert_eq!(ranked, vec!["n-c".to_string()]);

        // When all backups are in runtime pool cooldown (with empty hard_gates), fallback honors
        // shortest remaining cooldown order (n-b failed earlier so expires sooner than n-c).
        let later = now + Duration::from_secs(20);
        pool.record_probe_result("n-c", RuntimeDualHealth::Failed, None, later);
        let fallback = pick_group_candidates_with_cooldown_and_runtime(
            &group,
            &nodes,
            &snaps,
            Some("n-a"),
            &empty_local,
            Some(&pool),
            later,
            3,
        );
        assert_eq!(fallback, vec!["n-b".to_string(), "n-c".to_string()]);
        assert!(!fallback.contains(&"n-a".to_string()));
    }

    #[test]
    fn subscription_proxy_candidates_prefer_direct_then_core_then_distinct_local_sys_proxy() {
        let local_same = SystemProxySpec {
            enabled: true,
            host: "localhost".to_string(),
            port: 7890,
            bypass: Vec::new(),
            pac_url: None,
        };
        assert_eq!(
            build_subscription_proxy_candidates_from(Some(7890), Some(&local_same)),
            vec![None, Some("http://127.0.0.1:7890".to_string())]
        );

        let local_other = SystemProxySpec {
            enabled: true,
            host: "127.0.0.1".to_string(),
            port: 10809,
            bypass: Vec::new(),
            pac_url: None,
        };
        assert_eq!(
            build_subscription_proxy_candidates_from(Some(7890), Some(&local_other)),
            vec![
                None,
                Some("http://127.0.0.1:7890".to_string()),
                Some("http://127.0.0.1:10809".to_string()),
            ]
        );

        // Remote LAN/corporate proxy or PAC URL must be ignored for local fallback.
        let remote_proxy = SystemProxySpec {
            enabled: true,
            host: "192.168.1.20".to_string(),
            port: 8080,
            bypass: Vec::new(),
            pac_url: None,
        };
        let pac_proxy = SystemProxySpec {
            enabled: true,
            host: "127.0.0.1".to_string(),
            port: 10809,
            bypass: Vec::new(),
            pac_url: Some("http://127.0.0.1:10808/proxy.pac".to_string()),
        };
        assert_eq!(
            build_subscription_proxy_candidates_from(None, Some(&remote_proxy)),
            vec![None]
        );
        assert_eq!(
            build_subscription_proxy_candidates_from(None, Some(&pac_proxy)),
            vec![None]
        );
    }

    #[test]
    fn sample_diagnostic_logs_separates_key_events_from_routine_mihomo_traffic() {
        let mut logs = Vec::new();
        for i in 0..30 {
            logs.push(format!(
                "2026-11-24T12:00:{i:02}Z [info] [核心] 代理核心事件 #{i}"
            ));
        }
        logs.push(
            "2026-11-24T12:01:00Z [warning] [mihomo] [TCP] 127.0.0.1:50000 --> example.com:443 dial error"
                .to_string(),
        );
        for i in 0..60 {
            logs.push(format!(
                "2026-11-24T12:02:{:02}Z [info] [mihomo] [TCP] 127.0.0.1:{} --> example.invalid:443 match Match using Proxy",
                i % 60,
                40000 + i
            ));
            logs.push(format!(
                "2026-11-24T12:03:{:02}Z [info] [mihomo] [UDP] 127.0.0.1:{} --> 8.8.8.*:53 match GeoIP using DIRECT",
                i % 60,
                41000 + i
            ));
        }

        let (key_events, tail_logs) = sample_diagnostic_logs(&logs, 25, 35);
        assert_eq!(key_events.len(), 25);
        assert_eq!(tail_logs.len(), 35);
        assert!(key_events
            .last()
            .is_some_and(|l| l.contains("[warning] [mihomo] [TCP]")));
        assert!(key_events.iter().all(|l| !l.contains("[info] [mihomo] [TCP]")));
        assert!(key_events.iter().all(|l| !l.contains("[info] [mihomo] [UDP]")));
    }

    #[test]
    fn onboarding_prompt_and_runtime_verify_fields_render_sanitized_chinese_guide() {
        let tmp = std::env::temp_dir().join(format!(
            "catcloud_onboarding_verify_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let paths = AppPaths::from_data_dir(tmp.clone(), true).expect("resolve test paths");
        let storage = Storage::open_in_memory().expect("open in-memory storage");
        let job_guard = Arc::new(JobGuard::new().expect("job guard"));
        let state = AppState::new(paths, AppConfig::default(), storage, job_guard);

        let dto = build_runtime_info_dto(&state).expect("build runtime dto");
        assert_eq!(dto.global_preaccel_verify_state, "idle");
        assert_eq!(dto.global_preaccel_verify_ms, None);

        let mut cfg = state.snapshot_config();
        cfg.preaccel.enabled = true;

        let mut global_st = GlobalPreAccelStatus::default();
        global_st.running = true;
        global_st.mode = "windivert".to_string();
        global_st.is_windivert_active = true;
        global_st.verify_state = "verified".to_string();
        global_st.verify_latency_ms = Some(38);
        global_st.bound_physical_interface = Some("WLAN".to_string());
        global_st.detected_security_products = vec!["Windows 安全中心（Defender）".to_string()];
        global_st.security_guidance = Some(
            "请将目录 `D:\\SecretPortable\\CatCloud\\bin` 加入排除项".to_string(),
        );

        let sample_events = vec![
            "2026-11-24T12:00:00Z [info] [mihomo] Start initial compatible provider Proxy".to_string(),
            "2026-11-24T12:00:01Z [debug] [核心] 调试信息不应出现".to_string(),
            "2026-11-24T12:00:02Z [info] [应用/订阅] 事件一：已导入 5 个节点".to_string(),
            "2026-11-24T12:00:03Z [info] [应用/测速] 事件二：完成 3 个节点省流快测".to_string(),
            "2026-11-24T12:00:04Z [info] [应用/代理] 事件三：已开启系统代理".to_string(),
            "2026-11-24T12:00:05Z [info] [应用/分流] 事件四：已切换为规则分流模式".to_string(),
            "2026-11-24T12:00:06Z [info] [应用/路线] 事件五：已切换到低延迟节点".to_string(),
            "2026-11-24T12:00:07Z [info] [应用/环境] 事件六：检测到网卡状态更新".to_string(),
            "2026-11-24T12:00:08Z [info] [应用/国内提速] 事件七：探测通过 38 ms 内网 192.168.1.9".to_string(),
        ];

        let md = build_ai_onboarding_prompt_markdown(
            "0.1.0",
            "windows x86_64",
            true,
            &cfg,
            &state.snapshot_runtime(),
            Some(&dto),
            &global_st,
            (1, 5, 5, 3, 1, 1),
            Some("上次测试失败 trojan://secret_pw@203.0.113.88:443?token=abc123"),
            &sample_events,
        );
        assert!(md.contains("新手手把手上手导师"));
        assert!(md.contains("下一小步"));
        assert!(md.contains("Windows 电脑"));
        assert!(!md.contains("windows x86_64"));
        assert!(md.contains("已开启并在底层实测生效（38 ms）"));
        assert!(!md.contains("WinDivert 运行中"));
        assert!(!md.contains("SOCKS5 待命"));
        assert!(md.contains("已测速 3 个"));
        assert!(md.contains("WLAN"));
        assert!(md.contains("38 ms"));
        assert!(!md.contains("SecretPortable"));
        assert!(md.contains("<LOCAL_PATH>/bin"));
        assert!(!md.contains("secret_pw"));
        assert!(!md.contains("abc123"));
        assert!(!md.contains("203.0.113.88"));
        assert!(md.contains("203.0.113.*"));
        assert!(!md.contains("192.168.1.9"));
        assert!(md.contains("192.168.1.*"));
        assert!(!md.contains("Start initial compatible provider"));
        assert!(!md.contains("调试信息不应出现"));
        assert!(!md.contains("事件一"));
        assert!(md.contains("事件二"));
        assert!(md.contains("事件七"));

        // Verify degraded plain-Chinese wording without jargon.
        global_st.verify_state = "degraded".to_string();
        global_st.is_windivert_active = false;
        let degraded_md = build_ai_onboarding_prompt_markdown(
            "0.1.0",
            "macos aarch64",
            false,
            &cfg,
            &state.snapshot_runtime(),
            Some(&dto),
            &global_st,
            (1, 5, 5, 0, 1, 1),
            None,
            &[],
        );
        assert!(degraded_md.contains("macOS 电脑"));
        assert!(degraded_md.contains("已开启，底层探测未通过已自动保护回退"));
        assert!(degraded_md.contains("已测速 0 个"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn tray_visual_state_reflects_probing_and_degraded_verify_states() {
        let tmp = std::env::temp_dir().join(format!(
            "catcloud_tray_verify_state_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let paths = AppPaths::from_data_dir(tmp.clone(), true).expect("resolve test paths");
        let storage = Storage::open_in_memory().expect("open in-memory storage");
        let job_guard = Arc::new(JobGuard::new().expect("job guard"));

        let mut cfg = AppConfig::default();
        cfg.preaccel.enabled = true;
        let state = AppState::new(paths, cfg, storage, job_guard);

        let degraded = build_tray_visual_state_with_verify_override(&state, Some(("degraded", None)));
        assert_eq!(degraded.health, TrayHealthState::Warn);
        assert_eq!(degraded.global_preaccel_verify_state, "degraded");
        assert!(degraded
            .tooltip
            .contains("已保护回退（请查看国内提速环境放行指引）"));

        let probing = build_tray_visual_state_with_verify_override(&state, Some(("probing", None)));
        assert_ne!(probing.health, TrayHealthState::PreAccel);
        assert_eq!(probing.global_preaccel_verify_state, "probing");
        assert!(probing.tooltip.contains("探测链路中…"));
        assert!(!probing.tooltip.contains("全局提速中"));

        let dto_degraded =
            build_runtime_info_dto_with_verify_override(&state, Some(("degraded", None)))
                .expect("build degraded dto");
        assert_eq!(dto_degraded.status, "warn");
        assert_eq!(dto_degraded.global_preaccel_verify_state, "degraded");

        let dto_probing =
            build_runtime_info_dto_with_verify_override(&state, Some(("probing", None)))
                .expect("build probing dto");
        assert!(!dto_probing.preaccel_active);
        assert_eq!(dto_probing.global_preaccel_verify_state, "probing");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn format_subscription_error_zh_eliminates_all_english_error_residue() {
        let cases = [
            (
                "订阅链接格式不正确，请确认完整复制了链接（relative URL without a base）",
                "格式不正确",
            ),
            (
                "拉取订阅失败（invalid certificate: self signed）",
                "握手失败",
            ),
            (
                "解析失败：expected mapping at line 12 column 4",
                "格式无法解析",
            ),
            (
                "请求异常：dns error: failed to lookup address information",
                "域名解析失败",
            ),
            (
                "代理连接失败：tcp connect error: connection refused (os error 10061)",
                "被拒绝",
            ),
            (
                "拉取失败：operation timed out after 15s",
                "超时",
            ),
            (
                "上游响应错误：status 403 forbidden",
                "HTTP 403",
            ),
            (
                "上游响应错误：status 502 bad gateway",
                "HTTP 5xx",
            ),
            (
                "weird unknown upstream xyz failure without category",
                "拉取或解析订阅失败",
            ),
            (
                "网络请求失败（error sending request for url (https://secret:pw@sub.example.com/get)）",
                "无法连接到订阅服务器",
            ),
        ];

        for (raw, expected_substr) in cases {
            let formatted = format_subscription_error_zh(raw);
            assert!(
                formatted.contains(expected_substr),
                "expected `{expected_substr}` in `{formatted}` (from `{raw}`)"
            );
            assert!(
                !contains_english_error_residue(&formatted),
                "english residue leaked in `{formatted}` (from `{raw}`)"
            );
            assert!(!formatted.contains("weird unknown"));
            assert!(!formatted.contains("relative URL"));
            assert!(!formatted.contains("expected mapping"));
            assert!(!formatted.contains("secret:pw"));
        }

        // Clean pure-Chinese messages pass through unchanged.
        let clean_zh = "订阅认证失败（HTTP 401），链接里的访问令牌可能已失效或被重置";
        assert_eq!(format_subscription_error_zh(clean_zh), clean_zh);
    }

    #[test]
    fn upsert_subscription_deduplicates_normalized_and_clash_wrapped_urls() {
        let db = Storage::open_in_memory().expect("open in-memory storage");

        let first = upsert_subscription_in_storage(
            &db,
            SubscriptionRecord {
                id: String::new(),
                name: "主力机场".to_string(),
                kind: SubscriptionKind::Url,
                url_or_cmd: "  https://Sub.Example.COM:443/api/sub?token=AbC123  ".to_string(),
                traffic_total_bytes: 100 * 1024 * 1024,
                traffic_used_bytes: 20 * 1024 * 1024,
                enabled: true,
                ..Default::default()
            },
        )
        .expect("insert first sub");
        assert!(!first.id.is_empty());

        // Same URL with different casing + new ID should reuse existing record instead of duplicating.
        let second = upsert_subscription_in_storage(
            &db,
            SubscriptionRecord {
                id: "sub-new-dup-id".to_string(),
                name: "主力机场（重命名）".to_string(),
                kind: SubscriptionKind::Url,
                url_or_cmd: "HTTPS://sub.example.com/api/sub?token=AbC123".to_string(),
                enabled: true,
                ..Default::default()
            },
        )
        .expect("dedup second sub");
        assert_eq!(second.id, first.id);
        assert_eq!(second.name, "主力机场（重命名）");
        assert_eq!(second.traffic_total_bytes, 100 * 1024 * 1024);
        assert_eq!(db.list_subscriptions().unwrap().len(), 1);

        // clash:// one-click install link wrapping the exact same URL also deduplicates & unwraps.
        let third = upsert_subscription_in_storage(
            &db,
            SubscriptionRecord {
                id: String::new(),
                name: String::new(),
                kind: SubscriptionKind::Url,
                url_or_cmd: "clash://install-config?url=https%3A%2F%2Fsub.example.com%2Fapi%2Fsub%3Ftoken%3DAbC123&name=Ignored".to_string(),
                enabled: true,
                ..Default::default()
            },
        )
        .expect("dedup clash wrapped sub");
        assert_eq!(third.id, first.id);
        assert_eq!(third.name, "主力机场（重命名）");
        assert_eq!(
            third.url_or_cmd,
            "https://sub.example.com/api/sub?token=AbC123"
        );
        assert_eq!(db.list_subscriptions().unwrap().len(), 1);

        // Explicit update of an existing ID updates that ID directly.
        let updated = upsert_subscription_in_storage(
            &db,
            SubscriptionRecord {
                id: first.id.clone(),
                name: "显式更新".to_string(),
                kind: SubscriptionKind::Url,
                url_or_cmd: "https://other.example.com/sub?token=xyz".to_string(),
                enabled: true,
                ..Default::default()
            },
        )
        .expect("explicit update by id");
        assert_eq!(updated.id, first.id);
        assert_eq!(updated.name, "显式更新");
        assert_eq!(db.list_subscriptions().unwrap().len(), 1);
    }

    #[test]
    fn diagnostics_route_summary_sanitizes_sensitive_group_node_and_relay_names() {
        let tmp = std::env::temp_dir().join(format!(
            "catcloud_diag_route_sanitize_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let paths = AppPaths::from_data_dir(tmp.clone(), true).expect("resolve test paths");
        let storage = Storage::open_in_memory().expect("open in-memory storage");

        storage
            .upsert_subscription(&SubscriptionRecord {
                id: "s-1".to_string(),
                name: "测试订阅".to_string(),
                kind: SubscriptionKind::Url,
                url_or_cmd: "https://sub.example.com/api".to_string(),
                enabled: true,
                ..Default::default()
            })
            .expect("upsert subscription");
        storage
            .upsert_node(&ProxyNode {
                id: "n-1".to_string(),
                sub_id: "s-1".to_string(),
                name: "日本节点 203.0.113.88 token=node_secret_99".to_string(),
                region_code: "JP".to_string(),
                protocol: "trojan".to_string(),
                server: "203.0.113.88".to_string(),
                port: 443,
                enabled: true,
                ..Default::default()
            })
            .expect("upsert node");
        storage
            .upsert_multi_group(&MultiGroup {
                id: "g-1".to_string(),
                name: "公司组 192.168.10.55 C:\\Users\\John Doe\\cfg".to_string(),
                member_node_ids: vec!["n-1".to_string()],
                active_node_id: Some("n-1".to_string()),
                ..Default::default()
            })
            .expect("upsert group");
        storage
            .upsert_preaccel_relay(&PreAccelRelay {
                id: "r-1".to_string(),
                name: "杭州中转 10.8.0.12 secret=relay_pw_1".to_string(),
                server: "198.51.100.12".to_string(),
                port: 443,
                protocol: "trojan".to_string(),
                password: "pw".to_string(),
                enabled: true,
                ..Default::default()
            })
            .expect("upsert relay");

        let mut cfg = AppConfig::default();
        cfg.active_group_id = Some("g-1".to_string());
        cfg.preaccel.enabled = true;
        cfg.preaccel.active_relay_id = Some("r-1".to_string());
        let job_guard = Arc::new(JobGuard::new().expect("job guard"));
        let state = AppState::new(paths, cfg, storage, job_guard);

        let report =
            build_sanitized_diagnostics_report(&state, None).expect("build diagnostics report");
        let route_summary = &report["route_summary"];
        let g_name = route_summary["active_group_name"].as_str().unwrap();
        let n_name = route_summary["active_node_name"].as_str().unwrap();
        let r_name = route_summary["preaccel_relay_name"].as_str().unwrap();

        assert!(!g_name.contains("192.168.10.55"));
        assert!(!g_name.contains("John Doe"));
        assert!(g_name.contains("192.168.10.*"));
        assert!(g_name.contains(r"C:\Users\<USER>\cfg"));

        assert!(!n_name.contains("203.0.113.88"));
        assert!(!n_name.contains("node_secret_99"));
        assert!(n_name.contains("203.0.113.*"));
        assert!(n_name.contains("token=<REDACTED>"));

        assert!(!r_name.contains("10.8.0.12"));
        assert!(!r_name.contains("relay_pw_1"));
        assert!(r_name.contains("10.8.0.*"));
        assert!(r_name.contains("secret=<REDACTED>"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn diagnostics_key_events_survive_tcp_flood_and_section5_uses_redacted_cli_json() {
        let tmp = std::env::temp_dir().join(format!(
            "catcloud_diag_flood_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let paths = AppPaths::from_data_dir(tmp.clone(), true).expect("resolve test paths");
        let storage = Storage::open_in_memory().expect("open in-memory storage");
        let job_guard = Arc::new(JobGuard::new().expect("job guard"));
        let state = AppState::new(paths, AppConfig::default(), storage, job_guard);

        state.log_app_event(
            "info",
            "核心",
            "核心已启动，已按需加载节点 14 个（含中转 2 个，节点库共 796 个）",
        );
        state.log_app_event("warning", "分流", "检测到核心轻量重启触发条件");

        // Flood disk & telemetry with 1,800 routine Mihomo TCP forwarding entries.
        for i in 0..1800 {
            state.app_logger.append_formatted(
                "2026-11-25T01:00:00Z",
                "info",
                "mihomo",
                &format!("[TCP] 127.0.0.1:50000 --> example.com:443 match DomainSuffix using PROXY #{i}"),
            );
        }

        let report = build_sanitized_diagnostics_report(&state, None)
            .expect("build diagnostics report after flood");
        let key_events = report["key_event_logs"]
            .as_array()
            .expect("key_event_logs array");
        assert!(
            key_events.len() >= 2,
            "§4.1 key events must never collapse to 0 under heavy TCP traffic flood"
        );
        let joined_keys = serde_json::to_string(key_events).unwrap();
        assert!(joined_keys.contains("已按需加载节点 14 个（含中转 2 个，节点库共 796 个）"));
        assert!(joined_keys.contains("核心轻量重启"));

        let md = report["ai_prompt_markdown"]
            .as_str()
            .expect("ai_prompt_markdown");
        assert!(md.contains("--data-dir"));
        assert!(md.contains("docs export network_lifecycle --json"));
        assert!(!md.contains("--format json"));

        // Verify `format_global_preaccel_brief` never emits ambiguous `或` wording across states.
        let mut st_failed_driver = GlobalPreAccelStatus::default();
        st_failed_driver.verify_state = "failed".to_string();
        st_failed_driver.windivert_available = false;
        let brief_a = format_global_preaccel_brief(&st_failed_driver, true, false);
        assert!(!brief_a.contains('或'), "ambiguous brief: {brief_a}");
        assert!(brief_a.contains("底层提速驱动尚未就绪"));
        assert!(brief_a.contains("等待启动独立提速通道"));

        let mut st_tun = GlobalPreAccelStatus::default();
        st_tun.verify_state = "failed".to_string();
        st_tun.windivert_available = true;
        let brief_b = format_global_preaccel_brief(&st_tun, true, true);
        assert!(!brief_b.contains('或'), "ambiguous brief: {brief_b}");
        assert!(brief_b.contains("底层自动探测未通过"));
        assert!(brief_b.contains("由虚拟网卡主核心统一接管"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn github_issue_draft_enforces_600_char_body_and_strips_custom_labels() {
        let cfg = AppConfig::default();
        let rt = CoreRuntimeStatus {
            running: true,
            version: Some("v1.19.0".to_string()),
            ..Default::default()
        };
        let global_st = GlobalPreAccelStatus::default();
        let geodata = serde_json::json!({
            "country_mmdb": { "exists": true, "size_bytes": 4096, "updated_at": null },
            "geoip_dat": { "exists": false, "size_bytes": 0, "updated_at": null },
            "geosite_dat": { "exists": false, "size_bytes": 0, "updated_at": null },
            "asn_mmdb": { "exists": false, "size_bytes": 0, "updated_at": null }
        });
        let custom_labels = vec![
            "私人秘密香港节点01".to_string(),
            "我的专属AI多选组".to_string(),
            "寝室杭州中转机".to_string(),
            "神秘订阅源A".to_string(),
        ];
        let key_events = vec![
            "2026-11-25T01:00:00Z [warning] [应用/路线] 我的专属AI多选组 切换 私人秘密香港节点01 经 寝室杭州中转机 203.0.113.77 token=super_tok".to_string(),
        ];
        let long_summary = "连接私人秘密香港节点01和我的专属AI多选组时偶尔断流，请帮忙排查神秘订阅源A的日志，重复说明以触发长度截断验证，确保浏览器URL不会被ShellExecuteW截断导致丢失内容！".repeat(4);

        let sample_err = concat!(
            "连接 寝室杭州中转机 失败 ",
            "trojan",
            "://sample_test_pw@203.0.113.77:443"
        );
        let draft = build_github_issue_draft(
            "JuryBu/CatCloud",
            "0.1.0",
            "windows x86_64",
            false,
            false,
            true,
            &cfg,
            &rt,
            &global_st,
            (1, 12, 2, 1),
            &geodata,
            Some(sample_err),
            &key_events,
            &custom_labels,
            Some(&long_summary),
            "zh-CN",
        );

        assert!(draft
            .issue_url
            .starts_with("https://github.com/JuryBu/CatCloud/issues/new?title="));
        let encoded_body = draft
            .issue_url
            .split_once("&body=")
            .map(|(_, b)| b)
            .expect("issue_url must contain &body=");
        assert!(
            encoded_body.len() <= GITHUB_ISSUE_URL_BODY_MAX_CHARS,
            "encoded URL query body ({}) must be <= {}",
            encoded_body.len(),
            GITHUB_ISSUE_URL_BODY_MAX_CHARS
        );

        for secret_or_label in [
            "私人秘密香港节点01",
            "我的专属AI多选组",
            "寝室杭州中转机",
            "神秘订阅源A",
            "sample_test_pw",
            "super_tok",
            "203.0.113.77",
        ] {
            assert!(
                !draft.clipboard_markdown.contains(secret_or_label),
                "clipboard_markdown leaked `{secret_or_label}`"
            );
            assert!(
                !draft.title.contains(secret_or_label),
                "title leaked `{secret_or_label}`"
            );
            assert!(
                !draft.issue_url.contains(secret_or_label),
                "issue_url leaked `{secret_or_label}`"
            );
        }
        assert!(draft.clipboard_markdown.contains("203.0.113.*"));
        assert!(draft.clipboard_markdown.contains("CatCloud 版本"));
    }

    #[test]
    fn github_issue_draft_ja_and_ru_emit_zero_simplified_chinese_and_strip_relay_provider() {
        let cfg = AppConfig::default();
        let rt = CoreRuntimeStatus {
            running: true,
            version: Some("v1.19.0".to_string()),
            ..Default::default()
        };
        let global_st = GlobalPreAccelStatus::default();
        let geodata = serde_json::json!({
            "country_mmdb": { "exists": true, "size_bytes": 4096, "updated_at": null },
            "geoip_dat": { "exists": false, "size_bytes": 0, "updated_at": null },
            "geosite_dat": { "exists": false, "size_bytes": 0, "updated_at": null },
            "asn_mmdb": { "exists": false, "size_bytes": 0, "updated_at": null }
        });
        let relay = PreAccelRelay {
            id: "r-priv".to_string(),
            name: "PrivateRelayNode01".to_string(),
            provider: "SecretRelayProviderXYZ".to_string(),
            server: "198.51.100.42".to_string(),
            port: 443,
            protocol: "anytls".to_string(),
            enabled: true,
            ..Default::default()
        };
        let custom_labels = collect_github_issue_custom_labels(&[], &[], &[], &[relay]);
        assert!(custom_labels.iter().any(|l| l == "PrivateRelayNode01"));
        assert!(custom_labels.iter().any(|l| l == "SecretRelayProviderXYZ"));

        let key_events = vec![
            "2026-11-25T01:00:00Z [warning] relay PrivateRelayNode01 from SecretRelayProviderXYZ failed via 198.51.100.42".to_string(),
        ];
        let sample_err =
            "handshake timeout on PrivateRelayNode01 (SecretRelayProviderXYZ) 198.51.100.42:443";

        let has_cjk_or_cn_punct = |text: &str| {
            text.chars().any(|c| {
                ('\u{4E00}'..='\u{9FFF}').contains(&c)
                    || matches!(c, '（' | '）' | '，' | '。' | '：' | '！' | '、')
            })
        };

        for (lang, expected_title_prefix) in [
            ("ja", "[報告]"),
            ("ru", "[Отзыв]"),
            ("en", "[Feedback]"),
        ] {
            let draft = build_github_issue_draft(
                "JuryBu/CatCloud",
                "0.1.0",
                "windows x86_64",
                false,
                false,
                true,
                &cfg,
                &rt,
                &global_st,
                (1, 5, 1, 1),
                &geodata,
                Some(sample_err),
                &key_events,
                &custom_labels,
                Some("Timeout with SecretRelayProviderXYZ relay PrivateRelayNode01"),
                lang,
            );

            assert!(
                draft.title.starts_with(expected_title_prefix),
                "lang={lang} unexpected title: {}",
                draft.title
            );
            assert!(
                !has_cjk_or_cn_punct(&draft.clipboard_markdown),
                "lang={lang} clipboard_markdown must contain zero simplified Chinese: {}",
                draft.clipboard_markdown
            );
            assert!(draft.clipboard_markdown.contains("### Environment"));
            assert!(draft.clipboard_markdown.contains("Country.mmdb: ready"));
            assert!(draft.clipboard_markdown.contains("geoip.dat: missing"));

            let encoded_body = draft
                .issue_url
                .split_once("&body=")
                .map(|(_, b)| b)
                .expect("issue_url must contain &body=");
            assert!(encoded_body.len() <= GITHUB_ISSUE_URL_BODY_MAX_CHARS);
            assert!(
                encoded_body.contains("Sanitized%20Diagnostics")
                    || encoded_body.contains("Paste%20sanitized%20report"),
                "lang={lang} url body must use English template, got: {encoded_body}"
            );
            assert!(
                !encoded_body.contains("%E8%AF%A6%E7%BB%86")
                    && !encoded_body.contains("%E8%AF%B7%E7%AE%80%E8%BF%B0"),
                "lang={lang} url body leaked simplified Chinese: {encoded_body}"
            );

            for secret_label in ["SecretRelayProviderXYZ", "PrivateRelayNode01", "198.51.100.42"] {
                assert!(
                    !draft.title.contains(secret_label),
                    "lang={lang} title leaked {secret_label}"
                );
                assert!(
                    !draft.issue_url.contains(secret_label),
                    "lang={lang} issue_url leaked {secret_label}"
                );
                assert!(
                    !draft.clipboard_markdown.contains(secret_label),
                    "lang={lang} clipboard_markdown leaked {secret_label}"
                );
            }
        }
    }

    #[test]
    fn select_target_relays_ordered_preserves_request_order_and_deduplicates() {
        let make_relay = |id: &str, name: &str| PreAccelRelay {
            id: id.to_string(),
            name: name.to_string(),
            server: "198.51.100.10".to_string(),
            port: 443,
            protocol: "anytls".to_string(),
            enabled: true,
            ..Default::default()
        };
        let all = vec![
            make_relay("r1", "Relay-1"),
            make_relay("r2", "Relay-2"),
            make_relay("r3", "Relay-3"),
        ];

        let ordered = select_target_relays_ordered(
            all.clone(),
            Some(vec![
                "r3".to_string(),
                " ".to_string(),
                "r1".to_string(),
                "r3".to_string(),
                "missing".to_string(),
            ]),
        );
        let ids: Vec<&str> = ordered.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["r3", "r1"]);

        let all_default = select_target_relays_ordered(all, None);
        assert_eq!(all_default.len(), 3);
    }

    #[test]
    fn global_to_rule_heap_reclaim_guard_enforces_all_safety_gates() {
        let base = HeapReclaimCheckInput {
            gen_matches: true,
            is_rule_mode: true,
            core_running: true,
            tun_enabled: false,
            active_connections: 4,
            high_throughput: false,
            probing_active: false,
            memory_mb: 112.0,
            budget_mb: 64.0,
            cooldown_elapsed: true,
        };
        let threshold = evaluate_heap_reclaim_guard(&base).expect("base case should trigger");
        assert!((threshold - 96.0).abs() < 0.01);

        // Generation changed
        assert!(evaluate_heap_reclaim_guard(&HeapReclaimCheckInput {
            gen_matches: false,
            ..base
        })
        .is_err());
        // TUN active must skip
        assert!(evaluate_heap_reclaim_guard(&HeapReclaimCheckInput {
            tun_enabled: true,
            ..base
        })
        .is_err());
        // Active connections > 8 must skip
        assert!(evaluate_heap_reclaim_guard(&HeapReclaimCheckInput {
            active_connections: 9,
            ..base
        })
        .is_err());
        // High throughput must skip
        assert!(evaluate_heap_reclaim_guard(&HeapReclaimCheckInput {
            high_throughput: true,
            ..base
        })
        .is_err());
        // Probing active must skip
        assert!(evaluate_heap_reclaim_guard(&HeapReclaimCheckInput {
            probing_active: true,
            ..base
        })
        .is_err());
        // Below max(budget * 1.5, 90.0) floor must skip
        assert!(evaluate_heap_reclaim_guard(&HeapReclaimCheckInput {
            budget_mb: 48.0,
            memory_mb: 89.5,
            ..base
        })
        .is_err());
        // Cooldown active must skip
        assert!(evaluate_heap_reclaim_guard(&HeapReclaimCheckInput {
            cooldown_elapsed: false,
            ..base
        })
        .is_err());
    }

    #[test]
    fn ui_personalization_language_roundtrip_normalizes_locale() {
        let mut cfg = AppConfig::default();
        cfg.personalization.language = "ja-JP".to_string();
        let dto = UiAppConfigDto::from(&cfg);
        assert_eq!(dto.personalization.ui_language, "ja");

        let mut next_dto = dto.clone();
        next_dto.personalization.ui_language = "en-US".to_string();
        let mut updated = cfg.clone();
        apply_ui_dto(&mut updated, &next_dto);
        assert_eq!(updated.personalization.language, "en");
    }

    #[test]
    fn tray_and_runtime_dto_reflect_circuit_open_backoff_direct_and_activity_flags() {
        let tmp = std::env::temp_dir().join(format!(
            "catcloud_tray_stage14_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let paths = AppPaths::from_data_dir(tmp.clone(), true).expect("resolve test paths");
        let storage = Storage::open_in_memory().expect("open in-memory storage");

        let group = MultiGroup {
            id: "g-circuit".to_string(),
            name: "测试分组".to_string(),
            state: MultiGroupState::CircuitOpen,
            ..Default::default()
        };
        storage.upsert_multi_group(&group).expect("upsert group");

        let mut cfg = AppConfig::default();
        cfg.route_mode = RouteTargetMode::Group;
        cfg.active_group_id = Some("g-circuit".to_string());
        cfg.system_proxy.enabled = true;
        let job_guard = Arc::new(JobGuard::new().expect("job guard"));
        let state = AppState::new(paths, cfg, storage, job_guard);

        // Simulate active probing & switching flags plus CircuitOpen group state.
        state.probe_running.store(true, Ordering::SeqCst);
        state.switching_active.store(true, Ordering::SeqCst);
        if let Ok(mut rt) = state.cached_runtime.write() {
            rt.running = true;
        }

        let dto = build_runtime_info_dto(&state).expect("build runtime dto");
        assert!(dto.probing_active);
        assert!(dto.switching_active);
        assert!(dto.active_group_circuit_open);
        assert_eq!(dto.active_group_state.as_deref(), Some("circuit_open"));

        let vis = build_tray_visual_state(&state);
        assert_eq!(vis.health, TrayHealthState::Error);
        assert!(vis.tooltip.contains("熔断"));

        // Clear CircuitOpen -> verify group backoff triggers Warn.
        {
            let db = state.storage.lock().expect("lock db");
            let mut healthy_group = group.clone();
            healthy_group.state = MultiGroupState::Healthy;
            db.upsert_multi_group(&healthy_group)
                .expect("update healthy group");
        }
        state.set_group_backoff_until(
            "g-circuit",
            Some(Instant::now() + Duration::from_secs(60)),
        );
        let vis_backoff = build_tray_visual_state(&state);
        assert_eq!(vis_backoff.health, TrayHealthState::Warn);
        assert!(vis_backoff.tooltip.contains("退避"));

        // Direct mode without WinDivert -> Idle with direct-mode notice.
        state.clear_group_backoffs();
        state.probe_running.store(false, Ordering::SeqCst);
        state.switching_active.store(false, Ordering::SeqCst);
        if let Ok(mut c) = state.config.write() {
            c.proxy_mode = ProxyMode::Direct;
        }
        if let Ok(mut rt) = state.cached_runtime.write() {
            rt.proxy_mode = ProxyMode::Direct;
        }
        let vis_direct = build_tray_visual_state(&state);
        assert_eq!(vis_direct.health, TrayHealthState::Idle);
        assert!(vis_direct.tooltip.contains("直连"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn resolve_local_cli_path_finds_portable_installer_resource_dir_and_unix_layouts() {
        let cli_bin = if cfg!(target_os = "windows") {
            "catcloud.exe"
        } else {
            "catcloud"
        };
        let root = std::env::temp_dir().join(format!(
            "catcloud_cli_resolve_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let bin_dir = root.join("data").join("bin");
        let root_data = root.join("data");
        std::fs::create_dir_all(&bin_dir).unwrap();

        // 1. Portable layout: `<exe_dir>/cli/catcloud(.exe)`
        let portable_exe_dir = root.join("portable");
        let portable_cli = portable_exe_dir.join("cli").join(cli_bin);
        std::fs::create_dir_all(portable_cli.parent().unwrap()).unwrap();
        std::fs::write(&portable_cli, b"cli").unwrap();
        assert_eq!(
            resolve_local_cli_path_from(Some(&portable_exe_dir), None, &bin_dir, &root_data),
            catcloud_core::paths::normalize_os_path(&portable_cli)
        );

        // 2. Tauri `resource_dir`: `<res>/resources/cli/catcloud(.exe)` (Linux AppImage / macOS / MSI)
        let isolated_exe_dir = root.join("isolated_bin");
        let res_dir = root.join("tauri_res");
        let res_cli = res_dir.join("resources").join("cli").join(cli_bin);
        std::fs::create_dir_all(&isolated_exe_dir).unwrap();
        std::fs::create_dir_all(res_cli.parent().unwrap()).unwrap();
        std::fs::write(&res_cli, b"cli").unwrap();
        assert_eq!(
            resolve_local_cli_path_from(
                Some(&isolated_exe_dir),
                Some(&res_dir),
                &bin_dir,
                &root_data
            ),
            catcloud_core::paths::normalize_os_path(&res_cli)
        );

        // 3. macOS `.app` layout without explicit resource_dir: `Contents/MacOS -> ../Resources/resources/cli/catcloud`
        let mac_exe_dir = root.join("CatCloud.app").join("Contents").join("MacOS");
        let mac_cli = root
            .join("CatCloud.app")
            .join("Contents")
            .join("Resources")
            .join("resources")
            .join("cli")
            .join(cli_bin);
        std::fs::create_dir_all(&mac_exe_dir).unwrap();
        std::fs::create_dir_all(mac_cli.parent().unwrap()).unwrap();
        std::fs::write(&mac_cli, b"cli").unwrap();
        assert_eq!(
            resolve_local_cli_path_from(Some(&mac_exe_dir), None, &bin_dir, &root_data),
            catcloud_core::paths::normalize_os_path(&mac_cli)
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
