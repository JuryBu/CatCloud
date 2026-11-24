use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
    OverrideMode, PersonalizationConfig, PreAccelConfig, PreAccelRelay, ProbeDefinition,
    ProbeSnapshot, ProxyMode, ProxyNode, RouteTargetMode, SubscriptionKind, SubscriptionRecord,
    SwitchMode, ThemeDaySchedule, ThemeMode, TrayClickAction as CoreTrayClickAction, TrayIconMode,
    TunStackMode, UpdateApplyMode, UpdateConfig,
};
use catcloud_core::platform::{SystemProxySpec, default_platform};
use catcloud_core::preaccel::campus::{
    CampusBypassTracker, CampusPortalState, probe_campus_portal_with_fallback,
};
use catcloud_core::preaccel::global_tunnel::{GlobalPreAccelManager, GlobalPreAccelStatus};
#[cfg(target_os = "windows")]
use catcloud_core::preaccel::global_tunnel::download_and_install_windivert;
use catcloud_core::probe::{
    DEFAULT_READY_TIMEOUT, FunnelOptions, FunnelTier, IsolatedProbeCore, ProbeRegistry,
    ThroughputProbeConfig, build_isolated_http_client, probe_live_google_cleanliness,
    run_download_probe_with_config, run_funnel_for_node, run_latency_probe,
    run_upload_probe_with_config,
};
use catcloud_core::process_guard::JobGuard;
#[cfg(target_os = "windows")]
use catcloud_core::process_guard::relaunch_self_as_admin;
use catcloud_core::storage::Storage;
use catcloud_core::strategy::evaluator::evaluate_group_candidates;
use catcloud_core::subscription::{
    ADAPTER_REASON_MANUAL, AdapterConfig, AdapterCooldownGuard, AdapterRequest, FetchOptions,
    ParsedSubscription, SubscriptionPayloadFormat, apply_parsed_subscription,
    fetch_and_parse_subscription_with_options, inspect_process_source as core_inspect_process_source,
    invoke_external_adapter, parse_controller_proxies_json, parse_subscription_payload,
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

/// Shared backend state managed by Tauri across commands, tray callbacks, streams, and shortcuts.
pub struct AppState {
    pub paths: AppPaths,
    pub config: RwLock<AppConfig>,
    pub storage: Mutex<Storage>,
    pub job_guard: Arc<JobGuard>,
    pub global_preaccel: Arc<GlobalPreAccelManager>,
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
    pub core_session_gen: Arc<AtomicU64>,
    pub last_hotkey_bindings: Mutex<Option<ShortcutBindings>>,
    pub adapter_cooldown: Arc<AdapterCooldownGuard>,
    pub shutting_down: Arc<AtomicBool>,
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
        cfg: AppConfig,
        storage: Storage,
        job_guard: Arc<JobGuard>,
    ) -> Self {
        let adapter = Arc::new(
            MihomoAdapter::new(Arc::clone(&job_guard))
                .expect("failed to initialize MihomoAdapter"),
        );
        let global_preaccel = Arc::new(GlobalPreAccelManager::new(
            paths.clone(),
            Arc::clone(&job_guard),
        ));
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
            core_session_gen: Arc::new(AtomicU64::new(0)),
            last_hotkey_bindings: Mutex::new(None),
            adapter_cooldown: Arc::new(AdapterCooldownGuard::new()),
            shutting_down: Arc::new(AtomicBool::new(false)),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiPersonalizationDto {
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
                global_bypass_enabled: Some(cfg.preaccel.global_bypass_enabled),
                global_scope: Some(cfg.preaccel.global_scope),
                global_target_processes: Some(cfg.preaccel.global_target_processes.clone()),
                windivert_dir: cfg.preaccel.windivert_dir.clone(),
            },
            personalization: UiPersonalizationDto {
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
        global_bypass_enabled: dto
            .preaccel
            .global_bypass_enabled
            .unwrap_or(cfg.preaccel.global_bypass_enabled),
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
    pub preaccel_relay_name: Option<String>,
    pub captive_portal_required: bool,
    pub system_proxy_enabled: bool,
    pub tun_enabled: bool,
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
    let excluded = exclude_node_id.map(str::trim).filter(|s| !s.is_empty());
    let allowed = |id: &str| excluded != Some(id) && is_valid_group_member(group, id, nodes);

    if let Ok(report) = evaluate_group_candidates(group, nodes, snaps) {
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
        if !group.hard_gates.is_empty() {
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
    max_candidates: usize,
) -> Vec<String> {
    if max_candidates == 0 {
        return Vec::new();
    }
    let active_trimmed = active_node_id.map(str::trim).filter(|s| !s.is_empty());
    let allowed = |id: &str| {
        active_trimmed != Some(id)
            && !cooldown_node_ids.contains(id)
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

    if let Ok(report) = evaluate_group_candidates(group, nodes, snaps) {
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
        // Tier 3: remaining gate-passing candidates when static hard gates are configured.
        if !group.hard_gates.is_empty() {
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
/// `cooldown_node_ids`. If every non-active member is in cooldown, relaxes the cooldown filter as a
/// last resort while still excluding `active_node_id`.
pub(crate) fn pick_group_candidates_with_cooldown(
    group: &MultiGroup,
    nodes: &[ProxyNode],
    snaps: &HashMap<String, ProbeSnapshot>,
    active_node_id: Option<&str>,
    cooldown_node_ids: &HashSet<String>,
    max_candidates: usize,
) -> Vec<String> {
    let ranked = collect_ranked_group_candidates(
        group,
        nodes,
        snaps,
        active_node_id,
        cooldown_node_ids,
        max_candidates,
    );
    if !ranked.is_empty() || cooldown_node_ids.is_empty() {
        return ranked;
    }
    let empty = HashSet::new();
    collect_ranked_group_candidates(group, nodes, snaps, active_node_id, &empty, max_candidates)
}

/// Sanitize a group's `active_node_id`: when `!group.member_node_ids.is_empty()` and
/// `group.active_node_id` is missing, removed from `member_node_ids`, or disabled, replace it
/// with the highest-scoring gate-passing candidate via `evaluate_group_candidates` (falling back
/// to the first enabled member, or `None` if no enabled member exists).
/// Returns `true` if `group.active_node_id` was modified.
pub fn sanitize_group_active_node(
    group: &mut MultiGroup,
    nodes: &[ProxyNode],
    snaps: &HashMap<String, ProbeSnapshot>,
) -> bool {
    if !group.member_node_ids.is_empty() {
        let current_valid = group
            .active_node_id
            .as_deref()
            .is_some_and(|id| is_valid_group_member(group, id, nodes));
        if current_valid {
            return false;
        }
        let next = pick_best_group_candidate(group, nodes, snaps, None);
        if group.active_node_id != next {
            group.active_node_id = next;
            return true;
        }
        return false;
    }

    // Even for dynamic/empty-member groups, clear stale references to deleted or disabled nodes.
    if let Some(active_id) = group.active_node_id.as_deref() {
        if !is_valid_group_member(group, active_id, nodes) {
            let next = pick_best_group_candidate(group, nodes, snaps, None);
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
/// 1. Always clears ghost/invalid `active_node_id` via `sanitize_group_active_node`.
/// 2. For `StickyBest` / `ConditionalPool` groups, if the current active node is unprobed,
///    failed/disconnected, or violates hard gates while a gate-passing healthy candidate exists,
///    switches to the top-ranked candidate.
/// 3. Respects sticky user choice: if the current active node is already in-group, probed,
///    connected, and passes all hard gates, leaves it untouched to prevent IP drift.
fn reconcile_group_best_node_in_memory(
    group: &mut MultiGroup,
    nodes: &[ProxyNode],
    snaps: &HashMap<String, ProbeSnapshot>,
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
        sanitize_group_active_node(group, nodes, snaps);
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
    let Ok(report) = evaluate_group_candidates(group, nodes, snaps) else {
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
    let assessment = report.active_assessment.as_ref();

    let reason = if cur_snap.is_none() {
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
/// (core process is running AND either OS system proxy or TUN virtual NIC is enabled).
pub(crate) fn is_proxy_takeover_active(core_running: bool, cfg: &AppConfig) -> bool {
    core_running && (cfg.system_proxy.enabled || cfg.tun.enabled)
}

pub fn build_tray_menu_state(app: &AppHandle, state: &AppState) -> TrayMenuState {
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
                    ping_ms: snap
                        .and_then(|s| s.latency_ms)
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
            mbps: r.last_mbps.map(|v| v.max(0.0).round() as u32),
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
    let proxy_active = is_proxy_takeover_active(rt.running, &cfg);
    let global_mode_label = if global_status.running {
        if proxy_active && cfg.preaccel.enabled {
            Some("dual".to_string())
        } else {
            Some(global_status.mode.clone())
        }
    } else if cfg.preaccel.enabled && !proxy_active {
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
        tun_enabled: cfg.tun.enabled,
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
            global_enabled: cfg.preaccel.global_bypass_enabled,
            global_running: global_status.running,
            global_mode_label,
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
    let proxy_active = is_proxy_takeover_active(rt.running, &cfg);
    let preaccel_active = (proxy_active && cfg.preaccel.enabled) || global_status.running;
    let health = if rt.last_error.is_some() {
        TrayHealthState::Error
    } else if portal_required {
        TrayHealthState::Warn
    } else if preaccel_active {
        TrayHealthState::PreAccel
    } else if proxy_active {
        TrayHealthState::Ok
    } else {
        TrayHealthState::Idle
    };

    let (primary_group_summary, configured_relay_name) = state
        .storage
        .lock()
        .ok()
        .map(|db| {
            let relays = db.list_preaccel_relays(true).unwrap_or_default();
            let relay_name = cfg
                .preaccel
                .active_relay_id
                .as_deref()
                .and_then(|id| relays.iter().find(|r| r.id == id))
                .or_else(|| relays.first())
                .map(|r| r.name.clone());

            let group_summary = (|| {
                if cfg.route_mode == RouteTargetMode::Single {
                    if let Some(node) = cfg
                        .active_single_node_id
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .and_then(|id| db.get_node(id).ok().flatten())
                    {
                        return Some(format!("单节点 · {}", node.name));
                    }
                }
                let groups = db.list_multi_groups().ok()?;
                let nodes = db.list_nodes().unwrap_or_default();
                let g = cfg
                    .active_group_id
                    .as_deref()
                    .and_then(|gid| groups.iter().find(|g| g.id == gid))
                    .or_else(|| groups.first())?;
                let node_name = resolve_valid_group_active_node(g, &nodes)
                    .map(|n| n.name.clone())
                    .unwrap_or_else(|| "自动择优".to_string());
                Some(format!("{} -> {}", g.name, node_name))
            })();
            (group_summary, relay_name)
        })
        .unwrap_or((None, None));

    let active_relay_name = global_status
        .active_relays
        .first()
        .cloned()
        .or(configured_relay_name);

    let preaccel_summary = if global_status.running {
        if global_status.mode == "windivert" {
            let prefix = if proxy_active && cfg.preaccel.enabled {
                "全局+代理提速中"
            } else {
                "底层全局提速中"
            };
            match active_relay_name.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                Some(relay) => Some(format!("{prefix} · {relay}")),
                None => Some(prefix.to_string()),
            }
        } else if let Some(port) = global_status.socks_port {
            Some(format!("本地443通道 (127.0.0.1:{port})"))
        } else {
            Some("本地443通道就绪".to_string())
        }
    } else if proxy_active && cfg.preaccel.enabled {
        match active_relay_name.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(relay) => Some(format!("国内加速中 · {relay}")),
            None => Some("国内加速入口运行中".to_string()),
        }
    } else if cfg.preaccel.enabled {
        Some("国内加速已开启（待启动）".to_string())
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
        proxy_mode: match cfg.proxy_mode {
            ProxyMode::Rule => TrayProxyMode::Rule,
            ProxyMode::Global => TrayProxyMode::Global,
            ProxyMode::Direct => TrayProxyMode::Direct,
        },
        tun_enabled: cfg.tun.enabled,
        system_proxy_enabled: cfg.system_proxy.enabled,
        preaccel_summary,
        primary_group_summary,
        realtime_speed,
    };
    TrayVisualState {
        icon_mode,
        health,
        tooltip: info.format_tooltip(),
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
    let proxy_active = is_proxy_takeover_active(rt.running, &cfg);
    let preaccel_active = (proxy_active && cfg.preaccel.enabled) || global_status.running;

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

    let status_label = if rt.last_error.is_some() {
        "error".to_string()
    } else if portal_required {
        "warn".to_string()
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
        proxy_mode: if rt.running {
            rt.proxy_mode.clone()
        } else {
            cfg.proxy_mode.clone()
        },
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
        active_node_latency_ms: active_snap.as_ref().and_then(|s| s.latency_ms),
        active_node_up_mbps: active_snap.as_ref().and_then(|s| s.up_mbps),
        preaccel_active,
        preaccel_enabled: cfg.preaccel.enabled,
        global_preaccel_active: global_status.running,
        global_preaccel_mode: global_status.mode,
        global_preaccel_socks_port: global_status.socks_port,
        global_preaccel_connections: global_status.active_connections,
        preaccel_relay_name: active_relay_name,
        captive_portal_required: portal_required,
        system_proxy_enabled: cfg.system_proxy.enabled,
        tun_enabled: cfg.tun.enabled,
        tun_admin_ready: is_tun_privilege_ready(state),
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
                        let next = !st.snapshot_config().tun.enabled;
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
fn ensure_default_group_if_empty(state: &AppState) {
    let created_group_id = {
        let Ok(db) = state.storage.lock() else {
            return;
        };
        let Ok(groups) = db.list_multi_groups() else {
            return;
        };
        if !groups.is_empty() {
            return;
        }
        let Ok(nodes) = db.list_nodes() else {
            return;
        };
        if nodes.is_empty() {
            return;
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
            return;
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

/// Deterministic exit safety hook invoked before `JobGuard::terminate_all()` on `RunEvent::Exit`.
///
/// 1. Stops background `ProxyGuard` ticks immediately via `shutting_down`.
/// 2. Gracefully disables TUN (1.5s bounded timeout) whenever TUN or external overrides may have
///    activated Wintun & OS routes, so they are released cleanly.
/// 3. Clears Windows WinINet system proxy under `system_proxy_lock` (only if owned by CatCloud)
///    WITHOUT mutating `config.json` remembered preferences.
pub fn emergency_cleanup_on_exit(state: &AppState) {
    state.shutting_down.store(true, Ordering::SeqCst);
    state.stop_streams();

    let cfg = state.snapshot_config();
    let may_have_tun =
        cfg.tun.enabled || cfg.rules_override.override_mode != OverrideMode::Disabled;
    let global_running = state.global_preaccel.status().running;

    if may_have_tun || global_running {
        let adapter = Arc::clone(&state.adapter);
        let global_preaccel = Arc::clone(&state.global_preaccel);
        let run_teardown = move || {
            tauri::async_runtime::block_on(async move {
                if global_running {
                    let _ = tokio::time::timeout(
                        Duration::from_millis(1500),
                        global_preaccel.stop(),
                    )
                    .await;
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
        if tokio::runtime::Handle::try_current().is_ok() {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                run_teardown();
                let _ = tx.send(());
            });
            let _ = rx.recv_timeout(Duration::from_millis(2000));
        } else {
            run_teardown();
        }
    }

    if let Err(err) = clear_system_proxy_if_owned(state) {
        tracing::warn!("退出时清除系统代理失败：{err}");
    }
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

            for group in &mut groups {
                let prev_active = group.active_node_id.clone();
                let is_target =
                    primary_gid.as_deref() == Some(group.id.as_str()) || group.independent_routing;
                if let Some(ref probe_id) = group.primary_probe_id {
                    let group_snaps = db
                        .get_probe_snapshots_batch(&node_ids, Some(probe_id.as_str()))
                        .unwrap_or_else(|_| default_snaps.clone());
                    if is_target {
                        let _ = reconcile_group_best_node_in_memory(group, &nodes, &group_snaps);
                    } else {
                        let _ = sanitize_group_active_node(group, &nodes, &group_snaps);
                    }
                } else if is_target {
                    let _ = reconcile_group_best_node_in_memory(group, &nodes, &default_snaps);
                } else {
                    let _ = sanitize_group_active_node(group, &nodes, &default_snaps);
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

    let empty_filter = HashMap::new();
    let input = CompileInput {
        config: &cfg,
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
        config: cfg.clone(),
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
        .seed_active_state(cfg.clone(), compiled.sha256, allocated.clone(), secret.clone())
        .await;
    state.bump_core_session_generation();
    state.update_cached_runtime(status.clone());
    state.clear_app_error();
    state.log_app_event(
        "info",
        "核心",
        &format!(
            "代理核心已启动（模式 {}，混合端口 {}，节点 {} 个，规则 {} 条，虚拟网卡 {}，国内提速 {}）",
            cfg.proxy_mode.as_str(),
            status.mixed_port,
            status.node_count,
            status.rule_count,
            if cfg.tun.enabled { "开启" } else { "关闭" },
            if cfg.preaccel.enabled { "开启" } else { "关闭" }
        ),
    );

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

    // Coordinate with standalone global pre-acceleration: when CatCloud's primary core takes over
    // host traffic via system proxy or TUN, suspend the standalone 443 tunnel by default so we do
    // not run two redundant 443 Mihomo tunnels (preserving `global_bypass_enabled` for clean
    // hand-back if the primary core is stopped later). Otherwise, if the standalone global engine
    // remains running alongside an idle/mixed-port-only primary core, synchronize the new main
    // core PID so WinDivert excludes CatCloud's own `mihomo` process.
    let latest_cfg = state.snapshot_config();
    if is_proxy_takeover_active(status.running, &latest_cfg)
        && state.global_preaccel.status().running
    {
        let _ = state.global_preaccel.stop().await;
        state.log_app_event(
            "info",
            "国内提速",
            "主代理核心已启动接管流量，已暂挂独立底层 443 隧道以避免重复占用内存，改由主核心统一提供国内提速",
        );
    } else if state.global_preaccel.status().running {
        let main_pid = status.pid.filter(|&p| p > 0);
        state.global_preaccel.sync_main_core_pid(main_pid);
    }

    sync_app_side_effects(app, state, &latest_cfg);
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
    let may_have_tun =
        cfg.tun.enabled || cfg.rules_override.override_mode != OverrideMode::Disabled;
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
) -> Result<CoreRuntimeInfoDto, String> {
    let old_cfg = state.snapshot_config();
    let was_sys_proxy_enabled = old_cfg.system_proxy.enabled;
    let may_have_tun =
        old_cfg.tun.enabled || old_cfg.rules_override.override_mode != OverrideMode::Disabled;
    let mut cfg = old_cfg;
    let flags_changed = cfg.system_proxy.enabled || cfg.tun.enabled;

    if flags_changed {
        cfg.system_proxy.enabled = false;
        cfg.tun.enabled = false;
        if let Ok(mut guard) = state.config.write() {
            *guard = cfg.clone();
        }
    }

    if let Err(err) = clear_system_proxy_if_owned_with_hint(state, was_sys_proxy_enabled) {
        tracing::warn!("停止核心前清除系统代理失败：{err}");
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
    state.bump_core_session_generation();
    state.telemetry.clear_traffic();
    state.set_node_proxy_name_map(HashMap::new());
    state.set_compiled_group_ids(None);
    let status = state.adapter.status().await;
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
    state.log_app_event("info", "核心", "代理核心已停止，系统代理与虚拟网卡状态已复位");

    // If the user kept standalone global pre-acceleration enabled while stopping CatCloud's own
    // proxy core, seamlessly resume the lightweight standalone 443 tunnel.
    if !state.shutting_down.load(Ordering::SeqCst)
        && cfg.preaccel.enabled
        && cfg.preaccel.global_bypass_enabled
        && !state.global_preaccel.status().running
    {
        match start_global_preaccel_engine(state, &cfg).await {
            Ok(global_st) => {
                state.log_app_event(
                    "info",
                    "国内提速",
                    &format!(
                        "主代理核心已停止，已自动切回独立底层全局国内提速（模式：{}）",
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
    stop_core_locked(app, state).await
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
                "配置热重载成功（级别 {}，回放分组 {} 个）",
                outcome.level, outcome.replayed_groups
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
            tracing::warn!("核心 L3 重启后同步系统代理端口失败：{err}");
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

/// Coordinate standalone global pre-acceleration whenever host traffic takeover (`proxy_active`)
/// transitions between inactive and active:
/// - `false -> true`: suspend a running standalone 443 tunnel to prevent running two 443 tunnels
///   concurrently while preserving `global_bypass_enabled` for later hand-back.
/// - `true -> false`: seamlessly resume the standalone global pre-acceleration engine when
///   `cfg.preaccel.global_bypass_enabled` is true and enabled relays exist.
async fn coordinate_global_preaccel_on_proxy_transition(
    state: &AppState,
    cfg: &AppConfig,
    was_proxy_active: bool,
    now_proxy_active: bool,
    trigger_label: &str,
) {
    if state.shutting_down.load(Ordering::SeqCst) {
        return;
    }
    if !was_proxy_active && now_proxy_active {
        if state.global_preaccel.status().running {
            let _ = state.global_preaccel.stop().await;
            state.log_app_event(
                "info",
                "国内提速",
                &format!(
                    "{trigger_label}已生效接管流量，已暂挂独立底层 443 隧道以避免双跑 443，改由主核心统一提供国内提速"
                ),
            );
        }
    } else if was_proxy_active && !now_proxy_active {
        if cfg.preaccel.global_bypass_enabled
            && !state.global_preaccel.status().running
            && load_enabled_preaccel_relays(state).is_ok_and(|relays| !relays.is_empty())
        {
            match start_global_preaccel_engine(state, cfg).await {
                Ok(global_st) => {
                    state.log_app_event(
                        "info",
                        "国内提速",
                        &format!(
                            "{trigger_label}已关闭且主代理不再接管流量，已自动切回独立底层全局国内提速（模式：{}）",
                            global_st.mode
                        ),
                    );
                }
                Err(err) => {
                    state.log_app_event(
                        "warning",
                        "国内提速",
                        &format!("{trigger_label}关闭后自动切回独立底层全局国内提速失败：{err}"),
                    );
                }
            }
        }
    }
}

/// Apply system proxy state safely:
/// - Turning ON checks for enabled nodes, auto-starts the core when stopped, validates reload,
///   and rolls back `config.json` on any failure so Windows is never left with a dead proxy.
/// - Turning OFF updates in-memory config first, then clears owned OS proxy under `system_proxy_lock`.
pub async fn apply_system_proxy_internal(
    app: &AppHandle,
    state: &AppState,
    enabled: bool,
) -> Result<bool, String> {
    let old_cfg = state.snapshot_config();
    let was_core_running =
        state.snapshot_runtime().running || state.adapter.has_live_controller().await;
    let was_proxy_active = is_proxy_takeover_active(was_core_running, &old_cfg);

    if !enabled {
        let was_enabled = old_cfg.system_proxy.enabled;
        let mut cfg = old_cfg.clone();
        cfg.system_proxy.enabled = false;
        if let Ok(mut guard) = state.config.write() {
            *guard = cfg.clone();
        }
        if let Err(err) = clear_system_proxy_if_owned_with_hint(state, was_enabled) {
            if let Ok(mut guard) = state.config.write() {
                *guard = old_cfg.clone();
            }
            return Err(err);
        }
        config::save(&state.paths, &cfg).map_err(|e| format!("保存系统代理状态失败：{e}"))?;
        let now_core_running =
            state.snapshot_runtime().running || state.adapter.has_live_controller().await;
        let now_proxy_active = is_proxy_takeover_active(now_core_running, &cfg);
        coordinate_global_preaccel_on_proxy_transition(
            state,
            &cfg,
            was_proxy_active,
            now_proxy_active,
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
    let disk_cfg = config::load_or_init(&state.paths)
        .map_err(|e| format!("读取配置文件失败：{e}"))?;

    let mut cfg = disk_cfg.clone();
    if !state.adapter.has_live_controller().await {
        // Boot core first WITHOUT dirty-writing `system_proxy.enabled = true` to disk.
        let mut boot_cfg = disk_cfg.clone();
        boot_cfg.system_proxy.enabled = false;
        if let Ok(mut guard) = state.config.write() {
            *guard = boot_cfg;
        }
        if let Err(err) = start_core_internal(app, state).await {
            if let Ok(mut guard) = state.config.write() {
                *guard = old_cfg.clone();
            }
            sync_app_side_effects(app, state, &old_cfg);
            return Err(format!("开启系统代理前启动核心失败：{err}"));
        }
        cfg.system_proxy.enabled = true;
        config::save(&state.paths, &cfg).map_err(|e| format!("保存系统代理配置失败：{e}"))?;
        if let Ok(mut guard) = state.config.write() {
            *guard = cfg.clone();
        }
    } else {
        cfg.system_proxy.enabled = true;
        config::save(&state.paths, &cfg).map_err(|e| format!("保存系统代理配置失败：{e}"))?;
        if let Ok(mut guard) = state.config.write() {
            *guard = cfg.clone();
        }
        if let Some(outcome) = trigger_reload_if_running(app, state, true).await {
            if outcome.rejected {
                let _ = config::save(&state.paths, &old_cfg);
                if let Ok(mut guard) = state.config.write() {
                    *guard = old_cfg.clone();
                }
                sync_app_side_effects(app, state, &old_cfg);
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
            sync_app_side_effects(app, state, &latest);
            let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&latest));
            return Ok(false);
        }
        Err(err) => {
            let _ = config::save(&state.paths, &old_cfg);
            if let Ok(mut guard) = state.config.write() {
                *guard = old_cfg.clone();
            }
            state.log_app_event(
                "error",
                "系统代理",
                &format!("写入操作系统代理失败，已回滚配置：{err}"),
            );
            sync_app_side_effects(app, state, &old_cfg);
            return Err(err);
        }
    }

    let now_core_running =
        state.snapshot_runtime().running || state.adapter.has_live_controller().await;
    let now_proxy_active = is_proxy_takeover_active(now_core_running, &cfg);
    coordinate_global_preaccel_on_proxy_transition(
        state,
        &cfg,
        was_proxy_active,
        now_proxy_active,
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

            enabled_nodes.sort_by(|(idx_a, a), (idx_b, b)| {
                let rank = |n: &ProxyNode| -> (u8, f64, f64) {
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
                next_snap.and_then(|s| s.latency_ms),
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

    // Rank candidates using the real strategy formula evaluator; when all members fail hard gates,
    // keep honoring probed-ok scores in `gate_rejected` before falling back to enabled member order.
    let ranked_ids: Vec<String> = match evaluate_group_candidates(&group, &nodes, &snaps) {
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
    let trimmed = node_id.trim();
    if trimmed.is_empty() {
        return Err("节点标识不能为空".to_string());
    }

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

    Ok(SwitchResultDto {
        group_id: group.id,
        previous_node_id: prev_id,
        active_node_id: target_node.id,
        active_node_name: target_node.name,
        active_node_region: target_node.region_code,
        latency_ms: snap.as_ref().and_then(|s| s.latency_ms),
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
        let decision = reconcile_group_best_node_in_memory(&mut group, &nodes, &snaps);
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

    Ok(Some(SwitchResultDto {
        group_id: group_id.to_string(),
        previous_node_id: decision.from_node_id,
        active_node_id: decision.to_node_id,
        active_node_name: decision.to_node_name,
        active_node_region: target_node_region,
        latency_ms: target_snap.as_ref().and_then(|s| s.latency_ms),
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

async fn apply_and_save_config_transition(
    app: &AppHandle,
    state: &AppState,
    old: &AppConfig,
    next: &AppConfig,
) -> Result<(), String> {
    let was_core_running =
        state.snapshot_runtime().running || state.adapter.has_live_controller().await;
    let was_proxy_active = is_proxy_takeover_active(was_core_running, old);

    if !old.tun.enabled && next.tun.enabled && !is_tun_privilege_ready(state) {
        return Err(tun_needs_admin_error_message());
    }

    if (!old.system_proxy.enabled && next.system_proxy.enabled)
        || (!old.tun.enabled && next.tun.enabled)
    {
        if !has_enabled_nodes(state)? {
            return Err("暂无可用节点，请先导入订阅".to_string());
        }
    }

    if old.tun.enabled && !next.tun.enabled && state.adapter.has_live_controller().await {
        let _ = state.adapter.disable_tun_gracefully().await;
    }

    config::save(&state.paths, next).map_err(|e| format!("保存配置文件失败：{e}"))?;
    if let Ok(mut guard) = state.config.write() {
        *guard = next.clone();
    }

    let needs_core_boot = ((!old.system_proxy.enabled && next.system_proxy.enabled)
        || (!old.tun.enabled && next.tun.enabled))
        && !state.adapter.has_live_controller().await;

    if needs_core_boot {
        if let Err(err) = start_core_internal(app, state).await {
            let _ = config::save(&state.paths, old);
            if let Ok(mut guard) = state.config.write() {
                *guard = old.clone();
            }
            sync_app_side_effects(app, state, old);
            return Err(format!("保存配置后启动代理核心失败：{err}"));
        }
    } else if has_core_config_changes(old, next) {
        if let Some(outcome) = trigger_reload_if_running(app, state, false).await {
            if outcome.rejected {
                let _ = config::save(&state.paths, old);
                if let Ok(mut guard) = state.config.write() {
                    *guard = old.clone();
                }
                sync_app_side_effects(app, state, old);
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
            let _ = config::save(&state.paths, old);
            if let Ok(mut guard) = state.config.write() {
                *guard = old.clone();
            }
            sync_app_side_effects(app, state, old);
            return Err(err);
        }
    }

    let now_core_running =
        state.snapshot_runtime().running || state.adapter.has_live_controller().await;
    let now_proxy_active = is_proxy_takeover_active(now_core_running, next);
    if was_proxy_active != now_proxy_active {
        coordinate_global_preaccel_on_proxy_transition(
            state,
            next,
            was_proxy_active,
            now_proxy_active,
            "代理配置",
        )
        .await;
    }

    sync_autostart_if_changed(old, next);
    sync_app_side_effects(app, state, next);
    let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(next));
    Ok(())
}

#[tauri::command]
pub async fn save_app_config(
    app: AppHandle,
    state: State<'_, AppState>,
    config: UiAppConfigDto,
) -> Result<UiAppConfigDto, String> {
    let old = state.snapshot_config();
    let mut cfg = old.clone();
    apply_ui_dto(&mut cfg, &config);
    apply_and_save_config_transition(&app, &state, &old, &cfg).await?;
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
    next: AppConfig,
) -> Result<AppConfig, String> {
    let old = state.snapshot_config();
    apply_and_save_config_transition(&app, &state, &old, &next).await?;
    Ok(next)
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
    let old = state.snapshot_config();
    let mut base_val = serde_json::to_value(&old).map_err(|e| e.to_string())?;
    json_deep_merge(&mut base_val, &patch);
    let next: AppConfig = serde_json::from_value(base_val)
        .map_err(|e| format!("配置字段格式无效：{e}"))?;
    apply_and_save_config_transition(&app, &state, &old, &next).await?;
    Ok(next)
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
    start_core_internal(&app, &state).await
}

#[tauri::command]
pub async fn stop_core(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CoreRuntimeInfoDto, String> {
    stop_core_internal(&app, &state).await
}

#[tauri::command]
pub async fn restart_core(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CoreRuntimeInfoDto, String> {
    let _lifecycle_guard = state.core_lifecycle_lock.lock().await;
    stop_core_for_restart_locked(&state).await?;
    match start_core_locked(&app, &state).await {
        Ok(dto) => Ok(dto),
        Err(err) => {
            // If restart fails, flip in-memory flags first, then clear owned OS proxy & save
            // so ProxyGuard cannot race back to `ProxyEnable=1` and host internet is never blackholed.
            let mut cfg = state.snapshot_config();
            let was_sys_proxy_enabled = cfg.system_proxy.enabled;
            let flags_changed = cfg.system_proxy.enabled || cfg.tun.enabled;
            if flags_changed {
                cfg.system_proxy.enabled = false;
                cfg.tun.enabled = false;
                if let Ok(mut guard) = state.config.write() {
                    *guard = cfg.clone();
                }
            }
            let _ = clear_system_proxy_if_owned_with_hint(&state, was_sys_proxy_enabled);
            if flags_changed {
                let _ = config::save(&state.paths, &cfg);
            }
            sync_app_side_effects(&app, &state, &cfg);
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
pub async fn reload_core_config(
    app: AppHandle,
    state: State<'_, AppState>,
    force_disk_reload: Option<bool>,
) -> Result<ReloadOutcome, String> {
    let force = force_disk_reload.unwrap_or(true);
    let disk_cfg = config::load_or_init(&state.paths).map_err(|e| e.to_string())?;
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
    let mut outcome = state
        .hot_reload
        .apply_disk_reload(DiskReloadOptions {
            force,
            verify_with_binary: true,
            allow_l3_restart: false,
            ..DiskReloadOptions::default()
        })
        .await;
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
/// - Disabling calls `disable_tun_gracefully()` before saving and reloading.
pub async fn set_tun_enabled_internal(
    app: &AppHandle,
    state: &AppState,
    enabled: bool,
) -> Result<bool, String> {
    let old_cfg = state.snapshot_config();
    let was_core_running =
        state.snapshot_runtime().running || state.adapter.has_live_controller().await;
    let was_proxy_active = is_proxy_takeover_active(was_core_running, &old_cfg);

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
                let _ = config::save(&state.paths, &old_cfg);
                if let Ok(mut guard) = state.config.write() {
                    *guard = old_cfg.clone();
                }
                state.log_app_event(
                    "error",
                    "虚拟网卡",
                    &format!("开启虚拟网卡并启动核心失败，已回滚：{err}"),
                );
                sync_app_side_effects(app, state, &old_cfg);
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
                let _ = config::save(&state.paths, &old_cfg);
                if let Ok(mut guard) = state.config.write() {
                    *guard = old_cfg.clone();
                }
                state.log_app_event(
                    "error",
                    "虚拟网卡",
                    &format!("开启虚拟网卡失败，已回滚配置：{detail}"),
                );
                sync_app_side_effects(app, state, &old_cfg);
                return Err(detail);
            }
        }

        let now_core_running =
            state.snapshot_runtime().running || state.adapter.has_live_controller().await;
        let now_proxy_active = is_proxy_takeover_active(now_core_running, &cfg);
        coordinate_global_preaccel_on_proxy_transition(
            state,
            &cfg,
            was_proxy_active,
            now_proxy_active,
            "虚拟网卡（TUN）",
        )
        .await;

        state.log_app_event(
            "info",
            "虚拟网卡",
            &format!("已开启虚拟网卡（TUN 协议栈：{}）", cfg.tun.stack_mode.as_str()),
        );
        let latest_cfg = state.snapshot_config();
        sync_app_side_effects(app, state, &latest_cfg);
        let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&latest_cfg));
        return Ok(true);
    }

    // Disabling TUN: gracefully release Wintun adapter & OS routes first, then save & reload.
    if state.adapter.has_live_controller().await {
        let _ = state.adapter.disable_tun_gracefully().await;
    }

    let mut cfg = old_cfg.clone();
    cfg.tun.enabled = false;
    config::save(&state.paths, &cfg).map_err(|e| format!("保存虚拟网卡配置失败：{e}"))?;
    if let Ok(mut guard) = state.config.write() {
        *guard = cfg.clone();
    }

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

    let now_core_running =
        state.snapshot_runtime().running || state.adapter.has_live_controller().await;
    let now_proxy_active = is_proxy_takeover_active(now_core_running, &cfg);
    coordinate_global_preaccel_on_proxy_transition(
        state,
        &cfg,
        was_proxy_active,
        now_proxy_active,
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
            let may_have_tun =
                cfg.tun.enabled || cfg.rules_override.override_mode != OverrideMode::Disabled;
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

#[tauri::command]
pub fn list_multi_groups(state: State<'_, AppState>) -> Result<Vec<MultiGroup>, String> {
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
                let _ = sanitize_group_active_node(g, &nodes, &snaps);
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
        let _ = sanitize_group_active_node(&mut group, &nodes, &snaps);
        let _ = reconcile_group_best_node_in_memory(&mut group, &nodes, &snaps);

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
        let _ = sanitize_group_active_node(&mut group, &nodes, &snaps);
        let _ = reconcile_group_best_node_in_memory(&mut group, &nodes, &snaps);

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
}

impl Drop for ProbeRunningGuard {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.cancel_tx.lock() {
            *guard = None;
        }
        self.running.store(false, Ordering::SeqCst);
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
    let _running_guard = ProbeRunningGuard {
        running: Arc::clone(&state.probe_running),
        cancel_tx: Arc::clone(&state.probe_cancel_tx),
    };

    let cfg = state.snapshot_config();
    let extra_candidates = state.extra_binary_candidates();
    let resolution = resolve_mihomo_binary(&cfg, &state.paths, &extra_candidates, false)
        .map_err(|e| format!("查找代理核心失败：{e}"))?;
    let Some(mihomo_bin) = resolution.path else {
        return Err("未找到 Mihomo 内核文件，无法执行隔离测速".to_string());
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
        "隔离测速",
        &format!(
            "开始隔离测速：目标节点 {} 个，档位 {}，国内提速 {}",
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
                errors.push(format!("隔离测速核心启动失败：{err}"));
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
        "隔离测速",
        &format!(
            "隔离测速{status_text}：完成 {completed_count}/{total_count}，可用 {ok_count} 个，异常 {} 条",
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

#[tauri::command]
pub fn upsert_subscription(
    app: AppHandle,
    state: State<'_, AppState>,
    mut record: SubscriptionRecord,
) -> Result<SubscriptionRecord, String> {
    if record.id.trim().is_empty() {
        record.id = format!("sub-{}", uuid::Uuid::new_v4().simple());
    }
    {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        db.upsert_subscription(&record).map_err(|e| e.to_string())?;
    }
    ensure_default_group_if_empty(&state);
    let cfg = state.snapshot_config();
    sync_app_side_effects(&app, &state, &cfg);
    Ok(record)
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
        let _ = trigger_reload_if_running(&app, &state, false).await;
        let cfg = state.snapshot_config();
        sync_app_side_effects(&app, &state, &cfg);
    }
    Ok(deleted)
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
            .map_err(|e| format!("初始化控制接口请求客户端失败：{e}"))?;
        let mut req = client.get(&endpoint);
        if let Some(ref sec) = secret {
            req = req.bearer_auth(sec);
        }
        let mut resp = req.send().await.map_err(|e| {
            if e.is_timeout() {
                format!("连接控制接口（{endpoint}）超时，请确认目标代理软件正在运行")
            } else {
                format!("无法连接到控制接口（{endpoint}），请确认地址端口正确且目标程序已启动：{e}")
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
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| format!("读取控制接口响应失败：{e}"))?
        {
            if body.len().saturating_add(chunk.len()) > MAX_CTRL_BYTES {
                return Err("控制接口返回数据超过 16 MiB 上限，已安全终止读取".to_string());
            }
            body.extend_from_slice(&chunk);
        }

        let (nodes, meta_only_count, total_entries, mut warnings) =
            parse_controller_proxies_json(&sub.id, &body).map_err(|e| e.to_string())?;
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

    let adapter_cfg = AdapterConfig::from_command_line(raw)
        .map_err(|e| format!("外部适配器命令格式不正确，请检查路径与引号配对：{e}"))?;
    let req = AdapterRequest::new(ADAPTER_REASON_MANUAL, sub.id.clone(), Vec::new());
    let nodes = invoke_external_adapter(&adapter_cfg, &req, Some(&state.adapter_cooldown))
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if !msg.contains("cooldown") {
                state.adapter_cooldown.reset(&sub.id);
            }
            if msg.contains("cooldown") {
                format!("外部适配器刷新过于频繁，请稍候片刻再试（{msg}）")
            } else if msg.contains("failed to spawn") {
                format!(
                    "无法启动外部适配器程序「{}」，请确认命令路径正确且具有可执行权限：{msg}",
                    adapter_cfg.program
                )
            } else if msg.contains("timed out") {
                format!(
                    "外部适配器执行超时（超过 {} 秒），请检查脚本是否卡住",
                    adapter_cfg.timeout_sec
                )
            } else {
                format!(
                    "外部适配器未能返回有效节点，请确认脚本输出符合 catcloud-adapter/v1 规范：{msg}"
                )
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

async fn refresh_single_subscription_inner(
    state: &AppState,
    sub: &SubscriptionRecord,
) -> Result<serde_json::Value, String> {
    let parsed = match sub.kind {
        SubscriptionKind::Url => {
            fetch_and_parse_subscription_with_options(
                sub,
                Duration::from_secs(20),
                &FetchOptions::default(),
            )
            .await
            .map_err(|e| e.to_string())?
        }
        SubscriptionKind::File | SubscriptionKind::Migrated => {
            let raw = std::fs::read(&sub.url_or_cmd)
                .map_err(|e| format!("无法读取本地订阅文件「{}」：{e}", sub.url_or_cmd))?;
            parse_subscription_payload(&sub.id, &raw, None).map_err(|e| e.to_string())?
        }
        SubscriptionKind::ProcessAdapter => {
            refresh_process_adapter_subscription(state, sub).await?
        }
    };

    let node_count = {
        let mut db = state.storage.lock().map_err(|e| e.to_string())?;
        apply_parsed_subscription(&mut db, sub, &parsed).map_err(|e| e.to_string())?
    };
    ensure_default_group_if_empty(state);
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
    let sub = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        db.get_subscription(&sub_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("未找到指定订阅（{sub_id}）"))?
    };
    let result = refresh_single_subscription_inner(&state, &sub).await;
    if let Err(ref err) = result {
        if let Ok(db) = state.storage.lock() {
            let _ = db.update_subscription_refresh_status(
                &sub.id,
                None,
                None,
                Some(err.as_str()),
                None,
                None,
                None,
            );
        }
    } else {
        let _ = trigger_reload_if_running(&app, &state, false).await;
        let cfg = state.snapshot_config();
        sync_app_side_effects(&app, &state, &cfg);
    }
    result
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
        match refresh_single_subscription_inner(&state, &sub).await {
            Ok(v) => {
                refreshed += 1;
                total_nodes += v.get("node_count").and_then(|c| c.as_u64()).unwrap_or(0) as usize;
            }
            Err(err) => {
                errors.push(format!("{}: {err}", sub.name));
            }
        }
    }
    if refreshed > 0 {
        let _ = trigger_reload_if_running(&app, &state, false).await;
        let cfg = state.snapshot_config();
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
        .start(cfg, &relays, &excluded_pids)
        .await
        .map_err(|e| e.to_string())
}

async fn sync_running_global_preaccel_if_active(state: &AppState, cfg: &AppConfig) {
    if !state.global_preaccel.status().running {
        return;
    }
    match load_enabled_preaccel_relays(state) {
        Ok(relays) if !relays.is_empty() => {
            let excluded_pids = collect_excluded_pids_for_global_preaccel(state);
            if let Err(err) = state
                .global_preaccel
                .start(cfg, &relays, &excluded_pids)
                .await
            {
                state.log_app_event(
                    "warning",
                    "国内提速",
                    &format!("中转配置变更后重建独立底层 443 隧道失败：{err}"),
                );
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

pub async fn toggle_preaccel_internal(
    app: &AppHandle,
    state: &AppState,
    enabled: bool,
) -> Result<bool, String> {
    let old_cfg = state.snapshot_config();
    let mut cfg = old_cfg.clone();
    let core_running =
        state.snapshot_runtime().running || state.adapter.has_live_controller().await;
    let proxy_active = is_proxy_takeover_active(core_running, &cfg);

    if enabled {
        cfg.preaccel.enabled = true;
        if proxy_active {
            config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
            if let Ok(mut guard) = state.config.write() {
                *guard = cfg.clone();
            }
            state.log_app_event("info", "国内提速", "已开启国内 443 预加速（主代理核心生效）");
            let _ = trigger_reload_if_running(app, state, false).await;
        } else {
            let enabled_relays = load_enabled_preaccel_relays(state)?;
            if !enabled_relays.is_empty() {
                cfg.preaccel.global_bypass_enabled = true;
                config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
                if let Ok(mut guard) = state.config.write() {
                    *guard = cfg.clone();
                }
                match start_global_preaccel_engine(state, &cfg).await {
                    Ok(global_st) => {
                        let detail = match global_st.mode.as_str() {
                            "windivert" => "已开启独立底层全局国内提速（WinDivert 透明接管运行中）"
                                .to_string(),
                            _ => match global_st.socks_port {
                                Some(port) => format!(
                                    "已开启国内提速并启动本地独立 443 通道（127.0.0.1:{port}）"
                                ),
                                None => "已开启国内提速并启动本地独立 443 通道".to_string(),
                            },
                        };
                        state.log_app_event("info", "国内提速", &detail);
                    }
                    Err(err) => {
                        cfg.preaccel.global_bypass_enabled = old_cfg.preaccel.global_bypass_enabled;
                        let _ = config::save(&state.paths, &cfg);
                        if let Ok(mut guard) = state.config.write() {
                            *guard = cfg.clone();
                        }
                        state.log_app_event(
                            "error",
                            "国内提速",
                            &format!("主代理未接管流量时启动独立底层国内提速失败：{err}"),
                        );
                        sync_app_side_effects(app, state, &cfg);
                        let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&cfg));
                        return Err(err);
                    }
                }
            } else {
                config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
                if let Ok(mut guard) = state.config.write() {
                    *guard = cfg.clone();
                }
                state.log_app_event(
                    "warning",
                    "国内提速",
                    "已打开国内提速开关，但尚未配置可用的国内 443 中转线路",
                );
            }
        }
    } else {
        cfg.preaccel.enabled = false;
        cfg.preaccel.global_bypass_enabled = false;
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
        state.log_app_event("info", "国内提速", "已关闭国内 443 预加速（含独立底层全局提速）");
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

pub async fn toggle_global_preaccel_internal(
    app: &AppHandle,
    state: &AppState,
    enabled: bool,
) -> Result<GlobalPreAccelStatus, String> {
    let old_cfg = state.snapshot_config();
    let mut cfg = old_cfg.clone();

    if enabled {
        let relays = load_enabled_preaccel_relays(state)?;
        if relays.is_empty() {
            return Err("尚未配置已启用的国内 443 中转线路，请先添加并启用至少一条中转".to_string());
        }
        cfg.preaccel.global_bypass_enabled = true;
        cfg.preaccel.enabled = true;

        let excluded_pids = collect_excluded_pids_for_global_preaccel(state);
        match state
            .global_preaccel
            .start(&cfg, &relays, &excluded_pids)
            .await
        {
            Ok(status) => {
                if let Err(err) = config::save(&state.paths, &cfg) {
                    let _ = state.global_preaccel.stop().await;
                    let msg = format!("保存底层全局提速配置失败：{err}");
                    state.log_app_event("error", "国内提速", &msg);
                    sync_app_side_effects(app, state, &old_cfg);
                    let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&old_cfg));
                    return Err(msg);
                }
                if let Ok(mut guard) = state.config.write() {
                    *guard = cfg.clone();
                }
                let msg = match status.mode.as_str() {
                    "windivert" => "已开启独立底层全局国内提速（WinDivert 透明接管运行中）".to_string(),
                    _ => match status.socks_port {
                        Some(port) => format!(
                            "已开启独立底层国内提速（本地 443 SOCKS5 通道 127.0.0.1:{port}）"
                        ),
                        None => "已开启独立底层国内提速（本地 443 通道就绪）".to_string(),
                    },
                };
                state.log_app_event("info", "国内提速", &msg);
                sync_app_side_effects(app, state, &cfg);
                let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&cfg));
                Ok(status)
            }
            Err(err) => {
                let detail = err.to_string();
                state.log_app_event(
                    "error",
                    "国内提速",
                    &format!("开启独立底层全局国内提速失败：{detail}"),
                );
                sync_app_side_effects(app, state, &old_cfg);
                let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&old_cfg));
                Err(detail)
            }
        }
    } else {
        cfg.preaccel.global_bypass_enabled = false;
        config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
        if let Ok(mut guard) = state.config.write() {
            *guard = cfg.clone();
        }
        let status = state
            .global_preaccel
            .stop()
            .await
            .map_err(|e| e.to_string())?;
        state.log_app_event("info", "国内提速", "已停止独立底层全局国内提速");
        sync_app_side_effects(app, state, &cfg);
        let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&cfg));
        Ok(status)
    }
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

    let mut cfg = state.snapshot_config();
    cfg.preaccel.global_scope = parsed_scope;
    cfg.preaccel.global_target_processes = normalized_processes;
    cfg.preaccel.windivert_dir = normalized_dir;

    config::save(&state.paths, &cfg).map_err(|e| format!("保存底层全局提速设置失败：{e}"))?;
    if let Ok(mut guard) = state.config.write() {
        *guard = cfg.clone();
    }

    let was_running = state.global_preaccel.status().running;
    let status = if was_running {
        match start_global_preaccel_engine(&state, &cfg).await {
            Ok(st) => st,
            Err(err) => {
                state.log_app_event(
                    "warning",
                    "国内提速",
                    &format!("更新底层全局提速设置后重启引擎失败：{err}"),
                );
                sync_app_side_effects(&app, &state, &cfg);
                let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&cfg));
                return Err(err);
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

    #[cfg(target_os = "windows")]
    {
        let rt = state.snapshot_runtime();
        let proxy_url = if rt.running && rt.mixed_port > 0 {
            Some(format!("http://127.0.0.1:{}", rt.mixed_port))
        } else {
            None
        };

        let install_res = match proxy_url.as_deref() {
            Some(proxy) => match download_and_install_windivert(&state.paths, Some(proxy)).await {
                Ok(dir) => Ok(dir),
                Err(_) => download_and_install_windivert(&state.paths, None).await,
            },
            None => download_and_install_windivert(&state.paths, None).await,
        };

        let installed_dir = install_res.map_err(|e| {
            let msg = e.to_string();
            state.log_app_event("error", "国内提速", &format!("安装 WinDivert 驱动失败：{msg}"));
            msg
        })?;

        state.log_app_event(
            "info",
            "国内提速",
            &format!(
                "已下载并通过 SHA-256 校验安装官方 WinDivert v2.2.2 驱动至 {}",
                installed_dir.display()
            ),
        );

        let cfg = state.snapshot_config();
        let current = state.snapshot_global_preaccel();
        if current.running
            && current.mode != "windivert"
            && default_platform().capabilities().is_elevated
        {
            if let Err(err) = start_global_preaccel_engine(&state, &cfg).await {
                state.log_app_event(
                    "warning",
                    "国内提速",
                    &format!("驱动就绪后自动升级 WinDivert 透明模式失败：{err}"),
                );
            } else {
                state.log_app_event(
                    "info",
                    "国内提速",
                    "驱动安装完成，已自动升级为 WinDivert 最底层透明接管模式",
                );
            }
        }

        sync_app_side_effects(&app, &state, &cfg);
        let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&cfg));
        Ok(state.snapshot_global_preaccel())
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

#[tauri::command]
pub async fn select_preaccel_relay(
    app: AppHandle,
    state: State<'_, AppState>,
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
    sync_running_global_preaccel_if_active(&state, &cfg).await;
    state.log_app_event(
        "info",
        "国内提速",
        &format!("已切换国内提速中转至「{}」", relay.name),
    );
    sync_app_side_effects(&app, &state, &cfg);
    let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&cfg));
    Ok(relay.id)
}

#[tauri::command]
pub async fn failover_preaccel(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Option<String>, String> {
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
    let selected = select_preaccel_relay(app, state, next.id.clone()).await?;
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
    let mut metrics_updates: Vec<(String, f64, Option<f64>)> = Vec::new();
    for (_idx, relay, probe_res) in ordered_outcomes {
        match probe_res {
            Ok(ms) if ms.is_finite() && ms > 0.0 => {
                ok_count += 1;
                let rounded = ((ms * 10.0).round() / 10.0).max(0.1);
                metrics_updates.push((relay.id.clone(), rounded, relay.last_mbps));
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
            for (relay_id, rounded, last_mbps) in metrics_updates {
                let _ = db.update_preaccel_probe_metrics(&relay_id, Some(rounded), last_mbps);
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
    let _running_guard = ProbeRunningGuard {
        running: Arc::clone(&state.probe_running),
        cancel_tx: Arc::clone(&state.probe_cancel_tx),
    };

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
    std::fs::create_dir_all(&temp_root).map_err(|e| format!("创建隔离测速目录失败：{e}"))?;

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
        let msg = format_mihomo_error_for_user(&format!("启动隔离对比测速核心失败：{e}"));
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
        .or(relay.last_mbps);
    if recorded_relay_ms.is_some() || recorded_up_mbps.is_some() {
        if let Ok(db) = state.storage.lock() {
            let _ = db.update_preaccel_probe_metrics(
                &relay.id,
                recorded_relay_ms,
                recorded_up_mbps,
            );
        }
    }

    let up_boost_ratio = calc_boost_ratio(accelerated.up_mbps, direct.up_mbps);
    let down_boost_ratio = calc_boost_ratio(accelerated.down_mbps, direct.down_mbps);

    let overall_ok = accelerated.ok || direct.ok;
    let log_level = if accelerated.ok && direct.ok && accelerated.error.is_none() && direct.error.is_none() {
        "info"
    } else {
        "warning"
    };
    let relay_rtt_text = relay_real_rtt_ms
        .map(|v| format!("{v:.1}ms"))
        .unwrap_or_else(|| "--".to_string());
    state.log_app_event(
        log_level,
        "对比测速",
        &format!(
            "对比测速完成：中转「{}」(真实RTT={relay_rtt_text}) / 节点「{}」| 提速边[{}] | 直连边[{}] | 上行倍率={:?} 下行倍率={:?}",
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

#[tauri::command]
pub fn list_agent_docs() -> Vec<catcloud_core::agent_docs::AgentModuleDoc> {
    catcloud_core::agent_docs::list_agent_docs()
}

#[tauri::command]
pub fn export_agent_docs(module_id: String, as_json: bool) -> Result<String, String> {
    catcloud_core::agent_docs::export_agent_docs(&module_id, as_json).map_err(|e| e.to_string())
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
    evaluate_group_candidates(&group, &nodes, &snaps).map_err(|e| e.to_string())
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
    ensure_default_group_if_empty(&state);
    let _ = trigger_reload_if_running(&app, &state, false).await;
    let cfg = state.snapshot_config();
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

fn collect_sanitized_recent_logs(state: &AppState, limit: usize) -> Vec<String> {
    if limit == 0 {
        return Vec::new();
    }
    let disk_lines = state.app_logger.read_recent_lines(limit);
    let mem_logs = state.telemetry.logs_snapshot();
    merge_sanitized_recent_logs(disk_lines, mem_logs, limit)
}

fn format_geodata_brief(geodata: &serde_json::Value) -> String {
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
            format!("{label}: 已就绪 ({})", format_bytes_human(size))
        } else {
            format!("{label}: 缺失")
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

#[allow(clippy::too_many_arguments)]
fn build_ai_diagnostics_markdown(
    app_version: &str,
    os_label: &str,
    is_elevated: bool,
    is_portable: bool,
    cfg: &AppConfig,
    rt: &CoreRuntimeStatus,
    runtime_dto: Option<&CoreRuntimeInfoDto>,
    counts: (usize, usize, usize, usize),
    conn_summary: ConnectionSummaryCounts,
    core_mem_bytes: u64,
    geodata_status: &serde_json::Value,
    last_error: Option<&str>,
    recent_logs: &[String],
) -> String {
    let (sub_count, node_count, group_count, relay_count) = counts;
    let route_mode = runtime_dto
        .map(|d| d.route_mode.as_str())
        .unwrap_or_else(|| cfg.route_mode.as_str());
    let active_group_name = runtime_dto
        .map(|d| d.active_group_name.as_str())
        .unwrap_or("默认路线");
    let active_node_name = runtime_dto
        .map(|d| d.active_node_name.as_str())
        .unwrap_or("未选择");
    let active_node_region = runtime_dto
        .map(|d| d.active_node_region.as_str())
        .unwrap_or("--");
    let preaccel_relay_name = runtime_dto
        .and_then(|d| d.preaccel_relay_name.as_deref())
        .unwrap_or("未配置");
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
    let last_err_text = last_error.unwrap_or("无");

    let logs_block = if recent_logs.is_empty() {
        "（暂无运行日志记录）".to_string()
    } else {
        recent_logs.join("\n")
    };
    let cli_fence_lang = if cfg!(target_os = "windows") || os_label.starts_with("windows") {
        "powershell"
    } else {
        "bash"
    };

    format!(
        "请帮我排查猫猫云梯（CatCloud）当前问题。\n\
\n\
> 以下诊断包已自动完成隐私脱敏（订阅凭据、密码、Token、Secret 与公网 IP 末段均已隐藏），请先基于状态与日志定位根因并给出清晰步骤。\n\
\n\
## 1. 运行状态摘要\n\
\n\
| 项目 | 当前状态 |\n\
| --- | --- |\n\
| 应用版本 / 环境 | CatCloud v{app_version} · {os_label} · 管理员权限：{} · 便携模式：{} |\n\
| 代理核心 | {}（Mihomo {core_version}，内核内存：{core_mem_text}） |\n\
| 代理模式 / 路由方式 | `{}` / `{route_mode}` |\n\
| 当前路线组 / 节点 | 分组「{active_group_name}」 → 节点「{active_node_name}」（地区：{active_node_region}） |\n\
| 本地端口 | 混合端口 `{mixed_port}` / 控制端口 `{controller_port}` / DNS `{dns_port}` |\n\
| 流量接管 | 系统代理：{} · 虚拟网卡（TUN）：{}（协议栈 `{}`） |\n\
| 内存档位 | `{}`（GOGC={}） |\n\
| 最近异常 | {last_err_text} |\n\
\n\
## 2. 分流与加速配置要点\n\
\n\
- 国内直连规则：{} ｜ 阻断 QUIC（UDP/443）：{}\n\
- 国内 443 预加速：{}（当前中转：{preaccel_relay_name}，跳过 443 原生节点：{}）\n\
- IPv6 开关：核心数据面 {} ｜ DNS 解析 {}\n\
- GeoData 状态：{}\n\
- 本地资产统计：订阅 {sub_count} 个 · 节点 {node_count} 个 · 智能多选组 {group_count} 个 · 国内中转 {relay_count} 个\n\
\n\
## 3. 当前连接分布\n\
\n\
- 真实应用连接：{} 条（直连 {} 条 · 代理 {} 条）\n\
- 底层提速隧道（`Inner`）：{} 条（已从应用连接数中排除）\n\
\n\
## 4. 最近脱敏运行日志（最近 {} 条）\n\
\n\
```text\n\
{logs_block}\n\
```\n\
\n\
## 5. 本机只读 `catcloud` CLI 进一步排查指引\n\
\n\
如果你可以直接在本机终端执行命令，请**优先使用以下只读命令**补充信息（修改配置前请先征得我同意）：\n\
\n\
```{cli_fence_lang}\n\
catcloud status --json\n\
catcloud config diag --json\n\
catcloud config validate --json\n\
catcloud group list --json\n\
catcloud node list --json\n\
catcloud preaccel pool --json\n\
catcloud docs export network_reload --format json\n\
```\n",
        if is_elevated { "是" } else { "否" },
        if is_portable { "是" } else { "否" },
        if rt.running { "运行中" } else { "已停止" },
        cfg.proxy_mode.as_str(),
        if cfg.system_proxy.enabled {
            "已开启"
        } else {
            "关闭"
        },
        if cfg.tun.enabled { "已开启" } else { "关闭" },
        cfg.tun.stack_mode.as_str(),
        format_memory_tier_label(&cfg.core_runtime.memory_tier),
        cfg.core_runtime.gogc,
        if cfg.rules_override.domestic_direct_enabled {
            "开启"
        } else {
            "关闭"
        },
        if cfg.rules_override.block_quic_udp_443 {
            "开启"
        } else {
            "关闭"
        },
        if cfg.preaccel.enabled {
            "已开启"
        } else {
            "关闭"
        },
        if cfg.preaccel.skip_443_native {
            "是"
        } else {
            "否"
        },
        if cfg.core_ipv6 { "开启" } else { "关闭" },
        if cfg.dns.ipv6 { "开启" } else { "关闭" },
        format_geodata_brief(geodata_status),
        conn_summary.app_connections,
        conn_summary.direct_connections,
        conn_summary.proxied_connections,
        conn_summary.tunnel_connections,
        recent_logs.len(),
    )
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
    let recent_logs = match preloaded_disk_logs {
        Some(disk_lines) => {
            let mem_logs = state.telemetry.logs_snapshot();
            merge_sanitized_recent_logs(disk_lines, mem_logs, 60)
        }
        None => collect_sanitized_recent_logs(state, 60),
    };

    let route_mode = runtime_dto
        .as_ref()
        .map(|d| d.route_mode.clone())
        .unwrap_or_else(|| cfg.route_mode.as_str().to_string());
    let active_group_name = runtime_dto
        .as_ref()
        .map(|d| d.active_group_name.clone())
        .unwrap_or_else(|| "默认路线".to_string());
    let active_node_name = runtime_dto
        .as_ref()
        .map(|d| d.active_node_name.clone())
        .unwrap_or_else(|| "待导入节点".to_string());
    let active_node_region = runtime_dto
        .as_ref()
        .map(|d| d.active_node_region.clone())
        .unwrap_or_else(|| "--".to_string());
    let preaccel_relay_name = runtime_dto
        .as_ref()
        .and_then(|d| d.preaccel_relay_name.clone());

    let os_label = format!("{} {}", caps.os, caps.arch);
    let ai_prompt_markdown = build_ai_diagnostics_markdown(
        env!("CARGO_PKG_VERSION"),
        &os_label,
        caps.is_elevated,
        state.paths.is_portable,
        &cfg,
        &rt,
        runtime_dto.as_ref(),
        (sub_count, node_count, group_count, relay_count),
        conn_summary,
        core_mem_bytes,
        &geodata_status,
        last_error.as_deref(),
        &recent_logs,
    );

    Ok(serde_json::json!({
        "app_version": env!("CARGO_PKG_VERSION"),
        "os": caps.os,
        "arch": caps.arch,
        "is_elevated": caps.is_elevated,
        "is_portable": state.paths.is_portable,
        "instance_hash": state.paths.instance_hash,
        "core_running": rt.running,
        "core_version": rt.version,
        "proxy_mode": cfg.proxy_mode,
        "mixed_port": if rt.running { rt.mixed_port } else { cfg.mixed_port },
        "controller_port": if rt.running { rt.controller_port } else { cfg.controller_port },
        "dns_listen_port": if rt.running { rt.dns_listen_port } else { cfg.dns_listen_port },
        "core_ipv6": cfg.core_ipv6,
        "dns_ipv6": cfg.dns.ipv6,
        "tun_enabled": cfg.tun.enabled,
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
            "tun_enabled": cfg.tun.enabled,
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
    let disk_logs = tokio::task::spawn_blocking(move || logger.read_recent_lines(60))
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
        "country_mmdb": inspect_geodata_file(runtime_dir, &["Country.mmdb", "country.mmdb", "country-lite.mmdb"]),
        "geoip_dat": inspect_geodata_file(runtime_dir, &["geoip.dat", "GeoIP.dat"]),
        "geosite_dat": inspect_geodata_file(runtime_dir, &["geosite.dat", "GeoSite.dat"]),
        "asn_mmdb": inspect_geodata_file(runtime_dir, &["GeoLite2-ASN.mmdb", "geolite2-asn.mmdb", "asn.mmdb"]),
    })
}

#[tauri::command]
pub fn get_geodata_status(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    Ok(collect_geodata_status(&state.paths.runtime_dir))
}

#[tauri::command]
pub async fn refresh_geo_db(
    state: State<'_, AppState>,
    targets: Option<Vec<String>>,
) -> Result<serde_json::Value, String> {
    let updated_targets = targets.unwrap_or_else(|| {
        vec![
            "geoip".to_string(),
            "geosite".to_string(),
            "mmdb".to_string(),
            "asn".to_string(),
        ]
    });
    if !state.adapter.has_live_controller().await {
        return Err("代理核心尚未运行，请先启动核心再更新地理数据库".to_string());
    }
    let rt = state.adapter.status().await;
    let secret = state.adapter.controller_secret().await;
    let url = format!(
        "http://{}:{}/configs/geo",
        if rt.controller_host == "0.0.0.0" {
            "127.0.0.1"
        } else {
            rt.controller_host.as_str()
        },
        rt.controller_port
    );
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| format!("初始化地理数据库更新客户端失败：{e}"))?;
    let resp = client
        .post(&url)
        .bearer_auth(&secret)
        .send()
        .await
        .map_err(|e| format!("请求地理数据库更新失败：{e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "地理数据库更新请求失败（HTTP {}）",
            resp.status().as_u16()
        ));
    }
    Ok(serde_json::json!({
        "ok": true,
        "updated_targets": updated_targets,
        "message": "地理数据库已通过核心更新完成"
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

    let _ = trigger_reload_if_running(&app, &state, true).await;
    let cfg = state.snapshot_config();
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
    let mut cfg = state.snapshot_config();
    cfg.core_runtime.custom_binary_path = Some(candidate.display().to_string());
    config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
    if let Ok(mut guard) = state.config.write() {
        *guard = cfg.clone();
    }
    let version = if state.adapter.has_live_controller().await {
        let rt = restart_core(app, state).await?;
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
        assert!(!is_proxy_takeover_active(false, &cfg));
        assert!(!is_proxy_takeover_active(true, &cfg));

        // System proxy enabled -> active only while core is running.
        cfg.system_proxy.enabled = true;
        assert!(!is_proxy_takeover_active(false, &cfg));
        assert!(is_proxy_takeover_active(true, &cfg));

        // TUN enabled -> active only while core is running.
        cfg.system_proxy.enabled = false;
        cfg.tun.enabled = true;
        assert!(!is_proxy_takeover_active(false, &cfg));
        assert!(is_proxy_takeover_active(true, &cfg));

        // Both enabled -> active while core is running.
        cfg.system_proxy.enabled = true;
        assert!(is_proxy_takeover_active(true, &cfg));
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

        // 3. Core running with system proxy enabled & preaccel.enabled == true ->
        //    proxy_active is true, preaccel_active is true, status == "preaccel", tray == PreAccel.
        if let Ok(mut guard) = state.config.write() {
            guard.system_proxy.enabled = true;
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
        cfg.preaccel.global_target_processes = vec!["FlClashCore.exe".to_string()];
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
            Some(vec!["FlClashCore.exe".to_string()])
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
            vec!["FlClashCore.exe".to_string()]
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
                sub_id: "preview_clash_verge".to_string(),
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
                sub_id: "preview_clash_verge".to_string(),
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
                sub_id: "preview_clash_verge".to_string(),
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
}
