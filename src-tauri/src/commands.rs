use std::collections::{BTreeMap, HashMap};
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
    CompileInput, CompileStats, StaticValidationReport, compile_mihomo_config,
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
    ReloadLevel, ReloadOutcome,
};
use catcloud_core::models::{
    AppConfig, CoreLogLevel, MemoryLimitTier, MultiGroup, MultiGroupMode, PersonalizationConfig,
    PreAccelConfig, PreAccelRelay, ProbeDefinition, ProbeSnapshot, ProxyMode, ProxyNode,
    SubscriptionKind, SubscriptionRecord, SwitchMode, ThemeDaySchedule, ThemeMode,
    TrayClickAction as CoreTrayClickAction, TrayIconMode, TunStackMode, UpdateApplyMode,
    UpdateConfig,
};
use catcloud_core::platform::default_platform;
use catcloud_core::preaccel::campus::{
    CampusBypassTracker, CampusPortalState, probe_campus_portal_with_fallback,
};
use catcloud_core::probe::{
    DEFAULT_READY_TIMEOUT, FunnelOptions, FunnelTier, IsolatedProbeCore, ProbeRegistry,
    ThroughputProbeConfig, build_isolated_http_client, run_download_probe_with_config,
    run_funnel_for_node, run_latency_probe, run_upload_probe_with_config,
};
use catcloud_core::process_guard::JobGuard;
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
use tokio::net::TcpStream;

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

/// Shared backend state managed by Tauri across commands, tray callbacks, streams, and shortcuts.
pub struct AppState {
    pub paths: AppPaths,
    pub config: RwLock<AppConfig>,
    pub storage: Mutex<Storage>,
    pub job_guard: Arc<JobGuard>,
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
    pub started_at: Instant,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CachedRealtimeMetrics {
    pub up_bps: u64,
    pub down_bps: u64,
    pub core_mem_bytes: u64,
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
        let hot_reload = Arc::new(HotReloadCoordinator::new(paths.clone(), Arc::clone(&adapter)));
        let telemetry = Arc::new(CoreTelemetryStore::default());
        Self {
            paths,
            config: RwLock::new(cfg),
            storage: Mutex::new(storage),
            job_guard,
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
            started_at: Instant::now(),
        }
    }

    pub fn core_session_generation(&self) -> u64 {
        self.core_session_gen.load(Ordering::SeqCst)
    }

    pub fn bump_core_session_generation(&self) -> u64 {
        self.core_session_gen
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1)
    }

    pub fn attach_streams(
        &self,
        controller_host: &str,
        controller_port: u16,
        secret: &str,
        log_level: CoreLogLevel,
    ) {
        self.stop_streams();
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
        let member_nodes: Vec<&ProxyNode> = if g.member_node_ids.is_empty() {
            nodes.iter().filter(|n| n.enabled).take(8).collect()
        } else {
            g.member_node_ids
                .iter()
                .filter_map(|id| node_by_id.get(id.as_str()).copied())
                .filter(|n| n.enabled)
                .take(8)
                .collect()
        };
        let active_label = g
            .active_node_id
            .as_deref()
            .and_then(|id| node_by_id.get(id))
            .map(|n| n.name.clone())
            .or_else(|| member_nodes.first().map(|n| n.name.clone()))
            .unwrap_or_else(|| "自动择优".to_string());
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
                    selected: g.active_node_id.as_deref() == Some(n.id.as_str()),
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
        primary_group,
        extra_groups: group_summaries,
        preaccel: TrayPreAccelSummary {
            enabled: cfg.preaccel.enabled,
            active_label: active_relay_label,
            relays: tray_relays,
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
    let health = if rt.last_error.is_some() {
        TrayHealthState::Error
    } else if portal_required {
        TrayHealthState::Warn
    } else if cfg.preaccel.enabled && rt.running {
        TrayHealthState::PreAccel
    } else if rt.running || cfg.system_proxy.enabled || cfg.tun.enabled {
        TrayHealthState::Ok
    } else {
        TrayHealthState::Idle
    };

    let primary_group_summary = state.storage.lock().ok().and_then(|db| {
        let groups = db.list_multi_groups().ok()?;
        let g = cfg
            .active_group_id
            .as_deref()
            .and_then(|gid| groups.iter().find(|g| g.id == gid))
            .or_else(|| groups.first())?;
        let node_name = g
            .active_node_id
            .as_deref()
            .and_then(|id| db.get_node(id).ok().flatten())
            .map(|n| n.name)
            .unwrap_or_else(|| "自动择优".to_string());
        Some(format!("{} -> {}", g.name, node_name))
    });

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
        preaccel_summary: if cfg.preaccel.enabled {
            Some("国内加速入口已开启".to_string())
        } else {
            None
        },
        primary_group_summary,
        realtime_speed,
    };
    TrayVisualState {
        icon_mode,
        health,
        tooltip: info.format_tooltip(),
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

    let (groups, nodes, relays, active_snap) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let groups = db.list_multi_groups().unwrap_or_default();
        let nodes = db.list_nodes().unwrap_or_default();
        let relays = db.list_preaccel_relays(true).unwrap_or_default();
        let primary_group = cfg
            .active_group_id
            .as_deref()
            .and_then(|gid| groups.iter().find(|g| g.id == gid))
            .or_else(|| groups.first());
        let active_node = primary_group
            .and_then(|g| g.active_node_id.as_deref())
            .and_then(|id| nodes.iter().find(|n| n.id == id))
            .or_else(|| {
                primary_group
                    .and_then(|g| g.member_node_ids.first())
                    .and_then(|id| nodes.iter().find(|n| n.id == *id))
            })
            .or_else(|| nodes.first());
        let snap = active_node.and_then(|n| {
            db.get_probe_snapshot(&n.id, primary_group.and_then(|g| g.primary_probe_id.as_deref()))
                .ok()
                .flatten()
        });
        (groups, nodes, relays, snap)
    };

    let primary_group = cfg
        .active_group_id
        .as_deref()
        .and_then(|gid| groups.iter().find(|g| g.id == gid))
        .or_else(|| groups.first());
    let active_node = primary_group
        .and_then(|g| g.active_node_id.as_deref())
        .and_then(|id| nodes.iter().find(|n| n.id == id))
        .or_else(|| {
            primary_group
                .and_then(|g| g.member_node_ids.first())
                .and_then(|id| nodes.iter().find(|n| n.id == *id))
        })
        .or_else(|| nodes.first());

    let active_relay_name = cfg
        .preaccel
        .active_relay_id
        .as_deref()
        .and_then(|id| relays.iter().find(|r| r.id == id))
        .or_else(|| relays.first())
        .map(|r| r.name.clone());

    let status_label = if rt.last_error.is_some() {
        "error".to_string()
    } else if portal_required {
        "warn".to_string()
    } else if rt.running && cfg.preaccel.enabled {
        "preaccel".to_string()
    } else if rt.running {
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
        active_group_id: primary_group.map(|g| g.id.clone()).unwrap_or_default(),
        active_group_name: primary_group
            .map(|g| g.name.clone())
            .unwrap_or_else(|| "默认路线".to_string()),
        active_node_id: active_node.map(|n| n.id.clone()).unwrap_or_default(),
        active_node_name: active_node
            .map(|n| n.name.clone())
            .unwrap_or_else(|| "待导入节点".to_string()),
        active_node_region: active_node
            .map(|n| n.region_code.clone())
            .unwrap_or_else(|| "--".to_string()),
        active_node_latency_ms: active_snap.as_ref().and_then(|s| s.latency_ms),
        active_node_up_mbps: active_snap.as_ref().and_then(|s| s.up_mbps),
        preaccel_active: cfg.preaccel.enabled,
        preaccel_relay_name: active_relay_name,
        captive_portal_required: portal_required,
        system_proxy_enabled: cfg.system_proxy.enabled,
        tun_enabled: cfg.tun.enabled,
        tun_admin_ready: caps.is_elevated,
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
        CoreTrayClickAction::ToggleCapsule => TrayClickAction::ToggleCapsule,
        CoreTrayClickAction::None => TrayClickAction::ShowMenu,
        _ => TrayClickAction::ToggleMain,
    }
}

fn shortcut_bindings_from_config(cfg: &AppConfig) -> ShortcutBindings {
    if !cfg.behavior.hotkeys.enabled {
        return ShortcutBindings {
            switch_next_best: None,
            toggle_capsule: None,
            toggle_main_window: None,
            toggle_system_proxy: None,
        };
    }
    ShortcutBindings {
        switch_next_best: cfg.behavior.hotkeys.switch_next_best.clone(),
        toggle_capsule: cfg.behavior.hotkeys.toggle_capsule.clone(),
        toggle_main_window: cfg.behavior.hotkeys.show_main_window.clone(),
        toggle_system_proxy: cfg.behavior.hotkeys.toggle_system_proxy.clone(),
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
            ShortcutAction::SwitchNextBestNode => {
                tauri::async_runtime::spawn(async move {
                    if let Some(st) = app_async.try_state::<AppState>() {
                        let target_group = st
                            .snapshot_config()
                            .active_group_id
                            .unwrap_or_else(|| "default".to_string());
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

fn sync_app_side_effects(app: &AppHandle, state: &AppState, cfg: &AppConfig) {
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

/// Start the managed Mihomo core subprocess (if not running) and attach background telemetry streams.
pub async fn start_core_internal(app: &AppHandle, state: &AppState) -> Result<CoreRuntimeInfoDto, String> {
    let cfg = state.snapshot_config();
    let extra_candidates = state.extra_binary_candidates();
    let resolution = resolve_mihomo_binary(&cfg, &state.paths, &extra_candidates, false)
        .map_err(|e| format!("查找代理核心失败：{e}"))?;
    let binary_path = resolution.path.ok_or_else(|| {
        "未找到 Mihomo 代理核心文件，请将内核放入 bin 目录或在设置中指定内核路径".to_string()
    })?;

    let (nodes, groups, relays) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        (
            db.list_nodes().map_err(|e| e.to_string())?,
            db.list_multi_groups().map_err(|e| e.to_string())?,
            db.list_preaccel_relays(false).map_err(|e| e.to_string())?,
        )
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
    let compiled = compile_mihomo_config(&input)
        .map_err(|e| format_mihomo_error_for_user(&format!("生成代理配置失败：{e}")))?;
    if !compiled.validation.ok {
        let summary = compiled
            .validation
            .issues
            .iter()
            .map(|i| i.message.as_str())
            .collect::<Vec<_>>()
            .join("；");
        return Err(format!("代理配置静态预检未通过：{summary}"));
    }

    let runtime_yaml = state.hot_reload.runtime_yaml_path();
    if let Some(parent) = runtime_yaml.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp_yaml = runtime_yaml.with_extension("yaml.tmp");
    std::fs::write(&tmp_yaml, compiled.yaml.as_bytes()).map_err(|e| e.to_string())?;
    verify_config_with_binary(&binary_path, &state.paths.runtime_dir, &tmp_yaml, Duration::from_secs(8))
        .await
        .map_err(|e| {
            let _ = std::fs::remove_file(&tmp_yaml);
            format_mihomo_error_for_user(&e.to_string())
        })?;
    std::fs::rename(&tmp_yaml, &runtime_yaml).map_err(|e| e.to_string())?;

    let mut active_selections = BTreeMap::new();
    for g in &groups {
        if let Some(ref node_id) = g.active_node_id {
            if let Some(node) = nodes.iter().find(|n| &n.id == node_id) {
                active_selections.insert(g.name.clone(), node.name.clone());
            }
        }
    }

    let start_req = CoreStartRequest {
        binary_path,
        working_dir: state.paths.runtime_dir.clone(),
        config_path: runtime_yaml,
        config: cfg.clone(),
        allocated_ports: allocated.clone(),
        controller_host: cfg.controller_host.clone(),
        controller_secret: secret.clone(),
        node_count: compiled.stats.total_proxies,
        rule_count: compiled.stats.total_rules,
        active_selections,
    };

    let status = state
        .adapter
        .start(start_req)
        .await
        .map_err(|e| format_mihomo_error_for_user(&format!("启动代理核心失败：{e}")))?;

    state
        .hot_reload
        .seed_active_state(cfg.clone(), compiled.sha256, allocated.clone(), secret.clone())
        .await;
    state.bump_core_session_generation();
    state.update_cached_runtime(status.clone());

    // Attach bounded background telemetry streams (`/traffic`, `/memory`, `/logs`).
    state.attach_streams(
        &status.controller_host,
        status.controller_port,
        &secret,
        cfg.log_level.clone(),
    );

    sync_app_side_effects(app, state, &cfg);
    build_runtime_info_dto(state)
}

/// Stop managed core and background telemetry streams cleanly.
pub async fn stop_core_internal(app: &AppHandle, state: &AppState) -> Result<CoreRuntimeInfoDto, String> {
    state.stop_streams();
    state.adapter.stop().await.map_err(|e| e.to_string())?;
    state.bump_core_session_generation();
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
            core_memory_mb: 0.0,
            timestamp_ms: Utc::now().timestamp_millis(),
        },
    );
    let cfg = state.snapshot_config();
    sync_app_side_effects(app, state, &cfg);
    build_runtime_info_dto(state)
}

/// Reload core configuration from disk via `HotReloadCoordinator` when running.
pub async fn trigger_reload_if_running(
    app: &AppHandle,
    state: &AppState,
    force: bool,
) -> Option<ReloadOutcome> {
    if !state.adapter.has_live_controller().await {
        return None;
    }
    let prev_status = state.adapter.status().await;
    let prev_secret = state.adapter.controller_secret().await;

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

    let endpoint_changed = prev_status.controller_host != status.controller_host
        || prev_status.controller_port != status.controller_port;
    let secret_changed = prev_secret != new_secret;
    let is_l3_restart = outcome.level == ReloadLevel::L3CoreRestart;

    if outcome.applied && status.running && (is_l3_restart || endpoint_changed || secret_changed) {
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

    sync_app_side_effects(app, state, &cfg);
    Some(outcome)
}

/// Apply system proxy state; when turning ON, reload disk config first so external Agent edits
/// take effect on a single toggle cycle.
pub async fn apply_system_proxy_internal(
    app: &AppHandle,
    state: &AppState,
    enabled: bool,
) -> Result<bool, String> {
    let mut cfg = if enabled {
        // Re-read disk config so Agent-written edits take effect immediately on toggle ON.
        let disk_cfg = config::load_or_init(&state.paths).map_err(|e| e.to_string())?;
        if let Ok(mut guard) = state.config.write() {
            *guard = disk_cfg.clone();
        }
        disk_cfg
    } else {
        state.snapshot_config()
    };

    cfg.system_proxy.enabled = enabled;
    config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
    if let Ok(mut guard) = state.config.write() {
        *guard = cfg.clone();
    }

    if enabled && state.adapter.has_live_controller().await {
        let outcome = trigger_reload_if_running(app, state, true).await;
        if let Some(o) = outcome {
            if o.rejected {
                let raw_err = o
                    .error
                    .unwrap_or_else(|| "配置预检未通过，已保持原配置运行".to_string());
                return Err(format_mihomo_error_for_user(&raw_err));
            }
        }
    }

    let effective_port = {
        let rt = state.snapshot_runtime();
        if rt.running { rt.mixed_port } else { cfg.mixed_port }
    };
    let spec = cfg.system_proxy.to_platform_spec("127.0.0.1", effective_port);
    let plat = default_platform();
    plat.apply_system_proxy(&spec).map_err(|e| e.to_string())?;

    sync_app_side_effects(app, state, &cfg);
    Ok(enabled)
}

/// Switch a multi-group to the next best formula-ranked healthy node without polluting SQLite.
pub async fn switch_next_best_internal(
    app: &AppHandle,
    state: &AppState,
    group_id: String,
) -> Result<SwitchResultDto, String> {
    let cfg = state.snapshot_config();
    let (group, nodes, snaps) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let nodes = db.list_nodes().map_err(|e| e.to_string())?;
        if nodes.is_empty() {
            return Err("暂无可用节点，请先导入订阅".to_string());
        }
        let requested_id = group_id.trim();
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

    // Rank candidates using the real strategy formula evaluator; fall back to enabled members if unprobed.
    let ranked_ids: Vec<String> = match evaluate_group_candidates(&group, &nodes, &snaps) {
        Ok(report) => {
            if !report.healthy_candidates.is_empty() {
                report
                    .healthy_candidates
                    .iter()
                    .map(|c| c.node_id.clone())
                    .collect()
            } else {
                report
                    .gate_passed
                    .iter()
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
        return Err("no enabled candidate nodes for group".to_string());
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

pub async fn select_group_node_internal(
    app: &AppHandle,
    state: &AppState,
    group_id: String,
    node_id: String,
    close_old: Option<bool>,
    prev_node_name_hint: Option<String>,
) -> Result<SwitchResultDto, String> {
    let (mut group, target_node, prev_id, prev_node_name, snap) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let group = db
            .get_multi_group(&group_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("multi-group `{group_id}` not found"))?;
        let target_node = db
            .get_node(&node_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("node `{node_id}` not found"))?;
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
    if !group.member_node_ids.iter().any(|id| id == &target_node.id) {
        group.member_node_ids.push(target_node.id.clone());
        members_changed = true;
    }
    group.active_node_id = Some(target_node.id.clone());
    {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        db.upsert_multi_group(&group).map_err(|e| e.to_string())?;
    }

    let mut closed_connections = 0usize;
    if state.adapter.has_live_controller().await {
        if members_changed {
            if let Some(outcome) = trigger_reload_if_running(app, state, true).await {
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
        state
            .adapter
            .select_group_proxy(&group.name, &target_node.name)
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
            if let Ok(closed) = state
                .adapter
                .close_connections_for_group_or_node(
                    Some(&group.name),
                    prev_node_name.as_deref(),
                )
                .await
            {
                closed_connections = closed;
            }
        }
    }

    let cfg = state.snapshot_config();
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
        let mut child = Command::new("cmd")
            .args(["/C", "clip"])
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
        }
        let _ = child.wait();
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut child = Command::new("pbcopy")
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
        }
        let _ = child.wait();
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut child = Command::new("xclip")
            .args(["-selection", "clipboard"])
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
        }
        let _ = child.wait();
        Ok(())
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

#[tauri::command]
pub async fn save_app_config(
    app: AppHandle,
    state: State<'_, AppState>,
    config: UiAppConfigDto,
) -> Result<UiAppConfigDto, String> {
    let old = state.snapshot_config();
    let mut cfg = old.clone();
    apply_ui_dto(&mut cfg, &config);
    catcloud_core::config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
    if let Ok(mut guard) = state.config.write() {
        *guard = cfg.clone();
    }
    sync_autostart_if_changed(&old, &cfg);
    if has_core_config_changes(&old, &cfg) {
        let _ = trigger_reload_if_running(&app, &state, false).await;
    }
    if old.system_proxy.enabled != cfg.system_proxy.enabled
        || (cfg.system_proxy.enabled && old.mixed_port != cfg.mixed_port)
    {
        let effective_port = {
            let rt = state.snapshot_runtime();
            if rt.running { rt.mixed_port } else { cfg.mixed_port }
        };
        let spec = cfg
            .system_proxy
            .to_platform_spec("127.0.0.1", effective_port);
        let _ = default_platform().apply_system_proxy(&spec);
    }
    sync_app_side_effects(&app, &state, &cfg);
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
    config::save(&state.paths, &next).map_err(|e| e.to_string())?;
    if let Ok(mut guard) = state.config.write() {
        *guard = next.clone();
    }
    sync_autostart_if_changed(&old, &next);
    if has_core_config_changes(&old, &next) {
        let _ = trigger_reload_if_running(&app, &state, false).await;
    }
    if old.system_proxy != next.system_proxy
        || (next.system_proxy.enabled && old.mixed_port != next.mixed_port)
    {
        let effective_port = {
            let rt = state.snapshot_runtime();
            if rt.running { rt.mixed_port } else { next.mixed_port }
        };
        let spec = next
            .system_proxy
            .to_platform_spec("127.0.0.1", effective_port);
        let _ = default_platform().apply_system_proxy(&spec);
    }
    sync_app_side_effects(&app, &state, &next);
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
    let next: AppConfig = serde_json::from_value(base_val).map_err(|e| e.to_string())?;
    config::save(&state.paths, &next).map_err(|e| e.to_string())?;
    if let Ok(mut guard) = state.config.write() {
        *guard = next.clone();
    }
    sync_autostart_if_changed(&old, &next);
    if has_core_config_changes(&old, &next) {
        let _ = trigger_reload_if_running(&app, &state, false).await;
    }
    if old.system_proxy != next.system_proxy
        || (next.system_proxy.enabled && old.mixed_port != next.mixed_port)
    {
        let effective_port = {
            let rt = state.snapshot_runtime();
            if rt.running { rt.mixed_port } else { next.mixed_port }
        };
        let spec = next
            .system_proxy
            .to_platform_spec("127.0.0.1", effective_port);
        let _ = default_platform().apply_system_proxy(&spec);
    }
    sync_app_side_effects(&app, &state, &next);
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
    let _ = stop_core_internal(&app, &state).await;
    start_core_internal(&app, &state).await
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
            outcome.error = Some(format_mihomo_error_for_user(&err));
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
    let mut cfg = state.snapshot_config();
    cfg.proxy_mode = mode.clone();
    config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
    if let Ok(mut guard) = state.config.write() {
        *guard = cfg.clone();
    }
    if state.adapter.has_live_controller().await {
        state
            .adapter
            .set_proxy_mode(mode.clone())
            .await
            .map_err(|e| e.to_string())?;
        let live = state.adapter.status().await;
        state.update_cached_runtime(live);
    }
    sync_app_side_effects(&app, &state, &cfg);
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

#[tauri::command]
pub async fn set_tun_enabled(
    app: AppHandle,
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<bool, String> {
    let mut cfg = state.snapshot_config();
    cfg.tun.enabled = enabled;
    config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
    if let Ok(mut guard) = state.config.write() {
        *guard = cfg.clone();
    }
    let _ = trigger_reload_if_running(&app, &state, false).await;
    sync_app_side_effects(&app, &state, &cfg);
    Ok(enabled)
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
        return Err("group_id cannot be empty".to_string());
    }
    {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let exists = db
            .get_multi_group(&trimmed)
            .map_err(|e| e.to_string())?
            .is_some();
        if !exists {
            return Err(format!("multi-group `{trimmed}` not found"));
        }
    }
    let mut cfg = state.snapshot_config();
    let changed = cfg.active_group_id.as_deref() != Some(trimmed.as_str());
    cfg.active_group_id = Some(trimmed);
    config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
    if let Ok(mut guard) = state.config.write() {
        *guard = cfg.clone();
    }
    if changed {
        let _ = trigger_reload_if_running(&app, &state, false).await;
    }
    sync_app_side_effects(&app, &state, &cfg);
    build_runtime_info_dto(&state)
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
    db.list_multi_groups().map_err(|e| e.to_string())
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
        .map_err(|e| format!("invalid group formula: {e}"))?;
    {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        db.upsert_multi_group(&group).map_err(|e| e.to_string())?;
    }
    let _ = trigger_reload_if_running(&app, &state, false).await;
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
    let updated = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let mut group = db
            .get_multi_group(&group_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("multi-group `{group_id}` not found"))?;
        group.member_node_ids = member_node_ids;
        db.upsert_multi_group(&group).map_err(|e| e.to_string())?;
        group
    };
    let _ = trigger_reload_if_running(&app, &state, false).await;
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
                "invalid override_mode `{other}` (expected inherit|force_on|force_off)"
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
        .map_err(|e| e.to_string())?;
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

    let (target_nodes, probe_defs) = {
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
        (target_nodes, filtered_defs)
    };

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
            res = IsolatedProbeCore::spawn(&mihomo_bin, &temp_root, &state.job_guard, chunk) => {
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
                    if !report.records.is_empty() {
                        if let Ok(mut db) = state.storage.lock() {
                            let _ = db.insert_probe_results_batch(&report.records);
                        }
                    }
                    let snap = report.snapshot;
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

    Ok(serde_json::json!({
        "probed_count": snapshots.len(),
        "total_count": total_count,
        "cancelled": cancelled,
        "snapshots": snapshots,
        "errors": errors,
        "core_available": true
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
            .ok_or_else(|| format!("subscription `{sub_id}` not found"))?
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
    sync_app_side_effects(&app, &state, &cfg);
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
        sync_app_side_effects(&app, &state, &cfg);
    }
    Ok(deleted)
}

#[tauri::command]
pub async fn toggle_preaccel(
    app: AppHandle,
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<bool, String> {
    let mut cfg = state.snapshot_config();
    cfg.preaccel.enabled = enabled;
    config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
    if let Ok(mut guard) = state.config.write() {
        *guard = cfg.clone();
    }
    let _ = trigger_reload_if_running(&app, &state, false).await;
    sync_app_side_effects(&app, &state, &cfg);
    Ok(enabled)
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
            .ok_or_else(|| format!("preaccel relay `{relay_id}` not found"))?
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
    sync_app_side_effects(&app, &state, &cfg);
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

#[tauri::command]
pub async fn test_preaccel_relays(
    state: State<'_, AppState>,
    relay_ids: Option<Vec<String>>,
) -> Result<serde_json::Value, String> {
    let relays = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let all = db.list_preaccel_relays(false).map_err(|e| e.to_string())?;
        if let Some(ids) = relay_ids {
            all.into_iter().filter(|r| ids.contains(&r.id)).collect()
        } else {
            all
        }
    };

    let mut results = Vec::new();
    for relay in relays {
        let addr = format!("{}:{}", relay.server.trim(), relay.port);
        let started = Instant::now();
        let probe_res = tokio::time::timeout(Duration::from_secs(4), TcpStream::connect(&addr)).await;
        match probe_res {
            Ok(Ok(_stream)) => {
                let ms = started.elapsed().as_secs_f64() * 1000.0;
                if let Ok(db) = state.storage.lock() {
                    let _ = db.update_preaccel_probe_metrics(&relay.id, Some(ms), relay.last_mbps);
                }
                results.push(serde_json::json!({
                    "relay_id": relay.id,
                    "ok": true,
                    "latency_ms": (ms * 10.0).round() / 10.0,
                    "error": null
                }));
            }
            Ok(Err(err)) => {
                results.push(serde_json::json!({
                    "relay_id": relay.id,
                    "ok": false,
                    "latency_ms": null,
                    "error": err.to_string()
                }));
            }
            Err(_) => {
                results.push(serde_json::json!({
                    "relay_id": relay.id,
                    "ok": false,
                    "latency_ms": null,
                    "error": "TCP connect timed out (4s)"
                }));
            }
        }
    }
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

fn select_comparison_overseas_node(
    groups: &[MultiGroup],
    nodes: &[ProxyNode],
    active_group_id: Option<&str>,
    requested_node_id: Option<&str>,
) -> Result<ProxyNode, String> {
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
        return Ok(node);
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
            if let Some(n) = nodes.iter().find(|n| &n.id == aid) {
                if seen.insert(n.id.as_str()) {
                    ordered.push(n);
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

    if let Some(n) = tcp_enabled
        .iter()
        .find(|n| !n.is_443_native && !is_info_placeholder_node(n))
    {
        return Ok((*n).clone());
    }
    if let Some(n) = tcp_enabled.iter().find(|n| !n.is_443_native) {
        return Ok((*n).clone());
    }
    if let Some(n) = tcp_enabled.iter().find(|n| !is_info_placeholder_node(n)) {
        return Ok((*n).clone());
    }
    if let Some(n) = tcp_enabled.first() {
        return Ok((*n).clone());
    }

    Err("暂无可用于对比测速的海外节点（请先导入至少 1 个已启用的非纯 UDP 海外节点）".to_string())
}

fn calc_boost_ratio(accel: Option<f64>, direct: Option<f64>) -> Option<f64> {
    let a = accel?;
    let d = direct?;
    if !a.is_finite() || !d.is_finite() || a <= 0.0 || d <= 0.01 {
        return None;
    }
    Some(((a / d) * 100.0).round() / 100.0)
}

async fn run_preaccel_comparison_side(
    proxy_port: u16,
    node_id: &str,
    label: &str,
) -> PreAccelSideSpeedDto {
    let side_fut = async {
        let client = match build_isolated_http_client(proxy_port, Duration::from_secs(6)) {
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
            timeout_ms: 2500,
            builtin: false,
        };
        let lat_rec = match tokio::time::timeout(
            Duration::from_secs(4),
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
                    error: Some(format!("{label}延迟探测超时")),
                };
            }
        };
        if !lat_rec.ok {
            return PreAccelSideSpeedDto {
                ok: false,
                latency_ms: lat_rec.latency_ms,
                up_mbps: None,
                down_mbps: None,
                error: Some(format!("{label}连通测试失败，请检查中转或海外节点是否可用")),
            };
        }

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
            timeout_ms: 4000,
            builtin: false,
        };
        let up_mbps = match tokio::time::timeout(
            Duration::from_millis(9000),
            run_upload_probe_with_config(&client, node_id, &upload_def, &tp_cfg),
        )
        .await
        {
            Ok(rec) => {
                if rec.ok {
                    rec.up_mbps
                } else {
                    rec.up_mbps.filter(|&v| v > 0.0)
                }
            }
            Err(_) => None,
        };

        let download_def = ProbeDefinition {
            id: "preaccel_cmp_download".to_string(),
            name: "Comparison Download".to_string(),
            kind: catcloud_core::models::ProbeKind::Download,
            target_url: "https://speed.cloudflare.com/__down?bytes=2097152".to_string(),
            method: "GET".to_string(),
            expected_status: Some(200),
            body_regex: None,
            payload_bytes: Some(2 * 1024 * 1024),
            timeout_ms: 3500,
            builtin: false,
        };
        let down_mbps = match tokio::time::timeout(
            Duration::from_secs(8),
            run_download_probe_with_config(&client, node_id, &download_def, &tp_cfg),
        )
        .await
        {
            Ok(rec) => {
                if rec.ok {
                    rec.down_mbps
                } else {
                    rec.down_mbps.filter(|&v| v > 0.0)
                }
            }
            Err(_) => None,
        };

        let ok = up_mbps.is_some() || down_mbps.is_some();
        let error = if ok {
            None
        } else {
            Some(format!("{label}上下行测速均超时，线路可能限速较严"))
        };

        PreAccelSideSpeedDto {
            ok,
            latency_ms: lat_rec.latency_ms,
            up_mbps,
            down_mbps,
            error,
        }
    };

    match tokio::time::timeout(Duration::from_secs(20), side_fut).await {
        Ok(res) => res,
        Err(_) => PreAccelSideSpeedDto {
            ok: false,
            latency_ms: None,
            up_mbps: None,
            down_mbps: None,
            error: Some(format!("{label}测速超过 20 秒已自动中止")),
        },
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

    let (relay, target_node) = {
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
        let target_node = select_comparison_overseas_node(
            &groups,
            &nodes,
            cfg.active_group_id.as_deref(),
            node_id.as_deref(),
        )?;
        (relay, target_node)
    };

    // Best-effort direct TCP handshake latency to the domestic relay itself.
    let relay_tcp_ms = {
        let host = relay.server.trim();
        let addr = if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]:{}", relay.port)
        } else {
            format!("{host}:{}", relay.port)
        };
        let started = Instant::now();
        match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await {
            Ok(Ok(_)) => Some((started.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0),
            _ => None,
        }
    };

    let temp_root = state.paths.runtime_dir.join("probe_sandbox");
    std::fs::create_dir_all(&temp_root).map_err(|e| format!("创建隔离测速目录失败：{e}"))?;

    let (probe_core, accel_port, direct_port) = IsolatedProbeCore::spawn_for_preaccel_comparison(
        &mihomo_bin,
        &temp_root,
        &state.job_guard,
        &relay,
        &target_node,
        &cfg.dns.proxy_server_nameserver,
        DEFAULT_READY_TIMEOUT,
    )
    .await
    .map_err(|e| format_mihomo_error_for_user(&format!("启动隔离对比测速核心失败：{e}")))?;

    // Run sequentially so accelerated and direct sides do not compete for local uplink bandwidth.
    let accelerated =
        run_preaccel_comparison_side(accel_port, &target_node.id, "国内提速通道").await;
    let direct = run_preaccel_comparison_side(direct_port, &target_node.id, "普通直连通道").await;

    let _ = probe_core.shutdown().await;

    let recorded_relay_ms = relay_tcp_ms
        .or(accelerated.latency_ms)
        .or(relay.last_probe_ms);
    let recorded_up_mbps = accelerated.up_mbps.or(relay.last_mbps);
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

    Ok(serde_json::json!({
        "ok": accelerated.ok || direct.ok,
        "relay_id": relay.id,
        "relay_name": relay.name,
        "node_id": target_node.id,
        "node_name": target_node.name,
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

#[tauri::command]
pub async fn get_exit_ip_info(state: State<'_, AppState>) -> Result<ExitIpInfoDto, String> {
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

    let proxy_url = format!("socks5h://127.0.0.1:{}", rt.mixed_port);
    let proxy = reqwest::Proxy::all(&proxy_url).map_err(|e| e.to_string())?;
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(6))
        .build()
        .map_err(|e| e.to_string())?;

    let trace_res = client
        .get("https://www.cloudflare.com/cdn-cgi/trace")
        .send()
        .await;

    let cfg = state.snapshot_config();
    let google_clean = state.storage.lock().ok().and_then(|db| {
        let groups = db.list_multi_groups().ok()?;
        let primary = cfg
            .active_group_id
            .as_deref()
            .and_then(|gid| groups.iter().find(|g| g.id == gid))
            .or_else(|| groups.first())?;
        let active_id = primary.active_node_id.as_deref()?;
        db.get_probe_snapshot(active_id, None)
            .ok()
            .flatten()
            .and_then(|s| s.google_clean)
    });

    match trace_res {
        Ok(resp) if resp.status().is_success() => {
            let body = resp.text().await.unwrap_or_default();
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
            let masked = if ip.is_empty() {
                "--.--.--.***".to_string()
            } else {
                mask_ip_address(&ip)
            };
            Ok(ExitIpInfoDto {
                ip_masked: masked,
                ip_raw: if ip.is_empty() { None } else { Some(ip) },
                isp: if colo.is_empty() {
                    "网络出口已连通".to_string()
                } else {
                    format!("接入节点 {colo}")
                },
                location: if loc.is_empty() {
                    "未知地区".to_string()
                } else {
                    loc
                },
                timezone: "UTC+8".to_string(),
                google_clean,
                core_running: true,
            })
        }
        Ok(resp) => Ok(ExitIpInfoDto {
            ip_masked: "--.--.--.***".to_string(),
            ip_raw: None,
            isp: format!("出口检测响应异常（HTTP {}）", resp.status().as_u16()),
            location: "暂未获取到位置".to_string(),
            timezone: "UTC+8".to_string(),
            google_clean,
            core_running: true,
        }),
        Err(err) => Ok(ExitIpInfoDto {
            ip_masked: "--.--.--.***".to_string(),
            ip_raw: None,
            isp: if err.is_timeout() {
                "出口检测超时，请检查当前路线是否可用".to_string()
            } else {
                "无法连接出口检测服务，请切换路线后重试".to_string()
            },
            location: "暂未获取到位置".to_string(),
            timezone: "UTC+8".to_string(),
            google_clean,
            core_running: true,
        }),
    }
}

#[tauri::command]
pub async fn check_quick_sites(state: State<'_, AppState>) -> Result<Vec<SiteCheckItemDto>, String> {
    let cfg = state.snapshot_config();
    let rt = state.adapter.status().await;
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none());
    if rt.running {
        let proxy_url = format!("socks5h://127.0.0.1:{}", rt.mixed_port);
        if let Ok(proxy) = reqwest::Proxy::all(&proxy_url) {
            builder = builder.proxy(proxy);
        }
    } else {
        builder = builder.no_proxy();
    }
    let client = builder.build().map_err(|e| e.to_string())?;

    let mut handles = Vec::new();
    for site in cfg.core_runtime.quick_check_sites {
        let cli = client.clone();
        handles.push(tokio::spawn(async move {
            let started = Instant::now();
            match cli.get(&site.url).send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let ok = site
                        .expected_status
                        .map(|exp| status == exp || (200..400).contains(&status))
                        .unwrap_or((200..400).contains(&status));
                    SiteCheckItemDto {
                        id: site.id,
                        name: site.name,
                        url: site.url,
                        latency_ms: Some(started.elapsed().as_millis() as u64),
                        ok: Some(ok),
                    }
                }
                Err(_) => SiteCheckItemDto {
                    id: site.id,
                    name: site.name,
                    url: site.url,
                    latency_ms: None,
                    ok: Some(false),
                },
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
        return Err("core controller is not running".to_string());
    }
    state
        .adapter
        .close_connection(&id)
        .await
        .map_err(|e| e.to_string())?;
    Ok(true)
}

#[tauri::command]
pub async fn close_group_connections(
    state: State<'_, AppState>,
    group_name: String,
) -> Result<usize, String> {
    if !state.adapter.has_live_controller().await {
        return Err("core controller is not running".to_string());
    }
    state
        .adapter
        .close_connections_for_group_or_node(Some(&group_name), None)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn close_all_connections(state: State<'_, AppState>) -> Result<usize, String> {
    if !state.adapter.has_live_controller().await {
        return Err("core controller is not running".to_string());
    }
    let snap = state
        .adapter
        .list_connections()
        .await
        .map_err(|e| e.to_string())?;
    let mut closed = 0usize;
    for conn in snap.connections {
        if state.adapter.close_connection(&conn.id).await.is_ok() {
            closed += 1;
        }
    }
    Ok(closed)
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
        .ok_or_else(|| format!("multi-group `{group_id}` not found"))?;
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
    let compiled = compile_mihomo_config(&input).map_err(|e| e.to_string())?;
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
    let cfg = state.snapshot_config();
    sync_app_side_effects(&app, &state, &cfg);
    Ok(bundle.relays)
}

#[tauri::command]
pub fn scan_local_migrations() -> Vec<catcloud_core::subscription::migrator::MigrationPreview> {
    catcloud_core::subscription::migrator::scan_local_clients()
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

#[tauri::command]
pub async fn apply_migration_nodes(
    app: AppHandle,
    state: State<'_, AppState>,
    source_name: String,
    mut nodes: Vec<ProxyNode>,
) -> Result<usize, String> {
    if nodes.is_empty() {
        return Err("refusing to import empty node set".to_string());
    }
    let sub_id = format!("migrated-{}", uuid::Uuid::new_v4().simple());
    for n in &mut nodes {
        n.sub_id = sub_id.clone();
    }
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
    let count = {
        let mut db = state.storage.lock().map_err(|e| e.to_string())?;
        db.upsert_subscription(&sub).map_err(|e| e.to_string())?;
        db.upsert_nodes_batch(&nodes).map_err(|e| e.to_string())?
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
        .ok_or_else(|| format!("process pid={pid} not found"))?;
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

#[tauri::command]
pub fn export_sanitized_diagnostics(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let cfg = state.snapshot_config();
    let rt = state.snapshot_runtime();
    let plat = default_platform();
    let caps = plat.capabilities();
    let (sub_count, node_count, group_count, relay_count) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        (
            db.list_subscriptions().map(|v| v.len()).unwrap_or(0),
            db.list_nodes().map(|v| v.len()).unwrap_or(0),
            db.list_multi_groups().map(|v| v.len()).unwrap_or(0),
            db.list_preaccel_relays(false).map(|v| v.len()).unwrap_or(0),
        )
    };
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
        "sanitized": true
    }))
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
        return Err("core is not running; start Mihomo core before refreshing GeoData".to_string());
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
        .map_err(|e| e.to_string())?;
    let resp = client
        .post(&url)
        .bearer_auth(&secret)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!(
            "Mihomo /configs/geo returned HTTP {}",
            resp.status().as_u16()
        ));
    }
    Ok(serde_json::json!({
        "ok": true,
        "updated_targets": updated_targets,
        "message": "GeoData updated via Mihomo controller"
    }))
}

#[tauri::command]
pub async fn check_app_update(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let mut cfg = state.snapshot_config();
    let current = env!("CARGO_PKG_VERSION").to_string();
    let checked_at = Utc::now().to_rfc3339();
    let updater = Updater::new(cfg.update.repo.clone(), current.clone())
        .map_err(|e| e.to_string())?;
    match updater.check_latest(None).await {
        Ok(res) => {
            cfg.update.last_checked_at = Some(checked_at.clone());
            let _ = config::save(&state.paths, &cfg);
            if let Ok(mut guard) = state.config.write() {
                *guard = cfg.clone();
            }
            Ok(serde_json::json!({
                "has_update": res.update_available,
                "current_version": res.current_version,
                "latest_version": res.latest_version,
                "release_url": format!("https://github.com/{}/releases/latest", cfg.update.repo.trim_matches('/')),
                "notes": res.notes,
                "checked_at": checked_at,
                "error": null
            }))
        }
        Err(err) => Ok(serde_json::json!({
            "has_update": false,
            "current_version": current,
            "latest_version": current,
            "release_url": format!("https://github.com/{}/releases/latest", cfg.update.repo.trim_matches('/')),
            "notes": "",
            "checked_at": checked_at,
            "error": err.to_string()
        })),
    }
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

#[tauri::command]
pub async fn import_backup_bundle(
    app: AppHandle,
    state: State<'_, AppState>,
    bundle_json: String,
) -> Result<serde_json::Value, String> {
    let parsed: serde_json::Value =
        serde_json::from_str(&bundle_json).map_err(|e| format!("invalid backup JSON: {e}"))?;
    let mut restored_config = false;
    let mut restored_groups = 0usize;
    let mut restored_relays = 0usize;

    if let Some(cfg_val) = parsed.get("config") {
        let next: AppConfig =
            serde_json::from_value(cfg_val.clone()).map_err(|e| e.to_string())?;
        config::save(&state.paths, &next).map_err(|e| e.to_string())?;
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
                if let Ok(r) = serde_json::from_value::<PreAccelRelay>(item.clone()) {
                    catcloud_core::preaccel::schema::validate_relay_strict(&r)
                        .map_err(|e| e.to_string())?;
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

    Ok(serde_json::json!({
        "restored_config": restored_config,
        "restored_groups": restored_groups,
        "restored_relays": restored_relays,
        "message": "Backup bundle restored"
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
        return Err(format!("binary file does not exist: {trimmed}"));
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
        "configured".to_string()
    };
    Ok(serde_json::json!({
        "ok": true,
        "version": version,
        "sha256": sha256,
        "binary_path": candidate.display().to_string(),
        "message": "Core binary updated"
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
        other => return Err(format!("unknown directory kind `{other}`")),
    };
    open_directory_in_os(path)
}

#[tauri::command]
pub fn open_web_ui(state: State<'_, AppState>, url: Option<String>) -> Result<String, String> {
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
    let secret = cfg.controller_secret.as_deref().unwrap_or("");
    let template = url
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| cfg.webui_urls.first().map(|w| w.url_template.clone()))
        .unwrap_or_else(|| {
            "https://metacubex.github.io/metacubexd/#/setup?http=true&hostname={host}&port={port}&secret={secret}".to_string()
        });
    let resolved = template
        .replace("{host}", host)
        .replace("{port}", &port.to_string())
        .replace("{secret}", secret);
    if !resolved.starts_with("https://") && !resolved.starts_with("http://") {
        return Err("WebUI URL must start with http:// or https://".to_string());
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(&resolved)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(&resolved)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(&resolved)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    Ok(resolved)
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
            "C:\\\\Users\\\\Stardust\\\\runtime.yaml.tmp test failed: rules[18] [DOMAIN-SUFFIX] error: format invalid\""
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

        let chosen = select_comparison_overseas_node(
            &[],
            &[udp_node.clone(), native_443.clone(), high_port_tcp.clone()],
            None,
            None,
        )
        .expect("should pick non-443 TCP node");
        assert_eq!(chosen.id, "n-8443");

        // Fallback to 443 TCP node when no non-443 TCP node exists
        let fallback = select_comparison_overseas_node(
            &[],
            &[udp_node.clone(), native_443.clone()],
            None,
            None,
        )
        .expect("should fallback to 443 TCP node");
        assert_eq!(fallback.id, "n-443");

        // Reject UDP-only when explicitly requested
        assert!(select_comparison_overseas_node(&[], &[udp_node], None, Some("n-hy2")).is_err());
    }
}
