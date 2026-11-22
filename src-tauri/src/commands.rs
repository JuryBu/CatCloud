use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use catcloud_core::config;
use catcloud_core::core_adapter::binary_resolver::{
    compute_file_sha256, mihomo_binary_name, resolve_mihomo_binary,
};
use catcloud_core::core_adapter::config_compiler::{
    CompileInput, CompileStats, StaticValidationReport, compile_mihomo_config,
};
use catcloud_core::core_adapter::hot_reload::{DiskReloadOptions, HotReloadCoordinator};
use catcloud_core::core_adapter::mihomo::{
    MihomoAdapter, generate_controller_secret, verify_config_with_binary,
};
use catcloud_core::core_adapter::port_guard::{AllocatedPorts, allocate_safe_ports};
use catcloud_core::core_adapter::stream_client::{
    CoreTelemetryStore, MihomoStreamClient, StreamSessionHandle,
};
use catcloud_core::core_adapter::{
    ConnectionsSnapshot, CoreAdapter, CoreLogLine, CoreRuntimeStatus, CoreStartRequest,
    ReloadOutcome,
};
use catcloud_core::models::{
    AppConfig, MemoryLimitTier, MultiGroup, PersonalizationConfig, PreAccelConfig, PreAccelRelay,
    ProbeDefinition, ProbeSnapshot, ProxyMode, ProxyNode, SubscriptionKind, SubscriptionRecord,
    SwitchMode, ThemeDaySchedule, ThemeMode, TrayIconMode, TunStackMode, UpdateApplyMode,
    UpdateConfig,
};
use catcloud_core::platform::default_platform;
use catcloud_core::preaccel::campus::{
    CampusBypassTracker, CampusPortalState, probe_campus_portal_with_fallback,
};
use catcloud_core::probe::{
    FunnelOptions, IsolatedProbeCore, ProbeRegistry, run_funnel_for_node,
};
use catcloud_core::process_guard::JobGuard;
use catcloud_core::storage::Storage;
use catcloud_core::strategy::evaluator::evaluate_group_candidates;
use catcloud_core::subscription::{
    FetchOptions, apply_parsed_subscription, fetch_and_parse_subscription_with_options,
    inspect_process_source as core_inspect_process_source, parse_subscription_payload,
    preview_from_text as core_preview_from_text,
};
use catcloud_core::updater::Updater;
use catcloud_core::AppPaths;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::net::TcpStream;

use crate::lifecycle;
use crate::tray::{
    self, TrayGroupSummary, TrayHealthState, TrayMenuState, TrayNodeCandidate,
    TrayPreAccelRelayItem, TrayPreAccelSummary, TrayProxyMode, TraySubscriptionItem,
    TraySubscriptionSummary, TrayVisualState,
};

pub const EVENT_TRAFFIC: &str = "catcloud://traffic";
pub const EVENT_RUNTIME: &str = "catcloud://runtime";
pub const EVENT_CORE_LOG: &str = "catcloud://core-log";

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
            started_at: Instant::now(),
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

    let mut group_summaries: Vec<TrayGroupSummary> = Vec::new();
    for g in groups.iter().take(6) {
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
        let g = groups.first()?;
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
            Some("国内 443 预加速已启用".to_string())
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
        let primary_group = groups.first();
        let active_node = primary_group
            .and_then(|g| g.active_node_id.as_deref())
            .and_then(|id| nodes.iter().find(|n| n.id == id))
            .or_else(|| nodes.first());
        let snap = active_node.and_then(|n| {
            db.get_probe_snapshot(&n.id, primary_group.and_then(|g| g.primary_probe_id.as_deref()))
                .ok()
                .flatten()
        });
        (groups, nodes, relays, snap)
    };

    let primary_group = groups.first();
    let active_node = primary_group
        .and_then(|g| g.active_node_id.as_deref())
        .and_then(|id| nodes.iter().find(|n| n.id == id))
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
            .unwrap_or_else(|| "默认多选组".to_string()),
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

fn sync_app_side_effects(app: &AppHandle, state: &AppState, cfg: &AppConfig) {
    if let Some(win_state) = app.try_state::<lifecycle::WindowLifecycleState>() {
        win_state.set_destroy_on_close(cfg.behavior.minimize_to_tray_on_close);
    }
    let _ = tray::sync_tray_menu(app, &build_tray_menu_state(app, state));
    let _ = tray::sync_tray_visual(app, &build_tray_visual_state(state));
    emit_runtime_snapshot(app, state);
}

fn sync_autostart_if_changed(old_autostart: bool, cfg: &AppConfig) {
    if old_autostart == cfg.behavior.autostart {
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

/// Start the managed Mihomo core subprocess (if not running) and attach background telemetry streams.
pub async fn start_core_internal(app: &AppHandle, state: &AppState) -> Result<CoreRuntimeInfoDto, String> {
    let cfg = state.snapshot_config();
    let extra_candidates = state.extra_binary_candidates();
    let resolution = resolve_mihomo_binary(&cfg, &state.paths, &extra_candidates, false)
        .map_err(|e| e.to_string())?;
    let binary_path = resolution.path.ok_or_else(|| {
        "mihomo core binary not found; please place mihomo in bin/ or configure custom_binary_path"
            .to_string()
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
    .map_err(|e| e.to_string())?;

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
    let compiled = compile_mihomo_config(&input).map_err(|e| e.to_string())?;
    if !compiled.validation.ok {
        let summary = compiled
            .validation
            .issues
            .iter()
            .map(|i| i.message.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!("compiled config failed static validation: {summary}"));
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
            e.to_string()
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
        .map_err(|e| e.to_string())?;

    state
        .hot_reload
        .seed_active_state(cfg.clone(), compiled.sha256, allocated.clone(), secret.clone())
        .await;
    state.update_cached_runtime(status.clone());

    // Attach bounded background telemetry streams (`/traffic`, `/memory`, `/logs`).
    state.stop_streams();
    if let Ok(stream_client) =
        MihomoStreamClient::new(&status.controller_host, status.controller_port, &secret)
    {
        let session = stream_client
            .spawn_background_streams(cfg.log_level.clone(), Arc::clone(&state.telemetry));
        if let Ok(mut guard) = state.stream_session.lock() {
            *guard = Some(session);
        }
    }

    sync_app_side_effects(app, state, &cfg);
    build_runtime_info_dto(state)
}

/// Stop managed core and background telemetry streams cleanly.
pub async fn stop_core_internal(app: &AppHandle, state: &AppState) -> Result<CoreRuntimeInfoDto, String> {
    state.stop_streams();
    state.adapter.stop().await.map_err(|e| e.to_string())?;
    let status = state.adapter.status().await;
    state.update_cached_runtime(status);
    if let Ok(mut m) = state.cached_metrics.write() {
        *m = CachedRealtimeMetrics::default();
    }
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
    state.update_cached_runtime(status);
    let cfg = state.snapshot_config();
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
                return Err(o
                    .error
                    .unwrap_or_else(|| "disk config pre-flight reload rejected".to_string()));
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
    let (group, nodes, snaps) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let nodes = db.list_nodes().map_err(|e| e.to_string())?;
        if nodes.is_empty() {
            return Err("no nodes available in storage".to_string());
        }
        let requested_id = group_id.trim();
        let found_group = if !requested_id.is_empty() && requested_id != "default" {
            db.get_multi_group(requested_id).map_err(|e| e.to_string())?
        } else {
            db.get_multi_group("default")
                .map_err(|e| e.to_string())?
                .or_else(|| db.list_multi_groups().ok().and_then(|mut v| v.drain(..).next()))
        };
        let Some(group) = found_group else {
            return Err("no configured multi-group available to switch".to_string());
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

    group.active_node_id = Some(target_node.id.clone());
    {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        db.upsert_multi_group(&group).map_err(|e| e.to_string())?;
    }

    let mut closed_connections = 0usize;
    if state.adapter.has_live_controller().await {
        let _ = state
            .adapter
            .select_group_proxy(&group.name, &target_node.name)
            .await;
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
    sync_autostart_if_changed(old.behavior.autostart, &cfg);
    if old.system_proxy.enabled != cfg.system_proxy.enabled {
        let spec = cfg.system_proxy.to_platform_spec("127.0.0.1", cfg.mixed_port);
        let _ = default_platform().apply_system_proxy(&spec);
    }
    let _ = trigger_reload_if_running(&app, &state, false).await;
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
    sync_autostart_if_changed(old.behavior.autostart, &next);
    let _ = trigger_reload_if_running(&app, &state, false).await;
    sync_app_side_effects(&app, &state, &next);
    Ok(next)
}

fn json_deep_merge(target: &mut serde_json::Value, patch: &serde_json::Value) {
    match (target, patch) {
        (serde_json::Value::Object(t_map), serde_json::Value::Object(p_map)) => {
            for (k, v) in p_map {
                if let Some(existing) = t_map.get_mut(k) {
                    json_deep_merge(existing, v);
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
    sync_autostart_if_changed(old.behavior.autostart, &next);
    let _ = trigger_reload_if_running(&app, &state, false).await;
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
    if let Some(outcome) = trigger_reload_if_running(&app, &state, force).await {
        return Ok(outcome);
    }
    // Core is stopped: still validate & compile candidate YAML so agents get real pre-flight feedback.
    let outcome = state
        .hot_reload
        .apply_disk_reload(DiskReloadOptions {
            force,
            verify_with_binary: true,
            allow_l3_restart: false,
            ..DiskReloadOptions::default()
        })
        .await;
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
    let deleted = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        db.delete_multi_group(&group_id).map_err(|e| e.to_string())?
    };
    if deleted {
        let _ = trigger_reload_if_running(&app, &state, false).await;
        let cfg = state.snapshot_config();
        sync_app_side_effects(&app, &state, &cfg);
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

#[tauri::command]
pub async fn run_isolated_probes(
    state: State<'_, AppState>,
    node_ids: Vec<String>,
    probe_ids: Vec<String>,
) -> Result<serde_json::Value, String> {
    let cfg = state.snapshot_config();
    let extra_candidates = state.extra_binary_candidates();
    let resolution = resolve_mihomo_binary(&cfg, &state.paths, &extra_candidates, false)
        .map_err(|e| e.to_string())?;
    let Some(mihomo_bin) = resolution.path else {
        return Err("mihomo binary not found for isolated probing".to_string());
    };

    let (target_nodes, probe_defs) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let all_nodes = db.list_nodes().map_err(|e| e.to_string())?;
        let target_nodes: Vec<ProxyNode> = if node_ids.is_empty() {
            all_nodes.into_iter().filter(|n| n.enabled).take(24).collect()
        } else {
            all_nodes
                .into_iter()
                .filter(|n| node_ids.contains(&n.id))
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
        (target_nodes, selected_defs)
    };

    if target_nodes.is_empty() {
        return Err("no target nodes selected for probing".to_string());
    }
    if probe_defs.is_empty() {
        return Err("no probe definitions available".to_string());
    }

    let mut registry = ProbeRegistry::new();
    for def in probe_defs {
        registry.register(def).map_err(|e| e.to_string())?;
    }

    let temp_root = state.paths.runtime_dir.join("probe_sandbox");
    std::fs::create_dir_all(&temp_root).map_err(|e| e.to_string())?;

    let probe_core =
        IsolatedProbeCore::spawn(&mihomo_bin, &temp_root, &state.job_guard, &target_nodes)
            .await
            .map_err(|e| e.to_string())?;

    let options = FunnelOptions::default();
    let mut all_records = Vec::new();
    let mut snapshots: HashMap<String, ProbeSnapshot> = HashMap::new();
    let mut errors: Vec<String> = Vec::new();

    for node in &target_nodes {
        let Some(port) = probe_core.port_for_node(&node.id) else {
            continue;
        };
        match run_funnel_for_node(
            &registry,
            &node.id,
            port,
            &options,
            Some(&state.job_guard),
            None,
        )
        .await
        {
            Ok(report) => {
                all_records.extend(report.records);
                snapshots.insert(node.id.clone(), report.snapshot);
            }
            Err(err) => {
                errors.push(format!("{}: {err}", node.name));
            }
        }
    }

    let _ = probe_core.shutdown().await;

    if !all_records.is_empty() {
        let mut db = state.storage.lock().map_err(|e| e.to_string())?;
        let _ = db.insert_probe_results_batch(&all_records);
    }

    Ok(serde_json::json!({
        "probed_count": snapshots.len(),
        "snapshots": snapshots,
        "errors": errors,
        "core_available": true
    }))
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
            let raw = std::fs::read(&sub.url_or_cmd).map_err(|e| e.to_string())?;
            parse_subscription_payload(&sub.id, &raw, None).map_err(|e| e.to_string())?
        }
        SubscriptionKind::ProcessAdapter => {
            return Err("process adapter subscriptions refresh via external adapter command".to_string());
        }
    };

    let node_count = {
        let mut db = state.storage.lock().map_err(|e| e.to_string())?;
        apply_parsed_subscription(&mut db, sub, &parsed).map_err(|e| e.to_string())?
    };
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

    let google_clean = state.storage.lock().ok().and_then(|db| {
        let groups = db.list_multi_groups().ok()?;
        let active_id = groups.first()?.active_node_id.as_deref()?;
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
                    "Cloudflare Trace".to_string()
                } else {
                    format!("Edge {colo}")
                },
                location: if loc.is_empty() {
                    "Unknown".to_string()
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
            isp: format!("HTTP {}", resp.status().as_u16()),
            location: "探测失败".to_string(),
            timezone: "UTC+8".to_string(),
            google_clean,
            core_running: true,
        }),
        Err(err) => Ok(ExitIpInfoDto {
            ip_masked: "--.--.--.***".to_string(),
            ip_raw: None,
            isp: format!("探测超时/不可达 ({})", err.is_timeout()),
            location: "探测失败".to_string(),
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
    Ok(CompiledYamlPreviewDto {
        yaml: compiled.yaml,
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
    let cfg = state.snapshot_config();
    let (groups, relays, probes) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        (
            db.list_multi_groups().map_err(|e| e.to_string())?,
            db.list_preaccel_relays(false).map_err(|e| e.to_string())?,
            db.list_probe_definitions().map_err(|e| e.to_string())?,
        )
    };
    let exported_at = Utc::now().to_rfc3339();
    let bundle = serde_json::json!({
        "schema": "catcloud-backup/v1",
        "exported_at": exported_at,
        "app_version": env!("CARGO_PKG_VERSION"),
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
            "message": format!("CheckNetIsolation inspected ({exempt_count} UWP loopback exemptions)")
        }))
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(serde_json::json!({
            "supported": false,
            "launched": false,
            "message": "UWP Loopback exemption is Windows-only"
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
}
