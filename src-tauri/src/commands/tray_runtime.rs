use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;
#[cfg(target_os = "linux")]
use catcloud_core::core_adapter::binary_resolver::resolve_mihomo_binary;
use catcloud_core::core_adapter::config_compiler::build_preaccel_transport_diagnostics;
use catcloud_core::core_adapter::CoreAdapter;
use catcloud_core::core_adapter::DNS_TLS_STATUS_HEALTHY;
use catcloud_core::models::AppConfig;
use catcloud_core::models::MultiGroup;
use catcloud_core::models::MultiGroupState;
use catcloud_core::models::NodeSummary;
use catcloud_core::models::OverrideMode;
use catcloud_core::models::PreAccelDispatchStrategy;
use catcloud_core::models::PreAccelRelay;
use catcloud_core::models::ProxyMode;
use catcloud_core::models::ProxyNode;
use catcloud_core::models::RouteTargetMode;
use catcloud_core::models::TrayClickAction as CoreTrayClickAction;
use catcloud_core::models::TrayIconMode;
use catcloud_core::models::is_info_proxy_node;
use catcloud_core::models::is_ipv6_only_node;
use catcloud_core::platform::default_platform;
use catcloud_core::preaccel::campus::CampusPortalState;
use catcloud_core::preaccel::global_tunnel::GlobalPreAccelStatus;
use tauri::AppHandle;
use tauri::Emitter;
use tauri::Manager;
use tauri::State;
use crate::lifecycle;
use crate::tray;
use crate::tray::TrayClickAction;
use crate::tray::TrayGroupSummary;
use crate::tray::TrayHealthState;
use crate::tray::TrayMenuState;
use crate::tray::TrayNodeCandidate;
use crate::tray::TrayPreAccelRelayItem;
use crate::tray::TrayPreAccelSummary;
use crate::tray::TrayProxyMode;
use crate::tray::TraySubscriptionItem;
use crate::tray::TraySubscriptionSummary;
use crate::tray::TrayVisualState;

use crate::commands::state::AppState;
use crate::commands::state::CoreRuntimeInfoDto;
use crate::commands::state::EVENT_CONFIG_UPDATED;
use crate::commands::state::EVENT_GROUPS_UPDATED;
use crate::commands::state::EVENT_NODES_UPDATED;
use crate::commands::state::EVENT_RELAYS_UPDATED;
use crate::commands::state::EVENT_RUNTIME;
use crate::commands::state::EVENT_TUN_NEEDS_ADMIN;
use crate::commands::state::UiAppConfigDto;
use crate::commands::state::format_bytes_human;
use crate::commands::state::format_speed_compact;

/// Nesting-safe RAII guard tracking active node/group switching and broadcasting
/// `catcloud://runtime` + tray visual updates on transitions so the floating capsule
/// and tray reflect live switching state across WebViews.
pub(in crate::commands) struct SwitchingActiveGuard {
    pub(in crate::commands) active: Arc<AtomicBool>,
    pub(in crate::commands) depth: Arc<AtomicUsize>,
    pub(in crate::commands) app: AppHandle,
}


impl SwitchingActiveGuard {
    pub(in crate::commands) fn enter(app: &AppHandle, state: &AppState) -> Self {
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


#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::commands) fn select_tray_group_candidates<'a>(
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

fn select_tray_group_candidates_from_summaries<'a>(
    group: &MultiGroup,
    nodes: &'a [NodeSummary],
    node_by_id: &HashMap<&str, &'a NodeSummary>,
    limit: usize,
) -> Vec<&'a NodeSummary> {
    let raw_members: Vec<&'a NodeSummary> = if group.member_node_ids.is_empty() {
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

/// Lightweight equivalent of `resolve_valid_group_active_node` operating on `NodeSummary` rows
/// without deserializing `raw_json`.
pub fn resolve_valid_group_active_node_summary<'a>(
    group: &MultiGroup,
    nodes: &'a [NodeSummary],
) -> Option<&'a NodeSummary> {
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

/// Lightweight equivalent of `pick_smart_default_node_id(&nodes, None)` operating on `NodeSummary`
/// rows without reading `raw_json`.
fn pick_smart_default_node_summary_id(nodes: &[NodeSummary]) -> Option<String> {
    fn preferred_region_rank(code: &str) -> Option<u8> {
        match code {
            "TW" => Some(0),
            "HK" => Some(1),
            "SG" => Some(2),
            "JP" => Some(3),
            "US" => Some(4),
            "KR" => Some(5),
            _ => None,
        }
    }

    fn region_tier(code: &str) -> u8 {
        if preferred_region_rank(code).is_some() {
            0
        } else if matches!(
            code,
            "GB" | "UK"
                | "DE"
                | "FR"
                | "NL"
                | "CA"
                | "AU"
                | "MY"
                | "TH"
                | "VN"
                | "PH"
                | "ID"
                | "IN"
                | "CH"
                | "SE"
                | "NO"
                | "FI"
                | "IT"
                | "ES"
        ) {
            1
        } else {
            2
        }
    }

    fn multiplier_tier(mult: f64) -> u8 {
        if !mult.is_finite() || mult < 0.0 {
            2
        } else if mult <= 1.5 + 1e-9 {
            0
        } else if mult < 3.0 - 1e-9 {
            1
        } else {
            2
        }
    }

    let mut best: Option<((u8, u8, u8, u64, String, String), &str)> = None;
    for node in nodes {
        if !node.enabled || node.id.trim().is_empty() || node.is_info_node() {
            continue;
        }
        let code = node.region_code.trim().to_ascii_uppercase();
        let r_tier = region_tier(&code);
        let r_sub = preferred_region_rank(&code).unwrap_or(u8::MAX);
        let m_tier = multiplier_tier(node.multiplier);
        let mult_milli = if node.multiplier.is_finite() && node.multiplier >= 0.0 {
            (node.multiplier * 1000.0).round() as u64
        } else {
            u64::MAX
        };
        let key = (
            r_tier,
            m_tier,
            r_sub,
            mult_milli,
            node.name.trim().to_ascii_lowercase(),
            node.id.clone(),
        );
        if best.as_ref().is_none_or(|(cur_key, _)| key < *cur_key) {
            best = Some((key, node.id.as_str()));
        }
    }
    best.map(|(_, id)| id.to_string())
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


pub(in crate::commands) fn has_non_empty_inline_override_yaml(cfg: &AppConfig) -> bool {
    cfg.rules_override
        .inline_override_yaml
        .as_deref()
        .is_some_and(|raw| !raw.trim().is_empty())
}


pub(in crate::commands) fn may_have_tun_for_teardown(effective_tun: bool, cfg: &AppConfig) -> bool {
    effective_tun
        || cfg.rules_override.override_mode != OverrideMode::Disabled
        || has_non_empty_inline_override_yaml(cfg)
}


pub(in crate::commands) fn config_may_have_tun(state: &AppState, cfg: &AppConfig) -> bool {
    may_have_tun_for_teardown(effective_tun_enabled(state, cfg), cfg)
}


/// Return `true` when the user configured TUN ON (`cfg.tun.enabled == true`) but current privileges
/// are insufficient so TUN cannot genuinely take effect.
pub fn tun_needs_elevation(state: &AppState, cfg: &AppConfig) -> bool {
    cfg.tun.enabled && !is_tun_privilege_ready(state)
}


/// Build a runtime copy of `cfg` with `tun.enabled` clamped to `false` when TUN privileges are absent,
/// without ever mutating the persisted `config.json` intent.
pub(in crate::commands) fn effective_config_for_runtime(state: &AppState, cfg: &AppConfig) -> AppConfig {
    let mut eff = cfg.clone();
    if eff.tun.enabled && !is_tun_privilege_ready(state) {
        eff.tun.enabled = false;
    }
    eff
}


/// Resolve the discrete tray pre-acceleration mode label, explicitly surfacing `"no_relay"`
/// whenever pre-acceleration is flagged on (or standalone is running) without any enabled relay
/// so the tray never falsely reports `"standby"` / `"已开启·待启动"`.
pub(in crate::commands) fn resolve_tray_preaccel_mode_label(
    preaccel_enabled: bool,
    has_enabled_relays: bool,
    proxy_active: bool,
    global_running: bool,
    is_windivert_active: bool,
    install_state: &str,
) -> Option<String> {
    if !preaccel_enabled && !global_running {
        None
    } else if !has_enabled_relays {
        Some("no_relay".to_string())
    } else if proxy_active && preaccel_enabled {
        if is_windivert_active {
            Some("dual".to_string())
        } else {
            None
        }
    } else if is_windivert_active {
        Some("windivert".to_string())
    } else if matches!(install_state, "downloading" | "verifying") {
        Some("downloading".to_string())
    } else if install_state == "need_elevation" {
        Some("need_elevation".to_string())
    } else if global_running {
        Some("local_socks5".to_string())
    } else if preaccel_enabled {
        Some("standby".to_string())
    } else {
        None
    }
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
            let nodes = db.list_node_summaries().unwrap_or_default();
            let relays = db.list_preaccel_relays(false).unwrap_or_default();
            let subs = db.list_subscriptions().unwrap_or_default();
            let ids: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
            let snaps = db.get_probe_snapshots_batch(&ids, None).unwrap_or_default();
            (groups, nodes, relays, subs, snaps)
        })
        .unwrap_or_default();

    let node_by_id: HashMap<&str, &NodeSummary> =
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
        let member_nodes = select_tray_group_candidates_from_summaries(g, &nodes, &node_by_id, 8);
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

    let has_enabled_relays = relays.iter().any(|r| r.enabled);
    let active_relay_label = cfg
        .preaccel
        .active_relay_id
        .as_deref()
        .and_then(|id| relays.iter().find(|r| r.id == id && r.enabled))
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
    let global_mode_label = resolve_tray_preaccel_mode_label(
        cfg.preaccel.enabled,
        has_enabled_relays,
        proxy_active,
        global_status.running,
        global_status.is_windivert_active,
        global_status.install_state.as_str(),
    );

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


pub(in crate::commands) fn build_tray_visual_state_with_verify_override(
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
                    if let Some(node_name) = cfg
                        .active_single_node_id
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .and_then(|id| db.get_node_name(id).ok().flatten())
                    {
                        return (Some(format!("单节点 · {node_name}")), false, false, false);
                    }
                }
                let Ok(groups) = db.list_multi_groups() else {
                    return (None, false, false, false);
                };
                let nodes = db.list_node_summaries().unwrap_or_default();
                let Some(g) = cfg
                    .active_group_id
                    .as_deref()
                    .and_then(|gid| groups.iter().find(|g| g.id == gid))
                    .or_else(|| groups.first())
                else {
                    return (None, false, false, false);
                };
                let node_name = resolve_valid_group_active_node_summary(g, &nodes)
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
    } else if cfg.preaccel.enabled && !has_enabled_relays {
        Some("待添加提速线路".to_string())
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


pub(in crate::commands) fn tun_needs_admin_error_message() -> String {
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


/// Resolve the unified domestic pre-acceleration effective carrier contract across all modes:
/// `"main_core_tun_suspended_standalone" | "main_core_proxy_only" | "standalone_windivert" | "standalone_socks5" | "off"`.
pub(in crate::commands) fn resolve_preaccel_effective_carrier(
    preaccel_enabled: bool,
    has_enabled_relays: bool,
    core_running: bool,
    eff_tun: bool,
    proxy_active: bool,
    is_direct_mode: bool,
    global_status: &GlobalPreAccelStatus,
) -> (&'static str, bool) {
    if global_status.is_windivert_active {
        return ("standalone_windivert", false);
    }
    if global_status.running {
        return ("standalone_socks5", false);
    }
    if is_direct_mode || !preaccel_enabled || !has_enabled_relays {
        return ("off", false);
    }
    let suspended_for_tun =
        global_status.mode == "suspended_for_tun" || (core_running && eff_tun);
    if suspended_for_tun {
        return ("main_core_tun_suspended_standalone", true);
    }
    if proxy_active {
        return ("main_core_proxy_only", false);
    }
    ("off", false)
}


pub(in crate::commands) fn has_existing_enabled_active_relay(
    active_relay_id: Option<&str>,
    enabled_relays: &[PreAccelRelay],
) -> bool {
    active_relay_id
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .is_some_and(|aid| enabled_relays.iter().any(|r| r.enabled && r.id == aid))
}


/// Align multi-cloud load-balance activation with `preaccel::generator::build_preaccel_proxy_groups`:
/// requires `distinct_host_count >= 2` and either explicit `LoadBalance` or `Auto` with no existing
/// enabled pinned `active_relay_id` (a dangling/deleted/disabled `active_relay_id` does not block LB).
pub(in crate::commands) fn is_preaccel_pool_lb_effective(
    strategy: PreAccelDispatchStrategy,
    active_relay_id: Option<&str>,
    enabled_relays: &[PreAccelRelay],
    distinct_host_count: usize,
) -> bool {
    let has_active_relay = has_existing_enabled_active_relay(active_relay_id, enabled_relays);
    distinct_host_count >= 2
        && (strategy == PreAccelDispatchStrategy::LoadBalance
            || (strategy == PreAccelDispatchStrategy::Auto && !has_active_relay))
}


/// Determine whether any enabled business proxy node will actually be wrapped with domestic
/// pre-acceleration `dialer-proxy`, mirroring `config_compiler.rs` and `catcloud-cli`
/// (`should_apply_preaccel` + `relays_support_ipv6` IPv6-only exclusion).
#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::commands) fn has_preaccel_wrappable_nodes(
    cfg: &AppConfig,
    relays: &[PreAccelRelay],
    nodes: &[ProxyNode],
) -> bool {
    let enabled_relays: Vec<&PreAccelRelay> = relays.iter().filter(|r| r.enabled).collect();
    if enabled_relays.is_empty() {
        return false;
    }
    let relays_support_ipv6 = enabled_relays.iter().all(|r| r.supports_ipv6);
    nodes.iter().any(|n| {
        if !n.enabled
            || is_info_proxy_node(n)
            || !n.should_apply_preaccel(cfg.preaccel.skip_443_native)
        {
            return false;
        }
        let skip_for_ipv6 =
            !relays_support_ipv6 && is_ipv6_only_node(n) && n.preaccel_override != Some(true);
        !skip_for_ipv6
    })
}

/// Lightweight equivalent of `has_preaccel_wrappable_nodes` operating on `NodeSummary` rows
/// without deserializing `raw_json`.
pub(in crate::commands) fn has_preaccel_wrappable_node_summaries(
    cfg: &AppConfig,
    relays: &[PreAccelRelay],
    summaries: &[NodeSummary],
) -> bool {
    let enabled_relays: Vec<&PreAccelRelay> = relays.iter().filter(|r| r.enabled).collect();
    if enabled_relays.is_empty() {
        return false;
    }
    let relays_support_ipv6 = enabled_relays.iter().all(|r| r.supports_ipv6);
    summaries.iter().any(|n| {
        if !n.enabled
            || n.is_info_node()
            || !n.should_apply_preaccel(cfg.preaccel.skip_443_native)
        {
            return false;
        }
        let skip_for_ipv6 =
            !relays_support_ipv6 && n.is_ipv6_only() && n.preaccel_override != Some(true);
        !skip_for_ipv6
    })
}


/// Infer the effective compiled TUN MTU when no cached `CompileStats.effective_tun_mtu` is
/// available yet (e.g. core stopped), mirroring `config_compiler::build_tun_section`:
/// clamp to `<= 1400` whenever domestic pre-acceleration will wrap business nodes via
/// `dialer-proxy`, otherwise preserve `cfg.tun.mtu`.
pub(in crate::commands) fn infer_effective_tun_mtu(
    cfg: &AppConfig,
    has_enabled_relays: bool,
    has_wrappable_nodes: bool,
) -> u16 {
    if cfg.preaccel.enabled && has_enabled_relays && has_wrappable_nodes {
        cfg.tun.mtu.min(1400)
    } else {
        cfg.tun.mtu
    }
}


pub fn build_runtime_info_dto(state: &AppState) -> Result<CoreRuntimeInfoDto, String> {
    build_runtime_info_dto_with_verify_override(state, None)
}


pub(in crate::commands) fn build_runtime_info_dto_with_verify_override(
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
        has_wrappable_nodes,
        active_snap,
    ) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let groups = db.list_multi_groups().unwrap_or_default();
        let nodes = db.list_node_summaries().unwrap_or_default();
        let relays = db.list_preaccel_relays(true).unwrap_or_default();
        let has_wrappable_nodes = has_preaccel_wrappable_node_summaries(&cfg, &relays, &nodes);
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
                Some(g) => resolve_valid_group_active_node_summary(g, &nodes),
                None => pick_smart_default_node_summary_id(&nodes)
                    .and_then(|id| nodes.iter().find(|n| n.id == id))
                    .or_else(|| nodes.iter().find(|n| n.enabled))
                    .or_else(|| nodes.first()),
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
            has_wrappable_nodes,
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

    let (preaccel_effective_carrier, standalone_tunnel_suspended_for_tun) =
        resolve_preaccel_effective_carrier(
            cfg.preaccel.enabled,
            has_enabled_relays,
            rt.running,
            eff_tun,
            proxy_active,
            is_direct_mode,
            &global_status,
        );
    let effective_tun_mtu_val = if rt.running {
        state
            .snapshot_last_effective_tun_mtu()
            .unwrap_or_else(|| {
                infer_effective_tun_mtu(&cfg, has_enabled_relays, has_wrappable_nodes)
            })
    } else {
        infer_effective_tun_mtu(&cfg, has_enabled_relays, has_wrappable_nodes)
    };
    let preaccel_transport = Some(build_preaccel_transport_diagnostics(
        &cfg,
        effective_tun_mtu_val,
        preaccel_effective_carrier,
    ));
    let dns_diag_raw = state.analyze_dns_tls_diagnostics_cached(64 * 1024);
    let dns_tls_diagnostics = if dns_diag_raw.status != DNS_TLS_STATUS_HEALTHY {
        Some(dns_diag_raw)
    } else {
        None
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
        preaccel_effective_carrier: preaccel_effective_carrier.to_string(),
        standalone_tunnel_suspended_for_tun,
        global_preaccel_active: global_status.running,
        global_preaccel_mode: global_status.mode,
        global_preaccel_socks_port: global_status.socks_port,
        global_preaccel_connections: global_status.active_connections,
        global_windivert_active: global_status.is_windivert_active,
        preaccel_install_state: global_status.install_state,
        global_preaccel_verify_state: verify_state,
        global_preaccel_verify_ms: verify_ms,
        dns_tls_diagnostics,
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
        power_on_tun_degraded: false,
        tun_admin_ready,
        effective_tun_mtu: Some(effective_tun_mtu_val),
        preaccel_transport,
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        os_label: format!("{} {}", caps.os, caps.arch),
        autostart_enabled: cfg.behavior.autostart,
        portable_mode: state.paths.is_portable,
        last_update_check: cfg.update.last_checked_at.clone(),
        last_error: state.last_app_error_snapshot(),
    })
}


pub fn emit_runtime_snapshot<R: tauri::Runtime>(app: &AppHandle<R>, state: &AppState) {
    if !lifecycle::has_visible_gui_window(app) {
        return;
    }
    if let Ok(dto) = build_runtime_info_dto(state) {
        let _ = app.emit(EVENT_RUNTIME, dto);
    }
}


pub fn emit_config_updated(app: &AppHandle, cfg: &AppConfig) {
    let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(cfg));
}


pub fn emit_groups_updated(app: &AppHandle) {
    let _ = app.emit(EVENT_GROUPS_UPDATED, ());
}


pub fn emit_relays_updated(app: &AppHandle) {
    let _ = app.emit(EVENT_RELAYS_UPDATED, ());
}


pub fn emit_nodes_updated(app: &AppHandle) {
    let _ = app.emit(EVENT_NODES_UPDATED, ());
}


pub fn refresh_tray(app: &AppHandle, state: &AppState) {
    let _ = tray::sync_tray_menu(app, &build_tray_menu_state(app, state));
    let _ = tray::sync_tray_visual(app, &build_tray_visual_state(state));
}


pub(in crate::commands) fn emit_preaccel_verify_override_snapshots(
    app: &AppHandle,
    state: &AppState,
    verify_state: &str,
    verify_ms: Option<u64>,
) {
    let override_val = Some((verify_state, verify_ms));
    if lifecycle::has_visible_gui_window(app) {
        if let Ok(dto) = build_runtime_info_dto_with_verify_override(state, override_val) {
            let _ = app.emit(EVENT_RUNTIME, dto);
        }
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
pub(in crate::commands) fn format_mihomo_error_for_user(raw: &str) -> String {
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
    db.has_enabled_nodes()
        .map_err(|e| format!("读取节点列表失败：{e}"))
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


#[tauri::command]
pub async fn get_runtime_info(state: State<'_, AppState>) -> Result<CoreRuntimeInfoDto, String> {
    let live = state.adapter.status().await;
    state.update_cached_runtime(live);
    build_runtime_info_dto(&state)
}


pub(in crate::commands) struct ProbeRunningGuard {
    pub(in crate::commands) running: Arc<AtomicBool>,
    pub(in crate::commands) cancel_tx: Arc<Mutex<Option<tokio::sync::watch::Sender<bool>>>>,
    pub(in crate::commands) app: AppHandle,
}


impl ProbeRunningGuard {
    pub(in crate::commands) fn enter(app: &AppHandle, state: &AppState) -> Self {
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


/// Synchronize window close policy, tray click action, tray menu/visual state, and runtime snapshot
/// without re-registering global shortcuts (used by lower layers that do not mutate hotkey bindings).
pub(in crate::commands) fn sync_tray_and_window_side_effects(
    app: &AppHandle,
    state: &AppState,
    cfg: &AppConfig,
) {
    if let Some(win_state) = app.try_state::<lifecycle::WindowLifecycleState>() {
        win_state.set_destroy_on_close(cfg.behavior.minimize_to_tray_on_close);
    }
    tray::set_tray_left_click_action(app, map_tray_click(&cfg.behavior.tray_click_action));
    let _ = tray::sync_tray_menu(app, &build_tray_menu_state(app, state));
    let _ = tray::sync_tray_visual(app, &build_tray_visual_state(state));
    emit_runtime_snapshot(app, state);
}
