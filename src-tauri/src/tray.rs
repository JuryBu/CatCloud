use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tauri::image::Image;
use tauri::menu::{CheckMenuItem, IsMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, Runtime};

/// Unique tray icon identifier used with `app.tray_by_id(MAIN_TRAY_ID)`.
pub const MAIN_TRAY_ID: &str = "catcloud-main-tray";

/// Maximum UTF-16 code units permitted by Windows `NOTIFYICONDATAW.szTip` (excluding NUL).
const WIN32_TOOLTIP_MAX_UTF16: usize = 127;

/// Stable menu item IDs and dynamic item prefixes for the tray context menu.
pub mod menu_id {
    pub const OPEN_MAIN: &str = "tray:open_main";
    pub const TOGGLE_CAPSULE: &str = "tray:toggle_capsule";
    pub const MODE_RULE: &str = "tray:mode:rule";
    pub const MODE_GLOBAL: &str = "tray:mode:global";
    pub const MODE_DIRECT: &str = "tray:mode:direct";
    pub const QUICK_SWITCH_NEXT_BEST_PREFIX: &str = "tray:group_next:";
    pub const GROUP_SELECT_PREFIX: &str = "tray:group_select:";
    pub const PREACCEL_TOGGLE: &str = "tray:preaccel:toggle";
    pub const PREACCEL_FAILOVER_NEXT: &str = "tray:preaccel:failover";
    pub const PREACCEL_RELAY_PREFIX: &str = "tray:preaccel:relay:";
    pub const SUBS_REFRESH_ALL: &str = "tray:subs:refresh_all";
    pub const TOGGLE_SYSTEM_PROXY: &str = "tray:toggle_system_proxy";
    pub const TOGGLE_TUN: &str = "tray:toggle_tun";
    pub const TOGGLE_WINDOWLESS: &str = "tray:toggle_windowless";
    pub const COPY_SHELL_ENV: &str = "tray:copy_shell_env";
    pub const TOGGLE_AUTOSTART: &str = "tray:toggle_autostart";
    pub const OPEN_DIR_DATA: &str = "tray:open_dir:data";
    pub const OPEN_DIR_CONFIG: &str = "tray:open_dir:config";
    pub const OPEN_DIR_LOGS: &str = "tray:open_dir:logs";
    pub const OPEN_DIR_BIN: &str = "tray:open_dir:bin";
    pub const RESTART_CORE: &str = "tray:restart_core";
    pub const QUIT: &str = "tray:quit";
}

// 15 pre-baked 64x64 RGBA PNG tray icons embedded directly into the binary.
const PNG_A_IDLE: &[u8] = include_bytes!("../icons/tray/tray_a_idle.png");
const PNG_A_OK: &[u8] = include_bytes!("../icons/tray/tray_a_ok.png");
const PNG_A_PREACCEL: &[u8] = include_bytes!("../icons/tray/tray_a_preaccel.png");
const PNG_A_WARN: &[u8] = include_bytes!("../icons/tray/tray_a_warn.png");
const PNG_A_ERROR: &[u8] = include_bytes!("../icons/tray/tray_a_error.png");

const PNG_C_IDLE: &[u8] = include_bytes!("../icons/tray/tray_c_idle.png");
const PNG_C_OK: &[u8] = include_bytes!("../icons/tray/tray_c_ok.png");
const PNG_C_PREACCEL: &[u8] = include_bytes!("../icons/tray/tray_c_preaccel.png");
const PNG_C_WARN: &[u8] = include_bytes!("../icons/tray/tray_c_warn.png");
const PNG_C_ERROR: &[u8] = include_bytes!("../icons/tray/tray_c_error.png");

const PNG_PIXEL_IDLE: &[u8] = include_bytes!("../icons/tray/tray_pixel_idle.png");
const PNG_PIXEL_OK: &[u8] = include_bytes!("../icons/tray/tray_pixel_ok.png");
const PNG_PIXEL_PREACCEL: &[u8] = include_bytes!("../icons/tray/tray_pixel_preaccel.png");
const PNG_PIXEL_WARN: &[u8] = include_bytes!("../icons/tray/tray_pixel_warn.png");
const PNG_PIXEL_ERROR: &[u8] = include_bytes!("../icons/tray/tray_pixel_error.png");

/// Pre-baked tray mascot pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrayIconPack {
    /// Plan A: cream cloud cat loaf.
    A,
    /// Plan C: midnight starry neko.
    C,
    /// Pixel art cat loaf.
    Pixel,
}

impl TrayIconPack {
    const fn row_index(self) -> usize {
        match self {
            Self::A => 0,
            Self::C => 1,
            Self::Pixel => 2,
        }
    }
}

/// 5-state tray health dot indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TrayHealthState {
    #[default]
    Idle,
    Ok,
    PreAccel,
    Warn,
    Error,
}

impl TrayHealthState {
    const fn col_index(self) -> usize {
        match self {
            Self::Idle => 0,
            Self::Ok => 1,
            Self::PreAccel => 2,
            Self::Warn => 3,
            Self::Error => 4,
        }
    }
}

/// User-selectable tray icon mapping policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TrayIconMode {
    /// Default mapping: `Idle | Ok -> A`, `PreAccel | Warn | Error -> C`.
    #[default]
    AutoAc,
    AlwaysA,
    AlwaysC,
    AlwaysPixel,
}

impl TrayIconMode {
    /// Resolve which icon pack should represent `state` under this mode.
    pub const fn resolve_pack(self, state: TrayHealthState) -> TrayIconPack {
        match self {
            Self::AutoAc => match state {
                TrayHealthState::Idle | TrayHealthState::Ok => TrayIconPack::A,
                TrayHealthState::PreAccel | TrayHealthState::Warn | TrayHealthState::Error => {
                    TrayIconPack::C
                }
            },
            Self::AlwaysA => TrayIconPack::A,
            Self::AlwaysC => TrayIconPack::C,
            Self::AlwaysPixel => TrayIconPack::Pixel,
        }
    }
}

/// Left-click action on the tray icon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TrayClickAction {
    #[default]
    ToggleMain,
    ToggleCapsule,
    ShowMenu,
}

/// Core proxy routing mode reflected in the tray menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TrayProxyMode {
    #[default]
    Rule,
    Global,
    Direct,
}

impl TrayProxyMode {
    pub const fn label_zh(self) -> &'static str {
        match self {
            Self::Rule => "规则",
            Self::Global => "全局",
            Self::Direct => "直连",
        }
    }
}

/// Directory shortcuts exposed under the "打开配置目录" submenu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrayOpenDirKind {
    DataRoot,
    Config,
    Logs,
    Bin,
}

/// One candidate node item in a multi-group quick-switch submenu.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrayNodeCandidate {
    pub node_id: String,
    pub label: String,
    /// Last probed upload speed in hundredths of Mbps (e.g., `268` => `↑2.68 Mbps`).
    /// Uses cached probe telemetry rather than live 1s traffic jitter to prevent menu churn.
    pub up_mbps_x100: Option<u32>,
    pub ping_ms: Option<u32>,
    pub selected: bool,
}

/// Summary of a smart multi-group shown in the tray submenu.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrayGroupSummary {
    pub group_id: String,
    pub group_name: String,
    pub active_node_label: String,
    pub candidates: Vec<TrayNodeCandidate>,
}

/// One domestic pre-acceleration relay entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrayPreAccelRelayItem {
    pub relay_id: String,
    pub label: String,
    pub mbps: Option<u32>,
    pub ping_ms: Option<u32>,
    pub selected: bool,
}

/// Summary of domestic pre-acceleration status for the tray submenu.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TrayPreAccelSummary {
    pub enabled: bool,
    pub active_label: Option<String>,
    pub relays: Vec<TrayPreAccelRelayItem>,
}

/// Read-only subscription entry shown under the subscription pool submenu.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraySubscriptionItem {
    pub sub_id: String,
    pub name: String,
    pub remaining_label: String,
    pub node_count: usize,
}

/// Summary of merged subscription traffic pool.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TraySubscriptionSummary {
    pub total_remaining_label: Option<String>,
    pub items: Vec<TraySubscriptionItem>,
}

/// Complete discrete summary governing the tray context menu.
///
/// Implements `PartialEq + Eq` so `sync_tray_menu` only rebuilds the Win32/native menu
/// when user-visible menu state genuinely changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrayMenuState {
    pub proxy_mode: TrayProxyMode,
    pub system_proxy_enabled: bool,
    pub tun_enabled: bool,
    pub windowless_mode: bool,
    pub capsule_open: bool,
    pub autostart_enabled: bool,
    pub primary_group: Option<TrayGroupSummary>,
    pub extra_groups: Vec<TrayGroupSummary>,
    pub preaccel: TrayPreAccelSummary,
    pub subscriptions: TraySubscriptionSummary,
}

impl Default for TrayMenuState {
    fn default() -> Self {
        Self {
            proxy_mode: TrayProxyMode::Rule,
            system_proxy_enabled: false,
            tun_enabled: false,
            windowless_mode: false,
            capsule_open: false,
            autostart_enabled: false,
            primary_group: None,
            extra_groups: Vec::new(),
            preaccel: TrayPreAccelSummary::default(),
            subscriptions: TraySubscriptionSummary::default(),
        }
    }
}

/// Structured inputs for formatting the multi-line tray hover tooltip (aligned with Fig. 9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrayTooltipInfo {
    pub version: String,
    pub runtime_mode_label: String,
    pub proxy_mode: TrayProxyMode,
    pub tun_enabled: bool,
    pub system_proxy_enabled: bool,
    pub preaccel_summary: Option<String>,
    pub primary_group_summary: Option<String>,
    pub realtime_speed: Option<String>,
}

impl Default for TrayTooltipInfo {
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            runtime_mode_label: "桌面模式".to_string(),
            proxy_mode: TrayProxyMode::Rule,
            tun_enabled: false,
            system_proxy_enabled: false,
            preaccel_summary: None,
            primary_group_summary: None,
            realtime_speed: None,
        }
    }
}

impl TrayTooltipInfo {
    /// Format a compact multi-line tooltip clamped safely to Windows' 127 UTF-16 limit.
    pub fn format_tooltip(&self) -> String {
        let mut lines = Vec::with_capacity(5);
        lines.push(format!(
            "猫猫云梯 v{} · {}",
            self.version, self.runtime_mode_label
        ));
        lines.push(format!(
            "模式: {} | TUN: {} | 代理: {}",
            self.proxy_mode.label_zh(),
            if self.tun_enabled { "开" } else { "关" },
            if self.system_proxy_enabled { "开" } else { "关" },
        ));
        if let Some(ref preaccel) = self.preaccel_summary {
            if !preaccel.trim().is_empty() {
                lines.push(format!("预加速: {}", preaccel.trim()));
            }
        }
        if let Some(ref group) = self.primary_group_summary {
            if !group.trim().is_empty() {
                lines.push(format!("主力: {}", group.trim()));
            }
        }
        if let Some(ref speed) = self.realtime_speed {
            if !speed.trim().is_empty() {
                lines.push(format!("实时: {}", speed.trim()));
            }
        }
        clamp_tooltip_utf16(&lines.join("\n"), WIN32_TOOLTIP_MAX_UTF16)
    }
}

fn clamp_tooltip_utf16(input: &str, max_units: usize) -> String {
    if input.encode_utf16().count() <= max_units {
        return input.to_string();
    }
    let budget = max_units.saturating_sub(1);
    let mut out = String::new();
    let mut units = 0usize;
    for ch in input.chars() {
        let ch_units = ch.len_utf16();
        if units + ch_units > budget {
            break;
        }
        out.push(ch);
        units += ch_units;
    }
    if max_units > 0 {
        out.push('…');
    }
    out
}

/// Visual-only tray update payload (icon + tooltip), decoupled from menu rebuilding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrayVisualState {
    pub icon_mode: TrayIconMode,
    pub health: TrayHealthState,
    pub tooltip: String,
}

impl Default for TrayVisualState {
    fn default() -> Self {
        Self {
            icon_mode: TrayIconMode::AutoAc,
            health: TrayHealthState::Idle,
            tooltip: TrayTooltipInfo::default().format_tooltip(),
        }
    }
}

/// Strongly typed actions dispatched from tray context menu clicks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrayAction {
    OpenMain,
    ToggleCapsule,
    SetProxyMode(TrayProxyMode),
    QuickSwitchNextBest { group_id: String },
    SelectGroupNode { group_id: String, node_id: String },
    TogglePreAccel,
    FailoverPreAccel,
    SelectPreAccelRelay { relay_id: String },
    RefreshSubscriptions,
    ToggleSystemProxy,
    ToggleTun,
    ToggleWindowless,
    CopyShellEnv,
    ToggleAutostart,
    OpenDir(TrayOpenDirKind),
    RestartCore,
    Quit,
}

/// Parse a Tauri menu item ID into a typed `TrayAction`.
pub fn parse_menu_action(id: &str) -> Option<TrayAction> {
    match id {
        menu_id::OPEN_MAIN => Some(TrayAction::OpenMain),
        menu_id::TOGGLE_CAPSULE => Some(TrayAction::ToggleCapsule),
        menu_id::MODE_RULE => Some(TrayAction::SetProxyMode(TrayProxyMode::Rule)),
        menu_id::MODE_GLOBAL => Some(TrayAction::SetProxyMode(TrayProxyMode::Global)),
        menu_id::MODE_DIRECT => Some(TrayAction::SetProxyMode(TrayProxyMode::Direct)),
        menu_id::PREACCEL_TOGGLE => Some(TrayAction::TogglePreAccel),
        menu_id::PREACCEL_FAILOVER_NEXT => Some(TrayAction::FailoverPreAccel),
        menu_id::SUBS_REFRESH_ALL => Some(TrayAction::RefreshSubscriptions),
        menu_id::TOGGLE_SYSTEM_PROXY => Some(TrayAction::ToggleSystemProxy),
        menu_id::TOGGLE_TUN => Some(TrayAction::ToggleTun),
        menu_id::TOGGLE_WINDOWLESS => Some(TrayAction::ToggleWindowless),
        menu_id::COPY_SHELL_ENV => Some(TrayAction::CopyShellEnv),
        menu_id::TOGGLE_AUTOSTART => Some(TrayAction::ToggleAutostart),
        menu_id::OPEN_DIR_DATA => Some(TrayAction::OpenDir(TrayOpenDirKind::DataRoot)),
        menu_id::OPEN_DIR_CONFIG => Some(TrayAction::OpenDir(TrayOpenDirKind::Config)),
        menu_id::OPEN_DIR_LOGS => Some(TrayAction::OpenDir(TrayOpenDirKind::Logs)),
        menu_id::OPEN_DIR_BIN => Some(TrayAction::OpenDir(TrayOpenDirKind::Bin)),
        menu_id::RESTART_CORE => Some(TrayAction::RestartCore),
        menu_id::QUIT => Some(TrayAction::Quit),
        other => {
            if let Some(group_id) = other.strip_prefix(menu_id::QUICK_SWITCH_NEXT_BEST_PREFIX) {
                return Some(TrayAction::QuickSwitchNextBest {
                    group_id: group_id.to_string(),
                });
            }
            if let Some(rest) = other.strip_prefix(menu_id::GROUP_SELECT_PREFIX) {
                if let Some((group_id, node_id)) = rest.split_once("::") {
                    return Some(TrayAction::SelectGroupNode {
                        group_id: group_id.to_string(),
                        node_id: node_id.to_string(),
                    });
                }
            }
            if let Some(relay_id) = other.strip_prefix(menu_id::PREACCEL_RELAY_PREFIX) {
                return Some(TrayAction::SelectPreAccelRelay {
                    relay_id: relay_id.to_string(),
                });
            }
            None
        }
    }
}

/// Startup-decoded cache of all 15 embedded 64x64 tray icons (zero runtime PNG decoding).
#[derive(Clone)]
pub struct TrayIconBank {
    icons: Arc<[Image<'static>; 15]>,
}

impl TrayIconBank {
    /// Decode all 15 embedded PNG assets once at application startup.
    pub fn load_embedded() -> tauri::Result<Self> {
        let raw_assets: [&[u8]; 15] = [
            PNG_A_IDLE,
            PNG_A_OK,
            PNG_A_PREACCEL,
            PNG_A_WARN,
            PNG_A_ERROR,
            PNG_C_IDLE,
            PNG_C_OK,
            PNG_C_PREACCEL,
            PNG_C_WARN,
            PNG_C_ERROR,
            PNG_PIXEL_IDLE,
            PNG_PIXEL_OK,
            PNG_PIXEL_PREACCEL,
            PNG_PIXEL_WARN,
            PNG_PIXEL_ERROR,
        ];

        let mut decoded = Vec::with_capacity(15);
        for bytes in raw_assets {
            decoded.push(Image::<'static>::from_bytes(bytes)?);
        }
        let array: [Image<'static>; 15] = decoded
            .try_into()
            .expect("embedded tray icon bank always holds exactly 15 icons");
        Ok(Self {
            icons: Arc::new(array),
        })
    }

    #[inline]
    const fn slot_index(pack: TrayIconPack, state: TrayHealthState) -> usize {
        pack.row_index() * 5 + state.col_index()
    }

    /// Borrow a pre-decoded RGBA image by pack and health state with zero allocation.
    pub fn get(&self, pack: TrayIconPack, state: TrayHealthState) -> Image<'_> {
        let img = &self.icons[Self::slot_index(pack, state)];
        Image::new(img.rgba(), img.width(), img.height())
    }

    /// Resolve icon pack according to `mode` and borrow the pre-decoded RGBA image.
    pub fn icon_for(&self, mode: TrayIconMode, state: TrayHealthState) -> Image<'_> {
        self.get(mode.resolve_pack(state), state)
    }
}

/// Managed runtime state caching the last applied menu/visual snapshot to suppress redundant
/// Win32/native tray refreshes.
#[derive(Default)]
pub struct TrayRuntimeState {
    inner: Mutex<TrayRuntimeInner>,
}

#[derive(Default)]
struct TrayRuntimeInner {
    last_menu_state: Option<TrayMenuState>,
    last_icon_key: Option<(TrayIconPack, TrayHealthState)>,
    last_tooltip: Option<String>,
    left_click_action: TrayClickAction,
}

impl TrayRuntimeState {
    fn new(
        menu: TrayMenuState,
        icon_key: (TrayIconPack, TrayHealthState),
        tooltip: String,
        left_click_action: TrayClickAction,
    ) -> Self {
        Self {
            inner: Mutex::new(TrayRuntimeInner {
                last_menu_state: Some(menu),
                last_icon_key: Some(icon_key),
                last_tooltip: Some(tooltip),
                left_click_action,
            }),
        }
    }

    /// Pure diff helper used both at runtime and in unit tests to verify menu rebuild gating.
    fn should_rebuild_menu(&self, next: &TrayMenuState) -> bool {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.last_menu_state.as_ref() != Some(next)
    }

    fn commit_menu(&self, next: TrayMenuState) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.last_menu_state = Some(next);
    }

    fn diff_visual(
        &self,
        icon_key: (TrayIconPack, TrayHealthState),
        tooltip: &str,
    ) -> (bool, bool) {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let icon_changed = guard.last_icon_key != Some(icon_key);
        let tooltip_changed = guard.last_tooltip.as_deref() != Some(tooltip);
        (icon_changed, tooltip_changed)
    }

    fn commit_visual(&self, icon_key: (TrayIconPack, TrayHealthState), tooltip: String) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.last_icon_key = Some(icon_key);
        guard.last_tooltip = Some(tooltip);
    }

    fn left_click_action(&self) -> TrayClickAction {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .left_click_action
    }

    fn set_left_click_action(&self, action: TrayClickAction) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .left_click_action = action;
    }
}

fn format_candidate_label(c: &TrayNodeCandidate) -> String {
    match (c.up_mbps_x100, c.ping_ms) {
        (Some(up_x100), _) => {
            let whole = up_x100 / 100;
            let frac = up_x100 % 100;
            format!("{}  (↑{whole}.{frac:02} Mbps)", c.label)
        }
        (None, Some(ms)) => format!("{}  ({ms} ms)", c.label),
        (None, None) => c.label.clone(),
    }
}

fn format_relay_label(r: &TrayPreAccelRelayItem) -> String {
    match (r.mbps, r.ping_ms) {
        (Some(mbps), Some(ms)) => format!("{}  ({mbps} Mbps · {ms} ms)", r.label),
        (Some(mbps), None) => format!("{}  ({mbps} Mbps)", r.label),
        (None, Some(ms)) => format!("{}  ({ms} ms)", r.label),
        (None, None) => r.label.clone(),
    }
}

fn build_group_submenu<R: Runtime>(
    app: &AppHandle<R>,
    title: &str,
    group: &TrayGroupSummary,
) -> tauri::Result<Submenu<R>> {
    let submenu = Submenu::new(app, title, true)?;
    let next_best_id = format!("{}{}", menu_id::QUICK_SWITCH_NEXT_BEST_PREFIX, group.group_id);
    let next_best_item = MenuItem::with_id(
        app,
        next_best_id,
        "⚡ 一键秒切下一优",
        !group.candidates.is_empty(),
        None::<&str>,
    )?;
    submenu.append(&next_best_item)?;
    submenu.append(&PredefinedMenuItem::separator(app)?)?;

    if group.candidates.is_empty() {
        let empty = MenuItem::new(app, "暂无可用候选节点", false, None::<&str>)?;
        submenu.append(&empty)?;
    } else {
        for cand in &group.candidates {
            let id = format!(
                "{}{}::{}",
                menu_id::GROUP_SELECT_PREFIX,
                group.group_id,
                cand.node_id
            );
            let item = CheckMenuItem::with_id(
                app,
                id,
                format_candidate_label(cand),
                true,
                cand.selected,
                None::<&str>,
            )?;
            submenu.append(&item)?;
        }
    }
    Ok(submenu)
}

/// Build the complete Fig. 9 context menu from a discrete `TrayMenuState`.
pub fn build_tray_menu<R: Runtime>(
    app: &AppHandle<R>,
    state: &TrayMenuState,
) -> tauri::Result<Menu<R>> {
    let open_main = MenuItem::with_id(app, menu_id::OPEN_MAIN, "打开主界面", true, None::<&str>)?;
    let capsule_text = if state.capsule_open {
        "关闭悬浮胶囊"
    } else {
        "切换悬浮胶囊"
    };
    let toggle_capsule = MenuItem::with_id(
        app,
        menu_id::TOGGLE_CAPSULE,
        capsule_text,
        true,
        None::<&str>,
    )?;

    let mode_rule = CheckMenuItem::with_id(
        app,
        menu_id::MODE_RULE,
        "规则模式",
        true,
        state.proxy_mode == TrayProxyMode::Rule,
        None::<&str>,
    )?;
    let mode_global = CheckMenuItem::with_id(
        app,
        menu_id::MODE_GLOBAL,
        "全局模式",
        true,
        state.proxy_mode == TrayProxyMode::Global,
        None::<&str>,
    )?;
    let mode_direct = CheckMenuItem::with_id(
        app,
        menu_id::MODE_DIRECT,
        "直连模式",
        true,
        state.proxy_mode == TrayProxyMode::Direct,
        None::<&str>,
    )?;

    // Multi-group quick-switch submenu (with ⚡ next-best + ↑ Mbps telemetry)
    let group_submenu = if let Some(ref primary) = state.primary_group {
        let title = if primary.active_node_label.trim().is_empty() {
            format!("路线分组快切 ({})", primary.group_name)
        } else {
            format!(
                "路线分组快切 ({}: {})",
                primary.group_name, primary.active_node_label
            )
        };
        let sub = build_group_submenu(app, &title, primary)?;
        if !state.extra_groups.is_empty() {
            sub.append(&PredefinedMenuItem::separator(app)?)?;
            for extra in &state.extra_groups {
                let extra_title = if extra.active_node_label.trim().is_empty() {
                    extra.group_name.clone()
                } else {
                    format!("{}: {}", extra.group_name, extra.active_node_label)
                };
                let nested = build_group_submenu(app, &extra_title, extra)?;
                sub.append(&nested)?;
            }
        }
        sub
    } else {
        let sub = Submenu::new(app, "路线分组快切", true)?;
        let quick = MenuItem::with_id(
            app,
            format!("{}default", menu_id::QUICK_SWITCH_NEXT_BEST_PREFIX),
            "⚡ 一键秒切下一优",
            true,
            None::<&str>,
        )?;
        let empty = MenuItem::new(app, "暂未配置路线分组", false, None::<&str>)?;
        sub.append(&quick)?;
        sub.append(&PredefinedMenuItem::separator(app)?)?;
        sub.append(&empty)?;
        sub
    };

    // Domestic Pre-Acceleration submenu
    let preaccel_title = match (&state.preaccel.enabled, &state.preaccel.active_label) {
        (true, Some(label)) if !label.trim().is_empty() => {
            format!("国内加速入口 (已开启 · {})", label.trim())
        }
        (true, _) => "国内加速入口 (已开启)".to_string(),
        (false, _) => "国内加速入口 (已关闭)".to_string(),
    };
    let preaccel_submenu = Submenu::new(app, preaccel_title, true)?;
    let preaccel_toggle = CheckMenuItem::with_id(
        app,
        menu_id::PREACCEL_TOGGLE,
        "启用国内加速入口",
        true,
        state.preaccel.enabled,
        None::<&str>,
    )?;
    let preaccel_failover = MenuItem::with_id(
        app,
        menu_id::PREACCEL_FAILOVER_NEXT,
        "⚡ 切换备用加速入口",
        state.preaccel.relays.len() > 1,
        None::<&str>,
    )?;
    preaccel_submenu.append(&preaccel_toggle)?;
    preaccel_submenu.append(&preaccel_failover)?;
    preaccel_submenu.append(&PredefinedMenuItem::separator(app)?)?;
    if state.preaccel.relays.is_empty() {
        let empty = MenuItem::new(app, "暂未配置国内加速入口", false, None::<&str>)?;
        preaccel_submenu.append(&empty)?;
    } else {
        for relay in &state.preaccel.relays {
            let item = CheckMenuItem::with_id(
                app,
                format!("{}{}", menu_id::PREACCEL_RELAY_PREFIX, relay.relay_id),
                format_relay_label(relay),
                true,
                relay.selected,
                None::<&str>,
            )?;
            preaccel_submenu.append(&item)?;
        }
    }

    // Merged Subscription Pool submenu
    let subs_title = match &state.subscriptions.total_remaining_label {
        Some(total) if !total.trim().is_empty() => format!("节点订阅 ({})", total.trim()),
        _ => "节点订阅".to_string(),
    };
    let subs_submenu = Submenu::new(app, subs_title, true)?;
    let subs_refresh = MenuItem::with_id(
        app,
        menu_id::SUBS_REFRESH_ALL,
        "立即刷新全部订阅",
        true,
        None::<&str>,
    )?;
    subs_submenu.append(&subs_refresh)?;
    subs_submenu.append(&PredefinedMenuItem::separator(app)?)?;
    if state.subscriptions.items.is_empty() {
        let empty = MenuItem::new(app, "暂无订阅来源", false, None::<&str>)?;
        subs_submenu.append(&empty)?;
    } else {
        for sub in &state.subscriptions.items {
            let label = format!("{}  ({} · {} 节点)", sub.name, sub.remaining_label, sub.node_count);
            let item = MenuItem::new(app, label, false, None::<&str>)?;
            subs_submenu.append(&item)?;
        }
    }

    // Core system toggles
    let sys_proxy = CheckMenuItem::with_id(
        app,
        menu_id::TOGGLE_SYSTEM_PROXY,
        "系统代理",
        true,
        state.system_proxy_enabled,
        None::<&str>,
    )?;
    let tun_mode = CheckMenuItem::with_id(
        app,
        menu_id::TOGGLE_TUN,
        "TUN 虚拟网卡模式",
        true,
        state.tun_enabled,
        None::<&str>,
    )?;
    let windowless = CheckMenuItem::with_id(
        app,
        menu_id::TOGGLE_WINDOWLESS,
        "轻量无窗模式（关闭 UI 省内存）",
        true,
        state.windowless_mode,
        None::<&str>,
    )?;

    let copy_env = MenuItem::with_id(
        app,
        menu_id::COPY_SHELL_ENV,
        "复制终端代理环境变量",
        true,
        None::<&str>,
    )?;
    let autostart = CheckMenuItem::with_id(
        app,
        menu_id::TOGGLE_AUTOSTART,
        "开机自启动",
        true,
        state.autostart_enabled,
        None::<&str>,
    )?;

    // Open directories submenu
    let open_dir_submenu = Submenu::with_items(
        app,
        "打开配置目录",
        true,
        &[
            &MenuItem::with_id(
                app,
                menu_id::OPEN_DIR_DATA,
                "数据根目录 (data)",
                true,
                None::<&str>,
            )?,
            &MenuItem::with_id(
                app,
                menu_id::OPEN_DIR_CONFIG,
                "配置目录 (config)",
                true,
                None::<&str>,
            )?,
            &MenuItem::with_id(
                app,
                menu_id::OPEN_DIR_LOGS,
                "日志目录 (logs)",
                true,
                None::<&str>,
            )?,
            &MenuItem::with_id(
                app,
                menu_id::OPEN_DIR_BIN,
                "内核目录 (bin)",
                true,
                None::<&str>,
            )?,
        ],
    )?;

    let restart_core =
        MenuItem::with_id(app, menu_id::RESTART_CORE, "重启核心", true, None::<&str>)?;

    #[cfg(target_os = "macos")]
    let quit_accel = Some("Cmd+Q");
    #[cfg(not(target_os = "macos"))]
    let quit_accel = Some("Ctrl+Q");
    let quit_item = MenuItem::with_id(app, menu_id::QUIT, "退出", true, quit_accel)?;

    let sep1 = PredefinedMenuItem::separator(app)?;
    let sep2 = PredefinedMenuItem::separator(app)?;
    let sep3 = PredefinedMenuItem::separator(app)?;
    let sep4 = PredefinedMenuItem::separator(app)?;
    let sep5 = PredefinedMenuItem::separator(app)?;

    let items: [&dyn IsMenuItem<R>; 21] = [
        &open_main,
        &toggle_capsule,
        &sep1,
        &mode_rule,
        &mode_global,
        &mode_direct,
        &sep2,
        &group_submenu,
        &preaccel_submenu,
        &subs_submenu,
        &sep3,
        &sys_proxy,
        &tun_mode,
        &windowless,
        &sep4,
        &copy_env,
        &autostart,
        &sep5,
        &open_dir_submenu,
        &restart_core,
        &quit_item,
    ];

    Menu::with_items(app, &items)
}

/// Handle built-in shell-level tray actions directly.
/// Returns `true` if the action was completely handled by the desktop shell.
pub fn handle_builtin_tray_action<R: Runtime>(app: &AppHandle<R>, action: &TrayAction) -> bool {
    match action {
        TrayAction::OpenMain => {
            crate::lifecycle::show_or_rebuild_main_window(app);
            true
        }
        TrayAction::ToggleCapsule => {
            crate::lifecycle::toggle_capsule_window(app);
            true
        }
        TrayAction::ToggleWindowless => {
            if crate::lifecycle::is_windowless_mode(app) {
                crate::lifecycle::show_or_rebuild_main_window(app);
            } else {
                crate::lifecycle::enter_pure_windowless_mode(app);
            }
            true
        }
        TrayAction::Quit => {
            crate::lifecycle::request_graceful_exit(app);
            true
        }
        _ => false,
    }
}

/// Initialize the system tray icon, decode and manage `TrayIconBank` (15 icons once),
/// manage `TrayRuntimeState`, and bind click + menu event dispatchers.
pub fn setup_tray<R, F>(
    app: &AppHandle<R>,
    initial_menu: TrayMenuState,
    initial_visual: TrayVisualState,
    click_action: TrayClickAction,
    on_action: F,
) -> tauri::Result<()>
where
    R: Runtime,
    F: Fn(&AppHandle<R>, TrayAction) + Send + Sync + 'static,
{
    let bank = TrayIconBank::load_embedded()?;
    let initial_pack = initial_visual.icon_mode.resolve_pack(initial_visual.health);
    let initial_icon = bank.get(initial_pack, initial_visual.health).to_owned();
    let menu = build_tray_menu(app, &initial_menu)?;

    app.manage(bank);
    app.manage(TrayRuntimeState::new(
        initial_menu,
        (initial_pack, initial_visual.health),
        initial_visual.tooltip.clone(),
        click_action,
    ));

    let show_menu_on_left = matches!(click_action, TrayClickAction::ShowMenu);
    let action_handler = Arc::new(on_action);

    let _tray = TrayIconBuilder::<R>::with_id(MAIN_TRAY_ID)
        .icon(initial_icon)
        .tooltip(&initial_visual.tooltip)
        .menu(&menu)
        .show_menu_on_left_click(show_menu_on_left)
        .on_menu_event(move |app_handle, event| {
            if let Some(action) = parse_menu_action(event.id().as_ref()) {
                action_handler(app_handle, action);
            }
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                let app_handle = tray.app_handle();
                let click = app_handle
                    .try_state::<TrayRuntimeState>()
                    .map(|s| s.left_click_action())
                    .unwrap_or_default();
                match click {
                    TrayClickAction::ToggleMain => {
                        let snap = crate::lifecycle::window_mode_snapshot(app_handle);
                        if snap.main_open {
                            crate::lifecycle::enter_windowless_mode(app_handle);
                        } else {
                            crate::lifecycle::show_or_rebuild_main_window(app_handle);
                        }
                    }
                    TrayClickAction::ToggleCapsule => {
                        crate::lifecycle::toggle_capsule_window(app_handle);
                    }
                    TrayClickAction::ShowMenu => {}
                }
            }
        })
        .build(app)?;

    Ok(())
}

/// Update the tray context menu **only** when `next` differs from the previously applied
/// `TrayMenuState`. Never call on a blind timer; returns `Ok(true)` iff rebuilt.
pub fn sync_tray_menu<R: Runtime>(
    app: &AppHandle<R>,
    next: &TrayMenuState,
) -> tauri::Result<bool> {
    let Some(state) = app.try_state::<TrayRuntimeState>() else {
        return Ok(false);
    };
    if !state.should_rebuild_menu(next) {
        return Ok(false);
    }
    let Some(tray) = app.tray_by_id(MAIN_TRAY_ID) else {
        return Ok(false);
    };
    let menu = build_tray_menu(app, next)?;
    tray.set_menu(Some(menu))?;
    state.commit_menu(next.clone());
    Ok(true)
}

/// Update tray icon and/or tooltip independently of the context menu using the pre-decoded
/// `TrayIconBank` (zero PNG decoding, zero Win32 menu rebuilds).
pub fn sync_tray_visual<R: Runtime>(
    app: &AppHandle<R>,
    visual: &TrayVisualState,
) -> tauri::Result<bool> {
    let Some(state) = app.try_state::<TrayRuntimeState>() else {
        return Ok(false);
    };
    let Some(tray) = app.tray_by_id(MAIN_TRAY_ID) else {
        return Ok(false);
    };

    let next_pack = visual.icon_mode.resolve_pack(visual.health);
    let icon_key = (next_pack, visual.health);
    let (icon_changed, tooltip_changed) = state.diff_visual(icon_key, &visual.tooltip);

    if !icon_changed && !tooltip_changed {
        return Ok(false);
    }

    if icon_changed {
        if let Some(bank) = app.try_state::<TrayIconBank>() {
            let icon = bank.get(next_pack, visual.health);
            tray.set_icon(Some(icon))?;
        }
    }
    if tooltip_changed {
        tray.set_tooltip(Some(&visual.tooltip))?;
    }

    state.commit_visual(icon_key, visual.tooltip.clone());
    Ok(true)
}

/// Update left-click behavior at runtime without rebuilding the tray or menu.
pub fn set_tray_left_click_action<R: Runtime>(app: &AppHandle<R>, action: TrayClickAction) {
    if let Some(state) = app.try_state::<TrayRuntimeState>() {
        state.set_left_click_action(action);
    }
    if let Some(tray) = app.tray_by_id(MAIN_TRAY_ID) {
        let _ = tray.set_show_menu_on_left_click(matches!(action, TrayClickAction::ShowMenu));
    }
}

/// Explicitly hide and remove the tray icon before process exit to prevent ghost icons
/// in the Windows notification area.
pub fn cleanup_tray<R: Runtime>(app: &AppHandle<R>) {
    if let Some(tray) = app.tray_by_id(MAIN_TRAY_ID) {
        let _ = tray.set_visible(false);
    }
    let _ = app.remove_tray_by_id(MAIN_TRAY_ID);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_icon_bank_decodes_all_15_64x64_pngs() {
        let bank = TrayIconBank::load_embedded().expect("decode all 15 embedded tray PNGs");
        let packs = [TrayIconPack::A, TrayIconPack::C, TrayIconPack::Pixel];
        let states = [
            TrayHealthState::Idle,
            TrayHealthState::Ok,
            TrayHealthState::PreAccel,
            TrayHealthState::Warn,
            TrayHealthState::Error,
        ];

        for pack in packs {
            for state in states {
                let img = bank.get(pack, state);
                assert_eq!(img.width(), 64, "pack={pack:?} state={state:?}");
                assert_eq!(img.height(), 64, "pack={pack:?} state={state:?}");
                assert_eq!(img.rgba().len(), 64 * 64 * 4);
            }
        }
    }

    #[test]
    fn icon_mode_mapping_matches_specification() {
        // Default AutoAc: Idle/Ok -> A, PreAccel/Warn/Error -> C
        assert_eq!(
            TrayIconMode::AutoAc.resolve_pack(TrayHealthState::Idle),
            TrayIconPack::A
        );
        assert_eq!(
            TrayIconMode::AutoAc.resolve_pack(TrayHealthState::Ok),
            TrayIconPack::A
        );
        assert_eq!(
            TrayIconMode::AutoAc.resolve_pack(TrayHealthState::PreAccel),
            TrayIconPack::C
        );
        assert_eq!(
            TrayIconMode::AutoAc.resolve_pack(TrayHealthState::Warn),
            TrayIconPack::C
        );
        assert_eq!(
            TrayIconMode::AutoAc.resolve_pack(TrayHealthState::Error),
            TrayIconPack::C
        );

        for state in [
            TrayHealthState::Idle,
            TrayHealthState::Ok,
            TrayHealthState::PreAccel,
            TrayHealthState::Warn,
            TrayHealthState::Error,
        ] {
            assert_eq!(TrayIconMode::AlwaysA.resolve_pack(state), TrayIconPack::A);
            assert_eq!(TrayIconMode::AlwaysC.resolve_pack(state), TrayIconPack::C);
            assert_eq!(
                TrayIconMode::AlwaysPixel.resolve_pack(state),
                TrayIconPack::Pixel
            );
        }
    }

    #[test]
    fn menu_state_diff_suppresses_unchanged_rebuilds() {
        let initial = TrayMenuState::default();
        let runtime = TrayRuntimeState::new(
            initial.clone(),
            (TrayIconPack::A, TrayHealthState::Idle),
            "CatCloud".into(),
            TrayClickAction::ToggleMain,
        );

        assert!(!runtime.should_rebuild_menu(&initial));

        let mut modified = initial.clone();
        modified.tun_enabled = true;
        assert!(runtime.should_rebuild_menu(&modified));
        runtime.commit_menu(modified.clone());
        assert!(!runtime.should_rebuild_menu(&modified));
    }

    #[test]
    fn visual_diff_tracks_icon_and_tooltip_independently() {
        let runtime = TrayRuntimeState::new(
            TrayMenuState::default(),
            (TrayIconPack::A, TrayHealthState::Ok),
            "initial".into(),
            TrayClickAction::ToggleMain,
        );

        assert_eq!(
            runtime.diff_visual((TrayIconPack::A, TrayHealthState::Ok), "initial"),
            (false, false)
        );
        assert_eq!(
            runtime.diff_visual((TrayIconPack::A, TrayHealthState::Ok), "updated"),
            (false, true)
        );
        assert_eq!(
            runtime.diff_visual((TrayIconPack::C, TrayHealthState::PreAccel), "initial"),
            (true, false)
        );
    }

    #[test]
    fn menu_id_parser_handles_static_and_dynamic_items() {
        assert_eq!(parse_menu_action(menu_id::OPEN_MAIN), Some(TrayAction::OpenMain));
        assert_eq!(
            parse_menu_action(menu_id::MODE_GLOBAL),
            Some(TrayAction::SetProxyMode(TrayProxyMode::Global))
        );
        assert_eq!(
            parse_menu_action("tray:group_next:ai_core"),
            Some(TrayAction::QuickSwitchNextBest {
                group_id: "ai_core".into()
            })
        );
        assert_eq!(
            parse_menu_action("tray:group_select:ai_core::node_tw_01"),
            Some(TrayAction::SelectGroupNode {
                group_id: "ai_core".into(),
                node_id: "node_tw_01".into()
            })
        );
        assert_eq!(
            parse_menu_action("tray:preaccel:relay:relay_main"),
            Some(TrayAction::SelectPreAccelRelay {
                relay_id: "relay_main".into()
            })
        );
        assert_eq!(
            parse_menu_action(menu_id::OPEN_DIR_LOGS),
            Some(TrayAction::OpenDir(TrayOpenDirKind::Logs))
        );
        assert_eq!(parse_menu_action(menu_id::QUIT), Some(TrayAction::Quit));
        assert_eq!(parse_menu_action("unknown"), None);
    }

    #[test]
    fn tooltip_respects_win32_127_utf16_limit() {
        let info = TrayTooltipInfo {
            version: "0.1.0".into(),
            runtime_mode_label: "便携模式".into(),
            proxy_mode: TrayProxyMode::Rule,
            tun_enabled: true,
            system_proxy_enabled: false,
            preaccel_summary: Some("国内主节点 443 预加速 (265 Mbps)".into()),
            primary_group_summary: Some("AI 专线: 节点 A (1x 零送中 · 超长描述测试文本测试文本测试文本测试文本)".into()),
            realtime_speed: Some("↑ 2.68 MB/s ↓ 18.4 MB/s".into()),
        };
        let formatted = info.format_tooltip();
        assert!(formatted.encode_utf16().count() <= WIN32_TOOLTIP_MAX_UTF16);
    }

    #[test]
    fn candidate_label_formats_upload_mbps_cleanly() {
        let cand = TrayNodeCandidate {
            node_id: "n1".into(),
            label: "节点 01".into(),
            up_mbps_x100: Some(268),
            ping_ms: Some(42),
            selected: true,
        };
        assert_eq!(format_candidate_label(&cand), "节点 01  (↑2.68 Mbps)");
    }
}
