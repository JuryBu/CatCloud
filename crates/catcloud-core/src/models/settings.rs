use crate::platform::SystemProxySpec;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Current configuration schema version.
pub const CONFIG_SCHEMA_VERSION: u32 = 1;

/// Default domestic 204 connectivity probe URL (never use overseas domains).
pub const DEFAULT_PREACCEL_PROBE_URL: &str =
    "http://connectivitycheck.platform.hicloud.com/generate_204";

/// Default fallback domestic 204 probe URL for networks blocking primary host/port.
pub const DEFAULT_PREACCEL_FALLBACK_PROBE_URL: &str =
    "http://connect.rom.miui.com/generate_204";

/// Default public GitHub repository for automatic updates.
pub const DEFAULT_UPDATE_REPO: &str = "JuryBu/CatCloud";

/// Core routing mode.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProxyMode {
    #[default]
    Rule,
    Global,
    Direct,
}

impl ProxyMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Rule => "rule",
            Self::Global => "global",
            Self::Direct => "direct",
        }
    }
}

/// Process matching mode in Mihomo.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum FindProcessMode {
    #[default]
    Strict,
    Always,
    Off,
}

impl FindProcessMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Always => "always",
            Self::Off => "off",
        }
    }
}

/// Proxy core log verbosity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CoreLogLevel {
    Silent,
    Error,
    Warning,
    #[default]
    Info,
    Debug,
}

impl CoreLogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Silent => "silent",
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }
}

/// External controller WebUI bookmark template.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct WebUiEntry {
    pub name: String,
    /// Supports `{host}`, `{port}`, and `{secret}` placeholders.
    pub url_template: String,
}

impl Default for WebUiEntry {
    fn default() -> Self {
        Self {
            name: "MetaCubeXD".to_string(),
            url_template: "https://metacubex.github.io/metacubexd/#/setup?http=true&hostname={host}&port={port}&secret={secret}".to_string(),
        }
    }
}

/// Proxy Guard background watchdog settings preventing third-party proxy hijacking.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ProxyGuardConfig {
    pub enabled: bool,
    pub interval_sec: u64,
}

impl Default for ProxyGuardConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_sec: 10,
        }
    }
}

/// Local PAC endpoint settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct PacConfig {
    pub enabled: bool,
    pub port: u16,
    pub script_override: Option<String>,
}

impl Default for PacConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 17891,
            script_override: None,
        }
    }
}

/// OS system proxy, Proxy Guard, bypass list, and PAC configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct SystemProxyConfig {
    pub enabled: bool,
    #[serde(alias = "guard")]
    pub proxy_guard: ProxyGuardConfig,
    pub bypass: Vec<String>,
    pub pac: PacConfig,
}

impl Default for SystemProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            proxy_guard: ProxyGuardConfig::default(),
            bypass: vec![
                "localhost".to_string(),
                "127.*".to_string(),
                "10.*".to_string(),
                "172.16.*".to_string(),
                "172.17.*".to_string(),
                "172.18.*".to_string(),
                "172.19.*".to_string(),
                "172.20.*".to_string(),
                "172.21.*".to_string(),
                "172.22.*".to_string(),
                "172.23.*".to_string(),
                "172.24.*".to_string(),
                "172.25.*".to_string(),
                "172.26.*".to_string(),
                "172.27.*".to_string(),
                "172.28.*".to_string(),
                "172.29.*".to_string(),
                "172.30.*".to_string(),
                "172.31.*".to_string(),
                "192.168.*".to_string(),
                "*.local".to_string(),
                "<local>".to_string(),
            ],
            pac: PacConfig::default(),
        }
    }
}

impl SystemProxyConfig {
    /// Build a platform-layer `SystemProxySpec` from this config and active mixed port.
    pub fn to_platform_spec(&self, host: &str, mixed_port: u16) -> SystemProxySpec {
        let pac_url = if self.pac.enabled {
            Some(format!("http://127.0.0.1:{}/proxy.pac", self.pac.port))
        } else {
            None
        };
        SystemProxySpec {
            enabled: self.enabled,
            host: host.to_string(),
            port: mixed_port,
            bypass: self.bypass.clone(),
            pac_url,
        }
    }
}

/// Virtual NIC TCP/IP stack implementation for TUN mode.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum TunStackMode {
    #[default]
    Mixed,
    System,
    Gvisor,
}

impl TunStackMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Mixed => "mixed",
            Self::System => "system",
            Self::Gvisor => "gvisor",
        }
    }
}

/// TUN virtual network interface configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct TunConfig {
    pub enabled: bool,
    pub stack_mode: TunStackMode,
    pub service_mode: bool,
    pub auto_route: bool,
    pub auto_detect_interface: bool,
    pub strict_route: bool,
    pub dns_hijack: Vec<String>,
    pub mtu: u16,
    pub device_name: String,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            stack_mode: TunStackMode::Mixed,
            service_mode: false,
            auto_route: true,
            auto_detect_interface: true,
            strict_route: false,
            dns_hijack: vec!["any:53".to_string(), "tcp://any:53".to_string()],
            mtu: 9000,
            device_name: "CatCloud".to_string(),
        }
    }
}

/// Mihomo DNS enhanced resolution mode.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum DnsMode {
    #[default]
    #[serde(rename = "fake-ip")]
    FakeIp,
    #[serde(rename = "redir-host")]
    RedirHost,
}

impl DnsMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FakeIp => "fake-ip",
            Self::RedirHost => "redir-host",
        }
    }
}

/// DNS fallback filter controlling when fallback resolvers are authoritative.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct DnsFallbackFilter {
    pub geoip: bool,
    pub geoip_code: String,
    pub geosite: Vec<String>,
    pub ipcidr: Vec<String>,
    pub domain: Vec<String>,
}

impl Default for DnsFallbackFilter {
    fn default() -> Self {
        Self {
            geoip: true,
            geoip_code: "CN".to_string(),
            geosite: vec!["gfw".to_string()],
            ipcidr: vec!["240.0.0.0/4".to_string(), "0.0.0.0/32".to_string()],
            domain: vec![
                "+.google.com".to_string(),
                "+.facebook.com".to_string(),
                "+.youtube.com".to_string(),
            ],
        }
    }
}

/// Full advanced DNS configuration (DNS IPv6 is controlled independently from `core_ipv6`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct DnsConfig {
    pub enable: bool,
    pub override_dns: bool,
    pub ipv6: bool,
    pub use_hosts: bool,
    pub hosts: BTreeMap<String, String>,
    pub use_system_hosts: bool,
    pub respect_rules: bool,
    pub prefer_h3: bool,
    #[serde(alias = "enhanced_mode")]
    pub mode: DnsMode,
    pub fake_ip_range: String,
    pub fake_ip_filter: Vec<String>,
    pub default_nameserver: Vec<String>,
    pub nameserver_policy: BTreeMap<String, Vec<String>>,
    pub nameserver: Vec<String>,
    pub fallback: Vec<String>,
    pub proxy_server_nameserver: Vec<String>,
    pub fallback_filter: DnsFallbackFilter,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enable: true,
            override_dns: true,
            ipv6: false,
            use_hosts: true,
            hosts: BTreeMap::new(),
            use_system_hosts: true,
            respect_rules: false,
            prefer_h3: false,
            mode: DnsMode::FakeIp,
            fake_ip_range: "198.18.0.1/16".to_string(),
            fake_ip_filter: vec![
                "*.lan".to_string(),
                "*.local".to_string(),
                "localhost.ptlogin2.qq.com".to_string(),
                "time.*.com".to_string(),
                "ntp.*.com".to_string(),
                "+.stun.*.*".to_string(),
                "+.msftconnecttest.com".to_string(),
                "+.msftncsi.com".to_string(),
                "connectivitycheck.platform.hicloud.com".to_string(),
                "connect.rom.miui.com".to_string(),
            ],
            default_nameserver: vec!["223.5.5.5".to_string(), "119.29.29.29".to_string()],
            nameserver_policy: BTreeMap::new(),
            nameserver: vec![
                "https://dns.alidns.com/dns-query".to_string(),
                "https://doh.pub/dns-query".to_string(),
            ],
            fallback: vec![
                "https://1.1.1.1/dns-query".to_string(),
                "https://8.8.8.8/dns-query".to_string(),
            ],
            proxy_server_nameserver: vec!["223.5.5.5".to_string(), "119.29.29.29".to_string()],
            fallback_filter: DnsFallbackFilter::default(),
        }
    }
}

/// Config override pipeline mode.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum OverrideMode {
    #[default]
    Disabled,
    MergePatch,
    Script,
    Both,
}

/// Global user rules and external merge/script override settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RulesAndOverrideConfig {
    pub global_prepend_rules: Vec<String>,
    pub global_append_rules: Vec<String>,
    pub override_mode: OverrideMode,
    pub override_merge_path: Option<String>,
    pub override_script_path: Option<String>,
    pub override_script_timeout_ms: u64,
}

impl Default for RulesAndOverrideConfig {
    fn default() -> Self {
        Self {
            global_prepend_rules: Vec::new(),
            global_append_rules: Vec::new(),
            override_mode: OverrideMode::Disabled,
            override_merge_path: None,
            override_script_path: None,
            override_script_timeout_ms: 5000,
        }
    }
}

/// GeoIP / GeoSite / MMDB / ASN database URLs and memory-conscious loader settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct GeoDataConfig {
    /// Defaults to `false` (lightweight MMDB + `.mrs`); when `true`, pairs with `memconservative`.
    pub geodata_mode: bool,
    pub geodata_loader: String,
    pub auto_update: bool,
    pub update_interval_hours: u32,
    pub geoip_url: String,
    pub geosite_url: String,
    pub mmdb_url: String,
    pub asn_url: String,
}

impl Default for GeoDataConfig {
    fn default() -> Self {
        Self {
            geodata_mode: false,
            geodata_loader: "memconservative".to_string(),
            auto_update: false,
            update_interval_hours: 168,
            geoip_url: "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geoip.dat".to_string(),
            geosite_url: "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geosite.dat".to_string(),
            mmdb_url: "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/country-lite.mmdb".to_string(),
            asn_url: "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/GeoLite2-ASN.mmdb".to_string(),
        }
    }
}

/// Supported core backend types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CoreKind {
    #[default]
    Mihomo,
    SingBox,
    Xray,
}

/// Adaptive three-tier `GOMEMLIMIT` budget for Mihomo (`48|64|96MiB`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MemoryLimitTier {
    /// Auto-select 48 / 64 / 96 MiB based on active node and rule counts.
    #[default]
    Auto,
    #[serde(rename = "48MiB", alias = "mb48")]
    Mb48,
    #[serde(rename = "64MiB", alias = "mb64")]
    Mb64,
    #[serde(rename = "96MiB", alias = "mb96")]
    Mb96,
}

impl MemoryLimitTier {
    /// Resolve concrete `GOMEMLIMIT` value in MiB for the given scale.
    pub fn resolve_mib(&self, node_count: usize, rule_count: usize) -> u32 {
        match self {
            Self::Mb48 => 48,
            Self::Mb64 => 64,
            Self::Mb96 => 96,
            Self::Auto => {
                if node_count >= 600 || rule_count >= 5000 {
                    96
                } else if node_count >= 200 || rule_count >= 1500 {
                    64
                } else {
                    48
                }
            }
        }
    }

    /// Format concrete `GOMEMLIMIT` environment string (e.g. `"48MiB"`).
    pub fn resolve_env_value(&self, node_count: usize, rule_count: usize) -> &'static str {
        match self.resolve_mib(node_count, rule_count) {
            96 => "96MiB",
            64 => "64MiB",
            _ => "48MiB",
        }
    }
}

/// Quick website reachability check card shown on the home dashboard.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct QuickCheckSite {
    pub id: String,
    pub name: String,
    pub url: String,
    pub expected_status: Option<u16>,
}

impl Default for QuickCheckSite {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            url: String::new(),
            expected_status: Some(200),
        }
    }
}

/// Core runtime tuning and kernel binary preferences.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct CoreRuntimeConfig {
    pub kernel_kind: CoreKind,
    pub custom_binary_path: Option<String>,
    pub memory_tier: MemoryLimitTier,
    pub gogc: u32,
    pub store_selected: bool,
    pub store_fake_ip: bool,
    pub startup_script_path: Option<String>,
    pub quick_check_sites: Vec<QuickCheckSite>,
}

impl Default for CoreRuntimeConfig {
    fn default() -> Self {
        Self {
            kernel_kind: CoreKind::Mihomo,
            custom_binary_path: None,
            memory_tier: MemoryLimitTier::Auto,
            gogc: 35,
            store_selected: false,
            store_fake_ip: false,
            startup_script_path: None,
            quick_check_sites: vec![
                QuickCheckSite {
                    id: "google".to_string(),
                    name: "Google".to_string(),
                    url: "https://www.google.com/generate_204".to_string(),
                    expected_status: Some(204),
                },
                QuickCheckSite {
                    id: "github".to_string(),
                    name: "GitHub".to_string(),
                    url: "https://github.com".to_string(),
                    expected_status: Some(200),
                },
                QuickCheckSite {
                    id: "youtube".to_string(),
                    name: "YouTube".to_string(),
                    url: "https://www.youtube.com/generate_204".to_string(),
                    expected_status: Some(204),
                },
                QuickCheckSite {
                    id: "openai".to_string(),
                    name: "OpenAI".to_string(),
                    url: "https://chatgpt.com".to_string(),
                    expected_status: Some(200),
                },
            ],
        }
    }
}

/// Domestic pre-acceleration configuration.
/// Probe URLs must point to domestic endpoints (`hicloud` / `miui`), never overseas `gstatic`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct PreAccelConfig {
    pub enabled: bool,
    pub skip_443_native: bool,
    pub probe_url: String,
    pub fallback_probe_url: String,
    pub probe_interval_sec: u64,
    pub active_relay_id: Option<String>,
    pub auto_failover: bool,
    pub campus_portal_guard: bool,
    pub campus_direct_domains: Vec<String>,
}

impl Default for PreAccelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            skip_443_native: true,
            probe_url: DEFAULT_PREACCEL_PROBE_URL.to_string(),
            fallback_probe_url: DEFAULT_PREACCEL_FALLBACK_PROBE_URL.to_string(),
            probe_interval_sec: 30,
            active_relay_id: None,
            auto_failover: true,
            campus_portal_guard: true,
            campus_direct_domains: Vec::new(),
        }
    }
}

/// Action triggered by left or middle clicking the system tray icon.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TrayClickAction {
    #[default]
    ToggleMainWindow,
    OpenMainWindow,
    ToggleCapsule,
    ToggleSystemProxy,
    SwitchNextBest,
    None,
}

/// Global keyboard shortcuts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct HotkeyConfig {
    pub enabled: bool,
    pub switch_next_best: Option<String>,
    pub toggle_capsule: Option<String>,
    pub toggle_system_proxy: Option<String>,
    pub toggle_tun: Option<String>,
    pub show_main_window: Option<String>,
    pub proxy_mode_rule: Option<String>,
    pub proxy_mode_global: Option<String>,
    pub proxy_mode_direct: Option<String>,
}

impl Default for HotkeyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            switch_next_best: Some("Alt+Shift+N".to_string()),
            toggle_capsule: Some("Alt+Shift+C".to_string()),
            toggle_system_proxy: None,
            toggle_tun: None,
            show_main_window: None,
            proxy_mode_rule: None,
            proxy_mode_global: None,
            proxy_mode_direct: None,
        }
    }
}

/// Desktop lifecycle, autostart, silent launch, tray actions, and hotkeys.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AppBehaviorConfig {
    pub autostart: bool,
    pub silent_start: bool,
    pub minimize_to_tray_on_close: bool,
    pub startup_page: String,
    pub tray_click_action: TrayClickAction,
    pub tray_middle_click_action: TrayClickAction,
    pub hotkeys: HotkeyConfig,
}

impl Default for AppBehaviorConfig {
    fn default() -> Self {
        Self {
            autostart: false,
            silent_start: false,
            minimize_to_tray_on_close: true,
            startup_page: "home".to_string(),
            tray_click_action: TrayClickAction::ToggleMainWindow,
            tray_middle_click_action: TrayClickAction::ToggleCapsule,
            hotkeys: HotkeyConfig::default(),
        }
    }
}

/// Visual theme selection mode.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ThemeMode {
    #[default]
    AutoTime,
    Light,
    WarmDark,
    MidnightBlue,
}

/// Three-phase diurnal theme schedule (local time `HH:MM`).
/// Defaults: `07:00-18:30` Light, `18:30-22:30` WarmDark, `22:30-07:00` MidnightBlue.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ThemeDaySchedule {
    pub light_start: String,
    pub warm_dark_start: String,
    pub midnight_blue_start: String,
}

impl Default for ThemeDaySchedule {
    fn default() -> Self {
        Self {
            light_start: "07:00".to_string(),
            warm_dark_start: "18:30".to_string(),
            midnight_blue_start: "22:30".to_string(),
        }
    }
}

/// System tray icon mapping policy across the pre-baked icon sets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TrayIconMode {
    /// Default mapping: `idle/ok -> A`, `preaccel/warn/error -> C`.
    #[default]
    AutoAc,
    AlwaysA,
    AlwaysC,
    AlwaysPixel,
}

/// Personalization, wallpaper, motion switches, and tray icon set preferences.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct PersonalizationConfig {
    pub theme_mode: ThemeMode,
    pub day_schedule: ThemeDaySchedule,
    pub wallpaper_path: Option<String>,
    #[serde(alias = "opacity")]
    pub wallpaper_opacity: f32,
    #[serde(alias = "blur", alias = "wallpaper_blur_px")]
    pub wallpaper_blur: u32,
    pub animations_enabled: bool,
    pub mascot_enabled: bool,
    pub sparkline_enabled: bool,
    pub tray_icon_mode: TrayIconMode,
    pub language: String,
    pub capsule_enabled: bool,
}

impl Default for PersonalizationConfig {
    fn default() -> Self {
        Self {
            theme_mode: ThemeMode::AutoTime,
            day_schedule: ThemeDaySchedule::default(),
            wallpaper_path: None,
            wallpaper_opacity: 0.25,
            wallpaper_blur: 12,
            animations_enabled: true,
            mascot_enabled: true,
            sparkline_enabled: true,
            tray_icon_mode: TrayIconMode::AutoAc,
            language: "zh-CN".to_string(),
            capsule_enabled: false,
        }
    }
}

/// How downloaded updates are applied.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum UpdateApplyMode {
    #[default]
    NextLaunch,
    Manual,
    AutoRestart,
}

/// GitHub Releases automatic update configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct UpdateConfig {
    pub repo: String,
    pub mode: UpdateApplyMode,
    pub check_interval_min: u64,
    pub include_prerelease: bool,
    pub auto_download: bool,
    pub last_checked_at: Option<String>,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            repo: DEFAULT_UPDATE_REPO.to_string(),
            mode: UpdateApplyMode::NextLaunch,
            check_interval_min: 360,
            include_prerelease: false,
            auto_download: true,
            last_checked_at: None,
        }
    }
}

/// Reserved V2 WebDAV cloud backup endpoint fields (disabled by default in V1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct WebDavReserveConfig {
    pub enabled: bool,
    pub endpoint_url: Option<String>,
    pub username: Option<String>,
}

/// Complete strongly-typed application configuration persisted atomically to `data/config.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AppConfig {
    pub schema_version: u32,
    pub proxy_mode: ProxyMode,
    #[serde(default)]
    pub active_group_id: Option<String>,
    pub mixed_port: u16,
    pub socks_port: Option<u16>,
    pub http_port: Option<u16>,
    pub redir_port: Option<u16>,
    pub tproxy_port: Option<u16>,
    pub allow_lan: bool,
    pub bind_address: String,
    pub controller_host: String,
    pub controller_port: u16,
    pub controller_secret: Option<String>,
    pub webui_urls: Vec<WebUiEntry>,
    pub dns_listen_host: String,
    pub dns_listen_port: u16,
    pub unified_delay: bool,
    pub tcp_concurrent: bool,
    pub find_process_mode: FindProcessMode,
    pub log_level: CoreLogLevel,
    /// Core data-plane IPv6 switch (controlled separately from `dns.ipv6`).
    pub core_ipv6: bool,
    pub port_guard_auto_shift: bool,
    pub system_proxy: SystemProxyConfig,
    pub tun: TunConfig,
    pub dns: DnsConfig,
    pub rules_override: RulesAndOverrideConfig,
    pub geodata: GeoDataConfig,
    pub core_runtime: CoreRuntimeConfig,
    pub preaccel: PreAccelConfig,
    pub behavior: AppBehaviorConfig,
    pub personalization: PersonalizationConfig,
    pub update: UpdateConfig,
    pub webdav_reserve: WebDavReserveConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            proxy_mode: ProxyMode::Rule,
            active_group_id: None,
            mixed_port: 7890,
            socks_port: None,
            http_port: None,
            redir_port: None,
            tproxy_port: None,
            allow_lan: false,
            bind_address: "127.0.0.1".to_string(),
            controller_host: "127.0.0.1".to_string(),
            controller_port: 9090,
            controller_secret: None,
            webui_urls: vec![
                WebUiEntry::default(),
                WebUiEntry {
                    name: "Yacd-meta".to_string(),
                    url_template: "https://yacd.metacubex.one/#/setup?hostname={host}&port={port}&secret={secret}".to_string(),
                },
            ],
            dns_listen_host: "127.0.0.1".to_string(),
            dns_listen_port: 1053,
            unified_delay: true,
            tcp_concurrent: true,
            find_process_mode: FindProcessMode::Strict,
            log_level: CoreLogLevel::Info,
            core_ipv6: false,
            port_guard_auto_shift: true,
            system_proxy: SystemProxyConfig::default(),
            tun: TunConfig::default(),
            dns: DnsConfig::default(),
            rules_override: RulesAndOverrideConfig::default(),
            geodata: GeoDataConfig::default(),
            core_runtime: CoreRuntimeConfig::default(),
            preaccel: PreAccelConfig::default(),
            behavior: AppBehaviorConfig::default(),
            personalization: PersonalizationConfig::default(),
            update: UpdateConfig::default(),
            webdav_reserve: WebDavReserveConfig::default(),
        }
    }
}

impl AppConfig {
    /// Formatted `host:port` string for the Mihomo external controller.
    pub fn controller_addr(&self) -> String {
        format!("{}:{}", self.controller_host, self.controller_port)
    }

    /// Formatted `host:port` string for the Mihomo DNS listener.
    pub fn dns_listen_addr(&self) -> String {
        format!("{}:{}", self.dns_listen_host, self.dns_listen_port)
    }

    /// Resolve `GOMEMLIMIT` environment variable value for the given node and rule counts.
    pub fn resolve_gomemlimit(&self, node_count: usize, rule_count: usize) -> &'static str {
        self.core_runtime
            .memory_tier
            .resolve_env_value(node_count, rule_count)
    }
}
