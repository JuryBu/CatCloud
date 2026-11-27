use crate::platform::SystemProxySpec;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Current configuration schema version.
pub const CONFIG_SCHEMA_VERSION: u32 = 4;

/// Legacy v3 pure-IP DoH (TCP 443) domestic resolver defaults, kept for backward compatibility
/// and idempotent v3 -> v4 schema migration detection.
pub const DEFAULT_PURE_IP_DOH_NAMESERVERS: &[&str] = &[
    "https://223.5.5.5/dns-query",
    "https://1.12.12.12/dns-query",
];

/// Default 4-endpoint heterogeneous pure-IP encrypted domestic DNS pool
/// (2x TCP/443 DoH + 2x TCP/853 DoT, all strictly TLS-verified with IP SANs; never `skip-cert-verify`).
pub const DEFAULT_PURE_IP_ENCRYPTED_NAMESERVERS: &[&str] = &[
    "https://223.5.5.5/dns-query",
    "https://1.12.12.12/dns-query",
    "tls://223.6.6.6:853",
    "tls://120.53.53.53:853",
];

/// Supported UI localization codes (Simplified Chinese authoritative default).
pub const SUPPORTED_UI_LANGUAGES: &[&str] = &["zh-CN", "en", "ja", "ru"];

/// Normalize a raw UI language code (including regional aliases such as `en-US`, `ja-JP`, `ru-RU`,
/// or `zh_CN`) to one of the four supported canonical codes (`"zh-CN" | "en" | "ja" | "ru"`),
/// falling back to `"zh-CN"` for blank or unrecognized inputs.
pub fn normalize_ui_language(raw: &str) -> &'static str {
    let lower = raw.trim().replace('_', "-").to_ascii_lowercase();
    if lower == "en" || lower.starts_with("en-") {
        "en"
    } else if lower == "ja" || lower.starts_with("ja-") || lower == "jp" {
        "ja"
    } else if lower == "ru" || lower.starts_with("ru-") {
        "ru"
    } else {
        "zh-CN"
    }
}

/// Return `true` when `raw` matches a supported UI language code or standard regional variant.
pub fn is_supported_ui_language(raw: &str) -> bool {
    let lower = raw.trim().replace('_', "-").to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "zh" | "zh-cn" | "zh-hans" | "en" | "en-us" | "en-gb" | "ja" | "ja-jp" | "ru" | "ru-ru"
    )
}

fn default_legacy_schema_version() -> u32 {
    1
}

/// Default domestic 204 connectivity probe URL (never use overseas domains).
pub const DEFAULT_PREACCEL_PROBE_URL: &str =
    "http://connectivitycheck.platform.hicloud.com/generate_204";

/// Default fallback domestic 204 probe URL for networks blocking primary host/port.
pub const DEFAULT_PREACCEL_FALLBACK_PROBE_URL: &str =
    "http://connect.rom.miui.com/generate_204";

/// Default public GitHub repository for automatic updates.
pub const DEFAULT_UPDATE_REPO: &str = "JuryBu/CatCloud";

/// Default global shortcut for switching to the next best node.
/// Cross-platform semantics: `Alt+Shift+N` on Windows/Linux (`Option+Shift+N` on macOS).
pub const DEFAULT_HOTKEY_SWITCH_NEXT_BEST: &str = "Alt+Shift+N";

/// Default global shortcut for toggling the floating capsule window.
/// Cross-platform semantics: `Alt+Shift+C` on Windows/Linux (`Option+Shift+C` on macOS).
pub const DEFAULT_HOTKEY_TOGGLE_CAPSULE: &str = "Alt+Shift+C";

/// Default target executable names intercepted by the standalone global domestic :443
/// pre-acceleration engine when `global_scope == GlobalPreAccelScope::ProxyAppsOnly`.
///
/// Only generic open-source proxy cores and remote transfer tools are listed here;
/// third-party proxy hosts are detected dynamically at runtime.
pub const DEFAULT_GLOBAL_PREACCEL_PROCESSES: &[&str] = &[
    "mihomo.exe",
    "clash-meta.exe",
    "clash.exe",
    "xray.exe",
    "sing-box.exe",
    "v2ray.exe",
    "hysteria.exe",
    "tuic-client.exe",
    "ssh.exe",
    "scp.exe",
    "sftp.exe",
    "rsync.exe",
];

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

/// Active routing target mode: smart multi-group (`group`) or direct single-node (`single`).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RouteTargetMode {
    #[default]
    Group,
    Single,
}

impl RouteTargetMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Group => "group",
            Self::Single => "single",
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
                "127.0.0.1".to_string(),
                "::1".to_string(),
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
            strict_route: true,
            dns_hijack: vec!["any:53".to_string(), "tcp://any:53".to_string()],
            mtu: 1500,
            device_name: "CatCloud".to_string(),
        }
    }
}

fn default_direct_nameserver() -> Vec<String> {
    DEFAULT_PURE_IP_ENCRYPTED_NAMESERVERS
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

fn default_true_bool() -> bool {
    true
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
                "+.googleapis.com".to_string(),
                "+.gstatic.com".to_string(),
                "+.googleusercontent.com".to_string(),
                "+.youtube.com".to_string(),
                "+.facebook.com".to_string(),
                "+.anthropic.com".to_string(),
                "+.claude.ai".to_string(),
                "+.claude.com".to_string(),
                "+.openai.com".to_string(),
                "+.chatgpt.com".to_string(),
                "+.github.com".to_string(),
                "+.windsurf.com".to_string(),
                "+.codeium.com".to_string(),
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
    #[serde(default = "default_direct_nameserver")]
    pub direct_nameserver: Vec<String>,
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
            respect_rules: true,
            prefer_h3: false,
            mode: DnsMode::FakeIp,
            fake_ip_range: "198.18.0.1/16".to_string(),
            fake_ip_filter: vec![
                "*.lan".to_string(),
                "+.lan".to_string(),
                "*.local".to_string(),
                "+.local".to_string(),
                "+.localdomain".to_string(),
                "*.home.arpa".to_string(),
                "localhost.ptlogin2.qq.com".to_string(),
                "time.*.com".to_string(),
                "time.*.gov".to_string(),
                "time.*.edu.cn".to_string(),
                "ntp.*.com".to_string(),
                "+.pool.ntp.org".to_string(),
                "+.stun.*.*".to_string(),
                "+.msftconnecttest.com".to_string(),
                "+.msftncsi.com".to_string(),
                "dns.msftncsi.com".to_string(),
                "connectivitycheck.platform.hicloud.com".to_string(),
                "connect.rom.miui.com".to_string(),
            ],
            default_nameserver: default_direct_nameserver(),
            direct_nameserver: default_direct_nameserver(),
            nameserver_policy: BTreeMap::new(),
            nameserver: default_direct_nameserver(),
            fallback: vec![
                "https://1.1.1.1/dns-query".to_string(),
                "https://8.8.8.8/dns-query".to_string(),
            ],
            proxy_server_nameserver: default_direct_nameserver(),
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

/// Hard upper bound (1 MiB) for inline YAML merge-patch overrides stored in `config.json`.
pub const MAX_INLINE_OVERRIDE_YAML_BYTES: usize = 1024 * 1024;

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
    #[serde(default = "default_true_bool")]
    pub block_quic_udp_443: bool,
    #[serde(default = "default_true_bool")]
    pub domestic_direct_enabled: bool,
    /// Pure custom-rules mode: keeps anti-loop / probe bypass / private LAN safety guards
    /// and user-authored rules while skipping built-in QUIC blocking, group auto match rules,
    /// built-in domestic direct lists, and built-in AI DNS policy overrides.
    #[serde(default)]
    pub custom_rules_only: bool,
    /// Optional inline Mihomo YAML Merge Patch (e.g. `rule-providers:` / `rules:` / `dns:`)
    /// applied directly during compilation without requiring an external file (<= 1 MiB).
    #[serde(default)]
    pub inline_override_yaml: Option<String>,
}

/// Compatibility alias for `RulesAndOverrideConfig`.
pub type RulesOverrideConfig = RulesAndOverrideConfig;

impl Default for RulesAndOverrideConfig {
    fn default() -> Self {
        Self {
            global_prepend_rules: Vec::new(),
            global_append_rules: Vec::new(),
            override_mode: OverrideMode::Disabled,
            override_merge_path: None,
            override_script_path: None,
            override_script_timeout_ms: 5000,
            block_quic_udp_443: true,
            domestic_direct_enabled: true,
            custom_rules_only: false,
            inline_override_yaml: None,
        }
    }
}

impl RulesAndOverrideConfig {
    /// Validate optional `inline_override_yaml` payload size (<= 1 MiB) and YAML mapping syntax.
    pub fn validate_inline_override_yaml(&self) -> Result<(), String> {
        let Some(raw) = self.inline_override_yaml.as_deref() else {
            return Ok(());
        };
        validate_inline_override_yaml_text(raw)
    }
}

/// Validate a raw inline YAML merge-patch snippet (<= 1 MiB, valid YAML syntax, top-level mapping).
pub fn validate_inline_override_yaml_text(raw: &str) -> Result<(), String> {
    if raw.trim().is_empty() {
        return Ok(());
    }
    if raw.len() > MAX_INLINE_OVERRIDE_YAML_BYTES {
        return Err(format!(
            "内联 YAML 覆写片段超出 1 MiB 大小限制（当前 {} 字节，最大 {} 字节）",
            raw.len(),
            MAX_INLINE_OVERRIDE_YAML_BYTES
        ));
    }
    let mut parsed: serde_yaml_ng::Value = serde_yaml_ng::from_str(raw).map_err(|e| {
        format!("内联 YAML 覆写片段存在语法错误，无法解析：{e}")
    })?;
    parsed.apply_merge().map_err(|e| {
        format!("内联 YAML 覆写片段的锚点合并（<<）解析失败：{e}")
    })?;
    if !parsed.is_mapping() {
        return Err(
            "内联 YAML 覆写片段的根节点必须是 YAML 键值对映射（例如 rule-providers: / rules: / dns:）"
                .to_string(),
        );
    }
    Ok(())
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

/// Adaptive `GOMEMLIMIT` budget for Mihomo (`Auto` -> `40|56|88MiB`; explicit `48|64|96MiB`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MemoryLimitTier {
    /// Auto-select 40 / 56 / 88 MiB based on compiled proxy and rule counts.
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
                if node_count >= 350 || rule_count >= 5000 {
                    88
                } else if node_count >= 100 || rule_count >= 1500 {
                    56
                } else {
                    40
                }
            }
        }
    }

    /// Format concrete `GOMEMLIMIT` environment string (e.g. `"40MiB"`).
    pub fn resolve_env_value(&self, node_count: usize, rule_count: usize) -> &'static str {
        match self.resolve_mib(node_count, rule_count) {
            96 => "96MiB",
            88 => "88MiB",
            64 => "64MiB",
            56 => "56MiB",
            48 => "48MiB",
            _ => "40MiB",
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
    #[serde(default)]
    pub compile_all_nodes: bool,
    pub startup_script_path: Option<String>,
    pub quick_check_sites: Vec<QuickCheckSite>,
}

impl Default for CoreRuntimeConfig {
    fn default() -> Self {
        Self {
            kernel_kind: CoreKind::Mihomo,
            custom_binary_path: None,
            memory_tier: MemoryLimitTier::Auto,
            gogc: 25,
            store_selected: false,
            store_fake_ip: false,
            compile_all_nodes: false,
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
                    url: "https://chatgpt.com/cdn-cgi/trace".to_string(),
                    expected_status: Some(200),
                },
            ],
        }
    }
}

/// Scope controlling which outbound non-443 TCP connections are intercepted by the
/// standalone global domestic :443 pre-acceleration engine.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GlobalPreAccelScope {
    /// Intercept only third-party proxy cores and configured transfer tools
    /// (`global_target_processes`), leaving unrelated applications untouched.
    #[default]
    ProxyAppsOnly,
    /// Intercept all public non-443/non-53 TCP connections on physical interfaces
    /// (always excluding core OS services, CatCloud itself, and the standalone 443 tunnel).
    #[serde(rename = "all_non_443_tcp", alias = "all_non443_tcp")]
    AllNon443Tcp,
}

impl GlobalPreAccelScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProxyAppsOnly => "proxy_apps_only",
            Self::AllNon443Tcp => "all_non_443_tcp",
        }
    }
}

fn default_global_target_processes() -> Vec<String> {
    DEFAULT_GLOBAL_PREACCEL_PROCESSES
        .iter()
        .map(|name| (*name).to_string())
        .collect()
}

/// Multi-cloud dispatch strategy for domestic `:443` pre-acceleration relays.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PreAccelDispatchStrategy {
    /// Automatically aggregate 2+ distinct physical cloud hosts with nested `load-balance`
    /// inside outer `fallback`, or use single-layer `fallback` for 1 physical host.
    #[default]
    Auto,
    /// Explicitly prefer multi-cloud nested `load-balance` when 2+ distinct physical hosts exist.
    LoadBalance,
    /// Always use single-layer active-standby `fallback` ordering.
    Fallback,
}

impl PreAccelDispatchStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::LoadBalance => "load_balance",
            Self::Fallback => "fallback",
        }
    }
}

/// Load-balancing algorithm used by the inner multi-cloud domestic pre-acceleration pool.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PreAccelLbStrategy {
    #[serde(alias = "round-robin")]
    RoundRobin,
    #[default]
    #[serde(alias = "consistent-hashing")]
    ConsistentHashing,
}

impl PreAccelLbStrategy {
    /// Canonical Mihomo YAML `load-balance.strategy` string (`"round-robin"` | `"consistent-hashing"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RoundRobin => "round-robin",
            Self::ConsistentHashing => "consistent-hashing",
        }
    }

    /// Canonical snake_case config/CLI string (`"round_robin"` | `"consistent_hashing"`).
    pub fn as_config_str(self) -> &'static str {
        match self {
            Self::RoundRobin => "round_robin",
            Self::ConsistentHashing => "consistent_hashing",
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
    /// Dispatch mode across multiple distinct physical domestic cloud hosts.
    #[serde(default)]
    pub dispatch_strategy: PreAccelDispatchStrategy,
    /// Load-balancing algorithm for the inner multi-cloud `load-balance` pool.
    #[serde(default)]
    pub lb_strategy: PreAccelLbStrategy,
    pub campus_portal_guard: bool,
    pub campus_direct_domains: Vec<String>,
    /// Allow standalone lowest-level domestic :443 pre-acceleration even when CatCloud's own
    /// main proxy is disabled, transparently accelerating third-party proxy cores or CLI tools.
    #[serde(default)]
    pub global_bypass_enabled: bool,
    /// Traffic scope for the standalone global :443 pre-acceleration engine.
    #[serde(default)]
    pub global_scope: GlobalPreAccelScope,
    /// Executable filenames accelerated when `global_scope == GlobalPreAccelScope::ProxyAppsOnly`.
    #[serde(default = "default_global_target_processes")]
    pub global_target_processes: Vec<String>,
    /// Optional custom directory containing `WinDivert64.dll` (or `WinDivert.dll`) and `WinDivert64.sys`.
    #[serde(default)]
    pub windivert_dir: Option<String>,
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
            dispatch_strategy: PreAccelDispatchStrategy::Auto,
            lb_strategy: PreAccelLbStrategy::ConsistentHashing,
            campus_portal_guard: true,
            campus_direct_domains: Vec::new(),
            global_bypass_enabled: false,
            global_scope: GlobalPreAccelScope::ProxyAppsOnly,
            global_target_processes: default_global_target_processes(),
            windivert_dir: None,
        }
    }
}

impl PreAccelConfig {
    /// Synchronize the unified domestic pre-acceleration master switch so both
    /// in-core (`enabled`) and standalone/global (`global_bypass_enabled`) flags
    /// always stay aligned as a single source of truth.
    pub fn sync_unified_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        self.global_bypass_enabled = enabled;
    }

    /// Reconcile legacy split flags (`enabled` vs `global_bypass_enabled`) into one
    /// unified master switch state and align both fields in-place.
    pub fn reconcile_unified_enabled(&mut self) -> bool {
        let unified = self.enabled || self.global_bypass_enabled;
        self.sync_unified_enabled(unified);
        unified
    }

    /// Return whether the unified domestic pre-acceleration master switch is enabled.
    pub fn is_unified_enabled(&self) -> bool {
        self.enabled
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
///
/// Default accelerators use `Alt+Shift+N` / `Alt+Shift+C` (`Option+Shift+N` / `Option+Shift+C`
/// on macOS), matching `src-tauri/src/shortcuts.rs` across Windows, macOS, and Linux.
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
            switch_next_best: Some(DEFAULT_HOTKEY_SWITCH_NEXT_BEST.to_string()),
            toggle_capsule: Some(DEFAULT_HOTKEY_TOGGLE_CAPSULE.to_string()),
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
    #[serde(alias = "ui_language")]
    pub language: String,
    pub capsule_enabled: bool,
    /// Whether the user has completed (or dismissed) the first-launch welcome & AI autopilot modal.
    #[serde(default)]
    pub onboarding_completed: bool,
}

impl PersonalizationConfig {
    /// Return the normalized canonical UI language (`"zh-CN" | "en" | "ja" | "ru"`),
    /// falling back to `"zh-CN"` when empty or unrecognized.
    pub fn normalized_ui_language(&self) -> &'static str {
        normalize_ui_language(&self.language)
    }
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
            onboarding_completed: false,
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
    /// Normalized SemVer string (without leading `v`/`V`) explicitly skipped by the user.
    #[serde(default)]
    pub skipped_version: Option<String>,
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
            skipped_version: None,
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
    #[serde(default = "default_legacy_schema_version")]
    pub schema_version: u32,
    pub proxy_mode: ProxyMode,
    #[serde(default)]
    pub route_mode: RouteTargetMode,
    #[serde(default)]
    pub active_single_node_id: Option<String>,
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
            route_mode: RouteTargetMode::Group,
            active_single_node_id: None,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardened_network_defaults_and_legacy_json_backcompat() {
        let cfg = AppConfig::default();
        assert_eq!(cfg.tun.mtu, 1500);
        assert!(cfg.tun.strict_route);
        assert_eq!(cfg.tun.stack_mode, TunStackMode::Mixed);
        assert!(cfg.tun.auto_route);
        assert!(cfg.tun.auto_detect_interface);

        assert!(cfg.dns.respect_rules);
        let expected_encrypted = vec![
            "https://223.5.5.5/dns-query",
            "https://1.12.12.12/dns-query",
            "tls://223.6.6.6:853",
            "tls://120.53.53.53:853",
        ];
        assert_eq!(cfg.dns.default_nameserver, expected_encrypted);
        assert_eq!(cfg.dns.direct_nameserver, expected_encrypted);
        assert_eq!(cfg.dns.proxy_server_nameserver, expected_encrypted);
        assert_eq!(cfg.dns.nameserver, expected_encrypted);
        assert_eq!(
            cfg.dns.fallback,
            vec!["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]
        );
        assert!(cfg.dns.fallback_filter.domain.iter().any(|d| d == "+.anthropic.com"));
        assert!(cfg.dns.fallback_filter.domain.iter().any(|d| d == "+.windsurf.com"));
        assert!(cfg.dns.fake_ip_filter.iter().any(|d| d == "+.localdomain"));
        assert!(cfg.dns.fake_ip_filter.iter().any(|d| d == "time.*.edu.cn"));

        assert!(cfg.rules_override.block_quic_udp_443);
        assert!(cfg.rules_override.domestic_direct_enabled);
        assert_eq!(cfg.core_runtime.gogc, 25);
        assert!(!cfg.core_runtime.compile_all_nodes);
        assert_eq!(cfg.resolve_gomemlimit(20, 100), "40MiB");
        assert_eq!(cfg.resolve_gomemlimit(99, 1499), "40MiB");
        assert_eq!(cfg.resolve_gomemlimit(100, 100), "56MiB");
        assert_eq!(cfg.resolve_gomemlimit(349, 100), "56MiB");
        assert_eq!(cfg.resolve_gomemlimit(350, 100), "88MiB");

        let openai_site = cfg
            .core_runtime
            .quick_check_sites
            .iter()
            .find(|s| s.id == "openai")
            .expect("default openai quick check site");
        assert_eq!(openai_site.url, "https://chatgpt.com/cdn-cgi/trace");
        assert_eq!(openai_site.expected_status, Some(200));

        // Legacy JSON missing newly added fields must populate defaults via serde attributes.
        let legacy: AppConfig =
            serde_json::from_str(r#"{"dns":{},"rules_override":{},"core_runtime":{},"preaccel":{},"behavior":{"hotkeys":{}}}"#).unwrap();
        assert_eq!(legacy.dns.direct_nameserver, expected_encrypted);
        assert!(legacy.rules_override.block_quic_udp_443);
        assert!(legacy.rules_override.domestic_direct_enabled);
        assert_eq!(legacy.core_runtime.gogc, 25);
        assert!(!legacy.core_runtime.compile_all_nodes);
        assert!(!cfg.personalization.onboarding_completed);
        assert!(!legacy.personalization.onboarding_completed);

        // Stage 10/12/19 global pre-acceleration defaults & backward-compatible deserialization.
        assert!(!cfg.preaccel.enabled);
        assert!(!cfg.preaccel.global_bypass_enabled);
        assert!(!cfg.preaccel.is_unified_enabled());
        assert_eq!(cfg.preaccel.probe_interval_sec, 30);
        assert_eq!(cfg.preaccel.dispatch_strategy, PreAccelDispatchStrategy::Auto);
        assert_eq!(
            cfg.preaccel.lb_strategy,
            PreAccelLbStrategy::ConsistentHashing
        );
        assert_eq!(legacy.preaccel.probe_interval_sec, 30);
        assert_eq!(legacy.preaccel.dispatch_strategy, PreAccelDispatchStrategy::Auto);
        assert_eq!(
            legacy.preaccel.lb_strategy,
            PreAccelLbStrategy::ConsistentHashing
        );
        assert_eq!(
            serde_json::from_str::<PreAccelLbStrategy>("\"round_robin\"").unwrap(),
            PreAccelLbStrategy::RoundRobin
        );
        assert_eq!(
            serde_json::from_str::<PreAccelLbStrategy>("\"round-robin\"").unwrap(),
            PreAccelLbStrategy::RoundRobin
        );
        assert_eq!(
            serde_json::to_string(&PreAccelDispatchStrategy::LoadBalance).unwrap(),
            "\"load_balance\""
        );
        assert_eq!(
            serde_json::to_string(&PreAccelLbStrategy::ConsistentHashing).unwrap(),
            "\"consistent_hashing\""
        );
        assert_eq!(PreAccelLbStrategy::RoundRobin.as_str(), "round-robin");
        assert_eq!(
            PreAccelLbStrategy::ConsistentHashing.as_str(),
            "consistent-hashing"
        );
        assert_eq!(cfg.preaccel.global_scope, GlobalPreAccelScope::ProxyAppsOnly);
        assert!(cfg.preaccel.windivert_dir.is_none());
        assert_eq!(
            cfg.preaccel.global_target_processes,
            vec![
                "mihomo.exe",
                "clash-meta.exe",
                "clash.exe",
                "xray.exe",
                "sing-box.exe",
                "v2ray.exe",
                "hysteria.exe",
                "tuic-client.exe",
                "ssh.exe",
                "scp.exe",
                "sftp.exe",
                "rsync.exe",
            ]
        );
        assert!(!legacy.preaccel.global_bypass_enabled);
        assert_eq!(legacy.preaccel.global_scope, GlobalPreAccelScope::ProxyAppsOnly);
        assert_eq!(
            legacy.preaccel.global_target_processes.len(),
            DEFAULT_GLOBAL_PREACCEL_PROCESSES.len()
        );
        assert!(legacy.preaccel.windivert_dir.is_none());

        // Unified master switch helper keeps `enabled` and `global_bypass_enabled` aligned.
        let mut preaccel = PreAccelConfig::default();
        preaccel.sync_unified_enabled(true);
        assert!(preaccel.enabled);
        assert!(preaccel.global_bypass_enabled);
        assert!(preaccel.is_unified_enabled());

        preaccel.sync_unified_enabled(false);
        assert!(!preaccel.enabled);
        assert!(!preaccel.global_bypass_enabled);
        assert!(!preaccel.is_unified_enabled());

        // Legacy split states reconcile cleanly to unified `true`, then turn off cleanly.
        preaccel.enabled = false;
        preaccel.global_bypass_enabled = true;
        assert!(preaccel.reconcile_unified_enabled());
        assert!(preaccel.enabled);
        assert!(preaccel.global_bypass_enabled);

        preaccel.enabled = true;
        preaccel.global_bypass_enabled = false;
        assert!(preaccel.reconcile_unified_enabled());
        assert!(preaccel.enabled);
        assert!(preaccel.global_bypass_enabled);

        preaccel.enabled = false;
        preaccel.global_bypass_enabled = false;
        assert!(!preaccel.reconcile_unified_enabled());
        assert!(!preaccel.enabled);
        assert!(!preaccel.global_bypass_enabled);
        assert_eq!(
            serde_json::to_string(&GlobalPreAccelScope::AllNon443Tcp).unwrap(),
            "\"all_non_443_tcp\""
        );
        assert_eq!(
            serde_json::from_str::<GlobalPreAccelScope>("\"all_non_443_tcp\"").unwrap(),
            GlobalPreAccelScope::AllNon443Tcp
        );
        assert_eq!(
            serde_json::from_str::<GlobalPreAccelScope>("\"all_non443_tcp\"").unwrap(),
            GlobalPreAccelScope::AllNon443Tcp
        );
        assert_eq!(GlobalPreAccelScope::AllNon443Tcp.as_str(), "all_non_443_tcp");
        assert_eq!(&cfg.system_proxy.bypass[..3], &["localhost", "127.0.0.1", "::1"]);

        // Cross-platform unified hotkey defaults & legacy deserialization.
        assert_eq!(
            cfg.behavior.hotkeys.switch_next_best.as_deref(),
            Some("Alt+Shift+N")
        );
        assert_eq!(
            cfg.behavior.hotkeys.toggle_capsule.as_deref(),
            Some("Alt+Shift+C")
        );
        assert_eq!(
            legacy.behavior.hotkeys.switch_next_best.as_deref(),
            Some("Alt+Shift+N")
        );
        assert_eq!(
            legacy.behavior.hotkeys.toggle_capsule.as_deref(),
            Some("Alt+Shift+C")
        );

        // Schema v4 default vs legacy missing schema_version field deserializing as v1.
        assert_eq!(CONFIG_SCHEMA_VERSION, 4);
        assert_eq!(cfg.schema_version, 4);
        assert_eq!(legacy.schema_version, 1);
    }

    #[test]
    fn personalization_language_preserves_wire_key_accepts_ui_language_alias_and_normalizes() {
        let mut p = PersonalizationConfig::default();
        assert_eq!(p.language, "zh-CN");
        assert_eq!(p.normalized_ui_language(), "zh-CN");

        // Serialization MUST keep field name `"language"` to preserve legacy backup SHA-256 hashes.
        let serialized = serde_json::to_value(&p).expect("serialize PersonalizationConfig");
        assert_eq!(serialized.get("language").and_then(|v| v.as_str()), Some("zh-CN"));
        assert!(serialized.get("ui_language").is_none());

        // Deserialization accepts `"ui_language"` alias transparently.
        let from_alias: PersonalizationConfig =
            serde_json::from_str(r#"{"ui_language":"en-US"}"#).expect("deserialize ui_language alias");
        assert_eq!(from_alias.language, "en-US");
        assert_eq!(from_alias.normalized_ui_language(), "en");

        let from_ja: PersonalizationConfig =
            serde_json::from_str(r#"{"language":"ja-JP"}"#).expect("deserialize ja-JP");
        assert_eq!(from_ja.normalized_ui_language(), "ja");

        let from_ru: PersonalizationConfig =
            serde_json::from_str(r#"{"ui_language":"ru_RU"}"#).expect("deserialize ru_RU");
        assert_eq!(from_ru.normalized_ui_language(), "ru");

        // Unknown / empty language falls back to `"zh-CN"`.
        p.language = "fr-FR".to_string();
        assert_eq!(p.normalized_ui_language(), "zh-CN");
        assert!(!is_supported_ui_language("fr-FR"));
        assert!(is_supported_ui_language("zh-CN"));
        assert!(is_supported_ui_language("en"));
        assert!(is_supported_ui_language("ja"));
        assert!(is_supported_ui_language("ru"));
    }

    #[test]
    fn update_config_skipped_version_default_and_serde_roundtrip() {
        let cfg = AppConfig::default();
        assert_eq!(cfg.update.skipped_version, None);

        // Legacy JSON missing `skipped_version` deserializes cleanly to `None`.
        let legacy: AppConfig =
            serde_json::from_str(r#"{"update":{"repo":"JuryBu/CatCloud","auto_download":true}}"#)
                .expect("deserialize legacy UpdateConfig");
        assert_eq!(legacy.update.skipped_version, None);

        // Explicit `skipped_version` round-trips identically.
        let mut with_skip = UpdateConfig::default();
        with_skip.skipped_version = Some("0.1.1".to_string());
        let json = serde_json::to_string(&with_skip).expect("serialize UpdateConfig");
        let parsed: UpdateConfig = serde_json::from_str(&json).expect("deserialize UpdateConfig");
        assert_eq!(parsed.skipped_version.as_deref(), Some("0.1.1"));
    }

    #[test]
    fn rules_override_custom_rules_and_inline_yaml_legacy_json_backcompat() {
        let cfg = AppConfig::default();
        assert!(!cfg.rules_override.custom_rules_only);
        assert!(cfg.rules_override.inline_override_yaml.is_none());
        assert!(cfg.rules_override.validate_inline_override_yaml().is_ok());

        // Legacy JSON missing `custom_rules_only` and `inline_override_yaml` must deserialize cleanly.
        let legacy_json = r#"{
            "rules_override": {
                "global_prepend_rules": ["DOMAIN-SUFFIX,example.com,DIRECT"],
                "global_append_rules": [],
                "override_mode": "disabled",
                "block_quic_udp_443": true,
                "domestic_direct_enabled": true
            }
        }"#;
        let legacy: AppConfig =
            serde_json::from_str(legacy_json).expect("deserialize legacy RulesAndOverrideConfig");
        assert!(!legacy.rules_override.custom_rules_only);
        assert!(legacy.rules_override.inline_override_yaml.is_none());
        assert_eq!(
            legacy.rules_override.global_prepend_rules,
            vec!["DOMAIN-SUFFIX,example.com,DIRECT"]
        );

        // New fields round-trip accurately through JSON.
        let mut custom = RulesAndOverrideConfig::default();
        custom.custom_rules_only = true;
        custom.inline_override_yaml = Some(
            "rule-providers:\n  direct_list:\n    type: http\n    behavior: domain\n".to_string(),
        );
        assert!(custom.validate_inline_override_yaml().is_ok());
        let serialized = serde_json::to_string(&custom).expect("serialize RulesAndOverrideConfig");
        let parsed: RulesAndOverrideConfig =
            serde_json::from_str(&serialized).expect("deserialize RulesAndOverrideConfig");
        assert!(parsed.custom_rules_only);
        assert_eq!(parsed.inline_override_yaml, custom.inline_override_yaml);

        // Reject oversized (> 1 MiB), malformed, or non-mapping inline YAML with Chinese diagnostics.
        let oversized = format!("rules:\n  - {}\n", "a".repeat(MAX_INLINE_OVERRIDE_YAML_BYTES + 16));
        let err_size = validate_inline_override_yaml_text(&oversized).unwrap_err();
        assert!(err_size.contains("1 MiB"), "unexpected size error: {err_size}");

        let err_syntax = validate_inline_override_yaml_text("rule-providers: [\n  broken").unwrap_err();
        assert!(
            err_syntax.contains("语法错误"),
            "unexpected syntax error: {err_syntax}"
        );

        let err_non_map = validate_inline_override_yaml_text("- just-a-list-item").unwrap_err();
        assert!(
            err_non_map.contains("键值对映射"),
            "unexpected non-mapping error: {err_non_map}"
        );
    }
}
