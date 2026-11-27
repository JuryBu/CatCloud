use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// Source type of a subscription or node feed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionKind {
    #[default]
    Url,
    File,
    Migrated,
    ProcessAdapter,
}

impl SubscriptionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Url => "url",
            Self::File => "file",
            Self::Migrated => "migrated",
            Self::ProcessAdapter => "process_adapter",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "url" => Self::Url,
            "file" => Self::File,
            "migrated" => Self::Migrated,
            "process_adapter" => Self::ProcessAdapter,
            _ => Self::Url,
        }
    }
}

/// Persisted subscription source metadata and traffic accounting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct SubscriptionRecord {
    pub id: String,
    pub name: String,
    pub kind: SubscriptionKind,
    #[serde(alias = "source")]
    pub url_or_cmd: String,
    pub refresh_interval_sec: u64,
    pub traffic_used_bytes: u64,
    pub traffic_total_bytes: u64,
    pub expires_at: Option<String>,
    pub etag: Option<String>,
    pub last_ok_at: Option<String>,
    pub last_error: Option<String>,
    pub enabled: bool,
}

impl Default for SubscriptionRecord {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            kind: SubscriptionKind::Url,
            url_or_cmd: String::new(),
            refresh_interval_sec: 3600,
            traffic_used_bytes: 0,
            traffic_total_bytes: 0,
            expires_at: None,
            etag: None,
            last_ok_at: None,
            last_error: None,
            enabled: true,
        }
    }
}

impl SubscriptionRecord {
    /// Remaining traffic in bytes, saturating at zero when used exceeds total.
    pub fn remaining_bytes(&self) -> u64 {
        self.traffic_total_bytes
            .saturating_sub(self.traffic_used_bytes)
    }
}

/// Normalized proxy node record stored in SQLite and fed into compilers/probes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ProxyNode {
    pub id: String,
    pub sub_id: String,
    pub name: String,
    pub protocol: String,
    pub server: String,
    pub port: u16,
    #[serde(alias = "raw_json")]
    pub raw_config: serde_json::Value,
    pub region_code: String,
    pub multiplier: f64,
    pub is_443_native: bool,
    pub preaccel_eligible: bool,
    pub preaccel_override: Option<bool>,
    pub tags: Vec<String>,
    pub enabled: bool,
}

impl Default for ProxyNode {
    fn default() -> Self {
        Self {
            id: String::new(),
            sub_id: String::new(),
            name: String::new(),
            protocol: String::new(),
            server: String::new(),
            port: 443,
            raw_config: serde_json::Value::Object(serde_json::Map::new()),
            region_code: "UNK".to_string(),
            multiplier: 1.0,
            is_443_native: false,
            preaccel_eligible: true,
            preaccel_override: None,
            tags: Vec::new(),
            enabled: true,
        }
    }
}

impl ProxyNode {
    /// Returns true for UDP/QUIC-only proxy transports (such as Hysteria2, TUIC, WireGuard)
    /// that must not be wrapped by TCP-only `:443` domestic relays by default.
    pub fn is_udp_only_transport(&self) -> bool {
        matches!(
            self.protocol.trim().to_ascii_lowercase().as_str(),
            "hysteria2" | "hy2" | "hysteria" | "tuic" | "wireguard"
        )
    }

    /// Resolve whether domestic pre-acceleration should wrap this node.
    /// Per-node `preaccel_override` takes precedence over global `skip_443_native`
    /// and automatic UDP-only transport exclusion.
    pub fn should_apply_preaccel(&self, global_skip_443_native: bool) -> bool {
        if let Some(forced) = self.preaccel_override {
            return forced;
        }
        if !self.preaccel_eligible {
            return false;
        }
        if self.is_udp_only_transport() {
            return false;
        }
        if global_skip_443_native && self.is_443_native {
            return false;
        }
        true
    }
}

/// Return `true` when `node` appears to be a subscription metadata/informational banner row
/// (e.g. remaining traffic, expiry notice, official website, maintenance alert) rather than a
/// usable proxy endpoint.
pub fn is_info_proxy_node(node: &ProxyNode) -> bool {
    let trimmed = node.name.trim();
    if trimmed.is_empty() {
        return false;
    }

    const ZH_INFO_KEYWORDS: &[&str] = &[
        "剩余流量",
        "到期",
        "官网",
        "公告",
        "维护",
        "重置",
        "教程",
        "过期",
        "套餐",
        "客服",
        "通知",
        "交流群",
        "电报群",
        "通知群",
        "售后群",
        "用户群",
        "群组",
        "tg群",
        "qq群",
        "官方群",
    ];
    let lower = trimmed.to_ascii_lowercase();
    if ZH_INFO_KEYWORDS.iter().any(|kw| lower.contains(kw)) {
        return true;
    }
    if lower.contains("群") && !lower.contains("集群") {
        return true;
    }

    // ASCII word-boundary matching prevents false positives on unrelated substrings.
    let tokens: Vec<&str> = lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|tok| !tok.is_empty())
        .collect();
    for tok in tokens {
        if matches!(
            tok,
            "info" | "notice" | "website" | "official" | "maintenance" | "reset" | "renew"
        ) || tok.starts_with("expire")
            || tok.starts_with("traffic")
            || tok.starts_with("remaining")
        {
            return true;
        }
    }

    false
}

/// Pick a sensible default proxy node ID for fresh/fallback selections (avoiding disabled rows,
/// informational traffic/expiry banners, and obscure high-multiplier regions such as `AD 3x`).
///
/// Ranking precedence:
/// 1. Healthy / untested nodes ahead of confirmed failed (`ok == false`) snapshots;
/// 2. Preferred mainstream regions (`TW`/`HK`/`SG`/`JP`/`US`/`KR`) > other mainstream regions >
///    obscure/unknown regions;
/// 3. Low billing multiplier (`<= 1.5x` > `< 3.0x` > `>= 3.0x`);
/// 4. Confirmed healthy probe snapshot ahead of untested;
/// 5. Preferred region order (`TW` -> `HK` -> `SG` -> `JP` -> `US` -> `KR`), lower latency,
///    lower exact multiplier, then deterministic name/ID order.
pub fn pick_smart_default_node_id(
    nodes: &[ProxyNode],
    snapshots: Option<&HashMap<String, ProbeSnapshot>>,
) -> Option<String> {
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

    let mut best: Option<((u8, u8, u8, u8, u8, u32, u64, String, String), &str)> = None;

    for node in nodes {
        if !node.enabled || node.id.trim().is_empty() || is_info_proxy_node(node) {
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

        let snap = snapshots.and_then(|map| map.get(&node.id));
        let (dead_rank, probe_rank, latency_rank) = match snap {
            Some(s) if s.ok => {
                let lat = s
                    .latency_ms
                    .filter(|v| v.is_finite() && *v > 0.0)
                    .map(|v| v.round() as u32)
                    .unwrap_or(u32::MAX / 2);
                (0u8, 0u8, lat)
            }
            Some(_) => (1u8, 2u8, u32::MAX),
            None => (0u8, 1u8, u32::MAX),
        };

        let key = (
            dead_rank,
            r_tier,
            m_tier,
            probe_rank,
            r_sub,
            latency_rank,
            mult_milli,
            node.name.trim().to_ascii_lowercase(),
            node.id.clone(),
        );

        let replace = match &best {
            None => true,
            Some((cur_key, _)) => key < *cur_key,
        };
        if replace {
            best = Some((key, node.id.as_str()));
        }
    }

    best.map(|(_, id)| id.to_string())
}

/// Conservatively classify whether `node` is an IPv6-only business proxy that would fail when
/// chained through an IPv4-only domestic relay (strictly avoiding false positives on dual-stack
/// nodes such as `"HK-01-IPv6"`):
///
/// 1. `node.server` (or fallback `raw_config["server"]`) parses as `IpAddr::V6`;
/// 2. `raw_config["ip-version"]` explicitly specifies `"ipv6"` (or `"ipv6-only"`);
/// 3. `server` hostname carries a dedicated IPv6 label (`ipv6.` / `v6.` / `-ipv6.` / `-v6.` /
///    `.ipv6.` / `.v6.`) and does NOT contain `"dual"` or `"v4"`;
/// 4. `node.name` contains an exclusive IPv6-only marker (`ipv6-only` / `ipv6 only` / `v6-only` /
///    `纯ipv6` / `仅ipv6`, etc.).
pub fn is_ipv6_only_node(node: &ProxyNode) -> bool {
    let raw_server = {
        let s = node.server.trim();
        if !s.is_empty() {
            s
        } else {
            node.raw_config
                .get("server")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .unwrap_or("")
        }
    };
    let clean_server = raw_server
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.');

    // 1. Literal IPv6 server address.
    if let Ok(IpAddr::V6(_)) = clean_server.parse::<IpAddr>() {
        return true;
    }

    // 2. Explicit Mihomo `ip-version: ipv6` directive in raw_config.
    if let Some(ip_ver) = node
        .raw_config
        .get("ip-version")
        .and_then(serde_json::Value::as_str)
    {
        let normalized_ver = ip_ver.trim().to_ascii_lowercase();
        if matches!(normalized_ver.as_str(), "ipv6" | "ipv6-only") {
            return true;
        }
    }

    // 3. Dedicated IPv6-only DNS label in server hostname (excluding dual-stack / v4 markers).
    let server_lower = clean_server.to_ascii_lowercase();
    if !server_lower.is_empty()
        && !server_lower.contains("dual")
        && !server_lower.contains("v4")
        && (server_lower.starts_with("ipv6.")
            || server_lower.starts_with("v6.")
            || server_lower.contains(".ipv6.")
            || server_lower.contains(".v6.")
            || server_lower.contains("-ipv6.")
            || server_lower.contains("-v6."))
    {
        return true;
    }

    // 4. Exclusive IPv6-only terms in display name (never matching generic `HK-01-IPv6`).
    let name_lower = node.name.trim().to_ascii_lowercase();
    const EXCLUSIVE_V6_NAME_MARKERS: &[&str] = &[
        "ipv6-only",
        "ipv6 only",
        "ipv6_only",
        "ipv6only",
        "v6-only",
        "v6 only",
        "v6_only",
        "v6only",
        "纯ipv6",
        "纯 ipv6",
        "纯v6",
        "纯 v6",
        "仅ipv6",
        "仅 ipv6",
        "仅v6",
        "仅 v6",
        "only-ipv6",
        "only ipv6",
        "only-v6",
        "only v6",
    ];
    EXCLUSIVE_V6_NAME_MARKERS
        .iter()
        .any(|marker| name_lower.contains(marker))
}

/// Supported built-in and extensible probe kinds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    #[default]
    Latency,
    Upload,
    Download,
    Keepalive,
    GoogleCn,
    UnlockRegex,
    ExternalCmd,
}

impl ProbeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Latency => "latency",
            Self::Upload => "upload",
            Self::Download => "download",
            Self::Keepalive => "keepalive",
            Self::GoogleCn => "google_cn",
            Self::UnlockRegex => "unlock_regex",
            Self::ExternalCmd => "external_cmd",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "latency" => Self::Latency,
            "upload" => Self::Upload,
            "download" => Self::Download,
            "keepalive" => Self::Keepalive,
            "google_cn" => Self::GoogleCn,
            "unlock_regex" => Self::UnlockRegex,
            "external_cmd" => Self::ExternalCmd,
            _ => Self::Latency,
        }
    }
}

/// Extensible probe definition stored in `probe_definitions`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ProbeDefinition {
    pub id: String,
    pub name: String,
    pub kind: ProbeKind,
    pub target_url: String,
    pub method: String,
    pub expected_status: Option<u16>,
    pub body_regex: Option<String>,
    pub payload_bytes: Option<u64>,
    pub timeout_ms: u64,
    pub builtin: bool,
}

impl Default for ProbeDefinition {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            kind: ProbeKind::Latency,
            target_url: String::new(),
            method: "GET".to_string(),
            expected_status: Some(204),
            body_regex: None,
            payload_bytes: None,
            timeout_ms: 8000,
            builtin: false,
        }
    }
}

/// Default public AI service domains included in CatCloud built-in AI routing presets
/// (covers OpenAI, Anthropic, Google AI / Antigravity / Cloud Code / OAuth, Windsurf/Devin/Codeium,
/// Cursor, Perplexity, xAI, and GitHub Copilot endpoints; intentionally excludes `play.googleapis.com`).
pub const DEFAULT_AI_ROUTING_DOMAINS: &[&str] = &[
    "openai.com",
    "chatgpt.com",
    "oaistatic.com",
    "oaiusercontent.com",
    "auth.openai.com",
    "auth0.openai.com",
    "auth0.com",
    "sora.com",
    "chat.com",
    "anthropic.com",
    "claude.ai",
    "claude.com",
    "claudeusercontent.com",
    "clau.de",
    "statsig.anthropic.com",
    "sentry.io",
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "googleusercontent.com",
    "gvt1.com",
    "gvt2.com",
    "ggpht.com",
    "accounts.google.com",
    "oauth2.googleapis.com",
    "apis.google.com",
    "gemini.google.com",
    "aistudio.google.com",
    "generativelanguage.googleapis.com",
    "antigravity.google",
    "antigravity.google.com",
    "antigravity-unleash.goog",
    "cloudcode-pa.googleapis.com",
    "daily-cloudcode-pa.sandbox.googleapis.com",
    "daily-cloudcode-pa.googleapis.com",
    "autopush-cloudcode-pa.sandbox.googleapis.com",
    "aicode.googleapis.com",
    "businessaicode.googleapis.com",
    "aiplatform.googleapis.com",
    "alkalimakersuite-pa.clients6.google.com",
    "proactivebackend-pa.googleapis.com",
    "ai.google.dev",
    "makersuite.google.com",
    "deepmind.com",
    "deepmind.google",
    "labs.google",
    "notebooklm.google.com",
    "jules.google.com",
    "codeium.com",
    "windsurf.com",
    "devin.ai",
    "cognition.ai",
    "exafunction.com",
    "statsigapi.net",
    "featuregates.org",
    "cursor.sh",
    "cursor.com",
    "cursor-cdn.com",
    "perplexity.ai",
    "x.ai",
    "grok.com",
    "githubcopilot.com",
];

impl ProbeDefinition {
    /// Standard sanitized built-in probe suite seeded into fresh databases.
    pub fn builtin_defaults() -> Vec<Self> {
        vec![
            Self {
                id: "builtin_latency".to_string(),
                name: "Standard Latency 204".to_string(),
                kind: ProbeKind::Latency,
                target_url: "https://cp.cloudflare.com/generate_204".to_string(),
                method: "GET".to_string(),
                expected_status: Some(204),
                body_regex: None,
                payload_bytes: None,
                timeout_ms: 5000,
                builtin: true,
            },
            Self {
                id: "builtin_google_cn".to_string(),
                name: "Google Region Cleanliness".to_string(),
                kind: ProbeKind::GoogleCn,
                target_url: "https://www.google.com/generate_204".to_string(),
                method: "GET".to_string(),
                expected_status: Some(204),
                body_regex: None,
                payload_bytes: None,
                timeout_ms: 6000,
                builtin: true,
            },
            Self {
                id: "builtin_upload".to_string(),
                name: "Cloudflare Upload Throughput".to_string(),
                kind: ProbeKind::Upload,
                target_url: "https://speed.cloudflare.com/__up".to_string(),
                method: "POST".to_string(),
                expected_status: Some(200),
                body_regex: None,
                payload_bytes: Some(512 * 1024),
                timeout_ms: 12000,
                builtin: true,
            },
            Self {
                id: "builtin_download".to_string(),
                name: "Cloudflare Download Throughput".to_string(),
                kind: ProbeKind::Download,
                target_url: "https://speed.cloudflare.com/__down?bytes=2097152".to_string(),
                method: "GET".to_string(),
                expected_status: Some(200),
                body_regex: None,
                payload_bytes: Some(2 * 1024 * 1024),
                timeout_ms: 12000,
                builtin: true,
            },
            Self {
                id: "builtin_keepalive_60s".to_string(),
                name: "Silent 60s Keep-Alive Blackhole Check".to_string(),
                kind: ProbeKind::Keepalive,
                target_url: "https://cp.cloudflare.com/generate_204".to_string(),
                method: "GET".to_string(),
                expected_status: Some(204),
                body_regex: None,
                payload_bytes: None,
                timeout_ms: 65000,
                builtin: true,
            },
            Self {
                id: "builtin_unlock_windsurf".to_string(),
                name: "Windsurf / Codeium Reachability".to_string(),
                kind: ProbeKind::UnlockRegex,
                target_url: "https://windsurf.com".to_string(),
                method: "GET".to_string(),
                expected_status: Some(200),
                body_regex: None,
                payload_bytes: None,
                timeout_ms: 8000,
                builtin: true,
            },
            Self {
                id: "builtin_unlock_claude".to_string(),
                name: "Claude / Anthropic 解锁".to_string(),
                kind: ProbeKind::UnlockRegex,
                target_url: "https://api.anthropic.com/v1/messages".to_string(),
                method: "POST".to_string(),
                expected_status: None,
                body_regex: None,
                payload_bytes: None,
                timeout_ms: 8000,
                builtin: true,
            },
            Self {
                id: "builtin_unlock_chatgpt".to_string(),
                name: "ChatGPT / OpenAI 解锁".to_string(),
                kind: ProbeKind::UnlockRegex,
                target_url: "https://api.openai.com/v1/models".to_string(),
                method: "GET".to_string(),
                expected_status: None,
                body_regex: None,
                payload_bytes: None,
                timeout_ms: 8000,
                builtin: true,
            },
            Self {
                id: "builtin_unlock_gemini".to_string(),
                name: "Gemini / Google AI 解锁".to_string(),
                kind: ProbeKind::UnlockRegex,
                target_url: "https://generativelanguage.googleapis.com/v1beta/models".to_string(),
                method: "GET".to_string(),
                expected_status: None,
                body_regex: None,
                payload_bytes: None,
                timeout_ms: 8000,
                builtin: true,
            },
        ]
    }
}

/// Single execution record persisted in `probe_results`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct ProbeResultRecord {
    pub node_id: String,
    pub probe_id: String,
    pub tested_at: String,
    pub ok: bool,
    pub latency_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub loss_pct: Option<f64>,
    pub up_mbps: Option<f64>,
    pub down_mbps: Option<f64>,
    pub cf_loc: Option<String>,
    pub yt_gl: Option<String>,
    pub google_clean: Option<bool>,
    pub keepalive_60s_ok: Option<bool>,
    pub unlocked_map: HashMap<String, bool>,
    pub detail: Option<String>,
}

/// Aggregated per-node probe view consumed by the strategy formula engine and UI.
/// Contains per-probe maps for `probe_up("id")`, `probe_down("id")`,
/// `probe_ping("id")`, and `probe_ok("id")` lookups.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct ProbeSnapshot {
    pub node_id: String,
    pub tested_at: String,
    pub ok: bool,
    pub latency_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub loss_pct: Option<f64>,
    pub up_mbps: Option<f64>,
    pub down_mbps: Option<f64>,
    pub cf_loc: Option<String>,
    pub yt_gl: Option<String>,
    pub google_clean: Option<bool>,
    pub google_risk_mismatch: bool,
    pub keepalive_60s_ok: Option<bool>,
    pub unlocked_sites: HashMap<String, bool>,
    pub per_probe_ok: HashMap<String, bool>,
    pub per_probe_up_mbps: HashMap<String, f64>,
    pub per_probe_down_mbps: HashMap<String, f64>,
    pub per_probe_ping_ms: HashMap<String, f64>,
    pub per_probe_detail: HashMap<String, String>,
    #[serde(default)]
    pub per_probe_tested_at: HashMap<String, String>,
}

/// Infer the canonical [`ProbeKind`] for well-known built-in probe IDs.
pub fn infer_builtin_probe_kind(probe_id: &str) -> Option<ProbeKind> {
    let trimmed = probe_id.trim();
    match trimmed {
        "builtin_latency" => Some(ProbeKind::Latency),
        "builtin_google_cn" => Some(ProbeKind::GoogleCn),
        "builtin_upload" => Some(ProbeKind::Upload),
        "builtin_download" => Some(ProbeKind::Download),
        "builtin_keepalive_60s" => Some(ProbeKind::Keepalive),
        "builtin_unlock_windsurf"
        | "builtin_unlock_claude"
        | "builtin_unlock_chatgpt"
        | "builtin_unlock_gemini" => Some(ProbeKind::UnlockRegex),
        _ if trimmed.starts_with("builtin_unlock_") => Some(ProbeKind::UnlockRegex),
        _ => None,
    }
}

fn parse_tested_at_utc(ts: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(ts.trim())
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

fn compare_tested_at_desc(a: &str, b: &str) -> Ordering {
    match (parse_tested_at_utc(a), parse_tested_at_utc(b)) {
        (Some(da), Some(db)) => db.cmp(&da).then_with(|| b.cmp(a)),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => b.cmp(a),
    }
}

impl ProbeSnapshot {
    /// Merge latest per-probe result rows for a node into one formula-ready snapshot using the
    /// built-in probe ID -> [`ProbeKind`] mapping (compatibility wrapper around
    /// [`ProbeSnapshot::from_results_with_kinds`]).
    pub fn from_results(
        node_id: &str,
        results: &[ProbeResultRecord],
        primary_probe_id: Option<&str>,
    ) -> Self {
        let builtin_kinds: HashMap<String, ProbeKind> = ProbeDefinition::builtin_defaults()
            .into_iter()
            .map(|d| (d.id, d.kind))
            .collect();
        Self::from_results_with_kinds(node_id, results, primary_probe_id, &builtin_kinds)
    }

    /// Merge per-probe result rows for a node into one formula-ready snapshot with explicit
    /// `probe_id -> ProbeKind` semantics:
    /// - Records are sorted newest-first using RFC3339 UTC timestamp ordering (falling back to
    ///   lexicographic string comparison for non-RFC3339 timestamps).
    /// - Top-level `latency_ms` / `jitter_ms` / `loss_pct` are populated strictly from
    ///   [`ProbeKind::Latency`] records (priority: valid Latency `primary_probe_id` ->
    ///   `builtin_latency` -> latest Latency probe), never polluted by Unlock/Upload/Download/
    ///   Keepalive/GoogleCn/ExternalCmd probes.
    /// - Top-level `up_mbps` / `down_mbps` accept strictly `rec.ok == true` positive finite values
    ///   from `Upload`/`Download`/`ExternalCmd` probes.
    /// - `cf_loc` / `yt_gl` / `google_clean` / `keepalive_60s_ok` take the newest non-empty value.
    /// - In `unlocked_sites`, `builtin_unlock_gemini` strictly owns the `"gemini"` key whenever
    ///   present (never overwritten by `builtin_google_cn`, which independently maintains
    ///   `"gemini_aistudio"`).
    /// - When any `Latency` record exists, `snap.ok` strictly reflects the selected latest Latency
    ///   probe (`ok == false` clears `latency_ms = None`); only when no Latency record exists does
    ///   `snap.ok` fall back to `any_ok`.
    pub fn from_results_with_kinds(
        node_id: &str,
        results: &[ProbeResultRecord],
        primary_probe_id: Option<&str>,
        probe_kinds: &HashMap<String, ProbeKind>,
    ) -> Self {
        let mut snap = Self {
            node_id: node_id.to_string(),
            ..Default::default()
        };
        if results.is_empty() {
            return snap;
        }

        let primary_id = primary_probe_id
            .map(str::trim)
            .filter(|id| !id.is_empty());

        // Sort newest-first by parsed RFC3339 UTC timestamp (tie-break: probe_id ASC, later index first).
        let mut order: Vec<usize> = (0..results.len()).collect();
        order.sort_by(|&a, &b| {
            compare_tested_at_desc(&results[a].tested_at, &results[b].tested_at)
                .then_with(|| results[a].probe_id.cmp(&results[b].probe_id))
                .then_with(|| b.cmp(&a))
        });

        // Deduplicate to the latest record per `probe_id` while preserving newest-first order.
        let mut seen_probe_ids: HashSet<&str> = HashSet::with_capacity(results.len());
        let mut latest_records: Vec<(&ProbeResultRecord, Option<ProbeKind>)> =
            Vec::with_capacity(results.len());
        for idx in order {
            let rec = &results[idx];
            if !seen_probe_ids.insert(rec.probe_id.as_str()) {
                continue;
            }
            let kind = probe_kinds
                .get(&rec.probe_id)
                .cloned()
                .or_else(|| infer_builtin_probe_kind(&rec.probe_id));
            latest_records.push((rec, kind));
        }

        let mut any_ok = false;

        // First pass: populate per-probe maps, top-level `tested_at`, and newest-non-null metadata.
        for (rec, _) in &latest_records {
            if !rec.tested_at.trim().is_empty() {
                if snap.tested_at.trim().is_empty()
                    || compare_tested_at_desc(&rec.tested_at, &snap.tested_at) == Ordering::Less
                {
                    snap.tested_at = rec.tested_at.clone();
                }
                snap.per_probe_tested_at
                    .insert(rec.probe_id.clone(), rec.tested_at.clone());
            }
            if rec.ok {
                any_ok = true;
            }

            snap.per_probe_ok.insert(rec.probe_id.clone(), rec.ok);
            if rec.ok {
                if let Some(up) = rec.up_mbps.filter(|v| v.is_finite() && *v > 0.0) {
                    snap.per_probe_up_mbps.insert(rec.probe_id.clone(), up);
                }
                if let Some(down) = rec.down_mbps.filter(|v| v.is_finite() && *v > 0.0) {
                    snap.per_probe_down_mbps.insert(rec.probe_id.clone(), down);
                }
                if let Some(ping) = rec.latency_ms.filter(|v| v.is_finite() && *v > 0.0) {
                    snap.per_probe_ping_ms.insert(rec.probe_id.clone(), ping);
                }
            }
            if let Some(ref detail) = rec.detail {
                snap.per_probe_detail
                    .insert(rec.probe_id.clone(), detail.clone());
            }

            // Newest-non-empty wins (protected by `is_none()` because `latest_records` is DESC).
            if snap.cf_loc.is_none() {
                if let Some(ref loc) = rec.cf_loc {
                    if !loc.trim().is_empty() {
                        snap.cf_loc = Some(loc.clone());
                    }
                }
            }
            if snap.yt_gl.is_none() {
                if let Some(ref gl) = rec.yt_gl {
                    if !gl.trim().is_empty() {
                        snap.yt_gl = Some(gl.clone());
                    }
                }
            }
            if snap.google_clean.is_none() && rec.google_clean.is_some() {
                snap.google_clean = rec.google_clean;
            }
            if snap.keepalive_60s_ok.is_none() && rec.keepalive_60s_ok.is_some() {
                snap.keepalive_60s_ok = rec.keepalive_60s_ok;
            }
        }

        // `unlocked_sites`: `builtin_unlock_gemini` strictly owns `"gemini"` whenever present;
        // `builtin_google_cn` independently maintains `"gemini_aistudio"` and never overrides `"gemini"`.
        let dedicated_gemini = latest_records
            .iter()
            .find(|(rec, _)| rec.probe_id == "builtin_unlock_gemini");
        let gemini_owned_by_dedicated = if let Some((grec, _)) = dedicated_gemini {
            let val = grec.unlocked_map.get("gemini").copied().unwrap_or(grec.ok);
            snap.unlocked_sites.insert("gemini".to_string(), val);
            true
        } else {
            false
        };

        for (rec, _) in &latest_records {
            for (site, unlocked) in &rec.unlocked_map {
                if site == "gemini" {
                    if gemini_owned_by_dedicated {
                        continue;
                    }
                    if rec.probe_id == "builtin_google_cn" {
                        // When no dedicated `builtin_unlock_gemini` record exists yet, keep
                        // `gemini_aistudio` independent and only populate `"gemini"` if unset.
                        snap.unlocked_sites.entry(site.clone()).or_insert(*unlocked);
                        continue;
                    }
                }
                snap.unlocked_sites.entry(site.clone()).or_insert(*unlocked);
            }
        }

        // Top-level latency / jitter / loss & `ok`: strictly from `ProbeKind::Latency`.
        let latency_recs: Vec<&ProbeResultRecord> = latest_records
            .iter()
            .filter_map(|(rec, kind)| matches!(kind, Some(ProbeKind::Latency)).then_some(*rec))
            .collect();

        let chosen_latency = primary_id
            .and_then(|pid| latency_recs.iter().copied().find(|r| r.probe_id == pid))
            .or_else(|| {
                latency_recs
                    .iter()
                    .copied()
                    .find(|r| r.probe_id == "builtin_latency")
            })
            .or_else(|| latency_recs.first().copied());

        if let Some(lrec) = chosen_latency {
            snap.ok = lrec.ok;
            if lrec.ok {
                snap.latency_ms = lrec.latency_ms.filter(|v| v.is_finite() && *v > 0.0);
            } else {
                snap.latency_ms = None;
            }
            snap.jitter_ms = lrec.jitter_ms.filter(|v| v.is_finite() && *v >= 0.0);
            snap.loss_pct = lrec.loss_pct.filter(|v| v.is_finite() && *v >= 0.0);
        } else {
            snap.ok = any_ok;
        }

        // Top-level `up_mbps`: strictly `ok == true` positive values from Upload / ExternalCmd.
        let pick_up = |rec: &ProbeResultRecord, kind: &Option<ProbeKind>| -> Option<f64> {
            if !rec.ok {
                return None;
            }
            if !matches!(kind, Some(ProbeKind::Upload | ProbeKind::ExternalCmd)) {
                return None;
            }
            rec.up_mbps.filter(|v| v.is_finite() && *v > 0.0)
        };
        snap.up_mbps = primary_id
            .and_then(|pid| {
                latest_records
                    .iter()
                    .find(|(rec, _)| rec.probe_id == pid)
                    .and_then(|(rec, kind)| pick_up(rec, kind))
            })
            .or_else(|| {
                latest_records
                    .iter()
                    .find_map(|(rec, kind)| {
                        matches!(kind, Some(ProbeKind::Upload))
                            .then(|| pick_up(rec, kind))
                            .flatten()
                    })
            })
            .or_else(|| {
                latest_records
                    .iter()
                    .find_map(|(rec, kind)| {
                        matches!(kind, Some(ProbeKind::ExternalCmd))
                            .then(|| pick_up(rec, kind))
                            .flatten()
                    })
            });

        // Top-level `down_mbps`: strictly `ok == true` positive values from Download / ExternalCmd.
        let pick_down = |rec: &ProbeResultRecord, kind: &Option<ProbeKind>| -> Option<f64> {
            if !rec.ok {
                return None;
            }
            if !matches!(kind, Some(ProbeKind::Download | ProbeKind::ExternalCmd)) {
                return None;
            }
            rec.down_mbps.filter(|v| v.is_finite() && *v > 0.0)
        };
        snap.down_mbps = primary_id
            .and_then(|pid| {
                latest_records
                    .iter()
                    .find(|(rec, _)| rec.probe_id == pid)
                    .and_then(|(rec, kind)| pick_down(rec, kind))
            })
            .or_else(|| {
                latest_records
                    .iter()
                    .find_map(|(rec, kind)| {
                        matches!(kind, Some(ProbeKind::Download))
                            .then(|| pick_down(rec, kind))
                            .flatten()
                    })
            })
            .or_else(|| {
                latest_records
                    .iter()
                    .find_map(|(rec, kind)| {
                        matches!(kind, Some(ProbeKind::ExternalCmd))
                            .then(|| pick_down(rec, kind))
                            .flatten()
                    })
            });

        if let (Some(cf), Some(yt)) = (&snap.cf_loc, &snap.yt_gl) {
            snap.google_risk_mismatch = !cf.eq_ignore_ascii_case(yt);
        }

        snap
    }

    pub fn probe_up(&self, probe_id: &str) -> Option<f64> {
        self.per_probe_up_mbps.get(probe_id).copied()
    }

    pub fn probe_down(&self, probe_id: &str) -> Option<f64> {
        self.per_probe_down_mbps.get(probe_id).copied()
    }

    pub fn probe_ping(&self, probe_id: &str) -> Option<f64> {
        self.per_probe_ping_ms.get(probe_id).copied()
    }

    pub fn probe_ok(&self, probe_id: &str) -> Option<bool> {
        self.per_probe_ok.get(probe_id).copied()
    }
}

/// Multi-dimensional filter criteria for querying nodes across subscriptions.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct NodeFilter {
    /// Filter by one or more subscription IDs.
    pub sub_ids: Option<Vec<String>>,
    /// Filter by region codes (case-insensitive, e.g. `["JP", "SG"]`).
    pub region_codes: Option<Vec<String>>,
    /// Inclusive upper bound on billing multiplier (e.g. `Some(1.0)` for `<= 1x`).
    pub max_multiplier: Option<f64>,
    /// Inclusive lower bound on billing multiplier (e.g. `Some(3.0)` for `3x+`).
    pub min_multiplier: Option<f64>,
    /// Filter by proxy protocol names (case-insensitive, e.g. `["vless", "trojan"]`).
    pub protocols: Option<Vec<String>>,
    /// Filter by native 443 port flag.
    pub is_443_native: Option<bool>,
    /// Require latest Google cleanliness check to be `true`.
    pub google_clean_only: bool,
    /// Require latest 60s keep-alive check to be `true`.
    pub keepalive_60s_ok_only: bool,
    /// Require a specific unlocked site key to be `true` in latest probe results.
    pub unlocked_site: Option<String>,
    /// Filter by enabled status (`None` returns both enabled and disabled nodes).
    pub enabled_only: Option<bool>,
    /// Case-insensitive substring match across node name, server, and tags.
    pub keyword: Option<String>,
    /// Require node tags to contain all specified tags (case-insensitive).
    pub tags: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ai_routing_domains_and_builtin_probes_cover_required_entries() {
        assert!(!DEFAULT_AI_ROUTING_DOMAINS.contains(&"play.googleapis.com"));
        for required in [
            "openai.com",
            "chatgpt.com",
            "anthropic.com",
            "claude.ai",
            "claude.com",
            "antigravity.google",
            "antigravity.google.com",
            "cloudcode-pa.googleapis.com",
            "generativelanguage.googleapis.com",
            "windsurf.com",
            "codeium.com",
            "cursor.com",
            "githubcopilot.com",
        ] {
            assert!(
                DEFAULT_AI_ROUTING_DOMAINS.contains(&required),
                "missing required AI routing domain `{required}`"
            );
        }

        let builtins = ProbeDefinition::builtin_defaults();
        assert_eq!(builtins.len(), 9);
        let claude = builtins
            .iter()
            .find(|p| p.id == "builtin_unlock_claude")
            .expect("missing builtin_unlock_claude");
        assert_eq!(claude.kind, ProbeKind::UnlockRegex);
        assert_eq!(claude.method, "POST");
        assert_eq!(claude.expected_status, None);
        assert_eq!(claude.timeout_ms, 8000);
        assert!(claude.builtin);

        let chatgpt = builtins
            .iter()
            .find(|p| p.id == "builtin_unlock_chatgpt")
            .expect("missing builtin_unlock_chatgpt");
        assert_eq!(chatgpt.kind, ProbeKind::UnlockRegex);
        assert_eq!(chatgpt.method, "GET");
        assert_eq!(chatgpt.expected_status, None);

        let gemini = builtins
            .iter()
            .find(|p| p.id == "builtin_unlock_gemini")
            .expect("missing builtin_unlock_gemini");
        assert_eq!(gemini.kind, ProbeKind::UnlockRegex);
        assert_eq!(gemini.method, "GET");
        assert_eq!(gemini.expected_status, None);
    }

    fn demo_node(id: &str, name: &str, region: &str, mult: f64, server: &str) -> ProxyNode {
        ProxyNode {
            id: id.to_string(),
            sub_id: "sub-1".to_string(),
            name: name.to_string(),
            protocol: "trojan".to_string(),
            server: server.to_string(),
            port: 8443,
            region_code: region.to_string(),
            multiplier: mult,
            enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn pick_smart_default_node_skips_info_and_andorra_3x_prefers_mainstream_low_mult_and_healthy() {
        let mut disabled_tw = demo_node("n-tw-off", "TW 台湾 00", "TW", 1.0, "tw0.example.test");
        disabled_tw.enabled = false;

        let nodes = vec![
            demo_node("n-info-1", "剩余流量：180 GB", "UNK", 1.0, "info.example.test"),
            demo_node("n-info-2", "Expire: 2027-01-01", "TW", 1.0, "info2.example.test"),
            demo_node("n-info-3", "Official Website Info", "HK", 1.0, "info3.example.test"),
            demo_node("n-ad-3x", "AD 安道尔 | 3x AD", "AD", 3.0, "ad.example.test"),
            demo_node("n-tw-3x", "TW 台湾专线 3x", "TW", 3.0, "tw3x.example.test"),
            demo_node("n-de-1x", "DE 德国 01", "DE", 1.0, "de.example.test"),
            demo_node("n-hk-1x", "HK 香港 02", "HK", 1.0, "hk2.example.test"),
            demo_node("n-jp-1x", "JP 日本 01", "JP", 1.0, "jp1.example.test"),
            disabled_tw,
        ];

        // 1. Without probe snapshots: skips disabled, info rows, AD 3x, and TW 3x -> picks HK 1x (HK before JP).
        assert_eq!(
            pick_smart_default_node_id(&nodes, None).as_deref(),
            Some("n-hk-1x")
        );

        // 2. With probe snapshots: healthy JP 1x beats untested HK 1x!
        let mut snaps = HashMap::new();
        snaps.insert(
            "n-jp-1x".to_string(),
            ProbeSnapshot {
                node_id: "n-jp-1x".to_string(),
                ok: true,
                latency_ms: Some(42.0),
                ..Default::default()
            },
        );
        assert_eq!(
            pick_smart_default_node_id(&nodes, Some(&snaps)).as_deref(),
            Some("n-jp-1x")
        );

        // 3. When JP 1x failed (`ok == false`) and HK 1x is untested, never pick failed JP 1x.
        snaps.insert(
            "n-jp-1x".to_string(),
            ProbeSnapshot {
                node_id: "n-jp-1x".to_string(),
                ok: false,
                ..Default::default()
            },
        );
        assert_eq!(
            pick_smart_default_node_id(&nodes, Some(&snaps)).as_deref(),
            Some("n-hk-1x")
        );

        // 4. Only info / disabled nodes -> returns None safely.
        let only_info = vec![
            demo_node("i1", "官网公告维护通知", "UNK", 1.0, "x.test"),
            demo_node("i2", "Traffic Reset 1st", "TW", 1.0, "y.test"),
        ];
        assert_eq!(pick_smart_default_node_id(&only_info, None), None);
    }

    #[test]
    fn is_ipv6_only_node_classifies_strictly_without_false_positive_on_dual_stack() {
        // 1. Literal IPv6 address (with or without brackets) -> true
        assert!(is_ipv6_only_node(&demo_node(
            "v6-lit",
            "JP-01",
            "JP",
            1.0,
            "2001:db8::42"
        )));
        assert!(is_ipv6_only_node(&demo_node(
            "v6-bracket",
            "JP-02",
            "JP",
            1.0,
            "[2001:db8::43]"
        )));

        // 2. raw_config["ip-version"] == "ipv6" -> true; "dual" / "ipv4-prefer" -> false
        let mut raw_v6 = demo_node("v6-cfg", "SG-01", "SG", 1.0, "sg01.example.test");
        raw_v6.raw_config = serde_json::json!({"ip-version": "ipv6"});
        assert!(is_ipv6_only_node(&raw_v6));

        let mut raw_dual = demo_node("v6-dual-cfg", "HK-01-IPv6", "HK", 1.0, "hk01.example.test");
        raw_dual.raw_config = serde_json::json!({"ip-version": "dual"});
        assert!(!is_ipv6_only_node(&raw_dual));

        // 3. Dedicated v6 hostname labels -> true; dual/v4 labels -> false
        assert!(is_ipv6_only_node(&demo_node(
            "v6-host-1",
            "JP-01",
            "JP",
            1.0,
            "ipv6.jp.example.test"
        )));
        assert!(is_ipv6_only_node(&demo_node(
            "v6-host-2",
            "JP-02",
            "JP",
            1.0,
            "v6.jp.example.test"
        )));
        assert!(is_ipv6_only_node(&demo_node(
            "v6-host-3",
            "JP-03",
            "JP",
            1.0,
            "tokyo-ipv6.example.test"
        )));
        assert!(is_ipv6_only_node(&demo_node(
            "v6-host-4",
            "JP-04",
            "JP",
            1.0,
            "tokyo-v6.example.test"
        )));
        assert!(!is_ipv6_only_node(&demo_node(
            "dual-host-1",
            "HK-01-IPv6",
            "HK",
            1.0,
            "dual-ipv6.example.test"
        )));
        assert!(!is_ipv6_only_node(&demo_node(
            "dual-host-2",
            "HK-02-IPv6",
            "HK",
            1.0,
            "v4-v6.example.test"
        )));

        // 4. Exclusive name markers -> true; dual-stack label like `HK-01-IPv6` -> false!
        assert!(is_ipv6_only_node(&demo_node(
            "v6-name-1",
            "JP-01 IPv6-Only",
            "JP",
            1.0,
            "jp01.example.test"
        )));
        assert!(is_ipv6_only_node(&demo_node(
            "v6-name-2",
            "香港 纯IPv6 01",
            "HK",
            1.0,
            "hk01.example.test"
        )));
        assert!(is_ipv6_only_node(&demo_node(
            "v6-name-3",
            "台湾 仅IPv6 节点",
            "TW",
            1.0,
            "tw01.example.test"
        )));
        assert!(is_ipv6_only_node(&demo_node(
            "v6-name-4",
            "US v6-only 01",
            "US",
            1.0,
            "us01.example.test"
        )));
        assert!(!is_ipv6_only_node(&demo_node(
            "dual-name-1",
            "HK-01-IPv6",
            "HK",
            1.0,
            "hk01.example.test"
        )));
        assert!(!is_ipv6_only_node(&demo_node(
            "dual-name-2",
            "日本 IPv6 双栈 01",
            "JP",
            1.0,
            "jp01.example.test"
        )));
    }

    #[test]
    fn probe_snapshot_from_results_with_kinds_isolates_latency_speeds_gemini_and_rfc3339_order() {
        let mut kinds = HashMap::new();
        for def in ProbeDefinition::builtin_defaults() {
            kinds.insert(def.id, def.kind);
        }
        kinds.insert("custom_ext".to_string(), ProbeKind::ExternalCmd);
        kinds.insert("custom_unlock".to_string(), ProbeKind::UnlockRegex);

        // Simulate SQLite DESC order where Windsurf (1423ms), Upload (3500ms), Download (2800ms),
        // Keepalive (1900ms), ExternalCmd (2200ms) finished AFTER builtin_latency (38.5ms).
        let mut windsurf_map = HashMap::new();
        windsurf_map.insert("windsurf".to_string(), true);

        let mut gemini_map = HashMap::new();
        gemini_map.insert("gemini".to_string(), false);

        let mut google_cn_map = HashMap::new();
        google_cn_map.insert("google_clean".to_string(), true);
        google_cn_map.insert("gemini_aistudio".to_string(), true);
        google_cn_map.insert("gemini".to_string(), true);

        let mut custom_unlock_map = HashMap::new();
        custom_unlock_map.insert("custom_site".to_string(), true);

        let results = vec![
            // Newest: Upload failed with leaked stage1 speed (must NOT populate top-level or per-probe speed)
            ProbeResultRecord {
                node_id: "n1".into(),
                probe_id: "builtin_upload".into(),
                tested_at: "2026-11-27T13:00:10.500Z".into(),
                ok: false,
                latency_ms: Some(3500.0),
                up_mbps: Some(0.14),
                ..Default::default()
            },
            // Download ok (2800ms transfer duration must NOT pollute top-level latency_ms)
            ProbeResultRecord {
                node_id: "n1".into(),
                probe_id: "builtin_download".into(),
                tested_at: "2026-11-27T21:00:09+08:00".into(), // 13:00:09Z
                ok: true,
                latency_ms: Some(2800.0),
                down_mbps: Some(185.5),
                ..Default::default()
            },
            // ExternalCmd ok (with positive upload speed fallback)
            ProbeResultRecord {
                node_id: "n1".into(),
                probe_id: "custom_ext".into(),
                tested_at: "2026-11-27T13:00:08Z".into(),
                ok: true,
                latency_ms: Some(2200.0),
                up_mbps: Some(42.0),
                ..Default::default()
            },
            // Keepalive newer = true
            ProbeResultRecord {
                node_id: "n1".into(),
                probe_id: "builtin_keepalive_60s".into(),
                tested_at: "2026-11-27T13:00:07Z".into(),
                ok: true,
                latency_ms: Some(1900.0),
                keepalive_60s_ok: Some(true),
                ..Default::default()
            },
            // Windsurf unlock (1423ms full page load must NEVER override 38.5ms hot latency!)
            ProbeResultRecord {
                node_id: "n1".into(),
                probe_id: "builtin_unlock_windsurf".into(),
                tested_at: "2026-11-27T13:00:06Z".into(),
                ok: true,
                latency_ms: Some(1423.0),
                unlocked_map: windsurf_map,
                ..Default::default()
            },
            // Google CN ran AFTER builtin_unlock_gemini with AI Studio = true, MUST NOT overwrite gemini=false!
            ProbeResultRecord {
                node_id: "n1".into(),
                probe_id: "builtin_google_cn".into(),
                tested_at: "2026-11-27T13:00:05.9Z".into(),
                ok: true,
                latency_ms: Some(610.0),
                cf_loc: Some("JP".into()),
                yt_gl: Some("JP".into()),
                google_clean: Some(true),
                unlocked_map: google_cn_map,
                ..Default::default()
            },
            // Dedicated Gemini probe ran earlier and found API geo-blocked (gemini = false)
            ProbeResultRecord {
                node_id: "n1".into(),
                probe_id: "builtin_unlock_gemini".into(),
                tested_at: "2026-11-27T13:00:05.123456Z".into(),
                ok: false,
                latency_ms: Some(890.0),
                unlocked_map: gemini_map,
                ..Default::default()
            },
            // Custom unlock probe
            ProbeResultRecord {
                node_id: "n1".into(),
                probe_id: "custom_unlock".into(),
                tested_at: "2026-11-27T13:00:04Z".into(),
                ok: true,
                latency_ms: Some(777.0),
                unlocked_map: custom_unlock_map,
                ..Default::default()
            },
            // Standard L0 latency ran FIRST (earliest timestamp)
            ProbeResultRecord {
                node_id: "n1".into(),
                probe_id: "builtin_latency".into(),
                tested_at: "2026-11-27T13:00:01Z".into(),
                ok: true,
                latency_ms: Some(38.5),
                jitter_ms: Some(2.1),
                loss_pct: Some(0.0),
                ..Default::default()
            },
            // Older stale google_cn record (must NEVER reverse-override newer clean JP values)
            ProbeResultRecord {
                node_id: "n1".into(),
                probe_id: "legacy_google_probe".into(),
                tested_at: "2026-11-26T00:00:00Z".into(),
                ok: false,
                cf_loc: Some("CN".into()),
                yt_gl: Some("HK".into()),
                google_clean: Some(false),
                keepalive_60s_ok: Some(false),
                ..Default::default()
            },
        ];

        let snap = ProbeSnapshot::from_results_with_kinds("n1", &results, None, &kinds);
        assert!(snap.ok);
        assert_eq!(snap.latency_ms, Some(38.5));
        assert_eq!(snap.jitter_ms, Some(2.1));
        assert_eq!(snap.loss_pct, Some(0.0));
        // Failed builtin_upload (0.14) ignored; ExternalCmd (42.0) provides valid ok up_mbps
        assert_eq!(snap.up_mbps, Some(42.0));
        assert_eq!(snap.probe_up("builtin_upload"), None);
        // Failed probe durations must NEVER pollute `per_probe_ping_ms` / `probe_ping(...)`.
        assert_eq!(snap.probe_ping("builtin_upload"), None);
        assert_eq!(snap.probe_ping("builtin_unlock_gemini"), None);
        assert_eq!(snap.probe_ping("builtin_latency"), Some(38.5));
        assert_eq!(snap.down_mbps, Some(185.5));
        assert_eq!(snap.cf_loc.as_deref(), Some("JP"));
        assert_eq!(snap.yt_gl.as_deref(), Some("JP"));
        assert_eq!(snap.google_clean, Some(true));
        assert!(!snap.google_risk_mismatch);
        assert_eq!(snap.keepalive_60s_ok, Some(true));
        // Dedicated builtin_unlock_gemini strictly owns "gemini"; google_cn independently keeps "gemini_aistudio"
        assert_eq!(snap.unlocked_sites.get("gemini"), Some(&false));
        assert_eq!(snap.unlocked_sites.get("gemini_aistudio"), Some(&true));
        assert_eq!(snap.unlocked_sites.get("windsurf"), Some(&true));
        assert_eq!(snap.tested_at, "2026-11-27T13:00:10.500Z");
        assert_eq!(
            snap.per_probe_tested_at.get("builtin_latency").map(String::as_str),
            Some("2026-11-27T13:00:01Z")
        );
        assert_eq!(
            snap.per_probe_tested_at.get("builtin_download").map(String::as_str),
            Some("2026-11-27T21:00:09+08:00")
        );

        // When Latency fails, snap.ok MUST be false and latency_ms MUST be None even if Unlock succeeded!
        let failed_lat_results = vec![
            ProbeResultRecord {
                node_id: "n2".into(),
                probe_id: "builtin_unlock_windsurf".into(),
                tested_at: "2026-11-27T13:01:00Z".into(),
                ok: true,
                latency_ms: Some(1200.0),
                ..Default::default()
            },
            ProbeResultRecord {
                node_id: "n2".into(),
                probe_id: "builtin_latency".into(),
                tested_at: "2026-11-27T13:02:00Z".into(),
                ok: false,
                latency_ms: None,
                loss_pct: Some(100.0),
                ..Default::default()
            },
        ];
        let snap_fail = ProbeSnapshot::from_results_with_kinds("n2", &failed_lat_results, None, &kinds);
        assert!(!snap_fail.ok);
        assert_eq!(snap_fail.latency_ms, None);
        assert_eq!(snap_fail.loss_pct, Some(100.0));
        assert_eq!(snap_fail.probe_ping("builtin_latency"), None);

        // Non-positive latency (0.0ms) or failed probe with elapsed latency must not enter per_probe_ping_ms.
        let edge_results = vec![
            ProbeResultRecord {
                node_id: "n3".into(),
                probe_id: "custom_lat_fail".into(),
                tested_at: "2026-11-27T13:03:00Z".into(),
                ok: false,
                latency_ms: Some(4500.0),
                ..Default::default()
            },
            ProbeResultRecord {
                node_id: "n3".into(),
                probe_id: "custom_lat_zero".into(),
                tested_at: "2026-11-27T13:03:01Z".into(),
                ok: true,
                latency_ms: Some(0.0),
                ..Default::default()
            },
        ];
        let snap_edge = ProbeSnapshot::from_results_with_kinds("n3", &edge_results, None, &kinds);
        assert_eq!(snap_edge.probe_ping("custom_lat_fail"), None);
        assert_eq!(snap_edge.probe_ping("custom_lat_zero"), None);
    }
}
