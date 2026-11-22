use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    /// Resolve whether domestic pre-acceleration should wrap this node.
    /// Per-node `preaccel_override` takes precedence over global `skip_443_native`.
    pub fn should_apply_preaccel(&self, global_skip_443_native: bool) -> bool {
        if let Some(forced) = self.preaccel_override {
            return forced;
        }
        if !self.preaccel_eligible {
            return false;
        }
        if global_skip_443_native && self.is_443_native {
            return false;
        }
        true
    }
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
/// (covers OpenAI, Anthropic, Google AI, and Windsurf/Devin/Codeium endpoints).
pub const DEFAULT_AI_ROUTING_DOMAINS: &[&str] = &[
    "openai.com",
    "chatgpt.com",
    "oaistatic.com",
    "oaiusercontent.com",
    "anthropic.com",
    "claude.ai",
    "gemini.google.com",
    "aistudio.google.com",
    "generativelanguage.googleapis.com",
    "codeium.com",
    "windsurf.com",
    "devin.ai",
    "cognition.ai",
    "exafunction.com",
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
}

impl ProbeSnapshot {
    /// Merge latest per-probe result rows for a node into one formula-ready snapshot.
    /// When `primary_probe_id` is given, its scalar metrics take priority for top-level
    /// `latency_ms`/`up_mbps`/`down_mbps` fields.
    pub fn from_results(
        node_id: &str,
        results: &[ProbeResultRecord],
        primary_probe_id: Option<&str>,
    ) -> Self {
        let mut snap = Self {
            node_id: node_id.to_string(),
            ..Default::default()
        };
        if results.is_empty() {
            return snap;
        }

        let mut any_ok = false;
        let mut primary_matched = false;

        for rec in results {
            if rec.tested_at > snap.tested_at {
                snap.tested_at = rec.tested_at.clone();
            }
            if rec.ok {
                any_ok = true;
            }

            snap.per_probe_ok.insert(rec.probe_id.clone(), rec.ok);
            if let Some(up) = rec.up_mbps {
                snap.per_probe_up_mbps.insert(rec.probe_id.clone(), up);
            }
            if let Some(down) = rec.down_mbps {
                snap.per_probe_down_mbps.insert(rec.probe_id.clone(), down);
            }
            if let Some(ping) = rec.latency_ms {
                snap.per_probe_ping_ms.insert(rec.probe_id.clone(), ping);
            }
            if let Some(ref detail) = rec.detail {
                snap.per_probe_detail
                    .insert(rec.probe_id.clone(), detail.clone());
            }

            let is_primary = primary_probe_id.is_some_and(|pid| pid == rec.probe_id);
            if is_primary {
                primary_matched = true;
                snap.ok = rec.ok;
                if rec.latency_ms.is_some() {
                    snap.latency_ms = rec.latency_ms;
                }
                if rec.jitter_ms.is_some() {
                    snap.jitter_ms = rec.jitter_ms;
                }
                if rec.loss_pct.is_some() {
                    snap.loss_pct = rec.loss_pct;
                }
                if rec.up_mbps.is_some() {
                    snap.up_mbps = rec.up_mbps;
                }
                if rec.down_mbps.is_some() {
                    snap.down_mbps = rec.down_mbps;
                }
            } else {
                if snap.latency_ms.is_none() && rec.latency_ms.is_some() {
                    snap.latency_ms = rec.latency_ms;
                }
                if snap.jitter_ms.is_none() && rec.jitter_ms.is_some() {
                    snap.jitter_ms = rec.jitter_ms;
                }
                if snap.loss_pct.is_none() && rec.loss_pct.is_some() {
                    snap.loss_pct = rec.loss_pct;
                }
                if snap.up_mbps.is_none() && rec.up_mbps.is_some() {
                    snap.up_mbps = rec.up_mbps;
                }
                if snap.down_mbps.is_none() && rec.down_mbps.is_some() {
                    snap.down_mbps = rec.down_mbps;
                }
            }

            if rec.cf_loc.is_some() {
                snap.cf_loc = rec.cf_loc.clone();
            }
            if rec.yt_gl.is_some() {
                snap.yt_gl = rec.yt_gl.clone();
            }
            if rec.google_clean.is_some() {
                snap.google_clean = rec.google_clean;
            }
            if rec.keepalive_60s_ok.is_some() {
                snap.keepalive_60s_ok = rec.keepalive_60s_ok;
            }
            for (site, unlocked) in &rec.unlocked_map {
                snap.unlocked_sites.insert(site.clone(), *unlocked);
            }
        }

        if !primary_matched {
            snap.ok = any_ok;
        }

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
