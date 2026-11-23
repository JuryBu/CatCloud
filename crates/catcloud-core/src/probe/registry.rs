use crate::error::{CatError, CatResult};
use crate::models::{ProbeDefinition, ProbeKind};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use url::Url;

/// Minimum allowed probe timeout in milliseconds.
pub const MIN_TIMEOUT_MS: u64 = 200;

/// Maximum allowed probe timeout in milliseconds (2 minutes).
pub const MAX_TIMEOUT_MS: u64 = 120_000;

/// Minimum explicit throughput payload size in bytes (1 KiB).
pub const MIN_PAYLOAD_BYTES: u64 = 1024;

/// Maximum allowed throughput payload size in bytes (8 MiB).
pub const MAX_PAYLOAD_BYTES: u64 = 8 * 1024 * 1024;

/// Maximum length of a probe regular expression pattern.
pub const MAX_REGEX_LEN: usize = 2048;

/// Maximum length of a probe identifier.
pub const MAX_PROBE_ID_LEN: usize = 64;

/// Default upload throughput target payload size after passing the 512 KiB fast fuse.
pub const DEFAULT_UPLOAD_PAYLOAD_BYTES: u64 = 2 * 1024 * 1024;

/// Default download throughput target payload size after passing the 512 KiB fast fuse.
pub const DEFAULT_DOWNLOAD_PAYLOAD_BYTES: u64 = 2 * 1024 * 1024;

/// Three-tier traffic-saving probe funnel classification.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FunnelTier {
    /// Tier 0: lightweight connectivity, latency, jitter, and packet-loss checks.
    L0Connectivity,
    /// Tier 1: Google cleanliness ground-truth and site/AI unlock regex checks.
    L1CleanAndUnlock,
    /// Tier 2: upload/download throughput (with 512 KiB fast fuse), silent keep-alive, and external script probes.
    L2ThroughputAndKeepalive,
}

impl FunnelTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::L0Connectivity => "l0_connectivity",
            Self::L1CleanAndUnlock => "l1_clean_and_unlock",
            Self::L2ThroughputAndKeepalive => "l2_throughput_and_keepalive",
        }
    }

    pub fn all() -> [FunnelTier; 3] {
        [
            Self::L0Connectivity,
            Self::L1CleanAndUnlock,
            Self::L2ThroughputAndKeepalive,
        ]
    }
}

/// Map a `ProbeKind` into its traffic-saving funnel tier.
pub fn tier_for_kind(kind: &ProbeKind) -> FunnelTier {
    match kind {
        ProbeKind::Latency => FunnelTier::L0Connectivity,
        ProbeKind::GoogleCn | ProbeKind::UnlockRegex => FunnelTier::L1CleanAndUnlock,
        ProbeKind::Upload
        | ProbeKind::Download
        | ProbeKind::Keepalive
        | ProbeKind::ExternalCmd => FunnelTier::L2ThroughputAndKeepalive,
    }
}

/// Validate a probe definition across all 7 `ProbeKind` variants:
/// - identifier syntax and length
/// - URL scheme/host or external command sanity
/// - HTTP method and status range
/// - regular expression compilation and size limit
/// - timeout and payload upper bounds
pub fn validate_definition(def: &ProbeDefinition) -> CatResult<()> {
    let id = def.id.trim();
    if id.is_empty() {
        return Err(CatError::Validation("probe id cannot be empty".into()));
    }
    if id.len() > MAX_PROBE_ID_LEN {
        return Err(CatError::Validation(format!(
            "probe id `{id}` exceeds maximum length of {MAX_PROBE_ID_LEN} characters"
        )));
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(CatError::Validation(format!(
            "probe id `{id}` may only contain ASCII letters, digits, '-', '_', and '.'"
        )));
    }

    if def.name.trim().is_empty() {
        return Err(CatError::Validation(format!(
            "probe `{id}` display name cannot be empty"
        )));
    }

    if !(MIN_TIMEOUT_MS..=MAX_TIMEOUT_MS).contains(&def.timeout_ms) {
        return Err(CatError::Validation(format!(
            "probe `{id}` timeout_ms={} must be within {}..={}",
            def.timeout_ms, MIN_TIMEOUT_MS, MAX_TIMEOUT_MS
        )));
    }

    let target = def.target_url.trim();
    if target.is_empty() {
        return Err(CatError::Validation(format!(
            "probe `{id}` target_url cannot be empty"
        )));
    }

    match def.kind {
        ProbeKind::ExternalCmd => {
            if target.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n') {
                return Err(CatError::Validation(format!(
                    "external probe `{id}` command must not contain control newlines or NUL bytes"
                )));
            }
            let stripped = target.strip_prefix("cmd://").unwrap_or(target).trim();
            if stripped.is_empty() {
                return Err(CatError::Validation(format!(
                    "external probe `{id}` executable path cannot be empty"
                )));
            }
        }
        ProbeKind::Latency
        | ProbeKind::Upload
        | ProbeKind::Download
        | ProbeKind::Keepalive
        | ProbeKind::GoogleCn
        | ProbeKind::UnlockRegex => {
            let parsed = Url::parse(target).map_err(|e| {
                CatError::Validation(format!("probe `{id}` has invalid target_url `{target}`: {e}"))
            })?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err(CatError::Validation(format!(
                    "probe `{id}` URL scheme `{}` is not allowed; only http and https are supported",
                    parsed.scheme()
                )));
            }
            if parsed.host_str().is_none_or(|h| h.trim().is_empty()) {
                return Err(CatError::Validation(format!(
                    "probe `{id}` URL `{target}` must include a valid host"
                )));
            }

            let method_upper = def.method.trim().to_ascii_uppercase();
            if !matches!(
                method_upper.as_str(),
                "GET" | "POST" | "HEAD" | "PUT" | "OPTIONS"
            ) {
                return Err(CatError::Validation(format!(
                    "probe `{id}` HTTP method `{}` is not supported (allowed: GET, POST, HEAD, PUT, OPTIONS)",
                    def.method
                )));
            }
        }
    }

    if let Some(status) = def.expected_status {
        if !(100..=599).contains(&status) {
            return Err(CatError::Validation(format!(
                "probe `{id}` expected_status={status} must be within 100..=599"
            )));
        }
    }

    if let Some(ref pattern) = def.body_regex {
        if !pattern.is_empty() {
            if pattern.len() > MAX_REGEX_LEN {
                return Err(CatError::Validation(format!(
                    "probe `{id}` body_regex exceeds maximum length of {MAX_REGEX_LEN} bytes"
                )));
            }
            Regex::new(pattern).map_err(|e| {
                CatError::Validation(format!("probe `{id}` has invalid body_regex: {e}"))
            })?;
        }
    }

    if let Some(payload) = def.payload_bytes {
        if payload < MIN_PAYLOAD_BYTES || payload > MAX_PAYLOAD_BYTES {
            return Err(CatError::Validation(format!(
                "probe `{id}` payload_bytes={payload} must be within {}..={} bytes",
                MIN_PAYLOAD_BYTES, MAX_PAYLOAD_BYTES
            )));
        }
    }

    Ok(())
}

/// Extensible in-memory registry of built-in and user-defined probes.
#[derive(Debug, Clone)]
pub struct ProbeRegistry {
    probes: BTreeMap<String, ProbeDefinition>,
    allow_builtin_override: bool,
}

impl Default for ProbeRegistry {
    fn default() -> Self {
        Self::with_builtins()
    }
}

impl ProbeRegistry {
    /// Create an empty registry with built-in overwrite/removal protection enabled.
    pub fn new() -> Self {
        Self {
            probes: BTreeMap::new(),
            allow_builtin_override: false,
        }
    }

    /// Create a registry pre-populated with CatCloud's standard built-in probe suite.
    pub fn with_builtins() -> Self {
        let mut reg = Self::new();
        for def in ProbeDefinition::builtin_defaults() {
            reg.probes.insert(def.id.clone(), def);
        }
        reg
    }

    /// Construct a registry from a list of persisted definitions, validating every entry.
    pub fn from_definitions(
        defs: Vec<ProbeDefinition>,
        allow_builtin_override: bool,
    ) -> CatResult<Self> {
        let mut reg = Self {
            probes: BTreeMap::new(),
            allow_builtin_override,
        };
        for def in defs {
            validate_definition(&def)?;
            reg.probes.insert(def.id.clone(), def);
        }
        Ok(reg)
    }

    /// Configure whether built-in probes may be overwritten or removed.
    pub fn set_allow_builtin_override(&mut self, allow: bool) {
        self.allow_builtin_override = allow;
    }

    pub fn allow_builtin_override(&self) -> bool {
        self.allow_builtin_override
    }

    /// Validate and insert or update a probe definition.
    /// Rejects overwriting a protected built-in probe unless `allow_builtin_override` is enabled.
    pub fn register(&mut self, def: ProbeDefinition) -> CatResult<()> {
        self.register_with_override(def, self.allow_builtin_override)
    }

    /// Validate and register a probe definition with an explicit per-call builtin override switch.
    pub fn register_with_override(
        &mut self,
        def: ProbeDefinition,
        allow_override_builtin: bool,
    ) -> CatResult<()> {
        validate_definition(&def)?;
        if let Some(existing) = self.probes.get(&def.id) {
            if existing.builtin && !allow_override_builtin {
                return Err(CatError::Validation(format!(
                    "probe `{}` is a protected built-in probe; enable override to modify it",
                    def.id
                )));
            }
        }
        self.probes.insert(def.id.clone(), def);
        Ok(())
    }

    /// Remove a probe by ID. Protected built-in probes cannot be removed unless
    /// `allow_builtin_override` is enabled.
    pub fn remove(&mut self, id: &str) -> CatResult<ProbeDefinition> {
        self.remove_with_override(id, self.allow_builtin_override)
    }

    /// Remove a probe by ID with an explicit per-call builtin override switch.
    pub fn remove_with_override(
        &mut self,
        id: &str,
        allow_remove_builtin: bool,
    ) -> CatResult<ProbeDefinition> {
        let Some(existing) = self.probes.get(id) else {
            return Err(CatError::NotFound(format!("probe `{id}` not found")));
        };
        if existing.builtin && !allow_remove_builtin {
            return Err(CatError::Validation(format!(
                "probe `{id}` is a protected built-in probe and cannot be removed"
            )));
        }
        self.probes
            .remove(id)
            .ok_or_else(|| CatError::NotFound(format!("probe `{id}` not found")))
    }

    pub fn get(&self, id: &str) -> Option<&ProbeDefinition> {
        self.probes.get(id)
    }

    /// Return all registered probes, built-ins first then sorted by ID.
    pub fn list(&self) -> Vec<&ProbeDefinition> {
        let mut items: Vec<&ProbeDefinition> = self.probes.values().collect();
        items.sort_by(|a, b| b.builtin.cmp(&a.builtin).then_with(|| a.id.cmp(&b.id)));
        items
    }

    pub fn list_owned(&self) -> Vec<ProbeDefinition> {
        self.list().into_iter().cloned().collect()
    }

    /// Select all registered probes belonging to the given traffic-saving funnel tier.
    pub fn select_funnel_tier(&self, tier: FunnelTier) -> Vec<&ProbeDefinition> {
        self.list()
            .into_iter()
            .filter(|def| tier_for_kind(&def.kind) == tier)
            .collect()
    }

    /// Select all registered probes matching a specific `ProbeKind`.
    pub fn select_by_kind(&self, kind: &ProbeKind) -> Vec<&ProbeDefinition> {
        self.list()
            .into_iter()
            .filter(|def| &def.kind == kind)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.probes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.probes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_custom_probe(id: &str, kind: ProbeKind) -> ProbeDefinition {
        match kind {
            ProbeKind::ExternalCmd => ProbeDefinition {
                id: id.to_string(),
                name: format!("Custom {id}"),
                kind,
                target_url: "python3 /opt/probes/check.py".to_string(),
                method: "EXEC".to_string(),
                expected_status: None,
                body_regex: None,
                payload_bytes: None,
                timeout_ms: 8000,
                builtin: false,
            },
            _ => ProbeDefinition {
                id: id.to_string(),
                name: format!("Custom {id}"),
                kind,
                target_url: "https://example.invalid/check".to_string(),
                method: "GET".to_string(),
                expected_status: Some(200),
                body_regex: Some("ok|ready".to_string()),
                payload_bytes: Some(512 * 1024),
                timeout_ms: 5000,
                builtin: false,
            },
        }
    }

    #[test]
    fn builtin_suite_validates_and_groups_into_three_funnel_tiers() {
        let reg = ProbeRegistry::with_builtins();
        assert!(reg.len() >= 6);
        for def in reg.list() {
            validate_definition(def).expect("builtin probe must validate cleanly");
        }

        let l0 = reg.select_funnel_tier(FunnelTier::L0Connectivity);
        let l1 = reg.select_funnel_tier(FunnelTier::L1CleanAndUnlock);
        let l2 = reg.select_funnel_tier(FunnelTier::L2ThroughputAndKeepalive);

        assert!(l0.iter().any(|p| p.kind == ProbeKind::Latency));
        assert!(l1.iter().any(|p| p.kind == ProbeKind::GoogleCn));
        assert!(l1.iter().any(|p| p.kind == ProbeKind::UnlockRegex));
        assert!(l2.iter().any(|p| p.kind == ProbeKind::Upload));
        assert!(l2.iter().any(|p| p.kind == ProbeKind::Download));
        assert!(l2.iter().any(|p| p.kind == ProbeKind::Keepalive));
    }

    #[test]
    fn register_get_remove_and_builtin_protection_switch() {
        let mut reg = ProbeRegistry::with_builtins();

        // Register all custom kinds including ExternalCmd
        let ext = sample_custom_probe("custom_ext", ProbeKind::ExternalCmd);
        reg.register(ext.clone()).expect("register external probe");
        assert_eq!(reg.get("custom_ext"), Some(&ext));
        assert!(reg
            .select_funnel_tier(FunnelTier::L2ThroughputAndKeepalive)
            .iter()
            .any(|p| p.id == "custom_ext"));

        // Protected built-in cannot be overwritten or deleted by default
        let mut tampered_builtin = reg.get("builtin_latency").unwrap().clone();
        tampered_builtin.timeout_ms = 9000;
        assert!(reg.register(tampered_builtin.clone()).is_err());
        assert!(reg.remove("builtin_latency").is_err());

        // Enabling override switch permits modification and removal
        reg.set_allow_builtin_override(true);
        reg.register(tampered_builtin.clone())
            .expect("override allowed");
        assert_eq!(reg.get("builtin_latency").unwrap().timeout_ms, 9000);
        let removed = reg.remove("builtin_latency").expect("remove allowed");
        assert_eq!(removed.id, "builtin_latency");
        assert!(reg.get("builtin_latency").is_none());

        // Removing user probe always succeeds
        reg.set_allow_builtin_override(false);
        let removed_ext = reg.remove("custom_ext").expect("remove custom probe");
        assert_eq!(removed_ext.id, "custom_ext");
        assert!(matches!(reg.remove("missing"), Err(CatError::NotFound(_))));
    }

    #[test]
    fn validation_rejects_bad_urls_regex_timeouts_and_payload_limits() {
        let mut bad_scheme = sample_custom_probe("bad_scheme", ProbeKind::UnlockRegex);
        bad_scheme.target_url = "file:///etc/passwd".to_string();
        assert!(validate_definition(&bad_scheme).is_err());

        let mut bad_regex = sample_custom_probe("bad_regex", ProbeKind::UnlockRegex);
        bad_regex.body_regex = Some("[unclosed(".to_string());
        assert!(validate_definition(&bad_regex).is_err());

        let mut bad_timeout = sample_custom_probe("bad_timeout", ProbeKind::Latency);
        bad_timeout.timeout_ms = MAX_TIMEOUT_MS + 1;
        assert!(validate_definition(&bad_timeout).is_err());

        let mut bad_payload = sample_custom_probe("bad_payload", ProbeKind::Upload);
        bad_payload.payload_bytes = Some(MAX_PAYLOAD_BYTES + 1);
        assert!(validate_definition(&bad_payload).is_err());

        let mut bad_id = sample_custom_probe("bad id/slash", ProbeKind::Latency);
        bad_id.id = "bad id/slash".to_string();
        assert!(validate_definition(&bad_id).is_err());

        let mut bad_ext = sample_custom_probe("bad_ext", ProbeKind::ExternalCmd);
        bad_ext.target_url = "echo ok\nrm -rf /".to_string();
        assert!(validate_definition(&bad_ext).is_err());
    }

    #[test]
    fn semantic_ai_unlock_probe_definitions_validate_and_map_to_l1() {
        let mut reg = ProbeRegistry::new();
        let defs = [
            ProbeDefinition {
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
            ProbeDefinition {
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
            ProbeDefinition {
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
        ];

        for def in defs {
            validate_definition(&def).expect("semantic AI unlock probe must validate");
            reg.register(def).expect("register semantic AI unlock probe");
        }

        let l1 = reg.select_funnel_tier(FunnelTier::L1CleanAndUnlock);
        assert_eq!(l1.len(), 3);
    }
}
