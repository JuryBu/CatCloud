use crate::error::{CatError, CatResult};
use crate::models::group::{
    MMRELAY_ROLE_DOMESTIC_PRE_ACCEL, MMRELAY_SCHEMA_V1, MmRelayBundleV1, PreAccelRelay,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use uuid::Uuid;

/// Single-line clipboard URI prefix for `mmrelay/v1` relay bundles.
pub const MMRELAY_URI_PREFIX: &str = "mmrelay://v1/";

/// Days-remaining threshold below which a relay triggers an `expiring_soon` reminder.
pub const EXPIRY_SOON_THRESHOLD_DAYS: i64 = 3;

/// Mihomo inner `load-balance` proxy group name aggregating distinct physical domestic cloud hosts.
pub const PREACCEL_LB_GROUP_NAME: &str = "⚖️ 预加速多云均衡";

/// Supported domestic pre-acceleration relay protocols.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelayProtocol {
    AnyTls,
    Trojan,
    Vless,
    Hysteria2,
    Tuic,
}

impl RelayProtocol {
    /// Parse a protocol identifier (case-insensitive, supporting common aliases).
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "anytls" => Some(Self::AnyTls),
            "trojan" => Some(Self::Trojan),
            "vless" => Some(Self::Vless),
            "hysteria2" | "hy2" => Some(Self::Hysteria2),
            "tuic" => Some(Self::Tuic),
            _ => None,
        }
    }

    /// Canonical Mihomo proxy `type` value.
    pub fn mihomo_type(self) -> &'static str {
        match self {
            Self::AnyTls => "anytls",
            Self::Trojan => "trojan",
            Self::Vless => "vless",
            Self::Hysteria2 => "hysteria2",
            Self::Tuic => "tuic",
        }
    }

    /// Protocol-specific field name used for TLS SNI in Mihomo YAML.
    pub fn sni_field_name(self) -> &'static str {
        match self {
            Self::Vless => "servername",
            Self::AnyTls | Self::Trojan | Self::Hysteria2 | Self::Tuic => "sni",
        }
    }

    /// Return `true` for TCP-stream domestic relay transports preferred as primary representatives
    /// in multi-cloud `load-balance` pools carrying TCP business nodes.
    pub fn is_tcp_stream(self) -> bool {
        matches!(self, Self::AnyTls | Self::Trojan | Self::Vless)
    }
}

/// Deduplicated physical-host partition of enabled domestic pre-acceleration relays.
///
/// Each distinct physical host (grouped by normalized `server`) contributes exactly one primary
/// representative (preferring TCP-stream protocols `anytls`/`trojan`/`vless` over same-host UDP
/// protocols `hysteria2`/`tuic`, tie-broken by `priority ASC, id ASC`) to `primary_host_relays`,
/// while remaining same-host protocols are placed in `secondary_protocol_relays` as outer
/// `fallback` backups.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PhysicalRelaySelection {
    /// One primary representative relay per distinct physical host, ordered by `(priority ASC, id ASC)`.
    pub primary_host_relays: Vec<PreAccelRelay>,
    /// Remaining enabled relays sharing a physical host with a primary representative,
    /// ordered by `(priority ASC, id ASC)`.
    pub secondary_protocol_relays: Vec<PreAccelRelay>,
    /// Number of distinct physical cloud hosts represented in `primary_host_relays`.
    pub distinct_host_count: usize,
}

/// Normalize a domestic relay `server` address into a canonical physical-host deduplication key.
pub fn normalize_relay_host_key(server: &str) -> String {
    if let Some(ip) = parse_server_ip(server) {
        ip.to_string().to_ascii_lowercase()
    } else {
        server
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .trim_end_matches('.')
            .to_ascii_lowercase()
    }
}

/// Return `true` only when at least one enabled domestic relay exists and **every** enabled
/// relay declares public IPv6 egress support (preventing IPv6 blackholes in mixed IPv4-only
/// + dual-stack multi-cloud relay pools).
pub fn relays_support_ipv6(relays: &[PreAccelRelay]) -> bool {
    let mut has_enabled = false;
    for relay in relays.iter().filter(|r| r.enabled) {
        has_enabled = true;
        if !relay.supports_ipv6 {
            return false;
        }
    }
    has_enabled
}

/// Deduplicate enabled domestic relays by normalized physical host (`server`).
///
/// Per physical host, picks the highest-priority TCP-stream transport (`anytls`/`trojan`/`vless`)
/// into `primary_host_relays` (falling back to the highest-priority UDP protocol only when that
/// physical host has no TCP-stream relay), and places all remaining protocols on that same host
/// into `secondary_protocol_relays` for outer `fallback` backup.
pub fn select_physical_host_relays(relays: &[PreAccelRelay]) -> PhysicalRelaySelection {
    let mut by_host: HashMap<String, Vec<PreAccelRelay>> = HashMap::new();

    for relay in relays.iter().filter(|r| r.enabled) {
        let raw_key = normalize_relay_host_key(&relay.server);
        let host_key = if raw_key.is_empty() {
            format!("__empty_host__:{}", relay.id)
        } else {
            raw_key
        };
        by_host.entry(host_key).or_default().push(relay.clone());
    }

    let mut primary_host_relays: Vec<PreAccelRelay> = Vec::with_capacity(by_host.len());
    let mut secondary_protocol_relays: Vec<PreAccelRelay> = Vec::new();

    for mut group in by_host.into_values() {
        group.sort_by(|a, b| {
            let a_non_tcp = !RelayProtocol::parse(&a.protocol).is_some_and(RelayProtocol::is_tcp_stream);
            let b_non_tcp = !RelayProtocol::parse(&b.protocol).is_some_and(RelayProtocol::is_tcp_stream);
            a_non_tcp
                .cmp(&b_non_tcp)
                .then_with(|| a.priority.cmp(&b.priority))
                .then_with(|| a.id.cmp(&b.id))
        });

        let mut iter = group.into_iter();
        if let Some(primary) = iter.next() {
            primary_host_relays.push(primary);
            secondary_protocol_relays.extend(iter);
        }
    }

    primary_host_relays.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));
    secondary_protocol_relays
        .sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));
    let distinct_host_count = primary_host_relays.len();

    PhysicalRelaySelection {
        primary_host_relays,
        secondary_protocol_relays,
        distinct_host_count,
    }
}

/// Severity level for relay validation findings.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelayValidationSeverity {
    Error,
    Warning,
    Info,
}

/// Machine-readable diagnostic codes for domestic pre-acceleration relay checks.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelayValidationCode {
    EmptyId,
    EmptyName,
    EmptyServer,
    InvalidPort,
    UnsupportedProtocol,
    EmptyPassword,
    InvalidVlessUuid,
    ForbiddenSniOnDomestic443,
    SniPresentWarning,
    NonPureIpServer,
    SkipCertVerifyDisabledOnPureIp,
    Non443PortWarning,
    InvalidExpiresAt,
    ExpiringSoon,
    Expired,
}

/// Structured validation finding returned by `validate_relay`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayValidationIssue {
    pub code: RelayValidationCode,
    pub field: String,
    pub severity: RelayValidationSeverity,
    pub message: String,
}

/// Evaluated expiry classification for a relay's `expires_at` timestamp.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RelayExpiryStatus {
    NoExpiry,
    Active { days_remaining: i64 },
    ExpiringSoon { days_remaining: i64 },
    Expired { days_overdue: i64 },
    InvalidFormat { raw: String },
}

impl RelayExpiryStatus {
    /// Machine tag matching UI/CLI status badges (`none`, `active`, `expiring_soon`, `expired`, `invalid`).
    pub fn tag(&self) -> &'static str {
        match self {
            Self::NoExpiry => "none",
            Self::Active { .. } => "active",
            Self::ExpiringSoon { .. } => "expiring_soon",
            Self::Expired { .. } => "expired",
            Self::InvalidFormat { .. } => "invalid",
        }
    }
}

/// Convenience helper to wrap a relay slice into a standard `mmrelay/v1` bundle.
pub fn bundle_from_relays(relays: Vec<PreAccelRelay>) -> MmRelayBundleV1 {
    MmRelayBundleV1 {
        schema: MMRELAY_SCHEMA_V1.to_string(),
        role: MMRELAY_ROLE_DOMESTIC_PRE_ACCEL.to_string(),
        relays,
    }
}

/// Validate top-level `mmrelay/v1` envelope metadata.
pub fn validate_bundle_envelope(bundle: &MmRelayBundleV1) -> CatResult<()> {
    if bundle.schema.trim() != MMRELAY_SCHEMA_V1 {
        return Err(CatError::Validation(format!(
            "unsupported mmrelay schema `{}`; expected `{MMRELAY_SCHEMA_V1}`",
            bundle.schema
        )));
    }
    let role = bundle.role.trim();
    if !role.is_empty() && role != MMRELAY_ROLE_DOMESTIC_PRE_ACCEL {
        return Err(CatError::Validation(format!(
            "unsupported mmrelay role `{role}`; expected `{MMRELAY_ROLE_DOMESTIC_PRE_ACCEL}`"
        )));
    }
    Ok(())
}

/// Parse a `mmrelay/v1` JSON document and validate its envelope.
pub fn parse_mmrelay_json(raw: &str) -> CatResult<MmRelayBundleV1> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CatError::Validation(
            "mmrelay JSON payload cannot be empty".to_string(),
        ));
    }
    let bundle: MmRelayBundleV1 = serde_json::from_str(trimmed)?;
    validate_bundle_envelope(&bundle)?;
    Ok(bundle)
}

/// Serialize a `mmrelay/v1` bundle to pretty-printed JSON after envelope validation.
pub fn serialize_mmrelay_json(bundle: &MmRelayBundleV1) -> CatResult<String> {
    validate_bundle_envelope(bundle)?;
    Ok(serde_json::to_string_pretty(bundle)?)
}

/// Serialize a `mmrelay/v1` bundle to compact single-line JSON after envelope validation.
pub fn serialize_mmrelay_json_compact(bundle: &MmRelayBundleV1) -> CatResult<String> {
    validate_bundle_envelope(bundle)?;
    Ok(serde_json::to_string(bundle)?)
}

/// Encode a `mmrelay/v1` bundle into a single-line `mmrelay://v1/<base64url>` clipboard URI.
pub fn encode_mmrelay_uri(bundle: &MmRelayBundleV1) -> CatResult<String> {
    let compact = serialize_mmrelay_json_compact(bundle)?;
    let encoded = URL_SAFE_NO_PAD.encode(compact.as_bytes());
    Ok(format!("{MMRELAY_URI_PREFIX}{encoded}"))
}

/// Decode a single-line `mmrelay://v1/<base64url>` URI (tolerates optional `=` padding).
pub fn decode_mmrelay_uri(uri: &str) -> CatResult<MmRelayBundleV1> {
    let trimmed = uri.trim();
    let payload = strip_mmrelay_prefix(trimmed).ok_or_else(|| {
        CatError::Validation(format!(
            "invalid mmrelay URI: expected `{MMRELAY_URI_PREFIX}<base64url>` prefix"
        ))
    })?;

    let cleaned: String = payload
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let unpadded = cleaned.trim_end_matches('=');
    if unpadded.is_empty() {
        return Err(CatError::Validation(
            "mmrelay URI base64url payload is empty".to_string(),
        ));
    }

    let bytes = URL_SAFE_NO_PAD.decode(unpadded).map_err(|e| {
        CatError::Validation(format!("failed to decode mmrelay base64url payload: {e}"))
    })?;
    let json_text = String::from_utf8(bytes).map_err(|e| {
        CatError::Validation(format!("mmrelay payload is not valid UTF-8 JSON: {e}"))
    })?;

    parse_mmrelay_json(&json_text)
}

/// Auto-detect and parse either a `mmrelay://v1/<base64url>` URI or a raw `mmrelay/v1` JSON string.
pub fn parse_mmrelay_clipboard(input: &str) -> CatResult<MmRelayBundleV1> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(CatError::Validation(
            "clipboard input is empty; expected mmrelay://v1/... or mmrelay/v1 JSON".to_string(),
        ));
    }
    if strip_mmrelay_prefix(trimmed).is_some() {
        return decode_mmrelay_uri(trimmed);
    }
    if trimmed.starts_with('{') {
        return parse_mmrelay_json(trimmed);
    }
    for line in trimmed.lines() {
        let candidate = line.trim();
        if strip_mmrelay_prefix(candidate).is_some() {
            return decode_mmrelay_uri(candidate);
        }
    }
    Err(CatError::Validation(
        "unrecognized clipboard format: expected `mmrelay://v1/<base64url>` or `mmrelay/v1` JSON"
            .to_string(),
    ))
}

/// Parse an `expires_at` timestamp (RFC3339 or `YYYY-MM-DD`, treating date-only as 23:59:59 UTC).
pub fn parse_expiry_timestamp(raw: &str) -> Option<DateTime<Utc>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return Some(dt.with_timezone(&Utc));
    }
    if let Ok(date) = NaiveDate::parse_from_str(trimmed, "%Y-%m-%d")
        && let Some(naive_dt) = date.and_hms_opt(23, 59, 59)
    {
        return Some(Utc.from_utc_datetime(&naive_dt));
    }
    None
}

/// Compute signed whole-day countdown to expiry relative to `now`.
/// Values `<= 0` indicate expired; `1..=3` indicate expiring soon.
pub fn days_until_expiry(expires_at: Option<&str>, now: DateTime<Utc>) -> Option<i64> {
    let raw = expires_at?.trim();
    if raw.is_empty() {
        return None;
    }
    let expiry = parse_expiry_timestamp(raw)?;
    let delta_secs = expiry.signed_duration_since(now).num_seconds();
    if delta_secs <= 0 {
        // 0 or negative whole days (e.g. expired 1h ago => 0, expired 25h ago => -1).
        Some(delta_secs / 86_400)
    } else {
        // Round up partial remaining days so 2 hours remaining reports 1 day (expiring_soon), not 0 (expired).
        Some(delta_secs.saturating_add(86_399) / 86_400)
    }
}

/// Classify a relay's expiry status relative to `now`.
pub fn evaluate_expiry(expires_at: Option<&str>, now: DateTime<Utc>) -> RelayExpiryStatus {
    let Some(raw) = expires_at.map(str::trim).filter(|s| !s.is_empty()) else {
        return RelayExpiryStatus::NoExpiry;
    };
    let Some(expiry) = parse_expiry_timestamp(raw) else {
        return RelayExpiryStatus::InvalidFormat {
            raw: raw.to_string(),
        };
    };

    let delta_secs = expiry.signed_duration_since(now).num_seconds();
    if delta_secs <= 0 {
        let overdue_days = delta_secs.saturating_neg() / 86_400;
        RelayExpiryStatus::Expired {
            days_overdue: overdue_days,
        }
    } else {
        let remaining_days = delta_secs.saturating_add(86_399) / 86_400;
        if remaining_days <= EXPIRY_SOON_THRESHOLD_DAYS {
            RelayExpiryStatus::ExpiringSoon {
                days_remaining: remaining_days,
            }
        } else {
            RelayExpiryStatus::Active {
                days_remaining: remaining_days,
            }
        }
    }
}

/// Return true if `server` parses as a bare IPv4 or IPv6 literal (with optional IPv6 brackets).
pub fn is_pure_ip_server(server: &str) -> bool {
    parse_server_ip(server).is_some()
}

/// Parse a server string as an `IpAddr`, stripping surrounding brackets for IPv6 literals.
pub fn parse_server_ip(server: &str) -> Option<IpAddr> {
    let cleaned = server
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']');
    cleaned.parse::<IpAddr>().ok()
}

/// Return a sanitized copy of a domestic `:443` relay with SNI cleared and `skip_cert_verify = true`.
pub fn sanitize_relay_for_domestic_443(relay: &PreAccelRelay) -> PreAccelRelay {
    let mut fixed = relay.clone();
    fixed.sni = None;
    if is_pure_ip_server(&fixed.server) {
        fixed.skip_cert_verify = true;
    }
    fixed
}

/// Run full protocol-aware validation for a domestic pre-acceleration relay using current UTC time.
pub fn validate_relay(relay: &PreAccelRelay) -> Vec<RelayValidationIssue> {
    validate_relay_at(relay, Utc::now())
}

/// Run full protocol-aware validation for a domestic pre-acceleration relay at an explicit timestamp.
pub fn validate_relay_at(relay: &PreAccelRelay, now: DateTime<Utc>) -> Vec<RelayValidationIssue> {
    let mut issues = Vec::new();

    if relay.id.trim().is_empty() {
        issues.push(RelayValidationIssue {
            code: RelayValidationCode::EmptyId,
            field: "id".to_string(),
            severity: RelayValidationSeverity::Warning,
            message: "relay id is empty; assign a stable unique id before persisting".to_string(),
        });
    }

    if relay.name.trim().is_empty() {
        issues.push(RelayValidationIssue {
            code: RelayValidationCode::EmptyName,
            field: "name".to_string(),
            severity: RelayValidationSeverity::Warning,
            message: "relay display name is empty".to_string(),
        });
    }

    let server_trimmed = relay.server.trim();
    let is_ip = parse_server_ip(server_trimmed).is_some();
    if server_trimmed.is_empty() {
        issues.push(RelayValidationIssue {
            code: RelayValidationCode::EmptyServer,
            field: "server".to_string(),
            severity: RelayValidationSeverity::Error,
            message: "relay server IP or host cannot be empty".to_string(),
        });
    } else if !is_ip && relay.port == 443 {
        issues.push(RelayValidationIssue {
            code: RelayValidationCode::NonPureIpServer,
            field: "server".to_string(),
            severity: RelayValidationSeverity::Warning,
            message: format!(
                "domestic :443 relay `{server_trimmed}` uses a domain instead of a pure IP; prefer bare IPv4 to avoid ICP domain filtering and extra DNS dependency"
            ),
        });
    }

    if relay.port == 0 {
        issues.push(RelayValidationIssue {
            code: RelayValidationCode::InvalidPort,
            field: "port".to_string(),
            severity: RelayValidationSeverity::Error,
            message: "relay port must be within 1..=65535".to_string(),
        });
    } else if relay.port != 443 {
        issues.push(RelayValidationIssue {
            code: RelayValidationCode::Non443PortWarning,
            field: "port".to_string(),
            severity: RelayValidationSeverity::Warning,
            message: format!(
                "relay port is {} instead of 443; non-443 ports may suffer QoS throttling on campus or ISP networks",
                relay.port
            ),
        });
    }

    let parsed_protocol = RelayProtocol::parse(&relay.protocol);
    if parsed_protocol.is_none() {
        issues.push(RelayValidationIssue {
            code: RelayValidationCode::UnsupportedProtocol,
            field: "protocol".to_string(),
            severity: RelayValidationSeverity::Error,
            message: format!(
                "unsupported domestic pre-acceleration protocol `{}`; supported: anytls, trojan, vless, hysteria2, tuic",
                relay.protocol
            ),
        });
    }

    let password_trimmed = relay.password.trim();
    if password_trimmed.is_empty() {
        issues.push(RelayValidationIssue {
            code: RelayValidationCode::EmptyPassword,
            field: "password".to_string(),
            severity: RelayValidationSeverity::Error,
            message: "relay authentication password/UUID cannot be empty".to_string(),
        });
    } else if parsed_protocol == Some(RelayProtocol::Vless)
        && Uuid::parse_str(password_trimmed).is_err()
    {
        issues.push(RelayValidationIssue {
            code: RelayValidationCode::InvalidVlessUuid,
            field: "password".to_string(),
            severity: RelayValidationSeverity::Error,
            message: "VLESS relay credential must be a valid UUID".to_string(),
        });
    }

    let sni_field = parsed_protocol
        .map(RelayProtocol::sni_field_name)
        .unwrap_or("sni");

    // Iron rule for domestic cloud (Tencent/Alibaba) pure-IP :443 relays:
    // never set a non-empty SNI / VLESS servername.
    if relay.has_non_empty_sni() {
        let sni_val = relay.sni.as_deref().unwrap_or_default().trim();
        let provider_hint = provider_label(&relay.provider);
        if relay.port == 443 {
            issues.push(RelayValidationIssue {
                code: RelayValidationCode::ForbiddenSniOnDomestic443,
                field: sni_field.to_string(),
                severity: RelayValidationSeverity::Error,
                message: format!(
                    "domestic :443 pre-acceleration relay ({provider_hint}) must NOT set non-empty `{sni_field}` (`{sni_val}`); unfiled third-party SNI triggers domestic cloud 443 ICP/SNI blocking. Leave `{sni_field}` empty and use pure IP with `skip_cert_verify: true`"
                ),
            });
        } else {
            issues.push(RelayValidationIssue {
                code: RelayValidationCode::SniPresentWarning,
                field: sni_field.to_string(),
                severity: RelayValidationSeverity::Warning,
                message: format!(
                    "relay sets non-empty `{sni_field}` (`{sni_val}`); leave it empty for pure-IP domestic relays to prevent SNI inspection interference"
                ),
            });
        }
    }

    // Pure-IP self-signed TLS relay must skip certificate verification.
    if is_ip && parsed_protocol.is_some() && !relay.skip_cert_verify {
        issues.push(RelayValidationIssue {
            code: RelayValidationCode::SkipCertVerifyDisabledOnPureIp,
            field: "skip_cert_verify".to_string(),
            severity: RelayValidationSeverity::Error,
            message: "pure-IP self-signed domestic relay requires `skip_cert_verify: true` for TLS handshake".to_string(),
        });
    }

    // Expiry countdown check (`<= 3` days -> expiring_soon, `<= 0` -> expired).
    match evaluate_expiry(relay.expires_at.as_deref(), now) {
        RelayExpiryStatus::NoExpiry | RelayExpiryStatus::Active { .. } => {}
        RelayExpiryStatus::ExpiringSoon { days_remaining } => {
            issues.push(RelayValidationIssue {
                code: RelayValidationCode::ExpiringSoon,
                field: "expires_at".to_string(),
                severity: RelayValidationSeverity::Warning,
                message: format!(
                    "expiring_soon: relay expires in {days_remaining} day(s); renew or rotate backup relay"
                ),
            });
        }
        RelayExpiryStatus::Expired { days_overdue } => {
            issues.push(RelayValidationIssue {
                code: RelayValidationCode::Expired,
                field: "expires_at".to_string(),
                severity: RelayValidationSeverity::Warning,
                message: if days_overdue == 0 {
                    "expired: relay expired today and should be replaced".to_string()
                } else {
                    format!(
                        "expired: relay expired {days_overdue} day(s) ago and should be replaced"
                    )
                },
            });
        }
        RelayExpiryStatus::InvalidFormat { raw } => {
            issues.push(RelayValidationIssue {
                code: RelayValidationCode::InvalidExpiresAt,
                field: "expires_at".to_string(),
                severity: RelayValidationSeverity::Error,
                message: format!(
                    "invalid expires_at timestamp `{raw}`; expected RFC3339 or YYYY-MM-DD"
                ),
            });
        }
    }

    issues
}

/// Strictly validate a relay and fail on any `Error`-severity issue (including domestic :443 SNI violations).
pub fn validate_relay_strict(relay: &PreAccelRelay) -> CatResult<()> {
    validate_relay_strict_at(relay, Utc::now())
}

/// Strictly validate a relay at an explicit UTC timestamp.
pub fn validate_relay_strict_at(relay: &PreAccelRelay, now: DateTime<Utc>) -> CatResult<()> {
    let errors: Vec<RelayValidationIssue> = validate_relay_at(relay, now)
        .into_iter()
        .filter(|issue| issue.severity == RelayValidationSeverity::Error)
        .collect();

    if errors.is_empty() {
        return Ok(());
    }

    let summary = errors
        .iter()
        .map(|e| format!("{}: {}", e.field, e.message))
        .collect::<Vec<_>>()
        .join("; ");
    Err(CatError::Validation(summary))
}

/// Safely validate, deduplicate by `(protocol, server, port)` fingerprint, protect existing
/// relay IDs from collision, strip local speed caches, and upsert relays into SQLite storage.
///
/// Returns `(imported_count, warnings)`.
pub fn import_relays_dedup_into_storage(
    db: &crate::storage::Storage,
    relays: Vec<crate::models::PreAccelRelay>,
) -> crate::error::CatResult<(usize, Vec<String>)> {
    let existing = db.list_preaccel_relays(false)?;
    let mut fp_to_id: HashMap<(String, String, u16), String> =
        HashMap::with_capacity(existing.len() + relays.len());
    let mut used_ids: HashSet<String> = HashSet::with_capacity(existing.len() + relays.len());

    for r in &existing {
        used_ids.insert(r.id.clone());
        let fp = relay_dedup_fingerprint(r);
        fp_to_id.entry(fp).or_insert_with(|| r.id.clone());
    }

    let mut imported_count = 0usize;
    let mut warnings = Vec::new();

    for mut relay in relays {
        relay.last_probe_ms = None;
        relay.last_mbps = None;
        relay.last_up_mbps = None;
        relay.last_down_mbps = None;

        if let Err(err) = validate_relay_strict(&relay) {
            let label = if relay.name.trim().is_empty() {
                relay.server.trim()
            } else {
                relay.name.trim()
            };
            warnings.push(format!("已跳过无效中转「{label}」：{err}"));
            continue;
        }

        let fp = relay_dedup_fingerprint(&relay);
        if let Some(existing_id) = fp_to_id.get(&fp).cloned() {
            relay.id = existing_id;
        } else {
            let candidate_id = relay.id.trim().to_string();
            if candidate_id.is_empty() || used_ids.contains(&candidate_id) {
                let mut generated = format!("relay-{}", Uuid::new_v4().simple());
                while used_ids.contains(&generated) {
                    generated = format!("relay-{}", Uuid::new_v4().simple());
                }
                relay.id = generated;
            } else {
                relay.id = candidate_id;
            }
            used_ids.insert(relay.id.clone());
            fp_to_id.insert(fp, relay.id.clone());
        }

        db.upsert_preaccel_relay(&relay)?;
        imported_count += 1;
    }

    Ok((imported_count, warnings))
}

fn relay_dedup_fingerprint(relay: &PreAccelRelay) -> (String, String, u16) {
    let protocol_lower = RelayProtocol::parse(&relay.protocol)
        .map(|p| p.mihomo_type().to_string())
        .unwrap_or_else(|| relay.protocol.trim().to_ascii_lowercase());
    let server_lower = relay.server.trim().to_ascii_lowercase();
    (protocol_lower, server_lower, relay.port)
}

fn strip_mmrelay_prefix(raw: &str) -> Option<&str> {
    let prefix_len = MMRELAY_URI_PREFIX.len();
    if raw.len() < prefix_len {
        return None;
    }
    let head = raw.get(..prefix_len)?;
    if head.eq_ignore_ascii_case(MMRELAY_URI_PREFIX) {
        Some(&raw[prefix_len..])
    } else {
        None
    }
}

fn provider_label(provider: &str) -> &'static str {
    match provider.trim().to_ascii_lowercase().as_str() {
        "tencent" | "tencent_cloud" | "qcloud" => "Tencent Cloud",
        "aliyun" | "alibaba" | "alicloud" => "Alibaba Cloud",
        "huawei" | "huaweicloud" => "Huawei Cloud",
        _ => "domestic cloud",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_relay(id: &str, enabled: bool, supports_ipv6: bool) -> PreAccelRelay {
        PreAccelRelay {
            id: id.to_string(),
            name: id.to_string(),
            provider: "cloud".to_string(),
            region: "CN".to_string(),
            server: "203.0.113.10".to_string(),
            port: 443,
            protocol: "anytls".to_string(),
            password: "demo-password".to_string(),
            sni: None,
            skip_cert_verify: true,
            priority: 10,
            expires_at: None,
            enabled,
            supports_ipv6,
            last_probe_ms: None,
            last_mbps: None,
            last_up_mbps: None,
            last_down_mbps: None,
        }
    }

    #[test]
    fn relays_support_ipv6_requires_every_enabled_relay_to_support_ipv6() {
        assert!(!relays_support_ipv6(&[]));
        assert!(!relays_support_ipv6(&[mk_relay("r-off", false, true)]));
        assert!(!relays_support_ipv6(&[mk_relay("r-v4", true, false)]));
        assert!(relays_support_ipv6(&[mk_relay("r-v6", true, true)]));

        // Mixed IPv4-only + dual-stack pool must return false to avoid 50% IPv6 blackholes.
        assert!(!relays_support_ipv6(&[
            mk_relay("r-v4", true, false),
            mk_relay("r-v6", true, true),
        ]));

        // Disabled IPv4-only relays must not block an all-IPv6 active pool.
        assert!(relays_support_ipv6(&[
            mk_relay("r-v6-a", true, true),
            mk_relay("r-v6-b", true, true),
            mk_relay("r-v4-disabled", false, false),
        ]));
    }
}
