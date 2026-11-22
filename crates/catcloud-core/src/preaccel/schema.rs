use crate::error::{CatError, CatResult};
use crate::models::group::{
    MMRELAY_ROLE_DOMESTIC_PRE_ACCEL, MMRELAY_SCHEMA_V1, MmRelayBundleV1, PreAccelRelay,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

/// Single-line clipboard URI prefix for `mmrelay/v1` relay bundles.
pub const MMRELAY_URI_PREFIX: &str = "mmrelay://v1/";

/// Days-remaining threshold below which a relay triggers an `expiring_soon` reminder.
pub const EXPIRY_SOON_THRESHOLD_DAYS: i64 = 3;

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
