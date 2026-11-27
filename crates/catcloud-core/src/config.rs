use crate::error::{CatError, CatResult};
use crate::models::{
    AppConfig, CONFIG_SCHEMA_VERSION, DEFAULT_PREACCEL_FALLBACK_PROBE_URL,
    DEFAULT_PREACCEL_PROBE_URL, OverrideMode, is_supported_ui_language,
};
use crate::paths::AppPaths;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use url::Url;

/// Severity level for configuration validation issues.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ValidationSeverity {
    Error,
    Warning,
}

/// Structured validation finding returned to GUI/CLI callers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigValidationIssue {
    pub field: String,
    pub severity: ValidationSeverity,
    pub message: String,
}

/// Integrity-checked backup bundle exported by `export_backup`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigBackupBundle {
    pub schema: String,
    pub exported_at: String,
    pub app_version: String,
    pub config_sha256: String,
    pub config: AppConfig,
}

const BACKUP_SCHEMA: &str = "catcloud-config-backup/v1";

/// Overseas probe domains strictly forbidden for domestic pre-acceleration health checks.
const FORBIDDEN_DOMESTIC_PROBE_SUFFIXES: &[&str] = &[
    "gstatic.com",
    "google.com",
    "googleapis.com",
    "googleusercontent.com",
    "youtube.com",
    "cloudflare.com",
];

/// Stateful convenience wrapper around `AppPaths` for configuration lifecycle operations.
#[derive(Debug, Clone)]
pub struct ConfigManager {
    paths: AppPaths,
}

impl ConfigManager {
    pub fn new(paths: AppPaths) -> Self {
        Self { paths }
    }

    pub fn paths(&self) -> &AppPaths {
        &self.paths
    }

    pub fn load_or_default(&self) -> CatResult<AppConfig> {
        load_or_default(&self.paths)
    }

    pub fn load_or_init(&self) -> CatResult<AppConfig> {
        load_or_init(&self.paths)
    }

    pub fn save(&self, cfg: &AppConfig) -> CatResult<()> {
        save(&self.paths, cfg)
    }

    pub fn export_backup(
        &self,
        cfg: &AppConfig,
        target_path: Option<&Path>,
    ) -> CatResult<PathBuf> {
        export_backup(&self.paths, cfg, target_path)
    }

    pub fn import_backup(&self, backup_path: &Path) -> CatResult<AppConfig> {
        import_backup(&self.paths, backup_path)
    }

    pub fn reset_to_default(&self) -> CatResult<AppConfig> {
        reset_to_default(&self.paths)
    }
}

/// Legacy v3 pure-IP DoH (TCP 443) domestic resolvers preserved for compatibility and
/// v3 -> v4 idempotent migration matching.
pub(crate) const DEFAULT_PURE_IP_DOH_NAMESERVERS: &[&str] =
    crate::models::DEFAULT_PURE_IP_DOH_NAMESERVERS;

/// Default v4 4-endpoint heterogeneous pure-IP encrypted domestic resolvers (DoH 443 + DoT 853).
pub(crate) const DEFAULT_PURE_IP_ENCRYPTED_NAMESERVERS: &[&str] =
    crate::models::DEFAULT_PURE_IP_ENCRYPTED_NAMESERVERS;

const LEGACY_PLAINTEXT_DOMESTIC_DNS: &[&str] = &[
    "223.5.5.5",
    "119.29.29.29",
    "223.6.6.6",
    "223.5.5.5:53",
    "119.29.29.29:53",
];

/// Return `true` only when `list` is non-empty and every trimmed entry belongs strictly to the
/// legacy plaintext domestic UDP 53 default set (never matching encrypted or user-custom entries).
pub(crate) fn is_legacy_plaintext_domestic_dns_list(list: &[String]) -> bool {
    !list.is_empty()
        && list.iter().all(|entry| {
            let trimmed = entry.trim();
            !trimmed.is_empty() && LEGACY_PLAINTEXT_DOMESTIC_DNS.contains(&trimmed)
        })
}

/// Return `true` only when `list` strictly equals the legacy v3 dual-DoH default pair
/// `["https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query"]`.
pub(crate) fn is_legacy_v3_doh_default_dns_list(list: &[String]) -> bool {
    list.len() == DEFAULT_PURE_IP_DOH_NAMESERVERS.len()
        && list
            .iter()
            .zip(DEFAULT_PURE_IP_DOH_NAMESERVERS.iter())
            .all(|(actual, expected)| actual.trim().eq_ignore_ascii_case(expected))
}

fn is_valid_domestic_probe_url(raw: &str) -> bool {
    let trimmed = raw.trim();
    match Url::parse(trimmed) {
        Ok(parsed) if matches!(parsed.scheme(), "http" | "https") => parsed
            .host_str()
            .filter(|h| !h.is_empty())
            .is_some_and(|host| !is_forbidden_domestic_probe_host(host)),
        _ => false,
    }
}

/// Apply idempotent in-memory schema migrations and self-healing normalization on a loaded or
/// imported configuration:
///
/// - `schema_version < 2`: upgrades legacy `core_runtime.gogc == 35` to `25` without touching
///   v2+ configs where the user manually chose `35`.
/// - `schema_version < 3`: gently upgrades legacy plaintext domestic UDP 53 DNS lists in
///   `default_nameserver`, `direct_nameserver`, `nameserver`, and `proxy_server_nameserver`
///   to v3 DoH defaults without overwriting user-customized DNS entries.
/// - `schema_version < 4`: gently upgrades exact v3 dual-DoH default lists in
///   `default_nameserver`, `direct_nameserver`, `nameserver`, and `proxy_server_nameserver`
///   to the 4-endpoint heterogeneous pure-IP encrypted pool (DoH 443 + DoT 853, TLS verified)
///   without ever overwriting user-customized DNS entries.
/// - All versions: heals invalid or forbidden overseas `preaccel.probe_url` /
///   `preaccel.fallback_probe_url` back to domestic 204 defaults, reconciles unified
///   `preaccel.enabled` / `preaccel.global_bypass_enabled` flags, and strips blank
///   `preaccel.active_relay_id`.
/// - Returns `true` whenever `schema_version` or any field was actually mutated.
pub fn migrate_config_in_memory(cfg: &mut AppConfig) -> bool {
    let mut migrated = false;
    if cfg.schema_version < 2 {
        if cfg.core_runtime.gogc == 35 {
            cfg.core_runtime.gogc = 25;
        }
    }
    if cfg.schema_version < 3 {
        let v3_doh = || {
            DEFAULT_PURE_IP_DOH_NAMESERVERS
                .iter()
                .map(|s| (*s).to_string())
                .collect::<Vec<String>>()
        };
        if is_legacy_plaintext_domestic_dns_list(&cfg.dns.default_nameserver) {
            cfg.dns.default_nameserver = v3_doh();
        }
        if is_legacy_plaintext_domestic_dns_list(&cfg.dns.direct_nameserver) {
            cfg.dns.direct_nameserver = v3_doh();
        }
        if is_legacy_plaintext_domestic_dns_list(&cfg.dns.nameserver) {
            cfg.dns.nameserver = v3_doh();
        }
        if is_legacy_plaintext_domestic_dns_list(&cfg.dns.proxy_server_nameserver) {
            cfg.dns.proxy_server_nameserver = v3_doh();
        }
    }
    if cfg.schema_version < 4 {
        let v4_encrypted = || {
            DEFAULT_PURE_IP_ENCRYPTED_NAMESERVERS
                .iter()
                .map(|s| (*s).to_string())
                .collect::<Vec<String>>()
        };
        if is_legacy_v3_doh_default_dns_list(&cfg.dns.default_nameserver) {
            cfg.dns.default_nameserver = v4_encrypted();
        }
        if is_legacy_v3_doh_default_dns_list(&cfg.dns.direct_nameserver) {
            cfg.dns.direct_nameserver = v4_encrypted();
        }
        if is_legacy_v3_doh_default_dns_list(&cfg.dns.nameserver) {
            cfg.dns.nameserver = v4_encrypted();
        }
        if is_legacy_v3_doh_default_dns_list(&cfg.dns.proxy_server_nameserver) {
            cfg.dns.proxy_server_nameserver = v4_encrypted();
        }
    }

    if !is_valid_domestic_probe_url(&cfg.preaccel.probe_url) {
        cfg.preaccel.probe_url = DEFAULT_PREACCEL_PROBE_URL.to_string();
        migrated = true;
    }
    if !is_valid_domestic_probe_url(&cfg.preaccel.fallback_probe_url) {
        cfg.preaccel.fallback_probe_url = DEFAULT_PREACCEL_FALLBACK_PROBE_URL.to_string();
        migrated = true;
    }

    let before_enabled = cfg.preaccel.enabled;
    let before_global = cfg.preaccel.global_bypass_enabled;
    cfg.preaccel.reconcile_unified_enabled();
    if cfg.preaccel.enabled != before_enabled
        || cfg.preaccel.global_bypass_enabled != before_global
    {
        migrated = true;
    }

    if let Some(ref raw_id) = cfg.preaccel.active_relay_id {
        let trimmed = raw_id.trim();
        if trimmed.is_empty() {
            cfg.preaccel.active_relay_id = None;
            migrated = true;
        } else if trimmed != raw_id {
            cfg.preaccel.active_relay_id = Some(trimmed.to_string());
            migrated = true;
        }
    }

    if cfg.schema_version < CONFIG_SCHEMA_VERSION {
        cfg.schema_version = CONFIG_SCHEMA_VERSION;
        migrated = true;
    }
    migrated
}

/// Clear a dangling `cfg.preaccel.active_relay_id` when it is blank or no longer exists in
/// `enabled_relay_ids`. Returns `true` if `cfg.preaccel.active_relay_id` was modified.
pub fn reconcile_dangling_active_relay(
    cfg: &mut AppConfig,
    enabled_relay_ids: &HashSet<String>,
) -> bool {
    let Some(ref raw_id) = cfg.preaccel.active_relay_id else {
        return false;
    };
    let trimmed = raw_id.trim();
    if trimmed.is_empty() || !enabled_relay_ids.contains(trimmed) {
        cfg.preaccel.active_relay_id = None;
        return true;
    }
    if trimmed != raw_id {
        cfg.preaccel.active_relay_id = Some(trimmed.to_string());
        return true;
    }
    false
}

fn load_from_disk_with_migration(paths: &AppPaths) -> CatResult<(AppConfig, bool)> {
    let raw = std::fs::read_to_string(&paths.config_path)?;
    let mut cfg: AppConfig = serde_json::from_str(&raw)?;
    let migrated = migrate_config_in_memory(&mut cfg);
    validate_config(&cfg)?;
    Ok((cfg, migrated))
}

/// Load `data/config.json`, apply idempotent in-memory schema migrations without touching disk,
/// and validate it, or return `AppConfig::default()` when absent.
pub fn load_or_default(paths: &AppPaths) -> CatResult<AppConfig> {
    if paths.config_path.is_file() {
        let (cfg, _) = load_from_disk_with_migration(paths)?;
        Ok(cfg)
    } else {
        Ok(AppConfig::default())
    }
}

/// Load `data/config.json` (atomically persisting any in-memory schema migration),
/// or initialize and atomically persist defaults on first launch.
pub fn load_or_init(paths: &AppPaths) -> CatResult<AppConfig> {
    if paths.config_path.is_file() {
        let (cfg, migrated) = load_from_disk_with_migration(paths)?;
        if migrated {
            save(paths, &cfg)?;
        }
        Ok(cfg)
    } else {
        let cfg = AppConfig::default();
        save(paths, &cfg)?;
        Ok(cfg)
    }
}

/// Validate `cfg` and persist it atomically to `paths.config_path` via `AppPaths::atomic_write`,
/// unconditionally ensuring persisted configs carry `schema_version == CONFIG_SCHEMA_VERSION`.
pub fn save(paths: &AppPaths, cfg: &AppConfig) -> CatResult<()> {
    validate_config(cfg)?;
    let mut to_save = cfg.clone();
    to_save.schema_version = CONFIG_SCHEMA_VERSION;
    let bytes = serde_json::to_vec_pretty(&to_save)?;
    AppPaths::atomic_write(&paths.config_path, &bytes)
}

/// Export a validated configuration snapshot with SHA-256 integrity envelope.
pub fn export_backup(
    paths: &AppPaths,
    cfg: &AppConfig,
    target_path: Option<&Path>,
) -> CatResult<PathBuf> {
    validate_config(cfg)?;
    let canonical_json = serde_json::to_vec(cfg)?;
    let config_sha256 = sha256_hex(&canonical_json);

    let bundle = ConfigBackupBundle {
        schema: BACKUP_SCHEMA.to_string(),
        exported_at: Utc::now().to_rfc3339(),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        config_sha256,
        config: cfg.clone(),
    };

    let dest = match target_path {
        Some(p) => p.to_path_buf(),
        None => {
            std::fs::create_dir_all(&paths.backup_dir)?;
            let stamp = Utc::now().format("%Y%m%d-%H%M%S-%3f");
            paths
                .backup_dir
                .join(format!("config-backup-{stamp}.json"))
        }
    };

    let bytes = serde_json::to_vec_pretty(&bundle)?;
    AppPaths::atomic_write(&dest, &bytes)?;
    Ok(dest)
}

/// Import a configuration backup (either `ConfigBackupBundle` or raw `AppConfig` JSON),
/// verify integrity and field validity, snapshot the previous config if present, and save atomically.
pub fn import_backup(paths: &AppPaths, backup_path: &Path) -> CatResult<AppConfig> {
    if !backup_path.is_file() {
        return Err(CatError::NotFound(format!(
            "backup file not found: {}",
            backup_path.display()
        )));
    }
    let raw = std::fs::read_to_string(backup_path)?;
    let value: serde_json::Value = serde_json::from_str(&raw)?;

    let mut imported: AppConfig =
        if value.get("schema").and_then(|v| v.as_str()) == Some(BACKUP_SCHEMA) {
            let raw_config_compact_sha = extract_raw_json_object_field_compact(&raw, "config")
                .map(|bytes| sha256_hex(&bytes));
            let raw_config_value_sha = value
                .get("config")
                .and_then(|v| serde_json::to_vec(v).ok())
                .map(|bytes| sha256_hex(&bytes));
            let bundle: ConfigBackupBundle = serde_json::from_value(value)?;
            let reserialized_sha = sha256_hex(&serde_json::to_vec(&bundle.config)?);

            let digest_matches = raw_config_compact_sha
                .as_deref()
                .is_some_and(|h| h.eq_ignore_ascii_case(&bundle.config_sha256))
                || raw_config_value_sha
                    .as_deref()
                    .is_some_and(|h| h.eq_ignore_ascii_case(&bundle.config_sha256))
                || reserialized_sha.eq_ignore_ascii_case(&bundle.config_sha256);

            if !digest_matches {
                return Err(CatError::Validation(
                    "backup integrity check failed: SHA-256 digest mismatch".to_string(),
                ));
            }
            bundle.config
        } else {
            serde_json::from_value(value)?
        };

    migrate_config_in_memory(&mut imported);
    validate_config(&imported)?;

    if paths.config_path.is_file() {
        if let Ok(prev) = load_or_default(paths) {
            let _ = export_backup(paths, &prev, None);
        }
    }

    save(paths, &imported)?;
    Ok(imported)
}

/// Backup existing config (if valid and present) and reset `data/config.json` to defaults.
pub fn reset_to_default(paths: &AppPaths) -> CatResult<AppConfig> {
    if paths.config_path.is_file() {
        if let Ok(prev) = load_or_default(paths) {
            let _ = export_backup(paths, &prev, None);
        }
    }
    let cfg = AppConfig::default();
    save(paths, &cfg)?;
    Ok(cfg)
}

/// Check whether a hostname belongs to overseas endpoints disallowed for domestic pre-accel probes.
pub fn is_forbidden_domestic_probe_host(host: &str) -> bool {
    let normalized = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }
    FORBIDDEN_DOMESTIC_PROBE_SUFFIXES.iter().any(|suffix| {
        normalized == *suffix || normalized.ends_with(&format!(".{suffix}"))
    })
}

/// Run full validation and return the first error (or summary of all errors) if invalid.
pub fn validate_config(cfg: &AppConfig) -> CatResult<()> {
    let errors: Vec<ConfigValidationIssue> = validate_config_detailed(cfg)
        .into_iter()
        .filter(|issue| issue.severity == ValidationSeverity::Error)
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

/// Collect all validation errors and warnings without aborting on the first issue.
pub fn validate_config_detailed(cfg: &AppConfig) -> Vec<ConfigValidationIssue> {
    let mut issues = Vec::new();

    // 1. Core ports & uniqueness
    if cfg.mixed_port == 0 {
        push_err(&mut issues, "mixed_port", "port must be in 1..=65535");
    }
    if cfg.controller_port == 0 {
        push_err(&mut issues, "controller_port", "port must be in 1..=65535");
    }
    if cfg.dns_listen_port == 0 {
        push_err(&mut issues, "dns_listen_port", "port must be in 1..=65535");
    }
    if cfg.system_proxy.pac.enabled && cfg.system_proxy.pac.port == 0 {
        push_err(
            &mut issues,
            "system_proxy.pac.port",
            "PAC port must be in 1..=65535 when PAC mode is enabled",
        );
    }

    let mut used_ports: HashMap<u16, &'static str> = HashMap::new();
    let port_entries: [(&'static str, Option<u16>); 8] = [
        ("mixed_port", Some(cfg.mixed_port)),
        ("controller_port", Some(cfg.controller_port)),
        ("dns_listen_port", Some(cfg.dns_listen_port)),
        ("socks_port", cfg.socks_port),
        ("http_port", cfg.http_port),
        ("redir_port", cfg.redir_port),
        ("tproxy_port", cfg.tproxy_port),
        (
            "system_proxy.pac.port",
            cfg.system_proxy.pac.enabled.then_some(cfg.system_proxy.pac.port),
        ),
    ];
    for (field, maybe_port) in port_entries {
        if let Some(port) = maybe_port {
            if port == 0 {
                if !matches!(
                    field,
                    "mixed_port" | "controller_port" | "dns_listen_port" | "system_proxy.pac.port"
                ) {
                    push_err(&mut issues, field, "optional port cannot be 0");
                }
                continue;
            }
            if let Some(prev) = used_ports.insert(port, field) {
                push_err(
                    &mut issues,
                    field,
                    &format!("port {port} collides with {prev}"),
                );
            }
        }
    }

    if cfg.bind_address.trim().is_empty() {
        push_err(&mut issues, "bind_address", "bind_address cannot be empty");
    }
    if cfg.controller_host.trim().is_empty() {
        push_err(
            &mut issues,
            "controller_host",
            "controller_host cannot be empty",
        );
    }
    if cfg.dns_listen_host.trim().is_empty() {
        push_err(
            &mut issues,
            "dns_listen_host",
            "dns_listen_host cannot be empty",
        );
    }

    // 2. Proxy Guard
    if cfg.system_proxy.proxy_guard.enabled
        && !(2..=3600).contains(&cfg.system_proxy.proxy_guard.interval_sec)
    {
        push_err(
            &mut issues,
            "system_proxy.proxy_guard.interval_sec",
            "Proxy Guard interval must be within 2..=3600 seconds",
        );
    }

    // 3. TUN
    if cfg.tun.mtu < 576 {
        push_err(&mut issues, "tun.mtu", "TUN MTU must be at least 576");
    }
    if cfg.tun.device_name.trim().is_empty() {
        push_err(&mut issues, "tun.device_name", "TUN device name cannot be empty");
    }

    // 4. Advanced DNS
    if !is_valid_ipv4_cidr(&cfg.dns.fake_ip_range, 8, 30) {
        push_err(
            &mut issues,
            "dns.fake_ip_range",
            "fake_ip_range must be a valid IPv4 CIDR with prefix /8..=/30 (e.g. 198.18.0.1/16)",
        );
    }
    if cfg.dns.enable && cfg.dns.override_dns && cfg.dns.nameserver.is_empty() {
        push_err(
            &mut issues,
            "dns.nameserver",
            "at least one nameserver is required when DNS override is enabled",
        );
    }

    // 5. Rules & override pipeline
    if !(500..=60_000).contains(&cfg.rules_override.override_script_timeout_ms) {
        push_err(
            &mut issues,
            "rules_override.override_script_timeout_ms",
            "override script timeout must be within 500..=60000 ms",
        );
    }
    match cfg.rules_override.override_mode {
        OverrideMode::MergePatch => {
            if is_blank_opt(&cfg.rules_override.override_merge_path) {
                push_err(
                    &mut issues,
                    "rules_override.override_merge_path",
                    "merge patch path is required when override_mode is merge_patch",
                );
            }
        }
        OverrideMode::Script => {
            if is_blank_opt(&cfg.rules_override.override_script_path) {
                push_err(
                    &mut issues,
                    "rules_override.override_script_path",
                    "script path is required when override_mode is script",
                );
            }
        }
        OverrideMode::Both => {
            if is_blank_opt(&cfg.rules_override.override_merge_path) {
                push_err(
                    &mut issues,
                    "rules_override.override_merge_path",
                    "merge patch path is required when override_mode is both",
                );
            }
            if is_blank_opt(&cfg.rules_override.override_script_path) {
                push_err(
                    &mut issues,
                    "rules_override.override_script_path",
                    "script path is required when override_mode is both",
                );
            }
        }
        OverrideMode::Disabled => {}
    }
    if let Err(err) = cfg.rules_override.validate_inline_override_yaml() {
        push_err(&mut issues, "rules_override.inline_override_yaml", &err);
    }

    // 6. Geodata & Core Runtime
    if cfg.geodata.auto_update && cfg.geodata.update_interval_hours == 0 {
        push_err(
            &mut issues,
            "geodata.update_interval_hours",
            "auto update interval must be >= 1 hour",
        );
    }
    for (field, raw_url) in [
        ("geodata.geoip_url", cfg.geodata.geoip_url.as_str()),
        ("geodata.geosite_url", cfg.geodata.geosite_url.as_str()),
        ("geodata.mmdb_url", cfg.geodata.mmdb_url.as_str()),
        ("geodata.asn_url", cfg.geodata.asn_url.as_str()),
    ] {
        validate_http_url(&mut issues, field, raw_url);
    }
    if !(10..=500).contains(&cfg.core_runtime.gogc) {
        push_err(
            &mut issues,
            "core_runtime.gogc",
            "GOGC must be within 10..=500",
        );
    }

    // 7. Domestic Pre-Acceleration probe guard (hard reject overseas gstatic/google/cloudflare)
    validate_domestic_probe_url(&mut issues, "preaccel.probe_url", &cfg.preaccel.probe_url);
    validate_domestic_probe_url(
        &mut issues,
        "preaccel.fallback_probe_url",
        &cfg.preaccel.fallback_probe_url,
    );
    if !(5..=3600).contains(&cfg.preaccel.probe_interval_sec) {
        push_err(
            &mut issues,
            "preaccel.probe_interval_sec",
            "domestic pre-accel probe interval must be within 5..=3600 seconds",
        );
    }

    // 8. Personalization & diurnal schedule
    let light_m = parse_hhmm(&cfg.personalization.day_schedule.light_start);
    let warm_m = parse_hhmm(&cfg.personalization.day_schedule.warm_dark_start);
    let night_m = parse_hhmm(&cfg.personalization.day_schedule.midnight_blue_start);

    if light_m.is_none() {
        push_err(
            &mut issues,
            "personalization.day_schedule.light_start",
            "expected HH:MM (00:00..23:59)",
        );
    }
    if warm_m.is_none() {
        push_err(
            &mut issues,
            "personalization.day_schedule.warm_dark_start",
            "expected HH:MM (00:00..23:59)",
        );
    }
    if night_m.is_none() {
        push_err(
            &mut issues,
            "personalization.day_schedule.midnight_blue_start",
            "expected HH:MM (00:00..23:59)",
        );
    }
    if let (Some(a), Some(b), Some(c)) = (light_m, warm_m, night_m) {
        if a == b || b == c || a == c {
            push_err(
                &mut issues,
                "personalization.day_schedule",
                "diurnal theme switch timestamps must be distinct",
            );
        }
    }

    let opacity = cfg.personalization.wallpaper_opacity;
    if !opacity.is_finite() || !(0.0..=1.0).contains(&opacity) {
        push_err(
            &mut issues,
            "personalization.wallpaper_opacity",
            "wallpaper opacity must be finite and within 0.0..=1.0",
        );
    }
    if cfg.personalization.wallpaper_blur > 64 {
        push_err(
            &mut issues,
            "personalization.wallpaper_blur",
            "wallpaper blur radius must be <= 64 px",
        );
    }
    let lang = cfg.personalization.language.trim();
    if lang.is_empty() || !is_supported_ui_language(lang) {
        push_err(
            &mut issues,
            "personalization.language",
            "unsupported UI language (expected one of: zh-CN, en, ja, ru)",
        );
    }

    // 9. Updater config
    if !is_valid_github_repo(&cfg.update.repo) {
        push_err(
            &mut issues,
            "update.repo",
            "update.repo must follow `owner/repo` format",
        );
    }
    if cfg.update.check_interval_min < 15 {
        push_err(
            &mut issues,
            "update.check_interval_min",
            "update check interval must be >= 15 minutes",
        );
    }

    issues
}

fn validate_domestic_probe_url(
    issues: &mut Vec<ConfigValidationIssue>,
    field: &str,
    raw: &str,
) {
    let trimmed = raw.trim();
    match Url::parse(trimmed) {
        Ok(parsed) => {
            if !matches!(parsed.scheme(), "http" | "https") {
                push_err(issues, field, "probe URL must use http:// or https://");
                return;
            }
            match parsed.host_str() {
                Some(host) if !host.is_empty() => {
                    if is_forbidden_domestic_probe_host(host) {
                        push_err(
                            issues,
                            field,
                            &format!(
                                "overseas host `{host}` is forbidden for domestic pre-acceleration probes; use a domestic 204 endpoint such as connectivitycheck.platform.hicloud.com or connect.rom.miui.com"
                            ),
                        );
                    }
                }
                _ => push_err(issues, field, "probe URL must contain a valid host"),
            }
        }
        Err(e) => push_err(issues, field, &format!("invalid probe URL: {e}")),
    }
}

fn validate_http_url(issues: &mut Vec<ConfigValidationIssue>, field: &str, raw: &str) {
    match Url::parse(raw.trim()) {
        Ok(parsed) if matches!(parsed.scheme(), "http" | "https") && parsed.host_str().is_some() => {
        }
        Ok(_) => push_err(issues, field, "URL must be a valid http(s) URL with host"),
        Err(e) => push_err(issues, field, &format!("invalid URL: {e}")),
    }
}

fn is_valid_ipv4_cidr(cidr: &str, min_prefix: u8, max_prefix: u8) -> bool {
    let Some((ip_part, prefix_part)) = cidr.trim().split_once('/') else {
        return false;
    };
    let Ok(_ip) = ip_part.parse::<Ipv4Addr>() else {
        return false;
    };
    let Ok(prefix) = prefix_part.parse::<u8>() else {
        return false;
    };
    (min_prefix..=max_prefix).contains(&prefix)
}

fn parse_hhmm(value: &str) -> Option<u16> {
    let trimmed = value.trim();
    let (h, m) = trimmed.split_once(':')?;
    if h.len() != 2 || m.len() != 2 {
        return None;
    }
    let hour: u16 = h.parse().ok()?;
    let minute: u16 = m.parse().ok()?;
    if hour > 23 || minute > 59 {
        return None;
    }
    Some(hour * 60 + minute)
}

fn is_valid_github_repo(repo: &str) -> bool {
    let parts: Vec<&str> = repo.trim().split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    parts.iter().all(|seg| {
        !seg.is_empty()
            && *seg != "."
            && *seg != ".."
            && seg
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    })
}

fn is_blank_opt(opt: &Option<String>) -> bool {
    opt.as_deref().is_none_or(|s| s.trim().is_empty())
}

fn push_err(issues: &mut Vec<ConfigValidationIssue>, field: &str, message: &str) {
    issues.push(ConfigValidationIssue {
        field: field.to_string(),
        severity: ValidationSeverity::Error,
        message: message.to_string(),
    });
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Extract the exact raw JSON object value for top-level key `field_name` and compact all
/// structural whitespace outside string literals while preserving original field order.
///
/// This lets `import_backup` verify historical `ConfigBackupBundle` SHA-256 digests generated by
/// older CatCloud releases even after newer releases add fields to `AppConfig`.
fn extract_raw_json_object_field_compact(raw: &str, field_name: &str) -> Option<Vec<u8>> {
    let bytes = raw.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;

    let skip_ws = |idx: &mut usize| {
        while *idx < len && matches!(bytes[*idx], b' ' | b'\t' | b'\r' | b'\n') {
            *idx += 1;
        }
    };

    skip_ws(&mut i);
    if i >= len || bytes[i] != b'{' {
        return None;
    }
    i += 1;

    let mut depth: usize = 1;
    while i < len && depth == 1 {
        skip_ws(&mut i);
        if i >= len || bytes[i] == b'}' {
            return None;
        }
        if bytes[i] != b'"' {
            return None;
        }
        let key_start = i;
        i += 1;
        let mut escaped = false;
        while i < len {
            let b = bytes[i];
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                i += 1;
                break;
            }
            i += 1;
        }
        let key_str: String = serde_json::from_str(&raw[key_start..i]).ok()?;
        skip_ws(&mut i);
        if i >= len || bytes[i] != b':' {
            return None;
        }
        i += 1;
        skip_ws(&mut i);
        if i >= len {
            return None;
        }

        let val_start = i;
        // Advance past this JSON value (object, array, string, or primitive).
        match bytes[i] {
            b'{' | b'[' => {
                let mut inner_depth = 0usize;
                let mut in_str = false;
                let mut esc = false;
                while i < len {
                    let b = bytes[i];
                    if in_str {
                        if esc {
                            esc = false;
                        } else if b == b'\\' {
                            esc = true;
                        } else if b == b'"' {
                            in_str = false;
                        }
                    } else {
                        match b {
                            b'"' => in_str = true,
                            b'{' | b'[' => inner_depth += 1,
                            b'}' | b']' => {
                                inner_depth = inner_depth.saturating_sub(1);
                                if inner_depth == 0 {
                                    i += 1;
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    i += 1;
                }
            }
            b'"' => {
                i += 1;
                let mut esc = false;
                while i < len {
                    let b = bytes[i];
                    if esc {
                        esc = false;
                    } else if b == b'\\' {
                        esc = true;
                    } else if b == b'"' {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
            }
            _ => {
                while i < len && !matches!(bytes[i], b',' | b'}' | b' ' | b'\t' | b'\r' | b'\n') {
                    i += 1;
                }
            }
        }
        let val_end = i;

        if key_str == field_name {
            let slice = &bytes[val_start..val_end];
            let mut compact = Vec::with_capacity(slice.len());
            let mut in_str = false;
            let mut esc = false;
            for &b in slice {
                if in_str {
                    compact.push(b);
                    if esc {
                        esc = false;
                    } else if b == b'\\' {
                        esc = true;
                    } else if b == b'"' {
                        in_str = false;
                    }
                } else if b == b'"' {
                    in_str = true;
                    compact.push(b);
                } else if !matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
                    compact.push(b);
                }
            }
            return Some(compact);
        }

        skip_ws(&mut i);
        if i < len && bytes[i] == b',' {
            i += 1;
        } else if i < len && bytes[i] == b'}' {
            depth = 0;
        } else {
            return None;
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        DnsMode, MemoryLimitTier, ThemeMode, TrayIconMode, TunStackMode, UpdateApplyMode,
    };
    use uuid::Uuid;

    fn temp_paths(tag: &str) -> AppPaths {
        let dir = std::env::temp_dir().join(format!("catcloud-cfg-test-{tag}-{}", Uuid::new_v4()));
        AppPaths::from_data_dir(dir, true).expect("create temp AppPaths")
    }

    fn cleanup_dir(paths: &AppPaths) {
        let _ = std::fs::remove_dir_all(&paths.root_data_dir);
    }

    #[test]
    fn default_config_is_valid_and_covers_expected_defaults() {
        let cfg = AppConfig::default();
        assert!(validate_config(&cfg).is_ok());
        assert_eq!(cfg.mixed_port, 7890);
        assert_eq!(cfg.controller_port, 9090);
        assert_eq!(cfg.dns_listen_port, 1053);
        assert_eq!(cfg.tun.stack_mode, TunStackMode::Mixed);
        assert_eq!(cfg.dns.mode, DnsMode::FakeIp);
        assert!(!cfg.core_ipv6);
        assert!(!cfg.dns.ipv6);
        assert!(!cfg.geodata.geodata_mode);
        assert_eq!(cfg.core_runtime.memory_tier, MemoryLimitTier::Auto);
        assert_eq!(cfg.core_runtime.gogc, 25);
        assert!(!cfg.core_runtime.compile_all_nodes);
        assert_eq!(cfg.resolve_gomemlimit(50, 200), "40MiB");
        assert_eq!(cfg.resolve_gomemlimit(250, 200), "56MiB");
        assert_eq!(cfg.resolve_gomemlimit(700, 200), "88MiB");
        assert_eq!(MemoryLimitTier::Mb48.resolve_env_value(10, 10), "48MiB");
        assert_eq!(MemoryLimitTier::Mb64.resolve_env_value(10, 10), "64MiB");
        assert_eq!(MemoryLimitTier::Mb96.resolve_env_value(10, 10), "96MiB");
        assert_eq!(cfg.personalization.theme_mode, ThemeMode::AutoTime);
        assert_eq!(cfg.personalization.day_schedule.light_start, "07:00");
        assert_eq!(cfg.personalization.day_schedule.warm_dark_start, "18:30");
        assert_eq!(cfg.personalization.day_schedule.midnight_blue_start, "22:30");
        assert_eq!(cfg.personalization.tray_icon_mode, TrayIconMode::AutoAc);
        assert_eq!(cfg.update.repo, "JuryBu/CatCloud");
        assert_eq!(cfg.update.mode, UpdateApplyMode::NextLaunch);
        assert!(cfg.preaccel.skip_443_native);
        assert!(cfg.preaccel.probe_url.contains("hicloud.com"));
    }

    #[test]
    fn atomic_save_load_and_no_leftover_tmp_files() {
        let paths = temp_paths("atomic");
        let mgr = ConfigManager::new(paths.clone());

        let mut cfg = mgr.load_or_init().expect("init default config");
        assert!(paths.config_path.is_file());

        cfg.mixed_port = 27890;
        cfg.controller_port = 29090;
        cfg.dns_listen_port = 21053;
        cfg.core_ipv6 = true;
        cfg.dns.ipv6 = false;
        cfg.tun.stack_mode = TunStackMode::Gvisor;
        cfg.dns.mode = DnsMode::RedirHost;
        cfg.core_runtime.memory_tier = MemoryLimitTier::Mb64;
        cfg.personalization.tray_icon_mode = TrayIconMode::AlwaysPixel;

        mgr.save(&cfg).expect("atomic save");
        let reloaded = mgr.load_or_default().expect("reload config");
        assert_eq!(reloaded, cfg);

        // Verify no leftover `.tmp.<pid>` file exists alongside config.json
        let tmp_count = std::fs::read_dir(&paths.root_data_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .count();
        assert_eq!(tmp_count, 0);

        cleanup_dir(&paths);
    }

    #[test]
    fn rejects_overseas_gstatic_and_google_for_domestic_preaccel_probe() {
        let mut cfg = AppConfig::default();
        cfg.preaccel.probe_url = "https://www.gstatic.com/generate_204".to_string();
        let err = validate_config(&cfg).expect_err("gstatic probe must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("preaccel.probe_url"));
        assert!(msg.contains("gstatic.com"));

        let mut cfg2 = AppConfig::default();
        cfg2.preaccel.fallback_probe_url = "http://clients3.google.com/generate_204".to_string();
        let err2 = validate_config(&cfg2).expect_err("google fallback probe must be rejected");
        assert!(err2.to_string().contains("preaccel.fallback_probe_url"));

        let mut cfg3 = AppConfig::default();
        cfg3.preaccel.probe_url = "https://cp.cloudflare.com/generate_204".to_string();
        assert!(validate_config(&cfg3).is_err());

        let mut ok_cfg = AppConfig::default();
        ok_cfg.preaccel.probe_url =
            "https://connectivitycheck.platform.hicloud.com/generate_204".to_string();
        ok_cfg.preaccel.fallback_probe_url =
            "http://connect.rom.miui.com/generate_204".to_string();
        assert!(validate_config(&ok_cfg).is_ok());
    }

    #[test]
    fn rejects_port_collisions_bad_cidr_and_bad_schedule() {
        let mut cfg = AppConfig::default();
        cfg.controller_port = cfg.mixed_port;
        cfg.dns.fake_ip_range = "not-a-cidr".to_string();
        cfg.personalization.day_schedule.light_start = "25:99".to_string();
        cfg.personalization.wallpaper_opacity = 1.5;
        cfg.update.repo = "bad/repo/extra".to_string();

        let issues = validate_config_detailed(&cfg);
        let fields: Vec<&str> = issues.iter().map(|i| i.field.as_str()).collect();
        assert!(fields.contains(&"controller_port"));
        assert!(fields.contains(&"dns.fake_ip_range"));
        assert!(fields.contains(&"personalization.day_schedule.light_start"));
        assert!(fields.contains(&"personalization.wallpaper_opacity"));
        assert!(fields.contains(&"update.repo"));
    }

    #[test]
    fn backup_export_import_and_tamper_rejection() {
        let paths = temp_paths("backup");
        let mgr = ConfigManager::new(paths.clone());

        let mut original = AppConfig::default();
        original.mixed_port = 17890;
        original.personalization.theme_mode = ThemeMode::MidnightBlue;
        mgr.save(&original).expect("save original");

        let backup_file = mgr.export_backup(&original, None).expect("export backup");
        assert!(backup_file.is_file());

        // Overwrite active config with a different valid state
        let mut modified = original.clone();
        modified.mixed_port = 18890;
        mgr.save(&modified).expect("save modified");

        // Restore from backup
        let restored = mgr.import_backup(&backup_file).expect("import backup");
        assert_eq!(restored.mixed_port, 17890);
        assert_eq!(restored.personalization.theme_mode, ThemeMode::MidnightBlue);

        // Tamper backup JSON without updating sha256 -> must fail and preserve current config
        let raw = std::fs::read_to_string(&backup_file).unwrap();
        let tampered = raw.replace("17890", "19999");
        let tampered_path = paths.backup_dir.join("tampered.json");
        std::fs::write(&tampered_path, tampered).unwrap();

        let err = mgr
            .import_backup(&tampered_path)
            .expect_err("tampered backup must be rejected");
        assert!(err.to_string().contains("SHA-256"));
        assert_eq!(mgr.load_or_default().unwrap().mixed_port, 17890);

        cleanup_dir(&paths);
    }

    #[test]
    fn save_does_not_corrupt_existing_config_when_validation_fails() {
        let paths = temp_paths("preserve-on-invalid");
        let mut good = AppConfig::default();
        good.mixed_port = 17900;
        save(&paths, &good).expect("save good config");

        let mut bad = good.clone();
        bad.preaccel.probe_url = "http://connectivitycheck.gstatic.com/generate_204".to_string();
        assert!(save(&paths, &bad).is_err());

        let still_good = load_or_default(&paths).expect("existing good config remains intact");
        assert_eq!(still_good.mixed_port, 17900);
        assert!(still_good.preaccel.probe_url.contains("hicloud.com"));

        cleanup_dir(&paths);
    }

    #[test]
    fn legacy_schema_v1_gogc_35_migrates_idempotently_and_preserves_custom_values() {
        let paths = temp_paths("gogc-migration");
        let mgr = ConfigManager::new(paths.clone());

        // 1. Legacy v1 config (missing schema_version) with gogc == 35:
        //    `load_or_default` migrates in memory ONLY without mutating disk.
        let legacy_v1_raw = r#"{"core_runtime":{"gogc":35},"mixed_port":17890}"#;
        std::fs::write(&paths.config_path, legacy_v1_raw).unwrap();

        let loaded_ro = mgr.load_or_default().expect("load_or_default legacy v1");
        assert_eq!(loaded_ro.schema_version, CONFIG_SCHEMA_VERSION);
        assert_eq!(loaded_ro.core_runtime.gogc, 25);
        assert_eq!(loaded_ro.mixed_port, 17890);
        assert_eq!(
            std::fs::read_to_string(&paths.config_path).unwrap(),
            legacy_v1_raw,
            "load_or_default must remain strictly read-only"
        );

        // `load_or_init` atomically persists the migrated v3 config to disk.
        let loaded_init = mgr.load_or_init().expect("load_or_init legacy v1");
        assert_eq!(loaded_init.schema_version, CONFIG_SCHEMA_VERSION);
        assert_eq!(loaded_init.core_runtime.gogc, 25);
        let disk_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&paths.config_path).unwrap()).unwrap();
        assert_eq!(
            disk_json["schema_version"].as_u64(),
            Some(u64::from(CONFIG_SCHEMA_VERSION))
        );
        assert_eq!(disk_json["core_runtime"]["gogc"].as_u64(), Some(25));

        // 2. Legacy v1 config with user-customized gogc == 60 must NOT be overwritten.
        std::fs::write(
            &paths.config_path,
            r#"{"schema_version":1,"core_runtime":{"gogc":60}}"#,
        )
        .unwrap();
        let custom_v1 = mgr.load_or_init().expect("load_or_init custom gogc");
        assert_eq!(custom_v1.schema_version, CONFIG_SCHEMA_VERSION);
        assert_eq!(custom_v1.core_runtime.gogc, 60);

        // 3. Explicit v2 config where user manually chose gogc == 35 must stay 35 after v3 migration.
        std::fs::write(
            &paths.config_path,
            r#"{"schema_version":2,"core_runtime":{"gogc":35}}"#,
        )
        .unwrap();
        let explicit_v2 = mgr.load_or_default().expect("load v2 gogc=35");
        assert_eq!(explicit_v2.schema_version, CONFIG_SCHEMA_VERSION);
        assert_eq!(explicit_v2.core_runtime.gogc, 35);

        // 4. `save()` unconditionally persists schema_version == CONFIG_SCHEMA_VERSION.
        let mut stale = AppConfig::default();
        stale.schema_version = 1;
        stale.core_runtime.gogc = 50;
        mgr.save(&stale).expect("save with stale schema_version");
        let saved_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&paths.config_path).unwrap()).unwrap();
        assert_eq!(
            saved_json["schema_version"].as_u64(),
            Some(u64::from(CONFIG_SCHEMA_VERSION))
        );
        assert_eq!(saved_json["core_runtime"]["gogc"].as_u64(), Some(50));

        cleanup_dir(&paths);
    }

    #[test]
    fn schema_v2_and_v3_to_v4_migrates_default_dns_while_preserving_custom_gogc_and_dns() {
        let paths = temp_paths("v2-v3-to-v4-dns-migration");
        let mgr = ConfigManager::new(paths.clone());
        let expected_v4: Vec<String> = DEFAULT_PURE_IP_ENCRYPTED_NAMESERVERS
            .iter()
            .map(|s| (*s).to_string())
            .collect();

        assert!(is_legacy_plaintext_domestic_dns_list(&[
            "223.5.5.5".to_string(),
            " 119.29.29.29:53 ".to_string(),
            "223.6.6.6".to_string(),
        ]));
        assert!(!is_legacy_plaintext_domestic_dns_list(&[]));
        assert!(!is_legacy_plaintext_domestic_dns_list(&[
            "223.5.5.5".to_string(),
            "114.114.114.114".to_string(),
        ]));
        assert!(!is_legacy_plaintext_domestic_dns_list(&[
            "https://223.5.5.5/dns-query".to_string(),
        ]));

        assert!(is_legacy_v3_doh_default_dns_list(&[
            "https://223.5.5.5/dns-query".to_string(),
            "https://1.12.12.12/dns-query".to_string(),
        ]));
        assert!(!is_legacy_v3_doh_default_dns_list(&[
            "https://223.5.5.5/dns-query".to_string(),
        ]));

        // 1. v2 config with manual gogc=35 + legacy plaintext domestic UDP 53 defaults:
        //    DNS upgrades cleanly all the way to v4 4-endpoint encrypted pool while gogc=35 stays.
        let v2_legacy_dns_raw = r#"{
            "schema_version": 2,
            "core_runtime": { "gogc": 35 },
            "dns": {
                "default_nameserver": ["223.5.5.5", "119.29.29.29"],
                "direct_nameserver": ["223.5.5.5:53", "223.6.6.6"],
                "nameserver": ["223.5.5.5", "119.29.29.29"],
                "proxy_server_nameserver": ["119.29.29.29:53"]
            }
        }"#;
        std::fs::write(&paths.config_path, v2_legacy_dns_raw).unwrap();

        let migrated = mgr.load_or_init().expect("migrate v2 legacy dns to v4");
        assert_eq!(migrated.schema_version, 4);
        assert_eq!(migrated.core_runtime.gogc, 35);
        assert_eq!(migrated.dns.default_nameserver, expected_v4);
        assert_eq!(migrated.dns.direct_nameserver, expected_v4);
        assert_eq!(migrated.dns.nameserver, expected_v4);
        assert_eq!(migrated.dns.proxy_server_nameserver, expected_v4);

        // 2. v3 config carrying the exact v3 dual-DoH default upgrades all 4 DNS lists to v4 4-endpoint pool.
        let v3_default_doh_raw = r#"{
            "schema_version": 3,
            "dns": {
                "default_nameserver": ["https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query"],
                "direct_nameserver": ["https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query"],
                "nameserver": ["https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query"],
                "proxy_server_nameserver": ["https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query"]
            }
        }"#;
        std::fs::write(&paths.config_path, v3_default_doh_raw).unwrap();

        let migrated_v3 = mgr.load_or_init().expect("migrate v3 default doh to v4");
        assert_eq!(migrated_v3.schema_version, 4);
        assert_eq!(migrated_v3.dns.default_nameserver, expected_v4);
        assert_eq!(migrated_v3.dns.direct_nameserver, expected_v4);
        assert_eq!(migrated_v3.dns.nameserver, expected_v4);
        assert_eq!(migrated_v3.dns.proxy_server_nameserver, expected_v4);

        // 3. v2/v3 config with user-customized DNS entries (custom IP, mixed list, custom DoH) must
        //    NEVER be overwritten during migration.
        let v2_custom_dns_raw = r#"{
            "schema_version": 2,
            "core_runtime": { "gogc": 35 },
            "dns": {
                "default_nameserver": ["223.5.5.5", "10.0.0.53"],
                "direct_nameserver": ["114.114.114.114"],
                "nameserver": ["https://1.12.12.12/dns-query"],
                "proxy_server_nameserver": ["https://dns.alidns.com/dns-query"]
            }
        }"#;
        std::fs::write(&paths.config_path, v2_custom_dns_raw).unwrap();

        let preserved = mgr.load_or_init().expect("preserve custom dns on v2->v4");
        assert_eq!(preserved.schema_version, 4);
        assert_eq!(preserved.core_runtime.gogc, 35);
        assert_eq!(
            preserved.dns.default_nameserver,
            vec!["223.5.5.5".to_string(), "10.0.0.53".to_string()]
        );
        assert_eq!(
            preserved.dns.direct_nameserver,
            vec!["114.114.114.114".to_string()]
        );
        assert_eq!(
            preserved.dns.nameserver,
            vec!["https://1.12.12.12/dns-query".to_string()]
        );
        assert_eq!(
            preserved.dns.proxy_server_nameserver,
            vec!["https://dns.alidns.com/dns-query".to_string()]
        );

        // 4. Explicit v3 config intentionally configured with plaintext 223.5.5.5 is NOT overwritten.
        let v3_manual_raw = r#"{
            "schema_version": 3,
            "dns": {
                "direct_nameserver": ["223.5.5.5"]
            }
        }"#;
        std::fs::write(&paths.config_path, v3_manual_raw).unwrap();
        let v3_loaded = mgr.load_or_default().expect("load explicit v3");
        assert_eq!(v3_loaded.schema_version, 4);
        assert_eq!(v3_loaded.dns.direct_nameserver, vec!["223.5.5.5".to_string()]);

        // 5. Explicit v4 config manually choosing 2-endpoint DoH is NOT re-migrated.
        let v4_manual_raw = r#"{
            "schema_version": 4,
            "dns": {
                "nameserver": ["https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query"]
            }
        }"#;
        std::fs::write(&paths.config_path, v4_manual_raw).unwrap();
        let v4_loaded = mgr.load_or_default().expect("load explicit v4");
        assert_eq!(v4_loaded.schema_version, 4);
        assert_eq!(
            v4_loaded.dns.nameserver,
            vec![
                "https://223.5.5.5/dns-query".to_string(),
                "https://1.12.12.12/dns-query".to_string(),
            ]
        );

        cleanup_dir(&paths);
    }

    #[test]
    fn validates_ui_language_and_imports_legacy_raw_json_backup_digest() {
        let paths = temp_paths("lang-and-legacy-backup");
        let mgr = ConfigManager::new(paths.clone());

        // Reject unsupported or empty UI language; accept zh-CN, en, ja, ru.
        for ok_lang in ["zh-CN", "en", "en-US", "ja", "ja-JP", "ru", "ru-RU"] {
            let mut cfg = AppConfig::default();
            cfg.personalization.language = ok_lang.to_string();
            assert!(validate_config(&cfg).is_ok(), "language `{ok_lang}` should pass");
        }
        for bad_lang in ["", "   ", "fr-FR", "ko-KR"] {
            let mut cfg = AppConfig::default();
            cfg.personalization.language = bad_lang.to_string();
            let err = validate_config(&cfg).expect_err("unsupported language must fail");
            assert!(err.to_string().contains("personalization.language"));
        }

        // Simulate a historical v1 backup whose SHA-256 was computed over a sparse legacy JSON
        // object (missing newer fields, containing schema_version=1, gogc=35, and ui_language alias).
        let legacy_cfg_compact = r#"{"schema_version":1,"mixed_port":17911,"core_runtime":{"gogc":35},"personalization":{"ui_language":"ja"}}"#;
        let legacy_sha = sha256_hex(legacy_cfg_compact.as_bytes());
        let legacy_bundle_pretty = format!(
            "{{\n  \"schema\": \"{BACKUP_SCHEMA}\",\n  \"exported_at\": \"2026-01-01T00:00:00Z\",\n  \"app_version\": \"0.0.9\",\n  \"config_sha256\": \"{legacy_sha}\",\n  \"config\": {{\n    \"schema_version\": 1,\n    \"mixed_port\": 17911,\n    \"core_runtime\": {{\n      \"gogc\": 35\n    }},\n    \"personalization\": {{\n      \"ui_language\": \"ja\"\n    }}\n  }}\n}}"
        );
        let backup_file = paths.backup_dir.join("legacy-v1-backup.json");
        std::fs::create_dir_all(&paths.backup_dir).unwrap();
        std::fs::write(&backup_file, &legacy_bundle_pretty).unwrap();

        let restored = mgr
            .import_backup(&backup_file)
            .expect("legacy raw-JSON digest backup must import cleanly");
        assert_eq!(restored.mixed_port, 17911);
        assert_eq!(restored.schema_version, CONFIG_SCHEMA_VERSION);
        assert_eq!(restored.core_runtime.gogc, 25);
        assert_eq!(restored.personalization.normalized_ui_language(), "ja");

        // Saved config preserves `"language"` JSON key name.
        let saved_raw = std::fs::read_to_string(&paths.config_path).unwrap();
        let saved_val: serde_json::Value = serde_json::from_str(&saved_raw).unwrap();
        assert_eq!(
            saved_val["personalization"]["language"].as_str(),
            Some("ja")
        );
        assert!(saved_val["personalization"].get("ui_language").is_none());

        // Tampering any value in the legacy backup must still fail SHA-256 verification.
        let tampered_path = paths.backup_dir.join("legacy-v1-tampered.json");
        std::fs::write(
            &tampered_path,
            legacy_bundle_pretty.replace("17911", "17999"),
        )
        .unwrap();
        assert!(mgr.import_backup(&tampered_path).is_err());

        cleanup_dir(&paths);
    }

    #[test]
    fn validate_config_and_backup_restore_reject_invalid_or_oversized_inline_override_yaml() {
        let paths = temp_paths("inline-override-validation");
        let mgr = ConfigManager::new(paths.clone());

        // Valid inline YAML mapping passes config validation.
        let mut valid_cfg = AppConfig::default();
        valid_cfg.rules_override.inline_override_yaml =
            Some("rules:\n  - DOMAIN-SUFFIX,example.com,DIRECT\n  - MATCH,DIRECT\n".to_string());
        assert!(validate_config(&valid_cfg).is_ok());

        // Malformed inline YAML syntax is rejected by validate_config and save().
        let mut bad_syntax = AppConfig::default();
        bad_syntax.rules_override.inline_override_yaml =
            Some("rule-providers: [\n  unclosed".to_string());
        let err = validate_config(&bad_syntax).expect_err("malformed inline YAML must fail");
        assert!(err.to_string().contains("rules_override.inline_override_yaml"));
        assert!(mgr.save(&bad_syntax).is_err());

        // Non-mapping root (top-level sequence) is rejected.
        let mut non_map = AppConfig::default();
        non_map.rules_override.inline_override_yaml =
            Some("- DOMAIN,example.com,DIRECT\n".to_string());
        let non_map_err =
            validate_config(&non_map).expect_err("non-mapping inline YAML must fail");
        assert!(non_map_err.to_string().contains("rules_override.inline_override_yaml"));

        // Oversized (> 1 MiB) inline YAML is rejected both directly and through backup import.
        let mut oversized = AppConfig::default();
        oversized.rules_override.inline_override_yaml = Some(format!(
            "rules:\n  - {}\n",
            "a".repeat(crate::models::MAX_INLINE_OVERRIDE_YAML_BYTES + 64)
        ));
        let oversized_err =
            validate_config(&oversized).expect_err("oversized inline YAML must fail");
        assert!(oversized_err.to_string().contains("rules_override.inline_override_yaml"));
        assert!(oversized_err.to_string().contains("1 MiB"));

        let canonical = serde_json::to_vec(&oversized).unwrap();
        let digest = sha256_hex(&canonical);
        let backup = ConfigBackupBundle {
            schema: BACKUP_SCHEMA.to_string(),
            exported_at: "2026-01-01T00:00:00Z".to_string(),
            app_version: "0.1.0".to_string(),
            config_sha256: digest,
            config: oversized,
        };
        std::fs::create_dir_all(&paths.backup_dir).unwrap();
        let backup_path = paths.backup_dir.join("oversized-inline-override.json");
        std::fs::write(&backup_path, serde_json::to_vec_pretty(&backup).unwrap()).unwrap();
        let restore_err = mgr
            .import_backup(&backup_path)
            .expect_err("backup restore must reject oversized inline_override_yaml");
        assert!(restore_err.to_string().contains("rules_override.inline_override_yaml"));

        cleanup_dir(&paths);
    }

    #[test]
    fn migrate_config_in_memory_heals_overseas_probe_urls_unified_switch_and_reconciles_dangling_relay() {
        let paths = temp_paths("s22-migrate-reconcile");
        let mgr = ConfigManager::new(paths.clone());

        // 1. Even on current schema_version == 4, overseas probe_url + split unified switch MUST
        //    migrate and return true, persisting cleanly via load_or_init.
        let bad_v4 = format!(
            r#"{{
                "schema_version": {CONFIG_SCHEMA_VERSION},
                "preaccel": {{
                    "enabled": false,
                    "global_bypass_enabled": true,
                    "probe_url": "https://www.gstatic.com/generate_204",
                    "fallback_probe_url": "https://cp.cloudflare.com/generate_204",
                    "active_relay_id": "   "
                }}
            }}"#
        );
        std::fs::write(&paths.config_path, &bad_v4).unwrap();

        let healed = mgr.load_or_init().expect("load_or_init heals legacy v4 bad probe_url");
        assert_eq!(healed.preaccel.probe_url, DEFAULT_PREACCEL_PROBE_URL);
        assert_eq!(
            healed.preaccel.fallback_probe_url,
            DEFAULT_PREACCEL_FALLBACK_PROBE_URL
        );
        assert!(healed.preaccel.enabled);
        assert!(healed.preaccel.global_bypass_enabled);
        assert_eq!(healed.preaccel.active_relay_id, None);

        // Disk file was persisted because migrate_config_in_memory returned true.
        let persisted_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&paths.config_path).unwrap()).unwrap();
        assert_eq!(
            persisted_json["preaccel"]["probe_url"].as_str(),
            Some(DEFAULT_PREACCEL_PROBE_URL)
        );
        assert_eq!(
            persisted_json["preaccel"]["fallback_probe_url"].as_str(),
            Some(DEFAULT_PREACCEL_FALLBACK_PROBE_URL)
        );
        assert_eq!(persisted_json["preaccel"]["enabled"].as_bool(), Some(true));
        assert_eq!(
            persisted_json["preaccel"]["global_bypass_enabled"].as_bool(),
            Some(true)
        );
        assert!(persisted_json["preaccel"]["active_relay_id"].is_null());

        // Second call is strictly idempotent and returns false.
        let mut stable = healed.clone();
        assert!(!migrate_config_in_memory(&mut stable));

        // 2. reconcile_dangling_active_relay clears missing/disabled relay IDs and keeps valid ones.
        let enabled_ids: HashSet<String> = ["relay-a".to_string(), "relay-b".to_string()]
            .into_iter()
            .collect();
        stable.preaccel.active_relay_id = Some("relay-deleted".to_string());
        assert!(reconcile_dangling_active_relay(&mut stable, &enabled_ids));
        assert_eq!(stable.preaccel.active_relay_id, None);
        assert!(!reconcile_dangling_active_relay(&mut stable, &enabled_ids));

        stable.preaccel.active_relay_id = Some(" relay-a ".to_string());
        assert!(reconcile_dangling_active_relay(&mut stable, &enabled_ids));
        assert_eq!(stable.preaccel.active_relay_id.as_deref(), Some("relay-a"));
        assert!(!reconcile_dangling_active_relay(&mut stable, &enabled_ids));

        cleanup_dir(&paths);
    }
}
