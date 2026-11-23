use crate::error::{CatError, CatResult};
use crate::models::{AppConfig, OverrideMode};
use crate::paths::AppPaths;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
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

/// Load `data/config.json` and validate it, or return `AppConfig::default()` when absent.
pub fn load_or_default(paths: &AppPaths) -> CatResult<AppConfig> {
    if paths.config_path.is_file() {
        let raw = std::fs::read_to_string(&paths.config_path)?;
        let cfg: AppConfig = serde_json::from_str(&raw)?;
        validate_config(&cfg)?;
        Ok(cfg)
    } else {
        Ok(AppConfig::default())
    }
}

/// Load `data/config.json`, or initialize and atomically persist defaults on first launch.
pub fn load_or_init(paths: &AppPaths) -> CatResult<AppConfig> {
    if paths.config_path.is_file() {
        load_or_default(paths)
    } else {
        let cfg = AppConfig::default();
        save(paths, &cfg)?;
        Ok(cfg)
    }
}

/// Validate `cfg` and persist it atomically to `paths.config_path` via `AppPaths::atomic_write`.
pub fn save(paths: &AppPaths, cfg: &AppConfig) -> CatResult<()> {
    validate_config(cfg)?;
    let bytes = serde_json::to_vec_pretty(cfg)?;
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

    let imported: AppConfig = if value.get("schema").and_then(|v| v.as_str()) == Some(BACKUP_SCHEMA)
    {
        let bundle: ConfigBackupBundle = serde_json::from_value(value)?;
        let expected = sha256_hex(&serde_json::to_vec(&bundle.config)?);
        if !expected.eq_ignore_ascii_case(&bundle.config_sha256) {
            return Err(CatError::Validation(
                "backup integrity check failed: SHA-256 digest mismatch".to_string(),
            ));
        }
        bundle.config
    } else {
        serde_json::from_value(value)?
    };

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
}
