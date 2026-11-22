use crate::error::{CatError, CatResult};
use crate::models::{AppConfig, ProxyNode, SubscriptionKind, SubscriptionRecord};
use crate::storage::Storage;
use crate::subscription::parser::{
    MAX_SUBSCRIPTION_BYTES, build_proxy_node, extract_nodes_from_clash_yaml, json_to_u16,
    looks_like_clash_yaml, normalize_protocol, parse_clash_yaml_value, parse_subscription_payload,
    stable_node_id,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Maximum number of files inspected inside a single third-party profile directory.
const MAX_SCAN_FILES_PER_DIR: usize = 32;

/// Source category for a read-only configuration migration preview.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MigrationSourceKind {
    ClashVerge,
    FlClash,
    V2rayN,
    LocalFile,
    ClipboardText,
}

impl MigrationSourceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ClashVerge => "clash_verge",
            Self::FlClash => "flclash",
            Self::V2rayN => "v2rayn",
            Self::LocalFile => "local_file",
            Self::ClipboardText => "clipboard_text",
        }
    }
}

/// Read-only migration preview extracted from an existing client config, file, or clipboard text.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MigrationPreview {
    pub source_kind: MigrationSourceKind,
    pub source_path: Option<PathBuf>,
    pub nodes: Vec<ProxyNode>,
    pub prepend_rules: Vec<String>,
    pub append_rules: Vec<String>,
    pub warnings: Vec<String>,
}

/// Parameters controlling how a `MigrationPreview` is persisted into CatCloud storage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationImportOptions {
    pub subscription_id: String,
    pub subscription_name: String,
    /// When `true`, replace existing nodes belonging to `subscription_id`; otherwise upsert.
    pub replace_existing: bool,
}

impl MigrationImportOptions {
    pub fn new(subscription_id: impl Into<String>, subscription_name: impl Into<String>) -> Self {
        Self {
            subscription_id: subscription_id.into(),
            subscription_name: subscription_name.into(),
            replace_existing: true,
        }
    }
}

/// Summary returned after importing a `MigrationPreview` into SQLite.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationImportReport {
    pub subscription_id: String,
    pub imported_node_count: usize,
    pub prepend_rules_count: usize,
    pub append_rules_count: usize,
    pub warnings: Vec<String>,
}

/// Return standard read-only candidate plaintext configuration locations for common
/// open-source proxy clients (Clash Verge / Clash Verge Rev, FlClash, v2rayN).
///
/// This function never creates directories or writes to any third-party path.
pub fn discover_known_client_paths() -> Vec<(MigrationSourceKind, PathBuf)> {
    let mut candidates = Vec::new();

    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            let base = PathBuf::from(&appdata);
            candidates.push((
                MigrationSourceKind::ClashVerge,
                base.join("io.github.clash-verge-rev.clash-verge-rev")
                    .join("profiles"),
            ));
            candidates.push((
                MigrationSourceKind::ClashVerge,
                base.join("clash-verge").join("profiles"),
            ));
            candidates.push((
                MigrationSourceKind::ClashVerge,
                base.join("io.github.clash-verge-rev.clash-verge-rev")
                    .join("clash-verge.yaml"),
            ));
            candidates.push((
                MigrationSourceKind::FlClash,
                base.join("com.follow.clash").join("profiles"),
            ));
            candidates.push((
                MigrationSourceKind::FlClash,
                base.join("FlClash").join("profiles"),
            ));
            candidates.push((
                MigrationSourceKind::V2rayN,
                base.join("v2rayN").join("guiConfigs").join("config.json"),
            ));
        }
        if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
            let base = PathBuf::from(&local_appdata);
            candidates.push((
                MigrationSourceKind::V2rayN,
                base.join("v2rayN").join("guiConfigs").join("config.json"),
            ));
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            let app_support = PathBuf::from(&home)
                .join("Library")
                .join("Application Support");
            candidates.push((
                MigrationSourceKind::ClashVerge,
                app_support
                    .join("io.github.clash-verge-rev.clash-verge-rev")
                    .join("profiles"),
            ));
            candidates.push((
                MigrationSourceKind::ClashVerge,
                app_support.join("clash-verge").join("profiles"),
            ));
            candidates.push((
                MigrationSourceKind::FlClash,
                app_support.join("com.follow.clash").join("profiles"),
            ));
            candidates.push((
                MigrationSourceKind::V2rayN,
                app_support
                    .join("v2rayN")
                    .join("guiConfigs")
                    .join("config.json"),
            ));
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Ok(home) = std::env::var("HOME") {
            let home_path = PathBuf::from(&home);
            let cfg_root = std::env::var("XDG_CONFIG_HOME")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| home_path.join(".config"));
            let data_root = std::env::var("XDG_DATA_HOME")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| home_path.join(".local").join("share"));

            candidates.push((
                MigrationSourceKind::ClashVerge,
                data_root
                    .join("io.github.clash-verge-rev.clash-verge-rev")
                    .join("profiles"),
            ));
            candidates.push((
                MigrationSourceKind::ClashVerge,
                cfg_root.join("clash-verge").join("profiles"),
            ));
            candidates.push((
                MigrationSourceKind::FlClash,
                data_root.join("com.follow.clash").join("profiles"),
            ));
            candidates.push((
                MigrationSourceKind::FlClash,
                cfg_root.join("FlClash").join("profiles"),
            ));
            candidates.push((
                MigrationSourceKind::V2rayN,
                cfg_root
                    .join("v2rayN")
                    .join("guiConfigs")
                    .join("config.json"),
            ));
        }
    }

    candidates
}

/// Perform a one-click read-only scan across known open-source proxy client paths on this machine.
/// Never writes or modifies any file in third-party directories.
pub fn scan_local_clients() -> Vec<MigrationPreview> {
    let mut previews = Vec::new();
    let mut seen_paths = HashSet::new();

    for (kind, candidate) in discover_known_client_paths() {
        if !candidate.exists() {
            continue;
        }
        let found = scan_path_readonly(kind, &candidate);
        for preview in found {
            if let Some(ref p) = preview.source_path {
                let key = std::fs::canonicalize(p).unwrap_or_else(|_| p.clone());
                if !seen_paths.insert(key) {
                    continue;
                }
            }
            previews.push(preview);
        }
    }

    previews
}

/// Read-only scan of a specific directory or config file attributed to `kind`.
pub fn scan_path_readonly(kind: MigrationSourceKind, path: &Path) -> Vec<MigrationPreview> {
    if path.is_file() {
        return preview_from_file(path, Some(kind))
            .ok()
            .filter(|p| !p.nodes.is_empty() || !p.prepend_rules.is_empty() || !p.append_rules.is_empty())
            .into_iter()
            .collect();
    }

    if !path.is_dir() {
        return Vec::new();
    }

    let Ok(entries) = std::fs::read_dir(path) else {
        return Vec::new();
    };

    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file() && is_supported_config_extension(p))
        .collect();
    files.sort();
    files.truncate(MAX_SCAN_FILES_PER_DIR);

    let mut previews = Vec::new();
    for file in files {
        if let Ok(preview) = preview_from_file(&file, Some(kind)) {
            if !preview.nodes.is_empty()
                || !preview.prepend_rules.is_empty()
                || !preview.append_rules.is_empty()
            {
                previews.push(preview);
            }
        }
    }
    previews
}

/// Parse a user-selected local plaintext configuration file in read-only mode.
pub fn preview_from_file(
    path: &Path,
    kind_hint: Option<MigrationSourceKind>,
) -> CatResult<MigrationPreview> {
    if !path.is_file() {
        return Err(CatError::NotFound(format!(
            "migration source file not found: {}",
            path.display()
        )));
    }

    let meta = std::fs::metadata(path)?;
    if meta.len() > MAX_SUBSCRIPTION_BYTES as u64 {
        return Err(CatError::Validation(format!(
            "migration file `{}` ({} bytes) exceeds maximum allowed {} bytes",
            path.display(),
            meta.len(),
            MAX_SUBSCRIPTION_BYTES
        )));
    }

    let raw = std::fs::read(path)?;
    let text = std::str::from_utf8(&raw).map_err(|e| {
        CatError::Validation(format!(
            "migration file `{}` is not valid UTF-8 plaintext: {e}",
            path.display()
        ))
    })?;

    let source_kind = kind_hint.unwrap_or(MigrationSourceKind::LocalFile);
    let mut preview = parse_migration_text(source_kind, text)?;
    preview.source_path = Some(path.to_path_buf());
    Ok(preview)
}

/// Parse clipboard text (Clash YAML, v2rayN plaintext JSON, Base64, or plain proxy URIs)
/// into a read-only `MigrationPreview`.
pub fn preview_from_text(text: &str) -> CatResult<MigrationPreview> {
    if text.len() > MAX_SUBSCRIPTION_BYTES {
        return Err(CatError::Validation(format!(
            "clipboard text size {} bytes exceeds maximum allowed {} bytes",
            text.len(),
            MAX_SUBSCRIPTION_BYTES
        )));
    }
    parse_migration_text(MigrationSourceKind::ClipboardText, text)
}

/// Persist a reviewed `MigrationPreview` into CatCloud SQLite storage.
///
/// Always ensures the parent `SubscriptionRecord` exists before inserting nodes,
/// re-binds all node `sub_id`s deterministically, and rejects empty node sets.
pub fn import_migration_preview(
    storage: &mut Storage,
    preview: &MigrationPreview,
    options: &MigrationImportOptions,
) -> CatResult<MigrationImportReport> {
    let sub_id = options.subscription_id.trim();
    if sub_id.is_empty() {
        return Err(CatError::Validation(
            "migration subscription_id cannot be empty".to_string(),
        ));
    }
    if preview.nodes.is_empty() {
        return Err(CatError::Validation(
            "cannot import migration preview with 0 valid nodes".to_string(),
        ));
    }

    let sub_name = if options.subscription_name.trim().is_empty() {
        format!("Migrated ({})", preview.source_kind.as_str())
    } else {
        options.subscription_name.trim().to_string()
    };

    let source_label = preview
        .source_path
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| preview.source_kind.as_str().to_string());

    let sub_record = SubscriptionRecord {
        id: sub_id.to_string(),
        name: sub_name,
        kind: SubscriptionKind::Migrated,
        url_or_cmd: source_label,
        refresh_interval_sec: 0,
        traffic_used_bytes: 0,
        traffic_total_bytes: 0,
        expires_at: None,
        etag: None,
        last_ok_at: Some(Utc::now().to_rfc3339()),
        last_error: None,
        enabled: true,
    };

    let mut used_ids = HashSet::with_capacity(preview.nodes.len());
    let mut rebound_nodes = Vec::with_capacity(preview.nodes.len());
    for node in &preview.nodes {
        let mut cloned = node.clone();
        cloned.sub_id = sub_id.to_string();
        cloned.id = stable_node_id(
            sub_id,
            &cloned.protocol,
            &cloned.server,
            cloned.port,
            &cloned.name,
            &mut used_ids,
        );
        rebound_nodes.push(cloned);
    }

    storage.upsert_subscription(&sub_record)?;
    let imported_node_count = if options.replace_existing {
        storage.replace_subscription_nodes(sub_id, &rebound_nodes)?
    } else {
        storage.upsert_nodes_batch(&rebound_nodes)?
    };

    Ok(MigrationImportReport {
        subscription_id: sub_id.to_string(),
        imported_node_count,
        prepend_rules_count: preview.prepend_rules.len(),
        append_rules_count: preview.append_rules.len(),
        warnings: preview.warnings.clone(),
    })
}

/// Merge migrated prepend/append rules into `AppConfig.rules_override` without duplicating
/// or overwriting existing user-defined rules. Returns `(added_prepend, added_append)`.
pub fn apply_migration_rules_to_config(
    cfg: &mut AppConfig,
    preview: &MigrationPreview,
) -> (usize, usize) {
    let mut added_prepend = 0usize;
    let mut existing_prepend: HashSet<String> = cfg
        .rules_override
        .global_prepend_rules
        .iter()
        .map(|r| r.trim().to_string())
        .collect();
    for rule in &preview.prepend_rules {
        let trimmed = rule.trim();
        if !trimmed.is_empty() && existing_prepend.insert(trimmed.to_string()) {
            cfg.rules_override
                .global_prepend_rules
                .push(trimmed.to_string());
            added_prepend += 1;
        }
    }

    let mut added_append = 0usize;
    let mut existing_append: HashSet<String> = cfg
        .rules_override
        .global_append_rules
        .iter()
        .map(|r| r.trim().to_string())
        .collect();
    for rule in &preview.append_rules {
        let trimmed = rule.trim();
        if !trimmed.is_empty() && existing_append.insert(trimmed.to_string()) {
            cfg.rules_override
                .global_append_rules
                .push(trimmed.to_string());
            added_append += 1;
        }
    }

    (added_prepend, added_append)
}

// ============================================================================
// Internal plaintext parsers for Clash YAML, v2rayN/Xray JSON, and URI lists
// ============================================================================

fn parse_migration_text(
    source_kind: MigrationSourceKind,
    raw_text: &str,
) -> CatResult<MigrationPreview> {
    let text = raw_text.strip_prefix('\u{FEFF}').unwrap_or(raw_text).trim();
    if text.is_empty() {
        return Err(CatError::Validation(
            "migration source content is empty".to_string(),
        ));
    }

    let preview_sub_id = format!("preview_{}", source_kind.as_str());

    // 1. JSON configuration (v2rayN / Xray / sing-box plaintext JSON)
    if text.starts_with('{') {
        if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(text) {
            if json_val.get("outbounds").and_then(serde_json::Value::as_array).is_some() {
                return parse_v2ray_json_preview(source_kind, &preview_sub_id, &json_val);
            }
        }
    }

    // 2. Clash / Mihomo YAML (including Clash Verge / FlClash profiles & merge rules)
    if looks_like_clash_yaml(text) {
        return parse_clash_yaml_preview(source_kind, &preview_sub_id, text);
    }

    // 3. Fallback to generic subscription payload parser (Base64 / plain URI list / YAML)
    let parsed = parse_subscription_payload(&preview_sub_id, text.as_bytes(), None)?;
    Ok(MigrationPreview {
        source_kind,
        source_path: None,
        nodes: parsed.nodes,
        prepend_rules: Vec::new(),
        append_rules: Vec::new(),
        warnings: parsed.warnings,
    })
}

fn parse_clash_yaml_preview(
    source_kind: MigrationSourceKind,
    preview_sub_id: &str,
    text: &str,
) -> CatResult<MigrationPreview> {
    let yaml_val = parse_clash_yaml_value(text)?;
    let Some(root_map) = yaml_val.as_mapping() else {
        return Err(CatError::Validation(
            "expected YAML mapping in migration config".to_string(),
        ));
    };

    let mut warnings = Vec::new();
    let has_proxies = root_map.contains_key(serde_yaml_ng::Value::String("proxies".into()))
        || root_map.contains_key(serde_yaml_ng::Value::String("Proxy".into()));

    let nodes = if has_proxies {
        let (extracted, mut w) = extract_nodes_from_clash_yaml(preview_sub_id, &yaml_val)?;
        warnings.append(&mut w);
        extracted
    } else {
        Vec::new()
    };

    let mut prepend_rules = extract_yaml_string_list(root_map, "prepend-rules");
    let mut append_rules = extract_yaml_string_list(root_map, "append-rules");

    let general_rules = extract_yaml_string_list(root_map, "rules");
    let mut skipped_match_count = 0usize;

    for rule in general_rules {
        let trimmed = rule.trim();
        if trimmed.is_empty() {
            continue;
        }
        let upper = trimmed.to_ascii_uppercase();
        if upper.starts_with("MATCH,") || upper == "MATCH" {
            skipped_match_count += 1;
            continue;
        }
        if is_high_priority_rule(&upper) {
            prepend_rules.push(trimmed.to_string());
        } else {
            append_rules.push(trimmed.to_string());
        }
    }

    if skipped_match_count > 0 {
        warnings.push(format!(
            "skipped {skipped_match_count} legacy MATCH catch-all rule(s) to preserve CatCloud default routing"
        ));
    }

    if nodes.is_empty() && prepend_rules.is_empty() && append_rules.is_empty() {
        return Err(CatError::Validation(
            "YAML file contains neither valid proxy nodes nor importable rules".to_string(),
        ));
    }

    Ok(MigrationPreview {
        source_kind,
        source_path: None,
        nodes,
        prepend_rules,
        append_rules,
        warnings,
    })
}

fn parse_v2ray_json_preview(
    source_kind: MigrationSourceKind,
    preview_sub_id: &str,
    root: &serde_json::Value,
) -> CatResult<MigrationPreview> {
    let outbounds = root
        .get("outbounds")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| CatError::Validation("v2rayN JSON missing `outbounds` array".to_string()))?;

    let mut nodes = Vec::new();
    let mut warnings = Vec::new();
    let mut used_ids = HashSet::new();
    let mut skipped_builtins = 0usize;

    for (idx, outbound) in outbounds.iter().enumerate() {
        let Some(obj) = outbound.as_object() else {
            continue;
        };

        let raw_proto = obj
            .get("protocol")
            .or_else(|| obj.get("type"))
            .and_then(serde_json::Value::as_str)
            .map(|s| s.trim().to_ascii_lowercase())
            .unwrap_or_default();

        if matches!(
            raw_proto.as_str(),
            "" | "freedom"
                | "blackhole"
                | "dns"
                | "direct"
                | "block"
                | "selector"
                | "urltest"
                | "loopback"
        ) {
            skipped_builtins += 1;
            continue;
        }

        let tag = obj
            .get("tag")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned);

        match convert_v2ray_outbound(preview_sub_id, &raw_proto, tag, obj, &mut used_ids) {
            Ok(node) => nodes.push(node),
            Err(reason) => warnings.push(format!("skipped outbounds[{idx}] ({raw_proto}): {reason}")),
        }
    }

    if skipped_builtins > 0 {
        warnings.push(format!(
            "ignored {skipped_builtins} built-in non-proxy outbound(s) (freedom/blackhole/dns/direct)"
        ));
    }

    let (prepend_rules, append_rules, mut routing_warnings) = extract_v2ray_routing_rules(root);
    warnings.append(&mut routing_warnings);

    if nodes.is_empty() && prepend_rules.is_empty() && append_rules.is_empty() {
        return Err(CatError::Validation(
            "v2rayN JSON parsed 0 valid proxy nodes and 0 importable rules".to_string(),
        ));
    }

    Ok(MigrationPreview {
        source_kind,
        source_path: None,
        nodes,
        prepend_rules,
        append_rules,
        warnings,
    })
}

fn convert_v2ray_outbound(
    sub_id: &str,
    raw_proto: &str,
    tag: Option<String>,
    obj: &serde_json::Map<String, serde_json::Value>,
    used_ids: &mut HashSet<String>,
) -> Result<ProxyNode, String> {
    let protocol = normalize_protocol(raw_proto);

    // Flat sing-box style outbound (`server` + `server_port`)
    if let (Some(server), Some(port)) = (
        obj.get("server")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty()),
        obj.get("server_port").and_then(json_to_u16).filter(|&p| p > 0),
    ) {
        let name = tag.unwrap_or_else(|| format!("{protocol}-{server}:{port}"));
        let mut cfg = obj.clone();
        cfg.insert("name".into(), serde_json::json!(name));
        cfg.insert("type".into(), serde_json::json!(protocol));
        cfg.insert("server".into(), serde_json::json!(server));
        cfg.insert("port".into(), serde_json::json!(port));
        if let Some(tls_obj) = obj.get("tls").and_then(serde_json::Value::as_object) {
            if let Some(enabled) = tls_obj.get("enabled").and_then(serde_json::Value::as_bool) {
                cfg.insert("tls".into(), serde_json::json!(enabled));
            }
            if let Some(sni) = tls_obj.get("server_name").and_then(serde_json::Value::as_str) {
                cfg.insert("servername".into(), serde_json::json!(sni));
            }
        }
        return Ok(build_proxy_node(
            sub_id,
            name,
            protocol,
            server.to_string(),
            port,
            serde_json::Value::Object(cfg),
            used_ids,
        ));
    }

    let settings = obj
        .get("settings")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "missing `settings` object".to_string())?;
    let stream = obj
        .get("streamSettings")
        .and_then(serde_json::Value::as_object);

    let (server, port, mut cfg) = match protocol.as_str() {
        "vless" | "vmess" => {
            let vnext = settings
                .get("vnext")
                .and_then(serde_json::Value::as_array)
                .and_then(|arr| arr.first())
                .and_then(serde_json::Value::as_object)
                .ok_or_else(|| "missing `settings.vnext[0]`".to_string())?;
            let server = vnext
                .get("address")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "missing `vnext[0].address`".to_string())?
                .to_string();
            let port = vnext
                .get("port")
                .and_then(json_to_u16)
                .filter(|&p| p > 0)
                .ok_or_else(|| "missing valid `vnext[0].port`".to_string())?;
            let user = vnext
                .get("users")
                .and_then(serde_json::Value::as_array)
                .and_then(|arr| arr.first())
                .and_then(serde_json::Value::as_object)
                .ok_or_else(|| "missing `vnext[0].users[0]`".to_string())?;
            let uuid = user
                .get("id")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "missing user `id`".to_string())?;

            let mut map = serde_json::Map::new();
            map.insert("uuid".into(), serde_json::json!(uuid));
            if protocol == "vmess" {
                let aid = user
                    .get("alterId")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                let cipher = user
                    .get("security")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("auto");
                map.insert("alterId".into(), serde_json::json!(aid));
                map.insert("cipher".into(), serde_json::json!(cipher));
            } else if let Some(flow) = user
                .get("flow")
                .and_then(serde_json::Value::as_str)
                .filter(|s| !s.is_empty())
            {
                map.insert("flow".into(), serde_json::json!(flow));
            }
            (server, port, map)
        }
        "trojan" | "ss" => {
            let srv = settings
                .get("servers")
                .and_then(serde_json::Value::as_array)
                .and_then(|arr| arr.first())
                .and_then(serde_json::Value::as_object)
                .ok_or_else(|| "missing `settings.servers[0]`".to_string())?;
            let server = srv
                .get("address")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "missing `servers[0].address`".to_string())?
                .to_string();
            let port = srv
                .get("port")
                .and_then(json_to_u16)
                .filter(|&p| p > 0)
                .ok_or_else(|| "missing valid `servers[0].port`".to_string())?;
            let password = srv
                .get("password")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let mut map = serde_json::Map::new();
            map.insert("password".into(), serde_json::json!(password));
            if protocol == "ss" {
                let cipher = srv
                    .get("method")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("aes-256-gcm");
                map.insert("cipher".into(), serde_json::json!(cipher));
            }
            (server, port, map)
        }
        other => {
            return Err(format!("unsupported v2rayN outbound protocol `{other}`"));
        }
    };

    let name = tag.unwrap_or_else(|| format!("{protocol}-{server}:{port}"));
    cfg.insert("name".into(), serde_json::json!(name));
    cfg.insert("type".into(), serde_json::json!(protocol));
    cfg.insert("server".into(), serde_json::json!(server));
    cfg.insert("port".into(), serde_json::json!(port));
    cfg.insert("udp".into(), serde_json::json!(true));

    if let Some(ss) = stream {
        apply_v2ray_stream_settings(&mut cfg, ss);
    }

    Ok(build_proxy_node(
        sub_id,
        name,
        protocol,
        server,
        port,
        serde_json::Value::Object(cfg),
        used_ids,
    ))
}

fn apply_v2ray_stream_settings(
    cfg: &mut serde_json::Map<String, serde_json::Value>,
    stream: &serde_json::Map<String, serde_json::Value>,
) {
    if let Some(net) = stream
        .get("network")
        .and_then(serde_json::Value::as_str)
        .map(|s| s.trim().to_ascii_lowercase())
    {
        if !net.is_empty() && net != "tcp" {
            cfg.insert("network".into(), serde_json::json!(net));
        }
        if net == "ws" {
            if let Some(ws) = stream
                .get("wsSettings")
                .and_then(serde_json::Value::as_object)
            {
                let mut ws_opts = serde_json::Map::new();
                if let Some(path) = ws.get("path").and_then(serde_json::Value::as_str) {
                    ws_opts.insert("path".into(), serde_json::json!(path));
                }
                if let Some(headers) = ws.get("headers") {
                    ws_opts.insert("headers".into(), headers.clone());
                }
                if !ws_opts.is_empty() {
                    cfg.insert("ws-opts".into(), serde_json::Value::Object(ws_opts));
                }
            }
        } else if net == "grpc" {
            if let Some(svc) = stream
                .get("grpcSettings")
                .and_then(|g| g.get("serviceName"))
                .and_then(serde_json::Value::as_str)
            {
                cfg.insert(
                    "grpc-opts".into(),
                    serde_json::json!({ "grpc-service-name": svc }),
                );
            }
        }
    }

    let security = stream
        .get("security")
        .and_then(serde_json::Value::as_str)
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();

    match security.as_str() {
        "tls" => {
            cfg.insert("tls".into(), serde_json::json!(true));
            if let Some(tls_s) = stream
                .get("tlsSettings")
                .and_then(serde_json::Value::as_object)
            {
                if let Some(sni) = tls_s
                    .get("serverName")
                    .and_then(serde_json::Value::as_str)
                    .filter(|s| !s.is_empty())
                {
                    cfg.insert("servername".into(), serde_json::json!(sni));
                }
                if let Some(allow) = tls_s
                    .get("allowInsecure")
                    .and_then(serde_json::Value::as_bool)
                {
                    cfg.insert("skip-cert-verify".into(), serde_json::json!(allow));
                }
                if let Some(fp) = tls_s
                    .get("fingerprint")
                    .and_then(serde_json::Value::as_str)
                    .filter(|s| !s.is_empty())
                {
                    cfg.insert("client-fingerprint".into(), serde_json::json!(fp));
                }
            }
        }
        "reality" => {
            cfg.insert("tls".into(), serde_json::json!(true));
            if let Some(rs) = stream
                .get("realitySettings")
                .and_then(serde_json::Value::as_object)
            {
                if let Some(sni) = rs
                    .get("serverName")
                    .and_then(serde_json::Value::as_str)
                    .filter(|s| !s.is_empty())
                {
                    cfg.insert("servername".into(), serde_json::json!(sni));
                }
                if let Some(fp) = rs
                    .get("fingerprint")
                    .and_then(serde_json::Value::as_str)
                    .filter(|s| !s.is_empty())
                {
                    cfg.insert("client-fingerprint".into(), serde_json::json!(fp));
                }
                let mut reality_opts = serde_json::Map::new();
                if let Some(pbk) = rs.get("publicKey").and_then(serde_json::Value::as_str) {
                    reality_opts.insert("public-key".into(), serde_json::json!(pbk));
                }
                if let Some(sid) = rs.get("shortId").and_then(serde_json::Value::as_str) {
                    reality_opts.insert("short-id".into(), serde_json::json!(sid));
                }
                if !reality_opts.is_empty() {
                    cfg.insert("reality-opts".into(), serde_json::Value::Object(reality_opts));
                }
            }
        }
        _ => {}
    }
}

fn extract_v2ray_routing_rules(
    root: &serde_json::Value,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut prepend = Vec::new();
    let mut append = Vec::new();
    let mut warnings = Vec::new();

    let Some(rules) = root
        .get("routing")
        .and_then(|r| r.get("rules"))
        .and_then(serde_json::Value::as_array)
    else {
        return (prepend, append, warnings);
    };

    for rule in rules {
        let Some(obj) = rule.as_object() else {
            continue;
        };
        let target_raw = obj
            .get("outboundTag")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("PROXY");
        let target = match target_raw.to_ascii_lowercase().as_str() {
            "direct" | "freedom" => "DIRECT",
            "block" | "blackhole" | "reject" => "REJECT",
            _ => "PROXY",
        };
        let dest = if matches!(target, "DIRECT" | "REJECT") {
            &mut prepend
        } else {
            &mut append
        };

        let mut mapped_any = false;
        if let Some(domains) = obj.get("domain").and_then(serde_json::Value::as_array) {
            for d in domains.iter().filter_map(serde_json::Value::as_str) {
                if let Some(rest) = d.strip_prefix("domain:") {
                    dest.push(format!("DOMAIN-SUFFIX,{rest},{target}"));
                    mapped_any = true;
                } else if let Some(rest) = d.strip_prefix("full:") {
                    dest.push(format!("DOMAIN,{rest},{target}"));
                    mapped_any = true;
                } else if let Some(rest) = d.strip_prefix("geosite:") {
                    dest.push(format!("GEOSITE,{rest},{target}"));
                    mapped_any = true;
                } else if !d.starts_with("regexp:") && !d.trim().is_empty() {
                    dest.push(format!("DOMAIN-KEYWORD,{},{target}", d.trim()));
                    mapped_any = true;
                }
            }
        }
        if let Some(ips) = obj.get("ip").and_then(serde_json::Value::as_array) {
            for ip in ips.iter().filter_map(serde_json::Value::as_str) {
                if let Some(rest) = ip.strip_prefix("geoip:") {
                    dest.push(format!("GEOIP,{rest},{target}"));
                    mapped_any = true;
                } else if ip.contains('/') {
                    dest.push(format!("IP-CIDR,{ip},{target},no-resolve"));
                    mapped_any = true;
                }
            }
        }
        if !mapped_any {
            warnings.push(format!(
                "skipped non-mappable v2rayN routing rule targeting `{target_raw}`"
            ));
        }
    }

    (prepend, append, warnings)
}

fn extract_yaml_string_list(map: &serde_yaml_ng::Mapping, key: &str) -> Vec<String> {
    let Some(seq) = map
        .get(serde_yaml_ng::Value::String(key.to_string()))
        .and_then(serde_yaml_ng::Value::as_sequence)
    else {
        return Vec::new();
    };
    seq.iter()
        .filter_map(serde_yaml_ng::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn is_high_priority_rule(rule_upper: &str) -> bool {
    rule_upper.starts_with("PROCESS-NAME,")
        || rule_upper.starts_with("PROCESS-PATH,")
        || rule_upper.ends_with(",DIRECT")
        || rule_upper.ends_with(",DIRECT,NO-RESOLVE")
        || rule_upper.ends_with(",REJECT")
        || rule_upper.ends_with(",REJECT,NO-RESOLVE")
}

fn is_supported_config_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .is_some_and(|ext| matches!(ext.as_str(), "yaml" | "yml" | "json" | "txt"))
}
