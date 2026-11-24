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
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Maximum number of files inspected inside a single third-party profile directory.
const MAX_SCAN_FILES_PER_DIR: usize = 64;

/// Maximum `profiles.yaml` metadata index file size (2 MiB).
const MAX_PROFILES_YAML_BYTES: u64 = 2 * 1024 * 1024;

/// Maximum recursion depth below a user-selected directory for `scan_custom_path_readonly`.
const MAX_CUSTOM_SCAN_DEPTH: usize = 2;

/// Maximum total directory entries visited during a recursive custom scan to avoid hangs
/// when a user accidentally picks a large system/project directory.
const MAX_CUSTOM_SCAN_ENTRIES: usize = 4096;

/// Directory names skipped during recursive custom migration scans (case-insensitive).
const IGNORED_SCAN_DIRS: &[&str] = &[
    "cache",
    "logs",
    "ebwebview",
    "webview2",
    "node_modules",
    ".git",
];

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
    #[serde(default)]
    pub display_name: Option<String>,
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
/// open-source proxy clients (Clash Verge / Clash Verge Rev, Mihomo Party, Clash Party,
/// Clash Nyanpasu, FlClash, v2rayN).
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
                base.join("mihomo-party").join("profiles"),
            ));
            candidates.push((
                MigrationSourceKind::ClashVerge,
                base.join("clash-party").join("profiles"),
            ));
            candidates.push((
                MigrationSourceKind::ClashVerge,
                base.join("clash-nyanpasu").join("profiles"),
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
                base.join("com.follow.clash").join("config.yaml"),
            ));
            candidates.push((
                MigrationSourceKind::FlClash,
                base.join("FlClash").join("profiles"),
            ));
            candidates.push((
                MigrationSourceKind::FlClash,
                base.join("FlClash").join("config.yaml"),
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
                MigrationSourceKind::ClashVerge,
                app_support.join("mihomo-party").join("profiles"),
            ));
            candidates.push((
                MigrationSourceKind::ClashVerge,
                app_support.join("clash-party").join("profiles"),
            ));
            candidates.push((
                MigrationSourceKind::ClashVerge,
                app_support.join("clash-nyanpasu").join("profiles"),
            ));
            candidates.push((
                MigrationSourceKind::FlClash,
                app_support.join("com.follow.clash").join("profiles"),
            ));
            candidates.push((
                MigrationSourceKind::FlClash,
                app_support.join("com.follow.clash").join("config.yaml"),
            ));
            candidates.push((
                MigrationSourceKind::FlClash,
                app_support.join("FlClash").join("profiles"),
            ));
            candidates.push((
                MigrationSourceKind::FlClash,
                app_support.join("FlClash").join("config.yaml"),
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
                MigrationSourceKind::ClashVerge,
                cfg_root.join("mihomo-party").join("profiles"),
            ));
            candidates.push((
                MigrationSourceKind::ClashVerge,
                cfg_root.join("clash-party").join("profiles"),
            ));
            candidates.push((
                MigrationSourceKind::ClashVerge,
                cfg_root.join("clash-nyanpasu").join("profiles"),
            ));
            candidates.push((
                MigrationSourceKind::ClashVerge,
                data_root.join("clash-nyanpasu").join("profiles"),
            ));
            candidates.push((
                MigrationSourceKind::FlClash,
                data_root.join("com.follow.clash").join("profiles"),
            ));
            candidates.push((
                MigrationSourceKind::FlClash,
                data_root.join("com.follow.clash").join("config.yaml"),
            ));
            candidates.push((
                MigrationSourceKind::FlClash,
                cfg_root.join("FlClash").join("profiles"),
            ));
            candidates.push((
                MigrationSourceKind::FlClash,
                cfg_root.join("FlClash").join("config.yaml"),
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

/// Generate a unique subscription ID for an applied migration so repeated imports never
/// overwrite previously imported nodes.
pub fn generate_migration_subscription_id() -> String {
    format!("migrated-{}", uuid::Uuid::new_v4())
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
                let key = normalize_dedup_path(p);
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
    let mut profiles_cache: HashMap<PathBuf, HashMap<String, String>> = HashMap::new();

    if path.is_file() {
        return preview_from_file(path, Some(kind))
            .ok()
            .filter(|p| {
                !p.nodes.is_empty() || !p.prepend_rules.is_empty() || !p.append_rules.is_empty()
            })
            .map(|mut p| {
                p.display_name = resolve_display_name_for_file(path, &mut profiles_cache);
                p
            })
            .into_iter()
            .collect();
    }

    if !path.is_dir() {
        return Vec::new();
    }

    let Ok(entries) = std::fs::read_dir(path) else {
        return Vec::new();
    };

    let mut files: Vec<(PathBuf, u64)> = Vec::new();
    let mut seen_candidates: HashSet<PathBuf> = HashSet::new();
    for entry in entries.filter_map(Result::ok) {
        let p = entry.path();
        if !p.is_file() || !is_supported_config_extension(&p) {
            continue;
        }
        let Ok(meta) = std::fs::metadata(&p) else {
            continue;
        };
        let len = meta.len();
        if len == 0 || len > MAX_SUBSCRIPTION_BYTES as u64 {
            continue;
        }
        if seen_candidates.insert(normalize_dedup_path(&p)) {
            files.push((p, len));
        }
    }
    sort_files_by_size_desc(&mut files);
    files.truncate(MAX_SCAN_FILES_PER_DIR);

    let mut previews = Vec::new();
    let mut seen_paths = HashSet::new();
    for (file, _) in files {
        if !seen_paths.insert(normalize_dedup_path(&file)) {
            continue;
        }
        if let Ok(mut preview) = preview_from_file(&file, Some(kind)) {
            if !preview.nodes.is_empty()
                || !preview.prepend_rules.is_empty()
                || !preview.append_rules.is_empty()
            {
                preview.display_name = resolve_display_name_for_file(&file, &mut profiles_cache);
                previews.push(preview);
            }
        }
    }
    previews
}

/// Read-only scan of an arbitrary single plaintext config file or custom directory.
///
/// Recurses at most 2 levels below `path` (bounded by `MAX_CUSTOM_SCAN_ENTRIES`), skips
/// cache/log/webview/VCS subdirectories (`cache`, `logs`, `ebwebview`, `webview2`,
/// `node_modules`, `.git`), filters out empty or oversized (`> MAX_SUBSCRIPTION_BYTES`) files,
/// deduplicates canonicalized paths, ranks candidate YAML/JSON/TXT files by descending byte size
/// (tie-breaking by filename) before applying `MAX_SCAN_FILES_PER_DIR`, and automatically resolves
/// `profiles.yaml` / `profile.yaml` display names.
pub fn scan_custom_path_readonly(path: &Path) -> Vec<MigrationPreview> {
    let mut profiles_cache: HashMap<PathBuf, HashMap<String, String>> = HashMap::new();

    if path.is_file() {
        return preview_from_file(path, Some(MigrationSourceKind::LocalFile))
            .ok()
            .filter(|p| {
                !p.nodes.is_empty() || !p.prepend_rules.is_empty() || !p.append_rules.is_empty()
            })
            .map(|mut p| {
                p.display_name = resolve_display_name_for_file(path, &mut profiles_cache);
                p
            })
            .into_iter()
            .collect();
    }

    if !path.is_dir() {
        return Vec::new();
    }

    let mut files: Vec<(PathBuf, u64)> = Vec::new();
    let mut visited_entries: usize = 0;
    let mut seen_dirs: HashSet<PathBuf> = HashSet::new();
    let mut seen_files: HashSet<PathBuf> = HashSet::new();
    collect_custom_scan_files(
        path,
        0,
        &mut visited_entries,
        &mut seen_dirs,
        &mut seen_files,
        &mut files,
    );
    sort_files_by_size_desc(&mut files);
    files.truncate(MAX_SCAN_FILES_PER_DIR);

    let mut previews = Vec::new();
    let mut seen_paths = HashSet::new();
    for (file, _) in files {
        let key = normalize_dedup_path(&file);
        if !seen_paths.insert(key) {
            continue;
        }
        if let Ok(mut preview) = preview_from_file(&file, Some(MigrationSourceKind::LocalFile)) {
            if !preview.nodes.is_empty()
                || !preview.prepend_rules.is_empty()
                || !preview.append_rules.is_empty()
            {
                preview.display_name = resolve_display_name_for_file(&file, &mut profiles_cache);
                previews.push(preview);
            }
        }
    }
    previews
}

/// Deterministically re-bind every migrated node to `sub_id` and recompute its collision-free
/// primary key via `parser::stable_node_id`.
pub fn rebind_migration_nodes(sub_id: &str, nodes: &mut [ProxyNode]) {
    let mut used_ids = HashSet::with_capacity(nodes.len());
    for node in nodes.iter_mut() {
        node.sub_id = sub_id.to_string();
        node.id = stable_node_id(
            sub_id,
            &node.protocol,
            &node.server,
            node.port,
            &node.name,
            &mut used_ids,
        );
    }
}

/// Parse a user-selected local plaintext configuration file in read-only mode.
pub fn preview_from_file(
    path: &Path,
    kind_hint: Option<MigrationSourceKind>,
) -> CatResult<MigrationPreview> {
    let raw = read_file_bounded(path, MAX_SUBSCRIPTION_BYTES as u64)?;
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

    let mut rebound_nodes = preview.nodes.clone();
    rebind_migration_nodes(sub_id, &mut rebound_nodes);

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
        display_name: None,
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
        display_name: None,
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
        display_name: None,
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

fn sort_files_by_size_desc(files: &mut [(PathBuf, u64)]) {
    files.sort_by(|(pa, sa), (pb, sb)| {
        sb.cmp(sa).then_with(|| {
            let na = pa.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let nb = pb.file_name().and_then(|n| n.to_str()).unwrap_or("");
            na.cmp(nb).then_with(|| pa.cmp(pb))
        })
    });
}

fn is_ignored_scan_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|name| {
            IGNORED_SCAN_DIRS
                .iter()
                .any(|ignored| name.eq_ignore_ascii_case(ignored))
        })
}

fn normalize_dedup_path(path: &Path) -> PathBuf {
    let canonical = crate::paths::normalize_os_path(
        &std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()),
    );
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(canonical.to_string_lossy().to_ascii_lowercase())
    }
    #[cfg(not(target_os = "windows"))]
    {
        canonical
    }
}

fn read_file_bounded(path: &Path, max_bytes: u64) -> CatResult<Vec<u8>> {
    use std::io::Read as _;

    let file = std::fs::File::open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CatError::NotFound(format!("migration source file not found: {}", path.display()))
        } else {
            CatError::Io(e)
        }
    })?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(CatError::NotFound(format!(
            "migration source file not found: {}",
            path.display()
        )));
    }
    if meta.len() > max_bytes {
        return Err(CatError::Validation(format!(
            "migration file `{}` ({} bytes) exceeds maximum allowed {} bytes",
            path.display(),
            meta.len(),
            max_bytes
        )));
    }

    let mut raw = Vec::with_capacity((meta.len() as usize).min(64 * 1024));
    let mut limited = file.take(max_bytes.saturating_add(1));
    limited.read_to_end(&mut raw)?;
    if raw.len() as u64 > max_bytes {
        return Err(CatError::Validation(format!(
            "migration file `{}` exceeded maximum allowed {} bytes during read",
            path.display(),
            max_bytes
        )));
    }
    Ok(raw)
}

fn collect_custom_scan_files(
    dir: &Path,
    depth: usize,
    visited_entries: &mut usize,
    seen_dirs: &mut HashSet<PathBuf>,
    seen_files: &mut HashSet<PathBuf>,
    out: &mut Vec<(PathBuf, u64)>,
) {
    if *visited_entries >= MAX_CUSTOM_SCAN_ENTRIES {
        return;
    }
    if !seen_dirs.insert(normalize_dedup_path(dir)) {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        if *visited_entries >= MAX_CUSTOM_SCAN_ENTRIES {
            break;
        }
        *visited_entries += 1;

        let Ok(ft) = entry.file_type() else {
            continue;
        };
        let p = entry.path();
        if ft.is_dir() {
            if depth < MAX_CUSTOM_SCAN_DEPTH && !is_ignored_scan_dir(&p) {
                collect_custom_scan_files(
                    &p,
                    depth + 1,
                    visited_entries,
                    seen_dirs,
                    seen_files,
                    out,
                );
            }
            continue;
        }
        if (ft.is_file() || (ft.is_symlink() && p.is_file())) && is_supported_config_extension(&p) {
            let Ok(meta) = std::fs::metadata(&p) else {
                continue;
            };
            let len = meta.len();
            if len == 0 || len > MAX_SUBSCRIPTION_BYTES as u64 {
                continue;
            }
            if seen_files.insert(normalize_dedup_path(&p)) {
                out.push((p, len));
            }
        }
    }
}

fn is_profiles_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.eq_ignore_ascii_case("profiles"))
}

fn normalize_filename_key(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let base = trimmed.rsplit(['/', '\\']).next()?.trim();
    if base.is_empty() {
        return None;
    }
    Some(base.to_ascii_lowercase())
}

fn yaml_scalar_to_trimmed_string(v: &serde_yaml_ng::Value) -> Option<String> {
    match v {
        serde_yaml_ng::Value::String(s) => {
            let trimmed = s.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        }
        serde_yaml_ng::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                Some(u.to_string())
            } else if let Some(i) = n.as_i64() {
                Some(i.to_string())
            } else {
                n.as_f64().filter(|f| f.is_finite()).map(|f| f.to_string())
            }
        }
        serde_yaml_ng::Value::Tagged(tagged) => yaml_scalar_to_trimmed_string(&tagged.value),
        _ => None,
    }
}

fn load_profiles_yaml_name_map(profiles_yaml_path: &Path) -> HashMap<String, String> {
    use std::io::Read as _;

    let mut map = HashMap::new();
    let Ok(file) = std::fs::File::open(profiles_yaml_path) else {
        return map;
    };
    let Ok(meta) = file.metadata() else {
        return map;
    };
    if !meta.is_file() || meta.len() == 0 || meta.len() > MAX_PROFILES_YAML_BYTES {
        return map;
    }
    let mut raw = Vec::with_capacity((meta.len() as usize).min(64 * 1024));
    let mut limited = file.take(MAX_PROFILES_YAML_BYTES.saturating_add(1));
    if limited.read_to_end(&mut raw).is_err() || raw.len() as u64 > MAX_PROFILES_YAML_BYTES {
        return map;
    }
    let Ok(text) = std::str::from_utf8(&raw) else {
        return map;
    };
    let clean = text.strip_prefix('\u{FEFF}').unwrap_or(text);
    let Ok(mut val) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(clean) else {
        return map;
    };
    let _ = val.apply_merge();

    let Some(items) = val
        .as_mapping()
        .and_then(|root| root.get("items"))
        .and_then(serde_yaml_ng::Value::as_sequence)
    else {
        return map;
    };

    for item in items {
        let Some(item_map) = item.as_mapping() else {
            continue;
        };
        let Some(name_str) = item_map
            .get("name")
            .and_then(yaml_scalar_to_trimmed_string)
        else {
            continue;
        };
        let file_ref = item_map
            .get("file")
            .and_then(yaml_scalar_to_trimmed_string)
            .or_else(|| {
                item_map
                    .get("id")
                    .and_then(yaml_scalar_to_trimmed_string)
                    .map(|id| {
                        let lower = id.to_ascii_lowercase();
                        if lower.ends_with(".yaml")
                            || lower.ends_with(".yml")
                            || lower.ends_with(".json")
                            || lower.ends_with(".txt")
                        {
                            id
                        } else {
                            format!("{id}.yaml")
                        }
                    })
            });
        let Some(file_str) = file_ref else {
            continue;
        };
        if let Some(norm_file) = normalize_filename_key(&file_str) {
            map.insert(norm_file, name_str);
        }
    }
    map
}

fn lookup_display_name(map: &HashMap<String, String>, file_path: &Path) -> Option<String> {
    let key = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(normalize_filename_key)?;
    map.get(&key).cloned()
}

fn resolve_display_name_for_file(
    file_path: &Path,
    cache: &mut HashMap<PathBuf, HashMap<String, String>>,
) -> Option<String> {
    const PROFILE_INDEX_FILENAMES: &[&str] = &["profiles.yaml", "profile.yaml"];

    let parent = file_path.parent()?;
    let mut candidates = Vec::with_capacity(4);
    if is_profiles_dir(parent) {
        if let Some(grandparent) = parent.parent() {
            for index_name in PROFILE_INDEX_FILENAMES {
                candidates.push(grandparent.join(index_name));
            }
        }
    }
    for index_name in PROFILE_INDEX_FILENAMES {
        candidates.push(parent.join(index_name));
    }

    for cand in candidates {
        let map = cache
            .entry(cand.clone())
            .or_insert_with(|| load_profiles_yaml_name_map(&cand));
        if let Some(name) = lookup_display_name(map, file_path) {
            return Some(name);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_large_clash_subscription(sub_idx: usize) -> String {
        let mut yaml = String::from("proxies:\n");
        for n in 0..16 {
            yaml.push_str(&format!(
                "  - name: \"JP Tokyo Sub{sub_idx:02} Node{n:02} 1x\"\n    type: trojan\n    server: 203.0.113.{}\n    port: {}\n    password: \"placeholder-secret-token-{sub_idx:02}-{n:02}\"\n    sni: edge-{sub_idx:02}-{n:02}.example.invalid\n    udp: true\n",
                (sub_idx * 16 + n) % 240 + 1,
                443 + (n % 5)
            ));
        }
        yaml
    }

    fn build_single_node_yaml(label: &str, octet: u8) -> String {
        format!(
            "proxies:\n  - name: \"{label}\"\n    type: trojan\n    server: 198.51.100.{octet}\n    port: 443\n    password: \"placeholder-pass\"\n"
        )
    }

    #[test]
    fn clash_verge_52_files_descending_size_and_profiles_yaml_display_names() {
        let root = std::env::temp_dir().join(format!(
            "catcloud-migrator-52files-{}",
            uuid::Uuid::new_v4()
        ));
        let profiles_dir = root.join("profiles");
        std::fs::create_dir_all(&profiles_dir).expect("create profiles dir");

        // 42 small ~80-byte empty templates with alphabetically earlier filenames.
        let empty_template =
            "# Clash Verge empty merge template placeholder\nproxies: []\nrules: []\n# pad_80b!\n";
        assert_eq!(empty_template.len(), 80);
        for i in 0..42 {
            let path = profiles_dir.join(format!("a_{i:02}_empty.yaml"));
            std::fs::write(path, empty_template).expect("write empty template");
        }

        // 10 realistic >2KB subscriptions with alphabetically later filenames.
        let mut profiles_index = String::from("current: z_sub_00\nitems:\n");
        for i in 0..10 {
            let filename = format!("z_sub_{i:02}.yaml");
            let content = build_large_clash_subscription(i);
            assert!(
                content.len() >= 2048,
                "expected >= 2KB subscription fixture, got {} bytes",
                content.len()
            );
            std::fs::write(profiles_dir.join(&filename), content).expect("write real subscription");
            let file_ref = if i == 9 {
                format!("profiles/{filename}")
            } else {
                filename
            };
            profiles_index.push_str(&format!(
                "  - uid: sub_{i:02}\n    type: remote\n    name: \"真实订阅 {i:02}\"\n    file: {file_ref}\n"
            ));
        }
        std::fs::write(root.join("profiles.yaml"), profiles_index).expect("write profiles.yaml");

        let scanned = scan_path_readonly(MigrationSourceKind::ClashVerge, &profiles_dir);
        assert_eq!(
            scanned.len(),
            10,
            "all 10 real subscriptions must be discovered without truncation"
        );
        let names: HashSet<String> = scanned
            .iter()
            .filter_map(|p| p.display_name.clone())
            .collect();
        for i in 0..10 {
            let expected = format!("真实订阅 {i:02}");
            assert!(
                names.contains(&expected),
                "missing display_name `{expected}` in {names:?}"
            );
        }

        // Even when total files exceed MAX_SCAN_FILES_PER_DIR (64), descending-size ordering
        // still keeps all 10 large subscriptions ahead of 67 small empty templates.
        for i in 42..67 {
            let path = profiles_dir.join(format!("a_{i:02}_empty.yaml"));
            std::fs::write(path, empty_template).expect("write extra empty template");
        }
        let scanned_over_cap = scan_path_readonly(MigrationSourceKind::ClashVerge, &profiles_dir);
        assert_eq!(scanned_over_cap.len(), 10);
        for i in 0..10 {
            let expected = format!("真实订阅 {i:02}");
            assert!(
                scanned_over_cap
                    .iter()
                    .any(|p| p.display_name.as_deref() == Some(expected.as_str()))
            );
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scan_custom_path_readonly_recurses_two_levels_skips_ignored_dirs_and_maps_names() {
        let root = std::env::temp_dir().join(format!(
            "catcloud-migrator-custom-{}",
            uuid::Uuid::new_v4()
        ));
        let level1_dir = root.join("client_a");
        let level2_profiles = level1_dir.join("profiles");
        let level3_dir = level1_dir.join("nested").join("too_deep");
        std::fs::create_dir_all(&level2_profiles).expect("mkdir level2");
        std::fs::create_dir_all(&level3_dir).expect("mkdir level3");

        let level0_file = root.join("top_level.yaml");
        let level1_file = level1_dir.join("mid_level.yaml");
        let level2_file = level2_profiles.join("R406R4CRgJ3h.yaml");
        let level3_file = level3_dir.join("depth3_ignored.yaml");

        std::fs::write(&level0_file, build_single_node_yaml("HK Depth0 1x", 10)).unwrap();
        std::fs::write(&level1_file, build_single_node_yaml("SG Depth1 1x", 11)).unwrap();
        std::fs::write(&level2_file, build_single_node_yaml("JP Depth2 1x", 12)).unwrap();
        std::fs::write(&level3_file, build_single_node_yaml("US Depth3 1x", 13)).unwrap();
        std::fs::write(
            level1_dir.join("profiles.yaml"),
            "items:\n  - name: \"二层目录真实名称\"\n    file: R406R4CRgJ3h.yaml\n",
        )
        .unwrap();

        for (idx, ignored) in [
            "cache",
            "logs",
            "EBWebView",
            "WebView2",
            "node_modules",
            ".git",
        ]
        .iter()
        .enumerate()
        {
            let dir = root.join(ignored);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("should_skip.yaml"),
                build_single_node_yaml("Ignored Node", 50 + idx as u8),
            )
            .unwrap();
        }

        let scanned = scan_custom_path_readonly(&root);
        let found_names: HashSet<String> = scanned
            .iter()
            .filter_map(|p| {
                p.source_path
                    .as_ref()
                    .and_then(|sp| sp.file_name())
                    .and_then(|n| n.to_str())
                    .map(ToOwned::to_owned)
            })
            .collect();

        assert_eq!(scanned.len(), 3, "expected exactly depth 0/1/2 valid files");
        assert!(found_names.contains("top_level.yaml"));
        assert!(found_names.contains("mid_level.yaml"));
        assert!(found_names.contains("R406R4CRgJ3h.yaml"));
        assert!(!found_names.contains("depth3_ignored.yaml"));
        assert!(!found_names.contains("should_skip.yaml"));

        let mapped_preview = scanned
            .iter()
            .find(|p| {
                p.source_path
                    .as_ref()
                    .and_then(|sp| sp.file_name())
                    .and_then(|n| n.to_str())
                    == Some("R406R4CRgJ3h.yaml")
            })
            .expect("level2 profile present");
        assert_eq!(
            mapped_preview.display_name.as_deref(),
            Some("二层目录真实名称")
        );

        // Single-file custom scan also resolves parent `profiles.yaml` display_name.
        let single = scan_custom_path_readonly(&level2_file);
        assert_eq!(single.len(), 1);
        assert_eq!(single[0].display_name.as_deref(), Some("二层目录真实名称"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn migrator_filters_empty_and_oversized_files_and_caps_custom_scan_entries() {
        let root = std::env::temp_dir().join(format!(
            "catcloud-migrator-bounds-{}",
            uuid::Uuid::new_v4()
        ));
        let profiles_dir = root.join("profiles");
        std::fs::create_dir_all(&profiles_dir).unwrap();

        // Create 64 oversized (>16 MiB) files and 8 empty files; none should consume scan slots.
        for i in 0..MAX_SCAN_FILES_PER_DIR {
            let huge = profiles_dir.join(format!("huge_{i:02}.yaml"));
            let f = std::fs::File::create(&huge).unwrap();
            f.set_len(MAX_SUBSCRIPTION_BYTES as u64 + 1).unwrap();
        }
        for i in 0..8 {
            std::fs::write(profiles_dir.join(format!("empty_{i:02}.yaml")), b"").unwrap();
        }
        let valid_file = profiles_dir.join("real_small.yaml");
        std::fs::write(&valid_file, build_single_node_yaml("TW Valid 1x", 22)).unwrap();

        // Both scan_path_readonly and scan_custom_path_readonly must still discover `real_small.yaml`.
        let via_known = scan_path_readonly(MigrationSourceKind::ClashVerge, &profiles_dir);
        assert_eq!(via_known.len(), 1);
        assert_eq!(via_known[0].nodes.len(), 1);

        let via_custom = scan_custom_path_readonly(&root);
        assert_eq!(via_custom.len(), 1);
        assert_eq!(via_custom[0].nodes.len(), 1);

        // `preview_from_file` must reject oversized files cleanly via bounded read.
        let huge_err = preview_from_file(&profiles_dir.join("huge_00.yaml"), None)
            .expect_err("oversized file must be rejected");
        assert!(matches!(huge_err, CatError::Validation(_)));

        // Entry-visit cap stops collection cleanly when budget is nearly exhausted.
        let mut out = Vec::new();
        let mut visited = MAX_CUSTOM_SCAN_ENTRIES - 1;
        let mut seen_dirs = HashSet::new();
        let mut seen_files = HashSet::new();
        collect_custom_scan_files(
            &profiles_dir,
            0,
            &mut visited,
            &mut seen_dirs,
            &mut seen_files,
            &mut out,
        );
        assert_eq!(visited, MAX_CUSTOM_SCAN_ENTRIES);
        assert!(out.len() <= 1);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn load_profiles_yaml_supports_merge_numeric_names_and_singular_profile_yaml_id_fallback() {
        let root = std::env::temp_dir().join(format!(
            "catcloud-migrator-profile-yaml-{}",
            uuid::Uuid::new_v4()
        ));
        let profiles_dir = root.join("profiles");
        std::fs::create_dir_all(&profiles_dir).unwrap();

        let numeric_sub = profiles_dir.join("num_sub.yaml");
        let party_sub = profiles_dir.join("party_193a.yaml");
        let merged_sub = profiles_dir.join("merged_sub.yaml");
        std::fs::write(&numeric_sub, build_single_node_yaml("HK Num 1x", 31)).unwrap();
        std::fs::write(&party_sub, build_single_node_yaml("JP Party 1x", 32)).unwrap();
        std::fs::write(&merged_sub, build_single_node_yaml("SG Merge 1x", 33)).unwrap();

        // Mihomo/Clash Party singular `profile.yaml` using YAML anchor merge, numeric `name`,
        // and `id` without explicit `file` field.
        let profile_yaml = "\
defaults: &base_item
  name: \"锚点继承订阅\"
items:
  - id: party_193a
    name: \"Clash Party 订阅\"
  - file: num_sub.yaml
    name: 202601
  - <<: *base_item
    id: merged_sub
";
        std::fs::write(root.join("profile.yaml"), profile_yaml).unwrap();

        let scanned = scan_path_readonly(MigrationSourceKind::ClashVerge, &profiles_dir);
        assert_eq!(scanned.len(), 3);

        let by_file: HashMap<String, Option<String>> = scanned
            .iter()
            .filter_map(|p| {
                let fname = p
                    .source_path
                    .as_ref()?
                    .file_name()?
                    .to_str()?
                    .to_string();
                Some((fname, p.display_name.clone()))
            })
            .collect();

        assert_eq!(
            by_file.get("party_193a.yaml").and_then(|o| o.as_deref()),
            Some("Clash Party 订阅")
        );
        assert_eq!(
            by_file.get("num_sub.yaml").and_then(|o| o.as_deref()),
            Some("202601")
        );
        assert_eq!(
            by_file.get("merged_sub.yaml").and_then(|o| o.as_deref()),
            Some("锚点继承订阅")
        );

        let id1 = generate_migration_subscription_id();
        let id2 = generate_migration_subscription_id();
        assert!(id1.starts_with("migrated-"));
        assert!(id2.starts_with("migrated-"));
        assert_ne!(id1, id2);

        let _ = std::fs::remove_dir_all(&root);
    }
}
