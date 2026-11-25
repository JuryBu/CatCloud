use crate::error::{CatError, CatResult};
use crate::models::{
    DEFAULT_COST_EFFECTIVE_FORMULA, DynamicFilterSpec, FallbackPolicy, MultiGroup, MultiGroupMode,
    MultiGroupState, PreAccelRelay, ProxyNode, SwitchMode, TriggerRule,
};
use crate::preaccel::{bundle_from_relays, parse_mmrelay_json, serialize_mmrelay_json};
use crate::storage::Storage;
use crate::subscription::parser::{
    node_dedup_fingerprint, normalize_protocol, parse_subscription_payload,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_yaml_ng::{Mapping, Number, Value};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path};
use uuid::Uuid;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

/// Standard schema identifier for CatCloud `.zip` share bundles.
pub const SHARE_BUNDLE_SCHEMA: &str = "catcloud-share/v1";

/// Standard schema identifier for optional `groups.json` inside `catcloud-share/v1` ZIP archives.
pub const SHARE_GROUPS_SCHEMA: &str = "catcloud-groups/v1";

/// Maximum total uncompressed payload bytes allowed across all entries in a share ZIP (16 MiB).
pub const MAX_SHARE_ZIP_UNCOMPRESSED_BYTES: usize = 16 * 1024 * 1024;

/// Maximum number of ZIP archive entries accepted when previewing a share bundle.
pub const MAX_SHARE_ZIP_ENTRIES: usize = 32;

/// Maximum number of proxy nodes permitted in a single share bundle.
pub const MAX_SHARE_NODES: usize = 4000;

/// Maximum compressed `.zip` file size read from disk before parsing (17 MiB headroom).
const MAX_SHARE_ZIP_FILE_BYTES: u64 = (MAX_SHARE_ZIP_UNCOMPRESSED_BYTES as u64) + 1024 * 1024;

/// Unix file type mask and symlink mode bit (`S_IFMT` / `S_IFLNK`).
const UNIX_FILE_TYPE_MASK: u32 = 0o170000;
const UNIX_SYMLINK_MODE: u32 = 0o120000;

/// Metadata manifest stored as `manifest.json` inside every `catcloud-share/v1` ZIP archive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareBundleManifest {
    pub schema: String,
    pub name: String,
    pub created_at: String,
    pub node_count: usize,
    pub relay_count: usize,
    pub description: Option<String>,
    pub sanitized_notice: String,
}

/// Export request containing the selected proxy nodes and/or domestic pre-acceleration relays.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ShareBundleExportRequest {
    pub name: String,
    pub description: Option<String>,
    pub nodes: Vec<ProxyNode>,
    pub relays: Vec<PreAccelRelay>,
}

/// Portable multi-group record stored inside optional `groups.json` (`catcloud-groups/v1`).
/// Member and active node references use `node_dedup_fingerprint` (`catcloud-node-fp-v1`)
/// instead of machine-local node IDs so groups merge cleanly across devices.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ShareGroupRecord {
    pub name: String,
    pub mode: MultiGroupMode,
    pub match_rules: Vec<String>,
    pub member_fingerprints: Vec<String>,
    pub dynamic_filter: Option<DynamicFilterSpec>,
    pub primary_probe_id: Option<String>,
    pub hard_gates: Vec<String>,
    pub trigger_rules: Vec<TriggerRule>,
    pub formula_expr: String,
    pub fallback_policy: FallbackPolicy,
    pub fallback_pool_name: Option<String>,
    pub recover_probe_interval_sec: u64,
    pub switch_mode: SwitchMode,
    pub cooldown_sec: u64,
    pub hysteresis_pct: f64,
    pub active_node_fingerprint: Option<String>,
    pub independent_routing: bool,
}

impl Default for ShareGroupRecord {
    fn default() -> Self {
        Self {
            name: String::new(),
            mode: MultiGroupMode::StickyBest,
            match_rules: Vec::new(),
            member_fingerprints: Vec::new(),
            dynamic_filter: None,
            primary_probe_id: None,
            hard_gates: Vec::new(),
            trigger_rules: Vec::new(),
            formula_expr: DEFAULT_COST_EFFECTIVE_FORMULA.to_string(),
            fallback_policy: FallbackPolicy::DegradeBestWarn,
            fallback_pool_name: None,
            recover_probe_interval_sec: 120,
            switch_mode: SwitchMode::ForceCloseOld,
            cooldown_sec: 60,
            hysteresis_pct: 20.0,
            active_node_fingerprint: None,
            independent_routing: false,
        }
    }
}

/// Optional `groups.json` payload inside a `catcloud-share/v1` ZIP archive (`catcloud-groups/v1`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ShareGroupsBundle {
    pub schema: String,
    pub active_group_name: Option<String>,
    pub route_mode: Option<String>,
    pub groups: Vec<ShareGroupRecord>,
}

impl Default for ShareGroupsBundle {
    fn default() -> Self {
        Self {
            schema: SHARE_GROUPS_SCHEMA.to_string(),
            active_group_name: None,
            route_mode: None,
            groups: Vec::new(),
        }
    }
}

/// Build a portable `ShareGroupsBundle` from local `MultiGroup` records and their backing `ProxyNode`s.
pub fn build_share_groups_bundle(
    groups: &[MultiGroup],
    nodes: &[ProxyNode],
    active_group_id: Option<&str>,
    route_mode: Option<&str>,
) -> ShareGroupsBundle {
    let node_id_to_fp: HashMap<&str, String> = nodes
        .iter()
        .map(|n| (n.id.as_str(), node_dedup_fingerprint(n)))
        .collect();
    let group_id_to_name: HashMap<&str, &str> = groups
        .iter()
        .map(|g| (g.id.as_str(), g.name.trim()))
        .filter(|(_, name)| !name.is_empty())
        .collect();

    let active_group_name = active_group_id
        .and_then(|gid| group_id_to_name.get(gid.trim()).copied())
        .map(ToOwned::to_owned);

    let records = groups
        .iter()
        .filter(|g| !g.name.trim().is_empty())
        .map(|g| {
            let mut seen_fps = HashSet::new();
            let member_fingerprints: Vec<String> = g
                .member_node_ids
                .iter()
                .filter_map(|nid| node_id_to_fp.get(nid.as_str()).cloned())
                .filter(|fp| seen_fps.insert(fp.clone()))
                .collect();
            let active_node_fingerprint = g
                .active_node_id
                .as_deref()
                .and_then(|nid| node_id_to_fp.get(nid).cloned());
            let fallback_pool_name = g
                .fallback_pool_id
                .as_deref()
                .and_then(|pid| group_id_to_name.get(pid).copied())
                .map(ToOwned::to_owned);

            ShareGroupRecord {
                name: g.name.trim().to_string(),
                mode: g.mode.clone(),
                match_rules: g.match_rules.clone(),
                member_fingerprints,
                dynamic_filter: g.dynamic_filter.clone(),
                primary_probe_id: g.primary_probe_id.clone(),
                hard_gates: g.hard_gates.clone(),
                trigger_rules: g.trigger_rules.clone(),
                formula_expr: g.formula_expr.clone(),
                fallback_policy: g.fallback_policy.clone(),
                fallback_pool_name,
                recover_probe_interval_sec: g.recover_probe_interval_sec,
                switch_mode: g.switch_mode.clone(),
                cooldown_sec: g.cooldown_sec,
                hysteresis_pct: g.hysteresis_pct,
                active_node_fingerprint,
                independent_routing: g.independent_routing,
            }
        })
        .collect();

    ShareGroupsBundle {
        schema: SHARE_GROUPS_SCHEMA.to_string(),
        active_group_name,
        route_mode: route_mode
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned),
        groups: records,
    }
}

/// In-memory preview returned by parsing a `catcloud-share/v1` ZIP bundle without touching disk.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ShareBundlePreview {
    pub manifest: ShareBundleManifest,
    pub nodes: Vec<ProxyNode>,
    pub relays: Vec<PreAccelRelay>,
    pub warnings: Vec<String>,
    pub has_readme: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups_bundle: Option<ShareGroupsBundle>,
}

/// Export selected proxy nodes and/or domestic pre-acceleration relays into an in-memory
/// `catcloud-share/v1` ZIP archive alongside its manifest.
///
/// Export sanitization guarantees:
/// - Subscription source URLs, local file paths, controller secrets, and logs are never included.
/// - `dialer-proxy` / `dialer_proxy` keys are stripped from every exported node's `raw_config`
///   to avoid leaking private local relay group names.
/// - Local probe caches (`last_probe_ms`, `last_mbps`, `last_up_mbps`, `last_down_mbps`) are cleared on every exported relay.
pub fn export_share_bundle_zip_bytes(
    req: &ShareBundleExportRequest,
) -> CatResult<(Vec<u8>, ShareBundleManifest)> {
    export_share_bundle_zip_bytes_with_groups(req, None)
}

/// Export selected proxy nodes, domestic pre-acceleration relays, and an optional
/// `catcloud-groups/v1` (`groups.json`) payload into an in-memory `catcloud-share/v1` ZIP archive.
pub fn export_share_bundle_zip_bytes_with_groups(
    req: &ShareBundleExportRequest,
    groups_bundle: Option<&ShareGroupsBundle>,
) -> CatResult<(Vec<u8>, ShareBundleManifest)> {
    if req.nodes.is_empty() && req.relays.is_empty() {
        return Err(CatError::Validation(
            "分享包至少需要包含 1 个节点或 1 条国内中转线路".into(),
        ));
    }
    if req.nodes.len() > MAX_SHARE_NODES {
        return Err(CatError::Validation(format!(
            "节点数量超过单包安全上限（{} > {MAX_SHARE_NODES}）",
            req.nodes.len()
        )));
    }

    let bundle_name = {
        let trimmed = req.name.trim();
        if trimmed.is_empty() {
            "CatCloud Share Bundle".to_string()
        } else {
            trimmed.to_string()
        }
    };
    let description = req
        .description
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);

    let manifest = ShareBundleManifest {
        schema: SHARE_BUNDLE_SCHEMA.to_string(),
        name: bundle_name,
        created_at: Utc::now().to_rfc3339(),
        node_count: req.nodes.len(),
        relay_count: req.relays.len(),
        description,
        sanitized_notice: "已自动剥离原订阅链接、本机路径、控制口密钥、节点 dialer-proxy 及中转测速缓存；包内仍含可用节点/中转凭据，请仅私发给可信对象，切勿公开上传。".to_string(),
    };

    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    let readme_md = render_share_readme(&manifest);
    let nodes_yaml = if req.nodes.is_empty() {
        None
    } else {
        Some(serialize_exported_nodes_yaml(&req.nodes)?)
    };
    let relays_json = if req.relays.is_empty() {
        None
    } else {
        let cleaned_relays: Vec<PreAccelRelay> = req
            .relays
            .iter()
            .cloned()
            .map(|mut r| {
                r.last_probe_ms = None;
                r.last_mbps = None;
                r.last_up_mbps = None;
                r.last_down_mbps = None;
                r
            })
            .collect();
        let mm_bundle = bundle_from_relays(cleaned_relays);
        Some(serialize_mmrelay_json(&mm_bundle)?)
    };
    let groups_json = match groups_bundle {
        Some(gb)
            if !gb.groups.is_empty()
                || gb.active_group_name.is_some()
                || gb.route_mode.is_some() =>
        {
            let mut normalized = gb.clone();
            if normalized.schema.trim().is_empty() {
                normalized.schema = SHARE_GROUPS_SCHEMA.to_string();
            } else if normalized.schema.trim() != SHARE_GROUPS_SCHEMA {
                return Err(CatError::Validation(format!(
                    "不支持的多选组 schema「{}」，仅支持「{SHARE_GROUPS_SCHEMA}」",
                    normalized.schema
                )));
            }
            Some(serde_json::to_string_pretty(&normalized)?)
        }
        _ => None,
    };

    let total_uncompressed = manifest_json.len()
        + readme_md.len()
        + nodes_yaml.as_ref().map_or(0, String::len)
        + relays_json.as_ref().map_or(0, String::len)
        + groups_json.as_ref().map_or(0, String::len);
    if total_uncompressed > MAX_SHARE_ZIP_UNCOMPRESSED_BYTES {
        return Err(CatError::Validation(format!(
            "分享包内容总大小超过 16 MiB 上限（{total_uncompressed} 字节）"
        )));
    }

    let mut cursor = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut cursor);
        let opts = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .unix_permissions(0o644);

        writer
            .start_file("manifest.json", opts)
            .map_err(|e| CatError::Validation(format!("写入 manifest.json 失败：{e}")))?;
        writer.write_all(manifest_json.as_bytes())?;

        writer
            .start_file("README.md", opts)
            .map_err(|e| CatError::Validation(format!("写入 README.md 失败：{e}")))?;
        writer.write_all(readme_md.as_bytes())?;

        if let Some(ref yaml) = nodes_yaml {
            writer
                .start_file("nodes.yaml", opts)
                .map_err(|e| CatError::Validation(format!("写入 nodes.yaml 失败：{e}")))?;
            writer.write_all(yaml.as_bytes())?;
        }

        if let Some(ref relays) = relays_json {
            writer
                .start_file("relays.mmrelay.json", opts)
                .map_err(|e| CatError::Validation(format!("写入 relays.mmrelay.json 失败：{e}")))?;
            writer.write_all(relays.as_bytes())?;
        }

        if let Some(ref groups) = groups_json {
            writer
                .start_file("groups.json", opts)
                .map_err(|e| CatError::Validation(format!("写入 groups.json 失败：{e}")))?;
            writer.write_all(groups.as_bytes())?;
        }

        writer
            .finish()
            .map_err(|e| CatError::Validation(format!("封装分享包 ZIP 失败：{e}")))?;
    }

    Ok((cursor.into_inner(), manifest))
}

/// Atomically write a `catcloud-share/v1` ZIP archive to `target_path`.
pub fn export_share_bundle_zip_file(
    req: &ShareBundleExportRequest,
    target_path: &Path,
) -> CatResult<ShareBundleManifest> {
    export_share_bundle_zip_file_with_groups(req, None, target_path)
}

/// Atomically write a `catcloud-share/v1` ZIP archive (with optional `groups.json`) to `target_path`.
pub fn export_share_bundle_zip_file_with_groups(
    req: &ShareBundleExportRequest,
    groups_bundle: Option<&ShareGroupsBundle>,
    target_path: &Path,
) -> CatResult<ShareBundleManifest> {
    let (bytes, manifest) = export_share_bundle_zip_bytes_with_groups(req, groups_bundle)?;

    if let Some(parent) = target_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let parent_dir = target_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let tmp_path = parent_dir.join(format!(".catcloud-share-{}.tmp", Uuid::new_v4()));

    let write_res = (|| -> CatResult<()> {
        let mut f = File::create(&tmp_path)?;
        f.write_all(&bytes)?;
        f.flush()?;
        Ok(())
    })();
    if let Err(err) = write_res {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err);
    }

    if let Err(_err) = std::fs::rename(&tmp_path, target_path) {
        // Fallback if target file already exists on platforms where rename does not overwrite.
        let _ = std::fs::remove_file(target_path);
        if let Err(err2) = std::fs::rename(&tmp_path, target_path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(CatError::Io(err2));
        }
    }

    Ok(manifest)
}

/// Preview and validate a `catcloud-share/v1` ZIP archive from disk entirely in memory
/// (never extracts any entry onto disk).
pub fn preview_share_bundle_zip_file(zip_path: &Path) -> CatResult<ShareBundlePreview> {
    let meta = std::fs::metadata(zip_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CatError::NotFound(format!("找不到分享包文件：{}", zip_path.display()))
        } else {
            CatError::Io(e)
        }
    })?;
    if !meta.is_file() {
        return Err(CatError::Validation(format!(
            "路径不是有效的 ZIP 文件：{}",
            zip_path.display()
        )));
    }
    if meta.len() > MAX_SHARE_ZIP_FILE_BYTES {
        return Err(CatError::Security(format!(
            "分享包文件过大（{} 字节，超过安全读取上限）",
            meta.len()
        )));
    }

    let file = File::open(zip_path)?;
    let mut raw = Vec::with_capacity(meta.len().min(MAX_SHARE_ZIP_FILE_BYTES) as usize);
    file.take(MAX_SHARE_ZIP_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut raw)?;
    if (raw.len() as u64) > MAX_SHARE_ZIP_FILE_BYTES {
        return Err(CatError::Security(
            "分享包文件体积超过安全上限，已中止读取".into(),
        ));
    }

    preview_share_bundle_zip_bytes(&raw)
}

/// Preview and validate an in-memory `catcloud-share/v1` ZIP archive without writing to disk.
///
/// Enforces strict ZIP security invariants:
/// - Rejects archives with more than `MAX_SHARE_ZIP_ENTRIES` (32) entries.
/// - Validates every entry via `enclosed_name()` and rejects absolute paths, `..`, backslashes,
///   NUL bytes, Windows drive prefixes, and Unix symlinks (`(mode & 0o170000) == 0o120000`).
/// - Measures actual decompressed bytes via `Read::take(remaining + 1)` to defeat spoofed
///   uncompressed-size headers (Zip Bombs) at `MAX_SHARE_ZIP_UNCOMPRESSED_BYTES` (16 MiB).
/// - Caps parsed nodes at `MAX_SHARE_NODES` (4000).
pub fn preview_share_bundle_zip_bytes(bytes: &[u8]) -> CatResult<ShareBundlePreview> {
    if bytes.is_empty() {
        return Err(CatError::Validation("分享包内容为空".into()));
    }

    let mut archive = ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| CatError::Validation(format!("无法解析 ZIP 分享包：{e}")))?;

    if archive.len() > MAX_SHARE_ZIP_ENTRIES {
        return Err(CatError::Security(format!(
            "分享包条目数超限（{} > {MAX_SHARE_ZIP_ENTRIES}），已拒绝解析",
            archive.len()
        )));
    }

    let mut total_uncompressed: usize = 0;
    let mut manifest_bytes: Option<Vec<u8>> = None;
    let mut nodes_bytes: Option<Vec<u8>> = None;
    let mut relays_bytes: Option<Vec<u8>> = None;
    let mut groups_bytes: Option<Vec<u8>> = None;
    let mut has_readme = false;
    let mut warnings: Vec<String> = Vec::new();
    let mut seen_top_dirs: HashSet<String> = HashSet::new();

    for idx in 0..archive.len() {
        let entry = archive
            .by_index(idx)
            .map_err(|e| CatError::Validation(format!("读取分享包条目 #{idx} 失败：{e}")))?;

        let raw_name = entry.name().to_string();
        let unix_mode = entry.unix_mode();
        let is_symlink_entry = entry.is_symlink()
            || unix_mode.is_some_and(|mode| (mode & UNIX_FILE_TYPE_MASK) == UNIX_SYMLINK_MODE);
        if is_symlink_entry {
            return Err(CatError::Security(format!(
                "分享包包含非法符号链接条目「{raw_name}」，已拒绝解析"
            )));
        }

        let clean_rel_parts = validate_safe_zip_entry_path(&raw_name, entry.enclosed_name())?;
        let is_macos_junk = clean_rel_parts
            .first()
            .is_some_and(|first| first == "__MACOSX")
            || clean_rel_parts
                .last()
                .is_some_and(|file| file.starts_with("._"));
        if is_macos_junk {
            continue;
        }
        if entry.is_dir() {
            if let Some(first) = clean_rel_parts.first() {
                seen_top_dirs.insert(first.clone());
            }
            continue;
        }

        let remaining = MAX_SHARE_ZIP_UNCOMPRESSED_BYTES.saturating_sub(total_uncompressed);
        let mut buf = Vec::new();
        entry
            .take((remaining as u64).saturating_add(1))
            .read_to_end(&mut buf)?;
        if buf.len() > remaining {
            return Err(CatError::Security(
                "分享包实际解压大小超过 16 MiB 安全上限（疑似压缩炸弹），已拒绝解析".into(),
            ));
        }
        total_uncompressed = total_uncompressed.saturating_add(buf.len());

        // Accept root-level files or files nested inside a single wrapper directory.
        let file_name_lower = match clean_rel_parts.as_slice() {
            [file] => file.to_ascii_lowercase(),
            [dir, file] => {
                seen_top_dirs.insert(dir.clone());
                if seen_top_dirs.len() > 1 {
                    warnings.push(format!("已忽略额外目录条目：{raw_name}"));
                    continue;
                }
                file.to_ascii_lowercase()
            }
            _ => {
                warnings.push(format!("已忽略非规范嵌套条目：{raw_name}"));
                continue;
            }
        };

        match file_name_lower.as_str() {
            "manifest.json" => {
                if manifest_bytes.is_some() {
                    return Err(CatError::Security(
                        "分享包包含重复的 manifest.json 条目".into(),
                    ));
                }
                manifest_bytes = Some(buf);
            }
            "nodes.yaml" | "nodes.yml" => {
                if nodes_bytes.is_some() {
                    return Err(CatError::Security(
                        "分享包包含重复的 nodes.yaml 条目".into(),
                    ));
                }
                nodes_bytes = Some(buf);
            }
            "relays.mmrelay.json" => {
                if relays_bytes.is_some() {
                    return Err(CatError::Security(
                        "分享包包含重复的 relays.mmrelay.json 条目".into(),
                    ));
                }
                relays_bytes = Some(buf);
            }
            "groups.json" => {
                if groups_bytes.is_some() {
                    return Err(CatError::Security(
                        "分享包包含重复的 groups.json 条目".into(),
                    ));
                }
                groups_bytes = Some(buf);
            }
            "readme.md" => {
                has_readme = true;
            }
            _ => {
                warnings.push(format!("已忽略未识别的附加文件：{raw_name}"));
            }
        }
    }

    let manifest_raw = manifest_bytes.ok_or_else(|| {
        CatError::Validation("分享包缺少必需的 manifest.json 清单文件".into())
    })?;
    let manifest_str = std::str::from_utf8(&manifest_raw).map_err(|_| {
        CatError::Validation("manifest.json 不是有效的 UTF-8 编码".into())
    })?;
    let manifest: ShareBundleManifest = serde_json::from_str(manifest_str).map_err(|e| {
        CatError::Validation(format!("manifest.json 格式无效：{e}"))
    })?;
    if manifest.schema.trim() != SHARE_BUNDLE_SCHEMA {
        return Err(CatError::Validation(format!(
            "不支持的分享包 schema「{}」，仅支持「{SHARE_BUNDLE_SCHEMA}」",
            manifest.schema
        )));
    }

    let mut nodes: Vec<ProxyNode> = Vec::new();
    if let Some(raw_nodes) = nodes_bytes {
        let trimmed = std::str::from_utf8(&raw_nodes)
            .map_err(|_| CatError::Validation("nodes.yaml 不是有效的 UTF-8 文本".into()))?
            .trim();
        if !trimmed.is_empty() {
            let parsed = parse_subscription_payload("share_preview", trimmed.as_bytes(), None)?;
            if parsed.nodes.len() > MAX_SHARE_NODES {
                return Err(CatError::Validation(format!(
                    "分享包内节点数量超过上限（{} > {MAX_SHARE_NODES}）",
                    parsed.nodes.len()
                )));
            }
            nodes = parsed.nodes;
            warnings.extend(parsed.warnings);
        }
    }

    let mut relays: Vec<PreAccelRelay> = Vec::new();
    if let Some(raw_relays) = relays_bytes {
        let trimmed = std::str::from_utf8(&raw_relays)
            .map_err(|_| CatError::Validation("relays.mmrelay.json 不是有效的 UTF-8 文本".into()))?
            .trim();
        if !trimmed.is_empty() {
            let bundle = parse_mmrelay_json(trimmed)?;
            relays = bundle.relays;
        }
    }

    let mut groups_bundle: Option<ShareGroupsBundle> = None;
    if let Some(raw_groups) = groups_bytes {
        let trimmed = std::str::from_utf8(&raw_groups)
            .map_err(|_| CatError::Validation("groups.json 不是有效的 UTF-8 文本".into()))?
            .trim();
        if !trimmed.is_empty() {
            let mut parsed_groups: ShareGroupsBundle =
                serde_json::from_str(trimmed).map_err(|e| {
                    CatError::Validation(format!("groups.json 格式无效：{e}"))
                })?;
            if parsed_groups.schema.trim().is_empty() {
                parsed_groups.schema = SHARE_GROUPS_SCHEMA.to_string();
            } else if parsed_groups.schema.trim() != SHARE_GROUPS_SCHEMA {
                return Err(CatError::Validation(format!(
                    "不支持的多选组 schema「{}」，仅支持「{SHARE_GROUPS_SCHEMA}」",
                    parsed_groups.schema
                )));
            }
            groups_bundle = Some(parsed_groups);
        }
    }

    if nodes.is_empty() && relays.is_empty() {
        return Err(CatError::Validation(
            "分享包中未包含任何可用节点或国内中转线路".into(),
        ));
    }

    if manifest.node_count != nodes.len() {
        warnings.push(format!(
            "清单声明节点数（{}）与实际解析节点数（{}）不一致，已按实际节点数展示",
            manifest.node_count,
            nodes.len()
        ));
    }
    if manifest.relay_count != relays.len() {
        warnings.push(format!(
            "清单声明中转数（{}）与实际解析中转数（{}）不一致，已按实际中转数展示",
            manifest.relay_count,
            relays.len()
        ));
    }

    Ok(ShareBundlePreview {
        manifest,
        nodes,
        relays,
        warnings,
        has_readme,
        groups_bundle,
    })
}

/// Merge imported `catcloud-groups/v1` smart multi-groups into local SQLite storage:
/// - Maps `member_fingerprints` and `active_node_fingerprint` to persisted local node IDs via
///   `node_dedup_fingerprint`, silently dropping fingerprints that were not imported.
/// - Skips groups that end up with zero resolved members and no `dynamic_filter`, recording a warning.
/// - For same-name existing groups, performs an additive union of member node IDs while preserving
///   local group mode, scoring policy, and valid local `active_node_id`.
/// - Resolves `fallback_pool_name` against existing and newly imported groups by name (falls back
///   to `None` when unresolved or self-referential).
pub fn merge_imported_groups_into_storage(
    db: &Storage,
    groups_bundle: &ShareGroupsBundle,
) -> CatResult<(usize, Vec<String>)> {
    let mut warnings = Vec::new();
    if groups_bundle.groups.is_empty() {
        return Ok((0, warnings));
    }

    let nodes = db.list_nodes()?;
    let mut fp_to_node_id: HashMap<String, String> = HashMap::with_capacity(nodes.len());
    let mut fp_enabled: HashMap<String, bool> = HashMap::with_capacity(nodes.len());
    let mut existing_node_ids: HashSet<String> = HashSet::with_capacity(nodes.len());
    for node in &nodes {
        existing_node_ids.insert(node.id.clone());
        let fp = node_dedup_fingerprint(node);
        let replace = match fp_enabled.get(&fp) {
            None => true,
            Some(&prev_enabled) => !prev_enabled && node.enabled,
        };
        if replace {
            fp_enabled.insert(fp.clone(), node.enabled);
            fp_to_node_id.insert(fp, node.id.clone());
        }
    }

    let existing_groups = db.list_multi_groups()?;
    let mut working_by_name: HashMap<String, MultiGroup> =
        HashMap::with_capacity(existing_groups.len() + groups_bundle.groups.len());
    let mut group_name_to_id: HashMap<String, String> =
        HashMap::with_capacity(existing_groups.len() + groups_bundle.groups.len());
    let mut used_ids: HashSet<String> = HashSet::with_capacity(existing_groups.len());
    let mut existed_in_db: HashSet<String> = HashSet::with_capacity(existing_groups.len());

    for grp in existing_groups {
        let key = grp.name.trim().to_string();
        used_ids.insert(grp.id.clone());
        if !key.is_empty() {
            group_name_to_id.entry(key.clone()).or_insert_with(|| grp.id.clone());
            existed_in_db.insert(key.clone());
            working_by_name.entry(key).or_insert(grp);
        }
    }

    struct PreparedGroup<'a> {
        name: String,
        target_id: String,
        record: &'a ShareGroupRecord,
        mapped_member_ids: Vec<String>,
        mapped_active_node_id: Option<String>,
    }

    let mut prepared: Vec<PreparedGroup<'_>> = Vec::with_capacity(groups_bundle.groups.len());
    for rec in &groups_bundle.groups {
        let trimmed_name = rec.name.trim();
        if trimmed_name.is_empty() {
            warnings.push("已跳过未命名的多选组记录".to_string());
            continue;
        }

        let mut seen_members = HashSet::new();
        let mapped_member_ids: Vec<String> = rec
            .member_fingerprints
            .iter()
            .filter_map(|fp| fp_to_node_id.get(fp.trim()).cloned())
            .filter(|nid| seen_members.insert(nid.clone()))
            .collect();

        if mapped_member_ids.is_empty() && rec.dynamic_filter.is_none() {
            warnings.push(format!(
                "已跳过多选组「{trimmed_name}」：无已入库成员节点且未配置动态筛选规则"
            ));
            continue;
        }

        let mapped_active_node_id = rec
            .active_node_fingerprint
            .as_deref()
            .and_then(|fp| fp_to_node_id.get(fp.trim()).cloned())
            .filter(|nid| rec.dynamic_filter.is_some() || mapped_member_ids.contains(nid));

        let target_id = if let Some(existing_id) = group_name_to_id.get(trimmed_name) {
            existing_id.clone()
        } else {
            let mut candidate = format!(
                "grp-sync-{}",
                &Uuid::new_v4().simple().to_string()[..12]
            );
            while !used_ids.insert(candidate.clone()) {
                candidate = format!(
                    "grp-sync-{}",
                    &Uuid::new_v4().simple().to_string()[..12]
                );
            }
            group_name_to_id.insert(trimmed_name.to_string(), candidate.clone());
            candidate
        };

        prepared.push(PreparedGroup {
            name: trimmed_name.to_string(),
            target_id,
            record: rec,
            mapped_member_ids,
            mapped_active_node_id,
        });
    }

    let mut dirty_order: Vec<String> = Vec::new();
    let mut dirty_seen: HashSet<String> = HashSet::new();

    for item in prepared {
        if let Some(existing) = working_by_name.get_mut(&item.name) {
            // Same-name group: union member node IDs while preserving local mode, policy,
            // and valid local active_node_id.
            let mut member_set: HashSet<String> = existing.member_node_ids.iter().cloned().collect();
            for nid in item.mapped_member_ids {
                if member_set.insert(nid.clone()) {
                    existing.member_node_ids.push(nid);
                }
            }
            let local_active_valid = existing.active_node_id.as_deref().is_some_and(|aid| {
                existing_node_ids.contains(aid)
                    && (existing.dynamic_filter.is_some()
                        || existing.member_node_ids.is_empty()
                        || existing.member_node_ids.iter().any(|m| m == aid))
            });
            if !local_active_valid {
                existing.active_node_id = item.mapped_active_node_id;
            }
            // Only fill fallback_pool_id on a freshly-created same-turn duplicate; never overwrite
            // an already-persisted local group's customized settings.
            if !existed_in_db.contains(&item.name) && existing.fallback_pool_id.is_none() {
                existing.fallback_pool_id = item
                    .record
                    .fallback_pool_name
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .and_then(|pname| group_name_to_id.get(pname).cloned())
                    .filter(|pid| pid != &existing.id);
            }
        } else {
            let fallback_pool_id = item
                .record
                .fallback_pool_name
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .and_then(|pname| group_name_to_id.get(pname).cloned())
                .filter(|pid| pid != &item.target_id);
            let formula_expr = if item.record.formula_expr.trim().is_empty() {
                DEFAULT_COST_EFFECTIVE_FORMULA.to_string()
            } else {
                item.record.formula_expr.clone()
            };
            let recover_probe_interval_sec = if item.record.recover_probe_interval_sec == 0 {
                120
            } else {
                item.record.recover_probe_interval_sec
            };

            let new_group = MultiGroup {
                id: item.target_id,
                name: item.name.clone(),
                mode: item.record.mode.clone(),
                match_rules: item.record.match_rules.clone(),
                member_node_ids: item.mapped_member_ids,
                dynamic_filter: item.record.dynamic_filter.clone(),
                primary_probe_id: item.record.primary_probe_id.clone(),
                hard_gates: item.record.hard_gates.clone(),
                trigger_rules: item.record.trigger_rules.clone(),
                formula_expr,
                fallback_policy: item.record.fallback_policy.clone(),
                fallback_pool_id,
                escalated_since: None,
                recover_probe_interval_sec,
                switch_mode: item.record.switch_mode.clone(),
                cooldown_sec: item.record.cooldown_sec,
                hysteresis_pct: item.record.hysteresis_pct,
                active_node_id: item.mapped_active_node_id,
                state: MultiGroupState::Idle,
                independent_routing: item.record.independent_routing,
            };
            working_by_name.insert(item.name.clone(), new_group);
        }

        if dirty_seen.insert(item.name.clone()) {
            dirty_order.push(item.name);
        }
    }

    let mut saved_count = 0usize;
    for name in &dirty_order {
        if let Some(grp) = working_by_name.get(name) {
            db.upsert_multi_group(grp)?;
            saved_count += 1;
        }
    }

    Ok((saved_count, warnings))
}

fn validate_safe_zip_entry_path(
    raw_name: &str,
    enclosed: Option<std::path::PathBuf>,
) -> CatResult<Vec<String>> {
    if raw_name.is_empty()
        || raw_name.contains('\0')
        || raw_name.contains('\\')
        || raw_name.starts_with('/')
        || raw_name.as_bytes().get(1) == Some(&b':')
    {
        return Err(CatError::Security(format!(
            "检测到非法分享包路径「{raw_name}」，已拒绝解析"
        )));
    }

    let Some(path) = enclosed else {
        return Err(CatError::Security(format!(
            "分享包路径「{raw_name}」未通过 enclosed_name 安全校验（疑似 Zip Slip）"
        )));
    };

    let mut parts = Vec::new();
    for comp in path.components() {
        match comp {
            Component::Normal(seg) => {
                let s = seg.to_string_lossy().into_owned();
                if s.is_empty() || s == "." || s == ".." {
                    return Err(CatError::Security(format!(
                        "分享包路径包含非法片段「{raw_name}」"
                    )));
                }
                parts.push(s);
            }
            _ => {
                return Err(CatError::Security(format!(
                    "分享包路径包含越权组件「{raw_name}」（疑似 Zip Slip）"
                )));
            }
        }
    }

    if parts.is_empty() {
        return Err(CatError::Security(format!(
            "分享包路径为空或非法：「{raw_name}」"
        )));
    }
    Ok(parts)
}

fn serialize_exported_nodes_yaml(nodes: &[ProxyNode]) -> CatResult<String> {
    let mut used_names: HashSet<String> = HashSet::with_capacity(nodes.len());
    let mut proxies_seq: Vec<Value> = Vec::with_capacity(nodes.len());

    for (idx, node) in nodes.iter().enumerate() {
        let base_name = {
            let trimmed = node.name.trim();
            if !trimmed.is_empty() {
                trimmed.to_string()
            } else if !node.id.trim().is_empty() {
                format!("Node-{}", node.id.trim())
            } else {
                format!("Node-{}", idx + 1)
            }
        };
        let unique_name = make_unique_proxy_name(&base_name, &mut used_names);
        let proxy_map = build_sanitized_export_proxy_mapping(node, &unique_name)?;
        proxies_seq.push(Value::Mapping(proxy_map));
    }

    let mut root = Mapping::new();
    root.insert(
        Value::String("proxies".to_string()),
        Value::Sequence(proxies_seq),
    );
    Ok(serde_yaml_ng::to_string(&Value::Mapping(root))?)
}

fn build_sanitized_export_proxy_mapping(
    node: &ProxyNode,
    unique_name: &str,
) -> CatResult<Mapping> {
    let mut map = match serde_yaml_ng::to_value(&node.raw_config)? {
        Value::Mapping(m) => m,
        _ => Mapping::new(),
    };

    // Always strip private local relay bindings before exporting.
    map.shift_remove("dialer-proxy");
    map.shift_remove("dialer_proxy");

    map.insert(
        Value::String("name".to_string()),
        Value::String(unique_name.to_string()),
    );
    let proto = normalize_protocol(&node.protocol);
    if !proto.is_empty() {
        map.insert(Value::String("type".to_string()), Value::String(proto));
    }
    if !node.server.trim().is_empty() {
        map.insert(
            Value::String("server".to_string()),
            Value::String(node.server.trim().to_string()),
        );
    }
    if node.port > 0 {
        map.insert(
            Value::String("port".to_string()),
            Value::Number(Number::from(u64::from(node.port))),
        );
    }

    Ok(map)
}

fn make_unique_proxy_name(base: &str, used: &mut HashSet<String>) -> String {
    if used.insert(base.to_string()) {
        return base.to_string();
    }
    let mut suffix = 2usize;
    loop {
        let candidate = format!("{base} #{suffix}");
        if used.insert(candidate.clone()) {
            return candidate;
        }
        suffix += 1;
    }
}

fn render_share_readme(manifest: &ShareBundleManifest) -> String {
    let desc_line_zh = manifest
        .description
        .as_deref()
        .map(|d| format!("- 简介：{d}\n"))
        .unwrap_or_default();
    let desc_line_en = manifest
        .description
        .as_deref()
        .map(|d| format!("- Description: {d}\n"))
        .unwrap_or_default();

    format!(
        "# CatCloud 分享包 / CatCloud Share Bundle ({schema})\n\n\
## 概览 / Overview\n\
- 名称 / Name: {name}\n\
- 创建时间 / Created At: {created_at}\n\
- 代理节点 / Proxy Nodes: {node_count}\n\
- 国内中转线路 / Domestic Relays: {relay_count}\n\
{desc_line_zh}{desc_line_en}\n\
## 一键导入猫猫云梯 / One-Click Import into CatCloud\n\
1. **桌面端图形界面（推荐）**：打开猫猫云梯 → 进入「订阅与导入」或「国内提速」页面 → 点击「导入分享包」，选择本 `.zip` 文件即可先预览再勾选导入（支持新建分组或更新已有分组）。\n\
2. **命令行 / 本机 AI Agent 导入**：\n\
```bash\n\
catcloud share import <file.zip> --json\n\
```\n\
3. **Desktop UI / CLI (English)**: Open CatCloud -> *Subscriptions* or *Domestic Boost* -> *Import Share Bundle*, select this `.zip` to preview and import selectively, or run `catcloud share import <file.zip> --json`.\n\n\
## 包内文件说明 / Bundle Contents\n\
- `manifest.json`: 分享包清单与版本标识 (`catcloud-share/v1`)。\n\
- `nodes.yaml`: 标准 Clash/Mihomo `proxies:` 格式节点（若有节点，导出前已自动剥离 `dialer-proxy`）。\n\
- `relays.mmrelay.json`: 标准 `mmrelay/v1` 国内提速中转配置（若有中转，已清理本机测速缓存）。\n\
- `README.md`: 本说明文件。\n\n\
## ⚠️ 安全与 AI Agent 红线 / Privacy & AI Agent Security Red Line\n\
- **仅限私发**：本分享包已剥离原订阅 URL、本机路径与控制口密钥，但仍包含可连接的节点/中转凭据，请仅私发给可信好友，**切勿公开上传到网盘、论坛或 GitHub**。\n\
- **AI Agent 安全铁律（CRITICAL FOR AI AGENTS）**：**严禁复述明文密码/UUID/中转 IP**！读取或导入本压缩包时，请直接将文件路径传给 `catcloud share import <file.zip> --json`，仅向用户汇报节点数量、地区分布与导入结果，**NEVER echo plaintext passwords, UUIDs, or relay IP addresses in chat, summaries, or logs**。\n",
        schema = manifest.schema,
        name = manifest.name,
        created_at = manifest.created_at,
        node_count = manifest.node_count,
        relay_count = manifest.relay_count,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_node_with_dialer(id: &str, name: &str, server: &str, uuid: &str) -> ProxyNode {
        ProxyNode {
            id: id.to_string(),
            sub_id: "sub-private-origin".to_string(),
            name: name.to_string(),
            protocol: "vless".to_string(),
            server: server.to_string(),
            port: 443,
            raw_config: serde_json::json!({
                "name": name,
                "type": "vless",
                "server": server,
                "port": 443,
                "uuid": uuid,
                "tls": true,
                "servername": "edge.example.invalid",
                "dialer-proxy": "⚡ 私有中转入口",
                "dialer_proxy": "legacy-private-relay"
            }),
            region_code: "JP".to_string(),
            multiplier: 0.5,
            is_443_native: true,
            preaccel_eligible: true,
            preaccel_override: None,
            tags: vec!["ai".to_string()],
            enabled: true,
        }
    }

    fn sample_relay_with_metrics() -> PreAccelRelay {
        PreAccelRelay {
            id: "relay-demo-1".to_string(),
            name: "Domestic-Edge-443".to_string(),
            provider: "tencent".to_string(),
            region: "CN-GZ".to_string(),
            server: "198.51.100.10".to_string(),
            port: 443,
            protocol: "anytls".to_string(),
            password: "placeholder-relay-pass".to_string(),
            sni: None,
            skip_cert_verify: true,
            priority: 10,
            expires_at: Some("2027-06-01T00:00:00Z".to_string()),
            enabled: true,
            last_probe_ms: Some(14.5),
            last_mbps: Some(180.0),
            last_up_mbps: Some(125.0),
            last_down_mbps: Some(180.0),
        }
    }

    #[test]
    fn export_and_preview_roundtrip_strips_dialer_proxy_and_relay_metrics_and_includes_readme() {
        let req = ShareBundleExportRequest {
            name: "Campus Starter Pack".to_string(),
            description: Some("2 nodes + 1 domestic relay".to_string()),
            nodes: vec![
                sample_node_with_dialer(
                    "n1",
                    "🇯🇵 东京 0.5x",
                    "203.0.113.10",
                    "00000000-0000-4000-8000-000000000001",
                ),
                sample_node_with_dialer(
                    "n2",
                    "🇯🇵 东京 0.5x", // duplicate display name must deduplicate cleanly in YAML
                    "203.0.113.11",
                    "00000000-0000-4000-8000-000000000002",
                ),
            ],
            relays: vec![sample_relay_with_metrics()],
        };

        let (zip_bytes, manifest) =
            export_share_bundle_zip_bytes(&req).expect("export bundle bytes");
        assert_eq!(manifest.schema, SHARE_BUNDLE_SCHEMA);
        assert_eq!(manifest.node_count, 2);
        assert_eq!(manifest.relay_count, 1);

        // Verify raw ZIP entries contain README with agent red line and nodes.yaml has zero dialer-proxy.
        {
            let mut archive = ZipArchive::new(Cursor::new(&zip_bytes)).unwrap();
            let mut readme = String::new();
            archive
                .by_name("README.md")
                .unwrap()
                .read_to_string(&mut readme)
                .unwrap();
            assert!(readme.contains("catcloud share import <file.zip> --json"));
            assert!(readme.contains("严禁复述明文密码/UUID/中转 IP"));
            assert!(readme.contains("*Domestic Boost*"));
            assert!(readme.contains("国内提速中转配置"));
            assert!(!readme.contains("国内预加速"));

            let mut nodes_yaml = String::new();
            archive
                .by_name("nodes.yaml")
                .unwrap()
                .read_to_string(&mut nodes_yaml)
                .unwrap();
            assert!(!nodes_yaml.contains("dialer-proxy"));
            assert!(!nodes_yaml.contains("dialer_proxy"));
            assert!(!nodes_yaml.contains("私有中转入口"));
        }

        // Roundtrip through on-disk file helper and in-memory preview.
        let dir = std::env::temp_dir().join(format!("catcloud-share-test-{}", Uuid::new_v4()));
        let zip_path = dir.join("starter.zip");
        let file_manifest =
            export_share_bundle_zip_file(&req, &zip_path).expect("export bundle file");
        assert_eq!(file_manifest.schema, SHARE_BUNDLE_SCHEMA);

        let preview = preview_share_bundle_zip_file(&zip_path).expect("preview bundle file");
        assert!(preview.has_readme);
        assert_eq!(preview.manifest.name, "Campus Starter Pack");
        assert_eq!(preview.nodes.len(), 2);
        assert_eq!(preview.nodes[0].name, "🇯🇵 东京 0.5x");
        assert_eq!(preview.nodes[1].name, "🇯🇵 东京 0.5x #2");
        assert!(preview.nodes[0].raw_config.get("dialer-proxy").is_none());
        assert!(preview.nodes[0].raw_config.get("dialer_proxy").is_none());
        assert_eq!(preview.relays.len(), 1);
        assert_eq!(preview.relays[0].server, "198.51.100.10");
        assert_eq!(preview.relays[0].last_probe_ms, None);
        assert_eq!(preview.relays[0].last_mbps, None);
        assert_eq!(preview.relays[0].last_up_mbps, None);
        assert_eq!(preview.relays[0].last_down_mbps, None);
        assert!(preview.warnings.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn preview_rejects_zip_slip_backslashes_absolute_paths_and_unix_symlinks() {
        let make_custom_zip = |name: &str, mode: Option<u32>, body: &[u8]| -> Vec<u8> {
            let mut cursor = Cursor::new(Vec::new());
            {
                let mut zw = ZipWriter::new(&mut cursor);
                let mut opts = SimpleFileOptions::default()
                    .compression_method(CompressionMethod::Stored);
                if let Some(m) = mode {
                    opts = opts.unix_permissions(m);
                }
                zw.start_file(name, opts).unwrap();
                zw.write_all(body).unwrap();
                zw.finish().unwrap();
            }
            cursor.into_inner()
        };

        for evil_name in [
            "../escape.yaml",
            "nested/../../escape.yaml",
            "/etc/passwd",
            "C:/Windows/evil.yaml",
            "sub\\evil.yaml",
        ] {
            let z = make_custom_zip(evil_name, Some(0o644), b"x");
            let err = preview_share_bundle_zip_bytes(&z)
                .expect_err(&format!("must reject Zip Slip entry `{evil_name}`"));
            assert!(
                matches!(err, CatError::Security(_)),
                "expected CatError::Security for `{evil_name}`, got {err:?}"
            );
        }

        // Unix symlink entry (`0o120777`) must be rejected.
        let symlink_zip = {
            let mut cursor = Cursor::new(Vec::new());
            {
                let mut zw = ZipWriter::new(&mut cursor);
                let opts = SimpleFileOptions::default()
                    .compression_method(CompressionMethod::Stored)
                    .unix_permissions(0o777);
                zw.add_symlink("nodes.yaml", "/etc/hosts", opts).unwrap();
                zw.finish().unwrap();
            }
            cursor.into_inner()
        };
        let sym_err =
            preview_share_bundle_zip_bytes(&symlink_zip).expect_err("must reject Unix symlink");
        assert!(
            matches!(sym_err, CatError::Security(_)),
            "expected CatError::Security for symlink, got {sym_err:?}"
        );
    }

    #[test]
    fn preview_rejects_zip_bomb_entry_limit_and_node_limit() {
        // 1. Zip Bomb: highly compressible stream exceeding 16 MiB uncompressed bytes.
        let bomb_zip = {
            let mut cursor = Cursor::new(Vec::new());
            {
                let mut zw = ZipWriter::new(&mut cursor);
                let opts = SimpleFileOptions::default()
                    .compression_method(CompressionMethod::Deflated);
                zw.start_file("manifest.json", opts).unwrap();
                zw.write_all(
                    br#"{"schema":"catcloud-share/v1","name":"bomb","created_at":"2026-11-25T00:00:00Z","node_count":0,"relay_count":0,"description":null,"sanitized_notice":""}"#,
                )
                .unwrap();
                zw.start_file("nodes.yaml", opts).unwrap();
                let chunk = vec![b'A'; 64 * 1024];
                let mut written = 0usize;
                while written <= MAX_SHARE_ZIP_UNCOMPRESSED_BYTES {
                    zw.write_all(&chunk).unwrap();
                    written += chunk.len();
                }
                zw.finish().unwrap();
            }
            cursor.into_inner()
        };
        assert!(
            bomb_zip.len() < 256 * 1024,
            "compressed bomb should be tiny to prove streaming Read::take defense"
        );
        let bomb_err =
            preview_share_bundle_zip_bytes(&bomb_zip).expect_err("must reject >16 MiB zip bomb");
        assert!(
            matches!(bomb_err, CatError::Security(_)),
            "expected CatError::Security for zip bomb, got {bomb_err:?}"
        );

        // 2. Entry count limit (> 32 entries).
        let too_many_entries_zip = {
            let mut cursor = Cursor::new(Vec::new());
            {
                let mut zw = ZipWriter::new(&mut cursor);
                let opts = SimpleFileOptions::default()
                    .compression_method(CompressionMethod::Stored);
                for i in 0..=MAX_SHARE_ZIP_ENTRIES {
                    zw.start_file(format!("file_{i:02}.txt"), opts).unwrap();
                    zw.write_all(b"ok").unwrap();
                }
                zw.finish().unwrap();
            }
            cursor.into_inner()
        };
        let entries_err = preview_share_bundle_zip_bytes(&too_many_entries_zip)
            .expect_err("must reject >32 ZIP entries");
        assert!(matches!(entries_err, CatError::Security(_)));

        // 3. Node count limit (> 4000 nodes) rejected on both export and preview.
        let too_many_nodes: Vec<ProxyNode> = (0..=MAX_SHARE_NODES)
            .map(|i| {
                sample_node_with_dialer(
                    &format!("n-{i}"),
                    &format!("JP-{i}"),
                    "192.0.2.10",
                    &format!("00000000-0000-4000-8000-{i:012}"),
                )
            })
            .collect();
        let req_over_limit = ShareBundleExportRequest {
            name: "Too Many".to_string(),
            description: None,
            nodes: too_many_nodes,
            relays: Vec::new(),
        };
        assert!(export_share_bundle_zip_bytes(&req_over_limit).is_err());

        // Hand-crafted ZIP containing > 4000 nodes must also be rejected on preview.
        let over_limit_preview_zip = {
            let mut yaml = String::from("proxies:\n");
            for i in 0..=MAX_SHARE_NODES {
                yaml.push_str(&format!(
                    "  - {{name: \"N{i}\", type: trojan, server: \"192.0.2.10\", port: 443, password: \"p{i}\"}}\n"
                ));
            }
            let mut cursor = Cursor::new(Vec::new());
            {
                let mut zw = ZipWriter::new(&mut cursor);
                let opts = SimpleFileOptions::default()
                    .compression_method(CompressionMethod::Deflated);
                zw.start_file("manifest.json", opts).unwrap();
                zw.write_all(
                    br#"{"schema":"catcloud-share/v1","name":"over","created_at":"2026-11-25T00:00:00Z","node_count":4001,"relay_count":0,"description":null,"sanitized_notice":""}"#,
                )
                .unwrap();
                zw.start_file("nodes.yaml", opts).unwrap();
                zw.write_all(yaml.as_bytes()).unwrap();
                zw.finish().unwrap();
            }
            cursor.into_inner()
        };
        assert!(preview_share_bundle_zip_bytes(&over_limit_preview_zip).is_err());

        // Path containing NUL byte must be rejected by validator directly.
        assert!(matches!(
            validate_safe_zip_entry_path("nodes\0.yaml", Some(std::path::PathBuf::from("nodes.yaml"))),
            Err(CatError::Security(_))
        ));

        // Empty bundle request must also be rejected.
        let empty_req = ShareBundleExportRequest {
            name: "Empty".to_string(),
            description: None,
            nodes: Vec::new(),
            relays: Vec::new(),
        };
        assert!(export_share_bundle_zip_bytes(&empty_req).is_err());
    }

    #[test]
    fn preview_skips_macos_macosx_and_appledouble_entries_without_polluting_top_dirs() {
        let req = ShareBundleExportRequest {
            name: "macOS Repacked Bundle".to_string(),
            description: Some("Includes Finder __MACOSX metadata".to_string()),
            nodes: vec![sample_node_with_dialer(
                "n-mac-1",
                "🇯🇵 東京 1x",
                "203.0.113.55",
                "00000000-0000-4000-8000-000000000055",
            )],
            relays: vec![sample_relay_with_metrics()],
        };
        let (clean_zip_bytes, _) =
            export_share_bundle_zip_bytes(&req).expect("export base bundle");

        // Extract clean files and repack inside a single wrapper directory alongside
        // macOS Finder's `__MACOSX/` folder and `._*` AppleDouble sidecar entries.
        let mut base_archive = ZipArchive::new(Cursor::new(&clean_zip_bytes)).unwrap();
        let mut files: Vec<(String, Vec<u8>)> = Vec::new();
        for i in 0..base_archive.len() {
            let mut f = base_archive.by_index(i).unwrap();
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).unwrap();
            files.push((f.name().to_string(), buf));
        }

        let mac_zip = {
            let mut cursor = Cursor::new(Vec::new());
            {
                let mut zw = ZipWriter::new(&mut cursor);
                let opts = SimpleFileOptions::default()
                    .compression_method(CompressionMethod::Deflated)
                    .unix_permissions(0o644);
                let dir_opts = SimpleFileOptions::default()
                    .compression_method(CompressionMethod::Stored)
                    .unix_permissions(0o755);

                // macOS metadata directory & AppleDouble files placed FIRST to ensure they
                // do not occupy `seen_top_dirs` before the real bundle wrapper directory.
                zw.add_directory("__MACOSX/", dir_opts).unwrap();
                zw.add_directory("__MACOSX/friend-pack/", dir_opts).unwrap();
                zw.start_file("__MACOSX/friend-pack/._manifest.json", opts)
                    .unwrap();
                zw.write_all(&[0x00, 0x05, 0x16, 0x07, 0x00, 0x02]).unwrap();

                zw.add_directory("friend-pack/", dir_opts).unwrap();
                zw.start_file("friend-pack/._nodes.yaml", opts).unwrap();
                zw.write_all(&[0x00, 0x05, 0x16, 0x07, 0x00, 0x02]).unwrap();
                zw.start_file("._root_appledouble", opts).unwrap();
                zw.write_all(&[0x00, 0x05, 0x16, 0x07]).unwrap();

                for (name, body) in &files {
                    zw.start_file(format!("friend-pack/{name}"), opts).unwrap();
                    zw.write_all(body).unwrap();
                }
                zw.finish().unwrap();
            }
            cursor.into_inner()
        };

        let preview =
            preview_share_bundle_zip_bytes(&mac_zip).expect("macOS ZIP should preview cleanly");
        assert!(preview.has_readme);
        assert_eq!(preview.manifest.name, "macOS Repacked Bundle");
        assert_eq!(preview.nodes.len(), 1);
        assert_eq!(preview.relays.len(), 1);
        assert!(
            preview.warnings.is_empty(),
            "unexpected warnings: {:?}",
            preview.warnings
        );
        assert!(preview.groups_bundle.is_none());
    }

    #[test]
    fn groups_json_roundtrip_duplicate_rejection_and_uncompressed_limit() {
        let n1 = sample_node_with_dialer(
            "n-grp-1",
            "JP-01",
            "203.0.113.21",
            "00000000-0000-4000-8000-000000000021",
        );
        let n2 = sample_node_with_dialer(
            "n-grp-2",
            "SG-01",
            "203.0.113.22",
            "00000000-0000-4000-8000-000000000022",
        );
        let fp1 = node_dedup_fingerprint(&n1);
        let fp2 = node_dedup_fingerprint(&n2);

        let groups_bundle = ShareGroupsBundle {
            schema: SHARE_GROUPS_SCHEMA.to_string(),
            active_group_name: Some("AI Sticky".to_string()),
            route_mode: Some("group".to_string()),
            groups: vec![ShareGroupRecord {
                name: "AI Sticky".to_string(),
                mode: MultiGroupMode::StickyBest,
                match_rules: vec!["DOMAIN-SUFFIX,openai.com".to_string()],
                member_fingerprints: vec![fp1.clone(), fp2.clone()],
                fallback_policy: FallbackPolicy::CrossPoolEscalate,
                fallback_pool_name: Some("Backup Pool".to_string()),
                active_node_fingerprint: Some(fp1.clone()),
                independent_routing: true,
                ..ShareGroupRecord::default()
            }],
        };

        let req = ShareBundleExportRequest {
            name: "With Groups".to_string(),
            description: Some("Nodes + Groups".to_string()),
            nodes: vec![n1, n2],
            relays: Vec::new(),
        };
        let (zip_bytes, _) =
            export_share_bundle_zip_bytes_with_groups(&req, Some(&groups_bundle))
                .expect("export with groups");
        let preview =
            preview_share_bundle_zip_bytes(&zip_bytes).expect("preview with groups");
        let parsed_groups = preview
            .groups_bundle
            .expect("groups_bundle must be parsed");
        assert_eq!(parsed_groups.schema, SHARE_GROUPS_SCHEMA);
        assert_eq!(parsed_groups.active_group_name.as_deref(), Some("AI Sticky"));
        assert_eq!(parsed_groups.route_mode.as_deref(), Some("group"));
        assert_eq!(parsed_groups.groups.len(), 1);
        assert_eq!(parsed_groups.groups[0].member_fingerprints, vec![fp1, fp2]);
        assert!(parsed_groups.groups[0].independent_routing);

        // Duplicate `groups.json` must be rejected with CatError::Security.
        let dup_zip = {
            let mut cursor = Cursor::new(Vec::new());
            {
                let mut zw = ZipWriter::new(&mut cursor);
                let opts = SimpleFileOptions::default()
                    .compression_method(CompressionMethod::Deflated);
                zw.start_file("manifest.json", opts).unwrap();
                zw.write_all(
                    br#"{"schema":"catcloud-share/v1","name":"dup","created_at":"2026-11-25T00:00:00Z","node_count":0,"relay_count":0,"description":null,"sanitized_notice":""}"#,
                )
                .unwrap();
                zw.start_file("groups.json", opts).unwrap();
                zw.write_all(br#"{"schema":"catcloud-groups/v1","groups":[]}"#)
                    .unwrap();
                zw.start_file("wrap/groups.json", opts).unwrap();
                zw.write_all(br#"{"schema":"catcloud-groups/v1","groups":[]}"#)
                    .unwrap();
                zw.finish().unwrap();
            }
            cursor.into_inner()
        };
        let dup_err =
            preview_share_bundle_zip_bytes(&dup_zip).expect_err("duplicate groups.json must fail");
        assert!(matches!(dup_err, CatError::Security(_)));

        // Oversized `groups.json` exceeding 16 MiB uncompressed limit must be rejected with Security.
        let huge_groups_zip = {
            let mut cursor = Cursor::new(Vec::new());
            {
                let mut zw = ZipWriter::new(&mut cursor);
                let opts = SimpleFileOptions::default()
                    .compression_method(CompressionMethod::Deflated);
                zw.start_file("manifest.json", opts).unwrap();
                zw.write_all(
                    br#"{"schema":"catcloud-share/v1","name":"huge","created_at":"2026-11-25T00:00:00Z","node_count":0,"relay_count":0,"description":null,"sanitized_notice":""}"#,
                )
                .unwrap();
                zw.start_file("groups.json", opts).unwrap();
                let chunk = vec![b' '; 64 * 1024];
                let mut written = 0usize;
                while written <= MAX_SHARE_ZIP_UNCOMPRESSED_BYTES {
                    zw.write_all(&chunk).unwrap();
                    written += chunk.len();
                }
                zw.finish().unwrap();
            }
            cursor.into_inner()
        };
        let huge_err = preview_share_bundle_zip_bytes(&huge_groups_zip)
            .expect_err("oversized groups.json must fail");
        assert!(matches!(huge_err, CatError::Security(_)));
    }

    #[test]
    fn merge_imported_groups_handles_union_local_preservation_dynamic_filter_and_fallback_pool() {
        use crate::models::{SubscriptionKind, SubscriptionRecord};

        let db = Storage::open_in_memory().expect("in-memory db");
        db.upsert_subscription(&SubscriptionRecord {
            id: "sub-local".to_string(),
            name: "Local".to_string(),
            kind: SubscriptionKind::File,
            url_or_cmd: "local.yaml".to_string(),
            ..Default::default()
        })
        .unwrap();

        let mut n1 = sample_node_with_dialer(
            "local-n1",
            "JP-01",
            "203.0.113.31",
            "00000000-0000-4000-8000-000000000031",
        );
        n1.sub_id = "sub-local".to_string();
        let mut n2 = sample_node_with_dialer(
            "local-n2",
            "SG-01",
            "203.0.113.32",
            "00000000-0000-4000-8000-000000000032",
        );
        n2.sub_id = "sub-local".to_string();
        let mut n3 = sample_node_with_dialer(
            "local-n3",
            "TW-01",
            "203.0.113.33",
            "00000000-0000-4000-8000-000000000033",
        );
        n3.sub_id = "sub-local".to_string();

        db.upsert_node(&n1).unwrap();
        db.upsert_node(&n2).unwrap();
        db.upsert_node(&n3).unwrap();

        let fp1 = node_dedup_fingerprint(&n1);
        let fp2 = node_dedup_fingerprint(&n2);
        let fp3 = node_dedup_fingerprint(&n3);

        // Pre-existing local group with customized mode & active_node_id that must be preserved.
        db.upsert_multi_group(&MultiGroup {
            id: "grp-local-ai".to_string(),
            name: "AI Sticky".to_string(),
            mode: MultiGroupMode::LoadBalanceConsistentHash,
            member_node_ids: vec!["local-n1".to_string()],
            formula_expr: "up_mbps * 50".to_string(),
            active_node_id: Some("local-n1".to_string()),
            ..MultiGroup::default()
        })
        .unwrap();

        let incoming = ShareGroupsBundle {
            schema: SHARE_GROUPS_SCHEMA.to_string(),
            active_group_name: Some("AI Sticky".to_string()),
            route_mode: Some("group".to_string()),
            groups: vec![
                // 1. Same-name existing group: should union local-n2, silently drop unknown fp,
                //    keep local-n1 active and keep local mode/formula.
                ShareGroupRecord {
                    name: "AI Sticky".to_string(),
                    mode: MultiGroupMode::StickyBest,
                    member_fingerprints: vec![
                        fp1.clone(),
                        fp2.clone(),
                        "unknown-unimported-fingerprint".to_string(),
                    ],
                    formula_expr: "up_mbps * 10".to_string(),
                    active_node_fingerprint: Some(fp2.clone()),
                    ..ShareGroupRecord::default()
                },
                // 2. New group referencing a fallback pool defined later in the same bundle.
                ShareGroupRecord {
                    name: "Cost Saver".to_string(),
                    mode: MultiGroupMode::StickyBest,
                    member_fingerprints: vec![fp2.clone()],
                    fallback_policy: FallbackPolicy::CrossPoolEscalate,
                    fallback_pool_name: Some("Backup High Speed".to_string()),
                    active_node_fingerprint: Some(fp2.clone()),
                    independent_routing: true,
                    ..ShareGroupRecord::default()
                },
                // 3. New fallback pool referencing a missing fallback pool -> fallback_pool_id None.
                ShareGroupRecord {
                    name: "Backup High Speed".to_string(),
                    mode: MultiGroupMode::StickyBest,
                    member_fingerprints: vec![fp3.clone()],
                    fallback_policy: FallbackPolicy::CrossPoolEscalate,
                    fallback_pool_name: Some("Nonexistent Pool".to_string()),
                    ..ShareGroupRecord::default()
                },
                // 4. Dynamic filter group with zero explicit members -> allowed and persisted.
                ShareGroupRecord {
                    name: "Dynamic JP".to_string(),
                    mode: MultiGroupMode::ConditionalPool,
                    member_fingerprints: Vec::new(),
                    dynamic_filter: Some(DynamicFilterSpec {
                        region_codes: vec!["JP".to_string()],
                        ..DynamicFilterSpec::default()
                    }),
                    ..ShareGroupRecord::default()
                },
                // 5. Zero resolved members and no dynamic_filter -> skipped with warning.
                ShareGroupRecord {
                    name: "Ghost Group".to_string(),
                    mode: MultiGroupMode::StickyBest,
                    member_fingerprints: vec!["missing-fp-only".to_string()],
                    dynamic_filter: None,
                    ..ShareGroupRecord::default()
                },
            ],
        };

        let (count, warnings) =
            merge_imported_groups_into_storage(&db, &incoming).expect("merge groups");
        assert_eq!(count, 4);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Ghost Group"));

        let all = db.list_multi_groups().unwrap();
        assert_eq!(all.len(), 4);

        let ai = all.iter().find(|g| g.name == "AI Sticky").unwrap();
        assert_eq!(ai.id, "grp-local-ai");
        assert_eq!(ai.mode, MultiGroupMode::LoadBalanceConsistentHash);
        assert_eq!(ai.formula_expr, "up_mbps * 50");
        assert_eq!(ai.active_node_id.as_deref(), Some("local-n1"));
        assert_eq!(
            ai.member_node_ids,
            vec!["local-n1".to_string(), "local-n2".to_string()]
        );

        let backup = all.iter().find(|g| g.name == "Backup High Speed").unwrap();
        assert_eq!(backup.fallback_pool_id, None);
        assert_eq!(backup.member_node_ids, vec!["local-n3".to_string()]);

        let cost = all.iter().find(|g| g.name == "Cost Saver").unwrap();
        assert_eq!(cost.fallback_pool_id.as_deref(), Some(backup.id.as_str()));
        assert_eq!(cost.active_node_id.as_deref(), Some("local-n2"));
        assert!(cost.independent_routing);

        let dyn_jp = all.iter().find(|g| g.name == "Dynamic JP").unwrap();
        assert!(dyn_jp.member_node_ids.is_empty());
        assert!(dyn_jp.dynamic_filter.is_some());
    }
}
