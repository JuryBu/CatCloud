use crate::error::{CatError, CatResult};
use crate::models::{PreAccelRelay, ProxyNode};
use crate::preaccel::{bundle_from_relays, parse_mmrelay_json, serialize_mmrelay_json};
use crate::subscription::parser::{normalize_protocol, parse_subscription_payload};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_yaml_ng::{Mapping, Number, Value};
use std::collections::HashSet;
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path};
use uuid::Uuid;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

/// Standard schema identifier for CatCloud `.zip` share bundles.
pub const SHARE_BUNDLE_SCHEMA: &str = "catcloud-share/v1";

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

/// In-memory preview returned by parsing a `catcloud-share/v1` ZIP bundle without touching disk.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ShareBundlePreview {
    pub manifest: ShareBundleManifest,
    pub nodes: Vec<ProxyNode>,
    pub relays: Vec<PreAccelRelay>,
    pub warnings: Vec<String>,
    pub has_readme: bool,
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

    let total_uncompressed = manifest_json.len()
        + readme_md.len()
        + nodes_yaml.as_ref().map_or(0, String::len)
        + relays_json.as_ref().map_or(0, String::len);
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
    let (bytes, manifest) = export_share_bundle_zip_bytes(req)?;

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
    })
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
    }
}
