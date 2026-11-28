use std::collections::HashMap;
use std::collections::HashSet;
use std::path::PathBuf;
use catcloud_core::models::PreAccelRelay;
use catcloud_core::models::ProxyNode;
use catcloud_core::share_bundle::ShareBundleExportRequest;
use catcloud_core::share_bundle::ShareBundleManifest;
use catcloud_core::share_bundle::ShareBundlePreview;
use catcloud_core::share_bundle::ShareGroupsBundle;
use catcloud_core::share_bundle::build_share_groups_bundle;
use catcloud_core::share_bundle::export_share_bundle_zip_bytes_with_groups;
use catcloud_core::share_bundle::export_share_bundle_zip_file;
use catcloud_core::share_bundle::merge_imported_groups_into_storage;
use catcloud_core::share_bundle::preview_share_bundle_zip_bytes;
use catcloud_core::share_bundle::preview_share_bundle_zip_file;
use catcloud_core::storage::SubscriptionUpdateMode;
use serde::Deserialize;
use serde::Serialize;
use tauri::AppHandle;
use tauri::State;
use crate::lan_sync::SyncReceiveSessionDto;
use crate::lan_sync::SyncSendSessionDto;

use crate::commands::core_lifecycle::trigger_reload_if_running;
use crate::commands::groups_strategy::ensure_default_group_if_empty;
use crate::commands::nodes_subs_capture::parse_subscription_update_mode;
use crate::commands::nodes_subs_capture::persist_migration_nodes;
use crate::commands::nodes_subs_capture::remap_active_single_node_id_if_needed;
use crate::commands::state::AppState;
use crate::commands::state::prune_node_health_pool_from_db;
use crate::commands::state::sanitize_dialog_filename_stem;
use crate::commands::system_proxy::sync_running_global_preaccel_if_active;
use crate::commands::tray_runtime::emit_config_updated;
use crate::commands::tray_runtime::emit_groups_updated;
use crate::commands::tray_runtime::emit_relays_updated;
use crate::commands::tray_runtime::format_mihomo_error_for_user;
use crate::commands::tray_runtime::sync_tray_and_window_side_effects;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareBundleExportOutcome {
    pub cancelled: bool,
    pub path: Option<String>,
    pub manifest: Option<ShareBundleManifest>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareBundlePreviewDto {
    pub zip_path: String,
    pub manifest: ShareBundleManifest,
    pub nodes: Vec<ProxyNode>,
    pub relays: Vec<PreAccelRelay>,
    pub warnings: Vec<String>,
    pub has_readme: bool,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareBundleImportOutcome {
    pub imported_nodes: usize,
    pub imported_relays: usize,
    pub target_sub_id: Option<String>,
    pub target_sub_name: Option<String>,
    pub warnings: Vec<String>,
}


#[tauri::command]
pub async fn export_share_bundle_dialog(
    app: AppHandle,
    state: State<'_, AppState>,
    name: String,
    description: Option<String>,
    node_ids: Vec<String>,
    relay_ids: Vec<String>,
) -> Result<ShareBundleExportOutcome, String> {
    use tauri_plugin_dialog::DialogExt;

    let (selected_nodes, selected_relays) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let all_nodes = db.list_nodes().map_err(|e| e.to_string())?;
        let all_relays = db.list_preaccel_relays(false).map_err(|e| e.to_string())?;
        let node_map: HashMap<&str, &ProxyNode> =
            all_nodes.iter().map(|n| (n.id.as_str(), n)).collect();
        let relay_map: HashMap<&str, &PreAccelRelay> =
            all_relays.iter().map(|r| (r.id.as_str(), r)).collect();

        let mut seen_nodes: HashSet<String> = HashSet::new();
        let mut nodes_out: Vec<ProxyNode> = Vec::new();
        for id in &node_ids {
            let trimmed = id.trim();
            if !trimmed.is_empty() && seen_nodes.insert(trimmed.to_string()) {
                if let Some(node) = node_map.get(trimmed) {
                    nodes_out.push((*node).clone());
                }
            }
        }

        let mut seen_relays: HashSet<String> = HashSet::new();
        let mut relays_out: Vec<PreAccelRelay> = Vec::new();
        for id in &relay_ids {
            let trimmed = id.trim();
            if !trimmed.is_empty() && seen_relays.insert(trimmed.to_string()) {
                if let Some(relay) = relay_map.get(trimmed) {
                    relays_out.push((*relay).clone());
                }
            }
        }
        (nodes_out, relays_out)
    };

    if selected_nodes.is_empty() && selected_relays.is_empty() {
        return Err("请至少勾选 1 个节点或 1 条国内中转线路后再导出分享包".to_string());
    }

    let bundle_name = {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            "CatCloud 分享包".to_string()
        } else {
            trimmed.to_string()
        }
    };
    let default_filename = format!(
        "{}.zip",
        sanitize_dialog_filename_stem(&bundle_name, "catcloud-share")
    );

    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_title("导出猫猫云梯分享包 (.zip)")
        .set_file_name(&default_filename)
        .add_filter("CatCloud 分享包", &["zip"])
        .save_file(move |file_path| {
            let _ = tx.send(file_path);
        });

    let picked = rx.await.map_err(|_| "文件保存已取消".to_string())?;
    let Some(file_path) = picked else {
        return Ok(ShareBundleExportOutcome {
            cancelled: true,
            path: None,
            manifest: None,
        });
    };
    let mut target_path = file_path
        .into_path()
        .map_err(|e| format!("无法解析所选保存路径：{e}"))?;
    if target_path
        .extension()
        .and_then(|e| e.to_str())
        .is_none_or(|ext| !ext.eq_ignore_ascii_case("zip"))
    {
        target_path.set_extension("zip");
    }

    let req = ShareBundleExportRequest {
        name: bundle_name,
        description: description
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        nodes: selected_nodes,
        relays: selected_relays,
    };
    let path_for_write = target_path.clone();
    let manifest = tokio::task::spawn_blocking(move || {
        export_share_bundle_zip_file(&req, &path_for_write)
    })
    .await
    .map_err(|e| format!("后台导出分享包任务异常中止：{e}"))?
    .map_err(|e| e.to_string())?;

    let path_str = catcloud_core::paths::normalize_os_path(&target_path)
        .display()
        .to_string();
    state.log_app_event(
        "info",
        "分享包",
        &format!(
            "已导出分享包（节点 {} 个，国内中转 {} 条）",
            manifest.node_count, manifest.relay_count
        ),
    );
    Ok(ShareBundleExportOutcome {
        cancelled: false,
        path: Some(path_str),
        manifest: Some(manifest),
    })
}


#[tauri::command]
pub async fn pick_and_preview_share_bundle(
    app: AppHandle,
) -> Result<Option<ShareBundlePreviewDto>, String> {
    use tauri_plugin_dialog::DialogExt;

    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_title("选择猫猫云梯分享包 (.zip)")
        .add_filter("CatCloud 分享包", &["zip"])
        .pick_file(move |file_path| {
            let _ = tx.send(file_path);
        });

    let picked = rx.await.map_err(|_| "文件选择已取消".to_string())?;
    let Some(file_path) = picked else {
        return Ok(None);
    };
    let zip_path_buf = file_path
        .into_path()
        .map_err(|e| format!("无法获取所选分享包路径：{e}"))?;
    let zip_path_str = catcloud_core::paths::normalize_os_path(&zip_path_buf)
        .display()
        .to_string();
    let preview = tokio::task::spawn_blocking(move || preview_share_bundle_zip_file(&zip_path_buf))
        .await
        .map_err(|e| format!("解析分享包任务异常中止：{e}"))?
        .map_err(|e| e.to_string())?;

    // Redact plaintext credentials and server addresses before crossing IPC into WebView preview;
    // `import_share_bundle` re-parses the verified archive on disk using the selected IDs.
    let redacted_nodes: Vec<ProxyNode> = preview
        .nodes
        .iter()
        .map(catcloud_core::sanitize::redact_node_for_readonly)
        .collect();
    let redacted_relays: Vec<PreAccelRelay> = preview
        .relays
        .iter()
        .map(catcloud_core::sanitize::redact_relay_for_readonly)
        .collect();

    Ok(Some(ShareBundlePreviewDto {
        zip_path: zip_path_str,
        manifest: preview.manifest,
        nodes: redacted_nodes,
        relays: redacted_relays,
        warnings: preview.warnings,
        has_readme: preview.has_readme,
    }))
}


#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn import_share_bundle(
    app: AppHandle,
    state: State<'_, AppState>,
    zip_path: String,
    selected_node_ids: Vec<String>,
    selected_relay_ids: Vec<String>,
    target_sub_id: Option<String>,
    new_sub_name: Option<String>,
    update_mode: Option<String>,
) -> Result<ShareBundleImportOutcome, String> {
    let trimmed_zip = zip_path.trim().to_string();
    if trimmed_zip.is_empty() {
        return Err("分享包文件路径不能为空".to_string());
    }
    let path_for_read = PathBuf::from(&trimmed_zip);
    let preview = tokio::task::spawn_blocking(move || preview_share_bundle_zip_file(&path_for_read))
        .await
        .map_err(|e| format!("解析分享包任务异常中止：{e}"))?
        .map_err(|e| e.to_string())?;

    let node_filter: HashSet<&str> = selected_node_ids
        .iter()
        .map(String::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let relay_filter: HashSet<&str> = selected_relay_ids
        .iter()
        .map(String::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    let chosen_nodes: Vec<ProxyNode> = preview
        .nodes
        .into_iter()
        .filter(|n| node_filter.contains(n.id.as_str()))
        .collect();
    let chosen_relays: Vec<PreAccelRelay> = preview
        .relays
        .into_iter()
        .filter(|r| relay_filter.contains(r.id.as_str()))
        .collect();

    if chosen_nodes.is_empty() && chosen_relays.is_empty() {
        return Err("请至少勾选 1 个节点或 1 条国内中转线路后再导入".to_string());
    }

    let mut warnings = preview.warnings;
    let mut imported_nodes: usize = 0;
    let mut resolved_sub_id: Option<String> = None;
    let mut resolved_sub_name: Option<String> = None;
    let mut id_remap: HashMap<String, String> = HashMap::new();

    if !chosen_nodes.is_empty() {
        let existing_target_id = target_sub_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        if let Some(tid) = existing_target_id {
            let mode = parse_subscription_update_mode(
                update_mode.as_deref().unwrap_or("merge_dedup"),
            )?;
            let (update_res, sub_name) = {
                let db = state.storage.lock().map_err(|e| e.to_string())?;
                let res = db
                    .update_subscription_nodes_with_mode(&tid, &chosen_nodes, mode)
                    .map_err(|e| e.to_string())?;
                let name = db
                    .get_subscription(&tid)
                    .ok()
                    .flatten()
                    .map(|s| s.name);
                (res, name)
            };
            imported_nodes = chosen_nodes.len();
            id_remap = update_res.id_remap;
            resolved_sub_id = Some(tid);
            resolved_sub_name = sub_name;
        } else {
            let sub_name = new_sub_name
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| {
                    let manifest_name = preview.manifest.name.trim();
                    if manifest_name.is_empty() {
                        "分享包导入".to_string()
                    } else {
                        manifest_name.to_string()
                    }
                });
            let (sub_id, count) = {
                let mut db = state.storage.lock().map_err(|e| e.to_string())?;
                persist_migration_nodes(&mut db, sub_name.clone(), chosen_nodes)?
            };
            imported_nodes = count;
            resolved_sub_id = Some(sub_id);
            resolved_sub_name = Some(sub_name);
        }
    }

    let mut imported_relays: usize = 0;
    if !chosen_relays.is_empty() {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let (count, relay_warnings) =
            catcloud_core::preaccel::import_relays_dedup_into_storage(&db, chosen_relays)
                .map_err(|e| e.to_string())?;
        imported_relays = count;
        warnings.extend(relay_warnings);
    }

    let mut created_default_group = false;
    if imported_nodes > 0 {
        let _ = remap_active_single_node_id_if_needed(&state, &id_remap)?;
        prune_node_health_pool_from_db(&state);
        created_default_group = ensure_default_group_if_empty(&state);
    }
    if let Some(outcome) = trigger_reload_if_running(&app, &state, false).await {
        if outcome.rejected {
            let detail = outcome
                .error
                .as_deref()
                .map(format_mihomo_error_for_user)
                .unwrap_or_else(|| "未知原因".to_string());
            warnings.push(format!("已导入数据，但热重载核心配置未通过：{detail}"));
        }
    }
    let latest_cfg = state.snapshot_config();
    if imported_relays > 0 {
        sync_running_global_preaccel_if_active(&state, &latest_cfg).await;
    }
    state.log_app_event(
        "info",
        "分享包",
        &format!(
            "已从分享包导入节点 {} 个、国内中转 {} 条",
            imported_nodes, imported_relays
        ),
    );
    emit_config_updated(&app, &latest_cfg);
    if created_default_group {
        emit_groups_updated(&app);
    }
    if imported_relays > 0 {
        emit_relays_updated(&app);
    }
    sync_tray_and_window_side_effects(&app, &state, &latest_cfg);

    Ok(ShareBundleImportOutcome {
        imported_nodes,
        imported_relays,
        target_sub_id: resolved_sub_id,
        target_sub_name: resolved_sub_name,
        warnings,
    })
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncEncryptedFileExportDto {
    pub cancelled: bool,
    pub path: Option<String>,
    pub fingerprint: String,
    pub key_uri: String,
    pub qr_svg: String,
    pub payload_bytes: usize,
    pub node_count: usize,
    pub relay_count: usize,
    pub group_count: usize,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncPreviewDto {
    pub pending_token: String,
    pub fingerprint: String,
    pub group_count: usize,
    pub group_names: Vec<String>,
    pub preview: ShareBundlePreviewDto,
}


fn collect_sync_export_payload(
    state: &AppState,
    name: String,
    description: Option<String>,
    node_ids: Vec<String>,
    relay_ids: Vec<String>,
    include_groups: Option<bool>,
) -> Result<(ShareBundleExportRequest, Option<ShareGroupsBundle>), String> {
    let want_groups = include_groups.unwrap_or(true);
    let (selected_nodes, selected_relays, all_groups) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let all_nodes = db.list_nodes().map_err(|e| e.to_string())?;
        let all_relays = db.list_preaccel_relays(false).map_err(|e| e.to_string())?;
        let node_map: HashMap<&str, &ProxyNode> =
            all_nodes.iter().map(|n| (n.id.as_str(), n)).collect();
        let relay_map: HashMap<&str, &PreAccelRelay> =
            all_relays.iter().map(|r| (r.id.as_str(), r)).collect();

        let mut seen_nodes: HashSet<String> = HashSet::new();
        let mut nodes_out: Vec<ProxyNode> = Vec::new();
        for id in &node_ids {
            let trimmed = id.trim();
            if !trimmed.is_empty() && seen_nodes.insert(trimmed.to_string()) {
                if let Some(node) = node_map.get(trimmed) {
                    nodes_out.push((*node).clone());
                }
            }
        }

        let mut seen_relays: HashSet<String> = HashSet::new();
        let mut relays_out: Vec<PreAccelRelay> = Vec::new();
        for id in &relay_ids {
            let trimmed = id.trim();
            if !trimmed.is_empty() && seen_relays.insert(trimmed.to_string()) {
                if let Some(relay) = relay_map.get(trimmed) {
                    relays_out.push((*relay).clone());
                }
            }
        }

        let groups_out = if want_groups {
            db.list_multi_groups().map_err(|e| e.to_string())?
        } else {
            Vec::new()
        };
        (nodes_out, relays_out, groups_out)
    };

    if selected_nodes.is_empty() && selected_relays.is_empty() {
        return Err("请至少勾选 1 个节点或 1 条国内中转线路后再发起跨设备同步".to_string());
    }

    let groups_bundle = if want_groups && !all_groups.is_empty() {
        let cfg = state.snapshot_config();
        let built = build_share_groups_bundle(
            &all_groups,
            &selected_nodes,
            cfg.active_group_id.as_deref(),
            Some(cfg.route_mode.as_str()),
        );
        if built.groups.is_empty() {
            None
        } else {
            Some(built)
        }
    } else {
        None
    };

    let bundle_name = {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            "CatCloud 跨设备同步包".to_string()
        } else {
            trimmed.to_string()
        }
    };
    let req = ShareBundleExportRequest {
        name: bundle_name,
        description: description
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        nodes: selected_nodes,
        relays: selected_relays,
    };

    Ok((req, groups_bundle))
}


pub(in crate::commands) fn build_redacted_sync_preview_dto(
    pending_token: String,
    fingerprint: String,
    zip_label: String,
    preview: ShareBundlePreview,
) -> SyncPreviewDto {
    let group_names: Vec<String> = preview
        .groups_bundle
        .as_ref()
        .map(|gb| gb.groups.iter().map(|g| g.name.clone()).collect())
        .unwrap_or_default();
    let group_count = group_names.len();
    let redacted_nodes: Vec<ProxyNode> = preview
        .nodes
        .iter()
        .map(catcloud_core::sanitize::redact_node_for_readonly)
        .collect();
    let redacted_relays: Vec<PreAccelRelay> = preview
        .relays
        .iter()
        .map(catcloud_core::sanitize::redact_relay_for_readonly)
        .collect();

    SyncPreviewDto {
        pending_token,
        fingerprint,
        group_count,
        group_names,
        preview: ShareBundlePreviewDto {
            zip_path: zip_label,
            manifest: preview.manifest,
            nodes: redacted_nodes,
            relays: redacted_relays,
            warnings: preview.warnings,
            has_readme: preview.has_readme,
        },
    }
}


fn parse_ccsync_raw_key_material(raw: &str) -> Result<([u8; catcloud_core::sync::KEY_LEN], Option<String>), String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("请先输入 .ccsync 解密密钥（file_key 链接或 32 字节 Base64 密钥）".to_string());
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("catcloud://") || lower.starts_with("catcloud-sync://") {
        let parsed = catcloud_core::sync::parse_sync_uri(trimmed)
            .map_err(|e| format!("无法解析文件密钥链接：{e}"))?;
        if parsed.role != catcloud_core::sync::SyncRole::FileKey {
            return Err(format!(
                "所提供的链接类型为「{}」，解密 .ccsync 文件需要 role=file_key 密钥链接或 32 字节 Base64 密钥",
                parsed.role.as_str()
            ));
        }
        return Ok((parsed.key, parsed.fingerprint));
    }

    let decoded = catcloud_core::sync::decode_base64_flex(trimmed)
        .map_err(|e| format!("解密密钥格式无效（既不是 file_key 链接也不是有效 Base64）：{e}"))?;
    if decoded.len() != catcloud_core::sync::KEY_LEN {
        return Err(format!(
            "解密密钥长度无效（需 32 字节，实际 {} 字节）",
            decoded.len()
        ));
    }
    let mut key = [0u8; catcloud_core::sync::KEY_LEN];
    key.copy_from_slice(&decoded);
    Ok((key, None))
}


pub(in crate::commands) fn open_ccsync_envelope_bytes(
    raw_bytes: &[u8],
    secret_input: Option<&str>,
    pin: Option<&str>,
) -> Result<Vec<u8>, String> {
    let header = catcloud_core::sync::inspect_envelope_header(raw_bytes)
        .map_err(|e| format!("无效的 .ccsync 加密同步文件：{e}"))?;
    match header.kdf_mode {
        catcloud_core::sync::KDF_MODE_RAW_KEY => {
            let secret_str = secret_input
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    "请先输入 .ccsync 解密密钥（file_key 链接或 32 字节 Base64 密钥）".to_string()
                })?;
            let (key, expected_fp) = parse_ccsync_raw_key_material(secret_str)?;
            let zip_bytes = catcloud_core::sync::open_with_key(raw_bytes, &key)
                .map_err(|e| format!("解密 .ccsync 文件失败（请核对密钥是否匹配）：{e}"))?;
            if let Some(fp) = expected_fp {
                let actual_fp = catcloud_core::sync::plaintext_fingerprint(&zip_bytes);
                if actual_fp != fp {
                    return Err(format!(
                        ".ccsync 文件内容指纹校验不匹配（期望 {fp}，实际 {actual_fp}）"
                    ));
                }
            }
            Ok(zip_bytes)
        }
        catcloud_core::sync::KDF_MODE_PBKDF2_SHA256 => {
            let password = pin
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .or_else(|| secret_input.map(str::trim).filter(|s| !s.is_empty()))
                .ok_or_else(|| "该 .ccsync 文件使用口令加密，请输入解密口令".to_string())?;
            catcloud_core::sync::open_with_password(raw_bytes, password)
                .map_err(|e| format!("口令解密 .ccsync 文件失败：{e}"))
        }
        other => Err(format!("不支持的 .ccsync 加密模式：0x{other:02x}")),
    }
}


fn write_bytes_atomic(target_path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;

    if let Some(parent) = target_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("创建目标目录失败：{e}"))?;
        }
    }
    let parent_dir = target_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let tmp_path = parent_dir.join(format!(".catcloud-sync-{}.tmp", uuid::Uuid::new_v4()));

    let write_res = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp_path)?;
        f.write_all(bytes)?;
        f.flush()?;
        let _ = f.sync_all();
        Ok(())
    })();
    if let Err(err) = write_res {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(format!("写入临时同步文件失败：{err}"));
    }

    if let Err(_err) = std::fs::rename(&tmp_path, target_path) {
        let _ = std::fs::remove_file(target_path);
        if let Err(err2) = std::fs::rename(&tmp_path, target_path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(format!("原子落盘同步文件失败：{err2}"));
        }
    }
    Ok(())
}


#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn start_sync_send_session(
    app: AppHandle,
    state: State<'_, AppState>,
    name: String,
    description: Option<String>,
    node_ids: Vec<String>,
    relay_ids: Vec<String>,
    include_groups: Option<bool>,
    custom_endpoint: Option<String>,
    ttl_sec: Option<u64>,
    allow_multiple: Option<bool>,
) -> Result<SyncSendSessionDto, String> {
    let (req, groups_bundle) = collect_sync_export_payload(
        &state,
        name,
        description,
        node_ids,
        relay_ids,
        include_groups,
    )?;
    let group_count = groups_bundle.as_ref().map_or(0, |g| g.groups.len());

    let (zip_bytes, manifest) = tokio::task::spawn_blocking(move || {
        export_share_bundle_zip_bytes_with_groups(&req, groups_bundle.as_ref())
    })
    .await
    .map_err(|e| format!("打包跨设备同步数据失败：{e}"))?
    .map_err(|e| e.to_string())?;

    let dto = state
        .lan_sync
        .start_send_session(
            app,
            zip_bytes,
            custom_endpoint,
            ttl_sec,
            allow_multiple.unwrap_or(false),
        )
        .await?;

    state.log_app_event(
        "info",
        "跨设备同步",
        &format!(
            "已启动局域网发送会话（节点 {} 个，国内中转 {} 条，多选组 {} 个，端口 {}）",
            manifest.node_count, manifest.relay_count, group_count, dto.port
        ),
    );
    Ok(dto)
}


#[tauri::command]
pub async fn cancel_sync_send_session(
    state: State<'_, AppState>,
    session_id: Option<String>,
) -> Result<bool, String> {
    let cancelled = state
        .lan_sync
        .cancel_send_session(session_id.as_deref())
        .await;
    if cancelled {
        state.log_app_event("info", "跨设备同步", "已关闭局域网发送同步会话");
    }
    Ok(cancelled)
}


#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn export_encrypted_sync_file(
    app: AppHandle,
    state: State<'_, AppState>,
    name: String,
    description: Option<String>,
    node_ids: Vec<String>,
    relay_ids: Vec<String>,
    include_groups: Option<bool>,
) -> Result<SyncEncryptedFileExportDto, String> {
    use tauri_plugin_dialog::DialogExt;

    let (req, groups_bundle) = collect_sync_export_payload(
        &state,
        name,
        description,
        node_ids,
        relay_ids,
        include_groups,
    )?;
    let group_count = groups_bundle.as_ref().map_or(0, |g| g.groups.len());
    let default_filename = format!(
        "{}.ccsync",
        sanitize_dialog_filename_stem(&req.name, "catcloud-sync")
    );

    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_title("导出端到端加密同步文件 (.ccsync)")
        .set_file_name(&default_filename)
        .add_filter("CatCloud 加密同步包", &["ccsync"])
        .save_file(move |file_path| {
            let _ = tx.send(file_path);
        });

    let picked = rx.await.map_err(|_| "文件保存已取消".to_string())?;
    let Some(file_path) = picked else {
        return Ok(SyncEncryptedFileExportDto {
            cancelled: true,
            path: None,
            fingerprint: String::new(),
            key_uri: String::new(),
            qr_svg: String::new(),
            payload_bytes: 0,
            node_count: 0,
            relay_count: 0,
            group_count: 0,
        });
    };

    let mut target_path = file_path
        .into_path()
        .map_err(|e| format!("无法解析所选保存路径：{e}"))?;
    if target_path
        .extension()
        .and_then(|e| e.to_str())
        .is_none_or(|ext| !ext.eq_ignore_ascii_case("ccsync"))
    {
        target_path.set_extension("ccsync");
    }

    let path_for_write = target_path.clone();
    let export_res = tokio::task::spawn_blocking(move || -> Result<(ShareBundleManifest, String, String, String, usize), String> {
        let (zip_bytes, manifest) =
            export_share_bundle_zip_bytes_with_groups(&req, groups_bundle.as_ref())
                .map_err(|e| e.to_string())?;
        let fingerprint = catcloud_core::sync::plaintext_fingerprint(&zip_bytes);
        let key = catcloud_core::sync::generate_random_key()
            .map_err(|e| format!("生成加密同步密钥失败：{e}"))?;
        let envelope = catcloud_core::sync::seal_with_key(&zip_bytes, &key, "")
            .map_err(|e| format!("加密同步包失败：{e}"))?;
        write_bytes_atomic(&path_for_write, &envelope)?;
        let key_uri = catcloud_core::sync::format_sync_uri(&catcloud_core::sync::SyncUri {
            role: catcloud_core::sync::SyncRole::FileKey,
            endpoint: None,
            hosts: Vec::new(),
            port: None,
            sid: None,
            url: None,
            fingerprint: Some(fingerprint.clone()),
            key,
        })
        .map_err(|e| format!("生成解密密钥链接失败：{e}"))?;
        let qr_svg = catcloud_core::sync::render_qr_svg(&key_uri)
            .map_err(|e| format!("生成密钥二维码失败：{e}"))?;
        Ok((manifest, fingerprint, key_uri, qr_svg, envelope.len()))
    })
    .await
    .map_err(|e| format!("后台导出加密同步文件任务异常中止：{e}"))??;

    let (manifest, fingerprint, key_uri, qr_svg, payload_bytes) = export_res;
    let path_str = catcloud_core::paths::normalize_os_path(&target_path)
        .display()
        .to_string();
    state.log_app_event(
        "info",
        "跨设备同步",
        &format!(
            "已导出加密同步文件（节点 {} 个，国内中转 {} 条，多选组 {} 个，指纹 {}）",
            manifest.node_count, manifest.relay_count, group_count, fingerprint
        ),
    );

    Ok(SyncEncryptedFileExportDto {
        cancelled: false,
        path: Some(path_str),
        fingerprint,
        key_uri,
        qr_svg,
        payload_bytes,
        node_count: manifest.node_count,
        relay_count: manifest.relay_count,
        group_count,
    })
}


#[tauri::command]
pub async fn start_sync_receive_listener(
    app: AppHandle,
    state: State<'_, AppState>,
    custom_endpoint: Option<String>,
    ttl_sec: Option<u64>,
    allow_multiple: Option<bool>,
) -> Result<SyncReceiveSessionDto, String> {
    let dto = state
        .lan_sync
        .start_receive_listener(
            app,
            custom_endpoint,
            ttl_sec,
            allow_multiple.unwrap_or(false),
        )
        .await?;
    state.log_app_event(
        "info",
        "跨设备同步",
        &format!("已开启局域网接收同步监听（端口 {}）", dto.port),
    );
    Ok(dto)
}


#[tauri::command]
pub async fn cancel_sync_receive_session(
    state: State<'_, AppState>,
    session_id: Option<String>,
) -> Result<bool, String> {
    let cancelled = state
        .lan_sync
        .cancel_receive_session(session_id.as_deref())
        .await;
    if cancelled {
        state.log_app_event("info", "跨设备同步", "已关闭局域网接收同步监听");
    }
    Ok(cancelled)
}


#[tauri::command]
pub async fn preview_sync_source(
    app: AppHandle,
    state: State<'_, AppState>,
    source_input: Option<String>,
    pin: Option<String>,
    pending_token: Option<String>,
    pick_ccsync_file: Option<bool>,
) -> Result<Option<SyncPreviewDto>, String> {
    if let Some(tok) = pending_token
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let (preview, fingerprint) = state
            .lan_sync
            .clone_pending_preview(tok)
            .ok_or_else(|| "待导入的同步包已过期或已被处理，请重新发起同步".to_string())?;
        return Ok(Some(build_redacted_sync_preview_dto(
            tok.to_string(),
            fingerprint,
            "sync://pending".to_string(),
            preview,
        )));
    }

    if pick_ccsync_file == Some(true) {
        use std::io::Read as _;
        use tauri_plugin_dialog::DialogExt;

        let (tx, rx) = tokio::sync::oneshot::channel();
        app.dialog()
            .file()
            .set_title("选择端到端加密同步文件 (.ccsync)")
            .add_filter("CatCloud 加密同步包", &["ccsync"])
            .pick_file(move |file_path| {
                let _ = tx.send(file_path);
            });

        let picked = rx.await.map_err(|_| "文件选择已取消".to_string())?;
        let Some(file_path) = picked else {
            return Ok(None);
        };
        let ccsync_path = file_path
            .into_path()
            .map_err(|e| format!("无法获取所选同步文件路径：{e}"))?;
        let display_label = catcloud_core::sanitize::redact_path_for_display(
            &catcloud_core::paths::normalize_os_path(&ccsync_path)
                .display()
                .to_string(),
        );
        let secret_owned = source_input.clone();
        let pin_owned = pin.clone();

        let (zip_bytes, preview, fingerprint) = tokio::task::spawn_blocking(
            move || -> Result<(Vec<u8>, ShareBundlePreview, String), String> {
                let meta = std::fs::metadata(&ccsync_path)
                    .map_err(|e| format!("无法读取同步文件信息：{e}"))?;
                if !meta.is_file() {
                    return Err("所选路径不是有效的 .ccsync 文件".to_string());
                }
                let max_bytes = catcloud_core::sync::MAX_SYNC_ENVELOPE_BYTES as u64;
                if meta.len() > max_bytes {
                    return Err(format!(
                        ".ccsync 文件大小（{} 字节）超过 17 MiB 安全上限",
                        meta.len()
                    ));
                }
                let file = std::fs::File::open(&ccsync_path)
                    .map_err(|e| format!("打开 .ccsync 文件失败：{e}"))?;
                let mut raw = Vec::with_capacity(meta.len().min(max_bytes) as usize);
                file.take(max_bytes.saturating_add(1))
                    .read_to_end(&mut raw)
                    .map_err(|e| format!("读取 .ccsync 文件失败：{e}"))?;
                if (raw.len() as u64) > max_bytes {
                    return Err(".ccsync 文件内容超过 17 MiB 安全上限".to_string());
                }
                let zip_bytes =
                    open_ccsync_envelope_bytes(&raw, secret_owned.as_deref(), pin_owned.as_deref())?;
                let fingerprint = catcloud_core::sync::plaintext_fingerprint(&zip_bytes);
                let preview = preview_share_bundle_zip_bytes(&zip_bytes)
                    .map_err(|e| format!("解析同步包内容失败：{e}"))?;
                Ok((zip_bytes, preview, fingerprint))
            },
        )
        .await
        .map_err(|e| format!("后台解密同步文件任务异常中止：{e}"))??;

        let token = state.lan_sync.store_pending_bundle(
            zip_bytes,
            preview.clone(),
            fingerprint.clone(),
        );
        return Ok(Some(build_redacted_sync_preview_dto(
            token,
            fingerprint,
            display_label,
            preview,
        )));
    }

    let trimmed_source = source_input
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "请粘贴同步链接/二维码内容，或输入发送端局域网地址与 6 位配对码".to_string())?;
    let source_lower = trimmed_source.to_ascii_lowercase();

    let (zip_bytes, zip_label) =
        if source_lower.starts_with("catcloud://") || source_lower.starts_with("catcloud-sync://") {
            let parsed = catcloud_core::sync::parse_sync_uri(trimmed_source)
                .map_err(|e| format!("同步链接格式无效：{e}"))?;
            match parsed.role {
                catcloud_core::sync::SyncRole::Pull => {
                    let bytes = catcloud_core::sync::fetch_sync_bundle_via_uri(trimmed_source)
                        .await
                        .map_err(|e| format!("从局域网发送端拉取同步包失败：{e}"))?;
                    (bytes, "sync://pull".to_string())
                }
                catcloud_core::sync::SyncRole::RelayUrl => {
                    let bytes = catcloud_core::sync::fetch_relay_url_bundle(trimmed_source)
                        .await
                        .map_err(|e| format!("从零知识中转链接下载同步包失败：{e}"))?;
                    (bytes, "sync://relay_url".to_string())
                }
                catcloud_core::sync::SyncRole::Push => {
                    return Err(
                        "该二维码属于接收端推送地址（role=push），请在发送设备扫描推送而非用于拉取"
                            .to_string(),
                    );
                }
                catcloud_core::sync::SyncRole::FileKey => {
                    return Err(
                        "该内容为 .ccsync 文件解密密钥（role=file_key），请选择本地 .ccsync 文件配合解密"
                            .to_string(),
                    );
                }
            }
        } else {
            let pin_code = pin
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "使用局域网地址拉取时，请输入发送端显示的 6 位配对码".to_string())?;
            let bytes = catcloud_core::sync::fetch_sync_bundle_via_pin(trimmed_source, pin_code)
                .await
                .map_err(|e| format!("通过局域网地址与配对码拉取同步包失败：{e}"))?;
            (bytes, "sync://pin".to_string())
        };

    let fingerprint = catcloud_core::sync::plaintext_fingerprint(&zip_bytes);
    let zip_for_parse = zip_bytes.clone();
    let preview = tokio::task::spawn_blocking(move || preview_share_bundle_zip_bytes(&zip_for_parse))
        .await
        .map_err(|e| format!("解析同步包任务异常中止：{e}"))?
        .map_err(|e| format!("解析同步包内容失败：{e}"))?;

    let token = state.lan_sync.store_pending_bundle(
        zip_bytes,
        preview.clone(),
        fingerprint.clone(),
    );
    Ok(Some(build_redacted_sync_preview_dto(
        token,
        fingerprint,
        zip_label,
        preview,
    )))
}


#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn apply_sync_import(
    app: AppHandle,
    state: State<'_, AppState>,
    pending_token: String,
    selected_node_ids: Vec<String>,
    selected_relay_ids: Vec<String>,
    import_groups: Option<bool>,
    target_sub_id: Option<String>,
    new_sub_name: Option<String>,
    update_mode: Option<String>,
) -> Result<ShareBundleImportOutcome, String> {
    let trimmed_token = pending_token.trim();
    if trimmed_token.is_empty() {
        return Err("待导入同步令牌不能为空".to_string());
    }

    let existing_target_id = target_sub_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let parsed_update_mode = if existing_target_id.is_some() {
        Some(parse_subscription_update_mode(
            update_mode.as_deref().unwrap_or("merge_dedup"),
        )?)
    } else {
        None
    };

    let node_filter: HashSet<&str> = selected_node_ids
        .iter()
        .map(String::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let relay_filter: HashSet<&str> = selected_relay_ids
        .iter()
        .map(String::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    // Validate selections before consuming the pending token so a mistapped empty submit can retry.
    {
        let (peek_preview, _) = state
            .lan_sync
            .clone_pending_preview(trimmed_token)
            .ok_or_else(|| "待导入的同步包已过期或已被处理，请重新接收".to_string())?;
        let has_selected_node = peek_preview
            .nodes
            .iter()
            .any(|n| node_filter.contains(n.id.as_str()));
        let has_selected_relay = peek_preview
            .relays
            .iter()
            .any(|r| relay_filter.contains(r.id.as_str()));
        if !has_selected_node && !has_selected_relay {
            return Err("请至少勾选 1 个节点或 1 条国内中转线路后再导入".to_string());
        }
    }

    let bundle = state
        .lan_sync
        .take_pending_bundle(trimmed_token)
        .ok_or_else(|| "待导入的同步包已过期或已被处理，请重新接收".to_string())?;
    let payload_len = bundle.zip_bytes.len();
    let preview = bundle.preview;

    let chosen_nodes: Vec<ProxyNode> = preview
        .nodes
        .into_iter()
        .filter(|n| node_filter.contains(n.id.as_str()))
        .collect();
    let chosen_relays: Vec<PreAccelRelay> = preview
        .relays
        .into_iter()
        .filter(|r| relay_filter.contains(r.id.as_str()))
        .collect();

    let mut warnings = preview.warnings;
    let mut imported_nodes: usize = 0;
    let mut resolved_sub_id: Option<String> = None;
    let mut resolved_sub_name: Option<String> = None;
    let mut id_remap: HashMap<String, String> = HashMap::new();

    if !chosen_nodes.is_empty() {
        if let Some(tid) = existing_target_id {
            let mode = parsed_update_mode.unwrap_or(SubscriptionUpdateMode::MergeDedup);
            let (update_res, sub_name) = {
                let db = state.storage.lock().map_err(|e| e.to_string())?;
                let res = db
                    .update_subscription_nodes_with_mode(&tid, &chosen_nodes, mode)
                    .map_err(|e| e.to_string())?;
                let name = db
                    .get_subscription(&tid)
                    .ok()
                    .flatten()
                    .map(|s| s.name);
                (res, name)
            };
            imported_nodes = chosen_nodes.len();
            id_remap = update_res.id_remap;
            resolved_sub_id = Some(tid);
            resolved_sub_name = sub_name;
        } else {
            let sub_name = new_sub_name
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| {
                    let manifest_name = preview.manifest.name.trim();
                    if manifest_name.is_empty() {
                        "跨设备同步导入".to_string()
                    } else {
                        manifest_name.to_string()
                    }
                });
            let (sub_id, count) = {
                let mut db = state.storage.lock().map_err(|e| e.to_string())?;
                persist_migration_nodes(&mut db, sub_name.clone(), chosen_nodes)?
            };
            imported_nodes = count;
            resolved_sub_id = Some(sub_id);
            resolved_sub_name = Some(sub_name);
        }
    }

    let mut imported_relays: usize = 0;
    if !chosen_relays.is_empty() {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let (count, relay_warnings) =
            catcloud_core::preaccel::import_relays_dedup_into_storage(&db, chosen_relays)
                .map_err(|e| e.to_string())?;
        imported_relays = count;
        warnings.extend(relay_warnings);
    }

    let mut imported_groups: usize = 0;
    if import_groups.unwrap_or(true) {
        if let Some(ref groups_bundle) = preview.groups_bundle {
            let db = state.storage.lock().map_err(|e| e.to_string())?;
            let (count, group_warnings) = merge_imported_groups_into_storage(&db, groups_bundle)
                .map_err(|e| e.to_string())?;
            imported_groups = count;
            warnings.extend(group_warnings);
        }
    }

    let mut created_default_group = false;
    if imported_nodes > 0 {
        let _ = remap_active_single_node_id_if_needed(&state, &id_remap)?;
        prune_node_health_pool_from_db(&state);
        created_default_group = ensure_default_group_if_empty(&state);
    } else if imported_groups > 0 {
        created_default_group = ensure_default_group_if_empty(&state);
    }
    if let Some(outcome) = trigger_reload_if_running(&app, &state, false).await {
        if outcome.rejected {
            let detail = outcome
                .error
                .as_deref()
                .map(format_mihomo_error_for_user)
                .unwrap_or_else(|| "未知原因".to_string());
            warnings.push(format!("已导入同步包，但热重载核心配置未通过：{detail}"));
        }
    }
    let latest_cfg = state.snapshot_config();
    if imported_relays > 0 {
        sync_running_global_preaccel_if_active(&state, &latest_cfg).await;
    }
    state.log_app_event(
        "info",
        "跨设备同步",
        &format!(
            "已导入跨设备同步包（节点 {} 个、国内中转 {} 条、多选组 {} 个，{} 字节，指纹 {}）",
            imported_nodes, imported_relays, imported_groups, payload_len, bundle.fingerprint
        ),
    );
    emit_config_updated(&app, &latest_cfg);
    if imported_groups > 0 || created_default_group {
        emit_groups_updated(&app);
    }
    if imported_relays > 0 {
        emit_relays_updated(&app);
    }
    sync_tray_and_window_side_effects(&app, &state, &latest_cfg);

    Ok(ShareBundleImportOutcome {
        imported_nodes,
        imported_relays,
        target_sub_id: resolved_sub_id,
        target_sub_name: resolved_sub_name,
        warnings,
    })
}

