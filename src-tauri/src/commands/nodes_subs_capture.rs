use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use catcloud_core::config;
use catcloud_core::core_adapter::CoreAdapter;
use catcloud_core::models::ProxyNode;
use catcloud_core::models::SubscriptionKind;
use catcloud_core::models::SubscriptionRecord;
use catcloud_core::models::pick_smart_default_node_id;
use catcloud_core::platform::SystemProxySpec;
use catcloud_core::platform::default_platform;
use catcloud_core::storage::MergeSubscriptionsResult;
use catcloud_core::storage::Storage;
use catcloud_core::storage::SubscriptionNodesUpdateResult;
use catcloud_core::storage::SubscriptionUpdateMode;
use catcloud_core::subscription::live_capture::DesktopAppCandidate;
use catcloud_core::subscription::live_capture::LiveCaptureOutcomeDto;
use catcloud_core::subscription::live_capture::LiveCaptureStartDto;
use catcloud_core::subscription::live_capture::LiveCaptureStatusDto;
use catcloud_core::subscription::live_capture::list_desktop_app_candidates as core_list_desktop_app_candidates;
use catcloud_core::subscription::ADAPTER_REASON_MANUAL;
use catcloud_core::subscription::AdapterConfig;
use catcloud_core::subscription::AdapterRequest;
use catcloud_core::subscription::FetchOptions;
use catcloud_core::subscription::ParsedSubscription;
use catcloud_core::subscription::SubscriptionPayloadFormat;
use catcloud_core::subscription::apply_parsed_subscription;
use catcloud_core::subscription::inspect_process_source as core_inspect_process_source;
use catcloud_core::subscription::invoke_external_adapter;
use catcloud_core::subscription::parse_controller_proxies_json;
use catcloud_core::subscription::parse_subscription_payload;
use catcloud_core::subscription::preview_from_text as core_preview_from_text;
use chrono::Utc;
use serde::Deserialize;
use serde::Serialize;
use tauri::AppHandle;
use tauri::State;
use crate::app_log;

use crate::commands::core_lifecycle::stop_core_internal;
use crate::commands::core_lifecycle::trigger_reload_if_running;
use crate::commands::groups_strategy::ensure_default_group_if_empty;
use crate::commands::state::AppState;
use crate::commands::state::SubRefreshGuard;
use crate::commands::state::prune_node_health_pool_from_db;
use crate::commands::system_proxy::clear_system_proxy_if_owned_with_hint;
use crate::commands::tray_runtime::emit_config_updated;
use crate::commands::tray_runtime::emit_groups_updated;
use crate::commands::tray_runtime::emit_nodes_updated;
use crate::commands::tray_runtime::format_mihomo_error_for_user;
use crate::commands::tray_runtime::has_enabled_nodes;
use crate::commands::tray_runtime::sync_tray_and_window_side_effects;

#[tauri::command]
pub fn list_nodes(state: State<'_, AppState>) -> Result<Vec<ProxyNode>, String> {
    let db = state.storage.lock().map_err(|e| e.to_string())?;
    db.list_nodes().map_err(|e| e.to_string())
}


#[tauri::command]
pub async fn set_nodes_preaccel_override(
    app: AppHandle,
    state: State<'_, AppState>,
    node_ids: Vec<String>,
    override_mode: String,
) -> Result<usize, String> {
    let parsed: Option<bool> = match override_mode.trim().to_ascii_lowercase().as_str() {
        "inherit" | "auto" | "default" => None,
        "force_on" | "on" | "true" => Some(true),
        "force_off" | "off" | "false" => Some(false),
        other => {
            return Err(format!(
                "不支持的提速覆写模式「{other}」（仅支持 inherit / force_on / force_off）"
            ))
        }
    };
    let count = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let mut changed = 0usize;
        for nid in &node_ids {
            if let Some(mut node) = db.get_node(nid).map_err(|e| e.to_string())? {
                node.preaccel_override = parsed;
                db.upsert_node(&node).map_err(|e| e.to_string())?;
                changed += 1;
            }
        }
        changed
    };
    if count > 0 {
        let _ = trigger_reload_if_running(&app, &state, false).await;
    }
    Ok(count)
}


#[tauri::command]
pub fn list_subscriptions(state: State<'_, AppState>) -> Result<Vec<SubscriptionRecord>, String> {
    let db = state.storage.lock().map_err(|e| e.to_string())?;
    db.list_subscriptions().map_err(|e| e.to_string())
}


fn unwrap_clash_subscription_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let parsed = reqwest::Url::parse(trimmed).ok()?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    if !matches!(scheme.as_str(), "clash" | "clashmeta" | "mihomo") {
        return None;
    }
    for (k, v) in parsed.query_pairs() {
        if k.eq_ignore_ascii_case("url") {
            let candidate = v.trim();
            let lower = candidate.to_ascii_lowercase();
            if lower.starts_with("http://") || lower.starts_with("https://") {
                return Some(candidate.to_string());
            }
        }
    }
    None
}


fn normalize_subscription_url_for_dedup(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let effective = unwrap_clash_subscription_url(trimmed).unwrap_or_else(|| trimmed.to_string());
    let eff_trimmed = effective.trim();
    if let Ok(mut parsed) = reqwest::Url::parse(eff_trimmed) {
        parsed.set_fragment(None);
        return Some(parsed.to_string());
    }
    if let Some((scheme, rest)) = eff_trimmed.split_once("://") {
        let (host_port, tail) = match rest.find(['/', '?', '#']) {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, ""),
        };
        let tail_no_frag = tail.split('#').next().unwrap_or(tail);
        return Some(format!(
            "{}://{}{}",
            scheme.to_ascii_lowercase(),
            host_port.to_ascii_lowercase(),
            tail_no_frag
        ));
    }
    Some(eff_trimmed.to_string())
}


pub(in crate::commands) fn upsert_subscription_in_storage(
    db: &Storage,
    mut record: SubscriptionRecord,
) -> Result<SubscriptionRecord, String> {
    let requested_id = record.id.trim().to_string();
    if record.kind == SubscriptionKind::Url {
        let trimmed_url = record.url_or_cmd.trim().to_string();
        record.url_or_cmd = unwrap_clash_subscription_url(&trimmed_url).unwrap_or(trimmed_url);
    }

    let existing_by_id = if requested_id.is_empty() {
        None
    } else {
        db.get_subscription(&requested_id)
            .map_err(|e| e.to_string())?
    };

    if existing_by_id.is_some() {
        // Explicit update of an existing subscription ID: update in place without cross-ID merging.
        record.id = requested_id;
        db.upsert_subscription(&record).map_err(|e| e.to_string())?;
        return Ok(record);
    }

    // New or empty ID for a URL subscription: deduplicate by normalized URL to prevent duplicate
    // subscriptions and doubled nodes.
    if record.kind == SubscriptionKind::Url {
        if let Some(target_key) = normalize_subscription_url_for_dedup(&record.url_or_cmd) {
            let existing_subs = db.list_subscriptions().map_err(|e| e.to_string())?;
            if let Some(matched) = existing_subs.into_iter().find(|s| {
                s.kind == SubscriptionKind::Url
                    && normalize_subscription_url_for_dedup(&s.url_or_cmd).as_deref()
                        == Some(target_key.as_str())
            }) {
                record.id = matched.id;
                if record.name.trim().is_empty() {
                    record.name = matched.name;
                }
                if record.traffic_total_bytes == 0 && record.traffic_used_bytes == 0 {
                    record.traffic_used_bytes = matched.traffic_used_bytes;
                    record.traffic_total_bytes = matched.traffic_total_bytes;
                }
                if record.expires_at.is_none() {
                    record.expires_at = matched.expires_at;
                }
                if record.etag.is_none() {
                    record.etag = matched.etag;
                }
                if record.last_ok_at.is_none() {
                    record.last_ok_at = matched.last_ok_at;
                }
                if record.last_error.is_none() {
                    record.last_error = matched.last_error;
                }
                db.upsert_subscription(&record).map_err(|e| e.to_string())?;
                return Ok(record);
            }
        }
    }

    if requested_id.is_empty() {
        record.id = format!("sub-{}", uuid::Uuid::new_v4().simple());
    } else {
        record.id = requested_id;
    }
    db.upsert_subscription(&record).map_err(|e| e.to_string())?;
    Ok(record)
}


#[tauri::command]
pub fn upsert_subscription(
    app: AppHandle,
    state: State<'_, AppState>,
    record: SubscriptionRecord,
) -> Result<SubscriptionRecord, String> {
    let saved = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        upsert_subscription_in_storage(&db, record)?
    };
    let created_default_group = ensure_default_group_if_empty(&state);
    let cfg = state.snapshot_config();
    if created_default_group {
        emit_config_updated(&app, &cfg);
    }
    sync_tray_and_window_side_effects(&app, &state, &cfg);
    Ok(saved)
}


#[tauri::command]
pub async fn delete_subscription(
    app: AppHandle,
    state: State<'_, AppState>,
    sub_id: String,
) -> Result<bool, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    let deleted = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        db.delete_subscription(&sub_id).map_err(|e| e.to_string())?
    };
    if deleted {
        let removed_migrated_rules = {
            let mut cfg = state.clone_config();
            let removed = catcloud_core::subscription::remove_subscription_migrated_rules(
                &mut cfg,
                &sub_id,
            );
            if removed > 0 {
                let _ = config::save(&state.paths, &cfg);
                if let Ok(mut guard) = state.config.write() {
                    *guard = Arc::new(cfg.clone());
                }
            }
            removed
        };
        if removed_migrated_rules > 0 {
            state.log_app_event(
                "info",
                "订阅",
                &format!("删除订阅时已自动清理其带入的 {removed_migrated_rules} 条分流规则"),
            );
        }
        let _ = remap_active_single_node_id_if_needed(&state, &HashMap::new())?;
        prune_node_health_pool_from_db(&state);

        let has_remaining_enabled = has_enabled_nodes(&state).unwrap_or(false);
        let core_running =
            state.snapshot_runtime().running || state.adapter.has_live_controller().await;

        if !has_remaining_enabled {
            if core_running {
                if let Err(err) = stop_core_internal(&app, &state).await {
                    state.log_app_event(
                        "warning",
                        "订阅",
                        &format!("删除订阅后已无可用节点，安全停止代理核心失败：{err}"),
                    );
                } else {
                    state.log_app_event(
                        "info",
                        "订阅",
                        "删除订阅后已无可用节点，已自动清除系统代理并安全停止核心",
                    );
                }
            } else {
                let mut cfg = state.clone_config();
                if cfg.system_proxy.enabled || cfg.tun.enabled {
                    if cfg.system_proxy.enabled {
                        let _ = clear_system_proxy_if_owned_with_hint(&state, true);
                        cfg.system_proxy.enabled = false;
                    }
                    if cfg.tun.enabled {
                        cfg.tun.enabled = false;
                        state.clear_power_off_takeover_memory();
                    }
                    let _ = config::save(&state.paths, &cfg);
                    if let Ok(mut guard) = state.config.write() {
                        *guard = Arc::new(cfg.clone());
                    }
                }
            }
        } else if core_running {
            let _ = trigger_reload_if_running(&app, &state, false).await;
        }

        let cfg = state.snapshot_config();
        emit_groups_updated(&app);
        emit_nodes_updated(&app);
        emit_config_updated(&app, &cfg);
        sync_tray_and_window_side_effects(&app, &state, &cfg);
    }
    Ok(deleted)
}


pub(in crate::commands) fn parse_subscription_update_mode(raw: &str) -> Result<SubscriptionUpdateMode, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "replace_latest" => Ok(SubscriptionUpdateMode::ReplaceLatest),
        "merge_dedup" => Ok(SubscriptionUpdateMode::MergeDedup),
        other => Err(format!(
            "不支持的节点更新方式 `{other}`，仅支持 `replace_latest` 或 `merge_dedup`"
        )),
    }
}


/// Synchronize `AppConfig.active_single_node_id` whenever subscription node updates, deletions, or
/// merges remap deduplicated node IDs or remove stale nodes (falling back strictly to an existing
/// enabled node, or clearing to `None` when no enabled nodes remain).
pub(in crate::commands) fn remap_active_single_node_id_if_needed(
    state: &AppState,
    id_remap: &HashMap<String, String>,
) -> Result<bool, String> {
    let mut cfg = state.clone_config();
    let Some(current_id) = cfg
        .active_single_node_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
    else {
        return Ok(false);
    };

    let next_id = if let Some(remapped) = id_remap.get(&current_id) {
        Some(remapped.clone())
    } else {
        let still_exists = state
            .storage
            .lock()
            .ok()
            .and_then(|db| db.get_node(&current_id).ok())
            .flatten()
            .is_some_and(|n| n.enabled);
        if still_exists {
            return Ok(false);
        }
        state
            .storage
            .lock()
            .ok()
            .and_then(|db| {
                let nodes = db.list_nodes().ok()?;
                let enabled_nodes: Vec<ProxyNode> =
                    nodes.iter().filter(|n| n.enabled).cloned().collect();
                if enabled_nodes.is_empty() {
                    return None;
                }
                let ids: Vec<String> = enabled_nodes.iter().map(|n| n.id.clone()).collect();
                let snaps = db
                    .get_probe_snapshots_batch(&ids, None)
                    .unwrap_or_default();
                pick_smart_default_node_id(&enabled_nodes, Some(&snaps))
                    .or_else(|| enabled_nodes.first().map(|n| n.id.clone()))
            })
    };

    if cfg.active_single_node_id == next_id {
        return Ok(false);
    }
    cfg.active_single_node_id = next_id;
    config::save(&state.paths, &cfg).map_err(|e| format!("保存配置失败：{e}"))?;
    if let Ok(mut guard) = state.config.write() {
        *guard = Arc::new(cfg);
    }
    state.bump_config_generation();
    Ok(true)
}


#[tauri::command]
pub async fn rename_subscription(
    app: AppHandle,
    state: State<'_, AppState>,
    sub_id: String,
    new_name: String,
) -> Result<SubscriptionRecord, String> {
    let updated = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        db.rename_subscription(&sub_id, &new_name)
            .map_err(|e| e.to_string())?
    };
    state.log_app_event(
        "info",
        "订阅",
        &format!("已将订阅组重命名为「{}」", updated.name),
    );
    let cfg = state.snapshot_config();
    sync_tray_and_window_side_effects(&app, &state, &cfg);
    emit_config_updated(&app, &cfg);
    Ok(updated)
}


#[tauri::command]
pub async fn apply_nodes_to_existing_subscription(
    app: AppHandle,
    state: State<'_, AppState>,
    target_sub_id: String,
    nodes: Vec<ProxyNode>,
    mode: String,
) -> Result<SubscriptionNodesUpdateResult, String> {
    let update_mode = parse_subscription_update_mode(&mode)?;
    let outcome = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        db.update_subscription_nodes_with_mode(&target_sub_id, &nodes, update_mode)
            .map_err(|e| e.to_string())?
    };
    let _ = remap_active_single_node_id_if_needed(&state, &outcome.id_remap)?;
    prune_node_health_pool_from_db(&state);
    let _ = ensure_default_group_if_empty(&state);
    let _ = trigger_reload_if_running(&app, &state, false).await;
    state.log_app_event(
        "info",
        "订阅",
        &format!(
            "已按 {} 模式更新已有订阅组：保留 {} 个，新增 {} 个，替换/更新 {} 个，当前共 {} 个节点",
            mode.trim(),
            outcome.kept_count,
            outcome.added_count,
            outcome.replaced_count,
            outcome.total_count
        ),
    );
    let cfg = state.snapshot_config();
    emit_groups_updated(&app);
    emit_nodes_updated(&app);
    emit_config_updated(&app, &cfg);
    sync_tray_and_window_side_effects(&app, &state, &cfg);
    Ok(outcome)
}


#[tauri::command]
pub async fn merge_subscriptions(
    app: AppHandle,
    state: State<'_, AppState>,
    source_sub_id: String,
    target_sub_id: String,
    new_target_name: Option<String>,
    deduplicate: Option<bool>,
    convert_target_to_migrated: Option<bool>,
) -> Result<MergeSubscriptionsResult, String> {
    let clean_name = new_target_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let outcome = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        db.merge_subscriptions(
            &source_sub_id,
            &target_sub_id,
            clean_name.as_deref(),
            deduplicate.unwrap_or(true),
            convert_target_to_migrated.unwrap_or(false),
        )
        .map_err(|e| e.to_string())?
    };
    {
        let mut cfg = state.clone_config();
        if catcloud_core::subscription::merge_subscription_migrated_rules(
            &mut cfg,
            &source_sub_id,
            &target_sub_id,
        ) {
            let _ = config::save(&state.paths, &cfg);
            if let Ok(mut guard) = state.config.write() {
                *guard = Arc::new(cfg.clone());
            }
        }
    }
    let _ = remap_active_single_node_id_if_needed(&state, &outcome.id_remap)?;
    prune_node_health_pool_from_db(&state);
    let _ = trigger_reload_if_running(&app, &state, false).await;
    state.log_app_event(
        "info",
        "订阅",
        &format!(
            "已整合合并订阅组：迁入 {} 个节点，去重 {} 个，合并后目标组共 {} 个节点",
            outcome.moved_count, outcome.deduplicated_count, outcome.total_count
        ),
    );
    let cfg = state.snapshot_config();
    emit_groups_updated(&app);
    emit_nodes_updated(&app);
    emit_config_updated(&app, &cfg);
    sync_tray_and_window_side_effects(&app, &state, &cfg);
    Ok(outcome)
}


pub(in crate::commands) fn parse_controller_endpoint_and_secret(raw: &str) -> (String, Option<String>) {
    let trimmed = raw.trim();
    let (url_part, pipe_secret) = if let Some((left, right)) = trimmed.split_once("|secret=") {
        let sec = right.trim();
        (
            left.trim().to_string(),
            (!sec.is_empty()).then(|| sec.to_string()),
        )
    } else {
        (trimmed.to_string(), None)
    };

    let (clean_url, query_secret) = if let Some((base, query)) = url_part.split_once('?') {
        let mut kept_pairs = Vec::new();
        let mut found_secret = None;
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            if let Some((k, v)) = pair.split_once('=') {
                if k.eq_ignore_ascii_case("secret") {
                    let val = v.trim();
                    if !val.is_empty() {
                        found_secret = Some(val.to_string());
                    }
                    continue;
                }
            }
            kept_pairs.push(pair);
        }
        let rebuilt = if kept_pairs.is_empty() {
            base.to_string()
        } else {
            format!("{base}?{}", kept_pairs.join("&"))
        };
        (rebuilt, found_secret)
    } else {
        (url_part, None)
    };

    let base_no_slash = clean_url.trim_end_matches('/');
    let endpoint = if let Some((path_only, query)) = base_no_slash.split_once('?') {
        let p = path_only.trim_end_matches('/');
        if p.ends_with("/proxies") {
            format!("{p}?{query}")
        } else {
            format!("{p}/proxies?{query}")
        }
    } else if base_no_slash.ends_with("/proxies") {
        base_no_slash.to_string()
    } else {
        format!("{base_no_slash}/proxies")
    };

    (endpoint, pipe_secret.or(query_secret))
}


async fn refresh_process_adapter_subscription(
    state: &AppState,
    sub: &SubscriptionRecord,
) -> Result<ParsedSubscription, String> {
    let raw = sub.url_or_cmd.trim();
    if raw.is_empty() {
        return Err("来源地址或外部脚本命令不能为空，请先填写公开控制接口地址或适配器命令".to_string());
    }
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        let (endpoint, secret) = parse_controller_endpoint_and_secret(raw);
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| {
                tracing::warn!(
                    sub_id = %sub.id,
                    error = %app_log::sanitize_log_line(&e.to_string()),
                    "初始化控制接口请求客户端失败"
                );
                "初始化控制接口请求客户端失败，请稍后重试".to_string()
            })?;
        let mut req = client.get(&endpoint);
        if let Some(ref sec) = secret {
            req = req.bearer_auth(sec);
        }
        let mut resp = req.send().await.map_err(|e| {
            tracing::warn!(
                sub_id = %sub.id,
                endpoint = %app_log::sanitize_log_line(&endpoint),
                error = %app_log::sanitize_log_line(&e.to_string()),
                "连接代理控制接口失败"
            );
            if e.is_timeout() {
                "连接控制接口超时，请确认目标代理软件正在运行".to_string()
            } else {
                "无法连接到控制接口，请确认地址端口正确且目标代理软件已启动".to_string()
            }
        })?;
        let status = resp.status();
        if status.as_u16() == 401 || status.as_u16() == 403 {
            return Err(format!(
                "控制接口需要口令认证（HTTP {}），请在地址末尾附加 |secret=你的口令 后重试",
                status.as_u16()
            ));
        }
        if !status.is_success() {
            return Err(format!(
                "控制接口返回异常状态（HTTP {}），请确认该地址为有效的代理控制接口",
                status.as_u16()
            ));
        }
        const MAX_CTRL_BYTES: usize = 16 * 1024 * 1024;
        if let Some(len) = resp.content_length() {
            if len > MAX_CTRL_BYTES as u64 {
                return Err("控制接口返回数据超过 16 MiB 上限，已安全终止读取".to_string());
            }
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| {
            tracing::warn!(
                sub_id = %sub.id,
                error = %app_log::sanitize_log_line(&e.to_string()),
                "读取控制接口响应失败"
            );
            "读取控制接口响应失败，请确认目标代理软件运行正常后重试".to_string()
        })? {
            if body.len().saturating_add(chunk.len()) > MAX_CTRL_BYTES {
                return Err("控制接口返回数据超过 16 MiB 上限，已安全终止读取".to_string());
            }
            body.extend_from_slice(&chunk);
        }

        let (nodes, meta_only_count, total_entries, mut warnings) =
            parse_controller_proxies_json(&sub.id, &body)
                .map_err(|e| format_subscription_error_zh(&e.to_string()))?;
        if nodes.is_empty() {
            if meta_only_count > 0 {
                return Err(format!(
                    "已连通控制接口并识别到 {meta_only_count} 个节点名称，但该接口未公开服务器地址与端口（缺少 server/port），无法直接抓取可连接节点；请改用目标软件的本地 YAML 配置文件或外挂脚本适配器导入"
                ));
            }
            return Err(format!(
                "已连通控制接口，但未发现可用代理节点（共 {total_entries} 项均为内置项或分组）"
            ));
        }
        if meta_only_count > 0 {
            warnings.push(format!(
                "另有 {meta_only_count} 个节点因控制接口未公开 server/port 已跳过"
            ));
        }
        return Ok(ParsedSubscription {
            format: SubscriptionPayloadFormat::ClashYaml,
            nodes,
            userinfo: None,
            etag: None,
            warnings,
        });
    }

    let adapter_cfg = AdapterConfig::from_command_line(raw).map_err(|e| {
        tracing::warn!(
            sub_id = %sub.id,
            error = %app_log::sanitize_log_line(&e.to_string()),
            "外部适配器命令格式不正确"
        );
        "外部适配器命令格式不正确，请检查路径与引号配对".to_string()
    })?;
    let req = AdapterRequest::new(ADAPTER_REASON_MANUAL, sub.id.clone(), Vec::new());
    let nodes = invoke_external_adapter(&adapter_cfg, &req, Some(&state.adapter_cooldown))
        .await
        .map_err(|e| {
            let msg = e.to_string();
            tracing::warn!(
                sub_id = %sub.id,
                program = %app_log::sanitize_log_line(&adapter_cfg.program),
                error = %app_log::sanitize_log_line(&msg),
                "外部适配器执行失败"
            );
            if !msg.contains("cooldown") {
                state.adapter_cooldown.reset(&sub.id);
            }
            if msg.contains("cooldown") {
                "外部适配器刷新过于频繁，请稍候片刻再试".to_string()
            } else if msg.contains("failed to spawn") {
                "无法启动外部适配器程序，请确认命令路径正确且具有可执行权限".to_string()
            } else if msg.contains("timed out") {
                format!(
                    "外部适配器执行超时（超过 {} 秒），请检查脚本是否卡住",
                    adapter_cfg.timeout_sec
                )
            } else {
                "外部适配器未能返回有效节点，请确认脚本输出格式符合要求".to_string()
            }
        })?;
    Ok(ParsedSubscription {
        format: SubscriptionPayloadFormat::ClashYaml,
        nodes,
        userinfo: None,
        etag: None,
        warnings: Vec::new(),
    })
}


fn extract_local_system_proxy_url(spec: &SystemProxySpec) -> Option<String> {
    if !spec.enabled || spec.port == 0 {
        return None;
    }
    if spec
        .pac_url
        .as_deref()
        .map(str::trim)
        .is_some_and(|s| !s.is_empty())
    {
        return None;
    }
    let host_raw = spec.host.trim();
    if host_raw.is_empty() {
        return None;
    }
    if host_raw.contains("://") {
        let parsed = reqwest::Url::parse(host_raw).ok()?;
        let scheme = match parsed.scheme().to_ascii_lowercase().as_str() {
            "http" => "http",
            "https" => "https",
            "socks5" => "socks5",
            "socks5h" => "socks5h",
            _ => return None,
        };
        let port = parsed.port().unwrap_or(spec.port);
        if port == 0 {
            return None;
        }
        let host = parsed.host_str()?.trim();
        if host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" {
            return Some(format!("{scheme}://127.0.0.1:{port}"));
        }
        if host == "::1" || host == "[::1]" {
            return Some(format!("{scheme}://[::1]:{port}"));
        }
        return None;
    }
    let bare = host_raw.trim_start_matches('[').trim_end_matches(']');
    if bare.eq_ignore_ascii_case("localhost") || bare == "127.0.0.1" {
        Some(format!("http://127.0.0.1:{}", spec.port))
    } else if bare == "::1" {
        Some(format!("http://[::1]:{}", spec.port))
    } else {
        None
    }
}


/// Build deduplicated proxy fallback candidates for subscription fetching:
/// 1. Direct (`None`) first so domestic-accessible feeds refresh at full speed without detour.
/// 2. CatCloud main core local mixed port (`http://127.0.0.1:<mixed_port>`) when running.
/// 3. Active OS local loopback system proxy (`127.0.0.1` / `localhost` / `[::1]`) when distinct.
pub(in crate::commands) fn build_subscription_proxy_candidates_from(
    catcloud_mixed_port: Option<u16>,
    sys_proxy: Option<&SystemProxySpec>,
) -> Vec<Option<String>> {
    let mut out: Vec<Option<String>> = Vec::with_capacity(3);
    let mut seen: HashSet<String> = HashSet::new();

    // Always try direct first.
    out.push(None);

    let mut push_unique = |url: String| {
        let key = url.trim().trim_end_matches('/').to_ascii_lowercase();
        if !key.is_empty() && seen.insert(key) {
            out.push(Some(url));
        }
    };

    if let Some(port) = catcloud_mixed_port.filter(|&p| p > 0) {
        push_unique(format!("http://127.0.0.1:{port}"));
    }

    if let Some(spec) = sys_proxy {
        if let Some(local_proxy) = extract_local_system_proxy_url(spec) {
            push_unique(local_proxy);
        }
    }

    out
}


fn contains_cjk_char(text: &str) -> bool {
    text.chars().any(|c| ('\u{4E00}'..='\u{9FFF}').contains(&c))
}


const SAFE_SUBSCRIPTION_ZH_ASCII_TOKENS: &[&str] = &[
    "http",
    "https",
    "tls",
    "utf-8",
    "utf8",
    "yaml",
    "json",
    "mib",
    "kb",
    "mb",
    "gb",
    "base64",
    "uri",
    "url",
    "proxies",
    "outbounds",
    "sing-box",
    "clash",
    "mihomo",
    "server",
    "port",
    "secret",
    "4xx",
    "5xx",
];


fn has_embedded_http_url(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    for pat in ["http://", "https://"] {
        let mut rest = lower.as_str();
        while let Some(pos) = rest.find(pat) {
            let after = &rest[pos + pat.len()..];
            if after
                .as_bytes()
                .first()
                .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'[')
            {
                return true;
            }
            rest = after;
        }
    }
    false
}


/// Detect whether an error string still contains raw English exception tails (e.g. `（invalid ...）`,
/// `expected ...`, `dns error`, `connection refused`, `timed out`, `status 4xx/5xx`, OS errors, or
/// embedded URLs) so they are never leaked into user-facing prompts or SQLite `last_error`.
pub(in crate::commands) fn contains_english_error_residue(text: &str) -> bool {
    if has_embedded_http_url(text) {
        return true;
    }
    for token in text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-')) {
        let trimmed = token.trim_matches('-');
        let alpha_count = trimmed.bytes().filter(u8::is_ascii_alphabetic).count();
        if alpha_count < 2 {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if !SAFE_SUBSCRIPTION_ZH_ASCII_TOKENS.contains(&lower.as_str()) {
            return true;
        }
    }
    false
}


fn contains_http_status_code(text: &str, code: &str) -> bool {
    let bytes = text.as_bytes();
    let code_len = code.len();
    let mut offset = 0usize;
    while let Some(rel) = text[offset..].find(code) {
        let idx = offset + rel;
        let prev_ok = idx == 0 || !bytes[idx - 1].is_ascii_digit();
        let next_idx = idx + code_len;
        let next_ok = next_idx == bytes.len() || !bytes[next_idx].is_ascii_digit();
        if prev_ok && next_ok {
            return true;
        }
        offset = idx + 1;
    }
    false
}


/// Ensure subscription fetch/parse error strings persisted to SQLite and surfaced to users are
/// strictly clean, actionable plain Chinese. Any raw English error or mixed-language exception tail
/// is logged (sanitized) via `tracing::warn!` and mapped to a pure-Chinese category message.
pub(in crate::commands) fn format_subscription_error_zh(raw: &str) -> String {
    let cleaned = raw.replace(['\r', '\n'], " ").trim().to_string();
    if cleaned.is_empty() {
        return "拉取或解析订阅失败，请检查订阅链接是否有效".to_string();
    }
    if contains_cjk_char(&cleaned) && !contains_english_error_residue(&cleaned) {
        return cleaned;
    }

    tracing::warn!(
        raw_error = %app_log::sanitize_log_line(&cleaned),
        "订阅错误包含原始英文或未归类异常详情，已转为纯中文提示"
    );

    let lower = cleaned.to_ascii_lowercase();
    if lower.contains("timed out") || lower.contains("timeout") || cleaned.contains("超时") {
        "拉取订阅超时：直连与本机代理均未在规定时间内响应，请检查网络连接或开启代理后重试"
            .to_string()
    } else if lower.contains("dns")
        || lower.contains("failed to lookup")
        || lower.contains("no such host")
        || lower.contains("name or service not known")
        || cleaned.contains("域名无法解析")
    {
        "订阅域名解析失败：无法解析该订阅地址，请检查网络或开启代理后重试".to_string()
    } else if lower.contains("connection refused")
        || lower.contains("actively refused")
        || cleaned.contains("拒绝连接")
    {
        "连接订阅服务器或本地代理被拒绝，请确认订阅链接可用且本地代理正常运行".to_string()
    } else if lower.contains("connection reset")
        || lower.contains("forcibly closed")
        || lower.contains("unexpected eof")
        || lower.contains("broken pipe")
        || cleaned.contains("被对方重置")
        || cleaned.contains("意外中断")
    {
        "拉取订阅时连接被远端中断，可能需要通过代理访问该订阅链接".to_string()
    } else if lower.contains("certificate")
        || lower.contains("tls")
        || lower.contains("ssl")
        || lower.contains("handshake")
        || lower.contains("rustls")
        || lower.contains("openssl")
    {
        "拉取订阅时安全连接（TLS）握手失败，请检查系统时间或网络环境后重试".to_string()
    } else if lower.contains("too many redirects")
        || lower.contains("redirect")
        || cleaned.contains("重定向")
    {
        "订阅链接重定向次数过多，可能存在循环跳转，请检查订阅地址".to_string()
    } else if lower.contains("relative url")
        || lower.contains("empty host")
        || lower.contains("invalid url")
        || lower.contains("invalid port")
        || lower.contains("invalid domain")
        || lower.contains("invalid ipv")
        || lower.contains("invalid proxy")
        || cleaned.contains("链接格式不正确")
        || cleaned.contains("代理地址")
    {
        "订阅链接或代理地址格式不正确，请确认完整复制了 http:// 或 https:// 订阅地址".to_string()
    } else if contains_http_status_code(&lower, "401") || lower.contains("unauthorized") {
        "订阅认证失败（HTTP 401），链接里的访问令牌可能已失效或被重置".to_string()
    } else if contains_http_status_code(&lower, "403") || lower.contains("forbidden") {
        "订阅服务器拒绝访问（HTTP 403），可能被防火墙拦截、需要通过代理拉取或链接已失效"
            .to_string()
    } else if contains_http_status_code(&lower, "404") || lower.contains("not found") {
        "订阅地址不存在（HTTP 404），请确认复制了完整的订阅链接".to_string()
    } else if contains_http_status_code(&lower, "410") {
        "该订阅链接已被服务商下线（HTTP 410），请重新获取最新订阅地址".to_string()
    } else if contains_http_status_code(&lower, "429") || lower.contains("too many requests") {
        "订阅请求过于频繁（HTTP 429），请稍候片刻再试".to_string()
    } else if contains_http_status_code(&lower, "500")
        || contains_http_status_code(&lower, "502")
        || contains_http_status_code(&lower, "503")
        || contains_http_status_code(&lower, "504")
        || lower.contains("status 5")
        || lower.contains("5xx")
    {
        "订阅服务器暂时异常（HTTP 5xx），请稍后再试".to_string()
    } else if contains_http_status_code(&lower, "400")
        || lower.contains("status 4")
        || lower.contains("4xx")
    {
        "订阅服务器拒绝了本次请求（HTTP 4xx），请确认订阅链接有效且未失效".to_string()
    } else if lower.contains("no such file")
        || lower.contains("cannot find the file")
        || lower.contains("os error 2")
    {
        "未找到本地订阅文件，请确认文件未被移动或删除".to_string()
    } else if lower.contains("permission denied")
        || lower.contains("access is denied")
        || lower.contains("os error 5")
        || lower.contains("os error 13")
    {
        "无权限读取订阅来源，请检查文件或程序访问权限".to_string()
    } else if lower.contains("cooldown") {
        "订阅刷新过于频繁，请稍候片刻再试".to_string()
    } else if lower.contains("expected ")
        || lower.contains("invalid ")
        || lower.contains("missing field")
        || lower.contains("unknown variant")
        || lower.contains("yaml")
        || lower.contains("json")
        || lower.contains("base64")
        || lower.contains("utf-8")
        || lower.contains("decode")
        || lower.contains("parse")
        || cleaned.contains("解析")
    {
        "订阅内容格式无法解析，请确认该链接返回的是有效的节点订阅配置".to_string()
    } else if lower.contains("error sending request") || lower.contains("connect") {
        "无法连接到订阅服务器，请检查网络连接或开启代理后重试".to_string()
    } else {
        "拉取或解析订阅失败，请检查订阅链接是否有效或稍后重试".to_string()
    }
}


async fn refresh_single_subscription_inner(
    state: &AppState,
    sub: &SubscriptionRecord,
) -> Result<serde_json::Value, String> {
    let parsed = match sub.kind {
        SubscriptionKind::Url => {
            let live_rt = state.adapter.status().await;
            let catcloud_mixed_port = if live_rt.running && live_rt.mixed_port > 0 {
                Some(live_rt.mixed_port)
            } else {
                None
            };
            let sys_proxy = tokio::task::spawn_blocking(|| {
                default_platform().read_system_proxy().ok()
            })
            .await
            .ok()
            .flatten();
            let proxy_candidates = build_subscription_proxy_candidates_from(
                catcloud_mixed_port,
                sys_proxy.as_ref(),
            );
            let fetched = catcloud_core::subscription::parser::fetch_subscription_url_with_fallback(
                &sub.url_or_cmd,
                &proxy_candidates,
                &FetchOptions::default(),
            )
            .await
            .map_err(|e| format_subscription_error_zh(&e.to_string()))?;

            if let Some(ref used_proxy) = fetched.used_proxy {
                state.log_app_event(
                    "info",
                    "订阅",
                    &format!(
                        "订阅「{}」直连未通，已自动通过本地代理（{used_proxy}）拉取成功",
                        sub.name
                    ),
                );
            }

            let mut parsed = fetched
                .parse(&sub.id)
                .map_err(|e| format_subscription_error_zh(&e.to_string()))?;
            if parsed.etag.is_none() {
                parsed.etag = fetched.etag;
            }
            parsed
        }
        SubscriptionKind::File | SubscriptionKind::Migrated => {
            let raw = std::fs::read(&sub.url_or_cmd).map_err(|e| {
                tracing::warn!(
                    sub_id = %sub.id,
                    path = %app_log::sanitize_log_line(&sub.url_or_cmd),
                    error = %app_log::sanitize_log_line(&e.to_string()),
                    "读取本地订阅文件失败"
                );
                match e.kind() {
                    std::io::ErrorKind::NotFound => {
                        "未找到本地订阅文件，请确认文件未被移动或删除".to_string()
                    }
                    std::io::ErrorKind::PermissionDenied => {
                        "无权限读取本地订阅文件，请检查文件访问权限".to_string()
                    }
                    _ => "无法读取本地订阅文件，请确认文件路径有效且未被其它程序占用".to_string(),
                }
            })?;
            parse_subscription_payload(&sub.id, &raw, None)
                .map_err(|e| format_subscription_error_zh(&e.to_string()))?
        }
        SubscriptionKind::ProcessAdapter => {
            refresh_process_adapter_subscription(state, sub).await?
        }
    };

    let node_count = {
        let mut db = state.storage.lock().map_err(|e| {
            tracing::warn!(error = %app_log::sanitize_log_line(&e.to_string()), "锁定订阅数据库失败");
            "本地数据库繁忙，请稍后重试".to_string()
        })?;
        apply_parsed_subscription(&mut db, sub, &parsed)
            .map_err(|e| format_subscription_error_zh(&e.to_string()))?
    };
    let _ = ensure_default_group_if_empty(state);
    Ok(serde_json::json!({
        "sub_id": sub.id,
        "node_count": node_count,
        "updated_at": Utc::now().to_rfc3339(),
        "warnings": parsed.warnings
    }))
}


#[tauri::command]
pub async fn refresh_subscription(
    app: AppHandle,
    state: State<'_, AppState>,
    sub_id: String,
) -> Result<serde_json::Value, String> {
    let Some(_refresh_guard) = SubRefreshGuard::try_acquire(&state.refreshing_sub_ids, sub_id.clone())
    else {
        return Err("该订阅正在刷新中，请稍候完成后再试".to_string());
    };
    let sub = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        db.get_subscription(&sub_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("未找到指定订阅（{sub_id}）"))?
    };
    let result = refresh_single_subscription_inner(&state, &sub).await;
    match result {
        Err(err) => {
            let sanitized_err = app_log::sanitize_log_line(&format_subscription_error_zh(&err));
            if let Ok(db) = state.storage.lock() {
                let _ = db.update_subscription_refresh_status(
                    &sub.id,
                    None,
                    None,
                    Some(sanitized_err.as_str()),
                    None,
                    None,
                    None,
                );
            }
            state.log_app_event(
                "warn",
                "订阅",
                &format!("刷新订阅「{}」失败：{sanitized_err}", sub.name),
            );
            Err(sanitized_err)
        }
        Ok(val) => {
            let _ = remap_active_single_node_id_if_needed(&state, &HashMap::new());
            prune_node_health_pool_from_db(&state);
            let _ = trigger_reload_if_running(&app, &state, false).await;
            let cfg = state.snapshot_config();
            emit_groups_updated(&app);
            emit_nodes_updated(&app);
            emit_config_updated(&app, &cfg);
            sync_tray_and_window_side_effects(&app, &state, &cfg);
            Ok(val)
        }
    }
}


#[tauri::command]
pub async fn refresh_all_subscriptions(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let subs = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        db.list_subscriptions().map_err(|e| e.to_string())?
    };
    let mut refreshed = 0usize;
    let mut total_nodes = 0usize;
    let mut errors = Vec::new();
    for sub in subs.into_iter().filter(|s| s.enabled) {
        let Some(_refresh_guard) =
            SubRefreshGuard::try_acquire(&state.refreshing_sub_ids, sub.id.clone())
        else {
            continue;
        };
        match refresh_single_subscription_inner(&state, &sub).await {
            Ok(v) => {
                refreshed += 1;
                total_nodes += v.get("node_count").and_then(|c| c.as_u64()).unwrap_or(0) as usize;
            }
            Err(err) => {
                let sanitized_err = app_log::sanitize_log_line(&format_subscription_error_zh(&err));
                if let Ok(db) = state.storage.lock() {
                    let _ = db.update_subscription_refresh_status(
                        &sub.id,
                        None,
                        None,
                        Some(sanitized_err.as_str()),
                        None,
                        None,
                        None,
                    );
                }
                state.log_app_event(
                    "warn",
                    "订阅",
                    &format!("批量刷新订阅「{}」失败：{sanitized_err}", sub.name),
                );
                errors.push(format!("{}: {sanitized_err}", sub.name));
            }
        }
    }
    if refreshed > 0 {
        prune_node_health_pool_from_db(&state);
        let _ = trigger_reload_if_running(&app, &state, false).await;
        let cfg = state.snapshot_config();
        emit_config_updated(&app, &cfg);
        sync_tray_and_window_side_effects(&app, &state, &cfg);
    }
    Ok(serde_json::json!({
        "refreshed": refreshed,
        "total_nodes": total_nodes,
        "errors": errors
    }))
}


#[tauri::command]
pub async fn scan_local_migrations(
) -> Result<Vec<catcloud_core::subscription::migrator::MigrationPreview>, String> {
    tauri::async_runtime::spawn_blocking(catcloud_core::subscription::migrator::scan_local_clients)
        .await
        .map_err(|e| format!("扫描本地客户端配置任务异常中止：{e}"))
}


#[tauri::command]
pub async fn scan_migration_path(
    path: String,
) -> Result<Vec<catcloud_core::subscription::migrator::MigrationPreview>, String> {
    let trimmed = path.trim().to_string();
    if trimmed.is_empty() {
        return Err("请先选择需要扫描的配置文件或目录路径".to_string());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let target = std::path::Path::new(&trimmed);
        if !target.exists() {
            return Err(format!("指定路径不存在：{trimmed}"));
        }
        Ok(catcloud_core::subscription::migrator::scan_custom_path_readonly(target))
    })
    .await
    .map_err(|e| format!("扫描指定迁移路径任务异常中止：{e}"))?
}


#[tauri::command]
pub fn preview_migration_from_text(
    name: String,
    raw_yaml: String,
) -> Result<serde_json::Value, String> {
    let preview = core_preview_from_text(&raw_yaml).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "name": name,
        "node_count": preview.nodes.len(),
        "nodes": preview.nodes,
        "prepend_rules": preview.prepend_rules,
        "append_rules": preview.append_rules,
        "warnings": preview.warnings
    }))
}


pub(in crate::commands) fn persist_migration_nodes(
    storage: &mut Storage,
    source_name: String,
    mut nodes: Vec<ProxyNode>,
) -> Result<(String, usize), String> {
    if nodes.is_empty() {
        return Err("未解析到可导入的节点，已取消导入".to_string());
    }
    let sub_id = format!("migrated-{}", uuid::Uuid::new_v4().simple());
    catcloud_core::subscription::migrator::rebind_migration_nodes(&sub_id, &mut nodes);
    let sub = SubscriptionRecord {
        id: sub_id.clone(),
        name: if source_name.trim().is_empty() {
            "迁移导入".to_string()
        } else {
            source_name
        },
        kind: SubscriptionKind::Migrated,
        url_or_cmd: "local://migrated".to_string(),
        last_ok_at: Some(Utc::now().to_rfc3339()),
        enabled: true,
        ..SubscriptionRecord::default()
    };
    storage.upsert_subscription(&sub).map_err(|e| e.to_string())?;
    let count = storage.upsert_nodes_batch(&nodes).map_err(|e| e.to_string())?;
    Ok((sub_id, count))
}


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationApplyOutcome {
    pub imported_count: usize,
    pub sub_id: String,
    #[serde(default)]
    pub saved_rules_count: usize,
    #[serde(default)]
    pub dropped_dangling_rules_count: usize,
    #[serde(default)]
    pub rewritten_dangling_rules_count: usize,
    #[serde(default)]
    pub dropped_dangling_targets: Vec<(String, usize)>,
}


async fn apply_migration_nodes_with_meta_internal(
    app: &AppHandle,
    state: &AppState,
    source_name: String,
    nodes: Vec<ProxyNode>,
    include_rules: bool,
    prepend_rules: Vec<String>,
    append_rules: Vec<String>,
    dangling_rule_policy: Option<String>,
) -> Result<MigrationApplyOutcome, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    let (sub_id, count) = {
        let mut db = state.storage.lock().map_err(|e| e.to_string())?;
        persist_migration_nodes(&mut db, source_name, nodes)?
    };
    prune_node_health_pool_from_db(state);
    let created_default_group = ensure_default_group_if_empty(state);

    let mut rule_outcome = catcloud_core::subscription::MigrationRuleApplyOutcome::default();
    if include_rules && (!prepend_rules.is_empty() || !append_rules.is_empty()) {
        let (all_groups, all_nodes) = {
            let db = state.storage.lock().map_err(|e| e.to_string())?;
            let g = db.list_multi_groups().map_err(|e| e.to_string())?;
            let n = db.list_nodes().map_err(|e| e.to_string())?;
            (g, n)
        };
        let mut cfg = state.clone_config();
        let policy = match dangling_rule_policy
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("rewrite" | "rewrite_default") => {
                let fallback = catcloud_core::core_adapter::resolve_default_fallback_group_name(
                    &cfg,
                    &all_groups,
                );
                catcloud_core::subscription::MigrationDanglingRulePolicy::RewriteTo(fallback)
            }
            _ => catcloud_core::subscription::MigrationDanglingRulePolicy::Drop,
        };
        rule_outcome = catcloud_core::subscription::apply_migration_rules_for_subscription(
            &mut cfg,
            &sub_id,
            &prepend_rules,
            &append_rules,
            &all_groups,
            &all_nodes,
            policy,
        );
        if rule_outcome.added_prepend > 0 || rule_outcome.added_append > 0 {
            config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
            if let Ok(mut guard) = state.config.write() {
                *guard = Arc::new(cfg.clone());
            }
        }
        if rule_outcome.dropped_dangling_count > 0 {
            let target_list: Vec<String> = rule_outcome
                .dropped_targets
                .iter()
                .take(3)
                .map(|(t, c)| format!("「{t}」({c} 条)"))
                .collect();
            state.log_app_event(
                "info",
                "迁移导入",
                &format!(
                    "导入规则时已自动过滤 {} 条指向不存在分组的旧规则（{}），避免阻断核心启动",
                    rule_outcome.dropped_dangling_count,
                    target_list.join("、")
                ),
            );
        }
    }

    if let Some(outcome) = trigger_reload_if_running(app, state, false).await {
        if outcome.rejected {
            let detail = outcome
                .error
                .as_deref()
                .map(format_mihomo_error_for_user)
                .unwrap_or_else(|| "未知原因".to_string());
            state.log_app_event(
                "warning",
                "迁移导入",
                &format!("已导入 {count} 个节点，但热重载核心配置未通过：{detail}"),
            );
        }
    }
    let cfg = state.snapshot_config();
    emit_config_updated(app, &cfg);
    if created_default_group {
        emit_groups_updated(app);
    }
    sync_tray_and_window_side_effects(app, state, &cfg);
    Ok(MigrationApplyOutcome {
        imported_count: count,
        sub_id,
        saved_rules_count: rule_outcome.added_prepend + rule_outcome.added_append,
        dropped_dangling_rules_count: rule_outcome.dropped_dangling_count,
        rewritten_dangling_rules_count: rule_outcome.rewritten_dangling_count,
        dropped_dangling_targets: rule_outcome.dropped_targets,
    })
}


#[tauri::command]
pub async fn apply_migration_nodes_with_meta(
    app: AppHandle,
    state: State<'_, AppState>,
    source_name: String,
    nodes: Vec<ProxyNode>,
    include_rules: Option<bool>,
    prepend_rules: Option<Vec<String>>,
    append_rules: Option<Vec<String>>,
    dangling_rule_policy: Option<String>,
) -> Result<MigrationApplyOutcome, String> {
    apply_migration_nodes_with_meta_internal(
        &app,
        &state,
        source_name,
        nodes,
        include_rules.unwrap_or(false),
        prepend_rules.unwrap_or_default(),
        append_rules.unwrap_or_default(),
        dangling_rule_policy,
    )
    .await
}


#[tauri::command]
pub async fn apply_migration_nodes(
    app: AppHandle,
    state: State<'_, AppState>,
    source_name: String,
    nodes: Vec<ProxyNode>,
) -> Result<usize, String> {
    apply_migration_nodes_with_meta_internal(
        &app,
        &state,
        source_name,
        nodes,
        false,
        Vec::new(),
        Vec::new(),
        None,
    )
    .await
    .map(|o| o.imported_count)
}


#[tauri::command]
pub fn list_running_processes(
    only_likely_proxy: bool,
) -> Vec<catcloud_core::subscription::process_attach::ProcessCandidate> {
    catcloud_core::subscription::process_attach::list_process_candidates(only_likely_proxy)
}


#[tauri::command]
pub async fn inspect_process_source(pid: u32) -> Result<serde_json::Value, String> {
    let candidates = catcloud_core::subscription::process_attach::list_process_candidates(false);
    let candidate = candidates
        .into_iter()
        .find(|p| p.pid == pid)
        .ok_or_else(|| format!("未找到对应进程（PID {pid}）"))?;
    let report = core_inspect_process_source(&candidate).await;
    serde_json::to_value(report).map_err(|e| e.to_string())
}


#[tauri::command]
pub async fn list_desktop_app_candidates(
    state: State<'_, AppState>,
    baseline_pids: Option<Vec<u32>>,
) -> Result<Vec<DesktopAppCandidate>, String> {
    let baseline: Option<HashSet<u32>> = baseline_pids.map(|v| v.into_iter().collect());
    let self_data_dir = state.paths.root_data_dir.clone();
    tauri::async_runtime::spawn_blocking(move || {
        core_list_desktop_app_candidates(baseline.as_ref(), Some(self_data_dir.as_path()))
    })
    .await
    .map_err(|e| format!("枚举桌面软件列表失败：{e}"))
}


#[tauri::command]
pub async fn start_live_capture_session(
    state: State<'_, AppState>,
    target_pid: u32,
) -> Result<LiveCaptureStartDto, String> {
    let mgr = Arc::clone(&state.live_capture);
    let self_data_dir = state.paths.root_data_dir.clone();
    tauri::async_runtime::spawn_blocking(move || mgr.start_session(target_pid, Some(self_data_dir)))
        .await
        .map_err(|e| format!("启动实时捕捉会话失败：{e}"))?
        .map_err(|e| e.to_string())
}


#[tauri::command]
pub fn poll_live_capture_session(
    state: State<'_, AppState>,
    session_id: String,
) -> Result<LiveCaptureStatusDto, String> {
    state
        .live_capture
        .poll_session(&session_id)
        .map_err(|e| e.to_string())
}


#[tauri::command]
pub async fn finish_live_capture_session(
    state: State<'_, AppState>,
    session_id: String,
) -> Result<LiveCaptureOutcomeDto, String> {
    let mgr = Arc::clone(&state.live_capture);
    tauri::async_runtime::spawn_blocking(move || mgr.finish_session(&session_id))
        .await
        .map_err(|e| format!("整理实时捕捉结果失败：{e}"))?
        .map_err(|e| e.to_string())
}


#[tauri::command]
pub async fn cancel_live_capture_session(
    state: State<'_, AppState>,
    session_id: String,
) -> Result<bool, String> {
    let mgr = Arc::clone(&state.live_capture);
    tauri::async_runtime::spawn_blocking(move || mgr.cancel_session(&session_id))
        .await
        .map_err(|e| format!("取消实时捕捉失败: {e}"))
}

