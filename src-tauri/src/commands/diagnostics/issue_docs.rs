use std::collections::HashSet;
use std::sync::Arc;
use catcloud_core::core_adapter::CoreRuntimeStatus;
use catcloud_core::models::AppConfig;
use catcloud_core::models::MultiGroup;
use catcloud_core::models::PreAccelRelay;
use catcloud_core::models::ProxyNode;
use catcloud_core::models::SubscriptionRecord;
use catcloud_core::platform::default_platform;
use catcloud_core::preaccel::global_tunnel::GlobalPreAccelStatus;
use catcloud_core::AppPaths;
use serde::Deserialize;
use serde::Serialize;
use tauri::AppHandle;
use tauri::State;
use crate::app_log;

use crate::commands::diagnostics::report::DIAGNOSTICS_DISK_SCAN_LIMIT;
use crate::commands::diagnostics::report::format_geodata_brief_localized;
use crate::commands::diagnostics::report::merge_diagnostic_key_events;
use crate::commands::diagnostics::report::merge_sanitized_recent_logs;
use crate::commands::diagnostics::report::resolve_effective_doc_lang;
use crate::commands::diagnostics::report::resolve_local_cli_path;
use crate::commands::diagnostics::report::sanitize_log_text;
use crate::commands::geo_backup::collect_geodata_status;
use crate::commands::state::AppState;
use crate::commands::state::percent_encode_query_value;
use crate::commands::state::sanitize_dialog_filename_stem;
use crate::commands::tray_runtime::is_tun_privilege_ready;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentModuleDocDto {
    pub id: String,
    pub module_id: String,
    pub file_name: String,
    pub lang: String,
    pub title: String,
    pub summary: String,
    pub when_to_use_and_signals: Vec<String>,
    pub external_prereqs_and_schema: Vec<String>,
    pub gui_and_cli_verification: Vec<String>,
    pub rollback_and_troubleshooting: Vec<String>,
    pub contract_example: String,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentBootstrapPromptDto {
    pub prompt: String,
    pub cli_path: String,
    pub data_dir: String,
    pub docs_index_path: String,
    pub lang: String,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportAgentDocOutcome {
    pub cancelled: bool,
    pub path: Option<String>,
    pub bytes: usize,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GithubIssueDraftDto {
    pub issue_url: String,
    pub clipboard_markdown: String,
    pub title: String,
}


fn canonical_agent_doc_filename(module_id: &str) -> &'static str {
    match catcloud_core::agent_docs::resolve_canonical_doc_id(module_id)
        .unwrap_or(module_id)
    {
        catcloud_core::agent_docs::TROUBLESHOOTING_DOC_ID => "00-general-troubleshooting.md",
        catcloud_core::agent_docs::ONBOARDING_DOC_ID => "01-onboarding.md",
        catcloud_core::agent_docs::PREACCEL_DOC_ID => "02-domestic-preaccel.md",
        catcloud_core::agent_docs::MULTIGROUP_DOC_ID => "03-multigroup.md",
        catcloud_core::agent_docs::NODES_PROBES_DOC_ID => "04-nodes-and-probes.md",
        catcloud_core::agent_docs::ROUTING_CONNS_DOC_ID => "05-routing-and-connections.md",
        catcloud_core::agent_docs::NETWORK_LIFECYCLE_DOC_ID => "06-network-and-lifecycle.md",
        catcloud_core::agent_docs::SHARE_BUNDLE_DOC_ID => "07-share-bundle.md",
        _ => "00-general-troubleshooting.md",
    }
}


#[tauri::command]
pub fn list_agent_docs(
    state: State<'_, AppState>,
    lang: Option<String>,
) -> Vec<AgentModuleDocDto> {
    let norm_lang = resolve_effective_doc_lang(&state, lang.as_deref());
    catcloud_core::agent_docs::list_agent_docs_for_lang(norm_lang)
        .into_iter()
        .map(|doc| {
            let file_name = canonical_agent_doc_filename(&doc.module_id).to_string();
            AgentModuleDocDto {
                id: doc.module_id.clone(),
                module_id: doc.module_id,
                file_name,
                lang: norm_lang.to_string(),
                title: doc.title,
                summary: doc.summary,
                when_to_use_and_signals: doc.when_to_use_and_signals,
                external_prereqs_and_schema: doc.external_prereqs_and_schema,
                gui_and_cli_verification: doc.gui_and_cli_verification,
                rollback_and_troubleshooting: doc.rollback_and_troubleshooting,
                contract_example: doc.contract_example,
            }
        })
        .collect()
}


#[tauri::command]
pub fn export_agent_docs(
    state: State<'_, AppState>,
    module_id: String,
    as_json: bool,
    lang: Option<String>,
) -> Result<String, String> {
    let norm_lang = resolve_effective_doc_lang(&state, lang.as_deref());
    catcloud_core::agent_docs::export_agent_docs_with_lang(&module_id, as_json, norm_lang)
        .map_err(|e| e.to_string())
}


#[tauri::command]
pub async fn build_agent_bootstrap_prompt(
    state: State<'_, AppState>,
    lang: Option<String>,
    current_page: Option<String>,
    mode: Option<String>,
) -> Result<AgentBootstrapPromptDto, String> {
    let norm_lang = resolve_effective_doc_lang(&state, lang.as_deref());
    let cli_path = resolve_local_cli_path(&state).to_string_lossy().to_string();
    let data_dir_pb = catcloud_core::paths::normalize_os_path(&state.paths.root_data_dir);
    let data_dir = data_dir_pb.to_string_lossy().to_string();
    let docs_index_pb = data_dir_pb.join("agent_docs").join(norm_lang).join("INDEX.md");

    if !docs_index_pb.is_file() {
        let sync_root = data_dir_pb.clone();
        let _ = tokio::task::spawn_blocking(move || {
            catcloud_core::agent_docs::sync_agent_docs_to_disk(&sync_root)
        })
        .await;
    }

    let docs_index_path = docs_index_pb.to_string_lossy().to_string();
    let page = current_page.as_deref().unwrap_or("overview");
    let prompt_mode = catcloud_core::agent_docs::AgentPromptMode::from_opt_str(mode.as_deref());
    let prompt = catcloud_core::agent_docs::render_agent_bootstrap_prompt_with_mode(
        &cli_path,
        &data_dir,
        &docs_index_path,
        page,
        norm_lang,
        prompt_mode,
    );

    Ok(AgentBootstrapPromptDto {
        prompt,
        cli_path,
        data_dir,
        docs_index_path,
        lang: norm_lang.to_string(),
    })
}


#[tauri::command]
pub async fn export_agent_doc_file_dialog(
    app: AppHandle,
    state: State<'_, AppState>,
    module_id: String,
    lang: Option<String>,
) -> Result<ExportAgentDocOutcome, String> {
    use tauri_plugin_dialog::DialogExt;

    let norm_lang = resolve_effective_doc_lang(&state, lang.as_deref());
    let content = catcloud_core::agent_docs::export_agent_docs_with_lang(
        &module_id,
        false,
        norm_lang,
    )
    .map_err(|e| e.to_string())?;

    let trimmed_mod = module_id.trim().to_ascii_lowercase();
    let default_filename = if trimmed_mod.is_empty() || trimmed_mod == "all" {
        format!("catcloud-guide-all-{norm_lang}.md")
    } else if let Some(canonical) = catcloud_core::agent_docs::resolve_canonical_doc_id(&trimmed_mod)
    {
        canonical_agent_doc_filename(canonical).to_string()
    } else {
        format!(
            "catcloud-guide-{}-{norm_lang}.md",
            sanitize_dialog_filename_stem(&trimmed_mod, "doc")
        )
    };

    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_title("导出猫猫云梯权威手册 (.md)")
        .set_file_name(&default_filename)
        .add_filter("Markdown 文档", &["md"])
        .save_file(move |file_path| {
            let _ = tx.send(file_path);
        });

    let picked = rx.await.map_err(|_| "导出手册已取消".to_string())?;
    let Some(file_path) = picked else {
        return Ok(ExportAgentDocOutcome {
            cancelled: true,
            path: None,
            bytes: 0,
        });
    };
    let mut target_path = file_path
        .into_path()
        .map_err(|e| format!("无法解析所选保存路径：{e}"))?;
    if target_path
        .extension()
        .and_then(|e| e.to_str())
        .is_none_or(|ext| !ext.eq_ignore_ascii_case("md"))
    {
        target_path.set_extension("md");
    }

    let bytes = content.len();
    let write_path = target_path.clone();
    tokio::task::spawn_blocking(move || AppPaths::atomic_write(&write_path, content.as_bytes()))
        .await
        .map_err(|e| format!("保存手册文件任务异常：{e}"))?
        .map_err(|e| format!("写入手册文件失败：{e}"))?;

    Ok(ExportAgentDocOutcome {
        cancelled: false,
        path: Some(target_path.to_string_lossy().to_string()),
        bytes,
    })
}


pub(in crate::commands) const GITHUB_ISSUE_URL_BODY_MAX_CHARS: usize = 600;

const GITHUB_ISSUE_KEY_EVENTS_LIMIT: usize = 12;


fn is_generic_protocol_or_mode_token(token: &str) -> bool {
    matches!(
        token.trim().to_ascii_lowercase().as_str(),
        "rule"
            | "global"
            | "direct"
            | "reject"
            | "proxy"
            | "auto"
            | "default"
            | "group"
            | "single"
            | "ok"
            | "warn"
            | "error"
            | "idle"
            | "http"
            | "https"
            | "socks"
            | "socks5"
            | "tcp"
            | "udp"
            | "tun"
            | "dns"
            | "ip"
            | "cn"
            | "us"
            | "jp"
            | "hk"
            | "sg"
            | "tw"
            | "uk"
            | "de"
            | "fr"
            | "kr"
            | "mihomo"
            | "catcloud"
            | "windows"
            | "macos"
            | "linux"
    )
}


fn replace_ascii_case_insensitive(haystack: &str, needle: &str, replacement: &str) -> String {
    if needle.is_empty() || !needle.is_ascii() {
        return haystack.replace(needle, replacement);
    }
    let needle_bytes = needle.as_bytes();
    let h_bytes = haystack.as_bytes();
    if needle_bytes.len() > h_bytes.len() {
        return haystack.to_string();
    }
    let mut out = String::with_capacity(haystack.len());
    let mut i = 0;
    while i < h_bytes.len() {
        if i + needle_bytes.len() <= h_bytes.len()
            && h_bytes[i..i + needle_bytes.len()].eq_ignore_ascii_case(needle_bytes)
        {
            out.push_str(replacement);
            i += needle_bytes.len();
        } else {
            let ch = haystack[i..].chars().next().unwrap_or(' ');
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}


/// Strip all user-defined node / multi-group / relay / subscription remark names from text
/// and apply full `sanitize_log_line` redaction so public GitHub Issues never leak private names.
fn strip_user_custom_labels(raw: &str, custom_labels: &[String]) -> String {
    let mut labels: Vec<String> = Vec::with_capacity(custom_labels.len() * 2);
    let mut seen: HashSet<String> = HashSet::new();
    for raw_label in custom_labels {
        let trimmed = raw_label.trim();
        if trimmed.chars().count() < 2 || is_generic_protocol_or_mode_token(trimmed) {
            continue;
        }
        if seen.insert(trimmed.to_string()) {
            labels.push(trimmed.to_string());
        }
        let sanitized_variant = app_log::sanitize_log_line(trimmed);
        let sv_trim = sanitized_variant.trim();
        if sv_trim.chars().count() >= 2
            && !is_generic_protocol_or_mode_token(sv_trim)
            && seen.insert(sv_trim.to_string())
        {
            labels.push(sv_trim.to_string());
        }
    }
    labels.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));

    let mut out = raw.to_string();
    for label in &labels {
        if label.is_ascii() {
            out = replace_ascii_case_insensitive(&out, label, "<REDACTED_NAME>");
        } else {
            out = out.replace(label.as_str(), "<REDACTED_NAME>");
        }
    }
    sanitize_log_text(&out)
}


fn sanitize_github_repo_slug(raw: &str) -> String {
    let trimmed = raw.trim().trim_matches('/');
    let mut parts = trimmed.split('/');
    let owner = parts.next().unwrap_or("");
    let repo = parts.next().unwrap_or("");
    let extra = parts.next();
    let valid_part = |s: &str| {
        !s.is_empty()
            && s.len() <= 80
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    };
    if extra.is_none() && valid_part(owner) && valid_part(repo) {
        format!("{owner}/{repo}")
    } else {
        "JuryBu/CatCloud".to_string()
    }
}


fn truncate_chars_with_ellipsis(raw: &str, max_chars: usize) -> String {
    let count = raw.chars().count();
    if count <= max_chars {
        return raw.to_string();
    }
    if max_chars <= 1 {
        return "…".to_string();
    }
    let prefix: String = raw.chars().take(max_chars - 1).collect();
    format!("{prefix}…")
}


#[allow(clippy::too_many_arguments)]
pub(in crate::commands) fn build_github_issue_draft(
    repo_slug: &str,
    app_version: &str,
    os_label: &str,
    is_elevated: bool,
    tun_privilege_ready: bool,
    is_portable: bool,
    cfg: &AppConfig,
    rt: &CoreRuntimeStatus,
    global_status: &GlobalPreAccelStatus,
    counts: (usize, usize, usize, usize),
    geodata_status: &serde_json::Value,
    last_error: Option<&str>,
    key_event_logs: &[String],
    custom_labels: &[String],
    summary: Option<&str>,
    lang: &str,
) -> GithubIssueDraftDto {
    let norm_lang = catcloud_core::agent_docs::normalize_doc_lang(Some(lang));
    let repo = sanitize_github_repo_slug(repo_slug);
    let (sub_count, node_count, group_count, relay_count) = counts;

    let clean_summary = summary
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            strip_user_custom_labels(s, custom_labels)
                .replace(['\r', '\n'], " ")
                .trim()
                .to_string()
        })
        .filter(|s| !s.is_empty());

    let title = match (&clean_summary, norm_lang) {
        (Some(s), "en") => format!("[Feedback] {}", truncate_chars_with_ellipsis(s, 64)),
        (Some(s), "ja") => format!("[報告] {}", truncate_chars_with_ellipsis(s, 64)),
        (Some(s), "ru") => format!("[Отзыв] {}", truncate_chars_with_ellipsis(s, 64)),
        (Some(s), _) => format!("[反馈] {}", truncate_chars_with_ellipsis(s, 64)),
        (None, "en") => "[Feedback] CatCloud issue report".to_string(),
        (None, "ja") => "[報告] CatCloud 不具合・質問レポート".to_string(),
        (None, "ru") => "[Отзыв] Сообщение о проблеме CatCloud".to_string(),
        (None, _) => "[反馈] 猫猫云梯使用问题反馈".to_string(),
    };

    let eff_tun = cfg.tun.enabled && tun_privilege_ready;
    let tun_need_elev = cfg.tun.enabled && !tun_privilege_ready;
    let tun_active = rt.running && eff_tun;
    let tun_display_zh = if eff_tun {
        "true"
    } else if tun_need_elev {
        "false (已勾选但需管理员权限)"
    } else {
        "false"
    };
    let tun_display_en = if eff_tun {
        "true"
    } else if tun_need_elev {
        "false (configured, needs_elevation)"
    } else {
        "false"
    };
    let tun_url_flag = if eff_tun {
        "true"
    } else if tun_need_elev {
        "needs_elevation"
    } else {
        "false"
    };
    let preaccel_state = if !cfg.preaccel.enabled && !global_status.running {
        "off"
    } else if global_status.is_windivert_active {
        "windivert_active"
    } else if global_status.running {
        "socks5_running"
    } else if tun_active {
        "managed_by_tun"
    } else {
        "enabled_idle"
    };
    let core_version = rt.version.as_deref().unwrap_or("unknown");
    let clean_last_error = last_error
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| strip_user_custom_labels(s, custom_labels))
        .unwrap_or_else(|| "none".to_string());

    let clean_events: Vec<String> = key_event_logs
        .iter()
        .rev()
        .take(GITHUB_ISSUE_KEY_EVENTS_LIMIT)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|line| strip_user_custom_labels(line, custom_labels))
        .collect();
    let events_block = if clean_events.is_empty() {
        "(no recent non-traffic key events)".to_string()
    } else {
        clean_events.join("\n")
    };
    let is_zh = norm_lang == "zh-CN";
    let geodata_brief = format_geodata_brief_localized(geodata_status, is_zh);
    let core_state = if rt.running { "running" } else { "stopped" };

    let clipboard_markdown = if is_zh {
        let summary_section = clean_summary
            .as_deref()
            .unwrap_or("（请简述遇到的问题、预期结果与复现步骤）");
        format!(
            "### 环境信息（已自动脱敏，已剥离自定义节点/分组/中转备注名）\n\
             - CatCloud 版本：`v{app_version}`（便携模式：`{is_portable}` · 管理员权限：`{is_elevated}`）\n\
             - 操作系统：`{os_label}`\n\
             - 代理核心：`{core_state}`（Mihomo `{core_version}`）\n\
             - 代理模式 / 路由方式：`{}` / `{}`\n\
             - 流量接管：系统代理=`{}` · 虚拟网卡(TUN)=`{}`（协议栈 `{}`）\n\
             - 国内提速：开关=`{}` · 状态=`{preaccel_state}` · 探测=`{}`\n\
             - 本地资产数量：订阅 `{sub_count}` · 节点 `{node_count}` · 多选组 `{group_count}` · 中转 `{relay_count}`\n\
             - GeoData：{geodata_brief}\n\
             \n\
             ### 问题描述与复现步骤\n\
             {summary_section}\n\
             \n\
             ### 最近脱敏异常\n\
             ```text\n\
             {clean_last_error}\n\
             ```\n\
             \n\
             ### 最近关键事件（最多 {GITHUB_ISSUE_KEY_EVENTS_LIMIT} 条，已脱敏并剥离自定义备注名）\n\
             ```text\n\
             {events_block}\n\
             ```\n",
            cfg.proxy_mode.as_str(),
            cfg.route_mode.as_str(),
            cfg.system_proxy.enabled,
            tun_display_zh,
            cfg.tun.stack_mode.as_str(),
            cfg.preaccel.enabled,
            global_status.verify_state,
        )
    } else {
        let summary_section = clean_summary
            .as_deref()
            .unwrap_or("(Please describe the issue, expected behavior, and reproduction steps)");
        format!(
            "### Environment (auto-sanitized; custom node/group/relay/provider labels stripped)\n\
             - CatCloud version: `v{app_version}` (portable: `{is_portable}`, elevated: `{is_elevated}`)\n\
             - OS: `{os_label}`\n\
             - Proxy core: `{core_state}` (Mihomo `{core_version}`)\n\
             - Proxy / Route mode: `{}` / `{}`\n\
             - Traffic takeover: system_proxy=`{}` · TUN=`{}` (stack `{}`)\n\
             - Domestic acceleration: enabled=`{}` · state=`{preaccel_state}` · verify=`{}`\n\
             - Local asset counts: subscriptions `{sub_count}` · nodes `{node_count}` · groups `{group_count}` · relays `{relay_count}`\n\
             - GeoData: {geodata_brief}\n\
             \n\
             ### Issue Summary & Reproduction Steps\n\
             {summary_section}\n\
             \n\
             ### Recent Sanitized Error\n\
             ```text\n\
             {clean_last_error}\n\
             ```\n\
             \n\
             ### Recent Key Events (up to {GITHUB_ISSUE_KEY_EVENTS_LIMIT}, sanitized & stripped of custom labels)\n\
             ```text\n\
             {events_block}\n\
             ```\n",
            cfg.proxy_mode.as_str(),
            cfg.route_mode.as_str(),
            cfg.system_proxy.enabled,
            tun_display_en,
            cfg.tun.stack_mode.as_str(),
            cfg.preaccel.enabled,
            global_status.verify_state,
        )
    };

    // Keep URL `body` strictly <= 600 chars (both raw char count and URL-encoded length)
    // to prevent Windows ShellExecuteW URL truncation.
    let build_short_url_body = |sum_limit: usize| -> String {
        let sum_line = match &clean_summary {
            Some(s) if sum_limit > 0 => truncate_chars_with_ellipsis(s, sum_limit),
            _ => {
                if is_zh {
                    "(请简述复现步骤)".to_string()
                } else {
                    "(Briefly describe steps to reproduce)".to_string()
                }
            }
        };
        let env_line = format!(
            "Env: CatCloud v{app_version} | {os_label} | mode={} | core={core_state} | tun={} | preaccel={preaccel_state}",
            cfg.proxy_mode.as_str(),
            tun_url_flag,
        );
        if is_zh {
            format!(
                "### Issue\n{sum_line}\n\n### Diagnostics\n{env_line}\n(详细脱敏摘要已复制到剪贴板，请直接 Ctrl+V 粘贴)"
            )
        } else {
            format!(
                "### Summary\n{sum_line}\n\n### Sanitized Diagnostics\n{env_line}\n(Detailed sanitized report copied to clipboard - press Ctrl+V here)"
            )
        }
    };

    let mut sum_limit = 40usize;
    let mut url_body = build_short_url_body(sum_limit);
    while url_body.chars().count() > GITHUB_ISSUE_URL_BODY_MAX_CHARS
        || percent_encode_query_value(&url_body).len() > GITHUB_ISSUE_URL_BODY_MAX_CHARS
    {
        if sum_limit == 0 {
            url_body = format!(
                "Env: CatCloud v{app_version} | {os_label} | mode={} | core={}\n(Paste sanitized report from clipboard via Ctrl+V)",
                cfg.proxy_mode.as_str(),
                if rt.running { "running" } else { "stopped" },
            );
            if url_body.chars().count() > GITHUB_ISSUE_URL_BODY_MAX_CHARS {
                url_body = truncate_chars_with_ellipsis(&url_body, GITHUB_ISSUE_URL_BODY_MAX_CHARS);
            }
            break;
        }
        sum_limit = sum_limit.saturating_sub(8);
        url_body = build_short_url_body(sum_limit);
    }

    let issue_url = format!(
        "https://github.com/{repo}/issues/new?title={}&body={}",
        percent_encode_query_value(&title),
        percent_encode_query_value(&url_body),
    );

    GithubIssueDraftDto {
        issue_url,
        clipboard_markdown,
        title,
    }
}


pub(in crate::commands) fn collect_github_issue_custom_labels(
    subs: &[SubscriptionRecord],
    nodes: &[ProxyNode],
    groups: &[MultiGroup],
    relays: &[PreAccelRelay],
) -> Vec<String> {
    let mut labels: Vec<String> = Vec::with_capacity(
        subs.len() + nodes.len() + groups.len() + relays.len() * 2,
    );
    labels.extend(subs.iter().map(|s| s.name.clone()));
    labels.extend(nodes.iter().map(|n| n.name.clone()));
    labels.extend(groups.iter().map(|g| g.name.clone()));
    labels.extend(relays.iter().map(|r| r.name.clone()));
    labels.extend(
        relays
            .iter()
            .map(|r| r.provider.trim())
            .filter(|p| !p.is_empty())
            .map(str::to_string),
    );
    labels
}


#[tauri::command]
pub async fn build_github_issue_url(
    state: State<'_, AppState>,
    summary: Option<String>,
    lang: Option<String>,
) -> Result<GithubIssueDraftDto, String> {
    let norm_lang = resolve_effective_doc_lang(&state, lang.as_deref());
    let cfg = state.snapshot_config();
    let rt = state.snapshot_runtime();
    let plat = default_platform();
    let caps = plat.capabilities();
    let global_status = state.snapshot_global_preaccel();
    let geodata_status = collect_geodata_status(&state.paths.runtime_dir);

    let (counts, custom_labels) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let subs = db.list_subscriptions().unwrap_or_default();
        let nodes = db.list_nodes().unwrap_or_default();
        let groups = db.list_multi_groups().unwrap_or_default();
        let relays = db.list_preaccel_relays(false).unwrap_or_default();

        let labels = collect_github_issue_custom_labels(&subs, &nodes, &groups, &relays);
        ((subs.len(), nodes.len(), groups.len(), relays.len()), labels)
    };

    let last_error = rt
        .last_error
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(app_log::sanitize_log_line)
        .or_else(|| state.last_app_error_snapshot());

    let ring_events = state
        .app_logger
        .read_recent_key_events(app_log::MAX_KEY_EVENT_RING_LEN);
    let logger = Arc::clone(&state.app_logger);
    let disk_logs = tokio::task::spawn_blocking(move || {
        logger.read_recent_lines(DIAGNOSTICS_DISK_SCAN_LIMIT)
    })
    .await
    .unwrap_or_default();
    let mem_logs = state.telemetry.logs_snapshot();
    let merged_logs = merge_sanitized_recent_logs(disk_logs, mem_logs, DIAGNOSTICS_DISK_SCAN_LIMIT);
    let key_events =
        merge_diagnostic_key_events(ring_events, &merged_logs, GITHUB_ISSUE_KEY_EVENTS_LIMIT);

    let os_label = format!("{} {}", caps.os, caps.arch);
    let tun_privilege_ready = is_tun_privilege_ready(&state);
    Ok(build_github_issue_draft(
        &cfg.update.repo,
        env!("CARGO_PKG_VERSION"),
        &os_label,
        caps.is_elevated,
        tun_privilege_ready,
        state.paths.is_portable,
        &cfg,
        &rt,
        &global_status,
        counts,
        &geodata_status,
        last_error.as_deref(),
        &key_events,
        &custom_labels,
        summary.as_deref(),
        norm_lang,
    ))
}

