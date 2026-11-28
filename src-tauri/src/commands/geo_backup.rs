use std::collections::HashMap;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use catcloud_core::config;
use catcloud_core::core_adapter::binary_resolver::compute_file_sha256;
use catcloud_core::core_adapter::config_compiler::CompileInput;
use catcloud_core::core_adapter::config_compiler::compile_mihomo_config_with_runtime_dir;
use catcloud_core::core_adapter::port_guard::AllocatedPorts;
use catcloud_core::core_adapter::CoreAdapter;
use catcloud_core::core_adapter::ReloadOutcome;
use catcloud_core::models::AppConfig;
use catcloud_core::models::MultiGroup;
use catcloud_core::models::PreAccelRelay;
use catcloud_core::models::ProbeDefinition;
use catcloud_core::storage::BackupDbSnapshot;
use catcloud_core::AppPaths;
use chrono::Utc;
use tauri::AppHandle;
use tauri::State;

use crate::commands::core_lifecycle::format_reload_level_zh;
use crate::commands::core_lifecycle::trigger_reload_if_running;
use crate::commands::core_lifecycle::trigger_reload_if_running_with_options;
use crate::commands::hotkeys::sync_app_side_effects;
use crate::commands::state::AppState;
use crate::commands::state::format_bytes_human;
use crate::commands::state::normalize_inline_override_yaml;
use crate::commands::state::prune_node_health_pool_from_db;
use crate::commands::strategy_rank::validate_group_hard_gates;
use crate::commands::system_proxy::sync_running_global_preaccel_if_active;
use crate::commands::tray_runtime::effective_config_for_runtime;
use crate::commands::tray_runtime::emit_config_updated;
use crate::commands::tray_runtime::emit_groups_updated;
use crate::commands::tray_runtime::emit_relays_updated;
use crate::commands::tray_runtime::format_mihomo_error_for_user;
use crate::commands::tray_runtime::is_tun_privilege_ready;

fn inspect_geodata_file(runtime_dir: &std::path::Path, candidates: &[&str]) -> serde_json::Value {
    for name in candidates {
        let path = runtime_dir.join(name);
        if let Ok(meta) = std::fs::metadata(&path) {
            if meta.is_file() {
                let updated_at = meta
                    .modified()
                    .ok()
                    .map(|t| chrono::DateTime::<Utc>::from(t).to_rfc3339());
                return serde_json::json!({
                    "exists": true,
                    "size_bytes": meta.len(),
                    "updated_at": updated_at
                });
            }
        }
    }
    serde_json::json!({
        "exists": false,
        "size_bytes": 0u64,
        "updated_at": null
    })
}


pub(in crate::commands) fn collect_geodata_status(runtime_dir: &std::path::Path) -> serde_json::Value {
    serde_json::json!({
        "country_mmdb": inspect_geodata_file(runtime_dir, &["Country.mmdb", "country.mmdb"]),
        "geoip_dat": inspect_geodata_file(runtime_dir, &["geoip.dat", "GeoIP.dat"]),
        "geosite_dat": inspect_geodata_file(runtime_dir, &["geosite.dat", "GeoSite.dat"]),
        "asn_mmdb": inspect_geodata_file(runtime_dir, &["GeoLite2-ASN.mmdb", "geolite2-asn.mmdb", "asn.mmdb"]),
    })
}


#[tauri::command]
pub fn get_geodata_status(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    Ok(collect_geodata_status(&state.paths.runtime_dir))
}


const MAX_GEODATA_DOWNLOAD_BYTES: usize = 64 * 1024 * 1024;


fn resolve_geodata_target_spec<'a>(
    target: &str,
    geodata: &'a catcloud_core::models::GeoDataConfig,
) -> Option<(&'static str, &'a str, &'static str)> {
    match target.trim().to_ascii_lowercase().as_str() {
        "mmdb" | "country" | "country_mmdb" | "country-lite" => {
            Some(("mmdb", geodata.mmdb_url.as_str(), "Country.mmdb"))
        }
        "geoip" | "geoip_dat" => Some(("geoip", geodata.geoip_url.as_str(), "geoip.dat")),
        "geosite" | "geosite_dat" => {
            Some(("geosite", geodata.geosite_url.as_str(), "geosite.dat"))
        }
        "asn" | "asn_mmdb" => Some(("asn", geodata.asn_url.as_str(), "GeoLite2-ASN.mmdb")),
        _ => None,
    }
}


async fn fetch_geodata_bytes_once(
    url: &str,
    proxy_port: Option<u16>,
) -> Result<Vec<u8>, String> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(90))
        .user_agent(format!("CatCloud/{}", env!("CARGO_PKG_VERSION")));
    if let Some(port) = proxy_port {
        let proxy_url = format!("http://127.0.0.1:{port}");
        let proxy = reqwest::Proxy::all(&proxy_url)
            .map_err(|e| format!("构造本地代理客户端失败：{e}"))?;
        builder = builder.proxy(proxy);
    } else {
        builder = builder.no_proxy();
    }
    let client = builder
        .build()
        .map_err(|e| format!("初始化地理数据库下载客户端失败：{e}"))?;
    let mut resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("下载地理数据库失败：{e}"))?;
    if !resp.status().is_success() {
        return Err(format!("下载地理数据库返回 HTTP {}", resp.status().as_u16()));
    }
    if let Some(len) = resp.content_length() {
        if len > MAX_GEODATA_DOWNLOAD_BYTES as u64 {
            return Err("地理数据库文件超过安全体积上限（64 MiB）".to_string());
        }
    }
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("读取地理数据库响应流失败：{e}"))?
    {
        if buf.len().saturating_add(chunk.len()) > MAX_GEODATA_DOWNLOAD_BYTES {
            return Err("地理数据库文件超过安全体积上限（64 MiB）".to_string());
        }
        buf.extend_from_slice(&chunk);
    }
    if buf.len() < 1024 {
        return Err("下载到的地理数据库体积异常偏小，已放弃覆盖".to_string());
    }
    let head = String::from_utf8_lossy(&buf[..buf.len().min(256)]).to_ascii_lowercase();
    if head.contains("<!doctype html") || head.contains("<html") {
        return Err("地理数据库源返回了网页内容而非二进制数据，已放弃覆盖".to_string());
    }
    Ok(buf)
}


pub(in crate::commands) fn derive_geodata_mirror_urls(primary_url: &str) -> Vec<String> {
    const PREFIXES: &[&str] = &[
        "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/",
        "http://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/",
    ];
    let trimmed = primary_url.trim();
    let without_query = trimmed.split(['?', '#']).next().unwrap_or(trimmed);
    let rest = PREFIXES.iter().find_map(|prefix| {
        if without_query.len() > prefix.len()
            && without_query.is_char_boundary(prefix.len())
            && without_query[..prefix.len()].eq_ignore_ascii_case(prefix)
        {
            Some(&without_query[prefix.len()..])
        } else {
            None
        }
    });
    let Some(rest) = rest else {
        return Vec::new();
    };
    let filename = rest.trim_matches('/');
    if filename.is_empty()
        || filename.contains('/')
        || filename.contains('\\')
        || filename.contains("..")
    {
        return Vec::new();
    }
    let mirror_name = if filename.eq_ignore_ascii_case("country.mmdb") {
        "country.mmdb"
    } else {
        filename
    };
    vec![
        format!("https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/{mirror_name}"),
        format!(
            "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/{mirror_name}"
        ),
    ]
}


async fn download_geodata_file_atomic(
    url: &str,
    dest: &std::path::Path,
    local_proxy_port: Option<u16>,
) -> Result<usize, String> {
    let trimmed = url.trim();
    if !(trimmed.starts_with("https://") || trimmed.starts_with("http://")) {
        return Err("地理数据库下载地址必须是 http:// 或 https:// 链接".to_string());
    }
    let mut candidate_urls: Vec<String> = vec![trimmed.to_string()];
    candidate_urls.extend(derive_geodata_mirror_urls(trimmed));

    let mut downloaded: Option<Vec<u8>> = None;
    let mut last_err: Option<String> = None;

    for candidate_url in &candidate_urls {
        let attempt = if let Some(port) = local_proxy_port {
            match fetch_geodata_bytes_once(candidate_url, Some(port)).await {
                Ok(b) => Ok(b),
                Err(proxy_err) => match fetch_geodata_bytes_once(candidate_url, None).await {
                    Ok(b) => Ok(b),
                    Err(direct_err) => Err(format!("代理：{proxy_err}；直连：{direct_err}")),
                },
            }
        } else {
            fetch_geodata_bytes_once(candidate_url, None).await
        };
        match attempt {
            Ok(bytes) => {
                downloaded = Some(bytes);
                break;
            }
            Err(err) => {
                tracing::warn!(
                    url = %candidate_url,
                    error = %err,
                    "geodata download attempt failed; trying fallback mirror if available"
                );
                last_err = Some(err);
            }
        }
    }

    let bytes = downloaded.ok_or_else(|| {
        last_err.unwrap_or_else(|| "下载地理数据库失败（主源与备用镜像均不可用）".to_string())
    })?;
    let len = bytes.len();
    let dest_owned = dest.to_path_buf();
    tokio::task::spawn_blocking(move || AppPaths::atomic_write(&dest_owned, &bytes))
        .await
        .map_err(|e| format!("写入地理数据库任务异常：{e}"))?
        .map_err(|e| format!("原子落盘地理数据库失败：{e}"))?;
    Ok(len)
}


#[tauri::command]
pub async fn refresh_geo_db(
    app: AppHandle,
    state: State<'_, AppState>,
    targets: Option<Vec<String>>,
) -> Result<serde_json::Value, String> {
    let cfg = state.snapshot_config();
    let requested_targets = targets
        .filter(|list| !list.is_empty())
        .unwrap_or_else(|| {
            vec![
                "geoip".to_string(),
                "geosite".to_string(),
                "mmdb".to_string(),
                "asn".to_string(),
            ]
        });

    let core_live = state.adapter.has_live_controller().await;
    let rt = if core_live {
        Some(state.adapter.status().await)
    } else {
        None
    };
    let local_proxy_port = rt
        .as_ref()
        .filter(|r| r.running && r.mixed_port > 0)
        .map(|r| r.mixed_port);

    // When the core is running and user asked for a full refresh (or non-mmdb dat files),
    // trigger Mihomo's `/configs/geo` first, then ensure canonical `Country.mmdb` (and any
    // explicitly requested files missing or served from `country-lite.mmdb`) are atomically written.
    let mut core_geo_ok = false;
    let mut core_geo_err: Option<String> = None;
    if let Some(ref rt_live) = rt {
        let secret = state.adapter.controller_secret().await;
        let url = format!(
            "http://{}:{}/configs/geo",
            if rt_live.controller_host == "0.0.0.0" {
                "127.0.0.1"
            } else {
                rt_live.controller_host.as_str()
            },
            rt_live.controller_port
        );
        if let Ok(client) = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(60))
            .build()
        {
            match client.post(&url).bearer_auth(&secret).send().await {
                Ok(resp) if resp.status().is_success() => {
                    core_geo_ok = true;
                }
                Ok(resp) => {
                    core_geo_err = Some(format!(
                        "核心地理数据库更新返回 HTTP {}",
                        resp.status().as_u16()
                    ));
                }
                Err(e) => {
                    core_geo_err = Some(format!("请求核心地理数据库更新失败：{e}"));
                }
            }
        }
    }

    let mut updated_targets: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut seen_keys: HashSet<&'static str> = HashSet::new();

    for target in &requested_targets {
        let Some((canon_key, dl_url, filename)) =
            resolve_geodata_target_spec(target, &cfg.geodata)
        else {
            continue;
        };
        if !seen_keys.insert(canon_key) {
            continue;
        }
        let dest = state.paths.runtime_dir.join(filename);
        let need_atomic_download = if canon_key == "mmdb" {
            // Always download lightweight `mmdb_url` atomically to canonical `Country.mmdb`
            // whenever core is stopped, `/configs/geo` failed, or `Country.mmdb` is absent.
            !core_geo_ok || !dest.is_file() || requested_targets.len() == 1
        } else {
            !core_geo_ok || !dest.is_file()
        };

        if need_atomic_download {
            match download_geodata_file_atomic(dl_url, &dest, local_proxy_port).await {
                Ok(bytes) => {
                    updated_targets.push(canon_key.to_string());
                    state.log_app_event(
                        "info",
                        "地理库",
                        &format!(
                            "已原子更新 {filename}（{}）",
                            format_bytes_human(bytes as u64)
                        ),
                    );
                }
                Err(err) => {
                    errors.push(format!("{filename}: {err}"));
                }
            }
        } else {
            updated_targets.push(canon_key.to_string());
        }
    }

    if updated_targets.is_empty() {
        let detail = if !errors.is_empty() {
            errors.join("；")
        } else if let Some(err) = core_geo_err {
            err
        } else {
            "未指定可更新的地理数据库目标".to_string()
        };
        return Err(detail);
    }

    let mut reloaded = false;
    let mut reload_err_note: Option<String> = None;
    if state.adapter.has_live_controller().await {
        match trigger_reload_if_running_with_options(&app, &state, true, false).await {
            Some(outcome) if outcome.applied => {
                reloaded = true;
                state.log_app_event(
                    "info",
                    "地理库",
                    &format!(
                        "地理库落盘后已自动强制热重载（级别：{}，目标：{}）",
                        format_reload_level_zh(outcome.level),
                        updated_targets.join(", ")
                    ),
                );
            }
            Some(outcome) => {
                let reason = outcome
                    .error
                    .as_deref()
                    .map(format_mihomo_error_for_user)
                    .unwrap_or_else(|| {
                        if outcome.rejected {
                            "核心拒绝了本次热重载，请检查规则配置".to_string()
                        } else {
                            "核心未应用本次热重载".to_string()
                        }
                    });
                state.log_app_event(
                    "warn",
                    "地理库",
                    &format!("地理库已落盘，但自动热重载失败：{reason}"),
                );
                reload_err_note = Some(reason);
            }
            None => {
                state.log_app_event(
                    "info",
                    "地理库",
                    "地理库已落盘，核心已停止，将在下次启动时生效",
                );
            }
        }
    }

    let base_message = if errors.is_empty() {
        if core_geo_ok {
            "地理数据库已更新并原子写入运行目录".to_string()
        } else {
            "地理数据库已直接下载并原子写入运行目录".to_string()
        }
    } else {
        format!(
            "部分地理数据库已更新（成功：{}；未完成：{}）",
            updated_targets.join(", "),
            errors.join("；")
        )
    };
    let message = if reloaded {
        format!("{base_message}，并已自动热重载核心使地理分流规则立即生效")
    } else if let Some(reason) = reload_err_note {
        format!("{base_message}，但核心自动热重载失败（{reason}）")
    } else {
        base_message
    };

    Ok(serde_json::json!({
        "ok": true,
        "updated_targets": updated_targets,
        "reloaded": reloaded,
        "message": message
    }))
}


#[tauri::command]
pub fn export_backup_bundle(
    state: State<'_, AppState>,
    target_path: Option<String>,
) -> Result<serde_json::Value, String> {
    let mut cfg = state.clone_config();
    if cfg
        .controller_secret
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty())
    {
        cfg.controller_secret = Some("<REDACTED>".to_string());
    }
    let (groups, mut relays, probes) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        (
            db.list_multi_groups().map_err(|e| e.to_string())?,
            db.list_preaccel_relays(false).map_err(|e| e.to_string())?,
            db.list_probe_definitions().map_err(|e| e.to_string())?,
        )
    };
    for relay in &mut relays {
        if !relay.server.trim().is_empty() {
            relay.server = "<REDACTED>".to_string();
        }
        if !relay.password.trim().is_empty() {
            relay.password = "<REDACTED>".to_string();
        }
    }
    let exported_at = Utc::now().to_rfc3339();
    let bundle = serde_json::json!({
        "schema": "catcloud-backup/v1",
        "exported_at": exported_at,
        "app_version": env!("CARGO_PKG_VERSION"),
        "sanitized": true,
        "config": cfg,
        "multi_groups": groups,
        "preaccel_relays": relays,
        "probe_definitions": probes
    });
    let bytes = serde_json::to_vec_pretty(&bundle).map_err(|e| e.to_string())?;
    let out_path = match target_path.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        Some(p) => PathBuf::from(p),
        None => {
            std::fs::create_dir_all(&state.paths.backup_dir).map_err(|e| e.to_string())?;
            state.paths.backup_dir.join(format!(
                "catcloud-backup-{}.json",
                Utc::now().format("%Y%m%d-%H%M%S")
            ))
        }
    };
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(&out_path, &bytes).map_err(|e| e.to_string())?;
    let sha256 = compute_file_sha256(&out_path).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "path": out_path.display().to_string(),
        "bytes": bytes.len(),
        "sha256": sha256,
        "exported_at": exported_at
    }))
}


const REDACTED_PLACEHOLDER: &str = "<REDACTED>";


fn is_redacted_placeholder(s: &str) -> bool {
    s.trim() == REDACTED_PLACEHOLDER
}


pub(in crate::commands) fn preserve_local_secrets_in_config(existing: &AppConfig, incoming: &mut AppConfig) {
    if incoming
        .controller_secret
        .as_deref()
        .is_some_and(is_redacted_placeholder)
    {
        incoming.controller_secret = existing
            .controller_secret
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty() && !is_redacted_placeholder(s))
            .map(str::to_string);
    }
}


/// Merge a deserialized backup relay with any existing local relay of the same ID so
/// `"<REDACTED>"` placeholders never overwrite real local credentials or fail validation.
/// Returns `false` if a required redacted field has no local value to preserve (caller skips).
pub(in crate::commands) fn merge_redacted_backup_relay(
    existing: Option<&PreAccelRelay>,
    incoming: &mut PreAccelRelay,
) -> bool {
    if is_redacted_placeholder(&incoming.server) {
        if let Some(local_server) = existing
            .map(|r| r.server.trim())
            .filter(|s| !s.is_empty() && !is_redacted_placeholder(s))
        {
            incoming.server = local_server.to_string();
        } else {
            return false;
        }
    }
    if is_redacted_placeholder(&incoming.password) {
        if let Some(local_pw) = existing
            .map(|r| r.password.trim())
            .filter(|s| !s.is_empty() && !is_redacted_placeholder(s))
        {
            incoming.password = local_pw.to_string();
        } else {
            return false;
        }
    }
    true
}


pub(in crate::commands) struct BackupRestoreApplied {
    pub(in crate::commands) old_cfg: Arc<AppConfig>,
    pub(in crate::commands) db_snapshot: BackupDbSnapshot,
    pub(in crate::commands) config_written: bool,
    pub(in crate::commands) has_db_mutations: bool,
    pub(in crate::commands) restored_config: bool,
    pub(in crate::commands) restored_groups: usize,
    pub(in crate::commands) restored_relays: usize,
    pub(in crate::commands) restored_probes: usize,
    pub(in crate::commands) skipped_redacted_relays: usize,
}


/// Phase 1 + Phase 2 of backup restore:
/// Fully parses and strictly validates ALL entities (groups + formulas, probes + `validate_definition`,
/// relays + `validate_relay_strict`, config + Mihomo compile preflight) BEFORE mutating SQLite or
/// disk. Commits SQLite atomically in a single transaction first, then writes `config.json`, rolling
/// back SQLite in one transaction if `config::save` fails. Caller MUST hold `state.config_transition_lock`.
pub(in crate::commands) fn prepare_and_apply_backup_bundle_core(
    state: &AppState,
    bundle_json: &str,
) -> Result<BackupRestoreApplied, String> {
    let parsed: serde_json::Value = serde_json::from_str(bundle_json)
        .map_err(|e| format!("备份文件 JSON 格式无效：{e}"))?;
    if !parsed.is_object() {
        return Err("备份文件顶层格式无效：应为 JSON 对象".to_string());
    }

    let old_cfg = state.snapshot_config();

    // 1. Strictly parse & validate groups, probes, and relays in memory first (zero DB/disk mutation yet).
    let mut parsed_groups: Vec<MultiGroup> = Vec::new();
    if let Some(val) = parsed.get("multi_groups").filter(|v| !v.is_null()) {
        let arr = val
            .as_array()
            .ok_or_else(|| "备份中的 multi_groups 格式无效：应为数组".to_string())?;
        for (idx, item) in arr.iter().enumerate() {
            let g: MultiGroup = serde_json::from_value(item.clone())
                .map_err(|e| format!("备份中的第 {} 条多选分组数据损坏：{e}", idx + 1))?;
            if g.id.trim().is_empty() {
                return Err(format!("备份中的第 {} 条多选分组缺少有效 ID", idx + 1));
            }
            catcloud_core::strategy::formula::validate_formula(&g.formula_expr)
                .map_err(|e| format!("备份中的分组「{}」排序公式无效：{e}", g.name))?;
            validate_group_hard_gates(&g.hard_gates)
                .map_err(|e| format!("备份中的分组「{}」{e}", g.name))?;
            parsed_groups.push(g);
        }
    }

    let mut parsed_probes: Vec<ProbeDefinition> = Vec::new();
    if let Some(val) = parsed.get("probe_definitions").filter(|v| !v.is_null()) {
        let arr = val
            .as_array()
            .ok_or_else(|| "备份中的 probe_definitions 格式无效：应为数组".to_string())?;
        for (idx, item) in arr.iter().enumerate() {
            let p: ProbeDefinition = serde_json::from_value(item.clone())
                .map_err(|e| format!("备份中的第 {} 条测速探针数据损坏：{e}", idx + 1))?;
            catcloud_core::probe::validate_definition(&p)
                .map_err(|e| format!("备份中的测速探针「{}」校验未通过：{e}", p.name))?;
            parsed_probes.push(p);
        }
    }

    let (existing_nodes, db_snapshot) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        (
            db.list_nodes().map_err(|e| e.to_string())?,
            db.capture_backup_db_snapshot()
                .map_err(|e| format!("读取恢复前数据库快照失败：{e}"))?,
        )
    };
    let existing_groups = db_snapshot.groups.clone();
    let existing_relays = db_snapshot.relays.clone();

    let existing_relay_map: HashMap<&str, &PreAccelRelay> = existing_relays
        .iter()
        .map(|r| (r.id.as_str(), r))
        .collect();
    let mut validated_relays: Vec<PreAccelRelay> = Vec::new();
    let mut skipped_redacted_relays = 0usize;
    if let Some(val) = parsed.get("preaccel_relays").filter(|v| !v.is_null()) {
        let arr = val
            .as_array()
            .ok_or_else(|| "备份中的 preaccel_relays 格式无效：应为数组".to_string())?;
        for (idx, item) in arr.iter().enumerate() {
            let mut r: PreAccelRelay = serde_json::from_value(item.clone())
                .map_err(|e| format!("备份中的第 {} 条国内中转数据损坏：{e}", idx + 1))?;
            let existing = existing_relay_map.get(r.id.as_str()).copied();
            if !merge_redacted_backup_relay(existing, &mut r) {
                skipped_redacted_relays += 1;
                continue;
            }
            catcloud_core::preaccel::schema::validate_relay_strict(&r)
                .map_err(|e| format!("备份中的国内中转校验未通过：{e}"))?;
            validated_relays.push(r);
        }
    }

    // Build projected post-restore groups & relays to run dangling relay reconciliation and compile preflight.
    let mut projected_relays_map: HashMap<String, PreAccelRelay> = existing_relays
        .into_iter()
        .map(|r| (r.id.clone(), r))
        .collect();
    for r in &validated_relays {
        projected_relays_map.insert(r.id.clone(), r.clone());
    }
    let projected_relays: Vec<PreAccelRelay> = projected_relays_map.into_values().collect();
    let projected_enabled_relay_ids: HashSet<String> = projected_relays
        .iter()
        .filter(|r| r.enabled)
        .map(|r| r.id.clone())
        .collect();

    let mut projected_groups_map: HashMap<String, MultiGroup> = existing_groups
        .into_iter()
        .map(|g| (g.id.clone(), g))
        .collect();
    for g in &parsed_groups {
        projected_groups_map.insert(g.id.clone(), g.clone());
    }
    let projected_groups: Vec<MultiGroup> = projected_groups_map.into_values().collect();

    let mut next_cfg_opt: Option<AppConfig> = None;
    let mut restored_config = false;
    if let Some(cfg_val) = parsed.get("config").filter(|v| !v.is_null()) {
        let mut next: AppConfig = serde_json::from_value(cfg_val.clone())
            .map_err(|e| format!("备份中的配置格式无效：{e}"))?;
        preserve_local_secrets_in_config(&old_cfg, &mut next);
        normalize_inline_override_yaml(&mut next);
        let _ = config::migrate_config_in_memory(&mut next);
        // One-way latch: never regress `onboarding_completed` from `true` back to `false`.
        next.personalization.onboarding_completed |= old_cfg.personalization.onboarding_completed;
        let _ = config::reconcile_dangling_active_relay(&mut next, &projected_enabled_relay_ids);
        if projected_enabled_relay_ids.is_empty()
            && (next.preaccel.enabled || next.preaccel.global_bypass_enabled)
        {
            next.preaccel.sync_unified_enabled(false);
        }
        config::validate_config(&next)
            .map_err(|e| format!("备份中的配置参数校验未通过：{e}"))?;
        next_cfg_opt = Some(next);
        restored_config = true;
    } else {
        let mut reconciled_existing = (*old_cfg).clone();
        let mut changed = config::reconcile_dangling_active_relay(
            &mut reconciled_existing,
            &projected_enabled_relay_ids,
        );
        if projected_enabled_relay_ids.is_empty()
            && (reconciled_existing.preaccel.enabled
                || reconciled_existing.preaccel.global_bypass_enabled)
        {
            reconciled_existing.preaccel.sync_unified_enabled(false);
            changed = true;
        }
        if changed {
            next_cfg_opt = Some(reconciled_existing);
        }
    }

    // Compile preflight with projected config + groups + relays before touching disk or SQLite.
    let candidate_cfg = next_cfg_opt.as_ref().unwrap_or(old_cfg.as_ref());
    let eff_candidate = effective_config_for_runtime(state, candidate_cfg);
    let allocated = AllocatedPorts {
        bind_host: eff_candidate.bind_address.clone(),
        mixed_port: eff_candidate.mixed_port,
        controller_port: eff_candidate.controller_port,
        dns_port: eff_candidate.dns_listen_port,
        shifted: Vec::new(),
    };
    let empty_filter = HashMap::new();
    let compile_input = CompileInput {
        config: &eff_candidate,
        nodes: &existing_nodes,
        groups: &projected_groups,
        relays: &projected_relays,
        controller_secret: "backup-preflight-secret",
        allocated_ports: &allocated,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty_filter,
    };
    let mut compiled =
        compile_mihomo_config_with_runtime_dir(&compile_input, Some(&state.paths.runtime_dir))
            .map_err(|e| {
                format!(
                    "备份配置编译预检失败，已拒绝恢复：{}",
                    format_mihomo_error_for_user(&e.to_string())
                )
            })?;
    if !is_tun_privilege_ready(state) {
        catcloud_core::core_adapter::enforce_tun_disabled_on_compiled(&mut compiled).map_err(
            |e| format!("备份配置非提权 TUN 预检失败，已拒绝恢复：{e}"),
        )?;
    }
    if !compiled.validation.ok {
        let fallback_hint = catcloud_core::core_adapter::resolve_default_fallback_group_name(
            &eff_candidate,
            &projected_groups,
        );
        let summary = catcloud_core::core_adapter::format_static_validation_summary_zh(
            &compiled.validation,
            Some(&fallback_hint),
        );
        return Err(format!("备份配置静态防环预检未通过，已拒绝恢复：{summary}"));
    }

    // 2. All preflight checks passed:
    //    Step 2a: Atomically commit SQLite entities in a single transaction FIRST.
    let restored_groups = parsed_groups.len();
    let restored_relays = validated_relays.len();
    let restored_probes = parsed_probes.len();
    let has_db_mutations = restored_groups > 0 || restored_relays > 0 || restored_probes > 0;
    if has_db_mutations {
        let mut db = state.storage.lock().map_err(|e| e.to_string())?;
        db.apply_backup_entities_atomic(
            &parsed_groups,
            &validated_relays,
            &parsed_probes,
            false,
        )
        .map_err(|e| format!("原子写入备份数据库实体失败，已回滚：{e}"))?;
    }

    //    Step 2b: Persist `config.json` & update in-memory `state.config`. If `config::save` fails,
    //    atomically restore all three SQLite tables back to `db_snapshot` (removing newly inserted IDs).
    let mut config_written = false;
    if let Some(next_cfg) = next_cfg_opt {
        if let Err(save_err) = config::save(&state.paths, &next_cfg) {
            if has_db_mutations {
                if let Ok(mut db) = state.storage.lock() {
                    if let Err(rb_err) = db.apply_backup_entities_atomic(
                        &db_snapshot.groups,
                        &db_snapshot.relays,
                        &db_snapshot.probes,
                        true,
                    ) {
                        tracing::error!("写入恢复配置失败后回滚数据库快照异常：{rb_err}");
                    }
                }
            }
            return Err(format!("写入恢复配置失败，已原子回滚数据库变更：{save_err}"));
        }
        if let Ok(mut guard) = state.config.write() {
            *guard = Arc::new(next_cfg);
        }
        config_written = true;
    }

    Ok(BackupRestoreApplied {
        old_cfg,
        db_snapshot,
        config_written,
        has_db_mutations,
        restored_config,
        restored_groups,
        restored_relays,
        restored_probes,
        skipped_redacted_relays,
    })
}


/// Atomically restore SQLite (`multi_groups`, `preaccel_relays`, `probe_definitions` via
/// `replace_all = true`) AND `config.json` / `state.config` back to the pre-restore snapshot.
fn rollback_backup_restore_core(
    state: &AppState,
    applied: &BackupRestoreApplied,
) -> Result<(), String> {
    let mut errs: Vec<String> = Vec::new();
    if applied.has_db_mutations {
        match state.storage.lock() {
            Ok(mut db) => {
                if let Err(err) = db.apply_backup_entities_atomic(
                    &applied.db_snapshot.groups,
                    &applied.db_snapshot.relays,
                    &applied.db_snapshot.probes,
                    true,
                ) {
                    errs.push(format!("数据库回滚失败：{err}"));
                }
            }
            Err(err) => {
                errs.push(format!("获取数据库锁执行回滚失败：{err}"));
            }
        }
    }
    if applied.config_written {
        if let Err(err) = config::save(&state.paths, &applied.old_cfg) {
            errs.push(format!("配置文件回滚失败：{err}"));
        } else if let Ok(mut guard) = state.config.write() {
            *guard = Arc::clone(&applied.old_cfg);
        }
    }
    prune_node_health_pool_from_db(state);
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs.join("；"))
    }
}


/// Enforce atomic rollback whenever a live core hot-reload rejects the restored backup bundle.
pub(in crate::commands) fn finalize_backup_restore_reload_outcome(
    state: &AppState,
    applied: &BackupRestoreApplied,
    outcome: Option<&ReloadOutcome>,
) -> Result<(), String> {
    let Some(outcome) = outcome else {
        return Ok(());
    };
    if !outcome.rejected {
        return Ok(());
    }
    let rollback_res = rollback_backup_restore_core(state, applied);
    let detail = outcome
        .error
        .as_deref()
        .map(format_mihomo_error_for_user)
        .unwrap_or_else(|| "未知原因".to_string());
    if let Err(rb_err) = rollback_res {
        tracing::error!("备份恢复热重载失败后的原子回滚出现异常：{rb_err}");
        return Err(format!(
            "恢复备份后热重载代理核心未通过：{detail}（自动回滚异常：{rb_err}）"
        ));
    }
    Err(format!(
        "恢复备份后热重载代理核心未通过，已完整回滚配置与数据库：{detail}"
    ))
}


#[tauri::command]
pub async fn import_backup_bundle(
    app: AppHandle,
    state: State<'_, AppState>,
    bundle_json: String,
) -> Result<serde_json::Value, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    let applied = prepare_and_apply_backup_bundle_core(&state, &bundle_json)?;

    prune_node_health_pool_from_db(&state);
    let reload_outcome = trigger_reload_if_running(&app, &state, true).await;
    if let Err(err) =
        finalize_backup_restore_reload_outcome(&state, &applied, reload_outcome.as_ref())
    {
        let latest_cfg = state.snapshot_config();
        emit_config_updated(&app, &latest_cfg);
        if applied.restored_groups > 0 {
            emit_groups_updated(&app);
        }
        if applied.restored_relays > 0 {
            emit_relays_updated(&app);
        }
        sync_app_side_effects(&app, &state, &latest_cfg);
        return Err(err);
    }
    let cfg = state.snapshot_config();
    sync_running_global_preaccel_if_active(&state, &cfg).await;
    emit_config_updated(&app, &cfg);
    if applied.restored_groups > 0 {
        emit_groups_updated(&app);
    }
    if applied.restored_relays > 0 {
        emit_relays_updated(&app);
    }
    sync_app_side_effects(&app, &state, &cfg);

    let message = if applied.skipped_redacted_relays > 0 {
        format!(
            "备份已成功恢复（已跳过 {} 条脱敏中转占位项，保留本地密钥未受损）",
            applied.skipped_redacted_relays
        )
    } else {
        "备份已成功恢复".to_string()
    };

    Ok(serde_json::json!({
        "restored_config": applied.restored_config,
        "restored_groups": applied.restored_groups,
        "restored_relays": applied.restored_relays,
        "restored_probes": applied.restored_probes,
        "skipped_redacted_relays": applied.skipped_redacted_relays,
        "message": message
    }))
}

