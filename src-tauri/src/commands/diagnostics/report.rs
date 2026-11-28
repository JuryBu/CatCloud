use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use catcloud_core::core_adapter::config_compiler::build_preaccel_transport_diagnostics;
use catcloud_core::core_adapter::ConnectionsSnapshot;
use catcloud_core::core_adapter::CoreLogLine;
use catcloud_core::core_adapter::CoreRuntimeStatus;
use catcloud_core::core_adapter::DnsTlsDiagnostics;
use catcloud_core::core_adapter::analyze_dns_tls_diagnostics;
use catcloud_core::core_adapter::analyze_dns_tls_diagnostics_from_log_file;
use catcloud_core::models::AppConfig;
use catcloud_core::models::MemoryLimitTier;
use catcloud_core::models::ProxyMode;
use catcloud_core::platform::default_platform;
use catcloud_core::preaccel::global_tunnel::GlobalPreAccelStatus;
use tauri::State;
use crate::app_log;
use crate::app_log::APP_EVENT_PREFIX;

use crate::commands::geo_backup::collect_geodata_status;
use crate::commands::state::AppState;
use crate::commands::state::ConnectionSummaryCounts;
use crate::commands::state::CoreRuntimeInfoDto;
use crate::commands::state::format_bytes_human;
use crate::commands::state::summarize_connections;
use crate::commands::tray_runtime::build_runtime_info_dto;
use crate::commands::tray_runtime::effective_tun_enabled;
use crate::commands::tray_runtime::tun_needs_elevation;

pub(in crate::commands) fn resolve_effective_doc_lang(state: &AppState, lang: Option<&str>) -> &'static str {
    if let Some(explicit) = lang.map(str::trim).filter(|s| !s.is_empty()) {
        catcloud_core::agent_docs::normalize_doc_lang(Some(explicit))
    } else {
        let cfg = state.snapshot_config();
        catcloud_core::agent_docs::normalize_doc_lang(Some(&cfg.personalization.language))
    }
}


pub(in crate::commands) fn resolve_local_cli_path_from(
    exe_dir: Option<&std::path::Path>,
    resource_dir: Option<&std::path::Path>,
    bin_dir: &std::path::Path,
    root_data_dir: &std::path::Path,
) -> std::path::PathBuf {
    let cli_bin = if cfg!(target_os = "windows") {
        "catcloud.exe"
    } else {
        "catcloud"
    };
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    let norm_exe_dir = exe_dir.map(catcloud_core::paths::normalize_os_path);

    if let Some(ref dir) = norm_exe_dir {
        candidates.push(dir.join("cli").join(cli_bin));
        candidates.push(dir.join("resources").join("cli").join(cli_bin));
        candidates.push(dir.join(cli_bin));
    }
    if let Some(res_dir) = resource_dir {
        let norm_res = catcloud_core::paths::normalize_os_path(res_dir);
        candidates.push(norm_res.join("resources").join("cli").join(cli_bin));
        candidates.push(norm_res.join("cli").join(cli_bin));
        candidates.push(norm_res.join(cli_bin));
    }
    let norm_bin_dir = catcloud_core::paths::normalize_os_path(bin_dir);
    candidates.push(norm_bin_dir.join(cli_bin));
    let norm_root_data = catcloud_core::paths::normalize_os_path(root_data_dir);
    candidates.push(norm_root_data.join("cli").join(cli_bin));
    if let Some(ref dir) = norm_exe_dir {
        if let Some(parent) = dir.parent() {
            candidates.push(parent.join("cli").join(cli_bin));
            candidates.push(parent.join("Resources").join("resources").join("cli").join(cli_bin));
            candidates.push(parent.join("Resources").join("cli").join(cli_bin));
            candidates.push(parent.join("lib").join("CatCloud").join("resources").join("cli").join(cli_bin));
            candidates.push(parent.join("share").join("CatCloud").join("resources").join("cli").join(cli_bin));
            candidates.push(parent.join("share").join("catcloud").join("resources").join("cli").join(cli_bin));
        }
    }
    #[cfg(target_os = "linux")]
    {
        candidates.push(std::path::PathBuf::from("/usr/lib/CatCloud/resources/cli").join(cli_bin));
        candidates.push(std::path::PathBuf::from("/usr/share/CatCloud/resources/cli").join(cli_bin));
    }

    for candidate in &candidates {
        if candidate.is_file() {
            return catcloud_core::paths::normalize_os_path(candidate);
        }
    }

    if let Some(dir) = norm_exe_dir {
        catcloud_core::paths::normalize_os_path(&dir.join("cli").join(cli_bin))
    } else {
        catcloud_core::paths::normalize_os_path(&norm_bin_dir.join(cli_bin))
    }
}


pub(in crate::commands) fn resolve_local_cli_path(state: &AppState) -> std::path::PathBuf {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(std::path::Path::to_path_buf));
    let resource_dir = state
        .resource_dir
        .read()
        .ok()
        .and_then(|guard| guard.clone());
    resolve_local_cli_path_from(
        exe_dir.as_deref(),
        resource_dir.as_deref(),
        &state.paths.bin_dir,
        &state.paths.root_data_dir,
    )
}


fn format_memory_tier_label(tier: &MemoryLimitTier) -> &'static str {
    match tier {
        MemoryLimitTier::Auto => "auto",
        MemoryLimitTier::Mb48 => "48MiB",
        MemoryLimitTier::Mb64 => "64MiB",
        MemoryLimitTier::Mb96 => "96MiB",
    }
}


fn log_dedupe_key(timestamp: &str, body: &str) -> String {
    let ts_sec = timestamp.get(..19).unwrap_or(timestamp);
    format!("{ts_sec}|{}", body.trim())
}


fn extract_disk_log_dedupe_key(line: &str) -> String {
    let trimmed = line.trim();
    let (ts_sec, mut rest) = match trimmed.split_once(' ') {
        Some((ts, r)) => (ts, r.trim_start()),
        None => ("", trimmed),
    };
    let ts_key = ts_sec.get(..19).unwrap_or(ts_sec);
    // Strip `[level] ` and optional `[category] ` strictly from the left so brackets inside the
    // message body never break deduplication against `CoreTelemetryStore`.
    for _ in 0..2 {
        if rest.starts_with('[') {
            if let Some((_, after)) = rest.split_once("] ") {
                rest = after.trim_start();
                continue;
            }
        }
        break;
    }
    format!("{ts_key}|{rest}")
}


pub(in crate::commands) fn merge_sanitized_recent_logs(
    disk_lines: Vec<String>,
    mem_logs: Vec<CoreLogLine>,
    limit: usize,
) -> Vec<String> {
    if limit == 0 {
        return Vec::new();
    }
    let mut merged: Vec<String> = Vec::with_capacity(limit.saturating_mul(2));
    let mut seen: HashSet<String> = HashSet::new();

    for disk_line in disk_lines {
        let clean = app_log::sanitize_log_line(&disk_line);
        let key = extract_disk_log_dedupe_key(&clean);
        if seen.insert(key) {
            merged.push(clean);
        }
    }

    let start_idx = mem_logs.len().saturating_sub(limit);
    for entry in &mem_logs[start_idx..] {
        let clean_payload = app_log::sanitize_log_line(&entry.payload)
            .replace(['\r', '\n'], " ")
            .trim()
            .to_string();
        if clean_payload.is_empty() {
            continue;
        }
        let body_for_key = clean_payload
            .strip_prefix(APP_EVENT_PREFIX)
            .and_then(|rest| rest.split_once("] ").map(|(_, msg)| msg))
            .unwrap_or(clean_payload.as_str());
        let key = log_dedupe_key(&entry.timestamp, body_for_key);
        if seen.insert(key) {
            let lvl = app_log::normalize_log_level(&entry.level);
            merged.push(format!("{} [{lvl}] {clean_payload}", entry.timestamp));
        }
    }

    if merged.len() > limit {
        merged.split_off(merged.len() - limit)
    } else {
        merged
    }
}


pub(in crate::commands) const DIAGNOSTICS_DISK_SCAN_LIMIT: usize = 1500;

const DIAGNOSTICS_KEY_EVENTS_LIMIT: usize = 25;

const DIAGNOSTICS_TAIL_LOGS_LIMIT: usize = 35;

const DIAGNOSTICS_JSON_RECENT_LOGS_LIMIT: usize = 60;

const ONBOARDING_KEY_EVENTS_LIMIT: usize = 6;


/// Sanitize arbitrary single-line or multi-line text before embedding into AI prompts or logs.
pub(in crate::commands) fn sanitize_log_text(raw: &str) -> String {
    raw.lines()
        .map(app_log::sanitize_log_line)
        .collect::<Vec<_>>()
        .join("\n")
}


/// Return `true` when a formatted log line is a routine `[mihomo] [TCP]` / `[mihomo] [UDP]`
/// connection forwarding line at `info`/`debug` level (never filtering out `warning` or `error`
/// lines or application lifecycle/reload/switch/preaccel/ProxyGuard events).
fn is_routine_mihomo_traffic_log_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    if lower.contains(" [warning] ")
        || lower.contains(" [warn] ")
        || lower.contains(" [error] ")
    {
        return false;
    }
    lower.contains("[mihomo] [tcp]")
        || lower.contains("[mihomo] [udp]")
        || lower.contains(" [info] [tcp]")
        || lower.contains(" [info] [udp]")
        || lower.contains(" [debug] [tcp]")
        || lower.contains(" [debug] [udp]")
        || (lower.contains("[mihomo]") && (lower.contains(" match ") || lower.contains(" using ")))
}


/// Merge key events from the dedicated 256-entry ring buffer (immune to routine TCP/UDP floods)
/// with non-routine events found in the scanned disk + memory logs, deduplicated and capped to
/// the newest `limit` entries.
pub(in crate::commands) fn merge_diagnostic_key_events(
    ring_events: Vec<String>,
    all_logs: &[String],
    limit: usize,
) -> Vec<String> {
    if limit == 0 {
        return Vec::new();
    }
    let mut merged: Vec<String> = Vec::with_capacity(ring_events.len() + limit);
    let mut seen: HashSet<String> = HashSet::new();

    for raw in ring_events {
        let clean = app_log::sanitize_log_line(&raw)
            .replace(['\r', '\n'], " ")
            .trim()
            .to_string();
        if clean.is_empty() || is_routine_mihomo_traffic_log_line(&clean) {
            continue;
        }
        let key = extract_disk_log_dedupe_key(&clean);
        if seen.insert(key) {
            merged.push(clean);
        }
    }

    for line in all_logs {
        if is_routine_mihomo_traffic_log_line(line) {
            continue;
        }
        let clean = app_log::sanitize_log_line(line)
            .replace(['\r', '\n'], " ")
            .trim()
            .to_string();
        if clean.is_empty() {
            continue;
        }
        let key = extract_disk_log_dedupe_key(&clean);
        if seen.insert(key) {
            merged.push(clean);
        }
    }

    if merged.len() > limit {
        merged.split_off(merged.len() - limit)
    } else {
        merged
    }
}


/// Smart diagnostic log sampler returning:
/// 1. Up to `key_limit` most recent key non-traffic events (excluding routine TCP/UDP forwarding)
/// 2. Up to `tail_limit` most recent raw tail log lines
pub(in crate::commands) fn sample_diagnostic_logs(
    all_logs: &[String],
    key_limit: usize,
    tail_limit: usize,
) -> (Vec<String>, Vec<String>) {
    let key_events = merge_diagnostic_key_events(Vec::new(), all_logs, key_limit);

    let tail_logs = if tail_limit == 0 {
        Vec::new()
    } else {
        let start = all_logs.len().saturating_sub(tail_limit);
        all_logs[start..].to_vec()
    };

    (key_events, tail_logs)
}


fn collect_sanitized_recent_logs(state: &AppState, limit: usize) -> Vec<String> {
    if limit == 0 {
        return Vec::new();
    }
    let disk_lines = state.app_logger.read_recent_lines(limit);
    let mem_logs = state.telemetry.logs_snapshot();
    merge_sanitized_recent_logs(disk_lines, mem_logs, limit)
}


pub(in crate::commands) fn format_geodata_brief_localized(geodata: &serde_json::Value, is_zh: bool) -> String {
    let item = |key: &str, label: &str| -> String {
        let exists = geodata
            .get(key)
            .and_then(|v| v.get("exists"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let size = geodata
            .get(key)
            .and_then(|v| v.get("size_bytes"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if exists {
            if is_zh {
                format!("{label}: 已就绪 ({})", format_bytes_human(size))
            } else {
                format!("{label}: ready ({})", format_bytes_human(size))
            }
        } else if is_zh {
            format!("{label}: 缺失")
        } else {
            format!("{label}: missing")
        }
    };
    [
        item("country_mmdb", "Country.mmdb"),
        item("geoip_dat", "geoip.dat"),
        item("geosite_dat", "geosite.dat"),
        item("asn_mmdb", "ASN.mmdb"),
    ]
    .join(" / ")
}


fn format_geodata_brief(geodata: &serde_json::Value) -> String {
    format_geodata_brief_localized(geodata, true)
}


pub(in crate::commands) fn format_global_preaccel_brief(
    global_status: &GlobalPreAccelStatus,
    enabled: bool,
    tun_active: bool,
) -> String {
    let iface = global_status
        .bound_physical_interface
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(app_log::sanitize_log_line)
        .unwrap_or_else(|| "自动路由（未绑定固定网卡）".to_string());
    let security = if global_status.detected_security_products.is_empty() {
        "未检出拦截类安全软件".to_string()
    } else {
        app_log::sanitize_log_line(&global_status.detected_security_products.join(" / "))
    };
    let verify_desc = match global_status.verify_state.as_str() {
        "verified" => match global_status.verify_latency_ms {
            Some(ms) => format!("自动探测畅通（{ms} ms）"),
            None => "自动探测畅通".to_string(),
        },
        "probing" => "正在自动探测链路".to_string(),
        "degraded" => "已触发保护熔断并退回本地 443 通道".to_string(),
        "failed" => {
            if !global_status.windivert_available
                || global_status.install_state == "need_elevation"
            {
                "底层提速驱动尚未就绪".to_string()
            } else {
                "底层自动探测未通过".to_string()
            }
        }
        _ => "尚未探测".to_string(),
    };
    let mode_desc = if !enabled && !global_status.running {
        "未开启"
    } else if global_status.is_windivert_active {
        "底层透明加速（WinDivert 运行中）"
    } else if global_status.running {
        "本地独立 443 通道（SOCKS5 运行中）"
    } else if tun_active {
        "已开启（由虚拟网卡主核心统一接管）"
    } else if global_status.mode == "suspended_for_tun" {
        "已挂起（等待主核心接管）"
    } else {
        "已开启（等待启动独立提速通道）"
    };
    format!("{mode_desc} ｜ 探测状态：{verify_desc} ｜ 物理出口网卡：{iface} ｜ 安全环境：{security}")
}


fn format_dns_diagnostics_markdown_section(diag: &DnsTlsDiagnostics) -> String {
    let status_label = match diag.status.as_str() {
        "healthy" => "正常（未检出加密 DNS 证书校验失败）",
        "degraded_recovered" => "曾遇证书校验失败，已自动切备用加密 DNS 恢复",
        "cert_verification_failed" => "告警：加密 DNS 上游证书校验失败（尚未恢复）",
        other => other,
    };
    let paths_text = if diag.affected_paths.is_empty() {
        "无".to_string()
    } else {
        diag.affected_paths.join(" / ")
    };
    let upstreams_text = if diag.affected_upstreams.is_empty() {
        "无".to_string()
    } else {
        diag.affected_upstreams.join(" / ")
    };
    let time_range = match (diag.first_seen_at.as_deref(), diag.last_seen_at.as_deref()) {
        (Some(a), Some(b)) if a != b => format!("{a} ~ {b}"),
        (Some(a), _) => a.to_string(),
        _ => "无".to_string(),
    };
    let recovery_or_retry = if diag.recovered {
        format!(
            "已自动恢复（恢复时间：{}）",
            diag.recovery_time.as_deref().unwrap_or("未知")
        )
    } else if let Some(next_ts) = diag.next_retry_at.as_deref() {
        format!("尚未恢复（建议下次重试时间：{next_ts}）")
    } else {
        "无需重试".to_string()
    };
    let tls_policy = if diag.tls_verification_preserved {
        "严格保留（绝不跳过证书校验）"
    } else {
        "已放宽"
    };
    let window_desc = if diag.scanned_window_desc.trim().is_empty() {
        "最近 256 KiB 日志".to_string()
    } else {
        diag.scanned_window_desc.clone()
    };
    format!(
        "## 3.5 DNS 加密解析与证书校验诊断\n\n\
- 诊断状态：{status_label}（分类：{}，扫描窗口：{window_desc}）\n\
- 证书失败次数：{} 次（时间范围：{time_range}；纯 853/DoT 网络超时：{} 次）\n\
- 受影响路径：{paths_text} ｜ 受影响上游：{upstreams_text}\n\
- TLS 证书校验策略：{tls_policy} ｜ 恢复状态：{recovery_or_retry}\n\
- 建议说明：{}\n",
        diag.category,
        diag.failure_count,
        diag.network_timeout_only_count,
        diag.next_retry_hint,
    )
}


#[allow(clippy::too_many_arguments)]
fn build_ai_diagnostics_markdown(
    app_version: &str,
    os_label: &str,
    is_elevated: bool,
    is_portable: bool,
    cfg: &AppConfig,
    rt: &CoreRuntimeStatus,
    runtime_dto: Option<&CoreRuntimeInfoDto>,
    global_status: &GlobalPreAccelStatus,
    counts: (usize, usize, usize, usize),
    conn_summary: ConnectionSummaryCounts,
    core_mem_bytes: u64,
    geodata_status: &serde_json::Value,
    dns_diagnostics: &DnsTlsDiagnostics,
    last_error: Option<&str>,
    key_event_logs: &[String],
    tail_logs: &[String],
    cli_path_display: &str,
    data_dir_display: &str,
) -> String {
    let (sub_count, node_count, group_count, relay_count) = counts;
    let route_mode = runtime_dto
        .map(|d| d.route_mode.as_str())
        .unwrap_or_else(|| cfg.route_mode.as_str());
    let active_group_name = app_log::sanitize_log_line(
        runtime_dto
            .map(|d| d.active_group_name.as_str())
            .unwrap_or("默认路线"),
    );
    let active_node_name = app_log::sanitize_log_line(
        runtime_dto
            .map(|d| d.active_node_name.as_str())
            .unwrap_or("未选择"),
    );
    let active_node_region = runtime_dto
        .map(|d| d.active_node_region.as_str())
        .unwrap_or("--");
    let preaccel_relay_name = app_log::sanitize_log_line(
        runtime_dto
            .and_then(|d| d.preaccel_relay_name.as_deref())
            .unwrap_or("未配置"),
    );
    let mixed_port = if rt.running { rt.mixed_port } else { cfg.mixed_port };
    let controller_port = if rt.running {
        rt.controller_port
    } else {
        cfg.controller_port
    };
    let dns_port = if rt.running {
        rt.dns_listen_port
    } else {
        cfg.dns_listen_port
    };
    let core_version = rt.version.as_deref().unwrap_or("未知");
    let core_mem_text = if core_mem_bytes > 0 {
        format!("{:.1} MiB", (core_mem_bytes as f64) / (1024.0 * 1024.0))
    } else {
        "--".to_string()
    };
    let last_err_text = last_error
        .map(sanitize_log_text)
        .unwrap_or_else(|| "无".to_string());

    let key_events_block = if key_event_logs.is_empty() {
        "（暂无关键非连接流水事件）".to_string()
    } else {
        key_event_logs.join("\n")
    };
    let tail_logs_block = if tail_logs.is_empty() {
        "（暂无运行日志记录）".to_string()
    } else {
        tail_logs.join("\n")
    };
    let is_windows_cli = cfg!(target_os = "windows") || os_label.starts_with("windows");
    let cli_fence_lang = if is_windows_cli {
        "powershell"
    } else {
        "bash"
    };
    let cli_invoke_prefix = if is_windows_cli {
        format!("& \"{cli_path_display}\" --data-dir \"{data_dir_display}\"")
    } else {
        format!("\"{cli_path_display}\" --data-dir \"{data_dir_display}\"")
    };

    let elevated_label = if is_elevated { "是" } else { "否" };
    let portable_label = if is_portable { "是" } else { "否" };
    let core_state_label = if rt.running { "运行中" } else { "已停止" };
    let proxy_mode_label = cfg.proxy_mode.as_str();
    let sys_proxy_label = if cfg.system_proxy.enabled {
        "已开启"
    } else {
        "关闭"
    };
    let eff_tun = runtime_dto
        .map(|d| d.tun_enabled)
        .unwrap_or(cfg.tun.enabled && is_elevated);
    let tun_need_elev = runtime_dto
        .map(|d| d.tun_needs_elevation)
        .unwrap_or(cfg.tun.enabled && !is_elevated);
    let tun_label = if eff_tun {
        "已开启"
    } else if tun_need_elev {
        "未生效（已勾选但需管理员权限）"
    } else {
        "关闭"
    };
    let tun_stack_label = cfg.tun.stack_mode.as_str();
    let mem_tier_label = format_memory_tier_label(&cfg.core_runtime.memory_tier);
    let gogc_val = cfg.core_runtime.gogc;
    let domestic_direct_label = if cfg.rules_override.domestic_direct_enabled {
        "开启"
    } else {
        "关闭"
    };
    let block_quic_label = if cfg.rules_override.block_quic_udp_443 {
        "开启"
    } else {
        "关闭"
    };
    let preaccel_label = if cfg.preaccel.enabled {
        "已开启"
    } else {
        "关闭"
    };
    let skip_443_label = if cfg.preaccel.skip_443_native {
        "是"
    } else {
        "否"
    };
    let tun_active = rt.running && eff_tun;
    let global_preaccel_brief =
        format_global_preaccel_brief(global_status, cfg.preaccel.enabled, tun_active);
    let transport_diag = runtime_dto
        .and_then(|d| d.preaccel_transport.clone())
        .unwrap_or_else(|| {
            let fallback_mtu = runtime_dto
                .and_then(|d| d.effective_tun_mtu)
                .unwrap_or(cfg.tun.mtu);
            let fallback_mode = runtime_dto
                .map(|d| d.preaccel_effective_carrier.as_str())
                .unwrap_or("off");
            build_preaccel_transport_diagnostics(cfg, fallback_mtu, fallback_mode)
        });
    let preaccel_transport_summary = format!(
        "effective_mode=`{}`, effective_tun_mtu=`{}`, anytls_tfo={}, min_idle_session={}, keep_alive_idle={}s, keep_alive_interval={}s, expected_probe_status=`{}`, lb_strategy=`{}`, probe_interval={}s",
        app_log::sanitize_log_line(&transport_diag.effective_mode),
        transport_diag.effective_tun_mtu,
        transport_diag.anytls_tfo,
        transport_diag.anytls_min_idle_session,
        transport_diag.keep_alive_idle_sec,
        transport_diag.keep_alive_interval_sec,
        app_log::sanitize_log_line(&transport_diag.expected_probe_status),
        app_log::sanitize_log_line(&transport_diag.lb_strategy),
        transport_diag.probe_interval_sec,
    );
    let ipv6_core_label = if cfg.core_ipv6 { "开启" } else { "关闭" };
    let ipv6_dns_label = if cfg.dns.ipv6 { "开启" } else { "关闭" };
    let geodata_brief = format_geodata_brief(geodata_status);
    let app_conns = conn_summary.app_connections;
    let direct_conns = conn_summary.direct_connections;
    let proxied_conns = conn_summary.proxied_connections;
    let tunnel_conns = conn_summary.tunnel_connections;
    let key_count = key_event_logs.len();
    let tail_count = tail_logs.len();
    let dns_diag_section = format_dns_diagnostics_markdown_section(dns_diagnostics);

    format!(
        "请帮我排查猫猫云梯（CatCloud）当前问题。\n\
\n\
> 以下诊断包已自动完成隐私脱敏（订阅凭据、密码、Token、Secret 与公网/私网 IP 末段均已隐藏），请先基于状态与关键事件日志定位根因并给出清晰步骤。\n\
\n\
## 1. 运行状态摘要\n\
\n\
| 项目 | 当前状态 |\n\
| --- | --- |\n\
| 应用版本 / 环境 | CatCloud v{app_version} · {os_label} · 管理员权限：{elevated_label} · 便携模式：{portable_label} |\n\
| 代理核心 | {core_state_label}（Mihomo {core_version}，内核内存：{core_mem_text}） |\n\
| 代理模式 / 路由方式 | `{proxy_mode_label}` / `{route_mode}` |\n\
| 当前路线组 / 节点 | 分组「{active_group_name}」 → 节点「{active_node_name}」（地区：{active_node_region}） |\n\
| 本地端口 | 混合端口 `{mixed_port}` / 控制端口 `{controller_port}` / DNS `{dns_port}` |\n\
| 流量接管 | 系统代理：{sys_proxy_label} · 虚拟网卡（TUN）：{tun_label}（协议栈 `{tun_stack_label}`） |\n\
| 内存档位 | `{mem_tier_label}`（GOGC={gogc_val}） |\n\
| 最近异常 | {last_err_text} |\n\
\n\
## 2. 分流与加速配置要点\n\
\n\
- 国内直连规则：{domestic_direct_label} ｜ 阻断 QUIC（UDP/443）：{block_quic_label}\n\
- 国内 443 提速：{preaccel_label}（当前中转：{preaccel_relay_name}，跳过 443 原生节点：{skip_443_label}）\n\
- 底层提速诊断：{global_preaccel_brief}\n\
- 国内提速传输参数摘要：{preaccel_transport_summary}\n\
- IPv6 开关：核心数据面 {ipv6_core_label} ｜ DNS 解析 {ipv6_dns_label}\n\
- GeoData 状态：{geodata_brief}\n\
- 本地资产统计：订阅 {sub_count} 个 · 节点 {node_count} 个 · 智能多选组 {group_count} 个 · 国内中转 {relay_count} 个\n\
\n\
## 3. 当前连接分布\n\
\n\
- 真实应用连接：{app_conns} 条（直连 {direct_conns} 条 · 代理 {proxied_conns} 条）\n\
- 底层提速隧道（`Inner`）：{tunnel_conns} 条（已从应用连接数中排除）\n\
\n\
{dns_diag_section}\n\
## 4. 脱敏运行日志（智能采样：近 {key_count} 条关键事件 + 近 {tail_count} 条全量尾日志）\n\
\n\
### 4.1 关键非连接流水事件（近 {key_count} 条，已排除普通 TCP/UDP 转发）\n\
\n\
```text\n\
{key_events_block}\n\
```\n\
\n\
### 4.2 最新全量尾日志（近 {tail_count} 条）\n\
\n\
```text\n\
{tail_logs_block}\n\
```\n\
\n\
## 5. 本机只读 `catcloud` CLI 进一步排查指引\n\
\n\
- 当前实例 CLI 路径（已脱敏）：`{cli_path_display}`\n\
- 当前实例数据目录（已脱敏）：`{data_dir_display}`\n\
\n\
如果你可以直接在本机终端执行命令，请**优先使用以下只读命令**补充信息（修改配置前请先征得我同意，所有命令统一携带 `--json`）：\n\
\n\
```{cli_fence_lang}\n\
{cli_invoke_prefix} status --json\n\
{cli_invoke_prefix} config diag --json\n\
{cli_invoke_prefix} config validate --json\n\
{cli_invoke_prefix} net doctor --json\n\
{cli_invoke_prefix} group list --json\n\
{cli_invoke_prefix} node list --json\n\
{cli_invoke_prefix} preaccel pool --json\n\
{cli_invoke_prefix} docs export network_lifecycle --json\n\
```\n\
\n\
> 若已将 `catcloud` 加入系统 PATH，也可直接执行简写命令（如 `catcloud status --json`、`catcloud config diag --json`）。\n"
    )
}


fn format_onboarding_os_label_zh(os_raw: &str) -> &'static str {
    let lower = os_raw.trim().to_ascii_lowercase();
    if lower.contains("windows") || lower.contains("win") {
        "Windows 电脑"
    } else if lower.contains("macos") || lower.contains("darwin") || lower.contains("mac") {
        "macOS 电脑"
    } else if lower.contains("linux") {
        "Linux 电脑"
    } else {
        "桌面电脑"
    }
}


fn format_onboarding_preaccel_plain_zh(
    global_status: &GlobalPreAccelStatus,
    enabled: bool,
    tun_enabled: bool,
    core_running: bool,
) -> String {
    let main_desc = if !enabled && !global_status.running {
        "已关闭".to_string()
    } else {
        match global_status.verify_state.as_str() {
            "verified" => match global_status.verify_latency_ms {
                Some(ms) => format!("已开启并在底层实测生效（{ms} ms）"),
                None => "已开启并在底层实测生效".to_string(),
            },
            "probing" => "已开启，正在自动探测链路".to_string(),
            "degraded" => "已开启，底层探测未通过已自动保护回退".to_string(),
            "failed" => "已开启，底层提速组件暂未就绪".to_string(),
            _ => {
                if global_status.is_windivert_active {
                    "已开启并在底层运行中（等待自动探测）".to_string()
                } else if core_running && tun_enabled {
                    "已开启（由全局代理模式统一接管提速）".to_string()
                } else if matches!(
                    global_status.install_state.as_str(),
                    "downloading" | "verifying"
                ) {
                    "已开启，正在后台自动准备提速组件".to_string()
                } else if global_status.install_state == "need_elevation" {
                    "已开启，需以管理员身份重启后为其它软件自动提速".to_string()
                } else if global_status.running {
                    "已开启（本机独立提速通道待命中）".to_string()
                } else {
                    "已开启（待启动）".to_string()
                }
            }
        }
    };

    let mut parts = vec![main_desc];
    if let Some(iface) = global_status
        .bound_physical_interface
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        parts.push(format!("当前上网网卡：{}", app_log::sanitize_log_line(iface)));
    }
    if global_status.detected_security_products.is_empty() {
        parts.push("安全软件环境：未发现常见拦截类安全软件".to_string());
    } else {
        parts.push(format!(
            "检测到安全软件：{}",
            app_log::sanitize_log_line(&global_status.detected_security_products.join(" / "))
        ));
    }
    parts.join(" ｜ ")
}


fn strip_log_timestamp_and_level_prefix(line: &str) -> &str {
    let mut s = line.trim();
    // Strip leading ISO-8601 timestamp token such as `2026-11-24T12:00:00Z `
    if let Some((first, rest)) = s.split_once(' ') {
        if first.len() >= 19 && first.as_bytes().get(4) == Some(&b'-') && first.contains(':') {
            s = rest.trim_start();
        }
    }
    // Strip leading `[info]` / `[warning]` / `[error]` / `[warn]` tag
    if s.starts_with('[') {
        if let Some(close) = s.find(']') {
            let tag = &s[1..close];
            if matches!(
                tag.to_ascii_lowercase().as_str(),
                "info" | "warn" | "warning" | "error" | "debug" | "trace"
            ) {
                s = s[close + 1..].trim_start();
            }
        }
    }
    s
}


/// Keep at most `limit` high-value, sanitized Chinese status events suitable for onboarding
/// beginners (dropping routine traffic lines, debug/trace noise, and heavy English low-level logs).
fn filter_onboarding_key_events(all_logs: &[String], limit: usize) -> Vec<String> {
    if limit == 0 {
        return Vec::new();
    }
    let filtered: Vec<String> = all_logs
        .iter()
        .filter(|line| {
            if is_routine_mihomo_traffic_log_line(line) {
                return false;
            }
            let lower = line.to_ascii_lowercase();
            if lower.contains(" [debug] ") || lower.contains(" [trace] ") {
                return false;
            }
            let body = strip_log_timestamp_and_level_prefix(line);
            let cjk_count = body
                .chars()
                .filter(|c| ('\u{4E00}'..='\u{9FFF}').contains(c))
                .count();
            if cjk_count < 2 {
                return false;
            }
            let ascii_letters = body.bytes().filter(u8::is_ascii_alphabetic).count();
            !(ascii_letters > 24 && ascii_letters > cjk_count * 3)
        })
        .map(|line| sanitize_log_text(line))
        .collect();
    let start = filtered.len().saturating_sub(limit);
    filtered[start..].to_vec()
}


#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(in crate::commands) fn build_ai_onboarding_prompt_markdown(
    app_version: &str,
    os_label: &str,
    is_elevated: bool,
    cfg: &AppConfig,
    rt: &CoreRuntimeStatus,
    runtime_dto: Option<&CoreRuntimeInfoDto>,
    global_status: &GlobalPreAccelStatus,
    counts: (usize, usize, usize, usize, usize, usize),
    last_error: Option<&str>,
    key_event_logs: &[String],
) -> String {
    let (sub_count, total_nodes, enabled_nodes, tested_nodes, group_count, relay_count) = counts;
    let os_label_zh = format_onboarding_os_label_zh(os_label);
    let route_mode = runtime_dto
        .map(|d| d.route_mode.as_str())
        .unwrap_or_else(|| cfg.route_mode.as_str());
    let route_mode_zh = if route_mode == "single" {
        "单节点直选"
    } else {
        "智能多选组"
    };
    let active_group_name = app_log::sanitize_log_line(
        runtime_dto
            .map(|d| d.active_group_name.as_str())
            .unwrap_or("尚未创建"),
    );
    let active_node_name = app_log::sanitize_log_line(
        runtime_dto
            .map(|d| d.active_node_name.as_str())
            .unwrap_or("待导入节点"),
    );
    let active_node_region = runtime_dto
        .map(|d| d.active_node_region.as_str())
        .unwrap_or("--");
    let selection_desc = if total_nodes == 0 {
        "尚未导入任何节点".to_string()
    } else if route_mode == "single" {
        format!("单节点「{active_node_name}」（地区：{active_node_region}）")
    } else {
        format!("智能多选组「{active_group_name}」 → 当前生效节点「{active_node_name}」（地区：{active_node_region}）")
    };

    let core_state = if rt.running { "运行中" } else { "未启动" };
    let proxy_mode_zh = match cfg.proxy_mode {
        ProxyMode::Rule => "规则分流（国内外自动分流）",
        ProxyMode::Global => "全局代理",
        ProxyMode::Direct => "全部直连",
    };
    let sys_proxy_zh = if cfg.system_proxy.enabled {
        "已开启"
    } else {
        "未开启"
    };
    let eff_tun = runtime_dto
        .map(|d| d.tun_enabled)
        .unwrap_or(cfg.tun.enabled && is_elevated);
    let tun_need_elev = runtime_dto
        .map(|d| d.tun_needs_elevation)
        .unwrap_or(cfg.tun.enabled && !is_elevated);
    let tun_zh = if eff_tun {
        "已开启"
    } else if tun_need_elev {
        "未生效（需管理员权限）"
    } else {
        "未开启"
    };
    let admin_zh = if is_elevated {
        "已是管理员权限"
    } else {
        "普通用户权限"
    };
    let preaccel_brief = format_onboarding_preaccel_plain_zh(
        global_status,
        cfg.preaccel.enabled,
        eff_tun,
        rt.running,
    );
    let security_guidance_line = global_status
        .security_guidance
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|g| format!("- 安全软件放行提示：{}\n", sanitize_log_text(g)))
        .unwrap_or_default();
    let last_err_line = last_error
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|e| format!("- 最近异常提示：{}\n", sanitize_log_text(e)))
        .unwrap_or_else(|| "- 最近异常提示：无\n".to_string());

    let filtered_events = filter_onboarding_key_events(key_event_logs, ONBOARDING_KEY_EVENTS_LIMIT);
    let events_block = if filtered_events.is_empty() {
        "（暂无近期关键状态事件）".to_string()
    } else {
        filtered_events.join("\n")
    };

    let onboarding_guide = catcloud_core::agent_docs::render_zh_onboarding_guide().trim();

    format!(
        "# 请做我的「猫猫云梯（CatCloud）」新手手把手上手导师\n\
\n\
## 给 AI 导师的对话说明\n\
\n\
你好！我正在使用桌面代理管理工具「猫猫云梯（CatCloud）」，我可能是完全不懂代理、协议或网络术语的新手。\n\
请你严格按照以下方式一步一步带我上手：\n\
\n\
1. **先看现状，再带下一步**：请仔细阅读最下方「我当前的实时脱敏状态快照」，先用 1～2 句大白话告诉我我现在走到了哪一步。\n\
2. **一次只教当下最该做的下一小步**：千万不要一口气把所有教程全倒出来！每次只给我 1 个具体、马上能点的小操作，等我回复做完后再继续带我走下一步。\n\
3. **严格用界面上的准确中文按钮名指路**：请对照下方官方上手总纲中的页面名称和按钮名告诉我“点左边哪一页 → 点哪个按钮”，**不要甩源码、配置文件字段名或命令行/终端黑话**（除非我主动要求了解高级用法）。\n\
4. **遇异常优先解卡**：如果我的状态快照里显示有报错、未导入节点、或安全软件拦截提示，请先优先帮我把这个卡点解决掉。\n\
\n\
---\n\
\n\
{onboarding_guide}\n\
\n\
---\n\
\n\
## 我当前的实时脱敏状态快照\n\
\n\
> 以下信息已自动完成隐私脱敏（订阅链接凭据、密码、Token、本地用户名与非系统盘路径、私网及公网 IP 末段均已隐藏），可直接安全发给 AI。\n\
\n\
- 软件版本与环境：猫猫云梯 v{app_version} · {os_label_zh} · {admin_zh}\n\
- 资产进度：订阅 {sub_count} 个 · 节点共 {total_nodes} 个（已启用 {enabled_nodes} 个，已测速 {tested_nodes} 个） · 智能多选组 {group_count} 个 · 国内中转 {relay_count} 条\n\
- 当前路线方式与选中项：{route_mode_zh} ｜ {selection_desc}\n\
- 代理与网络接管：代理核心「{core_state}」 ｜ 分流模式「{proxy_mode_zh}」 ｜ 系统代理「{sys_proxy_zh}」 ｜ 虚拟网卡「{tun_zh}」\n\
- 国内提速与本机环境：{preaccel_brief}\n\
{security_guidance_line}{last_err_line}\
\n\
### 最近关键事件（最多 {ONBOARDING_KEY_EVENTS_LIMIT} 条，已过滤普通连接与底层调试信息）\n\
\n\
```text\n\
{events_block}\n\
```\n\
\n\
请根据我上面当前的真实进度，告诉我现在最先应该做的**下一小步**是什么吧！\n"
    )
}


#[allow(clippy::too_many_arguments)]
fn build_web_ai_realtime_snapshot_section(
    lang: &str,
    app_version: &str,
    os_label: &str,
    is_elevated: bool,
    cfg: &AppConfig,
    rt: &CoreRuntimeStatus,
    runtime_dto: Option<&CoreRuntimeInfoDto>,
    global_status: &GlobalPreAccelStatus,
    counts: (usize, usize, usize, usize, usize, usize),
    last_error: Option<&str>,
    key_event_logs: &[String],
) -> String {
    let norm_lang = catcloud_core::agent_docs::normalize_doc_lang(Some(lang));
    let (sub_count, total_nodes, enabled_nodes, tested_nodes, group_count, relay_count) = counts;
    let route_mode = runtime_dto
        .map(|d| d.route_mode.as_str())
        .unwrap_or_else(|| cfg.route_mode.as_str());
    let active_group_name = app_log::sanitize_log_line(
        runtime_dto
            .map(|d| d.active_group_name.as_str())
            .unwrap_or("--"),
    );
    let active_node_name = app_log::sanitize_log_line(
        runtime_dto
            .map(|d| d.active_node_name.as_str())
            .unwrap_or("--"),
    );
    let active_node_region = runtime_dto
        .map(|d| d.active_node_region.as_str())
        .unwrap_or("--");
    let clean_err = last_error
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(sanitize_log_text);
    let security_guidance = global_status
        .security_guidance
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(sanitize_log_text);

    if norm_lang == "zh-CN" {
        let os_label_zh = format_onboarding_os_label_zh(os_label);
        let route_mode_zh = if route_mode == "single" {
            "单节点直选"
        } else {
            "智能多选组"
        };
        let selection_desc = if total_nodes == 0 {
            "尚未导入任何节点".to_string()
        } else if route_mode == "single" {
            format!("单节点「{active_node_name}」（地区：{active_node_region}）")
        } else {
            format!("智能多选组「{active_group_name}」 → 当前生效节点「{active_node_name}」（地区：{active_node_region}）")
        };
        let core_state = if rt.running { "运行中" } else { "未启动" };
        let proxy_mode_zh = match cfg.proxy_mode {
            ProxyMode::Rule => "规则分流（国内外自动分流）",
            ProxyMode::Global => "全局代理",
            ProxyMode::Direct => "全部直连",
        };
        let sys_proxy_zh = if cfg.system_proxy.enabled {
            "已开启"
        } else {
            "未开启"
        };
        let eff_tun = runtime_dto
            .map(|d| d.tun_enabled)
            .unwrap_or(cfg.tun.enabled && is_elevated);
        let tun_need_elev = runtime_dto
            .map(|d| d.tun_needs_elevation)
            .unwrap_or(cfg.tun.enabled && !is_elevated);
        let tun_zh = if eff_tun {
            "已开启"
        } else if tun_need_elev {
            "未生效（需管理员权限）"
        } else {
            "未开启"
        };
        let admin_zh = if is_elevated {
            "已是管理员权限"
        } else {
            "普通用户权限"
        };
        let preaccel_brief = format_onboarding_preaccel_plain_zh(
            global_status,
            cfg.preaccel.enabled,
            eff_tun,
            rt.running,
        );
        let filtered_events =
            filter_onboarding_key_events(key_event_logs, ONBOARDING_KEY_EVENTS_LIMIT);
        let events_block = if filtered_events.is_empty() {
            "（暂无近期关键状态事件）".to_string()
        } else {
            filtered_events.join("\n")
        };
        let security_line = security_guidance
            .map(|g| format!("- 安全软件放行提示：{g}\n"))
            .unwrap_or_default();
        let err_line = clean_err
            .map(|e| format!("- 最近异常提示：{e}\n"))
            .unwrap_or_else(|| "- 最近异常提示：无\n".to_string());
        format!(
            "## 我当前的实时脱敏进度快照\n\
\n\
> 以下信息已自动完成隐私脱敏（订阅链接凭据、密码、Token、本地路径及公私网 IP 末段均已隐藏），可直接安全发给 AI。\n\
\n\
- 软件版本与环境：猫猫云梯 v{app_version} · {os_label_zh} · {admin_zh}\n\
- 资产进度：订阅 {sub_count} 个 · 节点共 {total_nodes} 个（已启用 {enabled_nodes} 个，已测速 {tested_nodes} 个） · 智能多选组 {group_count} 个 · 国内中转 {relay_count} 条\n\
- 当前路线方式与选中项：{route_mode_zh} ｜ {selection_desc}\n\
- 代理与网络接管：代理核心「{core_state}」 ｜ 分流模式「{proxy_mode_zh}」 ｜ 系统代理「{sys_proxy_zh}」 ｜ 虚拟网卡「{tun_zh}」\n\
- 国内提速与本机环境：{preaccel_brief}\n\
{security_line}{err_line}\
\n\
### 最近关键事件（最多 {ONBOARDING_KEY_EVENTS_LIMIT} 条）\n\
\n\
```text\n\
{events_block}\n\
```\n\
\n\
请结合我上面当前的真实进度，告诉我现在最先应该做的**下一小步**是什么吧！"
        )
    } else {
        let events_sanitized: Vec<String> = key_event_logs
            .iter()
            .rev()
            .take(ONBOARDING_KEY_EVENTS_LIMIT)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .map(|l| sanitize_log_text(l))
            .collect();
        let events_block = if events_sanitized.is_empty() {
            "(no recent key events)".to_string()
        } else {
            events_sanitized.join("\n")
        };
        let err_text = clean_err.unwrap_or_else(|| "none".to_string());
        let eff_tun = runtime_dto
            .map(|d| d.tun_enabled)
            .unwrap_or(cfg.tun.enabled && is_elevated);
        let tun_need_elev = runtime_dto
            .map(|d| d.tun_needs_elevation)
            .unwrap_or(cfg.tun.enabled && !is_elevated);
        let tun_active = rt.running && eff_tun;
        let tun_en = if eff_tun {
            "true"
        } else if tun_need_elev {
            "false (needs_elevation)"
        } else {
            "false"
        };
        let preaccel_brief =
            format_global_preaccel_brief(global_status, cfg.preaccel.enabled, tun_active);
        let (heading, ask_line) = match norm_lang {
            "ja" => (
                "## 現在のリアルタイム状態スナップショット（自動マスキング済み）",
                "上記の状態を踏まえて、今すぐ実行すべき**次の 1 ステップ**を教えてください。",
            ),
            "ru" => (
                "## Текущий снимок состояния (автоматически обезличен)",
                "Исходя из текущего состояния выше, подскажи **один следующий конкретный шаг**.",
            ),
            _ => (
                "## My Current Sanitized Progress Snapshot",
                "Based on my current state above, please tell me the **single next step** I should take right now.",
            ),
        };
        format!(
            "{heading}\n\
\n\
- App / OS: CatCloud v{app_version} · {os_label} · elevated={is_elevated}\n\
- Inventory: subscriptions={sub_count}, nodes={total_nodes} (enabled={enabled_nodes}, tested={tested_nodes}), groups={group_count}, relays={relay_count}\n\
- Routing: route_mode={route_mode}, group={active_group_name}, node={active_node_name} ({active_node_region})\n\
- Core & Takeover: core_running={}, proxy_mode={}, system_proxy={}, tun={}\n\
- Domestic Boost: {preaccel_brief}\n\
- Last Error: {err_text}\n\
\n\
### Recent Key Events (up to {ONBOARDING_KEY_EVENTS_LIMIT})\n\
\n\
```text\n\
{events_block}\n\
```\n\
\n\
{ask_line}",
            rt.running,
            cfg.proxy_mode.as_str(),
            cfg.system_proxy.enabled,
            tun_en,
        )
    }
}


#[tauri::command]
pub async fn build_ai_onboarding_prompt(
    state: State<'_, AppState>,
    lang: Option<String>,
    module_id: Option<String>,
) -> Result<String, String> {
    let norm_lang = resolve_effective_doc_lang(&state, lang.as_deref());
    let target_module = module_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(catcloud_core::agent_docs::ONBOARDING_DOC_ID);
    let guide = catcloud_core::agent_docs::render_web_ai_guide(target_module, norm_lang)
        .map_err(|e| e.to_string())?;

    let cfg = state.snapshot_config();
    let rt = state.snapshot_runtime();
    let plat = default_platform();
    let caps = plat.capabilities();
    let runtime_dto = build_runtime_info_dto(&state).ok();
    let global_status = state.snapshot_global_preaccel();

    let (sub_count, total_nodes, enabled_nodes, tested_nodes, group_count, relay_count) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let subs = db.list_subscriptions().map(|v| v.len()).unwrap_or(0);
        let nodes = db.list_nodes().unwrap_or_default();
        let total = nodes.len();
        let enabled = nodes.iter().filter(|n| n.enabled).count();
        let tested = if nodes.is_empty() {
            0
        } else {
            let node_ids: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
            db.get_probe_snapshots_batch(&node_ids, None)
                .map(|snaps| {
                    snaps
                        .values()
                        .filter(|s| {
                            s.latency_ms.is_some_and(|ms| ms.is_finite() && ms > 0.0)
                                || s.up_mbps.is_some_and(|v| v.is_finite() && v > 0.0)
                                || s.down_mbps.is_some_and(|v| v.is_finite() && v > 0.0)
                                || s.ok
                        })
                        .count()
                })
                .unwrap_or(0)
        };
        let groups = db.list_multi_groups().map(|v| v.len()).unwrap_or(0);
        let relays = db.list_preaccel_relays(false).map(|v| v.len()).unwrap_or(0);
        (subs, total, enabled, tested, groups, relays)
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
    let merged_key_events =
        merge_diagnostic_key_events(ring_events, &merged_logs, DIAGNOSTICS_KEY_EVENTS_LIMIT);

    let snapshot = build_web_ai_realtime_snapshot_section(
        norm_lang,
        env!("CARGO_PKG_VERSION"),
        &caps.os,
        caps.is_elevated,
        &cfg,
        &rt,
        runtime_dto.as_ref(),
        &global_status,
        (
            sub_count,
            total_nodes,
            enabled_nodes,
            tested_nodes,
            group_count,
            relay_count,
        ),
        last_error.as_deref(),
        &merged_key_events,
    );

    Ok(format!("{}\n\n---\n\n{snapshot}\n", guide.trim()))
}


#[cfg(test)]
pub(in crate::commands) fn build_sanitized_diagnostics_report(
    state: &AppState,
    live_conns: Option<&ConnectionsSnapshot>,
) -> Result<serde_json::Value, String> {
    build_sanitized_diagnostics_report_with_disk_logs(state, live_conns, None)
}


fn build_sanitized_diagnostics_report_with_disk_logs(
    state: &AppState,
    live_conns: Option<&ConnectionsSnapshot>,
    preloaded_disk_logs: Option<Vec<String>>,
) -> Result<serde_json::Value, String> {
    let cfg = state.snapshot_config();
    let rt = state.snapshot_runtime();
    let plat = default_platform();
    let caps = plat.capabilities();
    let runtime_dto = build_runtime_info_dto(state).ok();
    let global_status = state.snapshot_global_preaccel();
    let (sub_count, node_count, group_count, relay_count) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        (
            db.list_subscriptions().map(|v| v.len()).unwrap_or(0),
            db.list_node_ids().map(|v| v.len()).unwrap_or(0),
            db.list_multi_groups().map(|v| v.len()).unwrap_or(0),
            db.list_preaccel_relays(false).map(|v| v.len()).unwrap_or(0),
        )
    };

    let (conn_summary, core_mem_bytes) = if let Some(snap) = live_conns {
        let summary = summarize_connections(&snap.connections);
        let mem = if snap.memory > 0 {
            snap.memory
        } else {
            state
                .cached_metrics
                .read()
                .map(|m| m.core_mem_bytes)
                .unwrap_or(0)
        };
        (summary, mem)
    } else if let Ok(m) = state.cached_metrics.read() {
        (
            ConnectionSummaryCounts {
                app_connections: m.app_connections,
                tunnel_connections: m.tunnel_connections,
                direct_connections: m.direct_connections,
                proxied_connections: m.proxied_connections,
            },
            m.core_mem_bytes,
        )
    } else {
        (ConnectionSummaryCounts::default(), 0)
    };

    let geodata_status = collect_geodata_status(&state.paths.runtime_dir);
    let last_error = rt
        .last_error
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(app_log::sanitize_log_line)
        .or_else(|| state.last_app_error_snapshot());
    let ring_key_events = state
        .app_logger
        .read_recent_key_events(app_log::MAX_KEY_EVENT_RING_LEN);
    let all_merged_logs = match preloaded_disk_logs {
        Some(disk_lines) => {
            let mem_logs = state.telemetry.logs_snapshot();
            merge_sanitized_recent_logs(disk_lines, mem_logs, DIAGNOSTICS_DISK_SCAN_LIMIT)
        }
        None => collect_sanitized_recent_logs(state, DIAGNOSTICS_DISK_SCAN_LIMIT),
    };
    let key_event_logs = merge_diagnostic_key_events(
        ring_key_events,
        &all_merged_logs,
        DIAGNOSTICS_KEY_EVENTS_LIMIT,
    );
    let (_, tail_logs) = sample_diagnostic_logs(&all_merged_logs, 0, DIAGNOSTICS_TAIL_LOGS_LIMIT);
    let recent_logs = {
        let start = all_merged_logs
            .len()
            .saturating_sub(DIAGNOSTICS_JSON_RECENT_LOGS_LIMIT);
        all_merged_logs[start..].to_vec()
    };

    let route_mode = runtime_dto
        .as_ref()
        .map(|d| d.route_mode.clone())
        .unwrap_or_else(|| cfg.route_mode.as_str().to_string());
    let active_group_name = app_log::sanitize_log_line(
        runtime_dto
            .as_ref()
            .map(|d| d.active_group_name.as_str())
            .unwrap_or("默认路线"),
    );
    let active_node_name = app_log::sanitize_log_line(
        runtime_dto
            .as_ref()
            .map(|d| d.active_node_name.as_str())
            .unwrap_or("待导入节点"),
    );
    let active_node_region = runtime_dto
        .as_ref()
        .map(|d| d.active_node_region.clone())
        .unwrap_or_else(|| "--".to_string());
    let preaccel_relay_name = runtime_dto
        .as_ref()
        .and_then(|d| d.preaccel_relay_name.as_deref())
        .map(app_log::sanitize_log_line);

    let cli_path_display = catcloud_core::sanitize::redact_path_for_display(
        &resolve_local_cli_path(state).to_string_lossy(),
    );
    let data_dir_display = catcloud_core::sanitize::redact_path_for_display(
        &catcloud_core::paths::normalize_os_path(&state.paths.root_data_dir).to_string_lossy(),
    );

    let dns_diagnostics = {
        let disk_diag = analyze_dns_tls_diagnostics_from_log_file(
            &state.app_logger.active_log_path(),
            256 * 1024,
        );
        if disk_diag.failure_count > 0 || all_merged_logs.is_empty() {
            disk_diag
        } else {
            let mem_diag = analyze_dns_tls_diagnostics(
                &all_merged_logs,
                "diagnostics merged logs (tail <= 256 KiB)",
            );
            if mem_diag.failure_count > 0 || mem_diag.network_timeout_only_count > 0 {
                mem_diag
            } else {
                disk_diag
            }
        }
    };

    let os_label = format!("{} {}", caps.os, caps.arch);
    let ai_prompt_markdown = build_ai_diagnostics_markdown(
        env!("CARGO_PKG_VERSION"),
        &os_label,
        caps.is_elevated,
        state.paths.is_portable,
        &cfg,
        &rt,
        runtime_dto.as_ref(),
        &global_status,
        (sub_count, node_count, group_count, relay_count),
        conn_summary,
        core_mem_bytes,
        &geodata_status,
        &dns_diagnostics,
        last_error.as_deref(),
        &key_event_logs,
        &tail_logs,
        &cli_path_display,
        &data_dir_display,
    );

    let eff_tun = runtime_dto
        .as_ref()
        .map(|d| d.tun_enabled)
        .unwrap_or(effective_tun_enabled(state, &cfg));
    let tun_need_elev = runtime_dto
        .as_ref()
        .map(|d| d.tun_needs_elevation)
        .unwrap_or(tun_needs_elevation(state, &cfg));
    let mut report = serde_json::json!({
        "app_version": env!("CARGO_PKG_VERSION"),
        "os": caps.os,
        "arch": caps.arch,
        "is_elevated": caps.is_elevated,
        "is_portable": state.paths.is_portable,
        "instance_hash": state.paths.instance_hash,
        "cli_path": cli_path_display,
        "data_dir": data_dir_display,
        "core_running": rt.running,
        "core_version": rt.version,
        "proxy_mode": cfg.proxy_mode,
        "mixed_port": if rt.running { rt.mixed_port } else { cfg.mixed_port },
        "controller_port": if rt.running { rt.controller_port } else { cfg.controller_port },
        "dns_listen_port": if rt.running { rt.dns_listen_port } else { cfg.dns_listen_port },
        "core_ipv6": cfg.core_ipv6,
        "dns_ipv6": cfg.dns.ipv6,
        "tun_enabled": eff_tun,
        "tun_configured": cfg.tun.enabled,
        "tun_needs_elevation": tun_need_elev,
        "tun_stack": cfg.tun.stack_mode,
        "effective_tun_mtu": runtime_dto.as_ref().and_then(|d| d.effective_tun_mtu),
        "preaccel_enabled": cfg.preaccel.enabled,
        "skip_443_native": cfg.preaccel.skip_443_native,
        "preaccel_transport": runtime_dto.as_ref().and_then(|d| d.preaccel_transport.as_ref()),
        "counts": {
            "subscriptions": sub_count,
            "nodes": node_count,
            "multi_groups": group_count,
            "preaccel_relays": relay_count,
        },
        "route_summary": {
            "route_mode": route_mode,
            "active_group_name": active_group_name,
            "active_node_name": active_node_name,
            "active_node_region": active_node_region,
            "system_proxy_enabled": cfg.system_proxy.enabled,
            "tun_enabled": eff_tun,
            "tun_configured": cfg.tun.enabled,
            "tun_needs_elevation": tun_need_elev,
            "preaccel_active": cfg.preaccel.enabled,
            "preaccel_relay_name": preaccel_relay_name,
            "preaccel_effective_carrier": runtime_dto
                .as_ref()
                .map(|d| d.preaccel_effective_carrier.as_str())
                .unwrap_or("off"),
            "standalone_tunnel_suspended_for_tun": runtime_dto
                .as_ref()
                .map(|d| d.standalone_tunnel_suspended_for_tun)
                .unwrap_or(false),
            "domestic_direct_enabled": cfg.rules_override.domestic_direct_enabled,
            "block_quic_udp_443": cfg.rules_override.block_quic_udp_443,
            "memory_tier": cfg.core_runtime.memory_tier,
        },
        "geodata_status": geodata_status,
        "dns_diagnostics": dns_diagnostics,
        "connection_summary": {
            "app_connections": conn_summary.app_connections,
            "tunnel_connections": conn_summary.tunnel_connections,
            "direct_connections": conn_summary.direct_connections,
            "proxied_connections": conn_summary.proxied_connections,
        },
        "last_error": last_error,
        "key_event_logs": key_event_logs,
        "recent_logs": recent_logs,
        "ai_prompt_markdown": ai_prompt_markdown,
        "sanitized": true
    });
    // Final whole-tree sanitization safety pass guaranteeing zero leaked full public/private/TUN/DNS IPs.
    catcloud_core::sanitize::sanitize_json_value(&mut report);
    Ok(report)
}


#[tauri::command]
pub async fn export_sanitized_diagnostics(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let live_snap = if state.snapshot_runtime().running && state.adapter.has_live_controller().await
    {
        tokio::time::timeout(Duration::from_millis(600), state.adapter.list_connections())
            .await
            .ok()
            .and_then(|res| res.ok())
    } else {
        None
    };

    if let Some(ref snap) = live_snap {
        let summary = summarize_connections(&snap.connections);
        if let Ok(mut m) = state.cached_metrics.write() {
            m.app_connections = summary.app_connections;
            m.tunnel_connections = summary.tunnel_connections;
            m.direct_connections = summary.direct_connections;
            m.proxied_connections = summary.proxied_connections;
            if snap.upload_total > m.up_total_bytes {
                m.up_total_bytes = snap.upload_total;
            }
            if snap.download_total > m.down_total_bytes {
                m.down_total_bytes = snap.download_total;
            }
            if snap.memory > 0 {
                m.core_mem_bytes = snap.memory;
            }
        }
    }

    let logger = Arc::clone(&state.app_logger);
    let disk_logs = tokio::task::spawn_blocking(move || {
        logger.read_recent_lines(DIAGNOSTICS_DISK_SCAN_LIMIT)
    })
    .await
    .unwrap_or_default();

    build_sanitized_diagnostics_report_with_disk_logs(&state, live_snap.as_ref(), Some(disk_logs))
}

