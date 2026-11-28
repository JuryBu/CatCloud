//! Read-only `net doctor`/`connections`/`match`, managed process checks, and `logs tail`.

use anyhow::Result;
use catcloud_core::config::{self, ValidationSeverity};
use catcloud_core::core_adapter::config_compiler::{
    CompileInput, compile_mihomo_config_with_runtime_dir,
};
use catcloud_core::core_adapter::dns_diag::{
    DNS_TLS_STATUS_CERT_FAILED, DNS_TLS_STATUS_DEGRADED_RECOVERED, DnsTlsDiagnostics,
    analyze_dns_tls_diagnostics, analyze_dns_tls_diagnostics_from_log_file,
};
use catcloud_core::core_adapter::port_guard::{AllocatedPorts, is_port_available_tcp_udp};
use catcloud_core::core_adapter::rule_matcher::{
    RuleMatchQuery, evaluate_compiled_rules, matches_compiled_fake_ip_filter,
};
use catcloud_core::core_adapter::{
    ActiveConnection, MihomoAdapter, ResolvedControllerEndpoint, format_host_port,
    is_internal_or_preaccel_connection, read_live_runtime_controller_meta,
    resolve_effective_controller_endpoint_info, resolve_mihomo_binary,
};
use catcloud_core::models::{PreAccelRelay, ProxyMode, RouteTargetMode};
use catcloud_core::platform::{
    PortListenerOwner, default_platform, get_process_start_time_unix, list_listening_port_owners,
};
use catcloud_core::preaccel::generator::build_preaccel_compile_plan;
use catcloud_core::preaccel::global_tunnel::{
    detect_host_security_products, locate_windivert_files, read_global_preaccel_runtime_meta,
};
use catcloud_core::preaccel::schema::evaluate_expiry;
use catcloud_core::process_guard::JobGuard;
use catcloud_core::sanitize::{
    redact_ip_or_host, redact_path_for_display, sanitize_json_value, sanitize_log_line,
};
use catcloud_core::subscription::process_attach::{ProcessCandidate, list_process_candidates};
use catcloud_core::{AppPaths, CatError};
use chrono::{DateTime, Local, NaiveDateTime, NaiveTime, TimeZone, Utc};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use super::args::{LogsCommand, NetCommand};
use super::config_reload::{
    inspect_active_core_ports, is_valid_managed_pid, pid_start_time_matches_fail_closed,
    probe_live_controller,
};
use super::preaccel::{
    collect_cli_preaccel_transport_snapshot, is_live_global_preaccel_pid,
    verify_managed_pid_with_start_time,
};
use super::redact_helpers::{
    emit_output, open_storage, read_bounded_file_lines, redact_config_issues,
    redact_connection_for_readonly, redact_process_candidate,
};
use super::status_docs_update::{collect_geodata_status, is_cli_tun_privilege_ready};

pub(super) async fn handle_net(paths: &AppPaths, as_json: bool, action: NetCommand) -> Result<()> {
    match action {
        NetCommand::Doctor => {
            let (out, human) = build_net_doctor_payload(paths).await?;
            emit_output(as_json, &out, &human)
        }

        NetCommand::Connections {
            limit,
            reveal_secrets,
        } => {
            let (out, human) =
                build_net_connections_payload(paths, limit, reveal_secrets).await?;
            emit_output(as_json, &out, &human)
        }

        NetCommand::Match {
            domain,
            network,
            port,
            process_name,
            process_path,
        } => {
            let (out, human) = build_net_match_payload(
                paths,
                &domain,
                &network,
                port,
                process_name.as_deref(),
                process_path.as_deref(),
            )
            .await?;
            emit_output(as_json, &out, &human)
        }
    }
}

pub(super) fn handle_logs(paths: &AppPaths, as_json: bool, action: LogsCommand) -> Result<()> {
    match action {
        LogsCommand::Tail {
            lines,
            level,
            since,
            until,
            reveal_secrets,
        } => {
            let (out, human) = build_logs_tail_payload_with_options(
                paths,
                lines,
                &level,
                since.as_deref(),
                until.as_deref(),
                reveal_secrets,
                Local::now(),
            )?;
            emit_output(as_json, &out, &human)
        }
    }
}

const MAX_LOG_TAIL_LINES_CAP: usize = 2000;

const MAX_LOGS_TAIL_READ_BYTES_PER_FILE: u64 = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogLevelFilter {
    All,
    Error,
    Warning,
    Info,
    Debug,
}

impl LogLevelFilter {
    fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }
}

fn parse_log_level_filter(raw: &str) -> Result<LogLevelFilter> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "all" | "" => Ok(LogLevelFilter::All),
        "error" | "err" => Ok(LogLevelFilter::Error),
        "warning" | "warn" => Ok(LogLevelFilter::Warning),
        "info" => Ok(LogLevelFilter::Info),
        "debug" => Ok(LogLevelFilter::Debug),
        other => anyhow::bail!("unsupported log level `{other}` (use all|error|warning|info|debug)"),
    }
}

fn detect_log_line_severity(line: &str) -> Option<u8> {
    // 4=ERROR, 3=WARN, 2=INFO, 1=DEBUG/TRACE
    let upper = line.to_ascii_uppercase();
    if upper.contains(" ERROR ")
        || upper.contains("[ERROR]")
        || upper.contains("\"LEVEL\":\"ERROR\"")
        || upper.contains("LEVEL=ERROR")
        || upper.starts_with("ERROR ")
        || upper.starts_with("ERROR:")
    {
        return Some(4);
    }
    if upper.contains(" WARN ")
        || upper.contains(" WARNING ")
        || upper.contains("[WARN]")
        || upper.contains("[WARNING]")
        || upper.contains("\"LEVEL\":\"WARN")
        || upper.contains("LEVEL=WARN")
        || upper.starts_with("WARN ")
        || upper.starts_with("WARNING ")
    {
        return Some(3);
    }
    if upper.contains(" INFO ")
        || upper.contains("[INFO]")
        || upper.contains("\"LEVEL\":\"INFO\"")
        || upper.contains("LEVEL=INFO")
        || upper.starts_with("INFO ")
    {
        return Some(2);
    }
    if upper.contains(" DEBUG ")
        || upper.contains(" TRACE ")
        || upper.contains("[DEBUG]")
        || upper.contains("[TRACE]")
        || upper.contains("\"LEVEL\":\"DEBUG\"")
        || upper.contains("LEVEL=DEBUG")
    {
        return Some(1);
    }
    None
}

fn line_matches_log_level(line: &str, filter: LogLevelFilter) -> bool {
    match filter {
        LogLevelFilter::All => true,
        LogLevelFilter::Error => detect_log_line_severity(line).is_some_and(|s| s >= 4),
        LogLevelFilter::Warning => detect_log_line_severity(line).is_some_and(|s| s >= 3),
        LogLevelFilter::Info => detect_log_line_severity(line).map_or(true, |s| s >= 2),
        LogLevelFilter::Debug => detect_log_line_severity(line).map_or(true, |s| s >= 1),
    }
}

fn parse_log_time_bound(raw: &str, now_local: DateTime<Local>) -> Result<DateTime<Utc>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        anyhow::bail!("time filter cannot be empty");
    }

    // 1. RFC3339 (e.g. `2026-11-26T03:44:51+08:00` or `2026-11-26T03:44:51Z`)
    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return Ok(dt.with_timezone(&Utc));
    }

    // 2. Relative window (e.g. `30m`, `2h`, `45s`, `1d`, optionally prefixed with `-`)
    let rel = trimmed.strip_prefix('-').unwrap_or(trimmed).trim();
    let digit_end = rel
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rel.len());
    if digit_end > 0 && digit_end < rel.len() {
        if let Ok(amount) = rel[..digit_end].parse::<i64>() {
            let unit = rel[digit_end..].trim().to_ascii_lowercase();
            let secs = match unit.as_str() {
                "s" | "sec" | "secs" => Some(amount),
                "m" | "min" | "mins" => amount.checked_mul(60),
                "h" | "hr" | "hrs" => amount.checked_mul(3600),
                "d" | "day" | "days" => amount.checked_mul(86400),
                _ => None,
            };
            if let Some(delta_secs) = secs {
                return Ok(now_local.with_timezone(&Utc) - chrono::Duration::seconds(delta_secs));
            }
        }
    }

    // 3. Local datetime `YYYY-MM-DD HH:MM(:SS)` or `YYYY-MM-DDTHH:MM(:SS)`
    for fmt in [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M",
    ] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(trimmed, fmt) {
            if let Some(local_dt) = Local.from_local_datetime(&naive).earliest() {
                return Ok(local_dt.with_timezone(&Utc));
            }
            return Ok(Utc.from_utc_datetime(&naive));
        }
    }

    // 4. Local today `HH:MM(:SS)`
    for fmt in ["%H:%M:%S", "%H:%M"] {
        if let Ok(naive_time) = NaiveTime::parse_from_str(trimmed, fmt) {
            let naive = now_local.date_naive().and_time(naive_time);
            if let Some(local_dt) = Local.from_local_datetime(&naive).earliest() {
                return Ok(local_dt.with_timezone(&Utc));
            }
            return Ok(Utc.from_utc_datetime(&naive));
        }
    }

    anyhow::bail!(
        "unsupported time format `{trimmed}` (use RFC3339, YYYY-MM-DD HH:MM[:SS], HH:MM, or relative like 30m / 2h)"
    )
}

fn is_iso_datetime_prefix(slice: &[u8]) -> bool {
    slice.len() == 19
        && slice[0].is_ascii_digit()
        && slice[1].is_ascii_digit()
        && slice[2].is_ascii_digit()
        && slice[3].is_ascii_digit()
        && slice[4] == b'-'
        && slice[5].is_ascii_digit()
        && slice[6].is_ascii_digit()
        && slice[7] == b'-'
        && slice[8].is_ascii_digit()
        && slice[9].is_ascii_digit()
        && matches!(slice[10], b'T' | b't' | b' ')
        && slice[11].is_ascii_digit()
        && slice[12].is_ascii_digit()
        && slice[13] == b':'
        && slice[14].is_ascii_digit()
        && slice[15].is_ascii_digit()
        && slice[16] == b':'
        && slice[17].is_ascii_digit()
        && slice[18].is_ascii_digit()
}

fn extract_log_line_timestamp_utc(line: &str) -> Option<DateTime<Utc>> {
    // 1. Mihomo logfmt `time="..."`
    if let Some(pos) = line.find("time=\"") {
        let rest = &line[pos + 6..];
        if let Some(end) = rest.find('"') {
            let cand = rest[..end].trim();
            if let Ok(dt) = DateTime::parse_from_rfc3339(cand) {
                return Some(dt.with_timezone(&Utc));
            }
            if let Ok(naive) = NaiveDateTime::parse_from_str(cand, "%Y-%m-%d %H:%M:%S") {
                return Local
                    .from_local_datetime(&naive)
                    .earliest()
                    .map(|d| d.with_timezone(&Utc))
                    .or_else(|| Some(Utc.from_utc_datetime(&naive)));
            }
        }
    }

    // 2. Embedded or leading ISO/RFC3339 or `YYYY-MM-DD HH:MM:SS`
    let bytes = line.as_bytes();
    if bytes.len() >= 19 {
        let scan_limit = (bytes.len() - 19).min(64);
        for i in 0..=scan_limit {
            if is_iso_datetime_prefix(&bytes[i..i + 19]) {
                let mut end = i + 19;
                if end < bytes.len() && bytes[end] == b'.' {
                    end += 1;
                    while end < bytes.len() && bytes[end].is_ascii_digit() {
                        end += 1;
                    }
                }
                let mut has_tz = false;
                if end < bytes.len() && matches!(bytes[end], b'Z' | b'z') {
                    end += 1;
                    has_tz = true;
                } else if end + 6 <= bytes.len()
                    && matches!(bytes[end], b'+' | b'-')
                    && bytes[end + 1].is_ascii_digit()
                    && bytes[end + 2].is_ascii_digit()
                    && bytes[end + 3] == b':'
                    && bytes[end + 4].is_ascii_digit()
                    && bytes[end + 5].is_ascii_digit()
                {
                    end += 6;
                    has_tz = true;
                }
                let token = &line[i..end];
                if has_tz {
                    if let Ok(dt) = DateTime::parse_from_rfc3339(token) {
                        return Some(dt.with_timezone(&Utc));
                    }
                    let normalized = token.replacen(' ', "T", 1);
                    if let Ok(dt) = DateTime::parse_from_rfc3339(&normalized) {
                        return Some(dt.with_timezone(&Utc));
                    }
                }
                let base_19 = &line[i..i + 19];
                for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"] {
                    if let Ok(naive) = NaiveDateTime::parse_from_str(base_19, fmt) {
                        return Local
                            .from_local_datetime(&naive)
                            .earliest()
                            .map(|d| d.with_timezone(&Utc))
                            .or_else(|| Some(Utc.from_utc_datetime(&naive)));
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
pub(super) fn build_logs_tail_payload(
    paths: &AppPaths,
    requested_lines: usize,
    level_raw: &str,
) -> Result<(Value, String)> {
    build_logs_tail_payload_with_options(
        paths,
        requested_lines,
        level_raw,
        None,
        None,
        false,
        Local::now(),
    )
}

pub(super) fn build_logs_tail_payload_with_options(
    paths: &AppPaths,
    requested_lines: usize,
    level_raw: &str,
    since_raw: Option<&str>,
    until_raw: Option<&str>,
    reveal_secrets: bool,
    now_local: DateTime<Local>,
) -> Result<(Value, String)> {
    let filter = parse_log_level_filter(level_raw)?;
    let since_utc = since_raw
        .map(|s| parse_log_time_bound(s, now_local))
        .transpose()?;
    let until_utc = until_raw
        .map(|s| parse_log_time_bound(s, now_local))
        .transpose()?;
    if let (Some(s), Some(u)) = (since_utc, until_utc) {
        if s > u {
            anyhow::bail!("--since time cannot be later than --until time");
        }
    }
    let has_time_filter = since_utc.is_some() || until_utc.is_some();

    let capped = requested_lines.min(MAX_LOG_TAIL_LINES_CAP);
    let archive2_path = paths.logs_dir.join("catcloud.log.2");
    let archive1_path = paths.logs_dir.join("catcloud.log.1");
    let primary_path = paths.logs_dir.join("catcloud.log");

    let mut sources: Vec<String> = Vec::new();
    let mut combined: Vec<String> = Vec::new();
    for (label, candidate) in [
        ("catcloud.log.2", &archive2_path),
        ("catcloud.log.1", &archive1_path),
        ("catcloud.log", &primary_path),
    ] {
        if candidate.is_file() {
            sources.push(label.to_string());
            combined.extend(read_bounded_file_lines(
                candidate,
                MAX_LOGS_TAIL_READ_BYTES_PER_FILE,
            ));
        }
    }

    let mut matched: Vec<String> = Vec::new();
    let mut last_ts_matched = false;
    for line in combined {
        if has_time_filter {
            let in_window = match extract_log_line_timestamp_utc(&line) {
                Some(ts) => {
                    let ok = since_utc.map_or(true, |s| ts >= s)
                        && until_utc.map_or(true, |u| ts <= u);
                    last_ts_matched = ok;
                    ok
                }
                None => last_ts_matched,
            };
            if !in_window {
                continue;
            }
        }
        if line_matches_log_level(&line, filter) {
            matched.push(line);
        }
    }

    if matched.len() > capped {
        let drop_count = matched.len() - capped;
        matched.drain(0..drop_count);
    }
    let final_lines: Vec<String> = if reveal_secrets {
        matched
    } else {
        matched.iter().map(|l| sanitize_log_line(l)).collect()
    };

    let mut out = json!({
        "ok": true,
        "sanitized": !reveal_secrets,
        "level": filter.as_str(),
        "since": since_raw,
        "until": until_raw,
        "since_utc": since_utc.map(|d| d.to_rfc3339()),
        "until_utc": until_utc.map(|d| d.to_rfc3339()),
        "requested_lines": capped,
        "count": final_lines.len(),
        "sources": sources,
        "lines": &final_lines,
    });
    if !reveal_secrets {
        sanitize_json_value(&mut out);
    }
    let human = if final_lines.is_empty() {
        format!(
            "No matching log lines (level={}, sources={:?}).",
            filter.as_str(),
            out["sources"]
        )
    } else {
        final_lines.join("\n")
    };
    Ok((out, human))
}

pub(super) fn classify_and_format_connections(
    conns: &[ActiveConnection],
    limit: usize,
    reveal_secrets: bool,
) -> (
    Vec<ActiveConnection>,
    Vec<ActiveConnection>,
    Vec<ActiveConnection>,
    usize,
    usize,
) {
    let mut app_all: Vec<ActiveConnection> = Vec::new();
    let mut internal_all: Vec<ActiveConnection> = Vec::new();
    let mut all_formatted: Vec<ActiveConnection> = Vec::with_capacity(conns.len().min(limit));

    for conn in conns {
        let formatted = if reveal_secrets {
            conn.clone()
        } else {
            redact_connection_for_readonly(conn)
        };
        if all_formatted.len() < limit {
            all_formatted.push(formatted.clone());
        }
        if is_internal_or_preaccel_connection(
            &conn.conn_type,
            &conn.chains,
            &conn.host,
            &conn.rule,
        ) {
            internal_all.push(formatted);
        } else {
            app_all.push(formatted);
        }
    }

    let app_count = app_all.len();
    let internal_count = internal_all.len();
    app_all.truncate(limit);
    internal_all.truncate(limit);
    (all_formatted, app_all, internal_all, app_count, internal_count)
}

async fn build_net_connections_payload(
    paths: &AppPaths,
    limit: usize,
    reveal_secrets: bool,
) -> Result<(Value, String)> {
    let cfg = config::load_or_init(paths)?;
    let job_guard = Arc::new(JobGuard::new()?);
    let ep = resolve_effective_controller_endpoint_info(paths, &cfg);
    let controller_addr = format_host_port(&ep.host, ep.port);
    let adapter = MihomoAdapter::with_controller_endpoint(
        job_guard,
        &ep.host,
        ep.port,
        ep.secret,
    )?;

    match tokio::time::timeout(Duration::from_secs(2), adapter.list_connections()).await {
        Ok(Ok(snapshot)) => {
            let total = snapshot.connections.len();
            let (connections, app_connections, internal_connections, app_count, internal_count) =
                classify_and_format_connections(&snapshot.connections, limit, reveal_secrets);
            let mut out = json!({
                "ok": true,
                "sanitized": !reveal_secrets,
                "core_running": true,
                "auth_error": false,
                "controller_addr": controller_addr,
                "download_total": snapshot.download_total,
                "upload_total": snapshot.upload_total,
                "memory": snapshot.memory,
                "total_connections": total,
                "returned_connections": connections.len(),
                "app_count": app_count,
                "internal_count": internal_count,
                "app_connections": app_connections,
                "internal_connections": internal_connections,
                "connections": connections,
            });
            if !reveal_secrets {
                sanitize_json_value(&mut out);
            }
            let human = format!(
                "Active connections: showing {}/{total} (app={}, internal={}, sanitized={}, core_running=true).",
                out["returned_connections"],
                app_count,
                internal_count,
                !reveal_secrets
            );
            Ok((out, human))
        }
        Ok(Err(CatError::Core(msg))) if msg.contains("HTTP 401") || msg.contains("HTTP 403") => {
            let clean = sanitize_log_line(&msg);
            let mut out = json!({
                "ok": true,
                "sanitized": !reveal_secrets,
                "core_running": true,
                "auth_error": true,
                "controller_addr": controller_addr,
                "download_total": 0u64,
                "upload_total": 0u64,
                "memory": 0u64,
                "total_connections": 0usize,
                "returned_connections": 0usize,
                "app_count": 0usize,
                "internal_count": 0usize,
                "app_connections": [],
                "internal_connections": [],
                "connections": [],
                "note": format!("Controller reachable but authentication failed ({clean})."),
            });
            if !reveal_secrets {
                sanitize_json_value(&mut out);
            }
            Ok((
                out,
                "Core controller reachable, but authentication failed; returning 0 connections."
                    .to_string(),
            ))
        }
        _ => {
            let mut out = json!({
                "ok": true,
                "sanitized": !reveal_secrets,
                "core_running": false,
                "auth_error": false,
                "controller_addr": controller_addr,
                "download_total": 0u64,
                "upload_total": 0u64,
                "memory": 0u64,
                "total_connections": 0usize,
                "returned_connections": 0usize,
                "app_count": 0usize,
                "internal_count": 0usize,
                "app_connections": [],
                "internal_connections": [],
                "connections": [],
                "note": "Mihomo core controller is not currently running or reachable.",
            });
            if !reveal_secrets {
                sanitize_json_value(&mut out);
            }
            Ok((
                out,
                "Mihomo core is not running (core_running=false); 0 active connections."
                    .to_string(),
            ))
        }
    }
}

fn is_path_writable_probe(dir: &Path) -> bool {
    let probe = dir.join(format!(".catcloud_doc_probe.{}", std::process::id()));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Evaluate effective TUN status for `net doctor` / `status` / `config diag`.
///
/// Precedence:
/// 1. Live `Tun` inbound connections prove TUN is actively handling traffic.
/// 2. Authoritative `GET /configs` (`live_tun_enable == Some(true | false)`) overrides optimistic
///    inference so an unprivileged running core with `tun.enable == false` NEVER misreports
///    `tun_enabled = true` via `live_core_with_tun_config`.
/// 3. Only when `live_tun_enable` is unavailable (`None`) do we fall back to inferring from
///    `core_running` / process privileges.
pub(super) fn evaluate_doctor_tun_state(
    tun_configured: bool,
    tun_privilege_ready: bool,
    core_running: bool,
    has_live_tun_connections: bool,
    live_tun_enable: Option<bool>,
) -> (bool, bool, &'static str) {
    if has_live_tun_connections {
        return (true, false, "live_tun_connections");
    }
    if core_running && live_tun_enable == Some(true) {
        return (true, false, "live_core_configs");
    }
    if core_running && live_tun_enable == Some(false) {
        if !tun_configured {
            return (false, false, "disabled");
        }
        if !tun_privilege_ready {
            return (false, true, "live_core_tun_disabled_needs_elevation");
        }
        return (false, false, "live_core_tun_disabled");
    }
    if !tun_configured {
        return (false, false, "disabled");
    }
    if core_running {
        return (true, false, "live_core_with_tun_config");
    }
    if tun_privilege_ready {
        return (true, false, "process_privilege");
    }
    (false, true, "privilege_required")
}

pub(super) async fn probe_live_tun_connections(ep: &ResolvedControllerEndpoint) -> bool {
    let Ok(job_guard) = JobGuard::new() else {
        return false;
    };
    let Ok(adapter) = MihomoAdapter::with_controller_endpoint(
        Arc::new(job_guard),
        &ep.host,
        ep.port,
        ep.secret.clone(),
    ) else {
        return false;
    };
    match tokio::time::timeout(Duration::from_millis(1500), adapter.list_connections()).await {
        Ok(Ok(snapshot)) => snapshot.connections.iter().any(|conn| {
            let ct = conn.conn_type.trim().to_ascii_lowercase();
            ct == "tun" || ct.contains("tun")
        }),
        _ => false,
    }
}

pub(super) fn analyze_dns_tls_across_logs(logs_dir: &Path, max_tail_bytes: usize) -> DnsTlsDiagnostics {
    let primary = logs_dir.join("catcloud.log");
    let archive1 = logs_dir.join("catcloud.log.1");
    let primary_len = std::fs::metadata(&primary).map(|m| m.len()).unwrap_or(0);

    if !archive1.is_file() || primary_len >= max_tail_bytes as u64 {
        return analyze_dns_tls_diagnostics_from_log_file(&primary, max_tail_bytes);
    }

    // Combine tail of `.1` and all of `catcloud.log` strictly within the `max_tail_bytes` budget.
    let remaining_budget = (max_tail_bytes as u64).saturating_sub(primary_len);
    let mut lines: Vec<String> = Vec::new();
    let mut sources: Vec<&str> = Vec::new();
    if remaining_budget > 0 {
        let prev_lines = read_bounded_file_lines(&archive1, remaining_budget);
        if !prev_lines.is_empty() {
            sources.push("catcloud.log.1");
            lines.extend(prev_lines);
        }
    }
    if primary.is_file() {
        let cur_lines = read_bounded_file_lines(&primary, max_tail_bytes as u64);
        if !cur_lines.is_empty() {
            sources.push("catcloud.log");
            lines.extend(cur_lines);
        }
    }
    if lines.is_empty() {
        return analyze_dns_tls_diagnostics_from_log_file(&primary, max_tail_bytes);
    }
    let kib = max_tail_bytes.div_ceil(1024).max(1);
    let window_desc = format!(
        "tail <= {kib} KiB across {} ({} lines)",
        sources.join(" + "),
        lines.len()
    );
    analyze_dns_tls_diagnostics(&lines, &window_desc)
}

#[derive(Debug, Default)]
pub(super) struct CatCloudManagedProcessFilter {
    pub(super) managed_pid: Option<u32>,
    pub(super) managed_start_time_unix: Option<u64>,
    pub(super) standalone_tunnel_pid: Option<u32>,
    pub(super) standalone_tunnel_start_time_unix: Option<u64>,
    pub(super) standalone_tunnel_binary_path: Option<PathBuf>,
    pub(super) standalone_tunnel_socks_port: Option<u16>,
    pub(super) mihomo_binary_path: Option<PathBuf>,
    pub(super) owned_dirs: Vec<PathBuf>,
    pub(super) live_controller_port: Option<u16>,
    pub(super) verified_listener_pids: HashSet<u32>,
}

fn normalize_path_for_compare(path: &Path) -> String {
    let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let raw = resolved.to_string_lossy();
    let trimmed = raw.strip_prefix(r"\\?\").unwrap_or(&raw);
    let unified = trimmed.replace('\\', "/").trim_end_matches('/').to_string();
    if cfg!(target_os = "windows") {
        unified.to_ascii_lowercase()
    } else {
        unified
    }
}

fn path_matches_or_within_dir(candidate: &Path, dir: &Path) -> bool {
    let cand = normalize_path_for_compare(candidate);
    let base = normalize_path_for_compare(dir);
    if cand.is_empty() || base.is_empty() {
        return false;
    }
    cand == base || cand.strip_prefix(&base).is_some_and(|rest| rest.starts_with('/'))
}

fn extract_port_from_addr(addr: &str) -> Option<u16> {
    let trimmed = addr.trim();
    let (_, port_part) = trimmed.rsplit_once(':')?;
    port_part.trim().parse::<u16>().ok().filter(|&p| p > 0)
}

pub(super) fn is_mihomo_like_process_name(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    let stem = lower.strip_suffix(".exe").unwrap_or(&lower);
    stem == "mihomo"
        || stem.starts_with("mihomo-")
        || stem.starts_with("mihomo_")
        || stem == "clash-meta"
        || stem == "catcloud"
}

pub(super) fn is_catcloud_managed_proxy_process_with_start_time(
    candidate: &ProcessCandidate,
    filter: &CatCloudManagedProcessFilter,
    candidate_start_time_unix: Option<u64>,
) -> bool {
    // 1. Exact runtime PID recorded in `runtime-controller.json` or `global-preaccel-runtime.json`,
    //    strictly guarded by process name + OS creation time tolerance (<= 2s) against Windows PID reuse.
    if verify_managed_pid_with_start_time(
        candidate.pid,
        &candidate.name,
        filter.managed_pid,
        filter.managed_start_time_unix,
        candidate_start_time_unix,
    ) {
        return true;
    }
    if verify_managed_pid_with_start_time(
        candidate.pid,
        &candidate.name,
        filter.standalone_tunnel_pid,
        filter.standalone_tunnel_start_time_unix,
        candidate_start_time_unix,
    ) {
        return true;
    }

    if !is_mihomo_like_process_name(&candidate.name) {
        return false;
    }

    if filter.verified_listener_pids.contains(&candidate.pid) {
        return true;
    }

    // 2. Executable path matches resolved CatCloud mihomo binary (or standalone tunnel binary)
    //    or resides inside CatCloud's bin/data/install directories.
    if let Some(ref exe) = candidate.exe_path {
        let norm_exe = normalize_path_for_compare(exe);
        if let Some(ref resolved_bin) = filter.mihomo_binary_path {
            if norm_exe == normalize_path_for_compare(resolved_bin) {
                return true;
            }
        }
        if let Some(ref tunnel_bin) = filter.standalone_tunnel_binary_path {
            if norm_exe == normalize_path_for_compare(tunnel_bin) {
                return true;
            }
        }
        if filter
            .owned_dirs
            .iter()
            .any(|dir| path_matches_or_within_dir(exe, dir))
        {
            return true;
        }
    }

    // 3. Config dir / config file / command line arguments reference CatCloud's runtime/data dir.
    for detected in [
        candidate.detected_config_dir.as_deref(),
        candidate.detected_config_file.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if filter
            .owned_dirs
            .iter()
            .any(|dir| path_matches_or_within_dir(detected, dir))
        {
            return true;
        }
    }

    if !candidate.cmdline.is_empty() && !filter.owned_dirs.is_empty() {
        let norm_dirs: Vec<String> = filter
            .owned_dirs
            .iter()
            .map(|d| normalize_path_for_compare(d))
            .filter(|s| !s.is_empty())
            .collect();
        for arg in &candidate.cmdline {
            let norm_arg = arg.trim().trim_matches('"').replace('\\', "/");
            let cmp_arg = if cfg!(target_os = "windows") {
                norm_arg.to_ascii_lowercase()
            } else {
                norm_arg
            };
            if norm_dirs.iter().any(|dir| {
                cmp_arg == *dir
                    || cmp_arg
                        .strip_prefix(dir.as_str())
                        .is_some_and(|rest| rest.starts_with('/'))
            }) {
                return true;
            }
        }
    }

    // 4. Live controller port matches CatCloud's active controller port.
    if let (Some(live_port), Some(ref detected_ctrl)) = (
        filter.live_controller_port,
        candidate.detected_controller_addr.as_ref(),
    ) {
        if extract_port_from_addr(detected_ctrl) == Some(live_port) {
            return true;
        }
    }

    false
}

pub(super) fn is_catcloud_managed_proxy_process(
    candidate: &ProcessCandidate,
    filter: &CatCloudManagedProcessFilter,
) -> bool {
    let start_ts = get_process_start_time_unix(candidate.pid);
    is_catcloud_managed_proxy_process_with_start_time(candidate, filter, start_ts)
}

pub(super) fn collect_verified_listener_pids(
    owners: &[PortListenerOwner],
    managed_pid: Option<u32>,
    managed_start_time_unix: Option<u64>,
    standalone_tunnel_pid: Option<u32>,
    standalone_tunnel_start_time_unix: Option<u64>,
) -> HashSet<u32> {
    let mut verified_listener_pids = HashSet::new();
    for owner in owners {
        if !is_valid_managed_pid(owner.pid) {
            continue;
        }
        if let Some(mpid) = managed_pid.filter(|&p| is_valid_managed_pid(p)) {
            if owner.pid == mpid
                && pid_start_time_matches_fail_closed(
                    managed_start_time_unix,
                    owner.process_start_time_unix,
                )
            {
                verified_listener_pids.insert(owner.pid);
            }
        }
        if let Some(spid) = standalone_tunnel_pid.filter(|&p| is_valid_managed_pid(p)) {
            if owner.pid == spid
                && pid_start_time_matches_fail_closed(
                    standalone_tunnel_start_time_unix,
                    owner.process_start_time_unix,
                )
            {
                verified_listener_pids.insert(owner.pid);
            }
        }
    }
    verified_listener_pids
}

fn build_catcloud_managed_process_filter(
    paths: &AppPaths,
    mihomo_binary: Option<&Path>,
    core_running: bool,
    effective_ctrl_port: u16,
) -> CatCloudManagedProcessFilter {
    let mut owned_dirs: Vec<PathBuf> = vec![
        paths.bin_dir.clone(),
        paths.runtime_dir.clone(),
        paths.root_data_dir.clone(),
    ];
    if let Ok(cur_exe) = std::env::current_exe() {
        if let Some(exe_dir) = cur_exe.parent() {
            owned_dirs.push(exe_dir.to_path_buf());
            // Portable layout: `<InstallRoot>/cli/catcloud.exe` sibling of `<InstallRoot>/bin/mihomo.exe`.
            if exe_dir
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.eq_ignore_ascii_case("cli"))
            {
                if let Some(install_root) = exe_dir.parent() {
                    owned_dirs.push(install_root.to_path_buf());
                }
            }
        }
    }

    let live_core_meta = read_live_runtime_controller_meta(paths);
    let managed_pid = live_core_meta
        .as_ref()
        .and_then(|m| m.pid)
        .filter(|&p| is_valid_managed_pid(p));
    let managed_start_time_unix = live_core_meta
        .as_ref()
        .and_then(|m| m.process_start_time_unix);

    let global_meta = read_global_preaccel_runtime_meta(&paths.root_data_dir)
        .filter(is_live_global_preaccel_pid);
    let standalone_tunnel_pid = global_meta
        .as_ref()
        .and_then(|m| m.pid)
        .filter(|&p| is_valid_managed_pid(p));
    let standalone_tunnel_start_time_unix = global_meta
        .as_ref()
        .and_then(|m| m.process_start_time_unix);
    let standalone_tunnel_binary_path = global_meta
        .as_ref()
        .and_then(|m| m.binary_path.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let standalone_tunnel_socks_port = global_meta.as_ref().and_then(|m| m.socks_port);

    // Cross-check OS listening port ownership table for CatCloud's verified live controller
    // and standalone 443 tunnel ports, enforcing fail-closed start-time tolerance against PID reuse.
    let mut watched_ports = Vec::new();
    if core_running && effective_ctrl_port > 0 {
        watched_ports.push(effective_ctrl_port);
    }
    if let Some(m) = &live_core_meta {
        if let Some(mp) = m.mixed_port {
            watched_ports.push(mp);
        }
        if let Some(dp) = m.dns_port {
            watched_ports.push(dp);
        }
    }
    if let Some(sp) = standalone_tunnel_socks_port {
        watched_ports.push(sp);
    }
    watched_ports.sort_unstable();
    watched_ports.dedup();

    let owners = list_listening_port_owners(&watched_ports);
    let verified_listener_pids = collect_verified_listener_pids(
        &owners,
        managed_pid,
        managed_start_time_unix,
        standalone_tunnel_pid,
        standalone_tunnel_start_time_unix,
    );

    CatCloudManagedProcessFilter {
        managed_pid,
        managed_start_time_unix,
        standalone_tunnel_pid,
        standalone_tunnel_start_time_unix,
        standalone_tunnel_binary_path,
        standalone_tunnel_socks_port,
        mihomo_binary_path: mihomo_binary.map(Path::to_path_buf),
        owned_dirs,
        live_controller_port: if core_running {
            Some(effective_ctrl_port)
        } else {
            None
        },
        verified_listener_pids,
    }
}

pub(super) fn inspect_windows_proxy_override_warnings(
    proxy_override_raw: &str,
) -> (Vec<String>, Option<String>) {
    let invalid_raw =
        catcloud_core::platform::common::find_invalid_windows_proxy_override_entries(
            proxy_override_raw,
        );
    if invalid_raw.is_empty() {
        return (Vec::new(), None);
    }
    let invalid_sanitized: Vec<String> = invalid_raw
        .iter()
        .map(|entry| sanitize_log_line(entry))
        .collect();
    let warning = format!(
        "Windows system proxy ProxyOverride contains invalid WinHTTP entries ({}) such as bare IPv6 (e.g. `::1`) or `/` CIDR, which can break Windows Schannel TLS certificate revocation checks (0x80092013 / CRYPT_E_REVOCATION_OFFLINE); re-enable or refresh CatCloud system proxy to auto-repair.",
        invalid_sanitized.join(", ")
    );
    (invalid_sanitized, Some(warning))
}

pub(super) async fn build_net_doctor_payload(paths: &AppPaths) -> Result<(Value, String)> {
    let cfg = config::load_or_init(paths)?;
    let db = open_storage(paths)?;
    let plat = default_platform();
    let caps = plat.capabilities();

    let subs = db.list_subscriptions()?;
    let nodes = db.list_nodes()?;
    let groups = db.list_multi_groups()?;
    let relays = db.list_preaccel_relays(false)?;

    let mut checks: Vec<Value> = Vec::with_capacity(8);
    let mut recommendations: Vec<String> = Vec::new();

    // Check 1: Portable / standard paths & storage counts
    let data_dir_writable = is_path_writable_probe(&paths.root_data_dir);
    let display_data_dir = redact_path_for_display(&paths.root_data_dir.to_string_lossy());
    let storage_status = if !data_dir_writable {
        recommendations.push(
            "Data directory is not writable; verify permissions or pass a writable --data-dir."
                .to_string(),
        );
        "fail"
    } else if nodes.is_empty() {
        recommendations.push(
            "No proxy nodes imported yet; import a subscription URL, .zip share bundle, or migrate an existing client."
                .to_string(),
        );
        "warn"
    } else {
        "pass"
    };
    checks.push(json!({
        "id": "storage_and_paths",
        "layer": 1,
        "name": "Paths & Local Storage",
        "status": storage_status,
        "detail": format!(
            "portable={}, writable={}, subs={}, nodes={}, groups={}, relays={}",
            paths.is_portable,
            data_dir_writable,
            subs.len(),
            nodes.len(),
            groups.len(),
            relays.len()
        ),
        "data": {
            "is_portable": paths.is_portable,
            "data_dir": display_data_dir,
            "writable": data_dir_writable,
            "instance_hash": paths.instance_hash,
            "counts": {
                "subscriptions": subs.len(),
                "nodes": nodes.len(),
                "multi_groups": groups.len(),
                "preaccel_relays": relays.len(),
            }
        }
    }));

    // Check 2: Configuration validity & offline static compile check
    let cfg_issues = config::validate_config_detailed(&cfg);
    let cfg_errors = cfg_issues
        .iter()
        .filter(|i| i.severity == ValidationSeverity::Error)
        .count();
    let offline_ports = AllocatedPorts {
        bind_host: if cfg.allow_lan {
            cfg.bind_address.clone()
        } else {
            "127.0.0.1".to_string()
        },
        mixed_port: cfg.mixed_port,
        controller_port: cfg.controller_port,
        dns_port: cfg.dns_listen_port,
        shifted: Vec::new(),
    };
    let empty_filter = HashMap::new();
    let compile_res = compile_mihomo_config_with_runtime_dir(
        &CompileInput {
            config: &cfg,
            nodes: &nodes,
            groups: &groups,
            relays: &relays,
            controller_secret: "doctor-placeholder-secret",
            allocated_ports: &offline_ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &empty_filter,
        },
        Some(&paths.runtime_dir),
    );
    let (compile_ok, compile_err, compile_warn_count, compile_stats) = match compile_res {
        Ok(c) => {
            let err_list: Vec<String> = c
                .validation
                .errors()
                .iter()
                .map(|i| sanitize_log_line(&format!("[{}] {}", i.code, i.message)))
                .collect();
            let ok = err_list.is_empty();
            let err_text = if ok {
                None
            } else {
                Some(err_list.join("; "))
            };
            (ok, err_text, c.validation.warnings().len(), Some(c.stats))
        }
        Err(e) => (false, Some(sanitize_log_line(&e.to_string())), 0, None),
    };
    let config_status = if cfg_errors > 0 || !compile_ok {
        recommendations.push(
            "Configuration or anti-loop preflight check reported errors; inspect `catcloud config validate --json`."
                .to_string(),
        );
        "fail"
    } else if !cfg_issues.is_empty() || compile_warn_count > 0 {
        "warn"
    } else {
        "pass"
    };
    checks.push(json!({
        "id": "config_validation",
        "layer": 3,
        "name": "Configuration & Static Compile Preflight",
        "status": config_status,
        "detail": format!(
            "config_errors={cfg_errors}, compile_ok={compile_ok}, compile_warnings={compile_warn_count}"
        ),
        "data": {
            "config_issues": redact_config_issues(&cfg_issues),
            "compile_ok": compile_ok,
            "compile_error": compile_err,
            "compile_warnings": compile_warn_count,
            "stats": compile_stats,
        }
    }));

    // Check 3: Core binary, live controller & configured/active ports
    let bin_res = resolve_mihomo_binary(&cfg, paths, &[], false)?;
    let active_ports = inspect_active_core_ports(paths, &cfg).await;
    let live_version = active_ports.core_version.clone();
    let controller_auth_err = active_ports.controller_auth_error.clone();
    let ctrl_ep = active_ports.endpoint.clone();
    let core_running = active_ports.core_running;
    let effective_mixed_port = active_ports.effective_mixed_port;
    let effective_ctrl_port = active_ports.effective_controller_port;
    let effective_dns_port = active_ports.effective_dns_port;
    let third_party_port_conflicts = active_ports.third_party_conflicts_for_effective_ports(&cfg);
    let owned_by_active_core = active_ports.all_active_ports_owned_by_core();

    let core_status = if !bin_res.found {
        recommendations.push(
            "Mihomo core binary was not found; place mihomo in the bin directory or install a bundled release."
                .to_string(),
        );
        "fail"
    } else if controller_auth_err.is_some() {
        recommendations.push(
            "Running controller rejected authentication; ensure config.json controller_secret matches the active core or restart core to refresh runtime metadata."
                .to_string(),
        );
        "warn"
    } else if !third_party_port_conflicts.is_empty() {
        recommendations.push(
            "One or more configured CatCloud ports are occupied by a non-CatCloud process; enable port_guard_auto_shift or free conflicting ports."
                .to_string(),
        );
        if cfg.port_guard_auto_shift {
            "warn"
        } else {
            "fail"
        }
    } else {
        "pass"
    };
    let port_label = |port: u16, free: bool, owned: bool| -> String {
        if owned {
            format!("{port}:owned_by_active_core")
        } else if free {
            format!("{port}:free")
        } else {
            format!("{port}:occupied_conflict")
        }
    };
    checks.push(json!({
        "id": "core_and_ports",
        "layer": 3,
        "name": "Core Binary & Listening Ports",
        "status": core_status,
        "detail": format!(
            "binary_found={}, core_running={}, owned_by_active_core={}, ports(mixed={}, ctrl={}, dns={})",
            bin_res.found,
            core_running,
            owned_by_active_core,
            port_label(effective_mixed_port, active_ports.mixed_free, active_ports.mixed_owned_by_active_core),
            port_label(effective_ctrl_port, active_ports.controller_free, active_ports.controller_owned_by_active_core),
            port_label(effective_dns_port, active_ports.dns_free, active_ports.dns_owned_by_active_core)
        ),
        "data": {
            "binary_found": bin_res.found,
            "binary_source": bin_res.source,
            "binary_path": bin_res.path.as_ref().map(|p| redact_path_for_display(&p.to_string_lossy())),
            "core_running": core_running,
            "core_version": live_version,
            "controller_auth_error": controller_auth_err,
            "owned_by_active_core": owned_by_active_core,
            "port_guard_auto_shift": cfg.port_guard_auto_shift,
            "third_party_port_conflicts": third_party_port_conflicts,
            "ports": active_ports.to_status_json(),
        }
    }));

    // Check 4: System Proxy & TUN readiness
    let os_proxy_res = plat.read_system_proxy();
    let (os_proxy_val, os_proxy_mismatch, os_proxy_dangling, invalid_override_entries, proxy_override_warning) =
        match os_proxy_res {
            Ok(spec) => {
                let mismatch = spec.enabled && spec.port != effective_mixed_port;
                let dangling = spec.enabled && !core_running && spec.port == effective_mixed_port;
                let (invalid_entries, override_warn) = if cfg!(target_os = "windows") {
                    inspect_windows_proxy_override_warnings(&spec.bypass.join(";"))
                } else {
                    (Vec::new(), None)
                };
                (
                    json!({
                        "readable": true,
                        "enabled": spec.enabled,
                        "host": redact_ip_or_host(&spec.host),
                        "port": spec.port,
                        "pac_url": spec.pac_url.as_deref().map(sanitize_log_line),
                        "bypass_count": spec.bypass.len(),
                        "invalid_proxy_override_entries": &invalid_entries,
                    }),
                    mismatch,
                    dangling,
                    invalid_entries,
                    override_warn,
                )
            }
            Err(err) => (
                json!({
                    "readable": false,
                    "error": sanitize_log_line(&err.to_string()),
                    "invalid_proxy_override_entries": [],
                }),
                false,
                false,
                Vec::new(),
                None,
            ),
        };
    let tun_privilege_ready = is_cli_tun_privilege_ready(&caps, bin_res.path.as_deref());
    let tun_configured = cfg.tun.enabled;
    let has_live_tun_connections = if core_running {
        probe_live_tun_connections(&ctrl_ep).await
    } else {
        false
    };
    let live_tun_enable = active_ports.live_config.as_ref().map(|lc| lc.tun_enable);
    let (tun_effective_enabled, tun_needs_admin, tun_runtime_source) = evaluate_doctor_tun_state(
        tun_configured,
        tun_privilege_ready,
        core_running,
        has_live_tun_connections,
        live_tun_enable,
    );
    let has_invalid_proxy_override = !invalid_override_entries.is_empty();
    let proxy_tun_status = if os_proxy_dangling
        || os_proxy_mismatch
        || tun_needs_admin
        || has_invalid_proxy_override
    {
        if os_proxy_dangling {
            recommendations.push(
                "OS system proxy points to CatCloud mixed_port while core is stopped; start CatCloud core or disable system proxy."
                    .to_string(),
            );
        }
        if os_proxy_mismatch {
            recommendations.push(
                "OS system proxy is currently pointing to another port; check for another proxy client or residual system proxy setting."
                    .to_string(),
            );
        }
        if tun_needs_admin {
            recommendations.push(
                "TUN mode is enabled in config but current process lacks TUN privilege; run with administrator/root privileges (or grant cap_net_admin on Linux) for TUN."
                    .to_string(),
            );
        }
        if let Some(warn_msg) = proxy_override_warning {
            recommendations.push(warn_msg);
        }
        "warn"
    } else {
        "pass"
    };
    checks.push(json!({
        "id": "system_proxy_and_tun",
        "layer": 3,
        "name": "System Proxy & Virtual NIC (TUN)",
        "status": proxy_tun_status,
        "detail": format!(
            "cfg_sys_proxy={}, tun_configured={}, tun_enabled={}, tun_needs_elevation={}, tun_source={}, tun_stack={}, elevated={}, os_proxy_mismatch={}, os_proxy_dangling={}, invalid_proxy_override={}",
            cfg.system_proxy.enabled,
            tun_configured,
            tun_effective_enabled,
            tun_needs_admin,
            tun_runtime_source,
            cfg.tun.stack_mode.as_str(),
            caps.is_elevated,
            os_proxy_mismatch,
            os_proxy_dangling,
            invalid_override_entries.len()
        ),
        "data": {
            "config_system_proxy_enabled": cfg.system_proxy.enabled,
            "proxy_guard_enabled": cfg.system_proxy.proxy_guard.enabled,
            "config_tun_enabled": tun_configured,
            "tun_configured": tun_configured,
            "tun_enabled": tun_effective_enabled,
            "tun_needs_elevation": tun_needs_admin,
            "tun_privilege_ready": tun_privilege_ready,
            "live_tun_connections_detected": has_live_tun_connections,
            "tun_runtime_source": tun_runtime_source,
            "tun_stack": cfg.tun.stack_mode,
            "is_elevated": caps.is_elevated,
            "invalid_proxy_override_entries": invalid_override_entries,
            "os_system_proxy": os_proxy_val,
        }
    }));

    // Check 5: Domestic pre-acceleration relays & WinDivert readiness
    let now = Utc::now();
    let enabled_relays: Vec<&PreAccelRelay> = relays.iter().filter(|r| r.enabled).collect();
    let expired_relays = enabled_relays
        .iter()
        .filter(|r| evaluate_expiry(r.expires_at.as_deref(), now).tag() == "expired")
        .count();
    let expiring_soon_relays = enabled_relays
        .iter()
        .filter(|r| evaluate_expiry(r.expires_at.as_deref(), now).tag() == "expiring_soon")
        .count();
    let wd_files = locate_windivert_files(paths, cfg.preaccel.windivert_dir.as_deref());
    let security_products = detect_host_security_products();
    let preaccel_plan = build_preaccel_compile_plan(&cfg.preaccel, &relays, &nodes);
    let transport_snap = collect_cli_preaccel_transport_snapshot(
        paths,
        &cfg,
        &nodes,
        &groups,
        &relays,
        &active_ports,
        tun_effective_enabled,
        compile_stats.as_ref().map(|s| s.effective_tun_mtu),
    )
    .await;
    let preaccel_status = match &preaccel_plan {
        Err(_) => {
            recommendations.push(
                "Domestic pre-acceleration plan validation failed; verify domestic 204 probe URL and relay SNI rules."
                    .to_string(),
            );
            "fail"
        }
        Ok(_) if (cfg.preaccel.enabled || cfg.preaccel.global_bypass_enabled)
            && (enabled_relays.is_empty() || expired_relays > 0) =>
        {
            recommendations.push(
                "Domestic pre-acceleration is enabled but has no active non-expired relays; update relays or disable preaccel."
                    .to_string(),
            );
            "warn"
        }
        Ok(_) if cfg!(target_os = "windows")
            && cfg.preaccel.global_bypass_enabled
            && wd_files.is_none() =>
        {
            recommendations.push(
                "Global domestic pre-acceleration is enabled without WinDivert binaries; it will fall back to local SOCKS5 mode."
                    .to_string(),
            );
            "warn"
        }
        Ok(_) if expiring_soon_relays > 0 => "warn",
        Ok(_) => "pass",
    };
    checks.push(json!({
        "id": "preaccel_and_windivert",
        "layer": 5,
        "name": "Domestic Pre-Acceleration & WinDivert",
        "status": preaccel_status,
        "detail": format!(
            "enabled={}, global={}, enabled_relays={}, expired={}, windivert_available={}",
            cfg.preaccel.enabled,
            cfg.preaccel.global_bypass_enabled,
            enabled_relays.len(),
            expired_relays,
            wd_files.is_some()
        ),
        "data": {
            "enabled": cfg.preaccel.enabled,
            "global_bypass_enabled": cfg.preaccel.global_bypass_enabled,
            "skip_443_native": cfg.preaccel.skip_443_native,
            "enabled_relay_count": enabled_relays.len(),
            "expired_relay_count": expired_relays,
            "expiring_soon_relay_count": expiring_soon_relays,
            "windivert_available": wd_files.is_some(),
            "windivert_dll": wd_files.as_ref().map(|(dll, _)| redact_path_for_display(&dll.to_string_lossy())),
            "detected_security_products": security_products,
            "plan_error": preaccel_plan.as_ref().err().map(|e| sanitize_log_line(&e.to_string())),
            "plan_warnings": preaccel_plan.as_ref().map(|p| p.warnings.iter().map(|w| sanitize_log_line(w)).collect::<Vec<_>>()).unwrap_or_default(),
            "transport_diagnostics": &transport_snap.diagnostics,
            "active_relay_selected": &transport_snap.active_relay_selected,
            "active_exit_selected": &transport_snap.active_exit_selected,
            "runtime_config_sha256": &transport_snap.runtime_config_sha256,
        }
    }));

    // Check 6: Conflicting proxy processes, common occupied proxy ports, and proxy env vars
    let mut env_proxies: HashMap<String, String> = HashMap::new();
    for key in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    ] {
        if let Ok(val) = std::env::var(key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                env_proxies.insert(key.to_string(), sanitize_log_line(trimmed));
            }
        }
    }
    let managed_proc_filter = build_catcloud_managed_process_filter(
        paths,
        bin_res.path.as_deref(),
        core_running,
        effective_ctrl_port,
    );
    let other_proxy_procs: Vec<Value> = list_process_candidates(true)
        .into_iter()
        .filter(|p| !is_catcloud_managed_proxy_process(p, &managed_proc_filter))
        .map(|p| {
            let r = redact_process_candidate(&p);
            json!({
                "pid": r.pid,
                "name": r.name,
                "detected_controller_addr": r.detected_controller_addr,
            })
        })
        .collect();
    const COMMON_PROXY_PORTS: &[u16] = &[7890, 7897, 10808, 10809, 2080, 1080];
    let mut occupied_other_ports: Vec<u16> = Vec::new();
    for &p in COMMON_PROXY_PORTS {
        if core_running
            && (p == cfg.mixed_port
                || p == cfg.controller_port
                || p == effective_mixed_port
                || p == effective_ctrl_port)
        {
            continue;
        }
        if managed_proc_filter.standalone_tunnel_socks_port == Some(p) {
            continue;
        }
        if !is_port_available_tcp_udp("127.0.0.1", p) {
            occupied_other_ports.push(p);
        }
    }
    let conflict_status =
        if !other_proxy_procs.is_empty() || !occupied_other_ports.is_empty() || !env_proxies.is_empty()
        {
            if !other_proxy_procs.is_empty() {
                recommendations.push(
                    "Other proxy-like processes are running on this machine; verify they do not fight over ports, system proxy, or TUN routes."
                        .to_string(),
                );
            }
            if !env_proxies.is_empty() {
                recommendations.push(
                    "Terminal proxy environment variables (HTTP_PROXY/HTTPS_PROXY/ALL_PROXY) are set; confirm they point to the intended port."
                        .to_string(),
                );
            }
            "warn"
        } else {
            "pass"
        };
    checks.push(json!({
        "id": "proxy_conflicts_and_env",
        "layer": 2,
        "name": "Conflicting Proxy Clients, Ports & Env Vars",
        "status": conflict_status,
        "detail": format!(
            "other_proxy_processes={}, occupied_common_ports={:?}, proxy_env_vars={}",
            other_proxy_procs.len(),
            occupied_other_ports,
            env_proxies.len()
        ),
        "data": {
            "other_proxy_processes": other_proxy_procs,
            "occupied_common_proxy_ports": occupied_other_ports,
            "proxy_env_vars": env_proxies,
        }
    }));

    // Check 7: GeoData readiness (aligned strictly with Country.mmdb / country.mmdb)
    let mut geodata = collect_geodata_status(&paths.runtime_dir);
    let has_country_mmdb = geodata["country_mmdb"]["exists"].as_bool().unwrap_or(false);
    let has_geosite = geodata["geosite_dat"]["exists"].as_bool().unwrap_or(false);
    let mut missing_geodata_files: Vec<&str> = Vec::new();
    if !has_country_mmdb {
        missing_geodata_files.push("Country.mmdb");
    }
    if !has_geosite {
        missing_geodata_files.push("geosite.dat");
    }
    let geodata_impact_scope = if missing_geodata_files.is_empty() {
        json!({
            "missing_files": [],
            "explicit_domain_rules_unaffected": true,
            "affected_traffic_zh": "GeoData 完整，依赖 GeoIP/GeoSite 的国内直连与显式域名规则均正常工作。",
            "affected_traffic": "GeoData databases are complete; both GeoIP/GeoSite domestic direct rules and explicit domain rules are active.",
        })
    } else {
        json!({
            "missing_files": &missing_geodata_files,
            "explicit_domain_rules_unaffected": true,
            "affected_traffic_zh": "缺失 GeoData 仅影响依赖 GeoIP/GeoSite 的未显式列出国内域名与国内 IP 自动直连判定（可能误走代理）；已写明的 DOMAIN/DOMAIN-SUFFIX/IP-CIDR 规则（如内置 AI 域名、QQ/微信与自定义规则）不受影响。",
            "affected_traffic": "Missing GeoData only affects unlisted domestic domains/IPs relying on GeoIP/GeoSite auto-direct rules; explicit DOMAIN/DOMAIN-SUFFIX/IP-CIDR rules (AI domains, domestic IM, custom rules) are unaffected.",
        })
    };
    if let Some(obj) = geodata.as_object_mut() {
        obj.insert("impact_scope".to_string(), geodata_impact_scope.clone());
    }
    let geo_status = if cfg.rules_override.domestic_direct_enabled && !has_country_mmdb {
        recommendations.push(
            "Country.mmdb is missing while domestic direct routing is enabled (only affects unlisted domestic domains/IPs relying on GeoIP/GeoSite; explicit domain rules remain unaffected); refresh GeoData in Settings."
                .to_string(),
        );
        "warn"
    } else {
        "pass"
    };
    checks.push(json!({
        "id": "geodata_status",
        "layer": 4,
        "name": "GeoData Databases",
        "status": geo_status,
        "detail": format!(
            "country_mmdb={has_country_mmdb}, geosite_dat={has_geosite} ({})",
            if missing_geodata_files.is_empty() {
                "complete"
            } else {
                "missing files only affect GeoIP/GeoSite rules; explicit domain rules unaffected"
            }
        ),
        "data": geodata,
    }));

    // Check 8: Encrypted DNS TLS certificate verification health (256 KiB window across catcloud.log & .1)
    let dns_tls_diag = analyze_dns_tls_across_logs(&paths.logs_dir, 256 * 1024);
    let dns_tls_status = match dns_tls_diag.status.as_str() {
        DNS_TLS_STATUS_CERT_FAILED => {
            recommendations.push(format!(
                "{}: {} (upstreams={:?}; TLS verification preserved)",
                dns_tls_diag.category,
                dns_tls_diag.next_retry_hint,
                dns_tls_diag.affected_upstreams
            ));
            "fail"
        }
        DNS_TLS_STATUS_DEGRADED_RECOVERED => {
            recommendations.push(format!(
                "{}: {} (upstreams={:?})",
                dns_tls_diag.category,
                dns_tls_diag.next_retry_hint,
                dns_tls_diag.affected_upstreams
            ));
            "warn"
        }
        _ => "pass",
    };
    checks.push(json!({
        "id": "dns_tls_health",
        "layer": 4,
        "name": "Encrypted DNS TLS Certificate Health",
        "status": dns_tls_status,
        "detail": format!(
            "status={}, failures={}, recovered={}, dot_853_timeouts={}, tls_verified={}",
            dns_tls_diag.status,
            dns_tls_diag.failure_count,
            dns_tls_diag.recovered,
            dns_tls_diag.network_timeout_only_count,
            dns_tls_diag.tls_verification_preserved
        ),
        "data": dns_tls_diag,
    }));

    let pass_count = checks.iter().filter(|c| c["status"] == "pass").count();
    let warn_count = checks.iter().filter(|c| c["status"] == "warn").count();
    let fail_count = checks.iter().filter(|c| c["status"] == "fail").count();
    let healthy = fail_count == 0;

    let mut out = json!({
        "ok": true,
        "sanitized": true,
        "healthy": healthy,
        "version": env!("CARGO_PKG_VERSION"),
        "os": caps.os,
        "arch": caps.arch,
        "summary": {
            "total": checks.len(),
            "pass": pass_count,
            "warn": warn_count,
            "fail": fail_count,
        },
        "preaccel_transport_diagnostics": &transport_snap.diagnostics,
        "active_relay_selected": &transport_snap.active_relay_selected,
        "active_exit_selected": &transport_snap.active_exit_selected,
        "runtime_config_sha256": &transport_snap.runtime_config_sha256,
        "checks": &checks,
        "recommendations": &recommendations,
    });
    sanitize_json_value(&mut out);
    let mut lines = vec![format!(
        "CatCloud Net Doctor: healthy={healthy} (pass={pass_count}, warn={warn_count}, fail={fail_count})"
    )];
    for check in &checks {
        lines.push(format!(
            "- [{}] L{} {}: {}",
            check["status"].as_str().unwrap_or("info").to_uppercase(),
            check["layer"],
            check["name"].as_str().unwrap_or(""),
            check["detail"].as_str().unwrap_or("")
        ));
    }
    Ok((out, lines.join("\n")))
}

fn normalize_match_target(raw: &str) -> Result<(String, Option<u16>)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        anyhow::bail!("domain or IP target cannot be empty");
    }
    let without_scheme = trimmed
        .split_once("://")
        .map_or(trimmed, |(_, after)| after);
    let authority = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(without_scheme)
        .trim();
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, hp)| hp)
        .trim();

    if let Some(rest) = host_port.strip_prefix('[') {
        if let Some((inner, tail)) = rest.split_once(']') {
            let port_override = tail.strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
            return Ok((inner.trim_end_matches('.').to_ascii_lowercase(), port_override));
        }
    }

    if host_port.parse::<IpAddr>().is_ok() {
        return Ok((host_port.to_ascii_lowercase(), None));
    }

    if let Some((h, p)) = host_port.rsplit_once(':') {
        if !h.contains(':') {
            if let Ok(port_num) = p.parse::<u16>() {
                let norm = h.trim_end_matches('.').to_ascii_lowercase();
                if !norm.is_empty() {
                    return Ok((norm, Some(port_num)));
                }
            }
        }
    }

    let norm = host_port.trim_end_matches('.').to_ascii_lowercase();
    if norm.is_empty() {
        anyhow::bail!("invalid domain or IP target `{raw}`");
    }
    Ok((norm, None))
}

pub(super) async fn build_net_match_payload(
    paths: &AppPaths,
    raw_domain: &str,
    raw_network: &str,
    default_port: u16,
    process_name: Option<&str>,
    process_path: Option<&str>,
) -> Result<(Value, String)> {
    let (host, port_override) = normalize_match_target(raw_domain)?;
    let port = port_override.unwrap_or(default_port);
    let network = match raw_network.trim().to_ascii_lowercase().as_str() {
        "tcp" => "tcp",
        "udp" => "udp",
        other => anyhow::bail!("unsupported network `{other}` (use tcp|udp)"),
    };
    let parsed_ip = host.parse::<IpAddr>().ok();
    let norm_process_name = process_name
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);
    let norm_process_path = process_path
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);

    let cfg = config::load_or_init(paths)?;
    let db = open_storage(paths)?;
    let nodes = db.list_nodes()?;
    let groups = db.list_multi_groups()?;
    let relays = db.list_preaccel_relays(false)?;
    let (live_version, _, _) = probe_live_controller(paths, &cfg).await;

    let offline_ports = AllocatedPorts {
        bind_host: if cfg.allow_lan {
            cfg.bind_address.clone()
        } else {
            "127.0.0.1".to_string()
        },
        mixed_port: cfg.mixed_port,
        controller_port: cfg.controller_port,
        dns_port: cfg.dns_listen_port,
        shifted: Vec::new(),
    };
    let empty_filter = HashMap::new();
    let compiled = compile_mihomo_config_with_runtime_dir(
        &CompileInput {
            config: &cfg,
            nodes: &nodes,
            groups: &groups,
            relays: &relays,
            controller_secret: "match-placeholder-secret",
            allocated_ports: &offline_ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &empty_filter,
        },
        Some(&paths.runtime_dir),
    )?;

    let bypass_fake_ip = matches_compiled_fake_ip_filter(&compiled.value, &host);

    let mut skipped_geo_rules: Vec<String> = Vec::new();
    let mut matched_rule_idx: Option<usize> = None;
    let matched_rule: String;
    let matched_type: String;
    let matched_policy: String;

    match cfg.proxy_mode {
        ProxyMode::Direct => {
            matched_rule = "MODE,DIRECT".to_string();
            matched_type = "MODE".to_string();
            matched_policy = "DIRECT".to_string();
        }
        ProxyMode::Global => {
            matched_rule = "MODE,GLOBAL".to_string();
            matched_type = "MODE".to_string();
            matched_policy = "GLOBAL".to_string();
        }
        ProxyMode::Rule => {
            let query = RuleMatchQuery {
                host: host.clone(),
                network: network.to_string(),
                port,
                process_name: norm_process_name.clone(),
                process_path: norm_process_path.clone(),
            };
            let outcome = evaluate_compiled_rules(&compiled.value, &query);
            matched_rule_idx = outcome.matched_rule_index;
            matched_rule = outcome
                .matched_rule
                .as_deref()
                .map(sanitize_log_line)
                .unwrap_or_default();
            matched_type = outcome.matched_rule_type.unwrap_or_default();
            matched_policy = outcome.policy.unwrap_or_default();
            skipped_geo_rules = outcome
                .skipped_geo_rules
                .iter()
                .map(|r| sanitize_log_line(r))
                .collect();
        }
    }

    let primary_group_id: Option<&str> = if cfg.route_mode == RouteTargetMode::Single {
        None
    } else {
        cfg.active_group_id
            .as_deref()
            .map(str::trim)
            .filter(|aid| !aid.is_empty() && groups.iter().any(|g| g.id.trim() == *aid))
            .or_else(|| groups.first().map(|g| g.id.as_str()))
    };

    let resolved_group = compiled
        .group_mappings
        .iter()
        .find(|g| g.group_name == matched_policy)
        .map(|g| {
            let grp_meta = groups.iter().find(|item| item.id == g.group_id);
            let independent_routing = grp_meta.is_some_and(|item| item.independent_routing);
            let is_primary = primary_group_id == Some(g.group_id.as_str());
            let role = if is_primary {
                "primary_default"
            } else if independent_routing {
                "independent_routing"
            } else {
                "standby"
            };
            json!({
                "group_id": g.group_id,
                "group_name": g.group_name,
                "mihomo_type": g.mihomo_type,
                "active_proxy_name": g.active_proxy_name,
                "member_count": g.member_proxy_names.len(),
                "independent_routing": independent_routing,
                "role": role,
            })
        });

    let geodata_status = collect_geodata_status(&paths.runtime_dir);
    let has_country_mmdb = geodata_status["country_mmdb"]["exists"]
        .as_bool()
        .unwrap_or(false);
    let has_geosite_dat = geodata_status["geosite_dat"]["exists"]
        .as_bool()
        .unwrap_or(false);
    let mut missing_geodata_files: Vec<&str> = Vec::new();
    if !has_country_mmdb {
        missing_geodata_files.push("Country.mmdb");
    }
    if !has_geosite_dat {
        missing_geodata_files.push("geosite.dat");
    }
    let geodata_impact_scope = if missing_geodata_files.is_empty() {
        json!({
            "missing_files": [],
            "explicit_domain_rules_unaffected": true,
            "affected_traffic_zh": "GeoData 完整，GeoIP/GeoSite 与显式域名规则均有效。",
            "affected_traffic": "GeoData files are present; both GeoIP/GeoSite and explicit domain rules apply.",
        })
    } else {
        json!({
            "missing_files": &missing_geodata_files,
            "explicit_domain_rules_unaffected": true,
            "affected_traffic_zh": "缺失 GeoData 仅影响依赖 GeoIP/GeoSite 的未显式列出国内域名/IP；已写明的域名与 IP-CIDR 规则不受影响。",
            "affected_traffic": "Missing GeoData only affects unlisted domestic domains/IPs relying on GeoIP/GeoSite; explicit domain/IP-CIDR rules are unaffected.",
        })
    };

    let geo_note = if !skipped_geo_rules.is_empty() {
        if !missing_geodata_files.is_empty() {
            Some("Offline rule simulation cannot inspect binary GeoSite/GeoIP databases, and GeoData files are currently missing on disk (缺失 GeoData 仅影响依赖 GeoIP/GeoSite 的未列国内域名/IP，已写明域名规则不受影响).")
        } else {
            Some("Offline rule simulation cannot inspect binary GeoSite/GeoIP databases; live Mihomo core may match an earlier GEOSITE/GEOIP rule before the fallback result shown here.")
        }
    } else if !missing_geodata_files.is_empty() {
        Some("GeoData files are missing on disk (缺失 GeoData 仅影响依赖 GeoIP/GeoSite 的未列国内域名/IP，当前已写明域名规则不受影响).")
    } else {
        None
    };

    let display_process_name = norm_process_name.as_deref().map(sanitize_log_line);
    let display_process_path = norm_process_path
        .as_deref()
        .map(|p| sanitize_log_line(&redact_path_for_display(p)));

    let mut out = json!({
        "ok": true,
        "sanitized": true,
        "query": {
            "host": if parsed_ip.is_some() { redact_ip_or_host(&host) } else { host.clone() },
            "network": network,
            "port": port,
            "process_name": display_process_name,
            "process_path": display_process_path,
        },
        "proxy_mode": cfg.proxy_mode,
        "core_running": live_version.is_some(),
        "evaluation_source": "compiled_rules_offline",
        "matched": !matched_policy.is_empty(),
        "matched_rule_index": matched_rule_idx,
        "matched_rule": &matched_rule,
        "matched_rule_type": &matched_type,
        "policy": &matched_policy,
        "resolved_group": resolved_group,
        "bypass_fake_ip": bypass_fake_ip,
        "skipped_geo_rules": skipped_geo_rules,
        "geo_note": geo_note,
        "geodata_missing_files": missing_geodata_files,
        "geodata_impact_scope": geodata_impact_scope,
    });
    sanitize_json_value(&mut out);
    let human = format!(
        "Match {} ({}/{}) -> policy `{}` via rule `{}` (bypass_fake_ip={}).",
        out["query"]["host"].as_str().unwrap_or(""),
        network,
        port,
        matched_policy,
        matched_rule,
        bypass_fake_ip
    );
    Ok((out, human))
}
