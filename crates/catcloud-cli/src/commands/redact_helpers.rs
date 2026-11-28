//! Shared CLI output formatting, storage initialization, parsing helpers, and read-only redaction.

use anyhow::{Context, Result};
use catcloud_core::config::{self, ConfigValidationIssue};
use catcloud_core::core_adapter::config_compiler::{StaticCheckIssue, StaticValidationReport};
use catcloud_core::core_adapter::{ActiveConnection, DownloadGuidance, ReloadOutcome};
use catcloud_core::models::{
    FallbackPolicy, MultiGroup, MultiGroupMode, PreAccelConfig, PreAccelDispatchStrategy,
    PreAccelLbStrategy, ProxyNode, SubscriptionKind, SubscriptionRecord, SwitchMode,
};
use catcloud_core::probe::FunnelRunReport;
use catcloud_core::sanitize::{
    redact_ip_or_host, redact_node_for_readonly, redact_path_for_display, sanitize_json_value,
    sanitize_log_line,
};
use catcloud_core::storage::{Storage, SubscriptionUpdateMode};
use catcloud_core::subscription::migrator::MigrationPreview;
use catcloud_core::subscription::process_attach::{
    AttachRecommendation, ProcessCandidate, ProcessInspectionResult,
};
use catcloud_core::{AppPaths, CatResult};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

pub(super) fn finalize_output_value(value: &Value) -> Value {
    let mut out = value.clone();
    if out.get("sanitized").and_then(Value::as_bool) == Some(true) {
        sanitize_json_value(&mut out);
    }
    out
}

pub(super) fn emit_output(as_json: bool, value: &Value, human: &str) -> Result<()> {
    let should_sanitize = value.get("sanitized").and_then(Value::as_bool) == Some(true);
    if as_json {
        let final_value = finalize_output_value(value);
        println!("{}", serde_json::to_string_pretty(&final_value)?);
    } else if should_sanitize {
        println!("{}", sanitize_multiline_text(human));
    } else {
        println!("{human}");
    }
    Ok(())
}

pub(super) fn open_storage(paths: &AppPaths) -> Result<Storage> {
    let mut db = Storage::open(&paths.db_path)?;
    let _ = db.seed_builtin_probes();
    Ok(db)
}

pub(super) fn parse_group_mode(raw: &str) -> Result<MultiGroupMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "sticky_best" => Ok(MultiGroupMode::StickyBest),
        "conditional_pool" => Ok(MultiGroupMode::ConditionalPool),
        "load_balance_consistent_hash" => Ok(MultiGroupMode::LoadBalanceConsistentHash),
        "load_balance_round_robin" => Ok(MultiGroupMode::LoadBalanceRoundRobin),
        other => anyhow::bail!("unsupported group mode `{other}`"),
    }
}

pub(super) fn parse_fallback_policy(raw: &str) -> Result<FallbackPolicy> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "degrade_best_warn" => Ok(FallbackPolicy::DegradeBestWarn),
        "cross_pool_escalate" => Ok(FallbackPolicy::CrossPoolEscalate),
        "strict_circuit_break" => Ok(FallbackPolicy::StrictCircuitBreak),
        other => anyhow::bail!("unsupported fallback policy `{other}`"),
    }
}

pub(super) fn parse_switch_mode(raw: &str) -> Result<SwitchMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "force_close_old" => Ok(SwitchMode::ForceCloseOld),
        "graceful_new_only" => Ok(SwitchMode::GracefulNewOnly),
        other => anyhow::bail!("unsupported switch mode `{other}`"),
    }
}

pub(super) fn parse_preaccel_dispatch_strategy(raw: &str) -> Result<PreAccelDispatchStrategy> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "auto" => Ok(PreAccelDispatchStrategy::Auto),
        "load_balance" | "load-balance" | "lb" => Ok(PreAccelDispatchStrategy::LoadBalance),
        "fallback" | "failover" => Ok(PreAccelDispatchStrategy::Fallback),
        other => anyhow::bail!(
            "unsupported dispatch strategy `{other}` (use auto|load_balance|fallback)"
        ),
    }
}

pub(super) fn parse_preaccel_lb_strategy(raw: &str) -> Result<PreAccelLbStrategy> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "round_robin" | "round-robin" | "rr" => Ok(PreAccelLbStrategy::RoundRobin),
        "consistent_hashing" | "consistent-hashing" | "ch" => {
            Ok(PreAccelLbStrategy::ConsistentHashing)
        }
        other => anyhow::bail!(
            "unsupported lb strategy `{other}` (use round_robin|consistent_hashing)"
        ),
    }
}

pub(super) fn looks_like_clash_rule_prefix(token: &str) -> bool {
    matches!(
        token.trim().to_ascii_uppercase().as_str(),
        "DOMAIN"
            | "DOMAIN-SUFFIX"
            | "DOMAIN-KEYWORD"
            | "DOMAIN-WILDCARD"
            | "DOMAIN-REGEX"
            | "GEOSITE"
            | "GEOIP"
            | "IP-CIDR"
            | "IP-CIDR6"
            | "IP-SUFFIX"
            | "IP-ASN"
            | "SRC-IP-CIDR"
            | "SRC-PORT"
            | "DST-PORT"
            | "PROCESS-NAME"
            | "PROCESS-NAME-REGEX"
            | "PROCESS-PATH"
            | "PROCESS-PATH-REGEX"
            | "NETWORK"
            | "UID"
            | "IN-TYPE"
            | "IN-USER"
            | "IN-NAME"
            | "SUB-RULE"
            | "RULE-SET"
            | "AND"
            | "OR"
            | "NOT"
            | "MATCH"
    )
}

pub(super) fn parse_group_match_rules_arg(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    // Split multi-rule batches on `;` or newlines first; never blindly split rules containing
    // parentheses, regex quantifiers/escapes, or Clash rule prefixes on bare `,`.
    let raw_chunks: Vec<&str> = if trimmed.contains(';') || trimmed.contains('\n') {
        trimmed.split([';', '\n']).collect()
    } else {
        vec![trimmed]
    };

    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for chunk in raw_chunks {
        let seg = chunk.trim();
        if seg.is_empty() {
            continue;
        }
        let contains_structured_syntax = seg.contains('(')
            || seg.contains(')')
            || seg.contains('{')
            || seg.contains('}')
            || seg.contains('\\');
        let starts_with_rule_prefix = seg
            .split_once(',')
            .is_some_and(|(first, _)| looks_like_clash_rule_prefix(first));

        if !contains_structured_syntax && !starts_with_rule_prefix && seg.contains(',') {
            for part in seg.split(',') {
                let cleaned = part.trim();
                if !cleaned.is_empty() && seen.insert(cleaned.to_string()) {
                    out.push(cleaned.to_string());
                }
            }
        } else if seen.insert(seg.to_string()) {
            out.push(seg.to_string());
        }
    }
    out
}

pub(crate) fn redact_subscription_for_readonly(sub: &SubscriptionRecord) -> SubscriptionRecord {
    let mut out = sub.clone();
    out.url_or_cmd = match sub.kind {
        SubscriptionKind::Url => redact_subscription_url(&sub.url_or_cmd),
        SubscriptionKind::File | SubscriptionKind::Migrated | SubscriptionKind::ProcessAdapter => {
            sanitize_log_line(&redact_path_for_display(&sub.url_or_cmd))
        }
    };
    out.last_error = sub.last_error.as_deref().map(sanitize_log_line);
    out.etag = sub.etag.as_deref().map(sanitize_log_line);
    out
}

fn redact_subscription_url(raw: &str) -> String {
    let base = sanitize_log_line(raw.trim());
    let Some((scheme, rest)) = base.split_once("://") else {
        return base;
    };

    let (without_frag, has_frag) = match rest.split_once('#') {
        Some((before, frag)) => (before, !frag.is_empty()),
        None => (rest, false),
    };
    let (before_query, query_opt) = match without_frag.split_once('?') {
        Some((before, q)) => (before, Some(q)),
        None => (without_frag, None),
    };
    let (authority, path_part) = match before_query.find('/') {
        Some(idx) => (&before_query[..idx], &before_query[idx..]),
        None => (before_query, ""),
    };

    let masked_authority = if let Some((_, host_port)) = authority.rsplit_once('@') {
        format!("<REDACTED>@{}", redact_ip_or_host(host_port))
    } else {
        redact_ip_or_host(authority)
    };

    let masked_path = if path_part.is_empty() {
        String::new()
    } else {
        path_part
            .split('/')
            .map(|seg| {
                let looks_like_secret_token = seg.len() >= 16
                    && seg
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                    && seg.bytes().any(|b| b.is_ascii_digit())
                    && seg.bytes().any(|b| b.is_ascii_alphabetic());
                if looks_like_secret_token {
                    "<REDACTED>"
                } else {
                    seg
                }
            })
            .collect::<Vec<_>>()
            .join("/")
    };

    let mut out = format!("{scheme}://{masked_authority}{masked_path}");
    if let Some(q) = query_opt {
        let masked_query = q
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| match pair.split_once('=') {
                Some((k, _)) => format!("{k}=<REDACTED>"),
                None => "<REDACTED>".to_string(),
            })
            .collect::<Vec<_>>()
            .join("&");
        out.push('?');
        out.push_str(&masked_query);
    }
    if has_frag {
        out.push_str("#<REDACTED>");
    }
    out
}

pub(super) fn redact_migration_preview(preview: &MigrationPreview) -> MigrationPreview {
    MigrationPreview {
        source_kind: preview.source_kind,
        source_path: preview
            .source_path
            .as_ref()
            .map(|p| PathBuf::from(redact_path_for_display(&p.to_string_lossy()))),
        display_name: preview.display_name.clone(),
        nodes: preview.nodes.iter().map(redact_node_for_readonly).collect(),
        prepend_rules: preview
            .prepend_rules
            .iter()
            .map(|r| sanitize_log_line(r))
            .collect(),
        append_rules: preview
            .append_rules
            .iter()
            .map(|r| sanitize_log_line(r))
            .collect(),
        warnings: preview
            .warnings
            .iter()
            .map(|w| sanitize_log_line(w))
            .collect(),
    }
}

pub(super) fn redact_process_candidate(candidate: &ProcessCandidate) -> ProcessCandidate {
    let mut masked_cmd = Vec::with_capacity(candidate.cmdline.len());
    let mut redact_next = false;
    for arg in &candidate.cmdline {
        if redact_next {
            masked_cmd.push("<REDACTED>".to_string());
            redact_next = false;
            continue;
        }
        let lower = arg.trim().to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "-secret"
                | "--secret"
                | "-password"
                | "--password"
                | "-token"
                | "--token"
                | "-auth"
                | "--auth"
                | "-key"
                | "--key"
        ) {
            masked_cmd.push(arg.clone());
            redact_next = true;
            continue;
        }
        masked_cmd.push(sanitize_log_line(&redact_path_for_display(arg)));
    }

    ProcessCandidate {
        pid: candidate.pid,
        name: candidate.name.clone(),
        exe_path: candidate
            .exe_path
            .as_ref()
            .map(|p| PathBuf::from(redact_path_for_display(&p.to_string_lossy()))),
        cmdline: masked_cmd,
        detected_config_dir: candidate
            .detected_config_dir
            .as_ref()
            .map(|p| PathBuf::from(redact_path_for_display(&p.to_string_lossy()))),
        detected_config_file: candidate
            .detected_config_file
            .as_ref()
            .map(|p| PathBuf::from(redact_path_for_display(&p.to_string_lossy()))),
        detected_controller_addr: candidate
            .detected_controller_addr
            .as_deref()
            .map(redact_ip_or_host),
        likely_proxy_client: candidate.likely_proxy_client,
    }
}

pub(super) fn redact_process_inspection(inspection: &ProcessInspectionResult) -> ProcessInspectionResult {
    let recommendation = match &inspection.recommendation {
        AttachRecommendation::ReadOnlyLocalFile {
            path,
            node_count,
            reason,
        } => AttachRecommendation::ReadOnlyLocalFile {
            path: PathBuf::from(redact_path_for_display(&path.to_string_lossy())),
            node_count: *node_count,
            reason: sanitize_log_line(reason),
        },
        AttachRecommendation::PublicControllerApi {
            endpoint_url,
            proxy_count,
            requires_secret,
            reason,
        } => AttachRecommendation::PublicControllerApi {
            endpoint_url: sanitize_log_line(endpoint_url),
            proxy_count: *proxy_count,
            requires_secret: *requires_secret,
            reason: sanitize_log_line(reason),
        },
        AttachRecommendation::ExternalAdapterTemplate {
            schema,
            suggested_command,
            template_script,
            reason,
        } => AttachRecommendation::ExternalAdapterTemplate {
            schema: schema.clone(),
            suggested_command: suggested_command.clone(),
            template_script: template_script.clone(),
            reason: sanitize_log_line(reason),
        },
    };

    ProcessInspectionResult {
        pid: inspection.pid,
        process_name: inspection.process_name.clone(),
        readable_yaml_file: inspection
            .readable_yaml_file
            .as_ref()
            .map(|p| PathBuf::from(redact_path_for_display(&p.to_string_lossy()))),
        yaml_node_count: inspection.yaml_node_count,
        controller_url: inspection
            .controller_url
            .as_deref()
            .map(sanitize_log_line),
        controller_reachable: inspection.controller_reachable,
        controller_requires_secret: inspection.controller_requires_secret,
        controller_proxy_count: inspection.controller_proxy_count,
        recommendation,
        notes: inspection
            .notes
            .iter()
            .map(|n| sanitize_log_line(n))
            .collect(),
    }
}

fn redact_connection_host_for_readonly(host: &str) -> String {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    // Preserve normal business target domains (e.g. `api.openai.com`, `github.com`),
    // while masking IPv4/IPv6 literals (with or without `:port` / `[IPv6]:port`).
    if trimmed.starts_with('[') && trimmed.contains(']') {
        return redact_ip_or_host(trimmed);
    }
    if trimmed.parse::<IpAddr>().is_ok() {
        return redact_ip_or_host(trimmed);
    }
    if trimmed.bytes().filter(|&b| b == b':').count() >= 3 {
        if let Some((addr, port)) = trimmed.rsplit_once(':') {
            if port.parse::<u16>().is_ok() && addr.parse::<IpAddr>().is_ok() {
                return redact_ip_or_host(trimmed);
            }
        }
    }
    if let Some((addr, port)) = trimmed.rsplit_once(':') {
        if !addr.contains(':') && port.parse::<u16>().is_ok() && addr.parse::<IpAddr>().is_ok() {
            return redact_ip_or_host(trimmed);
        }
    }
    sanitize_log_line(trimmed)
}

pub(super) fn redact_connection_for_readonly(conn: &ActiveConnection) -> ActiveConnection {
    ActiveConnection {
        id: conn.id.clone(),
        upload: conn.upload,
        download: conn.download,
        start: conn.start.clone(),
        chains: conn.chains.iter().map(|c| sanitize_log_line(c)).collect(),
        rule: conn.rule.clone(),
        rule_payload: sanitize_log_line(&conn.rule_payload),
        network: conn.network.clone(),
        conn_type: conn.conn_type.clone(),
        source_ip: redact_ip_or_host(&conn.source_ip),
        source_port: conn.source_port.clone(),
        destination_ip: redact_ip_or_host(&conn.destination_ip),
        destination_port: conn.destination_port.clone(),
        host: redact_connection_host_for_readonly(&conn.host),
        process: conn.process.clone(),
        process_path: redact_path_for_display(&conn.process_path),
    }
}

pub(super) fn parse_csv_ids(raw: Option<&str>) -> Vec<String> {
    let Some(text) = raw else {
        return Vec::new();
    };
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for part in text.split(',') {
        let trimmed = part.trim();
        if !trimmed.is_empty() && seen.insert(trimmed.to_string()) {
            out.push(trimmed.to_string());
        }
    }
    out
}

pub(super) fn parse_subscription_update_mode(raw: &str) -> Result<SubscriptionUpdateMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "replace" | "replace_latest" => Ok(SubscriptionUpdateMode::ReplaceLatest),
        "merge" | "merge_dedup" => Ok(SubscriptionUpdateMode::MergeDedup),
        other => anyhow::bail!(
            "unsupported share import mode `{other}` (use replace|merge|replace_latest|merge_dedup)"
        ),
    }
}

/// Synchronize `AppConfig.active_single_node_id` after subscription merges or share imports:
/// applies `id_remap`, verifies the resolved node still exists in SQLite, falls back to the first
/// enabled node (or clears to `None` when none remain), and atomically writes `config.json` only
/// if `active_single_node_id` changed.
pub(super) fn sync_active_single_node_after_mutation(
    paths: &AppPaths,
    db: &Storage,
    id_remap: &HashMap<String, String>,
) -> CatResult<bool> {
    let mut cfg = config::load_or_default(paths)?;
    let Some(cur) = cfg
        .active_single_node_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
    else {
        return Ok(false);
    };

    let mapped = id_remap.get(&cur).cloned().unwrap_or(cur);
    let nodes = db.list_nodes()?;
    let next_id = if nodes.iter().any(|n| n.id == mapped) {
        Some(mapped)
    } else {
        nodes.iter().find(|n| n.enabled).map(|n| n.id.clone())
    };

    if cfg.active_single_node_id == next_id {
        return Ok(false);
    }
    cfg.active_single_node_id = next_id;
    config::save(paths, &cfg)?;
    Ok(true)
}

pub(super) fn sanitize_multiline_text(raw: &str) -> String {
    raw.split('\n')
        .map(sanitize_log_line)
        .collect::<Vec<_>>()
        .join("\n")
}

pub(super) fn format_path_with_reveal(path: &Path, reveal_secrets: bool) -> String {
    let raw = path.to_string_lossy();
    if reveal_secrets {
        raw.into_owned()
    } else {
        redact_path_for_display(&raw)
    }
}

pub(super) fn format_paths_with_reveal(paths: &[PathBuf], reveal_secrets: bool) -> Vec<String> {
    paths
        .iter()
        .map(|p| format_path_with_reveal(p, reveal_secrets))
        .collect()
}

pub(super) fn redact_download_guidance(guidance: &DownloadGuidance) -> DownloadGuidance {
    DownloadGuidance {
        core_kind: guidance.core_kind.clone(),
        platform_target: guidance.platform_target.clone(),
        recommended_asset_pattern: guidance.recommended_asset_pattern.clone(),
        official_releases_url: guidance.official_releases_url.clone(),
        target_install_path: PathBuf::from(redact_path_for_display(
            &guidance.target_install_path.to_string_lossy(),
        )),
        verify_sha256_required: guidance.verify_sha256_required,
        instructions: sanitize_multiline_text(&guidance.instructions),
    }
}

pub(super) fn redact_preaccel_config_for_output(cfg: &PreAccelConfig) -> PreAccelConfig {
    let mut out = cfg.clone();
    out.windivert_dir = out.windivert_dir.as_deref().map(redact_path_for_display);
    out
}

pub(super) fn redact_reload_outcome(outcome: &ReloadOutcome) -> ReloadOutcome {
    let mut out = outcome.clone();
    out.warnings = outcome
        .warnings
        .iter()
        .map(|w| sanitize_multiline_text(w))
        .collect();
    out.error = outcome.error.as_deref().map(sanitize_multiline_text);
    out
}

pub(super) fn redact_config_issues(issues: &[ConfigValidationIssue]) -> Vec<ConfigValidationIssue> {
    issues
        .iter()
        .map(|issue| ConfigValidationIssue {
            field: issue.field.clone(),
            severity: issue.severity.clone(),
            message: sanitize_multiline_text(&issue.message),
        })
        .collect()
}

pub(super) fn redact_static_validation(report: &StaticValidationReport) -> StaticValidationReport {
    StaticValidationReport {
        ok: report.ok,
        issues: report
            .issues
            .iter()
            .map(|issue| StaticCheckIssue {
                code: issue.code.clone(),
                severity: issue.severity,
                message: sanitize_multiline_text(&issue.message),
            })
            .collect(),
    }
}

pub(super) fn redact_funnel_report(report: &FunnelRunReport) -> FunnelRunReport {
    let mut out = report.clone();
    for rec in &mut out.records {
        rec.detail = rec.detail.as_deref().map(sanitize_multiline_text);
    }
    out
}

pub(super) fn is_info_placeholder_node(node: &ProxyNode) -> bool {
    const HINTS: &[&str] = &[
        "剩余流量",
        "剩餘流量",
        "过期时间",
        "過期時間",
        "到期",
        "套餐",
        "官网",
        "官網",
        "重置",
        "距离下次",
        "更新订阅",
    ];
    HINTS.iter().any(|h| node.name.contains(h))
}

pub(super) fn resolve_valid_group_active_node<'a>(
    group: &MultiGroup,
    nodes: &'a [ProxyNode],
) -> Option<&'a ProxyNode> {
    if !group.member_node_ids.is_empty() {
        if let Some(active_id) = group
            .active_node_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if group.member_node_ids.iter().any(|m| m == active_id) {
                if let Some(node) = nodes.iter().find(|n| n.id == active_id && n.enabled) {
                    return Some(node);
                }
            }
        }
        return group
            .member_node_ids
            .iter()
            .find_map(|mid| nodes.iter().find(|n| &n.id == mid && n.enabled));
    }

    if let Some(active_id) = group
        .active_node_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if let Some(node) = nodes.iter().find(|n| n.id == active_id && n.enabled) {
            return Some(node);
        }
    }
    nodes.iter().find(|n| n.enabled)
}

pub(super) fn read_bounded_file_lines(path: &Path, max_bytes: u64) -> Vec<String> {
    use std::io::{Read, Seek, SeekFrom};

    let Ok(mut file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let Ok(meta) = file.metadata() else {
        return Vec::new();
    };
    let len = meta.len();
    if len == 0 {
        return Vec::new();
    }
    let start = len.saturating_sub(max_bytes);
    if start > 0 && file.seek(SeekFrom::Start(start)).is_err() {
        return Vec::new();
    }
    let mut buf = Vec::with_capacity((len - start).min(max_bytes) as usize);
    if file.read_to_end(&mut buf).is_err() {
        return Vec::new();
    }
    let raw = String::from_utf8_lossy(&buf);
    let content = if start > 0 {
        match raw.find('\n') {
            Some(pos) => &raw[pos + 1..],
            None => raw.as_ref(),
        }
    } else {
        raw.as_ref()
    };
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

pub(super) fn unquote_yaml_scalar(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('\'') && trimmed.ends_with('\'') {
        return trimmed[1..trimmed.len() - 1].replace("''", "'");
    }
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        return serde_json::from_str::<String>(trimmed)
            .unwrap_or_else(|_| trimmed[1..trimmed.len() - 1].to_string());
    }
    trimmed.to_string()
}

pub(super) fn read_file_with_limit(
    path: &std::path::Path,
    max_bytes: usize,
    label: &str,
) -> Result<Vec<u8>> {
    use std::io::Read as _;

    let file = std::fs::File::open(path).with_context(|| {
        format!(
            "failed to open {label} `{}`",
            redact_path_for_display(&path.to_string_lossy())
        )
    })?;
    let meta = file.metadata().with_context(|| {
        format!(
            "failed to inspect {label} `{}`",
            redact_path_for_display(&path.to_string_lossy())
        )
    })?;
    if !meta.is_file() {
        anyhow::bail!(
            "{label} path is not a regular file: {}",
            redact_path_for_display(&path.to_string_lossy())
        );
    }
    if meta.len() > max_bytes as u64 {
        anyhow::bail!(
            "{label} `{}` ({} bytes) exceeds maximum allowed {} bytes",
            redact_path_for_display(&path.to_string_lossy()),
            meta.len(),
            max_bytes
        );
    }
    let mut out = Vec::with_capacity((meta.len() as usize).min(64 * 1024));
    let mut limited = file.take(max_bytes as u64 + 1);
    limited.read_to_end(&mut out).with_context(|| {
        format!(
            "failed to read {label} `{}`",
            redact_path_for_display(&path.to_string_lossy())
        )
    })?;
    if out.len() > max_bytes {
        anyhow::bail!(
            "{label} `{}` exceeded maximum allowed {} bytes while reading",
            redact_path_for_display(&path.to_string_lossy()),
            max_bytes
        );
    }
    Ok(out)
}
