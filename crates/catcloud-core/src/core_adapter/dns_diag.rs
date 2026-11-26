use chrono::{DateTime, Duration, NaiveDateTime};
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Canonical diagnostic category emitted for DNS upstream TLS certificate verification failures.
pub const DNS_TLS_CATEGORY: &str = "域名解析失败 → DNS 证书校验失败";
/// Status when no DNS TLS certificate verification failure is observed in the scanned window.
pub const DNS_TLS_STATUS_HEALTHY: &str = "healthy";
/// Status when DNS TLS certificate verification failed on one or more upstreams, then recovered.
pub const DNS_TLS_STATUS_DEGRADED_RECOVERED: &str = "degraded_recovered";
/// Status when DNS TLS certificate verification failed and has not yet recovered.
pub const DNS_TLS_STATUS_CERT_FAILED: &str = "cert_verification_failed";

/// Suggested retry delay window (in minutes) when all active encrypted DNS upstreams fail TLS verification.
const DEFAULT_RETRY_DELAY_MINUTES: i64 = 5;

/// Known encrypted DNS IPv4 `/24` prefixes mapped to human-readable provider labels.
/// Matching prefixes intentionally covers both raw IPs (`223.5.5.5`) and already-redacted
/// log entries (`223.5.5.*`) so diagnostics stay accurate even on sanitized disk logs.
const KNOWN_DNS_PREFIX_LABELS: &[(&str, &str)] = &[
    ("223.5.5.", "AliDNS DoH/DoT (223.5.5.*)"),
    ("223.6.6.", "AliDNS DoH/DoT (223.6.6.*)"),
    ("1.12.12.", "DNSPod DoH/DoT (1.12.12.*)"),
    ("120.53.53.", "DNSPod DoH/DoT (120.53.53.*)"),
    ("119.29.29.", "DNSPod DNS (119.29.29.*)"),
    ("119.28.28.", "DNSPod DNS (119.28.28.*)"),
    ("1.1.1.", "Cloudflare DoH/DoT (1.1.1.*)"),
    ("1.0.0.", "Cloudflare DoH/DoT (1.0.0.*)"),
    ("8.8.8.", "Google DoH/DoT (8.8.8.*)"),
    ("8.8.4.", "Google DoH/DoT (8.8.4.*)"),
    ("9.9.9.", "Quad9 DoH/DoT (9.9.9.*)"),
    ("114.114.114.", "114DNS (114.114.114.*)"),
    ("180.76.76.", "Baidu DNS (180.76.76.*)"),
    ("180.184.1.", "ByteDance DNS (180.184.1.*)"),
];

/// Known encrypted DNS domain endpoints mapped to human-readable provider labels.
const KNOWN_DNS_DOMAIN_LABELS: &[(&str, &str)] = &[
    ("dns.alidns.com", "AliDNS DoH/DoT (dns.alidns.com)"),
    ("alidns.com", "AliDNS DoH/DoT (alidns.com)"),
    ("doh.pub", "DNSPod DoH/DoT (doh.pub)"),
    ("dot.pub", "DNSPod DoH/DoT (dot.pub)"),
    ("dns.pub", "DNSPod DoH/DoT (dns.pub)"),
    ("cloudflare-dns.com", "Cloudflare DoH/DoT (cloudflare-dns.com)"),
    ("dns.google", "Google DoH/DoT (dns.google)"),
    ("dns.quad9.net", "Quad9 DoH/DoT (dns.quad9.net)"),
];

/// Structured DNS TLS certificate verification diagnostics shared by Desktop UI, CLI `net doctor`,
/// and `config diag`. Strict TLS certificate verification is always preserved (`true`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsTlsDiagnostics {
    pub status: String,
    pub category: String,
    pub first_seen_at: Option<String>,
    pub last_seen_at: Option<String>,
    pub failure_count: usize,
    pub affected_paths: Vec<String>,
    pub affected_upstreams: Vec<String>,
    pub tls_verification_preserved: bool,
    pub recovered: bool,
    pub recovery_time: Option<String>,
    pub next_retry_at: Option<String>,
    pub next_retry_hint: String,
    pub scanned_window_desc: String,
    pub network_timeout_only_count: usize,
}

impl Default for DnsTlsDiagnostics {
    fn default() -> Self {
        Self {
            status: DNS_TLS_STATUS_HEALTHY.to_string(),
            category: DNS_TLS_CATEGORY.to_string(),
            first_seen_at: None,
            last_seen_at: None,
            failure_count: 0,
            affected_paths: Vec::new(),
            affected_upstreams: Vec::new(),
            tls_verification_preserved: true,
            recovered: false,
            recovery_time: None,
            next_retry_at: None,
            next_retry_hint: "当前扫描窗口内加密 DNS 证书校验正常。".to_string(),
            scanned_window_desc: String::new(),
            network_timeout_only_count: 0,
        }
    }
}

/// Analyze log lines (raw or already sanitized with `A.B.C.*`) to detect encrypted DNS upstream
/// TLS certificate verification failures, distinguish pure port-853 network timeouts, map
/// upstreams to readable provider labels, and determine recovery state.
pub fn analyze_dns_tls_diagnostics(
    log_lines: &[String],
    scanned_window_desc: &str,
) -> DnsTlsDiagnostics {
    let mut first_seen_at: Option<String> = None;
    let mut last_seen_at: Option<String> = None;
    let mut failure_count: usize = 0;
    let mut last_failure_idx: Option<usize> = None;
    let mut affected_paths: Vec<String> = Vec::new();
    let mut affected_upstreams: Vec<String> = Vec::new();
    let mut network_timeout_only_count: usize = 0;

    for (idx, raw_line) in log_lines.iter().enumerate() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        let matched_upstreams = extract_dns_upstream_labels(trimmed, &lower);

        if is_cert_verification_error(&lower)
            && is_dns_context(trimmed, &lower, &matched_upstreams)
        {
            failure_count += 1;
            last_failure_idx = Some(idx);

            if let Some(ts) = extract_log_timestamp(trimmed) {
                if first_seen_at.is_none() {
                    first_seen_at = Some(ts.clone());
                }
                last_seen_at = Some(ts);
            }

            if matched_upstreams.is_empty() {
                if let Some(fallback_label) = extract_generic_masked_ipv4_upstream(trimmed) {
                    push_unique(&mut affected_upstreams, fallback_label);
                } else {
                    push_unique(
                        &mut affected_upstreams,
                        "Unknown Encrypted DNS Upstream".to_string(),
                    );
                }
            } else {
                for label in matched_upstreams {
                    push_unique(&mut affected_upstreams, label);
                }
            }

            let line_paths = infer_affected_paths(&lower);
            for path_tag in line_paths {
                push_unique(&mut affected_paths, path_tag.to_string());
            }
            continue;
        }

        // Explicitly exclude pure port-853 DoT network timeouts / connection drops from cert failures.
        if !is_cert_verification_error(&lower)
            && is_853_network_timeout_only(trimmed, &lower, &matched_upstreams)
        {
            network_timeout_only_count += 1;
        }
    }

    if failure_count == 0 {
        let hint = if network_timeout_only_count > 0 {
            format!(
                "未发现 DNS 证书校验失败；仅检测到 {network_timeout_only_count} 次 853/DoT 网络连接超时，属网络阻断或抖动，无需放宽 TLS 证书校验。"
            )
        } else {
            "当前扫描窗口内加密 DNS 证书校验正常。".to_string()
        };
        return DnsTlsDiagnostics {
            status: DNS_TLS_STATUS_HEALTHY.to_string(),
            category: DNS_TLS_CATEGORY.to_string(),
            first_seen_at: None,
            last_seen_at: None,
            failure_count: 0,
            affected_paths: Vec::new(),
            affected_upstreams: Vec::new(),
            tls_verification_preserved: true,
            recovered: false,
            recovery_time: None,
            next_retry_at: None,
            next_retry_hint: hint,
            scanned_window_desc: scanned_window_desc.to_string(),
            network_timeout_only_count,
        };
    }

    // Check subsequent log lines after the last certificate failure for recovery evidence.
    let mut recovered = false;
    let mut recovery_time: Option<String> = None;
    if let Some(last_idx) = last_failure_idx {
        for raw_line in log_lines.iter().skip(last_idx + 1) {
            let trimmed = raw_line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let lower = trimmed.to_ascii_lowercase();
            if is_recovery_evidence_line(&lower) {
                recovered = true;
                recovery_time = extract_log_timestamp(trimmed);
                break;
            }
        }
    }

    if recovered {
        return DnsTlsDiagnostics {
            status: DNS_TLS_STATUS_DEGRADED_RECOVERED.to_string(),
            category: DNS_TLS_CATEGORY.to_string(),
            first_seen_at,
            last_seen_at,
            failure_count,
            affected_paths,
            affected_upstreams,
            tls_verification_preserved: true,
            recovered: true,
            recovery_time,
            next_retry_at: None,
            next_retry_hint: "已自动切换至健康加密 DNS 备用上游恢复解析（全程保留严格 TLS 证书校验），无需降低安全级别。".to_string(),
            scanned_window_desc: scanned_window_desc.to_string(),
            network_timeout_only_count,
        };
    }

    let next_retry_at = compute_next_retry_at(last_seen_at.as_deref());
    let next_retry_hint = match next_retry_at.as_deref() {
        Some(ts) => format!(
            "已保留严格 TLS 证书校验（绝不跳过验证）；受影响上游证书拒绝尚未恢复，建议于 {ts}（约 {DEFAULT_RETRY_DELAY_MINUTES} 分钟后）重试，或确认多协议异构加密 DNS（443 DoH + 853 DoT）已启用。"
        ),
        None => format!(
            "已保留严格 TLS 证书校验（绝不跳过验证）；受影响上游证书拒绝尚未恢复，建议等待约 {DEFAULT_RETRY_DELAY_MINUTES} 分钟后重试，或切换至多协议异构加密 DNS（443 DoH + 853 DoT）。"
        ),
    };

    DnsTlsDiagnostics {
        status: DNS_TLS_STATUS_CERT_FAILED.to_string(),
        category: DNS_TLS_CATEGORY.to_string(),
        first_seen_at,
        last_seen_at,
        failure_count,
        affected_paths,
        affected_upstreams,
        tls_verification_preserved: true,
        recovered: false,
        recovery_time: None,
        next_retry_at,
        next_retry_hint,
        scanned_window_desc: scanned_window_desc.to_string(),
        network_timeout_only_count,
    }
}

/// Convenience helper that reads at most `max_tail_bytes` from the tail of `log_path`
/// (e.g. 64 KiB for UI polling or 256 KiB for CLI diagnostics) and runs
/// [`analyze_dns_tls_diagnostics`].
pub fn analyze_dns_tls_diagnostics_from_log_file(
    log_path: &Path,
    max_tail_bytes: usize,
) -> DnsTlsDiagnostics {
    let kib = max_tail_bytes.div_ceil(1024).max(1);
    let file_label = log_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("catcloud.log");

    let Ok(mut file) = std::fs::File::open(log_path) else {
        return analyze_dns_tls_diagnostics(
            &[],
            &format!("{file_label} not found (window <= {kib} KiB)"),
        );
    };
    let Ok(meta) = file.metadata() else {
        return analyze_dns_tls_diagnostics(
            &[],
            &format!("{file_label} unreadable (window <= {kib} KiB)"),
        );
    };
    let file_len = meta.len();
    if file_len == 0 || max_tail_bytes == 0 {
        return analyze_dns_tls_diagnostics(&[], &format!("{file_label} empty"));
    }

    let start = file_len.saturating_sub(max_tail_bytes as u64);
    if start > 0 && file.seek(SeekFrom::Start(start)).is_err() {
        return analyze_dns_tls_diagnostics(&[], &format!("{file_label} seek failed"));
    }

    let mut buf = Vec::with_capacity((file_len - start).min(max_tail_bytes as u64) as usize);
    if file.read_to_end(&mut buf).is_err() {
        return analyze_dns_tls_diagnostics(&[], &format!("{file_label} read failed"));
    }

    let text = String::from_utf8_lossy(&buf);
    let mut lines: Vec<String> = text.lines().map(ToString::to_string).collect();
    if start > 0 && !lines.is_empty() {
        // Drop potentially truncated leading partial line when reading mid-file.
        lines.remove(0);
    }

    let first_ts = lines.iter().find_map(|l| extract_log_timestamp(l));
    let last_ts = lines.iter().rev().find_map(|l| extract_log_timestamp(l));
    let window_desc = match (first_ts, last_ts) {
        (Some(a), Some(b)) if a != b => {
            format!("tail <= {kib} KiB ({} lines, {a} .. {b})", lines.len())
        }
        (Some(a), _) => format!("tail <= {kib} KiB ({} lines, at {a})", lines.len()),
        _ => format!("tail <= {kib} KiB ({} lines)", lines.len()),
    };

    analyze_dns_tls_diagnostics(&lines, &window_desc)
}

fn push_unique(list: &mut Vec<String>, item: String) {
    if !list.iter().any(|existing| existing == &item) {
        list.push(item);
    }
}

fn is_cert_verification_error(lower: &str) -> bool {
    lower.contains("doesn't contain any ip sans")
        || lower.contains("does not contain any ip sans")
        || lower.contains("x509:")
        || lower.contains("tls: failed to verify certificate")
        || lower.contains("cannot validate certificate")
        || (lower.contains("certificate")
            && (lower.contains("ip sans")
                || lower.contains("unknown authority")
                || lower.contains("not valid for")
                || lower.contains("has expired")))
}

fn contains_ascii_word(text: &str, word: &str) -> bool {
    let bytes = text.as_bytes();
    let mut start = 0usize;
    while let Some(rel) = text[start..].find(word) {
        let pos = start + rel;
        let prev_ok = pos == 0 || !(bytes[pos - 1].is_ascii_alphanumeric() || bytes[pos - 1] == b'_');
        let after = pos + word.len();
        let next_ok =
            after == bytes.len() || !(bytes[after].is_ascii_alphanumeric() || bytes[after] == b'_');
        if prev_ok && next_ok {
            return true;
        }
        start = pos + 1;
    }
    false
}

fn is_dns_context(line: &str, lower: &str, matched_upstreams: &[String]) -> bool {
    if !matched_upstreams.is_empty() {
        return true;
    }
    lower.contains("dns-query")
        || lower.contains("[dns]")
        || lower.contains("dns resolve")
        || lower.contains("nameserver")
        || lower.contains("doh")
        || contains_ascii_word(lower, "dot")
        || has_port_853_token(line)
        || (lower.contains("resolve ") && lower.contains("failed"))
}

fn has_port_853_token(text: &str) -> bool {
    let bytes = text.as_bytes();
    let needle = b":853";
    let mut start = 0usize;
    while let Some(rel) = text[start..].find(":853") {
        let pos = start + rel;
        let after = pos + needle.len();
        let next_is_digit = after < bytes.len() && bytes[after].is_ascii_digit();
        if !next_is_digit {
            return true;
        }
        start = pos + 1;
    }
    false
}

fn is_853_network_timeout_only(line: &str, lower: &str, matched_upstreams: &[String]) -> bool {
    let is_853 = has_port_853_token(line)
        || (lower.contains("tls://")
            && (contains_ascii_word(lower, "dot") || !matched_upstreams.is_empty()));
    if !is_853 {
        return false;
    }
    lower.contains("i/o timeout")
        || lower.contains("timeout")
        || lower.contains("timed out")
        || lower.contains("deadline exceeded")
        || lower.contains("connection refused")
        || lower.contains("connection reset")
        || lower.contains("network is unreachable")
        || lower.contains("no route to host")
        || lower.contains("eof")
}

fn extract_dns_upstream_labels(line: &str, lower: &str) -> Vec<String> {
    let mut out = Vec::new();
    for &(prefix, label) in KNOWN_DNS_PREFIX_LABELS {
        if contains_ipv4_prefix_token(line, prefix) {
            push_unique(&mut out, label.to_string());
        }
    }
    for &(domain, label) in KNOWN_DNS_DOMAIN_LABELS {
        if contains_domain_token(lower, domain) {
            push_unique(&mut out, label.to_string());
        }
    }
    out
}

fn contains_ipv4_prefix_token(text: &str, prefix: &str) -> bool {
    let bytes = text.as_bytes();
    let mut search_from = 0usize;
    while let Some(rel) = text[search_from..].find(prefix) {
        let idx = search_from + rel;
        let prev_ok =
            idx == 0 || !(bytes[idx - 1].is_ascii_alphanumeric() || bytes[idx - 1] == b'.');
        let after = idx + prefix.len();
        if prev_ok && after < bytes.len() {
            if bytes[after] == b'*' {
                let end = after + 1;
                let next_is_oid =
                    end + 1 < bytes.len() && bytes[end] == b'.' && bytes[end + 1].is_ascii_digit();
                let next_ok =
                    end == bytes.len() || (!bytes[end].is_ascii_alphanumeric() && !next_is_oid);
                if next_ok {
                    return true;
                }
            } else if bytes[after].is_ascii_digit() {
                let mut end = after;
                while end < bytes.len() && bytes[end].is_ascii_digit() {
                    end += 1;
                }
                let octet_ok = text[after..end].parse::<u8>().is_ok();
                let next_is_oid =
                    end + 1 < bytes.len() && bytes[end] == b'.' && bytes[end + 1].is_ascii_digit();
                let next_ok =
                    end == bytes.len() || (!bytes[end].is_ascii_alphanumeric() && !next_is_oid);
                if octet_ok && next_ok {
                    return true;
                }
            }
        }
        search_from = idx + 1;
    }
    false
}

fn contains_domain_token(lower: &str, domain: &str) -> bool {
    let bytes = lower.as_bytes();
    let mut start = 0usize;
    while let Some(rel) = lower[start..].find(domain) {
        let pos = start + rel;
        let prev_ok = pos == 0
            || !(bytes[pos - 1].is_ascii_alphanumeric() || bytes[pos - 1] == b'-');
        let after = pos + domain.len();
        let next_ok = after == bytes.len()
            || !(bytes[after].is_ascii_alphanumeric() || bytes[after] == b'-');
        if prev_ok && next_ok {
            return true;
        }
        start = pos + 1;
    }
    false
}

fn extract_generic_masked_ipv4_upstream(line: &str) -> Option<String> {
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let prev_ok = i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'.');
        if prev_ok && bytes[i].is_ascii_digit() {
            let mut end = i;
            let mut dots = 0usize;
            while end < bytes.len()
                && (bytes[end].is_ascii_digit() || bytes[end] == b'.' || bytes[end] == b'*')
            {
                if bytes[end] == b'.' {
                    dots += 1;
                }
                end += 1;
            }
            if dots == 3 {
                let token = &line[i..end];
                let parts: Vec<&str> = token.split('.').collect();
                if parts.len() == 4
                    && parts[0].parse::<u8>().is_ok()
                    && parts[1].parse::<u8>().is_ok()
                    && parts[2].parse::<u8>().is_ok()
                    && (parts[3] == "*" || parts[3].parse::<u8>().is_ok())
                {
                    return Some(format!(
                        "Encrypted DNS ({}.{}.{}.*)",
                        parts[0], parts[1], parts[2]
                    ));
                }
            }
            i = end;
            continue;
        }
        i += 1;
    }
    None
}

fn infer_affected_paths(lower: &str) -> Vec<&'static str> {
    let mut paths = Vec::new();
    if lower.contains("proxy-server-nameserver")
        || lower.contains("proxy_server_nameserver")
        || lower.contains("proxy_server")
        || lower.contains("proxy server")
    {
        paths.push("proxy_server");
    }
    if lower.contains("direct-nameserver")
        || lower.contains("direct_nameserver")
        || (lower.contains("direct") && !lower.contains("redirect"))
    {
        paths.push("direct");
    }
    if lower.contains("default-nameserver") || lower.contains("default_nameserver") {
        paths.push("default");
    }
    if lower.contains("fallback")
        || (lower.contains("proxy")
            && !lower.contains("proxy-server-nameserver")
            && !lower.contains("proxy_server"))
        || (lower.contains("nameserver")
            && !lower.contains("direct-nameserver")
            && !lower.contains("default-nameserver")
            && !lower.contains("proxy-server-nameserver"))
    {
        paths.push("proxy");
    }
    if paths.is_empty() {
        paths.push("direct");
    }
    paths
}

fn is_recovery_evidence_line(raw_lower: &str) -> bool {
    let lower_owned;
    let lower = if raw_lower.bytes().any(|b| b.is_ascii_uppercase()) {
        lower_owned = raw_lower.to_ascii_lowercase();
        lower_owned.as_str()
    } else {
        raw_lower
    };

    // Reject warning/error/fatal lines as recovery evidence (including persisted
    // `[warning] [mihomo] [TCP] ...` log entries).
    if lower.contains("level=error")
        || lower.contains("level=warning")
        || lower.contains("level=warn")
        || lower.contains("level=fatal")
        || lower.contains("[error]")
        || lower.contains("[warning]")
        || lower.contains("[fatal]")
        || lower.contains(" error ")
        || lower.contains(" error:")
        || lower.contains("[warn]")
        || lower.contains(" warn ")
        || lower.contains("failed")
        || lower.contains("timeout")
        || lower.contains("timed out")
        || lower.contains("x509:")
        || lower.contains("doesn't contain")
        || lower.contains("does not contain")
        || lower.contains("cannot validate")
        || lower.contains("refused")
        || lower.contains("unreachable")
        || lower.contains("deadline exceeded")
        || lower.contains("err=")
    {
        return false;
    }

    lower.contains("[tcp]")
        || lower.contains("[udp]")
        || lower.contains("-> direct")
        || lower.contains("using ")
        || lower.contains("match ")
        || lower.contains("dns resolved")
        || lower.contains("dns recovered")
        || lower.contains("fallback succeeded")
        || lower.contains("health check passed")
        || lower.contains("delay=")
        || (lower.contains("[dns]")
            && (lower.contains("resolved")
                || lower.contains("succeeded")
                || lower.contains("recovered")
                || lower.contains(" ok")))
}

fn extract_log_timestamp(line: &str) -> Option<String> {
    // 1. Mihomo logfmt `time="..."` attribute
    if let Some(pos) = line.find("time=\"") {
        let rest = &line[pos + 6..];
        if let Some(end) = rest.find('"') {
            let candidate = rest[..end].trim();
            if !candidate.is_empty() {
                return Some(candidate.to_string());
            }
        }
    }

    let bytes = line.as_bytes();
    // 2. Scan for `YYYY-MM-DDTHH:MM:SS...` or `YYYY-MM-DD HH:MM:SS...`
    if bytes.len() >= 19 {
        for i in 0..=bytes.len() - 19 {
            if is_iso_date_time_prefix(&bytes[i..i + 19]) {
                let mut end = i + 19;
                // Optional fractional seconds `.123456`
                if end < bytes.len() && bytes[end] == b'.' {
                    end += 1;
                    while end < bytes.len() && bytes[end].is_ascii_digit() {
                        end += 1;
                    }
                }
                // Optional timezone (`Z` or `+08:00` / `-05:00`)
                if end < bytes.len() && matches!(bytes[end], b'Z' | b'z') {
                    end += 1;
                } else if end + 6 <= bytes.len()
                    && matches!(bytes[end], b'+' | b'-')
                    && bytes[end + 1].is_ascii_digit()
                    && bytes[end + 2].is_ascii_digit()
                    && bytes[end + 3] == b':'
                    && bytes[end + 4].is_ascii_digit()
                    && bytes[end + 5].is_ascii_digit()
                {
                    end += 6;
                }
                return Some(line[i..end].to_string());
            }
        }
    }
    None
}

fn is_iso_date_time_prefix(slice: &[u8]) -> bool {
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

fn compute_next_retry_at(last_seen: Option<&str>) -> Option<String> {
    let raw = last_seen?.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return Some((dt + Duration::minutes(DEFAULT_RETRY_DELAY_MINUTES)).to_rfc3339());
    }
    if let Ok(naive) = NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S") {
        let next = naive + Duration::minutes(DEFAULT_RETRY_DELAY_MINUTES);
        return Some(next.format("%Y-%m-%d %H:%M:%S").to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_upstream_cert_rejection_then_fallback_recovery_reports_degraded_recovered() {
        let logs = vec![
            r#"time="2026-11-26T03:44:51+08:00" level=warning msg="[DNS] direct-nameserver resolve api.github.com failed: Post \"https://223.5.5.5/dns-query\": tls: failed to verify certificate: x509: cannot validate certificate for 223.5.5.5 because it doesn't contain any IP SANs""#.to_string(),
            r#"time="2026-11-26T03:44:54+08:00" level=info msg="[TCP] 127.0.0.1:54321 --> api.github.com:443 match DomainSuffix(github.com) using AI-Group[JP-01]""#.to_string(),
        ];

        let diag = analyze_dns_tls_diagnostics(&logs, "last 64 KiB");
        assert_eq!(diag.status, DNS_TLS_STATUS_DEGRADED_RECOVERED);
        assert_eq!(diag.category, DNS_TLS_CATEGORY);
        assert_eq!(diag.failure_count, 1);
        assert_eq!(diag.first_seen_at.as_deref(), Some("2026-11-26T03:44:51+08:00"));
        assert_eq!(diag.last_seen_at.as_deref(), Some("2026-11-26T03:44:51+08:00"));
        assert!(diag.tls_verification_preserved);
        assert!(diag.recovered);
        assert_eq!(diag.recovery_time.as_deref(), Some("2026-11-26T03:44:54+08:00"));
        assert!(diag.next_retry_at.is_none());
        assert_eq!(diag.network_timeout_only_count, 0);
        assert!(diag.affected_paths.contains(&"direct".to_string()));
        assert!(
            diag.affected_upstreams
                .contains(&"AliDNS DoH/DoT (223.5.5.*)".to_string())
        );
        // Must never leak full raw upstream IPv4 in output labels.
        assert!(!diag.affected_upstreams.iter().any(|u| u.contains("223.5.5.5")));
    }

    #[test]
    fn all_upstreams_cert_rejection_reports_alert_preserves_tls_and_gives_next_retry() {
        let logs = vec![
            r#"2026-11-26T03:44:51+08:00 WARN [DNS] direct-nameserver https://223.5.5.5/dns-query failed: x509: cannot validate certificate for 223.5.5.5 because it doesn't contain any IP SANs"#.to_string(),
            r#"2026-11-26T03:45:43+08:00 WARN [DNS] proxy-server-nameserver https://1.12.12.12/dns-query failed: tls: failed to verify certificate: x509: certificate is valid for *.doh.pub, not 1.12.12.12"#.to_string(),
        ];

        let diag = analyze_dns_tls_diagnostics(&logs, "last 256 KiB");
        assert_eq!(diag.status, DNS_TLS_STATUS_CERT_FAILED);
        assert_eq!(diag.category, DNS_TLS_CATEGORY);
        assert_eq!(diag.failure_count, 2);
        assert_eq!(diag.first_seen_at.as_deref(), Some("2026-11-26T03:44:51+08:00"));
        assert_eq!(diag.last_seen_at.as_deref(), Some("2026-11-26T03:45:43+08:00"));
        assert!(diag.tls_verification_preserved);
        assert!(!diag.recovered);
        assert!(diag.recovery_time.is_none());
        assert_eq!(
            diag.next_retry_at.as_deref(),
            Some("2026-11-26T03:50:43+08:00")
        );
        assert!(diag.next_retry_hint.contains("2026-11-26T03:50:43+08:00"));
        assert!(diag.next_retry_hint.contains("TLS"));
        assert!(diag.affected_paths.contains(&"direct".to_string()));
        assert!(diag.affected_paths.contains(&"proxy_server".to_string()));
        assert!(
            diag.affected_upstreams
                .contains(&"AliDNS DoH/DoT (223.5.5.*)".to_string())
        );
        assert!(
            diag.affected_upstreams
                .contains(&"DNSPod DoH/DoT (1.12.12.*)".to_string())
        );
    }

    #[test]
    fn pure_port_853_network_timeouts_are_excluded_from_cert_verification_failures() {
        let logs = vec![
            r#"2026-11-26T04:00:01Z WARN [DNS] resolve example.com via tls://223.6.6.6:853 failed: dial tcp 223.6.6.6:853: i/o timeout"#.to_string(),
            r#"2026-11-26T04:00:06Z WARN [DNS] resolve openai.com via tls://120.53.53.*:853 failed: context deadline exceeded"#.to_string(),
        ];

        let diag = analyze_dns_tls_diagnostics(&logs, "last 64 KiB");
        assert_eq!(diag.status, DNS_TLS_STATUS_HEALTHY);
        assert_eq!(diag.failure_count, 0);
        assert_eq!(diag.network_timeout_only_count, 2);
        assert!(diag.affected_upstreams.is_empty());
        assert!(diag.tls_verification_preserved);
        assert!(!diag.recovered);
        assert!(diag.next_retry_hint.contains("853/DoT"));
    }

    #[test]
    fn sanitized_disk_logs_with_masked_octets_are_precisely_recognized() {
        let logs = vec![
            r#"2026-11-26T03:44:51Z WARN [DNS] nameserver Post "https://223.5.5.*/dns-query": tls: failed to verify certificate: x509: cannot validate certificate for 223.5.5.* because it doesn't contain any IP SANs"#.to_string(),
            r#"2026-11-26T03:44:52Z WARN [DNS] nameserver tls://1.12.12.*:853 x509: cannot validate certificate for 1.12.12.* because it doesn't contain any IP SANs"#.to_string(),
            r#"2026-11-26T03:44:53Z WARN [DNS] fallback https://1.1.1.*/dns-query x509: certificate signed by unknown authority"#.to_string(),
            r#"2026-11-26T03:44:54Z WARN [DNS] fallback https://8.8.8.*/dns-query x509: certificate signed by unknown authority"#.to_string(),
        ];

        let diag = analyze_dns_tls_diagnostics(&logs, "sanitized catcloud.log");
        assert_eq!(diag.status, DNS_TLS_STATUS_CERT_FAILED);
        assert_eq!(diag.failure_count, 4);
        assert!(diag.tls_verification_preserved);
        assert_eq!(
            diag.affected_upstreams,
            vec![
                "AliDNS DoH/DoT (223.5.5.*)".to_string(),
                "DNSPod DoH/DoT (1.12.12.*)".to_string(),
                "Cloudflare DoH/DoT (1.1.1.*)".to_string(),
                "Google DoH/DoT (8.8.8.*)".to_string(),
            ]
        );
        assert_eq!(diag.scanned_window_desc, "sanitized catcloud.log");
    }

    #[test]
    fn recovery_excludes_warning_error_fatal_brackets_case_insensitively() {
        // Persisted `[warning] [mihomo] [TCP] ...` / `[ERROR]` / `[FATAL]` lines after a cert
        // failure must NOT trigger false recovery.
        let logs = vec![
            r#"2026-11-26T03:44:51+08:00 [warning] [mihomo] [DNS] direct-nameserver Post "https://223.5.5.*/dns-query": x509: cannot validate certificate for 223.5.5.*. because it doesn't contain any IP SANs"#.to_string(),
            r#"2026-11-26T03:45:01+08:00 [warning] [mihomo] [TCP] 127.0.0.1:50000 --> api.openai.com:443 match DomainSuffix(openai.com) using AI-Group[JP-01]"#.to_string(),
            r#"2026-11-26T03:45:02+08:00 [WARNING] [mihomo] [UDP] 127.0.0.1:50001 --> 1.1.1.*:443 -> DIRECT"#.to_string(),
            r#"2026-11-26T03:45:03+08:00 [ERROR] [mihomo] [TCP] dial using JP-01"#.to_string(),
            r#"2026-11-26T03:45:04+08:00 [FATAL] [mihomo] [DNS] resolved ok"#.to_string(),
        ];

        let diag = analyze_dns_tls_diagnostics(&logs, "persisted catcloud.log");
        assert_eq!(diag.status, DNS_TLS_STATUS_CERT_FAILED);
        assert!(!diag.recovered);
        assert!(diag.recovery_time.is_none());
        assert_eq!(diag.failure_count, 1);
        // Sentence-ending dot after masked IPv4 (`223.5.5.*.`) must still map to AliDNS.
        assert!(
            diag.affected_upstreams
                .contains(&"AliDNS DoH/DoT (223.5.5.*)".to_string()),
            "expected AliDNS upstream from `223.5.5.*.`, got: {:?}",
            diag.affected_upstreams
        );

        assert!(!is_recovery_evidence_line(
            "[warning] [mihomo] [TCP] 127.0.0.1:1234 --> example.com:443"
        ));
        assert!(!is_recovery_evidence_line(
            "[WARNING] [mihomo] [TCP] match DomainSuffix"
        ));
        assert!(!is_recovery_evidence_line(
            "[ERROR] [mihomo] [TCP] using JP-01"
        ));
        assert!(!is_recovery_evidence_line(
            "[FATAL] [mihomo] [DNS] dns resolved"
        ));
        assert!(is_recovery_evidence_line(
            r#"2026-11-26T03:46:00+08:00 [info] [mihomo] [TCP] 127.0.0.1:54321 --> api.github.com:443 match DomainSuffix(github.com) using AI-Group[JP-01]"#
        ));
    }

    #[test]
    fn contains_ipv4_prefix_token_handles_masked_sentence_dot_and_dot_word_boundary() {
        // Masked IPv4 with trailing sentence period aligns with raw IPv4 handling.
        assert!(contains_ipv4_prefix_token("cert failed for 223.5.5.*.", "223.5.5."));
        assert!(contains_ipv4_prefix_token("cert failed for 223.5.5.5.", "223.5.5."));
        assert!(contains_ipv4_prefix_token("cert failed for 223.5.5.*. Next", "223.5.5."));
        assert!(!contains_ipv4_prefix_token("oid 223.5.5.*.1", "223.5.5."));
        assert!(!contains_ipv4_prefix_token("oid 223.5.5.5.1", "223.5.5."));

        // `dot` inside `is_dns_context` requires word boundaries so unrelated words do not match.
        let dotcom_line =
            "2026-11-26T04:00:00Z WARN https://dotcom.example.com x509: certificate has expired";
        assert!(!is_dns_context(
            dotcom_line,
            &dotcom_line.to_ascii_lowercase(),
            &[]
        ));
        let window_line =
            "2026-11-26T04:00:00Z WARN window antidote x509: certificate has expired";
        assert!(!is_dns_context(
            window_line,
            &window_line.to_ascii_lowercase(),
            &[]
        ));
        let dot_line =
            "2026-11-26T04:00:00Z WARN DoT upstream handshake x509: certificate has expired";
        assert!(is_dns_context(
            dot_line,
            &dot_line.to_ascii_lowercase(),
            &[]
        ));

        // End-to-end: non-DNS `dotcom` / `window` cert errors must NOT trigger DNS TLS alert.
        let non_dns_logs = vec![dotcom_line.to_string(), window_line.to_string()];
        let diag = analyze_dns_tls_diagnostics(&non_dns_logs, "non-dns cert errors");
        assert_eq!(diag.status, DNS_TLS_STATUS_HEALTHY);
        assert_eq!(diag.failure_count, 0);
    }
}
