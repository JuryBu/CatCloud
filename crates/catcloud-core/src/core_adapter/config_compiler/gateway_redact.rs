//! AST-level YAML redaction engine for transparent-gateway and relay-fragment exports.

use crate::error::CatResult;
use crate::models::{PreAccelRelay, ProxyNode};
use serde_yaml_ng::{Mapping, Value};
use std::collections::HashSet;
use std::net::IpAddr;
use url::Url;

fn is_gateway_yaml_credential_key(key: &str) -> bool {
    let lower = key.trim().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "password"
            | "passwd"
            | "pwd"
            | "uuid"
            | "token"
            | "secret"
            | "controller_secret"
            | "controller-secret"
            | "obfs_password"
            | "obfs-password"
            | "client_secret"
            | "client-secret"
            | "access_token"
            | "access-token"
            | "refresh_token"
            | "refresh-token"
            | "api_key"
            | "api-key"
            | "apikey"
            | "x-api-key"
            | "private_key"
            | "private-key"
            | "public_key"
            | "public-key"
            | "peer-public-key"
            | "peer_public_key"
            | "pre-shared-key"
            | "pre_shared_key"
            | "short_id"
            | "short-id"
            | "auth"
            | "auth_str"
            | "auth-str"
            | "psk"
            | "pbk"
            | "sid"
            | "cookie"
            | "set-cookie"
            | "username"
            | "user"
            | "passphrase"
            | "authorization"
            | "hmac-key"
            | "hmac_key"
            | "encryption-key"
            | "encryption_key"
    ) || lower.ends_with("_password")
        || lower.ends_with("-password")
        || lower.ends_with("_secret")
        || lower.ends_with("-secret")
        || lower.ends_with("_token")
        || lower.ends_with("-token")
        || lower.ends_with("_private_key")
        || lower.ends_with("-private-key")
        || lower.ends_with("_public_key")
        || lower.ends_with("-public-key")
        || lower.ends_with("_api_key")
        || lower.ends_with("-api-key")
}

fn is_gateway_yaml_host_key(key: &str) -> bool {
    let lower = key.trim().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "server"
            | "sni"
            | "servername"
            | "server-name"
            | "server_name"
            | "host"
            | "obfs-host"
            | "obfs_host"
            | "endpoint"
            | "external-controller"
    )
}

fn normalize_sensitive_domain_candidate(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_start_matches('[').trim_end_matches(']');
    if trimmed.is_empty() {
        return None;
    }
    let host_part = if let Some((h, p)) = trimmed.rsplit_once(':') {
        if !h.contains(':') && p.parse::<u16>().is_ok() {
            h
        } else {
            trimmed
        }
    } else {
        trimmed
    };
    let bare = host_part
        .trim_start_matches("*.")
        .trim_start_matches("+.")
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if bare.is_empty()
        || !bare.contains('.')
        || bare == "localhost"
        || bare.starts_with("***.")
        || bare == "<redacted>"
        || bare.contains(char::is_whitespace)
        || bare.contains('/')
        || bare.contains(',')
        || bare.parse::<IpAddr>().is_ok()
    {
        return None;
    }
    Some(bare)
}

fn collect_sensitive_domains_from_yaml_value(val: &Value, out: &mut HashSet<String>) {
    match val {
        Value::Mapping(map) => {
            for (k, v) in map {
                if let Some(key_str) = k.as_str() {
                    if is_gateway_yaml_host_key(key_str)
                        && !key_str.eq_ignore_ascii_case("external-controller")
                    {
                        match v {
                            Value::String(s) => {
                                if let Some(dom) = normalize_sensitive_domain_candidate(s) {
                                    out.insert(dom);
                                }
                            }
                            Value::Sequence(seq) => {
                                for item in seq {
                                    if let Some(s) = item.as_str() {
                                        if let Some(dom) = normalize_sensitive_domain_candidate(s) {
                                            out.insert(dom);
                                        }
                                    } else {
                                        collect_sensitive_domains_from_yaml_value(item, out);
                                    }
                                }
                            }
                            _ => collect_sensitive_domains_from_yaml_value(v, out),
                        }
                        continue;
                    }
                }
                collect_sensitive_domains_from_yaml_value(v, out);
            }
        }
        Value::Sequence(seq) => {
            for item in seq {
                collect_sensitive_domains_from_yaml_value(item, out);
            }
        }
        _ => {}
    }
}

fn collect_sensitive_domains_from_json_value(
    val: &serde_json::Value,
    out: &mut HashSet<String>,
) {
    match val {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if is_gateway_yaml_host_key(k) && !k.eq_ignore_ascii_case("external-controller") {
                    match v {
                        serde_json::Value::String(s) => {
                            if let Some(dom) = normalize_sensitive_domain_candidate(s) {
                                out.insert(dom);
                            }
                        }
                        serde_json::Value::Array(arr) => {
                            for item in arr {
                                if let Some(s) = item.as_str() {
                                    if let Some(dom) = normalize_sensitive_domain_candidate(s) {
                                        out.insert(dom);
                                    }
                                } else {
                                    collect_sensitive_domains_from_json_value(item, out);
                                }
                            }
                        }
                        _ => collect_sensitive_domains_from_json_value(v, out),
                    }
                    continue;
                }
                collect_sensitive_domains_from_json_value(v, out);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_sensitive_domains_from_json_value(item, out);
            }
        }
        _ => {}
    }
}

fn collect_gateway_sensitive_domains(
    doc: &Value,
    nodes: &[ProxyNode],
    relays: &[PreAccelRelay],
) -> HashSet<String> {
    let mut domains = HashSet::new();
    for relay in relays {
        if let Some(dom) = normalize_sensitive_domain_candidate(&relay.server) {
            domains.insert(dom);
        }
        if let Some(sni) = relay.sni.as_deref() {
            if let Some(dom) = normalize_sensitive_domain_candidate(sni) {
                domains.insert(dom);
            }
        }
    }
    for node in nodes {
        if let Some(dom) = normalize_sensitive_domain_candidate(&node.server) {
            domains.insert(dom);
        }
        collect_sensitive_domains_from_json_value(&node.raw_config, &mut domains);
    }
    if let Some(proxies) = doc.get("proxies") {
        collect_sensitive_domains_from_yaml_value(proxies, &mut domains);
    }
    domains
}

fn is_broad_non_sensitive_suffix(norm: &str) -> bool {
    matches!(
        norm,
        "com.cn"
            | "net.cn"
            | "org.cn"
            | "gov.cn"
            | "edu.cn"
            | "co.jp"
            | "co.uk"
            | "com.hk"
            | "com.tw"
            | "hicloud.com"
            | "miui.com"
            | "qq.com"
            | "home.arpa"
    )
}

fn matches_sensitive_domain(candidate: &str, sensitive_domains: &HashSet<String>) -> bool {
    let Some(norm) = normalize_sensitive_domain_candidate(candidate) else {
        return false;
    };
    sensitive_domains.iter().any(|sens| {
        norm == *sens
            || norm.ends_with(&format!(".{sens}"))
            || (!is_broad_non_sensitive_suffix(&norm) && sens.ends_with(&format!(".{norm}")))
    })
}

fn is_domain_boundary_byte(b: u8) -> bool {
    !(b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
}

fn redact_sensitive_domains_in_text(text: &str, sensitive_domains: &HashSet<String>) -> String {
    if text.is_empty() || sensitive_domains.is_empty() {
        return text.to_string();
    }
    let mut sorted_domains: Vec<&String> = sensitive_domains.iter().collect();
    sorted_domains.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));

    let mut current = text.to_string();
    for domain in sorted_domains {
        let needle_bytes = domain.as_bytes();
        if needle_bytes.is_empty() {
            continue;
        }
        let replacement = crate::sanitize::redact_ip_or_host(domain);
        let bytes = current.as_bytes();
        let mut out = String::with_capacity(current.len());
        let mut i = 0usize;
        let mut replaced_any = false;
        while i < bytes.len() {
            if i + needle_bytes.len() <= bytes.len()
                && bytes[i..i + needle_bytes.len()].eq_ignore_ascii_case(needle_bytes)
            {
                let before_ok = i == 0
                    || is_domain_boundary_byte(bytes[i - 1])
                    || (i >= 2
                        && matches!(bytes[i - 2], b'+' | b'*')
                        && bytes[i - 1] == b'.');
                let after_ok = i + needle_bytes.len() == bytes.len()
                    || is_domain_boundary_byte(bytes[i + needle_bytes.len()]);
                if before_ok && after_ok {
                    out.push_str(&replacement);
                    i += needle_bytes.len();
                    replaced_any = true;
                    continue;
                }
            }
            if let Some(ch) = current[i..].chars().next() {
                out.push(ch);
                i += ch.len_utf8();
            } else {
                break;
            }
        }
        if replaced_any {
            current = out;
        }
    }
    current
}

fn is_reserved_standard_cidr(payload: &str) -> bool {
    let norm = payload.trim().to_ascii_lowercase();
    matches!(
        norm.as_str(),
        "127.0.0.0/8"
            | "10.0.0.0/8"
            | "100.64.0.0/10"
            | "172.16.0.0/12"
            | "192.168.0.0/16"
            | "169.254.0.0/16"
            | "224.0.0.0/4"
            | "255.255.255.255/32"
            | "0.0.0.0/32"
            | "240.0.0.0/4"
            | "::1/128"
            | "fc00::/7"
            | "fe80::/10"
    )
}

fn redact_cidr_payload(payload: &str) -> String {
    let trimmed = payload.trim();
    if is_reserved_standard_cidr(trimmed) {
        return trimmed.to_string();
    }
    if let Some((ip_part, prefix)) = trimmed.split_once('/') {
        let masked_ip = crate::sanitize::redact_ip_or_host(ip_part);
        format!("{masked_ip}/{prefix}")
    } else {
        crate::sanitize::redact_ip_or_host(trimmed)
    }
}

fn redact_gateway_fake_ip_entry(entry: &str, sensitive_domains: &HashSet<String>) -> String {
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let (prefix, bare) = if let Some(rest) = trimmed.strip_prefix("+.") {
        ("+.", rest)
    } else if let Some(rest) = trimmed.strip_prefix("*.") {
        ("*.", rest)
    } else {
        ("", trimmed)
    };
    if matches_sensitive_domain(bare, sensitive_domains) {
        return format!("{prefix}{}", crate::sanitize::redact_ip_or_host(bare));
    }
    if bare.parse::<IpAddr>().is_ok() {
        return format!("{prefix}{}", crate::sanitize::redact_ip_or_host(bare));
    }
    let dom_clean = redact_sensitive_domains_in_text(trimmed, sensitive_domains);
    crate::sanitize::sanitize_log_line(&dom_clean)
}

fn redact_gateway_rule_line(rule: &str, sensitive_domains: &HashSet<String>) -> String {
    let trimmed = rule.trim();
    if trimmed.is_empty() {
        return rule.to_string();
    }
    if trimmed.starts_with('#') {
        let dom_clean = redact_sensitive_domains_in_text(rule, sensitive_domains);
        return crate::sanitize::sanitize_log_line(&dom_clean);
    }
    if let Some((raw_type, _)) = trimmed.split_once(',') {
        let rt_upper = raw_type.trim().to_ascii_uppercase();
        if matches!(rt_upper.as_str(), "IP-CIDR" | "IP-CIDR6" | "SRC-IP-CIDR") {
            let parts: Vec<&str> = trimmed.split(',').map(str::trim).collect();
            if parts.len() >= 3 {
                let mut rebuilt: Vec<String> = Vec::with_capacity(parts.len());
                rebuilt.push(parts[0].to_string());
                rebuilt.push(redact_cidr_payload(parts[1]));
                for seg in &parts[2..] {
                    let s1 = redact_sensitive_domains_in_text(seg, sensitive_domains);
                    rebuilt.push(crate::sanitize::sanitize_log_line(&s1));
                }
                return rebuilt.join(",");
            }
        }
        if matches!(
            rt_upper.as_str(),
            "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-WILDCARD" | "DOMAIN-KEYWORD" | "DOMAIN-REGEX"
        ) {
            let parts: Vec<&str> = trimmed.split(',').map(str::trim).collect();
            if parts.len() >= 3 {
                let payload = parts[1];
                let payload_matches = matches_sensitive_domain(payload, sensitive_domains)
                    || (matches!(rt_upper.as_str(), "DOMAIN-KEYWORD" | "DOMAIN-REGEX")
                        && sensitive_domains.iter().any(|sens| {
                            let p_lower = payload.to_ascii_lowercase();
                            p_lower.contains(sens)
                                || (p_lower.len() >= 4 && sens.contains(&p_lower))
                        }));
                let clean_payload = if payload_matches {
                    let (prefix, bare) = if let Some(rest) = payload.strip_prefix("+.") {
                        ("+.", rest)
                    } else if let Some(rest) = payload.strip_prefix("*.") {
                        ("*.", rest)
                    } else {
                        ("", payload)
                    };
                    format!("{prefix}{}", crate::sanitize::redact_ip_or_host(bare))
                } else {
                    let s1 = redact_sensitive_domains_in_text(payload, sensitive_domains);
                    crate::sanitize::sanitize_log_line(&s1)
                };
                let mut rebuilt: Vec<String> = Vec::with_capacity(parts.len());
                rebuilt.push(parts[0].to_string());
                rebuilt.push(clean_payload);
                for seg in &parts[2..] {
                    let s1 = redact_sensitive_domains_in_text(seg, sensitive_domains);
                    rebuilt.push(crate::sanitize::sanitize_log_line(&s1));
                }
                return rebuilt.join(",");
            }
        }
    }
    let step1 = redact_sensitive_domains_in_text(trimmed, sensitive_domains);
    crate::sanitize::sanitize_log_line(&step1)
}

fn redact_all_scalar_values_deep(val: &mut Value) {
    match val {
        Value::String(s) => {
            if !s.is_empty() && s != "<REDACTED>" {
                *s = "<REDACTED>".to_string();
            }
        }
        Value::Number(_) => {
            *val = Value::String("<REDACTED>".to_string());
        }
        Value::Sequence(seq) => {
            for item in seq {
                redact_all_scalar_values_deep(item);
            }
        }
        Value::Mapping(map) => {
            for (_, v) in map.iter_mut() {
                redact_all_scalar_values_deep(v);
            }
        }
        _ => {}
    }
}

fn redact_gateway_yaml_host_value(val: &mut Value, sensitive_domains: &HashSet<String>) {
    match val {
        Value::String(s) => {
            if !s.trim().is_empty() {
                *s = crate::sanitize::redact_ip_or_host(s);
            }
        }
        Value::Sequence(seq) => {
            for item in seq {
                redact_gateway_yaml_host_value(item, sensitive_domains);
            }
        }
        Value::Mapping(_) => {
            redact_gateway_yaml_ast(val, sensitive_domains, false);
        }
        _ => {}
    }
}

fn is_public_dns_allowlisted_host(host: &str) -> bool {
    let norm = host.trim().trim_end_matches('.').to_ascii_lowercase();
    matches!(
        norm.as_str(),
        "dns.alidns.com"
            | "doh.pub"
            | "dot.pub"
            | "dns.pub"
            | "dns.google"
            | "dns.google.com"
            | "cloudflare-dns.com"
            | "one.one.one.one"
            | "mozilla.cloudflare-dns.com"
            | "dns.quad9.net"
            | "dns9.quad9.net"
            | "doh.opendns.com"
            | "dns.adguard-dns.com"
            | "dns.adguard.com"
            | "doh.360.cn"
            | "dot.360.cn"
            | "dns.sb"
            | "doh.dns.sb"
            | "dns.tuna.tsinghua.edu.cn"
    )
}

fn format_url_host_redacted(host: &str) -> String {
    let bare = host.trim().trim_start_matches('[').trim_end_matches(']');
    let masked = crate::sanitize::redact_ip_or_host(bare);
    if masked.contains(':') && !masked.starts_with('[') {
        format!("[{masked}]")
    } else {
        masked
    }
}

/// Redact `proxy-providers.*.url` and `rule-providers.*.url`: masks host/IP and replaces any
/// non-root path, query string, or fragment (e.g. `/subscribe/<secret-token>?flag=clash`) with
/// `/<REDACTED>` while preserving valid URL syntax.
fn redact_gateway_provider_url(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "<REDACTED>" {
        return trimmed.to_string();
    }
    let Ok(parsed) = Url::parse(trimmed) else {
        return "<REDACTED>".to_string();
    };
    let scheme = parsed.scheme();
    let Some(host) = parsed.host_str() else {
        return "<REDACTED>".to_string();
    };
    let masked_host = format_url_host_redacted(host);
    let port_part = parsed
        .port()
        .map(|p| format!(":{p}"))
        .unwrap_or_default();
    let has_sensitive_tail = (!parsed.path().is_empty() && parsed.path() != "/")
        || parsed.query().is_some()
        || parsed.fragment().is_some();
    if has_sensitive_tail {
        format!("{scheme}://{masked_host}{port_part}/<REDACTED>")
    } else if parsed.path() == "/" {
        format!("{scheme}://{masked_host}{port_part}/")
    } else {
        format!("{scheme}://{masked_host}{port_part}")
    }
}

/// Redact a single Mihomo DNS server entry while preserving allowlisted public DoH/DoT domains
/// and Mihomo `#DIRECT` / `#PROXY` routing suffixes.
fn redact_gateway_dns_entry(entry: &str, sensitive_domains: &HashSet<String>) -> String {
    let trimmed = entry.trim();
    if trimmed.is_empty() || trimmed == "<REDACTED>" {
        return trimmed.to_string();
    }

    // Preserve Mihomo DNS routing suffixes like `#DIRECT`, `#PROXY`, `#h3=true` intact.
    let (base, suffix) = match trimmed.split_once('#') {
        Some((b, s)) => (b.trim(), Some(s)),
        None => (trimmed, None),
    };
    let clean_suffix = suffix.map(|s| {
        if matches!(
            s.trim().to_ascii_uppercase().as_str(),
            "DIRECT" | "PROXY" | "REJECT"
        ) {
            s.to_string()
        } else {
            let d = redact_sensitive_domains_in_text(s, sensitive_domains);
            crate::sanitize::sanitize_log_line(&d)
        }
    });

    let base_lower = base.to_ascii_lowercase();
    let clean_base = if base_lower.starts_with("dhcp://") || base_lower.starts_with("rcode://") {
        let d = redact_sensitive_domains_in_text(base, sensitive_domains);
        crate::sanitize::sanitize_log_line(&d)
    } else if base.contains("://") {
        if let Ok(parsed) = Url::parse(base) {
            let scheme = parsed.scheme();
            if let Some(host) = parsed.host_str() {
                let is_standard_dns_path =
                    matches!(parsed.path(), "" | "/" | "/dns-query" | "/resolve");
                let has_credentials = !parsed.username().is_empty() || parsed.password().is_some();
                if is_public_dns_allowlisted_host(host)
                    && !has_credentials
                    && is_standard_dns_path
                    && parsed.query().is_none()
                {
                    base.to_string()
                } else {
                    let masked_host = format_url_host_redacted(host);
                    let port_part = parsed
                        .port()
                        .map(|p| format!(":{p}"))
                        .unwrap_or_default();
                    if is_standard_dns_path && !has_credentials && parsed.query().is_none() {
                        format!("{scheme}://{masked_host}{port_part}{}", parsed.path())
                    } else {
                        format!("{scheme}://{masked_host}{port_part}/<REDACTED>")
                    }
                }
            } else {
                let d = redact_sensitive_domains_in_text(base, sensitive_domains);
                crate::sanitize::sanitize_log_line(&d)
            }
        } else {
            let d = redact_sensitive_domains_in_text(base, sensitive_domains);
            crate::sanitize::sanitize_log_line(&d)
        }
    } else if base.eq_ignore_ascii_case("system") {
        base.to_string()
    } else {
        // Strip optional `:port` on bare non-IPv6 hostnames to check against the public DNS allowlist.
        let bare_host_candidate = if !base.starts_with('[')
            && base.bytes().filter(|&b| b == b':').count() == 1
        {
            match base.rsplit_once(':') {
                Some((h, p))
                    if !p.is_empty()
                        && p.bytes().all(|b| b.is_ascii_digit())
                        && p.parse::<u16>().is_ok() =>
                {
                    h
                }
                _ => base,
            }
        } else {
            base
        };
        if is_public_dns_allowlisted_host(bare_host_candidate) {
            base.to_string()
        } else if !base.chars().any(char::is_whitespace) {
            crate::sanitize::redact_ip_or_host(base)
        } else {
            let d = redact_sensitive_domains_in_text(base, sensitive_domains);
            crate::sanitize::sanitize_log_line(&d)
        }
    };

    if let Some(suf) = clean_suffix {
        format!("{clean_base}#{suf}")
    } else {
        clean_base
    }
}

fn redact_gateway_dns_value(val: &mut Value, sensitive_domains: &HashSet<String>) {
    match val {
        Value::String(s) => {
            *s = redact_gateway_dns_entry(s, sensitive_domains);
        }
        Value::Sequence(seq) => {
            for item in seq.iter_mut() {
                redact_gateway_dns_value(item, sensitive_domains);
            }
        }
        _ => redact_gateway_yaml_ast(val, sensitive_domains, false),
    }
}

fn redact_gateway_providers_section(
    val: &mut Value,
    sensitive_domains: &HashSet<String>,
) {
    let Some(providers_map) = val.as_mapping_mut() else {
        redact_gateway_yaml_ast(val, sensitive_domains, false);
        return;
    };
    for (_, provider_val) in providers_map.iter_mut() {
        let Some(pmap) = provider_val.as_mapping_mut() else {
            redact_gateway_yaml_ast(provider_val, sensitive_domains, false);
            continue;
        };
        for (k, v) in pmap.iter_mut() {
            let key_lower = k
                .as_str()
                .map(|s| s.trim().to_ascii_lowercase())
                .unwrap_or_default();
            if key_lower == "header" || key_lower == "headers" {
                redact_all_scalar_values_deep(v);
            } else if key_lower == "url" {
                if let Value::String(s) = v {
                    *s = redact_gateway_provider_url(s);
                } else {
                    redact_gateway_yaml_ast(v, sensitive_domains, false);
                }
            } else if key_lower == "path" {
                if let Value::String(s) = v {
                    let p = crate::sanitize::redact_path_for_display(s);
                    let d = redact_sensitive_domains_in_text(&p, sensitive_domains);
                    *s = crate::sanitize::sanitize_log_line(&d);
                } else {
                    redact_gateway_yaml_ast(v, sensitive_domains, false);
                }
            } else if is_gateway_yaml_credential_key(&key_lower) {
                redact_all_scalar_values_deep(v);
            } else {
                redact_gateway_yaml_ast(v, sensitive_domains, false);
            }
        }
    }
}

fn redact_gateway_dns_section(val: &mut Value, sensitive_domains: &HashSet<String>) {
    let Some(dns_map) = val.as_mapping_mut() else {
        redact_gateway_yaml_ast(val, sensitive_domains, false);
        return;
    };
    for (k, v) in dns_map.iter_mut() {
        let key_lower = k
            .as_str()
            .map(|s| s.trim().to_ascii_lowercase())
            .unwrap_or_default();
        match key_lower.as_str() {
            "fake-ip-filter" => {
                if let Value::Sequence(seq) = v {
                    for item in seq.iter_mut() {
                        if let Value::String(s) = item {
                            *s = redact_gateway_fake_ip_entry(s, sensitive_domains);
                        }
                    }
                } else {
                    redact_gateway_yaml_ast(v, sensitive_domains, false);
                }
            }
            "listen" => {
                if let Value::String(s) = v {
                    if !s.trim().is_empty() {
                        *s = crate::sanitize::redact_ip_or_host(s);
                    }
                }
            }
            "default-nameserver"
            | "direct-nameserver"
            | "nameserver"
            | "proxy-server-nameserver"
            | "fallback" => {
                redact_gateway_dns_value(v, sensitive_domains);
            }
            "nameserver-policy" => {
                if let Value::Mapping(old_policy) = v {
                    let mut new_policy = Mapping::new();
                    for (pk, mut pv) in std::mem::take(old_policy) {
                        let new_pk = if let Value::String(ks) = pk {
                            Value::String(redact_gateway_fake_ip_entry(&ks, sensitive_domains))
                        } else {
                            pk
                        };
                        redact_gateway_dns_value(&mut pv, sensitive_domains);
                        new_policy.insert(new_pk, pv);
                    }
                    *old_policy = new_policy;
                }
            }
            _ => redact_gateway_yaml_ast(v, sensitive_domains, false),
        }
    }
}

fn redact_gateway_hosts_section(val: &mut Value, sensitive_domains: &HashSet<String>) {
    let Some(old_hosts) = val.as_mapping_mut() else {
        redact_gateway_yaml_ast(val, sensitive_domains, false);
        return;
    };
    let mut new_hosts = Mapping::new();
    for (hk, mut hv) in std::mem::take(old_hosts) {
        let new_hk = if let Value::String(ks) = hk {
            Value::String(redact_gateway_fake_ip_entry(&ks, sensitive_domains))
        } else {
            hk
        };
        redact_gateway_yaml_host_value(&mut hv, sensitive_domains);
        new_hosts.insert(new_hk, hv);
    }
    *old_hosts = new_hosts;
}

fn redact_gateway_yaml_ast(
    val: &mut Value,
    sensitive_domains: &HashSet<String>,
    is_root: bool,
) {
    match val {
        Value::Mapping(map) => {
            for (k, v) in map.iter_mut() {
                let key_str = k.as_str().unwrap_or("");
                let key_lower = key_str.trim().to_ascii_lowercase();

                if is_root {
                    match key_lower.as_str() {
                        "rule-providers" | "proxy-providers" => {
                            redact_gateway_providers_section(v, sensitive_domains);
                            continue;
                        }
                        "dns" => {
                            redact_gateway_dns_section(v, sensitive_domains);
                            continue;
                        }
                        "hosts" => {
                            redact_gateway_hosts_section(v, sensitive_domains);
                            continue;
                        }
                        "rules" => {
                            if let Value::Sequence(seq) = v {
                                for item in seq.iter_mut() {
                                    if let Value::String(s) = item {
                                        *s = redact_gateway_rule_line(s, sensitive_domains);
                                    } else {
                                        redact_gateway_yaml_ast(item, sensitive_domains, false);
                                    }
                                }
                                continue;
                            }
                        }
                        _ => {}
                    }
                }

                if is_gateway_yaml_credential_key(&key_lower) {
                    redact_all_scalar_values_deep(v);
                    continue;
                }
                if is_gateway_yaml_host_key(&key_lower) {
                    redact_gateway_yaml_host_value(v, sensitive_domains);
                    continue;
                }
                if key_lower == "path" || key_lower.ends_with("-path") || key_lower.ends_with("_path")
                {
                    if let Value::String(s) = v {
                        let p = crate::sanitize::redact_path_for_display(s);
                        let d = redact_sensitive_domains_in_text(&p, sensitive_domains);
                        *s = crate::sanitize::sanitize_log_line(&d);
                        continue;
                    }
                }

                redact_gateway_yaml_ast(v, sensitive_domains, false);
            }
        }
        Value::Sequence(seq) => {
            for item in seq.iter_mut() {
                redact_gateway_yaml_ast(item, sensitive_domains, false);
            }
        }
        Value::String(s) => {
            if !s.is_empty() && s != "*" && s != "<REDACTED>" {
                let dom_clean = redact_sensitive_domains_in_text(s, sensitive_domains);
                *s = crate::sanitize::sanitize_log_line(&dom_clean);
            }
        }
        _ => {}
    }
}

/// AST-level redaction for gateway YAML exports: recursively sanitizes credentials, upstream
/// servers/SNIs/hosts, `rule-providers.*.header`, and sensitive domains/non-reserved IPs inside
/// `dns.fake-ip-filter` and `rules`, then serializes via `serde_yaml_ng::to_string` and re-attaches
/// the comment header so the output is guaranteed 100% syntactically valid YAML with zero leaks.
pub(super) fn redact_gateway_yaml(
    header: &str,
    mut value: Value,
    nodes: &[ProxyNode],
    relays: &[PreAccelRelay],
) -> CatResult<String> {
    let sensitive_domains = collect_gateway_sensitive_domains(&value, nodes, relays);
    redact_gateway_yaml_ast(&mut value, &sensitive_domains, true);
    let body_yaml = serde_yaml_ng::to_string(&value)?;
    Ok(format!("{header}{body_yaml}"))
}
