use crate::models::{PreAccelRelay, ProxyNode};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Well-known public DNS IPv4 resolvers (retained for reference and diagnostic labeling).
/// Note: Runtime sanitization via [`is_safe_dns_or_local_ipv4`] no longer exempts these IPv4s;
/// all non-loopback/non-unspecified IPv4s are masked to `A.B.C.*` (e.g. `223.5.5.*`).
pub const SAFE_PUBLIC_DNS_IPV4S: &[&str] = &[
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "223.5.5.5",
    "223.6.6.6",
    "119.29.29.29",
    "119.28.28.28",
    "1.12.12.12",
    "120.53.53.53",
    "114.114.114.114",
    "114.114.115.115",
    "180.76.76.76",
    "180.184.1.1",
    "180.184.2.2",
    "1.2.4.8",
    "210.2.4.8",
];

/// Returns `true` strictly for loopback (`127.0.0.1`) and unspecified (`0.0.0.0`).
/// All private (including `198.18.0.0/15`, `10.*`, `172.16-31.*`, `192.168.*`, `169.254.*`)
/// and public IPv4 addresses (including public DNS resolvers) are masked to `A.B.C.*`.
pub fn is_safe_dns_or_local_ipv4(octets: [u8; 4]) -> bool {
    matches!(octets, [127, 0, 0, 1] | [0, 0, 0, 0])
}

/// Strictly sanitize a log, diagnostic, or error line before persisting or exporting to AI/CLI:
/// - Redacts URL userinfo credentials (`scheme://user:pass@host`) and opaque proxy payloads
///   (`vmess://<base64>`, `ss://<base64>`, `mmrelay://v1/<payload>`)
/// - Redacts sensitive query/key-value secrets (`secret`, `password`, `token`, `key`, `auth`,
///   `uuid`, `obfs_password`, `refresh_token`, `client_secret`, `access_token`, `passphrase`,
///   `cookie`, `psk`, `pbk`, `sid`, prefixed keys, `Bearer`, etc.) while preserving valid JSON
/// - Redacts local user home directory usernames (`C:\Users\<USER>\`, `/Users/<USER>/`,
///   `/home/<USER>/`), including Chinese and space-containing usernames
/// - Redacts non-system drive absolute paths (`D:\SomeFolder\...` -> `<LOCAL_PATH>` / `<LOCAL_PATH>/bin`)
/// - Masks all private (including `198.18.0.0/15`), CGNAT, link-local, ULA, and public IPv4/IPv6
///   addresses, strictly exempting only `127.0.0.1`, `0.0.0.0`, `::1`, and `::` without touching
///   timestamps (`HH:MM:SS`), version strings (`v1_1.2.3.4`), or 5+ segment OIDs
/// - Masks non-allowlisted upstream proxy domains appearing in dial/connect error messages
///   (e.g. `dial tcp/udp ...` or `connect error ...`) to `***.<tld>`
pub fn sanitize_log_line(raw: &str) -> String {
    let step1 = redact_url_userinfo(raw);
    let step2 = redact_bearer_tokens(&step1);
    let step3 = redact_sensitive_key_values(&step2);
    let step4 = redact_user_home_paths(&step3);
    let step5 = redact_non_system_drive_paths(&step4);
    let step6 = redact_public_ipv4(&step5);
    let step7 = redact_public_ipv6(&step6);
    redact_dial_error_domains(&step7)
}

/// Redact a single server IP or hostname (optionally with `:port` or `[ipv6]:port`)
/// for read-only CLI/AI display.
/// - Safe local/DNS IPv4, `::1`, `::`, and `localhost` are preserved.
/// - Other IPv4 addresses are masked to `A.B.C.*`.
/// - Other IPv6 addresses are masked to `a:b::*`.
/// - Domain hostnames are masked to `***.<tld>` (hiding both subdomain and vendor SLD);
///   single-label hostnames are masked to `<REDACTED>`.
pub fn redact_ip_or_host(host: &str) -> String {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed == "<REDACTED>" || trimmed.starts_with("***.") {
        return trimmed.to_string();
    }

    // Handle bracketed IPv6 `[addr]` or `[addr]:port`
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some(close_idx) = rest.find(']') {
            let inner = &rest[..close_idx];
            let suffix = &rest[close_idx + 1..];
            if inner.ends_with("::*") {
                return trimmed.to_string();
            }
            if let Ok(ip) = Ipv6Addr::from_str(inner) {
                return format!("[{}]{suffix}", format_redacted_ipv6(ip, inner));
            }
            return format!("[<REDACTED>]{suffix}");
        }
    }

    // Pure IPv6 without brackets (e.g. `240e:390::42`, `::1`, `::`)
    if trimmed.ends_with("::*") {
        return trimmed.to_string();
    }
    if let Ok(ip) = Ipv6Addr::from_str(trimmed) {
        return format_redacted_ipv6(ip, trimmed);
    }

    // Unbracketed IPv6 + `:port` (at least 3 colons total)
    if trimmed.bytes().filter(|&b| b == b':').count() >= 3 {
        if let Some((addr_part, port_part)) = trimmed.rsplit_once(':') {
            if !port_part.is_empty()
                && port_part.bytes().all(|b| b.is_ascii_digit())
                && port_part.parse::<u16>().is_ok()
            {
                if addr_part.ends_with("::*") {
                    return trimmed.to_string();
                }
                if let Ok(ip) = Ipv6Addr::from_str(addr_part) {
                    return format!("{}:{port_part}", format_redacted_ipv6(ip, addr_part));
                }
            }
        }
    }

    // Optional single `:port` suffix for IPv4 or hostname
    let (host_part, port_suffix) = if let Some((h, p)) = trimmed.rsplit_once(':') {
        if !h.contains(':')
            && !p.is_empty()
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u16>().is_ok()
        {
            (h, Some(p))
        } else {
            (trimmed, None)
        }
    } else {
        (trimmed, None)
    };

    let masked = redact_bare_host_or_ipv4(host_part);
    if let Some(port) = port_suffix {
        format!("{masked}:{port}")
    } else {
        masked
    }
}

fn redact_bare_host_or_ipv4(host_part: &str) -> String {
    if host_part.is_empty() {
        return String::new();
    }
    if host_part.eq_ignore_ascii_case("localhost")
        || host_part == "<REDACTED>"
        || host_part.starts_with("***.")
    {
        return host_part.to_string();
    }
    // Already masked IPv4 like `198.51.100.*`
    if let Some(prefix) = host_part.strip_suffix(".*") {
        let parts: Vec<&str> = prefix.split('.').collect();
        if parts.len() == 3 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
            return host_part.to_string();
        }
    }
    if let Ok(ip) = Ipv4Addr::from_str(host_part) {
        let o = ip.octets();
        return if is_safe_dns_or_local_ipv4(o) {
            host_part.to_string()
        } else {
            format!("{}.{}.{}.*", o[0], o[1], o[2])
        };
    }

    // Domain name: hide subdomain and SLD, keeping only a clean alphabetic TLD (`***.com`)
    if let Some((_, tld)) = host_part.rsplit_once('.') {
        if !tld.is_empty()
            && tld.len() <= 12
            && tld.bytes().all(|b| b.is_ascii_alphabetic())
        {
            return format!("***.{}", tld.to_ascii_lowercase());
        }
    }

    "<REDACTED>".to_string()
}

/// Redact a single filesystem path for read-only CLI/UI/AI display:
/// - Strips local user home usernames (`C:\Users\<USER>\...`, `/Users/<USER>/...`, `/home/<USER>/...`)
/// - Replaces non-system Windows drive paths (`D:\Private\CatCloud\bin` -> `<LOCAL_PATH>/bin`)
/// - Masks long numeric account directory segments (>= 6 consecutive digits, e.g. IM/game user IDs)
///   with `***`
pub fn redact_path_for_display(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let (verbatim_prefix, body) = if let Some(rest) = trimmed.strip_prefix(r"\\?\") {
        (r"\\?\", rest)
    } else {
        ("", trimmed)
    };

    // Whole path on a non-system Windows drive (e.g. `D:\My Folder\CatCloud\bin`)
    if starts_with_windows_drive_path(body) && !body.as_bytes()[0].eq_ignore_ascii_case(&b'C') {
        return format_redacted_non_system_path(body);
    }

    // Whole path that starts with a home prefix and may end directly at a spaced username
    // (e.g. `C:\Users\<USER>` without trailing slash).
    if let Some(plen) = match_windows_users_prefix(body).or_else(|| match_unix_home_prefix(body)) {
        let after = &body[plen..];
        if !after.is_empty() && !after.starts_with("<USER>") {
            let next_sep = after.find(['\\', '/']);
            let rest_after_user = next_sep.map(|idx| &after[idx..]).unwrap_or("");
            let base = format!(
                "{verbatim_prefix}{}<USER>{rest_after_user}",
                &body[..plen]
            );
            return redact_numeric_account_path_segments(&base);
        }
    }

    let step1 = redact_user_home_paths(body);
    let step2 = redact_non_system_drive_paths(&step1);
    let assembled = if verbatim_prefix.is_empty() || step2.starts_with("<LOCAL_PATH>") {
        step2
    } else {
        format!("{verbatim_prefix}{step2}")
    };
    redact_numeric_account_path_segments(&assembled)
}

fn is_uuid_segment(seg: &str) -> bool {
    let b = seg.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (idx, &ch) in b.iter().enumerate() {
        if matches!(idx, 8 | 13 | 18 | 23) {
            if ch != b'-' {
                return false;
            }
        } else if !ch.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

fn is_long_hex_hash_segment(seg: &str) -> bool {
    seg.len() >= 16
        && seg.bytes().all(|b| b.is_ascii_hexdigit())
        && seg.bytes().any(|b| matches!(b, b'a'..=b'f' | b'A'..=b'F'))
}

fn redact_long_digits_in_dir_segment(seg: &str) -> String {
    if seg.is_empty()
        || seg == "<USER>"
        || seg == "<LOCAL_PATH>"
        || seg == "***"
        || is_uuid_segment(seg)
        || is_long_hex_hash_segment(seg)
    {
        return seg.to_string();
    }
    if seg.len() >= 6 && seg.bytes().all(|b| b.is_ascii_digit()) {
        return "***".to_string();
    }

    let bytes = seg.as_bytes();
    let mut out = String::with_capacity(seg.len());
    let mut i = 0usize;
    let mut changed = false;

    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let mut end = i;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
            let run_len = end - i;
            let prev_is_hex_alpha =
                i > 0 && matches!(bytes[i - 1], b'a'..=b'f' | b'A'..=b'F');
            let next_is_hex_alpha =
                end < bytes.len() && matches!(bytes[end], b'a'..=b'f' | b'A'..=b'F');
            if run_len >= 6 && !prev_is_hex_alpha && !next_is_hex_alpha {
                out.push_str("***");
                changed = true;
            } else {
                out.push_str(&seg[i..end]);
            }
            i = end;
            continue;
        }
        if let Some(ch) = seg[i..].chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }

    if changed { out } else { seg.to_string() }
}

/// Mask directory segments containing >= 6 consecutive ASCII digits (such as QQ, WeChat, or game
/// numeric account folders) with `***`, while preserving path separators and executable filenames.
pub fn redact_numeric_account_path_segments(path: &str) -> String {
    if path.is_empty() || path.starts_with("<LOCAL_PATH>") {
        return path.to_string();
    }

    let (prefix, rest) = if let Some(after) = path.strip_prefix(r"\\?\") {
        (r"\\?\", after)
    } else {
        ("", path)
    };

    // Tokenize into alternating `(is_sep, slice)` preserving exact separators (`\` or `/`).
    let mut tokens: Vec<(bool, &str)> = Vec::new();
    let mut start = 0usize;
    let bytes = rest.as_bytes();
    let mut idx = 0usize;
    while idx < bytes.len() {
        if matches!(bytes[idx], b'\\' | b'/') {
            if idx > start {
                tokens.push((false, &rest[start..idx]));
            }
            let sep_start = idx;
            while idx < bytes.len() && matches!(bytes[idx], b'\\' | b'/') {
                idx += 1;
            }
            tokens.push((true, &rest[sep_start..idx]));
            start = idx;
        } else {
            idx += 1;
        }
    }
    if start < bytes.len() {
        tokens.push((false, &rest[start..]));
    }

    let trailing_sep = tokens.last().is_some_and(|(is_sep, _)| *is_sep);
    let last_non_sep_idx = tokens.iter().rposition(|(is_sep, _)| !*is_sep);

    let mut out = String::with_capacity(path.len());
    out.push_str(prefix);
    for (ti, &(is_sep, seg)) in tokens.iter().enumerate() {
        if is_sep {
            out.push_str(seg);
            continue;
        }
        // Preserve Windows drive letter segment (`C:`).
        if ti == 0 && seg.len() == 2 && seg.as_bytes()[0].is_ascii_alphabetic() && seg.as_bytes()[1] == b':' {
            out.push_str(seg);
            continue;
        }
        let is_last_segment = Some(ti) == last_non_sep_idx;
        let is_likely_filename = is_last_segment && !trailing_sep && seg.contains('.');
        if is_likely_filename {
            out.push_str(seg);
        } else if is_last_segment && !trailing_sep {
            // Only mask trailing extensionless segment when it is a pure >=6-digit directory ID.
            if seg.len() >= 6 && seg.bytes().all(|b| b.is_ascii_digit()) {
                out.push_str("***");
            } else {
                out.push_str(seg);
            }
        } else {
            out.push_str(&redact_long_digits_in_dir_segment(seg));
        }
    }

    out
}

/// Return a sanitized read-only clone of `PreAccelRelay`:
/// preserves id, name, provider, region, protocol, port, priority, expires_at, enabled, metrics,
/// while masking `server` (and non-empty `sni`) via `redact_ip_or_host` and `password` (`<REDACTED>`).
pub fn redact_relay_for_readonly(relay: &PreAccelRelay) -> PreAccelRelay {
    let mut out = relay.clone();
    out.server = redact_ip_or_host(&relay.server);
    if let Some(ref sni) = out.sni {
        if !sni.trim().is_empty() {
            out.sni = Some(redact_ip_or_host(sni));
        }
    }
    if !out.password.is_empty() {
        out.password = "<REDACTED>".to_string();
    }
    out
}

/// Credential keys stripped inside `ProxyNode.raw_config` during read-only redaction.
fn is_node_raw_credential_key(key: &str) -> bool {
    let lower = key.trim().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "password"
            | "passwd"
            | "pwd"
            | "uuid"
            | "token"
            | "private-key"
            | "private_key"
            | "public-key"
            | "public_key"
            | "short-id"
            | "short_id"
            | "auth-str"
            | "auth_str"
            | "auth"
            | "authorization"
            | "obfs-password"
            | "obfs_password"
            | "psk"
            | "pbk"
            | "sid"
            | "secret"
            | "username"
            | "passphrase"
            | "cookie"
            | "set-cookie"
            | "api-key"
            | "api_key"
            | "apikey"
            | "client-secret"
            | "client_secret"
            | "access-token"
            | "access_token"
            | "refresh-token"
            | "refresh_token"
    ) || lower.ends_with("_password")
        || lower.ends_with("-password")
        || lower.ends_with("_secret")
        || lower.ends_with("-secret")
        || lower.ends_with("_token")
        || lower.ends_with("-token")
        || lower.ends_with("_private_key")
        || lower.ends_with("-private-key")
}

/// Host/SNI keys masked via `redact_ip_or_host` inside `ProxyNode.raw_config` during read-only
/// redaction (covers `server`, `sni`, `servername`, `plugin-opts.host`, `ws-opts.headers.Host`,
/// `h2-opts.host`, and `http-opts.headers.Host`).
fn is_node_raw_host_key(key: &str) -> bool {
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
    )
}

fn redact_json_node_value(val: &mut serde_json::Value) {
    match val {
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if is_node_raw_host_key(k) {
                    match v {
                        serde_json::Value::String(s) => {
                            if !s.trim().is_empty() {
                                *s = redact_ip_or_host(s);
                            }
                        }
                        serde_json::Value::Array(arr) => {
                            for item in arr.iter_mut() {
                                if let serde_json::Value::String(s) = item {
                                    if !s.trim().is_empty() {
                                        *s = redact_ip_or_host(s);
                                    }
                                } else {
                                    redact_json_node_value(item);
                                }
                            }
                        }
                        _ => redact_json_node_value(v),
                    }
                    continue;
                }
                if is_node_raw_credential_key(k) {
                    match v {
                        serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
                            redact_json_node_value(v);
                        }
                        serde_json::Value::Null => {}
                        serde_json::Value::String(s) if s.is_empty() => {}
                        _ => {
                            *v = serde_json::Value::String("<REDACTED>".to_string());
                        }
                    }
                    continue;
                }
                redact_json_node_value(v);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                redact_json_node_value(item);
            }
        }
        serde_json::Value::String(s) => {
            *s = sanitize_log_line(s);
        }
        _ => {}
    }
}

/// Return a sanitized read-only clone of `ProxyNode`:
/// masks `server`, `sni`, `servername`, `host` (`plugin-opts.host`, `ws-opts.headers.Host`, etc.)
/// and recursively redacts all credential keys (`password`, `uuid`, `token`, `private-key`,
/// `auth-str`, `obfs-password`, `psk`, `pbk`, `sid`, `secret`, `username`, etc.) inside `raw_config`.
pub fn redact_node_for_readonly(node: &ProxyNode) -> ProxyNode {
    let mut out = node.clone();
    out.server = redact_ip_or_host(&node.server);
    redact_json_node_value(&mut out.raw_config);
    out
}

/// Recursively sanitize an arbitrary JSON value in place as a final safety pass for
/// `sanitized: true` CLI/diagnostic outputs:
/// - Skips pure numbers, booleans, nulls, and allowlisted scalar metadata keys (`id`, `version`,
///   `core_version`, `schema_version`, `sha256`, `config_sha256`, `instance_hash`, `timestamp`,
///   and any `*_at` timestamp key).
/// - Routes `source_ip`, `destination_ip`, `controller_addr`, `controller_host`, `server`,
///   `sni`, and `servername` through [`redact_ip_or_host`].
/// - Routes plain `host` keys through IP-only redaction so IPv4/IPv6 literals (including
///   `IP:port` / `[IPv6]:port`) are masked while normal business target domains (such as
///   `api.openai.com` or `github.com`) remain intact.
/// - Routes filesystem path keys (`*_path`, `*_dir`, `data_dir`, `cli_path`, `binary_path`,
///   `config_path`, etc.) through [`redact_path_for_display`] + [`sanitize_log_line`].
/// - Routes explicit credential keys (`password`, `secret`, `*_secret`, `*_token`, etc.)
///   to `"<REDACTED>"` and all remaining strings through [`sanitize_log_line`].
pub fn sanitize_json_value(val: &mut serde_json::Value) {
    match val {
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if is_json_metadata_skip_key(k) {
                    if !v.is_string() {
                        sanitize_json_value(v);
                    }
                    continue;
                }
                if is_json_explicit_credential_key(k) {
                    match v {
                        serde_json::Value::String(s) => {
                            if !s.is_empty() && s != "<REDACTED>" {
                                *s = "<REDACTED>".to_string();
                            }
                        }
                        serde_json::Value::Number(_) => {
                            *v = serde_json::Value::String("<REDACTED>".to_string());
                        }
                        serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
                            sanitize_json_value(v);
                        }
                        _ => {}
                    }
                    continue;
                }
                if is_json_ip_or_upstream_host_key(k) {
                    match v {
                        serde_json::Value::String(s) => {
                            if !s.trim().is_empty() {
                                *s = redact_ip_or_host(s);
                            }
                        }
                        serde_json::Value::Array(arr) => {
                            for item in arr.iter_mut() {
                                if let serde_json::Value::String(s) = item {
                                    if !s.trim().is_empty() {
                                        *s = redact_ip_or_host(s);
                                    }
                                } else {
                                    sanitize_json_value(item);
                                }
                            }
                        }
                        _ => sanitize_json_value(v),
                    }
                    continue;
                }
                if k.trim().eq_ignore_ascii_case("host") {
                    match v {
                        serde_json::Value::String(s) => {
                            if !s.trim().is_empty() {
                                *s = redact_ip_literal_preserve_domain(s);
                            }
                        }
                        serde_json::Value::Array(arr) => {
                            for item in arr.iter_mut() {
                                if let serde_json::Value::String(s) = item {
                                    if !s.trim().is_empty() {
                                        *s = redact_ip_literal_preserve_domain(s);
                                    }
                                } else {
                                    sanitize_json_value(item);
                                }
                            }
                        }
                        _ => sanitize_json_value(v),
                    }
                    continue;
                }
                if is_json_path_key(k) {
                    match v {
                        serde_json::Value::String(s) => {
                            if !s.trim().is_empty() {
                                let p = redact_path_for_display(s);
                                *s = sanitize_log_line(&p);
                            }
                        }
                        serde_json::Value::Array(arr) => {
                            for item in arr.iter_mut() {
                                if let serde_json::Value::String(s) = item {
                                    if !s.trim().is_empty() {
                                        let p = redact_path_for_display(s);
                                        *s = sanitize_log_line(&p);
                                    }
                                } else {
                                    sanitize_json_value(item);
                                }
                            }
                        }
                        _ => sanitize_json_value(v),
                    }
                    continue;
                }
                sanitize_json_value(v);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                sanitize_json_value(item);
            }
        }
        serde_json::Value::String(s) => {
            *s = sanitize_log_line(s);
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

fn is_json_metadata_skip_key(key: &str) -> bool {
    let lower = key.trim().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "id" | "version"
            | "core_version"
            | "schema_version"
            | "sha256"
            | "config_sha256"
            | "instance_hash"
            | "timestamp"
    ) || lower.ends_with("_at")
}

fn is_json_explicit_credential_key(key: &str) -> bool {
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
            | "private_key"
            | "private-key"
            | "public_key"
            | "public-key"
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
            | "passphrase"
            | "authorization"
    ) || lower.ends_with("_password")
        || lower.ends_with("-password")
        || lower.ends_with("_secret")
        || lower.ends_with("-secret")
        || lower.ends_with("_token")
        || lower.ends_with("-token")
        || lower.ends_with("_private_key")
        || lower.ends_with("-private-key")
}

fn is_json_ip_or_upstream_host_key(key: &str) -> bool {
    let lower = key.trim().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "source_ip"
            | "destination_ip"
            | "sourceip"
            | "destinationip"
            | "controller_addr"
            | "controller_host"
            | "server"
            | "sni"
            | "servername"
            | "server_name"
            | "server-name"
            | "endpoint"
    )
}

fn is_json_path_key(key: &str) -> bool {
    let lower = key.trim().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "path"
            | "dir"
            | "data_dir"
            | "cli_path"
            | "binary_path"
            | "config_path"
            | "log_path"
            | "runtime_dir"
            | "process_path"
    ) || lower.ends_with("_path")
        || lower.ends_with("-path")
        || lower.ends_with("_dir")
        || lower.ends_with("-dir")
}

/// Mask a plain `host` value only when it is an IPv4/IPv6 literal (optionally with `:port` or
/// bracketed `[IPv6]:port`), preserving business target domains (e.g. `api.openai.com`,
/// `github.com`) intact.
fn redact_ip_literal_preserve_domain(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    // 1. Bracketed IPv6 `[addr]` or `[addr]:port`
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some(close_idx) = rest.find(']') {
            let inner = &rest[..close_idx];
            let suffix = &rest[close_idx + 1..];
            if inner.ends_with("::*") {
                return trimmed.to_string();
            }
            if let Ok(ip) = Ipv6Addr::from_str(inner) {
                return format!("[{}]{suffix}", format_redacted_ipv6(ip, inner));
            }
        }
    }

    // 2. Pure IPv6 without brackets
    if trimmed.ends_with("::*") {
        return trimmed.to_string();
    }
    if let Ok(ip) = Ipv6Addr::from_str(trimmed) {
        return format_redacted_ipv6(ip, trimmed);
    }

    // 3. Unbracketed IPv6 + `:port`
    if trimmed.bytes().filter(|&b| b == b':').count() >= 3 {
        if let Some((addr_part, port_part)) = trimmed.rsplit_once(':') {
            if !port_part.is_empty()
                && port_part.bytes().all(|b| b.is_ascii_digit())
                && port_part.parse::<u16>().is_ok()
            {
                if addr_part.ends_with("::*") {
                    return trimmed.to_string();
                }
                if let Ok(ip) = Ipv6Addr::from_str(addr_part) {
                    return format!("{}:{port_part}", format_redacted_ipv6(ip, addr_part));
                }
            }
        }
    }

    // 4. Optional single `:port` suffix for IPv4
    let (host_part, port_suffix) = if let Some((h, p)) = trimmed.rsplit_once(':') {
        if !h.contains(':')
            && !p.is_empty()
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u16>().is_ok()
        {
            (h, Some(p))
        } else {
            (trimmed, None)
        }
    } else {
        (trimmed, None)
    };

    if let Ok(ip) = Ipv4Addr::from_str(host_part) {
        let o = ip.octets();
        let masked = if is_safe_dns_or_local_ipv4(o) {
            host_part.to_string()
        } else {
            format!("{}.{}.{}.*", o[0], o[1], o[2])
        };
        return if let Some(port) = port_suffix {
            format!("{masked}:{port}")
        } else {
            masked
        };
    }

    // Business domain (e.g. `api.openai.com`, `github.com`): keep verbatim while still stripping
    // any accidentally embedded URL credentials or inline secrets.
    sanitize_log_line(raw)
}

/// Sanitize a compiled Mihomo YAML configuration for read-only CLI/AI output:
/// - Redacts controller `secret`, proxy `server`, `sni`, `servername`, `server-name`, `server_name`,
///   `host`, `obfs-host`, `obfs_host`, `username`, `password`, `uuid`, `token`, `private-key`,
///   `public-key`, `short-id`, `auth-str`, `obfs-password`, `psk`, `pbk`, `sid`
/// - Handles both inline YAML flow arrays (`host: [a, b]`) and multi-line YAML block sequences
///   (`host:\n  - a.vendor.com`)
/// - Redacts local user home paths, non-system drive paths, and all non-loopback/non-unspecified
///   IPv4/IPv6 literals
/// - Quotes leading `*` and other YAML special indicator scalars so redacted values remain
///   syntactically valid YAML
pub fn redact_compiled_yaml(yaml: &str) -> String {
    let mut out = String::with_capacity(yaml.len());
    let mut block_host_seq_indent: Option<usize> = None;

    for chunk in yaml.split_inclusive('\n') {
        let (line, newline) = if let Some(stripped) = chunk.strip_suffix("\r\n") {
            (stripped, "\r\n")
        } else if let Some(stripped) = chunk.strip_suffix('\n') {
            (stripped, "\n")
        } else {
            (chunk, "")
        };

        let mut handled_as_block_item = false;
        let step1 = if let Some(parent_indent) = block_host_seq_indent {
            if line.trim().is_empty() {
                block_host_seq_indent = None;
                redact_yaml_extra_fields(line)
            } else {
                let line_indent = line
                    .bytes()
                    .take_while(|&b| b == b' ' || b == b'\t')
                    .count();
                if line_indent <= parent_indent {
                    block_host_seq_indent = None;
                    redact_yaml_extra_fields(line)
                } else if line[line_indent..].starts_with('#') {
                    handled_as_block_item = true;
                    line.to_string()
                } else if let Some(redacted_item) =
                    redact_yaml_block_seq_host_item(line, line_indent)
                {
                    handled_as_block_item = true;
                    redacted_item
                } else {
                    block_host_seq_indent = None;
                    redact_yaml_extra_fields(line)
                }
            }
        } else {
            redact_yaml_extra_fields(line)
        };

        if !handled_as_block_item && block_host_seq_indent.is_none() {
            block_host_seq_indent = detect_yaml_block_host_seq_indent(line);
        }

        let step2 = sanitize_log_line(&step1);
        out.push_str(&step2);
        out.push_str(newline);
    }
    out
}

fn needs_yaml_quoting(s: &str) -> bool {
    matches!(
        s.as_bytes().first(),
        Some(
            b'*' | b'&'
                | b'!'
                | b'%'
                | b'@'
                | b'`'
                | b'['
                | b'{'
                | b'>'
                | b'|'
                | b'?'
                | b':'
                | b'-'
                | b'#'
                | b','
        )
    )
}

fn is_yaml_block_host_seq_key(key: &str) -> bool {
    let lower = key.trim().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "host"
            | "sni"
            | "servername"
            | "server-name"
            | "server_name"
            | "obfs-host"
            | "obfs_host"
            | "endpoint"
    )
}

fn detect_yaml_block_host_seq_indent(line: &str) -> Option<usize> {
    let indent = line
        .bytes()
        .take_while(|&b| b == b' ' || b == b'\t')
        .count();
    let mut rest = &line[indent..];
    if rest.is_empty() || rest.starts_with('#') {
        return None;
    }
    if let Some(after_dash) = rest
        .strip_prefix("- ")
        .or_else(|| rest.strip_prefix("-\t"))
    {
        rest = after_dash.trim_start_matches([' ', '\t']);
    }
    let colon_idx = rest.find(':')?;
    let after_colon = rest[colon_idx + 1..].trim_start_matches([' ', '\t']);
    if !after_colon.is_empty() && !after_colon.starts_with('#') {
        return None;
    }
    let raw_key = rest[..colon_idx].trim();
    let unquoted = if (raw_key.starts_with('"') && raw_key.ends_with('"') && raw_key.len() >= 2)
        || (raw_key.starts_with('\'') && raw_key.ends_with('\'') && raw_key.len() >= 2)
    {
        &raw_key[1..raw_key.len() - 1]
    } else {
        raw_key
    };
    if is_yaml_block_host_seq_key(unquoted) {
        Some(indent)
    } else {
        None
    }
}

fn split_yaml_unquoted_value_and_tail(val_slice: &str) -> (&str, &str) {
    let bytes = val_slice.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'#' && (i == 0 || matches!(bytes[i - 1], b' ' | b'\t')) {
            let value_part = val_slice[..i].trim_end_matches([' ', '\t']);
            return (value_part, &val_slice[value_part.len()..]);
        }
        i += 1;
    }
    let value_part = val_slice.trim_end_matches([' ', '\t']);
    (value_part, &val_slice[value_part.len()..])
}

fn redact_yaml_block_seq_host_item(line: &str, line_indent: usize) -> Option<String> {
    let rest = &line[line_indent..];
    if !(rest.starts_with("- ") || rest.starts_with("-\t")) {
        return None;
    }
    let after_dash_idx = line_indent + 1;
    let ws_len = line[after_dash_idx..]
        .bytes()
        .take_while(|&b| b == b' ' || b == b'\t')
        .count();
    let val_start = after_dash_idx + ws_len;
    let val_slice = &line[val_start..];
    if val_slice.is_empty() || val_slice.starts_with('#') {
        return Some(line.to_string());
    }
    let prefix = &line[..val_start];
    let first_byte = val_slice.as_bytes()[0];
    if matches!(first_byte, b'"' | b'\'') {
        let qc = first_byte as char;
        let inner = &val_slice[1..];
        let close_rel = find_unescaped_quote(inner, first_byte);
        if let Some(close_idx) = close_rel {
            let raw_val = &inner[..close_idx];
            let tail = &inner[close_idx + 1..];
            let masked = if raw_val.trim().is_empty() {
                raw_val.to_string()
            } else {
                redact_ip_or_host(raw_val)
            };
            return Some(format!("{prefix}{qc}{masked}{qc}{tail}"));
        }
    }

    let (raw_val, tail) = split_yaml_unquoted_value_and_tail(val_slice);
    if raw_val.is_empty() || raw_val.eq_ignore_ascii_case("null") || raw_val == "~" {
        return Some(line.to_string());
    }
    let masked = redact_ip_or_host(raw_val);
    let rendered = if needs_yaml_quoting(&masked) {
        format!("\"{masked}\"")
    } else {
        masked
    };
    Some(format!("{prefix}{rendered}{tail}"))
}

fn redact_yaml_flow_host_list(inner: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    for raw_item in inner.split(',') {
        let trimmed = raw_item.trim();
        if trimmed.is_empty() {
            parts.push(String::new());
            continue;
        }
        let quoted = (trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2)
            || (trimmed.starts_with('\'') && trimmed.ends_with('\'') && trimmed.len() >= 2);
        if quoted {
            let q = trimmed.as_bytes()[0] as char;
            let val = &trimmed[1..trimmed.len() - 1];
            let masked = redact_ip_or_host(val);
            parts.push(format!("{q}{masked}{q}"));
        } else if trimmed.eq_ignore_ascii_case("null") || trimmed == "~" {
            parts.push(trimmed.to_string());
        } else {
            let masked = redact_ip_or_host(trimmed);
            if needs_yaml_quoting(&masked) {
                parts.push(format!("\"{masked}\""));
            } else {
                parts.push(masked);
            }
        }
    }
    parts.join(", ")
}

/// Redact YAML-specific `server:`, `servername:`, `server-name:`, `server_name:`, `sni:`,
/// `host:`, `obfs-host:`, `obfs_host:`, and `username:` fields in both block and flow YAML
/// without matching `nameserver:` or `proxy-server-nameserver:`.
fn redact_yaml_extra_fields(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0usize;

    while i < bytes.len() {
        let prev_ok = i == 0
            || !(bytes[i - 1].is_ascii_alphanumeric()
                || matches!(bytes[i - 1], b'_' | b'-' | b'/'));

        if prev_ok && bytes[i].is_ascii_alphabetic() {
            let mut matched_kind: Option<(&str, bool)> = None; // (key, is_host_or_server)
            for &(key, is_host_or_server) in &[
                ("servername", true),
                ("server-name", true),
                ("server_name", true),
                ("server", true),
                ("sni", true),
                ("host", true),
                ("obfs-host", true),
                ("obfs_host", true),
                ("endpoint", true),
                ("username", false),
            ] {
                let klen = key.len();
                if i + klen < bytes.len()
                    && bytes[i..i + klen].eq_ignore_ascii_case(key.as_bytes())
                {
                    let mut sep_idx = i + klen;
                    let was_quoted_key =
                        sep_idx < bytes.len() && matches!(bytes[sep_idx], b'"' | b'\'');
                    if was_quoted_key {
                        sep_idx += 1;
                    }
                    while sep_idx < bytes.len() && bytes[sep_idx] == b' ' {
                        sep_idx += 1;
                    }
                    if sep_idx < bytes.len() && bytes[sep_idx] == b':' {
                        let next_after_colon = bytes.get(sep_idx + 1).copied();
                        let is_yaml_mapping_colon = matches!(
                            next_after_colon,
                            None | Some(b' ' | b'\t' | b'\r' | b'\n')
                        ) || (was_quoted_key
                            && matches!(next_after_colon, Some(b'"' | b'\'')));
                        if is_yaml_mapping_colon {
                            let mut val_start = sep_idx + 1;
                            while val_start < bytes.len() && bytes[val_start] == b' ' {
                                val_start += 1;
                            }
                            if val_start >= bytes.len()
                                || matches!(bytes[val_start], b'{' | b'\r' | b'\n' | b'#')
                            {
                                break;
                            }

                            // Support inline YAML flow arrays for host fields such as
                            // `host: [h2a.vendor.com, h2b.vendor.org]`.
                            if bytes[val_start] == b'[' {
                                if is_host_or_server {
                                    let rest = &line[val_start + 1..];
                                    if let Some(close_rel) = rest.find(']') {
                                        let inner = &rest[..close_rel];
                                        if !inner.contains('{') && !inner.contains('[') {
                                            matched_kind = Some((key, is_host_or_server));
                                            out.push_str(&line[i..val_start]);
                                            out.push('[');
                                            out.push_str(&redact_yaml_flow_host_list(inner));
                                            out.push(']');
                                            i = val_start + 1 + close_rel + 1;
                                        }
                                    }
                                }
                                break;
                            }

                            matched_kind = Some((key, is_host_or_server));
                            out.push_str(&line[i..val_start]);
                            if matches!(bytes[val_start], b'"' | b'\'') {
                                let q = bytes[val_start];
                                let qc = q as char;
                                out.push(qc);
                                let inner = &line[val_start + 1..];
                                if let Some(close_rel) = find_unescaped_quote(inner, q) {
                                    let raw_val = &inner[..close_rel];
                                    let rep = if is_host_or_server {
                                        redact_ip_or_host(raw_val)
                                    } else if raw_val.is_empty() {
                                        String::new()
                                    } else {
                                        "<REDACTED>".to_string()
                                    };
                                    out.push_str(&rep);
                                    out.push(qc);
                                    i = val_start + 1 + close_rel + 1;
                                } else {
                                    let end_rel = inner
                                        .find(is_value_terminator)
                                        .unwrap_or(inner.len());
                                    let raw_val = &inner[..end_rel];
                                    let rep = if is_host_or_server {
                                        redact_ip_or_host(raw_val)
                                    } else {
                                        "<REDACTED>".to_string()
                                    };
                                    out.push_str(&rep);
                                    i = val_start + 1 + end_rel;
                                }
                            } else {
                                let tail = &line[val_start..];
                                let val_len = tail
                                    .find(|c: char| {
                                        c.is_whitespace()
                                            || matches!(c, ',' | '}' | ']' | '#')
                                    })
                                    .unwrap_or(tail.len());
                                let raw_val = &tail[..val_len];
                                let rep = if raw_val.eq_ignore_ascii_case("null") || raw_val == "~"
                                {
                                    raw_val.to_string()
                                } else if is_host_or_server {
                                    let masked = redact_ip_or_host(raw_val);
                                    // Quote leading `*` or other YAML indicator chars so redacted values remain valid YAML scalars.
                                    if needs_yaml_quoting(&masked) {
                                        format!("\"{masked}\"")
                                    } else {
                                        masked
                                    }
                                } else if raw_val.is_empty() {
                                    String::new()
                                } else {
                                    "<REDACTED>".to_string()
                                };
                                out.push_str(&rep);
                                i = val_start + val_len;
                            }
                            break;
                        }
                    }
                }
            }
            if matched_kind.is_some() {
                continue;
            }
        }

        if let Some(ch) = line[i..].chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }

    out
}

fn is_opaque_uri_payload_end(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '?' | '#' | '"' | '\'' | ')' | ']' | '}' | '>' | ',' | ';'
        )
}

fn redact_url_userinfo(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(scheme_sep) = rest.find("://") {
        let prefix = &rest[..scheme_sep];
        let scheme = prefix
            .rsplit_once(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
            .map(|(_, s)| s)
            .unwrap_or(prefix);

        let after_sep_idx = scheme_sep + 3;
        out.push_str(&rest[..after_sep_idx]);
        let tail = &rest[after_sep_idx..];

        // 1. `mmrelay://v1/<payload>` (or opaque `mmrelay://<payload>` without `@`)
        if scheme.eq_ignore_ascii_case("mmrelay") {
            if tail.len() >= 3 && tail[..3].eq_ignore_ascii_case("v1/") {
                out.push_str(&tail[..3]);
                let after_v1 = &tail[3..];
                if after_v1.starts_with("<REDACTED>") {
                    out.push_str("<REDACTED>");
                    rest = &after_v1["<REDACTED>".len()..];
                } else {
                    let payload_end = after_v1
                        .find(is_opaque_uri_payload_end)
                        .unwrap_or(after_v1.len());
                    if payload_end > 0 {
                        out.push_str("<REDACTED>");
                    }
                    rest = &after_v1[payload_end..];
                }
                continue;
            }
            if tail.starts_with("<REDACTED>") {
                out.push_str("<REDACTED>");
                rest = &tail["<REDACTED>".len()..];
                continue;
            }
            let payload_end = tail.find(is_opaque_uri_payload_end).unwrap_or(tail.len());
            if payload_end > 0 && !tail[..payload_end].contains('@') {
                out.push_str("<REDACTED>");
                rest = &tail[payload_end..];
                continue;
            }
        }

        // 2. Base64 / opaque payloads without `@`: `vmess://<base64>`, `ss://<base64>`
        if scheme.eq_ignore_ascii_case("vmess") || scheme.eq_ignore_ascii_case("ss") {
            if tail.starts_with("<REDACTED>") {
                out.push_str("<REDACTED>");
                rest = &tail["<REDACTED>".len()..];
                continue;
            }
            let payload_end = tail.find(is_opaque_uri_payload_end).unwrap_or(tail.len());
            let payload = &tail[..payload_end];
            if !payload.is_empty() && !payload.contains('@') {
                out.push_str("<REDACTED>");
                rest = &tail[payload_end..];
                continue;
            }
        }

        // 3. Standard `scheme://user:pass@host` authority userinfo redaction
        let authority_end = tail
            .find(|c: char| {
                c.is_whitespace() || matches!(c, '/' | '?' | '#' | '"' | '\'' | ')' | ']' | '>')
            })
            .unwrap_or(tail.len());
        let authority = &tail[..authority_end];
        if let Some(at_idx) = authority.rfind('@') {
            if at_idx > 0 {
                out.push_str("<REDACTED>");
                out.push_str(&authority[at_idx..]);
            } else {
                out.push_str(authority);
            }
        } else {
            out.push_str(authority);
        }
        rest = &tail[authority_end..];
    }
    out.push_str(rest);
    out
}

fn is_value_terminator(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '&' | '#' | '"' | '\'' | ',' | ';' | ')' | ']' | '}' | '<' | '>'
        )
}

fn redact_bearer_tokens(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if i + 7 <= bytes.len() && bytes[i..i + 7].eq_ignore_ascii_case(b"bearer ") {
            let boundary_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
            if boundary_ok {
                out.push_str(&input[i..i + 7]);
                let mut val_start = i + 7;
                while val_start < bytes.len() && bytes[val_start] == b' ' {
                    out.push(' ');
                    val_start += 1;
                }
                let tail = &input[val_start..];
                if tail.starts_with("<REDACTED>") {
                    out.push_str("<REDACTED>");
                    i = val_start + "<REDACTED>".len();
                    continue;
                }
                let val_len = tail.find(is_value_terminator).unwrap_or(tail.len());
                if val_len > 0 {
                    out.push_str("<REDACTED>");
                    i = val_start + val_len;
                    continue;
                }
                i = val_start;
                continue;
            }
        }
        if let Some(ch) = input[i..].chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }
    out
}

const SENSITIVE_KEYS: &[&str] = &[
    "controller_secret",
    "obfs_password",
    "obfs-password",
    "authorization",
    "refresh_token",
    "refresh-token",
    "client_secret",
    "client-secret",
    "access_token",
    "access-token",
    "private_key",
    "private-key",
    "public_key",
    "public-key",
    "passphrase",
    "set-cookie",
    "auth_token",
    "sub_token",
    "user_uuid",
    "short_id",
    "short-id",
    "password",
    "auth_str",
    "auth-str",
    "api_key",
    "api-key",
    "apikey",
    "passwd",
    "secret",
    "cookie",
    "token",
    "auth",
    "uuid",
    "pwd",
    "key",
    "psk",
    "pbk",
    "sid",
];

fn find_unescaped_quote(inner: &str, quote: u8) -> Option<usize> {
    let bytes = inner.as_bytes();
    let mut pos = 0usize;
    if quote == b'\'' {
        // YAML single-quoted scalars do NOT treat `\` as an escape character;
        // literal single quotes are represented by doubling (`''`).
        while pos < bytes.len() {
            if bytes[pos] == b'\'' {
                if pos + 1 < bytes.len() && bytes[pos + 1] == b'\'' {
                    pos += 2;
                    continue;
                }
                return Some(pos);
            }
            pos += 1;
        }
        return None;
    }
    while pos < bytes.len() {
        if bytes[pos] == b'\\' {
            pos += 1;
            if pos < bytes.len() {
                if let Some(ch) = inner[pos..].chars().next() {
                    pos += ch.len_utf8();
                }
            }
            continue;
        }
        if bytes[pos] == quote {
            return Some(pos);
        }
        pos += 1;
    }
    None
}

fn redact_sensitive_key_values(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;

    while i < bytes.len() {
        let mut matched = false;
        // Allow `_` / `-` prefixed compound key names such as `x-api-key:`, `obfs-password:`,
        // `client_secret=`, `auth_token=`, `sub_token=`, `user_uuid=`, while still refusing
        // mid-word false positives such as `monkey=1` or `author=alice`.
        let prev_is_ident = i > 0 && bytes[i - 1].is_ascii_alphanumeric();

        if !prev_is_ident && bytes[i].is_ascii_alphabetic() {
            for &key in SENSITIVE_KEYS {
                let klen = key.len();
                if i + klen >= bytes.len()
                    || !bytes[i..i + klen].eq_ignore_ascii_case(key.as_bytes())
                {
                    continue;
                }
                let mut sep_idx = i + klen;
                // Optional closing quote around JSON/YAML key (`"secret": "val"`).
                let had_double_quote_before_sep =
                    sep_idx < bytes.len() && bytes[sep_idx] == b'"';
                if sep_idx < bytes.len() && matches!(bytes[sep_idx], b'"' | b'\'') {
                    sep_idx += 1;
                }
                if had_double_quote_before_sep {
                    let mut ws = sep_idx;
                    while ws < bytes.len() && bytes[ws] == b' ' {
                        ws += 1;
                    }
                    if ws < bytes.len() && bytes[ws] == b':' {
                        sep_idx = ws;
                    }
                }
                if sep_idx >= bytes.len() || !matches!(bytes[sep_idx], b'=' | b':') {
                    continue;
                }
                let sep = bytes[sep_idx];
                // Avoid matching URL scheme like `key://`
                if sep == b':'
                    && sep_idx + 2 < bytes.len()
                    && &bytes[sep_idx + 1..sep_idx + 3] == b"//"
                {
                    continue;
                }
                let is_json_colon_context = had_double_quote_before_sep && sep == b':';

                let mut val_start = sep_idx + 1;
                while val_start < bytes.len() && bytes[val_start] == b' ' {
                    val_start += 1;
                }
                if val_start >= bytes.len() {
                    continue;
                }
                // Skip structural values such as `secret: {` or `key: [`
                if matches!(bytes[val_start], b'{' | b'[' | b'\r' | b'\n') {
                    continue;
                }

                out.push_str(&input[i..val_start]);
                // Preserve `Bearer ` scheme prefix inside `Authorization: Bearer <token>` headers.
                if key == "authorization"
                    && val_start + 7 <= bytes.len()
                    && bytes[val_start..val_start + 7].eq_ignore_ascii_case(b"bearer ")
                {
                    out.push_str(&input[val_start..val_start + 7]);
                    val_start += 7;
                    while val_start < bytes.len() && bytes[val_start] == b' ' {
                        out.push(' ');
                        val_start += 1;
                    }
                    if val_start >= bytes.len() {
                        i = val_start;
                        matched = true;
                        break;
                    }
                }
                if input[val_start..].starts_with("<REDACTED>") {
                    if is_json_colon_context {
                        out.push_str("\"<REDACTED>\"");
                    } else {
                        out.push_str("<REDACTED>");
                    }
                    i = val_start + "<REDACTED>".len();
                    matched = true;
                    break;
                }
                if matches!(bytes[val_start], b'"' | b'\'') {
                    let quote_byte = bytes[val_start];
                    let quote = quote_byte as char;
                    out.push(quote);
                    let inner = &input[val_start + 1..];
                    if let Some(close_rel) = find_unescaped_quote(inner, quote_byte) {
                        out.push_str("<REDACTED>");
                        out.push(quote);
                        i = val_start + 1 + close_rel + 1;
                    } else {
                        let end_rel = inner.find(is_value_terminator).unwrap_or(inner.len());
                        out.push_str("<REDACTED>");
                        i = val_start + 1 + end_rel;
                    }
                } else {
                    let tail = &input[val_start..];
                    let val_len = tail.find(is_value_terminator).unwrap_or(tail.len());
                    if val_len == 0 {
                        i = val_start;
                    } else {
                        if is_json_colon_context {
                            out.push_str("\"<REDACTED>\"");
                        } else {
                            out.push_str("<REDACTED>");
                        }
                        i = val_start + val_len;
                    }
                }
                matched = true;
                break;
            }
        }

        if !matched {
            if let Some(ch) = input[i..].chars().next() {
                out.push(ch);
                i += ch.len_utf8();
            } else {
                break;
            }
        }
    }

    out
}

fn is_home_username_terminator(c: char) -> bool {
    matches!(
        c,
        '\\' | '/' | '"' | '\'' | '`' | '\r' | '\n' | '\t' | ')' | ']' | '}' | '>' | ',' | ';'
    )
}

fn match_windows_users_prefix(tail: &str) -> Option<usize> {
    let bytes = tail.as_bytes();
    if bytes.len() < 9 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' {
        return None;
    }
    let mut pos = 2;
    let sep1_len = if bytes.get(pos..pos + 2) == Some(b"\\\\") {
        2
    } else if matches!(bytes.get(pos), Some(b'\\' | b'/')) {
        1
    } else {
        return None;
    };
    pos += sep1_len;
    if pos + 5 > bytes.len() || !bytes[pos..pos + 5].eq_ignore_ascii_case(b"users") {
        return None;
    }
    pos += 5;
    let sep2_len = if bytes.get(pos..pos + 2) == Some(b"\\\\") {
        2
    } else if matches!(bytes.get(pos), Some(b'\\' | b'/')) {
        1
    } else {
        return None;
    };
    Some(pos + sep2_len)
}

fn match_unix_home_prefix(tail: &str) -> Option<usize> {
    let bytes = tail.as_bytes();
    if bytes.len() >= 7 && bytes[..7].eq_ignore_ascii_case(b"/users/") {
        return Some(7);
    }
    if bytes.len() >= 6 && bytes[..6].eq_ignore_ascii_case(b"/home/") {
        return Some(6);
    }
    None
}

fn redact_user_home_paths(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;

    while i < bytes.len() {
        let mut prefix_len: Option<usize> = None;
        let tail = &input[i..];

        // 1. Windows home path: `C:\Users\<USER>\`, `C:/Users/<USER>/`, `C:\\Users\\<USER>\\`
        if (i == 0 || !bytes[i - 1].is_ascii_alphanumeric()) && bytes[i].is_ascii_alphabetic() {
            prefix_len = match_windows_users_prefix(tail);
        }

        // 2. Unix home path: `/Users/<USER>/`, `/home/<USER>/`
        // Guard against URL paths like `https://example.com/users/profile`.
        if prefix_len.is_none()
            && bytes[i] == b'/'
            && (i == 0
                || (!bytes[i - 1].is_ascii_alphanumeric()
                    && !matches!(bytes[i - 1], b'.' | b'_' | b'-')))
        {
            prefix_len = match_unix_home_prefix(tail);
        }

        if let Some(plen) = prefix_len {
            let after = &tail[plen..];
            if after.starts_with("<USER>") {
                let consumed = plen + "<USER>".len();
                out.push_str(&tail[..consumed]);
                i += consumed;
                continue;
            }
            let hard_len = after
                .find(is_home_username_terminator)
                .unwrap_or(after.len());
            let candidate = &after[..hard_len];
            let next_char = after[hard_len..].chars().next();
            let bounded_by_path_or_quote = matches!(
                next_char,
                Some('\\' | '/' | '"' | '\'' | '`' | '\r' | '\n' | '\t')
            );
            let looks_like_spaced_username = bounded_by_path_or_quote
                && candidate.chars().count() <= 64
                && !candidate.contains("://")
                && !candidate.contains('=');
            let user_len = if looks_like_spaced_username {
                hard_len
            } else {
                after
                    .find(|c: char| c.is_whitespace() || is_home_username_terminator(c))
                    .unwrap_or(after.len())
            };
            if user_len > 0 {
                out.push_str(&tail[..plen]);
                out.push_str("<USER>");
                i += plen + user_len;
                continue;
            }
        }

        if let Some(ch) = tail.chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }

    out
}

fn starts_with_windows_drive_path(tail: &str) -> bool {
    let bytes = tail.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' {
        return false;
    }
    if bytes[2] == b'\\' {
        true
    } else if bytes[2] == b'/' {
        // Exclude single-letter URI schemes such as `d://...`
        bytes.get(3) != Some(&b'/')
    } else {
        false
    }
}

fn is_bare_path_hard_terminator(c: char) -> bool {
    matches!(
        c,
        '\r' | '\n'
            | '\t'
            | '"'
            | '\''
            | '`'
            | '('
            | ')'
            | '['
            | ']'
            | '{'
            | '}'
            | '<'
            | '>'
            | ','
            | ';'
            | '、'
            | '，'
            | '。'
            | '：'
            | '；'
            | '（'
            | '）'
            | '「'
            | '」'
            | '【'
            | '】'
            | '！'
            | '？'
    )
}

fn find_bare_windows_path_end(tail: &str) -> usize {
    let mut pos = 3usize;
    while pos < tail.len() {
        let Some(ch) = tail[pos..].chars().next() else {
            break;
        };
        if is_bare_path_hard_terminator(ch) {
            break;
        }
        if ch == ' ' {
            let mut next_non_space = pos;
            while next_non_space < tail.len() && tail.as_bytes()[next_non_space] == b' ' {
                next_non_space += 1;
            }
            if next_non_space >= tail.len() {
                break;
            }
            let rest = &tail[next_non_space..];
            let seg_len = rest
                .find(|c: char| c.is_whitespace() || is_bare_path_hard_terminator(c))
                .unwrap_or(rest.len());
            let next_seg = &rest[..seg_len];
            let continues_same_path = !next_seg.is_empty()
                && !starts_with_windows_drive_path(next_seg)
                && !next_seg.starts_with('/')
                && !next_seg.contains("://")
                && (next_seg.contains('\\') || next_seg.contains('/'));
            if continues_same_path {
                pos = next_non_space + seg_len;
                continue;
            }
            break;
        }
        pos += ch.len_utf8();
    }
    pos
}

fn format_redacted_non_system_path(raw_path: &str) -> String {
    let last_seg = raw_path
        .split(['\\', '/'])
        .rev()
        .find(|seg| !seg.is_empty());
    match last_seg {
        Some(seg)
            if matches!(
                seg.to_ascii_lowercase().as_str(),
                "bin"
                    | "logs"
                    | "config"
                    | "runtime"
                    | "data"
                    | "cache"
                    | "backup"
                    | "backups"
                    | "agent_docs"
            ) =>
        {
            format!("<LOCAL_PATH>/{seg}")
        }
        _ => "<LOCAL_PATH>".to_string(),
    }
}

/// Redact non-system Windows drive absolute paths (e.g. `D:\SomeFolder\CatCloud\bin` ->
/// `<LOCAL_PATH>/bin`, `E:\Private\sub.yaml` -> `<LOCAL_PATH>`) so portable installation
/// paths or security allowlist guidance never leak local folder names into logs or AI prompts.
fn redact_non_system_drive_paths(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;

    while i < bytes.len() {
        let tail = &input[i..];
        let prev_ok = i == 0
            || !(bytes[i - 1].is_ascii_alphanumeric()
                || matches!(bytes[i - 1], b'_' | b'-' | b'.' | b'/'));

        if prev_ok
            && starts_with_windows_drive_path(tail)
            && !bytes[i].eq_ignore_ascii_case(&b'C')
        {
            let closing_delim = out.chars().next_back().and_then(|prev| match prev {
                '`' => Some('`'),
                '"' => Some('"'),
                '\'' => Some('\''),
                '「' => Some('」'),
                _ => None,
            });
            let path_end = match closing_delim {
                Some('"') => {
                    let quote_end = find_unescaped_quote(tail, b'"').unwrap_or(tail.len());
                    tail[..quote_end]
                        .find(['\r', '\n'])
                        .unwrap_or(quote_end)
                }
                Some(delim) => tail
                    .find(|c: char| c == delim || matches!(c, '\r' | '\n'))
                    .unwrap_or(tail.len()),
                None => find_bare_windows_path_end(tail),
            };
            if path_end >= 3 {
                let raw_path = &tail[..path_end];
                out.push_str(&format_redacted_non_system_path(raw_path));
                i += path_end;
                continue;
            }
        }

        if let Some(ch) = tail.chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }

    out
}

fn is_version_word(word: &str) -> bool {
    let lower = word.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "v" | "ver"
            | "vers"
            | "version"
            | "rel"
            | "release"
            | "rev"
            | "build"
            | "schema"
            | "oid"
    ) || lower.ends_with("version")
    {
        return true;
    }
    if let Some(rest) = lower.strip_prefix('v') {
        if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()) {
            return true;
        }
    }
    if let Some(rest) = lower.strip_prefix("ver") {
        if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()) {
            return true;
        }
    }
    false
}

fn is_preceded_by_version_marker(bytes: &[u8], i: usize) -> bool {
    if i == 0 {
        return false;
    }
    // Underscore-prefixed version token such as `v1_<A.B.C.D>`, `version_<A.B.C.D>`, `core_version_<A.B.C.D>`.
    if bytes[i - 1] == b'_' {
        let mut word_start = i - 1;
        while word_start > 0 && bytes[word_start - 1].is_ascii_alphanumeric() {
            word_start -= 1;
        }
        if word_start < i - 1 {
            if let Ok(seg) = std::str::from_utf8(&bytes[word_start..i - 1]) {
                if is_version_word(seg) {
                    return true;
                }
            }
        }
        return false;
    }

    // Key-value version context such as `version=<A.B.C.D>`, `version: <A.B.C.D>`,
    // `"version": "<A.B.C.D>"`, `"core_version": "<A.B.C.D>"`.
    let mut pos = i;
    if pos > 0 && matches!(bytes[pos - 1], b'"' | b'\'') {
        pos -= 1;
    }
    while pos > 0 && bytes[pos - 1] == b' ' {
        pos -= 1;
    }
    if pos == 0 || !matches!(bytes[pos - 1], b':' | b'=') {
        return false;
    }
    pos -= 1;
    while pos > 0 && bytes[pos - 1] == b' ' {
        pos -= 1;
    }
    if pos > 0 && matches!(bytes[pos - 1], b'"' | b'\'') {
        pos -= 1;
    }
    let word_end = pos;
    while pos > 0
        && (bytes[pos - 1].is_ascii_alphanumeric() || matches!(bytes[pos - 1], b'_' | b'-'))
    {
        pos -= 1;
    }
    if pos < word_end {
        if let Ok(key) = std::str::from_utf8(&bytes[pos..word_end]) {
            let lower = key.to_ascii_lowercase();
            return lower == "version"
                || lower == "ver"
                || lower.ends_with("_version")
                || lower.ends_with("-version");
        }
    }
    false
}

fn redact_public_ipv4(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;

    while i < bytes.len() {
        let prev_ok = i == 0
            || (!(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'.')
                && !is_preceded_by_version_marker(bytes, i));
        if prev_ok && bytes[i].is_ascii_digit() {
            let mut end = i;
            let mut dots = 0usize;
            while end < bytes.len() && (bytes[end].is_ascii_digit() || bytes[end] == b'.') {
                if bytes[end] == b'.' {
                    dots += 1;
                }
                end += 1;
            }
            // Handle sentence-ending trailing dot (e.g. `203.0.113.10.` followed by non-digit/non-ident):
            // step back 1 byte so the period is preserved while the IPv4 is still redacted.
            let mut stepped_back_sentence_dot = false;
            if dots == 4 && end > i && bytes[end - 1] == b'.' {
                let after_dot_ok = end == bytes.len()
                    || !(bytes[end].is_ascii_alphanumeric()
                        || bytes[end] == b'.'
                        || bytes[end] == b'_');
                if after_dot_ok {
                    end -= 1;
                    dots -= 1;
                    stepped_back_sentence_dot = true;
                }
            }
            let next_ok = if stepped_back_sentence_dot {
                true
            } else {
                end == bytes.len()
                    || !(bytes[end].is_ascii_alphanumeric()
                        || bytes[end] == b'.'
                        || bytes[end] == b'_')
            };
            if dots == 3 && next_ok {
                let candidate = &input[i..end];
                if let Ok(ip) = Ipv4Addr::from_str(candidate) {
                    let o = ip.octets();
                    if is_safe_dns_or_local_ipv4(o) {
                        out.push_str(candidate);
                    } else {
                        out.push_str(&format!("{}.{}.{}.*", o[0], o[1], o[2]));
                    }
                    i = end;
                    continue;
                }
            }
        }

        if let Some(ch) = input[i..].chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }

    out
}

fn is_non_public_ipv6(ip: Ipv6Addr) -> bool {
    ip.is_loopback() || ip.is_unspecified()
}

fn is_ipv6_char(b: u8) -> bool {
    b.is_ascii_hexdigit() || b == b':'
}

fn format_redacted_ipv6(ip: Ipv6Addr, raw: &str) -> String {
    if is_non_public_ipv6(ip) {
        raw.to_string()
    } else {
        let segs = ip.segments();
        format!("{:x}:{:x}::*", segs[0], segs[1])
    }
}

fn try_redact_ipv6_token(candidate: &str) -> Option<String> {
    let trimmed = candidate.trim_end_matches(':');
    let trailing = &candidate[trimmed.len()..];
    let has_enough_colons =
        trimmed.contains("::") || trimmed.bytes().filter(|&b| b == b':').count() >= 3;
    if has_enough_colons {
        if let Ok(ip) = Ipv6Addr::from_str(trimmed) {
            return Some(format!("{}{trailing}", format_redacted_ipv6(ip, trimmed)));
        }
    }

    // Cover unbracketed full 8-hextet IPv6 + `:port` (9 colon-separated segments,
    // e.g. `240e:1234:5678:9abc:def0:1234:5678:9abc:443`).
    if let Some((addr_part, port_part)) = trimmed.rsplit_once(':') {
        let valid_port = !port_part.is_empty()
            && port_part.bytes().all(|b| b.is_ascii_digit())
            && port_part.parse::<u16>().is_ok();
        let addr_has_enough_colons =
            addr_part.contains("::") || addr_part.bytes().filter(|&b| b == b':').count() >= 3;
        if valid_port && addr_has_enough_colons {
            if let Ok(ip) = Ipv6Addr::from_str(addr_part) {
                return Some(format!(
                    "{}:{port_part}{trailing}",
                    format_redacted_ipv6(ip, addr_part)
                ));
            }
        }
    }

    None
}

fn redact_public_ipv6(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;

    while i < bytes.len() {
        let prev_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        if prev_ok && is_ipv6_char(bytes[i]) {
            let mut end = i;
            let mut colon_count = 0usize;
            while end < bytes.len() && is_ipv6_char(bytes[end]) {
                if bytes[end] == b':' {
                    colon_count += 1;
                }
                end += 1;
            }
            let next_is_alnum = end < bytes.len() && bytes[end].is_ascii_alphanumeric();
            let mut consume_end = end;
            if next_is_alnum {
                // Handle compressed/full IPv6 immediately followed by `:failed`, `:error`,
                // `:timeout`, etc. where leading hex letters were greedily consumed.
                if let Some(rel_colon) = input[i..end].rfind(':') {
                    consume_end = i + rel_colon;
                } else {
                    consume_end = i;
                }
            }

            if consume_end > i {
                let candidate = &input[i..consume_end];
                let cand_colons = if consume_end == end {
                    colon_count
                } else {
                    candidate.bytes().filter(|&b| b == b':').count()
                };
                // Require either `::` compression or at least 3 colons so `HH:MM:SS` timestamps
                // (exactly 2 colons) are never misclassified as IPv6 literals.
                if candidate.contains("::") || cand_colons >= 3 {
                    if let Some(redacted) = try_redact_ipv6_token(candidate) {
                        out.push_str(&redacted);
                        i = consume_end;
                        continue;
                    }
                }
            }
        }

        if let Some(ch) = input[i..].chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }

    out
}

/// Public connectivity, DoH, and well-known service domain suffixes preserved verbatim in dial/connect
/// error logs so diagnostic clues stay useful without exposing private upstream proxy domains.
const SAFE_PUBLIC_LOG_DOMAIN_SUFFIXES: &[&str] = &[
    "localhost",
    "local",
    "gstatic.com",
    "cloudflare.com",
    "cloudflare-dns.com",
    "dns.google",
    "google.com",
    "googleapis.com",
    "alidns.com",
    "doh.pub",
    "dns.pub",
    "hicloud.com",
    "miui.com",
    "github.com",
    "githubusercontent.com",
    "openai.com",
    "chatgpt.com",
    "anthropic.com",
    "claude.ai",
    "apple.com",
    "microsoft.com",
    "msftconnecttest.com",
];

/// File extensions excluded from domain detection in dial/connect error fragments.
const NON_DOMAIN_FILE_EXTENSIONS: &[&str] = &[
    "rs", "ts", "tsx", "js", "mjs", "cjs", "json", "yaml", "yml", "toml", "log", "txt", "md",
    "exe", "dll", "sys", "so", "dylib", "zip", "gz", "tar", "db", "sqlite", "mmdb", "dat",
    "conf", "cfg", "ini", "env", "pem", "crt", "key", "pid", "lock", "tmp", "bak", "nsh", "nsi",
    "kt", "go", "py", "sh", "ps1",
];

const DIAL_ERROR_TRIGGERS: &[&str] = &[
    "dial tcp4",
    "dial tcp6",
    "dial udp4",
    "dial udp6",
    "dial tcp",
    "dial udp",
    "connect error",
    "connect failed",
    "dial error",
    "dial failed",
];

fn is_safe_public_log_domain(domain: &str) -> bool {
    let lower = domain.to_ascii_lowercase();
    SAFE_PUBLIC_LOG_DOMAIN_SUFFIXES.iter().any(|suffix| {
        lower == *suffix
            || (lower.len() > suffix.len()
                && lower.ends_with(suffix)
                && lower.as_bytes()[lower.len() - suffix.len() - 1] == b'.')
    })
}

fn is_redactable_upstream_domain(candidate: &str) -> bool {
    if candidate.len() < 4
        || candidate.len() > 253
        || candidate.starts_with('.')
        || candidate.ends_with('.')
        || candidate.contains("..")
    {
        return false;
    }
    let Some((prefix, tld)) = candidate.rsplit_once('.') else {
        return false;
    };
    if tld.len() < 2
        || tld.len() > 12
        || !tld.bytes().all(|b| b.is_ascii_alphabetic())
    {
        return false;
    }
    let tld_lower = tld.to_ascii_lowercase();
    if NON_DOMAIN_FILE_EXTENSIONS.contains(&tld_lower.as_str()) {
        return false;
    }
    let mut has_alpha_in_prefix = false;
    for label in prefix.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return false;
        }
        if label.bytes().any(|b| b.is_ascii_alphabetic()) {
            has_alpha_in_prefix = true;
        }
    }
    if !has_alpha_in_prefix {
        return false;
    }
    !is_safe_public_log_domain(candidate)
}

fn match_dial_error_trigger(bytes: &[u8], i: usize) -> Option<usize> {
    let prev_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
    if !prev_ok {
        return None;
    }
    for &trigger in DIAL_ERROR_TRIGGERS {
        let tlen = trigger.len();
        if i + tlen < bytes.len()
            && bytes[i..i + tlen].eq_ignore_ascii_case(trigger.as_bytes())
        {
            let next = bytes[i + tlen];
            if matches!(next, b' ' | b'\t' | b':' | b'=' | b'(') {
                return Some(tlen);
            }
        }
    }
    None
}

fn redact_domains_in_dial_fragment(fragment: &str) -> String {
    let bytes = fragment.as_bytes();
    let mut out = String::with_capacity(fragment.len());
    let mut i = 0usize;

    while i < bytes.len() {
        let prev_ok = i == 0
            || !(bytes[i - 1].is_ascii_alphanumeric()
                || matches!(bytes[i - 1], b'.' | b'_' | b'-' | b'*' | b'/'))
            || (i >= 3 && &bytes[i - 3..i] == b"://");

        if prev_ok && bytes[i].is_ascii_alphanumeric() {
            let mut end = i;
            while end < bytes.len()
                && (bytes[end].is_ascii_alphanumeric() || matches!(bytes[end], b'.' | b'-'))
            {
                end += 1;
            }
            let next_ok = end == bytes.len()
                || !(bytes[end].is_ascii_alphanumeric()
                    || matches!(bytes[end], b'.' | b'_' | b'-' | b'*'));
            if next_ok {
                let candidate = &fragment[i..end];
                if is_redactable_upstream_domain(candidate) {
                    out.push_str(&redact_bare_host_or_ipv4(candidate));
                    i = end;
                    continue;
                }
            }
        }

        if let Some(ch) = fragment[i..].chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }

    out
}

/// Mask non-allowlisted upstream proxy domains exposed inside dial/connect error logs
/// (e.g. `dial tcp hk01.demo-vendor.com:443: i/o timeout` -> `dial tcp ***.com:443: i/o timeout`)
/// while preserving safe public connectivity/DoH domains, JSON syntax, and filenames.
fn redact_dial_error_domains(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;

    while i < bytes.len() {
        if let Some(tlen) = match_dial_error_trigger(bytes, i) {
            out.push_str(&input[i..i + tlen]);
            let frag_start = i + tlen;
            let mut frag_end = frag_start;
            while frag_end < bytes.len() {
                let b = bytes[frag_end];
                if matches!(b, b'\r' | b'\n') {
                    break;
                }
                if b == b'\\' && frag_end + 1 < bytes.len() {
                    frag_end += 2;
                    continue;
                }
                if b == b'"' {
                    // Stop before closing quote of a JSON string value so sibling JSON keys stay untouched.
                    let after_q = frag_end + 1;
                    let mut ws = after_q;
                    while ws < bytes.len() && bytes[ws] == b' ' {
                        ws += 1;
                    }
                    if ws == bytes.len() || matches!(bytes[ws], b',' | b'}' | b']' | b':') {
                        break;
                    }
                }
                frag_end += 1;
            }
            let fragment = &input[frag_start..frag_end];
            out.push_str(&redact_domains_in_dial_fragment(fragment));
            i = frag_end;
            continue;
        }

        if let Some(ch) = input[i..].chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn safe_public_dns_allowlist_matches_all_19_entries_and_local_ranges() {
        assert_eq!(SAFE_PUBLIC_DNS_IPV4S.len(), 19);
        // Only loopback (127.0.0.1) and unspecified (0.0.0.0) are exempted.
        assert!(is_safe_dns_or_local_ipv4([127, 0, 0, 1]));
        assert!(is_safe_dns_or_local_ipv4([0, 0, 0, 0]));

        // Public DNS resolvers are no longer exempted and must be masked to A.B.C.*.
        for dns in SAFE_PUBLIC_DNS_IPV4S {
            let ip = Ipv4Addr::from_str(dns).expect("valid allowlist DNS IPv4");
            assert!(
                !is_safe_dns_or_local_ipv4(ip.octets()),
                "DNS {dns} must be masked in strict sanitization"
            );
        }

        // Private ranges (including 198.18.0.0/15 Fake-IP, 169.254.*, LAN) and arbitrary public IPv4 must be redacted.
        for masked in [
            [198, 18, 0, 1],
            [198, 19, 255, 254],
            [192, 168, 1, 10],
            [10, 0, 0, 5],
            [172, 16, 8, 9],
            [169, 254, 10, 20],
            [100, 64, 1, 2],
            [192, 0, 2, 10],
            [198, 51, 100, 20],
            [203, 0, 113, 30],
        ] {
            assert!(
                !is_safe_dns_or_local_ipv4(masked),
                "IPv4 {masked:?} must not be exempted"
            );
        }
    }

    #[test]
    fn sanitize_log_line_covers_credentials_uris_paths_json_and_ips() {
        let raw = concat!(
            "2026-11-25T08:15:00Z https://alice:pw123@sub.example.invalid/api?token=tk_99&refresh_token=rt_88&client_secret=cs_77&access_token=at_66&passphrase=pp_55 ",
            "obfs_password=op_44 cookie: ck_33 psk=psk_22 pbk=pbk_11 sid=sid_00 x-api-key: xk_01 ",
            "Authorization: Bearer jwt_secret_token ",
            "vmess", "://eyJhZGQiOiIxOTguNTEuMTAwLjEifQ==#HK ",
            "ss", "://YWVzOjEyMw==#SG ",
            "mmrelay://v1/eyJzZXJ2ZXIiOiIyMDMuMC4xMTMuMTAifQ== ",
            "dns 1.1.1.1 8.8.8.8 223.5.5.5 119.29.29.29 114.114.114.114 127.0.0.1 0.0.0.0 198.18.0.12 ",
            "mask 203.0.113.45 192.168.10.25 [240e:390:1234:5678::42]:443 ::1 ::"
        );
        let clean = sanitize_log_line(raw);

        for leaked in [
            "alice:pw123",
            "tk_99",
            "rt_88",
            "cs_77",
            "at_66",
            "pp_55",
            "op_44",
            "ck_33",
            "psk_22",
            "pbk_11",
            "sid_00",
            "xk_01",
            "jwt_secret_token",
            "eyJhZGQiOiIxOTguNTEuMTAwLjEifQ==",
            "YWVzOjEyMw==",
            "eyJzZXJ2ZXIiOiIyMDMuMC4xMTMuMTAifQ==",
            "1.1.1.1",
            "8.8.8.8",
            "223.5.5.5",
            "119.29.29.29",
            "114.114.114.114",
            "198.18.0.12",
            "203.0.113.45",
            "192.168.10.25",
            "5678::42",
        ] {
            assert!(!clean.contains(leaked), "leaked `{leaked}` in: {clean}");
        }

        assert!(clean.contains("https://<REDACTED>@sub.example.invalid/api?token=<REDACTED>&refresh_token=<REDACTED>&client_secret=<REDACTED>&access_token=<REDACTED>&passphrase=<REDACTED>"));
        assert!(clean.contains("obfs_password=<REDACTED>"));
        assert!(clean.contains("cookie: <REDACTED>"));
        assert!(clean.contains("psk=<REDACTED>"));
        assert!(clean.contains("pbk=<REDACTED>"));
        assert!(clean.contains("sid=<REDACTED>"));
        assert!(clean.contains("x-api-key: <REDACTED>"));
        assert!(clean.contains("Authorization: Bearer <REDACTED>"));
        assert!(clean.contains("vmess://<REDACTED>#HK"));
        assert!(clean.contains("ss://<REDACTED>#SG"));
        assert!(clean.contains("mmrelay://v1/<REDACTED>"));
        assert!(clean.contains("1.1.1.* 8.8.8.* 223.5.5.* 119.29.29.* 114.114.114.* 127.0.0.1 0.0.0.0 198.18.0.*"));
        assert!(clean.contains("203.0.113.*"));
        assert!(clean.contains("192.168.10.*"));
        assert!(clean.contains("[240e:390::*]:443"));
        assert!(clean.contains("::1"));
        assert!(clean.contains(" ::"));
        assert!(clean.contains("2026-11-25T08:15:00Z"));
        assert_eq!(sanitize_log_line(&clean), clean);
    }

    #[test]
    fn sanitize_log_line_handles_spaced_chinese_paths_non_system_drives_and_json_escapes() {
        let raw = concat!(
            r#"{"password":"a\"b\\c","secret":9988,"path":"C:\\Users\\张三 同学\\AppData\\Local\\CatCloud","unix":"/"#,
            r#"home/alice_dev/.config/catcloud","portable":"D:\\Private Space\\CatCloud\\bin","ok":true}"#
        );
        let clean = sanitize_log_line(raw);
        let parsed: serde_json::Value =
            serde_json::from_str(&clean).expect("sanitized JSON must remain valid JSON");
        assert_eq!(parsed["password"], "<REDACTED>");
        assert_eq!(parsed["secret"], "<REDACTED>");
        assert_eq!(parsed["path"], r"C:\Users\<USER>\AppData\Local\CatCloud");
        assert_eq!(parsed["unix"], "/home/<USER>/.config/catcloud");
        assert_eq!(parsed["portable"], "<LOCAL_PATH>/bin");
        assert_eq!(parsed["ok"], true);
        assert_eq!(sanitize_log_line(&clean), clean);
    }

    #[test]
    fn redact_ip_or_host_and_path_for_display_are_thorough_and_idempotent() {
        assert_eq!(redact_ip_or_host("203.0.113.10"), "203.0.113.*");
        assert_eq!(redact_ip_or_host("203.0.113.10:443"), "203.0.113.*:443");
        assert_eq!(redact_ip_or_host("192.168.1.9"), "192.168.1.*");
        assert_eq!(redact_ip_or_host("198.18.0.1"), "198.18.0.*");
        assert_eq!(redact_ip_or_host("127.0.0.1:7890"), "127.0.0.1:7890");
        assert_eq!(redact_ip_or_host("0.0.0.0"), "0.0.0.0");
        assert_eq!(redact_ip_or_host("223.5.5.5"), "223.5.5.*");
        assert_eq!(redact_ip_or_host("240e:390:1234::42"), "240e:390::*");
        assert_eq!(redact_ip_or_host("[240e:390:1234::42]:443"), "[240e:390::*]:443");
        assert_eq!(redact_ip_or_host("::1"), "::1");
        assert_eq!(redact_ip_or_host("::"), "::");
        assert_eq!(redact_ip_or_host("localhost:9090"), "localhost:9090");
        assert_eq!(redact_ip_or_host("hk-01.private-vendor.example.com"), "***.com");
        assert_eq!(redact_ip_or_host("hk-01.private-vendor.net:8443"), "***.net:8443");
        assert_eq!(redact_ip_or_host("internal-box"), "<REDACTED>");

        // Idempotency
        for sample in [
            "203.0.113.*",
            "223.5.5.*",
            "[240e:390::*]:443",
            "***.com:443",
            "<REDACTED>",
        ] {
            assert_eq!(redact_ip_or_host(sample), sample);
        }

        assert_eq!(
            redact_path_for_display(concat!(r"C:\", r"Users\John Doe\AppData\Roaming\CatCloud")),
            r"C:\Users\<USER>\AppData\Roaming\CatCloud"
        );
        assert_eq!(
            redact_path_for_display(concat!(r"C:\", r"Users\John Doe")),
            r"C:\Users\<USER>"
        );
        assert_eq!(
            redact_path_for_display(r"D:\My Secret Folder\CatCloudPortable\bin"),
            "<LOCAL_PATH>/bin"
        );
        assert_eq!(
            redact_path_for_display(r"E:\Private\sub.yaml"),
            "<LOCAL_PATH>"
        );
        assert_eq!(
            redact_path_for_display(concat!("/", "Users/Alice Smith/Library/Logs")),
            "/Users/<USER>/Library/Logs"
        );
    }

    #[test]
    fn redact_relay_and_node_strip_servers_and_all_credential_keys() {
        let relay = PreAccelRelay {
            id: "relay-1".into(),
            name: "CN-East Primary".into(),
            provider: "cloud-a".into(),
            region: "CN-East".into(),
            server: "203.0.113.10".into(),
            port: 443,
            protocol: "anytls".into(),
            password: "super_secret_relay_pw".into(),
            sni: None,
            skip_cert_verify: true,
            priority: 10,
            expires_at: Some("2027-08-12".into()),
            enabled: true,
            last_probe_ms: Some(18.5),
            last_mbps: Some(220.0),
            last_up_mbps: Some(165.0),
            last_down_mbps: Some(220.0),
            ..Default::default()
        };
        let safe_relay = redact_relay_for_readonly(&relay);
        assert_eq!(safe_relay.id, "relay-1");
        assert_eq!(safe_relay.name, "CN-East Primary");
        assert_eq!(safe_relay.port, 443);
        assert_eq!(safe_relay.server, "203.0.113.*");
        assert_eq!(safe_relay.password, "<REDACTED>");
        assert_eq!(safe_relay.last_up_mbps, Some(165.0));
        assert_eq!(safe_relay.last_down_mbps, Some(220.0));

        let node = ProxyNode {
            id: "node-1".into(),
            sub_id: "sub-1".into(),
            name: "JP-01".into(),
            protocol: "vless".into(),
            server: "jp01.secret-provider.com".into(),
            port: 443,
            raw_config: json!({
                "name": "JP-01",
                "type": "vless",
                "server": "198.51.100.88",
                "port": 443,
                "uuid": "11111111-2222-3333-4444-555555555555",
                "password": "node_pw",
                "token": "tok_val",
                "private-key": "wg_priv",
                "auth-str": "hy_auth",
                "obfs-password": "hy_obfs",
                "psk": "psk_val",
                "pbk": "pbk_val",
                "sid": "sid_val",
                "secret": "sec_val",
                "username": "socks_user",
                "reality-opts": {
                    "public-key": "real_pub",
                    "short-id": "a1b2c3"
                },
                "ws-opts": {
                    "path": "/ws?token=ws_tok_99"
                }
            }),
            ..Default::default()
        };
        let safe_node = redact_node_for_readonly(&node);
        assert_eq!(safe_node.server, "***.com");
        assert_eq!(safe_node.raw_config["server"], "198.51.100.*");
        for key in [
            "uuid",
            "password",
            "token",
            "private-key",
            "auth-str",
            "obfs-password",
            "psk",
            "pbk",
            "sid",
            "secret",
            "username",
        ] {
            assert_eq!(safe_node.raw_config[key], "<REDACTED>", "key `{key}`");
        }
        assert_eq!(safe_node.raw_config["reality-opts"]["public-key"], "<REDACTED>");
        assert_eq!(safe_node.raw_config["reality-opts"]["short-id"], "<REDACTED>");
        assert_eq!(safe_node.raw_config["ws-opts"]["path"], "/ws?token=<REDACTED>");
    }

    #[test]
    fn redact_compiled_yaml_masks_secrets_servers_and_keeps_valid_yaml() {
        let yaml = r#"mixed-port: 7890
external-controller: 127.0.0.1:9090
secret: 0123456789abcdef0123456789abcdef
dns:
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  nameserver:
    - https://223.5.5.5/dns-query
    - https://1.12.12.12/dns-query
  fallback:
    - https://1.1.1.1/dns-query
    - https://8.8.8.8/dns-query
  fake-ip-range: 198.18.0.1/16
proxies:
  - name: "Relay-1"
    type: anytls
    server: 203.0.113.10
    port: 443
    sni: relay-sni.vendor-cloud.net
    password: "relay_secret_pw"
  - name: "Node-Domain"
    type: socks5
    server: hk1.vendor-domain.org
    servername: tls.vendor-edge.com
    port: 1080
    username: demo_user
    password: demo_password
    ws-opts:
      headers:
        Host: ws.vendor-front.io
    h2-opts:
      host: [h2a.vendor-h2.com, h2b.vendor-h2.org]
  - {name: "Node-Flow", type: vless, server: 198.51.100.77, sni: flow.vendor-sni.net, port: 443, uuid: "aaa-bbb-ccc", pbk: "pub_k", sid: "abcd"}
rules:
  - IP-CIDR,203.0.113.10/32,DIRECT,no-resolve
  - DOMAIN-SUFFIX,openai.com,AI
"#;
        let clean = redact_compiled_yaml(yaml);
        for leaked in [
            "0123456789abcdef",
            "203.0.113.10",
            "223.5.5.5",
            "1.1.1.1",
            "198.18.0.1",
            "relay_secret_pw",
            "vendor-domain",
            "vendor-cloud",
            "vendor-edge",
            "vendor-front",
            "vendor-h2",
            "vendor-sni",
            "demo_user",
            "demo_password",
            "198.51.100.77",
            "aaa-bbb-ccc",
            "pub_k",
            "abcd",
        ] {
            assert!(!clean.contains(leaked), "leaked `{leaked}` in:\n{clean}");
        }

        assert!(clean.contains("127.0.0.1:9090"));
        assert!(clean.contains("223.5.5.*"));
        assert!(clean.contains("1.1.1.*"));
        assert!(clean.contains("198.18.0.*/16"));
        assert!(clean.contains("server: 203.0.113.*"));
        assert!(clean.contains("server: \"***.org\""));
        assert!(clean.contains("sni: \"***.net\""));
        assert!(clean.contains("servername: \"***.com\""));
        assert!(clean.contains("Host: \"***.io\""));
        assert!(clean.contains("host: [\"***.com\", \"***.org\"]"));
        assert!(clean.contains("username: <REDACTED>"));
        assert!(clean.contains("IP-CIDR,203.0.113.*/32,DIRECT,no-resolve"));
        assert!(clean.contains("DOMAIN-SUFFIX,openai.com,AI"));

        // Verify the redacted output remains syntactically valid YAML.
        let parsed: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&clean).expect("redacted YAML must remain valid YAML");
        assert_eq!(parsed["secret"], serde_yaml_ng::Value::String("<REDACTED>".into()));
    }

    #[test]
    fn sanitize_log_line_masks_dial_and_connect_error_upstream_domains_only() {
        let raw_dial = "2026-11-26T01:00:00Z WARN [proxy] dial tcp hk01.demo-vendor.com:443: i/o timeout";
        let clean_dial = sanitize_log_line(raw_dial);
        assert_eq!(
            clean_dial,
            "2026-11-26T01:00:00Z WARN [proxy] dial tcp ***.com:443: i/o timeout"
        );
        assert_eq!(sanitize_log_line(&clean_dial), clean_dial);

        let raw_udp = "ERROR dial udp [sg-edge.test-relay.net]:8443: connect: connection refused";
        let clean_udp = sanitize_log_line(raw_udp);
        assert_eq!(
            clean_udp,
            "ERROR dial udp [***.net]:8443: connect: connection refused"
        );

        let raw_lookup =
            "WARN dial tcp: lookup jp-02.demo-cloud.org on 223.5.5.5:53: no such host";
        let clean_lookup = sanitize_log_line(raw_lookup);
        assert_eq!(
            clean_lookup,
            "WARN dial tcp: lookup ***.org on 223.5.5.*:53: no such host"
        );

        let raw_conn_err = "ERROR connect error: us-west.demo-node.io:443: EOF";
        let clean_conn_err = sanitize_log_line(raw_conn_err);
        assert_eq!(clean_conn_err, "ERROR connect error: ***.io:443: EOF");

        // Allowlisted public connectivity/DoH domains and file extensions must stay intact.
        let raw_allowlisted =
            "WARN connect error: dial tcp cp.cloudflare.com:443: timeout (see config.json)";
        let clean_allowlisted = sanitize_log_line(raw_allowlisted);
        assert!(clean_allowlisted.contains("cp.cloudflare.com:443"));
        assert!(clean_allowlisted.contains("config.json"));

        // JSON structure must remain valid when a dial error appears inside a JSON string field.
        let raw_json = r#"{"msg":"dial tcp node.demo-vendor.com:443: timeout","ok":false}"#;
        let clean_json = sanitize_log_line(raw_json);
        let parsed: serde_json::Value = serde_json::from_str(&clean_json).expect("valid JSON");
        assert_eq!(parsed["msg"], "dial tcp ***.com:443: timeout");
        assert_eq!(parsed["ok"], false);
    }

    #[test]
    fn redact_public_ipv4_handles_sentence_dot_underscore_prefix_and_protects_versions_and_oids() {
        // Sentence-ending dot preserves trailing period while redacting the IPv4.
        assert_eq!(
            sanitize_log_line("connection failed for 203.0.113.10."),
            "connection failed for 203.0.113.*."
        );
        assert_eq!(
            sanitize_log_line("peer 198.51.100.20. Retrying via 192.168.1.9."),
            "peer 198.51.100.*. Retrying via 192.168.1.*."
        );

        // Underscore-prefixed IPs are redacted.
        assert_eq!(sanitize_log_line("ip_192.168.1.1"), "ip_192.168.1.*");
        assert_eq!(
            sanitize_log_line("src_10.20.30.40 dst_172.16.5.9 fake_198.18.0.5 link_169.254.1.2"),
            "src_10.20.30.* dst_172.16.5.* fake_198.18.0.* link_169.254.1.*"
        );

        // Version strings, 5+ segment OIDs, and IP-prefixed hostnames must be preserved.
        let v1_ver = concat!("v1_", "1.2.", "3.4");
        let named_ver = concat!("version_", "1.2.", "3.4");
        let eq_ver = concat!("version=", "1.2.", "3.4");
        let core_ver_json = concat!(r#"{"core_version":""#, "1.19.", r#"1.0","v":"v"#, "1.2.", r#"3.4"}"#);
        assert_eq!(sanitize_log_line(v1_ver), v1_ver);
        assert_eq!(sanitize_log_line(named_ver), named_ver);
        assert_eq!(sanitize_log_line(eq_ver), eq_ver);
        assert_eq!(sanitize_log_line(core_ver_json), core_ver_json);
        assert_eq!(sanitize_log_line("oid 1.3.6.1.5.5.7.3.1"), "oid 1.3.6.1.5.5.7.3.1");
        assert_eq!(
            sanitize_log_line("host 203.0.113.10.example.com"),
            "host 203.0.113.10.example.com"
        );
    }

    #[test]
    fn sanitize_json_value_preserves_business_domains_and_metadata_while_redacting_ips_and_paths() {
        let ver_a = concat!("1.19.", "1.0");
        let ver_b = concat!("1.19.", "2.3");
        let ver_c = concat!("4.0.", "0.1");
        let win_home = concat!(r"C:\", r"Users\Alice Smith\AppData\Local\CatCloud");
        let unix_home = concat!("/", "home/bob_dev/.config/catcloud/config.json");

        let mut payload = json!({
            "ok": true,
            "sanitized": true,
            "count": 42,
            "id": "conn-203.0.113.10-keep",
            "version": ver_a,
            "core_version": ver_b,
            "schema_version": ver_c,
            "sha256": "deadbeef0123456789",
            "config_sha256": "cafebabe0123456789",
            "instance_hash": "a1b2c3d4",
            "tested_at": "2026-11-26T03:44:51Z",
            "started_at": "2026-11-26T03:40:00Z",
            "controller_addr": "127.0.0.1:9090",
            "data_dir": win_home,
            "cli_path": r"D:\PrivatePortable\CatCloud\bin\catcloud.exe",
            "binary_path": r"E:\SecretDir\mihomo.exe",
            "config_path": unix_home,
            "upstream": {
                "server": "edge01.vendor-relay.net",
                "sni": "sni.vendor-relay.com",
                "servername": "tls.vendor-relay.org",
                "controller_addr": "192.168.1.50:9090"
            },
            "connections": [
                {
                    "host": "api.openai.com",
                    "source_ip": "192.168.1.105",
                    "destination_ip": "203.0.113.55",
                    "note": "dns 223.5.5.5 and fake 198.18.0.12"
                },
                {
                    "host": "github.com",
                    "source_ip": "10.0.0.8",
                    "destination_ip": "172.16.0.9"
                },
                {
                    "host": "198.18.0.15",
                    "source_ip": "127.0.0.1",
                    "destination_ip": "240e:390:1234::42"
                },
                {
                    "host": "203.0.113.88:443",
                    "source_ip": "::1",
                    "destination_ip": "169.254.10.20"
                },
                {
                    "host": "[240e:390:abcd::99]:443"
                }
            ]
        });

        sanitize_json_value(&mut payload);

        // Numbers, booleans, and allowlisted metadata keys remain intact.
        assert_eq!(payload["ok"], true);
        assert_eq!(payload["count"], 42);
        assert_eq!(payload["id"], "conn-203.0.113.10-keep");
        assert_eq!(payload["version"], ver_a);
        assert_eq!(payload["core_version"], ver_b);
        assert_eq!(payload["schema_version"], ver_c);
        assert_eq!(payload["sha256"], "deadbeef0123456789");
        assert_eq!(payload["config_sha256"], "cafebabe0123456789");
        assert_eq!(payload["instance_hash"], "a1b2c3d4");
        assert_eq!(payload["tested_at"], "2026-11-26T03:44:51Z");
        assert_eq!(payload["started_at"], "2026-11-26T03:40:00Z");

        // Loopback controller preserved, LAN controller masked.
        assert_eq!(payload["controller_addr"], "127.0.0.1:9090");
        assert_eq!(payload["upstream"]["controller_addr"], "192.168.1.*:9090");

        // Upstream proxy server/sni/servername masked to ***.tld.
        assert_eq!(payload["upstream"]["server"], "***.net");
        assert_eq!(payload["upstream"]["sni"], "***.com");
        assert_eq!(payload["upstream"]["servername"], "***.org");

        // Paths redacted via redact_path_for_display.
        assert_eq!(
            payload["data_dir"],
            r"C:\Users\<USER>\AppData\Local\CatCloud"
        );
        assert_eq!(payload["cli_path"], "<LOCAL_PATH>");
        assert_eq!(payload["binary_path"], "<LOCAL_PATH>");
        assert_eq!(payload["config_path"], "/home/<USER>/.config/catcloud/config.json");

        // Business domains under plain `host` preserved; IP literals under `host` masked.
        assert_eq!(payload["connections"][0]["host"], "api.openai.com");
        assert_eq!(payload["connections"][0]["source_ip"], "192.168.1.*");
        assert_eq!(payload["connections"][0]["destination_ip"], "203.0.113.*");
        assert_eq!(
            payload["connections"][0]["note"],
            "dns 223.5.5.* and fake 198.18.0.*"
        );
        assert_eq!(payload["connections"][1]["host"], "github.com");
        assert_eq!(payload["connections"][1]["source_ip"], "10.0.0.*");
        assert_eq!(payload["connections"][1]["destination_ip"], "172.16.0.*");
        assert_eq!(payload["connections"][2]["host"], "198.18.0.*");
        assert_eq!(payload["connections"][2]["source_ip"], "127.0.0.1");
        assert_eq!(payload["connections"][2]["destination_ip"], "240e:390::*");
        assert_eq!(payload["connections"][3]["host"], "203.0.113.*:443");
        assert_eq!(payload["connections"][3]["source_ip"], "::1");
        assert_eq!(payload["connections"][3]["destination_ip"], "169.254.10.*");
        assert_eq!(payload["connections"][4]["host"], "[240e:390::*]:443");

        // Idempotent when applied twice.
        let snapshot = payload.clone();
        sanitize_json_value(&mut payload);
        assert_eq!(payload, snapshot);
    }

    #[test]
    fn redact_node_for_readonly_masks_sni_servername_plugin_host_and_ws_host() {
        let node = ProxyNode {
            id: "node-sni-1".into(),
            sub_id: "sub-demo".into(),
            name: "Demo-SNI".into(),
            protocol: "vless".into(),
            server: "edge01.demo-provider.net".into(),
            port: 443,
            raw_config: json!({
                "name": "Demo-SNI",
                "type": "vless",
                "server": "edge01.demo-provider.net",
                "port": 443,
                "uuid": "00000000-0000-4000-8000-000000000001",
                "sni": "sni.demo-upstream.com",
                "servername": "tls.demo-upstream.org",
                "plugin-opts": {
                    "mode": "websocket",
                    "host": "cdn.demo-plugin.io"
                },
                "ws-opts": {
                    "path": "/ws",
                    "headers": {
                        "Host": "ws.demo-front.net"
                    }
                },
                "h2-opts": {
                    "host": ["h2a.demo-front.com", "h2b.demo-front.org"]
                }
            }),
            ..ProxyNode::default()
        };

        let safe = redact_node_for_readonly(&node);
        assert_eq!(safe.server, "***.net");
        assert_eq!(safe.raw_config["server"], "***.net");
        assert_eq!(safe.raw_config["sni"], "***.com");
        assert_eq!(safe.raw_config["servername"], "***.org");
        assert_eq!(safe.raw_config["plugin-opts"]["host"], "***.io");
        assert_eq!(safe.raw_config["plugin-opts"]["mode"], "websocket");
        assert_eq!(safe.raw_config["ws-opts"]["headers"]["Host"], "***.net");
        assert_eq!(safe.raw_config["ws-opts"]["path"], "/ws");
        assert_eq!(
            safe.raw_config["h2-opts"]["host"],
            json!(["***.com", "***.org"])
        );

        let serialized = serde_json::to_string(&safe).unwrap();
        for leaked in [
            "demo-provider",
            "demo-upstream",
            "demo-plugin",
            "demo-front",
        ] {
            assert!(!serialized.contains(leaked), "leaked `{leaked}` in {serialized}");
        }
    }

    #[test]
    fn redact_path_for_display_masks_long_numeric_account_directories() {
        let qq_path = concat!(
            r"C:\",
            r"Users\Administrator\Documents\Tencent Files\0000001234\nt_qq\QQ.exe"
        );
        assert_eq!(
            redact_path_for_display(qq_path),
            r"C:\Users\<USER>\Documents\Tencent Files\***\nt_qq\QQ.exe"
        );

        let prefixed_acct = concat!(
            r"C:\",
            r"Users\Administrator\AppData\Roaming\DemoGame\uid_0000998877\bin\launcher.exe"
        );
        assert_eq!(
            redact_path_for_display(prefixed_acct),
            r"C:\Users\<USER>\AppData\Roaming\DemoGame\uid_***\bin\launcher.exe"
        );

        let unix_acct = concat!("/", "Users/catcloud/Library/Containers/0000123456/Data/app");
        assert_eq!(
            redact_path_for_display(unix_acct),
            "/Users/<USER>/Library/Containers/***/Data/app"
        );

        // Short numeric segments (< 6 digits) and filenames with version numbers must be preserved.
        let normal_path = r"C:\Program Files\CatCloud\v12345\bin\catcloud-20261126.exe";
        assert_eq!(redact_path_for_display(normal_path), normal_path);

        // Idempotent when called twice.
        let once = redact_path_for_display(qq_path);
        assert_eq!(redact_path_for_display(&once), once);
    }

    #[test]
    fn sanitize_json_value_redacts_all_node_credential_keys_and_numeric_secrets() {
        let mut payload = json!({
            "token": "tok_secret_1",
            "uuid": "11111111-2222-3333-4444-555555555555",
            "pwd": "pwd_secret_2",
            "auth": "auth_secret_3",
            "auth_str": "auth_str_4",
            "auth-str": "auth-str-5",
            "psk": "psk_secret_6",
            "pbk": "pbk_secret_7",
            "sid": "sid_secret_8",
            "cookie": "session=abc123",
            "set-cookie": "session=xyz789; HttpOnly",
            "apikey": "ak_secret_9",
            "public_key": "pub_key_10",
            "public-key": "pub-key-11",
            "short_id": "short_12",
            "short-id": "short-13",
            "username": "proxy_user_14",
            "nested": {
                "password": 987654321,
                "secret": 424242,
                "token": 13579,
                "short-id": 8080,
                "port": 443
            }
        });

        sanitize_json_value(&mut payload);

        for key in [
            "token",
            "uuid",
            "pwd",
            "auth",
            "auth_str",
            "auth-str",
            "psk",
            "pbk",
            "sid",
            "cookie",
            "set-cookie",
            "apikey",
            "public_key",
            "public-key",
            "short_id",
            "short-id",
            "username",
        ] {
            assert_eq!(
                payload[key], "<REDACTED>",
                "expected credential key `{key}` to be redacted"
            );
        }
        assert_eq!(payload["nested"]["password"], "<REDACTED>");
        assert_eq!(payload["nested"]["secret"], "<REDACTED>");
        assert_eq!(payload["nested"]["token"], "<REDACTED>");
        assert_eq!(payload["nested"]["short-id"], "<REDACTED>");
        assert_eq!(payload["nested"]["port"], 443);

        // Idempotent when applied twice.
        let snapshot = payload.clone();
        sanitize_json_value(&mut payload);
        assert_eq!(payload, snapshot);
    }

    #[test]
    fn redact_compiled_yaml_handles_block_sequences_and_extra_host_keys_as_valid_yaml() {
        let yaml = r#"mixed-port: 7890
external-controller: 127.0.0.1:9090
secret: secret_block_test_0123456789
proxies:
  - name: "Node-Block-Host"
    type: vmess
    server: edge.vendor-origin.net
    port: 443
    server-name: sni-dash.vendor-tls.com
    server_name: sni-under.vendor-tls.org
    obfs_host: obfs.vendor-obfs.io
    h2-opts:
      host:
        - h2a.vendor.com
        - "h2b.vendor.org"
        - 'h2c.vendor.net'
        - 203.0.113.42
        - h2d.vendor.io # keep comment
      path: /h2
    ws-opts:
      headers:
        "Host":
          - ws1.vendor-ws.com
          - ws2.vendor-ws.net

    extra-list:
      - keep.business-domain.com
rules:
  - DOMAIN-SUFFIX,github.com,DIRECT
"#;

        let clean = redact_compiled_yaml(yaml);
        for leaked in [
            "secret_block_test",
            "vendor-origin",
            "vendor-tls",
            "vendor-obfs",
            "h2a.vendor",
            "h2b.vendor",
            "h2c.vendor",
            "203.0.113.42",
            "h2d.vendor",
            "vendor-ws",
        ] {
            assert!(!clean.contains(leaked), "leaked `{leaked}` in:\n{clean}");
        }

        // Must remain syntactically valid YAML (no unquoted `*` alias errors).
        let parsed: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&clean).expect("redacted block-sequence YAML must parse");
        let proxy = &parsed["proxies"][0];
        assert_eq!(proxy["server"].as_str(), Some("***.net"));
        assert_eq!(proxy["server-name"].as_str(), Some("***.com"));
        assert_eq!(proxy["server_name"].as_str(), Some("***.org"));
        assert_eq!(proxy["obfs_host"].as_str(), Some("***.io"));

        let h2_hosts: Vec<&str> = proxy["h2-opts"]["host"]
            .as_sequence()
            .expect("h2-opts.host sequence")
            .iter()
            .filter_map(serde_yaml_ng::Value::as_str)
            .collect();
        assert_eq!(
            h2_hosts,
            vec!["***.com", "***.org", "***.net", "203.0.113.*", "***.io"]
        );
        assert_eq!(proxy["h2-opts"]["path"].as_str(), Some("/h2"));

        let ws_hosts: Vec<&str> = proxy["ws-opts"]["headers"]["Host"]
            .as_sequence()
            .expect("ws-opts.headers.Host sequence")
            .iter()
            .filter_map(serde_yaml_ng::Value::as_str)
            .collect();
        assert_eq!(ws_hosts, vec!["***.com", "***.net"]);

        // Exiting block-sequence state on blank line / shallower indent leaves later lists intact.
        assert_eq!(
            proxy["extra-list"][0].as_str(),
            Some("keep.business-domain.com")
        );

        // Idempotent on second pass.
        assert_eq!(redact_compiled_yaml(&clean), clean);
    }

    #[test]
    fn redact_single_quoted_yaml_secrets_handles_doubled_quotes_and_trailing_backslash() {
        let yaml = concat!(
            "secret: 'top''secret'\n",
            "proxies:\n",
            "  - name: Node-SingleQuote\n",
            "    type: anytls\n",
            "    server: edge.vendor-sq.example\n",
            "    port: 443\n",
            "    password: 'alpha_sq''beta_sq'\n",
            "    token: 'abc_sq\\'\n",
            "    username: 'u_sq''gamma_sq\\'\n",
            "    auth: ''''\n",
            "    uuid: \"dbl_sq\\\"quote_sq\\\\\"\n",
        );

        let clean = redact_compiled_yaml(yaml);
        for leaked in ["top", "secret'", "alpha_sq", "beta_sq", "abc_sq", "u_sq", "gamma_sq", "dbl_sq", "quote_sq", "vendor-sq"] {
            assert!(
                !clean.contains(leaked),
                "single-quoted YAML secret leaked `{leaked}` in:\n{clean}"
            );
        }

        let parsed: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&clean).expect("redacted single-quoted YAML must remain valid");
        assert_eq!(parsed["secret"].as_str(), Some("<REDACTED>"));
        let proxy = &parsed["proxies"][0];
        assert_eq!(proxy["password"].as_str(), Some("<REDACTED>"));
        assert_eq!(proxy["token"].as_str(), Some("<REDACTED>"));
        assert_eq!(proxy["username"].as_str(), Some("<REDACTED>"));
        assert_eq!(proxy["auth"].as_str(), Some("<REDACTED>"));
        assert_eq!(proxy["uuid"].as_str(), Some("<REDACTED>"));
        assert_eq!(proxy["server"].as_str(), Some("***.example"));
        assert_eq!(proxy["port"].as_u64(), Some(443));

        // Direct sanitize_log_line checks for doubled single-quotes and trailing backslash.
        assert_eq!(
            sanitize_log_line("password: 'pass''word' next=ok"),
            "password: '<REDACTED>' next=ok"
        );
        assert_eq!(
            sanitize_log_line("password: 'abc\\' next=ok"),
            "password: '<REDACTED>' next=ok"
        );
    }

    #[test]
    fn redacts_wireguard_peer_endpoint_in_compiled_yaml_and_readonly_node() {
        let yaml = concat!(
            "proxies:\n",
            "  - name: WG-01\n",
            "    type: wireguard\n",
            "    server: wg.private-corp.example\n",
            "    port: 51820\n",
            "    private-key: wg-secret-priv\n",
            "    peers:\n",
            "      - endpoint: peer.private-corp.example:51820\n",
            "        public-key: wg-secret-pub\n",
        );
        let clean = redact_compiled_yaml(yaml);
        assert!(!clean.contains("private-corp"));
        assert!(!clean.contains("wg-secret-priv"));
        assert!(!clean.contains("wg-secret-pub"));
        let parsed: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&clean).expect("valid redacted wireguard YAML");
        assert_eq!(
            parsed["proxies"][0]["peers"][0]["endpoint"].as_str(),
            Some("***.example:51820")
        );

        let node = ProxyNode {
            id: "wg1".to_string(),
            sub_id: "sub1".to_string(),
            name: "WG-01".to_string(),
            protocol: "wireguard".to_string(),
            server: "wg.private-corp.example".to_string(),
            port: 51820,
            raw_config: serde_json::json!({
                "type": "wireguard",
                "server": "wg.private-corp.example",
                "peers": [{ "endpoint": "peer.private-corp.example:51820" }]
            }),
            ..Default::default()
        };
        let redacted_node = redact_node_for_readonly(&node);
        assert_eq!(
            redacted_node.raw_config["peers"][0]["endpoint"].as_str(),
            Some("***.example:51820")
        );
    }
}
