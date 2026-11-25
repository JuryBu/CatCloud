use crate::models::{PreAccelRelay, ProxyNode};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Public DNS IPv4 allowlist aligned with `scripts/ci/check_public_sanitization.mjs`.
/// These well-known public resolvers are preserved verbatim during log/CLI sanitization.
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

/// Returns `true` strictly for loopback (`127.0.0.1`), unspecified (`0.0.0.0`),
/// Mihomo Fake-IP range (`198.18.0.0/15`), and the 19 allowlisted public DNS IPv4s.
/// All other public and private IPv4 addresses are masked to `A.B.C.*`.
pub fn is_safe_dns_or_local_ipv4(octets: [u8; 4]) -> bool {
    matches!(
        octets,
        [127, 0, 0, 1]
            | [0, 0, 0, 0]
            | [198, 18 | 19, _, _]
            | [1, 1, 1, 1]
            | [1, 0, 0, 1]
            | [8, 8, 8, 8]
            | [8, 8, 4, 4]
            | [9, 9, 9, 9]
            | [149, 112, 112, 112]
            | [223, 5, 5, 5]
            | [223, 6, 6, 6]
            | [119, 29, 29, 29]
            | [119, 28, 28, 28]
            | [1, 12, 12, 12]
            | [120, 53, 53, 53]
            | [114, 114, 114, 114]
            | [114, 114, 115, 115]
            | [180, 76, 76, 76]
            | [180, 184, 1, 1]
            | [180, 184, 2, 2]
            | [1, 2, 4, 8]
            | [210, 2, 4, 8]
    )
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
/// - Masks private, CGNAT, link-local, ULA, and public IPv4/IPv6 addresses, only exempting
///   `127.0.0.1`, `0.0.0.0`, `198.18.0.0/15`, `::1`, `::`, and `SAFE_PUBLIC_DNS_IPV4S`
///   without touching timestamps (`HH:MM:SS`)
pub fn sanitize_log_line(raw: &str) -> String {
    let step1 = redact_url_userinfo(raw);
    let step2 = redact_bearer_tokens(&step1);
    let step3 = redact_sensitive_key_values(&step2);
    let step4 = redact_user_home_paths(&step3);
    let step5 = redact_non_system_drive_paths(&step4);
    let step6 = redact_public_ipv4(&step5);
    redact_public_ipv6(&step6)
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
            return format!(
                "{verbatim_prefix}{}<USER>{rest_after_user}",
                &body[..plen]
            );
        }
    }

    let step1 = redact_user_home_paths(body);
    let step2 = redact_non_system_drive_paths(&step1);
    if verbatim_prefix.is_empty() || step2.starts_with("<LOCAL_PATH>") {
        step2
    } else {
        format!("{verbatim_prefix}{step2}")
    }
}

/// Return a sanitized read-only clone of `PreAccelRelay`:
/// preserves id, name, provider, region, protocol, port, priority, expires_at, enabled, metrics,
/// while masking `server` (via `redact_ip_or_host`) and `password` (`<REDACTED>`).
pub fn redact_relay_for_readonly(relay: &PreAccelRelay) -> PreAccelRelay {
    let mut out = relay.clone();
    out.server = redact_ip_or_host(&relay.server);
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

fn redact_json_node_value(val: &mut serde_json::Value) {
    match val {
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if k.eq_ignore_ascii_case("server") {
                    if let serde_json::Value::String(s) = v {
                        *s = redact_ip_or_host(s);
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
/// masks `server` and recursively redacts all credential keys (`password`, `uuid`, `token`,
/// `private-key`, `auth-str`, `obfs-password`, `psk`, `pbk`, `sid`, `secret`, `username`, etc.)
/// and `server` inside `raw_config`.
pub fn redact_node_for_readonly(node: &ProxyNode) -> ProxyNode {
    let mut out = node.clone();
    out.server = redact_ip_or_host(&node.server);
    redact_json_node_value(&mut out.raw_config);
    out
}

/// Sanitize a compiled Mihomo YAML configuration for read-only CLI/AI output:
/// - Redacts controller `secret`, proxy `server`, `username`, `password`, `uuid`, `token`,
///   `private-key`, `public-key`, `short-id`, `auth-str`, `obfs-password`, `psk`, `pbk`, `sid`
/// - Redacts local user home paths, non-system drive paths, and non-safe IPv4/IPv6 literals
/// - Preserves safe local/Fake-IP/public DNS literals and keeps output valid YAML
pub fn redact_compiled_yaml(yaml: &str) -> String {
    let mut out = String::with_capacity(yaml.len());
    for chunk in yaml.split_inclusive('\n') {
        let (line, newline) = if let Some(stripped) = chunk.strip_suffix("\r\n") {
            (stripped, "\r\n")
        } else if let Some(stripped) = chunk.strip_suffix('\n') {
            (stripped, "\n")
        } else {
            (chunk, "")
        };
        let step1 = redact_yaml_extra_fields(line);
        let step2 = sanitize_log_line(&step1);
        out.push_str(&step2);
        out.push_str(newline);
    }
    out
}

/// Redact YAML-specific `server:` (host/IP) and `username:` fields in both block and flow YAML
/// without matching `nameserver:`, `proxy-server-nameserver:`, or `servername:`.
fn redact_yaml_extra_fields(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0usize;

    while i < bytes.len() {
        let prev_ok = i == 0
            || !(bytes[i - 1].is_ascii_alphanumeric()
                || matches!(bytes[i - 1], b'_' | b'-' | b'/'));

        if prev_ok && bytes[i].is_ascii_alphabetic() {
            let mut matched_kind: Option<(&str, bool)> = None; // (key, is_server)
            for &(key, is_server) in &[("server", true), ("username", false)] {
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
                            matched_kind = Some((key, is_server));
                            let mut val_start = sep_idx + 1;
                            while val_start < bytes.len() && bytes[val_start] == b' ' {
                                val_start += 1;
                            }
                            if val_start >= bytes.len()
                                || matches!(bytes[val_start], b'{' | b'[' | b'\r' | b'\n' | b'#')
                            {
                                matched_kind = None;
                                break;
                            }

                            out.push_str(&line[i..val_start]);
                            if matches!(bytes[val_start], b'"' | b'\'') {
                                let q = bytes[val_start];
                                let qc = q as char;
                                out.push(qc);
                                let inner = &line[val_start + 1..];
                                if let Some(close_rel) = find_unescaped_quote(inner, q) {
                                    let raw_val = &inner[..close_rel];
                                    let rep = if is_server {
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
                                    let rep = if is_server {
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
                                let rep = if is_server {
                                    let masked = redact_ip_or_host(raw_val);
                                    // Quote leading `*` so redacted domains remain valid YAML scalars.
                                    if masked.starts_with('*') {
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

fn redact_public_ipv4(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;

    while i < bytes.len() {
        let prev_ok = i == 0
            || !(bytes[i - 1].is_ascii_alphanumeric()
                || bytes[i - 1] == b'.'
                || bytes[i - 1] == b'_');
        if prev_ok && bytes[i].is_ascii_digit() {
            let mut end = i;
            let mut dots = 0usize;
            while end < bytes.len() && (bytes[end].is_ascii_digit() || bytes[end] == b'.') {
                if bytes[end] == b'.' {
                    dots += 1;
                }
                end += 1;
            }
            let next_ok = end == bytes.len()
                || !(bytes[end].is_ascii_alphanumeric()
                    || bytes[end] == b'.'
                    || bytes[end] == b'_');
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn safe_public_dns_allowlist_matches_all_19_entries_and_local_ranges() {
        assert_eq!(SAFE_PUBLIC_DNS_IPV4S.len(), 19);
        for dns in SAFE_PUBLIC_DNS_IPV4S {
            let ip = Ipv4Addr::from_str(dns).expect("valid allowlist DNS IPv4");
            assert!(
                is_safe_dns_or_local_ipv4(ip.octets()),
                "DNS {dns} must be allowlisted"
            );
        }
        assert!(is_safe_dns_or_local_ipv4([127, 0, 0, 1]));
        assert!(is_safe_dns_or_local_ipv4([0, 0, 0, 0]));
        assert!(is_safe_dns_or_local_ipv4([198, 18, 0, 1]));
        assert!(is_safe_dns_or_local_ipv4([198, 19, 255, 254]));

        // Both private LAN and arbitrary public IPv4 must be redacted.
        for masked in [
            [192, 168, 1, 10],
            [10, 0, 0, 5],
            [172, 16, 8, 9],
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
            "dns 1.1.1.1 8.8.8.8 223.5.5.5 119.29.29.29 114.114.114.114 127.0.0.1 198.18.0.12 ",
            "mask 203.0.113.45 192.168.10.25 [240e:390:1234:5678::42]:443 ::1"
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
        assert!(clean.contains("1.1.1.1 8.8.8.8 223.5.5.5 119.29.29.29 114.114.114.114 127.0.0.1 198.18.0.12"));
        assert!(clean.contains("203.0.113.*"));
        assert!(clean.contains("192.168.10.*"));
        assert!(clean.contains("[240e:390::*]:443"));
        assert!(clean.contains("::1"));
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
        assert_eq!(redact_ip_or_host("127.0.0.1:7890"), "127.0.0.1:7890");
        assert_eq!(redact_ip_or_host("223.5.5.5"), "223.5.5.5");
        assert_eq!(redact_ip_or_host("240e:390:1234::42"), "240e:390::*");
        assert_eq!(redact_ip_or_host("[240e:390:1234::42]:443"), "[240e:390::*]:443");
        assert_eq!(redact_ip_or_host("::1"), "::1");
        assert_eq!(redact_ip_or_host("localhost:9090"), "localhost:9090");
        assert_eq!(redact_ip_or_host("hk-01.private-vendor.example.com"), "***.com");
        assert_eq!(redact_ip_or_host("hk-01.private-vendor.net:8443"), "***.net:8443");
        assert_eq!(redact_ip_or_host("internal-box"), "<REDACTED>");

        // Idempotency
        for sample in [
            "203.0.113.*",
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
    password: "relay_secret_pw"
  - name: "Node-Domain"
    type: socks5
    server: hk1.vendor-domain.org
    port: 1080
    username: demo_user
    password: demo_password
  - {name: "Node-Flow", type: vless, server: 198.51.100.77, port: 443, uuid: "aaa-bbb-ccc", pbk: "pub_k", sid: "abcd"}
rules:
  - IP-CIDR,203.0.113.10/32,DIRECT,no-resolve
  - DOMAIN-SUFFIX,openai.com,AI
"#;
        let clean = redact_compiled_yaml(yaml);
        for leaked in [
            "0123456789abcdef",
            "203.0.113.10",
            "relay_secret_pw",
            "vendor-domain",
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
        assert!(clean.contains("223.5.5.5"));
        assert!(clean.contains("1.1.1.1"));
        assert!(clean.contains("198.18.0.1/16"));
        assert!(clean.contains("server: 203.0.113.*"));
        assert!(clean.contains("server: \"***.org\""));
        assert!(clean.contains("username: <REDACTED>"));
        assert!(clean.contains("IP-CIDR,203.0.113.*/32,DIRECT,no-resolve"));
        assert!(clean.contains("DOMAIN-SUFFIX,openai.com,AI"));

        // Verify the redacted output remains syntactically valid YAML.
        let parsed: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&clean).expect("redacted YAML must remain valid YAML");
        assert_eq!(parsed["secret"], serde_yaml_ng::Value::String("<REDACTED>".into()));
    }
}
