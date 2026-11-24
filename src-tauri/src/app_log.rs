use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use chrono::Utc;

/// Primary persistent rotating log filename inside `paths.logs_dir`.
pub const APP_LOG_FILENAME: &str = "catcloud.log";
/// Single-file rotation threshold (2 MiB).
pub const MAX_LOG_FILE_BYTES: u64 = 2 * 1024 * 1024;
/// Number of rotated archives kept alongside `catcloud.log` (`.1`, `.2` => at most 3 files total).
pub const MAX_ROTATED_FILES: usize = 2;
/// Maximum tail bytes read per log file when collecting recent diagnostic lines.
const MAX_TAIL_READ_BYTES: u64 = 256 * 1024;
/// Prefix stamped on application-level events pushed into `CoreTelemetryStore` so the Mihomo
/// stream forwarder can skip writing them to disk a second time.
pub const APP_EVENT_PREFIX: &str = "[应用/";

/// Lightweight zero-dependency persistent rotating file logger for CatCloud desktop.
#[derive(Debug)]
pub struct RotatingAppLogger {
    log_dir: PathBuf,
    max_bytes: u64,
    write_lock: Mutex<()>,
}

impl RotatingAppLogger {
    pub fn new(log_dir: PathBuf) -> Self {
        Self::with_max_bytes(log_dir, MAX_LOG_FILE_BYTES)
    }

    pub fn with_max_bytes(log_dir: PathBuf, max_bytes: u64) -> Self {
        Self {
            log_dir,
            max_bytes: max_bytes.max(1024),
            write_lock: Mutex::new(()),
        }
    }

    pub fn active_log_path(&self) -> PathBuf {
        self.log_dir.join(APP_LOG_FILENAME)
    }

    pub fn rotated_path(&self, index: usize) -> PathBuf {
        self.log_dir.join(format!("{APP_LOG_FILENAME}.{index}"))
    }

    /// Append one sanitized log entry, rotating `catcloud.log` -> `.1` -> `.2` (max 3 files)
    /// whenever the active file would exceed `self.max_bytes`.
    pub fn append_line(&self, level: &str, category: &str, message: &str) {
        let ts = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        self.append_formatted(&ts, level, category, message);
    }

    pub fn append_formatted(&self, timestamp: &str, level: &str, category: &str, message: &str) {
        let lvl = normalize_log_level(level);
        let single_line = sanitize_log_line(message)
            .replace(['\r', '\n'], " ")
            .trim()
            .to_string();
        if single_line.is_empty() {
            return;
        }
        let cat = category.trim();
        let formatted = if cat.is_empty() {
            format!("{timestamp} [{lvl}] {single_line}\n")
        } else {
            format!("{timestamp} [{lvl}] [{cat}] {single_line}\n")
        };

        let Ok(_guard) = self.write_lock.lock() else {
            return;
        };
        if fs::create_dir_all(&self.log_dir).is_err() {
            return;
        }

        let active_path = self.active_log_path();
        let current_len = fs::metadata(&active_path).map(|m| m.len()).unwrap_or(0);
        let incoming_len = formatted.len() as u64;
        if current_len > 0 && current_len.saturating_add(incoming_len) > self.max_bytes {
            self.rotate_locked();
        }

        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&active_path)
        {
            let _ = file.write_all(formatted.as_bytes());
        }
    }

    fn rotate_locked(&self) {
        let oldest = self.rotated_path(MAX_ROTATED_FILES);
        if oldest.exists() {
            let _ = fs::remove_file(&oldest);
        }
        for idx in (1..MAX_ROTATED_FILES).rev() {
            let src = self.rotated_path(idx);
            let dst = self.rotated_path(idx + 1);
            if src.exists() {
                if dst.exists() {
                    let _ = fs::remove_file(&dst);
                }
                if fs::rename(&src, &dst).is_err() && fs::copy(&src, &dst).is_ok() {
                    let _ = fs::remove_file(&src);
                }
            }
        }
        let active = self.active_log_path();
        if active.exists() {
            let first_rotated = self.rotated_path(1);
            if first_rotated.exists() {
                let _ = fs::remove_file(&first_rotated);
            }
            if fs::rename(&active, &first_rotated).is_err() {
                // On Windows, an external reader or AV scanner can hold `catcloud.log` open
                // and cause `fs::rename` to fail. Copy best-effort to `.1` and truncate the
                // active file in place so logs never grow unbounded.
                let _ = fs::copy(&active, &first_rotated);
                if let Ok(file) = OpenOptions::new().write(true).truncate(true).open(&active) {
                    let _ = file.set_len(0);
                }
            }
        }
    }

    /// Read up to `limit` most recent lines across `catcloud.log` (and rotated archives if needed).
    pub fn read_recent_lines(&self, limit: usize) -> Vec<String> {
        if limit == 0 {
            return Vec::new();
        }
        let Ok(_guard) = self.write_lock.lock() else {
            return Vec::new();
        };

        let mut files: Vec<PathBuf> = Vec::with_capacity(MAX_ROTATED_FILES + 1);
        files.push(self.active_log_path());
        for idx in 1..=MAX_ROTATED_FILES {
            files.push(self.rotated_path(idx));
        }

        let mut collected_newest_first: Vec<String> = Vec::new();
        for path in files {
            if collected_newest_first.len() >= limit {
                break;
            }
            let lines = read_tail_lines(&path, MAX_TAIL_READ_BYTES);
            for line in lines.into_iter().rev() {
                collected_newest_first.push(line);
                if collected_newest_first.len() >= limit {
                    break;
                }
            }
        }
        collected_newest_first.reverse();
        collected_newest_first
    }
}

fn read_tail_lines(path: &Path, max_bytes: u64) -> Vec<String> {
    let Ok(mut file) = fs::File::open(path) else {
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
    let mut buf = Vec::new();
    if file.read_to_end(&mut buf).is_err() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.lines();
    // Drop the possibly truncated partial first line when we seeked into the middle of the file.
    if start > 0 {
        let _ = lines.next();
    }
    lines
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

pub fn normalize_log_level(level: &str) -> &'static str {
    match level.trim().to_ascii_lowercase().as_str() {
        "error" | "err" | "fatal" => "error",
        "warn" | "warning" => "warning",
        "debug" | "trace" => "debug",
        _ => "info",
    }
}

/// Decide whether an incoming `CoreLogLine` from Mihomo should be persisted to `catcloud.log`.
/// - Always skips application events (`[应用/...`) because `AppState::log_app_event` writes them once.
/// - Always persists `error`/`warning` lines.
/// - Persists important lifecycle `info` lines immediately and throttles routine `info` traffic lines.
pub fn should_persist_mihomo_log(
    level: &str,
    payload: &str,
    last_info_persisted: Option<Instant>,
    now: Instant,
) -> bool {
    let trimmed = payload.trim();
    if trimmed.is_empty() || trimmed.starts_with(APP_EVENT_PREFIX) {
        return false;
    }
    match normalize_log_level(level) {
        "error" | "warning" => true,
        "info" => {
            let lower = trimmed.to_ascii_lowercase();
            let is_routine_conn = lower.starts_with("[tcp]")
                || lower.starts_with("[udp]")
                || lower.contains(" match ")
                || lower.contains(" using ");
            let is_key_event = !is_routine_conn
                && (lower.contains("start initial")
                    || lower.contains("restful api")
                    || lower.contains("inbound")
                    || lower.contains("tun ")
                    || lower.contains("wintun")
                    || lower.contains("reload")
                    || lower.contains("mixed(")
                    || lower.contains("failed")
                    || lower.contains("error")
                    || lower.contains("panic")
                    || lower.contains("switched"));
            if is_key_event {
                true
            } else {
                last_info_persisted
                    .is_none_or(|t| now.saturating_duration_since(t) >= Duration::from_secs(3))
            }
        }
        _ => false,
    }
}

/// Strictly sanitize a log or error line before persisting or exporting to AI diagnostics:
/// - Redacts URL userinfo credentials (`scheme://user:pass@host`) and opaque proxy payloads
///   (`vmess://<base64>`, `ss://<base64>`, `mmrelay://v1/<payload>`)
/// - Redacts sensitive query/key-value secrets (`secret`, `password`, `token`, `key`, `auth`, `uuid`, `Bearer`, etc.)
/// - Redacts local user home directory usernames (`C:\Users\<USER>\`, `/Users/<USER>/`, `/home/<USER>/`),
///   including usernames containing spaces (`C:\Users\<USER Name>\...`)
/// - Redacts non-system drive absolute paths (`D:\SomeFolder\...` -> `<LOCAL_PATH>` / `<LOCAL_PATH>/bin`)
/// - Masks RFC1918 private, CGNAT, link-local, ULA, and public IPv4/IPv6 addresses, only exempting
///   `127.0.0.1`, `0.0.0.0`, `198.18.0.0/15`, `::1`, `::`, and public domestic DNS (`223.5.5.5`, `119.29.29.29`)
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
                let val_len = tail.find(is_value_terminator).unwrap_or(tail.len());
                if val_len > 0 {
                    out.push_str("<REDACTED>");
                    i = val_start + val_len;
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

const SENSITIVE_KEYS: &[&str] = &[
    "controller_secret",
    "obfs_password",
    "obfs-password",
    "authorization",
    "refresh_token",
    "client_secret",
    "access_token",
    "private_key",
    "private-key",
    "passphrase",
    "set-cookie",
    "auth_token",
    "sub_token",
    "user_uuid",
    "password",
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
                "bin" | "logs" | "config" | "runtime" | "data" | "cache" | "backup" | "backups"
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
                    let nl_end = tail[..quote_end]
                        .find(['\r', '\n'])
                        .unwrap_or(quote_end);
                    nl_end
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

fn is_non_public_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip == Ipv4Addr::LOCALHOST
        || ip.is_unspecified()
        // Mihomo Fake-IP benchmark range 198.18.0.0/15
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        // Well-known public domestic DNS resolvers safe to retain for diagnostics
        || ip == Ipv4Addr::new(223, 5, 5, 5)
        || ip == Ipv4Addr::new(119, 29, 29, 29)
}

fn redact_public_ipv4(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;

    while i < bytes.len() {
        let prev_ok =
            i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'.' || bytes[i - 1] == b'_');
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
                || !(bytes[end].is_ascii_alphanumeric() || bytes[end] == b'.' || bytes[end] == b'_');
            if dots == 3 && next_ok {
                let candidate = &input[i..end];
                if let Ok(ip) = Ipv4Addr::from_str(candidate) {
                    if is_non_public_ipv4(ip) {
                        out.push_str(candidate);
                    } else {
                        let o = ip.octets();
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
                // `:timeout`, etc. where leading hex letters (like `fa` in `failed` or `e`
                // in `error`) were greedily consumed past the separating colon.
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

    #[test]
    fn rotating_app_logger_rotates_and_caps_at_three_files() {
        let tmp = std::env::temp_dir().join(format!(
            "catcloud_applog_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let logger = RotatingAppLogger::with_max_bytes(tmp.clone(), 1024);

        for idx in 0..80 {
            logger.append_line(
                "info",
                "测试",
                &format!("第 {idx:02} 条持久化测试日志 token=secret_val_{idx} 远端 203.0.113.34"),
            );
        }

        assert!(logger.active_log_path().is_file());
        assert!(logger.rotated_path(1).is_file());
        assert!(logger.rotated_path(2).is_file());
        assert!(!logger.rotated_path(3).exists());

        let recent = logger.read_recent_lines(10);
        assert_eq!(recent.len(), 10);
        assert!(recent.last().unwrap().contains("第 79 条"));
        assert!(!recent.last().unwrap().contains("secret_val_79"));
        assert!(recent.last().unwrap().contains("token=<REDACTED>"));
        assert!(recent.last().unwrap().contains("203.0.113.*"));

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn sanitize_log_line_redacts_query_secrets_credentials_and_public_ips() {
        let raw = "2026-11-24T03:25:00Z 订阅拉取 https://alice:my_pass@sub.example.com/api/sub?token=abc123&secret=topsecret&key=k999&password=p1 代理 trojan://test_placeholder_pass@198.51.100.77:443 本地 127.0.0.1:7890 内网 192.168.1.10 FakeIP 198.18.0.12 IPv6 [240e:390:1234:5678::42]:443 回环 ::1 Authorization: Bearer eyJhbGciOi";
        let clean = sanitize_log_line(raw);

        assert!(!clean.contains("alice:my_pass"));
        assert!(!clean.contains("abc123"));
        assert!(!clean.contains("topsecret"));
        assert!(!clean.contains("k999"));
        assert!(!clean.contains("p1"));
        assert!(!clean.contains("test_placeholder_pass"));
        assert!(!clean.contains("198.51.100.77"));
        assert!(!clean.contains("5678::42"));
        assert!(!clean.contains("eyJhbGciOi"));

        assert!(clean.contains("https://<REDACTED>@sub.example.com/api/sub?token=<REDACTED>&secret=<REDACTED>&key=<REDACTED>&password=<REDACTED>"));
        assert!(clean.contains("trojan://<REDACTED>@198.51.100.*:443"));
        assert!(clean.contains("127.0.0.1:7890"));
        assert!(!clean.contains("192.168.1.10"));
        assert!(clean.contains("192.168.1.*"));
        assert!(clean.contains("198.18.0.12"));
        assert!(clean.contains("[240e:390::*]:443"));
        assert!(clean.contains("回环 ::1"));
        assert!(clean.contains("Bearer <REDACTED>"));
        // Timestamp HH:MM:SS must remain untouched.
        assert!(clean.contains("2026-11-24T03:25:00Z"));
    }

    #[test]
    fn should_persist_mihomo_log_skips_app_prefix_and_throttles_routine_info() {
        let now = Instant::now();
        assert!(!should_persist_mihomo_log(
            "error",
            "[应用/核心] 内部已写盘",
            None,
            now
        ));
        assert!(should_persist_mihomo_log(
            "warning",
            "dial proxy failed",
            Some(now),
            now
        ));
        assert!(should_persist_mihomo_log(
            "info",
            "Start initial compatible provider",
            Some(now),
            now
        ));
        assert!(!should_persist_mihomo_log(
            "info",
            "[TCP] 127.0.0.1:50000 --> example.com match MATCH using Proxy",
            Some(now),
            now + Duration::from_secs(1)
        ));
        assert!(should_persist_mihomo_log(
            "info",
            "[TCP] 127.0.0.1:50000 --> example.com match MATCH using Proxy",
            Some(now),
            now + Duration::from_secs(4)
        ));
        assert!(!should_persist_mihomo_log("debug", "verbose msg", None, now));
    }

    #[test]
    fn sanitize_log_line_redacts_prefixed_keys_and_extended_sensitive_keys() {
        let raw = "x-api-key: sk-live-999 api-key=ak111 private-key: priv_secret_01 \
                   obfs-password: obfs_pw_02 client_secret=cs_val_03 auth_token=at_val_04 \
                   sub_token=st_val_05 user_uuid=1111-2222-3333 cookie: sid_val_06 \
                   set-cookie: sc_val_07; HttpOnly auth-str=as_val_08 psk=psk_val_09 \
                   passphrase=pp_val_10 pbk=pbk_val_11&sid=sid_val_12 monkey=keep1 author=keep2";
        let clean = sanitize_log_line(raw);

        for leaked in [
            "sk-live-999",
            "ak111",
            "priv_secret_01",
            "obfs_pw_02",
            "cs_val_03",
            "at_val_04",
            "st_val_05",
            "1111-2222-3333",
            "sid_val_06",
            "sc_val_07",
            "as_val_08",
            "psk_val_09",
            "pp_val_10",
            "pbk_val_11",
            "sid_val_12",
        ] {
            assert!(!clean.contains(leaked), "leaked secret `{leaked}` in: {clean}");
        }

        assert!(clean.contains("x-api-key: <REDACTED>"));
        assert!(clean.contains("api-key=<REDACTED>"));
        assert!(clean.contains("private-key: <REDACTED>"));
        assert!(clean.contains("obfs-password: <REDACTED>"));
        assert!(clean.contains("client_secret=<REDACTED>"));
        assert!(clean.contains("auth_token=<REDACTED>"));
        assert!(clean.contains("sub_token=<REDACTED>"));
        assert!(clean.contains("user_uuid=<REDACTED>"));
        assert!(clean.contains("cookie: <REDACTED>"));
        assert!(clean.contains("set-cookie: <REDACTED>; HttpOnly"));
        assert!(clean.contains("auth-str=<REDACTED>"));
        assert!(clean.contains("psk=<REDACTED>"));
        assert!(clean.contains("passphrase=<REDACTED>"));
        assert!(clean.contains("pbk=<REDACTED>&sid=<REDACTED>"));
        assert!(clean.contains("monkey=keep1"));
        assert!(clean.contains("author=keep2"));
        assert_eq!(sanitize_log_line(&clean), clean);
    }

    #[test]
    fn sanitize_log_line_redacts_opaque_proxy_uris_and_user_home_paths() {
        let raw = concat!(
            "import ", "vmess", "://eyJ2IjoiMiIsImFkZCI6IjE5OC41MS4xMDAuNCJ9/abc==#HK ",
            "ss", "://YWVzLTI1Ni1nY206cGFzc0AxOTguNTEuMTAwLjQ6ODM4OA==#SG ",
            "ss", "://aes-256-gcm:rawpass@198.51.100.88:8388#JP ",
            "relay mmrelay://v1/eyJzZXJ2ZXIiOiIxOTguNTEuMTAwLjQifQ== ",
            "paths ", "C:\\Users\\", "张三\\AppData\\Local\\CatCloud ",
            "C:/Users/", "DemoAlice/Desktop/sub.yaml ",
            "C:\\\\Users\\\\", "小明\\\\logs\\\\catcloud.log ",
            "/Users/", "小猫/Library/Logs ",
            "/home/", "demo_tester/.config/catcloud ",
            "url https://example.com/users/profile"
        );
        let clean = sanitize_log_line(raw);

        for leaked in [
            "eyJ2IjoiMiIsImFkZCI6IjE5OC41MS4xMDAuNCJ9",
            "YWVzLTI1Ni1nY206cGFzc0AxOTguNTEuMTAwLjQ6ODM4OA==",
            "rawpass",
            "198.51.100.88",
            "eyJzZXJ2ZXIiOiIxOTguNTEuMTAwLjQifQ==",
            "张三",
            "DemoAlice",
            "小明",
            "小猫",
            "demo_tester",
        ] {
            assert!(!clean.contains(leaked), "leaked sensitive value `{leaked}` in: {clean}");
        }

        assert!(clean.contains("vmess://<REDACTED>#HK"));
        assert!(clean.contains("ss://<REDACTED>#SG"));
        assert!(clean.contains("ss://<REDACTED>@198.51.100.*:8388#JP"));
        assert!(clean.contains("mmrelay://v1/<REDACTED>"));
        assert!(clean.contains(r"C:\Users\<USER>\AppData\Local\CatCloud"));
        assert!(clean.contains("C:/Users/<USER>/Desktop/sub.yaml"));
        assert!(clean.contains(r"C:\\Users\\<USER>\\logs\\catcloud.log"));
        assert!(clean.contains("/Users/<USER>/Library/Logs"));
        assert!(clean.contains("/home/<USER>/.config/catcloud"));
        assert!(clean.contains("https://example.com/users/profile"));
        assert_eq!(sanitize_log_line(&clean), clean);
    }

    #[test]
    fn sanitize_log_line_redacts_ipv6_unbracketed_port_and_nonhex_suffix() {
        let raw = "dial 240e:1234:5678:9abc:def0:1234:5678:9abc:443 \
                   connect 240e:390::1:failed handshake 240e:390::1:error \
                   probe 240e:390::1:timeout local fe80::1:failed \
                   time 2026-11-24T03:25:00Z 12:34:56:789";
        let clean = sanitize_log_line(raw);

        assert!(!clean.contains("5678:9abc:def0"));
        assert!(!clean.contains("240e:390::1"));
        assert!(clean.contains("dial 240e:1234::*:443"));
        assert!(clean.contains("connect 240e:390::*:failed"));
        assert!(clean.contains("handshake 240e:390::*:error"));
        assert!(clean.contains("probe 240e:390::*:timeout"));
        assert!(!clean.contains("fe80::1"));
        assert!(clean.contains("local fe80:0::*:failed"));
        assert!(clean.contains("2026-11-24T03:25:00Z"));
        assert!(clean.contains("12:34:56:789"));
        assert_eq!(sanitize_log_line(&clean), clean);
    }

    #[test]
    fn sanitize_log_line_handles_escaped_quotes_and_preserves_valid_json() {
        let raw = r#"{"password":"abc\"def\"ghi","secret":12345,"x-api-key":98765,"private_key":"tail\\","path":"C:\\Users\\张三\\cfg.json","portable":"D:\\MySecretWork\\CatCloud\\bin","ok":true}"#;
        let clean = sanitize_log_line(raw);

        for leaked in [
            "abc",
            "def",
            "ghi",
            "12345",
            "98765",
            "tail",
            "张三",
            "MySecretWork",
        ] {
            assert!(!clean.contains(leaked), "leaked `{leaked}` in: {clean}");
        }

        let parsed: serde_json::Value =
            serde_json::from_str(&clean).expect("sanitized JSON payload must remain valid JSON");
        assert_eq!(parsed["password"], "<REDACTED>");
        assert_eq!(parsed["secret"], "<REDACTED>");
        assert_eq!(parsed["x-api-key"], "<REDACTED>");
        assert_eq!(parsed["private_key"], "<REDACTED>");
        assert_eq!(parsed["path"], r"C:\Users\<USER>\cfg.json");
        assert_eq!(parsed["portable"], "<LOCAL_PATH>/bin");
        assert_eq!(parsed["ok"], true);
        assert_eq!(sanitize_log_line(&clean), clean);
    }

    #[test]
    fn sanitize_log_line_redacts_private_ips_spaced_usernames_and_non_system_paths() {
        let raw = concat!(
            "lan 10.24.8.15 corp 172.16.9.22 home 192.168.50.88 cgnat 100.64.12.34 ",
            "ula fd12:3456:789a::42 link fe80::abcd:1234 ",
            "keep 127.0.0.1 0.0.0.0 198.18.0.5 223.5.5.5 119.29.29.29 ::1 :: ",
            "spaced C:\\", "Users\\John Doe\\AppData\\Local\\CatCloud ",
            "slash C:/", "Users/Jane Smith/Desktop/sub.yaml ",
            "escaped C:\\\\Users\\\\John Doe\\\\logs\\\\catcloud.log ",
            "mac /", "Users/Alex Mercer/Library/Logs ",
            "guidance 信任区添加目录 `D:\\My Secret Folder\\CatCloudPortable\\bin`（放行） ",
            "bare 安装至 E:\\Program Files\\CatCloud\\bin 完成 ",
            "file 读取 F:\\PrivateDocs\\secret.yaml 失败"
        );
        let clean = sanitize_log_line(raw);

        for leaked in [
            "10.24.8.15",
            "172.16.9.22",
            "192.168.50.88",
            "100.64.12.34",
            "789a::42",
            "abcd:1234",
            "John Doe",
            "Jane Smith",
            "Alex Mercer",
            "My Secret Folder",
            "CatCloudPortable",
            "Program Files",
            "PrivateDocs",
            "secret.yaml",
        ] {
            assert!(!clean.contains(leaked), "leaked `{leaked}` in: {clean}");
        }

        assert!(clean.contains("10.24.8.*"));
        assert!(clean.contains("172.16.9.*"));
        assert!(clean.contains("192.168.50.*"));
        assert!(clean.contains("100.64.12.*"));
        assert!(clean.contains("fd12:3456::*"));
        assert!(clean.contains("fe80:0::*"));

        assert!(clean.contains("127.0.0.1"));
        assert!(clean.contains("0.0.0.0"));
        assert!(clean.contains("198.18.0.5"));
        assert!(clean.contains("223.5.5.5"));
        assert!(clean.contains("119.29.29.29"));
        assert!(clean.contains("::1"));
        assert!(clean.contains(" :: "));

        assert!(clean.contains(r"C:\Users\<USER>\AppData\Local\CatCloud"));
        assert!(clean.contains("C:/Users/<USER>/Desktop/sub.yaml"));
        assert!(clean.contains(r"C:\\Users\\<USER>\\logs\\catcloud.log"));
        assert!(clean.contains("/Users/<USER>/Library/Logs"));
        assert!(clean.contains("`<LOCAL_PATH>/bin`（放行）"));
        assert!(clean.contains("安装至 <LOCAL_PATH>/bin 完成"));
        assert!(clean.contains("读取 <LOCAL_PATH> 失败"));
        assert_eq!(sanitize_log_line(&clean), clean);
    }
}
