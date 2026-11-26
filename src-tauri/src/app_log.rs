use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use chrono::Utc;

/// Primary persistent rotating log filename inside `paths.logs_dir`.
pub const APP_LOG_FILENAME: &str = "catcloud.log";
/// Single-file rotation threshold (2 MiB).
pub const MAX_LOG_FILE_BYTES: u64 = 2 * 1024 * 1024;
/// Number of rotated archives kept alongside `catcloud.log` (`.1`, `.2` => at most 3 files total).
pub const MAX_ROTATED_FILES: usize = 2;
/// Fixed capacity of the dedicated in-memory key-event ring buffer so high-volume TCP/UDP
/// traffic logs can never evict lifecycle/warning/error events from diagnostic exports.
pub const MAX_KEY_EVENT_RING_LEN: usize = 256;
/// Maximum tail bytes read per log file when collecting recent diagnostic lines.
const MAX_TAIL_READ_BYTES: u64 = 256 * 1024;
/// Prefix stamped on application-level events pushed into `CoreTelemetryStore` so the Mihomo
/// stream forwarder can skip writing them to disk a second time.
pub const APP_EVENT_PREFIX: &str = "[应用/";

/// Lightweight zero-dependency persistent rotating file logger for CatCloud desktop,
/// paired with a dedicated 256-entry key-event ring buffer immune to routine traffic floods.
#[derive(Debug)]
pub struct RotatingAppLogger {
    log_dir: PathBuf,
    max_bytes: u64,
    write_lock: Mutex<()>,
    key_events: Mutex<VecDeque<String>>,
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
            key_events: Mutex::new(VecDeque::with_capacity(MAX_KEY_EVENT_RING_LEN)),
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
        let line_no_nl = if cat.is_empty() {
            format!("{timestamp} [{lvl}] {single_line}")
        } else {
            format!("{timestamp} [{lvl}] [{cat}] {single_line}")
        };

        if is_key_event_entry(lvl, cat, &single_line) {
            if let Ok(mut ring) = self.key_events.lock() {
                if ring.len() >= MAX_KEY_EVENT_RING_LEN {
                    ring.pop_front();
                }
                ring.push_back(line_no_nl.clone());
            }
        }

        let formatted = format!("{line_no_nl}\n");

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

    /// Return up to `limit` most recent non-routine key events (oldest -> newest)
    /// directly from the dedicated in-memory ring buffer.
    pub fn read_recent_key_events(&self, limit: usize) -> Vec<String> {
        if limit == 0 {
            return Vec::new();
        }
        let Ok(ring) = self.key_events.lock() else {
            return Vec::new();
        };
        let skip = ring.len().saturating_sub(limit);
        ring.iter().skip(skip).cloned().collect()
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

/// Return `true` when an entry is a routine per-connection forwarding line (`[TCP]` / `[UDP]` /
/// ` match ` / ` using `) that should never displace key lifecycle/error events.
fn is_routine_traffic_payload(lower: &str) -> bool {
    lower.starts_with("[tcp]")
        || lower.starts_with("[udp]")
        || lower.contains(" match ")
        || lower.contains(" using ")
}

/// Return `true` when a Mihomo/core `info` payload carries a high-signal lifecycle event.
fn is_core_lifecycle_keyword(lower: &str) -> bool {
    lower.contains("start initial")
        || lower.contains("restful api")
        || lower.contains("inbound")
        || lower.contains("tun ")
        || lower.contains("wintun")
        || lower.contains("reload")
        || lower.contains("mixed(")
        || lower.contains("failed")
        || lower.contains("error")
        || lower.contains("warning")
        || lower.contains("panic")
        || lower.contains("switched")
        || lower.contains("listening")
        || lower.contains("mmdb")
        || lower.contains("geosite")
        || lower.contains("geoip")
}

/// Decide whether a formatted log entry belongs in the dedicated 256-entry key-event ring buffer.
/// - Always accepts `error` and `warning` entries.
/// - Always accepts application-level events (`[应用/` prefix or non-`mihomo` category at non-debug level).
/// - Accepts non-routine core lifecycle entries while strictly excluding routine `[TCP]`/`[UDP]`/` match `/` using ` traffic lines.
pub fn is_key_event_entry(level: &str, category: &str, message: &str) -> bool {
    let trimmed = message.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lvl = normalize_log_level(level);
    if matches!(lvl, "error" | "warning") {
        return true;
    }
    if lvl == "debug" {
        return false;
    }
    if trimmed.contains(APP_EVENT_PREFIX) {
        return true;
    }
    let cat = category.trim();
    if !cat.is_empty() && !cat.eq_ignore_ascii_case("mihomo") {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    !is_routine_traffic_payload(&lower) && is_core_lifecycle_keyword(&lower)
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
            let is_key_event =
                !is_routine_traffic_payload(&lower) && is_core_lifecycle_keyword(&lower);
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

/// Strictly sanitize a log or error line before persisting or exporting to AI diagnostics.
/// Delegates directly to `catcloud_core::sanitize::sanitize_log_line` as the single source of truth.
pub fn sanitize_log_line(raw: &str) -> String {
    catcloud_core::sanitize::sanitize_log_line(raw)
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
    fn key_event_ring_survives_heavy_tcp_udp_traffic_flood_and_caps_at_256() {
        let tmp = std::env::temp_dir().join(format!(
            "catcloud_key_ring_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let logger = RotatingAppLogger::with_max_bytes(tmp.clone(), 2048);

        logger.append_formatted(
            "2026-11-25T00:00:01Z",
            "info",
            "核心",
            "代理核心已启动（已按需加载节点 14 个（含中转 2 个，节点库共 796 个））",
        );
        logger.append_formatted(
            "2026-11-25T00:00:02Z",
            "info",
            "mihomo",
            "Start initial compatible provider Proxy",
        );
        logger.append_formatted(
            "2026-11-25T00:00:03Z",
            "warning",
            "mihomo",
            "[TCP] 127.0.0.1:50000 --> example.invalid:443 dial error",
        );
        logger.append_formatted(
            "2026-11-25T00:00:04Z",
            "info",
            "",
            "[应用/国内提速] 自动探测通过 32 ms",
        );
        logger.append_formatted(
            "2026-11-25T00:00:05Z",
            "debug",
            "核心",
            "调试信息不应进入关键事件缓冲",
        );

        // Flood 1200 routine TCP/UDP forwarding lines to completely flush and rotate all disk files.
        for idx in 0..600 {
            logger.append_formatted(
                "2026-11-25T00:05:00Z",
                "info",
                "mihomo",
                &format!(
                    "[TCP] 127.0.0.1:{} --> example.invalid:443 match MATCH using Proxy",
                    40000 + idx
                ),
            );
            logger.append_formatted(
                "2026-11-25T00:05:01Z",
                "info",
                "mihomo",
                &format!(
                    "[UDP] 127.0.0.1:{} --> 8.8.8.8:53 match GeoIP using DIRECT",
                    50000 + idx
                ),
            );
        }

        let key_events = logger.read_recent_key_events(25);
        assert_eq!(key_events.len(), 4);
        assert!(key_events[0].contains("已按需加载节点 14 个"));
        assert!(key_events[1].contains("Start initial compatible provider"));
        assert!(key_events[2].contains("[warning] [mihomo] [TCP]"));
        assert!(key_events[3].contains("[应用/国内提速]"));
        assert!(key_events
            .iter()
            .all(|l| !l.contains("match MATCH using Proxy")));
        assert!(key_events.iter().all(|l| !l.contains("调试信息不应进入")));

        // Verify 256-entry ring capacity bound.
        for idx in 0..300 {
            logger.append_formatted(
                "2026-11-25T00:10:00Z",
                "info",
                "节点切换",
                &format!("关键事件 #{idx:03}"),
            );
        }
        let all_ring = logger.read_recent_key_events(500);
        assert_eq!(all_ring.len(), MAX_KEY_EVENT_RING_LEN);
        assert!(all_ring.first().unwrap().contains("关键事件 #044"));
        assert!(all_ring.last().unwrap().contains("关键事件 #299"));

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
        assert!(!clean.contains("198.18.0.12"));
        assert!(clean.contains("198.18.0.*"));
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
            "198.18.0.5",
            "223.5.5.5",
            "119.29.29.29",
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
        assert!(clean.contains("198.18.0.*"));
        assert!(clean.contains("223.5.5.*"));
        assert!(clean.contains("119.29.29.*"));
        assert!(clean.contains("fd12:3456::*"));
        assert!(clean.contains("fe80:0::*"));

        assert!(clean.contains("127.0.0.1"));
        assert!(clean.contains("0.0.0.0"));
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

    #[test]
    fn sanitize_log_line_strictly_masks_fictional_public_private_tun_and_dns_ips() {
        let raw = concat!(
            "2026-11-26T03:44:51Z [warning] ",
            "public 203.0.113.10. relay 198.51.100.77:443 ",
            "private 10.99.88.77 corp 172.20.14.9 home ip_192.168.31.44 ",
            "tun 198.18.0.21 linklocal 169.254.12.34 ",
            "dns https://223.5.5.5/dns-query tls://1.12.12.12:853 fallback 8.8.8.8 ",
            "v6 [2001:db8:abcd:ef01::99]:443 ",
            "keep 127.0.0.1:7890 0.0.0.0 ::1 :: ver v1.2.3.4 oid 1.3.6.1.5.5"
        );
        let clean = sanitize_log_line(raw);

        for leaked in [
            "203.0.113.10",
            "198.51.100.77",
            "10.99.88.77",
            "172.20.14.9",
            "192.168.31.44",
            "198.18.0.21",
            "169.254.12.34",
            "223.5.5.5",
            "1.12.12.12",
            "8.8.8.8",
            "ef01::99",
        ] {
            assert!(
                !clean.contains(leaked),
                "strict app_log sanitizer leaked `{leaked}` in: {clean}"
            );
        }

        assert!(clean.contains("203.0.113.*."));
        assert!(clean.contains("198.51.100.*:443"));
        assert!(clean.contains("10.99.88.*"));
        assert!(clean.contains("172.20.14.*"));
        assert!(clean.contains("ip_192.168.31.*"));
        assert!(clean.contains("198.18.0.*"));
        assert!(clean.contains("169.254.12.*"));
        assert!(clean.contains("https://223.5.5.*/dns-query"));
        assert!(clean.contains("tls://1.12.12.*:853"));
        assert!(clean.contains("fallback 8.8.8.*"));
        assert!(clean.contains("[2001:db8::*]:443"));
        assert!(clean.contains("127.0.0.1:7890"));
        assert!(clean.contains("0.0.0.0"));
        assert!(clean.contains("::1"));
        assert!(clean.contains(" :: "));
        assert!(clean.contains("v1.2.3.4"));
        assert!(clean.contains("1.3.6.1.5.5"));
        assert!(clean.contains("2026-11-26T03:44:51Z"));
        assert_eq!(sanitize_log_line(&clean), clean);
    }
}
