use crate::core_adapter::resolve_mihomo_binary;
use crate::error::{CatError, CatResult};
use crate::models::{AppConfig, GlobalPreAccelScope, PreAccelConfig, PreAccelRelay};
use crate::paths::{AppPaths, normalize_os_path};
use crate::platform::default_platform;
use crate::preaccel::generator::{
    PREACCEL_SELECT_GROUP, build_preaccel_compile_plan, host_to_direct_rule,
};
use crate::preaccel::schema::{parse_server_ip, sanitize_relay_for_domestic_443};
use crate::process_guard::JobGuard;
use serde::{Deserialize, Serialize};
use serde_yaml_ng::{Mapping, Number, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::io::{Cursor, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener as StdTcpListener};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use url::Url;
use zip::ZipArchive;

/// Official WinDivert v2.2.2 release archive download URL (`basil00/Divert`).
pub const WINDIVERT_DOWNLOAD_URL: &str =
    "https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip";

/// Verified SHA-256 checksum of official `WinDivert-2.2.2-A.zip`.
pub const WINDIVERT_ZIP_SHA256: &str =
    "63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15";

/// Hard upper bound for downloaded WinDivert ZIP archive (16 MiB).
#[cfg_attr(
    all(target_os = "windows", target_arch = "aarch64"),
    allow(dead_code)
)]
const MAX_WINDIVERT_ZIP_BYTES: usize = 16 * 1024 * 1024;

/// Hard upper bound for a single extracted WinDivert binary file (8 MiB).
const MAX_WINDIVERT_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// Allowed HTTPS redirect hosts when downloading official WinDivert releases.
#[cfg_attr(
    all(target_os = "windows", target_arch = "aarch64"),
    allow(dead_code)
)]
const ALLOWED_WINDIVERT_HOSTS: &[&str] = &[
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "raw.githubusercontent.com",
];

/// Actionable Chinese notice returned when WinDivert is requested on Windows ARM64,
/// where official WinDivert v2.2.2 provides no native ARM64 kernel driver.
#[cfg_attr(
    not(all(target_os = "windows", target_arch = "aarch64")),
    allow(dead_code)
)]
pub(super) const WINDIVERT_ARM64_UNSUPPORTED_MSG: &str = "当前为 Windows ARM64 架构，官方 WinDivert v2.2.2 未提供原生 ARM64 内核驱动；请使用内置的「本地独立 443 通道 (SOCKS5)」为其它软件提速";

/// Maximum number of concurrent/recent NAT entries tracked by the transparent TCP NAT table.
pub const MAX_NAT_ENTRIES: usize = 4096;

/// Idle eviction timeout for stale NAT table entries.
pub const NAT_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// Grace period keeping a closing NAT entry alive so final `FIN-ACK` / `RST` return packets
/// still translate back to the client cleanly without leaving half-closed sockets or overly
/// delaying ephemeral port reuse.
pub const NAT_CLOSING_GRACE: Duration = Duration::from_secs(4);

/// Internal detection tag reserved for the built-in WinDivert loopback dataplane self-test flow.
pub const SELF_TEST_DETECTED_BY: &str = "self_test";

/// Maximum number of distinct recent accelerated process names retained in status snapshots.
const MAX_RECENT_PROCESSES: usize = 32;

/// Maximum number of distinct per-process telemetry buckets tracked simultaneously.
const MAX_PROCESS_STATS: usize = 64;

/// Generic open-source proxy core / tunnel executable stems recognized dynamically
/// without hardcoding any proprietary or commercial client names.
const OPEN_SOURCE_PROXY_CORE_STEMS: &[&str] = &[
    "mihomo",
    "clash",
    "xray",
    "v2ray",
    "sing-box",
    "singbox",
    "hysteria",
    "tuic",
    "trojan",
    "tun2socks",
    "naive",
    "shadowsocks",
    "sslocal",
    "ss-local",
];

/// Maximum startup readiness wait for the standalone lightweight 443 Mihomo tunnel.
const STANDALONE_TUNNEL_READY_TIMEOUT: Duration = Duration::from_secs(6);

/// Polling interval while waiting for the standalone 443 tunnel SOCKS5 port.
const STANDALONE_TUNNEL_POLL_INTERVAL: Duration = Duration::from_millis(80);

/// Dedicated memory budget for the lightweight standalone 443 tunnel subprocess.
pub const STANDALONE_TUNNEL_GOMEMLIMIT: &str = "48MiB";

/// Dedicated GC target for the lightweight standalone 443 tunnel subprocess.
pub const STANDALONE_TUNNEL_GOGC: &str = "25";

/// Filename of the persisted standalone global `:443` pre-acceleration runtime metadata snapshot
/// under `<data_dir>/run/`.
pub const GLOBAL_PREACCEL_RUNTIME_META_FILENAME: &str = "global-preaccel-runtime.json";

/// Persisted runtime metadata snapshot for the standalone global domestic `:443`
/// pre-acceleration engine, atomically written to `<data_dir>/run/global-preaccel-runtime.json`
/// (with Unix `0o600` permissions) for CLI and diagnostic self-recognition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct GlobalPreAccelRuntimeMeta {
    pub pid: Option<u32>,
    pub process_start_time_unix: Option<u64>,
    pub binary_path: Option<String>,
    pub running: bool,
    /// Active or suspended mode: `"off" | "windivert" | "local_socks5" | "suspended_for_tun"`.
    pub mode: String,
    /// Unified carrier label: `"standalone_windivert" | "standalone_socks5" | "main_core_tun_suspended_standalone" | "main_core_proxy_only" | "off"`.
    pub effective_carrier: String,
    pub socks_port: Option<u16>,
    pub active_relays: Vec<String>,
    pub updated_at: String,
}

impl Default for GlobalPreAccelRuntimeMeta {
    fn default() -> Self {
        Self {
            pid: None,
            process_start_time_unix: None,
            binary_path: None,
            running: false,
            mode: "off".to_string(),
            effective_carrier: "off".to_string(),
            socks_port: None,
            active_relays: Vec::new(),
            updated_at: String::new(),
        }
    }
}

/// Resolve the canonical runtime metadata file path `<data_dir>/run/global-preaccel-runtime.json`.
pub fn global_preaccel_runtime_meta_path(data_dir: &Path) -> PathBuf {
    data_dir
        .join("run")
        .join(GLOBAL_PREACCEL_RUNTIME_META_FILENAME)
}

fn write_restricted_runtime_meta_file(target: &Path, bytes: &[u8]) -> CatResult<()> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let parent = target.parent().unwrap_or_else(|| Path::new("."));
        let file_name = target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(GLOBAL_PREACCEL_RUNTIME_META_FILENAME);
        let tmp = parent.join(format!(
            ".{file_name}.tmp.{}.{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        if let Err(err) = f.write_all(bytes).and_then(|()| f.sync_all()) {
            drop(f);
            let _ = std::fs::remove_file(&tmp);
            return Err(CatError::Io(err));
        }
        drop(f);
        if let Err(err) = std::fs::rename(&tmp, target) {
            let _ = std::fs::remove_file(&tmp);
            return Err(CatError::Io(err));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        AppPaths::atomic_write(target, bytes)
    }
}

/// Atomically persist `GlobalPreAccelRuntimeMeta` to `<data_dir>/run/global-preaccel-runtime.json`
/// (creating with mode `0o600` on Unix).
pub fn write_global_preaccel_runtime_meta(
    data_dir: &Path,
    meta: &GlobalPreAccelRuntimeMeta,
) -> CatResult<()> {
    let target = global_preaccel_runtime_meta_path(data_dir);
    let bytes = serde_json::to_vec_pretty(meta)?;
    write_restricted_runtime_meta_file(&target, &bytes)
}

/// Read `<data_dir>/run/global-preaccel-runtime.json` if present and valid JSON.
/// Also falls back to `<data_dir>/global-preaccel-runtime.json` when the caller passes `run/` directly.
pub fn read_global_preaccel_runtime_meta(data_dir: &Path) -> Option<GlobalPreAccelRuntimeMeta> {
    let primary = global_preaccel_runtime_meta_path(data_dir);
    let candidate = if primary.is_file() {
        primary
    } else if data_dir
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.eq_ignore_ascii_case("run"))
    {
        let direct = data_dir.join(GLOBAL_PREACCEL_RUNTIME_META_FILENAME);
        if direct.is_file() {
            direct
        } else {
            return None;
        }
    } else {
        return None;
    };

    let raw = std::fs::read_to_string(candidate).ok()?;
    serde_json::from_str::<GlobalPreAccelRuntimeMeta>(&raw).ok()
}

/// Remove `<data_dir>/run/global-preaccel-runtime.json` cleanly when the tunnel stops or exits.
pub fn remove_global_preaccel_runtime_meta(data_dir: &Path) {
    let target = global_preaccel_runtime_meta_path(data_dir);
    let _ = std::fs::remove_file(target);
}

/// Well-known non-proxy communication, browser, IDE, office, media, and cloud-drive
/// executable stems excluded from automatic local proxy listener heuristics.
///
/// Intentionally never excludes CLI transfer tools (`ssh.exe`, `git.exe`, `scp.exe`, `rsync.exe`)
/// or user-configured manual target process lists.
const NON_PROXY_COMMUNICATION_PROCESS_STEMS: &[&str] = &[
    // Domestic IM & collaboration
    "qq",
    "qqnt",
    "qqprotect",
    "qqprotectupd",
    "qqexternal",
    "txupd",
    "txplatform",
    "tim",
    "wechat",
    "weixin",
    "wechatapp",
    "wechatappex",
    "wechatocr",
    "wechatplayer",
    "wechatutility",
    "dingtalk",
    "feishu",
    "lark",
    "wxwork",
    "wxworkweb",
    "qywx",
    "wemeetapp",
    "tencentmeeting",
    "aliwangwang",
    "wwbizsrv",
    "yy",
    "foxmail",
    "telegram",
    "discord",
    "slack",
    "teams",
    "ms-teams",
    "zoom",
    // Browsers & webviews
    "chrome",
    "msedge",
    "msedgewebview2",
    "firefox",
    "opera",
    "brave",
    "vivaldi",
    "safari",
    "360chrome",
    "360se",
    "qqbrowser",
    "quark",
    // IDEs & editors (never ssh/git)
    "code",
    "code-insiders",
    "cursor",
    "windsurf",
    "idea64",
    "pycharm64",
    "clion64",
    "goland64",
    "webstorm64",
    "devenv",
    // Gaming, music, media, netdisk & office
    "steam",
    "steamwebhelper",
    "steamservice",
    "epicgameslauncher",
    "wegame",
    "cloudmusic",
    "qqmusic",
    "kugou",
    "kuwo",
    "spotify",
    "baidunetdisk",
    "baidunetdiskhost",
    "aliyundrive",
    "quarkclouddrive",
    "thunder",
    "wps",
    "wpscloudsvr",
    "wpsoffice",
    "winword",
    "excel",
    "powerpnt",
    "outlook",
    "onenote",
    "obs64",
    "bilibili",
    "potplayer64",
    "potplayermini64",
    "vlc",
];

/// Thirteen whitelisted domestic public DNS IPv4 endpoints unconditionally bypassed at the
/// WinDivert kernel filter layer so DoT/DoH/TCP DNS queries never detour through relays.
pub const DOMESTIC_PUBLIC_DNS_IPV4S: &[Ipv4Addr] = &[
    Ipv4Addr::new(1, 2, 4, 8),
    Ipv4Addr::new(1, 12, 12, 12),
    Ipv4Addr::new(114, 114, 114, 114),
    Ipv4Addr::new(114, 114, 115, 115),
    Ipv4Addr::new(119, 28, 28, 28),
    Ipv4Addr::new(119, 29, 29, 29),
    Ipv4Addr::new(120, 53, 53, 53),
    Ipv4Addr::new(180, 76, 76, 76),
    Ipv4Addr::new(180, 184, 1, 1),
    Ipv4Addr::new(180, 184, 2, 2),
    Ipv4Addr::new(210, 2, 4, 8),
    Ipv4Addr::new(223, 5, 5, 5),
    Ipv4Addr::new(223, 6, 6, 6),
];

/// Compact, strictly sorted, non-overlapping inclusive IPv4 ranges `(start, end)` in host-order
/// `u32` hex covering major China Mainland ISP, cloud, and academic networks (China Telecom,
/// China Unicom, China Mobile, Alibaba Cloud CN, Tencent Cloud CN, Huawei Cloud CN, Baidu Cloud,
/// ByteDance/Volcengine, CERNET, CSTNET, and CNNIC).
///
/// Overseas cloud regions and RFC 1918/5737/Fake-IP spaces are strictly excluded.
const CN_IPV4_RANGES: &[(u32, u32)] = &[
    (0x0100_0100, 0x0100_03FF), (0x0100_0800, 0x0100_0FFF),
    (0x0100_2000, 0x0100_3FFF), (0x0101_0000, 0x0101_00FF),
    (0x0101_0200, 0x0101_3FFF), (0x0102_0000, 0x0102_02FF),
    (0x0102_0400, 0x0102_7FFF), (0x0104_0100, 0x0104_7FFF),
    (0x0108_0000, 0x0108_FFFF), (0x010C_0000, 0x010F_FFFF),
    (0x0118_0000, 0x011F_FFFF), (0x012D_0000, 0x012D_FFFF),
    (0x0130_0000, 0x0133_FFFF), (0x0138_0000, 0x013F_FFFF),
    (0x0144_0000, 0x0147_FFFF), (0x0150_0000, 0x015F_FFFF),
    (0x0174_0000, 0x0177_FFFF), (0x01B4_0000, 0x01B9_FFFF),
    (0x01BC_0000, 0x01C7_FFFF), (0x01CA_0000, 0x01CF_FFFF),
    (0x0E10_0000, 0x0E1F_FFFF), (0x0E68_0000, 0x0E7F_FFFF),
    (0x0E90_0000, 0x0E9F_FFFF), (0x0ED0_0000, 0x0EDF_FFFF),
    (0x1B08_0000, 0x1B1F_FFFF), (0x1B24_0000, 0x1B2F_FFFF),
    (0x1B73_0000, 0x1B73_FFFF), (0x1B80_0000, 0x1B81_FFFF),
    (0x1B94_0000, 0x1B9F_FFFF), (0x1BB8_0000, 0x1BE3_FFFF),
    (0x2420_0000, 0x243F_FFFF), (0x2460_0000, 0x24BF_FFFF),
    (0x24F8_0000, 0x24FB_FFFF), (0x2740_0000, 0x276B_FFFF),
    (0x2780_0000, 0x27BF_FFFF), (0x2A04_0000, 0x2A07_FFFF),
    (0x2A30_0000, 0x2A3B_FFFF), (0x2A50_0000, 0x2A60_FFFF),
    (0x2A64_0000, 0x2A67_FFFF), (0x2A78_0000, 0x2A79_FFFF),
    (0x2AB0_0000, 0x2AB3_FFFF), (0x2AB8_0000, 0x2AB9_FFFF),
    (0x2AC0_0000, 0x2AC3_FFFF), (0x2AE0_0000, 0x2AEF_FFFF),
    (0x2F5C_0000, 0x2F7B_FFFF), (0x3140_0000, 0x315F_FFFF),
    (0x3170_0000, 0x3177_FFFF), (0x31DC_0000, 0x31DF_FFFF),
    (0x31E8_0000, 0x31EB_FFFF), (0x3A10_0000, 0x3A19_FFFF),
    (0x3A20_0000, 0x3A3F_FFFF), (0x3A42_0000, 0x3A44_FFFF),
    (0x3A64_0000, 0x3A65_FFFF), (0x3A80_0000, 0x3A87_FFFF),
    (0x3A90_0000, 0x3A90_FFFF), (0x3A9A_0000, 0x3A9B_FFFF),
    (0x3AC0_0000, 0x3ADF_FFFF), (0x3AF0_0000, 0x3AFF_FFFF),
    (0x3B20_0000, 0x3B53_FFFF), (0x3B6C_0000, 0x3B6F_FFFF),
    (0x3BAC_0000, 0x3BAF_FFFF), (0x3C00_0000, 0x3C1F_FFFF),
    (0x3CA0_0000, 0x3CBF_FFFF), (0x3CCC_0000, 0x3CDF_FFFF),
    (0x3D30_0000, 0x3D37_FFFF), (0x3D80_0000, 0x3DBF_FFFF),
    (0x3DE8_0000, 0x3DED_FFFF), (0x3DF0_0000, 0x3DF3_FFFF),
    (0x5144_0000, 0x5147_FFFF), (0x529C_0000, 0x529D_FFFF),
    (0x6504_0000, 0x6507_FFFF), (0x6510_0000, 0x651F_FFFF),
    (0x6522_0000, 0x6525_FFFF), (0x6528_0000, 0x652B_FFFF),
    (0x6540_0000, 0x655F_FFFF), (0x657C_0000, 0x657F_FFFF),
    (0x6584_0000, 0x6585_FFFF), (0x65C8_0000, 0x65C9_FFFF),
    (0x65E0_0000, 0x65FF_FFFF), (0x6A02_0000, 0x6A0F_FFFF),
    (0x6A20_0000, 0x6A3F_FFFF), (0x6A4A_0000, 0x6A4B_FFFF),
    (0x6A50_0000, 0x6A5F_FFFF), (0x6A70_0000, 0x6A7F_FFFF),
    (0x6AE0_0000, 0x6AEF_FFFF), (0x6E34_0000, 0x6E37_FFFF),
    (0x6E48_0000, 0x6E5F_FFFF), (0x6E98_0000, 0x6E9F_FFFF),
    (0x6EA6_0000, 0x6EA7_FFFF), (0x6EB0_0000, 0x6EBF_FFFF),
    (0x6EC8_0000, 0x6ECF_FFFF), (0x6EF0_0000, 0x6F3F_FFFF),
    (0x6F48_0000, 0x6F4F_FFFF), (0x6F70_0000, 0x6FBF_FFFF),
    (0x6FE0_0000, 0x6FEF_FFFF), (0x7000_0000, 0x7077_FFFF),
    (0x707A_0000, 0x707F_FFFF), (0x70C0_0000, 0x70C3_FFFF),
    (0x70E0_0000, 0x711F_FFFF), (0x7138_0000, 0x713B_FFFF),
    (0x7140_0000, 0x718F_FFFF), (0x71C2_0000, 0x71C3_FFFF),
    (0x71C8_0000, 0x71FF_FFFF), (0x7240_0000, 0x727F_FFFF),
    (0x7284_0000, 0x7284_FFFF), (0x72D4_0000, 0x72FF_FFFF),
    (0x7310_0000, 0x731F_FFFF), (0x7330_0000, 0x733F_FFFF),
    (0x7396_0000, 0x739F_FFFF), (0x73A8_0000, 0x73AB_FFFF),
    (0x73C0_0000, 0x73EF_FFFF), (0x7401_0000, 0x741F_FFFF),
    (0x7434_0000, 0x7437_FFFF), (0x743E_0000, 0x743F_FFFF),
    (0x7470_0000, 0x74BF_FFFF), (0x74C4_0000, 0x74C7_FFFF),
    (0x74CC_0000, 0x74FF_FFFF), (0x7508_0000, 0x750F_FFFF),
    (0x7518_0000, 0x752F_FFFF), (0x753C_0000, 0x755F_FFFF),
    (0x7580_0000, 0x75BF_FFFF), (0x7618_0000, 0x761F_FFFF),
    (0x7648_0000, 0x764F_FFFF), (0x7670_0000, 0x767F_FFFF),
    (0x7690_0000, 0x7691_FFFF), (0x76B2_0000, 0x76BB_FFFF),
    (0x76BE_0000, 0x76C3_FFFF), (0x76F4_0000, 0x771B_FFFF),
    (0x771C_1C1C, 0x771C_1C1C), (0x771D_0000, 0x771D_FFFF),
    (0x7720_0000, 0x773B_FFFF), (0x7754_0000, 0x7757_FFFF),
    (0x7760_0000, 0x77BF_FFFF), (0x7800_0000, 0x780F_FFFF),
    (0x7818_0000, 0x781B_FFFF), (0x7820_0000, 0x7837_FFFF),
    (0x7840_0000, 0x785F_FFFF), (0x7880_0000, 0x788F_FFFF),
    (0x78C0_0000, 0x78FF_FFFF), (0x7904_0000, 0x7905_FFFF),
    (0x7908_0000, 0x792B_FFFF), (0x7930_0000, 0x7933_FFFF),
    (0x7938_0000, 0x7947_FFFF), (0x794C_0000, 0x794F_FFFF),
    (0x79C0_0000, 0x79C7_FFFF), (0x79CC_0000, 0x79CF_FFFF),
    (0x79E0_0000, 0x79FF_FFFF), (0x7A04_0000, 0x7A07_FFFF),
    (0x7A40_0000, 0x7A67_FFFF), (0x7A70_0000, 0x7A73_FFFF),
    (0x7A88_0000, 0x7A8F_FFFF), (0x7ABC_0000, 0x7ACF_FFFF),
    (0x7AE0_0000, 0x7AFF_FFFF), (0x7B04_0000, 0x7B0F_FFFF),
    (0x7B30_0000, 0x7B37_FFFF), (0x7B3C_0000, 0x7B3C_FFFF),
    (0x7B70_0000, 0x7BBF_FFFF), (0x7BCE_0000, 0x7BCF_FFFF),
    (0x7BE8_0000, 0x7BEF_FFFF), (0x7C40_0000, 0x7C43_FFFF),
    (0x7C46_0000, 0x7C4F_FFFF), (0x7C58_0000, 0x7C7F_FFFF),
    (0x7CA0_0000, 0x7CAF_FFFF), (0x7CC0_0000, 0x7CC3_FFFF),
    (0x7CC8_0000, 0x7CCF_FFFF), (0x7CDC_0000, 0x7CFF_FFFF),
    (0x7D20_0000, 0x7D5F_FFFF), (0x7D68_0000, 0x7D7F_FFFF),
    (0x7DD8_0000, 0x7DDF_FFFF), (0x8B09_0000, 0x8B09_FFFF),
    (0x8B9B_0000, 0x8B9B_FFFF), (0x8B9F_0000, 0x8B9F_FFFF),
    (0x8BC4_0000, 0x8BC4_FFFF), (0x8BC6_0000, 0x8BC7_FFFF),
    (0x8BE0_0000, 0x8BE0_FFFF), (0x8C8F_0000, 0x8C8F_FFFF),
    (0x8CCD_0000, 0x8CCF_FFFF), (0x969E_0000, 0x969E_FFFF),
    (0x9888_0000, 0x9888_FFFF), (0x9900_0000, 0x9907_FFFF),
    (0x9920_0000, 0x9927_FFFF), (0x9F4B_0000, 0x9F4B_FFFF),
    (0xA20E_0000, 0xA20E_FFFF), (0xA66F_0000, 0xA66F_FFFF),
    (0xAB08_0000, 0xAB0F_FFFF), (0xAB22_0000, 0xAB2F_FFFF),
    (0xAB50_0000, 0xAB6F_FFFF), (0xABD0_0000, 0xABDF_FFFF),
    (0xAF00_0000, 0xAF1F_FFFF), (0xAF2A_0000, 0xAF2B_FFFF),
    (0xAF92_0000, 0xAFAF_FFFF), (0xB44C_0000, 0xB44C_FFFF),
    (0xB460_0000, 0xB47F_FFFF), (0xB488_0000, 0xB48F_FFFF),
    (0xB498_0000, 0xB4AF_FFFF), (0xB4B8_0000, 0xB4B8_FFFF),
    (0xB620_0000, 0xB62F_FFFF), (0xB650_0000, 0xB69F_FFFF),
    (0xB6C8_0000, 0xB6CF_FFFF), (0xB6F0_0000, 0xB747_FFFF),
    (0xB780_0000, 0xB7AF_FFFF), (0xB7B8_0000, 0xB7FF_FFFF),
    (0xCA60_0000, 0xCA7F_FFFF), (0xCAC0_0000, 0xCADF_FFFF),
    (0xD202_0400, 0xD202_04FF), (0xD215_0000, 0xD216_FFFF),
    (0xD21C_0000, 0xD22F_FFFF), (0xD233_0000, 0xD235_FFFF),
    (0xD248_0000, 0xD24F_FFFF), (0xD2C0_0000, 0xD2C0_FFFF),
    (0xD340_0000, 0xD36F_FFFF), (0xD388_0000, 0xD3A7_FFFF),
    (0xDA00_0000, 0xDA1F_FFFF), (0xDA38_0000, 0xDA5F_FFFF),
    (0xDA68_0000, 0xDA6D_FFFF), (0xDAC0_0000, 0xDACF_FFFF),
    (0xDAF0_0000, 0xDAF7_FFFF), (0xDB80_0000, 0xDB9F_FFFF),
    (0xDBD0_0000, 0xDBDF_FFFF), (0xDBE8_0000, 0xDBEF_FFFF),
    (0xDCA0_0000, 0xDCCF_FFFF), (0xDCF8_0000, 0xDCFB_FFFF),
    (0xDD00_0000, 0xDD0F_FFFF), (0xDDB0_0000, 0xDDEF_FFFF),
    (0xDE10_0000, 0xDEDF_FFFF), (0xDEF0_0000, 0xDEFF_FFFF),
    (0xDF04_0000, 0xDF07_FFFF), (0xDF40_0000, 0xDF7F_FFFF),
    (0xDFA0_0000, 0xDFA7_FFFF), (0xDFC6_0000, 0xDFC7_FFFF),
    (0xDFD0_0000, 0xDFDF_FFFF), (0xDFF0_0000, 0xDFFF_FFFF),
];

/// Binary-search whether `ip` falls inside China Mainland's compact public IPv4 table (O(log N),
/// zero allocations).
#[inline]
pub fn is_domestic_ipv4(ip: Ipv4Addr) -> bool {
    let target = u32::from(ip);
    CN_IPV4_RANGES
        .binary_search_by(|&(start, end)| {
            if target < start {
                std::cmp::Ordering::Greater
            } else if target > end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Built-in core OS and CatCloud process names unconditionally excluded from transparent
/// WinDivert interception (case-insensitive) to guarantee system stability and zero loops.
const SYSTEM_AND_SELF_EXCLUDED_PROCESSES: &[&str] = &[
    "system",
    "idle",
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "smss.exe",
    "services.exe",
    "wininit.exe",
    "winlogon.exe",
    "catcloud.exe",
    "catcloud-desktop.exe",
    "catcloud-probe-core.exe",
];

// ============================================================================
// A. Standalone Lightweight Domestic :443 Dual-Active Tunnel (Cross-Platform)
// ============================================================================

/// Compile a minimal, zero-TUN, zero-DNS, zero-controller Mihomo YAML configuration for
/// the standalone domestic :443 active-standby pre-acceleration SOCKS5 tunnel.
///
/// Backward-compatible wrapper compiling without explicit `interface-name` binding.
pub fn compile_standalone_preaccel_yaml(
    cfg: &AppConfig,
    relays: &[PreAccelRelay],
    socks_port: u16,
) -> CatResult<String> {
    compile_standalone_preaccel_yaml_with_interface(cfg, relays, socks_port, None)
}

/// Compile the standalone domestic `:443` dual-active SOCKS5 tunnel YAML, optionally pinning
/// outbound sockets to a confirmed physical exit NIC (`interface-name`) so third-party VPN/TUN
/// adapters cannot hijack or loop CatCloud's domestic `:443` relay connections.
pub fn compile_standalone_preaccel_yaml_with_interface(
    cfg: &AppConfig,
    relays: &[PreAccelRelay],
    socks_port: u16,
    physical_interface: Option<&str>,
) -> CatResult<String> {
    if socks_port == 0 {
        return Err(CatError::Validation(
            "standalone pre-acceleration socks_port must be within 1..=65535".to_string(),
        ));
    }

    let mut sanitized_relays: Vec<PreAccelRelay> = relays
        .iter()
        .filter(|r| r.enabled)
        .map(|r| {
            if r.port == 443 {
                sanitize_relay_for_domestic_443(r)
            } else {
                r.clone()
            }
        })
        .collect();
    sanitized_relays.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));

    if sanitized_relays.is_empty() {
        return Err(CatError::Validation(
            "没有已启用的国内 443 中转节点，无法编译独立国内提速隧道配置".to_string(),
        ));
    }

    // Force `enabled = true` on a cloned config so standalone pre-accel can run independently
    // even while CatCloud's primary proxy or dialer-proxy toggle is off.
    let mut standalone_preaccel: PreAccelConfig = cfg.preaccel.clone();
    standalone_preaccel.enabled = true;

    let plan = build_preaccel_compile_plan(&standalone_preaccel, &sanitized_relays, &[])?;
    if !plan.active || plan.relay_proxies.is_empty() {
        return Err(CatError::Validation(
            "独立 443 国内提速隧道未能生成有效中转节点配置".to_string(),
        ));
    }

    let mut root = Mapping::new();
    root.insert(
        Value::String("socks-port".to_string()),
        Value::Number(Number::from(socks_port)),
    );
    root.insert(
        Value::String("bind-address".to_string()),
        Value::String("127.0.0.1".to_string()),
    );
    root.insert(Value::String("allow-lan".to_string()), Value::Bool(false));
    if let Some(iface) = physical_interface.map(str::trim).filter(|s| !s.is_empty()) {
        root.insert(
            Value::String("interface-name".to_string()),
            Value::String(iface.to_string()),
        );
    }
    root.insert(
        Value::String("mode".to_string()),
        Value::String("rule".to_string()),
    );
    root.insert(
        Value::String("log-level".to_string()),
        Value::String("warning".to_string()),
    );
    root.insert(Value::String("ipv6".to_string()), Value::Bool(false));
    root.insert(
        Value::String("find-process-mode".to_string()),
        Value::String("off".to_string()),
    );
    root.insert(
        Value::String("keep-alive-idle".to_string()),
        Value::Number(Number::from(45u64)),
    );
    root.insert(
        Value::String("keep-alive-interval".to_string()),
        Value::Number(Number::from(15u64)),
    );
    root.insert(
        Value::String("geo-auto-update".to_string()),
        Value::Bool(false),
    );
    root.insert(
        Value::String("geodata-mode".to_string()),
        Value::Bool(false),
    );
    root.insert(
        Value::String("geodata-loader".to_string()),
        Value::String("memconservative".to_string()),
    );

    let mut profile_map = Mapping::new();
    profile_map.insert(
        Value::String("store-selected".to_string()),
        Value::Bool(false),
    );
    profile_map.insert(
        Value::String("store-fake-ip".to_string()),
        Value::Bool(false),
    );
    root.insert(
        Value::String("profile".to_string()),
        Value::Mapping(profile_map),
    );

    let mut tun_map = Mapping::new();
    tun_map.insert(Value::String("enable".to_string()), Value::Bool(false));
    root.insert(Value::String("tun".to_string()), Value::Mapping(tun_map));

    let mut dns_map = Mapping::new();
    dns_map.insert(Value::String("enable".to_string()), Value::Bool(false));
    root.insert(Value::String("dns".to_string()), Value::Mapping(dns_map));

    root.insert(
        Value::String("proxies".to_string()),
        Value::Sequence(plan.relay_proxies),
    );
    root.insert(
        Value::String("proxy-groups".to_string()),
        Value::Sequence(plan.proxy_groups),
    );

    let mut rules: Vec<String> = Vec::with_capacity(sanitized_relays.len() + 12);
    let mut seen: HashSet<String> = HashSet::new();

    // Only emit anti-loop DIRECT rules for the enabled domestic relay endpoints themselves
    // (explicitly excluding `probe_url` / domestic 204 endpoints) so dataplane self-test
    // probes arriving over SOCKS5 must traverse the :443 relay group instead of bypassing via DIRECT.
    for relay in &sanitized_relays {
        if let Some(rule) = host_to_direct_rule(&relay.server) {
            let key = rule.to_ascii_lowercase();
            if seen.insert(key) {
                rules.push(rule);
            }
        }
    }

    const PRIVATE_DIRECT_RULES: &[&str] = &[
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
        "IP-CIDR6,::1/128,DIRECT,no-resolve",
        "IP-CIDR6,fc00::/7,DIRECT,no-resolve",
        "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
    ];
    for rule in PRIVATE_DIRECT_RULES {
        let key = rule.to_ascii_lowercase();
        if seen.insert(key) {
            rules.push((*rule).to_string());
        }
    }

    rules.push(format!("MATCH,{PREACCEL_SELECT_GROUP}"));

    root.insert(
        Value::String("rules".to_string()),
        Value::Sequence(rules.into_iter().map(Value::String).collect()),
    );

    let yaml = serde_yaml_ng::to_string(&Value::Mapping(root))?;
    Ok(yaml)
}

/// Managed lightweight Mihomo subprocess serving the standalone domestic :443 dual-active
/// SOCKS5 tunnel on `127.0.0.1:<socks_port>`.
///
/// Enforces `GOMEMLIMIT=48MiB`, `GOGC=25`, `GODEBUG=madvdontneed=1`, `CREATE_NO_WINDOW` on
/// Windows, `JobGuard` registration, and deterministic termination on `stop()` and `Drop`.
#[derive(Debug)]
pub struct StandalonePreAccelTunnel {
    child: Option<Child>,
    pid: Option<u32>,
    process_start_time_unix: Option<u64>,
    binary_path: PathBuf,
    socks_port: u16,
    work_dir: PathBuf,
    config_path: PathBuf,
    config_sha256: String,
    active_relays: Vec<String>,
    bound_physical_interface: Option<String>,
    job_guard: Arc<JobGuard>,
}

impl StandalonePreAccelTunnel {
    /// Compile and launch an isolated standalone :443 pre-acceleration Mihomo subprocess.
    ///
    /// On Windows, automatically detects the primary active physical exit NIC (e.g. `WLAN` or
    /// `以太网`) and pins `interface-name` so third-party proxy TUN adapters cannot hijack
    /// CatCloud's domestic `:443` relay connections; if binding that interface fails on an
    /// unusual adapter setup, automatically retries once without `interface-name`.
    pub async fn start(
        paths: &AppPaths,
        cfg: &AppConfig,
        relays: &[PreAccelRelay],
        job_guard: Arc<JobGuard>,
        preferred_socks_port: Option<u16>,
    ) -> CatResult<Self> {
        let bin_res = resolve_mihomo_binary(cfg, paths, &[], false)?;
        let mihomo_bin = bin_res.path.ok_or_else(|| {
            CatError::NotFound(
                "未找到 Mihomo 内核二进制文件，无法启动独立 443 国内提速隧道".to_string(),
            )
        })?;

        #[cfg(target_os = "windows")]
        let detected_physical_if: Option<String> = tokio::task::spawn_blocking(|| {
            super::windivert_win::detect_primary_physical_interface().map(|i| i.friendly_name)
        })
        .await
        .ok()
        .flatten();
        #[cfg(not(target_os = "windows"))]
        let detected_physical_if: Option<String> = None;

        if let Some(ref iface) = detected_physical_if {
            match Self::start_with_interface(
                paths,
                &mihomo_bin,
                cfg,
                relays,
                Arc::clone(&job_guard),
                preferred_socks_port,
                Some(iface.as_str()),
            )
            .await
            {
                Ok(tunnel) => return Ok(tunnel),
                Err(err) => {
                    tracing::warn!(
                        "standalone 443 tunnel failed with interface-name `{iface}` ({err}); retrying without explicit interface binding"
                    );
                }
            }
        }

        Self::start_with_interface(
            paths,
            &mihomo_bin,
            cfg,
            relays,
            job_guard,
            preferred_socks_port,
            None,
        )
        .await
    }

    async fn start_with_interface(
        paths: &AppPaths,
        mihomo_bin: &Path,
        cfg: &AppConfig,
        relays: &[PreAccelRelay],
        job_guard: Arc<JobGuard>,
        preferred_socks_port: Option<u16>,
        physical_interface: Option<&str>,
    ) -> CatResult<Self> {
        let socks_port = allocate_loopback_tcp_port(preferred_socks_port, cfg)?;
        let yaml = compile_standalone_preaccel_yaml_with_interface(
            cfg,
            relays,
            socks_port,
            physical_interface,
        )?;
        let bound_physical_interface = physical_interface
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string);

        let active_relays: Vec<String> = {
            let mut enabled: Vec<&PreAccelRelay> = relays.iter().filter(|r| r.enabled).collect();
            enabled.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));
            enabled
                .into_iter()
                .map(|r| {
                    if !r.name.trim().is_empty() {
                        r.name.trim().to_string()
                    } else {
                        r.id.trim().to_string()
                    }
                })
                .collect()
        };

        let work_dir = paths.runtime_dir.join("global-preaccel");
        std::fs::create_dir_all(&work_dir)?;
        let config_path = work_dir.join("standalone-preaccel.yaml");
        let config_sha256 = hex::encode(Sha256::digest(yaml.as_bytes()));
        AppPaths::atomic_write(&config_path, yaml.as_bytes())?;

        let stderr_path = work_dir.join("standalone-preaccel-stderr.log");
        let stderr_stdio = std::fs::File::create(&stderr_path)
            .map(Stdio::from)
            .unwrap_or_else(|_| Stdio::null());

        let norm_bin = normalize_os_path(mihomo_bin);
        let norm_work = normalize_os_path(&work_dir);
        let norm_cfg = normalize_os_path(&config_path);

        let mut cmd = Command::new(&norm_bin);
        cmd.arg("-d")
            .arg(&norm_work)
            .arg("-f")
            .arg(&norm_cfg)
            .env("GOMEMLIMIT", STANDALONE_TUNNEL_GOMEMLIMIT)
            .env("GOGC", STANDALONE_TUNNEL_GOGC)
            .env("GODEBUG", "madvdontneed=1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr_stdio)
            .kill_on_drop(true);
        JobGuard::configure_tokio_command(&mut cmd);

        let mut child = cmd.spawn().map_err(|e| {
            CatError::Process(format!(
                "启动独立 443 国内提速隧道 Mihomo 进程失败 ({}): {e}",
                mihomo_bin.display()
            ))
        })?;

        if let Err(err) = job_guard.assign_tokio_child(&mut child) {
            let _ = child.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
            return Err(err);
        }

        let pid = child.id();
        let process_start_time_unix = pid
            .and_then(crate::platform::get_process_start_time_unix)
            .or_else(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .ok()
                    .map(|d| d.as_secs())
            });
        let deadline = Instant::now() + STANDALONE_TUNNEL_READY_TIMEOUT;
        let target_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, socks_port);

        while Instant::now() < deadline {
            if let Ok(Some(status)) = child.try_wait() {
                if let Some(p) = pid {
                    job_guard.unregister_pid(p);
                }
                let detail = read_stderr_tail(&stderr_path, 2048);
                let msg = if detail.is_empty() {
                    format!("独立 443 国内提速隧道启动失败并提前退出 ({status})")
                } else {
                    format!("独立 443 国内提速隧道启动失败并提前退出 ({status}): {detail}")
                };
                return Err(CatError::Core(msg));
            }

            if tokio::time::timeout(
                Duration::from_millis(250),
                TcpStream::connect(target_addr),
            )
            .await
            .is_ok_and(|res| res.is_ok())
            {
                return Ok(Self {
                    child: Some(child),
                    pid,
                    process_start_time_unix,
                    binary_path: norm_bin,
                    socks_port,
                    work_dir,
                    config_path,
                    config_sha256,
                    active_relays,
                    bound_physical_interface,
                    job_guard,
                });
            }

            tokio::time::sleep(STANDALONE_TUNNEL_POLL_INTERVAL).await;
        }

        let _ = child.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
        if let Some(p) = pid {
            job_guard.unregister_pid(p);
        }
        let detail = read_stderr_tail(&stderr_path, 2048);
        let msg = if detail.is_empty() {
            format!("独立 443 国内提速隧道在超时前未能在 127.0.0.1:{socks_port} 就绪")
        } else {
            format!("独立 443 国内提速隧道未能在 127.0.0.1:{socks_port} 就绪: {detail}")
        };
        Err(CatError::Core(msg))
    }

    pub fn pid(&self) -> Option<u32> {
        self.pid
    }

    pub fn process_start_time_unix(&self) -> Option<u64> {
        self.process_start_time_unix
    }

    pub fn binary_path(&self) -> &Path {
        &self.binary_path
    }

    pub fn socks_port(&self) -> u16 {
        self.socks_port
    }

    pub fn active_relays(&self) -> &[String] {
        &self.active_relays
    }

    pub fn bound_physical_interface(&self) -> Option<&str> {
        self.bound_physical_interface.as_deref()
    }

    pub fn work_dir(&self) -> &Path {
        &self.work_dir
    }

    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub fn config_sha256(&self) -> &str {
        &self.config_sha256
    }

    /// Gracefully terminate the standalone Mihomo subprocess and reap its handle.
    pub async fn stop(&mut self) {
        let exited_pid = self.pid.take();
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(3), child.wait()).await;
        }
        if let Some(pid) = exited_pid {
            #[cfg(unix)]
            {
                let pgid = pid as i32;
                if pgid > 1 {
                    // SAFETY: Terminating the dedicated process group created via `setpgid(0, 0)`.
                    unsafe {
                        let _ = libc::kill(-pgid, libc::SIGTERM);
                    }
                    tokio::time::sleep(Duration::from_millis(60)).await;
                    unsafe {
                        let _ = libc::kill(-pgid, libc::SIGKILL);
                    }
                }
            }
            self.job_guard.unregister_pid(pid);
        }
    }
}

impl Drop for StandalonePreAccelTunnel {
    fn drop(&mut self) {
        let exited_pid = self.pid.take();
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
        }
        if let Some(pid) = exited_pid {
            #[cfg(unix)]
            {
                let pgid = pid as i32;
                if pgid > 1 {
                    // SAFETY: Synchronous fallback kill for the child process group on Drop.
                    unsafe {
                        let _ = libc::kill(-pgid, libc::SIGKILL);
                    }
                }
            }
            self.job_guard.unregister_pid(pid);
        }
    }
}

fn allocate_loopback_tcp_port(preferred: Option<u16>, cfg: &AppConfig) -> CatResult<u16> {
    let avoid: HashSet<u16> = [
        cfg.mixed_port,
        cfg.controller_port,
        cfg.dns_listen_port,
        cfg.socks_port.unwrap_or(0),
        cfg.http_port.unwrap_or(0),
        cfg.redir_port.unwrap_or(0),
        cfg.tproxy_port.unwrap_or(0),
    ]
    .into_iter()
    .filter(|&p| p > 0)
    .collect();

    if let Some(port) = preferred.filter(|&p| p > 0 && !avoid.contains(&p)) {
        if StdTcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)).is_ok() {
            return Ok(port);
        }
    }

    for _ in 0..32 {
        let listener = StdTcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        drop(listener);
        if port > 0 && !avoid.contains(&port) {
            return Ok(port);
        }
    }

    Err(CatError::Process(
        "无法为独立 443 国内提速隧道分配空闲本地回环 TCP 端口".to_string(),
    ))
}

fn read_stderr_tail(path: &Path, max_bytes: usize) -> String {
    let Ok(bytes) = std::fs::read(path) else {
        return String::new();
    };
    let slice = if bytes.len() > max_bytes {
        &bytes[bytes.len() - max_bytes..]
    } else {
        &bytes[..]
    };
    String::from_utf8_lossy(slice).trim().to_string()
}

// ============================================================================
// B. WinDivert v2.2.2 ABI, Locator, Verified Downloader, Filter & NAT Helpers
// ============================================================================

/// Exact 80-byte binary layout matching official `basil00/Divert` v2.2.2 `WINDIVERT_ADDRESS`.
///
/// Layout (little-endian Windows x64 ABI):
/// - `timestamp`: `i64` (bytes 0..8)
/// - `flags_lo`: `u32` (bytes 8..12) packing:
///   - bits `0..=7`: `Layer` (8 bits)
///   - bits `8..=15`: `Event` (8 bits)
///   - bit `16`: `Sniffed`
///   - bit `17`: `Outbound`
///   - bit `18`: `Loopback`
///   - bit `19`: `Impostor`
///   - bit `20`: `IPv6`
///   - bit `21`: `IPChecksum`
///   - bit `22`: `TCPChecksum`
///   - bit `23`: `UDPChecksum`
///   - bits `24..=31`: `Reserved1`
/// - `reserved2`: `u32` (bytes 12..16)
/// - `data`: `[u8; 64]` (bytes 16..80), union beginning with `WINDIVERT_DATA_NETWORK { IfIdx: u32, SubIfIdx: u32 }`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WinDivertAddress {
    pub timestamp: i64,
    pub flags_lo: u32,
    pub reserved2: u32,
    pub data: [u8; 64],
}

const _: () = assert!(std::mem::size_of::<WinDivertAddress>() == 80);

impl Default for WinDivertAddress {
    fn default() -> Self {
        Self {
            timestamp: 0,
            flags_lo: 0,
            reserved2: 0,
            data: [0u8; 64],
        }
    }
}

impl WinDivertAddress {
    const BIT_SNIFFED: u32 = 1 << 16;
    const BIT_OUTBOUND: u32 = 1 << 17;
    const BIT_LOOPBACK: u32 = 1 << 18;
    const BIT_IMPOSTOR: u32 = 1 << 19;
    const BIT_IPV6: u32 = 1 << 20;
    const BIT_IP_CHECKSUM: u32 = 1 << 21;
    const BIT_TCP_CHECKSUM: u32 = 1 << 22;
    const BIT_UDP_CHECKSUM: u32 = 1 << 23;

    pub fn layer(&self) -> u8 {
        (self.flags_lo & 0xFF) as u8
    }

    pub fn set_layer(&mut self, layer: u8) {
        self.flags_lo = (self.flags_lo & !0xFF) | u32::from(layer);
    }

    pub fn event(&self) -> u8 {
        ((self.flags_lo >> 8) & 0xFF) as u8
    }

    pub fn set_event(&mut self, event: u8) {
        self.flags_lo = (self.flags_lo & !(0xFF << 8)) | (u32::from(event) << 8);
    }

    pub fn sniffed(&self) -> bool {
        (self.flags_lo & Self::BIT_SNIFFED) != 0
    }

    pub fn set_sniffed(&mut self, value: bool) {
        self.set_bit(Self::BIT_SNIFFED, value);
    }

    pub fn outbound(&self) -> bool {
        (self.flags_lo & Self::BIT_OUTBOUND) != 0
    }

    pub fn set_outbound(&mut self, value: bool) {
        self.set_bit(Self::BIT_OUTBOUND, value);
    }

    pub fn loopback(&self) -> bool {
        (self.flags_lo & Self::BIT_LOOPBACK) != 0
    }

    pub fn set_loopback(&mut self, value: bool) {
        self.set_bit(Self::BIT_LOOPBACK, value);
    }

    pub fn impostor(&self) -> bool {
        (self.flags_lo & Self::BIT_IMPOSTOR) != 0
    }

    pub fn set_impostor(&mut self, value: bool) {
        self.set_bit(Self::BIT_IMPOSTOR, value);
    }

    pub fn ipv6(&self) -> bool {
        (self.flags_lo & Self::BIT_IPV6) != 0
    }

    pub fn set_ipv6(&mut self, value: bool) {
        self.set_bit(Self::BIT_IPV6, value);
    }

    pub fn ip_checksum(&self) -> bool {
        (self.flags_lo & Self::BIT_IP_CHECKSUM) != 0
    }

    pub fn set_ip_checksum(&mut self, value: bool) {
        self.set_bit(Self::BIT_IP_CHECKSUM, value);
    }

    pub fn tcp_checksum(&self) -> bool {
        (self.flags_lo & Self::BIT_TCP_CHECKSUM) != 0
    }

    pub fn set_tcp_checksum(&mut self, value: bool) {
        self.set_bit(Self::BIT_TCP_CHECKSUM, value);
    }

    pub fn udp_checksum(&self) -> bool {
        (self.flags_lo & Self::BIT_UDP_CHECKSUM) != 0
    }

    pub fn set_udp_checksum(&mut self, value: bool) {
        self.set_bit(Self::BIT_UDP_CHECKSUM, value);
    }

    pub fn network_if_idx(&self) -> u32 {
        u32::from_ne_bytes([self.data[0], self.data[1], self.data[2], self.data[3]])
    }

    pub fn set_network_if_idx(&mut self, if_idx: u32) {
        let bytes = if_idx.to_ne_bytes();
        self.data[0..4].copy_from_slice(&bytes);
    }

    pub fn network_sub_if_idx(&self) -> u32 {
        u32::from_ne_bytes([self.data[4], self.data[5], self.data[6], self.data[7]])
    }

    pub fn set_network_sub_if_idx(&mut self, sub_if_idx: u32) {
        let bytes = sub_if_idx.to_ne_bytes();
        self.data[4..8].copy_from_slice(&bytes);
    }

    fn set_bit(&mut self, mask: u32, value: bool) {
        if value {
            self.flags_lo |= mask;
        } else {
            self.flags_lo &= !mask;
        }
    }
}

/// Co-located WinDivert user-mode DLL and kernel-mode `.sys` driver paths.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WinDivertPaths {
    pub dll_path: PathBuf,
    pub sys_path: PathBuf,
}

/// Locate co-located `WinDivert64.dll` (or `WinDivert.dll`) and `WinDivert64.sys` in strict
/// priority order: `custom_dir` -> `paths.bin_dir` -> `<exe_dir>/resources/bin` -> `<exe_dir>`.
///
/// Short-circuits immediately to `None` with zero filesystem IO on non-Windows hosts and on
/// Windows ARM64 (where official WinDivert v2.2.2 provides no native ARM64 kernel driver).
pub fn locate_windivert_files(
    paths: &AppPaths,
    custom_dir: Option<&str>,
) -> Option<(PathBuf, PathBuf)> {
    #[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
    {
        let _ = (paths, custom_dir);
        None
    }
    #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
    {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf));
        locate_windivert_files_with_exe_dir(paths, custom_dir, exe_dir.as_deref())
    }
}

/// Convenience wrapper returning a structured `WinDivertPaths` from `locate_windivert_files`.
pub fn locate_windivert_paths(
    paths: &AppPaths,
    custom_dir: Option<&str>,
) -> Option<WinDivertPaths> {
    locate_windivert_files(paths, custom_dir).map(|(dll_path, sys_path)| WinDivertPaths {
        dll_path,
        sys_path,
    })
}

/// Deterministic variant of `locate_windivert_files` accepting an explicit `exe_dir`.
pub fn locate_windivert_files_with_exe_dir(
    paths: &AppPaths,
    custom_dir: Option<&str>,
    exe_dir: Option<&Path>,
) -> Option<(PathBuf, PathBuf)> {
    #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
    {
        let _ = (paths, custom_dir, exe_dir);
        None
    }
    #[cfg(not(all(target_os = "windows", target_arch = "aarch64")))]
    {
        let mut candidate_dirs: Vec<PathBuf> = Vec::with_capacity(4);

        if let Some(raw_custom) = custom_dir.map(str::trim).filter(|s| !s.is_empty()) {
            let custom_path = PathBuf::from(raw_custom);
            if custom_path.is_file() {
                if let Some(parent) = custom_path.parent() {
                    candidate_dirs.push(parent.to_path_buf());
                }
            } else {
                candidate_dirs.push(custom_path);
            }
        }

        candidate_dirs.push(paths.bin_dir.clone());

        if let Some(dir) = exe_dir {
            candidate_dirs.push(dir.join("resources").join("bin"));
            candidate_dirs.push(dir.to_path_buf());
        }

        for dir in candidate_dirs {
            let sys_path = dir.join("WinDivert64.sys");
            if !sys_path.is_file() {
                continue;
            }
            for dll_name in ["WinDivert64.dll", "WinDivert.dll"] {
                let dll_path = dir.join(dll_name);
                if dll_path.is_file() {
                    return Some((normalize_os_path(&dll_path), normalize_os_path(&sys_path)));
                }
            }
        }

        None
    }
}

/// Normalize and deduplicate ordered proxy candidates (`Some("http://...")` / `None` direct),
/// preserving first-seen priority. Empty input defaults to `[None]` (direct connection).
pub fn normalize_windivert_proxy_candidates(
    raw_candidates: &[Option<String>],
) -> Vec<Option<String>> {
    if raw_candidates.is_empty() {
        return vec![None];
    }

    let mut out: Vec<Option<String>> = Vec::with_capacity(raw_candidates.len());
    let mut seen_direct = false;
    let mut seen_proxies: HashSet<String> = HashSet::new();

    for candidate in raw_candidates {
        match candidate
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(proxy) => {
                let key = proxy.trim_end_matches('/').to_ascii_lowercase();
                if seen_proxies.insert(key) {
                    out.push(Some(proxy.to_string()));
                }
            }
            None => {
                if !seen_direct {
                    seen_direct = true;
                    out.push(None);
                }
            }
        }
    }

    if out.is_empty() {
        out.push(None);
    }
    out
}

/// Convert an active, non-PAC `SystemProxySpec` into an HTTP proxy URL suitable for `reqwest::Proxy`.
pub fn format_system_proxy_url(spec: &crate::platform::SystemProxySpec) -> Option<String> {
    if !spec.enabled || spec.port == 0 {
        return None;
    }
    if spec
        .pac_url
        .as_deref()
        .map(str::trim)
        .is_some_and(|s| !s.is_empty())
    {
        return None;
    }
    let host = spec.host.trim();
    if host.is_empty() {
        return None;
    }
    if host.contains("://") {
        return Some(host.to_string());
    }
    if host.contains(':') && !host.starts_with('[') {
        Some(format!("http://[{host}]:{}", spec.port))
    } else {
        Some(format!("http://{host}:{}", spec.port))
    }
}

/// Build the standard 3-tier WinDivert download proxy fallback chain:
/// 1. CatCloud main core local mixed port (when running)
/// 2. Current OS active system proxy (e.g. an active third-party proxy on Windows)
/// 3. Direct connection (`None`)
pub fn build_default_windivert_proxy_candidates(
    catcloud_mixed_port: Option<u16>,
) -> Vec<Option<String>> {
    let mut raw: Vec<Option<String>> = Vec::with_capacity(3);
    if let Some(port) = catcloud_mixed_port.filter(|&p| p > 0) {
        raw.push(Some(format!("http://127.0.0.1:{port}")));
    }
    if let Ok(spec) = default_platform().read_system_proxy() {
        if let Some(url) = format_system_proxy_url(&spec) {
            raw.push(Some(url));
        }
    }
    raw.push(None);
    normalize_windivert_proxy_candidates(&raw)
}

/// Download official WinDivert v2.2.2 (`WinDivert-2.2.2-A.zip`) trying each proxy candidate in
/// deduplicated priority order (for example: CatCloud core -> active Windows system proxy ->
/// direct), strictly enforcing `ALLOWED_WINDIVERT_HOSTS` and `WINDIVERT_ZIP_SHA256` on every
/// attempt before extracting into `paths.bin_dir`.
///
/// Never writes to Windows system directories. Returns actionable Chinese guidance if an
/// antivirus or Windows Defender quarantines the driver binary, or if running on Windows ARM64.
pub async fn download_and_install_windivert_with_fallbacks(
    paths: &AppPaths,
    proxy_candidates: &[Option<String>],
) -> CatResult<PathBuf> {
    #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
    {
        let _ = (paths, proxy_candidates);
        Err(CatError::Validation(
            WINDIVERT_ARM64_UNSUPPORTED_MSG.to_string(),
        ))
    }

    #[cfg(not(all(target_os = "windows", target_arch = "aarch64")))]
    {
        crate::init_crypto_provider();

        let candidates = normalize_windivert_proxy_candidates(proxy_candidates);
        let total_attempts = candidates.len();
        let mut attempt_errors: Vec<String> = Vec::with_capacity(total_attempts);
        let mut last_err: Option<CatError> = None;

        for (idx, candidate) in candidates.iter().enumerate() {
            let has_more = idx + 1 < total_attempts;
            let connect_timeout = if has_more && candidate.is_some() {
                Duration::from_secs(8)
            } else {
                Duration::from_secs(15)
            };
            let total_timeout = if has_more && candidate.is_some() {
                Duration::from_secs(45)
            } else {
                Duration::from_secs(90)
            };

            let route_label = candidate.as_deref().unwrap_or("direct");
            match download_windivert_archive_once(
                candidate.as_deref(),
                connect_timeout,
                total_timeout,
            )
            .await
            {
                Ok(archive_bytes) => {
                    match verify_and_extract_windivert_zip(
                        &archive_bytes,
                        WINDIVERT_ZIP_SHA256,
                        &paths.bin_dir,
                    ) {
                        Ok(_) => return Ok(paths.bin_dir.clone()),
                        Err(err) => {
                            // Local disk / AV write interception cannot be solved by switching proxies.
                            let is_local_write_block = matches!(&err, CatError::Io(_))
                                || matches!(
                                    &err,
                                    CatError::Security(msg)
                                        if msg.contains("杀毒软件") || msg.contains("安全软件")
                                );
                            if is_local_write_block {
                                return Err(err);
                            }
                            attempt_errors.push(format!("[{route_label}] {err}"));
                            last_err = Some(err);
                        }
                    }
                }
                Err(err) => {
                    attempt_errors.push(format!("[{route_label}] {err}"));
                    last_err = Some(err);
                }
            }
        }

        if total_attempts == 1 {
            if let Some(err) = last_err {
                return Err(err);
            }
        }

        Err(CatError::Core(format!(
            "尝试 {total_attempts} 条下载通道后仍未能安装官方 WinDivert v2.2.2：{}",
            attempt_errors.join("；")
        )))
    }
}

/// Download official WinDivert v2.2.2 (`WinDivert-2.2.2-A.zip`), strictly verify its SHA-256
/// against `WINDIVERT_ZIP_SHA256`, and extract only `x64/WinDivert.dll` (installed as both
/// `WinDivert.dll` and `WinDivert64.dll`) and `x64/WinDivert64.sys` into `paths.bin_dir`.
///
/// Backward-compatible single-route wrapper delegating to
/// [`download_and_install_windivert_with_fallbacks`].
pub async fn download_and_install_windivert(
    paths: &AppPaths,
    proxy_url: Option<&str>,
) -> CatResult<PathBuf> {
    let candidate = proxy_url
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);
    download_and_install_windivert_with_fallbacks(paths, &[candidate]).await
}

#[cfg(not(all(target_os = "windows", target_arch = "aarch64")))]
async fn download_windivert_archive_once(
    proxy_url: Option<&str>,
    connect_timeout: Duration,
    total_timeout: Duration,
) -> CatResult<Vec<u8>> {
    let redirect_policy = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() > 5 {
            return attempt.error(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "WinDivert 下载重定向次数超限",
            ));
        }
        match validate_windivert_https_url(attempt.url().as_str()) {
            Ok(()) => attempt.follow(),
            Err(err) => attempt.error(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                err.to_string(),
            )),
        }
    });

    let mut builder = reqwest::Client::builder()
        .redirect(redirect_policy)
        .connect_timeout(connect_timeout)
        .timeout(total_timeout)
        .user_agent(format!("CatCloud/{}", env!("CARGO_PKG_VERSION")));

    if let Some(proxy) = proxy_url.map(str::trim).filter(|s| !s.is_empty()) {
        let parsed = reqwest::Proxy::all(proxy).map_err(|e| {
            CatError::Validation(format!("无效的 WinDivert 下载代理地址 `{proxy}`: {e}"))
        })?;
        builder = builder.proxy(parsed);
    } else {
        builder = builder.no_proxy();
    }

    let client = builder.build()?;
    let mut resp = client
        .get(WINDIVERT_DOWNLOAD_URL)
        .send()
        .await
        .map_err(|e| CatError::Core(format!("下载官方 WinDivert v2.2.2 失败: {e}")))?;

    if !resp.status().is_success() {
        return Err(CatError::Core(format!(
            "下载官方 WinDivert v2.2.2 失败，HTTP 状态码: {}",
            resp.status()
        )));
    }

    let mut archive_bytes: Vec<u8> = Vec::with_capacity(512 * 1024);
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| CatError::Core(format!("读取 WinDivert 下载流失败: {e}")))?
    {
        if archive_bytes.len().saturating_add(chunk.len()) > MAX_WINDIVERT_ZIP_BYTES {
            return Err(CatError::Security(format!(
                "WinDivert 压缩包超出安全体积上限 ({MAX_WINDIVERT_ZIP_BYTES} bytes)"
            )));
        }
        archive_bytes.extend_from_slice(&chunk);
    }

    Ok(archive_bytes)
}

#[cfg_attr(
    all(target_os = "windows", target_arch = "aarch64"),
    allow(dead_code)
)]
fn validate_windivert_https_url(raw: &str) -> CatResult<()> {
    let parsed = Url::parse(raw.trim())
        .map_err(|e| CatError::Security(format!("非法 WinDivert 下载地址: {e}")))?;
    if !parsed.scheme().eq_ignore_ascii_case("https") {
        return Err(CatError::Security(
            "WinDivert 下载仅允许 HTTPS 协议".to_string(),
        ));
    }
    let host = parsed
        .host_str()
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if !ALLOWED_WINDIVERT_HOSTS.iter().any(|h| *h == host) {
        return Err(CatError::Security(format!(
            "拦截了未授权的 WinDivert 下载域名: {host}"
        )));
    }
    Ok(())
}

/// Verify SHA-256 of a WinDivert ZIP archive and safely extract `x64/WinDivert.dll` (saved as
/// both `WinDivert.dll` and `WinDivert64.dll`) and `x64/WinDivert64.sys` into `dest_dir`.
pub fn verify_and_extract_windivert_zip(
    zip_bytes: &[u8],
    expected_sha256: &str,
    dest_dir: &Path,
) -> CatResult<WinDivertPaths> {
    let mut hasher = Sha256::new();
    hasher.update(zip_bytes);
    let actual_sha256 = hex::encode(hasher.finalize());
    if !actual_sha256.eq_ignore_ascii_case(expected_sha256.trim()) {
        return Err(CatError::Security(format!(
            "WinDivert 安装包 SHA-256 校验失败（期望 {}，实际 {}），已拒绝安装",
            expected_sha256.trim(),
            actual_sha256
        )));
    }

    let mut archive = ZipArchive::new(Cursor::new(zip_bytes))
        .map_err(|e| CatError::Validation(format!("WinDivert ZIP 压缩包损坏: {e}")))?;

    let mut dll_bytes: Option<Vec<u8>> = None;
    let mut sys_bytes: Option<Vec<u8>> = None;

    for idx in 0..archive.len() {
        let entry = archive
            .by_index(idx)
            .map_err(|e| CatError::Validation(format!("读取 WinDivert ZIP 条目失败: {e}")))?;
        if entry.is_dir() {
            continue;
        }
        let normalized = entry.name().replace('\\', "/");
        if normalized.starts_with('/')
            || normalized.contains("..")
            || normalized.contains(':')
        {
            return Err(CatError::Security(format!(
                "WinDivert ZIP 包含非法路径穿越条目: `{normalized}`"
            )));
        }

        let lower = normalized.to_ascii_lowercase();
        let is_target_dll = lower == "x64/windivert.dll" || lower.ends_with("/x64/windivert.dll");
        let is_target_sys =
            lower == "x64/windivert64.sys" || lower.ends_with("/x64/windivert64.sys");
        if !is_target_dll && !is_target_sys {
            continue;
        }

        if entry.size() > MAX_WINDIVERT_FILE_BYTES {
            return Err(CatError::Security(format!(
                "WinDivert 解压条目 `{normalized}` 超出大小限制"
            )));
        }

        let mut buf = Vec::with_capacity((entry.size() as usize).min(2 * 1024 * 1024));
        let mut limited = entry.take(MAX_WINDIVERT_FILE_BYTES + 1);
        limited.read_to_end(&mut buf)?;
        if (buf.len() as u64) > MAX_WINDIVERT_FILE_BYTES {
            return Err(CatError::Security(format!(
                "WinDivert 解压条目 `{normalized}` 实际大小超出限制"
            )));
        }

        if is_target_dll {
            dll_bytes = Some(buf);
        } else if is_target_sys {
            sys_bytes = Some(buf);
        }
    }

    let dll_data = dll_bytes.ok_or_else(|| {
        CatError::Validation("WinDivert ZIP 中缺少 `x64/WinDivert.dll`".to_string())
    })?;
    let sys_data = sys_bytes.ok_or_else(|| {
        CatError::Validation("WinDivert ZIP 中缺少 `x64/WinDivert64.sys`".to_string())
    })?;

    std::fs::create_dir_all(dest_dir)?;
    let dll_plain = dest_dir.join("WinDivert.dll");
    let dll_64 = dest_dir.join("WinDivert64.dll");
    let sys_64 = dest_dir.join("WinDivert64.sys");

    write_windivert_binary_with_av_hint(&dll_plain, &dll_data, dest_dir)?;
    write_windivert_binary_with_av_hint(&dll_64, &dll_data, dest_dir)?;
    write_windivert_binary_with_av_hint(&sys_64, &sys_data, dest_dir)?;

    if !dll_64.is_file() || !sys_64.is_file() {
        let products = detect_host_security_products();
        let guidance = build_security_guidance(&products, Some(dest_dir), "download_or_write");
        return Err(CatError::Security(format!(
            "WinDivert 驱动文件写入后被安全软件移除或隔离。{guidance}"
        )));
    }

    Ok(WinDivertPaths {
        dll_path: normalize_os_path(&dll_64),
        sys_path: normalize_os_path(&sys_64),
    })
}

fn write_windivert_binary_with_av_hint(
    target: &Path,
    bytes: &[u8],
    bin_dir: &Path,
) -> CatResult<()> {
    match AppPaths::atomic_write(target, bytes) {
        Ok(()) => Ok(()),
        Err(CatError::Io(io_err)) => {
            let av_blocked = io_err.kind() == std::io::ErrorKind::PermissionDenied
                || matches!(io_err.raw_os_error(), Some(5 | 225 | 226));
            if av_blocked {
                let products = detect_host_security_products();
                let guidance =
                    build_security_guidance(&products, Some(bin_dir), "download_or_write");
                Err(CatError::Security(format!(
                    "写入 `{}` 时被安全软件拦截（{}）。{guidance}",
                    target.display(),
                    io_err,
                )))
            } else {
                Err(CatError::Io(io_err))
            }
        }
        Err(other) => Err(other),
    }
}

/// Classify installed/active Windows security & firewall products from running process basenames.
///
/// Third-party security suites (Huorong, 360, Tencent PC Manager, Kaspersky, etc.) are ordered
/// ahead of built-in Windows Security (Defender) so user guidance targets the active filter first.
pub fn classify_security_products_from_process_names(process_names: &[String]) -> Vec<String> {
    let lowers: HashSet<String> = process_names
        .iter()
        .map(|raw| normalize_process_basename(raw))
        .filter(|s| !s.is_empty())
        .collect();

    const RULES: &[(&[&str], &str)] = &[
        (
            &["hipsdaemon.exe", "wsctrl.exe", "hipstray.exe", "hipsmain.exe"],
            "火绒安全",
        ),
        (
            &["360tray.exe", "360safe.exe", "zhudongfangyu.exe", "360sd.exe", "360rp.exe"],
            "360 安全卫士",
        ),
        (&["qqpctray.exe", "qqpcrtp.exe", "qqpcsvc.exe"], "腾讯电脑管家"),
        (&["avp.exe", "avpui.exe"], "卡巴斯基安全软件"),
        (&["ekrn.exe", "egui.exe"], "ESET 安全软件"),
        (&["bdagent.exe", "vsserv.exe"], "Bitdefender"),
        (&["mcshield.exe", "mfemms.exe"], "McAfee 安全软件"),
        (&["msmpeng.exe", "mpdefendercoreservice.exe"], "Windows 安全中心（Defender）"),
    ];

    let mut detected = Vec::new();
    for (patterns, label) in RULES {
        if patterns.iter().any(|p| lowers.contains(*p)) {
            detected.push((*label).to_string());
        }
    }
    detected
}

/// Read-only best-effort detection of security products active on the current host.
pub fn detect_host_security_products() -> Vec<String> {
    #[cfg(target_os = "windows")]
    {
        super::windivert_win::detect_windows_security_products()
    }
    #[cfg(not(target_os = "windows"))]
    {
        Vec::new()
    }
}

/// Build actionable, plain-Chinese security/firewall allowlist guidance tailored to the
/// host's detected security products (`stage`: `"download_or_write" | "driver_load" | "self_test_blocked"`).
pub fn build_security_guidance(
    products: &[String],
    bin_dir: Option<&Path>,
    stage: &str,
) -> String {
    let dir_hint = bin_dir
        .map(|d| format!("目录 `{}`", d.display()))
        .unwrap_or_else(|| "猫猫云梯所在目录".to_string());

    let primary = products.first().map(String::as_str);
    let action_desc = match stage {
        "download_or_write" => format!(
            "WinDivert v2.2.2 为官方签名开源网络过滤组件（已通过 SHA-256 校验），请将{dir_hint}加入信任/排除区后点击重试。"
        ),
        "driver_load" => format!(
            "请确认以管理员身份运行，并将{dir_hint}加入信任区；如近期装过其它网络加速/抓包软件，可重启电脑或关闭冲突拦截后重试。"
        ),
        _ => format!(
            "猫猫云梯已自动停止底层拦截以防止断网。请将{dir_hint}及主程序加入信任/网络放行区后，点击「重新探测」恢复自动加速。"
        ),
    };

    match primary {
        Some("火绒安全") => format!(
            "检测到当前电脑运行「火绒安全」：打开火绒 → 防护中心 → 信任区添加{dir_hint}（如开启联网控制/防火墙，一并放行猫猫云梯本地回环流量），然后重试。{action_desc}"
        ),
        Some("360 安全卫士") => format!(
            "检测到当前电脑运行「360 安全卫士」：打开 360 → 木马查杀/防护中心 → 信任区添加{dir_hint}，并在流量防火墙中放行猫猫云梯后重试。{action_desc}"
        ),
        Some("腾讯电脑管家") => format!(
            "检测到当前电脑运行「腾讯电脑管家」：打开电脑管家 → 病毒查杀 → 信任区添加{dir_hint}，放行猫猫云梯网络拦截组件后重试。{action_desc}"
        ),
        Some("Windows 安全中心（Defender）") => format!(
            "检测到当前为原生「Windows 安全中心（Defender）」：打开 Windows 安全中心 → 病毒和威胁防护 → 管理设置 → 添加排除项，将{dir_hint}加入文件夹排除项后重试。{action_desc}"
        ),
        Some(other) => format!(
            "检测到当前电脑运行「{other}」：请在该安全软件的信任/排除区中添加{dir_hint}并放行猫猫云梯的本地转发流量后重试。{action_desc}"
        ),
        None => format!(
            "如电脑开启了 Windows 安全中心、火绒或其它防火墙/杀毒软件，请将{dir_hint}加入信任排除项并放行本地转发后重试。{action_desc}"
        ),
    }
}

/// Build the high-precision WinDivert v2.2.2 kernel-mode packet filter string with configurable
/// native `:443` skipping.
///
/// Design invariants:
/// - Matches only IPv4 TCP traffic (`ip and tcp`).
/// - Outbound public interception excludes loopback (`!loopback`), port `53`, port `443` when
///   `skip_443_native == true`, all private/loopback/CGNAT/link-local/Fake-IP/multicast ranges,
///   all 13 domestic public DNS IPv4 endpoints, and every domestic `:443` relay public IPv4
///   address (to guarantee zero loops).
/// - Also captures return packets from the local self-loop redirector (`outbound and
///   tcp.SrcPort == <local_redirect_port>`) without excluding loopback on the return branch,
///   because same-NIC self-loop replies traverse Windows loopback on outbound.
/// - NEVER bypasses GeoIP CN at the kernel filter layer so domestic-transit airport entry IPs
///   on non-443 ports remain 100% accelerated.
pub fn build_windivert_filter_with_options(
    relay_ipv4s: &[Ipv4Addr],
    local_redirect_port: u16,
    skip_443_native: bool,
) -> String {
    let mut outbound_terms: Vec<String> = Vec::with_capacity(28 + relay_ipv4s.len());
    outbound_terms.push("!loopback".to_string());
    outbound_terms.push("outbound".to_string());
    if skip_443_native {
        outbound_terms.push("tcp.DstPort != 443".to_string());
    }
    outbound_terms.extend([
        "tcp.DstPort != 53".to_string(),
        // Exclude 0.0.0.0/8 (this network) and 224.0.0.0/3 (multicast/reserved/broadcast)
        "ip.DstAddr > 0.255.255.255".to_string(),
        "ip.DstAddr < 224.0.0.0".to_string(),
        // Exclude 10.0.0.0/8 (RFC 1918)
        "(ip.DstAddr < 10.0.0.0 or ip.DstAddr > 10.255.255.255)".to_string(),
        // Exclude 100.64.0.0/10 (RFC 6598 CGNAT)
        "(ip.DstAddr < 100.64.0.0 or ip.DstAddr > 100.127.255.255)".to_string(),
        // Exclude 127.0.0.0/8 (loopback)
        "(ip.DstAddr < 127.0.0.0 or ip.DstAddr > 127.255.255.255)".to_string(),
        // Exclude 169.254.0.0/16 (link-local APIPA)
        "(ip.DstAddr < 169.254.0.0 or ip.DstAddr > 169.254.255.255)".to_string(),
        // Exclude 172.16.0.0/12 (RFC 1918)
        "(ip.DstAddr < 172.16.0.0 or ip.DstAddr > 172.31.255.255)".to_string(),
        // Exclude 192.168.0.0/16 (RFC 1918)
        "(ip.DstAddr < 192.168.0.0 or ip.DstAddr > 192.168.255.255)".to_string(),
        // Exclude 198.18.0.0/15 (Fake-IP / RFC 2544 benchmark range)
        "(ip.DstAddr < 198.18.0.0 or ip.DstAddr > 198.19.255.255)".to_string(),
    ]);

    let mut excluded_dst_ips: BTreeSet<Ipv4Addr> =
        DOMESTIC_PUBLIC_DNS_IPV4S.iter().copied().collect();
    for &ip in relay_ipv4s {
        if !ip.is_unspecified() && !ip.is_loopback() {
            excluded_dst_ips.insert(ip);
        }
    }

    for ip in excluded_dst_ips {
        outbound_terms.push(format!("ip.DstAddr != {ip}"));
    }

    format!(
        "ip and tcp and (({}) or (outbound and ip.SrcAddr == 127.0.0.1 and ip.DstAddr == 127.0.0.1 and tcp.SrcPort == {}))",
        outbound_terms.join(" and "),
        local_redirect_port
    )
}

/// Backward-compatible wrapper calling [`build_windivert_filter_with_options`] with
/// `skip_443_native = true`.
pub fn build_windivert_filter(relay_ipv4s: &[Ipv4Addr], local_redirect_port: u16) -> String {
    build_windivert_filter_with_options(relay_ipv4s, local_redirect_port, true)
}

/// Three-layer guard deciding whether an outbound TCP `:443` flow may be intercepted by WinDivert:
/// 1. Rejected whenever `skip_443_native == true`.
/// 2. Strictly limited to precisely identified proxy-core labels (`system_proxy_host`,
///    `local_proxy_listener`, `open_core_name`), unconditionally bypassing `manual` and `scope_all`.
/// 3. Rejected when `dst_ip` is a China Mainland IPv4 address (`is_domestic_ipv4(dst_ip)`),
///    preventing direct domestic HTTPS traffic from detouring through the domestic relay.
#[inline]
pub fn should_intercept_port_443(
    detected_by: &str,
    skip_443_native: bool,
    dst_ip: Ipv4Addr,
) -> bool {
    if skip_443_native {
        return false;
    }
    matches!(
        detected_by,
        "system_proxy_host" | "local_proxy_listener" | "open_core_name"
    ) && !is_domestic_ipv4(dst_ip)
}

/// Extract distinct IPv4 addresses of enabled domestic relays (resolving domain relays on a
/// best-effort basis so kernel-level anti-loop exclusions stay complete).
pub fn collect_enabled_relay_ipv4s(relays: &[PreAccelRelay]) -> Vec<Ipv4Addr> {
    let mut set = BTreeSet::new();
    for relay in relays.iter().filter(|r| r.enabled) {
        let server = relay.server.trim();
        if server.is_empty() {
            continue;
        }
        if let Some(ip) = parse_server_ip(server) {
            if let IpAddr::V4(v4) = ip {
                set.insert(v4);
            }
            continue;
        }
        use std::net::ToSocketAddrs as _;
        if let Ok(addrs) = (server, relay.port).to_socket_addrs() {
            for addr in addrs {
                if let SocketAddr::V4(v4) = addr {
                    set.insert(*v4.ip());
                }
            }
        }
    }
    set.into_iter().collect()
}

/// Decide whether a Windows network interface row describes a real physical exit NIC
/// (Ethernet, Wi-Fi, PPPoE dial-up, or 4G/5G cellular WWAN), strictly excluding TUN/TAP,
/// Hyper-V, VMware, VirtualBox, Loopback, PPTP/L2TP/SSTP/IKEv2, VPN, and virtual adapters.
pub fn is_physical_nic_descriptor(if_type: u32, oper_status: i32, descr: &str) -> bool {
    const IF_TYPE_ETHERNET: u32 = 6;
    const IF_TYPE_PPP: u32 = 23;
    const IF_TYPE_WIFI: u32 = 71;
    const IF_TYPE_WWANPP: u32 = 243;
    const IF_TYPE_WWANPP2: u32 = 244;
    const OPER_CONNECTED: i32 = 4;
    const OPER_OPERATIONAL: i32 = 5;

    if !matches!(
        if_type,
        IF_TYPE_ETHERNET | IF_TYPE_PPP | IF_TYPE_WIFI | IF_TYPE_WWANPP | IF_TYPE_WWANPP2
    ) {
        return false;
    }
    if oper_status != OPER_OPERATIONAL && oper_status != OPER_CONNECTED {
        return false;
    }

    let lower = descr.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return true;
    }

    const VIRTUAL_NIC_KEYWORDS: &[&str] = &[
        "wintun",
        "wireguard",
        "tap-windows",
        "tap-",
        "sing-tun",
        "mihomo",
        "clash",
        "pptp",
        "l2tp",
        "sstp",
        "ikev2",
        "hyper-v",
        "vethernet",
        "vmware",
        "virtualbox",
        "vbox",
        "zerotier",
        "tailscale",
        "radmin",
        "loopback",
        "teredo",
        "isatap",
        "pseudo",
        "bluetooth",
        "km-test",
        "virtual",
        "tunnel",
        "vpn",
        "npcap",
        "wsl",
        "docker",
    ];
    if VIRTUAL_NIC_KEYWORDS.iter().any(|kw| lower.contains(kw)) {
        return false;
    }
    // Exempt Windows PPPoE dial-up ("WAN Miniport (PPPOE)") while rejecting non-PPPoE miniports.
    if lower.contains("wan miniport") && !lower.contains("pppoe") {
        return false;
    }
    true
}

/// Normalize a process path or executable name down to lowercase basename (e.g. `"mihomo.exe"`).
pub fn normalize_process_basename(raw: &str) -> String {
    let trimmed = raw.trim();
    let base = trimmed
        .rsplit(|c| c == '\\' || c == '/')
        .next()
        .unwrap_or(trimmed);
    base.to_ascii_lowercase()
}

/// Return `true` when `raw` resolves to an empty name, a core Windows OS process, or any
/// CatCloud self executable that must never be transparently intercepted.
pub fn is_system_or_self_excluded_process(raw: &str) -> bool {
    let lower = normalize_process_basename(raw);
    lower.is_empty()
        || lower.starts_with("catcloud")
        || SYSTEM_AND_SELF_EXCLUDED_PROCESSES
            .iter()
            .any(|sys| *sys == lower)
}

/// Return `true` when `raw` matches a well-known non-proxy communication, browser, IDE, office,
/// media, or cloud-drive application (used strictly to prevent automatic proxy listener heuristics
/// from misclassifying ordinary desktop apps, never blocking `ssh.exe`, `git.exe`, or manual lists).
pub fn is_non_proxy_communication_process(raw: &str) -> bool {
    let lower = normalize_process_basename(raw);
    if lower.is_empty() {
        return false;
    }
    let stem = lower.strip_suffix(".exe").unwrap_or(&lower);
    NON_PROXY_COMMUNICATION_PROCESS_STEMS.contains(&stem)
}

/// Return `true` when an executable path or basename matches a generic open-source
/// proxy core stem (case-insensitive, never matching core OS processes or CatCloud self binaries).
pub fn is_open_source_proxy_core_name(raw: &str) -> bool {
    let lower = normalize_process_basename(raw);
    if is_system_or_self_excluded_process(&lower) {
        return false;
    }
    OPEN_SOURCE_PROXY_CORE_STEMS
        .iter()
        .any(|stem| lower.contains(stem))
}

/// Classify whether an outbound TCP flow from `(pid, process_name)` should be transparently
/// redirected into the standalone `:443` pre-acceleration tunnel, returning the detection label
/// when approved (`"system_proxy_host"`, `"local_proxy_listener"`, `"open_core_name"`, `"manual"`,
/// or `"scope_all"`), or `None` when bypassed.
///
/// Safety precedence:
/// 1. Unconditionally exclude `pid == 0`, `pid == 4`, every PID in `excluded_pids` (CatCloud full
///    descendant tree, standalone tunnel, main core), unresolvable/empty process names, and
///    `SYSTEM_AND_SELF_EXCLUDED_PROCESSES` / `catcloud*`.
/// 2. Accept dynamic runtime proxy hosts (`detected_proxy_pids`).
/// 3. Accept generic open-source proxy core stems (`OPEN_SOURCE_PROXY_CORE_STEMS`).
/// 4. Accept explicitly configured user target executables (`target_processes_lower`).
/// 5. In `AllNon443Tcp` scope, accept remaining public non-443 TCP flows as `"scope_all"`.
pub fn classify_intercept_process(
    pid: u32,
    process_name: Option<&str>,
    scope: GlobalPreAccelScope,
    target_processes_lower: &HashSet<String>,
    excluded_pids: &HashSet<u32>,
    detected_proxy_pids: &HashMap<u32, &'static str>,
) -> Option<&'static str> {
    if pid == 0 || pid == 4 || excluded_pids.contains(&pid) {
        return None;
    }
    let name = process_name?;
    // Conservatively bypass processes whose executable name cannot be resolved (such as
    // Windows PPL protected system processes) so they never bypass system exclusions.
    let lower = normalize_process_basename(name);
    if is_system_or_self_excluded_process(&lower) {
        return None;
    }
    if let Some(&detected_reason) = detected_proxy_pids.get(&pid) {
        return Some(detected_reason);
    }
    if is_open_source_proxy_core_name(&lower) {
        return Some("open_core_name");
    }
    if target_processes_lower.contains(&lower) {
        return Some("manual");
    }
    match scope {
        GlobalPreAccelScope::ProxyAppsOnly => None,
        GlobalPreAccelScope::AllNon443Tcp => Some("scope_all"),
    }
}

/// Pure policy check deciding whether an outbound TCP flow from `(pid, process_name)` should
/// be transparently redirected into the standalone :443 pre-acceleration tunnel.
///
/// Backward-compatible wrapper delegating to [`classify_intercept_process`] with an empty
/// dynamic runtime detection map.
pub fn should_intercept_process(
    pid: u32,
    process_name: Option<&str>,
    scope: GlobalPreAccelScope,
    target_processes_lower: &HashSet<String>,
    excluded_pids: &HashSet<u32>,
) -> bool {
    let empty_detected: HashMap<u32, &'static str> = HashMap::new();
    classify_intercept_process(
        pid,
        process_name,
        scope,
        target_processes_lower,
        excluded_pids,
        &empty_detected,
    )
    .is_some()
}

/// Thread-safe excluded-PID tracker shared between the control plane (`GlobalPreAccelManager` /
/// `WinDivertEngine`) and the packet worker thread (`Arc<std::sync::RwLock<HashSet<u32>>>`).
///
/// Always retains CatCloud's own PID, the standalone :443 tunnel subprocess PID, any static
/// startup exclusions, the dynamic full CatCloud descendant PID tree, and the external main core
/// PID slot using a strict lock order (`main_core_pid -> descendant_pids -> active`).
#[cfg_attr(
    any(not(target_os = "windows"), target_arch = "aarch64"),
    allow(dead_code)
)]
#[derive(Debug)]
pub(super) struct ExcludedPidTracker {
    pinned: HashSet<u32>,
    main_core_pid: Mutex<Option<u32>>,
    descendant_pids: Mutex<HashSet<u32>>,
    active: Arc<std::sync::RwLock<HashSet<u32>>>,
}

#[cfg_attr(
    any(not(target_os = "windows"), target_arch = "aarch64"),
    allow(dead_code)
)]
impl ExcludedPidTracker {
    pub(super) fn new(
        self_pid: u32,
        tunnel_pid: Option<u32>,
        static_extra_pids: impl IntoIterator<Item = u32>,
        initial_main_core_pid: Option<u32>,
    ) -> Self {
        let mut pinned = HashSet::new();
        if self_pid > 0 {
            pinned.insert(self_pid);
        }
        if let Some(pid) = tunnel_pid.filter(|&p| p > 0) {
            pinned.insert(pid);
        }
        for pid in static_extra_pids {
            if pid > 0 {
                pinned.insert(pid);
            }
        }
        let initial_main = initial_main_core_pid.filter(|&p| p > 0);
        let mut initial_set = pinned.clone();
        if let Some(pid) = initial_main {
            initial_set.insert(pid);
        }
        Self {
            pinned,
            main_core_pid: Mutex::new(initial_main),
            descendant_pids: Mutex::new(HashSet::new()),
            active: Arc::new(std::sync::RwLock::new(initial_set)),
        }
    }

    pub(super) fn shared_set(&self) -> Arc<std::sync::RwLock<HashSet<u32>>> {
        Arc::clone(&self.active)
    }

    pub(super) fn snapshot_active(&self) -> HashSet<u32> {
        self.active
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Return the current deduplicated root PIDs whose full Windows descendant subtrees
    /// must be excluded (always includes `std::process::id()`, pinned PIDs, and `main_core_pid`).
    pub(super) fn current_root_pids(&self) -> Vec<u32> {
        let main_pid = *self.main_core_pid.lock().unwrap_or_else(|e| e.into_inner());
        let mut roots: HashSet<u32> = self.pinned.clone();
        let current_self_pid = std::process::id();
        if current_self_pid > 0 {
            roots.insert(current_self_pid);
        }
        if let Some(pid) = main_pid {
            roots.insert(pid);
        }
        roots.into_iter().collect()
    }

    /// Replace or clear only the external main core PID slot while unconditionally preserving
    /// `std::process::id()`, the standalone tunnel PID, all pinned exclusions, and the dynamic
    /// descendant PID tree.
    pub(super) fn sync_main_core_pid(&self, main_core_pid: Option<u32>) {
        let next_pid = main_core_pid.filter(|&p| p > 0);
        let mut main_slot = self.main_core_pid.lock().unwrap_or_else(|e| e.into_inner());
        *main_slot = next_pid;
        let descendants = self
            .descendant_pids
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        self.rebuild_active_locked(*main_slot, &descendants);
    }

    /// Replace the dynamically scanned CatCloud descendant PID tree while unconditionally
    /// preserving pinned exclusions and the external main core PID slot.
    pub(super) fn sync_descendant_pids(&self, descendants: HashSet<u32>) {
        let cleaned: HashSet<u32> = descendants.into_iter().filter(|&p| p > 0).collect();
        let main_slot = self.main_core_pid.lock().unwrap_or_else(|e| e.into_inner());
        let mut desc_slot = self
            .descendant_pids
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *desc_slot = cleaned;
        self.rebuild_active_locked(*main_slot, &desc_slot);
    }

    fn rebuild_active_locked(&self, main_core_pid: Option<u32>, descendants: &HashSet<u32>) {
        let mut set = self.active.write().unwrap_or_else(|e| e.into_inner());
        set.clear();
        for &pid in &self.pinned {
            set.insert(pid);
        }
        let current_self_pid = std::process::id();
        if current_self_pid > 0 {
            set.insert(current_self_pid);
        }
        if let Some(pid) = main_core_pid {
            set.insert(pid);
        }
        for &pid in descendants {
            set.insert(pid);
        }
    }
}

/// Key identifying a local client TCP endpoint in the self-loop NAT table.
pub type NatKey = (Ipv4Addr, u16);

/// Recorded original endpoints, process identity, & interface metadata for one transparently
/// redirected flow in the loopback NAT table.
#[derive(Debug, Clone)]
pub struct NatEntry {
    pub orig_src_ip: Ipv4Addr,
    pub orig_dst_ip: Ipv4Addr,
    pub orig_dst_port: u16,
    pub if_idx: u32,
    pub sub_if_idx: u32,
    pub owner_pid: u32,
    pub process_name: String,
    pub detected_by: String,
    pub last_seen: Instant,
    pub closing_since: Option<Instant>,
}

/// Lightweight `Copy` view of a NAT entry used on the packet worker hot path so per-packet
/// address translation never clones heap-allocated `String` fields (`process_name`, `detected_by`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatPacketView {
    pub orig_src_ip: Ipv4Addr,
    pub orig_dst_ip: Ipv4Addr,
    pub orig_dst_port: u16,
    pub if_idx: u32,
    pub sub_if_idx: u32,
    pub is_closing: bool,
    pub is_self_test: bool,
}

/// Bounded-capacity transparent TCP NAT table with a lock-free 64K source-port occupancy bitmap,
/// idle timeout, closing-grace retention for clean `FIN-ACK` / `RST` teardown, and oldest-access
/// LRU eviction.
#[derive(Debug)]
pub struct NatTable {
    max_entries: usize,
    idle_timeout: Duration,
    /// Lock-free 65,536-bit source-port occupancy bitmap (`1024 * 64` bits).
    port_bitmap: Box<[AtomicU64; 1024]>,
    entries: Mutex<HashMap<NatKey, NatEntry>>,
}

impl NatTable {
    pub fn new(max_entries: usize, idle_timeout: Duration) -> Self {
        let port_bitmap: Box<[AtomicU64; 1024]> = (0..1024)
            .map(|_| AtomicU64::new(0))
            .collect::<Vec<_>>()
            .into_boxed_slice()
            .try_into()
            .unwrap_or_else(|_| unreachable!());
        Self {
            max_entries: max_entries.max(1),
            idle_timeout,
            port_bitmap,
            entries: Mutex::new(HashMap::with_capacity(max_entries.min(512))),
        }
    }

    #[inline]
    fn set_port_bit(&self, port: u16) {
        let idx = usize::from(port) >> 6;
        let mask = 1u64 << (port & 63);
        self.port_bitmap[idx].fetch_or(mask, Ordering::Release);
    }

    #[inline]
    fn clear_port_bit_locked(&self, guard: &HashMap<NatKey, NatEntry>, port: u16) {
        if !guard.contains_key(&(Ipv4Addr::LOCALHOST, port))
            && !guard.keys().any(|&(_, p)| p == port)
        {
            let idx = usize::from(port) >> 6;
            let mask = !(1u64 << (port & 63));
            self.port_bitmap[idx].fetch_and(mask, Ordering::Release);
        }
    }

    /// O(1) lock-free check indicating whether `port` currently has any NAT entry registered.
    ///
    /// Non-SYN packets whose source port bit is clear can be reinjected immediately without
    /// acquiring the internal `Mutex`.
    #[inline]
    pub fn may_contain_port(&self, port: u16) -> bool {
        let word = self.port_bitmap[usize::from(port) >> 6].load(Ordering::Acquire);
        (word & (1u64 << (port & 63))) != 0
    }

    fn is_entry_expired(entry: &NatEntry, now: Instant, idle_timeout: Duration) -> bool {
        if let Some(closing_at) = entry.closing_since {
            if now.saturating_duration_since(closing_at) >= NAT_CLOSING_GRACE {
                return true;
            }
        }
        now.saturating_duration_since(entry.last_seen) >= idle_timeout
    }

    /// Return `true` when `key` has a non-expired entry that would collide with an incoming new
    /// flow `(incoming_src_ip, incoming_dst_ip, incoming_dst_port)`:
    /// 1. Active (`closing_since.is_none()`) entry belonging to a DIFFERENT `orig_src_ip`
    ///    (multi-NIC ephemeral port collision); OR
    /// 2. Closing (`closing_since.is_some()`, still within `NAT_CLOSING_GRACE`) entry whose
    ///    recorded `(orig_src_ip, orig_dst_ip, orig_dst_port)` differs from the incoming flow,
    ///    so the new flow passes through safely without clobbering trailing `FIN-ACK`/`RST`
    ///    translation for the closing flow.
    pub fn has_active_conflict(
        &self,
        key: &NatKey,
        incoming_src_ip: Ipv4Addr,
        incoming_dst_ip: Ipv4Addr,
        incoming_dst_port: u16,
    ) -> bool {
        if !self.may_contain_port(key.1) {
            return false;
        }
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let Some(existing) = guard.get(key) else {
            return false;
        };
        let now = Instant::now();
        if Self::is_entry_expired(existing, now, self.idle_timeout) {
            guard.remove(key);
            self.clear_port_bit_locked(&guard, key.1);
            return false;
        }
        if existing.closing_since.is_some() {
            existing.orig_src_ip != incoming_src_ip
                || existing.orig_dst_ip != incoming_dst_ip
                || existing.orig_dst_port != incoming_dst_port
        } else {
            existing.orig_src_ip != incoming_src_ip
        }
    }

    /// Insert or update a NAT mapping, evicting expired or least-recently-used entries if full.
    pub fn insert(&self, key: NatKey, entry: NatEntry) {
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let now = entry.last_seen;
        if !guard.contains_key(&key) && guard.len() >= self.max_entries {
            let timeout = self.idle_timeout;
            let mut evicted_ports: Vec<u16> = Vec::new();
            guard.retain(|&(_, port), v| {
                let keep = !Self::is_entry_expired(v, now, timeout);
                if !keep {
                    evicted_ports.push(port);
                }
                keep
            });
            if evicted_ports.len() == 1 {
                self.clear_port_bit_locked(&guard, evicted_ports[0]);
            } else if !evicted_ports.is_empty() {
                let remaining_ports: HashSet<u16> = guard.keys().map(|&(_, p)| p).collect();
                for port in evicted_ports {
                    if !remaining_ports.contains(&port) {
                        let idx = usize::from(port) >> 6;
                        let mask = !(1u64 << (port & 63));
                        self.port_bitmap[idx].fetch_and(mask, Ordering::Release);
                    }
                }
            }
            // Prefer evicting already-closing entries before live flows when at capacity.
            while guard.len() >= self.max_entries {
                let candidate = guard
                    .iter()
                    .filter(|(_, v)| v.closing_since.is_some())
                    .min_by_key(|(_, v)| v.closing_since.unwrap_or(v.last_seen))
                    .or_else(|| guard.iter().min_by_key(|(_, v)| v.last_seen))
                    .map(|(k, _)| *k);
                if let Some(oldest_key) = candidate {
                    guard.remove(&oldest_key);
                    self.clear_port_bit_locked(&guard, oldest_key.1);
                } else {
                    break;
                }
            }
        }
        guard.insert(key, entry);
        self.set_port_bit(key.1);
    }

    /// Look up a lightweight `Copy` packet-rewrite view for `key` and refresh `last_seen`,
    /// avoiding any `String` heap allocation on the WinDivert packet worker hot path.
    pub fn get_packet_view_and_touch(&self, key: &NatKey) -> Option<NatPacketView> {
        if !self.may_contain_port(key.1) {
            return None;
        }
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let entry = guard.get_mut(key)?;
        let now = Instant::now();
        if Self::is_entry_expired(entry, now, self.idle_timeout) {
            guard.remove(key);
            self.clear_port_bit_locked(&guard, key.1);
            return None;
        }
        entry.last_seen = now;
        Some(NatPacketView {
            orig_src_ip: entry.orig_src_ip,
            orig_dst_ip: entry.orig_dst_ip,
            orig_dst_port: entry.orig_dst_port,
            if_idx: entry.if_idx,
            sub_if_idx: entry.sub_if_idx,
            is_closing: entry.closing_since.is_some(),
            is_self_test: entry.detected_by == SELF_TEST_DETECTED_BY,
        })
    }

    /// Look up a NAT mapping and refresh its `last_seen` timestamp.
    pub fn get_and_touch(&self, key: &NatKey) -> Option<NatEntry> {
        if !self.may_contain_port(key.1) {
            return None;
        }
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let entry = guard.get_mut(key)?;
        let now = Instant::now();
        if Self::is_entry_expired(entry, now, self.idle_timeout) {
            guard.remove(key);
            self.clear_port_bit_locked(&guard, key.1);
            return None;
        }
        entry.last_seen = now;
        Some(entry.clone())
    }

    /// Remove and return the NAT entry for `key`, if present.
    pub fn remove(&self, key: &NatKey) -> Option<NatEntry> {
        if !self.may_contain_port(key.1) {
            return None;
        }
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let removed = guard.remove(key);
        if removed.is_some() {
            self.clear_port_bit_locked(&guard, key.1);
        }
        removed
    }

    /// Mark the NAT entry for `key` as closing (retaining translation for `NAT_CLOSING_GRACE`
    /// so trailing `FIN-ACK`/`RST` return packets still map back to the client) only when its
    /// recorded original tuple matches `(orig_src_ip, orig_dst_ip, orig_dst_port)`.
    pub fn mark_closing_if_matching(
        &self,
        key: &NatKey,
        orig_src_ip: Ipv4Addr,
        orig_dst_ip: Ipv4Addr,
        orig_dst_port: u16,
    ) -> bool {
        if !self.may_contain_port(key.1) {
            return false;
        }
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = guard.get_mut(key) {
            if entry.orig_src_ip == orig_src_ip
                && entry.orig_dst_ip == orig_dst_ip
                && entry.orig_dst_port == orig_dst_port
            {
                entry.closing_since.get_or_insert_with(Instant::now);
                return true;
            }
        }
        false
    }

    /// Remove the NAT entry for `key` ONLY when it is still active (`closing_since.is_none()`)
    /// and its recorded original tuple matches `(src_ip, dst_ip, dst_port)`.
    ///
    /// Guarantees bypass/error paths never erase another flow or an entry retained in its
    /// `NAT_CLOSING_GRACE` teardown window.
    pub fn remove_active_if_matching(
        &self,
        key: &NatKey,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        dst_port: u16,
    ) -> bool {
        if !self.may_contain_port(key.1) {
            return false;
        }
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let matches = guard.get(key).is_some_and(|entry| {
            entry.closing_since.is_none()
                && entry.orig_src_ip == src_ip
                && entry.orig_dst_ip == dst_ip
                && entry.orig_dst_port == dst_port
        });
        if matches {
            guard.remove(key);
            self.clear_port_bit_locked(&guard, key.1);
            true
        } else {
            false
        }
    }

    /// Remove the NAT entry for `key` only when its recorded original destination matches
    /// `(orig_dst_ip, orig_dst_port)`, preventing a closing older connection from evicting
    /// a newer mapping created after local ephemeral port reuse.
    pub fn remove_if_matching(
        &self,
        key: &NatKey,
        orig_dst_ip: Ipv4Addr,
        orig_dst_port: u16,
    ) -> bool {
        if !self.may_contain_port(key.1) {
            return false;
        }
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let matches = guard.get(key).is_some_and(|entry| {
            entry.orig_dst_ip == orig_dst_ip && entry.orig_dst_port == orig_dst_port
        });
        if matches {
            guard.remove(key);
            self.clear_port_bit_locked(&guard, key.1);
            true
        } else {
            false
        }
    }

    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Parsed IPv4 + TCP header metadata extracted from a raw L3 packet buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4TcpMeta {
    pub ihl_bytes: usize,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: u8,
}

impl Ipv4TcpMeta {
    pub const FLAG_FIN: u8 = 0x01;
    pub const FLAG_SYN: u8 = 0x02;
    pub const FLAG_RST: u8 = 0x04;
    pub const FLAG_ACK: u8 = 0x10;

    pub fn is_syn_only(self) -> bool {
        (self.tcp_flags & Self::FLAG_SYN) != 0 && (self.tcp_flags & Self::FLAG_ACK) == 0
    }
}

/// Parse minimal IPv4 + TCP header metadata from raw packet bytes.
pub fn parse_ipv4_tcp_packet(buf: &[u8]) -> Option<Ipv4TcpMeta> {
    if buf.len() < 20 {
        return None;
    }
    let version = buf[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl = (buf[0] & 0x0F) as usize;
    if ihl < 5 {
        return None;
    }
    let ihl_bytes = ihl * 4;
    if buf[9] != 6 || buf.len() < ihl_bytes + 20 {
        return None;
    }

    let src_ip = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let dst_ip = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    let src_port = u16::from_be_bytes([buf[ihl_bytes], buf[ihl_bytes + 1]]);
    let dst_port = u16::from_be_bytes([buf[ihl_bytes + 2], buf[ihl_bytes + 3]]);
    let tcp_flags = buf[ihl_bytes + 13];

    Some(Ipv4TcpMeta {
        ihl_bytes,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        tcp_flags,
    })
}

/// Rewrite the IPv4 destination IP and TCP destination port in-place.
pub fn rewrite_ipv4_tcp_dst(
    buf: &mut [u8],
    ihl_bytes: usize,
    new_dst_ip: Ipv4Addr,
    new_dst_port: u16,
) -> bool {
    if ihl_bytes < 20 || buf.len() < ihl_bytes + 20 {
        return false;
    }
    buf[16..20].copy_from_slice(&new_dst_ip.octets());
    buf[ihl_bytes + 2..ihl_bytes + 4].copy_from_slice(&new_dst_port.to_be_bytes());
    true
}

/// Rewrite the IPv4 source IP and TCP source port in-place.
pub fn rewrite_ipv4_tcp_src(
    buf: &mut [u8],
    ihl_bytes: usize,
    new_src_ip: Ipv4Addr,
    new_src_port: u16,
) -> bool {
    if ihl_bytes < 20 || buf.len() < ihl_bytes + 20 {
        return false;
    }
    buf[12..16].copy_from_slice(&new_src_ip.octets());
    buf[ihl_bytes..ihl_bytes + 2].copy_from_slice(&new_src_port.to_be_bytes());
    true
}

/// Rewrite an outbound IPv4 TCP packet in-place for loopback reflection into the local
/// `127.0.0.1:<redirect_port>` transparent proxy listener:
/// - `ip.SrcAddr = 127.0.0.1`
/// - `ip.DstAddr = 127.0.0.1`
/// - `tcp.DstPort = redirect_port` (preserving `tcp.SrcPort` as the NAT lookup key)
///
/// Using loopback (`127.0.0.1 -> 127.0.0.1`, injected `Outbound = true`) avoids Windows
/// physical-NIC LAND-attack (`src == dst`) drops and bypasses Windows Defender / third-party
/// firewall public-inbound rules cleanly with zero LAN exposure.
pub fn rewrite_ipv4_tcp_to_loopback(
    buf: &mut [u8],
    ihl_bytes: usize,
    redirect_port: u16,
) -> bool {
    if ihl_bytes < 20 || buf.len() < ihl_bytes + 20 {
        return false;
    }
    let lo = Ipv4Addr::LOCALHOST.octets();
    buf[12..16].copy_from_slice(&lo);
    buf[16..20].copy_from_slice(&lo);
    buf[ihl_bytes + 2..ihl_bytes + 4].copy_from_slice(&redirect_port.to_be_bytes());
    true
}

/// Rewrite a return IPv4 TCP packet coming back from `127.0.0.1:<redirect_port>` in-place
/// back to the client's original remote/local tuple before inbound injection:
/// - `ip.SrcAddr = orig_dst_ip`
/// - `ip.DstAddr = orig_src_ip`
/// - `tcp.SrcPort = orig_dst_port` (preserving `tcp.DstPort`)
pub fn rewrite_ipv4_tcp_from_loopback(
    buf: &mut [u8],
    ihl_bytes: usize,
    orig_dst_ip: Ipv4Addr,
    orig_dst_port: u16,
    orig_src_ip: Ipv4Addr,
) -> bool {
    if ihl_bytes < 20 || buf.len() < ihl_bytes + 20 {
        return false;
    }
    buf[12..16].copy_from_slice(&orig_dst_ip.octets());
    buf[16..20].copy_from_slice(&orig_src_ip.octets());
    buf[ihl_bytes..ihl_bytes + 2].copy_from_slice(&orig_dst_port.to_be_bytes());
    true
}

/// Clamp the TCP MSS option (`Kind=2, Len=4`) inside a `SYN` / `SYN-ACK` header to at most
/// `max_mss` (typically `1460` for standard Ethernet/Wi-Fi MTU 1500), preventing oversized
/// loopback MSS announcements (`65495`) from causing path/LSO anomalies on physical NICs.
pub fn clamp_tcp_syn_mss(buf: &mut [u8], ihl_bytes: usize, max_mss: u16) -> bool {
    if ihl_bytes < 20 || buf.len() < ihl_bytes + 20 || max_mss == 0 {
        return false;
    }
    let data_offset_words = ((buf[ihl_bytes + 12] >> 4) & 0x0F) as usize;
    if data_offset_words <= 5 {
        return false;
    }
    let tcp_hdr_len = data_offset_words * 4;
    let opt_start = ihl_bytes + 20;
    let opt_end = ihl_bytes.saturating_add(tcp_hdr_len);
    if opt_end > buf.len() || opt_end <= opt_start {
        return false;
    }

    let mut pos = opt_start;
    while pos < opt_end {
        let kind = buf[pos];
        if kind == 0 {
            // End of Options List
            break;
        }
        if kind == 1 {
            // NOP
            pos += 1;
            continue;
        }
        if pos + 1 >= opt_end {
            break;
        }
        let len = buf[pos + 1] as usize;
        if len < 2 || pos + len > opt_end {
            break;
        }
        if kind == 2 && len == 4 {
            let current_mss = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
            if current_mss > max_mss {
                buf[pos + 2..pos + 4].copy_from_slice(&max_mss.to_be_bytes());
                return true;
            }
            return false;
        }
        pos += len;
    }
    false
}

/// Structured per-process live acceleration telemetry entry reported in `GlobalPreAccelStatus`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcceleratedProcessStat {
    pub process_name: String,
    pub pid: u32,
    pub detected_by: String,
    pub active_connections: usize,
    pub total_connections: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub last_seen_ms: u64,
}

const DETECTED_BY_RUNTIME: u8 = 0;
const DETECTED_BY_SCOPE_ALL: u8 = 1;
const DETECTED_BY_MANUAL: u8 = 2;
const DETECTED_BY_LOCAL_PROXY_LISTENER: u8 = 3;
const DETECTED_BY_OPEN_CORE_NAME: u8 = 4;
const DETECTED_BY_SYSTEM_PROXY_HOST: u8 = 5;

fn encode_detected_by(reason: &str) -> u8 {
    let trimmed = reason.trim();
    if trimmed.eq_ignore_ascii_case("system_proxy_host") {
        DETECTED_BY_SYSTEM_PROXY_HOST
    } else if trimmed.eq_ignore_ascii_case("open_core_name") {
        DETECTED_BY_OPEN_CORE_NAME
    } else if trimmed.eq_ignore_ascii_case("local_proxy_listener") {
        DETECTED_BY_LOCAL_PROXY_LISTENER
    } else if trimmed.eq_ignore_ascii_case("manual") {
        DETECTED_BY_MANUAL
    } else if trimmed.eq_ignore_ascii_case("scope_all") {
        DETECTED_BY_SCOPE_ALL
    } else {
        DETECTED_BY_RUNTIME
    }
}

fn decode_detected_by(code: u8) -> &'static str {
    match code {
        DETECTED_BY_SYSTEM_PROXY_HOST => "system_proxy_host",
        DETECTED_BY_OPEN_CORE_NAME => "open_core_name",
        DETECTED_BY_LOCAL_PROXY_LISTENER => "local_proxy_listener",
        DETECTED_BY_MANUAL => "manual",
        DETECTED_BY_SCOPE_ALL => "scope_all",
        _ => "runtime",
    }
}

/// Lock-free monotonic priority promotion for `ProcessCounters::detected_by_code`:
/// `system_proxy_host(5) > open_core_name(4) > local_proxy_listener(3) > manual(2) > scope_all(1) > runtime(0)`.
fn upgrade_detected_by_atomic(slot: &AtomicU8, candidate: u8) {
    let mut cur = slot.load(Ordering::Relaxed);
    while candidate > cur {
        match slot.compare_exchange_weak(cur, candidate, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(actual) => cur = actual,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ProcessStatKey {
    process_name_lower: String,
}

#[derive(Debug)]
struct ProcessCounters {
    process_name: String,
    pid: AtomicU32,
    detected_by_code: AtomicU8,
    active_connections: AtomicUsize,
    total_connections: AtomicU64,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    last_seen_ms: AtomicU64,
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn decrement_atomic_usize_saturating(counter: &AtomicUsize) {
    let mut cur = counter.load(Ordering::Relaxed);
    while let Err(actual) = counter.compare_exchange_weak(
        cur,
        cur.saturating_sub(1),
        Ordering::Relaxed,
        Ordering::Relaxed,
    ) {
        cur = actual;
    }
}

#[cfg_attr(
    any(not(target_os = "windows"), target_arch = "aarch64"),
    allow(dead_code)
)]
fn decrement_atomic_u64_saturating(counter: &AtomicU64) {
    let mut cur = counter.load(Ordering::Relaxed);
    while let Err(actual) = counter.compare_exchange_weak(
        cur,
        cur.saturating_sub(1),
        Ordering::Relaxed,
        Ordering::Relaxed,
    ) {
        cur = actual;
    }
}

/// Shared lock-free telemetry counters for the standalone global :443 pre-acceleration engine.
#[derive(Debug, Default)]
pub struct GlobalPreAccelMetrics {
    pub active_connections: AtomicU64,
    pub total_connections: AtomicU64,
    pub up_bytes: AtomicU64,
    pub down_bytes: AtomicU64,
    recent_processes: Mutex<VecDeque<String>>,
    process_stats: Mutex<HashMap<ProcessStatKey, Arc<ProcessCounters>>>,
}

impl GlobalPreAccelMetrics {
    pub fn reset(&self) {
        self.active_connections.store(0, Ordering::Relaxed);
        self.total_connections.store(0, Ordering::Relaxed);
        self.up_bytes.store(0, Ordering::Relaxed);
        self.down_bytes.store(0, Ordering::Relaxed);
        if let Ok(mut guard) = self.recent_processes.lock() {
            guard.clear();
        }
        if let Ok(mut guard) = self.process_stats.lock() {
            guard.clear();
        }
    }

    /// Zero out active connection gauges across both global and per-process counters (used on stop).
    pub fn clear_active_connections(&self) {
        self.active_connections.store(0, Ordering::Relaxed);
        if let Ok(guard) = self.process_stats.lock() {
            for pc in guard.values() {
                pc.active_connections.store(0, Ordering::Relaxed);
            }
        }
    }

    pub fn record_process(&self, name: &str) {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return;
        }
        let mut guard = self
            .recent_processes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(pos) = guard.iter().position(|p| p.eq_ignore_ascii_case(trimmed)) {
            guard.remove(pos);
        }
        guard.push_front(trimmed.to_string());
        while guard.len() > MAX_RECENT_PROCESSES {
            guard.pop_back();
        }
    }

    pub fn recent_processes_snapshot(&self) -> Vec<String> {
        self.recent_processes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    fn acquire_process_counters(
        &self,
        pid: u32,
        process_name: &str,
        detected_by: &str,
    ) -> Option<Arc<ProcessCounters>> {
        let display_name = {
            let trimmed = process_name.trim();
            if !trimmed.is_empty() {
                trimmed.to_string()
            } else if pid > 0 {
                format!("pid:{pid}")
            } else {
                return None;
            }
        };
        let reason_code = encode_detected_by(detected_by);
        let key = ProcessStatKey {
            process_name_lower: display_name.to_ascii_lowercase(),
        };

        let mut guard = self
            .process_stats
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = guard.get(&key) {
            if pid > 0 {
                existing.pid.store(pid, Ordering::Relaxed);
            }
            upgrade_detected_by_atomic(&existing.detected_by_code, reason_code);
            return Some(Arc::clone(existing));
        }

        if guard.len() >= MAX_PROCESS_STATS {
            // Evict the oldest idle process bucket first to maintain a hard memory bound.
            let evict_key = guard
                .iter()
                .filter(|(_, pc)| pc.active_connections.load(Ordering::Relaxed) == 0)
                .min_by_key(|(_, pc)| pc.last_seen_ms.load(Ordering::Relaxed))
                .map(|(k, _)| k.clone());
            if let Some(stale) = evict_key {
                guard.remove(&stale);
            } else {
                // All 64 tracked buckets are actively transferring; skip inserting a 65th bucket.
                return None;
            }
        }

        let counters = Arc::new(ProcessCounters {
            process_name: display_name,
            pid: AtomicU32::new(pid),
            detected_by_code: AtomicU8::new(reason_code),
            active_connections: AtomicUsize::new(0),
            total_connections: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            last_seen_ms: AtomicU64::new(now_epoch_ms()),
        });
        guard.insert(key, Arc::clone(&counters));
        Some(counters)
    }

    /// Record a new redirected connection opening for `(pid, process_name, detected_by)`.
    pub fn record_process_connection_open(
        &self,
        pid: u32,
        process_name: &str,
        detected_by: &str,
    ) {
        self.record_process(process_name);
        if let Some(pc) = self.acquire_process_counters(pid, process_name, detected_by) {
            pc.active_connections.fetch_add(1, Ordering::Relaxed);
            pc.total_connections.fetch_add(1, Ordering::Relaxed);
            pc.last_seen_ms.store(now_epoch_ms(), Ordering::Relaxed);
        }
    }

    /// Record a redirected connection closing for `(pid, process_name, detected_by)`.
    ///
    /// Matches solely by lowercase process name so PID restarts or detection-priority upgrades
    /// never leak `active_connections`.
    pub fn record_process_connection_close(
        &self,
        pid: u32,
        process_name: &str,
        _detected_by: &str,
    ) {
        let display_name = {
            let trimmed = process_name.trim();
            if !trimmed.is_empty() {
                trimmed.to_string()
            } else if pid > 0 {
                format!("pid:{pid}")
            } else {
                return;
            }
        };
        let key = ProcessStatKey {
            process_name_lower: display_name.to_ascii_lowercase(),
        };
        let guard = self
            .process_stats
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(pc) = guard.get(&key) {
            decrement_atomic_usize_saturating(&pc.active_connections);
            pc.last_seen_ms.store(now_epoch_ms(), Ordering::Relaxed);
        }
    }

    /// Accumulate transmitted (`tx_delta`) and received (`rx_delta`) bytes for a process bucket.
    pub fn record_process_bytes(
        &self,
        pid: u32,
        process_name: &str,
        detected_by: &str,
        tx_delta: u64,
        rx_delta: u64,
    ) {
        if tx_delta == 0 && rx_delta == 0 {
            return;
        }
        if let Some(pc) = self.acquire_process_counters(pid, process_name, detected_by) {
            if tx_delta > 0 {
                pc.tx_bytes.fetch_add(tx_delta, Ordering::Relaxed);
            }
            if rx_delta > 0 {
                pc.rx_bytes.fetch_add(rx_delta, Ordering::Relaxed);
            }
            pc.last_seen_ms.store(now_epoch_ms(), Ordering::Relaxed);
        }
    }

    /// Snapshot per-process acceleration telemetry sorted by active connections descending,
    /// then total transferred bytes (`tx_bytes + rx_bytes`) descending, then total connections.
    pub fn process_stats_snapshot(&self) -> Vec<AcceleratedProcessStat> {
        let guard = self
            .process_stats
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut stats: Vec<AcceleratedProcessStat> = guard
            .values()
            .map(|pc| AcceleratedProcessStat {
                process_name: pc.process_name.clone(),
                pid: pc.pid.load(Ordering::Relaxed),
                detected_by: decode_detected_by(pc.detected_by_code.load(Ordering::Relaxed))
                    .to_string(),
                active_connections: pc.active_connections.load(Ordering::Relaxed),
                total_connections: pc.total_connections.load(Ordering::Relaxed),
                tx_bytes: pc.tx_bytes.load(Ordering::Relaxed),
                rx_bytes: pc.rx_bytes.load(Ordering::Relaxed),
                last_seen_ms: pc.last_seen_ms.load(Ordering::Relaxed),
            })
            .collect();
        drop(guard);

        stats.sort_by(|a, b| {
            b.active_connections
                .cmp(&a.active_connections)
                .then_with(|| {
                    b.tx_bytes
                        .saturating_add(b.rx_bytes)
                        .cmp(&a.tx_bytes.saturating_add(a.rx_bytes))
                })
                .then_with(|| b.total_connections.cmp(&a.total_connections))
                .then_with(|| b.last_seen_ms.cmp(&a.last_seen_ms))
                .then_with(|| a.process_name.cmp(&b.process_name))
                .then_with(|| a.pid.cmp(&b.pid))
        });
        stats
    }

    /// Alias for [`Self::process_stats_snapshot`] returning sorted per-process telemetry.
    pub fn snapshot(&self) -> Vec<AcceleratedProcessStat> {
        self.process_stats_snapshot()
    }
}

/// RAII guard decrementing global and per-process `active_connections` when a forwarded TCP
/// stream terminates.
#[cfg_attr(
    any(not(target_os = "windows"), target_arch = "aarch64"),
    allow(dead_code)
)]
struct ActiveConnGuard {
    metrics: Arc<GlobalPreAccelMetrics>,
    process_counters: Option<Arc<ProcessCounters>>,
}

#[cfg_attr(
    any(not(target_os = "windows"), target_arch = "aarch64"),
    allow(dead_code)
)]
impl ActiveConnGuard {
    fn acquire_for_process(
        metrics: Arc<GlobalPreAccelMetrics>,
        pid: u32,
        process_name: &str,
        detected_by: &str,
    ) -> Self {
        metrics.active_connections.fetch_add(1, Ordering::Relaxed);
        metrics.total_connections.fetch_add(1, Ordering::Relaxed);
        metrics.record_process(process_name);
        let process_counters = metrics.acquire_process_counters(pid, process_name, detected_by);
        if let Some(ref pc) = process_counters {
            pc.active_connections.fetch_add(1, Ordering::Relaxed);
            pc.total_connections.fetch_add(1, Ordering::Relaxed);
            pc.last_seen_ms.store(now_epoch_ms(), Ordering::Relaxed);
        }
        Self {
            metrics,
            process_counters,
        }
    }

    fn process_counters(&self) -> Option<Arc<ProcessCounters>> {
        self.process_counters.clone()
    }
}

impl Drop for ActiveConnGuard {
    fn drop(&mut self) {
        decrement_atomic_u64_saturating(&self.metrics.active_connections);
        if let Some(ref pc) = self.process_counters {
            decrement_atomic_usize_saturating(&pc.active_connections);
            pc.last_seen_ms.store(now_epoch_ms(), Ordering::Relaxed);
        }
    }
}

/// RAII guard marking a flow's NAT table entry as closing on exit (keeping it alive for
/// `NAT_CLOSING_GRACE` so trailing `FIN-ACK` / `RST` packets still translate cleanly back to
/// the client) only if it still maps to the same original tuple.
#[cfg_attr(
    any(not(target_os = "windows"), target_arch = "aarch64"),
    allow(dead_code)
)]
struct NatEntryCleanupGuard {
    nat_table: Arc<NatTable>,
    key: NatKey,
    orig_src_ip: Ipv4Addr,
    orig_dst_ip: Ipv4Addr,
    orig_dst_port: u16,
}

impl Drop for NatEntryCleanupGuard {
    fn drop(&mut self) {
        self.nat_table.mark_closing_if_matching(
            &self.key,
            self.orig_src_ip,
            self.orig_dst_ip,
            self.orig_dst_port,
        );
    }
}

#[cfg_attr(
    any(not(target_os = "windows"), target_arch = "aarch64"),
    allow(dead_code)
)]
const COUNTING_LAST_SEEN_REFRESH_BYTES: u64 = 64 * 1024;

#[cfg_attr(
    any(not(target_os = "windows"), target_arch = "aarch64"),
    allow(dead_code)
)]
const REDIRECT_COPY_BUFFER_BYTES: usize = 64 * 1024;

/// Zero-copy `TcpStream` wrapper that atomically tracks real-time upload/download bytes
/// from the client side (`read` = upload/tx, `write` = download/rx) across both global and
/// per-process telemetry buckets without taking any mutex or clock syscall on small packets,
/// refreshing `last_seen_ms` strictly at `>= 64 KiB` byte thresholds (in addition to stream open/close).
#[cfg_attr(
    any(not(target_os = "windows"), target_arch = "aarch64"),
    allow(dead_code)
)]
struct CountingTcpStream {
    inner: TcpStream,
    metrics: Arc<GlobalPreAccelMetrics>,
    process_counters: Option<Arc<ProcessCounters>>,
    bytes_since_refresh: u64,
}

#[cfg_attr(
    any(not(target_os = "windows"), target_arch = "aarch64"),
    allow(dead_code)
)]
impl CountingTcpStream {
    fn client_side(
        inner: TcpStream,
        metrics: Arc<GlobalPreAccelMetrics>,
        process_counters: Option<Arc<ProcessCounters>>,
    ) -> Self {
        Self {
            inner,
            metrics,
            process_counters,
            bytes_since_refresh: 0,
        }
    }

    #[inline]
    fn maybe_refresh_last_seen(&mut self, delta: u64) {
        self.bytes_since_refresh = self.bytes_since_refresh.saturating_add(delta);
        if self.bytes_since_refresh >= COUNTING_LAST_SEEN_REFRESH_BYTES {
            if let Some(ref pc) = self.process_counters {
                pc.last_seen_ms.store(now_epoch_ms(), Ordering::Relaxed);
            }
            self.bytes_since_refresh = 0;
        }
    }
}

impl AsyncRead for CountingTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let res = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            let delta = buf.filled().len().saturating_sub(before) as u64;
            if delta > 0 {
                this.metrics.up_bytes.fetch_add(delta, Ordering::Relaxed);
                if let Some(ref pc) = this.process_counters {
                    pc.tx_bytes.fetch_add(delta, Ordering::Relaxed);
                }
                this.maybe_refresh_last_seen(delta);
            }
        }
        res
    }
}

impl AsyncWrite for CountingTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let res = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &res {
            if *n > 0 {
                let delta = *n as u64;
                this.metrics
                    .down_bytes
                    .fetch_add(delta, Ordering::Relaxed);
                if let Some(ref pc) = this.process_counters {
                    pc.rx_bytes.fetch_add(delta, Ordering::Relaxed);
                }
                this.maybe_refresh_last_seen(delta);
            }
        }
        res
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Perform a standard RFC 1928 SOCKS5 NOAUTH CONNECT handshake to `(dst_ip, dst_port)`.
pub async fn socks5_noauth_connect_ipv4(
    stream: &mut TcpStream,
    dst_ip: Ipv4Addr,
    dst_port: u16,
) -> CatResult<()> {
    // 1. Greeting: VER=5, NMETHODS=1, METHOD=0x00 (No Auth)
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method_resp = [0u8; 2];
    stream.read_exact(&mut method_resp).await?;
    if method_resp[0] != 0x05 || method_resp[1] != 0x00 {
        return Err(CatError::Core(format!(
            "SOCKS5 隧道握手认证失败: {:?}",
            method_resp
        )));
    }

    // 2. Request: VER=5, CMD=CONNECT(1), RSV=0, ATYP=IPv4(1), DST.ADDR, DST.PORT
    let octets = dst_ip.octets();
    let port_be = dst_port.to_be_bytes();
    let req = [
        0x05, 0x01, 0x00, 0x01, octets[0], octets[1], octets[2], octets[3], port_be[0], port_be[1],
    ];
    stream.write_all(&req).await?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return Err(CatError::Core(format!(
            "SOCKS5 CONNECT 到 {dst_ip}:{dst_port} 被拒绝 (rep=0x{:02x})",
            head[1]
        )));
    }

    match head[3] {
        0x01 => {
            let mut tail = [0u8; 6];
            stream.read_exact(&mut tail).await?;
        }
        0x03 => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let mut tail = vec![0u8; usize::from(len_buf[0]) + 2];
            stream.read_exact(&mut tail).await?;
        }
        0x04 => {
            let mut tail = [0u8; 18];
            stream.read_exact(&mut tail).await?;
        }
        other => {
            return Err(CatError::Core(format!(
                "SOCKS5 响应包含未知地址类型 ATYP=0x{other:02x}"
            )));
        }
    }

    Ok(())
}

/// Forward an accepted loopback-reflected TCP connection through the standalone :443 SOCKS5 tunnel.
///
/// Security invariant: any connection whose `(peer_ip, peer_port)` is not registered in
/// `nat_table` is dropped immediately without opening an upstream socket.
#[cfg_attr(
    any(not(target_os = "windows"), target_arch = "aarch64"),
    allow(dead_code)
)]
pub(super) async fn forward_redirected_stream(
    mut client_stream: TcpStream,
    peer_addr: SocketAddr,
    socks_port: u16,
    nat_table: Arc<NatTable>,
    metrics: Arc<GlobalPreAccelMetrics>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    self_test_accepted: Option<Arc<AtomicU64>>,
) {
    if *shutdown_rx.borrow() {
        return;
    }
    let SocketAddr::V4(peer_v4) = peer_addr else {
        return;
    };
    let key = (*peer_v4.ip(), peer_v4.port());
    let Some(entry) = nat_table.get_and_touch(&key) else {
        // Unregistered local scanner: close immediately.
        return;
    };
    let _nat_cleanup = NatEntryCleanupGuard {
        nat_table,
        key,
        orig_src_ip: entry.orig_src_ip,
        orig_dst_ip: entry.orig_dst_ip,
        orig_dst_port: entry.orig_dst_port,
    };

    let _ = client_stream.set_nodelay(true);
    let is_self_test = entry.detected_by == SELF_TEST_DETECTED_BY;
    if is_self_test {
        if let Some(ref counter) = self_test_accepted {
            counter.fetch_add(1, Ordering::SeqCst);
        }
    }

    let active_guard = if is_self_test {
        None
    } else {
        Some(ActiveConnGuard::acquire_for_process(
            Arc::clone(&metrics),
            entry.owner_pid,
            &entry.process_name,
            &entry.detected_by,
        ))
    };
    let process_counters = active_guard.as_ref().and_then(ActiveConnGuard::process_counters);

    let socks_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, socks_port);
    let connect_res = tokio::select! {
        _ = shutdown_rx.changed() => return,
        res = tokio::time::timeout(
            Duration::from_secs(10),
            TcpStream::connect(socks_addr),
        ) => res,
    };
    let Ok(Ok(mut upstream)) = connect_res else {
        tracing::debug!(
            "global preaccel failed to connect standalone SOCKS5 127.0.0.1:{socks_port} for {}:{}",
            entry.orig_dst_ip,
            entry.orig_dst_port
        );
        return;
    };
    let _ = upstream.set_nodelay(true);

    if *shutdown_rx.borrow() {
        return;
    }
    let handshake_res = tokio::select! {
        _ = shutdown_rx.changed() => return,
        res = tokio::time::timeout(
            Duration::from_secs(10),
            socks5_noauth_connect_ipv4(&mut upstream, entry.orig_dst_ip, entry.orig_dst_port),
        ) => res,
    };
    if let Err(err) = match handshake_res {
        Ok(inner) => inner,
        Err(_) => Err(CatError::Core("SOCKS5 握手超时".to_string())),
    } {
        tracing::debug!(
            "global preaccel SOCKS5 CONNECT to {}:{} failed: {err}",
            entry.orig_dst_ip,
            entry.orig_dst_port
        );
        return;
    }

    if *shutdown_rx.borrow() {
        return;
    }
    if is_self_test {
        tokio::select! {
            _ = tokio::io::copy_bidirectional_with_sizes(
                &mut client_stream,
                &mut upstream,
                REDIRECT_COPY_BUFFER_BYTES,
                REDIRECT_COPY_BUFFER_BYTES,
            ) => {}
            _ = shutdown_rx.changed() => {}
        }
    } else {
        let mut counting_client =
            CountingTcpStream::client_side(client_stream, metrics, process_counters);
        tokio::select! {
            _ = tokio::io::copy_bidirectional_with_sizes(
                &mut counting_client,
                &mut upstream,
                REDIRECT_COPY_BUFFER_BYTES,
                REDIRECT_COPY_BUFFER_BYTES,
            ) => {}
            _ = shutdown_rx.changed() => {}
        }
    }
}

// ============================================================================
// C. Unified Cross-Platform GlobalPreAccelManager & Status Snapshot
// ============================================================================

fn default_install_state() -> String {
    "idle".to_string()
}

fn default_verify_state() -> String {
    "idle".to_string()
}

fn normalize_install_state(raw: &str) -> &'static str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "downloading" => "downloading",
        "verifying" => "verifying",
        "ready" => "ready",
        "need_elevation" => "need_elevation",
        "failed" => "failed",
        _ => "idle",
    }
}

fn normalize_verify_state(raw: &str) -> &'static str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "probing" => "probing",
        "verified" => "verified",
        "degraded" => "degraded",
        "failed" => "failed",
        _ => "idle",
    }
}

/// Live status snapshot of the standalone global domestic :443 pre-acceleration engine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GlobalPreAccelStatus {
    pub running: bool,
    /// Active engine mode: `"off"`, `"windivert"` (Windows transparent kernel NAT),
    /// `"local_socks5"` (cross-platform standalone 127.0.0.1 :443 dual-active SOCKS5 entry),
    /// or `"suspended_for_tun"` (standalone tunnel paused while main-core TUN carries preaccel).
    pub mode: String,
    /// Strictly `true` only when `running && mode == "windivert"`.
    #[serde(default)]
    pub is_windivert_active: bool,
    /// Driver installation / elevation lifecycle state:
    /// `"idle" | "downloading" | "verifying" | "ready" | "need_elevation" | "failed"`.
    #[serde(default = "default_install_state")]
    pub install_state: String,
    /// Live dataplane self-test verification state:
    /// `"idle" | "probing" | "verified" | "degraded" | "failed"`.
    #[serde(default = "default_verify_state")]
    pub verify_state: String,
    /// End-to-end latency (ms) measured during the last successful WinDivert dataplane self-test.
    #[serde(default)]
    pub verify_latency_ms: Option<u64>,
    /// Plain-Chinese summary of the last dataplane self-test outcome.
    #[serde(default)]
    pub verify_message: Option<String>,
    /// Unix epoch timestamp (ms) of the last completed dataplane self-test.
    #[serde(default)]
    pub verify_checked_at_ms: Option<u64>,
    /// Security / firewall products detected read-only on this host (e.g. Huorong, Defender, 360).
    #[serde(default)]
    pub detected_security_products: Vec<String>,
    /// Actionable Chinese guidance tailored to the host's security products when blocked/degraded.
    #[serde(default)]
    pub security_guidance: Option<String>,
    /// Physical exit NIC friendly name bound by the standalone `:443` tunnel (e.g. `"WLAN"`).
    #[serde(default)]
    pub bound_physical_interface: Option<String>,
    pub socks_port: Option<u16>,
    pub windivert_available: bool,
    pub windivert_path: Option<String>,
    pub is_elevated: bool,
    pub active_connections: u64,
    pub total_connections: u64,
    pub up_bytes: u64,
    pub down_bytes: u64,
    pub accelerated_processes: Vec<String>,
    #[serde(default)]
    pub process_stats: Vec<AcceleratedProcessStat>,
    pub active_relays: Vec<String>,
    pub last_error: Option<String>,
}

impl Default for GlobalPreAccelStatus {
    fn default() -> Self {
        Self {
            running: false,
            mode: "off".to_string(),
            is_windivert_active: false,
            install_state: default_install_state(),
            verify_state: default_verify_state(),
            verify_latency_ms: None,
            verify_message: None,
            verify_checked_at_ms: None,
            detected_security_products: Vec::new(),
            security_guidance: None,
            bound_physical_interface: None,
            socks_port: None,
            windivert_available: false,
            windivert_path: None,
            is_elevated: false,
            active_connections: 0,
            total_connections: 0,
            up_bytes: 0,
            down_bytes: 0,
            accelerated_processes: Vec::new(),
            process_stats: Vec::new(),
            active_relays: Vec::new(),
            last_error: None,
        }
    }
}

#[derive(Debug, Clone)]
struct VerifySnapshot {
    state: String,
    latency_ms: Option<u64>,
    message: Option<String>,
    checked_at_ms: Option<u64>,
    security_guidance: Option<String>,
}

impl Default for VerifySnapshot {
    fn default() -> Self {
        Self {
            state: default_verify_state(),
            latency_ms: None,
            message: None,
            checked_at_ms: None,
            security_guidance: None,
        }
    }
}

/// Normalized static configuration fingerprint of a running WinDivert engine, intentionally
/// excluding dynamically hot-synced `main_core_pid` so unrelated config reloads keep existing
/// intercepted flows alive without tearing down WinDivert.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
struct WinDivertRuntimeFingerprint {
    dll_path: PathBuf,
    sys_path: Option<PathBuf>,
    relay_ipv4s: Vec<Ipv4Addr>,
    skip_443_native: bool,
    scope: GlobalPreAccelScope,
    target_processes: Vec<String>,
    static_excluded_pids: Vec<u32>,
}

#[allow(dead_code)]
impl WinDivertRuntimeFingerprint {
    fn from_inputs(
        dll_path: PathBuf,
        sys_path: Option<PathBuf>,
        relay_ipv4s: &[Ipv4Addr],
        skip_443_native: bool,
        scope: GlobalPreAccelScope,
        target_processes: &[String],
        static_excluded_pids: &HashSet<u32>,
    ) -> Self {
        let mut sorted_relays: Vec<Ipv4Addr> = relay_ipv4s.to_vec();
        sorted_relays.sort_unstable();
        sorted_relays.dedup();

        let mut normalized_procs: Vec<String> = target_processes
            .iter()
            .map(|p| normalize_process_basename(p))
            .filter(|p| !p.is_empty())
            .collect();
        normalized_procs.sort();
        normalized_procs.dedup();

        let mut sorted_pids: Vec<u32> = static_excluded_pids.iter().copied().collect();
        sorted_pids.sort_unstable();
        sorted_pids.dedup();

        Self {
            dll_path,
            sys_path,
            relay_ipv4s: sorted_relays,
            skip_443_native,
            scope,
            target_processes: normalized_procs,
            static_excluded_pids: sorted_pids,
        }
    }
}

#[allow(dead_code)]
fn should_skip_windivert_restart(
    tunnel_changed: bool,
    old_fp: Option<&WinDivertRuntimeFingerprint>,
    next_fp: Option<&WinDivertRuntimeFingerprint>,
) -> bool {
    !tunnel_changed && old_fp.is_some() && old_fp == next_fp
}

/// Strict HTTP 204 validator for WinDivert dataplane self-test results (rejects captive-portal
/// 200/302 responses, 4xx/5xx gateway errors, and empty/truncated non-HTTP replies).
#[allow(dead_code)]
pub(crate) fn validate_self_test_http_status(status_code: Option<u16>) -> Result<u16, String> {
    match status_code {
        Some(204) => Ok(204),
        Some(code) => Err(format!(
            "返回非预期 HTTP {code}（期望 HTTP 204，疑似被门户劫持或上游异常）"
        )),
        None => Err("返回空响应或非标准 HTTP 报文（期望 HTTP 204）".to_string()),
    }
}

#[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
fn enforce_self_test_strict_204(
    outcome: super::windivert_win::WinDivertSelfTestOutcome,
) -> super::windivert_win::WinDivertSelfTestOutcome {
    match outcome {
        super::windivert_win::WinDivertSelfTestOutcome::Passed {
            latency_ms,
            probe_host,
            status_code,
        } => match validate_self_test_http_status(Some(status_code)) {
            Ok(code) => super::windivert_win::WinDivertSelfTestOutcome::Passed {
                latency_ms,
                probe_host,
                status_code: code,
            },
            Err(reason) => super::windivert_win::WinDivertSelfTestOutcome::TunnelUnreachable {
                detail: format!("{probe_host} {reason}"),
            },
        },
        other => other,
    }
}

#[derive(Debug)]
struct ActiveGlobalRuntime {
    #[cfg(target_os = "windows")]
    engine: Option<super::windivert_win::WinDivertEngine>,
    #[allow(dead_code)]
    windivert_fp: Option<WinDivertRuntimeFingerprint>,
    tunnel: StandalonePreAccelTunnel,
    mode: String,
    socks_port: u16,
    active_relays: Vec<String>,
    bound_physical_interface: Option<String>,
}

impl ActiveGlobalRuntime {
    async fn stop(mut self, teardown_service: bool) {
        // Stop WinDivert kernel interception BEFORE tearing down the standalone 443 tunnel so
        // native network flow resumes immediately with zero packet drops.
        #[cfg(target_os = "windows")]
        if let Some(mut engine) = self.engine.take() {
            let _ = tokio::task::spawn_blocking(move || {
                engine.stop_sync_with_teardown(teardown_service);
            })
            .await;
        }
        #[cfg(not(target_os = "windows"))]
        let _ = teardown_service;
        self.tunnel.stop().await;
    }
}

/// Cross-platform manager orchestrating the standalone lightweight :443 dual-active tunnel
/// and (on elevated Windows with WinDivert v2.2.2) the native kernel transparent TCP NAT engine.
#[derive(Debug)]
pub struct GlobalPreAccelManager {
    paths: AppPaths,
    job_guard: Arc<JobGuard>,
    op_lock: tokio::sync::Mutex<()>,
    runtime: Mutex<Option<ActiveGlobalRuntime>>,
    metrics: Arc<GlobalPreAccelMetrics>,
    last_error: Mutex<Option<String>>,
    install_state: Mutex<String>,
    verify_snapshot: Mutex<VerifySnapshot>,
    detected_security_products: Mutex<Vec<String>>,
    custom_windivert_dir: Mutex<Option<String>>,
    synced_main_core_pid: Mutex<Option<u32>>,
    suspended_for_tun_relays: Mutex<Option<Vec<String>>>,
}

impl GlobalPreAccelManager {
    pub fn new(paths: AppPaths, job_guard: Arc<JobGuard>) -> Self {
        Self {
            paths,
            job_guard,
            op_lock: tokio::sync::Mutex::new(()),
            runtime: Mutex::new(None),
            metrics: Arc::new(GlobalPreAccelMetrics::default()),
            last_error: Mutex::new(None),
            install_state: Mutex::new(default_install_state()),
            verify_snapshot: Mutex::new(VerifySnapshot::default()),
            detected_security_products: Mutex::new(Vec::new()),
            custom_windivert_dir: Mutex::new(None),
            synced_main_core_pid: Mutex::new(None),
            suspended_for_tun_relays: Mutex::new(None),
        }
    }

    fn persist_current_runtime_meta(&self) {
        let running_meta = {
            let guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
            guard.as_ref().map(|rt| {
                let effective_carrier = if rt.mode == "windivert" {
                    "standalone_windivert"
                } else {
                    "standalone_socks5"
                };
                GlobalPreAccelRuntimeMeta {
                    pid: rt.tunnel.pid(),
                    process_start_time_unix: rt.tunnel.process_start_time_unix(),
                    binary_path: Some(rt.tunnel.binary_path().to_string_lossy().to_string()),
                    running: true,
                    mode: rt.mode.clone(),
                    effective_carrier: effective_carrier.to_string(),
                    socks_port: Some(rt.socks_port),
                    active_relays: rt.active_relays.clone(),
                    updated_at: chrono::Utc::now().to_rfc3339(),
                }
            })
        };

        if let Some(meta) = running_meta {
            let _ = write_global_preaccel_runtime_meta(&self.paths.root_data_dir, &meta);
            return;
        }

        let suspended_relays = self
            .suspended_for_tun_relays
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(active_relays) = suspended_relays {
            let meta = GlobalPreAccelRuntimeMeta {
                pid: None,
                process_start_time_unix: None,
                binary_path: None,
                running: false,
                mode: "suspended_for_tun".to_string(),
                effective_carrier: "main_core_tun_suspended_standalone".to_string(),
                socks_port: None,
                active_relays,
                updated_at: chrono::Utc::now().to_rfc3339(),
            };
            let _ = write_global_preaccel_runtime_meta(&self.paths.root_data_dir, &meta);
        } else {
            remove_global_preaccel_runtime_meta(&self.paths.root_data_dir);
        }
    }

    /// Update the driver installation / elevation lifecycle state exposed in `GlobalPreAccelStatus`.
    /// Accepted values: `"idle" | "downloading" | "verifying" | "ready" | "need_elevation" | "failed"`.
    pub fn set_install_state(&self, state: &str) {
        let normalized = normalize_install_state(state);
        let mut guard = self
            .install_state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *guard = normalized.to_string();
    }

    /// Read the currently stored driver installation / elevation lifecycle state.
    pub fn install_state(&self) -> String {
        self.install_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn set_verify_snapshot(&self, snapshot: VerifySnapshot) {
        if let Ok(mut guard) = self.verify_snapshot.lock() {
            *guard = VerifySnapshot {
                state: normalize_verify_state(&snapshot.state).to_string(),
                ..snapshot
            };
        }
    }

    fn reset_verify_snapshot(&self) {
        self.set_verify_snapshot(VerifySnapshot::default());
    }

    fn refresh_detected_security_products(&self) -> Vec<String> {
        let products = detect_host_security_products();
        if let Ok(mut guard) = self.detected_security_products.lock() {
            *guard = products.clone();
        }
        products
    }

    /// Dynamically synchronize the external main Mihomo core PID excluded from Windows
    /// transparent WinDivert interception (for example when the main core starts, restarts,
    /// or stops while operating in mixed-port-only mode without system proxy / TUN takeover).
    ///
    /// Always preserves CatCloud's own PID and the standalone :443 tunnel subprocess PID.
    pub fn sync_main_core_pid(&self, main_core_pid: Option<u32>) {
        let normalized = main_core_pid.filter(|&pid| pid > 0);
        let mut slot = self
            .synced_main_core_pid
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *slot = normalized;

        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        {
            let rt_guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(rt) = rt_guard.as_ref() {
                if let Some(engine) = rt.engine.as_ref() {
                    engine.sync_main_core_pid(normalized);
                }
            }
        }
    }

    /// Start (or restart) the standalone global domestic :443 pre-acceleration engine.
    ///
    /// - Launches the standalone lightweight `:443` dual-active SOCKS5 tunnel on all platforms.
    /// - On x64 Windows, when running elevated with `WinDivert64.dll` + `WinDivert64.sys` present,
    ///   engages the transparent kernel TCP NAT engine (`mode = "windivert"`) while excluding
    ///   CatCloud itself, the standalone tunnel PID, and any `extra_excluded_pids` (such as
    ///   CatCloud's main Mihomo core PID).
    /// - Falls back cleanly to `mode = "local_socks5"` on macOS/Linux, Windows ARM64, or
    ///   non-elevated/missing-driver Windows environments without ever disrupting network connectivity.
    pub async fn start(
        &self,
        cfg: &AppConfig,
        relays: &[PreAccelRelay],
        extra_excluded_pids: &[u32],
    ) -> CatResult<GlobalPreAccelStatus> {
        let _op = self.op_lock.lock().await;
        self.start_locked(cfg, relays, extra_excluded_pids, &_op)
            .await
    }

    async fn start_locked(
        &self,
        cfg: &AppConfig,
        relays: &[PreAccelRelay],
        extra_excluded_pids: &[u32],
        _op_guard: &tokio::sync::MutexGuard<'_, ()>,
    ) -> CatResult<GlobalPreAccelStatus> {
        {
            let mut dir_guard = self
                .custom_windivert_dir
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *dir_guard = cfg.preaccel.windivert_dir.clone();
        }

        // Clear any prior TUN-suspension state before starting a live standalone tunnel.
        {
            let mut susp_guard = self
                .suspended_for_tun_relays
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *susp_guard = None;
        }

        // Cleanly stop any previous runtime before starting a fresh instance (hot rebuild:
        // keep the WinDivert kernel service loaded to avoid Win32 error 1072 races).
        let previous = {
            let mut rt_guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
            rt_guard.take()
        };
        if let Some(prev) = previous {
            prev.stop(false).await;
        }
        remove_global_preaccel_runtime_meta(&self.paths.root_data_dir);
        self.metrics.reset();
        self.set_last_error(None);
        self.reset_verify_snapshot();
        let detected_products = self.refresh_detected_security_products();

        let tunnel = match StandalonePreAccelTunnel::start(
            &self.paths,
            cfg,
            relays,
            Arc::clone(&self.job_guard),
            None,
        )
        .await
        {
            Ok(t) => t,
            Err(err) => {
                self.set_last_error(Some(err.to_string()));
                return Err(err);
            }
        };

        let socks_port = tunnel.socks_port();
        let active_relays = tunnel.active_relays().to_vec();
        let bound_physical_interface = tunnel.bound_physical_interface().map(ToString::to_string);
        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        let mut mode = "local_socks5".to_string();
        #[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
        let mode = "local_socks5".to_string();

        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        let mut win_engine: Option<super::windivert_win::WinDivertEngine> = None;
        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        let mut win_engine_fp: Option<WinDivertRuntimeFingerprint> = None;
        #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
        let win_engine: Option<super::windivert_win::WinDivertEngine> = None;

        #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
        {
            let _ = (extra_excluded_pids, detected_products);
            self.set_last_error(Some(WINDIVERT_ARM64_UNSUPPORTED_MSG.to_string()));
        }

        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        {
            let is_elevated = default_platform().capabilities().is_elevated;
            let wd_files =
                locate_windivert_files(&self.paths, cfg.preaccel.windivert_dir.as_deref());

            if !is_elevated {
                if wd_files.is_some() {
                    self.set_install_state("need_elevation");
                } else {
                    let cur_state = self.install_state();
                    if cur_state != "downloading" && cur_state != "verifying" {
                        self.set_install_state("idle");
                    }
                }
                self.set_last_error(Some(
                    "当前非管理员权限，已自动运行在本地独立 443 SOCKS5 隧道模式；如需透明加速其它软件请以管理员身份运行"
                        .to_string(),
                ));
            } else if let Some((dll_path, sys_path)) = wd_files {
                let synced_main_pid = *self
                    .synced_main_core_pid
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let mut static_excluded_pids: HashSet<u32> = HashSet::new();
                for &pid in extra_excluded_pids {
                    if pid > 0 && Some(pid) != synced_main_pid {
                        static_excluded_pids.insert(pid);
                    }
                }

                let relay_ipv4s = collect_enabled_relay_ipv4s(relays);
                let wd_fp = WinDivertRuntimeFingerprint::from_inputs(
                    dll_path.clone(),
                    Some(sys_path),
                    &relay_ipv4s,
                    cfg.preaccel.skip_443_native,
                    cfg.preaccel.global_scope,
                    &cfg.preaccel.global_target_processes,
                    &static_excluded_pids,
                );
                let bin_dir = dll_path.parent().map(Path::to_path_buf);
                let engine_cfg = super::windivert_win::WinDivertEngineConfig {
                    dll_path,
                    socks_port,
                    relay_ipv4s,
                    skip_443_native: cfg.preaccel.skip_443_native,
                    scope: cfg.preaccel.global_scope,
                    target_processes: cfg.preaccel.global_target_processes.clone(),
                    excluded_pids: static_excluded_pids,
                    tunnel_pid: tunnel.pid(),
                    main_core_pid: synced_main_pid,
                    metrics: Arc::clone(&self.metrics),
                };

                match super::windivert_win::WinDivertEngine::start(engine_cfg).await {
                    Ok(mut engine) => {
                        self.set_verify_snapshot(VerifySnapshot {
                            state: "probing".to_string(),
                            latency_ms: None,
                            message: Some("正在自动探测底层透明加速链路…".to_string()),
                            checked_at_ms: None,
                            security_guidance: None,
                        });
                        let probe_urls = build_self_test_probe_urls(&cfg.preaccel.probe_url);
                        let probe_refs: Vec<&str> = probe_urls.iter().map(String::as_str).collect();
                        let outcome = enforce_self_test_strict_204(
                            engine
                                .run_self_test(&probe_refs, Duration::from_secs(4))
                                .await,
                        );
                        match outcome {
                            super::windivert_win::WinDivertSelfTestOutcome::Passed {
                                latency_ms,
                                probe_host,
                                status_code,
                            } => {
                                win_engine = Some(engine);
                                win_engine_fp = Some(wd_fp);
                                mode = "windivert".to_string();
                                self.set_install_state("ready");
                                self.set_last_error(None);
                                self.set_verify_snapshot(VerifySnapshot {
                                    state: "verified".to_string(),
                                    latency_ms: Some(latency_ms),
                                    message: Some(format!(
                                        "自动探测畅通：经由底层透明拦截与国内 443 中转连通 {probe_host}（HTTP {status_code}，{latency_ms} ms）"
                                    )),
                                    checked_at_ms: Some(now_epoch_ms()),
                                    security_guidance: None,
                                });
                            }
                            other => {
                                // Fail-safe circuit breaker: immediately tear down WinDivert
                                // interception and stop its kernel service so broken packet
                                // injection never blackholes the host.
                                let _ = tokio::task::spawn_blocking(move || {
                                    engine.stop_sync_with_teardown(true);
                                })
                                .await;
                                let (msg, guidance) = classify_self_test_failure(
                                    &other,
                                    &detected_products,
                                    bin_dir.as_deref(),
                                );
                                self.set_install_state("ready");
                                self.set_last_error(Some(msg.clone()));
                                self.set_verify_snapshot(VerifySnapshot {
                                    state: "degraded".to_string(),
                                    latency_ms: None,
                                    message: Some(msg),
                                    checked_at_ms: Some(now_epoch_ms()),
                                    security_guidance: guidance,
                                });
                            }
                        }
                    }
                    Err(err) => {
                        let guidance = build_security_guidance(
                            &detected_products,
                            bin_dir.as_deref(),
                            "driver_load",
                        );
                        self.set_install_state("failed");
                        self.set_last_error(Some(format!(
                            "WinDivert 透明内核引擎启动失败，已降级为本地独立 443 SOCKS5 隧道（{err}）"
                        )));
                        self.set_verify_snapshot(VerifySnapshot {
                            state: "failed".to_string(),
                            latency_ms: None,
                            message: Some(err.to_string()),
                            checked_at_ms: Some(now_epoch_ms()),
                            security_guidance: Some(guidance),
                        });
                    }
                }
            } else {
                let cur_state = self.install_state();
                if cur_state != "downloading" && cur_state != "verifying" {
                    self.set_install_state("idle");
                }
                self.set_last_error(Some(
                    "尚未安装 WinDivert v2.2.2 驱动组件，已自动运行在本地独立 443 SOCKS5 隧道模式"
                        .to_string(),
                ));
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = (extra_excluded_pids, detected_products);
        }

        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        {
            let synced_guard = self
                .synced_main_core_pid
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(ref engine) = win_engine {
                engine.sync_main_core_pid(*synced_guard);
            }
            let mut rt_guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
            *rt_guard = Some(ActiveGlobalRuntime {
                engine: win_engine,
                windivert_fp: win_engine_fp,
                tunnel,
                mode,
                socks_port,
                active_relays,
                bound_physical_interface,
            });
        }

        #[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
        {
            let mut rt_guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
            *rt_guard = Some(ActiveGlobalRuntime {
                #[cfg(target_os = "windows")]
                engine: win_engine,
                windivert_fp: None,
                tunnel,
                mode,
                socks_port,
                active_relays,
                bound_physical_interface,
            });
        }

        self.persist_current_runtime_meta();
        Ok(self.status())
    }

    /// Hot-upgrade a running `"local_socks5"` runtime in place to `"windivert"` transparent kernel
    /// interception once WinDivert driver files are ready, without stopping or interrupting the
    /// active standalone `:443` SOCKS5 tunnel.
    pub async fn upgrade_to_windivert_in_place(
        &self,
        cfg: &AppConfig,
        relays: &[PreAccelRelay],
        extra_excluded_pids: &[u32],
    ) -> CatResult<GlobalPreAccelStatus> {
        let _op = self.op_lock.lock().await;
        self.upgrade_to_windivert_in_place_locked(cfg, relays, extra_excluded_pids, &_op)
            .await
    }

    async fn upgrade_to_windivert_in_place_locked(
        &self,
        cfg: &AppConfig,
        relays: &[PreAccelRelay],
        extra_excluded_pids: &[u32],
        _op_guard: &tokio::sync::MutexGuard<'_, ()>,
    ) -> CatResult<GlobalPreAccelStatus> {
        {
            let mut dir_guard = self
                .custom_windivert_dir
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *dir_guard = cfg.preaccel.windivert_dir.clone();
        }

        #[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
        {
            let _ = (relays, extra_excluded_pids);
            #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
            {
                self.set_last_error(Some(WINDIVERT_ARM64_UNSUPPORTED_MSG.to_string()));
            }
            Ok(self.status())
        }

        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        {
            let running_snapshot = {
                let rt_guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
                rt_guard
                    .as_ref()
                    .map(|rt| (rt.mode == "windivert", rt.socks_port, rt.tunnel.pid()))
            };

            let Some((already_windivert, socks_port, tunnel_pid)) = running_snapshot else {
                // Not running: reflect readiness/elevation accurately without starting a new tunnel.
                let wd_ready =
                    locate_windivert_files(&self.paths, cfg.preaccel.windivert_dir.as_deref())
                        .is_some();
                if wd_ready {
                    if default_platform().capabilities().is_elevated {
                        self.set_install_state("ready");
                    } else {
                        self.set_install_state("need_elevation");
                    }
                } else {
                    self.set_install_state("idle");
                }
                return Ok(self.status());
            };

            if already_windivert {
                self.set_install_state("ready");
                self.set_last_error(None);
                return Ok(self.status());
            }

            let Some((dll_path, sys_path)) =
                locate_windivert_files(&self.paths, cfg.preaccel.windivert_dir.as_deref())
            else {
                self.set_install_state("failed");
                self.set_last_error(Some(
                    "未找到 WinDivert v2.2.2 驱动文件（WinDivert64.dll / WinDivert64.sys），继续保持本地独立 443 通道"
                        .to_string(),
                ));
                return Ok(self.status());
            };

            let is_elevated = default_platform().capabilities().is_elevated;
            if !is_elevated {
                self.set_install_state("need_elevation");
                self.set_last_error(Some(
                    "WinDivert 驱动已就绪，请以管理员身份重启猫猫云梯以启用底层透明提速"
                        .to_string(),
                ));
                return Ok(self.status());
            }

            let synced_main_pid = *self
                .synced_main_core_pid
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let mut static_excluded_pids: HashSet<u32> = HashSet::new();
            for &pid in extra_excluded_pids {
                if pid > 0 && Some(pid) != synced_main_pid {
                    static_excluded_pids.insert(pid);
                }
            }

            let relay_ipv4s = collect_enabled_relay_ipv4s(relays);
            let wd_fp = WinDivertRuntimeFingerprint::from_inputs(
                dll_path.clone(),
                Some(sys_path),
                &relay_ipv4s,
                cfg.preaccel.skip_443_native,
                cfg.preaccel.global_scope,
                &cfg.preaccel.global_target_processes,
                &static_excluded_pids,
            );
            let bin_dir = dll_path.parent().map(Path::to_path_buf);
            let detected_products = self.refresh_detected_security_products();
            let engine_cfg = super::windivert_win::WinDivertEngineConfig {
                dll_path,
                socks_port,
                relay_ipv4s,
                skip_443_native: cfg.preaccel.skip_443_native,
                scope: cfg.preaccel.global_scope,
                target_processes: cfg.preaccel.global_target_processes.clone(),
                excluded_pids: static_excluded_pids,
                tunnel_pid,
                main_core_pid: synced_main_pid,
                metrics: Arc::clone(&self.metrics),
            };

            match super::windivert_win::WinDivertEngine::start(engine_cfg).await {
                Ok(mut engine) => {
                    self.set_verify_snapshot(VerifySnapshot {
                        state: "probing".to_string(),
                        latency_ms: None,
                        message: Some("正在自动探测底层透明加速链路…".to_string()),
                        checked_at_ms: None,
                        security_guidance: None,
                    });
                    let probe_urls = build_self_test_probe_urls(&cfg.preaccel.probe_url);
                    let probe_refs: Vec<&str> = probe_urls.iter().map(String::as_str).collect();
                    let outcome = enforce_self_test_strict_204(
                        engine
                            .run_self_test(&probe_refs, Duration::from_secs(4))
                            .await,
                    );
                    match outcome {
                        super::windivert_win::WinDivertSelfTestOutcome::Passed {
                            latency_ms,
                            probe_host,
                            status_code,
                        } => {
                            let (installed, displaced_engine) = {
                                let synced_guard = self
                                    .synced_main_core_pid
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner());
                                engine.sync_main_core_pid(*synced_guard);
                                let mut rt_guard =
                                    self.runtime.lock().unwrap_or_else(|e| e.into_inner());
                                if let Some(rt) = rt_guard.as_mut() {
                                    let old = rt.engine.replace(engine);
                                    rt.windivert_fp = Some(wd_fp);
                                    rt.mode = "windivert".to_string();
                                    (true, old)
                                } else {
                                    (false, Some(engine))
                                }
                            };
                            if let Some(mut stale) = displaced_engine {
                                let teardown_service = !installed;
                                let _ = tokio::task::spawn_blocking(move || {
                                    stale.stop_sync_with_teardown(teardown_service);
                                })
                                .await;
                            }
                            if installed {
                                self.set_install_state("ready");
                                self.set_last_error(None);
                                self.set_verify_snapshot(VerifySnapshot {
                                    state: "verified".to_string(),
                                    latency_ms: Some(latency_ms),
                                    message: Some(format!(
                                        "自动探测畅通：经由底层透明拦截与国内 443 中转连通 {probe_host}（HTTP {status_code}，{latency_ms} ms）"
                                    )),
                                    checked_at_ms: Some(now_epoch_ms()),
                                    security_guidance: None,
                                });
                                self.persist_current_runtime_meta();
                            } else {
                                let wd_ready = locate_windivert_files(
                                    &self.paths,
                                    cfg.preaccel.windivert_dir.as_deref(),
                                )
                                .is_some();
                                if wd_ready && is_elevated {
                                    self.set_install_state("ready");
                                } else if wd_ready {
                                    self.set_install_state("need_elevation");
                                } else {
                                    self.set_install_state("idle");
                                }
                                self.reset_verify_snapshot();
                            }
                            Ok(self.status())
                        }
                        other => {
                            let _ = tokio::task::spawn_blocking(move || {
                                engine.stop_sync_with_teardown(true);
                            })
                            .await;
                            let (msg, guidance) = classify_self_test_failure(
                                &other,
                                &detected_products,
                                bin_dir.as_deref(),
                            );
                            self.set_install_state("ready");
                            self.set_last_error(Some(msg.clone()));
                            self.set_verify_snapshot(VerifySnapshot {
                                state: "degraded".to_string(),
                                latency_ms: None,
                                message: Some(msg),
                                checked_at_ms: Some(now_epoch_ms()),
                                security_guidance: guidance,
                            });
                            Ok(self.status())
                        }
                    }
                }
                Err(err) => {
                    let guidance = build_security_guidance(
                        &detected_products,
                        bin_dir.as_deref(),
                        "driver_load",
                    );
                    self.set_install_state("failed");
                    self.set_last_error(Some(format!(
                        "WinDivert 驱动就绪后原地热升格失败，继续保持本地独立 443 通道（{err}）"
                    )));
                    self.set_verify_snapshot(VerifySnapshot {
                        state: "failed".to_string(),
                        latency_ms: None,
                        message: Some(err.to_string()),
                        checked_at_ms: Some(now_epoch_ms()),
                        security_guidance: Some(guidance),
                    });
                    Err(err)
                }
            }
        }
    }

    /// Re-verify live transparent WinDivert dataplane connectivity on demand (e.g. after
    /// switching Wi-Fi/Ethernet, toggling a third-party TUN, or allowlisting CatCloud in
    /// Huorong / Windows Defender / 360).
    ///
    /// - When already running in `windivert` mode, runs an active non-disruptive dataplane
    ///   self-test and triggers automatic fail-safe downgrade to `local_socks5` if blocked.
    /// - When previously degraded to `local_socks5` (with driver + admin privileges available),
    ///   re-detects the current primary physical NIC and attempts a clean upgrade + self-test.
    pub async fn reverify_windivert(
        &self,
        cfg: &AppConfig,
        relays: &[PreAccelRelay],
        extra_excluded_pids: &[u32],
    ) -> CatResult<GlobalPreAccelStatus> {
        #[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
        {
            let _ = (cfg, relays, extra_excluded_pids);
            return Ok(self.status());
        }

        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        {
            let _op = self.op_lock.lock().await;
            let detected_products = self.refresh_detected_security_products();

            let (running, is_windivert, bound_if, bin_dir) = {
                let wd_dir =
                    locate_windivert_files(&self.paths, cfg.preaccel.windivert_dir.as_deref())
                        .and_then(|(dll, _)| dll.parent().map(Path::to_path_buf));
                let guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
                match guard.as_ref() {
                    Some(rt) => (
                        true,
                        rt.mode == "windivert" && rt.engine.is_some(),
                        rt.bound_physical_interface.clone(),
                        wd_dir,
                    ),
                    None => (false, false, None, wd_dir),
                }
            };

            if !running {
                return Ok(self.status());
            }

            if is_windivert {
                self.set_verify_snapshot(VerifySnapshot {
                    state: "probing".to_string(),
                    latency_ms: None,
                    message: Some("正在重新探测底层透明加速链路…".to_string()),
                    checked_at_ms: None,
                    security_guidance: None,
                });

                // Temporarily take the engine handle out of the mutex while running the async probe
                // so status snapshots never block and `op_lock` guarantees exclusive lifecycle control.
                let engine_opt = {
                    let mut guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
                    guard.as_mut().and_then(|rt| rt.engine.take())
                };
                if let Some(mut engine) = engine_opt {
                    let probe_urls = build_self_test_probe_urls(&cfg.preaccel.probe_url);
                    let probe_refs: Vec<&str> = probe_urls.iter().map(String::as_str).collect();
                    let outcome = enforce_self_test_strict_204(
                        engine
                            .run_self_test(&probe_refs, Duration::from_secs(4))
                            .await,
                    );
                    match outcome {
                        super::windivert_win::WinDivertSelfTestOutcome::Passed {
                            latency_ms,
                            probe_host,
                            status_code,
                        } => {
                            let leftover_engine = {
                                let mut guard =
                                    self.runtime.lock().unwrap_or_else(|e| e.into_inner());
                                if let Some(rt) = guard.as_mut() {
                                    rt.engine = Some(engine);
                                    rt.mode = "windivert".to_string();
                                    None
                                } else {
                                    Some(engine)
                                }
                            };
                            if let Some(mut orphan) = leftover_engine {
                                let _ = tokio::task::spawn_blocking(move || {
                                    orphan.stop_sync_with_teardown(true);
                                })
                                .await;
                                return Ok(self.status());
                            }
                            self.set_last_error(None);
                            self.set_verify_snapshot(VerifySnapshot {
                                state: "verified".to_string(),
                                latency_ms: Some(latency_ms),
                                message: Some(format!(
                                    "自动探测畅通：经由底层透明拦截与国内 443 中转连通 {probe_host}（HTTP {status_code}，{latency_ms} ms）"
                                )),
                                checked_at_ms: Some(now_epoch_ms()),
                                security_guidance: None,
                            });
                            self.persist_current_runtime_meta();
                            return Ok(self.status());
                        }
                        other => {
                            let _ = tokio::task::spawn_blocking(move || {
                                engine.stop_sync_with_teardown(true);
                            })
                            .await;
                            {
                                let mut guard =
                                    self.runtime.lock().unwrap_or_else(|e| e.into_inner());
                                if let Some(rt) = guard.as_mut() {
                                    rt.windivert_fp = None;
                                    rt.mode = "local_socks5".to_string();
                                }
                            }
                            self.persist_current_runtime_meta();
                            let (msg, guidance) = classify_self_test_failure(
                                &other,
                                &detected_products,
                                bin_dir.as_deref(),
                            );
                            self.set_last_error(Some(msg.clone()));
                            self.set_verify_snapshot(VerifySnapshot {
                                state: "degraded".to_string(),
                                latency_ms: None,
                                message: Some(msg),
                                checked_at_ms: Some(now_epoch_ms()),
                                security_guidance: guidance,
                            });
                            return Ok(self.status());
                        }
                    }
                }
            }

            // Currently running in `local_socks5`: check if primary physical NIC changed
            // (e.g. switched Ethernet <-> Wi-Fi) and retry full start or in-place upgrade
            // while holding the SAME `_op` lock so a concurrent `stop()` can never be resurrected.
            let latest_physical_if = tokio::task::spawn_blocking(|| {
                super::windivert_win::detect_primary_physical_interface().map(|i| i.friendly_name)
            })
            .await
            .ok()
            .flatten();
            let need_tunnel_rebuild = latest_physical_if != bound_if;

            if need_tunnel_rebuild {
                self.start_locked(cfg, relays, extra_excluded_pids, &_op)
                    .await
            } else {
                self.upgrade_to_windivert_in_place_locked(cfg, relays, extra_excluded_pids, &_op)
                    .await
            }
        }
    }

    /// Stop only the active WinDivert packet-interception handle for an imminent hot reload
    /// without stopping the `WinDivert` kernel driver service (avoiding Win32 error 1072 races)
    /// and without interrupting the standalone `:443` SOCKS5 tunnel.
    pub async fn stop_windivert_for_reload(&self) -> CatResult<GlobalPreAccelStatus> {
        let _op = self.op_lock.lock().await;
        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        {
            let engine_opt = {
                let mut rt_guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(rt) = rt_guard.as_mut() {
                    let taken = rt.engine.take();
                    if taken.is_some() {
                        rt.windivert_fp = None;
                        rt.mode = "local_socks5".to_string();
                    }
                    taken
                } else {
                    None
                }
            };
            if let Some(mut engine) = engine_opt {
                let _ = tokio::task::spawn_blocking(move || {
                    engine.stop_sync_with_teardown(false);
                })
                .await;
                self.metrics.clear_active_connections();
                self.persist_current_runtime_meta();
            }
        }
        Ok(self.status())
    }

    /// Hot-rebuild the running WinDivert transparent engine (and, when relay/probe settings
    /// changed, the standalone `:443` tunnel) using `stop_sync_with_teardown(false)` so the
    /// `WinDivert` kernel service stays loaded across reloads without triggering Win32 1072 errors.
    ///
    /// Returns the current idle status without launching anything if the manager is not running.
    pub async fn restart_windivert_if_running(
        &self,
        cfg: &AppConfig,
        relays: &[PreAccelRelay],
        extra_excluded_pids: &[u32],
    ) -> CatResult<GlobalPreAccelStatus> {
        let _op = self.op_lock.lock().await;
        let runtime_info = {
            let rt_guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
            rt_guard.as_ref().map(|rt| {
                #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
                let has_engine = rt.engine.is_some();
                #[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
                let has_engine = false;
                (
                    rt.socks_port,
                    rt.bound_physical_interface.clone(),
                    rt.tunnel.config_sha256().to_string(),
                    has_engine,
                    rt.windivert_fp.clone(),
                )
            })
        };
        let Some((socks_port, bound_if, current_yaml_sha, has_windivert_engine, old_wd_fp)) =
            runtime_info
        else {
            return Ok(self.status());
        };

        let next_yaml_sha = compile_standalone_preaccel_yaml_with_interface(
            cfg,
            relays,
            socks_port,
            bound_if.as_deref(),
        )
        .ok()
        .map(|yaml| hex::encode(Sha256::digest(yaml.as_bytes())));
        let tunnel_changed = next_yaml_sha.as_deref() != Some(current_yaml_sha.as_str());

        if tunnel_changed {
            return self
                .start_locked(cfg, relays, extra_excluded_pids, &_op)
                .await;
        }

        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        {
            if has_windivert_engine {
                let synced_main_pid = *self
                    .synced_main_core_pid
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let mut static_excluded_pids: HashSet<u32> = HashSet::new();
                for &pid in extra_excluded_pids {
                    if pid > 0 && Some(pid) != synced_main_pid {
                        static_excluded_pids.insert(pid);
                    }
                }
                let next_wd_fp =
                    locate_windivert_files(&self.paths, cfg.preaccel.windivert_dir.as_deref()).map(
                        |(dll_path, sys_path)| {
                            let relay_ipv4s = collect_enabled_relay_ipv4s(relays);
                            WinDivertRuntimeFingerprint::from_inputs(
                                dll_path,
                                Some(sys_path),
                                &relay_ipv4s,
                                cfg.preaccel.skip_443_native,
                                cfg.preaccel.global_scope,
                                &cfg.preaccel.global_target_processes,
                                &static_excluded_pids,
                            )
                        },
                    );
                if should_skip_windivert_restart(
                    tunnel_changed,
                    old_wd_fp.as_ref(),
                    next_wd_fp.as_ref(),
                ) {
                    let mut dir_guard = self
                        .custom_windivert_dir
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    *dir_guard = cfg.preaccel.windivert_dir.clone();
                    return Ok(self.status());
                }

                let old_engine = {
                    let mut rt_guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(rt) = rt_guard.as_mut() {
                        let taken = rt.engine.take();
                        if taken.is_some() {
                            rt.windivert_fp = None;
                            rt.mode = "local_socks5".to_string();
                        }
                        taken
                    } else {
                        None
                    }
                };
                if let Some(mut engine) = old_engine {
                    let _ = tokio::task::spawn_blocking(move || {
                        engine.stop_sync_with_teardown(false);
                    })
                    .await;
                    self.metrics.clear_active_connections();
                }
                return self
                    .upgrade_to_windivert_in_place_locked(cfg, relays, extra_excluded_pids, &_op)
                    .await;
            }
        }
        #[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
        let _ = old_wd_fp;

        {
            let mut dir_guard = self
                .custom_windivert_dir
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *dir_guard = cfg.preaccel.windivert_dir.clone();
        }

        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        {
            if !has_windivert_engine
                && default_platform().capabilities().is_elevated
                && locate_windivert_paths(&self.paths, cfg.preaccel.windivert_dir.as_deref())
                    .is_some()
            {
                return self
                    .upgrade_to_windivert_in_place_locked(cfg, relays, extra_excluded_pids, &_op)
                    .await;
            }
        }

        #[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
        let _ = (extra_excluded_pids, has_windivert_engine);

        Ok(self.status())
    }

    /// Suspend the standalone `:443` tunnel cleanly while the primary Mihomo core's TUN virtual NIC
    /// carries domestic pre-acceleration, recording `mode = "suspended_for_tun"` and
    /// `effective_carrier = "main_core_tun_suspended_standalone"` both in memory and on disk
    /// (`run/global-preaccel-runtime.json`) instead of conflating with `"off"`.
    pub async fn suspend_for_tun(
        &self,
        active_relays: Vec<String>,
    ) -> CatResult<GlobalPreAccelStatus> {
        let _op = self.op_lock.lock().await;
        let current = {
            let mut rt_guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
            rt_guard.take()
        };
        if let Some(rt) = current {
            rt.stop(true).await;
        }
        self.metrics.reset();
        self.reset_verify_snapshot();
        self.set_last_error(None);
        {
            let mut susp_guard = self
                .suspended_for_tun_relays
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *susp_guard = Some(active_relays);
        }
        self.persist_current_runtime_meta();
        Ok(self.status())
    }

    /// Deterministically stop transparent interception (including stopping the WinDivert kernel
    /// service cleanly) and terminate the standalone :443 tunnel, clearing stale process cards
    /// and removing `run/global-preaccel-runtime.json`.
    pub async fn stop(&self) -> CatResult<GlobalPreAccelStatus> {
        let _op = self.op_lock.lock().await;
        {
            let mut susp_guard = self
                .suspended_for_tun_relays
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *susp_guard = None;
        }
        let current = {
            let mut rt_guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
            rt_guard.take()
        };
        if let Some(rt) = current {
            rt.stop(true).await;
        }
        self.metrics.reset();
        self.reset_verify_snapshot();
        self.set_last_error(None);
        remove_global_preaccel_runtime_meta(&self.paths.root_data_dir);
        Ok(self.status())
    }

    /// Capture an up-to-date status snapshot without blocking asynchronous callers.
    pub fn status(&self) -> GlobalPreAccelStatus {
        let custom_dir = self
            .custom_windivert_dir
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        self.status_with_custom_dir(custom_dir.as_deref())
    }

    /// Capture an up-to-date status snapshot evaluating WinDivert presence against `custom_dir`.
    pub fn status_with_custom_dir(&self, custom_dir: Option<&str>) -> GlobalPreAccelStatus {
        let is_elevated = default_platform().capabilities().is_elevated;
        let wd_files = locate_windivert_files(&self.paths, custom_dir);
        let windivert_available = wd_files.is_some();
        let windivert_path = wd_files.map(|(dll, _)| dll.to_string_lossy().to_string());

        let (running, mode, socks_port, active_relays, bound_physical_interface) = {
            let guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(rt) => (
                    true,
                    rt.mode.clone(),
                    Some(rt.socks_port),
                    rt.active_relays.clone(),
                    rt.bound_physical_interface.clone(),
                ),
                None => {
                    let susp = self
                        .suspended_for_tun_relays
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone();
                    if let Some(relays) = susp {
                        (false, "suspended_for_tun".to_string(), None, relays, None)
                    } else {
                        (false, "off".to_string(), None, Vec::new(), None)
                    }
                }
            }
        };

        let is_windivert_active = running && mode == "windivert";
        let stored_install_state = self
            .install_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let install_state = match stored_install_state.as_str() {
            "downloading" | "verifying" | "failed" => stored_install_state,
            _ => {
                #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
                {
                    if !windivert_available {
                        "idle".to_string()
                    } else if is_windivert_active || is_elevated {
                        "ready".to_string()
                    } else {
                        "need_elevation".to_string()
                    }
                }
                #[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
                {
                    stored_install_state
                }
            }
        };

        let verify_snap = self
            .verify_snapshot
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let detected_security_products = self
            .detected_security_products
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

        let last_error = self
            .last_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

        GlobalPreAccelStatus {
            running,
            mode,
            is_windivert_active,
            install_state,
            verify_state: verify_snap.state,
            verify_latency_ms: verify_snap.latency_ms,
            verify_message: verify_snap.message,
            verify_checked_at_ms: verify_snap.checked_at_ms,
            detected_security_products,
            security_guidance: verify_snap.security_guidance,
            bound_physical_interface,
            socks_port,
            windivert_available,
            windivert_path,
            is_elevated,
            active_connections: self.metrics.active_connections.load(Ordering::Relaxed),
            total_connections: self.metrics.total_connections.load(Ordering::Relaxed),
            up_bytes: self.metrics.up_bytes.load(Ordering::Relaxed),
            down_bytes: self.metrics.down_bytes.load(Ordering::Relaxed),
            accelerated_processes: self.metrics.recent_processes_snapshot(),
            process_stats: self.metrics.process_stats_snapshot(),
            active_relays,
            last_error,
        }
    }

    fn set_last_error(&self, err: Option<String>) {
        if let Ok(mut guard) = self.last_error.lock() {
            *guard = err;
        }
    }
}

/// Build an ordered list of non-443 domestic HTTP 204 probe URLs for verifying WinDivert dataplane
/// transparent interception end-to-end: prioritizes the configured URL when it is a strict 204
/// endpoint, and always falls back to authoritative Huawei & MIUI HTTP 204 endpoints.
#[cfg_attr(
    any(not(target_os = "windows"), target_arch = "aarch64"),
    allow(dead_code)
)]
pub fn build_self_test_probe_urls(configured_probe_url: &str) -> Vec<String> {
    let mut urls: Vec<String> = Vec::with_capacity(3);
    let mut push_unique_http_204 = |raw: &str| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return;
        }
        let Ok(parsed) = Url::parse(trimmed) else {
            return;
        };
        if !parsed.scheme().eq_ignore_ascii_case("http") {
            return;
        }
        if parsed.port_or_known_default() == Some(443) {
            return;
        }
        if crate::preaccel::generator::expected_probe_status_for_url(trimmed) != "204" {
            return;
        }
        if !urls.iter().any(|u| u.eq_ignore_ascii_case(trimmed)) {
            urls.push(trimmed.to_string());
        }
    };

    push_unique_http_204(configured_probe_url);
    push_unique_http_204(crate::preaccel::generator::DEFAULT_DOMESTIC_204_PRIMARY);
    push_unique_http_204(crate::preaccel::generator::DEFAULT_DOMESTIC_204_FALLBACK);
    urls
}

#[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
fn classify_self_test_failure(
    outcome: &super::windivert_win::WinDivertSelfTestOutcome,
    detected_products: &[String],
    bin_dir: Option<&Path>,
) -> (String, Option<String>) {
    match outcome {
        super::windivert_win::WinDivertSelfTestOutcome::Passed { .. } => {
            ("底层透明加速探测已通过".to_string(), None)
        }
        super::windivert_win::WinDivertSelfTestOutcome::BlockedAtDataplane {
            intercepted,
            accepted,
            send_errors,
            detail,
        } => {
            let msg = format!(
                "底层透明加速自动探测未通过（拦截 {intercepted} 包、到达本地转发 {accepted} 次、注入异常 {send_errors} 次）：{detail}。已自动停止拦截以防断网，并安全退回本地独立 443 通道"
            );
            let guidance =
                build_security_guidance(detected_products, bin_dir, "self_test_blocked");
            (msg, Some(guidance))
        }
        super::windivert_win::WinDivertSelfTestOutcome::NoPacketIntercepted { detail } => {
            let msg = format!(
                "底层透明加速自动探测未捕获到物理网卡出站测试包：{detail}。已自动停止拦截并安全退回本地独立 443 通道"
            );
            let guidance =
                build_security_guidance(detected_products, bin_dir, "self_test_blocked");
            (msg, Some(guidance))
        }
        super::windivert_win::WinDivertSelfTestOutcome::TunnelUnreachable { detail } => {
            let msg = format!(
                "底层透明拦截已送达本机转发口，但经由国内 443 中转访问探测地址失败：{detail}。已自动停止拦截防止其它软件超时，请先测速确认国内中转线路畅通后点击「重新探测」"
            );
            (msg, None)
        }
    }
}

impl Drop for GlobalPreAccelManager {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.runtime.lock() {
            if let Some(rt) = guard.take() {
                // Dropping `ActiveGlobalRuntime` runs `WinDivertEngine::drop` first (field order),
                // then `StandalonePreAccelTunnel::drop`, ensuring zero leaks and zero network hang.
                drop(rt);
            }
        }
        remove_global_preaccel_runtime_meta(&self.paths.root_data_dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::preaccel::generator::PREACCEL_FALLBACK_GROUP;
    use std::io::Write as _;
    use tokio::net::TcpListener;
    use zip::CompressionMethod;
    use zip::write::SimpleFileOptions;

    const TEST_UUID: &str = "11111111-2222-4333-8444-555555555555";

    fn sample_anytls_relay_with_dirty_sni() -> PreAccelRelay {
        PreAccelRelay {
            id: "relay-tx-443".to_string(),
            name: "Relay-TX-443".to_string(),
            provider: "tencent".to_string(),
            region: "CN-GZ".to_string(),
            server: "203.0.113.10".to_string(),
            port: 443,
            protocol: "anytls".to_string(),
            password: "demo-pass-01".to_string(),
            sni: Some("unfiled.example.com".to_string()),
            skip_cert_verify: false,
            priority: 10,
            expires_at: None,
            enabled: true,
            last_probe_ms: None,
            last_mbps: None,
            last_up_mbps: None,
            last_down_mbps: None,
            supports_ipv6: false,
        }
    }

    fn sample_vless_relay_with_dirty_sni() -> PreAccelRelay {
        PreAccelRelay {
            id: "relay-ali-443".to_string(),
            name: "Relay-ALI-443".to_string(),
            provider: "aliyun".to_string(),
            region: "CN-SH".to_string(),
            server: "198.51.100.20".to_string(),
            port: 443,
            protocol: "vless".to_string(),
            password: TEST_UUID.to_string(),
            sni: Some("unfiled-vless.example.com".to_string()),
            skip_cert_verify: false,
            priority: 20,
            expires_at: None,
            enabled: true,
            last_probe_ms: None,
            last_mbps: None,
            last_up_mbps: None,
            last_down_mbps: None,
            supports_ipv6: false,
        }
    }

    #[test]
    fn windivert_address_is_exact_80_bytes_and_bitfield_roundtrips() {
        assert_eq!(std::mem::size_of::<WinDivertAddress>(), 80);

        let mut addr = WinDivertAddress::default();
        addr.timestamp = 1_700_000_000;
        addr.set_layer(0);
        addr.set_event(1);
        addr.set_sniffed(true);
        addr.set_outbound(true);
        addr.set_loopback(true);
        addr.set_impostor(true);
        addr.set_ipv6(true);
        addr.set_ip_checksum(true);
        addr.set_tcp_checksum(true);
        addr.set_udp_checksum(true);
        addr.set_network_if_idx(17);
        addr.set_network_sub_if_idx(3);

        assert_eq!(addr.layer(), 0);
        assert_eq!(addr.event(), 1);
        assert!(addr.sniffed());
        assert!(addr.outbound());
        assert!(addr.loopback());
        assert!(addr.impostor());
        assert!(addr.ipv6());
        assert!(addr.ip_checksum());
        assert!(addr.tcp_checksum());
        assert!(addr.udp_checksum());
        assert_eq!(addr.network_if_idx(), 17);
        assert_eq!(addr.network_sub_if_idx(), 3);

        // Clearing Outbound and Loopback must not disturb sibling bitfield flags.
        addr.set_outbound(false);
        addr.set_loopback(false);
        addr.set_layer(2);
        assert_eq!(addr.layer(), 2);
        assert_eq!(addr.event(), 1);
        assert!(addr.sniffed());
        assert!(!addr.outbound());
        assert!(!addr.loopback());
        assert!(addr.impostor());
        assert!(addr.ip_checksum());
        assert!(addr.tcp_checksum());
        assert!(addr.udp_checksum());
    }

    #[test]
    fn build_windivert_filter_excludes_relays_ports_private_ranges_and_never_geoip_cn() {
        let relays = [
            Ipv4Addr::new(203, 0, 113, 10),
            Ipv4Addr::new(198, 51, 100, 20),
            Ipv4Addr::new(203, 0, 113, 10), // duplicate must deduplicate
        ];
        let filter = build_windivert_filter(&relays, 54321);

        assert!(filter.starts_with("ip and tcp and ("));
        assert!(filter.contains("!loopback"));
        assert!(filter.contains("tcp.DstPort != 443"));
        assert!(filter.contains("tcp.DstPort != 53"));
        assert!(filter.contains("ip.DstAddr != 203.0.113.10"));
        assert!(filter.contains("ip.DstAddr != 198.51.100.20"));
        assert!(filter.contains("(ip.DstAddr < 10.0.0.0 or ip.DstAddr > 10.255.255.255)"));
        assert!(filter.contains("(ip.DstAddr < 100.64.0.0 or ip.DstAddr > 100.127.255.255)"));
        assert!(filter.contains("(ip.DstAddr < 127.0.0.0 or ip.DstAddr > 127.255.255.255)"));
        assert!(filter.contains("(ip.DstAddr < 169.254.0.0 or ip.DstAddr > 169.254.255.255)"));
        assert!(filter.contains("(ip.DstAddr < 172.16.0.0 or ip.DstAddr > 172.31.255.255)"));
        assert!(filter.contains("(ip.DstAddr < 192.168.0.0 or ip.DstAddr > 192.168.255.255)"));
        assert!(filter.contains("(ip.DstAddr < 198.18.0.0 or ip.DstAddr > 198.19.255.255)"));
        assert!(filter.contains("ip.DstAddr < 224.0.0.0"));
        assert!(filter.contains(
            "(outbound and ip.SrcAddr == 127.0.0.1 and ip.DstAddr == 127.0.0.1 and tcp.SrcPort == 54321)"
        ));

        // Must never contain CIDR syntax (invalid in WinDivert) or GeoIP CN bypass.
        assert!(!filter.contains('/'));
        let lower = filter.to_ascii_lowercase();
        assert!(!lower.contains("geoip"));
        assert!(!lower.contains("cn"));
    }

    #[test]
    fn compile_standalone_preaccel_yaml_enforces_zero_tun_zero_dns_no_sni_domestic_204_and_anti_loop()
    {
        let mut cfg = AppConfig::default();
        cfg.preaccel.enabled = false; // standalone mode must still compile cleanly when main preaccel is off
        let mut disabled = sample_anytls_relay_with_dirty_sni();
        disabled.id = "relay-disabled".to_string();
        disabled.server = "192.0.2.99".to_string();
        disabled.enabled = false;

        let relays = vec![
            sample_vless_relay_with_dirty_sni(),
            disabled,
            sample_anytls_relay_with_dirty_sni(),
        ];

        let yaml_str =
            compile_standalone_preaccel_yaml(&cfg, &relays, 17908).expect("compile standalone");
        let doc: Value = serde_yaml_ng::from_str(&yaml_str).expect("valid YAML");

        assert_eq!(doc["socks-port"].as_u64(), Some(17908));
        assert_eq!(doc["bind-address"].as_str(), Some("127.0.0.1"));
        assert_eq!(doc["allow-lan"].as_bool(), Some(false));
        assert_eq!(doc["tun"]["enable"].as_bool(), Some(false));
        assert_eq!(doc["dns"]["enable"].as_bool(), Some(false));
        assert!(doc.get("external-controller").is_none());
        assert_eq!(doc["geo-auto-update"].as_bool(), Some(false));
        assert_eq!(doc["geodata-loader"].as_str(), Some("memconservative"));
        assert_eq!(doc["keep-alive-idle"].as_u64(), Some(45));
        assert_eq!(doc["keep-alive-interval"].as_u64(), Some(15));
        assert_eq!(STANDALONE_TUNNEL_GOMEMLIMIT, "48MiB");
        assert_eq!(NAT_IDLE_TIMEOUT, Duration::from_secs(600));

        // Verify 443 relays had unfiled third-party SNI stripped and skip-cert-verify enforced.
        let proxies = doc["proxies"].as_sequence().unwrap();
        assert_eq!(proxies.len(), 2);
        let anytls = &proxies[0];
        assert_eq!(anytls["type"].as_str(), Some("anytls"));
        assert_eq!(anytls["server"].as_str(), Some("203.0.113.10"));
        assert!(anytls.get("sni").is_none());
        assert_eq!(anytls["skip-cert-verify"].as_bool(), Some(true));

        let vless = &proxies[1];
        assert_eq!(vless["type"].as_str(), Some("vless"));
        assert_eq!(vless["server"].as_str(), Some("198.51.100.20"));
        assert_eq!(vless["servername"].as_str(), Some(""));
        assert_eq!(vless["skip-cert-verify"].as_bool(), Some(true));

        // Verify two-layer nested LB + outer fallback group with domestic 204 probe, lazy: false,
        // DIRECT strictly in outer fallback and NEVER in inner load-balance.
        let groups = doc["proxy-groups"].as_sequence().unwrap();
        let fallback = groups
            .iter()
            .find(|g| g["name"].as_str() == Some(PREACCEL_FALLBACK_GROUP))
            .expect("fallback group");
        assert_eq!(fallback["lazy"].as_bool(), Some(false));
        assert!(fallback["url"].as_str().unwrap().contains("hicloud.com"));
        let fb_proxies: Vec<&str> = fallback["proxies"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(
            fb_proxies,
            vec![crate::preaccel::schema::PREACCEL_LB_GROUP_NAME, "DIRECT"]
        );

        let lb = groups
            .iter()
            .find(|g| g["name"].as_str() == Some(crate::preaccel::schema::PREACCEL_LB_GROUP_NAME))
            .expect("inner multi-cloud load-balance group");
        assert_eq!(lb["type"].as_str(), Some("load-balance"));
        assert_eq!(lb["strategy"].as_str(), Some("consistent-hashing"));
        assert_eq!(lb["expected-status"].as_str(), Some("204"));
        assert_eq!(lb["lazy"].as_bool(), Some(false));
        let lb_proxies: Vec<&str> = lb["proxies"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(lb_proxies, vec!["Relay-TX-443", "Relay-ALI-443"]);
        assert!(!lb_proxies.contains(&"DIRECT"));

        // Verify top-level relay DIRECT anti-loop rules precede MATCH while probe_url / domestic
        // 204 domains are excluded from standalone rules so self-test probes always traverse :443.
        let rules: Vec<&str> = doc["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        let idx_tx = rules
            .iter()
            .position(|r| *r == "IP-CIDR,203.0.113.10/32,DIRECT,no-resolve")
            .expect("relay 1 direct rule");
        let idx_ali = rules
            .iter()
            .position(|r| *r == "IP-CIDR,198.51.100.20/32,DIRECT,no-resolve")
            .expect("relay 2 direct rule");
        let idx_match = rules
            .iter()
            .position(|r| *r == format!("MATCH,{PREACCEL_SELECT_GROUP}"))
            .expect("MATCH preaccel select group");
        assert!(idx_tx < idx_match);
        assert!(idx_ali < idx_match);
        assert!(!rules.contains(&"IP-CIDR,192.0.2.99/32,DIRECT,no-resolve"));
        assert!(!rules.iter().any(|r| {
            let lower = r.to_ascii_lowercase();
            lower.contains("hicloud.com") || lower.contains("miui.com")
        }));
    }

    #[cfg(not(all(target_os = "windows", target_arch = "aarch64")))]
    #[test]
    fn locate_windivert_files_respects_priority_and_requires_colocated_sys() {
        let root = std::env::temp_dir().join(format!(
            "catcloud-wd-locate-{}",
            uuid::Uuid::new_v4()
        ));
        let paths = AppPaths::from_data_dir(root.join("data"), true).unwrap();
        let exe_dir = root.join("app");
        let res_bin = exe_dir.join("resources").join("bin");
        let custom_dir = root.join("custom_wd");
        std::fs::create_dir_all(&res_bin).unwrap();
        std::fs::create_dir_all(&custom_dir).unwrap();

        // Missing `.sys` in custom_dir must be skipped even when `.dll` exists.
        std::fs::write(custom_dir.join("WinDivert64.dll"), b"dll-only").unwrap();
        std::fs::write(exe_dir.join("WinDivert.dll"), b"exe-dll").unwrap();
        std::fs::write(exe_dir.join("WinDivert64.sys"), b"exe-sys").unwrap();

        let found_exe = locate_windivert_files_with_exe_dir(
            &paths,
            Some(custom_dir.to_str().unwrap()),
            Some(&exe_dir),
        )
        .expect("should fall back to exe_dir");
        assert_eq!(found_exe.0, normalize_os_path(&exe_dir.join("WinDivert.dll")));

        // Placing pair in resources/bin overrides exe_dir.
        std::fs::write(res_bin.join("WinDivert64.dll"), b"res-dll").unwrap();
        std::fs::write(res_bin.join("WinDivert64.sys"), b"res-sys").unwrap();
        let found_res = locate_windivert_files_with_exe_dir(&paths, None, Some(&exe_dir)).unwrap();
        assert_eq!(found_res.0, normalize_os_path(&res_bin.join("WinDivert64.dll")));

        // Placing pair in paths.bin_dir overrides resources/bin.
        std::fs::write(paths.bin_dir.join("WinDivert64.dll"), b"bin-dll").unwrap();
        std::fs::write(paths.bin_dir.join("WinDivert64.sys"), b"bin-sys").unwrap();
        let found_bin = locate_windivert_files_with_exe_dir(&paths, None, Some(&exe_dir)).unwrap();
        assert_eq!(
            found_bin.0,
            normalize_os_path(&paths.bin_dir.join("WinDivert64.dll"))
        );

        // Adding `.sys` to custom_dir makes custom_dir highest priority.
        std::fs::write(custom_dir.join("WinDivert64.sys"), b"custom-sys").unwrap();
        let found_custom = locate_windivert_files_with_exe_dir(
            &paths,
            Some(custom_dir.to_str().unwrap()),
            Some(&exe_dir),
        )
        .unwrap();
        assert_eq!(
            found_custom.0,
            normalize_os_path(&custom_dir.join("WinDivert64.dll"))
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn verify_and_extract_windivert_zip_validates_sha256_and_blocks_traversal() {
        let root = std::env::temp_dir().join(format!(
            "catcloud-wd-zip-{}",
            uuid::Uuid::new_v4()
        ));
        let dest = root.join("bin");

        let make_zip = |entries: &[(&str, &[u8])]| -> Vec<u8> {
            let mut cursor = Cursor::new(Vec::new());
            {
                let mut zw = zip::ZipWriter::new(&mut cursor);
                let opts = SimpleFileOptions::default()
                    .compression_method(CompressionMethod::Stored);
                for (name, body) in entries {
                    zw.start_file(*name, opts).unwrap();
                    zw.write_all(body).unwrap();
                }
                zw.finish().unwrap();
            }
            cursor.into_inner()
        };

        let good_zip = make_zip(&[
            ("WinDivert-2.2.2-A/x64/WinDivert.dll", b"fake-dll-bytes"),
            ("WinDivert-2.2.2-A/x64/WinDivert64.sys", b"fake-sys-bytes"),
            ("WinDivert-2.2.2-A/README", b"ignored"),
        ]);
        let good_sha = hex::encode(Sha256::digest(&good_zip));

        // Mismatched SHA-256 must fail.
        assert!(verify_and_extract_windivert_zip(&good_zip, "0000", &dest).is_err());

        // Matching SHA-256 installs WinDivert.dll, WinDivert64.dll, and WinDivert64.sys only.
        let installed =
            verify_and_extract_windivert_zip(&good_zip, &good_sha, &dest).expect("install ok");
        assert!(installed.dll_path.is_file());
        assert!(installed.sys_path.is_file());
        assert!(dest.join("WinDivert.dll").is_file());
        assert!(!dest.join("README").exists());

        // Path traversal entry must be rejected even when SHA-256 matches.
        let evil_zip = make_zip(&[("../evil.dll", b"nope")]);
        let evil_sha = hex::encode(Sha256::digest(&evil_zip));
        assert!(verify_and_extract_windivert_zip(&evil_zip, &evil_sha, &dest).is_err());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn nat_table_ipv4_tcp_rewrite_nic_filter_and_process_policy_work() {
        let table = NatTable::new(2, Duration::from_secs(60));
        let now = Instant::now();
        table.insert(
            (Ipv4Addr::LOCALHOST, 40001),
            NatEntry {
                orig_src_ip: Ipv4Addr::new(192, 0, 2, 10),
                orig_dst_ip: Ipv4Addr::new(203, 0, 113, 50),
                orig_dst_port: 8443,
                if_idx: 7,
                sub_if_idx: 0,
                owner_pid: 2001,
                process_name: "mihomo.exe".to_string(),
                detected_by: "open_core_name".to_string(),
                last_seen: now - Duration::from_secs(10),
                closing_since: None,
            },
        );
        table.insert(
            (Ipv4Addr::LOCALHOST, 40002),
            NatEntry {
                orig_src_ip: Ipv4Addr::new(192, 0, 2, 10),
                orig_dst_ip: Ipv4Addr::new(203, 0, 113, 51),
                orig_dst_port: 9443,
                if_idx: 7,
                sub_if_idx: 0,
                owner_pid: 2002,
                process_name: "xray.exe".to_string(),
                detected_by: "open_core_name".to_string(),
                last_seen: now - Duration::from_secs(5),
                closing_since: None,
            },
        );
        // Third entry evicts oldest (40001).
        table.insert(
            (Ipv4Addr::LOCALHOST, 40003),
            NatEntry {
                orig_src_ip: Ipv4Addr::new(192, 0, 2, 10),
                orig_dst_ip: Ipv4Addr::new(203, 0, 113, 52),
                orig_dst_port: 2053,
                if_idx: 7,
                sub_if_idx: 0,
                owner_pid: 2003,
                process_name: "ssh.exe".to_string(),
                detected_by: "manual".to_string(),
                last_seen: now,
                closing_since: None,
            },
        );
        assert_eq!(table.len(), 2);
        assert!(table.get_and_touch(&(Ipv4Addr::LOCALHOST, 40001)).is_none());
        assert!(table.get_and_touch(&(Ipv4Addr::LOCALHOST, 40003)).is_some());
        assert!(table.has_active_conflict(
            &(Ipv4Addr::LOCALHOST, 40003),
            Ipv4Addr::new(192, 0, 2, 99),
            Ipv4Addr::new(203, 0, 113, 52),
            2053
        ));
        assert!(!table.has_active_conflict(
            &(Ipv4Addr::LOCALHOST, 40003),
            Ipv4Addr::new(192, 0, 2, 10),
            Ipv4Addr::new(203, 0, 113, 52),
            2053
        ));
        assert!(table.mark_closing_if_matching(
            &(Ipv4Addr::LOCALHOST, 40003),
            Ipv4Addr::new(192, 0, 2, 10),
            Ipv4Addr::new(203, 0, 113, 52),
            2053
        ));
        // During the 4s closing grace window, any different 4-tuple conflicts to prevent cross-flow RST.
        assert!(table.has_active_conflict(
            &(Ipv4Addr::LOCALHOST, 40003),
            Ipv4Addr::new(192, 0, 2, 99),
            Ipv4Addr::new(203, 0, 113, 52),
            2053
        ));
        assert!(table.has_active_conflict(
            &(Ipv4Addr::LOCALHOST, 40003),
            Ipv4Addr::new(192, 0, 2, 10),
            Ipv4Addr::new(203, 0, 113, 88),
            2053
        ));
        assert!(!table.has_active_conflict(
            &(Ipv4Addr::LOCALHOST, 40003),
            Ipv4Addr::new(192, 0, 2, 10),
            Ipv4Addr::new(203, 0, 113, 52),
            2053
        ));

        // Build minimal 40-byte IPv4 + TCP SYN packet and test parse + dst/src rewrite.
        let mut pkt = [0u8; 40];
        pkt[0] = 0x45; // IPv4, IHL=5
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&[192, 0, 2, 10]);
        pkt[16..20].copy_from_slice(&[203, 0, 113, 88]);
        pkt[20..22].copy_from_slice(&50000u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&8443u16.to_be_bytes());
        pkt[33] = Ipv4TcpMeta::FLAG_SYN;

        let meta = parse_ipv4_tcp_packet(&pkt).expect("parse ipv4 tcp");
        assert!(meta.is_syn_only());
        assert_eq!(meta.src_ip, Ipv4Addr::new(192, 0, 2, 10));
        assert_eq!(meta.dst_ip, Ipv4Addr::new(203, 0, 113, 88));
        assert_eq!(meta.src_port, 50000);
        assert_eq!(meta.dst_port, 8443);

        assert!(rewrite_ipv4_tcp_dst(
            &mut pkt,
            meta.ihl_bytes,
            Ipv4Addr::new(192, 0, 2, 10),
            61000
        ));
        let rewritten = parse_ipv4_tcp_packet(&pkt).unwrap();
        assert_eq!(rewritten.dst_ip, Ipv4Addr::new(192, 0, 2, 10));
        assert_eq!(rewritten.dst_port, 61000);

        assert!(rewrite_ipv4_tcp_src(
            &mut pkt,
            meta.ihl_bytes,
            Ipv4Addr::new(203, 0, 113, 88),
            8443
        ));
        let restored = parse_ipv4_tcp_packet(&pkt).unwrap();
        assert_eq!(restored.src_ip, Ipv4Addr::new(203, 0, 113, 88));
        assert_eq!(restored.src_port, 8443);

        // Physical NIC descriptor filter
        assert!(is_physical_nic_descriptor(6, 5, "Realtek PCIe GbE Family Controller"));
        assert!(is_physical_nic_descriptor(71, 5, "Intel(R) Wi-Fi 6E AX211 160MHz"));
        assert!(!is_physical_nic_descriptor(53, 5, "Wintun Userspace Tunnel"));
        assert!(!is_physical_nic_descriptor(6, 5, "Hyper-V Virtual Ethernet Adapter"));
        assert!(!is_physical_nic_descriptor(6, 5, "Meta Wintun Tunnel"));
        assert!(!is_physical_nic_descriptor(24, 5, "Software Loopback Interface 1"));

        // Process interception scope & anti-loop exclusions
        let targets: HashSet<String> = ["ssh.exe", "custom-tool.exe"]
            .into_iter()
            .map(String::from)
            .collect();
        let excluded: HashSet<u32> = [1001, 1002].into_iter().collect();

        assert!(should_intercept_process(
            2000,
            Some(r"C:\Tools\ProxyCore\mihomo.exe"),
            GlobalPreAccelScope::ProxyAppsOnly,
            &targets,
            &excluded
        ));
        assert!(should_intercept_process(
            2005,
            Some(r"C:\Tools\OpenCore\custom-xray-runner.exe"),
            GlobalPreAccelScope::ProxyAppsOnly,
            &targets,
            &excluded
        ));
        assert!(should_intercept_process(
            2006,
            Some("ssh.exe"),
            GlobalPreAccelScope::ProxyAppsOnly,
            &targets,
            &excluded
        ));
        assert!(!should_intercept_process(
            1002,
            Some("mihomo.exe"),
            GlobalPreAccelScope::AllNon443Tcp,
            &targets,
            &excluded
        ));
        assert!(!should_intercept_process(
            3000,
            Some("svchost.exe"),
            GlobalPreAccelScope::AllNon443Tcp,
            &targets,
            &excluded
        ));
        assert!(!should_intercept_process(
            3002,
            Some("catcloud-probe-core.exe"),
            GlobalPreAccelScope::AllNon443Tcp,
            &targets,
            &excluded
        ));
        assert!(!should_intercept_process(
            3001,
            Some("chrome.exe"),
            GlobalPreAccelScope::ProxyAppsOnly,
            &targets,
            &excluded
        ));
        assert!(should_intercept_process(
            3001,
            Some("chrome.exe"),
            GlobalPreAccelScope::AllNon443Tcp,
            &targets,
            &excluded
        ));
    }

    #[tokio::test]
    async fn forward_redirected_stream_drops_unregistered_peers_and_relays_socks5_with_metrics() {
        // 1. Spawn mock SOCKS5 server expecting NOAUTH + CONNECT 203.0.113.77:8443 then echoing payload.
        let mock_socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = mock_socks.local_addr().unwrap().port();

        let socks_task = tokio::spawn(async move {
            let (mut sock, _) = mock_socks.accept().await.unwrap();
            let mut greet = [0u8; 3];
            sock.read_exact(&mut greet).await.unwrap();
            assert_eq!(greet, [0x05, 0x01, 0x00]);
            sock.write_all(&[0x05, 0x00]).await.unwrap();

            let mut req = [0u8; 10];
            sock.read_exact(&mut req).await.unwrap();
            assert_eq!(req[0..4], [0x05, 0x01, 0x00, 0x01]);
            assert_eq!(req[4..8], [203, 0, 113, 77]);
            assert_eq!(u16::from_be_bytes([req[8], req[9]]), 8443);
            sock.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();

            let mut data = [0u8; 5];
            sock.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"hello");
            sock.write_all(b"world!").await.unwrap();
            let _ = sock.shutdown().await;
        });

        // 2. Spawn local redirector listener backed by NatTable + GlobalPreAccelMetrics.
        let redir_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let redir_addr = redir_listener.local_addr().unwrap();
        let nat_table = Arc::new(NatTable::new(64, Duration::from_secs(60)));
        let metrics = Arc::new(GlobalPreAccelMetrics::default());
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let nat_clone = Arc::clone(&nat_table);
        let metrics_clone = Arc::clone(&metrics);
        let accept_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, peer) = redir_listener.accept().await.unwrap();
                let n = Arc::clone(&nat_clone);
                let m = Arc::clone(&metrics_clone);
                let rx = shutdown_rx.clone();
                tokio::spawn(async move {
                    forward_redirected_stream(stream, peer, socks_port, n, m, rx, None).await;
                });
            }
        });

        // Unregistered client must be dropped immediately without touching SOCKS5 or metrics.
        let mut rogue = TcpStream::connect(redir_addr).await.unwrap();
        let mut rogue_buf = [0u8; 8];
        let n_rogue = rogue.read(&mut rogue_buf).await.unwrap();
        assert_eq!(n_rogue, 0);
        assert_eq!(metrics.total_connections.load(Ordering::Relaxed), 0);

        // Registered client connects via pre-bound local port so NatTable key matches exact peer.
        let client_sock = tokio::net::TcpSocket::new_v4().unwrap();
        client_sock
            .bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
            .unwrap();
        let local_ep = match client_sock.local_addr().unwrap() {
            SocketAddr::V4(v4) => (*v4.ip(), v4.port()),
            _ => unreachable!(),
        };
        nat_table.insert(
            local_ep,
            NatEntry {
                orig_src_ip: Ipv4Addr::new(192, 0, 2, 10),
                orig_dst_ip: Ipv4Addr::new(203, 0, 113, 77),
                orig_dst_port: 8443,
                if_idx: 1,
                sub_if_idx: 0,
                owner_pid: 4242,
                process_name: "sing-box.exe".to_string(),
                detected_by: "system_proxy_host".to_string(),
                last_seen: Instant::now(),
                closing_since: None,
            },
        );

        let mut client = client_sock.connect(redir_addr).await.unwrap();
        client.write_all(b"hello").await.unwrap();
        let mut reply = [0u8; 6];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"world!");
        drop(client);

        let _ = socks_task.await;
        let _ = accept_task.await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = shutdown_tx.send(true);

        assert_eq!(metrics.total_connections.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 0);
        // NAT entry stays in closing-grace retention for clean FIN-ACK teardown instead of immediate deletion.
        let closing_entry = nat_table
            .get_and_touch(&local_ep)
            .expect("entry should stay in closing grace");
        assert!(closing_entry.closing_since.is_some());
        assert!(metrics.up_bytes.load(Ordering::Relaxed) >= 5);
        assert!(metrics.down_bytes.load(Ordering::Relaxed) >= 6);
        assert_eq!(
            metrics.recent_processes_snapshot(),
            vec!["sing-box.exe".to_string()]
        );

        let proc_stats = metrics.snapshot();
        assert_eq!(proc_stats.len(), 1);
        assert_eq!(proc_stats[0].process_name, "sing-box.exe");
        assert_eq!(proc_stats[0].pid, 4242);
        assert_eq!(proc_stats[0].detected_by, "system_proxy_host");
        assert_eq!(proc_stats[0].active_connections, 0);
        assert_eq!(proc_stats[0].total_connections, 1);
        assert!(proc_stats[0].tx_bytes >= 5);
        assert!(proc_stats[0].rx_bytes >= 6);
        assert!(proc_stats[0].last_seen_ms > 0);
    }

    #[test]
    fn nat_table_remove_and_remove_if_matching_guard_port_reuse() {
        let table = NatTable::new(16, Duration::from_secs(60));
        let now = Instant::now();
        let key_a = (Ipv4Addr::new(192, 0, 2, 10), 41000);
        let key_b = (Ipv4Addr::new(192, 0, 2, 10), 41001);

        table.insert(
            key_a,
            NatEntry {
                orig_src_ip: Ipv4Addr::new(192, 0, 2, 10),
                orig_dst_ip: Ipv4Addr::new(203, 0, 113, 10),
                orig_dst_port: 8443,
                if_idx: 3,
                sub_if_idx: 0,
                owner_pid: 5100,
                process_name: "app-a.exe".to_string(),
                detected_by: "manual".to_string(),
                last_seen: now,
                closing_since: None,
            },
        );
        table.insert(
            key_b,
            NatEntry {
                orig_src_ip: Ipv4Addr::new(192, 0, 2, 10),
                orig_dst_ip: Ipv4Addr::new(203, 0, 113, 20),
                orig_dst_port: 2053,
                if_idx: 3,
                sub_if_idx: 0,
                owner_pid: 5101,
                process_name: "app-b.exe".to_string(),
                detected_by: "local_proxy_listener".to_string(),
                last_seen: now,
                closing_since: None,
            },
        );

        // Mismatched destination IP or port must leave the newer mapping intact.
        assert!(!table.remove_if_matching(&key_a, Ipv4Addr::new(203, 0, 113, 99), 8443));
        assert!(!table.remove_if_matching(&key_a, Ipv4Addr::new(203, 0, 113, 10), 9443));
        assert!(table.get_and_touch(&key_a).is_some());

        // Exact destination match removes the entry cleanly.
        assert!(table.remove_if_matching(&key_a, Ipv4Addr::new(203, 0, 113, 10), 8443));
        assert!(table.get_and_touch(&key_a).is_none());
        assert!(!table.remove_if_matching(&key_a, Ipv4Addr::new(203, 0, 113, 10), 8443));

        // Direct `remove` returns the evicted entry once, then `None`.
        let removed = table.remove(&key_b).expect("remove existing key_b");
        assert_eq!(removed.orig_dst_ip, Ipv4Addr::new(203, 0, 113, 20));
        assert_eq!(removed.orig_dst_port, 2053);
        assert!(table.remove(&key_b).is_none());
        assert!(table.is_empty());
    }

    #[test]
    fn should_intercept_process_conservatively_bypasses_unknown_process_names() {
        let targets: HashSet<String> = ["mihomo.exe"].into_iter().map(String::from).collect();
        let excluded: HashSet<u32> = HashSet::new();

        assert!(!should_intercept_process(
            4001,
            None,
            GlobalPreAccelScope::AllNon443Tcp,
            &targets,
            &excluded
        ));
        assert!(!should_intercept_process(
            4001,
            None,
            GlobalPreAccelScope::ProxyAppsOnly,
            &targets,
            &excluded
        ));
        assert!(!should_intercept_process(
            4002,
            Some("   "),
            GlobalPreAccelScope::AllNon443Tcp,
            &targets,
            &excluded
        ));
    }

    #[test]
    fn sync_main_core_pid_dynamically_updates_and_preserves_self_and_tunnel() {
        let self_pid = std::process::id();
        let tunnel_pid = self_pid.wrapping_add(10_001).max(100);
        let static_pid = self_pid.wrapping_add(10_002).max(101);
        let main_pid_v1 = self_pid.wrapping_add(20_001).max(200);
        let main_pid_v2 = self_pid.wrapping_add(20_002).max(201);

        let tracker = ExcludedPidTracker::new(self_pid, Some(tunnel_pid), [static_pid], None);
        let shared = tracker.shared_set();

        {
            let guard = shared.read().unwrap();
            assert!(guard.contains(&self_pid));
            assert!(guard.contains(&tunnel_pid));
            assert!(guard.contains(&static_pid));
            assert!(!guard.contains(&main_pid_v1));
        }

        // First sync adds external main core PID.
        tracker.sync_main_core_pid(Some(main_pid_v1));
        {
            let guard = shared.read().unwrap();
            assert!(guard.contains(&self_pid));
            assert!(guard.contains(&tunnel_pid));
            assert!(guard.contains(&static_pid));
            assert!(guard.contains(&main_pid_v1));
        }

        // Restarting main core replaces only the main core slot, evicting old PID.
        tracker.sync_main_core_pid(Some(main_pid_v2));
        {
            let guard = shared.read().unwrap();
            assert!(guard.contains(&self_pid));
            assert!(guard.contains(&tunnel_pid));
            assert!(guard.contains(&static_pid));
            assert!(!guard.contains(&main_pid_v1));
            assert!(guard.contains(&main_pid_v2));
        }

        // Setting slot to a pinned PID and clearing must never drop self or tunnel PIDs.
        tracker.sync_main_core_pid(Some(tunnel_pid));
        tracker.sync_main_core_pid(None);
        {
            let guard = shared.read().unwrap();
            assert!(guard.contains(&self_pid));
            assert!(guard.contains(&tunnel_pid));
            assert!(guard.contains(&static_pid));
            assert!(!guard.contains(&main_pid_v2));
        }

        // Verify `GlobalPreAccelManager::sync_main_core_pid` tracks live slot updates cleanly.
        let root = std::env::temp_dir().join(format!(
            "catcloud-sync-pid-{}",
            uuid::Uuid::new_v4()
        ));
        let paths = AppPaths::from_data_dir(root.join("data"), true).unwrap();
        let job_guard = Arc::new(JobGuard::new().unwrap());
        let manager = GlobalPreAccelManager::new(paths, job_guard);

        manager.sync_main_core_pid(Some(main_pid_v1));
        assert_eq!(*manager.synced_main_core_pid.lock().unwrap(), Some(main_pid_v1));
        manager.sync_main_core_pid(Some(0));
        assert_eq!(*manager.synced_main_core_pid.lock().unwrap(), None);
        manager.sync_main_core_pid(Some(main_pid_v2));
        assert_eq!(*manager.synced_main_core_pid.lock().unwrap(), Some(main_pid_v2));
        manager.sync_main_core_pid(None);
        assert_eq!(*manager.synced_main_core_pid.lock().unwrap(), None);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn forward_redirected_stream_exits_promptly_on_shutdown_during_socks5_handshake() {
        // Stalled mock SOCKS5 server that accepts the TCP connection, signals readiness, and never replies.
        let stalled_socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = stalled_socks.local_addr().unwrap().port();
        let (connected_tx, connected_rx) = tokio::sync::oneshot::channel::<()>();
        let socks_hold = tokio::spawn(async move {
            let (_conn, _) = stalled_socks.accept().await.unwrap();
            let _ = connected_tx.send(());
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let redir_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let redir_addr = redir_listener.local_addr().unwrap();
        let nat_table = Arc::new(NatTable::new(16, Duration::from_secs(60)));
        let metrics = Arc::new(GlobalPreAccelMetrics::default());
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let client_sock = tokio::net::TcpSocket::new_v4().unwrap();
        client_sock
            .bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
            .unwrap();
        let local_ep = match client_sock.local_addr().unwrap() {
            SocketAddr::V4(v4) => (*v4.ip(), v4.port()),
            _ => unreachable!(),
        };
        nat_table.insert(
            local_ep,
            NatEntry {
                orig_src_ip: Ipv4Addr::new(192, 0, 2, 10),
                orig_dst_ip: Ipv4Addr::new(203, 0, 113, 88),
                orig_dst_port: 8443,
                if_idx: 1,
                sub_if_idx: 0,
                owner_pid: 6001,
                process_name: "stalled.exe".to_string(),
                detected_by: "manual".to_string(),
                last_seen: Instant::now(),
                closing_since: None,
            },
        );

        let nat_ref = Arc::clone(&nat_table);
        let metrics_ref = Arc::clone(&metrics);
        let fwd_task = tokio::spawn(async move {
            let (stream, peer) = redir_listener.accept().await.unwrap();
            forward_redirected_stream(
                stream,
                peer,
                socks_port,
                nat_ref,
                metrics_ref,
                shutdown_rx,
                None,
            )
            .await;
        });

        let _client = client_sock.connect(redir_addr).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), connected_rx)
            .await
            .expect("upstream SOCKS5 socket should connect promptly")
            .expect("connected signal ok");
        let _ = shutdown_tx.send(true);

        tokio::time::timeout(Duration::from_secs(2), fwd_task)
            .await
            .expect("forward_redirected_stream must exit promptly on shutdown")
            .expect("forward task join ok");

        socks_hold.abort();
        assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 0);
        // Entry transitions to graceful FIN-ACK closing grace rather than hard-dropping mid-close.
        let closed_entry = nat_table
            .get_and_touch(&local_ep)
            .expect("closing grace entry remains briefly for FIN-ACK rewrite");
        assert!(closed_entry.closing_since.is_some());
        assert!(nat_table.has_active_conflict(
            &local_ep,
            Ipv4Addr::new(192, 0, 2, 11),
            Ipv4Addr::new(203, 0, 113, 88),
            8443
        ));
        assert!(nat_table.has_active_conflict(
            &local_ep,
            Ipv4Addr::new(192, 0, 2, 10),
            Ipv4Addr::new(203, 0, 113, 99),
            8443
        ));
        assert!(!nat_table.has_active_conflict(
            &local_ep,
            Ipv4Addr::new(192, 0, 2, 10),
            Ipv4Addr::new(203, 0, 113, 88),
            8443
        ));
    }

    #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
    #[tokio::test]
    async fn windows_arm64_windivert_guards_return_none_and_validation_error() {
        let root = std::env::temp_dir().join(format!(
            "catcloud-wd-arm64-{}",
            uuid::Uuid::new_v4()
        ));
        let paths = AppPaths::from_data_dir(root.join("data"), true).unwrap();
        std::fs::write(paths.bin_dir.join("WinDivert64.dll"), b"x64-dll").unwrap();
        std::fs::write(paths.bin_dir.join("WinDivert64.sys"), b"x64-sys").unwrap();

        assert!(locate_windivert_files(&paths, None).is_none());
        assert!(locate_windivert_files_with_exe_dir(&paths, None, None).is_none());

        let err = download_and_install_windivert(&paths, None)
            .await
            .expect_err("ARM64 must reject WinDivert download");
        match err {
            CatError::Validation(msg) => {
                assert!(msg.contains("Windows ARM64"));
                assert!(msg.contains("本地独立 443 通道"));
            }
            other => panic!("expected CatError::Validation, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn classify_intercept_process_respects_exclusions_dynamic_hosts_open_stems_and_manual() {
        let targets: HashSet<String> = ["ssh.exe", "custom-sync.exe"]
            .into_iter()
            .map(String::from)
            .collect();
        let excluded: HashSet<u32> = [1001, 1002, 2001].into_iter().collect();
        let mut detected: HashMap<u32, &'static str> = HashMap::new();
        detected.insert(2001, "system_proxy_host"); // must still be blocked by `excluded`
        detected.insert(2002, "system_proxy_host");
        detected.insert(2003, "local_proxy_listener");

        // 1. Excluded PIDs and system/self binaries ALWAYS win over dynamic detection or scope.
        assert_eq!(
            classify_intercept_process(
                2001,
                Some("mihomo.exe"),
                GlobalPreAccelScope::AllNon443Tcp,
                &targets,
                &excluded,
                &detected,
            ),
            None
        );
        assert_eq!(
            classify_intercept_process(
                2002,
                Some("catcloud.exe"),
                GlobalPreAccelScope::AllNon443Tcp,
                &targets,
                &excluded,
                &detected,
            ),
            None
        );
        assert_eq!(
            classify_intercept_process(
                2002,
                Some("catcloud-helper.exe"),
                GlobalPreAccelScope::AllNon443Tcp,
                &targets,
                &excluded,
                &detected,
            ),
            None
        );
        assert_eq!(
            classify_intercept_process(
                2002,
                Some("svchost.exe"),
                GlobalPreAccelScope::AllNon443Tcp,
                &targets,
                &excluded,
                &detected,
            ),
            None
        );

        // 2. Dynamic runtime detections classify arbitrary executable names without hardcoded lists.
        assert_eq!(
            classify_intercept_process(
                2002,
                Some("third-party-proxy-engine.exe"),
                GlobalPreAccelScope::ProxyAppsOnly,
                &targets,
                &excluded,
                &detected,
            ),
            Some("system_proxy_host")
        );
        assert_eq!(
            classify_intercept_process(
                2003,
                Some("proxy-daemon.exe"),
                GlobalPreAccelScope::ProxyAppsOnly,
                &targets,
                &excluded,
                &detected,
            ),
            Some("local_proxy_listener")
        );

        // 3. Generic open-source core stems match even when not explicitly listed in `targets`.
        assert_eq!(
            classify_intercept_process(
                3001,
                Some(r"D:\Tools\sing-box-core.exe"),
                GlobalPreAccelScope::ProxyAppsOnly,
                &targets,
                &excluded,
                &detected,
            ),
            Some("open_core_name")
        );
        assert_eq!(
            classify_intercept_process(
                3002,
                Some("tun2socks-win64.exe"),
                GlobalPreAccelScope::ProxyAppsOnly,
                &targets,
                &excluded,
                &detected,
            ),
            Some("open_core_name")
        );

        // 4. Explicit manual target names match as `"manual"`.
        assert_eq!(
            classify_intercept_process(
                3003,
                Some("custom-sync.exe"),
                GlobalPreAccelScope::ProxyAppsOnly,
                &targets,
                &excluded,
                &detected,
            ),
            Some("manual")
        );

        // 5. Unrelated apps bypass in `ProxyAppsOnly`, match `"scope_all"` in `AllNon443Tcp`.
        assert_eq!(
            classify_intercept_process(
                3004,
                Some("browser.exe"),
                GlobalPreAccelScope::ProxyAppsOnly,
                &targets,
                &excluded,
                &detected,
            ),
            None
        );
        assert_eq!(
            classify_intercept_process(
                3004,
                Some("browser.exe"),
                GlobalPreAccelScope::AllNon443Tcp,
                &targets,
                &excluded,
                &detected,
            ),
            Some("scope_all")
        );
    }

    #[test]
    fn metrics_process_stats_aggregates_sorts_and_evicts_bounded_capacity() {
        let metrics = GlobalPreAccelMetrics::default();

        // Process A: 1 active connection, 100 bytes total.
        metrics.record_process_connection_open(100, "mihomo.exe", "system_proxy_host");
        metrics.record_process_bytes(100, "mihomo.exe", "system_proxy_host", 40, 60);

        // Process B: 2 active connections, 50 bytes total -> ranks first by active_connections.
        metrics.record_process_connection_open(200, "xray.exe", "local_proxy_listener");
        metrics.record_process_connection_open(200, "xray.exe", "local_proxy_listener");
        metrics.record_process_bytes(200, "xray.exe", "local_proxy_listener", 20, 30);

        // Process C: 0 active connections, 5000 bytes total -> ranks behind active processes.
        metrics.record_process_connection_open(300, "ssh.exe", "manual");
        metrics.record_process_bytes(300, "ssh.exe", "manual", 2000, 3000);
        metrics.record_process_connection_close(300, "ssh.exe", "manual");

        let snap = metrics.snapshot();
        assert_eq!(snap.len(), 3);
        assert_eq!(snap[0].process_name, "xray.exe");
        assert_eq!(snap[0].active_connections, 2);
        assert_eq!(snap[0].total_connections, 2);
        assert_eq!(snap[1].process_name, "mihomo.exe");
        assert_eq!(snap[1].active_connections, 1);
        assert_eq!(snap[2].process_name, "ssh.exe");
        assert_eq!(snap[2].active_connections, 0);
        assert_eq!(snap[2].tx_bytes, 2000);
        assert_eq!(snap[2].rx_bytes, 3000);

        // Clearing active connections zeroes active gauges while preserving historical bytes.
        metrics.clear_active_connections();
        let after_clear = metrics.snapshot();
        assert!(after_clear.iter().all(|s| s.active_connections == 0));
        // With all active == 0, highest total bytes (`ssh.exe`, 5000 B) moves to rank 0.
        assert_eq!(after_clear[0].process_name, "ssh.exe");

        // Bounded capacity test: insert > MAX_PROCESS_STATS idle processes and assert hard cap.
        for idx in 0..(MAX_PROCESS_STATS as u32 + 12) {
            let pid = 10_000 + idx;
            let name = format!("worker-{idx}.exe");
            metrics.record_process_connection_open(pid, &name, "open_core_name");
            metrics.record_process_connection_close(pid, &name, "open_core_name");
        }
        assert!(metrics.snapshot().len() <= MAX_PROCESS_STATS);

        metrics.reset();
        assert!(metrics.snapshot().is_empty());
    }

    #[test]
    fn global_preaccel_status_backcompat_serde_and_install_state_transitions() {
        // Legacy JSON missing new Stage 12 fields must deserialize cleanly with safe defaults.
        let legacy_json = r#"{
            "running": true,
            "mode": "local_socks5",
            "socks_port": 17908,
            "windivert_available": false,
            "windivert_path": null,
            "is_elevated": false,
            "active_connections": 0,
            "total_connections": 0,
            "up_bytes": 0,
            "down_bytes": 0,
            "accelerated_processes": [],
            "active_relays": ["Relay-A"],
            "last_error": null
        }"#;
        let parsed: GlobalPreAccelStatus =
            serde_json::from_str(legacy_json).expect("deserialize legacy GlobalPreAccelStatus");
        assert!(!parsed.is_windivert_active);
        assert_eq!(parsed.install_state, "idle");
        assert_eq!(parsed.verify_state, "idle");
        assert!(parsed.verify_latency_ms.is_none());
        assert!(parsed.verify_message.is_none());
        assert!(parsed.detected_security_products.is_empty());
        assert!(parsed.security_guidance.is_none());
        assert!(parsed.bound_physical_interface.is_none());
        assert!(parsed.process_stats.is_empty());

        // Manager install state normalization and reporting.
        let root = std::env::temp_dir().join(format!(
            "catcloud-install-state-{}",
            uuid::Uuid::new_v4()
        ));
        let paths = AppPaths::from_data_dir(root.join("data"), true).unwrap();
        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        let bin_dir = paths.bin_dir.clone();
        let job_guard = Arc::new(JobGuard::new().unwrap());
        let manager = GlobalPreAccelManager::new(paths, job_guard);

        manager.set_install_state("downloading");
        assert_eq!(manager.status().install_state, "downloading");
        assert!(!manager.status().is_windivert_active);

        manager.set_install_state("VERIFYING");
        assert_eq!(manager.status().install_state, "verifying");

        manager.set_install_state("need_elevation");
        assert_eq!(manager.install_state(), "need_elevation");
        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        {
            let st_missing = manager.status();
            if !st_missing.windivert_available {
                assert_eq!(st_missing.install_state, "idle");
            }
            let dll_path = bin_dir.join("WinDivert64.dll");
            let sys_path = bin_dir.join("WinDivert64.sys");
            std::fs::write(&dll_path, b"stub-dll").unwrap();
            std::fs::write(&sys_path, b"stub-sys").unwrap();
            let st_present = manager.status();
            assert!(st_present.windivert_available);
            assert_eq!(
                st_present.install_state,
                if st_present.is_elevated {
                    "ready"
                } else {
                    "need_elevation"
                }
            );
            manager.set_install_state("ready");
            let _ = std::fs::remove_file(&dll_path);
            let _ = std::fs::remove_file(&sys_path);
            let st_removed = manager.status();
            if !st_removed.windivert_available {
                assert_eq!(st_removed.install_state, "idle");
            }
        }
        #[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
        assert_eq!(manager.status().install_state, "need_elevation");

        manager.set_install_state("failed");
        assert_eq!(manager.status().install_state, "failed");

        manager.set_install_state("unknown-bogus");
        assert_eq!(manager.install_state(), "idle");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn windivert_proxy_candidates_dedup_and_system_proxy_url_formatting() {
        assert_eq!(normalize_windivert_proxy_candidates(&[]), vec![None]);

        let raw = vec![
            Some(" http://127.0.0.1:7890/ ".to_string()),
            Some("HTTP://127.0.0.1:7890".to_string()),
            Some("http://127.0.0.1:7897".to_string()),
            None,
            Some("   ".to_string()),
            None,
        ];
        assert_eq!(
            normalize_windivert_proxy_candidates(&raw),
            vec![
                Some("http://127.0.0.1:7890/".to_string()),
                Some("http://127.0.0.1:7897".to_string()),
                None,
            ]
        );

        let enabled_v4 = crate::platform::SystemProxySpec {
            enabled: true,
            host: "127.0.0.1".to_string(),
            port: 10809,
            bypass: Vec::new(),
            pac_url: None,
        };
        assert_eq!(
            format_system_proxy_url(&enabled_v4).as_deref(),
            Some("http://127.0.0.1:10809")
        );

        let enabled_v6 = crate::platform::SystemProxySpec {
            enabled: true,
            host: "::1".to_string(),
            port: 10809,
            bypass: Vec::new(),
            pac_url: None,
        };
        assert_eq!(
            format_system_proxy_url(&enabled_v6).as_deref(),
            Some("http://[::1]:10809")
        );

        let pac_only = crate::platform::SystemProxySpec {
            enabled: true,
            host: "127.0.0.1".to_string(),
            port: 7890,
            bypass: Vec::new(),
            pac_url: Some("http://127.0.0.1:17891/proxy.pac".to_string()),
        };
        assert_eq!(format_system_proxy_url(&pac_only), None);

        let disabled = crate::platform::SystemProxySpec {
            enabled: false,
            host: "127.0.0.1".to_string(),
            port: 7890,
            bypass: Vec::new(),
            pac_url: None,
        };
        assert_eq!(format_system_proxy_url(&disabled), None);
    }

    #[test]
    fn excluded_pid_tracker_merges_descendant_tree_and_main_core_without_clobbering() {
        let self_pid = std::process::id();
        let tunnel_pid = self_pid.wrapping_add(11_001).max(100);
        let main_pid = self_pid.wrapping_add(22_001).max(200);
        let webview_pid = self_pid.wrapping_add(33_001).max(300);
        let probe_pid = self_pid.wrapping_add(33_002).max(301);

        let tracker = ExcludedPidTracker::new(self_pid, Some(tunnel_pid), [], Some(main_pid));
        tracker.sync_descendant_pids([webview_pid, probe_pid, 0].into_iter().collect());

        let snap1 = tracker.snapshot_active();
        assert!(snap1.contains(&self_pid));
        assert!(snap1.contains(&tunnel_pid));
        assert!(snap1.contains(&main_pid));
        assert!(snap1.contains(&webview_pid));
        assert!(snap1.contains(&probe_pid));
        assert!(!snap1.contains(&0));

        // Clearing main_core_pid must keep descendant tree and pinned PIDs intact.
        tracker.sync_main_core_pid(None);
        let snap2 = tracker.snapshot_active();
        assert!(snap2.contains(&self_pid));
        assert!(snap2.contains(&tunnel_pid));
        assert!(snap2.contains(&webview_pid));
        assert!(snap2.contains(&probe_pid));
        assert!(!snap2.contains(&main_pid));

        // Refreshing descendant tree replaces stale descendants while retaining pinned PIDs.
        tracker.sync_descendant_pids([webview_pid].into_iter().collect());
        let snap3 = tracker.snapshot_active();
        assert!(snap3.contains(&self_pid));
        assert!(snap3.contains(&tunnel_pid));
        assert!(snap3.contains(&webview_pid));
        assert!(!snap3.contains(&probe_pid));
    }

    #[test]
    fn loopback_packet_rewrite_mss_clamp_and_interface_binding_work() {
        // 1. Standalone YAML writes `interface-name` when a physical NIC is provided.
        let cfg = AppConfig::default();
        let relays = vec![sample_anytls_relay_with_dirty_sni()];
        let yaml_bound = compile_standalone_preaccel_yaml_with_interface(
            &cfg,
            &relays,
            17909,
            Some("WLAN"),
        )
        .expect("compile with physical interface");
        let doc: Value = serde_yaml_ng::from_str(&yaml_bound).expect("valid yaml");
        assert_eq!(doc["interface-name"].as_str(), Some("WLAN"));

        let yaml_unbound = compile_standalone_preaccel_yaml_with_interface(
            &cfg,
            &relays,
            17909,
            Some("   "),
        )
        .expect("compile with blank interface");
        let doc_unbound: Value = serde_yaml_ng::from_str(&yaml_unbound).expect("valid yaml");
        assert!(doc_unbound.get("interface-name").is_none());

        // 2. Outbound packet rewrite to 127.0.0.1 loopback + return packet restoration + MSS clamping.
        let mut pkt = [0u8; 44]; // 20B IPv4 + 24B TCP (including 4B MSS option)
        pkt[0] = 0x45;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[192, 168, 2, 10]);
        pkt[16..20].copy_from_slice(&[203, 0, 113, 44]);
        pkt[20..22].copy_from_slice(&51234u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&2053u16.to_be_bytes());
        pkt[32] = 6 << 4; // TCP data offset = 24 bytes
        pkt[33] = Ipv4TcpMeta::FLAG_SYN | Ipv4TcpMeta::FLAG_ACK;
        // TCP Option Kind=2 (MSS), Len=4, Value=65495 (Windows loopback giant MSS)
        pkt[40] = 2;
        pkt[41] = 4;
        pkt[42..44].copy_from_slice(&65495u16.to_be_bytes());

        assert!(rewrite_ipv4_tcp_to_loopback(&mut pkt, 20, 48888));
        let lo_meta = parse_ipv4_tcp_packet(&pkt).expect("parse loopback packet");
        assert_eq!(lo_meta.src_ip, Ipv4Addr::LOCALHOST);
        assert_eq!(lo_meta.dst_ip, Ipv4Addr::LOCALHOST);
        assert_eq!(lo_meta.src_port, 51234);
        assert_eq!(lo_meta.dst_port, 48888);

        // Simulate return packet from 127.0.0.1:48888 -> 127.0.0.1:51234
        pkt[20..22].copy_from_slice(&48888u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&51234u16.to_be_bytes());
        assert!(rewrite_ipv4_tcp_from_loopback(
            &mut pkt,
            20,
            Ipv4Addr::new(203, 0, 113, 44),
            2053,
            Ipv4Addr::new(192, 168, 2, 10),
        ));
        assert!(clamp_tcp_syn_mss(&mut pkt, 20, 1460));
        assert!(!clamp_tcp_syn_mss(&mut pkt, 20, 1460)); // already clamped

        let ret_meta = parse_ipv4_tcp_packet(&pkt).expect("parse restored packet");
        assert_eq!(ret_meta.src_ip, Ipv4Addr::new(203, 0, 113, 44));
        assert_eq!(ret_meta.dst_ip, Ipv4Addr::new(192, 168, 2, 10));
        assert_eq!(ret_meta.src_port, 2053);
        assert_eq!(ret_meta.dst_port, 51234);
        assert_eq!(u16::from_be_bytes([pkt[42], pkt[43]]), 1460);
    }

    #[test]
    fn security_product_classification_and_tailored_guidance_cover_huorong_360_and_defender() {
        let procs = vec![
            "MsMpEng.exe".to_string(),
            "HipsDaemon.exe".to_string(),
            "svchost.exe".to_string(),
        ];
        let products = classify_security_products_from_process_names(&procs);
        // Third-party security suite (Huorong) ranks ahead of Defender.
        assert_eq!(
            products,
            vec![
                "火绒安全".to_string(),
                "Windows 安全中心（Defender）".to_string()
            ]
        );
        let guide_hr = build_security_guidance(
            &products,
            Some(Path::new(r"C:\CatCloud\bin")),
            "self_test_blocked",
        );
        assert!(guide_hr.contains("火绒安全"));
        assert!(guide_hr.contains("信任区"));
        assert!(guide_hr.contains("重新探测"));

        let defender_only =
            classify_security_products_from_process_names(&["msmpeng.exe".to_string()]);
        assert_eq!(
            defender_only,
            vec!["Windows 安全中心（Defender）".to_string()]
        );
        let guide_def = build_security_guidance(
            &defender_only,
            Some(Path::new(r"C:\CatCloud\bin")),
            "download_or_write",
        );
        assert!(guide_def.contains("Windows 安全中心"));
        assert!(guide_def.contains("排除项"));

        let suite_360 =
            classify_security_products_from_process_names(&["360Tray.exe".to_string()]);
        assert_eq!(suite_360, vec!["360 安全卫士".to_string()]);
        let guide_360 = build_security_guidance(&suite_360, None, "driver_load");
        assert!(guide_360.contains("360 安全卫士"));

        // Self-test probe URL list strictly retains HTTP non-443 endpoints and deduplicates.
        let urls = build_self_test_probe_urls("https://example.com:443/check");
        assert_eq!(urls.len(), 2);
        assert!(urls[0].starts_with("http://"));
        assert!(urls[1].starts_with("http://"));
    }

    #[tokio::test]
    async fn self_test_redirected_stream_increments_counter_without_polluting_user_metrics() {
        let mock_socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = mock_socks.local_addr().unwrap().port();
        let socks_task = tokio::spawn(async move {
            let (mut sock, _) = mock_socks.accept().await.unwrap();
            let mut greet = [0u8; 3];
            sock.read_exact(&mut greet).await.unwrap();
            sock.write_all(&[0x05, 0x00]).await.unwrap();
            let mut req = [0u8; 10];
            sock.read_exact(&mut req).await.unwrap();
            sock.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            let mut buf = [0u8; 64];
            let _ = sock.read(&mut buf).await;
            sock.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let _ = sock.shutdown().await;
        });

        let redir_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let redir_addr = redir_listener.local_addr().unwrap();
        let nat_table = Arc::new(NatTable::new(16, Duration::from_secs(60)));
        let metrics = Arc::new(GlobalPreAccelMetrics::default());
        let accepted_counter = Arc::new(AtomicU64::new(0));
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let nat_c = Arc::clone(&nat_table);
        let met_c = Arc::clone(&metrics);
        let acc_c = Arc::clone(&accepted_counter);
        let accept_task = tokio::spawn(async move {
            let (stream, peer) = redir_listener.accept().await.unwrap();
            forward_redirected_stream(stream, peer, socks_port, nat_c, met_c, shutdown_rx, Some(acc_c))
                .await;
        });

        let sock = tokio::net::TcpSocket::new_v4().unwrap();
        sock.bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
            .unwrap();
        let local_ep = match sock.local_addr().unwrap() {
            SocketAddr::V4(v4) => (*v4.ip(), v4.port()),
            _ => unreachable!(),
        };
        nat_table.insert(
            local_ep,
            NatEntry {
                orig_src_ip: Ipv4Addr::new(192, 0, 2, 10),
                orig_dst_ip: Ipv4Addr::new(203, 0, 113, 80),
                orig_dst_port: 80,
                if_idx: 1,
                sub_if_idx: 0,
                owner_pid: std::process::id(),
                process_name: "catcloud-desktop.exe".to_string(),
                detected_by: SELF_TEST_DETECTED_BY.to_string(),
                last_seen: Instant::now(),
                closing_since: None,
            },
        );

        let mut client = sock.connect(redir_addr).await.unwrap();
        client
            .write_all(b"GET /generate_204 HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .unwrap();
        let mut resp = [0u8; 64];
        let n = client.read(&mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp[..n]).contains("204"));
        drop(client);
        let _ = socks_task.await;
        let _ = accept_task.await;

        assert_eq!(accepted_counter.load(Ordering::SeqCst), 1);
        assert_eq!(metrics.total_connections.load(Ordering::Relaxed), 0);
        assert!(metrics.recent_processes_snapshot().is_empty());
        assert!(metrics.snapshot().is_empty());
    }

    #[test]
    fn standalone_preaccel_yaml_excludes_ip_and_domain_probe_url_from_direct_rules() {
        let mut cfg = AppConfig::default();
        cfg.preaccel.enabled = true;
        cfg.preaccel.probe_url = "http://203.0.113.204/generate_204".to_string();
        cfg.preaccel.fallback_probe_url = "http://connect.rom.miui.com/generate_204".to_string();
        cfg.preaccel.campus_direct_domains = vec!["portal.campus.example.edu".to_string()];

        let mut domain_relay = sample_vless_relay_with_dirty_sni();
        domain_relay.id = "relay-domain-443".to_string();
        domain_relay.server = "relay-cn.example.com".to_string();
        domain_relay.priority = 30;

        let relays = vec![sample_anytls_relay_with_dirty_sni(), domain_relay];
        let yaml_str =
            compile_standalone_preaccel_yaml_with_interface(&cfg, &relays, 17912, Some("WLAN"))
                .expect("compile standalone yaml");
        let doc: Value = serde_yaml_ng::from_str(&yaml_str).expect("parse standalone yaml");
        let rules: Vec<&str> = doc["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();

        assert!(rules.contains(&"IP-CIDR,203.0.113.10/32,DIRECT,no-resolve"));
        assert!(rules.contains(&"DOMAIN,relay-cn.example.com,DIRECT"));
        assert!(!rules.iter().any(|r| r.contains("203.0.113.204")));
        assert!(!rules.iter().any(|r| {
            let lower = r.to_ascii_lowercase();
            lower.contains("hicloud.com")
                || lower.contains("miui.com")
                || lower.contains("campus.example.edu")
        }));
        let expected_match = format!("MATCH,{PREACCEL_SELECT_GROUP}");
        assert_eq!(rules.last().copied(), Some(expected_match.as_str()));
    }

    #[test]
    fn is_physical_nic_descriptor_allows_pppoe_and_cellular_while_blocking_vpns_and_miniports() {
        // Real physical NICs: Ethernet (6), Wi-Fi (71), PPPoE dial-up (23), 4G/5G WWAN (243/244).
        assert!(is_physical_nic_descriptor(
            6,
            5,
            "Intel(R) Ethernet Controller I225-V"
        ));
        assert!(is_physical_nic_descriptor(
            71,
            4,
            "Qualcomm FastConnect 6900 Wi-Fi 6E"
        ));
        assert!(is_physical_nic_descriptor(23, 5, "WAN Miniport (PPPOE)"));
        assert!(is_physical_nic_descriptor(
            23,
            5,
            "WAN Miniport (PPPoE) 宽带连接"
        ));
        assert!(is_physical_nic_descriptor(
            243,
            5,
            "Qualcomm Snapdragon X55 5G Modem"
        ));
        assert!(is_physical_nic_descriptor(
            244,
            4,
            "Fibocom L850-GL 4G LTE"
        ));

        // Non-PPPoE WAN Miniports and VPN dial-up protocols must stay strictly blocked.
        assert!(!is_physical_nic_descriptor(23, 5, "WAN Miniport (PPTP)"));
        assert!(!is_physical_nic_descriptor(23, 5, "WAN Miniport (L2TP)"));
        assert!(!is_physical_nic_descriptor(23, 5, "WAN Miniport (SSTP)"));
        assert!(!is_physical_nic_descriptor(23, 5, "WAN Miniport (IKEv2)"));
        assert!(!is_physical_nic_descriptor(23, 5, "WAN Miniport (IP)"));
        assert!(!is_physical_nic_descriptor(23, 5, "Corp L2TP Dialer"));
        assert!(!is_physical_nic_descriptor(23, 5, "WAN Miniport (PPPOE) VPN"));

        // Virtual / TUN / container / hypervisor adapters remain strictly blocked.
        assert!(!is_physical_nic_descriptor(6, 5, "Wintun Userspace Tunnel"));
        assert!(!is_physical_nic_descriptor(6, 5, "WireGuard Tunnel"));
        assert!(!is_physical_nic_descriptor(6, 5, "Clash Meta Adapter"));
        assert!(!is_physical_nic_descriptor(6, 5, "Mihomo TUN"));
        assert!(!is_physical_nic_descriptor(6, 5, "TAP-Windows Adapter V9"));
        assert!(!is_physical_nic_descriptor(6, 5, "VMware Network Adapter VMnet8"));
        assert!(!is_physical_nic_descriptor(6, 5, "VirtualBox Host-Only Ethernet"));
        assert!(!is_physical_nic_descriptor(243, 5, "Virtual Cellular VPN"));
        assert!(!is_physical_nic_descriptor(23, 2, "WAN Miniport (PPPOE)")); // oper_status down
    }

    #[test]
    fn nat_table_closing_grace_blocks_port_reuse_cross_flow_and_remove_active_guards_closing() {
        assert_eq!(NAT_CLOSING_GRACE, Duration::from_secs(4));

        let table = NatTable::new(16, Duration::from_secs(60));
        let key = (Ipv4Addr::LOCALHOST, 52100);
        let src_a = Ipv4Addr::new(192, 0, 2, 10);
        let src_b = Ipv4Addr::new(192, 0, 2, 11);
        let dst_a = Ipv4Addr::new(203, 0, 113, 10);
        let dst_b = Ipv4Addr::new(203, 0, 113, 20);
        let now = Instant::now();

        table.insert(
            key,
            NatEntry {
                orig_src_ip: src_a,
                orig_dst_ip: dst_a,
                orig_dst_port: 8443,
                if_idx: 4,
                sub_if_idx: 0,
                owner_pid: 7001,
                process_name: "proxy-core.exe".to_string(),
                detected_by: "open_core_name".to_string(),
                last_seen: now,
                closing_since: None,
            },
        );

        // Active entry: mismatching 4-tuple cannot be removed by `remove_active_if_matching`.
        assert!(!table.remove_active_if_matching(&key, src_b, dst_a, 8443));
        assert!(!table.remove_active_if_matching(&key, src_a, dst_b, 8443));
        assert!(!table.remove_active_if_matching(&key, src_a, dst_a, 9443));
        assert!(table.get_and_touch(&key).is_some());

        // Transition to closing grace: `remove_active_if_matching` must refuse even exact 4-tuple.
        assert!(table.mark_closing_if_matching(&key, src_a, dst_a, 8443));
        assert!(!table.remove_active_if_matching(&key, src_a, dst_a, 8443));
        assert!(table.get_and_touch(&key).is_some());

        // Closing grace conflicts with any different 4-tuple reusing the ephemeral source port.
        assert!(table.has_active_conflict(&key, src_b, dst_a, 8443));
        assert!(table.has_active_conflict(&key, src_a, dst_b, 8443));
        assert!(table.has_active_conflict(&key, src_a, dst_a, 9443));
        assert!(!table.has_active_conflict(&key, src_a, dst_a, 8443));

        // Once the 4s closing grace elapses, conflict clears and the stale entry is evicted.
        table.insert(
            key,
            NatEntry {
                orig_src_ip: src_a,
                orig_dst_ip: dst_a,
                orig_dst_port: 8443,
                if_idx: 4,
                sub_if_idx: 0,
                owner_pid: 7001,
                process_name: "proxy-core.exe".to_string(),
                detected_by: "open_core_name".to_string(),
                last_seen: now,
                closing_since: Some(now - Duration::from_secs(5)),
            },
        );
        assert!(!table.has_active_conflict(&key, src_a, dst_b, 9443));
        assert!(table.is_empty());

        // Re-insert active entry and verify exact active removal works cleanly.
        table.insert(
            key,
            NatEntry {
                orig_src_ip: src_a,
                orig_dst_ip: dst_a,
                orig_dst_port: 8443,
                if_idx: 4,
                sub_if_idx: 0,
                owner_pid: 7001,
                process_name: "proxy-core.exe".to_string(),
                detected_by: "open_core_name".to_string(),
                last_seen: Instant::now(),
                closing_since: None,
            },
        );
        assert!(table.remove_active_if_matching(&key, src_a, dst_a, 8443));
        assert!(table.is_empty());
    }

    #[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
    #[test]
    fn locate_windivert_files_short_circuits_on_non_windows_x64() {
        let root = std::env::temp_dir().join(format!(
            "catcloud-wd-shortcircuit-{}",
            uuid::Uuid::new_v4()
        ));
        let paths = AppPaths::from_data_dir(root.join("data"), true).unwrap();
        std::fs::write(paths.bin_dir.join("WinDivert64.dll"), b"dll").unwrap();
        std::fs::write(paths.bin_dir.join("WinDivert64.sys"), b"sys").unwrap();

        assert!(locate_windivert_files(&paths, None).is_none());
        assert!(locate_windivert_paths(&paths, None).is_none());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn reverify_windivert_when_stopped_never_resurrects_runtime() {
        let root = std::env::temp_dir().join(format!(
            "catcloud-reverify-stopped-{}",
            uuid::Uuid::new_v4()
        ));
        let paths = AppPaths::from_data_dir(root.join("data"), true).unwrap();
        let job_guard = Arc::new(JobGuard::new().unwrap());
        let manager = GlobalPreAccelManager::new(paths, job_guard);
        let cfg = AppConfig::default();
        let relays = vec![sample_anytls_relay_with_dirty_sni()];

        let stopped = manager.stop().await.expect("stop idle manager");
        assert!(!stopped.running);
        assert_eq!(stopped.mode, "off");

        let reverified = manager
            .reverify_windivert(&cfg, &relays, &[])
            .await
            .expect("reverify stopped manager");
        assert!(!reverified.running);
        assert_eq!(reverified.mode, "off");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn process_stats_dedup_by_lowercase_name_upgrades_detected_by_priority_and_prevents_active_leak()
    {
        let metrics = GlobalPreAccelMetrics::default();

        // Unknown/empty labels normalize to lowest-priority `"runtime"` (0).
        metrics.record_process_connection_open(1000, "ProxyCore.exe", "");
        let snap0 = metrics.snapshot();
        assert_eq!(snap0.len(), 1);
        assert_eq!(snap0[0].detected_by, "runtime");

        // Same executable across different PIDs, casing, and detection labels must merge into one card
        // and monotonically promote priority: runtime(0) < scope_all(1) < manual(2) <
        // local_proxy_listener(3) < open_core_name(4) < system_proxy_host(5).
        metrics.record_process_connection_open(1001, "ProxyCore.exe", "scope_all");
        assert_eq!(metrics.snapshot()[0].detected_by, "scope_all");
        metrics.record_process_connection_open(1002, "proxycore.exe", "manual");
        assert_eq!(metrics.snapshot()[0].detected_by, "manual");
        metrics.record_process_connection_open(1003, "PROXYCORE.EXE", "local_proxy_listener");
        assert_eq!(metrics.snapshot()[0].detected_by, "local_proxy_listener");
        metrics.record_process_connection_open(1004, "proxycore.exe", "open_core_name");
        assert_eq!(metrics.snapshot()[0].detected_by, "open_core_name");
        metrics.record_process_connection_open(1005, "proxycore.exe", "system_proxy_host");
        assert_eq!(metrics.snapshot()[0].detected_by, "system_proxy_host");
        // Lower-priority subsequent open must NEVER downgrade `detected_by`.
        metrics.record_process_connection_open(1006, "proxycore.exe", "manual");
        metrics.record_process_bytes(1006, "proxycore.exe", "scope_all", 128, 256);

        let snap1 = metrics.snapshot();
        assert_eq!(snap1.len(), 1);
        assert_eq!(snap1[0].process_name, "ProxyCore.exe");
        assert_eq!(snap1[0].pid, 1006);
        assert_eq!(snap1[0].detected_by, "system_proxy_host");
        assert_eq!(snap1[0].active_connections, 7);
        assert_eq!(snap1[0].total_connections, 7);
        assert_eq!(snap1[0].tx_bytes, 128);
        assert_eq!(snap1[0].rx_bytes, 256);

        // Closing with old PIDs and old detection labels must still decrement cleanly to 0.
        for (pid, label) in [
            (1000, "runtime"),
            (1001, "scope_all"),
            (1002, "manual"),
            (1003, "local_proxy_listener"),
            (1004, "open_core_name"),
            (1005, "system_proxy_host"),
            (9999, "runtime"),
        ] {
            metrics.record_process_connection_close(pid, "PROXYCORE.EXE", label);
        }
        let snap2 = metrics.snapshot();
        assert_eq!(snap2.len(), 1);
        assert_eq!(snap2[0].active_connections, 0);
        assert_eq!(snap2[0].detected_by, "system_proxy_host");
    }

    #[tokio::test]
    async fn manager_stop_clears_stale_process_cards_and_reload_helpers_are_noop_when_idle() {
        let root = std::env::temp_dir().join(format!(
            "catcloud-stop-clear-{}",
            uuid::Uuid::new_v4()
        ));
        let paths = AppPaths::from_data_dir(root.join("data"), true).unwrap();
        let job_guard = Arc::new(JobGuard::new().unwrap());
        let manager = GlobalPreAccelManager::new(paths, job_guard);
        let cfg = AppConfig::default();
        let relays = vec![sample_anytls_relay_with_dirty_sni()];

        // Simulate active telemetry from a prior session.
        manager
            .metrics
            .record_process_connection_open(4100, "mihomo.exe", "open_core_name");
        manager
            .metrics
            .record_process_bytes(4100, "mihomo.exe", "open_core_name", 1024, 2048);
        assert_eq!(manager.status().process_stats.len(), 1);
        assert_eq!(manager.status().accelerated_processes.len(), 1);

        // Stopping must wipe both `process_stats` and `accelerated_processes` completely.
        let stopped = manager.stop().await.expect("stop manager");
        assert!(!stopped.running);
        assert_eq!(stopped.mode, "off");
        assert!(stopped.process_stats.is_empty());
        assert!(stopped.accelerated_processes.is_empty());

        // Reload helpers on an idle manager must remain safe no-ops without starting runtime.
        let after_stop_reload = manager
            .stop_windivert_for_reload()
            .await
            .expect("stop_windivert_for_reload when idle");
        assert!(!after_stop_reload.running);
        let after_restart = manager
            .restart_windivert_if_running(&cfg, &relays, &[])
            .await
            .expect("restart_windivert_if_running when idle");
        assert!(!after_restart.running);
        assert_eq!(after_restart.mode, "off");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn is_non_proxy_communication_process_filters_im_browsers_ides_without_hitting_ssh_git_or_manual()
    {
        for blocked in [
            "QQ.exe",
            r"C:\Program Files\Tencent\QQNT\QQNT.exe",
            "QQProtect.exe",
            "txupd.exe",
            "TIM.exe",
            "WeChat.exe",
            "Weixin.exe",
            "WeChatAppEx.exe",
            "WeChatOCR.exe",
            "DingTalk.exe",
            "Feishu.exe",
            "Lark.exe",
            "WXWork.exe",
            "QYWX.exe",
            "wemeetapp.exe",
            "TencentMeeting.exe",
            "AliWangWang.exe",
            "YY.exe",
            "Foxmail.exe",
            "chrome.exe",
            "msedge.exe",
            "firefox.exe",
            "Code.exe",
            "steam.exe",
            "steamwebhelper.exe",
            "cloudmusic.exe",
            "QQMusic.exe",
            "BaiduNetdisk.exe",
            "wps.exe",
        ] {
            assert!(
                is_non_proxy_communication_process(blocked),
                "`{blocked}` must be classified as a non-proxy communication/desktop process"
            );
        }

        // Must never misclassify SSH/Git/transfer tools or open-source proxy cores.
        for allowed in [
            "ssh.exe",
            "git.exe",
            "scp.exe",
            "rsync.exe",
            "mihomo.exe",
            "xray.exe",
            "sing-box.exe",
            "proxy-engine.exe",
            "",
        ] {
            assert!(
                !is_non_proxy_communication_process(allowed),
                "`{allowed}` must NOT be classified as a non-proxy communication process"
            );
        }

        // User manual target list still works even if a user explicitly adds an app name.
        let manual_targets: HashSet<String> = ["ssh.exe", "git.exe", "qq.exe"]
            .into_iter()
            .map(String::from)
            .collect();
        let empty_excl = HashSet::new();
        let empty_det = HashMap::new();
        assert_eq!(
            classify_intercept_process(
                5001,
                Some("ssh.exe"),
                GlobalPreAccelScope::ProxyAppsOnly,
                &manual_targets,
                &empty_excl,
                &empty_det
            ),
            Some("manual")
        );
        assert_eq!(
            classify_intercept_process(
                5002,
                Some("qq.exe"),
                GlobalPreAccelScope::ProxyAppsOnly,
                &manual_targets,
                &empty_excl,
                &empty_det
            ),
            Some("manual")
        );
    }

    #[test]
    fn cn_ipv4_ranges_are_strictly_sorted_disjoint_and_is_domestic_ipv4_classifies_accurately() {
        assert!(!CN_IPV4_RANGES.is_empty());
        for pair in CN_IPV4_RANGES.windows(2) {
            let (s0, e0) = pair[0];
            let (s1, e1) = pair[1];
            assert!(s0 <= e0, "invalid range {s0:#010X}..={e0:#010X}");
            assert!(s1 <= e1, "invalid range {s1:#010X}..={e1:#010X}");
            assert!(
                e0 < s1,
                "CN_IPV4_RANGES must be strictly ascending & non-overlapping: {e0:#010X} >= {s1:#010X}"
            );
        }

        // All 13 whitelisted domestic public DNS IPs & major CN ISP/cloud/CERNET hex samples match.
        for &dns_ip in DOMESTIC_PUBLIC_DNS_IPV4S {
            assert!(is_domestic_ipv4(dns_ip), "domestic DNS {dns_ip} must match CN table");
        }
        for hex_cn in [
            0xDCB5_2694u32, // China Telecom web portal range
            0x279C_420Au32, // China Mobile range
            0xB702_ACB9u32, // China Telecom GD range
            0x6F0D_65D0u32, // China Mobile core range
            0x2F60_0101u32, // Alibaba Cloud CN range
            0x7904_0101u32, // Tencent Cloud CN range
            0x72D4_0101u32, // CERNET range
            0xCA70_0E97u32, // CERNET backbone range
            0xA66F_0464u32, // CERNET university range
        ] {
            let ip = Ipv4Addr::from(hex_cn);
            assert!(
                is_domestic_ipv4(ip),
                "expected hex {hex_cn:#010X} to be domestic CN IPv4"
            );
        }

        // Overseas public IPs, overseas cloud ranges, private LAN, Fake-IP, and RFC 5737 must return false.
        for hex_non_cn in [
            0x0101_0101u32, // Cloudflare DNS
            0x0808_0808u32, // Google DNS
            0x0909_0909u32, // Quad9 DNS
            0x6812_0001u32, // Overseas CDN
            0x8EFA_0101u32, // Overseas search edge
            0x8C52_7904u32, // Overseas git forge
            0xACD9_A04Eu32, // Overseas search cloud
            0x2F4A_0101u32, // Overseas cloud node
            0x2B82_0101u32, // Overseas cloud node
            0x6520_0101u32, // Overseas cloud node
            0x771C_0101u32, // Overseas cloud node
            0x0A00_0001u32, // RFC 1918
            0x7F00_0001u32, // Loopback
            0xC0A8_0101u32, // RFC 1918
            0xC612_0001u32, // Fake-IP
            0xCB00_710Au32, // RFC 5737
        ] {
            let ip = Ipv4Addr::from(hex_non_cn);
            assert!(
                !is_domestic_ipv4(ip),
                "expected hex {hex_non_cn:#010X} NOT to match CN IPv4 table"
            );
        }
    }

    #[test]
    fn build_windivert_filter_with_options_toggles_443_and_excludes_13_domestic_dns_ips() {
        let relays = [Ipv4Addr::new(203, 0, 113, 10)];

        let filter_skip = build_windivert_filter_with_options(&relays, 55000, true);
        assert!(filter_skip.contains("tcp.DstPort != 443"));
        assert!(filter_skip.contains("tcp.DstPort != 53"));
        assert!(filter_skip.contains("ip.DstAddr != 203.0.113.10"));
        assert_eq!(DOMESTIC_PUBLIC_DNS_IPV4S.len(), 13);
        for &dns_ip in DOMESTIC_PUBLIC_DNS_IPV4S {
            let clause = format!("ip.DstAddr != {dns_ip}");
            assert!(
                filter_skip.contains(&clause),
                "missing domestic DNS exclusion `{clause}`"
            );
        }

        let filter_include_443 = build_windivert_filter_with_options(&relays, 55000, false);
        assert!(!filter_include_443.contains("tcp.DstPort != 443"));
        assert!(filter_include_443.contains("tcp.DstPort != 53"));
        assert!(filter_include_443.contains("ip.DstAddr != 203.0.113.10"));
        for &dns_ip in DOMESTIC_PUBLIC_DNS_IPV4S {
            assert!(filter_include_443.contains(&format!("ip.DstAddr != {dns_ip}")));
        }
    }

    #[test]
    fn should_intercept_port_443_enforces_skip_flag_proxy_tags_and_non_domestic_dst() {
        let overseas_dst = Ipv4Addr::from(0x6812_0001u32);
        let domestic_dst = Ipv4Addr::from(0xDCB5_2694u32);

        // skip_443_native == true always rejects 443 regardless of label or destination.
        assert!(!should_intercept_port_443("system_proxy_host", true, overseas_dst));
        assert!(!should_intercept_port_443("open_core_name", true, overseas_dst));

        // skip_443_native == false allows ONLY exact proxy-core tags to non-domestic IPs.
        for allowed_tag in ["system_proxy_host", "local_proxy_listener", "open_core_name"] {
            assert!(should_intercept_port_443(allowed_tag, false, overseas_dst));
            assert!(!should_intercept_port_443(allowed_tag, false, domestic_dst));
        }

        // manual & scope_all & unknown must ALWAYS bypass 443 even when skip_443_native == false.
        for denied_tag in ["manual", "scope_all", "unknown", "self_test"] {
            assert!(!should_intercept_port_443(denied_tag, false, overseas_dst));
        }
    }

    #[test]
    fn nat_table_lockfree_port_bitmap_and_copy_packet_view_stay_in_sync_across_insert_evict_remove()
    {
        let table = NatTable::new(2, Duration::from_secs(60));
        let now = Instant::now();
        let k1 = (Ipv4Addr::LOCALHOST, 45001);
        let k2 = (Ipv4Addr::LOCALHOST, 45002);
        let k3 = (Ipv4Addr::LOCALHOST, 45003);

        assert!(!table.may_contain_port(45001));
        assert!(table.get_packet_view_and_touch(&k1).is_none());

        table.insert(
            k1,
            NatEntry {
                orig_src_ip: Ipv4Addr::new(192, 0, 2, 10),
                orig_dst_ip: Ipv4Addr::new(203, 0, 113, 10),
                orig_dst_port: 8443,
                if_idx: 3,
                sub_if_idx: 1,
                owner_pid: 1111,
                process_name: "mihomo.exe".to_string(),
                detected_by: "open_core_name".to_string(),
                last_seen: now - Duration::from_secs(10),
                closing_since: None,
            },
        );
        assert!(table.may_contain_port(45001));
        let view1 = table.get_packet_view_and_touch(&k1).expect("view1");
        assert_eq!(view1.orig_dst_ip, Ipv4Addr::new(203, 0, 113, 10));
        assert_eq!(view1.orig_dst_port, 8443);
        assert_eq!(view1.if_idx, 3);
        assert_eq!(view1.sub_if_idx, 1);
        assert!(!view1.is_closing);
        assert!(!view1.is_self_test);

        // Insert k2 and k3 to trigger LRU eviction (k1 has older last_seen before touch? set k1 older again).
        table.insert(
            k1,
            NatEntry {
                orig_src_ip: Ipv4Addr::new(192, 0, 2, 10),
                orig_dst_ip: Ipv4Addr::new(203, 0, 113, 10),
                orig_dst_port: 8443,
                if_idx: 3,
                sub_if_idx: 1,
                owner_pid: 1111,
                process_name: "mihomo.exe".to_string(),
                detected_by: SELF_TEST_DETECTED_BY.to_string(),
                last_seen: now - Duration::from_secs(20),
                closing_since: None,
            },
        );
        assert!(table.get_packet_view_and_touch(&k1).unwrap().is_self_test);
        // Re-age k1 so k1 is oldest when k3 forces eviction.
        table.insert(
            k1,
            NatEntry {
                orig_src_ip: Ipv4Addr::new(192, 0, 2, 10),
                orig_dst_ip: Ipv4Addr::new(203, 0, 113, 10),
                orig_dst_port: 8443,
                if_idx: 3,
                sub_if_idx: 1,
                owner_pid: 1111,
                process_name: "mihomo.exe".to_string(),
                detected_by: "open_core_name".to_string(),
                last_seen: now - Duration::from_secs(30),
                closing_since: None,
            },
        );
        table.insert(
            k2,
            NatEntry {
                orig_src_ip: Ipv4Addr::new(192, 0, 2, 10),
                orig_dst_ip: Ipv4Addr::new(203, 0, 113, 20),
                orig_dst_port: 9443,
                if_idx: 3,
                sub_if_idx: 0,
                owner_pid: 2222,
                process_name: "xray.exe".to_string(),
                detected_by: "open_core_name".to_string(),
                last_seen: now - Duration::from_secs(5),
                closing_since: None,
            },
        );
        table.insert(
            k3,
            NatEntry {
                orig_src_ip: Ipv4Addr::new(192, 0, 2, 10),
                orig_dst_ip: Ipv4Addr::new(203, 0, 113, 30),
                orig_dst_port: 2053,
                if_idx: 3,
                sub_if_idx: 0,
                owner_pid: 3333,
                process_name: "ssh.exe".to_string(),
                detected_by: "manual".to_string(),
                last_seen: now,
                closing_since: None,
            },
        );

        // Evicted k1 must have its bitmap bit cleared while k2 & k3 remain set.
        assert!(!table.may_contain_port(45001));
        assert!(table.may_contain_port(45002));
        assert!(table.may_contain_port(45003));

        // Direct removal clears bitmap bit cleanly.
        assert!(table.remove(&k2).is_some());
        assert!(!table.may_contain_port(45002));
        assert!(table.remove_active_if_matching(
            &k3,
            Ipv4Addr::new(192, 0, 2, 10),
            Ipv4Addr::new(203, 0, 113, 30),
            2053
        ));
        assert!(!table.may_contain_port(45003));
        assert!(table.is_empty());
    }

    #[tokio::test]
    async fn global_preaccel_runtime_meta_suspend_for_tun_stop_and_drop_lifecycle() {
        let root = std::env::temp_dir().join(format!(
            "catcloud-global-meta-{}",
            uuid::Uuid::new_v4()
        ));
        let paths = AppPaths::from_data_dir(root.join("data"), true).unwrap();
        let data_dir = paths.root_data_dir.clone();

        // 1. Direct write/read/remove roundtrip.
        let sample_meta = GlobalPreAccelRuntimeMeta {
            pid: Some(42424),
            process_start_time_unix: Some(1_764_200_000),
            binary_path: Some("/opt/catcloud/bin/mihomo".to_string()),
            running: true,
            mode: "windivert".to_string(),
            effective_carrier: "standalone_windivert".to_string(),
            socks_port: Some(17908),
            active_relays: vec!["Relay-TX-443".to_string(), "Relay-ALI-443".to_string()],
            updated_at: "2026-11-27T00:00:00Z".to_string(),
        };
        write_global_preaccel_runtime_meta(&data_dir, &sample_meta).expect("write runtime meta");
        assert_eq!(
            read_global_preaccel_runtime_meta(&data_dir).as_ref(),
            Some(&sample_meta)
        );
        // Also readable when passing `run/` directory directly.
        assert_eq!(
            read_global_preaccel_runtime_meta(&paths.runtime_dir).as_ref(),
            Some(&sample_meta)
        );
        remove_global_preaccel_runtime_meta(&data_dir);
        assert!(read_global_preaccel_runtime_meta(&data_dir).is_none());

        // 2. Manager `suspend_for_tun` -> persists suspended_for_tun & carrier, updates live status;
        //    `stop` -> clears suspended state and removes runtime meta file cleanly.
        {
            let job_guard = Arc::new(JobGuard::new().unwrap());
            let manager = GlobalPreAccelManager::new(paths.clone(), job_guard);

            let suspended = manager
                .suspend_for_tun(vec!["Relay-TX-443".to_string()])
                .await
                .expect("suspend_for_tun");
            assert!(!suspended.running);
            assert_eq!(suspended.mode, "suspended_for_tun");
            assert_eq!(suspended.active_relays, vec!["Relay-TX-443".to_string()]);

            let persisted = read_global_preaccel_runtime_meta(&data_dir)
                .expect("suspended_for_tun meta must be written on disk");
            assert!(!persisted.running);
            assert_eq!(persisted.pid, None);
            assert_eq!(persisted.mode, "suspended_for_tun");
            assert_eq!(
                persisted.effective_carrier,
                "main_core_tun_suspended_standalone"
            );
            assert_eq!(persisted.active_relays, vec!["Relay-TX-443".to_string()]);

            let stopped = manager.stop().await.expect("stop clears suspended state");
            assert!(!stopped.running);
            assert_eq!(stopped.mode, "off");
            assert!(stopped.active_relays.is_empty());
            assert!(read_global_preaccel_runtime_meta(&data_dir).is_none());

            // 3. Re-suspend and drop manager -> Drop must clean up the runtime meta file.
            let _ = manager
                .suspend_for_tun(vec!["Relay-ALI-443".to_string()])
                .await
                .unwrap();
            assert!(read_global_preaccel_runtime_meta(&data_dir).is_some());
        }
        assert!(
            read_global_preaccel_runtime_meta(&data_dir).is_none(),
            "Drop must remove global-preaccel-runtime.json"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn windivert_runtime_fingerprint_skips_restart_when_unchanged_and_restarts_on_changes() {
        let base_relays = vec![Ipv4Addr::new(203, 0, 113, 10), Ipv4Addr::new(198, 51, 100, 20)];
        let base_procs = vec!["mihomo.exe".to_string(), "ssh.exe".to_string()];
        let mut base_pids = HashSet::new();
        base_pids.insert(1001);
        base_pids.insert(2002);

        let fp1 = WinDivertRuntimeFingerprint::from_inputs(
            PathBuf::from(r"C:\CatCloud\bin\WinDivert64.dll"),
            Some(PathBuf::from(r"C:\CatCloud\bin\WinDivert64.sys")),
            &base_relays,
            true,
            GlobalPreAccelScope::ProxyAppsOnly,
            &base_procs,
            &base_pids,
        );
        // Reordered inputs and uppercase process names normalize to the identical fingerprint.
        let fp_same = WinDivertRuntimeFingerprint::from_inputs(
            PathBuf::from(r"C:\CatCloud\bin\WinDivert64.dll"),
            Some(PathBuf::from(r"C:\CatCloud\bin\WinDivert64.sys")),
            &[Ipv4Addr::new(198, 51, 100, 20), Ipv4Addr::new(203, 0, 113, 10)],
            true,
            GlobalPreAccelScope::ProxyAppsOnly,
            &["SSH.EXE".to_string(), "mihomo.exe".to_string()],
            &base_pids,
        );
        assert_eq!(fp1, fp_same);
        assert!(should_skip_windivert_restart(false, Some(&fp1), Some(&fp_same)));
        assert!(!should_skip_windivert_restart(true, Some(&fp1), Some(&fp_same)));
        assert!(!should_skip_windivert_restart(false, None, Some(&fp_same)));
        assert!(!should_skip_windivert_restart(false, Some(&fp1), None));

        // Any static config change must invalidate the fingerprint and force restart.
        let fp_diff_dll = WinDivertRuntimeFingerprint::from_inputs(
            PathBuf::from(r"C:\Alt\WinDivert64.dll"),
            Some(PathBuf::from(r"C:\CatCloud\bin\WinDivert64.sys")),
            &base_relays,
            true,
            GlobalPreAccelScope::ProxyAppsOnly,
            &base_procs,
            &base_pids,
        );
        assert!(!should_skip_windivert_restart(false, Some(&fp1), Some(&fp_diff_dll)));

        let fp_diff_sys = WinDivertRuntimeFingerprint::from_inputs(
            PathBuf::from(r"C:\CatCloud\bin\WinDivert64.dll"),
            Some(PathBuf::from(r"C:\Alt\WinDivert64.sys")),
            &base_relays,
            true,
            GlobalPreAccelScope::ProxyAppsOnly,
            &base_procs,
            &base_pids,
        );
        assert!(!should_skip_windivert_restart(false, Some(&fp1), Some(&fp_diff_sys)));

        let fp_none_sys = WinDivertRuntimeFingerprint::from_inputs(
            PathBuf::from(r"C:\CatCloud\bin\WinDivert64.dll"),
            None,
            &base_relays,
            true,
            GlobalPreAccelScope::ProxyAppsOnly,
            &base_procs,
            &base_pids,
        );
        assert!(!should_skip_windivert_restart(false, Some(&fp1), Some(&fp_none_sys)));

        let fp_diff_skip443 = WinDivertRuntimeFingerprint::from_inputs(
            PathBuf::from(r"C:\CatCloud\bin\WinDivert64.dll"),
            Some(PathBuf::from(r"C:\CatCloud\bin\WinDivert64.sys")),
            &base_relays,
            false,
            GlobalPreAccelScope::ProxyAppsOnly,
            &base_procs,
            &base_pids,
        );
        assert!(!should_skip_windivert_restart(false, Some(&fp1), Some(&fp_diff_skip443)));

        let fp_diff_scope = WinDivertRuntimeFingerprint::from_inputs(
            PathBuf::from(r"C:\CatCloud\bin\WinDivert64.dll"),
            Some(PathBuf::from(r"C:\CatCloud\bin\WinDivert64.sys")),
            &base_relays,
            true,
            GlobalPreAccelScope::AllNon443Tcp,
            &base_procs,
            &base_pids,
        );
        assert!(!should_skip_windivert_restart(false, Some(&fp1), Some(&fp_diff_scope)));

        let fp_diff_procs = WinDivertRuntimeFingerprint::from_inputs(
            PathBuf::from(r"C:\CatCloud\bin\WinDivert64.dll"),
            Some(PathBuf::from(r"C:\CatCloud\bin\WinDivert64.sys")),
            &base_relays,
            true,
            GlobalPreAccelScope::ProxyAppsOnly,
            &["mihomo.exe".to_string(), "scp.exe".to_string()],
            &base_pids,
        );
        assert!(!should_skip_windivert_restart(false, Some(&fp1), Some(&fp_diff_procs)));

        let mut changed_pids = base_pids.clone();
        changed_pids.insert(3003);
        let fp_diff_pids = WinDivertRuntimeFingerprint::from_inputs(
            PathBuf::from(r"C:\CatCloud\bin\WinDivert64.dll"),
            Some(PathBuf::from(r"C:\CatCloud\bin\WinDivert64.sys")),
            &base_relays,
            true,
            GlobalPreAccelScope::ProxyAppsOnly,
            &base_procs,
            &changed_pids,
        );
        assert!(!should_skip_windivert_restart(false, Some(&fp1), Some(&fp_diff_pids)));
    }

    #[test]
    fn nat_table_full_4096_capacity_evicts_expired_and_closing_before_live_flows_in_sync() {
        let table = NatTable::new(MAX_NAT_ENTRIES, NAT_IDLE_TIMEOUT);
        let now = Instant::now();
        let expired_ts = now - (NAT_IDLE_TIMEOUT + Duration::from_secs(5));
        let closing_ts = now - Duration::from_secs(1);

        // Fill table to exact MAX_NAT_ENTRIES (4096):
        //   0..128   -> expired entries
        //   128..132 -> closing (within grace) entries
        //   132..4096 -> active live entries
        for i in 0..MAX_NAT_ENTRIES {
            let port = 20000u16 + (i as u16);
            let (last_seen, closing_since) = if i < 128 {
                (expired_ts, None)
            } else if i < 132 {
                (now, Some(closing_ts))
            } else {
                (now, None)
            };
            table.insert(
                (Ipv4Addr::LOCALHOST, port),
                NatEntry {
                    orig_src_ip: Ipv4Addr::new(192, 0, 2, 1),
                    orig_dst_ip: Ipv4Addr::new(203, 0, 113, 10),
                    orig_dst_port: 8443,
                    if_idx: 1,
                    sub_if_idx: 0,
                    owner_pid: 42,
                    process_name: "mihomo.exe".to_string(),
                    detected_by: "open_core_name".to_string(),
                    last_seen,
                    closing_since,
                },
            );
        }

        // Inserting one fresh entry at full capacity sweeps all 128 expired entries in O(N)
        // and clears their lock-free bitmap bits while preserving active flows.
        let fresh_port = 55000u16;
        table.insert(
            (Ipv4Addr::LOCALHOST, fresh_port),
            NatEntry {
                orig_src_ip: Ipv4Addr::new(192, 0, 2, 1),
                orig_dst_ip: Ipv4Addr::new(203, 0, 113, 10),
                orig_dst_port: 8443,
                if_idx: 1,
                sub_if_idx: 0,
                owner_pid: 42,
                process_name: "mihomo.exe".to_string(),
                detected_by: "open_core_name".to_string(),
                last_seen: now,
                closing_since: None,
            },
        );
        assert!(!table.may_contain_port(20000));
        assert!(!table.may_contain_port(20127));
        assert!(table.may_contain_port(20128));
        assert!(table.may_contain_port(20132));
        assert!(table.may_contain_port(fresh_port));

        // Refill the freed 127 slots so capacity reaches 4096 again, then insert 1 more entry:
        // the closing entry (port 20128..20131) must be evicted before any live entry.
        for offset in 0..127u16 {
            table.insert(
                (Ipv4Addr::LOCALHOST, 56000 + offset),
                NatEntry {
                    orig_src_ip: Ipv4Addr::new(192, 0, 2, 1),
                    orig_dst_ip: Ipv4Addr::new(203, 0, 113, 10),
                    orig_dst_port: 8443,
                    if_idx: 1,
                    sub_if_idx: 0,
                    owner_pid: 42,
                    process_name: "mihomo.exe".to_string(),
                    detected_by: "open_core_name".to_string(),
                    last_seen: now,
                    closing_since: None,
                },
            );
        }
        table.insert(
            (Ipv4Addr::LOCALHOST, 57000),
            NatEntry {
                orig_src_ip: Ipv4Addr::new(192, 0, 2, 1),
                orig_dst_ip: Ipv4Addr::new(203, 0, 113, 10),
                orig_dst_port: 8443,
                if_idx: 1,
                sub_if_idx: 0,
                owner_pid: 42,
                process_name: "mihomo.exe".to_string(),
                detected_by: "open_core_name".to_string(),
                last_seen: now,
                closing_since: None,
            },
        );
        let closing_remaining = (20128u16..20132)
            .filter(|&p| table.may_contain_port(p))
            .count();
        assert_eq!(closing_remaining, 3, "a closing entry must be evicted before live flows");
        assert!(table.may_contain_port(20132));
        assert!(table.may_contain_port(57000));
    }

    #[test]
    fn self_test_strict_204_rejects_non_204_and_empty_responses() {
        assert_eq!(validate_self_test_http_status(Some(204)), Ok(204));
        for bad in [Some(200), Some(302), Some(403), Some(502), None] {
            assert!(
                validate_self_test_http_status(bad).is_err(),
                "self-test must reject HTTP status {bad:?}"
            );
        }

        #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
        {
            use super::super::windivert_win::WinDivertSelfTestOutcome;

            let ok_outcome = enforce_self_test_strict_204(WinDivertSelfTestOutcome::Passed {
                latency_ms: 18,
                probe_host: "connectivitycheck.platform.hicloud.com".to_string(),
                status_code: 204,
            });
            assert!(matches!(
                ok_outcome,
                WinDivertSelfTestOutcome::Passed { status_code: 204, .. }
            ));

            for non_204 in [200u16, 302, 403, 502] {
                let rejected = enforce_self_test_strict_204(WinDivertSelfTestOutcome::Passed {
                    latency_ms: 25,
                    probe_host: "connectivitycheck.platform.hicloud.com".to_string(),
                    status_code: non_204,
                });
                assert!(
                    matches!(rejected, WinDivertSelfTestOutcome::TunnelUnreachable { .. }),
                    "HTTP {non_204} must downgrade to TunnelUnreachable, got {rejected:?}"
                );
            }
        }
    }

    #[test]
    fn build_self_test_probe_urls_prioritizes_custom_204_and_skips_non_204_with_204_fallbacks() {
        let custom_204 = build_self_test_probe_urls("http://custom-check.cn/generate_204");
        assert_eq!(
            custom_204,
            vec![
                "http://custom-check.cn/generate_204".to_string(),
                crate::preaccel::generator::DEFAULT_DOMESTIC_204_PRIMARY.to_string(),
                crate::preaccel::generator::DEFAULT_DOMESTIC_204_FALLBACK.to_string(),
            ]
        );

        let non_204 = build_self_test_probe_urls("http://custom-health.cn/ok");
        assert_eq!(
            non_204,
            vec![
                crate::preaccel::generator::DEFAULT_DOMESTIC_204_PRIMARY.to_string(),
                crate::preaccel::generator::DEFAULT_DOMESTIC_204_FALLBACK.to_string(),
            ]
        );

        let dedup = build_self_test_probe_urls(
            crate::preaccel::generator::DEFAULT_DOMESTIC_204_PRIMARY,
        );
        assert_eq!(dedup.len(), 2);
    }
}
