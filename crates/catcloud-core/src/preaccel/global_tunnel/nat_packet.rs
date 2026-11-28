use crate::error::{CatError, CatResult};
use crate::models::{GlobalPreAccelScope, PreAccelRelay};
use crate::preaccel::schema::parse_server_ip;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

/// Capacity threshold above which [`NatTable`] shrinks its hash map after bulk eviction.
const NAT_TABLE_SHRINK_THRESHOLD: usize = 512;

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
pub(super) const MAX_PROCESS_STATS: usize = 64;

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
pub(super) const CN_IPV4_RANGES: &[(u32, u32)] = &[
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
pub(in crate::preaccel) struct ExcludedPidTracker {
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
    pub(in crate::preaccel) fn new(
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

    pub(in crate::preaccel) fn shared_set(&self) -> Arc<std::sync::RwLock<HashSet<u32>>> {
        Arc::clone(&self.active)
    }

    pub(in crate::preaccel) fn snapshot_active(&self) -> HashSet<u32> {
        self.active
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Return the current deduplicated root PIDs whose full Windows descendant subtrees
    /// must be excluded (always includes `std::process::id()`, pinned PIDs, and `main_core_pid`).
    pub(in crate::preaccel) fn current_root_pids(&self) -> Vec<u32> {
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
    pub(in crate::preaccel) fn sync_main_core_pid(&self, main_core_pid: Option<u32>) {
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
    pub(in crate::preaccel) fn sync_descendant_pids(&self, descendants: HashSet<u32>) {
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
                if guard.capacity() > NAT_TABLE_SHRINK_THRESHOLD
                    && guard.len().saturating_mul(4) < guard.capacity()
                {
                    guard.shrink_to_fit();
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

    /// Sweep all idle or closing-grace-expired entries, synchronize the lock-free port bitmap,
    /// and shrink the underlying hash table when excess capacity remains.
    pub fn prune_expired(&self) -> usize {
        let now = Instant::now();
        let timeout = self.idle_timeout;
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let before = guard.len();
        if before == 0 {
            if guard.capacity() > NAT_TABLE_SHRINK_THRESHOLD {
                guard.shrink_to_fit();
            }
            return 0;
        }

        let mut evicted_ports: Vec<u16> = Vec::new();
        guard.retain(|&(_, port), v| {
            let keep = !Self::is_entry_expired(v, now, timeout);
            if !keep {
                evicted_ports.push(port);
            }
            keep
        });
        let removed = before.saturating_sub(guard.len());
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
        if removed > 0
            && guard.capacity() > NAT_TABLE_SHRINK_THRESHOLD
            && guard.len().saturating_mul(4) < guard.capacity()
        {
            guard.shrink_to_fit();
        }
        removed
    }

    /// Clear every entry and bit in the NAT table and immediately release excess heap capacity.
    pub fn clear(&self) {
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        guard.clear();
        guard.shrink_to_fit();
        for word in self.port_bitmap.iter() {
            word.store(0, Ordering::Release);
        }
    }

    /// Deterministically shrink the underlying NAT entry map to fit its active entry count.
    pub fn shrink_to_fit(&self) {
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        guard.shrink_to_fit();
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

pub(super) fn now_epoch_ms() -> u64 {
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
            guard.shrink_to_fit();
        }
        if let Ok(mut guard) = self.process_stats.lock() {
            guard.clear();
            guard.shrink_to_fit();
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
pub(in crate::preaccel) async fn forward_redirected_stream(
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

