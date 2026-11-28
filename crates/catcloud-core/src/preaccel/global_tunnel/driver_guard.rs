use super::nat_packet::normalize_process_basename;
use crate::error::{CatError, CatResult};
use crate::paths::{AppPaths, normalize_os_path};
use crate::platform::default_platform;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
#[cfg(not(all(target_os = "windows", target_arch = "aarch64")))]
use std::time::Duration;
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
pub(in crate::preaccel) const WINDIVERT_ARM64_UNSUPPORTED_MSG: &str = "当前为 Windows ARM64 架构，官方 WinDivert v2.2.2 未提供原生 ARM64 内核驱动；请使用内置的「本地独立 443 通道 (SOCKS5)」为其它软件提速";


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
        crate::preaccel::windivert_win::detect_windows_security_products()
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
