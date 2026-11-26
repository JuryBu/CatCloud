use crate::error::{CatError, CatResult};
use crate::paths::AppPaths;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;
use url::Url;
use zip::ZipArchive;

/// Strict HTTPS host allowlist for all CatCloud update metadata and artifact downloads.
pub const ALLOWED_UPDATE_HOSTS: &[&str] = &[
    "github.com",
    "api.github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "raw.githubusercontent.com",
];

/// Maximum number of HTTP redirects allowed across any update request.
pub const MAX_REDIRECT_HOPS: usize = 5;

/// Compressed update ZIP hard cap: 64 MiB.
pub const MAX_ZIP_BYTES: usize = 64 * 1024 * 1024;

/// Alias for the hard compressed update package size cap (64 MiB).
pub const MAX_PACKAGE_BYTES: usize = MAX_ZIP_BYTES;

/// Default request timeout for lightweight update metadata (`latest.json` / `SHA256SUMS.txt`).
pub const METADATA_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// Connect timeout for update artifact downloads.
pub const PACKAGE_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// Overall streaming download timeout for full update packages (up to 64 MiB).
pub const PACKAGE_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);

/// Known runtime subdirectory names that must never be stripped even when all files in an archive
/// reside under that single top-level directory.
const NON_STRIPPABLE_TOP_DIRS: &[&str] = &[
    "resources",
    "cli",
    "bin",
    "data",
    "assets",
    "icons",
    "themes",
    "locales",
    "plugins",
    "config",
    "runtime",
    "logs",
];

/// Uncompressed update payload hard cap (declared & real streamed): 192 MiB.
pub const MAX_UNCOMPRESSED_BYTES: u64 = 192 * 1024 * 1024;

/// Maximum number of file entries permitted inside an update ZIP archive.
pub const MAX_ZIP_ENTRIES: usize = 1000;

/// Metadata (`latest.json` / `SHA256SUMS.txt`) body cap: 512 KiB.
pub const MAX_METADATA_BYTES: usize = 512 * 1024;

/// Staging manifest filename written inside `.update_staging/`.
pub const PENDING_APPLY_MANIFEST: &str = "pending_apply.json";

/// Payload extraction subdirectory inside `.update_staging/`.
pub const STAGING_PAYLOAD_DIR: &str = "payload";

/// Verified installer package subdirectory inside `.update_staging/`.
pub const STAGING_INSTALLER_DIR: &str = "installer";

/// Maximum persisted UTF-8 byte length for release notes stored in `pending_apply.json` (32 KiB).
pub const MAX_RELEASE_NOTES_BYTES: usize = 32 * 1024;

/// Top-level user-owned paths that must NEVER be overwritten or deleted by an update.
const PRESERVED_TOP_NAMES: &[&str] = &[
    "data",
    "portable.flag",
    ".update_staging",
    ".update_backup",
    ".git",
    ".env",
    "logs",
    "config.json",
];

/// Any path segment matching one of these is unconditionally preserved.
const PRESERVED_ANY_SEGMENT: &[&str] = &[".git", ".update_staging", ".update_backup"];

// ============================================================================
// HTTPS allowlist & per-hop redirect validation
// ============================================================================

/// Validate a URL against CatCloud's strict update security policy:
/// - Scheme must be `https`
/// - Must not carry `username` or `password` (no userinfo)
/// - Port must be default or explicitly `443`
/// - Host must be an exact case-insensitive match in `ALLOWED_UPDATE_HOSTS`
pub fn validate_https_url(raw: &str) -> CatResult<Url> {
    if raw.chars().any(|c| c.is_control()) {
        return Err(CatError::Security(
            "update URL contains control characters".into(),
        ));
    }
    let parsed = Url::parse(raw.trim())
        .map_err(|e| CatError::Security(format!("malformed update URL: {e}")))?;

    if !parsed.scheme().eq_ignore_ascii_case("https") {
        return Err(CatError::Security(format!(
            "only HTTPS update URLs are allowed (got scheme '{}')",
            parsed.scheme()
        )));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(CatError::Security(
            "update URL must not contain userinfo credentials".into(),
        ));
    }
    if !matches!(parsed.port(), None | Some(443)) || parsed.port_or_known_default() != Some(443) {
        return Err(CatError::Security(format!(
            "update URL must use port 443 (got {:?})",
            parsed.port()
        )));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| CatError::Security("update URL missing host".into()))?;
    if host.ends_with('.') {
        return Err(CatError::Security(format!(
            "trailing dot in update host is not permitted: {host}"
        )));
    }
    let host_lower = host.to_ascii_lowercase();
    if !ALLOWED_UPDATE_HOSTS.iter().any(|allowed| *allowed == host_lower) {
        return Err(CatError::Security(format!(
            "unauthorized update host blocked: {host_lower}"
        )));
    }
    Ok(parsed)
}

/// Validate a single redirect hop BEFORE the HTTP client sends the redirected request.
/// `hops_so_far` is the 1-based redirect count (e.g., `attempt.previous().len()`).
pub fn validate_redirect_hop(hops_so_far: usize, next_url: &str) -> CatResult<Url> {
    if hops_so_far > MAX_REDIRECT_HOPS {
        return Err(CatError::Security(format!(
            "update redirect hop limit exceeded (max {MAX_REDIRECT_HOPS})"
        )));
    }
    validate_https_url(next_url)
}

/// Build a hardened `reqwest::Client` whose redirect policy validates every single hop
/// against `ALLOWED_UPDATE_HOSTS`, HTTPS-only, port 443, zero userinfo, and max 5 hops.
pub fn build_safe_http_client(timeout: Duration) -> CatResult<reqwest::Client> {
    build_safe_http_client_with_timeouts(timeout.min(PACKAGE_CONNECT_TIMEOUT), timeout)
}

/// Build a hardened `reqwest::Client` with explicit connect and total request timeouts.
pub fn build_safe_http_client_with_timeouts(
    connect_timeout: Duration,
    request_timeout: Duration,
) -> CatResult<reqwest::Client> {
    crate::init_crypto_provider();
    let policy = reqwest::redirect::Policy::custom(|attempt| {
        let hop_num = attempt.previous().len();
        match validate_redirect_hop(hop_num, attempt.url().as_str()) {
            Ok(_) => attempt.follow(),
            Err(err) => attempt.error(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                err.to_string(),
            )),
        }
    });

    reqwest::Client::builder()
        .redirect(policy)
        .connect_timeout(connect_timeout)
        .timeout(request_timeout)
        .user_agent(format!("CatCloud-Updater/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(CatError::Http)
}

// ============================================================================
// SemVer parsing & comparison (stable > same-core prerelease; rejects 0.0.0)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PreReleaseIdent {
    Numeric(u64),
    AlphaNumeric(String),
}

impl Ord for PreReleaseIdent {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Numeric(a), Self::Numeric(b)) => a.cmp(b),
            // SemVer 2.0 §11.4.3: numeric identifiers always have lower precedence than non-numeric.
            (Self::Numeric(_), Self::AlphaNumeric(_)) => Ordering::Less,
            (Self::AlphaNumeric(_), Self::Numeric(_)) => Ordering::Greater,
            (Self::AlphaNumeric(a), Self::AlphaNumeric(b)) => a.cmp(b),
        }
    }
}

impl PartialOrd for PreReleaseIdent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemVer {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub prerelease: Vec<PreReleaseIdent>,
}

impl SemVer {
    pub fn is_zero_core(&self) -> bool {
        self.major == 0 && self.minor == 0 && self.patch == 0
    }
}

impl Ord for SemVer {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (self.prerelease.is_empty(), other.prerelease.is_empty()) {
                (true, true) => Ordering::Equal,
                // Stable release strictly outranks same-core prerelease.
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => self.prerelease.cmp(&other.prerelease),
            })
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Parse a SemVer string such as `1.2.3`, `v1.2.3-rc.1`, or `0.2.0-beta.2+build.9`.
pub fn parse_semver(raw: &str) -> CatResult<SemVer> {
    let trimmed = raw.trim();
    let without_v = trimmed.strip_prefix('v').or_else(|| trimmed.strip_prefix('V')).unwrap_or(trimmed);
    if without_v.is_empty() {
        return Err(CatError::Validation("empty version string".into()));
    }

    // Strip optional `+build` metadata per SemVer 2.0 §10.
    let without_build = without_v.split('+').next().unwrap_or("");
    let (core_part, pre_part) = match without_build.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (without_build, None),
    };

    let core_segments: Vec<&str> = core_part.split('.').collect();
    if core_segments.is_empty() || core_segments.len() > 3 {
        return Err(CatError::Validation(format!("invalid SemVer core: {raw}")));
    }

    let parse_u64 = |s: &str| -> CatResult<u64> {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(CatError::Validation(format!(
                "invalid numeric SemVer component '{s}' in '{raw}'"
            )));
        }
        s.parse::<u64>()
            .map_err(|_| CatError::Validation(format!("SemVer overflow in '{raw}'")))
    };

    let major = parse_u64(core_segments[0])?;
    let minor = if core_segments.len() >= 2 {
        parse_u64(core_segments[1])?
    } else {
        0
    };
    let patch = if core_segments.len() == 3 {
        parse_u64(core_segments[2])?
    } else {
        0
    };

    let mut prerelease = Vec::new();
    if let Some(pre) = pre_part {
        if pre.is_empty() {
            return Err(CatError::Validation(format!(
                "empty prerelease suffix in '{raw}'"
            )));
        }
        for ident in pre.split('.') {
            if ident.is_empty()
                || !ident
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return Err(CatError::Validation(format!(
                    "invalid prerelease identifier '{ident}' in '{raw}'"
                )));
            }
            if ident.bytes().all(|b| b.is_ascii_digit()) {
                let n = ident
                    .parse::<u64>()
                    .map_err(|_| CatError::Validation(format!("prerelease overflow in '{raw}'")))?;
                prerelease.push(PreReleaseIdent::Numeric(n));
            } else {
                prerelease.push(PreReleaseIdent::AlphaNumeric(ident.to_ascii_lowercase()));
            }
        }
    }

    Ok(SemVer {
        major,
        minor,
        patch,
        prerelease,
    })
}

/// Return `Ok(true)` strictly when `remote` is a valid non-zero SemVer greater than `local`.
/// Always rejects `0.0.0` (returns `Err(CatError::Validation)`).
pub fn is_newer_version(remote: &str, local: &str) -> CatResult<bool> {
    let rem = parse_semver(remote)?;
    if rem.is_zero_core() {
        return Err(CatError::Validation(format!(
            "remote release version 0.0.0 is rejected: '{remote}'"
        )));
    }
    let loc = parse_semver(local)?;
    Ok(rem > loc)
}

/// Evaluate whether `latest` is an available update over `current` for the chosen release channel.
///
/// When `include_prerelease` is `false`, any prerelease version (containing a SemVer prerelease
/// identifier after `-`) returns `Ok(false)` while still validating SemVer syntax and rejecting
/// `0.0.0`.
pub fn is_update_available_for_channel(
    latest: &str,
    current: &str,
    include_prerelease: bool,
) -> CatResult<bool> {
    let rem = parse_semver(latest)?;
    if rem.is_zero_core() {
        return Err(CatError::Validation(format!(
            "remote release version 0.0.0 is rejected: '{latest}'"
        )));
    }
    let loc = parse_semver(current)?;
    if !include_prerelease && !rem.prerelease.is_empty() {
        return Ok(false);
    }
    Ok(rem > loc)
}

/// Normalize a raw SemVer string by trimming whitespace and stripping a single leading `v`/`V`,
/// validating with `parse_semver` and rejecting `0.0.0`.
pub fn normalize_semver_version(raw: &str) -> CatResult<String> {
    if raw.chars().any(|c| c.is_control()) {
        return Err(CatError::Validation(format!(
            "version string contains control characters: '{raw}'"
        )));
    }
    let trimmed = raw.trim();
    if trimmed.chars().any(|c| c.is_whitespace()) {
        return Err(CatError::Validation(format!(
            "version string contains invalid whitespace: '{raw}'"
        )));
    }
    if let Some((_, build)) = trimmed.split_once('+') {
        if build.is_empty()
            || !build
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        {
            return Err(CatError::Validation(format!(
                "invalid SemVer build metadata in '{raw}'"
            )));
        }
    }
    let parsed = parse_semver(trimmed)?;
    if parsed.is_zero_core() {
        return Err(CatError::Validation(format!(
            "version 0.0.0 is rejected: '{raw}'"
        )));
    }
    let without_v = trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed);
    Ok(without_v.to_string())
}

/// Return `true` when both `candidate` and `skipped` are valid non-zero SemVer strings
/// and `parse_semver(candidate) <= parse_semver(skipped)`.
/// Returns `false` when `skipped` is `None` or either version is invalid/zero.
pub fn is_version_skipped(candidate: &str, skipped: Option<&str>) -> bool {
    let Some(skipped_raw) = skipped else {
        return false;
    };
    let Ok(cand) = parse_semver(candidate) else {
        return false;
    };
    let Ok(skip) = parse_semver(skipped_raw) else {
        return false;
    };
    if cand.is_zero_core() || skip.is_zero_core() {
        return false;
    }
    cand <= skip
}

/// Truncate `s` to at most `max_bytes` UTF-8 bytes strictly along a character boundary.
pub fn truncate_utf8_bytes(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

const ALLOWED_INSTALLER_SUFFIXES: &[&str] = &[
    ".appimage.tar.gz",
    ".app.tar.gz",
    ".appimage",
    ".exe",
    ".msi",
    ".dmg",
    ".deb",
    ".rpm",
];

const WINDOWS_RESERVED_DEVICE_NAMES: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// Validate that `filename` is a strict single-segment safe installer filename matching
/// the supported desktop installer suffix allowlist (explicitly excluding `.zip`).
pub fn is_supported_installer_filename(filename: &str) -> bool {
    if filename.is_empty() || filename.len() > 255 {
        return false;
    }
    if filename != filename.trim() || filename.ends_with('.') {
        return false;
    }
    if filename.chars().any(|c| {
        c.is_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
    }) {
        return false;
    }
    if filename == "." || filename == ".." || filename.contains("..") {
        return false;
    }

    let mut comps = Path::new(filename).components();
    if !matches!(comps.next(), Some(Component::Normal(_))) || comps.next().is_some() {
        return false;
    }

    let lower = filename.to_ascii_lowercase();
    let stem = lower.split('.').next().unwrap_or("");
    if stem.is_empty() || WINDOWS_RESERVED_DEVICE_NAMES.contains(&stem) {
        return false;
    }
    if lower.ends_with(".zip") {
        return false;
    }

    ALLOWED_INSTALLER_SUFFIXES.iter().any(|suffix| {
        lower
            .strip_suffix(suffix)
            .is_some_and(|prefix| !prefix.is_empty() && !prefix.ends_with('.'))
    })
}

// ============================================================================
// GitHub Releases `latest.json` + `SHA256SUMS.txt` parsing & verification
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatestManifest {
    pub version: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub pub_date: Option<String>,
    #[serde(default)]
    pub sha256sums_url: Option<String>,
    #[serde(default)]
    pub platforms: HashMap<String, PlatformAsset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformAsset {
    pub url: String,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub filename: Option<String>,
}

/// Result of checking GitHub Releases `latest.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCheckResult {
    pub current_version: String,
    pub latest_version: String,
    pub update_available: bool,
    pub notes: String,
    pub pub_date: Option<String>,
    pub manifest: LatestManifest,
}

/// Map an explicit `(os, arch, is_portable)` target description to the `latest.json`
/// platform key emitted by `scripts/release/build_latest_json.mjs`.
///
/// Returns `Some(...)` strictly for the 7 official desktop release combinations and `None`
/// for unsupported `(os, arch)` pairs.
pub fn update_platform_key_for_opt(os: &str, arch: &str, is_portable: bool) -> Option<&'static str> {
    match (os, arch) {
        ("windows", "x86_64") => Some(if is_portable {
            "windows-x86_64-portable"
        } else {
            "windows-x86_64"
        }),
        ("windows", "aarch64") => Some(if is_portable {
            "windows-aarch64-portable"
        } else {
            "windows-aarch64"
        }),
        ("macos", "aarch64") => Some("darwin-aarch64"),
        ("macos", "x86_64") => Some("darwin-x86_64"),
        ("linux", "x86_64") => Some("linux-x86_64"),
        _ => None,
    }
}

/// Return the `latest.json` platform key for the current compile target and packaging mode,
/// or `None` if the current `(OS, ARCH)` is not among the 7 official desktop targets.
pub fn current_update_platform_key_opt(is_portable: bool) -> Option<&'static str> {
    update_platform_key_for_opt(std::env::consts::OS, std::env::consts::ARCH, is_portable)
}

/// Map an explicit `(os, arch, is_portable)` target description to the `latest.json`
/// platform key emitted by `scripts/release/build_latest_json.mjs`.
///
/// Compatibility wrapper over `update_platform_key_for_opt` falling back to `"linux-x86_64"`.
pub fn update_platform_key_for(os: &str, arch: &str, is_portable: bool) -> &'static str {
    update_platform_key_for_opt(os, arch, is_portable).unwrap_or("linux-x86_64")
}

/// Return the `latest.json` platform key for the current compile target and packaging mode.
///
/// Compatibility wrapper over `current_update_platform_key_opt` falling back to `"linux-x86_64"`.
pub fn current_update_platform_key(is_portable: bool) -> &'static str {
    current_update_platform_key_opt(is_portable).unwrap_or("linux-x86_64")
}

/// Parse and validate `latest.json` (verifies SemVer != `0.0.0` and validates every URL against allowlist).
pub fn parse_latest_manifest(json_bytes: &[u8]) -> CatResult<LatestManifest> {
    if json_bytes.len() > MAX_METADATA_BYTES {
        return Err(CatError::Security(format!(
            "latest.json exceeds {MAX_METADATA_BYTES} byte limit"
        )));
    }
    let manifest: LatestManifest = serde_json::from_slice(json_bytes)?;
    let ver = parse_semver(&manifest.version)?;
    if ver.is_zero_core() {
        return Err(CatError::Validation(format!(
            "manifest version 0.0.0 is rejected: '{}'",
            manifest.version
        )));
    }
    if let Some(ref sums_url) = manifest.sha256sums_url {
        validate_https_url(sums_url)?;
    }
    for (plat, asset) in &manifest.platforms {
        validate_https_url(&asset.url).map_err(|e| {
            CatError::Security(format!(
                "manifest platform '{plat}' has disallowed download URL: {e}"
            ))
        })?;
    }
    Ok(manifest)
}

/// Parse a `SHA256SUMS.txt` file into a map of `filename -> lowercase_64_hex_sha256`.
pub fn parse_sha256sums(content: &str) -> CatResult<HashMap<String, String>> {
    if content.len() > MAX_METADATA_BYTES {
        return Err(CatError::Security(format!(
            "SHA256SUMS.txt exceeds {MAX_METADATA_BYTES} byte limit"
        )));
    }
    let mut map = HashMap::new();
    for (idx, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, |c: char| c.is_ascii_whitespace());
        let hash_part = parts.next().unwrap_or("").trim();
        let file_part = parts.next().unwrap_or("").trim();

        if !is_valid_sha256_hex(hash_part) {
            return Err(CatError::Validation(format!(
                "invalid SHA256 digest on line {}: '{}'",
                idx + 1,
                hash_part
            )));
        }
        let clean_name = file_part
            .trim_start_matches('*')
            .trim_start_matches("./")
            .trim();
        if clean_name.is_empty() {
            return Err(CatError::Validation(format!(
                "missing filename on SHA256SUMS line {}",
                idx + 1
            )));
        }
        map.insert(clean_name.to_string(), hash_part.to_ascii_lowercase());
    }
    if map.is_empty() {
        return Err(CatError::Validation(
            "SHA256SUMS.txt contained no valid checksum entries".into(),
        ));
    }
    Ok(map)
}

/// Compute lowercase hex SHA256 digest of an in-memory byte slice.
pub fn compute_sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Compute lowercase hex SHA256 digest of a file using fixed 64 KiB streaming chunks.
pub fn compute_file_sha256_hex(path: &Path) -> CatResult<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Verify `bytes` against an expected 64-char hex SHA256 digest.
pub fn verify_sha256_bytes(bytes: &[u8], expected_hex: &str) -> CatResult<()> {
    let exp = expected_hex.trim().to_ascii_lowercase();
    if !is_valid_sha256_hex(&exp) {
        return Err(CatError::Security(format!(
            "invalid expected SHA256 format: '{expected_hex}'"
        )));
    }
    let actual = compute_sha256_hex(bytes);
    if !constant_time_eq(actual.as_bytes(), exp.as_bytes()) {
        return Err(CatError::Security(format!(
            "SHA256 checksum mismatch (expected {exp}, actual {actual})"
        )));
    }
    Ok(())
}

/// Verify a file on disk against an expected 64-char hex SHA256 digest.
pub fn verify_file_sha256(path: &Path, expected_hex: &str) -> CatResult<()> {
    let exp = expected_hex.trim().to_ascii_lowercase();
    if !is_valid_sha256_hex(&exp) {
        return Err(CatError::Security(format!(
            "invalid expected SHA256 format: '{expected_hex}'"
        )));
    }
    let actual = compute_file_sha256_hex(path)?;
    if !constant_time_eq(actual.as_bytes(), exp.as_bytes()) {
        return Err(CatError::Security(format!(
            "SHA256 checksum mismatch for {} (expected {exp}, actual {actual})",
            path.display()
        )));
    }
    Ok(())
}

/// Resolve the expected SHA256 for `asset` from parsed `SHA256SUMS.txt` (falling back to
/// `asset.sha256` only when no `SHA256SUMS.txt` map is provided; if `sums` is provided it is mandatory).
pub fn resolve_asset_sha256(
    asset: &PlatformAsset,
    sums: Option<&HashMap<String, String>>,
) -> CatResult<String> {
    let derived_filename = asset
        .filename
        .clone()
        .or_else(|| {
            Url::parse(&asset.url)
                .ok()
                .and_then(|u| u.path_segments()?.next_back().map(ToString::to_string))
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_default();

    if let Some(map) = sums {
        if let Some(hash) = map.get(&derived_filename) {
            if let Some(ref inline_hash) = asset.sha256 {
                if !inline_hash.trim().eq_ignore_ascii_case(hash) {
                    return Err(CatError::Security(format!(
                        "SHA256 mismatch between latest.json and SHA256SUMS.txt for '{derived_filename}'"
                    )));
                }
            }
            return Ok(hash.clone());
        }
        // Also try matching by basename in case SHA256SUMS includes a subdirectory path,
        // still enforcing strict cross-check against `asset.sha256`.
        if !derived_filename.is_empty() {
            for (k, v) in map {
                let base = Path::new(k)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");
                if base == derived_filename {
                    if let Some(ref inline_hash) = asset.sha256 {
                        if !inline_hash.trim().eq_ignore_ascii_case(v) {
                            return Err(CatError::Security(format!(
                                "SHA256 mismatch between latest.json and SHA256SUMS.txt for '{derived_filename}'"
                            )));
                        }
                    }
                    return Ok(v.clone());
                }
            }
        }
        return Err(CatError::Security(format!(
            "asset '{derived_filename}' missing from SHA256SUMS.txt"
        )));
    }

    if let Some(ref inline_hash) = asset.sha256 {
        let clean = inline_hash.trim().to_ascii_lowercase();
        if is_valid_sha256_hex(&clean) {
            return Ok(clean);
        }
    }

    Err(CatError::Security(
        "no verified SHA256 digest available for update asset".into(),
    ))
}

fn is_valid_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ============================================================================
// Data preservation allowlist
// ============================================================================

/// Return `true` if `rel_posix` belongs to user-owned state that MUST NEVER be overwritten
/// or deleted during updates (`data/`, `portable.flag`, `*.sqlite*`, `*.db*`, `*.local.*`,
/// `.update_staging`, `.update_backup`, etc.).
pub fn is_preserved_relpath(rel_posix: &str) -> bool {
    let normalized = rel_posix.replace('\\', "/");
    let clean = normalized.trim_matches('/');
    if clean.is_empty() {
        return true;
    }

    let parts: Vec<&str> = clean.split('/').collect();
    let first_low = parts[0].to_ascii_lowercase();
    if PRESERVED_TOP_NAMES.iter().any(|p| *p == first_low) {
        return true;
    }
    if parts
        .iter()
        .any(|seg| PRESERVED_ANY_SEGMENT.contains(&seg.to_ascii_lowercase().as_str()))
    {
        return true;
    }

    let file_low = parts.last().copied().unwrap_or("").to_ascii_lowercase();
    if file_low.contains(".local.") {
        return true;
    }
    if file_low.contains(".sqlite") {
        return true;
    }
    if file_low.ends_with(".db")
        || file_low.contains(".db-")
        || file_low.contains(".db.")
        || file_low.ends_with(".db3")
    {
        return true;
    }
    if file_low.ends_with(".lnk") || file_low.ends_with(".log") || file_low.ends_with(".tmp") {
        return true;
    }

    false
}

// ============================================================================
// Archive validation & extraction (size, entry count, symlink & path checks)
// ============================================================================

#[derive(Debug, Clone)]
pub struct ExtractedArchive {
    pub root_dir: PathBuf,
    pub rel_files: Vec<String>,
    pub total_bytes: u64,
}

/// Validate and safely extract a ZIP archive into `dest_dir`.
///
/// Enforces:
/// - Compressed size `<= 64 MiB` (`MAX_ZIP_BYTES`)
/// - Entry count `<= 1000` (`MAX_ZIP_ENTRIES`)
/// - Declared & actual streamed uncompressed bytes `<= 192 MiB` (`MAX_UNCOMPRESSED_BYTES`)
/// - Rejects POSIX symlinks (`unix_mode & 0o170000 == 0o120000` / `is_symlink()`)
/// - Rejects control characters, absolute paths, parent-dir references, drive prefixes, and root escape
pub fn extract_and_validate_zip(zip_bytes: &[u8], dest_dir: &Path) -> CatResult<ExtractedArchive> {
    if zip_bytes.len() > MAX_ZIP_BYTES {
        return Err(CatError::Security(format!(
            "update ZIP exceeds compressed size cap ({} > {MAX_ZIP_BYTES})",
            zip_bytes.len()
        )));
    }

    let mut archive = ZipArchive::new(Cursor::new(zip_bytes))
        .map_err(|e| CatError::Validation(format!("corrupt or invalid ZIP archive: {e}")))?;

    let mut file_indices: Vec<(usize, String)> = Vec::new();
    let mut entry_count: usize = 0;
    let mut declared_total: u64 = 0;

    // Pass 1: inspect every entry header before writing anything to disk.
    for i in 0..archive.len() {
        entry_count += 1;
        if entry_count > MAX_ZIP_ENTRIES {
            return Err(CatError::Security(format!(
                "update ZIP exceeds maximum entry limit ({MAX_ZIP_ENTRIES})"
            )));
        }

        let entry = archive
            .by_index(i)
            .map_err(|e| CatError::Validation(format!("failed to read ZIP entry #{i}: {e}")))?;

        if let Some(mode) = entry.unix_mode() {
            if (mode & 0o170000) == 0o120000 {
                return Err(CatError::Security(format!(
                    "symlink entry blocked in update archive: '{}'",
                    entry.name()
                )));
            }
        }
        if entry.is_symlink() {
            return Err(CatError::Security(format!(
                "symlink entry blocked in update archive: '{}'",
                entry.name()
            )));
        }

        let raw_name = entry.name();
        let validated_rel = sanitize_and_validate_zip_path(raw_name)?;

        if entry.is_dir() || raw_name.ends_with('/') || raw_name.ends_with('\\') {
            continue;
        }

        declared_total = declared_total
            .checked_add(entry.size())
            .ok_or_else(|| CatError::Security("ZIP uncompressed size overflow".into()))?;
        if declared_total > MAX_UNCOMPRESSED_BYTES {
            return Err(CatError::Security(format!(
                "update ZIP declared uncompressed size exceeds cap ({declared_total} > {MAX_UNCOMPRESSED_BYTES})"
            )));
        }

        file_indices.push((i, validated_rel));
    }

    if file_indices.is_empty() {
        return Err(CatError::Validation(
            "update ZIP archive contains no extractable files".into(),
        ));
    }

    // Strip a single top-level wrapper folder (e.g., `CatCloud-v0.2.0/`) if all files share it,
    // except when that folder is a known runtime subdirectory (`resources`, `bin`, `data`, etc.).
    let top_dirs: HashSet<&str> = file_indices
        .iter()
        .filter_map(|(_, rel)| rel.split_once('/').map(|(top, _)| top))
        .collect();
    let strip_prefix = if top_dirs.len() == 1
        && file_indices.iter().all(|(_, rel)| rel.contains('/'))
    {
        let sole_top = top_dirs.into_iter().next().unwrap_or("");
        let is_reserved_runtime_dir = NON_STRIPPABLE_TOP_DIRS
            .iter()
            .any(|reserved| reserved.eq_ignore_ascii_case(sole_top));
        if sole_top.is_empty() || is_reserved_runtime_dir {
            String::new()
        } else {
            format!("{sole_top}/")
        }
    } else {
        String::new()
    };

    std::fs::create_dir_all(dest_dir)?;
    let canonical_dest = std::fs::canonicalize(dest_dir).unwrap_or_else(|_| dest_dir.to_path_buf());

    let mut actual_total: u64 = 0;
    let mut extracted_files: Vec<String> = Vec::with_capacity(file_indices.len());
    let mut seen_rel: HashSet<String> = HashSet::new();
    let mut buf = [0u8; 64 * 1024];

    // Pass 2: stream-extract with live uncompressed byte cap enforcement.
    for (idx, full_rel) in file_indices {
        let rel = if !strip_prefix.is_empty() {
            full_rel
                .strip_prefix(&strip_prefix)
                .unwrap_or(&full_rel)
                .to_string()
        } else {
            full_rel
        };
        if rel.is_empty() {
            continue;
        }
        // Re-validate stripped relative path.
        let clean_rel = sanitize_and_validate_zip_path(&rel)?;
        if !seen_rel.insert(clean_rel.to_ascii_lowercase()) {
            return Err(CatError::Security(format!(
                "duplicate path detected in update ZIP: '{clean_rel}'"
            )));
        }

        let target_path = canonical_dest.join(rel_posix_to_path(&clean_rel));
        ensure_within_root(&target_path, &canonical_dest)?;
        if let Some(parent) = target_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut entry = archive
            .by_index(idx)
            .map_err(|e| CatError::Validation(format!("ZIP read error on '{clean_rel}': {e}")))?;
        let mut out_file = File::create(&target_path)?;

        loop {
            let n = entry.read(&mut buf).map_err(|e| {
                CatError::Validation(format!("corrupt ZIP stream in '{clean_rel}': {e}"))
            })?;
            if n == 0 {
                break;
            }
            actual_total = actual_total
                .checked_add(n as u64)
                .ok_or_else(|| CatError::Security("ZIP real byte counter overflow".into()))?;
            if actual_total > MAX_UNCOMPRESSED_BYTES {
                drop(out_file);
                let _ = std::fs::remove_file(&target_path);
                return Err(CatError::Security(format!(
                    "update ZIP real uncompressed stream exceeded cap ({actual_total} > {MAX_UNCOMPRESSED_BYTES})"
                )));
            }
            out_file.write_all(&buf[..n])?;
        }
        out_file.flush()?;
        extracted_files.push(clean_rel);
    }

    extracted_files.sort();
    Ok(ExtractedArchive {
        root_dir: canonical_dest,
        rel_files: extracted_files,
        total_bytes: actual_total,
    })
}

fn sanitize_and_validate_zip_path(raw: &str) -> CatResult<String> {
    if raw.is_empty() {
        return Err(CatError::Security("empty path in update ZIP".into()));
    }
    if raw.chars().any(|c| (c as u32) < 32 || c == '\x7f') {
        return Err(CatError::Security(format!(
            "control character blocked in ZIP entry path: {raw:?}"
        )));
    }
    let normalized = raw.replace('\\', "/");
    if normalized.starts_with('/') {
        return Err(CatError::Security(format!(
            "absolute path blocked in update ZIP: '{raw}'"
        )));
    }

    let mut clean_segments = Vec::new();
    for seg in normalized.split('/') {
        if seg.is_empty() {
            continue;
        }
        if seg == "." || seg == ".." {
            return Err(CatError::Security(format!(
                "path traversal blocked in update ZIP: '{raw}'"
            )));
        }
        if seg.contains(':') {
            return Err(CatError::Security(format!(
                "drive prefix or ADS colon blocked in update ZIP: '{raw}'"
            )));
        }
        clean_segments.push(seg);
    }

    if clean_segments.is_empty() {
        if normalized.ends_with('/') {
            return Ok(String::new());
        }
        return Err(CatError::Security(format!(
            "invalid empty path in update ZIP: '{raw}'"
        )));
    }
    Ok(clean_segments.join("/"))
}

fn rel_posix_to_path(rel_posix: &str) -> PathBuf {
    let mut pb = PathBuf::new();
    for seg in rel_posix.split('/') {
        if !seg.is_empty() {
            pb.push(seg);
        }
    }
    pb
}

fn ensure_within_root(target: &Path, canonical_root: &Path) -> CatResult<()> {
    let mut normalized = PathBuf::new();
    for comp in target.components() {
        match comp {
            Component::ParentDir => {
                return Err(CatError::Security(format!(
                    "parent directory escape blocked: {}",
                    target.display()
                )));
            }
            Component::CurDir => {}
            other => normalized.push(other),
        }
    }
    if !normalized.starts_with(canonical_root) {
        return Err(CatError::Security(format!(
            "target path escaped update root: {}",
            target.display()
        )));
    }
    Ok(())
}

// ============================================================================
// Staging for next launch & Windows portable same-volume swap + full rollback
// ============================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum StagedUpdateKind {
    #[default]
    PortableZip,
    InstallerPackage,
}

impl StagedUpdateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PortableZip => "portable_zip",
            Self::InstallerPackage => "installer_package",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagedFileEntry {
    pub rel_path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingUpdateMetadata {
    pub from_version: String,
    pub target_version: String,
    pub archive_sha256: String,
    pub staged_at: String,
    pub files: Vec<StagedFileEntry>,
    #[serde(default)]
    pub kind: StagedUpdateKind,
    #[serde(default)]
    pub installer_rel_path: Option<String>,
    #[serde(default)]
    pub release_notes: String,
    #[serde(default)]
    pub release_url: Option<String>,
    #[serde(default)]
    pub platform_key: Option<String>,
    #[serde(default)]
    pub package_size_bytes: u64,
}

/// Result of safely removing a `.update_staging` directory and reclaiming its disk space.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PurgeStagedOutcome {
    pub removed: bool,
    pub freed_bytes: u64,
}

/// Verified metadata returned after streaming an update artifact to a temporary file on disk.
#[derive(Debug, Clone)]
pub struct DownloadedVerifiedAsset {
    pub target_version: String,
    pub expected_sha256: String,
    pub filename: String,
    pub size_bytes: u64,
    pub release_notes: String,
    pub platform_key: String,
}

/// Outcome of attempting to apply a staged portable update at startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableApplyOutcome {
    pub applied: bool,
    pub from_version: String,
    pub to_version: String,
    pub files_updated: usize,
    pub needs_post_update_cleanup_relaunch: bool,
    pub relaunch_args: Vec<String>,
    pub old_exe_backup_path: Option<PathBuf>,
}

impl PortableApplyOutcome {
    pub fn no_pending() -> Self {
        Self {
            applied: false,
            from_version: String::new(),
            to_version: String::new(),
            files_updated: 0,
            needs_post_update_cleanup_relaunch: false,
            relaunch_args: Vec::new(),
            old_exe_backup_path: None,
        }
    }
}

fn is_symlink_or_reparse(meta: &std::fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return true;
        }
    }
    false
}

fn validate_staging_dir_guard(staging_dir: &Path) -> CatResult<()> {
    let mut comp_count = 0usize;
    for comp in staging_dir.components() {
        if matches!(comp, Component::ParentDir) {
            return Err(CatError::Security(format!(
                "refusing to operate on staging path with parent traversal: {}",
                staging_dir.display()
            )));
        }
        comp_count += 1;
    }
    if comp_count < 2 {
        return Err(CatError::Security(format!(
            "refusing to purge shallow or root staging path: {}",
            staging_dir.display()
        )));
    }
    let last_name = staging_dir
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.to_ascii_lowercase())
        .unwrap_or_default();
    if last_name != ".update_staging" && !last_name.contains("update_staging") {
        return Err(CatError::Security(format!(
            "refusing to purge non-staging directory: {}",
            staging_dir.display()
        )));
    }
    Ok(())
}

fn verify_file_sha256_bounded(
    path: &Path,
    expected_hex: &str,
    max_bytes: u64,
) -> CatResult<u64> {
    let exp = expected_hex.trim().to_ascii_lowercase();
    if !is_valid_sha256_hex(&exp) {
        return Err(CatError::Security(format!(
            "invalid expected SHA256 format: '{expected_hex}'"
        )));
    }
    let mut file = File::open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(CatError::Validation(format!(
            "expected regular file at {}",
            path.display()
        )));
    }
    if meta.len() > max_bytes {
        return Err(CatError::Security(format!(
            "file `{}` exceeds hard size limit ({} > {max_bytes})",
            path.display(),
            meta.len()
        )));
    }
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total = total.checked_add(n as u64).ok_or_else(|| {
            CatError::Security("file size overflow during SHA256 verification".into())
        })?;
        if total > max_bytes {
            return Err(CatError::Security(format!(
                "file `{}` exceeded hard size limit during read ({total} > {max_bytes})",
                path.display()
            )));
        }
        hasher.update(&buf[..n]);
    }
    let actual = hex::encode(hasher.finalize());
    if !constant_time_eq(actual.as_bytes(), exp.as_bytes()) {
        return Err(CatError::Security(format!(
            "SHA256 checksum mismatch for {} (expected {exp}, actual {actual})",
            path.display()
        )));
    }
    Ok(total)
}

fn remove_file_with_retry(path: &Path) -> CatResult<()> {
    let mut last_err = None;
    for attempt in 0..5 {
        clear_readonly(path);
        match std::fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                last_err = Some(e);
                if attempt < 4 {
                    std::thread::sleep(Duration::from_millis(80));
                }
            }
        }
    }
    Err(CatError::Io(last_err.unwrap_or_else(|| {
        std::io::Error::other("failed to remove staged file")
    })))
}

fn remove_dir_with_retry(path: &Path) -> CatResult<()> {
    let mut last_err = None;
    for attempt in 0..5 {
        clear_readonly(path);
        match std::fs::remove_dir(path) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                last_err = Some(e);
                if attempt < 4 {
                    std::thread::sleep(Duration::from_millis(80));
                }
            }
        }
    }
    Err(CatError::Io(last_err.unwrap_or_else(|| {
        std::io::Error::other("failed to remove staged directory")
    })))
}

fn remove_symlink_entry_with_retry(path: &Path, meta: &std::fs::Metadata) -> CatResult<()> {
    let mut last_err = None;
    for attempt in 0..5 {
        let res = if cfg!(target_os = "windows") && meta.is_dir() {
            std::fs::remove_dir(path).or_else(|_| std::fs::remove_file(path))
        } else {
            std::fs::remove_file(path).or_else(|_| std::fs::remove_dir(path))
        };
        match res {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                last_err = Some(e);
                if attempt < 4 {
                    std::thread::sleep(Duration::from_millis(80));
                }
            }
        }
    }
    Err(CatError::Io(last_err.unwrap_or_else(|| {
        std::io::Error::other("failed to remove staged symlink entry")
    })))
}

/// Safely delete a staged update directory and return exact reclaimed bytes.
///
/// Enforces strict anti-accidental-deletion guards:
/// - `staging_dir` must have at least 2 path components, zero `..` segments, and its final
///   component (case-insensitive) must be `.update_staging` or contain `update_staging`.
/// - Refuses when `staging_dir` itself is a symlink/reparse point.
/// - Traverses exclusively via `symlink_metadata` (never following symlinks), clearing readonly
///   attributes and retrying briefly before removing files and directories.
pub fn purge_staged_update(staging_dir: &Path) -> CatResult<PurgeStagedOutcome> {
    validate_staging_dir_guard(staging_dir)?;

    let root_meta = match std::fs::symlink_metadata(staging_dir) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PurgeStagedOutcome {
                removed: false,
                freed_bytes: 0,
            });
        }
        Err(e) => return Err(CatError::Io(e)),
    };

    if is_symlink_or_reparse(&root_meta) {
        return Err(CatError::Security(format!(
            "refusing to purge symlink staging directory: {}",
            staging_dir.display()
        )));
    }

    if !root_meta.is_dir() {
        let freed_bytes = root_meta.len();
        remove_file_with_retry(staging_dir)?;
        return Ok(PurgeStagedOutcome {
            removed: true,
            freed_bytes,
        });
    }

    let mut stack = vec![staging_dir.to_path_buf()];
    let mut dirs_to_remove = Vec::new();
    let mut freed_bytes: u64 = 0;

    while let Some(dir) = stack.pop() {
        clear_readonly(&dir);
        dirs_to_remove.push(dir.clone());
        for entry_res in std::fs::read_dir(&dir)? {
            let entry = entry_res?;
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path)?;
            if is_symlink_or_reparse(&meta) {
                remove_symlink_entry_with_retry(&path, &meta)?;
            } else if meta.is_dir() {
                stack.push(path);
            } else {
                let len = meta.len();
                remove_file_with_retry(&path)?;
                freed_bytes = freed_bytes.saturating_add(len);
            }
        }
    }

    dirs_to_remove.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    for dir in dirs_to_remove {
        remove_dir_with_retry(&dir)?;
    }

    Ok(PurgeStagedOutcome {
        removed: true,
        freed_bytes,
    })
}

/// Verify an update ZIP archive's SHA256, validate SemVer and optional metadata, safely extract
/// it into `staging_dir/payload/`, strip any preserved user data paths, and atomically write
/// `staging_dir/pending_apply.json` for user-confirmed restart application.
#[allow(clippy::too_many_arguments)]
pub fn stage_verified_archive_with_meta(
    zip_bytes: &[u8],
    expected_sha256: &str,
    from_version: &str,
    target_version: &str,
    release_notes: &str,
    release_url: Option<&str>,
    platform_key: Option<&str>,
    staging_dir: &Path,
) -> CatResult<PendingUpdateMetadata> {
    let validated_release_url = match release_url {
        Some(url) => {
            validate_https_url(url)?;
            Some(url.trim().to_string())
        }
        None => None,
    };
    verify_sha256_bytes(zip_bytes, expected_sha256)?;
    if !is_newer_version(target_version, from_version)? {
        return Err(CatError::Validation(format!(
            "target version {target_version} is not newer than current version {from_version}"
        )));
    }

    purge_staged_update(staging_dir)?;
    let payload_dir = staging_dir.join(STAGING_PAYLOAD_DIR);
    let extracted = extract_and_validate_zip(zip_bytes, &payload_dir)?;

    let mut staged_files = Vec::new();
    for rel in extracted.rel_files {
        if is_preserved_relpath(&rel) {
            // Defense-in-depth: strip any user-data path even inside staging payload.
            let skip_path = payload_dir.join(rel_posix_to_path(&rel));
            let _ = std::fs::remove_file(skip_path);
            continue;
        }
        let staged_path = payload_dir.join(rel_posix_to_path(&rel));
        let meta = std::fs::metadata(&staged_path)?;
        let hash = compute_file_sha256_hex(&staged_path)?;
        staged_files.push(StagedFileEntry {
            rel_path: rel,
            sha256: hash,
            size_bytes: meta.len(),
        });
    }

    if staged_files.is_empty() {
        let _ = purge_staged_update(staging_dir);
        return Err(CatError::Validation(
            "update archive contained no applicable program files after allowlist filtering".into(),
        ));
    }

    // Place `version.json` last so it acts as the commit marker.
    if let Some(pos) = staged_files
        .iter()
        .position(|e| e.rel_path.eq_ignore_ascii_case("version.json"))
    {
        let marker = staged_files.remove(pos);
        staged_files.push(marker);
    }

    let metadata = PendingUpdateMetadata {
        from_version: from_version.to_string(),
        target_version: target_version.to_string(),
        archive_sha256: expected_sha256.trim().to_ascii_lowercase(),
        staged_at: Utc::now().to_rfc3339(),
        files: staged_files,
        kind: StagedUpdateKind::PortableZip,
        installer_rel_path: None,
        release_notes: truncate_utf8_bytes(release_notes, MAX_RELEASE_NOTES_BYTES),
        release_url: validated_release_url,
        platform_key: platform_key
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        package_size_bytes: zip_bytes.len() as u64,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&metadata)?;
    AppPaths::atomic_write(&staging_dir.join(PENDING_APPLY_MANIFEST), &manifest_bytes)?;
    Ok(metadata)
}

/// Verify an update ZIP archive's SHA256, validate SemVer, safely extract it into
/// `staging_dir/payload/`, strip any preserved user data paths, and atomically write
/// `staging_dir/pending_apply.json` for next-launch application.
pub fn stage_verified_archive(
    zip_bytes: &[u8],
    expected_sha256: &str,
    from_version: &str,
    target_version: &str,
    staging_dir: &Path,
) -> CatResult<PendingUpdateMetadata> {
    stage_verified_archive_with_meta(
        zip_bytes,
        expected_sha256,
        from_version,
        target_version,
        "",
        None,
        None,
        staging_dir,
    )
}

/// Verify a downloaded desktop installer file on disk and stage it into
/// `staging_dir/installer/<filename>` alongside an atomic `pending_apply.json` manifest.
#[allow(clippy::too_many_arguments)]
pub fn stage_verified_installer_file(
    temp_file_path: &Path,
    expected_sha256: &str,
    filename: &str,
    from_version: &str,
    target_version: &str,
    release_notes: &str,
    release_url: Option<&str>,
    platform_key: Option<&str>,
    staging_dir: &Path,
) -> CatResult<PendingUpdateMetadata> {
    stage_verified_installer_file_with_cap(
        temp_file_path,
        expected_sha256,
        filename,
        from_version,
        target_version,
        release_notes,
        release_url,
        platform_key,
        staging_dir,
        MAX_PACKAGE_BYTES as u64,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn stage_verified_installer_file_with_cap(
    temp_file_path: &Path,
    expected_sha256: &str,
    filename: &str,
    from_version: &str,
    target_version: &str,
    release_notes: &str,
    release_url: Option<&str>,
    platform_key: Option<&str>,
    staging_dir: &Path,
    max_bytes: u64,
) -> CatResult<PendingUpdateMetadata> {
    if !is_supported_installer_filename(filename) {
        return Err(CatError::Security(format!(
            "unsupported or unsafe installer filename: '{filename}'"
        )));
    }
    if !is_newer_version(target_version, from_version)? {
        return Err(CatError::Validation(format!(
            "target version {target_version} is not newer than current version {from_version}"
        )));
    }
    let validated_release_url = match release_url {
        Some(url) => {
            validate_https_url(url)?;
            Some(url.trim().to_string())
        }
        None => None,
    };
    validate_staging_dir_guard(staging_dir)?;

    let temp_meta = std::fs::symlink_metadata(temp_file_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CatError::NotFound(format!(
                "staged installer temp file not found: {}",
                temp_file_path.display()
            ))
        } else {
            CatError::Io(e)
        }
    })?;
    if is_symlink_or_reparse(&temp_meta) {
        return Err(CatError::Security(format!(
            "symlink blocked for installer temp file: {}",
            temp_file_path.display()
        )));
    }
    if !temp_meta.is_file() {
        return Err(CatError::Validation(format!(
            "installer temp path is not a regular file: {}",
            temp_file_path.display()
        )));
    }
    if temp_meta.len() > max_bytes {
        return Err(CatError::Security(format!(
            "installer package exceeds size cap ({} > {max_bytes})",
            temp_meta.len()
        )));
    }

    let size_bytes = verify_file_sha256_bounded(temp_file_path, expected_sha256, max_bytes)?;

    let canonical_temp =
        std::fs::canonicalize(temp_file_path).unwrap_or_else(|_| temp_file_path.to_path_buf());
    if let Ok(canonical_staging) = std::fs::canonicalize(staging_dir) {
        if canonical_temp.starts_with(&canonical_staging) {
            return Err(CatError::Validation(
                "temp installer path must not reside inside staging_dir".into(),
            ));
        }
    }

    purge_staged_update(staging_dir)?;
    let installer_dir = staging_dir.join(STAGING_INSTALLER_DIR);
    std::fs::create_dir_all(&installer_dir)?;
    let dst_path = installer_dir.join(filename);

    if std::fs::rename(temp_file_path, &dst_path).is_err() {
        // Cross-volume fallback: copy, re-verify checksum on destination, then clean up source.
        if let Err(copy_err) = std::fs::copy(temp_file_path, &dst_path) {
            let _ = purge_staged_update(staging_dir);
            return Err(CatError::Io(copy_err));
        }
        if let Err(verify_err) = verify_file_sha256_bounded(&dst_path, expected_sha256, max_bytes) {
            let _ = purge_staged_update(staging_dir);
            return Err(verify_err);
        }
        let _ = std::fs::remove_file(temp_file_path);
    }

    #[cfg(unix)]
    {
        if filename.to_ascii_lowercase().ends_with(".appimage") {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&dst_path)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&dst_path, perms)?;
        }
    }

    let expected_lower = expected_sha256.trim().to_ascii_lowercase();
    let installer_rel = format!("{STAGING_INSTALLER_DIR}/{filename}");
    let metadata = PendingUpdateMetadata {
        from_version: from_version.to_string(),
        target_version: target_version.to_string(),
        archive_sha256: expected_lower.clone(),
        staged_at: Utc::now().to_rfc3339(),
        files: vec![StagedFileEntry {
            rel_path: installer_rel.clone(),
            sha256: expected_lower,
            size_bytes,
        }],
        kind: StagedUpdateKind::InstallerPackage,
        installer_rel_path: Some(installer_rel),
        release_notes: truncate_utf8_bytes(release_notes, MAX_RELEASE_NOTES_BYTES),
        release_url: validated_release_url,
        platform_key: platform_key
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        package_size_bytes: size_bytes,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&metadata)?;
    AppPaths::atomic_write(&staging_dir.join(PENDING_APPLY_MANIFEST), &manifest_bytes)?;
    Ok(metadata)
}

fn read_metadata_file_bounded(path: &Path) -> CatResult<Vec<u8>> {
    let file = File::open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CatError::NotFound(format!("update metadata file not found: {}", path.display()))
        } else {
            CatError::Io(e)
        }
    })?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(CatError::Validation(format!(
            "update metadata path is not a file: {}",
            path.display()
        )));
    }
    if meta.len() > MAX_METADATA_BYTES as u64 {
        return Err(CatError::Security(format!(
            "update metadata file `{}` exceeds {MAX_METADATA_BYTES} byte limit",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity((meta.len() as usize).min(64 * 1024));
    let mut limited = file.take(MAX_METADATA_BYTES as u64 + 1);
    limited.read_to_end(&mut bytes)?;
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(CatError::Security(format!(
            "update metadata file `{}` exceeded {MAX_METADATA_BYTES} byte limit",
            path.display()
        )));
    }
    Ok(bytes)
}

/// Strictly verify the integrity of a staged update inside `staging_dir` for both
/// `PortableZip` and `InstallerPackage` payloads.
///
/// Validates:
/// - `staging_dir` and `pending_apply.json` exist and are non-symlinks
/// - `target_version` is a valid non-zero SemVer and optional `release_url` passes `validate_https_url`
/// - `PortableZip`: `payload/` is a non-symlink directory and every declared relative path is
///   safe, non-preserved, non-duplicate, has zero symlink/reparse ancestor directories, resolves
///   strictly within `canonicalize(payload/)`, is a non-symlink regular file, and matches its
///   recorded SHA-256 digest (backfilling `package_size_bytes` from `files` when reading legacy manifests)
/// - `InstallerPackage`: `installer/` is a non-symlink directory, `installer_rel_path` matches
///   `installer/<safe_supported_filename>`, the file is a regular non-symlink `<= MAX_PACKAGE_BYTES`,
///   `files.len() == 1` with matching `rel_path`, `sha256`, and `size_bytes`, `package_size_bytes`
///   is either `0` (backfilled) or equals actual size, and the computed SHA-256 matches `archive_sha256`.
pub fn verify_staged_payload_integrity(staging_dir: &Path) -> CatResult<PendingUpdateMetadata> {
    let staging_meta = std::fs::symlink_metadata(staging_dir).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CatError::NotFound(format!(
                "staged update directory not found: {}",
                staging_dir.display()
            ))
        } else {
            CatError::Io(e)
        }
    })?;
    if is_symlink_or_reparse(&staging_meta) {
        return Err(CatError::Security(format!(
            "symlink blocked for staged update directory: {}",
            staging_dir.display()
        )));
    }
    if !staging_meta.is_dir() {
        return Err(CatError::Validation(format!(
            "staged update path is not a directory: {}",
            staging_dir.display()
        )));
    }

    let manifest_path = staging_dir.join(PENDING_APPLY_MANIFEST);
    let manifest_sym_meta = std::fs::symlink_metadata(&manifest_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CatError::NotFound(format!(
                "update metadata file not found: {}",
                manifest_path.display()
            ))
        } else {
            CatError::Io(e)
        }
    })?;
    if is_symlink_or_reparse(&manifest_sym_meta) {
        return Err(CatError::Security(format!(
            "symlink blocked for staged update manifest: {}",
            manifest_path.display()
        )));
    }

    let manifest_bytes = read_metadata_file_bounded(&manifest_path)?;
    let mut pending: PendingUpdateMetadata = serde_json::from_slice(&manifest_bytes)?;
    let parsed_ver = parse_semver(&pending.target_version)?;
    if parsed_ver.is_zero_core() {
        return Err(CatError::Validation(format!(
            "staged target version 0.0.0 is rejected: '{}'",
            pending.target_version
        )));
    }
    if let Some(ref url) = pending.release_url {
        validate_https_url(url)?;
    }

    match pending.kind {
        StagedUpdateKind::PortableZip => {
            if pending.files.is_empty() {
                return Err(CatError::Validation(
                    "pending_apply.json contains no files to apply".into(),
                ));
            }

            let payload_dir = staging_dir.join(STAGING_PAYLOAD_DIR);
            let payload_meta = std::fs::symlink_metadata(&payload_dir).map_err(|_| {
                CatError::Validation(format!(
                    "staged update payload directory missing: {}",
                    payload_dir.display()
                ))
            })?;
            if is_symlink_or_reparse(&payload_meta) {
                return Err(CatError::Security(format!(
                    "symlink blocked for staged payload directory: {}",
                    payload_dir.display()
                )));
            }
            if !payload_meta.is_dir() {
                return Err(CatError::Validation(format!(
                    "staged update payload directory missing: {}",
                    payload_dir.display()
                )));
            }
            let canonical_payload = std::fs::canonicalize(&payload_dir)?;

            let mut seen_rel: HashSet<String> = HashSet::with_capacity(pending.files.len());
            for entry in &pending.files {
                let clean_rel = sanitize_and_validate_zip_path(&entry.rel_path)?;
                if clean_rel.is_empty() {
                    return Err(CatError::Security(
                        "staged update manifest contains empty relative path".into(),
                    ));
                }
                if is_preserved_relpath(&clean_rel) {
                    return Err(CatError::Security(format!(
                        "staged update manifest references preserved user path: '{clean_rel}'"
                    )));
                }
                if !seen_rel.insert(clean_rel.to_ascii_lowercase()) {
                    return Err(CatError::Security(format!(
                        "duplicate file entry in staged update manifest: '{clean_rel}'"
                    )));
                }

                // Walk every relative ancestor directory segment via `symlink_metadata` to block
                // intermediate symlink/reparse directory redirection out of `payload/`.
                let segments: Vec<&str> = clean_rel.split('/').collect();
                if segments.len() > 1 {
                    let mut ancestor_path = canonical_payload.clone();
                    for &seg in &segments[..segments.len() - 1] {
                        ancestor_path.push(seg);
                        let ancestor_meta =
                            std::fs::symlink_metadata(&ancestor_path).map_err(|_| {
                                CatError::Validation(format!(
                                    "staged update file missing: '{clean_rel}'"
                                ))
                            })?;
                        if is_symlink_or_reparse(&ancestor_meta) {
                            return Err(CatError::Security(format!(
                                "symlink ancestor directory blocked in staged update payload: '{clean_rel}'"
                            )));
                        }
                        if !ancestor_meta.is_dir() {
                            return Err(CatError::Validation(format!(
                                "staged update ancestor path is not a directory: '{clean_rel}'"
                            )));
                        }
                    }
                }

                let staged_file = canonical_payload.join(rel_posix_to_path(&clean_rel));
                ensure_within_root(&staged_file, &canonical_payload)?;
                let sym_meta = std::fs::symlink_metadata(&staged_file).map_err(|_| {
                    CatError::Validation(format!("staged update file missing: '{clean_rel}'"))
                })?;
                if is_symlink_or_reparse(&sym_meta) {
                    return Err(CatError::Security(format!(
                        "symlink blocked in staged update payload: '{clean_rel}'"
                    )));
                }
                if !sym_meta.is_file() {
                    return Err(CatError::Validation(format!(
                        "staged update file missing: '{clean_rel}'"
                    )));
                }
                let canonical_staged = std::fs::canonicalize(&staged_file)?;
                ensure_within_root(&canonical_staged, &canonical_payload)?;
                if canonical_staged == canonical_payload {
                    return Err(CatError::Security(format!(
                        "staged update payload file escaped payload directory: '{clean_rel}'"
                    )));
                }
                verify_file_sha256(&canonical_staged, &entry.sha256)?;
            }

            if pending.package_size_bytes == 0 {
                pending.package_size_bytes = pending
                    .files
                    .iter()
                    .fold(0u64, |acc, f| acc.saturating_add(f.size_bytes));
            }
        }
        StagedUpdateKind::InstallerPackage => {
            let installer_dir = staging_dir.join(STAGING_INSTALLER_DIR);
            let installer_dir_meta = std::fs::symlink_metadata(&installer_dir).map_err(|_| {
                CatError::Validation(format!(
                    "staged installer directory missing: {}",
                    installer_dir.display()
                ))
            })?;
            if is_symlink_or_reparse(&installer_dir_meta) {
                return Err(CatError::Security(format!(
                    "symlink blocked for staged installer directory: {}",
                    installer_dir.display()
                )));
            }
            if !installer_dir_meta.is_dir() {
                return Err(CatError::Validation(format!(
                    "staged installer directory missing: {}",
                    installer_dir.display()
                )));
            }

            let rel = pending.installer_rel_path.as_deref().ok_or_else(|| {
                CatError::Validation(
                    "installer_rel_path is required for installer_package staging".into(),
                )
            })?;
            let Some(safe_name) = rel.strip_prefix("installer/") else {
                return Err(CatError::Security(format!(
                    "invalid installer_rel_path outside installer/: '{rel}'"
                )));
            };
            if !is_supported_installer_filename(safe_name) {
                return Err(CatError::Security(format!(
                    "unsupported or unsafe staged installer filename: '{safe_name}'"
                )));
            }

            let canonical_installer_dir =
                std::fs::canonicalize(&installer_dir).unwrap_or_else(|_| installer_dir.clone());
            let installer_path = canonical_installer_dir.join(safe_name);
            ensure_within_root(&installer_path, &canonical_installer_dir)?;

            let sym_meta = std::fs::symlink_metadata(&installer_path).map_err(|_| {
                CatError::Validation(format!("staged installer file missing: '{rel}'"))
            })?;
            if is_symlink_or_reparse(&sym_meta) {
                return Err(CatError::Security(format!(
                    "symlink blocked for staged installer file: '{rel}'"
                )));
            }
            if !sym_meta.is_file() {
                return Err(CatError::Validation(format!(
                    "staged installer path is not a regular file: '{rel}'"
                )));
            }
            if sym_meta.len() > MAX_PACKAGE_BYTES as u64 {
                return Err(CatError::Security(format!(
                    "staged installer file exceeds size cap ({} > {MAX_PACKAGE_BYTES})",
                    sym_meta.len()
                )));
            }

            let actual_size = verify_file_sha256_bounded(
                &installer_path,
                &pending.archive_sha256,
                MAX_PACKAGE_BYTES as u64,
            )?;

            if pending.files.len() != 1 {
                return Err(CatError::Security(format!(
                    "staged installer manifest must contain exactly 1 file entry (got {})",
                    pending.files.len()
                )));
            }
            let entry = &pending.files[0];
            if entry.rel_path != rel {
                return Err(CatError::Security(format!(
                    "staged installer files[0].rel_path ('{}') does not match installer_rel_path ('{rel}')",
                    entry.rel_path
                )));
            }
            let entry_sha = entry.sha256.trim().to_ascii_lowercase();
            let archive_sha = pending.archive_sha256.trim().to_ascii_lowercase();
            if !is_valid_sha256_hex(&entry_sha)
                || !constant_time_eq(entry_sha.as_bytes(), archive_sha.as_bytes())
            {
                return Err(CatError::Security(
                    "staged installer files[0].sha256 disagrees with archive_sha256".into(),
                ));
            }
            if entry.size_bytes != actual_size {
                return Err(CatError::Security(format!(
                    "staged installer files[0].size_bytes ({}) does not match actual file size ({actual_size})",
                    entry.size_bytes
                )));
            }

            if pending.package_size_bytes == 0 {
                pending.package_size_bytes = actual_size;
            } else if pending.package_size_bytes != actual_size {
                return Err(CatError::Security(format!(
                    "staged installer package_size_bytes ({}) does not match actual file size ({actual_size})",
                    pending.package_size_bytes
                )));
            }
        }
    }

    Ok(pending)
}

/// Read-only check for a verified staged portable update inside `staging_dir`.
///
/// Returns `Some(PendingUpdateMetadata)` only when `verify_staged_payload_integrity` succeeds
/// completely; returns `None` if no update is staged or if the staged payload is corrupt.
pub fn read_pending_staged_update(staging_dir: &Path) -> Option<PendingUpdateMetadata> {
    verify_staged_payload_integrity(staging_dir).ok()
}

/// Apply a previously verified & staged portable update at next startup:
/// 1. Checks anti-downgrade (`is_newer_version(target, current_version)`) and full staged
///    SHA256 integrity before touching `app_root`; automatically purges stale or corrupt
///    `staging_dir` directories to prevent deadlocked "ready" loops.
/// 2. If the running executable (`current_exe_path`) is among the updated files, performs a
///    same-volume rename of the live `.exe` to `backup_dir/<exe>.<old_ver>.old`, then atomically
///    renames the staged replacement into place and requests a `--post-update-cleanup` relaunch.
/// 3. Backs up every replaced file into `backup_dir/` prior to replacement.
/// 4. On ANY failure at ANY step, performs a complete reverse rollback from `backup_dir/` while
///    leaving `data/`, `portable.flag`, `*.sqlite*`, `*.db*`, and `*.local.*` 100% untouched.
pub fn apply_staged_portable_update(
    app_root: &Path,
    current_exe_path: &Path,
    staging_dir: &Path,
    backup_dir: &Path,
) -> CatResult<PortableApplyOutcome> {
    apply_staged_portable_update_internal(
        app_root,
        current_exe_path,
        staging_dir,
        backup_dir,
        env!("CARGO_PKG_VERSION"),
        None,
    )
}

/// Apply a staged portable update evaluated against an explicit `current_version`.
pub fn apply_staged_portable_update_for_version(
    app_root: &Path,
    current_exe_path: &Path,
    staging_dir: &Path,
    backup_dir: &Path,
    current_version: &str,
) -> CatResult<PortableApplyOutcome> {
    apply_staged_portable_update_internal(
        app_root,
        current_exe_path,
        staging_dir,
        backup_dir,
        current_version,
        None,
    )
}

/// Clean up `.old` binaries and stale files inside `.update_backup/` after the updated process
/// relaunches with `--post-update-cleanup`.
pub fn run_post_update_cleanup(backup_dir: &Path) -> CatResult<usize> {
    if !backup_dir.exists() {
        return Ok(0);
    }
    let mut removed = 0usize;
    let mut stack = vec![backup_dir.to_path_buf()];
    let mut dirs_to_prune = Vec::new();

    while let Some(dir) = stack.pop() {
        dirs_to_prune.push(dir.clone());
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                // Retry briefly in case the exiting old process just closed its image section.
                for attempt in 0..5 {
                    clear_readonly(&path);
                    match std::fs::remove_file(&path) {
                        Ok(()) => {
                            removed += 1;
                            break;
                        }
                        Err(_) if attempt < 4 => {
                            std::thread::sleep(Duration::from_millis(120));
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    }

    dirs_to_prune.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    for d in dirs_to_prune {
        let _ = std::fs::remove_dir(&d);
    }
    Ok(removed)
}

type FaultHook<'a> = &'a dyn Fn(&str) -> CatResult<()>;

fn apply_staged_portable_update_internal(
    app_root: &Path,
    current_exe_path: &Path,
    staging_dir: &Path,
    backup_dir: &Path,
    current_version: &str,
    fault_hook: Option<FaultHook<'_>>,
) -> CatResult<PortableApplyOutcome> {
    let staging_meta = match std::fs::symlink_metadata(staging_dir) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PortableApplyOutcome::no_pending());
        }
        Err(e) => return Err(CatError::Io(e)),
    };
    if is_symlink_or_reparse(&staging_meta) {
        return Err(CatError::Security(format!(
            "symlink blocked for staged update directory: {}",
            staging_dir.display()
        )));
    }
    if !staging_meta.is_dir() {
        return Ok(PortableApplyOutcome::no_pending());
    }

    let manifest_path = staging_dir.join(PENDING_APPLY_MANIFEST);
    let manifest_meta = match std::fs::symlink_metadata(&manifest_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PortableApplyOutcome::no_pending());
        }
        Err(e) => return Err(CatError::Io(e)),
    };
    if is_symlink_or_reparse(&manifest_meta) {
        return Err(CatError::Security(format!(
            "symlink blocked for staged update manifest: {}",
            manifest_path.display()
        )));
    }
    if !manifest_meta.is_file() {
        return Ok(PortableApplyOutcome::no_pending());
    }

    let manifest_bytes = match read_metadata_file_bounded(&manifest_path) {
        Ok(b) => b,
        Err(err) => {
            tracing::warn!(
                staging_dir = %staging_dir.display(),
                "removing unreadable staged update directory: {err}"
            );
            let _ = purge_staged_update(staging_dir);
            return Err(err);
        }
    };
    let parsed_pending: PendingUpdateMetadata = match serde_json::from_slice(&manifest_bytes) {
        Ok(p) => p,
        Err(err) => {
            tracing::warn!(
                staging_dir = %staging_dir.display(),
                "removing corrupt staged update manifest: {err}"
            );
            let _ = purge_staged_update(staging_dir);
            return Err(CatError::Json(err));
        }
    };

    // Pre-flight step 0: strictly refuse non-portable (installer) payloads without deleting
    // staging_dir or touching app_root.
    if parsed_pending.kind != StagedUpdateKind::PortableZip {
        return Err(CatError::Validation(
            "staged update is an installer package, not a portable ZIP".into(),
        ));
    }

    // Pre-flight step 1: enforce anti-downgrade before touching any payload or app file.
    match is_newer_version(&parsed_pending.target_version, current_version) {
        Ok(true) => {}
        Ok(false) => {
            tracing::info!(
                current_version = %current_version,
                staged_version = %parsed_pending.target_version,
                staging_dir = %staging_dir.display(),
                "staged portable update is not newer than current version; cleaning up stale staging dir"
            );
            let _ = purge_staged_update(staging_dir);
            return Ok(PortableApplyOutcome::no_pending());
        }
        Err(err) => {
            tracing::warn!(
                current_version = %current_version,
                staged_version = %parsed_pending.target_version,
                staging_dir = %staging_dir.display(),
                "staged portable update has invalid version; cleaning up staging dir: {err}"
            );
            let _ = purge_staged_update(staging_dir);
            return Err(err);
        }
    }

    // Pre-flight step 2: verify full staged payload existence, paths, and SHA-256 digests.
    // On any missing file or checksum mismatch, remove `staging_dir` so startup/UI never
    // deadlocks in a false "ready" state.
    let pending = match verify_staged_payload_integrity(staging_dir) {
        Ok(p) => p,
        Err(err) => {
            tracing::warn!(
                staging_dir = %staging_dir.display(),
                "staged portable update integrity check failed; removing corrupt staging dir: {err}"
            );
            let _ = purge_staged_update(staging_dir);
            return Err(err);
        }
    };

    let payload_dir = staging_dir.join(STAGING_PAYLOAD_DIR);
    std::fs::create_dir_all(app_root)?;
    let canonical_root = std::fs::canonicalize(app_root).unwrap_or_else(|_| app_root.to_path_buf());
    let canonical_payload =
        std::fs::canonicalize(&payload_dir).unwrap_or_else(|_| payload_dir.clone());
    let canonical_exe = std::fs::canonicalize(current_exe_path)
        .unwrap_or_else(|_| current_exe_path.to_path_buf());

    // Pre-flight step 3: verify target destinations inside `app_root` for directory collisions.
    let mut applicable: Vec<&StagedFileEntry> = Vec::with_capacity(pending.files.len());
    for entry in &pending.files {
        let clean_rel = sanitize_and_validate_zip_path(&entry.rel_path)?;
        if is_preserved_relpath(&clean_rel) {
            continue;
        }
        let dst_file = canonical_root.join(rel_posix_to_path(&clean_rel));
        ensure_within_root(&dst_file, &canonical_root)?;
        if dst_file.is_dir() {
            return Err(CatError::Validation(format!(
                "cannot replace existing directory with update file: '{clean_rel}'"
            )));
        }
        applicable.push(entry);
    }

    if applicable.is_empty() {
        let _ = purge_staged_update(staging_dir);
        return Err(CatError::Validation(
            "no applicable files remain after safety verification".into(),
        ));
    }

    if backup_dir.exists() {
        let _ = std::fs::remove_dir_all(backup_dir);
    }
    std::fs::create_dir_all(backup_dir)?;

    let mut replaced_files: Vec<PathBuf> = Vec::new();
    let mut created_files: Vec<PathBuf> = Vec::new();
    let mut created_dirs: Vec<PathBuf> = Vec::new();
    let mut swapped_live_exe: Option<(PathBuf, PathBuf)> = None; // (live_dst, backup_old_path)
    let mut updated_count: usize = 0;

    let apply_result: CatResult<()> = (|| {
        for entry in &applicable {
            let rel_path = rel_posix_to_path(&entry.rel_path);
            let src = canonical_payload.join(&rel_path);
            let dst = canonical_root.join(&rel_path);

            if let Some(hook) = fault_hook {
                hook(&entry.rel_path)?;
            }

            // Track any newly created parent directories for spotless rollback.
            if let Some(parent) = dst.parent() {
                if !parent.exists() {
                    let mut cur = parent.to_path_buf();
                    let mut to_track = Vec::new();
                    while cur != canonical_root && !cur.exists() {
                        to_track.push(cur.clone());
                        match cur.parent() {
                            Some(p) => cur = p.to_path_buf(),
                            None => break,
                        }
                    }
                    std::fs::create_dir_all(parent)?;
                    created_dirs.extend(to_track);
                }
            }

            let is_running_exe = paths_refer_to_same_target(&dst, &canonical_exe);

            if is_running_exe && dst.is_file() {
                // Windows portable live-exe swap:
                // Rename running `<exe>` on the same volume into `.update_backup/<exe>.<old_ver>.old`,
                // then atomically move the staged replacement into `<exe>`.
                let exe_name = dst
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("CatCloud.exe");
                let safe_old_ver = sanitize_version_for_filename(&pending.from_version);
                let old_backup_path = backup_dir.join(format!("{exe_name}.{safe_old_ver}.old"));
                if let Some(bp) = old_backup_path.parent() {
                    std::fs::create_dir_all(bp)?;
                }
                rename_with_retry(&dst, &old_backup_path)?;
                swapped_live_exe = Some((dst.clone(), old_backup_path));

                move_or_atomic_place(&src, &dst)?;
                updated_count += 1;
                continue;
            }

            let existed_before = dst.is_file();
            if existed_before {
                let bak = backup_dir.join(&rel_path);
                if let Some(bp) = bak.parent() {
                    std::fs::create_dir_all(bp)?;
                }
                std::fs::copy(&dst, &bak)?;
            }

            move_or_atomic_place_with_orphan_dir(&src, &dst, Some(backup_dir))?;
            if existed_before {
                replaced_files.push(rel_path.clone());
            } else {
                created_files.push(rel_path.clone());
            }
            updated_count += 1;
        }
        Ok(())
    })();

    if let Err(apply_err) = apply_result {
        let mut rollback_errors: Vec<String> = Vec::new();

        // 1. Delete newly created files in reverse order.
        for rel in created_files.iter().rev() {
            let target = canonical_root.join(rel);
            if target.exists() {
                clear_readonly(&target);
                if let Err(e) = std::fs::remove_file(&target) {
                    rollback_errors.push(format!("remove {}: {e}", rel.display()));
                }
            }
        }

        // 2. Restore swapped live executable if it was moved.
        if let Some((live_dst, old_bak)) = swapped_live_exe.take() {
            if live_dst.exists() {
                clear_readonly(&live_dst);
                if let Err(e) = std::fs::remove_file(&live_dst) {
                    rollback_errors.push(format!("remove new exe {}: {e}", live_dst.display()));
                }
            }
            if old_bak.is_file() {
                if let Err(e) = rename_with_retry(&old_bak, &live_dst) {
                    rollback_errors.push(format!("restore live exe {}: {e}", live_dst.display()));
                }
            }
        }

        // 3. Restore all replaced files from backup_dir in reverse order.
        for rel in replaced_files.iter().rev() {
            let bak = backup_dir.join(rel);
            let dst = canonical_root.join(rel);
            if bak.is_file() {
                if let Err(e) = copy_atomic_replace_with_orphan_dir(&bak, &dst, Some(backup_dir)) {
                    rollback_errors.push(format!("restore {}: {e}", rel.display()));
                }
            }
        }

        // 4. Remove newly created empty directories deepest-first.
        created_dirs.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
        for d in created_dirs {
            if d.is_dir() {
                let _ = std::fs::remove_dir(&d);
            }
        }

        if rollback_errors.is_empty() {
            let _ = std::fs::remove_dir_all(backup_dir);
            return Err(CatError::Process(format!(
                "portable update failed and was cleanly rolled back: {apply_err}"
            )));
        } else {
            return Err(CatError::Process(format!(
                "portable update failed ({apply_err}); partial rollback kept backup at {}: {}",
                backup_dir.display(),
                rollback_errors.join("; ")
            )));
        }
    }

    // Success: clean staging directory so the next launch will not re-apply.
    let _ = purge_staged_update(staging_dir);

    let (needs_relaunch, relaunch_args, old_exe_backup_path) =
        if let Some((_, old_bak)) = swapped_live_exe {
            // Keep `.update_backup/<exe>.<old_ver>.old` until the new process runs cleanup,
            // because Windows locks deletion of the currently mapped image until old PID exits.
            (
                true,
                vec!["--restarting".into(), "--post-update-cleanup".into()],
                Some(old_bak),
            )
        } else {
            let _ = std::fs::remove_dir_all(backup_dir);
            (false, Vec::new(), None)
        };

    Ok(PortableApplyOutcome {
        applied: true,
        from_version: pending.from_version,
        to_version: pending.target_version,
        files_updated: updated_count,
        needs_post_update_cleanup_relaunch: needs_relaunch,
        relaunch_args,
        old_exe_backup_path,
    })
}

fn paths_refer_to_same_target(a: &Path, b: &Path) -> bool {
    let ca = std::fs::canonicalize(a).unwrap_or_else(|_| a.to_path_buf());
    let cb = std::fs::canonicalize(b).unwrap_or_else(|_| b.to_path_buf());
    #[cfg(target_os = "windows")]
    {
        ca.to_string_lossy()
            .eq_ignore_ascii_case(&cb.to_string_lossy())
    }
    #[cfg(not(target_os = "windows"))]
    {
        ca == cb
    }
}

fn sanitize_version_for_filename(ver: &str) -> String {
    let cleaned: String = ver
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "prev".into()
    } else {
        cleaned
    }
}

fn clear_readonly(path: &Path) {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if is_symlink_or_reparse(&meta) {
            return;
        }
        let mut perms = meta.permissions();
        if perms.readonly() {
            perms.set_readonly(false);
            let _ = std::fs::set_permissions(path, perms);
        }
    }
}

fn rename_with_retry(src: &Path, dst: &Path) -> CatResult<()> {
    let mut last_err = None;
    for attempt in 0..3 {
        if dst.exists() {
            clear_readonly(dst);
        }
        match std::fs::rename(src, dst) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_err = Some(e);
                if attempt < 2 {
                    std::thread::sleep(Duration::from_millis(150));
                }
            }
        }
    }
    Err(CatError::Io(last_err.unwrap()))
}

/// Place `src` into `dst` atomically: writes a sibling temp file in `dst.parent()` (same volume)
/// and performs an atomic replace with retry, avoiding cross-device EXDEV issues and preserving
static SWAP_BAK_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// `src` intact in case an upstream rollback inspects staging.
fn move_or_atomic_place_with_orphan_dir(
    src: &Path,
    dst: &Path,
    orphan_dir: Option<&Path>,
) -> CatResult<()> {
    copy_atomic_replace_with_orphan_dir(src, dst, orphan_dir)
}

fn move_or_atomic_place(src: &Path, dst: &Path) -> CatResult<()> {
    copy_atomic_replace_with_orphan_dir(src, dst, None)
}

fn copy_atomic_replace_with_orphan_dir(
    src: &Path,
    dst: &Path,
    orphan_dir: Option<&Path>,
) -> CatResult<()> {
    let pid = std::process::id();
    let seq = SWAP_BAK_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let name = dst
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("update_file");
    let tmp = dst.with_file_name(format!("{name}.upd.{pid}.{seq}.tmp"));
    let copy_res = std::fs::copy(src, &tmp);
    if let Err(e) = copy_res {
        let _ = std::fs::remove_file(&tmp);
        return Err(CatError::Io(e));
    }

    #[cfg(target_os = "windows")]
    {
        const WIN_SWAP_MAX_ATTEMPTS: usize = 8;
        let swap_bak = dst.with_file_name(format!("{name}.swap_bak.{pid}.{seq}"));
        let mut last_err = None;

        for attempt in 0..WIN_SWAP_MAX_ATTEMPTS {
            let mut moved_existing = false;
            if dst.exists() {
                clear_readonly(dst);
                if swap_bak.exists() {
                    clear_readonly(&swap_bak);
                    let _ = std::fs::remove_file(&swap_bak);
                }
                match std::fs::rename(dst, &swap_bak) {
                    Ok(()) => moved_existing = true,
                    Err(bak_err) => {
                        last_err = Some(bak_err);
                        if attempt + 1 < WIN_SWAP_MAX_ATTEMPTS {
                            std::thread::sleep(Duration::from_millis(150));
                            continue;
                        }
                        let _ = std::fs::remove_file(&tmp);
                        return Err(CatError::Io(last_err.unwrap()));
                    }
                }
            }

            match std::fs::rename(&tmp, dst) {
                Ok(()) => {
                    if moved_existing {
                        clear_readonly(&swap_bak);
                        if std::fs::remove_file(&swap_bak).is_err() {
                            // If a running sibling PE (e.g. `cli/catcloud.exe`) prevents immediate
                            // deletion, relocate it into `.update_backup/` so `--post-update-cleanup`
                            // sweeps it cleanly instead of leaving an orphan next to the live binary.
                            if let Some(dir) = orphan_dir {
                                let _ = std::fs::create_dir_all(dir);
                                let deferred = dir.join(format!("{name}.{pid}.{seq}.old"));
                                let _ = std::fs::rename(&swap_bak, &deferred);
                            }
                        }
                    }
                    return Ok(());
                }
                Err(rename_err) => {
                    // Restore previous destination immediately to eliminate any missing-file window.
                    if moved_existing {
                        let _ = std::fs::rename(&swap_bak, dst);
                    }
                    last_err = Some(rename_err);
                    if attempt + 1 < WIN_SWAP_MAX_ATTEMPTS {
                        std::thread::sleep(Duration::from_millis(150));
                    }
                }
            }
        }

        let _ = std::fs::remove_file(&tmp);
        Err(CatError::Io(last_err.unwrap()))
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = orphan_dir;
        let mut last_err = None;
        for attempt in 0..3 {
            match std::fs::rename(&tmp, dst) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    last_err = Some(e);
                    if attempt < 2 {
                        std::thread::sleep(Duration::from_millis(150));
                    }
                }
            }
        }

        let _ = std::fs::remove_file(&tmp);
        Err(CatError::Io(last_err.unwrap()))
    }
}

// ============================================================================
// High-level async Updater facade (GitHub Releases latest.json + SHA256SUMS)
// ============================================================================

/// Validate that `raw` is a clean GitHub repository slug in strict `owner/repo` format
/// with two non-empty segments, zero whitespace/control characters, and no path traversal.
pub fn validate_github_repo_slug(raw: &str) -> CatResult<String> {
    if raw.chars().any(|c| c.is_control()) {
        return Err(CatError::Validation(
            "GitHub repository slug contains control characters".into(),
        ));
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().any(|c| c.is_whitespace()) {
        return Err(CatError::Validation(format!(
            "invalid GitHub repository slug '{raw}': expected `owner/repo` without whitespace"
        )));
    }
    if trimmed.starts_with('/') || trimmed.ends_with('/') || trimmed.contains('\\') {
        return Err(CatError::Validation(format!(
            "invalid GitHub repository slug '{raw}': expected `owner/repo`"
        )));
    }
    let mut parts = trimmed.split('/');
    let Some(owner) = parts.next() else {
        return Err(CatError::Validation(format!(
            "invalid GitHub repository slug '{raw}': missing owner"
        )));
    };
    let Some(repo) = parts.next() else {
        return Err(CatError::Validation(format!(
            "invalid GitHub repository slug '{raw}': expected `owner/repo`"
        )));
    };
    if parts.next().is_some() {
        return Err(CatError::Validation(format!(
            "invalid GitHub repository slug '{raw}': too many path segments"
        )));
    }
    if owner.is_empty()
        || owner.len() > 39
        || owner.starts_with('-')
        || owner.ends_with('-')
        || !owner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(CatError::Validation(format!(
            "invalid GitHub repository owner '{owner}' in '{raw}'"
        )));
    }
    if repo.is_empty()
        || repo.len() > 100
        || repo == "."
        || repo == ".."
        || repo.contains("..")
        || !repo
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(CatError::Validation(format!(
            "invalid GitHub repository name '{repo}' in '{raw}'"
        )));
    }
    Ok(format!("{owner}/{repo}"))
}

#[derive(Debug, Clone)]
pub struct Updater {
    repo: String,
    current_version: String,
    client: reqwest::Client,
    download_client: reqwest::Client,
}

impl Updater {
    pub fn new(repo: impl Into<String>, current_version: impl Into<String>) -> CatResult<Self> {
        let raw_repo = repo.into();
        let validated_repo = validate_github_repo_slug(&raw_repo)?;
        let client = build_safe_http_client(METADATA_REQUEST_TIMEOUT)?;
        let download_client = build_safe_http_client_with_timeouts(
            PACKAGE_CONNECT_TIMEOUT,
            PACKAGE_DOWNLOAD_TIMEOUT,
        )?;
        Ok(Self {
            repo: validated_repo,
            current_version: current_version.into(),
            client,
            download_client,
        })
    }

    pub fn default_latest_json_url(&self) -> String {
        format!(
            "https://github.com/{}/releases/latest/download/latest.json",
            self.repo.trim_matches('/')
        )
    }

    pub fn default_sha256sums_url(&self) -> String {
        format!(
            "https://github.com/{}/releases/latest/download/SHA256SUMS.txt",
            self.repo.trim_matches('/')
        )
    }

    /// Fetch and validate `latest.json` over the allowlisted HTTPS client.
    pub async fn check_latest(&self, latest_json_url: Option<&str>) -> CatResult<UpdateCheckResult> {
        let url = latest_json_url
            .map(ToString::to_string)
            .unwrap_or_else(|| self.default_latest_json_url());
        let bytes = Self::fetch_bytes_limited(
            &self.client,
            &url,
            MAX_METADATA_BYTES,
            METADATA_REQUEST_TIMEOUT,
        )
        .await?;
        let manifest = parse_latest_manifest(&bytes)?;
        let update_available = is_newer_version(&manifest.version, &self.current_version)?;

        Ok(UpdateCheckResult {
            current_version: self.current_version.clone(),
            latest_version: manifest.version.clone(),
            update_available,
            notes: manifest.notes.clone(),
            pub_date: manifest.pub_date.clone(),
            manifest,
        })
    }

    /// Download the platform asset + `SHA256SUMS.txt`, enforce SHA256 verification, and stage it
    /// into `staging_dir` for safe next-launch application.
    pub async fn download_and_stage(
        &self,
        manifest: &LatestManifest,
        platform_key: &str,
        staging_dir: &Path,
    ) -> CatResult<PendingUpdateMetadata> {
        let asset = manifest.platforms.get(platform_key).ok_or_else(|| {
            CatError::NotFound(format!(
                "no update artifact found for platform '{platform_key}'"
            ))
        })?;

        validate_https_url(&asset.url)?;
        let sums_url = manifest
            .sha256sums_url
            .clone()
            .unwrap_or_else(|| self.default_sha256sums_url());
        let sums_bytes = Self::fetch_bytes_limited(
            &self.client,
            &sums_url,
            MAX_METADATA_BYTES,
            METADATA_REQUEST_TIMEOUT,
        )
        .await?;
        let sums_text = String::from_utf8(sums_bytes)
            .map_err(|e| CatError::Validation(format!("SHA256SUMS.txt is not valid UTF-8: {e}")))?;
        let sums_map = parse_sha256sums(&sums_text)?;
        let expected_sha256 = resolve_asset_sha256(asset, Some(&sums_map))?;

        let archive_bytes = Self::fetch_bytes_limited(
            &self.download_client,
            &asset.url,
            MAX_PACKAGE_BYTES,
            PACKAGE_DOWNLOAD_TIMEOUT,
        )
        .await?;

        stage_verified_archive_with_meta(
            &archive_bytes,
            &expected_sha256,
            &self.current_version,
            &manifest.version,
            &manifest.notes,
            None,
            Some(platform_key),
            staging_dir,
        )
    }

    /// Stream-download a platform asset directly to `temp_file_path` using 64 KiB buffered writes
    /// while updating SHA-256 on the fly (zero full-package RAM buffering).
    ///
    /// Enforces:
    /// - Strict HTTPS allowlist on both `SHA256SUMS.txt` and asset URL (including final redirect)
    /// - Mandatory `SHA256SUMS.txt` cross-check via `resolve_asset_sha256`
    /// - Hard `MAX_PACKAGE_BYTES` (64 MiB) limit on both `Content-Length` and actual streamed bytes
    /// - Immediate cancellation via `cancel_rx` (`tokio::select!` on chunk loop), removing
    ///   `temp_file_path` on cancellation, timeout, size overflow, or checksum mismatch.
    pub async fn download_asset_to_temp_file(
        &self,
        manifest: &LatestManifest,
        platform_key: &str,
        temp_file_path: &Path,
        mut cancel_rx: Option<tokio::sync::watch::Receiver<bool>>,
    ) -> CatResult<DownloadedVerifiedAsset> {
        if cancel_rx.as_ref().is_some_and(|rx| *rx.borrow()) {
            return Err(CatError::Validation("update download cancelled".into()));
        }

        let ver = parse_semver(&manifest.version)?;
        if ver.is_zero_core() {
            return Err(CatError::Validation(format!(
                "manifest version 0.0.0 is rejected: '{}'",
                manifest.version
            )));
        }

        let asset = manifest.platforms.get(platform_key).ok_or_else(|| {
            CatError::NotFound(format!(
                "no update artifact found for platform '{platform_key}'"
            ))
        })?;
        validate_https_url(&asset.url)?;

        let filename = asset
            .filename
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .or_else(|| {
                Url::parse(&asset.url)
                    .ok()
                    .and_then(|u| u.path_segments()?.next_back().map(ToString::to_string))
                    .filter(|s| !s.is_empty())
            })
            .ok_or_else(|| {
                CatError::Validation(format!(
                    "unable to determine filename for platform '{platform_key}'"
                ))
            })?;

        if let Ok(existing_meta) = std::fs::symlink_metadata(temp_file_path) {
            if is_symlink_or_reparse(&existing_meta) {
                return Err(CatError::Security(format!(
                    "refusing to write update download into symlink path: {}",
                    temp_file_path.display()
                )));
            }
        }

        let sums_url = manifest
            .sha256sums_url
            .clone()
            .unwrap_or_else(|| self.default_sha256sums_url());
        validate_https_url(&sums_url)?;

        let sums_bytes = tokio::select! {
            biased;
            _ = wait_for_cancel(&mut cancel_rx) => {
                return Err(CatError::Validation("update download cancelled".into()));
            }
            res = Self::fetch_bytes_limited(
                &self.client,
                &sums_url,
                MAX_METADATA_BYTES,
                METADATA_REQUEST_TIMEOUT,
            ) => res?,
        };
        let sums_text = String::from_utf8(sums_bytes)
            .map_err(|e| CatError::Validation(format!("SHA256SUMS.txt is not valid UTF-8: {e}")))?;
        let sums_map = parse_sha256sums(&sums_text)?;
        let expected_sha256 = resolve_asset_sha256(asset, Some(&sums_map))?
            .trim()
            .to_ascii_lowercase();
        if !is_valid_sha256_hex(&expected_sha256) {
            return Err(CatError::Security(format!(
                "invalid expected SHA256 digest for '{filename}'"
            )));
        }

        if let Some(parent) = temp_file_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let result = match tokio::time::timeout(
            PACKAGE_DOWNLOAD_TIMEOUT,
            Self::stream_download_verified_to_file(
                &self.download_client,
                &asset.url,
                &filename,
                &expected_sha256,
                temp_file_path,
                &mut cancel_rx,
            ),
        )
        .await
        {
            Ok(inner_res) => inner_res,
            Err(_) => Err(CatError::Process(format!(
                "update download timed out after {}s for {}",
                PACKAGE_DOWNLOAD_TIMEOUT.as_secs(),
                asset.url
            ))),
        };

        match result {
            Ok(size_bytes) => Ok(DownloadedVerifiedAsset {
                target_version: manifest.version.clone(),
                expected_sha256,
                filename,
                size_bytes,
                release_notes: truncate_utf8_bytes(&manifest.notes, MAX_RELEASE_NOTES_BYTES),
                platform_key: platform_key.to_string(),
            }),
            Err(err) => {
                if let Err(e) = tokio::fs::remove_file(temp_file_path).await {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        let _ = tokio::fs::remove_file(temp_file_path).await;
                    }
                }
                Err(err)
            }
        }
    }

    async fn stream_download_verified_to_file(
        client: &reqwest::Client,
        url: &str,
        filename: &str,
        expected_sha256: &str,
        temp_file_path: &Path,
        cancel_rx: &mut Option<tokio::sync::watch::Receiver<bool>>,
    ) -> CatResult<u64> {
        let resp = tokio::select! {
            biased;
            _ = wait_for_cancel(cancel_rx) => {
                return Err(CatError::Validation("update download cancelled".into()));
            }
            send_res = client.get(url).send() => {
                send_res.map_err(CatError::Http)?
            }
        };

        // Secondary validation on the final resolved URL after all redirects.
        validate_https_url(resp.url().as_str())?;

        Self::stream_response_verified_to_file_with_cap(
            resp,
            filename,
            expected_sha256,
            temp_file_path,
            MAX_PACKAGE_BYTES as u64,
            cancel_rx,
        )
        .await
    }

    /// Stream an HTTP response body directly to `temp_file_path` in 64 KiB buffered chunks while
    /// enforcing `max_bytes`, cooperative cancellation, and streaming SHA-256 verification.
    /// Removes `temp_file_path` on any error after dropping the file handle.
    pub(crate) async fn stream_response_verified_to_file_with_cap(
        resp: reqwest::Response,
        filename: &str,
        expected_sha256: &str,
        temp_file_path: &Path,
        max_bytes: u64,
        cancel_rx: &mut Option<tokio::sync::watch::Receiver<bool>>,
    ) -> CatResult<u64> {
        let res = Self::stream_response_body_to_file_with_cap(
            resp,
            filename,
            expected_sha256,
            temp_file_path,
            max_bytes,
            cancel_rx,
        )
        .await;
        if res.is_err() {
            if let Err(e) = tokio::fs::remove_file(temp_file_path).await {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    let _ = tokio::fs::remove_file(temp_file_path).await;
                }
            }
        }
        res
    }

    async fn stream_response_body_to_file_with_cap(
        mut resp: reqwest::Response,
        filename: &str,
        expected_sha256: &str,
        temp_file_path: &Path,
        max_bytes: u64,
        cancel_rx: &mut Option<tokio::sync::watch::Receiver<bool>>,
    ) -> CatResult<u64> {
        use tokio::io::AsyncWriteExt as _;

        let expected_lower = expected_sha256.trim().to_ascii_lowercase();
        if !is_valid_sha256_hex(&expected_lower) {
            return Err(CatError::Security(format!(
                "invalid expected SHA256 digest for '{filename}'"
            )));
        }

        if !resp.status().is_success() {
            return Err(CatError::Process(format!(
                "update server returned HTTP {} for {}",
                resp.status(),
                resp.url()
            )));
        }

        if let Some(cl) = resp.content_length() {
            if cl > max_bytes {
                return Err(CatError::Security(format!(
                    "update response Content-Length {cl} exceeds limit {max_bytes}"
                )));
            }
        }

        let file = tokio::fs::File::create(temp_file_path).await?;
        let mut writer = tokio::io::BufWriter::with_capacity(64 * 1024, file);
        let mut hasher = Sha256::new();
        let mut total_bytes: u64 = 0;

        loop {
            let next_chunk = tokio::select! {
                biased;
                _ = wait_for_cancel(cancel_rx) => {
                    return Err(CatError::Validation("update download cancelled".into()));
                }
                chunk_res = resp.chunk() => {
                    chunk_res.map_err(CatError::Http)?
                }
            };
            let Some(chunk) = next_chunk else {
                break;
            };
            let new_total = total_bytes
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| CatError::Security("update download size overflow".into()))?;
            if new_total > max_bytes {
                return Err(CatError::Security(format!(
                    "update download stream exceeded hard limit ({max_bytes} bytes)"
                )));
            }
            hasher.update(&chunk);
            writer.write_all(&chunk).await?;
            total_bytes = new_total;
        }

        if cancel_rx.as_ref().is_some_and(|rx| *rx.borrow()) {
            return Err(CatError::Validation("update download cancelled".into()));
        }

        writer.flush().await?;
        let file = writer.into_inner();
        file.sync_all().await?;
        drop(file);

        let actual_sha256 = hex::encode(hasher.finalize());
        if !constant_time_eq(actual_sha256.as_bytes(), expected_lower.as_bytes()) {
            return Err(CatError::Security(format!(
                "SHA256 checksum mismatch for downloaded update asset '{filename}' (expected {expected_lower}, actual {actual_sha256})"
            )));
        }

        Ok(total_bytes)
    }

    async fn fetch_bytes_limited(
        client: &reqwest::Client,
        url: &str,
        max_bytes: usize,
        total_timeout: Duration,
    ) -> CatResult<Vec<u8>> {
        validate_https_url(url)?;

        let fut = async {
            let mut resp = client
                .get(url)
                .send()
                .await
                .map_err(CatError::Http)?;

            // Secondary validation on the final resolved URL after all redirects.
            validate_https_url(resp.url().as_str())?;

            if !resp.status().is_success() {
                return Err(CatError::Process(format!(
                    "update server returned HTTP {} for {}",
                    resp.status(),
                    resp.url()
                )));
            }

            if let Some(cl) = resp.content_length() {
                if cl > max_bytes as u64 {
                    return Err(CatError::Security(format!(
                        "update response Content-Length {cl} exceeds limit {max_bytes}"
                    )));
                }
            }

            let mut out = Vec::new();
            while let Some(chunk) = resp.chunk().await.map_err(CatError::Http)? {
                if out.len().saturating_add(chunk.len()) > max_bytes {
                    return Err(CatError::Security(format!(
                        "update download stream exceeded hard limit ({max_bytes} bytes)"
                    )));
                }
                out.extend_from_slice(&chunk);
            }
            Ok(out)
        };

        tokio::time::timeout(total_timeout, fut).await.map_err(|_| {
            CatError::Process(format!(
                "update download timed out after {}s for {url}",
                total_timeout.as_secs()
            ))
        })?
    }
}

async fn wait_for_cancel(cancel_rx: &mut Option<tokio::sync::watch::Receiver<bool>>) {
    match cancel_rx {
        Some(rx) => {
            let already_cancelled = *rx.borrow();
            if already_cancelled {
                return;
            }
            loop {
                if rx.changed().await.is_err() {
                    // Sender dropped without cancelling; pend forever so download continues.
                    std::future::pending::<()>().await;
                }
                let cancelled = *rx.borrow();
                if cancelled {
                    return;
                }
            }
        }
        None => std::future::pending::<()>().await,
    }
}

// ============================================================================
// Unit tests (versioning, URL allowlist, checksums, archive limits, rollback)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use zip::CompressionMethod;
    use zip::write::SimpleFileOptions;

    fn make_temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "catcloud-upd-test-{label}-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn build_zip(entries: &[(&str, &[u8], Option<u32>)]) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut zw = zip::ZipWriter::new(&mut buf);
            for (name, content, unix_mode) in entries {
                let mut opts =
                    SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
                if let Some(m) = unix_mode {
                    opts = opts.unix_permissions(*m);
                }
                zw.start_file(*name, opts).unwrap();
                zw.write_all(content).unwrap();
            }
            zw.finish().unwrap();
        }
        buf.into_inner()
    }

    #[test]
    fn https_allowlist_and_redirect_validation() {
        for host in ALLOWED_UPDATE_HOSTS {
            assert!(
                validate_https_url(&format!(
                    "https://{host}/JuryBu/CatCloud/releases/latest.json"
                ))
                .is_ok()
            );
            assert!(validate_https_url(&format!("https://{host}:443/asset.zip")).is_ok());
        }

        // Reject non-HTTPS, non-443 ports, userinfo, and non-allowlisted hosts.
        assert!(validate_https_url("http://github.com/JuryBu/CatCloud").is_err());
        assert!(validate_https_url("https://github.com:8443/JuryBu/CatCloud").is_err());
        assert!(validate_https_url("https://user:token@github.com/JuryBu/CatCloud").is_err());
        assert!(validate_https_url("https://example.invalid/latest.json").is_err());
        assert!(validate_https_url("https://mirror.example.org/latest.json").is_err());
        assert!(validate_https_url("https://github.com./latest.json").is_err());

        // Per-hop redirect checks: up to 5 hops on allowlisted HTTPS hosts are permitted.
        for hop in 1..=MAX_REDIRECT_HOPS {
            assert!(
                validate_redirect_hop(hop, "https://objects.githubusercontent.com/pkg.zip").is_ok()
            );
        }
        assert!(
            validate_redirect_hop(
                MAX_REDIRECT_HOPS + 1,
                "https://objects.githubusercontent.com/pkg.zip"
            )
            .is_err()
        );
        assert!(validate_redirect_hop(2, "https://example.invalid/pkg.zip").is_err());
        assert!(validate_redirect_hop(1, "http://objects.githubusercontent.com/pkg.zip").is_err());
    }

    #[test]
    fn semver_ordering_and_zero_rejection() {
        // Stable releases sort strictly above same-core prereleases.
        assert!(is_newer_version("1.0.0", "1.0.0-rc.1").unwrap());
        assert!(!is_newer_version("1.0.0-rc.1", "1.0.0").unwrap());
        assert!(is_newer_version("v1.2.0", "1.1.9").unwrap());
        assert!(is_newer_version("1.0.0-beta.11", "1.0.0-beta.2").unwrap());
        assert!(is_newer_version("1.0.0-rc.1", "1.0.0-beta.9").unwrap());
        assert!(!is_newer_version("1.0.0", "1.0.0").unwrap());

        // 0.0.0 is rejected as an invalid target version.
        assert!(is_newer_version("0.0.0", "0.0.0").is_err());
        assert!(is_newer_version("v0.0.0", "0.1.0").is_err());
        assert!(is_newer_version("0.0.0-alpha.1", "0.1.0").is_err());
    }

    #[test]
    fn sha256sums_parsing_and_checksum_verification() {
        let payload = b"catcloud-release-package-sample";
        let good_hash = compute_sha256_hex(payload);
        let sums_txt = format!(
            "# CatCloud Release Checksums\n\
             {good_hash}  CatCloud-0.2.0-windows-x64-portable.zip\n\
             {good_hash} *./catcloud-0.2.0-linux-x64.tar.gz\n"
        );

        let map = parse_sha256sums(&sums_txt).unwrap();
        assert_eq!(
            map.get("CatCloud-0.2.0-windows-x64-portable.zip")
                .map(String::as_str),
            Some(good_hash.as_str())
        );
        assert_eq!(
            map.get("catcloud-0.2.0-linux-x64.tar.gz").map(String::as_str),
            Some(good_hash.as_str())
        );

        verify_sha256_bytes(payload, &good_hash).unwrap();

        // Any content mismatch fails verification.
        let mut modified = payload.to_vec();
        modified[0] ^= 0x01;
        assert!(verify_sha256_bytes(&modified, &good_hash).is_err());

        // Malformed checksum lines fail parsing.
        assert!(parse_sha256sums("invalid-digest  file.zip\n").is_err());
    }

    #[test]
    fn archive_validation_enforces_format_and_entry_limits() {
        let tmp = make_temp_dir("zip-limits");

        // Normal archive extracts cleanly and strips a single top-level wrapper folder.
        let valid_zip = build_zip(&[
            ("CatCloud-0.2.0/CatCloud.exe", b"BIN_BYTES", None),
            ("CatCloud-0.2.0/version.json", br#"{"version":"0.2.0"}"#, None),
        ]);
        let extracted = extract_and_validate_zip(&valid_zip, &tmp.join("ok")).unwrap();
        assert_eq!(
            extracted.rel_files,
            vec!["CatCloud.exe".to_string(), "version.json".to_string()]
        );

        // Corrupt bytes fail cleanly.
        assert!(extract_and_validate_zip(b"not a valid zip stream", &tmp.join("bad")).is_err());

        // Relative path normalization rejects non-relative or invalid entry names.
        assert!(sanitize_and_validate_zip_path("resources/bin/mihomo.exe").is_ok());
        assert!(sanitize_and_validate_zip_path("../outside.txt").is_err());
        assert!(sanitize_and_validate_zip_path("/absolute.txt").is_err());
        assert!(sanitize_and_validate_zip_path("bad\x07name.txt").is_err());

        // Entry count above MAX_ZIP_ENTRIES (1000) is rejected.
        let many_names: Vec<String> = (0..1005).map(|i| format!("entry_{i:04}.txt")).collect();
        let many_entries: Vec<(&str, &[u8], Option<u32>)> = many_names
            .iter()
            .map(|s| (s.as_str(), b"x".as_slice(), None))
            .collect();
        let zip_many = build_zip(&many_entries);
        assert!(extract_and_validate_zip(&zip_many, &tmp.join("too-many")).is_err());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn preserved_data_allowlist_protects_user_files() {
        for protected in [
            "data/config.json",
            "data/catcloud.sqlite",
            "data/catcloud.sqlite-wal",
            "data/themes/wallpaper.webp",
            "portable.flag",
            "catcloud.sqlite",
            "catcloud.sqlite-shm",
            "state.db",
            "state.db-wal",
            "override.local.yaml",
            "rules.local.json",
            ".update_staging/pending_apply.json",
            ".update_backup/CatCloud.exe.0.1.0.old",
        ] {
            assert!(
                is_preserved_relpath(protected),
                "expected '{protected}' to be preserved"
            );
        }

        for managed in [
            "CatCloud.exe",
            "resources/bin/mihomo.exe",
            "version.json",
            "assets/icon.png",
        ] {
            assert!(
                !is_preserved_relpath(managed),
                "expected '{managed}' to be updatable"
            );
        }
    }

    #[test]
    fn portable_update_rollback_and_cleanup_preserve_user_data() {
        let root = make_temp_dir("portable-rollback");
        let app_root = root.join("app");
        let data_dir = app_root.join("data");
        let staging_dir = app_root.join(".update_staging");
        let backup_dir = app_root.join(".update_backup");
        std::fs::create_dir_all(&data_dir).unwrap();

        // Populate existing v0.1.0 program files and preserved user data.
        let exe_path = app_root.join("CatCloud.exe");
        let core_path = app_root.join("resources").join("bin").join("mihomo.exe");
        let ver_path = app_root.join("version.json");
        std::fs::create_dir_all(core_path.parent().unwrap()).unwrap();
        std::fs::write(&exe_path, b"OLD_CATCLOUD_EXE_V010").unwrap();
        std::fs::write(&core_path, b"OLD_MIHOMO_V010").unwrap();
        std::fs::write(&ver_path, br#"{"version":"0.1.0"}"#).unwrap();

        let user_cfg = data_dir.join("config.json");
        let user_db = data_dir.join("catcloud.sqlite");
        let user_wal = data_dir.join("catcloud.sqlite-wal");
        let portable_flag = app_root.join("portable.flag");
        let local_override = app_root.join("custom.local.yaml");
        std::fs::write(&user_cfg, b"USER_CONFIG_DATA").unwrap();
        std::fs::write(&user_db, b"SQLITE_USER_DATA").unwrap();
        std::fs::write(&user_wal, b"SQLITE_WAL_DATA").unwrap();
        std::fs::write(&portable_flag, b"1").unwrap();
        std::fs::write(&local_override, b"LOCAL_RULES").unwrap();

        // Build a v0.2.0 archive that also includes user-data paths to verify allowlist skipping.
        let zip_bytes = build_zip(&[
            ("CatCloud-0.2.0/CatCloud.exe", b"NEW_CATCLOUD_EXE_V020", None),
            (
                "CatCloud-0.2.0/resources/bin/mihomo.exe",
                b"NEW_MIHOMO_V020",
                None,
            ),
            ("CatCloud-0.2.0/new_plugin.dat", b"NEW_EXTRA_FILE", None),
            ("CatCloud-0.2.0/version.json", br#"{"version":"0.2.0"}"#, None),
            ("CatCloud-0.2.0/data/config.json", b"ARCHIVE_DEFAULT_CFG", None),
            ("CatCloud-0.2.0/portable.flag", b"0", None),
        ]);
        let zip_hash = compute_sha256_hex(&zip_bytes);

        let staged = stage_verified_archive(&zip_bytes, &zip_hash, "0.1.0", "0.2.0", &staging_dir)
            .expect("stage valid archive");
        assert!(
            staged
                .files
                .iter()
                .all(|f| !f.rel_path.starts_with("data/") && f.rel_path != "portable.flag")
        );
        assert_eq!(staged.files.last().unwrap().rel_path, "version.json");

        // Simulate a write I/O failure before committing `version.json`.
        let hook = |rel: &str| -> CatResult<()> {
            if rel == "version.json" {
                return Err(CatError::Io(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "simulated I/O failure while applying update",
                )));
            }
            Ok(())
        };
        let res = apply_staged_portable_update_internal(
            &app_root,
            &exe_path,
            &staging_dir,
            &backup_dir,
            "0.1.0",
            Some(&hook),
        );
        assert!(res.is_err(), "I/O failure must trigger rollback");

        // All previous program files are restored and newly created files are removed.
        assert_eq!(std::fs::read(&exe_path).unwrap(), b"OLD_CATCLOUD_EXE_V010");
        assert_eq!(std::fs::read(&core_path).unwrap(), b"OLD_MIHOMO_V010");
        assert_eq!(std::fs::read(&ver_path).unwrap(), br#"{"version":"0.1.0"}"#);
        assert!(!app_root.join("new_plugin.dat").exists());
        assert!(!backup_dir.exists());

        // Preserved user data remains completely intact.
        assert_eq!(std::fs::read(&user_cfg).unwrap(), b"USER_CONFIG_DATA");
        assert_eq!(std::fs::read(&user_db).unwrap(), b"SQLITE_USER_DATA");
        assert_eq!(std::fs::read(&user_wal).unwrap(), b"SQLITE_WAL_DATA");
        assert_eq!(std::fs::read(&portable_flag).unwrap(), b"1");
        assert_eq!(std::fs::read(&local_override).unwrap(), b"LOCAL_RULES");

        // Normal application succeeds, moves old exe to `.old`, and requests `--post-update-cleanup`.
        let outcome =
            apply_staged_portable_update(&app_root, &exe_path, &staging_dir, &backup_dir)
                .expect("clean portable update apply");
        assert!(outcome.applied);
        assert_eq!(outcome.from_version, "0.1.0");
        assert_eq!(outcome.to_version, "0.2.0");
        assert!(outcome.needs_post_update_cleanup_relaunch);
        assert!(outcome
            .relaunch_args
            .contains(&"--post-update-cleanup".to_string()));

        let old_bak = outcome
            .old_exe_backup_path
            .expect("should keep .old exe backup until post-update cleanup");
        assert!(old_bak.is_file());
        assert!(old_bak.to_string_lossy().ends_with("CatCloud.exe.0.1.0.old"));
        assert_eq!(std::fs::read(&exe_path).unwrap(), b"NEW_CATCLOUD_EXE_V020");
        assert_eq!(std::fs::read(&core_path).unwrap(), b"NEW_MIHOMO_V020");
        assert_eq!(std::fs::read(&ver_path).unwrap(), br#"{"version":"0.2.0"}"#);
        assert!(!staging_dir.exists());

        // Preserved user data remains untouched after successful apply.
        assert_eq!(std::fs::read(&user_cfg).unwrap(), b"USER_CONFIG_DATA");
        assert_eq!(std::fs::read(&user_db).unwrap(), b"SQLITE_USER_DATA");
        assert_eq!(std::fs::read(&portable_flag).unwrap(), b"1");

        // Post-update cleanup clears the `.old` backup and backup directory.
        let cleaned = run_post_update_cleanup(&backup_dir).expect("post-update cleanup");
        assert!(cleaned >= 1);
        assert!(!old_bak.exists());
        assert!(!backup_dir.exists());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn modified_staged_file_fails_pre_apply_checksum() {
        let root = make_temp_dir("staged-mismatch");
        let app_root = root.join("app");
        let staging_dir = app_root.join(".update_staging");
        let backup_dir = app_root.join(".update_backup");
        std::fs::create_dir_all(&app_root).unwrap();

        let exe_path = app_root.join("CatCloud.exe");
        std::fs::write(&exe_path, b"ORIGINAL_EXE").unwrap();

        let zip_bytes = build_zip(&[("CatCloud.exe", b"VERIFIED_NEW_EXE", None)]);
        let hash = compute_sha256_hex(&zip_bytes);
        stage_verified_archive(&zip_bytes, &hash, "0.1.0", "0.2.0", &staging_dir).unwrap();

        // Simulate disk corruption in staging prior to apply.
        std::fs::write(
            staging_dir.join(STAGING_PAYLOAD_DIR).join("CatCloud.exe"),
            b"CORRUPTED_STAGED_BYTES",
        )
        .unwrap();

        let err = apply_staged_portable_update(&app_root, &exe_path, &staging_dir, &backup_dir);
        assert!(err.is_err());
        assert_eq!(std::fs::read(&exe_path).unwrap(), b"ORIGINAL_EXE");
        assert!(
            !staging_dir.exists(),
            "corrupt staging_dir must be automatically removed to break false-ready deadlock"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn zip_entry_cap_counts_directories_and_preserves_reserved_top_dirs() {
        let tmp = make_temp_dir("zip-dirs-and-strip");

        // 1. Directory-only spam beyond MAX_ZIP_ENTRIES must be rejected before skipping dirs.
        let mut dir_spam_buf = Cursor::new(Vec::new());
        {
            let mut zw = zip::ZipWriter::new(&mut dir_spam_buf);
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            for i in 0..=MAX_ZIP_ENTRIES {
                zw.add_directory(format!("spam_dir_{i:04}/"), opts).unwrap();
            }
            zw.start_file("ok.txt", opts).unwrap();
            zw.write_all(b"hi").unwrap();
            zw.finish().unwrap();
        }
        assert!(
            extract_and_validate_zip(&dir_spam_buf.into_inner(), &tmp.join("dir-spam")).is_err()
        );

        // 2. A ZIP whose sole top-level directory is a runtime dir (`resources`, `bin`, `assets`)
        //    must NOT strip that directory name.
        let resources_only_zip = build_zip(&[
            ("resources/bin/mihomo.exe", b"MIHOMO_BIN", None),
            ("resources/README.txt", b"DOCS", None),
        ]);
        let extracted_res =
            extract_and_validate_zip(&resources_only_zip, &tmp.join("res-only")).unwrap();
        assert_eq!(
            extracted_res.rel_files,
            vec![
                "resources/README.txt".to_string(),
                "resources/bin/mihomo.exe".to_string()
            ]
        );

        let bin_only_zip = build_zip(&[("bin/mihomo", b"MIHOMO_UNIX", None)]);
        let extracted_bin =
            extract_and_validate_zip(&bin_only_zip, &tmp.join("bin-only")).unwrap();
        assert_eq!(extracted_bin.rel_files, vec!["bin/mihomo".to_string()]);

        // 3. Atomic swap replacement replaces existing destination cleanly without leaving swap_bak.
        let src_file = tmp.join("new_payload.bin");
        let dst_file = tmp.join("target.bin");
        std::fs::write(&src_file, b"NEW_DATA").unwrap();
        std::fs::write(&dst_file, b"OLD_DATA").unwrap();
        copy_atomic_replace_with_orphan_dir(&src_file, &dst_file, None).unwrap();
        assert_eq!(std::fs::read(&dst_file).unwrap(), b"NEW_DATA");
        let leftover_swap = std::fs::read_dir(&tmp)
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| e.file_name().to_string_lossy().contains(".swap_bak."));
        assert!(!leftover_swap, "swap_bak file must be removed after replace");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn platform_keys_pending_staging_and_full_12_platform_manifest_verification() {
        // 1. Platform key mapping aligns strictly with scripts/release/build_latest_json.mjs.
        assert_eq!(
            update_platform_key_for("windows", "x86_64", true),
            "windows-x86_64-portable"
        );
        assert_eq!(
            update_platform_key_for("windows", "x86_64", false),
            "windows-x86_64"
        );
        assert_eq!(
            update_platform_key_for("windows", "aarch64", true),
            "windows-aarch64-portable"
        );
        assert_eq!(
            update_platform_key_for("windows", "aarch64", false),
            "windows-aarch64"
        );
        assert_eq!(
            update_platform_key_for("macos", "aarch64", false),
            "darwin-aarch64"
        );
        assert_eq!(
            update_platform_key_for("macos", "x86_64", false),
            "darwin-x86_64"
        );
        assert_eq!(
            update_platform_key_for("linux", "x86_64", false),
            "linux-x86_64"
        );

        // 2. Realistic 12-platform latest.json + 18-line SHA256SUMS.txt cross-verification.
        let version = "0.2.0";
        let base_url = format!("https://github.com/JuryBu/CatCloud/releases/download/v{version}");
        let platform_assets: [(&str, &str); 12] = [
            (
                "windows-x86_64-portable",
                "CatCloud-0.2.0-windows-x64-portable.zip",
            ),
            (
                "windows-aarch64-portable",
                "CatCloud-0.2.0-windows-arm64-portable.zip",
            ),
            ("windows-x86_64", "CatCloud-0.2.0-windows-x64-setup.exe"),
            ("windows-aarch64", "CatCloud-0.2.0-windows-arm64-setup.exe"),
            ("darwin-aarch64", "CatCloud-0.2.0-macos-aarch64.app.tar.gz"),
            ("darwin-x86_64", "CatCloud-0.2.0-macos-x64.app.tar.gz"),
            (
                "linux-x86_64",
                "CatCloud-0.2.0-linux-x86_64.AppImage.tar.gz",
            ),
            ("windows-x86_64-cli", "catcloud-windows-x86_64.zip"),
            ("windows-aarch64-cli", "catcloud-windows-aarch64.zip"),
            ("darwin-aarch64-cli", "catcloud-macos-aarch64.tar.gz"),
            ("darwin-x86_64-cli", "catcloud-macos-x86_64.tar.gz"),
            ("linux-x86_64-cli", "catcloud-linux-x86_64.tar.gz"),
        ];
        let extra_release_assets: [&str; 6] = [
            "CatCloud-0.2.0-windows-x64.msi",
            "CatCloud-0.2.0-windows-arm64.msi",
            "CatCloud-0.2.0-macos-aarch64.dmg",
            "CatCloud-0.2.0-macos-x64.dmg",
            "CatCloud-0.2.0-linux-x86_64.AppImage",
            "CatCloud-0.2.0-linux-x86_64.deb",
        ];

        let mut platforms_json = serde_json::Map::new();
        let mut sums_lines: Vec<String> = Vec::with_capacity(18);
        let mut expected_by_platform: HashMap<&str, String> = HashMap::new();

        for (idx, (plat_key, filename)) in platform_assets.iter().enumerate() {
            let sha = compute_sha256_hex(format!("artifact:{plat_key}:{filename}").as_bytes());
            expected_by_platform.insert(*plat_key, sha.clone());
            if idx % 2 == 0 {
                sums_lines.push(format!("{sha}  {filename}"));
            } else {
                sums_lines.push(format!("{sha}  release-assets/{filename}"));
            }
            platforms_json.insert(
                (*plat_key).to_string(),
                serde_json::json!({
                    "url": format!("{base_url}/{filename}"),
                    "sha256": sha,
                    "filename": filename,
                }),
            );
        }
        for extra in extra_release_assets {
            let sha = compute_sha256_hex(format!("extra:{extra}").as_bytes());
            sums_lines.push(format!("{sha}  {extra}"));
        }
        assert_eq!(sums_lines.len(), 18);

        let latest_json = serde_json::json!({
            "version": version,
            "notes": "CatCloud v0.2.0 multi-platform release",
            "pub_date": "2026-11-24T00:00:00Z",
            "sha256sums_url": format!("{base_url}/SHA256SUMS.txt"),
            "platforms": serde_json::Value::Object(platforms_json),
        });
        let latest_bytes = serde_json::to_vec_pretty(&latest_json).unwrap();
        let sums_txt = sums_lines.join("\n");

        let manifest = parse_latest_manifest(&latest_bytes).expect("parse 12-platform latest.json");
        assert_eq!(manifest.version, version);
        assert_eq!(manifest.platforms.len(), 12);

        let sums_map = parse_sha256sums(&sums_txt).expect("parse 18-line SHA256SUMS.txt");
        assert_eq!(sums_map.len(), 18);

        for (plat_key, _) in &platform_assets {
            let asset = manifest
                .platforms
                .get(*plat_key)
                .unwrap_or_else(|| panic!("missing platform key {plat_key}"));
            let resolved = resolve_asset_sha256(asset, Some(&sums_map))
                .unwrap_or_else(|e| panic!("resolve sha256 failed for {plat_key}: {e}"));
            assert_eq!(resolved, expected_by_platform[*plat_key]);
        }

        // Current target platform keys must be covered by the 12-platform manifest.
        assert!(
            manifest
                .platforms
                .contains_key(current_update_platform_key(true))
        );
        assert!(
            manifest
                .platforms
                .contains_key(current_update_platform_key(false))
        );

        // 3. `read_pending_staged_update` validates pending_apply.json + payload/ existence.
        let tmp = make_temp_dir("read-pending");
        let staging_dir = tmp.join(".update_staging");
        assert!(read_pending_staged_update(&staging_dir).is_none());

        let zip_bytes = build_zip(&[
            ("CatCloud-0.2.0/CatCloud.exe", b"NEW_EXE_V020", None),
            ("CatCloud-0.2.0/version.json", br#"{"version":"0.2.0"}"#, None),
        ]);
        let zip_hash = compute_sha256_hex(&zip_bytes);
        stage_verified_archive(&zip_bytes, &zip_hash, "0.1.0", "0.2.0", &staging_dir)
            .expect("stage archive");

        let pending = read_pending_staged_update(&staging_dir)
            .expect("pending staged update should be detected");
        assert_eq!(pending.target_version, "0.2.0");
        assert_eq!(pending.archive_sha256, zip_hash);
        assert_eq!(pending.files.len(), 2);

        std::fs::remove_dir_all(staging_dir.join(STAGING_PAYLOAD_DIR)).unwrap();
        assert!(read_pending_staged_update(&staging_dir).is_none());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn platform_key_opt_only_accepts_seven_official_desktop_targets() {
        assert_eq!(
            update_platform_key_for_opt("windows", "x86_64", true),
            Some("windows-x86_64-portable")
        );
        assert_eq!(
            update_platform_key_for_opt("windows", "x86_64", false),
            Some("windows-x86_64")
        );
        assert_eq!(
            update_platform_key_for_opt("windows", "aarch64", true),
            Some("windows-aarch64-portable")
        );
        assert_eq!(
            update_platform_key_for_opt("windows", "aarch64", false),
            Some("windows-aarch64")
        );
        assert_eq!(
            update_platform_key_for_opt("macos", "aarch64", false),
            Some("darwin-aarch64")
        );
        assert_eq!(
            update_platform_key_for_opt("macos", "x86_64", false),
            Some("darwin-x86_64")
        );
        assert_eq!(
            update_platform_key_for_opt("linux", "x86_64", false),
            Some("linux-x86_64")
        );

        // Unsupported OS/arch combinations must return None (never silently misroute).
        assert_eq!(update_platform_key_for_opt("linux", "aarch64", false), None);
        assert_eq!(update_platform_key_for_opt("windows", "x86", true), None);
        assert_eq!(update_platform_key_for_opt("freebsd", "x86_64", false), None);
    }

    #[test]
    fn channel_update_availability_filters_prereleases_unless_opted_in() {
        // Stable-only channel skips prereleases even when core version is higher.
        assert!(!is_update_available_for_channel("0.2.0-rc.1", "0.1.0", false).unwrap());
        assert!(!is_update_available_for_channel("v1.0.0-beta.2", "0.9.0", false).unwrap());
        assert!(is_update_available_for_channel("0.2.0", "0.1.0", false).unwrap());
        assert!(is_update_available_for_channel("0.2.0+build-1", "0.1.0", false).unwrap());

        // Prerelease opt-in channel allows newer prereleases while still rejecting downgrades.
        assert!(is_update_available_for_channel("0.2.0-rc.1", "0.1.0", true).unwrap());
        assert!(!is_update_available_for_channel("0.1.0-rc.1", "0.1.0", true).unwrap());

        // Invalid or 0.0.0 versions are still strictly rejected.
        assert!(is_update_available_for_channel("0.0.0-alpha.1", "0.1.0", false).is_err());
        assert!(is_update_available_for_channel("not-semver", "0.1.0", false).is_err());
    }

    #[test]
    fn updater_new_strictly_validates_github_repo_slug() {
        assert!(Updater::new("JuryBu/CatCloud", "0.1.0").is_ok());
        assert!(Updater::new("org-1/cat_cloud.rs", "0.1.0").is_ok());

        for bad in [
            "",
            "   ",
            "JuryBu",
            "JuryBu/",
            "/CatCloud",
            "a/b/c",
            "../evil/repo",
            "JuryBu/..",
            "JuryBu/.",
            "JuryBu/CatCloud?x=1",
            "JuryBu/CatCloud#frag",
            "JuryBu/Cat Cloud",
            "JuryBu/Cat\nCloud",
            "-bad/repo",
            "bad-/repo",
            "https://github.com/JuryBu/CatCloud",
        ] {
            assert!(
                Updater::new(bad, "0.1.0").is_err(),
                "expected invalid repo slug '{bad}' to be rejected"
            );
        }
    }

    #[test]
    fn verify_staged_integrity_and_apply_auto_clean_downgrade_or_missing_payload() {
        let root = make_temp_dir("integrity-and-downgrade");
        let app_root = root.join("app");
        let staging_dir = app_root.join(".update_staging");
        let backup_dir = app_root.join(".update_backup");
        std::fs::create_dir_all(&app_root).unwrap();

        let exe_path = app_root.join("CatCloud.exe");
        std::fs::write(&exe_path, b"CURRENT_V030_EXE").unwrap();

        let zip_bytes = build_zip(&[
            ("CatCloud.exe", b"STAGED_V020_EXE", None),
            ("version.json", br#"{"version":"0.2.0"}"#, None),
        ]);
        let zip_hash = compute_sha256_hex(&zip_bytes);

        // 1. Healthy staging passes `verify_staged_payload_integrity` and `read_pending_staged_update`.
        stage_verified_archive(&zip_bytes, &zip_hash, "0.1.0", "0.2.0", &staging_dir).unwrap();
        assert!(verify_staged_payload_integrity(&staging_dir).is_ok());
        assert!(read_pending_staged_update(&staging_dir).is_some());

        // 2. Downgrade / same-version staged update (current 0.3.0 vs staged 0.2.0) returns
        //    NoPending (`applied == false`), leaves current exe untouched, and removes `staging_dir`.
        let downgrade_outcome = apply_staged_portable_update_for_version(
            &app_root,
            &exe_path,
            &staging_dir,
            &backup_dir,
            "0.3.0",
        )
        .expect("downgrade staging must safely no-op and clean up");
        assert!(!downgrade_outcome.applied);
        assert_eq!(std::fs::read(&exe_path).unwrap(), b"CURRENT_V030_EXE");
        assert!(
            !staging_dir.exists(),
            "stale/downgrade staging_dir must be deleted automatically"
        );

        // Same version (0.2.0 vs 0.2.0) also cleans up safely.
        stage_verified_archive(&zip_bytes, &zip_hash, "0.1.0", "0.2.0", &staging_dir).unwrap();
        let same_ver_outcome = apply_staged_portable_update_for_version(
            &app_root,
            &exe_path,
            &staging_dir,
            &backup_dir,
            "0.2.0",
        )
        .expect("same-version staging must safely no-op and clean up");
        assert!(!same_ver_outcome.applied);
        assert!(!staging_dir.exists());

        // 3. Missing payload file fails `verify_staged_payload_integrity`, makes
        //    `read_pending_staged_update` return `None`, and causes apply to remove `staging_dir`.
        stage_verified_archive(&zip_bytes, &zip_hash, "0.1.0", "0.2.0", &staging_dir).unwrap();
        std::fs::remove_file(staging_dir.join(STAGING_PAYLOAD_DIR).join("version.json")).unwrap();
        assert!(verify_staged_payload_integrity(&staging_dir).is_err());
        assert!(read_pending_staged_update(&staging_dir).is_none());

        let missing_err = apply_staged_portable_update_for_version(
            &app_root,
            &exe_path,
            &staging_dir,
            &backup_dir,
            "0.1.0",
        );
        assert!(missing_err.is_err());
        assert!(!staging_dir.exists());
        assert_eq!(std::fs::read(&exe_path).unwrap(), b"CURRENT_V030_EXE");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn apply_portable_update_installs_replaces_and_rolls_back_bundled_cli_cleanly() {
        let root = make_temp_dir("portable-cli-bundle");
        let app_root = root.join("app");
        let staging_dir = app_root.join(".update_staging");
        let backup_dir = app_root.join(".update_backup");
        std::fs::create_dir_all(&app_root).unwrap();

        let exe_path = app_root.join("CatCloud.exe");
        let cli_path = app_root.join("cli").join("catcloud.exe");
        let quickstart_path = app_root.join("README-QuickStart.txt");
        let flag_path = app_root.join("portable.flag");
        std::fs::write(&exe_path, b"EXE_V010").unwrap();
        std::fs::write(&flag_path, b"portable").unwrap();

        // 1. First update introduces `cli/catcloud.exe` + `README-QuickStart.txt` inside wrapper folder.
        let v020_zip = build_zip(&[
            ("CatCloud-0.2.0-windows-x64-portable/CatCloud.exe", b"EXE_V020", None),
            (
                "CatCloud-0.2.0-windows-x64-portable/cli/catcloud.exe",
                b"CLI_V020",
                None,
            ),
            (
                "CatCloud-0.2.0-windows-x64-portable/README-QuickStart.txt",
                b"QuickStart v0.2.0",
                None,
            ),
            (
                "CatCloud-0.2.0-windows-x64-portable/portable.flag",
                b"SHOULD_NOT_OVERWRITE",
                None,
            ),
        ]);
        let v020_hash = compute_sha256_hex(&v020_zip);
        stage_verified_archive(&v020_zip, &v020_hash, "0.1.0", "0.2.0", &staging_dir).unwrap();

        let outcome = apply_staged_portable_update_internal(
            &app_root,
            &exe_path,
            &staging_dir,
            &backup_dir,
            "0.1.0",
            None,
        )
        .expect("v0.2.0 portable update introducing cli/ should succeed");
        assert!(outcome.applied);
        assert_eq!(std::fs::read(&exe_path).unwrap(), b"EXE_V020");
        assert_eq!(std::fs::read(&cli_path).unwrap(), b"CLI_V020");
        assert_eq!(std::fs::read(&quickstart_path).unwrap(), b"QuickStart v0.2.0");
        assert_eq!(std::fs::read(&flag_path).unwrap(), b"portable");

        // 2. Subsequent update fails partway after replacing `cli/catcloud.exe`; rollback must
        //    restore `CLI_V020` cleanly without leaving any `.swap_bak` or `.upd.*.tmp` orphans.
        let v030_zip = build_zip(&[
            ("CatCloud-0.3.0-windows-x64-portable/cli/catcloud.exe", b"CLI_V030", None),
            (
                "CatCloud-0.3.0-windows-x64-portable/version.json",
                br#"{"version":"0.3.0"}"#,
                None,
            ),
        ]);
        let v030_hash = compute_sha256_hex(&v030_zip);
        stage_verified_archive(&v030_zip, &v030_hash, "0.2.0", "0.3.0", &staging_dir).unwrap();

        let hook = |rel: &str| {
            if rel == "version.json" {
                Err(CatError::Process("injected failure after cli replace".into()))
            } else {
                Ok(())
            }
        };
        let err = apply_staged_portable_update_internal(
            &app_root,
            &exe_path,
            &staging_dir,
            &backup_dir,
            "0.2.0",
            Some(&hook),
        );
        assert!(err.is_err());
        assert_eq!(
            std::fs::read(&cli_path).unwrap(),
            b"CLI_V020",
            "cli/catcloud.exe must be restored on rollback"
        );
        let cli_entries: Vec<String> = std::fs::read_dir(app_root.join("cli"))
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(
            cli_entries,
            vec!["catcloud.exe".to_string()],
            "cli/ must contain zero swap_bak or tmp orphan files after rollback"
        );

        // 3. `NON_STRIPPABLE_TOP_DIRS` protects a flat archive containing only `cli/catcloud.exe`.
        let cli_only_zip = build_zip(&[("cli/catcloud.exe", b"CLI_ONLY_V031", None)]);
        let cli_only_hash = compute_sha256_hex(&cli_only_zip);
        stage_verified_archive(&cli_only_zip, &cli_only_hash, "0.2.0", "0.3.1", &staging_dir)
            .unwrap();
        let pending_cli_only = read_pending_staged_update(&staging_dir).unwrap();
        assert_eq!(pending_cli_only.files.len(), 1);
        assert_eq!(pending_cli_only.files[0].rel_path, "cli/catcloud.exe");

        let _ = std::fs::remove_dir_all(&root);
    }

    fn try_create_file_symlink(original: &Path, link: &Path) -> bool {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(original, link).is_ok()
        }
        #[cfg(target_os = "windows")]
        {
            std::os::windows::fs::symlink_file(original, link).is_ok()
        }
    }

    fn try_create_dir_symlink(original: &Path, link: &Path) -> bool {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(original, link).is_ok()
        }
        #[cfg(target_os = "windows")]
        {
            std::os::windows::fs::symlink_dir(original, link).is_ok()
        }
    }

    #[test]
    fn normalize_semver_and_is_version_skipped_cover_all_edges() {
        assert_eq!(normalize_semver_version("0.1.1").unwrap(), "0.1.1");
        assert_eq!(normalize_semver_version(" v0.2.0 ").unwrap(), "0.2.0");
        assert_eq!(normalize_semver_version("V1.3.4-rc.1").unwrap(), "1.3.4-rc.1");
        assert!(normalize_semver_version("vv1.0.0").is_err());
        assert!(normalize_semver_version("0.0.0").is_err());
        assert!(normalize_semver_version("v0.0.0-alpha.1").is_err());
        assert!(normalize_semver_version("").is_err());
        assert!(normalize_semver_version("not-a-semver").is_err());
        assert!(normalize_semver_version("1.0.0+\n").is_err());

        // Same version and older version are skipped; newer version breaks through.
        assert!(is_version_skipped("0.1.1", Some("0.1.1")));
        assert!(is_version_skipped("v0.1.1", Some("V0.1.1")));
        assert!(is_version_skipped("0.1.0", Some("0.1.1")));
        assert!(!is_version_skipped("0.1.2", Some("0.1.1")));
        assert!(!is_version_skipped("v0.2.0", Some("0.1.9")));

        // Prerelease vs stable ordering.
        assert!(is_version_skipped("0.2.0-rc.1", Some("0.2.0")));
        assert!(!is_version_skipped("0.2.0", Some("0.2.0-rc.1")));

        // None, invalid, or zero versions never report skipped.
        assert!(!is_version_skipped("0.1.1", None));
        assert!(!is_version_skipped("0.1.1", Some("")));
        assert!(!is_version_skipped("0.1.1", Some("invalid")));
        assert!(!is_version_skipped("invalid", Some("0.1.1")));
        assert!(!is_version_skipped("0.0.0", Some("0.1.1")));
        assert!(!is_version_skipped("0.1.1", Some("0.0.0")));
    }

    #[test]
    fn truncate_utf8_bytes_respects_multibyte_char_boundaries() {
        assert_eq!(truncate_utf8_bytes("hello", 10), "hello");
        assert_eq!(truncate_utf8_bytes("hello", 5), "hello");
        assert_eq!(truncate_utf8_bytes("hello", 0), "");

        // Each Chinese character is 3 UTF-8 bytes.
        let zh = "猫猫云梯更新说明";
        assert_eq!(truncate_utf8_bytes(zh, 0), "");
        assert_eq!(truncate_utf8_bytes(zh, 2), "");
        assert_eq!(truncate_utf8_bytes(zh, 3), "猫");
        assert_eq!(truncate_utf8_bytes(zh, 5), "猫");
        assert_eq!(truncate_utf8_bytes(zh, 6), "猫猫");
        assert_eq!(truncate_utf8_bytes(zh, 8), "猫猫");

        // 4-byte emoji mixed with ASCII and CJK.
        let mixed = "v0.2🚀发布";
        assert_eq!(truncate_utf8_bytes(mixed, 4), "v0.2");
        assert_eq!(truncate_utf8_bytes(mixed, 7), "v0.2");
        assert_eq!(truncate_utf8_bytes(mixed, 8), "v0.2🚀");
        assert_eq!(truncate_utf8_bytes(mixed, 10), "v0.2🚀");
        assert_eq!(truncate_utf8_bytes(mixed, 11), "v0.2🚀发");

        // Oversized notes truncate cleanly under MAX_RELEASE_NOTES_BYTES without panicking.
        let huge = "猫".repeat(20_000);
        let truncated = truncate_utf8_bytes(&huge, MAX_RELEASE_NOTES_BYTES);
        assert!(truncated.len() <= MAX_RELEASE_NOTES_BYTES);
        assert_eq!(truncated.len() % 3, 0);
    }

    #[test]
    fn supported_installer_filename_allowlist_and_safety_guards() {
        for valid in [
            "CatCloud-0.2.0-windows-x64-setup.exe",
            "CatCloud-0.2.0-windows-x64.MSI",
            "CatCloud-0.2.0-macos-aarch64.dmg",
            "CatCloud-0.2.0-macos-aarch64.app.tar.gz",
            "CatCloud-0.2.0-linux-x86_64.AppImage",
            "CatCloud-0.2.0-linux-x86_64.AppImage.tar.gz",
            "CatCloud-0.2.0-linux-x86_64.deb",
            "CatCloud-0.2.0-linux-x86_64.rpm",
        ] {
            assert!(
                is_supported_installer_filename(valid),
                "expected '{valid}' to be accepted as installer filename"
            );
        }

        for invalid in [
            "",
            ".exe",
            ".app.tar.gz",
            "CatCloud-0.2.0-windows-x64-portable.zip",
            "CatCloud-0.2.0-windows-x64-portable.ZIP",
            "catcloud-linux-x86_64.tar.gz",
            "setup.bat",
            "setup.ps1",
            "../setup.exe",
            "sub/setup.exe",
            r"sub\setup.exe",
            "C:setup.exe",
            "setup.exe:ads",
            "foo..bar.exe",
            "setup\x00.exe",
            "setup\n.exe",
            " setup.exe",
            "setup.exe ",
            "setup.exe.",
            "CON.exe",
            "nul.msi",
            "COM1.dmg",
            "LPT9.AppImage",
            "prn.app.tar.gz",
        ] {
            assert!(
                !is_supported_installer_filename(invalid),
                "expected '{invalid}' to be rejected as installer filename"
            );
        }
    }

    #[test]
    fn stage_verified_installer_file_and_verify_integrity_cover_normal_tamper_and_symlink() {
        let root = make_temp_dir("installer-stage");
        let staging_dir = root.join(".update_staging");
        let temp_dl = root.join("download.tmp");

        let payload = b"FAKE_WINDOWS_INSTALLER_BINARY_V020";
        let payload_sha = compute_sha256_hex(payload);
        std::fs::write(&temp_dl, payload).unwrap();

        // 1. Disallowed `.zip` and non-allowlisted suffixes are rejected.
        assert!(matches!(
            stage_verified_installer_file(
                &temp_dl,
                &payload_sha,
                "CatCloud-0.2.0-windows-x64-portable.zip",
                "0.1.0",
                "0.2.0",
                "notes",
                None,
                Some("windows-x86_64"),
                &staging_dir,
            ),
            Err(CatError::Security(_))
        ));
        assert!(matches!(
            stage_verified_installer_file(
                &temp_dl,
                &payload_sha,
                "evil.bat",
                "0.1.0",
                "0.2.0",
                "notes",
                None,
                Some("windows-x86_64"),
                &staging_dir,
            ),
            Err(CatError::Security(_))
        ));

        // Non-allowlisted release_url is rejected.
        assert!(matches!(
            stage_verified_installer_file(
                &temp_dl,
                &payload_sha,
                "CatCloud-0.2.0-windows-x64-setup.exe",
                "0.1.0",
                "0.2.0",
                "notes",
                Some("https://evil.example.com/release"),
                Some("windows-x86_64"),
                &staging_dir,
            ),
            Err(CatError::Security(_))
        ));

        // 2. Normal staging succeeds and passes `verify_staged_payload_integrity`.
        let release_url = "https://github.com/JuryBu/CatCloud/releases/tag/v0.2.0";
        let staged = stage_verified_installer_file(
            &temp_dl,
            &payload_sha,
            "CatCloud-0.2.0-windows-x64-setup.exe",
            "0.1.0",
            "0.2.0",
            "修复了重要问题并优化性能",
            Some(release_url),
            Some("windows-x86_64"),
            &staging_dir,
        )
        .expect("stage valid installer");

        assert_eq!(staged.kind, StagedUpdateKind::InstallerPackage);
        assert_eq!(
            staged.installer_rel_path.as_deref(),
            Some("installer/CatCloud-0.2.0-windows-x64-setup.exe")
        );
        assert_eq!(staged.package_size_bytes, payload.len() as u64);
        assert_eq!(staged.release_url.as_deref(), Some(release_url));
        assert_eq!(staged.platform_key.as_deref(), Some("windows-x86_64"));
        assert_eq!(staged.files.len(), 1);
        assert_eq!(staged.files[0].sha256, payload_sha);

        let verified =
            verify_staged_payload_integrity(&staging_dir).expect("verify staged installer");
        assert_eq!(verified.kind, StagedUpdateKind::InstallerPackage);
        assert_eq!(verified.target_version, "0.2.0");
        assert_eq!(verified.package_size_bytes, payload.len() as u64);

        // 3. `apply_staged_portable_update` must refuse `InstallerPackage` without modifying
        //    `app_root` or deleting `staging_dir`.
        let app_root = root.join("app");
        let backup_dir = root.join(".update_backup");
        std::fs::create_dir_all(&app_root).unwrap();
        let live_exe = app_root.join("CatCloud.exe");
        std::fs::write(&live_exe, b"LIVE_PORTABLE_EXE").unwrap();

        let apply_err = apply_staged_portable_update_for_version(
            &app_root,
            &live_exe,
            &staging_dir,
            &backup_dir,
            "0.1.0",
        )
        .unwrap_err();
        assert!(
            matches!(apply_err, CatError::Validation(ref msg) if msg.contains("installer package, not a portable ZIP")),
            "unexpected error: {apply_err:?}"
        );
        assert_eq!(std::fs::read(&live_exe).unwrap(), b"LIVE_PORTABLE_EXE");
        assert!(
            staging_dir
                .join(STAGING_INSTALLER_DIR)
                .join("CatCloud-0.2.0-windows-x64-setup.exe")
                .is_file(),
            "installer staging must remain intact when portable apply refuses it"
        );

        // 4. Tampering with the staged installer bytes fails verification.
        let staged_file = staging_dir
            .join(STAGING_INSTALLER_DIR)
            .join("CatCloud-0.2.0-windows-x64-setup.exe");
        std::fs::write(&staged_file, b"TAMPERED_INSTALLER_BYTES").unwrap();
        assert!(verify_staged_payload_integrity(&staging_dir).is_err());

        // Restore valid bytes and verify mismatch between files[0].sha256 and archive_sha256 fails.
        std::fs::write(&staged_file, payload).unwrap();
        let mut tampered_manifest = verified.clone();
        tampered_manifest.files[0].sha256 = "0".repeat(64);
        AppPaths::atomic_write(
            &staging_dir.join(PENDING_APPLY_MANIFEST),
            &serde_json::to_vec_pretty(&tampered_manifest).unwrap(),
        )
        .unwrap();
        assert!(verify_staged_payload_integrity(&staging_dir).is_err());

        // 5. Symlink checks (always enforced on Unix; also run on Windows when privilege permits).
        let target_file = root.join("outside_real.exe");
        std::fs::write(&target_file, payload).unwrap();
        let symlink_temp = root.join("symlink_dl.tmp");
        let created_temp_link = try_create_file_symlink(&target_file, &symlink_temp);
        #[cfg(unix)]
        assert!(created_temp_link, "unix file symlink creation must succeed");
        if created_temp_link {
            assert!(matches!(
                stage_verified_installer_file(
                    &symlink_temp,
                    &payload_sha,
                    "CatCloud-0.2.0-windows-x64-setup.exe",
                    "0.1.0",
                    "0.2.0",
                    "",
                    None,
                    None,
                    &staging_dir,
                ),
                Err(CatError::Security(_))
            ));

            // Replace staged installer with a symlink and verify integrity check blocks it.
            let _ = std::fs::remove_file(&staged_file);
            AppPaths::atomic_write(
                &staging_dir.join(PENDING_APPLY_MANIFEST),
                &serde_json::to_vec_pretty(&verified).unwrap(),
            )
            .unwrap();
            if try_create_file_symlink(&target_file, &staged_file) {
                assert!(matches!(
                    verify_staged_payload_integrity(&staging_dir),
                    Err(CatError::Security(_))
                ));
            }
        }

        // 6. Unix `.AppImage` staging sets 0o755 executable permissions.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let appimage_dl = root.join("download.appimage.tmp");
            let appimage_bytes = b"ELF_APPIMAGE_STUB";
            let appimage_sha = compute_sha256_hex(appimage_bytes);
            std::fs::write(&appimage_dl, appimage_bytes).unwrap();
            let staged_ai = stage_verified_installer_file(
                &appimage_dl,
                &appimage_sha,
                "CatCloud-0.2.0-linux-x86_64.AppImage",
                "0.1.0",
                "0.2.0",
                "",
                None,
                Some("linux-x86_64"),
                &staging_dir,
            )
            .expect("stage AppImage");
            assert_eq!(staged_ai.kind, StagedUpdateKind::InstallerPackage);
            let mode = std::fs::metadata(
                staging_dir
                    .join(STAGING_INSTALLER_DIR)
                    .join("CatCloud-0.2.0-linux-x86_64.AppImage"),
            )
            .unwrap()
            .permissions()
            .mode();
            assert_eq!(mode & 0o777, 0o755);
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn purge_staged_update_counts_bytes_and_blocks_non_staging_or_symlink_paths() {
        let root = make_temp_dir("purge-staging");
        let staging_dir = root.join(".update_staging");

        // 1. Nonexistent valid staging path is a clean no-op.
        let noop = purge_staged_update(&staging_dir).expect("purge missing staging dir");
        assert_eq!(
            noop,
            PurgeStagedOutcome {
                removed: false,
                freed_bytes: 0,
            }
        );

        // 2. Populate nested files (including a readonly file) and verify exact byte accounting.
        let nested_dir = staging_dir.join("payload").join("bin");
        std::fs::create_dir_all(&nested_dir).unwrap();
        let f1 = staging_dir.join(PENDING_APPLY_MANIFEST);
        let f2 = nested_dir.join("mihomo.exe");
        let b1 = br#"{"from_version":"0.1.0"}"#;
        let b2 = vec![0xABu8; 4096];
        std::fs::write(&f1, b1).unwrap();
        std::fs::write(&f2, &b2).unwrap();
        let mut ro = std::fs::metadata(&f2).unwrap().permissions();
        ro.set_readonly(true);
        std::fs::set_permissions(&f2, ro).unwrap();

        let expected_freed = (b1.len() + b2.len()) as u64;
        let outcome = purge_staged_update(&staging_dir).expect("purge populated staging dir");
        assert!(outcome.removed);
        assert_eq!(outcome.freed_bytes, expected_freed);
        assert!(!staging_dir.exists());

        // 3. Anti-accidental-deletion guard refuses non-staging directories even if they contain `payload/`.
        let unrelated_dir = root.join("user_app_data");
        std::fs::create_dir_all(unrelated_dir.join("payload")).unwrap();
        std::fs::write(unrelated_dir.join("payload").join("important.dat"), b"KEEP_ME").unwrap();

        assert!(matches!(
            purge_staged_update(&unrelated_dir),
            Err(CatError::Security(_))
        ));
        assert!(unrelated_dir.join("payload").join("important.dat").is_file());

        // Shallow single-component or parent-traversal paths are also blocked.
        assert!(matches!(
            purge_staged_update(Path::new(".update_staging")),
            Err(CatError::Security(_))
        ));
        assert!(matches!(
            purge_staged_update(&root.join("foo").join("..").join(".update_staging")),
            Err(CatError::Security(_))
        ));

        // 4. Root symlink staging_dir is refused and target directory stays untouched.
        let outside_dir = root.join("outside_precious");
        std::fs::create_dir_all(&outside_dir).unwrap();
        std::fs::write(outside_dir.join("secret.txt"), b"DO_NOT_DELETE").unwrap();
        let symlink_staging = root.join(".update_staging");
        let created_dir_link = try_create_dir_symlink(&outside_dir, &symlink_staging);
        #[cfg(unix)]
        assert!(created_dir_link, "unix dir symlink creation must succeed");
        if created_dir_link {
            assert!(matches!(
                purge_staged_update(&symlink_staging),
                Err(CatError::Security(_))
            ));
            assert_eq!(
                std::fs::read(outside_dir.join("secret.txt")).unwrap(),
                b"DO_NOT_DELETE"
            );
            let _ = std::fs::remove_dir(&symlink_staging)
                .or_else(|_| std::fs::remove_file(&symlink_staging));
        }

        // 5. Symlink nested inside a real staging_dir is unlinked without touching symlink target.
        std::fs::create_dir_all(&staging_dir).unwrap();
        std::fs::write(staging_dir.join("a.bin"), b"12345").unwrap();
        let inner_link = staging_dir.join("linked_dir");
        if try_create_dir_symlink(&outside_dir, &inner_link) {
            let purged = purge_staged_update(&staging_dir).expect("purge with inner symlink");
            assert!(purged.removed);
            assert_eq!(purged.freed_bytes, 5);
            assert!(!staging_dir.exists());
            assert_eq!(
                std::fs::read(outside_dir.join("secret.txt")).unwrap(),
                b"DO_NOT_DELETE"
            );
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn legacy_five_field_pending_manifest_deserializes_and_backfills_size() {
        let root = make_temp_dir("legacy-five-field");
        let staging_dir = root.join(".update_staging");
        let payload_dir = staging_dir.join(STAGING_PAYLOAD_DIR);
        std::fs::create_dir_all(&payload_dir).unwrap();

        let exe_bytes = b"LEGACY_PORTABLE_EXE_BYTES";
        let ver_bytes = br#"{"version":"0.2.0"}"#;
        std::fs::write(payload_dir.join("CatCloud.exe"), exe_bytes).unwrap();
        std::fs::write(payload_dir.join("version.json"), ver_bytes).unwrap();

        let legacy_json = serde_json::json!({
            "from_version": "0.1.0",
            "target_version": "0.2.0",
            "archive_sha256": compute_sha256_hex(b"legacy-zip"),
            "staged_at": "2026-11-26T00:00:00Z",
            "files": [
                {
                    "rel_path": "CatCloud.exe",
                    "sha256": compute_sha256_hex(exe_bytes),
                    "size_bytes": exe_bytes.len() as u64,
                },
                {
                    "rel_path": "version.json",
                    "sha256": compute_sha256_hex(ver_bytes),
                    "size_bytes": ver_bytes.len() as u64,
                }
            ]
        });
        let raw_bytes = serde_json::to_vec_pretty(&legacy_json).unwrap();

        // Direct deserialization defaults all 6 newly added fields cleanly.
        let deserialized: PendingUpdateMetadata =
            serde_json::from_slice(&raw_bytes).expect("deserialize legacy 5-field manifest");
        assert_eq!(deserialized.kind, StagedUpdateKind::PortableZip);
        assert_eq!(deserialized.installer_rel_path, None);
        assert_eq!(deserialized.release_notes, "");
        assert_eq!(deserialized.release_url, None);
        assert_eq!(deserialized.platform_key, None);
        assert_eq!(deserialized.package_size_bytes, 0);

        // `verify_staged_payload_integrity` accepts legacy JSON and backfills `package_size_bytes`.
        AppPaths::atomic_write(&staging_dir.join(PENDING_APPLY_MANIFEST), &raw_bytes).unwrap();
        let verified =
            verify_staged_payload_integrity(&staging_dir).expect("verify legacy portable staging");
        assert_eq!(verified.kind, StagedUpdateKind::PortableZip);
        assert_eq!(
            verified.package_size_bytes,
            (exe_bytes.len() + ver_bytes.len()) as u64
        );

        // Also verify `stage_verified_archive_with_meta` persists release metadata, rejects bad URLs,
        // and truncates oversized Chinese release notes strictly on UTF-8 boundaries.
        let zip_bytes = build_zip(&[
            ("CatCloud.exe", b"PORTABLE_META_V020", None),
            ("version.json", br#"{"version":"0.2.0"}"#, None),
        ]);
        let zip_sha = compute_sha256_hex(&zip_bytes);
        assert!(matches!(
            stage_verified_archive_with_meta(
                &zip_bytes,
                &zip_sha,
                "0.1.0",
                "0.2.0",
                "ok",
                Some("http://github.com/JuryBu/CatCloud/releases/tag/v0.2.0"),
                Some("windows-x86_64-portable"),
                &staging_dir,
            ),
            Err(CatError::Security(_))
        ));

        let long_notes = "更新说明".repeat(4000); // 48,000 UTF-8 bytes > 32 KiB
        let staged_meta = stage_verified_archive_with_meta(
            &zip_bytes,
            &zip_sha,
            "0.1.0",
            "0.2.0",
            &long_notes,
            Some("https://github.com/JuryBu/CatCloud/releases/tag/v0.2.0"),
            Some("windows-x86_64-portable"),
            &staging_dir,
        )
        .expect("stage portable zip with full metadata");
        assert_eq!(staged_meta.kind, StagedUpdateKind::PortableZip);
        assert_eq!(staged_meta.package_size_bytes, zip_bytes.len() as u64);
        assert_eq!(
            staged_meta.platform_key.as_deref(),
            Some("windows-x86_64-portable")
        );
        assert_eq!(
            staged_meta.release_url.as_deref(),
            Some("https://github.com/JuryBu/CatCloud/releases/tag/v0.2.0")
        );
        assert!(staged_meta.release_notes.len() <= MAX_RELEASE_NOTES_BYTES);
        assert!(!staged_meta.release_notes.is_empty());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn download_asset_to_temp_file_honors_pre_cancel_and_security_guards() {
        let root = make_temp_dir("dl-temp-guards");
        let temp_file = root.join("asset.download.tmp");
        let updater = Updater::new("JuryBu/CatCloud", "0.1.0").unwrap();

        let mut platforms = HashMap::new();
        platforms.insert(
            "windows-x86_64".to_string(),
            PlatformAsset {
                url: "https://github.com/JuryBu/CatCloud/releases/download/v0.2.0/CatCloud-0.2.0-windows-x64-setup.exe".to_string(),
                signature: None,
                sha256: Some("a".repeat(64)),
                filename: Some("CatCloud-0.2.0-windows-x64-setup.exe".to_string()),
            },
        );
        let manifest = LatestManifest {
            version: "0.2.0".to_string(),
            notes: "Release 0.2.0".to_string(),
            pub_date: None,
            sha256sums_url: Some(
                "https://github.com/JuryBu/CatCloud/releases/download/v0.2.0/SHA256SUMS.txt"
                    .to_string(),
            ),
            platforms,
        };

        // 1. Pre-signalled cancel_rx aborts immediately without touching network or creating file.
        let (tx, rx) = tokio::sync::watch::channel(true);
        let _keep_tx = tx;
        let err = updater
            .download_asset_to_temp_file(&manifest, "windows-x86_64", &temp_file, Some(rx))
            .await
            .unwrap_err();
        assert!(
            matches!(err, CatError::Validation(ref m) if m.contains("cancelled")),
            "expected cancellation error, got {err:?}"
        );
        assert!(!temp_file.exists());

        // 2. Missing platform key returns NotFound.
        let err_missing = updater
            .download_asset_to_temp_file(&manifest, "darwin-aarch64", &temp_file, None)
            .await
            .unwrap_err();
        assert!(matches!(err_missing, CatError::NotFound(_)));

        // 3. Disallowed host URL is blocked immediately before network I/O.
        let mut bad_manifest = manifest.clone();
        bad_manifest
            .platforms
            .get_mut("windows-x86_64")
            .unwrap()
            .url = "https://untrusted.example.org/setup.exe".to_string();
        let err_host = updater
            .download_asset_to_temp_file(&bad_manifest, "windows-x86_64", &temp_file, None)
            .await
            .unwrap_err();
        assert!(matches!(err_host, CatError::Security(_)));

        let _ = std::fs::remove_dir_all(&root);
    }

    async fn read_http_request_head(sock: &mut tokio::net::TcpStream) {
        use tokio::io::AsyncReadExt as _;
        let mut buf = Vec::with_capacity(1024);
        let mut tmp = [0u8; 512];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 16 * 1024 {
            match sock.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
            }
        }
    }

    fn build_local_test_http_client() -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("build local no-proxy test http client")
    }

    #[tokio::test]
    async fn stream_download_writes_64k_chunks_and_matches_sha256() {
        use tokio::io::AsyncWriteExt as _;

        let root = make_temp_dir("stream-dl-ok");
        let temp_file = root.join(".update_download.tmp");
        let payload: Vec<u8> = (0usize..(200 * 1024 + 37))
            .map(|i| ((i.wrapping_mul(31).wrapping_add(7)) & 0xFF) as u8)
            .collect();
        let expected_sha = compute_sha256_hex(&payload);
        let server_payload = payload.clone();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            read_http_request_head(&mut sock).await;
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                server_payload.len()
            );
            sock.write_all(header.as_bytes()).await.unwrap();
            for chunk in server_payload.chunks(16 * 1024) {
                sock.write_all(chunk).await.unwrap();
                sock.flush().await.unwrap();
            }
            let _ = sock.shutdown().await;
        });

        let client = build_local_test_http_client();
        let resp = client
            .get(format!("http://{addr}/CatCloud-0.2.0-windows-x64-setup.exe"))
            .send()
            .await
            .unwrap();
        let written = Updater::stream_response_verified_to_file_with_cap(
            resp,
            "CatCloud-0.2.0-windows-x64-setup.exe",
            &expected_sha,
            &temp_file,
            MAX_PACKAGE_BYTES as u64,
            &mut None,
        )
        .await
        .expect("streamed download should succeed and match SHA-256");

        assert_eq!(written, payload.len() as u64);
        assert_eq!(std::fs::read(&temp_file).unwrap(), payload);
        assert_eq!(compute_file_sha256_hex(&temp_file).unwrap(), expected_sha);

        server.await.unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn stream_download_midstream_cancel_aborts_and_deletes_temp_file() {
        use tokio::io::AsyncWriteExt as _;

        let root = make_temp_dir("stream-dl-cancel");
        let temp_file = root.join(".update_download.tmp");

        let (first_chunk_tx, first_chunk_rx) = tokio::sync::oneshot::channel::<()>();
        let (release_server_tx, release_server_rx) = tokio::sync::oneshot::channel::<()>();
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let cancel_tx = std::sync::Arc::new(cancel_tx);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            read_http_request_head(&mut sock).await;
            let header =
                "HTTP/1.1 200 OK\r\nContent-Length: 262144\r\nConnection: close\r\n\r\n";
            if sock.write_all(header.as_bytes()).await.is_err() {
                return;
            }
            // Write 72 KiB (> 64 KiB BufWriter capacity) so bytes flush to `.update_download.tmp`
            // before pausing mid-stream.
            let first_chunk = vec![0x5Au8; 72 * 1024];
            if sock.write_all(&first_chunk).await.is_err() {
                return;
            }
            let _ = sock.flush().await;
            let _ = first_chunk_tx.send(());
            let _ = tokio::time::timeout(Duration::from_secs(5), release_server_rx).await;
        });

        let temp_for_cancel = temp_file.clone();
        let cancel_tx_task = std::sync::Arc::clone(&cancel_tx);
        let canceller = tokio::spawn(async move {
            let _ = first_chunk_rx.await;
            for _ in 0..100 {
                if std::fs::metadata(&temp_for_cancel)
                    .map(|m| m.len() > 0)
                    .unwrap_or(false)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
            let _ = cancel_tx_task.send(true);
        });

        let client = build_local_test_http_client();
        let resp = client
            .get(format!("http://{addr}/CatCloud-0.2.0-windows-x64-setup.exe"))
            .send()
            .await
            .unwrap();
        let mut cancel_opt = Some(cancel_rx);
        let err = Updater::stream_response_verified_to_file_with_cap(
            resp,
            "CatCloud-0.2.0-windows-x64-setup.exe",
            &"a".repeat(64),
            &temp_file,
            MAX_PACKAGE_BYTES as u64,
            &mut cancel_opt,
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, CatError::Validation(ref msg) if msg.contains("cancelled")),
            "expected mid-stream cancellation error, got {err:?}"
        );
        assert!(
            !temp_file.exists(),
            ".update_download.tmp must be deleted after mid-stream cancellation"
        );

        let _ = release_server_tx.send(());
        drop(cancel_tx);
        canceller.await.unwrap();
        server.await.unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn stream_download_exceeding_cap_aborts_and_deletes_temp_file() {
        use tokio::io::AsyncWriteExt as _;

        let root = make_temp_dir("stream-dl-cap");
        let client = build_local_test_http_client();

        // 1. Declared Content-Length exceeding MAX_PACKAGE_BYTES is rejected immediately.
        let temp_cl = root.join(".update_download_cl.tmp");
        let listener_cl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_cl = listener_cl.local_addr().unwrap();
        let server_cl = tokio::spawn(async move {
            let (mut sock, _) = listener_cl.accept().await.unwrap();
            read_http_request_head(&mut sock).await;
            let over_len = (MAX_PACKAGE_BYTES as u64) + 1;
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {over_len}\r\nConnection: close\r\n\r\n"
            );
            let _ = sock.write_all(header.as_bytes()).await;
            let _ = sock.flush().await;
            let _ = sock.shutdown().await;
        });

        let resp_cl = client
            .get(format!("http://{addr_cl}/oversized.exe"))
            .send()
            .await
            .unwrap();
        let err_cl = Updater::stream_response_verified_to_file_with_cap(
            resp_cl,
            "oversized.exe",
            &"b".repeat(64),
            &temp_cl,
            MAX_PACKAGE_BYTES as u64,
            &mut None,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err_cl, CatError::Security(ref msg) if msg.contains("Content-Length")),
            "expected Content-Length cap error, got {err_cl:?}"
        );
        assert!(!temp_cl.exists());
        server_cl.await.unwrap();

        // 2. Unannounced streamed body exceeding the hard cap aborts mid-stream and deletes temp file.
        let temp_stream = root.join(".update_download.tmp");
        let listener_stream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_stream = listener_stream.local_addr().unwrap();
        let server_stream = tokio::spawn(async move {
            let (mut sock, _) = listener_stream.accept().await.unwrap();
            read_http_request_head(&mut sock).await;
            let header = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
            if sock.write_all(header.as_bytes()).await.is_err() {
                return;
            }
            let block = vec![0xCDu8; 16 * 1024];
            for _ in 0..8 {
                if sock.write_all(&block).await.is_err() {
                    break;
                }
                if sock.flush().await.is_err() {
                    break;
                }
            }
            let _ = sock.shutdown().await;
        });

        let resp_stream = client
            .get(format!("http://{addr_stream}/stream-oversize.exe"))
            .send()
            .await
            .unwrap();
        let err_stream = Updater::stream_response_verified_to_file_with_cap(
            resp_stream,
            "stream-oversize.exe",
            &"c".repeat(64),
            &temp_stream,
            72 * 1024,
            &mut None,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err_stream, CatError::Security(ref msg) if msg.contains("exceeded hard limit")),
            "expected streamed size-cap error, got {err_stream:?}"
        );
        assert!(
            !temp_stream.exists(),
            "temp file must be deleted when stream exceeds hard byte cap"
        );
        server_stream.await.unwrap();

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn stream_download_sha256_mismatch_fails_and_deletes_temp_file() {
        use tokio::io::AsyncWriteExt as _;

        let root = make_temp_dir("stream-dl-sha-mismatch");
        let temp_file = root.join(".update_download.tmp");
        let payload = vec![0x3Cu8; 100 * 1024];
        let server_payload = payload.clone();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            read_http_request_head(&mut sock).await;
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                server_payload.len()
            );
            sock.write_all(header.as_bytes()).await.unwrap();
            sock.write_all(&server_payload).await.unwrap();
            let _ = sock.shutdown().await;
        });

        let client = build_local_test_http_client();
        let resp = client
            .get(format!("http://{addr}/CatCloud-0.2.0-setup.exe"))
            .send()
            .await
            .unwrap();
        let wrong_sha = "0".repeat(64);
        assert_ne!(compute_sha256_hex(&payload), wrong_sha);

        let err = Updater::stream_response_verified_to_file_with_cap(
            resp,
            "CatCloud-0.2.0-setup.exe",
            &wrong_sha,
            &temp_file,
            MAX_PACKAGE_BYTES as u64,
            &mut None,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, CatError::Security(ref msg) if msg.contains("SHA256 checksum mismatch")),
            "expected SHA-256 mismatch error, got {err:?}"
        );
        assert!(
            !temp_file.exists(),
            "temp file must be deleted on SHA-256 checksum mismatch"
        );

        server.await.unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stage_verified_installer_file_enforces_downgrade_size_cap_and_staging_containment() {
        let root = make_temp_dir("installer-boundaries");
        let staging_dir = root.join(".update_staging");

        let small_payload = vec![0x42u8; 64];
        let small_sha = compute_sha256_hex(&small_payload);
        let temp_small = root.join("small.tmp");
        std::fs::write(&temp_small, &small_payload).unwrap();

        // 1. Anti-downgrade: same version, older version, and 0.0.0 must all be rejected.
        for (from_v, target_v) in [("0.2.0", "0.2.0"), ("0.3.0", "0.2.0"), ("0.1.0", "0.0.0")] {
            let err = stage_verified_installer_file(
                &temp_small,
                &small_sha,
                "CatCloud-0.2.0-windows-x64-setup.exe",
                from_v,
                target_v,
                "",
                None,
                Some("windows-x86_64"),
                &staging_dir,
            )
            .unwrap_err();
            assert!(
                matches!(err, CatError::Validation(_)),
                "expected Validation anti-downgrade error for {from_v} -> {target_v}, got {err:?}"
            );
        }

        // 2. Size cap enforcement using injected 64-byte cap (zero 65 MiB disk overhead).
        let over_payload = vec![0x43u8; 65];
        let over_sha = compute_sha256_hex(&over_payload);
        let temp_over = root.join("over64.tmp");
        std::fs::write(&temp_over, &over_payload).unwrap();
        let err_cap = stage_verified_installer_file_with_cap(
            &temp_over,
            &over_sha,
            "CatCloud-0.2.0-windows-x64-setup.exe",
            "0.1.0",
            "0.2.0",
            "",
            None,
            Some("windows-x86_64"),
            &staging_dir,
            64,
        )
        .unwrap_err();
        assert!(
            matches!(err_cap, CatError::Security(ref msg) if msg.contains("exceeds size cap")),
            "expected size-cap Security error, got {err_cap:?}"
        );

        // Exact boundary (64 bytes == cap 64) succeeds cleanly.
        let staged_exact = stage_verified_installer_file_with_cap(
            &temp_small,
            &small_sha,
            "CatCloud-0.2.0-windows-x64-setup.exe",
            "0.1.0",
            "0.2.0",
            "",
            None,
            Some("windows-x86_64"),
            &staging_dir,
            64,
        )
        .expect("exact-cap installer should stage cleanly");
        assert_eq!(staged_exact.package_size_bytes, 64);

        // 3. `temp_file_path` located inside `staging_dir` (direct or nested) must be rejected
        //    before `purge_staged_update` runs.
        let inside_direct = staging_dir.join(".update_download.tmp");
        std::fs::write(&inside_direct, &small_payload).unwrap();
        let err_inside = stage_verified_installer_file(
            &inside_direct,
            &small_sha,
            "CatCloud-0.3.0-windows-x64-setup.exe",
            "0.2.0",
            "0.3.0",
            "",
            None,
            Some("windows-x86_64"),
            &staging_dir,
        )
        .unwrap_err();
        assert!(
            matches!(err_inside, CatError::Validation(ref msg) if msg.contains("staging_dir")),
            "expected staging_dir containment Validation error, got {err_inside:?}"
        );
        assert!(
            inside_direct.is_file(),
            "rejected temp file inside staging_dir must not be purged"
        );

        let inside_nested = staging_dir.join(STAGING_INSTALLER_DIR).join("nested.tmp");
        std::fs::write(&inside_nested, &small_payload).unwrap();
        let err_nested = stage_verified_installer_file(
            &inside_nested,
            &small_sha,
            "CatCloud-0.3.0-windows-x64-setup.exe",
            "0.2.0",
            "0.3.0",
            "",
            None,
            Some("windows-x86_64"),
            &staging_dir,
        )
        .unwrap_err();
        assert!(
            matches!(err_nested, CatError::Validation(ref msg) if msg.contains("staging_dir")),
            "expected nested staging_dir containment Validation error, got {err_nested:?}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn verify_staged_installer_requires_single_matching_file_entry_and_exact_sizes() {
        let root = make_temp_dir("installer-strict-manifest");
        let staging_dir = root.join(".update_staging");
        let temp_dl = root.join("setup.tmp");
        let payload = b"STRICT_INSTALLER_MANIFEST_TEST_PAYLOAD";
        let payload_sha = compute_sha256_hex(payload);
        std::fs::write(&temp_dl, payload).unwrap();

        let baseline = stage_verified_installer_file(
            &temp_dl,
            &payload_sha,
            "CatCloud-0.2.0-windows-x64-setup.exe",
            "0.1.0",
            "0.2.0",
            "",
            None,
            Some("windows-x86_64"),
            &staging_dir,
        )
        .unwrap();
        let manifest_path = staging_dir.join(PENDING_APPLY_MANIFEST);

        // 1. Empty `files` array must be rejected.
        let mut empty_files = baseline.clone();
        empty_files.files.clear();
        AppPaths::atomic_write(
            &manifest_path,
            &serde_json::to_vec_pretty(&empty_files).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            verify_staged_payload_integrity(&staging_dir),
            Err(CatError::Security(_))
        ));

        // 2. More than 1 entry in `files` must be rejected.
        let mut two_files = baseline.clone();
        two_files.files.push(baseline.files[0].clone());
        AppPaths::atomic_write(
            &manifest_path,
            &serde_json::to_vec_pretty(&two_files).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            verify_staged_payload_integrity(&staging_dir),
            Err(CatError::Security(_))
        ));

        // 3. Mismatched `files[0].rel_path` must be rejected.
        let mut bad_rel = baseline.clone();
        bad_rel.files[0].rel_path = "installer/other-setup.exe".into();
        AppPaths::atomic_write(&manifest_path, &serde_json::to_vec_pretty(&bad_rel).unwrap())
            .unwrap();
        assert!(matches!(
            verify_staged_payload_integrity(&staging_dir),
            Err(CatError::Security(_))
        ));

        // 4. Mismatched `files[0].size_bytes` must be rejected.
        let mut bad_file_size = baseline.clone();
        bad_file_size.files[0].size_bytes = (payload.len() as u64) + 1;
        AppPaths::atomic_write(
            &manifest_path,
            &serde_json::to_vec_pretty(&bad_file_size).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            verify_staged_payload_integrity(&staging_dir),
            Err(CatError::Security(_))
        ));

        // 5. Non-zero mismatched `package_size_bytes` must be rejected.
        let mut bad_pkg_size = baseline.clone();
        bad_pkg_size.package_size_bytes = (payload.len() as u64) + 10;
        AppPaths::atomic_write(
            &manifest_path,
            &serde_json::to_vec_pretty(&bad_pkg_size).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            verify_staged_payload_integrity(&staging_dir),
            Err(CatError::Security(_))
        ));

        // 6. Legacy `package_size_bytes == 0` with valid single `files[0]` succeeds and backfills.
        let mut zero_pkg_size = baseline.clone();
        zero_pkg_size.package_size_bytes = 0;
        AppPaths::atomic_write(
            &manifest_path,
            &serde_json::to_vec_pretty(&zero_pkg_size).unwrap(),
        )
        .unwrap();
        let verified = verify_staged_payload_integrity(&staging_dir)
            .expect("zero package_size_bytes should backfill when files[0] matches");
        assert_eq!(verified.package_size_bytes, payload.len() as u64);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn verify_staged_portable_blocks_ancestor_symlink_and_apply_blocks_staging_or_manifest_symlink()
    {
        let root = make_temp_dir("portable-ancestor-symlink");
        let app_root = root.join("app");
        let staging_dir = app_root.join(".update_staging");
        let backup_dir = app_root.join(".update_backup");
        std::fs::create_dir_all(&app_root).unwrap();
        let exe_path = app_root.join("CatCloud.exe");
        std::fs::write(&exe_path, b"OLD_EXE").unwrap();

        let nested_bytes = b"NESTED_MIHOMO_BIN_V020";
        let zip_bytes = build_zip(&[
            ("CatCloud.exe", b"NEW_EXE_V020", None),
            ("resources/bin/mihomo.exe", nested_bytes, None),
        ]);
        let zip_hash = compute_sha256_hex(&zip_bytes);
        stage_verified_archive(&zip_bytes, &zip_hash, "0.1.0", "0.2.0", &staging_dir).unwrap();

        // 1. Replace intermediate ancestor directory `payload/resources` with a symlink pointing
        //    to an outside directory containing a matching `bin/mihomo.exe`.
        let outside_res = root.join("outside_resources");
        std::fs::create_dir_all(outside_res.join("bin")).unwrap();
        std::fs::write(outside_res.join("bin").join("mihomo.exe"), nested_bytes).unwrap();

        let payload_res = staging_dir.join(STAGING_PAYLOAD_DIR).join("resources");
        std::fs::remove_dir_all(&payload_res).unwrap();
        let created_ancestor_link = try_create_dir_symlink(&outside_res, &payload_res);
        #[cfg(unix)]
        assert!(
            created_ancestor_link,
            "unix dir symlink creation must succeed"
        );
        if created_ancestor_link {
            let err = verify_staged_payload_integrity(&staging_dir).unwrap_err();
            assert!(
                matches!(err, CatError::Security(ref msg) if msg.contains("symlink ancestor")),
                "expected symlink ancestor Security error, got {err:?}"
            );
            let _ = std::fs::remove_dir(&payload_res)
                .or_else(|_| std::fs::remove_file(&payload_res));
        }

        // 2. Symlink `pending_apply.json` must be blocked at entry of `apply_staged_portable_update_for_version`.
        let outside_manifest = root.join("outside_pending_apply.json");
        std::fs::copy(staging_dir.join(PENDING_APPLY_MANIFEST), &outside_manifest).unwrap();
        std::fs::remove_file(staging_dir.join(PENDING_APPLY_MANIFEST)).unwrap();
        let created_manifest_link =
            try_create_file_symlink(&outside_manifest, &staging_dir.join(PENDING_APPLY_MANIFEST));
        #[cfg(unix)]
        assert!(
            created_manifest_link,
            "unix file symlink creation must succeed"
        );
        if created_manifest_link {
            let err = apply_staged_portable_update_for_version(
                &app_root,
                &exe_path,
                &staging_dir,
                &backup_dir,
                "0.1.0",
            )
            .unwrap_err();
            assert!(
                matches!(err, CatError::Security(_)),
                "expected Security error for symlink manifest, got {err:?}"
            );
            assert!(
                outside_manifest.is_file(),
                "outside manifest target must remain untouched"
            );
            let _ = std::fs::remove_file(staging_dir.join(PENDING_APPLY_MANIFEST));
        }

        // 3. Symlink `staging_dir` itself must be blocked at entry without purging target.
        let outside_staging = root.join("outside_staging_real");
        std::fs::create_dir_all(&outside_staging).unwrap();
        std::fs::write(outside_staging.join("keep.txt"), b"KEEP_OUTSIDE").unwrap();
        let symlink_staging = root.join("app2").join(".update_staging");
        std::fs::create_dir_all(symlink_staging.parent().unwrap()).unwrap();
        let created_staging_link = try_create_dir_symlink(&outside_staging, &symlink_staging);
        #[cfg(unix)]
        assert!(
            created_staging_link,
            "unix dir symlink creation must succeed"
        );
        if created_staging_link {
            let err = apply_staged_portable_update_for_version(
                &app_root,
                &exe_path,
                &symlink_staging,
                &backup_dir,
                "0.1.0",
            )
            .unwrap_err();
            assert!(
                matches!(err, CatError::Security(_)),
                "expected Security error for symlink staging_dir, got {err:?}"
            );
            assert_eq!(
                std::fs::read(outside_staging.join("keep.txt")).unwrap(),
                b"KEEP_OUTSIDE"
            );
            let _ = std::fs::remove_dir(&symlink_staging)
                .or_else(|_| std::fs::remove_file(&symlink_staging));
        }

        let _ = std::fs::remove_dir_all(&root);
    }
}
