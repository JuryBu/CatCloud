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
    verify_sha256_bytes(zip_bytes, expected_sha256)?;
    if !is_newer_version(target_version, from_version)? {
        return Err(CatError::Validation(format!(
            "target version {target_version} is not newer than current version {from_version}"
        )));
    }

    if staging_dir.exists() {
        std::fs::remove_dir_all(staging_dir)?;
    }
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
        let _ = std::fs::remove_dir_all(staging_dir);
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

/// Strictly verify the integrity of a staged portable update inside `staging_dir`.
///
/// Validates:
/// - `pending_apply.json` exists, is within `MAX_METADATA_BYTES`, and parses cleanly
/// - `target_version` is a valid non-zero SemVer and `files` is non-empty
/// - `staging_dir/payload/` exists as a directory
/// - Every declared relative path is safe, non-preserved, non-duplicate, non-symlink,
///   exists under `payload/`, and matches its recorded SHA-256 digest.
pub fn verify_staged_payload_integrity(staging_dir: &Path) -> CatResult<PendingUpdateMetadata> {
    let manifest_path = staging_dir.join(PENDING_APPLY_MANIFEST);
    let manifest_bytes = read_metadata_file_bounded(&manifest_path)?;
    let pending: PendingUpdateMetadata = serde_json::from_slice(&manifest_bytes)?;
    let parsed_ver = parse_semver(&pending.target_version)?;
    if parsed_ver.is_zero_core() {
        return Err(CatError::Validation(format!(
            "staged target version 0.0.0 is rejected: '{}'",
            pending.target_version
        )));
    }
    if pending.files.is_empty() {
        return Err(CatError::Validation(
            "pending_apply.json contains no files to apply".into(),
        ));
    }

    let payload_dir = staging_dir.join(STAGING_PAYLOAD_DIR);
    if !payload_dir.is_dir() {
        return Err(CatError::Validation(format!(
            "staged update payload directory missing: {}",
            payload_dir.display()
        )));
    }
    let canonical_payload =
        std::fs::canonicalize(&payload_dir).unwrap_or_else(|_| payload_dir.clone());

    let mut seen_rel: HashSet<String> = HashSet::with_capacity(pending.files.len());
    for entry in &pending.files {
        let clean_rel = sanitize_and_validate_zip_path(&entry.rel_path)?;
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

        let staged_file = canonical_payload.join(rel_posix_to_path(&clean_rel));
        ensure_within_root(&staged_file, &canonical_payload)?;
        let sym_meta = std::fs::symlink_metadata(&staged_file).map_err(|_| {
            CatError::Validation(format!("staged update file missing: '{clean_rel}'"))
        })?;
        if sym_meta.file_type().is_symlink() {
            return Err(CatError::Security(format!(
                "symlink blocked in staged update payload: '{clean_rel}'"
            )));
        }
        if !sym_meta.is_file() {
            return Err(CatError::Validation(format!(
                "staged update file missing: '{clean_rel}'"
            )));
        }
        verify_file_sha256(&staged_file, &entry.sha256)?;
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
    let manifest_path = staging_dir.join(PENDING_APPLY_MANIFEST);
    if !manifest_path.is_file() {
        return Ok(PortableApplyOutcome::no_pending());
    }

    let manifest_bytes = match read_metadata_file_bounded(&manifest_path) {
        Ok(b) => b,
        Err(err) => {
            tracing::warn!(
                staging_dir = %staging_dir.display(),
                "removing unreadable staged update directory: {err}"
            );
            let _ = std::fs::remove_dir_all(staging_dir);
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
            let _ = std::fs::remove_dir_all(staging_dir);
            return Err(CatError::Json(err));
        }
    };

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
            let _ = std::fs::remove_dir_all(staging_dir);
            return Ok(PortableApplyOutcome::no_pending());
        }
        Err(err) => {
            tracing::warn!(
                current_version = %current_version,
                staged_version = %parsed_pending.target_version,
                staging_dir = %staging_dir.display(),
                "staged portable update has invalid version; cleaning up staging dir: {err}"
            );
            let _ = std::fs::remove_dir_all(staging_dir);
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
            let _ = std::fs::remove_dir_all(staging_dir);
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
        let _ = std::fs::remove_dir_all(staging_dir);
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

            if dst.is_file() {
                let bak = backup_dir.join(&rel_path);
                if let Some(bp) = bak.parent() {
                    std::fs::create_dir_all(bp)?;
                }
                std::fs::copy(&dst, &bak)?;
                replaced_files.push(rel_path.clone());
            } else {
                created_files.push(rel_path.clone());
            }

            move_or_atomic_place(&src, &dst)?;
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
                if let Err(e) = copy_atomic_replace(&bak, &dst) {
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
    let _ = std::fs::remove_dir_all(staging_dir);

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
    if let Ok(meta) = std::fs::metadata(path) {
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
/// `src` intact in case an upstream rollback inspects staging.
fn move_or_atomic_place(src: &Path, dst: &Path) -> CatResult<()> {
    copy_atomic_replace(src, dst)
}

fn copy_atomic_replace(src: &Path, dst: &Path) -> CatResult<()> {
    let pid = std::process::id();
    let name = dst
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("update_file");
    let tmp = dst.with_file_name(format!("{name}.upd.{pid}.tmp"));
    let copy_res = std::fs::copy(src, &tmp);
    if let Err(e) = copy_res {
        let _ = std::fs::remove_file(&tmp);
        return Err(CatError::Io(e));
    }

    #[cfg(target_os = "windows")]
    {
        let swap_bak = dst.with_file_name(format!("{name}.swap_bak.{pid}"));
        let mut last_err = None;

        for attempt in 0..3 {
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
                        if attempt < 2 {
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
                        let _ = std::fs::remove_file(&swap_bak);
                    }
                    return Ok(());
                }
                Err(rename_err) => {
                    // Restore previous destination immediately to eliminate any missing-file window.
                    if moved_existing {
                        let _ = std::fs::rename(&swap_bak, dst);
                    }
                    last_err = Some(rename_err);
                    if attempt < 2 {
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

        stage_verified_archive(
            &archive_bytes,
            &expected_sha256,
            &self.current_version,
            &manifest.version,
            staging_dir,
        )
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
        copy_atomic_replace(&src_file, &dst_file).unwrap();
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
}
