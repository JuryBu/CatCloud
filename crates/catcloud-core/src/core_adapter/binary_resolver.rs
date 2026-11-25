use crate::error::CatResult;
use crate::models::{AppConfig, CoreKind};
use crate::paths::AppPaths;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Official MetaCubeX Mihomo releases page used for first-launch download guidance.
pub const MIHOMO_OFFICIAL_RELEASES_URL: &str = "https://github.com/MetaCubeX/mihomo/releases";

/// Origin category describing where the resolved core binary was found.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BinarySource {
    CustomConfigPath,
    UserDataBin,
    BundledResourcesBin,
    CandidatePath,
    SystemPath,
    NotFound,
}

/// Structured official download guidance returned when no local Mihomo binary exists.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DownloadGuidance {
    pub core_kind: CoreKind,
    pub platform_target: String,
    pub recommended_asset_pattern: String,
    pub official_releases_url: String,
    pub target_install_path: PathBuf,
    pub verify_sha256_required: bool,
    pub instructions: String,
}

/// Resolution result for locating the Mihomo binary on disk.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BinaryResolution {
    pub found: bool,
    pub path: Option<PathBuf>,
    pub source: BinarySource,
    pub sha256: Option<String>,
    pub checked_candidates: Vec<PathBuf>,
    pub download_guidance: Option<DownloadGuidance>,
}

/// Platform-appropriate Mihomo executable filename.
pub fn mihomo_binary_name() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "mihomo.exe"
    }
    #[cfg(not(target_os = "windows"))]
    {
        "mihomo"
    }
}

/// On Unix, ensure a located Mihomo binary has at least one execute permission bit (`mode & 0o111`).
/// When missing (e.g. a user-copied or hot-swapped binary in `paths.bin_dir`), performs a
/// best-effort `chmod 0o755` repair and returns `true` if permissions were updated.
pub fn ensure_unix_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let Ok(meta) = std::fs::metadata(path) else {
            return false;
        };
        let mode = meta.permissions().mode();
        if mode & 0o111 != 0 {
            return false;
        }
        let mut perms = meta.permissions();
        perms.set_mode(0o755);
        match std::fs::set_permissions(path, perms) {
            Ok(()) => {
                let old_mode = format!("{:o}", mode & 0o7777);
                tracing::info!(
                    path = %path.display(),
                    old_mode = %old_mode,
                    "repaired missing Unix execute permission bit on Mihomo binary (0o755)"
                );
                true
            }
            Err(err) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %err,
                    "failed to repair Unix execute permission bit on Mihomo binary"
                );
                false
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

/// Compute lowercase hex SHA-256 of a file using a bounded streaming buffer.
pub fn compute_file_sha256(path: &Path) -> CatResult<String> {
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

/// Build platform-specific download guidance for installing an official Mihomo binary.
pub fn build_mihomo_download_guidance(paths: &AppPaths) -> DownloadGuidance {
    let platform_target = platform_target_triplet();
    let ext = if cfg!(target_os = "windows") {
        "zip"
    } else {
        "gz"
    };
    let recommended_asset_pattern = format!("mihomo-{platform_target}-*.{ext}");
    let target_install_path = paths.bin_dir.join(mihomo_binary_name());
    let instructions = format!(
        "Download `{recommended_asset_pattern}` from {MIHOMO_OFFICIAL_RELEASES_URL}, verify its SHA-256 checksum against the official release manifest, and place the extracted executable at `{}`.",
        target_install_path.display()
    );

    DownloadGuidance {
        core_kind: CoreKind::Mihomo,
        platform_target: platform_target.to_string(),
        recommended_asset_pattern,
        official_releases_url: MIHOMO_OFFICIAL_RELEASES_URL.to_string(),
        target_install_path,
        verify_sha256_required: true,
        instructions,
    }
}

/// Resolve the Mihomo binary using the current executable directory as the bundle root.
///
/// Strict resolution priority:
/// 1. `config.core_runtime.custom_binary_path`
/// 2. `paths.bin_dir/mihomo(.exe)`
/// 3. Bundled locations (`<exe_dir>/resources/bin/mihomo(.exe)`, macOS `.app` `../Resources/...`,
///    Linux package `../lib/CatCloud/resources/bin/...`, `/usr/lib/CatCloud/...`, `/usr/share/CatCloud/...`)
/// 4. Extra candidates (`extra_candidates` files or resource directories, `<exe_dir>/bin/mihomo(.exe)`, `<exe_dir>/mihomo(.exe)`)
/// 5. `PATH` lookup for `mihomo(.exe)`
pub fn resolve_mihomo_binary(
    cfg: &AppConfig,
    paths: &AppPaths,
    extra_candidates: &[PathBuf],
    compute_sha256: bool,
) -> CatResult<BinaryResolution> {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf));
    resolve_mihomo_binary_with_exe_dir(
        cfg,
        paths,
        exe_dir.as_deref(),
        extra_candidates,
        compute_sha256,
    )
}

/// Deterministic variant of `resolve_mihomo_binary` accepting an explicit `exe_dir`
/// (useful for tests and packaged launchers).
pub fn resolve_mihomo_binary_with_exe_dir(
    cfg: &AppConfig,
    paths: &AppPaths,
    exe_dir: Option<&Path>,
    extra_candidates: &[PathBuf],
    compute_sha256: bool,
) -> CatResult<BinaryResolution> {
    let bin_name = mihomo_binary_name();
    let mut ordered_candidates: Vec<(PathBuf, BinarySource)> = Vec::new();

    // 1. Explicit user override in config.json
    if let Some(custom) = cfg
        .core_runtime
        .custom_binary_path
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        ordered_candidates.push((PathBuf::from(custom), BinarySource::CustomConfigPath));
    }

    // 2. Portable/user data bin directory (supports hot-swapped kernel binaries)
    ordered_candidates.push((paths.bin_dir.join(bin_name), BinarySource::UserDataBin));

    // 3. Bundled resources/bin locations (portable, portable cli/, macOS .app bundle, Linux system packages)
    if let Some(dir) = exe_dir {
        ordered_candidates.push((
            dir.join("resources").join("bin").join(bin_name),
            BinarySource::BundledResourcesBin,
        ));
        if dir
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("cli"))
        {
            if let Some(parent) = dir.parent() {
                if parent.parent().is_some() {
                    // Portable layout: `<root>/cli/catcloud(.exe)` -> `<root>/resources/bin/mihomo(.exe)`
                    ordered_candidates.push((
                        parent.join("resources").join("bin").join(bin_name),
                        BinarySource::BundledResourcesBin,
                    ));
                    // Bundled installer layout (Windows MSI/NSIS, macOS .app, Linux AppImage/deb/rpm):
                    // `<resources>/cli/catcloud(.exe)` -> `<resources>/bin/mihomo(.exe)`
                    ordered_candidates.push((
                        parent.join("bin").join(bin_name),
                        BinarySource::BundledResourcesBin,
                    ));
                }
            }
        }
        let parent_dir = dir
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| dir.join(".."));
        // macOS app bundle: <App>.app/Contents/MacOS -> ../Resources/...
        ordered_candidates.push((
            parent_dir
                .join("Resources")
                .join("resources")
                .join("bin")
                .join(bin_name),
            BinarySource::BundledResourcesBin,
        ));
        ordered_candidates.push((
            parent_dir.join("Resources").join("bin").join(bin_name),
            BinarySource::BundledResourcesBin,
        ));
        // Linux package layout: /usr/bin -> ../lib/CatCloud/resources/bin/mihomo
        ordered_candidates.push((
            parent_dir
                .join("lib")
                .join("CatCloud")
                .join("resources")
                .join("bin")
                .join(bin_name),
            BinarySource::BundledResourcesBin,
        ));
    }
    #[cfg(target_os = "linux")]
    {
        ordered_candidates.push((
            PathBuf::from("/usr/lib/CatCloud/resources/bin").join(bin_name),
            BinarySource::BundledResourcesBin,
        ));
        ordered_candidates.push((
            PathBuf::from("/usr/share/CatCloud/resources/bin").join(bin_name),
            BinarySource::BundledResourcesBin,
        ));
    }

    // 4. Explicit caller-provided candidates (file paths or resource dirs) and secondary app-relative locations
    for candidate in extra_candidates {
        if candidate.as_os_str().is_empty() {
            continue;
        }
        if candidate.is_dir() {
            ordered_candidates.push((
                candidate.join("resources").join("bin").join(bin_name),
                BinarySource::CandidatePath,
            ));
            ordered_candidates.push((
                candidate.join("bin").join(bin_name),
                BinarySource::CandidatePath,
            ));
            ordered_candidates.push((candidate.join(bin_name), BinarySource::CandidatePath));
        } else {
            ordered_candidates.push((candidate.clone(), BinarySource::CandidatePath));
        }
    }
    if let Some(dir) = exe_dir {
        ordered_candidates.push((dir.join("bin").join(bin_name), BinarySource::CandidatePath));
        ordered_candidates.push((dir.join(bin_name), BinarySource::CandidatePath));
    }

    // 5. Fallback scan on system PATH
    if let Some(path_var) = std::env::var_os("PATH") {
        for entry in std::env::split_paths(&path_var) {
            if !entry.as_os_str().is_empty() {
                ordered_candidates.push((entry.join(bin_name), BinarySource::SystemPath));
            }
        }
    }

    let mut checked = Vec::with_capacity(ordered_candidates.len());
    for (candidate, source) in ordered_candidates {
        checked.push(candidate.clone());
        if candidate.is_file() {
            let resolved_path = crate::paths::normalize_os_path(
                &std::fs::canonicalize(&candidate).unwrap_or_else(|_| candidate.clone()),
            );
            ensure_unix_executable(&resolved_path);
            let sha256 = if compute_sha256 {
                Some(compute_file_sha256(&resolved_path)?)
            } else {
                None
            };
            return Ok(BinaryResolution {
                found: true,
                path: Some(resolved_path),
                source,
                sha256,
                checked_candidates: checked,
                download_guidance: None,
            });
        }
    }

    Ok(BinaryResolution {
        found: false,
        path: None,
        source: BinarySource::NotFound,
        sha256: None,
        checked_candidates: checked,
        download_guidance: Some(build_mihomo_download_guidance(paths)),
    })
}

fn platform_target_triplet() -> &'static str {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    match (os, arch) {
        ("windows", "x86_64") => "windows-amd64",
        ("windows", "aarch64") => "windows-arm64",
        ("macos", "aarch64") => "darwin-arm64",
        ("macos", "x86_64") => "darwin-amd64",
        ("linux", "x86_64") => "linux-amd64",
        ("linux", "aarch64") => "linux-arm64",
        _ => "generic",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn make_temp_env(tag: &str) -> (PathBuf, AppPaths, PathBuf) {
        let root =
            std::env::temp_dir().join(format!("catcloud-binres-test-{tag}-{}", Uuid::new_v4()));
        let data_dir = root.join("data");
        let exe_dir = root.join("app");
        std::fs::create_dir_all(&exe_dir).expect("create exe_dir");
        let paths = AppPaths::from_data_dir(data_dir, true).expect("create AppPaths");
        (root, paths, exe_dir)
    }

    #[test]
    fn resolves_strict_priority_custom_over_data_bin_over_resources_over_candidates() {
        let (root, paths, exe_dir) = make_temp_env("priority");
        let bin_name = mihomo_binary_name();

        let custom_bin = root.join("custom").join(bin_name);
        let data_bin = paths.bin_dir.join(bin_name);
        let res_bin = exe_dir.join("resources").join("bin").join(bin_name);
        let extra_bin = root.join("extra").join(bin_name);

        for (p, body) in [
            (&custom_bin, b"custom-mihomo-bin".as_slice()),
            (&data_bin, b"data-mihomo-bin".as_slice()),
            (&res_bin, b"resources-mihomo-bin".as_slice()),
            (&extra_bin, b"extra-mihomo-bin".as_slice()),
        ] {
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(p, body).unwrap();
        }

        // 1. Custom path wins over everything and computes SHA-256
        let mut cfg = AppConfig::default();
        cfg.core_runtime.custom_binary_path = Some(custom_bin.to_string_lossy().to_string());
        let r1 = resolve_mihomo_binary_with_exe_dir(
            &cfg,
            &paths,
            Some(&exe_dir),
            std::slice::from_ref(&extra_bin),
            true,
        )
        .unwrap();
        assert!(r1.found);
        assert_eq!(r1.source, BinarySource::CustomConfigPath);
        assert_eq!(r1.sha256.as_deref().map(str::len), Some(64));

        // 2. Removing custom override selects paths.bin_dir
        cfg.core_runtime.custom_binary_path = None;
        let r2 = resolve_mihomo_binary_with_exe_dir(
            &cfg,
            &paths,
            Some(&exe_dir),
            std::slice::from_ref(&extra_bin),
            false,
        )
        .unwrap();
        assert!(r2.found);
        assert_eq!(r2.source, BinarySource::UserDataBin);
        assert!(r2.sha256.is_none());

        // 3. Removing data_bin selects <exe_dir>/resources/bin
        std::fs::remove_file(&data_bin).unwrap();
        let r3 = resolve_mihomo_binary_with_exe_dir(
            &cfg,
            &paths,
            Some(&exe_dir),
            std::slice::from_ref(&extra_bin),
            false,
        )
        .unwrap();
        assert!(r3.found);
        assert_eq!(r3.source, BinarySource::BundledResourcesBin);

        // 4. Removing resources/bin selects extra candidate
        std::fs::remove_file(&res_bin).unwrap();
        let r4 = resolve_mihomo_binary_with_exe_dir(
            &cfg,
            &paths,
            Some(&exe_dir),
            std::slice::from_ref(&extra_bin),
            false,
        )
        .unwrap();
        assert!(r4.found);
        assert_eq!(r4.source, BinarySource::CandidatePath);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn download_guidance_contains_official_release_metadata() {
        let (root, paths, _) = make_temp_env("guidance");
        let guidance = build_mihomo_download_guidance(&paths);
        assert_eq!(guidance.core_kind, CoreKind::Mihomo);
        assert_eq!(guidance.official_releases_url, MIHOMO_OFFICIAL_RELEASES_URL);
        assert!(guidance.verify_sha256_required);
        assert!(guidance.target_install_path.ends_with(mihomo_binary_name()));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn resolves_macos_bundle_linux_package_and_resource_dir_candidates() {
        let (root, paths, _) = make_temp_env("bundle-layouts");
        let bin_name = mihomo_binary_name();
        let cfg = AppConfig::default();

        // 1. macOS .app bundle: Contents/MacOS -> ../Resources/resources/bin/mihomo
        let mac_exe_dir = root.join("CatCloud.app").join("Contents").join("MacOS");
        let mac_res_nested = root
            .join("CatCloud.app")
            .join("Contents")
            .join("Resources")
            .join("resources")
            .join("bin")
            .join(bin_name);
        let mac_res_flat = root
            .join("CatCloud.app")
            .join("Contents")
            .join("Resources")
            .join("bin")
            .join(bin_name);
        std::fs::create_dir_all(&mac_exe_dir).unwrap();
        std::fs::create_dir_all(mac_res_nested.parent().unwrap()).unwrap();
        std::fs::create_dir_all(mac_res_flat.parent().unwrap()).unwrap();
        std::fs::write(&mac_res_nested, b"mac-nested").unwrap();
        std::fs::write(&mac_res_flat, b"mac-flat").unwrap();

        let r_mac1 =
            resolve_mihomo_binary_with_exe_dir(&cfg, &paths, Some(&mac_exe_dir), &[], false)
                .unwrap();
        assert!(r_mac1.found);
        assert_eq!(r_mac1.source, BinarySource::BundledResourcesBin);
        assert_eq!(
            r_mac1.path.unwrap(),
            crate::paths::normalize_os_path(&std::fs::canonicalize(&mac_res_nested).unwrap())
        );

        std::fs::remove_file(&mac_res_nested).unwrap();
        let r_mac2 =
            resolve_mihomo_binary_with_exe_dir(&cfg, &paths, Some(&mac_exe_dir), &[], false)
                .unwrap();
        assert!(r_mac2.found);
        assert_eq!(r_mac2.source, BinarySource::BundledResourcesBin);
        assert_eq!(
            r_mac2.path.unwrap(),
            crate::paths::normalize_os_path(&std::fs::canonicalize(&mac_res_flat).unwrap())
        );

        // 2. Linux package layout: usr/bin -> ../lib/CatCloud/resources/bin/mihomo
        let linux_exe_dir = root.join("usr").join("bin");
        let linux_lib_bin = root
            .join("usr")
            .join("lib")
            .join("CatCloud")
            .join("resources")
            .join("bin")
            .join(bin_name);
        std::fs::create_dir_all(&linux_exe_dir).unwrap();
        std::fs::create_dir_all(linux_lib_bin.parent().unwrap()).unwrap();
        std::fs::write(&linux_lib_bin, b"linux-lib").unwrap();

        let r_linux =
            resolve_mihomo_binary_with_exe_dir(&cfg, &paths, Some(&linux_exe_dir), &[], false)
                .unwrap();
        assert!(r_linux.found);
        assert_eq!(r_linux.source, BinarySource::BundledResourcesBin);
        assert_eq!(
            r_linux.path.unwrap(),
            crate::paths::normalize_os_path(&std::fs::canonicalize(&linux_lib_bin).unwrap())
        );

        // 3. Passing a Tauri resource_dir directory via extra_candidates resolves resources/bin/mihomo
        let empty_exe_dir = root.join("standalone");
        std::fs::create_dir_all(&empty_exe_dir).unwrap();
        let tauri_res_dir = root.join("tauri_resources");
        let tauri_res_bin = tauri_res_dir.join("resources").join("bin").join(bin_name);
        std::fs::create_dir_all(tauri_res_bin.parent().unwrap()).unwrap();
        std::fs::write(&tauri_res_bin, b"tauri-res").unwrap();

        let r_extra_dir = resolve_mihomo_binary_with_exe_dir(
            &cfg,
            &paths,
            Some(&empty_exe_dir),
            std::slice::from_ref(&tauri_res_dir),
            false,
        )
        .unwrap();
        assert!(r_extra_dir.found);
        assert_eq!(r_extra_dir.source, BinarySource::CandidatePath);
        assert_eq!(
            r_extra_dir.path.unwrap(),
            crate::paths::normalize_os_path(&std::fs::canonicalize(&tauri_res_bin).unwrap())
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn ensure_unix_executable_returns_false_for_missing_file() {
        let missing = std::env::temp_dir().join(format!(
            "catcloud-missing-bin-{}",
            Uuid::new_v4()
        ));
        assert!(!ensure_unix_executable(&missing));
    }

    #[cfg(unix)]
    #[test]
    fn resolves_user_data_bin_and_repairs_missing_unix_execute_bit() {
        use std::os::unix::fs::PermissionsExt;

        let (root, paths, exe_dir) = make_temp_env("unix-chmod");
        let data_bin = paths.bin_dir.join(mihomo_binary_name());
        std::fs::write(&data_bin, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&data_bin, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            std::fs::metadata(&data_bin).unwrap().permissions().mode() & 0o111,
            0
        );

        let cfg = AppConfig::default();
        let res = resolve_mihomo_binary_with_exe_dir(&cfg, &paths, Some(&exe_dir), &[], false)
            .unwrap();
        assert!(res.found);
        assert_eq!(res.source, BinarySource::UserDataBin);

        let repaired_mode = std::fs::metadata(&data_bin).unwrap().permissions().mode();
        assert_ne!(repaired_mode & 0o111, 0, "execute bit must be restored");
        assert_eq!(repaired_mode & 0o777, 0o755);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn resolves_parent_resources_bin_when_launched_from_portable_cli_subdir() {
        let (root, paths, _) = make_temp_env("cli-parent-res");
        let bin_name = mihomo_binary_name();
        let portable_root = root.join("CatCloud-Portable");
        let cli_dir = portable_root.join("cli");
        let tools_dir = portable_root.join("tools");
        let parent_res_bin = portable_root.join("resources").join("bin").join(bin_name);

        std::fs::create_dir_all(&cli_dir).unwrap();
        std::fs::create_dir_all(&tools_dir).unwrap();
        std::fs::create_dir_all(parent_res_bin.parent().unwrap()).unwrap();
        std::fs::write(&parent_res_bin, b"parent-res-mihomo").unwrap();

        let cfg = AppConfig::default();

        // 1. From `cli/`, resolves `../resources/bin/mihomo(.exe)` as BundledResourcesBin.
        let r_cli = resolve_mihomo_binary_with_exe_dir(&cfg, &paths, Some(&cli_dir), &[], false)
            .unwrap();
        assert!(r_cli.found);
        assert_eq!(r_cli.source, BinarySource::BundledResourcesBin);
        assert_eq!(
            r_cli.path.unwrap(),
            crate::paths::normalize_os_path(&std::fs::canonicalize(&parent_res_bin).unwrap())
        );

        // 2. Non-`cli` subdir does NOT check `../resources/bin` in checked_candidates.
        let r_tools =
            resolve_mihomo_binary_with_exe_dir(&cfg, &paths, Some(&tools_dir), &[], false)
                .unwrap();
        assert!(
            !r_tools.checked_candidates.contains(&parent_res_bin),
            "non-cli subdir must not include parent resources/bin candidate"
        );

        // 3. `UserDataBin` still takes precedence over `../resources/bin`.
        let data_bin = paths.bin_dir.join(bin_name);
        std::fs::write(&data_bin, b"user-data-mihomo").unwrap();
        let r_user = resolve_mihomo_binary_with_exe_dir(&cfg, &paths, Some(&cli_dir), &[], false)
            .unwrap();
        assert!(r_user.found);
        assert_eq!(r_user.source, BinarySource::UserDataBin);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn resolves_sibling_bin_when_launched_from_bundled_resources_cli_subdir() {
        let (root, paths, _) = make_temp_env("bundled-resources-cli");
        let bin_name = mihomo_binary_name();
        let res_root = root.join("AppBundle").join("resources");
        let cli_dir = res_root.join("cli");
        let sibling_bin = res_root.join("bin").join(bin_name);

        std::fs::create_dir_all(&cli_dir).unwrap();
        std::fs::create_dir_all(sibling_bin.parent().unwrap()).unwrap();
        std::fs::write(&sibling_bin, b"sibling-res-mihomo").unwrap();

        let cfg = AppConfig::default();
        let res = resolve_mihomo_binary_with_exe_dir(&cfg, &paths, Some(&cli_dir), &[], false)
            .unwrap();
        assert!(res.found);
        assert_eq!(res.source, BinarySource::BundledResourcesBin);
        assert_eq!(
            res.path.unwrap(),
            crate::paths::normalize_os_path(&std::fs::canonicalize(&sibling_bin).unwrap())
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
