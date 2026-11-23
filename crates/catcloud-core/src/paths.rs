use crate::error::{CatError, CatResult};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static ATOMIC_WRITE_SEQ: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "windows")]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn MoveFileExW(
        lp_existing_file_name: *const u16,
        lp_new_file_name: *const u16,
        dw_flags: u32,
    ) -> i32;
}

/// Strip Windows extended-length verbatim path prefix (`\\?\`) produced by
/// `std::fs::canonicalize`, preventing compatibility failures in Go subprocesses
/// (such as Mihomo `-d`/`-f`) and WebView2 user-data directories.
pub fn normalize_os_path(path: &Path) -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let s = path.to_string_lossy();
        if let Some(unc) = s.strip_prefix(r"\\?\UNC\") {
            return PathBuf::from(format!(r"\\{unc}"));
        }
        if let Some(stripped) = s.strip_prefix(r"\\?\") {
            return PathBuf::from(stripped);
        }
        path.to_path_buf()
    }
    #[cfg(not(target_os = "windows"))]
    {
        path.to_path_buf()
    }
}

/// Resolved runtime directory layout supporting CLI `--data-dir`, env `CATCLOUD_DATA_DIR`,
/// `portable.flag`, sibling `data/`, and standard OS app data fallback.
#[derive(Debug, Clone)]
pub struct AppPaths {
    pub root_data_dir: PathBuf,
    pub config_dir: PathBuf,
    pub db_path: PathBuf,
    pub config_path: PathBuf,
    pub runtime_dir: PathBuf,
    pub logs_dir: PathBuf,
    pub bin_dir: PathBuf,
    pub themes_dir: PathBuf,
    pub webview_dir: PathBuf,
    pub staging_dir: PathBuf,
    pub backup_dir: PathBuf,
    pub is_portable: bool,
    pub instance_hash: String,
}

impl AppPaths {
    /// Resolve runtime directories in strict priority order:
    /// 1. Explicit `--data-dir <PATH>` CLI argument
    /// 2. `CATCLOUD_DATA_DIR` environment variable
    /// 3. Portable mode (`<exe_dir>/portable.flag` or `<exe_dir>/data/` exists and writable)
    /// 4. Platform standard user data directory
    pub fn resolve(cli_data_dir: Option<PathBuf>) -> CatResult<Self> {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| PathBuf::from("."));

        let (root_data_dir, is_portable) = if let Some(dir) = cli_data_dir {
            (dir, true)
        } else if let Ok(env_dir) = std::env::var("CATCLOUD_DATA_DIR") {
            if !env_dir.trim().is_empty() {
                (PathBuf::from(env_dir), true)
            } else {
                Self::detect_portable_or_standard(&exe_dir)
            }
        } else {
            Self::detect_portable_or_standard(&exe_dir)
        };

        Self::from_data_dir(root_data_dir, is_portable)
    }

    fn detect_portable_or_standard(exe_dir: &Path) -> (PathBuf, bool) {
        let flag = exe_dir.join("portable.flag");
        let sibling_data = exe_dir.join("data");
        if flag.is_file() || sibling_data.is_dir() {
            return (sibling_data, true);
        }
        let std_dir = Self::standard_os_data_dir();
        (std_dir, false)
    }

    fn standard_os_data_dir() -> PathBuf {
        #[cfg(target_os = "windows")]
        {
            if let Ok(appdata) = std::env::var("APPDATA") {
                return PathBuf::from(appdata).join("CatCloud");
            }
        }
        #[cfg(target_os = "macos")]
        {
            if let Ok(home) = std::env::var("HOME") {
                return PathBuf::from(home)
                    .join("Library")
                    .join("Application Support")
                    .join("CatCloud");
            }
        }
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            if !xdg.trim().is_empty() {
                return PathBuf::from(xdg).join("catcloud");
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(".local").join("share").join("catcloud");
        }
        PathBuf::from("data")
    }

    pub fn from_data_dir(root_data_dir: PathBuf, is_portable: bool) -> CatResult<Self> {
        std::fs::create_dir_all(&root_data_dir)?;
        let canonical = normalize_os_path(
            &std::fs::canonicalize(&root_data_dir).unwrap_or(root_data_dir.clone()),
        );
        let mut hasher = Sha256::new();
        hasher.update(canonical.to_string_lossy().to_lowercase().as_bytes());
        let digest = hex::encode(hasher.finalize());
        let instance_hash = digest[..8].to_string();

        let paths = Self {
            config_dir: canonical.join("config"),
            db_path: canonical.join("catcloud.sqlite"),
            config_path: canonical.join("config.json"),
            runtime_dir: canonical.join("run"),
            logs_dir: canonical.join("logs"),
            bin_dir: canonical.join("bin"),
            themes_dir: canonical.join("themes"),
            webview_dir: canonical.join("webview2"),
            staging_dir: canonical.join(".update_staging"),
            backup_dir: canonical.join(".update_backup"),
            root_data_dir: canonical,
            is_portable,
            instance_hash,
        };
        paths.ensure_dirs()?;
        Ok(paths)
    }

    pub fn ensure_dirs(&self) -> CatResult<()> {
        for dir in [
            &self.root_data_dir,
            &self.config_dir,
            &self.runtime_dir,
            &self.logs_dir,
            &self.bin_dir,
            &self.themes_dir,
            &self.webview_dir,
        ] {
            std::fs::create_dir_all(dir)?;
        }
        Ok(())
    }

    /// Resolve the effective WebView2 user-data directory for the current privilege level.
    /// Elevated Windows processes use a dedicated `webview2_elevated` directory so High IL and
    /// Medium IL instances never collide on WebView2 profile locks or ACLs.
    pub fn effective_webview_dir(&self, is_elevated: bool) -> PathBuf {
        if is_elevated {
            self.root_data_dir.join("webview2_elevated")
        } else {
            self.webview_dir.clone()
        }
    }

    /// Parse `--data-dir <PATH>` from raw process args before Tauri initializes.
    pub fn parse_cli_data_dir_from_args() -> Option<PathBuf> {
        let mut args = std::env::args_os().skip(1);
        while let Some(arg) = args.next() {
            let s = arg.to_string_lossy();
            if s == "--data-dir" {
                return args.next().map(PathBuf::from);
            }
            if let Some(rest) = s.strip_prefix("--data-dir=") {
                if !rest.is_empty() {
                    return Some(PathBuf::from(rest));
                }
            }
        }
        None
    }

    /// Atomic file write: write `<path>.tmp.<pid>.<seq>`, sync to disk, then replace target.
    /// On Windows uses `MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)` with
    /// short backoff retries on transient lock errors (`ERROR_ACCESS_DENIED` / `ERROR_SHARING_VIOLATION`)
    /// and never deletes the target before rename, preserving the existing file on failure.
    pub fn atomic_write(path: &Path, bytes: &[u8]) -> CatResult<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let pid = std::process::id();
        let seq = ATOMIC_WRITE_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp_name = format!(
            "{}.tmp.{}.{}",
            path.file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| CatError::Config("invalid target filename".into()))?,
            pid,
            seq
        );
        let tmp_path = path.with_file_name(tmp_name);
        let write_res: std::io::Result<()> = (|| {
            use std::io::Write as _;
            let mut file = std::fs::File::create(&tmp_path)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            Ok(())
        })();
        if let Err(err) = write_res {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(CatError::Io(err));
        }

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::ffi::OsStrExt as _;
            // MOVEFILE_REPLACE_EXISTING (0x1) | MOVEFILE_WRITE_THROUGH (0x8)
            const MOVEFILE_REPLACE_EXISTING_WRITE_THROUGH: u32 = 0x9;
            const ERROR_ACCESS_DENIED: i32 = 5;
            const ERROR_SHARING_VIOLATION: i32 = 32;
            const RETRY_DELAYS_MS: [u64; 5] = [10, 20, 40, 60, 80];

            let src_wide: Vec<u16> = tmp_path
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let dst_wide: Vec<u16> = path
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let mut last_err: Option<std::io::Error> = None;
            for attempt in 0..=RETRY_DELAYS_MS.len() {
                // SAFETY: Both paths are valid NUL-terminated UTF-16 slices and `tmp_path` is closed.
                let moved = unsafe {
                    MoveFileExW(
                        src_wide.as_ptr(),
                        dst_wide.as_ptr(),
                        MOVEFILE_REPLACE_EXISTING_WRITE_THROUGH,
                    )
                };
                if moved != 0 {
                    return Ok(());
                }

                let os_err = std::io::Error::last_os_error();
                let is_retryable = matches!(
                    os_err.raw_os_error(),
                    Some(ERROR_ACCESS_DENIED | ERROR_SHARING_VIOLATION)
                );
                last_err = Some(os_err);

                if is_retryable && attempt < RETRY_DELAYS_MS.len() {
                    std::thread::sleep(std::time::Duration::from_millis(RETRY_DELAYS_MS[attempt]));
                    continue;
                }
                break;
            }

            let retryable_exhausted = last_err
                .as_ref()
                .and_then(std::io::Error::raw_os_error)
                .is_some_and(|code| matches!(code, ERROR_ACCESS_DENIED | ERROR_SHARING_VIOLATION));

            // Non-destructive atomic fallback only if MoveFileExW rejected WRITE_THROUGH on an
            // unusual filesystem; never delete `path` before rename.
            if !retryable_exhausted && std::fs::rename(&tmp_path, path).is_ok() {
                return Ok(());
            }

            let _ = std::fs::remove_file(&tmp_path);
            Err(CatError::Io(last_err.unwrap_or_else(|| {
                std::io::Error::other("MoveFileExW failed")
            })))
        }
        #[cfg(not(target_os = "windows"))]
        {
            if let Err(err) = std::fs::rename(&tmp_path, path) {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(CatError::Io(err));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_replaces_existing_file_cleanly_without_leftover_tmp() {
        let dir = std::env::temp_dir().join(format!(
            "catcloud-atomic-write-test-{}",
            uuid::Uuid::new_v4()
        ));
        let target = dir.join("config.json");

        AppPaths::atomic_write(&target, b"{\"v\":1}").expect("first atomic write");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "{\"v\":1}");

        AppPaths::atomic_write(&target, b"{\"v\":2,\"ok\":true}").expect("second atomic overwrite");
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "{\"v\":2,\"ok\":true}"
        );

        let leftovers = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .count();
        assert_eq!(leftovers, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn effective_webview_dir_separates_elevated_and_standard_profiles() {
        let dir = std::env::temp_dir().join(format!(
            "catcloud-webview-dir-test-{}",
            uuid::Uuid::new_v4()
        ));
        let paths = AppPaths::from_data_dir(dir.clone(), true).expect("init AppPaths");

        assert_eq!(paths.effective_webview_dir(false), paths.webview_dir);
        assert_eq!(
            paths.effective_webview_dir(true),
            paths.root_data_dir.join("webview2_elevated")
        );
        assert_ne!(
            paths.effective_webview_dir(false),
            paths.effective_webview_dir(true)
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn atomic_write_preserves_existing_file_and_cleans_tmp_on_sharing_violation() {
        use std::os::windows::fs::OpenOptionsExt as _;

        let dir = std::env::temp_dir().join(format!(
            "catcloud-atomic-lock-test-{}",
            uuid::Uuid::new_v4()
        ));
        let target = dir.join("config.json");
        AppPaths::atomic_write(&target, b"{\"stable\":true}").expect("initial write");

        // Hold an exclusive handle (share_mode = 0) to trigger ERROR_SHARING_VIOLATION (32).
        let lock_handle = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&target)
            .expect("open exclusive lock handle");

        let err = AppPaths::atomic_write(&target, b"{\"stable\":false}")
            .expect_err("atomic write must fail while target is exclusively locked");
        assert!(matches!(err, CatError::Io(_)));

        let leftovers = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .count();
        assert_eq!(leftovers, 0, "temporary file must be cleaned up on failure");

        drop(lock_handle);

        // Original file contents must remain intact after failed atomic replacement.
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "{\"stable\":true}"
        );

        // Once unlocked, subsequent atomic write succeeds cleanly.
        AppPaths::atomic_write(&target, b"{\"stable\":2}").expect("write after unlock");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "{\"stable\":2}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn normalize_os_path_strips_windows_verbatim_prefix() {
        #[cfg(target_os = "windows")]
        {
            assert_eq!(
                normalize_os_path(Path::new(r"\\?\C:\Users\Public\CatCloud\data")),
                PathBuf::from(r"C:\Users\Public\CatCloud\data")
            );
            assert_eq!(
                normalize_os_path(Path::new(r"\\?\UNC\server\share\catcloud")),
                PathBuf::from(r"\\server\share\catcloud")
            );
            assert_eq!(
                normalize_os_path(Path::new(r"C:\Users\Public\CatCloud\data")),
                PathBuf::from(r"C:\Users\Public\CatCloud\data")
            );
        }
        #[cfg(not(target_os = "windows"))]
        {
            assert_eq!(
                normalize_os_path(Path::new("/var/lib/catcloud")),
                PathBuf::from("/var/lib/catcloud")
            );
        }
    }
}
