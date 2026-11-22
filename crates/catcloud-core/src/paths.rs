use crate::error::{CatError, CatResult};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

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

    /// Atomic file write: write `<path>.tmp.<pid>` then rename to target.
    pub fn atomic_write(path: &Path, bytes: &[u8]) -> CatResult<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let pid = std::process::id();
        let tmp_name = format!(
            "{}.tmp.{}",
            path.file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| CatError::Config("invalid target filename".into()))?,
            pid
        );
        let tmp_path = path.with_file_name(tmp_name);
        std::fs::write(&tmp_path, bytes)?;
        #[cfg(target_os = "windows")]
        {
            if path.exists() {
                let _ = std::fs::remove_file(path);
            }
        }
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
