#![cfg_attr(
    any(not(debug_assertions), feature = "custom-protocol"),
    windows_subsystem = "windows"
)]

use std::path::PathBuf;

use catcloud_core::AppPaths;

/// Resolve startup paths with portable priority (`--data-dir` > `CATCLOUD_DATA_DIR` >
/// sibling `portable.flag` > sibling `data/` > standard OS data directory) and a read-only
/// directory fallback so launches from protected paths (e.g. `Program Files`) do not crash.
fn resolve_startup_paths() -> AppPaths {
    let cli_data_dir = AppPaths::parse_cli_data_dir_from_args();
    let has_explicit_override = cli_data_dir.is_some()
        || std::env::var("CATCLOUD_DATA_DIR")
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);

    match AppPaths::resolve(cli_data_dir) {
        Ok(paths) if is_dir_writable(&paths.root_data_dir) => paths,
        Ok(paths) if has_explicit_override => {
            eprintln!(
                "[catcloud] explicit data dir `{}` may not be writable; continuing as requested",
                paths.root_data_dir.display()
            );
            paths
        }
        Ok(paths) => {
            eprintln!(
                "[catcloud] portable data dir `{}` is read-only; falling back to standard user data dir",
                paths.root_data_dir.display()
            );
            fallback_standard_paths()
        }
        Err(err) => {
            eprintln!(
                "[catcloud] failed to initialize preferred data dir ({err}); falling back to standard user data dir"
            );
            fallback_standard_paths()
        }
    }
}

fn is_dir_writable(dir: &std::path::Path) -> bool {
    let probe = dir.join(format!(".catcloud_write_probe.{}", std::process::id()));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

fn fallback_standard_paths() -> AppPaths {
    let fallback_root = standard_fallback_root();
    AppPaths::from_data_dir(fallback_root, false)
        .or_else(|_| {
            let temp_root = std::env::temp_dir().join("CatCloud");
            AppPaths::from_data_dir(temp_root, true)
        })
        .expect("failed to initialize any writable CatCloud data directory")
}

fn standard_fallback_root() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            if !appdata.trim().is_empty() {
                return PathBuf::from(appdata).join("CatCloud");
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            if !home.trim().is_empty() {
                return PathBuf::from(home)
                    .join("Library")
                    .join("Application Support")
                    .join("CatCloud");
            }
        }
    }
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        if !xdg.trim().is_empty() {
            return PathBuf::from(xdg).join("catcloud");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.trim().is_empty() {
            return PathBuf::from(home).join(".local").join("share").join("catcloud");
        }
    }
    std::env::temp_dir().join("CatCloud")
}

fn main() {
    // 1. Install Rustls ring CryptoProvider before any thread or network stack initializes.
    catcloud_core::init_crypto_provider();

    // 2. Resolve portable/sandbox/standard data layout while strictly single-threaded.
    let paths = resolve_startup_paths();

    // 3. On Windows, redirect WebView2 user data folder before Tauri Builder or WebView2 initializes.
    //    Elevated instances always use a separate `webview2_elevated` directory to prevent
    //    cross-IL lock/ACL blank screens on Windows 11.
    // SAFETY: Called at the very start of `main()` before any threads or Tokio runtimes spawn.
    #[cfg(target_os = "windows")]
    unsafe {
        catcloud_desktop_lib::lifecycle::set_webview2_user_data_env(&paths);
    }

    // 4. Hand off resolved paths to the Tauri desktop shell.
    catcloud_desktop_lib::run_with_paths(paths);
}
