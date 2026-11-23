mod commands;

use catcloud_core::AppPaths;
use clap::Parser;
use commands::Commands;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "catcloud",
    version,
    about = "CatCloud intelligent proxy headless CLI (zero GUI dependencies)"
)]
struct Cli {
    /// Override portable/runtime data directory
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Output machine-readable JSON
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

/// Resolve CLI runtime paths with portable priority and a read-only directory fallback
/// matching `src-tauri/src/main.rs` so launches from AppImage or protected install paths
/// (`Program Files`, `/usr/bin`) never crash on read-only portable directory probes.
fn resolve_cli_paths(cli_data_dir: Option<PathBuf>) -> anyhow::Result<AppPaths> {
    let has_explicit_override = cli_data_dir.is_some()
        || std::env::var("CATCLOUD_DATA_DIR")
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);

    match AppPaths::resolve(cli_data_dir) {
        Ok(paths) if is_dir_writable(&paths.root_data_dir) => Ok(paths),
        Ok(paths) if has_explicit_override => {
            eprintln!(
                "[catcloud] explicit data dir `{}` may not be writable; continuing as requested",
                paths.root_data_dir.display()
            );
            Ok(paths)
        }
        Ok(paths) => {
            eprintln!(
                "[catcloud] portable data dir `{}` is read-only; falling back to standard user data dir",
                paths.root_data_dir.display()
            );
            fallback_standard_paths()
        }
        Err(err) if has_explicit_override => Err(err.into()),
        Err(err) => {
            eprintln!(
                "[catcloud] failed to initialize preferred data dir ({err}); falling back to standard user data dir"
            );
            fallback_standard_paths()
        }
    }
}

fn is_dir_writable(dir: &Path) -> bool {
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

fn fallback_standard_paths() -> anyhow::Result<AppPaths> {
    let fallback_root = standard_fallback_root();
    AppPaths::from_data_dir(fallback_root, false)
        .or_else(|_| {
            let temp_root = std::env::temp_dir().join("CatCloud");
            AppPaths::from_data_dir(temp_root, true)
        })
        .map_err(Into::into)
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
            return PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("catcloud");
        }
    }
    std::env::temp_dir().join("CatCloud")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    catcloud_core::init_crypto_provider();
    let cli = Cli::parse();
    let paths = resolve_cli_paths(cli.data_dir)?;
    commands::dispatch(&paths, cli.json, cli.command).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_all_core_subcommands() {
        let cases: &[&[&str]] = &[
            &["catcloud", "status", "--json"],
            &["catcloud", "node", "list", "--region", "TW", "--max-multiplier", "1.0", "--json"],
            &["catcloud", "node", "migrate", "--scan", "--json"],
            &["catcloud", "node", "attach-process", "--list", "--json"],
            &["catcloud", "probe", "list", "--json"],
            &["catcloud", "probe", "run", "--tier", "l1", "--json"],
            &["catcloud", "probe", "run", "--tier", "l1", "--dry-run", "--json"],
            &["catcloud", "group", "list", "--json"],
            &["catcloud", "group", "create", "--id", "g1", "--name", "AI", "--mode", "sticky_best"],
            &["catcloud", "preaccel", "pool", "--json"],
            &["catcloud", "preaccel", "bind", "--enabled", "true", "--skip-443-native", "true"],
            &["catcloud", "preaccel", "global-status", "--json"],
            &["catcloud", "config", "validate", "--json"],
            &["catcloud", "config", "reload", "--dry-run", "--json"],
            &["catcloud", "config", "export-env", "--json"],
            &["catcloud", "config", "export-env", "--shell", "powershell", "--json"],
            &["catcloud", "config", "diag", "--json"],
            &["catcloud", "docs", "export", "preaccel", "--format", "json"],
            &["catcloud", "update", "check", "--json"],
            &["catcloud", "update", "check", "--offline", "--json"],
        ];
        for argv in cases {
            let parsed = Cli::try_parse_from(*argv);
            assert!(parsed.is_ok(), "failed to parse {argv:?}: {parsed:?}");
        }
    }

    #[test]
    fn cli_export_env_defaults_shell_by_target_platform() {
        let parsed = Cli::try_parse_from(["catcloud", "config", "export-env"]).expect("parse");
        let Commands::Config {
            action: commands::ConfigCommand::ExportEnv { shell },
        } = parsed.command
        else {
            panic!("expected Config::ExportEnv");
        };
        if cfg!(target_os = "windows") {
            assert_eq!(shell, "powershell");
        } else {
            assert_eq!(shell, "bash");
        }
    }

    #[test]
    fn is_dir_writable_succeeds_on_temp_dir_and_cleans_probe_file() {
        let dir = std::env::temp_dir().join(format!(
            "catcloud-cli-writable-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(is_dir_writable(&dir));
        let leftover = std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(leftover, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
