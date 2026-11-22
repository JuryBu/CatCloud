mod commands;

use clap::Parser;
use commands::Commands;

#[derive(Parser, Debug)]
#[command(
    name = "catcloud",
    version,
    about = "CatCloud intelligent proxy headless CLI (zero GUI dependencies)"
)]
struct Cli {
    /// Override portable/runtime data directory
    #[arg(long)]
    data_dir: Option<std::path::PathBuf>,

    /// Output machine-readable JSON
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    catcloud_core::init_crypto_provider();
    let cli = Cli::parse();
    let paths = catcloud_core::AppPaths::resolve(cli.data_dir)?;
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
            &["catcloud", "config", "validate", "--json"],
            &["catcloud", "config", "reload", "--dry-run", "--json"],
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
}
