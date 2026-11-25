mod commands;

use catcloud_core::AppPaths;
use catcloud_core::sanitize::{redact_path_for_display, sanitize_log_line};
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

/// Format a sanitized machine-readable JSON error envelope for `--json` mode.
pub(crate) fn format_json_error(raw_error: &str) -> String {
    let sanitized = sanitize_log_line(raw_error);
    serde_json::to_string(&serde_json::json!({
        "ok": false,
        "error": sanitized,
    }))
    .unwrap_or_else(|_| "{\"ok\":false,\"error\":\"internal error\"}".to_string())
}

fn has_json_flag_in_args<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    args.into_iter().skip(1).any(|a| a.as_ref() == "--json")
}

fn emit_fatal_error(as_json: bool, err: &anyhow::Error) {
    if as_json {
        if err
            .downcast_ref::<commands::AlreadyEmittedJsonError>()
            .is_some()
        {
            return;
        }
        println!("{}", format_json_error(&format!("{err:#}")));
    } else {
        eprintln!("Error: {}", sanitize_log_line(&format!("{err:#}")));
    }
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
                redact_path_for_display(&paths.root_data_dir.to_string_lossy())
            );
            Ok(paths)
        }
        Ok(paths) => {
            eprintln!(
                "[catcloud] portable data dir `{}` is read-only; falling back to standard user data dir",
                redact_path_for_display(&paths.root_data_dir.to_string_lossy())
            );
            fallback_standard_paths()
        }
        Err(err) if has_explicit_override => Err(err.into()),
        Err(err) => {
            eprintln!(
                "[catcloud] failed to initialize preferred data dir ({}); falling back to standard user data dir",
                sanitize_log_line(&err.to_string())
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
async fn main() {
    catcloud_core::init_crypto_provider();
    let cli = match Cli::try_parse() {
        Ok(parsed) => parsed,
        Err(err) => {
            if matches!(
                err.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) {
                err.exit();
            }
            if has_json_flag_in_args(std::env::args_os()) {
                println!("{}", format_json_error(&err.to_string()));
                std::process::exit(1);
            }
            err.exit();
        }
    };

    let paths = match resolve_cli_paths(cli.data_dir) {
        Ok(p) => p,
        Err(err) => {
            emit_fatal_error(cli.json, &err);
            std::process::exit(1);
        }
    };

    if let Err(err) = commands::dispatch(&paths, cli.json, cli.command).await {
        emit_fatal_error(cli.json, &err);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use catcloud_core::models::{PreAccelRelay, ProxyNode, SubscriptionKind, SubscriptionRecord};
    use catcloud_core::sanitize::{
        redact_compiled_yaml, redact_node_for_readonly, redact_relay_for_readonly,
    };

    #[test]
    fn cli_parses_all_core_subcommands() {
        let cases: &[&[&str]] = &[
            &["catcloud", "status", "--json"],
            &[
                "catcloud",
                "node",
                "list",
                "--region",
                "TW",
                "--max-multiplier",
                "1.0",
                "--json",
            ],
            &["catcloud", "node", "list", "--reveal-secrets", "--json"],
            &["catcloud", "node", "migrate", "--scan", "--json"],
            &["catcloud", "node", "attach-process", "--list", "--json"],
            &["catcloud", "probe", "list", "--json"],
            &["catcloud", "probe", "run", "--tier", "l1", "--json"],
            &[
                "catcloud",
                "probe",
                "run",
                "--tier",
                "l1",
                "--dry-run",
                "--json",
            ],
            &["catcloud", "group", "list", "--json"],
            &[
                "catcloud",
                "group",
                "create",
                "--id",
                "g1",
                "--name",
                "AI",
                "--mode",
                "sticky_best",
            ],
            &["catcloud", "preaccel", "pool", "--json"],
            &[
                "catcloud",
                "preaccel",
                "pool",
                "--reveal-secrets",
                "--json",
            ],
            &[
                "catcloud",
                "preaccel",
                "bind",
                "--enabled",
                "true",
                "--skip-443-native",
                "true",
            ],
            &["catcloud", "preaccel", "global-status", "--json"],
            &["catcloud", "preaccel", "test", "--json"],
            &["catcloud", "preaccel", "test", "--campus", "--json"],
            &["catcloud", "preaccel", "test", "--speed", "--json"],
            &[
                "catcloud",
                "preaccel",
                "test",
                "--speed",
                "--node-id",
                "node-jp-01",
                "--json",
            ],
            &["catcloud", "config", "validate", "--json"],
            &["catcloud", "config", "reload", "--dry-run", "--json"],
            &["catcloud", "config", "compile", "--json"],
            &[
                "catcloud",
                "config",
                "compile",
                "--reveal-secrets",
                "--json",
            ],
            &["catcloud", "config", "export-env", "--json"],
            &[
                "catcloud",
                "config",
                "export-env",
                "--shell",
                "powershell",
                "--json",
            ],
            &["catcloud", "config", "diag", "--json"],
            &["catcloud", "config", "diag", "--reveal-secrets", "--json"],
            &[
                "catcloud",
                "config",
                "backup",
                "--output",
                "backup.json",
                "--json",
            ],
            &[
                "catcloud",
                "config",
                "restore",
                "--input",
                "backup.json",
                "--json",
            ],
            &[
                "catcloud",
                "config",
                "restore",
                "--file",
                "backup.json",
                "--json",
            ],
            &["catcloud", "docs", "list", "--json"],
            &["catcloud", "docs", "list", "--lang", "en", "--json"],
            &["catcloud", "docs", "export", "preaccel", "--format", "json"],
            &[
                "catcloud",
                "docs",
                "export",
                "troubleshooting",
                "--lang",
                "ja",
                "--format",
                "markdown",
            ],
            &[
                "catcloud",
                "docs",
                "export",
                "--sync-dir",
                "out-docs",
                "--json",
            ],
            &["catcloud", "update", "check", "--json"],
            &["catcloud", "update", "check", "--offline", "--json"],
        ];
        for argv in cases {
            let parsed = Cli::try_parse_from(*argv);
            assert!(parsed.is_ok(), "failed to parse {argv:?}: {parsed:?}");
        }
    }

    #[test]
    fn cli_parses_all_stage14_stethoscope_sub_and_share_subcommands() {
        let cases: &[&[&str]] = &[
            &["catcloud", "net", "doctor", "--json"],
            &["catcloud", "net", "connections", "--json"],
            &["catcloud", "net", "connections", "--limit", "25", "--json"],
            &["catcloud", "net", "match", "api.openai.com", "--json"],
            &[
                "catcloud",
                "net",
                "match",
                "qq.com",
                "--network",
                "udp",
                "--port",
                "443",
                "--json",
            ],
            &["catcloud", "logs", "tail", "--json"],
            &[
                "catcloud",
                "logs",
                "tail",
                "--lines",
                "120",
                "--level",
                "warning",
                "--json",
            ],
            &["catcloud", "sub", "list", "--json"],
            &["catcloud", "sub", "refresh", "--json"],
            &["catcloud", "sub", "refresh", "--id", "sub-main", "--json"],
            &["catcloud", "sub", "refresh", "sub-main", "--json"],
            &["catcloud", "sub", "remove", "sub-old", "--json"],
            &[
                "catcloud",
                "sub",
                "rename",
                "sub-main",
                "--name",
                "Primary Feed",
                "--json",
            ],
            &[
                "catcloud",
                "sub",
                "merge",
                "--source",
                "sub-a",
                "--target",
                "sub-b",
                "--name",
                "Merged Feed",
                "--no-dedup",
                "--json",
            ],
            &[
                "catcloud",
                "share",
                "export",
                "--output",
                "friend.zip",
                "--name",
                "Starter Pack",
                "--node-ids",
                "n1,n2",
                "--sub-id",
                "sub-a",
                "--relay-ids",
                "r1,r2",
                "--all-relays",
                "--json",
            ],
            &[
                "catcloud",
                "share",
                "export",
                "--output",
                "friend.zip",
                "--nodes",
                "n1,n2",
                "--relays",
                "r1",
                "--json",
            ],
            &["catcloud", "share", "inspect", "friend.zip", "--json"],
            &[
                "catcloud",
                "share",
                "inspect",
                "--file",
                "friend.zip",
                "--json",
            ],
            &["catcloud", "share", "import", "friend.zip", "--json"],
            &[
                "catcloud",
                "share",
                "import",
                "friend.zip",
                "--dry-run",
                "--json",
            ],
            &[
                "catcloud",
                "share",
                "import",
                "--file",
                "friend.zip",
                "--apply",
                "--target-sub",
                "sub-b",
                "--name",
                "Updated Pack",
                "--mode",
                "replace",
                "--no-relays",
                "--json",
            ],
            &[
                "catcloud",
                "share",
                "import",
                "friend.zip",
                "--apply",
                "--mode",
                "merge",
                "--no-nodes",
                "--json",
            ],
        ];
        for argv in cases {
            let parsed = Cli::try_parse_from(*argv);
            assert!(parsed.is_ok(), "failed to parse {argv:?}: {parsed:?}");
        }
    }

    #[test]
    fn reveal_secrets_flags_default_to_false() {
        let node_cli = Cli::try_parse_from(["catcloud", "node", "list"]).expect("node list");
        let Commands::Node {
            action: commands::NodeCommand::List(args),
        } = node_cli.command
        else {
            panic!("expected Node::List");
        };
        assert!(!args.reveal_secrets);

        let pool_cli = Cli::try_parse_from(["catcloud", "preaccel", "pool"]).expect("pool");
        let Commands::Preaccel {
            action: commands::PreaccelCommand::Pool { reveal_secrets },
        } = pool_cli.command
        else {
            panic!("expected Preaccel::Pool");
        };
        assert!(!reveal_secrets);

        let compile_cli =
            Cli::try_parse_from(["catcloud", "config", "compile"]).expect("config compile");
        let Commands::Config {
            action: commands::ConfigCommand::Compile { reveal_secrets, .. },
        } = compile_cli.command
        else {
            panic!("expected Config::Compile");
        };
        assert!(!reveal_secrets);

        let diag_cli = Cli::try_parse_from(["catcloud", "config", "diag"]).expect("config diag");
        let Commands::Config {
            action: commands::ConfigCommand::Diag { reveal_secrets },
        } = diag_cli.command
        else {
            panic!("expected Config::Diag");
        };
        assert!(!reveal_secrets);

        let probe_cli = Cli::try_parse_from(["catcloud", "probe", "run", "--dry-run"])
            .expect("probe run dry-run");
        let Commands::Probe {
            action: commands::ProbeCommand::Run(args),
        } = probe_cli.command
        else {
            panic!("expected Probe::Run");
        };
        assert!(!args.reveal_secrets);
    }

    #[test]
    fn preaccel_test_speed_and_node_id_flags_parse_correctly() {
        let default_cli =
            Cli::try_parse_from(["catcloud", "preaccel", "test"]).expect("preaccel test default");
        let Commands::Preaccel {
            action:
                commands::PreaccelCommand::Test {
                    campus,
                    speed,
                    node_id,
                },
        } = default_cli.command
        else {
            panic!("expected Preaccel::Test");
        };
        assert!(!campus);
        assert!(!speed);
        assert!(node_id.is_none());

        let speed_cli = Cli::try_parse_from([
            "catcloud",
            "preaccel",
            "test",
            "--speed",
            "--node-id",
            "node-jp-01",
            "--campus",
            "--json",
        ])
        .expect("preaccel test --speed --node-id");
        assert!(speed_cli.json);
        let Commands::Preaccel {
            action:
                commands::PreaccelCommand::Test {
                    campus,
                    speed,
                    node_id,
                },
        } = speed_cli.command
        else {
            panic!("expected Preaccel::Test");
        };
        assert!(campus);
        assert!(speed);
        assert_eq!(node_id.as_deref(), Some("node-jp-01"));
    }

    #[test]
    fn json_error_envelope_is_valid_json_and_sanitizes_secrets_paths_and_ips() {
        let raw = concat!(
            "failed to fetch https://user:secretpass@sub.example.invalid/feed?token=tok_demo_123 ",
            "from C:\\Users\\Administrator\\CatCloud\\config.json ",
            "via 203.0.113.42 Authorization: Bearer demo_jwt_value"
        );
        let rendered = format_json_error(raw);
        let parsed: serde_json::Value =
            serde_json::from_str(&rendered).expect("format_json_error must emit valid JSON");
        assert_eq!(parsed["ok"], serde_json::json!(false));
        let err_text = parsed["error"].as_str().expect("error string");
        assert!(!err_text.contains("secretpass"));
        assert!(!err_text.contains("tok_demo_123"));
        assert!(!err_text.contains("demo_jwt_value"));
        assert!(!err_text.contains("Administrator"));
        assert!(!err_text.contains("203.0.113.42"));
        assert!(err_text.contains("<REDACTED>"));
        assert!(err_text.contains("<USER>"));
        assert!(err_text.contains("203.0.113.*"));
    }

    #[test]
    fn default_readonly_sanitization_masks_relays_nodes_yaml_and_subscriptions() {
        let relay = PreAccelRelay {
            id: "relay-1".to_string(),
            name: "CN-443".to_string(),
            server: "198.51.100.25".to_string(),
            port: 443,
            protocol: "anytls".to_string(),
            password: "relay_secret_pw".to_string(),
            ..PreAccelRelay::default()
        };
        let masked_relay = redact_relay_for_readonly(&relay);
        assert_eq!(masked_relay.server, "198.51.100.*");
        assert_eq!(masked_relay.password, "<REDACTED>");

        let node = ProxyNode {
            id: "n-1".to_string(),
            sub_id: "sub-1".to_string(),
            name: "JP-01".to_string(),
            protocol: "vless".to_string(),
            server: "edge.vendor.example".to_string(),
            port: 443,
            raw_config: serde_json::json!({
                "type": "vless",
                "server": "edge.vendor.example",
                "uuid": "00000000-0000-4000-8000-000000000099",
                "password": "node_secret_pw"
            }),
            ..ProxyNode::default()
        };
        let masked_node = redact_node_for_readonly(&node);
        assert_eq!(masked_node.server, "***.example");
        assert_eq!(masked_node.raw_config["uuid"], "<REDACTED>");
        assert_eq!(masked_node.raw_config["password"], "<REDACTED>");

        let yaml = "secret: ctrl_secret_999\nproxies:\n  - name: JP\n    server: 203.0.113.55\n    password: yaml_secret_pw\n";
        let masked_yaml = redact_compiled_yaml(yaml);
        assert!(!masked_yaml.contains("ctrl_secret_999"));
        assert!(!masked_yaml.contains("yaml_secret_pw"));
        assert!(!masked_yaml.contains("203.0.113.55"));
        assert!(masked_yaml.contains("203.0.113.*"));

        let sub = SubscriptionRecord {
            id: "sub-1".to_string(),
            name: "Main".to_string(),
            kind: SubscriptionKind::Url,
            url_or_cmd: "https://acct:pw@sub.vendor.example/api/v1?token=tok_12345&flag=ok"
                .to_string(),
            last_error: Some("failed at C:\\Users\\Administrator\\sub.yaml".to_string()),
            ..SubscriptionRecord::default()
        };
        let masked_sub = commands::redact_subscription_for_readonly(&sub);
        assert!(!masked_sub.url_or_cmd.contains("pw"));
        assert!(!masked_sub.url_or_cmd.contains("tok_12345"));
        assert!(!masked_sub.url_or_cmd.contains("vendor"));
        assert!(
            !masked_sub
                .last_error
                .as_deref()
                .unwrap_or_default()
                .contains("Administrator")
        );
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
