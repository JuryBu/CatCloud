use anyhow::{Context, Result};
use catcloud_core::agent_docs;
use catcloud_core::config::{self, ConfigValidationIssue, ValidationSeverity};
use catcloud_core::core_adapter::config_compiler::{
    CompileInput, StaticCheckIssue, StaticValidationReport, compile_mihomo_config,
    compile_mihomo_config_with_runtime_dir, validate_compiled_yaml,
};
use catcloud_core::core_adapter::port_guard::{
    AllocatedPorts, allocate_safe_ports, is_port_available_tcp_udp,
};
use catcloud_core::core_adapter::{
    ActiveConnection, BinaryResolution, DiskReloadOptions, DownloadGuidance, HotReloadCoordinator,
    MihomoAdapter, ReloadOutcome, ResolvedControllerEndpoint, compute_file_sha256,
    format_host_port, generate_controller_secret, resolve_effective_controller_endpoint_info,
    resolve_mihomo_binary, verify_config_with_binary,
};
use catcloud_core::models::{
    AppConfig, DEFAULT_COST_EFFECTIVE_FORMULA, FallbackPolicy, MultiGroup, MultiGroupMode,
    NodeFilter, PreAccelConfig, PreAccelRelay, ProbeDefinition, ProbeKind, ProxyMode, ProxyNode,
    RouteTargetMode, SubscriptionKind, SubscriptionRecord, SwitchMode,
};
use catcloud_core::platform::default_platform;
use catcloud_core::preaccel::campus::{CampusBypassTracker, probe_campus_portal};
use catcloud_core::preaccel::generator::{build_preaccel_compile_plan, validate_domestic_probe_url};
use catcloud_core::preaccel::global_tunnel::{
    detect_host_security_products, locate_windivert_files,
};
use catcloud_core::preaccel::schema::{
    evaluate_expiry, parse_mmrelay_clipboard, validate_relay_strict,
};
use catcloud_core::probe::registry::{FunnelTier, ProbeRegistry, validate_definition};
use catcloud_core::probe::{
    DEFAULT_READY_TIMEOUT, FunnelOptions, FunnelRunReport, IsolatedProbeCore,
    ThroughputProbeConfig, build_isolated_http_client, run_download_probe_with_config,
    run_funnel_for_node, run_latency_probe, run_upload_probe_with_config,
};
use catcloud_core::process_guard::JobGuard;
use catcloud_core::sanitize::{
    redact_compiled_yaml, redact_ip_or_host, redact_node_for_readonly, redact_path_for_display,
    redact_relay_for_readonly, sanitize_log_line,
};
use catcloud_core::share_bundle::{
    ShareBundleExportRequest, export_share_bundle_zip_file, preview_share_bundle_zip_file,
};
use catcloud_core::storage::{Storage, SubscriptionUpdateMode};
use catcloud_core::strategy::arbiter::{ArbiterGroupMemory, decide_group_action};
use catcloud_core::strategy::evaluator::evaluate_group_candidates;
use catcloud_core::strategy::formula::validate_formula;
use catcloud_core::subscription::migrator::{
    MigrationImportOptions, MigrationPreview, generate_migration_subscription_id,
    import_migration_preview, scan_custom_path_readonly, scan_local_clients,
};
use catcloud_core::subscription::parser::{
    FetchOptions, apply_parsed_subscription, fetch_and_parse_subscription_with_fallback,
    parse_subscription_payload,
};
use catcloud_core::subscription::process_attach::{
    AttachRecommendation, ProcessCandidate, ProcessInspectionResult, inspect_process_source,
    list_process_candidates,
};
use catcloud_core::updater::{
    LatestManifest, MAX_METADATA_BYTES, MAX_ZIP_BYTES, PlatformAsset, Updater,
    current_update_platform_key_opt, is_update_available_for_channel, parse_latest_manifest,
    parse_sha256sums, read_pending_staged_update, resolve_asset_sha256, stage_verified_archive,
};
use catcloud_core::{AppPaths, CatError, CatResult};
use chrono::Utc;
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// Marker error indicating that a command in `--json` mode has already emitted a structured
/// `{"ok":false,...}` payload to stdout so `main()` exits non-zero without printing duplicate JSON.
#[derive(Debug)]
pub struct AlreadyEmittedJsonError(pub String);

impl std::fmt::Display for AlreadyEmittedJsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AlreadyEmittedJsonError {}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Print core runtime status, data paths, and storage counts
    Status,
    /// Manage multi-provider proxy nodes, imports, readonly migrations, and process attachment
    Node {
        #[command(subcommand)]
        action: NodeCommand,
    },
    /// Manage subscription groups (list, refresh, remove, rename, merge)
    Sub {
        #[command(subcommand)]
        action: SubCommand,
    },
    /// Manage extensible probe definitions and isolated probe plans
    Probe {
        #[command(subcommand)]
        action: ProbeCommand,
    },
    /// Manage smart multi-groups, scoring formulas, fallbacks, and node switching
    Group {
        #[command(subcommand)]
        action: GroupCommand,
    },
    /// Manage domestic :443 pre-acceleration relays, bindings, and campus portal checks
    Preaccel {
        #[command(subcommand)]
        action: PreaccelCommand,
    },
    /// Layered read-only network diagnostics, live connections, and rule match simulation
    Net {
        #[command(subcommand)]
        action: NetCommand,
    },
    /// Read sanitized CatCloud runtime logs
    Logs {
        #[command(subcommand)]
        action: LogsCommand,
    },
    /// Validate, compile, reload, backup/restore configuration, export env, or dump diagnostics
    Config {
        #[command(subcommand)]
        action: ConfigCommand,
    },
    /// List, export, or sync authoritative multi-language AI Agent guides embedded in CatCloud
    Docs {
        #[command(subcommand)]
        action: DocsCommand,
    },
    /// Export, inspect, or import selective catcloud-share/v1 .zip share bundles
    Share {
        #[command(subcommand)]
        action: ShareCommand,
    },
    /// Check or stage verified updates from GitHub Releases
    Update {
        #[command(subcommand)]
        action: UpdateCommand,
    },
}

#[derive(Subcommand, Debug)]
pub enum NodeCommand {
    /// Query nodes with multi-dimensional filters
    List(NodeListArgs),
    /// Import nodes from a local YAML/URI file or remote subscription URL
    Import(NodeImportArgs),
    /// Read-only scan or import from existing open-source proxy clients
    Migrate(NodeMigrateArgs),
    /// Read-only list running processes or inspect a PID for config/controller attachment
    AttachProcess(NodeAttachArgs),
}

#[derive(Subcommand, Debug)]
pub enum SubCommand {
    /// List all subscription groups (redacted URLs and paths by default)
    List,
    /// Refresh one subscription by ID or all enabled subscriptions
    Refresh {
        /// Optional positional subscription ID to refresh
        sub_id: Option<String>,
        /// Optional --id flag (equivalent to positional sub_id)
        #[arg(long = "id", conflicts_with = "sub_id")]
        id: Option<String>,
    },
    /// Remove a subscription group and all its nodes
    Remove { sub_id: String },
    /// Rename an existing subscription group in place
    Rename {
        sub_id: String,
        #[arg(long)]
        name: String,
    },
    /// Transactionally merge source subscription group into target group
    Merge {
        #[arg(long)]
        source: String,
        #[arg(long)]
        target: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        no_dedup: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum NetCommand {
    /// Run pure read-only layered diagnostics across paths, config, core, ports, proxy/TUN, preaccel, conflicts, and GeoData
    Doctor,
    /// Query active connections from the running Mihomo controller (redacted by default)
    Connections {
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Simulate or query which routing rule and outbound policy a domain or IP matches
    Match {
        domain: String,
        /// Transport protocol for rule evaluation (tcp or udp)
        #[arg(long, default_value = "tcp")]
        network: String,
        /// Destination port for rule evaluation
        #[arg(long, default_value_t = 443)]
        port: u16,
    },
}

#[derive(Subcommand, Debug)]
pub enum LogsCommand {
    /// Read sanitized tail lines from catcloud.log (and .1 archive)
    Tail {
        #[arg(long, default_value_t = 80)]
        lines: usize,
        #[arg(long, default_value = "all")]
        level: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum ShareCommand {
    /// Export selected nodes and/or domestic :443 relays to a catcloud-share/v1 .zip archive
    Export(ShareExportArgs),
    /// Read-only sanitized preview of a catcloud-share/v1 .zip share bundle
    Inspect {
        /// Path to .zip share bundle
        file_pos: Option<PathBuf>,
        /// Path to .zip share bundle (flag form)
        #[arg(long = "file", conflicts_with = "file_pos")]
        file: Option<PathBuf>,
    },
    /// Preview (default --dry-run) or apply import of a catcloud-share/v1 .zip share bundle
    Import(ShareImportArgs),
}

#[derive(Args, Debug)]
pub struct ShareExportArgs {
    #[arg(long)]
    pub output: PathBuf,
    #[arg(long, default_value = "CatCloud Share Bundle")]
    pub name: String,
    #[arg(long)]
    pub description: Option<String>,
    /// Comma-separated proxy node IDs to export
    #[arg(long = "node-ids", alias = "nodes")]
    pub node_ids: Option<String>,
    /// Export all nodes belonging to this subscription ID
    #[arg(long = "sub-id", alias = "sub")]
    pub sub_id: Option<String>,
    /// Comma-separated domestic pre-acceleration relay IDs to export
    #[arg(long = "relay-ids", alias = "relays")]
    pub relay_ids: Option<String>,
    /// Export all configured domestic pre-acceleration relays
    #[arg(long)]
    pub all_relays: bool,
}

#[derive(Args, Debug)]
pub struct ShareImportArgs {
    /// Path to .zip share bundle
    pub file_pos: Option<PathBuf>,
    /// Path to .zip share bundle (flag form)
    #[arg(long = "file", conflicts_with = "file_pos")]
    pub file: Option<PathBuf>,
    /// Safe sanitized preview without mutating storage (default unless --apply is set)
    #[arg(long)]
    pub dry_run: bool,
    /// Apply import into local CatCloud storage
    #[arg(long)]
    pub apply: bool,
    /// Update an existing subscription group instead of creating a new one
    #[arg(long)]
    pub target_sub: Option<String>,
    /// Custom subscription group name
    #[arg(long)]
    pub name: Option<String>,
    /// Update strategy for --target-sub: replace|merge (aliases: replace_latest|merge_dedup)
    #[arg(long, default_value = "merge")]
    pub mode: String,
    /// Skip importing domestic pre-acceleration relays
    #[arg(long)]
    pub no_relays: bool,
    /// Skip importing proxy nodes
    #[arg(long)]
    pub no_nodes: bool,
}

#[derive(Args, Debug)]
pub struct NodeListArgs {
    #[arg(long)]
    pub sub: Option<String>,
    #[arg(long)]
    pub region: Option<String>,
    #[arg(long)]
    pub max_multiplier: Option<f64>,
    #[arg(long)]
    pub protocol: Option<String>,
    #[arg(long)]
    pub only_443: bool,
    #[arg(long)]
    pub only_google_clean: bool,
    #[arg(long)]
    pub query: Option<String>,
    /// Reveal plaintext server hosts and raw_config credentials (default: redacted)
    #[arg(long)]
    pub reveal_secrets: bool,
}

#[derive(Args, Debug)]
pub struct NodeImportArgs {
    #[arg(long)]
    pub file: Option<PathBuf>,
    #[arg(long)]
    pub url: Option<String>,
    #[arg(long, default_value = "sub-cli-import")]
    pub sub_id: String,
    #[arg(long, default_value = "CLI Imported Subscription")]
    pub name: String,
}

#[derive(Args, Debug)]
pub struct NodeMigrateArgs {
    #[arg(long)]
    pub scan: bool,
    #[arg(long)]
    pub file: Option<PathBuf>,
    #[arg(long)]
    pub apply: bool,
}

#[derive(Args, Debug)]
pub struct NodeAttachArgs {
    #[arg(long)]
    pub list: bool,
    #[arg(long)]
    pub pid: Option<u32>,
    #[arg(long)]
    pub all: bool,
}

#[derive(Subcommand, Debug)]
pub enum ProbeCommand {
    /// List built-in and custom probe definitions
    List,
    /// Register or update a custom probe definition
    Add(ProbeAddArgs),
    /// Delete a custom probe definition by ID
    Remove {
        #[arg(long)]
        id: String,
    },
    /// Build or execute an isolated probe plan by funnel tier
    Run(ProbeRunArgs),
}

#[derive(Args, Debug)]
pub struct ProbeAddArgs {
    #[arg(long)]
    pub id: String,
    #[arg(long)]
    pub name: String,
    #[arg(long)]
    pub kind: String,
    #[arg(long)]
    pub url: String,
    #[arg(long, default_value = "GET")]
    pub method: String,
    #[arg(long)]
    pub expected_status: Option<u16>,
    #[arg(long)]
    pub regex: Option<String>,
    #[arg(long)]
    pub payload_bytes: Option<u64>,
    #[arg(long, default_value_t = 8000)]
    pub timeout_ms: u64,
}

#[derive(Args, Debug)]
pub struct ProbeRunArgs {
    #[arg(long)]
    pub node: Option<String>,
    #[arg(long, default_value = "l1")]
    pub tier: String,
    /// Print the probe execution plan without spawning an isolated Mihomo core
    #[arg(long)]
    pub dry_run: bool,
    /// Reveal unredacted local binary/candidate paths and raw probe error details (default: redacted)
    #[arg(long)]
    pub reveal_secrets: bool,
}

#[derive(Subcommand, Debug)]
pub enum GroupCommand {
    /// List all configured multi-groups
    List,
    /// Create or update a smart multi-group
    Create(GroupCreateArgs),
    /// Switch active node in a multi-group (explicit or next best)
    Switch {
        group_id: String,
        #[arg(long)]
        node: Option<String>,
    },
    /// Update formula, fallback policy, switch mode, or hard gates for a group
    Policy(GroupPolicyArgs),
    /// Evaluate candidate scores and arbiter decision for a group
    Eval { group_id: String },
}

#[derive(Args, Debug)]
pub struct GroupCreateArgs {
    #[arg(long)]
    pub id: String,
    #[arg(long)]
    pub name: String,
    #[arg(long, default_value = "sticky_best")]
    pub mode: String,
    #[arg(long)]
    pub formula: Option<String>,
    #[arg(long, default_value = "degrade_best_warn")]
    pub fallback: String,
    #[arg(long, default_value = "force_close_old")]
    pub switch_mode: String,
    #[arg(long)]
    pub nodes: Option<String>,
}

#[derive(Args, Debug)]
pub struct GroupPolicyArgs {
    pub group_id: String,
    #[arg(long)]
    pub formula: Option<String>,
    #[arg(long)]
    pub fallback: Option<String>,
    #[arg(long)]
    pub switch_mode: Option<String>,
    #[arg(long)]
    pub hard_gate: Vec<String>,
}

/// Platform-appropriate default shell for `config export-env`.
const DEFAULT_EXPORT_SHELL: &str = if cfg!(target_os = "windows") {
    "powershell"
} else {
    "bash"
};

#[derive(Subcommand, Debug)]
pub enum PreaccelCommand {
    /// Import domestic :443 relays from an mmrelay/v1 JSON file or mmrelay://v1 URI
    Add {
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long)]
        uri: Option<String>,
    },
    /// List configured domestic pre-acceleration relays and expiry status
    Pool {
        /// Reveal plaintext relay server IPs and passwords (default: redacted)
        #[arg(long)]
        reveal_secrets: bool,
    },
    /// Update domestic pre-acceleration enablement, native-443 skip, and domestic 204 probe URL
    Bind {
        #[arg(long)]
        enabled: Option<bool>,
        #[arg(long)]
        skip_443_native: Option<bool>,
        #[arg(long)]
        probe_url: Option<String>,
    },
    /// Validate pre-acceleration compile plan, anti-loop rules, optional campus portal check,
    /// and optional real relay speed test
    Test {
        #[arg(long)]
        campus: bool,
        /// Measure real domestic relay latency, upload, and download throughput via isolated Mihomo core
        #[arg(long, default_value_t = false)]
        speed: bool,
        /// Optional overseas reference node ID for dual-hop speed test (auto-selected when omitted)
        #[arg(long)]
        node_id: Option<String>,
    },
    /// Inspect standalone global domestic :443 pre-acceleration config and WinDivert readiness
    GlobalStatus,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// Validate config.json, compiled Mihomo YAML, and anti-loop preflight checks
    Validate,
    /// Validate, write runtime.yaml (with mihomo -t when available), and hot-reload live controller
    Reload {
        #[arg(long)]
        dry_run: bool,
    },
    /// Print or export compiled Mihomo YAML (redacted by default)
    Compile {
        #[arg(long)]
        output: Option<PathBuf>,
        /// Reveal plaintext proxy credentials and controller secret (default: redacted)
        #[arg(long)]
        reveal_secrets: bool,
    },
    /// Output shell proxy environment variable commands
    ExportEnv {
        #[arg(long, default_value = DEFAULT_EXPORT_SHELL)]
        shell: String,
    },
    /// Output sanitized diagnostic summary (pass --reveal-secrets for raw paths and logs)
    Diag {
        /// Reveal unredacted local paths and raw recent log lines (default: redacted)
        #[arg(long)]
        reveal_secrets: bool,
    },
    /// Export an integrity-checked configuration backup snapshot (JSON)
    Backup {
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Verify SHA-256 integrity and restore configuration from a backup snapshot
    Restore {
        #[arg(long = "input", alias = "file")]
        input: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
pub enum DocsCommand {
    /// List all built-in authoritative Agent guides
    List {
        #[arg(long)]
        lang: Option<String>,
    },
    /// Export a single module guide, "all", or sync the complete multi-language docs tree to disk
    Export {
        module: Option<String>,
        #[arg(long, default_value = "markdown")]
        format: String,
        #[arg(long)]
        lang: Option<String>,
        #[arg(long)]
        sync_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
pub enum UpdateCommand {
    /// Check GitHub Releases for updates (or show local config with --offline)
    Check {
        #[arg(long)]
        repo: Option<String>,
        /// Skip remote HTTPS check and only echo local update configuration
        #[arg(long)]
        offline: bool,
    },
    /// Verify and stage a local update archive using manifest + SHA256SUMS.txt
    Stage {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        archive: PathBuf,
        #[arg(long)]
        checksums: PathBuf,
        #[arg(long)]
        asset_name: Option<String>,
    },
}

fn emit_output(as_json: bool, value: &Value, human: &str) -> Result<()> {
    if as_json {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else {
        println!("{human}");
    }
    Ok(())
}

fn open_storage(paths: &AppPaths) -> Result<Storage> {
    let mut db = Storage::open(&paths.db_path)?;
    let _ = db.seed_builtin_probes();
    Ok(db)
}

fn parse_group_mode(raw: &str) -> Result<MultiGroupMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "sticky_best" => Ok(MultiGroupMode::StickyBest),
        "conditional_pool" => Ok(MultiGroupMode::ConditionalPool),
        "load_balance_consistent_hash" => Ok(MultiGroupMode::LoadBalanceConsistentHash),
        "load_balance_round_robin" => Ok(MultiGroupMode::LoadBalanceRoundRobin),
        other => anyhow::bail!("unsupported group mode `{other}`"),
    }
}

fn parse_fallback_policy(raw: &str) -> Result<FallbackPolicy> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "degrade_best_warn" => Ok(FallbackPolicy::DegradeBestWarn),
        "cross_pool_escalate" => Ok(FallbackPolicy::CrossPoolEscalate),
        "strict_circuit_break" => Ok(FallbackPolicy::StrictCircuitBreak),
        other => anyhow::bail!("unsupported fallback policy `{other}`"),
    }
}

fn parse_switch_mode(raw: &str) -> Result<SwitchMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "force_close_old" => Ok(SwitchMode::ForceCloseOld),
        "graceful_new_only" => Ok(SwitchMode::GracefulNewOnly),
        other => anyhow::bail!("unsupported switch mode `{other}`"),
    }
}

pub async fn dispatch(paths: &AppPaths, as_json: bool, cmd: Commands) -> Result<()> {
    match cmd {
        Commands::Status => {
            let cfg = config::load_or_init(paths)?;
            let db = open_storage(paths)?;
            let plat = default_platform();
            let caps = plat.capabilities();
            let mihomo_bin = resolve_mihomo_binary(&cfg, paths, &[], false)
                .ok()
                .and_then(|r| r.path);
            let tun_privilege_ready = is_cli_tun_privilege_ready(&caps, mihomo_bin.as_deref());
            let tun_configured = cfg.tun.enabled;
            let tun_enabled = tun_configured && tun_privilege_ready;
            let tun_needs_elevation = tun_configured && !tun_privilege_ready;
            let wd_files = locate_windivert_files(paths, cfg.preaccel.windivert_dir.as_deref());
            let sub_count = db.list_subscriptions()?.len();
            let node_count = db.list_nodes()?.len();
            let group_count = db.list_multi_groups()?.len();
            let relay_count = db.list_preaccel_relays(false)?.len();
            let probe_count = db.list_probe_definitions()?.len();
            let out = json!({
                "ok": true,
                "sanitized": true,
                "version": env!("CARGO_PKG_VERSION"),
                "data_dir": redact_path_for_display(&paths.root_data_dir.to_string_lossy()),
                "is_portable": paths.is_portable,
                "instance_hash": paths.instance_hash,
                "platform": caps,
                "proxy_mode": cfg.proxy_mode,
                "system_proxy_enabled": cfg.system_proxy.enabled,
                "tun_enabled": tun_enabled,
                "tun_configured": tun_configured,
                "tun_needs_elevation": tun_needs_elevation,
                "mixed_port": cfg.mixed_port,
                "controller_addr": cfg.controller_addr(),
                "dns_listen_addr": cfg.dns_listen_addr(),
                "preaccel_enabled": cfg.preaccel.enabled,
                "global_preaccel": {
                    "enabled": cfg.preaccel.global_bypass_enabled,
                    "scope": cfg.preaccel.global_scope,
                    "windivert_available": wd_files.is_some(),
                    "windivert_path": wd_files.as_ref().map(|(dll, _)| redact_path_for_display(&dll.to_string_lossy())),
                    "is_elevated": caps.is_elevated,
                },
                "counts": {
                    "subscriptions": sub_count,
                    "nodes": node_count,
                    "multi_groups": group_count,
                    "preaccel_relays": relay_count,
                    "probes": probe_count,
                }
            });
            let tun_summary = if tun_needs_elevation {
                "needs_elevation"
            } else if tun_enabled {
                "true"
            } else {
                "false"
            };
            let human = format!(
                "CatCloud CLI v{} | portable={} | mode={} | port={} | tun={} | nodes={} | groups={} | global_preaccel={} (windivert={})",
                env!("CARGO_PKG_VERSION"),
                paths.is_portable,
                cfg.proxy_mode.as_str(),
                cfg.mixed_port,
                tun_summary,
                node_count,
                group_count,
                cfg.preaccel.global_bypass_enabled,
                wd_files.is_some()
            );
            emit_output(as_json, &out, &human)
        }

        Commands::Node { action } => match action {
            NodeCommand::List(args) => {
                let db = open_storage(paths)?;
                let mut filter = NodeFilter::default();
                if let Some(sub) = args.sub {
                    filter.sub_ids = Some(vec![sub]);
                }
                if let Some(region) = args.region {
                    filter.region_codes = Some(vec![region]);
                }
                filter.max_multiplier = args.max_multiplier;
                if let Some(proto) = args.protocol {
                    filter.protocols = Some(vec![proto]);
                }
                if args.only_443 {
                    filter.is_443_native = Some(true);
                }
                if args.only_google_clean {
                    filter.google_clean_only = true;
                }
                filter.keyword = args.query;
                let raw_nodes = db.query_nodes(&filter)?;
                let nodes: Vec<ProxyNode> = if args.reveal_secrets {
                    raw_nodes
                } else {
                    raw_nodes.iter().map(redact_node_for_readonly).collect()
                };
                let out = json!({
                    "ok": true,
                    "sanitized": !args.reveal_secrets,
                    "count": nodes.len(),
                    "nodes": nodes
                });
                let human = format!(
                    "Found {} matching node(s) (sanitized={}).",
                    nodes.len(),
                    !args.reveal_secrets
                );
                emit_output(as_json, &out, &human)
            }

            NodeCommand::Import(args) => {
                let mut db = open_storage(paths)?;
                let (sub_rec, parsed) = if let Some(file) = args.file {
                    let bytes = std::fs::read(&file).with_context(|| {
                        format!(
                            "无法读取本地订阅文件：{}",
                            redact_path_for_display(&file.to_string_lossy())
                        )
                    })?;
                    let sub_rec = SubscriptionRecord {
                        id: args.sub_id.clone(),
                        name: args.name.clone(),
                        kind: SubscriptionKind::File,
                        url_or_cmd: file.to_string_lossy().to_string(),
                        ..Default::default()
                    };
                    let parsed = parse_subscription_payload(&args.sub_id, &bytes, None)?;
                    (sub_rec, parsed)
                } else if let Some(url) = args.url {
                    let sub_rec = SubscriptionRecord {
                        id: args.sub_id.clone(),
                        name: args.name.clone(),
                        kind: SubscriptionKind::Url,
                        url_or_cmd: url,
                        ..Default::default()
                    };
                    let proxy_candidates = build_subscription_proxy_candidates(paths);
                    let parsed = fetch_and_parse_subscription_with_fallback(
                        &sub_rec,
                        Duration::from_secs(20),
                        &proxy_candidates,
                        &FetchOptions::default(),
                    )
                    .await?;
                    (sub_rec, parsed)
                } else {
                    anyhow::bail!("请提供 --file（本地订阅文件）或 --url（订阅链接）");
                };
                let count = parsed.nodes.len();
                apply_parsed_subscription(&mut db, &sub_rec, &parsed)?;
                let out = json!({
                    "ok": true,
                    "sub_id": args.sub_id,
                    "imported_nodes": count,
                    "format": format!("{:?}", parsed.format),
                });
                emit_output(
                    as_json,
                    &out,
                    &format!("Imported {count} node(s) into subscription `{}`.", args.sub_id),
                )
            }

            NodeCommand::Migrate(args) => {
                let previews = if let Some(file) = args.file {
                    if !file.exists() {
                        anyhow::bail!(
                            "migration source path not found: {}",
                            redact_path_for_display(&file.to_string_lossy())
                        );
                    }
                    scan_custom_path_readonly(&file)
                } else {
                    let _ = args.scan;
                    scan_local_clients()
                };
                if args.apply {
                    let mut db = open_storage(paths)?;
                    let mut reports = Vec::new();
                    for p in &previews {
                        if !p.nodes.is_empty() {
                            let sub_id = generate_migration_subscription_id();
                            let sub_name = p
                                .display_name
                                .as_deref()
                                .map(str::trim)
                                .filter(|s| !s.is_empty())
                                .map(ToOwned::to_owned)
                                .or_else(|| {
                                    p.source_path
                                        .as_ref()
                                        .and_then(|sp| sp.file_name())
                                        .and_then(|n| n.to_str())
                                        .map(str::trim)
                                        .filter(|s| !s.is_empty())
                                        .map(ToOwned::to_owned)
                                })
                                .unwrap_or_else(|| format!("Migrated ({})", p.source_kind.as_str()));
                            let mut rep = import_migration_preview(
                                &mut db,
                                p,
                                &MigrationImportOptions::new(sub_id, sub_name),
                            )?;
                            rep.warnings = rep
                                .warnings
                                .iter()
                                .map(|w| sanitize_log_line(w))
                                .collect();
                            reports.push(rep);
                        }
                    }
                    let out = json!({
                        "ok": true,
                        "sanitized": true,
                        "applied": true,
                        "reports": reports
                    });
                    emit_output(as_json, &out, &format!("Applied {} migration(s).", reports.len()))
                } else {
                    let sanitized_previews: Vec<MigrationPreview> = previews
                        .iter()
                        .map(redact_migration_preview)
                        .collect();
                    let out = json!({
                        "ok": true,
                        "sanitized": true,
                        "applied": false,
                        "previews": sanitized_previews
                    });
                    emit_output(
                        as_json,
                        &out,
                        &format!(
                            "Scanned {} readonly migration candidate(s) (sanitized).",
                            sanitized_previews.len()
                        ),
                    )
                }
            }

            NodeCommand::AttachProcess(args) => {
                if let Some(pid) = args.pid {
                    let candidates = list_process_candidates(false);
                    let target = candidates
                        .into_iter()
                        .find(|p| p.pid == pid)
                        .with_context(|| format!("process PID {pid} not found"))?;
                    let inspection = inspect_process_source(&target).await;
                    let redacted = redact_process_inspection(&inspection);
                    let out = json!({
                        "ok": true,
                        "sanitized": true,
                        "inspection": redacted
                    });
                    emit_output(
                        as_json,
                        &out,
                        &format!("Inspected PID {pid} ({}).", target.name),
                    )
                } else {
                    let _ = args.list;
                    let candidates = list_process_candidates(!args.all);
                    let redacted: Vec<ProcessCandidate> = candidates
                        .iter()
                        .map(redact_process_candidate)
                        .collect();
                    let out = json!({
                        "ok": true,
                        "sanitized": true,
                        "count": redacted.len(),
                        "processes": redacted
                    });
                    emit_output(
                        as_json,
                        &out,
                        &format!("Found {} candidate process(es) (sanitized).", redacted.len()),
                    )
                }
            }
        },

        Commands::Sub { action } => match action {
            SubCommand::List => {
                let db = open_storage(paths)?;
                let subs = db.list_subscriptions()?;
                let all_nodes = db.list_nodes()?;
                let mut counts_by_sub: HashMap<String, usize> = HashMap::new();
                for n in &all_nodes {
                    *counts_by_sub.entry(n.sub_id.clone()).or_insert(0) += 1;
                }
                let items: Vec<Value> = subs
                    .iter()
                    .map(|s| {
                        let redacted = redact_subscription_for_readonly(s);
                        let node_count = counts_by_sub.get(&s.id).copied().unwrap_or(0);
                        let mut val = serde_json::to_value(&redacted).unwrap_or_else(|_| json!({}));
                        if let Some(obj) = val.as_object_mut() {
                            obj.insert("node_count".to_string(), json!(node_count));
                        }
                        val
                    })
                    .collect();
                let out = json!({
                    "ok": true,
                    "sanitized": true,
                    "count": items.len(),
                    "subscriptions": items,
                });
                let human = if subs.is_empty() {
                    "No subscriptions configured.".to_string()
                } else {
                    subs.iter()
                        .map(|s| {
                            let n = counts_by_sub.get(&s.id).copied().unwrap_or(0);
                            format!(
                                "- {} ({}) | kind={} | nodes={} | enabled={}",
                                s.id,
                                s.name,
                                s.kind.as_str(),
                                n,
                                s.enabled
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                emit_output(as_json, &out, &human)
            }

            SubCommand::Refresh { sub_id, id } => {
                let target_id = sub_id.or(id);
                let mut db = open_storage(paths)?;
                let proxy_candidates = build_subscription_proxy_candidates(paths);

                if let Some(single_id) = target_id {
                    let sub = db
                        .get_subscription(&single_id)?
                        .with_context(|| format!("subscription `{single_id}` not found"))?;
                    let res = refresh_single_subscription(&mut db, &sub, &proxy_candidates).await?;
                    let out = json!({
                        "ok": true,
                        "sanitized": true,
                        "sub_id": sub.id,
                        "name": sub.name,
                        "imported_nodes": res.node_count,
                        "format": res.format,
                    });
                    emit_output(
                        as_json,
                        &out,
                        &format!(
                            "Refreshed subscription `{}` ({} node(s)).",
                            sub.id, res.node_count
                        ),
                    )
                } else {
                    let subs = db.list_subscriptions()?;
                    let enabled_subs: Vec<SubscriptionRecord> =
                        subs.into_iter().filter(|s| s.enabled).collect();
                    let mut refreshed = 0usize;
                    let mut skipped = 0usize;
                    let mut failed = 0usize;
                    let mut results = Vec::with_capacity(enabled_subs.len());

                    for sub in &enabled_subs {
                        if !matches!(sub.kind, SubscriptionKind::Url | SubscriptionKind::File) {
                            skipped += 1;
                            results.push(json!({
                                "sub_id": sub.id,
                                "name": sub.name,
                                "kind": sub.kind.as_str(),
                                "status": "skipped",
                                "reason": "non-refreshable subscription kind",
                            }));
                            continue;
                        }
                        match refresh_single_subscription(&mut db, sub, &proxy_candidates).await {
                            Ok(info) => {
                                refreshed += 1;
                                results.push(json!({
                                    "sub_id": sub.id,
                                    "name": sub.name,
                                    "kind": sub.kind.as_str(),
                                    "status": "ok",
                                    "imported_nodes": info.node_count,
                                    "format": info.format,
                                }));
                            }
                            Err(err) => {
                                failed += 1;
                                results.push(json!({
                                    "sub_id": sub.id,
                                    "name": sub.name,
                                    "kind": sub.kind.as_str(),
                                    "status": "error",
                                    "error": sanitize_log_line(&err.to_string()),
                                }));
                            }
                        }
                    }

                    let out = json!({
                        "ok": failed == 0,
                        "sanitized": true,
                        "total_enabled": enabled_subs.len(),
                        "refreshed": refreshed,
                        "skipped": skipped,
                        "failed": failed,
                        "results": results,
                    });
                    let human = format!(
                        "Subscription refresh finished: refreshed={refreshed}, skipped={skipped}, failed={failed}."
                    );
                    if failed > 0 {
                        if as_json {
                            emit_output(true, &out, "")?;
                            return Err(AlreadyEmittedJsonError(human).into());
                        }
                        anyhow::bail!("{human}");
                    }
                    emit_output(as_json, &out, &human)
                }
            }

            SubCommand::Remove { sub_id } => {
                let db = open_storage(paths)?;
                let existing_nodes = db
                    .query_nodes(&NodeFilter {
                        sub_ids: Some(vec![sub_id.clone()]),
                        ..NodeFilter::default()
                    })?
                    .len();
                let removed = db.delete_subscription(&sub_id)?;
                let out = json!({
                    "ok": true,
                    "sub_id": sub_id,
                    "removed": removed,
                    "removed_nodes": if removed { existing_nodes } else { 0 },
                });
                emit_output(
                    as_json,
                    &out,
                    &format!(
                        "Subscription `{sub_id}` removed={removed} (nodes={}).",
                        if removed { existing_nodes } else { 0 }
                    ),
                )
            }

            SubCommand::Rename { sub_id, name } => {
                let db = open_storage(paths)?;
                let updated = db.rename_subscription(&sub_id, &name)?;
                let redacted = redact_subscription_for_readonly(&updated);
                let out = json!({
                    "ok": true,
                    "sanitized": true,
                    "subscription": redacted,
                });
                emit_output(
                    as_json,
                    &out,
                    &format!("Renamed subscription `{}` to `{}`.", updated.id, updated.name),
                )
            }

            SubCommand::Merge {
                source,
                target,
                name,
                no_dedup,
            } => {
                let db = open_storage(paths)?;
                let report =
                    db.merge_subscriptions(&source, &target, name.as_deref(), !no_dedup, false)?;
                let _ = sync_active_single_node_after_mutation(paths, &db, &report.id_remap)?;
                let out = json!({
                    "ok": true,
                    "merge": report,
                });
                emit_output(
                    as_json,
                    &out,
                    &format!(
                        "Merged `{}` into `{}`: moved={}, deduplicated={}, total={}.",
                        report.source_sub_id,
                        report.target_sub_id,
                        report.moved_count,
                        report.deduplicated_count,
                        report.total_count
                    ),
                )
            }
        },

        Commands::Probe { action } => match action {
            ProbeCommand::List => {
                let db = open_storage(paths)?;
                let defs = db.list_probe_definitions()?;
                let out = json!({ "ok": true, "count": defs.len(), "probes": defs });
                emit_output(as_json, &out, &format!("Listed {} probe definition(s).", defs.len()))
            }

            ProbeCommand::Add(args) => {
                let db = open_storage(paths)?;
                let def = ProbeDefinition {
                    id: args.id.clone(),
                    name: args.name,
                    kind: ProbeKind::from_db_str(&args.kind),
                    target_url: args.url,
                    method: args.method,
                    expected_status: args.expected_status,
                    body_regex: args.regex,
                    payload_bytes: args.payload_bytes,
                    timeout_ms: args.timeout_ms,
                    builtin: false,
                };
                validate_definition(&def)?;
                db.upsert_probe_definition(&def)?;
                let out = json!({ "ok": true, "probe": def });
                emit_output(as_json, &out, &format!("Saved probe `{}`.", args.id))
            }

            ProbeCommand::Remove { id } => {
                let db = open_storage(paths)?;
                let removed = db.delete_probe_definition(&id)?;
                let out = json!({ "ok": true, "id": id, "removed": removed });
                emit_output(as_json, &out, &format!("Probe `{id}` removed={removed}."))
            }

            ProbeCommand::Run(args) => {
                let cfg = config::load_or_init(paths)?;
                let mut db = open_storage(paths)?;
                let mut reg = ProbeRegistry::new();
                for def in db.list_probe_definitions()? {
                    let _ = reg.register_with_override(def, true);
                }
                let (max_tier, tiers) = match args.tier.to_ascii_lowercase().as_str() {
                    "l0" => (FunnelTier::L0Connectivity, vec![FunnelTier::L0Connectivity]),
                    "l1" => (
                        FunnelTier::L1CleanAndUnlock,
                        vec![FunnelTier::L0Connectivity, FunnelTier::L1CleanAndUnlock],
                    ),
                    "l2" | "all" => (
                        FunnelTier::L2ThroughputAndKeepalive,
                        vec![
                            FunnelTier::L0Connectivity,
                            FunnelTier::L1CleanAndUnlock,
                            FunnelTier::L2ThroughputAndKeepalive,
                        ],
                    ),
                    other => anyhow::bail!("unsupported funnel tier `{other}` (use l0|l1|l2|all)"),
                };
                let selected_probes: Vec<ProbeDefinition> = tiers
                    .iter()
                    .flat_map(|t| reg.select_funnel_tier(*t))
                    .cloned()
                    .collect();
                let probe_ids: Vec<String> = selected_probes.iter().map(|p| p.id.clone()).collect();
                let nodes = match args.node {
                    Some(ref id) => {
                        let node = db
                            .get_node(id)?
                            .with_context(|| format!("node `{id}` not found"))?;
                        vec![node]
                    }
                    None => db
                        .list_nodes()?
                        .into_iter()
                        .filter(|n| n.enabled)
                        .collect(),
                };
                let plan = json!({
                    "tier": &args.tier,
                    "max_tier": max_tier,
                    "node_count": nodes.len(),
                    "node_ids": nodes.iter().map(|n| &n.id).collect::<Vec<_>>(),
                    "probe_count": selected_probes.len(),
                    "probes": &probe_ids,
                });

                if args.dry_run {
                    let bin_res = resolve_mihomo_binary(&cfg, paths, &[], false)?;
                    let (out, human) = build_probe_run_dry_run_payload(
                        &args.tier,
                        nodes.len(),
                        &probe_ids,
                        &plan,
                        &bin_res,
                        args.reveal_secrets,
                    );
                    return emit_output(as_json, &out, &human);
                }

                if nodes.is_empty() {
                    let out = json!({
                        "ok": true,
                        "sanitized": !args.reveal_secrets,
                        "dry_run": false,
                        "executed": false,
                        "reason": "no enabled nodes available to probe",
                        "tier": &args.tier,
                        "node_count": 0,
                        "probe_count": selected_probes.len(),
                        "probes": &probe_ids,
                        "plan": plan,
                        "reports": [],
                    });
                    return emit_output(as_json, &out, "No enabled nodes available to probe.");
                }

                let bin_res = resolve_mihomo_binary(&cfg, paths, &[], false)?;
                let Some(mihomo_bin) = bin_res.path else {
                    let (out, human) = build_probe_run_missing_binary_payload(
                        &args.tier,
                        nodes.len(),
                        &probe_ids,
                        &plan,
                        &bin_res,
                        args.reveal_secrets,
                    );
                    return emit_output(as_json, &out, &human);
                };

                let job_guard = Arc::new(JobGuard::new()?);
                let registry = Arc::new(reg);
                let options = Arc::new(FunnelOptions {
                    max_tier,
                    ..FunnelOptions::default()
                });
                let active_relay = if cfg.preaccel.enabled {
                    let enabled_relays = db.list_preaccel_relays(true).unwrap_or_default();
                    cfg.preaccel
                        .active_relay_id
                        .as_deref()
                        .and_then(|aid| enabled_relays.iter().find(|r| r.id == aid).cloned())
                        .or_else(|| enabled_relays.into_iter().next())
                        .filter(|r| !r.server.trim().is_empty() && r.port > 0)
                } else {
                    None
                };
                let probe_temp_dir = paths.runtime_dir.join("probe-tmp");
                let mut reports: Vec<FunnelRunReport> = Vec::with_capacity(nodes.len());
                let mut persisted_records = 0usize;

                for batch in nodes.chunks(32) {
                    let core = IsolatedProbeCore::spawn_with_preaccel(
                        &mihomo_bin,
                        &probe_temp_dir,
                        job_guard.as_ref(),
                        batch,
                        active_relay.as_ref(),
                        cfg.preaccel.skip_443_native,
                    )
                    .await?;

                    let sem = Arc::new(tokio::sync::Semaphore::new(8));
                    let mut join_set = tokio::task::JoinSet::new();

                    for binding in core.bindings().to_vec() {
                        let sem_clone = Arc::clone(&sem);
                        let reg_clone = Arc::clone(&registry);
                        let opts_clone = Arc::clone(&options);
                        let guard_clone = Arc::clone(&job_guard);
                        join_set.spawn(async move {
                            let _permit = sem_clone
                                .acquire_owned()
                                .await
                                .map_err(|e| anyhow::anyhow!("probe semaphore closed: {e}"))?;
                            let report = run_funnel_for_node(
                                reg_clone.as_ref(),
                                &binding.node_id,
                                binding.listen_port,
                                opts_clone.as_ref(),
                                Some(guard_clone.as_ref()),
                                None,
                            )
                            .await?;
                            Ok::<FunnelRunReport, anyhow::Error>(report)
                        });
                    }

                    let mut batch_reports: Vec<FunnelRunReport> = Vec::with_capacity(batch.len());
                    let mut first_err: Option<anyhow::Error> = None;
                    while let Some(joined) = join_set.join_next().await {
                        match joined {
                            Ok(Ok(report)) => batch_reports.push(report),
                            Ok(Err(err)) => {
                                if first_err.is_none() {
                                    first_err = Some(err);
                                }
                            }
                            Err(join_err) => {
                                if first_err.is_none() {
                                    first_err =
                                        Some(anyhow::anyhow!("probe task panicked: {join_err}"));
                                }
                            }
                        }
                    }

                    let _ = core.shutdown().await;
                    if let Some(err) = first_err {
                        let _ = std::fs::remove_dir(&probe_temp_dir);
                        return Err(err);
                    }

                    for report in &batch_reports {
                        if !report.records.is_empty() {
                            persisted_records += db.insert_probe_results_batch(&report.records)?;
                        }
                    }
                    reports.extend(batch_reports);
                }

                let _ = std::fs::remove_dir(&probe_temp_dir);
                let _ = db.prune_old_probe_results(20);

                let order_map: HashMap<&str, usize> = nodes
                    .iter()
                    .enumerate()
                    .map(|(i, n)| (n.id.as_str(), i))
                    .collect();
                reports.sort_by_key(|r| {
                    order_map
                        .get(r.node_id.as_str())
                        .copied()
                        .unwrap_or(usize::MAX)
                });

                let passed_nodes = reports
                    .iter()
                    .filter(|r| !r.short_circuited && r.records.iter().any(|rec| rec.ok))
                    .count();
                let snapshots: HashMap<String, _> = reports
                    .iter()
                    .map(|r| (r.node_id.clone(), r.snapshot.clone()))
                    .collect();

                let display_binary_path = format_path_with_reveal(&mihomo_bin, args.reveal_secrets);
                let display_reports: Vec<FunnelRunReport> = if args.reveal_secrets {
                    reports
                } else {
                    reports.iter().map(redact_funnel_report).collect()
                };

                let out = json!({
                    "ok": true,
                    "sanitized": !args.reveal_secrets,
                    "dry_run": false,
                    "executed": true,
                    "tier": &args.tier,
                    "binary_path": &display_binary_path,
                    "used_preaccel": active_relay.is_some(),
                    "preaccel_relay_name": active_relay.as_ref().map(|r| &r.name),
                    "node_count": nodes.len(),
                    "passed_nodes": passed_nodes,
                    "probe_count": selected_probes.len(),
                    "probes": &probe_ids,
                    "persisted_records": persisted_records,
                    "snapshots": &snapshots,
                    "reports": &display_reports,
                });
                emit_output(
                    as_json,
                    &out,
                    &format!(
                        "Executed isolated probe funnel ({} tier): {}/{} node(s) healthy, {} result(s) saved to SQLite.",
                        args.tier,
                        passed_nodes,
                        nodes.len(),
                        persisted_records
                    ),
                )
            }
        },

        Commands::Group { action } => match action {
            GroupCommand::List => {
                let db = open_storage(paths)?;
                let groups = db.list_multi_groups()?;
                let out = json!({ "ok": true, "count": groups.len(), "groups": groups });
                emit_output(as_json, &out, &format!("Listed {} multi-group(s).", groups.len()))
            }

            GroupCommand::Create(args) => {
                let db = open_storage(paths)?;
                let formula = args
                    .formula
                    .unwrap_or_else(|| DEFAULT_COST_EFFECTIVE_FORMULA.to_string());
                validate_formula(&formula)?;
                let member_node_ids = args
                    .nodes
                    .map(|s| {
                        s.split(',')
                            .map(|v| v.trim().to_string())
                            .filter(|v| !v.is_empty())
                            .collect()
                    })
                    .unwrap_or_default();
                let group = MultiGroup {
                    id: args.id.clone(),
                    name: args.name,
                    mode: parse_group_mode(&args.mode)?,
                    member_node_ids,
                    formula_expr: formula,
                    fallback_policy: parse_fallback_policy(&args.fallback)?,
                    switch_mode: parse_switch_mode(&args.switch_mode)?,
                    ..MultiGroup::default()
                };
                db.upsert_multi_group(&group)?;
                let out = json!({ "ok": true, "group": group });
                emit_output(as_json, &out, &format!("Saved multi-group `{}`.", args.id))
            }

            GroupCommand::Switch { group_id, node } => {
                let db = open_storage(paths)?;
                let mut group = db
                    .get_multi_group(&group_id)?
                    .with_context(|| format!("multi-group `{group_id}` not found"))?;
                let nodes = db.list_nodes()?;
                let next_id = if let Some(explicit) = node {
                    explicit
                } else {
                    let pool: Vec<&catcloud_core::models::ProxyNode> = if group.member_node_ids.is_empty() {
                        nodes.iter().filter(|n| n.enabled).collect()
                    } else {
                        nodes
                            .iter()
                            .filter(|n| n.enabled && group.member_node_ids.contains(&n.id))
                            .collect()
                    };
                    if pool.is_empty() {
                        anyhow::bail!("no enabled candidate nodes available");
                    }
                    let cur = group
                        .active_node_id
                        .as_deref()
                        .and_then(|id| pool.iter().position(|n| n.id == id))
                        .unwrap_or(pool.len() - 1);
                    pool[(cur + 1) % pool.len()].id.clone()
                };
                let prev = group.active_node_id.clone();
                group.active_node_id = Some(next_id.clone());
                db.upsert_multi_group(&group)?;
                let out = json!({
                    "ok": true,
                    "group_id": group_id,
                    "previous_node_id": prev,
                    "active_node_id": next_id,
                });
                emit_output(
                    as_json,
                    &out,
                    &format!("Switched group `{group_id}` to `{next_id}`."),
                )
            }

            GroupCommand::Policy(args) => {
                let db = open_storage(paths)?;
                let mut group = db
                    .get_multi_group(&args.group_id)?
                    .with_context(|| format!("multi-group `{}` not found", args.group_id))?;
                if let Some(expr) = args.formula {
                    validate_formula(&expr)?;
                    group.formula_expr = expr;
                }
                if let Some(fb) = args.fallback {
                    group.fallback_policy = parse_fallback_policy(&fb)?;
                }
                if let Some(sw) = args.switch_mode {
                    group.switch_mode = parse_switch_mode(&sw)?;
                }
                if !args.hard_gate.is_empty() {
                    for g in &args.hard_gate {
                        validate_formula(g)?;
                    }
                    group.hard_gates = args.hard_gate;
                }
                db.upsert_multi_group(&group)?;
                let out = json!({ "ok": true, "group": group });
                emit_output(
                    as_json,
                    &out,
                    &format!("Updated policy for multi-group `{}`.", args.group_id),
                )
            }

            GroupCommand::Eval { group_id } => {
                let db = open_storage(paths)?;
                let group = db
                    .get_multi_group(&group_id)?
                    .with_context(|| format!("multi-group `{group_id}` not found"))?;
                let nodes = db.list_nodes()?;
                let ids: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
                let snaps = db.get_probe_snapshots_batch(&ids, group.primary_probe_id.as_deref())?;
                let eval_report = evaluate_group_candidates(&group, &nodes, &snaps)?;
                let mut mem = ArbiterGroupMemory::default();
                let decision =
                    decide_group_action(&group, &nodes, &snaps, None, &mut mem, Utc::now().timestamp())?;
                let out = json!({
                    "ok": true,
                    "evaluation": eval_report,
                    "decision": decision,
                });
                emit_output(
                    as_json,
                    &out,
                    &format!(
                        "Evaluated group `{group_id}`: {} gate-passed candidate(s) ranked.",
                        eval_report.gate_passed.len()
                    ),
                )
            }
        },

        Commands::Preaccel { action } => match action {
            PreaccelCommand::Add { file, uri } => {
                let raw = if let Some(path) = file {
                    std::fs::read_to_string(&path).with_context(|| {
                        format!(
                            "failed to read {}",
                            redact_path_for_display(&path.to_string_lossy())
                        )
                    })?
                } else if let Some(u) = uri {
                    u
                } else {
                    anyhow::bail!("either --file or --uri must be provided");
                };
                let bundle = parse_mmrelay_clipboard(&raw)?;
                let db = open_storage(paths)?;
                for relay in &bundle.relays {
                    validate_relay_strict(relay)?;
                    db.upsert_preaccel_relay(relay)?;
                }
                let redacted_relays: Vec<PreAccelRelay> = bundle
                    .relays
                    .iter()
                    .map(redact_relay_for_readonly)
                    .collect();
                let out = json!({
                    "ok": true,
                    "sanitized": true,
                    "imported_relays": redacted_relays.len(),
                    "relays": redacted_relays,
                });
                emit_output(
                    as_json,
                    &out,
                    &format!(
                        "Imported {} verified domestic :443 relay(s).",
                        bundle.relays.len()
                    ),
                )
            }

            PreaccelCommand::Pool { reveal_secrets } => {
                let db = open_storage(paths)?;
                let relays = db.list_preaccel_relays(false)?;
                let now = Utc::now();
                let items: Vec<Value> = relays
                    .iter()
                    .map(|r| {
                        let shown = if reveal_secrets {
                            r.clone()
                        } else {
                            redact_relay_for_readonly(r)
                        };
                        json!({
                            "relay": shown,
                            "expiry": evaluate_expiry(r.expires_at.as_deref(), now),
                        })
                    })
                    .collect();
                let out = json!({
                    "ok": true,
                    "sanitized": !reveal_secrets,
                    "count": items.len(),
                    "relays": items
                });
                emit_output(
                    as_json,
                    &out,
                    &format!(
                        "Domestic pre-acceleration pool has {} relay(s) (sanitized={}).",
                        items.len(),
                        !reveal_secrets
                    ),
                )
            }

            PreaccelCommand::Bind {
                enabled,
                skip_443_native,
                probe_url,
            } => {
                let mut cfg = config::load_or_init(paths)?;
                if let Some(en) = enabled {
                    cfg.preaccel.enabled = en;
                    cfg.preaccel.global_bypass_enabled = en;
                }
                if let Some(skip) = skip_443_native {
                    cfg.preaccel.skip_443_native = skip;
                }
                if let Some(url) = probe_url {
                    validate_domestic_probe_url(&url)?;
                    cfg.preaccel.probe_url = url;
                }
                config::save(paths, &cfg)?;
                let sanitized_preaccel = redact_preaccel_config_for_output(&cfg.preaccel);
                let out = json!({
                    "ok": true,
                    "sanitized": true,
                    "preaccel": sanitized_preaccel,
                });
                emit_output(
                    as_json,
                    &out,
                    &format!(
                        "Updated preaccel binding: enabled={}, skip_443_native={}.",
                        cfg.preaccel.enabled, cfg.preaccel.skip_443_native
                    ),
                )
            }

            PreaccelCommand::Test {
                campus,
                speed,
                node_id,
            } => {
                let cfg = config::load_or_init(paths)?;
                let db = open_storage(paths)?;
                let relays = db.list_preaccel_relays(false)?;
                let nodes = db.list_nodes()?;
                let plan = build_preaccel_compile_plan(&cfg.preaccel, &relays, &nodes)?;
                let campus_state = if campus {
                    let state =
                        probe_campus_portal(&cfg.preaccel.probe_url, Duration::from_secs(5)).await;
                    let mut tracker = CampusBypassTracker::new();
                    let transition = tracker.apply_state(state);
                    Some(json!({
                        "state": transition.state,
                        "temporary_rules": transition.active_direct_rules,
                        "fake_ip_filter": transition.active_fake_ip_filter,
                    }))
                } else {
                    None
                };
                let warnings: Vec<String> =
                    plan.warnings.iter().map(|w| sanitize_log_line(w)).collect();

                if !speed {
                    let out = json!({
                        "ok": true,
                        "sanitized": true,
                        "active": plan.active,
                        "relay_count": plan.ordered_relay_ids.len(),
                        "dialer_wrapped_nodes": plan.dialer_node_ids.len(),
                        "skipped_nodes": plan.skipped_node_ids.len(),
                        "anti_loop_rule_count": plan.anti_loop_rules.len(),
                        "probe_url": plan.effective_probe_url,
                        "warnings": warnings,
                        "campus": campus_state,
                    });
                    return emit_output(
                        as_json,
                        &out,
                        &format!(
                            "Pre-acceleration check ok: active={}, relays={}, wrapped={}, skipped={}, anti_loop_rules={}.",
                            plan.active,
                            plan.ordered_relay_ids.len(),
                            plan.dialer_node_ids.len(),
                            plan.skipped_node_ids.len(),
                            plan.anti_loop_rules.len()
                        ),
                    );
                }

                let groups = db.list_multi_groups()?;
                let (reference_node, ref_note) = select_preaccel_speed_reference_node(
                    &cfg,
                    &groups,
                    &nodes,
                    node_id.as_deref(),
                )?;
                let target_relays: Vec<PreAccelRelay> = relays
                    .iter()
                    .filter(|r| r.enabled && !r.server.trim().is_empty() && r.port > 0)
                    .cloned()
                    .collect();

                if target_relays.is_empty() {
                    let speed_test = json!({
                        "executed": false,
                        "reason": "no enabled domestic relays available for speed test",
                        "mode": if reference_node.is_some() { "dual_hop" } else { "single_hop" },
                        "reference_node": reference_node.as_ref().map(|n| json!({
                            "id": n.id,
                            "name": n.name,
                            "protocol": n.protocol,
                            "region_code": n.region_code,
                        })),
                        "reference_note": ref_note,
                        "tested_count": 0usize,
                        "passed_count": 0usize,
                        "results": [],
                    });
                    let out = json!({
                        "ok": true,
                        "sanitized": true,
                        "active": plan.active,
                        "relay_count": plan.ordered_relay_ids.len(),
                        "dialer_wrapped_nodes": plan.dialer_node_ids.len(),
                        "skipped_nodes": plan.skipped_node_ids.len(),
                        "anti_loop_rule_count": plan.anti_loop_rules.len(),
                        "probe_url": plan.effective_probe_url,
                        "warnings": warnings,
                        "campus": campus_state,
                        "speed_test": speed_test,
                    });
                    return emit_output(
                        as_json,
                        &out,
                        "Pre-acceleration speed test skipped: no enabled domestic relays available.",
                    );
                }

                let bin_res = resolve_mihomo_binary(&cfg, paths, &[], false)?;
                let Some(mihomo_bin) = bin_res.path else {
                    let checked_candidates =
                        format_paths_with_reveal(&bin_res.checked_candidates, false);
                    let download_guidance = bin_res
                        .download_guidance
                        .as_ref()
                        .map(redact_download_guidance);
                    let human = match &download_guidance {
                        Some(g) => format!(
                            "Pre-acceleration speed test failed: Mihomo binary not found. {}",
                            g.instructions
                        ),
                        None => {
                            "Pre-acceleration speed test failed: Mihomo binary not found."
                                .to_string()
                        }
                    };
                    let out = json!({
                        "ok": false,
                        "sanitized": true,
                        "reason": "mihomo binary not found",
                        "checked_candidates": checked_candidates,
                        "download_guidance": download_guidance,
                        "error": &human,
                    });
                    if as_json {
                        emit_output(true, &out, "")?;
                        return Err(AlreadyEmittedJsonError(human).into());
                    }
                    anyhow::bail!("{human}");
                };

                let job_guard = JobGuard::new()?;
                let probe_temp_dir = paths.runtime_dir.join("probe-tmp");
                std::fs::create_dir_all(&probe_temp_dir)?;
                let empty_dns: &[String] = &[];
                let (probe_core, relay_ports) =
                    IsolatedProbeCore::spawn_for_preaccel_relay_speeds(
                        &mihomo_bin,
                        &probe_temp_dir,
                        &job_guard,
                        &target_relays,
                        reference_node.as_ref(),
                        empty_dns,
                        DEFAULT_READY_TIMEOUT,
                    )
                    .await?;

                let relay_by_id: HashMap<&str, &PreAccelRelay> = target_relays
                    .iter()
                    .map(|r| (r.id.as_str(), r))
                    .collect();
                let mut speed_results: Vec<Value> = Vec::with_capacity(relay_ports.len());
                let mut human_lines: Vec<String> = Vec::with_capacity(relay_ports.len() + 2);
                let mut passed_count = 0usize;
                let mut persist_err: Option<anyhow::Error> = None;

                // Measure relays strictly one-by-one to prevent bandwidth contention.
                for (relay_id, proxy_port) in relay_ports {
                    let sample = measure_single_preaccel_relay_speed(proxy_port, &relay_id).await;
                    let rounded_lat = sample
                        .latency_ms
                        .filter(|v| v.is_finite() && *v > 0.0)
                        .map(|ms| ((ms * 10.0).round() / 10.0).max(0.1));
                    let rounded_up = sample
                        .up_mbps
                        .filter(|v| v.is_finite() && *v > 0.0)
                        .map(|v| (v * 100.0).round() / 100.0);
                    let rounded_down = sample
                        .down_mbps
                        .filter(|v| v.is_finite() && *v > 0.0)
                        .map(|v| (v * 100.0).round() / 100.0);
                    if rounded_lat.is_some() || rounded_up.is_some() || rounded_down.is_some() {
                        if let Err(err) = db.update_preaccel_speed_metrics(
                            &relay_id,
                            rounded_lat,
                            rounded_up,
                            rounded_down,
                        ) {
                            persist_err = Some(err.into());
                            break;
                        }
                    }
                    if sample.ok {
                        passed_count += 1;
                    }

                    let relay_opt = relay_by_id.get(relay_id.as_str()).copied();
                    let relay_name = relay_opt
                        .map(|r| r.name.as_str())
                        .filter(|s| !s.trim().is_empty())
                        .unwrap_or(relay_id.as_str());
                    let clean_err = sample.error.as_deref().map(sanitize_multiline_text);

                    speed_results.push(json!({
                        "relay_id": &relay_id,
                        "name": relay_name,
                        "provider": relay_opt.map(|r| r.provider.as_str()).unwrap_or(""),
                        "region": relay_opt.map(|r| r.region.as_str()).unwrap_or(""),
                        "protocol": relay_opt.map(|r| r.protocol.as_str()).unwrap_or(""),
                        "server": relay_opt.map(|r| redact_ip_or_host(&r.server)).unwrap_or_default(),
                        "port": relay_opt.map(|r| r.port).unwrap_or(0),
                        "ok": sample.ok,
                        "latency_ms": rounded_lat,
                        "up_mbps": rounded_up,
                        "down_mbps": rounded_down,
                        "error": &clean_err,
                    }));

                    let lat_str = rounded_lat
                        .map(|v| format!("{v:.1}ms"))
                        .unwrap_or_else(|| "--".to_string());
                    let up_str = rounded_up
                        .map(|v| format!("{v:.2} Mbps"))
                        .unwrap_or_else(|| "--".to_string());
                    let down_str = rounded_down
                        .map(|v| format!("{v:.2} Mbps"))
                        .unwrap_or_else(|| "--".to_string());
                    if let Some(err_text) = clean_err {
                        human_lines.push(format!(
                            "- {relay_name} ({relay_id}): ok={} | latency={lat_str} | up={up_str} | down={down_str} | note={err_text}",
                            sample.ok
                        ));
                    } else {
                        human_lines.push(format!(
                            "- {relay_name} ({relay_id}): ok={} | latency={lat_str} | up={up_str} | down={down_str}",
                            sample.ok
                        ));
                    }
                }

                let _ = probe_core.shutdown().await;
                let _ = std::fs::remove_dir(&probe_temp_dir);
                if let Some(err) = persist_err {
                    return Err(err);
                }

                let mode_label = if reference_node.is_some() {
                    "dual_hop"
                } else {
                    "single_hop"
                };
                let speed_test = json!({
                    "executed": true,
                    "mode": mode_label,
                    "binary_path": redact_path_for_display(&mihomo_bin.to_string_lossy()),
                    "reference_node": reference_node.as_ref().map(|n| json!({
                        "id": n.id,
                        "name": n.name,
                        "protocol": n.protocol,
                        "region_code": n.region_code,
                    })),
                    "reference_note": &ref_note,
                    "tested_count": speed_results.len(),
                    "passed_count": passed_count,
                    "results": &speed_results,
                });
                let out = json!({
                    "ok": true,
                    "sanitized": true,
                    "active": plan.active,
                    "relay_count": plan.ordered_relay_ids.len(),
                    "dialer_wrapped_nodes": plan.dialer_node_ids.len(),
                    "skipped_nodes": plan.skipped_node_ids.len(),
                    "anti_loop_rule_count": plan.anti_loop_rules.len(),
                    "probe_url": plan.effective_probe_url,
                    "warnings": warnings,
                    "campus": campus_state,
                    "speed_test": speed_test,
                });
                let header = match &reference_node {
                    Some(n) => format!(
                        "Pre-acceleration speed test ({mode_label} via `{}`): {passed_count}/{} relay(s) passed.",
                        n.name,
                        speed_results.len()
                    ),
                    None => format!(
                        "Pre-acceleration speed test ({mode_label}): {passed_count}/{} relay(s) passed.",
                        speed_results.len()
                    ),
                };
                let mut summary_lines = vec![header];
                if let Some(note) = ref_note {
                    summary_lines.push(format!("Note: {}", sanitize_log_line(&note)));
                }
                summary_lines.extend(human_lines);
                emit_output(as_json, &out, &summary_lines.join("\n"))
            }

            PreaccelCommand::GlobalStatus => {
                let (out, human) = build_global_preaccel_status_payload(paths)?;
                emit_output(as_json, &out, &human)
            }
        },

        Commands::Net { action } => match action {
            NetCommand::Doctor => {
                let (out, human) = build_net_doctor_payload(paths).await?;
                emit_output(as_json, &out, &human)
            }

            NetCommand::Connections { limit } => {
                let (out, human) = build_net_connections_payload(paths, limit).await?;
                emit_output(as_json, &out, &human)
            }

            NetCommand::Match {
                domain,
                network,
                port,
            } => {
                let (out, human) = build_net_match_payload(paths, &domain, &network, port).await?;
                emit_output(as_json, &out, &human)
            }
        },

        Commands::Logs { action } => match action {
            LogsCommand::Tail { lines, level } => {
                let (out, human) = build_logs_tail_payload(paths, lines, &level)?;
                emit_output(as_json, &out, &human)
            }
        },

        Commands::Config { action } => match action {
            ConfigCommand::Validate => {
                let cfg = config::load_or_init(paths)?;
                let cfg_issues = config::validate_config_detailed(&cfg);
                let db = open_storage(paths)?;
                let nodes = db.list_nodes()?;
                let groups = db.list_multi_groups()?;
                let relays = db.list_preaccel_relays(false)?;
                let ports = allocate_safe_ports(
                    &cfg.bind_address,
                    cfg.mixed_port,
                    cfg.controller_port,
                    cfg.dns_listen_port,
                    cfg.port_guard_auto_shift,
                )?;
                let empty_filter = HashMap::new();
                let compiled = compile_mihomo_config(&CompileInput {
                    config: &cfg,
                    nodes: &nodes,
                    groups: &groups,
                    relays: &relays,
                    controller_secret: "validation-placeholder-secret",
                    allocated_ports: &ports,
                    extra_prepend_rules: &[],
                    extra_fake_ip_filters: &[],
                    group_filtered_members: &empty_filter,
                })?;
                let relay_servers: Vec<String> = relays
                    .iter()
                    .filter(|r| r.enabled)
                    .map(|r| r.server.clone())
                    .collect();
                let static_report = validate_compiled_yaml(&compiled.yaml, &relay_servers)?;
                let ok = cfg_issues.is_empty() && static_report.ok;
                let sanitized_cfg_issues = redact_config_issues(&cfg_issues);
                let sanitized_static = redact_static_validation(&static_report);
                let out = json!({
                    "ok": ok,
                    "sanitized": true,
                    "config_issues": sanitized_cfg_issues,
                    "static_validation": sanitized_static,
                    "stats": compiled.stats,
                    "ports": ports,
                });
                emit_output(
                    as_json,
                    &out,
                    &format!(
                        "Config validation ok={ok} (rules={}, proxies={}).",
                        compiled.stats.total_rules, compiled.stats.total_proxies
                    ),
                )?;
                if !ok {
                    if as_json {
                        return Err(AlreadyEmittedJsonError(
                            "configuration validation failed".to_string(),
                        )
                        .into());
                    }
                    anyhow::bail!("configuration validation failed");
                }
                Ok(())
            }

            ConfigCommand::Reload { dry_run } => {
                let cfg = config::load_or_init(paths)?;
                let _ = open_storage(paths)?;
                let bin_res = resolve_mihomo_binary(&cfg, paths, &[], false)?;
                let job_guard = Arc::new(JobGuard::new()?);

                let ep = resolve_effective_controller_endpoint_info(paths, &cfg);
                let ctrl_addr = format_host_port(&ep.host, ep.port);
                let configured_secret =
                    (!ep.secret.trim().is_empty()).then_some(ep.secret.clone());

                let probe_adapter = MihomoAdapter::with_controller_endpoint(
                    Arc::clone(&job_guard),
                    &ep.host,
                    ep.port,
                    ep.secret.clone(),
                )?;

                let mut live_controller_version: Option<String> = None;
                let mut controller_auth_error: Option<String> = None;
                match tokio::time::timeout(Duration::from_secs(2), probe_adapter.fetch_version())
                    .await
                {
                    Ok(Ok(ver)) => {
                        live_controller_version = Some(ver);
                    }
                    Ok(Err(CatError::Core(msg)))
                        if msg.contains("HTTP 401") || msg.contains("HTTP 403") =>
                    {
                        controller_auth_error = Some(msg);
                    }
                    _ => {}
                }

                let redacted_bin_path = bin_res
                    .path
                    .as_ref()
                    .map(|p| redact_path_for_display(&p.to_string_lossy()));
                let caps = default_platform().capabilities();
                let allow_tun = is_cli_tun_privilege_ready(&caps, bin_res.path.as_deref());
                let tun_masked_no_elevation = cfg.tun.enabled && !allow_tun;

                if dry_run {
                    let db = open_storage(paths)?;
                    let nodes = db.list_nodes()?;
                    let groups = db.list_multi_groups()?;
                    let relays = db.list_preaccel_relays(false)?;
                    let mut effective_cfg = cfg.clone();
                    if !allow_tun && effective_cfg.tun.enabled {
                        effective_cfg.tun.enabled = false;
                    }
                    let bind_host = if effective_cfg.allow_lan {
                        effective_cfg.bind_address.clone()
                    } else {
                        "127.0.0.1".to_string()
                    };
                    let ports = AllocatedPorts {
                        bind_host,
                        mixed_port: ep.mixed_port.unwrap_or(effective_cfg.mixed_port),
                        controller_port: ep.port,
                        dns_port: ep.dns_port.unwrap_or(effective_cfg.dns_listen_port),
                        shifted: Vec::new(),
                    };
                    let secret = configured_secret
                        .clone()
                        .unwrap_or_else(generate_controller_secret);
                    let empty_filter = HashMap::new();
                    let compiled = compile_mihomo_config(&CompileInput {
                        config: &effective_cfg,
                        nodes: &nodes,
                        groups: &groups,
                        relays: &relays,
                        controller_secret: &secret,
                        allocated_ports: &ports,
                        extra_prepend_rules: &[],
                        extra_fake_ip_filters: &[],
                        group_filtered_members: &empty_filter,
                    })?;
                    if !compiled.validation.ok {
                        let summary = sanitize_log_line(
                            &compiled
                                .validation
                                .errors()
                                .iter()
                                .map(|i| format!("[{}] {}", i.code, i.message))
                                .collect::<Vec<_>>()
                                .join("; "),
                        );
                        let msg =
                            format!("compiled YAML failed static anti-loop preflight: {summary}");
                        let sanitized_validation = redact_static_validation(&compiled.validation);
                        let out = json!({
                            "ok": false,
                            "sanitized": true,
                            "dry_run": true,
                            "validated_and_written": false,
                            "error": &msg,
                            "static_validation": &sanitized_validation,
                        });
                        if as_json {
                            emit_output(true, &out, "")?;
                            return Err(AlreadyEmittedJsonError(msg).into());
                        }
                        anyhow::bail!("refused reload dry-run: {summary}");
                    }

                    let mut binary_verified = false;
                    if let Some(ref bin_path) = bin_res.path {
                        let candidate_path = paths
                            .runtime_dir
                            .join(format!("runtime-dryrun-{}.yaml", std::process::id()));
                        AppPaths::atomic_write(&candidate_path, compiled.yaml.as_bytes())?;
                        let verify_res = verify_config_with_binary(
                            bin_path,
                            &paths.runtime_dir,
                            &candidate_path,
                            Duration::from_secs(8),
                        )
                        .await;
                        let _ = std::fs::remove_file(&candidate_path);
                        if let Err(err) = verify_res {
                            let msg = sanitize_log_line(&err.to_string());
                            let out = json!({
                                "ok": false,
                                "dry_run": true,
                                "validated_and_written": false,
                                "binary_verified": false,
                                "binary_path": &redacted_bin_path,
                                "error": &msg,
                            });
                            if as_json {
                                emit_output(true, &out, "")?;
                                return Err(AlreadyEmittedJsonError(msg).into());
                            }
                            anyhow::bail!("refused reload dry-run: {msg}");
                        }
                        binary_verified = true;
                    }

                    let offline_coord = HotReloadCoordinator::new(
                        paths.clone(),
                        Arc::new(MihomoAdapter::new(Arc::clone(&job_guard))?),
                    );
                    let runtime_yaml_path = offline_coord.runtime_yaml_path();
                    let warnings: Vec<String> = compiled
                        .validation
                        .warnings()
                        .iter()
                        .map(|w| sanitize_log_line(&format!("[{}] {}", w.code, w.message)))
                        .collect();
                    let out = json!({
                        "ok": true,
                        "sanitized": true,
                        "dry_run": true,
                        "runtime_yaml_path": redact_path_for_display(&runtime_yaml_path.to_string_lossy()),
                        "core_not_running": live_controller_version.is_none() && controller_auth_error.is_none(),
                        "core_version": &live_controller_version,
                        "hot_reloaded": false,
                        "validated_and_written": false,
                        "allow_tun": allow_tun,
                        "tun_masked_no_elevation": tun_masked_no_elevation,
                        "binary_verified": binary_verified,
                        "binary_path": &redacted_bin_path,
                        "sha256": &compiled.sha256,
                        "stats": &compiled.stats,
                        "warnings": &warnings,
                    });
                    return emit_output(
                        as_json,
                        &out,
                        &format!(
                            "Validated candidate runtime.yaml (dry_run=true, binary_verified={}, sha256={}).",
                            binary_verified,
                            &compiled.sha256[..12]
                        ),
                    );
                }

                if let Some(auth_err) = controller_auth_error {
                    let msg = sanitize_log_line(&format!(
                        "running Mihomo controller at {} rejected authentication ({auth_err}); ensure config.json controller_secret matches the active core or restart core",
                        ctrl_addr
                    ));
                    let out = json!({
                        "ok": false,
                        "dry_run": false,
                        "core_not_running": false,
                        "hot_reloaded": false,
                        "validated_and_written": false,
                        "error": &msg,
                    });
                    if as_json {
                        emit_output(true, &out, "")?;
                        return Err(AlreadyEmittedJsonError(msg).into());
                    }
                    anyhow::bail!("{msg}");
                }

                let core_running = live_controller_version.is_some();
                let adapter = if core_running {
                    Arc::new(probe_adapter)
                } else {
                    Arc::new(MihomoAdapter::new(Arc::clone(&job_guard))?)
                };
                let coordinator = HotReloadCoordinator::new(paths.clone(), adapter);
                if core_running {
                    let mut seeded_cfg = cfg.clone();
                    if !allow_tun && seeded_cfg.tun.enabled {
                        seeded_cfg.tun.enabled = false;
                    }
                    let seeded_ports = AllocatedPorts {
                        bind_host: if seeded_cfg.allow_lan {
                            seeded_cfg.bind_address.clone()
                        } else {
                            "127.0.0.1".to_string()
                        },
                        mixed_port: ep.mixed_port.unwrap_or(seeded_cfg.mixed_port),
                        controller_port: ep.port,
                        dns_port: ep.dns_port.unwrap_or(seeded_cfg.dns_listen_port),
                        shifted: Vec::new(),
                    };
                    coordinator
                        .seed_active_state(
                            seeded_cfg,
                            String::new(),
                            seeded_ports,
                            ep.secret.clone(),
                        )
                        .await;
                }
                let runtime_yaml_path = coordinator.runtime_yaml_path();
                let redacted_runtime_yaml =
                    redact_path_for_display(&runtime_yaml_path.to_string_lossy());
                let outcome = coordinator
                    .apply_disk_reload(DiskReloadOptions {
                        force: true,
                        verify_with_binary: true,
                        allow_l3_restart: false,
                        allow_tun,
                        ..DiskReloadOptions::default()
                    })
                    .await;
                let sanitized_outcome = redact_reload_outcome(&outcome);

                if sanitized_outcome.rejected || !sanitized_outcome.applied {
                    let err_msg = sanitized_outcome
                        .error
                        .clone()
                        .unwrap_or_else(|| "hot reload rejected".to_string());
                    let out = json!({
                        "ok": false,
                        "sanitized": true,
                        "dry_run": false,
                        "runtime_yaml_path": &redacted_runtime_yaml,
                        "core_not_running": !core_running,
                        "core_version": &live_controller_version,
                        "hot_reloaded": false,
                        "validated_and_written": false,
                        "binary_verified": bin_res.found,
                        "binary_path": &redacted_bin_path,
                        "error": &err_msg,
                        "outcome": &sanitized_outcome,
                    });
                    if as_json {
                        emit_output(true, &out, "")?;
                        return Err(AlreadyEmittedJsonError(err_msg).into());
                    }
                    anyhow::bail!("config reload failed: {err_msg}");
                }

                let sha_preview = sanitized_outcome
                    .config_hash
                    .as_deref()
                    .map(|h| &h[..h.len().min(12)])
                    .unwrap_or("unknown");
                let out = json!({
                    "ok": true,
                    "sanitized": true,
                    "dry_run": false,
                    "runtime_yaml_path": &redacted_runtime_yaml,
                    "core_not_running": !core_running,
                    "core_version": &live_controller_version,
                    "hot_reloaded": core_running,
                    "validated_and_written": true,
                    "allow_tun": allow_tun,
                    "tun_masked_no_elevation": tun_masked_no_elevation,
                    "binary_verified": bin_res.found,
                    "binary_path": &redacted_bin_path,
                    "replayed_groups": sanitized_outcome.replayed_groups,
                    "level": sanitized_outcome.level,
                    "sha256": &sanitized_outcome.config_hash,
                    "warnings": &sanitized_outcome.warnings,
                    "applied_at": &sanitized_outcome.applied_at,
                    "outcome": &sanitized_outcome,
                });
                let human = if core_running {
                    format!(
                        "Hot-reloaded runtime.yaml via controller ({}) and replayed {} group(s) (sha256={sha_preview}).",
                        ctrl_addr,
                        outcome.replayed_groups
                    )
                } else {
                    format!(
                        "Core not running; validated and wrote {} (binary_verified={}, sha256={sha_preview}).",
                        redacted_runtime_yaml, bin_res.found
                    )
                };
                emit_output(as_json, &out, &human)
            }

            ConfigCommand::Compile {
                output,
                reveal_secrets,
            } => {
                let cfg = config::load_or_init(paths)?;
                let db = open_storage(paths)?;
                let nodes = db.list_nodes()?;
                let groups = db.list_multi_groups()?;
                let relays = db.list_preaccel_relays(false)?;
                let ports = allocate_safe_ports(
                    &cfg.bind_address,
                    cfg.mixed_port,
                    cfg.controller_port,
                    cfg.dns_listen_port,
                    cfg.port_guard_auto_shift,
                )?;
                let empty_filter = HashMap::new();
                let compiled = compile_mihomo_config_with_runtime_dir(
                    &CompileInput {
                        config: &cfg,
                        nodes: &nodes,
                        groups: &groups,
                        relays: &relays,
                        controller_secret: cfg
                            .controller_secret
                            .as_deref()
                            .filter(|s| !s.trim().is_empty())
                            .unwrap_or("compile-placeholder-secret"),
                        allocated_ports: &ports,
                        extra_prepend_rules: &[],
                        extra_fake_ip_filters: &[],
                        group_filtered_members: &empty_filter,
                    },
                    Some(&paths.runtime_dir),
                )?;
                let rendered_yaml = if reveal_secrets {
                    compiled.yaml.clone()
                } else {
                    redact_compiled_yaml(&compiled.yaml)
                };
                if let Some(path) = output {
                    AppPaths::atomic_write(&path, rendered_yaml.as_bytes())?;
                    let file_sha256 = compute_file_sha256(&path)?;
                    let display_path = redact_path_for_display(&path.to_string_lossy());
                    let out = json!({
                        "ok": true,
                        "sanitized": !reveal_secrets,
                        "output": &display_path,
                        "sha256": file_sha256,
                    });
                    emit_output(
                        as_json,
                        &out,
                        &format!(
                            "Wrote compiled YAML (sanitized={}) to {}.",
                            !reveal_secrets, display_path
                        ),
                    )
                } else if as_json {
                    emit_output(
                        true,
                        &json!({
                            "ok": true,
                            "sanitized": !reveal_secrets,
                            "yaml": rendered_yaml,
                            "sha256": compiled.sha256,
                        }),
                        "",
                    )
                } else {
                    println!("{rendered_yaml}");
                    Ok(())
                }
            }

            ConfigCommand::ExportEnv { shell } => {
                let cfg = config::load_or_init(paths)?;
                let plat = default_platform();
                let snippet = plat.export_shell_env_snippet(
                    &shell,
                    "127.0.0.1",
                    cfg.mixed_port,
                    cfg.mixed_port,
                );
                let out = json!({ "ok": true, "shell": shell, "snippet": snippet });
                emit_output(as_json, &out, &snippet)
            }

            ConfigCommand::Diag { reveal_secrets } => {
                let out = build_diag_payload(paths, reveal_secrets)?;
                emit_output(as_json, &out, &serde_json::to_string_pretty(&out)?)
            }

            ConfigCommand::Backup { output } => {
                let cfg = config::load_or_init(paths)?;
                let dest = config::export_backup(paths, &cfg, output.as_deref())?;
                let file_sha256 = compute_file_sha256(&dest)?;
                let raw = std::fs::read_to_string(&dest).unwrap_or_default();
                let config_sha256 = serde_json::from_str::<Value>(&raw)
                    .ok()
                    .and_then(|v| {
                        v.get("config_sha256")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned)
                    });
                let display_path = redact_path_for_display(&dest.to_string_lossy());
                let out = json!({
                    "ok": true,
                    "sanitized": true,
                    "schema": "catcloud-config-backup/v1",
                    "output": &display_path,
                    "sha256": &file_sha256,
                    "config_sha256": config_sha256,
                });
                emit_output(
                    as_json,
                    &out,
                    &format!(
                        "Exported config backup to {} (sha256={}).",
                        display_path,
                        &file_sha256[..file_sha256.len().min(12)]
                    ),
                )
            }

            ConfigCommand::Restore { input } => {
                let restored = config::import_backup(paths, &input)?;
                let display_path = redact_path_for_display(&input.to_string_lossy());
                let out = json!({
                    "ok": true,
                    "sanitized": true,
                    "restored": true,
                    "input": &display_path,
                    "schema_version": restored.schema_version,
                    "proxy_mode": restored.proxy_mode,
                    "mixed_port": restored.mixed_port,
                    "controller_port": restored.controller_port,
                    "dns_listen_port": restored.dns_listen_port,
                });
                emit_output(
                    as_json,
                    &out,
                    &format!(
                        "Verified SHA-256 and restored configuration from {}.",
                        display_path
                    ),
                )
            }
        },

        Commands::Docs { action } => match action {
            DocsCommand::List { lang } => {
                let norm_lang = agent_docs::normalize_doc_lang(lang.as_deref());
                let docs = agent_docs::list_agent_docs_for_lang(norm_lang);
                let summary: Vec<Value> = docs
                    .iter()
                    .map(|d| {
                        json!({
                            "module_id": d.module_id,
                            "title": d.title,
                            "summary": d.summary
                        })
                    })
                    .collect();
                let out = json!({
                    "ok": true,
                    "lang": norm_lang,
                    "count": summary.len(),
                    "modules": summary
                });
                let human = docs
                    .iter()
                    .map(|d| format!("- {}: {}", d.module_id, d.title))
                    .collect::<Vec<_>>()
                    .join("\n");
                emit_output(as_json, &out, &human)
            }

            DocsCommand::Export {
                module,
                format,
                lang,
                sync_dir,
            } => {
                let norm_lang = agent_docs::normalize_doc_lang(lang.as_deref());
                let json_fmt = as_json || format.eq_ignore_ascii_case("json");

                if let Some(dir) = sync_dir {
                    let docs_root = agent_docs::sync_agent_docs_to_disk(&dir)?;
                    let display_root = redact_path_for_display(&docs_root.to_string_lossy());
                    if let Some(ref mod_id) = module {
                        let rendered =
                            agent_docs::export_agent_docs_with_lang(mod_id, json_fmt, norm_lang)?;
                        if json_fmt {
                            let content: Value = serde_json::from_str(&rendered)
                                .unwrap_or_else(|_| Value::String(rendered));
                            let out = json!({
                                "ok": true,
                                "synced": true,
                                "docs_root": &display_root,
                                "languages": agent_docs::SUPPORTED_DOC_LANGS,
                                "lang": norm_lang,
                                "module": mod_id,
                                "content": content,
                            });
                            return emit_output(true, &out, "");
                        }
                        println!("{rendered}");
                        return Ok(());
                    }
                    let out = json!({
                        "ok": true,
                        "synced": true,
                        "docs_root": &display_root,
                        "languages": agent_docs::SUPPORTED_DOC_LANGS,
                        "module_count": agent_docs::list_agent_docs_for_lang(norm_lang).len(),
                    });
                    return emit_output(
                        json_fmt,
                        &out,
                        &format!(
                            "Synchronized complete multi-language agent docs tree to {}.",
                            display_root
                        ),
                    );
                }

                let target_module = module.as_deref().unwrap_or("all");
                let rendered =
                    agent_docs::export_agent_docs_with_lang(target_module, json_fmt, norm_lang)?;
                println!("{rendered}");
                Ok(())
            }
        },

        Commands::Share { action } => match action {
            ShareCommand::Export(args) => handle_share_export(paths, as_json, args),
            ShareCommand::Inspect { file_pos, file } => {
                let target = file_pos
                    .or(file)
                    .context("please provide a .zip share bundle path")?;
                handle_share_inspect(as_json, &target)
            }
            ShareCommand::Import(args) => handle_share_import(paths, as_json, args),
        },

        Commands::Update { action } => match action {
            UpdateCommand::Check { repo, offline } => {
                let cfg = config::load_or_init(paths)?;
                let target_repo = repo.unwrap_or_else(|| cfg.update.repo.clone());
                let current_version = env!("CARGO_PKG_VERSION");
                let is_self_updatable_portable = paths.is_self_updatable_portable();
                let platform_key = current_update_platform_key_opt(is_self_updatable_portable);
                let staged_version =
                    read_pending_staged_update(&paths.staging_dir).map(|p| p.target_version);
                let display_staging_dir =
                    redact_path_for_display(&paths.staging_dir.to_string_lossy());

                if offline {
                    let out = json!({
                        "ok": true,
                        "sanitized": true,
                        "offline": true,
                        "current_version": current_version,
                        "repo": &target_repo,
                        "mode": &cfg.update.mode,
                        "include_prerelease": cfg.update.include_prerelease,
                        "is_self_updatable_portable": is_self_updatable_portable,
                        "platform_key": platform_key,
                        "download_url": Value::Null,
                        "staged_version": &staged_version,
                        "staging_dir": &display_staging_dir,
                    });
                    return emit_output(
                        as_json,
                        &out,
                        &format!(
                            "CatCloud v{current_version} offline update channel: {} ({:?}, platform={}, self_updatable_portable={}, staged={})",
                            target_repo,
                            cfg.update.mode,
                            platform_key.unwrap_or("unsupported"),
                            is_self_updatable_portable,
                            staged_version.as_deref().unwrap_or("none"),
                        ),
                    );
                }

                let updater = match Updater::new(&target_repo, current_version) {
                    Ok(u) => u,
                    Err(err) => {
                        let msg = sanitize_log_line(&err.to_string());
                        let out = json!({
                            "ok": false,
                            "offline": false,
                            "current_version": current_version,
                            "repo": &target_repo,
                            "mode": &cfg.update.mode,
                            "include_prerelease": cfg.update.include_prerelease,
                            "is_self_updatable_portable": is_self_updatable_portable,
                            "platform_key": platform_key,
                            "download_url": Value::Null,
                            "staged_version": &staged_version,
                            "staging_dir": &display_staging_dir,
                            "error": &msg,
                        });
                        if as_json {
                            emit_output(true, &out, "")?;
                            return Err(AlreadyEmittedJsonError(msg).into());
                        }
                        anyhow::bail!("failed to initialize updater for `{target_repo}`: {msg}");
                    }
                };
                let manifest_url = updater.default_latest_json_url();
                match updater.check_latest(None).await {
                    Ok(check) => {
                        let update_available = is_update_available_for_channel(
                            &check.latest_version,
                            &check.current_version,
                            cfg.update.include_prerelease,
                        )?;
                        let download_url = platform_key
                            .and_then(|k| check.manifest.platforms.get(k))
                            .map(|asset| asset.url.clone());
                        let platforms: Vec<&String> = check.manifest.platforms.keys().collect();
                        let out = json!({
                            "ok": true,
                            "sanitized": true,
                            "offline": false,
                            "current_version": &check.current_version,
                            "latest_version": &check.latest_version,
                            "update_available": update_available,
                            "pub_date": &check.pub_date,
                            "notes": &check.notes,
                            "repo": &target_repo,
                            "manifest_url": &manifest_url,
                            "mode": &cfg.update.mode,
                            "include_prerelease": cfg.update.include_prerelease,
                            "is_self_updatable_portable": is_self_updatable_portable,
                            "platform_key": platform_key,
                            "download_url": &download_url,
                            "staged_version": &staged_version,
                            "staging_dir": &display_staging_dir,
                            "platforms": platforms,
                            "manifest": &check.manifest,
                        });
                        let human = if update_available {
                            format!(
                                "Update available for CatCloud: v{} -> v{} (repo={}, platform={}, staged={}).",
                                check.current_version,
                                check.latest_version,
                                target_repo,
                                platform_key.unwrap_or("unsupported"),
                                staged_version.as_deref().unwrap_or("none"),
                            )
                        } else {
                            format!(
                                "CatCloud v{} is up to date (latest: v{}, repo={}, platform={}, staged={}).",
                                check.current_version,
                                check.latest_version,
                                target_repo,
                                platform_key.unwrap_or("unsupported"),
                                staged_version.as_deref().unwrap_or("none"),
                            )
                        };
                        emit_output(as_json, &out, &human)
                    }
                    Err(err) => {
                        let msg = sanitize_log_line(&err.to_string());
                        let out = json!({
                            "ok": false,
                            "offline": false,
                            "current_version": current_version,
                            "repo": &target_repo,
                            "manifest_url": &manifest_url,
                            "mode": &cfg.update.mode,
                            "include_prerelease": cfg.update.include_prerelease,
                            "is_self_updatable_portable": is_self_updatable_portable,
                            "platform_key": platform_key,
                            "download_url": Value::Null,
                            "staged_version": &staged_version,
                            "staging_dir": &display_staging_dir,
                            "error": &msg,
                        });
                        if as_json {
                            emit_output(true, &out, "")?;
                            return Err(AlreadyEmittedJsonError(msg).into());
                        }
                        anyhow::bail!("update check failed for `{target_repo}`: {msg}");
                    }
                }
            }

            UpdateCommand::Stage {
                manifest,
                archive,
                checksums,
                asset_name,
            } => {
                let manifest_bytes =
                    read_file_with_limit(&manifest, MAX_METADATA_BYTES, "update manifest")?;
                let parsed_manifest = parse_latest_manifest(&manifest_bytes)?;
                let sums_bytes =
                    read_file_with_limit(&checksums, MAX_METADATA_BYTES, "SHA256SUMS")?;
                let sums_raw = String::from_utf8(sums_bytes)
                    .context("SHA256SUMS file is not valid UTF-8")?;
                let sums = parse_sha256sums(&sums_raw)?;
                let fname = asset_name.unwrap_or_else(|| {
                    archive
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("update.zip")
                        .to_string()
                });
                let fallback_asset = PlatformAsset {
                    url: String::new(),
                    signature: None,
                    sha256: None,
                    filename: Some(fname.clone()),
                };
                let target_asset = find_manifest_asset_for_stage(&parsed_manifest, &fname)
                    .unwrap_or(&fallback_asset);
                let expected = resolve_asset_sha256(target_asset, Some(&sums))?;
                let zip_bytes =
                    read_file_with_limit(&archive, MAX_ZIP_BYTES, "update archive")?;
                let staged = stage_verified_archive(
                    &zip_bytes,
                    &expected,
                    env!("CARGO_PKG_VERSION"),
                    &parsed_manifest.version,
                    &paths.staging_dir,
                )?;
                let out = json!({ "ok": true, "staged": staged });
                emit_output(
                    as_json,
                    &out,
                    &format!("Staged verified update v{} for next launch.", parsed_manifest.version),
                )
            }
        },
    }
}

const MAX_DIAG_LOG_LINES: usize = 40;
const MAX_LOG_TAIL_LINES_CAP: usize = 2000;
const MAX_DIAG_LOG_TAIL_READ_BYTES: u64 = 64 * 1024;
const MAX_LOGS_TAIL_READ_BYTES_PER_FILE: u64 = 512 * 1024;

fn build_subscription_proxy_candidates(paths: &AppPaths) -> Vec<Option<String>> {
    let mut proxy_candidates: Vec<Option<String>> = vec![None];
    if let Ok(cfg) = config::load_or_init(paths) {
        if cfg.mixed_port > 0 {
            proxy_candidates.push(Some(format!("http://127.0.0.1:{}", cfg.mixed_port)));
        }
    }
    for env_key in [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        if let Ok(val) = std::env::var(env_key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                proxy_candidates.push(Some(trimmed.to_string()));
            }
        }
    }
    proxy_candidates
}

struct SubscriptionRefreshInfo {
    node_count: usize,
    format: String,
}

async fn refresh_single_subscription(
    db: &mut Storage,
    sub: &SubscriptionRecord,
    proxy_candidates: &[Option<String>],
) -> Result<SubscriptionRefreshInfo> {
    let parsed_res = match sub.kind {
        SubscriptionKind::Url => {
            fetch_and_parse_subscription_with_fallback(
                sub,
                Duration::from_secs(20),
                proxy_candidates,
                &FetchOptions::default(),
            )
            .await
            .map_err(anyhow::Error::from)
        }
        SubscriptionKind::File => {
            let path = PathBuf::from(&sub.url_or_cmd);
            let bytes = std::fs::read(&path).with_context(|| {
                format!(
                    "failed to read local subscription file `{}`",
                    redact_path_for_display(&path.to_string_lossy())
                )
            })?;
            parse_subscription_payload(&sub.id, &bytes, None).map_err(anyhow::Error::from)
        }
        SubscriptionKind::Migrated | SubscriptionKind::ProcessAdapter => {
            anyhow::bail!(
                "subscription `{}` (kind={}) does not support direct refresh",
                sub.id,
                sub.kind.as_str()
            );
        }
    };

    match parsed_res {
        Ok(parsed) => {
            let count = apply_parsed_subscription(db, sub, &parsed)?;
            Ok(SubscriptionRefreshInfo {
                node_count: count,
                format: format!("{:?}", parsed.format),
            })
        }
        Err(err) => {
            let clean_err = sanitize_log_line(&err.to_string());
            let _ = db.update_subscription_refresh_status(
                &sub.id,
                None,
                None,
                Some(&clean_err),
                None,
                None,
                None,
            );
            Err(err)
        }
    }
}

pub(crate) fn redact_subscription_for_readonly(sub: &SubscriptionRecord) -> SubscriptionRecord {
    let mut out = sub.clone();
    out.url_or_cmd = match sub.kind {
        SubscriptionKind::Url => redact_subscription_url(&sub.url_or_cmd),
        SubscriptionKind::File | SubscriptionKind::Migrated | SubscriptionKind::ProcessAdapter => {
            sanitize_log_line(&redact_path_for_display(&sub.url_or_cmd))
        }
    };
    out.last_error = sub.last_error.as_deref().map(sanitize_log_line);
    out.etag = sub.etag.as_deref().map(sanitize_log_line);
    out
}

fn redact_subscription_url(raw: &str) -> String {
    let base = sanitize_log_line(raw.trim());
    let Some((scheme, rest)) = base.split_once("://") else {
        return base;
    };

    let (without_frag, has_frag) = match rest.split_once('#') {
        Some((before, frag)) => (before, !frag.is_empty()),
        None => (rest, false),
    };
    let (before_query, query_opt) = match without_frag.split_once('?') {
        Some((before, q)) => (before, Some(q)),
        None => (without_frag, None),
    };
    let (authority, path_part) = match before_query.find('/') {
        Some(idx) => (&before_query[..idx], &before_query[idx..]),
        None => (before_query, ""),
    };

    let masked_authority = if let Some((_, host_port)) = authority.rsplit_once('@') {
        format!("<REDACTED>@{}", redact_ip_or_host(host_port))
    } else {
        redact_ip_or_host(authority)
    };

    let masked_path = if path_part.is_empty() {
        String::new()
    } else {
        path_part
            .split('/')
            .map(|seg| {
                let looks_like_secret_token = seg.len() >= 16
                    && seg
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                    && seg.bytes().any(|b| b.is_ascii_digit())
                    && seg.bytes().any(|b| b.is_ascii_alphabetic());
                if looks_like_secret_token {
                    "<REDACTED>"
                } else {
                    seg
                }
            })
            .collect::<Vec<_>>()
            .join("/")
    };

    let mut out = format!("{scheme}://{masked_authority}{masked_path}");
    if let Some(q) = query_opt {
        let masked_query = q
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| match pair.split_once('=') {
                Some((k, _)) => format!("{k}=<REDACTED>"),
                None => "<REDACTED>".to_string(),
            })
            .collect::<Vec<_>>()
            .join("&");
        out.push('?');
        out.push_str(&masked_query);
    }
    if has_frag {
        out.push_str("#<REDACTED>");
    }
    out
}

fn redact_migration_preview(preview: &MigrationPreview) -> MigrationPreview {
    MigrationPreview {
        source_kind: preview.source_kind,
        source_path: preview
            .source_path
            .as_ref()
            .map(|p| PathBuf::from(redact_path_for_display(&p.to_string_lossy()))),
        display_name: preview.display_name.clone(),
        nodes: preview.nodes.iter().map(redact_node_for_readonly).collect(),
        prepend_rules: preview
            .prepend_rules
            .iter()
            .map(|r| sanitize_log_line(r))
            .collect(),
        append_rules: preview
            .append_rules
            .iter()
            .map(|r| sanitize_log_line(r))
            .collect(),
        warnings: preview
            .warnings
            .iter()
            .map(|w| sanitize_log_line(w))
            .collect(),
    }
}

fn redact_process_candidate(candidate: &ProcessCandidate) -> ProcessCandidate {
    let mut masked_cmd = Vec::with_capacity(candidate.cmdline.len());
    let mut redact_next = false;
    for arg in &candidate.cmdline {
        if redact_next {
            masked_cmd.push("<REDACTED>".to_string());
            redact_next = false;
            continue;
        }
        let lower = arg.trim().to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "-secret"
                | "--secret"
                | "-password"
                | "--password"
                | "-token"
                | "--token"
                | "-auth"
                | "--auth"
                | "-key"
                | "--key"
        ) {
            masked_cmd.push(arg.clone());
            redact_next = true;
            continue;
        }
        masked_cmd.push(sanitize_log_line(&redact_path_for_display(arg)));
    }

    ProcessCandidate {
        pid: candidate.pid,
        name: candidate.name.clone(),
        exe_path: candidate
            .exe_path
            .as_ref()
            .map(|p| PathBuf::from(redact_path_for_display(&p.to_string_lossy()))),
        cmdline: masked_cmd,
        detected_config_dir: candidate
            .detected_config_dir
            .as_ref()
            .map(|p| PathBuf::from(redact_path_for_display(&p.to_string_lossy()))),
        detected_config_file: candidate
            .detected_config_file
            .as_ref()
            .map(|p| PathBuf::from(redact_path_for_display(&p.to_string_lossy()))),
        detected_controller_addr: candidate
            .detected_controller_addr
            .as_deref()
            .map(redact_ip_or_host),
        likely_proxy_client: candidate.likely_proxy_client,
    }
}

fn redact_process_inspection(inspection: &ProcessInspectionResult) -> ProcessInspectionResult {
    let recommendation = match &inspection.recommendation {
        AttachRecommendation::ReadOnlyLocalFile {
            path,
            node_count,
            reason,
        } => AttachRecommendation::ReadOnlyLocalFile {
            path: PathBuf::from(redact_path_for_display(&path.to_string_lossy())),
            node_count: *node_count,
            reason: sanitize_log_line(reason),
        },
        AttachRecommendation::PublicControllerApi {
            endpoint_url,
            proxy_count,
            requires_secret,
            reason,
        } => AttachRecommendation::PublicControllerApi {
            endpoint_url: sanitize_log_line(endpoint_url),
            proxy_count: *proxy_count,
            requires_secret: *requires_secret,
            reason: sanitize_log_line(reason),
        },
        AttachRecommendation::ExternalAdapterTemplate {
            schema,
            suggested_command,
            template_script,
            reason,
        } => AttachRecommendation::ExternalAdapterTemplate {
            schema: schema.clone(),
            suggested_command: suggested_command.clone(),
            template_script: template_script.clone(),
            reason: sanitize_log_line(reason),
        },
    };

    ProcessInspectionResult {
        pid: inspection.pid,
        process_name: inspection.process_name.clone(),
        readable_yaml_file: inspection
            .readable_yaml_file
            .as_ref()
            .map(|p| PathBuf::from(redact_path_for_display(&p.to_string_lossy()))),
        yaml_node_count: inspection.yaml_node_count,
        controller_url: inspection
            .controller_url
            .as_deref()
            .map(sanitize_log_line),
        controller_reachable: inspection.controller_reachable,
        controller_requires_secret: inspection.controller_requires_secret,
        controller_proxy_count: inspection.controller_proxy_count,
        recommendation,
        notes: inspection
            .notes
            .iter()
            .map(|n| sanitize_log_line(n))
            .collect(),
    }
}

fn redact_connection_for_readonly(conn: &ActiveConnection) -> ActiveConnection {
    ActiveConnection {
        id: conn.id.clone(),
        upload: conn.upload,
        download: conn.download,
        start: conn.start.clone(),
        chains: conn.chains.iter().map(|c| sanitize_log_line(c)).collect(),
        rule: conn.rule.clone(),
        rule_payload: sanitize_log_line(&conn.rule_payload),
        network: conn.network.clone(),
        conn_type: conn.conn_type.clone(),
        source_ip: redact_ip_or_host(&conn.source_ip),
        source_port: conn.source_port.clone(),
        destination_ip: redact_ip_or_host(&conn.destination_ip),
        destination_port: conn.destination_port.clone(),
        host: redact_ip_or_host(&conn.host),
        process: conn.process.clone(),
        process_path: redact_path_for_display(&conn.process_path),
    }
}

fn parse_csv_ids(raw: Option<&str>) -> Vec<String> {
    let Some(text) = raw else {
        return Vec::new();
    };
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for part in text.split(',') {
        let trimmed = part.trim();
        if !trimmed.is_empty() && seen.insert(trimmed.to_string()) {
            out.push(trimmed.to_string());
        }
    }
    out
}

fn parse_subscription_update_mode(raw: &str) -> Result<SubscriptionUpdateMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "replace" | "replace_latest" => Ok(SubscriptionUpdateMode::ReplaceLatest),
        "merge" | "merge_dedup" => Ok(SubscriptionUpdateMode::MergeDedup),
        other => anyhow::bail!(
            "unsupported share import mode `{other}` (use replace|merge|replace_latest|merge_dedup)"
        ),
    }
}

fn handle_share_export(paths: &AppPaths, as_json: bool, args: ShareExportArgs) -> Result<()> {
    let db = open_storage(paths)?;
    let explicit_node_ids = parse_csv_ids(args.node_ids.as_deref());
    let explicit_relay_ids = parse_csv_ids(args.relay_ids.as_deref());

    let selected_nodes: Vec<ProxyNode> = if let Some(ref sub_id) = args.sub_id {
        let sub_nodes = db.query_nodes(&NodeFilter {
            sub_ids: Some(vec![sub_id.clone()]),
            ..NodeFilter::default()
        })?;
        if explicit_node_ids.is_empty() {
            sub_nodes
        } else {
            let wanted: HashSet<&str> = explicit_node_ids.iter().map(String::as_str).collect();
            sub_nodes
                .into_iter()
                .filter(|n| wanted.contains(n.id.as_str()))
                .collect()
        }
    } else if !explicit_node_ids.is_empty() {
        let all_nodes = db.list_nodes()?;
        let by_id: HashMap<&str, &ProxyNode> =
            all_nodes.iter().map(|n| (n.id.as_str(), n)).collect();
        let mut missing = Vec::new();
        let mut chosen = Vec::with_capacity(explicit_node_ids.len());
        for nid in &explicit_node_ids {
            if let Some(node) = by_id.get(nid.as_str()) {
                chosen.push((*node).clone());
            } else {
                missing.push(nid.clone());
            }
        }
        if !missing.is_empty() {
            anyhow::bail!("node ID(s) not found: {}", missing.join(", "));
        }
        chosen
    } else {
        Vec::new()
    };

    let selected_relays: Vec<PreAccelRelay> = if args.all_relays {
        db.list_preaccel_relays(false)?
    } else if !explicit_relay_ids.is_empty() {
        let all_relays = db.list_preaccel_relays(false)?;
        let by_id: HashMap<&str, &PreAccelRelay> =
            all_relays.iter().map(|r| (r.id.as_str(), r)).collect();
        let mut missing = Vec::new();
        let mut chosen = Vec::with_capacity(explicit_relay_ids.len());
        for rid in &explicit_relay_ids {
            if let Some(relay) = by_id.get(rid.as_str()) {
                chosen.push((*relay).clone());
            } else {
                missing.push(rid.clone());
            }
        }
        if !missing.is_empty() {
            anyhow::bail!("relay ID(s) not found: {}", missing.join(", "));
        }
        chosen
    } else {
        Vec::new()
    };

    let req = ShareBundleExportRequest {
        name: args.name,
        description: args.description,
        nodes: selected_nodes,
        relays: selected_relays,
    };
    let manifest = export_share_bundle_zip_file(&req, &args.output)?;
    let sha256 = compute_file_sha256(&args.output)?;
    let display_output = redact_path_for_display(&args.output.to_string_lossy());
    let out = json!({
        "ok": true,
        "sanitized": true,
        "output": &display_output,
        "sha256": &sha256,
        "manifest": &manifest,
    });
    emit_output(
        as_json,
        &out,
        &format!(
            "Exported share bundle `{}` to {} ({} node(s), {} relay(s), sha256={}).",
            manifest.name,
            display_output,
            manifest.node_count,
            manifest.relay_count,
            &sha256[..sha256.len().min(12)]
        ),
    )
}

fn handle_share_inspect(as_json: bool, file: &Path) -> Result<()> {
    let preview = preview_share_bundle_zip_file(file)?;
    let redacted_nodes: Vec<ProxyNode> = preview
        .nodes
        .iter()
        .map(redact_node_for_readonly)
        .collect();
    let redacted_relays: Vec<PreAccelRelay> = preview
        .relays
        .iter()
        .map(redact_relay_for_readonly)
        .collect();
    let warnings: Vec<String> = preview
        .warnings
        .iter()
        .map(|w| sanitize_log_line(w))
        .collect();
    let display_file = redact_path_for_display(&file.to_string_lossy());
    let out = json!({
        "ok": true,
        "sanitized": true,
        "file": &display_file,
        "manifest": &preview.manifest,
        "has_readme": preview.has_readme,
        "node_count": redacted_nodes.len(),
        "relay_count": redacted_relays.len(),
        "nodes": redacted_nodes,
        "relays": redacted_relays,
        "warnings": warnings,
    });
    emit_output(
        as_json,
        &out,
        &format!(
            "Inspected share bundle `{}` ({}): {} node(s), {} relay(s) (sanitized).",
            preview.manifest.name,
            preview.manifest.schema,
            preview.nodes.len(),
            preview.relays.len()
        ),
    )
}

fn execute_share_import(paths: &AppPaths, args: ShareImportArgs) -> Result<(Value, String)> {
    let file = args
        .file_pos
        .or(args.file)
        .context("please provide a .zip share bundle path")?;
    if args.dry_run && args.apply {
        anyhow::bail!("--dry-run and --apply cannot be specified together");
    }
    let update_mode = parse_subscription_update_mode(&args.mode)?;
    let effective_dry_run = args.dry_run || !args.apply;

    let preview = preview_share_bundle_zip_file(&file)?;
    let selected_nodes = if args.no_nodes {
        Vec::new()
    } else {
        preview.nodes.clone()
    };
    let selected_relays = if args.no_relays {
        Vec::new()
    } else {
        preview.relays.clone()
    };
    let display_file = redact_path_for_display(&file.to_string_lossy());
    let mut warnings: Vec<String> = preview
        .warnings
        .iter()
        .map(|w| sanitize_log_line(w))
        .collect();

    if effective_dry_run {
        let redacted_nodes: Vec<ProxyNode> = selected_nodes
            .iter()
            .map(redact_node_for_readonly)
            .collect();
        let redacted_relays: Vec<PreAccelRelay> = selected_relays
            .iter()
            .map(redact_relay_for_readonly)
            .collect();
        let out = json!({
            "ok": true,
            "sanitized": true,
            "dry_run": true,
            "applied": false,
            "file": &display_file,
            "manifest": &preview.manifest,
            "target_sub": &args.target_sub,
            "mode": update_mode,
            "would_import_nodes": redacted_nodes.len(),
            "would_import_relays": redacted_relays.len(),
            "nodes": redacted_nodes,
            "relays": redacted_relays,
            "warnings": warnings,
        });
        let human = format!(
            "Share bundle dry-run preview `{}`: {} node(s), {} relay(s) ready to import (pass --apply to persist).",
            preview.manifest.name,
            selected_nodes.len(),
            selected_relays.len()
        );
        return Ok((out, human));
    }

    if selected_nodes.is_empty() && selected_relays.is_empty() {
        anyhow::bail!("nothing to import after applying --no-nodes / --no-relays filters");
    }

    let db = open_storage(paths)?;
    let mut imported_sub_id: Option<String> = None;
    let mut node_update_result = None;
    let mut imported_nodes_count = 0usize;
    let mut target_sub_total_nodes: Option<usize> = None;

    if !selected_nodes.is_empty() {
        let id_remap = if let Some(ref target_sub) = args.target_sub {
            let res =
                db.update_subscription_nodes_with_mode(target_sub, &selected_nodes, update_mode)?;
            if let Some(ref custom_name) = args.name {
                let trimmed = custom_name.trim();
                if !trimmed.is_empty() {
                    let _ = db.rename_subscription(target_sub, trimmed)?;
                }
            }
            imported_nodes_count = selected_nodes.len();
            target_sub_total_nodes = Some(res.total_count);
            imported_sub_id = Some(target_sub.clone());
            let remap = res.id_remap.clone();
            node_update_result = Some(res);
            remap
        } else {
            let new_sub_id = generate_migration_subscription_id().replacen("migrated-", "share-", 1);
            let sub_name = args
                .name
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| preview.manifest.name.clone());
            let sub_rec = SubscriptionRecord {
                id: new_sub_id.clone(),
                name: sub_name,
                kind: SubscriptionKind::File,
                url_or_cmd: display_file.clone(),
                ..Default::default()
            };
            db.upsert_subscription(&sub_rec)?;
            let res = db.update_subscription_nodes_with_mode(
                &new_sub_id,
                &selected_nodes,
                SubscriptionUpdateMode::ReplaceLatest,
            )?;
            imported_nodes_count = res.total_count;
            imported_sub_id = Some(new_sub_id);
            let remap = res.id_remap.clone();
            node_update_result = Some(res);
            remap
        };
        let _ = sync_active_single_node_after_mutation(paths, &db, &id_remap)?;
    }

    let imported_relays_count = if !selected_relays.is_empty() {
        let (count, relay_warnings) =
            catcloud_core::preaccel::import_relays_dedup_into_storage(&db, selected_relays)?;
        warnings.extend(
            relay_warnings
                .into_iter()
                .map(|w| sanitize_multiline_text(&w)),
        );
        count
    } else {
        0
    };

    let out = json!({
        "ok": true,
        "sanitized": true,
        "dry_run": false,
        "applied": true,
        "file": &display_file,
        "manifest": &preview.manifest,
        "subscription_id": &imported_sub_id,
        "mode": update_mode,
        "imported_nodes": imported_nodes_count,
        "target_sub_total_nodes": target_sub_total_nodes,
        "imported_relays": imported_relays_count,
        "node_update": node_update_result,
        "warnings": warnings,
    });
    let human = format!(
        "Imported share bundle `{}`: {} node(s), {} relay(s).",
        preview.manifest.name, imported_nodes_count, imported_relays_count
    );
    Ok((out, human))
}

fn handle_share_import(paths: &AppPaths, as_json: bool, args: ShareImportArgs) -> Result<()> {
    let (out, human) = execute_share_import(paths, args)?;
    emit_output(as_json, &out, &human)
}

/// Synchronize `AppConfig.active_single_node_id` after subscription merges or share imports:
/// applies `id_remap`, verifies the resolved node still exists in SQLite, falls back to the first
/// enabled node (or clears to `None` when none remain), and atomically writes `config.json` only
/// if `active_single_node_id` changed.
fn sync_active_single_node_after_mutation(
    paths: &AppPaths,
    db: &Storage,
    id_remap: &HashMap<String, String>,
) -> CatResult<bool> {
    let mut cfg = config::load_or_default(paths)?;
    let Some(cur) = cfg
        .active_single_node_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
    else {
        return Ok(false);
    };

    let mapped = id_remap.get(&cur).cloned().unwrap_or(cur);
    let nodes = db.list_nodes()?;
    let next_id = if nodes.iter().any(|n| n.id == mapped) {
        Some(mapped)
    } else {
        nodes.iter().find(|n| n.enabled).map(|n| n.id.clone())
    };

    if cfg.active_single_node_id == next_id {
        return Ok(false);
    }
    cfg.active_single_node_id = next_id;
    config::save(paths, &cfg)?;
    Ok(true)
}

fn sanitize_multiline_text(raw: &str) -> String {
    raw.split('\n')
        .map(sanitize_log_line)
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_path_with_reveal(path: &Path, reveal_secrets: bool) -> String {
    let raw = path.to_string_lossy();
    if reveal_secrets {
        raw.into_owned()
    } else {
        redact_path_for_display(&raw)
    }
}

fn format_paths_with_reveal(paths: &[PathBuf], reveal_secrets: bool) -> Vec<String> {
    paths
        .iter()
        .map(|p| format_path_with_reveal(p, reveal_secrets))
        .collect()
}

fn redact_download_guidance(guidance: &DownloadGuidance) -> DownloadGuidance {
    DownloadGuidance {
        core_kind: guidance.core_kind.clone(),
        platform_target: guidance.platform_target.clone(),
        recommended_asset_pattern: guidance.recommended_asset_pattern.clone(),
        official_releases_url: guidance.official_releases_url.clone(),
        target_install_path: PathBuf::from(redact_path_for_display(
            &guidance.target_install_path.to_string_lossy(),
        )),
        verify_sha256_required: guidance.verify_sha256_required,
        instructions: sanitize_multiline_text(&guidance.instructions),
    }
}

fn redact_preaccel_config_for_output(cfg: &PreAccelConfig) -> PreAccelConfig {
    let mut out = cfg.clone();
    out.windivert_dir = out.windivert_dir.as_deref().map(redact_path_for_display);
    out
}

fn redact_reload_outcome(outcome: &ReloadOutcome) -> ReloadOutcome {
    let mut out = outcome.clone();
    out.warnings = outcome
        .warnings
        .iter()
        .map(|w| sanitize_multiline_text(w))
        .collect();
    out.error = outcome.error.as_deref().map(sanitize_multiline_text);
    out
}

fn redact_config_issues(issues: &[ConfigValidationIssue]) -> Vec<ConfigValidationIssue> {
    issues
        .iter()
        .map(|issue| ConfigValidationIssue {
            field: issue.field.clone(),
            severity: issue.severity.clone(),
            message: sanitize_multiline_text(&issue.message),
        })
        .collect()
}

fn redact_static_validation(report: &StaticValidationReport) -> StaticValidationReport {
    StaticValidationReport {
        ok: report.ok,
        issues: report
            .issues
            .iter()
            .map(|issue| StaticCheckIssue {
                code: issue.code.clone(),
                severity: issue.severity,
                message: sanitize_multiline_text(&issue.message),
            })
            .collect(),
    }
}

fn redact_funnel_report(report: &FunnelRunReport) -> FunnelRunReport {
    let mut out = report.clone();
    for rec in &mut out.records {
        rec.detail = rec.detail.as_deref().map(sanitize_multiline_text);
    }
    out
}

fn build_probe_run_dry_run_payload(
    tier: &str,
    node_count: usize,
    probe_ids: &[String],
    plan: &Value,
    bin_res: &BinaryResolution,
    reveal_secrets: bool,
) -> (Value, String) {
    let display_binary_path = bin_res
        .path
        .as_ref()
        .map(|p| format_path_with_reveal(p, reveal_secrets));
    let display_candidates = format_paths_with_reveal(&bin_res.checked_candidates, reveal_secrets);
    let out = json!({
        "ok": true,
        "sanitized": !reveal_secrets,
        "dry_run": true,
        "executed": false,
        "tier": tier,
        "binary_found": bin_res.found,
        "binary_path": display_binary_path,
        "checked_candidates": display_candidates,
        "node_count": node_count,
        "probe_count": probe_ids.len(),
        "probes": probe_ids,
        "plan": plan,
    });
    let human = format!(
        "Prepared isolated probe plan (dry-run, {tier} tier): {} probe(s) x {node_count} node(s).",
        probe_ids.len()
    );
    (out, human)
}

fn build_probe_run_missing_binary_payload(
    tier: &str,
    node_count: usize,
    probe_ids: &[String],
    plan: &Value,
    bin_res: &BinaryResolution,
    reveal_secrets: bool,
) -> (Value, String) {
    let display_candidates = format_paths_with_reveal(&bin_res.checked_candidates, reveal_secrets);
    let display_guidance = bin_res.download_guidance.as_ref().map(|g| {
        if reveal_secrets {
            g.clone()
        } else {
            redact_download_guidance(g)
        }
    });
    let out = json!({
        "ok": false,
        "sanitized": !reveal_secrets,
        "dry_run": false,
        "executed": false,
        "reason": "mihomo binary not found",
        "tier": tier,
        "node_count": node_count,
        "probe_count": probe_ids.len(),
        "probes": probe_ids,
        "plan": plan,
        "checked_candidates": display_candidates,
        "download_guidance": display_guidance,
    });
    let human = match &display_guidance {
        Some(g) => format!(
            "Probe execution skipped: Mihomo binary not found. {}",
            g.instructions
        ),
        None => "Probe execution skipped: Mihomo binary not found.".to_string(),
    };
    (out, human)
}

fn is_info_placeholder_node(node: &ProxyNode) -> bool {
    const HINTS: &[&str] = &[
        "剩余流量",
        "剩餘流量",
        "过期时间",
        "過期時間",
        "到期",
        "套餐",
        "官网",
        "官網",
        "重置",
        "距离下次",
        "更新订阅",
    ];
    HINTS.iter().any(|h| node.name.contains(h))
}

fn resolve_valid_group_active_node<'a>(
    group: &MultiGroup,
    nodes: &'a [ProxyNode],
) -> Option<&'a ProxyNode> {
    if !group.member_node_ids.is_empty() {
        if let Some(active_id) = group
            .active_node_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if group.member_node_ids.iter().any(|m| m == active_id) {
                if let Some(node) = nodes.iter().find(|n| n.id == active_id && n.enabled) {
                    return Some(node);
                }
            }
        }
        return group
            .member_node_ids
            .iter()
            .find_map(|mid| nodes.iter().find(|n| &n.id == mid && n.enabled));
    }

    if let Some(active_id) = group
        .active_node_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if let Some(node) = nodes.iter().find(|n| n.id == active_id && n.enabled) {
            return Some(node);
        }
    }
    nodes.iter().find(|n| n.enabled)
}

fn select_preaccel_speed_reference_node(
    cfg: &AppConfig,
    groups: &[MultiGroup],
    nodes: &[ProxyNode],
    requested_node_id: Option<&str>,
) -> Result<(Option<ProxyNode>, Option<String>)> {
    if let Some(nid) = requested_node_id.map(str::trim).filter(|s| !s.is_empty()) {
        let node = nodes
            .iter()
            .find(|n| n.id == nid)
            .cloned()
            .with_context(|| format!("reference node `{nid}` not found"))?;
        if node.is_udp_only_transport() {
            anyhow::bail!(
                "reference node `{nid}` uses UDP-only transport (`{}`) and cannot chain through domestic TCP relays",
                node.protocol
            );
        }
        return Ok((Some(node), None));
    }

    let primary_group = cfg
        .active_group_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|gid| groups.iter().find(|g| g.id == gid))
        .or_else(|| groups.first());

    let homepage_node = if cfg.route_mode == RouteTargetMode::Single {
        cfg.active_single_node_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|nid| nodes.iter().find(|n| n.id == nid))
            .or_else(|| primary_group.and_then(|g| resolve_valid_group_active_node(g, nodes)))
    } else {
        match primary_group {
            Some(g) => resolve_valid_group_active_node(g, nodes),
            None => nodes.iter().find(|n| n.enabled).or_else(|| nodes.first()),
        }
    };

    if let Some(home) = homepage_node {
        if home.enabled && !home.is_udp_only_transport() {
            return Ok((Some(home.clone()), None));
        }
    }

    let mut seen: HashSet<&str> = HashSet::with_capacity(nodes.len());
    let mut ordered: Vec<&ProxyNode> = Vec::with_capacity(nodes.len());
    if let Some(group) = primary_group {
        if let Some(ref aid) = group.active_node_id {
            let in_group = group.member_node_ids.is_empty()
                || group.member_node_ids.iter().any(|m| m == aid);
            if in_group {
                if let Some(n) = nodes.iter().find(|n| &n.id == aid) {
                    if seen.insert(n.id.as_str()) {
                        ordered.push(n);
                    }
                }
            }
        }
        for mid in &group.member_node_ids {
            if let Some(n) = nodes.iter().find(|n| &n.id == mid) {
                if seen.insert(n.id.as_str()) {
                    ordered.push(n);
                }
            }
        }
    }
    for n in nodes {
        if seen.insert(n.id.as_str()) {
            ordered.push(n);
        }
    }

    let tcp_enabled: Vec<&ProxyNode> = ordered
        .into_iter()
        .filter(|n| n.enabled && !n.is_udp_only_transport())
        .collect();

    let picked = tcp_enabled
        .iter()
        .find(|n| !n.is_443_native && !is_info_placeholder_node(n))
        .or_else(|| tcp_enabled.iter().find(|n| !n.is_443_native))
        .or_else(|| tcp_enabled.iter().find(|n| !is_info_placeholder_node(n)))
        .or_else(|| tcp_enabled.first())
        .copied()
        .cloned();

    match picked {
        Some(node) => {
            let note = match homepage_node {
                Some(home) if home.is_udp_only_transport() => Some(format!(
                    "homepage node `{}` uses UDP-only transport; auto-selected `{}` as reference node",
                    home.name, node.name
                )),
                Some(home) if !home.enabled => Some(format!(
                    "homepage node `{}` is disabled; auto-selected `{}` as reference node",
                    home.name, node.name
                )),
                _ => None,
            };
            Ok((Some(node), note))
        }
        None => Ok((
            None,
            Some(
                "no enabled non-UDP overseas node available; running single-hop direct relay speed test"
                    .to_string(),
            ),
        )),
    }
}

struct PreAccelRelaySpeedOutcome {
    ok: bool,
    latency_ms: Option<f64>,
    up_mbps: Option<f64>,
    down_mbps: Option<f64>,
    error: Option<String>,
}

fn summarize_relay_throughput_error(direction: &str, detail: Option<&str>) -> String {
    let raw = detail.unwrap_or("").trim();
    if raw.is_empty() {
        return format!("{direction} returned no valid throughput");
    }
    let clean = sanitize_multiline_text(raw);
    let lower = clean.to_ascii_lowercase();
    if lower.contains("timed out") || lower.contains("timeout") {
        format!("{direction} timed out")
    } else if lower.contains("fast_fuse_triggered") {
        format!("{direction} aborted by fast fuse (<0.2 Mbps)")
    } else if lower.contains("connection reset")
        || lower.contains("broken pipe")
        || lower.contains("unexpected eof")
    {
        format!("{direction} connection closed by peer")
    } else {
        format!("{direction} failed ({clean})")
    }
}

async fn measure_single_preaccel_relay_speed(
    proxy_port: u16,
    relay_id: &str,
) -> PreAccelRelaySpeedOutcome {
    let measured_latency: Arc<std::sync::Mutex<Option<f64>>> =
        Arc::new(std::sync::Mutex::new(None));
    let measured_up: Arc<std::sync::Mutex<Option<f64>>> = Arc::new(std::sync::Mutex::new(None));
    let measured_down: Arc<std::sync::Mutex<Option<f64>>> = Arc::new(std::sync::Mutex::new(None));
    let lat_ref = Arc::clone(&measured_latency);
    let up_ref = Arc::clone(&measured_up);
    let down_ref = Arc::clone(&measured_down);
    let relay_id_owned = relay_id.to_string();

    let speed_fut = async move {
        let client = match build_isolated_http_client(proxy_port, Duration::from_secs(12)) {
            Ok(c) => c,
            Err(err) => {
                return PreAccelRelaySpeedOutcome {
                    ok: false,
                    latency_ms: None,
                    up_mbps: None,
                    down_mbps: None,
                    error: Some(sanitize_multiline_text(&format!(
                        "failed to build isolated probe HTTP client: {err}"
                    ))),
                };
            }
        };

        let latency_def = ProbeDefinition {
            id: "preaccel_relay_speed_latency".to_string(),
            name: "PreAccel Relay Latency".to_string(),
            kind: ProbeKind::Latency,
            target_url: "https://cp.cloudflare.com/generate_204".to_string(),
            method: "GET".to_string(),
            expected_status: Some(204),
            body_regex: None,
            payload_bytes: None,
            timeout_ms: 3500,
            builtin: false,
        };
        let lat_rec = match tokio::time::timeout(
            Duration::from_secs(6),
            run_latency_probe(&client, &relay_id_owned, &latency_def, 2),
        )
        .await
        {
            Ok(rec) => rec,
            Err(_) => {
                return PreAccelRelaySpeedOutcome {
                    ok: false,
                    latency_ms: None,
                    up_mbps: None,
                    down_mbps: None,
                    error: Some("latency probe timed out (6s)".to_string()),
                };
            }
        };
        if let Some(lat_ms) = lat_rec.latency_ms.filter(|v| v.is_finite() && *v > 0.0) {
            if let Ok(mut guard) = lat_ref.lock() {
                *guard = Some(lat_ms);
            }
        }
        if !lat_rec.ok {
            let reason = lat_rec
                .detail
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|d| format!("connectivity probe failed: {}", sanitize_multiline_text(d)))
                .unwrap_or_else(|| "connectivity probe failed".to_string());
            return PreAccelRelaySpeedOutcome {
                ok: false,
                latency_ms: lat_rec.latency_ms,
                up_mbps: None,
                down_mbps: None,
                error: Some(reason),
            };
        }

        // Keep-Alive TLS warmup against speed.cloudflare.com before measuring throughput.
        let _ = tokio::time::timeout(Duration::from_secs(4), async {
            if let Ok(resp) = client
                .get("https://speed.cloudflare.com/__down?bytes=1")
                .timeout(Duration::from_secs(4))
                .send()
                .await
            {
                let _ = resp.bytes().await;
            }
        })
        .await;

        let tp_cfg = ThroughputProbeConfig {
            fuse_bytes: 512 * 1024,
            fuse_min_mbps: 0.2,
            max_payload_bytes: 2 * 1024 * 1024,
        };

        let upload_def = ProbeDefinition {
            id: "preaccel_relay_speed_upload".to_string(),
            name: "PreAccel Relay Upload".to_string(),
            kind: ProbeKind::Upload,
            target_url: "https://speed.cloudflare.com/__up".to_string(),
            method: "POST".to_string(),
            expected_status: Some(200),
            body_regex: None,
            payload_bytes: Some(2 * 1024 * 1024),
            timeout_ms: 9000,
            builtin: false,
        };
        let (up_mbps, up_err): (Option<f64>, Option<String>) = match tokio::time::timeout(
            Duration::from_secs(20),
            run_upload_probe_with_config(&client, &relay_id_owned, &upload_def, &tp_cfg),
        )
        .await
        {
            Ok(rec) => {
                let speed = rec.up_mbps.filter(|v| v.is_finite() && *v > 0.0);
                if speed.is_some() {
                    (speed, None)
                } else {
                    (
                        None,
                        Some(summarize_relay_throughput_error(
                            "upload",
                            rec.detail.as_deref(),
                        )),
                    )
                }
            }
            Err(_) => (None, Some("upload timed out (20s)".to_string())),
        };
        if let Some(speed) = up_mbps {
            if let Ok(mut guard) = up_ref.lock() {
                *guard = Some(speed);
            }
        }

        let download_def = ProbeDefinition {
            id: "preaccel_relay_speed_download".to_string(),
            name: "PreAccel Relay Download".to_string(),
            kind: ProbeKind::Download,
            target_url: "https://speed.cloudflare.com/__down?bytes=2097152".to_string(),
            method: "GET".to_string(),
            expected_status: Some(200),
            body_regex: None,
            payload_bytes: Some(2 * 1024 * 1024),
            timeout_ms: 8000,
            builtin: false,
        };
        let (down_mbps, down_err): (Option<f64>, Option<String>) = match tokio::time::timeout(
            Duration::from_secs(18),
            run_download_probe_with_config(&client, &relay_id_owned, &download_def, &tp_cfg),
        )
        .await
        {
            Ok(rec) => {
                let speed = rec.down_mbps.filter(|v| v.is_finite() && *v > 0.0);
                if speed.is_some() {
                    (speed, None)
                } else {
                    (
                        None,
                        Some(summarize_relay_throughput_error(
                            "download",
                            rec.detail.as_deref(),
                        )),
                    )
                }
            }
            Err(_) => (None, Some("download timed out (18s)".to_string())),
        };
        if let Some(speed) = down_mbps {
            if let Ok(mut guard) = down_ref.lock() {
                *guard = Some(speed);
            }
        }

        let ok = up_mbps.is_some() || down_mbps.is_some();
        let error = match (up_mbps.is_some(), down_mbps.is_some()) {
            (true, true) => None,
            (true, false) => Some(down_err.unwrap_or_else(|| "download failed".to_string())),
            (false, true) => Some(up_err.unwrap_or_else(|| "upload failed".to_string())),
            (false, false) => Some(format!(
                "{}; {}",
                up_err.unwrap_or_else(|| "upload failed".to_string()),
                down_err.unwrap_or_else(|| "download failed".to_string())
            )),
        };

        PreAccelRelaySpeedOutcome {
            ok,
            latency_ms: lat_rec.latency_ms,
            up_mbps,
            down_mbps,
            error,
        }
    };

    match tokio::time::timeout(Duration::from_secs(45), speed_fut).await {
        Ok(outcome) => outcome,
        Err(_) => {
            let preserved_lat = measured_latency.lock().ok().and_then(|g| *g);
            let preserved_up = measured_up.lock().ok().and_then(|g| *g);
            let preserved_down = measured_down.lock().ok().and_then(|g| *g);
            PreAccelRelaySpeedOutcome {
                ok: preserved_up.is_some() || preserved_down.is_some(),
                latency_ms: preserved_lat,
                up_mbps: preserved_up,
                down_mbps: preserved_down,
                error: Some("relay speed test exceeded 45s budget and aborted".to_string()),
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogLevelFilter {
    All,
    Error,
    Warning,
    Info,
    Debug,
}

impl LogLevelFilter {
    fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }
}

fn parse_log_level_filter(raw: &str) -> Result<LogLevelFilter> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "all" | "" => Ok(LogLevelFilter::All),
        "error" | "err" => Ok(LogLevelFilter::Error),
        "warning" | "warn" => Ok(LogLevelFilter::Warning),
        "info" => Ok(LogLevelFilter::Info),
        "debug" => Ok(LogLevelFilter::Debug),
        other => anyhow::bail!("unsupported log level `{other}` (use all|error|warning|info|debug)"),
    }
}

fn detect_log_line_severity(line: &str) -> Option<u8> {
    // 4=ERROR, 3=WARN, 2=INFO, 1=DEBUG/TRACE
    let upper = line.to_ascii_uppercase();
    if upper.contains(" ERROR ")
        || upper.contains("[ERROR]")
        || upper.contains("\"LEVEL\":\"ERROR\"")
        || upper.contains("LEVEL=ERROR")
        || upper.starts_with("ERROR ")
        || upper.starts_with("ERROR:")
    {
        return Some(4);
    }
    if upper.contains(" WARN ")
        || upper.contains(" WARNING ")
        || upper.contains("[WARN]")
        || upper.contains("[WARNING]")
        || upper.contains("\"LEVEL\":\"WARN")
        || upper.contains("LEVEL=WARN")
        || upper.starts_with("WARN ")
        || upper.starts_with("WARNING ")
    {
        return Some(3);
    }
    if upper.contains(" INFO ")
        || upper.contains("[INFO]")
        || upper.contains("\"LEVEL\":\"INFO\"")
        || upper.contains("LEVEL=INFO")
        || upper.starts_with("INFO ")
    {
        return Some(2);
    }
    if upper.contains(" DEBUG ")
        || upper.contains(" TRACE ")
        || upper.contains("[DEBUG]")
        || upper.contains("[TRACE]")
        || upper.contains("\"LEVEL\":\"DEBUG\"")
        || upper.contains("LEVEL=DEBUG")
    {
        return Some(1);
    }
    None
}

fn line_matches_log_level(line: &str, filter: LogLevelFilter) -> bool {
    match filter {
        LogLevelFilter::All => true,
        LogLevelFilter::Error => detect_log_line_severity(line).is_some_and(|s| s >= 4),
        LogLevelFilter::Warning => detect_log_line_severity(line).is_some_and(|s| s >= 3),
        LogLevelFilter::Info => detect_log_line_severity(line).map_or(true, |s| s >= 2),
        LogLevelFilter::Debug => detect_log_line_severity(line).map_or(true, |s| s >= 1),
    }
}

fn read_bounded_file_lines(path: &Path, max_bytes: u64) -> Vec<String> {
    use std::io::{Read, Seek, SeekFrom};

    let Ok(mut file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let Ok(meta) = file.metadata() else {
        return Vec::new();
    };
    let len = meta.len();
    if len == 0 {
        return Vec::new();
    }
    let start = len.saturating_sub(max_bytes);
    if start > 0 && file.seek(SeekFrom::Start(start)).is_err() {
        return Vec::new();
    }
    let mut buf = Vec::with_capacity((len - start).min(max_bytes) as usize);
    if file.read_to_end(&mut buf).is_err() {
        return Vec::new();
    }
    let raw = String::from_utf8_lossy(&buf);
    let content = if start > 0 {
        match raw.find('\n') {
            Some(pos) => &raw[pos + 1..],
            None => raw.as_ref(),
        }
    } else {
        raw.as_ref()
    };
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn build_logs_tail_payload(
    paths: &AppPaths,
    requested_lines: usize,
    level_raw: &str,
) -> Result<(Value, String)> {
    let filter = parse_log_level_filter(level_raw)?;
    let capped = requested_lines.min(MAX_LOG_TAIL_LINES_CAP);
    let archive_path = paths.logs_dir.join("catcloud.log.1");
    let primary_path = paths.logs_dir.join("catcloud.log");

    let mut sources: Vec<String> = Vec::new();
    let mut combined: Vec<String> = Vec::new();
    for (label, candidate) in [
        ("catcloud.log.1", &archive_path),
        ("catcloud.log", &primary_path),
    ] {
        if candidate.is_file() {
            sources.push(label.to_string());
            combined.extend(read_bounded_file_lines(
                candidate,
                MAX_LOGS_TAIL_READ_BYTES_PER_FILE,
            ));
        }
    }

    let mut matched: Vec<String> = combined
        .into_iter()
        .filter(|line| line_matches_log_level(line, filter))
        .collect();
    if matched.len() > capped {
        let drop_count = matched.len() - capped;
        matched.drain(0..drop_count);
    }
    let sanitized_lines: Vec<String> = matched.iter().map(|l| sanitize_log_line(l)).collect();

    let out = json!({
        "ok": true,
        "sanitized": true,
        "level": filter.as_str(),
        "requested_lines": capped,
        "count": sanitized_lines.len(),
        "sources": sources,
        "lines": &sanitized_lines,
    });
    let human = if sanitized_lines.is_empty() {
        format!(
            "No matching log lines (level={}, sources={:?}).",
            filter.as_str(),
            out["sources"]
        )
    } else {
        sanitized_lines.join("\n")
    };
    Ok((out, human))
}

async fn probe_live_controller(
    paths: &AppPaths,
    cfg: &AppConfig,
) -> (Option<String>, Option<String>, ResolvedControllerEndpoint) {
    let ep = resolve_effective_controller_endpoint_info(paths, cfg);
    let Ok(job_guard) = JobGuard::new() else {
        return (None, None, ep);
    };
    let Ok(adapter) = MihomoAdapter::with_controller_endpoint(
        Arc::new(job_guard),
        &ep.host,
        ep.port,
        ep.secret.clone(),
    ) else {
        return (None, None, ep);
    };
    match tokio::time::timeout(Duration::from_secs(2), adapter.fetch_version()).await {
        Ok(Ok(ver)) => (Some(ver), None, ep),
        Ok(Err(CatError::Core(msg))) if msg.contains("HTTP 401") || msg.contains("HTTP 403") => {
            (None, Some(sanitize_log_line(&msg)), ep)
        }
        _ => (None, None, ep),
    }
}

async fn build_net_connections_payload(paths: &AppPaths, limit: usize) -> Result<(Value, String)> {
    let cfg = config::load_or_init(paths)?;
    let job_guard = Arc::new(JobGuard::new()?);
    let ep = resolve_effective_controller_endpoint_info(paths, &cfg);
    let controller_addr = format_host_port(&ep.host, ep.port);
    let adapter = MihomoAdapter::with_controller_endpoint(
        job_guard,
        &ep.host,
        ep.port,
        ep.secret,
    )?;

    match tokio::time::timeout(Duration::from_secs(2), adapter.list_connections()).await {
        Ok(Ok(snapshot)) => {
            let total = snapshot.connections.len();
            let redacted: Vec<ActiveConnection> = snapshot
                .connections
                .iter()
                .take(limit)
                .map(redact_connection_for_readonly)
                .collect();
            let out = json!({
                "ok": true,
                "sanitized": true,
                "core_running": true,
                "auth_error": false,
                "controller_addr": controller_addr,
                "download_total": snapshot.download_total,
                "upload_total": snapshot.upload_total,
                "memory": snapshot.memory,
                "total_connections": total,
                "returned_connections": redacted.len(),
                "connections": redacted,
            });
            let human = format!(
                "Active connections: showing {}/{total} (sanitized, core_running=true).",
                out["returned_connections"]
            );
            Ok((out, human))
        }
        Ok(Err(CatError::Core(msg))) if msg.contains("HTTP 401") || msg.contains("HTTP 403") => {
            let clean = sanitize_log_line(&msg);
            let out = json!({
                "ok": true,
                "sanitized": true,
                "core_running": true,
                "auth_error": true,
                "controller_addr": controller_addr,
                "download_total": 0u64,
                "upload_total": 0u64,
                "memory": 0u64,
                "total_connections": 0usize,
                "returned_connections": 0usize,
                "connections": [],
                "note": format!("Controller reachable but authentication failed ({clean})."),
            });
            Ok((
                out,
                "Core controller reachable, but authentication failed; returning 0 connections."
                    .to_string(),
            ))
        }
        _ => {
            let out = json!({
                "ok": true,
                "sanitized": true,
                "core_running": false,
                "auth_error": false,
                "controller_addr": controller_addr,
                "download_total": 0u64,
                "upload_total": 0u64,
                "memory": 0u64,
                "total_connections": 0usize,
                "returned_connections": 0usize,
                "connections": [],
                "note": "Mihomo core controller is not currently running or reachable.",
            });
            Ok((
                out,
                "Mihomo core is not running (core_running=false); 0 active connections."
                    .to_string(),
            ))
        }
    }
}

fn is_path_writable_probe(dir: &Path) -> bool {
    let probe = dir.join(format!(".catcloud_doc_probe.{}", std::process::id()));
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

async fn build_net_doctor_payload(paths: &AppPaths) -> Result<(Value, String)> {
    let cfg = config::load_or_init(paths)?;
    let db = open_storage(paths)?;
    let plat = default_platform();
    let caps = plat.capabilities();

    let subs = db.list_subscriptions()?;
    let nodes = db.list_nodes()?;
    let groups = db.list_multi_groups()?;
    let relays = db.list_preaccel_relays(false)?;

    let mut checks: Vec<Value> = Vec::with_capacity(7);
    let mut recommendations: Vec<String> = Vec::new();

    // Check 1: Portable / standard paths & storage counts
    let data_dir_writable = is_path_writable_probe(&paths.root_data_dir);
    let display_data_dir = redact_path_for_display(&paths.root_data_dir.to_string_lossy());
    let storage_status = if !data_dir_writable {
        recommendations.push(
            "Data directory is not writable; verify permissions or pass a writable --data-dir."
                .to_string(),
        );
        "fail"
    } else if nodes.is_empty() {
        recommendations.push(
            "No proxy nodes imported yet; import a subscription URL, .zip share bundle, or migrate an existing client."
                .to_string(),
        );
        "warn"
    } else {
        "pass"
    };
    checks.push(json!({
        "id": "storage_and_paths",
        "layer": 1,
        "name": "Paths & Local Storage",
        "status": storage_status,
        "detail": format!(
            "portable={}, writable={}, subs={}, nodes={}, groups={}, relays={}",
            paths.is_portable,
            data_dir_writable,
            subs.len(),
            nodes.len(),
            groups.len(),
            relays.len()
        ),
        "data": {
            "is_portable": paths.is_portable,
            "data_dir": display_data_dir,
            "writable": data_dir_writable,
            "instance_hash": paths.instance_hash,
            "counts": {
                "subscriptions": subs.len(),
                "nodes": nodes.len(),
                "multi_groups": groups.len(),
                "preaccel_relays": relays.len(),
            }
        }
    }));

    // Check 2: Configuration validity & offline static compile check
    let cfg_issues = config::validate_config_detailed(&cfg);
    let cfg_errors = cfg_issues
        .iter()
        .filter(|i| i.severity == ValidationSeverity::Error)
        .count();
    let offline_ports = AllocatedPorts {
        bind_host: if cfg.allow_lan {
            cfg.bind_address.clone()
        } else {
            "127.0.0.1".to_string()
        },
        mixed_port: cfg.mixed_port,
        controller_port: cfg.controller_port,
        dns_port: cfg.dns_listen_port,
        shifted: Vec::new(),
    };
    let empty_filter = HashMap::new();
    let compile_res = compile_mihomo_config_with_runtime_dir(
        &CompileInput {
            config: &cfg,
            nodes: &nodes,
            groups: &groups,
            relays: &relays,
            controller_secret: "doctor-placeholder-secret",
            allocated_ports: &offline_ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &empty_filter,
        },
        Some(&paths.runtime_dir),
    );
    let (compile_ok, compile_err, compile_warn_count, compile_stats) = match compile_res {
        Ok(c) => {
            let err_list: Vec<String> = c
                .validation
                .errors()
                .iter()
                .map(|i| sanitize_log_line(&format!("[{}] {}", i.code, i.message)))
                .collect();
            let ok = err_list.is_empty();
            let err_text = if ok {
                None
            } else {
                Some(err_list.join("; "))
            };
            (ok, err_text, c.validation.warnings().len(), Some(c.stats))
        }
        Err(e) => (false, Some(sanitize_log_line(&e.to_string())), 0, None),
    };
    let config_status = if cfg_errors > 0 || !compile_ok {
        recommendations.push(
            "Configuration or anti-loop preflight check reported errors; inspect `catcloud config validate --json`."
                .to_string(),
        );
        "fail"
    } else if !cfg_issues.is_empty() || compile_warn_count > 0 {
        "warn"
    } else {
        "pass"
    };
    checks.push(json!({
        "id": "config_validation",
        "layer": 3,
        "name": "Configuration & Static Compile Preflight",
        "status": config_status,
        "detail": format!(
            "config_errors={cfg_errors}, compile_ok={compile_ok}, compile_warnings={compile_warn_count}"
        ),
        "data": {
            "config_issues": redact_config_issues(&cfg_issues),
            "compile_ok": compile_ok,
            "compile_error": compile_err,
            "compile_warnings": compile_warn_count,
            "stats": compile_stats,
        }
    }));

    // Check 3: Core binary, live controller & configured/active ports
    let bin_res = resolve_mihomo_binary(&cfg, paths, &[], false)?;
    let (live_version, controller_auth_err, ctrl_ep) = probe_live_controller(paths, &cfg).await;
    let core_running = live_version.is_some();
    let effective_mixed_port = if core_running {
        ctrl_ep.mixed_port.unwrap_or(cfg.mixed_port)
    } else {
        cfg.mixed_port
    };
    let effective_ctrl_port = if core_running || controller_auth_err.is_some() {
        ctrl_ep.port
    } else {
        cfg.controller_port
    };
    let effective_dns_port = if core_running {
        ctrl_ep.dns_port.unwrap_or(cfg.dns_listen_port)
    } else {
        cfg.dns_listen_port
    };
    let mixed_free = is_port_available_tcp_udp(&cfg.bind_address, effective_mixed_port);
    let ctrl_free = is_port_available_tcp_udp(&ctrl_ep.host, effective_ctrl_port);
    let dns_free = is_port_available_tcp_udp(&cfg.dns_listen_host, effective_dns_port);

    let core_status = if !bin_res.found {
        recommendations.push(
            "Mihomo core binary was not found; place mihomo in the bin directory or install a bundled release."
                .to_string(),
        );
        "fail"
    } else if controller_auth_err.is_some() {
        recommendations.push(
            "Running controller rejected authentication; ensure config.json controller_secret matches the active core or restart core to refresh runtime metadata."
                .to_string(),
        );
        "warn"
    } else if !core_running && (!mixed_free || !ctrl_free || !dns_free) {
        recommendations.push(
            "One or more configured CatCloud ports are occupied while CatCloud core is not running; enable port_guard_auto_shift or free conflicting ports."
                .to_string(),
        );
        if cfg.port_guard_auto_shift {
            "warn"
        } else {
            "fail"
        }
    } else {
        "pass"
    };
    checks.push(json!({
        "id": "core_and_ports",
        "layer": 3,
        "name": "Core Binary & Listening Ports",
        "status": core_status,
        "detail": format!(
            "binary_found={}, core_running={}, ports(mixed={}:free={}, ctrl={}:free={}, dns={}:free={})",
            bin_res.found,
            core_running,
            effective_mixed_port,
            mixed_free,
            effective_ctrl_port,
            ctrl_free,
            effective_dns_port,
            dns_free
        ),
        "data": {
            "binary_found": bin_res.found,
            "binary_source": bin_res.source,
            "binary_path": bin_res.path.as_ref().map(|p| redact_path_for_display(&p.to_string_lossy())),
            "core_running": core_running,
            "core_version": live_version,
            "controller_auth_error": controller_auth_err,
            "port_guard_auto_shift": cfg.port_guard_auto_shift,
            "ports": {
                "mixed_port": effective_mixed_port,
                "mixed_available": mixed_free,
                "controller_port": effective_ctrl_port,
                "controller_available": ctrl_free,
                "dns_listen_port": effective_dns_port,
                "dns_available": dns_free,
            }
        }
    }));

    // Check 4: System Proxy & TUN readiness
    let os_proxy_res = plat.read_system_proxy();
    let (os_proxy_val, os_proxy_mismatch, os_proxy_dangling) = match os_proxy_res {
        Ok(spec) => {
            let mismatch = spec.enabled && spec.port != effective_mixed_port;
            let dangling = spec.enabled && !core_running && spec.port == effective_mixed_port;
            (
                json!({
                    "readable": true,
                    "enabled": spec.enabled,
                    "host": redact_ip_or_host(&spec.host),
                    "port": spec.port,
                    "pac_url": spec.pac_url.as_deref().map(sanitize_log_line),
                    "bypass_count": spec.bypass.len(),
                }),
                mismatch,
                dangling,
            )
        }
        Err(err) => (
            json!({
                "readable": false,
                "error": sanitize_log_line(&err.to_string()),
            }),
            false,
            false,
        ),
    };
    let tun_privilege_ready = is_cli_tun_privilege_ready(&caps, bin_res.path.as_deref());
    let tun_configured = cfg.tun.enabled;
    let tun_effective_enabled = tun_configured && tun_privilege_ready;
    let tun_needs_admin = tun_configured && !tun_privilege_ready;
    let proxy_tun_status = if os_proxy_dangling || os_proxy_mismatch || tun_needs_admin {
        if os_proxy_dangling {
            recommendations.push(
                "OS system proxy points to CatCloud mixed_port while core is stopped; start CatCloud core or disable system proxy."
                    .to_string(),
            );
        }
        if os_proxy_mismatch {
            recommendations.push(
                "OS system proxy is currently pointing to another port; check for another proxy client or residual system proxy setting."
                    .to_string(),
            );
        }
        if tun_needs_admin {
            recommendations.push(
                "TUN mode is enabled in config but current process lacks TUN privilege; run with administrator/root privileges (or grant cap_net_admin on Linux) for TUN."
                    .to_string(),
            );
        }
        "warn"
    } else {
        "pass"
    };
    checks.push(json!({
        "id": "system_proxy_and_tun",
        "layer": 3,
        "name": "System Proxy & Virtual NIC (TUN)",
        "status": proxy_tun_status,
        "detail": format!(
            "cfg_sys_proxy={}, tun_configured={}, tun_enabled={}, tun_needs_elevation={}, tun_stack={}, elevated={}, os_proxy_mismatch={}, os_proxy_dangling={}",
            cfg.system_proxy.enabled,
            tun_configured,
            tun_effective_enabled,
            tun_needs_admin,
            cfg.tun.stack_mode.as_str(),
            caps.is_elevated,
            os_proxy_mismatch,
            os_proxy_dangling
        ),
        "data": {
            "config_system_proxy_enabled": cfg.system_proxy.enabled,
            "proxy_guard_enabled": cfg.system_proxy.proxy_guard.enabled,
            "config_tun_enabled": tun_configured,
            "tun_configured": tun_configured,
            "tun_enabled": tun_effective_enabled,
            "tun_needs_elevation": tun_needs_admin,
            "tun_privilege_ready": tun_privilege_ready,
            "tun_stack": cfg.tun.stack_mode,
            "is_elevated": caps.is_elevated,
            "os_system_proxy": os_proxy_val,
        }
    }));

    // Check 5: Domestic pre-acceleration relays & WinDivert readiness
    let now = Utc::now();
    let enabled_relays: Vec<&PreAccelRelay> = relays.iter().filter(|r| r.enabled).collect();
    let expired_relays = enabled_relays
        .iter()
        .filter(|r| evaluate_expiry(r.expires_at.as_deref(), now).tag() == "expired")
        .count();
    let expiring_soon_relays = enabled_relays
        .iter()
        .filter(|r| evaluate_expiry(r.expires_at.as_deref(), now).tag() == "expiring_soon")
        .count();
    let wd_files = locate_windivert_files(paths, cfg.preaccel.windivert_dir.as_deref());
    let security_products = detect_host_security_products();
    let preaccel_plan = build_preaccel_compile_plan(&cfg.preaccel, &relays, &nodes);
    let preaccel_status = match &preaccel_plan {
        Err(_) => {
            recommendations.push(
                "Domestic pre-acceleration plan validation failed; verify domestic 204 probe URL and relay SNI rules."
                    .to_string(),
            );
            "fail"
        }
        Ok(_) if (cfg.preaccel.enabled || cfg.preaccel.global_bypass_enabled)
            && (enabled_relays.is_empty() || expired_relays > 0) =>
        {
            recommendations.push(
                "Domestic pre-acceleration is enabled but has no active non-expired relays; update relays or disable preaccel."
                    .to_string(),
            );
            "warn"
        }
        Ok(_) if cfg!(target_os = "windows")
            && cfg.preaccel.global_bypass_enabled
            && wd_files.is_none() =>
        {
            recommendations.push(
                "Global domestic pre-acceleration is enabled without WinDivert binaries; it will fall back to local SOCKS5 mode."
                    .to_string(),
            );
            "warn"
        }
        Ok(_) if expiring_soon_relays > 0 => "warn",
        Ok(_) => "pass",
    };
    checks.push(json!({
        "id": "preaccel_and_windivert",
        "layer": 5,
        "name": "Domestic Pre-Acceleration & WinDivert",
        "status": preaccel_status,
        "detail": format!(
            "enabled={}, global={}, enabled_relays={}, expired={}, windivert_available={}",
            cfg.preaccel.enabled,
            cfg.preaccel.global_bypass_enabled,
            enabled_relays.len(),
            expired_relays,
            wd_files.is_some()
        ),
        "data": {
            "enabled": cfg.preaccel.enabled,
            "global_bypass_enabled": cfg.preaccel.global_bypass_enabled,
            "skip_443_native": cfg.preaccel.skip_443_native,
            "enabled_relay_count": enabled_relays.len(),
            "expired_relay_count": expired_relays,
            "expiring_soon_relay_count": expiring_soon_relays,
            "windivert_available": wd_files.is_some(),
            "windivert_dll": wd_files.as_ref().map(|(dll, _)| redact_path_for_display(&dll.to_string_lossy())),
            "detected_security_products": security_products,
            "plan_error": preaccel_plan.as_ref().err().map(|e| sanitize_log_line(&e.to_string())),
            "plan_warnings": preaccel_plan.as_ref().map(|p| p.warnings.iter().map(|w| sanitize_log_line(w)).collect::<Vec<_>>()).unwrap_or_default(),
        }
    }));

    // Check 6: Conflicting proxy processes, common occupied proxy ports, and proxy env vars
    let mut env_proxies: HashMap<String, String> = HashMap::new();
    for key in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    ] {
        if let Ok(val) = std::env::var(key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                env_proxies.insert(key.to_string(), sanitize_log_line(trimmed));
            }
        }
    }
    let other_proxy_procs: Vec<Value> = list_process_candidates(true)
        .into_iter()
        .map(|p| {
            let r = redact_process_candidate(&p);
            json!({
                "pid": r.pid,
                "name": r.name,
                "detected_controller_addr": r.detected_controller_addr,
            })
        })
        .collect();
    const COMMON_PROXY_PORTS: &[u16] = &[7890, 7897, 10808, 10809, 2080, 1080];
    let mut occupied_other_ports: Vec<u16> = Vec::new();
    for &p in COMMON_PROXY_PORTS {
        if core_running && (p == cfg.mixed_port || p == cfg.controller_port) {
            continue;
        }
        if !is_port_available_tcp_udp("127.0.0.1", p) {
            occupied_other_ports.push(p);
        }
    }
    let conflict_status =
        if !other_proxy_procs.is_empty() || !occupied_other_ports.is_empty() || !env_proxies.is_empty()
        {
            if !other_proxy_procs.is_empty() {
                recommendations.push(
                    "Other proxy-like processes are running on this machine; verify they do not fight over ports, system proxy, or TUN routes."
                        .to_string(),
                );
            }
            if !env_proxies.is_empty() {
                recommendations.push(
                    "Terminal proxy environment variables (HTTP_PROXY/HTTPS_PROXY/ALL_PROXY) are set; confirm they point to the intended port."
                        .to_string(),
                );
            }
            "warn"
        } else {
            "pass"
        };
    checks.push(json!({
        "id": "proxy_conflicts_and_env",
        "layer": 2,
        "name": "Conflicting Proxy Clients, Ports & Env Vars",
        "status": conflict_status,
        "detail": format!(
            "other_proxy_processes={}, occupied_common_ports={:?}, proxy_env_vars={}",
            other_proxy_procs.len(),
            occupied_other_ports,
            env_proxies.len()
        ),
        "data": {
            "other_proxy_processes": other_proxy_procs,
            "occupied_common_proxy_ports": occupied_other_ports,
            "proxy_env_vars": env_proxies,
        }
    }));

    // Check 7: GeoData readiness (aligned strictly with Country.mmdb / country.mmdb)
    let geodata = collect_geodata_status(&paths.runtime_dir);
    let has_country_mmdb = geodata["country_mmdb"]["exists"].as_bool().unwrap_or(false);
    let has_geosite = geodata["geosite_dat"]["exists"].as_bool().unwrap_or(false);
    let geo_status = if cfg.rules_override.domestic_direct_enabled && !has_country_mmdb {
        recommendations.push(
            "Country.mmdb is missing while domestic direct routing is enabled; refresh GeoData in Settings."
                .to_string(),
        );
        "warn"
    } else {
        "pass"
    };
    checks.push(json!({
        "id": "geodata_status",
        "layer": 4,
        "name": "GeoData Databases",
        "status": geo_status,
        "detail": format!("country_mmdb={has_country_mmdb}, geosite_dat={has_geosite}"),
        "data": geodata,
    }));

    let pass_count = checks.iter().filter(|c| c["status"] == "pass").count();
    let warn_count = checks.iter().filter(|c| c["status"] == "warn").count();
    let fail_count = checks.iter().filter(|c| c["status"] == "fail").count();
    let healthy = fail_count == 0;

    let out = json!({
        "ok": true,
        "sanitized": true,
        "healthy": healthy,
        "version": env!("CARGO_PKG_VERSION"),
        "os": caps.os,
        "arch": caps.arch,
        "summary": {
            "total": checks.len(),
            "pass": pass_count,
            "warn": warn_count,
            "fail": fail_count,
        },
        "checks": &checks,
        "recommendations": &recommendations,
    });
    let mut lines = vec![format!(
        "CatCloud Net Doctor: healthy={healthy} (pass={pass_count}, warn={warn_count}, fail={fail_count})"
    )];
    for check in &checks {
        lines.push(format!(
            "- [{}] L{} {}: {}",
            check["status"].as_str().unwrap_or("info").to_uppercase(),
            check["layer"],
            check["name"].as_str().unwrap_or(""),
            check["detail"].as_str().unwrap_or("")
        ));
    }
    Ok((out, lines.join("\n")))
}

fn normalize_match_target(raw: &str) -> Result<(String, Option<u16>)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        anyhow::bail!("domain or IP target cannot be empty");
    }
    let without_scheme = trimmed
        .split_once("://")
        .map_or(trimmed, |(_, after)| after);
    let authority = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(without_scheme)
        .trim();
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, hp)| hp)
        .trim();

    if let Some(rest) = host_port.strip_prefix('[') {
        if let Some((inner, tail)) = rest.split_once(']') {
            let port_override = tail.strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
            return Ok((inner.trim_end_matches('.').to_ascii_lowercase(), port_override));
        }
    }

    if host_port.parse::<IpAddr>().is_ok() {
        return Ok((host_port.to_ascii_lowercase(), None));
    }

    if let Some((h, p)) = host_port.rsplit_once(':') {
        if !h.contains(':') {
            if let Ok(port_num) = p.parse::<u16>() {
                let norm = h.trim_end_matches('.').to_ascii_lowercase();
                if !norm.is_empty() {
                    return Ok((norm, Some(port_num)));
                }
            }
        }
    }

    let norm = host_port.trim_end_matches('.').to_ascii_lowercase();
    if norm.is_empty() {
        anyhow::bail!("invalid domain or IP target `{raw}`");
    }
    Ok((norm, None))
}

fn unquote_yaml_scalar(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('\'') && trimmed.ends_with('\'') {
        return trimmed[1..trimmed.len() - 1].replace("''", "'");
    }
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        return serde_json::from_str::<String>(trimmed)
            .unwrap_or_else(|_| trimmed[1..trimmed.len() - 1].to_string());
    }
    trimmed.to_string()
}

fn extract_yaml_sequence_under_key(yaml: &str, key: &str, top_level_only: bool) -> Vec<String> {
    let mut items = Vec::new();
    let mut in_section = false;
    let mut key_indent: usize = 0;

    for raw_line in yaml.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = raw_line.len() - raw_line.trim_start_matches(' ').len();
        if !in_section {
            if (!top_level_only || indent == 0) && trimmed == format!("{key}:") {
                in_section = true;
                key_indent = indent;
            }
            continue;
        }

        if indent < key_indent || (indent == key_indent && !trimmed.starts_with('-')) {
            break;
        }
        if let Some(rest) = trimmed.strip_prefix("- ") {
            items.push(unquote_yaml_scalar(rest));
        } else if trimmed == "-" {
            continue;
        } else if indent <= key_indent {
            break;
        }
    }
    items
}

fn domain_matches_wildcard(pattern: &str, host: &str) -> bool {
    let p = pattern.trim().to_ascii_lowercase();
    let h = host.trim().to_ascii_lowercase();
    if p.is_empty() || h.is_empty() {
        return false;
    }
    if let Some(suffix) = p.strip_prefix("+.") {
        return h == suffix || h.ends_with(&format!(".{suffix}"));
    }
    if let Some(suffix) = p.strip_prefix("*.") {
        return h.ends_with(&format!(".{suffix}"));
    }
    if !p.contains('*') {
        return h == p;
    }
    // Simple glob wildcard matching for `*`
    let parts: Vec<&str> = p.split('*').collect();
    let mut cursor = 0usize;
    for (idx, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if idx == 0 {
            if !h.starts_with(part) {
                return false;
            }
            cursor = part.len();
        } else if idx + 1 == parts.len() {
            if !h[cursor..].ends_with(part) {
                return false;
            }
            cursor = h.len();
        } else if let Some(rel) = h[cursor..].find(part) {
            cursor += rel + part.len();
        } else {
            return false;
        }
    }
    true
}

fn ip_matches_cidr(ip: IpAddr, cidr: &str) -> bool {
    let Some((net_str, prefix_str)) = cidr.trim().split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix_str.trim().parse::<u32>() else {
        return false;
    };
    match (ip, net_str.trim().parse::<IpAddr>()) {
        (IpAddr::V4(addr), Ok(IpAddr::V4(net))) if prefix <= 32 => {
            if prefix == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - prefix);
            (u32::from(addr) & mask) == (u32::from(net) & mask)
        }
        (IpAddr::V6(addr), Ok(IpAddr::V6(net))) if prefix <= 128 => {
            if prefix == 0 {
                return true;
            }
            let mask = u128::MAX << (128 - prefix);
            (u128::from(addr) & mask) == (u128::from(net) & mask)
        }
        _ => false,
    }
}

fn port_matches_spec(port: u16, spec: &str) -> bool {
    for part in spec.split('/') {
        let p = part.trim();
        if let Some((lo, hi)) = p.split_once('-') {
            if let (Ok(a), Ok(b)) = (lo.trim().parse::<u16>(), hi.trim().parse::<u16>()) {
                if port >= a && port <= b {
                    return true;
                }
            }
        } else if let Ok(exact) = p.parse::<u16>() {
            if port == exact {
                return true;
            }
        }
    }
    false
}

fn split_top_level_rule_parts(rule: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (idx, ch) in rule.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth = (depth - 1).max(0),
            ',' if depth == 0 => {
                parts.push(rule[start..idx].trim());
                start = idx + 1;
            }
            _ => {}
        }
    }
    parts.push(rule[start..].trim());
    parts
}

fn split_logical_children(expr: &str) -> Option<Vec<&str>> {
    let trimmed = expr.trim();
    if !trimmed.starts_with('(') || !trimmed.ends_with(')') {
        return None;
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    let mut items = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (idx, ch) in inner.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth = (depth - 1).max(0),
            ',' if depth == 0 => {
                let seg = inner[start..idx].trim();
                if !seg.is_empty() {
                    items.push(seg);
                }
                start = idx + 1;
            }
            _ => {}
        }
    }
    let tail = inner[start..].trim();
    if !tail.is_empty() {
        items.push(tail);
    }
    Some(items)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConditionEval {
    Matched,
    NotMatched,
    UnknownGeo,
}

fn eval_rule_condition(
    rule_type: &str,
    payload: &str,
    host: &str,
    parsed_ip: Option<IpAddr>,
    network: &str,
    port: u16,
) -> ConditionEval {
    match rule_type.trim().to_ascii_uppercase().as_str() {
        "MATCH" => ConditionEval::Matched,
        "DOMAIN" => {
            if host.eq_ignore_ascii_case(payload.trim()) {
                ConditionEval::Matched
            } else {
                ConditionEval::NotMatched
            }
        }
        "DOMAIN-SUFFIX" => {
            let suffix = payload.trim().to_ascii_lowercase();
            if !suffix.is_empty() && (host == suffix || host.ends_with(&format!(".{suffix}"))) {
                ConditionEval::Matched
            } else {
                ConditionEval::NotMatched
            }
        }
        "DOMAIN-KEYWORD" => {
            let kw = payload.trim().to_ascii_lowercase();
            if !kw.is_empty() && host.contains(&kw) {
                ConditionEval::Matched
            } else {
                ConditionEval::NotMatched
            }
        }
        "DOMAIN-WILDCARD" => {
            if domain_matches_wildcard(payload, host) {
                ConditionEval::Matched
            } else {
                ConditionEval::NotMatched
            }
        }
        "IP-CIDR" | "IP-CIDR6" => match parsed_ip {
            Some(ip) if ip_matches_cidr(ip, payload) => ConditionEval::Matched,
            _ => ConditionEval::NotMatched,
        },
        "NETWORK" => {
            if network.eq_ignore_ascii_case(payload.trim()) {
                ConditionEval::Matched
            } else {
                ConditionEval::NotMatched
            }
        }
        "DST-PORT" => {
            if port_matches_spec(port, payload) {
                ConditionEval::Matched
            } else {
                ConditionEval::NotMatched
            }
        }
        "GEOSITE" | "GEOIP" => ConditionEval::UnknownGeo,
        "AND" => {
            let Some(children) = split_logical_children(payload) else {
                return ConditionEval::NotMatched;
            };
            let mut saw_unknown = false;
            for child in children {
                let inner = child
                    .strip_prefix('(')
                    .and_then(|s| s.strip_suffix(')'))
                    .unwrap_or(child);
                let parts = split_top_level_rule_parts(inner);
                if parts.len() < 2 {
                    return ConditionEval::NotMatched;
                }
                match eval_rule_condition(parts[0], parts[1], host, parsed_ip, network, port) {
                    ConditionEval::Matched => {}
                    ConditionEval::NotMatched => return ConditionEval::NotMatched,
                    ConditionEval::UnknownGeo => saw_unknown = true,
                }
            }
            if saw_unknown {
                ConditionEval::UnknownGeo
            } else {
                ConditionEval::Matched
            }
        }
        "OR" => {
            let Some(children) = split_logical_children(payload) else {
                return ConditionEval::NotMatched;
            };
            let mut saw_unknown = false;
            for child in children {
                let inner = child
                    .strip_prefix('(')
                    .and_then(|s| s.strip_suffix(')'))
                    .unwrap_or(child);
                let parts = split_top_level_rule_parts(inner);
                if parts.len() < 2 {
                    continue;
                }
                match eval_rule_condition(parts[0], parts[1], host, parsed_ip, network, port) {
                    ConditionEval::Matched => return ConditionEval::Matched,
                    ConditionEval::NotMatched => {}
                    ConditionEval::UnknownGeo => saw_unknown = true,
                }
            }
            if saw_unknown {
                ConditionEval::UnknownGeo
            } else {
                ConditionEval::NotMatched
            }
        }
        "NOT" => {
            let Some(children) = split_logical_children(payload) else {
                return ConditionEval::NotMatched;
            };
            let Some(first) = children.first() else {
                return ConditionEval::NotMatched;
            };
            let inner = first
                .strip_prefix('(')
                .and_then(|s| s.strip_suffix(')'))
                .unwrap_or(first);
            let parts = split_top_level_rule_parts(inner);
            if parts.len() < 2 {
                return ConditionEval::NotMatched;
            }
            match eval_rule_condition(parts[0], parts[1], host, parsed_ip, network, port) {
                ConditionEval::Matched => ConditionEval::NotMatched,
                ConditionEval::NotMatched => ConditionEval::Matched,
                ConditionEval::UnknownGeo => ConditionEval::UnknownGeo,
            }
        }
        _ => ConditionEval::NotMatched,
    }
}

async fn build_net_match_payload(
    paths: &AppPaths,
    raw_domain: &str,
    raw_network: &str,
    default_port: u16,
) -> Result<(Value, String)> {
    let (host, port_override) = normalize_match_target(raw_domain)?;
    let port = port_override.unwrap_or(default_port);
    let network = match raw_network.trim().to_ascii_lowercase().as_str() {
        "tcp" => "tcp",
        "udp" => "udp",
        other => anyhow::bail!("unsupported network `{other}` (use tcp|udp)"),
    };
    let parsed_ip = host.parse::<IpAddr>().ok();

    let cfg = config::load_or_init(paths)?;
    let db = open_storage(paths)?;
    let nodes = db.list_nodes()?;
    let groups = db.list_multi_groups()?;
    let relays = db.list_preaccel_relays(false)?;
    let (live_version, _, _) = probe_live_controller(paths, &cfg).await;

    let offline_ports = AllocatedPorts {
        bind_host: if cfg.allow_lan {
            cfg.bind_address.clone()
        } else {
            "127.0.0.1".to_string()
        },
        mixed_port: cfg.mixed_port,
        controller_port: cfg.controller_port,
        dns_port: cfg.dns_listen_port,
        shifted: Vec::new(),
    };
    let empty_filter = HashMap::new();
    let compiled = compile_mihomo_config_with_runtime_dir(
        &CompileInput {
            config: &cfg,
            nodes: &nodes,
            groups: &groups,
            relays: &relays,
            controller_secret: "match-placeholder-secret",
            allocated_ports: &offline_ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &empty_filter,
        },
        Some(&paths.runtime_dir),
    )?;

    let rules = extract_yaml_sequence_under_key(&compiled.yaml, "rules", true);
    let fake_ip_filters =
        extract_yaml_sequence_under_key(&compiled.yaml, "fake-ip-filter", false);
    let bypass_fake_ip = fake_ip_filters
        .iter()
        .any(|pat| domain_matches_wildcard(pat, &host));

    let mut skipped_geo_rules: Vec<String> = Vec::new();
    let mut matched_rule_idx: Option<usize> = None;
    let mut matched_rule = String::new();
    let mut matched_type = String::new();
    let mut matched_policy = String::new();

    match cfg.proxy_mode {
        ProxyMode::Direct => {
            matched_rule = "MODE,DIRECT".to_string();
            matched_type = "MODE".to_string();
            matched_policy = "DIRECT".to_string();
        }
        ProxyMode::Global => {
            matched_rule = "MODE,GLOBAL".to_string();
            matched_type = "MODE".to_string();
            matched_policy = "GLOBAL".to_string();
        }
        ProxyMode::Rule => {
            for (idx, rule) in rules.iter().enumerate() {
                let parts = split_top_level_rule_parts(rule);
                if parts.is_empty() {
                    continue;
                }
                let rtype = parts[0].to_ascii_uppercase();
                let (payload, policy) = if rtype == "MATCH" {
                    ("", parts.get(1).copied().unwrap_or("DIRECT"))
                } else if parts.len() >= 3 {
                    (parts[1], parts[2])
                } else {
                    continue;
                };

                match eval_rule_condition(&rtype, payload, &host, parsed_ip, network, port) {
                    ConditionEval::Matched => {
                        matched_rule_idx = Some(idx);
                        matched_rule = sanitize_log_line(rule);
                        matched_type = rtype;
                        matched_policy = policy.to_string();
                        break;
                    }
                    ConditionEval::UnknownGeo => {
                        skipped_geo_rules.push(sanitize_log_line(rule));
                    }
                    ConditionEval::NotMatched => {}
                }
            }
        }
    }

    let resolved_group = compiled
        .group_mappings
        .iter()
        .find(|g| g.group_name == matched_policy)
        .map(|g| {
            json!({
                "group_id": g.group_id,
                "group_name": g.group_name,
                "mihomo_type": g.mihomo_type,
                "active_proxy_name": g.active_proxy_name,
                "member_count": g.member_proxy_names.len(),
            })
        });

    let geo_note = if !skipped_geo_rules.is_empty() {
        Some("Offline rule simulation cannot inspect binary GeoSite/GeoIP databases; live Mihomo core may match an earlier GEOSITE/GEOIP rule before the fallback result shown here.")
    } else {
        None
    };

    let out = json!({
        "ok": true,
        "sanitized": true,
        "query": {
            "host": if parsed_ip.is_some() { redact_ip_or_host(&host) } else { host.clone() },
            "network": network,
            "port": port,
        },
        "proxy_mode": cfg.proxy_mode,
        "core_running": live_version.is_some(),
        "evaluation_source": "compiled_rules_offline",
        "matched": !matched_policy.is_empty(),
        "matched_rule_index": matched_rule_idx,
        "matched_rule": &matched_rule,
        "matched_rule_type": &matched_type,
        "policy": &matched_policy,
        "resolved_group": resolved_group,
        "bypass_fake_ip": bypass_fake_ip,
        "skipped_geo_rules": skipped_geo_rules,
        "geo_note": geo_note,
    });
    let human = format!(
        "Match {} ({}/{}) -> policy `{}` via rule `{}` (bypass_fake_ip={}).",
        out["query"]["host"].as_str().unwrap_or(""),
        network,
        port,
        matched_policy,
        matched_rule,
        bypass_fake_ip
    );
    Ok((out, human))
}

fn read_file_with_limit(
    path: &std::path::Path,
    max_bytes: usize,
    label: &str,
) -> Result<Vec<u8>> {
    use std::io::Read as _;

    let file = std::fs::File::open(path).with_context(|| {
        format!(
            "failed to open {label} `{}`",
            redact_path_for_display(&path.to_string_lossy())
        )
    })?;
    let meta = file.metadata().with_context(|| {
        format!(
            "failed to inspect {label} `{}`",
            redact_path_for_display(&path.to_string_lossy())
        )
    })?;
    if !meta.is_file() {
        anyhow::bail!(
            "{label} path is not a regular file: {}",
            redact_path_for_display(&path.to_string_lossy())
        );
    }
    if meta.len() > max_bytes as u64 {
        anyhow::bail!(
            "{label} `{}` ({} bytes) exceeds maximum allowed {} bytes",
            redact_path_for_display(&path.to_string_lossy()),
            meta.len(),
            max_bytes
        );
    }
    let mut out = Vec::with_capacity((meta.len() as usize).min(64 * 1024));
    let mut limited = file.take(max_bytes as u64 + 1);
    limited.read_to_end(&mut out).with_context(|| {
        format!(
            "failed to read {label} `{}`",
            redact_path_for_display(&path.to_string_lossy())
        )
    })?;
    if out.len() > max_bytes {
        anyhow::bail!(
            "{label} `{}` exceeded maximum allowed {} bytes while reading",
            redact_path_for_display(&path.to_string_lossy()),
            max_bytes
        );
    }
    Ok(out)
}

fn find_manifest_asset_for_stage<'a>(
    manifest: &'a LatestManifest,
    target_name: &str,
) -> Option<&'a PlatformAsset> {
    if let Some(by_key) = manifest.platforms.get(target_name) {
        return Some(by_key);
    }
    manifest.platforms.values().find(|asset| {
        if asset
            .filename
            .as_deref()
            .is_some_and(|f| f == target_name)
        {
            return true;
        }
        asset
            .url
            .rsplit('/')
            .next()
            .map(|seg| seg.split('?').next().unwrap_or(seg))
            .is_some_and(|seg| seg == target_name)
    })
}

fn inspect_geodata_file(runtime_dir: &std::path::Path, candidates: &[&str]) -> Value {
    for name in candidates {
        let path = runtime_dir.join(name);
        if let Ok(meta) = std::fs::metadata(&path) {
            if meta.is_file() {
                let updated_at = meta
                    .modified()
                    .ok()
                    .map(|t| chrono::DateTime::<Utc>::from(t).to_rfc3339());
                return json!({
                    "exists": true,
                    "size_bytes": meta.len(),
                    "updated_at": updated_at
                });
            }
        }
    }
    json!({
        "exists": false,
        "size_bytes": 0u64,
        "updated_at": null
    })
}

fn collect_geodata_status(runtime_dir: &std::path::Path) -> Value {
    json!({
        "country_mmdb": inspect_geodata_file(runtime_dir, &["Country.mmdb", "country.mmdb"]),
        "geoip_dat": inspect_geodata_file(runtime_dir, &["geoip.dat", "GeoIP.dat"]),
        "geosite_dat": inspect_geodata_file(runtime_dir, &["geosite.dat", "GeoSite.dat"]),
        "asn_mmdb": inspect_geodata_file(runtime_dir, &["GeoLite2-ASN.mmdb", "geolite2-asn.mmdb", "asn.mmdb"]),
    })
}

fn build_global_preaccel_status_payload(paths: &AppPaths) -> Result<(Value, String)> {
    let cfg = config::load_or_init(paths)?;
    let db = open_storage(paths)?;
    let plat = default_platform();
    let caps = plat.capabilities();
    let enabled_relays = db.list_preaccel_relays(true)?;
    let active_relay_names: Vec<String> = enabled_relays
        .iter()
        .map(|r| {
            if !r.name.trim().is_empty() {
                r.name.trim().to_string()
            } else {
                r.id.trim().to_string()
            }
        })
        .collect();
    let wd_files = locate_windivert_files(paths, cfg.preaccel.windivert_dir.as_deref());
    let windivert_available = wd_files.is_some();
    let bin_res = resolve_mihomo_binary(&cfg, paths, &[], false)?;
    let recommended_mode = if cfg!(target_os = "windows") && caps.is_elevated && windivert_available
    {
        "windivert"
    } else {
        "local_socks5"
    };

    let out = json!({
        "ok": true,
        "sanitized": true,
        "os": caps.os,
        "arch": caps.arch,
        "is_elevated": caps.is_elevated,
        "global_bypass_enabled": cfg.preaccel.global_bypass_enabled,
        "global_scope": cfg.preaccel.global_scope,
        "global_target_processes": cfg.preaccel.global_target_processes,
        "windivert_dir": cfg.preaccel.windivert_dir.as_deref().map(redact_path_for_display),
        "windivert_available": windivert_available,
        "windivert_dll": wd_files.as_ref().map(|(dll, _)| redact_path_for_display(&dll.to_string_lossy())),
        "windivert_sys": wd_files.as_ref().map(|(_, sys)| redact_path_for_display(&sys.to_string_lossy())),
        "mihomo_available": bin_res.found,
        "enabled_relay_count": active_relay_names.len(),
        "active_relays": active_relay_names,
        "recommended_mode": recommended_mode,
    });

    let human = format!(
        "Global Pre-Accel: enabled={} | scope={} | relays={} | windivert_ready={} | elevated={} | recommended_mode={}",
        cfg.preaccel.global_bypass_enabled,
        cfg.preaccel.global_scope.as_str(),
        enabled_relays.len(),
        windivert_available,
        caps.is_elevated,
        recommended_mode
    );

    Ok((out, human))
}

fn is_cli_tun_privilege_ready(
    caps: &catcloud_core::platform::PlatformCapabilities,
    mihomo_binary: Option<&Path>,
) -> bool {
    if caps.is_elevated {
        return true;
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(bin) = mihomo_binary {
            return catcloud_core::platform::linux::has_mihomo_tun_capability(bin);
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = mihomo_binary;
    false
}

fn build_diag_payload(paths: &AppPaths, reveal_secrets: bool) -> Result<Value> {
    let cfg = config::load_or_init(paths)?;
    let db = open_storage(paths)?;
    let plat = default_platform();
    let caps = plat.capabilities();
    let mihomo_bin = resolve_mihomo_binary(&cfg, paths, &[], false)
        .ok()
        .and_then(|r| r.path);
    let tun_privilege_ready = is_cli_tun_privilege_ready(&caps, mihomo_bin.as_deref());
    let tun_configured = cfg.tun.enabled;
    let tun_enabled = tun_configured && tun_privilege_ready;
    let tun_needs_elevation = tun_configured && !tun_privilege_ready;
    let geodata_status = collect_geodata_status(&paths.runtime_dir);
    let wd_files = locate_windivert_files(paths, cfg.preaccel.windivert_dir.as_deref());
    let recent_logs = read_diag_log_tail(
        &paths.logs_dir.join("catcloud.log"),
        MAX_DIAG_LOG_LINES,
        !reveal_secrets,
    );
    let data_dir = if reveal_secrets {
        paths.root_data_dir.to_string_lossy().to_string()
    } else {
        redact_path_for_display(&paths.root_data_dir.to_string_lossy())
    };
    let mut payload = json!({
        "ok": true,
        "sanitized": !reveal_secrets,
        "version": env!("CARGO_PKG_VERSION"),
        "data_dir": data_dir,
        "os": caps.os,
        "arch": caps.arch,
        "is_elevated": caps.is_elevated,
        "is_portable": paths.is_portable,
        "instance_hash": paths.instance_hash,
        "proxy_mode": cfg.proxy_mode,
        "route_mode": cfg.route_mode,
        "active_group_id": cfg.active_group_id,
        "active_single_node_id": cfg.active_single_node_id,
        "mixed_port": cfg.mixed_port,
        "controller_port": cfg.controller_port,
        "dns_listen_port": cfg.dns_listen_port,
        "core_ipv6": cfg.core_ipv6,
        "dns_ipv6": cfg.dns.ipv6,
        "system_proxy_enabled": cfg.system_proxy.enabled,
        "tun_enabled": tun_enabled,
        "tun_configured": tun_configured,
        "tun_needs_elevation": tun_needs_elevation,
        "tun_stack": cfg.tun.stack_mode,
        "domestic_direct_enabled": cfg.rules_override.domestic_direct_enabled,
        "block_quic_udp_443": cfg.rules_override.block_quic_udp_443,
        "preaccel_enabled": cfg.preaccel.enabled,
        "skip_443_native": cfg.preaccel.skip_443_native,
        "global_preaccel_enabled": cfg.preaccel.global_bypass_enabled,
        "global_preaccel_scope": cfg.preaccel.global_scope,
        "windivert_available": wd_files.is_some(),
        "compile_all_nodes": cfg.core_runtime.compile_all_nodes,
        "geodata_status": geodata_status,
        "recent_logs": recent_logs,
        "counts": {
            "subscriptions": db.list_subscriptions()?.len(),
            "nodes": db.list_nodes()?.len(),
            "multi_groups": db.list_multi_groups()?.len(),
            "preaccel_relays": db.list_preaccel_relays(false)?.len(),
        }
    });
    if reveal_secrets {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("controller_secret".to_string(), json!(cfg.controller_secret));
        }
    }
    Ok(payload)
}

fn read_diag_log_tail(log_path: &Path, max_lines: usize, sanitize: bool) -> Vec<String> {
    if max_lines == 0 {
        return Vec::new();
    }
    let mut lines = read_bounded_file_lines(log_path, MAX_DIAG_LOG_TAIL_READ_BYTES);
    if lines.len() > max_lines {
        let drop_count = lines.len() - max_lines;
        lines.drain(0..drop_count);
    }
    if sanitize {
        lines.into_iter().map(|l| sanitize_log_line(&l)).collect()
    } else {
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_log_line_redacts_secrets_passwords_tokens_paths_and_ipv6_without_breaking_timestamps() {
        let raw = concat!(
            "2026-11-24T03:20:00Z INFO auth failed ",
            "controller_secret=deadbeef01234567 ",
            "\"password\": \"myS3cr3t!\", ",
            "url=https://sub.example.com/api?token=tok_999888&ok=1 ",
            "Authorization: Bearer eyJhbGci.payload.sig ",
            "path=C:\\Users\\Administrator\\CatCloud\\config.json ",
            "peer=[2001:db8:85a3::8a2e:370:7334]:443 ",
            "src=fe80::1 net=2001:db8::/48 local=::1 ",
            "mod=catcloud_core::config"
        );
        let sanitized = sanitize_log_line(raw);

        assert!(sanitized.contains("2026-11-24T03:20:00Z"));
        assert!(sanitized.contains("mod=catcloud_core::config"));
        assert!(sanitized.contains("ok=1"));
        assert!(sanitized.contains("local=::1"));

        assert!(!sanitized.contains("deadbeef01234567"));
        assert!(!sanitized.contains("myS3cr3t!"));
        assert!(!sanitized.contains("tok_999888"));
        assert!(!sanitized.contains("eyJhbGci.payload.sig"));
        assert!(!sanitized.contains("Administrator"));
        assert!(!sanitized.contains("8a2e:370:7334"));

        assert!(sanitized.contains("controller_secret=<REDACTED>"));
        assert!(sanitized.contains("\"password\": \"<REDACTED>\""));
        assert!(sanitized.contains("token=<REDACTED>&ok=1"));
        assert!(sanitized.contains("Authorization: Bearer <REDACTED>"));
        assert!(sanitized.contains("<USER>"));
        assert!(sanitized.contains("2001:db8::*"));
    }

    #[test]
    fn diag_payload_aligns_country_mmdb_and_supports_reveal_secrets() {
        let temp_root = std::env::temp_dir().join(format!(
            "catcloud-cli-diag-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");

        let mut cfg = config::load_or_init(&paths).expect("init config");
        cfg.route_mode = RouteTargetMode::Single;
        cfg.active_group_id = Some("grp-tw".to_string());
        cfg.active_single_node_id = Some("node-tw-01".to_string());
        cfg.system_proxy.enabled = true;
        cfg.tun.enabled = true;
        cfg.rules_override.domestic_direct_enabled = true;
        cfg.rules_override.block_quic_udp_443 = true;
        cfg.preaccel.enabled = true;
        cfg.controller_secret = Some("diag_secret_token_demo".to_string());
        config::save(&paths, &cfg).expect("save config");

        // country-lite.mmdb alone must NOT produce a false green for country_mmdb.
        std::fs::write(paths.runtime_dir.join("country-lite.mmdb"), b"stub-lite").unwrap();
        std::fs::write(paths.runtime_dir.join("geosite.dat"), b"stub-geosite").unwrap();
        let diag_before_mmdb = build_diag_payload(&paths, false).expect("diag before Country.mmdb");
        assert_eq!(
            diag_before_mmdb["geodata_status"]["country_mmdb"]["exists"],
            json!(false)
        );
        assert_eq!(
            diag_before_mmdb["geodata_status"]["geosite_dat"]["exists"],
            json!(true)
        );

        // Once Country.mmdb is placed, country_mmdb reports exists=true.
        std::fs::write(paths.runtime_dir.join("Country.mmdb"), b"stub-mmdb").unwrap();

        let mut log_content = String::new();
        for idx in 1..=55 {
            log_content.push_str(&format!(
                "2026-11-24T03:00:{:02}Z INFO line={} secret=sec_{idx} token=tok_{idx} ip=203.0.113.{}\n",
                idx % 60,
                idx,
                idx % 200 + 1
            ));
        }
        std::fs::write(paths.logs_dir.join("catcloud.log"), log_content).unwrap();

        let diag = build_diag_payload(&paths, false).expect("build sanitized diag payload");
        assert_eq!(diag["ok"], json!(true));
        assert_eq!(diag["sanitized"], json!(true));
        assert!(diag.get("controller_secret").is_none());
        assert_eq!(diag["route_mode"], json!("single"));
        assert_eq!(diag["active_group_id"], json!("grp-tw"));
        assert_eq!(diag["active_single_node_id"], json!("node-tw-01"));
        assert_eq!(diag["system_proxy_enabled"], json!(true));
        let expected_tun_ready = is_cli_tun_privilege_ready(
            &default_platform().capabilities(),
            resolve_mihomo_binary(&cfg, &paths, &[], false)
                .ok()
                .and_then(|r| r.path)
                .as_deref(),
        );
        assert_eq!(diag["tun_configured"], json!(true));
        assert_eq!(diag["tun_enabled"], json!(expected_tun_ready));
        assert_eq!(diag["tun_needs_elevation"], json!(!expected_tun_ready));
        assert_eq!(diag["domestic_direct_enabled"], json!(true));
        assert_eq!(diag["block_quic_udp_443"], json!(true));
        assert_eq!(diag["preaccel_enabled"], json!(true));

        assert_eq!(diag["geodata_status"]["country_mmdb"]["exists"], json!(true));
        assert_eq!(diag["geodata_status"]["geosite_dat"]["exists"], json!(true));
        assert_eq!(diag["geodata_status"]["geoip_dat"]["exists"], json!(false));

        let logs = diag["recent_logs"].as_array().expect("recent_logs array");
        assert_eq!(logs.len(), MAX_DIAG_LOG_LINES);
        assert!(logs[0].as_str().unwrap().contains("line=16"));
        assert!(logs[39].as_str().unwrap().contains("line=55"));
        for entry in logs {
            let s = entry.as_str().unwrap();
            assert!(!s.contains("sec_"));
            assert!(!s.contains("tok_"));
            assert!(s.contains("secret=<REDACTED>"));
            assert!(s.contains("token=<REDACTED>"));
            assert!(s.contains("203.0.113.*"));
        }

        let revealed = build_diag_payload(&paths, true).expect("build revealed diag payload");
        assert_eq!(revealed["sanitized"], json!(false));
        assert_eq!(revealed["controller_secret"], json!("diag_secret_token_demo"));
        assert!(
            revealed["recent_logs"][0]
                .as_str()
                .unwrap()
                .contains("sec_16")
        );

        // When tun.enabled is disabled in config, all three TUN truth fields must be false.
        cfg.tun.enabled = false;
        config::save(&paths, &cfg).expect("save tun disabled config");
        let diag_tun_off = build_diag_payload(&paths, false).expect("diag with tun off");
        assert_eq!(diag_tun_off["tun_configured"], json!(false));
        assert_eq!(diag_tun_off["tun_enabled"], json!(false));
        assert_eq!(diag_tun_off["tun_needs_elevation"], json!(false));

        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn logs_tail_merges_archive_filters_by_level_and_sanitizes_output() {
        let temp_root = std::env::temp_dir().join(format!(
            "catcloud-cli-logs-tail-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");

        std::fs::write(
            paths.logs_dir.join("catcloud.log.1"),
            "2026-11-24T01:00:00Z WARN archive warn password=oldpass\n2026-11-24T01:01:00Z INFO archive info\n",
        )
        .unwrap();
        std::fs::write(
            paths.logs_dir.join("catcloud.log"),
            "2026-11-24T02:00:00Z INFO current info\n2026-11-24T02:01:00Z ERROR current err token=tok_abc host=198.51.100.77\n",
        )
        .unwrap();

        let (warn_out, _) = build_logs_tail_payload(&paths, 10, "warning").expect("warning tail");
        assert_eq!(warn_out["sanitized"], json!(true));
        let lines = warn_out["lines"].as_array().unwrap();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].as_str().unwrap().contains("password=<REDACTED>"));
        assert!(!lines[0].as_str().unwrap().contains("oldpass"));
        assert!(lines[1].as_str().unwrap().contains("token=<REDACTED>"));
        assert!(lines[1].as_str().unwrap().contains("198.51.100.*"));

        let (err_out, _) = build_logs_tail_payload(&paths, 10, "error").expect("error tail");
        assert_eq!(err_out["count"], json!(1));
        assert!(build_logs_tail_payload(&paths, 10, "invalid_lvl").is_err());

        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[tokio::test]
    async fn net_match_and_net_doctor_work_offline_with_sanitized_output() {
        let temp_root = std::env::temp_dir().join(format!(
            "catcloud-cli-net-tools-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");

        let mut cfg = config::load_or_init(&paths).expect("init config");
        cfg.rules_override
            .global_prepend_rules
            .push("DOMAIN-SUFFIX,custom-direct.example,DIRECT".to_string());
        config::save(&paths, &cfg).expect("save config");

        let (match_direct, _) =
            build_net_match_payload(&paths, "api.custom-direct.example", "tcp", 443)
                .await
                .expect("match prepend rule");
        assert_eq!(match_direct["policy"], json!("DIRECT"));
        assert_eq!(match_direct["matched_rule_type"], json!("DOMAIN-SUFFIX"));

        let (match_quic_cn, _) = build_net_match_payload(&paths, "qq.com", "udp", 443)
            .await
            .expect("match domestic QUIC allow");
        assert_eq!(match_quic_cn["policy"], json!("DIRECT"));
        assert_eq!(match_quic_cn["bypass_fake_ip"], json!(true));

        let (match_quic_overseas, _) =
            build_net_match_payload(&paths, "api.openai.com", "udp", 443)
                .await
                .expect("match overseas QUIC reject");
        assert_eq!(match_quic_overseas["policy"], json!("REJECT"));

        let (doctor, _) = build_net_doctor_payload(&paths).await.expect("net doctor");
        assert_eq!(doctor["ok"], json!(true));
        assert_eq!(doctor["sanitized"], json!(true));
        assert_eq!(doctor["checks"].as_array().unwrap().len(), 7);

        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn share_bundle_export_inspect_and_import_roundtrip_is_sanitized_by_default() {
        let temp_root = std::env::temp_dir().join(format!(
            "catcloud-cli-share-roundtrip-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        let paths = AppPaths::from_data_dir(temp_root.join("data"), true).expect("init temp paths");
        let db = open_storage(&paths).expect("open db");

        db.upsert_subscription(&SubscriptionRecord {
            id: "sub-origin".to_string(),
            name: "Origin".to_string(),
            kind: SubscriptionKind::File,
            url_or_cmd: "origin.yaml".to_string(),
            ..Default::default()
        })
        .unwrap();
        db.upsert_node(&ProxyNode {
            id: "node-share-1".to_string(),
            sub_id: "sub-origin".to_string(),
            name: "JP Share 1x".to_string(),
            protocol: "trojan".to_string(),
            server: "203.0.113.91".to_string(),
            port: 443,
            raw_config: json!({
                "name": "JP Share 1x",
                "type": "trojan",
                "server": "203.0.113.91",
                "port": 443,
                "password": "secret_node_pass_demo"
            }),
            region_code: "JP".to_string(),
            ..ProxyNode::default()
        })
        .unwrap();
        db.upsert_preaccel_relay(&PreAccelRelay {
            id: "relay-share-1".to_string(),
            name: "CN-443-Demo".to_string(),
            provider: "cloud".to_string(),
            region: "CN-East".to_string(),
            server: "198.51.100.92".to_string(),
            port: 443,
            protocol: "anytls".to_string(),
            password: "secret_relay_pass_demo".to_string(),
            skip_cert_verify: true,
            ..PreAccelRelay::default()
        })
        .unwrap();
        drop(db);

        let zip_path = temp_root.join("friend-pack.zip");
        handle_share_export(
            &paths,
            true,
            ShareExportArgs {
                output: zip_path.clone(),
                name: "Friend Pack".to_string(),
                description: None,
                node_ids: Some("node-share-1".to_string()),
                sub_id: None,
                relay_ids: Some("relay-share-1".to_string()),
                all_relays: false,
            },
        )
        .expect("export share zip");
        assert!(zip_path.is_file());

        // Inspect must succeed and preview in a separate fresh data dir must not persist on dry-run.
        handle_share_inspect(true, &zip_path).expect("inspect share zip");

        let dst_paths =
            AppPaths::from_data_dir(temp_root.join("dst-data"), true).expect("init dst paths");
        handle_share_import(
            &dst_paths,
            true,
            ShareImportArgs {
                file_pos: Some(zip_path.clone()),
                file: None,
                dry_run: false,
                apply: false,
                target_sub: None,
                name: None,
                mode: "merge".to_string(),
                no_relays: false,
                no_nodes: false,
            },
        )
        .expect("dry-run share import");
        let dst_db = open_storage(&dst_paths).expect("open dst db");
        assert_eq!(dst_db.list_nodes().unwrap().len(), 0);
        assert_eq!(dst_db.list_preaccel_relays(false).unwrap().len(), 0);
        drop(dst_db);

        handle_share_import(
            &dst_paths,
            true,
            ShareImportArgs {
                file_pos: Some(zip_path),
                file: None,
                dry_run: false,
                apply: true,
                target_sub: None,
                name: Some("Imported Friend Pack".to_string()),
                mode: "merge".to_string(),
                no_relays: false,
                no_nodes: false,
            },
        )
        .expect("apply share import");
        let dst_db = open_storage(&dst_paths).expect("open dst db after apply");
        assert_eq!(dst_db.list_nodes().unwrap().len(), 1);
        assert_eq!(dst_db.list_preaccel_relays(false).unwrap().len(), 1);
        let subs = dst_db.list_subscriptions().unwrap();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].name, "Imported Friend Pack");

        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn global_preaccel_status_payload_reports_config_and_windivert_readiness() {
        let temp_root = std::env::temp_dir().join(format!(
            "catcloud-cli-global-preaccel-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");

        let mut cfg = config::load_or_init(&paths).expect("init config");
        cfg.preaccel.global_bypass_enabled = true;
        config::save(&paths, &cfg).expect("save config");

        let (payload_before, human_before) =
            build_global_preaccel_status_payload(&paths).expect("status before windivert");
        assert_eq!(payload_before["ok"], json!(true));
        assert_eq!(payload_before["global_bypass_enabled"], json!(true));
        assert_eq!(payload_before["global_scope"], json!("proxy_apps_only"));
        assert_eq!(payload_before["windivert_available"], json!(false));
        assert!(human_before.contains("enabled=true"));

        std::fs::write(paths.bin_dir.join("WinDivert64.dll"), b"stub-dll").unwrap();
        std::fs::write(paths.bin_dir.join("WinDivert64.sys"), b"stub-sys").unwrap();

        let (payload_after, _) =
            build_global_preaccel_status_payload(&paths).expect("status after windivert");
        if !cfg!(all(target_os = "windows", not(target_arch = "aarch64"))) {
            assert_eq!(payload_after["windivert_available"], json!(false));
            assert!(payload_after["windivert_dll"].is_null());
            assert!(payload_after["windivert_sys"].is_null());
        } else {
            assert_eq!(payload_after["windivert_available"], json!(true));
            assert!(payload_after["windivert_dll"].as_str().is_some());
            assert!(payload_after["windivert_sys"].as_str().is_some());
        }

        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[tokio::test]
    async fn node_migrate_supports_directory_display_name_and_unique_subscription_ids() {
        let temp_root = std::env::temp_dir().join(format!(
            "catcloud-cli-migrate-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        let data_dir = temp_root.join("data");
        let src_dir = temp_root.join("third_party");
        let profiles_dir = src_dir.join("profiles");
        std::fs::create_dir_all(&profiles_dir).unwrap();
        std::fs::write(
            profiles_dir.join("sub_a.yaml"),
            "proxies:\n  - name: \"HK Migrate Test 1x\"\n    type: trojan\n    server: 198.51.100.44\n    port: 443\n    password: \"placeholder-pass\"\n",
        )
        .unwrap();
        std::fs::write(
            src_dir.join("profiles.yaml"),
            "items:\n  - name: \"我的真实订阅\"\n    file: sub_a.yaml\n",
        )
        .unwrap();

        let paths = AppPaths::from_data_dir(data_dir, true).expect("init temp paths");
        for _ in 0..2 {
            dispatch(
                &paths,
                true,
                Commands::Node {
                    action: NodeCommand::Migrate(NodeMigrateArgs {
                        scan: false,
                        file: Some(src_dir.clone()),
                        apply: true,
                    }),
                },
            )
            .await
            .expect("apply migration from directory");
        }

        let db = open_storage(&paths).expect("open db");
        let subs = db.list_subscriptions().expect("list subs");
        let nodes = db.list_nodes().expect("list nodes");
        assert_eq!(subs.len(), 2, "repeated --apply must not overwrite previous migrated subscription");
        assert_eq!(nodes.len(), 2, "nodes from both imports must be preserved");
        assert_ne!(subs[0].id, subs[1].id);
        for sub in &subs {
            assert!(sub.id.starts_with("migrated-"));
            assert_eq!(sub.name, "我的真实订阅");
        }

        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn update_stage_helpers_enforce_size_cap_and_cross_check_manifest_sha256() {
        let temp_root = std::env::temp_dir().join(format!(
            "catcloud-cli-stage-helpers-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        std::fs::create_dir_all(&temp_root).unwrap();

        let oversized = temp_root.join("oversized.zip");
        let f = std::fs::File::create(&oversized).unwrap();
        f.set_len(MAX_ZIP_BYTES as u64 + 1).unwrap();
        assert!(
            read_file_with_limit(&oversized, MAX_ZIP_BYTES, "update archive").is_err(),
            "archives larger than MAX_ZIP_BYTES must be rejected before reading"
        );

        let good_sha = "a".repeat(64);
        let bad_sha = "b".repeat(64);
        let manifest_bytes = serde_json::to_vec(&json!({
            "version": "0.2.0",
            "platforms": {
                "windows-x86_64-portable": {
                    "url": "https://github.com/JuryBu/CatCloud/releases/download/v0.2.0/CatCloud-0.2.0-windows-x64-portable.zip",
                    "filename": "CatCloud-0.2.0-windows-x64-portable.zip",
                    "sha256": good_sha
                }
            }
        }))
        .unwrap();
        let manifest = parse_latest_manifest(&manifest_bytes).unwrap();
        let asset = find_manifest_asset_for_stage(
            &manifest,
            "CatCloud-0.2.0-windows-x64-portable.zip",
        )
        .expect("asset matched by filename");

        let mut matching_sums = HashMap::new();
        matching_sums.insert(
            "release-assets/CatCloud-0.2.0-windows-x64-portable.zip".to_string(),
            good_sha.clone(),
        );
        assert_eq!(
            resolve_asset_sha256(asset, Some(&matching_sums)).unwrap(),
            good_sha
        );

        let mut mismatched_sums = HashMap::new();
        mismatched_sums.insert(
            "CatCloud-0.2.0-windows-x64-portable.zip".to_string(),
            bad_sha,
        );
        assert!(
            resolve_asset_sha256(asset, Some(&mismatched_sums)).is_err(),
            "mismatched manifest sha256 vs SHA256SUMS must fail"
        );

        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[tokio::test]
    async fn sub_merge_remaps_and_falls_back_active_single_node_id() {
        let temp_root = std::env::temp_dir().join(format!(
            "catcloud-cli-sub-merge-remap-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");
        let db = open_storage(&paths).expect("open db");

        db.upsert_subscription(&SubscriptionRecord {
            id: "sub-src".to_string(),
            name: "Source".to_string(),
            kind: SubscriptionKind::File,
            url_or_cmd: "src.yaml".to_string(),
            ..Default::default()
        })
        .unwrap();
        db.upsert_subscription(&SubscriptionRecord {
            id: "sub-dst".to_string(),
            name: "Target".to_string(),
            kind: SubscriptionKind::File,
            url_or_cmd: "dst.yaml".to_string(),
            ..Default::default()
        })
        .unwrap();

        let shared_raw = json!({
            "name": "JP Shared 1x",
            "type": "trojan",
            "server": "203.0.113.50",
            "port": 443,
            "password": "shared_demo_password"
        });
        db.upsert_node(&ProxyNode {
            id: "node-src-dup".to_string(),
            sub_id: "sub-src".to_string(),
            name: "JP Shared 1x".to_string(),
            protocol: "trojan".to_string(),
            server: "203.0.113.50".to_string(),
            port: 443,
            raw_config: shared_raw.clone(),
            region_code: "JP".to_string(),
            ..ProxyNode::default()
        })
        .unwrap();
        db.upsert_node(&ProxyNode {
            id: "node-dst-keep".to_string(),
            sub_id: "sub-dst".to_string(),
            name: "JP Shared 1x".to_string(),
            protocol: "trojan".to_string(),
            server: "203.0.113.50".to_string(),
            port: 443,
            raw_config: shared_raw,
            region_code: "JP".to_string(),
            ..ProxyNode::default()
        })
        .unwrap();

        let mut cfg = config::load_or_init(&paths).expect("init config");
        cfg.active_single_node_id = Some("node-src-dup".to_string());
        config::save(&paths, &cfg).expect("save config");
        drop(db);

        dispatch(
            &paths,
            true,
            Commands::Sub {
                action: SubCommand::Merge {
                    source: "sub-src".to_string(),
                    target: "sub-dst".to_string(),
                    name: None,
                    no_dedup: false,
                },
            },
        )
        .await
        .expect("sub merge must succeed");

        let updated = config::load_or_default(&paths).expect("reload config after merge");
        assert_eq!(
            updated.active_single_node_id.as_deref(),
            Some("node-dst-keep"),
            "sub merge must remap active_single_node_id to deduplicated target node ID"
        );

        // When active_single_node_id points to a deleted node and id_remap is empty,
        // sync_active_single_node_after_mutation must fall back to the first enabled node.
        let mut stale_cfg = updated;
        stale_cfg.active_single_node_id = Some("node-ghost-deleted".to_string());
        config::save(&paths, &stale_cfg).expect("save stale config");
        let db = open_storage(&paths).expect("reopen db");
        let changed = sync_active_single_node_after_mutation(&paths, &db, &HashMap::new())
            .expect("sync fallback");
        assert!(changed);
        let after_fallback = config::load_or_default(&paths).expect("reload config after fallback");
        assert_eq!(
            after_fallback.active_single_node_id.as_deref(),
            Some("node-dst-keep")
        );

        // When all nodes are gone, active_single_node_id must clear to None.
        let _ = db.delete_subscription("sub-dst").unwrap();
        let cleared = sync_active_single_node_after_mutation(&paths, &db, &HashMap::new())
            .expect("sync clear");
        assert!(cleared);
        let after_clear = config::load_or_default(&paths).expect("reload config after clear");
        assert_eq!(after_clear.active_single_node_id, None);

        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn share_import_preserves_conflicting_relay_id_unifies_node_count_and_syncs_active_node() {
        let temp_root = std::env::temp_dir().join(format!(
            "catcloud-cli-share-conflict-sync-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        let src_paths =
            AppPaths::from_data_dir(temp_root.join("src-data"), true).expect("init src paths");
        let src_db = open_storage(&src_paths).expect("open src db");

        src_db
            .upsert_subscription(&SubscriptionRecord {
                id: "sub-export".to_string(),
                name: "Export Sub".to_string(),
                kind: SubscriptionKind::File,
                url_or_cmd: "export.yaml".to_string(),
                ..Default::default()
            })
            .unwrap();
        src_db
            .upsert_node(&ProxyNode {
                id: "node-incoming-1".to_string(),
                sub_id: "sub-export".to_string(),
                name: "SG Incoming 1x".to_string(),
                protocol: "trojan".to_string(),
                server: "203.0.113.81".to_string(),
                port: 443,
                raw_config: json!({
                    "name": "SG Incoming 1x",
                    "type": "trojan",
                    "server": "203.0.113.81",
                    "port": 443,
                    "password": "incoming_node_pass_demo"
                }),
                region_code: "SG".to_string(),
                ..ProxyNode::default()
            })
            .unwrap();
        src_db
            .upsert_preaccel_relay(&PreAccelRelay {
                id: "relay-same-id".to_string(),
                name: "Incoming-Relay-B".to_string(),
                provider: "cloud".to_string(),
                region: "CN-South".to_string(),
                server: "198.51.100.88".to_string(),
                port: 443,
                protocol: "anytls".to_string(),
                password: "incoming_relay_pass_demo".to_string(),
                skip_cert_verify: true,
                ..PreAccelRelay::default()
            })
            .unwrap();
        drop(src_db);

        let zip_path = temp_root.join("conflict-pack.zip");
        handle_share_export(
            &src_paths,
            true,
            ShareExportArgs {
                output: zip_path.clone(),
                name: "Conflict Pack".to_string(),
                description: None,
                node_ids: Some("node-incoming-1".to_string()),
                sub_id: None,
                relay_ids: Some("relay-same-id".to_string()),
                all_relays: false,
            },
        )
        .expect("export conflict share zip");

        let dst_paths =
            AppPaths::from_data_dir(temp_root.join("dst-data"), true).expect("init dst paths");
        let dst_db = open_storage(&dst_paths).expect("open dst db");
        dst_db
            .upsert_subscription(&SubscriptionRecord {
                id: "sub-existing".to_string(),
                name: "Existing Sub".to_string(),
                kind: SubscriptionKind::File,
                url_or_cmd: "existing.yaml".to_string(),
                ..Default::default()
            })
            .unwrap();
        for (nid, host) in [
            ("node-existing-1", "198.51.100.11"),
            ("node-existing-2", "198.51.100.12"),
        ] {
            dst_db
                .upsert_node(&ProxyNode {
                    id: nid.to_string(),
                    sub_id: "sub-existing".to_string(),
                    name: format!("Old {nid}"),
                    protocol: "trojan".to_string(),
                    server: host.to_string(),
                    port: 443,
                    raw_config: json!({
                        "name": format!("Old {nid}"),
                        "type": "trojan",
                        "server": host,
                        "port": 443,
                        "password": "old_node_pass_demo"
                    }),
                    region_code: "US".to_string(),
                    ..ProxyNode::default()
                })
                .unwrap();
        }
        // Existing local relay with the same ID (`relay-same-id`) but a distinct server IP.
        dst_db
            .upsert_preaccel_relay(&PreAccelRelay {
                id: "relay-same-id".to_string(),
                name: "Original-Local-Relay-A".to_string(),
                provider: "cloud".to_string(),
                region: "CN-East".to_string(),
                server: "203.0.113.77".to_string(),
                port: 443,
                protocol: "anytls".to_string(),
                password: "original_relay_pass_demo".to_string(),
                skip_cert_verify: true,
                ..PreAccelRelay::default()
            })
            .unwrap();
        drop(dst_db);

        let mut dst_cfg = config::load_or_init(&dst_paths).expect("init dst config");
        dst_cfg.active_single_node_id = Some("node-existing-1".to_string());
        config::save(&dst_paths, &dst_cfg).expect("save dst config");

        // 1. Merge into existing sub: imported_nodes reflects chosen count (1),
        //    while target_sub_total_nodes reports full group total (3);
        //    conflicting relay ID must be regenerated without overwriting the existing relay.
        let (merge_out, _) = execute_share_import(
            &dst_paths,
            ShareImportArgs {
                file_pos: Some(zip_path.clone()),
                file: None,
                dry_run: false,
                apply: true,
                target_sub: Some("sub-existing".to_string()),
                name: None,
                mode: "merge".to_string(),
                no_relays: false,
                no_nodes: false,
            },
        )
        .expect("merge share import");
        assert_eq!(merge_out["imported_nodes"], json!(1));
        assert_eq!(merge_out["target_sub_total_nodes"], json!(3));
        assert_eq!(merge_out["imported_relays"], json!(1));

        let dst_db = open_storage(&dst_paths).expect("reopen dst db after merge");
        let relays = dst_db.list_preaccel_relays(false).unwrap();
        assert_eq!(
            relays.len(),
            2,
            "conflicting relay ID with distinct server must not overwrite original relay"
        );
        let original = relays
            .iter()
            .find(|r| r.id == "relay-same-id")
            .expect("original relay must remain intact");
        assert_eq!(original.server, "203.0.113.77");
        assert_eq!(original.name, "Original-Local-Relay-A");
        let imported_other = relays
            .iter()
            .find(|r| r.server == "198.51.100.88")
            .expect("incoming relay must be stored under a fresh non-colliding ID");
        assert_ne!(imported_other.id, "relay-same-id");
        drop(dst_db);

        // 2. Replace existing sub: drops `node-existing-1` (empty id_remap for it),
        //    so `active_single_node_id` must be synced to the surviving node.
        let (replace_out, _) = execute_share_import(
            &dst_paths,
            ShareImportArgs {
                file_pos: Some(zip_path),
                file: None,
                dry_run: false,
                apply: true,
                target_sub: Some("sub-existing".to_string()),
                name: None,
                mode: "replace".to_string(),
                no_relays: true,
                no_nodes: false,
            },
        )
        .expect("replace share import");
        assert_eq!(replace_out["imported_nodes"], json!(1));
        assert_eq!(replace_out["target_sub_total_nodes"], json!(1));

        let dst_db = open_storage(&dst_paths).expect("reopen dst db after replace");
        let remaining_nodes = dst_db.list_nodes().unwrap();
        assert_eq!(remaining_nodes.len(), 1);
        let synced_cfg = config::load_or_default(&dst_paths).expect("reload dst config");
        assert_eq!(
            synced_cfg.active_single_node_id.as_deref(),
            Some(remaining_nodes[0].id.as_str()),
            "replace_latest must sync stale active_single_node_id to a surviving enabled node"
        );

        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn probe_run_dry_run_missing_binary_preaccel_bind_and_reload_outcome_are_redacted() {
        use catcloud_core::core_adapter::{BinarySource, ReloadLevel};
        use catcloud_core::models::CoreKind;

        let win_user_root = ["C:", "Users", "DemoAccount"].join("\\");
        let fake_bin = PathBuf::from(format!("{win_user_root}\\CatCloud\\bin\\mihomo.exe"));
        let fake_cand = PathBuf::from(r"D:\PrivateWorkspace\CatCloud\bin\mihomo.exe");
        let plan = json!({
            "tier": "l1",
            "node_count": 1,
            "probe_count": 2
        });
        let probe_ids = vec!["builtin_latency".to_string(), "builtin_google_cn".to_string()];

        let found_res = BinaryResolution {
            found: true,
            path: Some(fake_bin.clone()),
            source: BinarySource::UserDataBin,
            sha256: None,
            checked_candidates: vec![fake_bin.clone(), fake_cand.clone()],
            download_guidance: None,
        };
        let (dry_redacted, _) =
            build_probe_run_dry_run_payload("l1", 1, &probe_ids, &plan, &found_res, false);
        assert_eq!(dry_redacted["sanitized"], json!(true));
        let dry_json = serde_json::to_string(&dry_redacted).unwrap();
        assert!(!dry_json.contains("DemoAccount"));
        assert!(!dry_json.contains("PrivateWorkspace"));
        assert!(dry_json.contains("<USER>"));
        assert!(dry_json.contains("<LOCAL_PATH>"));

        let (dry_revealed, _) =
            build_probe_run_dry_run_payload("l1", 1, &probe_ids, &plan, &found_res, true);
        assert_eq!(dry_revealed["sanitized"], json!(false));
        assert!(
            dry_revealed["binary_path"]
                .as_str()
                .unwrap()
                .contains("DemoAccount")
        );

        let missing_res = BinaryResolution {
            found: false,
            path: None,
            source: BinarySource::NotFound,
            sha256: None,
            checked_candidates: vec![fake_bin.clone(), fake_cand.clone()],
            download_guidance: Some(DownloadGuidance {
                core_kind: CoreKind::Mihomo,
                platform_target: "windows-amd64".to_string(),
                recommended_asset_pattern: "mihomo-windows-amd64*.zip".to_string(),
                official_releases_url: "https://github.com/MetaCubeX/mihomo/releases".to_string(),
                target_install_path: fake_bin.clone(),
                verify_sha256_required: true,
                instructions: format!(
                    "Install binary to {win_user_root}\\CatCloud\\bin\\mihomo.exe"
                ),
            }),
        };
        let (missing_out, missing_human) =
            build_probe_run_missing_binary_payload("l1", 1, &probe_ids, &plan, &missing_res, false);
        let missing_json = serde_json::to_string(&missing_out).unwrap();
        assert!(!missing_json.contains("DemoAccount"));
        assert!(!missing_json.contains("PrivateWorkspace"));
        assert!(!missing_human.contains("DemoAccount"));
        assert!(missing_human.contains("<USER>"));

        // PreAccelConfig windivert_dir redaction (preaccel bind)
        let mut preaccel_cfg = PreAccelConfig::default();
        preaccel_cfg.windivert_dir =
            Some(format!("{win_user_root}\\Tools\\WinDivert-2.2"));
        let masked_preaccel = redact_preaccel_config_for_output(&preaccel_cfg);
        let wd = masked_preaccel.windivert_dir.as_deref().unwrap();
        assert!(!wd.contains("DemoAccount"));
        assert!(wd.contains("<USER>"));

        // ReloadOutcome error & warnings redaction (config reload)
        let raw_outcome = ReloadOutcome {
            applied: false,
            level: ReloadLevel::L2HotReload,
            skipped_unchanged: false,
            rejected: true,
            config_hash: None,
            replayed_groups: 0,
            shifted_ports: Vec::new(),
            warnings: vec![format!(
                "warn path={win_user_root}\\CatCloud\\runtime.yaml token=secret_tok_99"
            )],
            error: Some(format!(
                "line1 failed at {win_user_root}\\runtime.yaml\nline2 peer=203.0.113.42 password=pw_demo"
            )),
            applied_at: "2026-11-25T00:00:00Z".to_string(),
        };
        let clean_outcome = redact_reload_outcome(&raw_outcome);
        let clean_err = clean_outcome.error.as_deref().unwrap();
        assert!(!clean_err.contains("DemoAccount"));
        assert!(!clean_err.contains("203.0.113.42"));
        assert!(!clean_err.contains("pw_demo"));
        assert!(clean_err.contains("<USER>"));
        assert!(clean_err.contains("203.0.113.*"));
        assert!(clean_err.contains("password=<REDACTED>"));
        assert!(!clean_outcome.warnings[0].contains("DemoAccount"));
        assert!(!clean_outcome.warnings[0].contains("secret_tok_99"));
    }

    #[test]
    fn preaccel_speed_reference_node_prefers_homepage_skips_udp_and_falls_back_to_single_hop() {
        let mut cfg = AppConfig::default();
        cfg.route_mode = RouteTargetMode::Single;
        cfg.active_single_node_id = Some("n-udp".to_string());

        let udp_node = ProxyNode {
            id: "n-udp".to_string(),
            sub_id: "sub-1".to_string(),
            name: "JP HY2".to_string(),
            protocol: "hysteria2".to_string(),
            server: "198.51.100.10".to_string(),
            port: 443,
            enabled: true,
            ..ProxyNode::default()
        };
        let tcp_node = ProxyNode {
            id: "n-tcp".to_string(),
            sub_id: "sub-1".to_string(),
            name: "SG Trojan".to_string(),
            protocol: "trojan".to_string(),
            server: "198.51.100.20".to_string(),
            port: 8443,
            is_443_native: false,
            enabled: true,
            ..ProxyNode::default()
        };

        // Homepage UDP node is auto-skipped in favor of enabled TCP node.
        let (picked, note) = select_preaccel_speed_reference_node(
            &cfg,
            &[],
            &[udp_node.clone(), tcp_node.clone()],
            None,
        )
        .expect("auto-select tcp node");
        assert_eq!(picked.as_ref().map(|n| n.id.as_str()), Some("n-tcp"));
        assert!(note.is_some());

        // Explicit UDP node must fail with clear validation error.
        assert!(
            select_preaccel_speed_reference_node(&cfg, &[], &[udp_node.clone(), tcp_node], Some("n-udp"))
                .is_err()
        );

        // When only UDP nodes exist, omit reference node for single-hop direct relay speed test.
        let (single_hop, single_note) =
            select_preaccel_speed_reference_node(&cfg, &[], &[udp_node], None)
                .expect("fallback to single-hop");
        assert!(single_hop.is_none());
        assert!(single_note.unwrap().contains("single-hop"));
    }
}
