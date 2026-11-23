use anyhow::{Context, Result};
use catcloud_core::agent_docs;
use catcloud_core::config;
use catcloud_core::core_adapter::config_compiler::{
    CompileInput, compile_mihomo_config, validate_compiled_yaml,
};
use catcloud_core::core_adapter::port_guard::{AllocatedPorts, allocate_safe_ports};
use catcloud_core::core_adapter::{
    DiskReloadOptions, HotReloadCoordinator, MihomoAdapter, generate_controller_secret,
    resolve_mihomo_binary, verify_config_with_binary,
};
use catcloud_core::models::{
    DEFAULT_COST_EFFECTIVE_FORMULA, FallbackPolicy, MultiGroup, MultiGroupMode, NodeFilter,
    ProbeDefinition, ProbeKind, SwitchMode,
};
use catcloud_core::platform::default_platform;
use catcloud_core::preaccel::campus::{CampusBypassTracker, probe_campus_portal};
use catcloud_core::preaccel::generator::{build_preaccel_compile_plan, validate_domestic_probe_url};
use catcloud_core::preaccel::global_tunnel::locate_windivert_files;
use catcloud_core::preaccel::schema::{
    evaluate_expiry, parse_mmrelay_clipboard, validate_relay_strict,
};
use catcloud_core::probe::registry::{FunnelTier, ProbeRegistry, validate_definition};
use catcloud_core::probe::{
    FunnelOptions, FunnelRunReport, IsolatedProbeCore, run_funnel_for_node,
};
use catcloud_core::process_guard::JobGuard;
use catcloud_core::storage::Storage;
use catcloud_core::strategy::arbiter::{ArbiterGroupMemory, decide_group_action};
use catcloud_core::strategy::evaluator::evaluate_group_candidates;
use catcloud_core::strategy::formula::validate_formula;
use catcloud_core::subscription::migrator::{
    MigrationImportOptions, import_migration_preview, preview_from_file, scan_local_clients,
};
use catcloud_core::subscription::parser::{
    apply_parsed_subscription, fetch_and_parse_subscription, parse_subscription_payload,
};
use catcloud_core::subscription::process_attach::{inspect_process_source, list_process_candidates};
use catcloud_core::updater::{
    Updater, parse_latest_manifest, parse_sha256sums, stage_verified_archive,
};
use catcloud_core::{AppPaths, CatError};
use chrono::Utc;
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Print core runtime status, data paths, and storage counts
    Status,
    /// Manage multi-provider proxy nodes, imports, readonly migrations, and process attachment
    Node {
        #[command(subcommand)]
        action: NodeCommand,
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
    /// Validate, compile, reload configuration, export shell env, or dump sanitized diagnostics
    Config {
        #[command(subcommand)]
        action: ConfigCommand,
    },
    /// List or export four-section AI Agent guides embedded in CatCloud
    Docs {
        #[command(subcommand)]
        action: DocsCommand,
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
    Pool,
    /// Update domestic pre-acceleration enablement, native-443 skip, and domestic 204 probe URL
    Bind {
        #[arg(long)]
        enabled: Option<bool>,
        #[arg(long)]
        skip_443_native: Option<bool>,
        #[arg(long)]
        probe_url: Option<String>,
    },
    /// Validate pre-acceleration compile plan, anti-loop rules, and optional campus portal probe
    Test {
        #[arg(long)]
        campus: bool,
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
    /// Print or export compiled Mihomo YAML
    Compile {
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Output shell proxy environment variable commands
    ExportEnv {
        #[arg(long, default_value = DEFAULT_EXPORT_SHELL)]
        shell: String,
    },
    /// Output 100% sanitized diagnostic summary
    Diag,
}

#[derive(Subcommand, Debug)]
pub enum DocsCommand {
    /// List all built-in four-section Agent guides
    List,
    /// Export a single module guide or "all" in Markdown or JSON
    Export {
        module: String,
        #[arg(long, default_value = "markdown")]
        format: String,
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
            let wd_files = locate_windivert_files(paths, cfg.preaccel.windivert_dir.as_deref());
            let out = json!({
                "ok": true,
                "version": env!("CARGO_PKG_VERSION"),
                "data_dir": paths.root_data_dir,
                "is_portable": paths.is_portable,
                "instance_hash": paths.instance_hash,
                "platform": caps,
                "proxy_mode": cfg.proxy_mode,
                "mixed_port": cfg.mixed_port,
                "controller_addr": cfg.controller_addr(),
                "dns_listen_addr": cfg.dns_listen_addr(),
                "preaccel_enabled": cfg.preaccel.enabled,
                "global_preaccel": {
                    "enabled": cfg.preaccel.global_bypass_enabled,
                    "scope": cfg.preaccel.global_scope,
                    "windivert_available": wd_files.is_some(),
                    "windivert_path": wd_files.as_ref().map(|(dll, _)| dll.to_string_lossy().to_string()),
                    "is_elevated": caps.is_elevated,
                },
                "counts": {
                    "subscriptions": db.list_subscriptions()?.len(),
                    "nodes": db.list_nodes()?.len(),
                    "multi_groups": db.list_multi_groups()?.len(),
                    "preaccel_relays": db.list_preaccel_relays(false)?.len(),
                    "probes": db.list_probe_definitions()?.len(),
                }
            });
            let human = format!(
                "CatCloud CLI v{} | portable={} | mode={} | port={} | nodes={} | groups={} | global_preaccel={} (windivert={})",
                env!("CARGO_PKG_VERSION"),
                paths.is_portable,
                cfg.proxy_mode.as_str(),
                cfg.mixed_port,
                db.list_nodes()?.len(),
                db.list_multi_groups()?.len(),
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
                let nodes = db.query_nodes(&filter)?;
                let out = json!({ "ok": true, "count": nodes.len(), "nodes": nodes });
                let human = format!("Found {} matching node(s).", nodes.len());
                emit_output(as_json, &out, &human)
            }

            NodeCommand::Import(args) => {
                let mut db = open_storage(paths)?;
                let (sub_rec, parsed) = if let Some(file) = args.file {
                    let bytes = std::fs::read(&file)
                        .with_context(|| format!("failed to read {}", file.display()))?;
                    let sub_rec = catcloud_core::models::SubscriptionRecord {
                        id: args.sub_id.clone(),
                        name: args.name.clone(),
                        kind: catcloud_core::models::SubscriptionKind::File,
                        url_or_cmd: file.to_string_lossy().to_string(),
                        ..Default::default()
                    };
                    let parsed = parse_subscription_payload(&args.sub_id, &bytes, None)?;
                    (sub_rec, parsed)
                } else if let Some(url) = args.url {
                    let sub_rec = catcloud_core::models::SubscriptionRecord {
                        id: args.sub_id.clone(),
                        name: args.name.clone(),
                        kind: catcloud_core::models::SubscriptionKind::Url,
                        url_or_cmd: url,
                        ..Default::default()
                    };
                    let parsed = fetch_and_parse_subscription(&sub_rec, Duration::from_secs(20)).await?;
                    (sub_rec, parsed)
                } else {
                    anyhow::bail!("either --file or --url must be provided");
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
                    vec![preview_from_file(&file, None)?]
                } else {
                    let _ = args.scan;
                    scan_local_clients()
                };
                if args.apply {
                    let mut db = open_storage(paths)?;
                    let mut reports = Vec::new();
                    for (idx, p) in previews.iter().enumerate() {
                        if !p.nodes.is_empty() {
                            let sub_id = format!("sub-migrated-{idx}");
                            let sub_name = format!("Migrated {:?}", p.source_kind);
                            reports.push(import_migration_preview(
                                &mut db,
                                p,
                                &MigrationImportOptions::new(sub_id, sub_name),
                            )?);
                        }
                    }
                    let out = json!({ "ok": true, "applied": true, "reports": reports });
                    emit_output(as_json, &out, &format!("Applied {} migration(s).", reports.len()))
                } else {
                    let out = json!({ "ok": true, "applied": false, "previews": previews });
                    emit_output(
                        as_json,
                        &out,
                        &format!("Scanned {} readonly migration candidate(s).", previews.len()),
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
                    let out = json!({ "ok": true, "inspection": inspection });
                    emit_output(
                        as_json,
                        &out,
                        &format!("Inspected PID {pid} ({}).", target.name),
                    )
                } else {
                    let _ = args.list;
                    let candidates = list_process_candidates(!args.all);
                    let out = json!({ "ok": true, "count": candidates.len(), "processes": candidates });
                    emit_output(
                        as_json,
                        &out,
                        &format!("Found {} candidate process(es).", candidates.len()),
                    )
                }
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
                    let out = json!({
                        "ok": true,
                        "dry_run": true,
                        "executed": false,
                        "tier": &args.tier,
                        "node_count": nodes.len(),
                        "probe_count": selected_probes.len(),
                        "probes": &probe_ids,
                        "plan": plan,
                    });
                    return emit_output(
                        as_json,
                        &out,
                        &format!(
                            "Prepared isolated probe plan (dry-run, {} tier): {} probe(s) x {} node(s).",
                            args.tier,
                            selected_probes.len(),
                            nodes.len()
                        ),
                    );
                }

                if nodes.is_empty() {
                    let out = json!({
                        "ok": true,
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
                    let out = json!({
                        "ok": false,
                        "dry_run": false,
                        "executed": false,
                        "reason": "mihomo binary not found",
                        "tier": &args.tier,
                        "node_count": nodes.len(),
                        "probe_count": selected_probes.len(),
                        "probes": &probe_ids,
                        "plan": plan,
                        "checked_candidates": &bin_res.checked_candidates,
                        "download_guidance": &bin_res.download_guidance,
                    });
                    let human = match &bin_res.download_guidance {
                        Some(g) => format!(
                            "Probe execution skipped: Mihomo binary not found. {}",
                            g.instructions
                        ),
                        None => "Probe execution skipped: Mihomo binary not found.".to_string(),
                    };
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

                let out = json!({
                    "ok": true,
                    "dry_run": false,
                    "executed": true,
                    "tier": &args.tier,
                    "binary_path": &mihomo_bin,
                    "used_preaccel": active_relay.is_some(),
                    "preaccel_relay_name": active_relay.as_ref().map(|r| &r.name),
                    "node_count": nodes.len(),
                    "passed_nodes": passed_nodes,
                    "probe_count": selected_probes.len(),
                    "probes": &probe_ids,
                    "persisted_records": persisted_records,
                    "snapshots": &snapshots,
                    "reports": &reports,
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
                    std::fs::read_to_string(&path)
                        .with_context(|| format!("failed to read {}", path.display()))?
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
                let out = json!({
                    "ok": true,
                    "imported_relays": bundle.relays.len(),
                    "relays": bundle.relays,
                });
                emit_output(
                    as_json,
                    &out,
                    &format!("Imported {} verified domestic :443 relay(s).", bundle.relays.len()),
                )
            }

            PreaccelCommand::Pool => {
                let db = open_storage(paths)?;
                let relays = db.list_preaccel_relays(false)?;
                let now = Utc::now();
                let items: Vec<Value> = relays
                    .iter()
                    .map(|r| {
                        json!({
                            "relay": r,
                            "expiry": evaluate_expiry(r.expires_at.as_deref(), now),
                        })
                    })
                    .collect();
                let out = json!({ "ok": true, "count": items.len(), "relays": items });
                emit_output(
                    as_json,
                    &out,
                    &format!("Domestic pre-acceleration pool has {} relay(s).", items.len()),
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
                }
                if let Some(skip) = skip_443_native {
                    cfg.preaccel.skip_443_native = skip;
                }
                if let Some(url) = probe_url {
                    validate_domestic_probe_url(&url)?;
                    cfg.preaccel.probe_url = url;
                }
                config::save(paths, &cfg)?;
                let out = json!({ "ok": true, "preaccel": cfg.preaccel });
                emit_output(
                    as_json,
                    &out,
                    &format!(
                        "Updated preaccel binding: enabled={}, skip_443_native={}.",
                        cfg.preaccel.enabled, cfg.preaccel.skip_443_native
                    ),
                )
            }

            PreaccelCommand::Test { campus } => {
                let cfg = config::load_or_init(paths)?;
                let db = open_storage(paths)?;
                let relays = db.list_preaccel_relays(false)?;
                let nodes = db.list_nodes()?;
                let plan = build_preaccel_compile_plan(&cfg.preaccel, &relays, &nodes)?;
                let campus_state = if campus {
                    let state = probe_campus_portal(&cfg.preaccel.probe_url, Duration::from_secs(5)).await;
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
                let out = json!({
                    "ok": true,
                    "active": plan.active,
                    "relay_count": plan.ordered_relay_ids.len(),
                    "dialer_wrapped_nodes": plan.dialer_node_ids.len(),
                    "skipped_nodes": plan.skipped_node_ids.len(),
                    "anti_loop_rule_count": plan.anti_loop_rules.len(),
                    "probe_url": plan.effective_probe_url,
                    "warnings": plan.warnings,
                    "campus": campus_state,
                });
                emit_output(
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
                )
            }

            PreaccelCommand::GlobalStatus => {
                let (out, human) = build_global_preaccel_status_payload(paths)?;
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
                let out = json!({
                    "ok": ok,
                    "config_issues": cfg_issues,
                    "static_validation": static_report,
                    "stats": compiled.stats,
                    "ports": ports,
                });
                emit_output(
                    as_json,
                    &out,
                    &format!("Config validation ok={ok} (rules={}, proxies={}).", compiled.stats.total_rules, compiled.stats.total_proxies),
                )?;
                if !ok {
                    anyhow::bail!("configuration validation failed");
                }
                Ok(())
            }

            ConfigCommand::Reload { dry_run } => {
                let cfg = config::load_or_init(paths)?;
                let _ = open_storage(paths)?;
                let bin_res = resolve_mihomo_binary(&cfg, paths, &[], false)?;
                let job_guard = Arc::new(JobGuard::new()?);

                let configured_secret = cfg
                    .controller_secret
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToString::to_string);

                let probe_adapter = MihomoAdapter::with_controller_endpoint(
                    Arc::clone(&job_guard),
                    &cfg.controller_host,
                    cfg.controller_port,
                    configured_secret.clone().unwrap_or_default(),
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

                if dry_run {
                    let db = open_storage(paths)?;
                    let nodes = db.list_nodes()?;
                    let groups = db.list_multi_groups()?;
                    let relays = db.list_preaccel_relays(false)?;
                    let bind_host = if cfg.allow_lan {
                        cfg.bind_address.clone()
                    } else {
                        "127.0.0.1".to_string()
                    };
                    let ports = AllocatedPorts {
                        bind_host,
                        mixed_port: cfg.mixed_port,
                        controller_port: cfg.controller_port,
                        dns_port: cfg.dns_listen_port,
                        shifted: Vec::new(),
                    };
                    let secret = configured_secret
                        .clone()
                        .unwrap_or_else(generate_controller_secret);
                    let empty_filter = HashMap::new();
                    let compiled = compile_mihomo_config(&CompileInput {
                        config: &cfg,
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
                        let summary = compiled
                            .validation
                            .errors()
                            .iter()
                            .map(|i| format!("[{}] {}", i.code, i.message))
                            .collect::<Vec<_>>()
                            .join("; ");
                        let out = json!({
                            "ok": false,
                            "dry_run": true,
                            "validated_and_written": false,
                            "error": format!("compiled YAML failed static anti-loop preflight: {summary}"),
                            "static_validation": &compiled.validation,
                        });
                        if as_json {
                            emit_output(true, &out, "")?;
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
                            let msg = err.to_string();
                            let out = json!({
                                "ok": false,
                                "dry_run": true,
                                "validated_and_written": false,
                                "binary_verified": false,
                                "binary_path": bin_path,
                                "error": &msg,
                            });
                            if as_json {
                                emit_output(true, &out, "")?;
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
                        .map(|w| format!("[{}] {}", w.code, w.message))
                        .collect();
                    let out = json!({
                        "ok": true,
                        "dry_run": true,
                        "runtime_yaml_path": &runtime_yaml_path,
                        "core_not_running": live_controller_version.is_none() && controller_auth_error.is_none(),
                        "core_version": &live_controller_version,
                        "hot_reloaded": false,
                        "validated_and_written": false,
                        "binary_verified": binary_verified,
                        "binary_path": &bin_res.path,
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
                    let msg = format!(
                        "running Mihomo controller at {} rejected authentication ({auth_err}); configure matching `controller_secret` in config.json",
                        cfg.controller_addr()
                    );
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
                let runtime_yaml_path = coordinator.runtime_yaml_path();
                let outcome = coordinator
                    .apply_disk_reload(DiskReloadOptions {
                        force: true,
                        verify_with_binary: true,
                        allow_l3_restart: false,
                        ..DiskReloadOptions::default()
                    })
                    .await;

                if outcome.rejected || !outcome.applied {
                    let err_msg = outcome
                        .error
                        .clone()
                        .unwrap_or_else(|| "hot reload rejected".to_string());
                    let out = json!({
                        "ok": false,
                        "dry_run": false,
                        "runtime_yaml_path": &runtime_yaml_path,
                        "core_not_running": !core_running,
                        "core_version": &live_controller_version,
                        "hot_reloaded": false,
                        "validated_and_written": false,
                        "binary_verified": bin_res.found,
                        "binary_path": &bin_res.path,
                        "error": &err_msg,
                        "outcome": &outcome,
                    });
                    if as_json {
                        emit_output(true, &out, "")?;
                    }
                    anyhow::bail!("config reload failed: {err_msg}");
                }

                let sha_preview = outcome
                    .config_hash
                    .as_deref()
                    .map(|h| &h[..h.len().min(12)])
                    .unwrap_or("unknown");
                let out = json!({
                    "ok": true,
                    "dry_run": false,
                    "runtime_yaml_path": &runtime_yaml_path,
                    "core_not_running": !core_running,
                    "core_version": &live_controller_version,
                    "hot_reloaded": core_running,
                    "validated_and_written": true,
                    "binary_verified": bin_res.found,
                    "binary_path": &bin_res.path,
                    "replayed_groups": outcome.replayed_groups,
                    "level": outcome.level,
                    "sha256": &outcome.config_hash,
                    "warnings": &outcome.warnings,
                    "applied_at": &outcome.applied_at,
                    "outcome": &outcome,
                });
                let human = if core_running {
                    format!(
                        "Hot-reloaded runtime.yaml via controller ({}) and replayed {} group(s) (sha256={sha_preview}).",
                        cfg.controller_addr(),
                        outcome.replayed_groups
                    )
                } else {
                    format!(
                        "Core not running; validated and wrote {} (binary_verified={}, sha256={sha_preview}).",
                        runtime_yaml_path.display(),
                        bin_res.found
                    )
                };
                emit_output(as_json, &out, &human)
            }

            ConfigCommand::Compile { output } => {
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
                let compiled = catcloud_core::core_adapter::compile_mihomo_config_with_runtime_dir(
                    &CompileInput {
                        config: &cfg,
                        nodes: &nodes,
                        groups: &groups,
                        relays: &relays,
                        controller_secret: "compile-placeholder-secret",
                        allocated_ports: &ports,
                        extra_prepend_rules: &[],
                        extra_fake_ip_filters: &[],
                        group_filtered_members: &empty_filter,
                    },
                    Some(&paths.runtime_dir),
                )?;
                if let Some(path) = output {
                    AppPaths::atomic_write(&path, compiled.yaml.as_bytes())?;
                    let out = json!({ "ok": true, "output": path, "sha256": compiled.sha256 });
                    emit_output(as_json, &out, &format!("Wrote compiled YAML to {}.", path.display()))
                } else if as_json {
                    emit_output(
                        true,
                        &json!({ "ok": true, "yaml": compiled.yaml, "sha256": compiled.sha256 }),
                        "",
                    )
                } else {
                    println!("{}", compiled.yaml);
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

            ConfigCommand::Diag => {
                let out = build_diag_payload(paths)?;
                emit_output(as_json, &out, &serde_json::to_string_pretty(&out)?)
            }
        },

        Commands::Docs { action } => match action {
            DocsCommand::List => {
                let docs = agent_docs::list_agent_docs();
                let summary: Vec<Value> = docs
                    .iter()
                    .map(|d| json!({ "module_id": d.module_id, "title": d.title, "summary": d.summary }))
                    .collect();
                let out = json!({ "ok": true, "modules": summary });
                let human = docs
                    .iter()
                    .map(|d| format!("- {}: {}", d.module_id, d.title))
                    .collect::<Vec<_>>()
                    .join("\n");
                emit_output(as_json, &out, &human)
            }

            DocsCommand::Export { module, format } => {
                let json_fmt = as_json || format.eq_ignore_ascii_case("json");
                let rendered = agent_docs::export_agent_docs(&module, json_fmt)?;
                println!("{rendered}");
                Ok(())
            }
        },

        Commands::Update { action } => match action {
            UpdateCommand::Check { repo, offline } => {
                let cfg = config::load_or_init(paths)?;
                let target_repo = repo.unwrap_or_else(|| cfg.update.repo.clone());
                let current_version = env!("CARGO_PKG_VERSION");

                if offline {
                    let out = json!({
                        "ok": true,
                        "offline": true,
                        "current_version": current_version,
                        "repo": &target_repo,
                        "mode": &cfg.update.mode,
                        "include_prerelease": cfg.update.include_prerelease,
                        "staging_dir": &paths.staging_dir,
                    });
                    return emit_output(
                        as_json,
                        &out,
                        &format!(
                            "CatCloud v{current_version} offline update channel: {} ({:?})",
                            target_repo, cfg.update.mode
                        ),
                    );
                }

                let updater = match Updater::new(&target_repo, current_version) {
                    Ok(u) => u,
                    Err(err) => {
                        let msg = err.to_string();
                        let out = json!({
                            "ok": false,
                            "offline": false,
                            "current_version": current_version,
                            "repo": &target_repo,
                            "mode": &cfg.update.mode,
                            "include_prerelease": cfg.update.include_prerelease,
                            "staging_dir": &paths.staging_dir,
                            "error": &msg,
                        });
                        if as_json {
                            emit_output(true, &out, "")?;
                        }
                        anyhow::bail!("failed to initialize updater for `{target_repo}`: {msg}");
                    }
                };
                let manifest_url = updater.default_latest_json_url();
                match updater.check_latest(None).await {
                    Ok(check) => {
                        let platforms: Vec<&String> = check.manifest.platforms.keys().collect();
                        let out = json!({
                            "ok": true,
                            "offline": false,
                            "current_version": &check.current_version,
                            "latest_version": &check.latest_version,
                            "update_available": check.update_available,
                            "pub_date": &check.pub_date,
                            "notes": &check.notes,
                            "repo": &target_repo,
                            "manifest_url": &manifest_url,
                            "mode": &cfg.update.mode,
                            "include_prerelease": cfg.update.include_prerelease,
                            "staging_dir": &paths.staging_dir,
                            "platforms": platforms,
                            "manifest": &check.manifest,
                        });
                        let human = if check.update_available {
                            format!(
                                "Update available for CatCloud: v{} -> v{} (repo={}).",
                                check.current_version, check.latest_version, target_repo
                            )
                        } else {
                            format!(
                                "CatCloud v{} is up to date (latest: v{}, repo={}).",
                                check.current_version, check.latest_version, target_repo
                            )
                        };
                        emit_output(as_json, &out, &human)
                    }
                    Err(err) => {
                        let msg = err.to_string();
                        let out = json!({
                            "ok": false,
                            "offline": false,
                            "current_version": current_version,
                            "repo": &target_repo,
                            "manifest_url": &manifest_url,
                            "mode": &cfg.update.mode,
                            "include_prerelease": cfg.update.include_prerelease,
                            "staging_dir": &paths.staging_dir,
                            "error": &msg,
                        });
                        if as_json {
                            emit_output(true, &out, "")?;
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
                let manifest_bytes = std::fs::read(&manifest)?;
                let parsed_manifest = parse_latest_manifest(&manifest_bytes)?;
                let sums_raw = std::fs::read_to_string(&checksums)?;
                let sums = parse_sha256sums(&sums_raw)?;
                let fname = asset_name.unwrap_or_else(|| {
                    archive
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("update.zip")
                        .to_string()
                });
                let expected = sums
                    .get(&fname)
                    .cloned()
                    .with_context(|| format!("asset `{fname}` missing from SHA256SUMS"))?;
                let zip_bytes = std::fs::read(&archive)?;
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
const MAX_DIAG_LOG_TAIL_READ_BYTES: u64 = 64 * 1024;

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
        "country_mmdb": inspect_geodata_file(runtime_dir, &["Country.mmdb", "country.mmdb", "country-lite.mmdb"]),
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
    let recommended_mode = if cfg!(target_os = "windows") && caps.is_elevated && windivert_available {
        "windivert"
    } else {
        "local_socks5"
    };

    let out = json!({
        "ok": true,
        "os": caps.os,
        "arch": caps.arch,
        "is_elevated": caps.is_elevated,
        "global_bypass_enabled": cfg.preaccel.global_bypass_enabled,
        "global_scope": cfg.preaccel.global_scope,
        "global_target_processes": cfg.preaccel.global_target_processes,
        "windivert_dir": cfg.preaccel.windivert_dir,
        "windivert_available": windivert_available,
        "windivert_dll": wd_files.as_ref().map(|(dll, _)| dll.to_string_lossy().to_string()),
        "windivert_sys": wd_files.as_ref().map(|(_, sys)| sys.to_string_lossy().to_string()),
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

fn build_diag_payload(paths: &AppPaths) -> Result<Value> {
    let cfg = config::load_or_init(paths)?;
    let db = open_storage(paths)?;
    let plat = default_platform();
    let caps = plat.capabilities();
    let geodata_status = collect_geodata_status(&paths.runtime_dir);
    let wd_files = locate_windivert_files(paths, cfg.preaccel.windivert_dir.as_deref());
    let recent_logs =
        read_sanitized_log_tail(&paths.logs_dir.join("catcloud.log"), MAX_DIAG_LOG_LINES);
    Ok(json!({
        "ok": true,
        "sanitized": true,
        "version": env!("CARGO_PKG_VERSION"),
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
        "tun_enabled": cfg.tun.enabled,
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
    }))
}

fn read_sanitized_log_tail(log_path: &std::path::Path, max_lines: usize) -> Vec<String> {
    use std::io::{Read, Seek, SeekFrom};

    if max_lines == 0 {
        return Vec::new();
    }
    let Ok(mut file) = std::fs::File::open(log_path) else {
        return Vec::new();
    };
    let Ok(meta) = file.metadata() else {
        return Vec::new();
    };
    let len = meta.len();
    if len == 0 {
        return Vec::new();
    }
    let start = len.saturating_sub(MAX_DIAG_LOG_TAIL_READ_BYTES);
    if start > 0 && file.seek(SeekFrom::Start(start)).is_err() {
        return Vec::new();
    }
    let mut buf = Vec::with_capacity((len - start).min(MAX_DIAG_LOG_TAIL_READ_BYTES) as usize);
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

    let mut lines: Vec<String> = content
        .lines()
        .rev()
        .filter(|l| !l.trim().is_empty())
        .take(max_lines)
        .map(sanitize_log_line)
        .collect();
    lines.reverse();
    lines
}

fn sanitize_log_line(line: &str) -> String {
    let step1 = redact_sensitive_fields(line);
    redact_ipv6_addresses(&step1)
}

fn is_sensitive_key(key_lower: &str) -> bool {
    matches!(
        key_lower,
        "secret"
            | "password"
            | "passwd"
            | "pwd"
            | "token"
            | "auth"
            | "authorization"
            | "uuid"
            | "apikey"
            | "api_key"
            | "api-key"
            | "private_key"
            | "private-key"
            | "auth_str"
            | "auth-str"
    ) || key_lower.ends_with("_secret")
        || key_lower.ends_with("-secret")
        || key_lower.ends_with("_password")
        || key_lower.ends_with("-password")
        || key_lower.ends_with("_token")
        || key_lower.ends_with("-token")
        || key_lower.ends_with("api_key")
        || key_lower.ends_with("api-key")
        || key_lower.ends_with("private_key")
        || key_lower.ends_with("private-key")
}

fn is_key_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn is_value_boundary(b: u8) -> bool {
    b.is_ascii_whitespace()
        || matches!(
            b,
            b',' | b'&' | b';' | b'"' | b'\'' | b'}' | b']' | b')' | b'>'
        )
}

fn redact_sensitive_fields(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut i = 0usize;

    while i < len {
        // Standalone `Bearer <token>` (case-insensitive)
        let prev_is_key = i > 0 && is_key_char(bytes[i - 1]);
        if !prev_is_key && i + 7 <= len && input[i..].len() >= 7 {
            if bytes[i..i + 6].eq_ignore_ascii_case(b"bearer")
                && (bytes[i + 6] == b' ' || bytes[i + 6] == b'\t')
            {
                let mut v_start = i + 6;
                while v_start < len && (bytes[v_start] == b' ' || bytes[v_start] == b'\t') {
                    v_start += 1;
                }
                if v_start < len && !is_value_boundary(bytes[v_start]) {
                    let mut v_end = v_start;
                    while v_end < len && !is_value_boundary(bytes[v_end]) {
                        v_end += 1;
                    }
                    out.push_str(&input[i..v_start]);
                    out.push_str("<REDACTED>");
                    i = v_end;
                    continue;
                }
            }
        }

        // Key-value pair: optional quote + sensitive key + optional quote + optional spaces + (`=` | `:`)
        let quote_ch = if bytes[i] == b'"' || bytes[i] == b'\'' {
            Some(bytes[i])
        } else {
            None
        };
        let key_start = if quote_ch.is_some() { i + 1 } else { i };
        let valid_key_boundary = quote_ch.is_some() || !prev_is_key;

        if valid_key_boundary && key_start < len && is_key_char(bytes[key_start]) {
            let mut key_end = key_start;
            while key_end < len && is_key_char(bytes[key_end]) {
                key_end += 1;
            }
            let after_key = match quote_ch {
                Some(q) if key_end < len && bytes[key_end] == q => Some(key_end + 1),
                Some(_) => None,
                None => Some(key_end),
            };
            if let Some(mut sep_pos) = after_key {
                let key_lower = input[key_start..key_end].to_ascii_lowercase();
                if is_sensitive_key(&key_lower) {
                    while sep_pos < len && (bytes[sep_pos] == b' ' || bytes[sep_pos] == b'\t') {
                        sep_pos += 1;
                    }
                    if sep_pos < len && (bytes[sep_pos] == b'=' || bytes[sep_pos] == b':') {
                        let mut v_start = sep_pos + 1;
                        while v_start < len && (bytes[v_start] == b' ' || bytes[v_start] == b'\t') {
                            v_start += 1;
                        }
                        if v_start < len {
                            if bytes[v_start] == b'"' || bytes[v_start] == b'\'' {
                                let vq = bytes[v_start];
                                let mut v_end = v_start + 1;
                                while v_end < len {
                                    if bytes[v_end] == b'\\' && v_end + 1 < len {
                                        v_end += 2;
                                        continue;
                                    }
                                    if bytes[v_end] == vq {
                                        break;
                                    }
                                    v_end += 1;
                                }
                                out.push_str(&input[i..=v_start]);
                                if v_end > v_start + 1 {
                                    out.push_str("<REDACTED>");
                                }
                                if v_end < len && bytes[v_end] == vq {
                                    out.push(vq as char);
                                    i = v_end + 1;
                                } else {
                                    i = v_end;
                                }
                                continue;
                            } else if !is_value_boundary(bytes[v_start]) {
                                // Preserve `Bearer ` prefix inside `Authorization: Bearer <val>`.
                                let mut actual_start = v_start;
                                if actual_start + 7 <= len
                                    && bytes[actual_start..actual_start + 6]
                                        .eq_ignore_ascii_case(b"bearer")
                                    && (bytes[actual_start + 6] == b' '
                                        || bytes[actual_start + 6] == b'\t')
                                {
                                    actual_start += 6;
                                    while actual_start < len
                                        && (bytes[actual_start] == b' '
                                            || bytes[actual_start] == b'\t')
                                    {
                                        actual_start += 1;
                                    }
                                }
                                if actual_start < len && !is_value_boundary(bytes[actual_start]) {
                                    let mut v_end = actual_start;
                                    while v_end < len && !is_value_boundary(bytes[v_end]) {
                                        v_end += 1;
                                    }
                                    out.push_str(&input[i..actual_start]);
                                    out.push_str("<REDACTED>");
                                    i = v_end;
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Advance one UTF-8 character safely.
        let ch = input[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }

    out
}

fn try_redact_bare_ipv6(tok: &str) -> Option<String> {
    let trimmed_end = tok.trim_end_matches('.');
    let trailing_dots = &tok[trimmed_end.len()..];
    if trimmed_end.is_empty() || !trimmed_end.contains(':') {
        return None;
    }

    let (addr_and_zone, cidr_suffix) = match trimmed_end.rsplit_once('/') {
        Some((left, prefix))
            if !prefix.is_empty() && prefix.parse::<u8>().is_ok_and(|p| p <= 128) =>
        {
            (left, Some(prefix))
        }
        _ => (trimmed_end, None),
    };
    let addr_part = addr_and_zone
        .split_once('%')
        .map_or(addr_and_zone, |(a, _)| a);
    if addr_part.parse::<std::net::Ipv6Addr>().is_ok() {
        let mut res = "<REDACTED_IPV6>".to_string();
        if let Some(prefix) = cidr_suffix {
            res.push('/');
            res.push_str(prefix);
        }
        res.push_str(trailing_dots);
        return Some(res);
    }
    None
}

fn redact_ipv6_token(tok: &str) -> Option<String> {
    // 1. Bracketed IPv6 such as `[2001:db8::1]:443` or `http://[2001:db8::1]:9090/version`
    if let Some(open) = tok.find('[') {
        if let Some(rel_close) = tok[open + 1..].find(']') {
            let close = open + 1 + rel_close;
            let inner = &tok[open + 1..close];
            let addr_part = inner.split_once('%').map_or(inner, |(a, _)| a);
            if addr_part.parse::<std::net::Ipv6Addr>().is_ok() {
                let mut res = String::with_capacity(tok.len());
                res.push_str(&tok[..=open]);
                res.push_str("<REDACTED_IPV6>");
                res.push_str(&tok[close..]);
                return Some(res);
            }
        }
    }

    // 2. Bare IPv6 / IPv6+zone / IPv6 CIDR
    if let Some(redacted) = try_redact_bare_ipv6(tok) {
        return Some(redacted);
    }

    // 3. `label:ipv6` (e.g. `src:2001:db8::1`)
    if let Some((prefix, rest)) = tok.split_once(':') {
        if !prefix.is_empty() && prefix.bytes().all(is_key_char) {
            if let Some(redacted_rest) = try_redact_bare_ipv6(rest) {
                return Some(format!("{prefix}:{redacted_rest}"));
            }
        }
    }

    None
}

fn is_ipv6_tok_sep(b: u8) -> bool {
    b.is_ascii_whitespace()
        || matches!(
            b,
            b',' | b';' | b'"' | b'\'' | b'(' | b')' | b'{' | b'}' | b'<' | b'>' | b'=' | b'&'
        )
}

fn redact_ipv6_addresses(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut i = 0usize;

    while i < len {
        if is_ipv6_tok_sep(bytes[i]) {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        let start = i;
        while i < len && !is_ipv6_tok_sep(bytes[i]) {
            i += 1;
        }
        let tok = &input[start..i];
        if let Some(redacted) = redact_ipv6_token(tok) {
            out.push_str(&redacted);
        } else {
            out.push_str(tok);
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use catcloud_core::models::RouteTargetMode;

    #[test]
    fn sanitize_log_line_redacts_secrets_passwords_tokens_and_ipv6_without_breaking_timestamps() {
        let raw = concat!(
            "2026-11-24T03:20:00Z INFO auth failed ",
            "controller_secret=deadbeef01234567 ",
            "\"password\": \"myS3cr3t!\", ",
            "url=https://sub.example.com/api?token=tok_999888&ok=1 ",
            "Authorization: Bearer eyJhbGci.payload.sig ",
            "peer=[2001:db8:85a3::8a2e:370:7334]:443 ",
            "src=fe80::1%12 net=2001:db8::/48 local=::1 ",
            "mod=catcloud_core::config"
        );
        let sanitized = sanitize_log_line(raw);

        assert!(sanitized.contains("2026-11-24T03:20:00Z"));
        assert!(sanitized.contains("mod=catcloud_core::config"));
        assert!(sanitized.contains("ok=1"));

        assert!(!sanitized.contains("deadbeef01234567"));
        assert!(!sanitized.contains("myS3cr3t!"));
        assert!(!sanitized.contains("tok_999888"));
        assert!(!sanitized.contains("eyJhbGci.payload.sig"));
        assert!(!sanitized.contains("2001:db8:85a3::8a2e:370:7334"));
        assert!(!sanitized.contains("fe80::1"));
        assert!(!sanitized.contains("2001:db8::/48"));

        assert!(sanitized.contains("controller_secret=<REDACTED>"));
        assert!(sanitized.contains("\"password\": \"<REDACTED>\""));
        assert!(sanitized.contains("token=<REDACTED>&ok=1"));
        assert!(sanitized.contains("Authorization: Bearer <REDACTED>"));
        assert!(sanitized.contains("peer=[<REDACTED_IPV6>]:443"));
        assert!(sanitized.contains("src=<REDACTED_IPV6>"));
        assert!(sanitized.contains("net=<REDACTED_IPV6>/48"));
        assert!(sanitized.contains("local=<REDACTED_IPV6>"));
    }

    #[test]
    fn diag_payload_includes_rich_routing_geodata_and_bounded_sanitized_log_tail() {
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
        config::save(&paths, &cfg).expect("save config");

        // Place country-lite.mmdb + geosite.dat so geodata_status reflects disk reality.
        std::fs::write(paths.runtime_dir.join("country-lite.mmdb"), b"stub-mmdb").unwrap();
        std::fs::write(paths.runtime_dir.join("geosite.dat"), b"stub-geosite").unwrap();

        // Write 55 log lines containing sensitive tokens and IPv6 addresses.
        let mut log_content = String::new();
        for idx in 1..=55 {
            log_content.push_str(&format!(
                "2026-11-24T03:00:{:02}Z INFO line={} secret=sec_{idx} token=tok_{idx} ip=2001:db8::{idx:x}\n",
                idx % 60,
                idx
            ));
        }
        std::fs::write(paths.logs_dir.join("catcloud.log"), log_content).unwrap();

        let diag = build_diag_payload(&paths).expect("build diag payload");
        assert_eq!(diag["ok"], json!(true));
        assert_eq!(diag["sanitized"], json!(true));
        assert_eq!(diag["route_mode"], json!("single"));
        assert_eq!(diag["active_group_id"], json!("grp-tw"));
        assert_eq!(diag["active_single_node_id"], json!("node-tw-01"));
        assert_eq!(diag["system_proxy_enabled"], json!(true));
        assert_eq!(diag["tun_enabled"], json!(true));
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
            assert!(!s.contains("2001:db8::"));
            assert!(s.contains("secret=<REDACTED>"));
            assert!(s.contains("token=<REDACTED>"));
            assert!(s.contains("ip=<REDACTED_IPV6>"));
        }

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
        assert_eq!(payload_after["windivert_available"], json!(true));
        assert!(payload_after["windivert_dll"].as_str().is_some());
        assert!(payload_after["windivert_sys"].as_str().is_some());

        let _ = std::fs::remove_dir_all(&temp_root);
    }
}
