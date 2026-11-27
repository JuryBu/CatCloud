use anyhow::{Context, Result};
use catcloud_core::agent_docs;
use catcloud_core::config::{self, ConfigValidationIssue, ValidationSeverity};
use catcloud_core::core_adapter::config_compiler::{
    CompileInput, DEFAULT_FALLBACK_GROUP_NAME, GatewayExportOptions, GatewayExportOutput,
    GatewayExportProfile, PREACCEL_SELECT_GROUP_NAME, PreAccelTransportDiagnostics,
    SINGLE_NODE_GROUP_NAME, StaticCheckIssue, StaticValidationReport,
    build_preaccel_transport_diagnostics, compile_mihomo_config_with_runtime_dir,
    export_gateway_yaml, validate_compiled_yaml,
};
use catcloud_core::core_adapter::dns_diag::{
    DNS_TLS_STATUS_CERT_FAILED, DNS_TLS_STATUS_DEGRADED_RECOVERED, DnsTlsDiagnostics,
    analyze_dns_tls_diagnostics, analyze_dns_tls_diagnostics_from_log_file,
};
use catcloud_core::core_adapter::port_guard::{
    AllocatedPorts, PortShiftNotice, allocate_safe_ports_for_hosts, is_port_available_tcp_udp,
};
use catcloud_core::core_adapter::{
    ActiveConnection, BinaryResolution, DiskReloadOptions, DownloadGuidance, HotReloadCoordinator,
    LiveCoreConfigSnapshot, MihomoAdapter, ReloadLevel, ReloadOutcome, ResolvedControllerEndpoint,
    classify_config_diff, compute_file_sha256, format_host_port, generate_controller_secret,
    is_internal_or_preaccel_connection, read_live_runtime_controller_meta,
    resolve_effective_controller_endpoint_info, resolve_mihomo_binary, verify_config_with_binary,
};
use catcloud_core::models::{
    AppConfig, CoreLogLevel, DEFAULT_COST_EFFECTIVE_FORMULA, FallbackPolicy, MultiGroup,
    MultiGroupMode, NodeFilter, PreAccelConfig, PreAccelDispatchStrategy, PreAccelLbStrategy,
    PreAccelRelay, ProbeDefinition, ProbeKind, ProxyMode, ProxyNode, RouteTargetMode,
    SubscriptionKind, SubscriptionRecord, SwitchMode, TunStackMode, is_ipv6_only_node,
};
use catcloud_core::platform::{
    PortListenerOwner, default_platform, get_process_start_time_unix, list_listening_port_owners,
};
use catcloud_core::preaccel::campus::{CampusBypassTracker, probe_campus_portal};
use catcloud_core::preaccel::generator::{build_preaccel_compile_plan, validate_domestic_probe_url};
use catcloud_core::preaccel::global_tunnel::{
    GlobalPreAccelRuntimeMeta, detect_host_security_products, locate_windivert_files,
    read_global_preaccel_runtime_meta,
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
    redact_relay_for_readonly, sanitize_json_value, sanitize_log_line,
};
use catcloud_core::share_bundle::{
    ShareBundleExportRequest, ShareBundlePreview, ShareGroupsBundle, build_share_groups_bundle,
    export_share_bundle_zip_bytes_with_groups, export_share_bundle_zip_file,
    merge_imported_groups_into_storage, preview_share_bundle_zip_bytes,
    preview_share_bundle_zip_file,
};
use catcloud_core::sync::{
    KDF_MODE_PBKDF2_SHA256, KDF_MODE_RAW_KEY, KEY_LEN, LanSyncReceiveServer, LanSyncSendServer,
    LanSyncServerOptions, MAX_SYNC_ENVELOPE_BYTES, SyncRole, SyncUri, decode_base64_flex,
    fetch_relay_url_bundle, fetch_sync_bundle_via_pin, fetch_sync_bundle_via_uri, format_sync_uri,
    generate_random_key, generate_session_id, inspect_envelope_header, open_with_key,
    open_with_password, parse_sync_uri, plaintext_fingerprint, push_sync_bundle_via_pin,
    push_sync_bundle_via_uri, render_qr_terminal, seal_with_key,
};
use catcloud_core::storage::{Storage, SubscriptionUpdateMode};
use catcloud_core::strategy::arbiter::{ArbiterGroupMemory, decide_group_action};
use catcloud_core::strategy::evaluator::evaluate_group_candidates;
use catcloud_core::strategy::formula::validate_formula;
use catcloud_core::strategy::health_pool::read_watchdog_state_snapshot;
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
use chrono::{DateTime, Local, NaiveDateTime, NaiveTime, TimeZone, Utc};
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
    /// Run pure read-only layered diagnostics across paths, config, core, ports, proxy/TUN, preaccel, conflicts, GeoData, and DNS TLS health
    Doctor,
    /// Query active connections from the running Mihomo controller (redacted by default)
    Connections {
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Reveal unredacted IPs and process paths (default: redacted)
        #[arg(long)]
        reveal_secrets: bool,
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
    /// Read sanitized tail lines from catcloud.log (and .2 / .1 archives)
    Tail {
        #[arg(long, default_value_t = 80)]
        lines: usize,
        #[arg(long, default_value = "all")]
        level: String,
        /// Filter entries at or after this time (RFC3339, YYYY-MM-DD HH:MM[:SS], HH:MM, or relative like 30m / 2h)
        #[arg(long)]
        since: Option<String>,
        /// Filter entries at or before this time (RFC3339, YYYY-MM-DD HH:MM[:SS], HH:MM, or relative like 5m / 1h)
        #[arg(long)]
        until: Option<String>,
        /// Reveal unredacted log lines (default: redacted)
        #[arg(long)]
        reveal_secrets: bool,
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
        /// Output compact summary (counts, top regions, protocols, and up to 5 sanitized samples)
        #[arg(long)]
        summary: bool,
    },
    /// Preview (default --dry-run) or apply import of a catcloud-share/v1 .zip share bundle
    Import(ShareImportArgs),
    /// Start an E2EE LAN sync sender, push to a receiver, or export an encrypted .ccsync file
    Send(ShareSendArgs),
    /// Receive an E2EE sync bundle via URI, LAN PIN, .ccsync file, or LAN listener (default --dry-run)
    Receive(ShareReceiveArgs),
}

#[derive(Args, Debug)]
pub struct ShareSendArgs {
    #[arg(long, default_value = "CatCloud Share Bundle")]
    pub name: String,
    #[arg(long)]
    pub description: Option<String>,
    /// Comma-separated proxy node IDs to sync
    #[arg(long = "node-ids", alias = "nodes")]
    pub node_ids: Option<String>,
    /// Sync all nodes belonging to this subscription ID
    #[arg(long = "sub-id", alias = "sub")]
    pub sub_id: Option<String>,
    /// Sync all configured proxy nodes
    #[arg(long)]
    pub all_nodes: bool,
    /// Comma-separated domestic pre-acceleration relay IDs to sync
    #[arg(long = "relay-ids", alias = "relays")]
    pub relay_ids: Option<String>,
    /// Sync all configured domestic pre-acceleration relays
    #[arg(long)]
    pub all_relays: bool,
    /// Exclude portable smart multi-groups (groups.json) from the sync bundle
    #[arg(long)]
    pub no_groups: bool,
    /// Optional custom reachable endpoint URL (e.g. Tailscale/FRP/reverse proxy)
    #[arg(long)]
    pub endpoint: Option<String>,
    /// Bind host for LAN send listener
    #[arg(long, default_value = "0.0.0.0")]
    pub bind: String,
    /// Bind port for LAN send listener (0 = OS ephemeral port)
    #[arg(long, default_value_t = 0)]
    pub port: u16,
    /// Session TTL in seconds (clamped to 30..=900)
    #[arg(long, default_value_t = 180)]
    pub ttl: u64,
    /// Keep listener alive across multiple transfers instead of one-shot auto-destruct
    #[arg(long)]
    pub allow_multiple: bool,
    /// Push directly to a receiver's catcloud://sync/v1?role=push...#k=... URI
    #[arg(long)]
    pub push_uri: Option<String>,
    /// Push directly to a receiver's LAN address (host:port or http://...) paired with --pin
    #[arg(long)]
    pub push_addr: Option<String>,
    /// 6-digit PIN code paired with --push-addr
    #[arg(long)]
    pub pin: Option<String>,
    /// Export an offline E2EE .ccsync file and emit its file_key URI instead of starting LAN HTTP
    #[arg(long = "ccsync-output", alias = "output")]
    pub ccsync_output: Option<PathBuf>,
    /// Suppress ASCII QR rendering in human-readable mode
    #[arg(long)]
    pub no_qr: bool,
}

#[derive(Args, Debug)]
pub struct ShareReceiveArgs {
    /// Positional sync URI (catcloud://sync/v1?...#k=...) or LAN address
    pub source: Option<String>,
    /// Explicit sync URI (role=pull or role=relay_url)
    #[arg(long, conflicts_with = "source")]
    pub uri: Option<String>,
    /// Sender LAN address (ip:port or http://...) paired with --pin
    #[arg(long)]
    pub addr: Option<String>,
    /// 6-digit PIN code paired with --addr
    #[arg(long)]
    pub pin: Option<String>,
    /// Path to an offline E2EE .ccsync file
    #[arg(long)]
    pub ccsync: Option<PathBuf>,
    /// Decryption key (catcloud://sync/v1?role=file_key...#k=... or 32-byte Base64) for --ccsync
    #[arg(long)]
    pub key: Option<String>,
    /// Password for PBKDF2-encrypted --ccsync files
    #[arg(long)]
    pub password: Option<String>,
    /// Start a local LAN receiver listener and wait for one incoming encrypted push
    #[arg(long)]
    pub listen: bool,
    /// Bind host when --listen is enabled
    #[arg(long, default_value = "0.0.0.0")]
    pub bind: String,
    /// Bind port when --listen is enabled (0 = OS ephemeral port)
    #[arg(long, default_value_t = 0)]
    pub port: u16,
    /// Optional custom reachable endpoint URL embedded in listener QR URI
    #[arg(long)]
    pub endpoint: Option<String>,
    /// Listener TTL in seconds when --listen is enabled (clamped to 30..=900)
    #[arg(long, default_value_t = 180)]
    pub ttl: u64,
    /// Suppress ASCII QR rendering when --listen is enabled
    #[arg(long)]
    pub no_qr: bool,
    /// Safe sanitized preview without mutating storage (default unless --apply is set)
    #[arg(long)]
    pub dry_run: bool,
    /// Persist received nodes, relays, and groups into local CatCloud storage
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
    /// Skip importing proxy nodes
    #[arg(long)]
    pub no_nodes: bool,
    /// Skip importing domestic pre-acceleration relays
    #[arg(long)]
    pub no_relays: bool,
    /// Skip merging portable smart multi-groups (groups.json)
    #[arg(long)]
    pub no_groups: bool,
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
    /// Create or partially update a smart multi-group (preserves unspecified fields on existing groups)
    Create(GroupCreateArgs),
    /// Safely add, remove, or replace member nodes without touching group policies or routing rules
    Members(GroupMembersArgs),
    /// Switch active node in a multi-group (explicit or next best)
    Switch {
        group_id: String,
        #[arg(long)]
        node: Option<String>,
    },
    /// Update formula, fallback policy, switch mode, hard gates, or routing match rules for a group
    Policy(GroupPolicyArgs),
    /// Evaluate candidate scores and arbiter decision for a group
    Eval { group_id: String },
}

#[derive(Args, Debug)]
pub struct GroupCreateArgs {
    #[arg(long)]
    pub id: String,
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub mode: Option<String>,
    #[arg(long)]
    pub formula: Option<String>,
    #[arg(long)]
    pub fallback: Option<String>,
    #[arg(long)]
    pub switch_mode: Option<String>,
    #[arg(long)]
    pub nodes: Option<String>,
}

#[derive(Args, Debug)]
pub struct GroupMembersArgs {
    /// Target multi-group ID
    #[arg(long = "id", alias = "group-id")]
    pub id: String,
    /// Member mutation operation: add | remove | set
    #[arg(value_parser = ["add", "remove", "set"])]
    pub action: String,
    /// Comma-separated node IDs
    #[arg(long)]
    pub nodes: String,
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
    /// Replace group match rules (semicolon-separated full rules or comma-separated domains)
    #[arg(long = "match-rules")]
    pub match_rules: Option<String>,
    /// Append one or more match rules (repeatable)
    #[arg(long = "add-match-rule")]
    pub add_match_rule: Vec<String>,
    /// Clear all match rules on this group
    #[arg(long = "clear-match-rules")]
    pub clear_match_rules: bool,
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
    /// Update domestic pre-acceleration enablement, native-443 skip, dispatch strategy, and domestic 204 probe URL
    Bind {
        #[arg(long)]
        enabled: Option<bool>,
        #[arg(long)]
        skip_443_native: Option<bool>,
        #[arg(long)]
        probe_url: Option<String>,
        /// Multi-cloud dispatch strategy: auto | load_balance | fallback
        #[arg(long)]
        dispatch_strategy: Option<String>,
        /// Inner load-balance strategy: consistent_hashing | round_robin
        #[arg(long)]
        lb_strategy: Option<String>,
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
    /// Export Mihomo YAML for transparent gateway / soft-router or domestic :443 relay fragment (redacted by default)
    ExportGateway {
        /// Export profile: relay-fragment | transparent-gateway | preferred-nodes
        #[arg(long, default_value = "relay-fragment")]
        profile: String,
        /// TPROXY listening port for transparent-gateway profile
        #[arg(long, default_value_t = 7893)]
        tproxy_port: u16,
        /// REDIR listening port for transparent-gateway profile
        #[arg(long, default_value_t = 7892)]
        redir_port: u16,
        /// DNS listening port for transparent-gateway profile (binds 0.0.0.0)
        #[arg(long, default_value_t = 1053)]
        dns_port: u16,
        /// Optional output path to write the exported YAML atomically
        #[arg(long)]
        output: Option<PathBuf>,
        /// Reveal plaintext relay/node credentials, IPs, and controller secret (default: redacted)
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

fn finalize_output_value(value: &Value) -> Value {
    let mut out = value.clone();
    if out.get("sanitized").and_then(Value::as_bool) == Some(true) {
        sanitize_json_value(&mut out);
    }
    out
}

fn emit_output(as_json: bool, value: &Value, human: &str) -> Result<()> {
    let should_sanitize = value.get("sanitized").and_then(Value::as_bool) == Some(true);
    if as_json {
        let final_value = finalize_output_value(value);
        println!("{}", serde_json::to_string_pretty(&final_value)?);
    } else if should_sanitize {
        println!("{}", sanitize_multiline_text(human));
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

fn parse_preaccel_dispatch_strategy(raw: &str) -> Result<PreAccelDispatchStrategy> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "auto" => Ok(PreAccelDispatchStrategy::Auto),
        "load_balance" | "load-balance" | "lb" => Ok(PreAccelDispatchStrategy::LoadBalance),
        "fallback" | "failover" => Ok(PreAccelDispatchStrategy::Fallback),
        other => anyhow::bail!(
            "unsupported dispatch strategy `{other}` (use auto|load_balance|fallback)"
        ),
    }
}

fn parse_preaccel_lb_strategy(raw: &str) -> Result<PreAccelLbStrategy> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "round_robin" | "round-robin" | "rr" => Ok(PreAccelLbStrategy::RoundRobin),
        "consistent_hashing" | "consistent-hashing" | "ch" => {
            Ok(PreAccelLbStrategy::ConsistentHashing)
        }
        other => anyhow::bail!(
            "unsupported lb strategy `{other}` (use round_robin|consistent_hashing)"
        ),
    }
}

fn looks_like_clash_rule_prefix(token: &str) -> bool {
    matches!(
        token.trim().to_ascii_uppercase().as_str(),
        "DOMAIN"
            | "DOMAIN-SUFFIX"
            | "DOMAIN-KEYWORD"
            | "DOMAIN-WILDCARD"
            | "DOMAIN-REGEX"
            | "GEOSITE"
            | "GEOIP"
            | "IP-CIDR"
            | "IP-CIDR6"
            | "SRC-IP-CIDR"
            | "SRC-PORT"
            | "DST-PORT"
            | "PROCESS-NAME"
            | "PROCESS-PATH"
            | "NETWORK"
            | "RULE-SET"
            | "AND"
            | "OR"
            | "NOT"
            | "SUB-RULE"
            | "MATCH"
    )
}

fn parse_group_match_rules_arg(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let items: Vec<&str> = if trimmed.contains(';') {
        trimmed.split(';').collect()
    } else if let Some((first, _)) = trimmed.split_once(',') {
        if looks_like_clash_rule_prefix(first) {
            vec![trimmed]
        } else {
            trimmed.split(',').collect()
        }
    } else {
        vec![trimmed]
    };
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for part in items {
        let cleaned = part.trim();
        if !cleaned.is_empty() && seen.insert(cleaned.to_string()) {
            out.push(cleaned.to_string());
        }
    }
    out
}

pub async fn dispatch(paths: &AppPaths, as_json: bool, cmd: Commands) -> Result<()> {
    match cmd {
        Commands::Status => {
            let (out, human) = build_status_payload(paths).await?;
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
                    "speed_unit": "Mbps",
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
                        "Executed isolated probe funnel ({} tier, speed unit: Mbps): {}/{} node(s) healthy, {} result(s) saved to SQLite.",
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
                let (out, human) = execute_group_create(paths, args)?;
                emit_output(as_json, &out, &human)
            }

            GroupCommand::Members(args) => {
                let (out, human) = execute_group_members(paths, args)?;
                emit_output(as_json, &out, &human)
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
                let (out, human) = execute_group_policy(paths, args)?;
                emit_output(as_json, &out, &human)
            }

            GroupCommand::Eval { group_id } => {
                let (out, human) = build_group_eval_payload(paths, &group_id)?;
                emit_output(as_json, &out, &human)
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
                    "speed_unit": "Mbps",
                    "count": items.len(),
                    "relays": items
                });
                let mut lines = vec![format!(
                    "Domestic pre-acceleration pool has {} relay(s) (sanitized={}, speed unit: Mbps).",
                    items.len(),
                    !reveal_secrets
                )];
                for r in &relays {
                    if r.last_up_mbps.is_some() || r.last_down_mbps.is_some() || r.last_mbps.is_some() {
                        let up = r
                            .last_up_mbps
                            .map(|v| format!("{v:.2} Mbps"))
                            .unwrap_or_else(|| "--".to_string());
                        let down = r
                            .last_down_mbps
                            .or(r.last_mbps)
                            .map(|v| format!("{v:.2} Mbps"))
                            .unwrap_or_else(|| "--".to_string());
                        lines.push(format!("- {} ({}): up={up} | down={down}", r.name, r.id));
                    }
                }
                emit_output(as_json, &out, &lines.join("\n"))
            }

            PreaccelCommand::Bind {
                enabled,
                skip_443_native,
                probe_url,
                dispatch_strategy,
                lb_strategy,
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
                if let Some(ds) = dispatch_strategy {
                    cfg.preaccel.dispatch_strategy = parse_preaccel_dispatch_strategy(&ds)?;
                }
                if let Some(lb) = lb_strategy {
                    cfg.preaccel.lb_strategy = parse_preaccel_lb_strategy(&lb)?;
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
                        "Updated preaccel binding: enabled={}, skip_443_native={}, dispatch_strategy={}, lb_strategy={}.",
                        cfg.preaccel.enabled,
                        cfg.preaccel.skip_443_native,
                        cfg.preaccel.dispatch_strategy.as_str(),
                        cfg.preaccel.lb_strategy.as_config_str()
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
                let target_relays: Vec<PreAccelRelay> = relays
                    .iter()
                    .filter(|r| r.enabled && !r.server.trim().is_empty() && r.port > 0)
                    .cloned()
                    .collect();
                let relays_support_ipv6 =
                    !target_relays.is_empty() && target_relays.iter().all(|r| r.supports_ipv6);
                let (reference_node, ref_note) = select_preaccel_speed_reference_node(
                    &cfg,
                    &groups,
                    &nodes,
                    node_id.as_deref(),
                    relays_support_ipv6,
                )?;

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
                    let rounded_chain_lat = sample
                        .chain_latency_ms
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
                    // Never overwrite domestic direct `last_probe_ms` with dual-hop overseas `cp.cloudflare.com` latency.
                    if rounded_up.is_some() || rounded_down.is_some() {
                        if let Err(err) = db.update_preaccel_speed_metrics(
                            &relay_id,
                            None,
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
                        "last_probe_ms": relay_opt.and_then(|r| r.last_probe_ms),
                        "chain_latency_ms": rounded_chain_lat,
                        "up_mbps": rounded_up,
                        "down_mbps": rounded_down,
                        "error": &clean_err,
                    }));

                    let lat_str = rounded_chain_lat
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
                            "- {relay_name} ({relay_id}): ok={} | chain_latency={lat_str} | up={up_str} | down={down_str} | note={err_text}",
                            sample.ok
                        ));
                    } else {
                        human_lines.push(format!(
                            "- {relay_name} ({relay_id}): ok={} | chain_latency={lat_str} | up={up_str} | down={down_str}",
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
                    "speed_unit": "Mbps",
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
                    "speed_unit": "Mbps",
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
                        "Pre-acceleration speed test ({mode_label} via `{}`, unit: Mbps): {passed_count}/{} relay(s) passed.",
                        n.name,
                        speed_results.len()
                    ),
                    None => format!(
                        "Pre-acceleration speed test ({mode_label}, unit: Mbps): {passed_count}/{} relay(s) passed.",
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
                let (out, human) = build_global_preaccel_status_payload(paths).await?;
                emit_output(as_json, &out, &human)
            }
        },

        Commands::Net { action } => match action {
            NetCommand::Doctor => {
                let (out, human) = build_net_doctor_payload(paths).await?;
                emit_output(as_json, &out, &human)
            }

            NetCommand::Connections {
                limit,
                reveal_secrets,
            } => {
                let (out, human) =
                    build_net_connections_payload(paths, limit, reveal_secrets).await?;
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
            LogsCommand::Tail {
                lines,
                level,
                since,
                until,
                reveal_secrets,
            } => {
                let (out, human) = build_logs_tail_payload_with_options(
                    paths,
                    lines,
                    &level,
                    since.as_deref(),
                    until.as_deref(),
                    reveal_secrets,
                    Local::now(),
                )?;
                emit_output(as_json, &out, &human)
            }
        },

        Commands::Config { action } => match action {
            ConfigCommand::Validate => {
                let (ok, out, human) = build_config_validate_payload(paths).await?;
                emit_output(as_json, &out, &human)?;
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
                execute_config_reload(paths, as_json, dry_run).await
            }

            ConfigCommand::Compile {
                output,
                reveal_secrets,
            } => execute_config_compile(paths, as_json, output, reveal_secrets).await,

            ConfigCommand::ExportGateway {
                profile,
                tproxy_port,
                redir_port,
                dns_port,
                output,
                reveal_secrets,
            } => {
                execute_config_export_gateway(
                    paths,
                    as_json,
                    &profile,
                    tproxy_port,
                    redir_port,
                    dns_port,
                    output,
                    reveal_secrets,
                )
                .await
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
                let out = build_diag_payload(paths, reveal_secrets).await?;
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
            ShareCommand::Inspect {
                file_pos,
                file,
                summary,
            } => {
                let target = file_pos
                    .or(file)
                    .context("please provide a .zip share bundle path")?;
                handle_share_inspect(as_json, &target, summary)
            }
            ShareCommand::Import(args) => handle_share_import(paths, as_json, args),
            ShareCommand::Send(args) => handle_share_send(paths, as_json, args).await,
            ShareCommand::Receive(args) => handle_share_receive(paths, as_json, args).await,
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
                        "skipped_version": &cfg.update.skipped_version,
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
                            "skipped_version": &cfg.update.skipped_version,
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
                            "skipped_version": &cfg.update.skipped_version,
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
                            "skipped_version": &cfg.update.skipped_version,
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
                    &format!(
                        "Staged verified update v{} (ready to apply on user confirmation/restart).",
                        parsed_manifest.version
                    ),
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

fn redact_connection_host_for_readonly(host: &str) -> String {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    // Preserve normal business target domains (e.g. `api.openai.com`, `github.com`),
    // while masking IPv4/IPv6 literals (with or without `:port` / `[IPv6]:port`).
    if trimmed.starts_with('[') && trimmed.contains(']') {
        return redact_ip_or_host(trimmed);
    }
    if trimmed.parse::<IpAddr>().is_ok() {
        return redact_ip_or_host(trimmed);
    }
    if trimmed.bytes().filter(|&b| b == b':').count() >= 3 {
        if let Some((addr, port)) = trimmed.rsplit_once(':') {
            if port.parse::<u16>().is_ok() && addr.parse::<IpAddr>().is_ok() {
                return redact_ip_or_host(trimmed);
            }
        }
    }
    if let Some((addr, port)) = trimmed.rsplit_once(':') {
        if !addr.contains(':') && port.parse::<u16>().is_ok() && addr.parse::<IpAddr>().is_ok() {
            return redact_ip_or_host(trimmed);
        }
    }
    sanitize_log_line(trimmed)
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
        host: redact_connection_host_for_readonly(&conn.host),
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

fn build_share_inspect_payload(file: &Path, summary: bool) -> Result<(Value, String)> {
    let preview = preview_share_bundle_zip_file(file)?;
    let warnings: Vec<String> = preview
        .warnings
        .iter()
        .map(|w| sanitize_log_line(w))
        .collect();
    let display_file = redact_path_for_display(&file.to_string_lossy());
    let group_count = preview
        .groups_bundle
        .as_ref()
        .map_or(0, |gb| gb.groups.len());

    if summary {
        let mut region_counts: HashMap<String, usize> = HashMap::new();
        let mut protocol_counts: HashMap<String, usize> = HashMap::new();
        for node in &preview.nodes {
            let region = {
                let trimmed = node.region_code.trim();
                if trimmed.is_empty() {
                    "UNKNOWN".to_string()
                } else {
                    trimmed.to_ascii_uppercase()
                }
            };
            *region_counts.entry(region).or_insert(0) += 1;
            let proto = {
                let trimmed = node.protocol.trim();
                if trimmed.is_empty() {
                    "unknown".to_string()
                } else {
                    trimmed.to_ascii_lowercase()
                }
            };
            *protocol_counts.entry(proto).or_insert(0) += 1;
        }

        let mut top_regions: Vec<(String, usize)> = region_counts.into_iter().collect();
        top_regions.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        top_regions.truncate(12);

        let mut protocols: Vec<(String, usize)> = protocol_counts.into_iter().collect();
        protocols.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        let sample_nodes: Vec<Value> = preview
            .nodes
            .iter()
            .take(5)
            .map(|n| {
                let safe = redact_node_for_readonly(n);
                json!({
                    "name": safe.name,
                    "protocol": safe.protocol,
                    "region_code": safe.region_code,
                    "server": safe.server,
                    "port": safe.port,
                    "multiplier": safe.multiplier,
                    "is_443_native": safe.is_443_native,
                })
            })
            .collect();
        let sample_relays: Vec<Value> = preview
            .relays
            .iter()
            .take(5)
            .map(|r| {
                let safe = redact_relay_for_readonly(r);
                json!({
                    "id": safe.id,
                    "name": safe.name,
                    "provider": safe.provider,
                    "region": safe.region,
                    "protocol": safe.protocol,
                    "server": safe.server,
                    "port": safe.port,
                    "enabled": safe.enabled,
                })
            })
            .collect();
        let group_summaries: Vec<Value> = preview
            .groups_bundle
            .as_ref()
            .map(|gb| {
                gb.groups
                    .iter()
                    .take(20)
                    .map(|g| {
                        json!({
                            "name": g.name,
                            "mode": g.mode,
                            "member_count": g.member_fingerprints.len(),
                            "has_dynamic_filter": g.dynamic_filter.is_some(),
                            "independent_routing": g.independent_routing,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let warnings_total = warnings.len();
        let truncated_warnings: Vec<String> = warnings.into_iter().take(20).collect();

        let out = json!({
            "ok": true,
            "sanitized": true,
            "summary_mode": true,
            "file": &display_file,
            "manifest": &preview.manifest,
            "has_readme": preview.has_readme,
            "node_count": preview.nodes.len(),
            "relay_count": preview.relays.len(),
            "group_count": group_count,
            "region_distribution": top_regions
                .iter()
                .map(|(region, count)| json!({ "region": region, "count": count }))
                .collect::<Vec<_>>(),
            "protocol_distribution": protocols
                .iter()
                .map(|(protocol, count)| json!({ "protocol": protocol, "count": count }))
                .collect::<Vec<_>>(),
            "sample_nodes": sample_nodes,
            "sample_relays": sample_relays,
            "groups": group_summaries,
            "warnings_total": warnings_total,
            "warnings": truncated_warnings,
        });
        let region_brief = top_regions
            .iter()
            .take(5)
            .map(|(r, c)| format!("{r}:{c}"))
            .collect::<Vec<_>>()
            .join(", ");
        let proto_brief = protocols
            .iter()
            .take(5)
            .map(|(p, c)| format!("{p}:{c}"))
            .collect::<Vec<_>>()
            .join(", ");
        let human = format!(
            "Share bundle summary `{}` ({}): {} node(s), {} relay(s), {} group(s) | top_regions=[{}] | protocols=[{}] (sanitized, <=5 samples).",
            preview.manifest.name,
            preview.manifest.schema,
            preview.nodes.len(),
            preview.relays.len(),
            group_count,
            region_brief,
            proto_brief,
        );
        return Ok((out, human));
    }

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
    let out = json!({
        "ok": true,
        "sanitized": true,
        "summary_mode": false,
        "file": &display_file,
        "manifest": &preview.manifest,
        "has_readme": preview.has_readme,
        "node_count": redacted_nodes.len(),
        "relay_count": redacted_relays.len(),
        "group_count": group_count,
        "nodes": redacted_nodes,
        "relays": redacted_relays,
        "groups_bundle": &preview.groups_bundle,
        "warnings": warnings,
    });
    let human = format!(
        "Inspected share bundle `{}` ({}): {} node(s), {} relay(s), {} group(s) (sanitized).",
        preview.manifest.name,
        preview.manifest.schema,
        preview.nodes.len(),
        preview.relays.len(),
        group_count,
    );
    Ok((out, human))
}

fn handle_share_inspect(as_json: bool, file: &Path, summary: bool) -> Result<()> {
    let (out, human) = build_share_inspect_payload(file, summary)?;
    emit_output(as_json, &out, &human)
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
        let would_import_groups = if args.no_nodes {
            0
        } else {
            preview
                .groups_bundle
                .as_ref()
                .map_or(0, |gb| gb.groups.len())
        };
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
            "would_import_groups": would_import_groups,
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

    let imported_groups_count = if !args.no_nodes {
        if let Some(ref gb) = preview.groups_bundle {
            let (count, group_warnings) = merge_imported_groups_into_storage(&db, gb)?;
            warnings.extend(
                group_warnings
                    .into_iter()
                    .map(|w| sanitize_multiline_text(&w)),
            );
            count
        } else {
            0
        }
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
        "imported_groups": imported_groups_count,
        "node_update": node_update_result,
        "warnings": warnings,
    });
    let human = format!(
        "Imported share bundle `{}`: {} node(s), {} relay(s), {} group(s).",
        preview.manifest.name, imported_nodes_count, imported_relays_count, imported_groups_count
    );
    Ok((out, human))
}

fn handle_share_import(paths: &AppPaths, as_json: bool, args: ShareImportArgs) -> Result<()> {
    let (out, human) = execute_share_import(paths, args)?;
    emit_output(as_json, &out, &human)
}

fn build_cli_sync_export_zip(
    paths: &AppPaths,
    args: &ShareSendArgs,
) -> Result<(Vec<u8>, catcloud_core::share_bundle::ShareBundleManifest, usize)> {
    let db = open_storage(paths)?;
    let explicit_node_ids = parse_csv_ids(args.node_ids.as_deref());
    let explicit_relay_ids = parse_csv_ids(args.relay_ids.as_deref());

    let selected_nodes: Vec<ProxyNode> = if args.all_nodes {
        db.list_nodes()?
    } else if let Some(ref sub_id) = args.sub_id {
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

    if selected_nodes.is_empty() && selected_relays.is_empty() {
        anyhow::bail!(
            "please select at least 1 node or relay via --all-nodes, --sub-id, --node-ids, --all-relays, or --relay-ids"
        );
    }

    let groups_bundle: Option<ShareGroupsBundle> = if args.no_groups {
        None
    } else {
        let all_groups = db.list_multi_groups()?;
        if all_groups.is_empty() {
            None
        } else {
            let cfg = config::load_or_default(paths).unwrap_or_default();
            let built = build_share_groups_bundle(
                &all_groups,
                &selected_nodes,
                cfg.active_group_id.as_deref(),
                Some(cfg.route_mode.as_str()),
            );
            if built.groups.is_empty() {
                None
            } else {
                Some(built)
            }
        }
    };
    let group_count = groups_bundle.as_ref().map_or(0, |g| g.groups.len());

    let req = ShareBundleExportRequest {
        name: args.name.clone(),
        description: args.description.clone(),
        nodes: selected_nodes,
        relays: selected_relays,
    };
    let (zip_bytes, manifest) =
        export_share_bundle_zip_bytes_with_groups(&req, groups_bundle.as_ref())?;
    Ok((zip_bytes, manifest, group_count))
}

fn write_sync_bytes_atomic(target_path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;

    if let Some(parent) = target_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let parent_dir = target_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let tmp_name = format!(
        ".catcloud-sync-{}-{}.tmp",
        std::process::id(),
        generate_session_id()?
    );
    let tmp_path = parent_dir.join(tmp_name);

    let write_res = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp_path)?;
        f.write_all(bytes)?;
        f.flush()?;
        let _ = f.sync_all();
        Ok(())
    })();
    if let Err(err) = write_res {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err.into());
    }

    if let Err(_err) = std::fs::rename(&tmp_path, target_path) {
        let _ = std::fs::remove_file(target_path);
        if let Err(err2) = std::fs::rename(&tmp_path, target_path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err2.into());
        }
    }
    Ok(())
}

fn parse_cli_ccsync_key(raw: &str) -> Result<([u8; KEY_LEN], Option<String>)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        anyhow::bail!("--key must not be empty");
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("catcloud://") || lower.starts_with("catcloud-sync://") {
        let parsed = parse_sync_uri(trimmed)?;
        if parsed.role != SyncRole::FileKey {
            anyhow::bail!(
                "expected role=file_key sync URI for --key, got role={}",
                parsed.role.as_str()
            );
        }
        return Ok((parsed.key, parsed.fingerprint));
    }
    let decoded = decode_base64_flex(trimmed)?;
    if decoded.len() != KEY_LEN {
        anyhow::bail!(
            "--key must decode to exactly {KEY_LEN} bytes, got {}",
            decoded.len()
        );
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&decoded);
    Ok((key, None))
}

fn open_cli_ccsync_file(
    path: &Path,
    key_input: Option<&str>,
    password_input: Option<&str>,
) -> Result<Vec<u8>> {
    let raw = read_file_with_limit(path, MAX_SYNC_ENVELOPE_BYTES, "ccsync envelope")?;
    let header = inspect_envelope_header(&raw)?;
    match header.kdf_mode {
        KDF_MODE_RAW_KEY => {
            let key_str = key_input
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .context("this .ccsync file requires --key (file_key URI or 32-byte Base64)")?;
            let (key, expected_fp) = parse_cli_ccsync_key(key_str)?;
            let zip_bytes = open_with_key(&raw, &key)?;
            if let Some(fp) = expected_fp {
                let actual_fp = plaintext_fingerprint(&zip_bytes);
                if actual_fp != fp {
                    anyhow::bail!(
                        "ccsync fingerprint mismatch (expected {fp}, got {actual_fp})"
                    );
                }
            }
            Ok(zip_bytes)
        }
        KDF_MODE_PBKDF2_SHA256 => {
            let pass = password_input
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .context("this .ccsync file is password-encrypted; pass --password")?;
            Ok(open_with_password(&raw, pass)?)
        }
        other => anyhow::bail!("unsupported .ccsync kdf_mode 0x{other:02x}"),
    }
}

fn execute_share_send_ccsync(
    paths: &AppPaths,
    args: &ShareSendArgs,
    output_path: &Path,
) -> Result<(Value, String)> {
    let (zip_bytes, manifest, group_count) = build_cli_sync_export_zip(paths, args)?;
    let fingerprint = plaintext_fingerprint(&zip_bytes);
    let key = generate_random_key()?;
    let envelope = seal_with_key(&zip_bytes, &key, "")?;
    write_sync_bytes_atomic(output_path, &envelope)?;

    let key_uri = format_sync_uri(&SyncUri {
        role: SyncRole::FileKey,
        endpoint: None,
        hosts: Vec::new(),
        port: None,
        sid: None,
        url: None,
        fingerprint: Some(fingerprint.clone()),
        key,
    })?;
    let display_output = redact_path_for_display(&output_path.to_string_lossy());
    let out = json!({
        "ok": true,
        "sanitized": true,
        "mode": "ccsync_file",
        "output": &display_output,
        "fingerprint": &fingerprint,
        "key_uri": &key_uri,
        "payload_bytes": envelope.len(),
        "node_count": manifest.node_count,
        "relay_count": manifest.relay_count,
        "group_count": group_count,
        "manifest": &manifest,
    });
    let mut human = format!(
        "Exported encrypted .ccsync bundle `{}` to {} ({} node(s), {} relay(s), {} group(s), {} bytes, fp={}).\nKey URI: {}",
        manifest.name,
        display_output,
        manifest.node_count,
        manifest.relay_count,
        group_count,
        envelope.len(),
        fingerprint,
        key_uri,
    );
    if !args.no_qr {
        if let Ok(qr_ascii) = render_qr_terminal(&key_uri) {
            human.push('\n');
            human.push_str(&qr_ascii);
        }
    }
    Ok((out, human))
}

async fn handle_share_send(paths: &AppPaths, as_json: bool, args: ShareSendArgs) -> Result<()> {
    if let Some(ref output_path) = args.ccsync_output {
        let (out, human) = execute_share_send_ccsync(paths, &args, output_path)?;
        return emit_output(as_json, &out, &human);
    }

    let (zip_bytes, manifest, group_count) = build_cli_sync_export_zip(paths, &args)?;
    let fingerprint = plaintext_fingerprint(&zip_bytes);
    let payload_bytes = zip_bytes.len();

    if let Some(ref push_uri) = args.push_uri {
        push_sync_bundle_via_uri(push_uri, &zip_bytes).await?;
        let out = json!({
            "ok": true,
            "sanitized": true,
            "mode": "lan_push_uri",
            "fingerprint": &fingerprint,
            "payload_bytes": payload_bytes,
            "node_count": manifest.node_count,
            "relay_count": manifest.relay_count,
            "group_count": group_count,
        });
        let human = format!(
            "Pushed encrypted sync bundle `{}` ({} node(s), {} relay(s), {} group(s), fp={}).",
            manifest.name, manifest.node_count, manifest.relay_count, group_count, fingerprint
        );
        return emit_output(as_json, &out, &human);
    }

    if let Some(ref push_addr) = args.push_addr {
        let pin = args
            .pin
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .context("--push-addr requires --pin <6-digit-code>")?;
        push_sync_bundle_via_pin(push_addr, pin, &zip_bytes).await?;
        let out = json!({
            "ok": true,
            "sanitized": true,
            "mode": "lan_push_pin",
            "fingerprint": &fingerprint,
            "payload_bytes": payload_bytes,
            "node_count": manifest.node_count,
            "relay_count": manifest.relay_count,
            "group_count": group_count,
        });
        let human = format!(
            "Pushed encrypted sync bundle `{}` via PIN ({} node(s), {} relay(s), {} group(s), fp={}).",
            manifest.name, manifest.node_count, manifest.relay_count, group_count, fingerprint
        );
        return emit_output(as_json, &out, &human);
    }

    let opts = LanSyncServerOptions {
        bind_host: args.bind.clone(),
        bind_port: args.port,
        custom_endpoint: args.endpoint.clone().filter(|s| !s.trim().is_empty()),
        ttl_secs: args.ttl.clamp(30, 900),
        allow_multiple: args.allow_multiple,
    };
    let mut server = LanSyncSendServer::start(zip_bytes, opts).await?;
    let info = server.info().clone();
    let lan_urls: Vec<String> = info
        .hosts
        .iter()
        .map(|h| format!("http://{h}:{}", info.port))
        .collect();

    if as_json {
        let out = json!({
            "ok": true,
            "sanitized": true,
            "mode": "lan_send_server",
            "session_id": &info.sid,
            "pin_code": &info.pin,
            "port": info.port,
            "lan_urls": &lan_urls,
            "custom_endpoint": &info.custom_endpoint,
            "fingerprint": &info.fingerprint,
            "qr_uri": &info.uri,
            "expires_at_unix": info.expires_at_unix,
            "allow_multiple": info.allow_multiple,
            "payload_bytes": payload_bytes,
            "node_count": manifest.node_count,
            "relay_count": manifest.relay_count,
            "group_count": group_count,
        });
        use std::io::Write as _;
        println!("{}", serde_json::to_string_pretty(&out)?);
        let _ = std::io::stdout().flush();
    } else {
        println!(
            "LAN sync sender ready for `{}` ({} node(s), {} relay(s), {} group(s), fp={}).",
            manifest.name, manifest.node_count, manifest.relay_count, group_count, info.fingerprint
        );
        println!("PIN: {} | URLs: {}", info.pin, lan_urls.join(", "));
        if let Some(ref ep) = info.custom_endpoint {
            println!("Endpoint: {ep}");
        }
        println!("URI: {}", info.uri);
        if !args.no_qr {
            if let Ok(qr_ascii) = render_qr_terminal(&info.uri) {
                println!("{qr_ascii}");
            }
        }
        println!("Waiting for receiver (press Ctrl+C to cancel)...");
    }

    while server.is_running() {
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    server.cancel().await;
    Ok(())
}

fn execute_share_receive_from_zip_bytes(
    paths: &AppPaths,
    args: &ShareReceiveArgs,
    zip_bytes: &[u8],
    source_label: &str,
) -> Result<(Value, String)> {
    if args.dry_run && args.apply {
        anyhow::bail!("--dry-run and --apply cannot be specified together");
    }
    let update_mode = parse_subscription_update_mode(&args.mode)?;
    let effective_dry_run = args.dry_run || !args.apply;

    let fingerprint = plaintext_fingerprint(zip_bytes);
    let preview: ShareBundlePreview = preview_share_bundle_zip_bytes(zip_bytes)?;
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
    let mut warnings: Vec<String> = preview
        .warnings
        .iter()
        .map(|w| sanitize_log_line(w))
        .collect();
    let group_names: Vec<String> = if args.no_groups || args.no_nodes {
        Vec::new()
    } else {
        preview
            .groups_bundle
            .as_ref()
            .map(|gb| gb.groups.iter().map(|g| g.name.clone()).collect())
            .unwrap_or_default()
    };

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
            "source": source_label,
            "fingerprint": &fingerprint,
            "manifest": &preview.manifest,
            "target_sub": &args.target_sub,
            "mode": update_mode,
            "would_import_nodes": redacted_nodes.len(),
            "would_import_relays": redacted_relays.len(),
            "would_import_groups": group_names.len(),
            "group_names": &group_names,
            "nodes": redacted_nodes,
            "relays": redacted_relays,
            "warnings": warnings,
        });
        let human = format!(
            "Sync receive dry-run preview `{}` (fp={}): {} node(s), {} relay(s), {} group(s) ready to import (pass --apply to persist).",
            preview.manifest.name,
            fingerprint,
            selected_nodes.len(),
            selected_relays.len(),
            group_names.len(),
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
            let new_sub_id = generate_migration_subscription_id().replacen("migrated-", "sync-", 1);
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
                url_or_cmd: source_label.to_string(),
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

    let imported_groups_count = if !args.no_groups && !args.no_nodes {
        if let Some(ref gb) = preview.groups_bundle {
            let (count, group_warnings) = merge_imported_groups_into_storage(&db, gb)?;
            warnings.extend(
                group_warnings
                    .into_iter()
                    .map(|w| sanitize_multiline_text(&w)),
            );
            count
        } else {
            0
        }
    } else {
        0
    };

    let out = json!({
        "ok": true,
        "sanitized": true,
        "dry_run": false,
        "applied": true,
        "source": source_label,
        "fingerprint": &fingerprint,
        "manifest": &preview.manifest,
        "subscription_id": &imported_sub_id,
        "mode": update_mode,
        "imported_nodes": imported_nodes_count,
        "target_sub_total_nodes": target_sub_total_nodes,
        "imported_relays": imported_relays_count,
        "imported_groups": imported_groups_count,
        "node_update": node_update_result,
        "warnings": warnings,
    });
    let human = format!(
        "Imported sync bundle `{}` (fp={}): {} node(s), {} relay(s), {} group(s).",
        preview.manifest.name,
        fingerprint,
        imported_nodes_count,
        imported_relays_count,
        imported_groups_count
    );
    Ok((out, human))
}

async fn handle_share_receive(
    paths: &AppPaths,
    as_json: bool,
    args: ShareReceiveArgs,
) -> Result<()> {
    if args.dry_run && args.apply {
        anyhow::bail!("--dry-run and --apply cannot be specified together");
    }

    let (zip_bytes, source_label) = if let Some(ref ccsync_path) = args.ccsync {
        let bytes = open_cli_ccsync_file(
            ccsync_path,
            args.key.as_deref(),
            args.password.as_deref(),
        )?;
        let label = redact_path_for_display(&ccsync_path.to_string_lossy());
        (bytes, label)
    } else if args.listen {
        let opts = LanSyncServerOptions {
            bind_host: args.bind.clone(),
            bind_port: args.port,
            custom_endpoint: args.endpoint.clone().filter(|s| !s.trim().is_empty()),
            ttl_secs: args.ttl.clamp(30, 900),
            allow_multiple: false,
        };
        let mut server = LanSyncReceiveServer::start(opts).await?;
        let info = server.info().clone();
        let lan_urls: Vec<String> = info
            .hosts
            .iter()
            .map(|h| format!("http://{h}:{}", info.port))
            .collect();

        // Emit listener details to stderr in --json mode so stdout remains a single valid JSON document.
        if as_json {
            eprintln!(
                "{}",
                serde_json::to_string(&json!({
                    "event": "listening",
                    "session_id": &info.sid,
                    "pin_code": &info.pin,
                    "port": info.port,
                    "lan_urls": &lan_urls,
                    "custom_endpoint": &info.custom_endpoint,
                    "qr_uri": &info.uri,
                    "expires_at_unix": info.expires_at_unix,
                }))?
            );
        } else {
            println!("LAN sync receiver listening on {}", lan_urls.join(", "));
            println!("PIN: {}", info.pin);
            if let Some(ref ep) = info.custom_endpoint {
                println!("Endpoint: {ep}");
            }
            println!("URI: {}", info.uri);
            if !args.no_qr {
                if let Ok(qr_ascii) = render_qr_terminal(&info.uri) {
                    println!("{qr_ascii}");
                }
            }
            println!("Waiting for sender push (press Ctrl+C to cancel)...");
        }

        let received = server.recv_bundle().await;
        let close_reason = server.close_reason();
        server.cancel().await;
        let bundle = match received {
            Some(b) => b,
            None => {
                let reason_msg = match close_reason.as_deref() {
                    Some("expired") => "receiver timed out before receiving a sync bundle",
                    Some("destroyed") => {
                        "receiver self-destructed after too many failed authentication attempts"
                    }
                    _ => "receiver closed before receiving a sync bundle",
                };
                anyhow::bail!("{reason_msg}");
            }
        };
        (bundle.zip_bytes, "sync://listen".to_string())
    } else if let Some(ref addr) = args.addr {
        let pin = args
            .pin
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .context("--addr requires --pin <6-digit-code>")?;
        let bytes = fetch_sync_bundle_via_pin(addr, pin).await?;
        (bytes, "sync://pin".to_string())
    } else if let Some(raw_source) = args.uri.as_deref().or(args.source.as_deref()) {
        let trimmed = raw_source.trim();
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("catcloud://") || lower.starts_with("catcloud-sync://") {
            let parsed = parse_sync_uri(trimmed)?;
            match parsed.role {
                SyncRole::Pull => (fetch_sync_bundle_via_uri(trimmed).await?, "sync://pull".to_string()),
                SyncRole::RelayUrl => (fetch_relay_url_bundle(trimmed).await?, "sync://relay_url".to_string()),
                SyncRole::Push => {
                    anyhow::bail!("received role=push URI; use `catcloud share send --push-uri` on the sender instead");
                }
                SyncRole::FileKey => {
                    anyhow::bail!("received role=file_key URI; pass `--ccsync <FILE> --key <URI>` instead");
                }
            }
        } else if let Some(pin) = args.pin.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            let bytes = fetch_sync_bundle_via_pin(trimmed, pin).await?;
            (bytes, "sync://pin".to_string())
        } else {
            anyhow::bail!(
                "source `{}` is not a catcloud://sync/v1 URI; pass --pin for LAN address or --ccsync for encrypted files",
                sanitize_log_line(trimmed)
            );
        }
    } else {
        anyhow::bail!(
            "please specify a sync source: <URI>, --uri, --addr + --pin, --ccsync + --key/--password, or --listen"
        );
    };

    let (out, human) = execute_share_receive_from_zip_bytes(paths, &args, &zip_bytes, &source_label)?;
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
    relay_supports_ipv6: bool,
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

    let is_ipv6_incompatible = |n: &ProxyNode| -> bool {
        !relay_supports_ipv6 && is_ipv6_only_node(n) && n.preaccel_override != Some(true)
    };

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
        if home.enabled && !home.is_udp_only_transport() && !is_ipv6_incompatible(home) {
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
        .filter(|n| n.enabled && !n.is_udp_only_transport() && !is_ipv6_incompatible(n))
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
                Some(home) if is_ipv6_incompatible(home) => Some(format!(
                    "homepage node `{}` is IPv6-only while domestic relay does not support IPv6; auto-selected `{}` as reference node",
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
            Some(if !relay_supports_ipv6
                && nodes
                    .iter()
                    .any(|n| n.enabled && !n.is_udp_only_transport() && is_ipv6_incompatible(n))
            {
                "no enabled non-UDP IPv4/dual-stack overseas node available for IPv4-only relay; running single-hop direct relay speed test"
                    .to_string()
            } else {
                "no enabled non-UDP overseas node available; running single-hop direct relay speed test"
                    .to_string()
            }),
        )),
    }
}

struct PreAccelRelaySpeedOutcome {
    ok: bool,
    /// Overseas two-hop chain latency measured via `cp.cloudflare.com/generate_204`.
    /// Must NEVER overwrite domestic direct `last_probe_ms`.
    chain_latency_ms: Option<f64>,
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
    let measured_chain_latency: Arc<std::sync::Mutex<Option<f64>>> =
        Arc::new(std::sync::Mutex::new(None));
    let measured_up: Arc<std::sync::Mutex<Option<f64>>> = Arc::new(std::sync::Mutex::new(None));
    let measured_down: Arc<std::sync::Mutex<Option<f64>>> = Arc::new(std::sync::Mutex::new(None));
    let lat_ref = Arc::clone(&measured_chain_latency);
    let up_ref = Arc::clone(&measured_up);
    let down_ref = Arc::clone(&measured_down);
    let relay_id_owned = relay_id.to_string();

    let speed_fut = async move {
        let client = match build_isolated_http_client(proxy_port, Duration::from_secs(12)) {
            Ok(c) => c,
            Err(err) => {
                return PreAccelRelaySpeedOutcome {
                    ok: false,
                    chain_latency_ms: None,
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
            name: "PreAccel Relay Chain Latency".to_string(),
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
                    chain_latency_ms: None,
                    up_mbps: None,
                    down_mbps: None,
                    error: Some("chain connectivity probe timed out (6s)".to_string()),
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
                chain_latency_ms: lat_rec.latency_ms,
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
            chain_latency_ms: lat_rec.latency_ms,
            up_mbps,
            down_mbps,
            error,
        }
    };

    match tokio::time::timeout(Duration::from_secs(45), speed_fut).await {
        Ok(outcome) => outcome,
        Err(_) => {
            let preserved_lat = measured_chain_latency.lock().ok().and_then(|g| *g);
            let preserved_up = measured_up.lock().ok().and_then(|g| *g);
            let preserved_down = measured_down.lock().ok().and_then(|g| *g);
            PreAccelRelaySpeedOutcome {
                ok: preserved_up.is_some() || preserved_down.is_some(),
                chain_latency_ms: preserved_lat,
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

fn parse_log_time_bound(raw: &str, now_local: DateTime<Local>) -> Result<DateTime<Utc>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        anyhow::bail!("time filter cannot be empty");
    }

    // 1. RFC3339 (e.g. `2026-11-26T03:44:51+08:00` or `2026-11-26T03:44:51Z`)
    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return Ok(dt.with_timezone(&Utc));
    }

    // 2. Relative window (e.g. `30m`, `2h`, `45s`, `1d`, optionally prefixed with `-`)
    let rel = trimmed.strip_prefix('-').unwrap_or(trimmed).trim();
    let digit_end = rel
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rel.len());
    if digit_end > 0 && digit_end < rel.len() {
        if let Ok(amount) = rel[..digit_end].parse::<i64>() {
            let unit = rel[digit_end..].trim().to_ascii_lowercase();
            let secs = match unit.as_str() {
                "s" | "sec" | "secs" => Some(amount),
                "m" | "min" | "mins" => amount.checked_mul(60),
                "h" | "hr" | "hrs" => amount.checked_mul(3600),
                "d" | "day" | "days" => amount.checked_mul(86400),
                _ => None,
            };
            if let Some(delta_secs) = secs {
                return Ok(now_local.with_timezone(&Utc) - chrono::Duration::seconds(delta_secs));
            }
        }
    }

    // 3. Local datetime `YYYY-MM-DD HH:MM(:SS)` or `YYYY-MM-DDTHH:MM(:SS)`
    for fmt in [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M",
    ] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(trimmed, fmt) {
            if let Some(local_dt) = Local.from_local_datetime(&naive).earliest() {
                return Ok(local_dt.with_timezone(&Utc));
            }
            return Ok(Utc.from_utc_datetime(&naive));
        }
    }

    // 4. Local today `HH:MM(:SS)`
    for fmt in ["%H:%M:%S", "%H:%M"] {
        if let Ok(naive_time) = NaiveTime::parse_from_str(trimmed, fmt) {
            let naive = now_local.date_naive().and_time(naive_time);
            if let Some(local_dt) = Local.from_local_datetime(&naive).earliest() {
                return Ok(local_dt.with_timezone(&Utc));
            }
            return Ok(Utc.from_utc_datetime(&naive));
        }
    }

    anyhow::bail!(
        "unsupported time format `{trimmed}` (use RFC3339, YYYY-MM-DD HH:MM[:SS], HH:MM, or relative like 30m / 2h)"
    )
}

fn is_iso_datetime_prefix(slice: &[u8]) -> bool {
    slice.len() == 19
        && slice[0].is_ascii_digit()
        && slice[1].is_ascii_digit()
        && slice[2].is_ascii_digit()
        && slice[3].is_ascii_digit()
        && slice[4] == b'-'
        && slice[5].is_ascii_digit()
        && slice[6].is_ascii_digit()
        && slice[7] == b'-'
        && slice[8].is_ascii_digit()
        && slice[9].is_ascii_digit()
        && matches!(slice[10], b'T' | b't' | b' ')
        && slice[11].is_ascii_digit()
        && slice[12].is_ascii_digit()
        && slice[13] == b':'
        && slice[14].is_ascii_digit()
        && slice[15].is_ascii_digit()
        && slice[16] == b':'
        && slice[17].is_ascii_digit()
        && slice[18].is_ascii_digit()
}

fn extract_log_line_timestamp_utc(line: &str) -> Option<DateTime<Utc>> {
    // 1. Mihomo logfmt `time="..."`
    if let Some(pos) = line.find("time=\"") {
        let rest = &line[pos + 6..];
        if let Some(end) = rest.find('"') {
            let cand = rest[..end].trim();
            if let Ok(dt) = DateTime::parse_from_rfc3339(cand) {
                return Some(dt.with_timezone(&Utc));
            }
            if let Ok(naive) = NaiveDateTime::parse_from_str(cand, "%Y-%m-%d %H:%M:%S") {
                return Local
                    .from_local_datetime(&naive)
                    .earliest()
                    .map(|d| d.with_timezone(&Utc))
                    .or_else(|| Some(Utc.from_utc_datetime(&naive)));
            }
        }
    }

    // 2. Embedded or leading ISO/RFC3339 or `YYYY-MM-DD HH:MM:SS`
    let bytes = line.as_bytes();
    if bytes.len() >= 19 {
        let scan_limit = (bytes.len() - 19).min(64);
        for i in 0..=scan_limit {
            if is_iso_datetime_prefix(&bytes[i..i + 19]) {
                let mut end = i + 19;
                if end < bytes.len() && bytes[end] == b'.' {
                    end += 1;
                    while end < bytes.len() && bytes[end].is_ascii_digit() {
                        end += 1;
                    }
                }
                let mut has_tz = false;
                if end < bytes.len() && matches!(bytes[end], b'Z' | b'z') {
                    end += 1;
                    has_tz = true;
                } else if end + 6 <= bytes.len()
                    && matches!(bytes[end], b'+' | b'-')
                    && bytes[end + 1].is_ascii_digit()
                    && bytes[end + 2].is_ascii_digit()
                    && bytes[end + 3] == b':'
                    && bytes[end + 4].is_ascii_digit()
                    && bytes[end + 5].is_ascii_digit()
                {
                    end += 6;
                    has_tz = true;
                }
                let token = &line[i..end];
                if has_tz {
                    if let Ok(dt) = DateTime::parse_from_rfc3339(token) {
                        return Some(dt.with_timezone(&Utc));
                    }
                    let normalized = token.replacen(' ', "T", 1);
                    if let Ok(dt) = DateTime::parse_from_rfc3339(&normalized) {
                        return Some(dt.with_timezone(&Utc));
                    }
                }
                let base_19 = &line[i..i + 19];
                for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"] {
                    if let Ok(naive) = NaiveDateTime::parse_from_str(base_19, fmt) {
                        return Local
                            .from_local_datetime(&naive)
                            .earliest()
                            .map(|d| d.with_timezone(&Utc))
                            .or_else(|| Some(Utc.from_utc_datetime(&naive)));
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
fn build_logs_tail_payload(
    paths: &AppPaths,
    requested_lines: usize,
    level_raw: &str,
) -> Result<(Value, String)> {
    build_logs_tail_payload_with_options(
        paths,
        requested_lines,
        level_raw,
        None,
        None,
        false,
        Local::now(),
    )
}

fn build_logs_tail_payload_with_options(
    paths: &AppPaths,
    requested_lines: usize,
    level_raw: &str,
    since_raw: Option<&str>,
    until_raw: Option<&str>,
    reveal_secrets: bool,
    now_local: DateTime<Local>,
) -> Result<(Value, String)> {
    let filter = parse_log_level_filter(level_raw)?;
    let since_utc = since_raw
        .map(|s| parse_log_time_bound(s, now_local))
        .transpose()?;
    let until_utc = until_raw
        .map(|s| parse_log_time_bound(s, now_local))
        .transpose()?;
    if let (Some(s), Some(u)) = (since_utc, until_utc) {
        if s > u {
            anyhow::bail!("--since time cannot be later than --until time");
        }
    }
    let has_time_filter = since_utc.is_some() || until_utc.is_some();

    let capped = requested_lines.min(MAX_LOG_TAIL_LINES_CAP);
    let archive2_path = paths.logs_dir.join("catcloud.log.2");
    let archive1_path = paths.logs_dir.join("catcloud.log.1");
    let primary_path = paths.logs_dir.join("catcloud.log");

    let mut sources: Vec<String> = Vec::new();
    let mut combined: Vec<String> = Vec::new();
    for (label, candidate) in [
        ("catcloud.log.2", &archive2_path),
        ("catcloud.log.1", &archive1_path),
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

    let mut matched: Vec<String> = Vec::new();
    let mut last_ts_matched = false;
    for line in combined {
        if has_time_filter {
            let in_window = match extract_log_line_timestamp_utc(&line) {
                Some(ts) => {
                    let ok = since_utc.map_or(true, |s| ts >= s)
                        && until_utc.map_or(true, |u| ts <= u);
                    last_ts_matched = ok;
                    ok
                }
                None => last_ts_matched,
            };
            if !in_window {
                continue;
            }
        }
        if line_matches_log_level(&line, filter) {
            matched.push(line);
        }
    }

    if matched.len() > capped {
        let drop_count = matched.len() - capped;
        matched.drain(0..drop_count);
    }
    let final_lines: Vec<String> = if reveal_secrets {
        matched
    } else {
        matched.iter().map(|l| sanitize_log_line(l)).collect()
    };

    let mut out = json!({
        "ok": true,
        "sanitized": !reveal_secrets,
        "level": filter.as_str(),
        "since": since_raw,
        "until": until_raw,
        "since_utc": since_utc.map(|d| d.to_rfc3339()),
        "until_utc": until_utc.map(|d| d.to_rfc3339()),
        "requested_lines": capped,
        "count": final_lines.len(),
        "sources": sources,
        "lines": &final_lines,
    });
    if !reveal_secrets {
        sanitize_json_value(&mut out);
    }
    let human = if final_lines.is_empty() {
        format!(
            "No matching log lines (level={}, sources={:?}).",
            filter.as_str(),
            out["sources"]
        )
    } else {
        final_lines.join("\n")
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

fn classify_and_format_connections(
    conns: &[ActiveConnection],
    limit: usize,
    reveal_secrets: bool,
) -> (
    Vec<ActiveConnection>,
    Vec<ActiveConnection>,
    Vec<ActiveConnection>,
    usize,
    usize,
) {
    let mut app_all: Vec<ActiveConnection> = Vec::new();
    let mut internal_all: Vec<ActiveConnection> = Vec::new();
    let mut all_formatted: Vec<ActiveConnection> = Vec::with_capacity(conns.len().min(limit));

    for conn in conns {
        let formatted = if reveal_secrets {
            conn.clone()
        } else {
            redact_connection_for_readonly(conn)
        };
        if all_formatted.len() < limit {
            all_formatted.push(formatted.clone());
        }
        if is_internal_or_preaccel_connection(
            &conn.conn_type,
            &conn.chains,
            &conn.host,
            &conn.rule,
        ) {
            internal_all.push(formatted);
        } else {
            app_all.push(formatted);
        }
    }

    let app_count = app_all.len();
    let internal_count = internal_all.len();
    app_all.truncate(limit);
    internal_all.truncate(limit);
    (all_formatted, app_all, internal_all, app_count, internal_count)
}

async fn build_net_connections_payload(
    paths: &AppPaths,
    limit: usize,
    reveal_secrets: bool,
) -> Result<(Value, String)> {
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
            let (connections, app_connections, internal_connections, app_count, internal_count) =
                classify_and_format_connections(&snapshot.connections, limit, reveal_secrets);
            let mut out = json!({
                "ok": true,
                "sanitized": !reveal_secrets,
                "core_running": true,
                "auth_error": false,
                "controller_addr": controller_addr,
                "download_total": snapshot.download_total,
                "upload_total": snapshot.upload_total,
                "memory": snapshot.memory,
                "total_connections": total,
                "returned_connections": connections.len(),
                "app_count": app_count,
                "internal_count": internal_count,
                "app_connections": app_connections,
                "internal_connections": internal_connections,
                "connections": connections,
            });
            if !reveal_secrets {
                sanitize_json_value(&mut out);
            }
            let human = format!(
                "Active connections: showing {}/{total} (app={}, internal={}, sanitized={}, core_running=true).",
                out["returned_connections"],
                app_count,
                internal_count,
                !reveal_secrets
            );
            Ok((out, human))
        }
        Ok(Err(CatError::Core(msg))) if msg.contains("HTTP 401") || msg.contains("HTTP 403") => {
            let clean = sanitize_log_line(&msg);
            let mut out = json!({
                "ok": true,
                "sanitized": !reveal_secrets,
                "core_running": true,
                "auth_error": true,
                "controller_addr": controller_addr,
                "download_total": 0u64,
                "upload_total": 0u64,
                "memory": 0u64,
                "total_connections": 0usize,
                "returned_connections": 0usize,
                "app_count": 0usize,
                "internal_count": 0usize,
                "app_connections": [],
                "internal_connections": [],
                "connections": [],
                "note": format!("Controller reachable but authentication failed ({clean})."),
            });
            if !reveal_secrets {
                sanitize_json_value(&mut out);
            }
            Ok((
                out,
                "Core controller reachable, but authentication failed; returning 0 connections."
                    .to_string(),
            ))
        }
        _ => {
            let mut out = json!({
                "ok": true,
                "sanitized": !reveal_secrets,
                "core_running": false,
                "auth_error": false,
                "controller_addr": controller_addr,
                "download_total": 0u64,
                "upload_total": 0u64,
                "memory": 0u64,
                "total_connections": 0usize,
                "returned_connections": 0usize,
                "app_count": 0usize,
                "internal_count": 0usize,
                "app_connections": [],
                "internal_connections": [],
                "connections": [],
                "note": "Mihomo core controller is not currently running or reachable.",
            });
            if !reveal_secrets {
                sanitize_json_value(&mut out);
            }
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

/// Evaluate effective TUN status for `net doctor` / `status` / `config diag`.
///
/// Precedence:
/// 1. Live `Tun` inbound connections prove TUN is actively handling traffic.
/// 2. Authoritative `GET /configs` (`live_tun_enable == Some(true | false)`) overrides optimistic
///    inference so an unprivileged running core with `tun.enable == false` NEVER misreports
///    `tun_enabled = true` via `live_core_with_tun_config`.
/// 3. Only when `live_tun_enable` is unavailable (`None`) do we fall back to inferring from
///    `core_running` / process privileges.
fn evaluate_doctor_tun_state(
    tun_configured: bool,
    tun_privilege_ready: bool,
    core_running: bool,
    has_live_tun_connections: bool,
    live_tun_enable: Option<bool>,
) -> (bool, bool, &'static str) {
    if has_live_tun_connections {
        return (true, false, "live_tun_connections");
    }
    if core_running && live_tun_enable == Some(true) {
        return (true, false, "live_core_configs");
    }
    if core_running && live_tun_enable == Some(false) {
        if !tun_configured {
            return (false, false, "disabled");
        }
        if !tun_privilege_ready {
            return (false, true, "live_core_tun_disabled_needs_elevation");
        }
        return (false, false, "live_core_tun_disabled");
    }
    if !tun_configured {
        return (false, false, "disabled");
    }
    if core_running {
        return (true, false, "live_core_with_tun_config");
    }
    if tun_privilege_ready {
        return (true, false, "process_privilege");
    }
    (false, true, "privilege_required")
}

async fn probe_live_tun_connections(ep: &ResolvedControllerEndpoint) -> bool {
    let Ok(job_guard) = JobGuard::new() else {
        return false;
    };
    let Ok(adapter) = MihomoAdapter::with_controller_endpoint(
        Arc::new(job_guard),
        &ep.host,
        ep.port,
        ep.secret.clone(),
    ) else {
        return false;
    };
    match tokio::time::timeout(Duration::from_millis(1500), adapter.list_connections()).await {
        Ok(Ok(snapshot)) => snapshot.connections.iter().any(|conn| {
            let ct = conn.conn_type.trim().to_ascii_lowercase();
            ct == "tun" || ct.contains("tun")
        }),
        _ => false,
    }
}

const MANAGED_PID_START_TIME_TOLERANCE_SECS: u64 = 2;

fn execute_group_create(paths: &AppPaths, args: GroupCreateArgs) -> Result<(Value, String)> {
    let db = open_storage(paths)?;
    let existing = db.get_multi_group(&args.id)?;
    let created = existing.is_none();

    let group = if let Some(mut existing_group) = existing {
        if let Some(name) = args.name {
            let trimmed = name.trim();
            if !trimmed.is_empty() {
                existing_group.name = trimmed.to_string();
            }
        }
        if let Some(mode_raw) = args.mode {
            existing_group.mode = parse_group_mode(&mode_raw)?;
        }
        if let Some(formula) = args.formula {
            validate_formula(&formula)?;
            existing_group.formula_expr = formula;
        }
        if let Some(fb_raw) = args.fallback {
            existing_group.fallback_policy = parse_fallback_policy(&fb_raw)?;
        }
        if let Some(sw_raw) = args.switch_mode {
            existing_group.switch_mode = parse_switch_mode(&sw_raw)?;
        }
        if let Some(nodes_csv) = args.nodes {
            existing_group.member_node_ids = parse_csv_ids(Some(&nodes_csv));
            if let Some(ref active) = existing_group.active_node_id {
                if !existing_group.member_node_ids.iter().any(|id| id == active) {
                    existing_group.active_node_id = None;
                }
            }
        }
        existing_group
    } else {
        let name = args
            .name
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| args.id.clone());
        let mode = match args.mode {
            Some(ref m) => parse_group_mode(m)?,
            None => MultiGroupMode::StickyBest,
        };
        let formula = args
            .formula
            .unwrap_or_else(|| DEFAULT_COST_EFFECTIVE_FORMULA.to_string());
        validate_formula(&formula)?;
        let fallback_policy = match args.fallback {
            Some(ref fb) => parse_fallback_policy(fb)?,
            None => FallbackPolicy::DegradeBestWarn,
        };
        let switch_mode = match args.switch_mode {
            Some(ref sw) => parse_switch_mode(sw)?,
            None => SwitchMode::ForceCloseOld,
        };
        let member_node_ids = parse_csv_ids(args.nodes.as_deref());
        MultiGroup {
            id: args.id.clone(),
            name,
            mode,
            member_node_ids,
            formula_expr: formula,
            fallback_policy,
            switch_mode,
            ..MultiGroup::default()
        }
    };

    db.upsert_multi_group(&group)?;
    let out = json!({
        "ok": true,
        "created": created,
        "updated": !created,
        "group": group,
    });
    let verb = if created { "Created" } else { "Updated" };
    Ok((out, format!("{verb} multi-group `{}`.", args.id)))
}

fn execute_group_members(paths: &AppPaths, args: GroupMembersArgs) -> Result<(Value, String)> {
    let db = open_storage(paths)?;
    let mut group = db
        .get_multi_group(&args.id)?
        .with_context(|| format!("multi-group `{}` not found", args.id))?;
    let action_norm = args.action.trim().to_ascii_lowercase();
    let target_ids = parse_csv_ids(Some(&args.nodes));

    let mut added: Vec<String> = Vec::new();
    let mut removed: Vec<String> = Vec::new();

    match action_norm.as_str() {
        "add" => {
            if target_ids.is_empty() {
                anyhow::bail!("--nodes must specify at least one node ID for `add`");
            }
            let mut existing_set: HashSet<String> =
                group.member_node_ids.iter().cloned().collect();
            for nid in target_ids {
                if existing_set.insert(nid.clone()) {
                    group.member_node_ids.push(nid.clone());
                    added.push(nid);
                }
            }
        }
        "remove" => {
            if target_ids.is_empty() {
                anyhow::bail!("--nodes must specify at least one node ID for `remove`");
            }
            let remove_set: HashSet<String> = target_ids.into_iter().collect();
            let mut kept = Vec::with_capacity(group.member_node_ids.len());
            for nid in group.member_node_ids.drain(..) {
                if remove_set.contains(&nid) {
                    removed.push(nid);
                } else {
                    kept.push(nid);
                }
            }
            group.member_node_ids = kept;
        }
        "set" => {
            let old_set: HashSet<String> = group.member_node_ids.iter().cloned().collect();
            let new_set: HashSet<String> = target_ids.iter().cloned().collect();
            for nid in &target_ids {
                if !old_set.contains(nid) {
                    added.push(nid.clone());
                }
            }
            for nid in &group.member_node_ids {
                if !new_set.contains(nid) {
                    removed.push(nid.clone());
                }
            }
            group.member_node_ids = target_ids;
        }
        other => anyhow::bail!("unsupported members action `{other}` (use add|remove|set)"),
    }

    if let Some(ref active) = group.active_node_id {
        if !group.member_node_ids.iter().any(|id| id == active) {
            group.active_node_id = None;
        }
    }

    db.upsert_multi_group(&group)?;
    let out = json!({
        "ok": true,
        "group_id": &group.id,
        "action": action_norm,
        "added": added,
        "removed": removed,
        "member_count": group.member_node_ids.len(),
        "active_node_id": &group.active_node_id,
        "member_node_ids": &group.member_node_ids,
    });
    let human = format!(
        "Updated members of group `{}` (action={}, added={}, removed={}, member_count={}).",
        group.id,
        action_norm,
        out["added"].as_array().map(|a| a.len()).unwrap_or(0),
        out["removed"].as_array().map(|a| a.len()).unwrap_or(0),
        group.member_node_ids.len()
    );
    Ok((out, human))
}

fn execute_group_policy(paths: &AppPaths, args: GroupPolicyArgs) -> Result<(Value, String)> {
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
    if args.clear_match_rules {
        group.match_rules.clear();
    }
    if let Some(raw_rules) = args.match_rules {
        group.match_rules = parse_group_match_rules_arg(&raw_rules);
    }
    if !args.add_match_rule.is_empty() {
        let mut seen: HashSet<String> = group.match_rules.iter().cloned().collect();
        for raw in args.add_match_rule {
            for rule in parse_group_match_rules_arg(&raw) {
                if seen.insert(rule.clone()) {
                    group.match_rules.push(rule);
                }
            }
        }
    }
    db.upsert_multi_group(&group)?;
    let out = json!({ "ok": true, "group": group });
    Ok((
        out,
        format!("Updated policy for multi-group `{}`.", args.group_id),
    ))
}

fn build_group_eval_payload(paths: &AppPaths, group_id: &str) -> Result<(Value, String)> {
    let db = open_storage(paths)?;
    let group = db
        .get_multi_group(group_id)?
        .with_context(|| format!("multi-group `{group_id}` not found"))?;
    let nodes = db.list_nodes()?;
    let ids: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
    let snaps = db.get_probe_snapshots_batch(&ids, group.primary_probe_id.as_deref())?;
    let eval_report = evaluate_group_candidates(&group, &nodes, &snaps)?;
    let mut mem = ArbiterGroupMemory::default();
    let decision =
        decide_group_action(&group, &nodes, &snaps, None, &mut mem, Utc::now().timestamp())?;
    let watchdog_snapshot = read_watchdog_state_snapshot(&paths.root_data_dir);
    let mut out = json!({
        "ok": true,
        "sanitized": true,
        "evaluation_mode": "offline_dry_run",
        "evaluation": eval_report,
        "decision": decision,
        "watchdog_snapshot": watchdog_snapshot,
    });
    sanitize_json_value(&mut out);
    let human = format!(
        "Evaluated group `{group_id}` (offline_dry_run): {} gate-passed candidate(s) ranked.",
        out["evaluation"]["gate_passed"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0)
    );
    Ok((out, human))
}

fn analyze_dns_tls_across_logs(logs_dir: &Path, max_tail_bytes: usize) -> DnsTlsDiagnostics {
    let primary = logs_dir.join("catcloud.log");
    let archive1 = logs_dir.join("catcloud.log.1");
    let primary_len = std::fs::metadata(&primary).map(|m| m.len()).unwrap_or(0);

    if !archive1.is_file() || primary_len >= max_tail_bytes as u64 {
        return analyze_dns_tls_diagnostics_from_log_file(&primary, max_tail_bytes);
    }

    // Combine tail of `.1` and all of `catcloud.log` strictly within the `max_tail_bytes` budget.
    let remaining_budget = (max_tail_bytes as u64).saturating_sub(primary_len);
    let mut lines: Vec<String> = Vec::new();
    let mut sources: Vec<&str> = Vec::new();
    if remaining_budget > 0 {
        let prev_lines = read_bounded_file_lines(&archive1, remaining_budget);
        if !prev_lines.is_empty() {
            sources.push("catcloud.log.1");
            lines.extend(prev_lines);
        }
    }
    if primary.is_file() {
        let cur_lines = read_bounded_file_lines(&primary, max_tail_bytes as u64);
        if !cur_lines.is_empty() {
            sources.push("catcloud.log");
            lines.extend(cur_lines);
        }
    }
    if lines.is_empty() {
        return analyze_dns_tls_diagnostics_from_log_file(&primary, max_tail_bytes);
    }
    let kib = max_tail_bytes.div_ceil(1024).max(1);
    let window_desc = format!(
        "tail <= {kib} KiB across {} ({} lines)",
        sources.join(" + "),
        lines.len()
    );
    analyze_dns_tls_diagnostics(&lines, &window_desc)
}

#[derive(Debug, Clone)]
struct ThirdPartyPortConflict {
    role: String,
    host: String,
    port: u16,
    owner_pids: Vec<u32>,
}

#[derive(Debug, Clone)]
struct ActiveCorePortState {
    core_running: bool,
    core_version: Option<String>,
    controller_auth_error: Option<String>,
    endpoint: ResolvedControllerEndpoint,
    live_config: Option<LiveCoreConfigSnapshot>,
    effective_mixed_port: u16,
    effective_controller_port: u16,
    effective_dns_port: u16,
    mixed_free: bool,
    controller_free: bool,
    dns_free: bool,
    mixed_owned_by_active_core: bool,
    controller_owned_by_active_core: bool,
    dns_owned_by_active_core: bool,
    owners: Vec<PortListenerOwner>,
}

impl ActiveCorePortState {
    fn all_active_ports_owned_by_core(&self) -> bool {
        self.core_running
            && self.controller_owned_by_active_core
            && (self.mixed_free || self.mixed_owned_by_active_core)
            && (self.dns_free || self.dns_owned_by_active_core)
    }

    fn third_party_conflicts_for_effective_ports(&self, cfg: &AppConfig) -> Vec<Value> {
        let mut out = Vec::new();
        let bind_host = if cfg.allow_lan {
            cfg.bind_address.as_str()
        } else {
            "127.0.0.1"
        };
        let dns_host = if cfg.allow_lan {
            cfg.dns_listen_host.as_str()
        } else {
            "127.0.0.1"
        };
        for (role, host, port, free, owned) in [
            (
                "mixed",
                bind_host,
                self.effective_mixed_port,
                self.mixed_free,
                self.mixed_owned_by_active_core,
            ),
            (
                "controller",
                self.endpoint.host.as_str(),
                self.effective_controller_port,
                self.controller_free,
                self.controller_owned_by_active_core,
            ),
            (
                "dns",
                dns_host,
                self.effective_dns_port,
                self.dns_free,
                self.dns_owned_by_active_core,
            ),
        ] {
            if !free && !owned {
                let mut pids: Vec<u32> = self
                    .owners
                    .iter()
                    .filter(|o| o.port == port)
                    .map(|o| o.pid)
                    .collect();
                pids.sort_unstable();
                pids.dedup();
                out.push(json!({
                    "role": role,
                    "host": host,
                    "port": port,
                    "owner_pids": pids,
                }));
            }
        }
        out
    }

    fn to_status_json(&self) -> Value {
        json!({
            "owned_by_active_core": self.all_active_ports_owned_by_core(),
            "mixed_port": self.effective_mixed_port,
            "mixed_available": self.mixed_free || self.mixed_owned_by_active_core,
            "mixed_free_for_new_instance": self.mixed_free,
            "mixed_owned_by_active_core": self.mixed_owned_by_active_core,
            "mixed_third_party_conflict": !self.mixed_free && !self.mixed_owned_by_active_core,
            "controller_port": self.effective_controller_port,
            "controller_available": self.controller_free || self.controller_owned_by_active_core,
            "controller_free_for_new_instance": self.controller_free,
            "controller_owned_by_active_core": self.controller_owned_by_active_core,
            "controller_third_party_conflict": !self.controller_free && !self.controller_owned_by_active_core,
            "dns_listen_port": self.effective_dns_port,
            "dns_available": self.dns_free || self.dns_owned_by_active_core,
            "dns_free_for_new_instance": self.dns_free,
            "dns_owned_by_active_core": self.dns_owned_by_active_core,
            "dns_third_party_conflict": !self.dns_free && !self.dns_owned_by_active_core,
        })
    }

    fn to_active_core_ports_json(&self) -> Value {
        if !self.core_running {
            return Value::Null;
        }
        json!({
            "owned_by_active_core": self.all_active_ports_owned_by_core(),
            "pid": self.endpoint.pid,
            "mixed_port": self.effective_mixed_port,
            "controller_port": self.effective_controller_port,
            "dns_listen_port": self.effective_dns_port,
            "mixed_owned_by_active_core": self.mixed_owned_by_active_core,
            "controller_owned_by_active_core": self.controller_owned_by_active_core,
            "dns_owned_by_active_core": self.dns_owned_by_active_core,
        })
    }
}

fn is_valid_managed_pid(pid: u32) -> bool {
    pid > 0 && pid != std::process::id()
}

fn pid_start_time_matches_fail_closed(
    expected_start_time: Option<u64>,
    actual_start_time: Option<u64>,
) -> bool {
    match (expected_start_time, actual_start_time) {
        (Some(exp), Some(actual)) => {
            actual.abs_diff(exp) <= MANAGED_PID_START_TIME_TOLERANCE_SECS
        }
        (Some(_), None) => false,
        (None, _) => true,
    }
}

fn is_port_owned_by_active_core(
    port: u16,
    core_running: bool,
    core_pid: Option<u32>,
    core_start_ts: Option<u64>,
    owners: &[PortListenerOwner],
    is_free: bool,
) -> bool {
    if !core_running || is_free || port == 0 {
        return false;
    }
    let matching_owners: Vec<&PortListenerOwner> =
        owners.iter().filter(|o| o.port == port).collect();
    if !matching_owners.is_empty() {
        if let Some(expected_pid) = core_pid.filter(|&p| p > 0) {
            if !is_valid_managed_pid(expected_pid) {
                return false;
            }
            return matching_owners.iter().any(|o| {
                o.pid == expected_pid
                    && is_valid_managed_pid(o.pid)
                    && pid_start_time_matches_fail_closed(core_start_ts, o.process_start_time_unix)
            });
        }
        // Live external controller with no recorded PID: treat active core's own ports as owned.
        return true;
    }
    // Cross-platform fallback when OS listener table is unavailable (e.g. non-Windows).
    true
}

async fn probe_trusted_live_core_configs(
    ep: &ResolvedControllerEndpoint,
) -> Option<LiveCoreConfigSnapshot> {
    if !ep.is_trusted_loopback_secret_endpoint() {
        return None;
    }
    let job_guard = JobGuard::new().ok()?;
    let adapter = MihomoAdapter::with_controller_endpoint(
        Arc::new(job_guard),
        &ep.host,
        ep.port,
        ep.secret.clone(),
    )
    .ok()?;
    tokio::time::timeout(Duration::from_secs(2), adapter.fetch_configs())
        .await
        .ok()
        .and_then(|res| res.ok())
}

async fn inspect_active_core_ports(paths: &AppPaths, cfg: &AppConfig) -> ActiveCorePortState {
    let (live_version, controller_auth_err, ctrl_ep) = probe_live_controller(paths, cfg).await;
    let core_running = live_version.is_some();
    let live_config = if core_running {
        probe_trusted_live_core_configs(&ctrl_ep).await
    } else {
        None
    };

    let effective_mixed_port = if core_running {
        ctrl_ep
            .mixed_port
            .or_else(|| live_config.as_ref().map(|lc| lc.mixed_port).filter(|&p| p > 0))
            .unwrap_or(cfg.mixed_port)
    } else {
        cfg.mixed_port
    };
    let effective_controller_port = if core_running || controller_auth_err.is_some() {
        ctrl_ep.port
    } else {
        cfg.controller_port
    };
    let effective_dns_port = if core_running {
        ctrl_ep.dns_port.unwrap_or(cfg.dns_listen_port)
    } else {
        cfg.dns_listen_port
    };

    let bind_host = if cfg.allow_lan {
        cfg.bind_address.as_str()
    } else {
        "127.0.0.1"
    };
    let dns_host = if cfg.allow_lan {
        cfg.dns_listen_host.as_str()
    } else {
        "127.0.0.1"
    };

    let mixed_free = is_port_available_tcp_udp(bind_host, effective_mixed_port);
    let controller_free = is_port_available_tcp_udp(&ctrl_ep.host, effective_controller_port);
    let dns_free = is_port_available_tcp_udp(dns_host, effective_dns_port);

    let mut watched_ports = vec![
        effective_mixed_port,
        effective_controller_port,
        effective_dns_port,
        cfg.mixed_port,
        cfg.controller_port,
        cfg.dns_listen_port,
    ];
    watched_ports.sort_unstable();
    watched_ports.dedup();
    let owners = list_listening_port_owners(&watched_ports);

    let mixed_owned_by_active_core = is_port_owned_by_active_core(
        effective_mixed_port,
        core_running,
        ctrl_ep.pid,
        ctrl_ep.process_start_time_unix,
        &owners,
        mixed_free,
    );
    let controller_owned_by_active_core = is_port_owned_by_active_core(
        effective_controller_port,
        core_running,
        ctrl_ep.pid,
        ctrl_ep.process_start_time_unix,
        &owners,
        controller_free,
    );
    let dns_owned_by_active_core = is_port_owned_by_active_core(
        effective_dns_port,
        core_running,
        ctrl_ep.pid,
        ctrl_ep.process_start_time_unix,
        &owners,
        dns_free,
    );

    ActiveCorePortState {
        core_running,
        core_version: live_version,
        controller_auth_error: controller_auth_err,
        endpoint: ctrl_ep,
        live_config,
        effective_mixed_port,
        effective_controller_port,
        effective_dns_port,
        mixed_free,
        controller_free,
        dns_free,
        mixed_owned_by_active_core,
        controller_owned_by_active_core,
        dns_owned_by_active_core,
        owners,
    }
}

fn find_next_free_port(host: &str, start_after: u16, reserved: &HashSet<u16>) -> Option<u16> {
    let mut cand = if start_after == u16::MAX {
        10240
    } else {
        start_after + 1
    };
    for _ in 0..512 {
        if !reserved.contains(&cand) && is_port_available_tcp_udp(host, cand) {
            return Some(cand);
        }
        cand = if cand == u16::MAX { 10240 } else { cand + 1 };
    }
    None
}

/// Separate compilation ports (retaining active CatCloud core's own listening ports without false
/// conflict shifts) from `new_instance_preview_ports` (if launching a fresh second instance) while
/// still detecting genuine third-party port conflicts.
fn resolve_compile_and_preview_ports(
    cfg: &AppConfig,
    active: &ActiveCorePortState,
) -> Result<(AllocatedPorts, Option<AllocatedPorts>, Vec<ThirdPartyPortConflict>)> {
    let bind_host = if cfg.allow_lan {
        cfg.bind_address.clone()
    } else {
        "127.0.0.1".to_string()
    };
    let ctrl_host = if cfg.allow_lan {
        cfg.controller_host.clone()
    } else {
        "127.0.0.1".to_string()
    };
    let dns_host = if cfg.allow_lan {
        cfg.dns_listen_host.clone()
    } else {
        "127.0.0.1".to_string()
    };

    let mut reserved = HashSet::with_capacity(3);
    let mut shifted: Vec<PortShiftNotice> = Vec::new();
    let mut conflicts: Vec<ThirdPartyPortConflict> = Vec::new();

    let mut resolve_role = |role: &str,
                            host: &str,
                            desired: u16,
                            active_port: u16,
                            active_owned: bool|
     -> Result<u16> {
        let owned_same = active.core_running && desired == active_port && active_owned;
        let is_free = is_port_available_tcp_udp(host, desired);
        let owned_by_core = owned_same
            || is_port_owned_by_active_core(
                desired,
                active.core_running,
                active.endpoint.pid,
                active.endpoint.process_start_time_unix,
                &active.owners,
                is_free,
            ) && (desired == active.effective_mixed_port
                || desired == active.effective_controller_port
                || desired == active.effective_dns_port);

        if !reserved.contains(&desired) && (owned_by_core || is_free) {
            reserved.insert(desired);
            return Ok(desired);
        }

        if !is_free && !owned_by_core {
            let mut pids: Vec<u32> = active
                .owners
                .iter()
                .filter(|o| o.port == desired)
                .map(|o| o.pid)
                .collect();
            pids.sort_unstable();
            pids.dedup();
            conflicts.push(ThirdPartyPortConflict {
                role: role.to_string(),
                host: host.to_string(),
                port: desired,
                owner_pids: pids,
            });
        }

        if cfg.port_guard_auto_shift {
            if let Some(next_port) = find_next_free_port(host, desired, &reserved) {
                reserved.insert(next_port);
                shifted.push(PortShiftNotice {
                    role: role.to_string(),
                    desired_port: desired,
                    actual_port: next_port,
                    reason: format!(
                        "port {desired} on `{host}` is occupied by another process or collides with another role"
                    ),
                });
                return Ok(next_port);
            }
        }
        reserved.insert(desired);
        Ok(desired)
    };

    let mixed_port = resolve_role(
        "mixed",
        &bind_host,
        cfg.mixed_port,
        active.effective_mixed_port,
        active.mixed_owned_by_active_core,
    )?;
    let controller_port = resolve_role(
        "controller",
        &ctrl_host,
        cfg.controller_port,
        active.effective_controller_port,
        active.controller_owned_by_active_core,
    )?;
    let dns_port = resolve_role(
        "dns",
        &dns_host,
        cfg.dns_listen_port,
        active.effective_dns_port,
        active.dns_owned_by_active_core,
    )?;

    let compile_ports = AllocatedPorts {
        bind_host: bind_host.clone(),
        mixed_port,
        controller_port,
        dns_port,
        shifted,
    };

    let new_instance_preview = allocate_safe_ports_for_hosts(
        &bind_host,
        &ctrl_host,
        &dns_host,
        cfg.mixed_port,
        cfg.controller_port,
        cfg.dns_listen_port,
        true,
    )
    .ok();

    Ok((compile_ports, new_instance_preview, conflicts))
}

fn parse_yaml_bool_scalar(raw: &str) -> Option<bool> {
    match unquote_yaml_scalar(raw).trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" => Some(true),
        "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn parse_yaml_u16_scalar(raw: &str) -> Option<u16> {
    unquote_yaml_scalar(raw).trim().parse::<u16>().ok()
}

fn parse_host_and_port_pair(raw: &str) -> Option<(String, u16)> {
    let clean = unquote_yaml_scalar(raw);
    let trimmed = clean.trim();
    if let Some(rest) = trimmed.strip_prefix('[') {
        let (host, tail) = rest.split_once("]:")?;
        let port = tail.trim().parse::<u16>().ok()?;
        return Some((host.trim().to_string(), port));
    }
    let (host, port_str) = trimmed.rsplit_once(':')?;
    let port = port_str.trim().parse::<u16>().ok()?;
    Some((host.trim().to_string(), port))
}

/// Reconstruct the live running baseline [`AppConfig`] from on-disk `run/runtime.yaml` plus
/// authenticated `GET /configs` runtime values so `classify_config_diff` compares the *actual*
/// running core state against the new `config.json` instead of comparing `cfg` against itself.
fn build_live_baseline_config_from_runtime(
    cfg: &AppConfig,
    runtime_yaml_path: &Path,
    live_cfg: Option<&LiveCoreConfigSnapshot>,
    ep: &ResolvedControllerEndpoint,
) -> AppConfig {
    let mut baseline = cfg.clone();
    let mut yaml_allow_lan: Option<bool> = None;
    let mut yaml_bind_addr: Option<String> = None;
    let mut yaml_ctrl_host: Option<String> = None;
    let mut yaml_dns_host: Option<String> = None;

    const MAX_RUNTIME_YAML_HEADER_LINES: usize = 65_536;
    if let Ok(raw_yaml) = std::fs::read_to_string(runtime_yaml_path) {
        let text = raw_yaml.strip_prefix('\u{feff}').unwrap_or(&raw_yaml);
        let mut section: Option<&str> = None;
        for raw_line in text.lines().take(MAX_RUNTIME_YAML_HEADER_LINES) {
            let trimmed = raw_line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let indent = raw_line.len() - raw_line.trim_start_matches(' ').len();
            if indent == 0 {
                if trimmed.starts_with("proxies:")
                    || trimmed.starts_with("proxy-groups:")
                    || trimmed.starts_with("rules:")
                {
                    break;
                }
                section = None;
                if trimmed == "tun:" {
                    section = Some("tun");
                    continue;
                }
                if trimmed == "dns:" {
                    section = Some("dns");
                    continue;
                }
                if let Some((k, v)) = trimmed.split_once(':') {
                    let key = k.trim().trim_matches(['"', '\'']);
                    let val = v.trim();
                    match key {
                        "mixed-port" => {
                            if let Some(p) = parse_yaml_u16_scalar(val).filter(|&p| p > 0) {
                                baseline.mixed_port = p;
                            }
                        }
                        "socks-port" => {
                            baseline.socks_port = parse_yaml_u16_scalar(val).filter(|&p| p > 0);
                        }
                        "port" => {
                            baseline.http_port = parse_yaml_u16_scalar(val).filter(|&p| p > 0);
                        }
                        "redir-port" => {
                            baseline.redir_port = parse_yaml_u16_scalar(val).filter(|&p| p > 0);
                        }
                        "tproxy-port" => {
                            baseline.tproxy_port = parse_yaml_u16_scalar(val).filter(|&p| p > 0);
                        }
                        "allow-lan" => {
                            if let Some(b) = parse_yaml_bool_scalar(val) {
                                yaml_allow_lan = Some(b);
                                baseline.allow_lan = b;
                            }
                        }
                        "bind-address" => {
                            let s = unquote_yaml_scalar(val);
                            if !s.trim().is_empty() {
                                yaml_bind_addr = Some(s.trim().to_string());
                            }
                        }
                        "external-controller" => {
                            if let Some((h, p)) = parse_host_and_port_pair(val) {
                                if p > 0 {
                                    baseline.controller_port = p;
                                }
                                if !h.is_empty() {
                                    yaml_ctrl_host = Some(h);
                                }
                            }
                        }
                        "mode" => {
                            match unquote_yaml_scalar(val).trim().to_ascii_lowercase().as_str() {
                                "rule" => baseline.proxy_mode = ProxyMode::Rule,
                                "global" => baseline.proxy_mode = ProxyMode::Global,
                                "direct" => baseline.proxy_mode = ProxyMode::Direct,
                                _ => {}
                            }
                        }
                        "log-level" => {
                            match unquote_yaml_scalar(val).trim().to_ascii_lowercase().as_str() {
                                "silent" => baseline.log_level = CoreLogLevel::Silent,
                                "error" => baseline.log_level = CoreLogLevel::Error,
                                "warning" | "warn" => baseline.log_level = CoreLogLevel::Warning,
                                "info" => baseline.log_level = CoreLogLevel::Info,
                                "debug" => baseline.log_level = CoreLogLevel::Debug,
                                _ => {}
                            }
                        }
                        "ipv6" => {
                            if let Some(b) = parse_yaml_bool_scalar(val) {
                                baseline.core_ipv6 = b;
                            }
                        }
                        "unified-delay" => {
                            if let Some(b) = parse_yaml_bool_scalar(val) {
                                baseline.unified_delay = b;
                            }
                        }
                        "tcp-concurrent" => {
                            if let Some(b) = parse_yaml_bool_scalar(val) {
                                baseline.tcp_concurrent = b;
                            }
                        }
                        "find-process-mode" => {
                            match unquote_yaml_scalar(val).trim().to_ascii_lowercase().as_str() {
                                "strict" => {
                                    baseline.find_process_mode =
                                        catcloud_core::models::FindProcessMode::Strict;
                                }
                                "always" => {
                                    baseline.find_process_mode =
                                        catcloud_core::models::FindProcessMode::Always;
                                }
                                "off" => {
                                    baseline.find_process_mode =
                                        catcloud_core::models::FindProcessMode::Off;
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }
            } else if indent == 2 && !trimmed.starts_with('-') {
                if let Some((k, v)) = trimmed.split_once(':') {
                    let key = k.trim().trim_matches(['"', '\'']);
                    let val = v.trim();
                    match section {
                        Some("tun") => match key {
                            "enable" => {
                                if let Some(b) = parse_yaml_bool_scalar(val) {
                                    baseline.tun.enabled = b;
                                }
                            }
                            "stack" => {
                                match unquote_yaml_scalar(val).trim().to_ascii_lowercase().as_str()
                                {
                                    "mixed" => baseline.tun.stack_mode = TunStackMode::Mixed,
                                    "system" => baseline.tun.stack_mode = TunStackMode::System,
                                    "gvisor" => baseline.tun.stack_mode = TunStackMode::Gvisor,
                                    _ => {}
                                }
                            }
                            "device" => {
                                let d = unquote_yaml_scalar(val);
                                if !d.trim().is_empty() {
                                    baseline.tun.device_name = d.trim().to_string();
                                }
                            }
                            "mtu" => {
                                if let Some(m) = parse_yaml_u16_scalar(val).filter(|&m| m > 0) {
                                    baseline.tun.mtu = m;
                                }
                            }
                            "auto-route" => {
                                if let Some(b) = parse_yaml_bool_scalar(val) {
                                    baseline.tun.auto_route = b;
                                }
                            }
                            "auto-detect-interface" => {
                                if let Some(b) = parse_yaml_bool_scalar(val) {
                                    baseline.tun.auto_detect_interface = b;
                                }
                            }
                            "strict-route" => {
                                if let Some(b) = parse_yaml_bool_scalar(val) {
                                    baseline.tun.strict_route = b;
                                }
                            }
                            _ => {}
                        },
                        Some("dns") => match key {
                            "listen" => {
                                if let Some((h, p)) = parse_host_and_port_pair(val) {
                                    if p > 0 {
                                        baseline.dns_listen_port = p;
                                    }
                                    if !h.is_empty() {
                                        yaml_dns_host = Some(h);
                                    }
                                }
                            }
                            "enable" => {
                                if let Some(b) = parse_yaml_bool_scalar(val) {
                                    baseline.dns.enable = b;
                                }
                            }
                            "ipv6" => {
                                if let Some(b) = parse_yaml_bool_scalar(val) {
                                    baseline.dns.ipv6 = b;
                                }
                            }
                            _ => {}
                        },
                        _ => {}
                    }
                }
            }
        }
    }

    // Apply live controller metadata ports when present.
    if let Some(p) = ep.mixed_port.filter(|&p| p > 0) {
        baseline.mixed_port = p;
    }
    if ep.port > 0
        && ep.source == catcloud_core::core_adapter::ControllerEndpointSource::LiveRuntimeMeta
    {
        baseline.controller_port = ep.port;
    }
    if let Some(p) = ep.dns_port.filter(|&p| p > 0) {
        baseline.dns_listen_port = p;
    }

    // Overlay live `GET /configs` values (highest authority for active running core).
    let mut live_bind_addr: Option<String> = None;
    if let Some(lc) = live_cfg {
        baseline.tun.enabled = lc.tun_enable;
        if lc.mixed_port > 0 {
            baseline.mixed_port = lc.mixed_port;
        }
        if lc.port > 0 {
            baseline.http_port = Some(lc.port);
        }
        if lc.socks_port > 0 {
            baseline.socks_port = Some(lc.socks_port);
        }
        baseline.allow_lan = lc.allow_lan;
        if !lc.bind_address.trim().is_empty() {
            live_bind_addr = Some(lc.bind_address.trim().to_string());
        }
        match lc.mode.trim().to_ascii_lowercase().as_str() {
            "rule" => baseline.proxy_mode = ProxyMode::Rule,
            "global" => baseline.proxy_mode = ProxyMode::Global,
            "direct" => baseline.proxy_mode = ProxyMode::Direct,
            _ => {}
        }
    }

    // Reconcile compiled bind/controller/DNS hosts with `allow_lan` semantics from
    // `config_compiler.rs` so non-LAN `127.0.0.1` bindings do not cause spurious L3 diffs.
    let effective_bind_candidate = live_bind_addr.or(yaml_bind_addr);
    if let Some(obs_bind) = effective_bind_candidate {
        let cfg_compiled_bind = if cfg.allow_lan {
            let c = cfg.bind_address.trim();
            if c.is_empty() || c == "127.0.0.1" {
                "*"
            } else {
                c
            }
        } else {
            "127.0.0.1"
        };
        if baseline.allow_lan == cfg.allow_lan && obs_bind == cfg_compiled_bind {
            baseline.bind_address = cfg.bind_address.clone();
        } else {
            baseline.bind_address = obs_bind;
        }
    }
    if let Some(obs_ctrl_host) = yaml_ctrl_host {
        let cfg_compiled_ctrl = if cfg.allow_lan {
            cfg.controller_host.trim()
        } else {
            "127.0.0.1"
        };
        if baseline.allow_lan == cfg.allow_lan && obs_ctrl_host == cfg_compiled_ctrl {
            baseline.controller_host = cfg.controller_host.clone();
        } else {
            baseline.controller_host = obs_ctrl_host;
        }
    }
    if let Some(obs_dns_host) = yaml_dns_host {
        let cfg_compiled_dns = if cfg.allow_lan {
            cfg.dns_listen_host.trim()
        } else {
            "127.0.0.1"
        };
        if baseline.allow_lan == cfg.allow_lan && obs_dns_host == cfg_compiled_dns {
            baseline.dns_listen_host = cfg.dns_listen_host.clone();
        } else {
            baseline.dns_listen_host = obs_dns_host;
        }
    }
    let _ = yaml_allow_lan;
    baseline
}

fn summarize_l3_diff_reasons(old: &AppConfig, new: &AppConfig) -> Vec<String> {
    let mut reasons = Vec::new();
    if old.mixed_port != new.mixed_port {
        reasons.push(format!("mixed_port: {} -> {}", old.mixed_port, new.mixed_port));
    }
    if old.socks_port != new.socks_port {
        reasons.push(format!("socks_port: {:?} -> {:?}", old.socks_port, new.socks_port));
    }
    if old.http_port != new.http_port {
        reasons.push(format!("http_port: {:?} -> {:?}", old.http_port, new.http_port));
    }
    if old.redir_port != new.redir_port {
        reasons.push(format!("redir_port: {:?} -> {:?}", old.redir_port, new.redir_port));
    }
    if old.tproxy_port != new.tproxy_port {
        reasons.push(format!("tproxy_port: {:?} -> {:?}", old.tproxy_port, new.tproxy_port));
    }
    if old.allow_lan != new.allow_lan {
        reasons.push(format!("allow_lan: {} -> {}", old.allow_lan, new.allow_lan));
    }
    if old.bind_address != new.bind_address {
        reasons.push(format!("bind_address: {} -> {}", old.bind_address, new.bind_address));
    }
    if old.controller_host != new.controller_host || old.controller_port != new.controller_port {
        reasons.push(format!(
            "controller: {}:{} -> {}:{}",
            old.controller_host, old.controller_port, new.controller_host, new.controller_port
        ));
    }
    if old.dns_listen_host != new.dns_listen_host || old.dns_listen_port != new.dns_listen_port {
        reasons.push(format!(
            "dns_listen: {}:{} -> {}:{}",
            old.dns_listen_host, old.dns_listen_port, new.dns_listen_host, new.dns_listen_port
        ));
    }
    if old.tun.enabled != new.tun.enabled {
        reasons.push(format!("tun.enabled: {} -> {}", old.tun.enabled, new.tun.enabled));
    } else if new.tun.enabled && old.tun != new.tun {
        reasons.push("tun settings changed (stack/mtu/route/device)".to_string());
    }
    if old.core_runtime.kernel_kind != new.core_runtime.kernel_kind
        || old.core_runtime.custom_binary_path != new.core_runtime.custom_binary_path
        || old.core_runtime.memory_tier != new.core_runtime.memory_tier
        || old.core_runtime.gogc != new.core_runtime.gogc
    {
        reasons.push("core_runtime binary or memory/GC settings changed".to_string());
    }
    reasons
}

async fn build_config_validate_payload(paths: &AppPaths) -> Result<(bool, Value, String)> {
    let cfg = config::load_or_init(paths)?;
    let cfg_issues = config::validate_config_detailed(&cfg);
    let db = open_storage(paths)?;
    let nodes = db.list_nodes()?;
    let groups = db.list_multi_groups()?;
    let relays = db.list_preaccel_relays(false)?;
    let active_ports = inspect_active_core_ports(paths, &cfg).await;
    let (ports, new_instance_preview_ports, third_party_conflicts) =
        resolve_compile_and_preview_ports(&cfg, &active_ports)?;

    let empty_filter = HashMap::new();
    let compiled = compile_mihomo_config_with_runtime_dir(
        &CompileInput {
            config: &cfg,
            nodes: &nodes,
            groups: &groups,
            relays: &relays,
            controller_secret: "validation-placeholder-secret",
            allocated_ports: &ports,
            extra_prepend_rules: &[],
            extra_fake_ip_filters: &[],
            group_filtered_members: &empty_filter,
        },
        Some(&paths.runtime_dir),
    )?;
    let relay_servers: Vec<String> = relays
        .iter()
        .filter(|r| r.enabled)
        .map(|r| r.server.clone())
        .collect();
    let static_report = validate_compiled_yaml(&compiled.yaml, &relay_servers)?;
    let conflict_blocks_start = !third_party_conflicts.is_empty() && !cfg.port_guard_auto_shift;
    let ok = cfg_issues.is_empty() && static_report.ok && !conflict_blocks_start;
    let sanitized_cfg_issues = redact_config_issues(&cfg_issues);
    let sanitized_static = redact_static_validation(&static_report);
    let conflicts_json: Vec<Value> = third_party_conflicts
        .iter()
        .map(|c| {
            json!({
                "role": &c.role,
                "host": &c.host,
                "port": c.port,
                "owner_pids": &c.owner_pids,
            })
        })
        .collect();

    let mut out = json!({
        "ok": ok,
        "sanitized": true,
        "config_issues": sanitized_cfg_issues,
        "static_validation": sanitized_static,
        "stats": compiled.stats,
        "ports": ports,
        "active_core_ports": active_ports.to_active_core_ports_json(),
        "new_instance_preview_ports": new_instance_preview_ports,
        "third_party_port_conflicts": conflicts_json,
    });
    sanitize_json_value(&mut out);
    let human = format!(
        "Config validation ok={ok} (rules={}, proxies={}, core_running={}, third_party_conflicts={}).",
        compiled.stats.total_rules,
        compiled.stats.total_proxies,
        active_ports.core_running,
        third_party_conflicts.len()
    );
    Ok((ok, out, human))
}

async fn build_config_compile_result(
    paths: &AppPaths,
    reveal_secrets: bool,
) -> Result<(String, Value)> {
    let cfg = config::load_or_init(paths)?;
    let db = open_storage(paths)?;
    let nodes = db.list_nodes()?;
    let groups = db.list_multi_groups()?;
    let relays = db.list_preaccel_relays(false)?;
    let active_ports = inspect_active_core_ports(paths, &cfg).await;
    let (ports, new_instance_preview_ports, third_party_conflicts) =
        resolve_compile_and_preview_ports(&cfg, &active_ports)?;

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
    let conflicts_json: Vec<Value> = third_party_conflicts
        .iter()
        .map(|c| {
            json!({
                "role": &c.role,
                "host": &c.host,
                "port": c.port,
                "owner_pids": &c.owner_pids,
            })
        })
        .collect();
    let meta = json!({
        "sha256": compiled.sha256,
        "ports": ports,
        "active_core_ports": active_ports.to_active_core_ports_json(),
        "new_instance_preview_ports": new_instance_preview_ports,
        "third_party_port_conflicts": conflicts_json,
    });
    Ok((rendered_yaml, meta))
}

async fn execute_config_compile(
    paths: &AppPaths,
    as_json: bool,
    output: Option<PathBuf>,
    reveal_secrets: bool,
) -> Result<()> {
    let (rendered_yaml, meta) = build_config_compile_result(paths, reveal_secrets).await?;
    if let Some(path) = output {
        AppPaths::atomic_write(&path, rendered_yaml.as_bytes())?;
        let file_sha256 = compute_file_sha256(&path)?;
        let display_path = redact_path_for_display(&path.to_string_lossy());
        let out = json!({
            "ok": true,
            "sanitized": !reveal_secrets,
            "output": &display_path,
            "sha256": file_sha256,
            "ports": &meta["ports"],
            "active_core_ports": &meta["active_core_ports"],
            "new_instance_preview_ports": &meta["new_instance_preview_ports"],
            "third_party_port_conflicts": &meta["third_party_port_conflicts"],
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
                "sha256": &meta["sha256"],
                "ports": &meta["ports"],
                "active_core_ports": &meta["active_core_ports"],
                "new_instance_preview_ports": &meta["new_instance_preview_ports"],
                "third_party_port_conflicts": &meta["third_party_port_conflicts"],
            }),
            "",
        )
    } else {
        println!("{rendered_yaml}");
        Ok(())
    }
}

fn parse_gateway_export_profile(raw: &str) -> Result<GatewayExportProfile> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "relay-fragment" | "relay_fragment" | "relay" => Ok(GatewayExportProfile::RelayFragment),
        "transparent-gateway" | "transparent_gateway" | "gateway" => {
            Ok(GatewayExportProfile::TransparentGateway)
        }
        "preferred-nodes" | "preferred_nodes" | "nodes" => Ok(GatewayExportProfile::PreferredNodes),
        other => anyhow::bail!(
            "unsupported gateway export profile `{other}` (expected: relay-fragment, transparent-gateway, preferred-nodes)"
        ),
    }
}

fn build_config_export_gateway_result(
    paths: &AppPaths,
    profile_raw: &str,
    tproxy_port: u16,
    redir_port: u16,
    dns_port: u16,
    reveal_secrets: bool,
) -> Result<GatewayExportOutput> {
    let profile = parse_gateway_export_profile(profile_raw)?;
    let cfg = config::load_or_init(paths)?;
    let db = open_storage(paths)?;
    let nodes = db.list_nodes()?;
    let groups = db.list_multi_groups()?;
    let relays = db.list_preaccel_relays(false)?;
    let opts = GatewayExportOptions {
        profile,
        tproxy_port,
        redir_port,
        dns_listen_port: dns_port,
        redact_secrets: !reveal_secrets,
    };
    let exported = export_gateway_yaml(
        &cfg,
        &nodes,
        &groups,
        &relays,
        Some(&paths.runtime_dir),
        &opts,
    )?;
    Ok(exported)
}

#[allow(clippy::too_many_arguments)]
async fn execute_config_export_gateway(
    paths: &AppPaths,
    as_json: bool,
    profile: &str,
    tproxy_port: u16,
    redir_port: u16,
    dns_port: u16,
    output: Option<PathBuf>,
    reveal_secrets: bool,
) -> Result<()> {
    let exported = build_config_export_gateway_result(
        paths,
        profile,
        tproxy_port,
        redir_port,
        dns_port,
        reveal_secrets,
    )?;
    if let Some(path) = output {
        AppPaths::atomic_write(&path, exported.yaml.as_bytes())?;
        let file_sha256 = compute_file_sha256(&path)?;
        let display_path = redact_path_for_display(&path.to_string_lossy());
        let out = json!({
            "ok": true,
            "sanitized": exported.redacted,
            "redacted": exported.redacted,
            "profile": exported.profile,
            "output": &display_path,
            "sha256": file_sha256,
            "relay_count": exported.relay_count,
            "node_count": exported.node_count,
            "rule_count": exported.rule_count,
            "warnings": &exported.warnings,
            "integration_hint": &exported.integration_hint,
        });
        emit_output(
            as_json,
            &out,
            &format!(
                "Wrote gateway YAML (profile={:?}, redacted={}) to {}. {}",
                exported.profile, exported.redacted, display_path, exported.integration_hint
            ),
        )
    } else if as_json {
        emit_output(
            true,
            &json!({
                "ok": true,
                "sanitized": exported.redacted,
                "redacted": exported.redacted,
                "profile": exported.profile,
                "yaml": &exported.yaml,
                "relay_count": exported.relay_count,
                "node_count": exported.node_count,
                "rule_count": exported.rule_count,
                "warnings": &exported.warnings,
                "integration_hint": &exported.integration_hint,
            }),
            "",
        )
    } else {
        println!("{}", exported.yaml);
        Ok(())
    }
}

async fn run_config_reload_inner(
    paths: &AppPaths,
    dry_run: bool,
    caps_override: Option<catcloud_core::platform::PlatformCapabilities>,
    verify_with_binary: bool,
) -> Result<(bool, Value, String)> {
    let cfg = config::load_or_init(paths)?;
    let _ = open_storage(paths)?;
    let bin_res = resolve_mihomo_binary(&cfg, paths, &[], false)?;
    let job_guard = Arc::new(JobGuard::new()?);

    let ep = resolve_effective_controller_endpoint_info(paths, &cfg);
    let ctrl_addr = format_host_port(&ep.host, ep.port);
    let configured_secret = (!ep.secret.trim().is_empty()).then_some(ep.secret.clone());

    let probe_adapter = MihomoAdapter::with_controller_endpoint(
        Arc::clone(&job_guard),
        &ep.host,
        ep.port,
        ep.secret.clone(),
    )?;

    let mut live_controller_version: Option<String> = None;
    let mut controller_auth_error: Option<String> = None;
    match tokio::time::timeout(Duration::from_secs(2), probe_adapter.fetch_version()).await {
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

    let core_running = live_controller_version.is_some();
    // Strictly query `GET /configs` ONLY on trusted loopback secret endpoints.
    let trusted_endpoint = ep.is_trusted_loopback_secret_endpoint();
    let live_cfg: Option<LiveCoreConfigSnapshot> = if core_running && trusted_endpoint {
        tokio::time::timeout(Duration::from_secs(2), probe_adapter.fetch_configs())
            .await
            .ok()
            .and_then(|res| res.ok())
    } else {
        None
    };

    let redacted_bin_path = bin_res
        .path
        .as_ref()
        .map(|p| redact_path_for_display(&p.to_string_lossy()));
    let caps = caps_override.unwrap_or_else(|| default_platform().capabilities());
    let cli_tun_privilege_ready = is_cli_tun_privilege_ready(&caps, bin_res.path.as_deref());
    let live_tun_enabled = live_cfg.as_ref().is_some_and(|lc| lc.tun_enable);
    // Issue #2 root fix: when an elevated desktop core is already running with TUN enabled and
    // `cfg.tun.enabled == true`, preserve `allow_tun = true` during L2 hot reload instead of
    // silently disabling TUN due to the CLI process running unprivileged.
    let tun_preserved_via_live_core =
        !cli_tun_privilege_ready && core_running && live_tun_enabled && cfg.tun.enabled;
    let allow_tun = cli_tun_privilege_ready || tun_preserved_via_live_core;
    let tun_masked_no_elevation = cfg.tun.enabled && !allow_tun;

    let runtime_yaml_path = paths.runtime_dir.join("runtime.yaml");
    let redacted_runtime_yaml = redact_path_for_display(&runtime_yaml_path.to_string_lossy());
    let mut effective_cfg = cfg.clone();
    if !allow_tun && effective_cfg.tun.enabled {
        effective_cfg.tun.enabled = false;
    }

    let live_baseline_cfg = if core_running {
        Some(build_live_baseline_config_from_runtime(
            &cfg,
            &runtime_yaml_path,
            live_cfg.as_ref(),
            &ep,
        ))
    } else {
        None
    };
    let classified_level = match &live_baseline_cfg {
        Some(old) => classify_config_diff(old, &effective_cfg),
        None => ReloadLevel::L2HotReload,
    };
    let diff_reasons = match &live_baseline_cfg {
        Some(old) => summarize_l3_diff_reasons(old, &effective_cfg),
        None => Vec::new(),
    };
    let requires_l3_restart = classified_level == ReloadLevel::L3CoreRestart;

    if dry_run {
        let db = open_storage(paths)?;
        let nodes = db.list_nodes()?;
        let groups = db.list_multi_groups()?;
        let relays = db.list_preaccel_relays(false)?;
        let bind_host = if effective_cfg.allow_lan {
            effective_cfg.bind_address.clone()
        } else {
            "127.0.0.1".to_string()
        };
        let ports = AllocatedPorts {
            bind_host,
            mixed_port: ep
                .mixed_port
                .or_else(|| live_cfg.as_ref().map(|lc| lc.mixed_port).filter(|&p| p > 0))
                .unwrap_or(effective_cfg.mixed_port),
            controller_port: ep.port,
            dns_port: ep.dns_port.unwrap_or(effective_cfg.dns_listen_port),
            shifted: Vec::new(),
        };
        let secret = configured_secret
            .clone()
            .unwrap_or_else(generate_controller_secret);
        let empty_filter = HashMap::new();
        let compiled = compile_mihomo_config_with_runtime_dir(
            &CompileInput {
                config: &effective_cfg,
                nodes: &nodes,
                groups: &groups,
                relays: &relays,
                controller_secret: &secret,
                allocated_ports: &ports,
                extra_prepend_rules: &[],
                extra_fake_ip_filters: &[],
                group_filtered_members: &empty_filter,
            },
            Some(&paths.runtime_dir),
        )?;
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
            let msg = format!("compiled YAML failed static anti-loop preflight: {summary}");
            let sanitized_validation = redact_static_validation(&compiled.validation);
            let mut out = json!({
                "ok": false,
                "sanitized": true,
                "dry_run": true,
                "validated_and_written": false,
                "level": classified_level,
                "allow_tun": allow_tun,
                "live_tun_enabled": live_tun_enabled,
                "requires_l3_restart": requires_l3_restart,
                "diff_reasons": &diff_reasons,
                "error": &msg,
                "static_validation": &sanitized_validation,
            });
            sanitize_json_value(&mut out);
            return Ok((false, out, format!("refused reload dry-run: {summary}")));
        }

        let mut binary_verified = false;
        if verify_with_binary {
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
                    let mut out = json!({
                        "ok": false,
                        "sanitized": true,
                        "dry_run": true,
                        "validated_and_written": false,
                        "binary_verified": false,
                        "binary_path": &redacted_bin_path,
                        "level": classified_level,
                        "allow_tun": allow_tun,
                        "error": &msg,
                    });
                    sanitize_json_value(&mut out);
                    return Ok((false, out, format!("refused reload dry-run: {msg}")));
                }
                binary_verified = true;
            }
        }

        let warnings: Vec<String> = compiled
            .validation
            .warnings()
            .iter()
            .map(|w| sanitize_log_line(&format!("[{}] {}", w.code, w.message)))
            .collect();
        let l3_restart_hint = if requires_l3_restart {
            Some("本次变更需要 L3 重启内核（端口、TUN 开关/栈或核心底层参数变更）；CLI 在非提权/非重启模式下会拒绝直接重启，请通过已提权的 CatCloud 桌面端重启核心生效。")
        } else {
            None
        };
        let mut out = json!({
            "ok": true,
            "sanitized": true,
            "dry_run": true,
            "runtime_yaml_path": &redacted_runtime_yaml,
            "core_not_running": live_controller_version.is_none() && controller_auth_error.is_none(),
            "core_version": &live_controller_version,
            "trusted_controller_endpoint": trusted_endpoint,
            "hot_reloaded": false,
            "validated_and_written": false,
            "level": classified_level,
            "requires_l3_restart": requires_l3_restart,
            "allow_l3_restart": false,
            "diff_reasons": &diff_reasons,
            "l3_restart_hint": l3_restart_hint,
            "allow_tun": allow_tun,
            "live_tun_enabled": live_tun_enabled,
            "tun_preserved_via_live_core": tun_preserved_via_live_core,
            "tun_masked_no_elevation": tun_masked_no_elevation,
            "binary_verified": binary_verified,
            "binary_path": &redacted_bin_path,
            "sha256": &compiled.sha256,
            "stats": &compiled.stats,
            "warnings": &warnings,
        });
        sanitize_json_value(&mut out);
        let human = format!(
            "Validated candidate runtime.yaml (dry_run=true, level={}, allow_tun={}, requires_l3_restart={}, binary_verified={}, sha256={}).",
            classified_level,
            allow_tun,
            requires_l3_restart,
            binary_verified,
            &compiled.sha256[..12]
        );
        return Ok((true, out, human));
    }

    if let Some(auth_err) = controller_auth_error {
        let msg = sanitize_log_line(&format!(
            "running Mihomo controller at {} rejected authentication ({auth_err}); ensure config.json controller_secret matches the active core or restart core",
            ctrl_addr
        ));
        let mut out = json!({
            "ok": false,
            "sanitized": true,
            "dry_run": false,
            "core_not_running": false,
            "hot_reloaded": false,
            "validated_and_written": false,
            "error": &msg,
        });
        sanitize_json_value(&mut out);
        return Ok((false, out, msg));
    }

    let adapter = if core_running {
        Arc::new(probe_adapter)
    } else {
        Arc::new(MihomoAdapter::new(Arc::clone(&job_guard))?)
    };
    let coordinator = HotReloadCoordinator::new(paths.clone(), adapter);
    if let Some(baseline_cfg) = live_baseline_cfg {
        let seeded_ports = AllocatedPorts {
            bind_host: if baseline_cfg.allow_lan {
                baseline_cfg.bind_address.clone()
            } else {
                "127.0.0.1".to_string()
            },
            mixed_port: ep
                .mixed_port
                .or_else(|| live_cfg.as_ref().map(|lc| lc.mixed_port).filter(|&p| p > 0))
                .unwrap_or(baseline_cfg.mixed_port),
            controller_port: ep.port,
            dns_port: ep.dns_port.unwrap_or(baseline_cfg.dns_listen_port),
            shifted: Vec::new(),
        };
        coordinator
            .seed_active_state(baseline_cfg, String::new(), seeded_ports, ep.secret.clone())
            .await;
    }

    let outcome = coordinator
        .apply_disk_reload(DiskReloadOptions {
            force: true,
            verify_with_binary,
            allow_l3_restart: false,
            allow_tun,
            ..DiskReloadOptions::default()
        })
        .await;
    let sanitized_outcome = redact_reload_outcome(&outcome);

    if sanitized_outcome.rejected || !sanitized_outcome.applied {
        let base_err = sanitized_outcome
            .error
            .clone()
            .unwrap_or_else(|| "hot reload rejected".to_string());
        let err_msg = if sanitized_outcome.level == ReloadLevel::L3CoreRestart {
            format!(
                "{base_err}；本次变更涉及监听端口、TUN 或底层内核参数（{}），请通过已提权的 CatCloud 桌面端执行内核重启生效。",
                if diff_reasons.is_empty() {
                    "L3 restart required".to_string()
                } else {
                    diff_reasons.join(", ")
                }
            )
        } else {
            base_err
        };
        let mut out = json!({
            "ok": false,
            "sanitized": true,
            "dry_run": false,
            "runtime_yaml_path": &redacted_runtime_yaml,
            "core_not_running": !core_running,
            "core_version": &live_controller_version,
            "trusted_controller_endpoint": trusted_endpoint,
            "hot_reloaded": false,
            "validated_and_written": false,
            "level": sanitized_outcome.level,
            "requires_l3_restart": sanitized_outcome.level == ReloadLevel::L3CoreRestart,
            "allow_l3_restart": false,
            "diff_reasons": &diff_reasons,
            "allow_tun": allow_tun,
            "live_tun_enabled": live_tun_enabled,
            "tun_preserved_via_live_core": tun_preserved_via_live_core,
            "tun_masked_no_elevation": tun_masked_no_elevation,
            "binary_verified": bin_res.found,
            "binary_path": &redacted_bin_path,
            "error": &err_msg,
            "outcome": &sanitized_outcome,
        });
        sanitize_json_value(&mut out);
        return Ok((false, out, format!("config reload failed: {err_msg}")));
    }

    let sha_preview = sanitized_outcome
        .config_hash
        .as_deref()
        .map(|h| &h[..h.len().min(12)])
        .unwrap_or("unknown");
    let mut out = json!({
        "ok": true,
        "sanitized": true,
        "dry_run": false,
        "runtime_yaml_path": &redacted_runtime_yaml,
        "core_not_running": !core_running,
        "core_version": &live_controller_version,
        "trusted_controller_endpoint": trusted_endpoint,
        "hot_reloaded": core_running,
        "validated_and_written": true,
        "allow_tun": allow_tun,
        "live_tun_enabled": live_tun_enabled,
        "tun_preserved_via_live_core": tun_preserved_via_live_core,
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
    sanitize_json_value(&mut out);
    let human = if core_running {
        format!(
            "Hot-reloaded runtime.yaml via controller ({}) and replayed {} group(s) (allow_tun={}, sha256={sha_preview}).",
            ctrl_addr, outcome.replayed_groups, allow_tun
        )
    } else {
        format!(
            "Core not running; validated and wrote {} (allow_tun={}, binary_verified={}, sha256={sha_preview}).",
            redacted_runtime_yaml, allow_tun, bin_res.found
        )
    };
    Ok((true, out, human))
}

async fn execute_config_reload(paths: &AppPaths, as_json: bool, dry_run: bool) -> Result<()> {
    let (ok, out, human) = run_config_reload_inner(paths, dry_run, None, true).await?;
    if !ok {
        if as_json {
            emit_output(true, &out, "")?;
            return Err(AlreadyEmittedJsonError(human).into());
        }
        anyhow::bail!("{human}");
    }
    emit_output(as_json, &out, &human)
}

#[derive(Debug, Default)]
struct CatCloudManagedProcessFilter {
    managed_pid: Option<u32>,
    managed_start_time_unix: Option<u64>,
    standalone_tunnel_pid: Option<u32>,
    standalone_tunnel_start_time_unix: Option<u64>,
    standalone_tunnel_binary_path: Option<PathBuf>,
    standalone_tunnel_socks_port: Option<u16>,
    mihomo_binary_path: Option<PathBuf>,
    owned_dirs: Vec<PathBuf>,
    live_controller_port: Option<u16>,
    verified_listener_pids: HashSet<u32>,
}

fn verify_managed_pid_with_start_time(
    candidate_pid: u32,
    candidate_name: &str,
    expected_pid: Option<u32>,
    expected_start_time: Option<u64>,
    actual_start_time: Option<u64>,
) -> bool {
    let Some(exp_pid) = expected_pid.filter(|&p| is_valid_managed_pid(p)) else {
        return false;
    };
    if candidate_pid != exp_pid || !is_valid_managed_pid(candidate_pid) {
        return false;
    }
    if !is_mihomo_like_process_name(candidate_name) {
        return false;
    }
    pid_start_time_matches_fail_closed(expected_start_time, actual_start_time)
}

fn is_mihomo_global_preaccel_process_name(name: Option<&str>) -> bool {
    name.is_some_and(|raw| raw.trim().to_ascii_lowercase().contains("mihomo"))
}

fn evaluate_live_global_preaccel_pid(
    meta: &GlobalPreAccelRuntimeMeta,
    actual_start_time: Option<u64>,
    non_windows_process_name: Option<Option<&str>>,
    listening_owners: Option<&[PortListenerOwner]>,
) -> bool {
    if !meta.running {
        return false;
    }
    let Some(pid) = meta.pid.filter(|&p| is_valid_managed_pid(p)) else {
        return false;
    };
    let Some(actual_ts) = actual_start_time else {
        return false;
    };
    if !pid_start_time_matches_fail_closed(meta.process_start_time_unix, Some(actual_ts)) {
        return false;
    }
    if let Some(proc_name) = non_windows_process_name {
        if !is_mihomo_global_preaccel_process_name(proc_name) {
            return false;
        }
    }
    if let Some(owners) = listening_owners {
        if !owners.is_empty()
            && !owners.iter().any(|o| {
                o.pid == pid
                    && is_valid_managed_pid(o.pid)
                    && pid_start_time_matches_fail_closed(
                        meta.process_start_time_unix,
                        o.process_start_time_unix,
                    )
            })
        {
            return false;
        }
    }
    true
}

fn is_live_global_preaccel_pid(meta: &GlobalPreAccelRuntimeMeta) -> bool {
    if !meta.running {
        return false;
    }
    let Some(pid) = meta.pid.filter(|&p| is_valid_managed_pid(p)) else {
        return false;
    };
    let actual_ts = get_process_start_time_unix(pid);
    #[cfg(not(target_os = "windows"))]
    let non_windows_proc_name_owned: Option<String> = list_process_candidates(false)
        .into_iter()
        .find(|c| c.pid == pid)
        .map(|c| c.name);
    #[cfg(not(target_os = "windows"))]
    let non_windows_proc_name = Some(non_windows_proc_name_owned.as_deref());
    #[cfg(target_os = "windows")]
    let non_windows_proc_name: Option<Option<&str>> = None;

    let owners = meta
        .socks_port
        .filter(|&p| p > 0)
        .map(|socks_port| list_listening_port_owners(&[socks_port]));

    evaluate_live_global_preaccel_pid(
        meta,
        actual_ts,
        non_windows_proc_name,
        owners.as_deref(),
    )
}

fn normalize_path_for_compare(path: &Path) -> String {
    let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let raw = resolved.to_string_lossy();
    let trimmed = raw.strip_prefix(r"\\?\").unwrap_or(&raw);
    let unified = trimmed.replace('\\', "/").trim_end_matches('/').to_string();
    if cfg!(target_os = "windows") {
        unified.to_ascii_lowercase()
    } else {
        unified
    }
}

fn path_matches_or_within_dir(candidate: &Path, dir: &Path) -> bool {
    let cand = normalize_path_for_compare(candidate);
    let base = normalize_path_for_compare(dir);
    if cand.is_empty() || base.is_empty() {
        return false;
    }
    cand == base || cand.strip_prefix(&base).is_some_and(|rest| rest.starts_with('/'))
}

fn extract_port_from_addr(addr: &str) -> Option<u16> {
    let trimmed = addr.trim();
    let (_, port_part) = trimmed.rsplit_once(':')?;
    port_part.trim().parse::<u16>().ok().filter(|&p| p > 0)
}

fn is_mihomo_like_process_name(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    let stem = lower.strip_suffix(".exe").unwrap_or(&lower);
    stem == "mihomo"
        || stem.starts_with("mihomo-")
        || stem.starts_with("mihomo_")
        || stem == "clash-meta"
        || stem == "catcloud"
}

fn is_catcloud_managed_proxy_process_with_start_time(
    candidate: &ProcessCandidate,
    filter: &CatCloudManagedProcessFilter,
    candidate_start_time_unix: Option<u64>,
) -> bool {
    // 1. Exact runtime PID recorded in `runtime-controller.json` or `global-preaccel-runtime.json`,
    //    strictly guarded by process name + OS creation time tolerance (<= 2s) against Windows PID reuse.
    if verify_managed_pid_with_start_time(
        candidate.pid,
        &candidate.name,
        filter.managed_pid,
        filter.managed_start_time_unix,
        candidate_start_time_unix,
    ) {
        return true;
    }
    if verify_managed_pid_with_start_time(
        candidate.pid,
        &candidate.name,
        filter.standalone_tunnel_pid,
        filter.standalone_tunnel_start_time_unix,
        candidate_start_time_unix,
    ) {
        return true;
    }

    if !is_mihomo_like_process_name(&candidate.name) {
        return false;
    }

    if filter.verified_listener_pids.contains(&candidate.pid) {
        return true;
    }

    // 2. Executable path matches resolved CatCloud mihomo binary (or standalone tunnel binary)
    //    or resides inside CatCloud's bin/data/install directories.
    if let Some(ref exe) = candidate.exe_path {
        let norm_exe = normalize_path_for_compare(exe);
        if let Some(ref resolved_bin) = filter.mihomo_binary_path {
            if norm_exe == normalize_path_for_compare(resolved_bin) {
                return true;
            }
        }
        if let Some(ref tunnel_bin) = filter.standalone_tunnel_binary_path {
            if norm_exe == normalize_path_for_compare(tunnel_bin) {
                return true;
            }
        }
        if filter
            .owned_dirs
            .iter()
            .any(|dir| path_matches_or_within_dir(exe, dir))
        {
            return true;
        }
    }

    // 3. Config dir / config file / command line arguments reference CatCloud's runtime/data dir.
    for detected in [
        candidate.detected_config_dir.as_deref(),
        candidate.detected_config_file.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if filter
            .owned_dirs
            .iter()
            .any(|dir| path_matches_or_within_dir(detected, dir))
        {
            return true;
        }
    }

    if !candidate.cmdline.is_empty() && !filter.owned_dirs.is_empty() {
        let norm_dirs: Vec<String> = filter
            .owned_dirs
            .iter()
            .map(|d| normalize_path_for_compare(d))
            .filter(|s| !s.is_empty())
            .collect();
        for arg in &candidate.cmdline {
            let norm_arg = arg.trim().trim_matches('"').replace('\\', "/");
            let cmp_arg = if cfg!(target_os = "windows") {
                norm_arg.to_ascii_lowercase()
            } else {
                norm_arg
            };
            if norm_dirs.iter().any(|dir| {
                cmp_arg == *dir
                    || cmp_arg
                        .strip_prefix(dir.as_str())
                        .is_some_and(|rest| rest.starts_with('/'))
            }) {
                return true;
            }
        }
    }

    // 4. Live controller port matches CatCloud's active controller port.
    if let (Some(live_port), Some(ref detected_ctrl)) = (
        filter.live_controller_port,
        candidate.detected_controller_addr.as_ref(),
    ) {
        if extract_port_from_addr(detected_ctrl) == Some(live_port) {
            return true;
        }
    }

    false
}

fn is_catcloud_managed_proxy_process(
    candidate: &ProcessCandidate,
    filter: &CatCloudManagedProcessFilter,
) -> bool {
    let start_ts = get_process_start_time_unix(candidate.pid);
    is_catcloud_managed_proxy_process_with_start_time(candidate, filter, start_ts)
}

fn collect_verified_listener_pids(
    owners: &[PortListenerOwner],
    managed_pid: Option<u32>,
    managed_start_time_unix: Option<u64>,
    standalone_tunnel_pid: Option<u32>,
    standalone_tunnel_start_time_unix: Option<u64>,
) -> HashSet<u32> {
    let mut verified_listener_pids = HashSet::new();
    for owner in owners {
        if !is_valid_managed_pid(owner.pid) {
            continue;
        }
        if let Some(mpid) = managed_pid.filter(|&p| is_valid_managed_pid(p)) {
            if owner.pid == mpid
                && pid_start_time_matches_fail_closed(
                    managed_start_time_unix,
                    owner.process_start_time_unix,
                )
            {
                verified_listener_pids.insert(owner.pid);
            }
        }
        if let Some(spid) = standalone_tunnel_pid.filter(|&p| is_valid_managed_pid(p)) {
            if owner.pid == spid
                && pid_start_time_matches_fail_closed(
                    standalone_tunnel_start_time_unix,
                    owner.process_start_time_unix,
                )
            {
                verified_listener_pids.insert(owner.pid);
            }
        }
    }
    verified_listener_pids
}

fn build_catcloud_managed_process_filter(
    paths: &AppPaths,
    mihomo_binary: Option<&Path>,
    core_running: bool,
    effective_ctrl_port: u16,
) -> CatCloudManagedProcessFilter {
    let mut owned_dirs: Vec<PathBuf> = vec![
        paths.bin_dir.clone(),
        paths.runtime_dir.clone(),
        paths.root_data_dir.clone(),
    ];
    if let Ok(cur_exe) = std::env::current_exe() {
        if let Some(exe_dir) = cur_exe.parent() {
            owned_dirs.push(exe_dir.to_path_buf());
            // Portable layout: `<InstallRoot>/cli/catcloud.exe` sibling of `<InstallRoot>/bin/mihomo.exe`.
            if exe_dir
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.eq_ignore_ascii_case("cli"))
            {
                if let Some(install_root) = exe_dir.parent() {
                    owned_dirs.push(install_root.to_path_buf());
                }
            }
        }
    }

    let live_core_meta = read_live_runtime_controller_meta(paths);
    let managed_pid = live_core_meta
        .as_ref()
        .and_then(|m| m.pid)
        .filter(|&p| is_valid_managed_pid(p));
    let managed_start_time_unix = live_core_meta
        .as_ref()
        .and_then(|m| m.process_start_time_unix);

    let global_meta = read_global_preaccel_runtime_meta(&paths.root_data_dir)
        .filter(is_live_global_preaccel_pid);
    let standalone_tunnel_pid = global_meta
        .as_ref()
        .and_then(|m| m.pid)
        .filter(|&p| is_valid_managed_pid(p));
    let standalone_tunnel_start_time_unix = global_meta
        .as_ref()
        .and_then(|m| m.process_start_time_unix);
    let standalone_tunnel_binary_path = global_meta
        .as_ref()
        .and_then(|m| m.binary_path.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let standalone_tunnel_socks_port = global_meta.as_ref().and_then(|m| m.socks_port);

    // Cross-check OS listening port ownership table for CatCloud's verified live controller
    // and standalone 443 tunnel ports, enforcing fail-closed start-time tolerance against PID reuse.
    let mut watched_ports = Vec::new();
    if core_running && effective_ctrl_port > 0 {
        watched_ports.push(effective_ctrl_port);
    }
    if let Some(m) = &live_core_meta {
        if let Some(mp) = m.mixed_port {
            watched_ports.push(mp);
        }
        if let Some(dp) = m.dns_port {
            watched_ports.push(dp);
        }
    }
    if let Some(sp) = standalone_tunnel_socks_port {
        watched_ports.push(sp);
    }
    watched_ports.sort_unstable();
    watched_ports.dedup();

    let owners = list_listening_port_owners(&watched_ports);
    let verified_listener_pids = collect_verified_listener_pids(
        &owners,
        managed_pid,
        managed_start_time_unix,
        standalone_tunnel_pid,
        standalone_tunnel_start_time_unix,
    );

    CatCloudManagedProcessFilter {
        managed_pid,
        managed_start_time_unix,
        standalone_tunnel_pid,
        standalone_tunnel_start_time_unix,
        standalone_tunnel_binary_path,
        standalone_tunnel_socks_port,
        mihomo_binary_path: mihomo_binary.map(Path::to_path_buf),
        owned_dirs,
        live_controller_port: if core_running {
            Some(effective_ctrl_port)
        } else {
            None
        },
        verified_listener_pids,
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

    let mut checks: Vec<Value> = Vec::with_capacity(8);
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
    let active_ports = inspect_active_core_ports(paths, &cfg).await;
    let live_version = active_ports.core_version.clone();
    let controller_auth_err = active_ports.controller_auth_error.clone();
    let ctrl_ep = active_ports.endpoint.clone();
    let core_running = active_ports.core_running;
    let effective_mixed_port = active_ports.effective_mixed_port;
    let effective_ctrl_port = active_ports.effective_controller_port;
    let effective_dns_port = active_ports.effective_dns_port;
    let third_party_port_conflicts = active_ports.third_party_conflicts_for_effective_ports(&cfg);
    let owned_by_active_core = active_ports.all_active_ports_owned_by_core();

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
    } else if !third_party_port_conflicts.is_empty() {
        recommendations.push(
            "One or more configured CatCloud ports are occupied by a non-CatCloud process; enable port_guard_auto_shift or free conflicting ports."
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
    let port_label = |port: u16, free: bool, owned: bool| -> String {
        if owned {
            format!("{port}:owned_by_active_core")
        } else if free {
            format!("{port}:free")
        } else {
            format!("{port}:occupied_conflict")
        }
    };
    checks.push(json!({
        "id": "core_and_ports",
        "layer": 3,
        "name": "Core Binary & Listening Ports",
        "status": core_status,
        "detail": format!(
            "binary_found={}, core_running={}, owned_by_active_core={}, ports(mixed={}, ctrl={}, dns={})",
            bin_res.found,
            core_running,
            owned_by_active_core,
            port_label(effective_mixed_port, active_ports.mixed_free, active_ports.mixed_owned_by_active_core),
            port_label(effective_ctrl_port, active_ports.controller_free, active_ports.controller_owned_by_active_core),
            port_label(effective_dns_port, active_ports.dns_free, active_ports.dns_owned_by_active_core)
        ),
        "data": {
            "binary_found": bin_res.found,
            "binary_source": bin_res.source,
            "binary_path": bin_res.path.as_ref().map(|p| redact_path_for_display(&p.to_string_lossy())),
            "core_running": core_running,
            "core_version": live_version,
            "controller_auth_error": controller_auth_err,
            "owned_by_active_core": owned_by_active_core,
            "port_guard_auto_shift": cfg.port_guard_auto_shift,
            "third_party_port_conflicts": third_party_port_conflicts,
            "ports": active_ports.to_status_json(),
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
    let has_live_tun_connections = if core_running {
        probe_live_tun_connections(&ctrl_ep).await
    } else {
        false
    };
    let live_tun_enable = active_ports.live_config.as_ref().map(|lc| lc.tun_enable);
    let (tun_effective_enabled, tun_needs_admin, tun_runtime_source) = evaluate_doctor_tun_state(
        tun_configured,
        tun_privilege_ready,
        core_running,
        has_live_tun_connections,
        live_tun_enable,
    );
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
            "cfg_sys_proxy={}, tun_configured={}, tun_enabled={}, tun_needs_elevation={}, tun_source={}, tun_stack={}, elevated={}, os_proxy_mismatch={}, os_proxy_dangling={}",
            cfg.system_proxy.enabled,
            tun_configured,
            tun_effective_enabled,
            tun_needs_admin,
            tun_runtime_source,
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
            "live_tun_connections_detected": has_live_tun_connections,
            "tun_runtime_source": tun_runtime_source,
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
    let transport_snap = collect_cli_preaccel_transport_snapshot(
        paths,
        &cfg,
        &nodes,
        &groups,
        &relays,
        &active_ports,
        tun_effective_enabled,
        compile_stats.as_ref().map(|s| s.effective_tun_mtu),
    )
    .await;
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
            "transport_diagnostics": &transport_snap.diagnostics,
            "active_relay_selected": &transport_snap.active_relay_selected,
            "active_exit_selected": &transport_snap.active_exit_selected,
            "runtime_config_sha256": &transport_snap.runtime_config_sha256,
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
    let managed_proc_filter = build_catcloud_managed_process_filter(
        paths,
        bin_res.path.as_deref(),
        core_running,
        effective_ctrl_port,
    );
    let other_proxy_procs: Vec<Value> = list_process_candidates(true)
        .into_iter()
        .filter(|p| !is_catcloud_managed_proxy_process(p, &managed_proc_filter))
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
        if core_running
            && (p == cfg.mixed_port
                || p == cfg.controller_port
                || p == effective_mixed_port
                || p == effective_ctrl_port)
        {
            continue;
        }
        if managed_proc_filter.standalone_tunnel_socks_port == Some(p) {
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
    let mut geodata = collect_geodata_status(&paths.runtime_dir);
    let has_country_mmdb = geodata["country_mmdb"]["exists"].as_bool().unwrap_or(false);
    let has_geosite = geodata["geosite_dat"]["exists"].as_bool().unwrap_or(false);
    let mut missing_geodata_files: Vec<&str> = Vec::new();
    if !has_country_mmdb {
        missing_geodata_files.push("Country.mmdb");
    }
    if !has_geosite {
        missing_geodata_files.push("geosite.dat");
    }
    let geodata_impact_scope = if missing_geodata_files.is_empty() {
        json!({
            "missing_files": [],
            "explicit_domain_rules_unaffected": true,
            "affected_traffic_zh": "GeoData 完整，依赖 GeoIP/GeoSite 的国内直连与显式域名规则均正常工作。",
            "affected_traffic": "GeoData databases are complete; both GeoIP/GeoSite domestic direct rules and explicit domain rules are active.",
        })
    } else {
        json!({
            "missing_files": &missing_geodata_files,
            "explicit_domain_rules_unaffected": true,
            "affected_traffic_zh": "缺失 GeoData 仅影响依赖 GeoIP/GeoSite 的未显式列出国内域名与国内 IP 自动直连判定（可能误走代理）；已写明的 DOMAIN/DOMAIN-SUFFIX/IP-CIDR 规则（如内置 AI 域名、QQ/微信与自定义规则）不受影响。",
            "affected_traffic": "Missing GeoData only affects unlisted domestic domains/IPs relying on GeoIP/GeoSite auto-direct rules; explicit DOMAIN/DOMAIN-SUFFIX/IP-CIDR rules (AI domains, domestic IM, custom rules) are unaffected.",
        })
    };
    if let Some(obj) = geodata.as_object_mut() {
        obj.insert("impact_scope".to_string(), geodata_impact_scope.clone());
    }
    let geo_status = if cfg.rules_override.domestic_direct_enabled && !has_country_mmdb {
        recommendations.push(
            "Country.mmdb is missing while domestic direct routing is enabled (only affects unlisted domestic domains/IPs relying on GeoIP/GeoSite; explicit domain rules remain unaffected); refresh GeoData in Settings."
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
        "detail": format!(
            "country_mmdb={has_country_mmdb}, geosite_dat={has_geosite} ({})",
            if missing_geodata_files.is_empty() {
                "complete"
            } else {
                "missing files only affect GeoIP/GeoSite rules; explicit domain rules unaffected"
            }
        ),
        "data": geodata,
    }));

    // Check 8: Encrypted DNS TLS certificate verification health (256 KiB window across catcloud.log & .1)
    let dns_tls_diag = analyze_dns_tls_across_logs(&paths.logs_dir, 256 * 1024);
    let dns_tls_status = match dns_tls_diag.status.as_str() {
        DNS_TLS_STATUS_CERT_FAILED => {
            recommendations.push(format!(
                "{}: {} (upstreams={:?}; TLS verification preserved)",
                dns_tls_diag.category,
                dns_tls_diag.next_retry_hint,
                dns_tls_diag.affected_upstreams
            ));
            "fail"
        }
        DNS_TLS_STATUS_DEGRADED_RECOVERED => {
            recommendations.push(format!(
                "{}: {} (upstreams={:?})",
                dns_tls_diag.category,
                dns_tls_diag.next_retry_hint,
                dns_tls_diag.affected_upstreams
            ));
            "warn"
        }
        _ => "pass",
    };
    checks.push(json!({
        "id": "dns_tls_health",
        "layer": 4,
        "name": "Encrypted DNS TLS Certificate Health",
        "status": dns_tls_status,
        "detail": format!(
            "status={}, failures={}, recovered={}, dot_853_timeouts={}, tls_verified={}",
            dns_tls_diag.status,
            dns_tls_diag.failure_count,
            dns_tls_diag.recovered,
            dns_tls_diag.network_timeout_only_count,
            dns_tls_diag.tls_verification_preserved
        ),
        "data": dns_tls_diag,
    }));

    let pass_count = checks.iter().filter(|c| c["status"] == "pass").count();
    let warn_count = checks.iter().filter(|c| c["status"] == "warn").count();
    let fail_count = checks.iter().filter(|c| c["status"] == "fail").count();
    let healthy = fail_count == 0;

    let mut out = json!({
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
        "preaccel_transport_diagnostics": &transport_snap.diagnostics,
        "active_relay_selected": &transport_snap.active_relay_selected,
        "active_exit_selected": &transport_snap.active_exit_selected,
        "runtime_config_sha256": &transport_snap.runtime_config_sha256,
        "checks": &checks,
        "recommendations": &recommendations,
    });
    sanitize_json_value(&mut out);
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

    let geodata_status = collect_geodata_status(&paths.runtime_dir);
    let has_country_mmdb = geodata_status["country_mmdb"]["exists"]
        .as_bool()
        .unwrap_or(false);
    let has_geosite_dat = geodata_status["geosite_dat"]["exists"]
        .as_bool()
        .unwrap_or(false);
    let mut missing_geodata_files: Vec<&str> = Vec::new();
    if !has_country_mmdb {
        missing_geodata_files.push("Country.mmdb");
    }
    if !has_geosite_dat {
        missing_geodata_files.push("geosite.dat");
    }
    let geodata_impact_scope = if missing_geodata_files.is_empty() {
        json!({
            "missing_files": [],
            "explicit_domain_rules_unaffected": true,
            "affected_traffic_zh": "GeoData 完整，GeoIP/GeoSite 与显式域名规则均有效。",
            "affected_traffic": "GeoData files are present; both GeoIP/GeoSite and explicit domain rules apply.",
        })
    } else {
        json!({
            "missing_files": &missing_geodata_files,
            "explicit_domain_rules_unaffected": true,
            "affected_traffic_zh": "缺失 GeoData 仅影响依赖 GeoIP/GeoSite 的未显式列出国内域名/IP；已写明的域名与 IP-CIDR 规则不受影响。",
            "affected_traffic": "Missing GeoData only affects unlisted domestic domains/IPs relying on GeoIP/GeoSite; explicit domain/IP-CIDR rules are unaffected.",
        })
    };

    let geo_note = if !skipped_geo_rules.is_empty() {
        if !missing_geodata_files.is_empty() {
            Some("Offline rule simulation cannot inspect binary GeoSite/GeoIP databases, and GeoData files are currently missing on disk (缺失 GeoData 仅影响依赖 GeoIP/GeoSite 的未列国内域名/IP，已写明域名规则不受影响).")
        } else {
            Some("Offline rule simulation cannot inspect binary GeoSite/GeoIP databases; live Mihomo core may match an earlier GEOSITE/GEOIP rule before the fallback result shown here.")
        }
    } else if !missing_geodata_files.is_empty() {
        Some("GeoData files are missing on disk (缺失 GeoData 仅影响依赖 GeoIP/GeoSite 的未列国内域名/IP，当前已写明域名规则不受影响).")
    } else {
        None
    };

    let mut out = json!({
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
        "geodata_missing_files": missing_geodata_files,
        "geodata_impact_scope": geodata_impact_scope,
    });
    sanitize_json_value(&mut out);
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

fn resolve_effective_preaccel_carrier(
    cfg: &AppConfig,
    has_enabled_relays: bool,
    is_direct_mode: bool,
    core_running: bool,
    live_tun_enabled: bool,
    runtime_meta: Option<&GlobalPreAccelRuntimeMeta>,
    standalone_pid_alive: bool,
) -> (&'static str, bool, bool, &'static str) {
    // Returns (effective_carrier, standalone_tunnel_running, standalone_tunnel_suspended_for_tun, runtime_mode)
    // Strictly aligned with Desktop `resolve_preaccel_effective_carrier` 5-state contract.
    if standalone_pid_alive {
        if let Some(meta) = runtime_meta {
            if meta.mode == "windivert" {
                return ("standalone_windivert", true, false, "windivert");
            }
            return ("standalone_socks5", true, false, "local_socks5");
        }
    }

    if !cfg.preaccel.enabled || !has_enabled_relays || is_direct_mode {
        return ("off", false, false, "off");
    }

    if core_running && live_tun_enabled {
        return (
            "main_core_tun_suspended_standalone",
            false,
            true,
            "suspended_for_tun",
        );
    }

    if core_running {
        return ("main_core_proxy_only", false, false, "off");
    }

    ("off", false, false, "off")
}

#[derive(Debug, Clone)]
struct CliPreAccelTransportSnapshot {
    diagnostics: PreAccelTransportDiagnostics,
    active_relay_selected: Option<String>,
    active_exit_selected: Option<String>,
    runtime_config_sha256: Option<String>,
}

fn read_tun_mtu_from_runtime_yaml(runtime_yaml_path: &Path) -> Option<u16> {
    catcloud_core::core_adapter::hot_reload::read_runtime_yaml_tun_mtu(runtime_yaml_path)
}

fn estimate_effective_tun_mtu(
    cfg: &AppConfig,
    relays: &[PreAccelRelay],
    nodes: &[ProxyNode],
) -> u16 {
    let enabled_relays: Vec<&PreAccelRelay> = relays.iter().filter(|r| r.enabled).collect();
    if !cfg.preaccel.enabled || enabled_relays.is_empty() {
        return cfg.tun.mtu;
    }
    let relays_support_ipv6 = enabled_relays.iter().all(|r| r.supports_ipv6);
    let has_dialer_wrapped = nodes.iter().any(|node| {
        if !node.enabled || !node.should_apply_preaccel(cfg.preaccel.skip_443_native) {
            return false;
        }
        let skip_for_ipv6 =
            !relays_support_ipv6 && is_ipv6_only_node(node) && node.preaccel_override != Some(true);
        !skip_for_ipv6
    });
    if has_dialer_wrapped {
        cfg.tun.mtu.min(1400)
    } else {
        cfg.tun.mtu
    }
}

fn decode_http_chunked_body(raw: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor < raw.len() {
        let rel_crlf = raw[cursor..].windows(2).position(|w| w == b"\r\n")?;
        let size_line = std::str::from_utf8(&raw[cursor..cursor + rel_crlf]).ok()?;
        let size_hex = size_line.split(';').next()?.trim();
        let chunk_len = usize::from_str_radix(size_hex, 16).ok()?;
        cursor += rel_crlf + 2;
        if chunk_len == 0 {
            return Some(out);
        }
        if cursor.checked_add(chunk_len)?.checked_add(2)? > raw.len() {
            return None;
        }
        out.extend_from_slice(&raw[cursor..cursor + chunk_len]);
        cursor += chunk_len + 2;
    }
    Some(out)
}

fn resolve_proxy_chain_now(
    proxies: &serde_json::Map<String, Value>,
    start_group: &str,
) -> Option<String> {
    let mut current = start_group.trim();
    if current.is_empty() {
        return None;
    }
    let mut visited: HashSet<String> = HashSet::new();
    let mut selected: Option<String> = None;

    for _ in 0..8 {
        if !visited.insert(current.to_string()) {
            break;
        }
        let Some(entry) = proxies.get(current) else {
            break;
        };
        let Some(next) = entry
            .get("now")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            break;
        };
        selected = Some(next.to_string());
        let next_has_now = proxies
            .get(next)
            .and_then(|v| v.get("now"))
            .and_then(Value::as_str)
            .map(str::trim)
            .is_some_and(|s| !s.is_empty());
        if next_has_now {
            current = next;
        } else {
            break;
        }
    }

    selected
}

async fn query_live_controller_selected_proxies(
    ep: &ResolvedControllerEndpoint,
    cfg: &AppConfig,
    groups: &[MultiGroup],
    live_mode: Option<&str>,
) -> (Option<String>, Option<String>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    const MAX_PROXIES_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
    let connect_host = match ep.host.trim() {
        "" | "0.0.0.0" | "*" => "127.0.0.1",
        "::" | "[::]" => "::1",
        other => other.trim_start_matches('[').trim_end_matches(']'),
    };
    let host_header = format_host_port(connect_host, ep.port);
    let auth_header = if ep.secret.trim().is_empty() {
        String::new()
    } else {
        format!("Authorization: Bearer {}\r\n", ep.secret.trim())
    };
    let request = format!(
        "GET /proxies HTTP/1.1\r\nHost: {host_header}\r\n{auth_header}Accept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
    );

    let raw_resp = tokio::time::timeout(Duration::from_secs(2), async {
        let mut stream = TcpStream::connect((connect_host, ep.port)).await.ok()?;
        stream.write_all(request.as_bytes()).await.ok()?;
        let mut buf: Vec<u8> = Vec::with_capacity(4096);
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                break;
            }
            if buf.len().saturating_add(n) > MAX_PROXIES_RESPONSE_BYTES {
                return None;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        Some(buf)
    })
    .await
    .ok()
    .flatten();

    let Some(raw) = raw_resp else {
        return (None, None);
    };
    let Some(header_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return (None, None);
    };
    let headers_str = String::from_utf8_lossy(&raw[..header_end]);
    let status_ok = headers_str
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .is_some_and(|code| (200..300).contains(&code));
    if !status_ok {
        return (None, None);
    }

    let is_chunked = headers_str.lines().any(|line| {
        line.split_once(':').is_some_and(|(k, v)| {
            k.trim().eq_ignore_ascii_case("transfer-encoding")
                && v.to_ascii_lowercase().contains("chunked")
        })
    });
    let raw_body = &raw[header_end + 4..];
    let decoded_body;
    let body_bytes: &[u8] = if is_chunked {
        let Some(decoded) = decode_http_chunked_body(raw_body) else {
            return (None, None);
        };
        decoded_body = decoded;
        &decoded_body
    } else {
        raw_body
    };

    let Ok(parsed) = serde_json::from_slice::<Value>(body_bytes) else {
        return (None, None);
    };
    let Some(proxies) = parsed.get("proxies").and_then(Value::as_object) else {
        return (None, None);
    };

    let active_relay_selected = resolve_proxy_chain_now(proxies, PREACCEL_SELECT_GROUP_NAME);

    let is_global_mode = live_mode
        .map(str::trim)
        .filter(|m| !m.is_empty())
        .map(|m| m.eq_ignore_ascii_case("global"))
        .unwrap_or(cfg.proxy_mode == ProxyMode::Global);

    let mut exit_candidates: Vec<String> = Vec::new();
    if is_global_mode {
        exit_candidates.push("GLOBAL".to_string());
    }
    if cfg.route_mode == RouteTargetMode::Single {
        exit_candidates.push(SINGLE_NODE_GROUP_NAME.to_string());
    }
    if let Some(active_gid) = cfg
        .active_group_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if let Some(group) = groups.iter().find(|g| g.id.trim() == active_gid) {
            let gname = if group.name.trim().is_empty() {
                group.id.trim()
            } else {
                group.name.trim()
            };
            if !gname.is_empty() {
                exit_candidates.push(gname.to_string());
            }
        }
    }
    if let Some(first_group) = groups.first() {
        let gname = if first_group.name.trim().is_empty() {
            first_group.id.trim()
        } else {
            first_group.name.trim()
        };
        if !gname.is_empty() && !exit_candidates.iter().any(|c| c == gname) {
            exit_candidates.push(gname.to_string());
        }
    }
    for fallback_name in [
        DEFAULT_FALLBACK_GROUP_NAME,
        SINGLE_NODE_GROUP_NAME,
        "GLOBAL",
    ] {
        if !exit_candidates.iter().any(|c| c == fallback_name) {
            exit_candidates.push(fallback_name.to_string());
        }
    }

    let active_exit_selected = exit_candidates
        .iter()
        .find_map(|group_name| resolve_proxy_chain_now(proxies, group_name));

    (active_relay_selected, active_exit_selected)
}

#[allow(clippy::too_many_arguments)]
async fn collect_cli_preaccel_transport_snapshot(
    paths: &AppPaths,
    cfg: &AppConfig,
    nodes: &[ProxyNode],
    groups: &[MultiGroup],
    relays: &[PreAccelRelay],
    active_ports: &ActiveCorePortState,
    tun_enabled: bool,
    compiled_effective_tun_mtu: Option<u16>,
) -> CliPreAccelTransportSnapshot {
    let has_enabled_relays = relays.iter().any(|r| r.enabled);
    let live_mode = active_ports
        .live_config
        .as_ref()
        .map(|lc| lc.mode.as_str());
    let is_direct_mode = live_mode
        .map(str::trim)
        .filter(|m| !m.is_empty())
        .map(|m| m.eq_ignore_ascii_case("direct"))
        .unwrap_or(cfg.proxy_mode == ProxyMode::Direct);
    let raw_meta = read_global_preaccel_runtime_meta(&paths.root_data_dir);
    let standalone_pid_alive = raw_meta.as_ref().is_some_and(is_live_global_preaccel_pid);
    let (effective_carrier, standalone_tunnel_running, _, runtime_mode) =
        resolve_effective_preaccel_carrier(
            cfg,
            has_enabled_relays,
            is_direct_mode,
            active_ports.core_running,
            tun_enabled,
            raw_meta.as_ref(),
            standalone_pid_alive,
        );
    let effective_mode = if standalone_tunnel_running && runtime_mode == "windivert" {
        "windivert"
    } else if standalone_tunnel_running {
        "local_socks5"
    } else if effective_carrier == "main_core_tun_suspended_standalone" {
        "main-tun-core"
    } else if effective_carrier == "main_core_proxy_only" {
        "main-proxy-core"
    } else {
        "off"
    };

    let runtime_yaml_path = paths.runtime_dir.join("runtime.yaml");
    let runtime_config_sha256 = runtime_yaml_path
        .is_file()
        .then(|| compute_file_sha256(&runtime_yaml_path).ok())
        .flatten();

    let effective_tun_mtu = active_ports
        .core_running
        .then(|| read_tun_mtu_from_runtime_yaml(&runtime_yaml_path))
        .flatten()
        .or(compiled_effective_tun_mtu)
        .unwrap_or_else(|| estimate_effective_tun_mtu(cfg, relays, nodes));

    let diagnostics =
        build_preaccel_transport_diagnostics(cfg, effective_tun_mtu, effective_mode);

    let (active_relay_selected, active_exit_selected) = if active_ports.core_running {
        query_live_controller_selected_proxies(&active_ports.endpoint, cfg, groups, live_mode).await
    } else {
        (None, None)
    };

    CliPreAccelTransportSnapshot {
        diagnostics,
        active_relay_selected,
        active_exit_selected,
        runtime_config_sha256,
    }
}

async fn build_status_payload(paths: &AppPaths) -> Result<(Value, String)> {
    let cfg = config::load_or_init(paths)?;
    let db = open_storage(paths)?;
    let plat = default_platform();
    let caps = plat.capabilities();
    let mihomo_bin = resolve_mihomo_binary(&cfg, paths, &[], false)
        .ok()
        .and_then(|r| r.path);
    let tun_configured = cfg.tun.enabled;
    let active_ports = inspect_active_core_ports(paths, &cfg).await;
    let (tun_enabled, tun_needs_elevation, tun_runtime_source) =
        resolve_cli_effective_tun_state_with_probe(
            &cfg,
            &caps,
            mihomo_bin.as_deref(),
            &active_ports,
        )
        .await;
    let wd_files = locate_windivert_files(paths, cfg.preaccel.windivert_dir.as_deref());
    let subs = db.list_subscriptions()?;
    let nodes = db.list_nodes()?;
    let groups = db.list_multi_groups()?;
    let relays = db.list_preaccel_relays(false)?;
    let probe_count = db.list_probe_definitions()?.len();
    let sub_count = subs.len();
    let node_count = nodes.len();
    let group_count = groups.len();
    let relay_count = relays.len();
    let eff_mixed = active_ports.effective_mixed_port;
    let eff_ctrl = active_ports.effective_controller_port;
    let eff_dns = active_ports.effective_dns_port;
    let transport_snap = collect_cli_preaccel_transport_snapshot(
        paths,
        &cfg,
        &nodes,
        &groups,
        &relays,
        &active_ports,
        tun_enabled,
        None,
    )
    .await;

    let mut out = json!({
        "ok": true,
        "sanitized": true,
        "version": env!("CARGO_PKG_VERSION"),
        "data_dir": redact_path_for_display(&paths.root_data_dir.to_string_lossy()),
        "is_portable": paths.is_portable,
        "instance_hash": paths.instance_hash,
        "platform": caps,
        "core_running": active_ports.core_running,
        "core_version": &active_ports.core_version,
        "proxy_mode": cfg.proxy_mode,
        "system_proxy_enabled": cfg.system_proxy.enabled,
        "tun_enabled": tun_enabled,
        "tun_configured": tun_configured,
        "tun_needs_elevation": tun_needs_elevation,
        "tun_source": tun_runtime_source,
        "mixed_port": eff_mixed,
        "controller_addr": format_host_port(&active_ports.endpoint.host, eff_ctrl),
        "dns_listen_addr": format_host_port(&cfg.dns_listen_host, eff_dns),
        "ports": active_ports.to_status_json(),
        "preaccel_enabled": cfg.preaccel.enabled,
        "preaccel_transport_diagnostics": &transport_snap.diagnostics,
        "active_relay_selected": &transport_snap.active_relay_selected,
        "active_exit_selected": &transport_snap.active_exit_selected,
        "runtime_config_sha256": &transport_snap.runtime_config_sha256,
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
    sanitize_json_value(&mut out);

    let tun_summary = if tun_needs_elevation {
        "needs_elevation"
    } else if tun_enabled {
        "true"
    } else {
        "false"
    };
    let human = format!(
        "CatCloud CLI v{} | core_running={} | portable={} | mode={} | port={} | tun={} | nodes={} | groups={} | global_preaccel={} (windivert={})",
        env!("CARGO_PKG_VERSION"),
        active_ports.core_running,
        paths.is_portable,
        cfg.proxy_mode.as_str(),
        eff_mixed,
        tun_summary,
        node_count,
        group_count,
        cfg.preaccel.global_bypass_enabled,
        wd_files.is_some()
    );
    Ok((out, human))
}

async fn build_global_preaccel_status_payload(paths: &AppPaths) -> Result<(Value, String)> {
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

    let active_ports = inspect_active_core_ports(paths, &cfg).await;
    let core_running = active_ports.core_running;
    let live_tun_enabled = if core_running {
        active_ports
            .live_config
            .as_ref()
            .map(|lc| lc.tun_enable)
            .unwrap_or(false)
            || probe_live_tun_connections(&active_ports.endpoint).await
    } else {
        false
    };

    let has_enabled_relays = !enabled_relays.is_empty();
    let is_direct_mode = active_ports
        .live_config
        .as_ref()
        .map(|lc| lc.mode.trim())
        .filter(|m| !m.is_empty())
        .map(|m| m.eq_ignore_ascii_case("direct"))
        .unwrap_or(cfg.proxy_mode == ProxyMode::Direct);
    let raw_meta = read_global_preaccel_runtime_meta(&paths.root_data_dir);
    let standalone_pid_alive = raw_meta.as_ref().is_some_and(is_live_global_preaccel_pid);
    let runtime_meta_stale = raw_meta.as_ref().is_some_and(|m| {
        (m.running && !standalone_pid_alive)
            || (m.mode == "suspended_for_tun"
                && (!core_running || !live_tun_enabled || is_direct_mode || !has_enabled_relays))
    });
    let (
        effective_carrier,
        standalone_tunnel_running,
        standalone_tunnel_suspended_for_tun,
        runtime_mode,
    ) = resolve_effective_preaccel_carrier(
        &cfg,
        has_enabled_relays,
        is_direct_mode,
        core_running,
        live_tun_enabled,
        raw_meta.as_ref(),
        standalone_pid_alive,
    );
    let live_socks_port = if standalone_tunnel_running {
        raw_meta.as_ref().and_then(|m| m.socks_port)
    } else {
        None
    };

    let mut out = json!({
        "ok": true,
        "sanitized": true,
        "os": caps.os,
        "arch": caps.arch,
        "is_elevated": caps.is_elevated,
        "core_running": core_running,
        "live_tun_enabled": live_tun_enabled,
        "global_bypass_enabled": cfg.preaccel.global_bypass_enabled,
        "global_scope": cfg.preaccel.global_scope,
        "dispatch_strategy": cfg.preaccel.dispatch_strategy,
        "lb_strategy": cfg.preaccel.lb_strategy,
        "global_target_processes": cfg.preaccel.global_target_processes,
        "windivert_dir": cfg.preaccel.windivert_dir.as_deref().map(redact_path_for_display),
        "windivert_available": windivert_available,
        "windivert_dll": wd_files.as_ref().map(|(dll, _)| redact_path_for_display(&dll.to_string_lossy())),
        "windivert_sys": wd_files.as_ref().map(|(_, sys)| redact_path_for_display(&sys.to_string_lossy())),
        "mihomo_available": bin_res.found,
        "enabled_relay_count": active_relay_names.len(),
        "active_relays": active_relay_names,
        "recommended_mode": recommended_mode,
        "runtime_mode": runtime_mode,
        "effective_carrier": effective_carrier,
        "standalone_tunnel_running": standalone_tunnel_running,
        "standalone_tunnel_suspended_for_tun": standalone_tunnel_suspended_for_tun,
        "standalone_socks_port": live_socks_port,
        "runtime_meta_stale": runtime_meta_stale,
    });
    sanitize_json_value(&mut out);

    let human = format!(
        "Global Pre-Accel: enabled={} | carrier={} | standalone_running={} | suspended_for_tun={} | scope={} | dispatch={} | relays={} | windivert_ready={} | elevated={} | recommended_mode={}",
        cfg.preaccel.global_bypass_enabled,
        effective_carrier,
        standalone_tunnel_running,
        standalone_tunnel_suspended_for_tun,
        cfg.preaccel.global_scope.as_str(),
        cfg.preaccel.dispatch_strategy.as_str(),
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

async fn resolve_cli_effective_tun_state_with_probe(
    cfg: &AppConfig,
    caps: &catcloud_core::platform::PlatformCapabilities,
    mihomo_binary: Option<&Path>,
    active_ports: &ActiveCorePortState,
) -> (bool, bool, &'static str) {
    let tun_privilege_ready = is_cli_tun_privilege_ready(caps, mihomo_binary);
    let tun_configured = cfg.tun.enabled;
    let core_running = active_ports.core_running;
    let has_live_tun_connections = if core_running {
        probe_live_tun_connections(&active_ports.endpoint).await
    } else {
        false
    };
    let live_tun_enable = active_ports.live_config.as_ref().map(|lc| lc.tun_enable);
    evaluate_doctor_tun_state(
        tun_configured,
        tun_privilege_ready,
        core_running,
        has_live_tun_connections,
        live_tun_enable,
    )
}

async fn resolve_cli_effective_tun_state(
    paths: &AppPaths,
    cfg: &AppConfig,
    caps: &catcloud_core::platform::PlatformCapabilities,
    mihomo_binary: Option<&Path>,
) -> (bool, bool, &'static str) {
    let active_ports = inspect_active_core_ports(paths, cfg).await;
    resolve_cli_effective_tun_state_with_probe(cfg, caps, mihomo_binary, &active_ports).await
}

async fn build_diag_payload(paths: &AppPaths, reveal_secrets: bool) -> Result<Value> {
    let cfg = config::load_or_init(paths)?;
    let db = open_storage(paths)?;
    let plat = default_platform();
    let caps = plat.capabilities();
    let mihomo_bin = resolve_mihomo_binary(&cfg, paths, &[], false)
        .ok()
        .and_then(|r| r.path);
    let tun_configured = cfg.tun.enabled;
    let (tun_enabled, tun_needs_elevation, tun_runtime_source) =
        resolve_cli_effective_tun_state(paths, &cfg, &caps, mihomo_bin.as_deref()).await;
    let geodata_status = collect_geodata_status(&paths.runtime_dir);
    let wd_files = locate_windivert_files(paths, cfg.preaccel.windivert_dir.as_deref());
    let recent_logs = read_diag_log_tail(
        &paths.logs_dir.join("catcloud.log"),
        MAX_DIAG_LOG_LINES,
        !reveal_secrets,
    );
    let dns_diagnostics = analyze_dns_tls_across_logs(&paths.logs_dir, 256 * 1024);
    let relays = db.list_preaccel_relays(false)?;
    let enabled_relay_count = relays.iter().filter(|r| r.enabled).count();

    let mut warnings: Vec<String> = Vec::new();
    if dns_diagnostics.status == DNS_TLS_STATUS_CERT_FAILED {
        warnings.push(format!(
            "{}: {}",
            dns_diagnostics.category, dns_diagnostics.next_retry_hint
        ));
    } else if dns_diagnostics.status == DNS_TLS_STATUS_DEGRADED_RECOVERED {
        warnings.push(format!(
            "{}（已自动恢复）: {}",
            dns_diagnostics.category, dns_diagnostics.next_retry_hint
        ));
    }
    if tun_needs_elevation {
        warnings.push(
            "TUN 模式已在配置中开启，但当前进程缺少管理员/TUN 权限，需要提权后生效。".to_string(),
        );
    }
    if cfg.rules_override.domestic_direct_enabled
        && !geodata_status["country_mmdb"]["exists"]
            .as_bool()
            .unwrap_or(false)
    {
        warnings.push(
            "缺失 Country.mmdb（仅影响依赖 GeoIP/GeoSite 的未列国内域名/IP，已写明域名规则不受影响）。"
                .to_string(),
        );
    }
    if cfg.preaccel.enabled && enabled_relay_count == 0 {
        warnings.push("国内提速已开启，但当前没有已启用的国内 443 中转节点。".to_string());
    }

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
        "tun_source": tun_runtime_source,
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
        "dns_diagnostics": dns_diagnostics,
        "warnings": warnings,
        "recent_logs": recent_logs,
        "counts": {
            "subscriptions": db.list_subscriptions()?.len(),
            "nodes": db.list_nodes()?.len(),
            "multi_groups": db.list_multi_groups()?.len(),
            "preaccel_relays": relays.len(),
        }
    });
    if reveal_secrets {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("controller_secret".to_string(), json!(cfg.controller_secret));
        }
    } else {
        sanitize_json_value(&mut payload);
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

    #[tokio::test]
    async fn diag_payload_aligns_country_mmdb_and_supports_reveal_secrets() {
        let temp_root = std::env::temp_dir().join(format!(
            "catcloud-cli-diag-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");

        let unused_ctrl_port = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("ephemeral port")
            .local_addr()
            .unwrap()
            .port();

        let mut cfg = config::load_or_init(&paths).expect("init config");
        cfg.route_mode = RouteTargetMode::Single;
        cfg.active_group_id = Some("grp-tw".to_string());
        cfg.active_single_node_id = Some("node-tw-01".to_string());
        cfg.controller_port = unused_ctrl_port;
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
        let diag_before_mmdb = build_diag_payload(&paths, false)
            .await
            .expect("diag before Country.mmdb");
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

        let diag = build_diag_payload(&paths, false)
            .await
            .expect("build sanitized diag payload");
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

        let revealed = build_diag_payload(&paths, true)
            .await
            .expect("build revealed diag payload");
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
        let diag_tun_off = build_diag_payload(&paths, false)
            .await
            .expect("diag with tun off");
        assert_eq!(diag_tun_off["tun_configured"], json!(false));
        assert_eq!(diag_tun_off["tun_enabled"], json!(false));
        assert_eq!(diag_tun_off["tun_needs_elevation"], json!(false));

        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[tokio::test]
    async fn status_and_diag_align_live_tun_state_when_core_running_without_elevation() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock controller");
        let mock_port = listener.local_addr().unwrap().port();

        let server_task = tokio::spawn(async move {
            for _ in 0..8 {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut req_buf = [0u8; 2048];
                let n = stream.read(&mut req_buf).await.unwrap_or(0);
                let req_str = String::from_utf8_lossy(&req_buf[..n]);
                let body = if req_str.starts_with("GET /version ") {
                    r#"{"version":"v1.19.0"}"#
                } else if req_str.starts_with("GET /connections ") {
                    r#"{"downloadTotal":0,"uploadTotal":0,"connections":[{"id":"c1","metadata":{"network":"tcp","type":"Tun","sourceIP":"198.18.0.1","destinationIP":"203.0.113.10","sourcePort":"51234","destinationPort":"443","host":"example.com","dnsMode":"fake-ip","processPath":""},"upload":10,"download":20,"start":"2026-11-25T00:00:00Z","chains":["DIRECT"],"rule":"MATCH","rulePayload":""}]}"#
                } else {
                    r#"{}"#
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            }
        });

        let temp_root = std::env::temp_dir().join(format!(
            "catcloud-cli-live-tun-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");
        let mut cfg = config::load_or_init(&paths).expect("init config");
        cfg.controller_port = mock_port;
        cfg.controller_secret = None;
        cfg.tun.enabled = true;
        config::save(&paths, &cfg).expect("save config");

        let mut unprivileged_caps = default_platform().capabilities();
        unprivileged_caps.is_elevated = false;

        let (tun_enabled, tun_needs_elevation, tun_source) =
            resolve_cli_effective_tun_state(&paths, &cfg, &unprivileged_caps, None).await;
        assert!(tun_enabled);
        assert!(!tun_needs_elevation);
        assert_eq!(tun_source, "live_tun_connections");

        let diag = build_diag_payload(&paths, false)
            .await
            .expect("build diag with live core");
        assert_eq!(diag["tun_configured"], json!(true));
        assert_eq!(diag["tun_enabled"], json!(true));
        assert_eq!(diag["tun_needs_elevation"], json!(false));
        assert_eq!(diag["tun_source"], json!("live_tun_connections"));

        server_task.abort();
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
        let checks = doctor["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 8);
        assert!(checks.iter().any(|c| c["id"] == "dns_tls_health"));
        let geo_check = checks
            .iter()
            .find(|c| c["id"] == "geodata_status")
            .expect("geodata_status check");
        assert_eq!(
            geo_check["data"]["impact_scope"]["explicit_domain_rules_unaffected"],
            json!(true)
        );
        assert_eq!(
            match_direct["geodata_impact_scope"]["explicit_domain_rules_unaffected"],
            json!(true)
        );

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
        handle_share_inspect(true, &zip_path, false).expect("inspect share zip");
        handle_share_inspect(true, &zip_path, true).expect("inspect share zip summary");

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

    #[tokio::test]
    async fn global_preaccel_status_payload_reports_config_and_windivert_readiness() {
        let temp_root = std::env::temp_dir().join(format!(
            "catcloud-cli-global-preaccel-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");

        let mut cfg = config::load_or_init(&paths).expect("init config");
        cfg.preaccel.global_bypass_enabled = true;
        config::save(&paths, &cfg).expect("save config");

        let (payload_before, human_before) = build_global_preaccel_status_payload(&paths)
            .await
            .expect("status before windivert");
        assert_eq!(payload_before["ok"], json!(true));
        assert_eq!(payload_before["global_bypass_enabled"], json!(true));
        assert_eq!(payload_before["global_scope"], json!("proxy_apps_only"));
        assert_eq!(payload_before["windivert_available"], json!(false));
        assert_eq!(payload_before["effective_carrier"], json!("off"));
        assert_eq!(payload_before["standalone_tunnel_running"], json!(false));
        assert_eq!(
            payload_before["standalone_tunnel_suspended_for_tun"],
            json!(false)
        );
        assert!(human_before.contains("enabled=true"));

        std::fs::write(paths.bin_dir.join("WinDivert64.dll"), b"stub-dll").unwrap();
        std::fs::write(paths.bin_dir.join("WinDivert64.sys"), b"stub-sys").unwrap();

        let (payload_after, _) = build_global_preaccel_status_payload(&paths)
            .await
            .expect("status after windivert");
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
            false,
        )
        .expect("auto-select tcp node");
        assert_eq!(picked.as_ref().map(|n| n.id.as_str()), Some("n-tcp"));
        assert!(note.is_some());

        // Explicit UDP node must fail with clear validation error.
        assert!(
            select_preaccel_speed_reference_node(
                &cfg,
                &[],
                &[udp_node.clone(), tcp_node],
                Some("n-udp"),
                false,
            )
            .is_err()
        );

        // When only UDP nodes exist, omit reference node for single-hop direct relay speed test.
        let (single_hop, single_note) =
            select_preaccel_speed_reference_node(&cfg, &[], &[udp_node], None, false)
                .expect("fallback to single-hop");
        assert!(single_hop.is_none());
        assert!(single_note.unwrap().contains("single-hop"));
    }

    #[test]
    fn share_inspect_summary_returns_compact_distributions_and_masks_sni_and_host_fields() {
        use catcloud_core::share_bundle::{
            SHARE_GROUPS_SCHEMA, ShareGroupRecord, ShareGroupsBundle,
            export_share_bundle_zip_file_with_groups,
        };
        use catcloud_core::subscription::parser::node_dedup_fingerprint;

        let temp_root = std::env::temp_dir().join(format!(
            "catcloud-cli-share-summary-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        std::fs::create_dir_all(&temp_root).unwrap();

        let mut nodes = Vec::new();
        for i in 0..12usize {
            let (region, proto, label) = match i % 3 {
                0 => ("JP", "vless", format!("🇯🇵 东京 0.5x #{i}")),
                1 => ("SG", "trojan", format!("🇸🇬 新加坡 1x #{i}")),
                _ => ("US", "vless", format!("🇺🇸 美国 1x #{i}")),
            };
            nodes.push(ProxyNode {
                id: format!("n-sum-{i}"),
                sub_id: "sub-demo".to_string(),
                name: label.clone(),
                protocol: proto.to_string(),
                server: format!("edge{i}.demo-upstream.com"),
                port: 443,
                raw_config: json!({
                    "name": label,
                    "type": proto,
                    "server": format!("edge{i}.demo-upstream.com"),
                    "port": 443,
                    "uuid": format!("00000000-0000-4000-8000-{i:012}"),
                    "password": format!("demo_pass_{i}"),
                    "sni": format!("sni{i}.demo-secret.net"),
                    "servername": format!("tls{i}.demo-secret.org"),
                    "plugin-opts": {
                        "mode": "websocket",
                        "host": format!("plug{i}.demo-cdn.io")
                    },
                    "ws-opts": {
                        "path": "/ws",
                        "headers": {
                            "Host": format!("ws{i}.demo-edge.com")
                        }
                    }
                }),
                region_code: region.to_string(),
                ..ProxyNode::default()
            });
        }
        let fp0 = node_dedup_fingerprint(&nodes[0]);
        let groups_bundle = ShareGroupsBundle {
            schema: SHARE_GROUPS_SCHEMA.to_string(),
            active_group_name: Some("AI Pool".to_string()),
            route_mode: Some("group".to_string()),
            groups: vec![ShareGroupRecord {
                name: "AI Pool".to_string(),
                member_fingerprints: vec![fp0],
                ..ShareGroupRecord::default()
            }],
        };

        let zip_path = temp_root.join("summary-pack.zip");
        let req = ShareBundleExportRequest {
            name: "Summary Demo Pack".to_string(),
            description: Some("12 nodes + 1 group".to_string()),
            nodes,
            relays: Vec::new(),
        };
        export_share_bundle_zip_file_with_groups(&req, Some(&groups_bundle), &zip_path)
            .expect("export summary pack");

        // 1. Summary mode: compact JSON with <= 5 samples, counts, top regions, protocols.
        let (summary_out, summary_human) =
            build_share_inspect_payload(&zip_path, true).expect("inspect --summary");
        assert_eq!(summary_out["summary_mode"], json!(true));
        assert_eq!(summary_out["node_count"], json!(12));
        assert_eq!(summary_out["relay_count"], json!(0));
        assert_eq!(summary_out["group_count"], json!(1));
        assert_eq!(summary_out["sample_nodes"].as_array().unwrap().len(), 5);
        assert!(summary_out.get("nodes").is_none());
        assert!(summary_human.contains("12 node(s)"));
        assert!(summary_human.contains("1 group(s)"));
        let summary_json = serde_json::to_string(&summary_out).unwrap();
        assert!(!summary_json.contains("demo-upstream"));
        assert!(!summary_json.contains("demo-secret"));
        assert!(!summary_json.contains("demo-cdn"));
        assert!(!summary_json.contains("demo-edge"));

        // 2. Full inspect mode: raw_config must mask sni, servername, plugin-opts.host, ws-opts.headers.Host.
        let (full_out, _) =
            build_share_inspect_payload(&zip_path, false).expect("inspect full");
        assert_eq!(full_out["summary_mode"], json!(false));
        assert_eq!(full_out["group_count"], json!(1));
        let first_node = &full_out["nodes"][0];
        assert_eq!(first_node["raw_config"]["sni"], json!("***.net"));
        assert_eq!(first_node["raw_config"]["servername"], json!("***.org"));
        assert_eq!(
            first_node["raw_config"]["plugin-opts"]["host"],
            json!("***.io")
        );
        assert_eq!(
            first_node["raw_config"]["ws-opts"]["headers"]["Host"],
            json!("***.com")
        );
        let full_json = serde_json::to_string(&full_out).unwrap();
        for leaked in ["demo-upstream", "demo-secret", "demo-cdn", "demo-edge"] {
            assert!(!full_json.contains(leaked), "full inspect leaked `{leaked}`");
        }

        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn net_doctor_tun_state_and_managed_mihomo_filter_prevent_false_positives() {
        // 1. Live Tun inbound connections or running core with tun_configured=true (when live
        //    `GET /configs` is unavailable) must not falsely claim tun_needs_elevation=true /
        //    tun_enabled=false on standard CLI; conversely, authoritative `Some(false)` MUST
        //    report `tun_enabled = false`.
        assert_eq!(
            evaluate_doctor_tun_state(true, false, true, true, None),
            (true, false, "live_tun_connections")
        );
        assert_eq!(
            evaluate_doctor_tun_state(true, false, true, false, None),
            (true, false, "live_core_with_tun_config")
        );
        assert_eq!(
            evaluate_doctor_tun_state(false, false, true, true, None),
            (true, false, "live_tun_connections")
        );
        assert_eq!(
            evaluate_doctor_tun_state(true, false, false, false, None),
            (false, true, "privilege_required")
        );
        assert_eq!(
            evaluate_doctor_tun_state(true, true, false, false, None),
            (true, false, "process_privilege")
        );
        assert_eq!(
            evaluate_doctor_tun_state(false, false, false, false, None),
            (false, false, "disabled")
        );
        assert_eq!(
            evaluate_doctor_tun_state(true, false, true, false, Some(false)),
            (false, true, "live_core_tun_disabled_needs_elevation")
        );
        assert_eq!(
            evaluate_doctor_tun_state(true, true, true, false, Some(false)),
            (false, false, "live_core_tun_disabled")
        );
        assert_eq!(
            evaluate_doctor_tun_state(true, false, true, false, Some(true)),
            (true, false, "live_core_configs")
        );

        // 2. Managed CatCloud mihomo.exe must be excluded by PID, binary path, or data dir,
        //    while genuine third-party proxy clients remain flagged as conflicts.
        let data_dir = PathBuf::from(r"C:\CatCloudPortable\data");
        let bin_dir = PathBuf::from(r"C:\CatCloudPortable\bin");
        let runtime_dir = data_dir.join("run");
        let filter = CatCloudManagedProcessFilter {
            managed_pid: Some(42420),
            managed_start_time_unix: Some(1_700_000_000),
            standalone_tunnel_pid: Some(42421),
            standalone_tunnel_start_time_unix: Some(1_700_000_100),
            mihomo_binary_path: Some(bin_dir.join("mihomo.exe")),
            owned_dirs: vec![bin_dir.clone(), runtime_dir.clone(), data_dir.clone()],
            live_controller_port: Some(19090),
            ..CatCloudManagedProcessFilter::default()
        };

        // Case A: Elevated mihomo.exe with inaccessible exe_path/cmdline matched via runtime PID + valid start time.
        let by_pid = ProcessCandidate {
            pid: 42420,
            name: "mihomo.exe".to_string(),
            exe_path: None,
            cmdline: Vec::new(),
            detected_config_dir: None,
            detected_config_file: None,
            detected_controller_addr: None,
            likely_proxy_client: true,
        };
        assert!(is_catcloud_managed_proxy_process_with_start_time(
            &by_pid,
            &filter,
            Some(1_700_000_001)
        ));
        // PID reuse guard: if OS start time drifts > 2s, the recycled PID must NOT be exempted!
        assert!(!is_catcloud_managed_proxy_process_with_start_time(
            &by_pid,
            &filter,
            Some(1_700_000_050)
        ));
        // Standalone 443 tunnel PID with valid start time is exempted.
        let standalone_tunnel = ProcessCandidate {
            pid: 42421,
            name: "mihomo.exe".to_string(),
            exe_path: None,
            cmdline: Vec::new(),
            detected_config_dir: None,
            detected_config_file: None,
            detected_controller_addr: None,
            likely_proxy_client: true,
        };
        assert!(is_catcloud_managed_proxy_process_with_start_time(
            &standalone_tunnel,
            &filter,
            Some(1_700_000_100)
        ));

        // Case B: Managed mihomo.exe matched via binary path in CatCloud bin dir.
        let by_exe = ProcessCandidate {
            pid: 55111,
            name: "mihomo.exe".to_string(),
            exe_path: Some(bin_dir.join("mihomo.exe")),
            cmdline: vec!["mihomo.exe".to_string()],
            detected_config_dir: None,
            detected_config_file: None,
            detected_controller_addr: None,
            likely_proxy_client: true,
        };
        assert!(is_catcloud_managed_proxy_process(&by_exe, &filter));

        // Case C: Managed mihomo.exe matched via `-d <data_dir>/run` config dir.
        let by_data_dir = ProcessCandidate {
            pid: 55112,
            name: "mihomo.exe".to_string(),
            exe_path: Some(PathBuf::from(r"C:\Tools\mihomo.exe")),
            cmdline: vec![
                "mihomo.exe".to_string(),
                "-d".to_string(),
                runtime_dir.to_string_lossy().to_string(),
            ],
            detected_config_dir: Some(runtime_dir.clone()),
            detected_config_file: Some(runtime_dir.join("runtime.yaml")),
            detected_controller_addr: None,
            likely_proxy_client: true,
        };
        assert!(is_catcloud_managed_proxy_process(&by_data_dir, &filter));

        // Case D: Unrelated third-party proxy client must NOT be excluded.
        let third_party = ProcessCandidate {
            pid: 66222,
            name: "clash-verge.exe".to_string(),
            exe_path: Some(PathBuf::from(r"C:\Program Files\Clash Verge\clash-verge.exe")),
            cmdline: vec!["clash-verge.exe".to_string()],
            detected_config_dir: Some(PathBuf::from(r"C:\ProgramData\ClashVerge")),
            detected_config_file: None,
            detected_controller_addr: Some("127.0.0.1:9097".to_string()),
            likely_proxy_client: true,
        };
        assert!(!is_catcloud_managed_proxy_process(&third_party, &filter));

        // Case E: Separate third-party mihomo.exe in another folder and controller port must stay flagged.
        let other_mihomo = ProcessCandidate {
            pid: 66223,
            name: "mihomo.exe".to_string(),
            exe_path: Some(PathBuf::from(r"C:\OtherClient\mihomo.exe")),
            cmdline: vec!["mihomo.exe".to_string(), "-d".to_string(), r"C:\OtherClient\cfg".to_string()],
            detected_config_dir: Some(PathBuf::from(r"C:\OtherClient\cfg")),
            detected_config_file: None,
            detected_controller_addr: Some("127.0.0.1:9099".to_string()),
            likely_proxy_client: true,
        };
        assert!(!is_catcloud_managed_proxy_process(&other_mihomo, &filter));
    }

    #[test]
    fn net_connections_and_logs_tail_sanitize_numeric_account_dirs_and_dial_domains() {
        let raw_conn = ActiveConnection {
            id: "c-1".to_string(),
            host: "api.demo-service.com".to_string(),
            source_ip: "192.168.1.50".to_string(),
            destination_ip: "203.0.113.44".to_string(),
            process: "QQ.exe".to_string(),
            process_path: concat!(
                r"C:\",
                r"Users\Administrator\Documents\Tencent Files\0000008899\nt_qq\QQ.exe"
            )
            .to_string(),
            ..ActiveConnection::default()
        };
        let safe_conn = redact_connection_for_readonly(&raw_conn);
        assert_eq!(
            safe_conn.process_path,
            r"C:\Users\<USER>\Documents\Tencent Files\***\nt_qq\QQ.exe"
        );
        assert!(!safe_conn.process_path.contains("0000008899"));

        let temp_root = std::env::temp_dir().join(format!(
            "catcloud-cli-logs-dial-mask-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");
        std::fs::write(
            paths.logs_dir.join("catcloud.log"),
            "2026-11-26T01:05:00Z WARN dial tcp hk01.demo-vendor.com:443: i/o timeout\n\
             2026-11-26T01:05:01Z ERROR connect error: sg02.demo-node.net:8443: EOF\n",
        )
        .unwrap();

        let (tail_out, _) = build_logs_tail_payload(&paths, 10, "all").expect("logs tail");
        let lines = tail_out["lines"].as_array().unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0].as_str().unwrap(),
            "2026-11-26T01:05:00Z WARN dial tcp ***.com:443: i/o timeout"
        );
        assert_eq!(
            lines[1].as_str().unwrap(),
            "2026-11-26T01:05:01Z ERROR connect error: ***.net:8443: EOF"
        );

        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[tokio::test]
    async fn share_send_ccsync_and_receive_dry_run_then_apply_merges_groups() {
        let sender_root = std::env::temp_dir().join(format!(
            "catcloud-cli-sync-sender-{}",
            std::process::id()
        ));
        let receiver_root = std::env::temp_dir().join(format!(
            "catcloud-cli-sync-receiver-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&sender_root);
        let _ = std::fs::remove_dir_all(&receiver_root);

        let sender_paths = AppPaths::from_data_dir(sender_root.clone(), true).expect("sender paths");
        let receiver_paths =
            AppPaths::from_data_dir(receiver_root.clone(), true).expect("receiver paths");

        {
            let mut db = open_storage(&sender_paths).expect("sender db");
            let sub = SubscriptionRecord {
                id: "sub-sync-src".to_string(),
                name: "Sync Source".to_string(),
                kind: SubscriptionKind::File,
                url_or_cmd: "local://demo".to_string(),
                ..Default::default()
            };
            db.upsert_subscription(&sub).unwrap();
            let node = ProxyNode {
                id: "node-sync-jp".to_string(),
                sub_id: sub.id.clone(),
                name: "JP-Sync-01".to_string(),
                protocol: "vless".to_string(),
                region_code: "JP".to_string(),
                server: "jp-sync.example.invalid".to_string(),
                port: 443,
                raw_config: serde_json::json!({
                    "name": "JP-Sync-01",
                    "type": "vless",
                    "server": "jp-sync.example.invalid",
                    "port": 443,
                    "uuid": "00000000-0000-4000-8000-000000000011",
                    "password": "node_sync_secret_pw"
                }),
                ..ProxyNode::default()
            };
            db.upsert_nodes_batch(&[node]).unwrap();
            let relay = PreAccelRelay {
                id: "relay-sync-cn".to_string(),
                name: "CN-Sync-443".to_string(),
                server: "198.51.100.77".to_string(),
                port: 443,
                protocol: "anytls".to_string(),
                password: "relay_sync_secret_pw".to_string(),
                ..PreAccelRelay::default()
            };
            db.upsert_preaccel_relay(&relay).unwrap();
            let mut grp = MultiGroup::default();
            grp.id = "grp-sync-ai".to_string();
            grp.name = "AI Sync Group".to_string();
            grp.member_node_ids = vec!["node-sync-jp".to_string()];
            grp.active_node_id = Some("node-sync-jp".to_string());
            db.upsert_multi_group(&grp).unwrap();
        }

        let ccsync_path = sender_root.join("export.ccsync");
        let send_args = ShareSendArgs {
            name: "Device Sync Pack".to_string(),
            description: Some("CLI roundtrip".to_string()),
            node_ids: None,
            sub_id: Some("sub-sync-src".to_string()),
            all_nodes: false,
            relay_ids: None,
            all_relays: true,
            no_groups: false,
            endpoint: None,
            bind: "127.0.0.1".to_string(),
            port: 0,
            ttl: 60,
            allow_multiple: false,
            push_uri: None,
            push_addr: None,
            pin: None,
            ccsync_output: Some(ccsync_path.clone()),
            no_qr: true,
        };
        let (send_out, _) =
            execute_share_send_ccsync(&sender_paths, &send_args, &ccsync_path).expect("ccsync send");
        assert_eq!(send_out["ok"], json!(true));
        assert_eq!(send_out["node_count"], json!(1));
        assert_eq!(send_out["relay_count"], json!(1));
        assert_eq!(send_out["group_count"], json!(1));
        let key_uri = send_out["key_uri"].as_str().expect("key_uri").to_string();
        assert!(key_uri.starts_with("catcloud://sync/v1?role=file_key"));

        // 1. Default dry-run receive must redact secrets and NOT mutate receiver storage.
        let dry_args = ShareReceiveArgs {
            source: None,
            uri: None,
            addr: None,
            pin: None,
            ccsync: Some(ccsync_path.clone()),
            key: Some(key_uri.clone()),
            password: None,
            listen: false,
            bind: "127.0.0.1".to_string(),
            port: 0,
            endpoint: None,
            ttl: 60,
            no_qr: true,
            dry_run: false,
            apply: false,
            target_sub: None,
            name: None,
            mode: "merge".to_string(),
            no_nodes: false,
            no_relays: false,
            no_groups: false,
        };
        let zip_bytes =
            open_cli_ccsync_file(&ccsync_path, Some(&key_uri), None).expect("open ccsync");
        let (dry_out, _) = execute_share_receive_from_zip_bytes(
            &receiver_paths,
            &dry_args,
            &zip_bytes,
            "export.ccsync",
        )
        .expect("dry-run receive");
        assert_eq!(dry_out["dry_run"], json!(true));
        assert_eq!(dry_out["applied"], json!(false));
        assert_eq!(dry_out["would_import_nodes"], json!(1));
        assert_eq!(dry_out["would_import_relays"], json!(1));
        assert_eq!(dry_out["would_import_groups"], json!(1));
        assert_eq!(dry_out["nodes"][0]["raw_config"]["password"], json!("<REDACTED>"));
        assert_eq!(dry_out["relays"][0]["password"], json!("<REDACTED>"));
        {
            let rx_db = open_storage(&receiver_paths).expect("rx db");
            assert_eq!(rx_db.list_nodes().unwrap().len(), 0);
            assert_eq!(rx_db.list_preaccel_relays(false).unwrap().len(), 0);
            assert_eq!(rx_db.list_multi_groups().unwrap().len(), 0);
        }

        // 2. Apply receive persists nodes, relays, and smart multi-groups.
        let mut apply_args = dry_args;
        apply_args.apply = true;
        let (apply_out, _) = execute_share_receive_from_zip_bytes(
            &receiver_paths,
            &apply_args,
            &zip_bytes,
            "export.ccsync",
        )
        .expect("apply receive");
        assert_eq!(apply_out["applied"], json!(true));
        assert_eq!(apply_out["imported_nodes"], json!(1));
        assert_eq!(apply_out["imported_relays"], json!(1));
        assert_eq!(apply_out["imported_groups"], json!(1));
        {
            let rx_db = open_storage(&receiver_paths).expect("rx db");
            assert_eq!(rx_db.list_nodes().unwrap().len(), 1);
            assert_eq!(rx_db.list_preaccel_relays(false).unwrap().len(), 1);
            let groups = rx_db.list_multi_groups().unwrap();
            assert_eq!(groups.len(), 1);
            assert_eq!(groups[0].name, "AI Sync Group");
            assert_eq!(groups[0].member_node_ids.len(), 1);
        }

        // 3. LAN HTTP pull roundtrip via LanSyncSendServer + fetch_sync_bundle_via_uri
        let (built_zip, _, _) =
            build_cli_sync_export_zip(&sender_paths, &send_args).expect("build zip");
        let mut srv = LanSyncSendServer::start(
            built_zip.clone(),
            LanSyncServerOptions {
                bind_host: "127.0.0.1".to_string(),
                bind_port: 0,
                custom_endpoint: None,
                ttl_secs: 60,
                allow_multiple: false,
            },
        )
        .await
        .expect("start lan send");
        let fetched = fetch_sync_bundle_via_uri(&srv.info().uri)
            .await
            .expect("fetch via uri");
        assert_eq!(fetched, built_zip);
        srv.cancel().await;

        let _ = std::fs::remove_dir_all(&sender_root);
        let _ = std::fs::remove_dir_all(&receiver_root);
    }

    #[tokio::test]
    async fn issue2_config_reload_preserves_live_tun_and_rejects_l3_restart_with_real_baseline() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Reserve clean ports for mixed and dns so test never collides with host listeners.
        let tmp_mixed = std::net::TcpListener::bind("127.0.0.1:0").expect("mixed port");
        let mixed_port = tmp_mixed.local_addr().unwrap().port();
        drop(tmp_mixed);
        let tmp_dns = std::net::TcpListener::bind("127.0.0.1:0").expect("dns port");
        let dns_port = tmp_dns.local_addr().unwrap().port();
        drop(tmp_dns);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock controller");
        let mock_port = listener.local_addr().unwrap().port();
        let put_reload_count = Arc::new(AtomicUsize::new(0));
        let put_counter_srv = Arc::clone(&put_reload_count);

        let server_task = tokio::spawn(async move {
            for _ in 0..32 {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut req_buf = [0u8; 4096];
                let n = stream.read(&mut req_buf).await.unwrap_or(0);
                let req_str = String::from_utf8_lossy(&req_buf[..n]);
                let has_auth = req_str
                    .to_ascii_lowercase()
                    .contains("authorization: bearer test-issue2-secret");
                let (status_line, body) = if !has_auth {
                    ("HTTP/1.1 401 Unauthorized", r#"{"message":"Unauthorized"}"#.to_string())
                } else if req_str.starts_with("GET /version ") {
                    ("HTTP/1.1 200 OK", r#"{"version":"v1.19.1"}"#.to_string())
                } else if req_str.starts_with("GET /configs ") {
                    (
                        "HTTP/1.1 200 OK",
                        format!(
                            r#"{{"tun":{{"enable":true}},"mixed-port":{},"port":0,"socks-port":0,"bind-address":"127.0.0.1","allow-lan":false,"mode":"rule"}}"#,
                            mixed_port
                        ),
                    )
                } else if req_str.starts_with("PUT /configs") {
                    put_counter_srv.fetch_add(1, Ordering::SeqCst);
                    ("HTTP/1.1 204 No Content", String::new())
                } else if req_str.starts_with("PUT /proxies/") {
                    ("HTTP/1.1 204 No Content", String::new())
                } else {
                    ("HTTP/1.1 200 OK", r#"{}"#.to_string())
                };
                let resp = format!(
                    "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            }
        });

        let temp_root = std::env::temp_dir().join(format!(
            "catcloud-cli-issue2-reload-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");

        let mut cfg = config::load_or_init(&paths).expect("init config");
        cfg.mixed_port = mixed_port;
        cfg.controller_port = mock_port;
        cfg.dns_listen_port = dns_port;
        cfg.controller_secret = Some("test-issue2-secret".to_string());
        cfg.tun.enabled = true;
        cfg.allow_lan = false;
        cfg.bind_address = "127.0.0.1".to_string();
        config::save(&paths, &cfg).expect("save config");

        let db = open_storage(&paths).expect("open db");
        db.upsert_subscription(&SubscriptionRecord {
            id: "sub-issue2".to_string(),
            name: "Issue2 Sub".to_string(),
            kind: SubscriptionKind::File,
            url_or_cmd: "issue2.yaml".to_string(),
            ..Default::default()
        })
        .unwrap();
        db.upsert_node(&ProxyNode {
            id: "n-issue2-1".to_string(),
            sub_id: "sub-issue2".to_string(),
            name: "JP-Issue2".to_string(),
            protocol: "trojan".to_string(),
            server: "203.0.113.10".to_string(),
            port: 443,
            enabled: true,
            raw_config: json!({
                "name": "JP-Issue2",
                "type": "trojan",
                "server": "203.0.113.10",
                "port": 443,
                "password": "demo-trojan-password"
            }),
            ..ProxyNode::default()
        })
        .unwrap();
        drop(db);

        // Seed realistic on-disk `run/runtime.yaml` reflecting the running elevated core.
        let initial_yaml = format!(
            "mixed-port: {mixed_port}\n\
             allow-lan: false\n\
             bind-address: 127.0.0.1\n\
             mode: rule\n\
             log-level: info\n\
             external-controller: 127.0.0.1:{mock_port}\n\
             secret: test-issue2-secret\n\
             dns:\n\
               enable: true\n\
               listen: 127.0.0.1:{dns_port}\n\
               ipv6: false\n\
             tun:\n\
               enable: true\n\
               stack: mixed\n\
               device: CatCloud\n\
               mtu: 1500\n\
               auto-route: true\n\
               auto-detect-interface: true\n\
               strict-route: true\n"
        );
        let runtime_yaml_path = paths.runtime_dir.join("runtime.yaml");
        std::fs::write(&runtime_yaml_path, &initial_yaml).unwrap();

        let mut unpriv_caps = default_platform().capabilities();
        unpriv_caps.is_elevated = false;

        // 1. Dry-run from unprivileged CLI must recognize live elevated TUN and keep allow_tun=true.
        let (dry_ok, dry_out, _) =
            run_config_reload_inner(&paths, true, Some(unpriv_caps.clone()), false)
                .await
                .expect("dry run");
        assert!(dry_ok, "dry run failed: {dry_out}");
        assert_eq!(dry_out["trusted_controller_endpoint"], json!(true));
        assert_eq!(dry_out["live_tun_enabled"], json!(true));
        assert_eq!(dry_out["allow_tun"], json!(true));
        assert_eq!(dry_out["tun_preserved_via_live_core"], json!(true));
        assert_eq!(dry_out["requires_l3_restart"], json!(false));

        // 2. Real L2 hot reload from unprivileged CLI must preserve `tun.enable: true` in runtime.yaml!
        let (reload_ok, reload_out, _) =
            run_config_reload_inner(&paths, false, Some(unpriv_caps.clone()), false)
                .await
                .expect("l2 reload");
        assert!(reload_ok, "l2 reload failed: {reload_out}");
        assert_eq!(reload_out["allow_tun"], json!(true));
        assert_eq!(reload_out["hot_reloaded"], json!(true));
        assert_eq!(put_reload_count.load(Ordering::SeqCst), 1);
        let updated_yaml = std::fs::read_to_string(&runtime_yaml_path).unwrap();
        assert!(
            updated_yaml.contains("tun:") && updated_yaml.contains("enable: true"),
            "L2 hot reload from unprivileged CLI must never silently disable live TUN"
        );

        // 3. Mutate an L3 field (`mixed_port`): dry-run must report `l3_core_restart`, and
        //    real reload must be hard-rejected without touching runtime.yaml or calling PUT /configs.
        let mut next_mixed = if mixed_port < 65000 {
            mixed_port + 1
        } else {
            mixed_port - 1
        };
        while next_mixed == mixed_port
            || next_mixed == cfg.controller_port
            || next_mixed == cfg.dns_listen_port
        {
            next_mixed = if next_mixed < 65000 {
                next_mixed + 1
            } else {
                20000
            };
        }
        cfg.mixed_port = next_mixed;
        config::save(&paths, &cfg).expect("save l3 port change");

        let (l3_dry_ok, l3_dry_out, _) =
            run_config_reload_inner(&paths, true, Some(unpriv_caps.clone()), false)
                .await
                .expect("l3 dry run");
        assert!(l3_dry_ok);
        assert_eq!(l3_dry_out["level"], json!("l3_core_restart"));
        assert_eq!(l3_dry_out["requires_l3_restart"], json!(true));
        assert!(
            l3_dry_out["diff_reasons"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r.as_str().unwrap_or("").contains("mixed_port"))
        );

        let yaml_before_l3_reject = std::fs::read_to_string(&runtime_yaml_path).unwrap();
        let (l3_ok, l3_out, _) =
            run_config_reload_inner(&paths, false, Some(unpriv_caps), false)
                .await
                .expect("l3 reject outcome");
        assert!(!l3_ok, "L3 change must be rejected when allow_l3_restart=false");
        assert_eq!(l3_out["level"], json!("l3_core_restart"));
        assert_eq!(l3_out["outcome"]["rejected"], json!(true));
        assert!(
            l3_out["error"]
                .as_str()
                .unwrap_or("")
                .contains("桌面端")
        );
        assert_eq!(
            put_reload_count.load(Ordering::SeqCst),
            1,
            "rejected L3 reload must never call PUT /configs?force=true"
        );
        assert_eq!(
            std::fs::read_to_string(&runtime_yaml_path).unwrap(),
            yaml_before_l3_reject,
            "rejected L3 reload must leave runtime.yaml untouched"
        );

        server_task.abort();
        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn issue3_group_create_preserves_fields_and_group_members_and_policy_match_rules_work() {
        use catcloud_core::models::{DynamicFilterSpec, TriggerRule};

        let temp_root = std::env::temp_dir().join(format!(
            "catcloud-cli-issue3-group-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");
        let db = open_storage(&paths).expect("open db");

        let original = MultiGroup {
            id: "grp-issue3".to_string(),
            name: "AI Dedicated".to_string(),
            mode: MultiGroupMode::ConditionalPool,
            match_rules: vec!["DOMAIN-SUFFIX,openai.com".to_string()],
            member_node_ids: vec!["n1".to_string(), "n2".to_string()],
            dynamic_filter: Some(DynamicFilterSpec {
                region_codes: vec!["JP".to_string(), "SG".to_string()],
                max_multiplier: Some(1.0),
                ..DynamicFilterSpec::default()
            }),
            primary_probe_id: Some("probe-ai".to_string()),
            hard_gates: vec!["google_clean == 1".to_string(), "keepalive_ok == 1".to_string()],
            trigger_rules: vec![TriggerRule {
                expr: "ping_ms > 1500".to_string(),
                consecutive_failures: 3,
                bypass_cooldown_on_disconnect: true,
            }],
            formula_expr: "up_mbps * 40 - ping_ms * 0.1".to_string(),
            fallback_policy: FallbackPolicy::CrossPoolEscalate,
            fallback_pool_id: Some("grp-backup".to_string()),
            escalated_since: None,
            recover_probe_interval_sec: 90,
            switch_mode: SwitchMode::GracefulNewOnly,
            cooldown_sec: 120,
            hysteresis_pct: 35.0,
            active_node_id: Some("n1".to_string()),
            state: catcloud_core::models::MultiGroupState::Healthy,
            independent_routing: true,
        };
        db.upsert_multi_group(&original).unwrap();
        drop(db);

        // 1. Updating existing group via `group create` with only `--nodes` (omitting name/mode/fallback/switch_mode)
        //    must preserve ALL existing fields including `switch_mode` and keep `active_node_id` while still in pool.
        let (upd_out, _) = execute_group_create(
            &paths,
            GroupCreateArgs {
                id: "grp-issue3".to_string(),
                name: None,
                mode: None,
                formula: None,
                fallback: None,
                switch_mode: None,
                nodes: Some("n1,n3".to_string()),
            },
        )
        .expect("partial update existing group");
        assert_eq!(upd_out["created"], json!(false));
        assert_eq!(upd_out["updated"], json!(true));

        let db = open_storage(&paths).expect("reopen db");
        let after = db.get_multi_group("grp-issue3").unwrap().unwrap();
        assert_eq!(after.name, "AI Dedicated");
        assert_eq!(after.mode, MultiGroupMode::ConditionalPool);
        assert_eq!(after.fallback_policy, FallbackPolicy::CrossPoolEscalate);
        assert_eq!(after.switch_mode, SwitchMode::GracefulNewOnly);
        assert_eq!(after.hard_gates, original.hard_gates);
        assert_eq!(after.match_rules, original.match_rules);
        assert_eq!(after.trigger_rules, original.trigger_rules);
        assert_eq!(after.dynamic_filter, original.dynamic_filter);
        assert_eq!(after.primary_probe_id, original.primary_probe_id);
        assert_eq!(after.fallback_pool_id, original.fallback_pool_id);
        assert_eq!(after.independent_routing, true);
        assert_eq!(after.cooldown_sec, 120);
        assert!((after.hysteresis_pct - 35.0).abs() < 1e-6);
        assert_eq!(after.member_node_ids, vec!["n1", "n3"]);
        assert_eq!(after.active_node_id.as_deref(), Some("n1"));
        drop(db);

        // 2. `group members add / remove / set` mutates members safely without touching policy/rules.
        let (add_out, _) = execute_group_members(
            &paths,
            GroupMembersArgs {
                id: "grp-issue3".to_string(),
                action: "add".to_string(),
                nodes: "n3,n4".to_string(),
            },
        )
        .expect("members add");
        assert_eq!(add_out["added"], json!(["n4"]));
        assert_eq!(add_out["removed"], json!([]));
        assert_eq!(add_out["member_count"], json!(3));
        assert_eq!(add_out["active_node_id"], json!("n1"));

        let (rem_out, _) = execute_group_members(
            &paths,
            GroupMembersArgs {
                id: "grp-issue3".to_string(),
                action: "remove".to_string(),
                nodes: "n1".to_string(),
            },
        )
        .expect("members remove active node");
        assert_eq!(rem_out["removed"], json!(["n1"]));
        assert_eq!(rem_out["member_count"], json!(2));
        assert!(rem_out["active_node_id"].is_null());

        let (set_out, _) = execute_group_members(
            &paths,
            GroupMembersArgs {
                id: "grp-issue3".to_string(),
                action: "set".to_string(),
                nodes: "n4,n5".to_string(),
            },
        )
        .expect("members set");
        assert_eq!(set_out["added"], json!(["n5"]));
        assert_eq!(set_out["removed"], json!(["n3"]));
        assert_eq!(set_out["member_count"], json!(2));

        // 3. `group policy` match-rules add / replace / clear.
        let (pol_add, _) = execute_group_policy(
            &paths,
            GroupPolicyArgs {
                group_id: "grp-issue3".to_string(),
                formula: None,
                fallback: None,
                switch_mode: None,
                hard_gate: Vec::new(),
                match_rules: None,
                add_match_rule: vec!["DOMAIN-SUFFIX,claude.ai".to_string()],
                clear_match_rules: false,
            },
        )
        .expect("policy add match rule");
        assert_eq!(
            pol_add["group"]["match_rules"],
            json!(["DOMAIN-SUFFIX,openai.com", "DOMAIN-SUFFIX,claude.ai"])
        );

        let (pol_rep, _) = execute_group_policy(
            &paths,
            GroupPolicyArgs {
                group_id: "grp-issue3".to_string(),
                formula: None,
                fallback: None,
                switch_mode: None,
                hard_gate: Vec::new(),
                match_rules: Some("DOMAIN-SUFFIX,anthropic.com;DOMAIN,chatgpt.com".to_string()),
                add_match_rule: Vec::new(),
                clear_match_rules: false,
            },
        )
        .expect("policy replace match rules");
        assert_eq!(
            pol_rep["group"]["match_rules"],
            json!(["DOMAIN-SUFFIX,anthropic.com", "DOMAIN,chatgpt.com"])
        );

        let (pol_clr, _) = execute_group_policy(
            &paths,
            GroupPolicyArgs {
                group_id: "grp-issue3".to_string(),
                formula: None,
                fallback: None,
                switch_mode: None,
                hard_gate: Vec::new(),
                match_rules: None,
                add_match_rule: Vec::new(),
                clear_match_rules: true,
            },
        )
        .expect("policy clear match rules");
        assert_eq!(pol_clr["group"]["match_rules"], json!([]));

        // Verify policy/switch_mode/hard_gates remained intact throughout all mutations.
        let db = open_storage(&paths).expect("final check db");
        let final_grp = db.get_multi_group("grp-issue3").unwrap().unwrap();
        assert_eq!(final_grp.switch_mode, SwitchMode::GracefulNewOnly);
        assert_eq!(final_grp.hard_gates, original.hard_gates);
        assert_eq!(final_grp.fallback_policy, FallbackPolicy::CrossPoolEscalate);

        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn emit_output_post_sanitization_masks_public_and_private_ips_while_preserving_api_openai_com() {
        let raw_sanitized = json!({
            "ok": true,
            "sanitized": true,
            "version": "0.1.0",
            "source_ip": "198.18.0.5",
            "destination_ip": "203.0.113.42",
            "host": "api.openai.com",
            "ip_host": { "host": "198.51.100.77:443" },
            "dns_note": "direct 223.5.5.5 and lan 10.20.30.40 and loopback 127.0.0.1",
            "nested": {
                "host": "github.com",
                "server": "192.168.1.99"
            }
        });
        let cleaned = finalize_output_value(&raw_sanitized);
        assert_eq!(cleaned["source_ip"], json!("198.18.0.*"));
        assert_eq!(cleaned["destination_ip"], json!("203.0.113.*"));
        assert_eq!(cleaned["host"], json!("api.openai.com"));
        assert_eq!(cleaned["nested"]["host"], json!("github.com"));
        assert_eq!(cleaned["ip_host"]["host"], json!("198.51.100.*:443"));
        assert_eq!(cleaned["nested"]["server"], json!("192.168.1.*"));
        let note = cleaned["dns_note"].as_str().unwrap();
        assert!(!note.contains("223.5.5.5"));
        assert!(!note.contains("10.20.30.40"));
        assert!(note.contains("223.5.5.*"));
        assert!(note.contains("10.20.30.*"));
        assert!(note.contains("127.0.0.1"));

        // When `sanitized` is false (`--reveal-secrets`), values must pass through untouched.
        let raw_revealed = json!({
            "ok": true,
            "sanitized": false,
            "source_ip": "198.18.0.5",
            "destination_ip": "203.0.113.42"
        });
        let revealed = finalize_output_value(&raw_revealed);
        assert_eq!(revealed["source_ip"], json!("198.18.0.5"));
        assert_eq!(revealed["destination_ip"], json!("203.0.113.42"));
    }

    #[test]
    fn logs_tail_supports_archive2_since_until_relative_and_reveal_secrets() {
        let temp_root = std::env::temp_dir().join(format!(
            "catcloud-cli-logs-since-until-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");

        std::fs::write(
            paths.logs_dir.join("catcloud.log.2"),
            "2026-11-26T01:00:00Z WARN oldest-archive2 secret=pw_arch2\n",
        )
        .unwrap();
        std::fs::write(
            paths.logs_dir.join("catcloud.log.1"),
            "2026-11-26T02:30:00Z WARN mid-archive1 ip=203.0.113.88\n",
        )
        .unwrap();
        std::fs::write(
            paths.logs_dir.join("catcloud.log"),
            "2026-11-26T03:45:00Z ERROR latest-main token=tok_live_99\n\
             2026-11-26T04:10:00Z INFO after-window\n",
        )
        .unwrap();

        let anchor_utc = DateTime::parse_from_rfc3339("2026-11-26T04:00:00Z")
            .unwrap()
            .with_timezone(&Local);

        // 1. Absolute RFC3339 window (`--since` + `--until`) reads `.2`/`.1`/primary in order and sanitizes by default.
        let (window_out, _) = build_logs_tail_payload_with_options(
            &paths,
            50,
            "all",
            Some("2026-11-26T02:00:00Z"),
            Some("2026-11-26T03:50:00Z"),
            false,
            anchor_utc,
        )
        .expect("since/until window");
        assert_eq!(
            window_out["sources"],
            json!(["catcloud.log.2", "catcloud.log.1", "catcloud.log"])
        );
        assert_eq!(window_out["sanitized"], json!(true));
        let lines = window_out["lines"].as_array().unwrap();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].as_str().unwrap().contains("mid-archive1"));
        assert!(lines[0].as_str().unwrap().contains("203.0.113.*"));
        assert!(lines[1].as_str().unwrap().contains("latest-main"));
        assert!(!lines[1].as_str().unwrap().contains("tok_live_99"));

        // 2. Relative `--since 30m` from anchor `04:00Z` -> `03:30Z..`, plus `--reveal-secrets`.
        let (rel_out, _) = build_logs_tail_payload_with_options(
            &paths,
            50,
            "error",
            Some("30m"),
            None,
            true,
            anchor_utc,
        )
        .expect("relative since + reveal");
        assert_eq!(rel_out["sanitized"], json!(false));
        let rel_lines = rel_out["lines"].as_array().unwrap();
        assert_eq!(rel_lines.len(), 1);
        assert!(rel_lines[0].as_str().unwrap().contains("tok_live_99"));

        // 3. Invalid inverted window (`since > until`) must error cleanly.
        assert!(
            build_logs_tail_payload_with_options(
                &paths,
                50,
                "all",
                Some("2026-11-26T05:00:00Z"),
                Some("2026-11-26T03:00:00Z"),
                false,
                anchor_utc,
            )
            .is_err()
        );

        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[tokio::test]
    async fn config_validate_separates_active_core_ports_from_new_instance_preview_and_detects_third_party_conflict()
    {
        use catcloud_core::core_adapter::ControllerEndpointSource;

        fn reserve_tcp_udp_port() -> (u16, std::net::TcpListener, std::net::UdpSocket) {
            for _ in 0..64 {
                let tcp = std::net::TcpListener::bind("127.0.0.1:0").expect("bind tcp");
                let port = tcp.local_addr().unwrap().port();
                if let Ok(udp) = std::net::UdpSocket::bind(format!("127.0.0.1:{port}")) {
                    return (port, tcp, udp);
                }
            }
            panic!("failed to reserve ephemeral tcp+udp port");
        }

        let (busy_mixed, _t1, _u1) = reserve_tcp_udp_port();
        let (busy_ctrl, _t2, _u2) = reserve_tcp_udp_port();
        let (busy_dns, _t3, _u3) = reserve_tcp_udp_port();

        let mut cfg = AppConfig::default();
        cfg.mixed_port = busy_mixed;
        cfg.controller_port = busy_ctrl;
        cfg.dns_listen_port = busy_dns;
        cfg.port_guard_auto_shift = true;

        // 1. When all three ports are owned by the active CatCloud core, compilation MUST reuse
        //    the active ports without false shifting, while `new_instance_preview_ports` shifts cleanly.
        let active_owned_state = ActiveCorePortState {
            core_running: true,
            core_version: Some("v1.19.1".to_string()),
            controller_auth_error: None,
            endpoint: ResolvedControllerEndpoint {
                host: "127.0.0.1".to_string(),
                port: busy_ctrl,
                secret: "demo-secret".to_string(),
                mixed_port: Some(busy_mixed),
                dns_port: Some(busy_dns),
                pid: Some(std::process::id()),
                process_start_time_unix: get_process_start_time_unix(std::process::id()),
                binary_path: None,
                source: ControllerEndpointSource::LiveRuntimeMeta,
            },
            live_config: None,
            effective_mixed_port: busy_mixed,
            effective_controller_port: busy_ctrl,
            effective_dns_port: busy_dns,
            mixed_free: false,
            controller_free: false,
            dns_free: false,
            mixed_owned_by_active_core: true,
            controller_owned_by_active_core: true,
            dns_owned_by_active_core: true,
            owners: Vec::new(),
        };
        let (compile_ports, preview_opt, conflicts) =
            resolve_compile_and_preview_ports(&cfg, &active_owned_state)
                .expect("resolve active core ports");
        assert!(conflicts.is_empty());
        assert!(compile_ports.shifted.is_empty());
        assert_eq!(compile_ports.mixed_port, busy_mixed);
        assert_eq!(compile_ports.controller_port, busy_ctrl);
        assert_eq!(compile_ports.dns_port, busy_dns);

        let preview = preview_opt.expect("new_instance_preview_ports");
        assert_ne!(preview.mixed_port, busy_mixed);
        assert_ne!(preview.controller_port, busy_ctrl);
        assert_ne!(preview.dns_port, busy_dns);
        assert_eq!(preview.shifted.len(), 3);

        // 2. When no CatCloud core is running and a real third-party listener holds `busy_mixed`,
        //    `config validate` must detect the genuine conflict!
        let temp_root = std::env::temp_dir().join(format!(
            "catcloud-cli-validate-conflict-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");

        let mut cfg_conflict = config::load_or_init(&paths).expect("init config");
        cfg_conflict.mixed_port = busy_mixed;
        cfg_conflict.port_guard_auto_shift = false;
        config::save(&paths, &cfg_conflict).expect("save conflict cfg");

        let (ok_no_shift, out_no_shift, _) = build_config_validate_payload(&paths)
            .await
            .expect("validate conflict no shift");
        assert!(!ok_no_shift, "third-party conflict with auto_shift=false must fail validation");
        assert!(out_no_shift["active_core_ports"].is_null());
        assert!(
            out_no_shift["third_party_port_conflicts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["port"] == json!(busy_mixed))
        );

        cfg_conflict.port_guard_auto_shift = true;
        config::save(&paths, &cfg_conflict).expect("save auto_shift cfg");
        let (ok_shift, out_shift, _) = build_config_validate_payload(&paths)
            .await
            .expect("validate conflict with shift");
        assert!(ok_shift);
        assert_ne!(out_shift["ports"]["mixed_port"], json!(busy_mixed));
        assert!(
            out_shift["third_party_port_conflicts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["port"] == json!(busy_mixed))
        );
        assert!(out_shift["new_instance_preview_ports"].is_object());

        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn net_connections_separates_app_and_internal_connections_and_respects_reveal_secrets() {
        let conns = vec![
            ActiveConnection {
                id: "app-1".to_string(),
                conn_type: "Tun".to_string(),
                host: "api.openai.com".to_string(),
                source_ip: "198.18.0.1".to_string(),
                destination_ip: "203.0.113.55".to_string(),
                rule: "DomainSuffix".to_string(),
                chains: vec!["JP-01".to_string(), "AI-Group".to_string()],
                ..ActiveConnection::default()
            },
            ActiveConnection {
                id: "inner-1".to_string(),
                conn_type: "Inner".to_string(),
                host: "223.5.5.5".to_string(),
                source_ip: "127.0.0.1".to_string(),
                destination_ip: "223.5.5.5".to_string(),
                rule: "".to_string(),
                chains: vec!["DIRECT".to_string()],
                ..ActiveConnection::default()
            },
            ActiveConnection {
                id: "preaccel-1".to_string(),
                conn_type: "Socks5".to_string(),
                host: "198.51.100.10".to_string(),
                source_ip: "127.0.0.1".to_string(),
                destination_ip: "198.51.100.10".to_string(),
                rule: "MATCH".to_string(),
                chains: vec!["Relay-CN".to_string(), "⚖️ 预加速多云均衡".to_string()],
                ..ActiveConnection::default()
            },
        ];

        let (all_redacted, app, internal, app_count, internal_count) =
            classify_and_format_connections(&conns, 50, false);
        assert_eq!(all_redacted.len(), 3);
        assert_eq!(app_count, 1);
        assert_eq!(internal_count, 2);
        assert_eq!(app[0].id, "app-1");
        assert_eq!(app[0].host, "api.openai.com");
        assert_eq!(app[0].source_ip, "198.18.0.*");
        assert_eq!(app[0].destination_ip, "203.0.113.*");
        assert_eq!(internal[0].id, "inner-1");
        assert_eq!(internal[0].destination_ip, "223.5.5.*");
        assert_eq!(internal[1].id, "preaccel-1");
        assert_eq!(internal[1].host, "198.51.100.*");

        let (_, app_raw, _, _, _) = classify_and_format_connections(&conns, 50, true);
        assert_eq!(app_raw[0].source_ip, "198.18.0.1");
        assert_eq!(app_raw[0].destination_ip, "203.0.113.55");
    }

    #[tokio::test]
    async fn group_eval_diag_and_global_preaccel_surface_observability_snapshots() {
        use catcloud_core::models::ProbeResultRecord;
        use catcloud_core::preaccel::global_tunnel::write_global_preaccel_runtime_meta;
        use catcloud_core::strategy::health_pool::{
            WatchdogDecisionEvent, WatchdogStateSnapshot, write_watchdog_state_snapshot,
        };

        let temp_root = std::env::temp_dir().join(format!(
            "catcloud-cli-stage19-obs-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");

        let db = open_storage(&paths).expect("open db");
        db.upsert_subscription(&SubscriptionRecord {
            id: "sub-obs".to_string(),
            name: "Obs Sub".to_string(),
            kind: SubscriptionKind::File,
            url_or_cmd: "obs.yaml".to_string(),
            ..Default::default()
        })
        .unwrap();
        db.upsert_node(&ProxyNode {
            id: "n-obs-1".to_string(),
            sub_id: "sub-obs".to_string(),
            name: "JP-Obs-1".to_string(),
            protocol: "trojan".to_string(),
            server: "203.0.113.20".to_string(),
            port: 443,
            enabled: true,
            ..ProxyNode::default()
        })
        .unwrap();
        db.insert_probe_result(&ProbeResultRecord {
            node_id: "n-obs-1".to_string(),
            probe_id: "builtin_latency".to_string(),
            tested_at: "2026-11-26T12:00:00Z".to_string(),
            ok: true,
            latency_ms: Some(45.0),
            up_mbps: Some(25.0),
            down_mbps: Some(120.0),
            google_clean: Some(true),
            keepalive_60s_ok: Some(true),
            ..ProbeResultRecord::default()
        })
        .unwrap();
        db.upsert_multi_group(&MultiGroup {
            id: "grp-obs".to_string(),
            name: "Obs Group".to_string(),
            member_node_ids: vec!["n-obs-1".to_string()],
            active_node_id: Some("n-obs-1".to_string()),
            ..MultiGroup::default()
        })
        .unwrap();
        drop(db);

        let mut wd = WatchdogStateSnapshot {
            updated_at: "2026-11-26T12:05:00Z".to_string(),
            ..WatchdogStateSnapshot::default()
        };
        wd.push_event(WatchdogDecisionEvent {
            timestamp: "2026-11-26T12:05:00Z".to_string(),
            group_id: "grp-obs".to_string(),
            group_name: "Obs Group".to_string(),
            trigger_reason: "manual_check".to_string(),
            action: "keep_active".to_string(),
            ..WatchdogDecisionEvent::default()
        });
        write_watchdog_state_snapshot(&paths.root_data_dir, &wd).unwrap();

        let (eval_out, _) = build_group_eval_payload(&paths, "grp-obs").expect("group eval");
        assert_eq!(eval_out["evaluation_mode"], json!("offline_dry_run"));
        assert_eq!(
            eval_out["evaluation"]["gate_passed"][0]["tested_at"],
            json!("2026-11-26T12:00:00Z")
        );
        assert_eq!(
            eval_out["watchdog_snapshot"]["recent_events"][0]["group_id"],
            json!("grp-obs")
        );

        // Verify `config diag` and `net doctor` detect DNS TLS cert verification errors across `.1` + main log.
        std::fs::write(
            paths.logs_dir.join("catcloud.log.1"),
            "2026-11-26T03:44:51+08:00 WARN [DNS] direct-nameserver https://223.5.5.5/dns-query failed: x509: cannot validate certificate for 223.5.5.5 because it doesn't contain any IP SANs\n",
        )
        .unwrap();
        std::fs::write(paths.logs_dir.join("catcloud.log"), "").unwrap();

        let diag = build_diag_payload(&paths, false).await.expect("diag");
        assert_eq!(
            diag["dns_diagnostics"]["status"],
            json!("cert_verification_failed")
        );
        assert_eq!(diag["dns_diagnostics"]["tls_verification_preserved"], json!(true));
        assert!(!diag["warnings"].as_array().unwrap().is_empty());

        let (doctor, _) = build_net_doctor_payload(&paths).await.expect("net doctor");
        let dns_check = doctor["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == "dns_tls_health")
            .expect("dns_tls_health check");
        assert_eq!(dns_check["status"], json!("fail"));
        assert_eq!(dns_check["data"]["failure_count"], json!(1));

        // Verify stale `global-preaccel-runtime.json` with a bogus dead PID does not report running=true.
        write_global_preaccel_runtime_meta(
            &paths.root_data_dir,
            &GlobalPreAccelRuntimeMeta {
                pid: Some(u32::MAX - 7),
                process_start_time_unix: Some(1_600_000_000),
                running: true,
                mode: "local_socks5".to_string(),
                effective_carrier: "standalone_socks5".to_string(),
                socks_port: Some(17999),
                updated_at: "2026-11-26T00:00:00Z".to_string(),
                ..GlobalPreAccelRuntimeMeta::default()
            },
        )
        .unwrap();
        let (gp_out, _) = build_global_preaccel_status_payload(&paths)
            .await
            .expect("global status");
        assert_eq!(gp_out["standalone_tunnel_running"], json!(false));
        assert_eq!(gp_out["runtime_meta_stale"], json!(true));
        assert_eq!(gp_out["effective_carrier"], json!("off"));

        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn preaccel_global_status_carrier_aligns_with_desktop_for_zero_relays_direct_and_tun() {
        let mut cfg = AppConfig::default();
        cfg.preaccel.enabled = true;
        cfg.preaccel.global_bypass_enabled = false;

        // 1. Zero enabled relays MUST return `off` in both proxy-only and TUN modes.
        assert_eq!(
            resolve_effective_preaccel_carrier(&cfg, false, false, true, false, None, false),
            ("off", false, false, "off")
        );
        assert_eq!(
            resolve_effective_preaccel_carrier(&cfg, false, false, true, true, None, false),
            ("off", false, false, "off")
        );

        // 2. Direct proxy mode MUST return `off` in both proxy-only and TUN modes.
        assert_eq!(
            resolve_effective_preaccel_carrier(&cfg, true, true, true, false, None, false),
            ("off", false, false, "off")
        );
        assert_eq!(
            resolve_effective_preaccel_carrier(&cfg, true, true, true, true, None, false),
            ("off", false, false, "off")
        );

        // 3. Enabled relays + non-direct + live TUN reports `main_core_tun_suspended_standalone`
        //    even when `global_bypass_enabled == false` and `runtime_meta == None` (aligned with Desktop).
        assert_eq!(
            resolve_effective_preaccel_carrier(&cfg, true, false, true, true, None, false),
            (
                "main_core_tun_suspended_standalone",
                false,
                true,
                "suspended_for_tun"
            )
        );

        // 4. Enabled relays + non-direct + running core without TUN reports `main_core_proxy_only`.
        assert_eq!(
            resolve_effective_preaccel_carrier(&cfg, true, false, true, false, None, false),
            ("main_core_proxy_only", false, false, "off")
        );

        // 5. Live standalone tunnel processes report `standalone_windivert` / `standalone_socks5`.
        let wd_meta = GlobalPreAccelRuntimeMeta {
            running: true,
            mode: "windivert".to_string(),
            ..GlobalPreAccelRuntimeMeta::default()
        };
        assert_eq!(
            resolve_effective_preaccel_carrier(&cfg, true, false, false, false, Some(&wd_meta), true),
            ("standalone_windivert", true, false, "windivert")
        );
        let socks_meta = GlobalPreAccelRuntimeMeta {
            running: true,
            mode: "local_socks5".to_string(),
            ..GlobalPreAccelRuntimeMeta::default()
        };
        assert_eq!(
            resolve_effective_preaccel_carrier(&cfg, true, false, false, false, Some(&socks_meta), true),
            ("standalone_socks5", true, false, "local_socks5")
        );
    }

    #[test]
    fn live_baseline_reads_tun_section_beyond_512_lines_of_fake_ip_filter() {
        use catcloud_core::core_adapter::ControllerEndpointSource;

        let temp_root = std::env::temp_dir().join(format!(
            "catcloud-cli-large-fake-ip-filter-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        std::fs::create_dir_all(&temp_root).unwrap();
        let runtime_yaml_path = temp_root.join("runtime.yaml");

        let mut yaml = String::from(concat!(
            "mixed-port: 17890\n",
            "allow-lan: false\n",
            "mode: rule\n",
            "dns:\n",
            "  enable: true\n",
            "  listen: 127.0.0.1:21053\n",
            "  ipv6: false\n",
            "  fake-ip-filter:\n",
        ));
        for idx in 0..700usize {
            yaml.push_str(&format!("    - 'node-{idx}.demo.example.invalid'\n"));
        }
        yaml.push_str(concat!(
            "tun:\n",
            "  enable: true\n",
            "  stack: gvisor\n",
            "  device: CatCloudBig\n",
            "  mtu: 1480\n",
            "  auto-route: true\n",
            "  auto-detect-interface: true\n",
            "  strict-route: false\n",
            "proxies:\n",
            "  - name: dummy\n",
            "    type: trojan\n",
            "    server: 203.0.113.10\n",
            "    port: 443\n",
        ));
        std::fs::write(&runtime_yaml_path, &yaml).unwrap();

        let mut cfg = AppConfig::default();
        cfg.tun.enabled = false;
        cfg.tun.stack_mode = TunStackMode::Mixed;
        cfg.tun.device_name = "CatCloud".to_string();
        cfg.tun.mtu = 1500;
        cfg.tun.strict_route = true;

        let ep = ResolvedControllerEndpoint {
            host: "127.0.0.1".to_string(),
            port: 19090,
            secret: "demo".to_string(),
            mixed_port: None,
            dns_port: None,
            pid: None,
            process_start_time_unix: None,
            binary_path: None,
            source: ControllerEndpointSource::ExplicitConfigSecret,
        };

        let baseline =
            build_live_baseline_config_from_runtime(&cfg, &runtime_yaml_path, None, &ep);
        assert_eq!(baseline.mixed_port, 17890);
        assert_eq!(baseline.dns_listen_port, 21053);
        assert!(baseline.tun.enabled, "tun.enable past >600 fake-ip-filter lines must be parsed");
        assert_eq!(baseline.tun.stack_mode, TunStackMode::Gvisor);
        assert_eq!(baseline.tun.device_name, "CatCloudBig");
        assert_eq!(baseline.tun.mtu, 1480);
        assert!(!baseline.tun.strict_route);

        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn pid_reuse_guards_fail_closed_on_missing_start_time_self_pid_and_non_windows_process_name() {
        let self_pid = std::process::id();
        let other_pid = if self_pid == 42420 { 42421 } else { 42420 };

        // 1. `is_port_owned_by_active_core`: missing actual start time fails closed, self PID rejected.
        let owner_missing_ts = PortListenerOwner {
            port: 7890,
            protocol: "tcp".to_string(),
            pid: other_pid,
            process_start_time_unix: None,
        };
        assert!(!is_port_owned_by_active_core(
            7890,
            true,
            Some(other_pid),
            Some(1_700_000_000),
            &[owner_missing_ts],
            false,
        ));
        let owner_matching_ts = PortListenerOwner {
            port: 7890,
            protocol: "tcp".to_string(),
            pid: other_pid,
            process_start_time_unix: Some(1_700_000_001),
        };
        assert!(is_port_owned_by_active_core(
            7890,
            true,
            Some(other_pid),
            Some(1_700_000_000),
            &[owner_matching_ts],
            false,
        ));
        let owner_self = PortListenerOwner {
            port: 7890,
            protocol: "tcp".to_string(),
            pid: self_pid,
            process_start_time_unix: Some(1_700_000_000),
        };
        assert!(!is_port_owned_by_active_core(
            7890,
            true,
            Some(self_pid),
            Some(1_700_000_000),
            &[owner_self.clone()],
            false,
        ));

        // 2. `verify_managed_pid_with_start_time`: missing actual start time fails closed, self PID rejected.
        assert!(!verify_managed_pid_with_start_time(
            other_pid,
            "mihomo.exe",
            Some(other_pid),
            Some(1_700_000_000),
            None,
        ));
        assert!(!verify_managed_pid_with_start_time(
            self_pid,
            "mihomo.exe",
            Some(self_pid),
            Some(1_700_000_000),
            Some(1_700_000_000),
        ));
        assert!(verify_managed_pid_with_start_time(
            other_pid,
            "mihomo.exe",
            Some(other_pid),
            Some(1_700_000_000),
            Some(1_700_000_002),
        ));

        // 3. `collect_verified_listener_pids`: missing actual start time fails closed, self PID rejected.
        let verified_missing = collect_verified_listener_pids(
            &[PortListenerOwner {
                port: 19090,
                protocol: "tcp".to_string(),
                pid: other_pid,
                process_start_time_unix: None,
            }],
            Some(other_pid),
            Some(1_700_000_000),
            None,
            None,
        );
        assert!(verified_missing.is_empty());
        let verified_self = collect_verified_listener_pids(
            &[owner_self],
            Some(self_pid),
            Some(1_700_000_000),
            None,
            None,
        );
        assert!(verified_self.is_empty());
        let verified_ok = collect_verified_listener_pids(
            &[PortListenerOwner {
                port: 19090,
                protocol: "tcp".to_string(),
                pid: other_pid,
                process_start_time_unix: Some(1_700_000_002),
            }],
            Some(other_pid),
            Some(1_700_000_000),
            None,
            None,
        );
        assert!(verified_ok.contains(&other_pid));

        // 4. `is_live_global_preaccel_pid` & `evaluate_live_global_preaccel_pid`:
        //    reject self PID, fail closed on missing start time, and validate non-Windows process name.
        let self_meta = GlobalPreAccelRuntimeMeta {
            running: true,
            pid: Some(self_pid),
            process_start_time_unix: get_process_start_time_unix(self_pid),
            mode: "local_socks5".to_string(),
            ..GlobalPreAccelRuntimeMeta::default()
        };
        assert!(!is_live_global_preaccel_pid(&self_meta));

        let other_meta = GlobalPreAccelRuntimeMeta {
            running: true,
            pid: Some(other_pid),
            process_start_time_unix: Some(1_700_000_000),
            mode: "local_socks5".to_string(),
            ..GlobalPreAccelRuntimeMeta::default()
        };
        assert!(evaluate_live_global_preaccel_pid(
            &other_meta,
            Some(1_700_000_001),
            Some(Some("mihomo-linux-amd64")),
            None,
        ));
        assert!(!evaluate_live_global_preaccel_pid(
            &other_meta,
            Some(1_700_000_001),
            Some(Some("python3")),
            None,
        ));
        assert!(!evaluate_live_global_preaccel_pid(
            &other_meta,
            Some(1_700_000_001),
            Some(None),
            None,
        ));
        assert!(!evaluate_live_global_preaccel_pid(
            &other_meta,
            None,
            Some(Some("mihomo")),
            None,
        ));
    }

    #[test]
    fn preaccel_speed_reference_node_skips_ipv6_only_for_ipv4_relay_without_breaking_dual_stack() {
        let ipv6_only = ProxyNode {
            id: "n-v6-only".to_string(),
            sub_id: "sub-1".to_string(),
            name: "JP Pure IPv6".to_string(),
            protocol: "vless".to_string(),
            server: "2001:db8:cafe::1".to_string(),
            port: 8443,
            is_443_native: false,
            enabled: true,
            ..ProxyNode::default()
        };
        let dual_stack_named_ipv6 = ProxyNode {
            id: "n-hk-dual".to_string(),
            sub_id: "sub-1".to_string(),
            name: "HK-01-IPv6".to_string(),
            protocol: "trojan".to_string(),
            server: "hk01.example.com".to_string(),
            port: 8443,
            is_443_native: false,
            enabled: true,
            ..ProxyNode::default()
        };
        let mut cfg = AppConfig::default();
        cfg.route_mode = RouteTargetMode::Single;
        cfg.active_single_node_id = Some("n-v6-only".to_string());

        // 1. Homepage IPv6-only node gracefully falls back to dual-stack `HK-01-IPv6` when relay is IPv4-only.
        let (picked, note) = select_preaccel_speed_reference_node(
            &cfg,
            &[],
            &[ipv6_only.clone(), dual_stack_named_ipv6.clone()],
            None,
            false,
        )
        .expect("fallback from IPv6-only homepage node");
        assert_eq!(picked.as_ref().map(|n| n.id.as_str()), Some("n-hk-dual"));
        assert!(note.as_deref().is_some_and(|n| n.contains("IPv6-only")));

        // 2. Dual-stack `HK-01-IPv6` is NOT skipped when selected on homepage.
        cfg.active_single_node_id = Some("n-hk-dual".to_string());
        let (picked_dual, note_dual) = select_preaccel_speed_reference_node(
            &cfg,
            &[],
            &[ipv6_only.clone(), dual_stack_named_ipv6.clone()],
            None,
            false,
        )
        .expect("dual-stack node kept");
        assert_eq!(picked_dual.as_ref().map(|n| n.id.as_str()), Some("n-hk-dual"));
        assert!(note_dual.is_none());

        // 3. When relay supports IPv6, IPv6-only homepage node is kept directly.
        cfg.active_single_node_id = Some("n-v6-only".to_string());
        let (picked_v6, note_v6) = select_preaccel_speed_reference_node(
            &cfg,
            &[],
            &[ipv6_only.clone(), dual_stack_named_ipv6.clone()],
            None,
            true,
        )
        .expect("IPv6-capable relay keeps IPv6-only node");
        assert_eq!(picked_v6.as_ref().map(|n| n.id.as_str()), Some("n-v6-only"));
        assert!(note_v6.is_none());

        // 4. Explicit requested_node_id honors user choice even for IPv6-only node.
        let (picked_explicit, note_explicit) = select_preaccel_speed_reference_node(
            &cfg,
            &[],
            &[ipv6_only.clone(), dual_stack_named_ipv6],
            Some("n-v6-only"),
            false,
        )
        .expect("explicit node honored");
        assert_eq!(picked_explicit.as_ref().map(|n| n.id.as_str()), Some("n-v6-only"));
        assert!(note_explicit.is_none());

        // 5. Only IPv6-only node with IPv4-only relay gracefully falls back to single-hop speed test.
        let (single_hop, single_note) =
            select_preaccel_speed_reference_node(&cfg, &[], &[ipv6_only], None, false)
                .expect("fallback to single-hop when only IPv6-only nodes exist");
        assert!(single_hop.is_none());
        assert!(single_note.as_deref().is_some_and(|n| n.contains("single-hop")));
    }

    #[tokio::test]
    async fn cli_tun_state_does_not_misreport_enabled_when_live_core_reports_tun_disabled() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock controller");
        let mock_port = listener.local_addr().unwrap().port();
        let secret = "test-bp15-secret";

        let server_task = tokio::spawn(async move {
            for _ in 0..16 {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut req_buf = [0u8; 2048];
                let n = stream.read(&mut req_buf).await.unwrap_or(0);
                let req_str = String::from_utf8_lossy(&req_buf[..n]);
                let has_auth = req_str
                    .to_ascii_lowercase()
                    .contains("authorization: bearer test-bp15-secret");
                let (status_line, body) = if !has_auth {
                    ("HTTP/1.1 401 Unauthorized", r#"{"message":"Unauthorized"}"#)
                } else if req_str.starts_with("GET /version ") {
                    ("HTTP/1.1 200 OK", r#"{"version":"v1.19.1"}"#)
                } else if req_str.starts_with("GET /configs ") {
                    (
                        "HTTP/1.1 200 OK",
                        r#"{"tun":{"enable":false},"mixed-port":17890,"port":0,"socks-port":0,"bind-address":"127.0.0.1","allow-lan":false,"mode":"rule"}"#,
                    )
                } else if req_str.starts_with("GET /connections ") {
                    ("HTTP/1.1 200 OK", r#"{"downloadTotal":0,"uploadTotal":0,"connections":[]}"#)
                } else {
                    ("HTTP/1.1 200 OK", r#"{}"#)
                };
                let resp = format!(
                    "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            }
        });

        let temp_root = std::env::temp_dir().join(format!(
            "catcloud-cli-live-tun-disabled-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");
        let mut cfg = config::load_or_init(&paths).expect("init config");
        cfg.controller_port = mock_port;
        cfg.controller_secret = Some(secret.to_string());
        cfg.tun.enabled = true;
        config::save(&paths, &cfg).expect("save config");

        let mut unpriv_caps = default_platform().capabilities();
        unpriv_caps.is_elevated = false;

        let active_ports = inspect_active_core_ports(&paths, &cfg).await;
        assert!(active_ports.core_running);
        assert_eq!(
            active_ports.live_config.as_ref().map(|lc| lc.tun_enable),
            Some(false)
        );

        let (tun_enabled, tun_needs_elevation, tun_source) =
            resolve_cli_effective_tun_state_with_probe(&cfg, &unpriv_caps, None, &active_ports)
                .await;
        assert!(!tun_enabled, "must NOT misreport tun_enabled=true when live /configs says false");
        assert!(tun_needs_elevation);
        assert_eq!(tun_source, "live_core_tun_disabled_needs_elevation");

        let (doctor, _) = build_net_doctor_payload(&paths).await.expect("net doctor");
        let tun_check = doctor["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == "system_proxy_and_tun")
            .expect("system_proxy_and_tun check");
        assert_eq!(tun_check["data"]["tun_enabled"], json!(false));
        assert_ne!(
            tun_check["data"]["tun_runtime_source"],
            json!("live_core_with_tun_config")
        );

        server_task.abort();
        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[tokio::test]
    async fn status_and_net_doctor_emit_preaccel_transport_diagnostics_and_sanitize_private_and_public_ips()
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock controller");
        let mock_port = listener.local_addr().unwrap().port();
        let secret = "stage21-diag-secret-token";

        let proxies_body = serde_json::json!({
            "proxies": {
                PREACCEL_SELECT_GROUP_NAME: {
                    "type": "Selector",
                    "now": "🔄 预加速自动双活"
                },
                "🔄 预加速自动双活": {
                    "type": "Fallback",
                    "now": "Relay-Priv-10.23.45.67-Pub-203.0.113.88"
                },
                "AI-Stable": {
                    "type": "Selector",
                    "now": "Exit-Priv-192.168.88.12-Pub-198.51.100.77"
                }
            }
        })
        .to_string();

        let server_task = tokio::spawn(async move {
            for _ in 0..32 {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut req_buf = [0u8; 2048];
                let n = stream.read(&mut req_buf).await.unwrap_or(0);
                let req_str = String::from_utf8_lossy(&req_buf[..n]);
                let has_auth = req_str
                    .to_ascii_lowercase()
                    .contains("authorization: bearer stage21-diag-secret-token");
                let (status_line, body) = if !has_auth {
                    ("HTTP/1.1 401 Unauthorized", r#"{"message":"Unauthorized"}"#.to_string())
                } else if req_str.starts_with("GET /version ") {
                    ("HTTP/1.1 200 OK", r#"{"version":"v1.19.34"}"#.to_string())
                } else if req_str.starts_with("GET /configs ") {
                    (
                        "HTTP/1.1 200 OK",
                        r#"{"tun":{"enable":true},"mixed-port":17890,"port":0,"socks-port":0,"bind-address":"127.0.0.1","allow-lan":false,"mode":"rule"}"#.to_string(),
                    )
                } else if req_str.starts_with("GET /connections ") {
                    (
                        "HTTP/1.1 200 OK",
                        r#"{"downloadTotal":0,"uploadTotal":0,"connections":[]}"#.to_string(),
                    )
                } else if req_str.starts_with("GET /proxies ") {
                    ("HTTP/1.1 200 OK", proxies_body.clone())
                } else {
                    ("HTTP/1.1 200 OK", r#"{}"#.to_string())
                };
                let resp = format!(
                    "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            }
        });

        let temp_root = std::env::temp_dir().join(format!(
            "catcloud-cli-s21-transport-diag-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");
        let mut cfg = config::load_or_init(&paths).expect("init config");
        cfg.controller_port = mock_port;
        cfg.controller_secret = Some(secret.to_string());
        cfg.tun.enabled = true;
        cfg.tun.mtu = 1500;
        cfg.preaccel.enabled = true;
        cfg.active_group_id = Some("grp-ai".to_string());
        config::save(&paths, &cfg).expect("save config");

        let db = open_storage(&paths).expect("open db");
        db.upsert_subscription(&SubscriptionRecord {
            id: "sub-s21".to_string(),
            name: "Sub-S21".to_string(),
            kind: SubscriptionKind::File,
            url_or_cmd: "s21.yaml".to_string(),
            ..Default::default()
        })
        .expect("upsert subscription");
        db.upsert_preaccel_relay(&PreAccelRelay {
            id: "relay-s21".to_string(),
            name: "Relay-Priv-10.23.45.67-Pub-203.0.113.88".to_string(),
            provider: "cloud-a".to_string(),
            region: "CN-East".to_string(),
            server: "203.0.113.88".to_string(),
            port: 443,
            protocol: "anytls".to_string(),
            password: "demo-secret-relay-pw".to_string(),
            sni: None,
            skip_cert_verify: true,
            priority: 10,
            expires_at: None,
            enabled: true,
            supports_ipv6: false,
            last_probe_ms: None,
            last_mbps: None,
            last_up_mbps: None,
            last_down_mbps: None,
        })
        .expect("upsert relay");
        db.upsert_node(&ProxyNode {
            id: "node-s21".to_string(),
            sub_id: "sub-s21".to_string(),
            name: "Exit-Priv-192.168.88.12-Pub-198.51.100.77".to_string(),
            protocol: "ss".to_string(),
            server: "198.51.100.77".to_string(),
            port: 8443,
            is_443_native: false,
            preaccel_eligible: true,
            preaccel_override: None,
            enabled: true,
            raw_config: json!({
                "name": "Exit-Priv-192.168.88.12-Pub-198.51.100.77",
                "type": "ss",
                "server": "198.51.100.77",
                "port": 8443,
                "cipher": "aes-128-gcm",
                "password": "demo-secret-node-pw"
            }),
            ..Default::default()
        })
        .expect("upsert node");
        db.upsert_multi_group(&MultiGroup {
            id: "grp-ai".to_string(),
            name: "AI-Stable".to_string(),
            mode: MultiGroupMode::StickyBest,
            member_node_ids: vec!["node-s21".to_string()],
            active_node_id: Some("node-s21".to_string()),
            ..Default::default()
        })
        .expect("upsert multi group");

        let runtime_yaml_path = paths.runtime_dir.join("runtime.yaml");
        let runtime_yaml_body = "mixed-port: 17890\ntun:\n  enable: true\n  mtu: 1400\n";
        std::fs::write(&runtime_yaml_path, runtime_yaml_body).expect("write runtime.yaml");
        let expected_sha256 = compute_file_sha256(&runtime_yaml_path).expect("sha256");

        let (status_json, _) = build_status_payload(&paths).await.expect("status payload");
        let (doctor_json, _) = build_net_doctor_payload(&paths).await.expect("net doctor payload");

        for (label, payload) in [("status", &status_json), ("net_doctor", &doctor_json)] {
            let diag = &payload["preaccel_transport_diagnostics"];
            assert_eq!(diag["effective_mode"], json!("main-tun-core"), "{label}");
            assert_eq!(diag["effective_tun_mtu"], json!(1400), "{label}");
            assert_eq!(diag["anytls_tfo"], json!(false), "{label}");
            assert_eq!(diag["anytls_min_idle_session"], json!(0), "{label}");
            assert_eq!(diag["keep_alive_idle_sec"], json!(45), "{label}");
            assert_eq!(diag["keep_alive_interval_sec"], json!(15), "{label}");
            assert_eq!(diag["expected_probe_status"], json!("204"), "{label}");
            assert_eq!(diag["lb_strategy"], json!("consistent-hashing"), "{label}");
            assert_eq!(diag["probe_interval_sec"], json!(30), "{label}");

            assert_eq!(
                payload["runtime_config_sha256"],
                json!(expected_sha256),
                "{label} must preserve 64-hex runtime_config_sha256"
            );
            let relay_sel = payload["active_relay_selected"]
                .as_str()
                .expect("active_relay_selected present");
            let exit_sel = payload["active_exit_selected"]
                .as_str()
                .expect("active_exit_selected present");
            assert!(relay_sel.contains("10.23.45.*"), "{label}: {relay_sel}");
            assert!(relay_sel.contains("203.0.113.*"), "{label}: {relay_sel}");
            assert!(exit_sel.contains("192.168.88.*"), "{label}: {exit_sel}");
            assert!(exit_sel.contains("198.51.100.*"), "{label}: {exit_sel}");

            let serialized = serde_json::to_string(payload).expect("serialize payload");
            for leaked in [
                "10.23.45.67",
                "203.0.113.88",
                "192.168.88.12",
                "198.51.100.77",
                "stage21-diag-secret-token",
                "demo-secret-relay-pw",
                "demo-secret-node-pw",
            ] {
                assert!(
                    !serialized.contains(leaked),
                    "{label} leaked raw sensitive fixture `{leaked}`: {serialized}"
                );
            }
        }

        server_task.abort();
        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn config_export_gateway_cli_parse_defaults_and_custom_flags() {
        use clap::Parser;

        #[derive(Parser, Debug)]
        struct TestCli {
            #[command(subcommand)]
            command: Commands,
        }

        let parsed_default =
            TestCli::try_parse_from(["catcloud", "config", "export-gateway"]).expect("default parse");
        match parsed_default.command {
            Commands::Config {
                action:
                    ConfigCommand::ExportGateway {
                        profile,
                        tproxy_port,
                        redir_port,
                        dns_port,
                        output,
                        reveal_secrets,
                    },
            } => {
                assert_eq!(profile, "relay-fragment");
                assert_eq!(tproxy_port, 7893);
                assert_eq!(redir_port, 7892);
                assert_eq!(dns_port, 1053);
                assert!(output.is_none());
                assert!(!reveal_secrets, "must default to redacted mode");
            }
            other => panic!("unexpected parsed command: {other:?}"),
        }

        let parsed_custom = TestCli::try_parse_from([
            "catcloud",
            "config",
            "export-gateway",
            "--profile",
            "transparent-gateway",
            "--tproxy-port",
            "17893",
            "--redir-port",
            "17892",
            "--dns-port",
            "11053",
            "--output",
            "gateway.yaml",
            "--reveal-secrets",
        ])
        .expect("custom parse");
        match parsed_custom.command {
            Commands::Config {
                action:
                    ConfigCommand::ExportGateway {
                        profile,
                        tproxy_port,
                        redir_port,
                        dns_port,
                        output,
                        reveal_secrets,
                    },
            } => {
                assert_eq!(
                    parse_gateway_export_profile(&profile).unwrap(),
                    GatewayExportProfile::TransparentGateway
                );
                assert_eq!(tproxy_port, 17893);
                assert_eq!(redir_port, 17892);
                assert_eq!(dns_port, 11053);
                assert_eq!(output, Some(PathBuf::from("gateway.yaml")));
                assert!(reveal_secrets);
            }
            other => panic!("unexpected parsed command: {other:?}"),
        }

        assert_eq!(
            parse_gateway_export_profile("preferred-nodes").unwrap(),
            GatewayExportProfile::PreferredNodes
        );
        assert!(parse_gateway_export_profile("unknown-mode").is_err());
    }

    #[tokio::test]
    async fn config_export_gateway_redacts_private_public_ips_and_secrets_by_default_and_writes_atomically()
    {
        let temp_root = std::env::temp_dir().join(format!(
            "catcloud-cli-export-gateway-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");
        let mut cfg = config::load_or_init(&paths).expect("init config");
        cfg.preaccel.enabled = true;
        cfg.tun.enabled = true;
        cfg.controller_secret = Some("cli-gw-controller-secret-9988".to_string());
        cfg.rules_override.global_prepend_rules =
            vec!["IP-CIDR,10.23.45.67/32,DIRECT,no-resolve".to_string()];
        config::save(&paths, &cfg).expect("save config");

        let db = open_storage(&paths).expect("open db");
        db.upsert_subscription(&SubscriptionRecord {
            id: "sub-gw".to_string(),
            name: "Sub-GW".to_string(),
            kind: SubscriptionKind::File,
            url_or_cmd: "gw.yaml".to_string(),
            ..Default::default()
        })
        .expect("upsert subscription");
        db.upsert_preaccel_relay(&PreAccelRelay {
            id: "relay-gw-1".to_string(),
            name: "Relay-CN-East".to_string(),
            provider: "cloud-a".to_string(),
            region: "CN-East".to_string(),
            server: "203.0.113.88".to_string(),
            port: 443,
            protocol: "anytls".to_string(),
            password: "cli-gw-relay-secret-pw".to_string(),
            sni: None,
            skip_cert_verify: true,
            priority: 10,
            expires_at: None,
            enabled: true,
            supports_ipv6: false,
            last_probe_ms: None,
            last_mbps: None,
            last_up_mbps: None,
            last_down_mbps: None,
        })
        .expect("upsert relay");
        db.upsert_node(&ProxyNode {
            id: "node-gw-1".to_string(),
            sub_id: "sub-gw".to_string(),
            name: "Exit-LAN-192.168.88.12".to_string(),
            protocol: "ss".to_string(),
            server: "198.51.100.77".to_string(),
            port: 8443,
            is_443_native: false,
            preaccel_eligible: true,
            preaccel_override: None,
            enabled: true,
            raw_config: json!({
                "name": "Exit-LAN-192.168.88.12",
                "type": "ss",
                "server": "198.51.100.77",
                "port": 8443,
                "cipher": "aes-128-gcm",
                "password": "cli-gw-node-secret-pw"
            }),
            ..Default::default()
        })
        .expect("upsert node");

        // 1. Redacted export (default) must mask private & public IPs and all credentials while remaining valid YAML.
        let redacted_out = temp_root.join("gw-redacted.yaml");
        execute_config_export_gateway(
            &paths,
            true,
            "transparent-gateway",
            17893,
            17892,
            11053,
            Some(redacted_out.clone()),
            false,
        )
        .await
        .expect("redacted export succeeds");
        let redacted_yaml = std::fs::read_to_string(&redacted_out).expect("read redacted file");
        let redacted_report =
            validate_compiled_yaml(&redacted_yaml, &[]).expect("redacted YAML must parse cleanly");
        assert!(
            !redacted_report.issues.iter().any(|i| matches!(
                i.code.as_str(),
                "invalid_proxy_group" | "empty_proxy_group" | "group_cycle" | "unknown_rule_target"
            )),
            "redacted transparent gateway YAML had structural errors: {:?}",
            redacted_report.issues
        );
        assert!(redacted_yaml.contains("allow-lan: true"));
        assert!(redacted_yaml.contains("tproxy-port: 17893"));
        assert!(redacted_yaml.contains("redir-port: 17892"));
        assert!(redacted_yaml.contains("listen: 0.0.0.0:11053"));
        assert!(redacted_yaml.contains("tun:\n  enable: false"));

        for secret_val in [
            "10.23.45.67",
            "192.168.88.12",
            "203.0.113.88",
            "198.51.100.77",
            "cli-gw-controller-secret-9988",
            "cli-gw-relay-secret-pw",
            "cli-gw-node-secret-pw",
        ] {
            assert!(
                !redacted_yaml.contains(secret_val),
                "default redacted export leaked `{secret_val}`"
            );
        }

        // 2. Explicit `--reveal-secrets` emits deployable plaintext YAML with exact relay/node fields.
        let plain_out = temp_root.join("gw-plain.yaml");
        execute_config_export_gateway(
            &paths,
            true,
            "transparent-gateway",
            17893,
            17892,
            11053,
            Some(plain_out.clone()),
            true,
        )
        .await
        .expect("plaintext export succeeds");
        let plain_yaml = std::fs::read_to_string(&plain_out).expect("read plaintext file");
        let plain_report = validate_compiled_yaml(&plain_yaml, &["203.0.113.88".to_string()])
            .expect("plaintext YAML must parse cleanly");
        assert!(
            plain_report.ok,
            "plaintext transparent gateway YAML should pass static validation: {:?}",
            plain_report.issues
        );
        assert!(plain_yaml.contains("bind-address: '*'"));
        assert!(plain_yaml.contains("203.0.113.88"));
        assert!(plain_yaml.contains("198.51.100.77"));
        assert!(plain_yaml.contains("cli-gw-relay-secret-pw"));
        assert!(plain_yaml.contains("cli-gw-node-secret-pw"));
        assert!(plain_yaml.contains("cli-gw-controller-secret-9988"));

        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn read_tun_mtu_from_runtime_yaml_checks_tun_enable_and_supports_flow_yaml() {
        let temp_root = std::env::temp_dir().join(format!(
            "catcloud-cli-tun-mtu-yaml-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        std::fs::create_dir_all(&temp_root).unwrap();

        let p_block_on = temp_root.join("block_on.yaml");
        std::fs::write(&p_block_on, "\u{feff}tun:\n  enable: true\n  mtu: 1400\n").unwrap();
        assert_eq!(read_tun_mtu_from_runtime_yaml(&p_block_on), Some(1400));

        let p_flow_on = temp_root.join("flow_on.yaml");
        std::fs::write(&p_flow_on, "tun: { enable: true, mtu: 1420 }\n").unwrap();
        assert_eq!(read_tun_mtu_from_runtime_yaml(&p_flow_on), Some(1420));

        let p_block_off = temp_root.join("block_off.yaml");
        std::fs::write(&p_block_off, "tun:\n  enable: false\n  mtu: 1400\n").unwrap();
        assert_eq!(read_tun_mtu_from_runtime_yaml(&p_block_off), None);

        let p_flow_off = temp_root.join("flow_off.yaml");
        std::fs::write(&p_flow_off, "tun: { enable: false, mtu: 1400 }\n").unwrap();
        assert_eq!(read_tun_mtu_from_runtime_yaml(&p_flow_off), None);

        let p_missing_enable = temp_root.join("missing_enable.yaml");
        std::fs::write(&p_missing_enable, "tun:\n  mtu: 1400\n").unwrap();
        assert_eq!(read_tun_mtu_from_runtime_yaml(&p_missing_enable), None);

        let _ = std::fs::remove_dir_all(&temp_root);
    }
}
