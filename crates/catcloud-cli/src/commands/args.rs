//! Clap CLI command enums, argument structs, and `AlreadyEmittedJsonError`.

use clap::{Args, Subcommand};
use std::path::PathBuf;

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
    /// Trigger live hot-reload on the running CatCloud desktop app (falling back to direct core reload)
    Reload(ReloadArgs),
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
        /// Optional process executable name (e.g. QQ.exe) for PROCESS-NAME / composite rule matching
        #[arg(long = "process-name")]
        process_name: Option<String>,
        /// Optional process executable path for PROCESS-PATH / basename fallback matching
        #[arg(long = "process-path")]
        process_path: Option<String>,
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
    /// Also import sanitized valid routing rules (dangling third-party group targets are dropped and bound to subscription)
    #[arg(long)]
    pub include_rules: bool,
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
    /// Enable or disable parallel independent routing for this group
    #[arg(long)]
    pub independent_routing: Option<bool>,
    /// Replace group match rules (semicolon-separated full rules or comma-separated domains)
    #[arg(long = "match-rules")]
    pub match_rules: Option<String>,
    /// Append one or more match rules (repeatable)
    #[arg(long = "add-match-rule")]
    pub add_match_rule: Vec<String>,
    /// Hard gate boolean formula expressions (repeatable)
    #[arg(long = "hard-gate")]
    pub hard_gate: Vec<String>,
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
    /// Enable or disable parallel independent routing for this group
    #[arg(long)]
    pub independent_routing: Option<bool>,
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

#[derive(Args, Debug, Clone, Default)]
pub struct ReloadArgs {
    /// Validate candidate runtime.yaml without writing or signaling the running instance
    #[arg(long)]
    pub dry_run: bool,
    /// Force recompilation and reload even if configuration fingerprint appears unchanged
    #[arg(long)]
    pub force: bool,
    /// Allow L3 core restart (listening ports / TUN / core runtime changes) when handled by desktop
    #[arg(long)]
    pub allow_restart: bool,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// Validate config.json, compiled Mihomo YAML, and anti-loop preflight checks
    Validate,
    /// Audit and repair dangling global rules targeting non-existent proxy groups
    RepairRules {
        /// Repair strategy: remove | rewrite
        #[arg(long, default_value = "remove")]
        mode: String,
        /// Target existing group name when `--mode rewrite` (defaults to active/first group)
        #[arg(long)]
        target: Option<String>,
        /// Preview affected rules without writing config.json or reloading
        #[arg(long)]
        dry_run: bool,
    },
    /// Validate, write runtime.yaml (with mihomo -t when available), and hot-reload live instance
    Reload(ReloadArgs),
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
        /// Optional current version override recorded as `from_version` (defaults to CLI version)
        #[arg(long)]
        from_version: Option<String>,
    },
    /// Signal a running portable desktop instance to verify `.update_staging/` and self-update in place
    Apply {
        /// Relaunch silently to tray without popping the main window (`--silent-relaunch`)
        #[arg(long)]
        silent: bool,
        /// Timeout in seconds waiting for desktop handoff acknowledgment
        #[arg(long, default_value_t = 12)]
        timeout_secs: u64,
    },
}
