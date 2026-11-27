use crate::config::{load_or_default, validate_config};
use crate::core_adapter::binary_resolver::resolve_mihomo_binary;
use crate::core_adapter::config_compiler::{
    CompileInput, CompiledCoreConfig, compile_mihomo_config_with_runtime_dir,
};
use crate::core_adapter::mihomo::{
    MihomoAdapter, generate_controller_secret, verify_config_with_binary,
};
use crate::core_adapter::port_guard::{
    AllocatedPorts, PortShiftNotice, allocate_safe_ports_for_hosts, is_port_available_tcp_udp,
};
use crate::core_adapter::stream_client::StreamCancelToken;
use crate::core_adapter::{CoreRuntimeStatus, CoreStartRequest, ReloadLevel, ReloadOutcome};
use crate::error::{CatError, CatResult};
use crate::models::{AppConfig, MultiGroup, PreAccelRelay, ProxyNode};
use crate::paths::AppPaths;
use crate::storage::Storage;
use chrono::Utc;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, broadcast, mpsc};
use tokio::task::JoinHandle;

/// Default filesystem event debounce window (300ms) for hot-reload watcher.
pub const DEFAULT_DEBOUNCE_WINDOW: Duration = Duration::from_millis(300);

/// Decision returned by `HotReloadDebouncer::evaluate_and_consume`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebounceDecision {
    NoPendingEvent,
    Wait(Duration),
    SkipDuplicate { sha256: String },
    TriggerReload { sha256: String },
}

/// Pure, deterministic state machine implementing 300ms debounce and SHA-256 content deduplication.
#[derive(Debug, Clone)]
pub struct HotReloadDebouncer {
    debounce_window: Duration,
    last_event_at: Option<Instant>,
    last_applied_hash: Option<String>,
}

impl HotReloadDebouncer {
    pub fn new(debounce_window: Duration) -> Self {
        Self {
            debounce_window,
            last_event_at: None,
            last_applied_hash: None,
        }
    }

    pub fn with_initial_hash(debounce_window: Duration, initial_hash: impl Into<String>) -> Self {
        Self {
            debounce_window,
            last_event_at: None,
            last_applied_hash: Some(initial_hash.into()),
        }
    }

    pub fn debounce_window(&self) -> Duration {
        self.debounce_window
    }

    pub fn last_applied_hash(&self) -> Option<&str> {
        self.last_applied_hash.as_deref()
    }

    pub fn record_event(&mut self, now: Instant) {
        self.last_event_at = Some(now);
    }

    pub fn has_pending_event(&self) -> bool {
        self.last_event_at.is_some()
    }

    pub fn time_until_ready(&self, now: Instant) -> Option<Duration> {
        let last = self.last_event_at?;
        let elapsed = now.saturating_duration_since(last);
        if elapsed >= self.debounce_window {
            Some(Duration::ZERO)
        } else {
            Some(self.debounce_window - elapsed)
        }
    }

    pub fn is_ready(&self, now: Instant) -> bool {
        self.time_until_ready(now) == Some(Duration::ZERO)
    }

    /// Evaluate the pending event against `now` and the current content bytes.
    ///
    /// - Returns `Wait(remaining)` if still inside the debounce window.
    /// - Returns `SkipDuplicate` if the window elapsed and content SHA-256 matches the last applied digest.
    /// - Returns `TriggerReload` and updates `last_applied_hash` when content actually changed.
    pub fn evaluate_and_consume(&mut self, now: Instant, content_bytes: &[u8]) -> DebounceDecision {
        let Some(remaining) = self.time_until_ready(now) else {
            return DebounceDecision::NoPendingEvent;
        };
        if !remaining.is_zero() {
            return DebounceDecision::Wait(remaining);
        }

        // Consume the pending trigger.
        self.last_event_at = None;
        let sha256 = Self::compute_fingerprint(&[content_bytes]);
        if self.last_applied_hash.as_deref() == Some(sha256.as_str()) {
            return DebounceDecision::SkipDuplicate { sha256 };
        }
        self.last_applied_hash = Some(sha256.clone());
        DebounceDecision::TriggerReload { sha256 }
    }

    /// Record a freshly applied fingerprint after a direct or forced reload.
    pub fn force_commit_hash(&mut self, sha256: String) {
        self.last_applied_hash = Some(sha256);
        self.last_event_at = None;
    }

    /// Compute a stable SHA-256 fingerprint across one or more byte slices.
    pub fn compute_fingerprint(parts: &[&[u8]]) -> String {
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update((part.len() as u64).to_le_bytes());
            hasher.update(part);
        }
        hex::encode(hasher.finalize())
    }
}

/// Classify the reload tier required when transitioning from `old` to `new`:
/// - `L3CoreRestart`: listening ports, bind/controller/DNS addresses, port guard auto-shift,
///   TUN interface/stack settings, kernel kind/binary path, or Go runtime memory/GC parameters.
/// - `L2HotReload`: DNS settings, rules/override pipeline, geodata mode/loader, domestic pre-accel,
///   core IPv6, unified-delay, tcp-concurrent, find-process-mode, log-level, controller secret, or profile persistence.
/// - `L1Rest`: mode-only switches (`rule`/`global`/`direct`) or pure UI/behavior/system-proxy changes.
pub fn classify_config_diff(old: &AppConfig, new: &AppConfig) -> ReloadLevel {
    let requires_l3 = old.mixed_port != new.mixed_port
        || old.socks_port != new.socks_port
        || old.http_port != new.http_port
        || old.redir_port != new.redir_port
        || old.tproxy_port != new.tproxy_port
        || old.allow_lan != new.allow_lan
        || old.bind_address != new.bind_address
        || old.controller_host != new.controller_host
        || old.controller_port != new.controller_port
        || old.dns_listen_host != new.dns_listen_host
        || old.dns_listen_port != new.dns_listen_port
        || old.port_guard_auto_shift != new.port_guard_auto_shift
        || old.tun.enabled != new.tun.enabled
        || (new.tun.enabled && old.tun != new.tun)
        || old.core_runtime.kernel_kind != new.core_runtime.kernel_kind
        || old.core_runtime.custom_binary_path != new.core_runtime.custom_binary_path
        || old.core_runtime.memory_tier != new.core_runtime.memory_tier
        || old.core_runtime.gogc != new.core_runtime.gogc;

    if requires_l3 {
        return ReloadLevel::L3CoreRestart;
    }

    let requires_l2 = old.route_mode != new.route_mode
        || old.active_single_node_id != new.active_single_node_id
        || old.active_group_id != new.active_group_id
        || old.controller_secret != new.controller_secret
        || old.unified_delay != new.unified_delay
        || old.tcp_concurrent != new.tcp_concurrent
        || old.find_process_mode != new.find_process_mode
        || old.log_level != new.log_level
        || old.core_ipv6 != new.core_ipv6
        || old.dns != new.dns
        || old.dns.direct_nameserver != new.dns.direct_nameserver
        || old.rules_override != new.rules_override
        || old.rules_override.block_quic_udp_443 != new.rules_override.block_quic_udp_443
        || old.rules_override.domestic_direct_enabled != new.rules_override.domestic_direct_enabled
        || old.geodata != new.geodata
        || old.preaccel != new.preaccel
        || old.core_runtime.store_selected != new.core_runtime.store_selected
        || old.core_runtime.store_fake_ip != new.core_runtime.store_fake_ip
        || old.core_runtime.compile_all_nodes != new.core_runtime.compile_all_nodes;

    if requires_l2 {
        return ReloadLevel::L2HotReload;
    }

    ReloadLevel::L1Rest
}

/// Returns true if any core-relevant setting (including `proxy_mode`) changed between `old` and `new`.
pub fn has_core_config_changes(old: &AppConfig, new: &AppConfig) -> bool {
    old.proxy_mode != new.proxy_mode
        || !matches!(classify_config_diff(old, new), ReloadLevel::L1Rest)
}

/// Optional in-memory snapshot injected into `apply_disk_reload` (decoupled from SQLite for tests).
#[derive(Debug, Clone, Default)]
pub struct DiskReloadSnapshot {
    pub nodes: Vec<ProxyNode>,
    pub groups: Vec<MultiGroup>,
    pub relays: Vec<PreAccelRelay>,
}

/// Execution options for a single `apply_disk_reload` run.
#[derive(Debug, Clone)]
pub struct DiskReloadOptions {
    /// Bypass SHA-256 deduplication and force at least an L2 reload (or L3 if ports/TUN/binary changed).
    pub force: bool,
    /// Run `mihomo -t -f <candidate>` pre-flight check when a Mihomo binary is available.
    pub verify_with_binary: bool,
    /// Maximum time allowed for `mihomo -t` verification.
    pub binary_verify_timeout: Duration,
    /// Allow L3 core subprocess restart when `classify_config_diff` returns `L3CoreRestart`.
    pub allow_l3_restart: bool,
    /// Whether the current process has OS privileges/capabilities to enable TUN mode.
    /// When `false`, any `tun.enabled = true` loaded from disk is masked to `false` in memory
    /// during diffing, YAML compilation, and restart without mutating `config.json`.
    pub allow_tun: bool,
    /// Optional override for nodes/groups/relays instead of reading SQLite.
    pub snapshot_override: Option<DiskReloadSnapshot>,
    /// Extra high-priority rules prepended after anti-loop rules (e.g., temporary campus portal rules).
    pub extra_prepend_rules: Vec<String>,
    /// Extra temporary fake-ip-filter entries (e.g., captive portal redirect host).
    pub extra_fake_ip_filters: Vec<String>,
    /// Optional hard-gate filtered member lists keyed by `group.id` or `group.name`.
    pub group_filtered_members: HashMap<String, Vec<String>>,
}

impl Default for DiskReloadOptions {
    fn default() -> Self {
        Self {
            force: false,
            verify_with_binary: true,
            binary_verify_timeout: Duration::from_secs(8),
            allow_l3_restart: true,
            allow_tun: true,
            snapshot_override: None,
            extra_prepend_rules: Vec::new(),
            extra_fake_ip_filters: Vec::new(),
            group_filtered_members: HashMap::new(),
        }
    }
}

#[derive(Debug, Default)]
struct CoordinatorState {
    last_applied_config: Option<AppConfig>,
    last_compiled_hash: Option<String>,
    last_snapshot_fingerprint: Option<String>,
    last_allocated_ports: Option<AllocatedPorts>,
    last_effective_tun_mtu: Option<u16>,
    controller_secret: Option<String>,
    last_binary_path: Option<PathBuf>,
    last_node_count: usize,
    last_rule_count: usize,
    last_active_selections: BTreeMap<String, String>,
}

/// Default TUN MTU assumed by Mihomo when `tun.enable: true` is active without an explicit `mtu` key.
const DEFAULT_LIVE_TUN_MTU: u16 = 1500;

fn compiled_tun_enabled(doc: &serde_yaml_ng::Value) -> bool {
    doc.get("tun")
        .and_then(|t| t.get("enable"))
        .and_then(|v| v.as_bool())
        == Some(true)
}

fn read_runtime_yaml_tun_enabled(runtime_yaml_path: &Path) -> bool {
    let Ok(raw) = std::fs::read_to_string(runtime_yaml_path) else {
        return false;
    };
    let text = raw.strip_prefix('\u{feff}').unwrap_or(&raw);
    let Ok(mut doc) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(text) else {
        return false;
    };
    let _ = doc.apply_merge();
    compiled_tun_enabled(&doc)
}

/// Inspect on-disk `runtime.yaml` to recover the active effective `tun.mtu` when TUN is enabled.
pub fn read_runtime_yaml_tun_mtu(runtime_yaml_path: &Path) -> Option<u16> {
    let raw = std::fs::read_to_string(runtime_yaml_path).ok()?;
    let text = raw.strip_prefix('\u{feff}').unwrap_or(&raw);
    let mut doc: serde_yaml_ng::Value = serde_yaml_ng::from_str(text).ok()?;
    let _ = doc.apply_merge();
    let tun = doc.get("tun")?;
    if !tun.get("enable").and_then(|v| v.as_bool()).unwrap_or(false) {
        return None;
    }
    tun.get("mtu")
        .and_then(|v| v.as_u64())
        .and_then(|v| u16::try_from(v).ok())
}

/// Public alias for inspecting the live `tun.mtu` value directly from an on-disk `runtime.yaml` path.
pub fn read_live_tun_mtu_from_path(path: &Path) -> Option<u16> {
    read_runtime_yaml_tun_mtu(path)
}

/// Enforce `tun.enable = false` on a final compiled configuration when the current process lacks
/// TUN privileges (`!options.allow_tun`), preventing `inline_override_yaml` or merge patches from
/// silently re-enabling TUN.
pub fn enforce_tun_disabled_on_compiled(compiled: &mut CompiledCoreConfig) -> CatResult<()> {
    let Some(root_map) = compiled.value.as_mapping_mut() else {
        return Ok(());
    };
    let tun_key = serde_yaml_ng::Value::String("tun".to_string());
    let enable_key = serde_yaml_ng::Value::String("enable".to_string());
    let mut mutated = false;
    match root_map.get_mut(&tun_key) {
        Some(serde_yaml_ng::Value::Mapping(tun_map)) => {
            if tun_map
                .get(&enable_key)
                .and_then(serde_yaml_ng::Value::as_bool)
                != Some(false)
            {
                tun_map.insert(enable_key, serde_yaml_ng::Value::Bool(false));
                mutated = true;
            }
        }
        Some(other) => {
            let mut tun_map = serde_yaml_ng::Mapping::new();
            tun_map.insert(enable_key, serde_yaml_ng::Value::Bool(false));
            *other = serde_yaml_ng::Value::Mapping(tun_map);
            mutated = true;
        }
        None => {}
    }
    if mutated {
        compiled.yaml = serde_yaml_ng::to_string(&compiled.value)?;
        let mut hasher = Sha256::new();
        hasher.update(compiled.yaml.as_bytes());
        compiled.sha256 = hex::encode(hasher.finalize());
    }
    Ok(())
}

/// Orchestrates disk reading, validation, compilation, static anti-loop pre-flight,
/// optional `mihomo -t` check, safe rejection on failure, and 3-tier hot reloading.
#[derive(Debug, Clone)]
pub struct HotReloadCoordinator {
    paths: AppPaths,
    adapter: Arc<MihomoAdapter>,
    state: Arc<Mutex<CoordinatorState>>,
    op_lock: Arc<Mutex<()>>,
    extra_binary_candidates: Arc<RwLock<Vec<PathBuf>>>,
}

impl HotReloadCoordinator {
    pub fn new(paths: AppPaths, adapter: Arc<MihomoAdapter>) -> Self {
        Self {
            paths,
            adapter,
            state: Arc::new(Mutex::new(CoordinatorState::default())),
            op_lock: Arc::new(Mutex::new(())),
            extra_binary_candidates: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn set_extra_binary_candidates(&self, candidates: Vec<PathBuf>) {
        let mut guard = self
            .extra_binary_candidates
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = candidates;
    }

    fn extra_binary_candidates_snapshot(&self) -> Vec<PathBuf> {
        self.extra_binary_candidates
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn paths(&self) -> &AppPaths {
        &self.paths
    }

    pub fn adapter(&self) -> &Arc<MihomoAdapter> {
        &self.adapter
    }

    /// Seed the coordinator with the currently running configuration and compiled YAML hash
    /// (typically called right after initial core launch).
    pub async fn seed_active_state(
        &self,
        cfg: AppConfig,
        compiled_hash: String,
        allocated_ports: AllocatedPorts,
        controller_secret: String,
    ) {
        let _op_guard = self.op_lock.lock().await;
        let status = self.adapter.runtime_status().await;
        let active_selections = self.adapter.active_selections_snapshot().await;
        let runtime_yaml_path = self.runtime_yaml_path();
        let seeded_tun_mtu = cfg.tun.enabled.then(|| {
            read_runtime_yaml_tun_mtu(&runtime_yaml_path).unwrap_or_else(|| {
                if read_runtime_yaml_tun_enabled(&runtime_yaml_path) {
                    DEFAULT_LIVE_TUN_MTU
                } else {
                    cfg.tun.mtu
                }
            })
        });
        let mut guard = self.state.lock().await;
        guard.last_applied_config = Some(cfg);
        guard.last_compiled_hash = Some(compiled_hash);
        guard.last_allocated_ports = Some(allocated_ports);
        guard.last_effective_tun_mtu = seeded_tun_mtu;
        guard.controller_secret = Some(controller_secret);
        if status.binary_path.is_some() {
            guard.last_binary_path = status.binary_path;
        }
        guard.last_node_count = status.node_count;
        guard.last_rule_count = status.rule_count;
        if !active_selections.is_empty() {
            guard.last_active_selections = active_selections;
        }
    }

    /// Canonical path for the active runtime Mihomo YAML under `paths.runtime_dir`.
    pub fn runtime_yaml_path(&self) -> PathBuf {
        self.paths.runtime_dir.join("runtime.yaml")
    }

    /// Execute the full disk reload pipeline:
    /// read disk -> validate -> compile -> static anti-loop check -> optional `mihomo -t` check ->
    /// safely reject without disturbing active core on any error, or atomically apply & replay selections.
    pub async fn apply_disk_reload(&self, options: DiskReloadOptions) -> ReloadOutcome {
        let _op_guard = self.op_lock.lock().await;

        // 1. Read and validate `config.json` from disk.
        let new_cfg = match load_or_default(&self.paths) {
            Ok(cfg) => cfg,
            Err(err) => {
                return rejected_outcome(
                    ReloadLevel::L2HotReload,
                    format!("failed to read/validate config.json: {err}"),
                );
            }
        };
        if let Err(err) = validate_config(&new_cfg) {
            return rejected_outcome(
                ReloadLevel::L2HotReload,
                format!("config validation rejected reload: {err}"),
            );
        }

        // Mask `tun.enabled` in memory when the current process lacks TUN privilege, preserving
        // the user's persisted intent in `config.json` without ever compiling `tun.enable: true`.
        let mut effective_cfg = new_cfg;
        if !options.allow_tun && effective_cfg.tun.enabled {
            effective_cfg.tun.enabled = false;
        }

        // 2. Load nodes, multi-groups, and domestic relays from override or SQLite.
        let snapshot = match options.snapshot_override.clone() {
            Some(s) => s,
            None => match self.load_snapshot_from_storage() {
                Ok(s) => s,
                Err(err) => {
                    return rejected_outcome(
                        ReloadLevel::L2HotReload,
                        format!("failed to load nodes/groups/relays from SQLite: {err}"),
                    );
                }
            },
        };

        // 3. Determine reload tier against the last applied config and data snapshot.
        let current_snapshot_fp = compute_snapshot_fingerprint(
            &snapshot,
            &options.extra_prepend_rules,
            &options.extra_fake_ip_filters,
            &options.group_filtered_members,
        );

        let (
            prev_cfg,
            prev_hash,
            prev_snapshot_fp,
            prev_ports,
            prev_effective_tun_mtu,
            prev_secret,
            prev_bin,
            prev_node_count,
            prev_rule_count,
            prev_selections,
        ) = {
            let guard = self.state.lock().await;
            (
                guard.last_applied_config.clone(),
                guard.last_compiled_hash.clone(),
                guard.last_snapshot_fingerprint.clone(),
                guard.last_allocated_ports.clone(),
                guard.last_effective_tun_mtu,
                guard.controller_secret.clone(),
                guard.last_binary_path.clone(),
                guard.last_node_count,
                guard.last_rule_count,
                guard.last_active_selections.clone(),
            )
        };

        let mut level = match &prev_cfg {
            Some(old) => classify_config_diff(old, &effective_cfg),
            None => ReloadLevel::L2HotReload,
        };

        let snapshot_unchanged = prev_snapshot_fp.as_deref() == Some(current_snapshot_fp.as_str());
        let requires_global_node_expansion = !effective_cfg.core_runtime.compile_all_nodes
            && snapshot.nodes.len() > 32
            && prev_cfg.as_ref().is_some_and(|old| {
                old.proxy_mode != effective_cfg.proxy_mode
                    && (old.proxy_mode == crate::models::ProxyMode::Global
                        || effective_cfg.proxy_mode == crate::models::ProxyMode::Global)
            });

        // Fast L1 path when only `proxy_mode` changed, snapshot is identical, and not forced.
        if !options.force
            && !requires_global_node_expansion
            && level == ReloadLevel::L1Rest
            && snapshot_unchanged
        {
            if let Some(ref old) = prev_cfg {
                if old.proxy_mode != effective_cfg.proxy_mode
                    && self.adapter.has_live_controller().await
                {
                    match self
                        .adapter
                        .patch_proxy_mode(effective_cfg.proxy_mode.clone())
                        .await
                    {
                        Ok(()) => {
                            let mut guard = self.state.lock().await;
                            guard.last_applied_config = Some(effective_cfg);
                            return ReloadOutcome {
                                applied: true,
                                level: ReloadLevel::L1Rest,
                                skipped_unchanged: false,
                                rejected: false,
                                config_hash: prev_hash,
                                replayed_groups: 0,
                                shifted_ports: Vec::new(),
                                warnings: Vec::new(),
                                error: None,
                                applied_at: Utc::now().to_rfc3339(),
                            };
                        }
                        Err(err) => {
                            return rejected_outcome(
                                ReloadLevel::L1Rest,
                                format!("L1 mode switch failed: {err}"),
                            );
                        }
                    }
                }
            }
        }

        if (options.force || !snapshot_unchanged || requires_global_node_expansion)
            && level == ReloadLevel::L1Rest
        {
            level = ReloadLevel::L2HotReload;
        }

        // Hard L3 gate: when a full core restart is required (e.g., listening ports, TUN toggle/stack,
        // binary path, or memory tier) and `allow_l3_restart` is disabled, reject immediately before
        // running port allocation, rewriting `runtime.yaml`, or falling through into L2 hot reload.
        if level == ReloadLevel::L3CoreRestart && !options.allow_l3_restart {
            return rejected_outcome(
                ReloadLevel::L3CoreRestart,
                "L3 core restart is required for these configuration changes (ports, TUN, binary, or memory tier), but allow_l3_restart is disabled; active core and runtime.yaml were left untouched".to_string(),
            );
        }

        // 4. Resolve controller secret and active ports for compilation.
        let secret = match effective_cfg
            .controller_secret
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(explicit) => explicit.to_string(),
            None => match prev_secret.as_deref() {
                Some(existing) if !existing.is_empty() => existing.to_string(),
                _ => {
                    let from_adapter = self.adapter.controller_secret().await;
                    if from_adapter.is_empty() {
                        generate_controller_secret()
                    } else {
                        from_adapter
                    }
                }
            },
        };

        let current_status = self.adapter.runtime_status().await;
        let mut allocated_ports = if level == ReloadLevel::L3CoreRestart {
            match allocate_l3_ports_respecting_running_core(&effective_cfg, &current_status) {
                Ok(p) => p,
                Err(err) => {
                    return rejected_outcome(
                        ReloadLevel::L3CoreRestart,
                        format!("port_guard rejected L3 port allocation: {err}"),
                    );
                }
            }
        } else {
            prev_ports.clone().unwrap_or_else(|| AllocatedPorts {
                bind_host: if effective_cfg.allow_lan {
                    effective_cfg.bind_address.clone()
                } else {
                    "127.0.0.1".to_string()
                },
                mixed_port: effective_cfg.mixed_port,
                controller_port: effective_cfg.controller_port,
                dns_port: effective_cfg.dns_listen_port,
                shifted: Vec::new(),
            })
        };

        // 5. Compile candidate Mihomo YAML (includes optional YAML Merge Patch override).
        let compile_input = CompileInput {
            config: &effective_cfg,
            nodes: &snapshot.nodes,
            groups: &snapshot.groups,
            relays: &snapshot.relays,
            controller_secret: &secret,
            allocated_ports: &allocated_ports,
            extra_prepend_rules: &options.extra_prepend_rules,
            extra_fake_ip_filters: &options.extra_fake_ip_filters,
            group_filtered_members: &options.group_filtered_members,
        };

        let mut compiled = match compile_mihomo_config_with_runtime_dir(
            &compile_input,
            Some(&self.paths.runtime_dir),
        ) {
            Ok(c) => c,
            Err(err) => {
                return rejected_outcome(level, format!("YAML compilation failed: {err}"));
            }
        };
        if !options.allow_tun {
            if let Err(err) = enforce_tun_disabled_on_compiled(&mut compiled) {
                return rejected_outcome(
                    level,
                    format!("failed to enforce tun.enable=false under !allow_tun: {err}"),
                );
            }
        }

        // 6. Static anti-loop and syntax pre-flight gate: reject before touching active runtime.yaml.
        if !compiled.validation.ok {
            let fallback_hint = super::resolve_default_fallback_group_name(
                &effective_cfg,
                &snapshot.groups,
            );
            let summary = super::format_static_validation_summary_zh(
                &compiled.validation,
                Some(&fallback_hint),
            );
            return rejected_outcome(
                level,
                format!("代理配置静态预检未通过：{summary}"),
            );
        }

        // 6b. When compiled TUN is enabled (including via `inline_override_yaml`) and the compiled
        //     effective TUN MTU crosses (e.g. 1500 <-> 1400 when dialer-proxy wrapping activates or
        //     deactivates), escalate to L3CoreRestart so Wintun / virtual NIC MTU changes cleanly,
        //     strictly honoring `allow_l3_restart`.
        let mut compiled_tun_is_enabled = compiled_tun_enabled(&compiled.value);
        let live_runtime_yaml_path = self.runtime_yaml_path();
        let live_prev_tun_mtu = prev_effective_tun_mtu.or_else(|| {
            if current_status.running || prev_cfg.is_some() {
                read_live_tun_mtu_from_path(&live_runtime_yaml_path).or_else(|| {
                    read_runtime_yaml_tun_enabled(&live_runtime_yaml_path)
                        .then_some(DEFAULT_LIVE_TUN_MTU)
                })
            } else {
                None
            }
        });
        let effective_tun_mtu_changed = compiled_tun_is_enabled
            && live_prev_tun_mtu
                .is_some_and(|prev_mtu| prev_mtu != compiled.stats.effective_tun_mtu);
        if effective_tun_mtu_changed && level != ReloadLevel::L3CoreRestart {
            if !options.allow_l3_restart {
                return rejected_outcome(
                    ReloadLevel::L3CoreRestart,
                    format!(
                        "L3 core restart is required because effective TUN MTU changed ({} -> {}), but allow_l3_restart is disabled; active core and runtime.yaml were left untouched",
                        live_prev_tun_mtu.unwrap_or(DEFAULT_LIVE_TUN_MTU),
                        compiled.stats.effective_tun_mtu
                    ),
                );
            }
            level = ReloadLevel::L3CoreRestart;
            let next_ports = match allocate_l3_ports_respecting_running_core(
                &effective_cfg,
                &current_status,
            ) {
                Ok(p) => p,
                Err(err) => {
                    return rejected_outcome(
                        ReloadLevel::L3CoreRestart,
                        format!(
                            "port_guard rejected L3 port allocation for effective TUN MTU change: {err}"
                        ),
                    );
                }
            };
            let ports_changed = next_ports.bind_host != allocated_ports.bind_host
                || next_ports.mixed_port != allocated_ports.mixed_port
                || next_ports.controller_port != allocated_ports.controller_port
                || next_ports.dns_port != allocated_ports.dns_port;
            allocated_ports = next_ports;
            if ports_changed {
                let recompile_input = CompileInput {
                    config: &effective_cfg,
                    nodes: &snapshot.nodes,
                    groups: &snapshot.groups,
                    relays: &snapshot.relays,
                    controller_secret: &secret,
                    allocated_ports: &allocated_ports,
                    extra_prepend_rules: &options.extra_prepend_rules,
                    extra_fake_ip_filters: &options.extra_fake_ip_filters,
                    group_filtered_members: &options.group_filtered_members,
                };
                compiled = match compile_mihomo_config_with_runtime_dir(
                    &recompile_input,
                    Some(&self.paths.runtime_dir),
                ) {
                    Ok(c) => c,
                    Err(err) => {
                        return rejected_outcome(
                            ReloadLevel::L3CoreRestart,
                            format!(
                                "YAML recompilation failed after L3 MTU port allocation: {err}"
                            ),
                        );
                    }
                };
                if !options.allow_tun {
                    if let Err(err) = enforce_tun_disabled_on_compiled(&mut compiled) {
                        return rejected_outcome(
                            ReloadLevel::L3CoreRestart,
                            format!(
                                "failed to enforce tun.enable=false after L3 MTU recompilation: {err}"
                            ),
                        );
                    }
                }
                if !compiled.validation.ok {
                    let fallback_hint = super::resolve_default_fallback_group_name(
                        &effective_cfg,
                        &snapshot.groups,
                    );
                    let summary = super::format_static_validation_summary_zh(
                        &compiled.validation,
                        Some(&fallback_hint),
                    );
                    return rejected_outcome(
                        ReloadLevel::L3CoreRestart,
                        format!("代理配置静态预检未通过（L3 MTU 重载）：{summary}"),
                    );
                }
                compiled_tun_is_enabled = compiled_tun_enabled(&compiled.value);
            }
        }

        let warnings: Vec<String> = compiled
            .validation
            .warnings()
            .iter()
            .map(|w| format!("[{}] {}", w.code, w.message))
            .collect();

        // 7. SHA-256 content deduplication unless forced or L3 restart is required.
        if !options.force
            && level != ReloadLevel::L3CoreRestart
            && prev_hash.as_deref() == Some(compiled.sha256.as_str())
        {
            let mut guard = self.state.lock().await;
            guard.last_effective_tun_mtu = compiled_tun_is_enabled
                .then_some(compiled.stats.effective_tun_mtu);
            guard.last_applied_config = Some(effective_cfg);
            return ReloadOutcome {
                applied: false,
                level,
                skipped_unchanged: true,
                rejected: false,
                config_hash: Some(compiled.sha256),
                replayed_groups: 0,
                shifted_ports: Vec::new(),
                warnings,
                error: None,
                applied_at: Utc::now().to_rfc3339(),
            };
        }

        // 8. Write staged candidate YAML and run optional `mihomo -t` binary verification.
        let candidate_path = self.paths.runtime_dir.join("runtime-candidate.yaml");
        if let Err(err) = AppPaths::atomic_write(&candidate_path, compiled.yaml.as_bytes()) {
            return rejected_outcome(
                level,
                format!("failed to stage candidate YAML before verification: {err}"),
            );
        }

        let extra_candidates = self.extra_binary_candidates_snapshot();
        let resolved_binary =
            resolve_mihomo_binary(&effective_cfg, &self.paths, &extra_candidates, false)
                .ok()
                .and_then(|r| r.path);

        if options.verify_with_binary {
            if let Some(ref bin_path) = resolved_binary {
                if let Err(err) = verify_config_with_binary(
                    bin_path,
                    &self.paths.runtime_dir,
                    &candidate_path,
                    options.binary_verify_timeout,
                )
                .await
                {
                    let _ = std::fs::remove_file(&candidate_path);
                    return rejected_outcome(level, err.to_string());
                }
            }
        }

        // Pre-validate binary availability before replacing active runtime.yaml on L3 restart.
        if level == ReloadLevel::L3CoreRestart
            && options.allow_l3_restart
            && resolved_binary.is_none()
        {
            let _ = std::fs::remove_file(&candidate_path);
            return rejected_outcome(
                ReloadLevel::L3CoreRestart,
                "L3 restart required, but no Mihomo binary could be resolved".to_string(),
            );
        }

        // 9. Snapshot previous runtime.yaml for rollback, then atomically promote candidate YAML.
        let runtime_yaml = self.runtime_yaml_path();
        let previous_runtime_yaml = std::fs::read(&runtime_yaml).ok();
        if let Err(err) = AppPaths::atomic_write(&runtime_yaml, compiled.yaml.as_bytes()) {
            let _ = std::fs::remove_file(&candidate_path);
            return rejected_outcome(
                level,
                format!("failed to atomically write active runtime.yaml: {err}"),
            );
        }
        let _ = std::fs::remove_file(&candidate_path);

        // 10. Apply via L3 core restart or L2 hot reload with active group selection replay.
        let mut applied_binary_path: Option<PathBuf> = None;
        let replayed_groups = if level == ReloadLevel::L3CoreRestart && options.allow_l3_restart {
            let bin_path = resolved_binary.expect("validated binary path above");
            // Capture previous running core snapshot BEFORE stopping/overwriting state.
            let prev_status = self.adapter.runtime_status().await;
            let prev_adapter_selections = self.adapter.active_selections_snapshot().await;
            let prev_adapter_secret = self.adapter.controller_secret().await;
            let had_previous_core = prev_status.running
                || prev_status.pid.is_some()
                || prev_status.binary_path.is_some()
                || prev_bin.is_some();

            let rollback_request = if had_previous_core && previous_runtime_yaml.is_some() {
                prev_cfg.as_ref().and_then(|old_cfg| {
                    let old_bin = prev_status
                        .binary_path
                        .clone()
                        .or_else(|| prev_bin.clone())
                        .or_else(|| {
                            resolve_mihomo_binary(old_cfg, &self.paths, &extra_candidates, false)
                                .ok()
                                .and_then(|r| r.path)
                        })
                        .filter(|p| p.is_file())?;
                    let old_ports = prev_ports.clone().unwrap_or_else(|| AllocatedPorts {
                        bind_host: prev_status.bind_host.clone(),
                        mixed_port: prev_status.mixed_port,
                        controller_port: prev_status.controller_port,
                        dns_port: prev_status.dns_listen_port,
                        shifted: prev_status.shifted_ports.clone(),
                    });
                    let old_controller_host = if old_cfg.allow_lan {
                        old_cfg.controller_host.clone()
                    } else {
                        "127.0.0.1".to_string()
                    };
                    let old_secret = prev_secret
                        .clone()
                        .filter(|s| !s.is_empty())
                        .unwrap_or(prev_adapter_secret);
                    let old_selections = if !prev_adapter_selections.is_empty() {
                        prev_adapter_selections
                    } else {
                        prev_selections.clone()
                    };
                    let old_node_count = if prev_status.node_count > 0 {
                        prev_status.node_count
                    } else {
                        prev_node_count
                    };
                    let old_rule_count = if prev_status.rule_count > 0 {
                        prev_status.rule_count
                    } else {
                        prev_rule_count
                    };
                    Some(CoreStartRequest {
                        binary_path: old_bin,
                        working_dir: self.paths.runtime_dir.clone(),
                        config_path: runtime_yaml.clone(),
                        config: old_cfg.clone(),
                        allocated_ports: old_ports,
                        controller_host: old_controller_host,
                        controller_secret: old_secret,
                        node_count: old_node_count,
                        rule_count: old_rule_count,
                        active_selections: old_selections,
                    })
                })
            } else {
                None
            };

            let prev_yaml_tun_enabled = previous_runtime_yaml
                .as_deref()
                .and_then(|bytes| serde_yaml_ng::from_slice::<serde_yaml_ng::Value>(bytes).ok())
                .is_some_and(|doc| compiled_tun_enabled(&doc));
            let prev_tun_enabled =
                prev_cfg.as_ref().is_some_and(|c| c.tun.enabled) || prev_yaml_tun_enabled;

            let proxy_host = if effective_cfg.allow_lan {
                effective_cfg.bind_address.as_str()
            } else {
                "127.0.0.1"
            };
            let controller_host = if effective_cfg.allow_lan {
                effective_cfg.controller_host.clone()
            } else {
                "127.0.0.1".to_string()
            };
            let dns_host = if effective_cfg.allow_lan {
                effective_cfg.dns_listen_host.as_str()
            } else {
                "127.0.0.1"
            };

            // Before restarting the core: gracefully tear down TUN if active, then explicitly stop
            // the running core and allow any retained ports to finish releasing before spawning.
            if prev_status.running {
                if prev_tun_enabled {
                    let _ = self.adapter.disable_tun_gracefully().await;
                }
                let _ = self.adapter.stop_process().await;
                if prev_status.pid.is_some() {
                    wait_for_reused_ports_release(
                        proxy_host,
                        &controller_host,
                        dns_host,
                        &allocated_ports,
                        &prev_status,
                    )
                    .await;
                }
            }

            let req = CoreStartRequest {
                binary_path: bin_path.clone(),
                working_dir: self.paths.runtime_dir.clone(),
                config_path: runtime_yaml.clone(),
                config: effective_cfg.clone(),
                allocated_ports: allocated_ports.clone(),
                controller_host,
                controller_secret: secret.clone(),
                node_count: compiled.stats.total_proxies,
                rule_count: compiled.stats.total_rules,
                active_selections: compiled.active_selections.clone(),
            };
            if let Err(err) = self.adapter.start_with_request(req).await {
                let rollback_note = match previous_runtime_yaml {
                    Some(prev_bytes) => match AppPaths::atomic_write(&runtime_yaml, &prev_bytes) {
                        Ok(()) => {
                            if let Some(rb_req) = rollback_request {
                                match self.adapter.start_with_request(rb_req).await {
                                    Ok(_) => "previous runtime.yaml restored and previous core restarted".to_string(),
                                    Err(rb_err) => format!(
                                        "previous runtime.yaml restored, but restarting previous core failed: {rb_err}"
                                    ),
                                }
                            } else {
                                "previous runtime.yaml restored; no previous core instance to restart".to_string()
                            }
                        }
                        Err(io_err) => format!(
                            "failed to restore previous runtime.yaml ({io_err}); previous core not restarted"
                        ),
                    },
                    None => "no previous runtime.yaml snapshot available for rollback".to_string(),
                };
                return rejected_outcome(
                    ReloadLevel::L3CoreRestart,
                    format!("L3 core restart failed: {err} ({rollback_note})"),
                );
            }
            applied_binary_path = Some(bin_path);
            compiled.active_selections.len()
        } else if self.adapter.has_live_controller().await {
            match self
                .adapter
                .reload_config_with_secret(&runtime_yaml, &compiled.active_selections, Some(&secret))
                .await
            {
                Ok(count) => count,
                Err(err) => {
                    if let Some(prev_bytes) = previous_runtime_yaml {
                        let _ = AppPaths::atomic_write(&runtime_yaml, &prev_bytes);
                    }
                    return rejected_outcome(
                        ReloadLevel::L2HotReload,
                        format!("L2 hot reload failed (active core untouched): {err}"),
                    );
                }
            }
        } else {
            0
        };

        let shifted = std::mem::take(&mut allocated_ports.shifted);
        {
            let mut guard = self.state.lock().await;
            guard.last_effective_tun_mtu = compiled_tun_is_enabled
                .then_some(compiled.stats.effective_tun_mtu);
            guard.last_applied_config = Some(effective_cfg);
            guard.last_compiled_hash = Some(compiled.sha256.clone());
            guard.last_snapshot_fingerprint = Some(current_snapshot_fp);
            guard.last_allocated_ports = Some(allocated_ports);
            guard.controller_secret = Some(secret);
            if applied_binary_path.is_some() {
                guard.last_binary_path = applied_binary_path;
            }
            guard.last_node_count = compiled.stats.total_proxies;
            guard.last_rule_count = compiled.stats.total_rules;
            guard.last_active_selections = compiled.active_selections.clone();
        }

        ReloadOutcome {
            applied: true,
            level,
            skipped_unchanged: false,
            rejected: false,
            config_hash: Some(compiled.sha256),
            replayed_groups,
            shifted_ports: shifted,
            warnings,
            error: None,
            applied_at: Utc::now().to_rfc3339(),
        }
    }

    /// Enforce the product guarantee that toggling the main proxy switch off -> on
    /// unconditionally re-reads `config.json` + SQLite from disk and applies the latest state.
    pub async fn force_reload_on_proxy_toggle(
        &self,
        enable_proxy: bool,
        mut options: DiskReloadOptions,
    ) -> ReloadOutcome {
        if !enable_proxy {
            return ReloadOutcome {
                applied: false,
                level: ReloadLevel::L1Rest,
                skipped_unchanged: true,
                rejected: false,
                config_hash: None,
                replayed_groups: 0,
                shifted_ports: Vec::new(),
                warnings: Vec::new(),
                error: None,
                applied_at: Utc::now().to_rfc3339(),
            };
        }

        options.force = true;
        self.apply_disk_reload(options).await
    }

    /// Start a `notify`-backed filesystem watcher monitoring `config.json`, `paths.config_dir`
    /// (override files), and any extra caller-specified paths with 300ms debounce and SHA-256 dedup.
    pub fn start_config_watcher(
        &self,
        extra_watch_paths: Vec<PathBuf>,
        options: DiskReloadOptions,
    ) -> CatResult<ConfigWatcherHandle> {
        let (fs_tx, mut fs_rx) = mpsc::unbounded_channel::<()>();
        let (outcome_tx, _) = broadcast::channel::<ReloadOutcome>(32);

        let config_file_name = self
            .paths
            .config_path
            .file_name()
            .map(|n| n.to_os_string());
        let config_dir = self.paths.config_dir.clone();

        let mut watched_dirs: HashSet<PathBuf> = HashSet::new();
        let mut watched_extra_files: HashSet<PathBuf> = HashSet::new();

        if let Some(parent) = self.paths.config_path.parent() {
            watched_dirs.insert(parent.to_path_buf());
        }
        watched_dirs.insert(config_dir.clone());

        for extra in &extra_watch_paths {
            if extra.is_dir() {
                watched_dirs.insert(extra.clone());
            } else {
                watched_extra_files.insert(extra.clone());
                if let Some(parent) = extra.parent() {
                    if !parent.as_os_str().is_empty() {
                        watched_dirs.insert(parent.to_path_buf());
                    }
                }
            }
        }

        let config_dir_filter = config_dir.clone();
        let extra_files_filter = watched_extra_files.clone();
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
            let Ok(event) = res else {
                return;
            };
            if matches!(event.kind, EventKind::Access(_)) {
                return;
            }
            let relevant = event.paths.iter().any(|p| {
                let is_config_json = config_file_name
                    .as_ref()
                    .is_some_and(|name| p.file_name() == Some(name.as_os_str()));
                let in_override_dir = p.starts_with(&config_dir_filter);
                let in_extra = extra_files_filter.iter().any(|f| p == f);
                is_config_json || in_override_dir || in_extra
            });
            if relevant {
                let _ = fs_tx.send(());
            }
        })
        .map_err(|e| CatError::Core(format!("failed to initialize notify watcher: {e}")))?;

        for dir in &watched_dirs {
            if dir.exists() {
                let mode = if dir == &self.paths.config_dir {
                    RecursiveMode::Recursive
                } else {
                    RecursiveMode::NonRecursive
                };
                watcher.watch(dir, mode).map_err(|e| {
                    CatError::Core(format!("failed to watch `{}`: {e}", dir.display()))
                })?;
            }
        }

        let cancel = StreamCancelToken::new();
        let cancel_clone = cancel.clone();
        let coordinator = self.clone();
        let outcome_tx_clone = outcome_tx.clone();
        let tracked_extra_paths = extra_watch_paths;

        let task = tokio::spawn(async move {
            let mut debouncer = HotReloadDebouncer::new(DEFAULT_DEBOUNCE_WINDOW);
            // Seed initial fingerprint so an immediate no-op touch does not trigger redundant reload.
            if let Ok(initial) =
                compute_watched_disk_fingerprint(&coordinator.paths, &tracked_extra_paths)
            {
                debouncer.force_commit_hash(initial);
            }

            loop {
                if let Some(wait_dur) = debouncer.time_until_ready(Instant::now()) {
                    tokio::select! {
                        _ = cancel_clone.cancelled() => break,
                        maybe_evt = fs_rx.recv() => {
                            match maybe_evt {
                                Some(()) => debouncer.record_event(Instant::now()),
                                None => break,
                            }
                        }
                        _ = tokio::time::sleep(wait_dur) => {
                            let bytes = read_watched_disk_bytes(&coordinator.paths, &tracked_extra_paths);
                            match debouncer.evaluate_and_consume(Instant::now(), &bytes) {
                                DebounceDecision::TriggerReload { .. } => {
                                    let outcome = coordinator.apply_disk_reload(options.clone()).await;
                                    let _ = outcome_tx_clone.send(outcome);
                                }
                                DebounceDecision::SkipDuplicate { .. }
                                | DebounceDecision::Wait(_)
                                | DebounceDecision::NoPendingEvent => {}
                            }
                        }
                    }
                } else {
                    tokio::select! {
                        _ = cancel_clone.cancelled() => break,
                        maybe_evt = fs_rx.recv() => {
                            match maybe_evt {
                                Some(()) => debouncer.record_event(Instant::now()),
                                None => break,
                            }
                        }
                    }
                }
            }
        });

        Ok(ConfigWatcherHandle {
            _watcher: watcher,
            cancel,
            task,
            outcome_tx,
        })
    }

    fn load_snapshot_from_storage(&self) -> CatResult<DiskReloadSnapshot> {
        if !self.paths.db_path.is_file() {
            return Ok(DiskReloadSnapshot::default());
        }
        let storage = Storage::open(&self.paths.db_path)?;
        let nodes = storage.list_nodes()?;
        let groups = storage.list_multi_groups()?;
        let relays = storage.list_preaccel_relays(false)?;
        Ok(DiskReloadSnapshot {
            nodes,
            groups,
            relays,
        })
    }
}

/// Active filesystem watcher handle; stops cleanly when `stop()` is called or on `Drop`.
pub struct ConfigWatcherHandle {
    _watcher: RecommendedWatcher,
    cancel: StreamCancelToken,
    task: JoinHandle<()>,
    outcome_tx: broadcast::Sender<ReloadOutcome>,
}

impl ConfigWatcherHandle {
    pub fn subscribe(&self) -> broadcast::Receiver<ReloadOutcome> {
        self.outcome_tx.subscribe()
    }

    pub fn stop(&self) {
        self.cancel.cancel();
    }
}

impl Drop for ConfigWatcherHandle {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}

const L3_PORT_MAX_SHIFT_PROBES: u16 = 512;
const L3_PORT_WRAP_MIN: u16 = 10240;

fn normalize_l3_bind_host(host: &str) -> &str {
    let trimmed = host.trim();
    if trimmed.is_empty() || trimmed == "*" {
        "0.0.0.0"
    } else {
        trimmed
    }
}

fn next_l3_probe_port(current: u16) -> u16 {
    if current == u16::MAX {
        L3_PORT_WRAP_MIN
    } else {
        current + 1
    }
}

/// Allocate L3 restart ports while preserving any port currently bound by our own running core,
/// preventing `port_guard` false conflicts or upward port drift when restarting Mihomo.
fn allocate_l3_ports_respecting_running_core(
    new_cfg: &AppConfig,
    prev_status: &CoreRuntimeStatus,
) -> CatResult<AllocatedPorts> {
    let proxy_host = if new_cfg.allow_lan {
        new_cfg.bind_address.as_str()
    } else {
        "127.0.0.1"
    };
    let controller_host = if new_cfg.allow_lan {
        new_cfg.controller_host.as_str()
    } else {
        "127.0.0.1"
    };
    let dns_host = if new_cfg.allow_lan {
        new_cfg.dns_listen_host.as_str()
    } else {
        "127.0.0.1"
    };

    if !prev_status.running {
        return allocate_safe_ports_for_hosts(
            proxy_host,
            controller_host,
            dns_host,
            new_cfg.mixed_port,
            new_cfg.controller_port,
            new_cfg.dns_listen_port,
            new_cfg.port_guard_auto_shift,
        );
    }

    let mut owned_by_prev_core: HashSet<u16> = HashSet::with_capacity(3);
    if prev_status.mixed_port > 0 {
        owned_by_prev_core.insert(prev_status.mixed_port);
    }
    if prev_status.controller_port > 0 {
        owned_by_prev_core.insert(prev_status.controller_port);
    }
    if prev_status.dns_listen_port > 0 {
        owned_by_prev_core.insert(prev_status.dns_listen_port);
    }

    let mut reserved = HashSet::with_capacity(3);
    let mut shifted = Vec::new();

    let mixed_port = allocate_single_l3_role(
        "mixed",
        proxy_host,
        new_cfg.mixed_port,
        new_cfg.port_guard_auto_shift,
        &owned_by_prev_core,
        &mut reserved,
        &mut shifted,
    )?;
    let controller_port = allocate_single_l3_role(
        "controller",
        controller_host,
        new_cfg.controller_port,
        new_cfg.port_guard_auto_shift,
        &owned_by_prev_core,
        &mut reserved,
        &mut shifted,
    )?;
    let dns_port = allocate_single_l3_role(
        "dns",
        dns_host,
        new_cfg.dns_listen_port,
        new_cfg.port_guard_auto_shift,
        &owned_by_prev_core,
        &mut reserved,
        &mut shifted,
    )?;

    Ok(AllocatedPorts {
        bind_host: normalize_l3_bind_host(proxy_host).to_string(),
        mixed_port,
        controller_port,
        dns_port,
        shifted,
    })
}

fn allocate_single_l3_role(
    role: &str,
    host: &str,
    desired: u16,
    auto_shift: bool,
    owned_by_prev_core: &HashSet<u16>,
    reserved: &mut HashSet<u16>,
    shifted: &mut Vec<PortShiftNotice>,
) -> CatResult<u16> {
    if desired == 0 {
        return Err(CatError::Core(format!(
            "port_guard: desired {role} port cannot be 0"
        )));
    }

    if !reserved.contains(&desired)
        && (owned_by_prev_core.contains(&desired) || is_port_available_tcp_udp(host, desired))
    {
        reserved.insert(desired);
        return Ok(desired);
    }

    let reason = if reserved.contains(&desired) {
        format!("port {desired} collides with another CatCloud listener role")
    } else {
        format!("port {desired} on `{host}` is already occupied on TCP or UDP")
    };

    if !auto_shift {
        return Err(CatError::Core(format!(
            "port_guard: cannot bind {role} listener ({reason}); auto_shift is disabled"
        )));
    }

    let mut candidate = next_l3_probe_port(desired);
    for _ in 0..L3_PORT_MAX_SHIFT_PROBES {
        if !reserved.contains(&candidate)
            && (owned_by_prev_core.contains(&candidate)
                || is_port_available_tcp_udp(host, candidate))
        {
            reserved.insert(candidate);
            shifted.push(PortShiftNotice {
                role: role.to_string(),
                desired_port: desired,
                actual_port: candidate,
                reason,
            });
            return Ok(candidate);
        }
        candidate = next_l3_probe_port(candidate);
    }

    Err(CatError::Core(format!(
        "port_guard: exhausted {L3_PORT_MAX_SHIFT_PROBES} upward probes for {role} port starting from {desired} on `{host}`"
    )))
}

async fn wait_for_reused_ports_release(
    proxy_host: &str,
    controller_host: &str,
    dns_host: &str,
    ports: &AllocatedPorts,
    prev_status: &CoreRuntimeStatus,
) {
    let prev_ports = [
        prev_status.mixed_port,
        prev_status.controller_port,
        prev_status.dns_listen_port,
    ];
    let mut watched: Vec<(&str, u16)> = Vec::new();
    if prev_ports.contains(&ports.mixed_port) {
        watched.push((proxy_host, ports.mixed_port));
    }
    if prev_ports.contains(&ports.controller_port) {
        watched.push((controller_host, ports.controller_port));
    }
    if prev_ports.contains(&ports.dns_port) {
        watched.push((dns_host, ports.dns_port));
    }
    if watched.is_empty() {
        return;
    }

    let deadline = Instant::now() + Duration::from_millis(500);
    while Instant::now() < deadline {
        if watched
            .iter()
            .all(|(host, port)| is_port_available_tcp_udp(host, *port))
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn rejected_outcome(level: ReloadLevel, error: String) -> ReloadOutcome {
    ReloadOutcome {
        applied: false,
        level,
        skipped_unchanged: false,
        rejected: true,
        config_hash: None,
        replayed_groups: 0,
        shifted_ports: Vec::new(),
        warnings: Vec::new(),
        error: Some(error),
        applied_at: Utc::now().to_rfc3339(),
    }
}

fn read_watched_disk_bytes(paths: &AppPaths, extra_paths: &[PathBuf]) -> Vec<u8> {
    let mut combined = Vec::new();
    append_file_bytes(&mut combined, &paths.config_path);

    if let Ok(entries) = std::fs::read_dir(&paths.config_dir) {
        let mut override_files: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect();
        override_files.sort();
        for file in override_files {
            append_file_bytes(&mut combined, &file);
        }
    }

    for extra in extra_paths {
        if extra.is_file() {
            append_file_bytes(&mut combined, extra);
        }
    }
    combined
}

fn compute_watched_disk_fingerprint(paths: &AppPaths, extra_paths: &[PathBuf]) -> CatResult<String> {
    let bytes = read_watched_disk_bytes(paths, extra_paths);
    Ok(HotReloadDebouncer::compute_fingerprint(&[&bytes]))
}

fn compute_snapshot_fingerprint(
    snapshot: &DiskReloadSnapshot,
    extra_prepend_rules: &[String],
    extra_fake_ip_filters: &[String],
    group_filtered_members: &HashMap<String, Vec<String>>,
) -> String {
    let mut hasher = Sha256::new();
    if let Ok(bytes) = serde_json::to_vec(&snapshot.nodes) {
        hasher.update(bytes);
    }
    if let Ok(bytes) = serde_json::to_vec(&snapshot.groups) {
        hasher.update(bytes);
    }
    if let Ok(bytes) = serde_json::to_vec(&snapshot.relays) {
        hasher.update(bytes);
    }
    if let Ok(bytes) = serde_json::to_vec(extra_prepend_rules) {
        hasher.update(bytes);
    }
    if let Ok(bytes) = serde_json::to_vec(extra_fake_ip_filters) {
        hasher.update(bytes);
    }
    let mut keys: Vec<&String> = group_filtered_members.keys().collect();
    keys.sort();
    for key in keys {
        hasher.update(key.as_bytes());
        if let Some(members) = group_filtered_members.get(key) {
            for m in members {
                hasher.update(m.as_bytes());
                hasher.update([0u8]);
            }
        }
    }
    hex::encode(hasher.finalize())
}

fn append_file_bytes(dst: &mut Vec<u8>, path: &Path) {
    let label = path.to_string_lossy();
    dst.extend_from_slice(label.as_bytes());
    dst.push(0);
    if let Ok(data) = std::fs::read(path) {
        dst.extend_from_slice(&(data.len() as u64).to_le_bytes());
        dst.extend_from_slice(&data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::save;
    use crate::models::{MemoryLimitTier, OverrideMode, ProxyMode, RouteTargetMode, TunStackMode};
    use crate::process_guard::JobGuard;
    use uuid::Uuid;

    fn temp_paths(tag: &str) -> AppPaths {
        let dir = std::env::temp_dir().join(format!(
            "catcloud-hotreload-test-{tag}-{}",
            Uuid::new_v4()
        ));
        AppPaths::from_data_dir(dir, true).expect("create temp paths")
    }

    #[test]
    fn debouncer_enforces_300ms_window_and_sha256_deduplication() {
        let mut debouncer = HotReloadDebouncer::new(DEFAULT_DEBOUNCE_WINDOW);
        let t0 = Instant::now();

        assert_eq!(
            debouncer.evaluate_and_consume(t0, b"v1"),
            DebounceDecision::NoPendingEvent
        );

        debouncer.record_event(t0);
        // 150ms later: still waiting
        let t1 = t0 + Duration::from_millis(150);
        assert!(matches!(
            debouncer.evaluate_and_consume(t1, b"v1"),
            DebounceDecision::Wait(_)
        ));

        // Burst event at t1 resets debounce window
        debouncer.record_event(t1);
        let t2 = t0 + Duration::from_millis(320); // only 170ms since t1
        assert!(matches!(
            debouncer.evaluate_and_consume(t2, b"v1"),
            DebounceDecision::Wait(_)
        ));

        // 300ms after t1 -> triggers first reload
        let t3 = t1 + Duration::from_millis(300);
        let decision = debouncer.evaluate_and_consume(t3, b"v1");
        assert!(matches!(decision, DebounceDecision::TriggerReload { .. }));

        // Another event with identical content -> skipped via SHA-256 dedup
        let t4 = t3 + Duration::from_millis(10);
        debouncer.record_event(t4);
        let t5 = t4 + Duration::from_millis(300);
        assert!(matches!(
            debouncer.evaluate_and_consume(t5, b"v1"),
            DebounceDecision::SkipDuplicate { .. }
        ));

        // Modified content triggers a fresh reload
        let t6 = t5 + Duration::from_millis(10);
        debouncer.record_event(t6);
        let t7 = t6 + Duration::from_millis(300);
        assert!(matches!(
            debouncer.evaluate_and_consume(t7, b"v2"),
            DebounceDecision::TriggerReload { .. }
        ));
    }

    #[test]
    fn classify_config_diff_distinguishes_l1_l2_and_l3_accurately() {
        let base = AppConfig::default();

        // L1: proxy mode or UI personalization only
        let mut l1 = base.clone();
        l1.proxy_mode = ProxyMode::Global;
        l1.personalization.animations_enabled = false;
        assert_eq!(classify_config_diff(&base, &l1), ReloadLevel::L1Rest);

        // L2: DNS / rules / preaccel / core IPv6
        let mut l2_dns = base.clone();
        l2_dns.dns.prefer_h3 = true;
        assert_eq!(classify_config_diff(&base, &l2_dns), ReloadLevel::L2HotReload);

        let mut l2_direct_ns = base.clone();
        l2_direct_ns.dns.direct_nameserver = vec!["114.114.114.114".to_string()];
        assert_eq!(
            classify_config_diff(&base, &l2_direct_ns),
            ReloadLevel::L2HotReload
        );

        let mut l2_rules = base.clone();
        l2_rules
            .rules_override
            .global_prepend_rules
            .push("DOMAIN,example.com,DIRECT".to_string());
        assert_eq!(
            classify_config_diff(&base, &l2_rules),
            ReloadLevel::L2HotReload
        );

        let mut l2_quic = base.clone();
        l2_quic.rules_override.block_quic_udp_443 = !base.rules_override.block_quic_udp_443;
        assert_eq!(
            classify_config_diff(&base, &l2_quic),
            ReloadLevel::L2HotReload
        );

        let mut l2_domestic = base.clone();
        l2_domestic.rules_override.domestic_direct_enabled =
            !base.rules_override.domestic_direct_enabled;
        assert_eq!(
            classify_config_diff(&base, &l2_domestic),
            ReloadLevel::L2HotReload
        );

        let mut l2_preaccel = base.clone();
        l2_preaccel.preaccel.enabled = true;
        assert_eq!(
            classify_config_diff(&base, &l2_preaccel),
            ReloadLevel::L2HotReload
        );

        let mut l2_active_group = base.clone();
        l2_active_group.active_group_id = Some("grp-ai".to_string());
        assert_eq!(
            classify_config_diff(&base, &l2_active_group),
            ReloadLevel::L2HotReload
        );
        assert!(has_core_config_changes(&base, &l2_active_group));

        let mut l2_route_mode = base.clone();
        l2_route_mode.route_mode = RouteTargetMode::Single;
        assert_eq!(
            classify_config_diff(&base, &l2_route_mode),
            ReloadLevel::L2HotReload
        );
        assert!(has_core_config_changes(&base, &l2_route_mode));

        let mut l2_single_node = base.clone();
        l2_single_node.active_single_node_id = Some("node-jp-1".to_string());
        assert_eq!(
            classify_config_diff(&base, &l2_single_node),
            ReloadLevel::L2HotReload
        );
        assert!(has_core_config_changes(&base, &l2_single_node));

        let mut l2_compile_all = base.clone();
        l2_compile_all.core_runtime.compile_all_nodes = true;
        assert_eq!(
            classify_config_diff(&base, &l2_compile_all),
            ReloadLevel::L2HotReload
        );
        assert!(has_core_config_changes(&base, &l2_compile_all));

        // L3: ports / TUN stack / binary path / memory tier
        let mut l3_port = base.clone();
        l3_port.mixed_port = 27890;
        assert_eq!(
            classify_config_diff(&base, &l3_port),
            ReloadLevel::L3CoreRestart
        );

        // Editing TUN stack/MTU while TUN is disabled must NOT trigger an unnecessary L3 restart.
        let mut l1_tun_inactive = base.clone();
        l1_tun_inactive.tun.stack_mode = TunStackMode::Gvisor;
        l1_tun_inactive.tun.mtu = 1400;
        assert_eq!(
            classify_config_diff(&base, &l1_tun_inactive),
            ReloadLevel::L1Rest
        );

        // Enabling TUN or changing TUN stack/MTU while TUN is enabled MUST trigger L3 restart.
        let mut l3_tun_on = base.clone();
        l3_tun_on.tun.enabled = true;
        assert_eq!(
            classify_config_diff(&base, &l3_tun_on),
            ReloadLevel::L3CoreRestart
        );
        let mut l3_tun_stack = l3_tun_on.clone();
        l3_tun_stack.tun.stack_mode = TunStackMode::Gvisor;
        assert_eq!(
            classify_config_diff(&l3_tun_on, &l3_tun_stack),
            ReloadLevel::L3CoreRestart
        );

        let mut l3_bin = base.clone();
        l3_bin.core_runtime.custom_binary_path = Some("C:/opt/mihomo.exe".to_string());
        assert_eq!(
            classify_config_diff(&base, &l3_bin),
            ReloadLevel::L3CoreRestart
        );

        let mut l3_mem = base.clone();
        l3_mem.core_runtime.memory_tier = MemoryLimitTier::Mb96;
        assert_eq!(
            classify_config_diff(&base, &l3_mem),
            ReloadLevel::L3CoreRestart
        );

        let mut l3_gogc = base.clone();
        l3_gogc.core_runtime.gogc = 35;
        assert_eq!(
            classify_config_diff(&base, &l3_gogc),
            ReloadLevel::L3CoreRestart
        );

        let mut l2_skip443 = base.clone();
        l2_skip443.preaccel.skip_443_native = !base.preaccel.skip_443_native;
        assert_eq!(
            classify_config_diff(&base, &l2_skip443),
            ReloadLevel::L2HotReload
        );

        let mut l1_lang = base.clone();
        l1_lang.personalization.language = "en".to_string();
        assert_eq!(classify_config_diff(&base, &l1_lang), ReloadLevel::L1Rest);
        assert!(!has_core_config_changes(&base, &l1_lang));
    }

    #[tokio::test]
    async fn disk_reload_safely_rejects_broken_override_without_clobbering_active_yaml() {
        let paths = temp_paths("reject-broken");
        let guard = Arc::new(JobGuard::new().unwrap());
        let adapter = Arc::new(MihomoAdapter::new(guard).unwrap());
        let coordinator = HotReloadCoordinator::new(paths.clone(), adapter);

        // 1. Apply an initial valid configuration.
        let good_cfg = AppConfig::default();
        save(&paths, &good_cfg).unwrap();
        let initial_outcome = coordinator
            .apply_disk_reload(DiskReloadOptions {
                verify_with_binary: false,
                ..Default::default()
            })
            .await;
        assert!(initial_outcome.applied, "initial error: {:?}", initial_outcome.error);
        let original_yaml = std::fs::read_to_string(coordinator.runtime_yaml_path()).unwrap();

        // 2. Inject a malformed YAML merge patch and re-trigger reload -> must safely reject.
        let bad_patch_path = paths.config_dir.join("broken_patch.yaml");
        std::fs::write(&bad_patch_path, "dns: [unclosed_yaml").unwrap();
        let mut broken_cfg = good_cfg.clone();
        broken_cfg.rules_override.override_mode = OverrideMode::MergePatch;
        broken_cfg.rules_override.override_merge_path =
            Some(bad_patch_path.to_string_lossy().to_string());
        save(&paths, &broken_cfg).unwrap();

        let rejected = coordinator
            .apply_disk_reload(DiskReloadOptions {
                verify_with_binary: false,
                ..Default::default()
            })
            .await;
        assert!(rejected.rejected);
        assert!(!rejected.applied);
        assert!(rejected.error.is_some());

        // Active runtime.yaml must remain completely untouched.
        let still_original = std::fs::read_to_string(coordinator.runtime_yaml_path()).unwrap();
        assert_eq!(still_original, original_yaml);

        // 3. Proxy toggle off -> on forces reload when config is fixed again.
        save(&paths, &good_cfg).unwrap();
        let toggle_off = coordinator
            .force_reload_on_proxy_toggle(
                false,
                DiskReloadOptions {
                    verify_with_binary: false,
                    ..Default::default()
                },
            )
            .await;
        assert!(toggle_off.skipped_unchanged);

        let toggle_on = coordinator
            .force_reload_on_proxy_toggle(
                true,
                DiskReloadOptions {
                    verify_with_binary: false,
                    ..Default::default()
                },
            )
            .await;
        assert!(toggle_on.applied);
        assert!(!toggle_on.skipped_unchanged);

        let _ = std::fs::remove_dir_all(&paths.root_data_dir);
    }

    #[tokio::test]
    async fn l2_secret_rotation_updates_adapter_secret_without_401_desync() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let old_secret = "old_secret_token_0123456789abcdef".to_string();
        let new_secret = "new_secret_token_fedcba9876543210".to_string();
        let old_auth = format!("Bearer {old_secret}");
        let new_auth = format!("Bearer {new_secret}");

        let server = tokio::spawn(async move {
            let mut active_auth = old_auth;
            for _ in 0..4 {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let mut raw_bytes = Vec::with_capacity(1024);
                let mut chunk = [0u8; 1024];
                loop {
                    let n = socket.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    raw_bytes.extend_from_slice(&chunk[..n]);
                    if raw_bytes.windows(4).any(|w| w == b"\r\n\r\n") || raw_bytes.len() >= 8192 {
                        break;
                    }
                }
                if raw_bytes.is_empty() {
                    continue;
                }
                let raw = String::from_utf8_lossy(&raw_bytes).to_string();
                let first_line = raw.lines().next().unwrap_or_default().to_string();
                let (status_line, body) = if !raw.contains(&active_auth) {
                    ("HTTP/1.1 401 Unauthorized", r#"{"message":"unauthorized"}"#)
                } else if first_line.starts_with("PUT /configs?force=true") {
                    // Simulate Mihomo rotating its controller secret immediately after reload.
                    active_auth = new_auth.clone();
                    ("HTTP/1.1 204 No Content", "")
                } else if first_line.starts_with("PUT /proxies/") {
                    ("HTTP/1.1 204 No Content", "")
                } else if first_line.starts_with("GET /version") {
                    ("HTTP/1.1 200 OK", r#"{"version":"v1.19.0"}"#)
                } else {
                    ("HTTP/1.1 404 Not Found", "")
                };
                let response = format!(
                    "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let paths = temp_paths("l2-secret-rotation");
        let guard = Arc::new(JobGuard::new().unwrap());
        let adapter = Arc::new(
            MihomoAdapter::with_controller_endpoint(guard, "127.0.0.1", port, old_secret.clone())
                .unwrap(),
        );
        let coordinator = HotReloadCoordinator::new(paths.clone(), Arc::clone(&adapter));

        let mut initial_cfg = AppConfig::default();
        initial_cfg.controller_port = port;
        initial_cfg.controller_secret = Some(old_secret.clone());
        let ports = AllocatedPorts {
            bind_host: "127.0.0.1".to_string(),
            mixed_port: initial_cfg.mixed_port,
            controller_port: port,
            dns_port: initial_cfg.dns_listen_port,
            shifted: Vec::new(),
        };
        coordinator
            .seed_active_state(initial_cfg.clone(), "initial-hash".into(), ports, old_secret)
            .await;

        let mut rotated_cfg = initial_cfg;
        rotated_cfg.controller_secret = Some(new_secret.clone());
        save(&paths, &rotated_cfg).unwrap();

        let outcome = coordinator
            .apply_disk_reload(DiskReloadOptions {
                verify_with_binary: false,
                ..Default::default()
            })
            .await;
        assert!(outcome.applied, "unexpected reload error: {:?}", outcome.error);
        assert_eq!(outcome.level, ReloadLevel::L2HotReload);
        assert_eq!(adapter.controller_secret().await, new_secret);
        assert_eq!(adapter.fetch_version().await.unwrap(), "v1.19.0");

        server.abort();
        let _ = std::fs::remove_dir_all(&paths.root_data_dir);
    }

    #[tokio::test]
    async fn disk_reload_passes_runtime_dir_for_geodata_file_detection() {
        let paths = temp_paths("runtime-geodata");
        let guard = Arc::new(JobGuard::new().unwrap());
        let adapter = Arc::new(MihomoAdapter::new(guard).unwrap());
        let coordinator = HotReloadCoordinator::new(paths.clone(), adapter);

        let cfg = AppConfig::default();
        save(&paths, &cfg).unwrap();

        // Without geosite.dat / Country.mmdb in runtime_dir -> safe fallback rules, no GEOSITE/GEOIP
        let outcome_no_geo = coordinator
            .apply_disk_reload(DiskReloadOptions {
                verify_with_binary: false,
                ..Default::default()
            })
            .await;
        assert!(outcome_no_geo.applied, "err: {:?}", outcome_no_geo.error);
        let yaml_no_geo = std::fs::read_to_string(coordinator.runtime_yaml_path()).unwrap();
        assert!(!yaml_no_geo.contains("GEOSITE,cn,DIRECT"));
        assert!(!yaml_no_geo.contains("GEOIP,CN,DIRECT,no-resolve"));

        // Place geosite.dat and Country.mmdb in runtime_dir and force reload -> GEOSITE/GEOIP enabled
        std::fs::write(paths.runtime_dir.join("geosite.dat"), b"stub").unwrap();
        std::fs::write(paths.runtime_dir.join("Country.mmdb"), b"stub").unwrap();
        let outcome_with_geo = coordinator
            .apply_disk_reload(DiskReloadOptions {
                force: true,
                verify_with_binary: false,
                ..Default::default()
            })
            .await;
        assert!(outcome_with_geo.applied, "err: {:?}", outcome_with_geo.error);
        let yaml_with_geo = std::fs::read_to_string(coordinator.runtime_yaml_path()).unwrap();
        assert!(yaml_with_geo.contains("GEOSITE,private,DIRECT"));
        assert!(yaml_with_geo.contains("GEOSITE,cn,DIRECT"));
        assert!(yaml_with_geo.contains("GEOIP,CN,DIRECT,no-resolve"));

        let _ = std::fs::remove_dir_all(&paths.root_data_dir);
    }

    #[test]
    fn l3_port_allocation_retains_running_core_ports_without_self_conflict_or_drift() {
        use std::net::{TcpListener, UdpSocket};

        fn hold_tcp_udp_port() -> (u16, TcpListener, UdpSocket) {
            for _ in 0..64 {
                let tcp = TcpListener::bind("127.0.0.1:0").expect("bind tcp");
                let port = tcp.local_addr().unwrap().port();
                if let Ok(udp) = UdpSocket::bind(format!("127.0.0.1:{port}")) {
                    return (port, tcp, udp);
                }
            }
            panic!("failed to reserve ephemeral test port pair");
        }

        let (p_mixed, _t1, _u1) = hold_tcp_udp_port();
        let (p_ctrl, _t2, _u2) = hold_tcp_udp_port();
        let (p_dns, _t3, _u3) = hold_tcp_udp_port();
        let (p_external, _t4, _u4) = hold_tcp_udp_port();

        let prev_status = CoreRuntimeStatus {
            running: true,
            mixed_port: p_mixed,
            controller_port: p_ctrl,
            dns_listen_port: p_dns,
            ..Default::default()
        };

        // Even with auto_shift=false, ports owned by the running core must be retained verbatim.
        let mut cfg_no_shift = AppConfig::default();
        cfg_no_shift.mixed_port = p_mixed;
        cfg_no_shift.controller_port = p_ctrl;
        cfg_no_shift.dns_listen_port = p_dns;
        cfg_no_shift.port_guard_auto_shift = false;

        let kept = allocate_l3_ports_respecting_running_core(&cfg_no_shift, &prev_status)
            .expect("running core's own ports must not self-conflict");
        assert_eq!(kept.mixed_port, p_mixed);
        assert_eq!(kept.controller_port, p_ctrl);
        assert_eq!(kept.dns_port, p_dns);
        assert!(kept.shifted.is_empty());

        // With auto_shift=true, ports owned by the running core must also stay pinned without drift.
        let mut cfg_auto_shift = cfg_no_shift.clone();
        cfg_auto_shift.port_guard_auto_shift = true;
        let pinned = allocate_l3_ports_respecting_running_core(&cfg_auto_shift, &prev_status)
            .expect("running core's own ports must not drift");
        assert_eq!(pinned.mixed_port, p_mixed);
        assert_eq!(pinned.controller_port, p_ctrl);
        assert_eq!(pinned.dns_port, p_dns);
        assert!(pinned.shifted.is_empty());

        // Switching mixed_port to an externally occupied port still triggers conflict / shift,
        // while keeping unchanged controller & DNS ports pinned.
        let mut cfg_ext_conflict = cfg_no_shift.clone();
        cfg_ext_conflict.mixed_port = p_external;
        assert!(
            allocate_l3_ports_respecting_running_core(&cfg_ext_conflict, &prev_status).is_err(),
            "external occupancy must still fail when auto_shift is disabled"
        );
        cfg_ext_conflict.port_guard_auto_shift = true;
        let shifted = allocate_l3_ports_respecting_running_core(&cfg_ext_conflict, &prev_status)
            .expect("auto_shift must shift only the externally conflicted port");
        assert_ne!(shifted.mixed_port, p_external);
        assert_eq!(shifted.controller_port, p_ctrl);
        assert_eq!(shifted.dns_port, p_dns);
        assert_eq!(shifted.shifted.len(), 1);
        assert_eq!(shifted.shifted[0].role, "mixed");

        // When previous core is NOT running, occupied ports must never be bypassed.
        let stopped_status = CoreRuntimeStatus {
            running: false,
            ..prev_status
        };
        assert!(
            allocate_l3_ports_respecting_running_core(&cfg_no_shift, &stopped_status).is_err(),
            "stopped core must not suppress port occupancy checks"
        );
    }

    #[tokio::test]
    async fn extra_binary_candidates_are_stored_and_tun_disabled_gracefully_before_l3_restart() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ctrl_port = listener.local_addr().unwrap().port();
        let secret = "tun_graceful_secret_0123456789abcdef".to_string();
        let tun_patch_received = Arc::new(AtomicBool::new(false));
        let tun_flag = Arc::clone(&tun_patch_received);

        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = vec![0u8; 4096];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let raw = String::from_utf8_lossy(&buf[..n]).to_string();
                if raw.starts_with("PATCH /configs")
                    && raw.contains("\"tun\"")
                    && raw.contains("\"enable\":false")
                {
                    tun_flag.store(true, Ordering::SeqCst);
                }
                let resp = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = socket.write_all(resp.as_bytes()).await;
            }
        });

        let paths = temp_paths("l3-extra-candidates-tun");
        let extra_bin_dir = paths.root_data_dir.join("bundled-extra");
        std::fs::create_dir_all(&extra_bin_dir).unwrap();
        let fake_bin = extra_bin_dir.join(crate::core_adapter::mihomo_binary_name());
        std::fs::write(&fake_bin, b"not-a-real-binary").unwrap();

        let guard = Arc::new(JobGuard::new().unwrap());
        let adapter = Arc::new(
            MihomoAdapter::with_controller_endpoint(guard, "127.0.0.1", ctrl_port, secret.clone())
                .unwrap(),
        );
        let coordinator = HotReloadCoordinator::new(paths.clone(), adapter);
        coordinator.set_extra_binary_candidates(vec![fake_bin.clone()]);
        assert_eq!(coordinator.extra_binary_candidates_snapshot(), vec![fake_bin]);

        let mut old_cfg = AppConfig::default();
        old_cfg.controller_port = ctrl_port;
        old_cfg.controller_secret = Some(secret.clone());
        old_cfg.tun.enabled = true;
        old_cfg.port_guard_auto_shift = false;

        let ports = AllocatedPorts {
            bind_host: "127.0.0.1".to_string(),
            mixed_port: old_cfg.mixed_port,
            controller_port: ctrl_port,
            dns_port: old_cfg.dns_listen_port,
            shifted: Vec::new(),
        };
        coordinator
            .seed_active_state(old_cfg.clone(), "prev-hash".into(), ports, secret)
            .await;

        let mut next_cfg = old_cfg;
        next_cfg.tun.stack_mode = TunStackMode::Gvisor;
        save(&paths, &next_cfg).unwrap();

        // Trigger L3 restart: controller_port is held by our mock server (matching prev_status),
        // candidate binary comes from `extra_binary_candidates`, and TUN must be patched off first.
        let outcome = coordinator
            .apply_disk_reload(DiskReloadOptions {
                verify_with_binary: false,
                ..Default::default()
            })
            .await;
        assert!(outcome.rejected, "fake binary spawn should reject & rollback");
        assert_eq!(outcome.level, ReloadLevel::L3CoreRestart);
        assert!(
            !outcome
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("no Mihomo binary could be resolved"),
            "extra_binary_candidates must resolve the fake binary: {:?}",
            outcome.error
        );
        assert!(
            tun_patch_received.load(Ordering::SeqCst),
            "disable_tun_gracefully must be invoked before L3 restart when old core had TUN enabled"
        );

        server.abort();
        let _ = std::fs::remove_dir_all(&paths.root_data_dir);
    }

    #[tokio::test]
    async fn independent_routing_toggle_triggers_l2_hot_reload_and_updates_rules() {
        let paths = temp_paths("independent-routing-l2");
        let guard = Arc::new(JobGuard::new().unwrap());
        let adapter = Arc::new(MihomoAdapter::new(guard).unwrap());
        let coordinator = HotReloadCoordinator::new(paths.clone(), adapter);

        let mut cfg = AppConfig::default();
        cfg.active_group_id = Some("grp-main".to_string());
        save(&paths, &cfg).unwrap();

        let node = ProxyNode {
            id: "n-jp".to_string(),
            sub_id: "sub-1".to_string(),
            name: "Node-JP-01".to_string(),
            protocol: "trojan".to_string(),
            server: "203.0.113.50".to_string(),
            port: 443,
            raw_config: serde_json::json!({
                "name": "Node-JP-01",
                "type": "trojan",
                "server": "203.0.113.50",
                "port": 443,
                "password": "demo"
            }),
            region_code: "JP".to_string(),
            multiplier: 1.0,
            is_443_native: true,
            ..Default::default()
        };

        let active_group = MultiGroup {
            id: "grp-main".to_string(),
            name: "Main-Group".to_string(),
            member_node_ids: vec!["n-jp".to_string()],
            ..Default::default()
        };
        let mut ai_group = MultiGroup {
            id: "grp-ai".to_string(),
            name: "AI-Dedicated".to_string(),
            match_rules: vec!["DOMAIN-SUFFIX,openai.com".to_string()],
            member_node_ids: vec!["n-jp".to_string()],
            independent_routing: false,
            ..Default::default()
        };

        // 1. Initial apply with independent_routing = false -> AI rules excluded.
        let out1 = coordinator
            .apply_disk_reload(DiskReloadOptions {
                verify_with_binary: false,
                snapshot_override: Some(DiskReloadSnapshot {
                    nodes: vec![node.clone()],
                    groups: vec![active_group.clone(), ai_group.clone()],
                    relays: Vec::new(),
                }),
                ..Default::default()
            })
            .await;
        assert!(out1.applied, "initial error: {:?}", out1.error);
        let yaml1 = std::fs::read_to_string(coordinator.runtime_yaml_path()).unwrap();
        assert!(!yaml1.contains("DOMAIN-SUFFIX,openai.com,AI-Dedicated"));

        // 2. Toggle independent_routing = true without changing config.json -> must trigger L2 reload.
        ai_group.independent_routing = true;
        let out2 = coordinator
            .apply_disk_reload(DiskReloadOptions {
                verify_with_binary: false,
                snapshot_override: Some(DiskReloadSnapshot {
                    nodes: vec![node.clone()],
                    groups: vec![active_group.clone(), ai_group.clone()],
                    relays: Vec::new(),
                }),
                ..Default::default()
            })
            .await;
        assert!(out2.applied, "toggle-on error: {:?}", out2.error);
        assert!(!out2.skipped_unchanged);
        assert_eq!(out2.level, ReloadLevel::L2HotReload);
        let yaml2 = std::fs::read_to_string(coordinator.runtime_yaml_path()).unwrap();
        assert!(yaml2.contains("DOMAIN-SUFFIX,openai.com,AI-Dedicated"));

        // 3. Toggle independent_routing = false -> must trigger L2 reload again and strip rule.
        ai_group.independent_routing = false;
        let out3 = coordinator
            .apply_disk_reload(DiskReloadOptions {
                verify_with_binary: false,
                snapshot_override: Some(DiskReloadSnapshot {
                    nodes: vec![node],
                    groups: vec![active_group, ai_group],
                    relays: Vec::new(),
                }),
                ..Default::default()
            })
            .await;
        assert!(out3.applied, "toggle-off error: {:?}", out3.error);
        assert!(!out3.skipped_unchanged);
        assert_eq!(out3.level, ReloadLevel::L2HotReload);
        let yaml3 = std::fs::read_to_string(coordinator.runtime_yaml_path()).unwrap();
        assert!(!yaml3.contains("DOMAIN-SUFFIX,openai.com,AI-Dedicated"));

        let _ = std::fs::remove_dir_all(&paths.root_data_dir);
    }

    #[tokio::test]
    async fn disk_reload_masks_tun_when_not_allowed_without_mutating_disk_or_triggering_l3() {
        let paths = temp_paths("allow-tun-gate");
        let guard = Arc::new(JobGuard::new().unwrap());
        let adapter = Arc::new(MihomoAdapter::new(guard).unwrap());
        let coordinator = HotReloadCoordinator::new(paths.clone(), adapter);

        // 1. Persist `tun.enabled = true` on disk, then reload with `allow_tun = false`.
        let mut disk_cfg = AppConfig::default();
        disk_cfg.tun.enabled = true;
        disk_cfg.tun.mtu = 1450;
        save(&paths, &disk_cfg).unwrap();

        let out1 = coordinator
            .apply_disk_reload(DiskReloadOptions {
                verify_with_binary: false,
                allow_tun: false,
                ..Default::default()
            })
            .await;
        assert!(out1.applied, "initial masked reload failed: {:?}", out1.error);
        assert_eq!(out1.level, ReloadLevel::L2HotReload);

        let yaml1: serde_yaml_ng::Value = serde_yaml_ng::from_str(
            &std::fs::read_to_string(coordinator.runtime_yaml_path()).unwrap(),
        )
        .expect("parse runtime.yaml");
        assert_eq!(yaml1["tun"]["enable"].as_bool(), Some(false));

        // On-disk `config.json` must remain untouched with user intent `tun.enabled == true`.
        let persisted = load_or_default(&paths).expect("re-read disk config.json");
        assert!(persisted.tun.enabled);

        // 2. Second reload with unchanged config -> cleanly deduplicated without L3 jitter.
        let out2 = coordinator
            .apply_disk_reload(DiskReloadOptions {
                verify_with_binary: false,
                allow_tun: false,
                ..Default::default()
            })
            .await;
        assert!(!out2.applied);
        assert!(out2.skipped_unchanged);
        assert_ne!(out2.level, ReloadLevel::L3CoreRestart);

        // 3. Changing TUN stack/MTU on disk while `allow_tun = false` must NOT trigger L3 restart.
        disk_cfg.tun.stack_mode = TunStackMode::Gvisor;
        disk_cfg.tun.mtu = 1400;
        save(&paths, &disk_cfg).unwrap();
        let out3 = coordinator
            .apply_disk_reload(DiskReloadOptions {
                verify_with_binary: false,
                allow_tun: false,
                ..Default::default()
            })
            .await;
        assert!(!out3.rejected, "unexpected rejection: {:?}", out3.error);
        assert_ne!(out3.level, ReloadLevel::L3CoreRestart);

        // 4. Subsequent L2 change keeps `tun.enable: false` in runtime.yaml without L3 restart.
        disk_cfg.log_level = crate::models::CoreLogLevel::Warning;
        save(&paths, &disk_cfg).unwrap();
        let out4 = coordinator
            .apply_disk_reload(DiskReloadOptions {
                verify_with_binary: false,
                allow_tun: false,
                ..Default::default()
            })
            .await;
        assert!(out4.applied, "l2 reload under masked tun failed: {:?}", out4.error);
        assert_eq!(out4.level, ReloadLevel::L2HotReload);
        let yaml4: serde_yaml_ng::Value = serde_yaml_ng::from_str(
            &std::fs::read_to_string(coordinator.runtime_yaml_path()).unwrap(),
        )
        .expect("parse runtime.yaml after l2");
        assert_eq!(yaml4["tun"]["enable"].as_bool(), Some(false));
        assert!(load_or_default(&paths).unwrap().tun.enabled);

        let _ = std::fs::remove_dir_all(&paths.root_data_dir);
    }

    #[tokio::test]
    async fn l3_hard_gate_rejects_without_port_shift_yaml_overwrite_or_l2_fallback() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ctrl_port = listener.local_addr().unwrap().port();
        let secret = "l3_hard_gate_secret_0123456789abcdef".to_string();
        let http_hits = Arc::new(AtomicUsize::new(0));
        let hits_bg = Arc::clone(&http_hits);

        let server = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                hits_bg.fetch_add(1, Ordering::SeqCst);
                let resp =
                    "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = socket.write_all(resp.as_bytes()).await;
            }
        });

        let paths = temp_paths("l3-hard-gate");
        let guard = Arc::new(JobGuard::new().unwrap());
        let adapter = Arc::new(
            MihomoAdapter::with_controller_endpoint(guard, "127.0.0.1", ctrl_port, secret.clone())
                .unwrap(),
        );
        let coordinator = HotReloadCoordinator::new(paths.clone(), adapter);

        let mut old_cfg = AppConfig::default();
        old_cfg.controller_port = ctrl_port;
        old_cfg.controller_secret = Some(secret.clone());
        old_cfg.tun.enabled = false;
        let ports = AllocatedPorts {
            bind_host: "127.0.0.1".to_string(),
            mixed_port: old_cfg.mixed_port,
            controller_port: ctrl_port,
            dns_port: old_cfg.dns_listen_port,
            shifted: Vec::new(),
        };
        coordinator
            .seed_active_state(old_cfg.clone(), "seed-hash".into(), ports, secret)
            .await;

        let sentinel_yaml = "# SENTINEL_ACTIVE_RUNTIME_YAML\nmixed-port: 7890\n";
        std::fs::write(coordinator.runtime_yaml_path(), sentinel_yaml).unwrap();

        // Persist an L3-requiring change (port + TUN toggle) on disk.
        let mut next_cfg = old_cfg;
        next_cfg.mixed_port = 27890;
        next_cfg.tun.enabled = true;
        save(&paths, &next_cfg).unwrap();

        let outcome = coordinator
            .apply_disk_reload(DiskReloadOptions {
                allow_l3_restart: false,
                verify_with_binary: false,
                ..Default::default()
            })
            .await;

        assert!(outcome.rejected, "L3 reload must be rejected when allow_l3_restart=false");
        assert!(!outcome.applied, "L3 reload must never fall through into L2 apply");
        assert_eq!(outcome.level, ReloadLevel::L3CoreRestart);
        assert!(outcome.shifted_ports.is_empty());
        assert!(outcome.error.as_deref().unwrap_or_default().contains("allow_l3_restart"));
        assert_eq!(
            std::fs::read_to_string(coordinator.runtime_yaml_path()).unwrap(),
            sentinel_yaml,
            "active runtime.yaml must remain completely untouched"
        );
        assert_eq!(
            http_hits.load(Ordering::SeqCst),
            0,
            "must never send PUT /configs?force=true to the active core"
        );

        server.abort();
        let _ = std::fs::remove_dir_all(&paths.root_data_dir);
    }

    #[tokio::test]
    async fn effective_tun_mtu_transition_escalates_to_l3_and_respects_allow_l3_gate() {
        let paths = temp_paths("tun-mtu-l3-escalation");
        let guard = Arc::new(JobGuard::new().unwrap());
        let adapter = Arc::new(MihomoAdapter::new(guard).unwrap());
        let coordinator = HotReloadCoordinator::new(paths.clone(), adapter);

        let relay = PreAccelRelay {
            id: "relay-mtu-test".to_string(),
            name: "Relay-MTU-443".to_string(),
            provider: "cloud-a".to_string(),
            region: "CN-East".to_string(),
            server: "203.0.113.10".to_string(),
            port: 443,
            protocol: "anytls".to_string(),
            password: "demo-mtu-password".to_string(),
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
        };
        let mut non443_node = ProxyNode {
            id: "n-mtu-8443".to_string(),
            sub_id: "sub-mtu".to_string(),
            name: "Node-8443".to_string(),
            protocol: "ss".to_string(),
            server: "198.51.100.30".to_string(),
            port: 8443,
            is_443_native: false,
            preaccel_eligible: true,
            preaccel_override: None,
            enabled: true,
            raw_config: serde_json::json!({
                "name": "Node-8443",
                "type": "ss",
                "server": "198.51.100.30",
                "port": 8443,
                "cipher": "aes-128-gcm",
                "password": "demo-ss-password"
            }),
            ..Default::default()
        };
        let native443_node = ProxyNode {
            id: "n-mtu-443".to_string(),
            sub_id: "sub-mtu".to_string(),
            name: "Node-443-Native".to_string(),
            protocol: "trojan".to_string(),
            server: "198.51.100.44".to_string(),
            port: 443,
            is_443_native: true,
            preaccel_eligible: true,
            preaccel_override: None,
            enabled: true,
            raw_config: serde_json::json!({
                "name": "Node-443-Native",
                "type": "trojan",
                "server": "198.51.100.44",
                "port": 443,
                "password": "demo-trojan-password"
            }),
            ..Default::default()
        };

        // 1. Baseline: TUN enabled (MTU 1500), preaccel disabled -> effective MTU = 1500.
        let mut cfg = AppConfig::default();
        cfg.tun.enabled = true;
        cfg.tun.mtu = 1500;
        cfg.preaccel.enabled = false;
        save(&paths, &cfg).unwrap();

        let snapshot_with_non443 = DiskReloadSnapshot {
            nodes: vec![non443_node.clone()],
            groups: Vec::new(),
            relays: vec![relay.clone()],
        };
        let out1 = coordinator
            .apply_disk_reload(DiskReloadOptions {
                verify_with_binary: false,
                allow_l3_restart: false,
                allow_tun: true,
                snapshot_override: Some(snapshot_with_non443.clone()),
                ..Default::default()
            })
            .await;
        assert!(out1.applied, "initial baseline reload failed: {:?}", out1.error);
        assert_eq!(out1.level, ReloadLevel::L2HotReload);
        let baseline_yaml = std::fs::read_to_string(coordinator.runtime_yaml_path()).unwrap();
        let baseline_doc: serde_yaml_ng::Value = serde_yaml_ng::from_str(&baseline_yaml).unwrap();
        assert_eq!(baseline_doc["tun"]["mtu"].as_u64(), Some(1500));

        // 2. Enable preaccel with non-443 node -> effective MTU drops 1500 -> 1400.
        //    With allow_l3_restart=false, must reject as L3CoreRestart without touching runtime.yaml.
        cfg.preaccel.enabled = true;
        save(&paths, &cfg).unwrap();
        let out_blocked = coordinator
            .apply_disk_reload(DiskReloadOptions {
                verify_with_binary: false,
                allow_l3_restart: false,
                allow_tun: true,
                snapshot_override: Some(snapshot_with_non443.clone()),
                ..Default::default()
            })
            .await;
        assert!(out_blocked.rejected);
        assert_eq!(out_blocked.level, ReloadLevel::L3CoreRestart);
        assert!(
            out_blocked
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("effective TUN MTU changed (1500 -> 1400)")
        );
        assert_eq!(
            std::fs::read_to_string(coordinator.runtime_yaml_path()).unwrap(),
            baseline_yaml
        );

        // 3. With allow_l3_restart=true (and no binary in temp_paths), it escalates to L3CoreRestart
        //    and hits the L3 binary resolution guard instead of silently applying as L2.
        let out_escalated = coordinator
            .apply_disk_reload(DiskReloadOptions {
                verify_with_binary: false,
                allow_l3_restart: true,
                allow_tun: true,
                snapshot_override: Some(snapshot_with_non443.clone()),
                ..Default::default()
            })
            .await;
        assert_eq!(out_escalated.level, ReloadLevel::L3CoreRestart);
        assert!(out_escalated.rejected);
        assert!(
            out_escalated
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("no Mihomo binary could be resolved")
        );

        // 4. Reverse direction (1400 -> 1500): seed runtime.yaml with mtu=1400, disable preaccel.
        let mut seeded_cfg = cfg.clone();
        seeded_cfg.preaccel.enabled = true;
        let seeded_yaml = "tun:\n  enable: true\n  mtu: 1400\n";
        std::fs::write(coordinator.runtime_yaml_path(), seeded_yaml).unwrap();
        let ports = AllocatedPorts {
            bind_host: "127.0.0.1".to_string(),
            mixed_port: seeded_cfg.mixed_port,
            controller_port: seeded_cfg.controller_port,
            dns_port: seeded_cfg.dns_listen_port,
            shifted: Vec::new(),
        };
        coordinator
            .seed_active_state(
                seeded_cfg.clone(),
                "seed-1400".into(),
                ports.clone(),
                "0123456789abcdef0123456789abcdef".into(),
            )
            .await;

        seeded_cfg.preaccel.enabled = false;
        save(&paths, &seeded_cfg).unwrap();
        let out_reverse = coordinator
            .apply_disk_reload(DiskReloadOptions {
                verify_with_binary: false,
                allow_l3_restart: false,
                allow_tun: true,
                snapshot_override: Some(snapshot_with_non443),
                ..Default::default()
            })
            .await;
        assert!(out_reverse.rejected);
        assert_eq!(out_reverse.level, ReloadLevel::L3CoreRestart);
        assert!(
            out_reverse
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("effective TUN MTU changed (1400 -> 1500)")
        );

        // 5. No MTU crossing (all nodes skipped native 443 -> effective MTU stays 1500): stays L2HotReload.
        let seeded_yaml_1500 = "tun:\n  enable: true\n  mtu: 1500\n";
        std::fs::write(coordinator.runtime_yaml_path(), seeded_yaml_1500).unwrap();
        seeded_cfg.preaccel.enabled = false;
        coordinator
            .seed_active_state(
                seeded_cfg.clone(),
                "seed-1500".into(),
                ports,
                "0123456789abcdef0123456789abcdef".into(),
            )
            .await;
        seeded_cfg.preaccel.enabled = true;
        seeded_cfg.preaccel.skip_443_native = true;
        save(&paths, &seeded_cfg).unwrap();
        non443_node.enabled = false;
        let out_same_mtu = coordinator
            .apply_disk_reload(DiskReloadOptions {
                verify_with_binary: false,
                allow_l3_restart: false,
                allow_tun: true,
                snapshot_override: Some(DiskReloadSnapshot {
                    nodes: vec![native443_node, non443_node],
                    groups: Vec::new(),
                    relays: vec![relay],
                }),
                ..Default::default()
            })
            .await;
        assert!(
            out_same_mtu.applied,
            "same-MTU preaccel toggle must stay L2: {:?}",
            out_same_mtu.error
        );
        assert_eq!(out_same_mtu.level, ReloadLevel::L2HotReload);

        let _ = std::fs::remove_dir_all(&paths.root_data_dir);
    }

    #[tokio::test]
    async fn apply_disk_reload_locks_tun_disabled_when_allow_tun_false_even_with_inline_override_yaml()
    {
        let paths = temp_paths("allow-tun-false-inline-lock");
        let adapter = Arc::new(MihomoAdapter::new(Arc::new(JobGuard::new().unwrap())).unwrap());
        let coordinator = HotReloadCoordinator::new(paths.clone(), adapter);

        let mut cfg = AppConfig::default();
        cfg.tun.enabled = true;
        cfg.rules_override.override_mode = OverrideMode::Disabled;
        cfg.rules_override.inline_override_yaml = Some("tun:\n  enable: true\n  mtu: 1480\n".to_string());
        save(&paths, &cfg).unwrap();

        let out = coordinator
            .apply_disk_reload(DiskReloadOptions {
                verify_with_binary: false,
                allow_l3_restart: false,
                allow_tun: false,
                snapshot_override: Some(DiskReloadSnapshot::default()),
                ..Default::default()
            })
            .await;
        assert!(out.applied, "reload under !allow_tun failed: {:?}", out.error);

        let written = std::fs::read_to_string(coordinator.runtime_yaml_path()).unwrap();
        let doc: serde_yaml_ng::Value = serde_yaml_ng::from_str(&written).unwrap();
        assert_eq!(
            doc["tun"]["enable"],
            serde_yaml_ng::Value::Bool(false),
            "inline_override_yaml must not bypass !allow_tun to enable TUN"
        );

        let _ = std::fs::remove_dir_all(&paths.root_data_dir);
    }

    #[tokio::test]
    async fn seed_active_state_ignores_stale_runtime_yaml_tun_mtu_when_tun_disabled() {
        let paths = temp_paths("seed-active-state-tun-disabled");
        let adapter = Arc::new(MihomoAdapter::new(Arc::new(JobGuard::new().unwrap())).unwrap());
        let coordinator = HotReloadCoordinator::new(paths.clone(), adapter);

        // Leave a stale runtime.yaml with tun.enable: true on disk.
        std::fs::create_dir_all(&paths.runtime_dir).unwrap();
        std::fs::write(
            coordinator.runtime_yaml_path(),
            "tun:\n  enable: true\n  mtu: 1400\n",
        )
        .unwrap();

        let mut cfg = AppConfig::default();
        cfg.tun.enabled = false;
        cfg.tun.mtu = 1500;
        let ports = AllocatedPorts {
            bind_host: "127.0.0.1".to_string(),
            mixed_port: cfg.mixed_port,
            controller_port: cfg.controller_port,
            dns_port: cfg.dns_listen_port,
            shifted: Vec::new(),
        };
        coordinator
            .seed_active_state(
                cfg,
                "seed-tun-off".into(),
                ports,
                "0123456789abcdef0123456789abcdef".into(),
            )
            .await;

        let guard = coordinator.state.lock().await;
        assert_eq!(
            guard.last_effective_tun_mtu, None,
            "seed_active_state must not seed stale runtime.yaml MTU when cfg.tun.enabled is false"
        );
        drop(guard);

        let _ = std::fs::remove_dir_all(&paths.root_data_dir);
    }

    #[tokio::test]
    async fn apply_disk_reload_detects_mtu_change_when_override_enables_tun_and_live_yaml_omits_mtu()
    {
        let paths = temp_paths("override-tun-and-omit-mtu");
        let adapter = Arc::new(MihomoAdapter::new(Arc::new(JobGuard::new().unwrap())).unwrap());
        let coordinator = HotReloadCoordinator::new(paths.clone(), adapter);

        let relay = PreAccelRelay {
            id: "relay-ov".to_string(),
            name: "Relay-OV".to_string(),
            provider: "aliyun".to_string(),
            region: "CN".to_string(),
            server: "203.0.113.21".to_string(),
            port: 443,
            protocol: "anytls".to_string(),
            password: "demo-password".to_string(),
            sni: None,
            skip_cert_verify: true,
            priority: 10,
            expires_at: None,
            enabled: true,
            last_probe_ms: None,
            last_mbps: None,
            last_up_mbps: None,
            last_down_mbps: None,
            supports_ipv6: false,
        };
        let non443_node = ProxyNode {
            id: "node-non443-ov".to_string(),
            sub_id: "sub-ov".to_string(),
            name: "Node-8443-OV".to_string(),
            protocol: "trojan".to_string(),
            server: "198.51.100.88".to_string(),
            port: 8443,
            is_443_native: false,
            preaccel_eligible: true,
            preaccel_override: None,
            enabled: true,
            raw_config: serde_json::json!({
                "name": "Node-8443-OV",
                "type": "trojan",
                "server": "198.51.100.88",
                "port": 8443,
                "password": "demo-trojan-password"
            }),
            ..Default::default()
        };
        let snapshot = DiskReloadSnapshot {
            nodes: vec![non443_node],
            groups: Vec::new(),
            relays: vec![relay],
        };

        // Case 1: cfg.tun.enabled == false, but inline_override_yaml enables TUN under allow_tun=true.
        // Baseline reload compiles tun.enable=true & effective_tun_mtu=1500.
        let mut cfg = AppConfig::default();
        cfg.tun.enabled = false;
        cfg.tun.mtu = 1500;
        cfg.preaccel.enabled = false;
        cfg.rules_override.inline_override_yaml = Some("tun:\n  enable: true\n".to_string());
        save(&paths, &cfg).unwrap();

        let out1 = coordinator
            .apply_disk_reload(DiskReloadOptions {
                verify_with_binary: false,
                allow_l3_restart: false,
                allow_tun: true,
                snapshot_override: Some(snapshot.clone()),
                ..Default::default()
            })
            .await;
        assert!(out1.applied, "override-enabled TUN baseline failed: {:?}", out1.error);

        // Now enable preaccel -> dialer-proxy clamps effective TUN MTU 1500 -> 1400.
        // Even though cfg.tun.enabled is still false, compiled tun.enable==true must trigger L3!
        cfg.preaccel.enabled = true;
        save(&paths, &cfg).unwrap();
        let out_l3 = coordinator
            .apply_disk_reload(DiskReloadOptions {
                verify_with_binary: false,
                allow_l3_restart: false,
                allow_tun: true,
                snapshot_override: Some(snapshot.clone()),
                ..Default::default()
            })
            .await;
        assert!(out_l3.rejected);
        assert_eq!(out_l3.level, ReloadLevel::L3CoreRestart);
        assert!(
            out_l3
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("effective TUN MTU changed (1500 -> 1400)"),
            "unexpected error: {:?}",
            out_l3.error
        );

        // Case 2: Live runtime.yaml enables TUN (`tun.enable: true`) but OMITS the `mtu` key so
        // `read_live_tun_mtu_from_path` returns None -> must fall back to 1500 baseline and detect
        // transition to 1400!
        std::fs::write(coordinator.runtime_yaml_path(), "tun:\n  enable: true\n").unwrap();
        assert_eq!(
            read_live_tun_mtu_from_path(&coordinator.runtime_yaml_path()),
            None
        );
        {
            let mut guard = coordinator.state.lock().await;
            guard.last_effective_tun_mtu = None;
        }
        let out_omitted_mtu = coordinator
            .apply_disk_reload(DiskReloadOptions {
                verify_with_binary: false,
                allow_l3_restart: false,
                allow_tun: true,
                snapshot_override: Some(snapshot),
                ..Default::default()
            })
            .await;
        assert!(out_omitted_mtu.rejected);
        assert_eq!(out_omitted_mtu.level, ReloadLevel::L3CoreRestart);
        assert!(
            out_omitted_mtu
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("effective TUN MTU changed (1500 -> 1400)"),
            "expected omitted-mtu 1500 -> 1400 escalation, got: {:?}",
            out_omitted_mtu.error
        );

        let _ = std::fs::remove_dir_all(&paths.root_data_dir);
    }
}
