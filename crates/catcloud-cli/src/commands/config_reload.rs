//! `config` subcommands, live baseline/port inspection, diagnostics, and desktop hot-reload handoff.

use anyhow::{Context, Result};
use catcloud_core::config;
use catcloud_core::core_adapter::config_compiler::{
    CompileInput, DanglingRuleRepairAction, GatewayExportOptions, GatewayExportOutput,
    GatewayExportProfile, audit_dangling_global_rules, compile_mihomo_config_with_runtime_dir,
    export_gateway_yaml, format_static_validation_summary_zh, repair_dangling_global_rules,
    resolve_default_fallback_group_name, validate_compiled_yaml,
};
use catcloud_core::core_adapter::dns_diag::{
    DNS_TLS_STATUS_CERT_FAILED, DNS_TLS_STATUS_DEGRADED_RECOVERED,
};
use catcloud_core::core_adapter::port_guard::{
    AllocatedPorts, PortShiftNotice, allocate_safe_ports_for_hosts, is_port_available_tcp_udp,
};
use catcloud_core::core_adapter::{
    DiskReloadOptions, HotReloadCoordinator, LiveCoreConfigSnapshot, MihomoAdapter, ReloadLevel,
    ResolvedControllerEndpoint, classify_config_diff, compute_file_sha256, format_host_port,
    generate_controller_secret, resolve_effective_controller_endpoint_info, resolve_mihomo_binary,
    verify_config_with_binary,
};
use catcloud_core::models::{AppConfig, CoreLogLevel, ProxyMode, TunStackMode};
use catcloud_core::platform::{PortListenerOwner, default_platform, list_listening_port_owners};
use catcloud_core::preaccel::global_tunnel::locate_windivert_files;
use catcloud_core::process_guard::{
    ConfigReloadWaitOutcome, JobGuard, is_primary_instance_alive,
    signal_config_reload_and_wait_outcome, signal_config_reload_for_data_dir,
};
use catcloud_core::sanitize::{
    redact_compiled_yaml, redact_path_for_display, sanitize_json_value, sanitize_log_line,
};
use catcloud_core::{AppPaths, CatError};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use super::args::{AlreadyEmittedJsonError, ConfigCommand, ReloadArgs};
use super::net_logs::analyze_dns_tls_across_logs;
use super::redact_helpers::{
    emit_output, open_storage, read_bounded_file_lines, redact_config_issues,
    redact_reload_outcome, redact_static_validation, sanitize_multiline_text, unquote_yaml_scalar,
};
use super::status_docs_update::{
    collect_geodata_status, is_cli_tun_privilege_ready, resolve_cli_effective_tun_state,
};

pub(super) async fn handle_config(paths: &AppPaths, as_json: bool, action: ConfigCommand) -> Result<()> {
    match action {
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

        ConfigCommand::RepairRules {
            mode,
            target,
            dry_run,
        } => {
            let mut cfg = config::load_or_init(paths)?;
            let db = open_storage(paths)?;
            let groups = db.list_multi_groups()?;
            let nodes = db.list_nodes()?;
            drop(db);
            let audit_before = audit_dangling_global_rules(&cfg, &groups, &nodes);
            let action = match mode.trim().to_ascii_lowercase().as_str() {
                "remove" | "delete" | "clean" => DanglingRuleRepairAction::Remove,
                "rewrite" | "remap" => {
                    let dest = target
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(ToOwned::to_owned)
                        .unwrap_or_else(|| resolve_default_fallback_group_name(&cfg, &groups));
                    DanglingRuleRepairAction::RewriteToGroup { target_group: dest }
                }
                other => anyhow::bail!(
                    "unsupported --mode `{other}` (expected `remove` or `rewrite`)"
                ),
            };
            let report = repair_dangling_global_rules(&mut cfg, &groups, &nodes, action, None);
            let changed = report.removed_count > 0 || report.rewritten_count > 0;
            let mut live_reload_signaled = false;
            if !dry_run && changed {
                config::save(paths, &cfg)?;
                live_reload_signaled = signal_config_reload_for_data_dir(&paths.root_data_dir);
            }
            let audit_after = if dry_run {
                audit_before.clone()
            } else {
                audit_dangling_global_rules(&cfg, &groups, &nodes)
            };
            let out = json!({
                "ok": true,
                "sanitized": true,
                "dry_run": dry_run,
                "changed": changed,
                "audit_before": audit_before,
                "report": report,
                "audit_after": audit_after,
                "live_reload_signaled": live_reload_signaled,
            });
            let human = format!(
                "Dangling rules repair (dry_run={dry_run}): removed={}, rewritten={}, remaining={}.",
                report.removed_count, report.rewritten_count, audit_after.total_dangling
            );
            emit_output(as_json, &out, &human)
        }

        ConfigCommand::Reload(args) => {
            execute_config_reload(paths, as_json, args).await
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
            let live_reload_signaled =
                signal_config_reload_for_data_dir(&paths.root_data_dir);
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
                "live_reload_signaled": live_reload_signaled,
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
    }
}

pub(super) const MAX_DIAG_LOG_LINES: usize = 40;

const MAX_DIAG_LOG_TAIL_READ_BYTES: u64 = 64 * 1024;

pub(super) async fn probe_live_controller(
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

const MANAGED_PID_START_TIME_TOLERANCE_SECS: u64 = 2;

#[derive(Debug, Clone)]
pub(super) struct ThirdPartyPortConflict {
    pub(super) role: String,
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) owner_pids: Vec<u32>,
}

#[derive(Debug, Clone)]
pub(super) struct ActiveCorePortState {
    pub(super) core_running: bool,
    pub(super) core_version: Option<String>,
    pub(super) controller_auth_error: Option<String>,
    pub(super) endpoint: ResolvedControllerEndpoint,
    pub(super) live_config: Option<LiveCoreConfigSnapshot>,
    pub(super) effective_mixed_port: u16,
    pub(super) effective_controller_port: u16,
    pub(super) effective_dns_port: u16,
    pub(super) mixed_free: bool,
    pub(super) controller_free: bool,
    pub(super) dns_free: bool,
    pub(super) mixed_owned_by_active_core: bool,
    pub(super) controller_owned_by_active_core: bool,
    pub(super) dns_owned_by_active_core: bool,
    pub(super) owners: Vec<PortListenerOwner>,
}

impl ActiveCorePortState {
    pub(super) fn all_active_ports_owned_by_core(&self) -> bool {
        self.core_running
            && self.controller_owned_by_active_core
            && (self.mixed_free || self.mixed_owned_by_active_core)
            && (self.dns_free || self.dns_owned_by_active_core)
    }

    pub(super) fn third_party_conflicts_for_effective_ports(&self, cfg: &AppConfig) -> Vec<Value> {
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

    pub(super) fn to_status_json(&self) -> Value {
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

pub(super) fn is_valid_managed_pid(pid: u32) -> bool {
    pid > 0 && pid != std::process::id()
}

pub(super) fn pid_start_time_matches_fail_closed(
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

pub(super) fn is_port_owned_by_active_core(
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

pub(super) async fn inspect_active_core_ports(paths: &AppPaths, cfg: &AppConfig) -> ActiveCorePortState {
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
pub(super) fn resolve_compile_and_preview_ports(
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
pub(super) fn build_live_baseline_config_from_runtime(
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

pub(super) async fn build_config_validate_payload(paths: &AppPaths) -> Result<(bool, Value, String)> {
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
    let relay_servers: Vec<String> = if cfg.preaccel.enabled {
        relays
            .iter()
            .filter(|r| r.enabled)
            .map(|r| r.server.clone())
            .collect()
    } else {
        Vec::new()
    };
    let static_report = validate_compiled_yaml(&compiled.yaml, &relay_servers)?;
    let dangling_audit = audit_dangling_global_rules(&cfg, &groups, &nodes);
    let fallback_group_hint = resolve_default_fallback_group_name(&cfg, &groups);
    let static_summary_zh =
        format_static_validation_summary_zh(&static_report, Some(&fallback_group_hint));
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
        "static_validation_summary_zh": static_summary_zh,
        "dangling_rules_audit": dangling_audit,
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

pub(super) fn parse_gateway_export_profile(raw: &str) -> Result<GatewayExportProfile> {
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
pub(super) async fn execute_config_export_gateway(
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

pub(super) async fn run_config_reload_inner(
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
    let mut classified_level = match &live_baseline_cfg {
        Some(old) => classify_config_diff(old, &effective_cfg),
        None => ReloadLevel::L2HotReload,
    };
    let mut diff_reasons = match &live_baseline_cfg {
        Some(old) => summarize_l3_diff_reasons(old, &effective_cfg),
        None => Vec::new(),
    };
    let mut requires_l3_restart = classified_level == ReloadLevel::L3CoreRestart;

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
        let mut compiled = compile_mihomo_config_with_runtime_dir(
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
        if !allow_tun {
            catcloud_core::core_adapter::enforce_tun_disabled_on_compiled(&mut compiled)?;
        }
        let compiled_tun_enabled = compiled
            .value
            .get("tun")
            .and_then(|t| t.get("enable"))
            .and_then(|v| v.as_bool())
            == Some(true);
        if core_running && compiled_tun_enabled {
            let live_mtu =
                catcloud_core::core_adapter::read_live_tun_mtu_from_path(&runtime_yaml_path)
                    .or_else(|| live_tun_enabled.then_some(1500));
            if let Some(live_mtu) = live_mtu {
                let next_mtu = compiled.stats.effective_tun_mtu;
                if live_mtu != next_mtu {
                    classified_level = ReloadLevel::L3CoreRestart;
                    requires_l3_restart = true;
                    let reason = format!("tun.effective_mtu ({live_mtu} -> {next_mtu})");
                    if !diff_reasons.iter().any(|r| r.contains("tun.effective_mtu")) {
                        diff_reasons.push(reason);
                    }
                }
            }
        }
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

pub(super) async fn run_config_reload_with_desktop_handoff(
    paths: &AppPaths,
    args: &ReloadArgs,
    desktop_timeout: Duration,
    caps_override: Option<catcloud_core::platform::PlatformCapabilities>,
    verify_with_binary: bool,
) -> Result<(bool, Value, String)> {
    if !args.dry_run {
        let data_dir = paths.root_data_dir.clone();
        let allow_l3_restart = args.allow_restart;
        let wait_result = tokio::task::spawn_blocking(move || {
            let outcome =
                signal_config_reload_and_wait_outcome(&data_dir, allow_l3_restart, desktop_timeout);
            let desktop_alive = match &outcome {
                ConfigReloadWaitOutcome::TimedOut { .. } => is_primary_instance_alive(&data_dir),
                _ => false,
            };
            (outcome, desktop_alive)
        })
        .await
        .context("failed to join desktop live hot-reload handoff task")?;

        match wait_result {
            (ConfigReloadWaitOutcome::Ack(ack), _) => {
                let ok = ack.applied && !ack.rejected;
                let sanitized_error = ack.error.as_deref().map(sanitize_multiline_text);
                let mut out = json!({
                    "ok": ok,
                    "sanitized": true,
                    "dry_run": false,
                    "live_reload_signaled": true,
                    "via": "desktop_live_hotswap",
                    "req_id": &ack.req_id,
                    "applied": ack.applied,
                    "rejected": ack.rejected,
                    "level": &ack.level,
                    "error": &sanitized_error,
                    "completed_at_ms": ack.completed_at_ms,
                    "force": args.force,
                    "allow_l3_restart": args.allow_restart,
                });
                sanitize_json_value(&mut out);
                let level_label = ack.level.as_deref().unwrap_or("unknown");
                let human = if ok {
                    format!(
                        "Desktop live hot-reload applied (via=desktop_live_hotswap, level={level_label}, req_id={}).",
                        ack.req_id
                    )
                } else {
                    format!(
                        "Desktop live hot-reload rejected (via=desktop_live_hotswap, level={level_label}, error={}).",
                        sanitized_error.as_deref().unwrap_or("rejected")
                    )
                };
                return Ok((ok, out, human));
            }
            (ConfigReloadWaitOutcome::TimedOut { req_id }, true) => {
                let err_msg = format!(
                    "Desktop live hot-reload timed out after {}ms while primary desktop instance is still running (req_id={req_id}); refusing direct controller fallback to avoid concurrent core writes.",
                    desktop_timeout.as_millis()
                );
                let mut out = json!({
                    "ok": false,
                    "sanitized": true,
                    "dry_run": false,
                    "live_reload_signaled": true,
                    "via": "desktop_live_hotswap",
                    "req_id": &req_id,
                    "timed_out": true,
                    "desktop_alive": true,
                    "applied": false,
                    "rejected": false,
                    "error": &err_msg,
                    "force": args.force,
                    "allow_l3_restart": args.allow_restart,
                });
                sanitize_json_value(&mut out);
                return Ok((false, out, err_msg));
            }
            (ConfigReloadWaitOutcome::TimedOut { .. }, false)
            | (ConfigReloadWaitOutcome::NotRunning, _) => {}
        }
    }

    let (ok, mut out, human) =
        run_config_reload_inner(paths, args.dry_run, caps_override, verify_with_binary).await?;
    if let Some(obj) = out.as_object_mut() {
        obj.insert("live_reload_signaled".to_string(), json!(false));
        if !args.dry_run {
            obj.insert("via".to_string(), json!("direct_controller"));
        }
        obj.entry("force".to_string())
            .or_insert_with(|| json!(args.force));
    }
    Ok((ok, out, human))
}

pub(super) async fn execute_config_reload(paths: &AppPaths, as_json: bool, args: ReloadArgs) -> Result<()> {
    let (ok, out, human) =
        run_config_reload_with_desktop_handoff(paths, &args, Duration::from_secs(4), None, true)
            .await?;
    if !ok {
        if as_json {
            emit_output(true, &out, "")?;
            return Err(AlreadyEmittedJsonError(human).into());
        }
        anyhow::bail!("{human}");
    }
    emit_output(as_json, &out, &human)
}

pub(super) async fn build_diag_payload(paths: &AppPaths, reveal_secrets: bool) -> Result<Value> {
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
