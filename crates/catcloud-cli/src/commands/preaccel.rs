//! `preaccel` relay management, speed/campus testing, and live transport diagnostics.

use anyhow::{Context, Result};
use catcloud_core::config;
use catcloud_core::core_adapter::config_compiler::{
    DEFAULT_FALLBACK_GROUP_NAME, PREACCEL_SELECT_GROUP_NAME, PreAccelTransportDiagnostics,
    SINGLE_NODE_GROUP_NAME, build_preaccel_transport_diagnostics,
};
use catcloud_core::core_adapter::{
    ResolvedControllerEndpoint, compute_file_sha256, format_host_port, resolve_mihomo_binary,
};
use catcloud_core::models::{
    AppConfig, MultiGroup, PreAccelDispatchStrategy, PreAccelRelay, ProbeDefinition, ProbeKind,
    ProxyMode, ProxyNode, RouteTargetMode, is_ipv6_only_node,
};
use catcloud_core::platform::{
    PortListenerOwner, default_platform, get_process_start_time_unix, list_listening_port_owners,
};
use catcloud_core::preaccel::campus::{CampusBypassTracker, probe_campus_portal};
use catcloud_core::preaccel::generator::{build_preaccel_compile_plan, validate_domestic_probe_url};
use catcloud_core::preaccel::global_tunnel::{
    GlobalPreAccelRuntimeMeta, locate_windivert_files, read_global_preaccel_runtime_meta,
};
use catcloud_core::preaccel::schema::{evaluate_expiry, parse_mmrelay_clipboard};
use catcloud_core::probe::{
    DEFAULT_READY_TIMEOUT, IsolatedProbeCore, ThroughputProbeConfig, build_isolated_http_client,
    run_download_probe_with_config, run_latency_probe, run_upload_probe_with_config,
};
use catcloud_core::process_guard::{JobGuard, signal_config_reload_for_data_dir};
use catcloud_core::sanitize::{
    redact_ip_or_host, redact_path_for_display, redact_relay_for_readonly, sanitize_json_value,
    sanitize_log_line,
};
use catcloud_core::AppPaths;
use chrono::Utc;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use super::args::{AlreadyEmittedJsonError, PreaccelCommand};
use super::config_reload::{
    ActiveCorePortState, inspect_active_core_ports, is_valid_managed_pid,
    pid_start_time_matches_fail_closed,
};
use super::net_logs::{is_mihomo_like_process_name, probe_live_tun_connections};
use super::redact_helpers::{
    emit_output, format_paths_with_reveal, is_info_placeholder_node, open_storage,
    parse_preaccel_dispatch_strategy, parse_preaccel_lb_strategy, redact_download_guidance,
    redact_preaccel_config_for_output, resolve_valid_group_active_node, sanitize_multiline_text,
};

pub(super) async fn handle_preaccel(paths: &AppPaths, as_json: bool, action: PreaccelCommand) -> Result<()> {
    match action {
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
            let (imported_count, warnings) =
                catcloud_core::preaccel::import_relays_dedup_into_storage(&db, bundle.relays)?;
            if imported_count == 0 && !warnings.is_empty() {
                anyhow::bail!("{}", warnings.join("; "));
            }
            let persisted_relays = db.list_preaccel_relays(false)?;
            drop(db);
            let live_reload_signaled = if imported_count > 0 {
                signal_config_reload_for_data_dir(&paths.root_data_dir)
            } else {
                false
            };
            let redacted_relays: Vec<PreAccelRelay> = persisted_relays
                .iter()
                .map(redact_relay_for_readonly)
                .collect();
            let out = json!({
                "ok": true,
                "sanitized": true,
                "imported_relays": imported_count,
                "warnings": warnings,
                "relays": redacted_relays,
                "live_reload_signaled": live_reload_signaled,
            });
            emit_output(
                as_json,
                &out,
                &format!(
                    "Imported {} verified domestic :443 relay(s).",
                    imported_count
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
            let db = open_storage(paths)?;
            let enabled_relays = db.list_preaccel_relays(true)?;
            if enabled == Some(true) && enabled_relays.is_empty() {
                anyhow::bail!(
                    "NO_ENABLED_RELAY: 尚未添加或启用任何国内提速线路（当前已启用中转数为 0），请先通过 `catcloud preaccel add` 添加并启用至少一条中转后再开启提速"
                );
            }
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
                if matches!(
                    cfg.preaccel.dispatch_strategy,
                    PreAccelDispatchStrategy::Auto | PreAccelDispatchStrategy::LoadBalance
                ) {
                    cfg.preaccel.active_relay_id = None;
                }
            }
            let enabled_ids: HashSet<String> =
                enabled_relays.into_iter().map(|r| r.id).collect();
            let _ = config::reconcile_dangling_active_relay(&mut cfg, &enabled_ids);
            if let Some(lb) = lb_strategy {
                cfg.preaccel.lb_strategy = parse_preaccel_lb_strategy(&lb)?;
            }
            drop(db);
            config::save(paths, &cfg)?;
            let live_reload_signaled =
                signal_config_reload_for_data_dir(&paths.root_data_dir);
            let sanitized_preaccel = redact_preaccel_config_for_output(&cfg.preaccel);
            let out = json!({
                "ok": true,
                "sanitized": true,
                "preaccel": sanitized_preaccel,
                "live_reload_signaled": live_reload_signaled,
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
            let mut persisted_speed_updates = 0usize;
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
                    persisted_speed_updates += 1;
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
            drop(db);
            if let Some(err) = persist_err {
                return Err(err);
            }
            let live_reload_signaled = if persisted_speed_updates > 0 {
                signal_config_reload_for_data_dir(&paths.root_data_dir)
            } else {
                false
            };

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
                "live_reload_signaled": live_reload_signaled,
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
    }
}

pub(super) fn select_preaccel_speed_reference_node(
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

pub(super) fn verify_managed_pid_with_start_time(
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

pub(super) fn evaluate_live_global_preaccel_pid(
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

pub(super) fn is_live_global_preaccel_pid(meta: &GlobalPreAccelRuntimeMeta) -> bool {
    if !meta.running {
        return false;
    }
    let Some(pid) = meta.pid.filter(|&p| is_valid_managed_pid(p)) else {
        return false;
    };
    let actual_ts = get_process_start_time_unix(pid);
    #[cfg(not(target_os = "windows"))]
    let non_windows_proc_name_owned: Option<String> = catcloud_core::subscription::process_attach::list_process_candidates(false)
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

pub(super) fn resolve_effective_preaccel_carrier(
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
pub(super) struct CliPreAccelTransportSnapshot {
    pub(super) diagnostics: PreAccelTransportDiagnostics,
    pub(super) active_relay_selected: Option<String>,
    pub(super) active_exit_selected: Option<String>,
    pub(super) runtime_config_sha256: Option<String>,
}

pub(super) fn read_tun_mtu_from_runtime_yaml(runtime_yaml_path: &Path) -> Option<u16> {
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
pub(super) async fn collect_cli_preaccel_transport_snapshot(
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

pub(super) async fn build_global_preaccel_status_payload(paths: &AppPaths) -> Result<(Value, String)> {
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
