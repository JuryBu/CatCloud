//! `probe` and `group` subcommand handlers, isolated probes, and multi-group evaluation.

use anyhow::{Context, Result};
use catcloud_core::config;
use catcloud_core::core_adapter::config_compiler::cascade_group_name_change_in_global_rules;
use catcloud_core::core_adapter::{BinaryResolution, resolve_mihomo_binary};
use catcloud_core::models::{
    DEFAULT_COST_EFFECTIVE_FORMULA, FallbackPolicy, MultiGroup, MultiGroupMode, ProbeDefinition,
    ProbeKind, SwitchMode,
};
use catcloud_core::probe::registry::{FunnelTier, ProbeRegistry, validate_definition};
use catcloud_core::probe::{FunnelOptions, FunnelRunReport, IsolatedProbeCore, run_funnel_for_node};
use catcloud_core::process_guard::{JobGuard, signal_config_reload_for_data_dir};
use catcloud_core::sanitize::sanitize_json_value;
use catcloud_core::strategy::arbiter::{ArbiterGroupMemory, decide_group_action};
use catcloud_core::strategy::evaluator::evaluate_group_candidates;
use catcloud_core::strategy::formula::validate_formula;
use catcloud_core::strategy::health_pool::read_watchdog_state_snapshot;
use catcloud_core::AppPaths;
use chrono::Utc;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use super::args::{GroupCommand, GroupCreateArgs, GroupMembersArgs, GroupPolicyArgs, ProbeCommand};
use super::redact_helpers::{
    emit_output, format_path_with_reveal, format_paths_with_reveal, open_storage, parse_csv_ids,
    parse_fallback_policy, parse_group_match_rules_arg, parse_group_mode, parse_switch_mode,
    redact_download_guidance, redact_funnel_report,
};

pub(super) async fn handle_probe(paths: &AppPaths, as_json: bool, action: ProbeCommand) -> Result<()> {
    match action {
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
            drop(db);
            let live_reload_signaled =
                signal_config_reload_for_data_dir(&paths.root_data_dir);
            let out = json!({
                "ok": true,
                "probe": def,
                "live_reload_signaled": live_reload_signaled,
            });
            emit_output(as_json, &out, &format!("Saved probe `{}`.", args.id))
        }

        ProbeCommand::Remove { id } => {
            let db = open_storage(paths)?;
            let removed = db.delete_probe_definition(&id)?;
            drop(db);
            let live_reload_signaled = if removed {
                signal_config_reload_for_data_dir(&paths.root_data_dir)
            } else {
                false
            };
            let out = json!({
                "ok": true,
                "id": id,
                "removed": removed,
                "live_reload_signaled": live_reload_signaled,
            });
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
            drop(db);
            let live_reload_signaled = if persisted_records > 0 {
                signal_config_reload_for_data_dir(&paths.root_data_dir)
            } else {
                false
            };

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
                "live_reload_signaled": live_reload_signaled,
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
    }
}

pub(super) fn handle_group(paths: &AppPaths, as_json: bool, action: GroupCommand) -> Result<()> {
    match action {
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
            drop(db);
            let live_reload_signaled =
                signal_config_reload_for_data_dir(&paths.root_data_dir);
            let out = json!({
                "ok": true,
                "group_id": group_id,
                "previous_node_id": prev,
                "active_node_id": next_id,
                "live_reload_signaled": live_reload_signaled,
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
    }
}

pub(super) fn build_probe_run_dry_run_payload(
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

pub(super) fn build_probe_run_missing_binary_payload(
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

pub(super) fn execute_group_create(paths: &AppPaths, args: GroupCreateArgs) -> Result<(Value, String)> {
    for gate in &args.hard_gate {
        validate_formula(gate)?;
    }

    let db = open_storage(paths)?;
    let existing = db.get_multi_group(&args.id)?;
    let created = existing.is_none();
    let old_name: Option<String> = existing.as_ref().map(|g| g.name.clone());

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
        if let Some(indep) = args.independent_routing {
            existing_group.independent_routing = indep;
        }
        if !args.hard_gate.is_empty() {
            existing_group.hard_gates = args.hard_gate;
        }
        if let Some(raw_rules) = args.match_rules {
            existing_group.match_rules = parse_group_match_rules_arg(&raw_rules);
        }
        if !args.add_match_rule.is_empty() {
            let mut seen: HashSet<String> = existing_group.match_rules.iter().cloned().collect();
            for raw in args.add_match_rule {
                for rule in parse_group_match_rules_arg(&raw) {
                    if seen.insert(rule.clone()) {
                        existing_group.match_rules.push(rule);
                    }
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
        let mut match_rules: Vec<String> = args
            .match_rules
            .as_deref()
            .map(parse_group_match_rules_arg)
            .unwrap_or_default();
        if !args.add_match_rule.is_empty() {
            let mut seen: HashSet<String> = match_rules.iter().cloned().collect();
            for raw in args.add_match_rule {
                for rule in parse_group_match_rules_arg(&raw) {
                    if seen.insert(rule.clone()) {
                        match_rules.push(rule);
                    }
                }
            }
        }
        MultiGroup {
            id: args.id.clone(),
            name,
            mode,
            match_rules,
            member_node_ids,
            hard_gates: args.hard_gate,
            formula_expr: formula,
            fallback_policy,
            switch_mode,
            independent_routing: args.independent_routing.unwrap_or(false),
            ..MultiGroup::default()
        }
    };

    db.upsert_multi_group(&group)?;
    drop(db);

    let mut cascaded_global_rules = 0usize;
    if let Some(prev_name) = old_name.as_deref() {
        let prev_trimmed = prev_name.trim();
        let next_trimmed = group.name.trim();
        if !prev_trimmed.is_empty() && !next_trimmed.is_empty() && prev_trimmed != next_trimmed {
            let mut cfg = config::load_or_init(paths)?;
            cascaded_global_rules = cascade_group_name_change_in_global_rules(
                &mut cfg,
                prev_trimmed,
                Some(next_trimmed),
            );
            if cascaded_global_rules > 0 {
                config::save(paths, &cfg)?;
            }
        }
    }

    let live_reload_signaled = signal_config_reload_for_data_dir(&paths.root_data_dir);
    let out = json!({
        "ok": true,
        "created": created,
        "updated": !created,
        "group": group,
        "cascaded_global_rules": cascaded_global_rules,
        "live_reload_signaled": live_reload_signaled,
    });
    let verb = if created { "Created" } else { "Updated" };
    Ok((out, format!("{verb} multi-group `{}`.", args.id)))
}

pub(super) fn execute_group_members(paths: &AppPaths, args: GroupMembersArgs) -> Result<(Value, String)> {
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
    drop(db);
    let live_reload_signaled = signal_config_reload_for_data_dir(&paths.root_data_dir);
    let out = json!({
        "ok": true,
        "group_id": &group.id,
        "action": action_norm,
        "added": added,
        "removed": removed,
        "member_count": group.member_node_ids.len(),
        "active_node_id": &group.active_node_id,
        "member_node_ids": &group.member_node_ids,
        "live_reload_signaled": live_reload_signaled,
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

pub(super) fn execute_group_policy(paths: &AppPaths, args: GroupPolicyArgs) -> Result<(Value, String)> {
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
    if let Some(indep) = args.independent_routing {
        group.independent_routing = indep;
    }
    db.upsert_multi_group(&group)?;
    drop(db);
    let live_reload_signaled = signal_config_reload_for_data_dir(&paths.root_data_dir);
    let out = json!({
        "ok": true,
        "group": group,
        "live_reload_signaled": live_reload_signaled,
    });
    Ok((
        out,
        format!("Updated policy for multi-group `{}`.", args.group_id),
    ))
}

pub(super) fn build_group_eval_payload(paths: &AppPaths, group_id: &str) -> Result<(Value, String)> {
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
