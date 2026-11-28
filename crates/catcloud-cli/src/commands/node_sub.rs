//! `node` and `sub` subcommand handlers and subscription refresh logic.

use anyhow::{Context, Result};
use catcloud_core::config;
use catcloud_core::models::{NodeFilter, ProxyNode, SubscriptionKind, SubscriptionRecord};
use catcloud_core::process_guard::signal_config_reload_for_data_dir;
use catcloud_core::sanitize::{redact_node_for_readonly, redact_path_for_display, sanitize_log_line};
use catcloud_core::storage::Storage;
use catcloud_core::subscription::migrator::{
    MigrationDanglingRulePolicy, MigrationImportOptions, MigrationPreview,
    apply_migration_rules_for_subscription, generate_migration_subscription_id,
    import_migration_preview, merge_subscription_migrated_rules,
    remove_subscription_migrated_rules, scan_custom_path_readonly, scan_local_clients,
};
use catcloud_core::subscription::parser::{
    FetchOptions, apply_parsed_subscription, fetch_and_parse_subscription_with_fallback,
    parse_subscription_payload,
};
use catcloud_core::subscription::process_attach::{
    ProcessCandidate, inspect_process_source, list_process_candidates,
};
use catcloud_core::AppPaths;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use super::args::{AlreadyEmittedJsonError, NodeCommand, SubCommand};
use super::redact_helpers::{
    emit_output, open_storage, redact_migration_preview, redact_process_candidate,
    redact_process_inspection, redact_subscription_for_readonly,
    sync_active_single_node_after_mutation,
};

pub(super) async fn handle_node(paths: &AppPaths, as_json: bool, action: NodeCommand) -> Result<()> {
    match action {
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
            let _ = db.ensure_default_group_if_empty();
            drop(db);
            let live_reload_signaled = signal_config_reload_for_data_dir(&paths.root_data_dir);
            let out = json!({
                "ok": true,
                "sub_id": args.sub_id,
                "imported_nodes": count,
                "format": format!("{:?}", parsed.format),
                "live_reload_signaled": live_reload_signaled,
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
                let mut cfg = config::load_or_init(paths)?;
                let mut cfg_dirty = false;
                let mut reports = Vec::new();
                let mut total_saved_rules = 0usize;
                let mut total_dropped_dangling = 0usize;
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
                            &MigrationImportOptions::new(sub_id.clone(), sub_name),
                        )?;
                        let _ = db.ensure_default_group_if_empty()?;
                        if args.include_rules
                            && (!p.prepend_rules.is_empty() || !p.append_rules.is_empty())
                        {
                            let all_groups = db.list_multi_groups()?;
                            let all_nodes = db.list_nodes()?;
                            let rule_outcome = apply_migration_rules_for_subscription(
                                &mut cfg,
                                &sub_id,
                                &p.prepend_rules,
                                &p.append_rules,
                                &all_groups,
                                &all_nodes,
                                MigrationDanglingRulePolicy::Drop,
                            );
                            total_saved_rules +=
                                rule_outcome.added_prepend + rule_outcome.added_append;
                            total_dropped_dangling += rule_outcome.dropped_dangling_count;
                            if rule_outcome.added_prepend > 0 || rule_outcome.added_append > 0 {
                                cfg_dirty = true;
                            }
                        }
                        rep.warnings = rep
                            .warnings
                            .iter()
                            .map(|w| sanitize_log_line(w))
                            .collect();
                        reports.push(rep);
                    }
                }
                if cfg_dirty {
                    config::save(paths, &cfg)?;
                }
                drop(db);
                let live_reload_signaled = if !reports.is_empty() {
                    signal_config_reload_for_data_dir(&paths.root_data_dir)
                } else {
                    false
                };
                let out = json!({
                    "ok": true,
                    "sanitized": true,
                    "applied": true,
                    "reports": reports,
                    "saved_rules_count": total_saved_rules,
                    "dropped_dangling_rules_count": total_dropped_dangling,
                    "live_reload_signaled": live_reload_signaled,
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
    }
}

pub(super) async fn handle_sub(paths: &AppPaths, as_json: bool, action: SubCommand) -> Result<()> {
    match action {
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
                drop(db);
                let live_reload_signaled =
                    signal_config_reload_for_data_dir(&paths.root_data_dir);
                let out = json!({
                    "ok": true,
                    "sanitized": true,
                    "sub_id": sub.id,
                    "name": sub.name,
                    "imported_nodes": res.node_count,
                    "format": res.format,
                    "live_reload_signaled": live_reload_signaled,
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

                drop(db);
                let live_reload_signaled = if refreshed > 0 || failed > 0 {
                    signal_config_reload_for_data_dir(&paths.root_data_dir)
                } else {
                    false
                };
                let out = json!({
                    "ok": failed == 0,
                    "sanitized": true,
                    "total_enabled": enabled_subs.len(),
                    "refreshed": refreshed,
                    "skipped": skipped,
                    "failed": failed,
                    "results": results,
                    "live_reload_signaled": live_reload_signaled,
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
            let mut removed_rules = 0usize;
            if removed {
                let _ = sync_active_single_node_after_mutation(paths, &db, &HashMap::new())?;
                if let Ok(mut cfg) = config::load_or_init(paths) {
                    removed_rules = remove_subscription_migrated_rules(&mut cfg, &sub_id);
                    if removed_rules > 0 {
                        config::save(paths, &cfg)?;
                    }
                }
            }
            drop(db);
            let live_reload_signaled = if removed {
                signal_config_reload_for_data_dir(&paths.root_data_dir)
            } else {
                false
            };
            let out = json!({
                "ok": true,
                "sub_id": sub_id,
                "removed": removed,
                "removed_nodes": if removed { existing_nodes } else { 0 },
                "removed_rules": removed_rules,
                "live_reload_signaled": live_reload_signaled,
            });
            emit_output(
                as_json,
                &out,
                &format!(
                    "Subscription `{sub_id}` removed={removed} (nodes={}, rules={removed_rules}).",
                    if removed { existing_nodes } else { 0 }
                ),
            )
        }

        SubCommand::Rename { sub_id, name } => {
            let db = open_storage(paths)?;
            let updated = db.rename_subscription(&sub_id, &name)?;
            drop(db);
            let live_reload_signaled =
                signal_config_reload_for_data_dir(&paths.root_data_dir);
            let redacted = redact_subscription_for_readonly(&updated);
            let out = json!({
                "ok": true,
                "sanitized": true,
                "subscription": redacted,
                "live_reload_signaled": live_reload_signaled,
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
            if let Ok(mut cfg) = config::load_or_init(paths) {
                if merge_subscription_migrated_rules(&mut cfg, &source, &target) {
                    config::save(paths, &cfg)?;
                }
            }
            drop(db);
            let live_reload_signaled =
                signal_config_reload_for_data_dir(&paths.root_data_dir);
            let out = json!({
                "ok": true,
                "merge": report,
                "live_reload_signaled": live_reload_signaled,
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
    }
}

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
