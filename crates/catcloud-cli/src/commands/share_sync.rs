//! `share` `.zip` bundle export/inspect/import and E2EE `.ccsync` send/receive handlers.

use anyhow::{Context, Result};
use catcloud_core::config;
use catcloud_core::core_adapter::compute_file_sha256;
use catcloud_core::models::{
    NodeFilter, PreAccelRelay, ProxyNode, SubscriptionKind, SubscriptionRecord,
};
use catcloud_core::process_guard::signal_config_reload_for_data_dir;
use catcloud_core::sanitize::{
    redact_node_for_readonly, redact_path_for_display, redact_relay_for_readonly,
    sanitize_log_line,
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
use catcloud_core::storage::SubscriptionUpdateMode;
use catcloud_core::subscription::migrator::generate_migration_subscription_id;
use catcloud_core::AppPaths;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;
use super::args::{ShareCommand, ShareExportArgs, ShareImportArgs, ShareReceiveArgs, ShareSendArgs};
use super::redact_helpers::{
    emit_output, open_storage, parse_csv_ids, parse_subscription_update_mode, read_file_with_limit,
    sanitize_multiline_text, sync_active_single_node_after_mutation,
};

pub(super) async fn handle_share(paths: &AppPaths, as_json: bool, action: ShareCommand) -> Result<()> {
    match action {
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
    }
}

pub(super) fn handle_share_export(paths: &AppPaths, as_json: bool, args: ShareExportArgs) -> Result<()> {
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

pub(super) fn build_share_inspect_payload(file: &Path, summary: bool) -> Result<(Value, String)> {
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

pub(super) fn handle_share_inspect(as_json: bool, file: &Path, summary: bool) -> Result<()> {
    let (out, human) = build_share_inspect_payload(file, summary)?;
    emit_output(as_json, &out, &human)
}

pub(super) fn execute_share_import(paths: &AppPaths, args: ShareImportArgs) -> Result<(Value, String)> {
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

    drop(db);
    let live_reload_signaled = signal_config_reload_for_data_dir(&paths.root_data_dir);

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
        "live_reload_signaled": live_reload_signaled,
    });
    let human = format!(
        "Imported share bundle `{}`: {} node(s), {} relay(s), {} group(s).",
        preview.manifest.name, imported_nodes_count, imported_relays_count, imported_groups_count
    );
    Ok((out, human))
}

pub(super) fn handle_share_import(paths: &AppPaths, as_json: bool, args: ShareImportArgs) -> Result<()> {
    let (out, human) = execute_share_import(paths, args)?;
    emit_output(as_json, &out, &human)
}

pub(super) fn build_cli_sync_export_zip(
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

pub(super) fn open_cli_ccsync_file(
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

pub(super) fn execute_share_send_ccsync(
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

pub(super) fn execute_share_receive_from_zip_bytes(
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

    drop(db);
    let live_reload_signaled = signal_config_reload_for_data_dir(&paths.root_data_dir);

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
        "live_reload_signaled": live_reload_signaled,
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
