//! `status`, `docs`, and `update` handlers plus GeoData and effective TUN state helpers.

use anyhow::{Context, Result};
use catcloud_core::{AppPaths, agent_docs};
use catcloud_core::config;
use catcloud_core::core_adapter::{format_host_port, resolve_mihomo_binary};
use catcloud_core::models::AppConfig;
use catcloud_core::platform::default_platform;
use catcloud_core::preaccel::global_tunnel::locate_windivert_files;
use catcloud_core::process_guard::{
    ConfigReloadWaitOutcome, signal_portable_self_update_and_wait_outcome,
};
use catcloud_core::sanitize::{redact_path_for_display, sanitize_json_value, sanitize_log_line};
use catcloud_core::updater::{
    LatestManifest, MAX_METADATA_BYTES, MAX_ZIP_BYTES, PlatformAsset, StagedUpdateKind, Updater,
    current_update_platform_key_opt, is_update_available_for_channel, parse_latest_manifest,
    parse_sha256sums, read_pending_staged_update, resolve_asset_sha256, stage_verified_archive,
    verify_staged_payload_integrity,
};
use chrono::Utc;
use serde_json::{Value, json};
use std::path::Path;
use std::time::Duration;
use super::args::{AlreadyEmittedJsonError, DocsCommand, UpdateCommand};
use super::config_reload::{ActiveCorePortState, inspect_active_core_ports};
use super::net_logs::{evaluate_doctor_tun_state, probe_live_tun_connections};
use super::preaccel::collect_cli_preaccel_transport_snapshot;
use super::redact_helpers::{emit_output, open_storage, read_file_with_limit};

pub(super) async fn handle_status(paths: &AppPaths, as_json: bool) -> Result<()> {
    let (out, human) = build_status_payload(paths).await?;
    emit_output(as_json, &out, &human)
}

pub(super) fn handle_docs(as_json: bool, action: DocsCommand) -> Result<()> {
    match action {
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
    }
}

pub(super) async fn handle_update(paths: &AppPaths, as_json: bool, action: UpdateCommand) -> Result<()> {
    match action {
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
            from_version,
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
            let effective_from = from_version
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(env!("CARGO_PKG_VERSION"));
            let staged = stage_verified_archive(
                &zip_bytes,
                &expected,
                effective_from,
                &parsed_manifest.version,
                &paths.staging_dir,
            )?;
            let out = json!({ "ok": true, "staged": staged });
            emit_output(
                as_json,
                &out,
                &format!(
                    "Staged verified update v{} (ready to apply via `catcloud update apply --silent` or restart).",
                    parsed_manifest.version
                ),
            )
        }

        UpdateCommand::Apply {
            silent,
            timeout_secs,
        } => {
            let pending = verify_staged_payload_integrity(&paths.staging_dir)
                .context("staged update verification failed; stage a verified portable package first")?;
            if pending.kind != StagedUpdateKind::PortableZip {
                anyhow::bail!(
                    "staged update kind `{:?}` is not a PortableZip; in-place hot-swap only supports portable archives",
                    pending.kind
                );
            }
            let wait_dur = Duration::from_secs(timeout_secs.clamp(2, 60));
            let outcome = signal_portable_self_update_and_wait_outcome(
                &paths.root_data_dir,
                silent,
                wait_dur,
            );
            match outcome {
                ConfigReloadWaitOutcome::Ack(ack) if ack.applied && !ack.rejected => {
                    let out = json!({
                        "ok": true,
                        "applied": true,
                        "target_version": pending.target_version,
                        "silent": silent,
                        "ack": ack,
                    });
                    emit_output(
                        as_json,
                        &out,
                        &format!(
                            "Desktop accepted portable self-update to v{} (silent={}); swapping in place.",
                            pending.target_version, silent
                        ),
                    )
                }
                ConfigReloadWaitOutcome::Ack(ack) => {
                    let reason = ack
                        .error
                        .clone()
                        .unwrap_or_else(|| "desktop rejected portable self-update".to_string());
                    let out = json!({
                        "ok": false,
                        "applied": false,
                        "rejected": true,
                        "target_version": pending.target_version,
                        "error": reason,
                        "ack": ack,
                    });
                    if as_json {
                        emit_output(true, &out, "")?;
                        return Err(AlreadyEmittedJsonError(reason).into());
                    }
                    anyhow::bail!("portable self-update rejected by desktop: {reason}");
                }
                ConfigReloadWaitOutcome::NotRunning => {
                    let out = json!({
                        "ok": true,
                        "applied": false,
                        "status": "not_running",
                        "target_version": pending.target_version,
                    });
                    emit_output(
                        as_json,
                        &out,
                        &format!(
                            "No running desktop instance detected for this data dir; staged v{} will apply on next launch with --apply-staged-update.",
                            pending.target_version
                        ),
                    )
                }
                ConfigReloadWaitOutcome::TimedOut { req_id } => {
                    let msg = format!(
                        "timed out waiting for desktop self-update handoff ack (req_id={req_id})"
                    );
                    let out = json!({
                        "ok": false,
                        "applied": false,
                        "status": "timed_out",
                        "req_id": req_id,
                        "target_version": pending.target_version,
                        "error": msg,
                    });
                    if as_json {
                        emit_output(true, &out, "")?;
                        return Err(AlreadyEmittedJsonError(msg).into());
                    }
                    anyhow::bail!(msg);
                }
            }
        }
    }
}

pub(super) fn find_manifest_asset_for_stage<'a>(
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

pub(super) fn collect_geodata_status(runtime_dir: &std::path::Path) -> Value {
    json!({
        "country_mmdb": inspect_geodata_file(runtime_dir, &["Country.mmdb", "country.mmdb"]),
        "geoip_dat": inspect_geodata_file(runtime_dir, &["geoip.dat", "GeoIP.dat"]),
        "geosite_dat": inspect_geodata_file(runtime_dir, &["geosite.dat", "GeoSite.dat"]),
        "asn_mmdb": inspect_geodata_file(runtime_dir, &["GeoLite2-ASN.mmdb", "geolite2-asn.mmdb", "asn.mmdb"]),
    })
}

pub(super) async fn build_status_payload(paths: &AppPaths) -> Result<(Value, String)> {
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

pub(super) fn is_cli_tun_privilege_ready(
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

pub(super) async fn resolve_cli_effective_tun_state_with_probe(
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

pub(super) async fn resolve_cli_effective_tun_state(
    paths: &AppPaths,
    cfg: &AppConfig,
    caps: &catcloud_core::platform::PlatformCapabilities,
    mihomo_binary: Option<&Path>,
) -> (bool, bool, &'static str) {
    let active_ports = inspect_active_core_ports(paths, cfg).await;
    resolve_cli_effective_tun_state_with_probe(cfg, caps, mihomo_binary, &active_ports).await
}
