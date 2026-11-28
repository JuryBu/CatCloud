use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
#[cfg(any(target_os = "linux", test))]
use std::time::Instant;
use catcloud_core::config;
use catcloud_core::core_adapter::CoreAdapter;
use catcloud_core::models::AppConfig;
use catcloud_core::platform::default_platform;
use catcloud_core::process_guard::ConfigReloadAck;
use catcloud_core::process_guard::write_config_reload_ack;
use catcloud_core::updater::Updater;
use chrono::Utc;
use serde::Deserialize;
use serde::Serialize;
use tauri::AppHandle;
use tauri::Emitter;
use tauri::Manager;
use tauri::State;
use crate::lifecycle;

use crate::commands::state::AppState;
use crate::commands::state::EVENT_CONFIG_UPDATED;
use crate::commands::state::UiAppConfigDto;
use crate::commands::state::current_unix_ms;
#[cfg(target_os = "windows")]
use crate::commands::state::open_directory_in_os;
use crate::commands::system_proxy::emergency_cleanup_on_exit;
use crate::commands::tray_runtime::emit_runtime_snapshot;
use crate::commands::tray_runtime::sync_tray_and_window_side_effects;

pub(in crate::commands) fn can_auto_stage_portable_update(is_portable_install: bool) -> bool {
    is_portable_install && cfg!(target_os = "windows")
}


fn derive_manifest_asset_filename(asset: &catcloud_core::updater::PlatformAsset) -> Option<String> {
    if let Some(name) = asset
        .filename
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return Some(name.to_string());
    }
    let without_query = asset
        .url
        .split(['?', '#'])
        .next()
        .unwrap_or(asset.url.as_str());
    let last_seg = without_query.rsplit('/').next()?.trim();
    if last_seg.is_empty() {
        None
    } else {
        Some(last_seg.to_string())
    }
}


fn manifest_asset_is_zip(asset: &catcloud_core::updater::PlatformAsset) -> bool {
    let candidate = asset
        .filename
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(asset.url.as_str());
    let without_query = candidate.split(['?', '#']).next().unwrap_or(candidate);
    without_query.to_ascii_lowercase().ends_with(".zip")
}


pub(in crate::commands) fn resolve_can_auto_stage_for_manifest(
    is_self_updatable_portable: bool,
    platform_key: Option<&str>,
    manifest: Option<&catcloud_core::updater::LatestManifest>,
) -> bool {
    let Some(key) = platform_key else {
        return false;
    };
    let Some(asset) = manifest.and_then(|m| m.platforms.get(key)) else {
        return false;
    };
    if is_self_updatable_portable {
        can_auto_stage_portable_update(true) && manifest_asset_is_zip(asset)
    } else {
        derive_manifest_asset_filename(asset)
            .is_some_and(|name| catcloud_core::updater::is_supported_installer_filename(&name))
    }
}


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingUpdatePromptDto {
    pub current_version: String,
    pub target_version: String,
    pub kind: String,
    pub apply_action: String,
    pub archive_sha256: String,
    pub package_size_bytes: u64,
    pub staged_at: String,
    pub release_notes: String,
    pub release_url: Option<String>,
    pub platform_key: Option<String>,
    pub installer_filename: Option<String>,
    pub dismissed_in_session: bool,
    #[serde(default)]
    pub silent_badge_only: bool,
    pub is_elevated: bool,
}


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SkipUpdateResultDto {
    pub skipped_version: String,
    pub purged_staged: bool,
    pub freed_bytes: u64,
    pub message: String,
}


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApplyUpdateRestartResultDto {
    pub started: bool,
    pub exiting: bool,
    pub cancelled: bool,
    pub kind: String,
    pub apply_action: String,
    pub target_version: String,
    pub message: String,
}


fn staged_update_kind_str(kind: catcloud_core::updater::StagedUpdateKind) -> &'static str {
    match kind {
        catcloud_core::updater::StagedUpdateKind::PortableZip => "portable_zip",
        catcloud_core::updater::StagedUpdateKind::InstallerPackage => "installer_package",
    }
}


fn expected_staged_kind_for_install(
    is_self_updatable_portable: bool,
) -> catcloud_core::updater::StagedUpdateKind {
    if is_self_updatable_portable {
        catcloud_core::updater::StagedUpdateKind::PortableZip
    } else {
        catcloud_core::updater::StagedUpdateKind::InstallerPackage
    }
}


fn extract_installer_filename(
    pending: &catcloud_core::updater::PendingUpdateMetadata,
) -> Option<String> {
    if pending.kind != catcloud_core::updater::StagedUpdateKind::InstallerPackage {
        return None;
    }
    let rel = pending.installer_rel_path.as_deref()?.trim();
    if rel.is_empty() {
        return None;
    }
    let normalized = rel.replace('\\', "/");
    let name = normalized.rsplit('/').next()?.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}


pub(in crate::commands) fn resolve_apply_action_for_os(
    kind: catcloud_core::updater::StagedUpdateKind,
    installer_filename: Option<&str>,
    target_os: &str,
) -> &'static str {
    match kind {
        catcloud_core::updater::StagedUpdateKind::PortableZip => "portable_restart",
        catcloud_core::updater::StagedUpdateKind::InstallerPackage => {
            let lower = installer_filename
                .map(str::trim)
                .unwrap_or("")
                .to_ascii_lowercase();
            let is_direct_installer = match target_os {
                "windows" => lower.ends_with(".exe") || lower.ends_with(".msi"),
                "macos" => lower.ends_with(".dmg"),
                _ => false,
            };
            if is_direct_installer {
                "installer_launch"
            } else {
                "reveal_archive"
            }
        }
    }
}


pub(in crate::commands) fn resolve_apply_action(
    kind: catcloud_core::updater::StagedUpdateKind,
    installer_filename: Option<&str>,
) -> &'static str {
    resolve_apply_action_for_os(kind, installer_filename, std::env::consts::OS)
}


#[cfg(test)]
pub(in crate::commands) fn resolve_staged_update_version(
    staging_dir: &std::path::Path,
    current_version: &str,
    include_prerelease: bool,
) -> Option<String> {
    if !staging_dir.exists() {
        return None;
    }
    let pending = catcloud_core::updater::verify_staged_payload_integrity(staging_dir).ok()?;
    if catcloud_core::updater::is_update_available_for_channel(
        &pending.target_version,
        current_version,
        include_prerelease,
    )
    .unwrap_or(false)
    {
        Some(pending.target_version)
    } else {
        None
    }
}


pub(in crate::commands) fn resolve_staged_update_version_checked(
    staging_dir: &std::path::Path,
    current_version: &str,
    include_prerelease: bool,
    skipped_version: Option<&str>,
    expected_kind: catcloud_core::updater::StagedUpdateKind,
) -> Option<String> {
    if !staging_dir.exists() {
        return None;
    }
    let pending = match catcloud_core::updater::verify_staged_payload_integrity(staging_dir) {
        Ok(meta) => meta,
        Err(err) => {
            tracing::warn!(
                staging_dir = %staging_dir.display(),
                "staged update failed integrity check during background probe; auto-purging: {err}"
            );
            let _ = catcloud_core::updater::purge_staged_update(staging_dir);
            return None;
        }
    };
    if pending.kind != expected_kind {
        tracing::info!(
            staged_kind = ?pending.kind,
            expected_kind = ?expected_kind,
            "staged update kind mismatch during background probe; auto-purging"
        );
        let _ = catcloud_core::updater::purge_staged_update(staging_dir);
        return None;
    }
    if catcloud_core::updater::is_version_skipped(&pending.target_version, skipped_version) {
        tracing::info!(
            staged = %pending.target_version,
            skipped = ?skipped_version,
            "staged update matches skipped version during background probe; auto-purging"
        );
        let _ = catcloud_core::updater::purge_staged_update(staging_dir);
        return None;
    }
    if catcloud_core::updater::is_update_available_for_channel(
        &pending.target_version,
        current_version,
        include_prerelease,
    )
    .unwrap_or(false)
    {
        Some(pending.target_version)
    } else {
        tracing::info!(
            current = %current_version,
            staged = %pending.target_version,
            "staged update is expired/not newer than current build; auto-purging"
        );
        let _ = catcloud_core::updater::purge_staged_update(staging_dir);
        None
    }
}


#[allow(clippy::too_many_arguments)]
pub(in crate::commands) fn inspect_and_reconcile_staged_update(
    staging_dir: &std::path::Path,
    current_version: &str,
    include_prerelease: bool,
    skipped_version: Option<&str>,
    expected_kind: catcloud_core::updater::StagedUpdateKind,
    dismissed_version: Option<&str>,
    default_release_repo: &str,
    is_elevated: bool,
) -> Option<PendingUpdatePromptDto> {
    if !staging_dir.exists() {
        return None;
    }
    let pending = match catcloud_core::updater::verify_staged_payload_integrity(staging_dir) {
        Ok(meta) => meta,
        Err(err) => {
            tracing::warn!(
                staging_dir = %staging_dir.display(),
                "staged update failed integrity verification, auto-purging: {err}"
            );
            let _ = catcloud_core::updater::purge_staged_update(staging_dir);
            return None;
        }
    };

    if pending.kind != expected_kind {
        tracing::info!(
            staged_kind = ?pending.kind,
            expected_kind = ?expected_kind,
            "staged update kind does not match current installation mode; auto-purging"
        );
        let _ = catcloud_core::updater::purge_staged_update(staging_dir);
        return None;
    }

    let is_newer = catcloud_core::updater::is_update_available_for_channel(
        &pending.target_version,
        current_version,
        include_prerelease,
    )
    .unwrap_or(false);
    if !is_newer {
        tracing::info!(
            current = %current_version,
            staged = %pending.target_version,
            "staged update is no longer newer than current build/channel; auto-purging"
        );
        let _ = catcloud_core::updater::purge_staged_update(staging_dir);
        return None;
    }

    if catcloud_core::updater::is_version_skipped(&pending.target_version, skipped_version) {
        tracing::info!(
            staged = %pending.target_version,
            skipped = ?skipped_version,
            "staged update matches skipped version; auto-purging"
        );
        let _ = catcloud_core::updater::purge_staged_update(staging_dir);
        return None;
    }

    let installer_filename = extract_installer_filename(&pending);
    let apply_action = resolve_apply_action(pending.kind, installer_filename.as_deref()).to_string();
    let package_size_bytes = if pending.package_size_bytes > 0 {
        pending.package_size_bytes
    } else {
        pending.files.iter().map(|f| f.size_bytes).sum()
    };
    let release_url = pending.release_url.or_else(|| {
        let repo_clean = default_release_repo.trim().trim_matches('/');
        if repo_clean.is_empty() {
            return None;
        }
        let candidate = format!("https://github.com/{repo_clean}/releases/latest");
        catcloud_core::updater::validate_https_url(&candidate)
            .ok()
            .map(|_| candidate)
    });
    let dismissed_in_session =
        catcloud_core::updater::is_version_skipped(&pending.target_version, dismissed_version);

    Some(PendingUpdatePromptDto {
        current_version: current_version.to_string(),
        target_version: pending.target_version,
        kind: staged_update_kind_str(pending.kind).to_string(),
        apply_action,
        archive_sha256: pending.archive_sha256,
        package_size_bytes,
        staged_at: pending.staged_at,
        release_notes: pending.release_notes,
        release_url,
        platform_key: pending.platform_key,
        installer_filename,
        dismissed_in_session,
        silent_badge_only: false,
        is_elevated,
    })
}


pub(in crate::commands) async fn persist_last_update_check_time_core(state: &AppState, checked_at: &str) {
    let _cfg_guard = state.config_transition_lock.lock().await;
    let updated_cfg = if let Ok(mut guard) = state.config.write() {
        let mut next = (**guard).clone();
        next.update.last_checked_at = Some(checked_at.to_string());
        let arc_next = Arc::new(next);
        *guard = Arc::clone(&arc_next);
        arc_next
    } else {
        let mut fallback = state.clone_config();
        fallback.update.last_checked_at = Some(checked_at.to_string());
        Arc::new(fallback)
    };
    if let Err(err) = config::save(&state.paths, &updated_cfg) {
        tracing::warn!("failed to persist update last_checked_at: {err}");
    }
}


async fn persist_last_update_check_time(app: &AppHandle, state: &AppState, checked_at: &str) {
    persist_last_update_check_time_core(state, checked_at).await;
    emit_runtime_snapshot(app, state);
}


struct UpdateDownloadCancelGuard<'a> {
    slot: &'a Mutex<Option<tokio::sync::watch::Sender<bool>>>,
}

impl<'a> UpdateDownloadCancelGuard<'a> {
    fn register(
        slot: &'a Mutex<Option<tokio::sync::watch::Sender<bool>>>,
    ) -> (Self, tokio::sync::watch::Receiver<bool>) {
        let (tx, rx) = tokio::sync::watch::channel(false);
        if let Ok(mut guard) = slot.lock() {
            *guard = Some(tx);
        }
        (Self { slot }, rx)
    }
}


impl Drop for UpdateDownloadCancelGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.slot.lock() {
            *guard = None;
        }
    }
}


struct TempFileCleanupGuard(PathBuf);


impl Drop for TempFileCleanupGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}


struct ApplyInProgressGuard<'a> {
    flag: &'a AtomicBool,
    release_on_drop: bool,
}

impl<'a> ApplyInProgressGuard<'a> {
    fn acquire(flag: &'a AtomicBool) -> Result<Self, String> {
        if flag
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err("更新流程正在执行中，请勿重复点击".to_string());
        }
        Ok(Self {
            flag,
            release_on_drop: true,
        })
    }

    fn keep_locked(mut self) {
        self.release_on_drop = false;
    }
}


impl Drop for ApplyInProgressGuard<'_> {
    fn drop(&mut self) {
        if self.release_on_drop {
            self.flag.store(false, Ordering::SeqCst);
        }
    }
}


pub(in crate::commands) fn should_abort_stage_due_to_skip(
    silent_background: bool,
    target_version: &str,
    initial_skipped_version: Option<&str>,
    current_skipped_version: Option<&str>,
) -> bool {
    if !catcloud_core::updater::is_version_skipped(target_version, current_skipped_version) {
        return false;
    }
    if silent_background {
        return true;
    }
    // Manual download: only abort if `skipped_version` was concurrently modified after
    // the download started (meaning the user explicitly clicked Skip mid-download).
    current_skipped_version != initial_skipped_version
}


/// Clear a previously skipped version when a manual download commits that version.
/// Caller MUST hold `state.config_transition_lock` (and, during staging commit, also
/// `state.update_staging_lock` in `config_transition_lock -> update_staging_lock` order).
pub(in crate::commands) fn clear_skipped_for_manual_download_locked(
    state: &AppState,
    target_version: &str,
) -> Result<Option<AppConfig>, String> {
    if let Ok(mut dismissed_guard) = state.dismissed_update_prompt_version.write() {
        if catcloud_core::updater::is_version_skipped(target_version, dismissed_guard.as_deref()) {
            *dismissed_guard = None;
        }
    }
    let mut next_cfg = state.clone_config();
    if !catcloud_core::updater::is_version_skipped(
        target_version,
        next_cfg.update.skipped_version.as_deref(),
    ) {
        return Ok(None);
    }
    next_cfg.update.skipped_version = None;
    config::save(&state.paths, &next_cfg)
        .map_err(|e| format!("清除已跳过版本设置失败：{e}"))?;
    if let Ok(mut guard) = state.config.write() {
        *guard = Arc::new(next_cfg.clone());
    }
    state.bump_config_generation();
    if let Ok(mut dismissed_guard) = state.dismissed_update_prompt_version.write() {
        *dismissed_guard = None;
    }
    Ok(Some(next_cfg))
}


pub(in crate::commands) enum CommitStagedOutcome {
    Staged {
        metadata: catcloud_core::updater::PendingUpdateMetadata,
        cleared_config: Option<AppConfig>,
    },
    Skipped,
    ShuttingDown,
}


pub(in crate::commands) struct CommitStagedError {
    pub(in crate::commands) message: String,
    pub(in crate::commands) cleared_config: Option<AppConfig>,
}


pub(in crate::commands) async fn commit_staged_update_atomically<F>(
    state: &AppState,
    silent_background: bool,
    initial_skipped_version: Option<&str>,
    target_version: &str,
    stage_fn: F,
) -> Result<CommitStagedOutcome, CommitStagedError>
where
    F: FnOnce() -> Result<catcloud_core::updater::PendingUpdateMetadata, String> + Send + 'static,
{
    // Strictly follow global lock ordering:
    // `config_transition_lock` (manual mode only) -> `update_staging_lock`.
    let _cfg_guard = if silent_background {
        None
    } else {
        Some(state.config_transition_lock.lock().await)
    };
    let _staging_guard = state.update_staging_lock.lock().await;

    if state.shutting_down.load(Ordering::SeqCst) {
        return Ok(CommitStagedOutcome::ShuttingDown);
    }

    let current_skipped = state.snapshot_config().update.skipped_version.clone();
    if should_abort_stage_due_to_skip(
        silent_background,
        target_version,
        initial_skipped_version,
        current_skipped.as_deref(),
    ) {
        return Ok(CommitStagedOutcome::Skipped);
    }

    let cleared_config = if !silent_background {
        clear_skipped_for_manual_download_locked(state, target_version).map_err(|message| {
            CommitStagedError {
                message,
                cleared_config: None,
            }
        })?
    } else {
        None
    };

    let metadata = tokio::task::spawn_blocking(stage_fn)
        .await
        .map_err(|e| CommitStagedError {
            message: format!("写入校验更新包任务异常中止：{e}"),
            cleared_config: cleared_config.clone(),
        })?
        .map_err(|message| CommitStagedError {
            message,
            cleared_config: cleared_config.clone(),
        })?;

    Ok(CommitStagedOutcome::Staged {
        metadata,
        cleared_config,
    })
}


pub(in crate::commands) fn reconcile_check_result_staged_version(
    staged_version: Option<String>,
    final_skipped: bool,
    stage_branch_skipped: bool,
    final_skipped_version: Option<&str>,
) -> Option<String> {
    if final_skipped || stage_branch_skipped {
        return None;
    }
    staged_version
        .filter(|ver| !catcloud_core::updater::is_version_skipped(ver, final_skipped_version))
}


async fn resolve_expected_archive_sha256(
    updater: &Updater,
    manifest: &catcloud_core::updater::LatestManifest,
    asset: &catcloud_core::updater::PlatformAsset,
) -> Option<String> {
    if let Ok(inline_sha) = catcloud_core::updater::resolve_asset_sha256(asset, None) {
        return Some(inline_sha);
    }
    let sums_url = manifest
        .sha256sums_url
        .clone()
        .unwrap_or_else(|| updater.default_sha256sums_url());
    if catcloud_core::updater::validate_https_url(&sums_url).is_err() {
        return None;
    }
    let client = catcloud_core::updater::build_safe_http_client(
        catcloud_core::updater::METADATA_REQUEST_TIMEOUT,
    )
    .ok()?;
    let mut resp = client.get(&sums_url).send().await.ok()?;
    if catcloud_core::updater::validate_https_url(resp.url().as_str()).is_err()
        || !resp.status().is_success()
    {
        return None;
    }
    if resp
        .content_length()
        .is_some_and(|cl| cl > catcloud_core::updater::MAX_METADATA_BYTES as u64)
    {
        return None;
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await.ok()? {
        if buf.len().saturating_add(chunk.len()) > catcloud_core::updater::MAX_METADATA_BYTES {
            return None;
        }
        buf.extend_from_slice(&chunk);
    }
    let sums_text = String::from_utf8(buf).ok()?;
    let sums_map = catcloud_core::updater::parse_sha256sums(&sums_text).ok()?;
    catcloud_core::updater::resolve_asset_sha256(asset, Some(&sums_map)).ok()
}


/// Download, SHA256-verify, and stage an update archive or installer from an already-fetched manifest.
///
/// Lock discipline (global lock ordering: `update_download_lock` -> `config_transition_lock` -> `update_staging_lock`):
/// - Serializes downloads via `state.update_download_lock` ONLY.
/// - NEVER holds `state.config_transition_lock` or `state.update_staging_lock` during network I/O.
/// - Streams into `root_data_dir/.update_download.tmp` with live cancel listening, then acquires
///   `config_transition_lock` (manual mode only) -> `update_staging_lock` strictly for the atomic
///   skip-state check/clear + disk verification/commit step.
#[allow(clippy::too_many_arguments)]
async fn stage_update_from_manifest(
    app: &AppHandle,
    state: &AppState,
    updater: &Updater,
    res: &catcloud_core::updater::UpdateCheckResult,
    update_available: bool,
    is_portable_install: bool,
    platform_key: Option<&'static str>,
    release_url: &str,
    silent_background: bool,
) -> Result<serde_json::Value, String> {
    let _download_guard = state.update_download_lock.lock().await;
    let initial_skipped_version = state.snapshot_config().update.skipped_version.clone();

    let can_auto_stage =
        resolve_can_auto_stage_for_manifest(is_portable_install, platform_key, Some(&res.manifest));
    let download_url = platform_key
        .and_then(|key| res.manifest.platforms.get(key))
        .map(|asset| asset.url.clone());

    if !update_available {
        return Ok(serde_json::json!({
            "staged": false,
            "reused": false,
            "skipped": false,
            "already_latest": true,
            "can_auto_stage": can_auto_stage,
            "current_version": res.current_version,
            "latest_version": res.latest_version,
            "target_version": null,
            "archive_sha256": null,
            "platform_key": platform_key,
            "release_url": release_url,
            "download_url": download_url,
            "message": format!("当前已是最新版本 v{}", res.current_version),
        }));
    }

    let (Some(key), Some(asset)) = (
        platform_key,
        platform_key.and_then(|k| res.manifest.platforms.get(k)),
    ) else {
        let guide_msg = format!(
            "当前系统架构暂未提供自动预置更新包，请前往官方 Release 页面下载 v{} 安装包",
            res.latest_version
        );
        if !silent_background {
            state.log_app_event("info", "软件更新", &guide_msg);
        }
        return Ok(serde_json::json!({
            "staged": false,
            "reused": false,
            "skipped": false,
            "already_latest": false,
            "can_auto_stage": false,
            "current_version": res.current_version,
            "latest_version": res.latest_version,
            "target_version": res.latest_version,
            "archive_sha256": null,
            "platform_key": platform_key,
            "release_url": release_url,
            "download_url": download_url,
            "message": guide_msg,
        }));
    };

    if !can_auto_stage {
        let guide_msg = if is_portable_install {
            format!(
                "当前便携版清单未提供 ZIP 更新包，请前往官方 Release 页面下载 v{} 更新包",
                res.latest_version
            )
        } else {
            format!(
                "当前平台（{key}）清单暂未提供受支持的安装包格式，请前往官方 Release 页面下载 v{} 安装包",
                res.latest_version
            )
        };
        if !silent_background {
            state.log_app_event("info", "软件更新", &guide_msg);
        }
        return Ok(serde_json::json!({
            "staged": false,
            "reused": false,
            "skipped": false,
            "already_latest": false,
            "can_auto_stage": false,
            "current_version": res.current_version,
            "latest_version": res.latest_version,
            "target_version": res.latest_version,
            "archive_sha256": null,
            "platform_key": Some(key),
            "release_url": release_url,
            "download_url": download_url,
            "message": guide_msg,
        }));
    }

    if silent_background
        && catcloud_core::updater::is_version_skipped(
            &res.latest_version,
            state.snapshot_config().update.skipped_version.as_deref(),
        )
    {
        return Ok(serde_json::json!({
            "staged": false,
            "reused": false,
            "skipped": true,
            "already_latest": false,
            "can_auto_stage": true,
            "current_version": res.current_version,
            "latest_version": res.latest_version,
            "target_version": res.latest_version,
            "archive_sha256": null,
            "platform_key": Some(key),
            "release_url": release_url,
            "download_url": download_url,
            "message": format!("已跳过 v{}，不再后台预下载", res.latest_version),
        }));
    }

    let expected_sha = resolve_expected_archive_sha256(updater, &res.manifest, asset).await;
    let expected_kind = expected_staged_kind_for_install(is_portable_install);

    enum ExistingStageProbe {
        None,
        Reuse(catcloud_core::updater::PendingUpdateMetadata),
        PurgedMismatch(String),
        PurgedCorrupt(String),
    }

    let probe = {
        let _staging_guard = state.update_staging_lock.lock().await;
        let staging_dir = state.paths.staging_dir.clone();
        let latest_ver = res.latest_version.clone();
        let exp_sha = expected_sha.clone();
        tokio::task::spawn_blocking(move || {
            if !staging_dir.exists() {
                return ExistingStageProbe::None;
            }
            match catcloud_core::updater::verify_staged_payload_integrity(&staging_dir) {
                Ok(existing) => {
                    let kind_matches = existing.kind == expected_kind;
                    let version_matches = existing.target_version == latest_ver;
                    let sha_matches = exp_sha
                        .as_deref()
                        .is_some_and(|exp| existing.archive_sha256.eq_ignore_ascii_case(exp));
                    if kind_matches && version_matches && sha_matches {
                        ExistingStageProbe::Reuse(existing)
                    } else if !kind_matches || (version_matches && exp_sha.is_some() && !sha_matches)
                    {
                        let ver_label = existing.target_version.clone();
                        let _ = catcloud_core::updater::purge_staged_update(&staging_dir);
                        ExistingStageProbe::PurgedMismatch(ver_label)
                    } else {
                        ExistingStageProbe::None
                    }
                }
                Err(err) => {
                    let _ = catcloud_core::updater::purge_staged_update(&staging_dir);
                    ExistingStageProbe::PurgedCorrupt(err.to_string())
                }
            }
        })
        .await
        .unwrap_or(ExistingStageProbe::None)
    };

    match probe {
        ExistingStageProbe::Reuse(existing) => {
            if silent_background {
                if should_abort_stage_due_to_skip(
                    true,
                    &existing.target_version,
                    initial_skipped_version.as_deref(),
                    state.snapshot_config().update.skipped_version.as_deref(),
                ) {
                    return Ok(serde_json::json!({
                        "staged": false,
                        "reused": false,
                        "skipped": true,
                        "already_latest": false,
                        "can_auto_stage": true,
                        "current_version": res.current_version,
                        "latest_version": res.latest_version,
                        "target_version": existing.target_version,
                        "archive_sha256": null,
                        "platform_key": Some(key),
                        "release_url": release_url,
                        "download_url": download_url,
                        "message": format!("已跳过 v{}，不再后台预下载", existing.target_version),
                    }));
                }
            } else {
                let reuse_clear_outcome = {
                    let _cfg_guard = state.config_transition_lock.lock().await;
                    let _staging_guard = state.update_staging_lock.lock().await;
                    let current_skipped = state.snapshot_config().update.skipped_version.clone();
                    if should_abort_stage_due_to_skip(
                        false,
                        &existing.target_version,
                        initial_skipped_version.as_deref(),
                        current_skipped.as_deref(),
                    ) {
                        None
                    } else {
                        Some(clear_skipped_for_manual_download_locked(
                            state,
                            &existing.target_version,
                        )?)
                    }
                };
                match reuse_clear_outcome {
                    None => {
                        return Ok(serde_json::json!({
                            "staged": false,
                            "reused": false,
                            "skipped": true,
                            "already_latest": false,
                            "can_auto_stage": true,
                            "current_version": res.current_version,
                            "latest_version": res.latest_version,
                            "target_version": existing.target_version,
                            "archive_sha256": null,
                            "platform_key": Some(key),
                            "release_url": release_url,
                            "download_url": download_url,
                            "message": format!("已跳过 v{}，已取消复用更新包", existing.target_version),
                        }));
                    }
                    Some(Some(updated_cfg)) => {
                        let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&updated_cfg));
                        emit_runtime_snapshot(app, state);
                    }
                    Some(None) => {}
                }
            }
            let msg = format!(
                "v{} 更新包已在本地完成校验，可立即重启应用或启动安装更新",
                existing.target_version
            );
            if !silent_background {
                state.log_app_event("info", "软件更新", &msg);
            }
            return Ok(serde_json::json!({
                "staged": true,
                "reused": true,
                "skipped": false,
                "already_latest": false,
                "can_auto_stage": true,
                "current_version": res.current_version,
                "latest_version": res.latest_version,
                "target_version": existing.target_version,
                "archive_sha256": existing.archive_sha256,
                "platform_key": Some(key),
                "release_url": release_url,
                "download_url": download_url,
                "message": msg,
            }));
        }
        ExistingStageProbe::PurgedMismatch(ver_label) => {
            state.log_app_event(
                "warning",
                "软件更新",
                &format!(
                    "检测到本地预置的 v{ver_label} 更新包摘要或安装形态与最新清单不一致，已清理缓存并重新下载校验"
                ),
            );
        }
        ExistingStageProbe::PurgedCorrupt(err) => {
            state.log_app_event(
                "warning",
                "软件更新",
                &format!("检测到本地预置更新包损坏或缺失（{err}），已清理并重新下载"),
            );
        }
        ExistingStageProbe::None => {}
    }

    if state.shutting_down.load(Ordering::SeqCst) {
        return Err("应用正在退出，已取消更新包下载".to_string());
    }

    let pkg_label = if is_portable_install {
        "便携更新包"
    } else {
        "安装包"
    };
    state.log_app_event(
        "info",
        "软件更新",
        &format!(
            "{}下载并校验 v{} {pkg_label}（平台：{key}）",
            if silent_background { "后台自动" } else { "开始" },
            res.latest_version
        ),
    );

    let (cancel_guard, cancel_rx) =
        UpdateDownloadCancelGuard::register(&state.update_download_cancel);

    if should_abort_stage_due_to_skip(
        silent_background,
        &res.latest_version,
        initial_skipped_version.as_deref(),
        state.snapshot_config().update.skipped_version.as_deref(),
    ) {
        drop(cancel_guard);
        return Ok(serde_json::json!({
            "staged": false,
            "reused": false,
            "skipped": true,
            "already_latest": false,
            "can_auto_stage": true,
            "current_version": res.current_version,
            "latest_version": res.latest_version,
            "target_version": res.latest_version,
            "archive_sha256": null,
            "platform_key": Some(key),
            "release_url": release_url,
            "download_url": download_url,
            "message": format!("已跳过 v{}，已取消更新包下载", res.latest_version),
        }));
    }

    let temp_file_path = state.paths.root_data_dir.join(".update_download.tmp");
    let temp_cleanup = TempFileCleanupGuard(temp_file_path.clone());

    let downloaded = match updater
        .download_asset_to_temp_file(&res.manifest, key, &temp_file_path, Some(cancel_rx))
        .await
    {
        Ok(dl) => dl,
        Err(e) => {
            drop(cancel_guard);
            drop(temp_cleanup);
            if should_abort_stage_due_to_skip(
                silent_background,
                &res.latest_version,
                initial_skipped_version.as_deref(),
                state.snapshot_config().update.skipped_version.as_deref(),
            ) {
                return Ok(serde_json::json!({
                    "staged": false,
                    "reused": false,
                    "skipped": true,
                    "already_latest": false,
                    "can_auto_stage": true,
                    "current_version": res.current_version,
                    "latest_version": res.latest_version,
                    "target_version": res.latest_version,
                    "archive_sha256": null,
                    "platform_key": Some(key),
                    "release_url": release_url,
                    "download_url": download_url,
                    "message": format!("已跳过 v{}，已中止更新包下载", res.latest_version),
                }));
            }
            let err_msg = format!("下载或校验 v{} 更新包失败：{e}", res.latest_version);
            if !state.shutting_down.load(Ordering::SeqCst) {
                state.log_app_event(
                    if silent_background { "warning" } else { "error" },
                    "软件更新",
                    &err_msg,
                );
            }
            return Err(err_msg);
        }
    };
    drop(cancel_guard);

    let staging_dir = state.paths.staging_dir.clone();
    let temp_path_for_stage = temp_file_path.clone();
    let expected_sha_owned = downloaded.expected_sha256.clone();
    let filename_owned = downloaded.filename.clone();
    let current_ver_owned = res.current_version.clone();
    let target_ver_owned = downloaded.target_version.clone();
    let notes_owned = if res.notes.trim().is_empty() {
        downloaded.release_notes.clone()
    } else {
        res.notes.clone()
    };
    let release_url_owned = Some(release_url.to_string());
    let platform_key_owned = Some(key.to_string());

    let commit_outcome = commit_staged_update_atomically(
        state,
        silent_background,
        initial_skipped_version.as_deref(),
        &downloaded.target_version,
        move || {
            if is_portable_install {
                let zip_bytes = std::fs::read(&temp_path_for_stage)
                    .map_err(|e| format!("读取临时便携更新包失败：{e}"))?;
                catcloud_core::updater::stage_verified_archive_with_meta(
                    &zip_bytes,
                    &expected_sha_owned,
                    &current_ver_owned,
                    &target_ver_owned,
                    &notes_owned,
                    release_url_owned.as_deref(),
                    platform_key_owned.as_deref(),
                    &staging_dir,
                )
                .map_err(|e| e.to_string())
            } else {
                catcloud_core::updater::stage_verified_installer_file(
                    &temp_path_for_stage,
                    &expected_sha_owned,
                    &filename_owned,
                    &current_ver_owned,
                    &target_ver_owned,
                    &notes_owned,
                    release_url_owned.as_deref(),
                    platform_key_owned.as_deref(),
                    &staging_dir,
                )
                .map_err(|e| e.to_string())
            }
        },
    )
    .await;
    drop(temp_cleanup);

    let (staged, cleared_config) = match commit_outcome {
        Ok(CommitStagedOutcome::Staged {
            metadata,
            cleared_config,
        }) => (metadata, cleared_config),
        Ok(CommitStagedOutcome::Skipped) => {
            return Ok(serde_json::json!({
                "staged": false,
                "reused": false,
                "skipped": true,
                "already_latest": false,
                "can_auto_stage": true,
                "current_version": res.current_version,
                "latest_version": res.latest_version,
                "target_version": downloaded.target_version,
                "archive_sha256": null,
                "platform_key": Some(key),
                "release_url": release_url,
                "download_url": download_url,
                "message": format!("已跳过 v{}，已清理下载临时文件", downloaded.target_version),
            }));
        }
        Ok(CommitStagedOutcome::ShuttingDown) => {
            return Err("应用正在退出，已取消更新包写入".to_string());
        }
        Err(err) => {
            if let Some(updated_cfg) = err.cleared_config {
                let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&updated_cfg));
                emit_runtime_snapshot(app, state);
            }
            let err_msg = format!("写入或校验 v{} 更新包失败：{}", res.latest_version, err.message);
            state.log_app_event(
                if silent_background { "warning" } else { "error" },
                "软件更新",
                &err_msg,
            );
            return Err(err_msg);
        }
    };

    if let Some(updated_cfg) = cleared_config {
        let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&updated_cfg));
    }

    let short_sha: String = staged.archive_sha256.chars().take(12).collect();
    let ok_msg = format!(
        "已{}下载并完成 SHA256 校验 v{}（{short_sha}），可立即重启应用或启动安装更新",
        if silent_background { "在后台自动" } else { "" },
        staged.target_version
    );
    state.log_app_event("info", "软件更新", &ok_msg);
    emit_runtime_snapshot(app, state);

    Ok(serde_json::json!({
        "staged": true,
        "reused": false,
        "skipped": false,
        "already_latest": false,
        "can_auto_stage": true,
        "current_version": res.current_version,
        "latest_version": res.latest_version,
        "target_version": staged.target_version,
        "archive_sha256": staged.archive_sha256,
        "platform_key": Some(key),
        "release_url": release_url,
        "download_url": download_url,
        "message": ok_msg,
    }))
}


pub(crate) async fn check_and_optionally_stage_update_internal(
    app: &AppHandle,
    state: &AppState,
    allow_auto_stage: bool,
    is_background: bool,
) -> Result<serde_json::Value, String> {
    let cfg = state.snapshot_config();
    let current = env!("CARGO_PKG_VERSION").to_string();
    let checked_at = Utc::now().to_rfc3339();
    let repo_clean = cfg.update.repo.trim().trim_matches('/');
    let release_url = format!("https://github.com/{repo_clean}/releases/latest");
    let is_portable_install = state.paths.is_self_updatable_portable();
    let expected_kind = expected_staged_kind_for_install(is_portable_install);
    let platform_key = catcloud_core::updater::current_update_platform_key_opt(is_portable_install);

    let updater = Updater::new(cfg.update.repo.clone(), current.clone())
        .map_err(|e| e.to_string())?;
    match updater.check_latest(None).await {
        Ok(res) => {
            persist_last_update_check_time(app, state, &checked_at).await;

            let latest_cfg = state.snapshot_config();
            let skipped_version = latest_cfg.update.skipped_version.clone();
            let update_available = catcloud_core::updater::is_update_available_for_channel(
                &res.latest_version,
                &current,
                latest_cfg.update.include_prerelease,
            )
            .unwrap_or(false);
            let is_skipped = update_available
                && catcloud_core::updater::is_version_skipped(
                    &res.latest_version,
                    skipped_version.as_deref(),
                );
            let can_auto_stage = resolve_can_auto_stage_for_manifest(
                is_portable_install,
                platform_key,
                Some(&res.manifest),
            );
            let download_url = platform_key
                .and_then(|key| res.manifest.platforms.get(key))
                .map(|asset| asset.url.clone());

            let mut staged_version = if let Ok(_guard) = state.update_staging_lock.try_lock() {
                let staging_dir = state.paths.staging_dir.clone();
                let cur = current.clone();
                let inc_pre = latest_cfg.update.include_prerelease;
                let skipped = skipped_version.clone();
                tokio::task::spawn_blocking(move || {
                    resolve_staged_update_version_checked(
                        &staging_dir,
                        &cur,
                        inc_pre,
                        skipped.as_deref(),
                        expected_kind,
                    )
                })
                .await
                .ok()
                .flatten()
            } else {
                None
            };

            let mut auto_staged = false;
            let mut auto_stage_reused = false;
            let mut stage_reported_skipped = false;
            if allow_auto_stage && update_available && can_auto_stage && !is_skipped {
                if !state.shutting_down.load(Ordering::SeqCst) {
                    match stage_update_from_manifest(
                        app,
                        state,
                        &updater,
                        &res,
                        update_available,
                        is_portable_install,
                        platform_key,
                        &release_url,
                        is_background,
                    )
                    .await
                    {
                        Ok(stage_val) => {
                            if stage_val
                                .get("skipped")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false)
                            {
                                stage_reported_skipped = true;
                                staged_version = None;
                            } else if stage_val
                                .get("staged")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false)
                            {
                                auto_staged = true;
                                auto_stage_reused = stage_val
                                    .get("reused")
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false);
                                staged_version = stage_val
                                    .get("target_version")
                                    .and_then(|v| v.as_str())
                                    .map(str::to_string)
                                    .or(staged_version);
                            }
                        }
                        Err(err) => {
                            tracing::warn!("background auto-stage update failed: {err}");
                        }
                    }
                }
            }

            let final_skipped_version = state.snapshot_config().update.skipped_version.clone();
            let final_skipped = update_available
                && catcloud_core::updater::is_version_skipped(
                    &res.latest_version,
                    final_skipped_version.as_deref(),
                );
            let staged_version = reconcile_check_result_staged_version(
                staged_version,
                final_skipped,
                stage_reported_skipped,
                final_skipped_version.as_deref(),
            );

            Ok(serde_json::json!({
                "has_update": update_available,
                "skipped": final_skipped,
                "skipped_version": final_skipped_version,
                "current_version": res.current_version,
                "latest_version": res.latest_version,
                "release_url": release_url,
                "notes": res.notes,
                "checked_at": checked_at,
                "staged_version": staged_version,
                "platform_key": platform_key,
                "can_auto_stage": can_auto_stage,
                "download_url": download_url,
                "auto_staged": auto_staged,
                "auto_stage_reused": auto_stage_reused,
                "error": null
            }))
        }
        Err(err) => {
            let skipped_version = cfg.update.skipped_version.clone();
            let staged_version = if let Ok(_guard) = state.update_staging_lock.try_lock() {
                let staging_dir = state.paths.staging_dir.clone();
                let cur = current.clone();
                let inc_pre = cfg.update.include_prerelease;
                let skipped = skipped_version.clone();
                tokio::task::spawn_blocking(move || {
                    resolve_staged_update_version_checked(
                        &staging_dir,
                        &cur,
                        inc_pre,
                        skipped.as_deref(),
                        expected_kind,
                    )
                })
                .await
                .ok()
                .flatten()
            } else {
                None
            };
            Ok(serde_json::json!({
                "has_update": false,
                "skipped": false,
                "skipped_version": skipped_version,
                "current_version": current,
                "latest_version": current,
                "release_url": release_url,
                "notes": "",
                "checked_at": checked_at,
                "staged_version": staged_version,
                "platform_key": platform_key,
                "can_auto_stage": false,
                "download_url": null,
                "auto_staged": false,
                "auto_stage_reused": false,
                "error": err.to_string()
            }))
        }
    }
}


pub(crate) async fn download_and_stage_update_internal(
    app: &AppHandle,
    state: &AppState,
) -> Result<serde_json::Value, String> {
    if state.shutting_down.load(Ordering::SeqCst) {
        return Err("应用正在退出，已取消下载更新".to_string());
    }

    let cfg = state.snapshot_config();
    let current = env!("CARGO_PKG_VERSION").to_string();
    let checked_at = Utc::now().to_rfc3339();
    let repo_clean = cfg.update.repo.trim().trim_matches('/');
    let release_url = format!("https://github.com/{repo_clean}/releases/latest");
    let is_portable_install = state.paths.is_self_updatable_portable();
    let platform_key = catcloud_core::updater::current_update_platform_key_opt(is_portable_install);

    let updater = Updater::new(cfg.update.repo.clone(), current.clone())
        .map_err(|e| e.to_string())?;
    let res = updater.check_latest(None).await.map_err(|e| {
        let msg = format!("检查最新版本失败：{e}");
        state.log_app_event("warning", "软件更新", &msg);
        msg
    })?;

    persist_last_update_check_time(app, state, &checked_at).await;

    let latest_cfg = state.snapshot_config();
    let update_available = catcloud_core::updater::is_update_available_for_channel(
        &res.latest_version,
        &current,
        latest_cfg.update.include_prerelease,
    )
    .unwrap_or(false);

    stage_update_from_manifest(
        app,
        state,
        &updater,
        &res,
        update_available,
        is_portable_install,
        platform_key,
        &release_url,
        false,
    )
    .await
}


#[tauri::command]
pub async fn check_app_update(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    check_and_optionally_stage_update_internal(&app, &state, false, false).await
}


#[tauri::command]
pub async fn download_and_stage_update(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    download_and_stage_update_internal(&app, &state).await
}


pub(crate) async fn get_pending_staged_update_internal(
    state: &AppState,
) -> Result<Option<PendingUpdatePromptDto>, String> {
    let current_version = env!("CARGO_PKG_VERSION").to_string();
    let is_portable = state.paths.is_self_updatable_portable();
    let expected_kind = expected_staged_kind_for_install(is_portable);
    let staging_dir = state.paths.staging_dir.clone();
    let is_elevated = default_platform().capabilities().is_elevated;

    // Acquire `update_staging_lock` BEFORE reading config/dismissed state so this reader can
    // never observe a stale pre-clear `skipped_version` paired with a newly committed package.
    let _staging_guard = state.update_staging_lock.lock().await;
    let cfg = state.snapshot_config();
    let include_prerelease = cfg.update.include_prerelease;
    let skipped_version = cfg.update.skipped_version.clone();
    let default_repo = cfg.update.repo.clone();
    let dismissed_version = state
        .dismissed_update_prompt_version
        .read()
        .ok()
        .and_then(|g| g.clone());

    tokio::task::spawn_blocking(move || {
        inspect_and_reconcile_staged_update(
            &staging_dir,
            &current_version,
            include_prerelease,
            skipped_version.as_deref(),
            expected_kind,
            dismissed_version.as_deref(),
            &default_repo,
            is_elevated,
        )
    })
    .await
    .map_err(|e| format!("检查本地预下载更新包任务异常中止：{e}"))
}


#[tauri::command]
pub async fn get_pending_staged_update(
    state: State<'_, AppState>,
) -> Result<Option<PendingUpdatePromptDto>, String> {
    get_pending_staged_update_internal(&state).await
}


pub(in crate::commands) fn dismiss_update_prompt_for_session_state(
    state: &AppState,
    version: &str,
) -> Result<bool, String> {
    let norm = catcloud_core::updater::normalize_semver_version(version)
        .map_err(|e| format!("版本号格式无效：{e}"))?;
    let mut guard = state
        .dismissed_update_prompt_version
        .write()
        .unwrap_or_else(|e| e.into_inner());
    let should_update = match guard.as_deref() {
        Some(existing) => !catcloud_core::updater::is_version_skipped(&norm, Some(existing)),
        None => true,
    };
    if should_update {
        *guard = Some(norm);
    }
    Ok(true)
}


pub(crate) fn dismiss_update_prompt_for_session_internal(
    state: &AppState,
    version: &str,
) -> Result<bool, String> {
    dismiss_update_prompt_for_session_state(state, version)
}


#[tauri::command]
pub fn dismiss_update_prompt_for_session(
    state: State<'_, AppState>,
    version: String,
) -> Result<bool, String> {
    dismiss_update_prompt_for_session_state(&state, &version)
}


pub(in crate::commands) async fn skip_update_version_core(
    state: &AppState,
    version: &str,
) -> Result<(SkipUpdateResultDto, AppConfig), String> {
    let norm = catcloud_core::updater::normalize_semver_version(version)
        .map_err(|e| format!("版本号格式无效：{e}"))?;

    // 1. Cancel any in-flight update package download immediately.
    state.cancel_in_flight_update_download();

    // 2. Strictly follow global lock ordering: `config_transition_lock` -> `update_staging_lock`.
    let (next_cfg, purge_outcome) = {
        let _cfg_guard = state.config_transition_lock.lock().await;
        let mut next_cfg = state.clone_config();
        next_cfg.update.skipped_version = Some(norm.clone());
        config::save(&state.paths, &next_cfg)
            .map_err(|e| format!("保存跳过版本设置失败：{e}"))?;
        if let Ok(mut guard) = state.config.write() {
            *guard = Arc::new(next_cfg.clone());
        }
        state.bump_config_generation();

        let purge_outcome = {
            let _staging_guard = state.update_staging_lock.lock().await;
            let staging_dir = state.paths.staging_dir.clone();
            tokio::task::spawn_blocking(move || {
                catcloud_core::updater::purge_staged_update(&staging_dir)
            })
            .await
            .map_err(|e| format!("清理预下载更新包任务异常中止：{e}"))?
            .map_err(|e| format!("删除已预下载更新包失败：{e}"))?
        };

        if let Ok(mut dismissed_guard) = state.dismissed_update_prompt_version.write() {
            *dismissed_guard = None;
        }
        (next_cfg, purge_outcome)
    };

    let message = if purge_outcome.removed {
        let mb = (purge_outcome.freed_bytes as f64) / (1024.0 * 1024.0);
        format!("已跳过 v{norm}，并彻底删除已预下载更新包（释放 {mb:.1} MB 磁盘空间）")
    } else {
        format!("已跳过 v{norm}，此版本将不再自动预下载或弹窗提醒")
    };
    state.log_app_event("info", "软件更新", &message);

    Ok((
        SkipUpdateResultDto {
            skipped_version: norm,
            purged_staged: purge_outcome.removed,
            freed_bytes: purge_outcome.freed_bytes,
            message,
        },
        next_cfg,
    ))
}


#[tauri::command]
pub async fn skip_update_version(
    app: AppHandle,
    state: State<'_, AppState>,
    version: String,
) -> Result<SkipUpdateResultDto, String> {
    let (result, next_cfg) = skip_update_version_core(&state, &version).await?;
    let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&next_cfg));
    emit_runtime_snapshot(&app, &state);
    Ok(result)
}


pub(in crate::commands) async fn clear_skipped_update_version_core(state: &AppState) -> Result<AppConfig, String> {
    let (next_cfg, prev_skipped) = {
        let _cfg_guard = state.config_transition_lock.lock().await;
        let mut next_cfg = state.clone_config();
        let prev = next_cfg.update.skipped_version.take();
        config::save(&state.paths, &next_cfg)
            .map_err(|e| format!("取消跳过版本保存失败：{e}"))?;
        if let Ok(mut guard) = state.config.write() {
            *guard = Arc::new(next_cfg.clone());
        }
        state.bump_config_generation();
        if let Ok(mut dismissed_guard) = state.dismissed_update_prompt_version.write() {
            *dismissed_guard = None;
        }
        (next_cfg, prev)
    };

    if let Some(prev) = prev_skipped {
        state.log_app_event(
            "info",
            "软件更新",
            &format!("已取消跳过 v{prev}，后续将恢复该版本的更新提醒"),
        );
    }

    Ok(next_cfg)
}


#[tauri::command]
pub async fn clear_skipped_update_version(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let next_cfg = clear_skipped_update_version_core(&state).await?;
    let _ = app.emit(EVENT_CONFIG_UPDATED, UiAppConfigDto::from(&next_cfg));
    emit_runtime_snapshot(&app, &state);
    Ok(true)
}


pub(in crate::commands) fn collect_portable_update_relaunch_args(
    raw_args: &[std::ffi::OsString],
    silent_relaunch: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    for raw in raw_args {
        let s = raw.to_string_lossy();
        if matches!(
            s.as_ref(),
            "--silent"
                | "--silent-relaunch"
                | "--restarting"
                | "--post-update-cleanup"
                | "--apply-staged-update"
                | "--enable-tun"
                | "--enable-global-preaccel"
                | "--shutdown-existing"
        ) {
            continue;
        }
        out.push(s.into_owned());
    }
    out.push("--apply-staged-update".to_string());
    out.push("--restarting".to_string());
    if silent_relaunch {
        out.push("--silent-relaunch".to_string());
    }
    out
}


/// Cross-process in-place portable update handoff triggered via `catcloud update apply`.
/// Verifies SHA-256 integrity, portable install kind, and anti-downgrade rules inside the
/// running process, then stops core and relaunches itself with `--apply-staged-update`
/// (inheriting elevated token with zero UAC prompt and optional `--silent-relaunch`).
pub(in crate::commands) async fn handle_cross_process_portable_self_update(
    app: &AppHandle,
    state: &AppState,
    req_id: String,
    silent_relaunch: bool,
) -> Result<ConfigReloadAck, String> {
    let persist_ack = |ack: &ConfigReloadAck| {
        if !ack.req_id.is_empty() {
            if let Err(err) = write_config_reload_ack(&state.paths.root_data_dir, ack) {
                tracing::warn!("写入跨进程自热切更新回执失败：{err}");
            }
        }
    };
    let reject = |msg: String| {
        let ack = ConfigReloadAck {
            req_id: req_id.clone(),
            applied: false,
            rejected: true,
            level: Some("portable_self_update_rejected".to_string()),
            error: Some(msg),
            completed_at_ms: current_unix_ms(),
        };
        persist_ack(&ack);
        Ok(ack)
    };

    if !state.paths.is_self_updatable_portable() {
        return reject("仅便携版支持原地静默自热切升级".to_string());
    }

    let apply_guard = match ApplyInProgressGuard::acquire(&state.update_apply_in_progress) {
        Ok(g) => g,
        Err(err) => return reject(err),
    };

    let current_version = env!("CARGO_PKG_VERSION").to_string();
    let include_prerelease = state.snapshot_config().update.include_prerelease;
    let staging_dir = state.paths.staging_dir.clone();

    let verified = {
        let _staging_guard = state.update_staging_lock.lock().await;
        tokio::task::spawn_blocking(
            move || -> Result<catcloud_core::updater::PendingUpdateMetadata, String> {
                if !staging_dir.exists() {
                    return Err("未找到已预下载的便携更新包".to_string());
                }
                let pending = catcloud_core::updater::verify_staged_payload_integrity(&staging_dir)
                    .map_err(|e| format!("便携更新包完整性校验未通过：{e}"))?;
                if pending.kind != catcloud_core::updater::StagedUpdateKind::PortableZip {
                    return Err("已暂存更新包不是便携版 ZIP，已拒绝原地热切".to_string());
                }
                if !catcloud_core::updater::is_update_available_for_channel(
                    &pending.target_version,
                    &current_version,
                    include_prerelease,
                )
                .unwrap_or(false)
                {
                    return Err(format!(
                        "暂存版本 v{} 不高于当前版本 v{}",
                        pending.target_version, current_version
                    ));
                }
                Ok(pending)
            },
        )
        .await
        .map_err(|e| format!("更新包校验任务异常中止：{e}"))
    };

    let pending = match verified {
        Ok(Ok(p)) => p,
        Ok(Err(err)) => return reject(err),
        Err(err) => return reject(err),
    };

    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(err) => return reject(format!("无法获取当前程序路径：{err}")),
    };
    let Some(app_root) = exe.parent().map(|p| p.to_path_buf()) else {
        return reject("无法定位当前程序所在目录".to_string());
    };
    let raw_args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let args = collect_portable_update_relaunch_args(&raw_args, silent_relaunch);

    let app_cleanup = app.clone();
    let _ = tokio::task::spawn_blocking(move || {
        if let Some(st) = app_cleanup.try_state::<AppState>() {
            emergency_cleanup_on_exit(&st);
            let _ = st.job_guard.terminate_all();
        }
    })
    .await;

    let exe_clone = exe.clone();
    let app_root_clone = app_root.clone();
    let spawn_res = tokio::task::spawn_blocking(move || {
        catcloud_core::process_guard::spawn_detached_self(&exe_clone, &args, &app_root_clone)
    })
    .await
    .map_err(|e| format!("拉起重启更新进程任务异常中止：{e}"))
    .and_then(|r| r.map_err(|e| format!("拉起重启更新进程失败：{e}")));

    if let Err(err) = spawn_res {
        state.shutting_down.store(false, Ordering::SeqCst);
        state.exit_cleanup_done.store(false, Ordering::SeqCst);
        let latest_status = state.adapter.status().await;
        state.update_cached_runtime(latest_status);
        let latest_cfg = state.snapshot_config();
        emit_runtime_snapshot(app, state);
        sync_tray_and_window_side_effects(app, state, &latest_cfg);
        return reject(format!("{err}；核心已停止，请重试更新或手动重连"));
    }

    let msg = format!(
        "收到跨进程自热切指令：已拉起 v{} 便携更新换轨进程（静默：{}），应用即将退出并无缝重启",
        pending.target_version, silent_relaunch
    );
    state.log_app_event("info", "软件更新", &msg);

    let ack = ConfigReloadAck {
        req_id,
        applied: true,
        rejected: false,
        level: Some("portable_self_update_relaunch".to_string()),
        error: None,
        completed_at_ms: current_unix_ms(),
    };
    persist_ack(&ack);

    apply_guard.keep_locked();
    let app_exit = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        lifecycle::request_graceful_exit(&app_exit);
    });

    Ok(ack)
}


#[cfg(any(target_os = "linux", test))]
pub(in crate::commands) fn reap_or_detach_child_with_grace(
    mut child: std::process::Child,
    grace: Duration,
    fail_prefix: &str,
) -> Result<(), String> {
    let deadline = Instant::now() + grace;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    return Ok(());
                }
                let code_desc = status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "信号中止".to_string());
                return Err(format!("{fail_prefix}（退出码：{code_desc}）"));
            }
            Ok(None) => {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                let remaining = deadline.saturating_duration_since(now);
                std::thread::sleep(remaining.min(Duration::from_millis(25)));
            }
            Err(err) => {
                return Err(format!("{fail_prefix}（检查进程状态失败：{err}）"));
            }
        }
    }
    // Hand still-running child ownership to a background reaper thread so it never becomes
    // a `<defunct>` zombie process on Linux.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}


#[tauri::command]
pub async fn apply_staged_update_and_restart(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<ApplyUpdateRestartResultDto, String> {
    let apply_guard = ApplyInProgressGuard::acquire(&state.update_apply_in_progress)?;

    let is_portable = state.paths.is_self_updatable_portable();
    let expected_kind = expected_staged_kind_for_install(is_portable);
    let current_version = env!("CARGO_PKG_VERSION").to_string();
    let include_prerelease = state.snapshot_config().update.include_prerelease;
    let staging_dir = state.paths.staging_dir.clone();

    // Perform full SHA-256 + anti-downgrade + install-kind re-verification under a short
    // `update_staging_lock` BEFORE launching anything; never hold the lock while spawning/exiting.
    let verified = {
        let _staging_guard = state.update_staging_lock.lock().await;
        tokio::task::spawn_blocking(
            move || -> Result<catcloud_core::updater::PendingUpdateMetadata, String> {
                if !staging_dir.exists() {
                    return Err("未找到已预下载的更新包，请先重新检查并下载更新".to_string());
                }
                let pending = catcloud_core::updater::verify_staged_payload_integrity(&staging_dir)
                    .map_err(|e| {
                        let _ = catcloud_core::updater::purge_staged_update(&staging_dir);
                        format!("本地预下载更新包完整性校验未通过，已自动清理，请重新下载：{e}")
                    })?;
                if pending.kind != expected_kind {
                    let _ = catcloud_core::updater::purge_staged_update(&staging_dir);
                    return Err(
                        "本地预下载更新包与当前安装形态不匹配，已自动清理，请重新下载"
                            .to_string(),
                    );
                }
                if !catcloud_core::updater::is_update_available_for_channel(
                    &pending.target_version,
                    &current_version,
                    include_prerelease,
                )
                .unwrap_or(false)
                {
                    let _ = catcloud_core::updater::purge_staged_update(&staging_dir);
                    return Err(format!(
                        "预下载版本 v{} 不高于当前版本 v{}，已自动清理",
                        pending.target_version, current_version
                    ));
                }
                Ok(pending)
            },
        )
        .await
        .map_err(|e| format!("更新包二次校验任务异常中止：{e}"))??
    };

    let kind_str = staged_update_kind_str(verified.kind).to_string();
    let installer_filename = extract_installer_filename(&verified);
    let apply_action =
        resolve_apply_action(verified.kind, installer_filename.as_deref()).to_string();
    let target_version = verified.target_version.clone();

    match verified.kind {
        catcloud_core::updater::StagedUpdateKind::PortableZip => {
            let exe = std::env::current_exe()
                .map_err(|e| format!("无法获取当前程序路径：{e}"))?;
            let app_root = exe
                .parent()
                .map(|p| p.to_path_buf())
                .ok_or_else(|| "无法定位当前程序所在目录".to_string())?;
            let raw_args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
            let args = collect_portable_update_relaunch_args(&raw_args, false);

            // Track A (PortableZip, no UAC): synchronously stop core/TUN/WinDivert, clear owned
            // OS proxy, and release child process file locks BEFORE spawning the swapper binary.
            let app_cleanup = app.clone();
            let _ = tokio::task::spawn_blocking(move || {
                if let Some(st) = app_cleanup.try_state::<AppState>() {
                    emergency_cleanup_on_exit(&st);
                    let _ = st.job_guard.terminate_all();
                }
            })
            .await;

            let exe_clone = exe.clone();
            let app_root_clone = app_root.clone();
            let spawn_res = tokio::task::spawn_blocking(move || {
                catcloud_core::process_guard::spawn_detached_self(
                    &exe_clone,
                    &args,
                    &app_root_clone,
                )
            })
            .await
            .map_err(|e| format!("拉起重启更新进程任务异常中止：{e}"))
            .and_then(|r| r.map_err(|e| format!("拉起重启更新进程失败：{e}")));
            if let Err(err) = spawn_res {
                // Restore exit flags so user can retry or exit normally without getting stuck.
                state.shutting_down.store(false, Ordering::SeqCst);
                state.exit_cleanup_done.store(false, Ordering::SeqCst);
                let latest_status = state.adapter.status().await;
                state.update_cached_runtime(latest_status);
                let latest_cfg = state.snapshot_config();
                emit_runtime_snapshot(&app, &state);
                sync_tray_and_window_side_effects(&app, &state, &latest_cfg);
                return Err(format!("{err}；核心已停止，请重试更新或手动重连"));
            }

            let msg = format!("已拉起 v{target_version} 便携更新换轨进程，应用即将优雅退出并重启");
            state.log_app_event("info", "软件更新", &msg);

            apply_guard.keep_locked();
            let app_exit = app.clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(Duration::from_millis(80)).await;
                lifecycle::request_graceful_exit(&app_exit);
            });

            Ok(ApplyUpdateRestartResultDto {
                started: true,
                exiting: true,
                cancelled: false,
                kind: kind_str,
                apply_action,
                target_version,
                message: msg,
            })
        }
        catcloud_core::updater::StagedUpdateKind::InstallerPackage => {
            let rel = verified
                .installer_rel_path
                .as_deref()
                .ok_or_else(|| "安装包元数据缺少安装文件路径".to_string())?;
            let mut installer_path = state.paths.staging_dir.clone();
            for seg in rel.replace('\\', "/").split('/') {
                if !seg.is_empty() {
                    installer_path.push(seg);
                }
            }
            if !installer_path.is_file() {
                return Err(format!(
                    "预下载的安装包文件不存在：{}",
                    installer_path.display()
                ));
            }

            #[cfg(target_os = "windows")]
            {
                if apply_action == "installer_launch" {
                    // Track B (Windows InstallerPackage): launch installer FIRST so UAC
                    // cancellation causes 0 network disruption and immediately releases
                    // `update_apply_in_progress`.
                    let path_for_launch = installer_path.clone();
                    let launched = tokio::task::spawn_blocking(move || {
                        catcloud_core::process_guard::launch_windows_installer(&path_for_launch)
                    })
                    .await
                    .map_err(|e| format!("启动安装向导任务异常中止：{e}"))?
                    .map_err(|e| format!("启动安装包失败：{e}"))?;

                    if !launched {
                        let msg = "已取消安装向导授权，当前代理与连接未受影响".to_string();
                        state.log_app_event("info", "软件更新", &msg);
                        return Ok(ApplyUpdateRestartResultDto {
                            started: false,
                            exiting: false,
                            cancelled: true,
                            kind: kind_str,
                            apply_action,
                            target_version,
                            message: msg,
                        });
                    }

                    // UAC approved and installer is running: synchronously stop core/TUN/proxy and
                    // release child locks immediately before exiting cleanly.
                    let app_cleanup = app.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        if let Some(st) = app_cleanup.try_state::<AppState>() {
                            emergency_cleanup_on_exit(&st);
                            let _ = st.job_guard.terminate_all();
                        }
                    })
                    .await;

                    let msg = format!(
                        "已启动 v{target_version} 安装向导，应用即将优雅退出以释放程序文件"
                    );
                    state.log_app_event("info", "软件更新", &msg);

                    apply_guard.keep_locked();
                    let app_exit = app.clone();
                    tauri::async_runtime::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(80)).await;
                        lifecycle::request_graceful_exit(&app_exit);
                    });

                    Ok(ApplyUpdateRestartResultDto {
                        started: true,
                        exiting: true,
                        cancelled: false,
                        kind: kind_str,
                        apply_action,
                        target_version,
                        message: msg,
                    })
                } else {
                    let parent_dir = installer_path
                        .parent()
                        .unwrap_or(state.paths.staging_dir.as_path());
                    open_directory_in_os(parent_dir)?;
                    let msg = format!("已打开 v{target_version} 更新包所在目录，请手动运行安装");
                    state.log_app_event("info", "软件更新", &msg);
                    Ok(ApplyUpdateRestartResultDto {
                        started: true,
                        exiting: false,
                        cancelled: false,
                        kind: kind_str,
                        apply_action,
                        target_version,
                        message: msg,
                    })
                }
            }

            #[cfg(target_os = "macos")]
            {
                let launch_installer = apply_action == "installer_launch";
                let path_for_open = installer_path.clone();
                let status = tokio::task::spawn_blocking(move || {
                    let mut cmd = std::process::Command::new("open");
                    if !launch_installer {
                        cmd.arg("-R");
                    }
                    cmd.arg(&path_for_open)
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status()
                })
                .await
                .map_err(|e| {
                    if launch_installer {
                        format!("打开 macOS 安装镜像任务异常中止：{e}")
                    } else {
                        format!("在 Finder 中显示更新包任务异常中止：{e}")
                    }
                })?
                .map_err(|e| {
                    if launch_installer {
                        format!("打开 macOS 安装镜像失败：{e}")
                    } else {
                        format!("在 Finder 中显示更新包失败：{e}")
                    }
                })?;

                if !status.success() {
                    let code_desc = status
                        .code()
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "信号中止".to_string());
                    return Err(if launch_installer {
                        format!("打开 macOS 安装镜像失败（退出码：{code_desc}）")
                    } else {
                        format!("在 Finder 中显示更新包失败（退出码：{code_desc}）")
                    });
                }

                let msg = if launch_installer {
                    format!(
                        "已打开 v{target_version} 安装镜像，请将应用拖入「应用程序」目录完成更新"
                    )
                } else {
                    format!("已在 Finder 中定位 v{target_version} 更新包，请解压并替换应用")
                };
                state.log_app_event("info", "软件更新", &msg);
                Ok(ApplyUpdateRestartResultDto {
                    started: true,
                    exiting: false,
                    cancelled: false,
                    kind: kind_str,
                    apply_action,
                    target_version,
                    message: msg,
                })
            }

            #[cfg(target_os = "linux")]
            {
                let parent_dir = installer_path
                    .parent()
                    .unwrap_or(state.paths.staging_dir.as_path())
                    .to_path_buf();
                tokio::task::spawn_blocking(move || -> Result<(), String> {
                    let child = std::process::Command::new("xdg-open")
                        .arg(&parent_dir)
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .spawn()
                        .map_err(|e| format!("打开更新包目录失败：{e}"))?;
                    reap_or_detach_child_with_grace(
                        child,
                        Duration::from_millis(250),
                        "打开更新包目录失败",
                    )
                })
                .await
                .map_err(|e| format!("打开更新包目录任务异常中止：{e}"))??;

                let msg = format!(
                    "已打开 v{target_version} 安装包所在目录，请手动完成安装替换"
                );
                state.log_app_event("info", "软件更新", &msg);
                Ok(ApplyUpdateRestartResultDto {
                    started: true,
                    exiting: false,
                    cancelled: false,
                    kind: kind_str,
                    apply_action,
                    target_version,
                    message: msg,
                })
            }

            #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
            {
                let _ = (
                    &app,
                    &apply_guard,
                    &installer_path,
                    &kind_str,
                    &apply_action,
                    &target_version,
                );
                Err("当前平台暂不支持自动打开安装包，请前往官方下载页手动更新".to_string())
            }
        }
    }
}

