#[allow(unused_imports)]
use super::prelude::*;

#[test]
fn json_deep_merge_updates_nested_fields_without_clobbering_siblings() {
    let mut base = serde_json::json!({
        "dns": { "ipv6": false, "prefer_h3": false },
        "mixed_port": 7890
    });
    let patch = serde_json::json!({
        "dns": { "prefer_h3": true }
    });
    json_deep_merge(&mut base, &patch);
    assert_eq!(base["dns"]["ipv6"], false);
    assert_eq!(base["dns"]["prefer_h3"], true);
    assert_eq!(base["mixed_port"], 7890);
}

#[test]
fn redacted_backup_merge_preserves_local_secrets_and_skips_orphaned_placeholders() {
    let mut local_cfg = AppConfig::default();
    local_cfg.controller_secret = Some("real-secret-xyz".to_string());
    let mut incoming_cfg = AppConfig::default();
    incoming_cfg.controller_secret = Some("<REDACTED>".to_string());
    preserve_local_secrets_in_config(&local_cfg, &mut incoming_cfg);
    assert_eq!(
        incoming_cfg.controller_secret.as_deref(),
        Some("real-secret-xyz")
    );

    let existing_relay = PreAccelRelay {
        id: "r1".to_string(),
        server: "203.0.113.42".to_string(),
        password: "real-password".to_string(),
        ..Default::default()
    };
    let mut incoming_relay = PreAccelRelay {
        id: "r1".to_string(),
        server: "<REDACTED>".to_string(),
        password: "<REDACTED>".to_string(),
        ..Default::default()
    };
    assert!(merge_redacted_backup_relay(
        Some(&existing_relay),
        &mut incoming_relay
    ));
    assert_eq!(incoming_relay.server, "203.0.113.42");
    assert_eq!(incoming_relay.password, "real-password");

    let mut orphan_relay = PreAccelRelay {
        id: "r2".to_string(),
        server: "<REDACTED>".to_string(),
        password: "<REDACTED>".to_string(),
        ..Default::default()
    };
    assert!(!merge_redacted_backup_relay(None, &mut orphan_relay));
}

#[test]
fn collect_geodata_status_detects_present_and_missing_files() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_geo_test_{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&tmp).expect("mkdir tmp");
    // `country-lite.mmdb` alone must NEVER report a false-green `country_mmdb.exists == true`.
    std::fs::write(tmp.join("country-lite.mmdb"), b"legacy-lite-bytes")
        .expect("write legacy country-lite");
    let lite_only = collect_geodata_status(&tmp);
    assert_eq!(lite_only["country_mmdb"]["exists"], false);
    assert_eq!(lite_only["country_mmdb"]["size_bytes"], 0);

    std::fs::write(tmp.join("Country.mmdb"), b"mock-mmdb-bytes").expect("write mmdb");
    std::fs::write(tmp.join("geosite.dat"), b"mock-geosite").expect("write geosite");

    let status = collect_geodata_status(&tmp);
    assert_eq!(status["country_mmdb"]["exists"], true);
    assert_eq!(status["country_mmdb"]["size_bytes"], 15);
    assert!(status["country_mmdb"]["updated_at"].is_string());
    assert_eq!(status["geosite_dat"]["exists"], true);
    assert_eq!(status["geoip_dat"]["exists"], false);
    assert_eq!(status["asn_mmdb"]["exists"], false);

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn update_platform_keys_and_staging_status_helpers_align() {
    assert_eq!(
        catcloud_core::updater::update_platform_key_for("windows", "x86_64", true),
        "windows-x86_64-portable"
    );
    assert_eq!(
        catcloud_core::updater::update_platform_key_for("windows", "x86_64", false),
        "windows-x86_64"
    );
    assert_eq!(
        catcloud_core::updater::update_platform_key_for("windows", "aarch64", true),
        "windows-aarch64-portable"
    );
    assert_eq!(
        catcloud_core::updater::update_platform_key_for("windows", "aarch64", false),
        "windows-aarch64"
    );
    assert_eq!(
        catcloud_core::updater::update_platform_key_for("macos", "aarch64", false),
        "darwin-aarch64"
    );
    assert_eq!(
        catcloud_core::updater::update_platform_key_for("macos", "x86_64", false),
        "darwin-x86_64"
    );
    assert_eq!(
        catcloud_core::updater::update_platform_key_for("linux", "x86_64", false),
        "linux-x86_64"
    );

    assert_eq!(
        can_auto_stage_portable_update(true),
        cfg!(target_os = "windows")
    );
    assert!(!can_auto_stage_portable_update(false));

    let current_portable_key = catcloud_core::updater::current_update_platform_key_opt(true);
    let current_standard_key = catcloud_core::updater::current_update_platform_key_opt(false);
    if cfg!(target_os = "windows") {
        assert!(current_portable_key.is_some_and(|k| k.ends_with("-portable")));
        assert!(current_standard_key.is_some_and(|k| !k.ends_with("-portable")));
    } else {
        assert_eq!(current_portable_key, current_standard_key);
    }

    // Verify unified `can_auto_stage` rules across portable ZIP and all-platform installers.
    let mut platforms = HashMap::new();
    platforms.insert(
        "windows-x86_64-portable".to_string(),
        catcloud_core::updater::PlatformAsset {
            url: "https://github.com/JuryBu/CatCloud/releases/download/v0.2.0/CatCloud-portable.zip"
                .to_string(),
            signature: None,
            sha256: Some("a".repeat(64)),
            filename: Some("CatCloud-portable.zip".to_string()),
        },
    );
    platforms.insert(
        "windows-x86_64".to_string(),
        catcloud_core::updater::PlatformAsset {
            url: "https://github.com/JuryBu/CatCloud/releases/download/v0.2.0/CatCloud-setup.exe"
                .to_string(),
            signature: None,
            sha256: Some("b".repeat(64)),
            filename: Some("CatCloud-setup.exe".to_string()),
        },
    );
    platforms.insert(
        "darwin-aarch64".to_string(),
        catcloud_core::updater::PlatformAsset {
            url: "https://github.com/JuryBu/CatCloud/releases/download/v0.2.0/CatCloud_0.2.0_aarch64.dmg"
                .to_string(),
            signature: None,
            sha256: Some("c".repeat(64)),
            filename: None,
        },
    );
    platforms.insert(
        "linux-x86_64".to_string(),
        catcloud_core::updater::PlatformAsset {
            url: "https://github.com/JuryBu/CatCloud/releases/download/v0.2.0/CatCloud_0.2.0_amd64.AppImage"
                .to_string(),
            signature: None,
            sha256: Some("d".repeat(64)),
            filename: Some("CatCloud_0.2.0_amd64.AppImage".to_string()),
        },
    );
    let manifest = catcloud_core::updater::LatestManifest {
        version: "0.2.0".to_string(),
        notes: String::new(),
        pub_date: None,
        sha256sums_url: None,
        platforms,
    };
    assert_eq!(
        resolve_can_auto_stage_for_manifest(
            true,
            Some("windows-x86_64-portable"),
            Some(&manifest)
        ),
        cfg!(target_os = "windows")
    );
    // Installer mode rejects portable `.zip` assets to prevent cross-mode confusion.
    assert!(!resolve_can_auto_stage_for_manifest(
        false,
        Some("windows-x86_64-portable"),
        Some(&manifest)
    ));
    // Installer mode enables pre-download on Windows (.exe/.msi), macOS (.dmg), and Linux (.AppImage).
    assert!(resolve_can_auto_stage_for_manifest(
        false,
        Some("windows-x86_64"),
        Some(&manifest)
    ));
    assert!(resolve_can_auto_stage_for_manifest(
        false,
        Some("darwin-aarch64"),
        Some(&manifest)
    ));
    assert!(resolve_can_auto_stage_for_manifest(
        false,
        Some("linux-x86_64"),
        Some(&manifest)
    ));
    // Portable mode rejects non-ZIP installer assets.
    assert!(!resolve_can_auto_stage_for_manifest(
        true,
        Some("windows-x86_64"),
        Some(&manifest)
    ));
    assert!(!resolve_can_auto_stage_for_manifest(
        true,
        None,
        Some(&manifest)
    ));
    assert!(!resolve_can_auto_stage_for_manifest(
        true,
        Some("windows-x86_64-portable"),
        None
    ));

    let tmp = std::env::temp_dir().join(format!(
        "catcloud_upd_helper_test_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let staging_dir = tmp.join(".update_staging");
    let payload_dir = staging_dir.join(catcloud_core::updater::STAGING_PAYLOAD_DIR);
    std::fs::create_dir_all(&payload_dir).expect("create staging payload dir");

    assert_eq!(
        resolve_staged_update_version(&staging_dir, "0.1.0", false),
        None
    );

    let version_payload = br#"{"version":"0.2.0"}"#;
    let version_sha = catcloud_core::updater::compute_sha256_hex(version_payload);
    std::fs::write(payload_dir.join("version.json"), version_payload)
        .expect("write staged payload file");

    let pending = catcloud_core::updater::PendingUpdateMetadata {
        from_version: "0.1.0".to_string(),
        target_version: "0.2.0".to_string(),
        archive_sha256: "a".repeat(64),
        staged_at: Utc::now().to_rfc3339(),
        files: vec![catcloud_core::updater::StagedFileEntry {
            rel_path: "version.json".to_string(),
            sha256: version_sha.clone(),
            size_bytes: version_payload.len() as u64,
        }],
        kind: catcloud_core::updater::StagedUpdateKind::PortableZip,
        installer_rel_path: None,
        release_notes: String::new(),
        release_url: None,
        platform_key: Some("windows-x86_64-portable".to_string()),
        package_size_bytes: version_payload.len() as u64,
    };
    let bytes = serde_json::to_vec_pretty(&pending).expect("serialize pending manifest");
    std::fs::write(
        staging_dir.join(catcloud_core::updater::PENDING_APPLY_MANIFEST),
        bytes,
    )
    .expect("write pending manifest");

    assert_eq!(
        resolve_staged_update_version(&staging_dir, "0.1.0", false).as_deref(),
        Some("0.2.0")
    );
    assert_eq!(
        resolve_staged_update_version(&staging_dir, "0.2.0", false),
        None
    );

    // Prerelease staged target is gated on `include_prerelease`.
    let pre_pending = catcloud_core::updater::PendingUpdateMetadata {
        target_version: "0.2.0-rc.1".to_string(),
        ..pending
    };
    std::fs::write(
        staging_dir.join(catcloud_core::updater::PENDING_APPLY_MANIFEST),
        serde_json::to_vec_pretty(&pre_pending).expect("serialize prerelease manifest"),
    )
    .expect("write prerelease manifest");
    assert_eq!(
        resolve_staged_update_version(&staging_dir, "0.1.0", false),
        None
    );
    assert_eq!(
        resolve_staged_update_version(&staging_dir, "0.1.0", true).as_deref(),
        Some("0.2.0-rc.1")
    );

    // Tampering with staged payload must fail integrity verification and return None.
    std::fs::write(payload_dir.join("version.json"), b"CORRUPTED_BYTES")
        .expect("corrupt staged payload");
    assert_eq!(
        resolve_staged_update_version(&staging_dir, "0.1.0", true),
        None
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn ui_update_dto_roundtrips_auto_download_and_preserves_legacy_none() {
    let mut cfg = AppConfig::default();
    cfg.update.auto_download = false;
    cfg.update.include_prerelease = true;
    cfg.update.check_interval_min = 120;
    cfg.update.mode = UpdateApplyMode::Manual;

    let dto = UiAppConfigDto::from(&cfg);
    assert_eq!(dto.update.auto_download, Some(false));
    assert!(dto.update.include_prerelease);
    assert_eq!(dto.update.check_interval_min, 120);
    assert_eq!(dto.update.mode, UpdateApplyMode::Manual);

    let mut target = AppConfig::default();
    assert!(target.update.auto_download);
    apply_ui_dto(&mut target, &dto);
    assert!(!target.update.auto_download);
    assert!(target.update.include_prerelease);
    assert_eq!(target.update.check_interval_min, 120);
    assert_eq!(target.update.mode, UpdateApplyMode::Manual);

    let mut enable_dto = dto.clone();
    enable_dto.update.auto_download = Some(true);
    apply_ui_dto(&mut target, &enable_dto);
    assert!(target.update.auto_download);

    // Legacy payload omitting `auto_download` deserializes as `None` and preserves current value.
    let mut raw_val = serde_json::to_value(&dto).expect("serialize dto");
    raw_val["update"]
        .as_object_mut()
        .expect("update object")
        .remove("auto_download");
    let legacy_dto: UiAppConfigDto =
        serde_json::from_value(raw_val).expect("deserialize legacy dto without auto_download");
    assert_eq!(legacy_dto.update.auto_download, None);

    target.update.auto_download = true;
    apply_ui_dto(&mut target, &legacy_dto);
    assert!(target.update.auto_download);

    target.update.auto_download = false;
    apply_ui_dto(&mut target, &legacy_dto);
    assert!(!target.update.auto_download);
}

#[test]
fn stage20_collect_portable_update_relaunch_args_strips_transient_flags_and_preserves_data_dir() {
    use std::ffi::OsString;

    let raw = vec![
        OsString::from("--data-dir"),
        OsString::from(r"E:\CatCloud\data"),
        OsString::from("--silent"),
        OsString::from("--restarting"),
        OsString::from("--post-update-cleanup"),
        OsString::from("--apply-staged-update"),
        OsString::from("--enable-tun"),
        OsString::from("--enable-global-preaccel"),
    ];
    assert_eq!(
        collect_portable_update_relaunch_args(&raw, false),
        vec![
            "--data-dir".to_string(),
            r"E:\CatCloud\data".to_string(),
            "--apply-staged-update".to_string(),
            "--restarting".to_string(),
        ]
    );
    assert_eq!(
        collect_portable_update_relaunch_args(&raw, true),
        vec![
            "--data-dir".to_string(),
            r"E:\CatCloud\data".to_string(),
            "--apply-staged-update".to_string(),
            "--restarting".to_string(),
            "--silent-relaunch".to_string(),
        ]
    );
}

#[test]
fn stage20_dismiss_skip_clear_and_reconcile_update_state_machine() {
    use catcloud_core::updater::{StagedUpdateKind, compute_sha256_hex, stage_verified_installer_file};

    let tmp = std::env::temp_dir().join(format!(
        "catcloud_s20_state_machine_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), false).expect("create temp AppPaths");
    let storage = Storage::open_in_memory().expect("open memory storage");
    let state = AppState::new(
        paths.clone(),
        AppConfig::default(),
        storage,
        Arc::new(JobGuard::new().expect("create JobGuard")),
    );

    let installer_bytes = b"fake-signed-catcloud-installer-payload-bytes";
    let installer_sha = compute_sha256_hex(installer_bytes);
    let temp_download = tmp.join(".tmp_installer.exe");
    std::fs::write(&temp_download, installer_bytes).expect("write temp installer");

    stage_verified_installer_file(
        &temp_download,
        &installer_sha,
        "CatCloud-0.2.0-windows-x64-setup.exe",
        "0.1.0",
        "0.2.0",
        "## What's New\n- Stage 20 update modal",
        Some("https://github.com/JuryBu/CatCloud/releases/tag/v0.2.0"),
        Some("windows-x86_64"),
        &paths.staging_dir,
    )
    .expect("stage verified installer");

    let prompt = inspect_and_reconcile_staged_update(
        &paths.staging_dir,
        "0.1.0",
        false,
        None,
        StagedUpdateKind::InstallerPackage,
        None,
        "JuryBu/CatCloud",
        false,
    )
    .expect("staged installer should produce pending prompt");
    assert_eq!(prompt.current_version, "0.1.0");
    assert_eq!(prompt.target_version, "0.2.0");
    assert_eq!(prompt.kind, "installer_package");
    assert_eq!(
        prompt.apply_action,
        if cfg!(target_os = "windows") {
            "installer_launch"
        } else {
            "reveal_archive"
        }
    );
    assert_eq!(
        prompt.installer_filename.as_deref(),
        Some("CatCloud-0.2.0-windows-x64-setup.exe")
    );
    assert_eq!(prompt.package_size_bytes, installer_bytes.len() as u64);
    assert!(prompt.release_notes.contains("Stage 20"));
    assert!(!prompt.dismissed_in_session);

    // Session dismiss rejects invalid versions and tracks `<=` semantics cleanly.
    assert!(dismiss_update_prompt_for_session_state(&state, "0.0.0").is_err());
    assert!(dismiss_update_prompt_for_session_state(&state, "not-semver").is_err());
    assert!(dismiss_update_prompt_for_session_state(&state, "v0.2.0").expect("dismiss v0.2.0"));
    let dismissed_ver = state
        .dismissed_update_prompt_version
        .read()
        .unwrap()
        .clone();
    assert_eq!(dismissed_ver.as_deref(), Some("0.2.0"));

    let prompt_dismissed = inspect_and_reconcile_staged_update(
        &paths.staging_dir,
        "0.1.0",
        false,
        None,
        StagedUpdateKind::InstallerPackage,
        dismissed_ver.as_deref(),
        "JuryBu/CatCloud",
        true,
    )
    .expect("staged installer remains ready after session dismiss");
    assert!(prompt_dismissed.dismissed_in_session);
    assert!(prompt_dismissed.is_elevated);

    // Register an active download cancel watcher, then skip `v0.2.0`:
    // must cancel download, persist `skipped_version`, purge staged files, and clear dismiss.
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    *state.update_download_cancel.lock().unwrap() = Some(cancel_tx);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    let (skip_res, saved_cfg) = rt
        .block_on(skip_update_version_core(&state, "v0.2.0"))
        .expect("skip_update_version_core succeeds");
    assert!(*cancel_rx.borrow(), "skip must trigger in-flight download cancel");
    assert_eq!(skip_res.skipped_version, "0.2.0");
    assert!(skip_res.purged_staged);
    assert!(skip_res.freed_bytes >= installer_bytes.len() as u64);
    assert!(!paths.staging_dir.exists(), "staging_dir must be purged");
    assert_eq!(saved_cfg.update.skipped_version.as_deref(), Some("0.2.0"));
    assert_eq!(
        state.snapshot_config().update.skipped_version.as_deref(),
        Some("0.2.0")
    );
    assert!(
        state
            .dismissed_update_prompt_version
            .read()
            .unwrap()
            .is_none()
    );
    let reloaded = config::load_or_init(&paths).expect("reload config.json");
    assert_eq!(reloaded.update.skipped_version.as_deref(), Some("0.2.0"));

    // Re-stage the same version: reconcile must auto-purge it because `skipped_version` covers 0.2.0.
    std::fs::write(&temp_download, installer_bytes).expect("rewrite temp installer");
    stage_verified_installer_file(
        &temp_download,
        &installer_sha,
        "CatCloud-0.2.0-windows-x64-setup.exe",
        "0.1.0",
        "0.2.0",
        "",
        None,
        Some("windows-x86_64"),
        &paths.staging_dir,
    )
    .expect("re-stage installer");
    assert!(
        inspect_and_reconcile_staged_update(
            &paths.staging_dir,
            "0.1.0",
            false,
            Some("0.2.0"),
            StagedUpdateKind::InstallerPackage,
            None,
            "JuryBu/CatCloud",
            false,
        )
        .is_none()
    );
    assert!(
        !paths.staging_dir.exists(),
        "reconcile must auto-purge staged package matching skipped_version"
    );

    // Re-stage again and verify kind mismatch also auto-purges.
    std::fs::write(&temp_download, installer_bytes)
        .expect("rewrite temp installer for kind mismatch check");
    stage_verified_installer_file(
        &temp_download,
        &installer_sha,
        "CatCloud-0.2.0-windows-x64-setup.exe",
        "0.1.0",
        "0.2.0",
        "",
        None,
        Some("windows-x86_64"),
        &paths.staging_dir,
    )
    .expect("re-stage installer for kind mismatch check");
    assert!(
        inspect_and_reconcile_staged_update(
            &paths.staging_dir,
            "0.1.0",
            false,
            None,
            StagedUpdateKind::PortableZip,
            None,
            "JuryBu/CatCloud",
            false,
        )
        .is_none()
    );
    assert!(!paths.staging_dir.exists());

    // Clear skipped version persists `None`.
    let cleared_cfg = rt
        .block_on(clear_skipped_update_version_core(&state))
        .expect("clear_skipped_update_version_core succeeds");
    assert_eq!(cleared_cfg.update.skipped_version, None);
    assert_eq!(state.snapshot_config().update.skipped_version, None);
    let reloaded_after_clear = config::load_or_init(&paths).expect("reload cleared config");
    assert_eq!(reloaded_after_clear.update.skipped_version, None);

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn stage21_persist_last_update_check_time_serializes_under_config_transition_lock() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_s21_persist_check_time_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), false).expect("create temp AppPaths");
    let storage = Storage::open_in_memory().expect("open memory storage");
    let state = Arc::new(AppState::new(
        paths.clone(),
        AppConfig::default(),
        storage,
        Arc::new(JobGuard::new().expect("create JobGuard")),
    ));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build tokio runtime");

    rt.block_on(async {
        let cfg_guard = state.config_transition_lock.lock().await;
        let state_writer = Arc::clone(&state);
        let check_time_task = tokio::spawn(async move {
            persist_last_update_check_time_core(&state_writer, "2026-11-27T04:00:00Z").await;
        });

        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(
            !check_time_task.is_finished(),
            "persist_last_update_check_time_core must wait for config_transition_lock"
        );
        let mut next_cfg = state.clone_config();
        next_cfg.update.skipped_version = Some("9.9.9".to_string());
        config::save(&state.paths, &next_cfg).expect("save skipped_version under lock");
        *state.config.write().unwrap() = Arc::new(next_cfg);
        drop(cfg_guard);

        check_time_task
            .await
            .expect("join persist_last_update_check_time_core");

        let mem_cfg = state.clone_config();
        assert_eq!(mem_cfg.update.skipped_version.as_deref(), Some("9.9.9"));
        assert_eq!(
            mem_cfg.update.last_checked_at.as_deref(),
            Some("2026-11-27T04:00:00Z")
        );
        let disk_cfg = config::load_or_init(&paths).expect("reload config.json");
        assert_eq!(disk_cfg.update.skipped_version.as_deref(), Some("9.9.9"));
        assert_eq!(
            disk_cfg.update.last_checked_at.as_deref(),
            Some("2026-11-27T04:00:00Z")
        );
    });

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn stage21_reconcile_check_result_staged_version_clears_when_skipped() {
    assert_eq!(
        reconcile_check_result_staged_version(
            Some("0.2.0".to_string()),
            false,
            false,
            None
        )
        .as_deref(),
        Some("0.2.0")
    );
    assert_eq!(
        reconcile_check_result_staged_version(
            Some("0.2.0".to_string()),
            true,
            false,
            Some("0.2.0")
        ),
        None
    );
    assert_eq!(
        reconcile_check_result_staged_version(
            Some("0.2.0".to_string()),
            false,
            true,
            None
        ),
        None
    );
    assert_eq!(
        reconcile_check_result_staged_version(
            Some("0.1.9".to_string()),
            false,
            false,
            Some("0.1.9")
        ),
        None
    );
    assert_eq!(
        reconcile_check_result_staged_version(
            Some("0.2.0".to_string()),
            false,
            false,
            Some("0.1.9")
        )
        .as_deref(),
        Some("0.2.0")
    );
}

#[test]
fn stage21_reap_or_detach_child_with_grace_checks_exit_status() {
    use std::process::{Command, Stdio};

    let spawn_exit = |code: i32| -> std::process::Child {
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            Command::new("cmd")
                .args(["/C", &format!("exit {code}")])
                .creation_flags(CREATE_NO_WINDOW)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn cmd exit helper")
        }
        #[cfg(not(target_os = "windows"))]
        {
            Command::new("sh")
                .args(["-c", &format!("exit {code}")])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn sh exit helper")
        }
    };

    assert!(
        reap_or_detach_child_with_grace(
            spawn_exit(0),
            Duration::from_millis(1500),
            "打开更新包目录失败",
        )
        .is_ok()
    );

    let err = reap_or_detach_child_with_grace(
        spawn_exit(7),
        Duration::from_millis(1500),
        "打开更新包目录失败",
    )
    .expect_err("non-zero exit code must return Err");
    assert!(err.contains("打开更新包目录失败"));
    assert!(err.contains("7"));
}

#[test]
fn stage21_5_json_deep_merge_updates_and_clears_custom_rules_and_inline_override_yaml() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_s21_5_merge_rules_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), false).expect("create temp AppPaths");
    let storage = Storage::open_in_memory().expect("open memory storage");
    let initial = AppConfig::default();
    let state = AppState::new(
        paths,
        initial.clone(),
        storage,
        Arc::new(JobGuard::new().expect("create JobGuard")),
    );

    let valid_inline_yaml = concat!(
        "rule-providers:\n",
        "  demo-domain:\n",
        "    type: http\n",
        "    behavior: domain\n",
        "    url: https://example.invalid/demo.yaml\n",
        "    path: ./ruleset/demo.yaml\n",
        "    interval: 86400\n"
    );
    let enable_patch = serde_json::json!({
        "rules_override": {
            "custom_rules_only": true,
            "inline_override_yaml": valid_inline_yaml
        }
    });
    let updated = prepare_extended_settings_next(&state, &initial, &enable_patch)
        .expect("valid inline_override_yaml and custom_rules_only update must succeed");
    assert!(updated.rules_override.custom_rules_only);
    assert_eq!(
        updated.rules_override.inline_override_yaml.as_deref(),
        Some(valid_inline_yaml)
    );
    assert_eq!(
        updated.rules_override.block_quic_udp_443,
        initial.rules_override.block_quic_udp_443
    );
    assert_eq!(
        updated.rules_override.domestic_direct_enabled,
        initial.rules_override.domestic_direct_enabled
    );

    // Clearing via JSON `null` restores `None` while keeping sibling `custom_rules_only`.
    let clear_null_patch = serde_json::json!({
        "rules_override": {
            "inline_override_yaml": null
        }
    });
    let cleared_null = prepare_extended_settings_next(&state, &updated, &clear_null_patch)
        .expect("clearing inline_override_yaml with null must succeed");
    assert!(cleared_null.rules_override.custom_rules_only);
    assert_eq!(cleared_null.rules_override.inline_override_yaml, None);

    // Clearing via empty / whitespace-only string `""` also normalizes to `None`.
    let clear_empty_patch = serde_json::json!({
        "rules_override": {
            "custom_rules_only": false,
            "inline_override_yaml": "   \n\t  "
        }
    });
    let cleared_empty = prepare_extended_settings_next(&state, &updated, &clear_empty_patch)
        .expect("clearing inline_override_yaml with empty string must succeed");
    assert!(!cleared_empty.rules_override.custom_rules_only);
    assert_eq!(cleared_empty.rules_override.inline_override_yaml, None);

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn stage22_resolve_staged_update_version_checked_purges_stale_skipped_mismatched_and_corrupt() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_s22_stage_purge_{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&tmp).expect("create temp root");

    // 1. Corrupted staging dir is auto-purged.
    let corrupt_dir = tmp.join("corrupt").join(".update_staging");
    std::fs::create_dir_all(&corrupt_dir).unwrap();
    std::fs::write(corrupt_dir.join("pending_apply.json"), b"{corrupt").unwrap();
    assert_eq!(
        resolve_staged_update_version_checked(
            &corrupt_dir,
            "0.1.1",
            false,
            None,
            catcloud_core::updater::StagedUpdateKind::PortableZip
        ),
        None
    );
    assert!(
        !corrupt_dir.exists(),
        "corrupt staging_dir must be purged automatically"
    );

    // Helper to build a valid staged portable zip payload.
    let write_valid_staged = |dir: &std::path::Path, target_ver: &str| {
        let payload_dir = dir.join("payload");
        std::fs::create_dir_all(&payload_dir).unwrap();
        let payload_rel = "payload.bin";
        let payload_bytes = b"catcloud-s22-test-payload";
        let payload_file = payload_dir.join(payload_rel);
        std::fs::write(&payload_file, payload_bytes).unwrap();
        let sha = compute_file_sha256(&payload_file).unwrap();
        let meta = catcloud_core::updater::PendingUpdateMetadata {
            from_version: "0.1.0".to_string(),
            target_version: target_ver.to_string(),
            kind: catcloud_core::updater::StagedUpdateKind::PortableZip,
            archive_sha256: sha.clone(),
            staged_at: "2026-11-27T00:00:00Z".to_string(),
            package_size_bytes: payload_bytes.len() as u64,
            release_notes: String::new(),
            release_url: None,
            platform_key: None,
            installer_rel_path: None,
            files: vec![catcloud_core::updater::StagedFileEntry {
                rel_path: payload_rel.to_string(),
                sha256: sha,
                size_bytes: payload_bytes.len() as u64,
            }],
        };
        let meta_bytes = serde_json::to_vec_pretty(&meta).unwrap();
        std::fs::write(dir.join("pending_apply.json"), meta_bytes).unwrap();
    };

    // 2. Kind mismatch -> purged.
    let mismatch_dir = tmp.join("mismatch").join(".update_staging");
    write_valid_staged(&mismatch_dir, "0.2.0");
    assert_eq!(
        resolve_staged_update_version_checked(
            &mismatch_dir,
            "0.1.1",
            false,
            None,
            catcloud_core::updater::StagedUpdateKind::InstallerPackage
        ),
        None
    );
    assert!(!mismatch_dir.exists(), "kind-mismatched staging must be purged");

    // 3. Skipped version -> purged.
    let skipped_dir = tmp.join("skipped").join(".update_staging");
    write_valid_staged(&skipped_dir, "0.2.0");
    assert_eq!(
        resolve_staged_update_version_checked(
            &skipped_dir,
            "0.1.1",
            false,
            Some("0.2.0"),
            catcloud_core::updater::StagedUpdateKind::PortableZip
        ),
        None
    );
    assert!(!skipped_dir.exists(), "skipped staging must be purged");

    // 4. Expired (<= current_version) -> purged.
    let expired_dir = tmp.join("expired").join(".update_staging");
    write_valid_staged(&expired_dir, "0.1.1");
    assert_eq!(
        resolve_staged_update_version_checked(
            &expired_dir,
            "0.1.1",
            false,
            None,
            catcloud_core::updater::StagedUpdateKind::PortableZip
        ),
        None
    );
    assert!(!expired_dir.exists(), "expired staging must be purged");

    // 5. Valid newer non-skipped matching kind -> preserved and returned.
    let valid_dir = tmp.join("valid").join(".update_staging");
    write_valid_staged(&valid_dir, "0.2.0");
    assert_eq!(
        resolve_staged_update_version_checked(
            &valid_dir,
            "0.1.1",
            false,
            None,
            catcloud_core::updater::StagedUpdateKind::PortableZip
        )
        .as_deref(),
        Some("0.2.0")
    );
    assert!(valid_dir.exists(), "valid newer staging must remain intact");

    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn stage22_mark_onboarding_completed_and_backup_restore_preflight_invariants() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_s22_backup_onboard_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), true).unwrap();
    let mut storage = Storage::open(&paths.db_path).unwrap();
    storage.seed_builtin_probes().unwrap();
    let initial_cfg = AppConfig::default();
    config::save(&paths, &initial_cfg).unwrap();
    let state = AppState::new(
        paths.clone(),
        initial_cfg,
        storage,
        Arc::new(JobGuard::new().unwrap()),
    );

    // 1. Lightweight `mark_onboarding_completed_core` sets and persists `onboarding_completed = true`.
    assert!(!state.snapshot_config().personalization.onboarding_completed);
    let updated = mark_onboarding_completed_core(&state)
        .await
        .expect("mark onboarding completed");
    assert!(updated.personalization.onboarding_completed);
    let reloaded = config::load_or_init(&paths).unwrap();
    assert!(reloaded.personalization.onboarding_completed);

    // 2. Backup bundle containing an invalid relay MUST fail BEFORE touching `config.json`.
    let mut bad_cfg = AppConfig::default();
    bad_cfg.mixed_port = 19999;
    let bad_relay = PreAccelRelay {
        id: "r-bad".to_string(),
        name: "Bad-SNI".to_string(),
        provider: "tencent".to_string(),
        region: "CN".to_string(),
        server: "203.0.113.10".to_string(),
        port: 443,
        protocol: "trojan".to_string(),
        password: "demo-password".to_string(),
        sni: Some("forbidden.example.invalid".to_string()),
        skip_cert_verify: true,
        enabled: true,
        ..Default::default()
    };
    let bad_bundle = serde_json::json!({
        "config": bad_cfg,
        "preaccel_relays": [bad_relay]
    })
    .to_string();
    let err = prepare_and_apply_backup_bundle_core(&state, &bad_bundle)
        .err()
        .expect("invalid relay backup must reject before writing config");
    assert!(err.contains("国内中转校验未通过"), "unexpected err: {err}");
    assert_ne!(
        state.snapshot_config().mixed_port,
        19999,
        "failed backup must NOT leave half-restored config in memory"
    );
    assert_ne!(
        config::load_or_init(&paths).unwrap().mixed_port,
        19999,
        "failed backup must NOT leave half-restored config on disk"
    );

    // 3. Valid backup with `onboarding_completed=false`, overseas `probe_url`, dangling
    //    `active_relay_id`, and legacy official Windsurf probe (`https://windsurf.com` + GET 200):
    //    must latch `onboarding_completed |= true`, heal `probe_url`, clear dangling relay,
    //    and migrate built-in Windsurf to ConnectRPC semantic probe (`POST`, `expected_status = None`).
    let mut legacy_cfg = AppConfig::default();
    legacy_cfg.personalization.onboarding_completed = false;
    legacy_cfg.preaccel.probe_url = "https://www.gstatic.com/generate_204".to_string();
    legacy_cfg.preaccel.active_relay_id = Some("nonexistent-relay-id".to_string());
    let stale_windsurf = ProbeDefinition {
        id: "builtin_unlock_windsurf".to_string(),
        name: "Windsurf / Codeium Reachability".to_string(),
        kind: catcloud_core::models::ProbeKind::UnlockRegex,
        target_url: "https://windsurf.com".to_string(),
        method: "GET".to_string(),
        expected_status: Some(200),
        body_regex: None,
        payload_bytes: None,
        timeout_ms: 8000,
        builtin: true,
    };
    let good_bundle = serde_json::json!({
        "config": legacy_cfg,
        "probe_definitions": [stale_windsurf]
    })
    .to_string();
    let applied = prepare_and_apply_backup_bundle_core(&state, &good_bundle)
        .expect("valid backup restore must succeed");
    assert!(applied.restored_config);
    let after_cfg = state.clone_config();
    assert!(
        after_cfg.personalization.onboarding_completed,
        "backup restore must one-way latch onboarding_completed |= old"
    );
    assert_eq!(after_cfg.preaccel.active_relay_id, None);
    assert!(
        !after_cfg.preaccel.probe_url.contains("gstatic"),
        "backup restore must run migrate_config_in_memory to heal overseas probe_url"
    );
    let probes = state.storage.lock().unwrap().list_probe_definitions().unwrap();
    let ws = probes
        .iter()
        .find(|p| p.id == "builtin_unlock_windsurf")
        .expect("windsurf builtin probe exists");
    assert_eq!(
        ws.target_url,
        "https://server.codeium.com/exa.api_server_pb.ApiServerService/GetChatMessage",
        "seed_builtin_probes after restore must migrate legacy windsurf target_url to ConnectRPC endpoint"
    );
    assert_eq!(
        ws.method,
        "POST",
        "seed_builtin_probes after restore must migrate legacy windsurf method to POST"
    );
    assert_eq!(
        ws.expected_status,
        None,
        "seed_builtin_probes after restore must migrate legacy windsurf expected_status to None"
    );

    drop(state);
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn stage22_r25_backup_bundle_strict_validation_and_atomic_rollback_on_reload_rejected() {
    let tmp = std::env::temp_dir().join(format!(
        "catcloud_s22_r25_backup_atomic_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let paths = AppPaths::from_data_dir(tmp.clone(), true).unwrap();
    let mut storage = Storage::open(&paths.db_path).unwrap();
    storage.seed_builtin_probes().unwrap();

    // Seed existing group, relay, node + probe_result so rollback must preserve them intact.
    let mut orig_group = MultiGroup::default();
    orig_group.id = "grp-orig".to_string();
    orig_group.name = "OriginalGroup".to_string();
    storage.upsert_multi_group(&orig_group).unwrap();

    let orig_relay = PreAccelRelay {
        id: "relay-orig".to_string(),
        name: "Orig-Relay".to_string(),
        provider: "aliyun".to_string(),
        region: "CN-SH".to_string(),
        server: "198.51.100.11".to_string(),
        port: 443,
        protocol: "anytls".to_string(),
        password: "demo-orig-password".to_string(),
        skip_cert_verify: true,
        enabled: true,
        ..Default::default()
    };
    storage.upsert_preaccel_relay(&orig_relay).unwrap();

    storage
        .upsert_subscription(&SubscriptionRecord {
            id: "sub-orig".to_string(),
            name: "Orig Sub".to_string(),
            ..Default::default()
        })
        .unwrap();
    storage
        .upsert_node(&ProxyNode {
            id: "node-orig".to_string(),
            sub_id: "sub-orig".to_string(),
            name: "Orig-Node".to_string(),
            protocol: "vless".to_string(),
            server: "203.0.113.22".to_string(),
            port: 443,
            enabled: true,
            raw_config: serde_json::json!({
                "name": "Orig-Node",
                "type": "vless",
                "server": "203.0.113.22",
                "port": 443,
                "uuid": "00000000-0000-4000-8000-000000000022",
                "tls": true,
                "network": "tcp"
            }),
            ..Default::default()
        })
        .unwrap();
    storage
        .insert_probe_results_batch(&[catcloud_core::models::ProbeResultRecord {
            node_id: "node-orig".to_string(),
            probe_id: "builtin_latency".to_string(),
            tested_at: "2026-11-27T12:00:00Z".to_string(),
            ok: true,
            latency_ms: Some(45.0),
            ..Default::default()
        }])
        .unwrap();

    let snap_before = storage.capture_backup_db_snapshot().unwrap();
    let mut orig_cfg = AppConfig::default();
    orig_cfg.mixed_port = 17890;
    config::save(&paths, &orig_cfg).unwrap();

    let state = AppState::new(
        paths.clone(),
        orig_cfg.clone(),
        storage,
        Arc::new(JobGuard::new().unwrap()),
    );

    // 1. Corrupt item inside `multi_groups` (both schema type mismatch & missing ID) MUST
    //    reject with clear Chinese error (never silently skip).
    let corrupt_group_bundle = serde_json::json!({
        "config": { "mixed_port": 18888 },
        "multi_groups": [{ "id": 12345, "mode": "invalid_mode" }]
    })
    .to_string();
    let err_group = prepare_and_apply_backup_bundle_core(&state, &corrupt_group_bundle)
        .err()
        .expect("corrupt multi_groups entry must be rejected");
    assert!(err_group.contains("多选分组数据损坏"), "unexpected err: {err_group}");
    assert_eq!(state.snapshot_config().mixed_port, 17890);
    assert_eq!(
        state.storage.lock().unwrap().capture_backup_db_snapshot().unwrap(),
        snap_before
    );

    let missing_id_group_bundle = serde_json::json!({
        "multi_groups": [{ "name": "NoIdGroup" }]
    })
    .to_string();
    let err_missing_id = prepare_and_apply_backup_bundle_core(&state, &missing_id_group_bundle)
        .err()
        .expect("multi_groups entry with empty ID must be rejected");
    assert!(
        err_missing_id.contains("缺少有效 ID"),
        "unexpected err: {err_missing_id}"
    );

    // 2. Corrupt item inside `preaccel_relays` MUST reject strictly.
    let corrupt_relay_bundle = serde_json::json!({
        "preaccel_relays": [{ "port": "not-a-port" }]
    })
    .to_string();
    let err_relay = prepare_and_apply_backup_bundle_core(&state, &corrupt_relay_bundle)
        .err()
        .expect("corrupt preaccel_relays entry must be rejected");
    assert!(err_relay.contains("国内中转数据损坏"), "unexpected err: {err_relay}");
    assert_eq!(
        state.storage.lock().unwrap().capture_backup_db_snapshot().unwrap(),
        snap_before
    );

    // 3. Invalid probe failing `validate_definition` (bad scheme `ftp://`) MUST reject cleanly.
    let bad_probe = ProbeDefinition {
        id: "custom_bad_scheme".to_string(),
        name: "BadSchemeProbe".to_string(),
        kind: catcloud_core::models::ProbeKind::Latency,
        target_url: "ftp://example.invalid/test".to_string(),
        method: "GET".to_string(),
        expected_status: Some(204),
        body_regex: None,
        payload_bytes: None,
        timeout_ms: 4000,
        builtin: false,
    };
    let bad_probe_bundle = serde_json::json!({
        "probe_definitions": [bad_probe]
    })
    .to_string();
    let err_probe = prepare_and_apply_backup_bundle_core(&state, &bad_probe_bundle)
        .err()
        .expect("invalid probe definition must be rejected");
    assert!(err_probe.contains("测速探针"), "unexpected err: {err_probe}");
    assert_eq!(
        state.storage.lock().unwrap().capture_backup_db_snapshot().unwrap(),
        snap_before
    );

    // 4. Valid bundle mutating config + adding new group, new relay, new probe, and modifying
    //    existing group -> apply succeeds -> simulated live hot-reload `outcome.rejected == true`
    //    MUST atomically roll back ALL three SQLite tables (deleting newly added IDs and
    //    restoring modified rows without cascading `probe_results`) AND restore `config.json`
    //    & in-memory `state.config`.
    let mut next_cfg = orig_cfg.clone();
    next_cfg.mixed_port = 18899;
    let mut modified_orig_group = orig_group.clone();
    modified_orig_group.name = "ModifiedDuringRestore".to_string();
    let mut added_group = MultiGroup::default();
    added_group.id = "grp-added-in-backup".to_string();
    added_group.name = "AddedBackupGroup".to_string();
    let added_relay = PreAccelRelay {
        id: "relay-added-in-backup".to_string(),
        name: "Added-Relay".to_string(),
        provider: "tencent".to_string(),
        region: "CN-GZ".to_string(),
        server: "198.51.100.99".to_string(),
        port: 443,
        protocol: "anytls".to_string(),
        password: "demo-added-password".to_string(),
        skip_cert_verify: true,
        enabled: true,
        ..Default::default()
    };
    let added_probe = ProbeDefinition {
        id: "custom_probe_added_in_backup".to_string(),
        name: "AddedProbe".to_string(),
        kind: catcloud_core::models::ProbeKind::Latency,
        target_url: "https://example.invalid/generate_204".to_string(),
        method: "GET".to_string(),
        expected_status: Some(204),
        body_regex: None,
        payload_bytes: None,
        timeout_ms: 4000,
        builtin: false,
    };
    let valid_bundle = serde_json::json!({
        "config": next_cfg,
        "multi_groups": [modified_orig_group, added_group],
        "preaccel_relays": [added_relay],
        "probe_definitions": [added_probe]
    })
    .to_string();

    let applied = prepare_and_apply_backup_bundle_core(&state, &valid_bundle)
        .expect("valid backup restore must apply before reload check");
    assert_eq!(state.snapshot_config().mixed_port, 18899);
    assert_eq!(config::load_or_init(&paths).unwrap().mixed_port, 18899);
    assert!(
        state
            .storage
            .lock()
            .unwrap()
            .list_multi_groups()
            .unwrap()
            .iter()
            .any(|g| g.id == "grp-added-in-backup")
    );

    let rejected = ReloadOutcome {
        applied: false,
        level: ReloadLevel::L2HotReload,
        skipped_unchanged: false,
        rejected: true,
        config_hash: None,
        replayed_groups: 0,
        shifted_ports: Vec::new(),
        warnings: Vec::new(),
        error: Some("simulated mihomo -t rejection".to_string()),
        applied_at: "2026-11-27T12:05:00Z".to_string(),
    };
    let rb_err = finalize_backup_restore_reload_outcome(&state, &applied, Some(&rejected))
        .expect_err("rejected reload must return error after atomic rollback");
    assert!(
        rb_err.contains("已完整回滚配置与数据库"),
        "unexpected rollback err: {rb_err}"
    );

    // Verify 100% atomic restoration of config (memory + disk) and all 3 SQLite tables + probe_results.
    assert_eq!(state.snapshot_config().mixed_port, 17890);
    assert_eq!(config::load_or_init(&paths).unwrap().mixed_port, 17890);
    let snap_after = state
        .storage
        .lock()
        .unwrap()
        .capture_backup_db_snapshot()
        .unwrap();
    assert_eq!(
        snap_after, snap_before,
        "DB snapshot after rejected-reload rollback must equal pre-restore snapshot byte-for-byte"
    );
    let preserved_snap = state
        .storage
        .lock()
        .unwrap()
        .get_probe_snapshot("node-orig", None)
        .unwrap()
        .expect("probe_results must remain intact after rollback");
    assert_eq!(preserved_snap.latency_ms, Some(45.0));

    drop(state);
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn stage26_geodata_mirrors_exit_ip_dto_and_hard_gate_validation() {
    // 1. `Country.mmdb` normalizes to lowercase `country.mmdb` on MetaCubeX jsDelivr mirrors.
    assert_eq!(
        derive_geodata_mirror_urls(
            "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/Country.mmdb"
        ),
        vec![
            "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb"
                .to_string(),
            "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb"
                .to_string(),
        ]
    );

    // 2. `country-lite.mmdb`, `geosite.dat`, `geoip.dat`, `GeoLite2-ASN.mmdb` keep exact casing.
    assert_eq!(
        derive_geodata_mirror_urls(
            "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/country-lite.mmdb"
        ),
        vec![
            "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country-lite.mmdb"
                .to_string(),
            "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country-lite.mmdb"
                .to_string(),
        ]
    );
    assert_eq!(
        derive_geodata_mirror_urls(
            "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/GeoLite2-ASN.mmdb?raw=1"
        ),
        vec![
            "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/GeoLite2-ASN.mmdb"
                .to_string(),
            "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/GeoLite2-ASN.mmdb"
                .to_string(),
        ]
    );
    assert_eq!(
        derive_geodata_mirror_urls(
            "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geosite.dat"
        ),
        vec![
            "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat"
                .to_string(),
            "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat"
                .to_string(),
        ]
    );

    // 3. Non-MetaCubeX or malformed URLs return no mirrors.
    assert!(
        derive_geodata_mirror_urls("https://example.com/custom/Country.mmdb").is_empty()
    );
    assert!(
        derive_geodata_mirror_urls(
            "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/"
        )
        .is_empty()
    );
    assert!(
        derive_geodata_mirror_urls(
            "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/sub/geoip.dat"
        )
        .is_empty()
    );

    // 4. Hard-gate expression validation accepts valid gates (including `ip_clean`) and rejects malformed ones.
    validate_group_hard_gates(&[
        "site_unlocked(\"windsurf\") == 1".to_string(),
        "ip_clean == 1".to_string(),
        "ping_ms <= 300".to_string(),
        "   ".to_string(),
    ])
    .expect("valid hard gates must pass");

    let bad_syntax = validate_group_hard_gates(&["ping_ms <==".to_string()])
        .expect_err("malformed hard gate syntax must be rejected");
    assert!(bad_syntax.contains("硬门禁表达式无效"), "unexpected err: {bad_syntax}");

    let bad_ident = validate_group_hard_gates(&["no_such_metric == 1".to_string()])
        .expect_err("unknown hard gate identifier must be rejected");
    assert!(bad_ident.contains("硬门禁表达式无效"), "unexpected err: {bad_ident}");

    // 5. `ExitIpInfoDto` backwards-compatible deserialization + roundtrip with purity fields.
    let legacy_json = serde_json::json!({
        "ip_masked": "203.0.113.***",
        "ip_raw": "203.0.113.4",
        "isp": "Example ISP",
        "location": "TW",
        "timezone": "Asia/Taipei",
        "google_clean": true,
        "core_running": true
    });
    let legacy_dto: ExitIpInfoDto =
        serde_json::from_value(legacy_json).expect("legacy ExitIpInfoDto must deserialize");
    assert_eq!(legacy_dto.ip_clean, None);
    assert_eq!(legacy_dto.ip_risk_level, None);
    assert_eq!(legacy_dto.ip_asn, None);
    assert_eq!(legacy_dto.ip_risk_flags, None);

    let full_dto = ExitIpInfoDto {
        ip_masked: "203.0.113.***".to_string(),
        ip_raw: Some("203.0.113.4".to_string()),
        isp: "Example ISP".to_string(),
        location: "TW".to_string(),
        timezone: "Asia/Taipei".to_string(),
        google_clean: Some(true),
        core_running: true,
        ip_clean: Some(false),
        ip_risk_level: Some("proxy_risk".to_string()),
        ip_asn: Some("AS38136 Akari Networks".to_string()),
        ip_risk_flags: Some("proxy,datacenter".to_string()),
    };
    let encoded = serde_json::to_value(&full_dto).expect("serialize full ExitIpInfoDto");
    let decoded: ExitIpInfoDto =
        serde_json::from_value(encoded).expect("deserialize full ExitIpInfoDto");
    assert_eq!(decoded.ip_clean, Some(false));
    assert_eq!(
        decoded.ip_risk_level.as_deref(),
        Some("proxy_risk")
    );

    // 6. Selecting a node inside a non-primary independent routing group keeps the primary default group intact.
    assert!(!should_activate_group_on_node_select(
        None,
        true,
        "grp-wsf",
        RouteTargetMode::Group,
        Some("grp-taiwan"),
    ));
    assert!(should_activate_group_on_node_select(
        None,
        false,
        "grp-other",
        RouteTargetMode::Group,
        Some("grp-taiwan"),
    ));
    assert!(should_activate_group_on_node_select(
        Some(true),
        true,
        "grp-wsf",
        RouteTargetMode::Group,
        Some("grp-taiwan"),
    ));
    assert!(should_activate_group_on_node_select(
        None,
        true,
        "grp-taiwan",
        RouteTargetMode::Group,
        Some("grp-taiwan"),
    ));
    assert_eq!(decoded.ip_risk_level.as_deref(), Some("proxy_risk"));
    assert_eq!(decoded.ip_asn.as_deref(), Some("AS38136 Akari Networks"));
    assert_eq!(decoded.ip_risk_flags.as_deref(), Some("proxy,datacenter"));
}
