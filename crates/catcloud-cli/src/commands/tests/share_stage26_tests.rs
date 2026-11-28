//! Share bundle / `.ccsync` roundtrip tests and Stage 26 rule/group/doctor regression tests.

use catcloud_core::config;
use catcloud_core::models::{
    MultiGroup, PreAccelRelay, ProxyMode, ProxyNode, SubscriptionKind, SubscriptionRecord,
};
use catcloud_core::share_bundle::ShareBundleExportRequest;
use catcloud_core::sync::{LanSyncSendServer, LanSyncServerOptions, fetch_sync_bundle_via_uri};
use catcloud_core::AppPaths;
use chrono::Utc;
use serde_json::json;
use crate::commands::{
    Commands, ConfigCommand, GroupCreateArgs, GroupPolicyArgs, NodeCommand, NodeMigrateArgs,
    ShareExportArgs, ShareImportArgs, ShareReceiveArgs, ShareSendArgs, SubCommand, dispatch,
};
use crate::commands::config_reload::build_config_validate_payload;
use crate::commands::net_logs::{build_net_match_payload, inspect_windows_proxy_override_warnings};
use crate::commands::probe_group::{execute_group_create, execute_group_policy};
use crate::commands::redact_helpers::{
    looks_like_clash_rule_prefix, open_storage, parse_group_match_rules_arg,
};
use crate::commands::share_sync::{
    build_cli_sync_export_zip, build_share_inspect_payload, execute_share_import,
    execute_share_receive_from_zip_bytes, execute_share_send_ccsync, handle_share_export,
    handle_share_import, handle_share_inspect, open_cli_ccsync_file,
};

#[test]
fn share_bundle_export_inspect_and_import_roundtrip_is_sanitized_by_default() {
    let temp_root = std::env::temp_dir().join(format!(
        "catcloud-cli-share-roundtrip-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    let paths = AppPaths::from_data_dir(temp_root.join("data"), true).expect("init temp paths");
    let db = open_storage(&paths).expect("open db");

    db.upsert_subscription(&SubscriptionRecord {
        id: "sub-origin".to_string(),
        name: "Origin".to_string(),
        kind: SubscriptionKind::File,
        url_or_cmd: "origin.yaml".to_string(),
        ..Default::default()
    })
    .unwrap();
    db.upsert_node(&ProxyNode {
        id: "node-share-1".to_string(),
        sub_id: "sub-origin".to_string(),
        name: "JP Share 1x".to_string(),
        protocol: "trojan".to_string(),
        server: "203.0.113.91".to_string(),
        port: 443,
        raw_config: json!({
            "name": "JP Share 1x",
            "type": "trojan",
            "server": "203.0.113.91",
            "port": 443,
            "password": "secret_node_pass_demo"
        }),
        region_code: "JP".to_string(),
        ..ProxyNode::default()
    })
    .unwrap();
    db.upsert_preaccel_relay(&PreAccelRelay {
        id: "relay-share-1".to_string(),
        name: "CN-443-Demo".to_string(),
        provider: "cloud".to_string(),
        region: "CN-East".to_string(),
        server: "198.51.100.92".to_string(),
        port: 443,
        protocol: "anytls".to_string(),
        password: "secret_relay_pass_demo".to_string(),
        skip_cert_verify: true,
        ..PreAccelRelay::default()
    })
    .unwrap();
    drop(db);

    let zip_path = temp_root.join("friend-pack.zip");
    handle_share_export(
        &paths,
        true,
        ShareExportArgs {
            output: zip_path.clone(),
            name: "Friend Pack".to_string(),
            description: None,
            node_ids: Some("node-share-1".to_string()),
            sub_id: None,
            relay_ids: Some("relay-share-1".to_string()),
            all_relays: false,
        },
    )
    .expect("export share zip");
    assert!(zip_path.is_file());

    // Inspect must succeed and preview in a separate fresh data dir must not persist on dry-run.
    handle_share_inspect(true, &zip_path, false).expect("inspect share zip");
    handle_share_inspect(true, &zip_path, true).expect("inspect share zip summary");

    let dst_paths =
        AppPaths::from_data_dir(temp_root.join("dst-data"), true).expect("init dst paths");
    handle_share_import(
        &dst_paths,
        true,
        ShareImportArgs {
            file_pos: Some(zip_path.clone()),
            file: None,
            dry_run: false,
            apply: false,
            target_sub: None,
            name: None,
            mode: "merge".to_string(),
            no_relays: false,
            no_nodes: false,
        },
    )
    .expect("dry-run share import");
    let dst_db = open_storage(&dst_paths).expect("open dst db");
    assert_eq!(dst_db.list_nodes().unwrap().len(), 0);
    assert_eq!(dst_db.list_preaccel_relays(false).unwrap().len(), 0);
    drop(dst_db);

    handle_share_import(
        &dst_paths,
        true,
        ShareImportArgs {
            file_pos: Some(zip_path),
            file: None,
            dry_run: false,
            apply: true,
            target_sub: None,
            name: Some("Imported Friend Pack".to_string()),
            mode: "merge".to_string(),
            no_relays: false,
            no_nodes: false,
        },
    )
    .expect("apply share import");
    let dst_db = open_storage(&dst_paths).expect("open dst db after apply");
    assert_eq!(dst_db.list_nodes().unwrap().len(), 1);
    assert_eq!(dst_db.list_preaccel_relays(false).unwrap().len(), 1);
    let subs = dst_db.list_subscriptions().unwrap();
    assert_eq!(subs.len(), 1);
    assert_eq!(subs[0].name, "Imported Friend Pack");

    let _ = std::fs::remove_dir_all(&temp_root);
}

#[test]
fn share_import_preserves_conflicting_relay_id_unifies_node_count_and_syncs_active_node() {
    let temp_root = std::env::temp_dir().join(format!(
        "catcloud-cli-share-conflict-sync-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    let src_paths =
        AppPaths::from_data_dir(temp_root.join("src-data"), true).expect("init src paths");
    let src_db = open_storage(&src_paths).expect("open src db");

    src_db
        .upsert_subscription(&SubscriptionRecord {
            id: "sub-export".to_string(),
            name: "Export Sub".to_string(),
            kind: SubscriptionKind::File,
            url_or_cmd: "export.yaml".to_string(),
            ..Default::default()
        })
        .unwrap();
    src_db
        .upsert_node(&ProxyNode {
            id: "node-incoming-1".to_string(),
            sub_id: "sub-export".to_string(),
            name: "SG Incoming 1x".to_string(),
            protocol: "trojan".to_string(),
            server: "203.0.113.81".to_string(),
            port: 443,
            raw_config: json!({
                "name": "SG Incoming 1x",
                "type": "trojan",
                "server": "203.0.113.81",
                "port": 443,
                "password": "incoming_node_pass_demo"
            }),
            region_code: "SG".to_string(),
            ..ProxyNode::default()
        })
        .unwrap();
    src_db
        .upsert_preaccel_relay(&PreAccelRelay {
            id: "relay-same-id".to_string(),
            name: "Incoming-Relay-B".to_string(),
            provider: "cloud".to_string(),
            region: "CN-South".to_string(),
            server: "198.51.100.88".to_string(),
            port: 443,
            protocol: "anytls".to_string(),
            password: "incoming_relay_pass_demo".to_string(),
            skip_cert_verify: true,
            ..PreAccelRelay::default()
        })
        .unwrap();
    drop(src_db);

    let zip_path = temp_root.join("conflict-pack.zip");
    handle_share_export(
        &src_paths,
        true,
        ShareExportArgs {
            output: zip_path.clone(),
            name: "Conflict Pack".to_string(),
            description: None,
            node_ids: Some("node-incoming-1".to_string()),
            sub_id: None,
            relay_ids: Some("relay-same-id".to_string()),
            all_relays: false,
        },
    )
    .expect("export conflict share zip");

    let dst_paths =
        AppPaths::from_data_dir(temp_root.join("dst-data"), true).expect("init dst paths");
    let dst_db = open_storage(&dst_paths).expect("open dst db");
    dst_db
        .upsert_subscription(&SubscriptionRecord {
            id: "sub-existing".to_string(),
            name: "Existing Sub".to_string(),
            kind: SubscriptionKind::File,
            url_or_cmd: "existing.yaml".to_string(),
            ..Default::default()
        })
        .unwrap();
    for (nid, host) in [
        ("node-existing-1", "198.51.100.11"),
        ("node-existing-2", "198.51.100.12"),
    ] {
        dst_db
            .upsert_node(&ProxyNode {
                id: nid.to_string(),
                sub_id: "sub-existing".to_string(),
                name: format!("Old {nid}"),
                protocol: "trojan".to_string(),
                server: host.to_string(),
                port: 443,
                raw_config: json!({
                    "name": format!("Old {nid}"),
                    "type": "trojan",
                    "server": host,
                    "port": 443,
                    "password": "old_node_pass_demo"
                }),
                region_code: "US".to_string(),
                ..ProxyNode::default()
            })
            .unwrap();
    }
    // Existing local relay with the same ID (`relay-same-id`) but a distinct server IP.
    dst_db
        .upsert_preaccel_relay(&PreAccelRelay {
            id: "relay-same-id".to_string(),
            name: "Original-Local-Relay-A".to_string(),
            provider: "cloud".to_string(),
            region: "CN-East".to_string(),
            server: "203.0.113.77".to_string(),
            port: 443,
            protocol: "anytls".to_string(),
            password: "original_relay_pass_demo".to_string(),
            skip_cert_verify: true,
            ..PreAccelRelay::default()
        })
        .unwrap();
    drop(dst_db);

    let mut dst_cfg = config::load_or_init(&dst_paths).expect("init dst config");
    dst_cfg.active_single_node_id = Some("node-existing-1".to_string());
    config::save(&dst_paths, &dst_cfg).expect("save dst config");

    // 1. Merge into existing sub: imported_nodes reflects chosen count (1),
    //    while target_sub_total_nodes reports full group total (3);
    //    conflicting relay ID must be regenerated without overwriting the existing relay.
    let (merge_out, _) = execute_share_import(
        &dst_paths,
        ShareImportArgs {
            file_pos: Some(zip_path.clone()),
            file: None,
            dry_run: false,
            apply: true,
            target_sub: Some("sub-existing".to_string()),
            name: None,
            mode: "merge".to_string(),
            no_relays: false,
            no_nodes: false,
        },
    )
    .expect("merge share import");
    assert_eq!(merge_out["imported_nodes"], json!(1));
    assert_eq!(merge_out["target_sub_total_nodes"], json!(3));
    assert_eq!(merge_out["imported_relays"], json!(1));

    let dst_db = open_storage(&dst_paths).expect("reopen dst db after merge");
    let relays = dst_db.list_preaccel_relays(false).unwrap();
    assert_eq!(
        relays.len(),
        2,
        "conflicting relay ID with distinct server must not overwrite original relay"
    );
    let original = relays
        .iter()
        .find(|r| r.id == "relay-same-id")
        .expect("original relay must remain intact");
    assert_eq!(original.server, "203.0.113.77");
    assert_eq!(original.name, "Original-Local-Relay-A");
    let imported_other = relays
        .iter()
        .find(|r| r.server == "198.51.100.88")
        .expect("incoming relay must be stored under a fresh non-colliding ID");
    assert_ne!(imported_other.id, "relay-same-id");
    drop(dst_db);

    // 2. Replace existing sub: drops `node-existing-1` (empty id_remap for it),
    //    so `active_single_node_id` must be synced to the surviving node.
    let (replace_out, _) = execute_share_import(
        &dst_paths,
        ShareImportArgs {
            file_pos: Some(zip_path),
            file: None,
            dry_run: false,
            apply: true,
            target_sub: Some("sub-existing".to_string()),
            name: None,
            mode: "replace".to_string(),
            no_relays: true,
            no_nodes: false,
        },
    )
    .expect("replace share import");
    assert_eq!(replace_out["imported_nodes"], json!(1));
    assert_eq!(replace_out["target_sub_total_nodes"], json!(1));

    let dst_db = open_storage(&dst_paths).expect("reopen dst db after replace");
    let remaining_nodes = dst_db.list_nodes().unwrap();
    assert_eq!(remaining_nodes.len(), 1);
    let synced_cfg = config::load_or_default(&dst_paths).expect("reload dst config");
    assert_eq!(
        synced_cfg.active_single_node_id.as_deref(),
        Some(remaining_nodes[0].id.as_str()),
        "replace_latest must sync stale active_single_node_id to a surviving enabled node"
    );

    let _ = std::fs::remove_dir_all(&temp_root);
}

#[test]
fn share_inspect_summary_returns_compact_distributions_and_masks_sni_and_host_fields() {
    use catcloud_core::share_bundle::{
        SHARE_GROUPS_SCHEMA, ShareGroupRecord, ShareGroupsBundle,
        export_share_bundle_zip_file_with_groups,
    };
    use catcloud_core::subscription::parser::node_dedup_fingerprint;

    let temp_root = std::env::temp_dir().join(format!(
        "catcloud-cli-share-summary-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    std::fs::create_dir_all(&temp_root).unwrap();

    let mut nodes = Vec::new();
    for i in 0..12usize {
        let (region, proto, label) = match i % 3 {
            0 => ("JP", "vless", format!("🇯🇵 东京 0.5x #{i}")),
            1 => ("SG", "trojan", format!("🇸🇬 新加坡 1x #{i}")),
            _ => ("US", "vless", format!("🇺🇸 美国 1x #{i}")),
        };
        nodes.push(ProxyNode {
            id: format!("n-sum-{i}"),
            sub_id: "sub-demo".to_string(),
            name: label.clone(),
            protocol: proto.to_string(),
            server: format!("edge{i}.demo-upstream.com"),
            port: 443,
            raw_config: json!({
                "name": label,
                "type": proto,
                "server": format!("edge{i}.demo-upstream.com"),
                "port": 443,
                "uuid": format!("00000000-0000-4000-8000-{i:012}"),
                "password": format!("demo_pass_{i}"),
                "sni": format!("sni{i}.demo-secret.net"),
                "servername": format!("tls{i}.demo-secret.org"),
                "plugin-opts": {
                    "mode": "websocket",
                    "host": format!("plug{i}.demo-cdn.io")
                },
                "ws-opts": {
                    "path": "/ws",
                    "headers": {
                        "Host": format!("ws{i}.demo-edge.com")
                    }
                }
            }),
            region_code: region.to_string(),
            ..ProxyNode::default()
        });
    }
    let fp0 = node_dedup_fingerprint(&nodes[0]);
    let groups_bundle = ShareGroupsBundle {
        schema: SHARE_GROUPS_SCHEMA.to_string(),
        active_group_name: Some("AI Pool".to_string()),
        route_mode: Some("group".to_string()),
        groups: vec![ShareGroupRecord {
            name: "AI Pool".to_string(),
            member_fingerprints: vec![fp0],
            ..ShareGroupRecord::default()
        }],
    };

    let zip_path = temp_root.join("summary-pack.zip");
    let req = ShareBundleExportRequest {
        name: "Summary Demo Pack".to_string(),
        description: Some("12 nodes + 1 group".to_string()),
        nodes,
        relays: Vec::new(),
    };
    export_share_bundle_zip_file_with_groups(&req, Some(&groups_bundle), &zip_path)
        .expect("export summary pack");

    // 1. Summary mode: compact JSON with <= 5 samples, counts, top regions, protocols.
    let (summary_out, summary_human) =
        build_share_inspect_payload(&zip_path, true).expect("inspect --summary");
    assert_eq!(summary_out["summary_mode"], json!(true));
    assert_eq!(summary_out["node_count"], json!(12));
    assert_eq!(summary_out["relay_count"], json!(0));
    assert_eq!(summary_out["group_count"], json!(1));
    assert_eq!(summary_out["sample_nodes"].as_array().unwrap().len(), 5);
    assert!(summary_out.get("nodes").is_none());
    assert!(summary_human.contains("12 node(s)"));
    assert!(summary_human.contains("1 group(s)"));
    let summary_json = serde_json::to_string(&summary_out).unwrap();
    assert!(!summary_json.contains("demo-upstream"));
    assert!(!summary_json.contains("demo-secret"));
    assert!(!summary_json.contains("demo-cdn"));
    assert!(!summary_json.contains("demo-edge"));

    // 2. Full inspect mode: raw_config must mask sni, servername, plugin-opts.host, ws-opts.headers.Host.
    let (full_out, _) =
        build_share_inspect_payload(&zip_path, false).expect("inspect full");
    assert_eq!(full_out["summary_mode"], json!(false));
    assert_eq!(full_out["group_count"], json!(1));
    let first_node = &full_out["nodes"][0];
    assert_eq!(first_node["raw_config"]["sni"], json!("***.net"));
    assert_eq!(first_node["raw_config"]["servername"], json!("***.org"));
    assert_eq!(
        first_node["raw_config"]["plugin-opts"]["host"],
        json!("***.io")
    );
    assert_eq!(
        first_node["raw_config"]["ws-opts"]["headers"]["Host"],
        json!("***.com")
    );
    let full_json = serde_json::to_string(&full_out).unwrap();
    for leaked in ["demo-upstream", "demo-secret", "demo-cdn", "demo-edge"] {
        assert!(!full_json.contains(leaked), "full inspect leaked `{leaked}`");
    }

    let _ = std::fs::remove_dir_all(&temp_root);
}

#[tokio::test]
async fn share_send_ccsync_and_receive_dry_run_then_apply_merges_groups() {
    let sender_root = std::env::temp_dir().join(format!(
        "catcloud-cli-sync-sender-{}",
        std::process::id()
    ));
    let receiver_root = std::env::temp_dir().join(format!(
        "catcloud-cli-sync-receiver-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&sender_root);
    let _ = std::fs::remove_dir_all(&receiver_root);

    let sender_paths = AppPaths::from_data_dir(sender_root.clone(), true).expect("sender paths");
    let receiver_paths =
        AppPaths::from_data_dir(receiver_root.clone(), true).expect("receiver paths");

    {
        let mut db = open_storage(&sender_paths).expect("sender db");
        let sub = SubscriptionRecord {
            id: "sub-sync-src".to_string(),
            name: "Sync Source".to_string(),
            kind: SubscriptionKind::File,
            url_or_cmd: "local://demo".to_string(),
            ..Default::default()
        };
        db.upsert_subscription(&sub).unwrap();
        let node = ProxyNode {
            id: "node-sync-jp".to_string(),
            sub_id: sub.id.clone(),
            name: "JP-Sync-01".to_string(),
            protocol: "vless".to_string(),
            region_code: "JP".to_string(),
            server: "jp-sync.example.invalid".to_string(),
            port: 443,
            raw_config: serde_json::json!({
                "name": "JP-Sync-01",
                "type": "vless",
                "server": "jp-sync.example.invalid",
                "port": 443,
                "uuid": "00000000-0000-4000-8000-000000000011",
                "password": "node_sync_secret_pw"
            }),
            ..ProxyNode::default()
        };
        db.upsert_nodes_batch(&[node]).unwrap();
        let relay = PreAccelRelay {
            id: "relay-sync-cn".to_string(),
            name: "CN-Sync-443".to_string(),
            server: "198.51.100.77".to_string(),
            port: 443,
            protocol: "anytls".to_string(),
            password: "relay_sync_secret_pw".to_string(),
            ..PreAccelRelay::default()
        };
        db.upsert_preaccel_relay(&relay).unwrap();
        let mut grp = MultiGroup::default();
        grp.id = "grp-sync-ai".to_string();
        grp.name = "AI Sync Group".to_string();
        grp.member_node_ids = vec!["node-sync-jp".to_string()];
        grp.active_node_id = Some("node-sync-jp".to_string());
        db.upsert_multi_group(&grp).unwrap();
    }

    let ccsync_path = sender_root.join("export.ccsync");
    let send_args = ShareSendArgs {
        name: "Device Sync Pack".to_string(),
        description: Some("CLI roundtrip".to_string()),
        node_ids: None,
        sub_id: Some("sub-sync-src".to_string()),
        all_nodes: false,
        relay_ids: None,
        all_relays: true,
        no_groups: false,
        endpoint: None,
        bind: "127.0.0.1".to_string(),
        port: 0,
        ttl: 60,
        allow_multiple: false,
        push_uri: None,
        push_addr: None,
        pin: None,
        ccsync_output: Some(ccsync_path.clone()),
        no_qr: true,
    };
    let (send_out, _) =
        execute_share_send_ccsync(&sender_paths, &send_args, &ccsync_path).expect("ccsync send");
    assert_eq!(send_out["ok"], json!(true));
    assert_eq!(send_out["node_count"], json!(1));
    assert_eq!(send_out["relay_count"], json!(1));
    assert_eq!(send_out["group_count"], json!(1));
    let key_uri = send_out["key_uri"].as_str().expect("key_uri").to_string();
    assert!(key_uri.starts_with("catcloud://sync/v1?role=file_key"));

    // 1. Default dry-run receive must redact secrets and NOT mutate receiver storage.
    let dry_args = ShareReceiveArgs {
        source: None,
        uri: None,
        addr: None,
        pin: None,
        ccsync: Some(ccsync_path.clone()),
        key: Some(key_uri.clone()),
        password: None,
        listen: false,
        bind: "127.0.0.1".to_string(),
        port: 0,
        endpoint: None,
        ttl: 60,
        no_qr: true,
        dry_run: false,
        apply: false,
        target_sub: None,
        name: None,
        mode: "merge".to_string(),
        no_nodes: false,
        no_relays: false,
        no_groups: false,
    };
    let zip_bytes =
        open_cli_ccsync_file(&ccsync_path, Some(&key_uri), None).expect("open ccsync");
    let (dry_out, _) = execute_share_receive_from_zip_bytes(
        &receiver_paths,
        &dry_args,
        &zip_bytes,
        "export.ccsync",
    )
    .expect("dry-run receive");
    assert_eq!(dry_out["dry_run"], json!(true));
    assert_eq!(dry_out["applied"], json!(false));
    assert_eq!(dry_out["would_import_nodes"], json!(1));
    assert_eq!(dry_out["would_import_relays"], json!(1));
    assert_eq!(dry_out["would_import_groups"], json!(1));
    assert_eq!(dry_out["nodes"][0]["raw_config"]["password"], json!("<REDACTED>"));
    assert_eq!(dry_out["relays"][0]["password"], json!("<REDACTED>"));
    {
        let rx_db = open_storage(&receiver_paths).expect("rx db");
        assert_eq!(rx_db.list_nodes().unwrap().len(), 0);
        assert_eq!(rx_db.list_preaccel_relays(false).unwrap().len(), 0);
        assert_eq!(rx_db.list_multi_groups().unwrap().len(), 0);
    }

    // 2. Apply receive persists nodes, relays, and smart multi-groups.
    let mut apply_args = dry_args;
    apply_args.apply = true;
    let (apply_out, _) = execute_share_receive_from_zip_bytes(
        &receiver_paths,
        &apply_args,
        &zip_bytes,
        "export.ccsync",
    )
    .expect("apply receive");
    assert_eq!(apply_out["applied"], json!(true));
    assert_eq!(apply_out["imported_nodes"], json!(1));
    assert_eq!(apply_out["imported_relays"], json!(1));
    assert_eq!(apply_out["imported_groups"], json!(1));
    {
        let rx_db = open_storage(&receiver_paths).expect("rx db");
        assert_eq!(rx_db.list_nodes().unwrap().len(), 1);
        assert_eq!(rx_db.list_preaccel_relays(false).unwrap().len(), 1);
        let groups = rx_db.list_multi_groups().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].name, "AI Sync Group");
        assert_eq!(groups[0].member_node_ids.len(), 1);
    }

    // 3. LAN HTTP pull roundtrip via LanSyncSendServer + fetch_sync_bundle_via_uri
    let (built_zip, _, _) =
        build_cli_sync_export_zip(&sender_paths, &send_args).expect("build zip");
    let mut srv = LanSyncSendServer::start(
        built_zip.clone(),
        LanSyncServerOptions {
            bind_host: "127.0.0.1".to_string(),
            bind_port: 0,
            custom_endpoint: None,
            ttl_secs: 60,
            allow_multiple: false,
        },
    )
    .await
    .expect("start lan send");
    let fetched = fetch_sync_bundle_via_uri(&srv.info().uri)
        .await
        .expect("fetch via uri");
    assert_eq!(fetched, built_zip);
    srv.cancel().await;

    let _ = std::fs::remove_dir_all(&sender_root);
    let _ = std::fs::remove_dir_all(&receiver_root);
}

#[tokio::test]
async fn issue4_cli_validate_skips_relay_direct_when_preaccel_off_and_repair_rules_heals_legacy() {
    let temp_root = std::env::temp_dir().join(format!(
        "catcloud-cli-issue4-dirty-{}-{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");

    // 1. Seed a dirty third-party Clash YAML file with 10 DIRECT rules + 25 rules targeting
    //    non-existent group "节点列表" + MATCH, plus an enabled relay while preaccel is OFF.
    let dirty_yaml_path = temp_root.join("old_client.yaml");
    let mut yaml = String::from(
        "proxies:\n  - name: Dirty-SG-01\n    type: ss\n    server: 198.51.100.88\n    port: 443\n    cipher: aes-128-gcm\n    password: demo\nproxy-groups:\n  - name: 节点列表\n    type: select\n    proxies: [Dirty-SG-01]\nrules:\n",
    );
    for i in 0..10 {
        yaml.push_str(&format!("  - DOMAIN-SUFFIX,cn-{i}.cn,DIRECT\n"));
    }
    for i in 0..25 {
        yaml.push_str(&format!("  - DOMAIN-SUFFIX,app-{i}.example.com,节点列表\n"));
    }
    yaml.push_str("  - MATCH,节点列表\n");
    std::fs::write(&dirty_yaml_path, yaml).expect("write dirty yaml");

    // Add an enabled relay while cfg.preaccel.enabled == false
    {
        let db = open_storage(&paths).expect("open db");
        let relay = PreAccelRelay {
            id: "relay-off-test".to_string(),
            name: "Disabled PreAccel Relay".to_string(),
            provider: "aliyun".to_string(),
            region: "CN-SH".to_string(),
            protocol: "anytls".to_string(),
            server: "203.0.113.55".to_string(),
            port: 443,
            password: "secret-demo-password".to_string(),
            skip_cert_verify: true,
            enabled: true,
            ..Default::default()
        };
        db.upsert_preaccel_relay(&relay).expect("upsert relay");
    }
    let mut cfg = config::load_or_init(&paths).expect("load cfg");
    cfg.preaccel.enabled = false;
    cfg.proxy_mode = ProxyMode::Global;
    config::save(&paths, &cfg).expect("save cfg");

    // 2. Migrate with --apply --include-rules: must filter the 25 dangling rules, keep 10 DIRECT,
    //    create default group, and pass `config validate` with ZERO `missing_relay_direct_rule`!
    dispatch(
        &paths,
        true,
        Commands::Node {
            action: NodeCommand::Migrate(NodeMigrateArgs {
                scan: false,
                file: Some(dirty_yaml_path.clone()),
                apply: true,
                include_rules: true,
            }),
        },
    )
    .await
    .expect("migrate dirty yaml with rules");

    let (ok_after_migrate, val_json, _) =
        build_config_validate_payload(&paths).await.expect("validate after migrate");
    assert!(
        ok_after_migrate,
        "config validate must pass when preaccel=false and migrated dangling rules were filtered: {val_json}"
    );
    let static_issues = val_json["static_validation"]["issues"]
        .as_array()
        .expect("issues array");
    assert!(
        !static_issues
            .iter()
            .any(|i| i["code"] == "missing_relay_direct_rule"),
        "must not emit missing_relay_direct_rule when preaccel is disabled: {static_issues:?}"
    );

    let sub_id = {
        let db = open_storage(&paths).unwrap();
        assert!(!db.list_multi_groups().unwrap().is_empty());
        db.list_subscriptions().unwrap()[0].id.clone()
    };
    let cfg_mid = config::load_or_init(&paths).unwrap();
    assert_eq!(
        cfg_mid.rules_override.global_prepend_rules.len()
            + cfg_mid.rules_override.global_append_rules.len(),
        10
    );

    // 3. Removing the migrated subscription cascades and cleans up all 10 imported rules.
    dispatch(
        &paths,
        true,
        Commands::Sub {
            action: SubCommand::Remove { sub_id },
        },
    )
    .await
    .expect("remove migrated subscription");
    let cfg_after_del = config::load_or_init(&paths).unwrap();
    assert!(
        cfg_after_del.rules_override.global_prepend_rules.is_empty()
            && cfg_after_del.rules_override.global_append_rules.is_empty(),
        "deleting migrated sub must remove its bound rules"
    );

    // 4. Simulate legacy v0.1.1 config with 25 leftover dangling rules -> validate fails with
    //    concise Chinese summary -> `config repair-rules --mode remove` heals it to 0 dangling.
    let mut legacy_cfg = config::load_or_init(&paths).unwrap();
    for i in 0..25 {
        legacy_cfg
            .rules_override
            .global_append_rules
            .push(format!("DOMAIN-SUFFIX,leftover-{i}.example.com,节点列表"));
    }
    config::save(&paths, &legacy_cfg).unwrap();

    let (ok_legacy, legacy_json, _) =
        build_config_validate_payload(&paths).await.expect("validate legacy dirty cfg");
    assert!(!ok_legacy);
    assert_eq!(legacy_json["dangling_rules_audit"]["total_dangling"], 25);
    let summary_zh = legacy_json["static_validation_summary_zh"]
        .as_str()
        .unwrap_or("");
    assert!(
        summary_zh.contains("25 条") && summary_zh.contains("节点列表"),
        "expected concise zh summary, got: {summary_zh}"
    );

    dispatch(
        &paths,
        true,
        Commands::Config {
            action: ConfigCommand::RepairRules {
                mode: "remove".to_string(),
                target: None,
                dry_run: false,
            },
        },
    )
    .await
    .expect("repair dangling rules via CLI");

    let (ok_healed, _, _) =
        build_config_validate_payload(&paths).await.expect("validate after repair");
    assert!(ok_healed, "config validate must pass after repair-rules");

    let _ = std::fs::remove_dir_all(&temp_root);
}

#[test]
fn stage26_cli_rule_prefix_and_match_rules_parser_preserve_composite_and_regex_rules() {
    for prefix in [
        "PROCESS-NAME-REGEX",
        "PROCESS-PATH-REGEX",
        "IP-SUFFIX",
        "IP-ASN",
        "UID",
        "IN-TYPE",
        "IN-USER",
        "IN-NAME",
        "SUB-RULE",
        "RULE-SET",
    ] {
        assert!(
            looks_like_clash_rule_prefix(prefix),
            "expected `{prefix}` to be recognized as Clash rule prefix"
        );
    }

    // Composite AND rules and regex rules with `{1,3}` commas must never be split on bare `,`.
    assert_eq!(
        parse_group_match_rules_arg("AND,((PROCESS-NAME,QQ.exe),(DST-PORT,15000)),DIRECT"),
        vec!["AND,((PROCESS-NAME,QQ.exe),(DST-PORT,15000)),DIRECT".to_string()]
    );
    assert_eq!(
        parse_group_match_rules_arg(r"DOMAIN-REGEX,^a{1,3}\.com$"),
        vec![r"DOMAIN-REGEX,^a{1,3}\.com$".to_string()]
    );
    assert_eq!(
        parse_group_match_rules_arg(r"PROCESS-NAME-REGEX,^qq{1,2}\.exe$"),
        vec![r"PROCESS-NAME-REGEX,^qq{1,2}\.exe$".to_string()]
    );
    assert_eq!(
        parse_group_match_rules_arg(
            r"AND,((PROCESS-NAME,QQ.exe),(DST-PORT,15000)),DIRECT;DOMAIN-REGEX,^a{1,3}\.com$;codeium.com"
        ),
        vec![
            "AND,((PROCESS-NAME,QQ.exe),(DST-PORT,15000)),DIRECT".to_string(),
            r"DOMAIN-REGEX,^a{1,3}\.com$".to_string(),
            "codeium.com".to_string(),
        ]
    );
    // Comma-separated bare domains continue to expand cleanly.
    assert_eq!(
        parse_group_match_rules_arg("codeium.com,windsurf.com,devin.ai"),
        vec![
            "codeium.com".to_string(),
            "windsurf.com".to_string(),
            "devin.ai".to_string(),
        ]
    );
}

#[test]
fn stage26_group_create_policy_independent_routing_hard_gate_and_rename_cascade() {
    let temp_root = std::env::temp_dir().join(format!(
        "catcloud-cli-stage26-group-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");

    // 1. Invalid `--hard-gate` formula must be rejected before writing storage.
    let bad_gate = execute_group_create(
        &paths,
        GroupCreateArgs {
            id: "grp-bad-gate".to_string(),
            name: Some("Bad".to_string()),
            mode: None,
            formula: None,
            fallback: None,
            switch_mode: None,
            nodes: None,
            independent_routing: Some(true),
            match_rules: None,
            add_match_rule: Vec::new(),
            hard_gate: vec!["not_a_valid_formula ((( ".to_string()],
        },
    );
    assert!(bad_gate.is_err());

    // 2. Create independent-routing group with match rules + hard gates.
    let (created_out, _) = execute_group_create(
        &paths,
        GroupCreateArgs {
            id: "grp-wsf".to_string(),
            name: Some("WSF-Old".to_string()),
            mode: None,
            formula: None,
            fallback: None,
            switch_mode: None,
            nodes: Some("n1".to_string()),
            independent_routing: Some(true),
            match_rules: Some("DOMAIN-SUFFIX,codeium.com;DOMAIN-SUFFIX,windsurf.com".to_string()),
            add_match_rule: vec![
                "AND,((PROCESS-NAME,QQ.exe),(DST-PORT,15000)),DIRECT".to_string(),
                r"DOMAIN-REGEX,^a{1,3}\.com$".to_string(),
            ],
            hard_gate: vec!["site_unlocked(\"windsurf\") == 1".to_string()],
        },
    )
    .expect("create wsf independent group");
    assert_eq!(created_out["created"], json!(true));
    assert_eq!(created_out["group"]["independent_routing"], json!(true));
    assert_eq!(
        created_out["group"]["hard_gates"],
        json!(["site_unlocked(\"windsurf\") == 1"])
    );
    assert_eq!(
        created_out["group"]["match_rules"],
        json!([
            "DOMAIN-SUFFIX,codeium.com",
            "DOMAIN-SUFFIX,windsurf.com",
            "AND,((PROCESS-NAME,QQ.exe),(DST-PORT,15000)),DIRECT",
            r"DOMAIN-REGEX,^a{1,3}\.com$",
        ])
    );

    // 3. Seed global rules targeting `WSF-Old`, then rename to `WSF (日本)` and verify cascade!
    let mut cfg = config::load_or_init(&paths).expect("load cfg");
    cfg.rules_override.global_prepend_rules.push(
        "AND,((NETWORK,TCP),(DST-PORT,443)),WSF-Old".to_string(),
    );
    cfg.rules_override.global_append_rules.push(
        "DOMAIN-SUFFIX,devin.ai,WSF-Old".to_string(),
    );
    config::save(&paths, &cfg).expect("save cfg");

    let (renamed_out, _) = execute_group_create(
        &paths,
        GroupCreateArgs {
            id: "grp-wsf".to_string(),
            name: Some("WSF (日本)".to_string()),
            mode: None,
            formula: None,
            fallback: None,
            switch_mode: None,
            nodes: None,
            independent_routing: None,
            match_rules: None,
            add_match_rule: Vec::new(),
            hard_gate: Vec::new(),
        },
    )
    .expect("rename group with cascade");
    assert_eq!(renamed_out["cascaded_global_rules"], json!(2));
    let cfg_after = config::load_or_init(&paths).expect("reload cfg");
    assert!(
        cfg_after
            .rules_override
            .global_prepend_rules
            .contains(&"AND,((NETWORK,TCP),(DST-PORT,443)),WSF (日本)".to_string())
    );
    assert!(
        cfg_after
            .rules_override
            .global_append_rules
            .contains(&"DOMAIN-SUFFIX,devin.ai,WSF (日本)".to_string())
    );

    // 4. `group policy --independent-routing false` toggles and persists.
    let (pol_out, _) = execute_group_policy(
        &paths,
        GroupPolicyArgs {
            group_id: "grp-wsf".to_string(),
            formula: None,
            fallback: None,
            switch_mode: None,
            hard_gate: Vec::new(),
            match_rules: None,
            add_match_rule: Vec::new(),
            clear_match_rules: false,
            independent_routing: Some(false),
        },
    )
    .expect("toggle independent_routing via policy");
    assert_eq!(pol_out["group"]["independent_routing"], json!(false));

    let _ = std::fs::remove_dir_all(&temp_root);
}

#[tokio::test]
async fn stage26_net_match_process_args_redaction_roles_and_proxy_override_doctor() {
    let temp_root = std::env::temp_dir().join(format!(
        "catcloud-cli-stage26-netmatch-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    let paths = AppPaths::from_data_dir(temp_root.clone(), true).expect("init temp paths");

    let db = open_storage(&paths).expect("open db");
    db.upsert_subscription(&SubscriptionRecord {
        id: "sub-1".to_string(),
        name: "Stage26 Sub".to_string(),
        kind: SubscriptionKind::File,
        url_or_cmd: "stage26.yaml".to_string(),
        ..Default::default()
    })
    .unwrap();
    db.upsert_node(&ProxyNode {
        id: "n-tw".to_string(),
        sub_id: "sub-1".to_string(),
        name: "TW-Clean-01".to_string(),
        protocol: "trojan".to_string(),
        server: "198.51.100.44".to_string(),
        port: 443,
        raw_config: json!({
            "name": "TW-Clean-01",
            "type": "trojan",
            "server": "198.51.100.44",
            "port": 443,
            "password": "demo"
        }),
        ..ProxyNode::default()
    })
    .unwrap();
    db.upsert_multi_group(&MultiGroup {
        id: "grp-primary".to_string(),
        name: "Main-Group".to_string(),
        member_node_ids: vec!["n-tw".to_string()],
        independent_routing: false,
        ..MultiGroup::default()
    })
    .unwrap();
    db.upsert_multi_group(&MultiGroup {
        id: "grp-wsf".to_string(),
        name: "WSF-Dedicated".to_string(),
        member_node_ids: vec!["n-tw".to_string()],
        match_rules: vec!["DOMAIN-SUFFIX,codeium.com".to_string()],
        independent_routing: true,
        ..MultiGroup::default()
    })
    .unwrap();
    drop(db);

    let mut cfg = config::load_or_init(&paths).expect("load cfg");
    cfg.active_group_id = Some("grp-primary".to_string());
    cfg.rules_override.global_prepend_rules.push(
        "AND,((PROCESS-NAME,QQ.exe),(DST-PORT,15000)),DIRECT".to_string(),
    );
    config::save(&paths, &cfg).expect("save cfg");

    // 1. Domain matching independent_routing group reports role = "independent_routing".
    let (wsf_match, _) =
        build_net_match_payload(&paths, "server.codeium.com", "tcp", 443, None, None)
            .await
            .expect("match wsf");
    assert_eq!(wsf_match["policy"], json!("WSF-Dedicated"));
    assert_eq!(
        wsf_match["resolved_group"]["independent_routing"],
        json!(true)
    );
    assert_eq!(
        wsf_match["resolved_group"]["role"],
        json!("independent_routing")
    );

    // 2. Unmatched overseas domain falls back to primary group with role = "primary_default".
    let (primary_match, _) =
        build_net_match_payload(&paths, "api.openai.com", "tcp", 443, None, None)
            .await
            .expect("match primary");
    assert_eq!(primary_match["policy"], json!("Main-Group"));
    assert_eq!(
        primary_match["resolved_group"]["independent_routing"],
        json!(false)
    );
    assert_eq!(
        primary_match["resolved_group"]["role"],
        json!("primary_default")
    );

    // 3. Process name + port hits composite AND rule; process_path basename fallback works
    //    and username inside `process_path` is strictly redacted in JSON output.
    let (qq_by_name, _) = build_net_match_payload(
        &paths,
        "203.0.113.10",
        "tcp",
        15000,
        Some("QQ.exe"),
        None,
    )
    .await
    .expect("match qq by name");
    assert_eq!(qq_by_name["policy"], json!("DIRECT"));
    assert_eq!(qq_by_name["matched_rule_type"], json!("AND"));
    assert_eq!(qq_by_name["query"]["process_name"], json!("QQ.exe"));

    let sample_user_path = format!(
        "{}:\\{}\\SecretAlice\\AppData\\Local\\Tencent\\QQNT\\QQ.exe",
        "C", "Users"
    );
    let (qq_by_path, _) = build_net_match_payload(
        &paths,
        "203.0.113.10",
        "tcp",
        15000,
        None,
        Some(&sample_user_path),
    )
    .await
    .expect("match qq by path");
    assert_eq!(qq_by_path["policy"], json!("DIRECT"));
    assert_eq!(qq_by_path["matched_rule_type"], json!("AND"));
    let redacted_path = qq_by_path["query"]["process_path"].as_str().unwrap_or("");
    assert!(
        !redacted_path.contains("SecretAlice"),
        "process_path must redact local username, got: {redacted_path}"
    );
    assert!(
        redacted_path.contains("<USER>"),
        "expected <USER> placeholder in redacted process_path, got: {redacted_path}"
    );

    // 4. Windows ProxyOverride diagnostic helper detects bare `::1` and `/` CIDR and emits
    //    Schannel 0x80092013 warning, while clean bracketed `[::1]` produces zero warnings.
    let (bad_entries, bad_warn) =
        inspect_windows_proxy_override_warnings("localhost;127.0.0.1;::1;10.0.0.0/8;<local>");
    assert!(bad_entries.iter().any(|e| e == "::1"));
    assert!(bad_entries.iter().any(|e| e.contains('/')));
    let warn_text = bad_warn.expect("expected Schannel warning");
    assert!(warn_text.contains("0x80092013"));
    assert!(warn_text.contains("Schannel"));

    let (clean_entries, clean_warn) = inspect_windows_proxy_override_warnings(
        "localhost;127.0.0.1;[::1];127.*;10.*;192.168.*;<local>",
    );
    assert!(clean_entries.is_empty());
    assert!(clean_warn.is_none());

    let _ = std::fs::remove_dir_all(&temp_root);
}
