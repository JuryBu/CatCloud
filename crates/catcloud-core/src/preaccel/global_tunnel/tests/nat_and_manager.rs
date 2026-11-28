#[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
use super::super::manager::enforce_self_test_strict_204;
use super::super::manager::{WinDivertRuntimeFingerprint, should_skip_windivert_restart};
use super::super::nat_packet::CN_IPV4_RANGES;
use super::super::*;
use super::{sample_anytls_relay_with_dirty_sni, sample_vless_relay_with_dirty_sni};
use crate::models::{AppConfig, GlobalPreAccelScope};
use crate::paths::AppPaths;
use crate::preaccel::generator::PREACCEL_SELECT_GROUP;
use crate::process_guard::JobGuard;
use serde_yaml_ng::Value;
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[test]
fn windivert_proxy_candidates_dedup_and_system_proxy_url_formatting() {
    assert_eq!(normalize_windivert_proxy_candidates(&[]), vec![None]);

    let raw = vec![
        Some(" http://127.0.0.1:7890/ ".to_string()),
        Some("HTTP://127.0.0.1:7890".to_string()),
        Some("http://127.0.0.1:7897".to_string()),
        None,
        Some("   ".to_string()),
        None,
    ];
    assert_eq!(
        normalize_windivert_proxy_candidates(&raw),
        vec![
            Some("http://127.0.0.1:7890/".to_string()),
            Some("http://127.0.0.1:7897".to_string()),
            None,
        ]
    );

    let enabled_v4 = crate::platform::SystemProxySpec {
        enabled: true,
        host: "127.0.0.1".to_string(),
        port: 10809,
        bypass: Vec::new(),
        pac_url: None,
    };
    assert_eq!(
        format_system_proxy_url(&enabled_v4).as_deref(),
        Some("http://127.0.0.1:10809")
    );

    let enabled_v6 = crate::platform::SystemProxySpec {
        enabled: true,
        host: "::1".to_string(),
        port: 10809,
        bypass: Vec::new(),
        pac_url: None,
    };
    assert_eq!(
        format_system_proxy_url(&enabled_v6).as_deref(),
        Some("http://[::1]:10809")
    );

    let pac_only = crate::platform::SystemProxySpec {
        enabled: true,
        host: "127.0.0.1".to_string(),
        port: 7890,
        bypass: Vec::new(),
        pac_url: Some("http://127.0.0.1:17891/proxy.pac".to_string()),
    };
    assert_eq!(format_system_proxy_url(&pac_only), None);

    let disabled = crate::platform::SystemProxySpec {
        enabled: false,
        host: "127.0.0.1".to_string(),
        port: 7890,
        bypass: Vec::new(),
        pac_url: None,
    };
    assert_eq!(format_system_proxy_url(&disabled), None);
}

#[test]
fn excluded_pid_tracker_merges_descendant_tree_and_main_core_without_clobbering() {
    let self_pid = std::process::id();
    let tunnel_pid = self_pid.wrapping_add(11_001).max(100);
    let main_pid = self_pid.wrapping_add(22_001).max(200);
    let webview_pid = self_pid.wrapping_add(33_001).max(300);
    let probe_pid = self_pid.wrapping_add(33_002).max(301);

    let tracker = ExcludedPidTracker::new(self_pid, Some(tunnel_pid), [], Some(main_pid));
    tracker.sync_descendant_pids([webview_pid, probe_pid, 0].into_iter().collect());

    let snap1 = tracker.snapshot_active();
    assert!(snap1.contains(&self_pid));
    assert!(snap1.contains(&tunnel_pid));
    assert!(snap1.contains(&main_pid));
    assert!(snap1.contains(&webview_pid));
    assert!(snap1.contains(&probe_pid));
    assert!(!snap1.contains(&0));

    // Clearing main_core_pid must keep descendant tree and pinned PIDs intact.
    tracker.sync_main_core_pid(None);
    let snap2 = tracker.snapshot_active();
    assert!(snap2.contains(&self_pid));
    assert!(snap2.contains(&tunnel_pid));
    assert!(snap2.contains(&webview_pid));
    assert!(snap2.contains(&probe_pid));
    assert!(!snap2.contains(&main_pid));

    // Refreshing descendant tree replaces stale descendants while retaining pinned PIDs.
    tracker.sync_descendant_pids([webview_pid].into_iter().collect());
    let snap3 = tracker.snapshot_active();
    assert!(snap3.contains(&self_pid));
    assert!(snap3.contains(&tunnel_pid));
    assert!(snap3.contains(&webview_pid));
    assert!(!snap3.contains(&probe_pid));
}

#[test]
fn loopback_packet_rewrite_mss_clamp_and_interface_binding_work() {
    // 1. Standalone YAML writes `interface-name` when a physical NIC is provided.
    let cfg = AppConfig::default();
    let relays = vec![sample_anytls_relay_with_dirty_sni()];
    let yaml_bound = compile_standalone_preaccel_yaml_with_interface(
        &cfg,
        &relays,
        17909,
        Some("WLAN"),
    )
    .expect("compile with physical interface");
    let doc: Value = serde_yaml_ng::from_str(&yaml_bound).expect("valid yaml");
    assert_eq!(doc["interface-name"].as_str(), Some("WLAN"));

    let yaml_unbound = compile_standalone_preaccel_yaml_with_interface(
        &cfg,
        &relays,
        17909,
        Some("   "),
    )
    .expect("compile with blank interface");
    let doc_unbound: Value = serde_yaml_ng::from_str(&yaml_unbound).expect("valid yaml");
    assert!(doc_unbound.get("interface-name").is_none());

    // 2. Outbound packet rewrite to 127.0.0.1 loopback + return packet restoration + MSS clamping.
    let mut pkt = [0u8; 44]; // 20B IPv4 + 24B TCP (including 4B MSS option)
    pkt[0] = 0x45;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&[192, 168, 2, 10]);
    pkt[16..20].copy_from_slice(&[203, 0, 113, 44]);
    pkt[20..22].copy_from_slice(&51234u16.to_be_bytes());
    pkt[22..24].copy_from_slice(&2053u16.to_be_bytes());
    pkt[32] = 6 << 4; // TCP data offset = 24 bytes
    pkt[33] = Ipv4TcpMeta::FLAG_SYN | Ipv4TcpMeta::FLAG_ACK;
    // TCP Option Kind=2 (MSS), Len=4, Value=65495 (Windows loopback giant MSS)
    pkt[40] = 2;
    pkt[41] = 4;
    pkt[42..44].copy_from_slice(&65495u16.to_be_bytes());

    assert!(rewrite_ipv4_tcp_to_loopback(&mut pkt, 20, 48888));
    let lo_meta = parse_ipv4_tcp_packet(&pkt).expect("parse loopback packet");
    assert_eq!(lo_meta.src_ip, Ipv4Addr::LOCALHOST);
    assert_eq!(lo_meta.dst_ip, Ipv4Addr::LOCALHOST);
    assert_eq!(lo_meta.src_port, 51234);
    assert_eq!(lo_meta.dst_port, 48888);

    // Simulate return packet from 127.0.0.1:48888 -> 127.0.0.1:51234
    pkt[20..22].copy_from_slice(&48888u16.to_be_bytes());
    pkt[22..24].copy_from_slice(&51234u16.to_be_bytes());
    assert!(rewrite_ipv4_tcp_from_loopback(
        &mut pkt,
        20,
        Ipv4Addr::new(203, 0, 113, 44),
        2053,
        Ipv4Addr::new(192, 168, 2, 10),
    ));
    assert!(clamp_tcp_syn_mss(&mut pkt, 20, 1460));
    assert!(!clamp_tcp_syn_mss(&mut pkt, 20, 1460)); // already clamped

    let ret_meta = parse_ipv4_tcp_packet(&pkt).expect("parse restored packet");
    assert_eq!(ret_meta.src_ip, Ipv4Addr::new(203, 0, 113, 44));
    assert_eq!(ret_meta.dst_ip, Ipv4Addr::new(192, 168, 2, 10));
    assert_eq!(ret_meta.src_port, 2053);
    assert_eq!(ret_meta.dst_port, 51234);
    assert_eq!(u16::from_be_bytes([pkt[42], pkt[43]]), 1460);
}

#[test]
fn security_product_classification_and_tailored_guidance_cover_huorong_360_and_defender() {
    let procs = vec![
        "MsMpEng.exe".to_string(),
        "HipsDaemon.exe".to_string(),
        "svchost.exe".to_string(),
    ];
    let products = classify_security_products_from_process_names(&procs);
    // Third-party security suite (Huorong) ranks ahead of Defender.
    assert_eq!(
        products,
        vec![
            "火绒安全".to_string(),
            "Windows 安全中心（Defender）".to_string()
        ]
    );
    let guide_hr = build_security_guidance(
        &products,
        Some(Path::new(r"C:\CatCloud\bin")),
        "self_test_blocked",
    );
    assert!(guide_hr.contains("火绒安全"));
    assert!(guide_hr.contains("信任区"));
    assert!(guide_hr.contains("重新探测"));

    let defender_only =
        classify_security_products_from_process_names(&["msmpeng.exe".to_string()]);
    assert_eq!(
        defender_only,
        vec!["Windows 安全中心（Defender）".to_string()]
    );
    let guide_def = build_security_guidance(
        &defender_only,
        Some(Path::new(r"C:\CatCloud\bin")),
        "download_or_write",
    );
    assert!(guide_def.contains("Windows 安全中心"));
    assert!(guide_def.contains("排除项"));

    let suite_360 =
        classify_security_products_from_process_names(&["360Tray.exe".to_string()]);
    assert_eq!(suite_360, vec!["360 安全卫士".to_string()]);
    let guide_360 = build_security_guidance(&suite_360, None, "driver_load");
    assert!(guide_360.contains("360 安全卫士"));

    // Self-test probe URL list strictly retains HTTP non-443 endpoints and deduplicates.
    let urls = build_self_test_probe_urls("https://example.com:443/check");
    assert_eq!(urls.len(), 2);
    assert!(urls[0].starts_with("http://"));
    assert!(urls[1].starts_with("http://"));
}

#[tokio::test]
async fn self_test_redirected_stream_increments_counter_without_polluting_user_metrics() {
    let mock_socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_port = mock_socks.local_addr().unwrap().port();
    let socks_task = tokio::spawn(async move {
        let (mut sock, _) = mock_socks.accept().await.unwrap();
        let mut greet = [0u8; 3];
        sock.read_exact(&mut greet).await.unwrap();
        sock.write_all(&[0x05, 0x00]).await.unwrap();
        let mut req = [0u8; 10];
        sock.read_exact(&mut req).await.unwrap();
        sock.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        let _ = sock.read(&mut buf).await;
        sock.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let _ = sock.shutdown().await;
    });

    let redir_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let redir_addr = redir_listener.local_addr().unwrap();
    let nat_table = Arc::new(NatTable::new(16, Duration::from_secs(60)));
    let metrics = Arc::new(GlobalPreAccelMetrics::default());
    let accepted_counter = Arc::new(AtomicU64::new(0));
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let nat_c = Arc::clone(&nat_table);
    let met_c = Arc::clone(&metrics);
    let acc_c = Arc::clone(&accepted_counter);
    let accept_task = tokio::spawn(async move {
        let (stream, peer) = redir_listener.accept().await.unwrap();
        forward_redirected_stream(stream, peer, socks_port, nat_c, met_c, shutdown_rx, Some(acc_c))
            .await;
    });

    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        .unwrap();
    let local_ep = match sock.local_addr().unwrap() {
        SocketAddr::V4(v4) => (*v4.ip(), v4.port()),
        _ => unreachable!(),
    };
    nat_table.insert(
        local_ep,
        NatEntry {
            orig_src_ip: Ipv4Addr::new(192, 0, 2, 10),
            orig_dst_ip: Ipv4Addr::new(203, 0, 113, 80),
            orig_dst_port: 80,
            if_idx: 1,
            sub_if_idx: 0,
            owner_pid: std::process::id(),
            process_name: "catcloud-desktop.exe".to_string(),
            detected_by: SELF_TEST_DETECTED_BY.to_string(),
            last_seen: Instant::now(),
            closing_since: None,
        },
    );

    let mut client = sock.connect(redir_addr).await.unwrap();
    client
        .write_all(b"GET /generate_204 HTTP/1.1\r\nHost: test\r\n\r\n")
        .await
        .unwrap();
    let mut resp = [0u8; 64];
    let n = client.read(&mut resp).await.unwrap();
    assert!(String::from_utf8_lossy(&resp[..n]).contains("204"));
    drop(client);
    let _ = socks_task.await;
    let _ = accept_task.await;

    assert_eq!(accepted_counter.load(Ordering::SeqCst), 1);
    assert_eq!(metrics.total_connections.load(Ordering::Relaxed), 0);
    assert!(metrics.recent_processes_snapshot().is_empty());
    assert!(metrics.snapshot().is_empty());
}

#[test]
fn standalone_preaccel_yaml_excludes_ip_and_domain_probe_url_from_direct_rules() {
    let mut cfg = AppConfig::default();
    cfg.preaccel.enabled = true;
    cfg.preaccel.probe_url = "http://203.0.113.204/generate_204".to_string();
    cfg.preaccel.fallback_probe_url = "http://connect.rom.miui.com/generate_204".to_string();
    cfg.preaccel.campus_direct_domains = vec!["portal.campus.example.edu".to_string()];

    let mut domain_relay = sample_vless_relay_with_dirty_sni();
    domain_relay.id = "relay-domain-443".to_string();
    domain_relay.server = "relay-cn.example.com".to_string();
    domain_relay.priority = 30;

    let relays = vec![sample_anytls_relay_with_dirty_sni(), domain_relay];
    let yaml_str =
        compile_standalone_preaccel_yaml_with_interface(&cfg, &relays, 17912, Some("WLAN"))
            .expect("compile standalone yaml");
    let doc: Value = serde_yaml_ng::from_str(&yaml_str).expect("parse standalone yaml");
    let rules: Vec<&str> = doc["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();

    assert!(rules.contains(&"IP-CIDR,203.0.113.10/32,DIRECT,no-resolve"));
    assert!(rules.contains(&"DOMAIN,relay-cn.example.com,DIRECT"));
    assert!(!rules.iter().any(|r| r.contains("203.0.113.204")));
    assert!(!rules.iter().any(|r| {
        let lower = r.to_ascii_lowercase();
        lower.contains("hicloud.com")
            || lower.contains("miui.com")
            || lower.contains("campus.example.edu")
    }));
    let expected_match = format!("MATCH,{PREACCEL_SELECT_GROUP}");
    assert_eq!(rules.last().copied(), Some(expected_match.as_str()));
}

#[test]
fn is_physical_nic_descriptor_allows_pppoe_and_cellular_while_blocking_vpns_and_miniports() {
    // Real physical NICs: Ethernet (6), Wi-Fi (71), PPPoE dial-up (23), 4G/5G WWAN (243/244).
    assert!(is_physical_nic_descriptor(
        6,
        5,
        "Intel(R) Ethernet Controller I225-V"
    ));
    assert!(is_physical_nic_descriptor(
        71,
        4,
        "Qualcomm FastConnect 6900 Wi-Fi 6E"
    ));
    assert!(is_physical_nic_descriptor(23, 5, "WAN Miniport (PPPOE)"));
    assert!(is_physical_nic_descriptor(
        23,
        5,
        "WAN Miniport (PPPoE) 宽带连接"
    ));
    assert!(is_physical_nic_descriptor(
        243,
        5,
        "Qualcomm Snapdragon X55 5G Modem"
    ));
    assert!(is_physical_nic_descriptor(
        244,
        4,
        "Fibocom L850-GL 4G LTE"
    ));

    // Non-PPPoE WAN Miniports and VPN dial-up protocols must stay strictly blocked.
    assert!(!is_physical_nic_descriptor(23, 5, "WAN Miniport (PPTP)"));
    assert!(!is_physical_nic_descriptor(23, 5, "WAN Miniport (L2TP)"));
    assert!(!is_physical_nic_descriptor(23, 5, "WAN Miniport (SSTP)"));
    assert!(!is_physical_nic_descriptor(23, 5, "WAN Miniport (IKEv2)"));
    assert!(!is_physical_nic_descriptor(23, 5, "WAN Miniport (IP)"));
    assert!(!is_physical_nic_descriptor(23, 5, "Corp L2TP Dialer"));
    assert!(!is_physical_nic_descriptor(23, 5, "WAN Miniport (PPPOE) VPN"));

    // Virtual / TUN / container / hypervisor adapters remain strictly blocked.
    assert!(!is_physical_nic_descriptor(6, 5, "Wintun Userspace Tunnel"));
    assert!(!is_physical_nic_descriptor(6, 5, "WireGuard Tunnel"));
    assert!(!is_physical_nic_descriptor(6, 5, "Clash Meta Adapter"));
    assert!(!is_physical_nic_descriptor(6, 5, "Mihomo TUN"));
    assert!(!is_physical_nic_descriptor(6, 5, "TAP-Windows Adapter V9"));
    assert!(!is_physical_nic_descriptor(6, 5, "VMware Network Adapter VMnet8"));
    assert!(!is_physical_nic_descriptor(6, 5, "VirtualBox Host-Only Ethernet"));
    assert!(!is_physical_nic_descriptor(243, 5, "Virtual Cellular VPN"));
    assert!(!is_physical_nic_descriptor(23, 2, "WAN Miniport (PPPOE)")); // oper_status down
}

#[test]
fn nat_table_closing_grace_blocks_port_reuse_cross_flow_and_remove_active_guards_closing() {
    assert_eq!(NAT_CLOSING_GRACE, Duration::from_secs(4));

    let table = NatTable::new(16, Duration::from_secs(60));
    let key = (Ipv4Addr::LOCALHOST, 52100);
    let src_a = Ipv4Addr::new(192, 0, 2, 10);
    let src_b = Ipv4Addr::new(192, 0, 2, 11);
    let dst_a = Ipv4Addr::new(203, 0, 113, 10);
    let dst_b = Ipv4Addr::new(203, 0, 113, 20);
    let now = Instant::now();

    table.insert(
        key,
        NatEntry {
            orig_src_ip: src_a,
            orig_dst_ip: dst_a,
            orig_dst_port: 8443,
            if_idx: 4,
            sub_if_idx: 0,
            owner_pid: 7001,
            process_name: "proxy-core.exe".to_string(),
            detected_by: "open_core_name".to_string(),
            last_seen: now,
            closing_since: None,
        },
    );

    // Active entry: mismatching 4-tuple cannot be removed by `remove_active_if_matching`.
    assert!(!table.remove_active_if_matching(&key, src_b, dst_a, 8443));
    assert!(!table.remove_active_if_matching(&key, src_a, dst_b, 8443));
    assert!(!table.remove_active_if_matching(&key, src_a, dst_a, 9443));
    assert!(table.get_and_touch(&key).is_some());

    // Transition to closing grace: `remove_active_if_matching` must refuse even exact 4-tuple.
    assert!(table.mark_closing_if_matching(&key, src_a, dst_a, 8443));
    assert!(!table.remove_active_if_matching(&key, src_a, dst_a, 8443));
    assert!(table.get_and_touch(&key).is_some());

    // Closing grace conflicts with any different 4-tuple reusing the ephemeral source port.
    assert!(table.has_active_conflict(&key, src_b, dst_a, 8443));
    assert!(table.has_active_conflict(&key, src_a, dst_b, 8443));
    assert!(table.has_active_conflict(&key, src_a, dst_a, 9443));
    assert!(!table.has_active_conflict(&key, src_a, dst_a, 8443));

    // Once the 4s closing grace elapses, conflict clears and the stale entry is evicted.
    table.insert(
        key,
        NatEntry {
            orig_src_ip: src_a,
            orig_dst_ip: dst_a,
            orig_dst_port: 8443,
            if_idx: 4,
            sub_if_idx: 0,
            owner_pid: 7001,
            process_name: "proxy-core.exe".to_string(),
            detected_by: "open_core_name".to_string(),
            last_seen: now,
            closing_since: Some(now - Duration::from_secs(5)),
        },
    );
    assert!(!table.has_active_conflict(&key, src_a, dst_b, 9443));
    assert!(table.is_empty());

    // Re-insert active entry and verify exact active removal works cleanly.
    table.insert(
        key,
        NatEntry {
            orig_src_ip: src_a,
            orig_dst_ip: dst_a,
            orig_dst_port: 8443,
            if_idx: 4,
            sub_if_idx: 0,
            owner_pid: 7001,
            process_name: "proxy-core.exe".to_string(),
            detected_by: "open_core_name".to_string(),
            last_seen: Instant::now(),
            closing_since: None,
        },
    );
    assert!(table.remove_active_if_matching(&key, src_a, dst_a, 8443));
    assert!(table.is_empty());
}

#[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
#[test]
fn locate_windivert_files_short_circuits_on_non_windows_x64() {
    let root = std::env::temp_dir().join(format!(
        "catcloud-wd-shortcircuit-{}",
        uuid::Uuid::new_v4()
    ));
    let paths = AppPaths::from_data_dir(root.join("data"), true).unwrap();
    std::fs::write(paths.bin_dir.join("WinDivert64.dll"), b"dll").unwrap();
    std::fs::write(paths.bin_dir.join("WinDivert64.sys"), b"sys").unwrap();

    assert!(locate_windivert_files(&paths, None).is_none());
    assert!(locate_windivert_paths(&paths, None).is_none());

    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn reverify_windivert_when_stopped_never_resurrects_runtime() {
    let root = std::env::temp_dir().join(format!(
        "catcloud-reverify-stopped-{}",
        uuid::Uuid::new_v4()
    ));
    let paths = AppPaths::from_data_dir(root.join("data"), true).unwrap();
    let job_guard = Arc::new(JobGuard::new().unwrap());
    let manager = GlobalPreAccelManager::new(paths, job_guard);
    let cfg = AppConfig::default();
    let relays = vec![sample_anytls_relay_with_dirty_sni()];

    let stopped = manager.stop().await.expect("stop idle manager");
    assert!(!stopped.running);
    assert_eq!(stopped.mode, "off");

    let reverified = manager
        .reverify_windivert(&cfg, &relays, &[])
        .await
        .expect("reverify stopped manager");
    assert!(!reverified.running);
    assert_eq!(reverified.mode, "off");

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn process_stats_dedup_by_lowercase_name_upgrades_detected_by_priority_and_prevents_active_leak()
{
    let metrics = GlobalPreAccelMetrics::default();

    // Unknown/empty labels normalize to lowest-priority `"runtime"` (0).
    metrics.record_process_connection_open(1000, "ProxyCore.exe", "");
    let snap0 = metrics.snapshot();
    assert_eq!(snap0.len(), 1);
    assert_eq!(snap0[0].detected_by, "runtime");

    // Same executable across different PIDs, casing, and detection labels must merge into one card
    // and monotonically promote priority: runtime(0) < scope_all(1) < manual(2) <
    // local_proxy_listener(3) < open_core_name(4) < system_proxy_host(5).
    metrics.record_process_connection_open(1001, "ProxyCore.exe", "scope_all");
    assert_eq!(metrics.snapshot()[0].detected_by, "scope_all");
    metrics.record_process_connection_open(1002, "proxycore.exe", "manual");
    assert_eq!(metrics.snapshot()[0].detected_by, "manual");
    metrics.record_process_connection_open(1003, "PROXYCORE.EXE", "local_proxy_listener");
    assert_eq!(metrics.snapshot()[0].detected_by, "local_proxy_listener");
    metrics.record_process_connection_open(1004, "proxycore.exe", "open_core_name");
    assert_eq!(metrics.snapshot()[0].detected_by, "open_core_name");
    metrics.record_process_connection_open(1005, "proxycore.exe", "system_proxy_host");
    assert_eq!(metrics.snapshot()[0].detected_by, "system_proxy_host");
    // Lower-priority subsequent open must NEVER downgrade `detected_by`.
    metrics.record_process_connection_open(1006, "proxycore.exe", "manual");
    metrics.record_process_bytes(1006, "proxycore.exe", "scope_all", 128, 256);

    let snap1 = metrics.snapshot();
    assert_eq!(snap1.len(), 1);
    assert_eq!(snap1[0].process_name, "ProxyCore.exe");
    assert_eq!(snap1[0].pid, 1006);
    assert_eq!(snap1[0].detected_by, "system_proxy_host");
    assert_eq!(snap1[0].active_connections, 7);
    assert_eq!(snap1[0].total_connections, 7);
    assert_eq!(snap1[0].tx_bytes, 128);
    assert_eq!(snap1[0].rx_bytes, 256);

    // Closing with old PIDs and old detection labels must still decrement cleanly to 0.
    for (pid, label) in [
        (1000, "runtime"),
        (1001, "scope_all"),
        (1002, "manual"),
        (1003, "local_proxy_listener"),
        (1004, "open_core_name"),
        (1005, "system_proxy_host"),
        (9999, "runtime"),
    ] {
        metrics.record_process_connection_close(pid, "PROXYCORE.EXE", label);
    }
    let snap2 = metrics.snapshot();
    assert_eq!(snap2.len(), 1);
    assert_eq!(snap2[0].active_connections, 0);
    assert_eq!(snap2[0].detected_by, "system_proxy_host");
}

#[tokio::test]
async fn manager_stop_clears_stale_process_cards_and_reload_helpers_are_noop_when_idle() {
    let root = std::env::temp_dir().join(format!(
        "catcloud-stop-clear-{}",
        uuid::Uuid::new_v4()
    ));
    let paths = AppPaths::from_data_dir(root.join("data"), true).unwrap();
    let job_guard = Arc::new(JobGuard::new().unwrap());
    let manager = GlobalPreAccelManager::new(paths, job_guard);
    let cfg = AppConfig::default();
    let relays = vec![sample_anytls_relay_with_dirty_sni()];

    // Simulate active telemetry from a prior session.
    manager
        .metrics
        .record_process_connection_open(4100, "mihomo.exe", "open_core_name");
    manager
        .metrics
        .record_process_bytes(4100, "mihomo.exe", "open_core_name", 1024, 2048);
    assert_eq!(manager.status().process_stats.len(), 1);
    assert_eq!(manager.status().accelerated_processes.len(), 1);

    // Stopping must wipe both `process_stats` and `accelerated_processes` completely.
    let stopped = manager.stop().await.expect("stop manager");
    assert!(!stopped.running);
    assert_eq!(stopped.mode, "off");
    assert!(stopped.process_stats.is_empty());
    assert!(stopped.accelerated_processes.is_empty());

    // Reload helpers on an idle manager must remain safe no-ops without starting runtime.
    let after_stop_reload = manager
        .stop_windivert_for_reload()
        .await
        .expect("stop_windivert_for_reload when idle");
    assert!(!after_stop_reload.running);
    let after_restart = manager
        .restart_windivert_if_running(&cfg, &relays, &[])
        .await
        .expect("restart_windivert_if_running when idle");
    assert!(!after_restart.running);
    assert_eq!(after_restart.mode, "off");

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn is_non_proxy_communication_process_filters_im_browsers_ides_without_hitting_ssh_git_or_manual()
{
    for blocked in [
        "QQ.exe",
        r"C:\Program Files\Tencent\QQNT\QQNT.exe",
        "QQProtect.exe",
        "txupd.exe",
        "TIM.exe",
        "WeChat.exe",
        "Weixin.exe",
        "WeChatAppEx.exe",
        "WeChatOCR.exe",
        "DingTalk.exe",
        "Feishu.exe",
        "Lark.exe",
        "WXWork.exe",
        "QYWX.exe",
        "wemeetapp.exe",
        "TencentMeeting.exe",
        "AliWangWang.exe",
        "YY.exe",
        "Foxmail.exe",
        "chrome.exe",
        "msedge.exe",
        "firefox.exe",
        "Code.exe",
        "steam.exe",
        "steamwebhelper.exe",
        "cloudmusic.exe",
        "QQMusic.exe",
        "BaiduNetdisk.exe",
        "wps.exe",
    ] {
        assert!(
            is_non_proxy_communication_process(blocked),
            "`{blocked}` must be classified as a non-proxy communication/desktop process"
        );
    }

    // Must never misclassify SSH/Git/transfer tools or open-source proxy cores.
    for allowed in [
        "ssh.exe",
        "git.exe",
        "scp.exe",
        "rsync.exe",
        "mihomo.exe",
        "xray.exe",
        "sing-box.exe",
        "proxy-engine.exe",
        "",
    ] {
        assert!(
            !is_non_proxy_communication_process(allowed),
            "`{allowed}` must NOT be classified as a non-proxy communication process"
        );
    }

    // User manual target list still works even if a user explicitly adds an app name.
    let manual_targets: HashSet<String> = ["ssh.exe", "git.exe", "qq.exe"]
        .into_iter()
        .map(String::from)
        .collect();
    let empty_excl = HashSet::new();
    let empty_det = HashMap::new();
    assert_eq!(
        classify_intercept_process(
            5001,
            Some("ssh.exe"),
            GlobalPreAccelScope::ProxyAppsOnly,
            &manual_targets,
            &empty_excl,
            &empty_det
        ),
        Some("manual")
    );
    assert_eq!(
        classify_intercept_process(
            5002,
            Some("qq.exe"),
            GlobalPreAccelScope::ProxyAppsOnly,
            &manual_targets,
            &empty_excl,
            &empty_det
        ),
        Some("manual")
    );
}

#[test]
fn cn_ipv4_ranges_are_strictly_sorted_disjoint_and_is_domestic_ipv4_classifies_accurately() {
    assert!(!CN_IPV4_RANGES.is_empty());
    for pair in CN_IPV4_RANGES.windows(2) {
        let (s0, e0) = pair[0];
        let (s1, e1) = pair[1];
        assert!(s0 <= e0, "invalid range {s0:#010X}..={e0:#010X}");
        assert!(s1 <= e1, "invalid range {s1:#010X}..={e1:#010X}");
        assert!(
            e0 < s1,
            "CN_IPV4_RANGES must be strictly ascending & non-overlapping: {e0:#010X} >= {s1:#010X}"
        );
    }

    // All 13 whitelisted domestic public DNS IPs & major CN ISP/cloud/CERNET hex samples match.
    for &dns_ip in DOMESTIC_PUBLIC_DNS_IPV4S {
        assert!(is_domestic_ipv4(dns_ip), "domestic DNS {dns_ip} must match CN table");
    }
    for hex_cn in [
        0xDCB5_2694u32, // China Telecom web portal range
        0x279C_420Au32, // China Mobile range
        0xB702_ACB9u32, // China Telecom GD range
        0x6F0D_65D0u32, // China Mobile core range
        0x2F60_0101u32, // Alibaba Cloud CN range
        0x7904_0101u32, // Tencent Cloud CN range
        0x72D4_0101u32, // CERNET range
        0xCA70_0E97u32, // CERNET backbone range
        0xA66F_0464u32, // CERNET university range
    ] {
        let ip = Ipv4Addr::from(hex_cn);
        assert!(
            is_domestic_ipv4(ip),
            "expected hex {hex_cn:#010X} to be domestic CN IPv4"
        );
    }

    // Overseas public IPs, overseas cloud ranges, private LAN, Fake-IP, and RFC 5737 must return false.
    for hex_non_cn in [
        0x0101_0101u32, // Cloudflare DNS
        0x0808_0808u32, // Google DNS
        0x0909_0909u32, // Quad9 DNS
        0x6812_0001u32, // Overseas CDN
        0x8EFA_0101u32, // Overseas search edge
        0x8C52_7904u32, // Overseas git forge
        0xACD9_A04Eu32, // Overseas search cloud
        0x2F4A_0101u32, // Overseas cloud node
        0x2B82_0101u32, // Overseas cloud node
        0x6520_0101u32, // Overseas cloud node
        0x771C_0101u32, // Overseas cloud node
        0x0A00_0001u32, // RFC 1918
        0x7F00_0001u32, // Loopback
        0xC0A8_0101u32, // RFC 1918
        0xC612_0001u32, // Fake-IP
        0xCB00_710Au32, // RFC 5737
    ] {
        let ip = Ipv4Addr::from(hex_non_cn);
        assert!(
            !is_domestic_ipv4(ip),
            "expected hex {hex_non_cn:#010X} NOT to match CN IPv4 table"
        );
    }
}

#[test]
fn build_windivert_filter_with_options_toggles_443_and_excludes_13_domestic_dns_ips() {
    let relays = [Ipv4Addr::new(203, 0, 113, 10)];

    let filter_skip = build_windivert_filter_with_options(&relays, 55000, true);
    assert!(filter_skip.contains("tcp.DstPort != 443"));
    assert!(filter_skip.contains("tcp.DstPort != 53"));
    assert!(filter_skip.contains("ip.DstAddr != 203.0.113.10"));
    assert_eq!(DOMESTIC_PUBLIC_DNS_IPV4S.len(), 13);
    for &dns_ip in DOMESTIC_PUBLIC_DNS_IPV4S {
        let clause = format!("ip.DstAddr != {dns_ip}");
        assert!(
            filter_skip.contains(&clause),
            "missing domestic DNS exclusion `{clause}`"
        );
    }

    let filter_include_443 = build_windivert_filter_with_options(&relays, 55000, false);
    assert!(!filter_include_443.contains("tcp.DstPort != 443"));
    assert!(filter_include_443.contains("tcp.DstPort != 53"));
    assert!(filter_include_443.contains("ip.DstAddr != 203.0.113.10"));
    for &dns_ip in DOMESTIC_PUBLIC_DNS_IPV4S {
        assert!(filter_include_443.contains(&format!("ip.DstAddr != {dns_ip}")));
    }
}

#[test]
fn should_intercept_port_443_enforces_skip_flag_proxy_tags_and_non_domestic_dst() {
    let overseas_dst = Ipv4Addr::from(0x6812_0001u32);
    let domestic_dst = Ipv4Addr::from(0xDCB5_2694u32);

    // skip_443_native == true always rejects 443 regardless of label or destination.
    assert!(!should_intercept_port_443("system_proxy_host", true, overseas_dst));
    assert!(!should_intercept_port_443("open_core_name", true, overseas_dst));

    // skip_443_native == false allows ONLY exact proxy-core tags to non-domestic IPs.
    for allowed_tag in ["system_proxy_host", "local_proxy_listener", "open_core_name"] {
        assert!(should_intercept_port_443(allowed_tag, false, overseas_dst));
        assert!(!should_intercept_port_443(allowed_tag, false, domestic_dst));
    }

    // manual & scope_all & unknown must ALWAYS bypass 443 even when skip_443_native == false.
    for denied_tag in ["manual", "scope_all", "unknown", "self_test"] {
        assert!(!should_intercept_port_443(denied_tag, false, overseas_dst));
    }
}

#[test]
fn nat_table_lockfree_port_bitmap_and_copy_packet_view_stay_in_sync_across_insert_evict_remove()
{
    let table = NatTable::new(2, Duration::from_secs(60));
    let now = Instant::now();
    let k1 = (Ipv4Addr::LOCALHOST, 45001);
    let k2 = (Ipv4Addr::LOCALHOST, 45002);
    let k3 = (Ipv4Addr::LOCALHOST, 45003);

    assert!(!table.may_contain_port(45001));
    assert!(table.get_packet_view_and_touch(&k1).is_none());

    table.insert(
        k1,
        NatEntry {
            orig_src_ip: Ipv4Addr::new(192, 0, 2, 10),
            orig_dst_ip: Ipv4Addr::new(203, 0, 113, 10),
            orig_dst_port: 8443,
            if_idx: 3,
            sub_if_idx: 1,
            owner_pid: 1111,
            process_name: "mihomo.exe".to_string(),
            detected_by: "open_core_name".to_string(),
            last_seen: now - Duration::from_secs(10),
            closing_since: None,
        },
    );
    assert!(table.may_contain_port(45001));
    let view1 = table.get_packet_view_and_touch(&k1).expect("view1");
    assert_eq!(view1.orig_dst_ip, Ipv4Addr::new(203, 0, 113, 10));
    assert_eq!(view1.orig_dst_port, 8443);
    assert_eq!(view1.if_idx, 3);
    assert_eq!(view1.sub_if_idx, 1);
    assert!(!view1.is_closing);
    assert!(!view1.is_self_test);

    // Insert k2 and k3 to trigger LRU eviction (k1 has older last_seen before touch? set k1 older again).
    table.insert(
        k1,
        NatEntry {
            orig_src_ip: Ipv4Addr::new(192, 0, 2, 10),
            orig_dst_ip: Ipv4Addr::new(203, 0, 113, 10),
            orig_dst_port: 8443,
            if_idx: 3,
            sub_if_idx: 1,
            owner_pid: 1111,
            process_name: "mihomo.exe".to_string(),
            detected_by: SELF_TEST_DETECTED_BY.to_string(),
            last_seen: now - Duration::from_secs(20),
            closing_since: None,
        },
    );
    assert!(table.get_packet_view_and_touch(&k1).unwrap().is_self_test);
    // Re-age k1 so k1 is oldest when k3 forces eviction.
    table.insert(
        k1,
        NatEntry {
            orig_src_ip: Ipv4Addr::new(192, 0, 2, 10),
            orig_dst_ip: Ipv4Addr::new(203, 0, 113, 10),
            orig_dst_port: 8443,
            if_idx: 3,
            sub_if_idx: 1,
            owner_pid: 1111,
            process_name: "mihomo.exe".to_string(),
            detected_by: "open_core_name".to_string(),
            last_seen: now - Duration::from_secs(30),
            closing_since: None,
        },
    );
    table.insert(
        k2,
        NatEntry {
            orig_src_ip: Ipv4Addr::new(192, 0, 2, 10),
            orig_dst_ip: Ipv4Addr::new(203, 0, 113, 20),
            orig_dst_port: 9443,
            if_idx: 3,
            sub_if_idx: 0,
            owner_pid: 2222,
            process_name: "xray.exe".to_string(),
            detected_by: "open_core_name".to_string(),
            last_seen: now - Duration::from_secs(5),
            closing_since: None,
        },
    );
    table.insert(
        k3,
        NatEntry {
            orig_src_ip: Ipv4Addr::new(192, 0, 2, 10),
            orig_dst_ip: Ipv4Addr::new(203, 0, 113, 30),
            orig_dst_port: 2053,
            if_idx: 3,
            sub_if_idx: 0,
            owner_pid: 3333,
            process_name: "ssh.exe".to_string(),
            detected_by: "manual".to_string(),
            last_seen: now,
            closing_since: None,
        },
    );

    // Evicted k1 must have its bitmap bit cleared while k2 & k3 remain set.
    assert!(!table.may_contain_port(45001));
    assert!(table.may_contain_port(45002));
    assert!(table.may_contain_port(45003));

    // Direct removal clears bitmap bit cleanly.
    assert!(table.remove(&k2).is_some());
    assert!(!table.may_contain_port(45002));
    assert!(table.remove_active_if_matching(
        &k3,
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(203, 0, 113, 30),
        2053
    ));
    assert!(!table.may_contain_port(45003));
    assert!(table.is_empty());
}

#[tokio::test]
async fn global_preaccel_runtime_meta_suspend_for_tun_stop_and_drop_lifecycle() {
    let root = std::env::temp_dir().join(format!(
        "catcloud-global-meta-{}",
        uuid::Uuid::new_v4()
    ));
    let paths = AppPaths::from_data_dir(root.join("data"), true).unwrap();
    let data_dir = paths.root_data_dir.clone();

    // 1. Direct write/read/remove roundtrip.
    let sample_meta = GlobalPreAccelRuntimeMeta {
        pid: Some(42424),
        process_start_time_unix: Some(1_764_200_000),
        binary_path: Some("/opt/catcloud/bin/mihomo".to_string()),
        running: true,
        mode: "windivert".to_string(),
        effective_carrier: "standalone_windivert".to_string(),
        socks_port: Some(17908),
        active_relays: vec!["Relay-TX-443".to_string(), "Relay-ALI-443".to_string()],
        updated_at: "2026-11-27T00:00:00Z".to_string(),
    };
    write_global_preaccel_runtime_meta(&data_dir, &sample_meta).expect("write runtime meta");
    assert_eq!(
        read_global_preaccel_runtime_meta(&data_dir).as_ref(),
        Some(&sample_meta)
    );
    // Also readable when passing `run/` directory directly.
    assert_eq!(
        read_global_preaccel_runtime_meta(&paths.runtime_dir).as_ref(),
        Some(&sample_meta)
    );
    remove_global_preaccel_runtime_meta(&data_dir);
    assert!(read_global_preaccel_runtime_meta(&data_dir).is_none());

    // 2. Manager `suspend_for_tun` -> persists suspended_for_tun & carrier, updates live status;
    //    `stop` -> clears suspended state and removes runtime meta file cleanly.
    {
        let job_guard = Arc::new(JobGuard::new().unwrap());
        let manager = GlobalPreAccelManager::new(paths.clone(), job_guard);

        let suspended = manager
            .suspend_for_tun(vec!["Relay-TX-443".to_string()])
            .await
            .expect("suspend_for_tun");
        assert!(!suspended.running);
        assert_eq!(suspended.mode, "suspended_for_tun");
        assert_eq!(suspended.active_relays, vec!["Relay-TX-443".to_string()]);

        let persisted = read_global_preaccel_runtime_meta(&data_dir)
            .expect("suspended_for_tun meta must be written on disk");
        assert!(!persisted.running);
        assert_eq!(persisted.pid, None);
        assert_eq!(persisted.mode, "suspended_for_tun");
        assert_eq!(
            persisted.effective_carrier,
            "main_core_tun_suspended_standalone"
        );
        assert_eq!(persisted.active_relays, vec!["Relay-TX-443".to_string()]);

        let stopped = manager.stop().await.expect("stop clears suspended state");
        assert!(!stopped.running);
        assert_eq!(stopped.mode, "off");
        assert!(stopped.active_relays.is_empty());
        assert!(read_global_preaccel_runtime_meta(&data_dir).is_none());

        // 3. Re-suspend and drop manager -> Drop must clean up the runtime meta file.
        let _ = manager
            .suspend_for_tun(vec!["Relay-ALI-443".to_string()])
            .await
            .unwrap();
        assert!(read_global_preaccel_runtime_meta(&data_dir).is_some());
    }
    assert!(
        read_global_preaccel_runtime_meta(&data_dir).is_none(),
        "Drop must remove global-preaccel-runtime.json"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn windivert_runtime_fingerprint_skips_restart_when_unchanged_and_restarts_on_changes() {
    let base_relays = vec![Ipv4Addr::new(203, 0, 113, 10), Ipv4Addr::new(198, 51, 100, 20)];
    let base_procs = vec!["mihomo.exe".to_string(), "ssh.exe".to_string()];
    let mut base_pids = HashSet::new();
    base_pids.insert(1001);
    base_pids.insert(2002);

    let fp1 = WinDivertRuntimeFingerprint::from_inputs(
        PathBuf::from(r"C:\CatCloud\bin\WinDivert64.dll"),
        Some(PathBuf::from(r"C:\CatCloud\bin\WinDivert64.sys")),
        &base_relays,
        true,
        GlobalPreAccelScope::ProxyAppsOnly,
        &base_procs,
        &base_pids,
    );
    // Reordered inputs and uppercase process names normalize to the identical fingerprint.
    let fp_same = WinDivertRuntimeFingerprint::from_inputs(
        PathBuf::from(r"C:\CatCloud\bin\WinDivert64.dll"),
        Some(PathBuf::from(r"C:\CatCloud\bin\WinDivert64.sys")),
        &[Ipv4Addr::new(198, 51, 100, 20), Ipv4Addr::new(203, 0, 113, 10)],
        true,
        GlobalPreAccelScope::ProxyAppsOnly,
        &["SSH.EXE".to_string(), "mihomo.exe".to_string()],
        &base_pids,
    );
    assert_eq!(fp1, fp_same);
    assert!(should_skip_windivert_restart(false, Some(&fp1), Some(&fp_same)));
    assert!(!should_skip_windivert_restart(true, Some(&fp1), Some(&fp_same)));
    assert!(!should_skip_windivert_restart(false, None, Some(&fp_same)));
    assert!(!should_skip_windivert_restart(false, Some(&fp1), None));

    // Any static config change must invalidate the fingerprint and force restart.
    let fp_diff_dll = WinDivertRuntimeFingerprint::from_inputs(
        PathBuf::from(r"C:\Alt\WinDivert64.dll"),
        Some(PathBuf::from(r"C:\CatCloud\bin\WinDivert64.sys")),
        &base_relays,
        true,
        GlobalPreAccelScope::ProxyAppsOnly,
        &base_procs,
        &base_pids,
    );
    assert!(!should_skip_windivert_restart(false, Some(&fp1), Some(&fp_diff_dll)));

    let fp_diff_sys = WinDivertRuntimeFingerprint::from_inputs(
        PathBuf::from(r"C:\CatCloud\bin\WinDivert64.dll"),
        Some(PathBuf::from(r"C:\Alt\WinDivert64.sys")),
        &base_relays,
        true,
        GlobalPreAccelScope::ProxyAppsOnly,
        &base_procs,
        &base_pids,
    );
    assert!(!should_skip_windivert_restart(false, Some(&fp1), Some(&fp_diff_sys)));

    let fp_none_sys = WinDivertRuntimeFingerprint::from_inputs(
        PathBuf::from(r"C:\CatCloud\bin\WinDivert64.dll"),
        None,
        &base_relays,
        true,
        GlobalPreAccelScope::ProxyAppsOnly,
        &base_procs,
        &base_pids,
    );
    assert!(!should_skip_windivert_restart(false, Some(&fp1), Some(&fp_none_sys)));

    let fp_diff_skip443 = WinDivertRuntimeFingerprint::from_inputs(
        PathBuf::from(r"C:\CatCloud\bin\WinDivert64.dll"),
        Some(PathBuf::from(r"C:\CatCloud\bin\WinDivert64.sys")),
        &base_relays,
        false,
        GlobalPreAccelScope::ProxyAppsOnly,
        &base_procs,
        &base_pids,
    );
    assert!(!should_skip_windivert_restart(false, Some(&fp1), Some(&fp_diff_skip443)));

    let fp_diff_scope = WinDivertRuntimeFingerprint::from_inputs(
        PathBuf::from(r"C:\CatCloud\bin\WinDivert64.dll"),
        Some(PathBuf::from(r"C:\CatCloud\bin\WinDivert64.sys")),
        &base_relays,
        true,
        GlobalPreAccelScope::AllNon443Tcp,
        &base_procs,
        &base_pids,
    );
    assert!(!should_skip_windivert_restart(false, Some(&fp1), Some(&fp_diff_scope)));

    let fp_diff_procs = WinDivertRuntimeFingerprint::from_inputs(
        PathBuf::from(r"C:\CatCloud\bin\WinDivert64.dll"),
        Some(PathBuf::from(r"C:\CatCloud\bin\WinDivert64.sys")),
        &base_relays,
        true,
        GlobalPreAccelScope::ProxyAppsOnly,
        &["mihomo.exe".to_string(), "scp.exe".to_string()],
        &base_pids,
    );
    assert!(!should_skip_windivert_restart(false, Some(&fp1), Some(&fp_diff_procs)));

    let mut changed_pids = base_pids.clone();
    changed_pids.insert(3003);
    let fp_diff_pids = WinDivertRuntimeFingerprint::from_inputs(
        PathBuf::from(r"C:\CatCloud\bin\WinDivert64.dll"),
        Some(PathBuf::from(r"C:\CatCloud\bin\WinDivert64.sys")),
        &base_relays,
        true,
        GlobalPreAccelScope::ProxyAppsOnly,
        &base_procs,
        &changed_pids,
    );
    assert!(!should_skip_windivert_restart(false, Some(&fp1), Some(&fp_diff_pids)));
}

#[test]
fn nat_table_full_4096_capacity_evicts_expired_and_closing_before_live_flows_in_sync() {
    let table = NatTable::new(MAX_NAT_ENTRIES, NAT_IDLE_TIMEOUT);
    let now = Instant::now();
    let expired_ts = now - (NAT_IDLE_TIMEOUT + Duration::from_secs(5));
    let closing_ts = now - Duration::from_secs(1);

    // Fill table to exact MAX_NAT_ENTRIES (4096):
    //   0..128   -> expired entries
    //   128..132 -> closing (within grace) entries
    //   132..4096 -> active live entries
    for i in 0..MAX_NAT_ENTRIES {
        let port = 20000u16 + (i as u16);
        let (last_seen, closing_since) = if i < 128 {
            (expired_ts, None)
        } else if i < 132 {
            (now, Some(closing_ts))
        } else {
            (now, None)
        };
        table.insert(
            (Ipv4Addr::LOCALHOST, port),
            NatEntry {
                orig_src_ip: Ipv4Addr::new(192, 0, 2, 1),
                orig_dst_ip: Ipv4Addr::new(203, 0, 113, 10),
                orig_dst_port: 8443,
                if_idx: 1,
                sub_if_idx: 0,
                owner_pid: 42,
                process_name: "mihomo.exe".to_string(),
                detected_by: "open_core_name".to_string(),
                last_seen,
                closing_since,
            },
        );
    }

    // Inserting one fresh entry at full capacity sweeps all 128 expired entries in O(N)
    // and clears their lock-free bitmap bits while preserving active flows.
    let fresh_port = 55000u16;
    table.insert(
        (Ipv4Addr::LOCALHOST, fresh_port),
        NatEntry {
            orig_src_ip: Ipv4Addr::new(192, 0, 2, 1),
            orig_dst_ip: Ipv4Addr::new(203, 0, 113, 10),
            orig_dst_port: 8443,
            if_idx: 1,
            sub_if_idx: 0,
            owner_pid: 42,
            process_name: "mihomo.exe".to_string(),
            detected_by: "open_core_name".to_string(),
            last_seen: now,
            closing_since: None,
        },
    );
    assert!(!table.may_contain_port(20000));
    assert!(!table.may_contain_port(20127));
    assert!(table.may_contain_port(20128));
    assert!(table.may_contain_port(20132));
    assert!(table.may_contain_port(fresh_port));

    // Refill the freed 127 slots so capacity reaches 4096 again, then insert 1 more entry:
    // the closing entry (port 20128..20131) must be evicted before any live entry.
    for offset in 0..127u16 {
        table.insert(
            (Ipv4Addr::LOCALHOST, 56000 + offset),
            NatEntry {
                orig_src_ip: Ipv4Addr::new(192, 0, 2, 1),
                orig_dst_ip: Ipv4Addr::new(203, 0, 113, 10),
                orig_dst_port: 8443,
                if_idx: 1,
                sub_if_idx: 0,
                owner_pid: 42,
                process_name: "mihomo.exe".to_string(),
                detected_by: "open_core_name".to_string(),
                last_seen: now,
                closing_since: None,
            },
        );
    }
    table.insert(
        (Ipv4Addr::LOCALHOST, 57000),
        NatEntry {
            orig_src_ip: Ipv4Addr::new(192, 0, 2, 1),
            orig_dst_ip: Ipv4Addr::new(203, 0, 113, 10),
            orig_dst_port: 8443,
            if_idx: 1,
            sub_if_idx: 0,
            owner_pid: 42,
            process_name: "mihomo.exe".to_string(),
            detected_by: "open_core_name".to_string(),
            last_seen: now,
            closing_since: None,
        },
    );
    let closing_remaining = (20128u16..20132)
        .filter(|&p| table.may_contain_port(p))
        .count();
    assert_eq!(closing_remaining, 3, "a closing entry must be evicted before live flows");
    assert!(table.may_contain_port(20132));
    assert!(table.may_contain_port(57000));
}

#[test]
fn self_test_strict_204_rejects_non_204_and_empty_responses() {
    assert_eq!(validate_self_test_http_status(Some(204)), Ok(204));
    for bad in [Some(200), Some(302), Some(403), Some(502), None] {
        assert!(
            validate_self_test_http_status(bad).is_err(),
            "self-test must reject HTTP status {bad:?}"
        );
    }

    #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
    {
        use crate::preaccel::windivert_win::WinDivertSelfTestOutcome;

        let ok_outcome = enforce_self_test_strict_204(WinDivertSelfTestOutcome::Passed {
            latency_ms: 18,
            probe_host: "connectivitycheck.platform.hicloud.com".to_string(),
            status_code: 204,
        });
        assert!(matches!(
            ok_outcome,
            WinDivertSelfTestOutcome::Passed { status_code: 204, .. }
        ));

        for non_204 in [200u16, 302, 403, 502] {
            let rejected = enforce_self_test_strict_204(WinDivertSelfTestOutcome::Passed {
                latency_ms: 25,
                probe_host: "connectivitycheck.platform.hicloud.com".to_string(),
                status_code: non_204,
            });
            assert!(
                matches!(rejected, WinDivertSelfTestOutcome::TunnelUnreachable { .. }),
                "HTTP {non_204} must downgrade to TunnelUnreachable, got {rejected:?}"
            );
        }
    }
}

#[test]
fn build_self_test_probe_urls_prioritizes_custom_204_and_skips_non_204_with_204_fallbacks() {
    let custom_204 = build_self_test_probe_urls("http://custom-check.cn/generate_204");
    assert_eq!(
        custom_204,
        vec![
            "http://custom-check.cn/generate_204".to_string(),
            crate::preaccel::generator::DEFAULT_DOMESTIC_204_PRIMARY.to_string(),
            crate::preaccel::generator::DEFAULT_DOMESTIC_204_FALLBACK.to_string(),
        ]
    );

    let non_204 = build_self_test_probe_urls("http://custom-health.cn/ok");
    assert_eq!(
        non_204,
        vec![
            crate::preaccel::generator::DEFAULT_DOMESTIC_204_PRIMARY.to_string(),
            crate::preaccel::generator::DEFAULT_DOMESTIC_204_FALLBACK.to_string(),
        ]
    );

    let dedup = build_self_test_probe_urls(
        crate::preaccel::generator::DEFAULT_DOMESTIC_204_PRIMARY,
    );
    assert_eq!(dedup.len(), 2);
}

#[test]
fn nat_table_prune_expired_clear_and_shrink_to_fit_release_excess_capacity() {
    let table = NatTable::new(MAX_NAT_ENTRIES, Duration::from_secs(60));
    let now = Instant::now();
    let expired_ts = now - Duration::from_secs(120);

    // Populate > 1024 entries (1000 expired + 24 active) so internal HashMap capacity grows well past 512.
    for i in 0..1024u16 {
        let port = 30000 + i;
        let last_seen = if i < 1000 { expired_ts } else { now };
        table.insert(
            (Ipv4Addr::LOCALHOST, port),
            NatEntry {
                orig_src_ip: Ipv4Addr::new(198, 51, 100, 10),
                orig_dst_ip: Ipv4Addr::new(203, 0, 113, 10),
                orig_dst_port: 8443,
                if_idx: 1,
                sub_if_idx: 0,
                owner_pid: 42,
                process_name: "mihomo.exe".to_string(),
                detected_by: "open_core_name".to_string(),
                last_seen,
                closing_since: None,
            },
        );
    }
    assert_eq!(table.len(), 1024);

    let removed = table.prune_expired();
    assert_eq!(removed, 1000);
    assert_eq!(table.len(), 24);
    assert!(!table.may_contain_port(30000));
    assert!(!table.may_contain_port(30999));
    assert!(table.may_contain_port(31000));
    assert!(table.may_contain_port(31023));

    // Clear resets both table entries and lock-free port bitmap and shrinks capacity cleanly.
    table.clear();
    assert!(table.is_empty());
    assert!(!table.may_contain_port(31000));
    assert!(!table.may_contain_port(31023));
    table.shrink_to_fit();
    assert_eq!(table.len(), 0);
}
