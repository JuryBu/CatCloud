use super::super::*;
use super::{sample_anytls_relay_with_dirty_sni, sample_vless_relay_with_dirty_sni};
#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
use crate::error::CatError;
use crate::models::{AppConfig, GlobalPreAccelScope};
use crate::paths::AppPaths;
#[cfg(not(all(target_os = "windows", target_arch = "aarch64")))]
use crate::paths::normalize_os_path;
use crate::preaccel::generator::{PREACCEL_FALLBACK_GROUP, PREACCEL_SELECT_GROUP};
use crate::process_guard::JobGuard;
use serde_yaml_ng::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Write as _};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zip::CompressionMethod;
use zip::write::SimpleFileOptions;

#[test]
fn windivert_address_is_exact_80_bytes_and_bitfield_roundtrips() {
    assert_eq!(std::mem::size_of::<WinDivertAddress>(), 80);

    let mut addr = WinDivertAddress::default();
    addr.timestamp = 1_700_000_000;
    addr.set_layer(0);
    addr.set_event(1);
    addr.set_sniffed(true);
    addr.set_outbound(true);
    addr.set_loopback(true);
    addr.set_impostor(true);
    addr.set_ipv6(true);
    addr.set_ip_checksum(true);
    addr.set_tcp_checksum(true);
    addr.set_udp_checksum(true);
    addr.set_network_if_idx(17);
    addr.set_network_sub_if_idx(3);

    assert_eq!(addr.layer(), 0);
    assert_eq!(addr.event(), 1);
    assert!(addr.sniffed());
    assert!(addr.outbound());
    assert!(addr.loopback());
    assert!(addr.impostor());
    assert!(addr.ipv6());
    assert!(addr.ip_checksum());
    assert!(addr.tcp_checksum());
    assert!(addr.udp_checksum());
    assert_eq!(addr.network_if_idx(), 17);
    assert_eq!(addr.network_sub_if_idx(), 3);

    // Clearing Outbound and Loopback must not disturb sibling bitfield flags.
    addr.set_outbound(false);
    addr.set_loopback(false);
    addr.set_layer(2);
    assert_eq!(addr.layer(), 2);
    assert_eq!(addr.event(), 1);
    assert!(addr.sniffed());
    assert!(!addr.outbound());
    assert!(!addr.loopback());
    assert!(addr.impostor());
    assert!(addr.ip_checksum());
    assert!(addr.tcp_checksum());
    assert!(addr.udp_checksum());
}

#[test]
fn build_windivert_filter_excludes_relays_ports_private_ranges_and_never_geoip_cn() {
    let relays = [
        Ipv4Addr::new(203, 0, 113, 10),
        Ipv4Addr::new(198, 51, 100, 20),
        Ipv4Addr::new(203, 0, 113, 10), // duplicate must deduplicate
    ];
    let filter = build_windivert_filter(&relays, 54321);

    assert!(filter.starts_with("ip and tcp and ("));
    assert!(filter.contains("!loopback"));
    assert!(filter.contains("tcp.DstPort != 443"));
    assert!(filter.contains("tcp.DstPort != 53"));
    assert!(filter.contains("ip.DstAddr != 203.0.113.10"));
    assert!(filter.contains("ip.DstAddr != 198.51.100.20"));
    assert!(filter.contains("(ip.DstAddr < 10.0.0.0 or ip.DstAddr > 10.255.255.255)"));
    assert!(filter.contains("(ip.DstAddr < 100.64.0.0 or ip.DstAddr > 100.127.255.255)"));
    assert!(filter.contains("(ip.DstAddr < 127.0.0.0 or ip.DstAddr > 127.255.255.255)"));
    assert!(filter.contains("(ip.DstAddr < 169.254.0.0 or ip.DstAddr > 169.254.255.255)"));
    assert!(filter.contains("(ip.DstAddr < 172.16.0.0 or ip.DstAddr > 172.31.255.255)"));
    assert!(filter.contains("(ip.DstAddr < 192.168.0.0 or ip.DstAddr > 192.168.255.255)"));
    assert!(filter.contains("(ip.DstAddr < 198.18.0.0 or ip.DstAddr > 198.19.255.255)"));
    assert!(filter.contains("ip.DstAddr < 224.0.0.0"));
    assert!(filter.contains(
        "(outbound and ip.SrcAddr == 127.0.0.1 and ip.DstAddr == 127.0.0.1 and tcp.SrcPort == 54321)"
    ));

    // Must never contain CIDR syntax (invalid in WinDivert) or GeoIP CN bypass.
    assert!(!filter.contains('/'));
    let lower = filter.to_ascii_lowercase();
    assert!(!lower.contains("geoip"));
    assert!(!lower.contains("cn"));
}

#[test]
fn compile_standalone_preaccel_yaml_enforces_zero_tun_zero_dns_no_sni_domestic_204_and_anti_loop()
{
    let mut cfg = AppConfig::default();
    cfg.preaccel.enabled = false; // standalone mode must still compile cleanly when main preaccel is off
    let mut disabled = sample_anytls_relay_with_dirty_sni();
    disabled.id = "relay-disabled".to_string();
    disabled.server = "192.0.2.99".to_string();
    disabled.enabled = false;

    let relays = vec![
        sample_vless_relay_with_dirty_sni(),
        disabled,
        sample_anytls_relay_with_dirty_sni(),
    ];

    let yaml_str =
        compile_standalone_preaccel_yaml(&cfg, &relays, 17908).expect("compile standalone");
    let doc: Value = serde_yaml_ng::from_str(&yaml_str).expect("valid YAML");

    assert_eq!(doc["socks-port"].as_u64(), Some(17908));
    assert_eq!(doc["bind-address"].as_str(), Some("127.0.0.1"));
    assert_eq!(doc["allow-lan"].as_bool(), Some(false));
    assert_eq!(doc["tun"]["enable"].as_bool(), Some(false));
    assert_eq!(doc["dns"]["enable"].as_bool(), Some(false));
    assert!(doc.get("external-controller").is_none());
    assert_eq!(doc["geo-auto-update"].as_bool(), Some(false));
    assert_eq!(doc["geodata-loader"].as_str(), Some("memconservative"));
    assert_eq!(doc["keep-alive-idle"].as_u64(), Some(45));
    assert_eq!(doc["keep-alive-interval"].as_u64(), Some(15));
    assert_eq!(STANDALONE_TUNNEL_GOMEMLIMIT, "48MiB");
    assert_eq!(NAT_IDLE_TIMEOUT, Duration::from_secs(600));

    // Verify 443 relays had unfiled third-party SNI stripped and skip-cert-verify enforced.
    let proxies = doc["proxies"].as_sequence().unwrap();
    assert_eq!(proxies.len(), 2);
    let anytls = &proxies[0];
    assert_eq!(anytls["type"].as_str(), Some("anytls"));
    assert_eq!(anytls["server"].as_str(), Some("203.0.113.10"));
    assert!(anytls.get("sni").is_none());
    assert_eq!(anytls["skip-cert-verify"].as_bool(), Some(true));

    let vless = &proxies[1];
    assert_eq!(vless["type"].as_str(), Some("vless"));
    assert_eq!(vless["server"].as_str(), Some("198.51.100.20"));
    assert_eq!(vless["servername"].as_str(), Some(""));
    assert_eq!(vless["skip-cert-verify"].as_bool(), Some(true));

    // Verify two-layer nested LB + outer fallback group with domestic 204 probe, lazy: false,
    // DIRECT strictly in outer fallback and NEVER in inner load-balance.
    let groups = doc["proxy-groups"].as_sequence().unwrap();
    let fallback = groups
        .iter()
        .find(|g| g["name"].as_str() == Some(PREACCEL_FALLBACK_GROUP))
        .expect("fallback group");
    assert_eq!(fallback["lazy"].as_bool(), Some(false));
    assert!(fallback["url"].as_str().unwrap().contains("hicloud.com"));
    let fb_proxies: Vec<&str> = fallback["proxies"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        fb_proxies,
        vec![crate::preaccel::schema::PREACCEL_LB_GROUP_NAME, "DIRECT"]
    );

    let lb = groups
        .iter()
        .find(|g| g["name"].as_str() == Some(crate::preaccel::schema::PREACCEL_LB_GROUP_NAME))
        .expect("inner multi-cloud load-balance group");
    assert_eq!(lb["type"].as_str(), Some("load-balance"));
    assert_eq!(lb["strategy"].as_str(), Some("consistent-hashing"));
    assert_eq!(lb["expected-status"].as_str(), Some("204"));
    assert_eq!(lb["lazy"].as_bool(), Some(false));
    let lb_proxies: Vec<&str> = lb["proxies"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(lb_proxies, vec!["Relay-TX-443", "Relay-ALI-443"]);
    assert!(!lb_proxies.contains(&"DIRECT"));

    // Verify top-level relay DIRECT anti-loop rules precede MATCH while probe_url / domestic
    // 204 domains are excluded from standalone rules so self-test probes always traverse :443.
    let rules: Vec<&str> = doc["rules"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let idx_tx = rules
        .iter()
        .position(|r| *r == "IP-CIDR,203.0.113.10/32,DIRECT,no-resolve")
        .expect("relay 1 direct rule");
    let idx_ali = rules
        .iter()
        .position(|r| *r == "IP-CIDR,198.51.100.20/32,DIRECT,no-resolve")
        .expect("relay 2 direct rule");
    let idx_match = rules
        .iter()
        .position(|r| *r == format!("MATCH,{PREACCEL_SELECT_GROUP}"))
        .expect("MATCH preaccel select group");
    assert!(idx_tx < idx_match);
    assert!(idx_ali < idx_match);
    assert!(!rules.contains(&"IP-CIDR,192.0.2.99/32,DIRECT,no-resolve"));
    assert!(!rules.iter().any(|r| {
        let lower = r.to_ascii_lowercase();
        lower.contains("hicloud.com") || lower.contains("miui.com")
    }));
}

#[cfg(not(all(target_os = "windows", target_arch = "aarch64")))]
#[test]
fn locate_windivert_files_respects_priority_and_requires_colocated_sys() {
    let root = std::env::temp_dir().join(format!(
        "catcloud-wd-locate-{}",
        uuid::Uuid::new_v4()
    ));
    let paths = AppPaths::from_data_dir(root.join("data"), true).unwrap();
    let exe_dir = root.join("app");
    let res_bin = exe_dir.join("resources").join("bin");
    let custom_dir = root.join("custom_wd");
    std::fs::create_dir_all(&res_bin).unwrap();
    std::fs::create_dir_all(&custom_dir).unwrap();

    // Missing `.sys` in custom_dir must be skipped even when `.dll` exists.
    std::fs::write(custom_dir.join("WinDivert64.dll"), b"dll-only").unwrap();
    std::fs::write(exe_dir.join("WinDivert.dll"), b"exe-dll").unwrap();
    std::fs::write(exe_dir.join("WinDivert64.sys"), b"exe-sys").unwrap();

    let found_exe = locate_windivert_files_with_exe_dir(
        &paths,
        Some(custom_dir.to_str().unwrap()),
        Some(&exe_dir),
    )
    .expect("should fall back to exe_dir");
    assert_eq!(found_exe.0, normalize_os_path(&exe_dir.join("WinDivert.dll")));

    // Placing pair in resources/bin overrides exe_dir.
    std::fs::write(res_bin.join("WinDivert64.dll"), b"res-dll").unwrap();
    std::fs::write(res_bin.join("WinDivert64.sys"), b"res-sys").unwrap();
    let found_res = locate_windivert_files_with_exe_dir(&paths, None, Some(&exe_dir)).unwrap();
    assert_eq!(found_res.0, normalize_os_path(&res_bin.join("WinDivert64.dll")));

    // Placing pair in paths.bin_dir overrides resources/bin.
    std::fs::write(paths.bin_dir.join("WinDivert64.dll"), b"bin-dll").unwrap();
    std::fs::write(paths.bin_dir.join("WinDivert64.sys"), b"bin-sys").unwrap();
    let found_bin = locate_windivert_files_with_exe_dir(&paths, None, Some(&exe_dir)).unwrap();
    assert_eq!(
        found_bin.0,
        normalize_os_path(&paths.bin_dir.join("WinDivert64.dll"))
    );

    // Adding `.sys` to custom_dir makes custom_dir highest priority.
    std::fs::write(custom_dir.join("WinDivert64.sys"), b"custom-sys").unwrap();
    let found_custom = locate_windivert_files_with_exe_dir(
        &paths,
        Some(custom_dir.to_str().unwrap()),
        Some(&exe_dir),
    )
    .unwrap();
    assert_eq!(
        found_custom.0,
        normalize_os_path(&custom_dir.join("WinDivert64.dll"))
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn verify_and_extract_windivert_zip_validates_sha256_and_blocks_traversal() {
    let root = std::env::temp_dir().join(format!(
        "catcloud-wd-zip-{}",
        uuid::Uuid::new_v4()
    ));
    let dest = root.join("bin");

    let make_zip = |entries: &[(&str, &[u8])]| -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut zw = zip::ZipWriter::new(&mut cursor);
            let opts = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Stored);
            for (name, body) in entries {
                zw.start_file(*name, opts).unwrap();
                zw.write_all(body).unwrap();
            }
            zw.finish().unwrap();
        }
        cursor.into_inner()
    };

    let good_zip = make_zip(&[
        ("WinDivert-2.2.2-A/x64/WinDivert.dll", b"fake-dll-bytes"),
        ("WinDivert-2.2.2-A/x64/WinDivert64.sys", b"fake-sys-bytes"),
        ("WinDivert-2.2.2-A/README", b"ignored"),
    ]);
    let good_sha = hex::encode(Sha256::digest(&good_zip));

    // Mismatched SHA-256 must fail.
    assert!(verify_and_extract_windivert_zip(&good_zip, "0000", &dest).is_err());

    // Matching SHA-256 installs WinDivert.dll, WinDivert64.dll, and WinDivert64.sys only.
    let installed =
        verify_and_extract_windivert_zip(&good_zip, &good_sha, &dest).expect("install ok");
    assert!(installed.dll_path.is_file());
    assert!(installed.sys_path.is_file());
    assert!(dest.join("WinDivert.dll").is_file());
    assert!(!dest.join("README").exists());

    // Path traversal entry must be rejected even when SHA-256 matches.
    let evil_zip = make_zip(&[("../evil.dll", b"nope")]);
    let evil_sha = hex::encode(Sha256::digest(&evil_zip));
    assert!(verify_and_extract_windivert_zip(&evil_zip, &evil_sha, &dest).is_err());

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn nat_table_ipv4_tcp_rewrite_nic_filter_and_process_policy_work() {
    let table = NatTable::new(2, Duration::from_secs(60));
    let now = Instant::now();
    table.insert(
        (Ipv4Addr::LOCALHOST, 40001),
        NatEntry {
            orig_src_ip: Ipv4Addr::new(192, 0, 2, 10),
            orig_dst_ip: Ipv4Addr::new(203, 0, 113, 50),
            orig_dst_port: 8443,
            if_idx: 7,
            sub_if_idx: 0,
            owner_pid: 2001,
            process_name: "mihomo.exe".to_string(),
            detected_by: "open_core_name".to_string(),
            last_seen: now - Duration::from_secs(10),
            closing_since: None,
        },
    );
    table.insert(
        (Ipv4Addr::LOCALHOST, 40002),
        NatEntry {
            orig_src_ip: Ipv4Addr::new(192, 0, 2, 10),
            orig_dst_ip: Ipv4Addr::new(203, 0, 113, 51),
            orig_dst_port: 9443,
            if_idx: 7,
            sub_if_idx: 0,
            owner_pid: 2002,
            process_name: "xray.exe".to_string(),
            detected_by: "open_core_name".to_string(),
            last_seen: now - Duration::from_secs(5),
            closing_since: None,
        },
    );
    // Third entry evicts oldest (40001).
    table.insert(
        (Ipv4Addr::LOCALHOST, 40003),
        NatEntry {
            orig_src_ip: Ipv4Addr::new(192, 0, 2, 10),
            orig_dst_ip: Ipv4Addr::new(203, 0, 113, 52),
            orig_dst_port: 2053,
            if_idx: 7,
            sub_if_idx: 0,
            owner_pid: 2003,
            process_name: "ssh.exe".to_string(),
            detected_by: "manual".to_string(),
            last_seen: now,
            closing_since: None,
        },
    );
    assert_eq!(table.len(), 2);
    assert!(table.get_and_touch(&(Ipv4Addr::LOCALHOST, 40001)).is_none());
    assert!(table.get_and_touch(&(Ipv4Addr::LOCALHOST, 40003)).is_some());
    assert!(table.has_active_conflict(
        &(Ipv4Addr::LOCALHOST, 40003),
        Ipv4Addr::new(192, 0, 2, 99),
        Ipv4Addr::new(203, 0, 113, 52),
        2053
    ));
    assert!(!table.has_active_conflict(
        &(Ipv4Addr::LOCALHOST, 40003),
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(203, 0, 113, 52),
        2053
    ));
    assert!(table.mark_closing_if_matching(
        &(Ipv4Addr::LOCALHOST, 40003),
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(203, 0, 113, 52),
        2053
    ));
    // During the 4s closing grace window, any different 4-tuple conflicts to prevent cross-flow RST.
    assert!(table.has_active_conflict(
        &(Ipv4Addr::LOCALHOST, 40003),
        Ipv4Addr::new(192, 0, 2, 99),
        Ipv4Addr::new(203, 0, 113, 52),
        2053
    ));
    assert!(table.has_active_conflict(
        &(Ipv4Addr::LOCALHOST, 40003),
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(203, 0, 113, 88),
        2053
    ));
    assert!(!table.has_active_conflict(
        &(Ipv4Addr::LOCALHOST, 40003),
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(203, 0, 113, 52),
        2053
    ));

    // Build minimal 40-byte IPv4 + TCP SYN packet and test parse + dst/src rewrite.
    let mut pkt = [0u8; 40];
    pkt[0] = 0x45; // IPv4, IHL=5
    pkt[9] = 6; // TCP
    pkt[12..16].copy_from_slice(&[192, 0, 2, 10]);
    pkt[16..20].copy_from_slice(&[203, 0, 113, 88]);
    pkt[20..22].copy_from_slice(&50000u16.to_be_bytes());
    pkt[22..24].copy_from_slice(&8443u16.to_be_bytes());
    pkt[33] = Ipv4TcpMeta::FLAG_SYN;

    let meta = parse_ipv4_tcp_packet(&pkt).expect("parse ipv4 tcp");
    assert!(meta.is_syn_only());
    assert_eq!(meta.src_ip, Ipv4Addr::new(192, 0, 2, 10));
    assert_eq!(meta.dst_ip, Ipv4Addr::new(203, 0, 113, 88));
    assert_eq!(meta.src_port, 50000);
    assert_eq!(meta.dst_port, 8443);

    assert!(rewrite_ipv4_tcp_dst(
        &mut pkt,
        meta.ihl_bytes,
        Ipv4Addr::new(192, 0, 2, 10),
        61000
    ));
    let rewritten = parse_ipv4_tcp_packet(&pkt).unwrap();
    assert_eq!(rewritten.dst_ip, Ipv4Addr::new(192, 0, 2, 10));
    assert_eq!(rewritten.dst_port, 61000);

    assert!(rewrite_ipv4_tcp_src(
        &mut pkt,
        meta.ihl_bytes,
        Ipv4Addr::new(203, 0, 113, 88),
        8443
    ));
    let restored = parse_ipv4_tcp_packet(&pkt).unwrap();
    assert_eq!(restored.src_ip, Ipv4Addr::new(203, 0, 113, 88));
    assert_eq!(restored.src_port, 8443);

    // Physical NIC descriptor filter
    assert!(is_physical_nic_descriptor(6, 5, "Realtek PCIe GbE Family Controller"));
    assert!(is_physical_nic_descriptor(71, 5, "Intel(R) Wi-Fi 6E AX211 160MHz"));
    assert!(!is_physical_nic_descriptor(53, 5, "Wintun Userspace Tunnel"));
    assert!(!is_physical_nic_descriptor(6, 5, "Hyper-V Virtual Ethernet Adapter"));
    assert!(!is_physical_nic_descriptor(6, 5, "Meta Wintun Tunnel"));
    assert!(!is_physical_nic_descriptor(24, 5, "Software Loopback Interface 1"));

    // Process interception scope & anti-loop exclusions
    let targets: HashSet<String> = ["ssh.exe", "custom-tool.exe"]
        .into_iter()
        .map(String::from)
        .collect();
    let excluded: HashSet<u32> = [1001, 1002].into_iter().collect();

    assert!(should_intercept_process(
        2000,
        Some(r"C:\Tools\ProxyCore\mihomo.exe"),
        GlobalPreAccelScope::ProxyAppsOnly,
        &targets,
        &excluded
    ));
    assert!(should_intercept_process(
        2005,
        Some(r"C:\Tools\OpenCore\custom-xray-runner.exe"),
        GlobalPreAccelScope::ProxyAppsOnly,
        &targets,
        &excluded
    ));
    assert!(should_intercept_process(
        2006,
        Some("ssh.exe"),
        GlobalPreAccelScope::ProxyAppsOnly,
        &targets,
        &excluded
    ));
    assert!(!should_intercept_process(
        1002,
        Some("mihomo.exe"),
        GlobalPreAccelScope::AllNon443Tcp,
        &targets,
        &excluded
    ));
    assert!(!should_intercept_process(
        3000,
        Some("svchost.exe"),
        GlobalPreAccelScope::AllNon443Tcp,
        &targets,
        &excluded
    ));
    assert!(!should_intercept_process(
        3002,
        Some("catcloud-probe-core.exe"),
        GlobalPreAccelScope::AllNon443Tcp,
        &targets,
        &excluded
    ));
    assert!(!should_intercept_process(
        3001,
        Some("chrome.exe"),
        GlobalPreAccelScope::ProxyAppsOnly,
        &targets,
        &excluded
    ));
    assert!(should_intercept_process(
        3001,
        Some("chrome.exe"),
        GlobalPreAccelScope::AllNon443Tcp,
        &targets,
        &excluded
    ));
}

#[tokio::test]
async fn forward_redirected_stream_drops_unregistered_peers_and_relays_socks5_with_metrics() {
    // 1. Spawn mock SOCKS5 server expecting NOAUTH + CONNECT 203.0.113.77:8443 then echoing payload.
    let mock_socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_port = mock_socks.local_addr().unwrap().port();

    let socks_task = tokio::spawn(async move {
        let (mut sock, _) = mock_socks.accept().await.unwrap();
        let mut greet = [0u8; 3];
        sock.read_exact(&mut greet).await.unwrap();
        assert_eq!(greet, [0x05, 0x01, 0x00]);
        sock.write_all(&[0x05, 0x00]).await.unwrap();

        let mut req = [0u8; 10];
        sock.read_exact(&mut req).await.unwrap();
        assert_eq!(req[0..4], [0x05, 0x01, 0x00, 0x01]);
        assert_eq!(req[4..8], [203, 0, 113, 77]);
        assert_eq!(u16::from_be_bytes([req[8], req[9]]), 8443);
        sock.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
            .await
            .unwrap();

        let mut data = [0u8; 5];
        sock.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"hello");
        sock.write_all(b"world!").await.unwrap();
        let _ = sock.shutdown().await;
    });

    // 2. Spawn local redirector listener backed by NatTable + GlobalPreAccelMetrics.
    let redir_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let redir_addr = redir_listener.local_addr().unwrap();
    let nat_table = Arc::new(NatTable::new(64, Duration::from_secs(60)));
    let metrics = Arc::new(GlobalPreAccelMetrics::default());
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let nat_clone = Arc::clone(&nat_table);
    let metrics_clone = Arc::clone(&metrics);
    let accept_task = tokio::spawn(async move {
        for _ in 0..2 {
            let (stream, peer) = redir_listener.accept().await.unwrap();
            let n = Arc::clone(&nat_clone);
            let m = Arc::clone(&metrics_clone);
            let rx = shutdown_rx.clone();
            tokio::spawn(async move {
                forward_redirected_stream(stream, peer, socks_port, n, m, rx, None).await;
            });
        }
    });

    // Unregistered client must be dropped immediately without touching SOCKS5 or metrics.
    let mut rogue = TcpStream::connect(redir_addr).await.unwrap();
    let mut rogue_buf = [0u8; 8];
    let n_rogue = rogue.read(&mut rogue_buf).await.unwrap();
    assert_eq!(n_rogue, 0);
    assert_eq!(metrics.total_connections.load(Ordering::Relaxed), 0);

    // Registered client connects via pre-bound local port so NatTable key matches exact peer.
    let client_sock = tokio::net::TcpSocket::new_v4().unwrap();
    client_sock
        .bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        .unwrap();
    let local_ep = match client_sock.local_addr().unwrap() {
        SocketAddr::V4(v4) => (*v4.ip(), v4.port()),
        _ => unreachable!(),
    };
    nat_table.insert(
        local_ep,
        NatEntry {
            orig_src_ip: Ipv4Addr::new(192, 0, 2, 10),
            orig_dst_ip: Ipv4Addr::new(203, 0, 113, 77),
            orig_dst_port: 8443,
            if_idx: 1,
            sub_if_idx: 0,
            owner_pid: 4242,
            process_name: "sing-box.exe".to_string(),
            detected_by: "system_proxy_host".to_string(),
            last_seen: Instant::now(),
            closing_since: None,
        },
    );

    let mut client = client_sock.connect(redir_addr).await.unwrap();
    client.write_all(b"hello").await.unwrap();
    let mut reply = [0u8; 6];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"world!");
    drop(client);

    let _ = socks_task.await;
    let _ = accept_task.await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let _ = shutdown_tx.send(true);

    assert_eq!(metrics.total_connections.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 0);
    // NAT entry stays in closing-grace retention for clean FIN-ACK teardown instead of immediate deletion.
    let closing_entry = nat_table
        .get_and_touch(&local_ep)
        .expect("entry should stay in closing grace");
    assert!(closing_entry.closing_since.is_some());
    assert!(metrics.up_bytes.load(Ordering::Relaxed) >= 5);
    assert!(metrics.down_bytes.load(Ordering::Relaxed) >= 6);
    assert_eq!(
        metrics.recent_processes_snapshot(),
        vec!["sing-box.exe".to_string()]
    );

    let proc_stats = metrics.snapshot();
    assert_eq!(proc_stats.len(), 1);
    assert_eq!(proc_stats[0].process_name, "sing-box.exe");
    assert_eq!(proc_stats[0].pid, 4242);
    assert_eq!(proc_stats[0].detected_by, "system_proxy_host");
    assert_eq!(proc_stats[0].active_connections, 0);
    assert_eq!(proc_stats[0].total_connections, 1);
    assert!(proc_stats[0].tx_bytes >= 5);
    assert!(proc_stats[0].rx_bytes >= 6);
    assert!(proc_stats[0].last_seen_ms > 0);
}

#[test]
fn nat_table_remove_and_remove_if_matching_guard_port_reuse() {
    let table = NatTable::new(16, Duration::from_secs(60));
    let now = Instant::now();
    let key_a = (Ipv4Addr::new(192, 0, 2, 10), 41000);
    let key_b = (Ipv4Addr::new(192, 0, 2, 10), 41001);

    table.insert(
        key_a,
        NatEntry {
            orig_src_ip: Ipv4Addr::new(192, 0, 2, 10),
            orig_dst_ip: Ipv4Addr::new(203, 0, 113, 10),
            orig_dst_port: 8443,
            if_idx: 3,
            sub_if_idx: 0,
            owner_pid: 5100,
            process_name: "app-a.exe".to_string(),
            detected_by: "manual".to_string(),
            last_seen: now,
            closing_since: None,
        },
    );
    table.insert(
        key_b,
        NatEntry {
            orig_src_ip: Ipv4Addr::new(192, 0, 2, 10),
            orig_dst_ip: Ipv4Addr::new(203, 0, 113, 20),
            orig_dst_port: 2053,
            if_idx: 3,
            sub_if_idx: 0,
            owner_pid: 5101,
            process_name: "app-b.exe".to_string(),
            detected_by: "local_proxy_listener".to_string(),
            last_seen: now,
            closing_since: None,
        },
    );

    // Mismatched destination IP or port must leave the newer mapping intact.
    assert!(!table.remove_if_matching(&key_a, Ipv4Addr::new(203, 0, 113, 99), 8443));
    assert!(!table.remove_if_matching(&key_a, Ipv4Addr::new(203, 0, 113, 10), 9443));
    assert!(table.get_and_touch(&key_a).is_some());

    // Exact destination match removes the entry cleanly.
    assert!(table.remove_if_matching(&key_a, Ipv4Addr::new(203, 0, 113, 10), 8443));
    assert!(table.get_and_touch(&key_a).is_none());
    assert!(!table.remove_if_matching(&key_a, Ipv4Addr::new(203, 0, 113, 10), 8443));

    // Direct `remove` returns the evicted entry once, then `None`.
    let removed = table.remove(&key_b).expect("remove existing key_b");
    assert_eq!(removed.orig_dst_ip, Ipv4Addr::new(203, 0, 113, 20));
    assert_eq!(removed.orig_dst_port, 2053);
    assert!(table.remove(&key_b).is_none());
    assert!(table.is_empty());
}

#[test]
fn should_intercept_process_conservatively_bypasses_unknown_process_names() {
    let targets: HashSet<String> = ["mihomo.exe"].into_iter().map(String::from).collect();
    let excluded: HashSet<u32> = HashSet::new();

    assert!(!should_intercept_process(
        4001,
        None,
        GlobalPreAccelScope::AllNon443Tcp,
        &targets,
        &excluded
    ));
    assert!(!should_intercept_process(
        4001,
        None,
        GlobalPreAccelScope::ProxyAppsOnly,
        &targets,
        &excluded
    ));
    assert!(!should_intercept_process(
        4002,
        Some("   "),
        GlobalPreAccelScope::AllNon443Tcp,
        &targets,
        &excluded
    ));
}

#[test]
fn sync_main_core_pid_dynamically_updates_and_preserves_self_and_tunnel() {
    let self_pid = std::process::id();
    let tunnel_pid = self_pid.wrapping_add(10_001).max(100);
    let static_pid = self_pid.wrapping_add(10_002).max(101);
    let main_pid_v1 = self_pid.wrapping_add(20_001).max(200);
    let main_pid_v2 = self_pid.wrapping_add(20_002).max(201);

    let tracker = ExcludedPidTracker::new(self_pid, Some(tunnel_pid), [static_pid], None);
    let shared = tracker.shared_set();

    {
        let guard = shared.read().unwrap();
        assert!(guard.contains(&self_pid));
        assert!(guard.contains(&tunnel_pid));
        assert!(guard.contains(&static_pid));
        assert!(!guard.contains(&main_pid_v1));
    }

    // First sync adds external main core PID.
    tracker.sync_main_core_pid(Some(main_pid_v1));
    {
        let guard = shared.read().unwrap();
        assert!(guard.contains(&self_pid));
        assert!(guard.contains(&tunnel_pid));
        assert!(guard.contains(&static_pid));
        assert!(guard.contains(&main_pid_v1));
    }

    // Restarting main core replaces only the main core slot, evicting old PID.
    tracker.sync_main_core_pid(Some(main_pid_v2));
    {
        let guard = shared.read().unwrap();
        assert!(guard.contains(&self_pid));
        assert!(guard.contains(&tunnel_pid));
        assert!(guard.contains(&static_pid));
        assert!(!guard.contains(&main_pid_v1));
        assert!(guard.contains(&main_pid_v2));
    }

    // Setting slot to a pinned PID and clearing must never drop self or tunnel PIDs.
    tracker.sync_main_core_pid(Some(tunnel_pid));
    tracker.sync_main_core_pid(None);
    {
        let guard = shared.read().unwrap();
        assert!(guard.contains(&self_pid));
        assert!(guard.contains(&tunnel_pid));
        assert!(guard.contains(&static_pid));
        assert!(!guard.contains(&main_pid_v2));
    }

    // Verify `GlobalPreAccelManager::sync_main_core_pid` tracks live slot updates cleanly.
    let root = std::env::temp_dir().join(format!(
        "catcloud-sync-pid-{}",
        uuid::Uuid::new_v4()
    ));
    let paths = AppPaths::from_data_dir(root.join("data"), true).unwrap();
    let job_guard = Arc::new(JobGuard::new().unwrap());
    let manager = GlobalPreAccelManager::new(paths, job_guard);

    manager.sync_main_core_pid(Some(main_pid_v1));
    assert_eq!(*manager.synced_main_core_pid.lock().unwrap(), Some(main_pid_v1));
    manager.sync_main_core_pid(Some(0));
    assert_eq!(*manager.synced_main_core_pid.lock().unwrap(), None);
    manager.sync_main_core_pid(Some(main_pid_v2));
    assert_eq!(*manager.synced_main_core_pid.lock().unwrap(), Some(main_pid_v2));
    manager.sync_main_core_pid(None);
    assert_eq!(*manager.synced_main_core_pid.lock().unwrap(), None);

    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn forward_redirected_stream_exits_promptly_on_shutdown_during_socks5_handshake() {
    // Stalled mock SOCKS5 server that accepts the TCP connection, signals readiness, and never replies.
    let stalled_socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_port = stalled_socks.local_addr().unwrap().port();
    let (connected_tx, connected_rx) = tokio::sync::oneshot::channel::<()>();
    let socks_hold = tokio::spawn(async move {
        let (_conn, _) = stalled_socks.accept().await.unwrap();
        let _ = connected_tx.send(());
        tokio::time::sleep(Duration::from_secs(30)).await;
    });

    let redir_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let redir_addr = redir_listener.local_addr().unwrap();
    let nat_table = Arc::new(NatTable::new(16, Duration::from_secs(60)));
    let metrics = Arc::new(GlobalPreAccelMetrics::default());
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let client_sock = tokio::net::TcpSocket::new_v4().unwrap();
    client_sock
        .bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        .unwrap();
    let local_ep = match client_sock.local_addr().unwrap() {
        SocketAddr::V4(v4) => (*v4.ip(), v4.port()),
        _ => unreachable!(),
    };
    nat_table.insert(
        local_ep,
        NatEntry {
            orig_src_ip: Ipv4Addr::new(192, 0, 2, 10),
            orig_dst_ip: Ipv4Addr::new(203, 0, 113, 88),
            orig_dst_port: 8443,
            if_idx: 1,
            sub_if_idx: 0,
            owner_pid: 6001,
            process_name: "stalled.exe".to_string(),
            detected_by: "manual".to_string(),
            last_seen: Instant::now(),
            closing_since: None,
        },
    );

    let nat_ref = Arc::clone(&nat_table);
    let metrics_ref = Arc::clone(&metrics);
    let fwd_task = tokio::spawn(async move {
        let (stream, peer) = redir_listener.accept().await.unwrap();
        forward_redirected_stream(
            stream,
            peer,
            socks_port,
            nat_ref,
            metrics_ref,
            shutdown_rx,
            None,
        )
        .await;
    });

    let _client = client_sock.connect(redir_addr).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), connected_rx)
        .await
        .expect("upstream SOCKS5 socket should connect promptly")
        .expect("connected signal ok");
    let _ = shutdown_tx.send(true);

    tokio::time::timeout(Duration::from_secs(2), fwd_task)
        .await
        .expect("forward_redirected_stream must exit promptly on shutdown")
        .expect("forward task join ok");

    socks_hold.abort();
    assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 0);
    // Entry transitions to graceful FIN-ACK closing grace rather than hard-dropping mid-close.
    let closed_entry = nat_table
        .get_and_touch(&local_ep)
        .expect("closing grace entry remains briefly for FIN-ACK rewrite");
    assert!(closed_entry.closing_since.is_some());
    assert!(nat_table.has_active_conflict(
        &local_ep,
        Ipv4Addr::new(192, 0, 2, 11),
        Ipv4Addr::new(203, 0, 113, 88),
        8443
    ));
    assert!(nat_table.has_active_conflict(
        &local_ep,
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(203, 0, 113, 99),
        8443
    ));
    assert!(!nat_table.has_active_conflict(
        &local_ep,
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(203, 0, 113, 88),
        8443
    ));
}

#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
#[tokio::test]
async fn windows_arm64_windivert_guards_return_none_and_validation_error() {
    let root = std::env::temp_dir().join(format!(
        "catcloud-wd-arm64-{}",
        uuid::Uuid::new_v4()
    ));
    let paths = AppPaths::from_data_dir(root.join("data"), true).unwrap();
    std::fs::write(paths.bin_dir.join("WinDivert64.dll"), b"x64-dll").unwrap();
    std::fs::write(paths.bin_dir.join("WinDivert64.sys"), b"x64-sys").unwrap();

    assert!(locate_windivert_files(&paths, None).is_none());
    assert!(locate_windivert_files_with_exe_dir(&paths, None, None).is_none());

    let err = download_and_install_windivert(&paths, None)
        .await
        .expect_err("ARM64 must reject WinDivert download");
    match err {
        CatError::Validation(msg) => {
            assert!(msg.contains("Windows ARM64"));
            assert!(msg.contains("本地独立 443 通道"));
        }
        other => panic!("expected CatError::Validation, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn classify_intercept_process_respects_exclusions_dynamic_hosts_open_stems_and_manual() {
    let targets: HashSet<String> = ["ssh.exe", "custom-sync.exe"]
        .into_iter()
        .map(String::from)
        .collect();
    let excluded: HashSet<u32> = [1001, 1002, 2001].into_iter().collect();
    let mut detected: HashMap<u32, &'static str> = HashMap::new();
    detected.insert(2001, "system_proxy_host"); // must still be blocked by `excluded`
    detected.insert(2002, "system_proxy_host");
    detected.insert(2003, "local_proxy_listener");

    // 1. Excluded PIDs and system/self binaries ALWAYS win over dynamic detection or scope.
    assert_eq!(
        classify_intercept_process(
            2001,
            Some("mihomo.exe"),
            GlobalPreAccelScope::AllNon443Tcp,
            &targets,
            &excluded,
            &detected,
        ),
        None
    );
    assert_eq!(
        classify_intercept_process(
            2002,
            Some("catcloud.exe"),
            GlobalPreAccelScope::AllNon443Tcp,
            &targets,
            &excluded,
            &detected,
        ),
        None
    );
    assert_eq!(
        classify_intercept_process(
            2002,
            Some("catcloud-helper.exe"),
            GlobalPreAccelScope::AllNon443Tcp,
            &targets,
            &excluded,
            &detected,
        ),
        None
    );
    assert_eq!(
        classify_intercept_process(
            2002,
            Some("svchost.exe"),
            GlobalPreAccelScope::AllNon443Tcp,
            &targets,
            &excluded,
            &detected,
        ),
        None
    );

    // 2. Dynamic runtime detections classify arbitrary executable names without hardcoded lists.
    assert_eq!(
        classify_intercept_process(
            2002,
            Some("third-party-proxy-engine.exe"),
            GlobalPreAccelScope::ProxyAppsOnly,
            &targets,
            &excluded,
            &detected,
        ),
        Some("system_proxy_host")
    );
    assert_eq!(
        classify_intercept_process(
            2003,
            Some("proxy-daemon.exe"),
            GlobalPreAccelScope::ProxyAppsOnly,
            &targets,
            &excluded,
            &detected,
        ),
        Some("local_proxy_listener")
    );

    // 3. Generic open-source core stems match even when not explicitly listed in `targets`.
    assert_eq!(
        classify_intercept_process(
            3001,
            Some(r"D:\Tools\sing-box-core.exe"),
            GlobalPreAccelScope::ProxyAppsOnly,
            &targets,
            &excluded,
            &detected,
        ),
        Some("open_core_name")
    );
    assert_eq!(
        classify_intercept_process(
            3002,
            Some("tun2socks-win64.exe"),
            GlobalPreAccelScope::ProxyAppsOnly,
            &targets,
            &excluded,
            &detected,
        ),
        Some("open_core_name")
    );

    // 4. Explicit manual target names match as `"manual"`.
    assert_eq!(
        classify_intercept_process(
            3003,
            Some("custom-sync.exe"),
            GlobalPreAccelScope::ProxyAppsOnly,
            &targets,
            &excluded,
            &detected,
        ),
        Some("manual")
    );

    // 5. Unrelated apps bypass in `ProxyAppsOnly`, match `"scope_all"` in `AllNon443Tcp`.
    assert_eq!(
        classify_intercept_process(
            3004,
            Some("browser.exe"),
            GlobalPreAccelScope::ProxyAppsOnly,
            &targets,
            &excluded,
            &detected,
        ),
        None
    );
    assert_eq!(
        classify_intercept_process(
            3004,
            Some("browser.exe"),
            GlobalPreAccelScope::AllNon443Tcp,
            &targets,
            &excluded,
            &detected,
        ),
        Some("scope_all")
    );
}

#[test]
fn metrics_process_stats_aggregates_sorts_and_evicts_bounded_capacity() {
    let metrics = GlobalPreAccelMetrics::default();

    // Process A: 1 active connection, 100 bytes total.
    metrics.record_process_connection_open(100, "mihomo.exe", "system_proxy_host");
    metrics.record_process_bytes(100, "mihomo.exe", "system_proxy_host", 40, 60);

    // Process B: 2 active connections, 50 bytes total -> ranks first by active_connections.
    metrics.record_process_connection_open(200, "xray.exe", "local_proxy_listener");
    metrics.record_process_connection_open(200, "xray.exe", "local_proxy_listener");
    metrics.record_process_bytes(200, "xray.exe", "local_proxy_listener", 20, 30);

    // Process C: 0 active connections, 5000 bytes total -> ranks behind active processes.
    metrics.record_process_connection_open(300, "ssh.exe", "manual");
    metrics.record_process_bytes(300, "ssh.exe", "manual", 2000, 3000);
    metrics.record_process_connection_close(300, "ssh.exe", "manual");

    let snap = metrics.snapshot();
    assert_eq!(snap.len(), 3);
    assert_eq!(snap[0].process_name, "xray.exe");
    assert_eq!(snap[0].active_connections, 2);
    assert_eq!(snap[0].total_connections, 2);
    assert_eq!(snap[1].process_name, "mihomo.exe");
    assert_eq!(snap[1].active_connections, 1);
    assert_eq!(snap[2].process_name, "ssh.exe");
    assert_eq!(snap[2].active_connections, 0);
    assert_eq!(snap[2].tx_bytes, 2000);
    assert_eq!(snap[2].rx_bytes, 3000);

    // Clearing active connections zeroes active gauges while preserving historical bytes.
    metrics.clear_active_connections();
    let after_clear = metrics.snapshot();
    assert!(after_clear.iter().all(|s| s.active_connections == 0));
    // With all active == 0, highest total bytes (`ssh.exe`, 5000 B) moves to rank 0.
    assert_eq!(after_clear[0].process_name, "ssh.exe");

    // Bounded capacity test: insert > MAX_PROCESS_STATS idle processes and assert hard cap.
    for idx in 0..(MAX_PROCESS_STATS as u32 + 12) {
        let pid = 10_000 + idx;
        let name = format!("worker-{idx}.exe");
        metrics.record_process_connection_open(pid, &name, "open_core_name");
        metrics.record_process_connection_close(pid, &name, "open_core_name");
    }
    assert!(metrics.snapshot().len() <= MAX_PROCESS_STATS);

    metrics.reset();
    assert!(metrics.snapshot().is_empty());
}

#[test]
fn global_preaccel_status_backcompat_serde_and_install_state_transitions() {
    // Legacy JSON missing new Stage 12 fields must deserialize cleanly with safe defaults.
    let legacy_json = r#"{
        "running": true,
        "mode": "local_socks5",
        "socks_port": 17908,
        "windivert_available": false,
        "windivert_path": null,
        "is_elevated": false,
        "active_connections": 0,
        "total_connections": 0,
        "up_bytes": 0,
        "down_bytes": 0,
        "accelerated_processes": [],
        "active_relays": ["Relay-A"],
        "last_error": null
    }"#;
    let parsed: GlobalPreAccelStatus =
        serde_json::from_str(legacy_json).expect("deserialize legacy GlobalPreAccelStatus");
    assert!(!parsed.is_windivert_active);
    assert_eq!(parsed.install_state, "idle");
    assert_eq!(parsed.verify_state, "idle");
    assert!(parsed.verify_latency_ms.is_none());
    assert!(parsed.verify_message.is_none());
    assert!(parsed.detected_security_products.is_empty());
    assert!(parsed.security_guidance.is_none());
    assert!(parsed.bound_physical_interface.is_none());
    assert!(parsed.process_stats.is_empty());

    // Manager install state normalization and reporting.
    let root = std::env::temp_dir().join(format!(
        "catcloud-install-state-{}",
        uuid::Uuid::new_v4()
    ));
    let paths = AppPaths::from_data_dir(root.join("data"), true).unwrap();
    #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
    let bin_dir = paths.bin_dir.clone();
    let job_guard = Arc::new(JobGuard::new().unwrap());
    let manager = GlobalPreAccelManager::new(paths, job_guard);

    manager.set_install_state("downloading");
    assert_eq!(manager.status().install_state, "downloading");
    assert!(!manager.status().is_windivert_active);

    manager.set_install_state("VERIFYING");
    assert_eq!(manager.status().install_state, "verifying");

    manager.set_install_state("need_elevation");
    assert_eq!(manager.install_state(), "need_elevation");
    #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
    {
        let st_missing = manager.status();
        if !st_missing.windivert_available {
            assert_eq!(st_missing.install_state, "idle");
        }
        let dll_path = bin_dir.join("WinDivert64.dll");
        let sys_path = bin_dir.join("WinDivert64.sys");
        std::fs::write(&dll_path, b"stub-dll").unwrap();
        std::fs::write(&sys_path, b"stub-sys").unwrap();
        let st_present = manager.status();
        assert!(st_present.windivert_available);
        assert_eq!(
            st_present.install_state,
            if st_present.is_elevated {
                "ready"
            } else {
                "need_elevation"
            }
        );
        manager.set_install_state("ready");
        let _ = std::fs::remove_file(&dll_path);
        let _ = std::fs::remove_file(&sys_path);
        let st_removed = manager.status();
        if !st_removed.windivert_available {
            assert_eq!(st_removed.install_state, "idle");
        }
    }
    #[cfg(not(all(target_os = "windows", not(target_arch = "aarch64"))))]
    assert_eq!(manager.status().install_state, "need_elevation");

    manager.set_install_state("failed");
    assert_eq!(manager.status().install_state, "failed");

    manager.set_install_state("unknown-bogus");
    assert_eq!(manager.install_state(), "idle");

    let _ = std::fs::remove_dir_all(&root);
}

