use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;
use catcloud_core::core_adapter::binary_resolver::resolve_mihomo_binary;
use catcloud_core::models::MultiGroup;
use catcloud_core::models::PreAccelRelay;
use catcloud_core::models::ProbeDefinition;
use catcloud_core::models::ProxyNode;
use catcloud_core::models::RouteTargetMode;
use catcloud_core::models::is_info_proxy_node;
use catcloud_core::models::is_ipv6_only_node;
use catcloud_core::models::pick_smart_default_node_id;
use catcloud_core::preaccel::campus::CampusPortalState;
use catcloud_core::preaccel::campus::probe_campus_portal_with_fallback;
use catcloud_core::probe::DEFAULT_READY_TIMEOUT;
use catcloud_core::probe::IsolatedProbeCore;
use catcloud_core::probe::ThroughputProbeConfig;
use catcloud_core::probe::build_isolated_http_client;
use catcloud_core::probe::run_download_probe_with_config;
use catcloud_core::probe::run_latency_probe;
use catcloud_core::probe::run_upload_probe_with_config;
use chrono::Utc;
use serde::Deserialize;
use serde::Serialize;
use tauri::AppHandle;
use tauri::State;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::commands::core_lifecycle::trigger_reload_if_running;
use crate::commands::state::AppState;
use crate::commands::strategy_rank::resolve_valid_group_active_node;
use crate::commands::tray_runtime::ProbeRunningGuard;
use crate::commands::tray_runtime::emit_relays_updated;
use crate::commands::tray_runtime::format_mihomo_error_for_user;
use crate::commands::tray_runtime::sync_tray_and_window_side_effects;

pub(in crate::commands) fn format_tcp_host_port(host: &str, port: u16) -> String {
    let trimmed = host.trim();
    if trimmed.contains(':') && !(trimmed.starts_with('[') && trimmed.ends_with(']')) {
        format!("[{trimmed}]:{port}")
    } else {
        format!("{trimmed}:{port}")
    }
}


#[derive(Debug)]
struct RelayProbeNoCertVerify;


impl rustls::client::danger::ServerCertVerifier for RelayProbeNoCertVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}


fn relay_probe_tls_config() -> Arc<rustls::ClientConfig> {
    static TLS_CFG: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    TLS_CFG
        .get_or_init(|| {
            catcloud_core::init_crypto_provider();
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let cfg = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("valid ring TLS protocol versions")
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(RelayProbeNoCertVerify))
                .with_no_client_auth();
            Arc::new(cfg)
        })
        .clone()
}


pub(in crate::commands) fn relay_is_udp_quic_protocol(relay: &PreAccelRelay) -> bool {
    matches!(
        relay.protocol.trim().to_ascii_lowercase().as_str(),
        "tuic" | "hysteria2" | "hy2" | "hysteria"
    )
}


pub(in crate::commands) fn relay_uses_tls_probe(relay: &PreAccelRelay) -> bool {
    if relay_is_udp_quic_protocol(relay) {
        return false;
    }
    if relay.port == 443 {
        return true;
    }
    matches!(
        relay.protocol.trim().to_ascii_lowercase().as_str(),
        "trojan" | "anytls" | "vless" | "vmess"
    )
}


pub(in crate::commands) fn relay_allows_plain_fallback(relay: &PreAccelRelay) -> bool {
    !matches!(
        relay.protocol.trim().to_ascii_lowercase().as_str(),
        "trojan" | "anytls"
    )
}


/// Align relay TLS probe SNI with `preaccel/generator.rs` compilation rules:
/// domestic `:443` relays always strip `relay.sni` and probe with bare host/IP (`relay.server`),
/// while non-443 relays prefer configured `relay.sni` when present.
pub(in crate::commands) fn resolve_relay_probe_sni_or_host(relay: &PreAccelRelay) -> String {
    let bare_host = relay
        .server
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']');
    if relay.port == 443 {
        return bare_host.to_string();
    }
    relay
        .sni
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(bare_host)
        .to_string()
}


fn is_local_or_private_host(host: &str) -> bool {
    let bare = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']');
    if bare.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match bare.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
        }
        Err(_) => false,
    }
}


async fn measure_relay_tls_handshake_ms(
    addr: &str,
    sni_or_host: &str,
    timeout: Duration,
) -> Result<f64, String> {
    let server_name = rustls::pki_types::ServerName::try_from(sni_or_host.to_string())
        .or_else(|_| rustls::pki_types::ServerName::try_from("localhost".to_string()))
        .map_err(|e| format!("解析中转主机名失败：{e}"))?;
    let tls_cfg = relay_probe_tls_config();

    let handshake_fut = async move {
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("连接国内中转失败：{e}"))?;
        let _ = stream.set_nodelay(true);

        // Start timing right before TLS ClientHello: even when Wintun/TUN proxies TCP SYN-ACK
        // locally in <1ms, the TLS ServerHello MUST arrive from the remote relay server.
        let tls_started = Instant::now();
        let mut conn = rustls::ClientConnection::new(tls_cfg, server_name)
            .map_err(|e| format!("初始化 TLS 探测失败：{e}"))?;
        let mut write_buf = Vec::with_capacity(2048);
        let mut read_buf = [0u8; 4096];

        while conn.is_handshaking() {
            while conn.wants_write() {
                write_buf.clear();
                conn.write_tls(&mut write_buf)
                    .map_err(|e| format!("构造 TLS 握手包失败：{e}"))?;
                if !write_buf.is_empty() {
                    stream
                        .write_all(&write_buf)
                        .await
                        .map_err(|e| format!("发送 TLS 握手包失败：{e}"))?;
                }
            }
            if !conn.is_handshaking() {
                break;
            }
            if conn.wants_read() {
                let n = stream
                    .read(&mut read_buf)
                    .await
                    .map_err(|e| format!("读取远端 TLS 响应失败：{e}"))?;
                if n == 0 {
                    return Err("远端在 TLS 握手完成前关闭了连接".to_string());
                }
                let mut slice = &read_buf[..n];
                while !slice.is_empty() {
                    let read_in = conn
                        .read_tls(&mut slice)
                        .map_err(|e| format!("解析远端 TLS 响应失败：{e}"))?;
                    if read_in == 0 {
                        break;
                    }
                    conn.process_new_packets()
                        .map_err(|e| format!("TLS 握手未通过：{e}"))?;
                }
            } else if !conn.wants_write() {
                break;
            }
        }

        let ms = (tls_started.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0;
        Ok(ms.max(0.1))
    };

    match tokio::time::timeout(timeout, handshake_fut).await {
        Ok(res) => res,
        Err(_) => Err("中转 TLS 握手超时（4 秒）".to_string()),
    }
}


async fn measure_relay_plain_rtt_ms(relay: &PreAccelRelay) -> Result<f64, String> {
    let addr = format_tcp_host_port(&relay.server, relay.port);
    let started = Instant::now();
    match tokio::time::timeout(Duration::from_secs(4), TcpStream::connect(&addr)).await {
        Ok(Ok(_stream)) => {
            let ms = started.elapsed().as_secs_f64() * 1000.0;
            if !is_local_or_private_host(&relay.server) && ms < 2.0 {
                // Likely synthetic local SYN-ACK from Wintun TUN; try an end-to-end HTTP probe.
                if let Ok(client) = reqwest::Client::builder()
                    .no_proxy()
                    .danger_accept_invalid_certs(true)
                    .connect_timeout(Duration::from_secs(3))
                    .timeout(Duration::from_secs(3))
                    .build()
                {
                    let http_url = format!("http://{addr}/");
                    let http_started = Instant::now();
                    match client.get(&http_url).send().await {
                        Ok(_resp) => {
                            let h_ms = http_started.elapsed().as_secs_f64() * 1000.0;
                            if h_ms >= 2.0 {
                                return Ok(((h_ms * 10.0).round() / 10.0).max(0.1));
                            }
                        }
                        Err(err) if !err.is_timeout() && !err.is_connect() => {
                            let h_ms = http_started.elapsed().as_secs_f64() * 1000.0;
                            if h_ms >= 2.0 {
                                return Ok(((h_ms * 10.0).round() / 10.0).max(0.1));
                            }
                        }
                        Err(_) => {}
                    }
                }
                return Err(
                    "虚拟网卡接管了明文 TCP 握手，无法测得真实延迟（建议改用 443/TLS 中转或关闭虚拟网卡后重试）"
                        .to_string(),
                );
            }
            Ok(((ms * 10.0).round() / 10.0).max(0.1))
        }
        Ok(Err(err)) => Err(format!("TCP 连接中转失败：{err}")),
        Err(_) => Err("TCP 连接超时（4 秒）".to_string()),
    }
}


/// Native UDP/QUIC end-to-end RTT probe for pure UDP/QUIC relays (`tuic`, `hysteria2`, `hy2`,
/// `hysteria`), avoiding meaningless 4s TCP TLS handshake failures against UDP-only endpoints.
/// Sends an RFC 9000 QUIC Version Negotiation trigger (1200-byte Long Header with GREASE version)
/// so compliant QUIC servers reply statelessly in 1 RTT without credentials.
async fn measure_relay_udp_quic_rtt_ms(relay: &PreAccelRelay) -> Result<f64, String> {
    let addr = format_tcp_host_port(relay.server.trim(), relay.port);
    let target = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::lookup_host(addr.as_str()),
    )
    .await
    .map_err(|_| "解析 UDP/QUIC 中转地址超时（2 秒）".to_string())?
    .map_err(|e| format!("解析 UDP/QUIC 中转地址失败：{e}"))?
    .next()
    .ok_or_else(|| "未能解析到有效的 UDP/QUIC 中转 IP 地址".to_string())?;

    let bind_addr = if target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = tokio::net::UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| format!("创建本地 UDP 探测套接字失败：{e}"))?;
    socket
        .connect(target)
        .await
        .map_err(|e| format!("绑定 UDP/QUIC 中转目标失败：{e}"))?;

    let mut probe_pkt = vec![0u8; 1200];
    probe_pkt[0] = 0xc0; // QUIC Long Header | Fixed Bit
    probe_pkt[1..5].copy_from_slice(&[0x0a, 0x0a, 0x0a, 0x0a]); // GREASE version
    probe_pkt[5] = 8; // DCID len
    probe_pkt[6..14].copy_from_slice(b"CATCLOUD");
    probe_pkt[14] = 8; // SCID len
    probe_pkt[15..23].copy_from_slice(b"PROBE001");

    let started = Instant::now();
    socket
        .send(&probe_pkt)
        .await
        .map_err(|e| format!("发送 UDP/QUIC 探测包失败：{e}"))?;

    let mut recv_buf = [0u8; 2048];
    match tokio::time::timeout(Duration::from_millis(2500), socket.recv(&mut recv_buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let ms = (started.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0;
            Ok(ms.max(0.1))
        }
        Ok(Ok(_)) => Err("UDP/QUIC 中转返回了空响应".to_string()),
        Ok(Err(err)) => Err(format!("UDP/QUIC 中转端口不可达或被拒绝：{err}")),
        Err(_) => Err(
            "UDP/QUIC 中转探测超时（2.5 秒，服务端可能未开放 UDP 端口或启用了静默防探测）"
                .to_string(),
        ),
    }
}


/// Measure real end-to-end RTT to a domestic pre-acceleration relay without falling prey to
/// Wintun/TUN synthetic `<1ms` local TCP SYN-ACK responses.
pub(in crate::commands) async fn measure_relay_real_rtt_ms(relay: &PreAccelRelay) -> Result<f64, String> {
    let host = relay.server.trim();
    if host.is_empty() || relay.port == 0 {
        return Err("中转服务器地址或端口无效".to_string());
    }
    if relay_is_udp_quic_protocol(relay) {
        return measure_relay_udp_quic_rtt_ms(relay).await;
    }
    let addr = format_tcp_host_port(host, relay.port);
    if relay_uses_tls_probe(relay) {
        let sni_or_host = resolve_relay_probe_sni_or_host(relay);
        match measure_relay_tls_handshake_ms(&addr, &sni_or_host, Duration::from_secs(4)).await {
            Ok(ms) => Ok(ms),
            Err(tls_err) => {
                if relay_allows_plain_fallback(relay) {
                    measure_relay_plain_rtt_ms(relay).await.or(Err(tls_err))
                } else {
                    Err(tls_err)
                }
            }
        }
    } else {
        measure_relay_plain_rtt_ms(relay).await
    }
}


#[tauri::command]
pub async fn test_preaccel_relays(
    app: AppHandle,
    state: State<'_, AppState>,
    relay_ids: Option<Vec<String>>,
) -> Result<serde_json::Value, String> {
    const MAX_RELAY_PROBE_CONCURRENCY: usize = 4;

    let relays = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let all = db.list_preaccel_relays(false).map_err(|e| e.to_string())?;
        if let Some(ids) = relay_ids {
            all.into_iter().filter(|r| ids.contains(&r.id)).collect()
        } else {
            all
        }
    };

    let total_count = relays.len();
    let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_RELAY_PROBE_CONCURRENCY));
    let mut join_set = tokio::task::JoinSet::new();

    for (idx, relay) in relays.into_iter().enumerate() {
        let sem = Arc::clone(&semaphore);
        join_set.spawn(async move {
            let _permit = sem.acquire_owned().await.ok();
            let probe_res = measure_relay_real_rtt_ms(&relay).await;
            (idx, relay, probe_res)
        });
    }

    let mut ordered_outcomes: Vec<(usize, PreAccelRelay, Result<f64, String>)> =
        Vec::with_capacity(total_count);
    while let Some(joined) = join_set.join_next().await {
        if let Ok(item) = joined {
            ordered_outcomes.push(item);
        }
    }
    ordered_outcomes.sort_by_key(|(idx, _, _)| *idx);

    let mut results = Vec::with_capacity(total_count);
    let mut ok_count = 0usize;
    let mut metrics_updates: Vec<(String, f64, Option<f64>, Option<f64>)> = Vec::new();
    for (_idx, relay, probe_res) in ordered_outcomes {
        match probe_res {
            Ok(ms) if ms.is_finite() && ms > 0.0 => {
                ok_count += 1;
                let rounded = ((ms * 10.0).round() / 10.0).max(0.1);
                metrics_updates.push((
                    relay.id.clone(),
                    rounded,
                    relay.last_up_mbps.or(relay.last_mbps),
                    relay.last_down_mbps,
                ));
                results.push(serde_json::json!({
                    "relay_id": relay.id,
                    "ok": true,
                    "latency_ms": rounded,
                    "error": null
                }));
            }
            Ok(_) => {
                results.push(serde_json::json!({
                    "relay_id": relay.id,
                    "ok": false,
                    "latency_ms": null,
                    "error": "未测得有效的端到端延迟"
                }));
            }
            Err(err) => {
                results.push(serde_json::json!({
                    "relay_id": relay.id,
                    "ok": false,
                    "latency_ms": null,
                    "error": err
                }));
            }
        }
    }
    if !metrics_updates.is_empty() {
        if let Ok(db) = state.storage.lock() {
            for (relay_id, rounded, last_up_mbps, last_down_mbps) in metrics_updates {
                let _ = db.update_preaccel_speed_metrics(
                    &relay_id,
                    Some(rounded),
                    last_up_mbps,
                    last_down_mbps,
                );
            }
        }
        emit_relays_updated(&app);
    }
    state.log_app_event(
        if ok_count == total_count { "info" } else { "warning" },
        "国内提速",
        &format!("国内中转真实 RTT 测速完成：可用 {ok_count}/{total_count}"),
    );
    Ok(serde_json::Value::Array(results))
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::commands) struct PreAccelSideSpeedDto {
    pub(in crate::commands) ok: bool,
    pub(in crate::commands) latency_ms: Option<f64>,
    pub(in crate::commands) up_mbps: Option<f64>,
    pub(in crate::commands) down_mbps: Option<f64>,
    pub(in crate::commands) error: Option<String>,
}


fn is_info_placeholder_node(node: &ProxyNode) -> bool {
    if is_info_proxy_node(node) {
        return true;
    }
    const HINTS: &[&str] = &[
        "剩余流量",
        "剩餘流量",
        "过期时间",
        "過期時間",
        "到期",
        "套餐",
        "官网",
        "官網",
        "重置",
        "距离下次",
        "更新订阅",
    ];
    HINTS.iter().any(|h| node.name.contains(h))
}


fn is_preferred_comparison_region(region_code: &str) -> bool {
    matches!(
        region_code.trim().to_ascii_uppercase().as_str(),
        "TW" | "HK" | "SG" | "JP" | "US" | "KR"
    )
}


fn is_obscure_high_multiplier_node(node: &ProxyNode) -> bool {
    node.multiplier.is_finite()
        && node.multiplier >= 3.0 - 1e-9
        && !is_preferred_comparison_region(&node.region_code)
}


fn resolve_homepage_node<'a>(
    groups: &'a [MultiGroup],
    nodes: &'a [ProxyNode],
    route_mode: RouteTargetMode,
    active_single_node_id: Option<&str>,
    active_group_id: Option<&str>,
) -> Option<&'a ProxyNode> {
    if route_mode == RouteTargetMode::Single {
        if let Some(node) = active_single_node_id
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|nid| nodes.iter().find(|n| n.id == nid))
        {
            return Some(node);
        }
    }

    let primary_group = active_group_id
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|gid| groups.iter().find(|g| g.id == gid))
        .or_else(|| groups.first());

    match primary_group {
        Some(g) => resolve_valid_group_active_node(g, nodes),
        None => pick_smart_default_node_id(nodes, None)
            .and_then(|id| nodes.iter().find(|n| n.id == id))
            .or_else(|| nodes.iter().find(|n| n.enabled))
            .or_else(|| nodes.first()),
    }
}


fn pick_smart_from_refs<'a>(candidates: &[&'a ProxyNode]) -> Option<&'a ProxyNode> {
    if candidates.is_empty() {
        return None;
    }
    let owned: Vec<ProxyNode> = candidates.iter().map(|n| (*n).clone()).collect();
    pick_smart_default_node_id(&owned, None)
        .and_then(|best_id| candidates.iter().copied().find(|n| n.id == best_id))
}


pub(in crate::commands) fn select_comparison_overseas_node(
    groups: &[MultiGroup],
    nodes: &[ProxyNode],
    route_mode: RouteTargetMode,
    active_single_node_id: Option<&str>,
    active_group_id: Option<&str>,
    requested_node_id: Option<&str>,
    relay_supports_ipv6: bool,
) -> Result<(ProxyNode, Option<String>), String> {
    if let Some(nid) = requested_node_id.map(str::trim).filter(|s| !s.is_empty()) {
        let node = nodes
            .iter()
            .find(|n| n.id == nid)
            .cloned()
            .ok_or_else(|| "未找到指定的海外节点，请刷新节点列表后重试".to_string())?;
        if node.is_udp_only_transport() {
            return Err(
                "所选海外节点为纯 UDP 协议（Hysteria2/TUIC/WireGuard），暂不支持走国内 TCP 中转对比，请改选 VLESS/Trojan/SS/VMess 节点"
                    .to_string(),
            );
        }
        return Ok((node, None));
    }

    let is_ipv6_incompatible = |n: &ProxyNode| -> bool {
        !relay_supports_ipv6 && is_ipv6_only_node(n) && n.preaccel_override != Some(true)
    };

    let homepage_node = resolve_homepage_node(
        groups,
        nodes,
        route_mode,
        active_single_node_id,
        active_group_id,
    );

    if let Some(home) = homepage_node {
        if home.enabled
            && !home.is_udp_only_transport()
            && !is_info_placeholder_node(home)
            && !is_obscure_high_multiplier_node(home)
            && !is_ipv6_incompatible(home)
        {
            return Ok((home.clone(), None));
        }
    }

    let mut seen = std::collections::HashSet::new();
    let mut ordered: Vec<&ProxyNode> = Vec::with_capacity(nodes.len());

    let primary_group = active_group_id
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|gid| groups.iter().find(|g| g.id == gid))
        .or_else(|| groups.first());

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

    let preferred_non443: Vec<&ProxyNode> = tcp_enabled
        .iter()
        .copied()
        .filter(|n| {
            !n.is_443_native
                && !is_info_placeholder_node(n)
                && !is_obscure_high_multiplier_node(n)
        })
        .collect();
    let preferred_any_tcp: Vec<&ProxyNode> = tcp_enabled
        .iter()
        .copied()
        .filter(|n| !is_info_placeholder_node(n) && !is_obscure_high_multiplier_node(n))
        .collect();

    let picked = pick_smart_from_refs(&preferred_non443)
        .or_else(|| pick_smart_from_refs(&preferred_any_tcp))
        .or_else(|| {
            tcp_enabled
                .iter()
                .copied()
                .find(|n| !n.is_443_native && !is_info_placeholder_node(n))
        })
        .or_else(|| tcp_enabled.iter().copied().find(|n| !n.is_443_native))
        .or_else(|| {
            tcp_enabled
                .iter()
                .copied()
                .find(|n| !is_info_placeholder_node(n))
        })
        .or_else(|| tcp_enabled.first().copied())
        .cloned()
        .ok_or_else(|| {
            if !relay_supports_ipv6
                && nodes
                    .iter()
                    .any(|n| n.enabled && !n.is_udp_only_transport() && is_ipv6_incompatible(n))
            {
                "暂无可用于对比测速的 IPv4/双栈海外节点（当前国内中转未启用 IPv6 出口，已跳过纯 IPv6 节点；请先导入 IPv4/双栈非纯 UDP 节点或开启中转 IPv6 开关）"
                    .to_string()
            } else {
                "暂无可用于对比测速的海外节点（请先导入至少 1 个已启用的非纯 UDP 海外节点）"
                    .to_string()
            }
        })?;

    let fallback_reason = match homepage_node {
        Some(home) if home.is_udp_only_transport() => Some(format!(
            "首页当前节点「{}」是纯 UDP 协议无法套 TCP 中转，已自动改测「{}」",
            home.name, picked.name
        )),
        Some(home) if is_ipv6_incompatible(home) && picked.id != home.id => Some(format!(
            "首页当前节点「{}」为纯 IPv6 节点，当前国内中转未启用 IPv6 出口，已自动改测「{}」",
            home.name, picked.name
        )),
        Some(home) if !home.enabled => Some(format!(
            "首页当前节点「{}」已禁用，已自动改测「{}」",
            home.name, picked.name
        )),
        Some(home) if is_info_placeholder_node(home) && picked.id != home.id => Some(format!(
            "首页当前节点「{}」为信息提示节点，已自动改测优选节点「{}」",
            home.name, picked.name
        )),
        Some(home) if is_obscure_high_multiplier_node(home) && picked.id != home.id => {
            Some(format!(
                "首页当前节点「{}」为冷门高倍率（{:.1}x），已自动改测常用低倍率节点「{}」",
                home.name, home.multiplier, picked.name
            ))
        }
        _ => None,
    };

    Ok((picked, fallback_reason))
}


fn calc_boost_ratio(accel: Option<f64>, direct: Option<f64>) -> Option<f64> {
    let a = accel?;
    let d = direct?;
    if !a.is_finite() || !d.is_finite() || a <= 0.0 || d <= 0.01 {
        return None;
    }
    Some(((a / d) * 100.0).round() / 100.0)
}


pub(in crate::commands) fn summarize_throughput_probe_error(direction: &str, detail: Option<&str>) -> String {
    let raw = detail.unwrap_or("").trim();
    if raw.is_empty() {
        return format!("{direction}未返回有效速率");
    }
    let lower = raw.to_ascii_lowercase();
    if lower.contains("timed out") || lower.contains("timeout") {
        format!("{direction}超时")
    } else if lower.contains("fast_fuse_triggered") {
        format!("{direction}速率过低触发保护熔断（<0.2 Mbps）")
    } else if lower.contains("unexpected upload http status")
        || lower.contains("unexpected download http status")
    {
        format!("{direction}测速节点返回异常状态码（{raw}）")
    } else if lower.contains("connection reset")
        || lower.contains("broken pipe")
        || lower.contains("unexpected eof")
        || lower.contains("closed")
    {
        format!("{direction}连接被远端中途断开")
    } else if lower.contains("error sending request") || lower.contains("connect") {
        format!("{direction}建连失败（线路握手超时或受阻）")
    } else {
        format!("{direction}失败（{raw}）")
    }
}


fn format_side_log_summary(side: &PreAccelSideSpeedDto) -> String {
    let lat = side
        .latency_ms
        .map(|v| format!("{v:.1}ms"))
        .unwrap_or_else(|| "--".to_string());
    let up = side
        .up_mbps
        .map(|v| format!("{v:.2}Mbps"))
        .unwrap_or_else(|| "--".to_string());
    let down = side
        .down_mbps
        .map(|v| format!("{v:.2}Mbps"))
        .unwrap_or_else(|| "--".to_string());
    match side.error.as_deref() {
        Some(err) if !err.trim().is_empty() => {
            format!("ok={} 延迟={} 上行={} 下行={} 备注={}", side.ok, lat, up, down, err)
        }
        _ => format!("ok={} 延迟={} 上行={} 下行={}", side.ok, lat, up, down),
    }
}


pub(in crate::commands) fn extract_verified_throughput_mbps(
    rec: &catcloud_core::models::ProbeResultRecord,
    is_upload: bool,
) -> Option<f64> {
    if !rec.ok {
        return None;
    }
    let val = if is_upload { rec.up_mbps } else { rec.down_mbps };
    val.filter(|&v| v.is_finite() && v > 0.0)
}


async fn run_preaccel_comparison_side(
    proxy_port: u16,
    node_id: &str,
    label: &str,
) -> PreAccelSideSpeedDto {
    let measured_latency: Arc<Mutex<Option<f64>>> = Arc::new(Mutex::new(None));
    let measured_up: Arc<Mutex<Option<f64>>> = Arc::new(Mutex::new(None));
    let measured_down: Arc<Mutex<Option<f64>>> = Arc::new(Mutex::new(None));
    let measured_latency_ref = Arc::clone(&measured_latency);
    let measured_up_ref = Arc::clone(&measured_up);
    let measured_down_ref = Arc::clone(&measured_down);

    let side_fut = async move {
        let client = match build_isolated_http_client(proxy_port, Duration::from_secs(12)) {
            Ok(c) => c,
            Err(e) => {
                return PreAccelSideSpeedDto {
                    ok: false,
                    latency_ms: None,
                    up_mbps: None,
                    down_mbps: None,
                    error: Some(format!("{label}初始化测速通道失败：{e}")),
                };
            }
        };

        let latency_def = ProbeDefinition {
            id: "preaccel_cmp_latency".to_string(),
            name: "Comparison Latency".to_string(),
            kind: catcloud_core::models::ProbeKind::Latency,
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
            run_latency_probe(&client, node_id, &latency_def, 2),
        )
        .await
        {
            Ok(rec) => rec,
            Err(_) => {
                return PreAccelSideSpeedDto {
                    ok: false,
                    latency_ms: None,
                    up_mbps: None,
                    down_mbps: None,
                    error: Some(format!("{label}延迟探测超时（6 秒）")),
                };
            }
        };
        if let Some(lat_ms) = lat_rec.latency_ms.filter(|v| v.is_finite() && *v > 0.0) {
            if let Ok(mut guard) = measured_latency_ref.lock() {
                *guard = Some(lat_ms);
            }
        }
        if !lat_rec.ok {
            let reason = lat_rec
                .detail
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|d| format!("{label}连通测试失败：{d}"))
                .unwrap_or_else(|| format!("{label}连通测试失败，请检查中转或海外节点是否可用"));
            return PreAccelSideSpeedDto {
                ok: false,
                latency_ms: lat_rec.latency_ms,
                up_mbps: None,
                down_mbps: None,
                error: Some(reason),
            };
        }

        // Lightweight Keep-Alive warmup against speed.cloudflare.com so dual-hop cold TLS
        // handshake does not burn upload/download timeout budget on fresh proxy start.
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
            id: "preaccel_cmp_upload".to_string(),
            name: "Comparison Upload".to_string(),
            kind: catcloud_core::models::ProbeKind::Upload,
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
            run_upload_probe_with_config(&client, node_id, &upload_def, &tp_cfg),
        )
        .await
        {
            Ok(rec) => {
                let speed = extract_verified_throughput_mbps(&rec, true);
                if speed.is_some() {
                    (speed, None)
                } else {
                    (
                        None,
                        Some(summarize_throughput_probe_error(
                            "上行测速",
                            rec.detail.as_deref(),
                        )),
                    )
                }
            }
            Err(_) => (None, Some("上行测速超时（20 秒）".to_string())),
        };
        if let Some(speed) = up_mbps {
            if let Ok(mut guard) = measured_up_ref.lock() {
                *guard = Some(speed);
            }
        }

        let download_def = ProbeDefinition {
            id: "preaccel_cmp_download".to_string(),
            name: "Comparison Download".to_string(),
            kind: catcloud_core::models::ProbeKind::Download,
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
            run_download_probe_with_config(&client, node_id, &download_def, &tp_cfg),
        )
        .await
        {
            Ok(rec) => {
                let speed = extract_verified_throughput_mbps(&rec, false);
                if speed.is_some() {
                    (speed, None)
                } else {
                    (
                        None,
                        Some(summarize_throughput_probe_error(
                            "下行测速",
                            rec.detail.as_deref(),
                        )),
                    )
                }
            }
            Err(_) => (None, Some("下行测速超时（18 秒）".to_string())),
        };
        if let Some(speed) = down_mbps {
            if let Ok(mut guard) = measured_down_ref.lock() {
                *guard = Some(speed);
            }
        }

        let ok = up_mbps.is_some() || down_mbps.is_some();
        let error = match (up_mbps.is_some(), down_mbps.is_some()) {
            (true, true) => None,
            (true, false) => Some(format!(
                "{}（上行正常）",
                down_err.unwrap_or_else(|| "下行测速超时".to_string())
            )),
            (false, true) => Some(format!(
                "{}（下行正常）",
                up_err.unwrap_or_else(|| "上行测速超时".to_string())
            )),
            (false, false) => Some(format!(
                "{label}上下行测速均未通过（{}；{}）",
                up_err.unwrap_or_else(|| "上行超时".to_string()),
                down_err.unwrap_or_else(|| "下行超时".to_string())
            )),
        };

        PreAccelSideSpeedDto {
            ok,
            latency_ms: lat_rec.latency_ms,
            up_mbps,
            down_mbps,
            error,
        }
    };

    match tokio::time::timeout(Duration::from_secs(44), side_fut).await {
        Ok(res) => res,
        Err(_) => {
            let preserved_latency = measured_latency.lock().ok().and_then(|g| *g);
            let preserved_up = measured_up.lock().ok().and_then(|g| *g);
            let preserved_down = measured_down.lock().ok().and_then(|g| *g);
            let ok = preserved_up.is_some() || preserved_down.is_some();
            PreAccelSideSpeedDto {
                ok,
                latency_ms: preserved_latency,
                up_mbps: preserved_up,
                down_mbps: preserved_down,
                error: Some(format!("{label}测速超过 44 秒已自动中止")),
            }
        }
    }
}


#[tauri::command]
pub async fn benchmark_preaccel_comparison(
    app: AppHandle,
    state: State<'_, AppState>,
    relay_id: Option<String>,
    node_id: Option<String>,
) -> Result<serde_json::Value, String> {
    if state
        .probe_running
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("当前已有测速任务正在进行，请等待完成或先暂停后再开始对比测速".to_string());
    }
    let _running_guard = ProbeRunningGuard::enter(&app, &state);

    let cfg = state.snapshot_config();
    let extra_candidates = state.extra_binary_candidates();
    let resolution = resolve_mihomo_binary(&cfg, &state.paths, &extra_candidates, false)
        .map_err(|e| format!("查找代理核心失败：{e}"))?;
    let Some(mihomo_bin) = resolution.path else {
        return Err("未找到 Mihomo 核心文件，无法执行国内提速对比测速".to_string());
    };

    let (relay, target_node, fallback_reason) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let relay = if let Some(rid) = relay_id.as_deref().map(str::trim).filter(|s| !s.is_empty())
        {
            db.get_preaccel_relay(rid)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "未找到指定的国内中转节点，请刷新页面后重试".to_string())?
        } else {
            let enabled_relays = db.list_preaccel_relays(true).map_err(|e| e.to_string())?;
            if enabled_relays.is_empty() {
                return Err(
                    "暂无已启用的国内中转节点，请先添加并启用至少 1 个国内中转".to_string(),
                );
            }
            cfg.preaccel
                .active_relay_id
                .as_deref()
                .and_then(|aid| enabled_relays.iter().find(|r| r.id == aid).cloned())
                .unwrap_or_else(|| enabled_relays[0].clone())
        };

        if relay.server.trim().is_empty() || relay.port == 0 {
            return Err("所选国内中转缺少有效的服务器地址或端口".to_string());
        }

        let groups = db.list_multi_groups().map_err(|e| e.to_string())?;
        let nodes = db.list_nodes().map_err(|e| e.to_string())?;
        let (target_node, fallback_reason) = select_comparison_overseas_node(
            &groups,
            &nodes,
            cfg.route_mode,
            cfg.active_single_node_id.as_deref(),
            cfg.active_group_id.as_deref(),
            node_id.as_deref(),
            relay.supports_ipv6,
        )?;
        (relay, target_node, fallback_reason)
    };

    state.log_app_event(
        "info",
        "对比测速",
        &format!(
            "开始国内提速对比测速：中转「{}」+ 海外节点「{}」",
            relay.name, target_node.name
        ),
    );

    // Measure true end-to-end RTT to the domestic relay (immune to Wintun synthetic 0~1ms TCP ACK).
    let relay_real_rtt_ms = measure_relay_real_rtt_ms(&relay)
        .await
        .ok()
        .filter(|&v| v.is_finite() && v > 0.0);

    let temp_root = state.paths.runtime_dir.join("probe_sandbox");
    std::fs::create_dir_all(&temp_root).map_err(|e| format!("创建后台测速目录失败：{e}"))?;

    let (probe_core, accel_port, direct_port) = IsolatedProbeCore::spawn_for_preaccel_comparison(
        &mihomo_bin,
        &temp_root,
        &state.job_guard,
        &relay,
        &target_node,
        &[],
        DEFAULT_READY_TIMEOUT,
    )
    .await
    .map_err(|e| {
        let msg = format_mihomo_error_for_user(&format!("启动对比测速核心失败：{e}"));
        state.log_app_event("error", "对比测速", &msg);
        msg
    })?;

    // Run sequentially so accelerated and direct sides do not compete for local uplink bandwidth.
    let accelerated =
        run_preaccel_comparison_side(accel_port, &target_node.id, "国内提速通道").await;
    let direct = run_preaccel_comparison_side(direct_port, &target_node.id, "普通直连通道").await;

    let _ = probe_core.shutdown().await;

    // Never pollute domestic relay `last_probe_ms` with two-hop overseas latency; only update
    // from direct `measure_relay_real_rtt_ms` (SQLite COALESCE retains existing valid direct RTT).
    let recorded_relay_ms = relay_real_rtt_ms
        .filter(|&v| v.is_finite() && v > 0.0)
        .map(|ms| ((ms * 10.0).round() / 10.0).max(0.1));
    let recorded_up_mbps = accelerated
        .up_mbps
        .filter(|&v| v.is_finite() && v > 0.0)
        .or(relay.last_up_mbps)
        .or(relay.last_mbps);
    let recorded_down_mbps = accelerated
        .down_mbps
        .filter(|&v| v.is_finite() && v > 0.0)
        .or(relay.last_down_mbps);
    if recorded_relay_ms.is_some() || recorded_up_mbps.is_some() || recorded_down_mbps.is_some() {
        if let Ok(db) = state.storage.lock() {
            let _ = db.update_preaccel_speed_metrics(
                &relay.id,
                recorded_relay_ms,
                recorded_up_mbps,
                recorded_down_mbps,
            );
        }
        emit_relays_updated(&app);
    }

    let up_boost_ratio = calc_boost_ratio(accelerated.up_mbps, direct.up_mbps);
    let down_boost_ratio = calc_boost_ratio(accelerated.down_mbps, direct.down_mbps);

    let overall_ok = accelerated.ok || direct.ok;
    let log_level = if accelerated.ok { "info" } else { "warning" };
    let direct_note = if accelerated.ok && !direct.ok {
        let reason = direct
            .error
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("直连对照通道超时或不可达");
        format!(" | 说明：提速边实测畅通，普通直连对照组未完成（{reason}，常见于运营商对海外非 443 端口限速或丢包）")
    } else if accelerated.ok && direct.error.is_some() {
        let reason = direct
            .error
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("部分阶段超时");
        format!(" | 说明：提速边实测畅通，直连对照组存在部分超时（{reason}）")
    } else {
        String::new()
    };
    let relay_rtt_text = relay_real_rtt_ms
        .map(|v| format!("{v:.1}ms"))
        .unwrap_or_else(|| "--".to_string());
    state.log_app_event(
        log_level,
        "对比测速",
        &format!(
            "对比测速完成：中转「{}」(真实RTT={relay_rtt_text}) / 节点「{}」| 提速边[{}] | 直连边[{}] | 上行倍率={:?} 下行倍率={:?}{direct_note}",
            relay.name,
            target_node.name,
            format_side_log_summary(&accelerated),
            format_side_log_summary(&direct),
            up_boost_ratio,
            down_boost_ratio
        ),
    );

    Ok(serde_json::json!({
        "ok": overall_ok,
        "relay_id": relay.id,
        "relay_name": relay.name,
        "node_id": target_node.id,
        "node_name": target_node.name,
        "fallback_reason": fallback_reason,
        "accelerated": accelerated,
        "direct": direct,
        "up_boost_ratio": up_boost_ratio,
        "down_boost_ratio": down_boost_ratio,
        "tested_at": Utc::now().to_rfc3339()
    }))
}


pub(in crate::commands) fn select_target_relays_ordered(
    all_relays: Vec<PreAccelRelay>,
    relay_ids: Option<Vec<String>>,
) -> Vec<PreAccelRelay> {
    let Some(ids) = relay_ids else {
        return all_relays;
    };
    let by_id: HashMap<&str, &PreAccelRelay> =
        all_relays.iter().map(|r| (r.id.as_str(), r)).collect();
    let mut seen: HashSet<String> = HashSet::new();
    ids.into_iter()
        .filter_map(|raw_id| {
            let trimmed = raw_id.trim();
            if trimmed.is_empty() || !seen.insert(trimmed.to_string()) {
                return None;
            }
            by_id.get(trimmed).map(|r| (*r).clone())
        })
        .collect()
}


/// Strongly-typed per-relay speed benchmark result keeping direct domestic relay RTT
/// strictly separated from two-hop overseas chain latency (`chain_latency_ms`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreAccelRelaySpeedResultDto {
    pub relay_id: String,
    pub relay_name: String,
    pub ok: bool,
    pub latency_ms: Option<f64>,
    #[serde(default)]
    pub chain_latency_ms: Option<u64>,
    pub up_mbps: Option<f64>,
    pub down_mbps: Option<f64>,
    pub mode: String,
    pub reference_node_name: Option<String>,
    pub error: Option<String>,
}


/// Separate direct domestic relay RTT from two-hop overseas chain latency:
/// returns `(db_direct_update_ms, dto_direct_latency_ms, chain_latency_ms)`.
/// Never falls back `last_probe_ms` to overseas `side_latency_ms`.
pub(in crate::commands) fn split_relay_direct_and_chain_latency(
    relay_real_rtt_ms: Option<f64>,
    existing_last_probe_ms: Option<f64>,
    side_latency_ms: Option<f64>,
) -> (Option<f64>, Option<f64>, Option<u64>) {
    let direct_new = relay_real_rtt_ms
        .filter(|v| v.is_finite() && *v > 0.0)
        .map(|ms| ((ms * 10.0).round() / 10.0).max(0.1));
    let existing_valid = existing_last_probe_ms.filter(|v| v.is_finite() && *v > 0.0);
    let dto_direct_ms = direct_new.or(existing_valid);
    let chain_ms = side_latency_ms
        .filter(|v| v.is_finite() && *v > 0.0)
        .map(|ms| ms.round().max(1.0) as u64);
    (direct_new, dto_direct_ms, chain_ms)
}


#[tauri::command]
pub async fn test_preaccel_relay_speeds(
    app: AppHandle,
    state: State<'_, AppState>,
    relay_ids: Option<Vec<String>>,
    node_id: Option<String>,
) -> Result<serde_json::Value, String> {
    if state
        .probe_running
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("当前已有测速任务正在进行，请等待完成后再测中转上下行".to_string());
    }
    let _running_guard = ProbeRunningGuard::enter(&app, &state);

    let cfg = state.snapshot_config();
    let extra_candidates = state.extra_binary_candidates();
    let resolution = resolve_mihomo_binary(&cfg, &state.paths, &extra_candidates, false)
        .map_err(|e| format!("查找代理核心失败：{e}"))?;
    let Some(mihomo_bin) = resolution.path else {
        return Err("未找到 Mihomo 核心文件，无法执行国内中转上下行测速".to_string());
    };

    let (target_relays, reference_node) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let all_relays = db.list_preaccel_relays(false).map_err(|e| e.to_string())?;
        let target_relays = select_target_relays_ordered(all_relays, relay_ids);
        if target_relays.is_empty() {
            return Ok(serde_json::Value::Array(Vec::new()));
        }

        let groups = db.list_multi_groups().map_err(|e| e.to_string())?;
        let nodes = db.list_nodes().map_err(|e| e.to_string())?;
        let valid_relays_for_v6: Vec<&PreAccelRelay> = target_relays
            .iter()
            .filter(|r| !r.server.trim().is_empty() && r.port > 0)
            .collect();
        let relays_support_ipv6 = !valid_relays_for_v6.is_empty()
            && valid_relays_for_v6.iter().all(|r| r.supports_ipv6);
        let reference_node = select_comparison_overseas_node(
            &groups,
            &nodes,
            cfg.route_mode,
            cfg.active_single_node_id.as_deref(),
            cfg.active_group_id.as_deref(),
            node_id.as_deref(),
            relays_support_ipv6,
        )
        .ok()
        .or_else(|| {
            if node_id
                .as_deref()
                .map(str::trim)
                .is_some_and(|s| !s.is_empty())
            {
                select_comparison_overseas_node(
                    &groups,
                    &nodes,
                    cfg.route_mode,
                    cfg.active_single_node_id.as_deref(),
                    cfg.active_group_id.as_deref(),
                    None,
                    relays_support_ipv6,
                )
                .ok()
            } else {
                None
            }
        })
        .map(|(node, _)| node);

        (target_relays, reference_node)
    };

    let mode_str = if reference_node.is_some() {
        "via_node"
    } else {
        "relay_direct"
    };
    let reference_node_name = reference_node.as_ref().map(|n| n.name.clone());

    let valid_relays: Vec<PreAccelRelay> = target_relays
        .iter()
        .filter(|r| !r.server.trim().is_empty() && r.port > 0)
        .cloned()
        .collect();

    if valid_relays.is_empty() {
        let results: Vec<PreAccelRelaySpeedResultDto> = target_relays
            .iter()
            .map(|relay| PreAccelRelaySpeedResultDto {
                relay_id: relay.id.clone(),
                relay_name: relay.name.clone(),
                ok: false,
                latency_ms: relay.last_probe_ms.filter(|v| v.is_finite() && *v > 0.0),
                chain_latency_ms: None,
                up_mbps: None,
                down_mbps: None,
                mode: mode_str.to_string(),
                reference_node_name: reference_node_name.clone(),
                error: Some("中转缺少有效的服务器地址或端口".to_string()),
            })
            .collect();
        state.log_app_event(
            "warning",
            "国内提速",
            &format!(
                "国内中转真实上下行测速已跳过：{} 条中转均缺少有效的服务器地址或端口",
                target_relays.len()
            ),
        );
        return serde_json::to_value(results).map_err(|e| e.to_string());
    }

    let mode_desc = match reference_node_name.as_deref() {
        Some(name) => format!("经海外对照节点「{name}」"),
        None => "单跳直测中转本身".to_string(),
    };
    state.log_app_event(
        "info",
        "国内提速",
        &format!(
            "开始国内中转真实上下行测速：共 {} 条（有效 {} 条，模式：{mode_desc}）",
            target_relays.len(),
            valid_relays.len()
        ),
    );

    let temp_root = state.paths.runtime_dir.join("probe_sandbox");
    std::fs::create_dir_all(&temp_root).map_err(|e| format!("创建后台测速目录失败：{e}"))?;

    let (probe_core, relay_ports) = IsolatedProbeCore::spawn_for_preaccel_relay_speeds(
        &mihomo_bin,
        &temp_root,
        &state.job_guard,
        &valid_relays,
        reference_node.as_ref(),
        &[],
        DEFAULT_READY_TIMEOUT,
    )
    .await
    .map_err(|e| {
        let msg = format_mihomo_error_for_user(&format!("启动中转上下行测速核心失败：{e}"));
        state.log_app_event("error", "国内提速", &msg);
        msg
    })?;
    let port_map: HashMap<String, u16> = relay_ports.into_iter().collect();

    let total_count = target_relays.len();
    let mut ok_count = 0usize;
    let mut any_metrics_updated = false;
    let mut results: Vec<PreAccelRelaySpeedResultDto> = Vec::with_capacity(total_count);

    // Run strictly sequentially per relay to prevent local uplink bandwidth contention.
    for relay in &target_relays {
        if relay.server.trim().is_empty() || relay.port == 0 {
            results.push(PreAccelRelaySpeedResultDto {
                relay_id: relay.id.clone(),
                relay_name: relay.name.clone(),
                ok: false,
                latency_ms: relay.last_probe_ms.filter(|v| v.is_finite() && *v > 0.0),
                chain_latency_ms: None,
                up_mbps: None,
                down_mbps: None,
                mode: mode_str.to_string(),
                reference_node_name: reference_node_name.clone(),
                error: Some("中转缺少有效的服务器地址或端口".to_string()),
            });
            continue;
        }
        let Some(&port) = port_map.get(&relay.id) else {
            results.push(PreAccelRelaySpeedResultDto {
                relay_id: relay.id.clone(),
                relay_name: relay.name.clone(),
                ok: false,
                latency_ms: relay.last_probe_ms.filter(|v| v.is_finite() && *v > 0.0),
                chain_latency_ms: None,
                up_mbps: None,
                down_mbps: None,
                mode: mode_str.to_string(),
                reference_node_name: reference_node_name.clone(),
                error: Some("未能为该中转分配测速通道，请检查协议与参数配置".to_string()),
            });
            continue;
        };

        let relay_real_rtt_ms = measure_relay_real_rtt_ms(relay).await.ok();

        let side = run_preaccel_comparison_side(
            port,
            &relay.id,
            &format!("中转「{}」", relay.name),
        )
        .await;

        let (recorded_direct_ms, display_direct_ms, chain_latency_ms) =
            split_relay_direct_and_chain_latency(
                relay_real_rtt_ms,
                relay.last_probe_ms,
                side.latency_ms,
            );
        let recorded_up = side.up_mbps.filter(|v| v.is_finite() && *v > 0.0);
        let recorded_down = side.down_mbps.filter(|v| v.is_finite() && *v > 0.0);
        let ok = side.ok;
        if ok {
            ok_count += 1;
        }

        if recorded_direct_ms.is_some() || recorded_up.is_some() || recorded_down.is_some() {
            if let Ok(db) = state.storage.lock() {
                let _ = db.update_preaccel_speed_metrics(
                    &relay.id,
                    recorded_direct_ms,
                    recorded_up,
                    recorded_down,
                );
                any_metrics_updated = true;
            }
        }

        results.push(PreAccelRelaySpeedResultDto {
            relay_id: relay.id.clone(),
            relay_name: relay.name.clone(),
            ok,
            latency_ms: display_direct_ms,
            chain_latency_ms,
            up_mbps: recorded_up,
            down_mbps: recorded_down,
            mode: mode_str.to_string(),
            reference_node_name: reference_node_name.clone(),
            error: side.error,
        });
    }

    let _ = probe_core.shutdown().await;
    if any_metrics_updated {
        emit_relays_updated(&app);
    }

    state.log_app_event(
        if ok_count == total_count {
            "info"
        } else {
            "warning"
        },
        "国内提速",
        &format!(
            "国内中转真实上下行测速完成：可用 {ok_count}/{total_count}（模式：{mode_desc}）"
        ),
    );

    serde_json::to_value(results).map_err(|e| e.to_string())
}


#[tauri::command]
pub async fn check_campus_portal(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let cfg = state.snapshot_config();
    let observed = probe_campus_portal_with_fallback(
        &cfg.preaccel.probe_url,
        Some(cfg.preaccel.fallback_probe_url.as_str()),
        Duration::from_secs(5),
    )
    .await;

    let transition = {
        let mut tracker = state.campus_tracker.lock().map_err(|e| e.to_string())?;
        tracker.apply_state(observed.clone())
    };
    if transition.rules_changed {
        let _ = trigger_reload_if_running(&app, &state, true).await;
    }
    sync_tray_and_window_side_effects(&app, &state, &cfg);

    let (required, status_code, redirect_location) = match &observed {
        CampusPortalState::Connected => (false, Some(204u16), None),
        CampusPortalState::CaptivePortalRequired {
            portal_url,
            status_code,
            ..
        } => (true, Some(*status_code), Some(portal_url.clone())),
        CampusPortalState::Offline { .. } => (false, None, None),
    };

    Ok(serde_json::json!({
        "captive_portal_required": required,
        "state": observed,
        "status_code": status_code,
        "redirect_location": redirect_location,
        "bypass_hosts": transition.active_fake_ip_filter,
        "direct_rules": transition.active_direct_rules,
        "checked_at": Utc::now().to_rfc3339()
    }))
}

