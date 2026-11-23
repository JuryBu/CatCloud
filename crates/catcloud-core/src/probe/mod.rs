pub mod builtins;
pub mod external;
pub mod isolated_runner;
pub mod registry;

pub use builtins::{
    DEFAULT_AI_STUDIO_URL, DEFAULT_CF_TRACE_URL, DEFAULT_GOOGLE_204_URL,
    DEFAULT_KEEPALIVE_INTERVALS_MS, DEFAULT_LATENCY_SAMPLES, DEFAULT_YOUTUBE_REGION_URL,
    FAST_FUSE_MIN_MBPS, FAST_FUSE_PROBE_BYTES, GoogleCleanAssessment, GoogleCleanSignals,
    GoogleCnEndpoints, LatencyStats, MAX_INSPECT_BODY_BYTES, MAX_THROUGHPUT_PAYLOAD_BYTES,
    ThroughputProbeConfig, build_download_stage_url, compute_latency_stats, compute_mbps,
    default_keepalive_intervals, evaluate_google_cleanliness, infer_unlock_site_key,
    is_google_cn_location, parse_cloudflare_trace_loc, parse_youtube_gl, run_download_probe,
    run_download_probe_with_config, run_google_cn_probe, run_keepalive_probe, run_latency_probe,
    run_unlock_regex_probe, run_upload_probe, run_upload_probe_with_config,
};
pub use external::{
    ExternalProbeInput, ExternalProbeOutput, MAX_EXTERNAL_STDERR_BYTES, MAX_EXTERNAL_STDOUT_BYTES,
    parse_command_tokens, parse_external_probe_output, run_external_probe,
};
pub use isolated_runner::{
    CMP_ACCEL_PROXY_NAME, CMP_DIRECT_PROXY_NAME, CMP_RELAY_PROXY_NAME, DEFAULT_PROBE_NAMESERVERS,
    DEFAULT_READY_TIMEOUT, ISOLATED_BIND_HOST, ISOLATED_CORE_GOGC, ISOLATED_CORE_GOMEMLIMIT,
    IsolatedProbeCore, IsolatedProxyScheme, NodeProbeBinding, allocate_ephemeral_ports,
    build_direct_no_proxy_client, build_isolated_http_client,
    build_isolated_http_client_with_options, build_isolated_probe_yaml,
    generate_controller_secret, generate_preaccel_comparison_yaml, isolated_proxy_url,
    resolve_unique_proxy_names,
};
pub use registry::{
    DEFAULT_DOWNLOAD_PAYLOAD_BYTES, DEFAULT_UPLOAD_PAYLOAD_BYTES, FunnelTier, MAX_PAYLOAD_BYTES,
    MAX_PROBE_ID_LEN, MAX_REGEX_LEN, MAX_TIMEOUT_MS, MIN_PAYLOAD_BYTES, MIN_TIMEOUT_MS,
    ProbeRegistry, tier_for_kind, validate_definition,
};

use crate::error::{CatError, CatResult};
use crate::models::{ProbeDefinition, ProbeKind, ProbeResultRecord, ProbeSnapshot};
use crate::process_guard::JobGuard;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use url::Url;

/// Execution options for the three-tier traffic-saving probe funnel.
#[derive(Debug, Clone)]
pub struct FunnelOptions {
    /// Highest tier to execute (`L0Connectivity`, `L1CleanAndUnlock`, or `L2ThroughputAndKeepalive`).
    pub max_tier: FunnelTier,
    /// Number of HTTP samples for L0 latency/jitter/loss calculation (default: 3).
    pub latency_samples: usize,
    /// Optional injectable endpoints for L1 Google cleanliness probes.
    pub google_endpoints: Option<GoogleCnEndpoints>,
    /// Stage-1 fast-fuse and Stage-2 scale-up limits for L2 throughput probes.
    pub throughput: ThroughputProbeConfig,
    /// Silent intervals for L2 Keep-Alive blackhole checks (default: `[20s, 40s, 60s]`).
    pub keepalive_intervals: Vec<Duration>,
    /// Local proxy transport scheme (`Socks5h` default or `HttpConnect`; never `socks5://`).
    pub proxy_scheme: IsolatedProxyScheme,
    /// Stop immediately after L0 when all L0 connectivity checks fail (default: `true`).
    pub short_circuit_on_l0_failure: bool,
    /// Optionally stop before L2 if L1 Google cleanliness check fails (default: `false`).
    pub short_circuit_on_google_dirty: bool,
    /// Test-only switch allowing direct `.no_proxy()` requests strictly to loopback (`127.0.0.1`).
    /// Rejected with `CatError::Security` if any target URL is non-loopback.
    pub bypass_proxy_for_loopback_test: bool,
}

impl Default for FunnelOptions {
    fn default() -> Self {
        Self {
            max_tier: FunnelTier::L2ThroughputAndKeepalive,
            latency_samples: DEFAULT_LATENCY_SAMPLES,
            google_endpoints: None,
            throughput: ThroughputProbeConfig::default(),
            keepalive_intervals: default_keepalive_intervals(),
            proxy_scheme: IsolatedProxyScheme::Socks5h,
            short_circuit_on_l0_failure: true,
            short_circuit_on_google_dirty: false,
            bypass_proxy_for_loopback_test: false,
        }
    }
}

/// Complete outcome of running the three-tier probe funnel against a single node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunnelRunReport {
    pub node_id: String,
    pub reached_tier: FunnelTier,
    pub short_circuited: bool,
    pub short_circuit_reason: Option<String>,
    pub records: Vec<ProbeResultRecord>,
    pub snapshot: ProbeSnapshot,
}

/// Execute a single registered probe definition against one node bound on `127.0.0.1:<proxy_port>`.
pub async fn run_single_probe(
    def: &ProbeDefinition,
    node_id: &str,
    proxy_port: u16,
    options: &FunnelOptions,
    job_guard: Option<&JobGuard>,
) -> CatResult<ProbeResultRecord> {
    validate_definition(def)?;

    if def.kind == ProbeKind::ExternalCmd {
        return run_external_probe(def, node_id, proxy_port, job_guard).await;
    }

    if options.bypass_proxy_for_loopback_test {
        ensure_loopback_target(&def.target_url)?;
        if def.kind == ProbeKind::GoogleCn {
            if let Some(ref ep) = options.google_endpoints {
                ensure_loopback_target(&ep.google_url)?;
                if let Some(ref u) = ep.youtube_url {
                    ensure_loopback_target(u)?;
                }
                if let Some(ref u) = ep.ai_studio_url {
                    ensure_loopback_target(u)?;
                }
                if let Some(ref u) = ep.cf_trace_url {
                    ensure_loopback_target(u)?;
                }
            }
        }
    }

    let timeout = Duration::from_millis(def.timeout_ms.max(MIN_TIMEOUT_MS));

    match def.kind {
        ProbeKind::Latency => {
            let client = build_client_for_mode(proxy_port, timeout, options, true, None)?;
            Ok(run_latency_probe(&client, node_id, def, options.latency_samples).await)
        }
        ProbeKind::GoogleCn => {
            // Disable redirects so 302 to google.cn is captured directly.
            let client = build_client_for_mode(proxy_port, timeout, options, false, None)?;
            Ok(run_google_cn_probe(&client, node_id, def, options.google_endpoints.as_ref()).await)
        }
        ProbeKind::UnlockRegex => {
            let client = build_client_for_mode(proxy_port, timeout, options, true, None)?;
            Ok(run_unlock_regex_probe(&client, node_id, def).await)
        }
        ProbeKind::Upload => {
            let client = build_client_for_mode(proxy_port, timeout, options, true, None)?;
            Ok(run_upload_probe_with_config(&client, node_id, def, &options.throughput).await)
        }
        ProbeKind::Download => {
            let client = build_client_for_mode(proxy_port, timeout, options, true, None)?;
            Ok(run_download_probe_with_config(&client, node_id, def, &options.throughput).await)
        }
        ProbeKind::Keepalive => {
            let max_interval = options
                .keepalive_intervals
                .iter()
                .copied()
                .max()
                .unwrap_or(Duration::from_secs(60));
            let idle_timeout = max_interval.saturating_add(Duration::from_secs(15));
            let client =
                build_client_for_mode(proxy_port, timeout, options, true, Some(idle_timeout))?;
            Ok(run_keepalive_probe(&client, node_id, def, &options.keepalive_intervals).await)
        }
        ProbeKind::ExternalCmd => unreachable!("handled above"),
    }
}

/// Orchestrate the three-tier traffic-saving probe funnel (`L0 -> L1 -> L2`) for a single node
/// bound on an isolated `127.0.0.1:<proxy_port>` listener and produce an aggregated `ProbeSnapshot`.
pub async fn run_funnel_for_node(
    registry: &ProbeRegistry,
    node_id: &str,
    proxy_port: u16,
    options: &FunnelOptions,
    job_guard: Option<&JobGuard>,
    primary_probe_id: Option<&str>,
) -> CatResult<FunnelRunReport> {
    if node_id.trim().is_empty() {
        return Err(CatError::Validation("node_id cannot be empty".into()));
    }
    if !options.bypass_proxy_for_loopback_test && proxy_port == 0 {
        return Err(CatError::Validation(
            "proxy_port must be non-zero when running isolated funnel probes".into(),
        ));
    }

    let mut records: Vec<ProbeResultRecord> = Vec::new();
    let mut reached_tier = FunnelTier::L0Connectivity;

    // -------------------------------------------------------------------------
    // Tier L0: Connectivity, latency, jitter, packet loss
    // -------------------------------------------------------------------------
    let l0_defs = registry.select_funnel_tier(FunnelTier::L0Connectivity);
    let mut l0_any_ok = false;
    for def in &l0_defs {
        let rec = execute_or_capture_error(def, node_id, proxy_port, options, job_guard).await?;
        if rec.ok {
            l0_any_ok = true;
        }
        records.push(rec);
    }

    if !l0_defs.is_empty() && !l0_any_ok && options.short_circuit_on_l0_failure {
        let snapshot = ProbeSnapshot::from_results(node_id, &records, primary_probe_id);
        return Ok(FunnelRunReport {
            node_id: node_id.to_string(),
            reached_tier,
            short_circuited: true,
            short_circuit_reason: Some("l0_connectivity_failed".to_string()),
            records,
            snapshot,
        });
    }

    if options.max_tier == FunnelTier::L0Connectivity {
        let snapshot = ProbeSnapshot::from_results(node_id, &records, primary_probe_id);
        return Ok(FunnelRunReport {
            node_id: node_id.to_string(),
            reached_tier,
            short_circuited: false,
            short_circuit_reason: None,
            records,
            snapshot,
        });
    }

    // -------------------------------------------------------------------------
    // Tier L1: Google cleanliness ground-truth & arbitrary site regex unlock
    // -------------------------------------------------------------------------
    reached_tier = FunnelTier::L1CleanAndUnlock;
    let l1_defs = registry.select_funnel_tier(FunnelTier::L1CleanAndUnlock);
    let mut google_dirty = false;
    for def in &l1_defs {
        let rec = execute_or_capture_error(def, node_id, proxy_port, options, job_guard).await?;
        if rec.google_clean == Some(false) {
            google_dirty = true;
        }
        records.push(rec);
    }

    if google_dirty && options.short_circuit_on_google_dirty {
        let snapshot = ProbeSnapshot::from_results(node_id, &records, primary_probe_id);
        return Ok(FunnelRunReport {
            node_id: node_id.to_string(),
            reached_tier,
            short_circuited: true,
            short_circuit_reason: Some("l1_google_clean_failed".to_string()),
            records,
            snapshot,
        });
    }

    if options.max_tier == FunnelTier::L1CleanAndUnlock {
        let snapshot = ProbeSnapshot::from_results(node_id, &records, primary_probe_id);
        return Ok(FunnelRunReport {
            node_id: node_id.to_string(),
            reached_tier,
            short_circuited: false,
            short_circuit_reason: None,
            records,
            snapshot,
        });
    }

    // -------------------------------------------------------------------------
    // Tier L2: Upload/Download throughput (512 KiB fast fuse), Keep-Alive, ExternalCmd
    // -------------------------------------------------------------------------
    reached_tier = FunnelTier::L2ThroughputAndKeepalive;
    let l2_defs = registry.select_funnel_tier(FunnelTier::L2ThroughputAndKeepalive);
    for def in &l2_defs {
        let rec = execute_or_capture_error(def, node_id, proxy_port, options, job_guard).await?;
        records.push(rec);
    }

    let snapshot = ProbeSnapshot::from_results(node_id, &records, primary_probe_id);
    Ok(FunnelRunReport {
        node_id: node_id.to_string(),
        reached_tier,
        short_circuited: false,
        short_circuit_reason: None,
        records,
        snapshot,
    })
}

async fn execute_or_capture_error(
    def: &ProbeDefinition,
    node_id: &str,
    proxy_port: u16,
    options: &FunnelOptions,
    job_guard: Option<&JobGuard>,
) -> CatResult<ProbeResultRecord> {
    match run_single_probe(def, node_id, proxy_port, options, job_guard).await {
        Ok(rec) => Ok(rec),
        Err(CatError::Security(msg)) => Err(CatError::Security(msg)),
        Err(err) => Ok(ProbeResultRecord {
            node_id: node_id.to_string(),
            probe_id: def.id.clone(),
            tested_at: Utc::now().to_rfc3339(),
            ok: false,
            detail: Some(err.to_string()),
            ..Default::default()
        }),
    }
}

fn build_client_for_mode(
    proxy_port: u16,
    timeout: Duration,
    options: &FunnelOptions,
    follow_redirects: bool,
    keepalive_idle: Option<Duration>,
) -> CatResult<reqwest::Client> {
    if options.bypass_proxy_for_loopback_test {
        build_direct_no_proxy_client(timeout, follow_redirects, keepalive_idle)
    } else {
        build_isolated_http_client_with_options(
            proxy_port,
            timeout,
            options.proxy_scheme,
            follow_redirects,
            keepalive_idle,
        )
    }
}

fn ensure_loopback_target(raw_url: &str) -> CatResult<()> {
    let parsed = Url::parse(raw_url.trim())
        .map_err(|e| CatError::Validation(format!("invalid probe URL `{raw_url}`: {e}")))?;
    let host = parsed.host_str().unwrap_or("");
    let is_loopback = matches!(host, "127.0.0.1" | "localhost" | "[::1]" | "::1");
    if !is_loopback {
        return Err(CatError::Security(format!(
            "bypass_proxy_for_loopback_test refused non-loopback target `{raw_url}`"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ProxyNode;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::sleep;

    #[derive(Debug)]
    struct ParsedHttpRequest {
        method: String,
        target: String,
        body_len: usize,
    }

    async fn read_http_request(stream: &mut TcpStream) -> Option<ParsedHttpRequest> {
        let mut buf = Vec::with_capacity(4096);
        let mut tmp = [0u8; 2048];
        let header_end = loop {
            if let Some(pos) = find_header_end(&buf) {
                break pos;
            }
            let n = stream.read(&mut tmp).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() > 64 * 1024 {
                return None;
            }
        };

        let header_str = String::from_utf8_lossy(&buf[..header_end]);
        let mut lines = header_str.lines();
        let request_line = lines.next()?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next()?.to_string();
        let target = parts.next()?.to_string();

        let mut content_length: usize = 0;
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                if k.trim().eq_ignore_ascii_case("content-length") {
                    content_length = v.trim().parse::<usize>().unwrap_or(0);
                }
            }
        }

        let body_start = header_end + 4;
        let mut body_received = buf.len().saturating_sub(body_start);
        while body_received < content_length {
            let remaining = content_length - body_received;
            let to_read = remaining.min(tmp.len());
            let n = stream.read(&mut tmp[..to_read]).await.ok()?;
            if n == 0 {
                break;
            }
            body_received += n;
        }

        Some(ParsedHttpRequest {
            method,
            target,
            body_len: body_received,
        })
    }

    fn find_header_end(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|w| w == b"\r\n\r\n")
    }

    fn extract_bytes_query(target: &str, default_bytes: usize) -> usize {
        let Some((_, query)) = target.split_once('?') else {
            return default_bytes;
        };
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k.eq_ignore_ascii_case("bytes") {
                    if let Ok(n) = v.parse::<usize>() {
                        return n;
                    }
                }
            }
        }
        default_bytes
    }

    #[derive(Default)]
    struct MockServerCounters {
        accepted_conns: AtomicUsize,
        total_requests: AtomicUsize,
        flaky_hits: AtomicUsize,
        upload_hits: AtomicUsize,
        upload_bytes_total: AtomicUsize,
        upload_slow_hits: AtomicUsize,
        download_hits: AtomicUsize,
        download_slow_hits: AtomicUsize,
        l1_hits: AtomicUsize,
        keepalive_hits: AtomicUsize,
    }

    async fn spawn_local_probe_mock_server() -> (u16, Arc<MockServerCounters>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local mock server");
        let port = listener.local_addr().unwrap().port();
        let counters = Arc::new(MockServerCounters::default());
        let counters_bg = Arc::clone(&counters);

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let c = Arc::clone(&counters_bg);
                c.accepted_conns.fetch_add(1, Ordering::SeqCst);

                tokio::spawn(async move {
                    let mut conn_req_index = 0usize;
                    while let Some(req) = read_http_request(&mut stream).await {
                        c.total_requests.fetch_add(1, Ordering::SeqCst);
                        conn_req_index += 1;

                        let path = req.target.split('?').next().unwrap_or(&req.target);
                        let response_bytes: Vec<u8> = match (req.method.as_str(), path) {
                            ("GET", "/ping") => {
                                sleep(Duration::from_millis(8)).await;
                                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
                                    .to_vec()
                            }
                            ("GET", "/flaky") => {
                                let n = c.flaky_hits.fetch_add(1, Ordering::SeqCst);
                                if n == 1 {
                                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
                                        .to_vec()
                                } else {
                                    sleep(Duration::from_millis(6)).await;
                                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
                                        .to_vec()
                                }
                            }
                            ("GET", "/dead") => {
                                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                                    .to_vec()
                            }
                            // Google Cleanliness mock endpoints
                            ("GET", "/google_ok") => {
                                c.l1_hits.fetch_add(1, Ordering::SeqCst);
                                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
                                    .to_vec()
                            }
                            ("GET", "/google_cn_302") => {
                                c.l1_hits.fetch_add(1, Ordering::SeqCst);
                                b"HTTP/1.1 302 Found\r\nLocation: https://www.google.cn/generate_204\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
                                    .to_vec()
                            }
                            ("GET", "/yt_us") => {
                                let body = br#"{"countryCode":"US","ok":true}"#;
                                format!(
                                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
                                    body.len(),
                                    std::str::from_utf8(body).unwrap()
                                )
                                .into_bytes()
                            }
                            ("GET", "/yt_hk") => {
                                let body = br#"{"countryCode":"HK","ok":true}"#;
                                format!(
                                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
                                    body.len(),
                                    std::str::from_utf8(body).unwrap()
                                )
                                .into_bytes()
                            }
                            ("GET", "/ai_ok") => {
                                let body = "AI Studio Available";
                                format!(
                                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
                                    body.len(),
                                    body
                                )
                                .into_bytes()
                            }
                            ("GET", "/ai_blocked") => {
                                let body = "Gemini is not available in your country.";
                                format!(
                                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
                                    body.len(),
                                    body
                                )
                                .into_bytes()
                            }
                            ("GET", "/cf_tw") => {
                                let body = "fl=1f\nh=cp.cloudflare.com\nloc=TW\n";
                                format!(
                                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
                                    body.len(),
                                    body
                                )
                                .into_bytes()
                            }
                            // Unlock regex mock endpoints
                            ("GET", "/unlock/chatgpt") => {
                                c.l1_hits.fetch_add(1, Ordering::SeqCst);
                                let body = r#"{"service":"chatgpt","status":"chatgpt_web_ready"}"#;
                                format!(
                                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
                                    body.len(),
                                    body
                                )
                                .into_bytes()
                            }
                            ("GET", "/unlock/claude_denied") => {
                                let body = "Access restricted";
                                format!(
                                    "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
                                    body.len(),
                                    body
                                )
                                .into_bytes()
                            }
                            // L2 Throughput endpoints
                            ("POST", "/__up") => {
                                c.upload_hits.fetch_add(1, Ordering::SeqCst);
                                c.upload_bytes_total
                                    .fetch_add(req.body_len, Ordering::SeqCst);
                                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok"
                                    .to_vec()
                            }
                            ("POST", "/__up_slow") => {
                                c.upload_slow_hits.fetch_add(1, Ordering::SeqCst);
                                sleep(Duration::from_millis(120)).await;
                                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok"
                                    .to_vec()
                            }
                            ("GET", "/__down") => {
                                c.download_hits.fetch_add(1, Ordering::SeqCst);
                                let size = extract_bytes_query(&req.target, 512 * 1024);
                                let header = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Length: {size}\r\nConnection: keep-alive\r\n\r\n"
                                );
                                let mut out = Vec::with_capacity(header.len() + size);
                                out.extend_from_slice(header.as_bytes());
                                out.resize(header.len() + size, b'D');
                                out
                            }
                            ("GET", "/__down_slow") => {
                                c.download_slow_hits.fetch_add(1, Ordering::SeqCst);
                                sleep(Duration::from_millis(120)).await;
                                let size = extract_bytes_query(&req.target, 16 * 1024);
                                let header = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Length: {size}\r\nConnection: keep-alive\r\n\r\n"
                                );
                                let mut out = Vec::with_capacity(header.len() + size);
                                out.extend_from_slice(header.as_bytes());
                                out.resize(header.len() + size, b'S');
                                out
                            }
                            // L2 Keep-Alive endpoints
                            ("GET", "/keepalive_ok") => {
                                c.keepalive_hits.fetch_add(1, Ordering::SeqCst);
                                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
                                    .to_vec()
                            }
                            ("GET", "/keepalive_blackhole") => {
                                if conn_req_index == 1 {
                                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
                                        .to_vec()
                                } else {
                                    // Simulate silent NAT/middlebox blackhole: swallow packets without replying
                                    sleep(Duration::from_secs(5)).await;
                                    break;
                                }
                            }
                            _ => {
                                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                                    .to_vec()
                            }
                        };

                        if stream.write_all(&response_bytes).await.is_err() {
                            break;
                        }
                        if path == "/dead" {
                            break;
                        }
                    }
                });
            }
        });

        (port, counters)
    }

    #[test]
    fn isolated_yaml_and_socks5h_invariants_verified() {
        let node = ProxyNode {
            id: "node-jp-1".to_string(),
            sub_id: "sub-1".to_string(),
            name: "JP-Tokyo-01".to_string(),
            protocol: "vless".to_string(),
            server: "jp.example.invalid".to_string(),
            port: 443,
            raw_config: serde_json::json!({
                "name": "JP-Tokyo-01",
                "type": "vless",
                "server": "jp.example.invalid",
                "port": 443,
                "uuid": "00000000-0000-0000-0000-000000000000"
            }),
            region_code: "JP".to_string(),
            multiplier: 1.0,
            is_443_native: true,
            ..Default::default()
        };

        let ports = allocate_ephemeral_ports(2).unwrap();
        let yaml = build_isolated_probe_yaml(ports[0], "test-secret-0123456789", &[(ports[1], &node)], &[])
            .expect("build isolated yaml");

        assert!(yaml.contains("mixed-port: 0"));
        assert!(yaml.contains("allow-lan: false"));
        assert!(yaml.contains("geodata-mode: false"));
        assert!(yaml.contains("enhanced-mode: redir-host"));
        assert!(yaml.contains("listen: 127.0.0.1"));
        assert!(yaml.contains("223.5.5.5"));
        assert!(yaml.contains("119.29.29.29"));

        let s5h = isolated_proxy_url(ports[1], IsolatedProxyScheme::Socks5h);
        assert!(s5h.starts_with("socks5h://127.0.0.1:"));
        assert!(!s5h.starts_with("socks5://"));
    }

    #[tokio::test]
    async fn local_http_google_cleanliness_truth_and_cf_tw_yt_us_preserved() {
        let (port, _counters) = spawn_local_probe_mock_server().await;
        let client_no_redir = build_direct_no_proxy_client(Duration::from_secs(3), false, None).unwrap();

        let def = ProbeDefinition {
            id: "builtin_google_cn".to_string(),
            name: "Google Cleanliness".to_string(),
            kind: ProbeKind::GoogleCn,
            target_url: format!("http://127.0.0.1:{port}/google_ok"),
            method: "GET".to_string(),
            expected_status: Some(204),
            timeout_ms: 3000,
            builtin: true,
            ..Default::default()
        };

        // Case 1: CF=TW while YT=US, Google 204, AI Studio 200 -> CLEAN + advisory risk tag only
        let ep_clean_mismatch = GoogleCnEndpoints {
            google_url: format!("http://127.0.0.1:{port}/google_ok"),
            youtube_url: Some(format!("http://127.0.0.1:{port}/yt_us")),
            ai_studio_url: Some(format!("http://127.0.0.1:{port}/ai_ok")),
            cf_trace_url: Some(format!("http://127.0.0.1:{port}/cf_tw")),
        };
        let rec = run_google_cn_probe(&client_no_redir, "n-tw", &def, Some(&ep_clean_mismatch)).await;
        assert!(rec.ok);
        assert_eq!(rec.google_clean, Some(true));
        assert_eq!(rec.cf_loc.as_deref(), Some("TW"));
        assert_eq!(rec.yt_gl.as_deref(), Some("US"));
        let snap = ProbeSnapshot::from_results("n-tw", &[rec], None);
        assert_eq!(snap.google_clean, Some(true));
        assert!(snap.google_risk_mismatch);

        // Case 2: Google 302 -> google.cn must fail hard gate
        let ep_cn_302 = GoogleCnEndpoints {
            google_url: format!("http://127.0.0.1:{port}/google_cn_302"),
            youtube_url: Some(format!("http://127.0.0.1:{port}/yt_us")),
            ai_studio_url: Some(format!("http://127.0.0.1:{port}/ai_ok")),
            cf_trace_url: Some(format!("http://127.0.0.1:{port}/cf_tw")),
        };
        let rec_302 = run_google_cn_probe(&client_no_redir, "n-cn", &def, Some(&ep_cn_302)).await;
        assert!(!rec_302.ok);
        assert_eq!(rec_302.google_clean, Some(false));

        // Case 3: YouTube GL=HK must fail hard gate
        let ep_yt_hk = GoogleCnEndpoints {
            google_url: format!("http://127.0.0.1:{port}/google_ok"),
            youtube_url: Some(format!("http://127.0.0.1:{port}/yt_hk")),
            ai_studio_url: Some(format!("http://127.0.0.1:{port}/ai_ok")),
            cf_trace_url: Some(format!("http://127.0.0.1:{port}/cf_tw")),
        };
        let rec_hk = run_google_cn_probe(&client_no_redir, "n-hk", &def, Some(&ep_yt_hk)).await;
        assert!(!rec_hk.ok);
        assert_eq!(rec_hk.google_clean, Some(false));

        // Case 4: AI Studio body region block must fail hard gate
        let ep_ai_blocked = GoogleCnEndpoints {
            google_url: format!("http://127.0.0.1:{port}/google_ok"),
            youtube_url: Some(format!("http://127.0.0.1:{port}/yt_us")),
            ai_studio_url: Some(format!("http://127.0.0.1:{port}/ai_blocked")),
            cf_trace_url: Some(format!("http://127.0.0.1:{port}/cf_tw")),
        };
        let rec_ai = run_google_cn_probe(&client_no_redir, "n-ai", &def, Some(&ep_ai_blocked)).await;
        assert!(!rec_ai.ok);
        assert_eq!(rec_ai.google_clean, Some(false));
        assert_eq!(rec_ai.unlocked_map.get("gemini_aistudio"), Some(&false));
    }

    #[tokio::test]
    async fn local_http_l0_latency_jitter_and_l1_unlock_regex() {
        let (port, _counters) = spawn_local_probe_mock_server().await;
        let client = build_direct_no_proxy_client(Duration::from_secs(3), true, None).unwrap();

        let l0_ok_def = ProbeDefinition {
            id: "l0_ping".to_string(),
            name: "Local Ping".to_string(),
            kind: ProbeKind::Latency,
            target_url: format!("http://127.0.0.1:{port}/ping"),
            method: "GET".to_string(),
            expected_status: Some(204),
            timeout_ms: 2000,
            ..Default::default()
        };
        let rec_ok = run_latency_probe(&client, "n1", &l0_ok_def, 3).await;
        assert!(rec_ok.ok);
        assert!(rec_ok.latency_ms.unwrap_or(0.0) > 0.0);
        assert!(rec_ok.jitter_ms.is_some());
        assert_eq!(rec_ok.loss_pct, Some(0.0));

        let l0_flaky_def = ProbeDefinition {
            id: "l0_flaky".to_string(),
            target_url: format!("http://127.0.0.1:{port}/flaky"),
            ..l0_ok_def
        };
        let rec_flaky = run_latency_probe(&client, "n1", &l0_flaky_def, 3).await;
        assert!(rec_flaky.ok);
        assert_eq!(rec_flaky.loss_pct, Some(33.33));

        let unlock_chatgpt = ProbeDefinition {
            id: "unlock_chatgpt".to_string(),
            name: "ChatGPT Unlock".to_string(),
            kind: ProbeKind::UnlockRegex,
            target_url: format!("http://127.0.0.1:{port}/unlock/chatgpt"),
            method: "GET".to_string(),
            expected_status: Some(200),
            body_regex: Some("chatgpt_web_ready".to_string()),
            timeout_ms: 2000,
            ..Default::default()
        };
        let rec_cgpt = run_unlock_regex_probe(&client, "n1", &unlock_chatgpt).await;
        assert!(rec_cgpt.ok);
        assert_eq!(rec_cgpt.unlocked_map.get("chatgpt"), Some(&true));

        let unlock_claude = ProbeDefinition {
            id: "unlock_claude".to_string(),
            name: "Claude Unlock".to_string(),
            kind: ProbeKind::UnlockRegex,
            target_url: format!("http://127.0.0.1:{port}/unlock/claude_denied"),
            method: "GET".to_string(),
            expected_status: Some(200),
            body_regex: Some("claude_ready".to_string()),
            timeout_ms: 2000,
            ..Default::default()
        };
        let rec_claude = run_unlock_regex_probe(&client, "n1", &unlock_claude).await;
        assert!(!rec_claude.ok);
        assert_eq!(rec_claude.unlocked_map.get("claude"), Some(&false));
    }

    #[tokio::test]
    async fn local_http_l2_throughput_scale_up_and_512kb_fast_fuse() {
        let (port, counters) = spawn_local_probe_mock_server().await;
        let client = build_direct_no_proxy_client(Duration::from_secs(5), true, None).unwrap();

        // Normal upload: 512 KiB Stage-1 passes -> scales up to 1 MiB Stage-2
        let up_def = ProbeDefinition {
            id: "up_test".to_string(),
            name: "Local Upload".to_string(),
            kind: ProbeKind::Upload,
            target_url: format!("http://127.0.0.1:{port}/__up"),
            method: "POST".to_string(),
            expected_status: Some(200),
            payload_bytes: Some(1024 * 1024),
            timeout_ms: 5000,
            ..Default::default()
        };
        let up_rec = run_upload_probe(&client, "n1", &up_def).await;
        assert!(up_rec.ok, "detail={:?}", up_rec.detail);
        assert!(up_rec.up_mbps.unwrap_or(0.0) > FAST_FUSE_MIN_MBPS);
        assert_eq!(counters.upload_hits.load(Ordering::SeqCst), 2);
        assert_eq!(
            counters.upload_bytes_total.load(Ordering::SeqCst),
            FAST_FUSE_PROBE_BYTES + 1024 * 1024
        );

        // Normal download: 512 KiB Stage-1 passes -> scales up to 1 MiB Stage-2
        let down_def = ProbeDefinition {
            id: "down_test".to_string(),
            name: "Local Download".to_string(),
            kind: ProbeKind::Download,
            target_url: format!("http://127.0.0.1:{port}/__down?bytes=1048576"),
            method: "GET".to_string(),
            expected_status: Some(200),
            payload_bytes: Some(1024 * 1024),
            timeout_ms: 5000,
            ..Default::default()
        };
        let down_rec = run_download_probe(&client, "n1", &down_def).await;
        assert!(down_rec.ok, "detail={:?}", down_rec.detail);
        assert!(down_rec.down_mbps.unwrap_or(0.0) > FAST_FUSE_MIN_MBPS);
        assert_eq!(counters.download_hits.load(Ordering::SeqCst), 2);

        // Fast-fuse abort: slow server yields throughput below threshold -> stops at Stage-1 (1 request only)
        let strict_cfg = ThroughputProbeConfig {
            fuse_bytes: 16 * 1024,
            fuse_min_mbps: 50.0, // 16 KiB over 120ms is ~1.09 Mbps < 50 Mbps -> immediate fuse
            max_payload_bytes: 1024 * 1024,
        };
        let slow_up = ProbeDefinition {
            id: "up_slow".to_string(),
            target_url: format!("http://127.0.0.1:{port}/__up_slow"),
            ..up_def
        };
        let fused_up = run_upload_probe_with_config(&client, "n1", &slow_up, &strict_cfg).await;
        assert!(!fused_up.ok);
        assert!(
            fused_up
                .detail
                .as_deref()
                .unwrap_or("")
                .contains("fast_fuse_triggered")
        );
        assert_eq!(counters.upload_slow_hits.load(Ordering::SeqCst), 1);

        let slow_down = ProbeDefinition {
            id: "down_slow".to_string(),
            target_url: format!("http://127.0.0.1:{port}/__down_slow?bytes=1048576"),
            ..down_def
        };
        let fused_down =
            run_download_probe_with_config(&client, "n1", &slow_down, &strict_cfg).await;
        assert!(!fused_down.ok);
        assert!(
            fused_down
                .detail
                .as_deref()
                .unwrap_or("")
                .contains("fast_fuse_triggered")
        );
        assert_eq!(counters.download_slow_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn local_http_l2_keepalive_reuse_and_silent_blackhole_detection() {
        let (port, counters) = spawn_local_probe_mock_server().await;
        let short_intervals = vec![Duration::from_millis(50), Duration::from_millis(100)];

        let ka_client = build_direct_no_proxy_client(
            Duration::from_secs(2),
            true,
            Some(Duration::from_secs(10)),
        )
        .unwrap();

        let ka_ok_def = ProbeDefinition {
            id: "ka_ok".to_string(),
            name: "KeepAlive OK".to_string(),
            kind: ProbeKind::Keepalive,
            target_url: format!("http://127.0.0.1:{port}/keepalive_ok"),
            method: "GET".to_string(),
            expected_status: Some(204),
            timeout_ms: 1000,
            ..Default::default()
        };
        let before_conns = counters.accepted_conns.load(Ordering::SeqCst);
        let rec_ok = run_keepalive_probe(&ka_client, "n1", &ka_ok_def, &short_intervals).await;
        assert!(rec_ok.ok, "detail={:?}", rec_ok.detail);
        assert_eq!(rec_ok.keepalive_60s_ok, Some(true));
        assert_eq!(counters.keepalive_hits.load(Ordering::SeqCst), 3);
        assert_eq!(
            counters.accepted_conns.load(Ordering::SeqCst) - before_conns,
            1,
            "keep-alive probe should reuse a single persistent TCP connection"
        );

        // Silent blackhole: warmup succeeds, post-idle probe stalls past step timeout
        let bh_client = build_direct_no_proxy_client(
            Duration::from_secs(2),
            true,
            Some(Duration::from_secs(10)),
        )
        .unwrap();
        let ka_bh_def = ProbeDefinition {
            id: "ka_bh".to_string(),
            name: "KeepAlive Blackhole".to_string(),
            kind: ProbeKind::Keepalive,
            target_url: format!("http://127.0.0.1:{port}/keepalive_blackhole"),
            method: "GET".to_string(),
            expected_status: Some(204),
            timeout_ms: 250,
            ..Default::default()
        };
        let rec_bh = run_keepalive_probe(&bh_client, "n1", &ka_bh_def, &short_intervals).await;
        assert!(!rec_bh.ok);
        assert_eq!(rec_bh.keepalive_60s_ok, Some(false));
        assert!(
            rec_bh
                .detail
                .as_deref()
                .unwrap_or("")
                .contains("keepalive_blackhole")
        );
    }

    #[tokio::test]
    async fn funnel_orchestrator_executes_full_pipeline_and_short_circuits_dead_l0() {
        let (port, counters) = spawn_local_probe_mock_server().await;

        let mut reg = ProbeRegistry::new();
        reg.register(ProbeDefinition {
            id: "l0_ping".to_string(),
            name: "L0 Ping".to_string(),
            kind: ProbeKind::Latency,
            target_url: format!("http://127.0.0.1:{port}/ping"),
            method: "GET".to_string(),
            expected_status: Some(204),
            timeout_ms: 2000,
            ..Default::default()
        })
        .unwrap();
        reg.register(ProbeDefinition {
            id: "l1_google".to_string(),
            name: "L1 Google".to_string(),
            kind: ProbeKind::GoogleCn,
            target_url: format!("http://127.0.0.1:{port}/google_ok"),
            method: "GET".to_string(),
            expected_status: Some(204),
            timeout_ms: 2000,
            ..Default::default()
        })
        .unwrap();
        reg.register(ProbeDefinition {
            id: "l1_chatgpt".to_string(),
            name: "L1 ChatGPT".to_string(),
            kind: ProbeKind::UnlockRegex,
            target_url: format!("http://127.0.0.1:{port}/unlock/chatgpt"),
            method: "GET".to_string(),
            expected_status: Some(200),
            body_regex: Some("chatgpt_web_ready".to_string()),
            timeout_ms: 2000,
            ..Default::default()
        })
        .unwrap();
        reg.register(ProbeDefinition {
            id: "l2_up".to_string(),
            name: "L2 Upload".to_string(),
            kind: ProbeKind::Upload,
            target_url: format!("http://127.0.0.1:{port}/__up"),
            method: "POST".to_string(),
            expected_status: Some(200),
            payload_bytes: Some(512 * 1024),
            timeout_ms: 4000,
            ..Default::default()
        })
        .unwrap();
        reg.register(ProbeDefinition {
            id: "l2_ka".to_string(),
            name: "L2 KeepAlive".to_string(),
            kind: ProbeKind::Keepalive,
            target_url: format!("http://127.0.0.1:{port}/keepalive_ok"),
            method: "GET".to_string(),
            expected_status: Some(204),
            timeout_ms: 1000,
            ..Default::default()
        })
        .unwrap();

        let opts = FunnelOptions {
            max_tier: FunnelTier::L2ThroughputAndKeepalive,
            latency_samples: 2,
            google_endpoints: Some(GoogleCnEndpoints {
                google_url: format!("http://127.0.0.1:{port}/google_ok"),
                youtube_url: Some(format!("http://127.0.0.1:{port}/yt_us")),
                ai_studio_url: Some(format!("http://127.0.0.1:{port}/ai_ok")),
                cf_trace_url: Some(format!("http://127.0.0.1:{port}/cf_tw")),
            }),
            throughput: ThroughputProbeConfig::default(),
            keepalive_intervals: vec![Duration::from_millis(40), Duration::from_millis(60)],
            proxy_scheme: IsolatedProxyScheme::Socks5h,
            short_circuit_on_l0_failure: true,
            short_circuit_on_google_dirty: false,
            bypass_proxy_for_loopback_test: true,
        };

        let report = run_funnel_for_node(&reg, "node-good", 0, &opts, None, Some("l2_up"))
            .await
            .expect("full funnel run");
        assert!(!report.short_circuited);
        assert_eq!(report.reached_tier, FunnelTier::L2ThroughputAndKeepalive);
        assert_eq!(report.records.len(), 5);
        assert!(report.snapshot.ok);
        assert_eq!(report.snapshot.google_clean, Some(true));
        assert!(report.snapshot.google_risk_mismatch);
        assert_eq!(report.snapshot.keepalive_60s_ok, Some(true));
        assert_eq!(report.snapshot.unlocked_sites.get("l1_chatgpt"), Some(&true));
        assert!(report.snapshot.probe_up("l2_up").unwrap_or(0.0) > 0.2);

        // Short-circuit test: dead L0 must stop immediately and never hit L1/L2
        let mut dead_reg = ProbeRegistry::new();
        dead_reg
            .register(ProbeDefinition {
                id: "l0_dead".to_string(),
                name: "Dead L0".to_string(),
                kind: ProbeKind::Latency,
                target_url: format!("http://127.0.0.1:{port}/dead"),
                method: "GET".to_string(),
                expected_status: Some(204),
                timeout_ms: 1000,
                ..Default::default()
            })
            .unwrap();
        dead_reg
            .register(ProbeDefinition {
                id: "l1_never".to_string(),
                name: "Should Skip".to_string(),
                kind: ProbeKind::UnlockRegex,
                target_url: format!("http://127.0.0.1:{port}/unlock/chatgpt"),
                method: "GET".to_string(),
                expected_status: Some(200),
                timeout_ms: 1000,
                ..Default::default()
            })
            .unwrap();

        let l1_before = counters.l1_hits.load(Ordering::SeqCst);
        let dead_report = run_funnel_for_node(&dead_reg, "node-dead", 0, &opts, None, None)
            .await
            .expect("dead node funnel");
        assert!(dead_report.short_circuited);
        assert_eq!(dead_report.reached_tier, FunnelTier::L0Connectivity);
        assert_eq!(dead_report.records.len(), 1);
        assert!(!dead_report.snapshot.ok);
        assert_eq!(
            counters.l1_hits.load(Ordering::SeqCst),
            l1_before,
            "L1 must not be invoked when L0 short-circuits"
        );
    }
}
