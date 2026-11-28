use crate::error::{CatError, CatResult};
use crate::models::{ProbeDefinition, ProbeResultRecord};
use crate::probe::registry::{
    DEFAULT_DOWNLOAD_PAYLOAD_BYTES, DEFAULT_UPLOAD_PAYLOAD_BYTES, MAX_PAYLOAD_BYTES,
};
use chrono::Utc;
use regex::Regex;
use reqwest::Method;
use reqwest::header::{ACCEPT_LANGUAGE, CONTENT_TYPE, COOKIE, LOCATION};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use url::Url;

/// Default number of HTTP samples for L0 latency/jitter/loss probes.
pub const DEFAULT_LATENCY_SAMPLES: usize = 3;

/// Initial probe size (512 KiB) for L2 upload/download fast-fuse blackhole detection.
pub const FAST_FUSE_PROBE_BYTES: usize = 512 * 1024;

/// Minimum throughput threshold (0.2 Mbps) to pass the 512 KiB fast fuse before scaling up.
pub const FAST_FUSE_MIN_MBPS: f64 = 0.2;

/// Hard upper limit (8 MiB) on single upload/download throughput payload size.
pub const MAX_THROUGHPUT_PAYLOAD_BYTES: usize = MAX_PAYLOAD_BYTES as usize;

/// Maximum response body size read for unlock/Google text inspection (256 KiB).
pub const MAX_INSPECT_BODY_BYTES: usize = 256 * 1024;

/// Default silent intervals for L2 Keep-Alive blackhole detection (`[20s, 40s, 60s]`).
pub const DEFAULT_KEEPALIVE_INTERVALS_MS: &[u64] = &[20_000, 40_000, 60_000];

/// Default Google-side and advisory endpoints for L1 Google cleanliness probing.
pub const DEFAULT_GOOGLE_204_URL: &str = "https://www.google.com/generate_204";
pub const DEFAULT_GOOGLE_HOME_URL: &str = "https://www.google.com/";
pub const DEFAULT_YOUTUBE_REGION_URL: &str = "https://www.youtube.com/premium";
pub const DEFAULT_AI_STUDIO_URL: &str = "https://aistudio.google.com/";
pub const DEFAULT_CF_TRACE_URL: &str = "https://cp.cloudflare.com/cdn-cgi/trace";

/// Credential-free endpoints for built-in AI semantic unlock probes.
const CLAUDE_TRACE_URL: &str = "https://claude.ai/cdn-cgi/trace";
const CLAUDE_API_MESSAGES_URL: &str = "https://api.anthropic.com/v1/messages";
const CHATGPT_TRACE_URL: &str = "https://chatgpt.com/cdn-cgi/trace";
const CHATGPT_API_MODELS_URL: &str = "https://api.openai.com/v1/models";
const CHATGPT_AB_URL: &str = "https://ab.chatgpt.com/v1/rgstr";
const GEMINI_API_MODELS_CHECK_URL: &str =
    "https://generativelanguage.googleapis.com/v1beta/models?key=catcloud_probe_check";
const WINDSURF_API_CHAT_URL: &str =
    "https://server.codeium.com/exa.api_server_pb.ApiServerService/GetChatMessage";
const IPQUERY_JSON_URL: &str = "https://api.ipquery.io/?format=json";
const IPAPI_JSON_URL: &str =
    "http://ip-api.com/json/?fields=status,countryCode,isp,org,as,mobile,proxy,hosting";

/// Unsupported jurisdictions for Claude / ChatGPT Cloudflare trace pre-filtering.
const AI_TRACE_BLOCKED_COUNTRIES: &[&str] =
    &["CN", "HK", "MO", "RU", "BY", "KP", "IR", "SY", "CU"];

/// Computed summary statistics for multi-sample L0 latency probes.
#[derive(Debug, Clone, PartialEq)]
pub struct LatencyStats {
    pub latency_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub loss_pct: f64,
    pub ok_count: usize,
    pub total_count: usize,
}

/// Pure calculation of mean latency, mean absolute adjacent jitter, and packet loss percentage.
pub fn compute_latency_stats(samples_ms: &[Option<f64>]) -> LatencyStats {
    if samples_ms.is_empty() {
        return LatencyStats {
            latency_ms: None,
            jitter_ms: None,
            loss_pct: 100.0,
            ok_count: 0,
            total_count: 0,
        };
    }

    let valid: Vec<f64> = samples_ms
        .iter()
        .filter_map(|opt| *opt)
        .filter(|v| v.is_finite() && *v >= 0.0)
        .collect();

    let total_count = samples_ms.len();
    let ok_count = valid.len();
    let loss_pct = ((total_count - ok_count) as f64 / total_count as f64) * 100.0;

    if valid.is_empty() {
        return LatencyStats {
            latency_ms: None,
            jitter_ms: None,
            loss_pct,
            ok_count: 0,
            total_count,
        };
    }

    let latency_ms = valid.iter().sum::<f64>() / (valid.len() as f64);
    let jitter_ms = if valid.len() >= 2 {
        let sum_diff: f64 = valid.windows(2).map(|w| (w[1] - w[0]).abs()).sum();
        sum_diff / ((valid.len() - 1) as f64)
    } else {
        0.0
    };

    LatencyStats {
        latency_ms: Some(round2(latency_ms)),
        jitter_ms: Some(round2(jitter_ms)),
        loss_pct: round2(loss_pct),
        ok_count,
        total_count,
    }
}

/// Execute an L0 latency/jitter/loss probe with `samples` HTTP attempts (default 3).
///
/// For non-loopback targets with `samples >= 2`, performs one warmup request first to establish
/// the SOCKS5/TCP/TLS connection and drain the response body so subsequent samples measure true
/// hot keep-alive RTT without cold-handshake inflation.
pub async fn run_latency_probe(
    client: &reqwest::Client,
    node_id: &str,
    def: &ProbeDefinition,
    samples: usize,
) -> ProbeResultRecord {
    let target_url = def.target_url.trim();
    let sample_count = samples.max(1);
    let do_warmup = sample_count >= 2 && !is_loopback_url(target_url);
    run_latency_probe_with_warmup(client, node_id, def, sample_count, do_warmup).await
}

async fn execute_single_latency_attempt(
    client: &reqwest::Client,
    method: Method,
    target_url: &str,
    expected_status: Option<u16>,
    timeout: Duration,
) -> Result<f64, String> {
    let started = Instant::now();
    match client
        .request(method, target_url)
        .timeout(timeout)
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
            // Drain small response body so keep-alive connections can be reused cleanly.
            let _ = drain_capped_body(resp, 16 * 1024).await;

            let status_ok = match expected_status {
                Some(exp) => status == exp,
                None => status < 500,
            };
            if status_ok {
                Ok(elapsed_ms)
            } else {
                Err(format!("unexpected HTTP status {status}"))
            }
        }
        Err(err) => Err(err.to_string()),
    }
}

async fn run_latency_probe_with_warmup(
    client: &reqwest::Client,
    node_id: &str,
    def: &ProbeDefinition,
    samples: usize,
    do_warmup: bool,
) -> ProbeResultRecord {
    let sample_count = samples.max(1);
    let timeout = Duration::from_millis(def.timeout_ms.max(200));
    let method = match parse_http_method(&def.method) {
        Ok(m) => m,
        Err(err) => {
            return failed_record(node_id, &def.id, format!("invalid method: {err}"));
        }
    };
    let target_url = def.target_url.trim();

    let mut warmup_ok_ms: Option<f64> = None;
    let mut last_error: Option<String> = None;

    if do_warmup {
        match execute_single_latency_attempt(
            client,
            method.clone(),
            target_url,
            def.expected_status,
            timeout,
        )
        .await
        {
            Ok(ms) => {
                warmup_ok_ms = Some(ms);
            }
            Err(err) => {
                // Never abort on warmup failure; proceed to full sample attempts.
                last_error = Some(err);
            }
        }
    }

    // When warmup succeeded and `samples >= 3`, measuring `sample_count - 1` (minimum 2) hot
    // keep-alive requests keeps total HTTP round-trips identical to `samples` while yielding
    // accurate hot RTT and adjacent jitter.
    let measured_count = if warmup_ok_ms.is_some() && sample_count >= 3 {
        (sample_count - 1).max(2)
    } else {
        sample_count
    };

    let mut timings: Vec<Option<f64>> = Vec::with_capacity(measured_count);
    for _ in 0..measured_count {
        match execute_single_latency_attempt(
            client,
            method.clone(),
            target_url,
            def.expected_status,
            timeout,
        )
        .await
        {
            Ok(ms) => timings.push(Some(ms)),
            Err(err) => {
                timings.push(None);
                last_error = Some(err);
            }
        }
    }

    let stats = compute_latency_stats(&timings);
    if stats.ok_count > 0 {
        let detail = if do_warmup {
            if let Some(w_ms) = warmup_ok_ms {
                format!(
                    "warmup_ms={:.2}, samples={}/{}, latency_ms={:.2}, jitter_ms={:.2}, loss_pct={:.1}",
                    round2(w_ms),
                    stats.ok_count,
                    stats.total_count,
                    stats.latency_ms.unwrap_or(0.0),
                    stats.jitter_ms.unwrap_or(0.0),
                    stats.loss_pct
                )
            } else {
                format!(
                    "warmup=failed, samples={}/{}, latency_ms={:.2}, jitter_ms={:.2}, loss_pct={:.1}",
                    stats.ok_count,
                    stats.total_count,
                    stats.latency_ms.unwrap_or(0.0),
                    stats.jitter_ms.unwrap_or(0.0),
                    stats.loss_pct
                )
            }
        } else {
            format!(
                "samples={}/{}, latency_ms={:.2}, jitter_ms={:.2}, loss_pct={:.1}",
                stats.ok_count,
                stats.total_count,
                stats.latency_ms.unwrap_or(0.0),
                stats.jitter_ms.unwrap_or(0.0),
                stats.loss_pct
            )
        };

        return ProbeResultRecord {
            node_id: node_id.to_string(),
            probe_id: def.id.clone(),
            tested_at: now_rfc3339(),
            ok: true,
            latency_ms: stats.latency_ms,
            jitter_ms: stats.jitter_ms,
            loss_pct: Some(stats.loss_pct),
            detail: Some(detail),
            ..Default::default()
        };
    }

    // All measured hot samples failed: fall back to the warmup timing if warmup succeeded.
    if let Some(w_ms) = warmup_ok_ms {
        let total_attempts = measured_count + 1;
        let loss_pct = round2((measured_count as f64 / total_attempts as f64) * 100.0);
        let fallback_ms = round2(w_ms);
        return ProbeResultRecord {
            node_id: node_id.to_string(),
            probe_id: def.id.clone(),
            tested_at: now_rfc3339(),
            ok: true,
            latency_ms: Some(fallback_ms),
            jitter_ms: Some(0.0),
            loss_pct: Some(loss_pct),
            detail: Some(format!(
                "warmup_fallback=true, samples=1/{total_attempts}, latency_ms={fallback_ms:.2}, jitter_ms=0.00, loss_pct={loss_pct:.1}"
            )),
            ..Default::default()
        };
    }

    ProbeResultRecord {
        node_id: node_id.to_string(),
        probe_id: def.id.clone(),
        tested_at: now_rfc3339(),
        ok: false,
        latency_ms: None,
        jitter_ms: None,
        loss_pct: Some(stats.loss_pct),
        detail: Some(format!(
            "all {} samples failed: {}",
            stats.total_count,
            last_error.unwrap_or_else(|| "request failed".to_string())
        )),
        ..Default::default()
    }
}

// ============================================================================
// L1: Google Cleanliness Ground-Truth Evaluation & Probe
// ============================================================================

/// Injectable endpoints for Google region cleanliness checks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GoogleCnEndpoints {
    pub google_url: String,
    #[serde(default)]
    pub google_home_url: Option<String>,
    pub youtube_url: Option<String>,
    pub ai_studio_url: Option<String>,
    pub cf_trace_url: Option<String>,
}

impl Default for GoogleCnEndpoints {
    fn default() -> Self {
        Self {
            google_url: DEFAULT_GOOGLE_204_URL.to_string(),
            google_home_url: Some(DEFAULT_GOOGLE_HOME_URL.to_string()),
            youtube_url: Some(DEFAULT_YOUTUBE_REGION_URL.to_string()),
            ai_studio_url: Some(DEFAULT_AI_STUDIO_URL.to_string()),
            cf_trace_url: Some(DEFAULT_CF_TRACE_URL.to_string()),
        }
    }
}

impl GoogleCnEndpoints {
    pub fn from_probe_definition(def: &ProbeDefinition) -> Self {
        let mut ep = Self::default();
        let trimmed = def.target_url.trim();
        if !trimmed.is_empty() {
            ep.google_url = trimmed.to_string();
            if is_loopback_url(trimmed) {
                ep.google_home_url = None;
            }
        }
        ep
    }
}

/// Raw signals collected from Google-side endpoints and optional Cloudflare trace.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct GoogleCleanSignals {
    /// HTTP status from the Google 204/landing endpoint.
    pub google_status: Option<u16>,
    /// `Location` header or final URL host when Google redirected (including `/sorry/` or `google.cn`).
    pub google_redirect_location: Option<String>,
    /// YouTube resolved country/region code (`GL`, e.g., `"US"`, `"JP"`, `"TW"`, `"HK"`, `"CN"`).
    pub yt_gl: Option<String>,
    /// Optional AI Studio / Gemini HTTP status code.
    pub ai_studio_status: Option<u16>,
    /// Optional AI Studio / Gemini `Location` redirect header or restricted final URL.
    #[serde(default)]
    pub ai_studio_redirect_location: Option<String>,
    /// Optional AI Studio / Gemini response body snippet for region-block detection.
    pub ai_studio_body_snippet: Option<String>,
    /// Optional Cloudflare trace `loc` country code (advisory risk mismatch signal ONLY).
    pub cf_loc: Option<String>,
}

/// Verdict produced by `evaluate_google_cleanliness`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GoogleCleanAssessment {
    /// Hard gate verdict determined strictly from Google-side ground truth.
    pub google_clean: bool,
    /// Advisory warning tag (`cf_loc != yt_gl`); never turns a clean node into `google_clean=false`.
    pub google_risk_mismatch: bool,
    pub cf_loc: Option<String>,
    pub yt_gl: Option<String>,
    pub ai_studio_restricted: bool,
    pub reasons: Vec<String>,
}

const AI_STUDIO_GEO_BLOCK_MARKERS: &[&str] = &[
    "not available in your country",
    "not available in your region",
    "gemini is not currently supported",
    "region is not supported",
    "location is not supported",
    "unsupported_country",
    "unsupported_region",
];

/// Evaluate Google cleanliness strictly from Google-side ground truth:
/// - Hard gate fails if Google redirects to `google.cn` or `/sorry/`, Google returns HTTP 403/429/451,
///   YouTube `yt_gl` falls into `{CN, HK}`, or AI Studio/Gemini redirects to/reports regional unavailability.
/// - `cf_loc != yt_gl` ONLY sets `google_risk_mismatch = true` as an advisory warning badge
///   and NEVER false-kills valid TW/JP/SG/US nodes.
pub fn evaluate_google_cleanliness(signals: &GoogleCleanSignals) -> GoogleCleanAssessment {
    let mut clean = true;
    let mut ai_studio_restricted = false;
    let mut reasons = Vec::new();

    let cf_loc = signals
        .cf_loc
        .as_deref()
        .and_then(normalize_country_code);
    let yt_gl = signals
        .yt_gl
        .as_deref()
        .and_then(normalize_country_code);

    let has_google_ground_truth = signals.google_status.is_some()
        || signals.google_redirect_location.is_some()
        || yt_gl.is_some()
        || signals.ai_studio_status.is_some()
        || signals.ai_studio_redirect_location.is_some()
        || signals.ai_studio_body_snippet.is_some();

    if !has_google_ground_truth {
        clean = false;
        reasons.push("no_google_ground_truth".to_string());
    }

    if let Some(ref loc) = signals.google_redirect_location {
        if is_google_cn_location(loc) {
            clean = false;
            reasons.push(format!("google_redirect_to_cn:{loc}"));
        } else if is_google_sorry_or_cn_location(loc) {
            clean = false;
            reasons.push(format!("google_redirect_to_sorry:{loc}"));
        }
    }

    if let Some(status) = signals.google_status {
        if matches!(status, 403 | 429 | 451) {
            clean = false;
            reasons.push(format!("google_http_restricted:{status}"));
        } else if status >= 500 {
            clean = false;
            reasons.push(format!("google_http_server_error:{status}"));
        }
    }

    if let Some(ref gl) = yt_gl {
        if matches!(gl.as_str(), "CN" | "HK") {
            clean = false;
            reasons.push(format!("youtube_gl_restricted:{gl}"));
        }
    }

    if let Some(status) = signals.ai_studio_status {
        if matches!(status, 403 | 451) {
            clean = false;
            ai_studio_restricted = true;
            reasons.push(format!("ai_studio_http_restricted:{status}"));
        }
    }

    if let Some(ref loc) = signals.ai_studio_redirect_location {
        if is_ai_studio_restricted_location(loc) {
            clean = false;
            ai_studio_restricted = true;
            reasons.push(format!("ai_studio_redirect_restricted:{loc}"));
        }
    }

    if let Some(ref snippet) = signals.ai_studio_body_snippet {
        let lower = snippet.to_ascii_lowercase();
        if let Some(marker) = AI_STUDIO_GEO_BLOCK_MARKERS
            .iter()
            .find(|m| lower.contains(**m))
        {
            clean = false;
            ai_studio_restricted = true;
            reasons.push(format!("ai_studio_body_restricted:{marker}"));
        }
    }

    // Advisory mismatch tag only: NEVER alters `clean`.
    let google_risk_mismatch = match (&cf_loc, &yt_gl) {
        (Some(cf), Some(yt)) => !cf.eq_ignore_ascii_case(yt),
        _ => false,
    };
    if google_risk_mismatch {
        if let (Some(cf), Some(yt)) = (&cf_loc, &yt_gl) {
            reasons.push(format!("advisory_cf_yt_mismatch:cf={cf},yt={yt}"));
        }
    }

    GoogleCleanAssessment {
        google_clean: clean,
        google_risk_mismatch,
        cf_loc,
        yt_gl,
        ai_studio_restricted,
        reasons,
    }
}

/// Check whether a redirect `Location` or URL points to `google.cn` or any subdomain of `google.cn`.
pub fn is_google_cn_location(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return false;
    }

    let candidate = if trimmed.starts_with("//") {
        format!("https:{trimmed}")
    } else if !trimmed.contains("://") && trimmed.contains('.') {
        format!("https://{trimmed}")
    } else {
        trimmed.to_string()
    };

    if let Ok(parsed) = Url::parse(&candidate) {
        if let Some(host) = parsed.host_str() {
            let h = host.trim_end_matches('.').to_ascii_lowercase();
            return h == "google.cn" || h.ends_with(".google.cn");
        }
    }

    let lower = trimmed.to_ascii_lowercase();
    lower.contains("://google.cn")
        || lower.contains(".google.cn/")
        || lower.ends_with(".google.cn")
        || lower == "google.cn"
}

/// Check whether a redirect `Location` or URL points to `google.cn` or Google's `/sorry/` captcha gate.
pub fn is_google_sorry_or_cn_location(raw: &str) -> bool {
    if is_google_cn_location(raw) {
        return true;
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    lower.contains("/sorry/") || lower.ends_with("/sorry") || lower.contains("/sorry?")
}

/// Check whether an AI Studio redirect `Location` or final URL indicates regional restriction or `/sorry/`.
pub fn is_ai_studio_restricted_location(raw: &str) -> bool {
    let lower = raw.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }
    lower.contains("available_regions")
        || lower.contains("available-regions")
        || lower.contains("unsupported")
        || lower.contains("/sorry/")
        || lower.ends_with("/sorry")
        || lower.contains("/sorry?")
}

/// Extract the two-letter `loc` country code from a Cloudflare `/cdn-cgi/trace` text response.
pub fn parse_cloudflare_trace_loc(body: &str) -> Option<String> {
    for line in body.lines() {
        if let Some(val) = line.trim().strip_prefix("loc=") {
            if let Some(code) = normalize_country_code(val) {
                return Some(code);
            }
        }
    }
    None
}

/// Extract YouTube's resolved region code (`GL`) from an explicit response header or HTML/JSON body.
pub fn parse_youtube_gl(header_gl: Option<&str>, body: &str) -> Option<String> {
    if let Some(raw) = header_gl {
        if let Some(code) = normalize_country_code(raw) {
            return Some(code);
        }
    }

    static YT_JSON_GL_RE: OnceLock<Regex> = OnceLock::new();
    let json_re = YT_JSON_GL_RE.get_or_init(|| {
        Regex::new(r#"(?i)"(?:gl|countryCode|innertubeContextClientCountry)"\s*:\s*"([A-Za-z]{2})""#)
            .expect("valid YouTube GL json regex")
    });
    if let Some(caps) = json_re.captures(body) {
        if let Some(m) = caps.get(1) {
            if let Some(code) = normalize_country_code(m.as_str()) {
                return Some(code);
            }
        }
    }

    static YT_QUERY_GL_RE: OnceLock<Regex> = OnceLock::new();
    let query_re = YT_QUERY_GL_RE
        .get_or_init(|| Regex::new(r"(?i)\bgl=([A-Za-z]{2})\b").expect("valid YouTube GL regex"));
    if let Some(caps) = query_re.captures(body) {
        if let Some(m) = caps.get(1) {
            if let Some(code) = normalize_country_code(m.as_str()) {
                return Some(code);
            }
        }
    }

    None
}

fn normalize_country_code(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.len() == 2 && trimmed.bytes().all(|b| b.is_ascii_alphabetic()) {
        Some(trimmed.to_ascii_uppercase())
    } else {
        None
    }
}

fn is_loopback_url(raw: &str) -> bool {
    let Ok(parsed) = Url::parse(raw.trim()) else {
        return false;
    };
    matches!(
        parsed.host_str().map(|h| h.to_ascii_lowercase()).as_deref(),
        Some("127.0.0.1" | "localhost" | "[::1]" | "::1")
    )
}

async fn fetch_youtube_gl(
    client: &reqwest::Client,
    initial_url: &str,
    timeout: Duration,
) -> Option<String> {
    let initial_is_loopback = is_loopback_url(initial_url);
    let mut current_url = initial_url.to_string();

    // Initial request + up to 2 manual redirect hops via the SAME proxied client (never leak unproxied).
    for hop in 0..=2 {
        let Ok(resp) = client
            .get(&current_url)
            .header(COOKIE, "SOCS=CAI")
            .header(ACCEPT_LANGUAGE, "en-US,en;q=0.9")
            .timeout(timeout)
            .send()
            .await
        else {
            return None;
        };

        let status = resp.status().as_u16();
        let header_gl = resp
            .headers()
            .get("x-youtube-gl")
            .or_else(|| resp.headers().get("x-goog-country"))
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string);
        if let Some(ref raw_gl) = header_gl {
            if let Some(code) = normalize_country_code(raw_gl) {
                let _ = drain_capped_body(resp, 4 * 1024).await;
                return Some(code);
            }
        }

        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            let loc = resp
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(ToString::to_string);
            let _ = drain_capped_body(resp, 4 * 1024).await;

            if let Some(loc_str) = loc {
                if let Some(code) = parse_youtube_gl(None, &loc_str) {
                    return Some(code);
                }
                if hop < 2 {
                    let joined = Url::parse(&current_url)
                        .ok()
                        .and_then(|base| base.join(loc_str.trim()).ok())
                        .map(|u| u.to_string());
                    let next_url = joined.unwrap_or(loc_str);
                    if (next_url.starts_with("http://") || next_url.starts_with("https://"))
                        && (!initial_is_loopback || is_loopback_url(&next_url))
                    {
                        current_url = next_url;
                        continue;
                    }
                }
            }
            return None;
        }

        let final_url = resp.url().to_string();
        if let Some(code) = parse_youtube_gl(None, &final_url) {
            let _ = drain_capped_body(resp, 4 * 1024).await;
            return Some(code);
        }

        let bytes = drain_capped_body(resp, MAX_INSPECT_BODY_BYTES)
            .await
            .unwrap_or_default();
        let body = String::from_utf8_lossy(&bytes);
        return parse_youtube_gl(header_gl.as_deref(), &body);
    }

    None
}

async fn collect_google_clean_signals(
    client: &reqwest::Client,
    endpoints: &GoogleCnEndpoints,
    timeout: Duration,
) -> (GoogleCleanSignals, Option<f64>) {
    let google_fut = async {
        let started = Instant::now();
        match client.get(&endpoints.google_url).timeout(timeout).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
                let loc_header = resp
                    .headers()
                    .get(LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .map(ToString::to_string);
                let final_url = resp.url().to_string();
                let redirect_loc = loc_header.or_else(|| {
                    if is_google_sorry_or_cn_location(&final_url) {
                        Some(final_url)
                    } else {
                        None
                    }
                });
                let _ = drain_capped_body(resp, 16 * 1024).await;
                (Some(status), redirect_loc, Some(round2(elapsed_ms)))
            }
            Err(_) => (None, None, None),
        }
    };

    let google_home_fut = async {
        let Some(ref url) = endpoints.google_home_url else {
            return (None, None);
        };
        let Ok(resp) = client.get(url).timeout(timeout).send().await else {
            return (None, None);
        };
        let status = resp.status().as_u16();
        let loc_header = resp
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string);
        let final_url = resp.url().to_string();
        let redirect_loc = loc_header
            .filter(|loc| is_google_sorry_or_cn_location(loc))
            .or_else(|| {
                if is_google_sorry_or_cn_location(&final_url) {
                    Some(final_url)
                } else {
                    None
                }
            });
        let _ = drain_capped_body(resp, 16 * 1024).await;
        (Some(status), redirect_loc)
    };

    let yt_fut = async {
        let Some(ref url) = endpoints.youtube_url else {
            return None;
        };
        fetch_youtube_gl(client, url, timeout).await
    };

    let ai_fut = async {
        let Some(ref url) = endpoints.ai_studio_url else {
            return (None, None, None);
        };
        let Ok(resp) = client.get(url).timeout(timeout).send().await else {
            return (None, None, None);
        };
        let status = resp.status().as_u16();
        let loc_header = resp
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string);
        let final_url = resp.url().to_string();
        let redirect_loc = loc_header.or_else(|| {
            if is_ai_studio_restricted_location(&final_url) {
                Some(final_url)
            } else {
                None
            }
        });
        let bytes = drain_capped_body(resp, 64 * 1024)
            .await
            .unwrap_or_default();
        let body = String::from_utf8_lossy(&bytes).into_owned();
        (Some(status), redirect_loc, Some(body))
    };

    let cf_fut = async {
        let Some(ref url) = endpoints.cf_trace_url else {
            return None;
        };
        let Ok(resp) = client.get(url).timeout(timeout).send().await else {
            return None;
        };
        let bytes = drain_capped_body(resp, 16 * 1024)
            .await
            .unwrap_or_default();
        let body = String::from_utf8_lossy(&bytes);
        parse_cloudflare_trace_loc(&body)
    };

    let (
        (google_204_status, google_204_redirect, google_ms),
        (google_home_status, google_home_redirect),
        yt_gl,
        (ai_status, ai_redirect, ai_body),
        cf_loc,
    ) = tokio::join!(google_fut, google_home_fut, yt_fut, ai_fut, cf_fut);

    let google_redirect_location = if google_204_redirect
        .as_deref()
        .is_some_and(is_google_sorry_or_cn_location)
    {
        google_204_redirect
    } else if google_home_redirect
        .as_deref()
        .is_some_and(is_google_sorry_or_cn_location)
    {
        google_home_redirect
    } else {
        google_204_redirect.or(google_home_redirect)
    };

    let google_status = match (google_204_status, google_home_status) {
        (_, Some(s)) if matches!(s, 403 | 429 | 451) => Some(s),
        (Some(s), _) => Some(s),
        (None, home) => home,
    };

    let signals = GoogleCleanSignals {
        google_status,
        google_redirect_location,
        yt_gl,
        ai_studio_status: ai_status,
        ai_studio_redirect_location: ai_redirect,
        ai_studio_body_snippet: ai_body,
        cf_loc,
    };

    (signals, google_ms)
}

/// Lightweight live Google cleanliness probe for exit-IP diagnostics.
/// Uses ONLY the caller-supplied proxied `client` and never creates an unproxied client.
pub async fn probe_live_google_cleanliness(
    client: &reqwest::Client,
    timeout: Duration,
) -> GoogleCleanAssessment {
    let effective_timeout = timeout.max(Duration::from_millis(500));
    let endpoints = GoogleCnEndpoints::default();
    let (signals, _) = collect_google_clean_signals(client, &endpoints, effective_timeout).await;
    evaluate_google_cleanliness(&signals)
}

/// Execute an L1 Google region cleanliness probe across injectable Google, Google Home,
/// YouTube, AI Studio, and Cloudflare trace endpoints. The supplied `client` should disable
/// auto-redirects (`Policy::none()`) so 302 redirects to `google.cn`, `/sorry/`, or AI Studio
/// `available_regions` are captured directly; final URL host/path is also inspected as a fallback.
pub async fn run_google_cn_probe(
    client: &reqwest::Client,
    node_id: &str,
    def: &ProbeDefinition,
    endpoints: Option<&GoogleCnEndpoints>,
) -> ProbeResultRecord {
    let owned_ep = match endpoints {
        Some(ep) => ep.clone(),
        None => GoogleCnEndpoints::from_probe_definition(def),
    };
    let timeout = Duration::from_millis(def.timeout_ms.max(500));

    let (signals, google_ms) = collect_google_clean_signals(client, &owned_ep, timeout).await;
    let assessment = evaluate_google_cleanliness(&signals);

    let mut unlocked_map = HashMap::new();
    unlocked_map.insert("google_clean".to_string(), assessment.google_clean);
    if owned_ep.ai_studio_url.is_some()
        && (signals.ai_studio_status.is_some() || signals.ai_studio_redirect_location.is_some())
    {
        let gemini_ok = !assessment.ai_studio_restricted;
        unlocked_map.insert("gemini_aistudio".to_string(), gemini_ok);
        unlocked_map.insert("gemini".to_string(), gemini_ok);
    }

    let detail = if assessment.reasons.is_empty() {
        Some(format!(
            "google_clean={}, google_risk_mismatch={}, cf_loc={}, yt_gl={}",
            assessment.google_clean,
            assessment.google_risk_mismatch,
            assessment.cf_loc.as_deref().unwrap_or("NONE"),
            assessment.yt_gl.as_deref().unwrap_or("NONE"),
        ))
    } else {
        Some(format!(
            "google_clean={}, google_risk_mismatch={}, reasons=[{}]",
            assessment.google_clean,
            assessment.google_risk_mismatch,
            assessment.reasons.join("; ")
        ))
    };

    ProbeResultRecord {
        node_id: node_id.to_string(),
        probe_id: def.id.clone(),
        tested_at: now_rfc3339(),
        ok: assessment.google_clean,
        latency_ms: google_ms,
        cf_loc: assessment.cf_loc,
        yt_gl: assessment.yt_gl,
        google_clean: Some(assessment.google_clean),
        unlocked_map,
        detail,
        ..Default::default()
    }
}

// ============================================================================
// L1: Custom Site / AI Service Regex Unlock Probe
// ============================================================================

/// Infer a canonical unlocked-site map key for a probe definition (e.g. `"chatgpt"`, `"claude"`, `"windsurf"`).
pub fn infer_unlock_site_key(def: &ProbeDefinition) -> String {
    let lower_id = def.id.trim().to_ascii_lowercase();
    if let Some(rest) = lower_id.strip_prefix("builtin_unlock_") {
        if !rest.is_empty() {
            return rest.to_string();
        }
    }
    if let Some(rest) = lower_id.strip_prefix("unlock_") {
        if !rest.is_empty() {
            return rest.to_string();
        }
    }

    if let Ok(parsed) = Url::parse(def.target_url.trim()) {
        if let Some(host) = parsed.host_str() {
            let h = host.to_ascii_lowercase();
            if h.contains("chatgpt.com") || h.contains("openai.com") {
                return "chatgpt".to_string();
            }
            if h.contains("claude.ai") || h.contains("anthropic.com") {
                return "claude".to_string();
            }
            if h.contains("windsurf.com")
                || h.contains("codeium.com")
                || h.contains("codeiumdata.com")
                || h.contains("exafunction.com")
            {
                return "windsurf".to_string();
            }
            if h.contains("devin.ai") || h.contains("cognition.ai") {
                return "devin".to_string();
            }
            if h.contains("gemini.google.com")
                || h.contains("aistudio.google.com")
                || h.contains("generativelanguage.googleapis.com")
            {
                return "gemini".to_string();
            }
        }
    }

    if !lower_id.is_empty() {
        lower_id
    } else {
        "custom_unlock".to_string()
    }
}

fn is_ai_trace_country_blocked(loc: &str) -> bool {
    AI_TRACE_BLOCKED_COUNTRIES
        .iter()
        .any(|code| loc.eq_ignore_ascii_case(code))
}

const CLAUDE_GEO_BLOCK_MARKERS: &[&str] = &[
    "not available in your country",
    "not available in your region",
    "country is not supported",
    "region is not supported",
    "unsupported_country",
    "unsupported_region",
    "unavailable in your country",
];

fn evaluate_claude_semantic_unlock(
    trace_loc: Option<&str>,
    api_status: Option<u16>,
    api_body: Option<&str>,
) -> (bool, String) {
    let normalized_loc = trace_loc.and_then(normalize_country_code);
    let trace_blocked = normalized_loc
        .as_deref()
        .is_some_and(is_ai_trace_country_blocked);

    let (api_ok, api_reason) = match api_status {
        Some(status) => {
            let body_lower = api_body.unwrap_or("").to_ascii_lowercase();
            let geo_blocked = CLAUDE_GEO_BLOCK_MARKERS
                .iter()
                .any(|marker| body_lower.contains(marker));
            if matches!(status, 403 | 451) || geo_blocked {
                (
                    false,
                    format!("blocked(status={status},geo={geo_blocked})"),
                )
            } else if matches!(status, 401 | 400) {
                (true, format!("ok(status={status})"))
            } else {
                (false, format!("unexpected_status({status})"))
            }
        }
        None => (false, "request_failed".to_string()),
    };

    let unlocked = !trace_blocked && api_ok;
    let detail = format!(
        "semantic_claude: unlocked={unlocked}, trace_loc={}, trace_blocked={trace_blocked}, api={api_reason}",
        normalized_loc.as_deref().unwrap_or("NONE"),
    );
    (unlocked, detail)
}

const CHATGPT_AB_BLOCK_MARKERS: &[&str] = &[
    "unsupported_country_region_territory",
    "unsupported_country",
    "not available in your country",
    "not available in your region",
    "just a moment",
    "attention required",
    "cf-challenge",
    "challenge-platform",
    "enable javascript and cookies",
    "sorry, you have been blocked",
];

#[allow(dead_code)]
fn evaluate_chatgpt_semantic_unlock(
    trace_loc: Option<&str>,
    api_status: Option<u16>,
    api_body: Option<&str>,
) -> (bool, String) {
    evaluate_chatgpt_semantic_unlock_with_ab(trace_loc, api_status, api_body, Some(200), None)
}

fn evaluate_chatgpt_semantic_unlock_with_ab(
    trace_loc: Option<&str>,
    api_status: Option<u16>,
    api_body: Option<&str>,
    ab_status: Option<u16>,
    ab_body: Option<&str>,
) -> (bool, String) {
    let normalized_loc = trace_loc.and_then(normalize_country_code);
    let trace_blocked = normalized_loc
        .as_deref()
        .is_some_and(is_ai_trace_country_blocked);

    let (api_ok, api_reason) = match api_status {
        Some(status) => {
            let body_lower = api_body.unwrap_or("").to_ascii_lowercase();
            let geo_blocked = body_lower.contains("unsupported_country_region_territory")
                || body_lower.contains("unsupported_country");
            if matches!(status, 403 | 451) || geo_blocked {
                (
                    false,
                    format!("blocked(status={status},geo={geo_blocked})"),
                )
            } else if status == 401 {
                (true, "ok(status=401)".to_string())
            } else {
                (false, format!("unexpected_status({status})"))
            }
        }
        None => (false, "request_failed".to_string()),
    };

    let (ab_ok, ab_reason) = match ab_status {
        Some(status) => {
            let body_lower = ab_body.unwrap_or("").to_ascii_lowercase();
            let geo_blocked = CHATGPT_AB_BLOCK_MARKERS
                .iter()
                .any(|marker| body_lower.contains(marker));
            if status == 451 || geo_blocked {
                (
                    false,
                    format!("blocked(status={status},geo={geo_blocked})"),
                )
            } else if status == 429 {
                (false, "rate_limited(status=429)".to_string())
            } else if status >= 500 {
                (false, format!("server_error(status={status})"))
            } else if (200..500).contains(&status) {
                (true, format!("ok(status={status})"))
            } else {
                (false, format!("unexpected_status({status})"))
            }
        }
        None => (false, "request_failed".to_string()),
    };

    let unlocked = !trace_blocked && api_ok && ab_ok;
    let detail = format!(
        "semantic_chatgpt: unlocked={unlocked}, trace_loc={}, trace_blocked={trace_blocked}, api={api_reason}, ab={ab_reason}",
        normalized_loc.as_deref().unwrap_or("NONE"),
    );
    (unlocked, detail)
}

fn evaluate_gemini_semantic_unlock(
    api_status: Option<u16>,
    api_body: Option<&str>,
    aistudio_status: Option<u16>,
    aistudio_location: Option<&str>,
    aistudio_body: Option<&str>,
) -> (bool, String) {
    let aistudio_blocked = aistudio_status.is_some_and(|s| matches!(s, 403 | 451))
        || aistudio_location.is_some_and(is_ai_studio_restricted_location)
        || aistudio_body.is_some_and(|body| {
            let lower = body.to_ascii_lowercase();
            AI_STUDIO_GEO_BLOCK_MARKERS
                .iter()
                .any(|marker| lower.contains(marker))
        });

    let (api_ok, api_reason) = match api_status {
        Some(status) => {
            let body = api_body.unwrap_or("");
            let body_lower = body.to_ascii_lowercase();
            let geo_blocked = status == 451
                || body_lower.contains("user location is not supported")
                || body_lower.contains("failed_precondition")
                || body_lower.contains("location is not supported");
            let key_invalid = body.contains("API_KEY_INVALID")
                || body_lower.contains("api key not valid");

            if geo_blocked {
                (false, format!("geo_blocked(status={status})"))
            } else if key_invalid {
                (true, format!("ok_api_key_invalid(status={status})"))
            } else {
                (false, format!("unexpected(status={status})"))
            }
        }
        None => (false, "request_failed".to_string()),
    };

    let unlocked = api_ok && !aistudio_blocked;
    let detail = format!(
        "semantic_gemini: unlocked={unlocked}, api={api_reason}, aistudio_blocked={aistudio_blocked}"
    );
    (unlocked, detail)
}

/// Aggregated exit-IP purity / risk intelligence collected from dual credential-free sources
/// (`api.ipquery.io` + `ip-api.com`) strictly through the caller's proxied HTTP client.
/// Never stores plaintext exit IP addresses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpPuritySignals {
    pub country_code: Option<String>,
    pub ip_clean: Option<bool>,
    pub ip_risk_level: String, // "clean" | "datacenter" | "proxy_risk" | "unknown"
    pub ip_asn: Option<String>,
    pub ip_risk_flags: Option<String>,
    pub risk_score: Option<u32>,
    pub sources_used: Vec<&'static str>,
}

/// Captured response signals from `POST https://server.codeium.com/.../GetChatMessage`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WindsurfApiResponseSignals {
    pub status: Option<u16>,
    pub via_header: Option<String>,
    pub has_accept_post: bool,
    pub content_type: Option<String>,
    pub body: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct IpQuerySourceData {
    country_code: Option<String>,
    asn: Option<String>,
    is_proxy: Option<bool>,
    is_vpn: Option<bool>,
    is_tor: Option<bool>,
    is_datacenter: Option<bool>,
    risk_score: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct IpApiSourceData {
    country_code: Option<String>,
    asn: Option<String>,
    proxy: Option<bool>,
    hosting: Option<bool>,
}

const WINDSURF_BLOCK_MARKERS: &[&str] = &[
    "just a moment",
    "attention required",
    "cf-challenge",
    "challenge-platform",
    "enable javascript and cookies",
    "sorry, you have been blocked",
    "not available in your country",
    "not available in your region",
    "unsupported_country",
    "unsupported_region",
    "access denied",
];

fn sanitize_asn_text(raw: &str) -> Option<String> {
    let cleaned_tokens: Vec<String> = raw
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .split_whitespace()
        .filter_map(|tok| {
            let trimmed = tok.trim_matches(|c: char| matches!(c, '[' | ']' | '(' | ')' | ',' | ';' | ':'));
            if trimmed.parse::<std::net::IpAddr>().is_ok() {
                None
            } else {
                Some(tok.to_string())
            }
        })
        .collect();
    let cleaned = cleaned_tokens.join(" ");
    if cleaned.is_empty() {
        return None;
    }
    Some(cleaned)
}

fn starts_with_ascii_as(s: &str) -> bool {
    s.as_bytes()
        .get(..2)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"as"))
}

fn normalize_asn_prefix(raw: &str) -> String {
    let mut parts = raw.splitn(2, ' ');
    let first = parts.next().unwrap_or("");
    let rest = parts.next().map(str::trim).unwrap_or("");

    let mut stripped = first;
    while starts_with_ascii_as(stripped) {
        let tail = &stripped[2..];
        if !tail.is_empty()
            && (tail.bytes().all(|b| b.is_ascii_digit()) || starts_with_ascii_as(tail))
        {
            stripped = tail;
        } else {
            break;
        }
    }

    let norm_first = if !stripped.is_empty() && stripped.bytes().all(|b| b.is_ascii_digit()) {
        format!("AS{stripped}")
    } else {
        first.to_string()
    };

    if rest.is_empty() {
        norm_first
    } else {
        format!("{norm_first} {rest}")
    }
}

fn format_asn_label(asn_raw: Option<&str>, org_raw: Option<&str>) -> Option<String> {
    let asn_clean = asn_raw.and_then(sanitize_asn_text).map(|s| normalize_asn_prefix(&s));
    let org_clean = org_raw.and_then(sanitize_asn_text);

    match (asn_clean, org_clean) {
        (Some(asn), Some(org)) => {
            let asn_lower = asn.to_ascii_lowercase();
            let org_lower = org.to_ascii_lowercase();
            if asn_lower.contains(&org_lower) {
                Some(asn)
            } else if org_lower.starts_with(&asn_lower) {
                Some(normalize_asn_prefix(&org))
            } else {
                Some(format!("{asn} {org}"))
            }
        }
        (Some(asn), None) => Some(asn),
        (None, Some(org)) => Some(org),
        (None, None) => None,
    }
}

fn parse_ipquery_json(status: u16, body: &str) -> Option<IpQuerySourceData> {
    if status != 200 {
        return None;
    }
    let val: serde_json::Value = serde_json::from_str(body.trim()).ok()?;
    let risk = val.get("risk").and_then(serde_json::Value::as_object)?;

    let is_proxy = risk.get("is_proxy").and_then(serde_json::Value::as_bool);
    let is_vpn = risk.get("is_vpn").and_then(serde_json::Value::as_bool);
    let is_tor = risk.get("is_tor").and_then(serde_json::Value::as_bool);
    let is_datacenter = risk.get("is_datacenter").and_then(serde_json::Value::as_bool);
    let risk_score = risk.get("risk_score").and_then(|v| {
        v.as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .or_else(|| {
                v.as_f64()
                    .filter(|f| f.is_finite() && *f >= 0.0)
                    .map(|f| f.round() as u32)
            })
    });

    // Reject empty/degraded `risk: {}` objects so missing fields are NEVER mistaken for `false`.
    if is_proxy.is_none()
        && is_vpn.is_none()
        && is_tor.is_none()
        && is_datacenter.is_none()
        && risk_score.is_none()
    {
        return None;
    }

    let country_code = val
        .get("location")
        .and_then(|l| l.get("country_code"))
        .and_then(serde_json::Value::as_str)
        .and_then(normalize_country_code);
    let isp_obj = val.get("isp");
    let asn_raw = isp_obj
        .and_then(|i| i.get("asn"))
        .and_then(serde_json::Value::as_str);
    let org_raw = isp_obj
        .and_then(|i| {
            i.get("org")
                .and_then(serde_json::Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .or_else(|| i.get("isp").and_then(serde_json::Value::as_str))
        });

    Some(IpQuerySourceData {
        country_code,
        asn: format_asn_label(asn_raw, org_raw),
        is_proxy,
        is_vpn,
        is_tor,
        is_datacenter,
        risk_score,
    })
}

fn parse_ipapi_json(status: u16, body: &str) -> Option<IpApiSourceData> {
    if status != 200 {
        return None;
    }
    let val: serde_json::Value = serde_json::from_str(body.trim()).ok()?;
    let status_ok = val
        .get("status")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|s| s.eq_ignore_ascii_case("success"));
    if !status_ok {
        return None;
    }

    let proxy = val.get("proxy").and_then(serde_json::Value::as_bool);
    let hosting = val.get("hosting").and_then(serde_json::Value::as_bool);
    if proxy.is_none() && hosting.is_none() {
        return None;
    }

    let country_code = val
        .get("countryCode")
        .and_then(serde_json::Value::as_str)
        .and_then(normalize_country_code);
    let as_raw = val.get("as").and_then(serde_json::Value::as_str);
    let org_raw = val
        .get("org")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .or_else(|| val.get("isp").and_then(serde_json::Value::as_str));

    Some(IpApiSourceData {
        country_code,
        asn: format_asn_label(as_raw, org_raw),
        proxy,
        hosting,
    })
}

fn merge_ip_purity_signals(
    ipq: Option<&IpQuerySourceData>,
    ipapi: Option<&IpApiSourceData>,
) -> IpPuritySignals {
    let mut sources_used = Vec::new();
    if ipq.is_some() {
        sources_used.push("ipquery");
    }
    if ipapi.is_some() {
        sources_used.push("ip-api");
    }

    if sources_used.is_empty() {
        return IpPuritySignals {
            country_code: None,
            ip_clean: None,
            ip_risk_level: "unknown".to_string(),
            ip_asn: None,
            ip_risk_flags: None,
            risk_score: None,
            sources_used,
        };
    }

    let ipq_cc = ipq.and_then(|d| d.country_code.as_deref());
    let ipapi_cc = ipapi.and_then(|d| d.country_code.as_deref());
    // Conservative union for geo-blocking: if either source flags a blocked country (e.g. HK/CN
    // on broadcast IPs), keep the blocked country code so geo_blocked is never masked.
    let country_code = if let Some(cc) = ipq_cc.filter(|c| is_ai_trace_country_blocked(c)) {
        Some(cc.to_string())
    } else if let Some(cc) = ipapi_cc.filter(|c| is_ai_trace_country_blocked(c)) {
        Some(cc.to_string())
    } else {
        ipq_cc.or(ipapi_cc).map(ToString::to_string)
    };
    let ip_asn = ipq
        .and_then(|d| d.asn.clone())
        .or_else(|| ipapi.and_then(|d| d.asn.clone()));
    let risk_score = ipq.and_then(|d| d.risk_score);

    let is_proxy_flag =
        ipapi.and_then(|d| d.proxy) == Some(true) || ipq.and_then(|d| d.is_proxy) == Some(true);
    let is_tor_flag = ipq.and_then(|d| d.is_tor) == Some(true);
    let is_vpn_flag = ipq.and_then(|d| d.is_vpn) == Some(true);
    let is_hosting_flag = ipq.and_then(|d| d.is_datacenter) == Some(true)
        || ipapi.and_then(|d| d.hosting) == Some(true);

    let is_proxy_risk = is_proxy_flag || is_tor_flag || risk_score.is_some_and(|s| s >= 80);
    let is_datacenter = is_hosting_flag || is_vpn_flag;

    let mut flags: Vec<String> = Vec::new();
    if is_proxy_flag {
        flags.push("proxy".to_string());
    }
    if is_tor_flag {
        flags.push("tor".to_string());
    }
    if is_vpn_flag {
        flags.push("vpn".to_string());
    }
    if is_hosting_flag {
        flags.push("datacenter".to_string());
    }
    let is_medium_risk_score = risk_score.is_some_and(|s| (50..80).contains(&s));
    if let Some(score) = risk_score {
        if score >= 50 {
            flags.push(format!("risk={score}"));
        }
    }
    let ip_risk_flags = if flags.is_empty() {
        None
    } else {
        Some(flags.join(","))
    };

    let any_proxy_confirmed_false = ipq.is_some_and(|d| d.is_proxy == Some(false))
        || ipapi.is_some_and(|d| d.proxy == Some(false));
    let any_dc_confirmed_false = ipq.is_some_and(|d| d.is_datacenter == Some(false))
        || ipapi.is_some_and(|d| d.hosting == Some(false));

    let (ip_risk_level, ip_clean) = if is_proxy_risk {
        ("proxy_risk".to_string(), Some(false))
    } else if is_datacenter || is_medium_risk_score {
        ("datacenter".to_string(), Some(false))
    } else if any_proxy_confirmed_false && any_dc_confirmed_false {
        ("clean".to_string(), Some(true))
    } else {
        ("unknown".to_string(), None)
    };

    IpPuritySignals {
        country_code,
        ip_clean,
        ip_risk_level,
        ip_asn,
        ip_risk_flags,
        risk_score,
        sources_used,
    }
}

/// Query dual credential-free IP risk sources (`api.ipquery.io` + `ip-api.com`) concurrently
/// within a strict 4-second overall budget through the caller's proxied `client`.
pub async fn query_ip_purity_signals(client: &reqwest::Client) -> IpPuritySignals {
    let work = async {
        let ipq_fut = async {
            let resp = client
                .get(IPQUERY_JSON_URL)
                .timeout(Duration::from_millis(3500))
                .send()
                .await
                .ok()?;
            let status = resp.status().as_u16();
            let bytes = drain_capped_body(resp, 32 * 1024).await.ok()?;
            let body = String::from_utf8_lossy(&bytes);
            parse_ipquery_json(status, &body)
        };
        let ipapi_fut = async {
            let resp = client
                .get(IPAPI_JSON_URL)
                .timeout(Duration::from_millis(3000))
                .send()
                .await
                .ok()?;
            let status = resp.status().as_u16();
            let bytes = drain_capped_body(resp, 32 * 1024).await.ok()?;
            let body = String::from_utf8_lossy(&bytes);
            parse_ipapi_json(status, &body)
        };
        let (ipq, ipapi) = tokio::join!(ipq_fut, ipapi_fut);
        merge_ip_purity_signals(ipq.as_ref(), ipapi.as_ref())
    };

    match tokio::time::timeout(Duration::from_secs(4), work).await {
        Ok(signals) => signals,
        Err(_) => IpPuritySignals {
            ip_risk_level: "unknown".to_string(),
            ..Default::default()
        },
    }
}

/// Pure semantic evaluator for `builtin_unlock_windsurf` combining Codeium ConnectRPC gateway
/// reachability with dual-source IP purity signals.
pub fn evaluate_windsurf_semantic_unlock(
    api: &WindsurfApiResponseSignals,
    ip: &IpPuritySignals,
) -> (bool, String) {
    let country_code = ip.country_code.as_deref().and_then(normalize_country_code);
    let geo_blocked = country_code
        .as_deref()
        .is_some_and(is_ai_trace_country_blocked);

    let (api_ok, api_reason) = match api.status {
        Some(status) => {
            let body_lower = api.body.as_deref().unwrap_or("").to_ascii_lowercase();
            let marker_blocked = WINDSURF_BLOCK_MARKERS
                .iter()
                .any(|m| body_lower.contains(m));
            if matches!(status, 403 | 429 | 451) || marker_blocked {
                (
                    false,
                    format!("blocked(status={status},marker={marker_blocked})"),
                )
            } else if status >= 500 {
                (false, format!("server_error(status={status})"))
            } else if matches!(status, 415 | 400 | 401 | 404) {
                let has_google_via = api
                    .via_header
                    .as_deref()
                    .is_some_and(|v| v.to_ascii_lowercase().contains("google"));
                let has_structured_api_ct = api.content_type.as_deref().is_some_and(|ct| {
                    let lower = ct.to_ascii_lowercase();
                    lower.contains("json") || lower.contains("grpc") || lower.contains("connect")
                });
                let has_plain_ct = api
                    .content_type
                    .as_deref()
                    .is_some_and(|ct| ct.to_ascii_lowercase().contains("text/plain"));
                let gateway_ok = has_google_via
                    || api.has_accept_post
                    || has_structured_api_ct
                    || (status == 415 && has_plain_ct);
                if gateway_ok {
                    (true, format!("ok(status={status})"))
                } else {
                    (false, format!("missing_gateway_signature(status={status})"))
                }
            } else {
                (false, format!("unexpected_status({status})"))
            }
        }
        None => (false, "request_failed".to_string()),
    };

    let risk_level = if ip.ip_risk_level.trim().is_empty() {
        "unknown"
    } else {
        ip.ip_risk_level.as_str()
    };
    let is_proxy_risk = risk_level == "proxy_risk";
    let unlocked = api_ok && !geo_blocked && !is_proxy_risk;

    let reason = if geo_blocked {
        "geo_blocked"
    } else if !api_ok {
        "api_unreachable_or_blocked"
    } else if is_proxy_risk {
        "high_risk_proxy_ip"
    } else if risk_level == "datacenter" {
        "ok_datacenter_advisory"
    } else if risk_level == "clean" {
        "ok_clean"
    } else {
        "ok_ip_risk_unavailable"
    };

    let flags_display = ip.ip_risk_flags.as_deref().unwrap_or("");
    let asn_display = ip.ip_asn.as_deref().unwrap_or("NONE");
    let cc_display = country_code.as_deref().unwrap_or("NONE");

    let detail = format!(
        "semantic_windsurf: unlocked={unlocked}, reason={reason}, api={api_reason}, ip_risk={risk_level}, flags=[{flags_display}], asn={asn_display}, cc={cc_display}"
    );
    (unlocked, detail)
}

async fn run_builtin_ai_semantic_unlock_probe(
    client: &reqwest::Client,
    node_id: &str,
    def: &ProbeDefinition,
    site_key: &str,
) -> ProbeResultRecord {
    let timeout = Duration::from_millis(def.timeout_ms.max(500));

    let (unlocked, latency_ms, detail, ip_purity): (
        bool,
        Option<f64>,
        String,
        Option<IpPuritySignals>,
    ) = match def.id.trim() {
        "builtin_unlock_claude" => {
            let trace_fut = async {
                let Ok(resp) = client.get(CLAUDE_TRACE_URL).timeout(timeout).send().await else {
                    return None;
                };
                let bytes = drain_capped_body(resp, 16 * 1024).await.unwrap_or_default();
                let body = String::from_utf8_lossy(&bytes);
                parse_cloudflare_trace_loc(&body)
            };
            let api_fut = async {
                let started = Instant::now();
                match client
                    .post(CLAUDE_API_MESSAGES_URL)
                    .header("anthropic-version", "2023-06-01")
                    .header(CONTENT_TYPE, "application/json")
                    .body("{}")
                    .timeout(timeout)
                    .send()
                    .await
                {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let elapsed_ms = round2(started.elapsed().as_secs_f64() * 1000.0);
                        let bytes = drain_capped_body(resp, 32 * 1024).await.unwrap_or_default();
                        let body = String::from_utf8_lossy(&bytes).into_owned();
                        (Some(status), Some(body), Some(elapsed_ms))
                    }
                    Err(_) => (None, None, None),
                }
            };

            let (trace_loc, (api_status, api_body, api_ms)) = tokio::join!(trace_fut, api_fut);
            let (ok, detail) = evaluate_claude_semantic_unlock(
                trace_loc.as_deref(),
                api_status,
                api_body.as_deref(),
            );
            (ok, api_ms, detail, None)
        }
        "builtin_unlock_chatgpt" => {
            let trace_fut = async {
                let Ok(resp) = client.get(CHATGPT_TRACE_URL).timeout(timeout).send().await else {
                    return None;
                };
                let bytes = drain_capped_body(resp, 16 * 1024).await.unwrap_or_default();
                let body = String::from_utf8_lossy(&bytes);
                parse_cloudflare_trace_loc(&body)
            };
            let api_fut = async {
                let started = Instant::now();
                match client
                    .get(CHATGPT_API_MODELS_URL)
                    .timeout(timeout)
                    .send()
                    .await
                {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let elapsed_ms = round2(started.elapsed().as_secs_f64() * 1000.0);
                        let bytes = drain_capped_body(resp, 32 * 1024).await.unwrap_or_default();
                        let body = String::from_utf8_lossy(&bytes).into_owned();
                        (Some(status), Some(body), Some(elapsed_ms))
                    }
                    Err(_) => (None, None, None),
                }
            };
            let ab_fut = async {
                match client.get(CHATGPT_AB_URL).timeout(timeout).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let bytes = drain_capped_body(resp, 16 * 1024).await.unwrap_or_default();
                        let body = String::from_utf8_lossy(&bytes).into_owned();
                        (Some(status), Some(body))
                    }
                    Err(_) => (None, None),
                }
            };

            let (trace_loc, (api_status, api_body, api_ms), (ab_status, ab_body)) =
                tokio::join!(trace_fut, api_fut, ab_fut);
            let (ok, detail) = evaluate_chatgpt_semantic_unlock_with_ab(
                trace_loc.as_deref(),
                api_status,
                api_body.as_deref(),
                ab_status,
                ab_body.as_deref(),
            );
            (ok, api_ms, detail, None)
        }
        "builtin_unlock_gemini" => {
            let api_fut = async {
                let started = Instant::now();
                match client
                    .get(GEMINI_API_MODELS_CHECK_URL)
                    .timeout(timeout)
                    .send()
                    .await
                {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let elapsed_ms = round2(started.elapsed().as_secs_f64() * 1000.0);
                        let bytes = drain_capped_body(resp, 32 * 1024).await.unwrap_or_default();
                        let body = String::from_utf8_lossy(&bytes).into_owned();
                        (Some(status), Some(body), Some(elapsed_ms))
                    }
                    Err(_) => (None, None, None),
                }
            };
            let aistudio_fut = async {
                let Ok(resp) = client
                    .get(DEFAULT_AI_STUDIO_URL)
                    .timeout(timeout)
                    .send()
                    .await
                else {
                    return (None, None, None);
                };
                let status = resp.status().as_u16();
                let loc_header = resp
                    .headers()
                    .get(LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .map(ToString::to_string);
                let final_url = resp.url().to_string();
                let redirect_loc = loc_header.or_else(|| {
                    if is_ai_studio_restricted_location(&final_url) {
                        Some(final_url)
                    } else {
                        None
                    }
                });
                let bytes = drain_capped_body(resp, 32 * 1024).await.unwrap_or_default();
                let body = String::from_utf8_lossy(&bytes).into_owned();
                (Some(status), redirect_loc, Some(body))
            };

            let ((api_status, api_body, api_ms), (ai_status, ai_redirect, ai_body)) =
                tokio::join!(api_fut, aistudio_fut);
            let (ok, detail) = evaluate_gemini_semantic_unlock(
                api_status,
                api_body.as_deref(),
                ai_status,
                ai_redirect.as_deref(),
                ai_body.as_deref(),
            );
            (ok, api_ms, detail, None)
        }
        "builtin_unlock_windsurf" => {
            let api_fut = async {
                let started = Instant::now();
                match client
                    .post(WINDSURF_API_CHAT_URL)
                    .header(CONTENT_TYPE, "application/json")
                    .body("{}")
                    .timeout(timeout)
                    .send()
                    .await
                {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let elapsed_ms = round2(started.elapsed().as_secs_f64() * 1000.0);
                        let via_header = resp
                            .headers()
                            .get("via")
                            .and_then(|v| v.to_str().ok())
                            .map(ToString::to_string);
                        let has_accept_post = resp.headers().contains_key("accept-post");
                        let content_type = resp
                            .headers()
                            .get(CONTENT_TYPE)
                            .and_then(|v| v.to_str().ok())
                            .map(ToString::to_string);
                        let bytes = drain_capped_body(resp, 32 * 1024).await.unwrap_or_default();
                        let body = String::from_utf8_lossy(&bytes).into_owned();
                        (
                            WindsurfApiResponseSignals {
                                status: Some(status),
                                via_header,
                                has_accept_post,
                                content_type,
                                body: Some(body),
                            },
                            Some(elapsed_ms),
                        )
                    }
                    Err(_) => (WindsurfApiResponseSignals::default(), None),
                }
            };
            let ip_fut = query_ip_purity_signals(client);
            let ((api_signals, api_ms), ip_signals) = tokio::join!(api_fut, ip_fut);
            let (ok, detail) = evaluate_windsurf_semantic_unlock(&api_signals, &ip_signals);
            (ok, api_ms, detail, Some(ip_signals))
        }
        _ => (
            false,
            None,
            format!("unsupported semantic probe {}", def.id),
            None,
        ),
    };

    let mut unlocked_map = HashMap::new();
    unlocked_map.insert(site_key.to_string(), unlocked);
    if def.id != site_key && !def.id.is_empty() {
        unlocked_map.insert(def.id.clone(), unlocked);
    }

    let (ip_clean, ip_risk_level, ip_asn, ip_risk_flags) = match ip_purity {
        Some(sig) => {
            let level = if sig.ip_risk_level.trim().is_empty() {
                "unknown".to_string()
            } else {
                sig.ip_risk_level
            };
            (sig.ip_clean, Some(level), sig.ip_asn, sig.ip_risk_flags)
        }
        None => (None, None, None, None),
    };

    ProbeResultRecord {
        node_id: node_id.to_string(),
        probe_id: def.id.clone(),
        tested_at: now_rfc3339(),
        ok: unlocked,
        latency_ms,
        unlocked_map,
        detail: Some(detail),
        ip_clean,
        ip_risk_level,
        ip_asn,
        ip_risk_flags,
        ..Default::default()
    }
}

/// Execute an L1 arbitrary site unlock probe with configurable URL, HTTP method,
/// expected status code, and optional response-body regular expression.
/// For built-in AI unlock probes (`builtin_unlock_claude`, `builtin_unlock_chatgpt`,
/// `builtin_unlock_gemini`, `builtin_unlock_windsurf`) without custom regex/status targeting
/// non-loopback endpoints, dispatches to credential-free semantic unlock detection.
pub async fn run_unlock_regex_probe(
    client: &reqwest::Client,
    node_id: &str,
    def: &ProbeDefinition,
) -> ProbeResultRecord {
    let site_key = infer_unlock_site_key(def);

    let has_body_regex = def
        .body_regex
        .as_deref()
        .is_some_and(|pat| !pat.trim().is_empty());
    if !has_body_regex
        && def.expected_status.is_none()
        && matches!(
            def.id.trim(),
            "builtin_unlock_claude"
                | "builtin_unlock_chatgpt"
                | "builtin_unlock_gemini"
                | "builtin_unlock_windsurf"
        )
        && !is_loopback_url(&def.target_url)
    {
        return run_builtin_ai_semantic_unlock_probe(client, node_id, def, &site_key).await;
    }
    let method = match parse_http_method(&def.method) {
        Ok(m) => m,
        Err(err) => {
            let mut rec = failed_record(node_id, &def.id, format!("invalid method: {err}"));
            rec.unlocked_map.insert(site_key, false);
            return rec;
        }
    };

    let compiled_regex = match def.body_regex.as_deref() {
        Some(pat) if !pat.is_empty() => match Regex::new(pat) {
            Ok(re) => Some(re),
            Err(err) => {
                let mut rec =
                    failed_record(node_id, &def.id, format!("invalid body_regex: {err}"));
                rec.unlocked_map.insert(site_key, false);
                return rec;
            }
        },
        _ => None,
    };

    let timeout = Duration::from_millis(def.timeout_ms.max(200));
    let started = Instant::now();

    match client
        .request(method, def.target_url.trim())
        .timeout(timeout)
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let elapsed_ms = round2(started.elapsed().as_secs_f64() * 1000.0);
            let bytes = match drain_capped_body(resp, MAX_INSPECT_BODY_BYTES).await {
                Ok(b) => b,
                Err(err) => {
                    let mut rec = failed_record(
                        node_id,
                        &def.id,
                        format!("failed to read unlock response body: {err}"),
                    );
                    rec.latency_ms = Some(elapsed_ms);
                    rec.unlocked_map.insert(site_key, false);
                    return rec;
                }
            };

            let status_ok = match def.expected_status {
                Some(exp) => status == exp,
                None => (200..400).contains(&status),
            };
            let body_text = String::from_utf8_lossy(&bytes);
            let regex_ok = match &compiled_regex {
                Some(re) => re.is_match(&body_text),
                None => true,
            };

            let unlocked = status_ok && regex_ok;
            let mut unlocked_map = HashMap::new();
            unlocked_map.insert(site_key.clone(), unlocked);
            if def.id != site_key && !def.id.is_empty() {
                unlocked_map.insert(def.id.clone(), unlocked);
            }

            let detail = Some(format!(
                "site={site_key}, status={status}, status_ok={status_ok}, regex_ok={regex_ok}"
            ));

            ProbeResultRecord {
                node_id: node_id.to_string(),
                probe_id: def.id.clone(),
                tested_at: now_rfc3339(),
                ok: unlocked,
                latency_ms: Some(elapsed_ms),
                unlocked_map,
                detail,
                ..Default::default()
            }
        }
        Err(err) => {
            let mut rec = failed_record(node_id, &def.id, format!("request failed: {err}"));
            rec.unlocked_map.insert(site_key, false);
            rec
        }
    }
}

// ============================================================================
// L2: Custom Upload / Download Throughput + 512 KiB Fast-Fuse Blackhole Abort
// ============================================================================

/// Configuration for two-stage throughput probes with fast-fuse blackhole cutoff.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ThroughputProbeConfig {
    /// Stage-1 fast-fuse sample size in bytes (default: 512 KiB).
    pub fuse_bytes: usize,
    /// Minimum Mbps required during Stage-1 to avoid fast-fuse abort (default: 0.2 Mbps).
    pub fuse_min_mbps: f64,
    /// Hard cap on Stage-2 scaled payload bytes (default: 8 MiB).
    pub max_payload_bytes: usize,
}

impl Default for ThroughputProbeConfig {
    fn default() -> Self {
        Self {
            fuse_bytes: FAST_FUSE_PROBE_BYTES,
            fuse_min_mbps: FAST_FUSE_MIN_MBPS,
            max_payload_bytes: MAX_THROUGHPUT_PAYLOAD_BYTES,
        }
    }
}

/// Convert transferred bytes and elapsed duration into Megabits per second (Mbps).
pub fn compute_mbps(bytes: usize, elapsed: Duration) -> f64 {
    if bytes == 0 {
        return 0.0;
    }
    let secs = elapsed.as_secs_f64().max(1e-6);
    round2((bytes as f64 * 8.0) / (secs * 1_000_000.0))
}

/// Adjust the `bytes=<N>` query parameter on a download URL when present so Stage-1
/// truly downloads only 512 KiB before scaling up to `payload_bytes`.
pub fn build_download_stage_url(base_url: &str, stage_bytes: usize) -> String {
    let Ok(mut parsed) = Url::parse(base_url.trim()) else {
        return base_url.to_string();
    };
    let pairs: Vec<(String, String)> = parsed
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let has_bytes_param = pairs.iter().any(|(k, _)| k.eq_ignore_ascii_case("bytes"));
    if !has_bytes_param {
        return base_url.to_string();
    }

    {
        let mut qp = parsed.query_pairs_mut();
        qp.clear();
        for (k, v) in pairs {
            if k.eq_ignore_ascii_case("bytes") {
                qp.append_pair(&k, &stage_bytes.to_string());
            } else {
                qp.append_pair(&k, &v);
            }
        }
    }
    parsed.to_string()
}

/// Execute an L2 upload throughput probe with default 512 KiB fast-fuse config.
pub async fn run_upload_probe(
    client: &reqwest::Client,
    node_id: &str,
    def: &ProbeDefinition,
) -> ProbeResultRecord {
    run_upload_probe_with_config(client, node_id, def, &ThroughputProbeConfig::default()).await
}

/// Execute an L2 upload throughput probe with injectable fast-fuse thresholds.
pub async fn run_upload_probe_with_config(
    client: &reqwest::Client,
    node_id: &str,
    def: &ProbeDefinition,
    cfg: &ThroughputProbeConfig,
) -> ProbeResultRecord {
    let method = match parse_http_method(if def.method.trim().is_empty() {
        "POST"
    } else {
        &def.method
    }) {
        Ok(m) => m,
        Err(err) => {
            return failed_record(node_id, &def.id, format!("invalid upload method: {err}"));
        }
    };

    let max_cap = cfg.max_payload_bytes.clamp(1024, MAX_THROUGHPUT_PAYLOAD_BYTES);
    let target_bytes = def
        .payload_bytes
        .unwrap_or(DEFAULT_UPLOAD_PAYLOAD_BYTES)
        .clamp(1024, max_cap as u64) as usize;
    let fuse_bytes = cfg.fuse_bytes.clamp(1024, max_cap);
    let stage1_bytes = target_bytes.min(fuse_bytes);
    let timeout = Duration::from_millis(def.timeout_ms.max(200));

    // Stage 1: 512 KiB fast-fuse probe
    let (stage1_mbps, stage1_ms) = match execute_upload_transfer(
        client,
        method.clone(),
        def.target_url.trim(),
        stage1_bytes,
        def.expected_status,
        timeout,
    )
    .await
    {
        Ok(v) => v,
        Err(err) => {
            return failed_record(
                node_id,
                &def.id,
                format!("fast_fuse_upload_abort(stage1={stage1_bytes}B): {err}"),
            );
        }
    };

    if stage1_mbps < cfg.fuse_min_mbps {
        return ProbeResultRecord {
            node_id: node_id.to_string(),
            probe_id: def.id.clone(),
            tested_at: now_rfc3339(),
            ok: false,
            latency_ms: Some(stage1_ms),
            up_mbps: None,
            detail: Some(format!(
                "fast_fuse_triggered: stage1_bytes={stage1_bytes}, up_mbps={stage1_mbps:.2} < {:.2}",
                cfg.fuse_min_mbps
            )),
            ..Default::default()
        };
    }

    if target_bytes <= stage1_bytes {
        return ProbeResultRecord {
            node_id: node_id.to_string(),
            probe_id: def.id.clone(),
            tested_at: now_rfc3339(),
            ok: true,
            latency_ms: Some(stage1_ms),
            up_mbps: Some(stage1_mbps),
            detail: Some(format!(
                "stage1_complete: bytes={stage1_bytes}, up_mbps={stage1_mbps:.2}"
            )),
            ..Default::default()
        };
    }

    // Stage 2: scale up to configured payload_bytes (capped at 8 MiB)
    match execute_upload_transfer(
        client,
        method,
        def.target_url.trim(),
        target_bytes,
        def.expected_status,
        timeout,
    )
    .await
    {
        Ok((stage2_mbps, stage2_ms)) => ProbeResultRecord {
            node_id: node_id.to_string(),
            probe_id: def.id.clone(),
            tested_at: now_rfc3339(),
            ok: true,
            latency_ms: Some(stage2_ms),
            up_mbps: Some(stage2_mbps),
            detail: Some(format!(
                "scaled_upload_ok: stage1_mbps={stage1_mbps:.2}, stage2_bytes={target_bytes}, up_mbps={stage2_mbps:.2}"
            )),
            ..Default::default()
        },
        Err(err) => ProbeResultRecord {
            node_id: node_id.to_string(),
            probe_id: def.id.clone(),
            tested_at: now_rfc3339(),
            ok: false,
            latency_ms: Some(stage1_ms),
            up_mbps: None,
            detail: Some(format!(
                "stage2_upload_failed(bytes={target_bytes}, stage1_mbps={stage1_mbps:.2}): {err}"
            )),
            ..Default::default()
        },
    }
}

async fn execute_upload_transfer(
    client: &reqwest::Client,
    method: Method,
    url: &str,
    payload_bytes: usize,
    expected_status: Option<u16>,
    timeout: Duration,
) -> CatResult<(f64, f64)> {
    let payload = vec![b'C'; payload_bytes];
    let started = Instant::now();
    let resp = client
        .request(method, url)
        .timeout(timeout)
        .body(payload)
        .send()
        .await?;
    let status = resp.status().as_u16();
    let _ = drain_capped_body(resp, 16 * 1024).await;
    let elapsed = started.elapsed();

    let status_ok = match expected_status {
        Some(exp) => status == exp,
        None => (200..400).contains(&status),
    };
    if !status_ok {
        return Err(CatError::Process(format!(
            "unexpected upload HTTP status {status}"
        )));
    }

    let mbps = compute_mbps(payload_bytes, elapsed);
    let ms = round2(elapsed.as_secs_f64() * 1000.0);
    Ok((mbps, ms))
}

/// Execute an L2 download throughput probe with default 512 KiB fast-fuse config.
pub async fn run_download_probe(
    client: &reqwest::Client,
    node_id: &str,
    def: &ProbeDefinition,
) -> ProbeResultRecord {
    run_download_probe_with_config(client, node_id, def, &ThroughputProbeConfig::default()).await
}

/// Execute an L2 download throughput probe with injectable fast-fuse thresholds.
pub async fn run_download_probe_with_config(
    client: &reqwest::Client,
    node_id: &str,
    def: &ProbeDefinition,
    cfg: &ThroughputProbeConfig,
) -> ProbeResultRecord {
    let method = match parse_http_method(if def.method.trim().is_empty() {
        "GET"
    } else {
        &def.method
    }) {
        Ok(m) => m,
        Err(err) => {
            return failed_record(node_id, &def.id, format!("invalid download method: {err}"));
        }
    };

    let max_cap = cfg.max_payload_bytes.clamp(1024, MAX_THROUGHPUT_PAYLOAD_BYTES);
    let target_bytes = def
        .payload_bytes
        .unwrap_or(DEFAULT_DOWNLOAD_PAYLOAD_BYTES)
        .clamp(1024, max_cap as u64) as usize;
    let fuse_bytes = cfg.fuse_bytes.clamp(1024, max_cap);
    let stage1_bytes = target_bytes.min(fuse_bytes);
    let timeout = Duration::from_millis(def.timeout_ms.max(200));

    let stage1_url = build_download_stage_url(&def.target_url, stage1_bytes);
    let (stage1_read, stage1_mbps, stage1_ms) = match execute_download_transfer(
        client,
        method.clone(),
        &stage1_url,
        stage1_bytes,
        def.expected_status,
        timeout,
    )
    .await
    {
        Ok(v) => v,
        Err(err) => {
            return failed_record(
                node_id,
                &def.id,
                format!("fast_fuse_download_abort(stage1={stage1_bytes}B): {err}"),
            );
        }
    };

    if stage1_read == 0 || stage1_mbps < cfg.fuse_min_mbps {
        return ProbeResultRecord {
            node_id: node_id.to_string(),
            probe_id: def.id.clone(),
            tested_at: now_rfc3339(),
            ok: false,
            latency_ms: Some(stage1_ms),
            down_mbps: None,
            detail: Some(format!(
                "fast_fuse_triggered: stage1_read={stage1_read}, down_mbps={stage1_mbps:.2} < {:.2}",
                cfg.fuse_min_mbps
            )),
            ..Default::default()
        };
    }

    if target_bytes <= stage1_bytes {
        return ProbeResultRecord {
            node_id: node_id.to_string(),
            probe_id: def.id.clone(),
            tested_at: now_rfc3339(),
            ok: true,
            latency_ms: Some(stage1_ms),
            down_mbps: Some(stage1_mbps),
            detail: Some(format!(
                "stage1_complete: bytes={stage1_read}, down_mbps={stage1_mbps:.2}"
            )),
            ..Default::default()
        };
    }

    // Stage 2: scale up to target payload_bytes (capped at 8 MiB)
    let stage2_url = build_download_stage_url(&def.target_url, target_bytes);
    match execute_download_transfer(
        client,
        method,
        &stage2_url,
        target_bytes,
        def.expected_status,
        timeout,
    )
    .await
    {
        Ok((stage2_read, stage2_mbps, stage2_ms)) => ProbeResultRecord {
            node_id: node_id.to_string(),
            probe_id: def.id.clone(),
            tested_at: now_rfc3339(),
            ok: stage2_read > 0,
            latency_ms: Some(stage2_ms),
            down_mbps: if stage2_read > 0 {
                Some(stage2_mbps)
            } else {
                None
            },
            detail: Some(format!(
                "scaled_download_ok: stage1_mbps={stage1_mbps:.2}, stage2_read={stage2_read}, down_mbps={stage2_mbps:.2}"
            )),
            ..Default::default()
        },
        Err(err) => ProbeResultRecord {
            node_id: node_id.to_string(),
            probe_id: def.id.clone(),
            tested_at: now_rfc3339(),
            ok: false,
            latency_ms: Some(stage1_ms),
            down_mbps: None,
            detail: Some(format!(
                "stage2_download_failed(bytes={target_bytes}, stage1_mbps={stage1_mbps:.2}): {err}"
            )),
            ..Default::default()
        },
    }
}

async fn execute_download_transfer(
    client: &reqwest::Client,
    method: Method,
    url: &str,
    max_bytes: usize,
    expected_status: Option<u16>,
    timeout: Duration,
) -> CatResult<(usize, f64, f64)> {
    let started = Instant::now();
    let mut resp = client
        .request(method, url)
        .timeout(timeout)
        .send()
        .await?;
    let status = resp.status().as_u16();
    let status_ok = match expected_status {
        Some(exp) => status == exp,
        None => (200..400).contains(&status),
    };
    if !status_ok {
        return Err(CatError::Process(format!(
            "unexpected download HTTP status {status}"
        )));
    }

    let mut total_read = 0usize;
    while total_read < max_bytes {
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            return Err(CatError::Process(format!(
                "download timed out after {:.2}s ({total_read} bytes received)",
                elapsed.as_secs_f64()
            )));
        }
        let remaining = timeout.saturating_sub(elapsed);
        let chunk_res = tokio::time::timeout(remaining, resp.chunk()).await;
        match chunk_res {
            Ok(Ok(Some(chunk))) => {
                let take = chunk.len().min(max_bytes - total_read);
                total_read += take;
            }
            Ok(Ok(None)) => break,
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => {
                return Err(CatError::Process(format!(
                    "download stalled after {total_read} bytes"
                )));
            }
        }
    }

    let elapsed = started.elapsed();
    let mbps = compute_mbps(total_read, elapsed);
    let ms = round2(elapsed.as_secs_f64() * 1000.0);
    Ok((total_read, mbps, ms))
}

// ============================================================================
// L2: Silent Keep-Alive Blackhole Verification
// ============================================================================

/// Default `[20s, 40s, 60s]` silent Keep-Alive check schedule.
pub fn default_keepalive_intervals() -> Vec<Duration> {
    DEFAULT_KEEPALIVE_INTERVALS_MS
        .iter()
        .map(|&ms| Duration::from_millis(ms))
        .collect()
}

/// Verify that a reused HTTP/1.1 or HTTP/2 connection survives silent idle intervals
/// (default `[20s, 40s, 60s]`, injectable such as `[50ms, 100ms]` in unit tests) without
/// silently blackholing subsequent requests.
pub async fn run_keepalive_probe(
    client: &reqwest::Client,
    node_id: &str,
    def: &ProbeDefinition,
    silent_intervals: &[Duration],
) -> ProbeResultRecord {
    let intervals: Vec<Duration> = if silent_intervals.is_empty() {
        default_keepalive_intervals()
    } else {
        silent_intervals.to_vec()
    };

    let method = match parse_http_method(&def.method) {
        Ok(m) => m,
        Err(err) => {
            let mut rec =
                failed_record(node_id, &def.id, format!("invalid keepalive method: {err}"));
            rec.keepalive_60s_ok = Some(false);
            return rec;
        }
    };

    // Per-step HTTP request timeout bounded so silent blackhole hangs fail deterministically.
    let step_timeout = Duration::from_millis(def.timeout_ms.clamp(200, 10_000));
    let mut step_latencies: Vec<f64> = Vec::with_capacity(intervals.len() + 1);

    // Step 0: Warm up and establish the persistent connection in the pool.
    match execute_keepalive_ping(
        client,
        method.clone(),
        def.target_url.trim(),
        def.expected_status,
        step_timeout,
    )
    .await
    {
        Ok(ms) => step_latencies.push(ms),
        Err(err) => {
            return ProbeResultRecord {
                node_id: node_id.to_string(),
                probe_id: def.id.clone(),
                tested_at: now_rfc3339(),
                ok: false,
                keepalive_60s_ok: Some(false),
                detail: Some(format!("keepalive_warmup_failed: {err}")),
                ..Default::default()
            };
        }
    }

    // Subsequent steps: stay silent for each configured duration, then reuse the same client pool.
    let mut completed_ms: Vec<u64> = Vec::with_capacity(intervals.len());
    for (idx, interval) in intervals.iter().enumerate() {
        sleep(*interval).await;
        match execute_keepalive_ping(
            client,
            method.clone(),
            def.target_url.trim(),
            def.expected_status,
            step_timeout,
        )
        .await
        {
            Ok(ms) => {
                step_latencies.push(ms);
                completed_ms.push(interval.as_millis() as u64);
            }
            Err(err) => {
                let avg_ms = if step_latencies.is_empty() {
                    None
                } else {
                    Some(round2(
                        step_latencies.iter().sum::<f64>() / step_latencies.len() as f64,
                    ))
                };
                return ProbeResultRecord {
                    node_id: node_id.to_string(),
                    probe_id: def.id.clone(),
                    tested_at: now_rfc3339(),
                    ok: false,
                    latency_ms: avg_ms,
                    keepalive_60s_ok: Some(false),
                    detail: Some(format!(
                        "keepalive_blackhole_at_step={idx} (silent_ms={}): {err}",
                        interval.as_millis()
                    )),
                    ..Default::default()
                };
            }
        }
    }

    let avg_ms = round2(step_latencies.iter().sum::<f64>() / step_latencies.len() as f64);
    ProbeResultRecord {
        node_id: node_id.to_string(),
        probe_id: def.id.clone(),
        tested_at: now_rfc3339(),
        ok: true,
        latency_ms: Some(avg_ms),
        keepalive_60s_ok: Some(true),
        detail: Some(format!(
            "keepalive_ok: intervals_ms={completed_ms:?}, avg_ms={avg_ms:.2}"
        )),
        ..Default::default()
    }
}

async fn execute_keepalive_ping(
    client: &reqwest::Client,
    method: Method,
    url: &str,
    expected_status: Option<u16>,
    timeout: Duration,
) -> CatResult<f64> {
    let started = Instant::now();
    let resp = client
        .request(method, url)
        .timeout(timeout)
        .send()
        .await?;
    let status = resp.status().as_u16();
    // Always consume full body so reqwest returns the connection to the idle keep-alive pool.
    let _ = drain_capped_body(resp, 16 * 1024).await?;
    let elapsed_ms = round2(started.elapsed().as_secs_f64() * 1000.0);

    let status_ok = match expected_status {
        Some(exp) => status == exp,
        None => (200..400).contains(&status),
    };
    if !status_ok {
        return Err(CatError::Process(format!(
            "unexpected keepalive HTTP status {status}"
        )));
    }
    Ok(elapsed_ms)
}

// ============================================================================
// Internal Helpers
// ============================================================================

fn parse_http_method(raw: &str) -> CatResult<Method> {
    let trimmed = raw.trim().to_ascii_uppercase();
    if trimmed.is_empty() {
        return Ok(Method::GET);
    }
    Method::from_bytes(trimmed.as_bytes())
        .map_err(|e| CatError::Validation(format!("invalid HTTP method `{raw}`: {e}")))
}

async fn drain_capped_body(mut resp: reqwest::Response, max_bytes: usize) -> CatResult<Vec<u8>> {
    let mut out = Vec::new();
    if max_bytes == 0 {
        return Ok(out);
    }
    while let Some(chunk) = resp.chunk().await? {
        let remaining = max_bytes.saturating_sub(out.len());
        if remaining == 0 {
            break;
        }
        let take = chunk.len().min(remaining);
        out.extend_from_slice(&chunk[..take]);
        if out.len() >= max_bytes {
            break;
        }
    }
    Ok(out)
}

fn failed_record(node_id: &str, probe_id: &str, detail: String) -> ProbeResultRecord {
    ProbeResultRecord {
        node_id: node_id.to_string(),
        probe_id: probe_id.to_string(),
        tested_at: now_rfc3339(),
        ok: false,
        detail: Some(detail),
        ..Default::default()
    }
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

fn round2(val: f64) -> f64 {
    (val * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_stats_computes_average_adjacent_jitter_and_loss() {
        let stats = compute_latency_stats(&[Some(100.0), Some(130.0), Some(110.0)]);
        assert_eq!(stats.ok_count, 3);
        assert_eq!(stats.loss_pct, 0.0);
        assert_eq!(stats.latency_ms, Some(113.33));
        // |130-100| = 30, |110-130| = 20 -> mean jitter = 25.0
        assert_eq!(stats.jitter_ms, Some(25.0));

        let partial = compute_latency_stats(&[Some(80.0), None, Some(120.0)]);
        assert_eq!(partial.ok_count, 2);
        assert_eq!(partial.latency_ms, Some(100.0));
        assert_eq!(partial.jitter_ms, Some(40.0));
        assert_eq!(partial.loss_pct, 33.33);

        let total_loss = compute_latency_stats(&[None, None, None]);
        assert_eq!(total_loss.ok_count, 0);
        assert_eq!(total_loss.loss_pct, 100.0);
        assert!(total_loss.latency_ms.is_none());
    }

    #[test]
    fn google_cleanliness_uses_google_ground_truth_and_never_false_kills_cf_tw_yt_us() {
        // CF=TW while YT=US must stay google_clean=true with an advisory mismatch tag.
        let clean_mismatch = evaluate_google_cleanliness(&GoogleCleanSignals {
            google_status: Some(204),
            google_redirect_location: None,
            yt_gl: Some("US".to_string()),
            ai_studio_status: Some(200),
            ai_studio_redirect_location: None,
            ai_studio_body_snippet: Some("<html>AI Studio Ready</html>".to_string()),
            cf_loc: Some("TW".to_string()),
        });
        assert!(clean_mismatch.google_clean);
        assert!(clean_mismatch.google_risk_mismatch);
        assert_eq!(clean_mismatch.cf_loc.as_deref(), Some("TW"));
        assert_eq!(clean_mismatch.yt_gl.as_deref(), Some("US"));

        // Google 302 redirect to google.cn -> hard fail
        let cn_redirect = evaluate_google_cleanliness(&GoogleCleanSignals {
            google_status: Some(302),
            google_redirect_location: Some("https://www.google.cn/generate_204".to_string()),
            yt_gl: Some("US".to_string()),
            cf_loc: Some("US".to_string()),
            ..Default::default()
        });
        assert!(!cn_redirect.google_clean);
        assert!(!cn_redirect.google_risk_mismatch);

        // Google 302 redirect to /sorry/ captcha wall -> hard fail
        let sorry_redirect = evaluate_google_cleanliness(&GoogleCleanSignals {
            google_status: Some(204),
            google_redirect_location: Some(
                "https://www.google.com/sorry/index?continue=https://www.google.com/".to_string(),
            ),
            yt_gl: Some("US".to_string()),
            cf_loc: Some("US".to_string()),
            ..Default::default()
        });
        assert!(!sorry_redirect.google_clean);
        assert!(is_google_sorry_or_cn_location(
            "https://www.google.com/sorry/index?continue=https://www.google.com/"
        ));
        assert!(!is_google_sorry_or_cn_location("https://www.google.co.jp/"));

        // YouTube GL in {CN, HK} -> hard fail
        for restricted in ["CN", "HK"] {
            let dirty_yt = evaluate_google_cleanliness(&GoogleCleanSignals {
                google_status: Some(204),
                yt_gl: Some(restricted.to_string()),
                cf_loc: Some("SG".to_string()),
                ..Default::default()
            });
            assert!(!dirty_yt.google_clean);
            assert!(dirty_yt.google_risk_mismatch);
        }

        // AI Studio regional block in body -> hard fail
        let dirty_ai = evaluate_google_cleanliness(&GoogleCleanSignals {
            google_status: Some(204),
            yt_gl: Some("JP".to_string()),
            ai_studio_status: Some(200),
            ai_studio_body_snippet: Some(
                "Sorry, this service is not available in your country.".to_string(),
            ),
            cf_loc: Some("JP".to_string()),
            ..Default::default()
        });
        assert!(!dirty_ai.google_clean);
        assert!(dirty_ai.ai_studio_restricted);

        // AI Studio body mentioning "available regions" in a normal doc link must NOT false-fail
        let clean_ai_doc_link = evaluate_google_cleanliness(&GoogleCleanSignals {
            google_status: Some(204),
            yt_gl: Some("US".to_string()),
            ai_studio_status: Some(200),
            ai_studio_body_snippet: Some(
                r#"<html><a href="/docs/available-regions">View available regions</a></html>"#
                    .to_string(),
            ),
            cf_loc: Some("US".to_string()),
            ..Default::default()
        });
        assert!(clean_ai_doc_link.google_clean);
        assert!(!clean_ai_doc_link.ai_studio_restricted);

        // AI Studio exact phrase "Gemini is not currently supported" -> hard fail
        let dirty_ai_gemini_phrase = evaluate_google_cleanliness(&GoogleCleanSignals {
            google_status: Some(204),
            yt_gl: Some("SG".to_string()),
            ai_studio_status: Some(200),
            ai_studio_body_snippet: Some(
                "Gemini is not currently supported in your location.".to_string(),
            ),
            cf_loc: Some("SG".to_string()),
            ..Default::default()
        });
        assert!(!dirty_ai_gemini_phrase.google_clean);
        assert!(dirty_ai_gemini_phrase.ai_studio_restricted);

        // AI Studio 302 redirect to available_regions / available-regions / unsupported -> hard fail
        for loc in [
            "https://ai.google.dev/available_regions",
            "https://ai.google.dev/gemini-api/docs/available-regions",
            "https://aistudio.google.com/unsupported",
            "https://www.google.com/sorry/index",
        ] {
            let dirty_ai_redir = evaluate_google_cleanliness(&GoogleCleanSignals {
                google_status: Some(204),
                yt_gl: Some("US".to_string()),
                ai_studio_status: Some(302),
                ai_studio_redirect_location: Some(loc.to_string()),
                cf_loc: Some("US".to_string()),
                ..Default::default()
            });
            assert!(!dirty_ai_redir.google_clean, "loc={loc} must fail");
            assert!(dirty_ai_redir.ai_studio_restricted, "loc={loc} must restrict AI Studio");
        }
    }

    #[test]
    fn google_endpoints_disables_home_probe_for_loopback_definitions() {
        let prod_def = ProbeDefinition {
            id: "builtin_google_cn".to_string(),
            target_url: DEFAULT_GOOGLE_204_URL.to_string(),
            ..Default::default()
        };
        let prod_ep = GoogleCnEndpoints::from_probe_definition(&prod_def);
        assert_eq!(
            prod_ep.google_home_url.as_deref(),
            Some(DEFAULT_GOOGLE_HOME_URL)
        );

        let local_def = ProbeDefinition {
            id: "test_google".to_string(),
            target_url: "http://127.0.0.1:18080/google_ok".to_string(),
            ..Default::default()
        };
        let local_ep = GoogleCnEndpoints::from_probe_definition(&local_def);
        assert!(local_ep.google_home_url.is_none());
    }

    #[test]
    fn semantic_ai_unlock_evaluators_handle_clean_blocked_and_fallback_cases() {
        // Claude: JP + 401 auth error -> unlocked
        let (ok, _) = evaluate_claude_semantic_unlock(
            Some("JP"),
            Some(401),
            Some(r#"{"type":"error","error":{"type":"authentication_error","message":"x-api-key header is required"}}"#),
        );
        assert!(ok);
        // Claude: trace failed + 400 clean invalid_request -> fallback to api_ok=true
        let (ok, _) = evaluate_claude_semantic_unlock(
            None,
            Some(400),
            Some(r#"{"type":"error","error":{"type":"invalid_request_error","message":"model: Field required"}}"#),
        );
        assert!(ok);
        // Claude: 400 API schema error mentioning broad words ("unsupported", "country", "region")
        // must NOT be misclassified as a geo-block.
        let (ok, _) = evaluate_claude_semantic_unlock(
            Some("US"),
            Some(400),
            Some(r#"{"type":"error","error":{"type":"invalid_request_error","message":"unsupported parameter: country / region is not available in beta"}}"#),
        );
        assert!(ok);
        // Claude: HK in trace -> blocked even if API 401
        let (ok, _) = evaluate_claude_semantic_unlock(Some("HK"), Some(401), Some("authentication_error"));
        assert!(!ok);
        // Claude: 403 or exact geo-block phrase -> blocked
        let (ok, _) = evaluate_claude_semantic_unlock(
            Some("US"),
            Some(403),
            Some("Request not allowed"),
        );
        assert!(!ok);
        for phrase in [
            "Claude is not available in your country",
            "Claude is not available in your region",
            "Your country is not supported",
            "This region is not supported",
            r#"{"error":{"code":"unsupported_country"}}"#,
            r#"{"error":{"code":"unsupported_region"}}"#,
            "Service is unavailable in your country",
        ] {
            let (ok, _) = evaluate_claude_semantic_unlock(Some("US"), Some(400), Some(phrase));
            assert!(!ok, "exact Claude geo-block phrase `{phrase}` must fail");
        }

        // ChatGPT: US + 401 missing api key -> unlocked
        let (ok, _) = evaluate_chatgpt_semantic_unlock(
            Some("US"),
            Some(401),
            Some(r#"{"error":{"message":"You didn't provide an API key."}}"#),
        );
        assert!(ok);
        // ChatGPT: CN in trace -> blocked
        let (ok, _) = evaluate_chatgpt_semantic_unlock(Some("CN"), Some(401), Some("missing key"));
        assert!(!ok);
        // ChatGPT: unsupported_country_region_territory -> blocked
        let (ok, _) = evaluate_chatgpt_semantic_unlock(
            Some("SG"),
            Some(403),
            Some(r#"{"error":{"code":"unsupported_country_region_territory"}}"#),
        );
        assert!(!ok);

        // Gemini: API_KEY_INVALID + clean AI Studio (even with doc link mentioning "available regions") -> unlocked
        let (ok, _) = evaluate_gemini_semantic_unlock(
            Some(400),
            Some(r#"{"error":{"status":"INVALID_ARGUMENT","details":[{"reason":"API_KEY_INVALID"}]}}"#),
            Some(200),
            None,
            Some(r#"<html><a href="/docs">See available regions</a></html>"#),
        );
        assert!(ok);
        // Gemini: API_KEY_INVALID + AI Studio body exact geo-block phrase -> blocked
        let (ok, _) = evaluate_gemini_semantic_unlock(
            Some(400),
            Some(r#"{"error":{"status":"INVALID_ARGUMENT","details":[{"reason":"API_KEY_INVALID"}]}}"#),
            Some(200),
            None,
            Some("Gemini is not currently supported in this area"),
        );
        assert!(!ok);
        // Gemini: User location is not supported -> blocked
        let (ok, _) = evaluate_gemini_semantic_unlock(
            Some(400),
            Some(r#"{"error":{"message":"User location is not supported for the API use.","status":"FAILED_PRECONDITION"}}"#),
            Some(200),
            None,
            Some("ok"),
        );
        assert!(!ok);
        // Gemini: API key invalid BUT AI Studio redirects to available_regions -> blocked
        let (ok, _) = evaluate_gemini_semantic_unlock(
            Some(400),
            Some("API key not valid. Please pass a valid API key."),
            Some(302),
            Some("https://ai.google.dev/available_regions"),
            Some(""),
        );
        assert!(!ok);
    }

    #[test]
    fn chatgpt_semantic_unlock_with_ab_enforces_ab_reachability_and_geo_blocks() {
        let valid_api_body = Some(r#"{"error":{"message":"You didn't provide an API key."}}"#);

        // 1. ab.chatgpt.com timeout / EOF (`None`) -> MUST fail even when trace & api are clean.
        let (ok, detail) = evaluate_chatgpt_semantic_unlock_with_ab(
            Some("US"),
            Some(401),
            valid_api_body,
            None,
            None,
        );
        assert!(!ok);
        assert!(detail.contains("ab=request_failed"), "detail={detail}");

        // 2. ab.chatgpt.com returns 404 / 405 / 400 / 200 (typical Statsig GET responses) -> unlocked.
        for status in [200u16, 202, 204, 400, 401, 404, 405] {
            let (ok, detail) = evaluate_chatgpt_semantic_unlock_with_ab(
                Some("TW"),
                Some(401),
                valid_api_body,
                Some(status),
                Some("Method Not Allowed"),
            );
            assert!(ok, "ab status {status} should pass, detail={detail}");
            assert!(
                detail.contains(&format!("ab=ok(status={status})")),
                "detail={detail}"
            );
        }

        // 3. ab.chatgpt.com returns 403 from Envoy/Statsig origin without WAF/geo block -> pass.
        for origin_403 in [
            r#"{"error":"Missing statsig-api-key"}"#,
            "RBAC: access denied",
        ] {
            let (ok, detail) = evaluate_chatgpt_semantic_unlock_with_ab(
                Some("TW"),
                Some(401),
                valid_api_body,
                Some(403),
                Some(origin_403),
            );
            assert!(
                ok,
                "origin 403 `{origin_403}` proves ab.chatgpt.com reachability, detail={detail}"
            );
        }

        // 4. ab.chatgpt.com returns 451 -> MUST fail.
        let (ok, detail) = evaluate_chatgpt_semantic_unlock_with_ab(
            Some("SG"),
            Some(401),
            valid_api_body,
            Some(451),
            Some("Unavailable For Legal Reasons"),
        );
        assert!(!ok);
        assert!(detail.contains("ab=blocked(status=451"), "detail={detail}");

        // 5. ab.chatgpt.com returns 5xx -> MUST fail.
        let (ok, detail) = evaluate_chatgpt_semantic_unlock_with_ab(
            Some("US"),
            Some(401),
            valid_api_body,
            Some(502),
            Some("Bad Gateway"),
        );
        assert!(!ok);
        assert!(detail.contains("ab=server_error(status=502)"), "detail={detail}");

        // 6. ab.chatgpt.com returns 403/400 with geo-block or Cloudflare WAF challenge -> MUST fail.
        for blocked_body in [
            "<!DOCTYPE html><title>Just a moment...</title>",
            "Attention Required! | Cloudflare",
            r#"{"error":{"code":"unsupported_country"}}"#,
            r#"{"error":{"code":"unsupported_country_region_territory"}}"#,
        ] {
            let (ok, detail) = evaluate_chatgpt_semantic_unlock_with_ab(
                Some("US"),
                Some(401),
                valid_api_body,
                Some(403),
                Some(blocked_body),
            );
            assert!(
                !ok,
                "ab body `{blocked_body}` must fail unlock, detail={detail}"
            );
            assert!(detail.contains("ab=blocked(status=403,geo=true)"), "detail={detail}");
        }
    }

    #[test]
    fn parsers_extract_cf_loc_youtube_gl_and_stage_download_url() {
        let trace = "fl=123f\nh=cp.cloudflare.com\nloc=TW\ntls=TLSv1.3\n";
        assert_eq!(parse_cloudflare_trace_loc(trace).as_deref(), Some("TW"));

        let yt_html = r#"<script>var cfg = {"INNERTUBE_CONTEXT":{"client":{"gl":"JP"}}};</script>"#;
        assert_eq!(parse_youtube_gl(None, yt_html).as_deref(), Some("JP"));
        assert_eq!(parse_youtube_gl(Some("us"), "").as_deref(), Some("US"));

        let staged = build_download_stage_url("http://127.0.0.1:8080/__down?bytes=2097152&tag=a", 524288);
        assert!(staged.contains("bytes=524288"));
        assert!(staged.contains("tag=a"));
    }

    #[tokio::test]
    async fn drain_capped_body_stops_immediately_at_cap() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let total_len = 512 * 1024usize;

        let server = tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut req_buf = [0u8; 512];
                let _ = socket.read(&mut req_buf).await;
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {total_len}\r\nConnection: close\r\n\r\n"
                );
                let _ = socket.write_all(header.as_bytes()).await;
                let chunk = vec![b'A'; 16 * 1024];
                for _ in 0..(total_len / chunk.len()) {
                    if socket.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
            }
        });

        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let resp = client
            .get(format!("http://127.0.0.1:{port}/oversized"))
            .send()
            .await
            .unwrap();
        let drained = drain_capped_body(resp, 1024).await.unwrap();
        assert_eq!(drained.len(), 1024);
        assert!(drained.iter().all(|&b| b == b'A'));

        server.abort();
    }

    #[tokio::test]
    async fn latency_probe_warmup_excludes_cold_handshake_and_handles_failures() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted_conns = Arc::new(AtomicUsize::new(0));
        let warm_hits = Arc::new(AtomicUsize::new(0));
        let warmup_fail_hits = Arc::new(AtomicUsize::new(0));
        let fallback_hits = Arc::new(AtomicUsize::new(0));

        let c_conns = Arc::clone(&accepted_conns);
        let c_warm = Arc::clone(&warm_hits);
        let c_wf = Arc::clone(&warmup_fail_hits);
        let c_fb = Arc::clone(&fallback_hits);

        let server = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                c_conns.fetch_add(1, Ordering::SeqCst);
                let c_warm = Arc::clone(&c_warm);
                let c_wf = Arc::clone(&c_wf);
                let c_fb = Arc::clone(&c_fb);

                tokio::spawn(async move {
                    let mut tmp = [0u8; 2048];
                    loop {
                        let mut req_buf = Vec::with_capacity(512);
                        let mut eof = false;
                        while !req_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            let n = socket.read(&mut tmp).await.unwrap_or(0);
                            if n == 0 {
                                eof = true;
                                break;
                            }
                            req_buf.extend_from_slice(&tmp[..n]);
                            if req_buf.len() > 16 * 1024 {
                                eof = true;
                                break;
                            }
                        }
                        if eof && req_buf.is_empty() {
                            break;
                        }
                        let req = String::from_utf8_lossy(&req_buf);
                        let first_line = req.lines().next().unwrap_or_default();
                        let path = first_line.split_whitespace().nth(1).unwrap_or("/");

                        let resp: &[u8] = match path {
                            "/cold_then_hot" => {
                                let idx = c_warm.fetch_add(1, Ordering::SeqCst);
                                if idx == 0 {
                                    // Simulate expensive cold SOCKS5 + TLS handshake (160ms)
                                    sleep(Duration::from_millis(160)).await;
                                } else {
                                    // Simulate fast hot keep-alive RTT (~8ms)
                                    sleep(Duration::from_millis(8)).await;
                                }
                                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
                            }
                            "/warmup_fail_then_ok" => {
                                let idx = c_wf.fetch_add(1, Ordering::SeqCst);
                                if idx == 0 {
                                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
                                } else {
                                    sleep(Duration::from_millis(5)).await;
                                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
                                }
                            }
                            "/warmup_ok_then_fail" => {
                                let idx = c_fb.fetch_add(1, Ordering::SeqCst);
                                if idx == 0 {
                                    sleep(Duration::from_millis(12)).await;
                                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
                                } else {
                                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
                                }
                            }
                            _ => {
                                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            }
                        };

                        if socket.write_all(resp).await.is_err() {
                            break;
                        }
                        if path == "/all_fail" {
                            break;
                        }
                    }
                });
            }
        });

        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();

        // 1. Cold handshake (160ms) stripped; 2 hot samples measured on reused keep-alive socket.
        let def_warm = ProbeDefinition {
            id: "latency_warm".to_string(),
            target_url: format!("http://127.0.0.1:{port}/cold_then_hot"),
            method: "GET".to_string(),
            expected_status: Some(204),
            timeout_ms: 2000,
            ..Default::default()
        };
        let conns_before = accepted_conns.load(Ordering::SeqCst);
        let rec_warm = run_latency_probe_with_warmup(&client, "n1", &def_warm, 3, true).await;
        assert!(rec_warm.ok, "detail={:?}", rec_warm.detail);
        assert_eq!(warm_hits.load(Ordering::SeqCst), 3); // 1 warmup + 2 hot samples
        assert_eq!(
            accepted_conns.load(Ordering::SeqCst) - conns_before,
            1,
            "warmup and measured samples must reuse the same keep-alive connection"
        );
        let rtt = rec_warm.latency_ms.expect("latency_ms present");
        assert!(
            rtt < 80.0,
            "cold 160ms warmup must be excluded from hot RTT, got {rtt}ms (detail={:?})",
            rec_warm.detail
        );
        assert_eq!(rec_warm.loss_pct, Some(0.0));

        // 2. Warmup failure must NOT abort; proceeds with full `sample_count` (3) attempts.
        let def_wf = ProbeDefinition {
            id: "latency_wf".to_string(),
            target_url: format!("http://127.0.0.1:{port}/warmup_fail_then_ok"),
            ..def_warm.clone()
        };
        let rec_wf = run_latency_probe_with_warmup(&client, "n1", &def_wf, 3, true).await;
        assert!(rec_wf.ok, "detail={:?}", rec_wf.detail);
        assert_eq!(warmup_fail_hits.load(Ordering::SeqCst), 4); // 1 failed warmup + 3 ok samples
        assert_eq!(rec_wf.loss_pct, Some(0.0));

        // 3. Warmup succeeds, all hot samples fail -> falls back to warmup timing with honest loss%.
        let def_fb = ProbeDefinition {
            id: "latency_fb".to_string(),
            target_url: format!("http://127.0.0.1:{port}/warmup_ok_then_fail"),
            ..def_warm.clone()
        };
        let rec_fb = run_latency_probe_with_warmup(&client, "n1", &def_fb, 3, true).await;
        assert!(rec_fb.ok, "detail={:?}", rec_fb.detail);
        assert!(rec_fb.latency_ms.unwrap_or(0.0) >= 5.0);
        assert_eq!(rec_fb.loss_pct, Some(66.67));
        assert!(
            rec_fb
                .detail
                .as_deref()
                .unwrap_or("")
                .contains("warmup_fallback=true")
        );

        // 4. Warmup and all samples fail -> ok=false, loss_pct=100.0.
        let def_fail = ProbeDefinition {
            id: "latency_fail".to_string(),
            target_url: format!("http://127.0.0.1:{port}/all_fail"),
            ..def_warm
        };
        let rec_fail = run_latency_probe_with_warmup(&client, "n1", &def_fail, 3, true).await;
        assert!(!rec_fail.ok);
        assert!(rec_fail.latency_ms.is_none());
        assert_eq!(rec_fail.loss_pct, Some(100.0));

        server.abort();
    }

    #[tokio::test]
    async fn throughput_stage2_failure_and_stage1_abort_never_leak_residual_mbps() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let up_hits = Arc::new(AtomicUsize::new(0));
        let down_hits = Arc::new(AtomicUsize::new(0));
        let c_up = Arc::clone(&up_hits);
        let c_down = Arc::clone(&down_hits);

        let server = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let c_up = Arc::clone(&c_up);
                let c_down = Arc::clone(&c_down);
                tokio::spawn(async move {
                    let mut buf = Vec::with_capacity(4096);
                    let mut tmp = [0u8; 4096];
                    loop {
                        buf.clear();
                        let mut header_end = None;
                        while header_end.is_none() {
                            let n = socket.read(&mut tmp).await.unwrap_or(0);
                            if n == 0 {
                                return;
                            }
                            buf.extend_from_slice(&tmp[..n]);
                            header_end = buf.windows(4).position(|w| w == b"\r\n\r\n");
                        }
                        let hend = header_end.unwrap();
                        let header_str = String::from_utf8_lossy(&buf[..hend]);
                        let first = header_str.lines().next().unwrap_or("");
                        let path = first.split_whitespace().nth(1).unwrap_or("/");
                        let content_len: usize = header_str
                            .lines()
                            .find_map(|l| {
                                let (k, v) = l.split_once(':')?;
                                k.trim()
                                    .eq_ignore_ascii_case("content-length")
                                    .then(|| v.trim().parse::<usize>().ok())
                                    .flatten()
                            })
                            .unwrap_or(0);
                        let mut read_body = buf.len().saturating_sub(hend + 4);
                        while read_body < content_len {
                            let n = socket.read(&mut tmp).await.unwrap_or(0);
                            if n == 0 {
                                break;
                            }
                            read_body += n;
                        }

                        if path.starts_with("/up_stage2_fail") {
                            let hit = c_up.fetch_add(1, Ordering::SeqCst);
                            if hit == 0 {
                                let _ = socket
                                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                                    .await;
                            } else {
                                let _ = socket
                                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                                    .await;
                            }
                            return;
                        } else if path.starts_with("/down_stage2_fail") {
                            let hit = c_down.fetch_add(1, Ordering::SeqCst);
                            if hit == 0 {
                                let body = vec![b'D'; 16 * 1024];
                                let hdr = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                    body.len()
                                );
                                let _ = socket.write_all(hdr.as_bytes()).await;
                                let _ = socket.write_all(&body).await;
                            } else {
                                let _ = socket
                                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                                    .await;
                            }
                            return;
                        } else {
                            let _ = socket
                                .write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                                .await;
                            return;
                        }
                    }
                });
            }
        });

        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let cfg = ThroughputProbeConfig {
            fuse_bytes: 16 * 1024,
            fuse_min_mbps: 0.01,
            max_payload_bytes: 64 * 1024,
        };

        // 1. Stage-2 upload failure -> ok=false AND up_mbps=None (stage1_mbps kept in detail only)
        let up_def = ProbeDefinition {
            id: "builtin_upload".to_string(),
            kind: crate::models::ProbeKind::Upload,
            target_url: format!("http://127.0.0.1:{port}/up_stage2_fail"),
            method: "POST".to_string(),
            expected_status: Some(200),
            payload_bytes: Some(32 * 1024),
            timeout_ms: 3000,
            ..Default::default()
        };
        let up_rec = run_upload_probe_with_config(&client, "n1", &up_def, &cfg).await;
        assert!(!up_rec.ok);
        assert_eq!(up_rec.up_mbps, None);
        assert!(
            up_rec
                .detail
                .as_deref()
                .unwrap_or("")
                .contains("stage2_upload_failed")
        );

        // 2. Stage-2 download failure -> ok=false AND down_mbps=None
        let down_def = ProbeDefinition {
            id: "builtin_download".to_string(),
            kind: crate::models::ProbeKind::Download,
            target_url: format!("http://127.0.0.1:{port}/down_stage2_fail?bytes=32768"),
            method: "GET".to_string(),
            expected_status: Some(200),
            payload_bytes: Some(32 * 1024),
            timeout_ms: 3000,
            ..Default::default()
        };
        let down_rec = run_download_probe_with_config(&client, "n1", &down_def, &cfg).await;
        assert!(!down_rec.ok);
        assert_eq!(down_rec.down_mbps, None);
        assert!(
            down_rec
                .detail
                .as_deref()
                .unwrap_or("")
                .contains("stage2_download_failed")
        );

        // 3. Stage-1 HTTP error abort -> ok=false AND up_mbps/down_mbps == None (not Some(0.0))
        let abort_up = ProbeDefinition {
            target_url: format!("http://127.0.0.1:{port}/abort_500"),
            ..up_def
        };
        let rec_abort_up = run_upload_probe_with_config(&client, "n1", &abort_up, &cfg).await;
        assert!(!rec_abort_up.ok);
        assert_eq!(rec_abort_up.up_mbps, None);

        let abort_down = ProbeDefinition {
            target_url: format!("http://127.0.0.1:{port}/abort_500"),
            ..down_def
        };
        let rec_abort_down = run_download_probe_with_config(&client, "n1", &abort_down, &cfg).await;
        assert!(!rec_abort_down.ok);
        assert_eq!(rec_abort_down.down_mbps, None);

        server.abort();
    }

    #[test]
    fn ip_purity_parsers_reject_invalid_or_missing_fields_and_prevent_ip_leak_or_asas_prefix() {
        // 1. ip-api.com: HTTP != 200, status:"fail", or missing both proxy & hosting -> None!
        assert_eq!(parse_ipapi_json(429, r#"{"status":"success","proxy":false,"hosting":false}"#), None);
        assert_eq!(
            parse_ipapi_json(200, r#"{"status":"fail","message":"private range"}"#),
            None
        );
        assert_eq!(
            parse_ipapi_json(200, r#"{"status":"success","countryCode":"TW","isp":"HiNet"}"#),
            None
        );
        assert_eq!(parse_ipapi_json(200, "<html>Rate Limited</html>"), None);

        // Valid ip-api Akari proxy=true payload (must never leak query IP).
        let akari_api = parse_ipapi_json(
            200,
            r#"{"status":"success","query":"203.0.113.88","countryCode":"TW","isp":"Akari Networks","org":"Akari Networks","as":"AS38136 Akari Networks","mobile":false,"proxy":true,"hosting":true}"#,
        )
        .expect("valid akari ip-api payload");
        assert_eq!(akari_api.country_code.as_deref(), Some("TW"));
        assert_eq!(akari_api.proxy, Some(true));
        assert_eq!(akari_api.hosting, Some(true));
        assert_eq!(akari_api.asn.as_deref(), Some("AS38136 Akari Networks"));
        assert!(!akari_api.asn.as_deref().unwrap_or("").contains("203.0.113.88"));

        // 2. ipquery.io: HTTP != 200, missing risk, or empty risk:{} -> None!
        assert_eq!(parse_ipquery_json(503, r#"{"risk":{"is_proxy":false}}"#), None);
        assert_eq!(parse_ipquery_json(200, r#"{"ip":"203.0.113.10","location":{"country_code":"TW"}}"#), None);
        assert_eq!(parse_ipquery_json(200, r#"{"risk":{}}"#), None);

        // ASN prefix deduplication: "ASAS3462", "AS3462", "3462" all normalize cleanly to "AS3462 HiNet".
        let tw_ipq = parse_ipquery_json(
            200,
            r#"{"ip":"198.51.100.7","isp":{"asn":"ASAS3462","org":"HiNet"},"location":{"country_code":"tw"},"risk":{"is_proxy":false,"is_vpn":false,"is_tor":false,"is_datacenter":false,"is_mobile":false,"risk_score":0}}"#,
        )
        .expect("valid tw ipquery payload");
        assert_eq!(tw_ipq.country_code.as_deref(), Some("TW"));
        assert_eq!(tw_ipq.asn.as_deref(), Some("AS3462 HiNet"));
        assert!(!tw_ipq.asn.as_deref().unwrap_or("").contains("ASAS"));
        assert!(!tw_ipq.asn.as_deref().unwrap_or("").contains("198.51.100.7"));

        // Pure numeric ASN and literal IP in org must be normalized/stripped safely.
        assert_eq!(format_asn_label(Some("3462"), Some("HiNet")).as_deref(), Some("AS3462 HiNet"));
        assert_eq!(format_asn_label(Some("198.51.100.1"), Some("2001:db8::1")), None);
    }

    #[test]
    fn windsurf_semantic_unlock_kills_akari_proxy_risk_allows_clean_and_advises_datacenter_vpn() {
        let ok_codeium_api = WindsurfApiResponseSignals {
            status: Some(415),
            via_header: Some("1.1 google".to_string()),
            has_accept_post: true,
            content_type: Some("application/json".to_string()),
            body: Some(r#"{"code":"unknown","message":"unsupported media type"}"#.to_string()),
        };

        // 1. Akari proxy=true (exact training-machine bug): MUST fail unlocked=false + proxy_risk!
        let akari_ipapi = parse_ipapi_json(
            200,
            r#"{"status":"success","countryCode":"TW","as":"AS38136 Akari Networks","proxy":true,"hosting":true,"mobile":false}"#,
        )
        .unwrap();
        let akari_sig = merge_ip_purity_signals(None, Some(&akari_ipapi));
        assert_eq!(akari_sig.ip_risk_level, "proxy_risk");
        assert_eq!(akari_sig.ip_clean, Some(false));
        let (ok, detail) = evaluate_windsurf_semantic_unlock(&ok_codeium_api, &akari_sig);
        assert!(!ok, "Akari proxy=true MUST NOT pass Windsurf semantic unlock: {detail}");
        assert!(detail.starts_with("semantic_windsurf: "), "detail={detail}");
        assert!(detail.contains("reason=high_risk_proxy_ip"), "detail={detail}");
        assert!(detail.contains("ip_risk=proxy_risk"), "detail={detail}");
        assert!(detail.contains("AS38136 Akari Networks"), "detail={detail}");

        // 2. Ordinary airport node: ipquery is_vpn=true + risk_score=35, ip-api proxy=false, hosting=true
        //    MUST be classified as `datacenter` (NOT proxy_risk) and unlocked=true so ordinary
        //    datacenter relays are not false-killed while still carrying ip_clean=Some(false).
        let vpn_ipq = parse_ipquery_json(
            200,
            r#"{"isp":{"asn":"AS20473","org":"Vultr"},"location":{"country_code":"JP"},"risk":{"is_proxy":false,"is_vpn":true,"is_tor":false,"is_datacenter":true,"risk_score":35}}"#,
        )
        .unwrap();
        let vpn_ipapi = parse_ipapi_json(
            200,
            r#"{"status":"success","countryCode":"JP","as":"AS20473 The Constant Company","proxy":false,"hosting":true,"mobile":false}"#,
        )
        .unwrap();
        let dc_sig = merge_ip_purity_signals(Some(&vpn_ipq), Some(&vpn_ipapi));
        assert_eq!(dc_sig.ip_risk_level, "datacenter");
        assert_eq!(dc_sig.ip_clean, Some(false));
        let (ok_dc, detail_dc) = evaluate_windsurf_semantic_unlock(&ok_codeium_api, &dc_sig);
        assert!(ok_dc, "ordinary datacenter/vpn should remain unlocked with advisory: {detail_dc}");
        assert!(detail_dc.contains("ip_risk=datacenter"), "detail={detail_dc}");

        // 3. Taiwan residential ISP (HiNet clean): unlocked=true + ip_clean=Some(true) + clean.
        let tw_ipq = parse_ipquery_json(
            200,
            r#"{"isp":{"asn":"AS3462","org":"HiNet"},"location":{"country_code":"TW"},"risk":{"is_proxy":false,"is_vpn":false,"is_tor":false,"is_datacenter":false,"risk_score":0}}"#,
        )
        .unwrap();
        let tw_ipapi = parse_ipapi_json(
            200,
            r#"{"status":"success","countryCode":"TW","as":"AS3462 Data Communication Business Group","proxy":false,"hosting":false,"mobile":false}"#,
        )
        .unwrap();
        let clean_sig = merge_ip_purity_signals(Some(&tw_ipq), Some(&tw_ipapi));
        assert_eq!(clean_sig.ip_risk_level, "clean");
        assert_eq!(clean_sig.ip_clean, Some(true));
        assert_eq!(clean_sig.ip_risk_flags, None);
        let (ok_clean, detail_clean) = evaluate_windsurf_semantic_unlock(&ok_codeium_api, &clean_sig);
        assert!(ok_clean, "clean TW residential must unlock: {detail_clean}");
        assert!(detail_clean.contains("ip_risk=clean"), "detail={detail_clean}");

        // 4. Blocked jurisdictions (HK / CN): MUST fail unlocked=false even with clean IP & 415 API.
        for blocked_cc in ["HK", "CN"] {
            let blocked_sig = IpPuritySignals {
                country_code: Some(blocked_cc.to_string()),
                ip_clean: Some(true),
                ip_risk_level: "clean".to_string(),
                ip_asn: Some("AS4760 HKT".to_string()),
                ..Default::default()
            };
            let (ok_geo, detail_geo) =
                evaluate_windsurf_semantic_unlock(&ok_codeium_api, &blocked_sig);
            assert!(!ok_geo, "country {blocked_cc} must be geo-blocked: {detail_geo}");
            assert!(detail_geo.contains("reason=geo_blocked"), "detail={detail_geo}");
        }

        // 5. Dual-source failure/timeout -> ip_risk_level="unknown", ip_clean=None; degrades to API truth.
        let unknown_sig = merge_ip_purity_signals(None, None);
        assert_eq!(unknown_sig.ip_risk_level, "unknown");
        assert_eq!(unknown_sig.ip_clean, None);
        let (ok_unknown, detail_unknown) =
            evaluate_windsurf_semantic_unlock(&ok_codeium_api, &unknown_sig);
        assert!(ok_unknown, "unknown IP risk degrades to Codeium API truth: {detail_unknown}");
        assert!(detail_unknown.contains("ip_risk=unknown"), "detail={detail_unknown}");

        // 6. Partial source missing `hosting` (ip-api returns only proxy:false) MUST stay unknown (no fake green).
        let partial_api = parse_ipapi_json(200, r#"{"status":"success","proxy":false}"#).unwrap();
        let partial_sig = merge_ip_purity_signals(None, Some(&partial_api));
        assert_eq!(partial_sig.ip_risk_level, "unknown");
        assert_eq!(partial_sig.ip_clean, None);

        // 7. Codeium API 403 / 429 / Cloudflare challenge / missing gateway signature -> unlocked=false.
        let cf_403 = WindsurfApiResponseSignals {
            status: Some(403),
            body: Some("<html><title>Just a moment...</title></html>".to_string()),
            ..Default::default()
        };
        let (ok_403, _) = evaluate_windsurf_semantic_unlock(&cf_403, &clean_sig);
        assert!(!ok_403);

        let hijack_404 = WindsurfApiResponseSignals {
            status: Some(404),
            content_type: Some("text/html".to_string()),
            body: Some("<html>Captive Portal Not Found</html>".to_string()),
            ..Default::default()
        };
        let (ok_hijack, detail_hijack) = evaluate_windsurf_semantic_unlock(&hijack_404, &clean_sig);
        assert!(!ok_hijack, "404 without ConnectRPC/Google gateway signature must fail: {detail_hijack}");

        // 8. 404/400/401 with bare text/plain (no Google Via or Accept-Post) MUST also fail.
        for status_code in [400u16, 401u16, 404u16] {
            let plain_err = WindsurfApiResponseSignals {
                status: Some(status_code),
                content_type: Some("text/plain".to_string()),
                body: Some("Not Found".to_string()),
                ..Default::default()
            };
            let (ok_plain, detail_plain) =
                evaluate_windsurf_semantic_unlock(&plain_err, &clean_sig);
            assert!(
                !ok_plain,
                "status {status_code} bare text/plain without gateway header must fail: {detail_plain}"
            );
        }

        // 9. Non-ASCII ASN/Org strings must never panic UTF-8 slicing and embedded IPs must be stripped.
        assert_eq!(
            format_asn_label(Some("中华电信"), Some("台湾节点 203.0.113.55")).as_deref(),
            Some("中华电信 台湾节点")
        );
        assert_eq!(
            format_asn_label(Some("AS中国"), Some("AS3462 HiNet 2001:db8::9")).as_deref(),
            Some("AS中国 AS3462 HiNet")
        );

        // 10. Dual-source country mismatch: blocked region (HK/CN) MUST win conservatively over non-blocked (TW).
        let conflict_ipq = parse_ipquery_json(
            200,
            r#"{"isp":{"asn":"AS3462","org":"Broadcast"},"location":{"country_code":"TW"},"risk":{"is_proxy":false,"is_vpn":false,"is_tor":false,"is_datacenter":false,"risk_score":10}}"#,
        )
        .unwrap();
        let conflict_ipapi = parse_ipapi_json(
            200,
            r#"{"status":"success","countryCode":"HK","as":"AS3462 Broadcast","proxy":false,"hosting":false,"mobile":false}"#,
        )
        .unwrap();
        let conflict_sig = merge_ip_purity_signals(Some(&conflict_ipq), Some(&conflict_ipapi));
        assert_eq!(conflict_sig.country_code.as_deref(), Some("HK"));
        let (ok_conflict, detail_conflict) =
            evaluate_windsurf_semantic_unlock(&ok_codeium_api, &conflict_sig);
        assert!(
            !ok_conflict,
            "dual-source conflict with HK must conservatively geo-block: {detail_conflict}"
        );

        // 11. Medium risk_score (50..79) without proxy/tor classifies as datacenter advisory (not proxy_risk).
        let med_risk_ipq = parse_ipquery_json(
            200,
            r#"{"isp":{"asn":"AS20473","org":"Vultr"},"location":{"country_code":"JP"},"risk":{"is_proxy":false,"is_vpn":false,"is_tor":false,"is_datacenter":false,"risk_score":65}}"#,
        )
        .unwrap();
        let med_sig = merge_ip_purity_signals(Some(&med_risk_ipq), None);
        assert_eq!(med_sig.ip_risk_level, "datacenter");
        assert_eq!(med_sig.ip_clean, Some(false));
    }
}
