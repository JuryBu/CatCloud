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

async fn run_builtin_ai_semantic_unlock_probe(
    client: &reqwest::Client,
    node_id: &str,
    def: &ProbeDefinition,
    site_key: &str,
) -> ProbeResultRecord {
    let timeout = Duration::from_millis(def.timeout_ms.max(500));

    let (unlocked, latency_ms, detail) = match def.id.trim() {
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
            (ok, api_ms, detail)
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
            (ok, api_ms, detail)
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
            (ok, api_ms, detail)
        }
        _ => (false, None, format!("unsupported semantic probe {}", def.id)),
    };

    let mut unlocked_map = HashMap::new();
    unlocked_map.insert(site_key.to_string(), unlocked);
    if def.id != site_key && !def.id.is_empty() {
        unlocked_map.insert(def.id.clone(), unlocked);
    }

    ProbeResultRecord {
        node_id: node_id.to_string(),
        probe_id: def.id.clone(),
        tested_at: now_rfc3339(),
        ok: unlocked,
        latency_ms,
        unlocked_map,
        detail: Some(detail),
        ..Default::default()
    }
}

/// Execute an L1 arbitrary site unlock probe with configurable URL, HTTP method,
/// expected status code, and optional response-body regular expression.
/// For built-in AI unlock probes (`builtin_unlock_claude`, `builtin_unlock_chatgpt`,
/// `builtin_unlock_gemini`) without custom regex/status targeting non-loopback endpoints,
/// dispatches to credential-free semantic unlock detection to avoid Cloudflare 403 false negatives.
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
            "builtin_unlock_claude" | "builtin_unlock_chatgpt" | "builtin_unlock_gemini"
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
            let mut rec = failed_record(
                node_id,
                &def.id,
                format!("fast_fuse_upload_abort(stage1={stage1_bytes}B): {err}"),
            );
            rec.up_mbps = Some(0.0);
            return rec;
        }
    };

    if stage1_mbps < cfg.fuse_min_mbps {
        return ProbeResultRecord {
            node_id: node_id.to_string(),
            probe_id: def.id.clone(),
            tested_at: now_rfc3339(),
            ok: false,
            latency_ms: Some(stage1_ms),
            up_mbps: Some(stage1_mbps),
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
            up_mbps: Some(stage1_mbps),
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
            let mut rec = failed_record(
                node_id,
                &def.id,
                format!("fast_fuse_download_abort(stage1={stage1_bytes}B): {err}"),
            );
            rec.down_mbps = Some(0.0);
            return rec;
        }
    };

    if stage1_read == 0 || stage1_mbps < cfg.fuse_min_mbps {
        return ProbeResultRecord {
            node_id: node_id.to_string(),
            probe_id: def.id.clone(),
            tested_at: now_rfc3339(),
            ok: false,
            latency_ms: Some(stage1_ms),
            down_mbps: Some(stage1_mbps),
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
            down_mbps: Some(stage2_mbps),
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
            down_mbps: Some(stage1_mbps),
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
}
