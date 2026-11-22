use crate::error::CatResult;
use crate::preaccel::generator::{
    host_to_direct_rule, host_to_fake_ip_filter, validate_domestic_probe_url,
};
use regex::Regex;
use reqwest::header::LOCATION;
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use std::time::Duration;
use url::Url;

/// Maximum bytes read from an unexpected HTTP 200 captive-portal HTML response.
const MAX_PORTAL_BODY_SNIPPET_BYTES: usize = 16 * 1024;

/// Maximum number of temporary bypass hosts tracked simultaneously during one captive-portal login session.
const MAX_TEMP_BYPASS_HOSTS: usize = 16;

/// Detected campus network captive-portal state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CampusPortalState {
    /// Domestic 204 endpoint returned HTTP 204 No Content directly.
    Connected,
    /// Network intercepted the probe with a redirect or inline portal page requiring login.
    CaptivePortalRequired {
        portal_url: String,
        bypass_host: Option<String>,
        status_code: u16,
    },
    /// Probe failed to reach the network or returned an unexpected error status.
    Offline { reason: String },
}

/// Output of advancing `CampusBypassTracker` with a new probe observation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CampusBypassTransition {
    pub state: CampusPortalState,
    /// True when the active temporary `DIRECT` rules or `fake-ip-filter` entries changed.
    pub rules_changed: bool,
    pub active_direct_rules: Vec<String>,
    pub active_fake_ip_filter: Vec<String>,
}

/// Stateful guard that issues temporary `DIRECT` / `fake-ip-filter` bypass rules for campus
/// captive-portal authentication pages and withdraws every temporary entry once HTTP 204 resumes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CampusBypassTracker {
    state: CampusPortalState,
    temporary_hosts: Vec<String>,
    temporary_direct_rules: Vec<String>,
    temporary_fake_ip_filters: Vec<String>,
}

impl Default for CampusBypassTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl CampusBypassTracker {
    pub fn new() -> Self {
        Self {
            state: CampusPortalState::Connected,
            temporary_hosts: Vec::new(),
            temporary_direct_rules: Vec::new(),
            temporary_fake_ip_filters: Vec::new(),
        }
    }

    pub fn state(&self) -> &CampusPortalState {
        &self.state
    }

    pub fn active_bypass_hosts(&self) -> &[String] {
        &self.temporary_hosts
    }

    pub fn active_direct_rules(&self) -> &[String] {
        &self.temporary_direct_rules
    }

    pub fn active_fake_ip_filters(&self) -> &[String] {
        &self.temporary_fake_ip_filters
    }

    pub fn has_temporary_bypass(&self) -> bool {
        !self.temporary_direct_rules.is_empty() || !self.temporary_fake_ip_filters.is_empty()
    }

    /// Manually clear all temporary captive-portal bypass rules. Returns true if anything was cleared.
    pub fn clear_temporary_bypass(&mut self) -> bool {
        let had_entries = self.has_temporary_bypass() || !self.temporary_hosts.is_empty();
        self.temporary_hosts.clear();
        self.temporary_direct_rules.clear();
        self.temporary_fake_ip_filters.clear();
        had_entries
    }

    /// Apply a newly observed `CampusPortalState` and compute any temporary rule updates.
    pub fn apply_state(&mut self, next_state: CampusPortalState) -> CampusBypassTransition {
        let mut rules_changed = false;

        match &next_state {
            CampusPortalState::Connected => {
                // Recovery to HTTP 204 withdraws all temporary rules cleanly without leftovers.
                if self.clear_temporary_bypass() {
                    rules_changed = true;
                }
            }
            CampusPortalState::CaptivePortalRequired { bypass_host, .. } => {
                if let Some(host) = bypass_host.as_deref()
                    && self.record_temporary_host(host)
                {
                    rules_changed = true;
                }
            }
            CampusPortalState::Offline { .. } => {
                // Preserve any active portal bypass during transient offline blips until 204 recovers.
            }
        }

        self.state = next_state.clone();
        CampusBypassTransition {
            state: next_state,
            rules_changed,
            active_direct_rules: self.temporary_direct_rules.clone(),
            active_fake_ip_filter: self.temporary_fake_ip_filters.clone(),
        }
    }

    fn record_temporary_host(&mut self, raw_host: &str) -> bool {
        let normalized = normalize_host_token(raw_host);
        if normalized.is_empty() {
            return false;
        }
        if self
            .temporary_hosts
            .iter()
            .any(|h| h.eq_ignore_ascii_case(&normalized))
        {
            return false;
        }

        let prev_rules = self.temporary_direct_rules.clone();
        let prev_filters = self.temporary_fake_ip_filters.clone();

        if self.temporary_hosts.len() >= MAX_TEMP_BYPASS_HOSTS {
            self.temporary_hosts.remove(0);
        }

        self.temporary_hosts.push(normalized);
        self.rebuild_rules_from_hosts();

        prev_rules != self.temporary_direct_rules || prev_filters != self.temporary_fake_ip_filters
    }

    fn rebuild_rules_from_hosts(&mut self) {
        self.temporary_direct_rules.clear();
        self.temporary_fake_ip_filters.clear();

        for host in &self.temporary_hosts {
            let (maybe_rule, maybe_filter) = build_temporary_bypass_entries(host);
            if let Some(rule) = maybe_rule
                && !self
                    .temporary_direct_rules
                    .iter()
                    .any(|r| r.eq_ignore_ascii_case(&rule))
            {
                self.temporary_direct_rules.push(rule);
            }
            if let Some(filter) = maybe_filter
                && !self
                    .temporary_fake_ip_filters
                    .iter()
                    .any(|f| f.eq_ignore_ascii_case(&filter))
            {
                self.temporary_fake_ip_filters.push(filter);
            }
        }
    }
}

/// Build an isolated HTTP client for captive-portal detection:
/// - `Policy::none()` prevents following redirects so 301/302/307/308 `Location` headers are captured verbatim.
/// - `.no_proxy()` bypasses OS/environment proxy settings to inspect the real underlying physical link.
pub fn build_campus_probe_client(timeout: Duration) -> CatResult<reqwest::Client> {
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .no_proxy()
        .timeout(timeout)
        .user_agent("CatCloud-CampusProbe/1.0")
        .build()?;
    Ok(client)
}

/// Pure classifier turning an HTTP probe observation into a `CampusPortalState`.
pub fn classify_portal_response(
    probe_url: &str,
    status_code: u16,
    location_header: Option<&str>,
    body_snippet: Option<&str>,
) -> CampusPortalState {
    if status_code == 204 {
        return CampusPortalState::Connected;
    }

    let probe_host = extract_host_from_url(probe_url);

    // Standard HTTP redirect hijack (301/302/303/307/308).
    if matches!(status_code, 301 | 302 | 303 | 307 | 308) {
        let resolved_url = location_header
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|loc| resolve_redirect_url(probe_url, loc))
            .unwrap_or_else(|| {
                location_header
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .unwrap_or(probe_url)
                    .to_string()
            });

        let bypass_host = extract_host_from_url(&resolved_url);
        return CampusPortalState::CaptivePortalRequired {
            portal_url: resolved_url,
            bypass_host,
            status_code,
        };
    }

    // Unexpected HTTP 200 on a 204 endpoint indicates transparent portal page injection.
    if status_code == 200 {
        let embedded_url = body_snippet.and_then(|body| extract_portal_url_from_html(probe_url, body));
        let (portal_url, bypass_host) = match embedded_url {
            Some(url) => {
                let host = extract_host_from_url(&url).filter(|h| {
                    probe_host
                        .as_deref()
                        .is_none_or(|ph| !ph.eq_ignore_ascii_case(h))
                });
                (url, host)
            }
            None => (probe_url.to_string(), None),
        };
        return CampusPortalState::CaptivePortalRequired {
            portal_url,
            bypass_host,
            status_code,
        };
    }

    CampusPortalState::Offline {
        reason: format!("unexpected HTTP status {status_code} from domestic 204 probe"),
    }
}

/// Extract a normalized host or bare IP string (IPv6 brackets stripped) from a URL.
pub fn extract_host_from_url(raw_url: &str) -> Option<String> {
    let parsed = Url::parse(raw_url.trim()).ok()?;
    let host = parsed.host_str()?;
    let cleaned = normalize_host_token(host);
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

/// Generate a `(direct_rule, fake_ip_filter)` pair for a captive-portal host or IP.
pub fn build_temporary_bypass_entries(host: &str) -> (Option<String>, Option<String>) {
    let rule = host_to_direct_rule(host);
    let filter = host_to_fake_ip_filter(host);
    (rule, filter)
}

/// Execute an asynchronous no-proxy, no-redirect domestic 204 probe to detect campus captive portals.
pub async fn probe_campus_portal(probe_url: &str, timeout: Duration) -> CampusPortalState {
    if let Err(err) = validate_domestic_probe_url(probe_url) {
        return CampusPortalState::Offline {
            reason: err.to_string(),
        };
    }

    let client = match build_campus_probe_client(timeout) {
        Ok(c) => c,
        Err(err) => {
            return CampusPortalState::Offline {
                reason: format!("failed to construct campus probe HTTP client: {err}"),
            };
        }
    };

    let mut resp = match client.get(probe_url).send().await {
        Ok(r) => r,
        Err(err) => {
            return CampusPortalState::Offline {
                reason: format!("campus probe request failed: {err}"),
            };
        }
    };

    let status_code = resp.status().as_u16();
    let location = resp
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let body_snippet = if status_code == 200 {
        read_bounded_body_snippet(&mut resp, MAX_PORTAL_BODY_SNIPPET_BYTES).await
    } else {
        None
    };

    classify_portal_response(
        probe_url,
        status_code,
        location.as_deref(),
        body_snippet.as_deref(),
    )
}

/// Probe `primary_url` and fall back to `fallback_url` only when `primary_url` reports `Offline`.
pub async fn probe_campus_portal_with_fallback(
    primary_url: &str,
    fallback_url: Option<&str>,
    timeout: Duration,
) -> CampusPortalState {
    let first = probe_campus_portal(primary_url, timeout).await;
    if !matches!(first, CampusPortalState::Offline { .. }) {
        return first;
    }
    if let Some(fb) = fallback_url.map(str::trim).filter(|s| !s.is_empty()) {
        return probe_campus_portal(fb, timeout).await;
    }
    first
}

async fn read_bounded_body_snippet(
    resp: &mut reqwest::Response,
    max_bytes: usize,
) -> Option<String> {
    let mut buf = Vec::new();
    while buf.len() < max_bytes {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let remaining = max_bytes.saturating_sub(buf.len());
                let take = chunk.len().min(remaining);
                buf.extend_from_slice(&chunk[..take]);
                if take < chunk.len() {
                    break;
                }
            }
            Ok(None) | Err(_) => break,
        }
    }
    if buf.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&buf).into_owned())
    }
}

fn resolve_redirect_url(base_url: &str, location: &str) -> Option<String> {
    if let Ok(abs) = Url::parse(location) {
        return Some(abs.into());
    }
    let base = Url::parse(base_url).ok()?;
    base.join(location).ok().map(String::from)
}

fn extract_portal_url_from_html(base_url: &str, html: &str) -> Option<String> {
    static META_REFRESH_RE: OnceLock<Regex> = OnceLock::new();
    static JS_LOCATION_RE: OnceLock<Regex> = OnceLock::new();
    static FORM_ACTION_RE: OnceLock<Regex> = OnceLock::new();

    let meta_re = META_REFRESH_RE.get_or_init(|| {
        Regex::new(r#"(?i)url\s*=\s*['"]?(https?://[^'"\s>]+)"#).expect("valid meta refresh regex")
    });
    if let Some(caps) = meta_re.captures(html)
        && let Some(m) = caps.get(1)
        && let Some(url) = resolve_redirect_url(base_url, m.as_str().trim_end_matches(';'))
    {
        return Some(url);
    }

    let js_re = JS_LOCATION_RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:window\.|top\.|self\.)?location(?:\.href)?\s*(?:=|\.replace\()\s*['"](https?://[^'"]+)['"]"#,
        )
        .expect("valid js location regex")
    });
    if let Some(caps) = js_re.captures(html)
        && let Some(m) = caps.get(1)
        && let Some(url) = resolve_redirect_url(base_url, m.as_str())
    {
        return Some(url);
    }

    let form_re = FORM_ACTION_RE.get_or_init(|| {
        Regex::new(r#"(?i)<form[^>]*\baction\s*=\s*['"](https?://[^'"]+)['"]"#)
            .expect("valid form action regex")
    });
    if let Some(caps) = form_re.captures(html)
        && let Some(m) = caps.get(1)
        && let Some(url) = resolve_redirect_url(base_url, m.as_str())
    {
        return Some(url);
    }

    None
}

fn normalize_host_token(raw: &str) -> String {
    raw.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}
