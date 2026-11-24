use crate::error::{CatError, CatResult};
use crate::models::ProxyNode;
use crate::subscription::adapter::{ADAPTER_SCHEMA_V1, render_adapter_template_script};
use crate::subscription::parser::{
    MAX_SUBSCRIPTION_BYTES, json_to_u16, node_from_clash_json, parse_clash_yaml_value,
    parse_subscription_payload,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;
use sysinfo::{ProcessRefreshKind, RefreshKind, System, UpdateKind};
use url::Url;

/// Default HTTP probe timeout when checking a local Mihomo REST controller.
pub const DEFAULT_CONTROLLER_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Upper bound for local controller `/proxies` response body during read-only inspection (8 MiB).
const MAX_CONTROLLER_PROBE_BYTES: usize = 8 * 1024 * 1024;

/// Read-only snapshot of a running local process and any parsed CLI proxy configuration hints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessCandidate {
    pub pid: u32,
    pub name: String,
    pub exe_path: Option<PathBuf>,
    pub cmdline: Vec<String>,
    pub detected_config_dir: Option<PathBuf>,
    pub detected_config_file: Option<PathBuf>,
    pub detected_controller_addr: Option<String>,
    pub likely_proxy_client: bool,
}

/// Actionable read-only attach strategy recommended after inspecting a `ProcessCandidate`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum AttachRecommendation {
    /// Bind directly to a readable plaintext YAML file in read-only mode.
    ReadOnlyLocalFile {
        path: PathBuf,
        node_count: usize,
        reason: String,
    },
    /// Bind to a standard local Mihomo REST controller endpoint (`http://127.0.0.1:<port>/proxies`).
    PublicControllerApi {
        endpoint_url: String,
        proxy_count: usize,
        requires_secret: bool,
        reason: String,
    },
    /// Fall back to generating a clean `catcloud-adapter/v1` external adapter script template.
    ExternalAdapterTemplate {
        schema: String,
        suggested_command: String,
        template_script: String,
        reason: String,
    },
}

/// Complete read-only inspection report for a manually selected local process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessInspectionResult {
    pub pid: u32,
    pub process_name: String,
    pub readable_yaml_file: Option<PathBuf>,
    pub yaml_node_count: usize,
    pub controller_url: Option<String>,
    pub controller_reachable: bool,
    pub controller_requires_secret: bool,
    pub controller_proxy_count: usize,
    pub recommendation: AttachRecommendation,
    pub notes: Vec<String>,
}

/// Enumerate running local processes via `sysinfo` using lightweight read-only metadata
/// (PID, name, executable path, command line only — never touching process memory).
pub fn list_process_candidates(only_likely_proxy: bool) -> Vec<ProcessCandidate> {
    let refresh = RefreshKind::nothing().with_processes(
        ProcessRefreshKind::nothing()
            .with_cmd(UpdateKind::Always)
            .with_exe(UpdateKind::Always),
    );
    let system = System::new_with_specifics(refresh);
    let self_pids = crate::subscription::live_capture::collect_self_pid_tree(&system);

    let mut candidates: Vec<ProcessCandidate> = system
        .processes()
        .iter()
        .filter(|(pid, _)| !self_pids.contains(&pid.as_u32()))
        .map(|(pid, proc_info)| {
            let name = proc_info.name().to_string_lossy().into_owned();
            let exe_path = proc_info.exe().map(Path::to_path_buf);
            let cmdline: Vec<String> = proc_info
                .cmd()
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect();
            parse_process_cmdline(pid.as_u32(), name, exe_path, cmdline)
        })
        .filter(|c| !only_likely_proxy || c.likely_proxy_client)
        .collect();

    candidates.sort_by(|a, b| {
        b.likely_proxy_client
            .cmp(&a.likely_proxy_client)
            .then_with(|| a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()))
            .then_with(|| a.pid.cmp(&b.pid))
    });

    candidates
}

/// Pure read-only parser extracting `-d`, `-f`, `-ext-ctl`, and `--config` arguments
/// from a process command line and tagging whether it looks like a known open-source proxy client.
pub fn parse_process_cmdline(
    pid: u32,
    name: String,
    exe_path: Option<PathBuf>,
    cmdline: Vec<String>,
) -> ProcessCandidate {
    let mut detected_config_dir: Option<PathBuf> = None;
    let mut detected_config_file: Option<PathBuf> = None;
    let mut detected_controller_addr: Option<String> = None;

    let mut idx = 0usize;
    while idx < cmdline.len() {
        let arg = cmdline[idx].trim();
        let next_val = cmdline.get(idx + 1).map(|s| s.trim()).filter(|s| !s.is_empty());

        if arg == "-d" || arg == "--dir" {
            if let Some(val) = next_val {
                detected_config_dir = Some(PathBuf::from(strip_surrounding_quotes(val)));
                idx += 2;
                continue;
            }
        } else if let Some(val) = arg
            .strip_prefix("-d=")
            .or_else(|| arg.strip_prefix("--dir="))
        {
            let cleaned = strip_surrounding_quotes(val.trim());
            if !cleaned.is_empty() {
                detected_config_dir = Some(PathBuf::from(cleaned));
            }
        } else if arg == "-f" || arg == "-c" || arg == "--config" {
            if let Some(val) = next_val {
                detected_config_file = Some(PathBuf::from(strip_surrounding_quotes(val)));
                idx += 2;
                continue;
            }
        } else if let Some(val) = arg
            .strip_prefix("-f=")
            .or_else(|| arg.strip_prefix("-c="))
            .or_else(|| arg.strip_prefix("--config="))
        {
            let cleaned = strip_surrounding_quotes(val.trim());
            if !cleaned.is_empty() {
                detected_config_file = Some(PathBuf::from(cleaned));
            }
        } else if arg == "-ext-ctl" || arg == "--ext-ctl" || arg == "--external-controller" {
            if let Some(val) = next_val {
                let cleaned = strip_surrounding_quotes(val);
                if !cleaned.is_empty() {
                    detected_controller_addr = Some(cleaned.to_string());
                }
                idx += 2;
                continue;
            }
        } else if let Some(val) = arg
            .strip_prefix("-ext-ctl=")
            .or_else(|| arg.strip_prefix("--ext-ctl="))
            .or_else(|| arg.strip_prefix("--external-controller="))
        {
            let cleaned = strip_surrounding_quotes(val.trim());
            if !cleaned.is_empty() {
                detected_controller_addr = Some(cleaned.to_string());
            }
        }

        idx += 1;
    }

    // Resolve relative `-f` config file path against `-d` directory if both are present
    if let (Some(dir), Some(file)) = (&detected_config_dir, &detected_config_file) {
        if file.is_relative() {
            detected_config_file = Some(dir.join(file));
        }
    }

    let likely_proxy_client = is_likely_proxy_process(
        &name,
        exe_path.as_deref(),
        &cmdline,
        detected_controller_addr.is_some(),
    );

    ProcessCandidate {
        pid,
        name,
        exe_path,
        cmdline,
        detected_config_dir,
        detected_config_file,
        detected_controller_addr,
        likely_proxy_client,
    }
}

/// Inspect a selected `ProcessCandidate` in strict read-only mode using the default timeout.
///
/// Priority order:
/// 1. Readable plaintext YAML config containing at least one valid proxy node
/// 2. Public local Mihomo REST controller endpoint (`GET http://127.0.0.1:<port>/proxies`)
/// 3. Fallback `catcloud-adapter/v1` external script slot template
pub async fn inspect_process_source(candidate: &ProcessCandidate) -> ProcessInspectionResult {
    inspect_process_source_with_timeout(candidate, DEFAULT_CONTROLLER_PROBE_TIMEOUT).await
}

/// Inspect a selected `ProcessCandidate` in strict read-only mode with a custom HTTP timeout.
pub async fn inspect_process_source_with_timeout(
    candidate: &ProcessCandidate,
    probe_timeout: Duration,
) -> ProcessInspectionResult {
    let mut notes = Vec::new();
    let mut readable_yaml_file: Option<PathBuf> = None;
    let mut yaml_node_count = 0usize;
    let mut yaml_controller_hint: Option<String> = None;

    // 1. Check candidate plaintext YAML config files (read-only)
    for yaml_candidate in collect_candidate_yaml_files(candidate) {
        if !yaml_candidate.is_file() {
            continue;
        }
        let Ok(meta) = std::fs::metadata(&yaml_candidate) else {
            notes.push(format!(
                "could not read metadata for candidate config `{}`",
                yaml_candidate.display()
            ));
            continue;
        };
        if meta.len() > MAX_SUBSCRIPTION_BYTES as u64 {
            notes.push(format!(
                "skipped candidate config `{}` (size {} bytes exceeds 16 MiB limit)",
                yaml_candidate.display(),
                meta.len()
            ));
            continue;
        }
        let Ok(raw) = std::fs::read(&yaml_candidate) else {
            notes.push(format!(
                "candidate config `{}` is not readable",
                yaml_candidate.display()
            ));
            continue;
        };

        if yaml_controller_hint.is_none() {
            if let Ok(text) = std::str::from_utf8(&raw) {
                yaml_controller_hint = extract_controller_addr_from_yaml(text);
            }
        }

        match parse_subscription_payload("process_inspect", &raw, None) {
            Ok(parsed) if !parsed.nodes.is_empty() => {
                readable_yaml_file = Some(yaml_candidate.clone());
                yaml_node_count = parsed.nodes.len();
                notes.push(format!(
                    "parsed {} valid proxy node(s) from plaintext YAML `{}`",
                    yaml_node_count,
                    yaml_candidate.display()
                ));
                break;
            }
            Ok(_) => {
                notes.push(format!(
                    "candidate config `{}` contained 0 valid proxy nodes",
                    yaml_candidate.display()
                ));
            }
            Err(e) => {
                notes.push(format!(
                    "candidate config `{}` is not a standard plaintext proxy YAML: {e}",
                    yaml_candidate.display()
                ));
            }
        }
    }

    // 2. Check standard local loopback Mihomo REST controller endpoint
    let controller_raw = candidate
        .detected_controller_addr
        .as_deref()
        .or(yaml_controller_hint.as_deref());
    let controller_base_url = controller_raw.and_then(normalize_loopback_controller_base_url);
    let controller_proxies_url = controller_base_url
        .as_ref()
        .map(|base| format!("{base}/proxies"));

    if controller_raw.is_some() && controller_base_url.is_none() {
        notes.push(
            "ignored non-loopback or invalid controller address for local read-only inspection"
                .to_string(),
        );
    }

    let mut controller_reachable = false;
    let mut controller_requires_secret = false;
    let mut controller_proxy_count = 0usize;

    if let Some(ref proxies_url) = controller_proxies_url {
        match probe_local_mihomo_proxies(proxies_url, probe_timeout).await {
            ControllerProbeOutcome::PublicOk(count) => {
                controller_reachable = true;
                controller_requires_secret = false;
                controller_proxy_count = count;
                notes.push(format!(
                    "local Mihomo REST controller responded at `{proxies_url}` with {count} proxy entries"
                ));
            }
            ControllerProbeOutcome::RequiresSecret => {
                controller_reachable = true;
                controller_requires_secret = true;
                notes.push(format!(
                    "local controller at `{proxies_url}` requires a Bearer secret token"
                ));
            }
            ControllerProbeOutcome::Unavailable(reason) => {
                notes.push(format!(
                    "local controller probe at `{proxies_url}` unavailable: {reason}"
                ));
            }
        }
    }

    // 3. Build recommendation following strict priority order
    let recommendation = if let Some(ref yaml_path) = readable_yaml_file {
        AttachRecommendation::ReadOnlyLocalFile {
            path: yaml_path.clone(),
            node_count: yaml_node_count,
            reason: format!(
                "Detected readable plaintext YAML configuration ({yaml_node_count} valid nodes); bind as read-only local file source."
            ),
        }
    } else if controller_reachable {
        let endpoint = controller_proxies_url.clone().unwrap_or_default();
        let reason = if controller_requires_secret {
            "Detected local Mihomo REST controller requiring Bearer authentication; supply the configured secret to attach read-only.".to_string()
        } else {
            format!(
                "Detected open local Mihomo REST controller ({controller_proxy_count} proxy entries); bind to public controller API."
            )
        };
        AttachRecommendation::PublicControllerApi {
            endpoint_url: endpoint,
            proxy_count: controller_proxy_count,
            requires_secret: controller_requires_secret,
            reason,
        }
    } else {
        let template_script = render_adapter_template_script(&candidate.name);
        AttachRecommendation::ExternalAdapterTemplate {
            schema: ADAPTER_SCHEMA_V1.to_string(),
            suggested_command: "python3 /path/to/catcloud_adapter.py".to_string(),
            template_script,
            reason: "No readable plaintext YAML config or open local Mihomo REST controller was detected; configure a custom `catcloud-adapter/v1` external adapter script.".to_string(),
        }
    };

    ProcessInspectionResult {
        pid: candidate.pid,
        process_name: candidate.name.clone(),
        readable_yaml_file,
        yaml_node_count,
        controller_url: controller_proxies_url,
        controller_reachable,
        controller_requires_secret,
        controller_proxy_count,
        recommendation,
        notes,
    }
}

/// Normalize a local controller address (`127.0.0.1:9090`, `0.0.0.0:9090`, `:9090`,
/// `localhost:9090`, `[::1]:9090`, or `http://127.0.0.1:9090`) to `http://127.0.0.1:<port>`.
/// Returns `None` for non-loopback remote hosts to ensure probes never leave the local machine.
pub fn normalize_loopback_controller_base_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }

    if let Some(port_str) = trimmed.strip_prefix(':') {
        let port: u16 = port_str.parse().ok()?;
        return (port > 0).then(|| format!("http://127.0.0.1:{port}"));
    }

    let with_scheme = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };

    let parsed = Url::parse(&with_scheme).ok()?;
    if parsed.scheme() != "http" {
        return None;
    }
    let host = parsed
        .host_str()?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let is_local_bind = matches!(host.as_str(), "127.0.0.1" | "localhost" | "0.0.0.0" | "::1" | "::");
    if !is_local_bind {
        return None;
    }

    let port = parsed.port()?;
    if port == 0 {
        return None;
    }

    Some(format!("http://127.0.0.1:{port}"))
}

/// Parse a Mihomo/Clash REST controller `GET /proxies` JSON payload into normalized `ProxyNode`s.
///
/// Returns `(connectable_nodes, metadata_only_count, total_entries, warnings)`.
/// Standard Mihomo `/proxies` endpoints often omit `server`/`port` credentials for security;
/// callers can inspect `metadata_only_count` to surface a clear explanation when no directly
/// connectable node fields are exposed.
pub fn parse_controller_proxies_json(
    sub_id: &str,
    raw_json: &[u8],
) -> CatResult<(Vec<ProxyNode>, usize, usize, Vec<String>)> {
    if raw_json.len() > MAX_SUBSCRIPTION_BYTES {
        return Err(CatError::Validation(format!(
            "控制接口返回数据超过 16 MiB 上限（{} 字节）",
            raw_json.len()
        )));
    }
    let val: serde_json::Value = serde_json::from_slice(raw_json)
        .map_err(|e| CatError::Validation(format!("控制接口返回内容不是有效 JSON：{e}")))?;
    let Some(proxies_map) = val.get("proxies").and_then(serde_json::Value::as_object) else {
        return Err(CatError::Validation(
            "控制接口返回数据缺少 `proxies` 字段".to_string(),
        ));
    };

    let mut nodes = Vec::new();
    let mut meta_only_count = 0usize;
    let mut warnings = Vec::new();
    let mut used_ids = HashSet::new();

    for (key_name, entry) in proxies_map {
        let upper = key_name.to_ascii_uppercase();
        if matches!(
            upper.as_str(),
            "DIRECT" | "REJECT" | "REJECT-DROP" | "PASS" | "COMPATIBLE" | "GLOBAL"
        ) {
            continue;
        }
        let Some(obj) = entry.as_object() else {
            continue;
        };
        let kind = obj
            .get("type")
            .or_else(|| obj.get("protocol"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if kind.is_empty()
            || matches!(
                kind.as_str(),
                "selector"
                    | "urltest"
                    | "fallback"
                    | "loadbalance"
                    | "relay"
                    | "direct"
                    | "reject"
                    | "compatible"
                    | "pass"
            )
        {
            continue;
        }

        let has_server = obj
            .get("server")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|s| !s.trim().is_empty());
        let has_port = obj
            .get("port")
            .and_then(json_to_u16)
            .is_some_and(|p| p > 0);

        if !has_server || !has_port {
            meta_only_count += 1;
            continue;
        }

        let mut normalized = obj.clone();
        if !normalized.contains_key("name") {
            normalized.insert("name".to_string(), serde_json::Value::String(key_name.clone()));
        }
        match node_from_clash_json(sub_id, &normalized, &mut used_ids) {
            Ok(node) => nodes.push(node),
            Err(reason) => warnings.push(format!("跳过节点「{key_name}」：{reason}")),
        }
    }

    Ok((nodes, meta_only_count, proxies_map.len(), warnings))
}

enum ControllerProbeOutcome {
    PublicOk(usize),
    RequiresSecret,
    Unavailable(String),
}

async fn probe_local_mihomo_proxies(
    proxies_url: &str,
    timeout: Duration,
) -> ControllerProbeOutcome {
    let client = match reqwest::Client::builder()
        .no_proxy()
        .timeout(timeout)
        .connect_timeout(timeout)
        .build()
    {
        Ok(c) => c,
        Err(e) => return ControllerProbeOutcome::Unavailable(format!("client init failed: {e}")),
    };

    let mut resp = match client.get(proxies_url).send().await {
        Ok(r) => r,
        Err(e) => return ControllerProbeOutcome::Unavailable(e.to_string()),
    };

    let status = resp.status();
    if status.as_u16() == 401 || status.as_u16() == 403 {
        return ControllerProbeOutcome::RequiresSecret;
    }
    if !status.is_success() {
        return ControllerProbeOutcome::Unavailable(format!("HTTP {}", status.as_u16()));
    }
    if let Some(len) = resp.content_length() {
        if len > MAX_CONTROLLER_PROBE_BYTES as u64 {
            return ControllerProbeOutcome::Unavailable(
                "response exceeds 8 MiB inspection bound".to_string(),
            );
        }
    }

    let mut body = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if body.len().saturating_add(chunk.len()) > MAX_CONTROLLER_PROBE_BYTES {
                    return ControllerProbeOutcome::Unavailable(
                        "response exceeded 8 MiB inspection bound".to_string(),
                    );
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(e) => {
                return ControllerProbeOutcome::Unavailable(format!(
                    "failed to read response stream: {e}"
                ));
            }
        }
    }

    let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return ControllerProbeOutcome::Unavailable("response is not valid JSON".to_string());
    };
    let Some(proxies_map) = json_val
        .get("proxies")
        .and_then(serde_json::Value::as_object)
    else {
        return ControllerProbeOutcome::Unavailable(
            "JSON response missing `proxies` object".to_string(),
        );
    };

    let non_builtin_count = proxies_map
        .iter()
        .filter(|(k, v)| {
            let upper = k.to_ascii_uppercase();
            if matches!(
                upper.as_str(),
                "DIRECT" | "REJECT" | "REJECT-DROP" | "PASS" | "COMPATIBLE" | "GLOBAL"
            ) {
                return false;
            }
            let kind = v
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_ascii_lowercase();
            !matches!(
                kind.as_str(),
                "selector" | "urltest" | "fallback" | "loadbalance" | "direct" | "reject" | "compatible" | "pass"
            )
        })
        .count();

    let count = if non_builtin_count > 0 {
        non_builtin_count
    } else {
        proxies_map.len()
    };

    ControllerProbeOutcome::PublicOk(count)
}

fn collect_candidate_yaml_files(candidate: &ProcessCandidate) -> Vec<PathBuf> {
    let mut files = Vec::new();

    if let Some(ref explicit_file) = candidate.detected_config_file {
        files.push(explicit_file.clone());
    }
    if let Some(ref dir) = candidate.detected_config_dir {
        for filename in ["config.yaml", "config.yml", "clash.yaml", "runtime.yaml"] {
            let path = dir.join(filename);
            if !files.contains(&path) {
                files.push(path);
            }
        }
    }
    if files.is_empty() {
        if let Some(parent) = candidate.exe_path.as_deref().and_then(Path::parent) {
            files.push(parent.join("config.yaml"));
        }
    }

    files
}

fn extract_controller_addr_from_yaml(text: &str) -> Option<String> {
    let yaml_val = parse_clash_yaml_value(text).ok()?;
    let map = yaml_val.as_mapping()?;
    map.get(serde_yaml_ng::Value::String(
        "external-controller".to_string(),
    ))
    .and_then(serde_yaml_ng::Value::as_str)
    .map(str::trim)
    .filter(|s| !s.is_empty())
    .map(ToOwned::to_owned)
}

fn is_likely_proxy_process(
    name: &str,
    exe_path: Option<&Path>,
    cmdline: &[String],
    has_ext_ctl: bool,
) -> bool {
    if has_ext_ctl {
        return true;
    }

    const KNOWN_KEYWORDS: &[&str] = &[
        "mihomo",
        "clash",
        "sing-box",
        "xray",
        "v2ray",
        "hysteria",
        "tuic",
    ];

    let name_lower = name.to_ascii_lowercase();
    if KNOWN_KEYWORDS.iter().any(|kw| name_lower.contains(kw)) {
        return true;
    }

    if let Some(exe) = exe_path {
        let exe_lower = exe.to_string_lossy().to_ascii_lowercase();
        if KNOWN_KEYWORDS.iter().any(|kw| exe_lower.contains(kw)) {
            return true;
        }
    }

    cmdline.iter().any(|arg| {
        let lower = arg.to_ascii_lowercase();
        lower == "-ext-ctl"
            || lower.starts_with("-ext-ctl=")
            || lower.contains("mihomo")
            || lower.contains("clash")
    })
}

fn strip_surrounding_quotes(s: &str) -> &str {
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}
