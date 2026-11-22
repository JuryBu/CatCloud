use crate::error::{CatError, CatResult};
use crate::models::ProxyNode;
use crate::process_guard::JobGuard;
use crate::subscription::parser::{
    MAX_SUBSCRIPTION_BYTES, build_proxy_node, json_to_u16, node_from_clash_json,
    parse_proxy_uri_line, parse_subscription_payload, stable_node_id,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

/// Schema identifier required in every external adapter response.
pub const ADAPTER_SCHEMA_V1: &str = "catcloud-adapter/v1";

/// Minimum refresh cooldown enforced to prevent external adapter execution storms.
pub const MIN_ADAPTER_COOLDOWN_SEC: u64 = 60;

/// Default execution timeout for external adapter commands.
pub const DEFAULT_ADAPTER_TIMEOUT_SEC: u64 = 30;

/// Hard upper bound on external adapter `stdout` payload (16 MiB).
pub const MAX_ADAPTER_STDOUT_BYTES: usize = MAX_SUBSCRIPTION_BYTES;

/// Upper bound on captured `stderr` bytes for diagnostic messages (64 KiB).
pub const MAX_ADAPTER_STDERR_BYTES: usize = 64 * 1024;

/// Common standard reason strings sent in `AdapterRequest.reason`.
pub const ADAPTER_REASON_MANUAL: &str = "manual";
pub const ADAPTER_REASON_SCHEDULED: &str = "scheduled";
pub const ADAPTER_REASON_FAILOVER: &str = "failover";

/// JSON request payload written to the external adapter process `stdin`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterRequest {
    pub reason: String,
    pub sub_id: String,
    #[serde(default)]
    pub failed_servers: Vec<String>,
}

impl AdapterRequest {
    pub fn new(
        reason: impl Into<String>,
        sub_id: impl Into<String>,
        failed_servers: Vec<String>,
    ) -> Self {
        Self {
            reason: reason.into(),
            sub_id: sub_id.into(),
            failed_servers,
        }
    }
}

/// JSON response payload read from the external adapter process `stdout`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct AdapterResponse {
    pub schema: String,
    pub nodes: Vec<serde_json::Value>,
    pub yaml: Option<String>,
}

/// Execution configuration for a user-supplied `catcloud-adapter/v1` external command.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AdapterConfig {
    pub program: String,
    pub args: Vec<String>,
    pub working_dir: Option<PathBuf>,
    pub env: BTreeMap<String, String>,
    pub timeout_sec: u64,
    pub min_refresh_cooldown_sec: u64,
}

impl Default for AdapterConfig {
    fn default() -> Self {
        Self {
            program: String::new(),
            args: Vec::new(),
            working_dir: None,
            env: BTreeMap::new(),
            timeout_sec: DEFAULT_ADAPTER_TIMEOUT_SEC,
            min_refresh_cooldown_sec: MIN_ADAPTER_COOLDOWN_SEC,
        }
    }
}

impl AdapterConfig {
    /// Parse a single command-line string (supporting single/double quotes while preserving
    /// Windows drive backslashes) into an `AdapterConfig`.
    pub fn from_command_line(cmdline: &str) -> CatResult<Self> {
        let tokens = split_command_line(cmdline)?;
        let Some((program, rest)) = tokens.split_first() else {
            return Err(CatError::Validation(
                "adapter command line cannot be empty".to_string(),
            ));
        };
        Ok(Self {
            program: program.clone(),
            args: rest.to_vec(),
            ..Self::default()
        })
    }

    /// Validate adapter command, timeout bounds, and minimum anti-storm cooldown (`>= 60s`).
    pub fn validate(&self) -> CatResult<()> {
        if self.program.trim().is_empty() {
            return Err(CatError::Validation(
                "adapter program path cannot be empty".to_string(),
            ));
        }
        if !(1..=300).contains(&self.timeout_sec) {
            return Err(CatError::Validation(format!(
                "adapter timeout_sec ({}) must be within 1..=300 seconds",
                self.timeout_sec
            )));
        }
        if self.min_refresh_cooldown_sec < MIN_ADAPTER_COOLDOWN_SEC {
            return Err(CatError::Validation(format!(
                "adapter min_refresh_cooldown_sec ({}) must be >= {} seconds",
                self.min_refresh_cooldown_sec, MIN_ADAPTER_COOLDOWN_SEC
            )));
        }
        Ok(())
    }

    /// Effective anti-storm cooldown clamped to at least `MIN_ADAPTER_COOLDOWN_SEC` (60s).
    pub fn effective_cooldown(&self) -> Duration {
        Duration::from_secs(self.min_refresh_cooldown_sec.max(MIN_ADAPTER_COOLDOWN_SEC))
    }
}

/// Per-subscription cooldown tracker preventing rapid repeated adapter invocations.
#[derive(Debug, Default)]
pub struct AdapterCooldownGuard {
    last_invoked: Mutex<HashMap<String, Instant>>,
}

impl AdapterCooldownGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check whether `sub_id` is outside its cooldown window; if allowed, mark it invoked now.
    /// Returns `Err(remaining)` if still cooling down.
    pub fn check_and_mark(&self, sub_id: &str, cooldown: Duration) -> Result<(), Duration> {
        self.check_and_mark_at(sub_id, cooldown, Instant::now())
    }

    /// Deterministic timestamp-injected variant of `check_and_mark` for unit testing.
    pub fn check_and_mark_at(
        &self,
        sub_id: &str,
        cooldown: Duration,
        now: Instant,
    ) -> Result<(), Duration> {
        let enforced = cooldown.max(Duration::from_secs(MIN_ADAPTER_COOLDOWN_SEC));
        let mut guard = self
            .last_invoked
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(&prev) = guard.get(sub_id) {
            let elapsed = now.saturating_duration_since(prev);
            if elapsed < enforced {
                return Err(enforced.saturating_sub(elapsed));
            }
        }
        guard.insert(sub_id.to_string(), now);
        Ok(())
    }

    /// Inspect remaining cooldown duration for `sub_id`, if any.
    pub fn remaining_cooldown(&self, sub_id: &str, cooldown: Duration) -> Option<Duration> {
        self.remaining_cooldown_at(sub_id, cooldown, Instant::now())
    }

    pub fn remaining_cooldown_at(
        &self,
        sub_id: &str,
        cooldown: Duration,
        now: Instant,
    ) -> Option<Duration> {
        let enforced = cooldown.max(Duration::from_secs(MIN_ADAPTER_COOLDOWN_SEC));
        let guard = self
            .last_invoked
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prev = *guard.get(sub_id)?;
        let elapsed = now.saturating_duration_since(prev);
        (elapsed < enforced).then(|| enforced.saturating_sub(elapsed))
    }

    /// Clear recorded cooldown state for a subscription.
    pub fn reset(&self, sub_id: &str) {
        let mut guard = self
            .last_invoked
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        guard.remove(sub_id);
    }
}

/// Parse and validate raw `stdout` bytes from a `catcloud-adapter/v1` executable.
///
/// Enforces:
/// - Payload size `<= MAX_ADAPTER_STDOUT_BYTES` (16 MiB)
/// - `schema == "catcloud-adapter/v1"`
/// - At least one valid `ProxyNode` extracted from `nodes` and/or `yaml`
pub fn parse_adapter_response(sub_id: &str, raw_stdout: &[u8]) -> CatResult<Vec<ProxyNode>> {
    if sub_id.trim().is_empty() {
        return Err(CatError::Validation(
            "adapter sub_id cannot be empty".to_string(),
        ));
    }
    if raw_stdout.len() > MAX_ADAPTER_STDOUT_BYTES {
        return Err(CatError::Validation(format!(
            "adapter stdout size {} bytes exceeds maximum allowed {} bytes",
            raw_stdout.len(),
            MAX_ADAPTER_STDOUT_BYTES
        )));
    }

    let text_raw = std::str::from_utf8(raw_stdout)
        .map_err(|e| CatError::Validation(format!("adapter stdout is not valid UTF-8: {e}")))?;
    let text = text_raw.strip_prefix('\u{FEFF}').unwrap_or(text_raw).trim();
    if text.is_empty() {
        return Err(CatError::Validation(
            "adapter returned empty stdout".to_string(),
        ));
    }

    let response: AdapterResponse = serde_json::from_str(text)?;
    if response.schema.trim() != ADAPTER_SCHEMA_V1 {
        return Err(CatError::Validation(format!(
            "unsupported adapter response schema `{}` (expected `{}`)",
            response.schema, ADAPTER_SCHEMA_V1
        )));
    }

    let mut nodes = Vec::new();
    let mut used_ids = HashSet::new();

    for entry in &response.nodes {
        match entry {
            serde_json::Value::Object(obj) => {
                if let Ok(node) = convert_adapter_node_object(sub_id, obj, &mut used_ids) {
                    nodes.push(node);
                }
            }
            serde_json::Value::String(uri_line) => {
                if let Ok(node) = parse_proxy_uri_line(sub_id, uri_line, &mut used_ids) {
                    nodes.push(node);
                }
            }
            _ => {}
        }
    }

    if let Some(ref yaml_text) = response.yaml {
        let trimmed_yaml = yaml_text.trim();
        if !trimmed_yaml.is_empty() {
            let parsed = parse_subscription_payload(sub_id, trimmed_yaml.as_bytes(), None)?;
            for mut node in parsed.nodes {
                if !used_ids.insert(node.id.clone()) {
                    node.id = stable_node_id(
                        sub_id,
                        &node.protocol,
                        &node.server,
                        node.port,
                        &node.name,
                        &mut used_ids,
                    );
                }
                nodes.push(node);
            }
        }
    }

    if nodes.is_empty() {
        return Err(CatError::Validation(
            "adapter response validated schema but produced 0 valid proxy nodes".to_string(),
        ));
    }

    Ok(nodes)
}

/// Execute a user-configured external `catcloud-adapter/v1` command asynchronously.
///
/// - Enforces `min_refresh_cooldown_sec >= 60` via `cooldown_guard` when supplied.
/// - Passes `AdapterRequest` JSON via `stdin` and closes `stdin` for clean EOF.
/// - Reads bounded `stdout` (`<= 16 MiB`) and bounded `stderr` concurrently under `timeout_sec`.
/// - Guarantees child termination on timeout or oversized output (`kill_on_drop(true)` + explicit kill).
pub async fn invoke_external_adapter(
    config: &AdapterConfig,
    request: &AdapterRequest,
    cooldown_guard: Option<&AdapterCooldownGuard>,
) -> CatResult<Vec<ProxyNode>> {
    config.validate()?;
    if request.sub_id.trim().is_empty() {
        return Err(CatError::Validation(
            "adapter request sub_id cannot be empty".to_string(),
        ));
    }

    if let Some(guard) = cooldown_guard {
        if let Err(remaining) = guard.check_and_mark(&request.sub_id, config.effective_cooldown()) {
            return Err(CatError::Validation(format!(
                "adapter refresh cooldown active for `{}`: wait {}s before retrying",
                request.sub_id,
                remaining.as_secs().max(1)
            )));
        }
    }

    let req_bytes = serde_json::to_vec(request)?;

    let mut cmd = Command::new(&config.program);
    cmd.args(&config.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    if let Some(ref cwd) = config.working_dir {
        cmd.current_dir(cwd);
    }
    if !config.env.is_empty() {
        cmd.envs(&config.env);
    }
    JobGuard::configure_tokio_command(&mut cmd);

    let mut child = cmd.spawn().map_err(|e| {
        CatError::Process(format!(
            "failed to spawn external adapter `{}`: {e}",
            config.program
        ))
    })?;

    let stdin_pipe = child.stdin.take();
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let run_timeout = Duration::from_secs(config.timeout_sec);
    let outcome: Result<CatResult<(std::process::ExitStatus, Vec<u8>, Vec<u8>)>, _> =
        tokio::time::timeout(run_timeout, async {
            let write_fut = async move {
                if let Some(mut writer) = stdin_pipe {
                    if let Err(e) = writer.write_all(&req_bytes).await {
                        if e.kind() != std::io::ErrorKind::BrokenPipe {
                            return Err(e);
                        }
                    }
                    let _ = writer.shutdown().await;
                }
                Ok::<(), std::io::Error>(())
            };

            let stdout_fut = async move {
                let mut buf = Vec::new();
                if let Some(reader) = stdout_pipe {
                    let mut limited = reader.take((MAX_ADAPTER_STDOUT_BYTES as u64) + 1);
                    limited.read_to_end(&mut buf).await?;
                }
                Ok::<Vec<u8>, std::io::Error>(buf)
            };

            let stderr_fut = async move {
                let mut buf = Vec::new();
                if let Some(reader) = stderr_pipe {
                    let mut limited = reader.take((MAX_ADAPTER_STDERR_BYTES as u64) + 1);
                    limited.read_to_end(&mut buf).await?;
                }
                Ok::<Vec<u8>, std::io::Error>(buf)
            };

            let (write_res, stdout_res, stderr_res) =
                tokio::join!(write_fut, stdout_fut, stderr_fut);
            write_res?;
            let stdout_bytes = stdout_res?;
            let stderr_bytes = stderr_res?;

            if stdout_bytes.len() > MAX_ADAPTER_STDOUT_BYTES {
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Err(CatError::Validation(format!(
                    "adapter stdout exceeded maximum allowed {} bytes",
                    MAX_ADAPTER_STDOUT_BYTES
                )));
            }

            let status = child.wait().await?;
            Ok((status, stdout_bytes, stderr_bytes))
        })
        .await;

    let (status, stdout_bytes, stderr_bytes) = match outcome {
        Ok(res) => res?,
        Err(_) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(CatError::Process(format!(
                "external adapter `{}` timed out after {}s",
                config.program, config.timeout_sec
            )));
        }
    };

    if !status.success() {
        let stderr_summary = String::from_utf8_lossy(&stderr_bytes);
        let snippet = stderr_summary.trim();
        let detail = if snippet.is_empty() {
            format!("exit status {status}")
        } else {
            format!("exit status {status}: {snippet}")
        };
        return Err(CatError::Process(format!(
            "external adapter `{}` failed ({detail})",
            config.program
        )));
    }

    parse_adapter_response(&request.sub_id, &stdout_bytes)
}

/// Generate a clean, sanitized `catcloud-adapter/v1` starter script template
/// using RFC 5737 documentation IP addresses.
pub fn render_adapter_template_script(target_label: &str) -> String {
    let safe_label = target_label
        .chars()
        .filter(|c| !c.is_control() && *c != '"' && *c != '\\')
        .take(64)
        .collect::<String>();
    let display_label = if safe_label.is_empty() {
        "custom-source"
    } else {
        safe_label.as_str()
    };

    format!(
        r#"#!/usr/bin/env python3
"""
CatCloud external subscription adapter template (catcloud-adapter/v1).
Target hint: {display_label}

Contract:
  - Read JSON request from stdin: {{"reason", "sub_id", "failed_servers"}}
  - Print JSON response to stdout (<= 16 MiB):
    {{"schema": "catcloud-adapter/v1", "nodes": [...], "yaml": null}}
"""
import json
import sys


def main() -> None:
    raw_req = sys.stdin.read().strip()
    req = json.loads(raw_req) if raw_req else {{}}
    _reason = req.get("reason", "manual")
    _sub_id = req.get("sub_id", "adapter")
    _failed = set(req.get("failed_servers") or [])

    # Replace the sample node below with your own dynamic node source.
    response = {{
        "schema": "{schema}",
        "nodes": [
            {{
                "name": "JP Sample 1x",
                "type": "vless",
                "server": "203.0.113.10",
                "port": 443,
                "uuid": "00000000-0000-4000-8000-000000000001",
                "tls": True,
                "servername": "node.example.invalid",
                "udp": True,
            }}
        ],
        "yaml": None,
    }}
    sys.stdout.write(json.dumps(response, ensure_ascii=False))


if __name__ == "__main__":
    main()
"#,
        display_label = display_label,
        schema = ADAPTER_SCHEMA_V1
    )
}

fn convert_adapter_node_object(
    sub_id: &str,
    obj: &serde_json::Map<String, serde_json::Value>,
    used_ids: &mut HashSet<String>,
) -> Result<ProxyNode, String> {
    // Support both raw Clash/Mihomo node objects and pre-structured CatCloud ProxyNode objects
    if let Some(raw_cfg_obj) = obj
        .get("raw_config")
        .or_else(|| obj.get("raw_json"))
        .and_then(serde_json::Value::as_object)
    {
        let mut merged = raw_cfg_obj.clone();
        if !merged.contains_key("name") {
            if let Some(name) = obj.get("name") {
                merged.insert("name".into(), name.clone());
            }
        }
        if !merged.contains_key("type") {
            if let Some(proto) = obj.get("protocol").or_else(|| obj.get("type")) {
                merged.insert("type".into(), proto.clone());
            }
        }
        if !merged.contains_key("server") {
            if let Some(server) = obj.get("server") {
                merged.insert("server".into(), server.clone());
            }
        }
        if !merged.contains_key("port") {
            if let Some(port) = obj.get("port") {
                merged.insert("port".into(), port.clone());
            }
        }

        let mut node = node_from_clash_json(sub_id, &merged, used_ids)?;
        if let Some(region) = obj
            .get("region_code")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            node.region_code = region.to_ascii_uppercase();
        }
        if let Some(mult) = obj
            .get("multiplier")
            .and_then(serde_json::Value::as_f64)
            .filter(|v| v.is_finite() && *v >= 0.0)
        {
            node.multiplier = mult;
        }
        if let Some(tags) = obj.get("tags").and_then(serde_json::Value::as_array) {
            for tag in tags.iter().filter_map(serde_json::Value::as_str) {
                let t = tag.trim();
                if !t.is_empty() && !node.tags.iter().any(|existing| existing == t) {
                    node.tags.push(t.to_string());
                }
            }
        }
        return Ok(node);
    }

    // Standard Clash/Mihomo proxy mapping or minimal `{name, protocol/type, server, port}`
    if obj.get("type").is_some() {
        return node_from_clash_json(sub_id, obj, used_ids);
    }

    let protocol = obj
        .get("protocol")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "adapter node missing `type`/`protocol`".to_string())?
        .to_string();
    let server = obj
        .get("server")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "adapter node missing `server`".to_string())?
        .to_string();
    let port = obj
        .get("port")
        .and_then(json_to_u16)
        .filter(|&p| p > 0)
        .ok_or_else(|| "adapter node missing valid `port`".to_string())?;
    let name = obj
        .get("name")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("{protocol}-{server}:{port}"));

    let mut normalized = obj.clone();
    normalized.insert("name".into(), serde_json::json!(name));
    normalized.insert("type".into(), serde_json::json!(protocol));
    normalized.insert("server".into(), serde_json::json!(server));
    normalized.insert("port".into(), serde_json::json!(port));

    Ok(build_proxy_node(
        sub_id,
        name,
        protocol,
        server,
        port,
        serde_json::Value::Object(normalized),
        used_ids,
    ))
}

fn split_command_line(input: &str) -> CatResult<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '\'' if !in_double => {
                in_single = !in_single;
            }
            '"' if !in_single => {
                in_double = !in_double;
            }
            '\\' if in_double && matches!(chars.peek(), Some('"')) => {
                if let Some(escaped) = chars.next() {
                    current.push(escaped);
                }
            }
            c if c.is_whitespace() && !in_single && !in_double => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            other => current.push(other),
        }
    }

    if in_single || in_double {
        return Err(CatError::Validation(
            "unterminated quote in adapter command line".to_string(),
        ));
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Ok(tokens)
}
