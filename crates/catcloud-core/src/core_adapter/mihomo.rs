use crate::core_adapter::port_guard::PortShiftNotice;
use crate::core_adapter::stream_client::{MihomoStreamClient, RawConnectionsResponse};
use crate::core_adapter::{
    BoxFuture, ConnectionsSnapshot, CoreAdapter, CoreRuntimeStatus, CoreStartRequest, ReloadLevel,
    format_http_base_url, percent_encode_path_segment,
};
use crate::error::{CatError, CatResult};
use crate::models::{CoreKind, ProxyMode};
use crate::process_guard::JobGuard;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use url::Url;

/// Maximum wait window for Mihomo's external controller to come online after spawning.
const STARTUP_READY_TIMEOUT: Duration = Duration::from_secs(6);

/// Polling interval while waiting for `/version` during core startup.
const STARTUP_POLL_INTERVAL: Duration = Duration::from_millis(80);

/// Hard upper limit (64 KiB) for captured stdout/stderr during `mihomo -t` config verification.
const MAX_VERIFY_OUTPUT_BYTES: usize = 64 * 1024;

/// Maximum trailing stderr bytes attached to startup failure diagnostics.
const MAX_STARTUP_STDERR_TAIL_BYTES: usize = 4 * 1024;

/// Filename under `working_dir` capturing Mihomo stderr without blocking pipes.
const MIHOMO_STDERR_LOG_FILENAME: &str = "mihomo-stderr.log";

/// Generate a cryptographically secure 32-byte controller secret encoded as 64 lowercase hex chars.
pub fn generate_controller_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes[..]);
    hex::encode(bytes)
}

#[derive(Debug)]
struct MihomoRuntimeState {
    child: Option<Child>,
    pid: Option<u32>,
    binary_path: Option<PathBuf>,
    config_path: Option<PathBuf>,
    working_dir: Option<PathBuf>,
    bind_host: String,
    mixed_port: u16,
    controller_host: String,
    controller_port: u16,
    dns_listen_port: u16,
    controller_secret: String,
    proxy_mode: ProxyMode,
    version: Option<String>,
    started_at: Option<DateTime<Utc>>,
    started_instant: Option<Instant>,
    rule_count: usize,
    node_count: usize,
    shifted_ports: Vec<PortShiftNotice>,
    active_selections: BTreeMap<String, String>,
    last_reload_at: Option<String>,
    last_reload_level: Option<ReloadLevel>,
    last_error: Option<String>,
    external_endpoint_configured: bool,
}

impl Default for MihomoRuntimeState {
    fn default() -> Self {
        Self {
            child: None,
            pid: None,
            binary_path: None,
            config_path: None,
            working_dir: None,
            bind_host: "127.0.0.1".to_string(),
            mixed_port: 7890,
            controller_host: "127.0.0.1".to_string(),
            controller_port: 9090,
            dns_listen_port: 1053,
            controller_secret: generate_controller_secret(),
            proxy_mode: ProxyMode::Rule,
            version: None,
            started_at: None,
            started_instant: None,
            rule_count: 0,
            node_count: 0,
            shifted_ports: Vec::new(),
            active_selections: BTreeMap::new(),
            last_reload_at: None,
            last_reload_level: None,
            last_error: None,
            external_endpoint_configured: false,
        }
    }
}

/// Production Mihomo core adapter managing subprocess lifecycle via `JobGuard`
/// and authenticated `.no_proxy()` REST controller communication.
#[derive(Debug, Clone)]
pub struct MihomoAdapter {
    job_guard: Arc<JobGuard>,
    http: reqwest::Client,
    state: Arc<Mutex<MihomoRuntimeState>>,
    op_lock: Arc<Mutex<()>>,
}

impl MihomoAdapter {
    /// Create a new `MihomoAdapter` backed by the process-wide `JobGuard`.
    pub fn new(job_guard: Arc<JobGuard>) -> CatResult<Self> {
        let http = build_controller_http_client()?;
        Ok(Self {
            job_guard,
            http,
            state: Arc::new(Mutex::new(MihomoRuntimeState::default())),
            op_lock: Arc::new(Mutex::new(())),
        })
    }

    /// Create an adapter pre-bound to an existing controller endpoint (used for external
    /// controller attachment and deterministic mock-server integration tests).
    pub fn with_controller_endpoint(
        job_guard: Arc<JobGuard>,
        host: impl Into<String>,
        port: u16,
        secret: impl Into<String>,
    ) -> CatResult<Self> {
        let http = build_controller_http_client()?;
        let state = MihomoRuntimeState {
            controller_host: host.into(),
            controller_port: port,
            controller_secret: secret.into(),
            external_endpoint_configured: true,
            ..Default::default()
        };
        Ok(Self {
            job_guard,
            http,
            state: Arc::new(Mutex::new(state)),
            op_lock: Arc::new(Mutex::new(())),
        })
    }

    /// Snapshot the current controller secret used for Bearer authentication.
    pub async fn controller_secret(&self) -> String {
        let guard = self.state.lock().await;
        guard.controller_secret.clone()
    }

    /// Snapshot the currently recorded `select` group proxy selections.
    pub async fn active_selections_snapshot(&self) -> BTreeMap<String, String> {
        let guard = self.state.lock().await;
        guard.active_selections.clone()
    }

    /// Return whether either a managed child is alive or an external controller endpoint is bound.
    pub async fn has_live_controller(&self) -> bool {
        let mut guard = self.state.lock().await;
        if let Some(child) = guard.child.as_mut() {
            match child.try_wait() {
                Ok(None) => return true,
                Ok(Some(_)) | Err(_) => {
                    guard.child = None;
                    guard.pid = None;
                }
            }
        }
        guard.external_endpoint_configured
    }

    /// Build a matching `MihomoStreamClient` targeting the active controller endpoint and secret.
    pub async fn stream_client(&self) -> CatResult<MihomoStreamClient> {
        let guard = self.state.lock().await;
        MihomoStreamClient::new(
            &guard.controller_host,
            guard.controller_port,
            guard.controller_secret.clone(),
        )
    }

    /// Launch (or restart) the managed Mihomo subprocess with adaptive `GOMEMLIMIT` + `GOGC`,
    /// immediately assign it to `JobGuard` for zero-zombie cleanup, wait for controller readiness,
    /// and replay persisted `select` group choices.
    pub async fn start_with_request(&self, req: CoreStartRequest) -> CatResult<CoreRuntimeStatus> {
        let _op_guard = self.op_lock.lock().await;

        if !req.binary_path.is_file() {
            return Err(CatError::NotFound(format!(
                "Mihomo binary not found at `{}`",
                req.binary_path.display()
            )));
        }
        if !req.config_path.is_file() {
            return Err(CatError::NotFound(format!(
                "Mihomo config file not found at `{}`",
                req.config_path.display()
            )));
        }
        std::fs::create_dir_all(&req.working_dir)?;

        // Ensure any previous child process is cleanly terminated before spawning a new one.
        self.stop_process_unlocked().await?;

        let gomemlimit = req.config.resolve_gomemlimit(req.node_count, req.rule_count);
        let gogc = req.config.core_runtime.gogc.to_string();

        let norm_bin = crate::paths::normalize_os_path(&req.binary_path);
        let norm_work = crate::paths::normalize_os_path(&req.working_dir);
        let norm_cfg = crate::paths::normalize_os_path(&req.config_path);
        let stderr_log_path = req.working_dir.join(MIHOMO_STDERR_LOG_FILENAME);
        let (stderr_stdio, stderr_captured) = open_mihomo_stderr_stdio(&stderr_log_path);

        let mut cmd = Command::new(&norm_bin);
        cmd.arg("-d")
            .arg(&norm_work)
            .arg("-f")
            .arg(&norm_cfg)
            .env("GOMEMLIMIT", gomemlimit)
            .env("GOGC", &gogc)
            .env("GODEBUG", "madvdontneed=1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr_stdio)
            .kill_on_drop(true);
        JobGuard::configure_tokio_command(&mut cmd);

        let mut child = cmd.spawn().map_err(|e| {
            CatError::Process(format!(
                "failed to spawn Mihomo `{}`: {e}",
                req.binary_path.display()
            ))
        })?;

        if let Err(err) = self.job_guard.assign_tokio_child(&mut child) {
            let _ = child.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
            return Err(err);
        }

        let pid = child.id();
        let now_utc = Utc::now();
        let now_instant = Instant::now();

        // Defensively drain any lingering previous child before installing the new handle.
        let stale_child = {
            let mut guard = self.state.lock().await;
            (guard.child.take(), guard.pid.take())
        };
        if let (Some(mut old_child), old_pid) = stale_child {
            let _ = old_child.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(3), old_child.wait()).await;
            if let Some(p) = old_pid {
                self.job_guard.unregister_pid(p);
            }
        }

        {
            let mut guard = self.state.lock().await;
            guard.child = Some(child);
            guard.pid = pid;
            guard.binary_path = Some(req.binary_path.clone());
            guard.config_path = Some(req.config_path.clone());
            guard.working_dir = Some(req.working_dir.clone());
            guard.bind_host = req.allocated_ports.bind_host.clone();
            guard.mixed_port = req.allocated_ports.mixed_port;
            guard.controller_host = req.controller_host.clone();
            guard.controller_port = req.allocated_ports.controller_port;
            guard.dns_listen_port = req.allocated_ports.dns_port;
            guard.controller_secret = req.controller_secret.clone();
            guard.proxy_mode = req.config.proxy_mode.clone();
            guard.version = None;
            guard.started_at = Some(now_utc);
            guard.started_instant = Some(now_instant);
            guard.rule_count = req.rule_count;
            guard.node_count = req.node_count;
            guard.shifted_ports = req.allocated_ports.shifted.clone();
            guard.active_selections = req.active_selections.clone();
            guard.last_reload_at = Some(now_utc.to_rfc3339());
            guard.last_reload_level = Some(ReloadLevel::L3CoreRestart);
            guard.last_error = None;
            guard.external_endpoint_configured = false;
        }

        // Wait until the controller REST API responds to `/version` or child exits prematurely.
        let deadline = Instant::now() + STARTUP_READY_TIMEOUT;
        let mut ready_version: Option<String> = None;
        let mut last_probe_err: Option<String> = None;

        while Instant::now() < deadline {
            {
                let mut guard = self.state.lock().await;
                if let Some(child_ref) = guard.child.as_mut() {
                    if let Ok(Some(exit_status)) = child_ref.try_wait() {
                        let exited_pid = guard.pid.take();
                        guard.child = None;
                        if let Some(p) = exited_pid {
                            self.job_guard.unregister_pid(p);
                        }
                        let stderr_tail = read_captured_stderr_tail(
                            &stderr_log_path,
                            stderr_captured,
                            MAX_STARTUP_STDERR_TAIL_BYTES,
                        );
                        let msg = if stderr_tail.is_empty() {
                            format!(
                                "Mihomo exited prematurely during startup with status {exit_status}"
                            )
                        } else {
                            format!(
                                "Mihomo exited prematurely during startup with status {exit_status}: {stderr_tail}"
                            )
                        };
                        guard.last_error = Some(msg.clone());
                        return Err(CatError::Core(msg));
                    }
                }
            }

            match self.fetch_version().await {
                Ok(ver) => {
                    ready_version = Some(ver);
                    break;
                }
                Err(e) => {
                    last_probe_err = Some(e.to_string());
                    tokio::time::sleep(STARTUP_POLL_INTERVAL).await;
                }
            }
        }

        let Some(version) = ready_version else {
            let _ = self.stop_process_unlocked().await;
            let detail = last_probe_err.unwrap_or_else(|| "controller timeout".to_string());
            let stderr_tail = read_captured_stderr_tail(
                &stderr_log_path,
                stderr_captured,
                MAX_STARTUP_STDERR_TAIL_BYTES,
            );
            let msg = if stderr_tail.is_empty() {
                format!(
                    "Mihomo controller did not become ready within {:.1}s: {detail}",
                    STARTUP_READY_TIMEOUT.as_secs_f32()
                )
            } else {
                format!(
                    "Mihomo controller did not become ready within {:.1}s: {detail} (stderr: {stderr_tail})",
                    STARTUP_READY_TIMEOUT.as_secs_f32()
                )
            };
            let mut guard = self.state.lock().await;
            guard.last_error = Some(msg.clone());
            return Err(CatError::Core(msg));
        };

        {
            let mut guard = self.state.lock().await;
            guard.version = Some(version);
        }

        // Replay persisted `select` group selections immediately after startup.
        let base_url =
            format_http_base_url(&req.controller_host, req.allocated_ports.controller_port);
        for (group, proxy) in &req.active_selections {
            let _ = self
                .send_select_group_proxy(&base_url, &req.controller_secret, group, proxy)
                .await;
        }

        Ok(self.runtime_status().await)
    }

    /// Gracefully stop the managed Mihomo child process if running.
    pub async fn stop_process(&self) -> CatResult<()> {
        let _op_guard = self.op_lock.lock().await;
        self.stop_process_unlocked().await
    }

    async fn stop_process_unlocked(&self) -> CatResult<()> {
        let (maybe_child, old_pid) = {
            let mut guard = self.state.lock().await;
            let pid = guard.pid.take();
            guard.started_at = None;
            guard.started_instant = None;
            (guard.child.take(), pid)
        };

        if let Some(mut child) = maybe_child {
            let _ = child.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(3), child.wait()).await;
        }
        if let Some(p) = old_pid {
            self.job_guard.unregister_pid(p);
        }
        Ok(())
    }

    /// Build a thread-safe runtime status snapshot.
    pub async fn runtime_status(&self) -> CoreRuntimeStatus {
        let mut guard = self.state.lock().await;
        let running = if let Some(child) = guard.child.as_mut() {
            match child.try_wait() {
                Ok(None) => true,
                Ok(Some(_)) | Err(_) => {
                    guard.child = None;
                    guard.pid = None;
                    guard.started_instant = None;
                    false
                }
            }
        } else {
            guard.external_endpoint_configured
        };

        let uptime_sec = if running {
            guard
                .started_instant
                .map_or(0, |started| started.elapsed().as_secs())
        } else {
            0
        };

        CoreRuntimeStatus {
            running,
            kind: CoreKind::Mihomo,
            pid: guard.pid,
            version: guard.version.clone(),
            binary_path: guard.binary_path.clone(),
            config_path: guard.config_path.clone(),
            bind_host: guard.bind_host.clone(),
            mixed_port: guard.mixed_port,
            controller_host: guard.controller_host.clone(),
            controller_port: guard.controller_port,
            dns_listen_port: guard.dns_listen_port,
            proxy_mode: guard.proxy_mode.clone(),
            started_at: guard.started_at.map(|dt| dt.to_rfc3339()),
            uptime_sec,
            rule_count: guard.rule_count,
            node_count: guard.node_count,
            shifted_ports: guard.shifted_ports.clone(),
            last_reload_at: guard.last_reload_at.clone(),
            last_reload_level: guard.last_reload_level,
            last_error: guard.last_error.clone(),
        }
    }

    /// Hot-reload Mihomo from `config_path` via `PUT /configs?force=true`, then immediately
    /// replay every `select` group choice in `active_selections` via `PUT /proxies/{group}` so
    /// `store-selected: false` never resets user or arbiter selections.
    pub async fn put_configs_force_reload(
        &self,
        config_path: &Path,
        active_selections: &BTreeMap<String, String>,
    ) -> CatResult<usize> {
        self.reload_config_with_secret(config_path, active_selections, None)
            .await
    }

    /// Hot-reload Mihomo from `config_path` via `PUT /configs?force=true` while optionally
    /// rotating the active controller secret once the reload request succeeds, so subsequent
    /// group selection replay and REST calls never desynchronize with HTTP 401.
    pub async fn reload_config_with_secret(
        &self,
        config_path: &Path,
        active_selections: &BTreeMap<String, String>,
        next_controller_secret: Option<&str>,
    ) -> CatResult<usize> {
        let _op_guard = self.op_lock.lock().await;

        let (base_url, current_secret, fallback_selections) = {
            let guard = self.state.lock().await;
            (
                format_http_base_url(&guard.controller_host, guard.controller_port),
                guard.controller_secret.clone(),
                guard.active_selections.clone(),
            )
        };

        let canonical_path =
            std::fs::canonicalize(config_path).unwrap_or_else(|_| config_path.to_path_buf());
        let path_str = strip_windows_verbatim(&canonical_path);

        let url = format!("{base_url}/configs?force=true");
        let resp = self
            .http
            .put(&url)
            .bearer_auth(&current_secret)
            .json(&serde_json::json!({ "path": path_str }))
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CatError::Core(format!(
                "PUT /configs?force=true failed with HTTP {}: {}",
                status.as_u16(),
                body.trim()
            )));
        }

        // Mihomo has already applied the new config; immediately adopt the rotated secret
        // (when provided) before replaying group selections or serving further controller calls.
        let effective_secret = next_controller_secret
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(current_secret.as_str())
            .to_string();
        if effective_secret != current_secret {
            let mut guard = self.state.lock().await;
            guard.controller_secret = effective_secret.clone();
        }

        let selections_to_replay = if active_selections.is_empty() {
            &fallback_selections
        } else {
            active_selections
        };

        let mut replayed = 0usize;
        let mut replay_errors: Vec<String> = Vec::new();
        for (group, proxy) in selections_to_replay {
            match self
                .send_select_group_proxy(&base_url, &effective_secret, group, proxy)
                .await
            {
                Ok(()) => replayed += 1,
                Err(e) => replay_errors.push(format!("{group}->{proxy}: {e}")),
            }
        }

        {
            let mut guard = self.state.lock().await;
            guard.config_path = Some(config_path.to_path_buf());
            guard.controller_secret = effective_secret;
            guard.last_reload_at = Some(Utc::now().to_rfc3339());
            guard.last_reload_level = Some(ReloadLevel::L2HotReload);
            if !active_selections.is_empty() {
                guard.active_selections = active_selections.clone();
            }
            if replay_errors.is_empty() {
                guard.last_error = None;
            } else {
                guard.last_error = Some(format!(
                    "partial group selection replay warnings: {}",
                    replay_errors.join("; ")
                ));
            }
        }

        Ok(replayed)
    }

    /// Update the active routing mode (`rule` / `global` / `direct`) via `PATCH /configs` (L1 REST).
    pub async fn patch_proxy_mode(&self, mode: ProxyMode) -> CatResult<()> {
        let _op_guard = self.op_lock.lock().await;

        let (base_url, secret) = self.controller_endpoint().await;
        let url = format!("{base_url}/configs");
        let resp = self
            .http
            .patch(&url)
            .bearer_auth(&secret)
            .json(&serde_json::json!({ "mode": mode.as_str() }))
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CatError::Core(format!(
                "PATCH /configs(mode={}) failed with HTTP {}: {}",
                mode.as_str(),
                status.as_u16(),
                body.trim()
            )));
        }

        let mut guard = self.state.lock().await;
        guard.proxy_mode = mode;
        guard.last_reload_at = Some(Utc::now().to_rfc3339());
        guard.last_reload_level = Some(ReloadLevel::L1Rest);
        guard.last_error = None;
        Ok(())
    }

    /// Switch a `select` proxy group to `proxy_name` via `PUT /proxies/{group}` and record the choice.
    pub async fn select_group_proxy(&self, group_name: &str, proxy_name: &str) -> CatResult<()> {
        let _op_guard = self.op_lock.lock().await;

        let (base_url, secret) = self.controller_endpoint().await;
        self.send_select_group_proxy(&base_url, &secret, group_name, proxy_name)
            .await?;

        let mut guard = self.state.lock().await;
        guard
            .active_selections
            .insert(group_name.to_string(), proxy_name.to_string());
        guard.last_reload_at = Some(Utc::now().to_rfc3339());
        guard.last_reload_level = Some(ReloadLevel::L1Rest);
        Ok(())
    }

    /// List all currently active connections from `GET /connections`.
    pub async fn list_connections(&self) -> CatResult<ConnectionsSnapshot> {
        let (base_url, secret) = self.controller_endpoint().await;
        let url = format!("{base_url}/connections");
        let resp = self.http.get(&url).bearer_auth(&secret).send().await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CatError::Core(format!(
                "GET /connections failed with HTTP {}: {}",
                status.as_u16(),
                body.trim()
            )));
        }

        let raw: RawConnectionsResponse = resp.json().await?;
        Ok(raw.into_snapshot())
    }

    /// Close a single active connection by ID via `DELETE /connections/{id}`.
    pub async fn close_connection(&self, id: &str) -> CatResult<()> {
        let (base_url, secret) = self.controller_endpoint().await;
        let encoded_id = percent_encode_path_segment(id);
        let url = format!("{base_url}/connections/{encoded_id}");
        let resp = self.http.delete(&url).bearer_auth(&secret).send().await?;

        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        if status.as_u16() == 404 {
            return Err(CatError::NotFound(format!("connection `{id}` already closed")));
        }
        let body = resp.text().await.unwrap_or_default();
        Err(CatError::Core(format!(
            "DELETE /connections/{id} failed with HTTP {}: {}",
            status.as_u16(),
            body.trim()
        )))
    }

    /// Close all active connections via `DELETE /connections`.
    pub async fn close_all_connections(&self) -> CatResult<()> {
        let (base_url, secret) = self.controller_endpoint().await;
        let url = format!("{base_url}/connections");
        let resp = self.http.delete(&url).bearer_auth(&secret).send().await?;

        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let body = resp.text().await.unwrap_or_default();
        Err(CatError::Core(format!(
            "DELETE /connections failed with HTTP {}: {}",
            status.as_u16(),
            body.trim()
        )))
    }

    /// Gracefully disable TUN mode via `PATCH /configs` (`{"tun":{"enable":false}}`) when the
    /// controller is live, then pause 250ms so Mihomo can cleanly tear down Wintun and system routes.
    pub async fn disable_tun_gracefully(&self) -> CatResult<()> {
        if !self.has_live_controller().await {
            return Ok(());
        }

        let (base_url, secret) = self.controller_endpoint().await;
        let url = format!("{base_url}/configs");
        let resp = self
            .http
            .patch(&url)
            .bearer_auth(&secret)
            .timeout(Duration::from_millis(1200))
            .json(&serde_json::json!({ "tun": { "enable": false } }))
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CatError::Core(format!(
                "PATCH /configs(tun.enable=false) failed with HTTP {}: {}",
                status.as_u16(),
                body.trim()
            )));
        }

        tokio::time::sleep(Duration::from_millis(250)).await;
        Ok(())
    }

    /// Close only active connections matching the specified group and/or node chain
    /// without disrupting unrelated groups.
    pub async fn close_connections_for_group_or_node(
        &self,
        group_name: Option<&str>,
        node_name: Option<&str>,
    ) -> CatResult<usize> {
        let snapshot = self.list_connections().await?;
        let mut closed = 0usize;
        for conn in snapshot.connections {
            if !conn.matches_group_or_node(group_name, node_name) {
                continue;
            }
            match self.close_connection(&conn.id).await {
                Ok(()) => closed += 1,
                Err(CatError::NotFound(_)) => {}
                Err(err) => return Err(err),
            }
        }
        Ok(closed)
    }

    /// Trigger an immediate active delay check for `group_name` via `GET /group/{name}/delay`.
    pub async fn trigger_group_delay_check(
        &self,
        group_name: &str,
        probe_url: &str,
        timeout_ms: u64,
    ) -> CatResult<HashMap<String, u64>> {
        let (base_url, secret) = self.controller_endpoint().await;
        let encoded_group = percent_encode_path_segment(group_name);
        let endpoint = format!("{base_url}/group/{encoded_group}/delay");
        let mut parsed = Url::parse(&endpoint)
            .map_err(|e| CatError::Core(format!("invalid delay check URL `{endpoint}`: {e}")))?;
        parsed
            .query_pairs_mut()
            .append_pair("url", probe_url)
            .append_pair("timeout", &timeout_ms.to_string());

        let resp = self
            .http
            .get(parsed.as_str())
            .bearer_auth(&secret)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CatError::Core(format!(
                "GET /group/{group_name}/delay failed with HTTP {}: {}",
                status.as_u16(),
                body.trim()
            )));
        }

        let delays: HashMap<String, u64> = resp.json().await.unwrap_or_default();
        Ok(delays)
    }

    /// Query the running core version string via `GET /version`.
    pub async fn fetch_version(&self) -> CatResult<String> {
        let (base_url, secret) = self.controller_endpoint().await;
        let url = format!("{base_url}/version");
        let resp = self.http.get(&url).bearer_auth(&secret).send().await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CatError::Core(format!(
                "GET /version failed with HTTP {}: {}",
                status.as_u16(),
                body.trim()
            )));
        }

        let payload: VersionResponse = resp.json().await?;
        Ok(payload.version)
    }

    async fn controller_endpoint(&self) -> (String, String) {
        let guard = self.state.lock().await;
        (
            format_http_base_url(&guard.controller_host, guard.controller_port),
            guard.controller_secret.clone(),
        )
    }

    async fn send_select_group_proxy(
        &self,
        base_url: &str,
        secret: &str,
        group_name: &str,
        proxy_name: &str,
    ) -> CatResult<()> {
        let encoded_group = percent_encode_path_segment(group_name);
        let url = format!("{base_url}/proxies/{encoded_group}");
        let resp = self
            .http
            .put(&url)
            .bearer_auth(secret)
            .json(&serde_json::json!({ "name": proxy_name }))
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CatError::Core(format!(
                "PUT /proxies/{group_name}({proxy_name}) failed with HTTP {}: {}",
                status.as_u16(),
                body.trim()
            )));
        }
        Ok(())
    }
}

impl CoreAdapter for MihomoAdapter {
    fn kind(&self) -> CoreKind {
        CoreKind::Mihomo
    }

    fn start(&self, req: CoreStartRequest) -> BoxFuture<'_, CatResult<CoreRuntimeStatus>> {
        Box::pin(async move { self.start_with_request(req).await })
    }

    fn stop(&self) -> BoxFuture<'_, CatResult<()>> {
        Box::pin(async move { self.stop_process().await })
    }

    fn status(&self) -> BoxFuture<'_, CoreRuntimeStatus> {
        Box::pin(async move { self.runtime_status().await })
    }

    fn reload_config<'a>(
        &'a self,
        config_path: &'a Path,
        active_selections: &'a BTreeMap<String, String>,
    ) -> BoxFuture<'a, CatResult<usize>> {
        Box::pin(async move {
            self.put_configs_force_reload(config_path, active_selections)
                .await
        })
    }

    fn set_proxy_mode(&self, mode: ProxyMode) -> BoxFuture<'_, CatResult<()>> {
        Box::pin(async move { self.patch_proxy_mode(mode).await })
    }

    fn select_group_proxy<'a>(
        &'a self,
        group_name: &'a str,
        proxy_name: &'a str,
    ) -> BoxFuture<'a, CatResult<()>> {
        Box::pin(async move { self.select_group_proxy(group_name, proxy_name).await })
    }

    fn list_connections(&self) -> BoxFuture<'_, CatResult<ConnectionsSnapshot>> {
        Box::pin(async move { self.list_connections().await })
    }

    fn close_connection<'a>(&'a self, id: &'a str) -> BoxFuture<'a, CatResult<()>> {
        Box::pin(async move { self.close_connection(id).await })
    }

    fn close_connections_for_group_or_node<'a>(
        &'a self,
        group_name: Option<&'a str>,
        node_name: Option<&'a str>,
    ) -> BoxFuture<'a, CatResult<usize>> {
        Box::pin(async move {
            self.close_connections_for_group_or_node(group_name, node_name)
                .await
        })
    }

    fn trigger_group_delay_check<'a>(
        &'a self,
        group_name: &'a str,
        url: &'a str,
        timeout_ms: u64,
    ) -> BoxFuture<'a, CatResult<HashMap<String, u64>>> {
        Box::pin(async move {
            self.trigger_group_delay_check(group_name, url, timeout_ms)
                .await
        })
    }

    fn fetch_version(&self) -> BoxFuture<'_, CatResult<String>> {
        Box::pin(async move { self.fetch_version().await })
    }

    fn verify_config_file<'a>(
        &'a self,
        binary_path: &'a Path,
        working_dir: &'a Path,
        config_path: &'a Path,
    ) -> BoxFuture<'a, CatResult<()>> {
        Box::pin(async move {
            verify_config_with_binary(binary_path, working_dir, config_path, Duration::from_secs(8))
                .await
        })
    }
}

/// Run `mihomo -t -d <working_dir> -f <config_path>` with a bounded timeout to pre-flight verify
/// a candidate YAML configuration before touching the active running core.
pub async fn verify_config_with_binary(
    binary_path: &Path,
    working_dir: &Path,
    config_path: &Path,
    timeout_dur: Duration,
) -> CatResult<()> {
    if !binary_path.is_file() {
        return Err(CatError::NotFound(format!(
            "cannot verify config: Mihomo binary missing at `{}`",
            binary_path.display()
        )));
    }
    if !config_path.is_file() {
        return Err(CatError::NotFound(format!(
            "cannot verify config: candidate YAML missing at `{}`",
            config_path.display()
        )));
    }

    let norm_bin = crate::paths::normalize_os_path(binary_path);
    let norm_work = crate::paths::normalize_os_path(working_dir);
    let norm_cfg = crate::paths::normalize_os_path(config_path);

    let mut cmd = Command::new(&norm_bin);
    cmd.arg("-t")
        .arg("-d")
        .arg(&norm_work)
        .arg("-f")
        .arg(&norm_cfg)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    JobGuard::configure_tokio_command(&mut cmd);

    let mut child = cmd.spawn().map_err(|e| {
        CatError::Process(format!(
            "failed to spawn `{}` for `-t` verification: {e}",
            binary_path.display()
        ))
    })?;

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let outcome = {
        let run_fut = async {
            let stdout_fut = async move {
                match stdout_pipe {
                    Some(r) => read_bounded_output(r, MAX_VERIFY_OUTPUT_BYTES).await,
                    None => Ok((Vec::new(), false)),
                }
            };
            let stderr_fut = async move {
                match stderr_pipe {
                    Some(r) => read_bounded_output(r, MAX_VERIFY_OUTPUT_BYTES).await,
                    None => Ok((Vec::new(), false)),
                }
            };
            let (status_res, stdout_res, stderr_res) =
                tokio::join!(child.wait(), stdout_fut, stderr_fut);
            let status = status_res
                .map_err(|e| CatError::Process(format!("`mihomo -t` wait failed: {e}")))?;
            let (stdout_bytes, stdout_trunc) = stdout_res.unwrap_or_default();
            let (stderr_bytes, stderr_trunc) = stderr_res.unwrap_or_default();
            Ok::<_, CatError>((status, stdout_bytes, stdout_trunc, stderr_bytes, stderr_trunc))
        };
        tokio::time::timeout(timeout_dur, run_fut).await
    };

    let (status, stdout_bytes, stdout_trunc, stderr_bytes, stderr_trunc) = match outcome {
        Ok(res) => res?,
        Err(_) => {
            let _ = child.kill().await;
            let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
            return Err(CatError::Core(format!(
                "`mihomo -t` verification timed out after {:.1}s",
                timeout_dur.as_secs_f32()
            )));
        }
    };

    if status.success() {
        return Ok(());
    }

    let mut stderr = String::from_utf8_lossy(&stderr_bytes).trim().to_string();
    if stderr_trunc && !stderr.is_empty() {
        stderr.push_str(" [truncated]");
    }
    let mut stdout = String::from_utf8_lossy(&stdout_bytes).trim().to_string();
    if stdout_trunc && !stdout.is_empty() {
        stdout.push_str(" [truncated]");
    }
    let detail = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        format!("exit status {status}")
    };
    Err(CatError::Validation(format!(
        "Mihomo `-t` pre-flight check failed: {detail}"
    )))
}

async fn read_bounded_output<R: tokio::io::AsyncRead + Unpin>(
    mut reader: R,
    max_bytes: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    use tokio::io::AsyncReadExt;

    let mut buf = Vec::with_capacity(max_bytes.min(8192));
    let mut chunk = [0u8; 4096];
    let mut truncated = false;

    loop {
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        if buf.len() < max_bytes {
            let take = (max_bytes - buf.len()).min(n);
            buf.extend_from_slice(&chunk[..take]);
            if take < n {
                truncated = true;
            }
        } else {
            truncated = true;
        }
    }

    Ok((buf, truncated))
}

fn build_controller_http_client() -> CatResult<reqwest::Client> {
    crate::init_crypto_provider();
    reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(CatError::Http)
}

/// Open and truncate `mihomo-stderr.log` for the child process, returning `(stdio, captured)`.
/// When opening or truncating fails (e.g. file locked or permission denied), degrades to
/// `Stdio::null()` with `captured == false` so startup failure diagnostics skip reading stale logs.
fn open_mihomo_stderr_stdio(log_path: &Path) -> (Stdio, bool) {
    match std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(log_path)
    {
        Ok(file) => (Stdio::from(file), true),
        Err(_) => (Stdio::null(), false),
    }
}

fn read_captured_stderr_tail(log_path: &Path, stderr_captured: bool, max_bytes: usize) -> String {
    if !stderr_captured {
        return String::new();
    }
    read_stderr_tail(log_path, max_bytes)
}

fn read_stderr_tail(log_path: &Path, max_bytes: usize) -> String {
    use std::io::{Read, Seek, SeekFrom};

    let Ok(mut file) = std::fs::File::open(log_path) else {
        return String::new();
    };
    let Ok(meta) = file.metadata() else {
        return String::new();
    };
    let len = meta.len();
    if len == 0 || max_bytes == 0 {
        return String::new();
    }
    let start = len.saturating_sub(max_bytes as u64);
    if start > 0 && file.seek(SeekFrom::Start(start)).is_err() {
        return String::new();
    }
    let mut buf = Vec::with_capacity((len - start).min(max_bytes as u64) as usize);
    if file.read_to_end(&mut buf).is_err() {
        return String::new();
    }
    let raw = String::from_utf8_lossy(&buf);
    let compact = raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" | ");
    if start > 0 && !compact.is_empty() {
        format!("...{compact}")
    } else {
        compact
    }
}

fn strip_windows_verbatim(path: &Path) -> String {
    let raw = path.to_string_lossy();
    #[cfg(target_os = "windows")]
    {
        if let Some(stripped) = raw.strip_prefix(r"\\?\") {
            return stripped.to_string();
        }
    }
    raw.into_owned()
}

#[derive(Debug, Deserialize)]
struct VersionResponse {
    #[serde(default)]
    version: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn generates_distinct_64_hex_controller_secrets() {
        let s1 = generate_controller_secret();
        let s2 = generate_controller_secret();
        assert_eq!(s1.len(), 64);
        assert_eq!(s2.len(), 64);
        assert_ne!(s1, s2);
        assert!(s1.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn reload_replays_active_selections_and_kicks_only_matching_group_connections() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let secret = generate_controller_secret();
        let expected_auth = format!("Bearer {secret}");
        let recorded_requests: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
        let recorded_clone = Arc::clone(&recorded_requests);

        let server = tokio::spawn(async move {
            for _ in 0..6 {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let mut raw_bytes = Vec::with_capacity(1024);
                let mut chunk = [0u8; 1024];
                loop {
                    let n = socket.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    raw_bytes.extend_from_slice(&chunk[..n]);
                    if raw_bytes.windows(4).any(|w| w == b"\r\n\r\n") || raw_bytes.len() >= 8192 {
                        break;
                    }
                }
                if raw_bytes.is_empty() {
                    continue;
                }
                let raw = String::from_utf8_lossy(&raw_bytes).to_string();
                let first_line = raw.lines().next().unwrap_or_default().to_string();
                assert!(
                    raw.contains(&expected_auth),
                    "request missing bearer token: {raw}"
                );
                recorded_clone.lock().unwrap().push(first_line.clone());

                let (status_line, body) = if first_line.starts_with("PUT /configs?force=true") {
                    ("HTTP/1.1 204 No Content", "")
                } else if first_line.starts_with("PUT /proxies/") {
                    ("HTTP/1.1 204 No Content", "")
                } else if first_line.starts_with("GET /connections") {
                    (
                        "HTTP/1.1 200 OK",
                        r#"{"downloadTotal":100,"uploadTotal":50,"memory":1024,"connections":[{"id":"c-ai-old","upload":1,"download":2,"start":"","chains":["Node-A","AI-Group"],"rule":"DOMAIN-SUFFIX","rulePayload":"openai.com","metadata":{"network":"tcp","type":"HTTP","sourceIP":"127.0.0.1","sourcePort":"50000","destinationIP":"203.0.113.1","destinationPort":"443","host":"openai.com","process":"app","processPath":""}},{"id":"c-other","upload":1,"download":2,"start":"","chains":["Node-A","Browse-Group"],"rule":"MATCH","rulePayload":"","metadata":{"network":"tcp","type":"HTTP","sourceIP":"127.0.0.1","sourcePort":"50001","destinationIP":"203.0.113.2","destinationPort":"443","host":"example.com","process":"browser","processPath":""}}]}"#,
                    )
                } else if first_line.starts_with("DELETE /connections/") {
                    ("HTTP/1.1 204 No Content", "")
                } else if first_line.starts_with("GET /version") {
                    ("HTTP/1.1 200 OK", r#"{"version":"v1.19.0"}"#)
                } else {
                    ("HTTP/1.1 404 Not Found", "")
                };

                let response = format!(
                    "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let guard = Arc::new(JobGuard::new().unwrap());
        let adapter =
            MihomoAdapter::with_controller_endpoint(guard, "127.0.0.1", port, secret).unwrap();

        let mut selections = BTreeMap::new();
        selections.insert("AI-Group".to_string(), "Node-B".to_string());
        let fake_path = std::env::temp_dir().join("catcloud-mock-runtime.yaml");
        let replayed = adapter
            .put_configs_force_reload(&fake_path, &selections)
            .await
            .expect("force reload must succeed");
        assert_eq!(replayed, 1);

        let closed = adapter
            .close_connections_for_group_or_node(Some("AI-Group"), Some("Node-A"))
            .await
            .expect("targeted close must succeed");
        assert_eq!(closed, 1);

        let ver = adapter.fetch_version().await.unwrap();
        assert_eq!(ver, "v1.19.0");

        let reqs = recorded_requests.lock().unwrap().clone();
        assert!(reqs.iter().any(|r| r.starts_with("PUT /configs?force=true")));
        assert!(reqs.iter().any(|r| r.starts_with("PUT /proxies/AI-Group")));
        assert!(reqs
            .iter()
            .any(|r| r.starts_with("DELETE /connections/c-ai-old")));
        assert!(!reqs
            .iter()
            .any(|r| r.starts_with("DELETE /connections/c-other")));

        server.abort();
    }

    #[tokio::test]
    async fn reload_config_with_secret_rotates_token_and_bounds_verify_output() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let old_secret = generate_controller_secret();
        let new_secret = generate_controller_secret();
        let old_auth = format!("Bearer {old_secret}");
        let new_auth = format!("Bearer {new_secret}");

        let server = tokio::spawn(async move {
            let mut expected = old_auth;
            for _ in 0..3 {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let mut raw_bytes = Vec::with_capacity(1024);
                let mut chunk = [0u8; 1024];
                loop {
                    let n = socket.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    raw_bytes.extend_from_slice(&chunk[..n]);
                    if raw_bytes.windows(4).any(|w| w == b"\r\n\r\n") || raw_bytes.len() >= 8192 {
                        break;
                    }
                }
                if raw_bytes.is_empty() {
                    continue;
                }
                let raw = String::from_utf8_lossy(&raw_bytes).to_string();
                let first_line = raw.lines().next().unwrap_or_default().to_string();
                let (status_line, body) = if !raw.contains(&expected) {
                    ("HTTP/1.1 401 Unauthorized", "")
                } else if first_line.starts_with("PUT /configs?force=true") {
                    expected = new_auth.clone();
                    ("HTTP/1.1 204 No Content", "")
                } else if first_line.starts_with("PUT /proxies/") {
                    ("HTTP/1.1 204 No Content", "")
                } else if first_line.starts_with("GET /version") {
                    ("HTTP/1.1 200 OK", r#"{"version":"v1.19.1"}"#)
                } else {
                    ("HTTP/1.1 404 Not Found", "")
                };
                let response = format!(
                    "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let guard = Arc::new(JobGuard::new().unwrap());
        let adapter =
            MihomoAdapter::with_controller_endpoint(guard, "127.0.0.1", port, old_secret).unwrap();

        let mut selections = BTreeMap::new();
        selections.insert("AI-Group".to_string(), "Node-C".to_string());
        let fake_path = std::env::temp_dir().join("catcloud-mock-rotate.yaml");
        let replayed = adapter
            .reload_config_with_secret(&fake_path, &selections, Some(&new_secret))
            .await
            .expect("secret-rotating L2 reload must succeed");
        assert_eq!(replayed, 1);
        assert_eq!(adapter.controller_secret().await, new_secret);
        assert_eq!(adapter.fetch_version().await.unwrap(), "v1.19.1");

        // Bounded output reader caps captured bytes cleanly and sets the truncated flag.
        let oversized = vec![b'E'; MAX_VERIFY_OUTPUT_BYTES + 8192];
        let (captured, truncated) =
            read_bounded_output(std::io::Cursor::new(oversized), MAX_VERIFY_OUTPUT_BYTES)
                .await
                .unwrap();
        assert!(truncated);
        assert_eq!(captured.len(), MAX_VERIFY_OUTPUT_BYTES);

        server.abort();
    }

    #[tokio::test]
    async fn close_all_connections_and_disable_tun_gracefully_hit_expected_endpoints() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let secret = generate_controller_secret();
        let expected_auth = format!("Bearer {secret}");
        let recorded: Arc<StdMutex<Vec<(String, String)>>> = Arc::new(StdMutex::new(Vec::new()));
        let recorded_bg = Arc::clone(&recorded);

        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let mut raw_bytes = Vec::with_capacity(1024);
                let mut chunk = [0u8; 1024];
                loop {
                    let n = socket.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    raw_bytes.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = raw_bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let header = String::from_utf8_lossy(&raw_bytes[..pos]);
                        let content_len = header
                            .lines()
                            .find_map(|line| {
                                let (k, v) = line.split_once(':')?;
                                if k.trim().eq_ignore_ascii_case("content-length") {
                                    v.trim().parse::<usize>().ok()
                                } else {
                                    None
                                }
                            })
                            .unwrap_or(0);
                        if raw_bytes.len() >= pos + 4 + content_len {
                            break;
                        }
                    }
                    if raw_bytes.len() >= 8192 {
                        break;
                    }
                }
                let raw = String::from_utf8_lossy(&raw_bytes).to_string();
                let first_line = raw.lines().next().unwrap_or_default().to_string();
                let body_part = raw
                    .split_once("\r\n\r\n")
                    .map(|(_, b)| b.to_string())
                    .unwrap_or_default();
                assert!(raw.contains(&expected_auth), "missing bearer auth: {raw}");
                recorded_bg.lock().unwrap().push((first_line, body_part));

                let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        // Non-live adapter must short-circuit disable_tun_gracefully without error.
        let idle_guard = Arc::new(JobGuard::new().unwrap());
        let idle_adapter = MihomoAdapter::new(idle_guard).unwrap();
        idle_adapter
            .disable_tun_gracefully()
            .await
            .expect("idle disable_tun_gracefully should be a no-op");

        let guard = Arc::new(JobGuard::new().unwrap());
        let adapter =
            MihomoAdapter::with_controller_endpoint(guard, "127.0.0.1", port, secret).unwrap();

        adapter
            .close_all_connections()
            .await
            .expect("DELETE /connections must succeed");
        adapter
            .disable_tun_gracefully()
            .await
            .expect("PATCH /configs(tun.enable=false) must succeed");

        let reqs = recorded.lock().unwrap().clone();
        assert_eq!(reqs.len(), 2);
        assert!(reqs[0].0.starts_with("DELETE /connections HTTP/1.1"));
        assert!(reqs[1].0.starts_with("PATCH /configs HTTP/1.1"));
        let parsed: serde_json::Value = serde_json::from_str(&reqs[1].1).unwrap();
        assert_eq!(parsed["tun"]["enable"], serde_json::Value::Bool(false));

        server.abort();
    }

    #[test]
    fn stderr_log_helper_truncates_on_reopen_and_reads_bounded_tail() {
        let path = std::env::temp_dir().join(format!(
            "catcloud-mihomo-stderr-test-{}.log",
            uuid::Uuid::new_v4()
        ));

        // 1. Opening truncates any pre-existing content so stale errors do not bleed across restarts.
        std::fs::write(&path, "stale old error\n").unwrap();
        let (stdio, captured) = open_mihomo_stderr_stdio(&path);
        assert!(captured);
        drop(stdio);
        assert_eq!(read_stderr_tail(&path, MAX_STARTUP_STDERR_TAIL_BYTES), "");

        // 2. Small multiline stderr is compacted cleanly without truncation prefix.
        std::fs::write(&path, "line one\n\n  fatal: bad yaml  \n").unwrap();
        assert_eq!(
            read_stderr_tail(&path, MAX_STARTUP_STDERR_TAIL_BYTES),
            "line one | fatal: bad yaml"
        );

        // 3. Oversized stderr returns only the bounded trailing bytes with `...` prefix.
        let big = format!("{}TAIL_MARKER_END\n", "x".repeat(MAX_STARTUP_STDERR_TAIL_BYTES + 256));
        std::fs::write(&path, big).unwrap();
        let tail = read_stderr_tail(&path, MAX_STARTUP_STDERR_TAIL_BYTES);
        assert!(tail.starts_with("..."));
        assert!(tail.ends_with("TAIL_MARKER_END"));
        assert!(tail.len() <= MAX_STARTUP_STDERR_TAIL_BYTES + 16);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn stderr_log_open_failure_skips_stale_tail_reading() {
        let dir = std::env::temp_dir().join(format!(
            "catcloud-mihomo-stderr-fail-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        // Opening an existing directory as a truncated file always fails and degrades to
        // `Stdio::null()` with `captured == false`.
        let (_stdio, captured) = open_mihomo_stderr_stdio(&dir);
        assert!(!captured);

        // When `stderr_captured == false`, stale log content from an earlier run must be skipped.
        let stale_path = dir.join(MIHOMO_STDERR_LOG_FILENAME);
        std::fs::write(&stale_path, "stale previous crash reason\n").unwrap();
        assert_eq!(
            read_captured_stderr_tail(&stale_path, false, MAX_STARTUP_STDERR_TAIL_BYTES),
            ""
        );
        assert_eq!(
            read_captured_stderr_tail(&stale_path, true, MAX_STARTUP_STDERR_TAIL_BYTES),
            "stale previous crash reason"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
