use crate::error::{CatError, CatResult};
use crate::models::{ProbeDefinition, ProbeKind, ProbeResultRecord};
use crate::probe::isolated_runner::{ISOLATED_BIND_HOST, IsolatedProxyScheme, isolated_proxy_url};
use crate::process_guard::JobGuard;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

/// Hard upper limit (256 KiB) for external probe JSON stdout payload.
pub const MAX_EXTERNAL_STDOUT_BYTES: usize = 256 * 1024;

/// Hard upper limit (32 KiB) for captured external probe stderr diagnostics.
pub const MAX_EXTERNAL_STDERR_BYTES: usize = 32 * 1024;

/// Standard JSON contract passed via `stdin` to external executable probe scripts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalProbeInput {
    pub proxy_http: String,
    pub proxy_socks5h: String,
    pub node_id: String,
    pub probe_id: String,
    pub timeout_ms: u64,
}

impl ExternalProbeInput {
    pub fn new(node_id: &str, probe_id: &str, proxy_port: u16, timeout_ms: u64) -> Self {
        Self {
            proxy_http: isolated_proxy_url(proxy_port, IsolatedProxyScheme::HttpConnect),
            proxy_socks5h: isolated_proxy_url(proxy_port, IsolatedProxyScheme::Socks5h),
            node_id: node_id.to_string(),
            probe_id: probe_id.to_string(),
            timeout_ms,
        }
    }
}

/// Standard metrics JSON contract returned on `stdout` by external probe executables.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct ExternalProbeOutput {
    pub ok: bool,
    pub latency_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub loss_pct: Option<f64>,
    pub up_mbps: Option<f64>,
    pub down_mbps: Option<f64>,
    pub cf_loc: Option<String>,
    pub yt_gl: Option<String>,
    pub google_clean: Option<bool>,
    pub keepalive_60s_ok: Option<bool>,
    pub unlocked_map: HashMap<String, bool>,
    pub detail: Option<String>,
}

/// Parse an external probe's stdout JSON bytes (enforcing the 256 KiB cap) into a `ProbeResultRecord`.
pub fn parse_external_probe_output(
    raw_stdout: &[u8],
    node_id: &str,
    probe_id: &str,
) -> CatResult<ProbeResultRecord> {
    if raw_stdout.len() > MAX_EXTERNAL_STDOUT_BYTES {
        return Err(CatError::Validation(format!(
            "external probe `{probe_id}` stdout exceeded {} bytes limit",
            MAX_EXTERNAL_STDOUT_BYTES
        )));
    }
    let text = std::str::from_utf8(raw_stdout).map_err(|e| {
        CatError::Validation(format!(
            "external probe `{probe_id}` emitted non-UTF-8 stdout: {e}"
        ))
    })?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(CatError::Validation(format!(
            "external probe `{probe_id}` emitted empty stdout"
        )));
    }

    let parsed: ExternalProbeOutput = serde_json::from_str(trimmed).map_err(|e| {
        CatError::Validation(format!(
            "external probe `{probe_id}` returned invalid metrics JSON: {e}"
        ))
    })?;

    Ok(ProbeResultRecord {
        node_id: node_id.to_string(),
        probe_id: probe_id.to_string(),
        tested_at: Utc::now().to_rfc3339(),
        ok: parsed.ok,
        latency_ms: sanitize_finite_non_neg(parsed.latency_ms),
        jitter_ms: sanitize_finite_non_neg(parsed.jitter_ms),
        loss_pct: sanitize_finite_non_neg(parsed.loss_pct).map(|v| v.min(100.0)),
        up_mbps: sanitize_finite_non_neg(parsed.up_mbps),
        down_mbps: sanitize_finite_non_neg(parsed.down_mbps),
        cf_loc: parsed.cf_loc.map(|s| s.trim().to_ascii_uppercase()),
        yt_gl: parsed.yt_gl.map(|s| s.trim().to_ascii_uppercase()),
        google_clean: parsed.google_clean,
        keepalive_60s_ok: parsed.keepalive_60s_ok,
        unlocked_map: parsed.unlocked_map,
        detail: parsed.detail,
    })
}

/// Split an external command specification into `[program, args...]` without invoking a shell.
/// Supports single and double quotes for paths or arguments containing spaces.
pub fn parse_command_tokens(raw_cmd: &str) -> CatResult<(String, Vec<String>)> {
    let stripped = raw_cmd.trim().strip_prefix("cmd://").unwrap_or(raw_cmd).trim();
    if stripped.is_empty() {
        return Err(CatError::Validation(
            "external probe command cannot be empty".into(),
        ));
    }
    if stripped
        .bytes()
        .any(|b| b == 0 || b == b'\r' || b == b'\n')
    {
        return Err(CatError::Validation(
            "external probe command contains forbidden control characters".into(),
        ));
    }

    let mut tokens: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;

    for ch in stripped.chars() {
        match quote {
            Some(q) => {
                if ch == q {
                    quote = None;
                } else {
                    current.push(ch);
                }
            }
            None => match ch {
                '"' | '\'' => {
                    quote = Some(ch);
                }
                c if c.is_whitespace() => {
                    if !current.is_empty() {
                        tokens.push(std::mem::take(&mut current));
                    }
                }
                c => current.push(c),
            },
        }
    }

    if quote.is_some() {
        return Err(CatError::Validation(
            "external probe command has an unclosed quote".into(),
        ));
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    if tokens.is_empty() {
        return Err(CatError::Validation(
            "external probe command parsed to zero tokens".into(),
        ));
    }

    let program = tokens.remove(0);
    Ok((program, tokens))
}

/// Execute an external script/executable probe:
/// - Writes `ExternalProbeInput` JSON to child `stdin` (with both `http://127.0.0.1:<p>` and `socks5h://127.0.0.1:<p>`).
/// - Reads `stdout` up to `256 KiB` (aborts and kills child on overflow).
/// - Enforces strict wall-clock timeout (`def.timeout_ms`) with `kill_on_drop(true)` and optional `JobGuard`.
pub async fn run_external_probe(
    def: &ProbeDefinition,
    node_id: &str,
    proxy_port: u16,
    job_guard: Option<&JobGuard>,
) -> CatResult<ProbeResultRecord> {
    if def.kind != ProbeKind::ExternalCmd {
        return Err(CatError::Validation(format!(
            "probe `{}` has kind `{:?}`, expected `ExternalCmd`",
            def.id, def.kind
        )));
    }
    if proxy_port == 0 {
        return Err(CatError::Validation(
            "external probe proxy_port must be non-zero".into(),
        ));
    }

    let (program, args) = parse_command_tokens(&def.target_url)?;
    let input = ExternalProbeInput::new(node_id, &def.id, proxy_port, def.timeout_ms);
    let mut input_bytes = serde_json::to_vec(&input)?;
    input_bytes.push(b'\n');

    let mut cmd = Command::new(&program);
    cmd.args(&args)
        .env("CATCLOUD_PROXY_HTTP", &input.proxy_http)
        .env("CATCLOUD_PROXY_SOCKS5H", &input.proxy_socks5h)
        .env("CATCLOUD_PROXY_HOST", ISOLATED_BIND_HOST)
        .env("CATCLOUD_PROXY_PORT", proxy_port.to_string())
        .env("CATCLOUD_NODE_ID", node_id)
        .env("CATCLOUD_PROBE_ID", &def.id)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    JobGuard::configure_tokio_command(&mut cmd);

    let mut child = cmd.spawn().map_err(|e| {
        CatError::Process(format!(
            "failed to spawn external probe `{}` (`{program}`): {e}",
            def.id
        ))
    })?;

    if let Some(guard) = job_guard {
        if let Err(err) = guard.assign_tokio_child(&mut child) {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(err);
        }
    }

    let mut child_stdin = child.stdin.take();
    let child_stdout = child.stdout.take();
    let child_stderr = child.stderr.take();
    let timeout = Duration::from_millis(def.timeout_ms.max(200));

    let timed_outcome = {
        let io_and_wait = async {
            let (abort_tx, abort_rx) = tokio::sync::watch::channel(false);

            let mut write_abort_rx = abort_rx.clone();
            let write_fut = async move {
                if let Some(mut stdin) = child_stdin.take() {
                    let write_op = async {
                        if let Err(err) = stdin.write_all(&input_bytes).await {
                            if err.kind() != std::io::ErrorKind::BrokenPipe {
                                return Err(err);
                            }
                        }
                        let _ = stdin.shutdown().await;
                        Ok::<(), std::io::Error>(())
                    };
                    tokio::select! {
                        res = write_op => return res,
                        _ = wait_until_aborted(&mut write_abort_rx) => return Ok(()),
                    }
                }
                Ok::<(), std::io::Error>(())
            };

            let stdout_fut = async move {
                let res = match child_stdout {
                    Some(out) => read_capped_stream(out, MAX_EXTERNAL_STDOUT_BYTES).await,
                    None => Ok((Vec::new(), false)),
                };
                if matches!(res, Ok((_, true))) {
                    let _ = abort_tx.send(true);
                }
                res
            };

            let mut stderr_abort_rx = abort_rx.clone();
            let stderr_fut = async move {
                match child_stderr {
                    Some(err_stream) => {
                        tokio::select! {
                            res = read_capped_stream(err_stream, MAX_EXTERNAL_STDERR_BYTES) => res,
                            _ = wait_until_aborted(&mut stderr_abort_rx) => Ok((Vec::new(), false)),
                        }
                    }
                    None => Ok((Vec::new(), false)),
                }
            };

            let (write_res, stdout_res, stderr_res, ()) = {
                let mut kill_abort_rx = abort_rx;
                let kill_fut = async {
                    if kill_abort_rx.wait_for(|&aborted| aborted).await.is_ok() {
                        let _ = child.start_kill();
                    }
                };
                tokio::join!(write_fut, stdout_fut, stderr_fut, kill_fut)
            };

            let (stdout_bytes, stdout_overflow) = stdout_res?;
            let (stderr_bytes, _stderr_overflow) = stderr_res?;
            if stdout_overflow {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(CatError::Validation(format!(
                    "external probe `{}` stdout exceeded {} KiB limit; process terminated",
                    def.id,
                    MAX_EXTERNAL_STDOUT_BYTES / 1024
                )));
            }
            if let Err(err) = write_res {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(CatError::Process(format!(
                    "failed writing stdin to external probe `{}`: {err}",
                    def.id
                )));
            }

            let status = child.wait().await?;
            Ok((status, stdout_bytes, stderr_bytes))
        };

        tokio::time::timeout(timeout, io_and_wait).await
    };
    let (status, stdout_bytes, stderr_bytes) = match timed_outcome {
        Ok(Ok(result)) => result,
        Ok(Err(err)) => return Err(err),
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(CatError::Process(format!(
                "external probe `{}` timed out after {}ms and was terminated",
                def.id, def.timeout_ms
            )));
        }
    };

    if !status.success() {
        let stderr_msg = String::from_utf8_lossy(&stderr_bytes).trim().to_string();
        let detail = if stderr_msg.is_empty() {
            format!("external probe `{}` exited with status {status}", def.id)
        } else {
            format!(
                "external probe `{}` exited with status {status}: {stderr_msg}",
                def.id
            )
        };
        return Err(CatError::Process(detail));
    }

    parse_external_probe_output(&stdout_bytes, node_id, &def.id)
}

async fn wait_until_aborted(rx: &mut tokio::sync::watch::Receiver<bool>) {
    if rx.wait_for(|&aborted| aborted).await.is_err() {
        // Sender dropped without signaling abort; stay pending so normal stream reads finish.
        std::future::pending::<()>().await;
    }
}

async fn read_capped_stream<R: AsyncRead + Unpin>(
    mut reader: R,
    max_bytes: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut buf = Vec::with_capacity(max_bytes.min(8192));
    let mut chunk = [0u8; 4096];
    let mut overflow = false;

    loop {
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        if buf.len() + n > max_bytes {
            let take = max_bytes.saturating_sub(buf.len());
            if take > 0 {
                buf.extend_from_slice(&chunk[..take]);
            }
            overflow = true;
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }

    Ok((buf, overflow))
}

fn sanitize_finite_non_neg(value: Option<f64>) -> Option<f64> {
    value.filter(|v| v.is_finite() && *v >= 0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_input_formats_loopback_http_and_socks5h_urls() {
        let input = ExternalProbeInput::new("node-1", "ext_ai", 23456, 8000);
        assert_eq!(input.proxy_http, "http://127.0.0.1:23456");
        assert_eq!(input.proxy_socks5h, "socks5h://127.0.0.1:23456");
        assert!(!input.proxy_socks5h.starts_with("socks5://"));
        let encoded = serde_json::to_string(&input).unwrap();
        assert!(encoded.contains("\"proxy_socks5h\":\"socks5h://127.0.0.1:23456\""));
        assert!(encoded.contains("\"timeout_ms\":8000"));
    }

    #[test]
    fn command_tokenizer_handles_quotes_and_rejects_control_chars() {
        let (prog, args) = parse_command_tokens(r#""/usr/bin/my probe" --mode 'fast' --n 2"#)
            .expect("parse quoted command");
        assert_eq!(prog, "/usr/bin/my probe");
        assert_eq!(args, vec!["--mode", "fast", "--n", "2"]);

        let (prog2, args2) = parse_command_tokens("cmd://python3 check.py").unwrap();
        assert_eq!(prog2, "python3");
        assert_eq!(args2, vec!["check.py"]);

        assert!(parse_command_tokens("echo \"unterminated").is_err());
        assert!(parse_command_tokens("echo ok\nwhoami").is_err());
    }

    #[test]
    fn output_parser_converts_metrics_and_enforces_256kib_cap() {
        let raw = br#"{
            "ok": true,
            "latency_ms": 42.5,
            "jitter_ms": 3.1,
            "up_mbps": 28.4,
            "down_mbps": 150.0,
            "cf_loc": "jp",
            "yt_gl": "us",
            "google_clean": true,
            "keepalive_60s_ok": true,
            "unlocked_map": { "claude": true, "chatgpt": true },
            "detail": "custom script passed"
        }"#;

        let rec = parse_external_probe_output(raw, "node-a", "ext_1").expect("parse metrics");
        assert!(rec.ok);
        assert_eq!(rec.node_id, "node-a");
        assert_eq!(rec.probe_id, "ext_1");
        assert_eq!(rec.latency_ms, Some(42.5));
        assert_eq!(rec.up_mbps, Some(28.4));
        assert_eq!(rec.cf_loc.as_deref(), Some("JP"));
        assert_eq!(rec.yt_gl.as_deref(), Some("US"));
        assert_eq!(rec.google_clean, Some(true));
        assert_eq!(rec.keepalive_60s_ok, Some(true));
        assert_eq!(rec.unlocked_map.get("claude"), Some(&true));

        // Exceeding 256 KiB must be rejected
        let oversized = vec![b' '; MAX_EXTERNAL_STDOUT_BYTES + 1];
        assert!(parse_external_probe_output(&oversized, "node-a", "ext_1").is_err());
    }

    #[tokio::test]
    async fn stdout_overflow_signals_abort_immediately_without_waiting_for_stderr() {
        let (mut out_writer, out_reader) = tokio::io::duplex(4096);
        let (_err_writer, err_reader) = tokio::io::duplex(1024);
        let (abort_tx, abort_rx) = tokio::sync::watch::channel(false);

        let writer_task = tokio::spawn(async move {
            let chunk = vec![b'X'; 4096];
            // Write more than the 16 KiB test cap; writer stops once reader drops.
            for _ in 0..16 {
                if out_writer.write_all(&chunk).await.is_err() {
                    break;
                }
            }
        });

        let stdout_fut = async move {
            let res = read_capped_stream(out_reader, 16 * 1024).await;
            if matches!(res, Ok((_, true))) {
                let _ = abort_tx.send(true);
            }
            res
        };

        let mut err_abort_rx = abort_rx.clone();
        let stderr_fut = async move {
            tokio::select! {
                res = read_capped_stream(err_reader, 1024) => res,
                _ = wait_until_aborted(&mut err_abort_rx) => Ok((Vec::new(), false)),
            }
        };

        let mut kill_abort_rx = abort_rx;
        let kill_fut = async move { kill_abort_rx.wait_for(|&aborted| aborted).await.is_ok() };

        // Must complete promptly even though `_err_writer` is still open and never sends EOF.
        let (stdout_res, stderr_res, kill_triggered) = tokio::time::timeout(
            Duration::from_secs(2),
            async { tokio::join!(stdout_fut, stderr_fut, kill_fut) },
        )
        .await
        .expect("stdout overflow must abort stderr immediately without hanging");

        let (buf, overflow) = stdout_res.unwrap();
        assert!(overflow);
        assert_eq!(buf.len(), 16 * 1024);
        assert!(stderr_res.is_ok());
        assert!(kill_triggered);
        writer_task.abort();
    }
}
