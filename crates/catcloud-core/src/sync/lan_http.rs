use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore, mpsc, watch};
use tokio::time::Instant;
use url::Url;

use crate::sync::crypto::{
    EphemeralP256KeyPair, KEY_LEN, P256_UNCOMPRESSED_PUB_LEN, SyncRole, SyncUri, compute_auth_mac,
    compute_pin_proof, decode_base64_flex, derive_ecdh_session_key, format_sync_uri,
    generate_pin_6, generate_random_bytes, generate_random_key, generate_session_id,
    is_forbidden_relay_ip, open_with_key_expect_sid, parse_sync_uri, plaintext_fingerprint,
    seal_with_key, validate_relay_url, verify_auth_mac, verify_pin_proof,
};
use crate::{CatError, CatResult};

/// Default one-shot LAN sync session TTL (180 seconds).
pub const DEFAULT_SYNC_TTL_SECS: u64 = 180;
/// Hard authentication failure limit before server auto-destruction.
pub const MAX_AUTH_FAILURES: u32 = 5;
/// Hard maximum request/response payload size (17 MiB).
pub const MAX_HTTP_BODY_BYTES: usize = 17 * 1024 * 1024;
const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;
const MAX_CHUNK_LINE_BYTES: usize = 256;
const MAX_CHUNK_TRAILER_BYTES: usize = 4 * 1024;
const INITIAL_BODY_BUF_CAP: usize = 64 * 1024;
const MAX_PIN_EXCHANGE_BODY_BYTES: usize = 8 * 1024;
const MAX_CONCURRENT_CONNECTIONS: usize = 32;
const CONNECTION_IO_TIMEOUT: Duration = Duration::from_secs(30);
const LAN_RACE_PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
const MAX_PUSH_EPHEM_SESSIONS: usize = 8;

/// Options for starting a LAN sync send/receive HTTP server.
#[derive(Debug, Clone)]
pub struct LanSyncServerOptions {
    /// Local bind IP address (defaults to `"0.0.0.0"`).
    pub bind_host: String,
    /// Local bind port (defaults to `0` for OS-assigned ephemeral port).
    pub bind_port: u16,
    /// Optional custom reachable URL (e.g. Tailscale/FRP/reverse proxy) embedded as `ep=`.
    pub custom_endpoint: Option<String>,
    /// Session lifetime in seconds (defaults to `180`).
    pub ttl_secs: u64,
    /// Allow multiple successful transfers before shutting down (defaults to `false`).
    pub allow_multiple: bool,
}

impl Default for LanSyncServerOptions {
    fn default() -> Self {
        Self {
            bind_host: "0.0.0.0".to_string(),
            bind_port: 0,
            custom_endpoint: None,
            ttl_secs: DEFAULT_SYNC_TTL_SECS,
            allow_multiple: false,
        }
    }
}

/// Public session metadata returned by [`LanSyncSendServer::start`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanSyncSendInfo {
    pub sid: String,
    pub port: u16,
    pub hosts: Vec<String>,
    pub custom_endpoint: Option<String>,
    pub pin: String,
    pub fingerprint: String,
    pub uri: String,
    pub expires_at_unix: i64,
    pub allow_multiple: bool,
}

/// Public session metadata returned by [`LanSyncReceiveServer::start`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanSyncReceiveInfo {
    pub sid: String,
    pub port: u16,
    pub hosts: Vec<String>,
    pub custom_endpoint: Option<String>,
    pub pin: String,
    pub uri: String,
    pub expires_at_unix: i64,
    pub allow_multiple: bool,
}

/// Decrypted bundle pushed to [`LanSyncReceiveServer`].
#[derive(Debug, Clone)]
pub struct ReceivedSyncBundle {
    pub sid: String,
    pub zip_bytes: Vec<u8>,
    pub fingerprint: String,
    pub via_pin: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct SyncInfoPayload {
    sid: String,
    role: String,
    challenge_b64: String,
    server_pub_p256_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PinExchangeRequest {
    sid: String,
    client_pub_p256_b64: String,
    proof: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PinExchangePushResponse {
    ok: bool,
    session_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct BundlePushResponse {
    ok: bool,
    fingerprint: String,
    bytes: usize,
}

struct PinHandshakeState {
    challenge: [u8; 16],
    challenge_b64: String,
    server_kp: Option<EphemeralP256KeyPair>,
    server_pub_b64: String,
}

impl PinHandshakeState {
    fn new_fresh() -> CatResult<Self> {
        let challenge = generate_random_bytes::<16>()?;
        let challenge_b64 = STANDARD.encode(challenge);
        let server_kp = EphemeralP256KeyPair::generate()?;
        let server_pub_b64 = server_kp.public_key_b64();
        Ok(Self {
            challenge,
            challenge_b64,
            server_kp: Some(server_kp),
            server_pub_b64,
        })
    }
}

enum ServerMode {
    Send {
        zip_bytes: Arc<Vec<u8>>,
    },
    Receive {
        bundle_tx: std::sync::Mutex<Option<mpsc::Sender<ReceivedSyncBundle>>>,
        push_ephem_sessions: Mutex<Vec<(String, [u8; KEY_LEN])>>,
    },
}

struct SharedServerState {
    sid: String,
    role: SyncRole,
    master_key: [u8; KEY_LEN],
    pin: String,
    allow_multiple: bool,
    consumed: AtomicBool,
    auth_failures: AtomicU32,
    destroyed: AtomicBool,
    is_closed: AtomicBool,
    shutdown_tx: watch::Sender<bool>,
    close_reason_tx: watch::Sender<Option<String>>,
    pin_handshake: Mutex<PinHandshakeState>,
    mode: ServerMode,
}

impl SharedServerState {
    fn set_close_reason_if_unset(&self, reason: &str) {
        self.close_reason_tx.send_if_modified(|cur| {
            if cur.is_none() {
                *cur = Some(reason.to_string());
                true
            } else {
                false
            }
        });
    }

    fn close_bundle_channel(&self) {
        if let ServerMode::Receive { bundle_tx, .. } = &self.mode
            && let Ok(mut guard) = bundle_tx.lock()
        {
            let _ = guard.take();
        }
    }

    fn record_auth_failure(&self) -> bool {
        let count = self.auth_failures.fetch_add(1, Ordering::SeqCst) + 1;
        if count >= MAX_AUTH_FAILURES {
            self.trigger_shutdown_with_reason("destroyed");
            true
        } else {
            false
        }
    }

    fn trigger_shutdown_with_reason(&self, reason: &str) {
        self.set_close_reason_if_unset(reason);
        self.destroyed.store(true, Ordering::SeqCst);
        let _ = self.shutdown_tx.send(true);
        self.close_bundle_channel();
    }

    fn is_destroyed(&self) -> bool {
        self.destroyed.load(Ordering::SeqCst)
    }
}

/// Active one-shot (or multi-pull) LAN HTTP/1.1 sync sender server.
pub struct LanSyncSendServer {
    info: LanSyncSendInfo,
    state: Arc<SharedServerState>,
    close_reason: watch::Receiver<Option<String>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl LanSyncSendServer {
    pub async fn start(zip_bytes: Vec<u8>, opts: LanSyncServerOptions) -> CatResult<Self> {
        if zip_bytes.len() + 256 > MAX_HTTP_BODY_BYTES {
            return Err(CatError::Validation(format!(
                "sync bundle ({} bytes) exceeds 17 MiB transport limit",
                zip_bytes.len()
            )));
        }

        let sid = generate_session_id()?;
        let master_key = generate_random_key()?;
        let pin = generate_pin_6()?;
        let fingerprint = plaintext_fingerprint(&zip_bytes);

        let bind_addr = format_bind_addr(&opts.bind_host, opts.bind_port);
        let listener = TcpListener::bind(&bind_addr).await?;
        let local_addr = listener.local_addr()?;
        let port = local_addr.port();

        let hosts = resolve_advertised_hosts(&opts.bind_host);
        let uri = format_sync_uri(&SyncUri {
            role: SyncRole::Pull,
            endpoint: opts.custom_endpoint.clone(),
            hosts: hosts.clone(),
            port: Some(port),
            sid: Some(sid.clone()),
            url: None,
            fingerprint: Some(fingerprint.clone()),
            key: master_key,
        })?;

        let ttl_secs = if opts.ttl_secs == 0 {
            DEFAULT_SYNC_TTL_SECS
        } else {
            opts.ttl_secs
        };
        let expires_at_unix = Utc::now().timestamp() + ttl_secs as i64;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (close_reason_tx, close_reason_rx) = watch::channel(None);
        let state = Arc::new(SharedServerState {
            sid: sid.clone(),
            role: SyncRole::Pull,
            master_key,
            pin: pin.clone(),
            allow_multiple: opts.allow_multiple,
            consumed: AtomicBool::new(false),
            auth_failures: AtomicU32::new(0),
            destroyed: AtomicBool::new(false),
            is_closed: AtomicBool::new(false),
            shutdown_tx,
            close_reason_tx,
            pin_handshake: Mutex::new(PinHandshakeState::new_fresh()?),
            mode: ServerMode::Send {
                zip_bytes: Arc::new(zip_bytes),
            },
        });

        let task = spawn_accept_loop(
            listener,
            Arc::clone(&state),
            shutdown_rx,
            Duration::from_secs(ttl_secs),
        );

        let info = LanSyncSendInfo {
            sid,
            port,
            hosts,
            custom_endpoint: opts.custom_endpoint,
            pin,
            fingerprint,
            uri,
            expires_at_unix,
            allow_multiple: opts.allow_multiple,
        };

        Ok(Self {
            info,
            state,
            close_reason: close_reason_rx,
            task: Some(task),
        })
    }

    pub fn info(&self) -> &LanSyncSendInfo {
        &self.info
    }

    pub fn is_running(&self) -> bool {
        !self.state.is_closed.load(Ordering::SeqCst)
    }

    pub fn auth_failure_count(&self) -> u32 {
        self.state.auth_failures.load(Ordering::SeqCst)
    }

    /// Subscribe to the session termination reason (`"completed"` / `"expired"` / `"destroyed"` / `"cancelled"`).
    pub fn subscribe_close_reason(&self) -> watch::Receiver<Option<String>> {
        self.close_reason.clone()
    }

    /// Current termination reason if the session has already closed.
    pub fn close_reason(&self) -> Option<String> {
        self.close_reason.borrow().clone()
    }

    /// Deterministically stop the listener and release the bound TCP port.
    pub async fn cancel(&mut self) {
        self.state.trigger_shutdown_with_reason("cancelled");
        if let Some(handle) = self.task.take() {
            let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        }
        self.state.is_closed.store(true, Ordering::SeqCst);
    }
}

impl Drop for LanSyncSendServer {
    fn drop(&mut self) {
        self.state.trigger_shutdown_with_reason("cancelled");
        if let Some(handle) = self.task.take() {
            handle.abort();
        }
        self.state.is_closed.store(true, Ordering::SeqCst);
    }
}

/// Active one-shot (or multi-push) LAN HTTP/1.1 sync receiver server.
pub struct LanSyncReceiveServer {
    info: LanSyncReceiveInfo,
    state: Arc<SharedServerState>,
    close_reason: watch::Receiver<Option<String>>,
    rx: Option<mpsc::Receiver<ReceivedSyncBundle>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl LanSyncReceiveServer {
    pub async fn start(opts: LanSyncServerOptions) -> CatResult<Self> {
        let sid = generate_session_id()?;
        let master_key = generate_random_key()?;
        let pin = generate_pin_6()?;

        let bind_addr = format_bind_addr(&opts.bind_host, opts.bind_port);
        let listener = TcpListener::bind(&bind_addr).await?;
        let local_addr = listener.local_addr()?;
        let port = local_addr.port();

        let hosts = resolve_advertised_hosts(&opts.bind_host);
        let uri = format_sync_uri(&SyncUri {
            role: SyncRole::Push,
            endpoint: opts.custom_endpoint.clone(),
            hosts: hosts.clone(),
            port: Some(port),
            sid: Some(sid.clone()),
            url: None,
            fingerprint: None,
            key: master_key,
        })?;

        let ttl_secs = if opts.ttl_secs == 0 {
            DEFAULT_SYNC_TTL_SECS
        } else {
            opts.ttl_secs
        };
        let expires_at_unix = Utc::now().timestamp() + ttl_secs as i64;

        let (bundle_tx, bundle_rx) = mpsc::channel(8);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (close_reason_tx, close_reason_rx) = watch::channel(None);
        let state = Arc::new(SharedServerState {
            sid: sid.clone(),
            role: SyncRole::Push,
            master_key,
            pin: pin.clone(),
            allow_multiple: opts.allow_multiple,
            consumed: AtomicBool::new(false),
            auth_failures: AtomicU32::new(0),
            destroyed: AtomicBool::new(false),
            is_closed: AtomicBool::new(false),
            shutdown_tx,
            close_reason_tx,
            pin_handshake: Mutex::new(PinHandshakeState::new_fresh()?),
            mode: ServerMode::Receive {
                bundle_tx: std::sync::Mutex::new(Some(bundle_tx)),
                push_ephem_sessions: Mutex::new(Vec::new()),
            },
        });

        let task = spawn_accept_loop(
            listener,
            Arc::clone(&state),
            shutdown_rx,
            Duration::from_secs(ttl_secs),
        );

        let info = LanSyncReceiveInfo {
            sid,
            port,
            hosts,
            custom_endpoint: opts.custom_endpoint,
            pin,
            uri,
            expires_at_unix,
            allow_multiple: opts.allow_multiple,
        };

        Ok(Self {
            info,
            state,
            close_reason: close_reason_rx,
            rx: Some(bundle_rx),
            task: Some(task),
        })
    }

    pub fn info(&self) -> &LanSyncReceiveInfo {
        &self.info
    }

    pub fn is_running(&self) -> bool {
        !self.state.is_closed.load(Ordering::SeqCst)
    }

    pub fn auth_failure_count(&self) -> u32 {
        self.state.auth_failures.load(Ordering::SeqCst)
    }

    /// Subscribe to the session termination reason (`"completed"` / `"expired"` / `"destroyed"` / `"cancelled"`).
    pub fn subscribe_close_reason(&self) -> watch::Receiver<Option<String>> {
        self.close_reason.clone()
    }

    /// Current termination reason if the session has already closed.
    pub fn close_reason(&self) -> Option<String> {
        self.close_reason.borrow().clone()
    }

    /// Take ownership of the received-bundle channel (e.g. to forward into a Tauri event emitter).
    pub fn take_receiver(&mut self) -> Option<mpsc::Receiver<ReceivedSyncBundle>> {
        self.rx.take()
    }

    /// Wait for the next decrypted bundle pushed to this listener.
    pub async fn recv_bundle(&mut self) -> Option<ReceivedSyncBundle> {
        match self.rx.as_mut() {
            Some(rx) => rx.recv().await,
            None => None,
        }
    }

    /// Deterministically stop the listener and release the bound TCP port.
    pub async fn cancel(&mut self) {
        self.state.trigger_shutdown_with_reason("cancelled");
        if let Some(handle) = self.task.take() {
            let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        }
        self.state.is_closed.store(true, Ordering::SeqCst);
    }
}

impl Drop for LanSyncReceiveServer {
    fn drop(&mut self) {
        self.state.trigger_shutdown_with_reason("cancelled");
        if let Some(handle) = self.task.take() {
            handle.abort();
        }
        self.state.is_closed.store(true, Ordering::SeqCst);
    }
}

fn format_bind_addr(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn resolve_advertised_hosts(bind_host: &str) -> Vec<String> {
    let trimmed = bind_host.trim();
    if trimmed == "0.0.0.0" || trimmed == "::" || trimmed.is_empty() {
        let candidates = list_lan_ipv4_candidates();
        if candidates.is_empty() {
            vec!["127.0.0.1".to_string()]
        } else {
            candidates
        }
    } else {
        vec![trimmed.to_string()]
    }
}

fn spawn_accept_loop(
    listener: TcpListener,
    state: Arc<SharedServerState>,
    mut shutdown_rx: watch::Receiver<bool>,
    ttl: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
        let deadline = Instant::now() + ttl;
        let sleep = tokio::time::sleep_until(deadline);
        tokio::pin!(sleep);

        loop {
            if *shutdown_rx.borrow() || state.is_destroyed() {
                break;
            }
            tokio::select! {
                biased;
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = &mut sleep => {
                    state.trigger_shutdown_with_reason("expired");
                    break;
                }
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, _peer)) => {
                            if state.is_destroyed() {
                                drop(stream);
                                break;
                            }
                            let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                                drop(stream);
                                continue;
                            };
                            let conn_state = Arc::clone(&state);
                            tokio::spawn(async move {
                                let _permit = permit;
                                let _ = tokio::time::timeout(
                                    CONNECTION_IO_TIMEOUT,
                                    handle_connection(stream, conn_state),
                                )
                                .await;
                            });
                        }
                        Err(_) => {
                            if state.is_destroyed() {
                                break;
                            }
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        }
                    }
                }
            }
        }

        drop(listener);
        state.close_bundle_channel();
        state.set_close_reason_if_unset("cancelled");
        state.is_closed.store(true, Ordering::SeqCst);
    })
}

struct ParsedHttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

enum ReadRequestError {
    Closed,
    BadRequest(&'static str),
    HeadersTooLarge,
    PayloadTooLarge,
}

async fn read_http_request(stream: &mut TcpStream) -> Result<ParsedHttpRequest, ReadRequestError> {
    let mut reader = BufReader::new(stream);
    let mut head_bytes = Vec::with_capacity(512);
    let mut line = Vec::with_capacity(256);

    loop {
        let remaining = MAX_HTTP_HEADER_BYTES.saturating_sub(head_bytes.len());
        if remaining == 0 {
            return Err(ReadRequestError::HeadersTooLarge);
        }
        line.clear();
        let n = (&mut reader)
            .take((remaining + 1) as u64)
            .read_until(b'\n', &mut line)
            .await
            .map_err(|_| ReadRequestError::Closed)?;
        if n == 0 {
            return Err(ReadRequestError::Closed);
        }
        if n > remaining {
            return Err(ReadRequestError::HeadersTooLarge);
        }
        if !line.ends_with(b"\n") {
            return Err(ReadRequestError::Closed);
        }
        head_bytes.extend_from_slice(&line);
        if line == b"\r\n" || line == b"\n" {
            break;
        }
    }

    let head_str = std::str::from_utf8(&head_bytes)
        .map_err(|_| ReadRequestError::BadRequest("invalid utf-8 headers"))?;
    let mut lines = head_str.lines();
    let request_line = lines
        .next()
        .ok_or(ReadRequestError::BadRequest("missing request line"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or(ReadRequestError::BadRequest("missing method"))?
        .to_ascii_uppercase();
    let raw_target = parts
        .next()
        .ok_or(ReadRequestError::BadRequest("missing target"))?;
    let _version = parts
        .next()
        .ok_or(ReadRequestError::BadRequest("missing HTTP version"))?;

    let path = raw_target
        .split('?')
        .next()
        .unwrap_or(raw_target)
        .to_string();

    let mut headers = HashMap::new();
    for raw_line in lines {
        let trimmed = raw_line.trim_end_matches('\r');
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    // Handle `Expect: 100-continue` before reading body
    if let Some(expect) = headers.get("expect")
        && expect.eq_ignore_ascii_case("100-continue")
    {
        let _ = reader
            .get_mut()
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await;
    }

    let is_chunked = headers
        .get("transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);

    let body = if is_chunked {
        read_chunked_body(&mut reader, MAX_HTTP_BODY_BYTES).await?
    } else if let Some(cl_str) = headers.get("content-length") {
        let content_len: usize = cl_str
            .parse()
            .map_err(|_| ReadRequestError::BadRequest("invalid content-length"))?;
        if content_len > MAX_HTTP_BODY_BYTES {
            return Err(ReadRequestError::PayloadTooLarge);
        }
        let mut buf = Vec::with_capacity(content_len.min(INITIAL_BODY_BUF_CAP));
        let mut limited = (&mut reader).take(content_len as u64);
        let mut chunk = [0u8; 16 * 1024];
        while buf.len() < content_len {
            let n = limited
                .read(&mut chunk)
                .await
                .map_err(|_| ReadRequestError::BadRequest("truncated request body"))?;
            if n == 0 {
                return Err(ReadRequestError::BadRequest("truncated request body"));
            }
            if buf.len().saturating_add(n) > MAX_HTTP_BODY_BYTES {
                return Err(ReadRequestError::PayloadTooLarge);
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        buf
    } else {
        Vec::new()
    };

    Ok(ParsedHttpRequest {
        method,
        path,
        headers,
        body,
    })
}

async fn read_chunked_body<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    max_bytes: usize,
) -> Result<Vec<u8>, ReadRequestError> {
    let mut out = Vec::new();
    let mut size_line = Vec::with_capacity(64);
    let mut chunk_buf = [0u8; 16 * 1024];
    loop {
        size_line.clear();
        let n = (&mut *reader)
            .take((MAX_CHUNK_LINE_BYTES + 1) as u64)
            .read_until(b'\n', &mut size_line)
            .await
            .map_err(|_| ReadRequestError::BadRequest("truncated chunk size"))?;
        if n == 0 {
            return Err(ReadRequestError::BadRequest("unexpected EOF in chunked body"));
        }
        if n > MAX_CHUNK_LINE_BYTES {
            return Err(ReadRequestError::BadRequest("chunk size line too long"));
        }
        if !size_line.ends_with(b"\n") {
            return Err(ReadRequestError::BadRequest("truncated chunk size"));
        }
        let size_str = std::str::from_utf8(&size_line)
            .map_err(|_| ReadRequestError::BadRequest("invalid utf-8 chunk size"))?;
        let size_hex = size_str
            .trim()
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let chunk_len = usize::from_str_radix(size_hex, 16)
            .map_err(|_| ReadRequestError::BadRequest("invalid chunk size hex"))?;
        if chunk_len == 0 {
            // Drain bounded trailing headers / CRLF
            let mut trailer_total = 0usize;
            let mut trailer = Vec::with_capacity(64);
            loop {
                trailer.clear();
                let tn = (&mut *reader)
                    .take((MAX_CHUNK_LINE_BYTES + 1) as u64)
                    .read_until(b'\n', &mut trailer)
                    .await
                    .map_err(|_| ReadRequestError::BadRequest("truncated chunk trailer"))?;
                if tn == 0 {
                    break;
                }
                if tn > MAX_CHUNK_LINE_BYTES {
                    return Err(ReadRequestError::BadRequest("chunk trailer line too long"));
                }
                if !trailer.ends_with(b"\n") {
                    return Err(ReadRequestError::BadRequest("truncated chunk trailer"));
                }
                trailer_total = trailer_total.saturating_add(tn);
                if trailer_total > MAX_CHUNK_TRAILER_BYTES {
                    return Err(ReadRequestError::BadRequest("chunk trailers too large"));
                }
                if trailer == b"\r\n" || trailer == b"\n" {
                    break;
                }
            }
            break;
        }
        if out.len().saturating_add(chunk_len) > max_bytes {
            return Err(ReadRequestError::PayloadTooLarge);
        }
        let target_len = out.len() + chunk_len;
        out.reserve(chunk_len.min(INITIAL_BODY_BUF_CAP));
        let mut limited = (&mut *reader).take(chunk_len as u64);
        while out.len() < target_len {
            let rn = limited
                .read(&mut chunk_buf)
                .await
                .map_err(|_| ReadRequestError::BadRequest("truncated chunk payload"))?;
            if rn == 0 {
                return Err(ReadRequestError::BadRequest("truncated chunk payload"));
            }
            out.extend_from_slice(&chunk_buf[..rn]);
        }
        let mut crlf = [0u8; 2];
        reader
            .read_exact(&mut crlf)
            .await
            .map_err(|_| ReadRequestError::BadRequest("missing chunk CRLF"))?;
        if crlf != *b"\r\n" {
            return Err(ReadRequestError::BadRequest("invalid chunk CRLF"));
        }
    }
    Ok(out)
}

async fn write_http_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

async fn write_json_error(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    message: &str,
) -> std::io::Result<()> {
    let body = serde_json::json!({ "error": message }).to_string();
    write_http_response(stream, status, reason, "application/json", body.as_bytes()).await
}

async fn handle_connection(mut stream: TcpStream, state: Arc<SharedServerState>) {
    if state.is_destroyed() {
        return;
    }

    let req = match read_http_request(&mut stream).await {
        Ok(r) => r,
        Err(ReadRequestError::Closed) => return,
        Err(ReadRequestError::BadRequest(msg)) => {
            let _ = write_json_error(&mut stream, 400, "Bad Request", msg).await;
            return;
        }
        Err(ReadRequestError::HeadersTooLarge) => {
            let _ = write_json_error(&mut stream, 431, "Request Header Fields Too Large", "headers too large").await;
            return;
        }
        Err(ReadRequestError::PayloadTooLarge) => {
            let _ = write_json_error(&mut stream, 413, "Payload Too Large", "body exceeds 17 MiB limit").await;
            return;
        }
    };

    if state.is_destroyed() {
        let _ = write_json_error(&mut stream, 410, "Gone", "sync session closed").await;
        return;
    }

    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/sync/v1/info") => {
            handle_info(&mut stream, &state).await;
        }
        ("POST", "/sync/v1/pin-exchange") => {
            handle_pin_exchange(&mut stream, &state, &req).await;
        }
        ("GET", "/sync/v1/bundle") => {
            handle_get_bundle(&mut stream, &state, &req).await;
        }
        ("POST", "/sync/v1/bundle") => {
            handle_post_bundle(&mut stream, &state, &req).await;
        }
        (_, "/sync/v1/info" | "/sync/v1/pin-exchange" | "/sync/v1/bundle") => {
            let _ = write_json_error(&mut stream, 405, "Method Not Allowed", "method not allowed").await;
        }
        _ => {
            let _ = write_json_error(&mut stream, 404, "Not Found", "not found").await;
        }
    }
}

async fn handle_info(stream: &mut TcpStream, state: &SharedServerState) {
    let hs = state.pin_handshake.lock().await;
    let payload = SyncInfoPayload {
        sid: state.sid.clone(),
        role: state.role.as_str().to_string(),
        challenge_b64: hs.challenge_b64.clone(),
        server_pub_p256_b64: hs.server_pub_b64.clone(),
    };
    drop(hs);
    if let Ok(json) = serde_json::to_vec(&payload) {
        let _ = write_http_response(stream, 200, "OK", "application/json", &json).await;
    }
}

async fn handle_pin_exchange(
    stream: &mut TcpStream,
    state: &SharedServerState,
    req: &ParsedHttpRequest,
) {
    if req.body.len() > MAX_PIN_EXCHANGE_BODY_BYTES {
        let _ = write_json_error(stream, 413, "Payload Too Large", "pin-exchange body too large").await;
        return;
    }

    let parsed: PinExchangeRequest = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => {
            let destroyed = state.record_auth_failure();
            let status = if destroyed { (429, "Too Many Requests") } else { (400, "Bad Request") };
            let _ = write_json_error(stream, status.0, status.1, "invalid pin-exchange json").await;
            return;
        }
    };

    if parsed.sid != state.sid {
        let destroyed = state.record_auth_failure();
        let status = if destroyed { (429, "Too Many Requests") } else { (403, "Forbidden") };
        let _ = write_json_error(stream, status.0, status.1, "session id mismatch").await;
        return;
    }

    let client_pub = match decode_base64_flex(&parsed.client_pub_p256_b64) {
        Ok(b) if b.len() == P256_UNCOMPRESSED_PUB_LEN && b[0] == 0x04 => b,
        _ => {
            let destroyed = state.record_auth_failure();
            let status = if destroyed { (429, "Too Many Requests") } else { (400, "Bad Request") };
            let _ = write_json_error(stream, status.0, status.1, "invalid client P-256 public key").await;
            return;
        }
    };

    // Verify PIN proof BEFORE consuming server ephemeral P-256 private key
    let k_ephem = {
        let mut hs = state.pin_handshake.lock().await;
        if !verify_pin_proof(
            &state.pin,
            &state.sid,
            &hs.challenge_b64,
            &hs.server_pub_b64,
            &parsed.client_pub_p256_b64,
            &parsed.proof,
        ) {
            let destroyed = state.record_auth_failure();
            drop(hs);
            let status = if destroyed { (429, "Too Many Requests") } else { (403, "Forbidden") };
            let _ = write_json_error(stream, status.0, status.1, "invalid pin proof").await;
            return;
        }

        let Some(server_kp) = hs.server_kp.take() else {
            drop(hs);
            let _ = write_json_error(stream, 410, "Gone", "ephemeral handshake already consumed").await;
            return;
        };
        let challenge = hs.challenge;

        // Rotate handshake keypair for any subsequent client (when allow_multiple or push retry)
        if let Ok(next_hs) = PinHandshakeState::new_fresh() {
            *hs = next_hs;
        }
        drop(hs);

        match derive_ecdh_session_key(server_kp, &client_pub, &challenge, &state.sid) {
            Ok(k) => k,
            Err(_) => {
                let _ = write_json_error(stream, 400, "Bad Request", "ECDH agreement failed").await;
                return;
            }
        }
    };

    match &state.mode {
        ServerMode::Send { zip_bytes } => {
            if !state.allow_multiple
                && state
                    .consumed
                    .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                    .is_err()
            {
                let _ = write_json_error(stream, 410, "Gone", "sync session already consumed").await;
                return;
            }
            match seal_with_key(zip_bytes, &k_ephem, &state.sid) {
                Ok(envelope) => {
                    let _ = write_http_response(
                        stream,
                        200,
                        "OK",
                        "application/octet-stream",
                        &envelope,
                    )
                    .await;
                    if !state.allow_multiple {
                        state.trigger_shutdown_with_reason("completed");
                    }
                }
                Err(_) => {
                    if !state.allow_multiple {
                        state.consumed.store(false, Ordering::SeqCst);
                    }
                    let _ = write_json_error(stream, 500, "Internal Server Error", "encryption failed").await;
                }
            }
        }
        ServerMode::Receive {
            push_ephem_sessions,
            ..
        } => {
            let token = match generate_random_bytes::<16>() {
                Ok(b) => hex::encode(b),
                Err(_) => {
                    let _ = write_json_error(stream, 500, "Internal Server Error", "rng failed").await;
                    return;
                }
            };
            {
                let mut sessions = push_ephem_sessions.lock().await;
                if sessions.len() >= MAX_PUSH_EPHEM_SESSIONS {
                    sessions.remove(0);
                }
                sessions.push((token.clone(), k_ephem));
            }
            let resp = PinExchangePushResponse {
                ok: true,
                session_token: token,
            };
            if let Ok(json) = serde_json::to_vec(&resp) {
                let _ = write_http_response(stream, 200, "OK", "application/json", &json).await;
            }
        }
    }
}

async fn handle_get_bundle(
    stream: &mut TcpStream,
    state: &SharedServerState,
    req: &ParsedHttpRequest,
) {
    let ServerMode::Send { zip_bytes } = &state.mode else {
        let _ = write_json_error(stream, 405, "Method Not Allowed", "server is in push receive mode").await;
        return;
    };

    let sid_hdr = req.headers.get("x-catcloud-sid").map(String::as_str).unwrap_or("");
    let auth_hdr = req.headers.get("x-catcloud-auth").map(String::as_str).unwrap_or("");

    if sid_hdr != state.sid
        || !verify_auth_mac(&state.master_key, &state.sid, "GET", "/sync/v1/bundle", auth_hdr)
    {
        let destroyed = state.record_auth_failure();
        let status = if destroyed { (429, "Too Many Requests") } else { (403, "Forbidden") };
        let _ = write_json_error(stream, status.0, status.1, "authentication failed").await;
        return;
    }

    if !state.allow_multiple
        && state
            .consumed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
    {
        let _ = write_json_error(stream, 410, "Gone", "sync session already consumed").await;
        return;
    }

    match seal_with_key(zip_bytes, &state.master_key, &state.sid) {
        Ok(envelope) => {
            let _ = write_http_response(stream, 200, "OK", "application/octet-stream", &envelope).await;
            if !state.allow_multiple {
                state.trigger_shutdown_with_reason("completed");
            }
        }
        Err(_) => {
            if !state.allow_multiple {
                state.consumed.store(false, Ordering::SeqCst);
            }
            let _ = write_json_error(stream, 500, "Internal Server Error", "encryption failed").await;
        }
    }
}

async fn handle_post_bundle(
    stream: &mut TcpStream,
    state: &SharedServerState,
    req: &ParsedHttpRequest,
) {
    let ServerMode::Receive {
        bundle_tx,
        push_ephem_sessions,
    } = &state.mode
    else {
        let _ = write_json_error(stream, 405, "Method Not Allowed", "server is in pull send mode").await;
        return;
    };

    let sid_hdr = req.headers.get("x-catcloud-sid").map(String::as_str).unwrap_or("");
    let auth_hdr = req.headers.get("x-catcloud-auth").map(String::as_str).unwrap_or("");
    let token_hdr = req.headers.get("x-catcloud-session-token").map(String::as_str);

    if sid_hdr != state.sid {
        let destroyed = state.record_auth_failure();
        let status = if destroyed { (429, "Too Many Requests") } else { (403, "Forbidden") };
        let _ = write_json_error(stream, status.0, status.1, "session id mismatch").await;
        return;
    }

    let matched: Option<([u8; KEY_LEN], bool)> = if verify_auth_mac(
        &state.master_key,
        &state.sid,
        "POST",
        "/sync/v1/bundle",
        auth_hdr,
    ) {
        Some((state.master_key, false))
    } else {
        let mut sessions = push_ephem_sessions.lock().await;
        let idx = if let Some(tok) = token_hdr {
            sessions.iter().position(|(t, k)| {
                t == tok && verify_auth_mac(k, &state.sid, "POST", "/sync/v1/bundle", auth_hdr)
            })
        } else {
            sessions
                .iter()
                .position(|(_, k)| verify_auth_mac(k, &state.sid, "POST", "/sync/v1/bundle", auth_hdr))
        };
        idx.map(|i| {
            let (_, key) = sessions.remove(i);
            (key, true)
        })
    };

    let Some((decrypt_key, via_pin)) = matched else {
        let destroyed = state.record_auth_failure();
        let status = if destroyed { (429, "Too Many Requests") } else { (403, "Forbidden") };
        let _ = write_json_error(stream, status.0, status.1, "authentication failed").await;
        return;
    };

    let zip_bytes = match open_with_key_expect_sid(&req.body, &decrypt_key, &state.sid) {
        Ok(b) => b,
        Err(_) => {
            let destroyed = state.record_auth_failure();
            let status = if destroyed { (429, "Too Many Requests") } else { (400, "Bad Request") };
            let _ = write_json_error(stream, status.0, status.1, "failed to decrypt sync envelope").await;
            return;
        }
    };

    if !state.allow_multiple
        && state
            .consumed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
    {
        let _ = write_json_error(stream, 410, "Gone", "sync session already consumed").await;
        return;
    }

    let fingerprint = plaintext_fingerprint(&zip_bytes);
    let byte_len = zip_bytes.len();
    let event = ReceivedSyncBundle {
        sid: state.sid.clone(),
        zip_bytes,
        fingerprint: fingerprint.clone(),
        via_pin,
    };

    let tx_opt = bundle_tx.lock().ok().and_then(|g| g.as_ref().cloned());
    let Some(tx) = tx_opt else {
        let _ = write_json_error(stream, 410, "Gone", "receiver channel closed").await;
        return;
    };

    if tx.send(event).await.is_err() {
        let _ = write_json_error(stream, 410, "Gone", "receiver channel closed").await;
        return;
    }

    let resp = BundlePushResponse {
        ok: true,
        fingerprint,
        bytes: byte_len,
    };
    if let Ok(json) = serde_json::to_vec(&resp) {
        let _ = write_http_response(stream, 200, "OK", "application/json", &json).await;
    }

    if !state.allow_multiple {
        state.trigger_shutdown_with_reason("completed");
    }
}

// ============================================================================
// Client Helpers
// ============================================================================

fn build_lan_client(timeout: Duration) -> CatResult<reqwest::Client> {
    crate::init_crypto_provider();
    reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(3))
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(CatError::Http)
}

fn normalize_base_url(addr_or_url: &str) -> CatResult<String> {
    let trimmed = addr_or_url.trim();
    if trimmed.is_empty() {
        return Err(CatError::Validation("sync target address is empty".into()));
    }
    let with_scheme = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };
    let parsed = Url::parse(&with_scheme)
        .map_err(|err| CatError::Validation(format!("invalid sync target '{trimmed}': {err}")))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(CatError::Security(
            "sync target URL must not include embedded credentials".into(),
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| CatError::Validation("sync target missing host".into()))?;
    let port_part = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
    let path_prefix = parsed.path().trim_end_matches('/');
    let path_clean = if path_prefix == "/sync/v1/info"
        || path_prefix == "/sync/v1/bundle"
        || path_prefix == "/sync/v1/pin-exchange"
    {
        ""
    } else {
        path_prefix
    };
    Ok(format!("{}://{}{}{}", parsed.scheme(), host, port_part, path_clean))
}

fn candidate_base_urls_from_uri(uri: &SyncUri) -> CatResult<Vec<String>> {
    let mut out = Vec::new();
    if let Some(ep) = &uri.endpoint {
        out.push(normalize_base_url(ep)?);
    }
    if let Some(port) = uri.port {
        for host in &uri.hosts {
            let formatted = if host.contains(':') && !host.starts_with('[') {
                format!("http://[{host}]:{port}")
            } else {
                format!("http://{host}:{port}")
            };
            if !out.contains(&formatted) {
                out.push(formatted);
            }
        }
    }
    if out.is_empty() {
        return Err(CatError::Validation(
            "sync URI contains no reachable hosts or endpoint".into(),
        ));
    }
    Ok(out)
}

async fn race_best_base_url(candidates: &[String], expected_sid: &str) -> CatResult<String> {
    if candidates.len() == 1 {
        return Ok(candidates[0].clone());
    }
    let probe_client = build_lan_client(LAN_RACE_PROBE_TIMEOUT)?;
    let mut set = tokio::task::JoinSet::new();
    for base in candidates {
        let client = probe_client.clone();
        let url = format!("{base}/sync/v1/info");
        let base_owned = base.clone();
        let sid_owned = expected_sid.to_string();
        set.spawn(async move {
            let resp = client.get(&url).send().await.ok()?;
            if !resp.status().is_success() {
                return None;
            }
            let info: SyncInfoPayload = resp.json().await.ok()?;
            if info.sid == sid_owned {
                Some(base_owned)
            } else {
                None
            }
        });
    }
    while let Some(res) = set.join_next().await {
        if let Ok(Some(winner)) = res {
            set.abort_all();
            return Ok(winner);
        }
    }
    // Fallback to first candidate to produce a concrete connection error downstream
    Ok(candidates[0].clone())
}

async fn read_response_bytes_bounded(
    mut resp: reqwest::Response,
    max_bytes: usize,
) -> CatResult<Vec<u8>> {
    if let Some(cl) = resp.content_length()
        && cl as usize > max_bytes
    {
        return Err(CatError::Validation(format!(
            "sync response length ({cl} bytes) exceeds {max_bytes} byte limit"
        )));
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if out.len().saturating_add(chunk.len()) > max_bytes {
            return Err(CatError::Validation(format!(
                "sync response body exceeds {max_bytes} byte limit"
            )));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Fetch and decrypt a sync bundle from a `catcloud://sync/v1?role=pull...#k=...` URI
/// (also seamlessly delegates `role=relay_url` URIs).
pub async fn fetch_sync_bundle_via_uri(uri: &str) -> CatResult<Vec<u8>> {
    let parsed = parse_sync_uri(uri)?;
    match parsed.role {
        SyncRole::RelayUrl => return fetch_relay_url_bundle(uri).await,
        SyncRole::Pull => {}
        other => {
            return Err(CatError::Validation(format!(
                "expected 'pull' (or 'relay_url') sync URI, got '{}'",
                other.as_str()
            )));
        }
    }

    let sid = parsed
        .sid
        .as_deref()
        .ok_or_else(|| CatError::Validation("pull sync URI missing 'sid'".into()))?;
    let candidates = candidate_base_urls_from_uri(&parsed)?;
    let base = race_best_base_url(&candidates, sid).await?;

    let client = build_lan_client(Duration::from_secs(30))?;
    let auth = compute_auth_mac(&parsed.key, sid, "GET", "/sync/v1/bundle");
    let resp = client
        .get(format!("{base}/sync/v1/bundle"))
        .header("X-CatCloud-Sid", sid)
        .header("X-CatCloud-Auth", auth)
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(CatError::Security(format!(
            "sync pull rejected by sender with HTTP {}",
            resp.status().as_u16()
        )));
    }

    let body = read_response_bytes_bounded(resp, MAX_HTTP_BODY_BYTES).await?;
    let zip_bytes = open_with_key_expect_sid(&body, &parsed.key, sid)?;

    if let Some(expected_fp) = &parsed.fingerprint {
        let actual_fp = plaintext_fingerprint(&zip_bytes);
        if &actual_fp != expected_fp {
            return Err(CatError::Security(format!(
                "sync bundle fingerprint mismatch (expected {expected_fp}, got {actual_fp})"
            )));
        }
    }
    Ok(zip_bytes)
}

/// Fetch and decrypt a sync bundle from a LAN sender via 6-digit PIN + ephemeral ECDH P-256 handshake.
pub async fn fetch_sync_bundle_via_pin(addr_or_url: &str, pin: &str) -> CatResult<Vec<u8>> {
    let pin_clean = pin.trim();
    if pin_clean.is_empty() {
        return Err(CatError::Validation("sync PIN must not be empty".into()));
    }
    let base = normalize_base_url(addr_or_url)?;
    let client = build_lan_client(Duration::from_secs(30))?;

    let info_resp = client.get(format!("{base}/sync/v1/info")).send().await?;
    if !info_resp.status().is_success() {
        return Err(CatError::Core(format!(
            "sync info probe failed with HTTP {}",
            info_resp.status().as_u16()
        )));
    }
    let info: SyncInfoPayload = info_resp.json().await?;
    if info.role != "pull" {
        return Err(CatError::Validation(format!(
            "peer sync role is '{}', expected 'pull'",
            info.role
        )));
    }

    let challenge = decode_base64_flex(&info.challenge_b64)?;
    let server_pub = decode_base64_flex(&info.server_pub_p256_b64)?;
    let client_kp = EphemeralP256KeyPair::generate()?;
    let client_pub_b64 = client_kp.public_key_b64();
    let proof = compute_pin_proof(
        pin_clean,
        &info.sid,
        &info.challenge_b64,
        &info.server_pub_p256_b64,
        &client_pub_b64,
    );
    let k_ephem = derive_ecdh_session_key(client_kp, &server_pub, &challenge, &info.sid)?;

    let exchange_req = PinExchangeRequest {
        sid: info.sid.clone(),
        client_pub_p256_b64: client_pub_b64,
        proof,
    };
    let resp = client
        .post(format!("{base}/sync/v1/pin-exchange"))
        .json(&exchange_req)
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(CatError::Security(format!(
            "PIN exchange rejected with HTTP {}",
            resp.status().as_u16()
        )));
    }

    let envelope = read_response_bytes_bounded(resp, MAX_HTTP_BODY_BYTES).await?;
    open_with_key_expect_sid(&envelope, &k_ephem, &info.sid)
}

/// Encrypt and push a sync bundle to a `catcloud://sync/v1?role=push...#k=...` receiver URI.
pub async fn push_sync_bundle_via_uri(uri: &str, zip_bytes: &[u8]) -> CatResult<()> {
    let parsed = parse_sync_uri(uri)?;
    if parsed.role != SyncRole::Push {
        return Err(CatError::Validation(format!(
            "expected 'push' sync URI, got '{}'",
            parsed.role.as_str()
        )));
    }
    let sid = parsed
        .sid
        .as_deref()
        .ok_or_else(|| CatError::Validation("push sync URI missing 'sid'".into()))?;
    let envelope = seal_with_key(zip_bytes, &parsed.key, sid)?;
    if envelope.len() > MAX_HTTP_BODY_BYTES {
        return Err(CatError::Validation(
            "encrypted sync bundle exceeds 17 MiB limit".into(),
        ));
    }

    let candidates = candidate_base_urls_from_uri(&parsed)?;
    let base = race_best_base_url(&candidates, sid).await?;
    let client = build_lan_client(Duration::from_secs(30))?;
    let auth = compute_auth_mac(&parsed.key, sid, "POST", "/sync/v1/bundle");

    let resp = client
        .post(format!("{base}/sync/v1/bundle"))
        .header("Content-Type", "application/octet-stream")
        .header("X-CatCloud-Sid", sid)
        .header("X-CatCloud-Auth", auth)
        .body(envelope)
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(CatError::Security(format!(
            "sync push rejected by receiver with HTTP {}",
            resp.status().as_u16()
        )));
    }
    Ok(())
}

/// Push an encrypted sync bundle to a LAN receiver via 6-digit PIN + ephemeral ECDH P-256 handshake.
pub async fn push_sync_bundle_via_pin(
    addr_or_url: &str,
    pin: &str,
    zip_bytes: &[u8],
) -> CatResult<()> {
    let pin_clean = pin.trim();
    if pin_clean.is_empty() {
        return Err(CatError::Validation("sync PIN must not be empty".into()));
    }
    let base = normalize_base_url(addr_or_url)?;
    let client = build_lan_client(Duration::from_secs(30))?;

    let info_resp = client.get(format!("{base}/sync/v1/info")).send().await?;
    if !info_resp.status().is_success() {
        return Err(CatError::Core(format!(
            "sync info probe failed with HTTP {}",
            info_resp.status().as_u16()
        )));
    }
    let info: SyncInfoPayload = info_resp.json().await?;
    if info.role != "push" {
        return Err(CatError::Validation(format!(
            "peer sync role is '{}', expected 'push'",
            info.role
        )));
    }

    let challenge = decode_base64_flex(&info.challenge_b64)?;
    let server_pub = decode_base64_flex(&info.server_pub_p256_b64)?;
    let client_kp = EphemeralP256KeyPair::generate()?;
    let client_pub_b64 = client_kp.public_key_b64();
    let proof = compute_pin_proof(
        pin_clean,
        &info.sid,
        &info.challenge_b64,
        &info.server_pub_p256_b64,
        &client_pub_b64,
    );
    let k_ephem = derive_ecdh_session_key(client_kp, &server_pub, &challenge, &info.sid)?;

    let exchange_req = PinExchangeRequest {
        sid: info.sid.clone(),
        client_pub_p256_b64: client_pub_b64,
        proof,
    };
    let ex_resp = client
        .post(format!("{base}/sync/v1/pin-exchange"))
        .json(&exchange_req)
        .send()
        .await?;
    if !ex_resp.status().is_success() {
        return Err(CatError::Security(format!(
            "PIN exchange rejected with HTTP {}",
            ex_resp.status().as_u16()
        )));
    }
    let ex_body: PinExchangePushResponse = ex_resp.json().await?;
    if !ex_body.ok || ex_body.session_token.is_empty() {
        return Err(CatError::Security(
            "peer returned invalid pin-exchange push token".into(),
        ));
    }

    let envelope = seal_with_key(zip_bytes, &k_ephem, &info.sid)?;
    if envelope.len() > MAX_HTTP_BODY_BYTES {
        return Err(CatError::Validation(
            "encrypted sync bundle exceeds 17 MiB limit".into(),
        ));
    }
    let auth = compute_auth_mac(&k_ephem, &info.sid, "POST", "/sync/v1/bundle");
    let push_resp = client
        .post(format!("{base}/sync/v1/bundle"))
        .header("Content-Type", "application/octet-stream")
        .header("X-CatCloud-Sid", &info.sid)
        .header("X-CatCloud-Auth", auth)
        .header("X-CatCloud-Session-Token", &ex_body.session_token)
        .body(envelope)
        .send()
        .await?;

    if !push_resp.status().is_success() {
        return Err(CatError::Security(format!(
            "sync push rejected with HTTP {}",
            push_resp.status().as_u16()
        )));
    }
    Ok(())
}

/// Fetch and decrypt an encrypted `CCSYNC01` bundle hosted on a public zero-knowledge HTTPS URL.
/// Enforces `https://`, no redirects, DNS pre-resolution SSRF checks, and 17 MiB body cap.
pub async fn fetch_relay_url_bundle(uri: &str) -> CatResult<Vec<u8>> {
    let parsed = parse_sync_uri(uri)?;
    if parsed.role != SyncRole::RelayUrl {
        return Err(CatError::Validation(format!(
            "expected 'relay_url' sync URI, got '{}'",
            parsed.role.as_str()
        )));
    }
    let raw_url = parsed
        .url
        .as_deref()
        .ok_or_else(|| CatError::Validation("relay_url sync URI missing 'url'".into()))?;
    let validated_url = validate_relay_url(raw_url)?;

    let host = validated_url
        .host_str()
        .ok_or_else(|| CatError::Validation("relay_url missing host".into()))?;
    let port = validated_url.port_or_known_default().unwrap_or(443);

    // Pre-resolve DNS and pin vetted public IPs to prevent DNS rebinding SSRF
    let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|err| CatError::Core(format!("failed to resolve relay host '{host}': {err}")))?
        .collect();
    if resolved.is_empty() {
        return Err(CatError::Core(format!(
            "relay host '{host}' resolved to zero addresses"
        )));
    }
    for addr in &resolved {
        if is_forbidden_relay_ip(addr.ip()) {
            return Err(CatError::Security(format!(
                "relay host '{host}' resolved to forbidden IP {} (blocked by SSRF policy)",
                addr.ip()
            )));
        }
    }

    crate::init_crypto_provider();
    let client = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(45))
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(host, &resolved)
        .build()?;

    let resp = client.get(validated_url.as_str()).send().await?;
    if !resp.status().is_success() {
        return Err(CatError::Core(format!(
            "relay URL fetch failed with HTTP {}",
            resp.status().as_u16()
        )));
    }

    let body = read_response_bytes_bounded(resp, MAX_HTTP_BODY_BYTES).await?;
    let zip_bytes = open_with_key_expect_sid(&body, &parsed.key, "")?;

    if let Some(expected_fp) = &parsed.fingerprint {
        let actual_fp = plaintext_fingerprint(&zip_bytes);
        if &actual_fp != expected_fp {
            return Err(CatError::Security(format!(
                "relay bundle fingerprint mismatch (expected {expected_fp}, got {actual_fp})"
            )));
        }
    }
    Ok(zip_bytes)
}

// ============================================================================
// Multi-NIC Filtered LAN IPv4 Discovery
// ============================================================================

fn is_valid_lan_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    if ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_unspecified()
        || o[0] == 0
        || o[0] >= 240
    {
        return false;
    }
    // Filter 198.18.0.0/15 (Mihomo Fake-IP TUN)
    if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
        return false;
    }
    true
}

fn is_virtual_adapter_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    const NOISY_KEYWORDS: &[&str] = &[
        "wintun",
        "mihomo",
        "clash",
        "vethernet",
        "hyper-v",
        "wsl",
        "vmware",
        "virtualbox",
        "vbox",
        "loopback",
        "bluetooth",
        "npcap",
        "tap-windows",
        "docker",
        "virbr",
        "vmnet",
        "utun",
        "awdl",
        "llw",
    ];
    NOISY_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

fn probe_default_egress_ipv4() -> Option<Ipv4Addr> {
    for target in ["223.5.5.5:53", "8.8.8.8:53", "192.168.1.1:80"] {
        if let Ok(sock) = UdpSocket::bind("0.0.0.0:0")
            && sock.connect(target).is_ok()
            && let Ok(SocketAddr::V4(local)) = sock.local_addr()
        {
            let ip = *local.ip();
            if is_valid_lan_ipv4(ip) {
                return Some(ip);
            }
        }
    }
    None
}

#[derive(Debug, Clone)]
struct DiscoveredNic {
    ip: Ipv4Addr,
    is_virtual: bool,
}

#[cfg(windows)]
fn enumerate_platform_ipv4_nics() -> Vec<DiscoveredNic> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
        GetAdaptersAddresses, IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_TUNNEL, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

    unsafe fn pwstr_to_string(ptr: *const u16) -> String {
        if ptr.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        unsafe {
            while *ptr.add(len) != 0 {
                len += 1;
            }
            let slice = std::slice::from_raw_parts(ptr, len);
            OsString::from_wide(slice).to_string_lossy().into_owned()
        }
    }

    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut buf_len: u32 = 16 * 1024;
    let mut buffer = vec![0u8; buf_len as usize];

    let status = unsafe {
        GetAdaptersAddresses(
            AF_INET as u32,
            flags,
            std::ptr::null_mut(),
            buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
            &mut buf_len,
        )
    };
    let status = if status == ERROR_BUFFER_OVERFLOW {
        buffer.resize(buf_len as usize, 0);
        unsafe {
            GetAdaptersAddresses(
                AF_INET as u32,
                flags,
                std::ptr::null_mut(),
                buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut buf_len,
            )
        }
    } else {
        status
    };

    if status != ERROR_SUCCESS {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut current = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !current.is_null() {
        let adapter = unsafe { &*current };
        if adapter.OperStatus == IfOperStatusUp
            && adapter.IfType != IF_TYPE_SOFTWARE_LOOPBACK
            && adapter.IfType != IF_TYPE_TUNNEL
        {
            let friendly = unsafe { pwstr_to_string(adapter.FriendlyName) };
            let desc = unsafe { pwstr_to_string(adapter.Description) };
            let is_virtual = is_virtual_adapter_name(&friendly) || is_virtual_adapter_name(&desc);

            let mut unicast = adapter.FirstUnicastAddress;
            while !unicast.is_null() {
                let ua = unsafe { &*unicast };
                let sa = ua.Address.lpSockaddr;
                if !sa.is_null() && unsafe { (*sa).sa_family } == AF_INET {
                    let sin = unsafe { &*(sa as *const SOCKADDR_IN) };
                    let s_addr = unsafe { sin.sin_addr.S_un.S_addr };
                    let ip = Ipv4Addr::from(u32::from_be(s_addr));
                    if is_valid_lan_ipv4(ip) {
                        out.push(DiscoveredNic { ip, is_virtual });
                    }
                }
                unicast = ua.Next;
            }
        }
        current = adapter.Next;
    }
    out
}

#[cfg(unix)]
fn enumerate_platform_ipv4_nics() -> Vec<DiscoveredNic> {
    use std::ffi::CStr;

    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut cur = ifap;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        let flags = ifa.ifa_flags as i32;
        let is_up = (flags & libc::IFF_UP) != 0;
        let is_loop = (flags & libc::IFF_LOOPBACK) != 0;
        if is_up && !is_loop && !ifa.ifa_addr.is_null() {
            let family = unsafe { (*ifa.ifa_addr).sa_family } as i32;
            if family == libc::AF_INET {
                let name = if !ifa.ifa_name.is_null() {
                    unsafe { CStr::from_ptr(ifa.ifa_name) }
                        .to_string_lossy()
                        .into_owned()
                } else {
                    String::new()
                };
                let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                if is_valid_lan_ipv4(ip) {
                    out.push(DiscoveredNic {
                        ip,
                        is_virtual: is_virtual_adapter_name(&name),
                    });
                }
            }
        }
        cur = ifa.ifa_next;
    }
    unsafe { libc::freeifaddrs(ifap) };
    out
}

#[cfg(not(any(windows, unix)))]
fn enumerate_platform_ipv4_nics() -> Vec<DiscoveredNic> {
    Vec::new()
}

fn ipv4_priority_tier(ip: Ipv4Addr, is_virtual: bool, default_egress: Option<Ipv4Addr>) -> u8 {
    let o = ip.octets();
    let is_192_168 = o[0] == 192 && o[1] == 168;
    let is_rfc1918_other = o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1]));
    let is_cgnat = o[0] == 100 && (o[1] & 0b1100_0000) == 64;

    if !is_virtual && Some(ip) == default_egress {
        return 0;
    }
    if !is_virtual && is_192_168 {
        return 1;
    }
    if !is_virtual && is_rfc1918_other {
        return 2;
    }
    if Some(ip) == default_egress {
        return 3;
    }
    if !is_virtual && is_cgnat {
        return 4;
    }
    if !is_virtual {
        return 5;
    }
    if is_cgnat {
        return 6;
    }
    7
}

/// Enumerate deduplicated, noise-filtered LAN IPv4 addresses sorted with the default physical
/// egress interface and `192.168.x.x` first (filtering `198.18.0.0/15`, `169.254.0.0/16`, `127.0.0.0/8`).
pub fn list_lan_ipv4_candidates() -> Vec<String> {
    let default_egress = probe_default_egress_ipv4();
    let mut nics = enumerate_platform_ipv4_nics();

    if let Some(egress) = default_egress
        && !nics.iter().any(|n| n.ip == egress)
    {
        nics.push(DiscoveredNic {
            ip: egress,
            is_virtual: false,
        });
    }

    // Drop noisy virtual adapters when real physical adapters exist, while keeping CGNAT mesh (100.64/10)
    let has_physical = nics.iter().any(|n| !n.is_virtual);
    if has_physical {
        nics.retain(|n| {
            let o = n.ip.octets();
            let is_cgnat = o[0] == 100 && (o[1] & 0b1100_0000) == 64;
            !n.is_virtual || is_cgnat
        });
    }

    nics.sort_by_key(|n| (ipv4_priority_tier(n.ip, n.is_virtual, default_egress), n.ip));

    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for nic in nics {
        if seen.insert(nic.ip) {
            result.push(nic.ip.to_string());
            if result.len() >= 8 {
                break;
            }
        }
    }
    result
}

/// Helper to check whether an IP belongs to private/LAN space (usable by callers enforcing cleartext rules).
pub fn is_lan_or_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || (o[0] == 100 && (o[1] & 0b1100_0000) == 64)
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            v6.is_loopback() || (segs[0] & 0xfe00) == 0xfc00 || (segs[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback_opts(allow_multiple: bool) -> LanSyncServerOptions {
        LanSyncServerOptions {
            bind_host: "127.0.0.1".to_string(),
            bind_port: 0,
            custom_endpoint: None,
            ttl_secs: 60,
            allow_multiple,
        }
    }

    #[test]
    fn lan_ipv4_filter_rejects_tun_apipa_and_loopback() {
        assert!(!is_valid_lan_ipv4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_valid_lan_ipv4(Ipv4Addr::new(169, 254, 10, 20)));
        assert!(!is_valid_lan_ipv4(Ipv4Addr::new(198, 18, 0, 1)));
        assert!(!is_valid_lan_ipv4(Ipv4Addr::new(198, 19, 255, 1)));
        assert!(is_valid_lan_ipv4(Ipv4Addr::new(192, 168, 1, 10)));
        assert!(is_valid_lan_ipv4(Ipv4Addr::new(10, 0, 0, 5)));

        let candidates = list_lan_ipv4_candidates();
        for ip_str in &candidates {
            let ip: Ipv4Addr = ip_str.parse().unwrap();
            assert!(is_valid_lan_ipv4(ip), "invalid LAN candidate leaked: {ip_str}");
        }
    }

    #[tokio::test]
    async fn e2e_qr_uri_pull_and_auto_close() {
        let payload = b"PK\x03\x04catcloud-demo-zip-pull-payload-v1".to_vec();
        let mut server = LanSyncSendServer::start(payload.clone(), loopback_opts(false))
            .await
            .unwrap();
        let uri = server.info().uri.clone();
        assert!(uri.contains("role=pull"));
        assert!(uri.contains("#k="));

        let fetched = fetch_sync_bundle_via_uri(&uri).await.unwrap();
        assert_eq!(fetched, payload);

        // One-shot server should automatically shut down after successful transfer
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(!server.is_running());
        server.cancel().await;
    }

    #[tokio::test]
    async fn e2e_qr_uri_push_roundtrip() {
        let payload = b"PK\x03\x04catcloud-demo-zip-push-payload-v1".to_vec();
        let mut server = LanSyncReceiveServer::start(loopback_opts(false))
            .await
            .unwrap();
        let uri = server.info().uri.clone();
        let expected_fp = plaintext_fingerprint(&payload);

        push_sync_bundle_via_uri(&uri, &payload).await.unwrap();
        let received = tokio::time::timeout(Duration::from_secs(3), server.recv_bundle())
            .await
            .unwrap()
            .expect("receiver must yield decrypted bundle");
        assert_eq!(received.zip_bytes, payload);
        assert_eq!(received.fingerprint, expected_fp);
        assert!(!received.via_pin);

        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(!server.is_running());
        server.cancel().await;
    }

    #[tokio::test]
    async fn e2e_pin_ecdh_p256_pull_and_push() {
        // 1. PIN pull
        let pull_payload = b"PK\x03\x04catcloud-pin-ecdh-pull-bundle".to_vec();
        let mut send_srv = LanSyncSendServer::start(pull_payload.clone(), loopback_opts(false))
            .await
            .unwrap();
        let send_addr = format!("127.0.0.1:{}", send_srv.info().port);
        let send_pin = send_srv.info().pin.clone();
        assert_eq!(send_pin.len(), 6);

        let pulled = fetch_sync_bundle_via_pin(&send_addr, &send_pin)
            .await
            .unwrap();
        assert_eq!(pulled, pull_payload);
        send_srv.cancel().await;

        // 2. PIN push
        let push_payload = b"PK\x03\x04catcloud-pin-ecdh-push-bundle".to_vec();
        let mut recv_srv = LanSyncReceiveServer::start(loopback_opts(false))
            .await
            .unwrap();
        let recv_addr = format!("127.0.0.1:{}", recv_srv.info().port);
        let recv_pin = recv_srv.info().pin.clone();

        push_sync_bundle_via_pin(&recv_addr, &recv_pin, &push_payload)
            .await
            .unwrap();
        let received = tokio::time::timeout(Duration::from_secs(3), recv_srv.recv_bundle())
            .await
            .unwrap()
            .expect("receiver must yield PIN-pushed bundle");
        assert_eq!(received.zip_bytes, push_payload);
        assert!(received.via_pin);
        recv_srv.cancel().await;
    }

    #[tokio::test]
    async fn five_wrong_pins_auto_destroy_listener() {
        let payload = b"secret-bundle".to_vec();
        let mut server = LanSyncSendServer::start(payload, loopback_opts(true))
            .await
            .unwrap();
        let addr = format!("127.0.0.1:{}", server.info().port);
        let correct_pin = server.info().pin.clone();
        let wrong_pin = if correct_pin == "000000" {
            "999999"
        } else {
            "000000"
        };

        for attempt in 1..=MAX_AUTH_FAILURES {
            let res = fetch_sync_bundle_via_pin(&addr, wrong_pin).await;
            assert!(res.is_err(), "wrong PIN attempt {attempt} must fail");
        }

        // Wait briefly for accept loop to observe shutdown & drop listener
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!server.is_running(), "server must self-destruct after 5 wrong PINs");
        assert_eq!(server.auth_failure_count(), MAX_AUTH_FAILURES);

        // Even the real PIN must now fail because listener is destroyed
        let after = fetch_sync_bundle_via_pin(&addr, &correct_pin).await;
        assert!(after.is_err(), "destroyed server must refuse subsequent real PIN");
        server.cancel().await;
    }

    #[tokio::test]
    async fn oversize_payload_over_17mib_is_rejected_with_413() {
        let mut server = LanSyncReceiveServer::start(loopback_opts(false))
            .await
            .unwrap();
        let port = server.info().port;
        let sid = server.info().sid.clone();

        // Send raw HTTP/1.1 header declaring Content-Length = 17 MiB + 1 byte without allocating 17 MiB
        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let oversize = MAX_HTTP_BODY_BYTES + 1;
        let req = format!(
            "POST /sync/v1/bundle HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: {oversize}\r\nX-CatCloud-Sid: {sid}\r\nX-CatCloud-Auth: {}\r\n\r\n",
            "0".repeat(64)
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();

        let mut resp_buf = Vec::new();
        stream.read_to_end(&mut resp_buf).await.unwrap();
        let resp_text = String::from_utf8_lossy(&resp_buf);
        assert!(
            resp_text.starts_with("HTTP/1.1 413 "),
            "expected HTTP 413 Payload Too Large, got: {resp_text}"
        );
        server.cancel().await;
    }

    #[tokio::test]
    async fn receive_server_ttl_expiry_closes_bundle_channel_with_expired_reason() {
        let mut opts = loopback_opts(false);
        opts.ttl_secs = 1;
        let mut server = LanSyncReceiveServer::start(opts).await.unwrap();
        let reason_rx = server.subscribe_close_reason();

        let res = tokio::time::timeout(Duration::from_secs(3), server.recv_bundle())
            .await
            .expect("recv_bundle must not hang after TTL expiry");
        assert!(res.is_none(), "expired receiver must yield None");
        assert_eq!(reason_rx.borrow().as_deref(), Some("expired"));
        assert_eq!(server.close_reason().as_deref(), Some("expired"));
        server.cancel().await;
    }

    #[tokio::test]
    async fn receive_server_five_wrong_pins_closes_bundle_channel_with_destroyed_reason() {
        let mut server = LanSyncReceiveServer::start(loopback_opts(true)).await.unwrap();
        let addr = format!("127.0.0.1:{}", server.info().port);
        let correct_pin = server.info().pin.clone();
        let wrong_pin = if correct_pin == "000000" {
            "999999"
        } else {
            "000000"
        };
        let reason_rx = server.subscribe_close_reason();

        for _ in 0..MAX_AUTH_FAILURES {
            let res = push_sync_bundle_via_pin(&addr, wrong_pin, b"payload").await;
            assert!(res.is_err());
        }

        let res = tokio::time::timeout(Duration::from_secs(2), server.recv_bundle())
            .await
            .expect("recv_bundle must return immediately after 5 failed PIN attempts");
        assert!(res.is_none(), "destroyed receiver must yield None");
        assert_eq!(reason_rx.borrow().as_deref(), Some("destroyed"));
        assert_eq!(server.close_reason().as_deref(), Some("destroyed"));
        server.cancel().await;
    }

    #[tokio::test]
    async fn unbounded_header_line_without_newline_is_rejected_with_431() {
        let mut server = LanSyncReceiveServer::start(loopback_opts(false)).await.unwrap();
        let port = server.info().port;

        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let giant_line = vec![b'A'; MAX_HTTP_HEADER_BYTES + 2048];
        let _ = stream.write_all(&giant_line).await;
        let _ = stream.flush().await;

        let mut resp_buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut resp_buf))
            .await
            .expect("server must reject oversize header line promptly");
        let resp_text = String::from_utf8_lossy(&resp_buf);
        assert!(
            resp_text.starts_with("HTTP/1.1 431 "),
            "expected HTTP 431 Request Header Fields Too Large, got: {resp_text}"
        );
        server.cancel().await;
    }

    #[tokio::test]
    async fn oversized_chunk_size_line_and_truncated_large_cl_are_rejected_with_400() {
        let mut server = LanSyncReceiveServer::start(loopback_opts(true)).await.unwrap();
        let port = server.info().port;

        // 1. Oversize chunk size line without newline
        {
            let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
                .await
                .unwrap();
            let head = format!(
                "POST /sync/v1/bundle HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nTransfer-Encoding: chunked\r\n\r\n"
            );
            stream.write_all(head.as_bytes()).await.unwrap();
            let giant_chunk_line = vec![b'f'; MAX_CHUNK_LINE_BYTES + 64];
            let _ = stream.write_all(&giant_chunk_line).await;
            let _ = stream.flush().await;

            let mut resp_buf = Vec::new();
            let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut resp_buf))
                .await
                .expect("oversize chunk size line must be rejected promptly");
            let resp_text = String::from_utf8_lossy(&resp_buf);
            assert!(
                resp_text.starts_with("HTTP/1.1 400 "),
                "expected HTTP 400 for oversize chunk size line, got: {resp_text}"
            );
        }

        // 2. Declared 17 MiB Content-Length that closes immediately (must not preallocate 17 MiB)
        {
            let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
                .await
                .unwrap();
            let req = format!(
                "POST /sync/v1/bundle HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: {MAX_HTTP_BODY_BYTES}\r\n\r\n"
            );
            stream.write_all(req.as_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();

            let mut resp_buf = Vec::new();
            let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut resp_buf))
                .await
                .expect("truncated large body must return promptly");
            let resp_text = String::from_utf8_lossy(&resp_buf);
            assert!(
                resp_text.starts_with("HTTP/1.1 400 "),
                "expected HTTP 400 for truncated body, got: {resp_text}"
            );
        }

        server.cancel().await;
    }

    #[tokio::test]
    async fn one_shot_send_concurrent_get_only_delivers_once() {
        let payload = b"PK\x03\x04one-shot-concurrency-guard".to_vec();
        let mut server = LanSyncSendServer::start(payload.clone(), loopback_opts(false))
            .await
            .unwrap();
        let uri = server.info().uri.clone();

        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..6 {
            let u = uri.clone();
            tasks.spawn(async move { fetch_sync_bundle_via_uri(&u).await });
        }

        let mut successes = 0usize;
        while let Some(res) = tasks.join_next().await {
            if let Ok(Ok(bytes)) = res {
                assert_eq!(bytes, payload);
                successes += 1;
            }
        }
        assert_eq!(successes, 1, "one-shot send must deliver to exactly one client");
        assert_eq!(server.close_reason().as_deref(), Some("completed"));
        server.cancel().await;
    }
}
