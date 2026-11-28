use crate::core_adapter::{
    ActiveConnection, ConnectionsSnapshot, CoreLogLine, MemoryTick, TrafficTick,
    format_http_base_url,
};
use crate::error::{CatError, CatResult};
use crate::models::CoreLogLevel;
use chrono::Utc;
use serde::Deserialize;
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;

/// Hard default cap on buffered real-time Mihomo log lines to prevent unbounded memory growth.
pub const DEFAULT_MAX_LOG_ENTRIES: usize = 2000;

/// Hard default cap on buffered `/traffic` samples (10 minutes at 1 Hz).
pub const DEFAULT_MAX_TRAFFIC_SAMPLES: usize = 600;

/// Hard default cap on buffered `/memory` samples (10 minutes at 1 Hz).
pub const DEFAULT_MAX_MEMORY_SAMPLES: usize = 600;

/// Hard upper bound on a single NDJSON line before it is truncated to guard against malformed streams.
const MAX_NDJSON_LINE_BYTES: usize = 1024 * 1024;

/// Capacity threshold above which `NdjsonLineFramer` shrinks its reusable line buffer after finishing a line.
const NDJSON_FRAMER_SHRINK_THRESHOLD_BYTES: usize = 16 * 1024;

/// Target capacity retained by `NdjsonLineFramer` when shrinking an oversized line buffer.
const NDJSON_FRAMER_SHRINK_TARGET_BYTES: usize = 4096;

/// Hard upper bound (4 KiB) when reading non-2xx HTTP error bodies on NDJSON stream endpoints.
const MAX_STREAM_ERROR_BODY_BYTES: usize = 4 * 1024;

/// Initial reconnect backoff for background `/traffic`, `/memory`, and `/logs` streams.
const STREAM_RECONNECT_INITIAL: Duration = Duration::from_millis(250);

/// Maximum reconnect backoff cap for background streams.
const STREAM_RECONNECT_MAX: Duration = Duration::from_millis(3000);

/// Fixed-capacity ring buffer that evicts the oldest item when full.
#[derive(Debug, Clone)]
pub struct BoundedRingBuffer<T> {
    capacity: usize,
    items: VecDeque<T>,
}

impl<T> BoundedRingBuffer<T> {
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            capacity: cap,
            items: VecDeque::with_capacity(cap.min(256)),
        }
    }

    pub fn push(&mut self, item: T) {
        if self.items.len() >= self.capacity {
            self.items.pop_front();
        }
        self.items.push_back(item);
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn latest(&self) -> Option<&T> {
        self.items.back()
    }

    pub fn clear(&mut self) {
        self.items.clear();
    }

    pub fn shrink_to_fit(&mut self) {
        self.items.shrink_to_fit();
    }

    pub fn iter(&self) -> std::collections::vec_deque::Iter<'_, T> {
        self.items.iter()
    }
}

impl<T: Clone> BoundedRingBuffer<T> {
    pub fn snapshot(&self) -> Vec<T> {
        self.items.iter().cloned().collect()
    }
}

/// Race-free cancellation token built on `tokio::sync::watch` (zero extra crate dependencies).
#[derive(Debug, Clone)]
pub struct StreamCancelToken {
    tx: Arc<watch::Sender<bool>>,
}

impl StreamCancelToken {
    pub fn new() -> Self {
        let (tx, _rx) = watch::channel(false);
        Self { tx: Arc::new(tx) }
    }

    pub fn cancel(&self) {
        self.tx.send_replace(true);
    }

    pub fn is_cancelled(&self) -> bool {
        *self.tx.borrow()
    }

    pub async fn cancelled(&self) {
        let mut rx = self.tx.subscribe();
        if *rx.borrow_and_update() {
            return;
        }
        while rx.changed().await.is_ok() {
            if *rx.borrow_and_update() {
                return;
            }
        }
    }
}

impl Default for StreamCancelToken {
    fn default() -> Self {
        Self::new()
    }
}

/// Incremental NDJSON line framer handling arbitrarily split TCP/HTTP chunks with bounded line size.
#[derive(Debug, Default)]
pub struct NdjsonLineFramer {
    buf: Vec<u8>,
    dropping_oversized_line: bool,
}

impl NdjsonLineFramer {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    fn clear_and_maybe_shrink(&mut self) {
        self.buf.clear();
        if self.buf.capacity() > NDJSON_FRAMER_SHRINK_THRESHOLD_BYTES {
            self.buf.shrink_to(NDJSON_FRAMER_SHRINK_TARGET_BYTES);
        }
    }

    /// Push raw chunk bytes and return any complete non-empty UTF-8 lines extracted so far.
    pub fn push_chunk(&mut self, chunk: &[u8]) -> Vec<String> {
        let mut lines = Vec::new();
        for &b in chunk {
            if b == b'\n' {
                if self.dropping_oversized_line {
                    self.dropping_oversized_line = false;
                    self.clear_and_maybe_shrink();
                    continue;
                }
                if self.buf.last() == Some(&b'\r') {
                    self.buf.pop();
                }
                if !self.buf.is_empty() {
                    let line = String::from_utf8_lossy(&self.buf).trim().to_string();
                    self.clear_and_maybe_shrink();
                    if !line.is_empty() {
                        lines.push(line);
                    }
                } else {
                    self.clear_and_maybe_shrink();
                }
            } else if !self.dropping_oversized_line {
                if self.buf.len() >= MAX_NDJSON_LINE_BYTES {
                    self.clear_and_maybe_shrink();
                    self.dropping_oversized_line = true;
                } else {
                    self.buf.push(b);
                }
            }
        }
        lines
    }

    /// Flush any remaining buffered bytes at EOF.
    pub fn finish(&mut self) -> Option<String> {
        if self.dropping_oversized_line || self.buf.is_empty() {
            self.dropping_oversized_line = false;
            self.clear_and_maybe_shrink();
            return None;
        }
        let line = String::from_utf8_lossy(&self.buf).trim().to_string();
        self.clear_and_maybe_shrink();
        if line.is_empty() { None } else { Some(line) }
    }
}

/// Thread-safe bounded telemetry store holding recent traffic, memory, and log streams.
#[derive(Debug)]
pub struct CoreTelemetryStore {
    traffic: RwLock<BoundedRingBuffer<TrafficTick>>,
    memory: RwLock<BoundedRingBuffer<MemoryTick>>,
    logs: RwLock<BoundedRingBuffer<CoreLogLine>>,
    traffic_tx: broadcast::Sender<TrafficTick>,
    memory_tx: broadcast::Sender<MemoryTick>,
    logs_tx: broadcast::Sender<CoreLogLine>,
}

impl CoreTelemetryStore {
    pub fn new(max_logs: usize, max_traffic: usize, max_memory: usize) -> Self {
        let (traffic_tx, _) = broadcast::channel(64);
        let (memory_tx, _) = broadcast::channel(64);
        let (logs_tx, _) = broadcast::channel(256);
        Self {
            traffic: RwLock::new(BoundedRingBuffer::new(max_traffic)),
            memory: RwLock::new(BoundedRingBuffer::new(max_memory)),
            logs: RwLock::new(BoundedRingBuffer::new(max_logs)),
            traffic_tx,
            memory_tx,
            logs_tx,
        }
    }

    pub fn push_traffic(&self, tick: TrafficTick) {
        if let Ok(mut guard) = self.traffic.write() {
            guard.push(tick);
        }
        let _ = self.traffic_tx.send(tick);
    }

    pub fn push_memory(&self, tick: MemoryTick) {
        if let Ok(mut guard) = self.memory.write() {
            guard.push(tick);
        }
        let _ = self.memory_tx.send(tick);
    }

    pub fn push_log(&self, line: CoreLogLine) {
        if let Ok(mut guard) = self.logs.write() {
            guard.push(line.clone());
        }
        let _ = self.logs_tx.send(line);
    }

    pub fn traffic_snapshot(&self) -> Vec<TrafficTick> {
        self.traffic
            .read()
            .map(|g| g.snapshot())
            .unwrap_or_default()
    }

    /// Compute peak `(max_up, max_down)` throughput across traffic samples with
    /// `timestamp_ms >= cutoff_ms` without cloning the ring buffer.
    pub fn traffic_peak_since(&self, cutoff_ms: i64) -> (u64, u64) {
        self.traffic
            .read()
            .map(|guard| {
                let mut max_up = 0u64;
                let mut max_down = 0u64;
                for tick in guard.iter() {
                    if tick.timestamp_ms >= cutoff_ms {
                        if tick.up > max_up {
                            max_up = tick.up;
                        }
                        if tick.down > max_down {
                            max_down = tick.down;
                        }
                    }
                }
                (max_up, max_down)
            })
            .unwrap_or((0, 0))
    }

    pub fn clear_traffic(&self) {
        if let Ok(mut guard) = self.traffic.write() {
            guard.clear();
            guard.shrink_to_fit();
        }
        if let Ok(mut guard) = self.memory.write() {
            guard.clear();
            guard.shrink_to_fit();
        }
    }

    pub fn clear_logs(&self) {
        if let Ok(mut guard) = self.logs.write() {
            guard.clear();
            guard.shrink_to_fit();
        }
    }

    pub fn memory_snapshot(&self) -> Vec<MemoryTick> {
        self.memory
            .read()
            .map(|g| g.snapshot())
            .unwrap_or_default()
    }

    pub fn logs_snapshot(&self) -> Vec<CoreLogLine> {
        self.logs.read().map(|g| g.snapshot()).unwrap_or_default()
    }

    pub fn filter_logs(&self, level: Option<&str>, keyword: Option<&str>) -> Vec<CoreLogLine> {
        let level_filter = level
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_ascii_lowercase);
        let kw_filter = keyword
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_ascii_lowercase);

        self.logs
            .read()
            .map(|guard| {
                guard
                    .iter()
                    .filter(|entry| {
                        let level_ok = level_filter
                            .as_deref()
                            .is_none_or(|lv| entry.level.eq_ignore_ascii_case(lv));
                        let kw_ok = kw_filter.as_deref().is_none_or(|kw| {
                            entry.payload.to_ascii_lowercase().contains(kw)
                                || entry.level.to_ascii_lowercase().contains(kw)
                        });
                        level_ok && kw_ok
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn subscribe_traffic(&self) -> broadcast::Receiver<TrafficTick> {
        self.traffic_tx.subscribe()
    }

    pub fn subscribe_memory(&self) -> broadcast::Receiver<MemoryTick> {
        self.memory_tx.subscribe()
    }

    pub fn subscribe_logs(&self) -> broadcast::Receiver<CoreLogLine> {
        self.logs_tx.subscribe()
    }
}

impl Default for CoreTelemetryStore {
    fn default() -> Self {
        Self::new(
            DEFAULT_MAX_LOG_ENTRIES,
            DEFAULT_MAX_TRAFFIC_SAMPLES,
            DEFAULT_MAX_MEMORY_SAMPLES,
        )
    }
}

/// Handle managing spawned `/traffic`, `/memory`, and `/logs` background streaming tasks.
pub struct StreamSessionHandle {
    cancel: StreamCancelToken,
    tasks: Vec<JoinHandle<()>>,
}

impl StreamSessionHandle {
    pub fn cancel_token(&self) -> StreamCancelToken {
        self.cancel.clone()
    }

    pub fn stop(&self) {
        self.cancel.cancel();
    }

    pub async fn shutdown(mut self) {
        self.cancel.cancel();
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
    }
}

impl Drop for StreamSessionHandle {
    fn drop(&mut self) {
        self.cancel.cancel();
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Streaming and snapshot client for Mihomo's external controller REST/NDJSON endpoints.
///
/// Always forces `.no_proxy()` and attaches `Authorization: Bearer <secret>`.
#[derive(Debug, Clone)]
pub struct MihomoStreamClient {
    base_url: String,
    secret: String,
    stream_http: reqwest::Client,
    snapshot_http: reqwest::Client,
}

impl MihomoStreamClient {
    pub fn new(host: &str, port: u16, secret: impl Into<String>) -> CatResult<Self> {
        crate::init_crypto_provider();
        let stream_http = reqwest::Client::builder()
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .connect_timeout(Duration::from_secs(5))
            .build()?;
        let snapshot_http = reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()?;

        Ok(Self {
            base_url: format_http_base_url(host, port),
            secret: secret.into(),
            stream_http,
            snapshot_http,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Fetch a one-shot snapshot of active connections from `GET /connections`.
    pub async fn fetch_connections_snapshot(&self) -> CatResult<ConnectionsSnapshot> {
        let url = format!("{}/connections", self.base_url);
        let resp = self
            .snapshot_http
            .get(&url)
            .bearer_auth(&self.secret)
            .send()
            .await?;
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

    /// Stream real-time `/traffic` NDJSON ticks until EOF or `cancel` triggers.
    pub async fn stream_traffic<F>(
        &self,
        cancel: StreamCancelToken,
        mut on_tick: F,
    ) -> CatResult<()>
    where
        F: FnMut(TrafficTick),
    {
        let url = format!("{}/traffic", self.base_url);
        self.stream_ndjson_endpoint(&url, cancel, |line| {
            if let Ok(raw) = serde_json::from_str::<RawTrafficPayload>(&line) {
                on_tick(TrafficTick {
                    up: raw.up,
                    down: raw.down,
                    timestamp_ms: Utc::now().timestamp_millis(),
                });
            }
        })
        .await
    }

    /// Stream real-time `/memory` NDJSON ticks until EOF or `cancel` triggers.
    pub async fn stream_memory<F>(
        &self,
        cancel: StreamCancelToken,
        mut on_tick: F,
    ) -> CatResult<()>
    where
        F: FnMut(MemoryTick),
    {
        let url = format!("{}/memory", self.base_url);
        self.stream_ndjson_endpoint(&url, cancel, |line| {
            if let Ok(raw) = serde_json::from_str::<RawMemoryPayload>(&line) {
                on_tick(MemoryTick {
                    inuse: raw.inuse,
                    oslimit: raw.oslimit,
                    timestamp_ms: Utc::now().timestamp_millis(),
                });
            }
        })
        .await
    }

    /// Stream real-time `/logs?level=<level>` NDJSON entries until EOF or `cancel` triggers.
    pub async fn stream_logs<F>(
        &self,
        level: &CoreLogLevel,
        cancel: StreamCancelToken,
        mut on_line: F,
    ) -> CatResult<()>
    where
        F: FnMut(CoreLogLine),
    {
        let url = format!("{}/logs?level={}", self.base_url, level.as_str());
        self.stream_ndjson_endpoint(&url, cancel, |line| {
            if let Ok(raw) = serde_json::from_str::<RawLogPayload>(&line) {
                on_line(CoreLogLine {
                    level: raw.level,
                    payload: raw.payload,
                    timestamp: Utc::now().to_rfc3339(),
                });
            }
        })
        .await
    }

    /// Spawn background `/traffic`, `/memory`, and `/logs` stream tasks feeding a bounded `CoreTelemetryStore`.
    /// Each task runs an exponential-backoff reconnect loop (250ms -> 3000ms, reset to 250ms after
    /// receiving any valid payload) and exits immediately on `cancel`.
    pub fn spawn_background_streams(
        &self,
        log_level: CoreLogLevel,
        store: Arc<CoreTelemetryStore>,
    ) -> StreamSessionHandle {
        let cancel = StreamCancelToken::new();
        let mut tasks = Vec::with_capacity(3);

        {
            let client = self.clone();
            let token = cancel.clone();
            let sink = Arc::clone(&store);
            tasks.push(tokio::spawn(async move {
                let mut backoff = STREAM_RECONNECT_INITIAL;
                while !token.is_cancelled() {
                    let mut received_any = false;
                    let _ = client
                        .stream_traffic(token.clone(), |tick| {
                            received_any = true;
                            sink.push_traffic(tick);
                        })
                        .await;
                    if token.is_cancelled() {
                        break;
                    }
                    if received_any {
                        backoff = STREAM_RECONNECT_INITIAL;
                    }
                    tokio::select! {
                        biased;
                        _ = token.cancelled() => break,
                        _ = tokio::time::sleep(backoff) => {}
                    }
                    if !received_any {
                        backoff = backoff.saturating_mul(2).min(STREAM_RECONNECT_MAX);
                    }
                }
            }));
        }

        {
            let client = self.clone();
            let token = cancel.clone();
            let sink = Arc::clone(&store);
            tasks.push(tokio::spawn(async move {
                let mut backoff = STREAM_RECONNECT_INITIAL;
                while !token.is_cancelled() {
                    let mut received_any = false;
                    let _ = client
                        .stream_memory(token.clone(), |tick| {
                            received_any = true;
                            sink.push_memory(tick);
                        })
                        .await;
                    if token.is_cancelled() {
                        break;
                    }
                    if received_any {
                        backoff = STREAM_RECONNECT_INITIAL;
                    }
                    tokio::select! {
                        biased;
                        _ = token.cancelled() => break,
                        _ = tokio::time::sleep(backoff) => {}
                    }
                    if !received_any {
                        backoff = backoff.saturating_mul(2).min(STREAM_RECONNECT_MAX);
                    }
                }
            }));
        }

        {
            let client = self.clone();
            let token = cancel.clone();
            let sink = Arc::clone(&store);
            tasks.push(tokio::spawn(async move {
                let mut backoff = STREAM_RECONNECT_INITIAL;
                while !token.is_cancelled() {
                    let mut received_any = false;
                    let _ = client
                        .stream_logs(&log_level, token.clone(), |line| {
                            received_any = true;
                            sink.push_log(line);
                        })
                        .await;
                    if token.is_cancelled() {
                        break;
                    }
                    if received_any {
                        backoff = STREAM_RECONNECT_INITIAL;
                    }
                    tokio::select! {
                        biased;
                        _ = token.cancelled() => break,
                        _ = tokio::time::sleep(backoff) => {}
                    }
                    if !received_any {
                        backoff = backoff.saturating_mul(2).min(STREAM_RECONNECT_MAX);
                    }
                }
            }));
        }

        StreamSessionHandle { cancel, tasks }
    }

    async fn stream_ndjson_endpoint<F>(
        &self,
        url: &str,
        cancel: StreamCancelToken,
        mut on_line: F,
    ) -> CatResult<()>
    where
        F: FnMut(String),
    {
        let connect_fut = self
            .stream_http
            .get(url)
            .bearer_auth(&self.secret)
            .send();

        let mut resp = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            res = connect_fut => res?,
        };

        let status = resp.status();
        if !status.is_success() {
            let mut err_buf: Vec<u8> = Vec::new();
            while err_buf.len() < MAX_STREAM_ERROR_BODY_BYTES {
                if cancel.is_cancelled() {
                    return Ok(());
                }
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return Ok(()),
                    next_chunk = resp.chunk() => {
                        match next_chunk {
                            Ok(Some(chunk)) => {
                                let remaining = MAX_STREAM_ERROR_BODY_BYTES - err_buf.len();
                                let take = chunk.len().min(remaining);
                                err_buf.extend_from_slice(&chunk[..take]);
                            }
                            Ok(None) | Err(_) => break,
                        }
                    }
                }
            }
            let body = String::from_utf8_lossy(&err_buf);
            return Err(CatError::Core(format!(
                "NDJSON stream `{url}` failed with HTTP {}: {}",
                status.as_u16(),
                body.trim()
            )));
        }

        let mut framer = NdjsonLineFramer::new();
        loop {
            if cancel.is_cancelled() {
                return Ok(());
            }
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    return Ok(());
                }
                next_chunk = resp.chunk() => {
                    if cancel.is_cancelled() {
                        return Ok(());
                    }
                    match next_chunk? {
                        Some(chunk) => {
                            let bytes_slice: &[u8] = &chunk;
                            for line in framer.push_chunk(bytes_slice) {
                                on_line(line);
                                if cancel.is_cancelled() {
                                    return Ok(());
                                }
                            }
                        }
                        None => {
                            if let Some(tail) = framer.finish() {
                                on_line(tail);
                            }
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// Wire payload DTOs matching Mihomo REST/NDJSON schemas
// ============================================================================

#[derive(Debug, Deserialize)]
struct RawTrafficPayload {
    #[serde(default)]
    up: u64,
    #[serde(default)]
    down: u64,
}

#[derive(Debug, Deserialize)]
struct RawMemoryPayload {
    #[serde(default)]
    inuse: u64,
    #[serde(default)]
    oslimit: u64,
}

#[derive(Debug, Deserialize)]
struct RawLogPayload {
    #[serde(rename = "type", alias = "level", default)]
    level: String,
    #[serde(default)]
    payload: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub(crate) struct RawConnectionsResponse {
    #[serde(rename = "downloadTotal")]
    pub download_total: u64,
    #[serde(rename = "uploadTotal")]
    pub upload_total: u64,
    pub memory: u64,
    pub connections: Option<Vec<RawConnectionEntry>>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub(crate) struct RawConnectionEntry {
    pub id: String,
    pub upload: u64,
    pub download: u64,
    pub start: String,
    pub chains: Vec<String>,
    pub rule: String,
    #[serde(rename = "rulePayload")]
    pub rule_payload: String,
    pub metadata: RawConnectionMetadata,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub(crate) struct RawConnectionMetadata {
    pub network: String,
    #[serde(rename = "type")]
    pub conn_type: String,
    #[serde(rename = "sourceIP")]
    pub source_ip: String,
    #[serde(rename = "sourcePort")]
    pub source_port: String,
    #[serde(rename = "destinationIP")]
    pub destination_ip: String,
    #[serde(rename = "destinationPort")]
    pub destination_port: String,
    pub host: String,
    pub process: String,
    #[serde(rename = "processPath")]
    pub process_path: String,
}

impl RawConnectionsResponse {
    pub(crate) fn into_snapshot(self) -> ConnectionsSnapshot {
        let connections = self
            .connections
            .unwrap_or_default()
            .into_iter()
            .map(|entry| ActiveConnection {
                id: entry.id,
                upload: entry.upload,
                download: entry.download,
                start: entry.start,
                chains: entry.chains,
                rule: entry.rule,
                rule_payload: entry.rule_payload,
                network: entry.metadata.network,
                conn_type: entry.metadata.conn_type,
                source_ip: entry.metadata.source_ip,
                source_port: entry.metadata.source_port,
                destination_ip: entry.metadata.destination_ip,
                destination_port: entry.metadata.destination_port,
                host: entry.metadata.host,
                process: entry.metadata.process,
                process_path: entry.metadata.process_path,
            })
            .collect();

        ConnectionsSnapshot {
            download_total: self.download_total,
            upload_total: self.upload_total,
            memory: self.memory,
            connections,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn bounded_ring_buffer_caps_log_entries_and_evicts_oldest() {
        let store = CoreTelemetryStore::new(DEFAULT_MAX_LOG_ENTRIES, 10, 10);
        for idx in 0..(DEFAULT_MAX_LOG_ENTRIES + 350) {
            store.push_log(CoreLogLine {
                level: if idx % 2 == 0 {
                    "info".to_string()
                } else {
                    "warning".to_string()
                },
                payload: format!("line-{idx}"),
                timestamp: "2026-01-01T00:00:00Z".to_string(),
            });
        }

        let snap = store.logs_snapshot();
        assert_eq!(snap.len(), DEFAULT_MAX_LOG_ENTRIES);
        assert_eq!(snap.first().unwrap().payload, "line-350");
        assert_eq!(
            snap.last().unwrap().payload,
            format!("line-{}", DEFAULT_MAX_LOG_ENTRIES + 349)
        );

        let filtered = store.filter_logs(Some("warning"), Some("line-2349"));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].payload, "line-2349");
    }

    #[test]
    fn ndjson_framer_handles_split_chunks_crlf_and_eof() {
        let mut framer = NdjsonLineFramer::new();
        assert!(framer.push_chunk(b"{\"up\":10,").is_empty());
        let first = framer.push_chunk(b"\"down\":20}\r\n{\"up\":30,\"down\":40}\n{\"up\":50");
        assert_eq!(first.len(), 2);
        assert_eq!(first[0], "{\"up\":10,\"down\":20}");
        assert_eq!(first[1], "{\"up\":30,\"down\":40}");
        assert_eq!(framer.finish().as_deref(), Some("{\"up\":50"));
    }

    #[tokio::test]
    async fn streams_ndjson_with_bearer_auth_and_stops_cleanly_on_cancel() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let expected_secret = "test-secret-token";

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut req_buf = vec![0u8; 2048];
            let n = socket.read(&mut req_buf).await.unwrap();
            let req_text = String::from_utf8_lossy(&req_buf[..n]).to_string();
            assert!(req_text.contains("GET /traffic HTTP/1.1"));
            assert!(req_text.contains("authorization: Bearer test-secret-token")
                || req_text.contains("Authorization: Bearer test-secret-token"));

            let header = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n";
            socket.write_all(header.as_bytes()).await.unwrap();
            let chunk1 = "{\"up\":1024,\"down\":2048}\n";
            let frame1 = format!("{:x}\r\n{chunk1}\r\n", chunk1.len());
            socket.write_all(frame1.as_bytes()).await.unwrap();
            let chunk2 = "{\"up\":4096,\"down\":8192}\n";
            let frame2 = format!("{:x}\r\n{chunk2}\r\n", chunk2.len());
            socket.write_all(frame2.as_bytes()).await.unwrap();
            socket.flush().await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
        });

        let client = MihomoStreamClient::new("127.0.0.1", port, expected_secret).unwrap();
        let cancel = StreamCancelToken::new();
        let cancel_clone = cancel.clone();
        let mut received = Vec::new();

        client
            .stream_traffic(cancel, |tick| {
                received.push(tick);
                if received.len() >= 2 {
                    cancel_clone.cancel();
                }
            })
            .await
            .expect("stream should exit cleanly after cancellation");

        assert_eq!(received.len(), 2);
        assert_eq!(received[0].up, 1024);
        assert_eq!(received[0].down, 2048);
        assert_eq!(received[1].up, 4096);
        assert_eq!(received[1].down, 8192);

        server.abort();
    }

    #[tokio::test]
    async fn background_streams_reconnect_after_eof_and_shutdown_promptly() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let traffic_hits = Arc::new(AtomicUsize::new(0));
        let hits_bg = Arc::clone(&traffic_hits);

        let server = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let hits = Arc::clone(&hits_bg);
                tokio::spawn(async move {
                    let mut req_buf = vec![0u8; 2048];
                    let n = socket.read(&mut req_buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&req_buf[..n]).to_string();
                    if req.starts_with("GET /traffic") {
                        let idx = hits.fetch_add(1, Ordering::SeqCst);
                        let body = format!("{{\"up\":{},\"down\":{}}}\n", (idx + 1) * 100, (idx + 1) * 200);
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = socket.write_all(resp.as_bytes()).await;
                    } else {
                        let resp = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        let _ = socket.write_all(resp.as_bytes()).await;
                    }
                });
            }
        });

        let client = MihomoStreamClient::new("127.0.0.1", port, "reconnect-secret").unwrap();
        let store = Arc::new(CoreTelemetryStore::default());
        let handle = client.spawn_background_streams(CoreLogLevel::Info, Arc::clone(&store));

        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while store.traffic_snapshot().len() < 2 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let ticks = store.traffic_snapshot();
        assert!(
            ticks.len() >= 2,
            "expected reconnect to deliver >= 2 traffic ticks, got {}",
            ticks.len()
        );
        assert_eq!(ticks[0].up, 100);
        assert_eq!(ticks[1].up, 200);

        let shutdown_start = tokio::time::Instant::now();
        handle.shutdown().await;
        assert!(
            shutdown_start.elapsed() < Duration::from_millis(500),
            "background streams must stop promptly on cancel"
        );

        server.abort();
    }

    #[tokio::test]
    async fn non_2xx_stalled_error_body_exits_promptly_on_cancel() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut req_buf = vec![0u8; 1024];
            let _ = socket.read(&mut req_buf).await;
            let header = "HTTP/1.1 500 Internal Server Error\r\nTransfer-Encoding: chunked\r\n\r\n";
            let _ = socket.write_all(header.as_bytes()).await;
            let _ = socket.flush().await;
            // Intentionally stall without sending error body or closing the connection.
            tokio::time::sleep(Duration::from_secs(10)).await;
        });

        let client = MihomoStreamClient::new("127.0.0.1", port, "stall-secret").unwrap();
        let cancel = StreamCancelToken::new();
        let cancel_trigger = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(40)).await;
            cancel_trigger.cancel();
        });

        let started = tokio::time::Instant::now();
        let res = client.stream_traffic(cancel, |_| {}).await;
        assert!(res.is_ok(), "cancelled stalled error body must exit cleanly");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "cancelled non-2xx read must not hang"
        );

        server.abort();
    }

    #[tokio::test]
    async fn non_2xx_oversized_error_body_is_capped_at_4kib() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut req_buf = vec![0u8; 1024];
            let _ = socket.read(&mut req_buf).await;
            let payload = "E".repeat(16 * 1024);
            let header = format!(
                "HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\n\r\n",
                payload.len()
            );
            let _ = socket.write_all(header.as_bytes()).await;
            let _ = socket.write_all(&payload.as_bytes()[..8192]).await;
            let _ = socket.flush().await;
            // Hold open without sending remaining bytes to verify the 4 KiB cap returns early.
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let client = MihomoStreamClient::new("127.0.0.1", port, "cap-secret").unwrap();
        let cancel = StreamCancelToken::new();
        let started = tokio::time::Instant::now();
        let err = client
            .stream_traffic(cancel, |_| {})
            .await
            .expect_err("non-2xx response must return an error");
        let msg = err.to_string();
        assert!(msg.contains("HTTP 502"));
        assert!(
            msg.len() <= MAX_STREAM_ERROR_BODY_BYTES + 256,
            "error body must be bounded to 4 KiB, got len={}",
            msg.len()
        );
        assert!(
            started.elapsed() < Duration::from_millis(800),
            "oversized non-2xx body must stop after 4 KiB without waiting for EOF"
        );

        server.abort();
    }

    #[test]
    fn telemetry_store_traffic_peak_since_and_clear_shrink_buffers() {
        let store = CoreTelemetryStore::new(64, 64, 64);
        assert_eq!(store.traffic_peak_since(0), (0, 0));

        store.push_traffic(TrafficTick {
            up: 500_000,
            down: 900_000,
            timestamp_ms: 1_000,
        });
        store.push_traffic(TrafficTick {
            up: 120_000,
            down: 350_000,
            timestamp_ms: 2_000,
        });
        store.push_traffic(TrafficTick {
            up: 240_000,
            down: 180_000,
            timestamp_ms: 2_500,
        });
        store.push_traffic(TrafficTick {
            up: 80_000,
            down: 410_000,
            timestamp_ms: 3_000,
        });

        // Inclusive lower bound `timestamp_ms >= cutoff_ms`; peaks can come from different samples.
        assert_eq!(store.traffic_peak_since(2_000), (240_000, 410_000));
        assert_eq!(store.traffic_peak_since(2_500), (240_000, 410_000));
        assert_eq!(store.traffic_peak_since(3_000), (80_000, 410_000));
        assert_eq!(store.traffic_peak_since(3_001), (0, 0));

        for idx in 0..32 {
            store.push_log(CoreLogLine {
                level: "info".to_string(),
                payload: format!("entry-{idx}"),
                timestamp: "2026-11-28T00:00:00Z".to_string(),
            });
            store.push_memory(MemoryTick {
                inuse: 1024 * (idx as u64 + 1),
                oslimit: 0,
                timestamp_ms: 1_000 + idx as i64,
            });
        }

        store.clear_logs();
        assert!(store.logs_snapshot().is_empty());
        assert_eq!(store.logs.read().unwrap().items.capacity(), 0);

        store.clear_traffic();
        assert!(store.traffic_snapshot().is_empty());
        assert!(store.memory_snapshot().is_empty());
        assert_eq!(store.traffic_peak_since(0), (0, 0));
        assert_eq!(store.traffic.read().unwrap().items.capacity(), 0);
        assert_eq!(store.memory.read().unwrap().items.capacity(), 0);
    }

    #[test]
    fn ndjson_framer_shrinks_oversized_line_buffer_after_consuming_line() {
        let mut framer = NdjsonLineFramer::new();

        // Feed a 24 KiB line (> 16 KiB shrink threshold) without newline first so capacity expands.
        let large_payload = "x".repeat(24 * 1024);
        assert!(framer.push_chunk(large_payload.as_bytes()).is_empty());
        assert!(
            framer.buf.capacity() > NDJSON_FRAMER_SHRINK_THRESHOLD_BYTES,
            "expected buffer capacity to grow above 16 KiB"
        );

        let lines = framer.push_chunk(b"\n");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].len(), 24 * 1024);
        assert!(
            framer.buf.capacity() <= NDJSON_FRAMER_SHRINK_THRESHOLD_BYTES,
            "expected buffer capacity to shrink after line completion, got {}",
            framer.buf.capacity()
        );
        assert!(
            framer.buf.capacity() <= NDJSON_FRAMER_SHRINK_TARGET_BYTES,
            "expected buffer capacity <= 4096 after shrink_to(4096), got {}",
            framer.buf.capacity()
        );

        // Also verify EOF finish shrinks an oversized partial line buffer.
        let tail_payload = "y".repeat(20 * 1024);
        assert!(framer.push_chunk(tail_payload.as_bytes()).is_empty());
        assert!(framer.buf.capacity() > NDJSON_FRAMER_SHRINK_THRESHOLD_BYTES);
        let tail = framer.finish().expect("EOF tail");
        assert_eq!(tail.len(), 20 * 1024);
        assert!(framer.buf.capacity() <= NDJSON_FRAMER_SHRINK_TARGET_BYTES);

        // Oversized (> 1 MiB) malformed line drops safely and shrinks immediately.
        let oversized = vec![b'z'; MAX_NDJSON_LINE_BYTES + 128];
        assert!(framer.push_chunk(&oversized).is_empty());
        assert!(framer.buf.capacity() <= NDJSON_FRAMER_SHRINK_TARGET_BYTES);
        assert!(framer.push_chunk(b"\n{\"ok\":1}\n") == vec!["{\"ok\":1}"]);
    }
}
