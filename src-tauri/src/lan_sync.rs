use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use catcloud_core::share_bundle::{ShareBundlePreview, preview_share_bundle_zip_bytes};
use catcloud_core::sync::{
    LanSyncReceiveInfo, LanSyncReceiveServer, LanSyncSendInfo, LanSyncSendServer,
    LanSyncServerOptions, render_qr_svg,
};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use tokio::sync::watch;
use uuid::Uuid;

pub const EVENT_SYNC_SESSION_UPDATED: &str = "catcloud://sync-session-updated";
pub const EVENT_SYNC_RECEIVED: &str = "catcloud://sync-received";

const MAX_PENDING_BUNDLES: usize = 6;
const PENDING_BUNDLE_TTL: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncSendSessionDto {
    pub session_id: String,
    pub pin_code: String,
    pub lan_urls: Vec<String>,
    pub custom_endpoint: Option<String>,
    pub port: u16,
    pub fingerprint: String,
    pub qr_uri: String,
    pub qr_svg: String,
    pub expires_at_unix: u64,
    pub payload_bytes: usize,
    pub allow_multiple: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncReceiveSessionDto {
    pub session_id: String,
    pub pin_code: String,
    pub lan_urls: Vec<String>,
    pub custom_endpoint: Option<String>,
    pub port: u16,
    pub qr_uri: String,
    pub qr_svg: String,
    pub expires_at_unix: u64,
    pub allow_multiple: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncSessionEventPayload {
    pub session_id: String,
    pub role: String,
    pub status: String,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncReceivedEventPayload {
    pub session_id: String,
    pub pending_token: String,
    pub fingerprint: String,
    pub via_pin: bool,
    pub node_count: usize,
    pub relay_count: usize,
    pub group_count: usize,
    pub pack_name: String,
}

pub struct PendingSyncBundle {
    pub zip_bytes: Vec<u8>,
    pub preview: ShareBundlePreview,
    pub fingerprint: String,
    pub created_at: Instant,
}

pub struct LanSyncManager {
    active_send: Mutex<Option<LanSyncSendServer>>,
    active_receive: Mutex<Option<LanSyncReceiveServer>>,
    pending_bundles: Mutex<HashMap<String, PendingSyncBundle>>,
}

impl Default for LanSyncManager {
    fn default() -> Self {
        Self::new()
    }
}

impl LanSyncManager {
    pub fn new() -> Self {
        Self {
            active_send: Mutex::new(None),
            active_receive: Mutex::new(None),
            pending_bundles: Mutex::new(HashMap::new()),
        }
    }

    async fn start_send_session_inner(
        &self,
        zip_bytes: Vec<u8>,
        custom_endpoint: Option<String>,
        ttl_secs: Option<u64>,
        allow_multiple: bool,
    ) -> Result<(SyncSendSessionDto, watch::Receiver<Option<String>>), String> {
        let payload_bytes = zip_bytes.len();
        let opts = LanSyncServerOptions {
            bind_host: "0.0.0.0".to_string(),
            bind_port: 0,
            custom_endpoint: custom_endpoint.filter(|s| !s.trim().is_empty()),
            ttl_secs: ttl_secs.unwrap_or(180).clamp(30, 900),
            allow_multiple,
        };

        let server = LanSyncSendServer::start(zip_bytes, opts)
            .await
            .map_err(|e| format!("启动局域网发送同步失败：{e}"))?;
        let info: LanSyncSendInfo = server.info().clone();
        let close_reason_rx = server.subscribe_close_reason();
        let qr_svg = render_qr_svg(&info.uri)
            .map_err(|e| format!("生成同步二维码失败：{e}"))?;

        let lan_urls: Vec<String> = info
            .hosts
            .iter()
            .map(|h| format!("http://{h}:{}", info.port))
            .collect();

        let prev_server = if let Ok(mut guard) = self.active_send.lock() {
            let prev = guard.take();
            *guard = Some(server);
            prev
        } else {
            None
        };
        if let Some(mut prev) = prev_server {
            prev.cancel().await;
        }

        Ok((
            SyncSendSessionDto {
                session_id: info.sid,
                pin_code: info.pin,
                lan_urls,
                custom_endpoint: info.custom_endpoint,
                port: info.port,
                fingerprint: info.fingerprint,
                qr_uri: info.uri,
                qr_svg,
                expires_at_unix: info.expires_at_unix.max(0) as u64,
                payload_bytes,
                allow_multiple: info.allow_multiple,
            },
            close_reason_rx,
        ))
    }

    fn clear_send_slot_if_matches(&self, session_id: &str) {
        let removed = if let Ok(mut guard) = self.active_send.lock() {
            if guard.as_ref().is_some_and(|srv| srv.info().sid == session_id) {
                guard.take()
            } else {
                None
            }
        } else {
            None
        };
        drop(removed);
    }

    fn clear_receive_slot_if_matches(&self, session_id: &str) {
        let removed = if let Ok(mut guard) = self.active_receive.lock() {
            if guard.as_ref().is_some_and(|srv| srv.info().sid == session_id) {
                guard.take()
            } else {
                None
            }
        } else {
            None
        };
        drop(removed);
    }

    pub async fn start_send_session(
        self: &Arc<Self>,
        app: AppHandle,
        zip_bytes: Vec<u8>,
        custom_endpoint: Option<String>,
        ttl_secs: Option<u64>,
        allow_multiple: bool,
    ) -> Result<SyncSendSessionDto, String> {
        let (dto, mut close_reason_rx) = self
            .start_send_session_inner(zip_bytes, custom_endpoint, ttl_secs, allow_multiple)
            .await?;

        let mgr = Arc::clone(self);
        let sid_for_task = dto.session_id.clone();
        tauri::async_runtime::spawn(async move {
            let reason = loop {
                let current = close_reason_rx.borrow().clone();
                if let Some(r) = current {
                    break r;
                }
                if close_reason_rx.changed().await.is_err() {
                    let final_reason = close_reason_rx.borrow().clone();
                    break final_reason.unwrap_or_else(|| "closed".to_string());
                }
            };
            mgr.clear_send_slot_if_matches(&sid_for_task);
            let _ = app.emit(
                EVENT_SYNC_SESSION_UPDATED,
                SyncSessionEventPayload {
                    session_id: sid_for_task,
                    role: "pull".to_string(),
                    status: reason,
                    message: None,
                },
            );
        });

        Ok(dto)
    }

    pub async fn cancel_send_session(&self, session_id: Option<&str>) -> bool {
        let removed = if let Ok(mut guard) = self.active_send.lock() {
            let should_cancel = match (&*guard, session_id) {
                (Some(srv), Some(target)) => srv.info().sid == target,
                (Some(_), None) => true,
                (None, _) => false,
            };
            if should_cancel {
                guard.take()
            } else {
                None
            }
        } else {
            None
        };
        if let Some(mut prev) = removed {
            prev.cancel().await;
            return true;
        }
        false
    }

    pub async fn start_receive_listener(
        self: &Arc<Self>,
        app: AppHandle,
        custom_endpoint: Option<String>,
        ttl_secs: Option<u64>,
        allow_multiple: bool,
    ) -> Result<SyncReceiveSessionDto, String> {
        let opts = LanSyncServerOptions {
            bind_host: "0.0.0.0".to_string(),
            bind_port: 0,
            custom_endpoint: custom_endpoint.filter(|s| !s.trim().is_empty()),
            ttl_secs: ttl_secs.unwrap_or(180).clamp(30, 900),
            allow_multiple,
        };

        let mut server = LanSyncReceiveServer::start(opts)
            .await
            .map_err(|e| format!("启动局域网接收同步监听失败：{e}"))?;
        let info: LanSyncReceiveInfo = server.info().clone();
        let qr_svg = render_qr_svg(&info.uri)
            .map_err(|e| format!("生成接收二维码失败：{e}"))?;
        let lan_urls: Vec<String> = info
            .hosts
            .iter()
            .map(|h| format!("http://{h}:{}", info.port))
            .collect();

        let mut close_reason_rx = server.subscribe_close_reason();
        let rx_opt = server.take_receiver();

        let prev_server = if let Ok(mut guard) = self.active_receive.lock() {
            let prev = guard.take();
            *guard = Some(server);
            prev
        } else {
            None
        };
        if let Some(mut prev) = prev_server {
            prev.cancel().await;
        }

        if let Some(mut rx) = rx_opt {
            let mgr = Arc::clone(self);
            let sid_for_task = info.sid.clone();
            tauri::async_runtime::spawn(async move {
                while let Some(received) = rx.recv().await {
                    match preview_share_bundle_zip_bytes(&received.zip_bytes) {
                        Ok(preview) => {
                            let node_count = preview.nodes.len();
                            let relay_count = preview.relays.len();
                            let group_count = preview
                                .groups_bundle
                                .as_ref()
                                .map(|g| g.groups.len())
                                .unwrap_or(0);
                            let pack_name = preview.manifest.name.clone();
                            let token = mgr.store_pending_bundle(
                                received.zip_bytes,
                                preview,
                                received.fingerprint.clone(),
                            );
                            let _ = app.emit(
                                EVENT_SYNC_RECEIVED,
                                SyncReceivedEventPayload {
                                    session_id: sid_for_task.clone(),
                                    pending_token: token,
                                    fingerprint: received.fingerprint,
                                    via_pin: received.via_pin,
                                    node_count,
                                    relay_count,
                                    group_count,
                                    pack_name,
                                },
                            );
                        }
                        Err(err) => {
                            let _ = app.emit(
                                EVENT_SYNC_SESSION_UPDATED,
                                SyncSessionEventPayload {
                                    session_id: sid_for_task.clone(),
                                    role: "push".to_string(),
                                    status: "invalid_payload".to_string(),
                                    message: Some(format!("收到无法解析的同步包：{err}")),
                                },
                            );
                        }
                    }
                }
                let initial_reason = close_reason_rx.borrow().clone();
                let reason = match initial_reason {
                    Some(r) => r,
                    None => {
                        let _ = tokio::time::timeout(
                            Duration::from_millis(200),
                            close_reason_rx.changed(),
                        )
                        .await;
                        let final_reason = close_reason_rx.borrow().clone();
                        final_reason.unwrap_or_else(|| "closed".to_string())
                    }
                };
                mgr.clear_receive_slot_if_matches(&sid_for_task);
                let _ = app.emit(
                    EVENT_SYNC_SESSION_UPDATED,
                    SyncSessionEventPayload {
                        session_id: sid_for_task,
                        role: "push".to_string(),
                        status: reason,
                        message: None,
                    },
                );
            });
        }

        Ok(SyncReceiveSessionDto {
            session_id: info.sid,
            pin_code: info.pin,
            lan_urls,
            custom_endpoint: info.custom_endpoint,
            port: info.port,
            qr_uri: info.uri,
            qr_svg,
            expires_at_unix: info.expires_at_unix.max(0) as u64,
            allow_multiple: info.allow_multiple,
        })
    }

    pub async fn cancel_receive_session(&self, session_id: Option<&str>) -> bool {
        let removed = if let Ok(mut guard) = self.active_receive.lock() {
            let should_cancel = match (&*guard, session_id) {
                (Some(srv), Some(target)) => srv.info().sid == target,
                (Some(_), None) => true,
                (None, _) => false,
            };
            if should_cancel {
                guard.take()
            } else {
                None
            }
        } else {
            None
        };
        if let Some(mut prev) = removed {
            prev.cancel().await;
            return true;
        }
        false
    }

    pub fn store_pending_bundle(
        &self,
        zip_bytes: Vec<u8>,
        preview: ShareBundlePreview,
        fingerprint: String,
    ) -> String {
        let token = format!("sync-{}", Uuid::new_v4().simple());
        if let Ok(mut map) = self.pending_bundles.lock() {
            let now = Instant::now();
            map.retain(|_, v| now.saturating_duration_since(v.created_at) < PENDING_BUNDLE_TTL);
            while map.len() >= MAX_PENDING_BUNDLES {
                if let Some(oldest_key) = map
                    .iter()
                    .min_by_key(|(_, v)| v.created_at)
                    .map(|(k, _)| k.clone())
                {
                    map.remove(&oldest_key);
                } else {
                    break;
                }
            }
            map.insert(
                token.clone(),
                PendingSyncBundle {
                    zip_bytes,
                    preview,
                    fingerprint,
                    created_at: now,
                },
            );
        }
        token
    }

    pub fn clone_pending_preview(&self, token: &str) -> Option<(ShareBundlePreview, String)> {
        let mut map = self.pending_bundles.lock().ok()?;
        let now = Instant::now();
        map.retain(|_, v| now.saturating_duration_since(v.created_at) < PENDING_BUNDLE_TTL);
        map.get(token)
            .map(|item| (item.preview.clone(), item.fingerprint.clone()))
    }

    pub fn take_pending_bundle(&self, token: &str) -> Option<PendingSyncBundle> {
        let mut map = self.pending_bundles.lock().ok()?;
        let now = Instant::now();
        map.retain(|_, v| now.saturating_duration_since(v.created_at) < PENDING_BUNDLE_TTL);
        map.remove(token)
    }

    pub fn shutdown_all(&self) {
        if let Ok(mut guard) = self.active_send.lock() {
            if let Some(srv) = guard.take() {
                drop(srv);
            }
        }
        if let Ok(mut guard) = self.active_receive.lock() {
            if let Some(srv) = guard.take() {
                drop(srv);
            }
        }
        if let Ok(mut map) = self.pending_bundles.lock() {
            map.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use catcloud_core::models::ProxyNode;
    use catcloud_core::share_bundle::{
        ShareBundleExportRequest, export_share_bundle_zip_bytes,
    };
    use catcloud_core::sync::{fetch_sync_bundle_via_uri, plaintext_fingerprint};

    fn sample_zip_bytes() -> Vec<u8> {
        let node = ProxyNode {
            id: "node-sync-test-1".to_string(),
            sub_id: "sub-test".to_string(),
            name: "JP-01".to_string(),
            protocol: "vless".to_string(),
            server: "edge.example.invalid".to_string(),
            port: 443,
            raw_config: serde_json::json!({
                "name": "JP-01",
                "type": "vless",
                "server": "edge.example.invalid",
                "port": 443,
                "uuid": "00000000-0000-4000-8000-000000000001"
            }),
            ..ProxyNode::default()
        };
        let req = ShareBundleExportRequest {
            name: "Sync Test Pack".to_string(),
            description: Some("unit test".to_string()),
            nodes: vec![node],
            relays: Vec::new(),
        };
        export_share_bundle_zip_bytes(&req).expect("zip").0
    }

    #[tokio::test]
    async fn lan_sync_manager_send_pull_and_pending_store_roundtrip() {
        let mgr = LanSyncManager::new();
        let zip = sample_zip_bytes();
        let expected_fp = plaintext_fingerprint(&zip);

        let dto = mgr
            .start_send_session_inner(
                zip.clone(),
                Some("http://127.0.0.1:0".to_string()),
                Some(60),
                false,
            )
            .await;
        // custom_endpoint with port 0 is valid syntax, let's test normal local pull without custom_endpoint override
        drop(dto);

        let (dto, mut close_reason_rx) = mgr
            .start_send_session_inner(zip.clone(), None, Some(60), false)
            .await
            .expect("start_send_session_inner");
        assert_eq!(dto.fingerprint, expected_fp);
        assert_eq!(dto.pin_code.len(), 6);
        assert!(dto.qr_svg.contains("<svg"));
        assert!(dto.qr_uri.starts_with("catcloud://sync/v1?"));

        // Pull via loopback using rewritten localhost endpoint with same key/sid
        let mut parsed = catcloud_core::sync::parse_sync_uri(&dto.qr_uri).expect("parse uri");
        parsed.hosts = vec!["127.0.0.1".to_string()];
        let local_uri = catcloud_core::sync::format_sync_uri(&parsed).expect("format uri");
        let pulled = fetch_sync_bundle_via_uri(&local_uri)
            .await
            .expect("pull via uri");
        assert_eq!(pulled, zip);

        // One-shot pull should report completed close_reason and allow slot cleanup
        if close_reason_rx.borrow().is_none() {
            let _ = tokio::time::timeout(Duration::from_secs(2), close_reason_rx.changed()).await;
        }
        assert_eq!(close_reason_rx.borrow().as_deref(), Some("completed"));
        mgr.clear_send_slot_if_matches(&dto.session_id);
        assert!(mgr.active_send.lock().unwrap().is_none());

        let preview = preview_share_bundle_zip_bytes(&pulled).expect("preview");
        let token = mgr.store_pending_bundle(pulled, preview, expected_fp.clone());
        let (cloned_preview, cloned_fp) = mgr
            .clone_pending_preview(&token)
            .expect("clone pending preview");
        assert_eq!(cloned_fp, expected_fp);
        assert_eq!(cloned_preview.nodes.len(), 1);

        let taken = mgr
            .take_pending_bundle(&token)
            .expect("take pending bundle");
        assert_eq!(taken.zip_bytes.len(), zip.len());
        assert!(mgr.clone_pending_preview(&token).is_none());

        assert!(!mgr.cancel_send_session(Some("non-existent")).await);
        mgr.shutdown_all();
    }
}
