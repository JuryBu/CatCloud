use crate::error::{CatError, CatResult};
use crate::models::{
    DynamicFilterSpec, FallbackPolicy, MultiGroup, MultiGroupMode, MultiGroupState, NodeFilter,
    NodeSummary, PreAccelRelay, ProbeDefinition, ProbeKind, ProbeResultRecord, ProbeSnapshot,
    ProxyNode, SubscriptionKind, SubscriptionRecord, SwitchMode, TriggerRule,
    pick_smart_default_node_id,
};
use crate::subscription::parser::node_dedup_fingerprint;
use rusqlite::{Connection, OptionalExtension, Row, Transaction, params, params_from_iter};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Current SQLite schema version tracked via `PRAGMA user_version`.
pub const CURRENT_SCHEMA_VERSION: u32 = 5;

/// Strategy used by `Storage::update_subscription_nodes_with_mode` when updating an existing
/// subscription group with newly fetched, captured, or imported nodes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionUpdateMode {
    /// Keep only nodes present in the incoming payload while reusing existing node IDs
    /// (first by exact `id`, then by `node_dedup_fingerprint`) to preserve probe history
    /// and multi-group references.
    ReplaceLatest,
    /// Preserve all existing nodes and their IDs, updating in-place any matching fingerprint
    /// nodes and inserting only truly new fingerprints.
    MergeDedup,
}

/// Summary returned by `Storage::update_subscription_nodes_with_mode`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriptionNodesUpdateResult {
    pub sub_id: String,
    pub kept_count: usize,
    pub added_count: usize,
    pub replaced_count: usize,
    pub total_count: usize,
    pub id_remap: HashMap<String, String>,
}

/// Summary returned by `Storage::merge_subscriptions`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MergeSubscriptionsResult {
    pub target_sub_id: String,
    pub source_sub_id: String,
    pub moved_count: usize,
    pub deduplicated_count: usize,
    pub total_count: usize,
    pub id_remap: HashMap<String, String>,
}

/// Consistent snapshot of backup-managed SQLite entities (`multi_groups`, `preaccel_relays`,
/// `probe_definitions`) used for atomic backup restore and deterministic rollback.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct BackupDbSnapshot {
    pub groups: Vec<MultiGroup>,
    pub relays: Vec<PreAccelRelay>,
    pub probes: Vec<ProbeDefinition>,
}

/// SQLite persistence layer backed by bundled `rusqlite` in WAL mode.
pub struct Storage {
    conn: Connection,
}

impl Storage {
    /// Open (or create) an on-disk SQLite database, apply required PRAGMAs, and run migrations.
    pub fn open(path: &Path) -> CatResult<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let conn = Connection::open(path)?;
        let mut storage = Self { conn };
        storage.configure_pragmas()?;
        storage.migrate()?;
        Ok(storage)
    }

    /// Open an isolated in-memory SQLite database (primarily for tests and ephemeral dry-runs).
    pub fn open_in_memory() -> CatResult<Self> {
        let conn = Connection::open_in_memory()?;
        let mut storage = Self { conn };
        storage.configure_pragmas()?;
        storage.migrate()?;
        Ok(storage)
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    fn configure_pragmas(&self) -> CatResult<()> {
        self.conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA foreign_keys = ON;
            PRAGMA busy_timeout = 5000;
            PRAGMA temp_store = MEMORY;
            PRAGMA cache_size = -1024;
            PRAGMA mmap_size = 0;
            PRAGMA wal_autocheckpoint = 200;
            ",
        )?;
        self.conn.set_prepared_statement_cache_capacity(24);
        Ok(())
    }

    /// Release cached prepared statements, run a passive WAL checkpoint, and shrink SQLite
    /// page-cache memory back to the OS. Best-effort: logs errors at debug level and never panics.
    pub fn compact_memory(&self) {
        self.conn.flush_prepared_statement_cache();
        if let Err(err) = self.conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE);") {
            tracing::debug!("sqlite passive wal_checkpoint skipped during compact_memory: {err}");
        }
        if let Err(err) = self.conn.execute_batch("PRAGMA shrink_memory;") {
            tracing::debug!("sqlite shrink_memory skipped during compact_memory: {err}");
        }
    }

    pub fn schema_version(&self) -> CatResult<u32> {
        let v: i64 = self
            .conn
            .query_row("PRAGMA user_version;", [], |row| row.get(0))?;
        Ok(v.max(0) as u32)
    }

    pub fn journal_mode(&self) -> CatResult<String> {
        let mode: String = self
            .conn
            .query_row("PRAGMA journal_mode;", [], |row| row.get(0))?;
        Ok(mode)
    }

    pub fn foreign_keys_enabled(&self) -> CatResult<bool> {
        let enabled: i64 = self
            .conn
            .query_row("PRAGMA foreign_keys;", [], |row| row.get(0))?;
        Ok(enabled != 0)
    }

    pub fn busy_timeout_ms(&self) -> CatResult<i64> {
        let ms: i64 = self
            .conn
            .query_row("PRAGMA busy_timeout;", [], |row| row.get(0))?;
        Ok(ms)
    }

    /// Execute an atomic closure inside a SQLite transaction; any error rolls back all writes.
    pub fn in_transaction<T, F>(&mut self, op: F) -> CatResult<T>
    where
        F: FnOnce(&Transaction<'_>) -> CatResult<T>,
    {
        let tx = self.conn.transaction()?;
        let res = op(&tx)?;
        tx.commit()?;
        Ok(res)
    }

    /// Idempotent schema migration across all 6 core tables.
    fn migrate(&mut self) -> CatResult<()> {
        let current = self.schema_version()?;
        if current >= CURRENT_SCHEMA_VERSION {
            return Ok(());
        }

        self.in_transaction(|tx| {
            if current < 1 {
                tx.execute_batch(SCHEMA_V1_SQL)?;
            }
            if current < 2 {
                ensure_column_exists(
                    tx,
                    "multi_groups",
                    "independent_routing",
                    "INTEGER NOT NULL DEFAULT 0",
                )?;
            }
            if current < 3 {
                tx.execute_batch(
                    "
                    CREATE TABLE IF NOT EXISTS preaccel_relays (
                        id TEXT PRIMARY KEY NOT NULL,
                        name TEXT NOT NULL,
                        provider TEXT NOT NULL DEFAULT '',
                        region TEXT NOT NULL DEFAULT '',
                        server TEXT NOT NULL,
                        port INTEGER NOT NULL DEFAULT 443,
                        protocol TEXT NOT NULL,
                        password TEXT NOT NULL DEFAULT '',
                        sni TEXT,
                        skip_cert_verify INTEGER NOT NULL DEFAULT 1,
                        priority INTEGER NOT NULL DEFAULT 100,
                        expires_at TEXT,
                        enabled INTEGER NOT NULL DEFAULT 1,
                        last_probe_ms REAL,
                        last_mbps REAL,
                        last_up_mbps REAL,
                        last_down_mbps REAL
                    );
                    ",
                )?;
                ensure_column_exists(tx, "preaccel_relays", "last_up_mbps", "REAL")?;
                ensure_column_exists(tx, "preaccel_relays", "last_down_mbps", "REAL")?;
            }
            if current < 4 {
                ensure_column_exists(
                    tx,
                    "preaccel_relays",
                    "supports_ipv6",
                    "INTEGER NOT NULL DEFAULT 0",
                )?;
            }
            if current < 5 {
                tx.execute_batch(
                    "
                    CREATE TABLE IF NOT EXISTS probe_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        node_id TEXT NOT NULL,
                        probe_id TEXT NOT NULL,
                        tested_at TEXT NOT NULL,
                        ok INTEGER NOT NULL DEFAULT 0,
                        latency_ms REAL,
                        jitter_ms REAL,
                        loss_pct REAL,
                        up_mbps REAL,
                        down_mbps REAL,
                        cf_loc TEXT,
                        yt_gl TEXT,
                        google_clean INTEGER,
                        keepalive_60s_ok INTEGER,
                        unlocked_map_json TEXT NOT NULL DEFAULT '{}',
                        detail TEXT,
                        ip_clean INTEGER,
                        ip_risk_level TEXT,
                        ip_asn TEXT,
                        ip_risk_flags TEXT,
                        FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
                        FOREIGN KEY (probe_id) REFERENCES probe_definitions(id) ON DELETE CASCADE
                    );
                    ",
                )?;
                ensure_column_exists(tx, "probe_results", "ip_clean", "INTEGER")?;
                ensure_column_exists(tx, "probe_results", "ip_risk_level", "TEXT")?;
                ensure_column_exists(tx, "probe_results", "ip_asn", "TEXT")?;
                ensure_column_exists(tx, "probe_results", "ip_risk_flags", "TEXT")?;
            }
            tx.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION as i64)?;
            Ok(())
        })
    }

    // -------------------------------------------------------------------------
    // 1. Subscriptions CRUD
    // -------------------------------------------------------------------------

    pub fn upsert_subscription(&self, sub: &SubscriptionRecord) -> CatResult<()> {
        if sub.id.trim().is_empty() {
            return Err(CatError::Validation("subscription id cannot be empty".into()));
        }
        self.conn.execute(
            "
            INSERT INTO subscriptions (
                id, name, kind, url_or_cmd, refresh_interval_sec,
                traffic_used, traffic_total, expires_at, etag,
                last_ok_at, last_error, enabled, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                kind = excluded.kind,
                url_or_cmd = excluded.url_or_cmd,
                refresh_interval_sec = excluded.refresh_interval_sec,
                traffic_used = excluded.traffic_used,
                traffic_total = excluded.traffic_total,
                expires_at = excluded.expires_at,
                etag = excluded.etag,
                last_ok_at = excluded.last_ok_at,
                last_error = excluded.last_error,
                enabled = excluded.enabled,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
            ",
            params![
                sub.id,
                sub.name,
                sub.kind.as_str(),
                sub.url_or_cmd,
                sub.refresh_interval_sec as i64,
                sub.traffic_used_bytes as i64,
                sub.traffic_total_bytes as i64,
                sub.expires_at,
                sub.etag,
                sub.last_ok_at,
                sub.last_error,
                bool_to_int(sub.enabled),
            ],
        )?;
        Ok(())
    }

    pub fn get_subscription(&self, id: &str) -> CatResult<Option<SubscriptionRecord>> {
        let mut stmt = self.conn.prepare_cached(
            "
            SELECT id, name, kind, url_or_cmd, refresh_interval_sec,
                   traffic_used, traffic_total, expires_at, etag,
                   last_ok_at, last_error, enabled
            FROM subscriptions
            WHERE id = ?1
            ",
        )?;
        stmt.query_row(params![id], row_to_subscription)
            .optional()
            .map_err(Into::into)
    }

    pub fn list_subscriptions(&self) -> CatResult<Vec<SubscriptionRecord>> {
        let mut stmt = self.conn.prepare_cached(
            "
            SELECT id, name, kind, url_or_cmd, refresh_interval_sec,
                   traffic_used, traffic_total, expires_at, etag,
                   last_ok_at, last_error, enabled
            FROM subscriptions
            ORDER BY name ASC, id ASC
            ",
        )?;
        let rows = stmt.query_map([], row_to_subscription)?;
        let mut list = Vec::new();
        for row in rows {
            list.push(row?);
        }
        Ok(list)
    }

    pub fn delete_subscription(&self, id: &str) -> CatResult<bool> {
        let tx = self.conn.unchecked_transaction()?;
        let sub_node_ids = load_node_ids_for_subscription_in_tx(&tx, id)?;
        let changed = tx.execute("DELETE FROM subscriptions WHERE id = ?1", params![id])?;
        if changed > 0 {
            let live_node_ids = load_all_node_ids_in_tx(&tx)?;
            let empty_remap = HashMap::new();
            remap_multi_groups_in_tx(
                &tx,
                &empty_remap,
                &sub_node_ids,
                None,
                Some(id),
                Some(&live_node_ids),
            )?;
        }
        tx.commit()?;
        Ok(changed > 0)
    }

    /// Rename an existing subscription in place without touching its nodes, probe results,
    /// or multi-group memberships.
    pub fn rename_subscription(&self, sub_id: &str, new_name: &str) -> CatResult<SubscriptionRecord> {
        let id = sub_id.trim();
        if id.is_empty() {
            return Err(CatError::Validation("订阅 ID 不能为空".into()));
        }
        let trimmed_name = new_name.trim();
        if trimmed_name.is_empty() {
            return Err(CatError::Validation("订阅名称不能为空".into()));
        }

        let changed = self.conn.execute(
            "
            UPDATE subscriptions
            SET name = ?2,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
            WHERE id = ?1
            ",
            params![id, trimmed_name],
        )?;
        if changed == 0 {
            return Err(CatError::NotFound(format!("未找到订阅：{id}")));
        }

        self.get_subscription(id)?
            .ok_or_else(|| CatError::NotFound(format!("未找到订阅：{id}")))
    }

    /// Atomically update an existing subscription's nodes using either `ReplaceLatest` or
    /// `MergeDedup`, preserving probe history and multi-group references across ID reuse and
    /// deduplication remaps.
    ///
    /// - Rejects empty `incoming_nodes` immediately without mutating any table.
    /// - `ReplaceLatest`: matches incoming nodes to existing ones by exact `id` first, then by
    ///   `node_dedup_fingerprint` so surviving nodes keep their original ID, `probe_results`,
    ///   and `multi_groups` memberships; remaps duplicate vanished nodes and removes stale ones.
    /// - `MergeDedup`: keeps every existing node and ID intact, updates matching fingerprint
    ///   nodes in place (preserving original ID and `probe_results`), and inserts only new
    ///   fingerprints.
    pub fn update_subscription_nodes_with_mode(
        &self,
        target_sub_id: &str,
        incoming_nodes: &[ProxyNode],
        mode: SubscriptionUpdateMode,
    ) -> CatResult<SubscriptionNodesUpdateResult> {
        let sub_id = target_sub_id.trim();
        if sub_id.is_empty() {
            return Err(CatError::Validation("目标订阅 ID 不能为空".into()));
        }
        if incoming_nodes.is_empty() {
            return Err(CatError::Validation(
                "新节点列表为空，已取消更新以保留原有节点数据".into(),
            ));
        }

        let tx = self.conn.unchecked_transaction()?;

        if !subscription_exists_in_tx(&tx, sub_id)? {
            return Err(CatError::NotFound(format!("未找到目标订阅：{sub_id}")));
        }

        let existing_nodes = load_nodes_for_subscription_in_tx(&tx, sub_id)?;
        let foreign_ids = load_foreign_node_ids_in_tx(&tx, sub_id)?;

        let mut existing_by_id: HashMap<String, &ProxyNode> =
            HashMap::with_capacity(existing_nodes.len());
        let mut existing_by_fp: HashMap<String, Vec<String>> = HashMap::new();
        for node in &existing_nodes {
            existing_by_id.insert(node.id.clone(), node);
            let fp = node_dedup_fingerprint(node);
            existing_by_fp.entry(fp).or_default().push(node.id.clone());
        }

        let incoming_fps: Vec<String> = incoming_nodes.iter().map(node_dedup_fingerprint).collect();

        let result = match mode {
            SubscriptionUpdateMode::ReplaceLatest => {
                let mut assignments: Vec<Option<String>> = vec![None; incoming_nodes.len()];
                let mut claimed_old_ids: HashSet<String> = HashSet::new();
                let mut accepted_fps: HashSet<String> = HashSet::new();
                let mut fp_to_kept_id: HashMap<String, String> = HashMap::new();
                let mut occupied_ids: HashSet<String> = foreign_ids;
                for node in &existing_nodes {
                    occupied_ids.insert(node.id.clone());
                }

                // Pass 1: exact node ID reuse.
                for (idx, incoming) in incoming_nodes.iter().enumerate() {
                    let fp = &incoming_fps[idx];
                    if accepted_fps.contains(fp) {
                        continue;
                    }
                    let cid = incoming.id.trim();
                    if !cid.is_empty()
                        && existing_by_id.contains_key(cid)
                        && claimed_old_ids.insert(cid.to_string())
                    {
                        assignments[idx] = Some(cid.to_string());
                        accepted_fps.insert(fp.clone());
                        fp_to_kept_id.insert(fp.clone(), cid.to_string());
                    }
                }

                // Pass 2: physical fingerprint reuse of unclaimed existing node IDs.
                for (idx, _incoming) in incoming_nodes.iter().enumerate() {
                    if assignments[idx].is_some() {
                        continue;
                    }
                    let fp = &incoming_fps[idx];
                    if accepted_fps.contains(fp) {
                        continue;
                    }
                    if let Some(old_candidates) = existing_by_fp.get(fp) {
                        if let Some(reused_id) = old_candidates
                            .iter()
                            .find(|oid| !claimed_old_ids.contains(oid.as_str()))
                            .cloned()
                        {
                            claimed_old_ids.insert(reused_id.clone());
                            assignments[idx] = Some(reused_id.clone());
                            accepted_fps.insert(fp.clone());
                            fp_to_kept_id.insert(fp.clone(), reused_id);
                        }
                    }
                }

                // Pass 3: allocate collision-free IDs for genuinely new incoming nodes.
                let mut added_count = 0usize;
                for (idx, incoming) in incoming_nodes.iter().enumerate() {
                    if assignments[idx].is_some() {
                        continue;
                    }
                    let fp = &incoming_fps[idx];
                    if accepted_fps.contains(fp) {
                        continue;
                    }
                    let raw_id = incoming.id.trim();
                    let new_id = if !raw_id.is_empty() && occupied_ids.insert(raw_id.to_string()) {
                        raw_id.to_string()
                    } else {
                        allocate_unique_node_id(sub_id, fp, &mut occupied_ids)
                    };
                    assignments[idx] = Some(new_id.clone());
                    accepted_fps.insert(fp.clone());
                    fp_to_kept_id.insert(fp.clone(), new_id);
                    added_count += 1;
                }

                let kept_count = claimed_old_ids.len();

                // Handle vanished existing nodes: migrate newer probe_results if another surviving
                // node holds the same physical fingerprint, record id_remap, and delete vanished rows.
                let mut id_remap: HashMap<String, String> = HashMap::new();
                let mut removed_unmapped_ids: HashSet<String> = HashSet::new();
                let mut replaced_count = 0usize;

                for old in &existing_nodes {
                    if claimed_old_ids.contains(&old.id) {
                        continue;
                    }
                    replaced_count += 1;
                    let old_fp = node_dedup_fingerprint(old);
                    if let Some(kept_id) = fp_to_kept_id.get(&old_fp) {
                        if kept_id != &old.id {
                            migrate_newer_probe_results_in_tx(&tx, &old.id, kept_id)?;
                            id_remap.insert(old.id.clone(), kept_id.clone());
                        }
                    } else {
                        removed_unmapped_ids.insert(old.id.clone());
                    }
                    tx.execute("DELETE FROM nodes WHERE id = ?1", params![old.id])?;
                }

                // Upsert all surviving and newly added nodes (preserving per-node preaccel_override
                // when incoming does not explicitly specify one).
                for (idx, incoming) in incoming_nodes.iter().enumerate() {
                    let Some(assigned_id) = assignments[idx].as_ref() else {
                        continue;
                    };
                    let mut node = incoming.clone();
                    node.id = assigned_id.clone();
                    node.sub_id = sub_id.to_string();
                    if node.preaccel_override.is_none() {
                        if let Some(prev) = existing_by_id.get(assigned_id) {
                            node.preaccel_override = prev.preaccel_override;
                        }
                    }
                    upsert_node_with_conn(&tx, &node)?;
                }

                if !id_remap.is_empty() || !removed_unmapped_ids.is_empty() {
                    remap_multi_groups_in_tx(
                        &tx,
                        &id_remap,
                        &removed_unmapped_ids,
                        None,
                        None,
                        None,
                    )?;
                }

                let total_count = kept_count + added_count;
                SubscriptionNodesUpdateResult {
                    sub_id: sub_id.to_string(),
                    kept_count,
                    added_count,
                    replaced_count,
                    total_count,
                    id_remap,
                }
            }
            SubscriptionUpdateMode::MergeDedup => {
                let mut occupied_ids: HashSet<String> = foreign_ids;
                for node in &existing_nodes {
                    occupied_ids.insert(node.id.clone());
                }

                let mut updated_old_ids: HashSet<String> = HashSet::new();
                let mut inserted_fps: HashSet<String> = HashSet::new();
                let mut matched_indices: HashSet<usize> = HashSet::new();
                let mut added_count = 0usize;

                // Pass 1: exact existing ID updates in place (preserve original ID & probe history).
                for (idx, incoming) in incoming_nodes.iter().enumerate() {
                    let cid = incoming.id.trim();
                    if !cid.is_empty() && existing_by_id.contains_key(cid) {
                        let mut node = incoming.clone();
                        node.id = cid.to_string();
                        node.sub_id = sub_id.to_string();
                        if node.preaccel_override.is_none() {
                            if let Some(prev) = existing_by_id.get(cid) {
                                node.preaccel_override = prev.preaccel_override;
                            }
                        }
                        upsert_node_with_conn(&tx, &node)?;
                        updated_old_ids.insert(cid.to_string());
                        matched_indices.insert(idx);
                    }
                }

                // Pass 2: fingerprint match updates existing node in place; unseen fingerprints insert.
                for (idx, incoming) in incoming_nodes.iter().enumerate() {
                    if matched_indices.contains(&idx) {
                        continue;
                    }
                    let fp = &incoming_fps[idx];
                    if let Some(old_candidates) = existing_by_fp.get(fp) {
                        let target_old_id = old_candidates
                            .iter()
                            .find(|oid| !updated_old_ids.contains(oid.as_str()))
                            .or_else(|| old_candidates.first())
                            .cloned();
                        if let Some(old_id) = target_old_id {
                            let mut node = incoming.clone();
                            node.id = old_id.clone();
                            node.sub_id = sub_id.to_string();
                            if node.preaccel_override.is_none() {
                                if let Some(prev) = existing_by_id.get(&old_id) {
                                    node.preaccel_override = prev.preaccel_override;
                                }
                            }
                            upsert_node_with_conn(&tx, &node)?;
                            updated_old_ids.insert(old_id);
                            continue;
                        }
                    }

                    if !inserted_fps.insert(fp.clone()) {
                        continue;
                    }

                    let raw_id = incoming.id.trim();
                    let new_id = if !raw_id.is_empty() && occupied_ids.insert(raw_id.to_string()) {
                        raw_id.to_string()
                    } else {
                        allocate_unique_node_id(sub_id, fp, &mut occupied_ids)
                    };
                    let mut node = incoming.clone();
                    node.id = new_id;
                    node.sub_id = sub_id.to_string();
                    upsert_node_with_conn(&tx, &node)?;
                    added_count += 1;
                }

                let replaced_count = updated_old_ids.len();
                let kept_count = existing_nodes.len().saturating_sub(replaced_count);
                let total_count = existing_nodes.len() + added_count;
                SubscriptionNodesUpdateResult {
                    sub_id: sub_id.to_string(),
                    kept_count,
                    added_count,
                    replaced_count,
                    total_count,
                    id_remap: HashMap::new(),
                }
            }
        };

        tx.execute(
            "UPDATE subscriptions SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1",
            params![sub_id],
        )?;
        tx.commit()?;
        Ok(result)
    }

    /// Atomically merge `source_sub_id` into `target_sub_id` in a single SQLite transaction
    /// with zero accidental cascade deletion:
    /// 1. Verify both subscriptions exist and differ.
    /// 2. Identify duplicate source nodes by `node_dedup_fingerprint` when `deduplicate` is true.
    /// 3. Move non-duplicate source nodes in place (`UPDATE nodes SET sub_id = ?target WHERE id = ?id`)
    ///    so their IDs, `probe_results`, and `multi_groups` references remain intact.
    /// 4. For each deduplicated source node `S_dup -> T_keep`, migrate newer `probe_results` rows
    ///    (replacing only when `T_keep` has no record for that probe or `S_dup.tested_at` is newer),
    ///    delete `S_dup`, and remap every `multi_groups` entry (`member_node_ids` deduplicated,
    ///    `active_node_id`, and `dynamic_filter.sub_ids` rewriting `source_sub_id -> target_sub_id`).
    /// 5. Optionally rename `target_sub_id` and/or convert its `kind` to `migrated`.
    /// 6. Finally `DELETE FROM subscriptions WHERE id = ?source_sub_id`.
    pub fn merge_subscriptions(
        &self,
        source_sub_id: &str,
        target_sub_id: &str,
        new_target_name: Option<&str>,
        deduplicate: bool,
        convert_target_to_migrated: bool,
    ) -> CatResult<MergeSubscriptionsResult> {
        let src_id = source_sub_id.trim();
        let tgt_id = target_sub_id.trim();
        if src_id.is_empty() || tgt_id.is_empty() {
            return Err(CatError::Validation("源订阅和目标订阅 ID 均不能为空".into()));
        }
        if src_id == tgt_id {
            return Err(CatError::Validation("不能将订阅合并到自身".into()));
        }
        let validated_name = match new_target_name {
            Some(raw) => {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return Err(CatError::Validation("合并后的目标订阅名称不能为空".into()));
                }
                Some(trimmed.to_string())
            }
            None => None,
        };

        let tx = self.conn.unchecked_transaction()?;

        // Step 1: Verify both subscriptions exist.
        if !subscription_exists_in_tx(&tx, src_id)? {
            return Err(CatError::NotFound(format!("未找到源订阅：{src_id}")));
        }
        if !subscription_exists_in_tx(&tx, tgt_id)? {
            return Err(CatError::NotFound(format!("未找到目标订阅：{tgt_id}")));
        }

        // Step 2: Load nodes and compute physical fingerprints for deduplication.
        let target_nodes = load_nodes_for_subscription_in_tx(&tx, tgt_id)?;
        let source_nodes = load_nodes_for_subscription_in_tx(&tx, src_id)?;

        let mut target_fp_to_id: HashMap<String, String> =
            HashMap::with_capacity(target_nodes.len());
        for node in &target_nodes {
            let fp = node_dedup_fingerprint(node);
            target_fp_to_id.entry(fp).or_insert_with(|| node.id.clone());
        }

        let mut nodes_to_move: Vec<String> = Vec::new();
        let mut dup_pairs: Vec<(String, String)> = Vec::new();
        let mut id_remap: HashMap<String, String> = HashMap::new();

        for s_node in &source_nodes {
            if deduplicate {
                let fp = node_dedup_fingerprint(s_node);
                if let Some(t_keep_id) = target_fp_to_id.get(&fp) {
                    dup_pairs.push((s_node.id.clone(), t_keep_id.clone()));
                    id_remap.insert(s_node.id.clone(), t_keep_id.clone());
                } else {
                    target_fp_to_id.insert(fp, s_node.id.clone());
                    nodes_to_move.push(s_node.id.clone());
                }
            } else {
                nodes_to_move.push(s_node.id.clone());
            }
        }

        // Step 3: Move non-duplicate source nodes in place (preserving ID and probe_results).
        for move_id in &nodes_to_move {
            tx.execute(
                "
                UPDATE nodes
                SET sub_id = ?1,
                    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                WHERE id = ?2
                ",
                params![tgt_id, move_id],
            )?;
        }

        // Step 4: Migrate newer probe_results from S_dup -> T_keep, remove S_dup, and remap
        // all multi_groups (member_node_ids, active_node_id, dynamic_filter.sub_ids).
        for (s_dup_id, t_keep_id) in &dup_pairs {
            migrate_newer_probe_results_in_tx(&tx, s_dup_id, t_keep_id)?;
            tx.execute("DELETE FROM nodes WHERE id = ?1", params![s_dup_id])?;
        }
        let empty_removed: HashSet<String> = HashSet::new();
        remap_multi_groups_in_tx(
            &tx,
            &id_remap,
            &empty_removed,
            Some((src_id, tgt_id)),
            None,
            None,
        )?;

        // Step 5: Optional target rename and/or kind conversion to `migrated`.
        if let Some(ref new_name) = validated_name {
            tx.execute(
                "
                UPDATE subscriptions
                SET name = ?2,
                    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                WHERE id = ?1
                ",
                params![tgt_id, new_name],
            )?;
        }
        if convert_target_to_migrated {
            tx.execute(
                "
                UPDATE subscriptions
                SET kind = ?2,
                    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                WHERE id = ?1
                ",
                params![tgt_id, SubscriptionKind::Migrated.as_str()],
            )?;
        }

        // Step 6: Delete now-empty source subscription (zero unintended cascade deletes).
        tx.execute("DELETE FROM subscriptions WHERE id = ?1", params![src_id])?;

        let total_count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM nodes WHERE sub_id = ?1",
            params![tgt_id],
            |r| r.get(0),
        )?;

        tx.commit()?;

        Ok(MergeSubscriptionsResult {
            target_sub_id: tgt_id.to_string(),
            source_sub_id: src_id.to_string(),
            moved_count: nodes_to_move.len(),
            deduplicated_count: dup_pairs.len(),
            total_count: total_count.max(0) as usize,
            id_remap,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_subscription_refresh_status(
        &self,
        id: &str,
        last_ok_at: Option<&str>,
        etag: Option<&str>,
        last_error: Option<&str>,
        traffic_used_bytes: Option<u64>,
        traffic_total_bytes: Option<u64>,
        expires_at: Option<&str>,
    ) -> CatResult<bool> {
        let changed = self.conn.execute(
            "
            UPDATE subscriptions
            SET last_ok_at = COALESCE(?2, last_ok_at),
                etag = COALESCE(?3, etag),
                last_error = ?4,
                traffic_used = COALESCE(?5, traffic_used),
                traffic_total = COALESCE(?6, traffic_total),
                expires_at = COALESCE(?7, expires_at),
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
            WHERE id = ?1
            ",
            params![
                id,
                last_ok_at,
                etag,
                last_error,
                traffic_used_bytes.map(|v| v as i64),
                traffic_total_bytes.map(|v| v as i64),
                expires_at,
            ],
        )?;
        Ok(changed > 0)
    }

    // -------------------------------------------------------------------------
    // 2. Proxy Nodes CRUD & Multi-Dimensional Filtering
    // -------------------------------------------------------------------------

    pub fn upsert_node(&self, node: &ProxyNode) -> CatResult<()> {
        upsert_node_with_conn(&self.conn, node)
    }

    /// Atomically upsert a batch of proxy nodes inside a single transaction.
    pub fn upsert_nodes_batch(&mut self, nodes: &[ProxyNode]) -> CatResult<usize> {
        self.in_transaction(|tx| {
            for node in nodes {
                upsert_node_with_conn(tx, node)?;
            }
            Ok(nodes.len())
        })
    }

    /// Atomically sync nodes belonging to `sub_id` while protecting user groups and probe history:
    /// - Rejects empty node sets (prevents broken upstream 200/0-node refreshes from wiping data).
    /// - Rejects mismatched `sub_id` entries and rolls back the entire transaction on any error.
    /// - Updates surviving node IDs in place (preserving existing `probe_results` and overrides).
    /// - Removes only nodes of `sub_id` that disappeared from the new feed.
    pub fn replace_subscription_nodes(
        &mut self,
        sub_id: &str,
        new_nodes: &[ProxyNode],
    ) -> CatResult<usize> {
        if new_nodes.is_empty() {
            return Err(CatError::Validation(
                "refusing to replace subscription nodes with an empty node list".into(),
            ));
        }
        for node in new_nodes {
            if node.sub_id != sub_id {
                return Err(CatError::Validation(format!(
                    "node `{}` belongs to sub_id `{}` instead of `{}`",
                    node.id, node.sub_id, sub_id
                )));
            }
        }

        let incoming_ids: HashSet<&str> = new_nodes.iter().map(|n| n.id.as_str()).collect();

        self.in_transaction(|tx| {
            let mut existing_ids = Vec::new();
            {
                let mut stmt = tx.prepare("SELECT id FROM nodes WHERE sub_id = ?1")?;
                let rows = stmt.query_map(params![sub_id], |r| r.get::<_, String>(0))?;
                for r in rows {
                    existing_ids.push(r?);
                }
            }

            let mut removed_ids: HashSet<String> = HashSet::new();
            for old_id in existing_ids {
                if !incoming_ids.contains(old_id.as_str()) {
                    tx.execute("DELETE FROM nodes WHERE id = ?1", params![old_id])?;
                    removed_ids.insert(old_id);
                }
            }

            for node in new_nodes {
                upsert_node_with_conn(tx, node)?;
            }

            if !removed_ids.is_empty() {
                let live_node_ids = load_all_node_ids_in_tx(tx)?;
                let empty_remap = HashMap::new();
                remap_multi_groups_in_tx(
                    tx,
                    &empty_remap,
                    &removed_ids,
                    None,
                    None,
                    Some(&live_node_ids),
                )?;
            }

            Ok(new_nodes.len())
        })
    }

    pub fn get_node(&self, id: &str) -> CatResult<Option<ProxyNode>> {
        let mut stmt = self.conn.prepare_cached(
            "
            SELECT id, sub_id, name, protocol, server, port, raw_json,
                   region_code, multiplier, is_443_native, preaccel_eligible,
                   preaccel_override, tags_json, enabled
            FROM nodes
            WHERE id = ?1
            ",
        )?;
        stmt.query_row(params![id], row_to_node)
            .optional()
            .map_err(Into::into)
    }

    pub fn list_nodes(&self) -> CatResult<Vec<ProxyNode>> {
        self.query_nodes(&NodeFilter::default())
    }

    /// Lightweight node projection skipping full `raw_json` / `tags_json` deserialization.
    ///
    /// Extracts only `json_extract(raw_json, '$.ip-version')` (guarded by `json_valid`) and falls
    /// back to `json_extract(raw_json, '$.server')` only when the `server` column is blank,
    /// preserving the exact ordering of [`Self::list_nodes`].
    pub fn list_node_summaries(&self) -> CatResult<Vec<NodeSummary>> {
        let mut stmt = self.conn.prepare_cached(
            "
            SELECT id, sub_id, name, protocol,
                   CASE
                       WHEN TRIM(server) != '' THEN server
                       WHEN json_valid(raw_json) AND typeof(json_extract(raw_json, '$.server')) = 'text'
                           THEN json_extract(raw_json, '$.server')
                       ELSE server
                   END AS server,
                   port, region_code, multiplier, is_443_native, preaccel_eligible,
                   preaccel_override, enabled,
                   CASE
                       WHEN json_valid(raw_json) AND typeof(json_extract(raw_json, '$.ip-version')) = 'text'
                           THEN json_extract(raw_json, '$.ip-version')
                       ELSE NULL
                   END AS raw_ip_version
            FROM nodes
            ORDER BY sub_id ASC, region_code ASC, multiplier ASC, name ASC
            ",
        )?;
        let rows = stmt.query_map([], row_to_node_summary)?;
        let mut summaries = Vec::new();
        for row in rows {
            summaries.push(row?);
        }
        Ok(summaries)
    }

    /// Return all stored node IDs via a covering primary-key index scan without touching `raw_json`.
    pub fn list_node_ids(&self) -> CatResult<Vec<String>> {
        let mut stmt = self.conn.prepare_cached("SELECT id FROM nodes ORDER BY id ASC")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut ids = Vec::new();
        for row in rows {
            ids.push(row?);
        }
        Ok(ids)
    }

    /// Return `true` if at least one enabled node exists (short-circuit `EXISTS` query).
    pub fn has_enabled_nodes(&self) -> CatResult<bool> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT EXISTS(SELECT 1 FROM nodes WHERE enabled != 0)")?;
        let exists: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(exists != 0)
    }

    /// Fetch only the display name of `node_id` without reading or deserializing `raw_json`.
    pub fn get_node_name(&self, node_id: &str) -> CatResult<Option<String>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT name FROM nodes WHERE id = ?1")?;
        stmt.query_row(params![node_id], |row| row.get(0))
            .optional()
            .map_err(Into::into)
    }

    pub fn delete_node(&self, id: &str) -> CatResult<bool> {
        let tx = self.conn.unchecked_transaction()?;
        let changed = tx.execute("DELETE FROM nodes WHERE id = ?1", params![id])?;
        if changed > 0 {
            let empty_remap: HashMap<String, String> = HashMap::new();
            let mut removed_ids: HashSet<String> = HashSet::with_capacity(1);
            removed_ids.insert(id.to_string());
            let live_node_ids = load_all_node_ids_in_tx(&tx)?;
            remap_multi_groups_in_tx(
                &tx,
                &empty_remap,
                &removed_ids,
                None,
                None,
                Some(&live_node_ids),
            )?;
        }
        tx.commit()?;
        Ok(changed > 0)
    }

    /// Multi-dimensional node query supporting subscription source, region, multiplier bounds,
    /// protocol, native 443 flag, Google cleanliness, 60s keep-alive, unlocked sites, tags, and keyword.
    pub fn query_nodes(&self, filter: &NodeFilter) -> CatResult<Vec<ProxyNode>> {
        let mut sql = String::from(
            "SELECT n.id, n.sub_id, n.name, n.protocol, n.server, n.port, n.raw_json,
                    n.region_code, n.multiplier, n.is_443_native, n.preaccel_eligible,
                    n.preaccel_override, n.tags_json, n.enabled
             FROM nodes n
             WHERE 1 = 1",
        );
        let mut values: Vec<rusqlite::types::Value> = Vec::new();

        if let Some(sub_ids) = &filter.sub_ids {
            if !sub_ids.is_empty() {
                let placeholders = make_placeholders(sub_ids.len());
                sql.push_str(&format!(" AND n.sub_id IN ({placeholders})"));
                for id in sub_ids {
                    values.push(rusqlite::types::Value::Text(id.clone()));
                }
            }
        }

        if let Some(regions) = &filter.region_codes {
            if !regions.is_empty() {
                let placeholders = make_placeholders(regions.len());
                sql.push_str(&format!(" AND UPPER(n.region_code) IN ({placeholders})"));
                for reg in regions {
                    values.push(rusqlite::types::Value::Text(reg.trim().to_ascii_uppercase()));
                }
            }
        }

        if let Some(max_mult) = filter.max_multiplier {
            sql.push_str(" AND n.multiplier <= ?");
            values.push(rusqlite::types::Value::Real(max_mult));
        }

        if let Some(min_mult) = filter.min_multiplier {
            sql.push_str(" AND n.multiplier >= ?");
            values.push(rusqlite::types::Value::Real(min_mult));
        }

        if let Some(protocols) = &filter.protocols {
            if !protocols.is_empty() {
                let placeholders = make_placeholders(protocols.len());
                sql.push_str(&format!(" AND LOWER(n.protocol) IN ({placeholders})"));
                for proto in protocols {
                    values.push(rusqlite::types::Value::Text(
                        proto.trim().to_ascii_lowercase(),
                    ));
                }
            }
        }

        if let Some(is_443) = filter.is_443_native {
            sql.push_str(" AND n.is_443_native = ?");
            values.push(rusqlite::types::Value::Integer(bool_to_int(is_443)));
        }

        if let Some(enabled) = filter.enabled_only {
            sql.push_str(" AND n.enabled = ?");
            values.push(rusqlite::types::Value::Integer(bool_to_int(enabled)));
        }

        if filter.google_clean_only {
            sql.push_str(
                " AND (
                    SELECT pr.google_clean
                    FROM probe_results pr
                    WHERE pr.node_id = n.id AND pr.google_clean IS NOT NULL
                    ORDER BY pr.tested_at DESC, pr.id DESC
                    LIMIT 1
                ) = 1",
            );
        }

        if filter.keepalive_60s_ok_only {
            sql.push_str(
                " AND (
                    SELECT pr.keepalive_60s_ok
                    FROM probe_results pr
                    WHERE pr.node_id = n.id AND pr.keepalive_60s_ok IS NOT NULL
                    ORDER BY pr.tested_at DESC, pr.id DESC
                    LIMIT 1
                ) = 1",
            );
        }

        if let Some(kw) = &filter.keyword {
            let trimmed = kw.trim();
            if !trimmed.is_empty() {
                let pattern = format!("%{}%", trimmed.to_ascii_lowercase());
                sql.push_str(
                    " AND (LOWER(n.name) LIKE ? OR LOWER(n.server) LIKE ? OR LOWER(n.tags_json) LIKE ?)",
                );
                values.push(rusqlite::types::Value::Text(pattern.clone()));
                values.push(rusqlite::types::Value::Text(pattern.clone()));
                values.push(rusqlite::types::Value::Text(pattern));
            }
        }

        sql.push_str(" ORDER BY n.sub_id ASC, n.region_code ASC, n.multiplier ASC, n.name ASC");

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(values.iter()), row_to_node)?;
        let mut nodes = Vec::new();
        for row in rows {
            nodes.push(row?);
        }

        // Apply post-SQL exact JSON tag matching if requested
        if let Some(required_tags) = &filter.tags {
            let req_lower: Vec<String> = required_tags
                .iter()
                .map(|t| t.trim().to_ascii_lowercase())
                .filter(|t| !t.is_empty())
                .collect();
            if !req_lower.is_empty() {
                nodes.retain(|node| {
                    let node_tags: HashSet<String> = node
                        .tags
                        .iter()
                        .map(|t| t.trim().to_ascii_lowercase())
                        .collect();
                    req_lower.iter().all(|req| node_tags.contains(req))
                });
            }
        }

        // Apply unlocked site filter using latest per-probe results
        if let Some(site) = &filter.unlocked_site {
            let target = site.trim().to_ascii_lowercase();
            if !target.is_empty() && !nodes.is_empty() {
                let ids: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
                let snaps = self.get_probe_snapshots_batch(&ids, None)?;
                nodes.retain(|node| {
                    snaps.get(&node.id).is_some_and(|snap| {
                        snap.unlocked_sites
                            .iter()
                            .any(|(k, v)| *v && k.eq_ignore_ascii_case(&target))
                    })
                });
            }
        }

        Ok(nodes)
    }

    // -------------------------------------------------------------------------
    // 3. Probe Definitions CRUD
    // -------------------------------------------------------------------------

    pub fn upsert_probe_definition(&self, def: &ProbeDefinition) -> CatResult<()> {
        upsert_probe_definition_with_conn(&self.conn, def)
    }

    /// Seed missing built-in probe definitions and perform narrowly scoped legacy migrations
    /// without overwriting user-customized built-in rows (such as custom `builtin_latency` /
    /// `builtin_upload` / `builtin_download` URLs, methods, or expected statuses).
    pub fn seed_builtin_probes(&mut self) -> CatResult<usize> {
        self.in_transaction(seed_builtin_probes_in_tx)
    }

    pub fn get_probe_definition(&self, id: &str) -> CatResult<Option<ProbeDefinition>> {
        let mut stmt = self.conn.prepare_cached(
            "
            SELECT id, name, kind, target_url, method, expected_status,
                   body_regex, payload_bytes, timeout_ms, builtin
            FROM probe_definitions
            WHERE id = ?1
            ",
        )?;
        stmt.query_row(params![id], row_to_probe_def)
            .optional()
            .map_err(Into::into)
    }

    pub fn list_probe_definitions(&self) -> CatResult<Vec<ProbeDefinition>> {
        let mut stmt = self.conn.prepare_cached(
            "
            SELECT id, name, kind, target_url, method, expected_status,
                   body_regex, payload_bytes, timeout_ms, builtin
            FROM probe_definitions
            ORDER BY builtin DESC, name ASC, id ASC
            ",
        )?;
        let rows = stmt.query_map([], row_to_probe_def)?;
        let mut defs = Vec::new();
        for r in rows {
            defs.push(r?);
        }
        Ok(defs)
    }

    pub fn delete_probe_definition(&self, id: &str) -> CatResult<bool> {
        let changed = self
            .conn
            .execute("DELETE FROM probe_definitions WHERE id = ?1", params![id])?;
        Ok(changed > 0)
    }

    // -------------------------------------------------------------------------
    // 4. Probe Results & Aggregated Snapshots
    // -------------------------------------------------------------------------

    pub fn insert_probe_result(&self, rec: &ProbeResultRecord) -> CatResult<i64> {
        insert_probe_result_with_conn(&self.conn, rec)
    }

    pub fn insert_probe_results_batch(&mut self, records: &[ProbeResultRecord]) -> CatResult<usize> {
        self.in_transaction(|tx| {
            for rec in records {
                insert_probe_result_with_conn(tx, rec)?;
            }
            Ok(records.len())
        })
    }

    /// Return the latest result row per `probe_id` for a given `node_id`.
    pub fn latest_probe_results_for_node(&self, node_id: &str) -> CatResult<Vec<ProbeResultRecord>> {
        let mut stmt = self.conn.prepare_cached(
            "
            SELECT node_id, probe_id, tested_at, ok, latency_ms, jitter_ms, loss_pct,
                   up_mbps, down_mbps, cf_loc, yt_gl, google_clean, keepalive_60s_ok,
                   unlocked_map_json, detail, ip_clean, ip_risk_level, ip_asn, ip_risk_flags
            FROM (
                SELECT *,
                       ROW_NUMBER() OVER (
                           PARTITION BY probe_id
                           ORDER BY tested_at DESC, id DESC
                       ) AS rn
                FROM probe_results
                WHERE node_id = ?1
            )
            WHERE rn = 1
            ORDER BY tested_at DESC, probe_id ASC
            ",
        )?;
        let rows = stmt.query_map(params![node_id], row_to_probe_result)?;
        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    fn load_probe_kind_map(&self) -> CatResult<HashMap<String, ProbeKind>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT id, kind FROM probe_definitions")?;
        let rows = stmt.query_map([], |row| {
            let id: String = row.get(0)?;
            let kind_str: String = row.get(1)?;
            Ok((id, ProbeKind::from_db_str(&kind_str)))
        })?;
        let mut map = HashMap::new();
        for row in rows {
            let (id, kind) = row?;
            map.insert(id, kind);
        }
        Ok(map)
    }

    /// Build an aggregated formula-ready `ProbeSnapshot` from the latest per-probe results.
    pub fn get_probe_snapshot(
        &self,
        node_id: &str,
        primary_probe_id: Option<&str>,
    ) -> CatResult<Option<ProbeSnapshot>> {
        let latest = self.latest_probe_results_for_node(node_id)?;
        if latest.is_empty() {
            return Ok(None);
        }
        let probe_kinds = self.load_probe_kind_map()?;
        Ok(Some(ProbeSnapshot::from_results_with_kinds(
            node_id,
            &latest,
            primary_probe_id,
            &probe_kinds,
        )))
    }

    /// Batch-fetch aggregated snapshots for multiple nodes in a single SQL query.
    pub fn get_probe_snapshots_batch(
        &self,
        node_ids: &[String],
        primary_probe_id: Option<&str>,
    ) -> CatResult<HashMap<String, ProbeSnapshot>> {
        let mut out = HashMap::new();
        if node_ids.is_empty() {
            return Ok(out);
        }
        let probe_kinds = self.load_probe_kind_map()?;
        let placeholders = make_placeholders(node_ids.len());
        let sql = format!(
            "
            SELECT node_id, probe_id, tested_at, ok, latency_ms, jitter_ms, loss_pct,
                   up_mbps, down_mbps, cf_loc, yt_gl, google_clean, keepalive_60s_ok,
                   unlocked_map_json, detail, ip_clean, ip_risk_level, ip_asn, ip_risk_flags
            FROM (
                SELECT *,
                       ROW_NUMBER() OVER (
                           PARTITION BY node_id, probe_id
                           ORDER BY tested_at DESC, id DESC
                       ) AS rn
                FROM probe_results
                WHERE node_id IN ({placeholders})
            )
            WHERE rn = 1
            ORDER BY node_id ASC, tested_at DESC, probe_id ASC
            "
        );

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(node_ids.iter()), row_to_probe_result)?;
        let mut grouped: HashMap<String, Vec<ProbeResultRecord>> = HashMap::new();
        for row in rows {
            let rec = row?;
            grouped.entry(rec.node_id.clone()).or_default().push(rec);
        }

        for (nid, recs) in grouped {
            out.insert(
                nid.clone(),
                ProbeSnapshot::from_results_with_kinds(&nid, &recs, primary_probe_id, &probe_kinds),
            );
        }
        Ok(out)
    }

    /// Keep at most `keep_per_node_probe` latest rows for each `(node_id, probe_id)` pair
    /// to bound database size during continuous probing.
    pub fn prune_old_probe_results(&self, keep_per_node_probe: usize) -> CatResult<usize> {
        if keep_per_node_probe == 0 {
            return Err(CatError::Validation(
                "keep_per_node_probe must be >= 1".into(),
            ));
        }
        let deleted = self.conn.execute(
            "
            DELETE FROM probe_results
            WHERE id IN (
                SELECT id FROM (
                    SELECT id,
                           ROW_NUMBER() OVER (
                               PARTITION BY node_id, probe_id
                               ORDER BY tested_at DESC, id DESC
                           ) AS rn
                    FROM probe_results
                )
                WHERE rn > ?1
            )
            ",
            params![keep_per_node_probe as i64],
        )?;
        Ok(deleted)
    }

    // -------------------------------------------------------------------------
    // 5. Multi-Groups CRUD & Runtime State Persistence
    // -------------------------------------------------------------------------

    pub fn upsert_multi_group(&self, group: &MultiGroup) -> CatResult<()> {
        upsert_multi_group_with_conn(&self.conn, group)
    }

    pub fn get_multi_group(&self, id: &str) -> CatResult<Option<MultiGroup>> {
        let mut stmt = self.conn.prepare_cached(
            "
            SELECT id, name, mode, match_rules_json, member_node_ids_json,
                   dynamic_filter_json, primary_probe_id, hard_gates_json,
                   trigger_rules_json, formula_expr, fallback_policy, fallback_pool_id,
                   escalated_since, recover_probe_interval_sec, switch_mode,
                   cooldown_sec, hysteresis_pct, active_node_id, state,
                   independent_routing
            FROM multi_groups
            WHERE id = ?1
            ",
        )?;
        stmt.query_row(params![id], row_to_multi_group)
            .optional()
            .map_err(Into::into)
    }

    pub fn list_multi_groups(&self) -> CatResult<Vec<MultiGroup>> {
        let mut stmt = self.conn.prepare_cached(
            "
            SELECT id, name, mode, match_rules_json, member_node_ids_json,
                   dynamic_filter_json, primary_probe_id, hard_gates_json,
                   trigger_rules_json, formula_expr, fallback_policy, fallback_pool_id,
                   escalated_since, recover_probe_interval_sec, switch_mode,
                   cooldown_sec, hysteresis_pct, active_node_id, state,
                   independent_routing
            FROM multi_groups
            ORDER BY name ASC, id ASC
            ",
        )?;
        let rows = stmt.query_map([], row_to_multi_group)?;
        let mut groups = Vec::new();
        for r in rows {
            groups.push(r?);
        }
        Ok(groups)
    }

    pub fn delete_multi_group(&self, id: &str) -> CatResult<bool> {
        let tx = self.conn.unchecked_transaction()?;
        let changed = tx.execute("DELETE FROM multi_groups WHERE id = ?1", params![id])?;
        if changed > 0 {
            tx.execute(
                "UPDATE multi_groups SET fallback_pool_id = NULL WHERE fallback_pool_id = ?1",
                params![id],
            )?;
        }
        tx.commit()?;
        Ok(changed > 0)
    }

    /// Update only runtime selection, health state, and cross-pool escalation timestamp.
    pub fn update_multi_group_runtime(
        &self,
        id: &str,
        active_node_id: Option<&str>,
        state: &MultiGroupState,
        escalated_since: Option<&str>,
    ) -> CatResult<bool> {
        let changed = self.conn.execute(
            "
            UPDATE multi_groups
            SET active_node_id = ?2,
                state = ?3,
                escalated_since = ?4
            WHERE id = ?1
            ",
            params![id, active_node_id, state.as_str(), escalated_since],
        )?;
        Ok(changed > 0)
    }

    /// Ensure at least one usable default multi-group exists when enabled nodes are present.
    /// - If no groups exist at all, creates a fresh "默认路线" group containing all enabled nodes.
    /// - If groups exist, never touches them when any group uses `dynamic_filter` or any static
    ///   group still has >= 1 valid enabled member.
    /// - When all existing groups are static and empty (0 valid enabled members), prefers refilling
    ///   a clean static empty group (no custom `match_rules`, `!independent_routing`, no
    ///   `dynamic_filter`, prioritizing names containing "默认路线" or "Default"); only creates a
    ///   new "默认路线" group if every existing empty group has custom rules or independent routing.
    pub fn ensure_default_group_if_empty(&self) -> CatResult<Option<String>> {
        let enabled_nodes: Vec<ProxyNode> = self
            .list_nodes()?
            .into_iter()
            .filter(|n| n.enabled)
            .collect();
        if enabled_nodes.is_empty() {
            return Ok(None);
        }

        let groups = self.list_multi_groups()?;
        let member_node_ids: Vec<String> = enabled_nodes.iter().map(|n| n.id.clone()).collect();
        let enabled_id_set: HashSet<&str> = enabled_nodes.iter().map(|n| n.id.as_str()).collect();
        let snaps = self
            .get_probe_snapshots_batch(&member_node_ids, None)
            .unwrap_or_default();
        let active_node_id = pick_smart_default_node_id(&enabled_nodes, Some(&snaps))
            .or_else(|| member_node_ids.first().cloned());

        if !groups.is_empty() {
            if groups.iter().any(|g| g.dynamic_filter.is_some()) {
                return Ok(None);
            }
            let has_usable_static_member = groups.iter().any(|g| {
                g.member_node_ids
                    .iter()
                    .any(|mid| enabled_id_set.contains(mid.as_str()))
            });
            if has_usable_static_member {
                return Ok(None);
            }

            let is_clean_static_empty = |g: &MultiGroup| {
                g.dynamic_filter.is_none()
                    && !g.independent_routing
                    && g.match_rules.iter().all(|r| r.trim().is_empty())
            };
            let reusable_target = groups
                .iter()
                .find(|g| {
                    is_clean_static_empty(g)
                        && (g.name.contains("默认路线")
                            || g.name.to_ascii_lowercase().contains("default"))
                })
                .or_else(|| groups.iter().find(|g| is_clean_static_empty(g)));

            if let Some(existing) = reusable_target {
                let mut updated = existing.clone();
                updated.member_node_ids = member_node_ids;
                updated.active_node_id = active_node_id;
                self.upsert_multi_group(&updated)?;
                return Ok(Some(updated.id));
            }
        }

        let group = MultiGroup {
            id: format!("grp-{}", uuid::Uuid::new_v4().simple()),
            name: "默认路线".to_string(),
            mode: MultiGroupMode::StickyBest,
            hard_gates: Vec::new(),
            member_node_ids,
            active_node_id,
            ..MultiGroup::default()
        };
        self.upsert_multi_group(&group)?;
        Ok(Some(group.id))
    }

    // -------------------------------------------------------------------------
    // 6. Domestic Pre-Acceleration Relays CRUD
    // -------------------------------------------------------------------------

    pub fn upsert_preaccel_relay(&self, relay: &PreAccelRelay) -> CatResult<()> {
        upsert_preaccel_relay_with_conn(&self.conn, relay)
    }

    pub fn get_preaccel_relay(&self, id: &str) -> CatResult<Option<PreAccelRelay>> {
        let mut stmt = self.conn.prepare_cached(
            "
            SELECT id, name, provider, region, server, port, protocol,
                   password, sni, skip_cert_verify, priority, expires_at,
                   enabled, last_probe_ms, last_mbps, last_up_mbps, last_down_mbps,
                   supports_ipv6
            FROM preaccel_relays
            WHERE id = ?1
            ",
        )?;
        stmt.query_row(params![id], row_to_preaccel_relay)
            .optional()
            .map_err(Into::into)
    }

    pub fn list_preaccel_relays(&self, enabled_only: bool) -> CatResult<Vec<PreAccelRelay>> {
        let sql = if enabled_only {
            "
            SELECT id, name, provider, region, server, port, protocol,
                   password, sni, skip_cert_verify, priority, expires_at,
                   enabled, last_probe_ms, last_mbps, last_up_mbps, last_down_mbps,
                   supports_ipv6
            FROM preaccel_relays
            WHERE enabled = 1
            ORDER BY priority ASC, id ASC
            "
        } else {
            "
            SELECT id, name, provider, region, server, port, protocol,
                   password, sni, skip_cert_verify, priority, expires_at,
                   enabled, last_probe_ms, last_mbps, last_up_mbps, last_down_mbps,
                   supports_ipv6
            FROM preaccel_relays
            ORDER BY priority ASC, id ASC
            "
        };
        let mut stmt = self.conn.prepare_cached(sql)?;
        let rows = stmt.query_map([], row_to_preaccel_relay)?;
        let mut relays = Vec::new();
        for r in rows {
            relays.push(r?);
        }
        Ok(relays)
    }

    pub fn delete_preaccel_relay(&self, id: &str) -> CatResult<bool> {
        let changed = self
            .conn
            .execute("DELETE FROM preaccel_relays WHERE id = ?1", params![id])?;
        Ok(changed > 0)
    }

    pub fn update_preaccel_probe_metrics(
        &self,
        id: &str,
        last_probe_ms: Option<f64>,
        last_mbps: Option<f64>,
    ) -> CatResult<bool> {
        let changed = self.conn.execute(
            "
            UPDATE preaccel_relays
            SET last_probe_ms = ?2,
                last_mbps = ?3
            WHERE id = ?1
            ",
            params![id, last_probe_ms, last_mbps],
        )?;
        Ok(changed > 0)
    }

    pub fn update_preaccel_speed_metrics(
        &self,
        id: &str,
        last_probe_ms: Option<f64>,
        last_up_mbps: Option<f64>,
        last_down_mbps: Option<f64>,
    ) -> CatResult<bool> {
        let changed = self.conn.execute(
            "
            UPDATE preaccel_relays
            SET last_probe_ms = COALESCE(?2, last_probe_ms),
                last_up_mbps = COALESCE(?3, last_up_mbps),
                last_down_mbps = COALESCE(?4, last_down_mbps),
                last_mbps = COALESCE(?3, last_mbps)
            WHERE id = ?1
            ",
            params![id, last_probe_ms, last_up_mbps, last_down_mbps],
        )?;
        Ok(changed > 0)
    }

    // -------------------------------------------------------------------------
    // 7. Atomic Backup Snapshot & Transactional Restore / Rollback
    // -------------------------------------------------------------------------

    /// Capture a consistent snapshot of `multi_groups`, `preaccel_relays`, and
    /// `probe_definitions` before mutating SQLite during backup restore.
    pub fn capture_backup_db_snapshot(&self) -> CatResult<BackupDbSnapshot> {
        Ok(BackupDbSnapshot {
            groups: self.list_multi_groups()?,
            relays: self.list_preaccel_relays(false)?,
            probes: self.list_probe_definitions()?,
        })
    }

    /// Atomically apply `groups`, `relays`, and `probes` inside a single SQLite transaction.
    ///
    /// - Any validation or SQL failure rolls back the entire transaction cleanly.
    /// - When `replace_all == true` (e.g. rolling back to a prior [`BackupDbSnapshot`]), all
    ///   target rows are upserted in place and only extra rows whose IDs are absent from the
    ///   snapshot are deleted, preserving `probe_results` foreign-key references for surviving
    ///   `probe_definitions` (never cascading a full wipe).
    /// - When `replace_all == false` and `!probes.is_empty()`, legacy built-in probe migrations
    ///   run inside the same transaction so old backups never leave broken built-in rows.
    pub fn apply_backup_entities_atomic(
        &mut self,
        groups: &[MultiGroup],
        relays: &[PreAccelRelay],
        probes: &[ProbeDefinition],
        replace_all: bool,
    ) -> CatResult<()> {
        self.in_transaction(|tx| {
            for group in groups {
                upsert_multi_group_with_conn(tx, group)?;
            }
            for relay in relays {
                upsert_preaccel_relay_with_conn(tx, relay)?;
            }
            for probe in probes {
                upsert_probe_definition_with_conn(tx, probe)?;
            }

            if replace_all {
                let keep_groups: HashSet<&str> = groups.iter().map(|g| g.id.as_str()).collect();
                let keep_relays: HashSet<&str> = relays.iter().map(|r| r.id.as_str()).collect();
                let keep_probes: HashSet<&str> = probes.iter().map(|p| p.id.as_str()).collect();

                delete_ids_not_in_tx(tx, "multi_groups", &keep_groups)?;
                delete_ids_not_in_tx(tx, "preaccel_relays", &keep_relays)?;
                delete_ids_not_in_tx(tx, "probe_definitions", &keep_probes)?;
            } else if !probes.is_empty() {
                seed_builtin_probes_in_tx(tx)?;
            }

            Ok(())
        })
    }
}

// -----------------------------------------------------------------------------
// Schema DDL
// -----------------------------------------------------------------------------

const SCHEMA_V1_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS subscriptions (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    url_or_cmd TEXT NOT NULL,
    refresh_interval_sec INTEGER NOT NULL DEFAULT 3600,
    traffic_used INTEGER NOT NULL DEFAULT 0,
    traffic_total INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT,
    etag TEXT,
    last_ok_at TEXT,
    last_error TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY NOT NULL,
    sub_id TEXT NOT NULL,
    name TEXT NOT NULL,
    protocol TEXT NOT NULL,
    server TEXT NOT NULL,
    port INTEGER NOT NULL,
    raw_json TEXT NOT NULL,
    region_code TEXT NOT NULL DEFAULT 'UNK',
    multiplier REAL NOT NULL DEFAULT 1.0,
    is_443_native INTEGER NOT NULL DEFAULT 0,
    preaccel_eligible INTEGER NOT NULL DEFAULT 1,
    preaccel_override INTEGER,
    tags_json TEXT NOT NULL DEFAULT '[]',
    enabled INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    FOREIGN KEY (sub_id) REFERENCES subscriptions(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_nodes_sub_id ON nodes(sub_id);
CREATE INDEX IF NOT EXISTS idx_nodes_region ON nodes(region_code);
CREATE INDEX IF NOT EXISTS idx_nodes_protocol ON nodes(protocol);
CREATE INDEX IF NOT EXISTS idx_nodes_multiplier ON nodes(multiplier);
CREATE INDEX IF NOT EXISTS idx_nodes_443 ON nodes(is_443_native);

CREATE TABLE IF NOT EXISTS probe_definitions (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    target_url TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT 'GET',
    expected_status INTEGER,
    body_regex TEXT,
    payload_bytes INTEGER,
    timeout_ms INTEGER NOT NULL DEFAULT 8000,
    builtin INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS probe_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT NOT NULL,
    probe_id TEXT NOT NULL,
    tested_at TEXT NOT NULL,
    ok INTEGER NOT NULL DEFAULT 0,
    latency_ms REAL,
    jitter_ms REAL,
    loss_pct REAL,
    up_mbps REAL,
    down_mbps REAL,
    cf_loc TEXT,
    yt_gl TEXT,
    google_clean INTEGER,
    keepalive_60s_ok INTEGER,
    unlocked_map_json TEXT NOT NULL DEFAULT '{}',
    detail TEXT,
    ip_clean INTEGER,
    ip_risk_level TEXT,
    ip_asn TEXT,
    ip_risk_flags TEXT,
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
    FOREIGN KEY (probe_id) REFERENCES probe_definitions(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_probe_results_node_probe_time
    ON probe_results(node_id, probe_id, tested_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_probe_results_node_time
    ON probe_results(node_id, tested_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS multi_groups (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    mode TEXT NOT NULL,
    match_rules_json TEXT NOT NULL DEFAULT '[]',
    member_node_ids_json TEXT NOT NULL DEFAULT '[]',
    dynamic_filter_json TEXT,
    primary_probe_id TEXT,
    hard_gates_json TEXT NOT NULL DEFAULT '[]',
    trigger_rules_json TEXT NOT NULL DEFAULT '[]',
    formula_expr TEXT NOT NULL,
    fallback_policy TEXT NOT NULL,
    fallback_pool_id TEXT,
    escalated_since TEXT,
    recover_probe_interval_sec INTEGER NOT NULL DEFAULT 120,
    switch_mode TEXT NOT NULL,
    cooldown_sec INTEGER NOT NULL DEFAULT 60,
    hysteresis_pct REAL NOT NULL DEFAULT 20.0,
    active_node_id TEXT,
    state TEXT NOT NULL DEFAULT 'idle',
    independent_routing INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS preaccel_relays (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    provider TEXT NOT NULL DEFAULT '',
    region TEXT NOT NULL DEFAULT '',
    server TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 443,
    protocol TEXT NOT NULL,
    password TEXT NOT NULL DEFAULT '',
    sni TEXT,
    skip_cert_verify INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL DEFAULT 100,
    expires_at TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_probe_ms REAL,
    last_mbps REAL,
    last_up_mbps REAL,
    last_down_mbps REAL,
    supports_ipv6 INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_preaccel_priority ON preaccel_relays(enabled, priority ASC);
"#;

// -----------------------------------------------------------------------------
// Row Mappers & Low-Level Helpers
// -----------------------------------------------------------------------------

fn upsert_node_with_conn(conn: &Connection, node: &ProxyNode) -> CatResult<()> {
    if node.id.trim().is_empty() {
        return Err(CatError::Validation("node id cannot be empty".into()));
    }
    if node.sub_id.trim().is_empty() {
        return Err(CatError::Validation("node sub_id cannot be empty".into()));
    }
    let raw_json = serde_json::to_string(&node.raw_config)?;
    let tags_json = serde_json::to_string(&node.tags)?;
    conn.execute(
        "
        INSERT INTO nodes (
            id, sub_id, name, protocol, server, port, raw_json,
            region_code, multiplier, is_443_native, preaccel_eligible,
            preaccel_override, tags_json, enabled, updated_at
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7,
            ?8, ?9, ?10, ?11, ?12, ?13, ?14,
            strftime('%Y-%m-%dT%H:%M:%fZ','now')
        )
        ON CONFLICT(id) DO UPDATE SET
            sub_id = excluded.sub_id,
            name = excluded.name,
            protocol = excluded.protocol,
            server = excluded.server,
            port = excluded.port,
            raw_json = excluded.raw_json,
            region_code = excluded.region_code,
            multiplier = excluded.multiplier,
            is_443_native = excluded.is_443_native,
            preaccel_eligible = excluded.preaccel_eligible,
            preaccel_override = excluded.preaccel_override,
            tags_json = excluded.tags_json,
            enabled = excluded.enabled,
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
        ",
        params![
            node.id,
            node.sub_id,
            node.name,
            node.protocol,
            node.server,
            i64::from(node.port),
            raw_json,
            node.region_code,
            node.multiplier,
            bool_to_int(node.is_443_native),
            bool_to_int(node.preaccel_eligible),
            node.preaccel_override.map(bool_to_int),
            tags_json,
            bool_to_int(node.enabled),
        ],
    )?;
    Ok(())
}

fn upsert_probe_definition_with_conn(conn: &Connection, def: &ProbeDefinition) -> CatResult<()> {
    if def.id.trim().is_empty() {
        return Err(CatError::Validation(
            "probe definition id cannot be empty".into(),
        ));
    }
    conn.execute(
        "
        INSERT INTO probe_definitions (
            id, name, kind, target_url, method, expected_status,
            body_regex, payload_bytes, timeout_ms, builtin
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        ON CONFLICT(id) DO UPDATE SET
            name = excluded.name,
            kind = excluded.kind,
            target_url = excluded.target_url,
            method = excluded.method,
            expected_status = excluded.expected_status,
            body_regex = excluded.body_regex,
            payload_bytes = excluded.payload_bytes,
            timeout_ms = excluded.timeout_ms,
            builtin = excluded.builtin
        ",
        params![
            def.id,
            def.name,
            def.kind.as_str(),
            def.target_url,
            def.method,
            def.expected_status.map(i64::from),
            def.body_regex,
            def.payload_bytes.map(|v| v as i64),
            def.timeout_ms as i64,
            bool_to_int(def.builtin),
        ],
    )?;
    Ok(())
}

fn upsert_multi_group_with_conn(conn: &Connection, group: &MultiGroup) -> CatResult<()> {
    if group.id.trim().is_empty() {
        return Err(CatError::Validation("multi_group id cannot be empty".into()));
    }
    let match_rules_json = serde_json::to_string(&group.match_rules)?;
    let member_node_ids_json = serde_json::to_string(&group.member_node_ids)?;
    let dynamic_filter_json = group
        .dynamic_filter
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;
    let hard_gates_json = serde_json::to_string(&group.hard_gates)?;
    let trigger_rules_json = serde_json::to_string(&group.trigger_rules)?;

    conn.execute(
        "
        INSERT INTO multi_groups (
            id, name, mode, match_rules_json, member_node_ids_json,
            dynamic_filter_json, primary_probe_id, hard_gates_json,
            trigger_rules_json, formula_expr, fallback_policy, fallback_pool_id,
            escalated_since, recover_probe_interval_sec, switch_mode,
            cooldown_sec, hysteresis_pct, active_node_id, state,
            independent_routing
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
            ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20
        )
        ON CONFLICT(id) DO UPDATE SET
            name = excluded.name,
            mode = excluded.mode,
            match_rules_json = excluded.match_rules_json,
            member_node_ids_json = excluded.member_node_ids_json,
            dynamic_filter_json = excluded.dynamic_filter_json,
            primary_probe_id = excluded.primary_probe_id,
            hard_gates_json = excluded.hard_gates_json,
            trigger_rules_json = excluded.trigger_rules_json,
            formula_expr = excluded.formula_expr,
            fallback_policy = excluded.fallback_policy,
            fallback_pool_id = excluded.fallback_pool_id,
            escalated_since = excluded.escalated_since,
            recover_probe_interval_sec = excluded.recover_probe_interval_sec,
            switch_mode = excluded.switch_mode,
            cooldown_sec = excluded.cooldown_sec,
            hysteresis_pct = excluded.hysteresis_pct,
            active_node_id = excluded.active_node_id,
            state = excluded.state,
            independent_routing = excluded.independent_routing
        ",
        params![
            group.id,
            group.name,
            group.mode.as_str(),
            match_rules_json,
            member_node_ids_json,
            dynamic_filter_json,
            group.primary_probe_id,
            hard_gates_json,
            trigger_rules_json,
            group.formula_expr,
            group.fallback_policy.as_str(),
            group.fallback_pool_id,
            group.escalated_since,
            group.recover_probe_interval_sec as i64,
            group.switch_mode.as_str(),
            group.cooldown_sec as i64,
            group.hysteresis_pct,
            group.active_node_id,
            group.state.as_str(),
            bool_to_int(group.independent_routing),
        ],
    )?;
    Ok(())
}

fn upsert_preaccel_relay_with_conn(conn: &Connection, relay: &PreAccelRelay) -> CatResult<()> {
    if relay.id.trim().is_empty() {
        return Err(CatError::Validation(
            "preaccel_relay id cannot be empty".into(),
        ));
    }
    conn.execute(
        "
        INSERT INTO preaccel_relays (
            id, name, provider, region, server, port, protocol,
            password, sni, skip_cert_verify, priority, expires_at,
            enabled, last_probe_ms, last_mbps, last_up_mbps, last_down_mbps, supports_ipv6
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
        ON CONFLICT(id) DO UPDATE SET
            name = excluded.name,
            provider = excluded.provider,
            region = excluded.region,
            server = excluded.server,
            port = excluded.port,
            protocol = excluded.protocol,
            password = excluded.password,
            sni = excluded.sni,
            skip_cert_verify = excluded.skip_cert_verify,
            priority = excluded.priority,
            expires_at = excluded.expires_at,
            enabled = excluded.enabled,
            last_probe_ms = excluded.last_probe_ms,
            last_mbps = excluded.last_mbps,
            last_up_mbps = excluded.last_up_mbps,
            last_down_mbps = excluded.last_down_mbps,
            supports_ipv6 = excluded.supports_ipv6
        ",
        params![
            relay.id,
            relay.name,
            relay.provider,
            relay.region,
            relay.server,
            i64::from(relay.port),
            relay.protocol,
            relay.password,
            relay.sni,
            bool_to_int(relay.skip_cert_verify),
            relay.priority,
            relay.expires_at,
            bool_to_int(relay.enabled),
            relay.last_probe_ms,
            relay.last_mbps,
            relay.last_up_mbps,
            relay.last_down_mbps,
            bool_to_int(relay.supports_ipv6),
        ],
    )?;
    Ok(())
}

fn delete_ids_not_in_tx(
    tx: &Transaction<'_>,
    table: &str,
    keep_ids: &HashSet<&str>,
) -> CatResult<()> {
    let mut existing_ids: Vec<String> = Vec::new();
    {
        let mut stmt = tx.prepare(&format!("SELECT id FROM {table}"))?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        for row in rows {
            existing_ids.push(row?);
        }
    }
    for id in existing_ids {
        if !keep_ids.contains(id.as_str()) {
            tx.execute(&format!("DELETE FROM {table} WHERE id = ?1"), params![id])?;
        }
    }
    Ok(())
}

fn seed_builtin_probes_in_tx(tx: &Transaction<'_>) -> CatResult<usize> {
    let builtins = ProbeDefinition::builtin_defaults();
    let mut inserted = 0usize;
    for def in &builtins {
        let changed = tx.execute(
            "
            INSERT OR IGNORE INTO probe_definitions (
                id, name, kind, target_url, method, expected_status,
                body_regex, payload_bytes, timeout_ms, builtin
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            ",
            params![
                def.id,
                def.name,
                def.kind.as_str(),
                def.target_url,
                def.method,
                def.expected_status.map(i64::from),
                def.body_regex,
                def.payload_bytes.map(|v| v as i64),
                def.timeout_ms as i64,
                bool_to_int(def.builtin),
            ],
        )?;
        if changed == 0 {
            match def.id.as_str() {
                // Narrowly migrate known historical default URLs/methods/statuses for built-in AI
                // unlock probes, never overwriting user-customized endpoints.
                "builtin_unlock_claude" => {
                    tx.execute(
                        "
                        UPDATE probe_definitions
                        SET kind = ?2,
                            expected_status = NULL,
                            target_url = ?3,
                            method = ?4
                        WHERE id = ?1
                          AND builtin = 1
                          AND (body_regex IS NULL OR TRIM(body_regex) = '')
                          AND (
                              target_url IN ('https://claude.ai/', 'https://claude.ai')
                              OR (
                                  target_url = ?3
                                  AND (kind != ?2 OR expected_status IS NOT NULL OR method != ?4)
                              )
                          )
                        ",
                        params![def.id, def.kind.as_str(), def.target_url, def.method],
                    )?;
                }
                "builtin_unlock_chatgpt" => {
                    tx.execute(
                        "
                        UPDATE probe_definitions
                        SET kind = ?2,
                            expected_status = NULL,
                            target_url = ?3,
                            method = ?4
                        WHERE id = ?1
                          AND builtin = 1
                          AND (body_regex IS NULL OR TRIM(body_regex) = '')
                          AND (
                              target_url IN (
                                  'https://chatgpt.com/',
                                  'https://chatgpt.com',
                                  'https://chat.openai.com/',
                                  'https://chat.openai.com'
                              )
                              OR (
                                  target_url = ?3
                                  AND (kind != ?2 OR expected_status IS NOT NULL OR method != ?4)
                              )
                          )
                        ",
                        params![def.id, def.kind.as_str(), def.target_url, def.method],
                    )?;
                }
                "builtin_unlock_gemini" => {
                    tx.execute(
                        "
                        UPDATE probe_definitions
                        SET kind = ?2,
                            expected_status = NULL,
                            target_url = ?3,
                            method = ?4
                        WHERE id = ?1
                          AND builtin = 1
                          AND (body_regex IS NULL OR TRIM(body_regex) = '')
                          AND (
                              target_url IN ('https://gemini.google.com/', 'https://gemini.google.com')
                              OR (
                                  target_url = ?3
                                  AND (kind != ?2 OR expected_status IS NOT NULL OR method != ?4)
                              )
                          )
                        ",
                        params![def.id, def.kind.as_str(), def.target_url, def.method],
                    )?;
                }
                // Losslessly upgrade legacy default `builtin_unlock_windsurf` definitions to the
                // semantic Codeium API + dual-source IP purity probe without clobbering user
                // customizations (`body_regex` or custom `target_url`).
                "builtin_unlock_windsurf" => {
                    tx.execute(
                        "
                        UPDATE probe_definitions
                        SET name = ?2,
                            kind = ?3,
                            expected_status = NULL,
                            target_url = ?4,
                            method = ?5,
                            timeout_ms = CASE WHEN timeout_ms < ?6 THEN ?6 ELSE timeout_ms END
                        WHERE id = ?1
                          AND builtin = 1
                          AND (body_regex IS NULL OR TRIM(body_regex) = '')
                          AND (
                              target_url IN (
                                  'https://windsurf.com',
                                  'https://windsurf.com/',
                                  'https://codeium.com',
                                  'https://codeium.com/'
                              )
                              OR (
                                  target_url = ?4
                                  AND (kind != ?3 OR expected_status IS NOT NULL OR method != ?5)
                              )
                          )
                        ",
                        params![
                            def.id,
                            def.name,
                            def.kind.as_str(),
                            def.target_url,
                            def.method,
                            def.timeout_ms as i64,
                        ],
                    )?;
                }
                _ => {}
            }
        }
        inserted += changed;
    }
    Ok(inserted)
}

/// Normalize parseable RFC 3339 timestamps into fixed-width UTC microsecond strings
/// (`YYYY-MM-DDTHH:MM:SS.ffffffZ`) so SQLite `ORDER BY tested_at DESC` lexicographical
/// ordering is 100% isomorphic to UTC instant ordering across mixed timezones/precisions.
fn normalize_tested_at_for_storage(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(trimmed) {
        dt.with_timezone(&chrono::Utc)
            .to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
    } else {
        raw.to_string()
    }
}

fn insert_probe_result_with_conn(conn: &Connection, rec: &ProbeResultRecord) -> CatResult<i64> {
    let unlocked_map_json = serde_json::to_string(&rec.unlocked_map)?;
    let normalized_tested_at = normalize_tested_at_for_storage(&rec.tested_at);
    conn.execute(
        "
        INSERT INTO probe_results (
            node_id, probe_id, tested_at, ok, latency_ms, jitter_ms, loss_pct,
            up_mbps, down_mbps, cf_loc, yt_gl, google_clean, keepalive_60s_ok,
            unlocked_map_json, detail, ip_clean, ip_risk_level, ip_asn, ip_risk_flags
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)
        ",
        params![
            rec.node_id,
            rec.probe_id,
            normalized_tested_at,
            bool_to_int(rec.ok),
            rec.latency_ms,
            rec.jitter_ms,
            rec.loss_pct,
            rec.up_mbps,
            rec.down_mbps,
            rec.cf_loc,
            rec.yt_gl,
            rec.google_clean.map(bool_to_int),
            rec.keepalive_60s_ok.map(bool_to_int),
            unlocked_map_json,
            rec.detail,
            rec.ip_clean.map(bool_to_int),
            rec.ip_risk_level,
            rec.ip_asn,
            rec.ip_risk_flags,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

fn row_to_subscription(row: &Row<'_>) -> rusqlite::Result<SubscriptionRecord> {
    let kind_str: String = row.get(2)?;
    let refresh_interval: i64 = row.get(4)?;
    let used: i64 = row.get(5)?;
    let total: i64 = row.get(6)?;
    let enabled: i64 = row.get(11)?;
    Ok(SubscriptionRecord {
        id: row.get(0)?,
        name: row.get(1)?,
        kind: SubscriptionKind::from_db_str(&kind_str),
        url_or_cmd: row.get(3)?,
        refresh_interval_sec: refresh_interval.max(0) as u64,
        traffic_used_bytes: used.max(0) as u64,
        traffic_total_bytes: total.max(0) as u64,
        expires_at: row.get(7)?,
        etag: row.get(8)?,
        last_ok_at: row.get(9)?,
        last_error: row.get(10)?,
        enabled: enabled != 0,
    })
}

fn row_to_node(row: &Row<'_>) -> rusqlite::Result<ProxyNode> {
    let port_i64: i64 = row.get(5)?;
    let raw_json_str: String = row.get(6)?;
    let raw_config: serde_json::Value =
        serde_json::from_str(&raw_json_str).unwrap_or_else(|_| serde_json::json!({}));
    let is_443: i64 = row.get(9)?;
    let preaccel_eligible: i64 = row.get(10)?;
    let preaccel_override: Option<i64> = row.get(11)?;
    let tags_str: String = row.get(12)?;
    let tags: Vec<String> = serde_json::from_str(&tags_str).unwrap_or_default();
    let enabled: i64 = row.get(13)?;

    Ok(ProxyNode {
        id: row.get(0)?,
        sub_id: row.get(1)?,
        name: row.get(2)?,
        protocol: row.get(3)?,
        server: row.get(4)?,
        port: u16::try_from(port_i64).unwrap_or(0),
        raw_config,
        region_code: row.get(7)?,
        multiplier: row.get(8)?,
        is_443_native: is_443 != 0,
        preaccel_eligible: preaccel_eligible != 0,
        preaccel_override: preaccel_override.map(|v| v != 0),
        tags,
        enabled: enabled != 0,
    })
}

fn row_to_node_summary(row: &Row<'_>) -> rusqlite::Result<NodeSummary> {
    let port_i64: i64 = row.get(5)?;
    let is_443: i64 = row.get(8)?;
    let preaccel_eligible: i64 = row.get(9)?;
    let preaccel_override: Option<i64> = row.get(10)?;
    let enabled: i64 = row.get(11)?;

    Ok(NodeSummary {
        id: row.get(0)?,
        sub_id: row.get(1)?,
        name: row.get(2)?,
        protocol: row.get(3)?,
        server: row.get(4)?,
        port: u16::try_from(port_i64).unwrap_or(0),
        region_code: row.get(6)?,
        multiplier: row.get(7)?,
        is_443_native: is_443 != 0,
        preaccel_eligible: preaccel_eligible != 0,
        preaccel_override: preaccel_override.map(|v| v != 0),
        enabled: enabled != 0,
        raw_ip_version: row.get(12)?,
    })
}

fn row_to_probe_def(row: &Row<'_>) -> rusqlite::Result<ProbeDefinition> {
    let kind_str: String = row.get(2)?;
    let expected_status: Option<i64> = row.get(5)?;
    let payload_bytes: Option<i64> = row.get(7)?;
    let timeout_ms: i64 = row.get(8)?;
    let builtin: i64 = row.get(9)?;
    Ok(ProbeDefinition {
        id: row.get(0)?,
        name: row.get(1)?,
        kind: ProbeKind::from_db_str(&kind_str),
        target_url: row.get(3)?,
        method: row.get(4)?,
        expected_status: expected_status.and_then(|v| u16::try_from(v).ok()),
        body_regex: row.get(6)?,
        payload_bytes: payload_bytes.map(|v| v.max(0) as u64),
        timeout_ms: timeout_ms.max(0) as u64,
        builtin: builtin != 0,
    })
}

fn row_to_probe_result(row: &Row<'_>) -> rusqlite::Result<ProbeResultRecord> {
    let ok: i64 = row.get(3)?;
    let google_clean: Option<i64> = row.get(11)?;
    let keepalive: Option<i64> = row.get(12)?;
    let unlocked_json: String = row.get(13)?;
    let unlocked_map: HashMap<String, bool> =
        serde_json::from_str(&unlocked_json).unwrap_or_default();
    let ip_clean: Option<i64> = row.get(15)?;

    Ok(ProbeResultRecord {
        node_id: row.get(0)?,
        probe_id: row.get(1)?,
        tested_at: row.get(2)?,
        ok: ok != 0,
        latency_ms: row.get(4)?,
        jitter_ms: row.get(5)?,
        loss_pct: row.get(6)?,
        up_mbps: row.get(7)?,
        down_mbps: row.get(8)?,
        cf_loc: row.get(9)?,
        yt_gl: row.get(10)?,
        google_clean: google_clean.map(|v| v != 0),
        keepalive_60s_ok: keepalive.map(|v| v != 0),
        unlocked_map,
        detail: row.get(14)?,
        ip_clean: ip_clean.map(|v| v != 0),
        ip_risk_level: row.get(16)?,
        ip_asn: row.get(17)?,
        ip_risk_flags: row.get(18)?,
    })
}

fn row_to_multi_group(row: &Row<'_>) -> rusqlite::Result<MultiGroup> {
    let mode_str: String = row.get(2)?;
    let match_rules_str: String = row.get(3)?;
    let member_ids_str: String = row.get(4)?;
    let dynamic_filter_str: Option<String> = row.get(5)?;
    let hard_gates_str: String = row.get(7)?;
    let trigger_rules_str: String = row.get(8)?;
    let fallback_str: String = row.get(10)?;
    let recover_sec: i64 = row.get(13)?;
    let switch_str: String = row.get(14)?;
    let cooldown_sec: i64 = row.get(15)?;
    let state_str: String = row.get(18)?;
    let independent_routing: i64 = row.get(19)?;

    let dynamic_filter: Option<DynamicFilterSpec> = dynamic_filter_str
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok());
    let trigger_rules: Vec<TriggerRule> =
        serde_json::from_str(&trigger_rules_str).unwrap_or_default();

    Ok(MultiGroup {
        id: row.get(0)?,
        name: row.get(1)?,
        mode: MultiGroupMode::from_db_str(&mode_str),
        match_rules: serde_json::from_str(&match_rules_str).unwrap_or_default(),
        member_node_ids: serde_json::from_str(&member_ids_str).unwrap_or_default(),
        dynamic_filter,
        primary_probe_id: row.get(6)?,
        hard_gates: serde_json::from_str(&hard_gates_str).unwrap_or_default(),
        trigger_rules,
        formula_expr: row.get(9)?,
        fallback_policy: FallbackPolicy::from_db_str(&fallback_str),
        fallback_pool_id: row.get(11)?,
        escalated_since: row.get(12)?,
        recover_probe_interval_sec: recover_sec.max(0) as u64,
        switch_mode: SwitchMode::from_db_str(&switch_str),
        cooldown_sec: cooldown_sec.max(0) as u64,
        hysteresis_pct: row.get(16)?,
        active_node_id: row.get(17)?,
        state: MultiGroupState::from_db_str(&state_str),
        independent_routing: independent_routing != 0,
    })
}

fn ensure_column_exists(
    tx: &Transaction<'_>,
    table: &str,
    column: &str,
    col_def: &str,
) -> CatResult<()> {
    let mut stmt = tx.prepare(&format!("PRAGMA table_info({table});"))?;
    let mut rows = stmt.query([])?;
    let mut exists = false;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name.eq_ignore_ascii_case(column) {
            exists = true;
            break;
        }
    }
    drop(rows);
    drop(stmt);
    if !exists {
        tx.execute(
            &format!("ALTER TABLE {table} ADD COLUMN {column} {col_def};"),
            [],
        )?;
    }
    Ok(())
}

fn row_to_preaccel_relay(row: &Row<'_>) -> rusqlite::Result<PreAccelRelay> {
    let port_i64: i64 = row.get(5)?;
    let skip_cert: i64 = row.get(9)?;
    let enabled: i64 = row.get(12)?;
    let supports_ipv6: i64 = row.get(17)?;
    Ok(PreAccelRelay {
        id: row.get(0)?,
        name: row.get(1)?,
        provider: row.get(2)?,
        region: row.get(3)?,
        server: row.get(4)?,
        port: u16::try_from(port_i64).unwrap_or(443),
        protocol: row.get(6)?,
        password: row.get(7)?,
        sni: row.get(8)?,
        skip_cert_verify: skip_cert != 0,
        priority: row.get(10)?,
        expires_at: row.get(11)?,
        enabled: enabled != 0,
        last_probe_ms: row.get(13)?,
        last_mbps: row.get(14)?,
        last_up_mbps: row.get(15)?,
        last_down_mbps: row.get(16)?,
        supports_ipv6: supports_ipv6 != 0,
    })
}

fn bool_to_int(v: bool) -> i64 {
    if v { 1 } else { 0 }
}

fn subscription_exists_in_tx(tx: &Transaction<'_>, sub_id: &str) -> CatResult<bool> {
    let exists: Option<i64> = tx
        .query_row(
            "SELECT 1 FROM subscriptions WHERE id = ?1",
            params![sub_id],
            |r| r.get(0),
        )
        .optional()?;
    Ok(exists.is_some())
}

fn load_nodes_for_subscription_in_tx(
    tx: &Transaction<'_>,
    sub_id: &str,
) -> CatResult<Vec<ProxyNode>> {
    let mut stmt = tx.prepare(
        "
        SELECT id, sub_id, name, protocol, server, port, raw_json,
               region_code, multiplier, is_443_native, preaccel_eligible,
               preaccel_override, tags_json, enabled
        FROM nodes
        WHERE sub_id = ?1
        ORDER BY id ASC
        ",
    )?;
    let rows = stmt.query_map(params![sub_id], row_to_node)?;
    let mut nodes = Vec::new();
    for row in rows {
        nodes.push(row?);
    }
    Ok(nodes)
}

fn load_foreign_node_ids_in_tx(
    tx: &Transaction<'_>,
    sub_id: &str,
) -> CatResult<HashSet<String>> {
    let mut stmt = tx.prepare("SELECT id FROM nodes WHERE sub_id != ?1")?;
    let rows = stmt.query_map(params![sub_id], |r| r.get::<_, String>(0))?;
    let mut ids = HashSet::new();
    for row in rows {
        ids.insert(row?);
    }
    Ok(ids)
}

fn allocate_unique_node_id(
    target_sub_id: &str,
    fingerprint: &str,
    occupied_ids: &mut HashSet<String>,
) -> String {
    let mut attempt = 0u32;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(target_sub_id.as_bytes());
        hasher.update(b"\x1f");
        hasher.update(fingerprint.as_bytes());
        if attempt > 0 {
            hasher.update(b"\x1f");
            hasher.update(attempt.to_string().as_bytes());
        }
        let digest = hex::encode(hasher.finalize());
        let candidate = format!("node_{}", &digest[..16]);
        if occupied_ids.insert(candidate.clone()) {
            return candidate;
        }
        attempt = attempt.saturating_add(1);
    }
}

/// Migrate latest per-probe `probe_results` rows from `from_node_id` to `to_node_id`
/// whenever `to_node_id` lacks a result for that `probe_id` or `from_node_id`'s latest
/// `tested_at` timestamp is strictly newer.
fn migrate_newer_probe_results_in_tx(
    tx: &Transaction<'_>,
    from_node_id: &str,
    to_node_id: &str,
) -> CatResult<()> {
    if from_node_id == to_node_id {
        return Ok(());
    }

    let mut latest_from: Vec<(i64, String, String)> = Vec::new();
    {
        let mut stmt = tx.prepare(
            "
            SELECT id, probe_id, tested_at
            FROM (
                SELECT id, probe_id, tested_at,
                       ROW_NUMBER() OVER (
                           PARTITION BY probe_id
                           ORDER BY tested_at DESC, id DESC
                       ) AS rn
                FROM probe_results
                WHERE node_id = ?1
            )
            WHERE rn = 1
            ",
        )?;
        let rows = stmt.query_map(params![from_node_id], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            latest_from.push(row?);
        }
    }

    for (from_row_id, probe_id, from_tested_at) in latest_from {
        let to_latest_tested_at: Option<String> = tx
            .query_row(
                "
                SELECT tested_at
                FROM probe_results
                WHERE node_id = ?1 AND probe_id = ?2
                ORDER BY tested_at DESC, id DESC
                LIMIT 1
                ",
                params![to_node_id, probe_id],
                |r| r.get(0),
            )
            .optional()?;

        let should_replace = match to_latest_tested_at.as_deref() {
            None => true,
            Some(existing_ts) => {
                normalize_tested_at_for_storage(&from_tested_at)
                    > normalize_tested_at_for_storage(existing_ts)
            }
        };
        if should_replace {
            tx.execute(
                "DELETE FROM probe_results WHERE node_id = ?1 AND probe_id = ?2",
                params![to_node_id, probe_id],
            )?;
            tx.execute(
                "UPDATE probe_results SET node_id = ?1 WHERE id = ?2",
                params![to_node_id, from_row_id],
            )?;
        }
    }

    Ok(())
}

fn load_node_ids_for_subscription_in_tx(
    tx: &Transaction<'_>,
    sub_id: &str,
) -> CatResult<HashSet<String>> {
    let mut stmt = tx.prepare("SELECT id FROM nodes WHERE sub_id = ?1")?;
    let rows = stmt.query_map(params![sub_id], |row| row.get::<_, String>(0))?;
    let mut ids = HashSet::new();
    for r in rows {
        ids.insert(r?);
    }
    Ok(ids)
}

fn load_all_node_ids_in_tx(tx: &Transaction<'_>) -> CatResult<HashSet<String>> {
    let mut stmt = tx.prepare("SELECT id FROM nodes")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut ids = HashSet::new();
    for r in rows {
        ids.insert(r?);
    }
    Ok(ids)
}

fn remap_multi_groups_in_tx(
    tx: &Transaction<'_>,
    id_remap: &HashMap<String, String>,
    removed_unmapped_ids: &HashSet<String>,
    sub_id_replace: Option<(&str, &str)>,
    removed_sub_id: Option<&str>,
    live_node_ids: Option<&HashSet<String>>,
) -> CatResult<()> {
    let mut groups: Vec<MultiGroup> = Vec::new();
    {
        let mut stmt = tx.prepare(
            "
            SELECT id, name, mode, match_rules_json, member_node_ids_json,
                   dynamic_filter_json, primary_probe_id, hard_gates_json,
                   trigger_rules_json, formula_expr, fallback_policy, fallback_pool_id,
                   escalated_since, recover_probe_interval_sec, switch_mode,
                   cooldown_sec, hysteresis_pct, active_node_id, state,
                   independent_routing
            FROM multi_groups
            ",
        )?;
        let rows = stmt.query_map([], row_to_multi_group)?;
        for r in rows {
            groups.push(r?);
        }
    }

    for group in groups {
        let mut new_members = Vec::with_capacity(group.member_node_ids.len());
        let mut seen_members: HashSet<String> = HashSet::with_capacity(group.member_node_ids.len());
        for mid in &group.member_node_ids {
            let resolved = if let Some(mapped) = id_remap.get(mid) {
                mapped.as_str()
            } else if removed_unmapped_ids.contains(mid) {
                continue;
            } else {
                mid.as_str()
            };
            if let Some(live) = live_node_ids {
                if !live.contains(resolved) {
                    continue;
                }
            }
            if seen_members.insert(resolved.to_string()) {
                new_members.push(resolved.to_string());
            }
        }

        let new_active = match group.active_node_id.as_deref() {
            Some(cur) => {
                let candidate = if let Some(mapped) = id_remap.get(cur) {
                    Some(mapped.as_str())
                } else if removed_unmapped_ids.contains(cur) {
                    None
                } else {
                    Some(cur)
                };
                candidate
                    .filter(|resolved| live_node_ids.map_or(true, |live| live.contains(*resolved)))
                    .map(str::to_string)
            }
            None => None,
        };

        let mut new_dynamic_filter = group.dynamic_filter.clone();
        if let Some(df) = new_dynamic_filter.as_mut() {
            if let Some((src_sub, dst_sub)) = sub_id_replace {
                let mut updated_sub_ids = Vec::with_capacity(df.sub_ids.len());
                let mut seen_subs: HashSet<String> = HashSet::with_capacity(df.sub_ids.len());
                for sid in &df.sub_ids {
                    let resolved = if sid == src_sub { dst_sub } else { sid.as_str() };
                    if seen_subs.insert(resolved.to_string()) {
                        updated_sub_ids.push(resolved.to_string());
                    }
                }
                df.sub_ids = updated_sub_ids;
            }
            if let Some(del_sub) = removed_sub_id {
                df.sub_ids.retain(|sid| sid != del_sub);
            }
        }

        if new_members != group.member_node_ids
            || new_active != group.active_node_id
            || new_dynamic_filter != group.dynamic_filter
        {
            let member_json = serde_json::to_string(&new_members)?;
            let df_json = new_dynamic_filter
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            tx.execute(
                "
                UPDATE multi_groups
                SET member_node_ids_json = ?2,
                    active_node_id = ?3,
                    dynamic_filter_json = ?4
                WHERE id = ?1
                ",
                params![group.id, member_json, new_active, df_json],
            )?;
        }
    }

    Ok(())
}

fn make_placeholders(count: usize) -> String {
    let mut s = String::with_capacity(count * 2);
    for idx in 0..count {
        if idx > 0 {
            s.push(',');
        }
        s.push('?');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DEFAULT_COST_EFFECTIVE_FORMULA, MmRelayBundleV1};
    use uuid::Uuid;

    fn sample_sub(id: &str, name: &str) -> SubscriptionRecord {
        SubscriptionRecord {
            id: id.to_string(),
            name: name.to_string(),
            kind: SubscriptionKind::Url,
            url_or_cmd: format!("https://example.invalid/sub/{id}"),
            refresh_interval_sec: 1800,
            traffic_used_bytes: 1024,
            traffic_total_bytes: 10240,
            expires_at: Some("2027-12-31T00:00:00Z".to_string()),
            etag: Some("\"v1\"".to_string()),
            last_ok_at: Some("2026-11-22T00:00:00Z".to_string()),
            last_error: None,
            enabled: true,
        }
    }

    fn sample_node(
        id: &str,
        sub_id: &str,
        region: &str,
        multiplier: f64,
        protocol: &str,
        is_443_native: bool,
        tags: &[&str],
    ) -> ProxyNode {
        ProxyNode {
            id: id.to_string(),
            sub_id: sub_id.to_string(),
            name: format!("{region}-{protocol}-{id}"),
            protocol: protocol.to_string(),
            server: format!("{id}.node.example.invalid"),
            port: if is_443_native { 443 } else { 20443 },
            raw_config: serde_json::json!({
                "name": format!("{region}-{protocol}-{id}"),
                "type": protocol,
                "server": format!("{id}.node.example.invalid"),
                "port": if is_443_native { 443 } else { 20443 }
            }),
            region_code: region.to_string(),
            multiplier,
            is_443_native,
            preaccel_eligible: !is_443_native,
            preaccel_override: None,
            tags: tags.iter().map(|s| (*s).to_string()).collect(),
            enabled: true,
        }
    }

    #[test]
    fn on_disk_wal_pragmas_and_idempotent_migration() {
        let dir = std::env::temp_dir().join(format!("catcloud-db-test-{}", Uuid::new_v4()));
        let db_path = dir.join("catcloud.sqlite");

        {
            let storage = Storage::open(&db_path).expect("open sqlite on disk");
            assert_eq!(storage.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
            assert_eq!(storage.journal_mode().unwrap().to_ascii_lowercase(), "wal");
            assert!(storage.foreign_keys_enabled().unwrap());
            assert_eq!(storage.busy_timeout_ms().unwrap(), 5000);
        }

        // Re-opening must be idempotent
        {
            let storage = Storage::open(&db_path).expect("reopen sqlite on disk");
            assert_eq!(storage.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
            assert!(storage.foreign_keys_enabled().unwrap());
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn full_crud_across_all_six_tables_and_snapshot_aggregation() {
        let mut storage = Storage::open_in_memory().expect("open in-memory db");

        // 1. Subscriptions
        let sub_a = sample_sub("sub-alpha", "Provider Alpha");
        storage.upsert_subscription(&sub_a).unwrap();
        let got_sub = storage.get_subscription("sub-alpha").unwrap().unwrap();
        assert_eq!(got_sub.name, "Provider Alpha");
        assert_eq!(got_sub.remaining_bytes(), 9216);

        storage
            .update_subscription_refresh_status(
                "sub-alpha",
                Some("2026-11-23T01:00:00Z"),
                Some("\"v2\""),
                None,
                Some(2048),
                None,
                None,
            )
            .unwrap();
        let updated_sub = storage.get_subscription("sub-alpha").unwrap().unwrap();
        assert_eq!(updated_sub.traffic_used_bytes, 2048);
        assert_eq!(updated_sub.etag.as_deref(), Some("\"v2\""));

        // 2. Nodes
        let node1 = sample_node("n1", "sub-alpha", "JP", 1.0, "vless", true, &["ai", "low-cost"]);
        storage.upsert_node(&node1).unwrap();
        assert_eq!(storage.get_node("n1").unwrap().unwrap().port, 443);

        // 3. Probe definitions (builtins + custom)
        let seeded = storage.seed_builtin_probes().unwrap();
        assert!(seeded >= 5);
        assert_eq!(storage.seed_builtin_probes().unwrap(), 0); // idempotent

        let custom_probe = ProbeDefinition {
            id: "ai_upload".to_string(),
            name: "AI Endpoint Upload".to_string(),
            kind: ProbeKind::Upload,
            target_url: "https://example.invalid/upload".to_string(),
            method: "POST".to_string(),
            expected_status: Some(200),
            body_regex: None,
            payload_bytes: Some(1024 * 1024),
            timeout_ms: 10000,
            builtin: false,
        };
        storage.upsert_probe_definition(&custom_probe).unwrap();
        assert_eq!(
            storage.get_probe_definition("ai_upload").unwrap().unwrap().kind,
            ProbeKind::Upload
        );

        // 4. Probe results & per-probe snapshot aggregation
        let mut unlocked = HashMap::new();
        unlocked.insert("chatgpt".to_string(), true);
        unlocked.insert("claude".to_string(), true);

        storage
            .insert_probe_results_batch(&[
                ProbeResultRecord {
                    node_id: "n1".to_string(),
                    probe_id: "builtin_google_cn".to_string(),
                    tested_at: "2026-11-23T01:00:00Z".to_string(),
                    ok: true,
                    latency_ms: Some(45.0),
                    cf_loc: Some("TW".to_string()),
                    yt_gl: Some("US".to_string()),
                    google_clean: Some(true),
                    unlocked_map: unlocked,
                    ..Default::default()
                },
                ProbeResultRecord {
                    node_id: "n1".to_string(),
                    probe_id: "ai_upload".to_string(),
                    tested_at: "2026-11-23T01:01:00Z".to_string(),
                    ok: true,
                    latency_ms: Some(62.5),
                    jitter_ms: Some(4.2),
                    loss_pct: Some(0.0),
                    up_mbps: Some(18.6),
                    down_mbps: Some(140.0),
                    keepalive_60s_ok: Some(true),
                    detail: Some("fast".to_string()),
                    ..Default::default()
                },
            ])
            .unwrap();

        let snap = storage
            .get_probe_snapshot("n1", Some("ai_upload"))
            .unwrap()
            .expect("snapshot exists");
        assert!(snap.ok);
        assert_eq!(snap.up_mbps, Some(18.6));
        assert_eq!(snap.probe_up("ai_upload"), Some(18.6));
        assert_eq!(snap.probe_ping("builtin_google_cn"), Some(45.0));
        assert_eq!(snap.probe_ok("ai_upload"), Some(true));
        assert_eq!(snap.google_clean, Some(true));
        assert!(snap.google_risk_mismatch); // CF TW != YT US -> warning badge only, google_clean stays true
        assert_eq!(snap.unlocked_sites.get("chatgpt"), Some(&true));

        // 5. Multi-groups
        let group = MultiGroup {
            id: "grp-ai".to_string(),
            name: "AI Dedicated".to_string(),
            mode: MultiGroupMode::StickyBest,
            match_rules: vec!["DOMAIN-SUFFIX,openai.com".to_string()],
            member_node_ids: vec!["n1".to_string()],
            dynamic_filter: Some(DynamicFilterSpec {
                expr: Some("multiplier <= 1 && google_clean == 1".to_string()),
                max_multiplier: Some(1.0),
                require_google_clean: true,
                ..Default::default()
            }),
            primary_probe_id: Some("ai_upload".to_string()),
            hard_gates: vec!["google_clean == 1".to_string()],
            trigger_rules: vec![TriggerRule {
                expr: "probe_up(\"ai_upload\") < 2.0".to_string(),
                consecutive_failures: 2,
                bypass_cooldown_on_disconnect: true,
            }],
            formula_expr: DEFAULT_COST_EFFECTIVE_FORMULA.to_string(),
            fallback_policy: FallbackPolicy::CrossPoolEscalate,
            fallback_pool_id: Some("grp-backup-3x".to_string()),
            escalated_since: None,
            recover_probe_interval_sec: 120,
            switch_mode: SwitchMode::ForceCloseOld,
            cooldown_sec: 60,
            hysteresis_pct: 20.0,
            active_node_id: Some("n1".to_string()),
            state: MultiGroupState::Healthy,
            independent_routing: true,
        };
        storage.upsert_multi_group(&group).unwrap();
        let loaded_group = storage.get_multi_group("grp-ai").unwrap().unwrap();
        assert_eq!(loaded_group, group);
        assert!(loaded_group.independent_routing);
        let listed_groups = storage.list_multi_groups().unwrap();
        assert_eq!(listed_groups.len(), 1);
        assert!(listed_groups[0].independent_routing);

        storage
            .update_multi_group_runtime(
                "grp-ai",
                Some("n1"),
                &MultiGroupState::Escalated,
                Some("2026-11-23T02:00:00Z"),
            )
            .unwrap();
        let escalated = storage.get_multi_group("grp-ai").unwrap().unwrap();
        assert_eq!(escalated.state, MultiGroupState::Escalated);
        assert_eq!(
            escalated.escalated_since.as_deref(),
            Some("2026-11-23T02:00:00Z")
        );

        // 6. PreAccel relays (mmrelay/v1 compatible)
        let relay1 = PreAccelRelay {
            id: "relay-primary".to_string(),
            name: "Domestic Edge A".to_string(),
            provider: "CloudVendorA".to_string(),
            region: "East".to_string(),
            server: "198.51.100.10".to_string(),
            port: 443,
            protocol: "anytls".to_string(),
            password: "test-placeholder-token".to_string(),
            sni: None,
            skip_cert_verify: true,
            priority: 10,
            expires_at: Some("2027-06-01".to_string()),
            enabled: true,
            last_probe_ms: Some(14.5),
            last_mbps: Some(92.0),
            last_up_mbps: Some(85.0),
            last_down_mbps: Some(180.0),
            supports_ipv6: false,
        };
        let relay2 = PreAccelRelay {
            id: "relay-standby".to_string(),
            name: "Domestic Edge B".to_string(),
            provider: "CloudVendorB".to_string(),
            region: "South".to_string(),
            server: "198.51.100.20".to_string(),
            port: 443,
            protocol: "trojan".to_string(),
            password: "test-placeholder-token-2".to_string(),
            sni: None,
            skip_cert_verify: true,
            priority: 20,
            expires_at: None,
            enabled: false,
            last_probe_ms: None,
            last_mbps: None,
            last_up_mbps: None,
            last_down_mbps: None,
            supports_ipv6: true,
        };
        storage.upsert_preaccel_relay(&relay2).unwrap();
        storage.upsert_preaccel_relay(&relay1).unwrap();

        let all_relays = storage.list_preaccel_relays(false).unwrap();
        assert_eq!(all_relays.len(), 2);
        assert_eq!(all_relays[0].id, "relay-primary"); // priority 10 before 20
        assert!(!all_relays[0].has_non_empty_sni());

        let enabled_only = storage.list_preaccel_relays(true).unwrap();
        assert_eq!(enabled_only.len(), 1);

        let bundle = MmRelayBundleV1 {
            relays: enabled_only,
            ..Default::default()
        };
        assert_eq!(bundle.schema, "mmrelay/v1");
        assert_eq!(bundle.role, "domestic_pre_accel");

        // Deleting subscription cascades nodes and probe_results (foreign_keys = ON)
        assert!(storage.delete_subscription("sub-alpha").unwrap());
        assert!(storage.get_node("n1").unwrap().is_none());
        assert!(storage.latest_probe_results_for_node("n1").unwrap().is_empty());
    }

    #[test]
    fn multi_dimensional_node_filter_queries() {
        let mut storage = Storage::open_in_memory().unwrap();
        storage.seed_builtin_probes().unwrap();
        storage
            .upsert_subscription(&sample_sub("sub-1", "Feed One"))
            .unwrap();
        storage
            .upsert_subscription(&sample_sub("sub-2", "Feed Two"))
            .unwrap();

        let nodes = vec![
            sample_node("jp-1x-443", "sub-1", "JP", 1.0, "vless", true, &["ai", "fast"]),
            sample_node("jp-3x-nat", "sub-1", "JP", 3.0, "trojan", true, &["residential"]),
            sample_node("sg-1x-non443", "sub-2", "SG", 1.0, "ss", false, &["budget"]),
            sample_node("us-05x-443", "sub-2", "US", 0.5, "hysteria2", true, &["ai", "bulk"]),
        ];
        storage.upsert_nodes_batch(&nodes).unwrap();

        // Record Google cleanliness results (jp-1x-443 clean, jp-3x-nat dirty, us-05x-443 clean)
        storage
            .insert_probe_results_batch(&[
                ProbeResultRecord {
                    node_id: "jp-1x-443".into(),
                    probe_id: "builtin_google_cn".into(),
                    tested_at: "2026-11-23T01:00:00Z".into(),
                    ok: true,
                    google_clean: Some(true),
                    keepalive_60s_ok: Some(true),
                    ..Default::default()
                },
                ProbeResultRecord {
                    node_id: "jp-3x-nat".into(),
                    probe_id: "builtin_google_cn".into(),
                    tested_at: "2026-11-23T01:00:00Z".into(),
                    ok: false,
                    google_clean: Some(false),
                    ..Default::default()
                },
                ProbeResultRecord {
                    node_id: "us-05x-443".into(),
                    probe_id: "builtin_google_cn".into(),
                    tested_at: "2026-11-23T01:00:00Z".into(),
                    ok: true,
                    google_clean: Some(true),
                    keepalive_60s_ok: Some(false),
                    ..Default::default()
                },
            ])
            .unwrap();

        // Filter: sub-1 + JP + multiplier <= 1.5 + protocol vless + 443 native + google clean
        let filtered = storage
            .query_nodes(&NodeFilter {
                sub_ids: Some(vec!["sub-1".into()]),
                region_codes: Some(vec!["jp".into()]),
                max_multiplier: Some(1.5),
                protocols: Some(vec!["VLESS".into()]),
                is_443_native: Some(true),
                google_clean_only: true,
                keepalive_60s_ok_only: true,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "jp-1x-443");

        // Filter: google clean across all subscriptions + multiplier <= 1.0
        let clean_cheap = storage
            .query_nodes(&NodeFilter {
                max_multiplier: Some(1.0),
                google_clean_only: true,
                ..Default::default()
            })
            .unwrap();
        let ids: Vec<&str> = clean_cheap.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(ids, vec!["jp-1x-443", "us-05x-443"]);

        // Filter: non-443 native only
        let non_443 = storage
            .query_nodes(&NodeFilter {
                is_443_native: Some(false),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(non_443.len(), 1);
        assert_eq!(non_443[0].id, "sg-1x-non443");

        // Filter: tag + keyword
        let ai_nodes = storage
            .query_nodes(&NodeFilter {
                tags: Some(vec!["ai".into()]),
                keyword: Some("hysteria2".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(ai_nodes.len(), 1);
        assert_eq!(ai_nodes[0].id, "us-05x-443");
    }

    #[test]
    fn transaction_rollback_and_empty_refresh_protection() {
        let mut storage = Storage::open_in_memory().unwrap();
        storage.seed_builtin_probes().unwrap();
        storage
            .upsert_subscription(&sample_sub("sub-1", "Feed One"))
            .unwrap();

        let original = vec![
            sample_node("n1", "sub-1", "JP", 1.0, "vless", true, &[]),
            sample_node("n2", "sub-1", "SG", 1.0, "trojan", false, &[]),
        ];
        storage.upsert_nodes_batch(&original).unwrap();
        storage
            .insert_probe_result(&ProbeResultRecord {
                node_id: "n1".into(),
                probe_id: "builtin_latency".into(),
                tested_at: "2026-11-23T01:00:00Z".into(),
                ok: true,
                latency_ms: Some(33.0),
                ..Default::default()
            })
            .unwrap();

        // 1. Empty refresh must be rejected without deleting existing nodes
        assert!(storage.replace_subscription_nodes("sub-1", &[]).is_err());
        assert_eq!(storage.list_nodes().unwrap().len(), 2);

        // 2. Transaction failure mid-batch rolls back completely
        let rollback_res: CatResult<()> = storage.in_transaction(|tx| {
            let n3 = sample_node("n3", "sub-1", "TW", 1.0, "vless", true, &[]);
            upsert_node_with_conn(tx, &n3)?;
            // Insert node referencing non-existent subscription -> FK violation triggers rollback
            let bad = sample_node("n-bad", "sub-missing", "US", 1.0, "vless", true, &[]);
            upsert_node_with_conn(tx, &bad)?;
            Ok(())
        });
        assert!(rollback_res.is_err());
        assert!(storage.get_node("n3").unwrap().is_none());
        assert_eq!(storage.list_nodes().unwrap().len(), 2);

        // 3. Valid incremental replace preserves probe history of surviving node `n1` and removes `n2`
        let updated = vec![
            sample_node("n1", "sub-1", "JP", 0.8, "vless", true, &["updated"]),
            sample_node("n4", "sub-1", "TW", 1.0, "anytls", true, &[]),
        ];
        storage
            .replace_subscription_nodes("sub-1", &updated)
            .unwrap();
        assert!(storage.get_node("n2").unwrap().is_none());
        assert_eq!(storage.get_node("n1").unwrap().unwrap().multiplier, 0.8);
        assert_eq!(storage.latest_probe_results_for_node("n1").unwrap().len(), 1);
        assert!(storage.get_node("n4").unwrap().is_some());

        // 4. Prune old probe results bounds table growth
        for i in 0..5 {
            storage
                .insert_probe_result(&ProbeResultRecord {
                    node_id: "n1".into(),
                    probe_id: "builtin_latency".into(),
                    tested_at: format!("2026-11-23T02:0{i}:00Z"),
                    ok: true,
                    latency_ms: Some(30.0 + i as f64),
                    ..Default::default()
                })
                .unwrap();
        }
        let pruned = storage.prune_old_probe_results(2).unwrap();
        assert_eq!(pruned, 4); // 1 original + 5 new = 6 total, keep 2 -> delete 4
    }

    #[test]
    fn seed_builtin_probes_idempotently_backfills_missing_builtins_without_clobbering_legacy_data() {
        let mut storage = Storage::open_in_memory().unwrap();

        // Populate a legacy portable database with subscription, node, custom probe, and history.
        storage
            .upsert_subscription(&sample_sub("sub-legacy", "Legacy Provider"))
            .unwrap();
        let legacy_node = sample_node("n-legacy", "sub-legacy", "JP", 1.0, "vless", true, &["ai"]);
        storage.upsert_node(&legacy_node).unwrap();

        // Seed only a legacy subset of built-in probes, plus a user-customized version of one built-in
        // and a user-created custom probe.
        let customized_latency = ProbeDefinition {
            id: "builtin_latency".to_string(),
            name: "User Tuned Latency".to_string(),
            kind: ProbeKind::Latency,
            target_url: "https://cp.cloudflare.com/generate_204".to_string(),
            method: "GET".to_string(),
            expected_status: Some(204),
            body_regex: None,
            payload_bytes: None,
            timeout_ms: 9500,
            builtin: true,
        };
        storage.upsert_probe_definition(&customized_latency).unwrap();

        let custom_probe = ProbeDefinition {
            id: "user_custom_unlock".to_string(),
            name: "User Custom Unlock".to_string(),
            kind: ProbeKind::UnlockRegex,
            target_url: "https://example.invalid/custom".to_string(),
            method: "GET".to_string(),
            expected_status: Some(200),
            body_regex: Some("ok".to_string()),
            payload_bytes: None,
            timeout_ms: 5000,
            builtin: false,
        };
        storage.upsert_probe_definition(&custom_probe).unwrap();

        storage
            .insert_probe_result(&ProbeResultRecord {
                node_id: "n-legacy".into(),
                probe_id: "builtin_latency".into(),
                tested_at: "2026-11-22T12:00:00Z".into(),
                ok: true,
                latency_ms: Some(42.0),
                ..Default::default()
            })
            .unwrap();

        // Run seed_builtin_probes on the legacy DB: should backfill all missing builtins without
        // deleting or overwriting any existing rows.
        let expected_defaults = ProbeDefinition::builtin_defaults();
        let inserted = storage.seed_builtin_probes().unwrap();
        assert_eq!(inserted, expected_defaults.len().saturating_sub(1));

        // Second call must be strictly idempotent.
        assert_eq!(storage.seed_builtin_probes().unwrap(), 0);

        // Every built-in default must now exist in the database.
        for def in &expected_defaults {
            assert!(
                storage.get_probe_definition(&def.id).unwrap().is_some(),
                "missing seeded builtin probe {}",
                def.id
            );
        }

        // User customization on existing builtin_latency must remain intact.
        let preserved_latency = storage.get_probe_definition("builtin_latency").unwrap().unwrap();
        assert_eq!(preserved_latency.name, "User Tuned Latency");
        assert_eq!(preserved_latency.timeout_ms, 9500);
        assert_eq!(preserved_latency, customized_latency);

        // Custom probe, legacy node, and historical probe results must remain untouched.
        assert_eq!(
            storage.get_probe_definition("user_custom_unlock").unwrap(),
            Some(custom_probe)
        );
        assert!(storage.get_node("n-legacy").unwrap().is_some());
        let hist = storage.latest_probe_results_for_node("n-legacy").unwrap();
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0].latency_ms, Some(42.0));
    }

    #[test]
    fn seed_builtin_probes_migrates_legacy_ai_unlock_probes_and_preserves_customizations() {
        let mut storage = Storage::open_in_memory().unwrap();
        let defaults: HashMap<String, ProbeDefinition> = ProbeDefinition::builtin_defaults()
            .into_iter()
            .map(|d| (d.id.clone(), d))
            .collect();

        // Simulate legacy DB rows where built-in AI unlock probes used fixed expected_status=200
        // and legacy homepage URLs / methods without custom body_regex.
        let legacy_rows = [
            ProbeDefinition {
                id: "builtin_unlock_claude".to_string(),
                name: "Claude / Anthropic 解锁".to_string(),
                kind: ProbeKind::UnlockRegex,
                target_url: "https://claude.ai/".to_string(),
                method: "GET".to_string(),
                expected_status: Some(200),
                body_regex: None,
                payload_bytes: None,
                timeout_ms: 8000,
                builtin: true,
            },
            ProbeDefinition {
                id: "builtin_unlock_chatgpt".to_string(),
                name: "ChatGPT / OpenAI 解锁".to_string(),
                kind: ProbeKind::UnlockRegex,
                target_url: "https://chatgpt.com/".to_string(),
                method: "HEAD".to_string(),
                expected_status: Some(200),
                body_regex: Some(String::new()),
                payload_bytes: None,
                timeout_ms: 8000,
                builtin: true,
            },
            ProbeDefinition {
                id: "builtin_unlock_gemini".to_string(),
                name: "Gemini / Google AI 解锁".to_string(),
                kind: ProbeKind::UnlockRegex,
                target_url: "https://gemini.google.com/".to_string(),
                method: "HEAD".to_string(),
                expected_status: Some(200),
                body_regex: None,
                payload_bytes: None,
                timeout_ms: 8000,
                builtin: true,
            },
        ];
        for row in &legacy_rows {
            storage.upsert_probe_definition(row).unwrap();
        }

        storage.seed_builtin_probes().unwrap();

        for id in [
            "builtin_unlock_claude",
            "builtin_unlock_chatgpt",
            "builtin_unlock_gemini",
        ] {
            let migrated = storage.get_probe_definition(id).unwrap().unwrap();
            let expected = defaults.get(id).expect("default builtin exists");
            assert_eq!(migrated.expected_status, None, "{id} expected_status must be NULL");
            assert_eq!(migrated.target_url, expected.target_url, "{id} target_url must sync");
            assert_eq!(migrated.method, expected.method, "{id} method must sync");
        }

        // User customizations (non-empty body_regex OR builtin=false) must NOT be overwritten.
        let custom_regex_claude = ProbeDefinition {
            id: "builtin_unlock_claude".to_string(),
            name: "Custom Claude Regex".to_string(),
            kind: ProbeKind::UnlockRegex,
            target_url: "https://example.invalid/custom-claude".to_string(),
            method: "GET".to_string(),
            expected_status: Some(200),
            body_regex: Some("ok_marker".to_string()),
            payload_bytes: None,
            timeout_ms: 7000,
            builtin: true,
        };
        let custom_non_builtin_chatgpt = ProbeDefinition {
            id: "builtin_unlock_chatgpt".to_string(),
            name: "User Override ChatGPT".to_string(),
            kind: ProbeKind::UnlockRegex,
            target_url: "https://example.invalid/custom-chatgpt".to_string(),
            method: "POST".to_string(),
            expected_status: Some(204),
            body_regex: None,
            payload_bytes: None,
            timeout_ms: 6000,
            builtin: false,
        };
        storage.upsert_probe_definition(&custom_regex_claude).unwrap();
        storage
            .upsert_probe_definition(&custom_non_builtin_chatgpt)
            .unwrap();

        assert_eq!(storage.seed_builtin_probes().unwrap(), 0);
        assert_eq!(
            storage.get_probe_definition("builtin_unlock_claude").unwrap(),
            Some(custom_regex_claude)
        );
        assert_eq!(
            storage.get_probe_definition("builtin_unlock_chatgpt").unwrap(),
            Some(custom_non_builtin_chatgpt)
        );

        // `builtin_unlock_windsurf` MUST default to the semantic Codeium API POST definition
        // (`expected_status: None`, `timeout_ms: 9000`) and losslessly upgrade legacy official
        // `https://windsurf.com` / `https://codeium.com` rows while preserving user-customized
        // `body_regex` or custom URLs (and user edits to latency/upload/download).
        let ws = storage
            .get_probe_definition("builtin_unlock_windsurf")
            .unwrap()
            .expect("windsurf builtin exists");
        assert_eq!(ws.expected_status, None);
        assert_eq!(ws.method, "POST");
        assert_eq!(
            ws.target_url,
            "https://server.codeium.com/exa.api_server_pb.ApiServerService/GetChatMessage"
        );
        assert_eq!(ws.timeout_ms, 9000);

        let stale_ws = ProbeDefinition {
            id: "builtin_unlock_windsurf".to_string(),
            name: "Windsurf / Codeium Reachability".to_string(),
            kind: ProbeKind::UnlockRegex,
            target_url: "https://windsurf.com".to_string(),
            method: "GET".to_string(),
            expected_status: Some(200),
            body_regex: None,
            payload_bytes: None,
            timeout_ms: 8000,
            builtin: true,
        };
        storage.upsert_probe_definition(&stale_ws).unwrap();
        storage.seed_builtin_probes().unwrap();
        let realigned_ws = storage
            .get_probe_definition("builtin_unlock_windsurf")
            .unwrap()
            .unwrap();
        assert_eq!(realigned_ws.expected_status, None);
        assert_eq!(
            realigned_ws.target_url,
            "https://server.codeium.com/exa.api_server_pb.ApiServerService/GetChatMessage"
        );
        assert_eq!(realigned_ws.method, "POST");
        assert_eq!(realigned_ws.timeout_ms, 9000);

        // User-customized Windsurf regex or custom URL MUST NOT be overwritten by reseeding.
        let custom_ws_regex = ProbeDefinition {
            id: "builtin_unlock_windsurf".to_string(),
            name: "Custom Windsurf Regex".to_string(),
            kind: ProbeKind::UnlockRegex,
            target_url: "https://windsurf.com".to_string(),
            method: "GET".to_string(),
            expected_status: Some(200),
            body_regex: Some("custom_ws_marker".to_string()),
            payload_bytes: None,
            timeout_ms: 8000,
            builtin: true,
        };
        storage.upsert_probe_definition(&custom_ws_regex).unwrap();
        storage.seed_builtin_probes().unwrap();
        assert_eq!(
            storage.get_probe_definition("builtin_unlock_windsurf").unwrap(),
            Some(custom_ws_regex)
        );

        let custom_ws_url = ProbeDefinition {
            id: "builtin_unlock_windsurf".to_string(),
            name: "Custom Windsurf Endpoint".to_string(),
            kind: ProbeKind::UnlockRegex,
            target_url: "https://my-wsf-check.example.invalid/ping".to_string(),
            method: "GET".to_string(),
            expected_status: Some(200),
            body_regex: None,
            payload_bytes: None,
            timeout_ms: 7000,
            builtin: true,
        };
        storage.upsert_probe_definition(&custom_ws_url).unwrap();
        storage.seed_builtin_probes().unwrap();
        assert_eq!(
            storage.get_probe_definition("builtin_unlock_windsurf").unwrap(),
            Some(custom_ws_url)
        );

        // User-edited built-in latency/upload/download endpoints MUST survive restart seeding!
        let custom_lat = ProbeDefinition {
            id: "builtin_latency".to_string(),
            name: "Self-hosted 204".to_string(),
            kind: ProbeKind::Latency,
            target_url: "https://my-204.example.invalid/generate_204".to_string(),
            method: "HEAD".to_string(),
            expected_status: Some(200),
            body_regex: None,
            payload_bytes: None,
            timeout_ms: 3500,
            builtin: true,
        };
        let custom_up = ProbeDefinition {
            id: "builtin_upload".to_string(),
            name: "Custom Upload".to_string(),
            kind: ProbeKind::Upload,
            target_url: "https://my-speed.example.invalid/up".to_string(),
            method: "PUT".to_string(),
            expected_status: Some(201),
            body_regex: None,
            payload_bytes: Some(256 * 1024),
            timeout_ms: 10000,
            builtin: true,
        };
        let custom_claude_proxy = ProbeDefinition {
            id: "builtin_unlock_claude".to_string(),
            name: "Custom Claude Proxy".to_string(),
            kind: ProbeKind::UnlockRegex,
            target_url: "https://my-claude-mirror.example.invalid/check".to_string(),
            method: "GET".to_string(),
            expected_status: Some(204),
            body_regex: None,
            payload_bytes: None,
            timeout_ms: 7000,
            builtin: true,
        };
        storage.upsert_probe_definition(&custom_lat).unwrap();
        storage.upsert_probe_definition(&custom_up).unwrap();
        storage.upsert_probe_definition(&custom_claude_proxy).unwrap();
        assert_eq!(storage.seed_builtin_probes().unwrap(), 0);
        assert_eq!(
            storage.get_probe_definition("builtin_latency").unwrap(),
            Some(custom_lat)
        );
        assert_eq!(
            storage.get_probe_definition("builtin_upload").unwrap(),
            Some(custom_up)
        );
        assert_eq!(
            storage.get_probe_definition("builtin_unlock_claude").unwrap(),
            Some(custom_claude_proxy)
        );
    }

    #[test]
    fn query_nodes_and_cold_read_probe_snapshot_agree_under_desc_multi_probe_rows() {
        let mut storage = Storage::open_in_memory().unwrap();
        storage.seed_builtin_probes().unwrap();
        storage
            .upsert_subscription(&sample_sub("sub-s22", "Stage22 Sub"))
            .unwrap();
        let node = sample_node("n-s22", "sub-s22", "JP", 1.0, "anytls", true, &["ai"]);
        storage.upsert_node(&node).unwrap();

        let mut google_map_old = HashMap::new();
        google_map_old.insert("gemini".to_string(), true);
        google_map_old.insert("gemini_aistudio".to_string(), true);

        let mut google_map_new = HashMap::new();
        google_map_new.insert("gemini".to_string(), true);
        google_map_new.insert("gemini_aistudio".to_string(), true);

        let mut gemini_dedicated = HashMap::new();
        gemini_dedicated.insert("gemini".to_string(), false);

        let mut ws_map = HashMap::new();
        ws_map.insert("windsurf".to_string(), true);

        storage
            .insert_probe_results_batch(&[
                // Earlier stale negative google_clean & keepalive
                ProbeResultRecord {
                    node_id: "n-s22".into(),
                    probe_id: "builtin_google_cn".into(),
                    tested_at: "2026-11-26T10:00:00Z".into(),
                    ok: false,
                    google_clean: Some(false),
                    cf_loc: Some("CN".into()),
                    yt_gl: Some("HK".into()),
                    unlocked_map: google_map_old,
                    ..Default::default()
                },
                ProbeResultRecord {
                    node_id: "n-s22".into(),
                    probe_id: "builtin_keepalive_60s".into(),
                    tested_at: "2026-11-26T10:01:00Z".into(),
                    ok: false,
                    keepalive_60s_ok: Some(false),
                    ..Default::default()
                },
                // Current run: L0 latency first, then L1 gemini (blocked), google_cn (clean), windsurf (1423ms), L2 keepalive (ok)
                ProbeResultRecord {
                    node_id: "n-s22".into(),
                    probe_id: "builtin_latency".into(),
                    tested_at: "2026-11-27T12:00:01Z".into(),
                    ok: true,
                    latency_ms: Some(41.2),
                    jitter_ms: Some(1.5),
                    loss_pct: Some(0.0),
                    ..Default::default()
                },
                ProbeResultRecord {
                    node_id: "n-s22".into(),
                    probe_id: "builtin_unlock_gemini".into(),
                    tested_at: "2026-11-27T12:00:02Z".into(),
                    ok: false,
                    latency_ms: Some(810.0),
                    unlocked_map: gemini_dedicated,
                    ..Default::default()
                },
                ProbeResultRecord {
                    node_id: "n-s22".into(),
                    probe_id: "builtin_google_cn".into(),
                    tested_at: "2026-11-27T12:00:03Z".into(),
                    ok: true,
                    latency_ms: Some(530.0),
                    cf_loc: Some("JP".into()),
                    yt_gl: Some("JP".into()),
                    google_clean: Some(true),
                    unlocked_map: google_map_new,
                    ..Default::default()
                },
                ProbeResultRecord {
                    node_id: "n-s22".into(),
                    probe_id: "builtin_unlock_windsurf".into(),
                    tested_at: "2026-11-27T12:00:04Z".into(),
                    ok: true,
                    latency_ms: Some(1423.0),
                    unlocked_map: ws_map,
                    ..Default::default()
                },
                ProbeResultRecord {
                    node_id: "n-s22".into(),
                    probe_id: "builtin_keepalive_60s".into(),
                    tested_at: "2026-11-27T12:00:05Z".into(),
                    ok: true,
                    latency_ms: Some(1800.0),
                    keepalive_60s_ok: Some(true),
                    ..Default::default()
                },
            ])
            .unwrap();

        let snap = storage
            .get_probe_snapshot("n-s22", None)
            .unwrap()
            .expect("cold snapshot");
        let batch = storage
            .get_probe_snapshots_batch(&["n-s22".to_string()], None)
            .unwrap();
        assert_eq!(batch.get("n-s22"), Some(&snap));

        // Top-level latency MUST stay 41.2ms (never 1423ms Windsurf or 1800ms Keepalive!)
        assert!(snap.ok);
        assert_eq!(snap.latency_ms, Some(41.2));
        assert_eq!(snap.google_clean, Some(true));
        assert_eq!(snap.keepalive_60s_ok, Some(true));
        assert_eq!(snap.unlocked_sites.get("gemini"), Some(&false));
        assert_eq!(snap.unlocked_sites.get("gemini_aistudio"), Some(&true));
        assert_eq!(snap.unlocked_sites.get("windsurf"), Some(&true));

        // query_nodes SQL filters MUST match snapshot truth 100%
        let clean_ka_ws = storage
            .query_nodes(&NodeFilter {
                google_clean_only: true,
                keepalive_60s_ok_only: true,
                unlocked_site: Some("windsurf".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(clean_ka_ws.len(), 1);
        assert_eq!(clean_ka_ws[0].id, "n-s22");

        let gemini_unlocked = storage
            .query_nodes(&NodeFilter {
                unlocked_site: Some("gemini".into()),
                ..Default::default()
            })
            .unwrap();
        assert!(
            gemini_unlocked.is_empty(),
            "builtin_unlock_gemini=false must not be overridden by newer builtin_google_cn"
        );
    }

    #[test]
    fn migrates_v1_multi_groups_table_adding_independent_routing_column() {
        let dir = std::env::temp_dir().join(format!("catcloud-db-mig-v2-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("legacy-v1.sqlite");

        // Build a legacy v1 SQLite database whose `multi_groups` table lacks `independent_routing`.
        {
            let conn = Connection::open(&db_path).expect("create legacy v1 sqlite");
            conn.execute_batch(
                "
                CREATE TABLE multi_groups (
                    id TEXT PRIMARY KEY NOT NULL,
                    name TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    match_rules_json TEXT NOT NULL DEFAULT '[]',
                    member_node_ids_json TEXT NOT NULL DEFAULT '[]',
                    dynamic_filter_json TEXT,
                    primary_probe_id TEXT,
                    hard_gates_json TEXT NOT NULL DEFAULT '[]',
                    trigger_rules_json TEXT NOT NULL DEFAULT '[]',
                    formula_expr TEXT NOT NULL,
                    fallback_policy TEXT NOT NULL,
                    fallback_pool_id TEXT,
                    escalated_since TEXT,
                    recover_probe_interval_sec INTEGER NOT NULL DEFAULT 120,
                    switch_mode TEXT NOT NULL,
                    cooldown_sec INTEGER NOT NULL DEFAULT 60,
                    hysteresis_pct REAL NOT NULL DEFAULT 20.0,
                    active_node_id TEXT,
                    state TEXT NOT NULL DEFAULT 'idle'
                );
                INSERT INTO multi_groups (
                    id, name, mode, match_rules_json, member_node_ids_json,
                    formula_expr, fallback_policy, switch_mode, state
                ) VALUES (
                    'grp-legacy', 'Legacy AI', 'sticky_best', '[\"@ai_domains\"]', '[]',
                    'up_mbps', 'degrade_best_warn', 'force_close_old', 'healthy'
                );
                PRAGMA user_version = 1;
                ",
            )
            .expect("seed legacy v1 schema");
        }

        // Opening via `Storage::open` must idempotently migrate v1 -> v2 without losing rows
        // and default existing rows to `independent_routing = false`.
        {
            let storage = Storage::open(&db_path).expect("open & migrate v1 db");
            assert_eq!(storage.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
            let mut migrated = storage
                .get_multi_group("grp-legacy")
                .unwrap()
                .expect("legacy row preserved");
            assert_eq!(migrated.name, "Legacy AI");
            assert!(!migrated.independent_routing);

            migrated.independent_routing = true;
            storage.upsert_multi_group(&migrated).unwrap();
            assert!(
                storage
                    .get_multi_group("grp-legacy")
                    .unwrap()
                    .unwrap()
                    .independent_routing
            );
        }

        // Re-opening migrated database must remain idempotent and retain `independent_routing = true`.
        {
            let storage = Storage::open(&db_path).expect("reopen migrated v2 db");
            assert_eq!(storage.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
            let groups = storage.list_multi_groups().unwrap();
            assert_eq!(groups.len(), 1);
            assert!(groups[0].independent_routing);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn sample_vless_node(
        id: &str,
        sub_id: &str,
        name: &str,
        server: &str,
        port: u16,
        uuid: &str,
        ws_path: &str,
    ) -> ProxyNode {
        ProxyNode {
            id: id.to_string(),
            sub_id: sub_id.to_string(),
            name: name.to_string(),
            protocol: "vless".to_string(),
            server: server.to_string(),
            port,
            raw_config: serde_json::json!({
                "name": name,
                "type": "vless",
                "server": server,
                "port": port,
                "uuid": uuid,
                "tls": true,
                "network": "ws",
                "ws-opts": { "path": ws_path }
            }),
            region_code: "JP".to_string(),
            multiplier: 1.0,
            is_443_native: port == 443,
            preaccel_eligible: true,
            preaccel_override: None,
            tags: vec!["ai".to_string()],
            enabled: true,
        }
    }

    #[test]
    fn rename_subscription_updates_name_only_without_touching_nodes_or_probes() {
        let mut storage = Storage::open_in_memory().unwrap();
        storage.seed_builtin_probes().unwrap();
        storage
            .upsert_subscription(&sample_sub("sub-ren", "Old Name"))
            .unwrap();
        let node = sample_vless_node(
            "n-ren-1",
            "sub-ren",
            "JP Node",
            "203.0.113.10",
            443,
            "00000000-0000-4000-8000-000000000001",
            "/ws",
        );
        storage.upsert_node(&node).unwrap();
        storage
            .insert_probe_result(&ProbeResultRecord {
                node_id: "n-ren-1".into(),
                probe_id: "builtin_latency".into(),
                tested_at: "2026-11-24T01:00:00Z".into(),
                ok: true,
                latency_ms: Some(42.0),
                ..Default::default()
            })
            .unwrap();

        assert!(storage.rename_subscription("sub-ren", "   ").is_err());
        assert!(storage.rename_subscription("sub-missing", "Valid").is_err());

        let renamed = storage
            .rename_subscription("sub-ren", "  Renamed Feed  ")
            .unwrap();
        assert_eq!(renamed.name, "Renamed Feed");
        assert_eq!(renamed.id, "sub-ren");
        assert_eq!(storage.get_node("n-ren-1").unwrap().unwrap().sub_id, "sub-ren");
        assert_eq!(
            storage.latest_probe_results_for_node("n-ren-1").unwrap().len(),
            1
        );
    }

    #[test]
    fn update_subscription_nodes_with_mode_replace_latest_and_merge_dedup_preserve_probes_and_groups() {
        let mut storage = Storage::open_in_memory().unwrap();
        storage.seed_builtin_probes().unwrap();
        storage
            .upsert_subscription(&sample_sub("sub-main", "Main Feed"))
            .unwrap();

        // Seed two nodes (plus a duplicate-fingerprint legacy node to exercise remap).
        let n_keep = sample_vless_node(
            "old-keep",
            "sub-main",
            "JP Primary",
            "203.0.113.11",
            443,
            "00000000-0000-4000-8000-000000000011",
            "/p1",
        );
        let n_dup = sample_vless_node(
            "old-dup",
            "sub-main",
            "JP Primary Duplicate",
            "203.0.113.11",
            443,
            "00000000-0000-4000-8000-000000000011",
            "/p1",
        );
        let n_gone = sample_vless_node(
            "old-gone",
            "sub-main",
            "SG Vanished",
            "203.0.113.12",
            443,
            "00000000-0000-4000-8000-000000000012",
            "/p2",
        );
        storage
            .upsert_nodes_batch(&[n_keep.clone(), n_dup.clone(), n_gone.clone()])
            .unwrap();

        storage
            .insert_probe_results_batch(&[
                ProbeResultRecord {
                    node_id: "old-keep".into(),
                    probe_id: "builtin_latency".into(),
                    tested_at: "2026-11-24T03:00:00Z".into(),
                    ok: true,
                    latency_ms: Some(28.0),
                    ..Default::default()
                },
                ProbeResultRecord {
                    node_id: "old-dup".into(),
                    probe_id: "builtin_latency".into(),
                    tested_at: "2026-11-24T01:00:00Z".into(),
                    ok: true,
                    latency_ms: Some(50.0),
                    ..Default::default()
                },
            ])
            .unwrap();

        let grp = MultiGroup {
            id: "grp-upd".into(),
            name: "Update Group".into(),
            member_node_ids: vec![
                "old-dup".into(),
                "old-keep".into(),
                "old-gone".into(),
            ],
            active_node_id: Some("old-dup".into()),
            ..Default::default()
        };
        storage.upsert_multi_group(&grp).unwrap();

        // Empty incoming list must fail and leave DB untouched.
        assert!(
            storage
                .update_subscription_nodes_with_mode(
                    "sub-main",
                    &[],
                    SubscriptionUpdateMode::ReplaceLatest
                )
                .is_err()
        );
        assert_eq!(storage.list_nodes().unwrap().len(), 3);

        // ReplaceLatest: incoming has different IDs, one matches fingerprint of old-keep/old-dup,
        // one is brand new (same IP/port but different UUID -> must NOT collide).
        let incoming_replace = vec![
            sample_vless_node(
                "fresh-id-1",
                "cap-temp",
                "JP Primary Renamed",
                "203.0.113.11",
                443,
                "00000000-0000-4000-8000-000000000011",
                "/p1",
            ),
            sample_vless_node(
                "fresh-id-2",
                "cap-temp",
                "JP Second Account",
                "203.0.113.11",
                443,
                "00000000-0000-4000-8000-000000000099",
                "/p1",
            ),
        ];

        let rep = storage
            .update_subscription_nodes_with_mode(
                "sub-main",
                &incoming_replace,
                SubscriptionUpdateMode::ReplaceLatest,
            )
            .unwrap();
        assert_eq!(rep.sub_id, "sub-main");
        assert_eq!(rep.kept_count, 1);
        assert_eq!(rep.added_count, 1);
        assert_eq!(rep.replaced_count, 2);
        assert_eq!(rep.total_count, 2);
        // Deterministic ORDER BY id ASC puts "old-dup" before "old-keep", so "old-dup" is reused
        // and "old-keep" remaps to "old-dup".
        let kept_id = rep
            .id_remap
            .values()
            .next()
            .cloned()
            .expect("duplicate vanished node must be remapped");
        assert!(storage.get_node("old-gone").unwrap().is_none());
        let kept_node = storage.get_node(&kept_id).unwrap().expect("kept node exists");
        assert_eq!(kept_node.name, "JP Primary Renamed");
        assert_eq!(kept_node.sub_id, "sub-main");

        // Newer probe from vanished duplicate (`old-keep`, 28ms at 03:00) must migrate onto `old-dup`.
        let latest_probes = storage.latest_probe_results_for_node(&kept_id).unwrap();
        assert_eq!(latest_probes.len(), 1);
        assert_eq!(latest_probes[0].latency_ms, Some(28.0));

        // Multi-group must have deduplicated kept_id, removed old-gone, and valid active_node_id.
        let updated_grp = storage.get_multi_group("grp-upd").unwrap().unwrap();
        assert_eq!(updated_grp.member_node_ids, vec![kept_id.clone()]);
        assert_eq!(updated_grp.active_node_id, Some(kept_id.clone()));

        // MergeDedup: keeps all existing nodes, updates matching fingerprint in place preserving ID
        // & probe history, and inserts only unseen fingerprints.
        let incoming_merge = vec![
            sample_vless_node(
                "brand-new-id-matching-fp",
                "other-sub",
                "JP Primary V3",
                "203.0.113.11",
                443,
                "00000000-0000-4000-8000-000000000011",
                "/p1",
            ),
            sample_vless_node(
                "fresh-id-3",
                "other-sub",
                "US New Node",
                "198.51.100.33",
                443,
                "00000000-0000-4000-8000-000000000033",
                "/us",
            ),
        ];
        let merged = storage
            .update_subscription_nodes_with_mode(
                "sub-main",
                &incoming_merge,
                SubscriptionUpdateMode::MergeDedup,
            )
            .unwrap();
        assert_eq!(merged.kept_count, 1);
        assert_eq!(merged.replaced_count, 1);
        assert_eq!(merged.added_count, 1);
        assert_eq!(merged.total_count, 3);
        assert_eq!(
            storage.get_node(&kept_id).unwrap().unwrap().name,
            "JP Primary V3"
        );
        assert_eq!(
            storage
                .latest_probe_results_for_node(&kept_id)
                .unwrap()[0]
                .latency_ms,
            Some(28.0)
        );
        assert!(storage.get_node("fresh-id-3").unwrap().is_some());
    }

    #[test]
    fn merge_subscriptions_preserves_non_dup_ids_migrates_newer_probes_and_rewrites_groups_and_dynamic_filter() {
        let mut storage = Storage::open_in_memory().unwrap();
        storage.seed_builtin_probes().unwrap();
        storage
            .upsert_subscription(&sample_sub("sub-src", "Source Feed"))
            .unwrap();
        storage
            .upsert_subscription(&sample_sub("sub-tgt", "Target Feed"))
            .unwrap();
        storage
            .upsert_subscription(&sample_sub("sub-other", "Other Feed"))
            .unwrap();

        // Target has T_keep (203.0.113.20:443 uuid-1) and T_stay (203.0.113.21:443 uuid-2).
        let t_keep = sample_vless_node(
            "t-keep",
            "sub-tgt",
            "JP Target Shared",
            "203.0.113.20",
            443,
            "00000000-0000-4000-8000-000000000001",
            "/ws",
        );
        let t_stay = sample_vless_node(
            "t-stay",
            "sub-tgt",
            "JP Target Only",
            "203.0.113.21",
            443,
            "00000000-0000-4000-8000-000000000002",
            "/ws",
        );
        // Source has S_dup (same physical fingerprint as T_keep), S_move (unique), and
        // S_same_ip_diff_acct (same IP/port as T_keep but different UUID -> must NOT deduplicate!).
        let s_dup = sample_vless_node(
            "s-dup",
            "sub-src",
            "JP Source Shared Renamed",
            "203.0.113.20",
            443,
            "00000000-0000-4000-8000-000000000001",
            "/ws",
        );
        let s_move = sample_vless_node(
            "s-move",
            "sub-src",
            "SG Source Unique",
            "198.51.100.40",
            443,
            "00000000-0000-4000-8000-000000000003",
            "/sg",
        );
        let s_diff_acct = sample_vless_node(
            "s-diff-acct",
            "sub-src",
            "JP Shared IP Other Account",
            "203.0.113.20",
            443,
            "00000000-0000-4000-8000-000000000004",
            "/ws",
        );

        storage
            .upsert_nodes_batch(&[t_keep, t_stay, s_dup, s_move, s_diff_acct])
            .unwrap();

        // Probes:
        // - `builtin_latency`: S_dup (03:00, 18ms) is NEWER than T_keep (01:00, 65ms) -> T_keep gets 18ms.
        // - `builtin_google_cn`: T_keep (04:00, clean=true) is NEWER than S_dup (02:00, clean=false) -> T_keep keeps true.
        // - `builtin_upload`: only S_dup has it (02:30, 55 Mbps) -> T_keep inherits it.
        // - `s-move` probe must remain intact after sub_id update + source subscription deletion.
        storage
            .insert_probe_results_batch(&[
                ProbeResultRecord {
                    node_id: "t-keep".into(),
                    probe_id: "builtin_latency".into(),
                    tested_at: "2026-11-24T01:00:00Z".into(),
                    ok: true,
                    latency_ms: Some(65.0),
                    ..Default::default()
                },
                ProbeResultRecord {
                    node_id: "s-dup".into(),
                    probe_id: "builtin_latency".into(),
                    tested_at: "2026-11-24T03:00:00Z".into(),
                    ok: true,
                    latency_ms: Some(18.0),
                    ..Default::default()
                },
                ProbeResultRecord {
                    node_id: "t-keep".into(),
                    probe_id: "builtin_google_cn".into(),
                    tested_at: "2026-11-24T04:00:00Z".into(),
                    ok: true,
                    google_clean: Some(true),
                    ..Default::default()
                },
                ProbeResultRecord {
                    node_id: "s-dup".into(),
                    probe_id: "builtin_google_cn".into(),
                    tested_at: "2026-11-24T02:00:00Z".into(),
                    ok: false,
                    google_clean: Some(false),
                    ..Default::default()
                },
                ProbeResultRecord {
                    node_id: "s-dup".into(),
                    probe_id: "builtin_upload".into(),
                    tested_at: "2026-11-24T02:30:00Z".into(),
                    ok: true,
                    up_mbps: Some(55.0),
                    ..Default::default()
                },
                ProbeResultRecord {
                    node_id: "s-move".into(),
                    probe_id: "builtin_latency".into(),
                    tested_at: "2026-11-24T01:30:00Z".into(),
                    ok: true,
                    latency_ms: Some(25.0),
                    ..Default::default()
                },
            ])
            .unwrap();

        let grp = MultiGroup {
            id: "grp-merge".into(),
            name: "AI Pool".into(),
            member_node_ids: vec![
                "s-dup".into(),
                "t-keep".into(),
                "s-move".into(),
            ],
            active_node_id: Some("s-dup".into()),
            dynamic_filter: Some(DynamicFilterSpec {
                sub_ids: vec![
                    "sub-src".into(),
                    "sub-tgt".into(),
                    "sub-other".into(),
                ],
                ..Default::default()
            }),
            ..Default::default()
        };
        storage.upsert_multi_group(&grp).unwrap();

        // Guard: merging into self or missing IDs must fail cleanly.
        assert!(
            storage
                .merge_subscriptions("sub-src", "sub-src", None, true, false)
                .is_err()
        );
        assert!(
            storage
                .merge_subscriptions("sub-missing", "sub-tgt", None, true, false)
                .is_err()
        );

        let res = storage
            .merge_subscriptions(
                "sub-src",
                "sub-tgt",
                Some("Unified Migrated Pool"),
                true,
                true,
            )
            .unwrap();

        assert_eq!(res.source_sub_id, "sub-src");
        assert_eq!(res.target_sub_id, "sub-tgt");
        assert_eq!(res.moved_count, 2); // s-move + s-diff-acct
        assert_eq!(res.deduplicated_count, 1); // s-dup -> t-keep
        assert_eq!(res.total_count, 4);
        assert_eq!(res.id_remap.get("s-dup").map(String::as_str), Some("t-keep"));

        // Source subscription deleted; target renamed & converted to `migrated`.
        assert!(storage.get_subscription("sub-src").unwrap().is_none());
        let tgt_sub = storage.get_subscription("sub-tgt").unwrap().unwrap();
        assert_eq!(tgt_sub.name, "Unified Migrated Pool");
        assert_eq!(tgt_sub.kind, SubscriptionKind::Migrated);

        // Non-duplicate source nodes survived in place with original IDs and probe history.
        let moved = storage.get_node("s-move").unwrap().expect("s-move must survive");
        assert_eq!(moved.sub_id, "sub-tgt");
        assert_eq!(
            storage
                .latest_probe_results_for_node("s-move")
                .unwrap()[0]
                .latency_ms,
            Some(25.0)
        );
        let diff_acct = storage
            .get_node("s-diff-acct")
            .unwrap()
            .expect("distinct account on same IP/port must not be deduplicated");
        assert_eq!(diff_acct.sub_id, "sub-tgt");
        assert!(storage.get_node("s-dup").unwrap().is_none());

        // T_keep received newer latency (18ms), missing upload (55Mbps), and kept newer google_clean (true).
        let snap = storage.get_probe_snapshot("t-keep", None).unwrap().unwrap();
        assert_eq!(snap.probe_ping("builtin_latency"), Some(18.0));
        assert_eq!(snap.probe_up("builtin_upload"), Some(55.0));
        assert_eq!(snap.google_clean, Some(true));

        // Multi-group members deduplicated, active_node_id remapped, dynamic_filter.sub_ids rewritten.
        let updated_grp = storage.get_multi_group("grp-merge").unwrap().unwrap();
        assert_eq!(
            updated_grp.member_node_ids,
            vec!["t-keep".to_string(), "s-move".to_string()]
        );
        assert_eq!(updated_grp.active_node_id.as_deref(), Some("t-keep"));
        assert_eq!(
            updated_grp.dynamic_filter.unwrap().sub_ids,
            vec!["sub-tgt".to_string(), "sub-other".to_string()]
        );
    }

    #[test]
    fn migrates_v2_preaccel_relays_to_v3_and_preserves_speed_metrics_across_probe_updates() {
        let dir = std::env::temp_dir().join(format!("catcloud-db-mig-v3-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("legacy-v2.sqlite");

        // Build a legacy v2 SQLite database whose `preaccel_relays` table lacks
        // `last_up_mbps` and `last_down_mbps`.
        {
            let conn = Connection::open(&db_path).expect("create legacy v2 sqlite");
            conn.execute_batch(
                "
                CREATE TABLE preaccel_relays (
                    id TEXT PRIMARY KEY NOT NULL,
                    name TEXT NOT NULL,
                    provider TEXT NOT NULL DEFAULT '',
                    region TEXT NOT NULL DEFAULT '',
                    server TEXT NOT NULL,
                    port INTEGER NOT NULL DEFAULT 443,
                    protocol TEXT NOT NULL,
                    password TEXT NOT NULL DEFAULT '',
                    sni TEXT,
                    skip_cert_verify INTEGER NOT NULL DEFAULT 1,
                    priority INTEGER NOT NULL DEFAULT 100,
                    expires_at TEXT,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    last_probe_ms REAL,
                    last_mbps REAL
                );
                INSERT INTO preaccel_relays (
                    id, name, provider, region, server, port, protocol,
                    password, sni, skip_cert_verify, priority, enabled,
                    last_probe_ms, last_mbps
                ) VALUES (
                    'relay-v2-legacy', 'Legacy Relay 443', 'cloud-v2', 'CN-East',
                    '203.0.113.10', 443, 'anytls', 'placeholder-pass', NULL, 1, 10, 1,
                    22.5, 45.0
                );
                PRAGMA user_version = 2;
                ",
            )
            .expect("seed legacy v2 schema");
        }

        // First open: migrates v2 -> v3 idempotently without losing legacy rows.
        {
            let storage = Storage::open(&db_path).expect("open & migrate v2 db");
            assert_eq!(storage.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
            let relay = storage
                .get_preaccel_relay("relay-v2-legacy")
                .unwrap()
                .expect("legacy relay preserved");
            assert_eq!(relay.last_probe_ms, Some(22.5));
            assert_eq!(relay.last_mbps, Some(45.0));
            assert_eq!(relay.last_up_mbps, None);
            assert_eq!(relay.last_down_mbps, None);

            // Update speed metrics (updates latency, up, down, and mirrors up into last_mbps).
            assert!(
                storage
                    .update_preaccel_speed_metrics(
                        "relay-v2-legacy",
                        Some(18.2),
                        Some(64.5),
                        Some(195.8),
                    )
                    .unwrap()
            );
            let after_speed = storage
                .get_preaccel_relay("relay-v2-legacy")
                .unwrap()
                .unwrap();
            assert_eq!(after_speed.last_probe_ms, Some(18.2));
            assert_eq!(after_speed.last_up_mbps, Some(64.5));
            assert_eq!(after_speed.last_down_mbps, Some(195.8));
            assert_eq!(after_speed.last_mbps, Some(64.5));

            // COALESCE semantics: passing None preserves previously recorded values.
            assert!(
                storage
                    .update_preaccel_speed_metrics("relay-v2-legacy", Some(16.0), None, Some(210.0))
                    .unwrap()
            );
            let after_partial = storage
                .get_preaccel_relay("relay-v2-legacy")
                .unwrap()
                .unwrap();
            assert_eq!(after_partial.last_probe_ms, Some(16.0));
            assert_eq!(after_partial.last_up_mbps, Some(64.5));
            assert_eq!(after_partial.last_down_mbps, Some(210.0));
            assert_eq!(after_partial.last_mbps, Some(64.5));

            // Legacy latency probe update MUST NOT wipe out `last_up_mbps` / `last_down_mbps`.
            assert!(
                storage
                    .update_preaccel_probe_metrics("relay-v2-legacy", Some(14.0), None)
                    .unwrap()
            );
            let after_probe = storage
                .get_preaccel_relay("relay-v2-legacy")
                .unwrap()
                .unwrap();
            assert_eq!(after_probe.last_probe_ms, Some(14.0));
            assert_eq!(after_probe.last_mbps, None);
            assert_eq!(after_probe.last_up_mbps, Some(64.5));
            assert_eq!(after_probe.last_down_mbps, Some(210.0));
        }

        // Re-opening must be idempotent and retain all v3 columns and values.
        {
            let storage = Storage::open(&db_path).expect("reopen migrated v3 db");
            assert_eq!(storage.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
            let relays = storage.list_preaccel_relays(false).unwrap();
            assert_eq!(relays.len(), 1);
            assert_eq!(relays[0].last_up_mbps, Some(64.5));
            assert_eq!(relays[0].last_down_mbps, Some(210.0));
            assert!(!relays[0].supports_ipv6);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn migrates_v3_preaccel_relays_to_v4_with_supports_ipv6_default_and_roundtrip() {
        let dir = std::env::temp_dir().join(format!("catcloud-db-mig-v4-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("legacy-v3.sqlite");

        // Seed a legacy v3 database lacking `preaccel_relays.supports_ipv6`.
        {
            let conn = Connection::open(&db_path).expect("create legacy v3 sqlite");
            conn.execute_batch(
                "
                CREATE TABLE preaccel_relays (
                    id TEXT PRIMARY KEY NOT NULL,
                    name TEXT NOT NULL,
                    provider TEXT NOT NULL DEFAULT '',
                    region TEXT NOT NULL DEFAULT '',
                    server TEXT NOT NULL,
                    port INTEGER NOT NULL DEFAULT 443,
                    protocol TEXT NOT NULL,
                    password TEXT NOT NULL DEFAULT '',
                    sni TEXT,
                    skip_cert_verify INTEGER NOT NULL DEFAULT 1,
                    priority INTEGER NOT NULL DEFAULT 100,
                    expires_at TEXT,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    last_probe_ms REAL,
                    last_mbps REAL,
                    last_up_mbps REAL,
                    last_down_mbps REAL
                );
                INSERT INTO preaccel_relays (
                    id, name, provider, region, server, port, protocol,
                    password, sni, skip_cert_verify, priority, enabled,
                    last_probe_ms, last_mbps, last_up_mbps, last_down_mbps
                ) VALUES (
                    'relay-v3-legacy', 'Legacy V3 Relay', 'cloud-v3', 'CN-South',
                    '198.51.100.33', 443, 'anytls', 'placeholder-pass', NULL, 1, 10, 1,
                    19.5, 95.0, 95.0, 190.0
                );
                PRAGMA user_version = 3;
                ",
            )
            .expect("seed legacy v3 schema");
        }

        // First open: migrates v3 -> latest schema idempotently with supports_ipv6 defaulting to false.
        {
            let storage = Storage::open(&db_path).expect("open & migrate v3 db");
            assert_eq!(storage.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
            let mut relay = storage
                .get_preaccel_relay("relay-v3-legacy")
                .unwrap()
                .expect("legacy v3 relay preserved");
            assert!(!relay.supports_ipv6);
            assert_eq!(relay.last_up_mbps, Some(95.0));

            // Flip supports_ipv6 = true and verify roundtrip via get & list.
            relay.supports_ipv6 = true;
            storage.upsert_preaccel_relay(&relay).unwrap();
            let updated = storage
                .get_preaccel_relay("relay-v3-legacy")
                .unwrap()
                .unwrap();
            assert!(updated.supports_ipv6);
        }

        // Re-opening migrated database is idempotent and preserves supports_ipv6 == true.
        {
            let storage = Storage::open(&db_path).expect("reopen migrated v4 db");
            assert_eq!(storage.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
            let relays = storage.list_preaccel_relays(true).unwrap();
            assert_eq!(relays.len(), 1);
            assert!(relays[0].supports_ipv6);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn backup_db_snapshot_and_apply_atomic_commits_rolls_back_and_preserves_probe_results() {
        let mut storage = Storage::open_in_memory().unwrap();
        storage.seed_builtin_probes().unwrap();
        storage
            .upsert_subscription(&sample_sub("sub-bak", "Backup Sub"))
            .unwrap();
        storage
            .upsert_node(&sample_node("n-bak", "sub-bak", "JP", 1.0, "anytls", true, &[]))
            .unwrap();
        storage
            .insert_probe_result(&ProbeResultRecord {
                node_id: "n-bak".into(),
                probe_id: "builtin_latency".into(),
                tested_at: "2026-11-27T10:00:00Z".into(),
                ok: true,
                latency_ms: Some(36.0),
                ..Default::default()
            })
            .unwrap();

        let orig_group = MultiGroup {
            id: "grp-orig".into(),
            name: "Original Group".into(),
            member_node_ids: vec!["n-bak".into()],
            ..Default::default()
        };
        let orig_relay = PreAccelRelay {
            id: "relay-orig".into(),
            name: "Original Relay".into(),
            server: "203.0.113.10".into(),
            port: 443,
            protocol: "anytls".into(),
            password: "pw-orig".into(),
            enabled: true,
            ..Default::default()
        };
        storage.upsert_multi_group(&orig_group).unwrap();
        storage.upsert_preaccel_relay(&orig_relay).unwrap();

        let snap_before = storage.capture_backup_db_snapshot().unwrap();
        assert_eq!(snap_before.groups.len(), 1);
        assert_eq!(snap_before.relays.len(), 1);
        assert!(snap_before.probes.len() >= 9);

        // 1. Mid-batch error (empty relay ID) MUST roll back all writes including the new group.
        let new_group = MultiGroup {
            id: "grp-new".into(),
            name: "New Group".into(),
            ..Default::default()
        };
        let bad_relay = PreAccelRelay {
            id: "   ".into(),
            name: "Broken Relay".into(),
            ..Default::default()
        };
        assert!(
            storage
                .apply_backup_entities_atomic(&[new_group.clone()], &[bad_relay], &[], false)
                .is_err()
        );
        assert_eq!(storage.capture_backup_db_snapshot().unwrap(), snap_before);

        // 2. Valid atomic restore adds new group/relay/probe and heals stale built-in Windsurf.
        let new_relay = PreAccelRelay {
            id: "relay-new".into(),
            name: "New Relay".into(),
            server: "198.51.100.20".into(),
            port: 443,
            protocol: "anytls".into(),
            password: "pw-new".into(),
            enabled: true,
            ..Default::default()
        };
        let stale_ws = ProbeDefinition {
            id: "builtin_unlock_windsurf".into(),
            name: "Windsurf".into(),
            kind: ProbeKind::UnlockRegex,
            target_url: "https://windsurf.com".into(),
            method: "GET".into(),
            expected_status: Some(200),
            body_regex: None,
            payload_bytes: None,
            timeout_ms: 8000,
            builtin: true,
        };
        let extra_probe = ProbeDefinition {
            id: "custom_backup_probe".into(),
            name: "Backup Custom".into(),
            kind: ProbeKind::Latency,
            target_url: "https://example.invalid/204".into(),
            method: "GET".into(),
            expected_status: Some(204),
            body_regex: None,
            payload_bytes: None,
            timeout_ms: 5000,
            builtin: false,
        };
        storage
            .apply_backup_entities_atomic(
                &[new_group],
                &[new_relay],
                &[stale_ws, extra_probe],
                false,
            )
            .unwrap();
        assert!(storage.get_multi_group("grp-new").unwrap().is_some());
        assert!(storage.get_preaccel_relay("relay-new").unwrap().is_some());
        assert!(storage.get_probe_definition("custom_backup_probe").unwrap().is_some());
        let healed_ws = storage
            .get_probe_definition("builtin_unlock_windsurf")
            .unwrap()
            .unwrap();
        assert_eq!(healed_ws.expected_status, None);
        assert_eq!(healed_ws.method, "POST");
        assert_eq!(
            healed_ws.target_url,
            "https://server.codeium.com/exa.api_server_pb.ApiServerService/GetChatMessage"
        );
        assert_eq!(healed_ws.timeout_ms, 9000);

        // 3. Rollback with `replace_all = true` restores exact prior snapshot, removes added IDs,
        //    and MUST NOT cascade-delete existing `probe_results` for surviving probes!
        storage
            .apply_backup_entities_atomic(
                &snap_before.groups,
                &snap_before.relays,
                &snap_before.probes,
                true,
            )
            .unwrap();
        assert_eq!(storage.capture_backup_db_snapshot().unwrap(), snap_before);
        assert!(storage.get_multi_group("grp-new").unwrap().is_none());
        assert!(storage.get_preaccel_relay("relay-new").unwrap().is_none());
        assert!(storage.get_probe_definition("custom_backup_probe").unwrap().is_none());
        let surviving_results = storage.latest_probe_results_for_node("n-bak").unwrap();
        assert_eq!(surviving_results.len(), 1);
        assert_eq!(surviving_results[0].latency_ms, Some(36.0));
    }

    #[test]
    fn probe_results_mixed_timezone_rfc3339_normalized_for_sqlite_cold_read_order() {
        let mut storage = Storage::open_in_memory().unwrap();
        storage.seed_builtin_probes().unwrap();
        storage
            .upsert_subscription(&sample_sub("sub-tz", "TZ Sub"))
            .unwrap();
        storage
            .upsert_node(&sample_node("n-tz", "sub-tz", "JP", 1.0, "anytls", true, &[]))
            .unwrap();

        // Older instant written with +08:00 (lexicographically greater: "21:00:01+08:00" > "13:00:05Z"!)
        // Newer instant written with Z (13:00:05Z is 4 seconds AFTER 21:00:01+08:00 == 13:00:01Z).
        storage
            .insert_probe_results_batch(&[
                ProbeResultRecord {
                    node_id: "n-tz".into(),
                    probe_id: "builtin_latency".into(),
                    tested_at: "2026-11-27T21:00:01+08:00".into(),
                    ok: false,
                    latency_ms: None,
                    ..Default::default()
                },
                ProbeResultRecord {
                    node_id: "n-tz".into(),
                    probe_id: "builtin_latency".into(),
                    tested_at: "2026-11-27T13:00:05Z".into(),
                    ok: true,
                    latency_ms: Some(27.5),
                    ..Default::default()
                },
                ProbeResultRecord {
                    node_id: "n-tz".into(),
                    probe_id: "builtin_google_cn".into(),
                    tested_at: "2026-11-27T21:00:01.9+08:00".into(),
                    ok: false,
                    google_clean: Some(false),
                    ..Default::default()
                },
                ProbeResultRecord {
                    node_id: "n-tz".into(),
                    probe_id: "builtin_google_cn".into(),
                    tested_at: "2026-11-27T13:00:05.12Z".into(),
                    ok: true,
                    google_clean: Some(true),
                    ..Default::default()
                },
            ])
            .unwrap();

        let latest = storage.latest_probe_results_for_node("n-tz").unwrap();
        let lat_row = latest
            .iter()
            .find(|r| r.probe_id == "builtin_latency")
            .expect("latest latency row");
        assert!(lat_row.ok);
        assert_eq!(lat_row.latency_ms, Some(27.5));
        assert_eq!(lat_row.tested_at, "2026-11-27T13:00:05.000000Z");

        let snap = storage
            .get_probe_snapshot("n-tz", None)
            .unwrap()
            .expect("cold snapshot");
        assert!(snap.ok);
        assert_eq!(snap.latency_ms, Some(27.5));
        assert_eq!(snap.google_clean, Some(true));

        let batch = storage
            .get_probe_snapshots_batch(&["n-tz".to_string()], None)
            .unwrap();
        assert_eq!(batch.get("n-tz"), Some(&snap));

        let filtered = storage
            .query_nodes(&NodeFilter {
                google_clean_only: true,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "n-tz");
    }

    #[test]
    fn delete_subscription_and_delete_node_atomically_purge_ghost_members_active_and_dynamic_sub_ids()
    {
        let storage = Storage::open_in_memory().unwrap();
        storage
            .upsert_subscription(&sample_sub("sub-a", "Airport A"))
            .unwrap();
        storage
            .upsert_subscription(&sample_sub("sub-b", "Airport B"))
            .unwrap();
        storage
            .upsert_node(&sample_node("n-a1", "sub-a", "JP", 1.0, "anytls", true, &[]))
            .unwrap();
        storage
            .upsert_node(&sample_node("n-a2", "sub-a", "SG", 1.0, "anytls", true, &[]))
            .unwrap();
        storage
            .upsert_node(&sample_node("n-b1", "sub-b", "US", 1.0, "vless", true, &[]))
            .unwrap();
        storage
            .upsert_node(&sample_node("n-b2", "sub-b", "HK", 1.0, "vless", true, &[]))
            .unwrap();

        let grp_mixed = MultiGroup {
            id: "grp-mixed".into(),
            name: "Mixed Group".into(),
            member_node_ids: vec!["n-a1".into(), "n-a2".into(), "n-b1".into()],
            active_node_id: Some("n-a1".into()),
            ..MultiGroup::default()
        };
        let grp_only_a = MultiGroup {
            id: "grp-only-a".into(),
            name: "Only A".into(),
            member_node_ids: vec!["n-a1".into(), "n-a2".into()],
            active_node_id: Some("n-a2".into()),
            ..MultiGroup::default()
        };
        let grp_dyn = MultiGroup {
            id: "grp-dyn".into(),
            name: "Dynamic Pool".into(),
            member_node_ids: vec!["n-a1".into(), "n-b2".into()],
            active_node_id: Some("n-a1".into()),
            dynamic_filter: Some(DynamicFilterSpec {
                sub_ids: vec!["sub-a".into(), "sub-b".into()],
                ..DynamicFilterSpec::default()
            }),
            ..MultiGroup::default()
        };
        storage.upsert_multi_group(&grp_mixed).unwrap();
        storage.upsert_multi_group(&grp_only_a).unwrap();
        storage.upsert_multi_group(&grp_dyn).unwrap();

        // 1. Deleting `sub-a` must atomically purge all ghost member IDs, dangling active_node_id,
        //    and deleted `sub-a` from `dynamic_filter.sub_ids`.
        assert!(storage.delete_subscription("sub-a").unwrap());

        let mixed_after = storage.get_multi_group("grp-mixed").unwrap().unwrap();
        assert_eq!(mixed_after.member_node_ids, vec!["n-b1".to_string()]);
        assert_eq!(mixed_after.active_node_id, None);

        let only_a_after = storage.get_multi_group("grp-only-a").unwrap().unwrap();
        assert!(only_a_after.member_node_ids.is_empty());
        assert_eq!(only_a_after.active_node_id, None);

        let dyn_after = storage.get_multi_group("grp-dyn").unwrap().unwrap();
        assert_eq!(dyn_after.member_node_ids, vec!["n-b2".to_string()]);
        assert_eq!(dyn_after.active_node_id, None);
        assert_eq!(
            dyn_after
                .dynamic_filter
                .as_ref()
                .expect("dynamic filter retained")
                .sub_ids,
            vec!["sub-b".to_string()]
        );

        // 2. Deleting a single surviving node `n-b1` must also purge it from member_node_ids and active_node_id.
        let mut mixed_with_active = mixed_after;
        mixed_with_active.active_node_id = Some("n-b1".into());
        storage.upsert_multi_group(&mixed_with_active).unwrap();

        assert!(storage.delete_node("n-b1").unwrap());
        let mixed_final = storage.get_multi_group("grp-mixed").unwrap().unwrap();
        assert!(mixed_final.member_node_ids.is_empty());
        assert_eq!(mixed_final.active_node_id, None);
    }

    #[test]
    fn ensure_default_group_if_empty_refills_default_group_after_deleting_all_subscriptions_and_reimporting()
    {
        let storage = Storage::open_in_memory().unwrap();
        storage
            .upsert_subscription(&sample_sub("sub-1", "First Sub"))
            .unwrap();
        storage
            .upsert_node(&sample_node("n-1", "sub-1", "JP", 1.0, "anytls", true, &[]))
            .unwrap();

        // Initial creation builds "默认路线" populated with enabled nodes.
        let created_id = storage
            .ensure_default_group_if_empty()
            .unwrap()
            .expect("should create initial default group");
        let g0 = storage.get_multi_group(&created_id).unwrap().unwrap();
        assert_eq!(g0.name, "默认路线");
        assert_eq!(g0.member_node_ids, vec!["n-1".to_string()]);
        assert_eq!(g0.active_node_id.as_deref(), Some("n-1"));

        // Delete all subscriptions -> default group becomes empty with 0 ghost nodes.
        assert!(storage.delete_subscription("sub-1").unwrap());
        let g_empty = storage.get_multi_group(&created_id).unwrap().unwrap();
        assert!(g_empty.member_node_ids.is_empty());
        assert_eq!(g_empty.active_node_id, None);
        assert_eq!(storage.ensure_default_group_if_empty().unwrap(), None);

        // Re-import a new subscription -> existing clean "默认路线" is refilled in place (no duplicate group).
        storage
            .upsert_subscription(&sample_sub("sub-2", "Second Sub"))
            .unwrap();
        storage
            .upsert_node(&sample_node("n-2", "sub-2", "SG", 1.0, "vless", true, &[]))
            .unwrap();
        storage
            .upsert_node(&sample_node("n-3", "sub-2", "US", 1.0, "vless", true, &[]))
            .unwrap();

        let refilled_id = storage
            .ensure_default_group_if_empty()
            .unwrap()
            .expect("should refill existing default group");
        assert_eq!(refilled_id, created_id);
        let all_groups = storage.list_multi_groups().unwrap();
        assert_eq!(all_groups.len(), 1);
        let g_refilled = &all_groups[0];
        assert_eq!(g_refilled.member_node_ids.len(), 2);
        assert!(g_refilled.member_node_ids.contains(&"n-2".to_string()));
        assert!(g_refilled.member_node_ids.contains(&"n-3".to_string()));
        assert!(
            g_refilled
                .active_node_id
                .as_deref()
                .is_some_and(|aid| aid == "n-2" || aid == "n-3")
        );
    }

    #[test]
    fn ensure_default_group_if_empty_never_pollutes_match_rules_independent_or_dynamic_filter_empty_groups()
    {
        // Case A: Only custom match_rules / independent_routing empty groups exist ->
        // must NOT pollute them; creates a separate clean "默认路线" instead.
        let storage_a = Storage::open_in_memory().unwrap();
        storage_a
            .upsert_subscription(&sample_sub("sub-x", "Sub X"))
            .unwrap();
        storage_a
            .upsert_node(&sample_node("n-x1", "sub-x", "JP", 1.0, "anytls", true, &[]))
            .unwrap();
        let ruled_empty = MultiGroup {
            id: "grp-ai-rules".into(),
            name: "AI 专用".into(),
            match_rules: vec!["DOMAIN-SUFFIX,openai.com".into()],
            member_node_ids: Vec::new(),
            active_node_id: None,
            ..MultiGroup::default()
        };
        let indep_empty = MultiGroup {
            id: "grp-indep".into(),
            name: "默认路线 独立路由".into(),
            independent_routing: true,
            member_node_ids: Vec::new(),
            active_node_id: None,
            ..MultiGroup::default()
        };
        storage_a.upsert_multi_group(&ruled_empty).unwrap();
        storage_a.upsert_multi_group(&indep_empty).unwrap();

        let created_id = storage_a
            .ensure_default_group_if_empty()
            .unwrap()
            .expect("should create clean default group without touching ruled/independent groups");
        assert_ne!(created_id, "grp-ai-rules");
        assert_ne!(created_id, "grp-indep");

        let ai_after = storage_a.get_multi_group("grp-ai-rules").unwrap().unwrap();
        assert!(ai_after.member_node_ids.is_empty());
        assert_eq!(ai_after.active_node_id, None);

        let indep_after = storage_a.get_multi_group("grp-indep").unwrap().unwrap();
        assert!(indep_after.member_node_ids.is_empty());
        assert_eq!(indep_after.active_node_id, None);

        let created = storage_a.get_multi_group(&created_id).unwrap().unwrap();
        assert_eq!(created.name, "默认路线");
        assert_eq!(created.member_node_ids, vec!["n-x1".to_string()]);
        assert_eq!(created.active_node_id.as_deref(), Some("n-x1"));

        // Case B: A group with `dynamic_filter` exists -> do not touch any group or create a new one.
        let storage_b = Storage::open_in_memory().unwrap();
        storage_b
            .upsert_subscription(&sample_sub("sub-y", "Sub Y"))
            .unwrap();
        storage_b
            .upsert_node(&sample_node("n-y1", "sub-y", "SG", 1.0, "vless", true, &[]))
            .unwrap();
        let dyn_group = MultiGroup {
            id: "grp-dynamic".into(),
            name: "动态筛选组".into(),
            member_node_ids: Vec::new(),
            dynamic_filter: Some(DynamicFilterSpec {
                region_codes: vec!["SG".into()],
                ..DynamicFilterSpec::default()
            }),
            ..MultiGroup::default()
        };
        let static_empty = MultiGroup {
            id: "grp-static-empty".into(),
            name: "默认路线".into(),
            member_node_ids: Vec::new(),
            ..MultiGroup::default()
        };
        storage_b.upsert_multi_group(&dyn_group).unwrap();
        storage_b.upsert_multi_group(&static_empty).unwrap();

        assert_eq!(storage_b.ensure_default_group_if_empty().unwrap(), None);
        assert!(
            storage_b
                .get_multi_group("grp-dynamic")
                .unwrap()
                .unwrap()
                .member_node_ids
                .is_empty()
        );
        assert!(
            storage_b
                .get_multi_group("grp-static-empty")
                .unwrap()
                .unwrap()
                .member_node_ids
                .is_empty()
        );
    }

    #[test]
    fn migrates_v4_probe_results_to_v5_and_upgrades_legacy_windsurf_probe_losslessly() {
        let dir = std::env::temp_dir().join(format!("catcloud-db-mig-v5-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("legacy-v4.sqlite");

        // Build a realistic v4 database whose `probe_results` lacks the 4 IP purity columns and
        // whose `builtin_unlock_windsurf` still uses the legacy `GET https://windsurf.com == 200`.
        {
            let conn = Connection::open(&db_path).expect("create legacy v4 sqlite");
            conn.execute_batch(
                "
                CREATE TABLE subscriptions (
                    id TEXT PRIMARY KEY NOT NULL,
                    name TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    url_or_cmd TEXT NOT NULL,
                    refresh_interval_sec INTEGER NOT NULL DEFAULT 3600,
                    traffic_used INTEGER NOT NULL DEFAULT 0,
                    traffic_total INTEGER NOT NULL DEFAULT 0,
                    expires_at TEXT,
                    etag TEXT,
                    last_ok_at TEXT,
                    last_error TEXT,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    updated_at TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE nodes (
                    id TEXT PRIMARY KEY NOT NULL,
                    sub_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    server TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    raw_json TEXT NOT NULL,
                    region_code TEXT NOT NULL DEFAULT 'UNK',
                    multiplier REAL NOT NULL DEFAULT 1.0,
                    is_443_native INTEGER NOT NULL DEFAULT 0,
                    preaccel_eligible INTEGER NOT NULL DEFAULT 1,
                    preaccel_override INTEGER,
                    tags_json TEXT NOT NULL DEFAULT '[]',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    FOREIGN KEY (sub_id) REFERENCES subscriptions(id) ON DELETE CASCADE
                );
                CREATE TABLE probe_definitions (
                    id TEXT PRIMARY KEY NOT NULL,
                    name TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    method TEXT NOT NULL DEFAULT 'GET',
                    expected_status INTEGER,
                    body_regex TEXT,
                    payload_bytes INTEGER,
                    timeout_ms INTEGER NOT NULL DEFAULT 8000,
                    builtin INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE probe_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    node_id TEXT NOT NULL,
                    probe_id TEXT NOT NULL,
                    tested_at TEXT NOT NULL,
                    ok INTEGER NOT NULL DEFAULT 0,
                    latency_ms REAL,
                    jitter_ms REAL,
                    loss_pct REAL,
                    up_mbps REAL,
                    down_mbps REAL,
                    cf_loc TEXT,
                    yt_gl TEXT,
                    google_clean INTEGER,
                    keepalive_60s_ok INTEGER,
                    unlocked_map_json TEXT NOT NULL DEFAULT '{}',
                    detail TEXT,
                    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
                    FOREIGN KEY (probe_id) REFERENCES probe_definitions(id) ON DELETE CASCADE
                );
                INSERT INTO subscriptions (id, name, kind, url_or_cmd) VALUES ('sub-v4', 'V4 Sub', 'url', 'https://example.invalid/sub');
                INSERT INTO nodes (id, sub_id, name, protocol, server, port, raw_json, region_code)
                    VALUES ('n-v4', 'sub-v4', 'TW Legacy', 'trojan', '198.51.100.44', 443, '{}', 'TW');
                INSERT INTO probe_definitions (id, name, kind, target_url, method, expected_status, body_regex, timeout_ms, builtin)
                    VALUES ('builtin_unlock_windsurf', 'Windsurf / Codeium Reachability', 'unlock_regex', 'https://windsurf.com/', 'GET', 200, NULL, 8000, 1);
                INSERT INTO probe_results (node_id, probe_id, tested_at, ok, latency_ms, unlocked_map_json, detail)
                    VALUES ('n-v4', 'builtin_unlock_windsurf', '2026-11-27T12:00:00.000000Z', 1, 280.0, '{\"windsurf\":true}', 'site=windsurf, status=200, status_ok=true, regex_ok=true');
                PRAGMA user_version = 4;
                ",
            )
            .expect("seed legacy v4 schema");
        }

        // 1. Open migrates v4 -> v5 losslessly; legacy probe row reads back with 4 IP fields None.
        {
            let mut storage = Storage::open(&db_path).expect("open & migrate v4 db");
            assert_eq!(storage.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
            let legacy_rows = storage.latest_probe_results_for_node("n-v4").unwrap();
            assert_eq!(legacy_rows.len(), 1);
            assert!(legacy_rows[0].ok);
            assert_eq!(legacy_rows[0].ip_clean, None);
            assert_eq!(legacy_rows[0].ip_risk_level, None);
            assert_eq!(legacy_rows[0].ip_asn, None);
            assert_eq!(legacy_rows[0].ip_risk_flags, None);

            // 2. Seeding built-in probes upgrades legacy `builtin_unlock_windsurf` to semantic POST.
            storage.seed_builtin_probes().unwrap();
            let ws_def = storage
                .get_probe_definition("builtin_unlock_windsurf")
                .unwrap()
                .expect("windsurf def present");
            assert_eq!(ws_def.name, "Windsurf / Devin AI 纯净解锁");
            assert_eq!(
                ws_def.target_url,
                "https://server.codeium.com/exa.api_server_pb.ApiServerService/GetChatMessage"
            );
            assert_eq!(ws_def.method, "POST");
            assert_eq!(ws_def.expected_status, None);
            assert_eq!(ws_def.timeout_ms, 9000);

            // 3. Inserting a v5 semantic Windsurf result round-trips all 4 IP purity columns via
            //    both `latest_probe_results_for_node` and `get_probe_snapshots_batch`.
            let mut unlocked = HashMap::new();
            unlocked.insert("windsurf".to_string(), false);
            storage
                .insert_probe_result(&ProbeResultRecord {
                    node_id: "n-v4".into(),
                    probe_id: "builtin_unlock_windsurf".into(),
                    tested_at: "2026-11-28T06:00:00Z".into(),
                    ok: false,
                    latency_ms: Some(145.0),
                    unlocked_map: unlocked,
                    detail: Some(
                        "semantic_windsurf: unlocked=false, reason=high_risk_proxy_ip, api=ok(status=415), ip_risk=proxy_risk, flags=[proxy,datacenter], asn=AS38136 Akari Networks, cc=TW"
                            .into(),
                    ),
                    ip_clean: Some(false),
                    ip_risk_level: Some("proxy_risk".into()),
                    ip_asn: Some("AS38136 Akari Networks".into()),
                    ip_risk_flags: Some("proxy,datacenter".into()),
                    ..Default::default()
                })
                .unwrap();

            let latest = storage.latest_probe_results_for_node("n-v4").unwrap();
            assert_eq!(latest.len(), 1);
            assert!(!latest[0].ok);
            assert_eq!(latest[0].ip_clean, Some(false));
            assert_eq!(latest[0].ip_risk_level.as_deref(), Some("proxy_risk"));
            assert_eq!(latest[0].ip_asn.as_deref(), Some("AS38136 Akari Networks"));
            assert_eq!(latest[0].ip_risk_flags.as_deref(), Some("proxy,datacenter"));

            let batch = storage
                .get_probe_snapshots_batch(&["n-v4".to_string()], None)
                .unwrap();
            let snap = batch.get("n-v4").expect("snapshot present");
            assert_eq!(snap.ip_clean, Some(false));
            assert_eq!(snap.ip_risk_level.as_deref(), Some("proxy_risk"));
            assert_eq!(snap.ip_asn.as_deref(), Some("AS38136 Akari Networks"));
            assert_eq!(snap.ip_risk_flags.as_deref(), Some("proxy,datacenter"));
            assert_eq!(snap.unlocked_sites.get("windsurf"), Some(&false));
        }

        // 4. Re-opening migrated v5 DB is idempotent and retains all 4 IP columns.
        {
            let storage = Storage::open(&db_path).expect("reopen migrated v5 db");
            assert_eq!(storage.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
            let snap = storage
                .get_probe_snapshot("n-v4", None)
                .unwrap()
                .expect("persisted snapshot");
            assert_eq!(snap.ip_clean, Some(false));
            assert_eq!(snap.ip_risk_level.as_deref(), Some("proxy_risk"));
            assert_eq!(snap.ip_asn.as_deref(), Some("AS38136 Akari Networks"));
            assert_eq!(snap.ip_risk_flags.as_deref(), Some("proxy,datacenter"));
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn node_summary_lightweight_projections_memory_pragmas_and_compact_memory_work() {
        let dir = std::env::temp_dir().join(format!("catcloud-db-summary-{}", Uuid::new_v4()));
        let db_path = dir.join("summary.sqlite");
        let mut storage = Storage::open(&db_path).expect("open sqlite for summary test");

        // 1. Verify H4 SQLite memory-cap PRAGMAs without breaking existing WAL/FK/busy_timeout.
        let cache_size: i64 = storage
            .connection()
            .query_row("PRAGMA cache_size;", [], |r| r.get(0))
            .unwrap();
        let mmap_size: i64 = storage
            .connection()
            .query_row("PRAGMA mmap_size;", [], |r| r.get(0))
            .unwrap();
        let wal_auto: i64 = storage
            .connection()
            .query_row("PRAGMA wal_autocheckpoint;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(cache_size, -1024);
        assert_eq!(mmap_size, 0);
        assert_eq!(wal_auto, 200);
        assert_eq!(storage.journal_mode().unwrap().to_ascii_lowercase(), "wal");
        assert!(storage.foreign_keys_enabled().unwrap());
        assert_eq!(storage.busy_timeout_ms().unwrap(), 5000);

        // 2. Empty database checks.
        assert!(!storage.has_enabled_nodes().unwrap());
        assert!(storage.list_node_ids().unwrap().is_empty());
        assert!(storage.list_node_summaries().unwrap().is_empty());
        assert_eq!(storage.get_node_name("missing").unwrap(), None);

        storage
            .upsert_subscription(&sample_sub("sub-s1", "Summary Feed"))
            .unwrap();

        // 3. Disabled-only node keeps `has_enabled_nodes() == false`.
        let mut disabled_node = sample_node("n-off", "sub-s1", "US", 1.0, "trojan", false, &[]);
        disabled_node.enabled = false;
        disabled_node.server = "198.51.100.11".to_string();
        storage.upsert_node(&disabled_node).unwrap();
        assert!(!storage.has_enabled_nodes().unwrap());
        assert_eq!(
            storage.get_node_name("n-off").unwrap().as_deref(),
            Some("US-trojan-n-off")
        );

        // 4. Insert IPv6-only (`raw_json["ip-version"] == "ipv6-only"`), dual-stack, and forced-override nodes.
        let mut v6_node = sample_node("n-v6", "sub-s1", "JP", 1.0, "vless", false, &["ai"]);
        v6_node.server = "203.0.113.12".to_string();
        v6_node.preaccel_eligible = true;
        v6_node.preaccel_override = Some(false);
        v6_node.raw_config = serde_json::json!({
            "name": v6_node.name,
            "type": "vless",
            "server": "203.0.113.12",
            "port": 20443,
            "ip-version": "ipv6-only"
        });

        let mut dual_node = sample_node("n-dual", "sub-s1", "HK", 0.5, "anytls", true, &[]);
        dual_node.server = "198.51.100.22".to_string();
        dual_node.preaccel_eligible = false;
        dual_node.preaccel_override = Some(true);
        dual_node.raw_config = serde_json::json!({
            "name": dual_node.name,
            "type": "anytls",
            "server": "198.51.100.22",
            "port": 443,
            "ip-version": "dual"
        });

        // Node with empty `server` column but valid IPv6 in `raw_json["server"]`.
        let mut fallback_srv_node = sample_node("n-fb", "sub-s1", "SG", 1.5, "ss", false, &[]);
        fallback_srv_node.server = String::new();
        fallback_srv_node.raw_config = serde_json::json!({
            "name": fallback_srv_node.name,
            "type": "ss",
            "server": "2001:db8::99",
            "port": 20443
        });

        storage
            .upsert_nodes_batch(&[v6_node.clone(), dual_node.clone(), fallback_srv_node.clone()])
            .unwrap();

        // Corrupt one row's `raw_json` directly in SQLite to verify dirty-data resilience.
        storage
            .connection()
            .execute(
                "UPDATE nodes SET raw_json = '{not-valid-json' WHERE id = ?1",
                params!["n-off"],
            )
            .unwrap();

        assert!(storage.has_enabled_nodes().unwrap());
        assert_eq!(
            storage.list_node_ids().unwrap(),
            vec![
                "n-dual".to_string(),
                "n-fb".to_string(),
                "n-off".to_string(),
                "n-v6".to_string()
            ]
        );
        assert_eq!(
            storage.get_node_name("n-v6").unwrap().as_deref(),
            Some("JP-vless-n-v6")
        );

        let full_nodes = storage.list_nodes().unwrap();
        let summaries = storage.list_node_summaries().unwrap();
        assert_eq!(summaries.len(), full_nodes.len());
        let full_ids: Vec<&str> = full_nodes.iter().map(|n| n.id.as_str()).collect();
        let summary_ids: Vec<&str> = summaries.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(summary_ids, full_ids);

        let sum_v6 = summaries.iter().find(|n| n.id == "n-v6").unwrap();
        assert_eq!(sum_v6.sub_id, "sub-s1");
        assert_eq!(sum_v6.region_code, "JP");
        assert!(sum_v6.enabled);
        assert_eq!(sum_v6.protocol, "vless");
        assert_eq!(sum_v6.server, "203.0.113.12");
        assert_eq!(sum_v6.port, 20443);
        assert_eq!(sum_v6.multiplier, 1.0);
        assert!(!sum_v6.is_443_native);
        assert!(sum_v6.preaccel_eligible);
        assert_eq!(sum_v6.preaccel_override, Some(false));
        assert_eq!(sum_v6.raw_ip_version.as_deref(), Some("ipv6-only"));
        assert!(crate::models::is_ipv6_only_node_fields(
            &sum_v6.server,
            sum_v6.raw_ip_version.as_deref()
        ));
        assert!(sum_v6.is_ipv6_only());

        let sum_dual = summaries.iter().find(|n| n.id == "n-dual").unwrap();
        assert_eq!(sum_dual.raw_ip_version.as_deref(), Some("dual"));
        assert!(!sum_dual.is_ipv6_only());
        assert!(!sum_dual.preaccel_eligible);
        assert_eq!(sum_dual.preaccel_override, Some(true));
        assert!(sum_dual.should_apply_preaccel(true));

        let sum_fb = summaries.iter().find(|n| n.id == "n-fb").unwrap();
        assert_eq!(sum_fb.server, "2001:db8::99");
        assert!(sum_fb.is_ipv6_only());

        let sum_dirty = summaries.iter().find(|n| n.id == "n-off").unwrap();
        assert_eq!(sum_dirty.raw_ip_version, None);
        assert!(!sum_dirty.enabled);

        // 5. `compact_memory()` flushes prepared statement cache, checkpoints WAL, and shrinks memory
        //    cleanly without breaking subsequent cached queries.
        storage.compact_memory();
        assert!(storage.has_enabled_nodes().unwrap());
        assert_eq!(storage.list_node_summaries().unwrap().len(), 4);
        assert_eq!(
            storage.get_node_name("n-dual").unwrap().as_deref(),
            Some("HK-anytls-n-dual")
        );

        drop(storage);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
