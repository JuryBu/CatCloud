use crate::error::{CatError, CatResult};
use crate::models::{
    DynamicFilterSpec, FallbackPolicy, MultiGroup, MultiGroupMode, MultiGroupState, NodeFilter,
    PreAccelRelay, ProbeDefinition, ProbeKind, ProbeResultRecord, ProbeSnapshot, ProxyNode,
    SubscriptionKind, SubscriptionRecord, SwitchMode, TriggerRule,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, params, params_from_iter};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Current SQLite schema version tracked via `PRAGMA user_version`.
pub const CURRENT_SCHEMA_VERSION: u32 = 2;

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
            ",
        )?;
        Ok(())
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
        self.conn
            .query_row(
                "
                SELECT id, name, kind, url_or_cmd, refresh_interval_sec,
                       traffic_used, traffic_total, expires_at, etag,
                       last_ok_at, last_error, enabled
                FROM subscriptions
                WHERE id = ?1
                ",
                params![id],
                row_to_subscription,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_subscriptions(&self) -> CatResult<Vec<SubscriptionRecord>> {
        let mut stmt = self.conn.prepare(
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
        let changed = self
            .conn
            .execute("DELETE FROM subscriptions WHERE id = ?1", params![id])?;
        Ok(changed > 0)
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

            for old_id in existing_ids {
                if !incoming_ids.contains(old_id.as_str()) {
                    tx.execute("DELETE FROM nodes WHERE id = ?1", params![old_id])?;
                }
            }

            for node in new_nodes {
                upsert_node_with_conn(tx, node)?;
            }

            Ok(new_nodes.len())
        })
    }

    pub fn get_node(&self, id: &str) -> CatResult<Option<ProxyNode>> {
        self.conn
            .query_row(
                "
                SELECT id, sub_id, name, protocol, server, port, raw_json,
                       region_code, multiplier, is_443_native, preaccel_eligible,
                       preaccel_override, tags_json, enabled
                FROM nodes
                WHERE id = ?1
                ",
                params![id],
                row_to_node,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_nodes(&self) -> CatResult<Vec<ProxyNode>> {
        self.query_nodes(&NodeFilter::default())
    }

    pub fn delete_node(&self, id: &str) -> CatResult<bool> {
        let changed = self
            .conn
            .execute("DELETE FROM nodes WHERE id = ?1", params![id])?;
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
        if def.id.trim().is_empty() {
            return Err(CatError::Validation("probe definition id cannot be empty".into()));
        }
        self.conn.execute(
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

    /// Seed built-in probe definitions without overwriting user-modified rows, and migrate
    /// legacy built-in AI unlock probes (when `builtin = 1` and `body_regex IS NULL`) to
    /// credential-free semantic probing (`expected_status = NULL` + latest `target_url`/`method`).
    pub fn seed_builtin_probes(&mut self) -> CatResult<usize> {
        let builtins = ProbeDefinition::builtin_defaults();
        self.in_transaction(|tx| {
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
                if changed == 0
                    && matches!(
                        def.id.as_str(),
                        "builtin_unlock_claude"
                            | "builtin_unlock_chatgpt"
                            | "builtin_unlock_gemini"
                    )
                {
                    tx.execute(
                        "
                        UPDATE probe_definitions
                        SET expected_status = NULL,
                            target_url = ?2,
                            method = ?3
                        WHERE id = ?1
                          AND builtin = 1
                          AND (body_regex IS NULL OR TRIM(body_regex) = '')
                          AND (expected_status IS NOT NULL OR target_url != ?2 OR method != ?3)
                        ",
                        params![def.id, def.target_url, def.method],
                    )?;
                }
                inserted += changed;
            }
            Ok(inserted)
        })
    }

    pub fn get_probe_definition(&self, id: &str) -> CatResult<Option<ProbeDefinition>> {
        self.conn
            .query_row(
                "
                SELECT id, name, kind, target_url, method, expected_status,
                       body_regex, payload_bytes, timeout_ms, builtin
                FROM probe_definitions
                WHERE id = ?1
                ",
                params![id],
                row_to_probe_def,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_probe_definitions(&self) -> CatResult<Vec<ProbeDefinition>> {
        let mut stmt = self.conn.prepare(
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
        let mut stmt = self.conn.prepare(
            "
            SELECT node_id, probe_id, tested_at, ok, latency_ms, jitter_ms, loss_pct,
                   up_mbps, down_mbps, cf_loc, yt_gl, google_clean, keepalive_60s_ok,
                   unlocked_map_json, detail
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
        Ok(Some(ProbeSnapshot::from_results(
            node_id,
            &latest,
            primary_probe_id,
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
        let placeholders = make_placeholders(node_ids.len());
        let sql = format!(
            "
            SELECT node_id, probe_id, tested_at, ok, latency_ms, jitter_ms, loss_pct,
                   up_mbps, down_mbps, cf_loc, yt_gl, google_clean, keepalive_60s_ok,
                   unlocked_map_json, detail
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
                ProbeSnapshot::from_results(&nid, &recs, primary_probe_id),
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

        self.conn.execute(
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

    pub fn get_multi_group(&self, id: &str) -> CatResult<Option<MultiGroup>> {
        self.conn
            .query_row(
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
                params![id],
                row_to_multi_group,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_multi_groups(&self) -> CatResult<Vec<MultiGroup>> {
        let mut stmt = self.conn.prepare(
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
        let changed = self
            .conn
            .execute("DELETE FROM multi_groups WHERE id = ?1", params![id])?;
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

    // -------------------------------------------------------------------------
    // 6. Domestic Pre-Acceleration Relays CRUD
    // -------------------------------------------------------------------------

    pub fn upsert_preaccel_relay(&self, relay: &PreAccelRelay) -> CatResult<()> {
        if relay.id.trim().is_empty() {
            return Err(CatError::Validation(
                "preaccel_relay id cannot be empty".into(),
            ));
        }
        self.conn.execute(
            "
            INSERT INTO preaccel_relays (
                id, name, provider, region, server, port, protocol,
                password, sni, skip_cert_verify, priority, expires_at,
                enabled, last_probe_ms, last_mbps
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
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
                last_mbps = excluded.last_mbps
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
            ],
        )?;
        Ok(())
    }

    pub fn get_preaccel_relay(&self, id: &str) -> CatResult<Option<PreAccelRelay>> {
        self.conn
            .query_row(
                "
                SELECT id, name, provider, region, server, port, protocol,
                       password, sni, skip_cert_verify, priority, expires_at,
                       enabled, last_probe_ms, last_mbps
                FROM preaccel_relays
                WHERE id = ?1
                ",
                params![id],
                row_to_preaccel_relay,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_preaccel_relays(&self, enabled_only: bool) -> CatResult<Vec<PreAccelRelay>> {
        let sql = if enabled_only {
            "
            SELECT id, name, provider, region, server, port, protocol,
                   password, sni, skip_cert_verify, priority, expires_at,
                   enabled, last_probe_ms, last_mbps
            FROM preaccel_relays
            WHERE enabled = 1
            ORDER BY priority ASC, id ASC
            "
        } else {
            "
            SELECT id, name, provider, region, server, port, protocol,
                   password, sni, skip_cert_verify, priority, expires_at,
                   enabled, last_probe_ms, last_mbps
            FROM preaccel_relays
            ORDER BY priority ASC, id ASC
            "
        };
        let mut stmt = self.conn.prepare(sql)?;
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
    last_mbps REAL
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

fn insert_probe_result_with_conn(conn: &Connection, rec: &ProbeResultRecord) -> CatResult<i64> {
    let unlocked_map_json = serde_json::to_string(&rec.unlocked_map)?;
    conn.execute(
        "
        INSERT INTO probe_results (
            node_id, probe_id, tested_at, ok, latency_ms, jitter_ms, loss_pct,
            up_mbps, down_mbps, cf_loc, yt_gl, google_clean, keepalive_60s_ok,
            unlocked_map_json, detail
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
        ",
        params![
            rec.node_id,
            rec.probe_id,
            rec.tested_at,
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
    })
}

fn bool_to_int(v: bool) -> i64 {
    if v { 1 } else { 0 }
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
}
