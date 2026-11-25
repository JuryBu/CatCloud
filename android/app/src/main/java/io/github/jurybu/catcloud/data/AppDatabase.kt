package io.github.jurybu.catcloud.data

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream

/**
 * Single-writer SQLite store exclusively owned by the `:ui` process.
 *
 * The `:vpn` process NEVER opens this database; `:ui` atomically compiles `runtime_config.yaml`
 * (`0600`) and `vpn_boot_snapshot.json` (`0600`) for `:vpn` to read safely.
 */
class AppDatabase(private val appContext: Context) : SQLiteOpenHelper(
    appContext,
    DB_NAME,
    null,
    DB_VERSION,
) {

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS nodes (
                id TEXT PRIMARY KEY,
                sub_id TEXT NOT NULL,
                name TEXT NOT NULL,
                protocol TEXT NOT NULL,
                server TEXT NOT NULL,
                port INTEGER NOT NULL,
                raw_config_json TEXT NOT NULL,
                region_code TEXT NOT NULL,
                multiplier REAL NOT NULL,
                is_443_native INTEGER NOT NULL,
                preaccel_eligible INTEGER NOT NULL,
                preaccel_override INTEGER,
                tags_json TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                fingerprint TEXT NOT NULL,
                last_latency_ms INTEGER,
                last_down_mbps REAL,
                last_up_mbps REAL
            )
            """.trimIndent()
        )
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_nodes_fp ON nodes(fingerprint)")

        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS relays (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                provider TEXT NOT NULL,
                region TEXT NOT NULL,
                server TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                password TEXT NOT NULL,
                sni TEXT,
                skip_cert_verify INTEGER NOT NULL,
                priority INTEGER NOT NULL,
                expires_at TEXT,
                enabled INTEGER NOT NULL,
                last_probe_ms INTEGER
            )
            """.trimIndent()
        )

        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS groups (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                mode TEXT NOT NULL,
                match_rules_json TEXT NOT NULL,
                member_node_ids_json TEXT NOT NULL,
                dynamic_filter_json TEXT,
                primary_probe_id TEXT,
                hard_gates_json TEXT NOT NULL,
                trigger_rules_json TEXT NOT NULL,
                formula_expr TEXT NOT NULL,
                fallback_policy TEXT NOT NULL,
                fallback_pool_id TEXT,
                recover_probe_interval_sec INTEGER NOT NULL,
                switch_mode TEXT NOT NULL,
                cooldown_sec INTEGER NOT NULL,
                hysteresis_pct REAL NOT NULL,
                active_node_id TEXT,
                independent_routing INTEGER NOT NULL
            )
            """.trimIndent()
        )

        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS settings (
                k TEXT PRIMARY KEY,
                v TEXT NOT NULL
            )
            """.trimIndent()
        )

        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS relay_box (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                expires_at_ms INTEGER NOT NULL,
                zip_fp TEXT NOT NULL,
                payload_bytes BLOB NOT NULL,
                size_bytes INTEGER NOT NULL,
                node_count INTEGER NOT NULL,
                relay_count INTEGER NOT NULL,
                group_count INTEGER NOT NULL
            )
            """.trimIndent()
        )
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        onCreate(db)
    }

    // ---- Nodes ----

    fun listNodes(): List<ProxyNodeRecord> {
        val out = ArrayList<ProxyNodeRecord>()
        readableDatabase.rawQuery("SELECT * FROM nodes ORDER BY rowid ASC", null).use { c ->
            while (c.moveToNext()) {
                val overrideIdx = c.getColumnIndexOrThrow("preaccel_override")
                val latIdx = c.getColumnIndexOrThrow("last_latency_ms")
                val downIdx = c.getColumnIndexOrThrow("last_down_mbps")
                val upIdx = c.getColumnIndexOrThrow("last_up_mbps")
                out.add(
                    ProxyNodeRecord(
                        id = c.getString(c.getColumnIndexOrThrow("id")),
                        subId = c.getString(c.getColumnIndexOrThrow("sub_id")),
                        name = c.getString(c.getColumnIndexOrThrow("name")),
                        protocol = c.getString(c.getColumnIndexOrThrow("protocol")),
                        server = c.getString(c.getColumnIndexOrThrow("server")),
                        port = c.getInt(c.getColumnIndexOrThrow("port")),
                        rawConfigJson = c.getString(c.getColumnIndexOrThrow("raw_config_json")),
                        regionCode = c.getString(c.getColumnIndexOrThrow("region_code")),
                        multiplier = c.getDouble(c.getColumnIndexOrThrow("multiplier")),
                        is443Native = c.getInt(c.getColumnIndexOrThrow("is_443_native")) != 0,
                        preaccelEligible = c.getInt(c.getColumnIndexOrThrow("preaccel_eligible")) != 0,
                        preaccelOverride = if (c.isNull(overrideIdx)) null else c.getInt(overrideIdx) != 0,
                        tags = parseJsonStringList(c.getString(c.getColumnIndexOrThrow("tags_json"))),
                        enabled = c.getInt(c.getColumnIndexOrThrow("enabled")) != 0,
                        fingerprint = c.getString(c.getColumnIndexOrThrow("fingerprint")),
                        lastLatencyMs = if (c.isNull(latIdx)) null else c.getInt(latIdx),
                        lastDownMbps = if (c.isNull(downIdx)) null else c.getDouble(downIdx),
                        lastUpMbps = if (c.isNull(upIdx)) null else c.getDouble(upIdx),
                    )
                )
            }
        }
        return out
    }

    /**
     * Upsert nodes deduplicated by `catcloud-node-fp-v1` fingerprint while preserving
     * existing node IDs and local probe metrics. Returns map `fingerprint -> nodeId`.
     */
    fun upsertNodesDedup(incoming: List<ProxyNodeRecord>): Pair<Int, Map<String, String>> {
        val existing = listNodes()
        val fpToExisting = HashMap<String, ProxyNodeRecord>(existing.size)
        for (n in existing) {
            val fp = n.fingerprint.ifBlank { NodeFingerprint.computeNodeFingerprint(n) }
            fpToExisting[fp] = n
        }
        val db = writableDatabase
        var insertedOrUpdated = 0
        db.beginTransaction()
        try {
            for (raw in incoming) {
                val fp = raw.fingerprint.ifBlank { NodeFingerprint.computeNodeFingerprint(raw) }
                val prev = fpToExisting[fp]
                val finalNode = if (prev != null) {
                    raw.copy(
                        id = prev.id,
                        fingerprint = fp,
                        enabled = prev.enabled,
                        preaccelOverride = prev.preaccelOverride,
                        lastLatencyMs = prev.lastLatencyMs,
                        lastDownMbps = prev.lastDownMbps,
                        lastUpMbps = prev.lastUpMbps,
                    )
                } else {
                    raw.copy(fingerprint = fp)
                }
                db.insertWithOnConflict("nodes", null, nodeToContentValues(finalNode), SQLiteDatabase.CONFLICT_REPLACE)
                fpToExisting[fp] = finalNode
                insertedOrUpdated++
            }
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
        return insertedOrUpdated to fpToExisting.mapValues { it.value.id }
    }

    fun updateNodeMetrics(nodeId: String, latencyMs: Int?, downMbps: Double? = null, upMbps: Double? = null) {
        val cv = ContentValues()
        if (latencyMs != null) cv.put("last_latency_ms", latencyMs)
        if (downMbps != null) cv.put("last_down_mbps", downMbps)
        if (upMbps != null) cv.put("last_up_mbps", upMbps)
        if (cv.size() > 0) {
            writableDatabase.update("nodes", cv, "id = ?", arrayOf(nodeId))
        }
    }

    fun deleteNode(nodeId: String) {
        writableDatabase.delete("nodes", "id = ?", arrayOf(nodeId))
    }

    // ---- Relays ----

    fun listRelays(): List<PreAccelRelayRecord> {
        val out = ArrayList<PreAccelRelayRecord>()
        readableDatabase.rawQuery("SELECT * FROM relays ORDER BY priority ASC, id ASC", null).use { c ->
            while (c.moveToNext()) {
                val sniIdx = c.getColumnIndexOrThrow("sni")
                val expIdx = c.getColumnIndexOrThrow("expires_at")
                val probeIdx = c.getColumnIndexOrThrow("last_probe_ms")
                out.add(
                    PreAccelRelayRecord(
                        id = c.getString(c.getColumnIndexOrThrow("id")),
                        name = c.getString(c.getColumnIndexOrThrow("name")),
                        provider = c.getString(c.getColumnIndexOrThrow("provider")),
                        region = c.getString(c.getColumnIndexOrThrow("region")),
                        server = c.getString(c.getColumnIndexOrThrow("server")),
                        port = c.getInt(c.getColumnIndexOrThrow("port")),
                        protocol = c.getString(c.getColumnIndexOrThrow("protocol")),
                        password = c.getString(c.getColumnIndexOrThrow("password")),
                        sni = if (c.isNull(sniIdx)) null else c.getString(sniIdx),
                        skipCertVerify = c.getInt(c.getColumnIndexOrThrow("skip_cert_verify")) != 0,
                        priority = c.getInt(c.getColumnIndexOrThrow("priority")),
                        expiresAt = if (c.isNull(expIdx)) null else c.getString(expIdx),
                        enabled = c.getInt(c.getColumnIndexOrThrow("enabled")) != 0,
                        lastProbeMs = if (c.isNull(probeIdx)) null else c.getInt(probeIdx),
                    )
                )
            }
        }
        return out
    }

    fun upsertRelaysDedup(incoming: List<PreAccelRelayRecord>): Int {
        val existing = listRelays()
        val fpToId = HashMap<Triple<String, String, Int>, String>()
        for (r in existing) {
            fpToId[NodeFingerprint.relayDedupFingerprint(r)] = r.id
        }
        val db = writableDatabase
        var count = 0
        db.beginTransaction()
        try {
            for (r in incoming) {
                val fp = NodeFingerprint.relayDedupFingerprint(r)
                val finalRelay = fpToId[fp]?.let { r.copy(id = it) } ?: r
                db.insertWithOnConflict("relays", null, relayToContentValues(finalRelay), SQLiteDatabase.CONFLICT_REPLACE)
                fpToId[fp] = finalRelay.id
                count++
            }
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
        return count
    }

    fun updateRelayLatency(relayId: String, latencyMs: Int?) {
        val cv = ContentValues()
        if (latencyMs != null) cv.put("last_probe_ms", latencyMs) else cv.putNull("last_probe_ms")
        writableDatabase.update("relays", cv, "id = ?", arrayOf(relayId))
    }

    fun deleteRelay(relayId: String) {
        writableDatabase.delete("relays", "id = ?", arrayOf(relayId))
    }

    // ---- Groups ----

    fun listGroups(): List<MultiGroupRecord> {
        val out = ArrayList<MultiGroupRecord>()
        readableDatabase.rawQuery("SELECT * FROM groups ORDER BY rowid ASC", null).use { c ->
            while (c.moveToNext()) {
                val dfIdx = c.getColumnIndexOrThrow("dynamic_filter_json")
                val ppIdx = c.getColumnIndexOrThrow("primary_probe_id")
                val fbIdx = c.getColumnIndexOrThrow("fallback_pool_id")
                val actIdx = c.getColumnIndexOrThrow("active_node_id")
                out.add(
                    MultiGroupRecord(
                        id = c.getString(c.getColumnIndexOrThrow("id")),
                        name = c.getString(c.getColumnIndexOrThrow("name")),
                        mode = c.getString(c.getColumnIndexOrThrow("mode")),
                        matchRules = parseJsonStringList(c.getString(c.getColumnIndexOrThrow("match_rules_json"))),
                        memberNodeIds = parseJsonStringList(c.getString(c.getColumnIndexOrThrow("member_node_ids_json"))),
                        dynamicFilterJson = if (c.isNull(dfIdx)) null else c.getString(dfIdx),
                        primaryProbeId = if (c.isNull(ppIdx)) null else c.getString(ppIdx),
                        hardGates = parseJsonStringList(c.getString(c.getColumnIndexOrThrow("hard_gates_json"))),
                        triggerRulesJson = c.getString(c.getColumnIndexOrThrow("trigger_rules_json")),
                        formulaExpr = c.getString(c.getColumnIndexOrThrow("formula_expr")),
                        fallbackPolicy = c.getString(c.getColumnIndexOrThrow("fallback_policy")),
                        fallbackPoolId = if (c.isNull(fbIdx)) null else c.getString(fbIdx),
                        recoverProbeIntervalSec = c.getLong(c.getColumnIndexOrThrow("recover_probe_interval_sec")),
                        switchMode = c.getString(c.getColumnIndexOrThrow("switch_mode")),
                        cooldownSec = c.getLong(c.getColumnIndexOrThrow("cooldown_sec")),
                        hysteresisPct = c.getDouble(c.getColumnIndexOrThrow("hysteresis_pct")),
                        activeNodeId = if (c.isNull(actIdx)) null else c.getString(actIdx),
                        independentRouting = c.getInt(c.getColumnIndexOrThrow("independent_routing")) != 0,
                    )
                )
            }
        }
        return out
    }

    fun replaceAllGroups(groups: List<MultiGroupRecord>) {
        val db = writableDatabase
        db.beginTransaction()
        try {
            db.delete("groups", null, null)
            for (g in groups) {
                db.insertWithOnConflict("groups", null, groupToContentValues(g), SQLiteDatabase.CONFLICT_REPLACE)
            }
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    // ---- Settings ----

    fun loadSettings(): AppSettings {
        val jsonStr = readableDatabase.rawQuery(
            "SELECT v FROM settings WHERE k = ?",
            arrayOf(SETTINGS_KEY),
        ).use { c -> if (c.moveToFirst()) c.getString(0) else null }
        if (jsonStr.isNullOrBlank()) return AppSettings()
        val o = runCatching { JSONObject(jsonStr) }.getOrNull() ?: return AppSettings()
        return AppSettings(
            proxyMode = ProxyMode.fromWire(o.optString("proxy_mode", "rule")),
            routeMode = RouteMode.fromWire(o.optString("route_mode", "single")),
            activeSingleNodeId = o.optString("active_single_node_id", "").takeIf { it.isNotBlank() },
            activeGroupId = o.optString("active_group_id", "").takeIf { it.isNotBlank() },
            preaccelEnabled = o.optBoolean("preaccel_enabled", false),
            preaccelAutoFailover = o.optBoolean("preaccel_auto_failover", true),
            preaccelSkip443Native = o.optBoolean("preaccel_skip_443_native", true),
            preaccelActiveRelayId = o.optString("preaccel_active_relay_id", "").takeIf { it.isNotBlank() },
            preaccelProbeUrl = o.optString("preaccel_probe_url", AppSettings().preaccelProbeUrl),
            preaccelFallbackProbeUrl = o.optString("preaccel_fallback_probe_url", AppSettings().preaccelFallbackProbeUrl),
            preaccelProbeIntervalSec = o.optInt("preaccel_probe_interval_sec", 30),
            domesticDirectEnabled = o.optBoolean("domestic_direct_enabled", true),
            blockQuicUdp443 = o.optBoolean("block_quic_udp_443", true),
            campusDirectDomains = parseJsonStringList(o.optString("campus_direct_domains", "[]")),
            perAppMode = PerAppMode.fromWire(o.optString("per_app_mode", "bypass")),
            perAppPackages = parseJsonStringList(o.optString("per_app_packages", "[]")),
            theme = ThemePreference.fromWire(o.optString("theme", "midnight_blue")),
            autoStartOnBoot = o.optBoolean("auto_start_on_boot", false),
            lastVpnWasRunning = o.optBoolean("last_vpn_was_running", false),
            ignoredClipboardHash = o.optString("ignored_clipboard_hash", "").takeIf { it.isNotBlank() },
        )
    }

    fun saveSettings(s: AppSettings) {
        val o = JSONObject().apply {
            put("proxy_mode", s.proxyMode.wireValue)
            put("route_mode", s.routeMode.wireValue)
            put("active_single_node_id", s.activeSingleNodeId ?: "")
            put("active_group_id", s.activeGroupId ?: "")
            put("preaccel_enabled", s.preaccelEnabled)
            put("preaccel_auto_failover", s.preaccelAutoFailover)
            put("preaccel_skip_443_native", s.preaccelSkip443Native)
            put("preaccel_active_relay_id", s.preaccelActiveRelayId ?: "")
            put("preaccel_probe_url", s.preaccelProbeUrl)
            put("preaccel_fallback_probe_url", s.preaccelFallbackProbeUrl)
            put("preaccel_probe_interval_sec", s.preaccelProbeIntervalSec)
            put("domestic_direct_enabled", s.domesticDirectEnabled)
            put("block_quic_udp_443", s.blockQuicUdp443)
            put("campus_direct_domains", JSONArray(s.campusDirectDomains).toString())
            put("per_app_mode", s.perAppMode.wireValue)
            put("per_app_packages", JSONArray(s.perAppPackages).toString())
            put("theme", s.theme.wireValue)
            put("auto_start_on_boot", s.autoStartOnBoot)
            put("last_vpn_was_running", s.lastVpnWasRunning)
            put("ignored_clipboard_hash", s.ignoredClipboardHash ?: "")
        }
        val cv = ContentValues().apply {
            put("k", SETTINGS_KEY)
            put("v", o.toString())
        }
        writableDatabase.insertWithOnConflict("settings", null, cv, SQLiteDatabase.CONFLICT_REPLACE)
    }

    // ---- Portable Encrypted Relay Box (max 3 items, <= 4 MiB each, 7-day auto-expiry) ----

    fun pruneExpiredRelayBox(nowMs: Long = System.currentTimeMillis()) {
        writableDatabase.delete("relay_box", "expires_at_ms <= ?", arrayOf(nowMs.toString()))
    }

    fun listRelayBoxItems(nowMs: Long = System.currentTimeMillis()): List<RelayBoxItem> {
        pruneExpiredRelayBox(nowMs)
        val out = ArrayList<RelayBoxItem>()
        readableDatabase.rawQuery(
            "SELECT id, name, created_at_ms, expires_at_ms, zip_fp, size_bytes, node_count, relay_count, group_count FROM relay_box ORDER BY created_at_ms DESC",
            null,
        ).use { c ->
            while (c.moveToNext()) {
                out.add(
                    RelayBoxItem(
                        id = c.getString(0),
                        name = c.getString(1),
                        createdAtMs = c.getLong(2),
                        expiresAtMs = c.getLong(3),
                        zipFp = c.getString(4),
                        sizeBytes = c.getInt(5),
                        nodeCount = c.getInt(6),
                        relayCount = c.getInt(7),
                        groupCount = c.getInt(8),
                    )
                )
            }
        }
        return out
    }

    fun saveRelayBoxEntry(
        id: String,
        name: String,
        zipFp: String,
        payloadBytes: ByteArray,
        nodeCount: Int,
        relayCount: Int,
        groupCount: Int,
        nowMs: Long = System.currentTimeMillis(),
    ) {
        require(payloadBytes.size <= MAX_RELAY_BOX_ITEM_BYTES) {
            "接力箱单份包体超过 4 MiB 上限 (${payloadBytes.size} bytes)"
        }
        val db = writableDatabase
        db.beginTransaction()
        try {
            db.delete("relay_box", "expires_at_ms <= ?", arrayOf(nowMs.toString()))
            val cv = ContentValues().apply {
                put("id", id)
                put("name", name)
                put("created_at_ms", nowMs)
                put("expires_at_ms", nowMs + RELAY_BOX_TTL_MS)
                put("zip_fp", zipFp)
                put("payload_bytes", payloadBytes)
                put("size_bytes", payloadBytes.size)
                put("node_count", nodeCount)
                put("relay_count", relayCount)
                put("group_count", groupCount)
            }
            db.insertWithOnConflict("relay_box", null, cv, SQLiteDatabase.CONFLICT_REPLACE)

            // Keep only the newest 3 items
            db.execSQL(
                """
                DELETE FROM relay_box WHERE id NOT IN (
                    SELECT id FROM relay_box ORDER BY created_at_ms DESC LIMIT $MAX_RELAY_BOX_ITEMS
                )
                """.trimIndent()
            )
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    fun readRelayBoxPayload(id: String): ByteArray? =
        readableDatabase.rawQuery("SELECT payload_bytes FROM relay_box WHERE id = ?", arrayOf(id)).use { c ->
            if (c.moveToFirst()) c.getBlob(0) else null
        }

    fun deleteRelayBoxEntry(id: String) {
        writableDatabase.delete("relay_box", "id = ?", arrayOf(id))
    }

    fun clearRelayBox() {
        writableDatabase.delete("relay_box", null, null)
    }

    // ---- Atomic 0600 files shared read-only with `:vpn` ----

    fun writeRuntimeConfigAtomically(yamlContent: String): File {
        val target = File(appContext.filesDir, RUNTIME_CONFIG_FILENAME)
        atomicWritePrivate(target, yamlContent.toByteArray(Charsets.UTF_8))
        return target
    }

    fun writeBootSnapshotAtomically(
        configPath: String,
        settings: AppSettings,
        activeNodeName: String,
        activeNodeCount: Int,
        wasRunning: Boolean,
    ): File {
        val obj = JSONObject().apply {
            put("config_path", configPath)
            put("per_app_mode", settings.perAppMode.wireValue)
            put("per_app_packages", JSONArray(settings.perAppPackages))
            put("active_node_name", activeNodeName)
            put("active_node_count", activeNodeCount)
            put("auto_start_on_boot", settings.autoStartOnBoot)
            put("was_running", wasRunning)
        }
        val target = File(appContext.filesDir, BOOT_SNAPSHOT_FILENAME)
        atomicWritePrivate(target, obj.toString().toByteArray(Charsets.UTF_8))
        return target
    }

    private fun atomicWritePrivate(target: File, data: ByteArray) {
        val parent = target.parentFile ?: appContext.filesDir
        if (!parent.exists()) parent.mkdirs()
        val tmp = File(parent, "${target.name}.tmp")
        FileOutputStream(tmp).use { fos ->
            fos.write(data)
            fos.fd.sync()
        }
        tmp.setReadable(false, false)
        tmp.setReadable(true, true)
        tmp.setWritable(false, false)
        tmp.setWritable(true, true)
        if (!tmp.renameTo(target)) {
            target.delete()
            tmp.renameTo(target)
        }
    }

    private fun nodeToContentValues(n: ProxyNodeRecord) = ContentValues().apply {
        put("id", n.id)
        put("sub_id", n.subId)
        put("name", n.name)
        put("protocol", n.protocol)
        put("server", n.server)
        put("port", n.port)
        put("raw_config_json", n.rawConfigJson)
        put("region_code", n.regionCode)
        put("multiplier", n.multiplier)
        put("is_443_native", if (n.is443Native) 1 else 0)
        put("preaccel_eligible", if (n.preaccelEligible) 1 else 0)
        if (n.preaccelOverride != null) put("preaccel_override", if (n.preaccelOverride) 1 else 0) else putNull("preaccel_override")
        put("tags_json", JSONArray(n.tags).toString())
        put("enabled", if (n.enabled) 1 else 0)
        put("fingerprint", n.fingerprint)
        if (n.lastLatencyMs != null) put("last_latency_ms", n.lastLatencyMs) else putNull("last_latency_ms")
        if (n.lastDownMbps != null) put("last_down_mbps", n.lastDownMbps) else putNull("last_down_mbps")
        if (n.lastUpMbps != null) put("last_up_mbps", n.lastUpMbps) else putNull("last_up_mbps")
    }

    private fun relayToContentValues(r: PreAccelRelayRecord) = ContentValues().apply {
        put("id", r.id)
        put("name", r.name)
        put("provider", r.provider)
        put("region", r.region)
        put("server", r.server)
        put("port", r.port)
        put("protocol", r.protocol)
        put("password", r.password)
        if (r.sni != null) put("sni", r.sni) else putNull("sni")
        put("skip_cert_verify", if (r.skipCertVerify) 1 else 0)
        put("priority", r.priority)
        if (r.expiresAt != null) put("expires_at", r.expiresAt) else putNull("expires_at")
        put("enabled", if (r.enabled) 1 else 0)
        if (r.lastProbeMs != null) put("last_probe_ms", r.lastProbeMs) else putNull("last_probe_ms")
    }

    private fun groupToContentValues(g: MultiGroupRecord) = ContentValues().apply {
        put("id", g.id)
        put("name", g.name)
        put("mode", g.mode)
        put("match_rules_json", JSONArray(g.matchRules).toString())
        put("member_node_ids_json", JSONArray(g.memberNodeIds).toString())
        if (g.dynamicFilterJson != null) put("dynamic_filter_json", g.dynamicFilterJson) else putNull("dynamic_filter_json")
        if (g.primaryProbeId != null) put("primary_probe_id", g.primaryProbeId) else putNull("primary_probe_id")
        put("hard_gates_json", JSONArray(g.hardGates).toString())
        put("trigger_rules_json", g.triggerRulesJson)
        put("formula_expr", g.formulaExpr)
        put("fallback_policy", g.fallbackPolicy)
        if (g.fallbackPoolId != null) put("fallback_pool_id", g.fallbackPoolId) else putNull("fallback_pool_id")
        put("recover_probe_interval_sec", g.recoverProbeIntervalSec)
        put("switch_mode", g.switchMode)
        put("cooldown_sec", g.cooldownSec)
        put("hysteresis_pct", g.hysteresisPct)
        if (g.activeNodeId != null) put("active_node_id", g.activeNodeId) else putNull("active_node_id")
        put("independent_routing", if (g.independentRouting) 1 else 0)
    }

    private fun parseJsonStringList(raw: String): List<String> {
        val arr = runCatching { JSONArray(raw) }.getOrNull() ?: return emptyList()
        val list = ArrayList<String>(arr.length())
        for (i in 0 until arr.length()) {
            val s = arr.optString(i, "").trim()
            if (s.isNotEmpty()) list.add(s)
        }
        return list
    }

    companion object {
        const val DB_NAME = "catcloud_ui.db"
        const val DB_VERSION = 1
        private const val SETTINGS_KEY = "app_settings_v1"
        const val RUNTIME_CONFIG_FILENAME = "runtime_config.yaml"
        const val BOOT_SNAPSHOT_FILENAME = "vpn_boot_snapshot.json"
        const val MAX_RELAY_BOX_ITEMS = 3
        const val MAX_RELAY_BOX_ITEM_BYTES = 4 * 1024 * 1024
        const val RELAY_BOX_TTL_MS = 7L * 24L * 3600L * 1000L
    }
}
