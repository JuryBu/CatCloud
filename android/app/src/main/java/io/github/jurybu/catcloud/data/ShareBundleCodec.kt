package io.github.jurybu.catcloud.data

import org.json.JSONArray
import org.json.JSONObject
import org.yaml.snakeyaml.DumperOptions
import org.yaml.snakeyaml.LoaderOptions
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.constructor.SafeConstructor
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.URI
import java.net.URLDecoder
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.time.Instant
import java.util.Base64
import java.util.UUID
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

data class ShareBundleManifest(
    val schema: String,
    val name: String,
    val createdAt: String,
    val nodeCount: Int,
    val relayCount: Int,
    val description: String? = null,
    val sanitizedNotice: String = "",
)

data class ShareGroupRecord(
    val name: String,
    val mode: String = "sticky_best",
    val matchRules: List<String> = emptyList(),
    val memberFingerprints: List<String> = emptyList(),
    val dynamicFilterJson: String? = null,
    val primaryProbeId: String? = null,
    val hardGates: List<String> = emptyList(),
    val triggerRulesJson: String = "[]",
    val formulaExpr: String = MultiGroupRecord.DEFAULT_FORMULA_EXPR,
    val fallbackPolicy: String = "degrade_best_warn",
    val fallbackPoolName: String? = null,
    val recoverProbeIntervalSec: Long = 120L,
    val switchMode: String = "force_close_old",
    val cooldownSec: Long = 60L,
    val hysteresisPct: Double = 20.0,
    val activeNodeFingerprint: String? = null,
    val independentRouting: Boolean = false,
)

data class ShareGroupsDocument(
    val schema: String = ShareBundleCodec.GROUPS_SCHEMA_V1,
    val activeGroupName: String? = null,
    val routeMode: String? = null,
    val groups: List<ShareGroupRecord> = emptyList(),
)

data class ShareBundlePreview(
    val manifest: ShareBundleManifest,
    val nodes: List<ProxyNodeRecord>,
    val relays: List<PreAccelRelayRecord>,
    val groupsDoc: ShareGroupsDocument?,
    val warnings: List<String>,
    val hasReadme: Boolean,
)

data class GroupMergeResult(
    val mergedGroups: List<MultiGroupRecord>,
    val importedCount: Int,
    val mergedCount: Int,
    val warnings: List<String>,
)

/**
 * Full-compatibility codec for `catcloud-share/v1` `.zip` archives (with backward-compatible
 * `groups.json` `catcloud-groups/v1`), `mmrelay://v1/...`, Clash/Mihomo YAML, and proxy URIs.
 */
object ShareBundleCodec {

    const val SHARE_BUNDLE_SCHEMA = "catcloud-share/v1"
    const val GROUPS_SCHEMA_V1 = "catcloud-groups/v1"
    const val MMRELAY_SCHEMA_V1 = "mmrelay/v1"
    const val MMRELAY_ROLE = "domestic_pre_accel"
    const val MMRELAY_URI_PREFIX = "mmrelay://v1/"

    const val MAX_ZIP_UNCOMPRESSED_BYTES = 16 * 1024 * 1024
    const val MAX_ZIP_FILE_BYTES = MAX_ZIP_UNCOMPRESSED_BYTES + 1024 * 1024
    const val MAX_ZIP_ENTRIES = 32
    const val MAX_SHARE_NODES = 4000

    private const val UNIX_FILE_TYPE_MASK = 0xF000
    private const val UNIX_SYMLINK_MODE = 0xA000

    fun exportShareBundleZip(
        name: String,
        nodes: List<ProxyNodeRecord>,
        relays: List<PreAccelRelayRecord>,
        groups: List<MultiGroupRecord> = emptyList(),
        activeGroupName: String? = null,
        routeMode: String? = null,
        description: String? = null,
    ): Pair<ByteArray, ShareBundleManifest> {
        require(nodes.isNotEmpty() || relays.isNotEmpty()) {
            "分享包至少需要包含 1 个节点或 1 条国内中转线路"
        }
        require(nodes.size <= MAX_SHARE_NODES) {
            "节点数量超过单包安全上限 (${nodes.size} > $MAX_SHARE_NODES)"
        }

        val bundleName = name.trim().ifEmpty { "CatCloud Share Bundle" }
        val descClean = description?.trim()?.takeIf { it.isNotEmpty() }
        val manifest = ShareBundleManifest(
            schema = SHARE_BUNDLE_SCHEMA,
            name = bundleName,
            createdAt = Instant.now().toString(),
            nodeCount = nodes.size,
            relayCount = relays.size,
            description = descClean,
            sanitizedNotice = "已自动剥离原订阅链接、本机路径、控制口密钥、节点 dialer-proxy 及中转测速缓存；包内仍含可用节点/中转凭据，请仅私发给可信对象，切勿公开上传。",
        )

        val manifestJson = JSONObject().apply {
            put("schema", manifest.schema)
            put("name", manifest.name)
            put("created_at", manifest.createdAt)
            put("node_count", manifest.nodeCount)
            put("relay_count", manifest.relayCount)
            if (manifest.description != null) put("description", manifest.description)
            put("sanitized_notice", manifest.sanitizedNotice)
        }.toString(2).toByteArray(Charsets.UTF_8)

        val readmeBytes = buildString {
            appendLine("# CatCloud Share Bundle (${manifest.schema})")
            appendLine("- Name: ${manifest.name}")
            appendLine("- Nodes: ${manifest.nodeCount}")
            appendLine("- Relays: ${manifest.relayCount}")
            appendLine("- Groups: ${groups.size}")
        }.toByteArray(Charsets.UTF_8)

        val nodesYamlBytes = if (nodes.isNotEmpty()) {
            serializeExportedNodesYaml(nodes).toByteArray(Charsets.UTF_8)
        } else {
            null
        }

        val relaysJsonBytes = if (relays.isNotEmpty()) {
            serializeMmRelayJson(relays).toByteArray(Charsets.UTF_8)
        } else {
            null
        }

        val groupsJsonBytes = if (groups.isNotEmpty()) {
            val idToFp = nodes.associate { n ->
                n.id to n.fingerprint.ifBlank { NodeFingerprint.computeNodeFingerprint(n) }
            }
            val idToGroupName = groups.associate { it.id to it.name }
            serializeGroupsJson(groups, idToFp, idToGroupName, activeGroupName, routeMode)
                .toByteArray(Charsets.UTF_8)
        } else {
            null
        }

        val totalUncompressed = manifestJson.size + readmeBytes.size +
            (nodesYamlBytes?.size ?: 0) + (relaysJsonBytes?.size ?: 0) + (groupsJsonBytes?.size ?: 0)
        require(totalUncompressed <= MAX_ZIP_UNCOMPRESSED_BYTES) {
            "分享包内容总大小超过 16 MiB 上限 ($totalUncompressed bytes)"
        }

        val baos = ByteArrayOutputStream()
        ZipOutputStream(baos).use { zos ->
            writeZipEntry(zos, "manifest.json", manifestJson)
            writeZipEntry(zos, "README.md", readmeBytes)
            nodesYamlBytes?.let { writeZipEntry(zos, "nodes.yaml", it) }
            relaysJsonBytes?.let { writeZipEntry(zos, "relays.mmrelay.json", it) }
            groupsJsonBytes?.let { writeZipEntry(zos, "groups.json", it) }
        }
        return baos.toByteArray() to manifest
    }

    fun previewShareBundleZip(bytes: ByteArray): ShareBundlePreview {
        require(bytes.isNotEmpty()) { "分享包内容为空" }
        if (bytes.size > MAX_ZIP_FILE_BYTES) {
            throw SecurityException("分享包体积超过安全上限 (${bytes.size} > $MAX_ZIP_FILE_BYTES)")
        }

        // Scan Central Directory first to detect Unix symlinks and excessive entry counts
        // without ever extracting to disk.
        scanCentralDirectoryForSecurity(bytes)

        var totalUncompressed = 0
        var entryCount = 0
        var manifestBytes: ByteArray? = null
        var nodesBytes: ByteArray? = null
        var relaysBytes: ByteArray? = null
        var groupsBytes: ByteArray? = null
        var hasReadme = false
        val warnings = ArrayList<String>()
        val seenTopDirs = HashSet<String>()

        ZipInputStream(ByteArrayInputStream(bytes)).use { zis ->
            while (true) {
                val entry = zis.nextEntry ?: break
                entryCount++
                if (entryCount > MAX_ZIP_ENTRIES) {
                    throw SecurityException("分享包条目数超限 ($entryCount > $MAX_ZIP_ENTRIES)")
                }

                val rawName = entry.name
                val parts = validateSafeZipEntryPath(rawName)
                val isMacJunk = parts.firstOrNull() == "__MACOSX" ||
                    (parts.lastOrNull()?.startsWith("._") == true)
                if (isMacJunk) {
                    zis.closeEntry()
                    continue
                }
                if (entry.isDirectory) {
                    parts.firstOrNull()?.let { seenTopDirs.add(it) }
                    zis.closeEntry()
                    continue
                }

                val remaining = MAX_ZIP_UNCOMPRESSED_BYTES - totalUncompressed
                val content = readBounded(zis, remaining)
                totalUncompressed += content.size
                zis.closeEntry()

                val fileNameLower = when (parts.size) {
                    1 -> parts[0].lowercase()
                    2 -> {
                        seenTopDirs.add(parts[0])
                        if (seenTopDirs.size > 1) {
                            warnings.add("已忽略额外目录条目：$rawName")
                            continue
                        }
                        parts[1].lowercase()
                    }
                    else -> {
                        warnings.add("已忽略非规范嵌套条目：$rawName")
                        continue
                    }
                }

                when (fileNameLower) {
                    "manifest.json" -> {
                        if (manifestBytes != null) throw SecurityException("分享包包含重复的 manifest.json 条目")
                        manifestBytes = content
                    }
                    "nodes.yaml", "nodes.yml" -> {
                        if (nodesBytes != null) throw SecurityException("分享包包含重复的 nodes.yaml 条目")
                        nodesBytes = content
                    }
                    "relays.mmrelay.json" -> {
                        if (relaysBytes != null) throw SecurityException("分享包包含重复的 relays.mmrelay.json 条目")
                        relaysBytes = content
                    }
                    "groups.json" -> {
                        if (groupsBytes != null) throw SecurityException("分享包包含重复的 groups.json 条目")
                        groupsBytes = content
                    }
                    "readme.md" -> hasReadme = true
                    else -> warnings.add("已忽略未识别附加文件：$rawName")
                }
            }
        }

        val rawManifest = manifestBytes ?: throw IllegalArgumentException("分享包缺少必需的 manifest.json")
        val manifestObj = JSONObject(rawManifest.toString(Charsets.UTF_8))
        val schema = manifestObj.optString("schema", "").trim()
        if (schema != SHARE_BUNDLE_SCHEMA) {
            throw IllegalArgumentException("不支持的分享包 schema「$schema」")
        }
        val manifest = ShareBundleManifest(
            schema = schema,
            name = manifestObj.optString("name", "CatCloud Bundle"),
            createdAt = manifestObj.optString("created_at", ""),
            nodeCount = manifestObj.optInt("node_count", 0),
            relayCount = manifestObj.optInt("relay_count", 0),
            description = manifestObj.optString("description", "").takeIf { it.isNotBlank() },
            sanitizedNotice = manifestObj.optString("sanitized_notice", ""),
        )

        val nodes = if (nodesBytes != null) {
            val text = nodesBytes!!.toString(Charsets.UTF_8).trim()
            if (text.isEmpty()) emptyList() else parseClashYamlNodes(text, "share_bundle").also {
                if (it.size > MAX_SHARE_NODES) {
                    throw IllegalArgumentException("分享包内节点数量超过上限 (${it.size} > $MAX_SHARE_NODES)")
                }
            }
        } else {
            emptyList()
        }

        val relays = if (relaysBytes != null) {
            val text = relaysBytes!!.toString(Charsets.UTF_8).trim()
            if (text.isEmpty()) emptyList() else parseMmRelayJson(text)
        } else {
            emptyList()
        }

        val groupsDoc = if (groupsBytes != null) {
            val text = groupsBytes!!.toString(Charsets.UTF_8).trim()
            if (text.isEmpty()) null else parseGroupsJson(text)
        } else {
            null
        }

        if (nodes.isEmpty() && relays.isEmpty()) {
            throw IllegalArgumentException("分享包中未包含任何可用节点或国内中转线路")
        }

        return ShareBundlePreview(
            manifest = manifest,
            nodes = nodes,
            relays = relays,
            groupsDoc = groupsDoc,
            warnings = warnings,
            hasReadme = hasReadme,
        )
    }

    /**
     * Merge imported `groups.json` into existing local groups following Stage 18 Section 2.1:
     * 1. Map `member_fingerprints` and `active_node_fingerprint` to target node IDs.
     * 2. Silently drop unmapped fingerprints; skip groups with 0 valid members and no `dynamic_filter`.
     * 3. Same-name groups perform union incremental merge, preserving local active_node_id & settings.
     * 4. Resolve `fallback_pool_name` by group name; set null if unmatched.
     */
    fun mergeImportedGroups(
        existingGroups: List<MultiGroupRecord>,
        importedDoc: ShareGroupsDocument,
        fingerprintToNodeId: Map<String, String>,
    ): GroupMergeResult {
        val warnings = ArrayList<String>()
        val resultByName = LinkedHashMap<String, MultiGroupRecord>()
        for (g in existingGroups) {
            resultByName[g.name.trim()] = g
        }

        var importedCount = 0
        var mergedCount = 0
        val pendingFallbackNames = HashMap<String, String>()

        for (rec in importedDoc.groups) {
            val cleanName = rec.name.trim()
            if (cleanName.isEmpty()) continue

            val mappedMemberIds = rec.memberFingerprints
                .mapNotNull { fp -> fingerprintToNodeId[fp.trim().lowercase()] }
                .distinct()
            val hasDynamic = !rec.dynamicFilterJson.isNullOrBlank()
            if (mappedMemberIds.isEmpty() && !hasDynamic) {
                warnings.add("多选组「$cleanName」无有效成员节点且无动态过滤条件，已跳过")
                continue
            }

            val existing = resultByName[cleanName]
            if (existing != null) {
                val unionMembers = LinkedHashSet<String>(existing.memberNodeIds)
                unionMembers.addAll(mappedMemberIds)
                val keptActive = existing.activeNodeId?.takeIf { unionMembers.contains(it) }
                    ?: rec.activeNodeFingerprint?.let { fingerprintToNodeId[it.trim().lowercase()] }
                        ?.takeIf { unionMembers.contains(it) }
                    ?: unionMembers.firstOrNull()

                resultByName[cleanName] = existing.copy(
                    memberNodeIds = unionMembers.toList(),
                    activeNodeId = keptActive,
                )
                mergedCount++
            } else {
                val mappedActive = rec.activeNodeFingerprint
                    ?.let { fingerprintToNodeId[it.trim().lowercase()] }
                    ?.takeIf { mappedMemberIds.contains(it) }
                    ?: mappedMemberIds.firstOrNull()
                val newId = "grp-" + UUID.randomUUID().toString().replace("-", "").take(12)
                resultByName[cleanName] = MultiGroupRecord(
                    id = newId,
                    name = cleanName,
                    mode = rec.mode.ifBlank { "sticky_best" },
                    matchRules = rec.matchRules,
                    memberNodeIds = mappedMemberIds,
                    dynamicFilterJson = rec.dynamicFilterJson,
                    primaryProbeId = rec.primaryProbeId,
                    hardGates = rec.hardGates,
                    triggerRulesJson = rec.triggerRulesJson,
                    formulaExpr = rec.formulaExpr.ifBlank { MultiGroupRecord.DEFAULT_FORMULA_EXPR },
                    fallbackPolicy = rec.fallbackPolicy.ifBlank { "degrade_best_warn" },
                    fallbackPoolId = null,
                    recoverProbeIntervalSec = rec.recoverProbeIntervalSec,
                    switchMode = rec.switchMode.ifBlank { "force_close_old" },
                    cooldownSec = rec.cooldownSec,
                    hysteresisPct = rec.hysteresisPct,
                    activeNodeId = mappedActive,
                    independentRouting = rec.independentRouting,
                )
                rec.fallbackPoolName?.trim()?.takeIf { it.isNotEmpty() }?.let {
                    pendingFallbackNames[cleanName] = it
                }
                importedCount++
            }
        }

        // Resolve fallback_pool_name -> fallback_pool_id across final group set
        val nameToId = resultByName.values.associate { it.name.trim() to it.id }
        for ((groupName, fbName) in pendingFallbackNames) {
            val g = resultByName[groupName] ?: continue
            val resolvedId = nameToId[fbName]
            resultByName[groupName] = g.copy(fallbackPoolId = resolvedId)
        }

        return GroupMergeResult(
            mergedGroups = resultByName.values.toList(),
            importedCount = importedCount,
            mergedCount = mergedCount,
            warnings = warnings,
        )
    }

    // ---- mmrelay/v1 & URI codec ----

    fun encodeMmRelayUri(relays: List<PreAccelRelayRecord>): String {
        val compact = serializeMmRelayJson(relays, pretty = false)
        val b64 = Base64.getUrlEncoder().withoutPadding().encodeToString(compact.toByteArray(Charsets.UTF_8))
        return "$MMRELAY_URI_PREFIX$b64"
    }

    fun decodeMmRelayInput(input: String): List<PreAccelRelayRecord> {
        val trimmed = input.trim()
        require(trimmed.isNotEmpty()) { "输入内容为空" }
        if (trimmed.startsWith(MMRELAY_URI_PREFIX, ignoreCase = true)) {
            return decodeMmRelayUri(trimmed)
        }
        if (trimmed.startsWith("{")) {
            return parseMmRelayJson(trimmed)
        }
        for (line in trimmed.lines()) {
            val candidate = line.trim()
            if (candidate.startsWith(MMRELAY_URI_PREFIX, ignoreCase = true)) {
                return decodeMmRelayUri(candidate)
            }
        }
        throw IllegalArgumentException("未识别的国内提速中转格式，需要 mmrelay://v1/... 或 mmrelay/v1 JSON")
    }

    private fun decodeMmRelayUri(uri: String): List<PreAccelRelayRecord> {
        val payload = uri.substring(MMRELAY_URI_PREFIX.length)
            .filterNot { it.isWhitespace() }
            .trimEnd('=')
        require(payload.isNotEmpty()) { "mmrelay URI 载荷为空" }
        val bytes = Base64.getUrlDecoder().decode(payload)
        return parseMmRelayJson(bytes.toString(Charsets.UTF_8))
    }

    fun serializeMmRelayJson(relays: List<PreAccelRelayRecord>, pretty: Boolean = true): String {
        val arr = JSONArray()
        for (r in relays) {
            arr.put(
                JSONObject().apply {
                    put("id", r.id)
                    put("name", r.name)
                    put("provider", r.provider)
                    put("region", r.region)
                    put("server", r.server)
                    put("port", r.port)
                    put("protocol", r.protocol)
                    put("password", r.password)
                    if (!r.sni.isNullOrBlank()) put("sni", r.sni) else put("sni", JSONObject.NULL)
                    put("skip_cert_verify", r.skipCertVerify)
                    put("priority", r.priority)
                    if (!r.expiresAt.isNullOrBlank()) put("expires_at", r.expiresAt) else put("expires_at", JSONObject.NULL)
                    put("enabled", r.enabled)
                }
            )
        }
        val root = JSONObject().apply {
            put("schema", MMRELAY_SCHEMA_V1)
            put("role", MMRELAY_ROLE)
            put("relays", arr)
        }
        return if (pretty) root.toString(2) else root.toString()
    }

    fun parseMmRelayJson(raw: String): List<PreAccelRelayRecord> {
        val root = JSONObject(raw.trim())
        val schema = root.optString("schema", "").trim()
        require(schema == MMRELAY_SCHEMA_V1) { "不支持的 mmrelay schema: $schema" }
        val role = root.optString("role", "").trim()
        require(role.isEmpty() || role == MMRELAY_ROLE) { "不支持的 mmrelay role: $role" }

        val arr = root.optJSONArray("relays") ?: return emptyList()
        val out = ArrayList<PreAccelRelayRecord>(arr.length())
        for (i in 0 until arr.length()) {
            val obj = arr.optJSONObject(i) ?: continue
            val server = obj.optString("server", "").trim()
            val port = obj.optInt("port", 443)
            val proto = obj.optString("protocol", "anytls").trim()
            val password = obj.optString("password", "").trim()
            if (server.isEmpty() || port !in 1..65535 || password.isEmpty()) continue
            val id = obj.optString("id", "").trim()
                .ifEmpty { "relay-" + UUID.randomUUID().toString().replace("-", "").take(12) }
            val sni = obj.optString("sni", obj.optString("servername", ""))
                .takeIf { it.isNotBlank() && it != "null" }
            val expires = obj.optString("expires_at", "")
                .takeIf { it.isNotBlank() && it != "null" }
            out.add(
                PreAccelRelayRecord(
                    id = id,
                    name = obj.optString("name", server).trim().ifEmpty { server },
                    provider = obj.optString("provider", "").trim(),
                    region = obj.optString("region", "").trim(),
                    server = server,
                    port = port,
                    protocol = NodeFingerprint.normalizeRelayProtocol(proto),
                    password = password,
                    sni = sni,
                    skipCertVerify = obj.optBoolean("skip_cert_verify", true),
                    priority = obj.optInt("priority", 100),
                    expiresAt = expires,
                    enabled = obj.optBoolean("enabled", true),
                    lastProbeMs = null,
                )
            )
        }
        return out
    }

    // ---- Proxy URI, Base64 subscription, and Clash YAML import ----

    fun parseTextImport(raw: String, subId: String = "manual"): List<ProxyNodeRecord> {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return emptyList()

        // 1. Clash / Mihomo YAML with `proxies:`
        if (trimmed.contains("proxies:")) {
            val yamlNodes = runCatching { parseClashYamlNodes(trimmed, subId) }.getOrNull()
            if (!yamlNodes.isNullOrEmpty()) return yamlNodes
        }

        // 2. Direct proxy URI lines
        val directUris = parseUriLines(trimmed, subId)
        if (directUris.isNotEmpty()) return directUris

        // 3. Base64-encoded subscription list
        val compact = trimmed.filterNot { it.isWhitespace() }
        val decoded = decodeFlexibleBase64(compact)?.toString(Charsets.UTF_8)
        if (!decoded.isNullOrBlank()) {
            if (decoded.contains("proxies:")) {
                val yamlNodes = runCatching { parseClashYamlNodes(decoded, subId) }.getOrNull()
                if (!yamlNodes.isNullOrEmpty()) return yamlNodes
            }
            val b64Uris = parseUriLines(decoded, subId)
            if (b64Uris.isNotEmpty()) return b64Uris
        }

        return emptyList()
    }

    @Suppress("UNCHECKED_CAST")
    fun parseClashYamlNodes(yamlText: String, subId: String): List<ProxyNodeRecord> {
        val loaderOpts = LoaderOptions().apply {
            setCodePointLimit(MAX_ZIP_UNCOMPRESSED_BYTES)
            setMaxAliasesForCollections(50)
            setAllowDuplicateKeys(false)
        }
        val yaml = Yaml(SafeConstructor(loaderOpts))
        val doc = yaml.load<Any>(yamlText) as? Map<*, *> ?: return emptyList()
        val proxies = doc["proxies"] as? List<*> ?: return emptyList()
        val result = ArrayList<ProxyNodeRecord>(proxies.size)
        for ((idx, item) in proxies.withIndex()) {
            val map = item as? Map<*, *> ?: continue
            val jsonObj = mapToJsonObject(map)
            val proto = NodeFingerprint.normalizeProtocol(
                jsonObj.optString("type", jsonObj.optString("protocol", ""))
            )
            val server = jsonObj.optString("server", "").trim()
            val port = jsonObj.optInt("port", 0)
            if (proto.isEmpty() || server.isEmpty() || port !in 1..65535) continue
            val name = jsonObj.optString("name", "").trim().ifEmpty { "Node-${idx + 1}" }
            val fp = NodeFingerprint.computeNodeFingerprint(proto, server, port, jsonObj)
            result.add(
                ProxyNodeRecord(
                    id = "node-${fp.take(16)}",
                    subId = subId,
                    name = name,
                    protocol = proto,
                    server = server,
                    port = port,
                    rawConfigJson = jsonObj.toString(),
                    regionCode = NodeFingerprint.detectRegionCode(name),
                    multiplier = NodeFingerprint.extractMultiplier(name),
                    is443Native = NodeFingerprint.detectIs443Native(proto, port, jsonObj),
                    preaccelEligible = true,
                    preaccelOverride = null,
                    tags = emptyList(),
                    enabled = true,
                    fingerprint = fp,
                )
            )
        }
        return result
    }

    private fun parseUriLines(text: String, subId: String): List<ProxyNodeRecord> {
        val nodes = ArrayList<ProxyNodeRecord>()
        for (rawLine in text.lines()) {
            val line = rawLine.trim()
            if (line.isEmpty() || line.startsWith("#")) continue
            parseSingleProxyUri(line, subId)?.let { nodes.add(it) }
        }
        return nodes
    }

    fun parseSingleProxyUri(uri: String, subId: String = "manual"): ProxyNodeRecord? {
        val trimmed = uri.trim()
        val schemeIdx = trimmed.indexOf("://")
        if (schemeIdx <= 0) return null
        val scheme = trimmed.substring(0, schemeIdx).lowercase()
        val jsonObj: JSONObject = when (scheme) {
            "vless" -> parseVlessUri(trimmed) ?: return null
            "trojan" -> parseTrojanUri(trimmed) ?: return null
            "hy2", "hysteria2" -> parseHysteria2Uri(trimmed) ?: return null
            "tuic" -> parseTuicUri(trimmed) ?: return null
            "anytls" -> parseAnyTlsUri(trimmed) ?: return null
            "ss" -> parseShadowsocksUri(trimmed) ?: return null
            "vmess" -> parseVmessUri(trimmed) ?: return null
            else -> return null
        }

        val proto = NodeFingerprint.normalizeProtocol(jsonObj.optString("type", scheme))
        val server = jsonObj.optString("server", "").trim()
        val port = jsonObj.optInt("port", 0)
        if (server.isEmpty() || port !in 1..65535) return null
        val name = jsonObj.optString("name", "$proto-$server:$port").trim()
        val fp = NodeFingerprint.computeNodeFingerprint(proto, server, port, jsonObj)
        return ProxyNodeRecord(
            id = "node-${fp.take(16)}",
            subId = subId,
            name = name,
            protocol = proto,
            server = server,
            port = port,
            rawConfigJson = jsonObj.toString(),
            regionCode = NodeFingerprint.detectRegionCode(name),
            multiplier = NodeFingerprint.extractMultiplier(name),
            is443Native = NodeFingerprint.detectIs443Native(proto, port, jsonObj),
            fingerprint = fp,
        )
    }

    private fun parseVlessUri(raw: String): JSONObject? {
        val u = runCatching { URI(raw) }.getOrNull() ?: return null
        val uuid = u.userInfo?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        val host = u.host?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        val port = u.port.takeIf { it in 1..65535 } ?: 443
        val q = parseQueryParams(u.rawQuery)
        val name = urlDecode(u.rawFragment ?: "").ifBlank { "VLESS-$host" }
        val security = q["security"]?.lowercase() ?: ""
        return JSONObject().apply {
            put("name", name)
            put("type", "vless")
            put("server", host)
            put("port", port)
            put("uuid", uuid)
            put("udp", true)
            put("tls", security == "tls" || security == "reality")
            q["sni"]?.takeIf { it.isNotBlank() }?.let { put("servername", it) }
            q["flow"]?.takeIf { it.isNotBlank() }?.let { put("flow", it) }
            q["fp"]?.takeIf { it.isNotBlank() }?.let { put("client-fingerprint", it) }
            val net = q["type"]?.lowercase()?.takeIf { it.isNotBlank() } ?: "tcp"
            put("network", net)
            if (net == "ws") {
                put("ws-opts", JSONObject().apply {
                    put("path", q["path"] ?: "/")
                    q["host"]?.takeIf { it.isNotBlank() }?.let { h ->
                        put("headers", JSONObject().put("Host", h))
                    }
                })
            } else if (net == "grpc") {
                q["serviceName"]?.takeIf { it.isNotBlank() }?.let { sn ->
                    put("grpc-opts", JSONObject().put("grpc-service-name", sn))
                }
            }
            if (security == "reality") {
                put("reality-opts", JSONObject().apply {
                    q["pbk"]?.let { put("public-key", it) }
                    q["sid"]?.let { put("short-id", it) }
                })
            }
        }
    }

    private fun parseTrojanUri(raw: String): JSONObject? {
        val u = runCatching { URI(raw) }.getOrNull() ?: return null
        val pw = u.userInfo?.let { urlDecode(it) }?.takeIf { it.isNotEmpty() } ?: return null
        val host = u.host?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        val port = u.port.takeIf { it in 1..65535 } ?: 443
        val q = parseQueryParams(u.rawQuery)
        val name = urlDecode(u.rawFragment ?: "").ifBlank { "Trojan-$host" }
        return JSONObject().apply {
            put("name", name)
            put("type", "trojan")
            put("server", host)
            put("port", port)
            put("password", pw)
            put("udp", true)
            q["sni"]?.takeIf { it.isNotBlank() }?.let { put("sni", it) }
            if (q["allowInsecure"] == "1" || q["insecure"] == "1") put("skip-cert-verify", true)
        }
    }

    private fun parseHysteria2Uri(raw: String): JSONObject? {
        val u = runCatching { URI(raw) }.getOrNull() ?: return null
        val pw = u.userInfo?.let { urlDecode(it) }?.takeIf { it.isNotEmpty() } ?: return null
        val host = u.host?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        val port = u.port.takeIf { it in 1..65535 } ?: 443
        val q = parseQueryParams(u.rawQuery)
        val name = urlDecode(u.rawFragment ?: "").ifBlank { "HY2-$host" }
        return JSONObject().apply {
            put("name", name)
            put("type", "hysteria2")
            put("server", host)
            put("port", port)
            put("password", pw)
            q["sni"]?.takeIf { it.isNotBlank() }?.let { put("sni", it) }
            q["obfs"]?.takeIf { it.isNotBlank() }?.let { put("obfs", it) }
            q["obfs-password"]?.takeIf { it.isNotBlank() }?.let { put("obfs-password", it) }
            if (q["insecure"] == "1") put("skip-cert-verify", true)
        }
    }

    private fun parseTuicUri(raw: String): JSONObject? {
        val u = runCatching { URI(raw) }.getOrNull() ?: return null
        val userInfo = u.userInfo ?: return null
        val host = u.host?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        val port = u.port.takeIf { it in 1..65535 } ?: 443
        val q = parseQueryParams(u.rawQuery)
        val name = urlDecode(u.rawFragment ?: "").ifBlank { "TUIC-$host" }
        return JSONObject().apply {
            put("name", name)
            put("type", "tuic")
            put("server", host)
            put("port", port)
            val parts = userInfo.split(":", limit = 2)
            if (parts.size == 2) {
                put("uuid", urlDecode(parts[0]))
                put("password", urlDecode(parts[1]))
            } else {
                put("token", urlDecode(userInfo))
            }
            q["sni"]?.takeIf { it.isNotBlank() }?.let { put("sni", it) }
            q["congestion_control"]?.takeIf { it.isNotBlank() }?.let { put("congestion-controller", it) }
            q["udp_relay_mode"]?.takeIf { it.isNotBlank() }?.let { put("udp-relay-mode", it) }
        }
    }

    private fun parseAnyTlsUri(raw: String): JSONObject? {
        val u = runCatching { URI(raw) }.getOrNull() ?: return null
        val pw = u.userInfo?.let { urlDecode(it) }?.takeIf { it.isNotEmpty() } ?: return null
        val host = u.host?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        val port = u.port.takeIf { it in 1..65535 } ?: 443
        val q = parseQueryParams(u.rawQuery)
        val name = urlDecode(u.rawFragment ?: "").ifBlank { "AnyTLS-$host" }
        return JSONObject().apply {
            put("name", name)
            put("type", "anytls")
            put("server", host)
            put("port", port)
            put("password", pw)
            put("udp", true)
            q["sni"]?.takeIf { it.isNotBlank() }?.let { put("sni", it) }
            if (q["insecure"] == "1") put("skip-cert-verify", true)
        }
    }

    private fun parseShadowsocksUri(raw: String): JSONObject? {
        val withoutScheme = raw.substring("ss://".length)
        val fragSplit = withoutScheme.split("#", limit = 2)
        val name = if (fragSplit.size == 2) urlDecode(fragSplit[1]) else ""
        val mainPart = fragSplit[0].substringBefore("?")
        val (method, password, host, port) = if (mainPart.contains("@")) {
            val (userPart, hostPort) = mainPart.split("@", limit = 2)
            val decodedUser = if (userPart.contains(":")) {
                urlDecode(userPart)
            } else {
                decodeFlexibleBase64(userPart)?.toString(Charsets.UTF_8) ?: return null
            }
            val (m, p) = decodedUser.split(":", limit = 2).takeIf { it.size == 2 } ?: return null
            val (h, pt) = splitHostPort(hostPort) ?: return null
            Quad(m, p, h, pt)
        } else {
            val decoded = decodeFlexibleBase64(mainPart)?.toString(Charsets.UTF_8) ?: return null
            val (userPart, hostPort) = decoded.split("@", limit = 2).takeIf { it.size == 2 } ?: return null
            val (m, p) = userPart.split(":", limit = 2).takeIf { it.size == 2 } ?: return null
            val (h, pt) = splitHostPort(hostPort) ?: return null
            Quad(m, p, h, pt)
        }
        return JSONObject().apply {
            put("name", name.ifBlank { "SS-$host:$port" })
            put("type", "ss")
            put("server", host)
            put("port", port)
            put("cipher", method)
            put("password", password)
            put("udp", true)
        }
    }

    private fun parseVmessUri(raw: String): JSONObject? {
        val b64 = raw.substring("vmess://".length).trim()
        val decoded = decodeFlexibleBase64(b64)?.toString(Charsets.UTF_8) ?: return null
        val src = runCatching { JSONObject(decoded) }.getOrNull() ?: return null
        val host = src.optString("add", "").trim().takeIf { it.isNotEmpty() } ?: return null
        val port = src.optInt("port", src.optString("port", "0").toIntOrNull() ?: 0)
        if (port !in 1..65535) return null
        val uuid = src.optString("id", "").trim().takeIf { it.isNotEmpty() } ?: return null
        val name = src.optString("ps", "VMess-$host").trim().ifEmpty { "VMess-$host" }
        val net = src.optString("net", "tcp").lowercase()
        val tls = src.optString("tls", "").equals("tls", ignoreCase = true)
        return JSONObject().apply {
            put("name", name)
            put("type", "vmess")
            put("server", host)
            put("port", port)
            put("uuid", uuid)
            put("alterId", src.optInt("aid", src.optString("aid", "0").toIntOrNull() ?: 0))
            put("cipher", src.optString("scy", "auto").ifBlank { "auto" })
            put("udp", true)
            put("tls", tls)
            src.optString("sni", "").takeIf { it.isNotBlank() }?.let { put("servername", it) }
            put("network", net)
            if (net == "ws") {
                put("ws-opts", JSONObject().apply {
                    put("path", src.optString("path", "/").ifBlank { "/" })
                    src.optString("host", "").takeIf { it.isNotBlank() }?.let { h ->
                        put("headers", JSONObject().put("Host", h))
                    }
                })
            }
        }
    }

    private data class Quad(val a: String, val b: String, val c: String, val d: Int)

    private fun splitHostPort(hostPort: String): Pair<String, Int>? {
        val t = hostPort.trim()
        return if (t.startsWith("[")) {
            val end = t.indexOf(']')
            if (end < 0 || end + 2 >= t.length || t[end + 1] != ':') return null
            val port = t.substring(end + 2).toIntOrNull()?.takeIf { it in 1..65535 } ?: return null
            t.substring(1, end) to port
        } else {
            val colon = t.lastIndexOf(':')
            if (colon <= 0) return null
            val port = t.substring(colon + 1).toIntOrNull()?.takeIf { it in 1..65535 } ?: return null
            t.substring(0, colon) to port
        }
    }

    // ---- Internal ZIP / YAML / JSON helpers ----

    private fun scanCentralDirectoryForSecurity(bytes: ByteArray) {
        // Locate End of Central Directory (EOCD) signature 0x06054b50 from tail
        val minOffset = maxOf(0, bytes.size - 65557)
        var eocdPos = -1
        for (i in (bytes.size - 22) downTo minOffset) {
            if (bytes[i] == 0x50.toByte() &&
                bytes[i + 1] == 0x4b.toByte() &&
                bytes[i + 2] == 0x05.toByte() &&
                bytes[i + 3] == 0x06.toByte()
            ) {
                eocdPos = i
                break
            }
        }
        if (eocdPos < 0) return

        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val totalEntries = buf.getShort(eocdPos + 10).toInt() and 0xFFFF
        if (totalEntries > MAX_ZIP_ENTRIES) {
            throw SecurityException("分享包条目数超限 ($totalEntries > $MAX_ZIP_ENTRIES)")
        }
        val cdOffset = buf.getInt(eocdPos + 16).toLong() and 0xFFFFFFFFL
        if (cdOffset > bytes.size) return

        var pos = cdOffset.toInt()
        for (idx in 0 until totalEntries) {
            if (pos + 46 > bytes.size) break
            val sig = buf.getInt(pos)
            if (sig != 0x02014b50) break
            val versionMadeBy = buf.getShort(pos + 4).toInt() and 0xFFFF
            val hostOs = versionMadeBy ushr 8
            val nameLen = buf.getShort(pos + 28).toInt() and 0xFFFF
            val extraLen = buf.getShort(pos + 30).toInt() and 0xFFFF
            val commentLen = buf.getShort(pos + 32).toInt() and 0xFFFF
            val extAttr = buf.getInt(pos + 38)
            val unixMode = (extAttr ushr 16) and 0xFFFF
            val entryName = if (pos + 46 + nameLen <= bytes.size) {
                String(bytes, pos + 46, nameLen, Charsets.UTF_8)
            } else {
                "<entry#$idx>"
            }
            if ((hostOs == 3 || unixMode != 0) && (unixMode and UNIX_FILE_TYPE_MASK) == UNIX_SYMLINK_MODE) {
                throw SecurityException("分享包包含非法符号链接条目「$entryName」，已拒绝解析")
            }
            pos += 46 + nameLen + extraLen + commentLen
        }
    }

    private fun validateSafeZipEntryPath(rawName: String): List<String> {
        if (rawName.isEmpty() ||
            rawName.contains('\u0000') ||
            rawName.contains('\\') ||
            rawName.startsWith('/') ||
            (rawName.length >= 2 && rawName[1] == ':')
        ) {
            throw SecurityException("检测到非法分享包路径「$rawName」（疑似 Zip Slip）")
        }
        val trimmed = rawName.trimEnd('/')
        if (trimmed.isEmpty()) {
            throw SecurityException("分享包路径为空：「$rawName」")
        }
        val parts = trimmed.split('/')
        for (seg in parts) {
            if (seg.isEmpty() || seg == "." || seg == "..") {
                throw SecurityException("分享包路径包含越权组件「$rawName」（疑似 Zip Slip）")
            }
        }
        return parts
    }

    private fun readBounded(zis: ZipInputStream, remainingBytes: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        var readTotal = 0
        while (true) {
            val n = zis.read(buf)
            if (n < 0) break
            readTotal += n
            if (readTotal > remainingBytes) {
                throw SecurityException("分享包实际解压大小超过 16 MiB 安全上限（疑似压缩炸弹）")
            }
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }

    private fun writeZipEntry(zos: ZipOutputStream, name: String, data: ByteArray) {
        val entry = ZipEntry(name)
        zos.putNextEntry(entry)
        zos.write(data)
        zos.closeEntry()
    }

    private fun serializeExportedNodesYaml(nodes: List<ProxyNodeRecord>): String {
        val usedNames = HashSet<String>()
        val proxiesList = ArrayList<Map<String, Any?>>(nodes.size)
        for ((idx, node) in nodes.withIndex()) {
            val baseName = node.name.trim().ifEmpty { "Node-${idx + 1}" }
            val uniqueName = makeUniqueName(baseName, usedNames)
            val map = LinkedHashMap<String, Any?>()
            val obj = runCatching { JSONObject(node.rawConfigJson) }.getOrNull()
            if (obj != null) {
                val keys = obj.keys()
                while (keys.hasNext()) {
                    val k = keys.next()
                    if (k == "dialer-proxy" || k == "dialer_proxy") continue
                    map[k] = jsonToPlain(obj.opt(k))
                }
            }
            map["name"] = uniqueName
            map["type"] = NodeFingerprint.normalizeProtocol(node.protocol)
            map["server"] = node.server.trim()
            map["port"] = node.port
            proxiesList.add(map)
        }
        val opts = DumperOptions().apply {
            setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK)
            setPrettyFlow(true)
            setAllowUnicode(true)
        }
        return Yaml(opts).dump(mapOf("proxies" to proxiesList))
    }

    private fun serializeGroupsJson(
        groups: List<MultiGroupRecord>,
        idToFp: Map<String, String>,
        idToGroupName: Map<String, String>,
        activeGroupName: String?,
        routeMode: String?,
    ): String {
        val arr = JSONArray()
        for (g in groups) {
            val memberFps = JSONArray()
            for (nid in g.memberNodeIds) {
                idToFp[nid]?.let { memberFps.put(it) }
            }
            arr.put(
                JSONObject().apply {
                    put("name", g.name)
                    put("mode", g.mode)
                    put("match_rules", JSONArray(g.matchRules))
                    put("member_fingerprints", memberFps)
                    if (!g.dynamicFilterJson.isNullOrBlank()) {
                        put("dynamic_filter", runCatching { JSONObject(g.dynamicFilterJson) }.getOrNull() ?: JSONObject.NULL)
                    } else {
                        put("dynamic_filter", JSONObject.NULL)
                    }
                    put("primary_probe_id", g.primaryProbeId ?: JSONObject.NULL)
                    put("hard_gates", JSONArray(g.hardGates))
                    put("trigger_rules", runCatching { JSONArray(g.triggerRulesJson) }.getOrDefault(JSONArray()))
                    put("formula_expr", g.formulaExpr)
                    put("fallback_policy", g.fallbackPolicy)
                    put("fallback_pool_name", g.fallbackPoolId?.let { idToGroupName[it] } ?: JSONObject.NULL)
                    put("recover_probe_interval_sec", g.recoverProbeIntervalSec)
                    put("switch_mode", g.switchMode)
                    put("cooldown_sec", g.cooldownSec)
                    put("hysteresis_pct", g.hysteresisPct)
                    put("active_node_fingerprint", g.activeNodeId?.let { idToFp[it] } ?: JSONObject.NULL)
                    put("independent_routing", g.independentRouting)
                }
            )
        }
        return JSONObject().apply {
            put("schema", GROUPS_SCHEMA_V1)
            put("active_group_name", activeGroupName ?: JSONObject.NULL)
            put("route_mode", routeMode ?: JSONObject.NULL)
            put("groups", arr)
        }.toString(2)
    }

    fun parseGroupsJson(raw: String): ShareGroupsDocument {
        val root = JSONObject(raw.trim())
        val schema = root.optString("schema", GROUPS_SCHEMA_V1).trim()
        require(schema == GROUPS_SCHEMA_V1) { "不支持的 groups.json schema: $schema" }
        val arr = root.optJSONArray("groups") ?: JSONArray()
        val list = ArrayList<ShareGroupRecord>(arr.length())
        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i) ?: continue
            val name = o.optString("name", "").trim()
            if (name.isEmpty()) continue
            list.add(
                ShareGroupRecord(
                    name = name,
                    mode = o.optString("mode", "sticky_best"),
                    matchRules = jsonArrayToStringList(o.optJSONArray("match_rules")),
                    memberFingerprints = jsonArrayToStringList(o.optJSONArray("member_fingerprints")),
                    dynamicFilterJson = o.optJSONObject("dynamic_filter")?.toString(),
                    primaryProbeId = o.optNullableString("primary_probe_id"),
                    hardGates = jsonArrayToStringList(o.optJSONArray("hard_gates")),
                    triggerRulesJson = o.optJSONArray("trigger_rules")?.toString() ?: "[]",
                    formulaExpr = o.optString("formula_expr", MultiGroupRecord.DEFAULT_FORMULA_EXPR),
                    fallbackPolicy = o.optString("fallback_policy", "degrade_best_warn"),
                    fallbackPoolName = o.optNullableString("fallback_pool_name"),
                    recoverProbeIntervalSec = o.optLong("recover_probe_interval_sec", 120L),
                    switchMode = o.optString("switch_mode", "force_close_old"),
                    cooldownSec = o.optLong("cooldown_sec", 60L),
                    hysteresisPct = o.optDouble("hysteresis_pct", 20.0),
                    activeNodeFingerprint = o.optNullableString("active_node_fingerprint"),
                    independentRouting = o.optBoolean("independent_routing", false),
                )
            )
        }
        return ShareGroupsDocument(
            schema = schema,
            activeGroupName = root.optNullableString("active_group_name"),
            routeMode = root.optNullableString("route_mode"),
            groups = list,
        )
    }

    private fun JSONObject.optNullableString(key: String): String? {
        if (!has(key) || isNull(key)) return null
        val s = optString(key, "").trim()
        return s.takeIf { it.isNotEmpty() }
    }

    private fun jsonArrayToStringList(arr: JSONArray?): List<String> {
        if (arr == null) return emptyList()
        val out = ArrayList<String>(arr.length())
        for (i in 0 until arr.length()) {
            val s = arr.optString(i, "").trim()
            if (s.isNotEmpty()) out.add(s)
        }
        return out
    }

    private fun mapToJsonObject(map: Map<*, *>): JSONObject {
        val obj = JSONObject()
        for ((k, v) in map) {
            val key = k?.toString() ?: continue
            obj.put(key, plainToJson(v))
        }
        return obj
    }

    private fun plainToJson(v: Any?): Any = when (v) {
        null -> JSONObject.NULL
        is Map<*, *> -> mapToJsonObject(v)
        is List<*> -> JSONArray().apply { v.forEach { put(plainToJson(it)) } }
        is Boolean, is Int, is Long, is Double, is Float, is String -> v
        else -> v.toString()
    }

    private fun jsonToPlain(v: Any?): Any? = when (v) {
        null, JSONObject.NULL -> null
        is JSONObject -> {
            val m = LinkedHashMap<String, Any?>()
            val keys = v.keys()
            while (keys.hasNext()) {
                val k = keys.next()
                m[k] = jsonToPlain(v.opt(k))
            }
            m
        }
        is JSONArray -> {
            val list = ArrayList<Any?>(v.length())
            for (i in 0 until v.length()) list.add(jsonToPlain(v.opt(i)))
            list
        }
        else -> v
    }

    private fun makeUniqueName(base: String, used: MutableSet<String>): String {
        if (used.add(base)) return base
        var idx = 2
        while (true) {
            val candidate = "$base #$idx"
            if (used.add(candidate)) return candidate
            idx++
        }
    }

    private fun parseQueryParams(rawQuery: String?): Map<String, String> {
        if (rawQuery.isNullOrBlank()) return emptyMap()
        val out = LinkedHashMap<String, String>()
        for (pair in rawQuery.split('&')) {
            val eq = pair.indexOf('=')
            if (eq > 0) {
                val k = urlDecode(pair.substring(0, eq))
                val v = urlDecode(pair.substring(eq + 1))
                out[k] = v
            }
        }
        return out
    }

    private fun urlDecode(raw: String): String =
        runCatching { URLDecoder.decode(raw, "UTF-8") }.getOrDefault(raw)

    private fun decodeFlexibleBase64(input: String): ByteArray? {
        val cleaned = input.trim().filterNot { it.isWhitespace() }
        if (cleaned.isEmpty()) return null
        val padded = when (cleaned.length % 4) {
            2 -> "$cleaned=="
            3 -> "$cleaned="
            else -> cleaned
        }
        return runCatching { Base64.getDecoder().decode(padded) }.getOrNull()
            ?: runCatching { Base64.getUrlDecoder().decode(padded) }.getOrNull()
    }
}
