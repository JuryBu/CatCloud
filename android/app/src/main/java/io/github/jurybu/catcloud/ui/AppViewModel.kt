package io.github.jurybu.catcloud.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.compose.runtime.Immutable
import io.github.jurybu.catcloud.BuildConfig
import io.github.jurybu.catcloud.data.AppDatabase
import io.github.jurybu.catcloud.data.AppSettings
import io.github.jurybu.catcloud.data.InstalledAppInfo
import io.github.jurybu.catcloud.data.LogRingStore
import io.github.jurybu.catcloud.data.MultiGroupRecord
import io.github.jurybu.catcloud.data.NodeFingerprint
import io.github.jurybu.catcloud.data.PerAppMode
import io.github.jurybu.catcloud.data.PreAccelRelayRecord
import io.github.jurybu.catcloud.data.ProxyMode
import io.github.jurybu.catcloud.data.ProxyNodeRecord
import io.github.jurybu.catcloud.data.RelayBoxItem
import io.github.jurybu.catcloud.data.RouteMode
import io.github.jurybu.catcloud.data.ShareBundleCodec
import io.github.jurybu.catcloud.data.ShareBundlePreview
import io.github.jurybu.catcloud.data.ThemePreference
import io.github.jurybu.catcloud.data.VpnRuntimeStatus
import io.github.jurybu.catcloud.data.SpeedTestProgress
import io.github.jurybu.catcloud.engine.ConfigCompiler
import io.github.jurybu.catcloud.engine.SpeedTester
import io.github.jurybu.catcloud.sync.LanSyncClient
import io.github.jurybu.catcloud.sync.ParsedSyncUri
import io.github.jurybu.catcloud.sync.SyncCrypto
import io.github.jurybu.catcloud.sync.SyncRole
import io.github.jurybu.catcloud.vpn.VpnServiceController
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.util.UUID

@Immutable
data class PendingImportBundle(
    val zipBytes: ByteArray,
    val zipFpHex16: String,
    val preview: ShareBundlePreview,
    val sourceLabel: String,
)

@Immutable
data class CatCloudUiState(
    val nodes: List<ProxyNodeRecord> = emptyList(),
    val relays: List<PreAccelRelayRecord> = emptyList(),
    val groups: List<MultiGroupRecord> = emptyList(),
    val settings: AppSettings = AppSettings(),
    val relayBoxItems: List<RelayBoxItem> = emptyList(),
    val vpnStatus: VpnRuntimeStatus = VpnRuntimeStatus(),
    val speedTestProgress: SpeedTestProgress = SpeedTestProgress(),
    val installedApps: List<InstalledAppInfo> = emptyList(),
    val recentLogs: List<String> = emptyList(),
    val busy: Boolean = false,
    val toastMessage: String? = null,
    val pendingImportBundle: PendingImportBundle? = null,
    val pendingCcsyncBytes: ByteArray? = null,
    val pendingPushRelayBoxId: String? = null,
)

class AppViewModel(private val appContext: Context) {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val db = AppDatabase(appContext)
    private val logStore = LogRingStore(File(appContext.filesDir, "logs"))
    private val vpnController = VpnServiceController(appContext)
    private val syncClient = LanSyncClient()
    private val speedTester = SpeedTester()

    private val _state = MutableStateFlow(CatCloudUiState())
    val state: StateFlow<CatCloudUiState> = _state.asStateFlow()

    private var statusPollJob: Job? = null
    private var speedTestJob: Job? = null

    init {
        loadInitialData()
        startLightStatusPoller()
    }

    private fun loadInitialData() {
        scope.launch {
            val (nodes, relays, groups, settings, boxItems) = withContext(Dispatchers.IO) {
                Tuple5(
                    db.listNodes(),
                    db.listRelays(),
                    db.listGroups(),
                    db.loadSettings(),
                    db.listRelayBoxItems(),
                )
            }
            val vpnStatus = vpnController.pollStatusIfRunning()
            _state.update {
                it.copy(
                    nodes = nodes,
                    relays = relays,
                    groups = groups,
                    settings = settings,
                    relayBoxItems = boxItems,
                    vpnStatus = vpnStatus,
                )
            }
        }
    }

    private fun startLightStatusPoller() {
        statusPollJob?.cancel()
        statusPollJob = scope.launch {
            while (isActive) {
                delay(2500L)
                // Zero-wake guard: pollStatusIfRunning checks system VPN transport first
                val status = vpnController.pollStatusIfRunning()
                _state.update { cur ->
                    if (cur.vpnStatus == status) cur else cur.copy(vpnStatus = status)
                }
            }
        }
    }

    fun clearToast() {
        _state.update { it.copy(toastMessage = null) }
    }

    fun showToast(msg: String) {
        _state.update { it.copy(toastMessage = msg) }
    }

    fun dismissPendingImport() {
        _state.update { it.copy(pendingImportBundle = null) }
    }

    fun dismissPendingCcsync() {
        _state.update { it.copy(pendingCcsyncBytes = null) }
    }

    fun preparePushFromRelayBox(itemId: String?) {
        _state.update { it.copy(pendingPushRelayBoxId = itemId) }
    }

    // ---- VPN Lifecycle & Routing Selection ----

    fun connectVpn() {
        scope.launch {
            val cur = _state.value
            if (cur.nodes.none { it.enabled }) {
                showToast("请先扫码同步或导入至少 1 个代理节点")
                return@launch
            }
            _state.update { it.copy(busy = true) }
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val effectiveSettings = ensureValidActiveRoute(cur.settings, cur.nodes, cur.groups)
                    if (effectiveSettings != cur.settings) db.saveSettings(effectiveSettings)
                    val compiled = ConfigCompiler.compile(
                        settings = effectiveSettings,
                        nodes = cur.nodes,
                        groups = cur.groups,
                        relays = cur.relays,
                    )
                    val cfgFile = db.writeRuntimeConfigAtomically(compiled.yaml)
                    val updatedSettings = effectiveSettings.copy(lastVpnWasRunning = true)
                    db.saveSettings(updatedSettings)
                    db.writeBootSnapshotAtomically(
                        configPath = cfgFile.absolutePath,
                        settings = updatedSettings,
                        activeNodeName = compiled.activeGroupOrNodeName,
                        activeNodeCount = compiled.activeNodeCount,
                        wasRunning = true,
                    )
                    val startRes = vpnController.startVpn(
                        configPath = cfgFile.absolutePath,
                        perAppMode = updatedSettings.perAppMode.wireValue,
                        perAppPackages = updatedSettings.perAppPackages,
                        activeNodeName = compiled.activeGroupOrNodeName,
                        activeNodeCount = compiled.activeNodeCount,
                    )
                    Pair(updatedSettings, startRes)
                }
            }
            val status = vpnController.pollStatusIfRunning()
            result.fold(
                onSuccess = { (newSettings, startRes) ->
                    val ok = startRes == "OK"
                    logStore.append("UI", "startVpn -> $startRes")
                    _state.update {
                        it.copy(
                            busy = false,
                            settings = newSettings,
                            vpnStatus = status,
                            toastMessage = if (ok) "已连接猫猫云梯" else "连接失败：$startRes",
                        )
                    }
                },
                onFailure = { err ->
                    logStore.append("UI", "connectVpn failed: ${err.message}")
                    _state.update {
                        it.copy(busy = false, vpnStatus = status, toastMessage = "启动失败：${err.message}")
                    }
                },
            )
        }
    }

    fun disconnectVpn() {
        scope.launch {
            _state.update { it.copy(busy = true) }
            withContext(Dispatchers.IO) {
                val cur = _state.value
                val updated = cur.settings.copy(lastVpnWasRunning = false)
                db.saveSettings(updated)
                val cfgPath = File(appContext.filesDir, AppDatabase.RUNTIME_CONFIG_FILENAME).absolutePath
                db.writeBootSnapshotAtomically(
                    configPath = cfgPath,
                    settings = updated,
                    activeNodeName = cur.vpnStatus.activeNodeName,
                    activeNodeCount = cur.vpnStatus.activeNodeCount,
                    wasRunning = false,
                )
            }
            vpnController.stopVpn()
            logStore.append("UI", "VPN disconnected by user")
            _state.update {
                it.copy(
                    busy = false,
                    settings = it.settings.copy(lastVpnWasRunning = false),
                    vpnStatus = VpnRuntimeStatus(running = false, state = "stopped"),
                    toastMessage = "已断开连接",
                )
            }
        }
    }

    fun forceRestartCore() {
        scope.launch {
            _state.update { it.copy(busy = true) }
            val res = vpnController.forceRestartCore()
            val status = vpnController.pollStatusIfRunning()
            logStore.append("UI", "forceRestartCore -> $res")
            _state.update {
                it.copy(
                    busy = false,
                    vpnStatus = status,
                    toastMessage = if (res == "OK") "核心已强制重启并恢复连接" else "重启结果：$res",
                )
            }
        }
    }

    fun selectSingleNode(nodeId: String) {
        updateSettingsAndMaybeReload {
            it.copy(routeMode = RouteMode.SINGLE, activeSingleNodeId = nodeId)
        }
    }

    fun selectMultiGroup(groupId: String) {
        updateSettingsAndMaybeReload {
            it.copy(routeMode = RouteMode.GROUP, activeGroupId = groupId)
        }
    }

    fun setProxyMode(mode: ProxyMode) {
        updateSettingsAndMaybeReload { it.copy(proxyMode = mode) }
    }

    fun togglePreAccel(enabled: Boolean) {
        if (enabled && _state.value.relays.none { it.enabled }) {
            showToast("请先在「节点 → 国内提速」添加或同步中转线路")
            return
        }
        updateSettingsAndMaybeReload { it.copy(preaccelEnabled = enabled) }
    }

    fun togglePreAccelAutoFailover(autoFailover: Boolean) {
        updateSettingsAndMaybeReload { it.copy(preaccelAutoFailover = autoFailover) }
    }

    fun selectActiveRelay(relayId: String) {
        updateSettingsAndMaybeReload { it.copy(preaccelActiveRelayId = relayId) }
    }

    fun setTheme(theme: ThemePreference) {
        updateSettingsOnly { it.copy(theme = theme) }
    }

    fun setAutoStartOnBoot(enabled: Boolean) {
        updateSettingsOnly { it.copy(autoStartOnBoot = enabled) }
    }

    fun updatePerAppControl(mode: PerAppMode, packages: List<String>) {
        val clean = packages.filter { it.isNotBlank() && it != appContext.packageName }.distinct()
        updateSettingsOnly { it.copy(perAppMode = mode, perAppPackages = clean) }
        if (_state.value.vpnStatus.running) {
            showToast("分应用设置已保存，断开重连后生效")
        }
    }

    fun deleteNode(nodeId: String) {
        scope.launch {
            withContext(Dispatchers.IO) { db.deleteNode(nodeId) }
            reloadInventoryFromDb()
        }
    }

    fun deleteRelay(relayId: String) {
        scope.launch {
            withContext(Dispatchers.IO) { db.deleteRelay(relayId) }
            reloadInventoryFromDb()
        }
    }

    private fun updateSettingsOnly(transform: (AppSettings) -> AppSettings) {
        scope.launch {
            val next = transform(_state.value.settings)
            withContext(Dispatchers.IO) {
                db.saveSettings(next)
                val cfgPath = File(appContext.filesDir, AppDatabase.RUNTIME_CONFIG_FILENAME).absolutePath
                db.writeBootSnapshotAtomically(
                    configPath = cfgPath,
                    settings = next,
                    activeNodeName = _state.value.vpnStatus.activeNodeName,
                    activeNodeCount = _state.value.vpnStatus.activeNodeCount,
                    wasRunning = _state.value.vpnStatus.running,
                )
            }
            _state.update { it.copy(settings = next) }
        }
    }

    private fun updateSettingsAndMaybeReload(transform: (AppSettings) -> AppSettings) {
        scope.launch {
            val cur = _state.value
            val next = transform(cur.settings)
            _state.update { it.copy(settings = next) }
            val reloadMsg = withContext(Dispatchers.IO) {
                db.saveSettings(next)
                if (!cur.vpnStatus.running || cur.nodes.none { it.enabled }) return@withContext null
                runCatching {
                    val compiled = ConfigCompiler.compile(next, cur.nodes, cur.groups, cur.relays)
                    val cfgFile = db.writeRuntimeConfigAtomically(compiled.yaml)
                    db.writeBootSnapshotAtomically(
                        configPath = cfgFile.absolutePath,
                        settings = next,
                        activeNodeName = compiled.activeGroupOrNodeName,
                        activeNodeCount = compiled.activeNodeCount,
                        wasRunning = true,
                    )
                    vpnController.reloadVpn(cfgFile.absolutePath, compiled.activeGroupOrNodeName, compiled.activeNodeCount)
                }.getOrElse { "ERR:${it.message}" }
            }
            if (reloadMsg != null && reloadMsg != "OK" && reloadMsg != "OK_NOT_RUNNING") {
                showToast("热切换提示：$reloadMsg")
            } else if (reloadMsg == "OK") {
                val st = vpnController.pollStatusIfRunning()
                _state.update { it.copy(vpnStatus = st) }
            }
        }
    }

    // ---- Sync, QR, Clipboard (on-demand only!), File Import & Portable Relay Box ----

    /**
     * Explicitly invoked ONLY when the user taps "从剪贴板识别" (NEVER called silently on launch/resume).
     */
    fun importFromClipboardOnDemand() {
        val cm = appContext.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        val text = cm?.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(appContext)?.toString()?.trim()
        if (text.isNullOrBlank()) {
            showToast("剪贴板为空")
            return
        }
        handleScannedOrPastedText(text, sourceLabel = "剪贴板")
    }

    fun handleScannedOrPastedText(raw: String, sourceLabel: String = "扫码") {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return

        // 1. CatCloud encrypted sync URI (`catcloud://sync/v1?...#k=...` / `catcloud-sync://`)
        if (trimmed.startsWith("catcloud://sync", true) || trimmed.startsWith("catcloud-sync://", true)) {
            handleSyncUri(trimmed)
            return
        }

        // 2. Domestic `:443` relay bundle (`mmrelay://v1/...` or mmrelay JSON)
        if (trimmed.startsWith("mmrelay://v1/", true) || trimmed.contains("\"mmrelay/v1\"")) {
            scope.launch {
                val res = withContext(Dispatchers.IO) {
                    runCatching {
                        val relays = ShareBundleCodec.decodeMmRelayInput(trimmed)
                        db.upsertRelaysDedup(relays)
                    }
                }
                res.fold(
                    onSuccess = { count ->
                        reloadInventoryFromDb()
                        showToast("已导入 $count 条国内提速中转线路")
                    },
                    onFailure = { showToast("中转解析失败：${it.message}") },
                )
            }
            return
        }

        // 3. Standard proxy URIs / Base64 / Clash YAML
        scope.launch {
            val res = withContext(Dispatchers.IO) {
                runCatching {
                    val parsed = ShareBundleCodec.parseTextImport(trimmed, subId = sourceLabel)
                    require(parsed.isNotEmpty()) { "未识别到可导入的代理节点、中转或同步码" }
                    db.upsertNodesDedup(parsed).first
                }
            }
            res.fold(
                onSuccess = { count ->
                    reloadInventoryFromDb()
                    showToast("已从${sourceLabel}导入 $count 个节点")
                },
                onFailure = { showToast("${it.message}") },
            )
        }
    }

    private fun handleSyncUri(uriText: String) {
        scope.launch {
            val parsed = runCatching { SyncCrypto.parseSyncUri(uriText) }.getOrElse {
                showToast("同步码校验失败：${it.message}")
                return@launch
            }
            when (parsed.role) {
                SyncRole.PULL, SyncRole.RELAY_URL -> {
                    _state.update { it.copy(busy = true) }
                    val res = runCatching { syncClient.pullBySyncUri(parsed) }
                    res.fold(
                        onSuccess = { pulled ->
                            logStore.append("SYNC", "Pulled sync bundle fp=${pulled.zipFpHex16} nodes=${pulled.preview.nodes.size}")
                            _state.update {
                                it.copy(
                                    busy = false,
                                    pendingImportBundle = PendingImportBundle(
                                        zipBytes = pulled.zipBytes,
                                        zipFpHex16 = pulled.zipFpHex16,
                                        preview = pulled.preview,
                                        sourceLabel = pulled.sourceBaseUrl,
                                    ),
                                )
                            }
                        },
                        onFailure = { err ->
                            logStore.append("SYNC", "Pull failed: ${err.message}")
                            _state.update { it.copy(busy = false, toastMessage = "拉取同步失败：${err.message}") }
                        },
                    )
                }
                SyncRole.PUSH -> {
                    pushCurrentOrRelayBoxToDesktop(parsed)
                }
                SyncRole.FILE_KEY -> {
                    val pendingCcsync = _state.value.pendingCcsyncBytes
                    if (pendingCcsync == null) {
                        showToast("请先选择对应的 .ccsync 离线加密文件，再扫描密钥二维码")
                        return@launch
                    }
                    decryptPendingCcsync(pendingCcsync, fileKeyUri = parsed, password = null)
                }
            }
        }
    }

    fun pullWithSixDigitPin(host: String, port: Int, pin: String) {
        scope.launch {
            _state.update { it.copy(busy = true) }
            val res = runCatching { syncClient.pullWithPin(host, port, pin) }
            res.fold(
                onSuccess = { pulled ->
                    logStore.append("SYNC", "PIN ECDH pull success fp=${pulled.zipFpHex16}")
                    _state.update {
                        it.copy(
                            busy = false,
                            pendingImportBundle = PendingImportBundle(
                                zipBytes = pulled.zipBytes,
                                zipFpHex16 = pulled.zipFpHex16,
                                preview = pulled.preview,
                                sourceLabel = "PIN 配对 (${pulled.sourceBaseUrl})",
                            ),
                        )
                    }
                },
                onFailure = { err ->
                    logStore.append("SYNC", "PIN pull failed: ${err.message}")
                    _state.update { it.copy(busy = false, toastMessage = "配对码拉取失败：${err.message}") }
                },
            )
        }
    }

    private fun pushCurrentOrRelayBoxToDesktop(parsedPushUri: ParsedSyncUri) {
        scope.launch {
            _state.update { it.copy(busy = true) }
            val cur = _state.value
            val res = withContext(Dispatchers.IO) {
                runCatching {
                    val payloadZip: ByteArray = if (cur.pendingPushRelayBoxId != null) {
                        db.readRelayBoxPayload(cur.pendingPushRelayBoxId)
                            ?: throw IllegalStateException("随身接力箱中找不到目标包裹")
                    } else {
                        val activeGroupName = cur.groups.firstOrNull { it.id == cur.settings.activeGroupId }?.name
                        ShareBundleCodec.exportShareBundleZip(
                            name = "CatCloud-Android-Export",
                            nodes = cur.nodes,
                            relays = cur.relays,
                            groups = cur.groups,
                            activeGroupName = activeGroupName,
                            routeMode = cur.settings.routeMode.wireValue,
                        ).first
                    }
                    syncClient.pushBySyncUri(parsedPushUri, payloadZip)
                }
            }
            res.fold(
                onSuccess = { endpoint ->
                    logStore.append("SYNC", "Pushed encrypted bundle to $endpoint")
                    _state.update {
                        it.copy(
                            busy = false,
                            pendingPushRelayBoxId = null,
                            toastMessage = "已端到端加密推送到对方设备，请在电脑端确认导入",
                        )
                    }
                },
                onFailure = { err ->
                    logStore.append("SYNC", "Push failed: ${err.message}")
                    _state.update {
                        it.copy(
                            busy = false,
                            pendingPushRelayBoxId = null,
                            toastMessage = "推送失败：${err.message}",
                        )
                    }
                },
            )
        }
    }

    fun confirmImportPendingBundle(alsoSaveToRelayBox: Boolean) {
        val pending = _state.value.pendingImportBundle ?: return
        scope.launch {
            _state.update { it.copy(busy = true) }
            val res = withContext(Dispatchers.IO) {
                runCatching {
                    val (_, fpToNodeId) = db.upsertNodesDedup(pending.preview.nodes)
                    val relayCount = if (pending.preview.relays.isNotEmpty()) {
                        db.upsertRelaysDedup(pending.preview.relays)
                    } else 0
                    var groupMsg = ""
                    pending.preview.groupsDoc?.let { gDoc ->
                        val existing = db.listGroups()
                        val merged = ShareBundleCodec.mergeImportedGroups(existing, gDoc, fpToNodeId)
                        db.replaceAllGroups(merged.mergedGroups)
                        groupMsg = "，多选组 +${merged.importedCount}/合并 ${merged.mergedCount}"
                    }
                    if (alsoSaveToRelayBox && pending.zipBytes.size <= AppDatabase.MAX_RELAY_BOX_ITEM_BYTES) {
                        db.saveRelayBoxEntry(
                            id = "box-${UUID.randomUUID().toString().replace("-", "").take(10)}",
                            name = pending.preview.manifest.name,
                            zipFp = pending.zipFpHex16,
                            payloadBytes = pending.zipBytes,
                            nodeCount = pending.preview.nodes.size,
                            relayCount = pending.preview.relays.size,
                            groupCount = pending.preview.groupsDoc?.groups?.size ?: 0,
                        )
                    }
                    "已导入 ${pending.preview.nodes.size} 节点、$relayCount 中转$groupMsg"
                }
            }
            reloadInventoryFromDb()
            res.fold(
                onSuccess = { msg ->
                    _state.update { it.copy(busy = false, pendingImportBundle = null, toastMessage = msg) }
                },
                onFailure = { err ->
                    _state.update { it.copy(busy = false, toastMessage = "写入失败：${err.message}") }
                },
            )
        }
    }

    fun importFromContentUri(uri: Uri) {
        scope.launch {
            _state.update { it.copy(busy = true) }
            val rawBytes = withContext(Dispatchers.IO) {
                runCatching {
                    appContext.contentResolver.openInputStream(uri)?.use { ins ->
                        val out = java.io.ByteArrayOutputStream()
                        val buf = ByteArray(8192)
                        var total = 0
                        while (true) {
                            val n = ins.read(buf)
                            if (n < 0) break
                            total += n
                            if (total > ShareBundleCodec.MAX_ZIP_FILE_BYTES) {
                                throw SecurityException("文件超过 17 MiB 安全上限")
                            }
                            out.write(buf, 0, n)
                        }
                        out.toByteArray()
                    } ?: throw IllegalArgumentException("无法读取所选文件")
                }
            }.getOrElse { err ->
                _state.update { it.copy(busy = false, toastMessage = "读取文件失败：${err.message}") }
                return@launch
            }

            // Detect CCSYNC01 encrypted envelope
            if (rawBytes.size >= 8 && rawBytes.copyOfRange(0, 8).contentEquals(SyncCrypto.MAGIC)) {
                _state.update {
                    it.copy(
                        busy = false,
                        pendingCcsyncBytes = rawBytes,
                        toastMessage = "已加载加密包 .ccsync，请扫描密钥二维码或输入口令解密",
                    )
                }
                return@launch
            }

            // Detect ZIP share bundle (PK\x03\x04)
            if (rawBytes.size >= 4 && rawBytes[0] == 0x50.toByte() && rawBytes[1] == 0x4b.toByte()) {
                val res = withContext(Dispatchers.IO) {
                    runCatching {
                        val preview = ShareBundleCodec.previewShareBundleZip(rawBytes)
                        val fp = SyncCrypto.bundleFingerprintHex16(rawBytes)
                        PendingImportBundle(rawBytes, fp, preview, "本地 .zip 分享包")
                    }
                }
                res.fold(
                    onSuccess = { bundle ->
                        _state.update { it.copy(busy = false, pendingImportBundle = bundle) }
                    },
                    onFailure = { err ->
                        _state.update { it.copy(busy = false, toastMessage = "分享包校验失败：${err.message}") }
                    },
                )
                return@launch
            }

            // Plain text YAML / URI list / mmrelay
            _state.update { it.copy(busy = false) }
            handleScannedOrPastedText(rawBytes.toString(Charsets.UTF_8), sourceLabel = "文件")
        }
    }

    fun decryptPendingCcsyncWithPassword(password: String) {
        val bytes = _state.value.pendingCcsyncBytes ?: return
        decryptPendingCcsync(bytes, fileKeyUri = null, password = password)
    }

    private fun decryptPendingCcsync(bytes: ByteArray, fileKeyUri: ParsedSyncUri?, password: String?) {
        scope.launch {
            _state.update { it.copy(busy = true) }
            val res = withContext(Dispatchers.IO) {
                runCatching {
                    syncClient.decryptOfflineCcsyncFile(bytes, fileKeyUri = fileKeyUri, password = password)
                }
            }
            res.fold(
                onSuccess = { pulled ->
                    _state.update {
                        it.copy(
                            busy = false,
                            pendingCcsyncBytes = null,
                            pendingImportBundle = PendingImportBundle(
                                zipBytes = pulled.zipBytes,
                                zipFpHex16 = pulled.zipFpHex16,
                                preview = pulled.preview,
                                sourceLabel = "离线 .ccsync 加密包",
                            ),
                        )
                    }
                },
                onFailure = { err ->
                    _state.update { it.copy(busy = false, toastMessage = "解密失败：${err.message}") }
                },
            )
        }
    }

    fun deleteRelayBoxItem(id: String) {
        scope.launch {
            withContext(Dispatchers.IO) { db.deleteRelayBoxEntry(id) }
            reloadInventoryFromDb()
        }
    }

    fun clearRelayBox() {
        scope.launch {
            withContext(Dispatchers.IO) { db.clearRelayBox() }
            reloadInventoryFromDb()
            showToast("已清空随身加密接力箱")
        }
    }

    // ---- Speed Testing (default lightweight ping + optional serial throughput) ----

    fun testAllLatencies() {
        val cur = _state.value
        if (cur.nodes.isEmpty()) {
            showToast("当前没有可测速节点")
            return
        }
        speedTestJob?.cancel()
        speedTestJob = scope.launch {
            val targets = cur.nodes.filter { it.enabled }
            _state.update {
                it.copy(
                    speedTestProgress = SpeedTestProgress(
                        running = true,
                        modeLabel = "测延迟",
                        completed = 0,
                        total = targets.size,
                    )
                )
            }
            var done = 0
            speedTester.testLatencies(
                nodes = targets,
                restPort = cur.vpnStatus.restPort,
                restSecret = cur.vpnStatus.restSecret,
                onNodeDone = { nodeId, ms ->
                    done++
                    db.updateNodeMetrics(nodeId, latencyMs = ms)
                    _state.update { st ->
                        st.copy(
                            nodes = st.nodes.map { n ->
                                if (n.id == nodeId) n.copy(lastLatencyMs = ms) else n
                            },
                            speedTestProgress = st.speedTestProgress.copy(completed = done),
                        )
                    }
                },
            )
            _state.update { it.copy(speedTestProgress = SpeedTestProgress(running = false)) }
            showToast("延迟测速完成")
        }
    }

    fun startSerialThroughputTest(selectedNodeIds: Set<String>, usePreAccel: Boolean) {
        val cur = _state.value
        val targets = cur.nodes.filter { selectedNodeIds.contains(it.id) }
        if (targets.isEmpty()) {
            showToast("请先勾选至少 1 个节点")
            return
        }
        speedTestJob?.cancel()
        speedTestJob = scope.launch {
            _state.update {
                it.copy(
                    speedTestProgress = SpeedTestProgress(
                        running = true,
                        modeLabel = if (usePreAccel) "串行上下行 (含443提速)" else "串行上下行 (直连对照)",
                        completed = 0,
                        total = targets.size,
                        usePreAccel = usePreAccel,
                    )
                )
            }
            var done = 0
            try {
                speedTester.testThroughputSerial(
                    nodes = targets,
                    restPort = cur.vpnStatus.restPort,
                    restSecret = cur.vpnStatus.restSecret,
                    targetGroupName = cur.vpnStatus.activeNodeName.ifBlank { ConfigCompiler.SINGLE_NODE_GROUP },
                    usePreAccel = usePreAccel,
                    onPauseWatchdog = { paused ->
                        logStore.append("SPEED", if (paused) "Watchdog paused for throughput test" else "Watchdog resumed")
                    },
                    onProgress = { idx, total, node ->
                        _state.update {
                            it.copy(
                                speedTestProgress = it.speedTestProgress.copy(
                                    completed = idx,
                                    total = total,
                                    currentNodeName = node.name,
                                )
                            )
                        }
                    },
                    onNodeResult = { res ->
                        done++
                        db.updateNodeMetrics(res.nodeId, res.latencyMs, res.downMbps, res.upMbps)
                        _state.update { st ->
                            st.copy(
                                nodes = st.nodes.map { n ->
                                    if (n.id == res.nodeId) {
                                        n.copy(
                                            lastLatencyMs = res.latencyMs ?: n.lastLatencyMs,
                                            lastDownMbps = res.downMbps ?: n.lastDownMbps,
                                            lastUpMbps = res.upMbps ?: n.lastUpMbps,
                                        )
                                    } else n
                                },
                                speedTestProgress = st.speedTestProgress.copy(completed = done),
                            )
                        }
                    },
                )
                showToast("上下行测速已完成 ($done/${targets.size})")
            } finally {
                _state.update { it.copy(speedTestProgress = SpeedTestProgress(running = false)) }
            }
        }
    }

    fun stopSpeedTest() {
        speedTester.cancelActive()
        speedTestJob?.cancel()
        speedTestJob = null
        _state.update {
            it.copy(
                speedTestProgress = SpeedTestProgress(running = false),
                toastMessage = "已停止测速并保留已测结果",
            )
        }
    }

    // ---- Installed Apps & Sanitized Diagnostics ----

    fun loadInstalledAppsIfNeeded() {
        if (_state.value.installedApps.isNotEmpty()) return
        scope.launch {
            val apps = withContext(Dispatchers.IO) {
                val pm = appContext.packageManager
                val list = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0))
                } else {
                    @Suppress("DEPRECATION")
                    pm.getInstalledApplications(0)
                }
                list.filter { it.packageName != appContext.packageName }
                    .map { info ->
                        InstalledAppInfo(
                            packageName = info.packageName,
                            label = runCatching { pm.getApplicationLabel(info).toString() }
                                .getOrDefault(info.packageName),
                            isSystemApp = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
                        )
                    }
                    .sortedWith(compareBy<InstalledAppInfo> { it.isSystemApp }.thenBy { it.label.lowercase() })
            }
            _state.update { it.copy(installedApps = apps) }
        }
    }

    fun refreshLogs() {
        scope.launch {
            val lines = withContext(Dispatchers.IO) { logStore.readRecentLines(180) }
            _state.update { it.copy(recentLogs = lines) }
        }
    }

    fun copyDiagnosticsToClipboard() {
        val cur = _state.value
        val summary = logStore.buildDiagnosticSummary(
            appVersion = BuildConfig.VERSION_NAME,
            deviceModel = "${Build.MANUFACTURER} ${Build.MODEL}",
            androidSdk = Build.VERSION.SDK_INT,
            vpnStatus = cur.vpnStatus,
            nodeCount = cur.nodes.size,
            relayCount = cur.relays.size,
            groupCount = cur.groups.size,
        )
        val cm = appContext.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        cm?.setPrimaryClip(ClipData.newPlainText("CatCloud Diagnostics", summary))
        showToast("已复制脱敏诊断摘要")
    }

    private suspend fun reloadInventoryFromDb() {
        val (nodes, relays, groups, boxItems) = withContext(Dispatchers.IO) {
            Tuple4(db.listNodes(), db.listRelays(), db.listGroups(), db.listRelayBoxItems())
        }
        val fixedSettings = ensureValidActiveRoute(_state.value.settings, nodes, groups)
        if (fixedSettings != _state.value.settings) {
            withContext(Dispatchers.IO) { db.saveSettings(fixedSettings) }
        }
        _state.update {
            it.copy(
                nodes = nodes,
                relays = relays,
                groups = groups,
                settings = fixedSettings,
                relayBoxItems = boxItems,
            )
        }
    }

    private fun ensureValidActiveRoute(
        settings: AppSettings,
        nodes: List<ProxyNodeRecord>,
        groups: List<MultiGroupRecord>,
    ): AppSettings {
        val enabledNodes = nodes.filter { it.enabled }
        var next = settings
        if (next.routeMode == RouteMode.SINGLE) {
            val valid = next.activeSingleNodeId?.let { id -> enabledNodes.any { it.id == id } } == true
            if (!valid && enabledNodes.isNotEmpty()) {
                next = next.copy(activeSingleNodeId = enabledNodes.first().id)
            }
        } else {
            val valid = next.activeGroupId?.let { id -> groups.any { it.id == id } } == true
            if (!valid) {
                next = if (groups.isNotEmpty()) {
                    next.copy(activeGroupId = groups.first().id)
                } else {
                    next.copy(routeMode = RouteMode.SINGLE, activeSingleNodeId = enabledNodes.firstOrNull()?.id)
                }
            }
        }
        return next
    }

    fun close() {
        speedTester.cancelActive()
        statusPollJob?.cancel()
        vpnController.unbindSafely()
        scope.cancel()
        db.close()
    }

    private data class Tuple4<A, B, C, D>(val a: A, val b: B, val c: C, val d: D)
    private data class Tuple5<A, B, C, D, E>(val a: A, val b: B, val c: C, val d: D, val e: E)
}
