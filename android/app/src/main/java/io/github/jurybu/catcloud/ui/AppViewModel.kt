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
import io.github.jurybu.catcloud.data.SpeedTestProgress
import io.github.jurybu.catcloud.data.ThemePreference
import io.github.jurybu.catcloud.data.VpnRuntimeStatus
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
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import okhttp3.Credentials
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URLDecoder
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

@Immutable
data class PendingImportBundle(
    val pendingId: String,
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
    val pendingCcsyncId: String? = null,
    val pendingPushRelayBoxId: String? = null,
)

class AppViewModel(private val appContext: Context) {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val db = AppDatabase(appContext)
    private val logDir = File(appContext.filesDir, "logs")
    private val logStore = LogRingStore(logDir, filePrefix = "catcloud-ui")
    private val vpnController = VpnServiceController(appContext)
    private val syncClient = LanSyncClient()
    private val speedTester = SpeedTester()

    private val pendingZipBytesById = ConcurrentHashMap<String, ByteArray>()
    private val pendingCcsyncBytesById = ConcurrentHashMap<String, ByteArray>()

    @Volatile
    private var activeMixedPort: Int = 0

    @Volatile
    private var activeMixedSecret: String = ""

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
            syncCachedMixedFromStatus(vpnStatus)
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
                syncCachedMixedFromStatus(status)
                _state.update { cur ->
                    if (cur.vpnStatus == status) cur else cur.copy(vpnStatus = status)
                }
            }
        }
    }

    private fun syncCachedMixedFromStatus(status: VpnRuntimeStatus) {
        if (status.running && status.mixedPort > 0 && status.mixedSecret.isNotBlank()) {
            activeMixedPort = status.mixedPort
            activeMixedSecret = status.mixedSecret
        }
    }

    private fun generateRandomHexSecret(bytesLen: Int = 32): String {
        val buf = ByteArray(bytesLen)
        SecureRandom().nextBytes(buf)
        return NodeFingerprint.toHexLower(buf)
    }

    private fun resolveLocalMixedCredentials(
        status: VpnRuntimeStatus,
        forceNew: Boolean = false,
    ): Pair<Int, String> {
        if (!forceNew) {
            if (status.mixedPort > 0 && status.mixedSecret.isNotBlank()) {
                activeMixedPort = status.mixedPort
                activeMixedSecret = status.mixedSecret
                return status.mixedPort to status.mixedSecret
            }
            if (activeMixedPort > 0 && activeMixedSecret.isNotBlank()) {
                return activeMixedPort to activeMixedSecret
            }
        }
        val port = ConfigCompiler.allocateLoopbackPort()
        val secret = generateRandomHexSecret(32)
        activeMixedPort = port
        activeMixedSecret = secret
        return port to secret
    }

    private fun storePendingImportBundle(
        zipBytes: ByteArray,
        zipFpHex16: String,
        preview: ShareBundlePreview,
        sourceLabel: String,
    ): PendingImportBundle {
        pendingZipBytesById.clear()
        val id = UUID.randomUUID().toString()
        pendingZipBytesById[id] = zipBytes
        return PendingImportBundle(
            pendingId = id,
            zipFpHex16 = zipFpHex16,
            preview = preview,
            sourceLabel = sourceLabel,
        )
    }

    private fun storePendingCcsyncBytes(bytes: ByteArray): String {
        pendingCcsyncBytesById.clear()
        val id = UUID.randomUUID().toString()
        pendingCcsyncBytesById[id] = bytes
        return id
    }

    fun clearToast() {
        _state.update { it.copy(toastMessage = null) }
    }

    fun showToast(msg: String) {
        _state.update { it.copy(toastMessage = msg) }
    }

    fun dismissPendingImport() {
        pendingZipBytesById.clear()
        _state.update { it.copy(pendingImportBundle = null) }
    }

    fun dismissPendingCcsync() {
        pendingCcsyncBytesById.clear()
        _state.update { it.copy(pendingCcsyncId = null) }
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
                    val (mixedPort, mixedSecret) = resolveLocalMixedCredentials(cur.vpnStatus, forceNew = true)
                    val compiled = ConfigCompiler.compile(
                        settings = effectiveSettings,
                        nodes = cur.nodes,
                        groups = cur.groups,
                        relays = cur.relays,
                        localMixedPort = mixedPort,
                        localMixedSecret = mixedSecret,
                    )
                    activeMixedPort = compiled.localMixedPort
                    activeMixedSecret = compiled.localMixedSecret
                    val cfgFile = db.writeRuntimeConfigAtomically(compiled.yaml)
                    val updatedSettings = effectiveSettings.copy(lastVpnWasRunning = true)
                    db.saveSettings(updatedSettings)
                    db.writeBootSnapshotAtomically(
                        configPath = cfgFile.absolutePath,
                        settings = updatedSettings,
                        activeNodeName = compiled.activeGroupOrNodeName,
                        activeNodeCount = compiled.activeNodeCount,
                        wasRunning = true,
                        controllerGroupName = compiled.controllerGroupName,
                    )
                    val startRes = vpnController.startVpn(
                        configPath = cfgFile.absolutePath,
                        perAppMode = updatedSettings.perAppMode.wireValue,
                        perAppPackages = updatedSettings.perAppPackages,
                        activeNodeName = compiled.activeGroupOrNodeName,
                        activeNodeCount = compiled.activeNodeCount,
                        controllerGroupName = compiled.controllerGroupName,
                    )
                    Pair(updatedSettings, startRes)
                }
            }
            val status = vpnController.pollStatusIfRunning()
            syncCachedMixedFromStatus(status)
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
            activeMixedPort = 0
            activeMixedSecret = ""
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
                    controllerGroupName = cur.vpnStatus.controllerGroupName.ifBlank { cur.vpnStatus.activeNodeName },
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
            syncCachedMixedFromStatus(status)
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
            val cur = _state.value
            val next = transform(cur.settings)
            withContext(Dispatchers.IO) {
                db.saveSettings(next)
                val cfgPath = File(appContext.filesDir, AppDatabase.RUNTIME_CONFIG_FILENAME).absolutePath
                db.writeBootSnapshotAtomically(
                    configPath = cfgPath,
                    settings = next,
                    activeNodeName = cur.vpnStatus.activeNodeName,
                    activeNodeCount = cur.vpnStatus.activeNodeCount,
                    wasRunning = cur.vpnStatus.running,
                    controllerGroupName = cur.vpnStatus.controllerGroupName.ifBlank { cur.vpnStatus.activeNodeName },
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
                    val (mixedPort, mixedSecret) = resolveLocalMixedCredentials(cur.vpnStatus, forceNew = false)
                    val compiled = ConfigCompiler.compile(
                        settings = next,
                        nodes = cur.nodes,
                        groups = cur.groups,
                        relays = cur.relays,
                        localMixedPort = mixedPort,
                        localMixedSecret = mixedSecret,
                    )
                    activeMixedPort = compiled.localMixedPort
                    activeMixedSecret = compiled.localMixedSecret
                    val cfgFile = db.writeRuntimeConfigAtomically(compiled.yaml)
                    db.writeBootSnapshotAtomically(
                        configPath = cfgFile.absolutePath,
                        settings = next,
                        activeNodeName = compiled.activeGroupOrNodeName,
                        activeNodeCount = compiled.activeNodeCount,
                        wasRunning = true,
                        controllerGroupName = compiled.controllerGroupName,
                    )
                    vpnController.reloadVpn(
                        configPath = cfgFile.absolutePath,
                        activeNodeName = compiled.activeGroupOrNodeName,
                        activeNodeCount = compiled.activeNodeCount,
                        controllerGroupName = compiled.controllerGroupName,
                    )
                }.getOrElse { "ERR:${it.message}" }
            }
            if (reloadMsg != null && reloadMsg != "OK" && reloadMsg != "OK_NOT_RUNNING") {
                showToast("热切换提示：$reloadMsg")
            } else if (reloadMsg == "OK") {
                val st = vpnController.pollStatusIfRunning()
                syncCachedMixedFromStatus(st)
                _state.update { it.copy(vpnStatus = st) }
            }
        }
    }

    // ---- Sync, QR, Clipboard (on-demand only!), Subscription URL, File Import & Relay Box ----

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

        // Any non-PUSH scan/paste clears pending relay-box push target to prevent accidental push later
        _state.update { it.copy(pendingPushRelayBoxId = null) }

        // 2. One-click subscription install URI (`clash://install-config?url=...` / `catcloud://install-config?url=...`)
        val installSubUrl = extractInstallConfigSubscriptionUrl(trimmed)
        if (!installSubUrl.isNullOrBlank()) {
            importSubscriptionUrl(installSubUrl, sourceLabel = sourceLabel)
            return
        }

        // 3. Direct single-line `http://` or `https://` subscription URL
        if (isSingleLineHttpUrl(trimmed)) {
            importSubscriptionUrl(trimmed, sourceLabel = sourceLabel)
            return
        }

        // 4. Domestic `:443` relay bundle (`mmrelay://v1/...` or mmrelay JSON)
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

        // 5. Standard proxy URIs / Base64 / Clash YAML
        scope.launch {
            val res = withContext(Dispatchers.IO) {
                runCatching {
                    val parsed = ShareBundleCodec.parseTextImport(trimmed, subId = sourceLabel)
                    require(parsed.isNotEmpty()) { "未识别到可导入的代理节点、订阅链接或同步码" }
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

    fun importSubscriptionUrl(rawUrl: String, sourceLabel: String = "订阅链接") {
        _state.update { it.copy(pendingPushRelayBoxId = null) }
        val cleanUrl = rawUrl.trim()
        val parsedHttpUrl = cleanUrl.toHttpUrlOrNull()
        if (parsedHttpUrl == null ||
            (parsedHttpUrl.scheme != "http" && parsedHttpUrl.scheme != "https") ||
            parsedHttpUrl.host.isBlank()
        ) {
            showToast("订阅链接格式无效，仅支持 http:// 或 https://")
            return
        }

        scope.launch {
            _state.update { it.copy(busy = true) }
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val status = vpnController.pollStatusIfRunning()
                    syncCachedMixedFromStatus(status)
                    val directAttempt = runCatching { fetchSubscriptionBytes(cleanUrl) }
                    val (rawBytes, viaProxy) = if (directAttempt.isSuccess) {
                        directAttempt.getOrThrow() to false
                    } else {
                        val fallbackPort = status.mixedPort.takeIf { it > 0 } ?: activeMixedPort
                        val fallbackSecret = status.mixedSecret.ifBlank { activeMixedSecret }
                        if (status.running && fallbackPort > 0) {
                            fetchSubscriptionBytes(
                                url = cleanUrl,
                                proxyPort = fallbackPort,
                                proxySecret = fallbackSecret,
                            ) to true
                        } else {
                            throw directAttempt.exceptionOrNull() ?: IOException("订阅拉取失败")
                        }
                    }

                    val bodyText = rawBytes.toString(Charsets.UTF_8)
                    val subId = "sub-${parsedHttpUrl.host.lowercase()}"
                    val parsedNodes = ShareBundleCodec.parseTextImport(bodyText, subId = subId)
                    require(parsedNodes.isNotEmpty()) { "订阅拉取成功，但未识别到有效节点" }
                    val count = db.upsertNodesDedup(parsedNodes).first
                    Pair(count, viaProxy)
                }
            }
            result.fold(
                onSuccess = { (count, viaProxy) ->
                    reloadInventoryFromDb()
                    logStore.append("SUB", "Imported $count nodes from ${parsedHttpUrl.host} (viaProxy=$viaProxy)")
                    val msg = if (viaProxy) {
                        "已通过代理通道从${sourceLabel}导入 $count 个节点"
                    } else {
                        "已从${sourceLabel}导入 $count 个节点"
                    }
                    _state.update { it.copy(busy = false, toastMessage = msg) }
                },
                onFailure = { err ->
                    logStore.append("SUB", "Subscription fetch failed (${parsedHttpUrl.host}): ${err.message}")
                    _state.update {
                        it.copy(busy = false, toastMessage = "订阅拉取失败：${err.message ?: "请检查网络或先开启连接"}")
                    }
                },
            )
        }
    }

    private fun fetchSubscriptionBytes(
        url: String,
        proxyPort: Int = 0,
        proxySecret: String = "",
    ): ByteArray {
        val builder = OkHttpClient.Builder()
            .connectTimeout(SUBSCRIPTION_TIMEOUT_SEC, TimeUnit.SECONDS)
            .readTimeout(SUBSCRIPTION_TIMEOUT_SEC, TimeUnit.SECONDS)
            .writeTimeout(SUBSCRIPTION_TIMEOUT_SEC, TimeUnit.SECONDS)
            .followRedirects(true)
            .followSslRedirects(true)
        if (proxyPort > 0) {
            builder.proxy(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", proxyPort)))
            if (proxySecret.isNotBlank()) {
                builder.proxyAuthenticator { _, response ->
                    if (response.request.header("Proxy-Authorization") != null) {
                        return@proxyAuthenticator null
                    }
                    val credential = Credentials.basic(LOCAL_MIXED_AUTH_USER, proxySecret)
                    response.request.newBuilder()
                        .header("Proxy-Authorization", credential)
                        .build()
                }
            }
        }
        val client = builder.build()
        val req = Request.Builder()
            .url(url)
            .header("User-Agent", "CatCloud/${BuildConfig.VERSION_NAME} clash.meta mihomo")
            .header("Accept", "*/*")
            .get()
            .build()
        client.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) {
                throw IOException("HTTP ${resp.code}")
            }
            val body = resp.body ?: throw IOException("订阅响应为空")
            val contentLength = body.contentLength()
            if (contentLength > MAX_SUBSCRIPTION_BYTES) {
                throw SecurityException("订阅内容超过 16 MiB 安全上限")
            }
            body.byteStream().use { ins ->
                val out = ByteArrayOutputStream()
                val buf = ByteArray(8192)
                var total = 0
                while (true) {
                    val n = ins.read(buf)
                    if (n < 0) break
                    total += n
                    if (total > MAX_SUBSCRIPTION_BYTES) {
                        throw SecurityException("订阅内容超过 16 MiB 安全上限")
                    }
                    out.write(buf, 0, n)
                }
                return out.toByteArray()
            }
        }
    }

    private fun handleSyncUri(uriText: String) {
        scope.launch {
            val parsed = runCatching { SyncCrypto.parseSyncUri(uriText) }.getOrElse {
                _state.update { st -> st.copy(pendingPushRelayBoxId = null) }
                showToast("同步码校验失败：${it.message}")
                return@launch
            }
            if (parsed.role != SyncRole.PUSH) {
                _state.update { it.copy(pendingPushRelayBoxId = null) }
            }
            when (parsed.role) {
                SyncRole.PULL, SyncRole.RELAY_URL -> {
                    _state.update { it.copy(busy = true) }
                    val res = runCatching { syncClient.pullBySyncUri(parsed) }
                    res.fold(
                        onSuccess = { pulled ->
                            logStore.append("SYNC", "Pulled sync bundle fp=${pulled.zipFpHex16} nodes=${pulled.preview.nodes.size}")
                            val bundle = storePendingImportBundle(
                                zipBytes = pulled.zipBytes,
                                zipFpHex16 = pulled.zipFpHex16,
                                preview = pulled.preview,
                                sourceLabel = pulled.sourceBaseUrl,
                            )
                            _state.update {
                                it.copy(
                                    busy = false,
                                    pendingImportBundle = bundle,
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
                    val pendingId = _state.value.pendingCcsyncId
                    val pendingCcsync = pendingId?.let { pendingCcsyncBytesById[it] }
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
            _state.update { it.copy(busy = true, pendingPushRelayBoxId = null) }
            val res = runCatching { syncClient.pullWithPin(host, port, pin) }
            res.fold(
                onSuccess = { pulled ->
                    logStore.append("SYNC", "PIN pull success fp=${pulled.zipFpHex16}")
                    val bundle = storePendingImportBundle(
                        zipBytes = pulled.zipBytes,
                        zipFpHex16 = pulled.zipFpHex16,
                        preview = pulled.preview,
                        sourceLabel = "配对码 (${pulled.sourceBaseUrl})",
                    )
                    _state.update {
                        it.copy(
                            busy = false,
                            pendingImportBundle = bundle,
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
        val zipBytes = pendingZipBytesById[pending.pendingId]
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
                    if (alsoSaveToRelayBox && zipBytes != null && zipBytes.size <= AppDatabase.MAX_RELAY_BOX_ITEM_BYTES) {
                        db.saveRelayBoxEntry(
                            id = "box-${UUID.randomUUID().toString().replace("-", "").take(10)}",
                            name = pending.preview.manifest.name,
                            zipFp = pending.zipFpHex16,
                            payloadBytes = zipBytes,
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
                    pendingZipBytesById.remove(pending.pendingId)
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
            _state.update { it.copy(busy = true, pendingPushRelayBoxId = null) }
            val rawBytes = withContext(Dispatchers.IO) {
                runCatching {
                    appContext.contentResolver.openInputStream(uri)?.use { ins ->
                        val out = ByteArrayOutputStream()
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
                val ccsyncId = storePendingCcsyncBytes(rawBytes)
                _state.update {
                    it.copy(
                        busy = false,
                        pendingCcsyncId = ccsyncId,
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
                        storePendingImportBundle(rawBytes, fp, preview, "本地 .zip 分享包")
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

            // Plain text YAML / URI list / subscription URL / mmrelay
            _state.update { it.copy(busy = false) }
            handleScannedOrPastedText(rawBytes.toString(Charsets.UTF_8), sourceLabel = "文件")
        }
    }

    fun decryptPendingCcsyncWithPassword(password: String) {
        val pendingId = _state.value.pendingCcsyncId ?: return
        val bytes = pendingCcsyncBytesById[pendingId] ?: return
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
                    pendingCcsyncBytesById.clear()
                    val bundle = storePendingImportBundle(
                        zipBytes = pulled.zipBytes,
                        zipFpHex16 = pulled.zipFpHex16,
                        preview = pulled.preview,
                        sourceLabel = "离线 .ccsync 加密包",
                    )
                    _state.update {
                        it.copy(
                            busy = false,
                            pendingCcsyncId = null,
                            pendingImportBundle = bundle,
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
            showToast("已清空随身接力箱")
        }
    }

    // ---- Speed Testing (lightweight ping + relay TCP latency + optional serial throughput) ----

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
            try {
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
                showToast("延迟测速完成")
            } finally {
                _state.update { it.copy(speedTestProgress = SpeedTestProgress(running = false)) }
            }
        }
    }

    fun probeAllRelaysLatency() {
        val cur = _state.value
        if (cur.relays.isEmpty()) {
            showToast("当前没有可测速的国内提速中转")
            return
        }
        speedTestJob?.cancel()
        speedTestJob = scope.launch {
            val targets = cur.relays.filter { it.enabled }.ifEmpty { cur.relays }
            _state.update {
                it.copy(
                    speedTestProgress = SpeedTestProgress(
                        running = true,
                        modeLabel = "测中转延迟",
                        completed = 0,
                        total = targets.size,
                    )
                )
            }
            val doneCount = AtomicInteger(0)
            val reachableCount = AtomicInteger(0)
            try {
                withContext(Dispatchers.IO) {
                    val sem = Semaphore(SpeedTester.MAX_PING_CONCURRENCY)
                    coroutineScope {
                        targets.map { relay ->
                            async {
                                sem.withPermit {
                                    val ms = speedTester.testRelayTcpLatencyMs(
                                        host = relay.server,
                                        port = relay.port,
                                        timeoutMs = SpeedTester.PING_TIMEOUT_MS,
                                    )
                                    db.updateRelayLatency(relay.id, ms)
                                    if (ms != null) reachableCount.incrementAndGet()
                                    val completed = doneCount.incrementAndGet()
                                    _state.update { st ->
                                        st.copy(
                                            relays = st.relays.map { r ->
                                                if (r.id == relay.id) r.copy(lastProbeMs = ms) else r
                                            },
                                            speedTestProgress = st.speedTestProgress.copy(
                                                completed = completed,
                                                currentNodeName = relay.name,
                                            ),
                                        )
                                    }
                                }
                            }
                        }.awaitAll()
                    }
                }
                showToast("国内提速延迟测试完成 (${reachableCount.get()}/${targets.size} 可达)")
            } finally {
                _state.update { it.copy(speedTestProgress = SpeedTestProgress(running = false)) }
            }
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
            var status = vpnController.pollStatusIfRunning()
            syncCachedMixedFromStatus(status)
            _state.update { it.copy(vpnStatus = status) }

            if (!status.running) {
                showToast("请先在首页开启连接后再测上下行")
                return@launch
            }

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
            var tempExpandedForSpeedTest = false
            var watchdogPaused = false
            var restoreMixedPort = 0
            var restoreMixedSecret = ""

            try {
                val (mixedPort, mixedSecret) = resolveLocalMixedCredentials(status, forceNew = false)
                restoreMixedPort = mixedPort
                restoreMixedSecret = mixedSecret

                val prep = withContext(Dispatchers.IO) {
                    val normalCompiled = ConfigCompiler.compile(
                        settings = cur.settings,
                        nodes = cur.nodes,
                        groups = cur.groups,
                        relays = cur.relays,
                        localMixedPort = mixedPort,
                        localMixedSecret = mixedSecret,
                    )
                    val expandedCompiled = ConfigCompiler.compile(
                        settings = cur.settings,
                        nodes = cur.nodes,
                        groups = cur.groups,
                        relays = cur.relays,
                        extraIncludedNodeIds = selectedNodeIds,
                        localMixedPort = mixedPort,
                        localMixedSecret = mixedSecret,
                    )
                    val needsTempExpand = expandedCompiled.yaml != normalCompiled.yaml
                    val needsMixedReload = status.mixedPort <= 0 || status.mixedSecret.isBlank()
                    val activeCompiled = if (needsTempExpand || needsMixedReload) {
                        val cfgFile = db.writeRuntimeConfigAtomically(expandedCompiled.yaml)
                        val reloadRes = vpnController.reloadVpn(
                            configPath = cfgFile.absolutePath,
                            activeNodeName = expandedCompiled.activeGroupOrNodeName,
                            activeNodeCount = expandedCompiled.activeNodeCount,
                            controllerGroupName = expandedCompiled.controllerGroupName,
                        )
                        if (reloadRes != "OK") {
                            throw IllegalStateException("测速前准备配置失败：$reloadRes")
                        }
                        tempExpandedForSpeedTest = needsTempExpand
                        expandedCompiled
                    } else {
                        normalCompiled
                    }
                    activeCompiled
                }

                if (tempExpandedForSpeedTest || status.mixedPort <= 0 || status.mixedSecret.isBlank()) {
                    status = vpnController.pollStatusIfRunning()
                    syncCachedMixedFromStatus(status)
                    _state.update { it.copy(vpnStatus = status) }
                }

                val effectiveGroupName = status.controllerGroupName.ifBlank { prep.controllerGroupName }
                val effectiveMixedPort = status.mixedPort.takeIf { it > 0 } ?: prep.localMixedPort
                val effectiveMixedSecret = status.mixedSecret.ifBlank { prep.localMixedSecret }
                restoreMixedPort = effectiveMixedPort
                restoreMixedSecret = effectiveMixedSecret

                val restoreNodeName = resolveRestoreNodeName(cur)
                val restorePreAccelTarget = resolveRestorePreAccelTarget(cur)

                vpnController.setWatchdogPaused(true)
                watchdogPaused = true
                logStore.append("SPEED", "Watchdog paused for serial throughput test (group=$effectiveGroupName, nodes=${targets.size})")

                speedTester.runSerialThroughputTest(
                    nodes = targets,
                    restPort = status.restPort,
                    restSecret = status.restSecret,
                    targetGroupName = effectiveGroupName,
                    usePreAccel = usePreAccel,
                    onPauseWatchdog = { paused ->
                        vpnController.setWatchdogPaused(paused)
                        watchdogPaused = paused
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
                    mixedPort = effectiveMixedPort,
                    mixedSecret = effectiveMixedSecret,
                    restoreNodeName = restoreNodeName,
                    restorePreAccelTarget = restorePreAccelTarget,
                )
                showToast("上下行测速已完成 ($done/${targets.size})")
            } catch (err: Throwable) {
                if (err !is kotlinx.coroutines.CancellationException) {
                    logStore.append("SPEED", "Throughput test failed: ${err.message}")
                    showToast("上下行测速中断：${err.message}")
                } else {
                    throw err
                }
            } finally {
                withContext(NonCancellable) {
                    if (watchdogPaused) {
                        runCatching { vpnController.setWatchdogPaused(false) }
                    }
                    if (tempExpandedForSpeedTest) {
                        runCatching {
                            val latest = _state.value
                            if (latest.vpnStatus.running && latest.nodes.any { it.enabled }) {
                                withContext(Dispatchers.IO) {
                                    val compact = ConfigCompiler.compile(
                                        settings = latest.settings,
                                        nodes = latest.nodes,
                                        groups = latest.groups,
                                        relays = latest.relays,
                                        localMixedPort = restoreMixedPort,
                                        localMixedSecret = restoreMixedSecret,
                                    )
                                    val cfgFile = db.writeRuntimeConfigAtomically(compact.yaml)
                                    db.writeBootSnapshotAtomically(
                                        configPath = cfgFile.absolutePath,
                                        settings = latest.settings,
                                        activeNodeName = compact.activeGroupOrNodeName,
                                        activeNodeCount = compact.activeNodeCount,
                                        wasRunning = true,
                                        controllerGroupName = compact.controllerGroupName,
                                    )
                                    vpnController.reloadVpn(
                                        configPath = cfgFile.absolutePath,
                                        activeNodeName = compact.activeGroupOrNodeName,
                                        activeNodeCount = compact.activeNodeCount,
                                        controllerGroupName = compact.controllerGroupName,
                                    )
                                }
                            }
                        }
                    }
                    _state.update { it.copy(speedTestProgress = SpeedTestProgress(running = false)) }
                }
            }
        }
    }

    private fun resolveRestoreNodeName(cur: CatCloudUiState): String? {
        return if (cur.settings.routeMode == RouteMode.SINGLE) {
            cur.nodes.firstOrNull { it.id == cur.settings.activeSingleNodeId }?.name
                ?: cur.vpnStatus.activeNodeName.takeIf { it.isNotBlank() }
        } else {
            val activeGroup = cur.groups.firstOrNull { it.id == cur.settings.activeGroupId }
                ?: cur.groups.firstOrNull()
            activeGroup?.activeNodeId?.let { aid ->
                cur.nodes.firstOrNull { it.id == aid }?.name
            }
        }
    }

    private fun resolveRestorePreAccelTarget(cur: CatCloudUiState): String? {
        val enabledRelays = cur.relays.filter { it.enabled }
        if (!cur.settings.preaccelEnabled || enabledRelays.isEmpty()) return null
        if (cur.settings.preaccelAutoFailover) return ConfigCompiler.PREACCEL_FALLBACK_GROUP
        return enabledRelays.firstOrNull { it.id == cur.settings.preaccelActiveRelayId }?.name
            ?: enabledRelays.firstOrNull()?.name
            ?: ConfigCompiler.PREACCEL_FALLBACK_GROUP
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
            val lines = withContext(Dispatchers.IO) {
                LogRingStore.readMergedRecentLines(logDir, maxLines = 200)
            }
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
        pendingZipBytesById.clear()
        pendingCcsyncBytesById.clear()
        vpnController.unbindSafely()
        scope.cancel()
        db.close()
    }

    private data class Tuple4<A, B, C, D>(val a: A, val b: B, val c: C, val d: D)
    private data class Tuple5<A, B, C, D, E>(val a: A, val b: B, val c: C, val d: D, val e: E)

    companion object {
        private const val MAX_SUBSCRIPTION_BYTES = 16 * 1024 * 1024
        private const val SUBSCRIPTION_TIMEOUT_SEC = 15L
        private const val LOCAL_MIXED_AUTH_USER = "catcloud"
        private val URL_PARAM_RE = Regex("(?i)(?:^|&)url=")

        private fun isSingleLineHttpUrl(text: String): Boolean {
            if (text.contains('\n') || text.contains('\r') || text.any { it.isWhitespace() }) return false
            if (!text.startsWith("http://", ignoreCase = true) && !text.startsWith("https://", ignoreCase = true)) {
                return false
            }
            val parsed = text.toHttpUrlOrNull() ?: return false
            return (parsed.scheme == "http" || parsed.scheme == "https") && parsed.host.isNotBlank()
        }

        /**
         * Extracts the subscription `url` query parameter from `clash://install-config?url=...`
         * or `catcloud://install-config?url=...`, supporting both percent-encoded URLs and
         * unencoded nested query strings (e.g. `clash://install-config?url=https://host/sub?a=1&b=2`).
         */
        fun extractInstallConfigSubscriptionUrl(raw: String): String? {
            val trimmed = raw.trim()
            val lower = trimmed.lowercase()
            val isInstallConfig = lower.startsWith("clash://install-config") ||
                lower.startsWith("catcloud://install-config")
            if (!isInstallConfig) return null

            val qIdx = trimmed.indexOf('?')
            if (qIdx < 0 || qIdx + 1 >= trimmed.length) return null
            val rawQuery = trimmed.substring(qIdx + 1)
            val match = URL_PARAM_RE.find(rawQuery) ?: return null
            val afterUrl = rawQuery.substring(match.range.last + 1).trim()
            if (afterUrl.isEmpty()) return null

            val candidate = when {
                afterUrl.startsWith("http://", ignoreCase = true) ||
                    afterUrl.startsWith("https://", ignoreCase = true) -> {
                    afterUrl
                }
                afterUrl.startsWith("http%3a", ignoreCase = true) ||
                    afterUrl.startsWith("https%3a", ignoreCase = true) -> {
                    val encodedSegment = afterUrl.substringBefore('&')
                    runCatching { URLDecoder.decode(encodedSegment, "UTF-8") }.getOrNull()?.trim().orEmpty()
                }
                else -> {
                    val encodedSegment = afterUrl.substringBefore('&')
                    runCatching { URLDecoder.decode(encodedSegment, "UTF-8") }.getOrNull()?.trim().orEmpty()
                }
            }
            val parsed = candidate.toHttpUrlOrNull() ?: return null
            return if ((parsed.scheme == "http" || parsed.scheme == "https") && parsed.host.isNotBlank()) {
                candidate
            } else {
                null
            }
        }
    }
}
