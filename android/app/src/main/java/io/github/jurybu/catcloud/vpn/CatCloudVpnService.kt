package io.github.jurybu.catcloud.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.Process
import android.service.quicksettings.TileService
import androidx.core.content.ContextCompat
import io.github.jurybu.catcloud.MainActivity
import io.github.jurybu.catcloud.R
import io.github.jurybu.catcloud.core.MihomoBridge
import io.github.jurybu.catcloud.core.ProtectCallback
import io.github.jurybu.catcloud.data.AppDatabase
import io.github.jurybu.catcloud.data.LogRingStore
import io.github.jurybu.catcloud.data.NodeFingerprint
import io.github.jurybu.catcloud.ipc.ICatCloudVpnControl
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.File
import java.net.Inet4Address
import java.net.InetAddress
import java.net.ServerSocket
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Isolated `:vpn` process foreground VPN service hosting the embedded Go Mihomo core.
 *
 * Strictly enforces Stage 18 Section 5.1 & 5.2 invariants:
 * - `onStartCommand` calls `startForeground` on line 1 (API 34+ `FOREGROUND_SERVICE_TYPE_SPECIAL_USE`, API 26–33 2-arg).
 * - `onBind` forwards `SERVICE_INTERFACE` to `super.onBind(intent)` first, then verifies `callingUid == myUid()`.
 * - Exact 2-step startup: collect physical DNS -> `nativeSetMemoryLimit` -> `nativePrepareConfig` ->
 *   `VpnService.Builder` (forced `addDisallowedApplication(packageName)`) -> `detachFd()` -> `nativeAttachTun`.
 * - Runs [DualOriginWatchdogRunner], `NetworkCallback`, `ScreenStateReceiver`, and `onTrimMemory`/`onLowMemory` GC.
 */
class CatCloudVpnService : VpnService() {

    private val serviceLock = Any()
    private val coreInitialized = AtomicBoolean(false)
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private lateinit var logStore: LogRingStore
    private lateinit var watchdogRunner: DualOriginWatchdogRunner

    @Volatile
    private var running = false
    @Volatile
    private var stateText = "stopped"
    @Volatile
    private var restPort = 0
    @Volatile
    private var restSecret = ""
    @Volatile
    private var activeNodeName = ""
    @Volatile
    private var controllerGroupName = ""
    @Volatile
    private var activeNodeCount = 0
    @Volatile
    private var mixedPort = 0
    @Volatile
    private var mixedSecret = ""
    @Volatile
    private var lastAllocatedRestPort = 0
    @Volatile
    private var startedAtMs = 0L
    @Volatile
    private var watchdogStatus = "idle"
    @Volatile
    private var lastError: String? = null

    private var lastConfigPath: String = ""
    private var lastPerAppMode: String = "bypass"
    private var lastPerAppPackages: Array<String> = emptyArray()

    private var networkCallbackRegistered = false
    private var screenReceiverRegistered = false

    private val protectCallback = object : ProtectCallback {
        override fun protect(fd: Int): Boolean = this@CatCloudVpnService.protect(fd)
    }

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            if (!running) return
            watchdogRunner.engine.setNetworkAvailable(true)
            refreshPhysicalDnsAndReset(network)
        }

        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
            if (!running) return
            val dnsCsv = extractDnsCsv(linkProperties)
            if (dnsCsv.isNotEmpty() && MihomoBridge.isLoaded()) {
                MihomoBridge.nativeUpdateSystemDns(dnsCsv)
                MihomoBridge.nativeResetNetwork()
                logStore.append("VPN", "Network link updated, refreshed physical DNS")
            }
        }

        override fun onLost(network: Network) {
            if (!running) return
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            val hasAnyPhysical = cm?.activeNetwork != null
            watchdogRunner.engine.setNetworkAvailable(hasAnyPhysical)
            if (!hasAnyPhysical) {
                logStore.append("VPN", "Network lost; suspending dual-origin watchdog")
            }
        }
    }

    private val screenStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                Intent.ACTION_SCREEN_OFF -> {
                    watchdogRunner.engine.setScreenOff(true)
                    logStore.append("VPN", "Screen off -> watchdog interval stretched to 120s")
                }
                Intent.ACTION_SCREEN_ON -> {
                    watchdogRunner.engine.setScreenOff(false)
                    logStore.append("VPN", "Screen on -> watchdog interval restored to 25s")
                }
            }
        }
    }

    private val controlBinder = object : ICatCloudVpnControl.Stub() {
        override fun getStatusJson(): String {
            enforceSameUid()
            return buildStatusJson()
        }

        override fun startVpn(
            configPath: String?,
            perAppMode: String?,
            perAppPackages: Array<out String>?,
            activeNodeName: String?,
            controllerGroupName: String?,
            activeNodeCount: Int,
        ): String {
            enforceSameUid()
            return startVpnInternal(
                configPath = configPath.orEmpty(),
                perAppMode = perAppMode ?: "bypass",
                perAppPackages = perAppPackages?.filterNotNull()?.toTypedArray() ?: emptyArray(),
                nodeName = activeNodeName.orEmpty(),
                groupName = controllerGroupName.orEmpty(),
                nodeCount = activeNodeCount,
            )
        }

        override fun reloadVpn(
            configPath: String?,
            activeNodeName: String?,
            controllerGroupName: String?,
            activeNodeCount: Int,
        ): String {
            enforceSameUid()
            return reloadVpnInternal(
                configPath = configPath.orEmpty(),
                nodeName = activeNodeName.orEmpty(),
                groupName = controllerGroupName.orEmpty(),
                nodeCount = activeNodeCount,
            )
        }

        override fun stopVpn() {
            enforceSameUid()
            stopVpnInternal(stopServiceAfter = true)
        }

        override fun forceRestartCore(): String {
            enforceSameUid()
            return forceRestartCoreInternal()
        }

        override fun forceGc() {
            enforceSameUid()
            if (MihomoBridge.isLoaded()) {
                MihomoBridge.nativeForceGc()
            }
        }

        override fun setWatchdogPaused(paused: Boolean) {
            enforceSameUid()
            watchdogRunner.setPaused(paused)
            logStore.append("VPN", if (paused) "Watchdog paused via IPC" else "Watchdog resumed via IPC")
        }
    }

    override fun onCreate() {
        super.onCreate()
        logStore = LogRingStore(File(filesDir, "logs"), filePrefix = "catcloud-vpn")
        watchdogRunner = DualOriginWatchdogRunner(serviceScope) { status ->
            watchdogStatus = status
        }
        ensureNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Iron rule: call startForeground on line 1 to prevent Android 5s FGS ANR crash.
        startForegroundCompat(buildNotification(getString(R.string.vpn_notification_title_starting), ""))

        when (intent?.action) {
            ACTION_STOP -> {
                serviceScope.launch(Dispatchers.IO) {
                    stopVpnInternal(stopServiceAfter = true)
                }
                return START_NOT_STICKY
            }
            ACTION_START_FROM_SNAPSHOT -> {
                serviceScope.launch(Dispatchers.IO) {
                    val res = startFromBootSnapshot()
                    if (!res.startsWith("OK")) {
                        logStore.append("VPN", "Snapshot start failed: $res")
                        stopVpnInternal(stopServiceAfter = true)
                    }
                }
                return START_STICKY
            }
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? {
        // Iron rule: preserve Android system VpnService binding & onRevoke() delivery!
        if (intent?.action == SERVICE_INTERFACE) {
            return super.onBind(intent)
        }
        if (Binder.getCallingUid() != Process.myUid()) {
            return null
        }
        return controlBinder
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        if (MihomoBridge.isLoaded()) {
            MihomoBridge.nativeForceGc()
        }
    }

    override fun onLowMemory() {
        super.onLowMemory()
        if (MihomoBridge.isLoaded()) {
            MihomoBridge.nativeForceGc()
        }
    }

    override fun onRevoke() {
        logStore.append("VPN", "VPN permission revoked by OS")
        stopVpnInternal(stopServiceAfter = true)
        super.onRevoke()
    }

    override fun onDestroy() {
        stopVpnInternal(stopServiceAfter = false)
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun startVpnInternal(
        configPath: String,
        perAppMode: String,
        perAppPackages: Array<String>,
        nodeName: String,
        groupName: String,
        nodeCount: Int,
    ): String = synchronized(serviceLock) {
        startForegroundCompat(buildNotification(getString(R.string.vpn_notification_title_starting), nodeName))
        stateText = "starting"
        lastError = null

        val cfgFile = resolveSafeConfigFile(configPath)
            ?: return failAndReturn("ERR:INVALID_CONFIG_PATH")
        val yamlText = runCatching { cfgFile.readText(Charsets.UTF_8) }.getOrElse {
            return failAndReturn("ERR:READ_CONFIG_FAILED:${it.message}")
        }
        val (parsedMixedPort, parsedMixedSecret) = extractLoopbackMixedConfig(yamlText)

        if (!MihomoBridge.ensureLoaded()) {
            return failAndReturn("ERR:NATIVE_LIB_MISSING:${MihomoBridge.lastLoadError()}")
        }

        val homeDir = File(filesDir, "mihomo").apply { mkdirs() }
        if (coreInitialized.compareAndSet(false, true)) {
            val initErr = MihomoBridge.nativeInit(homeDir.absolutePath, protectCallback)
            if (initErr.isNotBlank()) {
                coreInitialized.set(false)
                return failAndReturn("ERR:NATIVE_INIT:$initErr")
            }
        }

        // Step 0: Collect physical NIC DNS and push to Go core
        val dnsCsv = collectActivePhysicalDnsCsv()
        MihomoBridge.nativeUpdateSystemDns(dnsCsv)

        // Step 1: Set dynamic GOMEMLIMIT tier (<=40 -> 24MiB, 41..199 -> 32MiB, >=200 -> 48MiB)
        val memLimit = MihomoBridge.computeMemoryLimitBytes(nodeCount)
        MihomoBridge.nativeSetMemoryLimit(memLimit, 25)

        // Step 2: Allocate loopback controller port + 32-byte random Bearer Secret, prepare Go config
        val port = allocateLoopbackPort()
        val secret = generateRandomHexSecret(32)
        val prepErr = MihomoBridge.nativePrepareConfig(yamlText, "127.0.0.1:$port", secret)
        if (prepErr.isNotBlank()) {
            return failAndReturn("ERR:PREPARE_CONFIG:$prepErr")
        }

        // Step 3: Build Android TUN interface (forced self-exclusion + per-app routing)
        val pfd = establishTunInterface(perAppMode, perAppPackages)
        if (pfd == null) {
            runCatching { MihomoBridge.nativeStopTun() }
            return failAndReturn("ERR:VPN_ESTABLISH_FAILED", stopService = true)
        }

        // Transfer FD ownership to Go sing_tun (NEVER call pfd.close() after detachFd -> prevents fdsan SIGABRT)
        val tunFd = pfd.detachFd()

        // Step 4: Attach TUN FD to Go core (ownership transferred to Go tun.go / sing_tun;
        // never close tunFd again on Kotlin side to prevent double-close / fdsan SIGABRT).
        val attachErr = MihomoBridge.nativeAttachTun(tunFd, VPN_MTU)
        if (attachErr.isNotBlank()) {
            runCatching { MihomoBridge.nativeStopTun() }
            return failAndReturn("ERR:ATTACH_TUN:$attachErr", stopService = true)
        }

        val resolvedGroupName = groupName.trim().ifEmpty { nodeName.trim() }
        lastConfigPath = cfgFile.absolutePath
        lastPerAppMode = perAppMode
        lastPerAppPackages = perAppPackages.copyOf()
        restPort = port
        restSecret = secret
        activeNodeName = nodeName
        controllerGroupName = resolvedGroupName
        activeNodeCount = nodeCount
        mixedPort = parsedMixedPort
        mixedSecret = parsedMixedSecret
        startedAtMs = System.currentTimeMillis()
        running = true
        stateText = "running"

        registerRuntimeObservers()
        watchdogRunner.start(port, secret) { controllerGroupName.ifBlank { activeNodeName } }
        updateNotification(getString(R.string.vpn_notification_title_running), nodeName)
        requestTileRefresh()
        logStore.append("VPN", "Tunnel started (nodes=$nodeCount, memLimitMiB=${memLimit / (1024 * 1024)}, perApp=$perAppMode, group=$resolvedGroupName)")
        "OK"
    }

    private fun reloadVpnInternal(
        configPath: String,
        nodeName: String,
        groupName: String,
        nodeCount: Int,
    ): String = synchronized(serviceLock) {
        if (!running) {
            return startVpnInternal(configPath, lastPerAppMode, lastPerAppPackages, nodeName, groupName, nodeCount)
        }
        val cfgFile = resolveSafeConfigFile(configPath) ?: run {
            lastError = "ERR:INVALID_CONFIG_PATH"
            logStore.append("VPN", "Reload rejected: ERR:INVALID_CONFIG_PATH")
            return "ERR:INVALID_CONFIG_PATH"
        }
        val yamlText = runCatching { cfgFile.readText(Charsets.UTF_8) }.getOrElse {
            val err = "ERR:READ_CONFIG_FAILED:${it.message}"
            lastError = err
            logStore.append("VPN", "Reload failed: $err")
            return err
        }
        val (parsedMixedPort, parsedMixedSecret) = extractLoopbackMixedConfig(yamlText)
        val memLimit = MihomoBridge.computeMemoryLimitBytes(nodeCount)
        MihomoBridge.nativeSetMemoryLimit(memLimit, 25)
        val reloadErr = MihomoBridge.nativeReloadConfig(yamlText)
        if (reloadErr.isNotBlank()) {
            lastError = reloadErr
            logStore.append("VPN", "Reload error: $reloadErr")
            return "ERR:RELOAD:$reloadErr"
        }
        val resolvedGroupName = groupName.trim().ifEmpty { nodeName.trim() }
        lastConfigPath = cfgFile.absolutePath
        activeNodeName = nodeName
        controllerGroupName = resolvedGroupName
        activeNodeCount = nodeCount
        mixedPort = parsedMixedPort
        mixedSecret = parsedMixedSecret
        lastError = null
        updateNotification(getString(R.string.vpn_notification_title_running), nodeName)
        logStore.append("VPN", "Hot-reloaded config (nodes=$nodeCount, group=$resolvedGroupName, mixedPort=$parsedMixedPort)")
        "OK"
    }

    private fun forceRestartCoreInternal(): String = synchronized(serviceLock) {
        val prevConfig = lastConfigPath
        val prevMode = lastPerAppMode
        val prevPkgs = lastPerAppPackages.copyOf()
        val prevNode = activeNodeName
        val prevGroup = controllerGroupName
        val prevCount = activeNodeCount

        stopVpnInternal(stopServiceAfter = false)
        if (prevConfig.isBlank()) {
            return startFromBootSnapshot()
        }
        return startVpnInternal(prevConfig, prevMode, prevPkgs, prevNode, prevGroup, prevCount)
    }

    private fun stopVpnInternal(stopServiceAfter: Boolean) = synchronized(serviceLock) {
        watchdogRunner.stop()
        unregisterRuntimeObservers()
        if (MihomoBridge.isLoaded() && (running || coreInitialized.get())) {
            runCatching { MihomoBridge.nativeStopTun() }
            runCatching { MihomoBridge.nativeForceGc() }
        }
        running = false
        stateText = "stopped"
        restPort = 0
        restSecret = ""
        controllerGroupName = ""
        mixedPort = 0
        mixedSecret = ""
        startedAtMs = 0L
        watchdogStatus = "idle"
        requestTileRefresh()
        if (stopServiceAfter) {
            stopForegroundCompat()
            stopSelf()
        }
    }

    private fun startFromBootSnapshot(): String {
        val snapFile = File(filesDir, AppDatabase.BOOT_SNAPSHOT_FILENAME)
        if (!snapFile.isFile) return "ERR:NO_SNAPSHOT"
        val obj = runCatching { JSONObject(snapFile.readText(Charsets.UTF_8)) }.getOrNull()
            ?: return "ERR:CORRUPT_SNAPSHOT"
        val cfgPath = obj.optString("config_path", "")
        val mode = obj.optString("per_app_mode", "bypass")
        val pkgsArr = obj.optJSONArray("per_app_packages")
        val pkgs = ArrayList<String>()
        if (pkgsArr != null) {
            for (i in 0 until pkgsArr.length()) {
                val p = pkgsArr.optString(i, "").trim()
                if (p.isNotEmpty()) pkgs.add(p)
            }
        }
        val nodeName = obj.optString("active_node_name", "")
        val groupName = obj.optString("controller_group_name", "").ifBlank { nodeName }
        val nodeCount = obj.optInt("active_node_count", 1)
        return startVpnInternal(cfgPath, mode, pkgs.toTypedArray(), nodeName, groupName, nodeCount)
    }

    private fun establishTunInterface(perAppMode: String, perAppPackages: Array<String>): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession("CatCloud")
            .addAddress(TUN_ADDR_V4, TUN_PREFIX_V4)
            .addRoute("0.0.0.0", 0)
            .addDnsServer(TUN_DNS_V4)
            .setMtu(VPN_MTU)

        // Iron rule: unconditionally exclude self packageName to prevent VPN routing loop.
        runCatching { builder.addDisallowedApplication(packageName) }

        when (perAppMode.lowercase()) {
            "bypass" -> {
                for (pkg in perAppPackages) {
                    val clean = pkg.trim()
                    if (clean.isNotEmpty() && clean != packageName) {
                        try {
                            builder.addDisallowedApplication(clean)
                        } catch (_: PackageManager.NameNotFoundException) {
                            // App uninstalled; skip safely
                        }
                    }
                }
            }
            "allow" -> {
                val allowed = perAppPackages.map { it.trim() }.filter { it.isNotEmpty() && it != packageName }
                if (allowed.isEmpty()) {
                    // Fail-Closed: never silently fall back to global proxy when allow-list is empty
                    logStore.append("VPN", "ERR:ALLOWLIST_EMPTY")
                    return null
                }
                // Android forbids mixing addAllowedApplication and addDisallowedApplication on the same Builder;
                // rebuild cleanly with allow-list only (omitting packageName already excludes CatCloud itself!).
                val allowBuilder = Builder()
                    .setSession("CatCloud")
                    .addAddress(TUN_ADDR_V4, TUN_PREFIX_V4)
                    .addRoute("0.0.0.0", 0)
                    .addDnsServer(TUN_DNS_V4)
                    .setMtu(VPN_MTU)
                var addedAny = false
                for (pkg in allowed) {
                    try {
                        allowBuilder.addAllowedApplication(pkg)
                        addedAny = true
                    } catch (_: PackageManager.NameNotFoundException) {
                        // Ignore uninstalled packages
                    }
                }
                if (!addedAny) {
                    // Fail-Closed: none of the configured allow-list packages are installed
                    logStore.append("VPN", "ERR:ALLOWLIST_EMPTY")
                    return null
                }
                return runCatching { allowBuilder.establish() }.getOrNull()
            }
        }
        return runCatching { builder.establish() }.getOrNull()
    }

    private fun registerRuntimeObservers() {
        if (!networkCallbackRegistered) {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            if (cm != null) {
                val req = NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    .build()
                runCatching {
                    cm.registerNetworkCallback(req, networkCallback)
                    networkCallbackRegistered = true
                }
            }
        }
        if (!screenReceiverRegistered) {
            val filter = IntentFilter().apply {
                addAction(Intent.ACTION_SCREEN_OFF)
                addAction(Intent.ACTION_SCREEN_ON)
            }
            runCatching {
                ContextCompat.registerReceiver(this, screenStateReceiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)
                screenReceiverRegistered = true
            }
        }
    }

    private fun unregisterRuntimeObservers() {
        if (networkCallbackRegistered) {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            runCatching { cm?.unregisterNetworkCallback(networkCallback) }
            networkCallbackRegistered = false
        }
        if (screenReceiverRegistered) {
            runCatching { unregisterReceiver(screenStateReceiver) }
            screenReceiverRegistered = false
        }
    }

    private fun refreshPhysicalDnsAndReset(network: Network) {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        val lp = cm.getLinkProperties(network)
        val dnsCsv = lp?.let { extractDnsCsv(it) }?.ifEmpty { FALLBACK_PHYSICAL_DNS } ?: FALLBACK_PHYSICAL_DNS
        if (MihomoBridge.isLoaded()) {
            MihomoBridge.nativeUpdateSystemDns(dnsCsv)
            MihomoBridge.nativeResetNetwork()
            logStore.append("VPN", "Network switched; updated physical DNS & reset core sockets")
        }
    }

    private fun collectActivePhysicalDnsCsv(): String {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return FALLBACK_PHYSICAL_DNS
        val candidates = ArrayList<String>()
        val active = cm.activeNetwork
        if (active != null) {
            val caps = cm.getNetworkCapabilities(active)
            if (caps != null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) {
                cm.getLinkProperties(active)?.let { lp ->
                    val csv = extractDnsCsv(lp)
                    if (csv.isNotEmpty()) return csv
                }
            }
        }
        for (net in cm.allNetworks) {
            val caps = cm.getNetworkCapabilities(net) ?: continue
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) continue
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
            val lp = cm.getLinkProperties(net) ?: continue
            val csv = extractDnsCsv(lp)
            if (csv.isNotEmpty()) candidates.add(csv)
        }
        return candidates.firstOrNull() ?: FALLBACK_PHYSICAL_DNS
    }

    private fun extractDnsCsv(lp: LinkProperties): String =
        lp.dnsServers
            .filterIsInstance<Inet4Address>()
            .mapNotNull { it.hostAddress }
            .filter { it != TUN_DNS_V4 && it != TUN_ADDR_V4 && !it.startsWith("127.") }
            .distinct()
            .joinToString(",")

    private fun resolveSafeConfigFile(configPath: String): File? {
        if (configPath.isBlank()) return null
        val file = runCatching { File(configPath).canonicalFile }.getOrNull() ?: return null
        val rootDir = runCatching { filesDir.canonicalFile }.getOrNull() ?: return null
        val prefix = rootDir.path.trimEnd(File.separatorChar) + File.separator
        if (!file.path.startsWith(prefix)) return null
        return if (file.isFile) file else null
    }

    private fun allocateLoopbackPort(): Int {
        val prevPort = lastAllocatedRestPort.takeIf { it > 0 } ?: restPort
        var fallbackCandidate = 0
        repeat(5) {
            val cand = runCatching {
                ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { it.localPort }
            }.getOrDefault(0)
            if (cand in 1..65535) {
                fallbackCandidate = cand
                if (cand != prevPort) {
                    lastAllocatedRestPort = cand
                    return cand
                }
            }
        }
        val finalPort = if (fallbackCandidate in 1..65535) {
            fallbackCandidate
        } else if (prevPort == 29090) {
            29091
        } else {
            29090
        }
        lastAllocatedRestPort = finalPort
        return finalPort
    }

    private fun generateRandomHexSecret(bytesLen: Int): String {
        val buf = ByteArray(bytesLen)
        SecureRandom().nextBytes(buf)
        return NodeFingerprint.toHexLower(buf)
    }

    private fun failAndReturn(err: String, stopService: Boolean = !running): String {
        val shouldTeardown = stopService || !running
        lastError = err
        logStore.append("VPN", "Error: $err")
        if (shouldTeardown) {
            watchdogRunner.stop()
            unregisterRuntimeObservers()
            running = false
            stateText = "error"
            restPort = 0
            restSecret = ""
            controllerGroupName = ""
            mixedPort = 0
            mixedSecret = ""
            startedAtMs = 0L
            watchdogStatus = "idle"
            requestTileRefresh()
            stopForegroundCompat()
            stopSelf()
        }
        return err
    }

    private fun buildStatusJson(): String {
        val uptimeSec = if (running && startedAtMs > 0L) {
            ((System.currentTimeMillis() - startedAtMs) / 1000L).coerceAtLeast(0L)
        } else {
            0L
        }
        return JSONObject().apply {
            put("running", running)
            put("state", stateText)
            put("rest_port", restPort)
            put("rest_secret", restSecret)
            put("active_node_name", activeNodeName)
            put("controller_group_name", controllerGroupName)
            put("active_node_count", activeNodeCount)
            put("mixed_port", mixedPort)
            put("mixed_secret", mixedSecret)
            put("uptime_sec", uptimeSec)
            put("watchdog_status", watchdogStatus)
            put("last_error", lastError ?: "")
        }.toString()
    }

    private fun enforceSameUid() {
        if (Binder.getCallingUid() != Process.myUid()) {
            throw SecurityException("Unauthorized cross-UID IPC caller")
        }
    }

    private fun ensureNotificationChannel() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return
        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            getString(R.string.vpn_notification_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = getString(R.string.vpn_notification_channel_desc)
            setShowBadge(false)
        }
        nm.createNotificationChannel(channel)
    }

    private fun buildNotification(title: String, subtitle: String): Notification {
        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val contentPi = PendingIntent.getActivity(
            this,
            1,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stopIntent = Intent(this, CatCloudVpnService::class.java).setAction(ACTION_STOP)
        val stopPi = PendingIntent.getForegroundService(
            this,
            2,
            stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notif_catcloud)
            .setContentTitle(title)
            .setContentText(subtitle.ifBlank { "独立加密代理隧道运行中" })
            .setOngoing(true)
            .setContentIntent(contentPi)
            .addAction(
                Notification.Action.Builder(
                    null as android.graphics.drawable.Icon?,
                    getString(R.string.vpn_notification_action_stop),
                    stopPi,
                ).build()
            )
            .build()
    }

    private fun startForegroundCompat(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun updateNotification(title: String, subtitle: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return
        nm.notify(NOTIFICATION_ID, buildNotification(title, subtitle))
    }

    private fun stopForegroundCompat() {
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    private fun requestTileRefresh() {
        runCatching {
            TileService.requestListeningState(this, ComponentName(this, CatCloudTileService::class.java))
        }
    }

    companion object {
        const val ACTION_START_FROM_SNAPSHOT = "io.github.jurybu.catcloud.action.START_FROM_SNAPSHOT"
        const val ACTION_STOP = "io.github.jurybu.catcloud.action.STOP_VPN"

        const val TUN_ADDR_V4 = "172.19.0.1"
        const val TUN_PREFIX_V4 = 30
        const val TUN_DNS_V4 = "172.19.0.2"
        const val VPN_MTU = 9000
        private const val FALLBACK_PHYSICAL_DNS = "223.5.5.5,1.12.12.12"
        private const val NOTIFICATION_CHANNEL_ID = "catcloud_vpn_tunnel"
        private const val NOTIFICATION_ID = 10443

        private val MIXED_PORT_LINE_RE = Regex("^mixed-port:\\s*['\"]?(\\d{1,5})['\"]?(?:\\s+#.*)?$")
        private val AUTH_INLINE_RE = Regex("catcloud:([^\\s'\",\\]]+)")

        /**
         * Extract top-level `mixed-port:` and `catcloud:<secret>` authentication credential
         * from compiled Mihomo YAML without allocating a full YAML AST inside `:vpn`.
         */
        internal fun extractLoopbackMixedConfig(yamlText: String): Pair<Int, String> {
            var parsedPort = 0
            var parsedSecret = ""
            var inAuthSection = false

            for (rawLine in yamlText.lineSequence()) {
                val trimmed = rawLine.trim()
                if (trimmed.isEmpty() || trimmed.startsWith("#")) continue

                if (inAuthSection && trimmed.startsWith("-")) {
                    val item = trimmed.removePrefix("-").trim()
                        .removeSurrounding("\"").removeSurrounding("'").trim()
                    if (item.startsWith("catcloud:")) {
                        val cand = item.substringAfter("catcloud:").trim()
                        if (cand.isNotEmpty() && parsedSecret.isEmpty()) {
                            parsedSecret = cand
                        }
                    }
                    continue
                }

                val isTopLevel = !rawLine[0].isWhitespace()
                if (isTopLevel) {
                    inAuthSection = false
                    val portMatch = MIXED_PORT_LINE_RE.matchEntire(trimmed)
                    if (portMatch != null) {
                        val p = portMatch.groupValues[1].toIntOrNull() ?: 0
                        if (p in 1..65535) parsedPort = p
                        continue
                    }
                    if (trimmed.startsWith("authentication:")) {
                        val rest = trimmed.removePrefix("authentication:").trim()
                        if (rest.isEmpty()) {
                            inAuthSection = true
                        } else {
                            AUTH_INLINE_RE.find(rest)?.groupValues?.getOrNull(1)?.trim()?.let { s ->
                                if (s.isNotEmpty() && parsedSecret.isEmpty()) parsedSecret = s
                            }
                        }
                    }
                }
            }

            return if (parsedPort in 1..65535) parsedPort to parsedSecret else 0 to ""
        }
    }
}
