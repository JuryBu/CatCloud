package io.github.jurybu.catcloud.vpn

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.IBinder
import androidx.core.content.ContextCompat
import io.github.jurybu.catcloud.data.VpnRuntimeStatus
import io.github.jurybu.catcloud.ipc.ICatCloudVpnControl
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject

/** Alias matching cross-module contract naming. */
typealias VpnStatusSnapshot = VpnRuntimeStatus

/**
 * `:ui` side AIDL client for [CatCloudVpnService].
 *
 * Strictly enforces the zero-wake invariant: never binds or starts `:vpn` while VPN is inactive.
 */
class VpnServiceController(private val appContext: Context) {

    @Volatile
    private var service: ICatCloudVpnControl? = null
    @Volatile
    private var bound = false
    @Volatile
    private var pendingConnect: CompletableDeferred<ICatCloudVpnControl?>? = null

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            val stub = ICatCloudVpnControl.Stub.asInterface(binder)
            service = stub
            bound = true
            pendingConnect?.complete(stub)
            pendingConnect = null
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            service = null
            bound = false
            pendingConnect?.complete(null)
            pendingConnect = null
        }
    }

    fun isSystemVpnTransportActive(): Boolean {
        val cm = appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return false
        return cm.allNetworks.any { net ->
            val caps = cm.getNetworkCapabilities(net)
            caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        }
    }

    suspend fun pollStatusIfRunning(): VpnRuntimeStatus = withContext(Dispatchers.IO) {
        val existing = service
        if (existing != null) {
            return@withContext readStatusFromStub(existing)
        }
        // Zero-wake guard: do NOT spawn `:vpn` when no VPN transport is active!
        if (!isSystemVpnTransportActive()) {
            return@withContext VpnRuntimeStatus(running = false, state = "stopped")
        }
        val stub = bindExistingOnly() ?: return@withContext VpnRuntimeStatus(running = false, state = "stopped")
        readStatusFromStub(stub)
    }

    suspend fun startVpn(
        configPath: String,
        perAppMode: String,
        perAppPackages: List<String>,
        activeNodeName: String,
        activeNodeCount: Int,
        controllerGroupName: String = activeNodeName,
    ): String = withContext(Dispatchers.IO) {
        val intent = Intent(appContext, CatCloudVpnService::class.java)
        ContextCompat.startForegroundService(appContext, intent)
        val stub = ensureBound(createIfNeeded = true) ?: return@withContext "ERR:BIND_TIMEOUT"
        runCatching {
            stub.startVpn(
                configPath,
                perAppMode,
                perAppPackages.toTypedArray(),
                activeNodeName,
                controllerGroupName,
                activeNodeCount,
            )
        }.getOrElse { "ERR:IPC:${it.message}" }
    }

    suspend fun reloadVpn(
        configPath: String,
        activeNodeName: String,
        activeNodeCount: Int,
        controllerGroupName: String = activeNodeName,
    ): String = withContext(Dispatchers.IO) {
        val stub = service ?: if (isSystemVpnTransportActive()) bindExistingOnly() else null
        if (stub == null) return@withContext "OK_NOT_RUNNING"
        runCatching {
            stub.reloadVpn(configPath, activeNodeName, controllerGroupName, activeNodeCount)
        }.getOrElse { "ERR:IPC:${it.message}" }
    }

    suspend fun setWatchdogPaused(paused: Boolean) = withContext(Dispatchers.IO) {
        val stub = service ?: if (isSystemVpnTransportActive()) bindExistingOnly() else null
        runCatching { stub?.setWatchdogPaused(paused) }
        Unit
    }

    suspend fun stopVpn() = withContext(Dispatchers.IO) {
        val stub = service
        if (stub != null) {
            runCatching { stub.stopVpn() }
        } else if (isSystemVpnTransportActive()) {
            val stopIntent = Intent(appContext, CatCloudVpnService::class.java)
                .setAction(CatCloudVpnService.ACTION_STOP)
            runCatching { appContext.startService(stopIntent) }
        }
        unbindSafely()
    }

    suspend fun forceRestartCore(): String = withContext(Dispatchers.IO) {
        val stub = service ?: if (isSystemVpnTransportActive()) bindExistingOnly() else null
        if (stub == null) return@withContext "ERR:CORE_NOT_RUNNING"
        runCatching { stub.forceRestartCore() }.getOrElse { "ERR:IPC:${it.message}" }
    }

    fun requestForceGc() {
        runCatching { service?.forceGc() }
    }

    fun unbindSafely() {
        if (bound) {
            runCatching { appContext.unbindService(connection) }
        }
        bound = false
        service = null
    }

    private suspend fun bindExistingOnly(): ICatCloudVpnControl? = ensureBound(createIfNeeded = false)

    private suspend fun ensureBound(createIfNeeded: Boolean): ICatCloudVpnControl? {
        service?.let { return it }
        val deferred = CompletableDeferred<ICatCloudVpnControl?>()
        pendingConnect = deferred
        val intent = Intent(appContext, CatCloudVpnService::class.java)
            .setAction(ACTION_CONTROL_BIND)
        val flags = if (createIfNeeded) Context.BIND_AUTO_CREATE else 0
        val ok = runCatching { appContext.bindService(intent, connection, flags) }.getOrDefault(false)
        if (!ok) {
            pendingConnect = null
            return null
        }
        return withTimeoutOrNull(4000L) { deferred.await() }
    }

    private fun readStatusFromStub(stub: ICatCloudVpnControl): VpnRuntimeStatus {
        val raw = runCatching { stub.statusJson }.getOrNull() ?: return VpnRuntimeStatus()
        val o = runCatching { JSONObject(raw) }.getOrNull() ?: return VpnRuntimeStatus()
        return VpnRuntimeStatus(
            running = o.optBoolean("running", false),
            state = o.optString("state", "stopped"),
            restPort = o.optInt("rest_port", 0),
            restSecret = o.optString("rest_secret", ""),
            activeNodeName = o.optString("active_node_name", ""),
            activeNodeCount = o.optInt("active_node_count", 0),
            uptimeSec = o.optLong("uptime_sec", 0L),
            watchdogStatus = o.optString("watchdog_status", "idle"),
            lastError = o.optString("last_error", "").takeIf { it.isNotBlank() },
            controllerGroupName = o.optString("controller_group_name", ""),
            mixedPort = o.optInt("mixed_port", 0),
            mixedSecret = o.optString("mixed_secret", ""),
        )
    }

    companion object {
        const val ACTION_CONTROL_BIND = "io.github.jurybu.catcloud.ipc.CONTROL_BIND"
    }
}
