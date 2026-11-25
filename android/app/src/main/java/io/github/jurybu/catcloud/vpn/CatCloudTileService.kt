package io.github.jurybu.catcloud.vpn

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.core.content.ContextCompat
import io.github.jurybu.catcloud.MainActivity
import io.github.jurybu.catcloud.data.AppDatabase
import java.io.File

/**
 * Quick Settings tile for one-tap VPN toggle.
 * Strictly uses `startActivityAndCollapse(PendingIntent)` on Android 14+ (API 34+).
 */
class CatCloudTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        refreshTileState()
    }

    override fun onClick() {
        super.onClick()
        val vpnActive = isSystemVpnActive()
        if (vpnActive) {
            val stopIntent = Intent(this, CatCloudVpnService::class.java)
                .setAction(CatCloudVpnService.ACTION_STOP)
            runCatching { startService(stopIntent) }
            updateTile(Tile.STATE_INACTIVE, "未连接")
            return
        }

        val prepareIntent = VpnService.prepare(this)
        val hasSnapshot = File(filesDir, AppDatabase.BOOT_SNAPSHOT_FILENAME).isFile
        if (prepareIntent == null && hasSnapshot) {
            val startIntent = Intent(this, CatCloudVpnService::class.java)
                .setAction(CatCloudVpnService.ACTION_START_FROM_SNAPSHOT)
            val started = runCatching {
                ContextCompat.startForegroundService(this, startIntent)
                true
            }.getOrDefault(false)
            if (started) {
                updateTile(Tile.STATE_ACTIVE, "正在连接…")
                return
            }
        }

        // Fall back to launching MainActivity to grant VPN permission or choose a node
        val launchIntent = Intent(this, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val pi = PendingIntent.getActivity(
                this,
                1001,
                launchIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
            startActivityAndCollapse(pi)
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(launchIntent)
        }
    }

    private fun refreshTileState() {
        val active = isSystemVpnActive()
        updateTile(
            state = if (active) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE,
            subtitle = if (active) "已连接" else "未连接",
        )
    }

    private fun updateTile(state: Int, subtitle: String) {
        val tile = qsTile ?: return
        tile.state = state
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = subtitle
        }
        tile.updateTile()
    }

    private fun isSystemVpnActive(): Boolean {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return false
        return cm.allNetworks.any { net ->
            val caps = cm.getNetworkCapabilities(net)
            caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        }
    }
}
