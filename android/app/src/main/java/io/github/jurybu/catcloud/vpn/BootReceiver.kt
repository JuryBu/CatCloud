package io.github.jurybu.catcloud.vpn

import android.app.ForegroundServiceStartNotAllowedException
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import androidx.core.content.ContextCompat
import io.github.jurybu.catcloud.data.AppDatabase
import org.json.JSONObject
import java.io.File

/**
 * Optional boot-restore receiver (DISABLED by default).
 *
 * Only restores `:vpn` when:
 * 1. User explicitly enabled `autoStartOnBoot == true`
 * 2. VPN was running before shutdown (`was_running == true`)
 * 3. System VPN permission is already granted (`VpnService.prepare(context) == null`)
 * Safely catches `ForegroundServiceStartNotAllowedException` and `SecurityException`.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != Intent.ACTION_BOOT_COMPLETED) return

        val snapFile = File(context.filesDir, AppDatabase.BOOT_SNAPSHOT_FILENAME)
        if (!snapFile.isFile) return

        val snapshot = runCatching { JSONObject(snapFile.readText(Charsets.UTF_8)) }.getOrNull()
            ?: return
        val autoStart = snapshot.optBoolean("auto_start_on_boot", false)
        val wasRunning = snapshot.optBoolean("was_running", false)
        if (!autoStart || !wasRunning) return

        // Never attempt boot start without existing VPN consent
        if (VpnService.prepare(context) != null) return

        val serviceIntent = Intent(context, CatCloudVpnService::class.java)
            .setAction(CatCloudVpnService.ACTION_START_FROM_SNAPSHOT)
        try {
            ContextCompat.startForegroundService(context, serviceIntent)
        } catch (e: SecurityException) {
            // Gracefully ignore restricted OEM boot starts
        } catch (e: IllegalStateException) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && e is ForegroundServiceStartNotAllowedException) {
                // Gracefully ignore Android 12+ background FGS restriction
            }
        }
    }
}
