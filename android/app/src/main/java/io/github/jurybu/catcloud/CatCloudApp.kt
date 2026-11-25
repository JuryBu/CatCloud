package io.github.jurybu.catcloud

import android.app.Application
import android.os.Build
import java.io.File

/**
 * Process-aware [Application] ensuring the `:vpn` process performs ZERO UI/DB initialization.
 */
class CatCloudApp : Application() {

    var isVpnProcess: Boolean = false
        private set

    override fun onCreate() {
        super.onCreate()
        val procName = currentProcessName()
        isVpnProcess = procName.endsWith(":vpn")
        if (isVpnProcess) {
            // Iron rule: `:vpn` initializes zero UI, SQLite, or Compose state.
            return
        }
        // `:ui` defers DB/Log creation lazily until MainActivity needs them for fast cold start.
    }

    private fun currentProcessName(): String {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            return Application.getProcessName().orEmpty()
        }
        return runCatching {
            File("/proc/self/cmdline").readText(Charsets.UTF_8).trimEnd('\u0000', '\n', ' ')
        }.getOrDefault("")
    }
}
