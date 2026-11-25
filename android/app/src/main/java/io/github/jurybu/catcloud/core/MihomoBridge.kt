package io.github.jurybu.catcloud.core

import java.util.concurrent.atomic.AtomicBoolean

/**
 * Socket protection callback invoked from Go `dialer.DefaultSocketHook` via JNI
 * to bypass Android's VPN TUN interface and prevent routing loops.
 */
interface ProtectCallback {
    fun protect(fd: Int): Boolean
}

/**
 * Frozen JNI contract shared 1:1 with `android/mihomo-bridge` (`libmihomo.so`).
 *
 * Package, object name, method names, and parameter types are locked by Stage 18 Section 5.1.
 */
object MihomoBridge {
    private val loaded = AtomicBoolean(false)
    @Volatile
    private var loadError: String? = null

    fun ensureLoaded(): Boolean {
        if (loaded.get()) return true
        return synchronized(this) {
            if (loaded.get()) return true
            try {
                System.loadLibrary("mihomo")
                loadError = null
                loaded.set(true)
                true
            } catch (t: UnsatisfiedLinkError) {
                loadError = t.message ?: "Failed to load libmihomo.so"
                false
            }
        }
    }

    fun isLoaded(): Boolean = loaded.get()

    fun lastLoadError(): String? = loadError

    /**
     * Compute dynamic `GOMEMLIMIT` bytes based on compiled active node count:
     * - `<= 40` active nodes -> 24 MiB
     * - `41..199` active nodes -> 32 MiB
     * - `>= 200` active nodes (full / Global) -> 48 MiB
     */
    fun computeMemoryLimitBytes(activeNodeCount: Int): Long = when {
        activeNodeCount <= 40 -> 24L * 1024L * 1024L
        activeNodeCount < 200 -> 32L * 1024L * 1024L
        else -> 48L * 1024L * 1024L
    }

    external fun nativeInit(homeDir: String, protectCb: ProtectCallback): String

    external fun nativeSetMemoryLimit(limitBytes: Long, gcPercent: Int)

    external fun nativePrepareConfig(
        configYaml: String,
        controllerAddr: String,
        controllerSecret: String,
    ): String

    external fun nativeAttachTun(tunFd: Int, mtu: Int): String

    external fun nativeReloadConfig(configYaml: String): String

    external fun nativeStopTun()

    external fun nativeUpdateSystemDns(dnsCsv: String)

    external fun nativeResetNetwork()

    external fun nativeForceGc()
}
