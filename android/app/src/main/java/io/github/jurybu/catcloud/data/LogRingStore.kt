package io.github.jurybu.catcloud.data

import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Bounded sanitized rolling log store (`512 KiB x 2 <= 1 MiB` hard disk budget).
 * Automatically strips bearer tokens, passwords, UUIDs, `#k=` fragments, and `mmrelay://` payloads.
 */
class LogRingStore(private val logDir: File) {

    private val lock = Any()
    private val slot0: File get() = File(logDir, "catcloud-log.0.txt")
    private val slot1: File get() = File(logDir, "catcloud-log.1.txt")

    fun append(tag: String, message: String) {
        val sanitized = sanitizeLine(message)
        val ts = SimpleDateFormat("MM-dd HH:mm:ss", Locale.US).format(Date())
        val line = "[$ts][$tag] $sanitized\n"
        val bytes = line.toByteArray(Charsets.UTF_8)

        synchronized(lock) {
            if (!logDir.exists()) {
                logDir.mkdirs()
            }
            val current = slot0
            if (current.exists() && current.length() + bytes.size > MAX_SLOT_BYTES) {
                val backup = slot1
                if (backup.exists()) backup.delete()
                current.renameTo(backup)
            }
            try {
                FileOutputStream(slot0, true).use { fos ->
                    fos.write(bytes)
                }
            } catch (_: Throwable) {
                // Best-effort log write; never crash caller.
            }
        }
    }

    fun readRecentLines(maxLines: Int = 180): List<String> = synchronized(lock) {
        val collected = ArrayList<String>()
        if (slot1.isFile) {
            collected.addAll(runCatching { slot1.readLines(Charsets.UTF_8) }.getOrDefault(emptyList()))
        }
        if (slot0.isFile) {
            collected.addAll(runCatching { slot0.readLines(Charsets.UTF_8) }.getOrDefault(emptyList()))
        }
        if (collected.size <= maxLines) collected else collected.takeLast(maxLines)
    }

    fun totalDiskBytes(): Long = synchronized(lock) {
        (if (slot0.isFile) slot0.length() else 0L) +
            (if (slot1.isFile) slot1.length() else 0L)
    }

    fun clear() = synchronized(lock) {
        if (slot0.isFile) slot0.delete()
        if (slot1.isFile) slot1.delete()
    }

    fun buildDiagnosticSummary(
        appVersion: String,
        deviceModel: String,
        androidSdk: Int,
        vpnStatus: VpnRuntimeStatus,
        nodeCount: Int,
        relayCount: Int,
        groupCount: Int,
    ): String {
        val sb = StringBuilder()
        sb.appendLine("=== CatCloud Android Diagnostics ===")
        sb.appendLine("Version: $appVersion | Device: $deviceModel | API: $androidSdk")
        sb.appendLine("VPN: running=${vpnStatus.running}, state=${vpnStatus.state}, uptime=${vpnStatus.uptimeSec}s, watchdog=${vpnStatus.watchdogStatus}")
        sb.appendLine("Inventory: nodes=$nodeCount, relays=$relayCount, groups=$groupCount, activeNodes=${vpnStatus.activeNodeCount}")
        if (!vpnStatus.lastError.isNullOrBlank()) {
            sb.appendLine("LastError: ${sanitizeLine(vpnStatus.lastError)}")
        }
        sb.appendLine("--- Recent Logs ---")
        for (line in readRecentLines(60)) {
            sb.appendLine(line)
        }
        return sb.toString()
    }

    companion object {
        const val MAX_SLOT_BYTES: Long = 512L * 1024L

        private val BEARER_RE = Regex("(?i)(Bearer\\s+)[A-Za-z0-9._~+/=-]{8,}")
        private val SECRET_KV_RE = Regex("(?i)((?:password|secret|token|uuid|auth-str|obfs-password|private-key)\\s*[:=]\\s*[\"']?)([^\"',\\s}&]{4,})")
        private val KEY_FRAG_RE = Regex("(#(?:[^\\s]*&)?k=)[A-Za-z0-9_-]{8,}")
        private val MMRELAY_RE = Regex("(?i)mmrelay://v1/[A-Za-z0-9_=-]{8,}")
        private val PROXY_URI_RE = Regex("(?i)\\b(vless|vmess|trojan|ss|ssr|hy2|hysteria2|tuic|anytls)://[^\\s\"']+")

        fun sanitizeLine(raw: String): String {
            var s = raw.replace('\r', ' ').replace('\n', ' ').trim()
            s = BEARER_RE.replace(s, "$1<REDACTED>")
            s = SECRET_KV_RE.replace(s, "$1<REDACTED>")
            s = KEY_FRAG_RE.replace(s, "$1<REDACTED>")
            s = MMRELAY_RE.replace(s, "mmrelay://v1/<REDACTED>")
            s = PROXY_URI_RE.replace(s) { m -> "${m.groupValues[1]}://<REDACTED>" }
            return s
        }
    }
}
