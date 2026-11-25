package io.github.jurybu.catcloud.data

import androidx.compose.runtime.Immutable

@Immutable
enum class ProxyMode(val wireValue: String) {
    RULE("rule"),
    GLOBAL("global");

    companion object {
        fun fromWire(raw: String?): ProxyMode =
            if (raw.equals("global", ignoreCase = true)) GLOBAL else RULE
    }
}

@Immutable
enum class RouteMode(val wireValue: String) {
    SINGLE("single"),
    GROUP("group");

    companion object {
        fun fromWire(raw: String?): RouteMode =
            if (raw.equals("group", ignoreCase = true)) GROUP else SINGLE
    }
}

@Immutable
enum class PerAppMode(val wireValue: String) {
    ALL("all"),
    BYPASS("bypass"),
    ALLOW("allow");

    companion object {
        fun fromWire(raw: String?): PerAppMode = when (raw?.trim()?.lowercase()) {
            "bypass" -> BYPASS
            "allow" -> ALLOW
            else -> ALL
        }
    }
}

@Immutable
enum class ThemePreference(val wireValue: String) {
    MIDNIGHT_BLUE("midnight_blue"),
    DAWN_LIGHT("dawn_light"),
    SYSTEM("system");

    companion object {
        fun fromWire(raw: String?): ThemePreference = when (raw?.trim()?.lowercase()) {
            "dawn_light", "light" -> DAWN_LIGHT
            "system" -> SYSTEM
            else -> MIDNIGHT_BLUE
        }
    }
}

@Immutable
data class ProxyNodeRecord(
    val id: String,
    val subId: String = "manual",
    val name: String,
    val protocol: String,
    val server: String,
    val port: Int,
    val rawConfigJson: String,
    val regionCode: String = "UNK",
    val multiplier: Double = 1.0,
    val is443Native: Boolean = false,
    val preaccelEligible: Boolean = true,
    val preaccelOverride: Boolean? = null,
    val tags: List<String> = emptyList(),
    val enabled: Boolean = true,
    val fingerprint: String = "",
    val lastLatencyMs: Int? = null,
    val lastDownMbps: Double? = null,
    val lastUpMbps: Double? = null,
) {
    fun isUdpOnlyTransport(): Boolean = when (protocol.trim().lowercase()) {
        "hysteria2", "hy2", "hysteria", "tuic", "wireguard" -> true
        else -> false
    }

    fun shouldApplyPreaccel(globalSkip443Native: Boolean): Boolean {
        preaccelOverride?.let { return it }
        if (!preaccelEligible) return false
        if (isUdpOnlyTransport()) return false
        if (globalSkip443Native && is443Native) return false
        return true
    }
}

@Immutable
data class PreAccelRelayRecord(
    val id: String,
    val name: String,
    val provider: String = "",
    val region: String = "",
    val server: String,
    val port: Int = 443,
    val protocol: String = "anytls",
    val password: String,
    val sni: String? = null,
    val skipCertVerify: Boolean = true,
    val priority: Int = 100,
    val expiresAt: String? = null,
    val enabled: Boolean = true,
    val lastProbeMs: Int? = null,
) {
    fun hasNonEmptySni(): Boolean = !sni.isNullOrBlank()
}

@Immutable
data class MultiGroupRecord(
    val id: String,
    val name: String,
    val mode: String = "sticky_best",
    val matchRules: List<String> = emptyList(),
    val memberNodeIds: List<String> = emptyList(),
    val dynamicFilterJson: String? = null,
    val primaryProbeId: String? = null,
    val hardGates: List<String> = emptyList(),
    val triggerRulesJson: String = "[]",
    val formulaExpr: String = DEFAULT_FORMULA_EXPR,
    val fallbackPolicy: String = "degrade_best_warn",
    val fallbackPoolId: String? = null,
    val recoverProbeIntervalSec: Long = 120L,
    val switchMode: String = "force_close_old",
    val cooldownSec: Long = 60L,
    val hysteresisPct: Double = 20.0,
    val activeNodeId: String? = null,
    val independentRouting: Boolean = false,
) {
    companion object {
        const val DEFAULT_FORMULA_EXPR =
            "(up_mbps * 35 + min(down_mbps, 200) * 0.25 - ping_ms * 0.08 - jitter_ms * 0.15) / max(multiplier, 0.25)"
    }
}

@Immutable
data class AppSettings(
    val proxyMode: ProxyMode = ProxyMode.RULE,
    val routeMode: RouteMode = RouteMode.SINGLE,
    val activeSingleNodeId: String? = null,
    val activeGroupId: String? = null,
    val preaccelEnabled: Boolean = false,
    val preaccelAutoFailover: Boolean = true,
    val preaccelSkip443Native: Boolean = true,
    val preaccelActiveRelayId: String? = null,
    val preaccelProbeUrl: String = "http://connectivitycheck.platform.hicloud.com/generate_204",
    val preaccelFallbackProbeUrl: String = "http://connect.rom.miui.com/generate_204",
    val preaccelProbeIntervalSec: Int = 30,
    val domesticDirectEnabled: Boolean = true,
    val blockQuicUdp443: Boolean = true,
    val campusDirectDomains: List<String> = emptyList(),
    val perAppMode: PerAppMode = PerAppMode.BYPASS,
    val perAppPackages: List<String> = emptyList(),
    val theme: ThemePreference = ThemePreference.MIDNIGHT_BLUE,
    val autoStartOnBoot: Boolean = false,
    val lastVpnWasRunning: Boolean = false,
    val ignoredClipboardHash: String? = null,
)

@Immutable
data class RelayBoxItem(
    val id: String,
    val name: String,
    val createdAtMs: Long,
    val expiresAtMs: Long,
    val zipFp: String,
    val sizeBytes: Int,
    val nodeCount: Int,
    val relayCount: Int,
    val groupCount: Int,
)

@Immutable
data class VpnRuntimeStatus(
    val running: Boolean = false,
    val state: String = "stopped",
    val restPort: Int = 0,
    val restSecret: String = "",
    val activeNodeName: String = "",
    val activeNodeCount: Int = 0,
    val uptimeSec: Long = 0L,
    val watchdogStatus: String = "idle",
    val lastError: String? = null,
)

@Immutable
data class SpeedTestProgress(
    val running: Boolean = false,
    val modeLabel: String = "",
    val completed: Int = 0,
    val total: Int = 0,
    val currentNodeName: String = "",
    val usePreAccel: Boolean = false,
)

@Immutable
data class InstalledAppInfo(
    val packageName: String,
    val label: String,
    val isSystemApp: Boolean,
)
