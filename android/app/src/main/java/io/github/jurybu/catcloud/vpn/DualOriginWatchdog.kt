package io.github.jurybu.catcloud.vpn

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.net.URLEncoder
import java.util.concurrent.TimeUnit
import kotlin.math.ceil

enum class DualHealth {
    FULL_HEALTHY, // 2/2 origins OK
    DEGRADED, // 1/2 origins OK (half-dead)
    FAILED, // 0/2 origins OK
}

enum class WatchdogSwitchMode {
    NONE,
    FORCE_CLOSE_OLD, // Full-dead >= 2 rounds
    GRACEFUL_NEW_ONLY, // Half-dead >= 4 rounds, only switch to 2/2 full-healthy candidate
}

data class NodeHealthState(
    var ewmaLatencyMs: Double? = null,
    var lastRawLatencyMs: Double? = null,
    var lastHealth: DualHealth? = null,
    var penaltyScore: Double = 0.0,
    var backoffStage: Int = 0,
    var cooldownUntilMs: Long = 0L,
    var recoveryStreak: Int = 0,
    var probationRemaining: Int = 0,
    var lastProbedAtMs: Long = 0L,
    var lastRecoveryCheckAtMs: Long = 0L,
) {
    fun isInCooldown(nowMs: Long): Boolean = cooldownUntilMs > nowMs

    fun cooldownRemainingSec(nowMs: Long): Long {
        if (cooldownUntilMs <= nowMs) return 0L
        return ceil((cooldownUntilMs - nowMs) / 1000.0).toLong().coerceAtLeast(1L)
    }

    fun needsRecoveryAttention(): Boolean =
        cooldownUntilMs > 0L || backoffStage > 0 || penaltyScore > 1e-6 || probationRemaining > 0

    fun statusLabel(nowMs: Long): String = when {
        isInCooldown(nowMs) -> "cooldown"
        probationRemaining > 0 -> "probation"
        backoffStage > 0 || penaltyScore > 1e-6 || lastHealth == DualHealth.DEGRADED || lastHealth == DualHealth.FAILED -> "degraded"
        else -> "healthy"
    }
}

data class WatchdogDecision(
    val switchMode: WatchdogSwitchMode,
    val targetNode: String? = null,
    val reason: String = "",
    val enteredAllDeadBackoff: Boolean = false,
)

/**
 * Pure JVM-testable dual-origin anti-half-dead watchdog state machine aligned 1:1 with desktop
 * `strategy/health_pool.rs` and Stage 18 Section 3.5:
 * - Dual origins: Google 204 + Cloudflare 204
 * - 1500ms retry-before-penalize re-check
 * - Full-dead (`0/2`) `>= 2` consecutive rounds -> immediate `FORCE_CLOSE_OLD` switch
 * - Half-dead (`1/2`) `>= 4` consecutive rounds -> smooth `GRACEFUL_NEW_ONLY` switch ONLY to `2/2` candidate
 * - All-dead backoff `180s`
 * - EWMA `alpha = 0.35`, cooldown ladder `[60, 180, 600]s`, 2-streak full-healthy recovery into half-penalty probation
 * - Screen-off stretches probe interval from `25s` to `120s`; pauses during speed test or offline
 */
class DualOriginWatchdogEngine {

    private val nodes = HashMap<String, NodeHealthState>()
    private var fullDownStreak = 0
    private var halfDeadStreak = 0
    private var allDeadBackoffUntilMs = 0L
    private var screenOff = false
    private var pausedBySpeedTest = false
    private var networkAvailable = true

    fun setScreenOff(off: Boolean) {
        screenOff = off
    }

    fun setPausedBySpeedTest(paused: Boolean) {
        pausedBySpeedTest = paused
    }

    fun setNetworkAvailable(available: Boolean) {
        networkAvailable = available
        if (!available) {
            fullDownStreak = 0
            halfDeadStreak = 0
        }
    }

    fun shouldRunProbeTick(nowMs: Long): Boolean {
        if (!networkAvailable || pausedBySpeedTest) return false
        if (allDeadBackoffUntilMs > nowMs) return false
        return true
    }

    fun currentIntervalMs(): Long =
        if (screenOff) SCREEN_OFF_INTERVAL_MS else SCREEN_ON_INTERVAL_MS

    fun getNodeHealth(nodeName: String): NodeHealthState? = nodes[nodeName]

    fun isInAllDeadBackoff(nowMs: Long): Boolean = allDeadBackoffUntilMs > nowMs

    fun recordProbeResult(
        nodeName: String,
        health: DualHealth,
        rawLatencyMs: Double?,
        nowMs: Long,
    ) {
        val key = nodeName.trim()
        if (key.isEmpty()) return
        val entry = nodes.getOrPut(key) { NodeHealthState() }
        val wasNeedingRecovery = entry.needsRecoveryAttention()
        entry.lastProbedAtMs = nowMs
        if (wasNeedingRecovery) entry.lastRecoveryCheckAtMs = nowMs

        if (rawLatencyMs != null && rawLatencyMs.isFinite() && rawLatencyMs > 0.0) {
            entry.lastRawLatencyMs = rawLatencyMs
            entry.ewmaLatencyMs = entry.ewmaLatencyMs
                ?.takeIf { it.isFinite() && it > 0.0 }
                ?.let { prev -> EWMA_ALPHA * rawLatencyMs + (1.0 - EWMA_ALPHA) * prev }
                ?: rawLatencyMs
        }

        when (health) {
            DualHealth.FULL_HEALTHY -> {
                entry.lastHealth = DualHealth.FULL_HEALTHY
                val inCooldownOrUnrecovered = entry.cooldownUntilMs > 0L ||
                    entry.backoffStage > 0 ||
                    (entry.penaltyScore > 1e-6 && entry.probationRemaining == 0)

                if (inCooldownOrUnrecovered) {
                    entry.recoveryStreak += 1
                    if (entry.recoveryStreak >= RECOVERY_STREAK_REQUIRED) {
                        entry.cooldownUntilMs = 0L
                        entry.backoffStage = 0
                        entry.recoveryStreak = 0
                        val halved = (entry.penaltyScore * 0.5).coerceAtLeast(0.0)
                        if (halved > 1e-6) {
                            entry.penaltyScore = halved
                            entry.probationRemaining = 1
                        } else {
                            entry.penaltyScore = 0.0
                            entry.probationRemaining = 0
                        }
                    }
                } else if (entry.probationRemaining > 0) {
                    entry.probationRemaining -= 1
                    if (entry.probationRemaining == 0) {
                        entry.penaltyScore = 0.0
                        entry.recoveryStreak = 0
                    }
                } else {
                    entry.penaltyScore = 0.0
                    entry.backoffStage = 0
                    entry.cooldownUntilMs = 0L
                    entry.recoveryStreak = 0
                    entry.probationRemaining = 0
                }
            }
            DualHealth.DEGRADED -> {
                entry.lastHealth = DualHealth.DEGRADED
                entry.recoveryStreak = 0
                if (entry.backoffStage > 0 || entry.cooldownUntilMs > 0L) {
                    if (!entry.isInCooldown(nowMs) && entry.backoffStage > 0) {
                        entry.cooldownUntilMs = nowMs + backoffCooldownSecs(entry.backoffStage) * 1000L
                    }
                } else {
                    entry.probationRemaining = 0
                    if (entry.penaltyScore < DEGRADED_PENALTY_CAP) {
                        entry.penaltyScore = (entry.penaltyScore + DEGRADED_PENALTY_STEP)
                            .coerceAtMost(DEGRADED_PENALTY_CAP)
                    }
                }
            }
            DualHealth.FAILED -> {
                entry.lastHealth = DualHealth.FAILED
                if (!(entry.isInCooldown(nowMs) && entry.backoffStage > 0)) {
                    entry.backoffStage = (entry.backoffStage + 1).coerceAtMost(MAX_BACKOFF_STAGE)
                }
                val cdSec = backoffCooldownSecs(entry.backoffStage)
                entry.cooldownUntilMs = nowMs + cdSec * 1000L
                entry.penaltyScore = FAILED_PENALTY_BASE + entry.backoffStage * FAILED_PENALTY_STAGE_STEP
                entry.recoveryStreak = 0
                entry.probationRemaining = 0
            }
        }
    }

    /**
     * Process a confirmed dual-origin probe of the currently active node and decide whether to switch.
     *
     * [candidatesWithHealth] supplies probed alternative candidates `(nodeName, health, latencyMs)`.
     */
    fun onActiveNodeChecked(
        activeNode: String,
        activeHealth: DualHealth,
        activeLatencyMs: Double?,
        candidatesWithHealth: List<Triple<String, DualHealth, Double?>>,
        nowMs: Long,
    ): WatchdogDecision {
        recordProbeResult(activeNode, activeHealth, activeLatencyMs, nowMs)
        for ((cand, h, lat) in candidatesWithHealth) {
            if (cand != activeNode) {
                recordProbeResult(cand, h, lat, nowMs)
            }
        }

        when (activeHealth) {
            DualHealth.FULL_HEALTHY -> {
                fullDownStreak = 0
                halfDeadStreak = 0
                allDeadBackoffUntilMs = 0L
                return WatchdogDecision(WatchdogSwitchMode.NONE, reason = "healthy_2_of_2")
            }
            DualHealth.FAILED -> {
                fullDownStreak += 1
                halfDeadStreak = 0
                if (fullDownStreak < FULL_DOWN_SWITCH_STREAK) {
                    return WatchdogDecision(WatchdogSwitchMode.NONE, reason = "full_down_streak_$fullDownStreak")
                }
                val best = pickBestCandidate(activeNode, candidatesWithHealth, requireFullHealthy = false, nowMs = nowMs)
                return if (best != null) {
                    fullDownStreak = 0
                    halfDeadStreak = 0
                    WatchdogDecision(
                        switchMode = WatchdogSwitchMode.FORCE_CLOSE_OLD,
                        targetNode = best,
                        reason = "full_down_2_rounds_switch",
                    )
                } else {
                    allDeadBackoffUntilMs = nowMs + ALL_DEAD_BACKOFF_SEC * 1000L
                    fullDownStreak = 0
                    WatchdogDecision(
                        switchMode = WatchdogSwitchMode.NONE,
                        reason = "all_candidates_failed_backoff_180s",
                        enteredAllDeadBackoff = true,
                    )
                }
            }
            DualHealth.DEGRADED -> {
                halfDeadStreak += 1
                fullDownStreak = 0
                if (halfDeadStreak < HALF_DEAD_SWITCH_STREAK) {
                    return WatchdogDecision(WatchdogSwitchMode.NONE, reason = "half_dead_streak_$halfDeadStreak")
                }
                // Half-dead switch STRICTLY requires a 2/2 FULL_HEALTHY candidate and never drops old connections
                val bestFullGreen = pickBestCandidate(activeNode, candidatesWithHealth, requireFullHealthy = true, nowMs = nowMs)
                return if (bestFullGreen != null) {
                    halfDeadStreak = 0
                    WatchdogDecision(
                        switchMode = WatchdogSwitchMode.GRACEFUL_NEW_ONLY,
                        targetNode = bestFullGreen,
                        reason = "half_dead_4_rounds_graceful_switch",
                    )
                } else {
                    WatchdogDecision(
                        switchMode = WatchdogSwitchMode.NONE,
                        reason = "half_dead_no_2_of_2_candidate_keep_current",
                    )
                }
            }
        }
    }

    private fun pickBestCandidate(
        activeNode: String,
        candidates: List<Triple<String, DualHealth, Double?>>,
        requireFullHealthy: Boolean,
        nowMs: Long,
    ): String? {
        val eligible = candidates.filter { (name, health, _) ->
            if (name == activeNode) return@filter false
            if (requireFullHealthy && health != DualHealth.FULL_HEALTHY) return@filter false
            if (!requireFullHealthy && health == DualHealth.FAILED) return@filter false
            val st = nodes[name]
            st == null || !st.isInCooldown(nowMs)
        }
        if (eligible.isEmpty()) return null
        return eligible.minByOrNull { (name, health, lat) ->
            val st = nodes[name]
            val baseLat = st?.ewmaLatencyMs ?: lat ?: 9999.0
            val healthBias = if (health == DualHealth.FULL_HEALTHY) 0.0 else 500.0
            baseLat + (st?.penaltyScore ?: 0.0) + healthBias
        }?.first
    }

    fun reset() {
        nodes.clear()
        fullDownStreak = 0
        halfDeadStreak = 0
        allDeadBackoffUntilMs = 0L
    }

    companion object {
        const val ORIGIN_GOOGLE_204 = "https://www.gstatic.com/generate_204"
        const val ORIGIN_CLOUDFLARE_204 = "https://cp.cloudflare.com/generate_204"

        const val SCREEN_ON_INTERVAL_MS = 25_000L
        const val SCREEN_OFF_INTERVAL_MS = 120_000L
        const val RETRY_RECHECK_DELAY_MS = 1_500L
        const val FULL_DOWN_SWITCH_STREAK = 2
        const val HALF_DEAD_SWITCH_STREAK = 4
        const val ALL_DEAD_BACKOFF_SEC = 180L

        const val EWMA_ALPHA = 0.35
        const val DEGRADED_PENALTY_STEP = 18.0
        const val DEGRADED_PENALTY_CAP = 45.0
        const val FAILED_PENALTY_BASE = 120.0
        const val FAILED_PENALTY_STAGE_STEP = 40.0
        const val MAX_BACKOFF_STAGE = 3
        const val RECOVERY_STREAK_REQUIRED = 2

        private val BACKOFF_COOLDOWN_SECS = longArrayOf(60L, 180L, 600L)

        fun backoffCooldownSecs(stage: Int): Long {
            if (stage <= 0) return 0L
            val idx = (stage - 1).coerceIn(0, BACKOFF_COOLDOWN_SECS.lastIndex)
            return BACKOFF_COOLDOWN_SECS[idx]
        }
    }
}

/**
 * Coroutine runner executed inside `:vpn` process, probing via Mihomo loopback REST API.
 */
class DualOriginWatchdogRunner(
    private val scope: CoroutineScope,
    private val onStatusUpdate: (String) -> Unit,
) {
    val engine = DualOriginWatchdogEngine()
    private var job: Job? = null

    private val client = OkHttpClient.Builder()
        .connectTimeout(3500, TimeUnit.MILLISECONDS)
        .readTimeout(4500, TimeUnit.MILLISECONDS)
        .build()

    fun start(restPort: Int, restSecret: String, groupNameProvider: () -> String) {
        stop()
        job = scope.launch(Dispatchers.IO) {
            onStatusUpdate("active_25s")
            while (isActive) {
                val now = System.currentTimeMillis()
                if (engine.shouldRunProbeTick(now)) {
                    runCatching {
                        runSingleCycle(restPort, restSecret, groupNameProvider(), now)
                    }
                } else {
                    onStatusUpdate("paused")
                }
                delay(engine.currentIntervalMs())
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
        onStatusUpdate("idle")
    }

    private suspend fun runSingleCycle(
        restPort: Int,
        restSecret: String,
        groupName: String,
        nowMs: Long,
    ) {
        if (restPort <= 0 || restSecret.isBlank() || groupName.isBlank()) return
        val groupInfo = fetchProxyGroup(restPort, restSecret, groupName) ?: return
        val activeNode = groupInfo.first.takeIf { it.isNotBlank() && it != "DIRECT" && it != "REJECT" } ?: return
        val allCandidates = groupInfo.second.filter { it != "DIRECT" && it != "REJECT" }

        var (health, latency) = probeDualOrigin(restPort, restSecret, activeNode)
        // Retry-before-penalize: immediate 1500ms re-check when 0/2 failed
        if (health == DualHealth.FAILED) {
            delay(DualOriginWatchdogEngine.RETRY_RECHECK_DELAY_MS)
            val recheck = probeDualOrigin(restPort, restSecret, activeNode)
            health = recheck.first
            latency = recheck.second
        }

        val candidateResults = if (health != DualHealth.FULL_HEALTHY) {
            allCandidates
                .filter { it != activeNode }
                .take(4)
                .map { cand ->
                    val (ch, cl) = probeDualOrigin(restPort, restSecret, cand)
                    Triple(cand, ch, cl)
                }
        } else {
            emptyList()
        }

        val decision = engine.onActiveNodeChecked(activeNode, health, latency, candidateResults, nowMs)
        when (decision.switchMode) {
            WatchdogSwitchMode.FORCE_CLOSE_OLD -> {
                decision.targetNode?.let { target ->
                    switchGroupNode(restPort, restSecret, groupName, target)
                    closeAllConnections(restPort, restSecret)
                    onStatusUpdate("switched_force:$target")
                }
            }
            WatchdogSwitchMode.GRACEFUL_NEW_ONLY -> {
                decision.targetNode?.let { target ->
                    switchGroupNode(restPort, restSecret, groupName, target)
                    // Intentionally keep existing connections alive for graceful half-dead migration
                    onStatusUpdate("switched_graceful:$target")
                }
            }
            WatchdogSwitchMode.NONE -> {
                val periodLabel = if (engine.currentIntervalMs() == DualOriginWatchdogEngine.SCREEN_OFF_INTERVAL_MS) "120s" else "25s"
                onStatusUpdate("${decision.reason} ($periodLabel)")
            }
        }
    }

    private fun probeDualOrigin(restPort: Int, restSecret: String, nodeName: String): Pair<DualHealth, Double?> {
        val g = probeSingleOrigin(restPort, restSecret, nodeName, DualOriginWatchdogEngine.ORIGIN_GOOGLE_204)
        val c = probeSingleOrigin(restPort, restSecret, nodeName, DualOriginWatchdogEngine.ORIGIN_CLOUDFLARE_204)
        val okCount = (if (g != null) 1 else 0) + (if (c != null) 1 else 0)
        val health = when (okCount) {
            2 -> DualHealth.FULL_HEALTHY
            1 -> DualHealth.DEGRADED
            else -> DualHealth.FAILED
        }
        val avgLat = when {
            g != null && c != null -> (g + c) / 2.0
            g != null -> g.toDouble()
            c != null -> c.toDouble()
            else -> null
        }
        return health to avgLat
    }

    private fun probeSingleOrigin(restPort: Int, restSecret: String, nodeName: String, url: String): Int? {
        val encNode = URLEncoder.encode(nodeName, "UTF-8").replace("+", "%20")
        val encUrl = URLEncoder.encode(url, "UTF-8")
        val req = Request.Builder()
            .url("http://127.0.0.1:$restPort/proxies/$encNode/delay?url=$encUrl&timeout=3500")
            .header("Authorization", "Bearer $restSecret")
            .get()
            .build()
        return runCatching {
            client.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return@use null
                val d = JSONObject(resp.body?.string().orEmpty()).optInt("delay", -1)
                if (d > 0) d else null
            }
        }.getOrNull()
    }

    private fun fetchProxyGroup(restPort: Int, restSecret: String, groupName: String): Pair<String, List<String>>? {
        val enc = URLEncoder.encode(groupName, "UTF-8").replace("+", "%20")
        val req = Request.Builder()
            .url("http://127.0.0.1:$restPort/proxies/$enc")
            .header("Authorization", "Bearer $restSecret")
            .get()
            .build()
        return runCatching {
            client.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return@use null
                val obj = JSONObject(resp.body?.string().orEmpty())
                val now = obj.optString("now", "")
                val allArr = obj.optJSONArray("all")
                val members = ArrayList<String>()
                if (allArr != null) {
                    for (i in 0 until allArr.length()) {
                        members.add(allArr.optString(i, ""))
                    }
                }
                now to members
            }
        }.getOrNull()
    }

    private fun switchGroupNode(restPort: Int, restSecret: String, groupName: String, targetNode: String) {
        val enc = URLEncoder.encode(groupName, "UTF-8").replace("+", "%20")
        val payload = JSONObject().put("name", targetNode).toString()
        val req = Request.Builder()
            .url("http://127.0.0.1:$restPort/proxies/$enc")
            .header("Authorization", "Bearer $restSecret")
            .put(payload.toRequestBody("application/json; charset=utf-8".toMediaType()))
            .build()
        runCatching { client.newCall(req).execute().close() }
    }

    private fun closeAllConnections(restPort: Int, restSecret: String) {
        val req = Request.Builder()
            .url("http://127.0.0.1:$restPort/connections")
            .header("Authorization", "Bearer $restSecret")
            .delete()
            .build()
        runCatching { client.newCall(req).execute().close() }
    }
}
