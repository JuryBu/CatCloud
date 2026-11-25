package io.github.jurybu.catcloud

import io.github.jurybu.catcloud.vpn.DualHealth
import io.github.jurybu.catcloud.vpn.DualOriginWatchdogEngine
import io.github.jurybu.catcloud.vpn.WatchdogSwitchMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DualOriginWatchdogTest {

    @Test
    fun fullDownTriggersForceCloseSwitchOnSecondRoundAndEntersAllDeadBackoffWhenNoCandidate() {
        val engine = DualOriginWatchdogEngine()
        val t0 = 1_000_000L

        // Round 1 full-down: hold (streak = 1)
        val d1 = engine.onActiveNodeChecked(
            activeNode = "n1",
            activeHealth = DualHealth.FAILED,
            activeLatencyMs = null,
            candidatesWithHealth = listOf(Triple("n2", DualHealth.FULL_HEALTHY, 60.0)),
            nowMs = t0,
        )
        assertEquals(WatchdogSwitchMode.NONE, d1.switchMode)

        // Round 2 full-down: switch immediately with FORCE_CLOSE_OLD
        val d2 = engine.onActiveNodeChecked(
            activeNode = "n1",
            activeHealth = DualHealth.FAILED,
            activeLatencyMs = null,
            candidatesWithHealth = listOf(Triple("n2", DualHealth.FULL_HEALTHY, 65.0)),
            nowMs = t0 + 25_000L,
        )
        assertEquals(WatchdogSwitchMode.FORCE_CLOSE_OLD, d2.switchMode)
        assertEquals("n2", d2.targetNode)

        // All candidates failed for 2 rounds -> enter 180s all-dead backoff
        val engine2 = DualOriginWatchdogEngine()
        engine2.onActiveNodeChecked("n1", DualHealth.FAILED, null, listOf(Triple("n2", DualHealth.FAILED, null)), t0)
        val dAllDead = engine2.onActiveNodeChecked("n1", DualHealth.FAILED, null, listOf(Triple("n2", DualHealth.FAILED, null)), t0 + 25_000L)
        assertTrue(dAllDead.enteredAllDeadBackoff)
        assertTrue(engine2.isInAllDeadBackoff(t0 + 25_000L + 179_000L))
        assertFalse(engine2.isInAllDeadBackoff(t0 + 25_000L + 181_000L))
    }

    @Test
    fun halfDeadRequires4RoundsAndOnlySwitchesGracefullyToFullHealthyCandidate() {
        val engine = DualOriginWatchdogEngine()
        val t0 = 2_000_000L

        // Rounds 1..3 degraded (1/2) -> never switch yet
        for (i in 0 until 3) {
            val d = engine.onActiveNodeChecked(
                activeNode = "n1",
                activeHealth = DualHealth.DEGRADED,
                activeLatencyMs = 150.0,
                candidatesWithHealth = listOf(Triple("n2", DualHealth.FULL_HEALTHY, 55.0)),
                nowMs = t0 + i * 25_000L,
            )
            assertEquals(WatchdogSwitchMode.NONE, d.switchMode)
        }

        // Round 4 degraded when candidate is ONLY degraded (1/2) -> must NOT switch
        val dNoFullGreen = engine.onActiveNodeChecked(
            activeNode = "n1",
            activeHealth = DualHealth.DEGRADED,
            activeLatencyMs = 155.0,
            candidatesWithHealth = listOf(Triple("n2", DualHealth.DEGRADED, 50.0)),
            nowMs = t0 + 75_000L,
        )
        assertEquals(WatchdogSwitchMode.NONE, dNoFullGreen.switchMode)

        // Next round with a 2/2 FULL_HEALTHY candidate -> smooth GRACEFUL_NEW_ONLY switch (keep old connections!)
        val dGraceful = engine.onActiveNodeChecked(
            activeNode = "n1",
            activeHealth = DualHealth.DEGRADED,
            activeLatencyMs = 160.0,
            candidatesWithHealth = listOf(Triple("n3", DualHealth.FULL_HEALTHY, 52.0)),
            nowMs = t0 + 100_000L,
        )
        assertEquals(WatchdogSwitchMode.GRACEFUL_NEW_ONLY, dGraceful.switchMode)
        assertEquals("n3", dGraceful.targetNode)
    }

    @Test
    fun ewmaSmoothingExponentialBackoffLadderAndTwoStreakProbationRecovery() {
        val engine = DualOriginWatchdogEngine()
        val t0 = 5_000_000L

        // EWMA alpha = 0.35
        engine.recordProbeResult("n1", DualHealth.FULL_HEALTHY, 100.0, t0)
        assertEquals(100.0, engine.getNodeHealth("n1")!!.ewmaLatencyMs!!, 1e-6)
        engine.recordProbeResult("n1", DualHealth.FULL_HEALTHY, 200.0, t0 + 25_000L)
        assertEquals(135.0, engine.getNodeHealth("n1")!!.ewmaLatencyMs!!, 1e-6)

        // Failure 1 -> stage 1, 60s cooldown, penalty 160
        engine.recordProbeResult("n1", DualHealth.FAILED, null, t0 + 50_000L)
        val h1 = engine.getNodeHealth("n1")!!
        assertEquals(1, h1.backoffStage)
        assertEquals(160.0, h1.penaltyScore, 1e-6)
        assertTrue(h1.isInCooldown(t0 + 50_000L + 59_000L))
        assertFalse(h1.isInCooldown(t0 + 50_000L + 60_000L))

        // Re-fail inside active cooldown holds stage 1
        engine.recordProbeResult("n1", DualHealth.FAILED, null, t0 + 75_000L)
        assertEquals(1, engine.getNodeHealth("n1")!!.backoffStage)

        // Fail after cooldown -> stage 2 (180s, penalty 200)
        val tStage2 = t0 + 140_000L
        engine.recordProbeResult("n1", DualHealth.FAILED, null, tStage2)
        assertEquals(2, engine.getNodeHealth("n1")!!.backoffStage)
        assertEquals(200.0, engine.getNodeHealth("n1")!!.penaltyScore, 1e-6)
        assertTrue(engine.getNodeHealth("n1")!!.isInCooldown(tStage2 + 179_000L))

        // Fail after stage 2 -> stage 3 (600s, penalty 240)
        val tStage3 = tStage2 + 190_000L
        engine.recordProbeResult("n1", DualHealth.FAILED, null, tStage3)
        assertEquals(3, engine.getNodeHealth("n1")!!.backoffStage)
        assertEquals(240.0, engine.getNodeHealth("n1")!!.penaltyScore, 1e-6)
        assertTrue(engine.getNodeHealth("n1")!!.isInCooldown(tStage3 + 599_000L))

        // 1st FullHealthy after cooldown -> streak = 1, still penalized
        val tRec1 = tStage3 + 605_000L
        engine.recordProbeResult("n1", DualHealth.FULL_HEALTHY, 75.0, tRec1)
        assertEquals(1, engine.getNodeHealth("n1")!!.recoveryStreak)
        assertEquals(3, engine.getNodeHealth("n1")!!.backoffStage)

        // 2nd consecutive FullHealthy -> exits cooldown into half-penalty probation (120.0)
        val tRec2 = tRec1 + 65_000L
        engine.recordProbeResult("n1", DualHealth.FULL_HEALTHY, 70.0, tRec2)
        val hProb = engine.getNodeHealth("n1")!!
        assertEquals(0, hProb.backoffStage)
        assertEquals(1, hProb.probationRemaining)
        assertEquals(120.0, hProb.penaltyScore, 1e-6)
        assertEquals("probation", hProb.statusLabel(tRec2))

        // 3rd FullHealthy clears probation completely to 0.0
        val tRec3 = tRec2 + 65_000L
        engine.recordProbeResult("n1", DualHealth.FULL_HEALTHY, 65.0, tRec3)
        val hClean = engine.getNodeHealth("n1")!!
        assertEquals(0, hClean.probationRemaining)
        assertEquals(0.0, hClean.penaltyScore, 1e-6)
        assertEquals("healthy", hClean.statusLabel(tRec3))
    }

    @Test
    fun screenOffIntervalAndSpeedTestPauseBehavior() {
        val engine = DualOriginWatchdogEngine()
        assertEquals(25_000L, engine.currentIntervalMs())
        engine.setScreenOff(true)
        assertEquals(120_000L, engine.currentIntervalMs())
        engine.setScreenOff(false)
        assertEquals(25_000L, engine.currentIntervalMs())

        assertTrue(engine.shouldRunProbeTick(1000L))
        engine.setPausedBySpeedTest(true)
        assertFalse(engine.shouldRunProbeTick(1000L))
        engine.setPausedBySpeedTest(false)
        assertTrue(engine.shouldRunProbeTick(1000L))
        engine.setNetworkAvailable(false)
        assertFalse(engine.shouldRunProbeTick(1000L))
    }
}
