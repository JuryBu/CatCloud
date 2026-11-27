// @ts-expect-error Node 24 built-in test runner (no @types/node in frontend tsconfig)
import { describe, it } from "node:test";
// @ts-expect-error Node 24 built-in strict assert
import assert from "node:assert/strict";

import type { NodeHealthHint, ProbeSnapshot } from "../api/tauri";
import {
  MISSING_LATENCY_PENALTY_MS,
  getLatencyTooltipKey,
  hasValidDownMbps,
  hasValidUpMbps,
  resolveNodeDisplayLatency,
} from "./latencyDisplay.ts";

function makeSnap(overrides: Partial<ProbeSnapshot> = {}): ProbeSnapshot {
  return {
    node_id: "node-1",
    tested_at: "2026-11-27T05:00:00Z",
    ok: true,
    latency_ms: 68,
    jitter_ms: 3.2,
    loss_pct: 0,
    up_mbps: 18.5,
    down_mbps: 165.0,
    cf_loc: "NRT",
    yt_gl: "JP",
    google_clean: true,
    google_risk_mismatch: false,
    keepalive_60s_ok: true,
    unlocked_sites: { gemini: true, chatgpt: true },
    per_probe_ok: { builtin_latency: true },
    per_probe_up_mbps: { builtin_upload: 18.5 },
    per_probe_down_mbps: { builtin_download: 165.0 },
    per_probe_ping_ms: { builtin_latency: 68 },
    per_probe_detail: {},
    per_probe_tested_at: { builtin_latency: "2026-11-27T05:00:00Z" },
    ...overrides,
  };
}

function makeHint(overrides: Partial<NodeHealthHint> = {}): NodeHealthHint {
  return {
    latency_ms: 112,
    status: "healthy",
    cooldown_remaining_sec: 0,
    ...overrides,
  };
}

describe("latencyDisplay", () => {
  it("exports MISSING_LATENCY_PENALTY_MS as 9999", () => {
    assert.equal(MISSING_LATENCY_PENALTY_MS, 9999);
  });

  it("never masks an explicit failed probe snapshot with a stale green healthHint", () => {
    const failedSnap = makeSnap({
      ok: false,
      latency_ms: null,
      per_probe_ok: { builtin_latency: false },
      per_probe_ping_ms: {},
    });
    const staleHealthy = makeHint({ status: "healthy", latency_ms: 54 });
    const staleProbation = makeHint({ status: "probation", latency_ms: 72 });
    const staleDegraded = makeHint({ status: "degraded", latency_ms: 180 });

    for (const hint of [staleHealthy, staleProbation, staleDegraded, null]) {
      const res = resolveNodeDisplayLatency(failedSnap, hint);
      assert.deepEqual(res, {
        latencyMs: null,
        ok: false,
        source: "probe",
        state: "failed",
        isProbation: false,
        isDegraded: false,
      });
      assert.equal(getLatencyTooltipKey(res), "failed");
    }
  });

  it("treats snap.ok === false as failed even if a residual numeric latency_ms exists", () => {
    const dirtyFailedSnap = makeSnap({
      ok: false,
      latency_ms: 120,
    });
    const res = resolveNodeDisplayLatency(dirtyFailedSnap, makeHint({ status: "healthy", latency_ms: 60 }));
    assert.equal(res.ok, false);
    assert.equal(res.latencyMs, null);
    assert.equal(res.state, "failed");
    assert.equal(getLatencyTooltipKey(res), "failed");
  });

  it("treats failed builtin_latency without positive top-level latency as failed", () => {
    const snap = makeSnap({
      ok: true,
      latency_ms: null,
      per_probe_ok: { builtin_latency: false, builtin_unlock_chatgpt: true },
    });
    const res = resolveNodeDisplayLatency(snap, makeHint({ status: "healthy", latency_ms: 85 }));
    assert.equal(res.ok, false);
    assert.equal(res.state, "failed");
    assert.equal(res.latencyMs, null);
    assert.equal(getLatencyTooltipKey(res), "failed");
  });

  it("marks node failed during runtime cooldown even if historical probe snapshot succeeded", () => {
    const snap = makeSnap({ ok: true, latency_ms: 58 });
    const cooldown = makeHint({
      status: "cooldown",
      latency_ms: null,
      cooldown_remaining_sec: 42,
    });
    const res = resolveNodeDisplayLatency(snap, cooldown);
    assert.deepEqual(res, {
      latencyMs: null,
      ok: false,
      source: "health",
      state: "failed",
      isProbation: false,
      isDegraded: false,
    });
    assert.equal(getLatencyTooltipKey(res), "failed");
  });

  it("clearly distinguishes standard 204 warm probe from newer background dual-source cold health probe", () => {
    const snapTsMs = Date.parse("2026-11-27T05:00:00Z");
    const warmOnly = resolveNodeDisplayLatency(makeSnap({ latency_ms: 64 }), null);
    assert.deepEqual(warmOnly, {
      latencyMs: 64,
      ok: true,
      source: "probe",
      state: "healthy",
      isProbation: false,
      isDegraded: false,
    });
    assert.equal(getLatencyTooltipKey(warmOnly), "probeHot");

    const coldHealth = resolveNodeDisplayLatency(
      makeSnap({ latency_ms: 64 }),
      makeHint({ status: "healthy", latency_ms: 118, probed_at_ms: snapTsMs + 60_000 })
    );
    assert.deepEqual(coldHealth, {
      latencyMs: 118,
      ok: true,
      source: "health",
      state: "healthy",
      isProbation: false,
      isDegraded: false,
    });
    assert.equal(getLatencyTooltipKey(coldHealth), "healthCold");

    const healthWithoutSnap = resolveNodeDisplayLatency(
      null,
      makeHint({ status: "healthy", latency_ms: 96 })
    );
    assert.equal(healthWithoutSnap.latencyMs, 96);
    assert.equal(healthWithoutSnap.source, "health");
    assert.equal(getLatencyTooltipKey(healthWithoutSnap), "healthCold");
  });

  it("allows strictly newer background watchdog health probe to clear stale historical probe failure", () => {
    const oldFailTs = "2026-11-27T04:00:00Z";
    const newerHealthMs = Date.parse("2026-11-27T05:30:00Z");
    const failedSnap = makeSnap({
      tested_at: oldFailTs,
      ok: false,
      latency_ms: null,
      per_probe_ok: { builtin_latency: false },
      per_probe_ping_ms: {},
      per_probe_tested_at: { builtin_latency: oldFailTs },
    });

    const recovered = resolveNodeDisplayLatency(
      failedSnap,
      makeHint({ status: "healthy", latency_ms: 45, probed_at_ms: newerHealthMs })
    );
    assert.deepEqual(recovered, {
      latencyMs: 45,
      ok: true,
      source: "health",
      state: "healthy",
      isProbation: false,
      isDegraded: false,
    });
    assert.equal(getLatencyTooltipKey(recovered), "healthCold");

    // Older healthHint before the manual probe failure MUST NOT mask the failure
    const staleHint = makeHint({
      status: "healthy",
      latency_ms: 45,
      probed_at_ms: Date.parse(oldFailTs) - 30_000,
    });
    const stillFailed = resolveNodeDisplayLatency(failedSnap, staleHint);
    assert.equal(stillFailed.ok, false);
    assert.equal(stillFailed.state, "failed");
    assert.equal(stillFailed.source, "probe");
  });

  it("keeps source as warm probe when manual probe is newer than or equal to health pool hint", () => {
    const warmTs = "2026-11-27T06:00:00Z";
    const warmSnap = makeSnap({
      tested_at: warmTs,
      ok: true,
      latency_ms: 52,
      per_probe_tested_at: { builtin_latency: warmTs },
    });

    // Older healthy healthHint must not mislabel a fresh warm test as "health"
    const olderHealthyHint = makeHint({
      status: "healthy",
      latency_ms: 120,
      probed_at_ms: Date.parse(warmTs) - 120_000,
    });
    const resHealthy = resolveNodeDisplayLatency(warmSnap, olderHealthyHint);
    assert.deepEqual(resHealthy, {
      latencyMs: 52,
      ok: true,
      source: "probe",
      state: "healthy",
      isProbation: false,
      isDegraded: false,
    });
    assert.equal(getLatencyTooltipKey(resHealthy), "probeHot");

    // Health hint without timestamp also does not override a passing warm probe
    const untimedHint = makeHint({ status: "healthy", latency_ms: 120 });
    const resUntimed = resolveNodeDisplayLatency(warmSnap, untimedHint);
    assert.equal(resUntimed.source, "probe");
    assert.equal(resUntimed.latencyMs, 52);

    // Older degraded hint passes through state flag without hijacking source to "health"
    const olderDegradedHint = makeHint({
      status: "degraded",
      latency_ms: 210,
      probed_at_ms: Date.parse(warmTs) - 10_000,
    });
    const resDegraded = resolveNodeDisplayLatency(warmSnap, olderDegradedHint);
    assert.deepEqual(resDegraded, {
      latencyMs: 52,
      ok: true,
      source: "probe",
      state: "degraded",
      isProbation: false,
      isDegraded: true,
    });
  });

  it("preserves probation and degraded states consistently across pages", () => {
    const snapTsMs = Date.parse("2026-11-27T05:00:00Z");
    const probation = resolveNodeDisplayLatency(
      makeSnap({ latency_ms: 65 }),
      makeHint({ status: "probation", latency_ms: 140, probed_at_ms: snapTsMs + 30_000 })
    );
    assert.deepEqual(probation, {
      latencyMs: 140,
      ok: true,
      source: "health",
      state: "probation",
      isProbation: true,
      isDegraded: false,
    });
    assert.equal(getLatencyTooltipKey(probation), "healthCold");

    const degraded = resolveNodeDisplayLatency(
      makeSnap({ latency_ms: 65 }),
      makeHint({ status: "degraded", latency_ms: 280, probed_at_ms: snapTsMs + 30_000 })
    );
    assert.deepEqual(degraded, {
      latencyMs: 280,
      ok: true,
      source: "health",
      state: "degraded",
      isProbation: false,
      isDegraded: true,
    });
    assert.equal(getLatencyTooltipKey(degraded), "healthCold");

    // Degraded hint without numeric latency falls back to probe latency while keeping degraded flag
    const degradedFallback = resolveNodeDisplayLatency(
      makeSnap({ latency_ms: 65 }),
      makeHint({ status: "degraded", latency_ms: null, probed_at_ms: snapTsMs + 30_000 })
    );
    assert.deepEqual(degradedFallback, {
      latencyMs: 65,
      ok: true,
      source: "probe",
      state: "degraded",
      isProbation: false,
      isDegraded: true,
    });
    assert.equal(getLatencyTooltipKey(degradedFallback), "probeHot");
  });

  it("validates upload/download speeds compatibly with custom probes when builtin speed probe fails", () => {
    // Builtin upload failed + custom upload succeeded => valid positive up_mbps
    const customUpSucceeded = makeSnap({
      up_mbps: 42.0,
      per_probe_ok: { builtin_latency: true, builtin_upload: false, custom_up: true },
      per_probe_up_mbps: { custom_up: 42.0 },
    });
    assert.equal(hasValidUpMbps(customUpSucceeded), true);

    // Builtin upload failed + no other successful upload probe => reject stale remnant
    const staleBuiltinUpRemnant = makeSnap({
      up_mbps: 18.5,
      per_probe_ok: { builtin_latency: true, builtin_upload: false },
      per_probe_up_mbps: {},
    });
    assert.equal(hasValidUpMbps(staleBuiltinUpRemnant), false);

    // Builtin download failed + external_cmd download succeeded => valid positive down_mbps
    const customDownSucceeded = makeSnap({
      down_mbps: 215.5,
      per_probe_ok: { builtin_latency: true, builtin_download: false, ext_speed: true },
      per_probe_down_mbps: { ext_speed: 215.5 },
    });
    assert.equal(hasValidDownMbps(customDownSucceeded), true);

    // Builtin download failed + custom download also failed => false
    const allDownFailed = makeSnap({
      down_mbps: 100.0,
      per_probe_ok: { builtin_download: false, ext_speed: false },
      per_probe_down_mbps: { ext_speed: 100.0 },
    });
    assert.equal(hasValidDownMbps(allDownFailed), false);

    assert.equal(hasValidUpMbps(null), false);
    assert.equal(hasValidDownMbps(makeSnap({ down_mbps: 0 })), false);
  });

  it("returns untested for missing, zero, negative, or NaN latencies", () => {
    for (const badSnap of [
      null,
      undefined,
      makeSnap({ ok: true, latency_ms: null }),
      makeSnap({ ok: true, latency_ms: 0 }),
      makeSnap({ ok: true, latency_ms: -10 }),
      makeSnap({ ok: true, latency_ms: Number.NaN }),
    ]) {
      const res = resolveNodeDisplayLatency(badSnap, null);
      assert.deepEqual(res, {
        latencyMs: null,
        ok: false,
        source: "none",
        state: "untested",
        isProbation: false,
        isDegraded: false,
      });
      assert.equal(getLatencyTooltipKey(res), "untested");
    }
  });
});
