// @ts-expect-error Node 24 built-in test runner (no @types/node in frontend tsconfig)
import { describe, it } from "node:test";
// @ts-expect-error Node 24 built-in strict assert
import assert from "node:assert/strict";

import type { ProbeSnapshot } from "../api/tauri";
import { mergeProbeSnapshotSafe } from "./probeSnapshotMerge.ts";

function makeSnap(overrides: Partial<ProbeSnapshot> = {}): ProbeSnapshot {
  return {
    node_id: "node-jp-01",
    tested_at: "2026-11-27T04:00:00Z",
    ok: true,
    latency_ms: 68,
    jitter_ms: 3.5,
    loss_pct: 0,
    up_mbps: 18.4,
    down_mbps: 185.2,
    cf_loc: "NRT",
    yt_gl: "JP",
    google_clean: true,
    google_risk_mismatch: false,
    keepalive_60s_ok: true,
    unlocked_sites: {
      gemini: true,
      chatgpt: true,
      claude: true,
      windsurf: true,
    },
    per_probe_ok: {
      builtin_latency: true,
      builtin_google_cn: true,
      builtin_upload: true,
      builtin_download: true,
      builtin_keepalive_60s: true,
      builtin_unlock_gemini: true,
      builtin_unlock_chatgpt: true,
      builtin_unlock_claude: true,
      builtin_unlock_windsurf: true,
    },
    per_probe_up_mbps: { builtin_upload: 18.4 },
    per_probe_down_mbps: { builtin_download: 185.2 },
    per_probe_ping_ms: { builtin_latency: 68 },
    per_probe_detail: {},
    per_probe_tested_at: {
      builtin_latency: "2026-11-27T04:00:00Z",
      builtin_upload: "2026-11-27T04:00:05Z",
      builtin_download: "2026-11-27T04:00:10Z",
    },
    ...overrides,
  };
}

describe("mergeProbeSnapshotSafe", () => {
  it("returns incoming normalized snapshot when prev is undefined", () => {
    const incoming = makeSnap({ latency_ms: 52 });
    const merged = mergeProbeSnapshotSafe(undefined, incoming);
    assert.equal(merged.latency_ms, 52);
    assert.equal(merged.per_probe_tested_at?.builtin_latency, "2026-11-27T04:00:00Z");
  });

  it("lets authoritative full DB snapshot clear stale speeds and green flags on retest failure (matches cold SQLite read)", () => {
    const prev = makeSnap();
    const fullDbAfterFailure = makeSnap({
      tested_at: "2026-11-27T05:00:00Z",
      ok: true,
      latency_ms: 72,
      up_mbps: null,
      down_mbps: null,
      keepalive_60s_ok: false,
      per_probe_ok: {
        ...prev.per_probe_ok,
        builtin_upload: false,
        builtin_download: false,
        builtin_keepalive_60s: false,
      },
      per_probe_up_mbps: {},
      per_probe_down_mbps: {},
      per_probe_ping_ms: { builtin_latency: 72 },
      per_probe_detail: {
        builtin_upload: "fast_fuse_triggered",
        builtin_download: "stage2_download_failed",
      },
      per_probe_tested_at: {
        builtin_latency: "2026-11-27T05:00:00Z",
        builtin_upload: "2026-11-27T05:00:03Z",
        builtin_download: "2026-11-27T05:00:06Z",
        builtin_keepalive_60s: "2026-11-27T05:00:09Z",
      },
    });

    const merged = mergeProbeSnapshotSafe(prev, fullDbAfterFailure);
    assert.equal(merged.latency_ms, 72);
    assert.equal(merged.up_mbps, null);
    assert.equal(merged.down_mbps, null);
    assert.equal(merged.keepalive_60s_ok, false);
    assert.equal(merged.per_probe_ok?.builtin_upload, false);
    assert.equal(merged.per_probe_up_mbps.builtin_upload, undefined);
    assert.equal(merged.per_probe_down_mbps.builtin_download, undefined);
    assert.equal(merged.per_probe_tested_at?.builtin_upload, "2026-11-27T05:00:03Z");
  });

  it("preserves previous latency/jitter/loss when a partial snapshot does not run any latency probe", () => {
    const prev = makeSnap({
      ok: true,
      latency_ms: 61,
      jitter_ms: 2.8,
      loss_pct: 0,
      up_mbps: 10.0,
      down_mbps: 100.0,
    });
    const partialBandwidthOnly: ProbeSnapshot = {
      node_id: "node-jp-01",
      tested_at: "2026-11-27T05:10:00Z",
      ok: true,
      latency_ms: null,
      jitter_ms: null,
      loss_pct: null,
      up_mbps: 24.6,
      down_mbps: 240.0,
      cf_loc: null,
      yt_gl: null,
      google_clean: null,
      google_risk_mismatch: false,
      keepalive_60s_ok: null,
      unlocked_sites: {},
      per_probe_ok: {
        builtin_upload: true,
        builtin_download: true,
      },
      per_probe_up_mbps: { builtin_upload: 24.6 },
      per_probe_down_mbps: { builtin_download: 240.0 },
      per_probe_ping_ms: {},
      per_probe_tested_at: {
        builtin_upload: "2026-11-27T05:10:00Z",
        builtin_download: "2026-11-27T05:10:04Z",
      },
    };

    const merged = mergeProbeSnapshotSafe(prev, partialBandwidthOnly);
    assert.equal(merged.ok, true);
    assert.equal(merged.latency_ms, 61);
    assert.equal(merged.jitter_ms, 2.8);
    assert.equal(merged.loss_pct, 0);
    assert.equal(merged.up_mbps, 24.6);
    assert.equal(merged.down_mbps, 240.0);
    assert.equal(merged.google_clean, true);
    assert.equal(merged.unlocked_sites.gemini, true);
    assert.equal(merged.per_probe_tested_at?.builtin_latency, "2026-11-27T04:00:00Z");
    assert.equal(merged.per_probe_tested_at?.builtin_upload, "2026-11-27T05:10:00Z");
    assert.equal(merged.per_probe_tested_at?.builtin_download, "2026-11-27T05:10:04Z");
  });

  it("clears stale latency and green ok flag when latency probe runs and fails", () => {
    const prev = makeSnap({ ok: true, latency_ms: 55, jitter_ms: 2.0, loss_pct: 0 });
    const failedLatencyPartial: ProbeSnapshot = {
      node_id: "node-jp-01",
      tested_at: "2026-11-27T05:20:00Z",
      ok: false,
      latency_ms: null,
      jitter_ms: null,
      loss_pct: 100,
      up_mbps: null,
      down_mbps: null,
      cf_loc: null,
      yt_gl: null,
      google_clean: null,
      google_risk_mismatch: false,
      keepalive_60s_ok: null,
      unlocked_sites: {},
      per_probe_ok: { builtin_latency: false },
      per_probe_up_mbps: {},
      per_probe_down_mbps: {},
      per_probe_ping_ms: {},
      per_probe_detail: { builtin_latency: "timeout" },
      per_probe_tested_at: { builtin_latency: "2026-11-27T05:20:00Z" },
    };

    const merged = mergeProbeSnapshotSafe(prev, failedLatencyPartial);
    assert.equal(merged.ok, false);
    assert.equal(merged.latency_ms, null);
    assert.equal(merged.jitter_ms, null);
    assert.equal(merged.loss_pct, 100);
    assert.equal(merged.per_probe_ok?.builtin_latency, false);
    assert.equal(merged.per_probe_ping_ms.builtin_latency, undefined);
    // Untouched bandwidth & unlocks from earlier run stay intact in partial merge
    assert.equal(merged.up_mbps, 18.4);
    assert.equal(merged.down_mbps, 185.2);
    assert.equal(merged.per_probe_tested_at?.builtin_latency, "2026-11-27T05:20:00Z");
    assert.equal(merged.per_probe_tested_at?.builtin_upload, "2026-11-27T04:00:05Z");
  });

  it("clears stale upload rate when partial upload retest fails while keeping prior latency and download", () => {
    const prev = makeSnap({
      ok: true,
      latency_ms: 68,
      up_mbps: 18.4,
      down_mbps: 185.2,
    });
    const failedUploadPartial: ProbeSnapshot = {
      node_id: "node-jp-01",
      tested_at: "2026-11-27T05:30:00Z",
      ok: false,
      latency_ms: null,
      jitter_ms: null,
      loss_pct: null,
      up_mbps: null,
      down_mbps: null,
      cf_loc: null,
      yt_gl: null,
      google_clean: null,
      google_risk_mismatch: false,
      keepalive_60s_ok: null,
      unlocked_sites: {},
      per_probe_ok: { builtin_upload: false },
      per_probe_up_mbps: {},
      per_probe_down_mbps: {},
      per_probe_ping_ms: {},
      per_probe_detail: { builtin_upload: "fast_fuse_triggered" },
      per_probe_tested_at: { builtin_upload: "2026-11-27T05:30:00Z" },
    };

    const merged = mergeProbeSnapshotSafe(prev, failedUploadPartial);
    assert.equal(merged.ok, true);
    assert.equal(merged.latency_ms, 68);
    assert.equal(merged.up_mbps, null);
    assert.equal(merged.per_probe_up_mbps.builtin_upload, undefined);
    assert.equal(merged.down_mbps, 185.2);
    assert.equal(merged.per_probe_ok?.builtin_upload, false);
    assert.equal(merged.per_probe_tested_at?.builtin_upload, "2026-11-27T05:30:00Z");
  });

  it("clears stale custom upload speed on partial retest failure and clears failed unlock badge", () => {
    const prev = makeSnap({
      up_mbps: 31.2,
      per_probe_ok: {
        builtin_latency: true,
        custom_up: true,
        builtin_unlock_windsurf: true,
      },
      per_probe_up_mbps: { custom_up: 31.2 },
      unlocked_sites: { windsurf: true, chatgpt: true },
    });
    const partialFail: ProbeSnapshot = {
      node_id: "node-jp-01",
      tested_at: "2026-11-27T05:40:00Z",
      ok: false,
      latency_ms: null,
      jitter_ms: null,
      loss_pct: null,
      up_mbps: null,
      down_mbps: null,
      cf_loc: null,
      yt_gl: null,
      google_clean: null,
      google_risk_mismatch: false,
      keepalive_60s_ok: null,
      unlocked_sites: {},
      per_probe_ok: {
        custom_up: false,
        builtin_unlock_windsurf: false,
      },
      per_probe_up_mbps: {},
      per_probe_down_mbps: {},
      per_probe_ping_ms: {},
      per_probe_tested_at: {
        custom_up: "2026-11-27T05:40:00Z",
        builtin_unlock_windsurf: "2026-11-27T05:40:01Z",
      },
    };

    const merged = mergeProbeSnapshotSafe(prev, partialFail);
    assert.equal(merged.latency_ms, 68);
    assert.equal(merged.ok, true);
    assert.equal(merged.up_mbps, null);
    assert.equal(merged.per_probe_up_mbps.custom_up, undefined);
    assert.equal(merged.unlocked_sites.windsurf, false);
    assert.equal(merged.unlocked_sites.chatgpt, true);
  });

  it("merges per_probe_tested_at keeping newer timestamps and prevents google_cn from clobbering dedicated gemini unlock", () => {
    const prev = makeSnap({
      unlocked_sites: { gemini: false, gemini_aistudio: true },
      per_probe_ok: {
        builtin_latency: true,
        builtin_unlock_gemini: false,
      },
      per_probe_tested_at: {
        builtin_latency: "2026-11-27T06:00:00Z",
        builtin_unlock_gemini: "2026-11-27T06:00:02Z",
      },
    });
    const partialGoogleCn: ProbeSnapshot = {
      node_id: "node-jp-01",
      tested_at: "2026-11-27T06:05:00Z",
      ok: true,
      latency_ms: null,
      jitter_ms: null,
      loss_pct: null,
      up_mbps: null,
      down_mbps: null,
      cf_loc: "NRT",
      yt_gl: "JP",
      google_clean: true,
      google_risk_mismatch: false,
      keepalive_60s_ok: null,
      unlocked_sites: { gemini: true, gemini_aistudio: true },
      per_probe_ok: { builtin_google_cn: true },
      per_probe_up_mbps: {},
      per_probe_down_mbps: {},
      per_probe_ping_ms: {},
      per_probe_tested_at: {
        builtin_latency: "2026-11-27T03:00:00Z", // stale timestamp must NOT overwrite newer
        builtin_google_cn: "2026-11-27T06:05:00Z",
      },
    };

    const merged = mergeProbeSnapshotSafe(prev, partialGoogleCn);
    assert.equal(merged.unlocked_sites.gemini, false);
    assert.equal(merged.unlocked_sites.gemini_aistudio, true);
    assert.equal(merged.per_probe_tested_at?.builtin_latency, "2026-11-27T06:00:00Z");
    assert.equal(merged.per_probe_tested_at?.builtin_google_cn, "2026-11-27T06:05:00Z");
  });

  it("does not clobber healthy latency_ms/ok when an unknown custom non-latency probe (e.g. my_netflix) fails", () => {
    const prev = makeSnap({
      ok: true,
      latency_ms: 55,
      jitter_ms: 2.1,
      loss_pct: 0,
      per_probe_ok: { builtin_latency: true },
      per_probe_ping_ms: { builtin_latency: 55 },
    });
    const customNonLatencyFail: ProbeSnapshot = {
      node_id: "node-jp-01",
      tested_at: "2026-11-27T06:10:00Z",
      ok: false,
      latency_ms: null,
      jitter_ms: null,
      loss_pct: null,
      up_mbps: null,
      down_mbps: null,
      cf_loc: null,
      yt_gl: null,
      google_clean: null,
      google_risk_mismatch: false,
      keepalive_60s_ok: null,
      unlocked_sites: {},
      per_probe_ok: { my_netflix: false, ai_cursor: false },
      per_probe_up_mbps: {},
      per_probe_down_mbps: {},
      per_probe_ping_ms: {},
      per_probe_detail: { my_netflix: "regex_mismatch" },
      per_probe_tested_at: { my_netflix: "2026-11-27T06:10:00Z" },
    };

    const merged = mergeProbeSnapshotSafe(prev, customNonLatencyFail);
    assert.equal(merged.ok, true);
    assert.equal(merged.latency_ms, 55);
    assert.equal(merged.jitter_ms, 2.1);
    assert.equal(merged.loss_pct, 0);
    assert.equal(merged.per_probe_ok?.my_netflix, false);
    assert.equal(merged.per_probe_ok?.ai_cursor, false);
    assert.equal(merged.per_probe_ok?.builtin_latency, true);
  });

  it("honors explicit latencyProbeIds for custom-named latency probes and authoritative full DB snapshots with deleted probes", () => {
    const prev = makeSnap({
      ok: true,
      latency_ms: 60,
      up_mbps: 22.0,
      per_probe_ok: {
        builtin_latency: true,
        builtin_upload: true,
        deleted_old_probe: true,
      },
      per_probe_up_mbps: { builtin_upload: 22.0 },
    });

    // 1. Explicitly declared custom latency probe `my_edge_rtt` failing updates latency & ok
    const customLatencyFail: ProbeSnapshot = {
      node_id: "node-jp-01",
      tested_at: "2026-11-27T06:15:00Z",
      ok: false,
      latency_ms: null,
      jitter_ms: null,
      loss_pct: 100,
      up_mbps: null,
      down_mbps: null,
      cf_loc: null,
      yt_gl: null,
      google_clean: null,
      google_risk_mismatch: false,
      keepalive_60s_ok: null,
      unlocked_sites: {},
      per_probe_ok: { my_edge_rtt: false },
      per_probe_up_mbps: {},
      per_probe_down_mbps: {},
      per_probe_ping_ms: {},
      per_probe_tested_at: { my_edge_rtt: "2026-11-27T06:15:00Z" },
    };
    const mergedCustomLat = mergeProbeSnapshotSafe(prev, customLatencyFail, {
      latencyProbeIds: new Set(["builtin_latency", "my_edge_rtt"]),
    });
    assert.equal(mergedCustomLat.ok, false);
    assert.equal(mergedCustomLat.latency_ms, null);
    assert.equal(mergedCustomLat.loss_pct, 100);

    // 2. Authoritative full DB snapshot without `deleted_old_probe` drops deleted key & clears failed upload
    const authoritativeDbSnap = makeSnap({
      tested_at: "2026-11-27T06:20:00Z",
      ok: true,
      latency_ms: 62,
      up_mbps: null,
      per_probe_ok: {
        builtin_latency: true,
        builtin_upload: false,
      },
      per_probe_up_mbps: {},
    });
    const mergedAuth = mergeProbeSnapshotSafe(prev, authoritativeDbSnap, {
      authoritative: true,
    });
    assert.equal(mergedAuth.up_mbps, null);
    assert.equal(mergedAuth.latency_ms, 62);
    assert.equal(mergedAuth.per_probe_ok?.deleted_old_probe, undefined);
    assert.equal(mergedAuth.per_probe_ok?.builtin_upload, false);
  });

  it("preserves ip_clean/ip_risk_level/ip_asn/ip_risk_flags during partial L0 latency retests", () => {
    const prev = makeSnap({
      ip_clean: false,
      ip_risk_level: "proxy_risk",
      ip_asn: "AS38136 Akari Networks",
      ip_risk_flags: "proxy,datacenter",
      unlocked_sites: { windsurf: false },
      per_probe_ok: { builtin_latency: true, builtin_unlock_windsurf: false },
      per_probe_detail: {
        builtin_unlock_windsurf: "semantic_windsurf: unlocked=false, ip_risk=proxy_risk",
      },
    });
    const latencyOnlyPartial: ProbeSnapshot = {
      node_id: "node-jp-01",
      tested_at: "2026-11-28T07:00:00Z",
      ok: true,
      latency_ms: 52,
      jitter_ms: 1.5,
      loss_pct: 0,
      up_mbps: null,
      down_mbps: null,
      cf_loc: null,
      yt_gl: null,
      google_clean: null,
      google_risk_mismatch: false,
      keepalive_60s_ok: null,
      ip_clean: null,
      ip_risk_level: null,
      ip_asn: null,
      ip_risk_flags: null,
      unlocked_sites: {},
      per_probe_ok: { builtin_latency: true },
      per_probe_up_mbps: {},
      per_probe_down_mbps: {},
      per_probe_ping_ms: { builtin_latency: 52 },
      per_probe_detail: { builtin_latency: "latency_ms=52" },
      per_probe_tested_at: { builtin_latency: "2026-11-28T07:00:00Z" },
    };

    const merged = mergeProbeSnapshotSafe(prev, latencyOnlyPartial);
    assert.equal(merged.latency_ms, 52);
    assert.equal(merged.ip_clean, false);
    assert.equal(merged.ip_risk_level, "proxy_risk");
    assert.equal(merged.ip_asn, "AS38136 Akari Networks");
    assert.equal(merged.ip_risk_flags, "proxy,datacenter");
  });
});
