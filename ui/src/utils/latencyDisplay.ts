import type { NodeHealthHint, ProbeSnapshot } from "../api/tauri";

export type LatencySourceKind = "probe" | "health" | "none";
export type LatencyHealthState =
  | "healthy"
  | "probation"
  | "degraded"
  | "failed"
  | "untested";

export interface ResolvedNodeLatency {
  latencyMs: number | null;
  ok: boolean;
  source: LatencySourceKind;
  state: LatencyHealthState;
  isProbation: boolean;
  isDegraded: boolean;
}

export const MISSING_LATENCY_PENALTY_MS = 9999;

function isValidPositiveLatency(ms: number | null | undefined): ms is number {
  return typeof ms === "number" && Number.isFinite(ms) && ms > 0;
}

function isValidPositiveRate(mbps: number | null | undefined): mbps is number {
  return typeof mbps === "number" && Number.isFinite(mbps) && mbps > 0;
}

function parseTsMs(raw: string | null | undefined): number | null {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;
  const ms = Date.parse(trimmed);
  return Number.isFinite(ms) && ms > 0 ? ms : null;
}

function parseHintTsMs(hint?: NodeHealthHint | null): number | null {
  const raw = hint?.probed_at_ms;
  return typeof raw === "number" && Number.isFinite(raw) && raw > 0 ? raw : null;
}

/**
 * Single authoritative latency resolver shared across Home, MultiGroup,
 * SpeedTest, NodesSubs, and Capsule views.
 *
 * Precedence & timestamp-aware anti-regression invariants:
 * 1. Compare `healthHint.probed_at_ms` against the latency probe timestamp
 *    (`snap.per_probe_tested_at?.builtin_latency || snap.tested_at`).
 * 2. When background watchdog health probing is strictly newer (`hintTs > snapLatTs`,
 *    or `snap` has no timestamp), the live watchdog outcome governs:
 *    - `healthy` / `probation` / `degraded` with positive RTT clears stale historical
 *      manual probe failures and reports `source: "health"`;
 *    - `cooldown` marks the node failed with `source: "health"`.
 * 3. Otherwise (manual warm 204 probe is newer/equal, or `healthHint` lacks a newer
 *    timestamp):
 *    - Explicit probe failure (`snap.ok === false`, or failed `builtin_latency` with
 *      no positive RTT) strictly wins as `failed` (`source: "probe"`), never masked by
 *      a stale green health hint;
 *    - Active runtime `cooldown` without a strictly newer passing probe marks `failed`;
 *    - Passing standard 204 warm probe returns `source: "probe"` (preserving any
 *      `degraded`/`probation` runtime state flag without mislabeling warm tests as
 *      `"health"`);
 *    - When `snap` has no valid positive latency, fall back to a valid runtime
 *      `healthHint` (`source: "health"`).
 */
export function resolveNodeDisplayLatency(
  snap?: ProbeSnapshot | null,
  healthHint?: NodeHealthHint | null
): ResolvedNodeLatency {
  const snapLatencyMs = isValidPositiveLatency(snap?.latency_ms)
    ? snap.latency_ms
    : null;
  const snapLatTs =
    parseTsMs(snap?.per_probe_tested_at?.builtin_latency) ??
    parseTsMs(snap?.tested_at);

  const hasExplicitProbeFail = Boolean(
    snap &&
      (snap.ok === false ||
        (snap.per_probe_ok?.builtin_latency === false && snapLatencyMs === null))
  );
  const hasValidWarmProbe = Boolean(
    snap && snap.ok === true && snapLatencyMs !== null
  );

  const hintStatus = healthHint?.status;
  const hintLatencyMs = isValidPositiveLatency(healthHint?.latency_ms)
    ? healthHint.latency_ms
    : null;
  const hintTs = parseHintTsMs(healthHint);

  const isProbation = hintStatus === "probation";
  const isDegraded = hintStatus === "degraded";
  const isRuntimeHealthState =
    hintStatus === "healthy" || isProbation || isDegraded;

  const healthIsNewer =
    hintTs !== null && (snapLatTs === null || hintTs > snapLatTs);
  const snapIsStrictlyNewer =
    snapLatTs !== null && hintTs !== null && snapLatTs > hintTs;

  // 1. Background watchdog probe is strictly newer than the latest manual latency test:
  //    allow it to lift stale historical probe failures or flag fresh runtime cooldown.
  if (healthIsNewer) {
    if (hintStatus === "cooldown") {
      return {
        latencyMs: null,
        ok: false,
        source: "health",
        state: "failed",
        isProbation: false,
        isDegraded: false,
      };
    }

    if (isRuntimeHealthState && hintLatencyMs !== null) {
      return {
        latencyMs: hintLatencyMs,
        ok: true,
        source: "health",
        state: hintStatus,
        isProbation,
        isDegraded,
      };
    }

    if (isDegraded || isProbation) {
      if (hasValidWarmProbe && snapLatencyMs !== null) {
        return {
          latencyMs: snapLatencyMs,
          ok: true,
          source: "probe",
          state: isDegraded ? "degraded" : "probation",
          isProbation,
          isDegraded,
        };
      }
      return {
        latencyMs: null,
        ok: false,
        source: "health",
        state: isDegraded ? "degraded" : "probation",
        isProbation,
        isDegraded,
      };
    }
  }

  // 2. Manual probe is newer/equal (or healthHint has no newer timestamp):
  //    explicit probe failure must NEVER be masked by a stale green health hint.
  if (hasExplicitProbeFail) {
    return {
      latencyMs: null,
      ok: false,
      source: "probe",
      state: "failed",
      isProbation: false,
      isDegraded: false,
    };
  }

  // 3. Active runtime cooldown wins unless a strictly newer manual warm probe succeeded.
  if (hintStatus === "cooldown" && !(hasValidWarmProbe && snapIsStrictlyNewer)) {
    return {
      latencyMs: null,
      ok: false,
      source: "health",
      state: "failed",
      isProbation: false,
      isDegraded: false,
    };
  }

  // 4. Passing manual standard 204 warm probe takes precedence when healthHint is NOT newer.
  //    Pass through degraded/probation flags without mislabeling warm tests as "health".
  if (hasValidWarmProbe && snapLatencyMs !== null) {
    return {
      latencyMs: snapLatencyMs,
      ok: true,
      source: "probe",
      state: isDegraded ? "degraded" : isProbation ? "probation" : "healthy",
      isProbation,
      isDegraded,
    };
  }

  // 5. Fallback to runtime background dual-source health probe when snap has no valid latency.
  if (isRuntimeHealthState && hintLatencyMs !== null) {
    return {
      latencyMs: hintLatencyMs,
      ok: true,
      source: "health",
      state: hintStatus,
      isProbation,
      isDegraded,
    };
  }

  // 6. Runtime health hint carries a degraded/probation state without a numeric RTT.
  if (isDegraded || isProbation) {
    return {
      latencyMs: null,
      ok: false,
      source: "health",
      state: isDegraded ? "degraded" : "probation",
      isProbation,
      isDegraded,
    };
  }

  // 7. Untested / no latency data available.
  return {
    latencyMs: null,
    ok: false,
    source: "none",
    state: "untested",
    isProbation: false,
    isDegraded: false,
  };
}

/**
 * Returns true when `snap.up_mbps` carries a trustworthy positive upload speed.
 *
 * Compatible with custom upload / external_cmd speed probes: when `builtin_upload`
 * failed, a positive `up_mbps` is still accepted if another non-failed upload probe
 * recorded a positive rate in `per_probe_up_mbps`.
 */
export function hasValidUpMbps(snap?: ProbeSnapshot | null): boolean {
  if (!snap || !isValidPositiveRate(snap.up_mbps)) return false;
  if (snap.per_probe_ok?.builtin_upload !== false) return true;
  const perUp = snap.per_probe_up_mbps ?? {};
  for (const [pid, val] of Object.entries(perUp)) {
    if (pid === "builtin_upload") continue;
    if (isValidPositiveRate(val) && snap.per_probe_ok?.[pid] !== false) {
      return true;
    }
  }
  return false;
}

/**
 * Returns true when `snap.down_mbps` carries a trustworthy positive download speed.
 *
 * Compatible with custom download / external_cmd speed probes: when `builtin_download`
 * failed, a positive `down_mbps` is still accepted if another non-failed download probe
 * recorded a positive rate in `per_probe_down_mbps`.
 */
export function hasValidDownMbps(snap?: ProbeSnapshot | null): boolean {
  if (!snap || !isValidPositiveRate(snap.down_mbps)) return false;
  if (snap.per_probe_ok?.builtin_download !== false) return true;
  const perDown = snap.per_probe_down_mbps ?? {};
  for (const [pid, val] of Object.entries(perDown)) {
    if (pid === "builtin_download") continue;
    if (isValidPositiveRate(val) && snap.per_probe_ok?.[pid] !== false) {
      return true;
    }
  }
  return false;
}

export function getLatencyTooltipKey(
  resolved: ResolvedNodeLatency
): "probeHot" | "healthCold" | "failed" | "untested" {
  if (resolved.state === "failed") return "failed";
  if (resolved.state === "untested" || resolved.source === "none") {
    return "untested";
  }
  return resolved.source === "health" ? "healthCold" : "probeHot";
}
