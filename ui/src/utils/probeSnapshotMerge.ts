import type { ProbeSnapshot } from "../api/tauri";

const BUILTIN_LATENCY_ID = "builtin_latency";
const BUILTIN_UPLOAD_ID = "builtin_upload";
const BUILTIN_DOWNLOAD_ID = "builtin_download";
const BUILTIN_GOOGLE_CN_ID = "builtin_google_cn";
const BUILTIN_KEEPALIVE_ID = "builtin_keepalive_60s";
const BUILTIN_UNLOCK_PREFIX = "builtin_unlock_";

const UNLOCK_PROBE_SITE_MAP: Record<string, string> = {
  builtin_unlock_windsurf: "windsurf",
  builtin_unlock_claude: "claude",
  builtin_unlock_chatgpt: "chatgpt",
  builtin_unlock_gemini: "gemini",
};

function isValidPositive(val: number | null | undefined): val is number {
  return typeof val === "number" && Number.isFinite(val) && val > 0;
}

function compareIsoTimestamps(a: string, b: string): number {
  const ta = Date.parse(a);
  const tb = Date.parse(b);
  if (Number.isFinite(ta) && Number.isFinite(tb)) {
    return ta - tb;
  }
  return a.localeCompare(b);
}

function pickNewerIso(prevTs: string, incomingTs: string): string {
  const p = prevTs?.trim() ?? "";
  const inc = incomingTs?.trim() ?? "";
  if (!p) return inc;
  if (!inc) return p;
  return compareIsoTimestamps(inc, p) >= 0 ? inc : p;
}

function isUploadProbeId(
  id: string,
  prev: ProbeSnapshot,
  incoming: ProbeSnapshot
): boolean {
  if (id === BUILTIN_UPLOAD_ID) return true;
  if (
    prev.per_probe_up_mbps?.[id] !== undefined ||
    incoming.per_probe_up_mbps?.[id] !== undefined
  ) {
    return true;
  }
  const lower = id.toLowerCase();
  return lower.includes("upload") || lower.endsWith("_up");
}

function isDownloadProbeId(
  id: string,
  prev: ProbeSnapshot,
  incoming: ProbeSnapshot
): boolean {
  if (id === BUILTIN_DOWNLOAD_ID) return true;
  if (
    prev.per_probe_down_mbps?.[id] !== undefined ||
    incoming.per_probe_down_mbps?.[id] !== undefined
  ) {
    return true;
  }
  const lower = id.toLowerCase();
  return lower.includes("download") || lower.endsWith("_down");
}

export interface MergeProbeSnapshotOptions {
  /**
   * When true, `incoming` is an authoritative full aggregated snapshot read back
   * directly from SQLite (e.g. `EVENT_PROBE_PROGRESS.snapshot`). Deleted probe IDs
   * lingering in memory are dropped cleanly and cleared metrics are never resurrected.
   */
  authoritative?: boolean;
  /**
   * Optional explicit set of probe IDs whose `ProbeKind` is `"latency"`.
   * Unknown custom probe IDs outside this set (and without `latency`/`ping` roots)
   * default to non-latency probes so custom unlock/script failures never clobber
   * healthy `latency_ms` and `ok`.
   */
  latencyProbeIds?: ReadonlySet<string>;
}

function isLatencyProbeId(
  id: string,
  options?: MergeProbeSnapshotOptions
): boolean {
  if (id === BUILTIN_LATENCY_ID) return true;
  if (options?.latencyProbeIds?.has(id)) return true;
  if (
    id === BUILTIN_UPLOAD_ID ||
    id === BUILTIN_DOWNLOAD_ID ||
    id === BUILTIN_GOOGLE_CN_ID ||
    id === BUILTIN_KEEPALIVE_ID ||
    id.startsWith(BUILTIN_UNLOCK_PREFIX)
  ) {
    return false;
  }
  const lower = id.toLowerCase();
  return lower.includes("latency") || lower.includes("ping");
}

function pickLatestSuccessfulRate(
  rateMap: Record<string, number>,
  okMap: Record<string, boolean>,
  testedAtMap: Record<string, string>,
  preferredBuiltinId: string
): number | null {
  let bestVal: number | null = null;
  let bestTs = "";

  for (const [pid, val] of Object.entries(rateMap)) {
    if (!isValidPositive(val)) continue;
    if (okMap[pid] === false) continue;
    const ts = testedAtMap[pid] ?? "";
    if (bestVal === null) {
      bestVal = val;
      bestTs = ts;
      continue;
    }
    if (ts && bestTs) {
      const cmp = compareIsoTimestamps(ts, bestTs);
      if (cmp > 0 || (cmp === 0 && pid === preferredBuiltinId)) {
        bestVal = val;
        bestTs = ts;
      }
    } else if (ts && !bestTs) {
      bestVal = val;
      bestTs = ts;
    } else if (!ts && !bestTs && pid === preferredBuiltinId) {
      bestVal = val;
    }
  }

  return bestVal;
}

/**
 * Safely merge an incoming `ProbeSnapshot` onto a previous cached snapshot while
 * staying 100% consistent with cold SQLite re-reads:
 *
 * - Full DB aggregated snapshots (whose `per_probe_ok` covers all previously known
 *   probe IDs) act as the authoritative source of truth so cleared/failed metrics
 *   never resurrect stale values.
 * - Partial single-tier / single-probe snapshots preserve historical fields for
 *   probe categories that did NOT run (including `latency_ms`/`jitter_ms`/`loss_pct`
 *   when latency probes did not run), while strictly clearing stale speeds/green
 *   badges whenever a probe ran in `incoming` with `per_probe_ok[id] === false`.
 * - Merges `per_probe_tested_at` per probe ID keeping the newest timestamp.
 */
export function mergeProbeSnapshotSafe(
  prev: ProbeSnapshot | undefined,
  incoming: ProbeSnapshot,
  options?: MergeProbeSnapshotOptions
): ProbeSnapshot {
  if (options?.authoritative === true) {
    const incomingOkMap: Record<string, boolean> = { ...(incoming.per_probe_ok ?? {}) };
    const nextUpMap: Record<string, number> = {};
    for (const [pid, val] of Object.entries(incoming.per_probe_up_mbps ?? {})) {
      if (isValidPositive(val) && incomingOkMap[pid] !== false) {
        nextUpMap[pid] = val;
      }
    }
    const nextDownMap: Record<string, number> = {};
    for (const [pid, val] of Object.entries(incoming.per_probe_down_mbps ?? {})) {
      if (isValidPositive(val) && incomingOkMap[pid] !== false) {
        nextDownMap[pid] = val;
      }
    }
    const nextPingMap: Record<string, number> = {};
    for (const [pid, val] of Object.entries(incoming.per_probe_ping_ms ?? {})) {
      if (isValidPositive(val) && incomingOkMap[pid] !== false) {
        nextPingMap[pid] = val;
      }
    }
    return {
      ...incoming,
      latency_ms:
        incoming.ok && isValidPositive(incoming.latency_ms)
          ? incoming.latency_ms
          : null,
      jitter_ms: incoming.ok ? incoming.jitter_ms : null,
      up_mbps: isValidPositive(incoming.up_mbps) ? incoming.up_mbps : null,
      down_mbps: isValidPositive(incoming.down_mbps) ? incoming.down_mbps : null,
      unlocked_sites: { ...(incoming.unlocked_sites ?? {}) },
      per_probe_ok: incomingOkMap,
      per_probe_up_mbps: nextUpMap,
      per_probe_down_mbps: nextDownMap,
      per_probe_ping_ms: nextPingMap,
      per_probe_detail: { ...(incoming.per_probe_detail ?? {}) },
      per_probe_tested_at: { ...(incoming.per_probe_tested_at ?? {}) },
    };
  }

  if (!prev) {
    return {
      ...incoming,
      unlocked_sites: { ...(incoming.unlocked_sites ?? {}) },
      per_probe_ok: { ...(incoming.per_probe_ok ?? {}) },
      per_probe_up_mbps: { ...(incoming.per_probe_up_mbps ?? {}) },
      per_probe_down_mbps: { ...(incoming.per_probe_down_mbps ?? {}) },
      per_probe_ping_ms: { ...(incoming.per_probe_ping_ms ?? {}) },
      per_probe_detail: { ...(incoming.per_probe_detail ?? {}) },
      per_probe_tested_at: { ...(incoming.per_probe_tested_at ?? {}) },
    };
  }

  const prevOkMap = prev.per_probe_ok ?? {};
  const incomingOkMap = incoming.per_probe_ok ?? {};
  const prevProbeIds = Object.keys(prevOkMap);
  const incomingProbeIds = Object.keys(incomingOkMap);

  const isFullDbSnapshot =
    prevProbeIds.length > 0 &&
    prevProbeIds.every((pid) => Object.prototype.hasOwnProperty.call(incomingOkMap, pid));

  const incomingRanLatency =
    incomingProbeIds.some((pid) => isLatencyProbeId(pid, options)) ||
    (incomingProbeIds.length === 0 &&
      (isValidPositive(incoming.latency_ms) ||
        incoming.jitter_ms !== null ||
        incoming.loss_pct !== null ||
        incoming.ok === false));

  const incomingTouchedUpload =
    incomingProbeIds.some((pid) => isUploadProbeId(pid, prev, incoming)) ||
    isValidPositive(incoming.up_mbps);

  const incomingTouchedDownload =
    incomingProbeIds.some((pid) => isDownloadProbeId(pid, prev, incoming)) ||
    isValidPositive(incoming.down_mbps);

  const incomingTouchedGoogleCn = Object.prototype.hasOwnProperty.call(
    incomingOkMap,
    BUILTIN_GOOGLE_CN_ID
  );

  const incomingTouchedKeepalive = Object.prototype.hasOwnProperty.call(
    incomingOkMap,
    BUILTIN_KEEPALIVE_ID
  );

  // 1. Merge per-probe maps & purge stale values for probes that explicitly failed.
  const mergedPerProbeOk: Record<string, boolean> = {
    ...prevOkMap,
    ...incomingOkMap,
  };

  const mergedPerProbeUp: Record<string, number> = {
    ...(prev.per_probe_up_mbps ?? {}),
  };
  for (const [pid, val] of Object.entries(incoming.per_probe_up_mbps ?? {})) {
    if (isValidPositive(val) && incomingOkMap[pid] !== false) {
      mergedPerProbeUp[pid] = val;
    }
  }

  const mergedPerProbeDown: Record<string, number> = {
    ...(prev.per_probe_down_mbps ?? {}),
  };
  for (const [pid, val] of Object.entries(incoming.per_probe_down_mbps ?? {})) {
    if (isValidPositive(val) && incomingOkMap[pid] !== false) {
      mergedPerProbeDown[pid] = val;
    }
  }

  const mergedPerProbePing: Record<string, number> = {
    ...(prev.per_probe_ping_ms ?? {}),
  };
  for (const [pid, val] of Object.entries(incoming.per_probe_ping_ms ?? {})) {
    if (isValidPositive(val) && incomingOkMap[pid] !== false) {
      mergedPerProbePing[pid] = val;
    }
  }

  const mergedPerProbeDetail: Record<string, string> = {
    ...(prev.per_probe_detail ?? {}),
  };
  for (const [pid, detail] of Object.entries(incoming.per_probe_detail ?? {})) {
    mergedPerProbeDetail[pid] = detail;
  }

  for (const [pid, ok] of Object.entries(incomingOkMap)) {
    if (ok === false) {
      delete mergedPerProbeUp[pid];
      delete mergedPerProbeDown[pid];
      delete mergedPerProbePing[pid];
    } else if (
      ok === true &&
      !Object.prototype.hasOwnProperty.call(incoming.per_probe_detail ?? {}, pid)
    ) {
      delete mergedPerProbeDetail[pid];
    }
  }

  // When a full DB snapshot explicitly dropped a per-probe speed entry, honor that removal.
  if (isFullDbSnapshot) {
    for (const pid of Object.keys(mergedPerProbeUp)) {
      if (
        Object.prototype.hasOwnProperty.call(incomingOkMap, pid) &&
        !isValidPositive(incoming.per_probe_up_mbps?.[pid])
      ) {
        delete mergedPerProbeUp[pid];
      }
    }
    for (const pid of Object.keys(mergedPerProbeDown)) {
      if (
        Object.prototype.hasOwnProperty.call(incomingOkMap, pid) &&
        !isValidPositive(incoming.per_probe_down_mbps?.[pid])
      ) {
        delete mergedPerProbeDown[pid];
      }
    }
  }

  // 2. Merge per_probe_tested_at keeping newest timestamp per probe.
  const mergedPerProbeTestedAt: Record<string, string> = {
    ...(prev.per_probe_tested_at ?? {}),
  };
  for (const [pid, ts] of Object.entries(incoming.per_probe_tested_at ?? {})) {
    if (typeof ts === "string" && ts.trim().length > 0) {
      const prevTs = mergedPerProbeTestedAt[pid];
      if (!prevTs || compareIsoTimestamps(ts, prevTs) >= 0) {
        mergedPerProbeTestedAt[pid] = ts;
      }
    }
  }

  // 3. Resolve top-level latency / ok fields.
  const prevHasLatencyState =
    prevProbeIds.some((pid) => isLatencyProbeId(pid, options)) ||
    isValidPositive(prev.latency_ms);

  let nextOk: boolean;
  let nextLatencyMs: number | null;
  let nextJitterMs: number | null;
  let nextLossPct: number | null;

  if (incomingRanLatency) {
    nextOk = incoming.ok;
    nextLatencyMs = incoming.ok && isValidPositive(incoming.latency_ms)
      ? incoming.latency_ms
      : null;
    nextJitterMs = incoming.ok ? incoming.jitter_ms : null;
    nextLossPct = incoming.loss_pct;
  } else if (isFullDbSnapshot) {
    nextOk = incoming.ok;
    nextLatencyMs = incoming.latency_ms;
    nextJitterMs = incoming.jitter_ms;
    nextLossPct = incoming.loss_pct;
  } else if (prevHasLatencyState) {
    // Partial non-latency probe (e.g. upload/download/unlock only): preserve prior latency state.
    nextOk = prev.ok;
    nextLatencyMs = prev.latency_ms;
    nextJitterMs = prev.jitter_ms;
    nextLossPct = prev.loss_pct;
  } else {
    // Neither prev nor incoming has a latency probe yet: mirror backend any_ok fallback.
    nextOk = Boolean(prev.ok || incoming.ok);
    nextLatencyMs = prev.latency_ms;
    nextJitterMs = prev.jitter_ms;
    nextLossPct = prev.loss_pct;
  }

  // 4. Resolve top-level upload/download throughput without resurrecting failed stale speeds.
  let nextUpMbps: number | null;
  if (isFullDbSnapshot) {
    nextUpMbps = isValidPositive(incoming.up_mbps) ? incoming.up_mbps : null;
  } else if (incomingTouchedUpload) {
    if (isValidPositive(incoming.up_mbps)) {
      const anyIncomingUploadOk = incomingProbeIds.some(
        (pid) => isUploadProbeId(pid, prev, incoming) && incomingOkMap[pid] === true
      );
      const allIncomingUploadsFailed =
        incomingProbeIds.some((pid) => isUploadProbeId(pid, prev, incoming)) &&
        !anyIncomingUploadOk;
      nextUpMbps = allIncomingUploadsFailed
        ? pickLatestSuccessfulRate(
            mergedPerProbeUp,
            mergedPerProbeOk,
            mergedPerProbeTestedAt,
            BUILTIN_UPLOAD_ID
          )
        : incoming.up_mbps;
    } else {
      nextUpMbps = pickLatestSuccessfulRate(
        mergedPerProbeUp,
        mergedPerProbeOk,
        mergedPerProbeTestedAt,
        BUILTIN_UPLOAD_ID
      );
    }
  } else {
    nextUpMbps = prev.up_mbps;
  }

  let nextDownMbps: number | null;
  if (isFullDbSnapshot) {
    nextDownMbps = isValidPositive(incoming.down_mbps) ? incoming.down_mbps : null;
  } else if (incomingTouchedDownload) {
    if (isValidPositive(incoming.down_mbps)) {
      const anyIncomingDownloadOk = incomingProbeIds.some(
        (pid) => isDownloadProbeId(pid, prev, incoming) && incomingOkMap[pid] === true
      );
      const allIncomingDownloadsFailed =
        incomingProbeIds.some((pid) => isDownloadProbeId(pid, prev, incoming)) &&
        !anyIncomingDownloadOk;
      nextDownMbps = allIncomingDownloadsFailed
        ? pickLatestSuccessfulRate(
            mergedPerProbeDown,
            mergedPerProbeOk,
            mergedPerProbeTestedAt,
            BUILTIN_DOWNLOAD_ID
          )
        : incoming.down_mbps;
    } else {
      nextDownMbps = pickLatestSuccessfulRate(
        mergedPerProbeDown,
        mergedPerProbeOk,
        mergedPerProbeTestedAt,
        BUILTIN_DOWNLOAD_ID
      );
    }
  } else {
    nextDownMbps = prev.down_mbps;
  }

  // 5. Resolve Google cleanliness / region & keepalive fields.
  let nextCfLoc: string | null;
  let nextYtGl: string | null;
  let nextGoogleClean: boolean | null;
  let nextGoogleRiskMismatch: boolean;

  if (isFullDbSnapshot || incomingTouchedGoogleCn) {
    const googleCnFailedWithNull =
      incomingTouchedGoogleCn &&
      incomingOkMap[BUILTIN_GOOGLE_CN_ID] === false &&
      incoming.google_clean === null;
    nextCfLoc = googleCnFailedWithNull ? null : (incoming.cf_loc ?? null);
    nextYtGl = googleCnFailedWithNull ? null : (incoming.yt_gl ?? null);
    nextGoogleClean = googleCnFailedWithNull ? null : (incoming.google_clean ?? null);
    nextGoogleRiskMismatch = googleCnFailedWithNull
      ? false
      : incoming.google_clean !== null && incoming.google_clean !== undefined
        ? incoming.google_risk_mismatch
        : false;
  } else {
    nextCfLoc = incoming.cf_loc ?? prev.cf_loc;
    nextYtGl = incoming.yt_gl ?? prev.yt_gl;
    nextGoogleClean = incoming.google_clean ?? prev.google_clean;
    nextGoogleRiskMismatch =
      incoming.google_clean !== null && incoming.google_clean !== undefined
        ? incoming.google_risk_mismatch
        : prev.google_risk_mismatch;
  }

  let nextKeepalive60sOk: boolean | null;
  if (isFullDbSnapshot || incomingTouchedKeepalive) {
    if (incomingTouchedKeepalive && incomingOkMap[BUILTIN_KEEPALIVE_ID] === false) {
      nextKeepalive60sOk =
        incoming.keepalive_60s_ok === false ? false : null;
    } else {
      nextKeepalive60sOk = incoming.keepalive_60s_ok ?? null;
    }
  } else {
    nextKeepalive60sOk = incoming.keepalive_60s_ok ?? prev.keepalive_60s_ok;
  }

  // 6. Merge unlocked_sites (protecting builtin_unlock_gemini precedence over builtin_google_cn).
  let mergedUnlocked: Record<string, boolean>;
  if (isFullDbSnapshot) {
    mergedUnlocked = { ...(incoming.unlocked_sites ?? {}) };
  } else {
    mergedUnlocked = { ...(prev.unlocked_sites ?? {}) };
    const prevHasDedicatedGemini = Object.prototype.hasOwnProperty.call(
      prevOkMap,
      "builtin_unlock_gemini"
    );
    const incomingHasDedicatedGemini = Object.prototype.hasOwnProperty.call(
      incomingOkMap,
      "builtin_unlock_gemini"
    );
    for (const [site, unlocked] of Object.entries(incoming.unlocked_sites ?? {})) {
      if (
        site === "gemini" &&
        prevHasDedicatedGemini &&
        !incomingHasDedicatedGemini &&
        incomingTouchedGoogleCn
      ) {
        continue;
      }
      mergedUnlocked[site] = unlocked;
    }
    for (const [probeId, siteKey] of Object.entries(UNLOCK_PROBE_SITE_MAP)) {
      if (
        incomingOkMap[probeId] === false &&
        !Object.prototype.hasOwnProperty.call(incoming.unlocked_sites ?? {}, siteKey)
      ) {
        mergedUnlocked[siteKey] = false;
      }
    }
  }

  return {
    ...prev,
    ...incoming,
    tested_at: pickNewerIso(prev.tested_at, incoming.tested_at),
    ok: nextOk,
    latency_ms: nextLatencyMs,
    jitter_ms: nextJitterMs,
    loss_pct: nextLossPct,
    up_mbps: nextUpMbps,
    down_mbps: nextDownMbps,
    cf_loc: nextCfLoc,
    yt_gl: nextYtGl,
    google_clean: nextGoogleClean,
    google_risk_mismatch: nextGoogleRiskMismatch,
    keepalive_60s_ok: nextKeepalive60sOk,
    unlocked_sites: mergedUnlocked,
    per_probe_ok: mergedPerProbeOk,
    per_probe_up_mbps: mergedPerProbeUp,
    per_probe_down_mbps: mergedPerProbeDown,
    per_probe_ping_ms: mergedPerProbePing,
    per_probe_detail: mergedPerProbeDetail,
    per_probe_tested_at: mergedPerProbeTestedAt,
  };
}
