import type {
  ProbeProgressEvent,
  ProbeRunSummary,
  ProbeSnapshot,
} from "../api/tauri";
import { mergeProbeSnapshotSafe } from "../utils/probeSnapshotMerge";
import type { StoreCore } from "./core";
import type { MascotState } from "./types";

export const PROBE_BATCH_WINDOW_MS = 100;

function hasProbeEventSummary(ev: ProbeProgressEvent): boolean {
  return (
    ev.latency_ok_count !== undefined ||
    ev.bandwidth_ok_count !== undefined ||
    ev.keepalive_ok_count !== undefined ||
    ev.failed_count !== undefined ||
    ev.exec_error_count !== undefined ||
    ev.untested_count !== undefined
  );
}

/**
 * 100ms batched probe-progress accumulator.
 * Accumulates every concurrently completed node snapshot in `pendingSnapshots`
 * via `mergeProbeSnapshotSafe` so concurrent finishes are never dropped,
 * flushes all accumulated snapshots together with `ev.done` in a single frame,
 * and cleans up its timer on dispose.
 */
export function createProbeProgressBatcher(core: StoreCore) {
  const pendingSnapshots = new Map<string, ProbeSnapshot>();
  let pendingLatestEvent: ProbeProgressEvent | null = null;
  let pendingSummaryEvent: ProbeProgressEvent | null = null;
  let batchTimer: number | null = null;

  function clearTimer(): void {
    if (batchTimer !== null && typeof window !== "undefined") {
      window.clearTimeout(batchTimer);
      batchTimer = null;
    }
  }

  function flush(): void {
    clearTimer();
    const ev = pendingLatestEvent;
    const summaryEv = pendingSummaryEvent;
    if (!ev && pendingSnapshots.size === 0) {
      return;
    }

    const snapshotBatch = Array.from(pendingSnapshots.entries());
    pendingSnapshots.clear();
    pendingLatestEvent = null;
    pendingSummaryEvent = null;

    const knownLatencyIds = core.getKnownLatencyProbeIds();
    const pendingQueue = core.getProbePendingQueue();
    const activeMascotCount = core.getActiveMascotTaskCount();

    core.setStateDeferredIfHidden((prev) => {
      let nextProbes = prev.probes;
      if (snapshotBatch.length > 0) {
        nextProbes = { ...prev.probes };
        for (const [nid, snap] of snapshotBatch) {
          nextProbes[nid] = mergeProbeSnapshotSafe(prev.probes[nid], snap, {
            authoritative: true,
            latencyProbeIds: knownLatencyIds,
          });
        }
      }

      if (!ev) {
        return nextProbes === prev.probes ? prev : { ...prev, probes: nextProbes };
      }

      let nextActiveNodeIds: string[];
      if (ev.done) {
        nextActiveNodeIds = [];
      } else if (pendingQueue.length > 0) {
        nextActiveNodeIds = pendingQueue.slice(0, 4);
      } else if (ev.node_id) {
        nextActiveNodeIds = ev.snapshot || ev.error ? [] : [ev.node_id];
      } else {
        nextActiveNodeIds = prev.bgTasks.probeActiveNodeIds;
      }

      const nextMascot: MascotState = ev.done
        ? activeMascotCount > 0
          ? prev.mascotState
          : ev.cancelled
            ? "idle"
            : "complete"
        : "searching";

      const summarySource = summaryEv ?? (hasProbeEventSummary(ev) ? ev : null);
      const nextLastProbeSummary: ProbeRunSummary | null = summarySource
        ? {
            latency_ok_count:
              summarySource.latency_ok_count ?? prev.lastProbeSummary?.latency_ok_count ?? 0,
            bandwidth_ok_count:
              summarySource.bandwidth_ok_count ?? prev.lastProbeSummary?.bandwidth_ok_count ?? 0,
            keepalive_ok_count:
              summarySource.keepalive_ok_count ?? prev.lastProbeSummary?.keepalive_ok_count ?? 0,
            failed_count:
              summarySource.failed_count ?? prev.lastProbeSummary?.failed_count ?? 0,
            exec_error_count:
              summarySource.exec_error_count ?? prev.lastProbeSummary?.exec_error_count ?? 0,
            untested_count:
              summarySource.untested_count ?? prev.lastProbeSummary?.untested_count ?? 0,
          }
        : prev.lastProbeSummary;

      return {
        ...prev,
        probes: nextProbes,
        mascotState: nextMascot,
        lastProbeSummary: nextLastProbeSummary,
        probeProgress: {
          running: !ev.done,
          completed: ev.completed,
          total: ev.total,
          currentNodeName: ev.done ? null : ev.node_name,
          cancelled: ev.cancelled,
        },
        bgTasks: {
          ...prev.bgTasks,
          probeLocalStarting: false,
          probeActiveNodeIds: nextActiveNodeIds,
          probeLockedOrderIds: ev.done ? [] : prev.bgTasks.probeLockedOrderIds,
          probeIsPausing: ev.done ? false : prev.bgTasks.probeIsPausing,
        },
      };
    });

    if (ev && ev.done && !ev.cancelled && core.getActiveMascotTaskCount() === 0) {
      core.celebrateMascotComplete(4000);
    }
  }

  function push(ev: ProbeProgressEvent): void {
    if (ev.done) {
      core.setProbePendingQueue([]);
    } else if (ev.node_id && (ev.snapshot || ev.error)) {
      core.removeFromProbePendingQueue(ev.node_id);
    }

    if (ev.node_id && ev.snapshot) {
      const mergedInWindow = mergeProbeSnapshotSafe(
        pendingSnapshots.get(ev.node_id),
        ev.snapshot,
        {
          authoritative: true,
          latencyProbeIds: core.getKnownLatencyProbeIds(),
        }
      );
      pendingSnapshots.set(ev.node_id, mergedInWindow);
    }

    pendingLatestEvent = ev;
    if (hasProbeEventSummary(ev)) {
      pendingSummaryEvent = ev;
    }

    if (ev.done) {
      // Flush all accumulated concurrent node snapshots together with `ev.done` in one frame.
      clearTimer();
      flush();
      return;
    }

    if (typeof window === "undefined") {
      flush();
      return;
    }

    if (batchTimer === null) {
      batchTimer = window.setTimeout(() => {
        batchTimer = null;
        flush();
      }, PROBE_BATCH_WINDOW_MS);
    }
  }

  function dispose(): void {
    clearTimer();
    pendingSnapshots.clear();
    pendingLatestEvent = null;
    pendingSummaryEvent = null;
  }

  return {
    push,
    flush,
    dispose,
  };
}
