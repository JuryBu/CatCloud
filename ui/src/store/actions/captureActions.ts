import {
  type LiveCaptureOutcomeDto,
  type LiveCaptureStartDto,
  type LiveCaptureStatusDto,
  catcloudApi,
  formatErrorMessage,
} from "../../api/tauri";
import type { StoreCore } from "../core";
import type { BgTasksState } from "../types";

const IDLE_CAPTURE_BG: BgTasksState["capture"] = {
  sessionId: null,
  active: false,
  timedOut: false,
  finishing: false,
  targetName: null,
  status: null,
  outcome: null,
};

export function createCaptureActions(core: StoreCore) {
  let liveCapturePollTimer: number | null = null;
  let liveCapturePollInFlight = false;
  let captureGen = 0;
  let activePollOnce: (() => void) | null = null;

  const resetCaptureBg = (patch?: Partial<BgTasksState["capture"]>) =>
    core.updateBgTasks((bg) => ({ ...bg, capture: { ...IDLE_CAPTURE_BG, ...patch } }));

  function stopLiveCapturePolling(): void {
    if (liveCapturePollTimer !== null && typeof window !== "undefined") {
      window.clearInterval(liveCapturePollTimer);
      liveCapturePollTimer = null;
    }
    liveCapturePollInFlight = false;
    activePollOnce = null;
  }

  function startLiveCapturePolling(sessionId: string, expectedGen: number): void {
    stopLiveCapturePolling();
    let consecutiveFailures = 0;

    const pollOnce = (bypassHiddenCheck = false) => {
      if (!bypassHiddenCheck && core.isDocumentHidden()) {
        // Pause 600ms polling while window is minimized/hidden; visibility restore triggers pollIfActive().
        return;
      }
      if (liveCapturePollInFlight) return;
      const currentCapture = core.getState().bgTasks.capture;
      if (
        expectedGen !== captureGen ||
        !currentCapture.active ||
        currentCapture.sessionId !== sessionId
      ) {
        stopLiveCapturePolling();
        return;
      }
      liveCapturePollInFlight = true;
      void catcloudApi
        .pollLiveCaptureSession(sessionId)
        .then((latestStatus) => {
          consecutiveFailures = 0;
          const latestCapture = core.getState().bgTasks.capture;
          if (
            expectedGen !== captureGen ||
            !latestCapture.active ||
            latestCapture.sessionId !== sessionId
          ) {
            return;
          }
          const isTimedOutOrStopped =
            Boolean(latestStatus.timed_out) || !latestStatus.active;
          core.updateBgTasks((bg) => ({
            ...bg,
            capture: {
              ...bg.capture,
              sessionId: bg.capture.sessionId || latestStatus.session_id || sessionId,
              active: latestStatus.active && !latestStatus.timed_out,
              timedOut: isTimedOutOrStopped ? true : bg.capture.timedOut,
              targetName: latestStatus.target_name || bg.capture.targetName,
              status: latestStatus,
            },
          }));
          if (isTimedOutOrStopped) {
            stopLiveCapturePolling();
          }
        })
        .catch((err) => {
          if (expectedGen !== captureGen) {
            stopLiveCapturePolling();
            return;
          }
          const latestCapture = core.getState().bgTasks.capture;
          if (!latestCapture.active || latestCapture.sessionId !== sessionId) {
            stopLiveCapturePolling();
            return;
          }
          consecutiveFailures += 1;
          const rawErrMsg =
            err instanceof Error
              ? err.message
              : typeof err === "string"
                ? err
                : String(err ?? "");
          const formattedErrMsg = formatErrorMessage(err);
          const isSessionMissing =
            /not\s*found|不存在|已失效|expired/i.test(rawErrMsg) ||
            /not\s*found|不存在|已失效|expired/i.test(formattedErrMsg);
          if (isSessionMissing || consecutiveFailures >= 3) {
            stopLiveCapturePolling();
            core.updateBgTasks((bg) => ({
              ...bg,
              capture: {
                ...bg.capture,
                active: false,
                timedOut: false,
                finishing: false,
                sessionId: null,
                status: null,
              },
            }));
            core.pushToast("捕捉会话已失效，请重新开始", "warn", 4200);
          }
        })
        .finally(() => {
          liveCapturePollInFlight = false;
        });
    };

    activePollOnce = () => pollOnce(true);
    pollOnce(false);
    if (typeof window !== "undefined") {
      liveCapturePollTimer = window.setInterval(() => pollOnce(false), 600);
    }
  }

  const actions = {
    async startLiveCaptureBg(targetPid: number): Promise<LiveCaptureStartDto | null> {
      captureGen += 1;
      const myGen = captureGen;
      const prevSid = core.getState().bgTasks.capture.sessionId;
      stopLiveCapturePolling();
      resetCaptureBg();
      if (prevSid) {
        void catcloudApi.cancelLiveCaptureSession(prevSid).catch(() => {
          /* ignore cleanup error of superseded capture session */
        });
      }
      try {
        const started = await catcloudApi.startLiveCaptureSession(targetPid);
        if (myGen !== captureGen) {
          void catcloudApi.cancelLiveCaptureSession(started.session_id).catch(() => {
            /* ignore cleanup error of stale capture session */
          });
          return null;
        }
        const targetName = started.target_name?.trim() || "目标软件";
        const initialStatus: LiveCaptureStatusDto = {
          session_id: started.session_id,
          active: true,
          timed_out: false,
          step_app_ready: true,
          step_activity_seen: false,
          step_nodes_ready: false,
          elapsed_sec: 0,
          captured_node_count: 0,
          opaque_change_detected: false,
          target_name: targetName,
          watch_dirs: Array.isArray(started.watch_dirs) ? started.watch_dirs : [],
          events: [
            {
              timestamp_ms: Date.now(),
              kind: "session",
              message: "已锁定目标软件，等待你在该软件内点击「更新订阅」或「连接」…",
            },
          ],
          preview_nodes: [],
          unsupported_reason: null,
        };
        resetCaptureBg({
          sessionId: started.session_id,
          active: true,
          targetName,
          status: initialStatus,
        });
        startLiveCapturePolling(started.session_id, myGen);
        return started;
      } catch (err) {
        if (myGen !== captureGen) {
          return null;
        }
        resetCaptureBg();
        core.pushToast(`启动实时捕捉失败：${formatErrorMessage(err)}`, "warn");
        return null;
      }
    },

    async finishLiveCaptureBg(): Promise<LiveCaptureOutcomeDto | null> {
      return core.runInFlight("capture:finish", async () => {
        const curCapture = core.getState().bgTasks.capture;
        const sid = curCapture.sessionId ?? curCapture.status?.session_id ?? null;
        stopLiveCapturePolling();
        if (!sid) {
          core.updateBgTasks((bg) => ({
            ...bg,
            capture: {
              ...IDLE_CAPTURE_BG,
              targetName: bg.capture.outcome ? bg.capture.targetName : null,
              outcome: bg.capture.outcome,
            },
          }));
          return core.getState().bgTasks.capture.outcome;
        }
        const myGen = captureGen;
        core.updateBgTasks((bg) => ({
          ...bg,
          capture: {
            ...bg.capture,
            finishing: true,
          },
        }));
        try {
          const outcome = await catcloudApi.finishLiveCaptureSession(sid);
          if (myGen !== captureGen) {
            return null;
          }
          core.updateBgTasks((bg) => ({
            ...bg,
            capture: {
              ...IDLE_CAPTURE_BG,
              targetName: outcome.target_name || bg.capture.targetName,
              outcome,
            },
          }));
          return outcome;
        } catch (err) {
          if (myGen !== captureGen) {
            return null;
          }
          resetCaptureBg();
          core.pushToast(`结束捕捉并整理失败：${formatErrorMessage(err)}`, "warn");
          return null;
        }
      });
    },

    async cancelLiveCaptureBg(): Promise<void> {
      captureGen += 1;
      const curCapture = core.getState().bgTasks.capture;
      const sid = curCapture.sessionId ?? curCapture.status?.session_id ?? null;
      stopLiveCapturePolling();
      resetCaptureBg();
      if (sid) {
        try {
          await catcloudApi.cancelLiveCaptureSession(sid);
        } catch {
          /* ignore backend cancel cleanup failure */
        }
      }
    },

    clearLiveCaptureOutcome(): void {
      core.updateBgTasks((bg) => {
        if (bg.capture.outcome === null && !bg.capture.finishing) return bg;
        return {
          ...bg,
          capture: {
            ...bg.capture,
            timedOut: bg.capture.active ? bg.capture.timedOut : false,
            finishing: false,
            outcome: null,
          },
        };
      });
    },
  };

  return {
    actions,
    pollIfActive(): void {
      const currentCapture = core.getState().bgTasks.capture;
      if (currentCapture.active && currentCapture.sessionId && activePollOnce) {
        activePollOnce();
      }
    },
    dispose(): void {
      captureGen += 1;
      stopLiveCapturePolling();
    },
  };
}
