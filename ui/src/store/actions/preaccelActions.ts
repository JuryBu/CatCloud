import {
  type AppConfig,
  type CoreRuntimeInfo,
  type GlobalPreAccelScope,
  type GlobalPreAccelStatus,
  type PreAccelComparisonResult,
  type PreAccelSpeedTestResult,
  catcloudApi,
  formatErrorMessage,
  isTauriEnv,
} from "../../api/tauri";
import { resolvePlatformOs } from "../../utils/platform";
import {
  isRealWinDivertActive,
  normalizePreAccelVerifyState,
  resolvePreAccelCoreState,
} from "../../utils/preaccelStatus";
import { type StoreCore, mergeIncomingAppConfig } from "../core";
import { selectIsProbeEngineBusy } from "../selectors";
import type { NavRouteId } from "../types";

function isUdpOnlyProtocol(proto: string): boolean {
  const p = proto.trim().toLowerCase();
  return (
    p === "hysteria2" ||
    p === "hy2" ||
    p === "hysteria" ||
    p === "tuic" ||
    p === "wireguard"
  );
}

function hasValidPositiveLatency(ms: number | null | undefined): ms is number {
  return ms !== null && ms !== undefined && Number.isFinite(ms) && ms > 0;
}

function formatMsShort(ms: number): string {
  return ms < 0.5 ? "<1 ms" : `${Math.round(ms)} ms`;
}

export interface PreAccelActionDeps {
  setNav: (nav: NavRouteId) => void;
}

export function createPreAccelActions(core: StoreCore, deps: PreAccelActionDeps) {
  let globalPreAccelRefreshInFlight = false;
  let globalPreAccelRefreshPending = false;

  async function refreshGlobalPreAccelStatus(): Promise<GlobalPreAccelStatus> {
    if (globalPreAccelRefreshInFlight) {
      globalPreAccelRefreshPending = true;
      return core.getState().globalPreAccel;
    }
    globalPreAccelRefreshInFlight = true;
    let latestStatus = core.getState().globalPreAccel;
    try {
      do {
        globalPreAccelRefreshPending = false;
        try {
          const status = await catcloudApi.getGlobalPreAccelStatus();
          latestStatus = status;
          core.setState((prev) => {
            const nextWinDivertActive = Boolean(
              status.is_windivert_active ?? (status.running && status.mode === "windivert")
            );
            return {
              ...prev,
              globalPreAccel: status,
              runtime: {
                ...prev.runtime,
                global_preaccel_active: status.running,
                global_preaccel_mode: status.mode,
                global_preaccel_socks_port: status.socks_port,
                global_preaccel_connections: status.active_connections,
                global_windivert_active: nextWinDivertActive,
                preaccel_install_state:
                  status.install_state ?? prev.runtime.preaccel_install_state,
                global_preaccel_verify_state: status.verify_state ?? "idle",
                global_preaccel_verify_ms: status.verify_latency_ms ?? null,
              },
            };
          });
        } catch {
          latestStatus = core.getState().globalPreAccel;
        }
      } while (globalPreAccelRefreshPending);
      return latestStatus;
    } finally {
      globalPreAccelRefreshInFlight = false;
      globalPreAccelRefreshPending = false;
    }
  }

  async function togglePreAccel(next?: boolean): Promise<boolean> {
    const state = core.getState();
    const currentlyOn = Boolean(
      (state.runtime.preaccel_enabled ?? state.config.preaccel.enabled) ||
        isRealWinDivertActive(state.runtime, state.globalPreAccel)
    );
    const target = next ?? !currentlyOn;
    let latestRelays = state.preAccelRelays;

    if (target) {
      try {
        latestRelays = await catcloudApi.listPreAccelRelays();
        core.setState((prev) => ({ ...prev, preAccelRelays: latestRelays }));
      } catch {
        /* fall back to cached relays on transient IPC failure */
      }
      const hasEnabledRelay = latestRelays.some((r) => r.enabled);
      if (!hasEnabledRelay) {
        core.pushToast(
          "还没有可用的国内提速线路，请先在「国内提速」页添加并启用至少一条线路",
          "warn",
          4400
        );
        const cur = core.getState();
        if (cur.windowMode === "main" && cur.activeNav !== "preaccel") {
          deps.setNav("preaccel");
        }
        return false;
      }
    }

    try {
      const applied = await catcloudApi.togglePreAccel(target);
      const [cfgRes, rtRes, globalRes] = await Promise.allSettled([
        catcloudApi.getConfig(),
        catcloudApi.getRuntimeInfo(),
        catcloudApi.getGlobalPreAccelStatus(),
      ]);

      const curState = core.getState();
      const nextCfg: AppConfig =
        cfgRes.status === "fulfilled"
          ? mergeIncomingAppConfig(cfgRes.value, curState.config)
          : {
              ...curState.config,
              preaccel: {
                ...curState.config.preaccel,
                enabled: applied,
                global_bypass_enabled: applied,
              },
            };

      const nextGlobal: GlobalPreAccelStatus =
        globalRes.status === "fulfilled"
          ? globalRes.value
          : applied
            ? curState.globalPreAccel
            : {
                ...curState.globalPreAccel,
                running: false,
                mode: "off",
                is_windivert_active: false,
                install_state: "idle",
                socks_port: null,
                active_connections: 0,
                accelerated_processes: [],
                process_stats: [],
                verify_state: "idle",
                verify_latency_ms: null,
                verify_message: null,
                security_guidance: null,
              };

      const nextWinDivertActive = Boolean(
        (rtRes.status === "fulfilled" && rtRes.value.global_windivert_active) ||
          (nextGlobal.running && nextGlobal.mode === "windivert")
      );

      const nextRt: CoreRuntimeInfo =
        rtRes.status === "fulfilled"
          ? {
              ...rtRes.value,
              global_preaccel_verify_state:
                rtRes.value.global_preaccel_verify_state ?? nextGlobal.verify_state ?? "idle",
              global_preaccel_verify_ms:
                rtRes.value.global_preaccel_verify_ms !== undefined
                  ? rtRes.value.global_preaccel_verify_ms
                  : (nextGlobal.verify_latency_ms ?? null),
            }
          : {
              ...curState.runtime,
              preaccel_enabled: applied,
              preaccel_active: applied && (curState.runtime.running || nextWinDivertActive),
              global_preaccel_active: nextGlobal.running,
              global_windivert_active: nextWinDivertActive,
              global_preaccel_mode: nextGlobal.mode,
              global_preaccel_socks_port: nextGlobal.socks_port,
              global_preaccel_connections: nextGlobal.active_connections,
              preaccel_install_state: nextGlobal.install_state ?? "idle",
              global_preaccel_verify_state: nextGlobal.verify_state ?? "idle",
              global_preaccel_verify_ms: nextGlobal.verify_latency_ms ?? null,
            };

      core.setState((prev) => ({
        ...prev,
        config: nextCfg,
        runtime: nextRt,
        globalPreAccel: nextGlobal,
      }));

      if (!applied) {
        core.pushToast("已关闭国内提速（猫猫代理与其它软件已一并关闭）", "info");
        return false;
      }

      const coreStatus = resolvePreAccelCoreState(
        nextRt,
        nextGlobal,
        nextCfg.preaccel.enabled,
        latestRelays.some((r) => r.enabled)
      );
      const os = resolvePlatformOs(nextRt.os_label);

      if (coreStatus.proxyActive) {
        if (coreStatus.realWinDivertActive) {
          if (coreStatus.verifyState === "probing") {
            core.pushToast(
              "已开启国内提速（猫猫代理已加速，正在自动探测其它代理软件链路…）",
              "ok",
              4200
            );
          } else if (coreStatus.verifyState === "verified" && coreStatus.verifyLatencyMs) {
            core.pushToast(
              `已开启国内提速（猫猫代理与其它软件均已走 443 加速，实测 ${coreStatus.verifyLatencyMs} ms）`,
              "ok",
              4200
            );
          } else {
            core.pushToast("已开启国内提速（猫猫代理与其它代理软件均已走 443 加速）", "ok", 4200);
          }
        } else if (coreStatus.verifyState === "probing") {
          core.pushToast(
            "已开启国内提速（猫猫代理已加速，正在自动探测其它代理软件链路…）",
            "ok",
            4200
          );
        } else if (coreStatus.verifyState === "degraded") {
          core.pushToast(
            "已开启国内提速（猫猫代理已加速；其它软件底层拦截已保护回退，可前往查看指引）",
            "warn",
            4800
          );
        } else if (
          coreStatus.installState === "downloading" ||
          coreStatus.installState === "verifying"
        ) {
          core.pushToast(
            "已开启国内提速（猫猫代理已加速，正在后台准备其它软件提速组件…）",
            "ok",
            4400
          );
        } else if (coreStatus.installState === "need_elevation") {
          core.pushToast(
            "已开启国内提速（猫猫代理已加速；加速其它代理软件需管理员权限）",
            "ok",
            4600
          );
        } else {
          const relayHint = nextRt.preaccel_relay_name
            ? `（当前主力：${nextRt.preaccel_relay_name}）`
            : "";
          core.pushToast(`已开启国内提速${relayHint}`, "ok");
        }
      } else if (coreStatus.realWinDivertActive) {
        if (coreStatus.verifyState === "probing") {
          core.pushToast("已开启国内提速，正在自动探测其它代理软件加速链路…", "info", 4200);
        } else if (coreStatus.verifyState === "verified" && coreStatus.verifyLatencyMs) {
          core.pushToast(
            `已开启国内提速并实测畅通（${coreStatus.verifyLatencyMs} ms），正在自动加速其它代理软件`,
            "ok",
            4200
          );
        } else {
          core.pushToast("已开启国内提速，正在自动加速电脑上其它代理软件", "ok", 4200);
        }
      } else if (coreStatus.verifyState === "probing") {
        core.pushToast("已开启国内提速，正在自动探测其它代理软件加速链路…", "info", 4200);
      } else if (coreStatus.verifyState === "degraded") {
        core.pushToast(
          nextGlobal.verify_message ||
            "底层拦截未畅通，已自动停止拦截防止断网，请查看环境放行指引",
          "warn",
          5000
        );
      } else if (
        coreStatus.installState === "downloading" ||
        coreStatus.installState === "verifying"
      ) {
        core.pushToast("已开启国内提速，正在后台自动准备官方提速组件…", "info", 4400);
      } else if (coreStatus.installState === "need_elevation") {
        core.pushToast(
          "已开启国内提速（提速组件已就绪，需以管理员身份重启以加速其它代理软件）",
          "warn",
          4800
        );
      } else if (os === "windows") {
        core.pushToast("已开启国内提速（本地提速入口已就绪）", "info", 4200);
      } else {
        const portLabel = nextGlobal.socks_port
          ? `127.0.0.1:${nextGlobal.socks_port}`
          : "本地提速入口";
        core.pushToast(`已开启国内提速（本地入口 ${portLabel} 已就绪）`, "ok", 4200);
      }

      return true;
    } catch (err) {
      const msg = formatErrorMessage(err);
      const rawMsg = err instanceof Error ? err.message : String(err ?? "");
      const isNoEnabledRelay =
        /\bNO_ENABLED_RELAY\b|no\s+enabled\s+(?:preaccel\s+)?relay|no\s+available\s+(?:domestic\s+)?relay|还没有可用的国内(?:提速线路|中转)|尚未(?:添加|配置|启用).*?(?:提速线路|中转)|没有可用.*?(?:提速线路|中转)/i.test(
          `${rawMsg} ${msg}`
        );
      if (target && isNoEnabledRelay) {
        core.pushToast(
          "还没有可用的国内提速线路，请先在「国内提速」页添加并启用至少一条线路",
          "warn",
          4600
        );
        const cur = core.getState();
        if (cur.windowMode === "main" && cur.activeNav !== "preaccel") {
          deps.setNav("preaccel");
        }
        return false;
      }
      core.pushToast(`切换国内提速失败：${msg}`, "warn", 4200);
      return false;
    }
  }

  async function installWinDivertDriver(): Promise<boolean> {
    return core.runInFlight(
      "preaccel:installDriver",
      async () => {
        core.updateBgTasks((bg) => ({
          ...bg,
          preaccel: { ...bg.preaccel, installingDriver: true },
        }));
        try {
          const nextGlobal = await catcloudApi.installWinDivertDriver();
          const rt = await catcloudApi.getRuntimeInfo().catch(() => null);
          core.setState((prev) => ({
            ...prev,
            globalPreAccel: nextGlobal,
            runtime: rt ?? prev.runtime,
          }));
          if (nextGlobal.windivert_available) {
            core.pushToast(
              nextGlobal.is_elevated
                ? "官方提速组件（WinDivert v2.2.2）已校验就绪，可自动加速其它代理软件"
                : "官方提速组件已校验就绪，以管理员身份重启即可自动加速其它代理软件",
              "ok",
              4600
            );
            return true;
          }
          core.pushToast(
            nextGlobal.last_error || "提速组件准备未完成，如被安全软件拦截请放行后重试",
            "warn",
            4600
          );
          return false;
        } catch (err) {
          core.pushToast(`下载校验 WinDivert 驱动失败：${formatErrorMessage(err)}`, "warn", 5000);
          return false;
        } finally {
          core.updateBgTasks((bg) => ({
            ...bg,
            preaccel: { ...bg.preaccel, installingDriver: false },
          }));
        }
      },
      { mascot: "thinking", celebrate: true }
    );
  }

  const actions = {
    refreshGlobalPreAccelStatus,
    togglePreAccel,

    async toggleGlobalPreAccel(next?: boolean): Promise<boolean> {
      return togglePreAccel(next);
    },

    async updateGlobalPreAccelSettings(
      scope: GlobalPreAccelScope,
      targetProcesses: string[],
      windivertDir: string | null = core.getState().config.preaccel.windivert_dir ?? null
    ): Promise<boolean> {
      try {
        const nextGlobal = await catcloudApi.updateGlobalPreAccelSettings(
          scope,
          targetProcesses,
          windivertDir
        );
        const [cfgRes, rtRes] = await Promise.allSettled([
          catcloudApi.getConfig(),
          catcloudApi.getRuntimeInfo(),
        ]);
        core.setState((prev) => ({
          ...prev,
          config:
            cfgRes.status === "fulfilled"
              ? mergeIncomingAppConfig(cfgRes.value, prev.config)
              : {
                  ...prev.config,
                  preaccel: {
                    ...prev.config.preaccel,
                    global_scope: scope,
                    global_target_processes: targetProcesses,
                    windivert_dir: windivertDir,
                  },
                },
          runtime: rtRes.status === "fulfilled" ? rtRes.value : prev.runtime,
          globalPreAccel: nextGlobal,
        }));
        return true;
      } catch (err) {
        core.pushToast(`保存国内提速范围失败：${formatErrorMessage(err)}`, "warn", 4000);
        return false;
      }
    },

    installWinDivertDriver,

    async relaunchAsAdminForGlobalPreAccel(): Promise<boolean> {
      try {
        const launched = await catcloudApi.relaunchAsAdminForGlobalPreAccel();
        if (launched) {
          if (!isTauriEnv()) {
            const [cfg, rt, globalStatus] = await Promise.all([
              catcloudApi.getConfig(),
              catcloudApi.getRuntimeInfo(),
              catcloudApi.getGlobalPreAccelStatus(),
            ]);
            core.setState((prev) => ({
              ...prev,
              config: cfg,
              runtime: rt,
              globalPreAccel: globalStatus,
            }));
            core.pushToast("演示模式：已模拟管理员提权并开启全局国内提速", "ok");
          } else {
            core.pushToast("已拉起管理员实例，正在启用全局国内提速…", "ok", 4200);
          }
          return true;
        }
        core.pushToast("已取消管理员授权，当前继续保持本地通道待命", "info");
        return false;
      } catch (err) {
        core.pushToast(`以管理员身份启动失败：${formatErrorMessage(err)}`, "warn", 4600);
        return false;
      }
    },

    async runPreAccelBenchmark(
      nodeId?: string | null
    ): Promise<PreAccelComparisonResult | null> {
      const existing = core.inFlightTasks.get("preaccel:benchmark");
      if (existing) {
        return existing as Promise<PreAccelComparisonResult | null>;
      }
      const state = core.getState();
      if (selectIsProbeEngineBusy(state)) {
        const relaySpeedBusy =
          state.bgTasks.preaccel.relaysSpeedTestingAll ||
          state.bgTasks.preaccel.relaysSpeedTestingIds.length > 0;
        core.pushToast(
          relaySpeedBusy
            ? "中转上下行测速正在后台进行，完成后即可运行提速对比"
            : "节点测速正在后台进行，完成后即可运行提速对比",
          "info"
        );
        return null;
      }

      const inDesktop = isTauriEnv();
      const enabledRelays = [...state.preAccelRelays]
        .filter((r) => r.enabled)
        .sort((a, b) =>
          a.priority !== b.priority ? a.priority - b.priority : a.id.localeCompare(b.id)
        );
      if (inDesktop && enabledRelays.length === 0) {
        core.pushToast("请先添加并启用至少一条国内中转线路，再进行提速对比", "warn");
        return null;
      }

      const hasComparableNode = state.nodes.some((n) => !isUdpOnlyProtocol(n.protocol));
      if (inDesktop && !hasComparableNode) {
        core.pushToast(
          "还没有可对比的海外节点，请先在「节点与测速 → 订阅与导入」中导入节点",
          "warn"
        );
        return null;
      }

      const primaryRelayId = (() => {
        const rtName = state.runtime.preaccel_relay_name;
        if (rtName) {
          const matched = enabledRelays.find((r) => r.name === rtName || r.id === rtName);
          if (matched) return matched.id;
        }
        return enabledRelays[0]?.id ?? null;
      })();
      const requestedNodeId = nodeId?.trim() || null;

      return core.runInFlight(
        "preaccel:benchmark",
        async () => {
          core.updateBgTasks((bg) => ({
            ...bg,
            preaccel: {
              ...bg.preaccel,
              benchmark: {
                ...bg.preaccel.benchmark,
                running: true,
                nodeId: requestedNodeId,
                error: null,
              },
            },
          }));

          try {
            try {
              const relayResults = await catcloudApi.testPreAccelRelays(null);
              if (inDesktop) {
                const latestRelays = await catcloudApi.listPreAccelRelays();
                core.setState((prev) => ({ ...prev, preAccelRelays: latestRelays }));
              } else {
                const resultMap = new Map(relayResults.map((r) => [r.relay_id, r]));
                core.setState((prev) => ({
                  ...prev,
                  preAccelRelays: prev.preAccelRelays.map((r) => {
                    const matched = resultMap.get(r.id);
                    return matched ? { ...r, last_probe_ms: matched.latency_ms } : r;
                  }),
                }));
              }
            } catch {
              /* continue to speed comparison even if relay pre-check fails */
            }

            const result = await catcloudApi.benchmarkPreAccelComparison(
              primaryRelayId,
              requestedNodeId
            );

            if (inDesktop) {
              try {
                const latestRelays = await catcloudApi.listPreAccelRelays();
                core.setState((prev) => ({ ...prev, preAccelRelays: latestRelays }));
              } catch {
                /* ignore secondary relay refresh failure */
              }
            }

            const finishedAt = Date.now();
            core.updateBgTasks((bg) => ({
              ...bg,
              preaccel: {
                ...bg.preaccel,
                benchmark: {
                  running: false,
                  nodeId: result.node_id || requestedNodeId,
                  result,
                  error: null,
                  finishedAt,
                },
              },
            }));

            const accUp = result.accelerated.up_mbps;
            const dirUp = result.direct.up_mbps;
            const ratio =
              result.up_boost_ratio ??
              (accUp !== null && dirUp !== null && dirUp > 0 ? accUp / dirUp : null);

            if (!inDesktop) {
              core.pushToast(
                ratio !== null
                  ? `提速效果对比完成（演示）：走国内中转上传提速约 ${ratio.toFixed(1)} 倍`
                  : "提速效果对比完成（演示）",
                "info",
                4000
              );
            } else if (result.ok && result.accelerated.ok && result.direct.ok) {
              core.pushToast(
                ratio !== null && ratio >= 1.1 && accUp !== null
                  ? `提速效果对比完成：走国内中转上传 ${accUp.toFixed(1)} Mbps（提速 ${ratio.toFixed(1)} 倍）`
                  : accUp !== null
                    ? `提速效果对比完成：走国内中转上传 ${accUp.toFixed(1)} Mbps`
                    : "提速效果对比完成",
                "ok",
                4200
              );
            } else {
              const errParts: string[] = [];
              if (!result.accelerated.ok) {
                const latHint = hasValidPositiveLatency(result.accelerated.latency_ms)
                  ? `延迟 ${formatMsShort(result.accelerated.latency_ms)}，`
                  : "";
                errParts.push(
                  `走中转（${latHint}${result.accelerated.error?.trim() || "连接超时"}）`
                );
              }
              if (!result.direct.ok) {
                const latHint = hasValidPositiveLatency(result.direct.latency_ms)
                  ? `延迟 ${formatMsShort(result.direct.latency_ms)}，`
                  : "";
                errParts.push(
                  `普通直连（${latHint}${result.direct.error?.trim() || "连接超时"}）`
                );
              }
              core.pushToast(
                errParts.length > 0
                  ? `提速效果对比完成：${errParts.join("；")}`
                  : "提速效果对比未全部成功，请检查中转与节点状态",
                "warn",
                4600
              );
            }
            return result;
          } catch (err) {
            const msg = formatErrorMessage(err);
            core.updateBgTasks((bg) => ({
              ...bg,
              preaccel: {
                ...bg.preaccel,
                benchmark: {
                  ...bg.preaccel.benchmark,
                  running: false,
                  error: msg,
                },
              },
            }));
            core.pushToast(`提速效果对比失败：${msg}`, "warn", 4400);
            return null;
          }
        },
        { mascot: "searching", celebrate: true }
      );
    },

    async runTestPreAccelRelays(relayId?: string | null): Promise<void> {
      const targetId = relayId?.trim() || null;
      const inDesktop = isTauriEnv();

      if (!targetId) {
        if (core.getState().preAccelRelays.length === 0) return;
        return core.runInFlight(
          "preaccel:relays:all",
          async () => {
            core.updateBgTasks((bg) => ({
              ...bg,
              preaccel: { ...bg.preaccel, relaysTestingAll: true },
            }));
            try {
              const results = await catcloudApi.testPreAccelRelays(null);
              if (inDesktop) {
                const latestRelays = await catcloudApi.listPreAccelRelays();
                core.setState((prev) => ({ ...prev, preAccelRelays: latestRelays }));
              } else {
                const resultMap = new Map(results.map((r) => [r.relay_id, r]));
                core.setState((prev) => ({
                  ...prev,
                  preAccelRelays: prev.preAccelRelays.map((r) => {
                    const matched = resultMap.get(r.id);
                    return matched ? { ...r, last_probe_ms: matched.latency_ms } : r;
                  }),
                }));
              }
              const okCount = results.filter((r) => r.ok).length;
              core.pushToast(
                `全部中转测速完成：${okCount}/${results.length} 条线路可用`,
                okCount > 0 ? "ok" : "warn"
              );
            } catch (err) {
              core.pushToast(`全部中转测速失败：${formatErrorMessage(err)}`, "warn");
            } finally {
              core.updateBgTasks((bg) => ({
                ...bg,
                preaccel: { ...bg.preaccel, relaysTestingAll: false },
              }));
            }
          },
          { mascot: true }
        );
      }

      if (core.getState().bgTasks.preaccel.relaysTestingAll) return;

      return core.runInFlight(
        `preaccel:relay:${targetId}`,
        async () => {
          core.updateBgTasks((bg) => ({
            ...bg,
            preaccel: {
              ...bg.preaccel,
              relaysTestingIds: bg.preaccel.relaysTestingIds.includes(targetId)
                ? bg.preaccel.relaysTestingIds
                : [...bg.preaccel.relaysTestingIds, targetId],
            },
          }));
          try {
            const results = await catcloudApi.testPreAccelRelays([targetId]);
            const item = results.find((r) => r.relay_id === targetId) ?? results[0];
            if (inDesktop) {
              const latestRelays = await catcloudApi.listPreAccelRelays();
              core.setState((prev) => ({ ...prev, preAccelRelays: latestRelays }));
            } else if (item) {
              core.setState((prev) => ({
                ...prev,
                preAccelRelays: prev.preAccelRelays.map((r) =>
                  r.id === targetId ? { ...r, last_probe_ms: item.latency_ms } : r
                ),
              }));
            }
            if (item && !item.ok) {
              core.pushToast(`中转测速失败：${item.error ?? "连接超时"}`, "warn");
            } else {
              const msText = hasValidPositiveLatency(item?.latency_ms)
                ? `（${formatMsShort(item.latency_ms)}）`
                : "";
              core.pushToast(`中转线路连通正常${msText}`, "ok");
            }
          } catch (err) {
            core.pushToast(`中转测速失败：${formatErrorMessage(err)}`, "warn");
          } finally {
            core.updateBgTasks((bg) => ({
              ...bg,
              preaccel: {
                ...bg.preaccel,
                relaysTestingIds: bg.preaccel.relaysTestingIds.filter((id) => id !== targetId),
              },
            }));
          }
        },
        { mascot: true }
      );
    },

    async runTestPreAccelRelaySpeeds(
      relayId?: string | null,
      nodeId?: string | null
    ): Promise<PreAccelSpeedTestResult[]> {
      const targetId = relayId?.trim() || null;
      const targetNodeId = nodeId?.trim() || null;
      const inDesktop = isTauriEnv();
      const taskKey = targetId ? `preaccel:relay-speed:${targetId}` : "preaccel:relay-speed:all";
      const existing = core.inFlightTasks.get(taskKey);
      if (existing) {
        return existing as Promise<PreAccelSpeedTestResult[]>;
      }
      const state = core.getState();
      if (!targetId && state.preAccelRelays.length === 0) {
        return [];
      }
      if (selectIsProbeEngineBusy(state)) {
        core.pushToast("当前已有测速或提速对比正在后台进行，请稍候完成后再试", "info");
        return [];
      }

      const hasValidSpeed = (v: number | null | undefined): v is number =>
        v !== null && v !== undefined && Number.isFinite(v) && v > 0;

      return core.runInFlight(
        taskKey,
        async () => {
          if (!targetId) {
            core.updateBgTasks((bg) => ({
              ...bg,
              preaccel: { ...bg.preaccel, relaysSpeedTestingAll: true },
            }));
          } else {
            core.updateBgTasks((bg) => ({
              ...bg,
              preaccel: {
                ...bg.preaccel,
                relaysSpeedTestingIds: bg.preaccel.relaysSpeedTestingIds.includes(targetId)
                  ? bg.preaccel.relaysSpeedTestingIds
                  : [...bg.preaccel.relaysSpeedTestingIds, targetId],
              },
            }));
          }

          try {
            const results = await catcloudApi.testPreAccelRelaySpeeds(
              targetId ? [targetId] : null,
              targetNodeId
            );

            const chainPatch: Record<string, number | null> = {};
            for (const res of results) {
              if (res.chain_latency_ms !== undefined) {
                chainPatch[res.relay_id] = res.chain_latency_ms ?? null;
              }
            }

            if (inDesktop) {
              const latestRelays = await catcloudApi.listPreAccelRelays();
              core.setState((prev) => ({
                ...prev,
                preAccelRelays: latestRelays,
                relayChainLatencies: { ...prev.relayChainLatencies, ...chainPatch },
              }));
            } else {
              const resultMap = new Map(results.map((r) => [r.relay_id, r]));
              core.setState((prev) => ({
                ...prev,
                relayChainLatencies: { ...prev.relayChainLatencies, ...chainPatch },
                preAccelRelays: prev.preAccelRelays.map((r) => {
                  const matched = resultMap.get(r.id);
                  if (!matched) return r;
                  return {
                    ...r,
                    last_probe_ms:
                      matched.latency_ms !== null ? matched.latency_ms : r.last_probe_ms,
                    last_up_mbps:
                      matched.up_mbps !== null ? matched.up_mbps : r.last_up_mbps ?? null,
                    last_down_mbps:
                      matched.down_mbps !== null ? matched.down_mbps : r.last_down_mbps ?? null,
                    last_mbps:
                      matched.up_mbps !== null
                        ? matched.up_mbps
                        : matched.down_mbps !== null
                          ? matched.down_mbps
                          : r.last_mbps,
                  };
                }),
              }));
            }

            if (targetId) {
              const item = results.find((r) => r.relay_id === targetId) ?? results[0];
              const relayName =
                item?.relay_name ||
                core.getState().preAccelRelays.find((r) => r.id === targetId)?.name ||
                "中转线路";
              if (!item || !item.ok) {
                core.pushToast(
                  `「${relayName}」测速失败：${item?.error ?? "连接超时"}`,
                  "warn",
                  4600
                );
              } else {
                const speedParts: string[] = [];
                if (hasValidSpeed(item.up_mbps)) {
                  speedParts.push(`↑${item.up_mbps.toFixed(1)} Mbps`);
                }
                if (hasValidSpeed(item.down_mbps)) {
                  speedParts.push(`↓${item.down_mbps.toFixed(1)} Mbps`);
                }
                const msPieces: string[] = [];
                if (hasValidPositiveLatency(item.latency_ms)) {
                  msPieces.push(`直连 ${formatMsShort(item.latency_ms)}`);
                }
                if (hasValidPositiveLatency(item.chain_latency_ms)) {
                  msPieces.push(`经海外对比 ${formatMsShort(item.chain_latency_ms)}`);
                }
                const msText = msPieces.length > 0 ? `（${msPieces.join(" / ")}）` : "";
                if (speedParts.length > 0) {
                  core.pushToast(
                    `「${relayName}」测速完成：${speedParts.join(" · ")}${msText}`,
                    "ok",
                    4600
                  );
                } else {
                  core.pushToast(
                    `「${relayName}」连通正常${msText}，暂未测出上下行速率`,
                    "warn",
                    4600
                  );
                }
              }
            } else {
              const measuredCount = results.filter(
                (r) => r.ok && (hasValidSpeed(r.up_mbps) || hasValidSpeed(r.down_mbps))
              ).length;
              core.pushToast(
                `中转上下行测速完成：${measuredCount}/${results.length} 条已测出速率`,
                measuredCount > 0 ? "ok" : "warn",
                4600
              );
            }

            return results;
          } catch (err) {
            core.pushToast(`中转上下行测速失败：${formatErrorMessage(err)}`, "warn", 4600);
            return [];
          } finally {
            if (!targetId) {
              core.updateBgTasks((bg) => ({
                ...bg,
                preaccel: { ...bg.preaccel, relaysSpeedTestingAll: false },
              }));
            } else {
              core.updateBgTasks((bg) => ({
                ...bg,
                preaccel: {
                  ...bg.preaccel,
                  relaysSpeedTestingIds: bg.preaccel.relaysSpeedTestingIds.filter(
                    (id) => id !== targetId
                  ),
                },
              }));
            }
          }
        },
        { mascot: "searching", celebrate: true }
      );
    },

    async runCheckCampusPortal(): Promise<void> {
      return core.runInFlight(
        "preaccel:campusPortal",
        async () => {
          core.updateBgTasks((bg) => ({
            ...bg,
            preaccel: {
              ...bg.preaccel,
              campusChecking: true,
              campusError: null,
            },
          }));
          try {
            const status = await catcloudApi.checkCampusPortal();
            core.setState((prev) => ({
              ...prev,
              runtime: {
                ...prev.runtime,
                captive_portal_required: status.captive_portal_required,
              },
              bgTasks: {
                ...prev.bgTasks,
                preaccel: {
                  ...prev.bgTasks.preaccel,
                  campusChecking: false,
                  campusResult: status,
                  campusError: null,
                },
              },
            }));
            if (status.captive_portal_required) {
              core.pushToast("检测到需要登录校园网，已自动临时放行认证页", "warn");
            } else {
              core.pushToast("当前国内网络连通正常，无需网页认证", "ok");
            }
          } catch (err) {
            const msg = formatErrorMessage(err);
            core.updateBgTasks((bg) => ({
              ...bg,
              preaccel: {
                ...bg.preaccel,
                campusChecking: false,
                campusError: msg,
              },
            }));
            core.pushToast(`校园网认证检测失败：${msg}`, "warn");
          }
        },
        { mascot: true }
      );
    },

    async runInstallWinDivertDriver(): Promise<void> {
      await installWinDivertDriver();
    },

    async runVerifyGlobalPreAccel(): Promise<GlobalPreAccelStatus | null> {
      return core.runInFlight(
        "preaccel:verifyGlobal",
        async () => {
          core.updateBgTasks((bg) => ({
            ...bg,
            preaccel: { ...bg.preaccel, verifyingGlobal: true },
          }));
          try {
            const status = await catcloudApi.verifyGlobalPreAccel();
            const rt = await catcloudApi.getRuntimeInfo().catch(() => null);
            core.setState((prev) => {
              const nextWinDivertActive = Boolean(
                status.is_windivert_active ?? (status.running && status.mode === "windivert")
              );
              const baseRuntime = rt ?? prev.runtime;
              return {
                ...prev,
                globalPreAccel: status,
                runtime: {
                  ...baseRuntime,
                  global_preaccel_active: status.running,
                  global_preaccel_mode: status.mode,
                  global_preaccel_socks_port: status.socks_port,
                  global_preaccel_connections: status.active_connections,
                  global_windivert_active: nextWinDivertActive,
                  preaccel_install_state:
                    status.install_state ?? baseRuntime.preaccel_install_state,
                  global_preaccel_verify_state: status.verify_state ?? "idle",
                  global_preaccel_verify_ms: status.verify_latency_ms ?? null,
                },
              };
            });

            const verifyState = normalizePreAccelVerifyState(status.verify_state);
            if (verifyState === "verified") {
              const msHint = hasValidPositiveLatency(status.verify_latency_ms)
                ? `（实测 ${formatMsShort(status.verify_latency_ms)}）`
                : "";
              core.pushToast(`全局提速链路探测畅通${msHint}`, "ok", 4200);
            } else if (verifyState === "degraded") {
              core.pushToast(
                status.verify_message ||
                  "底层拦截未畅通，已自动停止拦截防止断网，请查看环境放行指引",
                "warn",
                5200
              );
            } else if (verifyState === "failed") {
              core.pushToast(
                `链路探测未通过：${status.verify_message || status.last_error || "请检查中转线路与网络环境"}`,
                "warn",
                4800
              );
            } else if (verifyState === "probing") {
              core.pushToast("正在后台自动探测提速链路，请稍候…", "info", 3200);
            } else {
              core.pushToast(status.verify_message || "已完成当前提速链路检查", "info", 3200);
            }
            return status;
          } catch (err) {
            core.pushToast(`重新探测链路失败：${formatErrorMessage(err)}`, "warn", 4400);
            return null;
          } finally {
            core.updateBgTasks((bg) => ({
              ...bg,
              preaccel: { ...bg.preaccel, verifyingGlobal: false },
            }));
          }
        },
        { mascot: true }
      );
    },
  };

  return {
    actions,
    resetRuntime(): void {
      globalPreAccelRefreshPending = false;
    },
  };
}
