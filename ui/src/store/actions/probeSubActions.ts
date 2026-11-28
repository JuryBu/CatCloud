import {
  type ProbeKind,
  type ProbeRunSummary,
  type ProbeSnapshot,
  catcloudApi,
  formatErrorMessage,
  isTauriEnv,
} from "../../api/tauri";
import { mergeProbeSnapshotSafe } from "../../utils/probeSnapshotMerge";
import { type StoreCore, alignConfigWithRuntimeTun, mergeIncomingAppConfig } from "../core";
import { selectIsProbeEngineBusy } from "../selectors";
import type { ProbeRunProgressState } from "../types";

const PROBE_TIER_LABELS: Record<"latency" | "unlock" | "full", string> = {
  latency: "仅快测延迟",
  unlock: "测延迟 + 送中/AI",
  full: "含上下行完整测速",
};

export function createProbeSubActions(core: StoreCore) {
  let previewProbeTimer: number | null = null;
  let previewProbeCancelled = false;
  let previewProbeFinishResolve: (() => void) | null = null;

  function clearPreviewProbeTimer(): void {
    if (previewProbeTimer !== null && typeof window !== "undefined") {
      window.clearTimeout(previewProbeTimer);
      previewProbeTimer = null;
    }
  }

  const actions = {
    setProbeProgress(patch: Partial<ProbeRunProgressState>): void {
      core.setState((prev) => ({
        ...prev,
        probeProgress: { ...prev.probeProgress, ...patch },
      }));
    },

    syncProbeDefinitions(defs: ReadonlyArray<{ id: string; kind: ProbeKind }>): void {
      core.syncKnownLatencyProbeIds(defs);
    },

    async deleteSubscription(subId: string): Promise<boolean> {
      const deleted = await catcloudApi.deleteSubscription(subId);
      if (isTauriEnv()) {
        const [subsRes, nodesRes, groupsRes, probesRes, rtRes, cfgRes] = await Promise.allSettled([
          catcloudApi.listSubscriptions(),
          catcloudApi.listNodes(),
          catcloudApi.listGroups(),
          catcloudApi.listProbeSnapshots(),
          catcloudApi.getRuntimeInfo(),
          catcloudApi.getConfig(),
        ]);
        core.setState((prev) => {
          const nextRuntime = rtRes.status === "fulfilled" ? rtRes.value : prev.runtime;
          const baseConfig =
            cfgRes.status === "fulfilled"
              ? mergeIncomingAppConfig(cfgRes.value, prev.config)
              : prev.config;
          return {
            ...prev,
            subscriptions: subsRes.status === "fulfilled" ? subsRes.value : prev.subscriptions,
            nodes: nodesRes.status === "fulfilled" ? nodesRes.value : prev.nodes,
            groups: groupsRes.status === "fulfilled" ? groupsRes.value : prev.groups,
            probes: probesRes.status === "fulfilled" ? probesRes.value : prev.probes,
            runtime: nextRuntime,
            config:
              rtRes.status === "fulfilled"
                ? alignConfigWithRuntimeTun(baseConfig, nextRuntime)
                : baseConfig,
          };
        });
      } else {
        const [subsRes, nodesRes, groupsRes, rtRes, cfgRes] = await Promise.allSettled([
          catcloudApi.listSubscriptions(),
          catcloudApi.listNodes(),
          catcloudApi.listGroups(),
          catcloudApi.getRuntimeInfo(),
          catcloudApi.getConfig(),
        ]);
        core.setState((prev) => {
          const nextNodes =
            nodesRes.status === "fulfilled"
              ? nodesRes.value
              : prev.nodes.filter((n) => n.sub_id !== subId);
          const validIds = new Set(nextNodes.map((n) => n.id));
          const nextProbes: Record<string, ProbeSnapshot> = {};
          for (const [id, snap] of Object.entries(prev.probes)) {
            if (validIds.has(id)) nextProbes[id] = snap;
          }
          const nextGroups =
            groupsRes.status === "fulfilled"
              ? groupsRes.value
              : prev.groups.map((g) => {
                  const member_node_ids = g.member_node_ids.filter((id) => validIds.has(id));
                  const active_node_id =
                    g.active_node_id && validIds.has(g.active_node_id)
                      ? g.active_node_id
                      : (member_node_ids[0] ?? null);
                  return { ...g, member_node_ids, active_node_id };
                });
          const nextRuntime = rtRes.status === "fulfilled" ? rtRes.value : prev.runtime;
          const baseConfig =
            cfgRes.status === "fulfilled"
              ? mergeIncomingAppConfig(cfgRes.value, prev.config)
              : prev.config;
          return {
            ...prev,
            subscriptions:
              subsRes.status === "fulfilled"
                ? subsRes.value
                : prev.subscriptions.filter((s) => s.id !== subId),
            nodes: nextNodes,
            groups: nextGroups,
            probes: nextProbes,
            runtime: nextRuntime,
            config:
              rtRes.status === "fulfilled"
                ? alignConfigWithRuntimeTun(baseConfig, nextRuntime)
                : baseConfig,
          };
        });
      }
      return deleted;
    },

    async runIsolatedProbesBg(params: {
      nodeIds: string[];
      probeIds: string[];
      usePreAccel?: boolean;
      lockedOrderIds?: string[];
      maxTier?: "latency" | "unlock" | "full";
      includeKeepalive?: boolean;
    }): Promise<void> {
      const existing = core.inFlightTasks.get("probes:isolated");
      if (existing) {
        return existing as Promise<void>;
      }
      const state = core.getState();
      if (state.bgTasks.preaccel.benchmark.running) {
        core.pushToast("国内提速对比测速正在后台进行，完成后即可运行节点测速", "info");
        return;
      }
      if (state.probeProgress.running || state.bgTasks.probeLocalStarting) {
        core.pushToast("已有节点测速正在进行中，请稍候", "info");
        return;
      }

      const targetNodeIds = params.nodeIds.filter((id) => id.trim().length > 0);
      if (targetNodeIds.length === 0) {
        core.pushToast("请先筛选或勾选至少一个节点后再开始测速", "warn");
        return;
      }

      const tier = params.maxTier ?? "full";
      const includeKeepalive = params.includeKeepalive ?? false;
      const nodeNameById = new Map(state.nodes.map((n) => [n.id, n.name]));
      const firstNodeName = nodeNameById.get(targetNodeIds[0]) ?? null;
      const lockedOrder =
        params.lockedOrderIds && params.lockedOrderIds.length > 0
          ? [...params.lockedOrderIds]
          : state.nodes.map((n) => n.id);

      return core.runInFlight(
        "probes:isolated",
        async () => {
          core.setProbePauseRequested(false);
          previewProbeCancelled = false;
          clearPreviewProbeTimer();
          core.setProbePendingQueue([...targetNodeIds]);

          core.setState((prev) => ({
            ...prev,
            probeProgress: {
              running: true,
              completed: 0,
              total: targetNodeIds.length,
              currentNodeName: firstNodeName,
              cancelled: false,
            },
            bgTasks: {
              ...prev.bgTasks,
              probeLocalStarting: true,
              probeIsPausing: false,
              probeActiveNodeIds: targetNodeIds.slice(0, Math.min(4, targetNodeIds.length)),
              probeLockedOrderIds: lockedOrder,
            },
          }));

          if (isTauriEnv()) {
            try {
              const result = await catcloudApi.runIsolatedProbes(
                targetNodeIds,
                params.probeIds,
                tier,
                includeKeepalive,
                params.usePreAccel
              );

              // Flush any buffered 100ms probe-progress batch before committing final result
              // so a delayed timer cannot clobber `running: false`.
              core.flushProbeBatch();

              const wasCancelled = Boolean(result.cancelled) || core.isProbePauseRequested();
              const finalCompleted = Math.max(
                result.probed_count,
                core.getState().probeProgress.completed
              );
              const preaccelTag = result.used_preaccel
                ? `（已走 443 提速${result.preaccel_relay_name ? `：${result.preaccel_relay_name}` : ""}）`
                : "";

              const snapVals = Object.values(result.snapshots ?? {});
              const computedSummary: ProbeRunSummary = {
                latency_ok_count:
                  result.latency_ok_count ??
                  snapVals.filter((s) => s.ok && s.latency_ms !== null).length,
                bandwidth_ok_count:
                  result.bandwidth_ok_count ??
                  snapVals.filter((s) => s.ok && s.up_mbps !== null && s.down_mbps !== null)
                    .length,
                keepalive_ok_count:
                  result.keepalive_ok_count ??
                  snapVals.filter((s) => s.keepalive_60s_ok === true).length,
                failed_count:
                  result.failed_count ?? snapVals.filter((s) => !s.ok).length,
                exec_error_count: result.exec_error_count ?? result.errors.length,
                untested_count:
                  result.untested_count ??
                  Math.max(0, (result.total_count ?? targetNodeIds.length) - finalCompleted),
              };

              core.setState((prev) => {
                let nextProbes = prev.probes;
                if (result.snapshots && Object.keys(result.snapshots).length > 0) {
                  nextProbes = { ...prev.probes };
                  const knownLatencyIds = core.getKnownLatencyProbeIds();
                  for (const [nid, incoming] of Object.entries(result.snapshots)) {
                    nextProbes[nid] = mergeProbeSnapshotSafe(prev.probes[nid], incoming, {
                      authoritative: true,
                      latencyProbeIds: knownLatencyIds,
                    });
                  }
                }
                return {
                  ...prev,
                  probes: nextProbes,
                  lastProbeSummary: computedSummary,
                  probeProgress: {
                    running: false,
                    completed: finalCompleted,
                    total: result.total_count ?? targetNodeIds.length,
                    currentNodeName: null,
                    cancelled: wasCancelled,
                  },
                  bgTasks: {
                    ...prev.bgTasks,
                    probeLocalStarting: false,
                    probeIsPausing: false,
                    probeActiveNodeIds: [],
                    probeLockedOrderIds: [],
                  },
                };
              });

              if (wasCancelled) {
                core.pushToast(
                  `已暂停测速，已测完的 ${finalCompleted} 个节点结果已全部保留`,
                  "info"
                );
              } else if (!result.core_available) {
                core.pushToast(
                  result.errors[0] ?? "测速引擎尚未就绪，请先检查内核配置",
                  "warn"
                );
              } else if (result.errors.length > 0 && result.probed_count === 0) {
                core.pushToast(`测速未能完成：${result.errors[0]}`, "warn");
              } else {
                const summaryParts = [`延迟可达 ${computedSummary.latency_ok_count}`];
                if (tier === "full" || computedSummary.bandwidth_ok_count > 0) {
                  summaryParts.push(`双向带宽通过 ${computedSummary.bandwidth_ok_count}`);
                }
                if (includeKeepalive || computedSummary.keepalive_ok_count > 0) {
                  summaryParts.push(`60 秒保活 ${computedSummary.keepalive_ok_count}`);
                }
                if (computedSummary.failed_count > 0) {
                  summaryParts.push(`失败 ${computedSummary.failed_count}`);
                }
                if (computedSummary.exec_error_count > 0) {
                  summaryParts.push(`异常 ${computedSummary.exec_error_count}`);
                }
                core.pushToast(
                  `${PROBE_TIER_LABELS[tier]}完成${preaccelTag}：${summaryParts.join(" · ")}`,
                  computedSummary.failed_count > 0 || computedSummary.exec_error_count > 0
                    ? "info"
                    : "ok",
                  5200
                );
              }
            } catch (err) {
              core.flushProbeBatch();
              core.setState((prev) => ({
                ...prev,
                probeProgress: {
                  ...prev.probeProgress,
                  running: false,
                  currentNodeName: null,
                  cancelled: core.isProbePauseRequested(),
                },
                bgTasks: {
                  ...prev.bgTasks,
                  probeLocalStarting: false,
                  probeIsPausing: false,
                  probeActiveNodeIds: [],
                  probeLockedOrderIds: [],
                },
              }));
              core.pushToast(`测速执行失败：${formatErrorMessage(err)}`, "warn");
            } finally {
              core.setProbePendingQueue([]);
              core.setProbePauseRequested(false);
            }
            return;
          }

          // Browser preview streaming simulation hosted globally (survives page switches)
          await new Promise<void>((resolve) => {
            previewProbeFinishResolve = resolve;
            const total = targetNodeIds.length;
            const finishPreview = (cancelled: boolean, completed: number) => {
              clearPreviewProbeTimer();
              previewProbeFinishResolve = null;
              core.setProbePendingQueue([]);
              core.setProbePauseRequested(false);
              core.setState((prev) => ({
                ...prev,
                probeProgress: {
                  running: false,
                  completed,
                  total,
                  currentNodeName: null,
                  cancelled,
                },
                bgTasks: {
                  ...prev.bgTasks,
                  probeLocalStarting: false,
                  probeIsPausing: false,
                  probeActiveNodeIds: [],
                  probeLockedOrderIds: [],
                },
              }));
              if (!cancelled) {
                core.pushToast(
                  `预览模式：${PROBE_TIER_LABELS[tier]}完成，已逐条更新 ${total} 个节点`,
                  "ok"
                );
              }
              resolve();
            };

            const stepNext = (index: number) => {
              if (previewProbeCancelled) {
                finishPreview(true, core.getState().probeProgress.completed);
                return;
              }
              if (index >= total) {
                finishPreview(false, total);
                return;
              }

              const nodeId = targetNodeIds[index];
              const nodeName = nodeNameById.get(nodeId) ?? nodeId;
              core.setState((prev) => ({
                ...prev,
                probeProgress: {
                  running: true,
                  completed: index,
                  total,
                  currentNodeName: nodeName,
                  cancelled: false,
                },
                bgTasks: {
                  ...prev.bgTasks,
                  probeLocalStarting: false,
                  probeActiveNodeIds: [nodeId],
                },
              }));

              previewProbeTimer = window.setTimeout(() => {
                previewProbeTimer = null;
                if (previewProbeCancelled) {
                  finishPreview(true, core.getState().probeProgress.completed);
                  return;
                }
                void catcloudApi
                  .runIsolatedProbes(
                    [nodeId],
                    params.probeIds,
                    tier,
                    includeKeepalive,
                    params.usePreAccel
                  )
                  .then((res) => {
                    if (previewProbeCancelled) {
                      finishPreview(true, core.getState().probeProgress.completed);
                      return;
                    }
                    const rawSnap = res.snapshots[nodeId];
                    if (rawSnap) {
                      const jitterDelta = Math.round((Math.random() - 0.5) * 14);
                      const nextLatency =
                        rawSnap.latency_ms !== null
                          ? Math.max(18, Math.round(rawSnap.latency_ms + jitterDelta))
                          : 78;
                      const streamedSnap: ProbeSnapshot = {
                        ...rawSnap,
                        tested_at: new Date().toISOString(),
                        latency_ms: nextLatency,
                      };
                      core.setState((prev) => ({
                        ...prev,
                        probes: {
                          ...prev.probes,
                          [nodeId]: mergeProbeSnapshotSafe(prev.probes[nodeId], streamedSnap, {
                            latencyProbeIds: core.getKnownLatencyProbeIds(),
                          }),
                        },
                        probeProgress: {
                          running: true,
                          completed: index + 1,
                          total,
                          currentNodeName: nodeName,
                          cancelled: false,
                        },
                      }));
                    }
                    stepNext(index + 1);
                  })
                  .catch(() => {
                    if (previewProbeCancelled) {
                      finishPreview(true, core.getState().probeProgress.completed);
                      return;
                    }
                    stepNext(index + 1);
                  });
              }, 120);
            };

            stepNext(0);
          });
        },
        { mascot: true }
      );
    },

    async pauseIsolatedProbesBg(): Promise<void> {
      const state = core.getState();
      if (!state.probeProgress.running && !state.bgTasks.probeLocalStarting) return;
      if (state.bgTasks.probeIsPausing) return;

      core.setProbePauseRequested(true);
      core.updateBgTasks((bg) => ({ ...bg, probeIsPausing: true }));

      if (!isTauriEnv()) {
        previewProbeCancelled = true;
        clearPreviewProbeTimer();
        try {
          await catcloudApi.cancelIsolatedProbes();
        } catch {
          /* ignore mock cancel errors */
        }
        const cur = core.getState();
        const doneCount = cur.probeProgress.completed;
        const total = cur.probeProgress.total;
        const pendingResolve = previewProbeFinishResolve;
        previewProbeFinishResolve = null;
        core.setProbePendingQueue([]);
        core.setProbePauseRequested(false);
        core.setState((prev) => ({
          ...prev,
          probeProgress: {
            running: false,
            completed: doneCount,
            total,
            currentNodeName: null,
            cancelled: true,
          },
          bgTasks: {
            ...prev.bgTasks,
            probeLocalStarting: false,
            probeIsPausing: false,
            probeActiveNodeIds: [],
            probeLockedOrderIds: [],
          },
        }));
        pendingResolve?.();
        core.pushToast(`已暂停测速，已测完的 ${doneCount} 个节点结果已全部保留`, "info");
        return;
      }

      try {
        const wasRunning = await catcloudApi.cancelIsolatedProbes();
        const ownedByStore = core.inFlightTasks.has("probes:isolated");
        if (!ownedByStore && !wasRunning) {
          core.flushProbeBatch();
          const doneCount = core.getState().probeProgress.completed;
          core.setProbePendingQueue([]);
          core.setProbePauseRequested(false);
          core.setState((prev) => ({
            ...prev,
            probeProgress: {
              ...prev.probeProgress,
              running: false,
              currentNodeName: null,
              cancelled: true,
            },
            bgTasks: {
              ...prev.bgTasks,
              probeLocalStarting: false,
              probeIsPausing: false,
              probeActiveNodeIds: [],
              probeLockedOrderIds: [],
            },
          }));
          core.pushToast(`已暂停测速，已测完的 ${doneCount} 个节点结果已全部保留`, "info");
        }
      } catch (err) {
        core.setProbePauseRequested(false);
        core.updateBgTasks((bg) => ({ ...bg, probeIsPausing: false }));
        core.pushToast(`暂停测速失败：${formatErrorMessage(err)}`, "warn");
      }
    },

    setSubsImporting(importing: boolean): void {
      core.updateBgTasks((bg) =>
        bg.subs.importing === importing ? bg : { ...bg, subs: { ...bg.subs, importing } }
      );
    },

    async runRefreshAllSubscriptions(): Promise<void> {
      if (core.getState().subscriptions.length === 0) return;
      return core.runInFlight(
        "subs:refreshAll",
        async () => {
          core.updateBgTasks((bg) => ({
            ...bg,
            subs: { ...bg.subs, refreshingAll: true },
          }));
          try {
            if (isTauriEnv()) {
              const res = await catcloudApi.refreshAllSubscriptions();
              const [subsRes, nodesRes, groupsRes, rtRes, cfgRes] = await Promise.allSettled([
                catcloudApi.listSubscriptions(),
                catcloudApi.listNodes(),
                catcloudApi.listGroups(),
                catcloudApi.getRuntimeInfo(),
                catcloudApi.getConfig(),
              ]);
              core.setState((prev) => ({
                ...prev,
                subscriptions: subsRes.status === "fulfilled" ? subsRes.value : prev.subscriptions,
                nodes: nodesRes.status === "fulfilled" ? nodesRes.value : prev.nodes,
                groups: groupsRes.status === "fulfilled" ? groupsRes.value : prev.groups,
                runtime: rtRes.status === "fulfilled" ? rtRes.value : prev.runtime,
                config:
                  cfgRes.status === "fulfilled"
                    ? mergeIncomingAppConfig(cfgRes.value, prev.config)
                    : prev.config,
              }));
              if (res.errors.length > 0) {
                core.pushToast(
                  `已刷新 ${res.refreshed} 个订阅（共 ${res.total_nodes} 节点），${res.errors.length} 个失败：${formatErrorMessage(res.errors[0])}`,
                  "warn"
                );
              } else {
                core.pushToast(
                  `已刷新 ${res.refreshed} 个启用订阅，共 ${res.total_nodes} 个节点`,
                  "ok"
                );
              }
            } else {
              await new Promise<void>((r) => window.setTimeout(r, 260));
              const nowIso = new Date().toISOString();
              let refreshedCount = 0;
              core.setState((prev) => {
                const nextSubs = prev.subscriptions.map((item) => {
                  if (!item.enabled) return item;
                  refreshedCount += 1;
                  return { ...item, last_ok_at: nowIso, last_error: null };
                });
                return { ...prev, subscriptions: nextSubs };
              });
              core.pushToast(`已刷新 ${refreshedCount} 个已启用的订阅`, "ok");
            }
          } catch (err) {
            core.pushToast(`批量刷新订阅失败：${formatErrorMessage(err)}`, "warn");
          } finally {
            core.updateBgTasks((bg) => ({
              ...bg,
              subs: { ...bg.subs, refreshingAll: false },
            }));
          }
        },
        { mascot: "typing", celebrate: true }
      );
    },

    async runRefreshSingleSubscription(
      subId: string,
      options?: { simulateFault?: boolean }
    ): Promise<void> {
      if (core.getState().bgTasks.subs.refreshingAll) {
        core.pushToast("正在批量刷新全部订阅，请稍候", "info");
        return;
      }
      const simulateFault = Boolean(options?.simulateFault);

      return core.runInFlight(
        `subs:refresh:${subId}`,
        async () => {
          core.updateBgTasks((bg) => ({
            ...bg,
            subs: {
              ...bg.subs,
              refreshingIds: bg.subs.refreshingIds.includes(subId)
                ? bg.subs.refreshingIds
                : [...bg.subs.refreshingIds, subId],
            },
          }));

          const resolveSubName = () =>
            core.getState().subscriptions.find((item) => item.id === subId)?.name ?? "当前订阅";

          try {
            if (isTauriEnv() && !simulateFault) {
              const res = await catcloudApi.refreshSubscription(subId);
              const [subsRes, nodesRes, groupsRes, rtRes, cfgRes] = await Promise.allSettled([
                catcloudApi.listSubscriptions(),
                catcloudApi.listNodes(),
                catcloudApi.listGroups(),
                catcloudApi.getRuntimeInfo(),
                catcloudApi.getConfig(),
              ]);
              core.setState((prev) => ({
                ...prev,
                subscriptions: subsRes.status === "fulfilled" ? subsRes.value : prev.subscriptions,
                nodes: nodesRes.status === "fulfilled" ? nodesRes.value : prev.nodes,
                groups: groupsRes.status === "fulfilled" ? groupsRes.value : prev.groups,
                runtime: rtRes.status === "fulfilled" ? rtRes.value : prev.runtime,
                config:
                  cfgRes.status === "fulfilled"
                    ? mergeIncomingAppConfig(cfgRes.value, prev.config)
                    : prev.config,
              }));
              const warnNote =
                res.warnings.length > 0
                  ? `（提醒：${formatErrorMessage(res.warnings[0])}）`
                  : "";
              core.pushToast(
                `${resolveSubName()} 已刷新，当前 ${res.node_count} 个节点${warnNote}`,
                res.warnings.length > 0 ? "warn" : "ok"
              );
              return;
            }

            await new Promise<void>((r) => window.setTimeout(r, 240));
            const nowIso = new Date().toISOString();
            if (simulateFault) {
              const errMsg =
                "远端返回异常或 0 个节点，已自动中止覆盖并保留现有老节点与自建规则";
              core.setState((prev) => ({
                ...prev,
                subscriptions: prev.subscriptions.map((item) =>
                  item.id === subId ? { ...item, last_error: errMsg } : item
                ),
              }));
              core.pushToast(
                `${resolveSubName()} 刷新异常（预览演练）：已自动保护老节点与自建规则`,
                "warn"
              );
            } else {
              core.setState((prev) => ({
                ...prev,
                subscriptions: prev.subscriptions.map((item) =>
                  item.id === subId ? { ...item, last_ok_at: nowIso, last_error: null } : item
                ),
              }));
              core.pushToast(`${resolveSubName()} 已安全刷新`, "ok");
            }
          } catch (err) {
            const errMsg = formatErrorMessage(err);
            core.setState((prev) => ({
              ...prev,
              subscriptions: prev.subscriptions.map((item) =>
                item.id === subId ? { ...item, last_error: errMsg } : item
              ),
            }));
            core.pushToast(
              `${resolveSubName()} 刷新失败（已保留现有节点）：${errMsg}`,
              "warn"
            );
          } finally {
            core.updateBgTasks((bg) => ({
              ...bg,
              subs: {
                ...bg.subs,
                refreshingIds: bg.subs.refreshingIds.filter((id) => id !== subId),
              },
            }));
          }
        },
        { mascot: "typing", celebrate: true }
      );
    },

    async runMultiGroupNodeProbe(nodeId: string): Promise<void> {
      const taskKey = `groups:probe:${nodeId}`;
      const existing = core.inFlightTasks.get(taskKey);
      if (existing) {
        return existing as Promise<void>;
      }
      if (selectIsProbeEngineBusy(core.getState())) {
        core.pushToast("当前已有测速或对比任务正在进行，请稍候完成后再试", "info");
        return;
      }

      return core.runInFlight(
        taskKey,
        async () => {
          core.updateBgTasks((bg) => ({
            ...bg,
            probeLocalStarting: true,
            probeActiveNodeIds: bg.probeActiveNodeIds.includes(nodeId)
              ? bg.probeActiveNodeIds
              : [...bg.probeActiveNodeIds, nodeId],
            groups: {
              ...bg.groups,
              probingNodeIds: bg.groups.probingNodeIds.includes(nodeId)
                ? bg.groups.probingNodeIds
                : [...bg.groups.probingNodeIds, nodeId],
            },
          }));
          try {
            const res = await catcloudApi.runIsolatedProbes([nodeId], [], "unlock", false);
            if (res.snapshots && Object.keys(res.snapshots).length > 0) {
              core.setState((prev) => {
                const nextProbes = { ...prev.probes };
                const knownLatencyIds = core.getKnownLatencyProbeIds();
                for (const [nid, incoming] of Object.entries(res.snapshots)) {
                  nextProbes[nid] = mergeProbeSnapshotSafe(prev.probes[nid], incoming, {
                    authoritative: isTauriEnv(),
                    latencyProbeIds: knownLatencyIds,
                  });
                }
                return { ...prev, probes: nextProbes };
              });
            }
            const nodeName = core.getState().nodes.find((n) => n.id === nodeId)?.name ?? nodeId;
            const snap = res.snapshots?.[nodeId];
            if (snap && snap.ok && snap.latency_ms !== null) {
              core.pushToast(`测速完成：${nodeName} · ${Math.round(snap.latency_ms)} ms`, "ok");
            } else if (res.errors.length > 0) {
              core.pushToast(`测速提示：${res.errors[0]}`, "warn");
            } else {
              core.pushToast(`${nodeName} 暂时连接超时，可稍后再试`, "warn");
            }
          } catch (err) {
            core.pushToast(`测速失败：${formatErrorMessage(err)}`, "warn");
          } finally {
            core.updateBgTasks((bg) => ({
              ...bg,
              probeLocalStarting: false,
              probeActiveNodeIds: bg.probeActiveNodeIds.filter((id) => id !== nodeId),
              groups: {
                ...bg.groups,
                probingNodeIds: bg.groups.probingNodeIds.filter((id) => id !== nodeId),
              },
            }));
          }
        },
        { mascot: true }
      );
    },

    async runEvaluateMultiGroup(groupId: string): Promise<void> {
      return core.runInFlight(
        "groups:eval",
        async () => {
          core.updateBgTasks((bg) => ({
            ...bg,
            groups: { ...bg.groups, evaluatingGroupId: groupId },
          }));
          try {
            const report = await catcloudApi.evaluateMultiGroup(groupId);
            core.updateBgTasks((bg) => ({
              ...bg,
              groups: {
                ...bg.groups,
                evalReports: {
                  ...bg.groups.evalReports,
                  [groupId]: report,
                },
              },
            }));
            const state = core.getState();
            const latestProbes = state.probes;
            const targetGroup = state.groups.find((g) => g.id === groupId);
            const evalIds = new Set<string>();
            for (const c of report.gate_passed) evalIds.add(c.node_id);
            for (const c of report.gate_rejected) evalIds.add(c.node_id);
            if (evalIds.size === 0 && targetGroup) {
              for (const id of targetGroup.member_node_ids) evalIds.add(id);
            }
            let untestedCnt = 0;
            for (const id of evalIds) {
              if (!latestProbes[id]) untestedCnt += 1;
            }
            core.pushToast(
              untestedCnt > 0
                ? `评估完成：候选 ${report.pool_size} 个 · 达标 ${report.healthy_candidates.length} 个（其中 ${untestedCnt} 个尚未测速）`
                : `评估完成：候选 ${report.pool_size} 个 · 达标 ${report.healthy_candidates.length} 个`,
              "ok"
            );
          } catch (err) {
            core.pushToast(`后端评估失败：${formatErrorMessage(err)}`, "warn");
          } finally {
            core.updateBgTasks((bg) => ({
              ...bg,
              groups: {
                ...bg.groups,
                evaluatingGroupId:
                  bg.groups.evaluatingGroupId === groupId ? null : bg.groups.evaluatingGroupId,
              },
            }));
          }
        },
        { mascot: "thinking", celebrate: true }
      );
    },
  };

  return {
    actions,
    dispose(): void {
      clearPreviewProbeTimer();
      previewProbeCancelled = true;
      previewProbeFinishResolve?.();
      previewProbeFinishResolve = null;
    },
  };
}
