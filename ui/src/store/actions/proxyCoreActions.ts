import {
  type CoreRuntimeInfo,
  type ProxyMode,
  catcloudApi,
  formatErrorMessage,
  isTauriEnv,
} from "../../api/tauri";
import { resolvePlatformOs } from "../../utils/platform";
import { isRealWinDivertActive } from "../../utils/preaccelStatus";
import { type StoreCore, alignConfigWithRuntimeTun, mergeIncomingAppConfig } from "../core";
import { buildPendingExitIp } from "../types";

export function createProxyCoreActions(core: StoreCore) {
  function openTunAdminPrompt(reason: string | null = null): void {
    core.setState((prev) => ({
      ...prev,
      tunAdminPromptOpen: true,
      tunAdminPromptBusy: false,
      tunAdminPromptReason: reason?.trim() || null,
    }));
  }

  return {
    async refreshRuntime(): Promise<CoreRuntimeInfo | null> {
      try {
        const wasRunning = core.getState().runtime.running;
        const nextRuntime = await catcloudApi.getRuntimeInfo();
        if (wasRunning && !nextRuntime.running) {
          core.recordTrafficStopSample(true);
        }
        core.setState((prev) => ({
          ...prev,
          config: alignConfigWithRuntimeTun(prev.config, nextRuntime),
          runtime: nextRuntime,
        }));
        return nextRuntime;
      } catch {
        return null;
      }
    },

    async selectSingleNode(nodeId: string): Promise<void> {
      try {
        const rt = await catcloudApi.selectSingleNode(nodeId);
        const matchedNode = core.getState().nodes.find((n) => n.id === nodeId);
        const nextRuntime: CoreRuntimeInfo = {
          ...rt,
          route_mode: "single",
          active_node_id: rt.active_node_id || nodeId,
          active_node_name: rt.active_node_name || matchedNode?.name || nodeId,
        };
        core.setState((prev) => ({
          ...prev,
          runtime: nextRuntime,
          exitIp: buildPendingExitIp(nextRuntime.running),
        }));
        core.pushToast(`已切换为单节点模式：${nextRuntime.active_node_name}`, "ok");
      } catch (err) {
        core.pushToast(`切换单节点失败：${formatErrorMessage(err)}`, "warn");
      }
    },

    async setActiveGroup(groupId: string): Promise<void> {
      try {
        const rt = await catcloudApi.setActiveGroup(groupId);
        const nextRuntime: CoreRuntimeInfo = {
          ...rt,
          route_mode: "group",
        };
        core.setState((prev) => ({
          ...prev,
          runtime: nextRuntime,
          exitIp: buildPendingExitIp(nextRuntime.running),
        }));
        core.pushToast(`已切换当前分组：${nextRuntime.active_group_name}`, "ok");
      } catch (err) {
        core.pushToast(`切换分组失败：${formatErrorMessage(err)}`, "warn");
      }
    },

    async selectGroupNode(
      groupId: string,
      nodeId: string,
      closeOld = true,
      activateGroup?: boolean
    ): Promise<void> {
      try {
        const state = core.getState();
        const targetGroup = state.groups.find((g) => g.id === groupId);
        const keepPrimaryUnchanged =
          activateGroup === false ||
          (activateGroup === undefined &&
            Boolean(targetGroup?.independent_routing) &&
            state.runtime.route_mode === "group" &&
            Boolean(state.runtime.active_group_id) &&
            state.runtime.active_group_id !== groupId);
        const res = await catcloudApi.selectGroupNode(
          groupId,
          nodeId,
          closeOld,
          keepPrimaryUnchanged ? false : activateGroup
        );
        const rt = await catcloudApi.getRuntimeInfo();
        const nextRuntime: CoreRuntimeInfo = keepPrimaryUnchanged
          ? { ...rt }
          : {
              ...rt,
              route_mode: "group",
              active_group_id: rt.active_group_id || res.group_id,
              active_node_id: rt.active_node_id || res.active_node_id,
              active_node_name: rt.active_node_name || res.active_node_name,
            };
        core.setState((prev) => ({
          ...prev,
          runtime: nextRuntime,
          exitIp: keepPrimaryUnchanged ? prev.exitIp : buildPendingExitIp(nextRuntime.running),
          groups: prev.groups.map((g) =>
            g.id === res.group_id ? { ...g, active_node_id: res.active_node_id } : g
          ),
        }));
        if (keepPrimaryUnchanged && targetGroup) {
          core.pushToast(
            `已将独立分流组「${targetGroup.name}」出口切至：${res.active_node_name}（主兜底组保持不变）`,
            "ok"
          );
        } else {
          core.pushToast(`已切换至：${res.active_node_name}`, "ok");
        }
      } catch (err) {
        core.pushToast(`切换节点失败：${formatErrorMessage(err)}`, "warn");
      }
    },

    async setProxyMode(mode: ProxyMode): Promise<void> {
      try {
        const applied = await catcloudApi.setProxyMode(mode);
        const labelMap: Record<ProxyMode, string> = {
          rule: "规则模式",
          global: "全局模式",
          direct: "直连模式",
        };
        core.setState((prev) => ({
          ...prev,
          config: { ...prev.config, proxy_mode: applied },
          runtime: { ...prev.runtime, proxy_mode: applied },
          exitIp: buildPendingExitIp(prev.runtime.running),
        }));
        core.pushToast(`已切换至${labelMap[applied]}`, "ok");
      } catch (err) {
        core.pushToast(`切换代理模式失败：${formatErrorMessage(err)}`, "warn");
      }
    },

    async toggleSystemProxy(next?: boolean, silent = false): Promise<boolean> {
      const target = next ?? !core.getState().runtime.system_proxy_enabled;
      try {
        const applied = await catcloudApi.toggleSystemProxy(target);
        core.setState((prev) => ({
          ...prev,
          config: { ...prev.config, system_proxy_enabled: applied },
          runtime: { ...prev.runtime, system_proxy_enabled: applied },
        }));
        if (!silent) {
          core.pushToast(applied ? "系统代理已开启" : "系统代理已关闭", applied ? "ok" : "info");
        }
        return true;
      } catch (err) {
        core.pushToast(`切换系统代理失败：${formatErrorMessage(err)}`, "warn");
        return false;
      }
    },

    openTunAdminPrompt,

    closeTunAdminPrompt(): void {
      core.setState((prev) =>
        prev.tunAdminPromptOpen || prev.tunAdminPromptBusy
          ? {
              ...prev,
              tunAdminPromptOpen: false,
              tunAdminPromptBusy: false,
              tunAdminPromptReason: null,
            }
          : prev
      );
    },

    async relaunchAsAdminForTun(): Promise<boolean> {
      const state = core.getState();
      if (state.tunAdminPromptBusy) return false;
      const os = resolvePlatformOs(state.runtime.os_label);
      core.setState((prev) => ({ ...prev, tunAdminPromptBusy: true }));
      try {
        const launched = await catcloudApi.relaunchAsAdmin(true);
        if (launched) {
          if (!isTauriEnv()) {
            const [cfg, rt] = await Promise.all([
              catcloudApi.getConfig(),
              catcloudApi.getRuntimeInfo(),
            ]);
            core.setState((prev) => ({
              ...prev,
              config: cfg,
              runtime: rt,
              tunAdminPromptOpen: false,
              tunAdminPromptBusy: false,
              tunAdminPromptReason: null,
            }));
            core.pushToast("演示模式：已模拟完成提权并开启虚拟网卡", "ok");
          } else if (os === "linux") {
            const [cfgRes, rtRes] = await Promise.allSettled([
              catcloudApi.getConfig(),
              catcloudApi.getRuntimeInfo(),
            ]);
            core.setState((prev) => ({
              ...prev,
              config:
                cfgRes.status === "fulfilled"
                  ? mergeIncomingAppConfig(cfgRes.value, prev.config)
                  : prev.config,
              runtime: rtRes.status === "fulfilled" ? rtRes.value : prev.runtime,
              tunAdminPromptOpen: false,
              tunAdminPromptBusy: false,
              tunAdminPromptReason: null,
            }));
            core.pushToast("已为代理核心授予网络权限，虚拟网卡已就绪", "ok", 4000);
          } else {
            core.setState((prev) => ({
              ...prev,
              tunAdminPromptOpen: false,
              tunAdminPromptBusy: false,
              tunAdminPromptReason: null,
            }));
            core.pushToast(
              os === "macos"
                ? "已发起系统安全授权，正在开启虚拟网卡…"
                : "已拉起管理员实例，正在接管并开启虚拟网卡…",
              "ok"
            );
          }
          return true;
        }
        core.setState((prev) => ({
          ...prev,
          tunAdminPromptOpen: false,
          tunAdminPromptBusy: false,
          tunAdminPromptReason: null,
        }));
        core.pushToast("已取消系统授权，虚拟网卡未开启", "info");
        return false;
      } catch (err) {
        core.setState((prev) => ({ ...prev, tunAdminPromptBusy: false }));
        core.pushToast(
          os === "linux"
            ? `授予核心网络权限失败：${formatErrorMessage(err)}`
            : `系统授权启动失败：${formatErrorMessage(err)}`,
          "warn"
        );
        return false;
      }
    },

    async toggleTun(next?: boolean, silent = false): Promise<boolean> {
      const state = core.getState();
      if (next === undefined && state.runtime.tun_needs_elevation) {
        openTunAdminPrompt(null);
        return false;
      }
      const target = next ?? !state.runtime.tun_enabled;
      if (target && state.runtime.tun_admin_ready === false) {
        openTunAdminPrompt(null);
        return false;
      }
      try {
        const applied = await catcloudApi.toggleTun(target);
        core.setState((prev) => {
          const nextConfigured = target ? applied || prev.config.tun_enabled : false;
          const nextEffective = target ? applied : false;
          const nextNeedsElevation =
            nextConfigured && !prev.runtime.tun_admin_ready && !nextEffective;
          return {
            ...prev,
            config: { ...prev.config, tun_enabled: nextConfigured },
            runtime: {
              ...prev.runtime,
              tun_enabled: nextEffective,
              tun_configured: nextConfigured,
              tun_needs_elevation: nextNeedsElevation,
            },
          };
        });
        if (!silent) {
          core.pushToast(
            target && applied ? "虚拟网卡已开启" : "虚拟网卡已关闭",
            target && applied ? "ok" : "info"
          );
        }
        return true;
      } catch (err) {
        const msg = formatErrorMessage(err);
        const adminPrefix = "NEEDS_ADMIN:";
        const adminIdx = msg.indexOf(adminPrefix);
        if (target && adminIdx >= 0) {
          const detail = msg.slice(adminIdx + adminPrefix.length).trim() || null;
          core.setState((prev) => ({
            ...prev,
            runtime: {
              ...prev.runtime,
              tun_admin_ready: false,
              tun_enabled: false,
              tun_needs_elevation: Boolean(prev.runtime.tun_configured ?? prev.config.tun_enabled),
            },
            tunAdminPromptOpen: true,
            tunAdminPromptBusy: false,
            tunAdminPromptReason: detail,
          }));
          return false;
        }
        core.pushToast(`切换虚拟网卡失败：${msg}`, "warn");
        return false;
      }
    },

    async disableAllProxyAndStopCore(): Promise<boolean> {
      try {
        const nextRt = await catcloudApi.disableAllProxyAndStopCore();
        core.recordTrafficStopSample(true);

        const nextGlobal = await catcloudApi.getGlobalPreAccelStatus().catch(() => null);
        core.setState((prev) => ({
          ...prev,
          config: {
            ...prev.config,
            system_proxy_enabled: nextRt.system_proxy_enabled,
            tun_enabled:
              typeof nextRt.tun_configured === "boolean"
                ? nextRt.tun_configured
                : prev.config.tun_enabled,
          },
          runtime: nextRt,
          globalPreAccel: nextGlobal ?? prev.globalPreAccel,
          exitIp: buildPendingExitIp(nextRt.running),
        }));

        const realWinDivert = isRealWinDivertActive(
          nextRt,
          nextGlobal ?? core.getState().globalPreAccel
        );
        core.pushToast(
          realWinDivert
            ? "已关闭猫猫代理并停止主核（全局国内提速继续运行中）"
            : "已关闭代理并停止核心，释放内存与本地端口",
          "info"
        );
        return true;
      } catch (err) {
        core.pushToast(`关闭代理并停止核心失败：${formatErrorMessage(err)}`, "warn", 4200);
        return false;
      }
    },

    async enableProxyPower(): Promise<CoreRuntimeInfo> {
      try {
        const nextRt = await catcloudApi.enableProxyPower();
        const [cfgRes, globalRes] = await Promise.allSettled([
          catcloudApi.getConfig(),
          catcloudApi.getGlobalPreAccelStatus(),
        ]);
        core.setState((prev) => {
          const baseCfg =
            cfgRes.status === "fulfilled"
              ? mergeIncomingAppConfig(cfgRes.value, prev.config)
              : {
                  ...prev.config,
                  system_proxy_enabled: nextRt.system_proxy_enabled,
                  tun_enabled:
                    typeof nextRt.tun_configured === "boolean"
                      ? nextRt.tun_configured
                      : nextRt.tun_enabled,
                };
          return {
            ...prev,
            config: alignConfigWithRuntimeTun(baseCfg, nextRt),
            runtime: nextRt,
            globalPreAccel:
              globalRes.status === "fulfilled" ? globalRes.value : prev.globalPreAccel,
            exitIp: buildPendingExitIp(nextRt.running),
          };
        });
        if (nextRt.tun_enabled && nextRt.system_proxy_enabled) {
          core.pushToast("已开启代理（虚拟网卡 + 系统代理）", "ok");
        } else if (nextRt.tun_enabled) {
          core.pushToast("已开启代理（虚拟网卡已恢复）", "ok");
        } else if (nextRt.system_proxy_enabled) {
          core.pushToast("已开启系统代理", "ok");
        }
        return nextRt;
      } catch (err) {
        core.pushToast(`开启代理失败：${formatErrorMessage(err)}`, "warn", 4200);
        throw err;
      }
    },

    async switchNextBestNode(): Promise<void> {
      const state = core.getState();
      const isSingleMode = state.runtime.route_mode === "single";
      const targetId = isSingleMode
        ? "single"
        : state.runtime.active_group_id || state.groups[0]?.id || "";
      if (!isSingleMode && !targetId) {
        core.pushToast("当前暂无可用多选组，请先在「智能多选组」中创建", "warn");
        return;
      }
      core.setState((prev) => ({ ...prev, mascotState: "thinking" }));
      try {
        const res = await catcloudApi.switchNextBestNode(targetId);
        core.setState((prev) => ({
          ...prev,
          mascotState: "complete",
          exitIp: buildPendingExitIp(prev.runtime.running),
          runtime: {
            ...prev.runtime,
            ...(isSingleMode
              ? { route_mode: "single" as const }
              : { active_group_id: res.group_id || prev.runtime.active_group_id }),
            active_node_id: res.active_node_id,
            active_node_name: res.active_node_name,
            active_node_region: res.active_node_region,
            active_node_latency_ms: res.latency_ms,
            active_node_up_mbps: res.up_mbps,
          },
          groups: isSingleMode
            ? prev.groups
            : prev.groups.map((g) =>
                g.id === res.group_id ? { ...g, active_node_id: res.active_node_id } : g
              ),
        }));
        core.pushToast(
          `已秒切至 ${res.active_node_name}（清理 ${res.closed_connections} 条旧连接）`,
          "ok"
        );
        core.celebrateMascotComplete(4000);
      } catch (err) {
        core.setState((prev) => ({ ...prev, mascotState: "idle" }));
        core.pushToast(`切换次优节点失败：${formatErrorMessage(err)}`, "warn");
      }
    },

    async runCoreOperation(
      op: "start" | "stop" | "restart" | "reload" | "hotswap",
      binaryPath?: string
    ): Promise<boolean> {
      if (op === "hotswap" && !binaryPath?.trim()) {
        core.pushToast("请先输入内核程序的完整路径", "warn");
        return false;
      }
      const existing = core.inFlightTasks.get("settings:coreOp");
      if (existing) {
        if (core.getState().bgTasks.settings.coreOpBusy !== op) {
          core.pushToast("已有内核操作正在执行，请稍候", "info");
        }
        return existing as Promise<boolean>;
      }
      return core.runInFlight(
        "settings:coreOp",
        async () => {
          core.patchSettingsBg({ coreOpBusy: op });
          try {
            if (op === "reload") {
              const outcome = await catcloudApi.reloadCoreConfig(false);
              const rt = await catcloudApi.getRuntimeInfo();
              core.setState((prev) => ({ ...prev, runtime: rt }));
              if (outcome.rejected || outcome.error) {
                core.pushToast(
                  `热重载未生效：${outcome.error ?? "配置校验未通过"}`,
                  "warn"
                );
                return false;
              }
              core.pushToast("配置已热重载", "ok");
              return true;
            }
            if (op === "hotswap") {
              const res = await catcloudApi.hotSwapCore(binaryPath!.trim());
              const rt = await catcloudApi.getRuntimeInfo();
              core.setState((prev) => ({ ...prev, runtime: rt }));
              core.pushToast(
                res.ok
                  ? `内核热换成功：${res.version ?? res.binary_path}`
                  : `内核热换失败：${res.message}`,
                res.ok ? "ok" : "warn"
              );
              return Boolean(res.ok);
            }
            const rt =
              op === "start"
                ? await catcloudApi.startCore()
                : op === "stop"
                  ? await catcloudApi.stopCore()
                  : await catcloudApi.restartCore();
            core.setState((prev) => ({ ...prev, runtime: rt }));
            const labels = {
              start: "内核已启动",
              stop: "内核已停止",
              restart: "内核已重启",
            };
            core.pushToast(labels[op], "ok");
            return true;
          } catch (err) {
            core.pushToast(
              op === "hotswap"
                ? `内核热换失败：${formatErrorMessage(err)}`
                : `内核操作失败：${formatErrorMessage(err)}`,
              "warn"
            );
            return false;
          } finally {
            core.patchSettingsBg({ coreOpBusy: null });
          }
        },
        { mascot: "thinking", celebrate: true }
      );
    },

    async runBackupOperation(
      op: "export" | "import",
      fn: () => Promise<void>
    ): Promise<void> {
      const existing = core.inFlightTasks.get("settings:backupOp");
      if (existing) {
        core.pushToast("正在处理备份导入/导出，请稍候", "info");
        return existing as Promise<void>;
      }
      return core.runInFlight(
        "settings:backupOp",
        async () => {
          core.patchSettingsBg({ backupBusy: op });
          try {
            await fn();
          } finally {
            core.patchSettingsBg({ backupBusy: null });
          }
        },
        { mascot: "typing", celebrate: true }
      );
    },
  };
}
