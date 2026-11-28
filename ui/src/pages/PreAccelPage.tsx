import {
  ArrowLeftRight,
  Bot,
  ChevronDown,
  ChevronRight,
  Gauge,
  Layers,
  Loader2,
  Package,
  Plus,
  RefreshCw,
  Router,
  SlidersHorizontal,
  Sparkles,
  Upload,
  X,
  Zap,
} from "lucide-react";
import { Suspense, type FormEvent, lazy, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  type AppConfig,
  type GlobalPreAccelScope,
  type PreAccelDispatchStrategy,
  type PreAccelLbStrategy,
  type PreAccelRelay,
  catcloudApi,
  formatErrorMessage,
  isTauriEnv,
} from "../api/tauri";
import { formatBytes } from "../components/TrafficSparkline";
import { formatI18nTemplate, normalizeUiLanguage, useUiDict } from "../i18n";
import {
  appActions,
  appStore,
  selectIsProbeEngineBusy,
  useAppSelector,
} from "../store/appStore";
import { copyText } from "../utils/clipboard";
import { DEFAULT_GLOBAL_TARGET_PROCESSES, resolvePlatformOs } from "../utils/platform";
import { resolvePreAccelSummary } from "../utils/preaccelStatus";
import { resolveNodeRegionCode } from "../utils/regions";
import { isBoolPref, usePersistedState } from "../utils/uiPrefs";
import { AddRelayModal } from "./preaccel/AddRelayModal";
import { CampusPortalCard } from "./preaccel/CampusPortalCard";
import { DeleteRelayModal } from "./preaccel/DeleteRelayModal";
import { ProbeSourceModal } from "./preaccel/ProbeSourceModal";
import { RelayCardItem } from "./preaccel/RelayCardItem";
import {
  type AddModalTab,
  dedupeProcessStats,
  formatClockStamp,
  formatDetectedByLabel,
  hasValidLatency,
  isUdpOnlyProto,
  validateDomesticProbeUrl,
} from "./preaccel/relayImportParser";
import { SpeedCompareCard } from "./preaccel/SpeedCompareCard";
import { TopStatusCard } from "./preaccel/TopStatusCard";
import { WinDivertDiagPanel } from "./preaccel/WinDivertDiagPanel";

const GatewayExportModal = lazy(() => import("../components/GatewayExportModal"));
const ShareBundleModal = lazy(() =>
  import("../components/ShareBundleModal").then((m) => ({ default: m.ShareBundleModal }))
);

export function PreAccelPage() {
  const config = useAppSelector((s) => s.config);
  const uiLang = normalizeUiLanguage(config.personalization.ui_language);
  const dict = useUiDict(uiLang);
  const runtime = useAppSelector((s) => s.runtime);
  const globalPreAccel = useAppSelector((s) => s.globalPreAccel);
  const storeRelays = useAppSelector((s) => s.preAccelRelays);
  const relayChainLatencies = useAppSelector((s) => s.relayChainLatencies);
  const groups = useAppSelector((s) => s.groups);
  const nodes = useAppSelector((s) => s.nodes);
  const initialized = useAppSelector((s) => s.initialized);
  const bgPreaccel = useAppSelector((s) => s.bgTasks.preaccel);
  const preAccelDraft = useAppSelector((s) => s.sessionDrafts.preAccel);
  const probeRunning = useAppSelector(
    (s) => s.probeProgress.running || s.bgTasks.probeLocalStarting
  );
  const isProbeEngineBusy = useAppSelector(selectIsProbeEngineBusy);
  const inTauri = isTauriEnv();
  const platformOs = resolvePlatformOs(runtime.os_label);

  const enabled = config.preaccel.enabled;
  const dispatchStrategy: PreAccelDispatchStrategy = config.preaccel.dispatch_strategy ?? "auto";
  const activeRelayId: string | null = config?.preaccel.active_relay_id ?? null;
  const lbStrategy: PreAccelLbStrategy = config.preaccel.lb_strategy ?? "consistent_hashing";
  const [savingDispatch, setSavingDispatch] = useState(false);
  const [togglingEnabled, setTogglingEnabled] = useState(false);
  const [advancedOpen, setAdvancedOpen] = usePersistedState<boolean>(
    "preaccel.advancedOpen",
    false,
    isBoolPref
  );
  const [savingGlobalScope, setSavingGlobalScope] = useState(false);
  const [elevatingGlobal, setElevatingGlobal] = useState(false);
  const [refreshingGlobal, setRefreshingGlobal] = useState(false);
  const [globalScope, setGlobalScope] = useState<GlobalPreAccelScope>(
    config.preaccel.global_scope ?? "proxy_apps_only"
  );
  const [targetProcesses, setTargetProcesses] = useState<string[]>(() =>
    Array.isArray(config.preaccel?.global_target_processes)
      ? config.preaccel.global_target_processes
      : [...DEFAULT_GLOBAL_TARGET_PROCESSES]
  );
  const [copiedGlobalAddr, setCopiedGlobalAddr] = useState(false);
  const [skip443Native, setSkip443Native] = useState<boolean>(config.preaccel.skip_443_native);
  const [campusPortalGuard, setCampusPortalGuard] = useState<boolean>(
    config.preaccel.campus_portal_guard ?? true
  );
  const [savingCampusGuard, setSavingCampusGuard] = useState(false);
  const [probeUrl, setProbeUrl] = useState<string>(config.preaccel.probe_url);
  const [relays, setRelays] = useState<PreAccelRelay[]>(storeRelays);
  const [failoverBusy, setFailoverBusy] = useState(false);

  // Add Relay Modal & import warnings banner
  const [showAddModal, setShowAddModal] = useState(false);
  const [addModalTab, setAddModalTab] = useState<AddModalTab>("manual");
  const [importWarnings, setImportWarnings] = useState<string[]>([]);

  // Lightweight Advanced Modals (Probe URL, Share Bundle & Gateway Export)
  const [showProbeModal, setShowProbeModal] = useState(false);
  const [shareModalOpen, setShareModalOpen] = useState(false);
  const [shareModalMode, setShareModalMode] = useState<"export" | "import">("import");
  const [gatewayModalOpen, setGatewayModalOpen] = useState(false);
  const [pendingDeleteRelay, setPendingDeleteRelay] = useState<PreAccelRelay | null>(null);
  const [deletingRelay, setDeletingRelay] = useState(false);

  // Global background task bindings (survive page switches)
  const installingDriver = bgPreaccel.installingDriver;
  const verifyingGlobal = bgPreaccel.verifyingGlobal;
  const probingAll = bgPreaccel.relaysTestingAll;
  const probingIdsSet = useMemo(
    () => new Set(bgPreaccel.relaysTestingIds),
    [bgPreaccel.relaysTestingIds]
  );
  const speedTestingAll = bgPreaccel.relaysSpeedTestingAll;
  const speedTestingIdsSet = useMemo(
    () => new Set(bgPreaccel.relaysSpeedTestingIds),
    [bgPreaccel.relaysSpeedTestingIds]
  );
  const speedTestingAny = speedTestingAll || bgPreaccel.relaysSpeedTestingIds.length > 0;

  const benchmarking = bgPreaccel.benchmark.running;
  const comparison = bgPreaccel.benchmark.result;
  const comparisonError = bgPreaccel.benchmark.error;
  const comparisonFinishedAt = bgPreaccel.benchmark.finishedAt;
  const comparisonIsDemo = Boolean(comparison && !inTauri);
  const selectedCompareNodeId = preAccelDraft.selectedCompareNodeId;
  const setSelectedCompareNodeId = useCallback((nextNodeId: string) => {
    appActions.patchSessionDraft("preAccel", { selectedCompareNodeId: nextNodeId });
  }, []);

  const isOtherProbeRunning = probeRunning && !benchmarking;

  // Campus Network Auth Check Card (backed by global bgTasks.preaccel)
  const checkingPortal = bgPreaccel.campusChecking;
  const campusResult = bgPreaccel.campusResult;
  const campusError = bgPreaccel.campusError;
  const portalRequired = campusResult
    ? campusResult.captive_portal_required
    : runtime.captive_portal_required;
  const portalHttpCode: number | null = campusResult
    ? campusResult.status_code
    : inTauri
      ? null
      : runtime.captive_portal_required
        ? 302
        : 204;
  const portalRedirect = campusResult?.redirect_location ?? null;
  const portalBypassHosts = campusResult?.bypass_hosts ?? [];
  const portalLastCheck = campusResult?.checked_at
    ? formatClockStamp(campusResult.checked_at)
    : inTauri
      ? "尚未检测"
      : "演示态";

  const timersRef = useRef<number[]>([]);

  useEffect(() => {
    return () => {
      for (const id of timersRef.current) {
        window.clearTimeout(id);
      }
      timersRef.current = [];
    };
  }, []);

  useEffect(() => {
    if (initialized) {
      setRelays(storeRelays);
    }
  }, [storeRelays, initialized]);

  useEffect(() => {
    if (initialized) {
      setSkip443Native(config.preaccel.skip_443_native);
      if (typeof config.preaccel.campus_portal_guard === "boolean") {
        setCampusPortalGuard(config.preaccel.campus_portal_guard);
      }
      if (
        config.preaccel.global_scope === "proxy_apps_only" ||
        config.preaccel.global_scope === "all_non_443_tcp"
      ) {
        setGlobalScope(config.preaccel.global_scope);
      }
      if (Array.isArray(config.preaccel.global_target_processes)) {
        setTargetProcesses(config.preaccel.global_target_processes);
      }
      if (!showProbeModal) {
        setProbeUrl(config.preaccel.probe_url);
      }
    }
  }, [config.preaccel, initialized, showProbeModal]);

  useEffect(() => {
    void appActions.refreshGlobalPreAccelStatus();
  }, []);

  const installBusy =
    installingDriver ||
    globalPreAccel.install_state === "downloading" ||
    globalPreAccel.install_state === "verifying" ||
    runtime.preaccel_install_state === "downloading" ||
    runtime.preaccel_install_state === "verifying";

  const verifyProbingActive =
    verifyingGlobal ||
    globalPreAccel.verify_state === "probing" ||
    runtime.global_preaccel_verify_state === "probing";

  useEffect(() => {
    if (!enabled && !globalPreAccel.running && !installBusy && !verifyProbingActive) return;
    const intervalMs = installBusy || verifyProbingActive ? 1500 : 5000;
    const timer = window.setInterval(() => {
      if (typeof document !== "undefined" && document.visibilityState !== "visible") return;
      void appActions.refreshGlobalPreAccelStatus();
    }, intervalMs);
    return () => window.clearInterval(timer);
  }, [enabled, globalPreAccel.running, installBusy, verifyProbingActive]);

  useEffect(() => {
    let active = true;
    void catcloudApi
      .getFullConfig()
      .then((full) => {
        if (!active) return;
        const rawPreaccel = full.preaccel as
          | {
              campus_portal_guard?: unknown;
              global_scope?: unknown;
              global_target_processes?: unknown;
            }
          | undefined;
        if (typeof rawPreaccel?.campus_portal_guard === "boolean") {
          setCampusPortalGuard(rawPreaccel.campus_portal_guard);
        }
        if (
          rawPreaccel?.global_scope === "proxy_apps_only" ||
          rawPreaccel?.global_scope === "all_non_443_tcp"
        ) {
          setGlobalScope(rawPreaccel.global_scope);
        }
        if (Array.isArray(rawPreaccel?.global_target_processes)) {
          const list = rawPreaccel.global_target_processes.filter(
            (item): item is string => typeof item === "string" && item.trim().length > 0
          );
          setTargetProcesses(list);
        }
      })
      .catch(() => {
        /* keep fallback preaccel fields */
      });
    return () => {
      active = false;
    };
  }, []);

  const scheduleTimer = (fn: () => void, ms: number) => {
    const id = window.setTimeout(() => {
      timersRef.current = timersRef.current.filter((item) => item !== id);
      fn();
    }, ms);
    timersRef.current.push(id);
  };

  const probeValidation = useMemo(() => validateDomesticProbeUrl(probeUrl), [probeUrl]);

  const sortedRelays = useMemo(
    () =>
      [...relays].sort((a, b) => {
        if (a.priority !== b.priority) return a.priority - b.priority;
        return a.id.localeCompare(b.id);
      }),
    [relays]
  );

  const enabledRelayCount = useMemo(
    () => relays.filter((r) => r.enabled).length,
    [relays]
  );

  const physicalHostSummary = useMemo(() => {
    const enabledList = sortedRelays.filter((r) => r.enabled);
    const hostMap = new Map<string, number>();
    for (const r of enabledList) {
      const hostKey = r.server.trim().toLowerCase();
      if (!hostKey) continue;
      hostMap.set(hostKey, (hostMap.get(hostKey) ?? 0) + 1);
    }
    const distinctHosts = hostMap.size;
    const duplicateProtocolCount = Math.max(0, enabledList.length - distinctHosts);
    return {
      enabledCount: enabledList.length,
      distinctHosts,
      duplicateProtocolCount,
    };
  }, [sortedRelays]);

  const hasValidActiveRelay = useMemo(
    () =>
      Boolean(
        activeRelayId &&
          relays.some((r) => r.enabled && r.id === activeRelayId)
      ),
    [activeRelayId, relays]
  );

  const isMultiCloudLbStrategy =
    dispatchStrategy === "load_balance" ||
    (dispatchStrategy === "auto" && !hasValidActiveRelay);

  const isMultiCloudLbActive =
    physicalHostSummary.distinctHosts >= 2 && isMultiCloudLbStrategy;

  const enabledRankMap = useMemo(() => {
    const map = new Map<string, number>();
    let rank = 0;
    for (const r of sortedRelays) {
      if (r.enabled) {
        map.set(r.id, rank);
        rank += 1;
      }
    }
    return map;
  }, [sortedRelays]);

  const relayLatencyStats = useMemo(() => {
    const enabledList = sortedRelays.filter((r) => r.enabled);
    const probed = enabledList.filter((r) => hasValidLatency(r.last_probe_ms));
    const bestMs =
      probed.length > 0
        ? Math.min(...probed.map((r) => r.last_probe_ms as number))
        : null;
    return {
      enabledTotal: enabledList.length,
      probedCount: probed.length,
      bestMs,
    };
  }, [sortedRelays]);

  const primaryRelayId = useMemo(() => {
    if (runtime.preaccel_relay_name) {
      const matched = sortedRelays.find(
        (r) =>
          r.enabled &&
          (r.name === runtime.preaccel_relay_name || r.id === runtime.preaccel_relay_name)
      );
      if (matched) return matched.id;
    }
    if (!isMultiCloudLbStrategy && hasValidActiveRelay && activeRelayId) {
      return activeRelayId;
    }
    return sortedRelays.find((r) => r.enabled)?.id ?? null;
  }, [
    sortedRelays,
    runtime.preaccel_relay_name,
    isMultiCloudLbStrategy,
    hasValidActiveRelay,
    activeRelayId,
  ]);

  const homeCurrentNode = useMemo(() => {
    if (nodes.length === 0) return null;
    if (runtime.active_node_id) {
      const byRuntime = nodes.find((n) => n.id === runtime.active_node_id);
      if (byRuntime) return byRuntime;
    }
    if (runtime.route_mode !== "single") {
      const activeGroup =
        groups.find((g) => g.id === runtime.active_group_id) ?? groups[0] ?? null;
      if (activeGroup?.active_node_id) {
        const byGroupActive = nodes.find((n) => n.id === activeGroup.active_node_id);
        if (byGroupActive) return byGroupActive;
      }
      if (activeGroup && activeGroup.member_node_ids.length > 0) {
        const firstMember = nodes.find((n) => activeGroup.member_node_ids.includes(n.id));
        if (firstMember) return firstMember;
      }
    }
    return null;
  }, [nodes, groups, runtime.active_node_id, runtime.active_group_id, runtime.route_mode]);

  const isHomeCurrentNodeUdpOnly = homeCurrentNode
    ? isUdpOnlyProto(homeCurrentNode.protocol)
    : false;

  const benchmarkableNodes = useMemo(() => {
    const preferredRegions = new Set(["TW", "HK", "SG", "JP", "US", "KR"]);
    const isInfoPlaceholder = (name: string) =>
      /剩余流量|过期时间|到期时间|重置|套餐|官网|发布页|续费地址|使用前|更新订阅/i.test(name);
    const enabledList = nodes.filter(
      (n) => n.enabled && !isUdpOnlyProto(n.protocol) && !isInfoPlaceholder(n.name)
    );
    const base =
      enabledList.length > 0
        ? enabledList
        : nodes.filter((n) => !isUdpOnlyProto(n.protocol) && !isInfoPlaceholder(n.name));
    return [...base].sort((a, b) => {
      const aHighMult = a.multiplier >= 3 ? 1 : 0;
      const bHighMult = b.multiplier >= 3 ? 1 : 0;
      if (aHighMult !== bHighMult) return aHighMult - bHighMult;
      const aPreferredReg = preferredRegions.has(resolveNodeRegionCode(a)) ? 1 : 0;
      const bPreferredReg = preferredRegions.has(resolveNodeRegionCode(b)) ? 1 : 0;
      if (aPreferredReg !== bPreferredReg) return bPreferredReg - aPreferredReg;
      const aLowMult = a.multiplier <= 1.5 ? 1 : 0;
      const bLowMult = b.multiplier <= 1.5 ? 1 : 0;
      if (aLowMult !== bLowMult) return bLowMult - aLowMult;
      const aNon443 = a.is_443_native ? 0 : 1;
      const bNon443 = b.is_443_native ? 0 : 1;
      if (aNon443 !== bNon443) return bNon443 - aNon443;
      const aActive = a.id === runtime.active_node_id ? 1 : 0;
      const bActive = b.id === runtime.active_node_id ? 1 : 0;
      if (aActive !== bActive) return bActive - aActive;
      return a.name.localeCompare(b.name);
    });
  }, [nodes, runtime.active_node_id]);

  const otherBenchmarkableNodes = useMemo(
    () =>
      homeCurrentNode
        ? benchmarkableNodes.filter((n) => n.id !== homeCurrentNode.id)
        : benchmarkableNodes,
    [benchmarkableNodes, homeCurrentNode]
  );

  const resolvedCompareNodeId = useMemo(() => {
    if (
      selectedCompareNodeId &&
      otherBenchmarkableNodes.some((n) => n.id === selectedCompareNodeId)
    ) {
      return selectedCompareNodeId;
    }
    return "";
  }, [otherBenchmarkableNodes, selectedCompareNodeId]);

  const openAddModal = (tab: AddModalTab = "manual") => {
    setAddModalTab(tab);
    setShowAddModal(true);
  };

  const persistPreAccelConfig = async (
    nextSkip443: boolean,
    nextProbeUrl: string,
    notice: string,
    overrideEnabled?: boolean
  ): Promise<boolean> => {
    const latestConfig = appStore.getState().config;
    const authoritativeEnabled =
      overrideEnabled ?? latestConfig.preaccel.enabled;
    const nextConfig: AppConfig = {
      ...latestConfig,
      preaccel: {
        ...latestConfig.preaccel,
        enabled: authoritativeEnabled,
        skip_443_native: nextSkip443,
        probe_url: nextProbeUrl,
      },
    };
    try {
      const saved = await catcloudApi.saveConfig(nextConfig);
      appActions.syncConfig(saved);
      const rt = await catcloudApi.getRuntimeInfo();
      appActions.syncRuntime(rt);
      await appActions.refreshGlobalPreAccelStatus();
      appActions.showToast(notice, "ok");
      return true;
    } catch (err) {
      appActions.showToast(`保存国内提速设置失败：${formatErrorMessage(err)}`, "warn");
      return false;
    }
  };

  const handleToggleEnabled = async () => {
    if (togglingEnabled) return;
    const next = !appStore.getState().config.preaccel.enabled;
    setTogglingEnabled(true);
    try {
      await appActions.togglePreAccel(next);
    } finally {
      setTogglingEnabled(false);
    }
  };

  const handleRefreshGlobalStatus = async () => {
    if (refreshingGlobal) return;
    setRefreshingGlobal(true);
    try {
      await appActions.refreshGlobalPreAccelStatus();
    } finally {
      setRefreshingGlobal(false);
    }
  };

  const handleVerifyGlobalPreAccel = async () => {
    if (verifyingGlobal) return;
    await appActions.runVerifyGlobalPreAccel();
  };

  const handleSelectGlobalScope = async (nextScope: GlobalPreAccelScope) => {
    if (savingGlobalScope || nextScope === globalScope) return;
    const prev = globalScope;
    setGlobalScope(nextScope);
    setSavingGlobalScope(true);
    try {
      const ok = await appActions.updateGlobalPreAccelSettings(
        nextScope,
        targetProcesses,
        config.preaccel.windivert_dir ?? null
      );
      if (!ok) {
        setGlobalScope(prev);
      } else {
        appActions.showToast(
          nextScope === "proxy_apps_only"
            ? "已切换为：智能自动识别代理核心与常用工具"
            : "已切换为：全机非 443 兜底加速",
          "ok"
        );
      }
    } finally {
      setSavingGlobalScope(false);
    }
  };

  const handleAddTargetProcesses = async (rawInput: string): Promise<boolean> => {
    if (savingGlobalScope) return false;
    const raw = rawInput.trim();
    if (!raw) return false;
    const entries = raw
      .split(/[,;\s]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (entries.length === 0) return false;

    const existingLower = new Set(targetProcesses.map((p) => p.toLowerCase()));
    const added: string[] = [];
    for (const item of entries) {
      if (!existingLower.has(item.toLowerCase())) {
        existingLower.add(item.toLowerCase());
        added.push(item);
      }
    }
    if (added.length === 0) {
      appActions.showToast("该进程名已在加速列表中", "info");
      return true;
    }

    const prev = targetProcesses;
    const nextList = [...targetProcesses, ...added];
    setTargetProcesses(nextList);
    setSavingGlobalScope(true);
    try {
      const ok = await appActions.updateGlobalPreAccelSettings(
        globalScope,
        nextList,
        config.preaccel.windivert_dir ?? null
      );
      if (!ok) {
        setTargetProcesses(prev);
        return false;
      }
      appActions.showToast(`已添加加速软件：${added.join("、")}`, "ok");
      return true;
    } finally {
      setSavingGlobalScope(false);
    }
  };

  const handleRemoveTargetProcess = async (procName: string) => {
    if (savingGlobalScope) return;
    const prev = targetProcesses;
    const nextList = targetProcesses.filter((p) => p !== procName);
    setTargetProcesses(nextList);
    setSavingGlobalScope(true);
    try {
      const ok = await appActions.updateGlobalPreAccelSettings(
        globalScope,
        nextList,
        config.preaccel.windivert_dir ?? null
      );
      if (!ok) {
        setTargetProcesses(prev);
      } else {
        appActions.showToast(`已移出加速列表：${procName}`, "info");
      }
    } finally {
      setSavingGlobalScope(false);
    }
  };

  const handleResetTargetProcesses = async () => {
    if (savingGlobalScope) return;
    const prev = targetProcesses;
    const defaults = [...DEFAULT_GLOBAL_TARGET_PROCESSES];
    setTargetProcesses(defaults);
    setSavingGlobalScope(true);
    try {
      const ok = await appActions.updateGlobalPreAccelSettings(
        globalScope,
        defaults,
        config.preaccel.windivert_dir ?? null
      );
      if (!ok) {
        setTargetProcesses(prev);
      } else {
        appActions.showToast("已恢复默认代理核心与传输工具列表", "ok");
      }
    } finally {
      setSavingGlobalScope(false);
    }
  };

  const handleInstallWinDivert = async () => {
    if (installingDriver) return;
    await appActions.runInstallWinDivertDriver();
  };

  const handleRelaunchAdminGlobal = async () => {
    if (elevatingGlobal) return;
    setElevatingGlobal(true);
    try {
      await appActions.relaunchAsAdminForGlobalPreAccel();
    } finally {
      setElevatingGlobal(false);
    }
  };

  const handleCopyGlobalAddress = async (addr: string) => {
    const ok = await copyText(addr);
    if (ok) {
      setCopiedGlobalAddr(true);
      const sep = uiLang === "zh-CN" || uiLang === "ja" ? "：" : ": ";
      appActions.showToast(`${dict.preaccel.copiedLocalSocksToast}${sep}${addr}`, "ok");
      scheduleTimer(() => setCopiedGlobalAddr(false), 1800);
    } else {
      appActions.showToast("复制失败，请手动选中复制", "warn");
    }
  };

  const handleToggleSkip443 = async () => {
    const prev = skip443Native;
    const next = !skip443Native;
    setSkip443Native(next);
    const ok = await persistPreAccelConfig(
      next,
      probeValidation.ok ? probeUrl : config.preaccel.probe_url,
      next
        ? "已开启：已是高速通道的线路自动跳过"
        : "已关闭：猫云及第三方代理软件的 443 海外节点均将走国内提速"
    );
    if (!ok) setSkip443Native(prev);
  };

  const handleToggleCampusPortalGuard = async () => {
    if (savingCampusGuard) return;
    const prev = campusPortalGuard;
    const next = !campusPortalGuard;
    setCampusPortalGuard(next);
    setSavingCampusGuard(true);
    try {
      await catcloudApi.saveExtendedSettings({
        preaccel: { campus_portal_guard: next },
      });
      const freshCfg = await catcloudApi.getConfig();
      appActions.syncConfig(freshCfg);
      appActions.showToast(
        next ? "已开启校园网登录页自动放行" : "已关闭校园网登录页自动放行",
        "ok"
      );
    } catch (err) {
      setCampusPortalGuard(prev);
      appActions.showToast(`更新登录页自动放行失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setSavingCampusGuard(false);
    }
  };

  const handleSelectProbePreset = async (url: string, label: string) => {
    const prev = probeUrl;
    setProbeUrl(url);
    const ok = await persistPreAccelConfig(
      skip443Native,
      url,
      `已切换国内连通检测地址：${label}`
    );
    if (!ok) setProbeUrl(prev);
  };

  const handleSaveCustomProbe = async (ev: FormEvent) => {
    ev.preventDefault();
    if (!probeValidation.ok) {
      appActions.showToast(probeValidation.error ?? "检测地址不合规", "warn");
      return;
    }
    const ok = await persistPreAccelConfig(
      skip443Native,
      probeUrl.trim(),
      "国内连通检测地址已保存"
    );
    if (ok) {
      setShowProbeModal(false);
    }
  };

  const handleMoveRelay = async (id: string, direction: -1 | 1) => {
    const idx = sortedRelays.findIndex((r) => r.id === id);
    const swapIdx = idx + direction;
    if (idx < 0 || swapIdx < 0 || swapIdx >= sortedRelays.length) return;

    const reordered = [...sortedRelays];
    const [moved] = reordered.splice(idx, 1);
    reordered.splice(swapIdx, 0, moved);

    const normalized = reordered.map((r, i) => ({ ...r, priority: i + 1 }));
    const changed = normalized.filter((r) => {
      const old = relays.find((item) => item.id === r.id);
      return !old || old.priority !== r.priority;
    });

    const prevRelays = relays;
    setRelays(normalized);
    try {
      for (const item of changed) {
        await catcloudApi.upsertPreAccelRelay(item);
      }
      appActions.syncPreAccelRelays(normalized);
      const isMultiCloudLbMode = isMultiCloudLbActive || isMultiCloudLbStrategy;
      if (!isMultiCloudLbMode && (idx === 0 || swapIdx === 0) && normalized[0]?.enabled) {
        await catcloudApi.selectPreAccelRelay(normalized[0].id);
        const freshCfg = await catcloudApi.getConfig();
        appActions.syncConfig(freshCfg);
      }
      const rt = await catcloudApi.getRuntimeInfo();
      appActions.syncRuntime(rt);
      await appActions.refreshGlobalPreAccelStatus();
    } catch (err) {
      setRelays(prevRelays);
      appActions.showToast(`调整线路顺序失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleToggleRelay = async (id: string) => {
    const target = relays.find((r) => r.id === id);
    if (!target) return;
    const updated: PreAccelRelay = { ...target, enabled: !target.enabled };
    const prevRelays = relays;
    const nextRelays = relays.map((r) => (r.id === id ? updated : r));
    setRelays(nextRelays);
    try {
      await catcloudApi.upsertPreAccelRelay(updated);
      appActions.syncPreAccelRelays(nextRelays);
    } catch (err) {
      setRelays(prevRelays);
      appActions.showToast(`更新线路状态失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleUpdateDispatchConfig = async (
    nextStrategy: PreAccelDispatchStrategy,
    nextLbStrategy: PreAccelLbStrategy = lbStrategy,
    customNotice?: string
  ): Promise<boolean> => {
    if (savingDispatch) return false;
    setSavingDispatch(true);
    try {
      const latestConfig = appStore.getState().config;
      const nextPreAccel: AppConfig["preaccel"] = {
        ...latestConfig.preaccel,
        dispatch_strategy: nextStrategy,
        lb_strategy: nextLbStrategy,
        ...(nextStrategy !== "fallback" ? { active_relay_id: null } : {}),
      };
      const nextConfig: AppConfig = {
        ...latestConfig,
        preaccel: nextPreAccel,
      };
      const saved = await catcloudApi.saveConfig(nextConfig);
      appActions.syncConfig(saved);
      const rt = await catcloudApi.getRuntimeInfo();
      appActions.syncRuntime(rt);
      await appActions.refreshGlobalPreAccelStatus();
      const algoLabel =
        nextLbStrategy === "consistent_hashing"
          ? dict.preaccel.lbConsistentHashing
          : dict.preaccel.lbRoundRobin;
      const notice =
        customNotice ??
        (nextStrategy === "fallback"
          ? dict.preaccel.dispatchFallbackToast
          : formatI18nTemplate(dict.preaccel.dispatchLbToast, { algo: algoLabel }));
      appActions.showToast(notice, "ok");
      return true;
    } catch (err) {
      appActions.showToast(`切换中转调度方式失败：${formatErrorMessage(err)}`, "warn");
      return false;
    } finally {
      setSavingDispatch(false);
    }
  };

  const handleSelectRelay = async (relay: PreAccelRelay) => {
    if (!relay.enabled) {
      appActions.showToast("请先开启该线路，再设为主力", "warn");
      return;
    }
    const switchingFromMultiCloudLb = isMultiCloudLbActive;

    try {
      // Single atomic backend call: updates dispatch_strategy=fallback + active_relay_id
      // and triggers at most one hot reload instead of cascading saveConfig + per-relay upserts.
      await catcloudApi.selectPreAccelRelay(relay.id);
      const [freshCfg, rt] = await Promise.all([
        catcloudApi.getConfig(),
        catcloudApi.getRuntimeInfo(),
      ]);
      appActions.syncConfig(freshCfg);
      appActions.syncRuntime(rt);
      await appActions.refreshGlobalPreAccelStatus();
      appActions.showToast(
        switchingFromMultiCloudLb
          ? `已切换为单线主备并优先使用「${relay.name}」（保留其余线路自动兜底），可随时在上方切回多云自动均衡`
          : `已将「${relay.name}」设为主力线路（其余线路继续自动故障兜底）`,
        "ok",
        5200
      );
    } catch (err) {
      appActions.showToast(`设置主力线路失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleFailover = async () => {
    if (failoverBusy) return;
    setFailoverBusy(true);
    try {
      const nextId = await catcloudApi.failoverPreAccel();
      const [freshCfg, rt] = await Promise.all([
        catcloudApi.getConfig(),
        catcloudApi.getRuntimeInfo(),
      ]);
      appActions.syncConfig(freshCfg);
      appActions.syncRuntime(rt);
      if (nextId) {
        const matched = relays.find((r) => r.id === nextId);
        appActions.showToast(`已切换至备用线路：${matched?.name ?? nextId}`, "ok");
      } else {
        appActions.showToast("当前没有其他可用的备用线路", "warn");
      }
    } catch (err) {
      appActions.showToast(`切换备用线路失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setFailoverBusy(false);
    }
  };

  const handleProbeRelay = async (id: string) => {
    if (probingIdsSet.has(id) || probingAll) return;
    await appActions.runTestPreAccelRelays(id);
  };

  const handleProbeAllRelays = async () => {
    if (probingAll || relays.length === 0) return;
    await appActions.runTestPreAccelRelays(null);
  };

  const handleSpeedTestRelay = async (id: string) => {
    if (speedTestingIdsSet.has(id) || speedTestingAll || isProbeEngineBusy) return;
    await appActions.runTestPreAccelRelaySpeeds(id, resolvedCompareNodeId || null);
  };

  const handleSpeedTestAllRelays = async () => {
    if (speedTestingAll || speedTestingAny || isProbeEngineBusy || relays.length === 0) return;
    await appActions.runTestPreAccelRelaySpeeds(null, resolvedCompareNodeId || null);
  };

  const handleConfirmRemoveRelay = async () => {
    if (!pendingDeleteRelay || deletingRelay) return;
    const target = pendingDeleteRelay;
    setDeletingRelay(true);
    try {
      await catcloudApi.deletePreAccelRelay(target.id);
      const next = relays.filter((r) => r.id !== target.id);
      setRelays(next);
      appActions.syncPreAccelRelays(next);
      setPendingDeleteRelay(null);
      appActions.showToast(`已删除中转线路「${target.name}」`, "info");
    } catch (err) {
      appActions.showToast(`删除线路失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setDeletingRelay(false);
    }
  };

  const handleRunBenchmark = async () => {
    if (benchmarking) return;
    if (isOtherProbeRunning) {
      appActions.showToast("节点测速正在后台进行，完成后即可运行提速对比", "info");
      return;
    }
    if (inTauri && enabledRelayCount === 0) {
      appActions.showToast("请先添加并启用至少一条国内中转线路，再进行提速对比", "warn");
      return;
    }
    if (inTauri && benchmarkableNodes.length === 0) {
      appActions.showToast(
        "还没有可对比的海外节点，请先在「节点与测速 → 订阅与导入」中导入节点",
        "warn"
      );
      return;
    }
    await appActions.runPreAccelBenchmark(resolvedCompareNodeId || null);
  };

  const handleCheckCampusAuth = async () => {
    if (checkingPortal) return;
    await appActions.runCheckCampusPortal();
  };

  // Keep stable callback references for memoized RelayCardItem children
  const relayHandlersRef = useRef({
    handleToggleRelay,
    handleMoveRelay,
    handleSelectRelay,
    handleProbeRelay,
    handleSpeedTestRelay,
  });
  relayHandlersRef.current = {
    handleToggleRelay,
    handleMoveRelay,
    handleSelectRelay,
    handleProbeRelay,
    handleSpeedTestRelay,
  };

  const onToggleRelayCard = useCallback((id: string) => {
    void relayHandlersRef.current.handleToggleRelay(id);
  }, []);
  const onMoveRelayCard = useCallback((id: string, direction: -1 | 1) => {
    void relayHandlersRef.current.handleMoveRelay(id, direction);
  }, []);
  const onSelectRelayCard = useCallback((relay: PreAccelRelay) => {
    void relayHandlersRef.current.handleSelectRelay(relay);
  }, []);
  const onProbeRelayCard = useCallback((id: string) => {
    void relayHandlersRef.current.handleProbeRelay(id);
  }, []);
  const onSpeedTestRelayCard = useCallback((id: string) => {
    void relayHandlersRef.current.handleSpeedTestRelay(id);
  }, []);
  const onRequestDeleteRelayCard = useCallback((relay: PreAccelRelay) => {
    setPendingDeleteRelay(relay);
  }, []);

  const hasEnabledRelay = useMemo(
    () => sortedRelays.some((r) => r.enabled),
    [sortedRelays]
  );
  const preaccelSummary = resolvePreAccelSummary(
    runtime,
    globalPreAccel,
    enabled,
    hasEnabledRelay,
    uiLang
  );
  const effectiveGlobalPort =
    globalPreAccel.socks_port ?? runtime.global_preaccel_socks_port ?? null;
  const effectiveGlobalConns =
    globalPreAccel.active_connections || runtime.global_preaccel_connections || 0;
  const isWindows = platformOs === "windows";
  const localSocksAddress = effectiveGlobalPort ? `127.0.0.1:${effectiveGlobalPort}` : null;
  const processStats = useMemo(
    () => dedupeProcessStats(globalPreAccel.process_stats ?? []),
    [globalPreAccel.process_stats]
  );
  const acceleratedProcesses = useMemo(() => {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const proc of globalPreAccel.accelerated_processes ?? []) {
      const key = proc.trim().toLowerCase();
      if (!key || seen.has(key)) continue;
      seen.add(key);
      out.push(proc);
    }
    return out;
  }, [globalPreAccel.accelerated_processes]);
  const enabledRelayIds = useMemo(
    () => sortedRelays.filter((r) => r.enabled).map((r) => r.id),
    [sortedRelays]
  );
  const needsWindowsElevation =
    isWindows &&
    hasEnabledRelay &&
    preaccelSummary.enabled &&
    !preaccelSummary.suspendedForTun &&
    !preaccelSummary.realWinDivertActive &&
    (preaccelSummary.installState === "need_elevation" ||
      (globalPreAccel.windivert_available && !globalPreAccel.is_elevated));
  const isPreparingDriver =
    installingDriver ||
    preaccelSummary.installState === "downloading" ||
    preaccelSummary.installState === "verifying";
  const isProbingVerify = verifyingGlobal || preaccelSummary.verifyState === "probing";
  const isDegradedVerify = preaccelSummary.verifyState === "degraded";
  const isVerifiedVerify =
    preaccelSummary.realWinDivertActive && preaccelSummary.verifyState === "verified";
  const showReprobeButton =
    isWindows && preaccelSummary.enabled && !isPreparingDriver && !needsWindowsElevation;
  const detectedSecurityProducts = globalPreAccel.detected_security_products ?? [];
  const securityGuidanceText = globalPreAccel.security_guidance?.trim() || null;
  const verifyMessageText = globalPreAccel.verify_message?.trim() || null;
  const isAbnormalVerifyState = isDegradedVerify || preaccelSummary.verifyState === "failed";
  const hasDistinctVerifyDetail =
    isAbnormalVerifyState &&
    Boolean(verifyMessageText) &&
    verifyMessageText !== preaccelSummary.detailText.trim() &&
    verifyMessageText !== preaccelSummary.plainText.trim();
  const showSecurityGuidanceBox =
    !preaccelSummary.realWinDivertActive &&
    (Boolean(securityGuidanceText) || hasDistinctVerifyDetail);
  const verifyCheckedClock =
    typeof globalPreAccel.verify_checked_at_ms === "number" &&
    globalPreAccel.verify_checked_at_ms > 0
      ? formatClockStamp(globalPreAccel.verify_checked_at_ms)
      : null;
  const verifyStateFallbackLabel = (() => {
    switch (preaccelSummary.verifyState) {
      case "probing":
        return "正在自动探测…";
      case "verified":
        return preaccelSummary.verifyLatencyMs
          ? `探测畅通（${preaccelSummary.verifyLatencyMs} ms）`
          : "探测畅通";
      case "degraded":
        return "已自动保护回退";
      case "failed":
        return "探测未通过";
      default:
        return "尚未探测";
    }
  })();

  const topStatusBadge = (() => {
    const label =
      preaccelSummary.proxyActive && preaccelSummary.subBadgeText
        ? `${preaccelSummary.badgeText} · ${preaccelSummary.subBadgeText}`
        : preaccelSummary.badgeText;
    const cls =
      preaccelSummary.tone === "green"
        ? "bg-[var(--green-soft)] text-[var(--green)]"
        : preaccelSummary.tone === "accent"
          ? "bg-[var(--accent-soft)] text-[var(--accent)]"
          : preaccelSummary.tone === "amber"
            ? "bg-[var(--amber-soft)] text-[var(--amber)]"
            : preaccelSummary.tone === "red"
              ? "bg-[var(--red-soft)] text-[var(--red)]"
              : "bg-[var(--bg-elevated)] text-[var(--muted)]";
    return { label, cls };
  })();

  const hasAdvancedAlert = !probeValidation.ok || portalRequired;
  const openShareModal = (mode: "export" | "import") => {
    setShareModalMode(mode);
    setShareModalOpen(true);
  };

  return (
    <div className="space-y-4">
      {sortedRelays.length === 0 ? (
        /* 0-Relay Empty State: Friendly Hero Guide Card takes center stage (A-P2-8) */
        <section className="cc-card cc-glass rounded-2xl border-[var(--accent)]/40 bg-[var(--accent-soft)]/25 p-6">
          <div className="flex items-start gap-3.5">
            <span className="inline-flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl bg-[var(--accent-soft)] text-[var(--accent)]">
              <Zap className="h-5 w-5" />
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="rounded-full bg-[var(--card)]/85 px-2.5 py-0.5 text-[11px] font-medium text-[var(--accent)]">
                  {dict.preaccel.title}
                </span>
              </div>
              <h1 className="mt-2 text-base font-semibold tracking-tight text-[var(--text)]">
                {dict.preaccel.emptyFriendlyTitle}
              </h1>
              <p className="mt-1.5 max-w-2xl text-xs leading-relaxed text-[var(--text-secondary)]">
                {dict.preaccel.emptyFriendlyDesc}
              </p>
            </div>
          </div>

          <div className="mt-5 flex flex-wrap items-center gap-2.5">
            <button
              type="button"
              onClick={() => openAddModal("import")}
              className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[var(--accent-ink)] shadow-xs transition-opacity hover:opacity-90"
            >
              <Upload className="h-3.5 w-3.5 shrink-0" />
              <span>{dict.preaccel.emptyPasteCodeBtn}</span>
            </button>

            <button
              type="button"
              onClick={() => openShareModal("import")}
              className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border border-[var(--line-strong)] bg-[var(--card)] px-3.5 py-2 text-xs font-semibold text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
            >
              <Package className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
              <span>{dict.common.importShareBundle}</span>
            </button>

            <button
              type="button"
              onClick={() => openAddModal("manual")}
              className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border border-[var(--line)] bg-[var(--surface)] px-3.5 py-2 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)]"
            >
              <Plus className="h-3.5 w-3.5 shrink-0" />
              <span>{dict.preaccel.emptyAddManualBtn}</span>
            </button>

            <button
              type="button"
              onClick={() => appActions.openAiAssistant("preaccel", "agent")}
              className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border border-[var(--accent)]/45 bg-[var(--card)] px-3.5 py-2 text-xs font-medium text-[var(--accent)] transition-colors hover:border-[var(--accent)] hover:bg-[var(--accent-soft)]/55"
            >
              <Bot className="h-3.5 w-3.5 shrink-0" />
              <span>{dict.preaccel.emptyAskAiDeploy}</span>
            </button>
          </div>

          {importWarnings.length > 0 && (
            <div className="mt-4 flex items-start justify-between gap-3 rounded-xl border border-[var(--amber)]/45 bg-[var(--amber-soft)] px-3.5 py-2.5 text-xs text-[var(--amber)]">
              <div>
                <div className="font-semibold">导入配置提醒</div>
                <ul className="mt-1 list-disc space-y-0.5 pl-4 text-[11px]">
                  {importWarnings.map((w) => (
                    <li key={w}>{w}</li>
                  ))}
                </ul>
              </div>
              <button
                type="button"
                onClick={() => setImportWarnings([])}
                className="shrink-0 rounded-md p-1 opacity-75 hover:opacity-100"
                aria-label="关闭提醒"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          )}
        </section>
      ) : (
        <>
          {/* 1. 顶部精简总控卡片：全站唯一「开启国内提速」总开关 + 诚实状态条 */}
          <TopStatusCard
            title={dict.preaccel.title}
            subtitle={dict.preaccel.subtitle}
            toggleMainTitle={dict.preaccel.toggleMainTitle}
            toggleMainToggling={dict.preaccel.toggleMainToggling}
            toggleMainDesc={dict.preaccel.toggleMainDesc}
            socksCopyPlainHint={dict.preaccel.socksCopyPlainHint}
            refreshLabel={dict.common.refresh}
            enabled={enabled}
            togglingEnabled={togglingEnabled}
            topStatusBadge={topStatusBadge}
            preaccelSummary={preaccelSummary}
            globalPreAccel={globalPreAccel}
            effectiveGlobalConns={effectiveGlobalConns}
            localSocksAddress={localSocksAddress}
            copiedGlobalAddr={copiedGlobalAddr}
            isWindows={isWindows}
            isPreparingDriver={isPreparingDriver}
            isProbingVerify={isProbingVerify}
            isVerifiedVerify={isVerifiedVerify}
            isDegradedVerify={isDegradedVerify}
            needsWindowsElevation={needsWindowsElevation}
            elevatingGlobal={elevatingGlobal}
            installBusy={installBusy}
            showReprobeButton={showReprobeButton}
            refreshingGlobal={refreshingGlobal}
            showSecurityGuidanceBox={showSecurityGuidanceBox}
            detectedSecurityProducts={detectedSecurityProducts}
            hasDistinctVerifyDetail={hasDistinctVerifyDetail}
            verifyMessageText={verifyMessageText}
            securityGuidanceText={securityGuidanceText}
            onToggleEnabled={handleToggleEnabled}
            onRelaunchAdminGlobal={handleRelaunchAdminGlobal}
            onInstallWinDivert={handleInstallWinDivert}
            onCopyGlobalAddress={handleCopyGlobalAddress}
            onVerifyGlobalPreAccel={handleVerifyGlobalPreAccel}
            onRefreshGlobalStatus={handleRefreshGlobalStatus}
          />

          {/* 2. 中转线路列表卡片（首屏清爽头栏 + 清晰卡片核心控制） */}
          <section className="cc-card cc-glass rounded-2xl p-5">
            <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <h2 className="whitespace-nowrap text-sm font-semibold text-[var(--text)]">
                    中转线路
                  </h2>
                  <span className="shrink-0 whitespace-nowrap rounded-full bg-[var(--bg-elevated)] px-2 py-0.5 text-[11px] font-medium text-[var(--muted)]">
                    {sortedRelays.length} 条
                  </span>
                  {physicalHostSummary.distinctHosts >= 2 && (
                    <span className="shrink-0 whitespace-nowrap rounded-full bg-[var(--green-soft)] px-2 py-0.5 text-[10.5px] font-medium text-[var(--green)]">
                      {physicalHostSummary.distinctHosts} 台物理云
                    </span>
                  )}
                </div>
                <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                  {isMultiCloudLbActive
                    ? "多云并发聚合已生效，单台波动时自动无缝兜底"
                    : "优先使用主力线路，遇到波动时自动切换到备用线路"}
                </p>
              </div>

              <div className="flex max-w-full flex-wrap items-center gap-2">
                <button
                  type="button"
                  disabled={probingAll || relays.length === 0}
                  onClick={() => void handleProbeAllRelays()}
                  title="快速检测所有中转线路的连通性与实时延迟"
                  className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)] disabled:cursor-not-allowed disabled:opacity-65"
                >
                  <RefreshCw
                    className={`h-3.5 w-3.5 shrink-0 ${probingAll ? "animate-spin" : ""}`}
                  />
                  <span>{probingAll ? "测延迟中…" : "全部测延迟"}</span>
                </button>

                <button
                  type="button"
                  onClick={() => openShareModal("import")}
                  className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)]"
                  title="一键导入或导出国内提速中转与节点 .zip 分享包"
                >
                  <Package className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
                  <span>{dict.common.importShareBundle}</span>
                </button>

                <button
                  type="button"
                  onClick={() => openAddModal("manual")}
                  className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90"
                >
                  <Plus className="h-3.5 w-3.5 shrink-0" />
                  <span>添加中转</span>
                </button>
              </div>
            </div>

            {importWarnings.length > 0 && (
              <div className="mb-4 flex items-start justify-between gap-3 rounded-xl border border-[var(--amber)]/45 bg-[var(--amber-soft)] px-3.5 py-2.5 text-xs text-[var(--amber)]">
                <div>
                  <div className="font-semibold">导入配置提醒</div>
                  <ul className="mt-1 list-disc space-y-0.5 pl-4 text-[11px]">
                    {importWarnings.map((w) => (
                      <li key={w}>{w}</li>
                    ))}
                  </ul>
                </div>
                <button
                  type="button"
                  onClick={() => setImportWarnings([])}
                  className="shrink-0 rounded-md p-1 opacity-75 hover:opacity-100"
                  aria-label="关闭提醒"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              </div>
            )}

            {/* 中转机卡片列表 */}
            <div className="grid grid-cols-1 gap-3.5 min-[1160px]:grid-cols-2">
              {sortedRelays.map((relay, idx) => {
                const enabledRank = enabledRankMap.get(relay.id);
                const isActivePrimary = relay.id === primaryRelayId && relay.enabled;
                const isTopEnabled =
                  relay.enabled &&
                  (primaryRelayId ? isActivePrimary : enabledRank === 0);
                const fallbackOrder = (() => {
                  if (!relay.enabled || isTopEnabled) return 0;
                  let order = 0;
                  for (const item of sortedRelays) {
                    if (!item.enabled || item.id === primaryRelayId) continue;
                    order += 1;
                    if (item.id === relay.id) return order;
                  }
                  return enabledRank ?? 1;
                })();
                const roleLabel = !relay.enabled
                  ? "已停用"
                  : isTopEnabled
                    ? "主力线路"
                    : `备用 ${fallbackOrder}`;
                const isProbing = probingIdsSet.has(relay.id) || probingAll;
                const isSpeedTesting = speedTestingIdsSet.has(relay.id) || speedTestingAll;
                const canSetPrimary =
                  relay.enabled && (isMultiCloudLbActive || !isActivePrimary);
                const rawChainMs = relayChainLatencies[relay.id];
                const validChainMs =
                  typeof rawChainMs === "number" && Number.isFinite(rawChainMs) && rawChainMs > 0
                    ? Math.round(rawChainMs)
                    : null;

                return (
                  <RelayCardItem
                    key={relay.id}
                    relay={relay}
                    idx={idx}
                    totalCount={sortedRelays.length}
                    isTopEnabled={isTopEnabled}
                    isActivePrimary={isActivePrimary}
                    roleLabel={roleLabel}
                    isProbing={isProbing}
                    isSpeedTesting={isSpeedTesting}
                    isProbeEngineBusy={isProbeEngineBusy}
                    isMultiCloudLbActive={isMultiCloudLbActive}
                    canSetPrimary={canSetPrimary}
                    validChainMs={validChainMs}
                    chainLatencyLabel={dict.preaccel.chainLatencyLabel}
                    pinPrimaryBtnLabel={dict.preaccel.pinPrimaryBtn}
                    onToggleRelay={onToggleRelayCard}
                    onMoveRelay={onMoveRelayCard}
                    onSelectRelay={onSelectRelayCard}
                    onProbeRelay={onProbeRelayCard}
                    onSpeedTestRelay={onSpeedTestRelayCard}
                    onRequestDeleteRelay={onRequestDeleteRelayCard}
                  />
                );
              })}
            </div>
          </section>
        </>
      )}

      {/* 3. 统一默认折叠区：高级设置与对比工具（100% 保留全部高阶能力，零阉割） */}
      <section className="cc-card cc-glass rounded-2xl">
        <button
          type="button"
          aria-expanded={advancedOpen}
          onClick={() => setAdvancedOpen((v) => !v)}
          className="flex w-full items-center justify-between gap-3 rounded-2xl px-5 py-3.5 text-left transition-colors hover:bg-[var(--bg-elevated)]/45"
        >
          <div className="flex min-w-0 items-center gap-2.5">
            {advancedOpen ? (
              <ChevronDown className="h-4 w-4 shrink-0 text-[var(--accent)]" />
            ) : (
              <ChevronRight className="h-4 w-4 shrink-0 text-[var(--muted)]" />
            )}
            <div className="min-w-0">
              <div className="flex items-center gap-2 text-xs font-semibold text-[var(--text)]">
                <span>{dict.preaccel.advancedToolsTitle}</span>
                {hasAdvancedAlert && (
                  <span
                    className={`h-2 w-2 shrink-0 rounded-full ${
                      !probeValidation.ok ? "bg-[var(--red)]" : "bg-[var(--amber)]"
                    }`}
                    title={!probeValidation.ok ? "国内连通检测地址需要修正" : "检测到校园网需要认证"}
                  />
                )}
              </div>
              <div className="mt-0.5 truncate text-[11px] text-[var(--muted)]">
                {dict.preaccel.advancedToolsSub}
              </div>
            </div>
          </div>
          <span className="shrink-0 rounded-full border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-0.5 text-[10px] font-medium text-[var(--muted)]">
            {advancedOpen ? dict.preaccel.collapseBtn : dict.preaccel.expandBtn}
          </span>
        </button>

        {advancedOpen && (
          <div className="space-y-4 border-t border-[var(--line)]/70 px-5 pb-5 pt-4">
            {/* 高级快捷工具栏：检测地址 / 软路由导出 / 分享包导出 / 全部测上下行 / 切换备用 */}
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => setShowProbeModal(true)}
                className="relative inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)]"
              >
                <SlidersHorizontal className="h-3.5 w-3.5 shrink-0 text-[var(--muted)]" />
                <span>检测地址</span>
                {!probeValidation.ok && (
                  <span
                    className="h-2 w-2 shrink-0 rounded-full bg-[var(--red)]"
                    title="国内连通检测地址需要修正"
                  />
                )}
              </button>

              <button
                type="button"
                onClick={() => setGatewayModalOpen(true)}
                className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)]"
                title={dict.preaccel.gatewayExportTooltip}
              >
                <Router className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
                <span>{dict.preaccel.gatewayExportBtn}</span>
              </button>

              {sortedRelays.length > 0 && (
                <>
                  <button
                    type="button"
                    onClick={() => openShareModal("export")}
                    className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)]"
                    title={dict.share.exportZipTooltip}
                  >
                    <Package className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
                    <span>{dict.common.exportShareBundle}</span>
                  </button>

                  <button
                    type="button"
                    disabled={
                      speedTestingAll || speedTestingAny || isProbeEngineBusy || relays.length === 0
                    }
                    onClick={() => void handleSpeedTestAllRelays()}
                    title="逐条实测所有中转线路的实际上传与下载速率（切页不中断）"
                    className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)] disabled:cursor-not-allowed disabled:opacity-65"
                  >
                    {speedTestingAll ? (
                      <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin text-[var(--accent)]" />
                    ) : (
                      <Gauge className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
                    )}
                    <span>{speedTestingAll ? "测速中…" : "全部测上下行"}</span>
                  </button>

                  <button
                    type="button"
                    disabled={failoverBusy || enabledRelayCount < 2}
                    onClick={() => void handleFailover()}
                    className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)] disabled:cursor-not-allowed disabled:opacity-65"
                    title="将当前流量切换到下一条可用的备用线路"
                  >
                    <ArrowLeftRight className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
                    <span>{failoverBusy ? "切换中…" : "切换备用"}</span>
                  </button>
                </>
              )}
            </div>

            {/* 已自动识别并加速的进程小胶囊列表（含连接数与流量） */}
            {(processStats.length > 0 ||
              (preaccelSummary.realWinDivertActive &&
                acceleratedProcesses.length > 0)) && (
              <div className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)]/80 px-3.5 py-2.5">
                <div className="mb-2 flex items-center justify-between gap-2 text-[11px]">
                  <span className="font-medium text-[var(--text-secondary)]">
                    已自动识别并加速（
                    {processStats.length > 0
                      ? processStats.length
                      : acceleratedProcesses.length}
                    ）
                  </span>
                  <span className="text-[10px] text-[var(--muted)]">
                    自动排除猫猫云梯自身，零手动配置
                  </span>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {processStats.length > 0
                    ? processStats.slice(0, 12).map((stat) => (
                        <span
                          key={stat.process_name.toLowerCase()}
                          title={`PID ${stat.pid} · 来源：${formatDetectedByLabel(stat.detected_by)} · 累计 ${stat.total_connections} 连接`}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--accent)]/35 bg-[var(--card)] px-2 py-1 text-[11px]"
                        >
                          <span className="cc-mono font-semibold text-[var(--text)]">
                            {stat.process_name}
                          </span>
                          <span className="rounded bg-[var(--accent-soft)] px-1 py-0.5 text-[9.5px] font-medium text-[var(--accent)]">
                            {formatDetectedByLabel(stat.detected_by)}
                          </span>
                          <span className="cc-mono cc-tabular text-[10px] text-[var(--text-secondary)]">
                            {stat.active_connections > 0
                              ? `${stat.active_connections} 连`
                              : `累计 ${stat.total_connections}`}
                          </span>
                          <span className="cc-mono cc-tabular text-[10px] text-[var(--coral)]">
                            ↑{formatBytes(stat.tx_bytes)}
                          </span>
                          <span className="cc-mono cc-tabular text-[10px] text-[var(--sky)]">
                            ↓{formatBytes(stat.rx_bytes)}
                          </span>
                        </span>
                      ))
                    : acceleratedProcesses.slice(0, 10).map((proc) => (
                        <span
                          key={proc.toLowerCase()}
                          className="cc-mono rounded-lg border border-[var(--accent)]/35 bg-[var(--accent-soft)]/60 px-2 py-1 text-[11px] font-medium text-[var(--accent)]"
                        >
                          {proc}
                        </span>
                      ))}
                </div>
              </div>
            )}

            {/* 多云均衡聚合 / 单线主备 调度方式控制条 */}
            {sortedRelays.length > 0 && (
              <div className="space-y-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2.5 text-xs">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="inline-flex items-center gap-1.5 font-medium text-[var(--text-secondary)]">
                      <Layers className="h-3.5 w-3.5 text-[var(--accent)]" />
                      <span>{dict.preaccel.dispatchLabel}</span>
                    </span>
                    <div
                      className="inline-flex max-w-full flex-wrap rounded-xl border border-[var(--line)] bg-[var(--card)] p-0.5 text-[11px]"
                      role="group"
                      aria-label={dict.preaccel.dispatchLabel}
                    >
                      <button
                        type="button"
                        disabled={savingDispatch}
                        onClick={() => void handleUpdateDispatchConfig("auto", lbStrategy)}
                        className={`shrink-0 whitespace-nowrap rounded-lg px-2.5 py-1 font-medium transition-colors disabled:opacity-60 ${
                          isMultiCloudLbStrategy
                            ? "bg-[var(--accent-soft)] font-semibold text-[var(--accent)]"
                            : "text-[var(--muted)] hover:text-[var(--text)]"
                        }`}
                      >
                        {dict.preaccel.dispatchAutoLb}
                      </button>
                      <button
                        type="button"
                        disabled={savingDispatch}
                        onClick={() => void handleUpdateDispatchConfig("fallback", lbStrategy)}
                        className={`shrink-0 whitespace-nowrap rounded-lg px-2.5 py-1 font-medium transition-colors disabled:opacity-60 ${
                          !isMultiCloudLbStrategy
                            ? "bg-[var(--accent-soft)] font-semibold text-[var(--accent)]"
                            : "text-[var(--muted)] hover:text-[var(--text)]"
                        }`}
                      >
                        {dict.preaccel.dispatchFallback}
                      </button>
                    </div>
                  </div>

                  {isMultiCloudLbActive && (
                    <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
                      <span className="shrink-0 whitespace-nowrap text-[var(--muted)]">
                        {dict.preaccel.lbAlgorithmLabel}
                      </span>
                      <button
                        type="button"
                        disabled={savingDispatch}
                        onClick={() =>
                          void handleUpdateDispatchConfig(
                            dispatchStrategy,
                            lbStrategy === "round_robin" ? "consistent_hashing" : "round_robin"
                          )
                        }
                        className="shrink-0 whitespace-nowrap rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-1 font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-60"
                        title={dict.preaccel.lbAlgorithmTooltip}
                      >
                        {lbStrategy === "consistent_hashing"
                          ? dict.preaccel.lbConsistentHashing
                          : dict.preaccel.lbRoundRobin}
                      </button>
                    </div>
                  )}
                </div>

                {physicalHostSummary.distinctHosts >= 2 && isMultiCloudLbActive && (
                  <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--green)]/40 bg-[var(--green-soft)]/45 px-3.5 py-2 text-[11.5px] text-[var(--text)]">
                    <div className="flex min-w-0 items-center gap-2">
                      <Sparkles className="h-3.5 w-3.5 shrink-0 text-[var(--green)]" />
                      <span>
                        已自动聚合{" "}
                        <strong className="cc-mono text-[var(--green)]">
                          {physicalHostSummary.distinctHosts}
                        </strong>{" "}
                        台物理云并发带宽
                        {physicalHostSummary.duplicateProtocolCount > 0
                          ? `（同机多余 ${physicalHostSummary.duplicateProtocolCount} 条协议已自动去重防抢占网卡）`
                          : "（同机多协议自动去重）"}
                        ，单台故障自动切换备用与直连兜底。
                      </span>
                    </div>
                  </div>
                )}

                {physicalHostSummary.distinctHosts >= 2 && !isMultiCloudLbActive && (
                  <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--amber)]/40 bg-[var(--amber-soft)]/45 px-3.5 py-2 text-[11.5px] text-[var(--text)]">
                    <span className="text-[var(--text-secondary)]">
                      当前已手动固定为单线主备模式（优先使用首位主力线，其余线路作故障兜底）。检测到{" "}
                      <strong className="cc-mono text-[var(--text)]">
                        {physicalHostSummary.distinctHosts}
                      </strong>{" "}
                      台不同物理云，可随时切回并发聚合。
                    </span>
                    <button
                      type="button"
                      disabled={savingDispatch}
                      onClick={() => void handleUpdateDispatchConfig("auto", lbStrategy)}
                      className="inline-flex shrink-0 items-center gap-1 rounded-lg bg-[var(--accent)] px-2.5 py-1 text-[11px] font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-60"
                    >
                      <Layers className="h-3 w-3" />
                      <span>{dict.preaccel.switchBackLbBtn}</span>
                    </button>
                  </div>
                )}
              </div>
            )}

            {/* 提速前后测速对比 + 校园网认证检测 */}
            <div className="grid grid-cols-1 gap-4 min-[1160px]:grid-cols-12">
              <SpeedCompareCard
                comparison={comparison}
                comparisonError={comparisonError}
                comparisonFinishedAt={comparisonFinishedAt}
                comparisonIsDemo={comparisonIsDemo}
                benchmarking={benchmarking}
                speedTestingAny={speedTestingAny}
                isOtherProbeRunning={isOtherProbeRunning}
                isProbeEngineBusy={isProbeEngineBusy}
                relayLatencyStats={relayLatencyStats}
                benchmarkableNodes={benchmarkableNodes}
                otherBenchmarkableNodes={otherBenchmarkableNodes}
                homeCurrentNode={homeCurrentNode}
                isHomeCurrentNodeUdpOnly={isHomeCurrentNodeUdpOnly}
                resolvedCompareNodeId={resolvedCompareNodeId}
                onSelectCompareNodeId={setSelectedCompareNodeId}
                onRunBenchmark={handleRunBenchmark}
              />

              <CampusPortalCard
                checkingPortal={checkingPortal}
                portalRequired={portalRequired}
                portalHttpCode={portalHttpCode}
                portalLastCheck={portalLastCheck}
                portalRedirect={portalRedirect}
                portalBypassHosts={portalBypassHosts}
                campusError={campusError}
                campusPortalGuard={campusPortalGuard}
                savingCampusGuard={savingCampusGuard}
                probeValidationOk={probeValidation.ok}
                onCheckCampusAuth={handleCheckCampusAuth}
                onToggleCampusPortalGuard={handleToggleCampusPortalGuard}
                onOpenProbeModal={() => setShowProbeModal(true)}
              />
            </div>

            {/* 4.1 路由优化开关：已是高速通道的线路自动跳过 */}
            <button
              type="button"
              role="switch"
              aria-checked={skip443Native}
              onClick={() => void handleToggleSkip443()}
              className="flex w-full items-center justify-between gap-4 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-4 py-3 text-left transition-colors hover:border-[var(--line-strong)]"
            >
              <div className="min-w-0">
                <div className="text-xs font-semibold text-[var(--text)]">
                  已是高速通道的线路自动跳过
                </div>
                <div className="mt-0.5 text-[11px] leading-relaxed text-[var(--muted)]">
                  {dict.preaccel.skip443Hint}
                </div>
              </div>
              <span
                className={`inline-flex h-5 w-9 shrink-0 items-center rounded-full p-0.5 transition-colors ${
                  skip443Native ? "bg-[var(--accent)]" : "bg-[var(--line-strong)]"
                }`}
              >
                <span
                  className={`h-4 w-4 rounded-full bg-[var(--card)] transition-transform ${
                    skip443Native ? "translate-x-4" : "translate-x-0"
                  }`}
                />
              </span>
            </button>

            {/* 4.2 & 4.3 驱动诊断 / 本地 SOCKS5 命令 + Windows 加速范围与自定义进程名 */}
            <WinDivertDiagPanel
              isWindows={isWindows}
              platformOs={platformOs}
              preaccelSummary={preaccelSummary}
              globalPreAccel={globalPreAccel}
              effectiveGlobalPort={effectiveGlobalPort}
              installBusy={installBusy}
              elevatingGlobal={elevatingGlobal}
              savingGlobalScope={savingGlobalScope}
              globalScope={globalScope}
              targetProcesses={targetProcesses}
              detectedSecurityProducts={detectedSecurityProducts}
              verifyCheckedClock={verifyCheckedClock}
              verifyMessageText={verifyMessageText}
              verifyStateFallbackLabel={verifyStateFallbackLabel}
              isVerifiedVerify={isVerifiedVerify}
              isDegradedVerify={isDegradedVerify}
              onInstallWinDivert={handleInstallWinDivert}
              onRelaunchAdminGlobal={handleRelaunchAdminGlobal}
              onSelectGlobalScope={handleSelectGlobalScope}
              onAddTargetProcesses={handleAddTargetProcesses}
              onRemoveTargetProcess={handleRemoveTargetProcess}
              onResetTargetProcesses={handleResetTargetProcesses}
            />
          </div>
        )}
      </section>

      {/* 弹窗 1：添加中转线路（手动填表添加 + 粘贴导入码 / JSON 双标签） */}
      <AddRelayModal
        open={showAddModal}
        initialTab={addModalTab}
        relays={relays}
        inTauri={inTauri}
        onClose={() => setShowAddModal(false)}
        onRelaysChange={setRelays}
        onImportWarnings={setImportWarnings}
      />

      {/* 弹窗 2：国内连通检测地址（华为 / 小米 204 + 自定义） */}
      <ProbeSourceModal
        open={showProbeModal}
        probeUrl={probeUrl}
        probeValidation={probeValidation}
        onProbeUrlChange={setProbeUrl}
        onSelectPreset={handleSelectProbePreset}
        onSaveCustom={handleSaveCustomProbe}
        onClose={() => setShowProbeModal(false)}
      />

      {/* 弹窗 3：猫云分享包（按需懒加载） */}
      {shareModalOpen && (
        <Suspense fallback={null}>
          <ShareBundleModal
            open={shareModalOpen}
            mode={shareModalMode}
            allowModeSwitch
            defaultTab="relays"
            defaultPackName="国内提速中转分享包"
            initialRelayIds={enabledRelayIds}
            onClose={() => setShareModalOpen(false)}
          />
        </Suspense>
      )}

      {/* 弹窗 3.5：软路由 / 透明网关一键导出（按需懒加载） */}
      {gatewayModalOpen && (
        <Suspense fallback={null}>
          <GatewayExportModal
            open={gatewayModalOpen}
            defaultProfile="relay_fragment"
            onClose={() => setGatewayModalOpen(false)}
          />
        </Suspense>
      )}

      {/* 弹窗 4：删除中转线路二次确认 */}
      <DeleteRelayModal
        relay={pendingDeleteRelay}
        deleting={deletingRelay}
        onClose={() => setPendingDeleteRelay(null)}
        onConfirm={handleConfirmRemoveRelay}
      />
    </div>
  );
}
