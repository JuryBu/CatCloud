import {
  Activity,
  ArrowDown,
  ArrowRight,
  ArrowUp,
  Check,
  CheckCircle2,
  ChevronDown,
  Clock,
  Cpu,
  Eye,
  EyeOff,
  Globe,
  HardDriveDownload,
  HardDriveUpload,
  Layers,
  Minimize2,
  PictureInPicture2,
  Plus,
  Power,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
  Wifi,
  X,
  Zap,
} from "lucide-react";
import { type FormEvent, useEffect, useMemo, useRef, useState } from "react";
import {
  type ExitIpInfo,
  type ProxyMode,
  type ProxyNode,
  type SiteCheckItem,
  catcloudApi,
  formatErrorMessage,
  isTauriEnv,
} from "../api/tauri";
import { MASCOT_STATE_LABELS, type MascotState, MascotSprite } from "../components/MascotSprite";
import { TrafficSparkline, formatBytes, formatRate } from "../components/TrafficSparkline";
import { appActions, useAppSelector, useLatestTraffic } from "../store/appStore";

const PROXY_MODE_OPTIONS: ReadonlyArray<{ id: ProxyMode; label: string; hint: string }> = [
  { id: "rule", label: "规则", hint: "国内直连、海外自动走代理" },
  { id: "global", label: "全局", hint: "所有网站全部走当前代理" },
  { id: "direct", label: "直连", hint: "暂时绕过代理直接联网" },
];

const MAX_VISIBLE_QUICK_NODES = 60;

function formatQuickSiteName(name: string): string {
  const trimmed = name.trim();
  if (/^google\s*204$/i.test(trimmed)) return "Google 连通";
  return trimmed;
}

function formatUptime(sec: number): string {
  if (!Number.isFinite(sec) || sec <= 0) return "刚启动";
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d > 0) return `${d} 天 ${h} 小时`;
  if (h > 0) return `${h} 小时 ${m} 分`;
  if (m > 0) return `${m} 分钟`;
  return "不到 1 分钟";
}

function getLatencyColor(latencyMs: number | null, ok: boolean | null): string {
  if (ok === false) return "var(--red)";
  if (latencyMs === null) return "var(--muted)";
  if (latencyMs <= 140) return "var(--green)";
  if (latencyMs <= 300) return "var(--amber)";
  return "var(--red)";
}

export function HomePage() {
  const runtime = useAppSelector((s) => s.runtime);
  const config = useAppSelector((s) => s.config);
  const groups = useAppSelector((s) => s.groups);
  const nodes = useAppSelector((s) => s.nodes);
  const probes = useAppSelector((s) => s.probes);
  const storeExitIp = useAppSelector((s) => s.exitIp);
  const storeQuickSites = useAppSelector((s) => s.quickSites);
  const mascotState = useAppSelector((s) => s.mascotState);
  const initialized = useAppSelector((s) => s.initialized);
  const traffic = useLatestTraffic();

  const [togglingProxy, setTogglingProxy] = useState(false);
  const [groupMenuOpen, setGroupMenuOpen] = useState(false);
  const [nodeMenuOpen, setNodeMenuOpen] = useState(false);
  const [nodeSearch, setNodeSearch] = useState("");
  const [switchingGroup, setSwitchingGroup] = useState(false);
  const [switchingNode, setSwitchingNode] = useState(false);

  const [sites, setSites] = useState<SiteCheckItem[]>(storeQuickSites);
  const [customSiteIds, setCustomSiteIds] = useState<string[]>([]);
  const [showAddSite, setShowAddSite] = useState(false);
  const [newSiteName, setNewSiteName] = useState("");
  const [newSiteUrl, setNewSiteUrl] = useState("");
  const [checkingSites, setCheckingSites] = useState(false);

  const [exitIp, setExitIp] = useState<ExitIpInfo>(storeExitIp);
  const [ipMasked, setIpMasked] = useState(true);
  const [refreshingIp, setRefreshingIp] = useState(false);

  const syncedSitesRef = useRef(false);
  const timerIdsRef = useRef<number[]>([]);
  const groupDropdownRef = useRef<HTMLDivElement | null>(null);
  const nodeDropdownRef = useRef<HTMLDivElement | null>(null);
  const nodeSearchInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    return () => {
      for (const id of timerIdsRef.current) {
        window.clearTimeout(id);
      }
      timerIdsRef.current = [];
    };
  }, []);

  useEffect(() => {
    if (initialized && !syncedSitesRef.current) {
      syncedSitesRef.current = true;
      setSites(storeQuickSites);
    }
  }, [storeQuickSites, initialized]);

  useEffect(() => {
    if (initialized) {
      setExitIp(storeExitIp);
    }
  }, [storeExitIp, initialized]);

  // Close group / node popovers on outside click or Escape
  useEffect(() => {
    if (!groupMenuOpen && !nodeMenuOpen) return;
    const handlePointerDown = (ev: MouseEvent) => {
      const target = ev.target as Node;
      if (groupMenuOpen && groupDropdownRef.current && !groupDropdownRef.current.contains(target)) {
        setGroupMenuOpen(false);
      }
      if (nodeMenuOpen && nodeDropdownRef.current && !nodeDropdownRef.current.contains(target)) {
        setNodeMenuOpen(false);
      }
    };
    const handleKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") {
        setGroupMenuOpen(false);
        setNodeMenuOpen(false);
      }
    };
    document.addEventListener("mousedown", handlePointerDown);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("mousedown", handlePointerDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [groupMenuOpen, nodeMenuOpen]);

  useEffect(() => {
    if (!nodeMenuOpen) {
      setNodeSearch("");
      return;
    }
    const tid = window.setTimeout(() => nodeSearchInputRef.current?.focus(), 20);
    return () => window.clearTimeout(tid);
  }, [nodeMenuOpen]);

  const scheduleTimeout = (fn: () => void, ms: number) => {
    const id = window.setTimeout(() => {
      timerIdsRef.current = timerIdsRef.current.filter((item) => item !== id);
      fn();
    }, ms);
    timerIdsRef.current.push(id);
  };

  // Active group & candidate nodes for the interactive route selector
  const activeGroup = useMemo(() => {
    if (groups.length === 0) return null;
    return groups.find((g) => g.id === runtime.active_group_id) ?? groups[0];
  }, [groups, runtime.active_group_id]);

  const activeGroupId = activeGroup?.id ?? runtime.active_group_id ?? "";

  const groupCandidateNodes = useMemo<ProxyNode[]>(() => {
    if (nodes.length === 0) return [];
    const enabledNodes = nodes.filter((n) => n.enabled);
    const pool = enabledNodes.length > 0 ? enabledNodes : nodes;
    if (activeGroup && activeGroup.member_node_ids.length > 0) {
      const memberSet = new Set(activeGroup.member_node_ids);
      const matched = pool.filter((n) => memberSet.has(n.id));
      if (matched.length > 0) return matched;
    }
    return pool;
  }, [activeGroup, nodes]);

  const currentNodeId = runtime.active_node_id || activeGroup?.active_node_id || "";

  const sortedFilteredNodes = useMemo<ProxyNode[]>(() => {
    if (!nodeMenuOpen) return [];
    const q = nodeSearch.trim().toLowerCase();
    const filtered = q
      ? groupCandidateNodes.filter(
          (n) =>
            n.name.toLowerCase().includes(q) ||
            n.region_code.toLowerCase().includes(q)
        )
      : groupCandidateNodes;

    return [...filtered].sort((a, b) => {
      if (a.id === currentNodeId) return -1;
      if (b.id === currentNodeId) return 1;
      const pa = probes[a.id];
      const pb = probes[b.id];
      const aOk = pa ? pa.ok !== false && pa.latency_ms !== null : false;
      const bOk = pb ? pb.ok !== false && pb.latency_ms !== null : false;
      if (aOk !== bOk) return aOk ? -1 : 1;
      if (aOk && bOk && pa && pb && pa.latency_ms !== null && pb.latency_ms !== null) {
        return pa.latency_ms - pb.latency_ms;
      }
      const aFailed = pa?.ok === false;
      const bFailed = pb?.ok === false;
      if (aFailed !== bFailed) return aFailed ? 1 : -1;
      return a.name.localeCompare(b.name);
    });
  }, [currentNodeId, groupCandidateNodes, nodeMenuOpen, nodeSearch, probes]);

  const visibleDropdownNodes = useMemo(
    () => sortedFilteredNodes.slice(0, MAX_VISIBLE_QUICK_NODES),
    [sortedFilteredNodes]
  );

  const activeNodeRecord = useMemo(
    () => nodes.find((n) => n.id === currentNodeId) ?? null,
    [nodes, currentNodeId]
  );
  const activeNodeProbe = currentNodeId ? probes[currentNodeId] : undefined;

  const displayGroupName =
    activeGroup?.name ||
    (runtime.active_group_name && runtime.active_group_name !== "等待连接"
      ? runtime.active_group_name
      : groups.length > 0
        ? groups[0].name
        : "默认路线组");

  const displayNodeName =
    activeNodeRecord?.name ||
    (runtime.active_node_name && runtime.active_node_name !== "待核心就绪"
      ? runtime.active_node_name
      : nodes.length === 0
        ? "还没有可用节点"
        : "点此选择节点");

  const displayRegion =
    activeNodeRecord?.region_code ||
    (runtime.active_node_region && runtime.active_node_region !== "--"
      ? runtime.active_node_region
      : "");

  const displayLatencyMs =
    runtime.active_node_latency_ms ?? activeNodeProbe?.latency_ms ?? null;
  const displayUpMbps =
    runtime.active_node_up_mbps ?? activeNodeProbe?.up_mbps ?? null;

  // Main power switch state & human-friendly traffic status
  const isProxyEnabled =
    runtime.running && (runtime.system_proxy_enabled || runtime.tun_enabled);

  const trafficStatusSentence = (() => {
    if (!isProxyEnabled) {
      return runtime.running
        ? "未开启代理，仅本地待命，不走流量"
        : "未开启代理，电脑流量全部直连";
    }
    if (runtime.proxy_mode === "direct") {
      return "当前为直连模式，网络流量不经代理";
    }
    if (runtime.tun_enabled && runtime.system_proxy_enabled) {
      return "已接管电脑全部网络流量（含桌面软件）";
    }
    if (runtime.tun_enabled) {
      return "已通过虚拟网卡接管电脑全部流量";
    }
    return "已接管电脑网络流量";
  })();

  // Dual-form mascot: cream cat idle by default, working sprite during probing/switching/toggling
  const effectiveMascotState: MascotState = checkingSites
    ? "searching"
    : switchingNode || switchingGroup || togglingProxy
      ? "thinking"
      : mascotState;

  const handleToggleMainPower = async () => {
    if (togglingProxy) return;
    if (!isProxyEnabled && nodes.length === 0) {
      appActions.showToast("还没有导入节点，正在带你去导入订阅", "warn");
      appActions.setNav("nodes");
      return;
    }
    setTogglingProxy(true);
    try {
      if (!isProxyEnabled) {
        if (!runtime.running) {
          const started = await catcloudApi.startCore();
          appActions.syncRuntime(started);
        }
        await appActions.toggleSystemProxy(true);
      } else {
        const hadSysProxy = runtime.system_proxy_enabled;
        const hadTun = runtime.tun_enabled;
        const bothEnabled = hadSysProxy && hadTun;
        let sysOk = true;
        let tunOk = true;
        if (hadSysProxy) {
          sysOk = await appActions.toggleSystemProxy(false, bothEnabled);
        }
        if (hadTun) {
          tunOk = await appActions.toggleTun(false, bothEnabled);
        }
        if (bothEnabled && sysOk && tunOk) {
          appActions.showToast("已关闭系统代理与虚拟网卡", "info");
        }
      }
    } catch (err) {
      appActions.showToast(`切换代理开关失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setTogglingProxy(false);
    }
  };

  const handleSelectGroup = async (groupId: string) => {
    setGroupMenuOpen(false);
    if (switchingGroup || groupId === activeGroupId) return;
    setSwitchingGroup(true);
    try {
      await appActions.setActiveGroup(groupId);
    } finally {
      setSwitchingGroup(false);
    }
  };

  const handleSelectNode = async (nodeId: string) => {
    setNodeMenuOpen(false);
    if (switchingNode) return;
    if (!activeGroupId) {
      appActions.showToast("当前还没有路线分组，请先在「智能多选组」里创建一个", "warn");
      return;
    }
    setSwitchingNode(true);
    try {
      await appActions.selectGroupNode(activeGroupId, nodeId);
    } finally {
      setSwitchingNode(false);
    }
  };

  const handleSwitchNextBest = async () => {
    if (switchingNode) return;
    setSwitchingNode(true);
    try {
      await appActions.switchNextBestNode();
    } finally {
      setSwitchingNode(false);
    }
  };

  const handleEnterWindowless = async () => {
    try {
      await catcloudApi.enterWindowlessMode();
      appActions.showToast("已收进托盘省内存，点击右下角托盘图标即可随时打开", "info");
    } catch (err) {
      appActions.showToast(`收进托盘失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const persistQuickSites = async (nextSites: SiteCheckItem[]): Promise<boolean> => {
    const payload = nextSites.map((s) => ({
      id: s.id,
      name: s.name,
      url: s.url,
    }));
    try {
      await catcloudApi.saveExtendedSettings({ core_runtime: { quick_check_sites: payload } });
      appActions.syncQuickSites(nextSites);
      return true;
    } catch (err) {
      appActions.showToast(`保存检测网站失败：${formatErrorMessage(err)}`, "warn");
      return false;
    }
  };

  const handleCheckSites = async () => {
    if (checkingSites) return;
    setCheckingSites(true);
    appActions.setMascotState("searching");
    try {
      const freshSites = await catcloudApi.checkQuickSites();
      if (isTauriEnv()) {
        setSites(freshSites);
        appActions.syncQuickSites(freshSites);
      } else {
        const freshById = new Map(freshSites.map((item) => [item.id, item]));
        setSites((prev) => {
          const baseList = prev.length > 0 ? prev : freshSites;
          return baseList.map((site) => {
            const updated = freshById.get(site.id);
            if (updated) return updated;
            return { ...site, latency_ms: 88, ok: true };
          });
        });
      }
      appActions.showToast("网站连通检测完成", "ok");
    } catch (err) {
      appActions.showToast(`网站检测失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setCheckingSites(false);
      appActions.setMascotState("idle");
    }
  };

  const handleAddSite = async (ev: FormEvent) => {
    ev.preventDefault();
    const trimmedName = newSiteName.trim();
    const trimmedUrl = newSiteUrl.trim();
    if (!trimmedName || !trimmedUrl) {
      appActions.showToast("请填写网站名称和网址", "warn");
      return;
    }
    const normalizedUrl = /^https?:\/\//i.test(trimmedUrl) ? trimmedUrl : `https://${trimmedUrl}`;
    try {
      const parsed = new URL(normalizedUrl);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        appActions.showToast("网址需要以 http:// 或 https:// 开头", "warn");
        return;
      }
    } catch {
      appActions.showToast("请输入正确的网址格式", "warn");
      return;
    }

    const id = `site-custom-${Date.now()}`;
    const item: SiteCheckItem = {
      id,
      name: trimmedName,
      url: normalizedUrl,
      latency_ms: null,
      ok: null,
    };
    const nextSites = [...sites, item];
    const saved = await persistQuickSites(nextSites);
    if (!saved) return;

    setSites(nextSites);
    setCustomSiteIds((prev) => [...prev, id]);
    setNewSiteName("");
    setNewSiteUrl("");
    setShowAddSite(false);
    appActions.showToast(`已添加站点：${trimmedName}`, "ok");
  };

  const handleRemoveSite = async (id: string) => {
    const nextSites = sites.filter((item) => item.id !== id);
    const saved = await persistQuickSites(nextSites);
    if (!saved) return;
    setSites(nextSites);
    setCustomSiteIds((prev) => prev.filter((item) => item !== id));
    appActions.showToast("已移除该站点", "info");
  };

  const handleRefreshExitIp = async () => {
    if (refreshingIp) return;
    setRefreshingIp(true);
    appActions.setMascotState("searching");
    try {
      const info = await catcloudApi.getExitIpInfo();
      setExitIp(info);
      appActions.syncExitIp(info);
      appActions.showToast("出口信息已更新", "ok");
    } catch (err) {
      appActions.showToast(`检测出口信息失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      scheduleTimeout(() => {
        setRefreshingIp(false);
        appActions.setMascotState("idle");
      }, 240);
    }
  };

  const connectionSubLabel = runtime.tun_enabled
    ? "虚拟网卡已接管"
    : runtime.system_proxy_enabled
      ? "系统代理已接管"
      : "本地待命";

  const memSubLabel =
    config.gomemlimit_mb === 0
      ? "自动省内存"
      : `上限 ${config.gomemlimit_mb} MB`;

  const kpiCards = [
    {
      label: "上传速度",
      value: formatRate(traffic.up_bps),
      sub: "实时上传",
      accent: "var(--coral)",
      icon: ArrowUp,
    },
    {
      label: "下载速度",
      value: formatRate(traffic.down_bps),
      sub: "实时下载",
      accent: "var(--sky)",
      icon: ArrowDown,
    },
    {
      label: "当前连接",
      value: `${traffic.connections}`,
      sub: connectionSubLabel,
      accent: "var(--text)",
      icon: Activity,
    },
    {
      label: "累计上传",
      value: formatBytes(traffic.up_total_bytes),
      sub: "本次启动",
      accent: "var(--accent)",
      icon: HardDriveUpload,
    },
    {
      label: "累计下载",
      value: formatBytes(traffic.down_total_bytes),
      sub: "本次启动",
      accent: "var(--accent)",
      icon: HardDriveDownload,
    },
    {
      label: "内核内存",
      value: `${traffic.memory_mb.toFixed(1)} MB`,
      sub: memSubLabel,
      accent: "var(--green)",
      icon: Cpu,
    },
  ];

  // Determine whether exit IP has actually been probed
  const hasExitIpData =
    Boolean(exitIp.ip_raw?.trim()) ||
    (exitIp.ip_masked.trim().length > 0 && !exitIp.ip_masked.includes("--"));

  const displayedExitAddress = !hasExitIpData
    ? "待检测"
    : ipMasked
      ? exitIp.ip_masked
      : exitIp.ip_raw?.trim() || exitIp.ip_masked;

  const displayedExitLocation =
    !hasExitIpData || exitIp.location === "未连接" ? "待检测" : exitIp.location;

  const displayedLineStatus = !hasExitIpData
    ? "待检测"
    : exitIp.isp && exitIp.isp !== "待核心启动探测"
      ? exitIp.isp === "Example Transit Network"
        ? "东京示例线路"
        : exitIp.isp
      : runtime.running
        ? "已连通"
        : "待检测";

  const googleStatusBadge =
    exitIp.google_clean === true
      ? {
          cls: "bg-[var(--green-soft)] text-[var(--green)]",
          label: "正常（地区未偏移）",
          state: "clean" as const,
        }
      : exitIp.google_clean === false
        ? {
            cls: "bg-[var(--red-soft)] text-[var(--red)]",
            label: "地区异常（可能受限）",
            state: "risk" as const,
          }
        : {
            cls: "border border-[var(--line)] bg-[var(--card)] text-[var(--muted)]",
            label: "待检测",
            state: "unknown" as const,
          };

  return (
    <div className="space-y-3 pb-3">
      {/* Gentle two-step onboarding banner when no nodes have been imported yet */}
      {initialized && nodes.length === 0 && (
        <section className="cc-card cc-glass rounded-2xl border-[var(--accent)]/45 bg-[var(--accent-soft)]/50 p-4">
          <div className="flex flex-col gap-3.5 sm:flex-row sm:items-center sm:justify-between">
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <Sparkles className="h-4 w-4 text-[var(--accent)]" />
                <h2 className="text-sm font-semibold text-[var(--text)]">两步开始使用猫猫云梯</h2>
              </div>
              <div className="flex flex-col gap-1.5 text-xs text-[var(--text-secondary)] sm:flex-row sm:items-center sm:gap-5">
                <div className="flex items-center gap-2">
                  <span className="inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-[var(--accent)] text-[11px] font-bold text-[var(--accent-ink)]">
                    1
                  </span>
                  <span>导入订阅链接，或从已有代理软件一键迁移节点</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-[var(--accent)]/60 bg-[var(--card)] text-[11px] font-bold text-[var(--accent)]">
                    2
                  </span>
                  <span>打开下方代理总开关，即可轻松上网</span>
                </div>
              </div>
            </div>

            <button
              type="button"
              onClick={() => appActions.setNav("nodes")}
              className="inline-flex shrink-0 items-center justify-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-2.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90"
            >
              <span>去导入节点</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </div>
        </section>
      )}

      {/* Top Hero Dual-Zone Card: Main Proxy Power Switch + Interactive Current Route Selector */}
      <section className="cc-card cc-glass relative z-20 rounded-2xl p-5">
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-12 lg:gap-6">
          {/* Left Zone: Prominent Power Switch + Mode & Takeover Controls */}
          <div className="flex flex-col justify-between gap-4 lg:col-span-5 lg:border-r lg:border-[var(--line)]/70 lg:pr-6">
            <div className="space-y-3">
              {/* Large Power Toggle Button */}
              <button
                type="button"
                disabled={togglingProxy}
                onClick={() => void handleToggleMainPower()}
                className={`group flex w-full items-center gap-3.5 rounded-2xl border px-4 py-3.5 text-left transition-all disabled:opacity-70 ${
                  isProxyEnabled
                    ? "border-[var(--green)]/55 bg-[var(--green-soft)] hover:border-[var(--green)]"
                    : "border-[var(--line-strong)] bg-[var(--bg-elevated)] hover:border-[var(--accent)] hover:bg-[var(--accent-soft)]/45"
                }`}
              >
                <span
                  className={`relative flex h-12 w-12 shrink-0 items-center justify-center rounded-full transition-colors ${
                    isProxyEnabled
                      ? "bg-[var(--green)] text-[var(--accent-ink)]"
                      : "border border-[var(--line-strong)] bg-[var(--card)] text-[var(--accent)] group-hover:border-[var(--accent)]"
                  }`}
                >
                  {togglingProxy ? (
                    <RefreshCw className="h-5 w-5 animate-spin" />
                  ) : (
                    <Power className="h-5 w-5" />
                  )}
                  {isProxyEnabled && !togglingProxy && (
                    <span className="cc-pulse-dot absolute -right-0.5 -top-0.5 h-3 w-3 rounded-full border-2 border-[var(--card)] bg-[var(--green)]" />
                  )}
                </span>

                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-base font-bold tracking-tight text-[var(--text)]">
                      {togglingProxy
                        ? isProxyEnabled
                          ? "正在关闭代理…"
                          : "正在开启代理…"
                        : isProxyEnabled
                          ? "已开启代理"
                          : "点击开启代理"}
                    </span>
                  </div>
                  <p className="mt-0.5 truncate text-xs text-[var(--text-secondary)]">
                    {trafficStatusSentence}
                  </p>
                </div>
              </button>
            </div>

            {/* Mode + Takeover Method Controls */}
            <div className="flex flex-wrap items-center justify-between gap-2.5">
              {/* Proxy Mode Segmented Control */}
              <div
                className="inline-flex rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-0.5 text-xs"
                role="group"
                aria-label="代理模式"
              >
                {PROXY_MODE_OPTIONS.map((mode) => {
                  const selected = runtime.proxy_mode === mode.id;
                  return (
                    <button
                      key={mode.id}
                      type="button"
                      onClick={() => void appActions.setProxyMode(mode.id)}
                      title={mode.hint}
                      className={`rounded-lg px-3 py-1.5 font-medium transition-colors ${
                        selected
                          ? "bg-[var(--card)] text-[var(--accent)] shadow-xs"
                          : "text-[var(--muted)] hover:text-[var(--text)]"
                      }`}
                    >
                      {mode.label}
                    </button>
                  );
                })}
              </div>

              {/* Takeover Method Pills */}
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => void appActions.toggleSystemProxy()}
                  className={`inline-flex items-center gap-1.5 rounded-xl border px-2.5 py-1.5 text-xs font-medium transition-colors ${
                    runtime.system_proxy_enabled
                      ? "border-[var(--green)]/45 bg-[var(--green-soft)] text-[var(--green)]"
                      : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:text-[var(--text)]"
                  }`}
                  title="接管浏览器和大多数常用软件"
                >
                  <Wifi className="h-3.5 w-3.5" />
                  <span>系统代理</span>
                </button>

                <button
                  type="button"
                  onClick={() => void appActions.toggleTun()}
                  className={`inline-flex items-center gap-1.5 rounded-xl border px-2.5 py-1.5 text-xs font-medium transition-colors ${
                    runtime.tun_enabled
                      ? "border-[var(--accent)]/55 bg-[var(--accent-soft)] text-[var(--accent)]"
                      : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:text-[var(--text)]"
                  }`}
                  title={
                    runtime.tun_admin_ready
                      ? "接管电脑全部软件和命令行流量"
                      : "开启虚拟网卡需要管理员权限"
                  }
                >
                  <ShieldCheck className="h-3.5 w-3.5" />
                  <span>虚拟网卡</span>
                </button>
              </div>
            </div>
          </div>

          {/* Right Zone: Interactive Current Route Switcher + Quick Actions + Dual-Form Mascot */}
          <div className="flex flex-col justify-between gap-4 lg:col-span-7">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0 flex-1 space-y-2.5">
                {/* Row 1: Group Dropdown + Pre-accel & Campus Portal Badges */}
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs font-medium text-[var(--muted)]">当前路线</span>

                  {/* Interactive Group Switcher Dropdown */}
                  <div ref={groupDropdownRef} className="relative">
                    <button
                      type="button"
                      disabled={switchingGroup}
                      onClick={() => {
                        setNodeMenuOpen(false);
                        setGroupMenuOpen((open) => !open);
                      }}
                      aria-expanded={groupMenuOpen}
                      className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
                        groupMenuOpen
                          ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                          : "border-[var(--accent)]/35 bg-[var(--accent-soft)]/70 text-[var(--accent)] hover:border-[var(--accent)]"
                      }`}
                      title="点击切换多选组"
                    >
                      <Layers className="h-3 w-3 shrink-0" />
                      <span className="max-w-[160px] truncate">{displayGroupName}</span>
                      <ChevronDown
                        className={`h-3 w-3 shrink-0 transition-transform ${
                          groupMenuOpen ? "rotate-180" : ""
                        }`}
                      />
                    </button>

                    {groupMenuOpen && (
                      <div
                        className="absolute left-0 top-[calc(100%+6px)] z-50 w-[240px] rounded-2xl border border-[var(--line-strong)] bg-[var(--surface)] p-2 text-xs"
                        style={{ boxShadow: "var(--shadow-popover)" }}
                      >
                        <div className="mb-1.5 px-2 text-[11px] font-medium text-[var(--muted)]">
                          切换路线分组
                        </div>
                        <div className="max-h-[220px] space-y-0.5 overflow-y-auto">
                          {groups.map((g) => {
                            const selected = g.id === activeGroupId;
                            return (
                              <button
                                key={g.id}
                                type="button"
                                onClick={() => void handleSelectGroup(g.id)}
                                className={`flex w-full items-center justify-between gap-2 rounded-xl px-2.5 py-2 text-left transition-colors ${
                                  selected
                                    ? "bg-[var(--accent-soft)] font-semibold text-[var(--text)]"
                                    : "text-[var(--text-secondary)] hover:bg-[var(--card)] hover:text-[var(--text)]"
                                }`}
                              >
                                <span className="truncate">{g.name}</span>
                                <span className="flex shrink-0 items-center gap-1.5 text-[11px] text-[var(--muted)]">
                                  <span>{g.member_node_ids.length} 个</span>
                                  {selected && <Check className="h-3.5 w-3.5 text-[var(--accent)]" />}
                                </span>
                              </button>
                            );
                          })}
                          {groups.length === 0 && (
                            <div className="px-2 py-3 text-center text-[11px] text-[var(--muted)]">
                              还没有创建分组
                            </div>
                          )}
                        </div>
                        <div className="mt-1.5 border-t border-[var(--line)] pt-1.5">
                          <button
                            type="button"
                            onClick={() => {
                              setGroupMenuOpen(false);
                              appActions.setNav("groups");
                            }}
                            className="flex w-full items-center justify-between rounded-lg px-2 py-1.5 text-[11px] text-[var(--accent)] hover:bg-[var(--card)]"
                          >
                            <span>管理智能多选组</span>
                            <ArrowRight className="h-3 w-3" />
                          </button>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Domestic Pre-Acceleration Status Tag */}
                  {runtime.preaccel_active && (
                    <button
                      type="button"
                      onClick={() => appActions.setNav("preaccel")}
                      className="inline-flex items-center gap-1 rounded-full border border-[var(--green)]/50 bg-[var(--green-soft)] px-2.5 py-1 text-[11px] font-semibold transition-opacity hover:opacity-90"
                      style={{ color: "color-mix(in srgb, var(--green) 78%, var(--text))" }}
                      title="点击查看国内提速设置"
                    >
                      <Zap className="h-3 w-3" />
                      <span>国内提速中</span>
                    </button>
                  )}

                  {runtime.captive_portal_required && (
                    <button
                      type="button"
                      onClick={() => appActions.setNav("preaccel")}
                      className="inline-flex items-center gap-1 rounded-full bg-[var(--amber-soft)] px-2.5 py-1 text-[11px] font-medium text-[var(--amber)]"
                    >
                      <ShieldAlert className="h-3 w-3" />
                      <span>校园网需认证</span>
                    </button>
                  )}
                </div>

                {/* Row 2: Clickable Active Node Picker */}
                <div ref={nodeDropdownRef} className="relative">
                  <button
                    type="button"
                    onClick={() => {
                      if (nodes.length === 0) {
                        appActions.setNav("nodes");
                        return;
                      }
                      setGroupMenuOpen(false);
                      setNodeMenuOpen((open) => !open);
                    }}
                    aria-expanded={nodeMenuOpen}
                    className={`group flex w-full items-center justify-between gap-3 rounded-2xl border px-3.5 py-2.5 text-left transition-colors ${
                      nodeMenuOpen
                        ? "border-[var(--accent)] bg-[var(--bg-elevated)]"
                        : "border-[var(--line)] bg-[var(--bg-elevated)] hover:border-[var(--line-strong)]"
                    }`}
                    title={nodes.length === 0 ? "前往导入节点" : "点击展开当前分组节点列表"}
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="truncate text-base font-semibold tracking-tight text-[var(--text)]">
                          {displayNodeName}
                        </span>
                        {displayRegion && (
                          <span className="shrink-0 rounded-md border border-[var(--line)] bg-[var(--card)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--text-secondary)]">
                            {displayRegion}
                          </span>
                        )}
                      </div>

                      <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-xs text-[var(--muted)]">
                        <span>
                          延迟{" "}
                          <strong
                            className="cc-mono font-semibold"
                            style={{
                              color: getLatencyColor(
                                displayLatencyMs,
                                activeNodeProbe ? activeNodeProbe.ok : null
                              ),
                            }}
                          >
                            {activeNodeProbe?.ok === false
                              ? "超时"
                              : displayLatencyMs !== null
                                ? `${Math.round(displayLatencyMs)} ms`
                                : "未测"}
                          </strong>
                        </span>
                        <span>
                          上行{" "}
                          <strong className="cc-mono font-semibold text-[var(--green)]">
                            {displayUpMbps !== null ? `${displayUpMbps.toFixed(1)} Mbps` : "未测"}
                          </strong>
                        </span>
                        {nodes.length > 0 && (
                          <span className="text-[11px] font-medium text-[var(--accent-strong)] group-hover:underline">
                            点击切换节点
                          </span>
                        )}
                      </div>
                    </div>

                    <ChevronDown
                      className={`h-4 w-4 shrink-0 text-[var(--muted)] transition-transform group-hover:text-[var(--text)] ${
                        nodeMenuOpen ? "rotate-180 text-[var(--accent)]" : ""
                      }`}
                    />
                  </button>

                  {/* Node Quick Picker Dropdown with Search */}
                  {nodeMenuOpen && (
                    <div
                      className="absolute left-0 right-0 top-[calc(100%+8px)] z-50 rounded-2xl border border-[var(--line-strong)] bg-[var(--surface)] p-2.5 text-xs"
                      style={{ boxShadow: "var(--shadow-popover)" }}
                    >
                      <div className="relative mb-2">
                        <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--muted)]" />
                        <input
                          ref={nodeSearchInputRef}
                          type="text"
                          value={nodeSearch}
                          onChange={(e) => setNodeSearch(e.target.value)}
                          placeholder="搜索节点名称或地区…"
                          className="w-full rounded-xl border border-[var(--line)] bg-[var(--card)] py-1.5 pl-8 pr-7 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                        />
                        {nodeSearch && (
                          <button
                            type="button"
                            onClick={() => setNodeSearch("")}
                            className="absolute right-2 top-1/2 -translate-y-1/2 text-[var(--muted)] hover:text-[var(--text)]"
                            aria-label="清空搜索"
                          >
                            <X className="h-3.5 w-3.5" />
                          </button>
                        )}
                      </div>

                      <div className="max-h-[248px] space-y-1 overflow-y-auto pr-0.5">
                        {visibleDropdownNodes.map((node) => {
                          const isCurrent = node.id === currentNodeId;
                          const snap = probes[node.id];
                          const lat = snap?.latency_ms ?? null;
                          const up = snap?.up_mbps ?? null;
                          const latColor = getLatencyColor(lat, snap ? snap.ok : null);
                          return (
                            <button
                              key={node.id}
                              type="button"
                              disabled={switchingNode}
                              onClick={() => void handleSelectNode(node.id)}
                              className={`flex w-full items-center justify-between gap-2 rounded-xl border px-2.5 py-2 text-left transition-colors ${
                                isCurrent
                                  ? "border-[var(--accent)]/55 bg-[var(--accent-soft)] text-[var(--text)]"
                                  : "border-transparent bg-transparent text-[var(--text-secondary)] hover:bg-[var(--card)] hover:text-[var(--text)]"
                              }`}
                            >
                              <div className="flex min-w-0 items-center gap-2">
                                <span
                                  className="h-2 w-2 shrink-0 rounded-full"
                                  style={{ backgroundColor: latColor }}
                                />
                                <span className="truncate font-medium">{node.name}</span>
                                {node.region_code && node.region_code !== "--" && (
                                  <span className="shrink-0 rounded bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]">
                                    {node.region_code}
                                  </span>
                                )}
                                {isCurrent && (
                                  <span className="shrink-0 rounded-full bg-[var(--accent)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--accent-ink)]">
                                    当前
                                  </span>
                                )}
                              </div>

                              <div className="flex shrink-0 items-center gap-2.5 cc-mono text-[11px]">
                                {up !== null && (
                                  <span className="text-[var(--green)]">
                                    ↑{up.toFixed(1)}M
                                  </span>
                                )}
                                <span className="font-semibold" style={{ color: latColor }}>
                                  {snap?.ok === false
                                    ? "超时"
                                    : lat !== null
                                      ? `${Math.round(lat)} ms`
                                      : "未测"}
                                </span>
                              </div>
                            </button>
                          );
                        })}

                        {sortedFilteredNodes.length > MAX_VISIBLE_QUICK_NODES && (
                          <div className="rounded-lg bg-[var(--bg-elevated)] px-2.5 py-1.5 text-center text-[11px] text-[var(--text-secondary)]">
                            已显示前 {MAX_VISIBLE_QUICK_NODES} 个，输入关键词可秒搜全部{" "}
                            {sortedFilteredNodes.length} 个
                          </div>
                        )}

                        {sortedFilteredNodes.length === 0 && (
                          <div className="py-5 text-center text-[11px] text-[var(--muted)]">
                            没有找到匹配的节点
                          </div>
                        )}
                      </div>

                      <div className="mt-2 flex items-center justify-between border-t border-[var(--line)] pt-2 text-[11px] text-[var(--muted)]">
                        <span>当前分组共 {groupCandidateNodes.length} 个可选节点</span>
                        <button
                          type="button"
                          onClick={() => {
                            setNodeMenuOpen(false);
                            appActions.setNav("speedtest");
                          }}
                          className="text-[var(--accent)] hover:underline"
                        >
                          去批量测速 →
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Dual-Form Mascot Panel */}
              <button
                type="button"
                onClick={() =>
                  appActions.setMascotState(
                    effectiveMascotState === "idle"
                      ? runtime.preaccel_active
                        ? "complete"
                        : "searching"
                      : "idle"
                  )
                }
                className="hidden min-w-[84px] shrink-0 flex-col items-center justify-center rounded-2xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-2 text-center transition-colors hover:border-[var(--line-strong)] sm:flex"
                title="点击切换奶油猫饼待机与工作形态"
              >
                <div className="flex h-[68px] w-[68px] items-end justify-center pb-0.5">
                  <MascotSprite state={effectiveMascotState} scale={2} />
                </div>
                <div className="mt-1.5 whitespace-nowrap leading-none text-[10px] text-[var(--muted)]">
                  {MASCOT_STATE_LABELS[effectiveMascotState]}
                </div>
              </button>
            </div>

            {/* Row 3: Compact Quick Actions */}
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                disabled={switchingNode || nodes.length === 0}
                onClick={() => void handleSwitchNextBest()}
                className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-3.5 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-50"
              >
                <Zap className="h-3.5 w-3.5" />
                <span>{switchingNode ? "正在切换…" : "换下一个更快节点"}</span>
              </button>

              <button
                type="button"
                onClick={() => void appActions.toggleCapsule()}
                className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--line-strong)] hover:text-[var(--accent)]"
                title="显示桌面小悬浮条"
              >
                <PictureInPicture2 className="h-3.5 w-3.5 text-[var(--accent)]" />
                <span>悬浮小窗</span>
              </button>

              <button
                type="button"
                onClick={() => void handleEnterWindowless()}
                className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--line-strong)] hover:text-[var(--text)]"
                title="关闭主界面仅留托盘图标，大幅减少内存占用"
              >
                <Minimize2 className="h-3.5 w-3.5 text-[var(--green)]" />
                <span>托盘省内存</span>
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* Middle Traffic Section: 10-Minute Sparkline + 6 Clean Metric Cards */}
      <section className="space-y-3">
        <TrafficSparkline variant="full" />

        <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
          {kpiCards.map((card) => {
            const Icon = card.icon;
            return (
              <div
                key={card.label}
                className="cc-card cc-glass rounded-2xl px-3.5 py-3"
              >
                <div className="flex items-center justify-between text-[11px] text-[var(--muted)]">
                  <span>{card.label}</span>
                  <Icon className="h-3.5 w-3.5 shrink-0" style={{ color: card.accent }} />
                </div>
                <div
                  className="mt-1.5 cc-mono cc-tabular text-base font-semibold tracking-tight"
                  style={{ color: card.accent }}
                >
                  {card.value}
                </div>
                <div className="mt-0.5 truncate text-[10px] text-[var(--muted)]">
                  {card.sub}
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* Lower Detection Section: Site Connectivity Check + Exit Information */}
      <section className="grid grid-cols-1 gap-3 lg:grid-cols-12">
        {/* Site Connectivity Check Card */}
        <div className="cc-card cc-glass rounded-2xl p-4 lg:col-span-7">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold text-[var(--text)]">常用网站连通检测</h2>
              <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                点击右侧「测一下」检测，平时零后台流量
              </p>
            </div>
            <div className="flex items-center gap-1.5">
              <button
                type="button"
                onClick={() => setShowAddSite((v) => !v)}
                className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)]"
                title="添加常用网站"
              >
                {showAddSite ? <X className="h-3.5 w-3.5" /> : <Plus className="h-3.5 w-3.5" />}
                <span>{showAddSite ? "收起" : "添加"}</span>
              </button>
              <button
                type="button"
                disabled={checkingSites}
                onClick={() => void handleCheckSites()}
                className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--accent-soft)] px-3 py-1.5 text-xs font-medium text-[var(--accent)] transition-opacity hover:opacity-85 disabled:opacity-60"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${checkingSites ? "animate-spin" : ""}`} />
                <span>{checkingSites ? "检测中…" : "测一下"}</span>
              </button>
            </div>
          </div>

          {showAddSite && (
            <form
              onSubmit={(ev) => void handleAddSite(ev)}
              className="mb-3 grid grid-cols-1 gap-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-2.5 sm:grid-cols-12"
            >
              <input
                type="text"
                value={newSiteName}
                onChange={(e) => setNewSiteName(e.target.value)}
                placeholder="网站名称（如 Claude）"
                className="rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)] sm:col-span-4"
              />
              <input
                type="text"
                value={newSiteUrl}
                onChange={(e) => setNewSiteUrl(e.target.value)}
                placeholder="https://example.com"
                className="cc-mono rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)] sm:col-span-6"
              />
              <button
                type="submit"
                className="rounded-lg bg-[var(--accent)] px-3 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 sm:col-span-2"
              >
                添加
              </button>
            </form>
          )}

          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {sites.map((site) => {
              const isCustom = customSiteIds.includes(site.id);
              const color = getLatencyColor(site.latency_ms, site.ok);
              const displaySiteName = formatQuickSiteName(site.name);
              return (
                <div
                  key={site.id}
                  title={site.url}
                  className="group flex items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2.5 transition-colors hover:border-[var(--line-strong)]"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span
                        className="h-2 w-2 shrink-0 rounded-full"
                        style={{ backgroundColor: color }}
                      />
                      <span className="truncate text-xs font-medium text-[var(--text)]">
                        {displaySiteName}
                      </span>
                      {isCustom && (
                        <span className="shrink-0 rounded bg-[var(--card)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]">
                          自添加
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="flex shrink-0 items-center gap-2">
                    <span
                      className="cc-mono cc-tabular text-xs font-semibold"
                      style={{ color }}
                    >
                      {site.ok === false
                        ? "连不上"
                        : site.ok === null || site.latency_ms === null
                          ? "待检测"
                          : `${site.latency_ms} ms`}
                    </span>
                    <button
                      type="button"
                      onClick={() => void handleRemoveSite(site.id)}
                      className="rounded-md p-1 text-[var(--muted)] opacity-0 transition-opacity hover:bg-[var(--card)] hover:text-[var(--red)] group-hover:opacity-100"
                      title={`移除 ${displaySiteName}`}
                      aria-label={`移除 ${displaySiteName}`}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>
              );
            })}
            {sites.length === 0 && (
              <div className="col-span-full rounded-xl border border-dashed border-[var(--line)] py-6 text-center text-xs text-[var(--muted)]">
                暂无检测网站，点右上角「添加」即可放入常用网站
              </div>
            )}
          </div>
        </div>

        {/* Exit Info Card (Clean Chinese labels, probe on demand only) */}
        <div className="cc-card cc-glass flex flex-col justify-between rounded-2xl p-4 lg:col-span-5">
          <div>
            <div className="mb-3 flex items-center justify-between gap-2">
              <div className="flex items-start gap-2">
                <Globe className="mt-0.5 h-4 w-4 shrink-0 text-[var(--accent)]" />
                <div>
                  <h2 className="text-sm font-semibold text-[var(--text)]">出口信息</h2>
                  <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                    按需点击检测，默认不消耗流量
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-1.5">
                {hasExitIpData && (
                  <button
                    type="button"
                    onClick={() => setIpMasked((prev) => !prev)}
                    className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-1 text-[11px] text-[var(--muted)] transition-colors hover:border-[var(--line-strong)] hover:text-[var(--text)]"
                    title={ipMasked ? "点击查看完整地址" : "点击隐藏末尾数字"}
                  >
                    {ipMasked ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                    <span>{ipMasked ? "已遮掩" : "显示中"}</span>
                  </button>
                )}

                <button
                  type="button"
                  disabled={refreshingIp}
                  onClick={() => void handleRefreshExitIp()}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--accent-soft)] px-2.5 py-1.5 text-xs font-medium text-[var(--accent)] transition-opacity hover:opacity-85 disabled:opacity-60"
                >
                  <RefreshCw className={`h-3.5 w-3.5 ${refreshingIp ? "animate-spin" : ""}`} />
                  <span>{refreshingIp ? "检测中…" : "测一下"}</span>
                </button>
              </div>
            </div>

            <div className="mb-3 flex items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2.5">
              <div className="min-w-0">
                <div className="text-[11px] text-[var(--muted)]">出口地址</div>
                <div className="mt-0.5 truncate cc-mono cc-selectable text-base font-semibold tracking-tight text-[var(--text)]">
                  {displayedExitAddress}
                </div>
              </div>
              <span
                className={`inline-flex shrink-0 items-center gap-1 rounded-full px-2.5 py-1 text-[11px] font-medium ${googleStatusBadge.cls}`}
              >
                {googleStatusBadge.state === "clean" ? (
                  <CheckCircle2 className="h-3.5 w-3.5" />
                ) : googleStatusBadge.state === "risk" ? (
                  <ShieldAlert className="h-3.5 w-3.5" />
                ) : (
                  <Clock className="h-3.5 w-3.5" />
                )}
                <span>{googleStatusBadge.label}</span>
              </span>
            </div>

            <dl className="space-y-2 text-xs">
              <div className="flex items-center justify-between gap-3 border-b border-[var(--line)]/60 pb-1.5">
                <dt className="text-[var(--muted)]">归属地区</dt>
                <dd className="truncate font-medium text-[var(--text-secondary)]">
                  {displayedExitLocation}
                </dd>
              </div>
              <div className="flex items-center justify-between gap-3 border-b border-[var(--line)]/60 pb-1.5">
                <dt className="text-[var(--muted)]">线路状态</dt>
                <dd className="truncate font-medium text-[var(--text-secondary)]">
                  {displayedLineStatus}
                </dd>
              </div>
              <div className="flex items-center justify-between gap-3">
                <dt className="text-[var(--muted)]">谷歌地区状态</dt>
                <dd className="font-medium text-[var(--text-secondary)]">
                  {exitIp.google_clean === true
                    ? "正常（地区未偏移）"
                    : exitIp.google_clean === false
                      ? "地区异常（可能受限）"
                      : "待检测"}
                </dd>
              </div>
            </dl>
          </div>
        </div>
      </section>

      {/* Compact Elegant Bottom Status Bar */}
      <footer className="cc-card cc-glass mb-2 flex flex-wrap items-center justify-between gap-x-4 gap-y-2 rounded-2xl px-4 py-2.5 text-xs text-[var(--muted)]">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <span className="inline-flex items-center gap-1.5 font-medium text-[var(--text-secondary)]">
            <span
              className="h-2 w-2 rounded-full"
              style={{
                backgroundColor: runtime.running ? "var(--green)" : "var(--amber)",
              }}
            />
            {runtime.running ? `核心运行中 · ${formatUptime(runtime.uptime_sec)}` : "核心未启动"}
          </span>
          <span className="text-[var(--line-strong)]" aria-hidden="true">
            |
          </span>
          <span>
            本地端口 <span className="cc-mono text-[var(--text-secondary)]">{runtime.mixed_port}</span>
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <span>
            版本 <span className="cc-mono text-[var(--text-secondary)]">v{runtime.app_version}</span>
          </span>
          <span className="text-[var(--line-strong)]" aria-hidden="true">
            |
          </span>
          <span className="rounded-full border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-0.5 text-[11px] text-[var(--text-secondary)]">
            {runtime.portable_mode ? "便携版" : "安装版"}
          </span>
        </div>
      </footer>
    </div>
  );
}
