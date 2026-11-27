import {
  Activity,
  AlertTriangle,
  ArrowDown,
  ArrowLeftRight,
  ArrowRight,
  ArrowUp,
  Bot,
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
  Link2,
  Minimize2,
  PictureInPicture2,
  Plus,
  Power,
  QrCode,
  RefreshCw,
  RotateCcw,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
  Wifi,
  X,
  Zap,
} from "lucide-react";
import { type FormEvent, memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
  type ExitIpInfo,
  type MultiGroupMode,
  type NodeHealthHint,
  type ProbeSnapshot,
  type ProxyMode,
  type ProxyNode,
  type SiteCheckItem,
  catcloudApi,
  formatErrorMessage,
} from "../api/tauri";
import { type MascotState, MascotSprite } from "../components/MascotSprite";
import { ShareBundleModal } from "../components/ShareBundleModal";
import { TrafficSparkline, formatBytes, formatRate } from "../components/TrafficSparkline";
import { formatI18nTemplate, normalizeUiLanguage, useUiDict } from "../i18n";
import {
  appActions,
  selectHasBackgroundActivity,
  useAppSelector,
  useLatestTraffic,
} from "../store/appStore";
import {
  type ResolvedNodeLatency,
  getLatencyTooltipKey,
  hasValidDownMbps,
  hasValidUpMbps,
  resolveNodeDisplayLatency,
} from "../utils/latencyDisplay";
import { resolvePlatformOs } from "../utils/platform";
import { resolvePreAccelSummary } from "../utils/preaccelStatus";
import { getRegionLabel, resolveNodeRegionCode } from "../utils/regions";
import { isBoolPref, usePersistedState } from "../utils/uiPrefs";
import {
  TITLE_BAR_SAFE_TOP_PX,
  isAnchorVisibleInScrollHierarchy,
} from "../utils/viewportVisibility";

interface QuickNodeMenuPosition {
  left: number;
  width: number;
  maxHeight: number;
  placement: "bottom" | "top";
  top?: number;
  bottom?: number;
}

const MAX_VISIBLE_QUICK_NODES = 60;

const DEFAULT_QUICK_SITES: ReadonlyArray<SiteCheckItem> = [
  {
    id: "site-google",
    name: "Google 连通",
    url: "https://www.google.com/generate_204",
    latency_ms: null,
    ok: null,
  },
  {
    id: "site-github",
    name: "GitHub",
    url: "https://github.com",
    latency_ms: null,
    ok: null,
  },
  {
    id: "site-youtube",
    name: "YouTube",
    url: "https://www.youtube.com/generate_204",
    latency_ms: null,
    ok: null,
  },
  {
    id: "site-chatgpt",
    name: "OpenAI",
    url: "https://chatgpt.com/cdn-cgi/trace",
    latency_ms: null,
    ok: null,
  },
];

const GROUP_MODE_SHORT_LABELS: Record<MultiGroupMode, string> = {
  sticky_best: "自动优选",
  conditional_pool: "条件优选",
  load_balance_consistent_hash: "均衡分流",
  load_balance_round_robin: "轮询分流",
};

function formatQuickSiteName(name: string): string {
  const trimmed = name.trim();
  if (/^google\s*204$/i.test(trimmed)) return "Google 连通";
  return trimmed;
}

function formatQuickSiteShortName(name: string): string {
  const trimmed = name.trim();
  if (/^google(?:\s*204|\s*连通)?$/i.test(trimmed)) return "Google";
  return trimmed;
}

function formatUptime(sec: number): string {
  if (!Number.isFinite(sec) || sec <= 0) return "刚启动";
  const whole = Math.floor(sec);
  const d = Math.floor(whole / 86400);
  const h = Math.floor((whole % 86400) / 3600);
  const m = Math.floor((whole % 3600) / 60);
  const s = whole % 60;
  if (d > 0) return `${d} 天 ${h} 小时 ${m} 分`;
  if (h > 0) return `${h} 小时 ${m} 分 ${s} 秒`;
  if (m > 0) return `${m} 分 ${s} 秒`;
  return `${s} 秒`;
}

function getProbeGoogleState(snap: ProbeSnapshot | undefined): "clean" | "cn" | "unknown" {
  if (!snap) return "unknown";
  if (snap.google_clean === true) return "clean";
  if (snap.google_clean === false) return "cn";
  return "unknown";
}

function getProbeAiBadges(snap: ProbeSnapshot | undefined): {
  unlocked: Array<{ id: string; label: string; short: string }>;
  anyMeasured: boolean;
} {
  if (!snap) return { unlocked: [], anyMeasured: false };
  const sites = snap.unlocked_sites ?? {};
  const geminiVal = sites.gemini ?? sites.gemini_aistudio ?? sites.google_ai;
  const claudeVal = sites.claude;
  const chatgptVal = sites.chatgpt;
  const windsurfVal = sites.windsurf;
  const anyMeasured =
    geminiVal !== undefined ||
    claudeVal !== undefined ||
    chatgptVal !== undefined ||
    windsurfVal !== undefined;
  const unlocked: Array<{ id: string; label: string; short: string }> = [];
  if (claudeVal === true) unlocked.push({ id: "claude", label: "Claude", short: "Claude" });
  if (geminiVal === true) unlocked.push({ id: "gemini", label: "Gemini", short: "Gemini" });
  if (chatgptVal === true) unlocked.push({ id: "chatgpt", label: "ChatGPT", short: "ChatGPT" });
  if (windsurfVal === true) {
    unlocked.push({ id: "windsurf", label: "Windsurf", short: "Windsurf" });
  }
  return { unlocked, anyMeasured };
}

function formatHomeLatencyTooltip(
  resolved: ResolvedNodeLatency,
  dict: ReturnType<typeof useUiDict>,
  hint?: NodeHealthHint | null
): string {
  const key = getLatencyTooltipKey(resolved);
  const base =
    key === "probeHot"
      ? dict.latency.probeHotTooltip
      : key === "healthCold"
        ? dict.latency.healthColdTooltip
        : key === "failed"
          ? dict.latency.failedTooltip
          : dict.latency.untestedTooltip;
  const tags: string[] = [];
  if (resolved.isProbation) tags.push(dict.latency.probationBadge);
  if (resolved.isDegraded) tags.push(dict.latency.degradedBadge);
  if (hint?.status === "cooldown" && hint.cooldown_remaining_sec > 0) {
    tags.push(
      formatI18nTemplate(dict.latency.cooldownSec, {
        sec: Math.ceil(hint.cooldown_remaining_sec),
      })
    );
  }
  return tags.length > 0 ? `${base} · ${tags.join(" · ")}` : base;
}

function hasRealExitIp(info: ExitIpInfo): boolean {
  return (
    Boolean(info.ip_raw?.trim()) ||
    (info.ip_masked.trim().length > 0 && !info.ip_masked.includes("--"))
  );
}

function getLatencyColor(latencyMs: number | null, ok: boolean | null): string {
  if (ok === false) return "var(--red)";
  if (latencyMs === null) return "var(--muted)";
  if (latencyMs <= 140) return "var(--green)";
  if (latencyMs <= 300) return "var(--amber)";
  return "var(--red)";
}

const HomeLiveKpiGrid = memo(function HomeLiveKpiGrid({
  connectionSubLabel,
  kernelMemoryTitle,
  kernelMemorySub,
  kernelMemoryTooltip,
  gomemlimitMb,
}: {
  connectionSubLabel: string;
  kernelMemoryTitle: string;
  kernelMemorySub: string;
  kernelMemoryTooltip: string;
  gomemlimitMb: number;
}) {
  const traffic = useLatestTraffic();
  const tunnelCount = traffic.tunnel_connections ?? 0;
  const compactConnBase = connectionSubLabel.replace("已接管", "");
  const connSub =
    tunnelCount > 0 ? `${compactConnBase} · 含 ${tunnelCount} 隧道` : connectionSubLabel;
  const memoryTooltip =
    gomemlimitMb > 0
      ? `${kernelMemoryTooltip}（核心内存上限 ${gomemlimitMb} MB）`
      : kernelMemoryTooltip;

  const kpiCards = [
    {
      label: "上传速度",
      value: formatRate(traffic.up_bps),
      sub: "实时上传",
      title: undefined as string | undefined,
      accent: "var(--coral)",
      icon: ArrowUp,
    },
    {
      label: "下载速度",
      value: formatRate(traffic.down_bps),
      sub: "实时下载",
      title: undefined as string | undefined,
      accent: "var(--sky)",
      icon: ArrowDown,
    },
    {
      label: "当前连接",
      value: `${traffic.connections}`,
      sub: connSub,
      title:
        tunnelCount > 0
          ? `真实应用连接 ${traffic.connections} 条（另含 ${tunnelCount} 条国内提速隧道，未重复计入）`
          : `真实应用连接 ${traffic.connections} 条`,
      accent: "var(--text)",
      icon: Activity,
    },
    {
      label: "累计上传",
      value: formatBytes(traffic.up_total_bytes),
      sub: "本次启动",
      title: undefined as string | undefined,
      accent: "var(--accent)",
      icon: HardDriveUpload,
    },
    {
      label: "累计下载",
      value: formatBytes(traffic.down_total_bytes),
      sub: "本次启动",
      title: undefined as string | undefined,
      accent: "var(--accent)",
      icon: HardDriveDownload,
    },
    {
      label: kernelMemoryTitle,
      value: `${traffic.memory_mb.toFixed(1)} MB`,
      sub: kernelMemorySub,
      title: memoryTooltip,
      accent: "var(--green)",
      icon: Cpu,
    },
  ];

  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
      {kpiCards.map((card) => {
        const Icon = card.icon;
        return (
          <div
            key={card.label}
            title={card.title}
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
            <div className="mt-0.5 truncate text-[10px] text-[var(--muted)]">{card.sub}</div>
          </div>
        );
      })}
    </div>
  );
});

/**
 * Lightweight 1Hz leaf component for the compact inline status bar so live traffic
 * ticks never re-render HomePage itself.
 */
const HomeCompactTrafficRates = memo(function HomeCompactTrafficRates() {
  const traffic = useLatestTraffic();
  return (
    <div className="flex shrink-0 items-center gap-2.5 cc-mono cc-tabular text-xs font-semibold">
      <span className="inline-flex items-center gap-1 whitespace-nowrap text-[var(--coral)]">
        <ArrowUp className="h-3.5 w-3.5 shrink-0" />
        <span>{formatRate(traffic.up_bps)}</span>
      </span>
      <span className="inline-flex items-center gap-1 whitespace-nowrap text-[var(--sky)]">
        <ArrowDown className="h-3.5 w-3.5 shrink-0" />
        <span>{formatRate(traffic.down_bps)}</span>
      </span>
    </div>
  );
});

const HIGH_TRAFFIC_THRESHOLD_BPS = 512 * 1024;
const MASCOT_PAT_DURATION_MS = 2500;

interface MascotLabelSet {
  idle: string;
  ok: string;
  preaccel: string;
  searching: string;
  thinking: string;
  typing: string;
  approval: string;
  complete: string;
  pat: string;
}

/**
 * Isolated real-time mascot panel subscribing to 1Hz traffic telemetry independently
 * so the rest of HomePage never re-renders on traffic ticks.
 * Clicking triggers a local 2.5s head-pat Easter egg and restores real live state automatically.
 */
const HomeMascotPanel = memo(function HomeMascotPanel({
  needsApproval,
  isSearching,
  isThinking,
  storeMascotState,
  coreRunning,
  proxyActive,
  preaccelActive,
  directMode,
  labels,
  patTooltip,
}: {
  needsApproval: boolean;
  isSearching: boolean;
  isThinking: boolean;
  storeMascotState: MascotState;
  coreRunning: boolean;
  proxyActive: boolean;
  preaccelActive: boolean;
  directMode: boolean;
  labels: MascotLabelSet;
  patTooltip: string;
}) {
  const traffic = useLatestTraffic();
  const [patting, setPatting] = useState(false);
  const patTimerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (patTimerRef.current !== null) {
        window.clearTimeout(patTimerRef.current);
        patTimerRef.current = null;
      }
    };
  }, []);

  const handlePatMascot = () => {
    setPatting(true);
    if (patTimerRef.current !== null) {
      window.clearTimeout(patTimerRef.current);
    }
    patTimerRef.current = window.setTimeout(() => {
      patTimerRef.current = null;
      setPatting(false);
    }, MASCOT_PAT_DURATION_MS);
  };

  const isHighTraffic =
    coreRunning && traffic.up_bps + traffic.down_bps > HIGH_TRAFFIC_THRESHOLD_BPS;

  let effectiveMascotState: MascotState;
  let effectiveLabel: string;

  if (needsApproval || storeMascotState === "approval") {
    effectiveMascotState = "approval";
    effectiveLabel = labels.approval;
  } else if (isSearching || storeMascotState === "searching") {
    effectiveMascotState = "searching";
    effectiveLabel = labels.searching;
  } else if (isThinking || storeMascotState === "thinking") {
    effectiveMascotState = "thinking";
    effectiveLabel = labels.thinking;
  } else if (storeMascotState === "typing") {
    effectiveMascotState = "typing";
    effectiveLabel = labels.typing;
  } else if (storeMascotState === "complete") {
    effectiveMascotState = "complete";
    effectiveLabel = labels.complete;
  } else if (isHighTraffic) {
    effectiveMascotState = "typing";
    effectiveLabel =
      preaccelActive && !directMode
        ? labels.preaccel
        : proxyActive && !directMode
          ? labels.ok
          : labels.typing;
  } else {
    effectiveMascotState = "idle";
    effectiveLabel =
      preaccelActive && !directMode
        ? labels.preaccel
        : proxyActive && !directMode
          ? labels.ok
          : labels.idle;
  }

  const displayedState: MascotState = patting ? "complete" : effectiveMascotState;
  const displayedLabel = patting ? labels.pat : effectiveLabel;

  return (
    <button
      type="button"
      onClick={handlePatMascot}
      className={`relative hidden min-w-[92px] shrink-0 flex-col items-center justify-center rounded-2xl border px-2.5 py-2 text-center transition-colors sm:flex ${
        patting
          ? "border-[var(--accent)]/70 bg-[var(--accent-soft)]/55"
          : displayedState === "approval"
            ? "border-[var(--amber)]/65 bg-[var(--amber-soft)]/35 hover:border-[var(--amber)]"
            : "border-[var(--line)] bg-[var(--bg-elevated)] hover:border-[var(--line-strong)]"
      }`}
      title={`${displayedLabel} · ${patTooltip}`}
      aria-label={`${displayedLabel} · ${patTooltip}`}
    >
      {patting && (
        <span
          aria-live="polite"
          className="pointer-events-none absolute -top-2.5 left-1/2 -translate-x-1/2 whitespace-nowrap rounded-full border border-[var(--accent)]/55 bg-[var(--surface)] px-2 py-0.5 text-[10px] font-semibold text-[var(--accent)] shadow-xs"
        >
          {labels.pat}
        </span>
      )}
      <div className="flex h-[68px] w-[68px] items-end justify-center pb-0.5">
        <MascotSprite state={displayedState} scale={2} title={displayedLabel} />
      </div>
      <div
        className={`mt-1.5 max-w-[104px] truncate whitespace-nowrap leading-none text-[10px] ${
          patting
            ? "font-semibold text-[var(--accent)]"
            : displayedState === "approval"
              ? "font-medium text-[var(--amber)]"
              : "text-[var(--muted)]"
        }`}
      >
        {displayedLabel}
      </div>
    </button>
  );
});

const HomeLiveUptime = memo(function HomeLiveUptime({
  running,
  uptimeSec,
}: {
  running: boolean;
  uptimeSec: number;
}) {
  const anchorRef = useRef<{ anchorSeconds: number; anchorNowMs: number }>({
    anchorSeconds: running ? Math.max(0, Math.floor(uptimeSec)) : 0,
    anchorNowMs: Date.now(),
  });
  const [liveUptimeSec, setLiveUptimeSec] = useState<number>(() =>
    running ? Math.max(0, Math.floor(uptimeSec)) : 0
  );

  useEffect(() => {
    const baseSeconds = running ? Math.max(0, Math.floor(uptimeSec)) : 0;
    anchorRef.current = {
      anchorSeconds: baseSeconds,
      anchorNowMs: Date.now(),
    };
    setLiveUptimeSec(baseSeconds);
    if (!running) return;

    const syncFromAnchor = () => {
      const { anchorSeconds, anchorNowMs } = anchorRef.current;
      setLiveUptimeSec(
        anchorSeconds + Math.max(0, Math.floor((Date.now() - anchorNowMs) / 1000))
      );
    };

    let tickId: number | null = null;
    const stopTick = () => {
      if (tickId !== null) {
        window.clearInterval(tickId);
        tickId = null;
      }
    };
    const startTick = () => {
      if (tickId !== null) return;
      tickId = window.setInterval(syncFromAnchor, 1000);
    };

    if (typeof document === "undefined" || document.visibilityState === "visible") {
      startTick();
    }

    const handleVisibilityChange = () => {
      if (document.visibilityState === "visible") {
        syncFromAnchor();
        startTick();
      } else {
        stopTick();
      }
    };
    document.addEventListener("visibilitychange", handleVisibilityChange);

    return () => {
      stopTick();
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, [running, uptimeSec]);

  return <>{running ? `核心运行中 · ${formatUptime(liveUptimeSec)}` : "核心未启动"}</>;
});

export function HomePage() {
  const runtime = useAppSelector((s) => s.runtime);
  const config = useAppSelector((s) => s.config);
  const uiLang = useAppSelector((s) =>
    normalizeUiLanguage(s.config.personalization.ui_language)
  );
  const dict = useUiDict(uiLang);
  const globalPreAccel = useAppSelector((s) => s.globalPreAccel);
  const hasEnabledRelay = useAppSelector((s) => s.preAccelRelays.some((r) => r.enabled));
  const groups = useAppSelector((s) => s.groups);
  const nodes = useAppSelector((s) => s.nodes);
  const probes = useAppSelector((s) => s.probes);
  const probeProgress = useAppSelector((s) => s.probeProgress);
  const bgActivity = useAppSelector(selectHasBackgroundActivity);
  const tunAdminPromptOpen = useAppSelector((s) => s.tunAdminPromptOpen);
  const subscriptions = useAppSelector((s) => s.subscriptions);
  const exitIp = useAppSelector((s) => s.exitIp);
  const sites = useAppSelector((s) => s.quickSites);
  const checkingSites = useAppSelector((s) => s.bgTasks.home.checkingQuickSites);
  const refreshingIp = useAppSelector((s) => s.bgTasks.home.refreshingExitIp);
  const ipMasked = useAppSelector((s) => s.sessionDrafts.home.ipMasked);
  const mascotState = useAppSelector((s) => s.mascotState);
  const initialized = useAppSelector((s) => s.initialized);

  const [togglingProxy, setTogglingProxy] = useState(false);
  const [togglingPreAccel, setTogglingPreAccel] = useState(false);
  const [elevatingPreAccel, setElevatingPreAccel] = useState(false);
  const [detailsOpen, setDetailsOpen] = usePersistedState<boolean>(
    "home.detailsOpen",
    false,
    isBoolPref
  );
  const [nodeMenuOpen, setNodeMenuOpen] = useState(false);
  const [nodeMenuPos, setNodeMenuPos] = useState<QuickNodeMenuPosition | null>(null);
  const [nodeSearch, setNodeSearch] = useState("");
  const [switchingNode, setSwitchingNode] = useState(false);

  const [showAddSite, setShowAddSite] = useState(false);
  const [newSiteName, setNewSiteName] = useState("");
  const [newSiteUrl, setNewSiteUrl] = useState("");
  const [pendingRemoveSite, setPendingRemoveSite] = useState<SiteCheckItem | null>(null);
  const [removingSite, setRemovingSite] = useState(false);
  const [syncModalOpen, setSyncModalOpen] = useState(false);

  const nodeDropdownRef = useRef<HTMLDivElement | null>(null);
  const nodeMenuTriggerRef = useRef<HTMLButtonElement | null>(null);
  const nodeMenuPopoverRef = useRef<HTMLDivElement | null>(null);
  const nodeSearchInputRef = useRef<HTMLInputElement | null>(null);

  const isSingleMode = runtime.route_mode === "single";

  const proxyModeOptions = useMemo<
    ReadonlyArray<{ id: ProxyMode; label: string; hint: string }>
  >(
    () => [
      { id: "rule", label: dict.home.ruleMode, hint: "国内直连、海外自动走代理" },
      { id: "global", label: dict.home.globalMode, hint: "所有网站全部走当前代理" },
      { id: "direct", label: dict.home.directMode, hint: "暂时绕过代理直接联网" },
    ],
    [dict.home.directMode, dict.home.globalMode, dict.home.ruleMode]
  );

  useEffect(() => {
    if (!pendingRemoveSite) return;
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape" && !removingSite) {
        setPendingRemoveSite(null);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [pendingRemoveSite, removingSite]);

  useEffect(() => {
    if (isSingleMode) {
      setNodeMenuOpen(false);
    }
  }, [isSingleMode]);

  const computeNodeMenuPosition = useCallback((): QuickNodeMenuPosition | null => {
    const cardEl = nodeDropdownRef.current;
    const triggerEl = nodeMenuTriggerRef.current;
    if (
      !cardEl ||
      !triggerEl ||
      !cardEl.isConnected ||
      !triggerEl.isConnected ||
      typeof window === "undefined"
    ) {
      return null;
    }
    if (!isAnchorVisibleInScrollHierarchy(triggerEl, TITLE_BAR_SAFE_TOP_PX)) {
      return null;
    }

    const cardRect = cardEl.getBoundingClientRect();
    const triggerRect = triggerEl.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const viewportPad = 12;
    const topSafe = TITLE_BAR_SAFE_TOP_PX + 8;
    const gap = 8;
    const maxMenuH = 380;

    const maxAllowedW = Math.max(260, vw - viewportPad * 2);
    const width = Math.min(Math.max(cardRect.width, 420), Math.min(540, maxAllowedW));
    const left = Math.max(
      viewportPad,
      Math.min(cardRect.left, vw - viewportPad - width)
    );

    const anchorBottom = Math.max(cardRect.bottom, triggerRect.bottom);
    const anchorTop = Math.min(cardRect.top, triggerRect.top);
    const spaceBelow = Math.max(0, vh - anchorBottom - gap - viewportPad);
    const spaceAbove = Math.max(0, anchorTop - gap - topSafe);
    const openUpward = spaceBelow < 220 && spaceAbove > spaceBelow;
    const maxViewportSpan = Math.max(120, vh - topSafe - viewportPad);

    if (openUpward) {
      const maxHeight = Math.min(
        maxViewportSpan,
        Math.min(maxMenuH, Math.max(140, spaceAbove))
      );
      const bottom = Math.max(
        viewportPad,
        Math.min(vh - anchorTop + gap, vh - topSafe - maxHeight)
      );
      return { left, width, maxHeight, placement: "top", bottom };
    }

    const maxHeight = Math.min(
      maxViewportSpan,
      Math.min(maxMenuH, Math.max(140, spaceBelow))
    );
    const top = Math.max(
      topSafe,
      Math.min(anchorBottom + gap, vh - viewportPad - maxHeight)
    );
    return { left, width, maxHeight, placement: "bottom", top };
  }, []);

  // Close group node quick picker popover on outside click, Escape, scroll out of view, or resize
  useEffect(() => {
    if (!nodeMenuOpen) return;

    const initialPos = computeNodeMenuPosition();
    if (!initialPos) {
      setNodeMenuOpen(false);
      return;
    }
    setNodeMenuPos(initialPos);

    const handlePointerDown = (ev: MouseEvent) => {
      const target = ev.target as Node | null;
      if (!target) return;
      if (nodeDropdownRef.current?.contains(target)) return;
      if (nodeMenuPopoverRef.current?.contains(target)) return;
      setNodeMenuOpen(false);
    };
    const handleKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") {
        ev.preventDefault();
        setNodeMenuOpen(false);
        nodeMenuTriggerRef.current?.focus();
      }
    };
    const handleScrollOrResize = (ev: Event) => {
      if (ev.type === "scroll") {
        const target = ev.target as Node | null;
        if (target && nodeMenuPopoverRef.current?.contains(target)) {
          return;
        }
      }
      const nextPos = computeNodeMenuPosition();
      if (!nextPos) {
        setNodeMenuOpen(false);
      } else {
        setNodeMenuPos(nextPos);
      }
    };
    const handleWindowBlur = () => {
      setNodeMenuOpen(false);
    };
    const handleVisibilityChange = () => {
      if (document.visibilityState !== "visible") {
        setNodeMenuOpen(false);
      }
    };

    document.addEventListener("mousedown", handlePointerDown, true);
    document.addEventListener("keydown", handleKeyDown, true);
    document.addEventListener("visibilitychange", handleVisibilityChange);
    window.addEventListener("resize", handleScrollOrResize);
    window.addEventListener("scroll", handleScrollOrResize, true);
    window.addEventListener("blur", handleWindowBlur);
    return () => {
      document.removeEventListener("mousedown", handlePointerDown, true);
      document.removeEventListener("keydown", handleKeyDown, true);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
      window.removeEventListener("resize", handleScrollOrResize);
      window.removeEventListener("scroll", handleScrollOrResize, true);
      window.removeEventListener("blur", handleWindowBlur);
    };
  }, [computeNodeMenuPosition, nodeMenuOpen]);

  useEffect(() => {
    if (!nodeMenuOpen) {
      setNodeSearch("");
      return;
    }
    const tid = window.setTimeout(() => nodeSearchInputRef.current?.focus(), 20);
    return () => window.clearTimeout(tid);
  }, [nodeMenuOpen]);

  // Active group & candidate nodes for the interactive route selector
  const activeGroup = useMemo(() => {
    if (groups.length === 0) return null;
    return groups.find((g) => g.id === runtime.active_group_id) ?? groups[0];
  }, [groups, runtime.active_group_id]);

  const activeGroupId = activeGroup?.id ?? runtime.active_group_id ?? "";

  const otherIndependentGroups = useMemo(
    () =>
      groups.filter(
        (g) =>
          g.id !== activeGroupId &&
          Boolean(g.independent_routing) &&
          g.match_rules.length > 0
      ),
    [groups, activeGroupId]
  );

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

  const activeGroupCount = activeGroup
    ? activeGroup.member_node_ids.length > 0
      ? activeGroup.member_node_ids.length
      : groupCandidateNodes.length
    : groupCandidateNodes.length;

  const groupModeShortLabel = activeGroup
    ? GROUP_MODE_SHORT_LABELS[activeGroup.mode]
    : "自动优选";

  const currentNodeId = isSingleMode
    ? runtime.active_node_id || ""
    : runtime.active_node_id || activeGroup?.active_node_id || "";

  const sortedFilteredNodes = useMemo<ProxyNode[]>(() => {
    if (!nodeMenuOpen) return [];
    const q = nodeSearch.trim().toLowerCase();
    const filtered = q
      ? groupCandidateNodes.filter((n) => {
          const code = resolveNodeRegionCode(n);
          const label = getRegionLabel(code);
          return (
            n.name.toLowerCase().includes(q) ||
            code.toLowerCase().includes(q) ||
            label.toLowerCase().includes(q)
          );
        })
      : groupCandidateNodes;

    const healthHints = runtime.node_health_hints;
    const resolveSortMetric = (id: string) => {
      const resolved = resolveNodeDisplayLatency(probes[id], healthHints?.[id]);
      return {
        ok: resolved.ok && resolved.latencyMs !== null,
        latency: resolved.latencyMs,
        failed: resolved.state === "failed",
      };
    };

    return [...filtered].sort((a, b) => {
      if (a.id === currentNodeId) return -1;
      if (b.id === currentNodeId) return 1;
      const ma = resolveSortMetric(a.id);
      const mb = resolveSortMetric(b.id);
      if (ma.ok !== mb.ok) return ma.ok ? -1 : 1;
      if (ma.ok && mb.ok && ma.latency !== null && mb.latency !== null) {
        return ma.latency - mb.latency;
      }
      if (ma.failed !== mb.failed) return ma.failed ? 1 : -1;
      return a.name.localeCompare(b.name);
    });
  }, [
    currentNodeId,
    groupCandidateNodes,
    nodeMenuOpen,
    nodeSearch,
    probes,
    runtime.node_health_hints,
  ]);

  const visibleDropdownNodes = useMemo(
    () => sortedFilteredNodes.slice(0, MAX_VISIBLE_QUICK_NODES),
    [sortedFilteredNodes]
  );

  const activeNodeRecord = useMemo(
    () => nodes.find((n) => n.id === currentNodeId) ?? null,
    [nodes, currentNodeId]
  );
  const activeNodeProbe = currentNodeId ? probes[currentNodeId] : undefined;

  const activeNodeSourceName = useMemo(() => {
    if (!activeNodeRecord) return "";
    const sub = subscriptions.find((s) => s.id === activeNodeRecord.sub_id);
    return sub?.name ?? "";
  }, [activeNodeRecord, subscriptions]);

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

  const displayRegionCode = activeNodeRecord
    ? resolveNodeRegionCode(activeNodeRecord)
    : runtime.active_node_region && runtime.active_node_region !== "--"
      ? resolveNodeRegionCode({
          region_code: runtime.active_node_region,
          name: displayNodeName,
        })
      : "";

  const displayRegionLabel =
    displayRegionCode && displayRegionCode !== "UNK"
      ? getRegionLabel(displayRegionCode)
      : "";

  const liveActiveLatencyMs =
    typeof runtime.active_node_latency_ms === "number" &&
    Number.isFinite(runtime.active_node_latency_ms) &&
    runtime.active_node_latency_ms > 0
      ? runtime.active_node_latency_ms
      : null;
  const activeNodeHealthHint = currentNodeId
    ? runtime.node_health_hints?.[currentNodeId]
    : undefined;
  const rawActiveResolvedLatency = resolveNodeDisplayLatency(
    activeNodeProbe,
    activeNodeHealthHint
  );
  const activeResolvedLatency: ResolvedNodeLatency =
    rawActiveResolvedLatency.state === "untested" &&
    rawActiveResolvedLatency.source === "none" &&
    liveActiveLatencyMs !== null
      ? {
          latencyMs: liveActiveLatencyMs,
          ok: true,
          source: "probe",
          state: "healthy",
          isProbation: false,
          isDegraded: false,
        }
      : rawActiveResolvedLatency;
  const displayLatencyMs = activeResolvedLatency.latencyMs;
  const displayLatencyOk =
    activeResolvedLatency.state === "failed"
      ? false
      : activeResolvedLatency.ok
        ? true
        : null;
  const activeLatencyTooltip = formatHomeLatencyTooltip(
    activeResolvedLatency,
    dict,
    activeNodeHealthHint
  );
  const activeLatencyColor =
    activeNodeHealthHint?.status === "cooldown" && activeResolvedLatency.state === "failed"
      ? "var(--amber)"
      : getLatencyColor(displayLatencyMs, displayLatencyOk);
  const activeLatencyText =
    activeResolvedLatency.latencyMs !== null
      ? `${Math.round(activeResolvedLatency.latencyMs)} ms`
      : activeNodeHealthHint?.status === "cooldown" &&
          activeResolvedLatency.state === "failed"
        ? activeNodeHealthHint.cooldown_remaining_sec > 0
          ? formatI18nTemplate(dict.latency.cooldownSec, {
              sec: Math.ceil(activeNodeHealthHint.cooldown_remaining_sec),
            })
          : dict.latency.cooldownActive
        : activeResolvedLatency.state === "failed"
          ? dict.latency.timeoutShort
          : dict.latency.untestedShort;
  const displayUpMbps =
    hasValidUpMbps(activeNodeProbe)
      ? activeNodeProbe!.up_mbps!
      : typeof runtime.active_node_up_mbps === "number" &&
          Number.isFinite(runtime.active_node_up_mbps) &&
          runtime.active_node_up_mbps > 0 &&
          activeNodeProbe?.per_probe_ok?.builtin_upload !== false
        ? runtime.active_node_up_mbps
        : null;
  const displayDownMbps = hasValidDownMbps(activeNodeProbe)
    ? activeNodeProbe!.down_mbps!
    : null;
  const activeGoogleState = getProbeGoogleState(activeNodeProbe);
  const activeAiBadges = getProbeAiBadges(activeNodeProbe);

  // Main power switch state & human-friendly traffic status
  const platformOs = resolvePlatformOs(runtime.os_label);
  const preaccelSummary = resolvePreAccelSummary(
    runtime,
    globalPreAccel,
    config.preaccel.enabled,
    hasEnabledRelay,
    uiLang
  );
  const isProxyEnabled = preaccelSummary.proxyActive;
  const preaccelNeedsElevation =
    preaccelSummary.enabled &&
    hasEnabledRelay &&
    !preaccelSummary.suspendedForTun &&
    !preaccelSummary.realWinDivertActive &&
    (preaccelSummary.installState === "need_elevation" ||
      (platformOs === "windows" &&
        globalPreAccel.windivert_available &&
        !globalPreAccel.is_elevated));
  const preaccelQuickSubText = !preaccelSummary.enabled
    ? dict.home.preaccelQuickDescOff
    : preaccelSummary.subBadgeText
      ? `${preaccelSummary.badgeText} · ${preaccelSummary.subBadgeText}`
      : preaccelSummary.badgeText;

  const trafficStatusSentence = (() => {
    if (!isProxyEnabled) {
      if (runtime.tun_needs_elevation) {
        return "核心未运行 · 虚拟网卡需管理员";
      }
      if (preaccelSummary.realWinDivertActive) {
        if (preaccelSummary.verifyState === "probing") {
          return "未开启猫猫代理 · 正在自动探测国内提速链路…";
        }
        if (preaccelSummary.verifyState === "verified") {
          return preaccelSummary.verifyLatencyMs
            ? `未开启猫猫代理 · 正为原梯子提速（${preaccelSummary.verifyLatencyMs} ms）`
            : "未开启猫猫代理 · 正为原梯子提速";
        }
        return "未开启猫猫代理 · 正自动为你的原梯子提速";
      }
      if (preaccelSummary.enabled) {
        if (!hasEnabledRelay) {
          return `${dict.home.proxyOffPrefix} · ${preaccelSummary.badgeText}`;
        }
        if (
          preaccelSummary.installState === "downloading" ||
          preaccelSummary.installState === "verifying"
        ) {
          return "未开启代理 · 正在后台准备提速组件…";
        }
        if (preaccelSummary.installState === "need_elevation") {
          return "未开启代理 · 提速组件已就绪（点下方以管理员开启）";
        }
        if (preaccelSummary.verifyState === "probing") {
          return "未开启猫猫代理 · 正在自动探测国内提速链路…";
        }
        if (preaccelSummary.verifyState === "degraded") {
          return "未开启代理 · 底层拦截已自动保护回退";
        }
        return `${dict.home.proxyOffPrefix} · ${preaccelSummary.badgeText}`;
      }
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
    if (runtime.tun_needs_elevation && runtime.system_proxy_enabled) {
      return "仅系统代理生效 · 虚拟网卡需管理员";
    }
    if (runtime.tun_needs_elevation) {
      return "虚拟网卡需管理员 · 点下方一键提权";
    }
    return "已接管电脑网络流量";
  })();

  const tunPillTitle = runtime.tun_needs_elevation
    ? platformOs === "linux"
      ? "配置已开启虚拟网卡但当前核心权限不足，点击一键授予核心网络权限"
      : platformOs === "macos"
        ? "配置已开启虚拟网卡但尚未授权，点击查看并一键授权"
        : "配置已开启虚拟网卡但当前缺少管理员权限，点击一键以管理员身份重启生效"
    : runtime.tun_admin_ready
      ? "接管电脑全部软件和命令行流量"
      : platformOs === "linux"
        ? "开启虚拟网卡需要给代理核心授予网络权限，点击可一键授权"
        : platformOs === "macos"
          ? "开启虚拟网卡需要系统安全授权，点击查看并一键授权"
          : "开启虚拟网卡需要管理员权限，点击可一键以管理员身份重启并开启";

  const handleTogglePreAccelQuick = async () => {
    if (togglingPreAccel) return;
    if (!hasEnabledRelay && !preaccelSummary.enabled) {
      appActions.showToast(dict.home.needAddRelayToast, "info", 3800);
      appActions.setNav("preaccel");
      return;
    }
    setTogglingPreAccel(true);
    try {
      await appActions.togglePreAccel();
    } finally {
      setTogglingPreAccel(false);
    }
  };

  const handleRelaunchAdminPreAccel = async () => {
    if (elevatingPreAccel) return;
    setElevatingPreAccel(true);
    try {
      await appActions.relaunchAsAdminForGlobalPreAccel();
    } finally {
      setElevatingPreAccel(false);
    }
  };

  // Real-time live state signals driving HomeMascotPanel (zero fake binary toggle)
  const needsMascotApproval = Boolean(
    tunAdminPromptOpen ||
      runtime.tun_needs_elevation ||
      runtime.captive_portal_required ||
      runtime.status === "error" ||
      runtime.status === "warn" ||
      runtime.active_group_circuit_open ||
      globalPreAccel.verify_state === "degraded" ||
      globalPreAccel.verify_state === "failed" ||
      preaccelSummary.verifyState === "degraded" ||
      preaccelSummary.verifyState === "failed"
  );
  const isMascotSearching = Boolean(
    checkingSites ||
      refreshingIp ||
      probeProgress.running ||
      bgActivity.nodes ||
      bgActivity.preaccel ||
      bgActivity.home ||
      runtime.probing_active ||
      preaccelSummary.verifyState === "probing"
  );
  const isMascotThinking = Boolean(
    switchingNode ||
      togglingProxy ||
      togglingPreAccel ||
      elevatingPreAccel ||
      bgActivity.groups ||
      bgActivity.settings ||
      runtime.switching_active
  );
  const isPreAccelGuarding = Boolean(
    preaccelSummary.enabled &&
      (runtime.preaccel_active || preaccelSummary.realWinDivertActive)
  );

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
        const started = await appActions.enableProxyPower();
        if (
          started.power_on_tun_degraded ||
          (started.system_proxy_enabled && started.tun_needs_elevation)
        ) {
          appActions.showToast(
            started.tun_needs_elevation
              ? "已启用系统代理；如需接管全部桌面软件请点击『虚拟网卡 · 需管理员』一键提权"
              : "原虚拟网卡因缺少管理员权限已改用系统代理；如需接管全部桌面软件请点击『虚拟网卡』一键提权",
            "info",
            5200
          );
        }
      } else {
        await appActions.disableAllProxyAndStopCore();
      }
    } catch {
      /* appActions.enableProxyPower already surfaces user-facing toast on error */
    } finally {
      setTogglingProxy(false);
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
    const payload = nextSites.map((s) => {
      const lowerUrl = s.url.trim().toLowerCase();
      const expectedStatus = lowerUrl.includes("generate_204") ? 204 : 200;
      return {
        id: s.id,
        name: s.name,
        url: s.url,
        expected_status: expectedStatus,
      };
    });
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
    await appActions.runQuickSitesCheck();
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

    setNewSiteName("");
    setNewSiteUrl("");
    setShowAddSite(false);
    appActions.showToast(`已添加站点：${trimmedName}`, "ok");
  };

  const handleRequestRemoveSite = (site: SiteCheckItem) => {
    setPendingRemoveSite(site);
  };

  const handleConfirmRemoveSite = async () => {
    if (!pendingRemoveSite || removingSite) return;
    const target = pendingRemoveSite;
    const label = formatQuickSiteName(target.name);
    setRemovingSite(true);
    try {
      const nextSites = sites.filter((item) => item.id !== target.id);
      const saved = await persistQuickSites(nextSites);
      if (!saved) return;
      setPendingRemoveSite(null);
      appActions.showToast(`已移除站点：${label}`, "info");
    } finally {
      setRemovingSite(false);
    }
  };

  const handleResetDefaultSites = async () => {
    const nextSites = DEFAULT_QUICK_SITES.map((s) => ({ ...s }));
    const saved = await persistQuickSites(nextSites);
    if (!saved) return;
    setShowAddSite(false);
    appActions.showToast("已恢复默认的 4 个常用检测网站", "ok");
  };

  const handleRefreshExitIp = async () => {
    if (refreshingIp) return;
    await appActions.runRefreshExitIp();
  };

  const connectionSubLabel = runtime.tun_enabled
    ? "虚拟网卡已接管"
    : runtime.system_proxy_enabled
      ? "系统代理已接管"
      : preaccelSummary.realWinDivertActive
        ? preaccelSummary.verifyState === "probing"
          ? "探测链路中"
          : "正为原梯子提速"
        : preaccelSummary.enabled
          ? !hasEnabledRelay
            ? "待添加提速线路"
            : preaccelSummary.verifyState === "degraded"
              ? "已保护回退"
              : "本地提速待命"
          : "本地待命";

  // Determine whether exit IP has actually been probed
  const hasExitIpData = hasRealExitIp(exitIp);

  const displayedExitAddress = !hasExitIpData
    ? "待检测"
    : ipMasked
      ? exitIp.ip_masked
      : exitIp.ip_raw?.trim() || exitIp.ip_masked;

  const rawIsp = exitIp.isp?.trim() ?? "";
  const rawLocation = exitIp.location?.trim() ?? "";
  const rawTimezone = exitIp.timezone?.trim() ?? "";

  const displayedExitLocation = hasExitIpData
    ? rawLocation && rawLocation !== "未连接"
      ? rawLocation
      : "未知地区"
    : rawLocation && rawLocation !== "未连接" && rawLocation !== "待检测"
      ? rawLocation
      : "待检测";

  const displayedExitIsp = hasExitIpData
    ? rawIsp || "未知运营商"
    : rawIsp || "待检测";

  const displayedExitTimezone =
    hasExitIpData && rawTimezone && rawTimezone !== "--" ? rawTimezone : "待检测";

  const googleStatusBadge =
    exitIp.google_clean === true
      ? {
          cls: "bg-[var(--green-soft)] text-[var(--green)]",
          label: "谷歌正常",
          state: "clean" as const,
        }
      : exitIp.google_clean === false
        ? {
            cls: "bg-[var(--red-soft)] text-[var(--red)]",
            label: "谷歌送中",
            state: "risk" as const,
          }
        : {
            cls: "border border-[var(--line)] bg-[var(--card)] text-[var(--muted)]",
            label: "待检测",
            state: "unknown" as const,
          };

  const isZh = uiLang === "zh-CN";
  const dnsTlsDiag = runtime.dns_tls_diagnostics;
  const showDnsTlsBanner = Boolean(
    dnsTlsDiag && dnsTlsDiag.status && dnsTlsDiag.status !== "healthy"
  );
  const dnsLabelSep = isZh || uiLang === "ja" ? "：" : ": ";
  const dnsListSep = isZh ? "、" : uiLang === "ja" ? "・" : ", ";
  const hasCjkText = (value: string) => /[\u3400-\u9fff]/.test(value);
  const formatDnsPathLabel = (rawPath: string): string => {
    switch (rawPath.trim().toLowerCase()) {
      case "direct":
        return dict.home.dnsDiagPathDirect;
      case "proxy":
        return dict.home.dnsDiagPathProxy;
      case "proxy_server":
        return dict.home.dnsDiagPathProxyServer;
      case "default":
        return dict.home.dnsDiagPathDefault;
      default:
        return rawPath;
    }
  };
  const dnsDiagHeading = dnsTlsDiag
    ? dnsTlsDiag.status === "degraded_recovered"
      ? dict.home.dnsDiagRecoveredTitle
      : isZh
        ? dnsTlsDiag.category || dict.home.dnsDiagTitle
        : dnsTlsDiag.category && !hasCjkText(dnsTlsDiag.category)
          ? dnsTlsDiag.category
          : dict.home.dnsDiagTitle
    : "";
  const dnsDiagNextHint = dnsTlsDiag
    ? isZh
      ? dnsTlsDiag.next_retry_hint ||
        (dnsTlsDiag.status === "degraded_recovered" || dnsTlsDiag.recovered
          ? dict.home.dnsDiagRecoveredHint
          : dnsTlsDiag.next_retry_at
            ? formatI18nTemplate(dict.home.dnsDiagRetryWithTimeHint, {
                time: dnsTlsDiag.next_retry_at,
              })
            : dict.home.dnsDiagRetrySoonHint)
      : dnsTlsDiag.status === "degraded_recovered" || dnsTlsDiag.recovered
        ? dict.home.dnsDiagRecoveredHint
        : dnsTlsDiag.next_retry_at
          ? formatI18nTemplate(dict.home.dnsDiagRetryWithTimeHint, {
              time: dnsTlsDiag.next_retry_at,
            })
          : dnsTlsDiag.next_retry_hint && !hasCjkText(dnsTlsDiag.next_retry_hint)
            ? dnsTlsDiag.next_retry_hint
            : dict.home.dnsDiagRetrySoonHint
    : "";

  return (
    <div className="space-y-3 pb-3">
      {/* DNS TLS Diagnostics Banner: zero vertical space when healthy; explicit warning/recovery banner otherwise */}
      {showDnsTlsBanner && dnsTlsDiag && (
        <section
          className={`cc-card cc-glass rounded-2xl border px-4 py-3 text-xs ${
            dnsTlsDiag.status === "degraded_recovered"
              ? "border-[var(--amber)]/55 bg-[var(--amber-soft)]/50"
              : "border-[var(--red)]/55 bg-[var(--red-soft)]/45"
          }`}
        >
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="flex min-w-0 flex-1 items-start gap-2.5">
              <ShieldAlert
                className={`mt-0.5 h-4 w-4 shrink-0 ${
                  dnsTlsDiag.status === "degraded_recovered"
                    ? "text-[var(--amber)]"
                    : "text-[var(--red)]"
                }`}
              />
              <div className="min-w-0 flex-1 space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-semibold text-[var(--text)]">
                    {dnsDiagHeading}
                  </span>
                  {dnsTlsDiag.tls_verification_preserved !== false && (
                    <span className="inline-flex items-center gap-1 rounded-full border border-[var(--green)]/40 bg-[var(--green-soft)] px-2 py-0.5 text-[10px] font-medium text-[var(--green)]">
                      <ShieldCheck className="h-3 w-3" />
                      <span>{dict.home.dnsDiagTlsPreserved}</span>
                    </span>
                  )}
                  {dnsTlsDiag.failure_count > 0 && (
                    <span className="cc-mono rounded-full bg-[var(--surface)]/85 px-2 py-0.5 text-[10px] text-[var(--text-secondary)]">
                      {dnsTlsDiag.failure_count}x
                    </span>
                  )}
                </div>

                <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-[var(--text-secondary)]">
                  {dnsTlsDiag.first_seen_at && (
                    <span>
                      {dict.home.dnsDiagStartedLabel}
                      {dnsLabelSep}
                      <span className="cc-mono text-[var(--text)]">{dnsTlsDiag.first_seen_at}</span>
                    </span>
                  )}
                  {dnsTlsDiag.affected_paths.length > 0 && (
                    <span>
                      {dict.home.dnsDiagPathsLabel}
                      {dnsLabelSep}
                      <span className="cc-mono text-[var(--text)]">
                        {dnsTlsDiag.affected_paths.map(formatDnsPathLabel).join(" / ")}
                      </span>
                    </span>
                  )}
                  {dnsTlsDiag.affected_upstreams.length > 0 && (
                    <span>
                      {dict.home.dnsDiagUpstreamsLabel}
                      {dnsLabelSep}
                      <span className="cc-mono text-[var(--text)]">
                        {dnsTlsDiag.affected_upstreams.join(dnsListSep)}
                      </span>
                    </span>
                  )}
                </div>

                {dnsDiagNextHint && (
                  <div className="text-[11px] leading-relaxed text-[var(--text-secondary)]">
                    <span className="font-medium text-[var(--text)]">
                      {dict.home.dnsDiagNextLabel}
                      {dnsLabelSep}
                    </span>
                    <span>{dnsDiagNextHint}</span>
                    {dnsTlsDiag.next_retry_at && !dnsDiagNextHint.includes(dnsTlsDiag.next_retry_at) && (
                      <span className="ml-1.5 cc-mono text-[var(--muted)]">
                        ({dnsTlsDiag.next_retry_at})
                      </span>
                    )}
                  </div>
                )}
              </div>
            </div>

            <div className="flex shrink-0 flex-wrap items-center gap-1.5">
              <button
                type="button"
                onClick={() => appActions.setNav("logs")}
                className="rounded-lg border border-[var(--line)] bg-[var(--surface)] px-2.5 py-1 text-[11px] font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)]"
              >
                {dict.home.dnsDiagOpenLogs}
              </button>
              <button
                type="button"
                onClick={() => appActions.openAiAssistant("troubleshooting", "agent")}
                className="inline-flex items-center gap-1 rounded-lg bg-[var(--accent)] px-2.5 py-1 text-[11px] font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90"
              >
                <Bot className="h-3 w-3" />
                <span>{dict.home.dnsDiagAskAi}</span>
              </button>
            </div>
          </div>
        </section>
      )}

      {/* 0-Node Onboarding Guide Card: direct boost-only or import-as-main entry actions */}
      {initialized && nodes.length === 0 && (
        <section className="cc-card cc-glass rounded-2xl border-[var(--accent)]/45 bg-[var(--accent-soft)]/50 p-4">
          <div className="space-y-3">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <Sparkles className="h-4 w-4 shrink-0 text-[var(--accent)]" />
                <h2 className="text-sm font-semibold text-[var(--text)]">
                  {dict.home.emptyCardTitle}
                </h2>
              </div>
              <p className="text-xs leading-relaxed text-[var(--text-secondary)]">
                {dict.home.emptyCardMetaphor}
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => appActions.setNav("preaccel")}
                className="inline-flex shrink-0 items-center justify-center gap-1.5 rounded-xl border border-[var(--green)]/55 bg-[var(--green-soft)] px-3.5 py-2 text-xs font-semibold transition-colors hover:border-[var(--green)]"
                style={{ color: "color-mix(in srgb, var(--green) 80%, var(--text))" }}
              >
                <Zap className="h-3.5 w-3.5 shrink-0" />
                <span>{dict.home.emptyStepBoostOnly}</span>
              </button>

              <button
                type="button"
                onClick={() => appActions.openNodesWorkspace("subs", null, "migration")}
                className="inline-flex shrink-0 items-center justify-center gap-1.5 rounded-xl bg-[var(--accent)] px-3.5 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90"
              >
                <ArrowLeftRight className="h-3.5 w-3.5 shrink-0" />
                <span>{dict.home.emptyStepMigrate}</span>
              </button>

              <button
                type="button"
                onClick={() => appActions.openNodesWorkspace("subs")}
                className="inline-flex shrink-0 items-center justify-center gap-1.5 rounded-xl border border-[var(--accent)]/55 bg-[var(--card)] px-3.5 py-2 text-xs font-semibold text-[var(--accent)] transition-colors hover:border-[var(--accent)] hover:bg-[var(--accent-soft)]"
              >
                <Link2 className="h-3.5 w-3.5 shrink-0" />
                <span>{dict.home.emptyStepImport}</span>
              </button>

              <button
                type="button"
                onClick={() => setSyncModalOpen(true)}
                className="inline-flex shrink-0 items-center justify-center gap-1.5 rounded-xl border border-[var(--line-strong)] bg-[var(--card)] px-3.5 py-2 text-xs font-semibold text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
              >
                <QrCode className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
                <span>{dict.sync.emptyCardStep}</span>
              </button>

              <button
                type="button"
                onClick={() => appActions.openAiAssistant("onboarding", "web")}
                className="inline-flex shrink-0 items-center justify-center gap-1 rounded-xl px-2 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:text-[var(--accent)] hover:underline"
              >
                <span>{dict.home.emptyStepAi}</span>
              </button>
            </div>
          </div>
        </section>
      )}

      {/* Top Hero Dual-Zone Card: Main Proxy Power Switch + Interactive Current Route Selector */}
      <section className="cc-card cc-glass relative z-20 rounded-2xl p-5">
        <div className="grid grid-cols-1 gap-5 min-[1160px]:grid-cols-12 min-[1160px]:gap-5">
          {/* Left Zone: Prominent Power Switch + Standalone Domestic Boost Strip + Mode & Takeover Controls */}
          <div className="flex min-w-0 flex-col justify-between gap-3.5 min-[1160px]:col-span-5 min-[1160px]:border-r min-[1160px]:border-[var(--line)]/70 min-[1160px]:pr-5">
            <div className="space-y-2.5">
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
                    <span className="truncate whitespace-nowrap text-base font-bold tracking-tight text-[var(--text)]">
                      {togglingProxy
                        ? isProxyEnabled
                          ? "正在关闭代理…"
                          : "正在开启代理…"
                        : isProxyEnabled
                          ? dict.home.powerOnTitle
                          : preaccelSummary.realWinDivertActive
                            ? dict.home.powerPreaccelOnlyTitle
                            : dict.home.powerOffTitle}
                    </span>
                  </div>
                  <p
                    title={trafficStatusSentence}
                    className={`mt-0.5 truncate text-xs ${
                      runtime.tun_needs_elevation && runtime.proxy_mode !== "direct"
                        ? "font-medium text-[var(--amber)]"
                        : !isProxyEnabled && preaccelSummary.realWinDivertActive
                          ? "font-medium text-[var(--accent)]"
                          : !isProxyEnabled && preaccelSummary.enabled
                            ? "font-medium text-[var(--amber)]"
                            : "text-[var(--text-secondary)]"
                    }`}
                  >
                    {trafficStatusSentence}
                  </p>
                </div>
              </button>

              {/* Standalone Domestic Boost Quick Control Strip (Bug 4 & Bug 5 safe) */}
              <div
                title={preaccelSummary.detailText}
                className={`flex flex-wrap items-center justify-between gap-2 rounded-xl border px-3 py-2.5 transition-colors ${
                  !preaccelSummary.enabled
                    ? "border-[var(--line)] bg-[var(--bg-elevated)]"
                    : preaccelSummary.tone === "green"
                      ? "border-[var(--green)]/45 bg-[var(--green-soft)]/50"
                      : preaccelSummary.tone === "accent"
                        ? "border-[var(--accent)]/50 bg-[var(--accent-soft)]/45"
                        : "border-[var(--amber)]/55 bg-[var(--amber-soft)]/45"
                }`}
              >
                <button
                  type="button"
                  onClick={() => appActions.setNav("preaccel")}
                  className="group flex min-w-0 flex-1 items-center gap-2.5 text-left"
                  title={preaccelSummary.detailText}
                >
                  <span
                    className={`inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-lg transition-colors ${
                      !preaccelSummary.enabled
                        ? "border border-[var(--line)] bg-[var(--card)] text-[var(--muted)] group-hover:border-[var(--accent)] group-hover:text-[var(--accent)]"
                        : preaccelSummary.tone === "green"
                          ? "bg-[var(--green)] text-[var(--accent-ink)]"
                          : preaccelSummary.tone === "accent"
                            ? "bg-[var(--accent)] text-[var(--accent-ink)]"
                            : "bg-[var(--amber)] text-[var(--accent-ink)]"
                    }`}
                  >
                    {preaccelSummary.verifyState === "probing" ? (
                      <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                    ) : (
                      <Zap
                        className={`h-3.5 w-3.5 ${togglingPreAccel ? "animate-pulse" : ""}`}
                      />
                    )}
                  </span>

                  <div className="min-w-0 flex-1">
                    <div className="truncate text-xs font-semibold text-[var(--text)] group-hover:text-[var(--accent)]">
                      {dict.home.preaccelQuickTitle}
                    </div>
                    <div
                      className={`mt-0.5 truncate text-[11px] ${
                        !preaccelSummary.enabled
                          ? "text-[var(--muted)]"
                          : preaccelSummary.tone === "green"
                            ? "font-medium text-[var(--green)]"
                            : preaccelSummary.tone === "accent"
                              ? "font-medium text-[var(--accent)]"
                              : "font-medium text-[var(--amber)]"
                      }`}
                    >
                      {preaccelQuickSubText}
                    </div>
                  </div>
                </button>

                <div className="flex shrink-0 items-center gap-1.5">
                  {preaccelNeedsElevation && (
                    <button
                      type="button"
                      disabled={elevatingPreAccel}
                      onClick={() => void handleRelaunchAdminPreAccel()}
                      title={preaccelSummary.detailText}
                      className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-lg border border-[var(--amber)]/65 bg-[var(--amber-soft)] px-2.5 py-1 text-[11px] font-semibold text-[var(--amber)] transition-colors hover:border-[var(--amber)] disabled:opacity-65"
                    >
                      {elevatingPreAccel ? (
                        <RefreshCw className="h-3 w-3 shrink-0 animate-spin" />
                      ) : (
                        <ShieldCheck className="h-3 w-3 shrink-0" />
                      )}
                      <span>{dict.home.preaccelQuickNeedAdminBtn}</span>
                    </button>
                  )}

                  <button
                    type="button"
                    role="switch"
                    aria-checked={preaccelSummary.enabled}
                    aria-label={dict.home.preaccelQuickTitle}
                    disabled={togglingPreAccel}
                    onClick={() => void handleTogglePreAccelQuick()}
                    title={preaccelSummary.detailText}
                    className={`inline-flex h-5 w-9 shrink-0 items-center rounded-full p-0.5 transition-colors disabled:opacity-65 ${
                      preaccelSummary.enabled
                        ? preaccelSummary.tone === "amber"
                          ? "bg-[var(--amber)]"
                          : preaccelSummary.tone === "green"
                            ? "bg-[var(--green)]"
                            : "bg-[var(--accent)]"
                        : "bg-[var(--line-strong)]"
                    }`}
                  >
                    <span
                      className={`h-4 w-4 rounded-full bg-[var(--card)] transition-transform ${
                        preaccelSummary.enabled ? "translate-x-4" : "translate-x-0"
                      }`}
                    />
                  </button>
                </div>
              </div>
            </div>

            {/* Mode + Takeover Method Controls */}
            <div className="flex flex-wrap items-center justify-between gap-2.5">
              {/* Proxy Mode Segmented Control */}
              <div
                className="inline-flex shrink-0 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-0.5 text-xs"
                role="group"
                aria-label="代理模式"
              >
                {proxyModeOptions.map((mode) => {
                  const selected = runtime.proxy_mode === mode.id;
                  return (
                    <button
                      key={mode.id}
                      type="button"
                      onClick={() => void appActions.setProxyMode(mode.id)}
                      title={mode.hint}
                      className={`shrink-0 whitespace-nowrap rounded-lg px-3 py-1.5 font-medium transition-colors ${
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
              <div className="flex flex-wrap items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => void appActions.toggleSystemProxy()}
                  className={`inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border px-2.5 py-1.5 text-xs font-medium transition-colors ${
                    runtime.system_proxy_enabled
                      ? "border-[var(--green)]/45 bg-[var(--green-soft)] text-[var(--green)]"
                      : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:text-[var(--text)]"
                  }`}
                  title="接管浏览器和大多数常用软件"
                >
                  <Wifi className="h-3.5 w-3.5 shrink-0" />
                  <span>{dict.home.systemProxy}</span>
                </button>

                <button
                  type="button"
                  onClick={() =>
                    runtime.tun_needs_elevation
                      ? appActions.openTunAdminPrompt(null)
                      : void appActions.toggleTun()
                  }
                  className={`inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border px-2.5 py-1.5 text-xs font-medium transition-colors ${
                    runtime.tun_enabled
                      ? "border-[var(--accent)]/55 bg-[var(--accent-soft)] text-[var(--accent)]"
                      : runtime.tun_needs_elevation
                        ? "border-[var(--amber)]/65 bg-[var(--amber-soft)] text-[var(--amber)] hover:border-[var(--amber)]"
                        : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:text-[var(--text)]"
                  }`}
                  title={tunPillTitle}
                >
                  {runtime.tun_needs_elevation ? (
                    <ShieldAlert className="h-3.5 w-3.5 shrink-0" />
                  ) : (
                    <ShieldCheck className="h-3.5 w-3.5 shrink-0" />
                  )}
                  <span>
                    {runtime.tun_needs_elevation ? dict.home.tunNeedsAdmin : dict.home.tunMode}
                  </span>
                  {runtime.tun_needs_elevation && (
                    <span
                      className="h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--amber)]"
                      aria-hidden="true"
                    />
                  )}
                </button>
              </div>
            </div>
          </div>

          {/* Right Zone: Dual-Mode Current Route (Single Node vs Smart Multi-Group) + Quick Actions + Dual-Form Mascot */}
          <div className="flex min-w-0 flex-col justify-between gap-3.5 min-[1160px]:col-span-7">
            <div className="flex items-start justify-between gap-2.5">
              <div className="min-w-0 flex-1 space-y-2.5">
                {/* Row 1: Clear Dual-Mode Badge + Status Pills + Mode Switch Link */}
                <div className="flex flex-wrap items-center justify-between gap-x-1.5 gap-y-1">
                  <div className="flex flex-wrap items-center gap-1.5">
                    {isSingleMode ? (
                      <span
                        className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-full border border-[var(--green)]/45 bg-[var(--green-soft)] px-2 py-0.5 text-[11px] font-semibold"
                        style={{ color: "color-mix(in srgb, var(--green) 82%, var(--text))" }}
                      >
                        <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--green)]" />
                        <span>单节点模式</span>
                      </span>
                    ) : (
                      <span className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-full border border-[var(--accent)]/45 bg-[var(--accent-soft)] px-2 py-0.5 text-[11px] font-semibold text-[var(--accent)]">
                        <Layers className="h-3 w-3 shrink-0" />
                        <span>智能多选组</span>
                      </span>
                    )}

                    <span className="whitespace-nowrap text-[11px] text-[var(--muted)]">
                      {isSingleMode
                        ? "固定只走这 1 个节点"
                        : activeGroupCount > 0
                          ? `${activeGroupCount} 个节点 · ${groupModeShortLabel}`
                          : "自动优选"}
                    </span>

                    {/* Domestic Pre-Acceleration Status Tag */}
                    {(preaccelSummary.enabled || preaccelSummary.realWinDivertActive) && (
                      <button
                        type="button"
                        onClick={() => appActions.setNav("preaccel")}
                        className={`inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-full border px-1.5 py-0.5 text-[11px] font-semibold transition-opacity hover:opacity-90 ${
                          preaccelSummary.tone === "green"
                            ? "border-[var(--green)]/50 bg-[var(--green-soft)]"
                            : preaccelSummary.tone === "accent"
                              ? "border-[var(--accent)]/55 bg-[var(--accent-soft)] text-[var(--accent)]"
                              : "border-[var(--amber)]/55 bg-[var(--amber-soft)] text-[var(--amber)]"
                        }`}
                        style={
                          preaccelSummary.tone === "green"
                            ? { color: "color-mix(in srgb, var(--green) 78%, var(--text))" }
                            : undefined
                        }
                        title={`${preaccelSummary.detailText} · 点击前往国内提速页查看`}
                      >
                        {preaccelSummary.verifyState === "probing" ? (
                          <RefreshCw className="h-3 w-3 shrink-0 animate-spin" />
                        ) : (
                          <Zap className="h-3 w-3 shrink-0" />
                        )}
                        <span>
                          {preaccelSummary.badgeText}
                          {preaccelSummary.subBadgeText && preaccelSummary.proxyActive
                            ? ` · ${preaccelSummary.subBadgeText}`
                            : ""}
                        </span>
                      </button>
                    )}

                    {runtime.captive_portal_required && (
                      <button
                        type="button"
                        onClick={() => appActions.setNav("preaccel")}
                        className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-full bg-[var(--amber-soft)] px-1.5 py-0.5 text-[11px] font-medium text-[var(--amber)]"
                      >
                        <ShieldAlert className="h-3 w-3 shrink-0" />
                        <span>校园网需认证</span>
                      </button>
                    )}
                  </div>

                  <button
                    type="button"
                    onClick={() => appActions.setNav(isSingleMode ? "groups" : "nodes")}
                    className="inline-flex shrink-0 items-center gap-0.5 whitespace-nowrap rounded-lg px-1 py-0.5 text-[11px] font-medium text-[var(--accent)] transition-colors hover:bg-[var(--accent-soft)]/60"
                  >
                    <span>{isSingleMode ? "切到多选组" : "改用单节点"}</span>
                    <ArrowRight className="h-3 w-3 shrink-0" />
                  </button>
                </div>

                {/* Row 2: Direct-Jump Route Card (Single Node Card vs Two-Layer Smart Group Card) */}
                {isSingleMode ? (
                  <button
                    type="button"
                    onClick={() => appActions.setNav("nodes")}
                    className="group flex w-full items-center justify-between gap-3 rounded-2xl border border-[var(--green)]/45 bg-[var(--bg-elevated)] px-3.5 py-3 text-left transition-all hover:border-[var(--green)] hover:bg-[var(--green-soft)]/30"
                    title="点击前往「节点与测速」挑选单个节点"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="truncate text-base font-semibold tracking-tight text-[var(--text)]">
                          {displayNodeName}
                        </span>
                        {displayRegionLabel && (
                          <span
                            className="shrink-0 rounded-md border border-[var(--green)]/35 bg-[var(--green-soft)] px-1.5 py-0.5 text-[10px] font-medium"
                            style={{ color: "color-mix(in srgb, var(--green) 82%, var(--text))" }}
                            title={displayRegionCode}
                          >
                            {displayRegionLabel}
                            {displayRegionCode &&
                            displayRegionCode !== "UNK" &&
                            displayRegionLabel !== displayRegionCode
                              ? ` · ${displayRegionCode}`
                              : ""}
                          </span>
                        )}
                      </div>

                      <div className="mt-1.5 flex flex-wrap items-center gap-x-2.5 gap-y-1 text-xs text-[var(--muted)]">
                        {activeNodeSourceName && (
                          <span className="max-w-[140px] truncate text-[var(--text-secondary)]">
                            {activeNodeSourceName}
                          </span>
                        )}
                        <span
                          className="inline-flex items-center gap-1.5"
                          title={activeLatencyTooltip}
                        >
                          <span
                            className="h-2 w-2 shrink-0 rounded-full"
                            style={{ backgroundColor: activeLatencyColor }}
                          />
                          <strong
                            className="cc-mono font-semibold"
                            style={{
                              color: activeLatencyColor,
                            }}
                          >
                            {activeLatencyText}
                          </strong>
                        </span>
                        <span title="单位 Mbps（8 Mbps ≈ 1 MB/s）">
                          ↑{" "}
                          <strong className="cc-mono font-semibold text-[var(--coral)]">
                            {displayUpMbps !== null ? `${displayUpMbps.toFixed(1)} Mbps` : "未测"}
                          </strong>
                        </span>
                        <span title="单位 Mbps（8 Mbps ≈ 1 MB/s）">
                          ↓{" "}
                          <strong className="cc-mono font-semibold text-[var(--sky)]">
                            {displayDownMbps !== null ? `${displayDownMbps.toFixed(1)} Mbps` : "未测"}
                          </strong>
                        </span>
                        {activeGoogleState === "clean" && (
                          <span className="rounded-full bg-[var(--green-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--green)]">
                            谷歌正常
                          </span>
                        )}
                        {activeGoogleState === "cn" && (
                          <span className="rounded-full bg-[var(--red-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--red)]">
                            谷歌送中
                          </span>
                        )}
                        {activeNodeProbe?.google_risk_mismatch && (
                          <span
                            className="rounded-full bg-[var(--amber-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--amber)]"
                            title="不同网站识别出的地区存在差异，仅供参考"
                          >
                            地区有偏差
                          </span>
                        )}
                        {activeAiBadges.unlocked.map((ai) => (
                          <span
                            key={ai.id}
                            className="rounded-md bg-[var(--accent-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--accent)]"
                          >
                            {ai.label}
                          </span>
                        ))}
                        {activeAiBadges.anyMeasured && activeAiBadges.unlocked.length === 0 && (
                          <span className="rounded-md bg-[var(--card)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]">
                            AI 受限
                          </span>
                        )}
                      </div>
                    </div>

                    <span className="inline-flex shrink-0 items-center gap-1 rounded-xl border border-[var(--green)]/45 bg-[var(--card)] px-2.5 py-1.5 text-xs font-semibold text-[var(--green)] transition-colors group-hover:border-[var(--green)] group-hover:bg-[var(--green)] group-hover:text-[var(--accent-ink)]">
                      <span>更换节点</span>
                      <ArrowRight className="h-3.5 w-3.5" />
                    </span>
                  </button>
                ) : (
                  <div ref={nodeDropdownRef} className="relative">
                    <div className="rounded-2xl border border-[var(--accent)]/40 bg-[var(--bg-elevated)] transition-colors">
                      {/* Top Half: Clickable Group Header -> Jumps straight to Smart Multi-Groups page */}
                      <button
                        type="button"
                        onClick={() => {
                          setNodeMenuOpen(false);
                          appActions.setNav("groups");
                        }}
                        className="group flex w-full items-center justify-between gap-3 rounded-t-2xl px-3.5 py-2.5 text-left transition-colors hover:bg-[var(--accent-soft)]/35"
                        title="点击前往「智能多选组」切换或管理分组"
                      >
                        <div className="min-w-0 flex-1">
                          <div className="truncate text-base font-semibold tracking-tight text-[var(--text)]">
                            {displayGroupName}
                          </div>
                        </div>

                        <span className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-lg bg-[var(--accent-soft)] px-2.5 py-1 text-[11px] font-semibold text-[var(--accent)] transition-opacity group-hover:opacity-90">
                          <span>切换 / 管理多选组</span>
                          <ArrowRight className="h-3 w-3 shrink-0" />
                        </span>
                      </button>

                      {/* Bottom Half: Current Active Exit Node inside Group + Quick Switch Popover */}
                      <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[var(--line)]/70 px-3.5 py-2 text-xs">
                        <div className="flex min-w-0 flex-1 flex-wrap items-center gap-x-2 gap-y-1 text-[var(--muted)]">
                          <span className="inline-flex min-w-0 max-w-full items-center gap-1.5 text-[var(--text-secondary)]">
                            <span className="shrink-0 whitespace-nowrap text-[var(--muted)]">
                              当前出口：
                            </span>
                            <span
                              className="min-w-0 max-w-[200px] truncate font-medium text-[var(--text)]"
                              title={displayNodeName}
                            >
                              {displayNodeName}
                            </span>
                            {displayRegionCode && displayRegionCode !== "UNK" && (
                              <span
                                className="shrink-0 whitespace-nowrap rounded bg-[var(--card)] px-1 py-0.5 text-[10px] font-medium text-[var(--text-secondary)]"
                                title={displayRegionLabel}
                              >
                                {displayRegionCode}
                              </span>
                            )}
                          </span>
                          <span
                            className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap"
                            title={activeLatencyTooltip}
                          >
                            <span
                              className="h-2 w-2 shrink-0 rounded-full"
                              style={{ backgroundColor: activeLatencyColor }}
                            />
                            <strong
                              className="cc-mono font-semibold"
                              style={{
                                color: activeLatencyColor,
                              }}
                            >
                              {activeLatencyText}
                            </strong>
                          </span>
                          <span
                            className="inline-flex shrink-0 items-center gap-2 whitespace-nowrap cc-mono"
                            title="单位 Mbps（8 Mbps ≈ 1 MB/s）"
                          >
                            <strong className="font-semibold text-[var(--coral)]">
                              ↑{displayUpMbps !== null ? `${displayUpMbps.toFixed(1)} Mbps` : "--"}
                            </strong>
                            <strong className="font-semibold text-[var(--sky)]">
                              ↓{displayDownMbps !== null ? `${displayDownMbps.toFixed(1)} Mbps` : "--"}
                            </strong>
                          </span>
                          {activeGoogleState === "clean" && (
                            <span className="shrink-0 whitespace-nowrap rounded-full bg-[var(--green-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--green)]">
                              谷歌正常
                            </span>
                          )}
                          {activeGoogleState === "cn" && (
                            <span className="shrink-0 whitespace-nowrap rounded-full bg-[var(--red-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--red)]">
                              谷歌送中
                            </span>
                          )}
                          {activeNodeProbe?.google_risk_mismatch && (
                            <span
                              className="shrink-0 whitespace-nowrap rounded-full bg-[var(--amber-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--amber)]"
                              title="不同网站识别出的地区存在差异，仅供参考"
                            >
                              地区有偏差
                            </span>
                          )}
                          {activeAiBadges.unlocked.map((ai) => (
                            <span
                              key={ai.id}
                              className="shrink-0 whitespace-nowrap rounded-md bg-[var(--accent-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--accent)]"
                            >
                              {ai.label}
                            </span>
                          ))}
                        </div>

                        <button
                          ref={nodeMenuTriggerRef}
                          type="button"
                          onClick={() => {
                            if (nodes.length === 0) {
                              appActions.setNav("nodes");
                              return;
                            }
                            if (nodeMenuOpen) {
                              setNodeMenuOpen(false);
                              return;
                            }
                            const pos = computeNodeMenuPosition();
                            if (pos) {
                              setNodeMenuPos(pos);
                              setNodeMenuOpen(true);
                            }
                          }}
                          aria-expanded={nodeMenuOpen}
                          className={`inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-lg border px-2 py-1 text-[11px] font-medium transition-colors ${
                            nodeMenuOpen
                              ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                              : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--text)]"
                          }`}
                          title="快速切换本组内的其他出口节点"
                        >
                          <span>组内快选</span>
                          <ChevronDown
                            className={`h-3 w-3 shrink-0 transition-transform ${
                              nodeMenuOpen ? "rotate-180" : ""
                            }`}
                          />
                        </button>
                      </div>

                      {/* Transparent notice when other groups have independent site routing enabled */}
                      {otherIndependentGroups.length > 0 && (
                        <button
                          type="button"
                          onClick={() => {
                            setNodeMenuOpen(false);
                            appActions.setNav("groups");
                          }}
                          className="flex w-full items-center justify-between gap-2 rounded-b-2xl border-t border-[var(--amber)]/25 bg-[var(--amber-soft)]/45 px-3.5 py-1.5 text-left text-[11px] transition-colors hover:bg-[var(--amber-soft)]/70"
                          title="点击前往「智能多选组」查看或管理独立分流组"
                        >
                          <span className="flex min-w-0 items-center gap-1.5 text-[var(--text-secondary)]">
                            <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--amber)]" />
                            <span className="truncate">
                              另有{" "}
                              <strong className="cc-mono font-semibold text-[var(--amber)]">
                                {otherIndependentGroups.length}
                              </strong>{" "}
                              个独立分流组生效：
                              <span className="font-medium text-[var(--text)]">
                                {otherIndependentGroups.map((g) => g.name).join("、")}
                              </span>
                            </span>
                          </span>
                          <span className="inline-flex shrink-0 items-center gap-0.5 whitespace-nowrap font-medium text-[var(--amber)]">
                            <span>查看</span>
                            <ArrowRight className="h-3 w-3 shrink-0" />
                          </span>
                        </button>
                      )}
                    </div>

                    {/* In-Group Node Quick Picker Popover (Viewport-Clamped Portal + Anti-Squish 2-Row Items) */}
                    {nodeMenuOpen &&
                      nodeMenuPos &&
                      typeof document !== "undefined" &&
                      createPortal(
                        <div
                          ref={nodeMenuPopoverRef}
                          className="fixed z-[60] flex flex-col overflow-hidden rounded-2xl border border-[var(--line-strong)] bg-[var(--surface)] p-2.5 text-xs"
                          style={{
                            left: `${nodeMenuPos.left}px`,
                            top:
                              nodeMenuPos.placement === "bottom"
                                ? `${nodeMenuPos.top}px`
                                : undefined,
                            bottom:
                              nodeMenuPos.placement === "top"
                                ? `${nodeMenuPos.bottom}px`
                                : undefined,
                            width: `${nodeMenuPos.width}px`,
                            maxHeight: `${nodeMenuPos.maxHeight}px`,
                            boxShadow: "var(--shadow-popover)",
                          }}
                        >
                          <div className="relative mb-2 shrink-0">
                            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--muted)]" />
                            <input
                              ref={nodeSearchInputRef}
                              type="text"
                              value={nodeSearch}
                              onChange={(e) => setNodeSearch(e.target.value)}
                              placeholder="搜索本组节点名称或地区…"
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

                          <div className="min-h-0 flex-1 space-y-1 overflow-y-auto overscroll-contain pr-0.5">
                            {visibleDropdownNodes.map((node) => {
                              const isCurrent = node.id === currentNodeId;
                              const snap = probes[node.id];
                              const hint = runtime.node_health_hints?.[node.id];
                              const rawResolvedLat = resolveNodeDisplayLatency(snap, hint);
                              const resolvedLat: ResolvedNodeLatency =
                                rawResolvedLat.state === "untested" &&
                                rawResolvedLat.source === "none" &&
                                isCurrent &&
                                liveActiveLatencyMs !== null
                                  ? {
                                      latencyMs: liveActiveLatencyMs,
                                      ok: true,
                                      source: "probe",
                                      state: "healthy",
                                      isProbation: false,
                                      isDegraded: false,
                                    }
                                  : rawResolvedLat;
                              const isHintCooldown =
                                hint?.status === "cooldown" && resolvedLat.state === "failed";
                              const lat = resolvedLat.latencyMs;
                              const latOk =
                                resolvedLat.state === "failed"
                                  ? false
                                  : resolvedLat.ok
                                    ? true
                                    : null;
                              const up = hasValidUpMbps(snap) ? snap!.up_mbps! : null;
                              const down = hasValidDownMbps(snap) ? snap!.down_mbps! : null;
                              const googleState = getProbeGoogleState(snap);
                              const aiInfo = getProbeAiBadges(snap);
                              const latColor = isHintCooldown
                                ? "var(--amber)"
                                : getLatencyColor(lat, latOk);
                              const latTooltip = formatHomeLatencyTooltip(resolvedLat, dict, hint);
                              const nodeRegionCode = resolveNodeRegionCode(node);
                              const hasRegionTag = Boolean(
                                nodeRegionCode && nodeRegionCode !== "UNK"
                              );
                              const hasSecondRow =
                                hasRegionTag ||
                                googleState === "clean" ||
                                googleState === "cn" ||
                                Boolean(snap?.google_risk_mismatch) ||
                                aiInfo.unlocked.length > 0 ||
                                up !== null ||
                                down !== null;

                              return (
                                <button
                                  key={node.id}
                                  type="button"
                                  disabled={switchingNode}
                                  onClick={() => void handleSelectNode(node.id)}
                                  className={`flex w-full flex-col gap-1 rounded-xl border px-2.5 py-2 text-left transition-colors ${
                                    isCurrent
                                      ? "border-[var(--accent)]/55 bg-[var(--accent-soft)] text-[var(--text)]"
                                      : "border-transparent bg-transparent text-[var(--text-secondary)] hover:bg-[var(--card)] hover:text-[var(--text)]"
                                  }`}
                                >
                                  {/* Row 1: Status dot + Full Node Name + Current badge + Latency */}
                                  <div className="flex w-full min-w-0 items-center gap-2">
                                    <span
                                      className="h-2 w-2 shrink-0 rounded-full"
                                      style={{ backgroundColor: latColor }}
                                    />
                                    <span
                                      className="min-w-0 flex-1 truncate font-medium text-[var(--text)]"
                                      title={node.name}
                                    >
                                      {node.name}
                                    </span>
                                    {isCurrent && (
                                      <span className="shrink-0 whitespace-nowrap rounded-full bg-[var(--accent)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--accent-ink)]">
                                        当前
                                      </span>
                                    )}
                                    <span
                                      className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap cc-mono cc-tabular text-[11px] font-semibold"
                                      style={{ color: latColor }}
                                      title={latTooltip}
                                    >
                                      {lat !== null
                                        ? `${Math.round(lat)} ms`
                                        : isHintCooldown
                                          ? hint && hint.cooldown_remaining_sec > 0
                                            ? formatI18nTemplate(dict.latency.cooldownSec, {
                                                sec: Math.ceil(hint.cooldown_remaining_sec),
                                              })
                                            : dict.latency.cooldownActive
                                          : resolvedLat.state === "failed"
                                            ? dict.latency.timeoutShort
                                            : dict.latency.untestedShort}
                                    </span>
                                  </div>

                                  {/* Row 2: Region + Google + AI Badges (always visible) + Up/Down Speeds */}
                                  {hasSecondRow && (
                                    <div className="flex w-full min-w-0 flex-wrap items-center gap-x-2 gap-y-1 pl-4 text-[10px]">
                                      {hasRegionTag && (
                                        <span
                                          className="shrink-0 whitespace-nowrap rounded bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[var(--muted)]"
                                          title={getRegionLabel(nodeRegionCode)}
                                        >
                                          {nodeRegionCode}
                                        </span>
                                      )}
                                      {googleState === "clean" && (
                                        <span className="shrink-0 whitespace-nowrap rounded-full bg-[var(--green-soft)] px-1.5 py-0.5 font-medium text-[var(--green)]">
                                          正常
                                        </span>
                                      )}
                                      {googleState === "cn" && (
                                        <span className="shrink-0 whitespace-nowrap rounded-full bg-[var(--red-soft)] px-1.5 py-0.5 font-medium text-[var(--red)]">
                                          送中
                                        </span>
                                      )}
                                      {snap?.google_risk_mismatch && (
                                        <span
                                          className="shrink-0 whitespace-nowrap rounded-full bg-[var(--amber-soft)] px-1.5 py-0.5 font-medium text-[var(--amber)]"
                                          title="不同网站识别出的地区存在差异，仅供参考"
                                        >
                                          地区有偏差
                                        </span>
                                      )}
                                      {aiInfo.unlocked.length > 0 && (
                                        <span
                                          className="inline-flex shrink-0 flex-wrap items-center gap-1"
                                          title={`AI 可用：${aiInfo.unlocked.map((a) => a.label).join(" / ")}`}
                                        >
                                          {aiInfo.unlocked.map((ai) => (
                                            <span
                                              key={ai.id}
                                              className="whitespace-nowrap rounded bg-[var(--accent-soft)] px-1 py-0.5 text-[9px] font-medium text-[var(--accent)]"
                                            >
                                              {ai.short}
                                            </span>
                                          ))}
                                        </span>
                                      )}
                                      {(up !== null || down !== null) && (
                                        <span className="ml-auto inline-flex shrink-0 items-center gap-2 whitespace-nowrap cc-mono cc-tabular text-[10.5px]">
                                          {up !== null && (
                                            <span className="text-[var(--coral)]">
                                              ↑{up.toFixed(1)} Mbps
                                            </span>
                                          )}
                                          {down !== null && (
                                            <span className="text-[var(--sky)]">
                                              ↓{down >= 100 ? Math.round(down) : down.toFixed(1)} Mbps
                                            </span>
                                          )}
                                        </span>
                                      )}
                                    </div>
                                  )}
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

                          <div className="mt-2 flex shrink-0 flex-wrap items-center justify-between gap-2 border-t border-[var(--line)] pt-2 text-[11px] text-[var(--muted)]">
                            <span className="whitespace-nowrap">
                              本组共 {groupCandidateNodes.length} 个节点
                            </span>
                            <div className="flex flex-wrap items-center gap-3">
                              <button
                                type="button"
                                onClick={() => {
                                  setNodeMenuOpen(false);
                                  appActions.setNav("nodes");
                                }}
                                className="whitespace-nowrap text-[var(--text-secondary)] hover:text-[var(--accent)] hover:underline"
                              >
                                去选任意单节点 →
                              </button>
                              <button
                                type="button"
                                onClick={() => {
                                  setNodeMenuOpen(false);
                                  appActions.setNav("groups");
                                }}
                                className="whitespace-nowrap font-medium text-[var(--accent)] hover:underline"
                              >
                                管理多选组 →
                              </button>
                            </div>
                          </div>
                        </div>,
                        document.body
                      )}
                  </div>
                )}
              </div>

              {/* Real-Time Dynamic Mascot Panel (click for 2.5s local pat easter egg) */}
              <HomeMascotPanel
                needsApproval={needsMascotApproval}
                isSearching={isMascotSearching}
                isThinking={isMascotThinking}
                storeMascotState={mascotState}
                coreRunning={runtime.running}
                proxyActive={isProxyEnabled}
                preaccelActive={isPreAccelGuarding}
                directMode={runtime.proxy_mode === "direct"}
                labels={dict.mascot}
                patTooltip={uiLang === "zh-CN" ? "点我揉揉小猫" : "Click to pat"}
              />
            </div>

            {/* Row 3: Mode-Aware Quick Actions (zero duplicate AI buttons; AI Hub lives in sidebar) */}
            <div className="flex flex-wrap items-center gap-2">
              {isSingleMode ? (
                <>
                  <button
                    type="button"
                    onClick={() => appActions.setNav("nodes")}
                    className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl bg-[var(--accent)] px-3.5 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90"
                  >
                    <Server className="h-3.5 w-3.5 shrink-0" />
                    <span>更换单个节点</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => appActions.setNav("groups")}
                    className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
                  >
                    <Layers className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
                    <span>{dict.home.switchGroup}</span>
                  </button>
                </>
              ) : (
                <>
                  <button
                    type="button"
                    disabled={switchingNode || nodes.length === 0}
                    onClick={() => void handleSwitchNextBest()}
                    className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl bg-[var(--accent)] px-3 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-50"
                  >
                    <Zap className="h-3.5 w-3.5 shrink-0" />
                    <span>{switchingNode ? "正在切换…" : dict.home.switchNextNode}</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => appActions.setNav("groups")}
                    className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-2 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
                  >
                    <Layers className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
                    <span>{dict.home.switchGroup}</span>
                  </button>
                </>
              )}

              <button
                type="button"
                onClick={() => void appActions.toggleCapsule()}
                className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-2 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--line-strong)] hover:text-[var(--accent)]"
                title="显示桌面小悬浮条"
              >
                <PictureInPicture2 className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
                <span>{dict.home.openCapsule}</span>
              </button>

              <button
                type="button"
                onClick={() => void handleEnterWindowless()}
                className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-2 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--line-strong)] hover:text-[var(--text)]"
                title="关闭主界面仅留托盘图标，大幅减少内存占用"
              >
                <Minimize2 className="h-3.5 w-3.5 shrink-0 text-[var(--green)]" />
                <span>{dict.home.traySaveMem}</span>
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* Compact 1-Row Inline Status Bar: 1Hz Live Rates + 4 Quick Sites + Expand Details Toggle */}
      <section className="cc-card cc-glass flex flex-wrap items-center justify-between gap-x-3 gap-y-2 rounded-2xl px-3.5 py-2 text-xs">
        <div className="flex min-w-0 flex-wrap items-center gap-x-2.5 gap-y-1.5">
          <HomeCompactTrafficRates />

          <span className="hidden h-3.5 w-px bg-[var(--line)] sm:block" aria-hidden="true" />

          <div
            className="flex flex-wrap items-center gap-x-2.5 gap-y-1"
            aria-label={dict.home.quickSitesInlineLabel}
          >
            {(sites.length > 0 ? sites : DEFAULT_QUICK_SITES).slice(0, 4).map((site) => {
              const color = getLatencyColor(site.latency_ms, site.ok);
              const fullName = formatQuickSiteName(site.name);
              const statusDesc =
                site.ok === false
                  ? "连不上"
                  : site.ok === null || site.latency_ms === null
                    ? "待检测"
                    : `${site.latency_ms} ms`;
              return (
                <span
                  key={site.id}
                  title={`${fullName} · ${statusDesc} (${site.url})`}
                  className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap text-[11.5px]"
                >
                  <span
                    className="h-2 w-2 shrink-0 rounded-full"
                    style={{ backgroundColor: color }}
                  />
                  <span className="font-medium text-[var(--text-secondary)]">
                    {formatQuickSiteShortName(site.name)}
                  </span>
                  {site.ok === false ? (
                    <span className="cc-mono text-[10.5px] font-semibold text-[var(--red)]">
                      ×
                    </span>
                  ) : site.latency_ms !== null ? (
                    <span
                      className="cc-mono cc-tabular text-[10.5px] font-semibold"
                      style={{ color }}
                    >
                      {site.latency_ms}ms
                    </span>
                  ) : null}
                </span>
              );
            })}

            <button
              type="button"
              disabled={checkingSites}
              onClick={() => void handleCheckSites()}
              className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-lg bg-[var(--accent-soft)] px-2 py-1 text-[11px] font-medium text-[var(--accent)] transition-opacity hover:opacity-85 disabled:opacity-60"
            >
              <RefreshCw className={`h-3 w-3 shrink-0 ${checkingSites ? "animate-spin" : ""}`} />
              <span>{dict.home.quickSitesCheckBtn}</span>
            </button>
          </div>
        </div>

        <button
          type="button"
          aria-expanded={detailsOpen}
          onClick={() => setDetailsOpen((v) => !v)}
          className="ml-auto inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 text-[11.5px] font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)]"
        >
          <span>{detailsOpen ? dict.home.detailsCollapse : dict.home.detailsExpand}</span>
          <ChevronDown
            className={`h-3.5 w-3.5 shrink-0 transition-transform ${
              detailsOpen ? "rotate-180" : ""
            }`}
          />
        </button>
      </section>

      {/* Collapsible Detailed Telemetry, Quick Sites, Exit Info & Core Footer (Zero Feature Loss) */}
      {detailsOpen && (
        <>
      {/* Middle Traffic Section: 10-Minute Sparkline + Isolated 1Hz 6-Card KPI Grid */}
      <section className="space-y-3">
        <TrafficSparkline variant="full" />
        <HomeLiveKpiGrid
          connectionSubLabel={connectionSubLabel}
          kernelMemoryTitle={dict.home.kernelMemoryTitle}
          kernelMemorySub={dict.home.kernelMemorySub}
          kernelMemoryTooltip={dict.home.kernelMemoryTooltip}
          gomemlimitMb={config.gomemlimit_mb}
        />
      </section>

      {/* Lower Detection Section: Site Connectivity Check + Exit Information */}
      <section className="grid grid-cols-1 gap-3 min-[1160px]:grid-cols-12">
        {/* Site Connectivity Check Card */}
        <div className="cc-card cc-glass min-w-0 rounded-2xl p-4 min-[1160px]:col-span-7">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div className="min-w-0">
              <h2 className="text-sm font-semibold text-[var(--text)]">
                {dict.home.quickSitesTitle}
              </h2>
              <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                点击右侧「测一下」检测，平时零后台流量
              </p>
            </div>
            <div className="flex shrink-0 flex-wrap items-center gap-1.5">
              <button
                type="button"
                onClick={() => void handleResetDefaultSites()}
                className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-1.5 text-xs font-medium text-[var(--muted)] transition-colors hover:border-[var(--line-strong)] hover:text-[var(--text)]"
                title="一键还原 Google / GitHub / YouTube / OpenAI 4 个默认检测站"
              >
                <RotateCcw className="h-3 w-3 shrink-0" />
                <span>恢复默认</span>
              </button>
              <button
                type="button"
                onClick={() => setShowAddSite((v) => !v)}
                className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)]"
                title="添加常用网站"
              >
                {showAddSite ? <X className="h-3.5 w-3.5 shrink-0" /> : <Plus className="h-3.5 w-3.5 shrink-0" />}
                <span>{showAddSite ? "收起" : "添加"}</span>
              </button>
              <button
                type="button"
                disabled={checkingSites}
                onClick={() => void handleCheckSites()}
                className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-lg bg-[var(--accent-soft)] px-3 py-1.5 text-xs font-medium text-[var(--accent)] transition-opacity hover:opacity-85 disabled:opacity-60"
              >
                <RefreshCw className={`h-3.5 w-3.5 shrink-0 ${checkingSites ? "animate-spin" : ""}`} />
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
                className="min-w-0 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)] sm:col-span-4"
              />
              <input
                type="text"
                value={newSiteUrl}
                onChange={(e) => setNewSiteUrl(e.target.value)}
                placeholder="https://example.com"
                className="min-w-0 cc-mono rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)] sm:col-span-6"
              />
              <button
                type="submit"
                className="whitespace-nowrap rounded-lg bg-[var(--accent)] px-3 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 sm:col-span-2"
              >
                添加
              </button>
            </form>
          )}

          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {sites.map((site) => {
              const isCustom = site.id.startsWith("site-custom-");
              const color = getLatencyColor(site.latency_ms, site.ok);
              const displaySiteName = formatQuickSiteName(site.name);
              return (
                <div
                  key={site.id}
                  title={site.url}
                  className="group flex min-w-0 items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2.5 transition-colors hover:border-[var(--line-strong)]"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex min-w-0 items-center gap-2">
                      <span
                        className="h-2 w-2 shrink-0 rounded-full"
                        style={{ backgroundColor: color }}
                      />
                      <span className="min-w-0 flex-1 truncate text-xs font-medium text-[var(--text)]">
                        {displaySiteName}
                      </span>
                      {isCustom && (
                        <span className="shrink-0 whitespace-nowrap rounded bg-[var(--card)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]">
                          自添加
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="flex shrink-0 items-center gap-1.5">
                    <span
                      className="whitespace-nowrap cc-mono cc-tabular text-xs font-semibold"
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
                      onClick={() => handleRequestRemoveSite(site)}
                      className="w-0 overflow-hidden rounded-md p-0 text-[var(--muted)] opacity-0 transition-all hover:bg-[var(--card)] hover:text-[var(--red)] focus-visible:w-auto focus-visible:p-1 focus-visible:opacity-100 group-hover:w-auto group-hover:p-1 group-hover:opacity-100"
                      title={`移除 ${displaySiteName}`}
                      aria-label={`移除 ${displaySiteName}`}
                    >
                      <Trash2 className="h-3.5 w-3.5 shrink-0" />
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
        <div className="cc-card cc-glass flex min-w-0 flex-col justify-between rounded-2xl p-4 min-[1160px]:col-span-5">
          <div>
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <div className="flex min-w-0 flex-1 items-start gap-2">
                <Globe className="mt-0.5 h-4 w-4 shrink-0 text-[var(--accent)]" />
                <div className="min-w-0">
                  <h2 className="text-sm font-semibold text-[var(--text)]">
                    {dict.home.exitInfoTitle}
                  </h2>
                  <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                    按需点击检测，默认不消耗流量
                  </p>
                </div>
              </div>

              <div className="flex shrink-0 items-center gap-1.5">
                {hasExitIpData && (
                  <button
                    type="button"
                    onClick={() =>
                      appActions.patchSessionDraft("home", { ipMasked: !ipMasked })
                    }
                    className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-1 text-[11px] text-[var(--muted)] transition-colors hover:border-[var(--line-strong)] hover:text-[var(--text)]"
                    title={ipMasked ? "点击查看完整地址" : "点击隐藏末尾数字"}
                  >
                    {ipMasked ? <EyeOff className="h-3.5 w-3.5 shrink-0" /> : <Eye className="h-3.5 w-3.5 shrink-0" />}
                    <span>{ipMasked ? "已遮掩" : "显示中"}</span>
                  </button>
                )}

                <button
                  type="button"
                  disabled={refreshingIp}
                  onClick={() => void handleRefreshExitIp()}
                  className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-lg bg-[var(--accent-soft)] px-2.5 py-1.5 text-xs font-medium text-[var(--accent)] transition-opacity hover:opacity-85 disabled:opacity-60"
                >
                  <RefreshCw className={`h-3.5 w-3.5 shrink-0 ${refreshingIp ? "animate-spin" : ""}`} />
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
                className={`inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-full px-2.5 py-1 text-[11px] font-medium ${googleStatusBadge.cls}`}
              >
                {googleStatusBadge.state === "clean" ? (
                  <CheckCircle2 className="h-3.5 w-3.5 shrink-0" />
                ) : googleStatusBadge.state === "risk" ? (
                  <ShieldAlert className="h-3.5 w-3.5 shrink-0" />
                ) : (
                  <Clock className="h-3.5 w-3.5 shrink-0" />
                )}
                <span>{googleStatusBadge.label}</span>
              </span>
            </div>

            <dl className="space-y-2 text-xs">
              <div className="flex items-center justify-between gap-3 border-b border-[var(--line)]/60 pb-1.5">
                <dt className="shrink-0 text-[var(--muted)]">运营商</dt>
                <dd
                  className={`truncate font-medium ${
                    !hasExitIpData && rawIsp && rawIsp !== "待核心启动探测"
                      ? "text-[var(--amber)]"
                      : "text-[var(--text-secondary)]"
                  }`}
                  title={displayedExitIsp}
                >
                  {displayedExitIsp}
                </dd>
              </div>
              <div className="flex items-center justify-between gap-3 border-b border-[var(--line)]/60 pb-1.5">
                <dt className="shrink-0 text-[var(--muted)]">城市地区</dt>
                <dd className="truncate font-medium text-[var(--text-secondary)]" title={displayedExitLocation}>
                  {displayedExitLocation}
                </dd>
              </div>
              <div className="flex items-center justify-between gap-3">
                <dt className="shrink-0 text-[var(--muted)]">时区</dt>
                <dd className="truncate cc-mono font-medium text-[var(--text-secondary)]" title={displayedExitTimezone}>
                  {displayedExitTimezone}
                </dd>
              </div>
            </dl>
          </div>
        </div>
      </section>

      {/* Compact Elegant Bottom Status Bar */}
      <footer className="cc-card cc-glass mb-2 flex flex-wrap items-center justify-between gap-x-4 gap-y-2 rounded-2xl px-4 py-2.5 text-xs text-[var(--muted)]">
        <div className="flex flex-wrap items-center gap-x-3.5 gap-y-1">
          <span className="inline-flex items-center gap-1.5 whitespace-nowrap font-medium text-[var(--text-secondary)]">
            <span
              className="h-2 w-2 shrink-0 rounded-full"
              style={{
                backgroundColor: runtime.running ? "var(--green)" : "var(--amber)",
              }}
            />
            <HomeLiveUptime running={runtime.running} uptimeSec={runtime.uptime_sec} />
          </span>
          <span className="whitespace-nowrap">
            本地端口 <span className="cc-mono text-[var(--text-secondary)]">{runtime.mixed_port}</span>
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-x-3.5 gap-y-1">
          <span className="whitespace-nowrap">
            版本 <span className="cc-mono text-[var(--text-secondary)]">v{runtime.app_version}</span>
          </span>
          <span className="whitespace-nowrap rounded-full border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-0.5 text-[11px] text-[var(--text-secondary)]">
            {runtime.portable_mode ? "便携版" : "安装版"}
          </span>
        </div>
      </footer>
        </>
      )}

      {/* In-Page Two-Step Confirmation Modal for Removing a Quick Check Site */}
      {pendingRemoveSite &&
        typeof document !== "undefined" &&
        createPortal(
          <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4 backdrop-blur-[2px]"
            onClick={() => {
              if (!removingSite) setPendingRemoveSite(null);
            }}
          >
            <div
              role="dialog"
              aria-modal="true"
              aria-label="确认移除检测网站"
              onClick={(e) => e.stopPropagation()}
              className="cc-surface max-h-[calc(100vh-2rem)] w-full max-w-md overflow-y-auto rounded-2xl border border-[var(--line-strong)] p-5 shadow-2xl"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-start gap-3">
                  <span className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[var(--amber-soft)] text-[var(--amber)]">
                    <AlertTriangle className="h-4 w-4" />
                  </span>
                  <div className="min-w-0">
                    <h3 className="text-sm font-semibold text-[var(--text)]">
                      确认移除检测网站？
                    </h3>
                    <p className="mt-1 text-xs leading-relaxed text-[var(--text-secondary)]">
                      确定要从常用网站连通检测列表中移除「
                      <span className="font-semibold text-[var(--text)]">
                        {formatQuickSiteName(pendingRemoveSite.name)}
                      </span>
                      」吗？移除后可随时重新添加，或点击「恢复默认」还原预设站点。
                    </p>
                    <p
                      className="mt-1.5 truncate cc-mono rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 text-[11px] text-[var(--muted)]"
                      title={pendingRemoveSite.url}
                    >
                      {pendingRemoveSite.url}
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  disabled={removingSite}
                  onClick={() => setPendingRemoveSite(null)}
                  className="rounded-lg p-1 text-[var(--muted)] transition-colors hover:bg-[var(--bg-elevated)] hover:text-[var(--text)] disabled:opacity-50"
                  aria-label="关闭弹窗"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              <div className="mt-5 flex justify-end gap-2">
                <button
                  type="button"
                  disabled={removingSite}
                  onClick={() => setPendingRemoveSite(null)}
                  className="rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-2 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:text-[var(--text)] disabled:opacity-50"
                >
                  {dict.common.cancel}
                </button>
                <button
                  type="button"
                  disabled={removingSite}
                  onClick={() => void handleConfirmRemoveSite()}
                  className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--red)] px-4 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-60"
                >
                  {removingSite ? (
                    <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Trash2 className="h-3.5 w-3.5" />
                  )}
                  <span>{removingSite ? "正在移除…" : "确认移除"}</span>
                </button>
              </div>
            </div>
          </div>,
          document.body
        )}

      <ShareBundleModal
        open={syncModalOpen}
        mode="import"
        initialTransport="listen_qr"
        allowModeSwitch
        onClose={() => setSyncModalOpen(false)}
      />
    </div>
  );
}
