import { useSyncExternalStore } from "react";
import {
  type AgentPromptMode,
  type AppConfig,
  type AppUpdateCheckResult,
  type CampusPortalStatus,
  type CoreRuntimeInfo,
  DEFAULT_APP_CONFIG,
  DEFAULT_GLOBAL_PREACCEL_STATUS,
  type ExitIpInfo,
  type GeoDataStatusDto,
  type GlobalPreAccelScope,
  type GlobalPreAccelStatus,
  type GroupEvaluationReport,
  type LiveCaptureOutcomeDto,
  type LiveCaptureStartDto,
  type LiveCaptureStatusDto,
  type MultiGroup,
  type PreAccelComparisonResult,
  type PreAccelRelay,
  type PreAccelSpeedTestResult,
  type ProbeRunSummary,
  type ProbeSnapshot,
  type ProxyMode,
  type ProxyNode,
  type ResolvedTheme,
  type SiteCheckItem,
  type SubscriptionRecord,
  type ThemeMode,
  type ThemeSchedule,
  type TrafficSample,
  catcloudApi,
  formatErrorMessage,
  generateSeedTrafficSamples,
  hasPreviewTunNeedsAdminFlag,
  isTauriEnv,
} from "../api/tauri";
import { detectNavigatorOs, resolvePlatformOs } from "../utils/platform";
import {
  ensureUiLocaleLoaded,
  normalizeUiLanguage,
  type UiLanguage,
} from "../i18n";
import {
  isRealWinDivertActive,
  normalizePreAccelInstallState,
  normalizePreAccelVerifyState,
  resolvePreAccelSummary,
} from "../utils/preaccelStatus";

export type { UiLanguage };

export type {
  AgentPromptMode,
  AppConfig,
  CoreRuntimeInfo,
  DnsTlsDiagnostics,
  GlobalPreAccelMode,
  GlobalPreAccelScope,
  GlobalPreAccelStatus,
  PreAccelDispatchStrategy,
  PreAccelLbStrategy,
  PreAccelVerifyState,
  ProbeRunSummary,
  ProxyMode,
  ResolvedTheme,
  RouteTargetMode,
  ThemeMode,
  TrafficSample,
} from "../api/tauri";

export type MascotState =
  | "idle"
  | "searching"
  | "thinking"
  | "typing"
  | "approval"
  | "complete";

export type NavRouteId =
  | "overview"
  | "groups"
  | "speedtest"
  | "preaccel"
  | "nodes"
  | "rules"
  | "logs"
  | "ai"
  | "settings";

export type WindowMode = "main" | "capsule";

export interface ToastNotice {
  id: number;
  text: string;
  tone: "info" | "ok" | "warn";
}

export const TRAFFIC_HISTORY_CAPACITY = 600;
const UI_PREFS_STORAGE_KEY = "catcloud.ui.prefs.v1";

/**
 * Fixed-length 600-point Float64Array ring buffer (1s x 600 = full 10 minutes).
 * Zero allocations on push; zero GC churn during steady-state streaming.
 */
export class TrafficRingBuffer {
  readonly capacity: number;
  readonly up: Float64Array;
  readonly down: Float64Array;
  readonly ts: Float64Array;
  private head = 0;
  private count = 0;

  constructor(capacity = TRAFFIC_HISTORY_CAPACITY) {
    this.capacity = capacity;
    this.up = new Float64Array(capacity);
    this.down = new Float64Array(capacity);
    this.ts = new Float64Array(capacity);
  }

  get length(): number {
    return this.count;
  }

  push(upBps: number, downBps: number, timestampMs: number = Date.now()): void {
    const safeUp = Number.isFinite(upBps) && upBps > 0 ? upBps : 0;
    const safeDown = Number.isFinite(downBps) && downBps > 0 ? downBps : 0;
    this.up[this.head] = safeUp;
    this.down[this.head] = safeDown;
    this.ts[this.head] = timestampMs;
    this.head = (this.head + 1) % this.capacity;
    if (this.count < this.capacity) {
      this.count += 1;
    }
  }

  /** Logical index 0 = oldest retained point, length - 1 = newest point. */
  slotAt(logicalIndex: number): number {
    if (this.count < this.capacity) {
      return logicalIndex;
    }
    return (this.head + logicalIndex) % this.capacity;
  }

  upAt(logicalIndex: number): number {
    return this.up[this.slotAt(logicalIndex)];
  }

  downAt(logicalIndex: number): number {
    return this.down[this.slotAt(logicalIndex)];
  }

  tsAt(logicalIndex: number): number {
    return this.ts[this.slotAt(logicalIndex)];
  }

  clear(): void {
    this.head = 0;
    this.count = 0;
    this.up.fill(0);
    this.down.fill(0);
    this.ts.fill(0);
  }
}

/* ============================================================================
 * Beijing-Time (UTC+8) 3-Segment Theme Scheduler
 * 07:00 - 18:30 -> light
 * 18:30 - 22:30 -> warm-dark
 * 22:30 - 07:00 -> midnight-blue
 * ============================================================================ */

function parseClockMinutes(hhmm: string, fallback: number): number {
  const m = /^(\d{1,2}):(\d{2})$/.exec(hhmm.trim());
  if (!m) return fallback;
  const h = Number(m[1]);
  const min = Number(m[2]);
  if (h < 0 || h > 23 || min < 0 || min > 59) return fallback;
  return h * 60 + min;
}

export function getBeijingMinutes(now: Date = new Date()): number {
  const utcMinutes = now.getUTCHours() * 60 + now.getUTCMinutes();
  return (utcMinutes + 8 * 60) % 1440;
}

export function resolveThemeBySchedule(
  mode: ThemeMode,
  schedule: ThemeSchedule = DEFAULT_APP_CONFIG.personalization.theme_schedule,
  now: Date = new Date()
): ResolvedTheme {
  if (mode === "light") return "light";
  if (mode === "warm_dark") return "warm-dark";
  if (mode === "midnight_blue") return "midnight-blue";

  const bjt = getBeijingMinutes(now);
  const points: Array<{ min: number; theme: ResolvedTheme }> = [
    { min: parseClockMinutes(schedule.light_start, 7 * 60), theme: "light" },
    { min: parseClockMinutes(schedule.warm_dark_start, 18 * 60 + 30), theme: "warm-dark" },
    { min: parseClockMinutes(schedule.midnight_start, 22 * 60 + 30), theme: "midnight-blue" },
  ];
  points.sort((a, b) => a.min - b.min);

  let active = points[points.length - 1].theme;
  for (const pt of points) {
    if (bjt >= pt.min) {
      active = pt.theme;
    }
  }
  return active;
}

export function getBeijingTimeLabel(now: Date = new Date()): string {
  const bjt = getBeijingMinutes(now);
  const h = String(Math.floor(bjt / 60)).padStart(2, "0");
  const m = String(bjt % 60).padStart(2, "0");
  return `${h}:${m} BJT`;
}

function detectWindowModeFromLocation(): WindowMode {
  if (typeof window === "undefined") return "main";
  const hash = window.location.hash.replace(/^#\/?/, "").toLowerCase();
  if (hash === "capsule") return "capsule";
  return "main";
}

const VALID_ROUTES = new Set<NavRouteId>([
  "overview",
  "groups",
  "speedtest",
  "preaccel",
  "nodes",
  "rules",
  "logs",
  "ai",
  "settings",
]);

function detectNavFromHash(): NavRouteId {
  if (typeof window === "undefined") return "overview";
  const raw = window.location.hash.replace(/^#\/?/, "").toLowerCase();
  if (raw === "speedtest") return "nodes";
  if (raw === "home") return "overview";
  return VALID_ROUTES.has(raw as NavRouteId) ? (raw as NavRouteId) : "overview";
}

function hasExplicitRouteHash(): boolean {
  if (typeof window === "undefined") return false;
  const raw = window.location.hash.replace(/^#\/?/, "").toLowerCase();
  return raw.length > 0 && (raw === "capsule" || VALID_ROUTES.has(raw as NavRouteId));
}

function loadCachedUiPrefs(): Partial<AppConfig["personalization"]> {
  if (typeof window === "undefined") return {};
  try {
    const raw = window.localStorage.getItem(UI_PREFS_STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as Partial<AppConfig["personalization"]>;
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function saveCachedUiPrefs(p: AppConfig["personalization"]): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(
      UI_PREFS_STORAGE_KEY,
      JSON.stringify({
        ui_language: normalizeUiLanguage(p.ui_language),
        theme_mode: p.theme_mode,
        theme_schedule: p.theme_schedule,
        tray_icon_mode: p.tray_icon_mode,
        animations_enabled: p.animations_enabled,
        mascot_enabled: p.mascot_enabled,
        sparkline_enabled: p.sparkline_enabled,
        wallpaper_opacity: p.wallpaper_opacity,
        glass_blur_px: p.glass_blur_px,
        onboarding_completed: p.onboarding_completed,
      })
    );
  } catch {
    /* ignore storage quota errors */
  }
}

function sanitizeCssUrl(raw: string): string {
  return raw.replace(/["\\\n\r]/g, "");
}

export const BUILTIN_WALLPAPER_PRESETS: ReadonlyArray<{
  id: string;
  label: string;
  cssBackground: string;
  previewStyle: string;
}> = [
  {
    id: "preset:sunset-cloud",
    label: "晚霞猫云",
    cssBackground:
      "radial-gradient(circle at 18% 20%, rgba(242, 165, 114, 0.55), transparent 52%), radial-gradient(circle at 82% 28%, rgba(132, 179, 232, 0.5), transparent 56%), linear-gradient(135deg, #2b2338 0%, #5c3e4f 45%, #c77d5c 100%)",
    previewStyle:
      "linear-gradient(135deg, #2b2338 0%, #5c3e4f 45%, #c77d5c 100%)",
  },
  {
    id: "preset:warm-paper",
    label: "晨光暖雾",
    cssBackground:
      "radial-gradient(circle at 22% 18%, rgba(236, 189, 128, 0.55), transparent 55%), radial-gradient(circle at 80% 78%, rgba(164, 191, 159, 0.45), transparent 55%), linear-gradient(135deg, #f8f1e4 0%, #eadac2 55%, #dfcbb0 100%)",
    previewStyle:
      "linear-gradient(135deg, #f8f1e4 0%, #eadac2 55%, #dfcbb0 100%)",
  },
  {
    id: "preset:moss-gold",
    label: "深苔流金",
    cssBackground:
      "radial-gradient(circle at 20% 25%, rgba(223, 183, 130, 0.35), transparent 50%), radial-gradient(circle at 78% 72%, rgba(130, 175, 145, 0.3), transparent 55%), linear-gradient(135deg, #121716 0%, #1d2624 52%, #2c251c 100%)",
    previewStyle:
      "linear-gradient(135deg, #121716 0%, #1d2624 52%, #2c251c 100%)",
  },
  {
    id: "preset:midnight-star",
    label: "午夜星海",
    cssBackground:
      "radial-gradient(circle at 24% 22%, rgba(96, 165, 250, 0.4), transparent 48%), radial-gradient(circle at 80% 76%, rgba(223, 183, 130, 0.28), transparent 52%), linear-gradient(135deg, #0b1224 0%, #162447 55%, #1e315c 100%)",
    previewStyle:
      "linear-gradient(135deg, #0b1224 0%, #162447 55%, #1e315c 100%)",
  },
];

const SAFE_BITMAP_DATA_URL_RE = /^data:image\/(png|jpe?g|webp|gif|bmp);base64,/i;

let resolvedWallpaperCache: { rawPath: string; cssValue: string } | null = null;

function resolveImmediateWallpaperCss(rawPath: string | null | undefined): string | null {
  const trimmed = rawPath?.trim() ?? "";
  if (!trimmed) return null;
  const preset = BUILTIN_WALLPAPER_PRESETS.find((item) => item.id === trimmed);
  if (preset) return preset.cssBackground;
  if (
    /^https?:\/\//i.test(trimmed) ||
    SAFE_BITMAP_DATA_URL_RE.test(trimmed)
  ) {
    return `url("${sanitizeCssUrl(trimmed)}")`;
  }
  if (resolvedWallpaperCache && resolvedWallpaperCache.rawPath === trimmed) {
    return resolvedWallpaperCache.cssValue;
  }
  return null;
}

function applyPersonalizationToDom(
  resolvedTheme: ResolvedTheme,
  p: AppConfig["personalization"],
  windowMode: WindowMode,
  explicitCssValue?: string | null
): void {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  const lang = normalizeUiLanguage(p.ui_language);
  root.setAttribute("lang", lang);
  if (lang !== "zh-CN") {
    void ensureUiLocaleLoaded(lang);
  }
  root.setAttribute("data-theme", resolvedTheme);
  root.setAttribute("data-animations", p.animations_enabled ? "on" : "off");
  if (windowMode === "capsule") {
    root.setAttribute("data-window", "capsule");
    root.setAttribute("data-wallpaper", "off");
    root.setAttribute("data-glass", "off");
    root.style.setProperty("--wallpaper-image", "none");
    root.style.setProperty("--wallpaper-opacity", "0");
    root.style.setProperty("--surface-alpha", "1");
    root.style.setProperty("--card-alpha", "1");
    root.style.setProperty("--glass-blur", "0px");
    return;
  }
  root.removeAttribute("data-window");

  const rawPath = p.wallpaper_path?.trim() ?? "";
  const cssBg = explicitCssValue ?? resolveImmediateWallpaperCss(rawPath);
  if (rawPath && cssBg) {
    const opacity = Math.max(0.05, Math.min(0.65, p.wallpaper_opacity));
    const blurPx = Math.max(0, Math.min(24, Math.round(p.glass_blur_px)));
    root.setAttribute("data-wallpaper", "on");
    root.setAttribute("data-glass", blurPx > 0 ? "on" : "off");
    root.style.setProperty("--wallpaper-image", cssBg);
    root.style.setProperty("--wallpaper-opacity", String(opacity));
    root.style.setProperty("--surface-alpha", blurPx > 0 ? "0.82" : "0.90");
    root.style.setProperty("--card-alpha", blurPx > 0 ? "0.78" : "0.88");
    root.style.setProperty("--glass-blur", `${blurPx}px`);
  } else {
    root.setAttribute("data-wallpaper", "off");
    root.setAttribute("data-glass", "off");
    root.style.setProperty("--wallpaper-image", "none");
    root.style.setProperty("--wallpaper-opacity", "0");
    root.style.setProperty("--surface-alpha", "1");
    root.style.setProperty("--card-alpha", "1");
    root.style.setProperty("--glass-blur", "0px");
  }
}

async function ensureLocalWallpaperLoaded(
  rawPath: string | null | undefined,
  resolvedTheme: ResolvedTheme,
  p: AppConfig["personalization"],
  windowMode: WindowMode
): Promise<void> {
  if (windowMode === "capsule") {
    applyPersonalizationToDom(
      resolvedTheme,
      { ...p, wallpaper_path: null, glass_blur_px: 0 },
      windowMode,
      null
    );
    return;
  }
  const trimmed = rawPath?.trim() ?? "";
  if (!trimmed) {
    setState((prev) => (prev.wallpaperError === null ? prev : { ...prev, wallpaperError: null }));
    return;
  }
  if (/^data:/i.test(trimmed) && !SAFE_BITMAP_DATA_URL_RE.test(trimmed)) {
    applyPersonalizationToDom(resolvedTheme, { ...p, wallpaper_path: null }, windowMode, null);
    setState((prev) => ({
      ...prev,
      wallpaperPreviewUrl: null,
      wallpaperError: "不支持此图片格式，请选择 PNG、JPG、WebP、GIF 或 BMP 图片",
    }));
    return;
  }
  if (resolveImmediateWallpaperCss(trimmed)) {
    setState((prev) => {
      const nextPreview = SAFE_BITMAP_DATA_URL_RE.test(trimmed) ? trimmed : prev.wallpaperPreviewUrl;
      if (prev.wallpaperError === null && prev.wallpaperPreviewUrl === nextPreview) {
        return prev;
      }
      return {
        ...prev,
        wallpaperPreviewUrl: nextPreview,
        wallpaperError: null,
      };
    });
    return;
  }
  setState((prev) => (prev.wallpaperError === null ? prev : { ...prev, wallpaperError: null }));
  try {
    const dataUrl = await catcloudApi.resolveWallpaperDataUrl(trimmed);
    if ((state.config.personalization.wallpaper_path?.trim() ?? "") !== trimmed) {
      return;
    }
    if (!dataUrl || !SAFE_BITMAP_DATA_URL_RE.test(dataUrl)) {
      applyPersonalizationToDom(resolvedTheme, { ...p, wallpaper_path: null }, windowMode, null);
      setState((prev) => ({
        ...prev,
        wallpaperPreviewUrl: null,
        wallpaperError: "本地壁纸加载失败：原图片可能已移动、删除或格式不受支持，可重新选择或恢复纯色背景",
      }));
      return;
    }
    const cssVal = `url("${sanitizeCssUrl(dataUrl)}")`;
    resolvedWallpaperCache = { rawPath: trimmed, cssValue: cssVal };
    applyPersonalizationToDom(resolvedTheme, p, windowMode, cssVal);
    setState((prev) => ({ ...prev, wallpaperPreviewUrl: dataUrl, wallpaperError: null }));
  } catch (err) {
    if ((state.config.personalization.wallpaper_path?.trim() ?? "") !== trimmed) {
      return;
    }
    const detail = formatErrorMessage(err);
    applyPersonalizationToDom(resolvedTheme, { ...p, wallpaper_path: null }, windowMode, null);
    setState((prev) => ({
      ...prev,
      wallpaperPreviewUrl: null,
      wallpaperError: detail
        ? `本地壁纸加载失败（${detail}），可重新选择图片或恢复纯色背景`
        : "本地壁纸加载失败：无法读取图片文件，可重新选择或恢复纯色背景",
    }));
  }
}

/* ============================================================================
 * Reactive External Store (Zero extra dependencies, React 19 useSyncExternalStore)
 * ============================================================================ */

export interface ProbeRunProgressState {
  running: boolean;
  completed: number;
  total: number;
  currentNodeName: string | null;
  cancelled: boolean;
}

export interface BgTasksState {
  preaccel: {
    benchmark: {
      running: boolean;
      nodeId: string | null;
      result: PreAccelComparisonResult | null;
      error: string | null;
      finishedAt: number | null;
    };
    relaysTestingAll: boolean;
    relaysTestingIds: string[];
    relaysSpeedTestingAll: boolean;
    relaysSpeedTestingIds: string[];
    campusChecking: boolean;
    campusResult: CampusPortalStatus | null;
    campusError: string | null;
    installingDriver: boolean;
    verifyingGlobal: boolean;
  };
  subs: {
    refreshingAll: boolean;
    refreshingIds: string[];
    importing: boolean;
  };
  home: {
    checkingQuickSites: boolean;
    refreshingExitIp: boolean;
  };
  groups: {
    probingNodeIds: string[];
    evaluatingGroupId: string | null;
    evalReports: Record<string, GroupEvaluationReport>;
  };
  settings: {
    geoStatus: GeoDataStatusDto | null;
    geoLoading: boolean;
    geoBusy: string | null;
    checkingUpdate: boolean;
    downloadingUpdate: boolean;
    updateInfo: AppUpdateCheckResult | null;
    updateMessage: string | null;
    coreOpBusy: "start" | "stop" | "restart" | "reload" | "hotswap" | null;
    backupBusy: "export" | "import" | null;
  };
  capture: {
    sessionId: string | null;
    active: boolean;
    timedOut: boolean;
    finishing: boolean;
    targetName: string | null;
    status: LiveCaptureStatusDto | null;
    outcome: LiveCaptureOutcomeDto | null;
  };
  probeActiveNodeIds: string[];
  probeLockedOrderIds: string[];
  probeIsPausing: boolean;
  probeLocalStarting: boolean;
}

export interface SessionDraftsState {
  scrollPositions: Record<string, number>;
  nodesWorkspace: {
    tab: "nodes" | "subs";
    filterSubId: string;
  };
  preAccel: {
    selectedCompareNodeId: string;
  };
  speedTest: {
    searchQuery: string;
    sourceFilter: string;
    groupFilter: string;
    filterContinent?: string;
    regionFilter: string;
    onlyGolden: boolean;
    onlyTested: boolean;
    onlyGoogleClean: boolean;
    onlyAiUnlocked: boolean;
    page: number;
    selectedIds: string[];
  };
  multiGroup: {
    selectedId: string;
    hasDirtyDrafts: boolean;
  };
  settings: {
    tab: string;
    hasDirtyDrafts: boolean;
  };
  rulesConns: {
    connPaused: boolean;
    connSearch: string;
    ruleSearch: string;
  };
  home: {
    ipMasked: boolean;
  };
}

export interface AppState {
  initialized: boolean;
  isTauri: boolean;
  windowMode: WindowMode;
  activeNav: NavRouteId;
  aiRouteHint: { moduleId?: string; tab?: "web" | "agent" } | null;
  settingsTabHint: "system" | "appearance" | "dns" | "core" | "updates" | null;
  settingsOpenAgentDocs: boolean;
  nodesTabHint: {
    tab: "nodes" | "subs";
    subId?: string | null;
    action?: "migration" | null;
  } | null;
  config: AppConfig;
  resolvedTheme: ResolvedTheme;
  wallpaperPreviewUrl: string | null;
  wallpaperError: string | null;
  mascotState: MascotState;
  runtime: CoreRuntimeInfo;
  groups: MultiGroup[];
  nodes: ProxyNode[];
  probes: Record<string, ProbeSnapshot>;
  probeProgress: ProbeRunProgressState;
  lastProbeSummary: ProbeRunSummary | null;
  subscriptions: SubscriptionRecord[];
  preAccelRelays: PreAccelRelay[];
  relayChainLatencies: Record<string, number | null>;
  globalPreAccel: GlobalPreAccelStatus;
  exitIp: ExitIpInfo;
  quickSites: SiteCheckItem[];
  latestTraffic: TrafficSample;
  trafficVersion: number;
  toast: ToastNotice | null;
  onboardingModalOpen: boolean;
  onboardingAutoSkipped: boolean;
  tunAdminPromptOpen: boolean;
  tunAdminPromptBusy: boolean;
  tunAdminPromptReason: string | null;
  bgTasks: BgTasksState;
  sessionDrafts: SessionDraftsState;
}

export function selectIsProbeEngineBusy(s: AppState): boolean {
  return Boolean(
    s.probeProgress.running ||
      s.bgTasks.probeLocalStarting ||
      s.bgTasks.preaccel.benchmark.running ||
      s.bgTasks.preaccel.relaysSpeedTestingAll ||
      s.bgTasks.preaccel.relaysSpeedTestingIds.length > 0
  );
}

let cachedBgActivity: {
  preaccel: boolean;
  nodes: boolean;
  groups: boolean;
  home: boolean;
  settings: boolean;
} = {
  preaccel: false,
  nodes: false,
  groups: false,
  home: false,
  settings: false,
};

export function selectHasBackgroundActivity(s: AppState): {
  preaccel: boolean;
  nodes: boolean;
  groups: boolean;
  home: boolean;
  settings: boolean;
} {
  const preaccel = Boolean(
    s.bgTasks.preaccel.benchmark.running ||
      s.bgTasks.preaccel.relaysTestingAll ||
      s.bgTasks.preaccel.relaysTestingIds.length > 0 ||
      s.bgTasks.preaccel.relaysSpeedTestingAll ||
      s.bgTasks.preaccel.relaysSpeedTestingIds.length > 0 ||
      s.bgTasks.preaccel.campusChecking ||
      s.bgTasks.preaccel.installingDriver ||
      s.bgTasks.preaccel.verifyingGlobal
  );
  const nodes = Boolean(
    s.probeProgress.running ||
      s.bgTasks.probeLocalStarting ||
      s.bgTasks.subs.refreshingAll ||
      s.bgTasks.subs.refreshingIds.length > 0 ||
      s.bgTasks.subs.importing ||
      s.bgTasks.capture.active ||
      s.bgTasks.capture.finishing
  );
  const groups = Boolean(
    s.bgTasks.groups.probingNodeIds.length > 0 ||
      s.bgTasks.groups.evaluatingGroupId !== null
  );
  const home = Boolean(
    s.bgTasks.home.checkingQuickSites || s.bgTasks.home.refreshingExitIp
  );
  const settings = Boolean(
    s.bgTasks.settings.geoBusy !== null ||
      s.bgTasks.settings.checkingUpdate ||
      s.bgTasks.settings.downloadingUpdate ||
      s.bgTasks.settings.coreOpBusy !== null ||
      s.bgTasks.settings.backupBusy !== null
  );
  if (
    cachedBgActivity.preaccel === preaccel &&
    cachedBgActivity.nodes === nodes &&
    cachedBgActivity.groups === groups &&
    cachedBgActivity.home === home &&
    cachedBgActivity.settings === settings
  ) {
    return cachedBgActivity;
  }
  cachedBgActivity = { preaccel, nodes, groups, home, settings };
  return cachedBgActivity;
}

const runningInTauri = isTauriEnv();
const previewTunNeedsAdmin = !runningInTauri && hasPreviewTunNeedsAdminFlag();
const initialPrefs = loadCachedUiPrefs();
const initialConfig: AppConfig = runningInTauri
  ? {
      ...structuredClone(DEFAULT_APP_CONFIG),
      system_proxy_enabled: false,
      autostart_enabled: false,
      gomemlimit_mb: 0,
      memory_tier: "auto",
      preaccel: {
        ...DEFAULT_APP_CONFIG.preaccel,
        enabled: false,
      },
      personalization: {
        ...DEFAULT_APP_CONFIG.personalization,
        ...initialPrefs,
      },
    }
  : {
      ...structuredClone(DEFAULT_APP_CONFIG),
      system_proxy_enabled: previewTunNeedsAdmin ? true : DEFAULT_APP_CONFIG.system_proxy_enabled,
      tun_enabled: previewTunNeedsAdmin ? true : DEFAULT_APP_CONFIG.tun_enabled,
      personalization: {
        ...DEFAULT_APP_CONFIG.personalization,
        ...initialPrefs,
      },
    };

const initialWindowMode = detectWindowModeFromLocation();
const initialResolvedTheme = resolveThemeBySchedule(
  initialConfig.personalization.theme_mode,
  initialConfig.personalization.theme_schedule
);

const trafficBuffer = new TrafficRingBuffer(TRAFFIC_HISTORY_CAPACITY);
const EMPTY_TRAFFIC: TrafficSample = {
  up_bps: 0,
  down_bps: 0,
  up_total_bytes: 0,
  down_total_bytes: 0,
  connections: 0,
  tunnel_connections: 0,
  memory_mb: 0,
  timestamp_ms: 0,
};

let initialTraffic: TrafficSample = EMPTY_TRAFFIC;
let initialTrafficVersion = 0;
if (!runningInTauri) {
  const seedSamples = generateSeedTrafficSamples(300, 1000);
  for (const s of seedSamples) {
    trafficBuffer.push(s.up_bps, s.down_bps, s.timestamp_ms);
  }
  initialTraffic = seedSamples[seedSamples.length - 1] ?? EMPTY_TRAFFIC;
  initialTrafficVersion = seedSamples.length;
}

const initialDetectedOs = detectNavigatorOs();
const initialOsLabel =
  initialDetectedOs === "macos"
    ? "macos"
    : initialDetectedOs === "linux"
      ? "linux"
      : "windows";

const initialRuntime: CoreRuntimeInfo = runningInTauri
  ? {
      running: false,
      status: "idle",
      core_name: "Mihomo Meta",
      core_version: "--",
      proxy_mode: initialConfig.proxy_mode,
      mixed_port: initialConfig.mixed_port,
      controller_addr: `127.0.0.1:${initialConfig.controller_port}`,
      uptime_sec: 0,
      rule_count: 0,
      route_mode: "group",
      active_group_id: "",
      active_group_name: "等待连接",
      active_node_id: "",
      active_node_name: "待核心就绪",
      active_node_region: "--",
      active_node_latency_ms: null,
      active_node_up_mbps: null,
      preaccel_active: false,
      preaccel_enabled: false,
      preaccel_relay_name: null,
      global_preaccel_active: false,
      global_windivert_active: false,
      global_preaccel_mode: "off",
      global_preaccel_socks_port: null,
      global_preaccel_connections: 0,
      preaccel_install_state: "idle",
      global_preaccel_verify_state: "idle",
      global_preaccel_verify_ms: null,
      node_health_hints: {},
      captive_portal_required: false,
      system_proxy_enabled: false,
      tun_enabled: false,
      tun_configured: false,
      tun_needs_elevation: false,
      tun_admin_ready: false,
      app_version: "0.1.0",
      os_label: initialOsLabel,
      autostart_enabled: false,
      portable_mode: false,
      last_update_check: null,
    }
  : {
      running: true,
      status: "preaccel",
      core_name: "Mihomo Meta",
      core_version: "v1.19.12-alpha",
      proxy_mode: initialConfig.proxy_mode,
      mixed_port: initialConfig.mixed_port,
      controller_addr: `127.0.0.1:${initialConfig.controller_port}`,
      uptime_sec: 4820,
      rule_count: 1428,
      route_mode: "group",
      active_group_id: "grp-ai",
      active_group_name: "AI 专线粘性组",
      active_node_id: "node-jp-01",
      active_node_name: "JP-Tokyo-01 · 1x",
      active_node_region: "JP",
      active_node_latency_ms: 68,
      active_node_up_mbps: 14.8,
      preaccel_active: true,
      preaccel_enabled: initialConfig.preaccel.enabled,
      preaccel_relay_name: "CN-East-443 Primary",
      global_preaccel_active: false,
      global_windivert_active: false,
      global_preaccel_mode: "off",
      global_preaccel_socks_port: null,
      global_preaccel_connections: 0,
      preaccel_install_state: "idle",
      global_preaccel_verify_state: "idle",
      global_preaccel_verify_ms: null,
      node_health_hints: {},
      captive_portal_required: false,
      system_proxy_enabled: initialConfig.system_proxy_enabled,
      tun_enabled: initialConfig.tun_enabled && !previewTunNeedsAdmin,
      tun_configured: initialConfig.tun_enabled,
      tun_needs_elevation: initialConfig.tun_enabled && previewTunNeedsAdmin,
      tun_admin_ready: !previewTunNeedsAdmin,
      app_version: "0.1.0",
      os_label: "Windows 11 x64",
      autostart_enabled: true,
      portable_mode: true,
      last_update_check: "2026-11-23 04:30",
    };

const initialExitIp: ExitIpInfo = runningInTauri
  ? {
      ip_masked: "--.--.--.***",
      ip_raw: null,
      isp: "待核心启动探测",
      location: "未连接",
      timezone: "UTC+8",
      google_clean: null,
      core_running: false,
    }
  : {
      ip_masked: "203.0.113.***",
      ip_raw: "203.0.113.10",
      isp: "东京示例线路",
      location: "Tokyo, JP",
      timezone: "Asia/Tokyo (UTC+9)",
      google_clean: true,
      core_running: true,
    };

function buildPendingExitIp(coreRunning: boolean): ExitIpInfo {
  return {
    ip_masked: "--.--.--.***",
    ip_raw: null,
    isp: coreRunning ? "已切换线路，点击「测一下」刷新" : "待核心启动探测",
    location: "待检测",
    timezone: "--",
    google_clean: null,
    core_running: coreRunning,
  };
}

function mergeProbeSnapshotSafe(
  prev: ProbeSnapshot | undefined,
  incoming: ProbeSnapshot
): ProbeSnapshot {
  if (!prev) return incoming;
  const incomingUnlocked = incoming.unlocked_sites ?? {};
  const hasIncomingUnlocked = Object.keys(incomingUnlocked).length > 0;
  return {
    ...prev,
    ...incoming,
    up_mbps: incoming.up_mbps ?? prev.up_mbps,
    down_mbps: incoming.down_mbps ?? prev.down_mbps,
    cf_loc: incoming.cf_loc ?? prev.cf_loc,
    yt_gl: incoming.yt_gl ?? prev.yt_gl,
    google_clean: incoming.google_clean ?? prev.google_clean,
    google_risk_mismatch:
      incoming.google_clean !== null && incoming.google_clean !== undefined
        ? incoming.google_risk_mismatch
        : prev.google_risk_mismatch,
    keepalive_60s_ok: incoming.keepalive_60s_ok ?? prev.keepalive_60s_ok,
    unlocked_sites: hasIncomingUnlocked
      ? { ...(prev.unlocked_sites ?? {}), ...incomingUnlocked }
      : (prev.unlocked_sites ?? {}),
    per_probe_ok: { ...(prev.per_probe_ok ?? {}), ...(incoming.per_probe_ok ?? {}) },
    per_probe_up_mbps: {
      ...(prev.per_probe_up_mbps ?? {}),
      ...(incoming.per_probe_up_mbps ?? {}),
    },
    per_probe_down_mbps: {
      ...(prev.per_probe_down_mbps ?? {}),
      ...(incoming.per_probe_down_mbps ?? {}),
    },
    per_probe_ping_ms: {
      ...(prev.per_probe_ping_ms ?? {}),
      ...(incoming.per_probe_ping_ms ?? {}),
    },
    per_probe_detail: {
      ...(prev.per_probe_detail ?? {}),
      ...(incoming.per_probe_detail ?? {}),
    },
  };
}

function createInitialBgTasks(): BgTasksState {
  return {
    preaccel: {
      benchmark: {
        running: false,
        nodeId: null,
        result: null,
        error: null,
        finishedAt: null,
      },
      relaysTestingAll: false,
      relaysTestingIds: [],
      relaysSpeedTestingAll: false,
      relaysSpeedTestingIds: [],
      campusChecking: false,
      campusResult: null,
      campusError: null,
      installingDriver: false,
      verifyingGlobal: false,
    },
    subs: {
      refreshingAll: false,
      refreshingIds: [],
      importing: false,
    },
    home: {
      checkingQuickSites: false,
      refreshingExitIp: false,
    },
    groups: {
      probingNodeIds: [],
      evaluatingGroupId: null,
      evalReports: {},
    },
    settings: {
      geoStatus: null,
      geoLoading: false,
      geoBusy: null,
      checkingUpdate: false,
      downloadingUpdate: false,
      updateInfo: null,
      updateMessage: null,
      coreOpBusy: null,
      backupBusy: null,
    },
    capture: {
      sessionId: null,
      active: false,
      timedOut: false,
      finishing: false,
      targetName: null,
      status: null,
      outcome: null,
    },
    probeActiveNodeIds: [],
    probeLockedOrderIds: [],
    probeIsPausing: false,
    probeLocalStarting: false,
  };
}

function createInitialSessionDrafts(): SessionDraftsState {
  return {
    scrollPositions: {},
    nodesWorkspace: {
      tab: "nodes",
      filterSubId: "",
    },
    preAccel: {
      selectedCompareNodeId: "",
    },
    speedTest: {
      searchQuery: "",
      sourceFilter: "all",
      groupFilter: "all",
      filterContinent: "all",
      regionFilter: "all",
      onlyGolden: false,
      onlyTested: false,
      onlyGoogleClean: false,
      onlyAiUnlocked: false,
      page: 1,
      selectedIds: [],
    },
    multiGroup: {
      selectedId: "",
      hasDirtyDrafts: false,
    },
    settings: {
      tab: "system",
      hasDirtyDrafts: false,
    },
    rulesConns: {
      connPaused: false,
      connSearch: "",
      ruleSearch: "",
    },
    home: {
      ipMasked: true,
    },
  };
}

let state: AppState = {
  initialized: false,
  isTauri: runningInTauri,
  windowMode: initialWindowMode,
  activeNav: detectNavFromHash(),
  aiRouteHint: null,
  settingsTabHint: null,
  settingsOpenAgentDocs: false,
  nodesTabHint: null,
  config: initialConfig,
  resolvedTheme: initialResolvedTheme,
  wallpaperPreviewUrl: null,
  wallpaperError: null,
  mascotState: "idle",
  runtime: initialRuntime,
  groups: [],
  nodes: [],
  probes: {},
  probeProgress: {
    running: false,
    completed: 0,
    total: 0,
    currentNodeName: null,
    cancelled: false,
  },
  lastProbeSummary: null,
  subscriptions: [],
  preAccelRelays: [],
  relayChainLatencies: {},
  globalPreAccel: { ...DEFAULT_GLOBAL_PREACCEL_STATUS },
  exitIp: initialExitIp,
  quickSites: [],
  latestTraffic: initialTraffic,
  trafficVersion: initialTrafficVersion,
  toast: null,
  onboardingModalOpen: false,
  onboardingAutoSkipped: false,
  tunAdminPromptOpen: false,
  tunAdminPromptBusy: false,
  tunAdminPromptReason: null,
  bgTasks: createInitialBgTasks(),
  sessionDrafts: createInitialSessionDrafts(),
};

const listeners = new Set<() => void>();
const trafficListeners = new Set<() => void>();

function emitState(): void {
  for (const fn of listeners) fn();
}

function emitTraffic(): void {
  for (const fn of trafficListeners) fn();
}

function setState(updater: (prev: AppState) => AppState): void {
  const next = updater(state);
  if (next === state) return;
  state = next;
  emitState();
}

function updateBgTasks(updater: (prev: BgTasksState) => BgTasksState): void {
  setState((prev) => {
    const nextBg = updater(prev.bgTasks);
    if (nextBg === prev.bgTasks) return prev;
    return { ...prev, bgTasks: nextBg };
  });
}

interface QueuedToastItem {
  text: string;
  tone: ToastNotice["tone"];
  durationMs: number;
}

let toastTimer: number | null = null;
let mascotResetTimer: number | null = null;
let toastSeq = 0;
let toastShownAt = 0;
let toastQueue: QueuedToastItem[] = [];

function showToastNow(item: QueuedToastItem): void {
  toastSeq += 1;
  const id = toastSeq;
  toastShownAt = Date.now();
  setState((prev) => ({ ...prev, toast: { id, text: item.text, tone: item.tone } }));
  if (toastTimer !== null) {
    window.clearTimeout(toastTimer);
  }
  toastTimer = window.setTimeout(() => {
    toastTimer = null;
    const nextQueued = toastQueue.shift();
    if (nextQueued) {
      showToastNow(nextQueued);
      return;
    }
    setState((prev) => (prev.toast?.id === id ? { ...prev, toast: null } : prev));
  }, item.durationMs);
}

function pushToast(
  text: string,
  tone: ToastNotice["tone"] = "info",
  durationMs = 3000
): void {
  const normalized = text.trim();
  if (!normalized) return;

  if (!state.toast || toastTimer === null) {
    showToastNow({ text: normalized, tone, durationMs });
    return;
  }

  // Deduplicate identical consecutive toast text
  if (
    state.toast.text === normalized ||
    (toastQueue.length > 0 && toastQueue[toastQueue.length - 1].text === normalized)
  ) {
    return;
  }

  const elapsed = Date.now() - toastShownAt;
  if (elapsed >= 1500) {
    // Current toast has already been readable long enough; show the new one right away
    toastQueue = [];
    showToastNow({ text: normalized, tone, durationMs });
    return;
  }

  // Brief anti-clobber queue when multiple background tasks finish almost simultaneously
  if (toastQueue.length >= 3) {
    const dropIdx = toastQueue.findIndex((item) => item.tone !== "warn");
    if (dropIdx >= 0) {
      toastQueue.splice(dropIdx, 1);
    } else {
      toastQueue.shift();
    }
  }
  toastQueue.push({ text: normalized, tone, durationMs });

  const remaining = Math.max(450, 1600 - elapsed);
  window.clearTimeout(toastTimer);
  const currentId = state.toast.id;
  toastTimer = window.setTimeout(() => {
    toastTimer = null;
    const nextQueued = toastQueue.shift();
    if (nextQueued) {
      showToastNow(nextQueued);
      return;
    }
    setState((prev) => (prev.toast?.id === currentId ? { ...prev, toast: null } : prev));
  }, remaining);
}

/* ============================================================================
 * Global Background Task Coordinator (In-Flight Dedupe, Mascot Ref-Count, Poll)
 * ============================================================================ */

const inFlightTasks = new Map<string, Promise<unknown>>();
let activeMascotTaskCount = 0;

function beginMascotBusy(mode: MascotState = "searching"): void {
  activeMascotTaskCount += 1;
  if (mascotResetTimer !== null) {
    window.clearTimeout(mascotResetTimer);
    mascotResetTimer = null;
  }
  setState((prev) => (prev.mascotState === mode ? prev : { ...prev, mascotState: mode }));
}

function celebrateMascotComplete(durationMs = 4000): void {
  if (activeMascotTaskCount > 0 || state.probeProgress.running) {
    return;
  }
  if (mascotResetTimer !== null) {
    window.clearTimeout(mascotResetTimer);
    mascotResetTimer = null;
  }
  setState((prev) =>
    prev.mascotState === "complete" ? prev : { ...prev, mascotState: "complete" }
  );
  if (typeof window !== "undefined") {
    mascotResetTimer = window.setTimeout(() => {
      mascotResetTimer = null;
      if (activeMascotTaskCount === 0 && !state.probeProgress.running) {
        setState((prev) =>
          prev.mascotState === "complete" ? { ...prev, mascotState: "idle" } : prev
        );
      }
    }, durationMs);
  }
}

function endMascotBusy(celebrate = false): void {
  activeMascotTaskCount = Math.max(0, activeMascotTaskCount - 1);
  if (activeMascotTaskCount === 0 && !state.probeProgress.running) {
    if (celebrate) {
      celebrateMascotComplete(4000);
      return;
    }
    setState((prev) =>
      prev.mascotState === "searching" ||
      prev.mascotState === "thinking" ||
      prev.mascotState === "typing"
        ? { ...prev, mascotState: "idle" }
        : prev
    );
  }
}

function runInFlight<T>(
  taskKey: string,
  runner: () => Promise<T>,
  options?: { mascot?: boolean | MascotState; celebrate?: boolean }
): Promise<T> {
  const existing = inFlightTasks.get(taskKey);
  if (existing) {
    return existing as Promise<T>;
  }
  const mascotOpt = options?.mascot ?? false;
  const mascotMode: MascotState | null =
    mascotOpt === true ? "searching" : mascotOpt === false ? null : mascotOpt;
  if (mascotMode) {
    beginMascotBusy(mascotMode);
  }
  let succeeded = false;
  const promise = Promise.resolve()
    .then(async () => {
      const res = await runner();
      succeeded = true;
      return res;
    })
    .finally(() => {
      if (inFlightTasks.get(taskKey) === promise) {
        inFlightTasks.delete(taskKey);
      }
      if (mascotMode) {
        endMascotBusy(Boolean(options?.celebrate && succeeded));
      }
    });
  inFlightTasks.set(taskKey, promise);
  return promise;
}

let probePauseRequested = false;
let probePendingQueue: string[] = [];
let previewProbeTimer: number | null = null;
let previewProbeCancelled = false;
let previewProbeFinishResolve: (() => void) | null = null;

function clearPreviewProbeTimer(): void {
  if (previewProbeTimer !== null) {
    window.clearTimeout(previewProbeTimer);
    previewProbeTimer = null;
  }
}

let liveCapturePollTimer: number | null = null;
let liveCapturePollInFlight = false;
let captureGen = 0;

function stopLiveCapturePolling(): void {
  if (liveCapturePollTimer !== null) {
    window.clearInterval(liveCapturePollTimer);
    liveCapturePollTimer = null;
  }
  liveCapturePollInFlight = false;
}

function startLiveCapturePolling(sessionId: string, expectedGen: number): void {
  stopLiveCapturePolling();
  let consecutiveFailures = 0;
  const pollOnce = () => {
    if (liveCapturePollInFlight) return;
    const currentCapture = state.bgTasks.capture;
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
        const latestCapture = state.bgTasks.capture;
        if (
          expectedGen !== captureGen ||
          !latestCapture.active ||
          latestCapture.sessionId !== sessionId
        ) {
          return;
        }
        const isTimedOutOrStopped =
          Boolean(latestStatus.timed_out) || !latestStatus.active;
        updateBgTasks((bg) => ({
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
        const latestCapture = state.bgTasks.capture;
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
          updateBgTasks((bg) => ({
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
          pushToast("捕捉会话已失效，请重新开始", "warn", 4200);
        }
      })
      .finally(() => {
        liveCapturePollInFlight = false;
      });
  };
  pollOnce();
  liveCapturePollTimer = window.setInterval(pollOnce, 600);
}

function hasRealExitIpInfo(info: ExitIpInfo): boolean {
  const masked = info.ip_masked?.trim() ?? "";
  return Boolean(masked && !masked.includes("--") && masked !== "待检测");
}

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

function buildReleasesFallbackUrl(repo: string): string {
  const cleanRepo = repo.trim().replace(/^\/+|\/+$/g, "");
  return `https://github.com/${cleanRepo || "JuryBu/CatCloud"}/releases`;
}

const PROBE_TIER_LABELS: Record<"latency" | "unlock" | "full", string> = {
  latency: "仅快测延迟",
  unlock: "测延迟 + 送中/AI",
  full: "含上下行完整测速",
};

let bootStarted = false;
let startupPageApplied = false;
let userNavigatedManually = false;
let personalizationReqSeq = 0;
let disposeTraffic: (() => void) | null = null;
let disposeRuntime: (() => void) | null = null;
let disposeProbeProgress: (() => void) | null = null;
let disposeStrategySwitch: (() => void) | null = null;
let disposeConfigUpdate: (() => void) | null = null;
let disposeTunNeedsAdmin: (() => void) | null = null;
let themeClockTimer: number | null = null;
let trafficBackfillInFlight = false;
let globalPreAccelRefreshInFlight = false;
let globalPreAccelRefreshPending = false;

function syncResolvedThemeFromClock(): void {
  const p = state.config.personalization;
  const resolved = resolveThemeBySchedule(p.theme_mode, p.theme_schedule);
  applyPersonalizationToDom(resolved, p, state.windowMode);
  if (resolved !== state.resolvedTheme) {
    setState((prev) => ({ ...prev, resolvedTheme: resolved }));
  }
}

async function backfillTrafficHistory(coreRunning: boolean): Promise<void> {
  if (!isTauriEnv() || !coreRunning || trafficBackfillInFlight) return;
  trafficBackfillInFlight = true;
  try {
    const history = await catcloudApi.getTrafficHistory();
    if (history.length === 0) return;

    const merged = new Map<number, { up: number; down: number; ts: number }>();
    for (const pt of history) {
      if (pt.timestamp_ms > 0) {
        merged.set(pt.timestamp_ms, {
          up: pt.up_bps,
          down: pt.down_bps,
          ts: pt.timestamp_ms,
        });
      }
    }
    const existingLen = trafficBuffer.length;
    for (let i = 0; i < existingLen; i++) {
      const ts = trafficBuffer.tsAt(i);
      if (ts > 0) {
        merged.set(ts, {
          up: trafficBuffer.upAt(i),
          down: trafficBuffer.downAt(i),
          ts,
        });
      }
    }
    const sorted = Array.from(merged.values()).sort((a, b) => a.ts - b.ts);
    const tailSlice =
      sorted.length > TRAFFIC_HISTORY_CAPACITY
        ? sorted.slice(sorted.length - TRAFFIC_HISTORY_CAPACITY)
        : sorted;
    trafficBuffer.clear();
    for (const pt of tailSlice) {
      trafficBuffer.push(pt.up, pt.down, pt.ts);
    }
    const lastHist = history[history.length - 1];
    const newest = tailSlice[tailSlice.length - 1];
    const hasNewerLive = state.latestTraffic.timestamp_ms > lastHist.timestamp_ms;
    state = {
      ...state,
      latestTraffic: hasNewerLive
        ? {
            ...state.latestTraffic,
            up_bps: newest ? newest.up : state.latestTraffic.up_bps,
            down_bps: newest ? newest.down : state.latestTraffic.down_bps,
            timestamp_ms: newest ? newest.ts : state.latestTraffic.timestamp_ms,
          }
        : {
            ...state.latestTraffic,
            up_bps: newest ? newest.up : lastHist.up_bps,
            down_bps: newest ? newest.down : lastHist.down_bps,
            up_total_bytes: lastHist.up_total_bytes || state.latestTraffic.up_total_bytes,
            down_total_bytes: lastHist.down_total_bytes || state.latestTraffic.down_total_bytes,
            connections: lastHist.connections,
            tunnel_connections: lastHist.tunnel_connections ?? 0,
            memory_mb: lastHist.memory_mb,
            timestamp_ms: newest ? newest.ts : lastHist.timestamp_ms,
          },
      trafficVersion: state.trafficVersion + 1,
    };
    emitTraffic();
  } catch {
    /* ignore optional history backfill failure on older backend */
  } finally {
    trafficBackfillInFlight = false;
  }
}

function handleHashChange(): void {
  const nextWindowMode = detectWindowModeFromLocation();
  const nextNav = detectNavFromHash();
  setState((prev) => ({
    ...prev,
    windowMode: nextWindowMode,
    activeNav: nextWindowMode === "main" ? nextNav : prev.activeNav,
  }));
  applyPersonalizationToDom(
    state.resolvedTheme,
    state.config.personalization,
    nextWindowMode
  );
}

function handleVisibilityChange(): void {
  if (document.visibilityState === "visible") {
    syncResolvedThemeFromClock();
    emitTraffic();
    if (isTauriEnv() && state.runtime.running) {
      void backfillTrafficHistory(true);
    }
  }
}

function handleStorageSync(ev: StorageEvent): void {
  if (ev.key !== UI_PREFS_STORAGE_KEY || !ev.newValue) return;
  try {
    const parsed = JSON.parse(ev.newValue) as Partial<AppConfig["personalization"]>;
    if (!parsed || typeof parsed !== "object") return;
    const nextPersonalization: AppConfig["personalization"] = {
      ...state.config.personalization,
      ...parsed,
      theme_schedule: parsed.theme_schedule
        ? { ...state.config.personalization.theme_schedule, ...parsed.theme_schedule }
        : state.config.personalization.theme_schedule,
    };
    const nextConfig: AppConfig = {
      ...state.config,
      personalization: nextPersonalization,
    };
    const resolved = resolveThemeBySchedule(
      nextPersonalization.theme_mode,
      nextPersonalization.theme_schedule
    );
    applyPersonalizationToDom(resolved, nextPersonalization, state.windowMode);
    setState((prev) => ({
      ...prev,
      config: nextConfig,
      resolvedTheme: resolved,
    }));
  } catch {
    /* ignore malformed storage sync payload */
  }
}

function mergeIncomingAppConfig(
  incoming: AppConfig,
  prev: AppConfig,
  fallbackAutoDownload?: boolean
): AppConfig {
  const autoDownload =
    typeof incoming.update?.auto_download === "boolean"
      ? incoming.update.auto_download
      : typeof fallbackAutoDownload === "boolean"
        ? fallbackAutoDownload
        : (prev.update.auto_download ?? true);
  return {
    ...incoming,
    behavior: incoming.behavior ?? prev.behavior,
    update: {
      ...incoming.update,
      auto_download: autoDownload,
    },
  };
}

function alignConfigWithRuntimeTun(config: AppConfig, runtime: CoreRuntimeInfo): AppConfig {
  if (
    typeof runtime.tun_configured === "boolean" &&
    config.tun_enabled !== runtime.tun_configured
  ) {
    return { ...config, tun_enabled: runtime.tun_configured };
  }
  return config;
}

async function hydrateFromBackend(): Promise<void> {
  const inDesktop = isTauriEnv();
  // Never fire outbound network requests (exit IP / site checks) on startup in desktop mode
  // so launching the app consumes 0 B of unexpected traffic until the user explicitly requests a check.
  const results = await Promise.allSettled([
    catcloudApi.getConfig(),
    catcloudApi.getRuntimeInfo(),
    catcloudApi.listGroups(),
    catcloudApi.listNodes(),
    catcloudApi.listProbeSnapshots(),
    catcloudApi.listSubscriptions(),
    catcloudApi.listPreAccelRelays(),
    catcloudApi.getFullConfig(),
    catcloudApi.getGlobalPreAccelStatus(),
    inDesktop ? Promise.resolve(null) : catcloudApi.getExitIpInfo(),
    inDesktop ? Promise.resolve(null) : catcloudApi.checkQuickSites(),
  ]);

  const [
    cfgRes,
    runtimeRes,
    groupsRes,
    nodesRes,
    probesRes,
    subsRes,
    relaysRes,
    fullCfgRes,
    globalPreAccelRes,
    exitIpRes,
    quickSitesRes,
  ] = results;

  const cfg = cfgRes.status === "fulfilled" ? cfgRes.value : state.config;
  const hydratedAutoDownload =
    typeof cfg.update?.auto_download === "boolean"
      ? cfg.update.auto_download
      : fullCfgRes.status === "fulfilled" &&
          typeof fullCfgRes.value?.update?.auto_download === "boolean"
        ? fullCfgRes.value.update.auto_download
        : (state.config.update.auto_download ?? true);
  const hydratedMinimizeToTray =
    fullCfgRes.status === "fulfilled" &&
    fullCfgRes.value?.behavior?.minimize_to_tray_on_close !== undefined
      ? fullCfgRes.value.behavior.minimize_to_tray_on_close
      : (cfg.behavior?.minimize_to_tray_on_close ??
        state.config.behavior?.minimize_to_tray_on_close ??
        true);
  const mergedConfig: AppConfig = inDesktop
    ? {
        ...cfg,
        behavior: {
          ...cfg.behavior,
          minimize_to_tray_on_close: hydratedMinimizeToTray,
        },
        update: {
          ...cfg.update,
          auto_download: hydratedAutoDownload,
        },
      }
    : {
        ...cfg,
        behavior: {
          ...cfg.behavior,
          minimize_to_tray_on_close: hydratedMinimizeToTray,
        },
        update: {
          ...cfg.update,
          auto_download: hydratedAutoDownload,
        },
        personalization: {
          ...cfg.personalization,
          ...loadCachedUiPrefs(),
        },
      };

  const resolved = resolveThemeBySchedule(
    mergedConfig.personalization.theme_mode,
    mergedConfig.personalization.theme_schedule
  );
  applyPersonalizationToDom(resolved, mergedConfig.personalization, state.windowMode);
  if (state.windowMode !== "capsule") {
    void ensureLocalWallpaperLoaded(
      mergedConfig.personalization.wallpaper_path,
      resolved,
      mergedConfig.personalization,
      state.windowMode
    );
  }

  let hydratedSites: SiteCheckItem[] = state.quickSites;
  if (!inDesktop && quickSitesRes.status === "fulfilled" && Array.isArray(quickSitesRes.value)) {
    hydratedSites = quickSitesRes.value;
  } else if (
    inDesktop &&
    fullCfgRes.status === "fulfilled" &&
    fullCfgRes.value &&
    Array.isArray(fullCfgRes.value.core_runtime?.quick_check_sites)
  ) {
    const existingById = new Map(state.quickSites.map((s) => [s.id, s]));
    hydratedSites = fullCfgRes.value.core_runtime.quick_check_sites.map((s) => {
      const prev = existingById.get(s.id);
      return {
        id: s.id,
        name: s.name,
        url: s.url,
        latency_ms: prev?.latency_ms ?? null,
        ok: prev?.ok ?? null,
      };
    });
  }

  let startupNav: NavRouteId | null = null;
  if (
    !startupPageApplied &&
    !userNavigatedManually &&
    state.windowMode === "main" &&
    !hasExplicitRouteHash() &&
    fullCfgRes.status === "fulfilled" &&
    fullCfgRes.value
  ) {
    const rawStartup = fullCfgRes.value.behavior?.startup_page?.trim().toLowerCase();
    const mappedStartup = rawStartup === "speedtest" ? "nodes" : rawStartup;
    if (mappedStartup && VALID_ROUTES.has(mappedStartup as NavRouteId)) {
      startupNav = mappedStartup as NavRouteId;
    }
  }
  startupPageApplied = true;

  const resolvedRuntime = runtimeRes.status === "fulfilled" ? runtimeRes.value : state.runtime;

  // Backfill up to 10 minutes of buffered 1Hz telemetry from CoreTelemetryStore whenever the
  // main window opens/reopens while the core is running. Merge by timestamp_ms so early live
  // ticks arriving via `subscribeTraffic` before IPC returns never cause history to be dropped.
  if (inDesktop && resolvedRuntime.running) {
    await backfillTrafficHistory(true);
  }

  const resolvedGroups = groupsRes.status === "fulfilled" ? groupsRes.value : state.groups;
  const resolvedNodes = nodesRes.status === "fulfilled" ? nodesRes.value : state.nodes;
  const resolvedSubs = subsRes.status === "fulfilled" ? subsRes.value : state.subscriptions;
  const resolvedRelays = relaysRes.status === "fulfilled" ? relaysRes.value : state.preAccelRelays;
  const hasExistingUserData =
    resolvedNodes.length > 0 ||
    resolvedSubs.length > 0 ||
    resolvedRelays.length > 0 ||
    resolvedGroups.length > 0;
  const forcePreviewOnboarding =
    !inDesktop &&
    typeof window !== "undefined" &&
    new URLSearchParams(window.location.search).get("onboarding") === "1";
  const alreadyCompletedOnboarding = mergedConfig.personalization.onboarding_completed === true;
  const shouldAutoSkipOnboarding =
    !forcePreviewOnboarding && !alreadyCompletedOnboarding && hasExistingUserData;

  setState((prev) => ({
    ...prev,
    initialized: true,
    activeNav: startupNav ?? prev.activeNav,
    config: alignConfigWithRuntimeTun(mergedConfig, resolvedRuntime),
    resolvedTheme: resolved,
    runtime: resolvedRuntime,
    groups: resolvedGroups,
    nodes: resolvedNodes,
    probes: probesRes.status === "fulfilled" ? probesRes.value : prev.probes,
    subscriptions: resolvedSubs,
    preAccelRelays: resolvedRelays,
    globalPreAccel:
      globalPreAccelRes.status === "fulfilled"
        ? globalPreAccelRes.value
        : prev.globalPreAccel,
    exitIp:
      !inDesktop && exitIpRes.status === "fulfilled" && exitIpRes.value
        ? exitIpRes.value
        : prev.exitIp,
    quickSites: hydratedSites,
    onboardingAutoSkipped: prev.onboardingAutoSkipped || shouldAutoSkipOnboarding,
    onboardingModalOpen: prev.onboardingModalOpen || forcePreviewOnboarding,
  }));
}

export const appStore = {
  getState(): AppState {
    return state;
  },

  getTrafficBuffer(): TrafficRingBuffer {
    return trafficBuffer;
  },

  getTrafficVersion(): number {
    return state.trafficVersion;
  },

  subscribe(listener: () => void): () => void {
    listeners.add(listener);
    return () => listeners.delete(listener);
  },

  subscribeTraffic(listener: () => void): () => void {
    trafficListeners.add(listener);
    return () => trafficListeners.delete(listener);
  },

  init(): void {
    if (bootStarted) return;
    bootStarted = true;

    applyPersonalizationToDom(
      state.resolvedTheme,
      state.config.personalization,
      state.windowMode
    );

    if (typeof window !== "undefined") {
      window.addEventListener("hashchange", handleHashChange);
      window.addEventListener("storage", handleStorageSync);
      document.addEventListener("visibilitychange", handleVisibilityChange);

      themeClockTimer = window.setInterval(() => {
        if (
          document.visibilityState === "visible" &&
          state.config.personalization.theme_mode === "auto_time"
        ) {
          syncResolvedThemeFromClock();
        }
      }, 30_000);
    }

    disposeTraffic = catcloudApi.subscribeTraffic((sample) => {
      trafficBuffer.push(sample.up_bps, sample.down_bps, sample.timestamp_ms);
      state = {
        ...state,
        latestTraffic: sample,
        trafficVersion: state.trafficVersion + 1,
      };
      if (typeof document === "undefined" || document.visibilityState === "visible") {
        emitTraffic();
      }
    });

    disposeRuntime = catcloudApi.subscribeRuntimeUpdate((info) => {
      const wasRunning = state.runtime.running;
      if (wasRunning && !info.running) {
        // Core stopped: append a clean 0 B/s landing sample & zero live speeds so curve drops naturally
        const stopTs = Date.now();
        if (trafficBuffer.length > 0) {
          trafficBuffer.push(0, 0, stopTs);
        }
        state = {
          ...state,
          latestTraffic: {
            ...state.latestTraffic,
            up_bps: 0,
            down_bps: 0,
            connections: 0,
            tunnel_connections: 0,
            memory_mb: 0,
            timestamp_ms: stopTs,
          },
          trafficVersion: state.trafficVersion + 1,
        };
        emitTraffic();
      } else if (!wasRunning && info.running) {
        // Fresh core session started: clear previous session's stale buffer so new timeline starts clean
        trafficBuffer.clear();
        state = {
          ...state,
          latestTraffic: { ...EMPTY_TRAFFIC, timestamp_ms: Date.now() },
          trafficVersion: state.trafficVersion + 1,
        };
        emitTraffic();
      }
      const globalStateChanged =
        info.global_preaccel_active !== state.runtime.global_preaccel_active ||
        info.global_windivert_active !== state.runtime.global_windivert_active ||
        info.global_preaccel_mode !== state.runtime.global_preaccel_mode ||
        info.global_preaccel_socks_port !== state.runtime.global_preaccel_socks_port ||
        info.preaccel_install_state !== state.runtime.preaccel_install_state ||
        info.global_preaccel_verify_state !== state.runtime.global_preaccel_verify_state ||
        info.global_preaccel_verify_ms !== state.runtime.global_preaccel_verify_ms;
      const hasGlobalRuntimePatch =
        info.global_preaccel_active !== undefined ||
        info.global_windivert_active !== undefined ||
        info.global_preaccel_mode !== undefined ||
        info.global_preaccel_socks_port !== undefined ||
        info.global_preaccel_connections !== undefined ||
        info.preaccel_install_state !== undefined ||
        info.global_preaccel_verify_state !== undefined ||
        info.global_preaccel_verify_ms !== undefined;
      setState((prev) => {
        const nextRunning = info.global_preaccel_active ?? prev.globalPreAccel.running;
        const nextMode = info.global_preaccel_mode ?? prev.globalPreAccel.mode;
        const nextWinDivertActive =
          info.global_windivert_active !== undefined
            ? Boolean(info.global_windivert_active)
            : Boolean(nextRunning && nextMode === "windivert");
        const nextInstallState =
          info.preaccel_install_state !== undefined
            ? normalizePreAccelInstallState(info.preaccel_install_state)
            : prev.globalPreAccel.install_state;
        const nextVerifyState =
          info.global_preaccel_verify_state !== undefined
            ? normalizePreAccelVerifyState(info.global_preaccel_verify_state)
            : (prev.globalPreAccel.verify_state ?? "idle");
        const nextVerifyMs =
          info.global_preaccel_verify_ms !== undefined
            ? info.global_preaccel_verify_ms
            : (prev.globalPreAccel.verify_latency_ms ?? null);
        const nextTunConfigured =
          typeof info.tun_configured === "boolean"
            ? info.tun_configured
            : prev.runtime.tun_configured;
        const nextTunNeedsElevation =
          typeof info.tun_needs_elevation === "boolean"
            ? info.tun_needs_elevation
            : typeof nextTunConfigured === "boolean"
              ? nextTunConfigured && !info.tun_admin_ready
              : prev.runtime.tun_needs_elevation;
        return {
          ...prev,
          config: alignConfigWithRuntimeTun(prev.config, info),
          runtime: {
            ...info,
            tun_configured: nextTunConfigured,
            tun_needs_elevation: nextTunNeedsElevation,
            global_windivert_active: nextWinDivertActive,
            preaccel_install_state:
              info.preaccel_install_state ?? prev.runtime.preaccel_install_state,
            global_preaccel_verify_state:
              info.global_preaccel_verify_state ?? prev.runtime.global_preaccel_verify_state,
            global_preaccel_verify_ms:
              info.global_preaccel_verify_ms !== undefined
                ? info.global_preaccel_verify_ms
                : prev.runtime.global_preaccel_verify_ms,
            preaccel_effective_carrier:
              info.preaccel_effective_carrier ?? prev.runtime.preaccel_effective_carrier,
            standalone_tunnel_suspended_for_tun:
              info.standalone_tunnel_suspended_for_tun !== undefined
                ? info.standalone_tunnel_suspended_for_tun
                : prev.runtime.standalone_tunnel_suspended_for_tun,
            dns_tls_diagnostics:
              info.dns_tls_diagnostics !== undefined
                ? info.dns_tls_diagnostics
                : prev.runtime.dns_tls_diagnostics,
            node_health_hints: info.node_health_hints ?? prev.runtime.node_health_hints,
          },
          globalPreAccel: hasGlobalRuntimePatch
            ? {
                ...prev.globalPreAccel,
                running: nextRunning,
                mode: nextMode,
                is_windivert_active: nextWinDivertActive,
                install_state: nextInstallState,
                verify_state: nextVerifyState,
                verify_latency_ms: nextVerifyMs,
                socks_port:
                  info.global_preaccel_socks_port !== undefined
                    ? info.global_preaccel_socks_port
                    : prev.globalPreAccel.socks_port,
                active_connections:
                  info.global_preaccel_connections ?? prev.globalPreAccel.active_connections,
                process_stats: nextRunning ? prev.globalPreAccel.process_stats : [],
                accelerated_processes: nextRunning
                  ? prev.globalPreAccel.accelerated_processes
                  : [],
              }
            : prev.globalPreAccel,
        };
      });
      if (globalStateChanged && isTauriEnv() && state.windowMode === "main") {
        void appActions.refreshGlobalPreAccelStatus();
      }
    });

    disposeProbeProgress = catcloudApi.subscribeProbeProgress((ev) => {
      if (ev.done) {
        probePendingQueue = [];
      } else if (ev.node_id && (ev.snapshot || ev.error)) {
        probePendingQueue = probePendingQueue.filter((id) => id !== ev.node_id);
      }

      setState((prev) => {
        const nextProbes =
          ev.node_id && ev.snapshot
            ? {
                ...prev.probes,
                [ev.node_id]: mergeProbeSnapshotSafe(prev.probes[ev.node_id], ev.snapshot),
              }
            : prev.probes;

        let nextActiveNodeIds: string[];
        if (ev.done) {
          nextActiveNodeIds = [];
        } else if (probePendingQueue.length > 0) {
          nextActiveNodeIds = probePendingQueue.slice(0, 4);
        } else if (ev.node_id) {
          nextActiveNodeIds = ev.snapshot || ev.error ? [] : [ev.node_id];
        } else {
          nextActiveNodeIds = prev.bgTasks.probeActiveNodeIds;
        }

        const nextMascot: MascotState = ev.done
          ? activeMascotTaskCount > 0
            ? prev.mascotState
            : ev.cancelled
              ? "idle"
              : "complete"
          : "searching";

        const hasEventSummary =
          ev.latency_ok_count !== undefined ||
          ev.bandwidth_ok_count !== undefined ||
          ev.keepalive_ok_count !== undefined ||
          ev.failed_count !== undefined ||
          ev.exec_error_count !== undefined ||
          ev.untested_count !== undefined;
        const nextLastProbeSummary: ProbeRunSummary | null = hasEventSummary
          ? {
              latency_ok_count: ev.latency_ok_count ?? prev.lastProbeSummary?.latency_ok_count ?? 0,
              bandwidth_ok_count:
                ev.bandwidth_ok_count ?? prev.lastProbeSummary?.bandwidth_ok_count ?? 0,
              keepalive_ok_count:
                ev.keepalive_ok_count ?? prev.lastProbeSummary?.keepalive_ok_count ?? 0,
              failed_count: ev.failed_count ?? prev.lastProbeSummary?.failed_count ?? 0,
              exec_error_count: ev.exec_error_count ?? prev.lastProbeSummary?.exec_error_count ?? 0,
              untested_count: ev.untested_count ?? prev.lastProbeSummary?.untested_count ?? 0,
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
      if (ev.done && !ev.cancelled && activeMascotTaskCount === 0) {
        celebrateMascotComplete(4000);
      }
    });

    disposeStrategySwitch = catcloudApi.subscribeStrategySwitch((ev) => {
      const groupLabel = ev.group_name?.trim() || "当前多选组";
      const toLabel = ev.to_node?.trim() || "最优节点";
      const reasonText = ev.reason?.trim();
      const fromLabel = ev.from_node?.trim();
      const detail = reasonText
        ? reasonText
        : fromLabel
          ? `原节点 ${fromLabel} 异常`
          : "检测到原节点异常";

      pushToast(
        `智能策略已生效：「${groupLabel}」${detail}，已自动切换至 ${toLabel}`,
        "info",
        5000
      );

      void Promise.allSettled([
        catcloudApi.getRuntimeInfo(),
        catcloudApi.listGroups(),
      ]).then(([rtRes, groupsRes]) => {
        if (!bootStarted) return;
        setState((prev) => {
          const nextRuntime = rtRes.status === "fulfilled" ? rtRes.value : prev.runtime;
          const nextGroups = groupsRes.status === "fulfilled" ? groupsRes.value : prev.groups;
          const activeNodeChanged =
            nextRuntime.active_node_id !== prev.runtime.active_node_id;
          return {
            ...prev,
            runtime: nextRuntime,
            groups: nextGroups,
            exitIp: activeNodeChanged
              ? buildPendingExitIp(nextRuntime.running)
              : prev.exitIp,
          };
        });
      });
    });

    disposeConfigUpdate = catcloudApi.subscribeConfigUpdate((incomingCfg) => {
      const mergedConfig = mergeIncomingAppConfig(incomingCfg, state.config);
      const resolved = resolveThemeBySchedule(
        mergedConfig.personalization.theme_mode,
        mergedConfig.personalization.theme_schedule
      );
      saveCachedUiPrefs(mergedConfig.personalization);
      applyPersonalizationToDom(resolved, mergedConfig.personalization, state.windowMode);
      if (state.windowMode !== "capsule") {
        void ensureLocalWallpaperLoaded(
          mergedConfig.personalization.wallpaper_path,
          resolved,
          mergedConfig.personalization,
          state.windowMode
        );
      }
      const prevPreAccel = state.config.preaccel;
      const preAccelChanged =
        mergedConfig.preaccel.enabled !== prevPreAccel.enabled ||
        mergedConfig.preaccel.global_bypass_enabled !== prevPreAccel.global_bypass_enabled ||
        mergedConfig.preaccel.global_scope !== prevPreAccel.global_scope;
      setState((prev) => ({
        ...prev,
        config: mergedConfig,
        resolvedTheme: resolved,
      }));
      if (preAccelChanged && isTauriEnv() && state.windowMode === "main") {
        void appActions.refreshGlobalPreAccelStatus();
      }
    });

    if (isTauriEnv()) {
      let tunAdminDisposed = false;
      let tunAdminUnlisten: (() => void) | null = null;
      void import("@tauri-apps/api/event")
        .then(({ listen }) =>
          listen<unknown>("catcloud://tun-needs-admin", (ev) => {
            if (tunAdminDisposed || state.windowMode === "capsule") return;
            const payload = ev.payload;
            let rawReason: string | null = null;
            if (typeof payload === "string") {
              rawReason = payload;
            } else if (payload && typeof payload === "object") {
              const rec = payload as { reason?: unknown; message?: unknown };
              if (typeof rec.reason === "string") rawReason = rec.reason;
              else if (typeof rec.message === "string") rawReason = rec.message;
            }
            if (rawReason) {
              const prefix = "NEEDS_ADMIN:";
              const idx = rawReason.indexOf(prefix);
              if (idx >= 0) {
                rawReason = rawReason.slice(idx + prefix.length).trim() || null;
              }
            }
            setState((prev) => {
              const configured = Boolean(prev.runtime.tun_configured ?? prev.config.tun_enabled);
              return {
                ...prev,
                runtime: {
                  ...prev.runtime,
                  tun_admin_ready: false,
                  tun_enabled: false,
                  tun_needs_elevation: configured,
                },
              };
            });
            appActions.openTunAdminPrompt(rawReason);
          })
        )
        .then((unlisten) => {
          if (tunAdminDisposed) {
            unlisten();
          } else {
            tunAdminUnlisten = unlisten;
          }
        })
        .catch(() => {
          /* ignore event listener setup errors outside desktop runtime */
        });
      disposeTunNeedsAdmin = () => {
        tunAdminDisposed = true;
        tunAdminUnlisten?.();
        tunAdminUnlisten = null;
      };
    }

    void hydrateFromBackend().catch((err) => {
      setState((prev) => ({ ...prev, initialized: true }));
      if (isTauriEnv()) {
        pushToast(`初始化状态同步失败：${formatErrorMessage(err)}`, "warn");
      }
    });
  },

  dispose(): void {
    disposeTraffic?.();
    disposeTraffic = null;
    disposeRuntime?.();
    disposeRuntime = null;
    disposeProbeProgress?.();
    disposeProbeProgress = null;
    disposeStrategySwitch?.();
    disposeStrategySwitch = null;
    disposeConfigUpdate?.();
    disposeConfigUpdate = null;
    disposeTunNeedsAdmin?.();
    disposeTunNeedsAdmin = null;
    if (typeof window !== "undefined") {
      window.removeEventListener("hashchange", handleHashChange);
      window.removeEventListener("storage", handleStorageSync);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    }
    if (themeClockTimer !== null) {
      window.clearInterval(themeClockTimer);
      themeClockTimer = null;
    }
    if (toastTimer !== null) {
      window.clearTimeout(toastTimer);
      toastTimer = null;
    }
    if (mascotResetTimer !== null) {
      window.clearTimeout(mascotResetTimer);
      mascotResetTimer = null;
    }
    clearPreviewProbeTimer();
    previewProbeCancelled = true;
    previewProbeFinishResolve?.();
    previewProbeFinishResolve = null;
    captureGen += 1;
    stopLiveCapturePolling();
    globalPreAccelRefreshPending = false;
    toastQueue = [];
    inFlightTasks.clear();
    probePendingQueue = [];
    probePauseRequested = false;
    activeMascotTaskCount = 0;
    bootStarted = false;
    startupPageApplied = false;
    userNavigatedManually = false;
  },
};

export const appActions = {
  setNav(nav: NavRouteId): void {
    const normalized: NavRouteId = nav === "speedtest" ? "nodes" : nav;
    userNavigatedManually = true;
    if (typeof window !== "undefined" && state.windowMode === "main") {
      const targetHash = `#${normalized}`;
      if (window.location.hash !== targetHash) {
        window.history.replaceState(null, "", targetHash);
      }
    }
    setState((prev) => (prev.activeNav === normalized ? prev : { ...prev, activeNav: normalized }));
  },

  openNodesWorkspace(
    tab: "nodes" | "subs" = "nodes",
    subId?: string | null,
    action?: "migration" | null
  ): void {
    setState((prev) => ({
      ...prev,
      nodesTabHint: { tab, subId: subId ?? null, action: action ?? null },
      sessionDrafts: {
        ...prev.sessionDrafts,
        nodesWorkspace: {
          tab,
          filterSubId: subId ?? "",
        },
      },
    }));
    appActions.setNav("nodes");
  },

  consumeNodesTabHint(): void {
    setState((prev) => (prev.nodesTabHint === null ? prev : { ...prev, nodesTabHint: null }));
  },

  openSettingsTab(tab: "system" | "appearance" | "dns" | "core" | "updates"): void {
    setState((prev) => ({ ...prev, settingsTabHint: tab }));
    appActions.setNav("settings");
  },

  consumeSettingsTabHint(): void {
    setState((prev) => (prev.settingsTabHint === null ? prev : { ...prev, settingsTabHint: null }));
  },

  openSettingsAgentDocs(moduleId?: string): void {
    appActions.openAiAssistant(moduleId, "web");
  },

  openAiAssistant(moduleId?: string, tab?: "web" | "agent"): void {
    setState((prev) => ({
      ...prev,
      aiRouteHint: moduleId || tab ? { moduleId, tab } : prev.aiRouteHint,
    }));
    appActions.setNav("ai");
  },

  consumeAiRouteHint(): void {
    setState((prev) => (prev.aiRouteHint === null ? prev : { ...prev, aiRouteHint: null }));
  },

  consumeSettingsOpenAgentDocs(): void {
    setState((prev) =>
      prev.settingsOpenAgentDocs ? { ...prev, settingsOpenAgentDocs: false } : prev
    );
  },

  async setUiLanguage(lang: UiLanguage): Promise<void> {
    const normalized = normalizeUiLanguage(lang);
    await ensureUiLocaleLoaded(normalized);
    const labelMap: Record<UiLanguage, string> = {
      "zh-CN": "简体中文",
      en: "English",
      ja: "日本語",
      ru: "Русский",
    };
    await appActions.updatePersonalization(
      { ui_language: normalized },
      `界面语言已切换为 ${labelMap[normalized]}`
    );
  },

  async copyAiOnboardingForUser(lang?: UiLanguage, moduleId?: string | null): Promise<boolean> {
    const writeClipboard = async (text: string): Promise<boolean> => {
      try {
        if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
          await navigator.clipboard.writeText(text);
          return true;
        }
      } catch {
        /* fallback to textarea execCommand */
      }
      if (typeof document === "undefined") return false;
      try {
        const el = document.createElement("textarea");
        el.value = text;
        el.style.position = "fixed";
        el.style.left = "-9999px";
        el.style.opacity = "0";
        document.body.appendChild(el);
        el.select();
        const ok = document.execCommand("copy");
        document.body.removeChild(el);
        return ok;
      } catch {
        return false;
      }
    };

    try {
      const targetLang = normalizeUiLanguage(lang ?? state.config.personalization.ui_language);
      const prompt = await catcloudApi.buildAiOnboardingPrompt(targetLang, moduleId ?? null);
      const text = prompt.trim();
      if (!text) {
        pushToast("新手上手指南生成为空，请稍后重试", "warn");
        return false;
      }
      const copied = await writeClipboard(text);
      if (copied) {
        pushToast(
          "已复制网页 AI 指南与当前脱敏进度，直接粘贴给 DeepSeek / 豆包 / ChatGPT 就能一步步带你操作",
          "ok",
          5000
        );
        return true;
      }
      pushToast("无法写入剪贴板，请检查系统剪贴板权限后重试", "warn");
      return false;
    } catch (err) {
      pushToast(`生成 AI 上手指南失败：${formatErrorMessage(err)}`, "warn");
      return false;
    }
  },

  openOnboardingModal(): void {
    setState((prev) => (prev.onboardingModalOpen ? prev : { ...prev, onboardingModalOpen: true }));
  },

  async closeOnboardingModal(markCompleted = true): Promise<void> {
    setState((prev) => ({
      ...prev,
      onboardingModalOpen: false,
      onboardingAutoSkipped: prev.onboardingAutoSkipped || markCompleted,
    }));
    if (markCompleted && state.config.personalization.onboarding_completed !== true) {
      await appActions.updatePersonalization({ onboarding_completed: true });
    }
  },

  async copyAgentBootstrapPrompt(
    langOrPage?: UiLanguage | string,
    mode: AgentPromptMode = "autopilot",
    explicitLang?: UiLanguage
  ): Promise<boolean> {
    const writeClipboard = async (text: string): Promise<boolean> => {
      try {
        if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
          await navigator.clipboard.writeText(text);
          return true;
        }
      } catch {
        /* fallback */
      }
      if (typeof document === "undefined") return false;
      try {
        const el = document.createElement("textarea");
        el.value = text;
        el.style.position = "fixed";
        el.style.left = "-9999px";
        el.style.opacity = "0";
        document.body.appendChild(el);
        el.select();
        const ok = document.execCommand("copy");
        document.body.removeChild(el);
        return ok;
      } catch {
        return false;
      }
    };

    try {
      const knownLangs = new Set(["zh-CN", "en", "ja", "ru"]);
      const isLangArg = typeof langOrPage === "string" && knownLangs.has(langOrPage);
      const targetLang = normalizeUiLanguage(
        explicitLang ??
          (isLangArg ? (langOrPage as UiLanguage) : state.config.personalization.ui_language)
      );
      const targetPage =
        !isLangArg && typeof langOrPage === "string" && langOrPage.trim().length > 0
          ? langOrPage.trim()
          : state.activeNav;
      const resolvedMode: AgentPromptMode = mode === "readonly" ? "readonly" : "autopilot";
      const dto = await catcloudApi.buildAgentBootstrapPrompt(targetLang, targetPage, resolvedMode);
      const text = dto.prompt.trim();
      if (!text) {
        pushToast("本机 Agent 引导语生成为空，请稍后重试", "warn");
        return false;
      }
      const copied = await writeClipboard(text);
      if (copied) {
        pushToast(
          resolvedMode === "readonly"
            ? "已复制只读体检指令（仅查不改），直接粘贴发给 Codex / Claude Code / Antigravity 即可"
            : "已复制本机 AI 全权托管指令（含精确 CLI 路径与手册索引），直接粘贴发给 Codex / Claude Code / Antigravity 即可开始代配",
          "ok",
          5400
        );
        return true;
      }
      pushToast("无法写入剪贴板，请检查剪贴板权限后重试", "warn");
      return false;
    } catch (err) {
      pushToast(`生成本机 Agent 引导指令失败：${formatErrorMessage(err)}`, "warn");
      return false;
    }
  },

  async openGithubIssueFeedback(summary?: string | null): Promise<boolean> {
    try {
      const targetLang = normalizeUiLanguage(state.config.personalization.ui_language);
      const draft = await catcloudApi.buildGithubIssueUrl(summary ?? null, targetLang);
      let copied = false;
      if (draft.clipboard_markdown.trim()) {
        try {
          if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
            await navigator.clipboard.writeText(draft.clipboard_markdown);
            copied = true;
          }
        } catch {
          copied = false;
        }
        if (!copied && typeof document !== "undefined") {
          try {
            const el = document.createElement("textarea");
            el.value = draft.clipboard_markdown;
            el.style.position = "fixed";
            el.style.left = "-9999px";
            el.style.opacity = "0";
            document.body.appendChild(el);
            el.select();
            copied = document.execCommand("copy");
            document.body.removeChild(el);
          } catch {
            copied = false;
          }
        }
      }
      await catcloudApi.openExternalUrl(draft.issue_url);
      pushToast(
        copied
          ? "已打开 GitHub 反馈页，并自动复制了脱敏环境摘要（到页面内按 Ctrl+V 粘贴即可）"
          : "已打开 GitHub 反馈页，请按模板填写遇到的问题",
        "ok",
        5200
      );
      return true;
    } catch (err) {
      pushToast(`打开 GitHub 反馈页失败：${formatErrorMessage(err)}`, "warn");
      return false;
    }
  },

  async copySanitizedDiagnosticsForAi(extraSanitizedLogs?: string): Promise<boolean> {
    const writeClipboard = async (text: string): Promise<boolean> => {
      try {
        if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
          await navigator.clipboard.writeText(text);
          return true;
        }
      } catch {
        /* fallback to textarea execCommand */
      }
      if (typeof document === "undefined") return false;
      try {
        const el = document.createElement("textarea");
        el.value = text;
        el.style.position = "fixed";
        el.style.left = "-9999px";
        el.style.opacity = "0";
        document.body.appendChild(el);
        el.select();
        const ok = document.execCommand("copy");
        document.body.removeChild(el);
        return ok;
      } catch {
        return false;
      }
    };

    try {
      const diag = await catcloudApi.exportSanitizedDiagnostics();
      const rawMd =
        typeof diag.ai_prompt_markdown === "string" ? diag.ai_prompt_markdown.trim() : "";

      let markdown: string;
      if (rawMd.length > 0) {
        markdown = rawMd;
      } else {
        const rt = state.runtime;
        const cfg = state.config;
        const routeLine =
          rt.route_mode === "single"
            ? `单节点模式 → ${rt.active_node_name || "--"}`
            : `智能多选组（${rt.active_group_name || "--"}）→ ${rt.active_node_name || "--"}`;
        const tunStatusLabel = rt.tun_enabled
          ? "已开启"
          : rt.tun_needs_elevation
            ? "未生效（需管理员权限）"
            : "未开启";
        markdown = [
          "# 请帮我排查猫猫云梯（CatCloud）当前问题",
          "",
          "> 以下信息已自动脱敏（不含真实密钥、账号、用户名和公网 IP）。请根据状态与日志帮我分析原因并给出排查/配置建议。",
          "",
          "## 1. 运行状态摘要",
          `- 版本：v${rt.app_version}（${rt.os_label}）`,
          `- 代理核心：${rt.core_name} ${rt.core_version}（${rt.running ? "运行中" : "已停止"}）`,
          `- 代理模式：${rt.proxy_mode} | 系统代理：${rt.system_proxy_enabled ? "已开启" : "未开启"} | 虚拟网卡：${tunStatusLabel}`,
          `- 当前路线：${routeLine}`,
          `- 国内提速：${rt.preaccel_active ? `已开启（${rt.preaccel_relay_name ?? "已启用中转"}）` : "未开启"}`,
          `- 本地端口：混合 ${cfg.mixed_port} / 控制 127.0.0.1:${cfg.controller_port} / DNS ${cfg.dns_listen_port}`,
          "",
          "## 2. 本机只读排查 CLI 命令",
          "- `catcloud status --json`",
          "- `catcloud config diag --json`",
          "- `catcloud group list --json`",
          "- `catcloud config validate --json`",
          "",
          "## 3. 脱敏诊断快照（JSON）",
          "```json",
          JSON.stringify(diag, null, 2),
          "```",
        ].join("\n");
      }

      const trimmedExtra = extraSanitizedLogs?.trim();
      if (trimmedExtra) {
        markdown = `${markdown}\n\n## 当前日志视图补充（已自动打码隐私）\n\`\`\`text\n${trimmedExtra}\n\`\`\``;
      }

      const copied = await writeClipboard(markdown);
      if (copied) {
        pushToast(
          "已复制脱敏诊断包！直接粘贴给你的 AI 助手（Antigravity / Codex / ChatGPT 等）就能帮你排查",
          "ok",
          4500
        );
        return true;
      }
      pushToast("无法写入剪贴板，请在「运行日志」页点击导出或检查剪贴板权限", "warn");
      return false;
    } catch (err) {
      pushToast(`生成脱敏诊断包失败：${formatErrorMessage(err)}`, "warn");
      return false;
    }
  },

  setMascotState(next: MascotState): void {
    if (next === "idle" && (activeMascotTaskCount > 0 || state.probeProgress.running)) {
      return;
    }
    setState((prev) => (prev.mascotState === next ? prev : { ...prev, mascotState: next }));
  },

  syncConfig(nextConfig: AppConfig): void {
    const resolved = resolveThemeBySchedule(
      nextConfig.personalization.theme_mode,
      nextConfig.personalization.theme_schedule
    );
    applyPersonalizationToDom(resolved, nextConfig.personalization, state.windowMode);
    setState((prev) => ({
      ...prev,
      config: mergeIncomingAppConfig(nextConfig, prev.config),
      resolvedTheme: resolved,
    }));
  },

  syncRuntime(nextRuntime: CoreRuntimeInfo): void {
    setState((prev) => ({
      ...prev,
      config: alignConfigWithRuntimeTun(prev.config, nextRuntime),
      runtime: nextRuntime,
    }));
  },

  syncGroups(groups: MultiGroup[]): void {
    setState((prev) => ({ ...prev, groups }));
  },

  syncNodes(nodes: ProxyNode[]): void {
    setState((prev) => ({ ...prev, nodes }));
  },

  syncProbes(probes: Record<string, ProbeSnapshot>): void {
    setState((prev) => ({ ...prev, probes }));
  },

  syncSubscriptions(subscriptions: SubscriptionRecord[]): void {
    setState((prev) => ({ ...prev, subscriptions }));
  },

  syncPreAccelRelays(preAccelRelays: PreAccelRelay[]): void {
    setState((prev) => ({ ...prev, preAccelRelays }));
  },

  syncGlobalPreAccel(globalPreAccel: GlobalPreAccelStatus): void {
    setState((prev) => ({ ...prev, globalPreAccel }));
  },

  async refreshGlobalPreAccelStatus(): Promise<GlobalPreAccelStatus> {
    if (globalPreAccelRefreshInFlight) {
      globalPreAccelRefreshPending = true;
      return state.globalPreAccel;
    }
    globalPreAccelRefreshInFlight = true;
    let latestStatus = state.globalPreAccel;
    try {
      do {
        globalPreAccelRefreshPending = false;
        try {
          const status = await catcloudApi.getGlobalPreAccelStatus();
          latestStatus = status;
          setState((prev) => {
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
          latestStatus = state.globalPreAccel;
        }
      } while (globalPreAccelRefreshPending);
      return latestStatus;
    } finally {
      globalPreAccelRefreshInFlight = false;
      globalPreAccelRefreshPending = false;
    }
  },

  async togglePreAccel(next?: boolean): Promise<boolean> {
    const currentlyOn = Boolean(
      (state.runtime.preaccel_enabled ?? state.config.preaccel.enabled) ||
        isRealWinDivertActive(state.runtime, state.globalPreAccel)
    );
    const target = next ?? !currentlyOn;

    if (target) {
      let relays = state.preAccelRelays;
      if (!relays.some((r) => r.enabled) && isTauriEnv()) {
        try {
          relays = await catcloudApi.listPreAccelRelays();
          setState((prev) => ({ ...prev, preAccelRelays: relays }));
        } catch {
          /* fall through to empty relay guard */
        }
      }
      const hasEnabledRelay = relays.some((r) => r.enabled);
      if (!hasEnabledRelay) {
        pushToast(
          "还没有可用的国内中转线路，请先在「国内提速」页添加并启用至少一条中转",
          "warn",
          4200
        );
        if (state.windowMode === "main" && state.activeNav !== "preaccel") {
          appActions.setNav("preaccel");
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

      const nextCfg: AppConfig =
        cfgRes.status === "fulfilled"
          ? mergeIncomingAppConfig(cfgRes.value, state.config)
          : {
              ...state.config,
              preaccel: {
                ...state.config.preaccel,
                enabled: applied,
                global_bypass_enabled: applied,
              },
            };

      const nextGlobal: GlobalPreAccelStatus =
        globalRes.status === "fulfilled"
          ? globalRes.value
          : applied
            ? state.globalPreAccel
            : {
                ...state.globalPreAccel,
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
              ...state.runtime,
              preaccel_enabled: applied,
              preaccel_active:
                applied && (state.runtime.running || nextWinDivertActive),
              global_preaccel_active: nextGlobal.running,
              global_windivert_active: nextWinDivertActive,
              global_preaccel_mode: nextGlobal.mode,
              global_preaccel_socks_port: nextGlobal.socks_port,
              global_preaccel_connections: nextGlobal.active_connections,
              preaccel_install_state: nextGlobal.install_state ?? "idle",
              global_preaccel_verify_state: nextGlobal.verify_state ?? "idle",
              global_preaccel_verify_ms: nextGlobal.verify_latency_ms ?? null,
            };

      setState((prev) => ({
        ...prev,
        config: nextCfg,
        runtime: nextRt,
        globalPreAccel: nextGlobal,
      }));

      if (!applied) {
        pushToast("已关闭国内提速（猫猫代理与其它软件已一并关闭）", "info");
        return false;
      }

      const summary = resolvePreAccelSummary(nextRt, nextGlobal, nextCfg.preaccel.enabled);
      const os = resolvePlatformOs(nextRt.os_label);

      if (summary.proxyActive) {
        if (summary.realWinDivertActive) {
          if (summary.verifyState === "probing") {
            pushToast(
              "已开启国内提速（猫猫代理已加速，正在自动探测其它代理软件链路…）",
              "ok",
              4200
            );
          } else if (summary.verifyState === "verified" && summary.verifyLatencyMs) {
            pushToast(
              `已开启国内提速（猫猫代理与其它软件均已走 443 加速，实测 ${summary.verifyLatencyMs} ms）`,
              "ok",
              4200
            );
          } else {
            pushToast("已开启国内提速（猫猫代理与其它代理软件均已走 443 加速）", "ok", 4200);
          }
        } else if (summary.verifyState === "probing") {
          pushToast(
            "已开启国内提速（猫猫代理已加速，正在自动探测其它代理软件链路…）",
            "ok",
            4200
          );
        } else if (summary.verifyState === "degraded") {
          pushToast(
            "已开启国内提速（猫猫代理已加速；其它软件底层拦截已保护回退，可前往查看指引）",
            "warn",
            4800
          );
        } else if (
          summary.installState === "downloading" ||
          summary.installState === "verifying"
        ) {
          pushToast(
            "已开启国内提速（猫猫代理已加速，正在后台准备其它软件提速组件…）",
            "ok",
            4400
          );
        } else if (summary.installState === "need_elevation") {
          pushToast(
            "已开启国内提速（猫猫代理已加速；加速其它代理软件需管理员权限）",
            "ok",
            4600
          );
        } else {
          const relayHint = nextRt.preaccel_relay_name
            ? `（当前主力：${nextRt.preaccel_relay_name}）`
            : "";
          pushToast(`已开启国内提速${relayHint}`, "ok");
        }
      } else if (summary.realWinDivertActive) {
        if (summary.verifyState === "probing") {
          pushToast("已开启国内提速，正在自动探测其它代理软件加速链路…", "info", 4200);
        } else if (summary.verifyState === "verified" && summary.verifyLatencyMs) {
          pushToast(
            `已开启国内提速并实测畅通（${summary.verifyLatencyMs} ms），正在自动加速其它代理软件`,
            "ok",
            4200
          );
        } else {
          pushToast("已开启国内提速，正在自动加速电脑上其它代理软件", "ok", 4200);
        }
      } else if (summary.verifyState === "probing") {
        pushToast("已开启国内提速，正在自动探测其它代理软件加速链路…", "info", 4200);
      } else if (summary.verifyState === "degraded") {
        pushToast(
          nextGlobal.verify_message ||
            "底层拦截未畅通，已自动停止拦截防止断网，请查看环境放行指引",
          "warn",
          5000
        );
      } else if (
        summary.installState === "downloading" ||
        summary.installState === "verifying"
      ) {
        pushToast("已开启国内提速，正在后台自动准备官方提速组件…", "info", 4400);
      } else if (summary.installState === "need_elevation") {
        pushToast(
          "已开启国内提速（提速组件已就绪，需以管理员身份重启以加速其它代理软件）",
          "warn",
          4800
        );
      } else if (os === "windows") {
        pushToast("已开启国内提速（当前本地通道待命）", "info", 4200);
      } else {
        const portLabel = nextGlobal.socks_port
          ? `127.0.0.1:${nextGlobal.socks_port}`
          : "本地 443 通道";
        pushToast(`已开启国内提速（本地独立入口 ${portLabel} 已就绪）`, "ok", 4200);
      }

      return true;
    } catch (err) {
      pushToast(`切换国内提速失败：${formatErrorMessage(err)}`, "warn", 4200);
      return false;
    }
  },

  async toggleGlobalPreAccel(next?: boolean): Promise<boolean> {
    return appActions.togglePreAccel(next);
  },

  async updateGlobalPreAccelSettings(
    scope: GlobalPreAccelScope,
    targetProcesses: string[],
    windivertDir: string | null = state.config.preaccel.windivert_dir ?? null
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
      setState((prev) => ({
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
      pushToast(`保存国内提速范围失败：${formatErrorMessage(err)}`, "warn", 4000);
      return false;
    }
  },

  async installWinDivertDriver(): Promise<boolean> {
    return runInFlight(
      "preaccel:installDriver",
      async () => {
        updateBgTasks((bg) => ({
          ...bg,
          preaccel: { ...bg.preaccel, installingDriver: true },
        }));
        try {
          const nextGlobal = await catcloudApi.installWinDivertDriver();
          const rt = await catcloudApi.getRuntimeInfo().catch(() => null);
          setState((prev) => ({
            ...prev,
            globalPreAccel: nextGlobal,
            runtime: rt ?? prev.runtime,
          }));
          if (nextGlobal.windivert_available) {
            pushToast(
              nextGlobal.is_elevated
                ? "官方提速组件（WinDivert v2.2.2）已校验就绪，可自动加速其它代理软件"
                : "官方提速组件已校验就绪，以管理员身份重启即可自动加速其它代理软件",
              "ok",
              4600
            );
            return true;
          }
          pushToast(
            nextGlobal.last_error || "提速组件准备未完成，如被安全软件拦截请放行后重试",
            "warn",
            4600
          );
          return false;
        } catch (err) {
          pushToast(`下载校验 WinDivert 驱动失败：${formatErrorMessage(err)}`, "warn", 5000);
          return false;
        } finally {
          updateBgTasks((bg) => ({
            ...bg,
            preaccel: { ...bg.preaccel, installingDriver: false },
          }));
        }
      },
      { mascot: "thinking", celebrate: true }
    );
  },

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
          setState((prev) => ({
            ...prev,
            config: cfg,
            runtime: rt,
            globalPreAccel: globalStatus,
          }));
          pushToast("演示模式：已模拟管理员提权并开启全局国内提速", "ok");
        } else {
          pushToast("已拉起管理员实例，正在启用全局国内提速…", "ok", 4200);
        }
        return true;
      }
      pushToast("已取消管理员授权，当前继续保持本地通道待命", "info");
      return false;
    } catch (err) {
      pushToast(`以管理员身份启动失败：${formatErrorMessage(err)}`, "warn", 4600);
      return false;
    }
  },

  syncQuickSites(quickSites: SiteCheckItem[]): void {
    setState((prev) => ({ ...prev, quickSites }));
  },

  syncExitIp(exitIp: ExitIpInfo): void {
    setState((prev) => ({ ...prev, exitIp }));
  },

  async refreshAllData(): Promise<void> {
    await hydrateFromBackend();
  },

  previewPersonalization(patch: Partial<AppConfig["personalization"]>): void {
    personalizationReqSeq += 1;
    const nextConfig: AppConfig = {
      ...state.config,
      personalization: {
        ...state.config.personalization,
        ...patch,
      },
    };
    const resolved = resolveThemeBySchedule(
      nextConfig.personalization.theme_mode,
      nextConfig.personalization.theme_schedule
    );
    applyPersonalizationToDom(resolved, nextConfig.personalization, state.windowMode);
    setState((prev) => ({
      ...prev,
      config: nextConfig,
      resolvedTheme: resolved,
    }));
  },

  async updatePersonalization(
    patch: Partial<AppConfig["personalization"]>,
    notice?: string
  ): Promise<void> {
    const reqSeq = ++personalizationReqSeq;
    const prevConfig = state.config;
    const prevResolved = state.resolvedTheme;
    const nextConfig: AppConfig = {
      ...state.config,
      personalization: {
        ...state.config.personalization,
        ...patch,
      },
    };
    const resolved = resolveThemeBySchedule(
      nextConfig.personalization.theme_mode,
      nextConfig.personalization.theme_schedule
    );
    saveCachedUiPrefs(nextConfig.personalization);
    applyPersonalizationToDom(resolved, nextConfig.personalization, state.windowMode);
    setState((prev) => ({
      ...prev,
      config: nextConfig,
      resolvedTheme: resolved,
    }));
    try {
      const saved = await catcloudApi.saveConfig(nextConfig);
      if (reqSeq !== personalizationReqSeq) {
        return;
      }
      const savedResolved = resolveThemeBySchedule(
        saved.personalization.theme_mode,
        saved.personalization.theme_schedule
      );
      saveCachedUiPrefs(saved.personalization);
      applyPersonalizationToDom(savedResolved, saved.personalization, state.windowMode);
      setState((prev) => ({
        ...prev,
        config: mergeIncomingAppConfig(saved, prev.config),
        resolvedTheme: savedResolved,
      }));
      if (notice) pushToast(notice, "info");
    } catch (err) {
      if (reqSeq !== personalizationReqSeq) {
        return;
      }
      applyPersonalizationToDom(prevResolved, prevConfig.personalization, state.windowMode);
      setState((prev) => ({ ...prev, config: prevConfig, resolvedTheme: prevResolved }));
      pushToast(`个性化配置保存失败：${formatErrorMessage(err)}`, "warn");
    }
  },

  cycleThemeMode(): void {
    const manualOrder: ThemeMode[] = ["light", "warm_dark", "midnight_blue"];
    const labels: Record<ThemeMode, string> = {
      auto_time: "按时间自动切换",
      light: "浅色暖纸",
      warm_dark: "深苔暖金",
      midnight_blue: "午夜星蓝",
    };
    // Jump directly to a visibly different theme so the very first click always gives instant feedback
    const currentVisual: ThemeMode =
      state.resolvedTheme === "light"
        ? "light"
        : state.resolvedTheme === "warm-dark"
          ? "warm_dark"
          : "midnight_blue";
    const next = manualOrder[(manualOrder.indexOf(currentVisual) + 1) % manualOrder.length];
    void appActions.updatePersonalization({ theme_mode: next }, `已切换主题：${labels[next]}`);
  },

  async setThemeMode(mode: ThemeMode): Promise<void> {
    const labels: Record<ThemeMode, string> = {
      auto_time: "按时间自动切换",
      light: "浅色暖纸",
      warm_dark: "深苔暖金",
      midnight_blue: "午夜星蓝",
    };
    await appActions.updatePersonalization({ theme_mode: mode }, `已切换主题：${labels[mode]}`);
  },

  async pickWallpaperImage(): Promise<boolean> {
    try {
      const picked = await catcloudApi.pickWallpaperImage();
      if (picked.cancelled || !picked.path) {
        return false;
      }
      if (picked.data_url && !SAFE_BITMAP_DATA_URL_RE.test(picked.data_url)) {
        const msg = "不支持此图片格式，请选择 PNG、JPG、WebP、GIF 或 BMP 图片";
        setState((prev) => ({ ...prev, wallpaperError: msg }));
        pushToast(msg, "warn");
        return false;
      }
      const cssVal = picked.data_url ? `url("${sanitizeCssUrl(picked.data_url)}")` : null;
      if (cssVal) {
        resolvedWallpaperCache = { rawPath: picked.path, cssValue: cssVal };
      }
      const nextConfig: AppConfig = {
        ...state.config,
        personalization: {
          ...state.config.personalization,
          wallpaper_path: picked.path,
        },
      };
      applyPersonalizationToDom(
        state.resolvedTheme,
        nextConfig.personalization,
        state.windowMode,
        cssVal
      );
      setState((prev) => ({
        ...prev,
        config: nextConfig,
        wallpaperPreviewUrl: picked.data_url ?? prev.wallpaperPreviewUrl,
        wallpaperError: null,
      }));
      pushToast("背景壁纸已更换", "ok");
      return true;
    } catch (err) {
      const msg = `选择壁纸失败：${formatErrorMessage(err)}`;
      setState((prev) => ({ ...prev, wallpaperError: msg }));
      pushToast(msg, "warn");
      return false;
    }
  },

  async setWallpaperPath(path: string | null, notice?: string): Promise<void> {
    const trimmed = path?.trim() || null;
    if (!trimmed) {
      resolvedWallpaperCache = null;
      setState((prev) => ({ ...prev, wallpaperPreviewUrl: null, wallpaperError: null }));
    } else {
      setState((prev) => ({
        ...prev,
        wallpaperPreviewUrl: SAFE_BITMAP_DATA_URL_RE.test(trimmed) ? trimmed : null,
        wallpaperError: null,
      }));
    }
    await appActions.updatePersonalization({ wallpaper_path: trimmed }, notice);
    if (trimmed) {
      void ensureLocalWallpaperLoaded(
        trimmed,
        state.resolvedTheme,
        state.config.personalization,
        state.windowMode
      );
    }
  },

  async selectSingleNode(nodeId: string): Promise<void> {
    try {
      const rt = await catcloudApi.selectSingleNode(nodeId);
      const matchedNode = state.nodes.find((n) => n.id === nodeId);
      const nextRuntime: CoreRuntimeInfo = {
        ...rt,
        route_mode: "single",
        active_node_id: rt.active_node_id || nodeId,
        active_node_name: rt.active_node_name || matchedNode?.name || nodeId,
      };
      setState((prev) => ({
        ...prev,
        runtime: nextRuntime,
        exitIp: buildPendingExitIp(nextRuntime.running),
      }));
      pushToast(`已切换为单节点模式：${nextRuntime.active_node_name}`, "ok");
    } catch (err) {
      pushToast(`切换单节点失败：${formatErrorMessage(err)}`, "warn");
    }
  },

  async setActiveGroup(groupId: string): Promise<void> {
    try {
      const rt = await catcloudApi.setActiveGroup(groupId);
      const nextRuntime: CoreRuntimeInfo = {
        ...rt,
        route_mode: "group",
      };
      setState((prev) => ({
        ...prev,
        runtime: nextRuntime,
        exitIp: buildPendingExitIp(nextRuntime.running),
      }));
      pushToast(`已切换当前分组：${nextRuntime.active_group_name}`, "ok");
    } catch (err) {
      pushToast(`切换分组失败：${formatErrorMessage(err)}`, "warn");
    }
  },

  async selectGroupNode(groupId: string, nodeId: string, closeOld = true): Promise<void> {
    try {
      const res = await catcloudApi.selectGroupNode(groupId, nodeId, closeOld);
      const rt = await catcloudApi.getRuntimeInfo();
      const nextRuntime: CoreRuntimeInfo = {
        ...rt,
        route_mode: "group",
        active_group_id: rt.active_group_id || res.group_id,
        active_node_id: rt.active_node_id || res.active_node_id,
        active_node_name: rt.active_node_name || res.active_node_name,
      };
      setState((prev) => ({
        ...prev,
        runtime: nextRuntime,
        exitIp: buildPendingExitIp(nextRuntime.running),
        groups: prev.groups.map((g) =>
          g.id === res.group_id ? { ...g, active_node_id: res.active_node_id } : g
        ),
      }));
      pushToast(`已切换至：${res.active_node_name}`, "ok");
    } catch (err) {
      pushToast(`切换节点失败：${formatErrorMessage(err)}`, "warn");
    }
  },

  setProbeProgress(patch: Partial<ProbeRunProgressState>): void {
    setState((prev) => ({
      ...prev,
      probeProgress: { ...prev.probeProgress, ...patch },
    }));
  },

  async setProxyMode(mode: ProxyMode): Promise<void> {
    try {
      const applied = await catcloudApi.setProxyMode(mode);
      const labelMap: Record<ProxyMode, string> = {
        rule: "规则模式",
        global: "全局模式",
        direct: "直连模式",
      };
      setState((prev) => ({
        ...prev,
        config: { ...prev.config, proxy_mode: applied },
        runtime: { ...prev.runtime, proxy_mode: applied },
        exitIp: buildPendingExitIp(prev.runtime.running),
      }));
      pushToast(`已切换至${labelMap[applied]}`, "ok");
    } catch (err) {
      pushToast(`切换代理模式失败：${formatErrorMessage(err)}`, "warn");
    }
  },

  async toggleSystemProxy(next?: boolean, silent = false): Promise<boolean> {
    const target = next ?? !state.runtime.system_proxy_enabled;
    try {
      const applied = await catcloudApi.toggleSystemProxy(target);
      setState((prev) => ({
        ...prev,
        config: { ...prev.config, system_proxy_enabled: applied },
        runtime: { ...prev.runtime, system_proxy_enabled: applied },
      }));
      if (!silent) {
        pushToast(applied ? "系统代理已开启" : "系统代理已关闭", applied ? "ok" : "info");
      }
      return true;
    } catch (err) {
      pushToast(`切换系统代理失败：${formatErrorMessage(err)}`, "warn");
      return false;
    }
  },

  openTunAdminPrompt(reason: string | null = null): void {
    setState((prev) => ({
      ...prev,
      tunAdminPromptOpen: true,
      tunAdminPromptBusy: false,
      tunAdminPromptReason: reason?.trim() || null,
    }));
  },

  closeTunAdminPrompt(): void {
    setState((prev) =>
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
    if (state.tunAdminPromptBusy) return false;
    const os = resolvePlatformOs(state.runtime.os_label);
    setState((prev) => ({ ...prev, tunAdminPromptBusy: true }));
    try {
      const launched = await catcloudApi.relaunchAsAdmin(true);
      if (launched) {
        if (!isTauriEnv()) {
          const [cfg, rt] = await Promise.all([
            catcloudApi.getConfig(),
            catcloudApi.getRuntimeInfo(),
          ]);
          setState((prev) => ({
            ...prev,
            config: cfg,
            runtime: rt,
            tunAdminPromptOpen: false,
            tunAdminPromptBusy: false,
            tunAdminPromptReason: null,
          }));
          pushToast("演示模式：已模拟完成提权并开启虚拟网卡", "ok");
        } else if (os === "linux") {
          const [cfgRes, rtRes] = await Promise.allSettled([
            catcloudApi.getConfig(),
            catcloudApi.getRuntimeInfo(),
          ]);
          setState((prev) => ({
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
          pushToast("已为代理核心授予网络权限，虚拟网卡已就绪", "ok", 4000);
        } else {
          setState((prev) => ({
            ...prev,
            tunAdminPromptOpen: false,
            tunAdminPromptBusy: false,
            tunAdminPromptReason: null,
          }));
          pushToast(
            os === "macos"
              ? "已发起系统安全授权，正在开启虚拟网卡…"
              : "已拉起管理员实例，正在接管并开启虚拟网卡…",
            "ok"
          );
        }
        return true;
      }
      setState((prev) => ({
        ...prev,
        tunAdminPromptOpen: false,
        tunAdminPromptBusy: false,
        tunAdminPromptReason: null,
      }));
      pushToast("已取消系统授权，虚拟网卡未开启", "info");
      return false;
    } catch (err) {
      setState((prev) => ({ ...prev, tunAdminPromptBusy: false }));
      pushToast(
        os === "linux"
          ? `授予核心网络权限失败：${formatErrorMessage(err)}`
          : `系统授权启动失败：${formatErrorMessage(err)}`,
        "warn"
      );
      return false;
    }
  },

  async toggleTun(next?: boolean, silent = false): Promise<boolean> {
    if (next === undefined && state.runtime.tun_needs_elevation) {
      appActions.openTunAdminPrompt(null);
      return false;
    }
    const target = next ?? !state.runtime.tun_enabled;
    if (target && state.runtime.tun_admin_ready === false) {
      appActions.openTunAdminPrompt(null);
      return false;
    }
    try {
      const applied = await catcloudApi.toggleTun(target);
      setState((prev) => {
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
        pushToast(
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
        setState((prev) => ({
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
      pushToast(`切换虚拟网卡失败：${msg}`, "warn");
      return false;
    }
  },

  async disableAllProxyAndStopCore(): Promise<boolean> {
    try {
      const nextRt = await catcloudApi.disableAllProxyAndStopCore();
      const stopTs = Date.now();
      if (trafficBuffer.length > 0) {
        trafficBuffer.push(0, 0, stopTs);
      }
      state = {
        ...state,
        latestTraffic: {
          ...state.latestTraffic,
          up_bps: 0,
          down_bps: 0,
          connections: 0,
          tunnel_connections: 0,
          memory_mb: 0,
          timestamp_ms: stopTs,
        },
        trafficVersion: state.trafficVersion + 1,
      };
      emitTraffic();

      const nextGlobal = await catcloudApi.getGlobalPreAccelStatus().catch(() => null);
      setState((prev) => ({
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

      const realWinDivert = isRealWinDivertActive(nextRt, nextGlobal ?? state.globalPreAccel);
      pushToast(
        realWinDivert
          ? "已关闭猫猫代理并停止主核（全局国内提速继续运行中）"
          : "已关闭代理并停止核心，释放内存与本地端口",
        "info"
      );
      return true;
    } catch (err) {
      pushToast(`关闭代理并停止核心失败：${formatErrorMessage(err)}`, "warn", 4200);
      return false;
    }
  },

  async switchNextBestNode(): Promise<void> {
    const isSingleMode = state.runtime.route_mode === "single";
    const targetId = isSingleMode
      ? "single"
      : state.runtime.active_group_id || state.groups[0]?.id || "";
    if (!isSingleMode && !targetId) {
      pushToast("当前暂无可用多选组，请先在「智能多选组」中创建", "warn");
      return;
    }
    setState((prev) => ({ ...prev, mascotState: "thinking" }));
    try {
      const res = await catcloudApi.switchNextBestNode(targetId);
      setState((prev) => ({
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
      pushToast(`已秒切至 ${res.active_node_name}（清理 ${res.closed_connections} 条旧连接）`, "ok");
      celebrateMascotComplete(4000);
    } catch (err) {
      setState((prev) => ({ ...prev, mascotState: "idle" }));
      pushToast(`切换次优节点失败：${formatErrorMessage(err)}`, "warn");
    }
  },

  async toggleCapsule(): Promise<void> {
    if (isTauriEnv()) {
      try {
        await catcloudApi.toggleCapsuleWindow();
      } catch (err) {
        pushToast(`切换悬浮小窗失败：${formatErrorMessage(err)}`, "warn");
      }
      return;
    }
    const nextMode: WindowMode = state.windowMode === "capsule" ? "main" : "capsule";
    if (typeof window !== "undefined") {
      window.location.hash = nextMode === "capsule" ? "#capsule" : `#${state.activeNav}`;
    }
    setState((prev) => ({ ...prev, windowMode: nextMode }));
    applyPersonalizationToDom(state.resolvedTheme, state.config.personalization, nextMode);
  },

  async showMainFromCapsule(): Promise<void> {
    if (isTauriEnv()) {
      try {
        await catcloudApi.showMainWindow();
      } catch (err) {
        pushToast(`展开主窗口失败：${formatErrorMessage(err)}`, "warn");
      }
      return;
    }
    if (typeof window !== "undefined") {
      window.location.hash = `#${state.activeNav}`;
    }
    setState((prev) => ({ ...prev, windowMode: "main" }));
    applyPersonalizationToDom(state.resolvedTheme, state.config.personalization, "main");
  },

  async refreshQuickSites(): Promise<void> {
    await appActions.runQuickSitesCheck();
  },

  /* ==========================================================================
   * Global Background Task Actions (Survive Route Unmount + In-Flight Dedupe)
   * ========================================================================== */

  async runPreAccelBenchmark(
    nodeId?: string | null
  ): Promise<PreAccelComparisonResult | null> {
    const existing = inFlightTasks.get("preaccel:benchmark");
    if (existing) {
      return existing as Promise<PreAccelComparisonResult | null>;
    }
    if (selectIsProbeEngineBusy(state)) {
      const relaySpeedBusy =
        state.bgTasks.preaccel.relaysSpeedTestingAll ||
        state.bgTasks.preaccel.relaysSpeedTestingIds.length > 0;
      pushToast(
        relaySpeedBusy
          ? "中转上下行测速正在后台进行，完成后即可运行提速对比"
          : "节点测速正在后台进行，完成后即可运行提速对比",
        "info"
      );
      return null;
    }

    const inDesktop = isTauriEnv();
    const currentRelays = state.preAccelRelays;
    const enabledRelays = [...currentRelays]
      .filter((r) => r.enabled)
      .sort((a, b) => (a.priority !== b.priority ? a.priority - b.priority : a.id.localeCompare(b.id)));
    if (inDesktop && enabledRelays.length === 0) {
      pushToast("请先添加并启用至少一条国内中转线路，再进行提速对比", "warn");
      return null;
    }

    const hasComparableNode = state.nodes.some((n) => !isUdpOnlyProtocol(n.protocol));
    if (inDesktop && !hasComparableNode) {
      pushToast("还没有可对比的海外节点，请先在「节点与测速 → 订阅与导入」中导入节点", "warn");
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

    return runInFlight(
      "preaccel:benchmark",
      async () => {
        updateBgTasks((bg) => ({
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
          // 1) Pre-probe domestic relays so relay latency cards refresh alongside benchmark
          try {
            const relayResults = await catcloudApi.testPreAccelRelays(null);
            if (inDesktop) {
              const latestRelays = await catcloudApi.listPreAccelRelays();
              setState((prev) => ({ ...prev, preAccelRelays: latestRelays }));
            } else {
              const resultMap = new Map(relayResults.map((r) => [r.relay_id, r]));
              setState((prev) => ({
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

          // 2) Run accelerated vs direct speed comparison
          const result = await catcloudApi.benchmarkPreAccelComparison(
            primaryRelayId,
            requestedNodeId
          );

          if (inDesktop) {
            try {
              const latestRelays = await catcloudApi.listPreAccelRelays();
              setState((prev) => ({ ...prev, preAccelRelays: latestRelays }));
            } catch {
              /* ignore secondary relay refresh failure */
            }
          }

          const finishedAt = Date.now();
          updateBgTasks((bg) => ({
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
            pushToast(
              ratio !== null
                ? `提速效果对比完成（演示）：走国内中转上传提速约 ${ratio.toFixed(1)} 倍`
                : "提速效果对比完成（演示）",
              "info",
              4000
            );
          } else if (result.ok && result.accelerated.ok && result.direct.ok) {
            pushToast(
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
            pushToast(
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
          updateBgTasks((bg) => ({
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
          pushToast(`提速效果对比失败：${msg}`, "warn", 4400);
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
      if (state.preAccelRelays.length === 0) return;
      return runInFlight(
        "preaccel:relays:all",
        async () => {
          updateBgTasks((bg) => ({
            ...bg,
            preaccel: { ...bg.preaccel, relaysTestingAll: true },
          }));
          try {
            const results = await catcloudApi.testPreAccelRelays(null);
            if (inDesktop) {
              const latestRelays = await catcloudApi.listPreAccelRelays();
              setState((prev) => ({ ...prev, preAccelRelays: latestRelays }));
            } else {
              const resultMap = new Map(results.map((r) => [r.relay_id, r]));
              setState((prev) => ({
                ...prev,
                preAccelRelays: prev.preAccelRelays.map((r) => {
                  const matched = resultMap.get(r.id);
                  return matched ? { ...r, last_probe_ms: matched.latency_ms } : r;
                }),
              }));
            }
            const okCount = results.filter((r) => r.ok).length;
            pushToast(
              `全部中转测速完成：${okCount}/${results.length} 条线路可用`,
              okCount > 0 ? "ok" : "warn"
            );
          } catch (err) {
            pushToast(`全部中转测速失败：${formatErrorMessage(err)}`, "warn");
          } finally {
            updateBgTasks((bg) => ({
              ...bg,
              preaccel: { ...bg.preaccel, relaysTestingAll: false },
            }));
          }
        },
        { mascot: true }
      );
    }

    if (state.bgTasks.preaccel.relaysTestingAll) return;

    return runInFlight(
      `preaccel:relay:${targetId}`,
      async () => {
        updateBgTasks((bg) => ({
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
            setState((prev) => ({ ...prev, preAccelRelays: latestRelays }));
          } else if (item) {
            setState((prev) => ({
              ...prev,
              preAccelRelays: prev.preAccelRelays.map((r) =>
                r.id === targetId ? { ...r, last_probe_ms: item.latency_ms } : r
              ),
            }));
          }
          if (item && !item.ok) {
            pushToast(`中转测速失败：${item.error ?? "连接超时"}`, "warn");
          } else {
            const msText = hasValidPositiveLatency(item?.latency_ms)
              ? `（${formatMsShort(item.latency_ms)}）`
              : "";
            pushToast(`中转线路连通正常${msText}`, "ok");
          }
        } catch (err) {
          pushToast(`中转测速失败：${formatErrorMessage(err)}`, "warn");
        } finally {
          updateBgTasks((bg) => ({
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
    const existing = inFlightTasks.get(taskKey);
    if (existing) {
      return existing as Promise<PreAccelSpeedTestResult[]>;
    }
    if (!targetId && state.preAccelRelays.length === 0) {
      return [];
    }
    if (selectIsProbeEngineBusy(state)) {
      pushToast("当前已有测速或提速对比正在后台进行，请稍候完成后再试", "info");
      return [];
    }

    const hasValidSpeed = (v: number | null | undefined): v is number =>
      v !== null && v !== undefined && Number.isFinite(v) && v > 0;

    return runInFlight(
      taskKey,
      async () => {
        if (!targetId) {
          updateBgTasks((bg) => ({
            ...bg,
            preaccel: { ...bg.preaccel, relaysSpeedTestingAll: true },
          }));
        } else {
          updateBgTasks((bg) => ({
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
            setState((prev) => ({
              ...prev,
              preAccelRelays: latestRelays,
              relayChainLatencies: { ...prev.relayChainLatencies, ...chainPatch },
            }));
          } else {
            const resultMap = new Map(results.map((r) => [r.relay_id, r]));
            setState((prev) => ({
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
              state.preAccelRelays.find((r) => r.id === targetId)?.name ||
              "中转线路";
            if (!item || !item.ok) {
              pushToast(
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
                pushToast(
                  `「${relayName}」测速完成：${speedParts.join(" · ")}${msText}`,
                  "ok",
                  4600
                );
              } else {
                pushToast(
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
            pushToast(
              `中转上下行测速完成：${measuredCount}/${results.length} 条已测出速率`,
              measuredCount > 0 ? "ok" : "warn",
              4600
            );
          }

          return results;
        } catch (err) {
          pushToast(`中转上下行测速失败：${formatErrorMessage(err)}`, "warn", 4600);
          return [];
        } finally {
          if (!targetId) {
            updateBgTasks((bg) => ({
              ...bg,
              preaccel: { ...bg.preaccel, relaysSpeedTestingAll: false },
            }));
          } else {
            updateBgTasks((bg) => ({
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
    return runInFlight(
      "preaccel:campusPortal",
      async () => {
        updateBgTasks((bg) => ({
          ...bg,
          preaccel: {
            ...bg.preaccel,
            campusChecking: true,
            campusError: null,
          },
        }));
        try {
          const status = await catcloudApi.checkCampusPortal();
          setState((prev) => ({
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
            pushToast("检测到需要登录校园网，已自动临时放行认证页", "warn");
          } else {
            pushToast("当前国内网络连通正常，无需网页认证", "ok");
          }
        } catch (err) {
          const msg = formatErrorMessage(err);
          updateBgTasks((bg) => ({
            ...bg,
            preaccel: {
              ...bg.preaccel,
              campusChecking: false,
              campusError: msg,
            },
          }));
          pushToast(`校园网认证检测失败：${msg}`, "warn");
        }
      },
      { mascot: true }
    );
  },

  async runInstallWinDivertDriver(): Promise<void> {
    await appActions.installWinDivertDriver();
  },

  async runVerifyGlobalPreAccel(): Promise<GlobalPreAccelStatus | null> {
    return runInFlight(
      "preaccel:verifyGlobal",
      async () => {
        updateBgTasks((bg) => ({
          ...bg,
          preaccel: { ...bg.preaccel, verifyingGlobal: true },
        }));
        try {
          const status = await catcloudApi.verifyGlobalPreAccel();
          const rt = await catcloudApi.getRuntimeInfo().catch(() => null);
          setState((prev) => {
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
            pushToast(`全局提速链路探测畅通${msHint}`, "ok", 4200);
          } else if (verifyState === "degraded") {
            pushToast(
              status.verify_message ||
                "底层拦截未畅通，已自动停止拦截防止断网，请查看环境放行指引",
              "warn",
              5200
            );
          } else if (verifyState === "failed") {
            pushToast(
              `链路探测未通过：${status.verify_message || status.last_error || "请检查中转线路与网络环境"}`,
              "warn",
              4800
            );
          } else if (verifyState === "probing") {
            pushToast("正在后台自动探测提速链路，请稍候…", "info", 3200);
          } else {
            pushToast(status.verify_message || "已完成当前提速链路检查", "info", 3200);
          }
          return status;
        } catch (err) {
          pushToast(`重新探测链路失败：${formatErrorMessage(err)}`, "warn", 4400);
          return null;
        } finally {
          updateBgTasks((bg) => ({
            ...bg,
            preaccel: { ...bg.preaccel, verifyingGlobal: false },
          }));
        }
      },
      { mascot: true }
    );
  },

  async runIsolatedProbesBg(params: {
    nodeIds: string[];
    probeIds: string[];
    usePreAccel?: boolean;
    lockedOrderIds?: string[];
    maxTier?: "latency" | "unlock" | "full";
    includeKeepalive?: boolean;
  }): Promise<void> {
    const existing = inFlightTasks.get("probes:isolated");
    if (existing) {
      return existing as Promise<void>;
    }
    if (state.bgTasks.preaccel.benchmark.running) {
      pushToast("国内提速对比测速正在后台进行，完成后即可运行节点测速", "info");
      return;
    }
    if (state.probeProgress.running || state.bgTasks.probeLocalStarting) {
      pushToast("已有节点测速正在进行中，请稍候", "info");
      return;
    }

    const targetNodeIds = params.nodeIds.filter((id) => id.trim().length > 0);
    if (targetNodeIds.length === 0) {
      pushToast("请先筛选或勾选至少一个节点后再开始测速", "warn");
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

    return runInFlight(
      "probes:isolated",
      async () => {
        probePauseRequested = false;
        previewProbeCancelled = false;
        clearPreviewProbeTimer();
        probePendingQueue = [...targetNodeIds];

        setState((prev) => ({
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

            const wasCancelled = Boolean(result.cancelled) || probePauseRequested;
            const finalCompleted = Math.max(
              result.probed_count,
              state.probeProgress.completed
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
                snapVals.filter((s) => s.ok && s.up_mbps !== null && s.down_mbps !== null).length,
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

            setState((prev) => {
              let nextProbes = prev.probes;
              if (result.snapshots && Object.keys(result.snapshots).length > 0) {
                nextProbes = { ...prev.probes };
                for (const [nid, incoming] of Object.entries(result.snapshots)) {
                  nextProbes[nid] = mergeProbeSnapshotSafe(prev.probes[nid], incoming);
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
              pushToast(
                `已暂停测速，已测完的 ${finalCompleted} 个节点结果已全部保留`,
                "info"
              );
            } else if (!result.core_available) {
              pushToast(
                result.errors[0] ?? "测速引擎尚未就绪，请先检查内核配置",
                "warn"
              );
            } else if (result.errors.length > 0 && result.probed_count === 0) {
              pushToast(`测速未能完成：${result.errors[0]}`, "warn");
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
              pushToast(
                `${PROBE_TIER_LABELS[tier]}完成${preaccelTag}：${summaryParts.join(" · ")}`,
                computedSummary.failed_count > 0 || computedSummary.exec_error_count > 0
                  ? "info"
                  : "ok",
                5200
              );
            }
          } catch (err) {
            setState((prev) => ({
              ...prev,
              probeProgress: {
                ...prev.probeProgress,
                running: false,
                currentNodeName: null,
                cancelled: probePauseRequested,
              },
              bgTasks: {
                ...prev.bgTasks,
                probeLocalStarting: false,
                probeIsPausing: false,
                probeActiveNodeIds: [],
                probeLockedOrderIds: [],
              },
            }));
            pushToast(`测速执行失败：${formatErrorMessage(err)}`, "warn");
          } finally {
            probePendingQueue = [];
            probePauseRequested = false;
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
            probePendingQueue = [];
            probePauseRequested = false;
            setState((prev) => ({
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
              pushToast(
                `预览模式：${PROBE_TIER_LABELS[tier]}完成，已逐条更新 ${total} 个节点`,
                "ok"
              );
            }
            resolve();
          };

          const stepNext = (index: number) => {
            if (previewProbeCancelled) {
              finishPreview(true, state.probeProgress.completed);
              return;
            }
            if (index >= total) {
              finishPreview(false, total);
              return;
            }

            const nodeId = targetNodeIds[index];
            const nodeName = nodeNameById.get(nodeId) ?? nodeId;
            setState((prev) => ({
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
                finishPreview(true, state.probeProgress.completed);
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
                    finishPreview(true, state.probeProgress.completed);
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
                    setState((prev) => ({
                      ...prev,
                      probes: {
                        ...prev.probes,
                        [nodeId]: mergeProbeSnapshotSafe(prev.probes[nodeId], streamedSnap),
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
                    finishPreview(true, state.probeProgress.completed);
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
    if (!state.probeProgress.running && !state.bgTasks.probeLocalStarting) return;
    if (state.bgTasks.probeIsPausing) return;

    probePauseRequested = true;
    updateBgTasks((bg) => ({ ...bg, probeIsPausing: true }));

    if (!isTauriEnv()) {
      previewProbeCancelled = true;
      clearPreviewProbeTimer();
      try {
        await catcloudApi.cancelIsolatedProbes();
      } catch {
        /* ignore mock cancel errors */
      }
      const doneCount = state.probeProgress.completed;
      const total = state.probeProgress.total;
      const pendingResolve = previewProbeFinishResolve;
      previewProbeFinishResolve = null;
      probePendingQueue = [];
      probePauseRequested = false;
      setState((prev) => ({
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
      pushToast(`已暂停测速，已测完的 ${doneCount} 个节点结果已全部保留`, "info");
      return;
    }

    try {
      const wasRunning = await catcloudApi.cancelIsolatedProbes();
      const ownedByStore = inFlightTasks.has("probes:isolated");
      if (!ownedByStore && !wasRunning) {
        const doneCount = state.probeProgress.completed;
        probePendingQueue = [];
        probePauseRequested = false;
        setState((prev) => ({
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
        pushToast(`已暂停测速，已测完的 ${doneCount} 个节点结果已全部保留`, "info");
      }
    } catch (err) {
      probePauseRequested = false;
      updateBgTasks((bg) => ({ ...bg, probeIsPausing: false }));
      pushToast(`暂停测速失败：${formatErrorMessage(err)}`, "warn");
    }
  },

  setSubsImporting(importing: boolean): void {
    updateBgTasks((bg) =>
      bg.subs.importing === importing
        ? bg
        : { ...bg, subs: { ...bg.subs, importing } }
    );
  },

  async runRefreshAllSubscriptions(): Promise<void> {
    if (state.subscriptions.length === 0) return;
    return runInFlight(
      "subs:refreshAll",
      async () => {
        updateBgTasks((bg) => ({
          ...bg,
          subs: { ...bg.subs, refreshingAll: true },
        }));
        try {
          if (isTauriEnv()) {
            const res = await catcloudApi.refreshAllSubscriptions();
            const [subsRes, nodesRes, groupsRes, rtRes, cfgRes] =
              await Promise.allSettled([
                catcloudApi.listSubscriptions(),
                catcloudApi.listNodes(),
                catcloudApi.listGroups(),
                catcloudApi.getRuntimeInfo(),
                catcloudApi.getConfig(),
              ]);
            setState((prev) => ({
              ...prev,
              subscriptions:
                subsRes.status === "fulfilled" ? subsRes.value : prev.subscriptions,
              nodes: nodesRes.status === "fulfilled" ? nodesRes.value : prev.nodes,
              groups: groupsRes.status === "fulfilled" ? groupsRes.value : prev.groups,
              runtime: rtRes.status === "fulfilled" ? rtRes.value : prev.runtime,
              config:
                cfgRes.status === "fulfilled"
                  ? mergeIncomingAppConfig(cfgRes.value, prev.config)
                  : prev.config,
            }));
            if (res.errors.length > 0) {
              pushToast(
                `已刷新 ${res.refreshed} 个订阅（共 ${res.total_nodes} 节点），${res.errors.length} 个失败：${formatErrorMessage(res.errors[0])}`,
                "warn"
              );
            } else {
              pushToast(
                `已刷新 ${res.refreshed} 个启用订阅，共 ${res.total_nodes} 个节点`,
                "ok"
              );
            }
          } else {
            await new Promise<void>((r) => window.setTimeout(r, 260));
            const nowIso = new Date().toISOString();
            let refreshedCount = 0;
            setState((prev) => {
              const nextSubs = prev.subscriptions.map((item) => {
                if (!item.enabled) return item;
                refreshedCount += 1;
                return { ...item, last_ok_at: nowIso, last_error: null };
              });
              return { ...prev, subscriptions: nextSubs };
            });
            pushToast(`已刷新 ${refreshedCount} 个已启用的订阅`, "ok");
          }
        } catch (err) {
          pushToast(`批量刷新订阅失败：${formatErrorMessage(err)}`, "warn");
        } finally {
          updateBgTasks((bg) => ({
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
    if (state.bgTasks.subs.refreshingAll) {
      pushToast("正在批量刷新全部订阅，请稍候", "info");
      return;
    }
    const simulateFault = Boolean(options?.simulateFault);

    return runInFlight(
      `subs:refresh:${subId}`,
      async () => {
        updateBgTasks((bg) => ({
          ...bg,
          subs: {
            ...bg.subs,
            refreshingIds: bg.subs.refreshingIds.includes(subId)
              ? bg.subs.refreshingIds
              : [...bg.subs.refreshingIds, subId],
          },
        }));

        const resolveSubName = () =>
          state.subscriptions.find((item) => item.id === subId)?.name ?? "当前订阅";

        try {
          if (isTauriEnv() && !simulateFault) {
            const res = await catcloudApi.refreshSubscription(subId);
            const [subsRes, nodesRes, groupsRes, rtRes, cfgRes] =
              await Promise.allSettled([
                catcloudApi.listSubscriptions(),
                catcloudApi.listNodes(),
                catcloudApi.listGroups(),
                catcloudApi.getRuntimeInfo(),
                catcloudApi.getConfig(),
              ]);
            setState((prev) => ({
              ...prev,
              subscriptions:
                subsRes.status === "fulfilled" ? subsRes.value : prev.subscriptions,
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
            pushToast(
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
            setState((prev) => ({
              ...prev,
              subscriptions: prev.subscriptions.map((item) =>
                item.id === subId ? { ...item, last_error: errMsg } : item
              ),
            }));
            pushToast(
              `${resolveSubName()} 刷新异常（预览演练）：已自动保护老节点与自建规则`,
              "warn"
            );
          } else {
            setState((prev) => ({
              ...prev,
              subscriptions: prev.subscriptions.map((item) =>
                item.id === subId
                  ? { ...item, last_ok_at: nowIso, last_error: null }
                  : item
              ),
            }));
            pushToast(`${resolveSubName()} 已安全刷新`, "ok");
          }
        } catch (err) {
          const errMsg = formatErrorMessage(err);
          // Functional update against latest store state: never overwrite newer subscriptions!
          setState((prev) => ({
            ...prev,
            subscriptions: prev.subscriptions.map((item) =>
              item.id === subId ? { ...item, last_error: errMsg } : item
            ),
          }));
          pushToast(
            `${resolveSubName()} 刷新失败（已保留现有节点）：${errMsg}`,
            "warn"
          );
        } finally {
          updateBgTasks((bg) => ({
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

  async runQuickSitesCheck(): Promise<void> {
    return runInFlight(
      "home:quickSites",
      async () => {
        updateBgTasks((bg) => ({
          ...bg,
          home: { ...bg.home, checkingQuickSites: true },
        }));
        try {
          const freshSites = await catcloudApi.checkQuickSites();
          if (isTauriEnv()) {
            setState((prev) => ({ ...prev, quickSites: freshSites }));
          } else {
            const freshById = new Map(freshSites.map((item) => [item.id, item]));
            setState((prev) => {
              const baseList = prev.quickSites.length > 0 ? prev.quickSites : freshSites;
              return {
                ...prev,
                quickSites: baseList.map((site) => {
                  const updated = freshById.get(site.id);
                  return updated ?? { ...site, latency_ms: 88, ok: true };
                }),
              };
            });
          }
          pushToast("网站连通检测完成", "ok");
        } catch (err) {
          pushToast(`网站检测失败：${formatErrorMessage(err)}`, "warn");
        } finally {
          updateBgTasks((bg) => ({
            ...bg,
            home: { ...bg.home, checkingQuickSites: false },
          }));
        }
      },
      { mascot: true }
    );
  },

  async runRefreshExitIp(): Promise<void> {
    return runInFlight(
      "home:exitIp",
      async () => {
        updateBgTasks((bg) => ({
          ...bg,
          home: { ...bg.home, refreshingExitIp: true },
        }));
        try {
          const info = await catcloudApi.getExitIpInfo();
          setState((prev) => ({ ...prev, exitIp: info }));
          if (hasRealExitIpInfo(info)) {
            pushToast("出口信息已更新", "ok");
          } else {
            const detailParts = [info.isp, info.location]
              .map((s) => s?.trim() ?? "")
              .filter(
                (s) =>
                  s.length > 0 &&
                  s !== "未连接" &&
                  s !== "待检测" &&
                  s !== "待核心启动探测"
              );
            const detail = Array.from(new Set(detailParts)).join(" · ");
            pushToast(
              detail
                ? `未获取到出口 IP：${detail}`
                : "未获取到出口 IP，请确认核心已启动且节点连通",
              "warn"
            );
          }
        } catch (err) {
          pushToast(`检测出口信息失败：${formatErrorMessage(err)}`, "warn");
        } finally {
          updateBgTasks((bg) => ({
            ...bg,
            home: { ...bg.home, refreshingExitIp: false },
          }));
        }
      },
      { mascot: true }
    );
  },

  async runMultiGroupNodeProbe(nodeId: string): Promise<void> {
    const taskKey = `groups:probe:${nodeId}`;
    const existing = inFlightTasks.get(taskKey);
    if (existing) {
      return existing as Promise<void>;
    }
    if (selectIsProbeEngineBusy(state)) {
      pushToast("当前已有测速或对比任务正在进行，请稍候完成后再试", "info");
      return;
    }

    return runInFlight(
      taskKey,
      async () => {
        updateBgTasks((bg) => ({
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
            setState((prev) => {
              const nextProbes = { ...prev.probes };
              for (const [nid, incoming] of Object.entries(res.snapshots)) {
                nextProbes[nid] = mergeProbeSnapshotSafe(prev.probes[nid], incoming);
              }
              return { ...prev, probes: nextProbes };
            });
          }
          const nodeName = state.nodes.find((n) => n.id === nodeId)?.name ?? nodeId;
          const snap = res.snapshots?.[nodeId];
          if (snap && snap.ok && snap.latency_ms !== null) {
            pushToast(`测速完成：${nodeName} · ${Math.round(snap.latency_ms)} ms`, "ok");
          } else if (res.errors.length > 0) {
            pushToast(`测速提示：${res.errors[0]}`, "warn");
          } else {
            pushToast(`${nodeName} 暂时连接超时，可稍后再试`, "warn");
          }
        } catch (err) {
          pushToast(`测速失败：${formatErrorMessage(err)}`, "warn");
        } finally {
          updateBgTasks((bg) => ({
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
    return runInFlight(
      "groups:eval",
      async () => {
        updateBgTasks((bg) => ({
          ...bg,
          groups: { ...bg.groups, evaluatingGroupId: groupId },
        }));
        try {
          const report = await catcloudApi.evaluateMultiGroup(groupId);
          updateBgTasks((bg) => ({
            ...bg,
            groups: {
              ...bg.groups,
              evalReports: {
                ...bg.groups.evalReports,
                [groupId]: report,
              },
            },
          }));
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
          pushToast(
            untestedCnt > 0
              ? `评估完成：候选 ${report.pool_size} 个 · 达标 ${report.healthy_candidates.length} 个（其中 ${untestedCnt} 个尚未测速）`
              : `评估完成：候选 ${report.pool_size} 个 · 达标 ${report.healthy_candidates.length} 个`,
            "ok"
          );
        } catch (err) {
          pushToast(`后端评估失败：${formatErrorMessage(err)}`, "warn");
        } finally {
          updateBgTasks((bg) => ({
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

  async loadGeodataStatus(force = false): Promise<void> {
    if (!force && state.bgTasks.settings.geoStatus !== null) {
      return;
    }
    return runInFlight("settings:geoStatus", async () => {
      updateBgTasks((bg) => ({
        ...bg,
        settings: { ...bg.settings, geoLoading: true },
      }));
      try {
        const status = await catcloudApi.getGeodataStatus();
        updateBgTasks((bg) => ({
          ...bg,
          settings: { ...bg.settings, geoStatus: status },
        }));
      } catch {
        /* preserve previous geodata status on transient failure */
      } finally {
        updateBgTasks((bg) => ({
          ...bg,
          settings: { ...bg.settings, geoLoading: false },
        }));
      }
    });
  },

  async runRefreshGeoDb(target: string): Promise<void> {
    const existing = inFlightTasks.get("settings:geoRefresh");
    if (existing) {
      if (state.bgTasks.settings.geoBusy !== target) {
        pushToast("地理数据库正在更新中，请稍候完成后再试", "info");
      }
      return existing as Promise<void>;
    }
    return runInFlight(
      "settings:geoRefresh",
      async () => {
        updateBgTasks((bg) => ({
          ...bg,
          settings: { ...bg.settings, geoBusy: target },
        }));
        try {
          const res = await catcloudApi.refreshGeoDb(target === "all" ? null : [target]);
          try {
            const latest = await catcloudApi.getGeodataStatus();
            updateBgTasks((bg) => ({
              ...bg,
              settings: { ...bg.settings, geoStatus: latest },
            }));
          } catch {
            /* ignore secondary status refresh error */
          }
          pushToast(res.message || "地理数据库已更新", res.ok ? "ok" : "warn");
        } catch (err) {
          pushToast(`更新地理数据库失败：${formatErrorMessage(err)}`, "warn");
        } finally {
          updateBgTasks((bg) => ({
            ...bg,
            settings: { ...bg.settings, geoBusy: null },
          }));
        }
      },
      { mascot: true }
    );
  },

  async runCheckAppUpdate(): Promise<void> {
    return runInFlight(
      "settings:checkUpdate",
      async () => {
        updateBgTasks((bg) => ({
          ...bg,
          settings: { ...bg.settings, checkingUpdate: true },
        }));
        try {
          const res = await catcloudApi.checkAppUpdate();
          const autoDownloadOn = state.config.update.auto_download ?? true;
          let message: string;
          if (res.error) {
            message = `检查失败：${res.error}`;
            pushToast(`检查更新失败：${res.error}`, "warn");
          } else if (res.staged_version) {
            message = `已下载并校验完成 v${res.staged_version}，下次重启自动生效`;
            pushToast(
              `v${res.staged_version} 已准备就绪，下次重启猫猫云梯时自动生效`,
              "ok"
            );
          } else if (res.has_update) {
            if (res.can_auto_stage && autoDownloadOn && state.config.update.mode !== "manual") {
              message = `发现新版本 v${res.latest_version}（当前 v${res.current_version}），点击下方即可一键下载预置`;
              pushToast(
                `发现新版本 v${res.latest_version}，可一键下载并在下次启动自动应用`,
                "ok"
              );
            } else {
              message = `发现新版本 v${res.latest_version}（当前 v${res.current_version}）`;
              pushToast(`发现新版本 v${res.latest_version}`, "ok");
            }
          } else {
            message = `当前 v${res.current_version} 已是最新版本`;
            pushToast("当前已是最新版本", "info");
          }
          updateBgTasks((bg) => ({
            ...bg,
            settings: {
              ...bg.settings,
              updateInfo: res,
              updateMessage: message,
            },
          }));
        } catch (err) {
          const msg = formatErrorMessage(err);
          updateBgTasks((bg) => ({
            ...bg,
            settings: { ...bg.settings, updateMessage: `检查更新异常：${msg}` },
          }));
          pushToast(`检查更新失败：${msg}`, "warn");
        } finally {
          updateBgTasks((bg) => ({
            ...bg,
            settings: { ...bg.settings, checkingUpdate: false },
          }));
        }
      },
      { mascot: true }
    );
  },

  async runDownloadAppUpdate(): Promise<void> {
    return runInFlight(
      "settings:downloadUpdate",
      async () => {
        updateBgTasks((bg) => ({
          ...bg,
          settings: { ...bg.settings, downloadingUpdate: true },
        }));
        try {
          const res = await catcloudApi.downloadAndStageUpdate();
          if (res.staged) {
            const prevInfo = state.bgTasks.settings.updateInfo;
            const targetVersion =
              res.target_version || prevInfo?.latest_version || state.runtime.app_version;
            const nextInfo: AppUpdateCheckResult = {
              has_update: true,
              current_version: prevInfo?.current_version ?? state.runtime.app_version,
              latest_version: targetVersion,
              release_url:
                res.release_url ||
                prevInfo?.release_url ||
                buildReleasesFallbackUrl(state.config.update.repo),
              download_url: res.download_url ?? prevInfo?.download_url ?? null,
              notes: prevInfo?.notes ?? "",
              checked_at: prevInfo?.checked_at ?? new Date().toISOString(),
              platform_key: prevInfo?.platform_key,
              can_auto_stage: true,
              staged_version: targetVersion,
              error: null,
            };
            updateBgTasks((bg) => ({
              ...bg,
              settings: {
                ...bg.settings,
                updateInfo: nextInfo,
                updateMessage: `已下载并校验完成 v${targetVersion}，下次重启时自动生效`,
              },
            }));
            pushToast(
              res.message ||
                `已下载并校验完成 v${targetVersion}，下次重启猫猫云梯时自动生效`,
              "ok",
              4200
            );
          } else if (res.already_latest) {
            updateBgTasks((bg) => ({
              ...bg,
              settings: {
                ...bg.settings,
                updateInfo: bg.settings.updateInfo
                  ? { ...bg.settings.updateInfo, has_update: false }
                  : bg.settings.updateInfo,
                updateMessage: res.message || `当前 v${state.runtime.app_version} 已是最新版本`,
              },
            }));
            pushToast(res.message || "当前已是最新版本", "info");
          } else {
            const prevInfo = state.bgTasks.settings.updateInfo;
            const releaseUrl =
              res.release_url ||
              prevInfo?.release_url ||
              buildReleasesFallbackUrl(state.config.update.repo);
            const hint = res.message || "当前版本形态需通过官方下载页获取对应系统安装包";
            updateBgTasks((bg) => ({
              ...bg,
              settings: {
                ...bg.settings,
                updateInfo: bg.settings.updateInfo
                  ? {
                      ...bg.settings.updateInfo,
                      can_auto_stage:
                        res.can_auto_stage ?? bg.settings.updateInfo.can_auto_stage,
                      release_url: releaseUrl,
                      download_url: res.download_url ?? bg.settings.updateInfo.download_url,
                    }
                  : bg.settings.updateInfo,
                updateMessage: hint,
              },
            }));
            pushToast(hint, "info");
          }
        } catch (err) {
          const msg = formatErrorMessage(err);
          updateBgTasks((bg) => ({
            ...bg,
            settings: { ...bg.settings, updateMessage: `下载更新失败：${msg}` },
          }));
          pushToast(`下载更新失败：${msg}`, "warn");
        } finally {
          updateBgTasks((bg) => ({
            ...bg,
            settings: { ...bg.settings, downloadingUpdate: false },
          }));
        }
      },
      { mascot: true }
    );
  },

  async runCoreOperation(
    op: "start" | "stop" | "restart" | "reload" | "hotswap",
    binaryPath?: string
  ): Promise<boolean> {
    if (op === "hotswap" && !binaryPath?.trim()) {
      pushToast("请先输入内核程序的完整路径", "warn");
      return false;
    }
    const existing = inFlightTasks.get("settings:coreOp");
    if (existing) {
      if (state.bgTasks.settings.coreOpBusy !== op) {
        pushToast("已有内核操作正在执行，请稍候", "info");
      }
      return existing as Promise<boolean>;
    }
    return runInFlight(
      "settings:coreOp",
      async () => {
        updateBgTasks((bg) => ({
          ...bg,
          settings: { ...bg.settings, coreOpBusy: op },
        }));
        try {
          if (op === "reload") {
            const outcome = await catcloudApi.reloadCoreConfig(false);
            const rt = await catcloudApi.getRuntimeInfo();
            setState((prev) => ({ ...prev, runtime: rt }));
            if (outcome.rejected || outcome.error) {
              pushToast(
                `热重载未生效：${outcome.error ?? "配置校验未通过"}`,
                "warn"
              );
              return false;
            }
            pushToast("配置已热重载", "ok");
            return true;
          }
          if (op === "hotswap") {
            const res = await catcloudApi.hotSwapCore(binaryPath!.trim());
            const rt = await catcloudApi.getRuntimeInfo();
            setState((prev) => ({ ...prev, runtime: rt }));
            pushToast(
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
          setState((prev) => ({ ...prev, runtime: rt }));
          const labels = {
            start: "内核已启动",
            stop: "内核已停止",
            restart: "内核已重启",
          };
          pushToast(labels[op], "ok");
          return true;
        } catch (err) {
          pushToast(
            op === "hotswap"
              ? `内核热换失败：${formatErrorMessage(err)}`
              : `内核操作失败：${formatErrorMessage(err)}`,
            "warn"
          );
          return false;
        } finally {
          updateBgTasks((bg) => ({
            ...bg,
            settings: { ...bg.settings, coreOpBusy: null },
          }));
        }
      },
      { mascot: "thinking", celebrate: true }
    );
  },

  async runBackupOperation(
    op: "export" | "import",
    fn: () => Promise<void>
  ): Promise<void> {
    const existing = inFlightTasks.get("settings:backupOp");
    if (existing) {
      pushToast("正在处理备份导入/导出，请稍候", "info");
      return existing as Promise<void>;
    }
    return runInFlight(
      "settings:backupOp",
      async () => {
        updateBgTasks((bg) => ({
          ...bg,
          settings: { ...bg.settings, backupBusy: op },
        }));
        try {
          await fn();
        } finally {
          updateBgTasks((bg) => ({
            ...bg,
            settings: { ...bg.settings, backupBusy: null },
          }));
        }
      },
      { mascot: "typing", celebrate: true }
    );
  },

  async startLiveCaptureBg(targetPid: number): Promise<LiveCaptureStartDto | null> {
    captureGen += 1;
    const myGen = captureGen;
    const prevSid = state.bgTasks.capture.sessionId;
    stopLiveCapturePolling();
    updateBgTasks((bg) => ({
      ...bg,
      capture: {
        sessionId: null,
        active: false,
        timedOut: false,
        finishing: false,
        targetName: null,
        status: null,
        outcome: null,
      },
    }));
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
      updateBgTasks((bg) => ({
        ...bg,
        capture: {
          sessionId: started.session_id,
          active: true,
          timedOut: false,
          finishing: false,
          targetName,
          status: initialStatus,
          outcome: null,
        },
      }));
      startLiveCapturePolling(started.session_id, myGen);
      return started;
    } catch (err) {
      if (myGen !== captureGen) {
        return null;
      }
      updateBgTasks((bg) => ({
        ...bg,
        capture: {
          sessionId: null,
          active: false,
          timedOut: false,
          finishing: false,
          targetName: null,
          status: null,
          outcome: null,
        },
      }));
      pushToast(`启动实时捕捉失败：${formatErrorMessage(err)}`, "warn");
      return null;
    }
  },

  async finishLiveCaptureBg(): Promise<LiveCaptureOutcomeDto | null> {
    return runInFlight("capture:finish", async () => {
      const sid =
        state.bgTasks.capture.sessionId ??
        state.bgTasks.capture.status?.session_id ??
        null;
      stopLiveCapturePolling();
      if (!sid) {
        updateBgTasks((bg) => ({
          ...bg,
          capture: {
            sessionId: null,
            active: false,
            timedOut: false,
            finishing: false,
            targetName: bg.capture.outcome ? bg.capture.targetName : null,
            status: null,
            outcome: bg.capture.outcome,
          },
        }));
        return state.bgTasks.capture.outcome;
      }
      const myGen = captureGen;
      updateBgTasks((bg) => ({
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
        updateBgTasks((bg) => ({
          ...bg,
          capture: {
            sessionId: null,
            active: false,
            timedOut: false,
            finishing: false,
            targetName: outcome.target_name || bg.capture.targetName,
            status: null,
            outcome,
          },
        }));
        return outcome;
      } catch (err) {
        if (myGen !== captureGen) {
          return null;
        }
        updateBgTasks((bg) => ({
          ...bg,
          capture: {
            sessionId: null,
            active: false,
            timedOut: false,
            finishing: false,
            targetName: null,
            status: null,
            outcome: null,
          },
        }));
        pushToast(`结束捕捉并整理失败：${formatErrorMessage(err)}`, "warn");
        return null;
      }
    });
  },

  async cancelLiveCaptureBg(): Promise<void> {
    captureGen += 1;
    const sid =
      state.bgTasks.capture.sessionId ??
      state.bgTasks.capture.status?.session_id ??
      null;
    stopLiveCapturePolling();
    updateBgTasks((bg) => ({
      ...bg,
      capture: {
        sessionId: null,
        active: false,
        timedOut: false,
        finishing: false,
        targetName: null,
        status: null,
        outcome: null,
      },
    }));
    if (sid) {
      try {
        await catcloudApi.cancelLiveCaptureSession(sid);
      } catch {
        /* ignore backend cancel cleanup failure */
      }
    }
  },

  clearLiveCaptureOutcome(): void {
    updateBgTasks((bg) => {
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

  setScrollPosition(route: string, top: number): void {
    const normalizedTop = Math.max(0, Math.round(top));
    if (state.sessionDrafts.scrollPositions[route] === normalizedTop) {
      return;
    }
    setState((prev) => ({
      ...prev,
      sessionDrafts: {
        ...prev.sessionDrafts,
        scrollPositions: {
          ...prev.sessionDrafts.scrollPositions,
          [route]: normalizedTop,
        },
      },
    }));
  },

  patchSessionDraft<K extends keyof SessionDraftsState>(
    key: K,
    patch: Partial<SessionDraftsState[K]>
  ): void {
    setState((prev) => {
      const currentSlice = prev.sessionDrafts[key];
      const entries = Object.entries(patch) as Array<[string, unknown]>;
      let changed = false;
      for (const [field, val] of entries) {
        if ((currentSlice as Record<string, unknown>)[field] !== val) {
          changed = true;
          break;
        }
      }
      if (!changed) return prev;
      return {
        ...prev,
        sessionDrafts: {
          ...prev.sessionDrafts,
          [key]: {
            ...currentSlice,
            ...patch,
          },
        },
      };
    });
  },

  showToast: pushToast,
};

export function useAppSelector<T>(selector: (s: AppState) => T): T {
  return useSyncExternalStore(
    appStore.subscribe,
    () => selector(appStore.getState()),
    () => selector(appStore.getState())
  );
}

export function useTrafficVersion(): number {
  return useSyncExternalStore(
    appStore.subscribeTraffic,
    appStore.getTrafficVersion,
    appStore.getTrafficVersion
  );
}

export function useLatestTraffic(): TrafficSample {
  return useSyncExternalStore(
    appStore.subscribeTraffic,
    () => appStore.getState().latestTraffic,
    () => appStore.getState().latestTraffic
  );
}
