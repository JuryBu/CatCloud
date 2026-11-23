import { useSyncExternalStore } from "react";
import {
  type AppConfig,
  type CoreRuntimeInfo,
  DEFAULT_APP_CONFIG,
  type ExitIpInfo,
  type MultiGroup,
  type PreAccelRelay,
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
  isTauriEnv,
} from "../api/tauri";

export type {
  AppConfig,
  CoreRuntimeInfo,
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
  | "settings";

export type WindowMode = "main" | "capsule";

export interface ToastNotice {
  id: number;
  text: string;
  tone: "info" | "ok" | "warn";
}

export const TRAFFIC_HISTORY_CAPACITY = 300;
const UI_PREFS_STORAGE_KEY = "catcloud.ui.prefs.v1";

/**
 * Fixed-length 300-point Float64Array ring buffer (2s x 300 = 10 minutes).
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
  "settings",
]);

function detectNavFromHash(): NavRouteId {
  if (typeof window === "undefined") return "overview";
  const raw = window.location.hash.replace(/^#\/?/, "").toLowerCase() as NavRouteId;
  return VALID_ROUTES.has(raw) ? raw : "overview";
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
        theme_mode: p.theme_mode,
        animations_enabled: p.animations_enabled,
        mascot_enabled: p.mascot_enabled,
        sparkline_enabled: p.sparkline_enabled,
        wallpaper_opacity: p.wallpaper_opacity,
        glass_blur_px: p.glass_blur_px,
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
  root.setAttribute("data-theme", resolvedTheme);
  root.setAttribute("data-animations", p.animations_enabled ? "on" : "off");
  if (windowMode === "capsule") {
    root.setAttribute("data-window", "capsule");
  } else {
    root.removeAttribute("data-window");
  }

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

export interface AppState {
  initialized: boolean;
  isTauri: boolean;
  windowMode: WindowMode;
  activeNav: NavRouteId;
  settingsTabHint: "system" | "appearance" | "dns" | "core" | "updates" | null;
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
  subscriptions: SubscriptionRecord[];
  preAccelRelays: PreAccelRelay[];
  exitIp: ExitIpInfo;
  quickSites: SiteCheckItem[];
  latestTraffic: TrafficSample;
  trafficVersion: number;
  toast: ToastNotice | null;
  tunAdminPromptOpen: boolean;
  tunAdminPromptBusy: boolean;
  tunAdminPromptReason: string | null;
}

const runningInTauri = isTauriEnv();
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
  memory_mb: 0,
  timestamp_ms: 0,
};

let initialTraffic: TrafficSample = EMPTY_TRAFFIC;
let initialTrafficVersion = 0;
if (!runningInTauri) {
  const seedSamples = generateSeedTrafficSamples(75, 2000);
  for (const s of seedSamples) {
    trafficBuffer.push(s.up_bps, s.down_bps, s.timestamp_ms);
  }
  initialTraffic = seedSamples[seedSamples.length - 1] ?? EMPTY_TRAFFIC;
  initialTrafficVersion = seedSamples.length;
}

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
      preaccel_relay_name: null,
      captive_portal_required: false,
      system_proxy_enabled: false,
      tun_enabled: false,
      tun_admin_ready: false,
      app_version: "0.1.0",
      os_label: "Windows",
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
      preaccel_relay_name: "CN-East-443 Primary",
      captive_portal_required: false,
      system_proxy_enabled: initialConfig.system_proxy_enabled,
      tun_enabled: initialConfig.tun_enabled,
      tun_admin_ready: true,
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

let state: AppState = {
  initialized: false,
  isTauri: runningInTauri,
  windowMode: initialWindowMode,
  activeNav: detectNavFromHash(),
  settingsTabHint: null,
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
  subscriptions: [],
  preAccelRelays: [],
  exitIp: initialExitIp,
  quickSites: [],
  latestTraffic: initialTraffic,
  trafficVersion: initialTrafficVersion,
  toast: null,
  tunAdminPromptOpen: false,
  tunAdminPromptBusy: false,
  tunAdminPromptReason: null,
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

let toastTimer: number | null = null;
let mascotResetTimer: number | null = null;
let toastSeq = 0;

function pushToast(text: string, tone: ToastNotice["tone"] = "info"): void {
  toastSeq += 1;
  const id = toastSeq;
  setState((prev) => ({ ...prev, toast: { id, text, tone } }));
  if (toastTimer !== null) {
    window.clearTimeout(toastTimer);
  }
  toastTimer = window.setTimeout(() => {
    toastTimer = null;
    setState((prev) => (prev.toast?.id === id ? { ...prev, toast: null } : prev));
  }, 3000);
}

let bootStarted = false;
let startupPageApplied = false;
let userNavigatedManually = false;
let personalizationReqSeq = 0;
let disposeTraffic: (() => void) | null = null;
let disposeRuntime: (() => void) | null = null;
let disposeProbeProgress: (() => void) | null = null;
let disposeTunNeedsAdmin: (() => void) | null = null;
let themeClockTimer: number | null = null;

function syncResolvedThemeFromClock(): void {
  const p = state.config.personalization;
  const resolved = resolveThemeBySchedule(p.theme_mode, p.theme_schedule);
  applyPersonalizationToDom(resolved, p, state.windowMode);
  if (resolved !== state.resolvedTheme) {
    setState((prev) => ({ ...prev, resolvedTheme: resolved }));
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
  }
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
    exitIpRes,
    quickSitesRes,
  ] = results;

  const cfg = cfgRes.status === "fulfilled" ? cfgRes.value : state.config;
  const mergedConfig: AppConfig = inDesktop
    ? cfg
    : {
        ...cfg,
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
  void ensureLocalWallpaperLoaded(
    mergedConfig.personalization.wallpaper_path,
    resolved,
    mergedConfig.personalization,
    state.windowMode
  );

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
    if (rawStartup && VALID_ROUTES.has(rawStartup as NavRouteId)) {
      startupNav = rawStartup as NavRouteId;
    }
  }
  startupPageApplied = true;

  setState((prev) => ({
    ...prev,
    initialized: true,
    activeNav: startupNav ?? prev.activeNav,
    config: mergedConfig,
    resolvedTheme: resolved,
    runtime: runtimeRes.status === "fulfilled" ? runtimeRes.value : prev.runtime,
    groups: groupsRes.status === "fulfilled" ? groupsRes.value : prev.groups,
    nodes: nodesRes.status === "fulfilled" ? nodesRes.value : prev.nodes,
    probes: probesRes.status === "fulfilled" ? probesRes.value : prev.probes,
    subscriptions: subsRes.status === "fulfilled" ? subsRes.value : prev.subscriptions,
    preAccelRelays: relaysRes.status === "fulfilled" ? relaysRes.value : prev.preAccelRelays,
    exitIp:
      !inDesktop && exitIpRes.status === "fulfilled" && exitIpRes.value
        ? exitIpRes.value
        : prev.exitIp,
    quickSites: hydratedSites,
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
      document.addEventListener("visibilitychange", handleVisibilityChange);

      themeClockTimer = window.setInterval(() => {
        if (
          document.visibilityState === "visible" &&
          state.config.personalization.theme_mode === "auto_time"
        ) {
          syncResolvedThemeFromClock();
        }
      }, 60_000);
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
      setState((prev) => ({ ...prev, runtime: info }));
    });

    disposeProbeProgress = catcloudApi.subscribeProbeProgress((ev) => {
      setState((prev) => {
        const nextProbes =
          ev.node_id && ev.snapshot
            ? {
                ...prev.probes,
                [ev.node_id]: mergeProbeSnapshotSafe(prev.probes[ev.node_id], ev.snapshot),
              }
            : prev.probes;
        return {
          ...prev,
          probes: nextProbes,
          mascotState: ev.done ? "idle" : "searching",
          probeProgress: {
            running: !ev.done,
            completed: ev.completed,
            total: ev.total,
            currentNodeName: ev.done ? null : ev.node_name,
            cancelled: ev.cancelled,
          },
        };
      });
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
            setState((prev) => ({
              ...prev,
              runtime: { ...prev.runtime, tun_admin_ready: false },
            }));
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
    disposeTunNeedsAdmin?.();
    disposeTunNeedsAdmin = null;
    if (typeof window !== "undefined") {
      window.removeEventListener("hashchange", handleHashChange);
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
    bootStarted = false;
    startupPageApplied = false;
    userNavigatedManually = false;
  },
};

export const appActions = {
  setNav(nav: NavRouteId): void {
    userNavigatedManually = true;
    if (typeof window !== "undefined" && state.windowMode === "main") {
      const targetHash = `#${nav}`;
      if (window.location.hash !== targetHash) {
        window.history.replaceState(null, "", targetHash);
      }
    }
    setState((prev) => (prev.activeNav === nav ? prev : { ...prev, activeNav: nav }));
  },

  openSettingsTab(tab: "system" | "appearance" | "dns" | "core" | "updates"): void {
    setState((prev) => ({ ...prev, settingsTabHint: tab }));
    appActions.setNav("settings");
  },

  consumeSettingsTabHint(): void {
    setState((prev) => (prev.settingsTabHint === null ? prev : { ...prev, settingsTabHint: null }));
  },

  setMascotState(next: MascotState): void {
    setState((prev) => (prev.mascotState === next ? prev : { ...prev, mascotState: next }));
  },

  syncConfig(nextConfig: AppConfig): void {
    const resolved = resolveThemeBySchedule(
      nextConfig.personalization.theme_mode,
      nextConfig.personalization.theme_schedule
    );
    applyPersonalizationToDom(resolved, nextConfig.personalization, state.windowMode);
    setState((prev) => ({ ...prev, config: nextConfig, resolvedTheme: resolved }));
  },

  syncRuntime(nextRuntime: CoreRuntimeInfo): void {
    setState((prev) => ({ ...prev, runtime: nextRuntime }));
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
      setState((prev) => ({ ...prev, config: saved, resolvedTheme: savedResolved }));
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
          pushToast("演示模式：已模拟管理员提权并开启虚拟网卡", "ok");
        } else {
          setState((prev) => ({
            ...prev,
            tunAdminPromptOpen: false,
            tunAdminPromptBusy: false,
            tunAdminPromptReason: null,
          }));
          pushToast("已拉起管理员实例，正在接管并开启虚拟网卡…", "ok");
        }
        return true;
      }
      setState((prev) => ({
        ...prev,
        tunAdminPromptOpen: false,
        tunAdminPromptBusy: false,
        tunAdminPromptReason: null,
      }));
      pushToast("已取消管理员授权，虚拟网卡未开启", "info");
      return false;
    } catch (err) {
      setState((prev) => ({ ...prev, tunAdminPromptBusy: false }));
      pushToast(`管理员重启失败：${formatErrorMessage(err)}`, "warn");
      return false;
    }
  },

  async toggleTun(next?: boolean, silent = false): Promise<boolean> {
    const target = next ?? !state.runtime.tun_enabled;
    if (target && state.runtime.tun_admin_ready === false) {
      appActions.openTunAdminPrompt(null);
      return false;
    }
    try {
      const applied = await catcloudApi.toggleTun(target);
      setState((prev) => ({
        ...prev,
        config: { ...prev.config, tun_enabled: applied },
        runtime: { ...prev.runtime, tun_enabled: applied },
      }));
      if (!silent) {
        pushToast(applied ? "虚拟网卡已开启" : "虚拟网卡已关闭", applied ? "ok" : "info");
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
          runtime: { ...prev.runtime, tun_admin_ready: false },
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
      if (mascotResetTimer !== null) {
        window.clearTimeout(mascotResetTimer);
      }
      mascotResetTimer = window.setTimeout(() => {
        mascotResetTimer = null;
        setState((prev) =>
          prev.mascotState === "complete" ? { ...prev, mascotState: "idle" } : prev
        );
      }, 1800);
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
    setState((prev) => ({ ...prev, mascotState: "searching" }));
    try {
      const quickSites = await catcloudApi.checkQuickSites();
      setState((prev) => ({ ...prev, quickSites, mascotState: "idle" }));
      pushToast("快捷站点连通性已刷新", "ok");
    } catch (err) {
      setState((prev) => ({ ...prev, mascotState: "idle" }));
      pushToast(`刷新快捷站点失败：${formatErrorMessage(err)}`, "warn");
    }
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
