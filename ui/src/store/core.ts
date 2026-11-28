import {
  type AppConfig,
  type CoreRuntimeInfo,
  DEFAULT_APP_CONFIG,
  DEFAULT_GLOBAL_PREACCEL_STATUS,
  type ExitIpInfo,
  type PendingUpdatePromptDto,
  type ProbeKind,
  type ResolvedTheme,
  type TrafficSample,
  catcloudApi,
  generateSeedTrafficSamples,
  hasPreviewTunNeedsAdminFlag,
  isTauriEnv,
} from "../api/tauri";
import { detectNavigatorOs } from "../utils/platform";
import {
  detectNavFromHash,
  detectWindowModeFromLocation,
  disposeWallpaperCache,
  ensureLocalWallpaperLoaded,
  loadCachedUiPrefs,
  resolveThemeBySchedule,
  saveCachedUiPrefs,
  setPendingOnboardingSync,
} from "./themeWallpaper";
import {
  EMPTY_TRAFFIC,
  TRAFFIC_HISTORY_CAPACITY,
  TrafficRingBuffer,
} from "./trafficRingBuffer";
import {
  type AppState,
  type BgTasksState,
  type MascotState,
  type ToastNotice,
  createInitialBgTasks,
  createInitialSessionDrafts,
} from "./types";

/* ============================================================================
 * Pure Config Reconciliation Helpers
 * ============================================================================ */

export function mergeIncomingAppConfig(
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
  const skippedVersion =
    incoming.update?.skipped_version !== undefined
      ? incoming.update.skipped_version
      : (prev.update.skipped_version ?? null);
  return {
    ...incoming,
    behavior: incoming.behavior ?? prev.behavior,
    update: {
      ...incoming.update,
      auto_download: autoDownload,
      skipped_version: skippedVersion,
    },
  };
}

export function alignConfigWithRuntimeTun(
  config: AppConfig,
  runtime: CoreRuntimeInfo
): AppConfig {
  if (
    typeof runtime.tun_configured === "boolean" &&
    config.tun_enabled !== runtime.tun_configured
  ) {
    return { ...config, tun_enabled: runtime.tun_configured };
  }
  return config;
}

/* ============================================================================
 * Initial Store State Construction
 * ============================================================================ */

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
      system_proxy_enabled: previewTunNeedsAdmin
        ? true
        : DEFAULT_APP_CONFIG.system_proxy_enabled,
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

/* ============================================================================
 * Store Core Kernel (Zero Reverse Imports from actions/* or appStore.ts)
 * ============================================================================ */

let state: AppState = {
  initialized: false,
  isTauri: runningInTauri,
  windowMode: initialWindowMode,
  activeNav: detectNavFromHash(),
  aiRouteHint: null,
  settingsTabHint: null,
  settingsOpenAgentDocs: false,
  multiGroupCreateHint: null,
  geoRuleContext: {
    domesticDirectEnabled: true,
    customRulesOnly: false,
    geodataMode: false,
  },
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
  onboardingHydratedOk: false,
  onboardingModalOpen: false,
  onboardingAutoSkipped: false,
  tunAdminPromptOpen: false,
  tunAdminPromptBusy: false,
  tunAdminPromptReason: null,
  pendingUpdate: null,
  updateModalVisible: false,
  danglingRulesAudit: null,
  repairingDanglingRules: false,
  bgTasks: createInitialBgTasks(),
  sessionDrafts: createInitialSessionDrafts(),
};

const listeners = new Set<() => void>();
const trafficListeners = new Set<() => void>();
const inFlightTasks = new Map<string, Promise<unknown>>();

// Internal traffic snapshot & hidden-state deferral tracking
let latestTrafficSnapshot: TrafficSample = initialTraffic;
let trafficVersionCounter = initialTrafficVersion;
let trafficDirtyWhileHidden = false;
let stateDirtyWhileHidden = false;

// Shared lightweight coordination primitives
let toastTimer: number | null = null;
let mascotResetTimer: number | null = null;
let toastSeq = 0;
let toastShownAt = 0;
let toastQueue: Array<{ text: string; tone: ToastNotice["tone"]; durationMs: number }> = [];
let activeMascotTaskCount = 0;
let knownLatencyProbeIds: Set<string> = new Set(["builtin_latency"]);
let probePendingQueue: string[] = [];
let probePauseRequested = false;
let probeBatchFlusher: (() => void) | null = null;
let bootStarted = false;
let startupPageApplied = false;
let userNavigatedManually = false;
let personalizationReqSeq = 0;

function isDocumentHidden(): boolean {
  return typeof document !== "undefined" && document.hidden === true;
}

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
  stateDirtyWhileHidden = false;
  emitState();
}

/**
 * Update in-memory state immediately, but defer React subscriber notifications
 * while the window is hidden (`document.hidden === true`). Flushed automatically
 * on visibility restore via `flushHiddenPending()`.
 */
function setStateDeferredIfHidden(updater: (prev: AppState) => AppState): void {
  const next = updater(state);
  if (next === state) return;
  state = next;
  if (isDocumentHidden()) {
    stateDirtyWhileHidden = true;
    return;
  }
  stateDirtyWhileHidden = false;
  emitState();
}

function updateBgTasks(updater: (prev: BgTasksState) => BgTasksState): void {
  setState((prev) => {
    const nextBg = updater(prev.bgTasks);
    if (nextBg === prev.bgTasks) return prev;
    return { ...prev, bgTasks: nextBg };
  });
}

function flushHiddenPending(): void {
  let flushedTraffic = false;
  if (trafficDirtyWhileHidden) {
    trafficDirtyWhileHidden = false;
    state = {
      ...state,
      latestTraffic: latestTrafficSnapshot,
      trafficVersion: trafficVersionCounter,
    };
    flushedTraffic = true;
  }
  if (stateDirtyWhileHidden) {
    stateDirtyWhileHidden = false;
    emitState();
  }
  if (flushedTraffic) {
    emitTraffic();
  }
}

function recordLiveTrafficSample(sample: TrafficSample): void {
  trafficBuffer.push(sample.up_bps, sample.down_bps, sample.timestamp_ms);
  latestTrafficSnapshot = sample;
  trafficVersionCounter += 1;
  if (isDocumentHidden()) {
    // Avoid cloning the entire AppState every second while minimized/hidden.
    trafficDirtyWhileHidden = true;
    return;
  }
  trafficDirtyWhileHidden = false;
  state = {
    ...state,
    latestTraffic: sample,
    trafficVersion: trafficVersionCounter,
  };
  emitTraffic();
}

function recordTrafficStopSample(forceEmit = false): void {
  const stopTs = Date.now();
  if (trafficBuffer.length > 0) {
    trafficBuffer.push(0, 0, stopTs);
  }
  const stoppedSample: TrafficSample = {
    ...latestTrafficSnapshot,
    up_bps: 0,
    down_bps: 0,
    connections: 0,
    tunnel_connections: 0,
    memory_mb: 0,
    timestamp_ms: stopTs,
  };
  latestTrafficSnapshot = stoppedSample;
  trafficVersionCounter += 1;
  if (!forceEmit && isDocumentHidden()) {
    trafficDirtyWhileHidden = true;
    return;
  }
  trafficDirtyWhileHidden = false;
  state = {
    ...state,
    latestTraffic: stoppedSample,
    trafficVersion: trafficVersionCounter,
  };
  emitTraffic();
}

function resetTrafficSession(forceEmit = false): void {
  trafficBuffer.clear();
  const freshSample: TrafficSample = { ...EMPTY_TRAFFIC, timestamp_ms: Date.now() };
  latestTrafficSnapshot = freshSample;
  trafficVersionCounter += 1;
  if (!forceEmit && isDocumentHidden()) {
    trafficDirtyWhileHidden = true;
    return;
  }
  trafficDirtyWhileHidden = false;
  state = {
    ...state,
    latestTraffic: freshSample,
    trafficVersion: trafficVersionCounter,
  };
  emitTraffic();
}

function commitBackfilledTraffic(nextLatest: TrafficSample): void {
  latestTrafficSnapshot = nextLatest;
  trafficVersionCounter += 1;
  trafficDirtyWhileHidden = false;
  state = {
    ...state,
    latestTraffic: nextLatest,
    trafficVersion: trafficVersionCounter,
  };
  emitTraffic();
}

/* ============================================================================
 * Toast Queue & Mascot Busy Ref-Counting
 * ============================================================================ */

function showToastNow(item: {
  text: string;
  tone: ToastNotice["tone"];
  durationMs: number;
}): void {
  toastSeq += 1;
  const id = toastSeq;
  toastShownAt = Date.now();
  setState((prev) => ({ ...prev, toast: { id, text: item.text, tone: item.tone } }));
  if (typeof window === "undefined") return;
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

function beginMascotBusy(mode: MascotState = "searching"): void {
  activeMascotTaskCount += 1;
  if (mascotResetTimer !== null && typeof window !== "undefined") {
    window.clearTimeout(mascotResetTimer);
    mascotResetTimer = null;
  }
  setState((prev) => (prev.mascotState === mode ? prev : { ...prev, mascotState: mode }));
}

function celebrateMascotComplete(durationMs = 4000): void {
  if (activeMascotTaskCount > 0 || state.probeProgress.running) {
    return;
  }
  if (mascotResetTimer !== null && typeof window !== "undefined") {
    window.clearTimeout(mascotResetTimer);
    mascotResetTimer = null;
  }
  setStateDeferredIfHidden((prev) =>
    prev.mascotState === "complete" ? prev : { ...prev, mascotState: "complete" }
  );
  if (typeof window !== "undefined") {
    mascotResetTimer = window.setTimeout(() => {
      mascotResetTimer = null;
      if (activeMascotTaskCount === 0 && !state.probeProgress.running) {
        setStateDeferredIfHidden((prev) =>
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

/* ============================================================================
 * Shared Slice Patchers & Wallpaper/Onboarding Helpers
 * ============================================================================ */

function patchUpdateSlice(patch: {
  pendingUpdate?: PendingUpdatePromptDto | null;
  updateModalVisible?: boolean;
  skippedVersion?: string | null;
  settingsPatch?: Partial<BgTasksState["settings"]>;
}): void {
  setState((prev) => ({
    ...prev,
    ...(patch.pendingUpdate !== undefined ? { pendingUpdate: patch.pendingUpdate } : {}),
    ...(patch.updateModalVisible !== undefined
      ? { updateModalVisible: patch.updateModalVisible }
      : {}),
    ...(patch.skippedVersion !== undefined
      ? {
          config: {
            ...prev.config,
            update: { ...prev.config.update, skipped_version: patch.skippedVersion },
          },
        }
      : {}),
    ...(patch.settingsPatch
      ? {
          bgTasks: {
            ...prev.bgTasks,
            settings: { ...prev.bgTasks.settings, ...patch.settingsPatch },
          },
        }
      : {}),
  }));
}

function patchSettingsBg(settingsPatch: Partial<BgTasksState["settings"]>): void {
  patchUpdateSlice({ settingsPatch });
}

function syncKnownLatencyProbeIds(
  defs: ReadonlyArray<{ id: string; kind: ProbeKind }>
): void {
  const next = new Set<string>(["builtin_latency"]);
  for (const def of defs) {
    if (def.kind === "latency" && def.id.trim().length > 0) {
      next.add(def.id.trim());
    }
  }
  knownLatencyProbeIds = next;
}

function syncWallpaperForConfig(
  rawPath: string | null | undefined,
  resolvedTheme: ResolvedTheme,
  personalization: AppConfig["personalization"],
  windowMode = state.windowMode
): Promise<void> {
  return ensureLocalWallpaperLoaded(rawPath, resolvedTheme, personalization, windowMode, {
    getCurrentWallpaperPath: () => state.config.personalization.wallpaper_path,
    setWallpaperState: (patch) => {
      setState((prev) => {
        const nextPreview =
          patch.wallpaperPreviewUrl !== undefined
            ? patch.wallpaperPreviewUrl
            : prev.wallpaperPreviewUrl;
        const nextError =
          patch.wallpaperError !== undefined ? patch.wallpaperError : prev.wallpaperError;
        if (prev.wallpaperPreviewUrl === nextPreview && prev.wallpaperError === nextError) {
          return prev;
        }
        return {
          ...prev,
          wallpaperPreviewUrl: nextPreview,
          wallpaperError: nextError,
        };
      });
    },
  });
}

async function persistOnboardingCompletedLight(): Promise<void> {
  const nextPersonalization: AppConfig["personalization"] = {
    ...state.config.personalization,
    onboarding_completed: true,
  };
  saveCachedUiPrefs(nextPersonalization);
  setPendingOnboardingSync(true);
  setState((prev) => ({
    ...prev,
    config: {
      ...prev.config,
      personalization: {
        ...prev.config.personalization,
        onboarding_completed: true,
      },
    },
  }));
  try {
    await catcloudApi.markOnboardingCompleted();
    setPendingOnboardingSync(false);
  } catch {
    /* Keep local optimistic pending-sync fallback so onboarding never re-pops on next launch */
  }
}

function resetCoreRuntimeOnDispose(): void {
  if (typeof window !== "undefined") {
    if (toastTimer !== null) {
      window.clearTimeout(toastTimer);
      toastTimer = null;
    }
    if (mascotResetTimer !== null) {
      window.clearTimeout(mascotResetTimer);
      mascotResetTimer = null;
    }
  }
  toastQueue = [];
  inFlightTasks.clear();
  probePendingQueue = [];
  probePauseRequested = false;
  probeBatchFlusher = null;
  activeMascotTaskCount = 0;
  bootStarted = false;
  startupPageApplied = false;
  userNavigatedManually = false;
  trafficDirtyWhileHidden = false;
  stateDirtyWhileHidden = false;
  disposeWallpaperCache();
}

export const storeCore = {
  getState(): AppState {
    return state;
  },
  setState,
  setStateDeferredIfHidden,
  updateBgTasks,
  isDocumentHidden,
  flushHiddenPending,
  subscribe(listener: () => void): () => void {
    listeners.add(listener);
    return () => listeners.delete(listener);
  },
  subscribeTraffic(listener: () => void): () => void {
    trafficListeners.add(listener);
    return () => trafficListeners.delete(listener);
  },
  emitState,
  emitTraffic,
  getTrafficBuffer(): TrafficRingBuffer {
    return trafficBuffer;
  },
  getTrafficVersion(): number {
    return trafficVersionCounter;
  },
  getLatestTraffic(): TrafficSample {
    return latestTrafficSnapshot;
  },
  recordLiveTrafficSample,
  recordTrafficStopSample,
  resetTrafficSession,
  commitBackfilledTraffic,
  pushToast,
  beginMascotBusy,
  endMascotBusy,
  celebrateMascotComplete,
  getActiveMascotTaskCount(): number {
    return activeMascotTaskCount;
  },
  inFlightTasks,
  runInFlight,
  patchUpdateSlice,
  patchSettingsBg,
  getKnownLatencyProbeIds(): ReadonlySet<string> {
    return knownLatencyProbeIds;
  },
  syncKnownLatencyProbeIds,
  getProbePendingQueue(): string[] {
    return probePendingQueue;
  },
  setProbePendingQueue(ids: string[]): void {
    probePendingQueue = ids;
  },
  removeFromProbePendingQueue(nodeId: string): void {
    probePendingQueue = probePendingQueue.filter((id) => id !== nodeId);
  },
  isProbePauseRequested(): boolean {
    return probePauseRequested;
  },
  setProbePauseRequested(flag: boolean): void {
    probePauseRequested = flag;
  },
  registerProbeBatchFlusher(flusher: (() => void) | null): void {
    probeBatchFlusher = flusher;
  },
  flushProbeBatch(): void {
    probeBatchFlusher?.();
  },
  isBootStarted(): boolean {
    return bootStarted;
  },
  setBootStarted(flag: boolean): void {
    bootStarted = flag;
  },
  isStartupPageApplied(): boolean {
    return startupPageApplied;
  },
  setStartupPageApplied(flag: boolean): void {
    startupPageApplied = flag;
  },
  isUserNavigatedManually(): boolean {
    return userNavigatedManually;
  },
  setUserNavigatedManually(flag: boolean): void {
    userNavigatedManually = flag;
  },
  nextPersonalizationReqSeq(): number {
    personalizationReqSeq += 1;
    return personalizationReqSeq;
  },
  getPersonalizationReqSeq(): number {
    return personalizationReqSeq;
  },
  syncWallpaperForConfig,
  persistOnboardingCompletedLight,
  resetCoreRuntimeOnDispose,
};

export type StoreCore = typeof storeCore;
