import {
  type AppConfig,
  type CoreRuntimeInfo,
  type GlobalPreAccelStatus,
  type PendingUpdatePromptDto,
  type SiteCheckItem,
  catcloudApi,
  formatErrorMessage,
  hasPreviewUpdateModalFlag,
  isTauriEnv,
} from "../api/tauri";
import {
  normalizePreAccelInstallState,
  normalizePreAccelVerifyState,
} from "../utils/preaccelStatus";
import { type StoreCore, alignConfigWithRuntimeTun, mergeIncomingAppConfig } from "./core";
import { createProbeProgressBatcher } from "./probeBatcher";
import {
  UI_PREFS_STORAGE_KEY,
  VALID_ROUTES,
  applyPersonalizationToDom,
  detectNavFromHash,
  detectWindowModeFromLocation,
  hasExplicitRouteHash,
  hasPendingOnboardingSync,
  loadCachedUiPrefs,
  normalizeAllowedNavRoute,
  resolveThemeBySchedule,
  saveCachedUiPrefs,
  setPendingOnboardingSync,
} from "./themeWallpaper";
import { TRAFFIC_HISTORY_CAPACITY } from "./trafficRingBuffer";
import { type NavRouteId, buildPendingExitIp } from "./types";

export interface BootstrapDeps {
  setNav: (nav: NavRouteId) => void;
  refreshRuntime: () => Promise<CoreRuntimeInfo | null>;
  refreshGlobalPreAccelStatus: () => Promise<GlobalPreAccelStatus>;
  refreshPendingUpdate: () => Promise<PendingUpdatePromptDto | null>;
  loadGeodataStatus: (force?: boolean) => Promise<void>;
  openTunAdminPrompt: (reason?: string | null) => void;
  pollLiveCaptureIfActive: () => void;
  disposeProbeRuntime: () => void;
  disposeCaptureRuntime: () => void;
  resetPreAccelRuntime: () => void;
}

export function createStoreBootstrap(core: StoreCore, deps: BootstrapDeps) {
  let disposeTraffic: (() => void) | null = null;
  let disposeRuntime: (() => void) | null = null;
  let disposeProbeProgress: (() => void) | null = null;
  let disposeStrategySwitch: (() => void) | null = null;
  let disposeConfigUpdate: (() => void) | null = null;
  let disposeTunNeedsAdmin: (() => void) | null = null;
  let disposeUpdateReady: (() => void) | null = null;
  let disposeGroupsUpdated: (() => void) | null = null;
  let disposeRelaysUpdated: (() => void) | null = null;
  let disposeNodesUpdated: (() => void) | null = null;
  let disposeNavigate: (() => void) | null = null;

  let groupsRefreshDebounceTimer: number | null = null;
  let relaysRefreshDebounceTimer: number | null = null;
  let nodesRefreshDebounceTimer: number | null = null;
  let groupsRefreshSeq = 0;
  let relaysRefreshSeq = 0;
  let nodesRefreshSeq = 0;
  let themeClockTimer: number | null = null;
  let trafficBackfillInFlight = false;
  let globalPreAccelDirtyWhileHidden = false;

  const probeBatcher = createProbeProgressBatcher(core);

  function scheduleGroupsRefresh(): void {
    if (typeof window === "undefined") {
      const mySeq = ++groupsRefreshSeq;
      void catcloudApi
        .listGroups()
        .then((latestGroups) => {
          if (!core.isBootStarted() || mySeq !== groupsRefreshSeq) return;
          core.setState((prev) => ({ ...prev, groups: latestGroups }));
        })
        .catch(() => {
          /* ignore transient cross-window group refresh error */
        });
      return;
    }
    if (groupsRefreshDebounceTimer !== null) {
      window.clearTimeout(groupsRefreshDebounceTimer);
    }
    groupsRefreshDebounceTimer = window.setTimeout(() => {
      groupsRefreshDebounceTimer = null;
      const mySeq = ++groupsRefreshSeq;
      void catcloudApi
        .listGroups()
        .then((latestGroups) => {
          if (!core.isBootStarted() || mySeq !== groupsRefreshSeq) return;
          core.setState((prev) => ({ ...prev, groups: latestGroups }));
        })
        .catch(() => {
          /* ignore transient cross-window group refresh error */
        });
    }, 100);
  }

  function scheduleRelaysRefresh(): void {
    if (typeof window === "undefined") {
      const mySeq = ++relaysRefreshSeq;
      void catcloudApi
        .listPreAccelRelays()
        .then((latestRelays) => {
          if (!core.isBootStarted() || mySeq !== relaysRefreshSeq) return;
          core.setState((prev) => ({ ...prev, preAccelRelays: latestRelays }));
        })
        .catch(() => {
          /* ignore transient cross-window relay refresh error */
        });
      return;
    }
    if (relaysRefreshDebounceTimer !== null) {
      window.clearTimeout(relaysRefreshDebounceTimer);
    }
    relaysRefreshDebounceTimer = window.setTimeout(() => {
      relaysRefreshDebounceTimer = null;
      const mySeq = ++relaysRefreshSeq;
      void catcloudApi
        .listPreAccelRelays()
        .then((latestRelays) => {
          if (!core.isBootStarted() || mySeq !== relaysRefreshSeq) return;
          core.setState((prev) => ({ ...prev, preAccelRelays: latestRelays }));
        })
        .catch(() => {
          /* ignore transient cross-window relay refresh error */
        });
    }, 100);
  }

  function runNodesRefreshNow(): void {
    const mySeq = ++nodesRefreshSeq;
    void Promise.allSettled([
      catcloudApi.listNodes(),
      catcloudApi.listSubscriptions(),
      catcloudApi.listProbeSnapshots(),
      deps.refreshRuntime(),
    ]).then(([nodesRes, subsRes, probesRes]) => {
      if (!core.isBootStarted() || mySeq !== nodesRefreshSeq) return;
      core.setState((prev) => ({
        ...prev,
        nodes: nodesRes.status === "fulfilled" ? nodesRes.value : prev.nodes,
        subscriptions: subsRes.status === "fulfilled" ? subsRes.value : prev.subscriptions,
        probes: probesRes.status === "fulfilled" ? probesRes.value : prev.probes,
      }));
    });
  }

  function scheduleNodesRefresh(): void {
    if (typeof window === "undefined") {
      runNodesRefreshNow();
      return;
    }
    if (nodesRefreshDebounceTimer !== null) {
      window.clearTimeout(nodesRefreshDebounceTimer);
    }
    nodesRefreshDebounceTimer = window.setTimeout(() => {
      nodesRefreshDebounceTimer = null;
      runNodesRefreshNow();
    }, 200);
  }

  function syncResolvedThemeFromClock(): void {
    const cur = core.getState();
    const p = cur.config.personalization;
    const resolved = resolveThemeBySchedule(p.theme_mode, p.theme_schedule);
    applyPersonalizationToDom(resolved, p, cur.windowMode);
    if (resolved !== cur.resolvedTheme) {
      core.setState((prev) => ({ ...prev, resolvedTheme: resolved }));
    }
  }

  async function backfillTrafficHistory(coreRunning: boolean): Promise<void> {
    if (!isTauriEnv() || !coreRunning || trafficBackfillInFlight) return;
    trafficBackfillInFlight = true;
    try {
      const history = await catcloudApi.getTrafficHistory();
      if (history.length === 0) return;

      const trafficBuffer = core.getTrafficBuffer();
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
      const latestLive = core.getLatestTraffic();
      const hasNewerLive = latestLive.timestamp_ms > lastHist.timestamp_ms;
      const nextLatest = hasNewerLive
        ? {
            ...latestLive,
            up_bps: newest ? newest.up : latestLive.up_bps,
            down_bps: newest ? newest.down : latestLive.down_bps,
            timestamp_ms: newest ? newest.ts : latestLive.timestamp_ms,
          }
        : {
            ...latestLive,
            up_bps: newest ? newest.up : lastHist.up_bps,
            down_bps: newest ? newest.down : lastHist.down_bps,
            up_total_bytes: lastHist.up_total_bytes || latestLive.up_total_bytes,
            down_total_bytes: lastHist.down_total_bytes || latestLive.down_total_bytes,
            connections: lastHist.connections,
            tunnel_connections: lastHist.tunnel_connections ?? 0,
            memory_mb: lastHist.memory_mb,
            timestamp_ms: newest ? newest.ts : lastHist.timestamp_ms,
          };
      core.commitBackfilledTraffic(nextLatest);
    } catch {
      /* ignore optional history backfill failure on older backend */
    } finally {
      trafficBackfillInFlight = false;
    }
  }

  function handleHashChange(): void {
    const nextWindowMode = detectWindowModeFromLocation();
    const nextNav = detectNavFromHash();
    core.setState((prev) => ({
      ...prev,
      windowMode: nextWindowMode,
      activeNav: nextWindowMode === "main" ? nextNav : prev.activeNav,
    }));
    const cur = core.getState();
    applyPersonalizationToDom(cur.resolvedTheme, cur.config.personalization, nextWindowMode);
  }

  /**
   * Visibility restoration guard:
   * 1. Immediately flush hidden-period pending state and re-emit traffic for canvas repaint.
   * 2. Actively call `refreshRuntime()` (`catcloudApi.getRuntimeInfo()`) to recover any
   *    backend suppressed runtime snapshots, then backfill traffic history based on the
   *    LATEST `runtime.running`.
   * 3. Trigger an immediate `pollOnce()` if a live capture session is active.
   * Wallpaper CSS variables are never torn down while hidden (no solid-color flash on restore).
   */
  function handleVisibilityChange(): void {
    if (typeof document === "undefined" || document.visibilityState !== "visible") {
      return;
    }

    // 1. Flush deferred state & traffic updates accumulated while hidden
    core.flushHiddenPending();
    syncResolvedThemeFromClock();
    core.emitTraffic();

    // 2. Actively refresh runtime from backend & backfill traffic based on latest running state
    if (isTauriEnv()) {
      void (async () => {
        const latestRuntime = await deps.refreshRuntime();
        if (!core.isBootStarted()) return;
        const isRunning = latestRuntime
          ? latestRuntime.running
          : core.getState().runtime.running;
        if (isRunning) {
          void backfillTrafficHistory(true);
        }
        if (globalPreAccelDirtyWhileHidden && core.getState().windowMode === "main") {
          globalPreAccelDirtyWhileHidden = false;
          void deps.refreshGlobalPreAccelStatus();
        }
      })();
    }

    // 3. Resume active live capture session immediately
    deps.pollLiveCaptureIfActive();
  }

  function handleStorageSync(ev: StorageEvent): void {
    if (ev.key !== UI_PREFS_STORAGE_KEY || !ev.newValue) return;
    try {
      const parsed = JSON.parse(ev.newValue) as Partial<AppConfig["personalization"]>;
      if (!parsed || typeof parsed !== "object") return;
      const cur = core.getState();
      const nextPersonalization: AppConfig["personalization"] = {
        ...cur.config.personalization,
        ...parsed,
        theme_schedule: parsed.theme_schedule
          ? { ...cur.config.personalization.theme_schedule, ...parsed.theme_schedule }
          : cur.config.personalization.theme_schedule,
      };
      const nextConfig: AppConfig = {
        ...cur.config,
        personalization: nextPersonalization,
      };
      const resolved = resolveThemeBySchedule(
        nextPersonalization.theme_mode,
        nextPersonalization.theme_schedule
      );
      applyPersonalizationToDom(resolved, nextPersonalization, cur.windowMode);
      core.setState((prev) => ({
        ...prev,
        config: nextConfig,
        resolvedTheme: resolved,
      }));
    } catch {
      /* ignore malformed storage sync payload */
    }
  }

  async function hydrateFromBackend(): Promise<void> {
    const inDesktop = isTauriEnv();
    const initialSnap = core.getState();
    const isMainWindow = initialSnap.windowMode === "main";
    // Never fire outbound network requests (exit IP / site checks) on startup in desktop mode
    // so launching the app consumes 0 B of unexpected traffic until the user explicitly requests a check.
    const results = await Promise.allSettled([
      catcloudApi.getConfig(),
      catcloudApi.getRuntimeInfo(),
      catcloudApi.listGroups(),
      catcloudApi.listNodes(),
      catcloudApi.listProbeSnapshots(),
      catcloudApi.listProbeDefinitions(),
      catcloudApi.listSubscriptions(),
      catcloudApi.listPreAccelRelays(),
      catcloudApi.getFullConfig(),
      catcloudApi.getGlobalPreAccelStatus(),
      inDesktop ? Promise.resolve(null) : catcloudApi.getExitIpInfo(),
      inDesktop ? Promise.resolve(null) : catcloudApi.checkQuickSites(),
      isMainWindow ? catcloudApi.getPendingStagedUpdate() : Promise.resolve(null),
    ]);

    const [
      cfgRes,
      runtimeRes,
      groupsRes,
      nodesRes,
      probesRes,
      probeDefsRes,
      subsRes,
      relaysRes,
      fullCfgRes,
      globalPreAccelRes,
      exitIpRes,
      quickSitesRes,
      pendingUpdateRes,
    ] = results;

    if (probeDefsRes.status === "fulfilled" && Array.isArray(probeDefsRes.value)) {
      core.syncKnownLatencyProbeIds(probeDefsRes.value);
    }

    const state = core.getState();
    const configHydratedOk = cfgRes.status === "fulfilled";
    const cfg = configHydratedOk ? cfgRes.value : state.config;
    const pendingOnboardingSync = hasPendingOnboardingSync();
    if (
      configHydratedOk &&
      cfg.personalization.onboarding_completed === true &&
      pendingOnboardingSync
    ) {
      setPendingOnboardingSync(false);
    }
    const effectiveOnboardingCompleted =
      cfg.personalization.onboarding_completed === true || pendingOnboardingSync;
    if (
      configHydratedOk &&
      pendingOnboardingSync &&
      cfg.personalization.onboarding_completed !== true
    ) {
      void catcloudApi
        .markOnboardingCompleted()
        .then(() => {
          setPendingOnboardingSync(false);
        })
        .catch(() => {
          /* keep pending sync flag until backend write succeeds */
        });
    }
    const hydratedAutoDownload =
      typeof cfg.update?.auto_download === "boolean"
        ? cfg.update.auto_download
        : fullCfgRes.status === "fulfilled" &&
            typeof fullCfgRes.value?.update?.auto_download === "boolean"
          ? fullCfgRes.value.update.auto_download
          : (state.config.update.auto_download ?? true);
    const hydratedSkippedVersion =
      cfg.update?.skipped_version !== undefined
        ? cfg.update.skipped_version
        : fullCfgRes.status === "fulfilled" &&
            fullCfgRes.value?.update?.skipped_version !== undefined
          ? fullCfgRes.value.update.skipped_version
          : (state.config.update.skipped_version ?? null);
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
            skipped_version: hydratedSkippedVersion,
          },
          personalization: {
            ...cfg.personalization,
            onboarding_completed: effectiveOnboardingCompleted,
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
            skipped_version: hydratedSkippedVersion,
          },
          personalization: {
            ...cfg.personalization,
            ...loadCachedUiPrefs(),
            ...(effectiveOnboardingCompleted ? { onboarding_completed: true } : {}),
          },
        };

    const resolved = resolveThemeBySchedule(
      mergedConfig.personalization.theme_mode,
      mergedConfig.personalization.theme_schedule
    );
    applyPersonalizationToDom(resolved, mergedConfig.personalization, state.windowMode);

    let hydratedSites: SiteCheckItem[] = state.quickSites;
    if (
      !inDesktop &&
      quickSitesRes.status === "fulfilled" &&
      Array.isArray(quickSitesRes.value)
    ) {
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
      !core.isStartupPageApplied() &&
      !core.isUserNavigatedManually() &&
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
    core.setStartupPageApplied(true);

    const resolvedRuntime = runtimeRes.status === "fulfilled" ? runtimeRes.value : state.runtime;

    if (inDesktop && resolvedRuntime.running) {
      await backfillTrafficHistory(true);
    }

    const resolvedGroups = groupsRes.status === "fulfilled" ? groupsRes.value : state.groups;
    const resolvedNodes = nodesRes.status === "fulfilled" ? nodesRes.value : state.nodes;
    const resolvedSubs = subsRes.status === "fulfilled" ? subsRes.value : state.subscriptions;
    const resolvedRelays =
      relaysRes.status === "fulfilled" ? relaysRes.value : state.preAccelRelays;
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

    const hasAuthoritativePendingUpdate =
      isMainWindow && pendingUpdateRes.status === "fulfilled";
    const authoritativePendingUpdate = hasAuthoritativePendingUpdate
      ? pendingUpdateRes.value
      : null;
    const hydratedGeoRuleContext =
      fullCfgRes.status === "fulfilled" && fullCfgRes.value
        ? {
            domesticDirectEnabled:
              fullCfgRes.value.rules_override?.domestic_direct_enabled ?? true,
            customRulesOnly: Boolean(fullCfgRes.value.rules_override?.custom_rules_only),
            geodataMode: Boolean(fullCfgRes.value.geodata_mode),
          }
        : null;

    core.setState((prev) => {
      const resolvedPendingUpdate = hasAuthoritativePendingUpdate
        ? authoritativePendingUpdate
        : prev.pendingUpdate;
      const shouldOpenUpdateModal =
        isMainWindow &&
        resolvedPendingUpdate !== null &&
        !resolvedPendingUpdate.silent_badge_only &&
        (!resolvedPendingUpdate.dismissed_in_session ||
          (!inDesktop && hasPreviewUpdateModalFlag()));
      const resolvedUpdateModalVisible =
        resolvedPendingUpdate === null
          ? false
          : prev.updateModalVisible || shouldOpenUpdateModal;
      return {
        ...prev,
        initialized: true,
        onboardingHydratedOk: prev.onboardingHydratedOk || configHydratedOk,
        activeNav: startupNav ?? prev.activeNav,
        config: alignConfigWithRuntimeTun(mergedConfig, resolvedRuntime),
        geoRuleContext: hydratedGeoRuleContext ?? prev.geoRuleContext,
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
        pendingUpdate: resolvedPendingUpdate,
        updateModalVisible: resolvedUpdateModalVisible,
      };
    });

    // Resolve local wallpaper after hydrated config is written to state so the
    // path-consistency check in ensureLocalWallpaperLoaded matches immediately.
    if (core.getState().windowMode !== "capsule") {
      void core.syncWallpaperForConfig(
        mergedConfig.personalization.wallpaper_path,
        resolved,
        mergedConfig.personalization,
        core.getState().windowMode
      );
    }
  }

  function init(): void {
    if (core.isBootStarted()) return;
    core.setBootStarted(true);
    core.registerProbeBatchFlusher(probeBatcher.flush);

    const initState = core.getState();
    applyPersonalizationToDom(
      initState.resolvedTheme,
      initState.config.personalization,
      initState.windowMode
    );

    if (typeof window !== "undefined") {
      window.addEventListener("hashchange", handleHashChange);
      window.addEventListener("storage", handleStorageSync);
      document.addEventListener("visibilitychange", handleVisibilityChange);

      themeClockTimer = window.setInterval(() => {
        if (
          document.visibilityState === "visible" &&
          core.getState().config.personalization.theme_mode === "auto_time"
        ) {
          syncResolvedThemeFromClock();
        }
      }, 30_000);
    }

    disposeTraffic = catcloudApi.subscribeTraffic((sample) => {
      core.recordLiveTrafficSample(sample);
    });

    disposeRuntime = catcloudApi.subscribeRuntimeUpdate((info) => {
      const currentState = core.getState();
      const wasRunning = currentState.runtime.running;
      if (wasRunning && !info.running) {
        // Core stopped: append clean 0 B/s landing sample & zero live speeds
        core.recordTrafficStopSample(false);
      } else if (!wasRunning && info.running) {
        // Fresh core session started: clear previous session's stale buffer
        core.resetTrafficSession(false);
      }
      const globalStateChanged =
        info.global_preaccel_active !== currentState.runtime.global_preaccel_active ||
        info.global_windivert_active !== currentState.runtime.global_windivert_active ||
        info.global_preaccel_mode !== currentState.runtime.global_preaccel_mode ||
        info.global_preaccel_socks_port !== currentState.runtime.global_preaccel_socks_port ||
        info.preaccel_install_state !== currentState.runtime.preaccel_install_state ||
        info.global_preaccel_verify_state !== currentState.runtime.global_preaccel_verify_state ||
        info.global_preaccel_verify_ms !== currentState.runtime.global_preaccel_verify_ms;
      const hasGlobalRuntimePatch =
        info.global_preaccel_active !== undefined ||
        info.global_windivert_active !== undefined ||
        info.global_preaccel_mode !== undefined ||
        info.global_preaccel_socks_port !== undefined ||
        info.global_preaccel_connections !== undefined ||
        info.preaccel_install_state !== undefined ||
        info.global_preaccel_verify_state !== undefined ||
        info.global_preaccel_verify_ms !== undefined;

      core.setStateDeferredIfHidden((prev) => {
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

      if (globalStateChanged && isTauriEnv() && core.getState().windowMode === "main") {
        if (core.isDocumentHidden()) {
          globalPreAccelDirtyWhileHidden = true;
        } else {
          void deps.refreshGlobalPreAccelStatus();
        }
      }
    });

    const unsubProbeProgress = catcloudApi.subscribeProbeProgress((ev) => {
      probeBatcher.push(ev);
    });

    disposeProbeProgress = () => {
      unsubProbeProgress();
      probeBatcher.dispose();
      core.registerProbeBatchFlusher(null);
    };

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

      core.pushToast(
        `智能策略已生效：「${groupLabel}」${detail}，已自动切换至 ${toLabel}`,
        "info",
        5000
      );

      void Promise.allSettled([
        catcloudApi.getRuntimeInfo(),
        catcloudApi.listGroups(),
      ]).then(([rtRes, groupsRes]) => {
        if (!core.isBootStarted()) return;
        core.setState((prev) => {
          const nextRuntime = rtRes.status === "fulfilled" ? rtRes.value : prev.runtime;
          const nextGroups = groupsRes.status === "fulfilled" ? groupsRes.value : prev.groups;
          const activeNodeChanged = nextRuntime.active_node_id !== prev.runtime.active_node_id;
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
      const state = core.getState();
      const mergedConfig = mergeIncomingAppConfig(incomingCfg, state.config);
      const resolved = resolveThemeBySchedule(
        mergedConfig.personalization.theme_mode,
        mergedConfig.personalization.theme_schedule
      );
      saveCachedUiPrefs(mergedConfig.personalization);
      applyPersonalizationToDom(resolved, mergedConfig.personalization, state.windowMode);

      const prevPreAccel = state.config.preaccel;
      const prevIncludePrerelease = Boolean(state.config.update.include_prerelease);
      const preAccelChanged =
        mergedConfig.preaccel.enabled !== prevPreAccel.enabled ||
        mergedConfig.preaccel.global_bypass_enabled !== prevPreAccel.global_bypass_enabled ||
        mergedConfig.preaccel.global_scope !== prevPreAccel.global_scope;
      const includePrereleaseChanged =
        Boolean(mergedConfig.update.include_prerelease) !== prevIncludePrerelease;
      core.setState((prev) => ({
        ...prev,
        config: mergedConfig,
        resolvedTheme: resolved,
      }));
      if (state.windowMode !== "capsule") {
        void core.syncWallpaperForConfig(
          mergedConfig.personalization.wallpaper_path,
          resolved,
          mergedConfig.personalization,
          state.windowMode
        );
      }
      if (preAccelChanged && isTauriEnv() && state.windowMode === "main") {
        void deps.refreshGlobalPreAccelStatus();
      }
      if (includePrereleaseChanged && isTauriEnv() && state.windowMode === "main") {
        void deps.refreshPendingUpdate();
      }
      if (isTauriEnv() && state.windowMode === "main") {
        void catcloudApi
          .getFullConfig()
          .then((fullCfg) => {
            if (!core.isBootStarted() || !fullCfg) return;
            core.setState((prev) => ({
              ...prev,
              geoRuleContext: {
                domesticDirectEnabled:
                  fullCfg.rules_override?.domestic_direct_enabled ?? true,
                customRulesOnly: Boolean(fullCfg.rules_override?.custom_rules_only),
                geodataMode: Boolean(fullCfg.geodata_mode),
              },
            }));
          })
          .catch(() => {
            /* ignore transient full-config refresh error */
          });
      }
    });

    if (initState.windowMode === "main") {
      disposeUpdateReady = catcloudApi.subscribeUpdateReady((dto) => {
        if (core.getState().windowMode !== "main") return;
        core.setState((prev) => ({
          ...prev,
          pendingUpdate: dto,
          updateModalVisible:
            !dto.silent_badge_only && !dto.dismissed_in_session
              ? true
              : prev.updateModalVisible,
        }));
      });
    }

    disposeGroupsUpdated = catcloudApi.subscribeGroupsUpdated(() => {
      scheduleGroupsRefresh();
    });

    disposeRelaysUpdated = catcloudApi.subscribeRelaysUpdated(() => {
      scheduleRelaysRefresh();
    });

    disposeNodesUpdated = catcloudApi.subscribeNodesUpdated(() => {
      scheduleNodesRefresh();
    });

    if (initState.windowMode === "main") {
      disposeNavigate = catcloudApi.subscribeNavigate((rawNav) => {
        if (core.getState().windowMode !== "main") return;
        const validNav = normalizeAllowedNavRoute(rawNav);
        if (validNav) {
          deps.setNav(validNav);
        }
      });
    }

    if (isTauriEnv()) {
      let tunAdminDisposed = false;
      let tunAdminUnlisten: (() => void) | null = null;
      void import("@tauri-apps/api/event")
        .then(({ listen }) =>
          listen<unknown>("catcloud://tun-needs-admin", (ev) => {
            if (tunAdminDisposed || core.getState().windowMode === "capsule") return;
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
            core.setState((prev) => {
              const configured = Boolean(
                prev.runtime.tun_configured ?? prev.config.tun_enabled
              );
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
            deps.openTunAdminPrompt(rawReason);
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

    void hydrateFromBackend()
      .then(() => {
        if (!core.isBootStarted() || core.getState().windowMode !== "main") return;
        if (isTauriEnv()) {
          void deps.loadGeodataStatus();
        }
        void catcloudApi
          .consumePendingNav()
          .then((rawNav) => {
            if (!core.isBootStarted() || core.getState().windowMode !== "main") return;
            const validNav = normalizeAllowedNavRoute(rawNav);
            if (validNav) {
              deps.setNav(validNav);
            }
          })
          .catch(() => {
            /* ignore pending nav consume failure on older backends */
          });
      })
      .catch((err) => {
        core.setState((prev) => ({ ...prev, initialized: true }));
        if (isTauriEnv()) {
          core.pushToast(`初始化状态同步失败：${formatErrorMessage(err)}`, "warn");
        }
      });
  }

  function dispose(): void {
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
    disposeUpdateReady?.();
    disposeUpdateReady = null;
    disposeGroupsUpdated?.();
    disposeGroupsUpdated = null;
    disposeRelaysUpdated?.();
    disposeRelaysUpdated = null;
    disposeNodesUpdated?.();
    disposeNodesUpdated = null;
    disposeNavigate?.();
    disposeNavigate = null;

    if (typeof window !== "undefined") {
      if (groupsRefreshDebounceTimer !== null) {
        window.clearTimeout(groupsRefreshDebounceTimer);
        groupsRefreshDebounceTimer = null;
      }
      if (relaysRefreshDebounceTimer !== null) {
        window.clearTimeout(relaysRefreshDebounceTimer);
        relaysRefreshDebounceTimer = null;
      }
      if (nodesRefreshDebounceTimer !== null) {
        window.clearTimeout(nodesRefreshDebounceTimer);
        nodesRefreshDebounceTimer = null;
      }
      if (themeClockTimer !== null) {
        window.clearInterval(themeClockTimer);
        themeClockTimer = null;
      }
      window.removeEventListener("hashchange", handleHashChange);
      window.removeEventListener("storage", handleStorageSync);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    }

    probeBatcher.dispose();
    globalPreAccelDirtyWhileHidden = false;

    groupsRefreshSeq += 1;
    relaysRefreshSeq += 1;
    nodesRefreshSeq += 1;

    deps.disposeProbeRuntime();
    deps.disposeCaptureRuntime();
    deps.resetPreAccelRuntime();
    core.resetCoreRuntimeOnDispose();
  }

  return {
    init,
    dispose,
    hydrateFromBackend,
    backfillTrafficHistory,
  };
}
