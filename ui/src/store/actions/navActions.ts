import {
  type AppConfig,
  type CoreRuntimeInfo,
  type ExitIpInfo,
  type GlobalPreAccelStatus,
  type MultiGroup,
  type PreAccelRelay,
  type ProbeSnapshot,
  type ProxyNode,
  type SiteCheckItem,
  type SubscriptionRecord,
  type ThemeMode,
  catcloudApi,
  formatErrorMessage,
  isTauriEnv,
} from "../../api/tauri";
import { ensureUiLocaleLoaded, normalizeUiLanguage, type UiLanguage } from "../../i18n";
import { type StoreCore, alignConfigWithRuntimeTun, mergeIncomingAppConfig } from "../core";
import {
  SAFE_BITMAP_DATA_URL_RE,
  applyPersonalizationToDom,
  bumpWallpaperLoadSeq,
  commitDataUrlWallpaper,
  detachCachedWallpaperObjectUrl,
  hasPendingOnboardingSync,
  isBuiltinWallpaperPreset,
  resolveThemeBySchedule,
  revokeObjectUrlSafe,
  saveCachedUiPrefs,
} from "../themeWallpaper";
import type {
  AppState,
  MascotState,
  NavRouteId,
  SessionDraftsState,
  WindowMode,
} from "../types";

export function createNavActions(core: StoreCore) {
  function setNav(nav: NavRouteId): void {
    const normalized: NavRouteId = nav === "speedtest" ? "nodes" : nav;
    core.setUserNavigatedManually(true);
    if (typeof window !== "undefined" && core.getState().windowMode === "main") {
      const targetHash = `#${normalized}`;
      if (window.location.hash !== targetHash) {
        window.history.replaceState(null, "", targetHash);
      }
    }
    core.setState((prev) =>
      prev.activeNav === normalized ? prev : { ...prev, activeNav: normalized }
    );
  }

  function openAiAssistant(moduleId?: string, tab?: "web" | "agent"): void {
    core.setState((prev) => ({
      ...prev,
      aiRouteHint: moduleId || tab ? { moduleId, tab } : prev.aiRouteHint,
    }));
    setNav("ai");
  }

  async function updatePersonalization(
    patch: Partial<AppConfig["personalization"]>,
    notice?: string
  ): Promise<void> {
    const reqSeq = core.nextPersonalizationReqSeq();
    const prevState = core.getState();
    const prevConfig = prevState.config;
    const prevResolved = prevState.resolvedTheme;
    const nextConfig: AppConfig = {
      ...prevConfig,
      personalization: {
        ...prevConfig.personalization,
        ...patch,
      },
    };
    const resolved = resolveThemeBySchedule(
      nextConfig.personalization.theme_mode,
      nextConfig.personalization.theme_schedule
    );
    saveCachedUiPrefs(nextConfig.personalization);
    applyPersonalizationToDom(resolved, nextConfig.personalization, prevState.windowMode);
    core.setState((prev) => ({
      ...prev,
      config: nextConfig,
      resolvedTheme: resolved,
    }));
    try {
      const saved = await catcloudApi.saveConfig(nextConfig);
      if (reqSeq !== core.getPersonalizationReqSeq()) {
        return;
      }
      const savedResolved = resolveThemeBySchedule(
        saved.personalization.theme_mode,
        saved.personalization.theme_schedule
      );
      saveCachedUiPrefs(saved.personalization);
      applyPersonalizationToDom(savedResolved, saved.personalization, core.getState().windowMode);
      core.setState((prev) => ({
        ...prev,
        config: mergeIncomingAppConfig(saved, prev.config),
        resolvedTheme: savedResolved,
      }));
      if (notice) core.pushToast(notice, "info");
    } catch (err) {
      if (reqSeq !== core.getPersonalizationReqSeq()) {
        return;
      }
      const winMode = core.getState().windowMode;
      saveCachedUiPrefs(prevConfig.personalization);
      applyPersonalizationToDom(prevResolved, prevConfig.personalization, winMode);
      core.setState((prev) => ({
        ...prev,
        config: prevConfig,
        resolvedTheme: prevResolved,
        ...(prevConfig.personalization.wallpaper_path ? {} : { wallpaperPreviewUrl: null }),
      }));
      if (winMode !== "capsule" && prevConfig.personalization.wallpaper_path) {
        void core.syncWallpaperForConfig(
          prevConfig.personalization.wallpaper_path,
          prevResolved,
          prevConfig.personalization,
          winMode
        );
      }
      core.pushToast(`个性化配置保存失败：${formatErrorMessage(err)}`, "warn");
    }
  }

  return {
    setNav,

    openNodesWorkspace(
      tab: "nodes" | "subs" | "speed" = "nodes",
      subId?: string | null,
      action?: "migration" | "share" | null
    ): void {
      const normalizedTab: "nodes" | "subs" = tab === "speed" ? "nodes" : tab;
      core.setState((prev) => ({
        ...prev,
        nodesTabHint: { tab: normalizedTab, subId: subId ?? null, action: action ?? null },
        sessionDrafts: {
          ...prev.sessionDrafts,
          nodesWorkspace: {
            tab: normalizedTab,
            filterSubId: subId ?? "",
          },
        },
      }));
      setNav("nodes");
    },

    consumeNodesTabHint(): void {
      core.setState((prev) => (prev.nodesTabHint === null ? prev : { ...prev, nodesTabHint: null }));
    },

    openMultiGroup(groupId: string): void {
      const trimmed = groupId.trim();
      if (trimmed) {
        core.setState((prev) => ({
          ...prev,
          sessionDrafts: {
            ...prev.sessionDrafts,
            multiGroup: {
              ...prev.sessionDrafts.multiGroup,
              selectedId: trimmed,
            },
          },
        }));
      }
      setNav("groups");
    },

    openMultiGroupCreate(template: "wsf" | "ai" | "manual" | "download"): void {
      core.setState((prev) => ({ ...prev, multiGroupCreateHint: template }));
      setNav("groups");
    },

    consumeMultiGroupCreateHint(): void {
      core.setState((prev) =>
        prev.multiGroupCreateHint === null ? prev : { ...prev, multiGroupCreateHint: null }
      );
    },

    syncGeoRuleContext(patch: Partial<AppState["geoRuleContext"]>): void {
      core.setState((prev) => ({
        ...prev,
        geoRuleContext: {
          ...prev.geoRuleContext,
          ...patch,
        },
      }));
    },

    openSettingsTab(tab: "system" | "appearance" | "dns" | "core" | "updates"): void {
      core.setState((prev) => ({ ...prev, settingsTabHint: tab }));
      setNav("settings");
    },

    consumeSettingsTabHint(): void {
      core.setState((prev) =>
        prev.settingsTabHint === null ? prev : { ...prev, settingsTabHint: null }
      );
    },

    openSettingsAgentDocs(moduleId?: string): void {
      openAiAssistant(moduleId, "web");
    },

    openAiAssistant,

    consumeAiRouteHint(): void {
      core.setState((prev) => (prev.aiRouteHint === null ? prev : { ...prev, aiRouteHint: null }));
    },

    consumeSettingsOpenAgentDocs(): void {
      core.setState((prev) =>
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
      await updatePersonalization(
        { ui_language: normalized },
        `界面语言已切换为 ${labelMap[normalized]}`
      );
    },

    openOnboardingModal(): void {
      core.setState((prev) =>
        prev.onboardingModalOpen ? prev : { ...prev, onboardingModalOpen: true }
      );
    },

    async markOnboardingCompleted(): Promise<void> {
      if (
        core.getState().config.personalization.onboarding_completed === true &&
        !hasPendingOnboardingSync()
      ) {
        return;
      }
      core.setState((prev) => ({
        ...prev,
        onboardingModalOpen: true,
        onboardingAutoSkipped: true,
      }));
      await core.persistOnboardingCompletedLight();
    },

    async closeOnboardingModal(markCompleted = true): Promise<void> {
      core.setState((prev) => ({
        ...prev,
        onboardingModalOpen: false,
        onboardingAutoSkipped: prev.onboardingAutoSkipped || markCompleted,
      }));
      if (
        markCompleted &&
        (core.getState().config.personalization.onboarding_completed !== true ||
          hasPendingOnboardingSync())
      ) {
        await core.persistOnboardingCompletedLight();
      }
    },

    setMascotState(next: MascotState): void {
      if (
        next === "idle" &&
        (core.getActiveMascotTaskCount() > 0 || core.getState().probeProgress.running)
      ) {
        return;
      }
      core.setState((prev) => (prev.mascotState === next ? prev : { ...prev, mascotState: next }));
    },

    syncConfig(nextConfig: AppConfig): void {
      const prevState = core.getState();
      const prevPath = prevState.config.personalization.wallpaper_path?.trim() ?? "";
      const nextPath = nextConfig.personalization.wallpaper_path?.trim() ?? "";
      const resolved = resolveThemeBySchedule(
        nextConfig.personalization.theme_mode,
        nextConfig.personalization.theme_schedule
      );
      applyPersonalizationToDom(resolved, nextConfig.personalization, prevState.windowMode);
      core.setState((prev) => ({
        ...prev,
        config: mergeIncomingAppConfig(nextConfig, prev.config),
        resolvedTheme: resolved,
      }));
      if (prevState.windowMode !== "capsule" && prevPath !== nextPath) {
        void core.syncWallpaperForConfig(
          nextConfig.personalization.wallpaper_path,
          resolved,
          nextConfig.personalization,
          prevState.windowMode
        );
      }
    },

    syncRuntime(nextRuntime: CoreRuntimeInfo): void {
      core.setState((prev) => ({
        ...prev,
        config: alignConfigWithRuntimeTun(prev.config, nextRuntime),
        runtime: nextRuntime,
      }));
    },

    syncGroups(groups: MultiGroup[]): void {
      core.setState((prev) => ({ ...prev, groups }));
    },

    syncNodes(nodes: ProxyNode[]): void {
      core.setState((prev) => ({ ...prev, nodes }));
    },

    syncProbes(probes: Record<string, ProbeSnapshot>): void {
      core.setState((prev) => ({ ...prev, probes }));
    },

    syncSubscriptions(subscriptions: SubscriptionRecord[]): void {
      core.setState((prev) => ({ ...prev, subscriptions }));
    },

    syncPreAccelRelays(preAccelRelays: PreAccelRelay[]): void {
      core.setState((prev) => ({ ...prev, preAccelRelays }));
    },

    syncGlobalPreAccel(globalPreAccel: GlobalPreAccelStatus): void {
      core.setState((prev) => ({ ...prev, globalPreAccel }));
    },

    syncQuickSites(quickSites: SiteCheckItem[]): void {
      core.setState((prev) => ({ ...prev, quickSites }));
    },

    syncExitIp(exitIp: ExitIpInfo): void {
      core.setState((prev) => ({ ...prev, exitIp }));
    },

    previewPersonalization(patch: Partial<AppConfig["personalization"]>): void {
      core.nextPersonalizationReqSeq();
      const current = core.getState();
      const nextConfig: AppConfig = {
        ...current.config,
        personalization: {
          ...current.config.personalization,
          ...patch,
        },
      };
      const resolved = resolveThemeBySchedule(
        nextConfig.personalization.theme_mode,
        nextConfig.personalization.theme_schedule
      );
      applyPersonalizationToDom(resolved, nextConfig.personalization, current.windowMode);
      core.setState((prev) => ({
        ...prev,
        config: nextConfig,
        resolvedTheme: resolved,
      }));
    },

    updatePersonalization,

    cycleThemeMode(): void {
      const manualOrder: ThemeMode[] = ["light", "warm_dark", "midnight_blue"];
      const labels: Record<ThemeMode, string> = {
        auto_time: "按时间自动切换",
        light: "浅色暖纸",
        warm_dark: "深苔暖金",
        midnight_blue: "午夜星蓝",
      };
      const resolvedTheme = core.getState().resolvedTheme;
      const currentVisual: ThemeMode =
        resolvedTheme === "light"
          ? "light"
          : resolvedTheme === "warm-dark"
            ? "warm_dark"
            : "midnight_blue";
      const next = manualOrder[(manualOrder.indexOf(currentVisual) + 1) % manualOrder.length];
      void updatePersonalization({ theme_mode: next }, `已切换主题：${labels[next]}`);
    },

    async setThemeMode(mode: ThemeMode): Promise<void> {
      const labels: Record<ThemeMode, string> = {
        auto_time: "按时间自动切换",
        light: "浅色暖纸",
        warm_dark: "深苔暖金",
        midnight_blue: "午夜星蓝",
      };
      await updatePersonalization({ theme_mode: mode }, `已切换主题：${labels[mode]}`);
    },

    async pickWallpaperImage(): Promise<boolean> {
      try {
        const picked = await catcloudApi.pickWallpaperImage();
        if (picked.cancelled || !picked.path) {
          return false;
        }
        if (picked.data_url && !SAFE_BITMAP_DATA_URL_RE.test(picked.data_url)) {
          const msg = "不支持此图片格式，请选择 PNG、JPG、WebP、GIF 或 BMP 图片";
          core.setState((prev) => ({ ...prev, wallpaperError: msg }));
          core.pushToast(msg, "warn");
          return false;
        }

        const current = core.getState();
        const nextConfig: AppConfig = {
          ...current.config,
          personalization: {
            ...current.config.personalization,
            wallpaper_path: picked.path,
          },
        };

        if (picked.data_url) {
          // Cancel any in-flight resolveWallpaperDataUrl requests, then swap to the new
          // shared Blob ObjectURL on DOM and state BEFORE revoking the previous ObjectURL.
          bumpWallpaperLoadSeq();
          commitDataUrlWallpaper({
            rawPath: picked.path,
            dataUrl: picked.data_url,
            resolvedTheme: current.resolvedTheme,
            personalization: nextConfig.personalization,
            windowMode: current.windowMode,
            onCommitState: (previewUrl) => {
              core.setState((prev) => ({
                ...prev,
                config: nextConfig,
                wallpaperPreviewUrl: previewUrl,
                wallpaperError: null,
              }));
            },
          });
        } else {
          core.setState((prev) => ({
            ...prev,
            config: nextConfig,
            wallpaperError: null,
          }));
          if (current.windowMode !== "capsule") {
            void core.syncWallpaperForConfig(
              picked.path,
              current.resolvedTheme,
              nextConfig.personalization,
              current.windowMode
            );
          }
        }

        core.pushToast("背景壁纸已更换", "ok");
        return true;
      } catch (err) {
        const msg = `选择壁纸失败：${formatErrorMessage(err)}`;
        core.setState((prev) => ({ ...prev, wallpaperError: msg }));
        core.pushToast(msg, "warn");
        return false;
      }
    },

    async setWallpaperPath(path: string | null, notice?: string): Promise<void> {
      const trimmed = path?.trim() || null;
      const releasesLocalCache =
        !trimmed || isBuiltinWallpaperPreset(trimmed) || /^https?:\/\//i.test(trimmed);

      if (releasesLocalCache) {
        bumpWallpaperLoadSeq();
        await updatePersonalization({ wallpaper_path: trimmed }, notice);
        const latestPath = core.getState().config.personalization.wallpaper_path?.trim() || null;
        if (latestPath === trimmed) {
          const oldObjectUrl = detachCachedWallpaperObjectUrl();
          core.setState((prev) => ({
            ...prev,
            wallpaperPreviewUrl: null,
            wallpaperError: null,
          }));
          // Revoke only after persistence succeeds and DOM/state have switched away from the local blob.
          revokeObjectUrlSafe(oldObjectUrl);
        }
        return;
      }

      core.setState((prev) => ({
        ...prev,
        wallpaperError: null,
      }));
      await updatePersonalization({ wallpaper_path: trimmed }, notice);
      const latest = core.getState();
      if (latest.windowMode !== "capsule" && latest.config.personalization.wallpaper_path) {
        void core.syncWallpaperForConfig(
          latest.config.personalization.wallpaper_path,
          latest.resolvedTheme,
          latest.config.personalization,
          latest.windowMode
        );
      }
    },

    async toggleCapsule(): Promise<void> {
      if (isTauriEnv()) {
        try {
          await catcloudApi.toggleCapsuleWindow();
        } catch (err) {
          core.pushToast(`切换悬浮小窗失败：${formatErrorMessage(err)}`, "warn");
        }
        return;
      }
      const current = core.getState();
      const nextMode: WindowMode = current.windowMode === "capsule" ? "main" : "capsule";
      if (typeof window !== "undefined") {
        window.location.hash = nextMode === "capsule" ? "#capsule" : `#${current.activeNav}`;
      }
      core.setState((prev) => ({ ...prev, windowMode: nextMode }));
      applyPersonalizationToDom(current.resolvedTheme, current.config.personalization, nextMode);
    },

    async showMainFromCapsule(): Promise<void> {
      if (isTauriEnv()) {
        try {
          await catcloudApi.showMainWindow();
        } catch (err) {
          core.pushToast(`展开主窗口失败：${formatErrorMessage(err)}`, "warn");
        }
        return;
      }
      const current = core.getState();
      if (typeof window !== "undefined") {
        window.location.hash = `#${current.activeNav}`;
      }
      core.setState((prev) => ({ ...prev, windowMode: "main" }));
      applyPersonalizationToDom(current.resolvedTheme, current.config.personalization, "main");
    },

    setScrollPosition(route: string, top: number): void {
      const normalizedTop = Math.max(0, Math.round(top));
      if (core.getState().sessionDrafts.scrollPositions[route] === normalizedTop) {
        return;
      }
      core.setState((prev) => ({
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
      core.setState((prev) => {
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

    showToast: core.pushToast,
  };
}
