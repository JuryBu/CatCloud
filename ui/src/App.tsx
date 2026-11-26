import { X } from "lucide-react";
import { Suspense, lazy, useEffect, useLayoutEffect, useRef, useState } from "react";
import { type AppConfig, catcloudApi, isTauriEnv } from "./api/tauri";
import { Sidebar } from "./components/Sidebar";
import { TitleBar } from "./components/TitleBar";
import { normalizeUiLanguage, useUiDict } from "./i18n";
import {
  type NavRouteId,
  appActions,
  appStore,
  useAppSelector,
} from "./store/appStore";

function enforceCapsuleNoWallpaper(): void {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  root.setAttribute("data-wallpaper", "off");
  root.setAttribute("data-glass", "off");
  root.style.setProperty("--wallpaper-image", "none");
  root.style.setProperty("--wallpaper-opacity", "0");
  root.style.setProperty("--surface-alpha", "1");
  root.style.setProperty("--card-alpha", "1");
  root.style.setProperty("--glass-blur", "0px");
}

// Code-split every page + floating capsule so initial load and per-window memory stay minimal.
const HomePage = lazy(() =>
  import("./pages/HomePage").then((m) => ({ default: m.HomePage }))
);
const MultiGroupPage = lazy(() =>
  import("./pages/MultiGroupPage").then((m) => ({ default: m.MultiGroupPage }))
);
const NodesWorkspacePage = lazy(() =>
  import("./pages/NodesWorkspacePage").then((m) => ({ default: m.NodesWorkspacePage }))
);
const PreAccelPage = lazy(() =>
  import("./pages/PreAccelPage").then((m) => ({ default: m.PreAccelPage }))
);
const RulesConnsPage = lazy(() =>
  import("./pages/RulesConnsPage").then((m) => ({ default: m.RulesConnsPage }))
);
const LogsPage = lazy(() =>
  import("./pages/LogsPage").then((m) => ({ default: m.LogsPage }))
);
const AiAssistantPage = lazy(() =>
  import("./pages/AiAssistantPage").then((m) => ({ default: m.AiAssistantPage }))
);
const SettingsPage = lazy(() =>
  import("./pages/SettingsPage").then((m) => ({ default: m.SettingsPage }))
);
const CapsuleWindow = lazy(() =>
  import("./pages/CapsuleWindow").then((m) => ({ default: m.CapsuleWindow }))
);
const OnboardingModal = lazy(() =>
  import("./components/OnboardingModal").then((m) => ({ default: m.OnboardingModal }))
);

function PageLoadingFallback({ label }: { label: string }) {
  return (
    <div className="flex h-full min-h-[240px] items-center justify-center text-xs text-[var(--muted)]">
      {label}
    </div>
  );
}

function renderActivePage(route: NavRouteId) {
  switch (route) {
    case "overview":
      return <HomePage />;
    case "groups":
      return <MultiGroupPage />;
    case "speedtest":
    case "nodes":
      return <NodesWorkspacePage />;
    case "preaccel":
      return <PreAccelPage />;
    case "rules":
      return <RulesConnsPage />;
    case "logs":
      return <LogsPage />;
    case "ai":
      return <AiAssistantPage />;
    case "settings":
      return <SettingsPage />;
  }
}

export function App() {
  const windowMode = useAppSelector((s) => s.windowMode);
  const initialized = useAppSelector((s) => s.initialized);
  const onboardingCompleted = useAppSelector(
    (s) => s.config.personalization.onboarding_completed === true
  );
  const onboardingModalOpen = useAppSelector((s) => s.onboardingModalOpen);
  const onboardingAutoSkipped = useAppSelector((s) => s.onboardingAutoSkipped);
  const showOnboardingModal =
    windowMode === "main" &&
    initialized &&
    (onboardingModalOpen || (!onboardingCompleted && !onboardingAutoSkipped));
  const activeNav = useAppSelector((s) => s.activeNav);
  const resolvedTheme = useAppSelector((s) => s.resolvedTheme);
  const wallpaperPath = useAppSelector((s) => s.config.personalization.wallpaper_path);
  const uiLang = normalizeUiLanguage(
    useAppSelector((s) => s.config.personalization.ui_language)
  );
  const dict = useUiDict(uiLang);
  const toast = useAppSelector((s) => s.toast);
  const [dismissedToastId, setDismissedToastId] = useState<number | null>(null);
  const mainScrollRef = useRef<HTMLDivElement | null>(null);
  const scrollRouteKey: NavRouteId = activeNav === "speedtest" ? "nodes" : activeNav;
  const prevRouteRef = useRef<NavRouteId>(scrollRouteKey);
  const routeScrollTopRef = useRef<number>(0);
  const restoringScrollRef = useRef<boolean>(false);

  const visibleToast = toast && toast.id !== dismissedToastId ? toast : null;

  // Save outgoing route's scroll position and restore incoming route's scroll position smoothly.
  useLayoutEffect(() => {
    if (windowMode !== "main") return;
    const el = mainScrollRef.current;
    if (!el) return;

    const prevRoute = prevRouteRef.current;
    if (prevRoute !== scrollRouteKey) {
      appActions.setScrollPosition(prevRoute, routeScrollTopRef.current);
      prevRouteRef.current = scrollRouteKey;
    }

    const savedTop = appStore.getState().sessionDrafts.scrollPositions[scrollRouteKey] ?? 0;
    routeScrollTopRef.current = savedTop;
    restoringScrollRef.current = true;

    let raf2 = 0;
    const raf1 = window.requestAnimationFrame(() => {
      const node = mainScrollRef.current;
      if (!node) {
        restoringScrollRef.current = false;
        return;
      }
      node.scrollTop = savedTop;
      if (savedTop > 0 && node.scrollTop < savedTop - 2) {
        raf2 = window.requestAnimationFrame(() => {
          const retryNode = mainScrollRef.current;
          if (retryNode) {
            retryNode.scrollTop = savedTop;
          }
          restoringScrollRef.current = false;
        });
      } else {
        restoringScrollRef.current = false;
      }
    });

    return () => {
      window.cancelAnimationFrame(raf1);
      if (raf2) window.cancelAnimationFrame(raf2);
      restoringScrollRef.current = false;
    };
  }, [scrollRouteKey, windowMode]);

  useEffect(() => {
    return () => {
      appActions.setScrollPosition(prevRouteRef.current, routeScrollTopRef.current);
    };
  }, []);

  // Pause all CSS animations/transitions whenever the window is hidden or minimized.
  useEffect(() => {
    if (typeof document === "undefined") return;
    const syncPausedState = () => {
      document.documentElement.setAttribute("data-paused", document.hidden ? "on" : "off");
    };
    syncPausedState();
    document.addEventListener("visibilitychange", syncPausedState);
    return () => document.removeEventListener("visibilitychange", syncPausedState);
  }, []);

  // Force wallpaper & glass layers off in capsule mode so the 300x64 floating window never decodes wallpapers.
  useEffect(() => {
    if (windowMode !== "capsule") return;
    enforceCapsuleNoWallpaper();
  }, [windowMode, resolvedTheme, wallpaperPath]);

  // Keep the floating capsule window synced with the latest theme & personalization
  // changes saved from the main window across WebView instances (explicitly skipping wallpapers).
  useEffect(() => {
    if (windowMode !== "capsule") return;
    enforceCapsuleNoWallpaper();
    let disposed = false;
    let inFlight = false;
    let pendingAgain = false;
    let lastPersonalizationSig = "";
    let debounceTimer: number | null = null;

    const applyCapsuleConfig = (latestCfg: AppConfig, force = false) => {
      const sanitizedPersonalization: AppConfig["personalization"] = {
        ...latestCfg.personalization,
        wallpaper_path: null,
        glass_blur_px: 0,
      };
      const sig = JSON.stringify(sanitizedPersonalization);
      if (force || sig !== lastPersonalizationSig) {
        lastPersonalizationSig = sig;
        appActions.syncConfig({
          ...latestCfg,
          personalization: sanitizedPersonalization,
        });
      }
      enforceCapsuleNoWallpaper();
    };

    const syncCapsuleAppearance = async (force = false) => {
      if (disposed) return;
      if (inFlight) {
        pendingAgain = true;
        return;
      }
      inFlight = true;
      try {
        const latestCfg = await catcloudApi.getConfig();
        if (disposed) return;
        applyCapsuleConfig(latestCfg, force);
      } catch {
        /* ignore transient IPC sync failures */
      } finally {
        inFlight = false;
        if (!disposed && pendingAgain) {
          pendingAgain = false;
          void syncCapsuleAppearance(false);
        }
      }
    };

    const scheduleSync = () => {
      if (disposed) return;
      if (debounceTimer !== null) {
        window.clearTimeout(debounceTimer);
      }
      debounceTimer = window.setTimeout(() => {
        debounceTimer = null;
        void syncCapsuleAppearance(false);
      }, 80);
    };

    const onStorage = (ev: StorageEvent) => {
      if (!ev.key || ev.key === "catcloud.ui.prefs.v1") {
        if (ev.newValue) {
          try {
            const parsed = JSON.parse(ev.newValue) as Partial<AppConfig["personalization"]>;
            if (parsed && typeof parsed === "object") {
              appActions.previewPersonalization({
                ...parsed,
                wallpaper_path: null,
                glass_blur_px: 0,
              });
              enforceCapsuleNoWallpaper();
            }
          } catch {
            /* fallback to backend sync below */
          }
        }
        scheduleSync();
      }
    };

    void syncCapsuleAppearance(true);
    window.addEventListener("storage", onStorage);

    // Backend broadcasts `catcloud://config-updated` whenever config or theme is saved.
    const unsubConfig = isTauriEnv()
      ? catcloudApi.subscribeConfigUpdate((incomingCfg) => {
          if (disposed) return;
          applyCapsuleConfig(incomingCfg, false);
        })
      : null;

    return () => {
      disposed = true;
      if (debounceTimer !== null) {
        window.clearTimeout(debounceTimer);
        debounceTimer = null;
      }
      window.removeEventListener("storage", onStorage);
      unsubConfig?.();
    };
  }, [windowMode]);

  if (windowMode === "capsule") {
    return (
      <div className="relative h-full w-full">
        <Suspense fallback={null}>
          <CapsuleWindow />
        </Suspense>

        {visibleToast && (
          <div className="pointer-events-none fixed inset-x-1.5 bottom-1 z-50 flex justify-center">
            <div
              role="status"
              title={visibleToast.text}
              onClick={() => setDismissedToastId(visibleToast.id)}
              className="pointer-events-auto flex max-w-[288px] cursor-pointer items-center gap-1.5 rounded-full border border-[var(--line-strong)] bg-[var(--surface)]/95 px-2.5 py-0.5 text-[10px] leading-tight text-[var(--text)]"
            >
              <span
                className="inline-block h-1.5 w-1.5 shrink-0 rounded-full"
                style={{
                  backgroundColor:
                    visibleToast.tone === "warn"
                      ? "var(--amber)"
                      : visibleToast.tone === "ok"
                        ? "var(--green)"
                        : "var(--accent)",
                }}
              />
              <span className="min-w-0 truncate">{visibleToast.text}</span>
              <X className="h-2.5 w-2.5 shrink-0 text-[var(--muted)]" />
            </div>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="relative flex h-screen w-full flex-col overflow-hidden bg-[var(--bg)] text-[var(--text)]">
      {/* Wallpaper underlay (blurred once on underlay layer when enabled; 0 GPU layer when off) */}
      <div className="cc-wallpaper-layer pointer-events-none z-0" aria-hidden="true" />

      <TitleBar />

      <div className="relative flex min-h-0 flex-1 overflow-hidden">
        <Sidebar />

        <main className="relative flex min-w-0 flex-1 flex-col overflow-hidden">
          <div
            ref={mainScrollRef}
            onScroll={(ev) => {
              if (!restoringScrollRef.current && prevRouteRef.current === scrollRouteKey) {
                routeScrollTopRef.current = ev.currentTarget.scrollTop;
              }
            }}
            className="flex-1 overflow-y-auto px-5 py-4"
          >
            <Suspense fallback={<PageLoadingFallback label={dict.common.loading} />}>
              {renderActivePage(activeNav)}
            </Suspense>
          </div>
        </main>
      </div>

      {showOnboardingModal && (
        <Suspense fallback={null}>
          <OnboardingModal />
        </Suspense>
      )}

      {visibleToast && (
        <div className="pointer-events-none fixed inset-x-4 top-12 z-50 flex justify-center">
          <div
            role="status"
            className="pointer-events-auto flex max-w-lg items-start gap-2 rounded-xl border border-[var(--line-strong)] bg-[var(--surface)] px-3.5 py-2.5 text-xs leading-relaxed text-[var(--text)] shadow-lg"
          >
            <span
              className="mt-1.5 inline-block h-2 w-2 shrink-0 rounded-full"
              style={{
                backgroundColor:
                  visibleToast.tone === "warn"
                    ? "var(--amber)"
                    : visibleToast.tone === "ok"
                      ? "var(--green)"
                      : "var(--accent)",
              }}
            />
            <span className="min-w-0 flex-1 break-words">{visibleToast.text}</span>
            <button
              type="button"
              onClick={() => setDismissedToastId(visibleToast.id)}
              className="-mr-1 -mt-0.5 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-md text-[var(--muted)] transition-colors hover:bg-[var(--bg-elevated)] hover:text-[var(--text)]"
              aria-label={dict.common.close}
              title={dict.common.close}
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
