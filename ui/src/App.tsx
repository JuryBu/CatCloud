import { X } from "lucide-react";
import { Suspense, lazy, useEffect, useState } from "react";
import { type AppConfig, catcloudApi, isTauriEnv } from "./api/tauri";
import { Sidebar } from "./components/Sidebar";
import {
  BUILTIN_WALLPAPER_PRESETS,
  type NavRouteId,
  appActions,
  appStore,
  useAppSelector,
} from "./store/appStore";

const SAFE_BITMAP_DATA_URL_RE = /^data:image\/(png|jpe?g|webp|gif|bmp);base64,/i;

function isImmediateWallpaperPath(rawPath: string): boolean {
  if (!rawPath) return true;
  if (BUILTIN_WALLPAPER_PRESETS.some((p) => p.id === rawPath)) return true;
  if (/^https?:\/\//i.test(rawPath)) return true;
  if (SAFE_BITMAP_DATA_URL_RE.test(rawPath)) return true;
  return false;
}

async function syncLocalWallpaperVarsIfNeeded(cfg: AppConfig): Promise<void> {
  if (typeof document === "undefined") return;
  const p = cfg.personalization;
  const rawPath = p.wallpaper_path?.trim() ?? "";
  if (!rawPath || isImmediateWallpaperPath(rawPath)) return;
  if (/^data:/i.test(rawPath)) return;

  try {
    const dataUrl = await catcloudApi.resolveWallpaperDataUrl(rawPath);
    if ((appStore.getState().config.personalization.wallpaper_path?.trim() ?? "") !== rawPath) {
      return;
    }
    if (!dataUrl || !SAFE_BITMAP_DATA_URL_RE.test(dataUrl)) return;
    const safeUrl = dataUrl.replace(/["\\\n\r]/g, "");
    const opacity = Math.max(0.05, Math.min(0.65, p.wallpaper_opacity));
    const blurPx = Math.max(0, Math.min(24, Math.round(p.glass_blur_px)));
    const root = document.documentElement;
    root.setAttribute("data-wallpaper", "on");
    root.setAttribute("data-glass", blurPx > 0 ? "on" : "off");
    root.style.setProperty("--wallpaper-image", `url("${safeUrl}")`);
    root.style.setProperty("--wallpaper-opacity", String(opacity));
    root.style.setProperty("--surface-alpha", blurPx > 0 ? "0.82" : "0.90");
    root.style.setProperty("--card-alpha", blurPx > 0 ? "0.78" : "0.88");
    root.style.setProperty("--glass-blur", `${blurPx}px`);
  } catch {
    /* keep base theme tokens intact if local wallpaper file is unreadable */
  }
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
const SettingsPage = lazy(() =>
  import("./pages/SettingsPage").then((m) => ({ default: m.SettingsPage }))
);
const CapsuleWindow = lazy(() =>
  import("./pages/CapsuleWindow").then((m) => ({ default: m.CapsuleWindow }))
);

function PageLoadingFallback() {
  return (
    <div className="flex h-full min-h-[240px] items-center justify-center text-xs text-[var(--muted)]">
      正在载入模块...
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
    case "settings":
      return <SettingsPage />;
  }
}

export function App() {
  const windowMode = useAppSelector((s) => s.windowMode);
  const activeNav = useAppSelector((s) => s.activeNav);
  const toast = useAppSelector((s) => s.toast);
  const [dismissedToastId, setDismissedToastId] = useState<number | null>(null);

  const visibleToast = toast && toast.id !== dismissedToastId ? toast : null;

  // Keep the floating capsule window synced with the latest theme, wallpaper & personalization
  // changes saved from the main window across WebView instances.
  useEffect(() => {
    if (windowMode !== "capsule") return;
    let disposed = false;
    let inFlight = false;
    let pendingAgain = false;
    let lastPersonalizationSig = "";
    let debounceTimer: number | null = null;

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
        const sig = JSON.stringify(latestCfg.personalization);
        if (force || sig !== lastPersonalizationSig) {
          lastPersonalizationSig = sig;
          appActions.syncConfig(latestCfg);
          await syncLocalWallpaperVarsIfNeeded(latestCfg);
        }
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
              appActions.previewPersonalization(parsed);
            }
          } catch {
            /* fallback to backend sync below */
          }
        }
        scheduleSync();
      }
    };

    const onFocus = () => {
      scheduleSync();
    };

    const onVisibility = () => {
      if (document.visibilityState === "visible") {
        scheduleSync();
      }
    };

    void syncCapsuleAppearance(true);
    window.addEventListener("storage", onStorage);
    window.addEventListener("focus", onFocus);
    document.addEventListener("visibilitychange", onVisibility);

    // Backend broadcasts `catcloud://runtime` whenever config or wallpaper is saved.
    const unsubRuntime = isTauriEnv()
      ? catcloudApi.subscribeRuntimeUpdate(() => {
          scheduleSync();
        })
      : null;

    return () => {
      disposed = true;
      if (debounceTimer !== null) {
        window.clearTimeout(debounceTimer);
        debounceTimer = null;
      }
      window.removeEventListener("storage", onStorage);
      window.removeEventListener("focus", onFocus);
      document.removeEventListener("visibilitychange", onVisibility);
      unsubRuntime?.();
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
              className="pointer-events-auto flex max-w-[288px] cursor-pointer items-center gap-1.5 rounded-full border border-[var(--line-strong)] bg-[var(--surface)]/95 px-2.5 py-0.5 text-[10px] leading-tight text-[var(--text)] shadow-md"
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
    <div className="relative flex h-full w-full overflow-hidden bg-[var(--bg)] text-[var(--text)]">
      {/* Wallpaper underlay (zero GPU layer when disabled via CSS variables) */}
      <div className="cc-wallpaper-layer" aria-hidden="true" />

      <Sidebar />

      <main className="relative z-10 flex min-w-0 flex-1 flex-col overflow-hidden">
        <div className="flex-1 overflow-y-auto px-5 py-4">
          <Suspense fallback={<PageLoadingFallback />}>
            {renderActivePage(activeNav)}
          </Suspense>
        </div>
      </main>

      {visibleToast && (
        <div className="pointer-events-none fixed inset-x-4 top-4 z-50 flex justify-center">
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
              aria-label="关闭提示"
              title="关闭提示"
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
