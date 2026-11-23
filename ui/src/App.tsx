import { X } from "lucide-react";
import { Suspense, lazy, useState } from "react";
import { Sidebar } from "./components/Sidebar";
import { type NavRouteId, useAppSelector } from "./store/appStore";

// Code-split every page + floating capsule so initial load and per-window memory stay minimal.
const HomePage = lazy(() =>
  import("./pages/HomePage").then((m) => ({ default: m.HomePage }))
);
const MultiGroupPage = lazy(() =>
  import("./pages/MultiGroupPage").then((m) => ({ default: m.MultiGroupPage }))
);
const SpeedTestPage = lazy(() =>
  import("./pages/SpeedTestPage").then((m) => ({ default: m.SpeedTestPage }))
);
const PreAccelPage = lazy(() =>
  import("./pages/PreAccelPage").then((m) => ({ default: m.PreAccelPage }))
);
const NodesSubsPage = lazy(() =>
  import("./pages/NodesSubsPage").then((m) => ({ default: m.NodesSubsPage }))
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
      return <SpeedTestPage />;
    case "preaccel":
      return <PreAccelPage />;
    case "nodes":
      return <NodesSubsPage />;
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

  if (windowMode === "capsule") {
    return (
      <Suspense fallback={null}>
        <CapsuleWindow />
      </Suspense>
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
