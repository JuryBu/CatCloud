import { ArrowLeft, Globe, Link2, Plus } from "lucide-react";
import { Suspense, lazy, useEffect, useRef, useState } from "react";
import { appActions, useAppSelector } from "../store/appStore";
import { oneOfPref, readUiPref, usePersistedState } from "../utils/uiPrefs";

const NodesSubsPage = lazy(() =>
  import("./NodesSubsPage").then((m) => ({ default: m.NodesSubsPage }))
);
const SpeedTestPage = lazy(() =>
  import("./SpeedTestPage").then((m) => ({ default: m.SpeedTestPage }))
);

type WorkspaceTab = "nodes" | "subs";

const WORKSPACE_TAB_PREF_KEY = "nodesWorkspace.tab";
const WORKSPACE_TAB_VALIDATOR = oneOfPref(["nodes", "subs"] as const);

let workspaceInitialTabAligned = false;

function WorkspaceTabFallback() {
  return (
    <div className="cc-card cc-glass flex min-h-[220px] items-center justify-center rounded-2xl text-xs text-[var(--muted)]">
      正在加载…
    </div>
  );
}

export function NodesWorkspacePage() {
  const nodes = useAppSelector((s) => s.nodes);
  const subscriptions = useAppSelector((s) => s.subscriptions);
  const initialized = useAppSelector((s) => s.initialized);
  const nodesTabHint = useAppSelector((s) => s.nodesTabHint);
  const workspaceDraft = useAppSelector((s) => s.sessionDrafts.nodesWorkspace);
  const isProbeRunning = useAppSelector(
    (s) => s.probeProgress.running || s.bgTasks.probeLocalStarting
  );
  const subsBg = useAppSelector((s) => s.bgTasks.subs);
  const captureActive = useAppSelector(
    (s) => s.bgTasks.capture.active || s.bgTasks.capture.finishing
  );

  const hasStoredTabRef = useRef<boolean | null>(null);
  if (hasStoredTabRef.current === null) {
    hasStoredTabRef.current =
      readUiPref<WorkspaceTab | null>(WORKSPACE_TAB_PREF_KEY, null, WORKSPACE_TAB_VALIDATOR) !==
      null;
  }

  const [persistedTab, setPersistedTab] = usePersistedState<WorkspaceTab>(
    WORKSPACE_TAB_PREF_KEY,
    workspaceDraft.tab,
    WORKSPACE_TAB_VALIDATOR
  );

  // Immediately honor pending nodesTabHint.tab on first render so lazy chunks load the target tab without flashing or dropping actions
  const tab: WorkspaceTab = nodesTabHint ? nodesTabHint.tab : persistedTab;
  const activeSubFilter: string | null = workspaceDraft.filterSubId || null;
  const isSubsBusy =
    subsBg.refreshingAll ||
    subsBg.refreshingIds.length > 0 ||
    subsBg.importing ||
    captureActive;

  // Lazy-mount each tab only on first activation, then keep it alive via CSS `hidden` so selections & drafts survive switches
  const [visitedSpeed, setVisitedSpeed] = useState<boolean>(() => tab === "nodes");
  const [visitedSubs, setVisitedSubs] = useState<boolean>(() => tab === "subs");

  useEffect(() => {
    if (tab === "nodes" && !visitedSpeed) {
      setVisitedSpeed(true);
    } else if (tab === "subs" && !visitedSubs) {
      setVisitedSubs(true);
    }
  }, [tab, visitedSpeed, visitedSubs]);

  const shouldMountSpeed = visitedSpeed || tab === "nodes";
  const shouldMountSubs = visitedSubs || tab === "subs";

  // Keep sessionDrafts aligned with persisted sub-tab across reloads/reopens
  useEffect(() => {
    if (workspaceDraft.tab !== persistedTab) {
      appActions.patchSessionDraft("nodesWorkspace", { tab: persistedTab });
    }
  }, [persistedTab, workspaceDraft.tab]);

  // Consume navigation tab hints from other pages (e.g. HomePage / MultiGroupPage / OnboardingModal)
  useEffect(() => {
    if (!nodesTabHint) return;
    workspaceInitialTabAligned = true;
    hasStoredTabRef.current = true;
    setPersistedTab(nodesTabHint.tab);
    if (nodesTabHint.tab === "subs") {
      setVisitedSubs(true);
    } else {
      setVisitedSpeed(true);
    }
    appActions.patchSessionDraft("nodesWorkspace", {
      tab: nodesTabHint.tab,
      ...(nodesTabHint.subId !== undefined ? { filterSubId: nodesTabHint.subId ?? "" } : {}),
    });
    if (nodesTabHint.subId !== undefined) {
      appActions.patchSessionDraft("speedTest", {
        sourceFilter: nodesTabHint.subId || "all",
        page: 1,
      });
    }
    // Defer consuming hint when a sub-page action (e.g. "migration" or "share") needs to be handled by NodesSubsPage once mounted
    if (!nodesTabHint.action) {
      appActions.consumeNodesTabHint();
    }
  }, [nodesTabHint, setPersistedTab]);

  // Align initial default tab once after first backend hydration if user has no persisted preference yet
  useEffect(() => {
    if (!initialized || workspaceInitialTabAligned || nodesTabHint) return;
    workspaceInitialTabAligned = true;
    if (!hasStoredTabRef.current && nodes.length === 0 && tab !== "subs") {
      setPersistedTab("subs");
      setVisitedSubs(true);
      appActions.patchSessionDraft("nodesWorkspace", { tab: "subs" });
    }
  }, [initialized, nodes.length, nodesTabHint, setPersistedTab, tab]);

  const handleSelectTab = (next: WorkspaceTab) => {
    workspaceInitialTabAligned = true;
    hasStoredTabRef.current = true;
    if (nodesTabHint) {
      appActions.consumeNodesTabHint();
    }
    if (next === "nodes") setVisitedSpeed(true);
    else setVisitedSubs(true);
    setPersistedTab(next);
    appActions.patchSessionDraft("nodesWorkspace", { tab: next });
  };

  const handleOpenSubs = () => {
    workspaceInitialTabAligned = true;
    hasStoredTabRef.current = true;
    if (nodesTabHint) {
      appActions.consumeNodesTabHint();
    }
    setVisitedSubs(true);
    setPersistedTab("subs");
    appActions.patchSessionDraft("nodesWorkspace", { tab: "subs" });
  };

  const handleBackToNodes = () => {
    workspaceInitialTabAligned = true;
    hasStoredTabRef.current = true;
    if (nodesTabHint) {
      appActions.consumeNodesTabHint();
    }
    setVisitedSpeed(true);
    setPersistedTab("nodes");
    appActions.patchSessionDraft("nodesWorkspace", {
      tab: "nodes",
      filterSubId: "",
    });
    appActions.patchSessionDraft("speedTest", {
      sourceFilter: "all",
      page: 1,
    });
  };

  const handleViewSubNodes = (subId: string | null) => {
    workspaceInitialTabAligned = true;
    hasStoredTabRef.current = true;
    if (nodesTabHint) {
      appActions.consumeNodesTabHint();
    }
    setVisitedSpeed(true);
    setPersistedTab("nodes");
    appActions.patchSessionDraft("nodesWorkspace", {
      tab: "nodes",
      filterSubId: subId ?? "",
    });
    appActions.patchSessionDraft("speedTest", {
      sourceFilter: subId || "all",
      page: 1,
    });
  };

  return (
    <div className="space-y-3">
      {/* Compact single-row segmented workspace toolbar */}
      <div className="cc-card cc-glass flex flex-wrap items-center justify-between gap-2 rounded-2xl px-3.5 py-2.5">
        <div
          className="inline-flex min-w-0 max-w-full flex-wrap items-center gap-1 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-0.5"
          role="tablist"
          aria-label="节点与测速工作台切签"
        >
          <button
            type="button"
            role="tab"
            aria-selected={tab === "nodes"}
            onClick={() => handleSelectTab("nodes")}
            className={`inline-flex min-w-0 shrink-0 items-center gap-1.5 whitespace-nowrap rounded-lg px-3 py-1.5 text-xs transition-colors ${
              tab === "nodes"
                ? "bg-[var(--card)] font-semibold text-[var(--accent)] shadow-xs"
                : "font-medium text-[var(--muted)] hover:text-[var(--text)]"
            }`}
          >
            <Globe className="h-3.5 w-3.5 shrink-0" />
            <span>节点与测速（{nodes.length}）</span>
            {isProbeRunning && (
              <span
                className="cc-pulse-dot inline-block h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--amber)]"
                title="正在测速中"
              />
            )}
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={tab === "subs"}
            onClick={() => handleSelectTab("subs")}
            className={`inline-flex min-w-0 shrink-0 items-center gap-1.5 whitespace-nowrap rounded-lg px-3 py-1.5 text-xs transition-colors ${
              tab === "subs"
                ? "bg-[var(--card)] font-semibold text-[var(--accent)] shadow-xs"
                : "font-medium text-[var(--muted)] hover:text-[var(--text)]"
            }`}
          >
            <Link2 className="h-3.5 w-3.5 shrink-0" />
            <span>订阅与导入（{subscriptions.length}）</span>
            {isSubsBusy && (
              <span
                className={`cc-pulse-dot inline-block h-1.5 w-1.5 shrink-0 rounded-full ${
                  captureActive ? "bg-[var(--green)]" : "bg-[var(--accent)]"
                }`}
                title={captureActive ? "正在后台实时捕捉节点" : "正在后台刷新或导入订阅"}
              />
            )}
          </button>
        </div>

        <div className="flex shrink-0 items-center gap-2">
          {tab === "nodes" ? (
            <button
              type="button"
              onClick={handleOpenSubs}
              className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-xl border border-[var(--accent)]/45 bg-[var(--accent-soft)] px-3 py-1.5 text-xs font-semibold text-[var(--accent)] transition-colors hover:bg-[var(--accent)] hover:text-[var(--accent-ink)]"
            >
              <Plus className="h-3.5 w-3.5 shrink-0" />
              <span>导入订阅</span>
            </button>
          ) : (
            <button
              type="button"
              onClick={handleBackToNodes}
              className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border border-[var(--line-strong)] bg-[var(--card)] px-3 py-1.5 text-xs font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
            >
              <ArrowLeft className="h-3.5 w-3.5 shrink-0" />
              <span>返回节点列表</span>
            </button>
          )}
        </div>
      </div>

      {/* Lazy-load each tab on first activation, then keep mounted via CSS `hidden` so state, filters, and selections survive switches */}
      {shouldMountSpeed && (
        <div className={tab === "nodes" ? "contents" : "hidden"}>
          <Suspense fallback={<WorkspaceTabFallback />}>
            <SpeedTestPage
              embedded
              initialSubId={activeSubFilter}
              onOpenSubs={handleOpenSubs}
            />
          </Suspense>
        </div>
      )}
      {shouldMountSubs && (
        <div className={tab === "subs" ? "contents" : "hidden"}>
          <Suspense fallback={<WorkspaceTabFallback />}>
            <NodesSubsPage
              embeddedSubsOnly
              onViewSubNodes={handleViewSubNodes}
            />
          </Suspense>
        </div>
      )}
    </div>
  );
}
