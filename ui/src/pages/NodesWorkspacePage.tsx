import { ArrowLeft, Globe, Link2, Plus } from "lucide-react";
import { useEffect } from "react";
import { appActions, useAppSelector } from "../store/appStore";
import { NodesSubsPage } from "./NodesSubsPage";
import { SpeedTestPage } from "./SpeedTestPage";

type WorkspaceTab = "nodes" | "subs";

let workspaceInitialTabAligned = false;

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

  const tab: WorkspaceTab = workspaceDraft.tab;
  const activeSubFilter: string | null = workspaceDraft.filterSubId || null;
  const isSubsBusy =
    subsBg.refreshingAll ||
    subsBg.refreshingIds.length > 0 ||
    subsBg.importing ||
    captureActive;

  // Consume navigation tab hints from other pages (e.g. HomePage / MultiGroupPage)
  useEffect(() => {
    if (!nodesTabHint) return;
    workspaceInitialTabAligned = true;
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
    appActions.consumeNodesTabHint();
  }, [nodesTabHint]);

  // Align initial default tab once after first backend hydration if user hasn't picked yet
  useEffect(() => {
    if (!initialized || workspaceInitialTabAligned || nodesTabHint) return;
    workspaceInitialTabAligned = true;
    if (nodes.length === 0 && tab !== "subs") {
      appActions.patchSessionDraft("nodesWorkspace", { tab: "subs" });
    }
  }, [initialized, nodes.length, nodesTabHint, tab]);

  const handleSelectTab = (next: WorkspaceTab) => {
    workspaceInitialTabAligned = true;
    appActions.patchSessionDraft("nodesWorkspace", { tab: next });
  };

  const handleOpenSubs = () => {
    workspaceInitialTabAligned = true;
    appActions.patchSessionDraft("nodesWorkspace", { tab: "subs" });
  };

  const handleBackToNodes = () => {
    workspaceInitialTabAligned = true;
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
          className="inline-flex items-center gap-1 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-0.5"
          role="tablist"
          aria-label="节点与测速工作台切签"
        >
          <button
            type="button"
            role="tab"
            aria-selected={tab === "nodes"}
            onClick={() => handleSelectTab("nodes")}
            className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-lg px-3 py-1.5 text-xs transition-colors ${
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
            className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-lg px-3 py-1.5 text-xs transition-colors ${
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

        <div className="flex items-center gap-2">
          {tab === "nodes" ? (
            <button
              type="button"
              onClick={handleOpenSubs}
              className="inline-flex items-center gap-1 whitespace-nowrap rounded-xl border border-[var(--accent)]/45 bg-[var(--accent-soft)] px-3 py-1.5 text-xs font-semibold text-[var(--accent)] transition-colors hover:bg-[var(--accent)] hover:text-[var(--accent-ink)]"
            >
              <Plus className="h-3.5 w-3.5 shrink-0" />
              <span>导入订阅</span>
            </button>
          ) : (
            <button
              type="button"
              onClick={handleBackToNodes}
              className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-xl border border-[var(--line-strong)] bg-[var(--card)] px-3 py-1.5 text-xs font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
            >
              <ArrowLeft className="h-3.5 w-3.5 shrink-0" />
              <span>返回节点列表</span>
            </button>
          )}
        </div>
      </div>

      {/* Symmetrically keep both tabs mounted via CSS `hidden` so state, filters, and drawers survive tab switches */}
      <div className={tab === "nodes" ? "contents" : "hidden"}>
        <SpeedTestPage
          embedded
          initialSubId={activeSubFilter}
          onOpenSubs={handleOpenSubs}
        />
      </div>
      <div className={tab === "subs" ? "contents" : "hidden"}>
        <NodesSubsPage
          embeddedSubsOnly
          onViewSubNodes={handleViewSubNodes}
        />
      </div>
    </div>
  );
}
