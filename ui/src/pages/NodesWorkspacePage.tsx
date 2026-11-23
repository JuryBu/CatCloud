import { ArrowLeft, Globe, Link2, Plus } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { appActions, useAppSelector } from "../store/appStore";
import { NodesSubsPage } from "./NodesSubsPage";
import { SpeedTestPage } from "./SpeedTestPage";

type WorkspaceTab = "nodes" | "subs";

export function NodesWorkspacePage() {
  const nodes = useAppSelector((s) => s.nodes);
  const subscriptions = useAppSelector((s) => s.subscriptions);
  const initialized = useAppSelector((s) => s.initialized);
  const nodesTabHint = useAppSelector((s) => s.nodesTabHint);
  const isProbeRunning = useAppSelector((s) => s.probeProgress.running);

  const userPickedTabRef = useRef(Boolean(nodesTabHint));
  const [tab, setTab] = useState<WorkspaceTab>(() => {
    if (nodesTabHint) return nodesTabHint.tab;
    return nodes.length === 0 ? "subs" : "nodes";
  });
  const [activeSubFilter, setActiveSubFilter] = useState<string | null>(
    () => nodesTabHint?.subId ?? null
  );

  // Consume navigation tab hints from other pages (e.g. HomePage / MultiGroupPage)
  useEffect(() => {
    if (!nodesTabHint) return;
    userPickedTabRef.current = true;
    setTab(nodesTabHint.tab);
    if (nodesTabHint.subId !== undefined) {
      setActiveSubFilter(nodesTabHint.subId ?? null);
    }
    appActions.consumeNodesTabHint();
  }, [nodesTabHint]);

  // If mounted directly before backend hydration completes, align default tab once initialized
  useEffect(() => {
    if (!initialized || userPickedTabRef.current || nodesTabHint) return;
    setTab(nodes.length === 0 ? "subs" : "nodes");
  }, [initialized, nodes.length, nodesTabHint]);

  const handleSelectTab = (next: WorkspaceTab) => {
    userPickedTabRef.current = true;
    setTab(next);
  };

  const handleOpenSubs = () => {
    userPickedTabRef.current = true;
    setTab("subs");
  };

  const handleBackToNodes = () => {
    userPickedTabRef.current = true;
    setActiveSubFilter(null);
    setTab("nodes");
  };

  const handleViewSubNodes = (subId: string | null) => {
    userPickedTabRef.current = true;
    setActiveSubFilter(subId);
    setTab("nodes");
  };

  return (
    <div className="space-y-3">
      {/* Compact single-row segmented workspace toolbar */}
      <div className="cc-card cc-glass flex flex-wrap items-center justify-between gap-2 rounded-2xl px-3.5 py-2.5">
        <div
          className="inline-flex items-center gap-1 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-0.5"
          role="tablist"
          aria-label="节点与订阅工作台切签"
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

      {/* Keep SpeedTestPage mounted with CSS `hidden` so selections, search, region filters, and pagination survive tab switches */}
      <div className={tab === "nodes" ? "contents" : "hidden"}>
        <SpeedTestPage
          embedded
          initialSubId={activeSubFilter}
          onOpenSubs={handleOpenSubs}
        />
      </div>
      {tab === "subs" && (
        <NodesSubsPage
          embeddedSubsOnly
          onViewSubNodes={handleViewSubNodes}
        />
      )}
    </div>
  );
}
