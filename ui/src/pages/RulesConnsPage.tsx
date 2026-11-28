import { Activity, Layers, Network } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { catcloudApi, isTauriEnv } from "../api/tauri";
import { appStore, useAppSelector } from "../store/appStore";
import { usePersistedState } from "../utils/uiPrefs";
import { ConnectionsTab } from "./rules-conns/ConnectionsTab";
import { RulesTab } from "./rules-conns/RulesTab";
import {
  ACTIVE_TAB_VALIDATOR,
  AI_PRESETS_TEMPLATE,
  type ActiveTab,
  type ConnectionBreakdown,
  buildGroupBoundRules,
  computeConnectionBreakdown,
  hydrateRulesFromConfig,
  mapDtoConnection,
} from "./rules-conns/rulesCodec";

const EMPTY_BREAKDOWN: ConnectionBreakdown = {
  appCount: 0,
  innerTunnelCount: 0,
  loopbackCount: 0,
};

export function RulesConnsPage() {
  const inTauri = isTauriEnv();
  const runtimeRunning = useAppSelector((s) => s.runtime.running);
  const preAccelEnabled = useAppSelector(
    (s) => s.runtime.preaccel_active || s.config.preaccel.enabled
  );

  const [activeTab, setActiveTab] = usePersistedState<ActiveTab>(
    "rulesconns.activeTab",
    "rules",
    ACTIVE_TAB_VALIDATOR
  );

  const [rulesCount, setRulesCount] = useState<number>(() =>
    buildGroupBoundRules(appStore.getState().groups).length
  );
  const [connBreakdown, setConnBreakdown] = useState<ConnectionBreakdown>(EMPTY_BREAKDOWN);

  const handleRulesCountChange = useCallback((count: number) => {
    setRulesCount((prev) => (prev === count ? prev : count));
  }, []);

  const handleBreakdownChange = useCallback((next: ConnectionBreakdown) => {
    setConnBreakdown((prev) =>
      prev.appCount === next.appCount &&
      prev.innerTunnelCount === next.innerTunnelCount &&
      prev.loopbackCount === next.loopbackCount
        ? prev
        : next
    );
  }, []);

  // One-shot badge hydration when landing directly on Rules tab (zero 2.5s polling while on Rules tab).
  useEffect(() => {
    if (activeTab !== "rules") return;
    let cancelled = false;
    if (!inTauri) {
      void import("./rules-conns/previewConnections").then((mod) => {
        if (cancelled) return;
        handleBreakdownChange(computeConnectionBreakdown(mod.buildPreviewConnections(preAccelEnabled)));
      });
      return () => {
        cancelled = true;
      };
    }
    if (!runtimeRunning) {
      handleBreakdownChange(EMPTY_BREAKDOWN);
      return;
    }
    void catcloudApi
      .getActiveConnections()
      .then((snap) => {
        if (cancelled) return;
        const { groups, preAccelRelays } = appStore.getState();
        const mapped = snap.connections.map((dto) =>
          mapDtoConnection(dto, groups, preAccelRelays, preAccelEnabled)
        );
        handleBreakdownChange(computeConnectionBreakdown(mapped));
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [activeTab, handleBreakdownChange, inTauri, preAccelEnabled, runtimeRunning]);

  // One-shot rules badge hydration when landing directly on Connections tab.
  useEffect(() => {
    if (activeTab !== "connections") return;
    let cancelled = false;
    void catcloudApi
      .getFullConfig()
      .then((fullCfg) => {
        if (cancelled) return;
        const { groups } = appStore.getState();
        const fallbackTarget = groups[0]?.name || "DIRECT";
        const savedOverride = fullCfg.rules_override;
        const hasSavedOverride =
          savedOverride !== undefined &&
          (Array.isArray(savedOverride.global_prepend_rules) ||
            Array.isArray(savedOverride.global_append_rules));
        const prependList =
          !inTauri && !hasSavedOverride
            ? AI_PRESETS_TEMPLATE.flatMap((tpl) =>
                tpl.domains.map((d) => `DOMAIN-SUFFIX,${d},${fallbackTarget}`)
              )
            : Array.isArray(savedOverride?.global_prepend_rules)
              ? savedOverride.global_prepend_rules
              : [];
        const appendList =
          !inTauri && !hasSavedOverride
            ? ["GEOSITE,cn,DIRECT", "GEOIP,CN,DIRECT,no-resolve"]
            : Array.isArray(savedOverride?.global_append_rules)
              ? savedOverride.global_append_rules
              : [];
        const hydrated = hydrateRulesFromConfig(prependList, appendList, fallbackTarget);
        const enabledAiDomains = hydrated.presets
          .filter((p) => p.enabled)
          .reduce((acc, p) => acc + p.domains.length, 0);
        handleRulesCountChange(
          hydrated.userRules.length + buildGroupBoundRules(groups).length + enabledAiDomains
        );
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [activeTab, handleRulesCountChange, inTauri]);

  const innerCountShortLabel = preAccelEnabled ? "提速隧道" : "内核内部连接";

  return (
    <div className="space-y-4">
      {/* 顶部标题与标签切换 */}
      <section className="cc-card cc-glass flex flex-wrap items-center justify-between gap-3 rounded-2xl p-4">
        <div className="flex min-w-0 flex-1 items-center gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--accent)]">
            <Network className="h-5 w-5" />
          </div>
          <div className="min-w-0">
            <h1 className="text-sm font-semibold text-[var(--text)]">分流规则与当前连接</h1>
            <p className="mt-0.5 text-xs text-[var(--muted)]">
              决定哪些网站走哪组节点或直接连接，也可以随时查看并断开正在进行的网络连接。
            </p>
          </div>
        </div>

        <div className="flex shrink-0 flex-wrap items-center rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-1 text-xs">
          <button
            type="button"
            onClick={() => setActiveTab("rules")}
            className={`inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-lg px-3 py-1.5 font-medium transition-colors ${
              activeTab === "rules"
                ? "bg-[var(--card)] text-[var(--accent)] shadow-xs"
                : "text-[var(--muted)] hover:text-[var(--text)]"
            }`}
          >
            <Layers className="h-3.5 w-3.5 shrink-0" />
            分流规则
            <span className="cc-mono rounded-full bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10px]">
              {rulesCount}
            </span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("connections")}
            title={
              connBreakdown.innerTunnelCount > 0 || connBreakdown.loopbackCount > 0
                ? `真实应用连接 ${connBreakdown.appCount} 条（另含 ${connBreakdown.innerTunnelCount} 条${innerCountShortLabel} · ${connBreakdown.loopbackCount} 条本机回环）`
                : `真实应用连接 ${connBreakdown.appCount} 条`
            }
            className={`inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-lg px-3 py-1.5 font-medium transition-colors ${
              activeTab === "connections"
                ? "bg-[var(--card)] text-[var(--accent)] shadow-xs"
                : "text-[var(--muted)] hover:text-[var(--text)]"
            }`}
          >
            <Activity className="h-3.5 w-3.5 shrink-0" />
            当前连接
            <span className="cc-mono rounded-full bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10px]">
              {connBreakdown.appCount}
            </span>
          </button>
        </div>
      </section>

      {activeTab === "rules" ? (
        <RulesTab onRulesCountChange={handleRulesCountChange} />
      ) : (
        <ConnectionsTab onBreakdownChange={handleBreakdownChange} />
      )}
    </div>
  );
}
