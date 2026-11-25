import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Download,
  FileArchive,
  FolderPlus,
  Layers,
  Loader2,
  Package,
  Search,
  Server,
  ShieldAlert,
  Upload,
  X,
  Zap,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import {
  type ShareBundlePreview,
  type SubscriptionUpdateMode,
  catcloudApi,
  formatErrorMessage,
} from "../api/tauri";
import { normalizeUiLanguage, useUiDict } from "../i18n";
import { appActions, useAppSelector } from "../store/appStore";
import { getRegionLabel, resolveNodeRegionCode } from "../utils/regions";
import { AppSelect } from "./AppSelect";

export interface ShareBundleModalProps {
  open: boolean;
  mode: "export" | "import";
  onClose: () => void;
  initialNodeIds?: string[];
  initialRelayIds?: string[];
  defaultTab?: "nodes" | "relays";
  defaultPackName?: string;
  allowModeSwitch?: boolean;
}

function formatCreatedAt(raw: string | null | undefined): string {
  if (!raw) return "--";
  const d = new Date(raw);
  if (Number.isNaN(d.getTime())) return raw;
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd} ${hh}:${mi}`;
}

export function ShareBundleModal({
  open,
  mode,
  onClose,
  initialNodeIds,
  initialRelayIds,
  defaultTab = "nodes",
  defaultPackName,
  allowModeSwitch = true,
}: ShareBundleModalProps) {
  const nodes = useAppSelector((s) => s.nodes);
  const subscriptions = useAppSelector((s) => s.subscriptions);
  const relays = useAppSelector((s) => s.preAccelRelays);
  const uiLang = useAppSelector((s) => s.config.personalization.ui_language);
  const dict = useUiDict(normalizeUiLanguage(uiLang));

  const [activeMode, setActiveMode] = useState<"export" | "import">(mode);

  // Export mode state
  const [exportTab, setExportTab] = useState<"nodes" | "relays">(defaultTab);
  const [packName, setPackName] = useState<string>(defaultPackName || "猫猫云梯分享包");
  const [packDesc, setPackDesc] = useState<string>("");
  const [selectedNodeIds, setSelectedNodeIds] = useState<Set<string>>(() => new Set());
  const [selectedRelayIds, setSelectedRelayIds] = useState<Set<string>>(() => new Set());
  const [exportSubFilter, setExportSubFilter] = useState<string>("all");
  const [exportRegionFilter, setExportRegionFilter] = useState<string>("all");
  const [exportNodeSearch, setExportNodeSearch] = useState<string>("");
  const [exporting, setExporting] = useState<boolean>(false);
  const [exportError, setExportError] = useState<string | null>(null);

  // Import mode state
  const [pickingZip, setPickingZip] = useState<boolean>(false);
  const [preview, setPreview] = useState<ShareBundlePreview | null>(null);
  const [importTab, setImportTab] = useState<"nodes" | "relays">("nodes");
  const [importNodeSearch, setImportNodeSearch] = useState<string>("");
  const [importNodeIds, setImportNodeIds] = useState<Set<string>>(() => new Set());
  const [importRelayIds, setImportRelayIds] = useState<Set<string>>(() => new Set());
  const [importDestMode, setImportDestMode] = useState<"new" | "existing">("new");
  const [importNewSubName, setImportNewSubName] = useState<string>("");
  const [importTargetSubId, setImportTargetSubId] = useState<string>("");
  const [importUpdateMode, setImportUpdateMode] = useState<SubscriptionUpdateMode>("merge_dedup");
  const [importing, setImporting] = useState<boolean>(false);
  const [importError, setImportError] = useState<string | null>(null);

  const busy = exporting || pickingZip || importing;

  // Reset modal session cleanly whenever opened
  useEffect(() => {
    if (!open) return;

    setActiveMode(mode);
    setExportTab(defaultTab);
    setPackName(defaultPackName?.trim() || "猫猫云梯分享包");
    setPackDesc("");
    setExportSubFilter("all");
    setExportRegionFilter("all");
    setExportNodeSearch("");
    setExportError(null);

    const existingNodeIdSet = new Set(nodes.map((n) => n.id));
    const initNodes = new Set<string>();
    if (Array.isArray(initialNodeIds)) {
      for (const id of initialNodeIds) {
        if (existingNodeIdSet.has(id)) initNodes.add(id);
      }
    }
    setSelectedNodeIds(initNodes);

    const existingRelayIdSet = new Set(relays.map((r) => r.id));
    const initRelays = new Set<string>();
    if (Array.isArray(initialRelayIds)) {
      for (const id of initialRelayIds) {
        if (existingRelayIdSet.has(id)) initRelays.add(id);
      }
    }
    setSelectedRelayIds(initRelays);

    setPreview(null);
    setImportTab("nodes");
    setImportNodeSearch("");
    setImportNodeIds(new Set());
    setImportRelayIds(new Set());
    setImportDestMode("new");
    setImportNewSubName("");
    setImportTargetSubId(subscriptions[0]?.id ?? "");
    setImportUpdateMode("merge_dedup");
    setImportError(null);
    // Intentionally initialize only when opening modal or changing entry props
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, mode, defaultTab, defaultPackName, initialNodeIds, initialRelayIds]);

  // Keep valid targetSubId if subscriptions change
  useEffect(() => {
    if (!open) return;
    if (subscriptions.length === 0) {
      if (importDestMode === "existing") setImportDestMode("new");
      if (importTargetSubId !== "") setImportTargetSubId("");
    } else if (!subscriptions.some((s) => s.id === importTargetSubId)) {
      setImportTargetSubId(subscriptions[0].id);
    }
  }, [open, subscriptions, importDestMode, importTargetSubId]);

  // Escape to close when not busy
  useEffect(() => {
    if (!open) return;
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape" && !busy) {
        onClose();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, busy, onClose]);

  const subNameMap = useMemo(() => {
    const map = new Map<string, string>();
    for (const s of subscriptions) {
      map.set(s.id, s.name);
    }
    return map;
  }, [subscriptions]);

  const subNodeCounts = useMemo(() => {
    const map = new Map<string, number>();
    for (const n of nodes) {
      map.set(n.sub_id, (map.get(n.sub_id) ?? 0) + 1);
    }
    return map;
  }, [nodes]);

  const exportRegionOptions = useMemo(() => {
    const counts = new Map<string, number>();
    for (const n of nodes) {
      if (exportSubFilter !== "all" && n.sub_id !== exportSubFilter) continue;
      const code = resolveNodeRegionCode(n);
      counts.set(code, (counts.get(code) ?? 0) + 1);
    }
    const items = Array.from(counts.entries())
      .map(([code, count]) => ({
        value: code,
        label: `${getRegionLabel(code)} (${code}) · ${count}`,
        count,
      }))
      .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
    return [{ value: "all", label: "全部地区" }, ...items.map(({ value, label }) => ({ value, label }))];
  }, [nodes, exportSubFilter]);

  const filteredExportNodes = useMemo(() => {
    const kw = exportNodeSearch.trim().toLowerCase();
    return nodes.filter((n) => {
      if (exportSubFilter !== "all" && n.sub_id !== exportSubFilter) return false;
      const regionCode = resolveNodeRegionCode(n);
      if (exportRegionFilter !== "all" && regionCode !== exportRegionFilter) return false;
      if (kw) {
        const subName = subNameMap.get(n.sub_id) ?? "";
        const regionLabel = getRegionLabel(regionCode);
        const hay = `${n.name} ${subName} ${regionCode} ${regionLabel} ${n.protocol}`.toLowerCase();
        if (!hay.includes(kw)) return false;
      }
      return true;
    });
  }, [nodes, exportSubFilter, exportRegionFilter, exportNodeSearch, subNameMap]);

  const allFilteredExportNodesSelected = useMemo(
    () =>
      filteredExportNodes.length > 0 &&
      filteredExportNodes.every((n) => selectedNodeIds.has(n.id)),
    [filteredExportNodes, selectedNodeIds]
  );

  const filteredImportNodes = useMemo(() => {
    if (!preview) return [];
    const kw = importNodeSearch.trim().toLowerCase();
    if (!kw) return preview.nodes;
    return preview.nodes.filter((n) => {
      const code = resolveNodeRegionCode(n);
      const label = getRegionLabel(code);
      const hay = `${n.name} ${code} ${label} ${n.protocol} ${n.server}`.toLowerCase();
      return hay.includes(kw);
    });
  }, [preview, importNodeSearch]);

  const toggleExportNode = (id: string) => {
    setSelectedNodeIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleExportRelay = (id: string) => {
    setSelectedRelayIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleSelectAllFilteredExportNodes = () => {
    if (filteredExportNodes.length === 0) return;
    setSelectedNodeIds((prev) => {
      const next = new Set(prev);
      for (const n of filteredExportNodes) next.add(n.id);
      return next;
    });
  };

  const handleClearFilteredExportNodes = () => {
    if (filteredExportNodes.length === 0) return;
    setSelectedNodeIds((prev) => {
      const next = new Set(prev);
      for (const n of filteredExportNodes) next.delete(n.id);
      return next;
    });
  };

  const handleExportBundle = async () => {
    if (busy) return;
    const nodeIds = Array.from(selectedNodeIds);
    const relayIds = Array.from(selectedRelayIds);
    if (nodeIds.length === 0 && relayIds.length === 0) {
      setExportError("请至少勾选 1 个节点或 1 条国内提速中转线路");
      return;
    }

    setExporting(true);
    setExportError(null);
    try {
      const res = await catcloudApi.exportShareBundleDialog({
        name: packName.trim() || "猫猫云梯分享包",
        description: packDesc.trim() || null,
        nodeIds,
        relayIds,
      });
      if (res.cancelled) {
        return;
      }
      const savedPath = res.path ? `：${res.path}` : "";
      appActions.showToast(
        `分享包已保存（${nodeIds.length} 节点 · ${relayIds.length} 中转）${savedPath}`,
        "ok",
        5200
      );
      onClose();
    } catch (err) {
      const msg = formatErrorMessage(err);
      setExportError(msg);
      appActions.showToast(`导出分享包失败：${msg}`, "warn");
    } finally {
      setExporting(false);
    }
  };

  const handlePickPreviewZip = async () => {
    if (busy) return;
    setPickingZip(true);
    setImportError(null);
    try {
      const res = await catcloudApi.pickAndPreviewShareBundle();
      if (!res) {
        return;
      }
      setPreview(res);
      setImportNodeIds(new Set(res.nodes.map((n) => n.id)));
      setImportRelayIds(new Set(res.relays.map((r) => r.id)));
      setImportNodeSearch("");
      setImportNewSubName(res.manifest.name?.trim() || "朋友分享包");
      setImportTab(res.nodes.length > 0 ? "nodes" : "relays");
      if (subscriptions.length === 0) {
        setImportDestMode("new");
      }
    } catch (err) {
      const msg = formatErrorMessage(err);
      setImportError(msg);
      appActions.showToast(`读取分享包失败：${msg}`, "warn");
    } finally {
      setPickingZip(false);
    }
  };

  const toggleImportNode = (id: string) => {
    setImportNodeIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleImportRelay = (id: string) => {
    setImportRelayIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleConfirmImport = async () => {
    if (!preview || busy) return;
    const pickedNodes = Array.from(importNodeIds);
    const pickedRelays = Array.from(importRelayIds);
    if (pickedNodes.length === 0 && pickedRelays.length === 0) {
      setImportError("请至少勾选 1 个要导入的节点或 1 条国内提速中转");
      return;
    }
    if (pickedNodes.length > 0 && importDestMode === "existing" && !importTargetSubId) {
      setImportError("请选择要并入的目标已有分组");
      return;
    }

    setImporting(true);
    setImportError(null);
    try {
      const outcome = await catcloudApi.importShareBundle({
        zipPath: preview.zip_path,
        selectedNodeIds: pickedNodes,
        selectedRelayIds: pickedRelays,
        targetSubId:
          pickedNodes.length > 0 && importDestMode === "existing"
            ? importTargetSubId
            : null,
        newSubName:
          pickedNodes.length > 0 && importDestMode === "new"
            ? importNewSubName.trim() || preview.manifest.name?.trim() || "朋友分享包"
            : null,
        updateMode: importUpdateMode,
      });

      await appActions.refreshAllData();

      const summaryParts: string[] = [];
      if (outcome.imported_nodes > 0) {
        const subSuffix = outcome.target_sub_name ? `至「${outcome.target_sub_name}」` : "";
        summaryParts.push(`${outcome.imported_nodes} 个节点${subSuffix}`);
      }
      if (outcome.imported_relays > 0) {
        summaryParts.push(`${outcome.imported_relays} 条国内中转`);
      }
      const warnSuffix =
        outcome.warnings.length > 0 ? `（含 ${outcome.warnings.length} 条提示）` : "";
      appActions.showToast(
        `分享包导入完成：已导入 ${summaryParts.join("、") || "所选内容"}${warnSuffix}`,
        "ok",
        5000
      );
      onClose();
    } catch (err) {
      const msg = formatErrorMessage(err);
      setImportError(msg);
      appActions.showToast(`导入分享包失败：${msg}`, "warn");
    } finally {
      setImporting(false);
    }
  };

  if (!open || typeof document === "undefined") return null;

  const totalExportSelected = selectedNodeIds.size + selectedRelayIds.size;
  const totalImportSelected = importNodeIds.size + importRelayIds.size;

  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4 backdrop-blur-[2px]"
      onClick={() => {
        if (!busy) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={activeMode === "export" ? dict.share.exportTitle : dict.share.importTitle}
        onClick={(e) => e.stopPropagation()}
        className="cc-surface flex max-h-[86vh] w-full max-w-2xl flex-col overflow-hidden rounded-2xl border border-[var(--line-strong)] shadow-2xl"
      >
        {/* Modal Header */}
        <div className="flex items-center justify-between gap-3 border-b border-[var(--line)] px-5 py-3.5">
          <div className="flex min-w-0 items-center gap-2.5">
            <span className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-[var(--accent-soft)] text-[var(--accent)]">
              <Package className="h-4 w-4" />
            </span>
            <div className="min-w-0">
              <h3 className="truncate text-sm font-semibold text-[var(--text)]">
                {activeMode === "export" ? dict.share.exportTitle : dict.share.importTitle}
              </h3>
              <p className="mt-0.5 truncate text-[11px] text-[var(--muted)]">
                {activeMode === "export"
                  ? "把精选节点或国内提速中转打包成单个 .zip，方便私发给信任的朋友一键导入"
                  : "选择朋友发来的猫云 .zip 分享包，预览并自由勾选要导入的节点与中转"}
              </p>
            </div>
          </div>

          <div className="flex shrink-0 items-center gap-2">
            {allowModeSwitch && (
              <div
                className="inline-flex rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-0.5 text-[11px]"
                role="tablist"
                aria-label="分享包操作模式"
              >
                <button
                  type="button"
                  role="tab"
                  aria-selected={activeMode === "export"}
                  disabled={busy}
                  onClick={() => setActiveMode("export")}
                  className={`inline-flex items-center gap-1 rounded-lg px-2.5 py-1 font-medium transition-colors ${
                    activeMode === "export"
                      ? "bg-[var(--accent)] text-[var(--accent-ink)]"
                      : "text-[var(--text-secondary)] hover:text-[var(--text)]"
                  }`}
                >
                  <Upload className="h-3 w-3" />
                  <span>{dict.common.export}</span>
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={activeMode === "import"}
                  disabled={busy}
                  onClick={() => setActiveMode("import")}
                  className={`inline-flex items-center gap-1 rounded-lg px-2.5 py-1 font-medium transition-colors ${
                    activeMode === "import"
                      ? "bg-[var(--accent)] text-[var(--accent-ink)]"
                      : "text-[var(--text-secondary)] hover:text-[var(--text)]"
                  }`}
                >
                  <Download className="h-3 w-3" />
                  <span>{dict.common.import}</span>
                </button>
              </div>
            )}

            <button
              type="button"
              disabled={busy}
              onClick={onClose}
              aria-label={dict.common.close}
              className="rounded-lg p-1.5 text-[var(--muted)] transition-colors hover:bg-[var(--bg-elevated)] hover:text-[var(--text)] disabled:opacity-45"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Scrollable Body */}
        <div className="min-h-0 flex-1 space-y-3.5 overflow-y-auto px-5 py-4">
          {activeMode === "export" ? (
            <>
              {/* Warm Amber Privacy Notice */}
              <div className="flex items-start gap-2.5 rounded-xl border border-[var(--amber)]/50 bg-[var(--amber-soft)]/70 px-3.5 py-2.5 text-xs text-[var(--amber)]">
                <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
                <p className="leading-relaxed">{dict.share.privacyWarn}</p>
              </div>

              {/* Pack Name & Optional Description */}
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-12">
                <label className="block text-[11px] font-medium text-[var(--text-secondary)] sm:col-span-5">
                  {dict.share.packNameLabel}
                  <input
                    type="text"
                    disabled={exporting}
                    value={packName}
                    onChange={(e) => setPackName(e.target.value)}
                    placeholder={dict.share.packNamePlaceholder}
                    className="mt-1 w-full rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 text-xs text-[var(--text)] outline-none transition-colors focus:border-[var(--accent)]"
                  />
                </label>

                <label className="block text-[11px] font-medium text-[var(--text-secondary)] sm:col-span-7">
                  简短备注（可选）
                  <input
                    type="text"
                    disabled={exporting}
                    value={packDesc}
                    onChange={(e) => setPackDesc(e.target.value)}
                    placeholder="例如：晚高峰延迟低，含日本与台湾节点"
                    className="mt-1 w-full rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 text-xs text-[var(--text)] outline-none transition-colors focus:border-[var(--accent)]"
                  />
                </label>
              </div>

              {/* Dual Tabs: Nodes & Relays */}
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--line)] pb-2.5">
                <div className="inline-flex items-center gap-1.5">
                  <button
                    type="button"
                    onClick={() => setExportTab("nodes")}
                    className={`inline-flex items-center gap-1.5 rounded-xl border px-3 py-1.5 text-xs font-medium transition-colors ${
                      exportTab === "nodes"
                        ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                        : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                    }`}
                  >
                    <Server className="h-3.5 w-3.5" />
                    <span>{dict.share.selectNodesTab}</span>
                    <span
                      className={`cc-mono rounded-full px-1.5 py-0.2 text-[10px] font-semibold ${
                        selectedNodeIds.size > 0
                          ? "bg-[var(--accent)] text-[var(--accent-ink)]"
                          : "bg-[var(--card)] text-[var(--muted)]"
                      }`}
                    >
                      {selectedNodeIds.size}
                    </span>
                  </button>

                  <button
                    type="button"
                    onClick={() => setExportTab("relays")}
                    className={`inline-flex items-center gap-1.5 rounded-xl border px-3 py-1.5 text-xs font-medium transition-colors ${
                      exportTab === "relays"
                        ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                        : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                    }`}
                  >
                    <Zap className="h-3.5 w-3.5" />
                    <span>{dict.share.selectRelaysTab}</span>
                    <span
                      className={`cc-mono rounded-full px-1.5 py-0.2 text-[10px] font-semibold ${
                        selectedRelayIds.size > 0
                          ? "bg-[var(--accent)] text-[var(--accent-ink)]"
                          : "bg-[var(--card)] text-[var(--muted)]"
                      }`}
                    >
                      {selectedRelayIds.size}
                    </span>
                  </button>
                </div>

                {exportTab === "nodes" ? (
                  <div className="flex items-center gap-1.5 text-[11px]">
                    <button
                      type="button"
                      disabled={filteredExportNodes.length === 0}
                      onClick={
                        allFilteredExportNodesSelected
                          ? handleClearFilteredExportNodes
                          : handleSelectAllFilteredExportNodes
                      }
                      className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-45"
                    >
                      {allFilteredExportNodesSelected ? "清空当前筛选" : "全选当前筛选"}
                    </button>
                    {selectedNodeIds.size > 0 && (
                      <button
                        type="button"
                        onClick={() => setSelectedNodeIds(new Set())}
                        className="rounded-lg px-2 py-1 text-[var(--muted)] hover:text-[var(--text)]"
                      >
                        清空全部
                      </button>
                    )}
                  </div>
                ) : (
                  <div className="flex items-center gap-1.5 text-[11px]">
                    <button
                      type="button"
                      disabled={relays.length === 0}
                      onClick={() =>
                        setSelectedRelayIds(
                          new Set(relays.filter((r) => r.enabled).map((r) => r.id))
                        )
                      }
                      className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-45"
                    >
                      全选已启用
                    </button>
                    <button
                      type="button"
                      disabled={relays.length === 0}
                      onClick={() => setSelectedRelayIds(new Set(relays.map((r) => r.id)))}
                      className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-45"
                    >
                      全选全部
                    </button>
                    {selectedRelayIds.size > 0 && (
                      <button
                        type="button"
                        onClick={() => setSelectedRelayIds(new Set())}
                        className="rounded-lg px-2 py-1 text-[var(--muted)] hover:text-[var(--text)]"
                      >
                        清空
                      </button>
                    )}
                  </div>
                )}
              </div>

              {/* Export Nodes Selector */}
              {exportTab === "nodes" && (
                <div className="space-y-2.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <AppSelect
                      aria-label="按订阅来源筛选"
                      size="sm"
                      value={exportSubFilter}
                      onChange={(val) => {
                        setExportSubFilter(val);
                        setExportRegionFilter("all");
                      }}
                      options={[
                        { value: "all", label: `全部来源 (${nodes.length})` },
                        ...subscriptions.map((sub) => ({
                          value: sub.id,
                          label: `${sub.name} (${subNodeCounts.get(sub.id) ?? 0})`,
                        })),
                      ]}
                      className="min-w-[140px] max-w-[200px]"
                    />

                    <AppSelect
                      aria-label="按地区筛选"
                      size="sm"
                      value={exportRegionFilter}
                      onChange={setExportRegionFilter}
                      options={exportRegionOptions}
                      className="min-w-[125px] max-w-[180px]"
                    />

                    <div className="relative min-w-[160px] flex-1">
                      <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--muted)]" />
                      <input
                        type="text"
                        value={exportNodeSearch}
                        onChange={(e) => setExportNodeSearch(e.target.value)}
                        placeholder="搜索节点名称、地区或协议…"
                        className="w-full rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] py-1.5 pl-8 pr-7 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                      />
                      {exportNodeSearch && (
                        <button
                          type="button"
                          onClick={() => setExportNodeSearch("")}
                          aria-label="清空搜索"
                          className="absolute right-2 top-1/2 -translate-y-1/2 text-[var(--muted)] hover:text-[var(--text)]"
                        >
                          <X className="h-3.5 w-3.5" />
                        </button>
                      )}
                    </div>
                  </div>

                  {filteredExportNodes.length === 0 ? (
                    <div className="rounded-xl border border-dashed border-[var(--line)] px-4 py-8 text-center text-xs text-[var(--muted)]">
                      {nodes.length === 0
                        ? "当前还没有可导出的节点，也可以切到「选择国内提速中转」仅打包中转线路"
                        : "当前筛选条件下没有匹配节点"}
                    </div>
                  ) : (
                    <div className="max-h-60 space-y-1 overflow-y-auto rounded-xl border border-[var(--line)] bg-[var(--card)]/70 p-2">
                      {filteredExportNodes.map((node) => {
                        const checked = selectedNodeIds.has(node.id);
                        const regionCode = resolveNodeRegionCode(node);
                        const subName = subNameMap.get(node.sub_id) ?? node.sub_id;
                        return (
                          <label
                            key={node.id}
                            className={`flex cursor-pointer items-center justify-between gap-2.5 rounded-lg border px-2.5 py-1.5 text-xs transition-colors ${
                              checked
                                ? "border-[var(--accent)]/50 bg-[var(--accent-soft)]/50"
                                : "border-transparent bg-[var(--bg-elevated)]/65 hover:border-[var(--line)]"
                            }`}
                          >
                            <div className="flex min-w-0 flex-1 items-center gap-2">
                              <input
                                type="checkbox"
                                checked={checked}
                                onChange={() => toggleExportNode(node.id)}
                                className="h-3.5 w-3.5 shrink-0 cursor-pointer accent-[var(--accent)]"
                              />
                              <div className="min-w-0 flex-1">
                                <div className="truncate font-medium text-[var(--text)]">
                                  {node.name}
                                </div>
                                <div className="truncate text-[10.5px] text-[var(--muted)]">
                                  {subName} · {node.protocol.toUpperCase()}
                                </div>
                              </div>
                            </div>
                            <div className="flex shrink-0 items-center gap-1 cc-mono text-[10px]">
                              <span
                                title={getRegionLabel(regionCode)}
                                className="rounded bg-[var(--card)] px-1.5 py-0.5 text-[var(--text-secondary)]"
                              >
                                {regionCode}
                              </span>
                              <span className="rounded bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[var(--muted)]">
                                {node.multiplier}x
                              </span>
                            </div>
                          </label>
                        );
                      })}
                    </div>
                  )}
                </div>
              )}

              {/* Export Relays Selector (strictly never expose plaintext password) */}
              {exportTab === "relays" && (
                <div className="space-y-2">
                  {relays.length === 0 ? (
                    <div className="rounded-xl border border-dashed border-[var(--line)] px-4 py-8 text-center text-xs text-[var(--muted)]">
                      还没有添加国内提速中转线路
                    </div>
                  ) : (
                    <div className="max-h-64 space-y-1.5 overflow-y-auto rounded-xl border border-[var(--line)] bg-[var(--card)]/70 p-2">
                      {relays.map((relay) => {
                        const checked = selectedRelayIds.has(relay.id);
                        return (
                          <label
                            key={relay.id}
                            className={`flex cursor-pointer items-center justify-between gap-2.5 rounded-lg border px-3 py-2 text-xs transition-colors ${
                              checked
                                ? "border-[var(--accent)]/50 bg-[var(--accent-soft)]/50"
                                : "border-transparent bg-[var(--bg-elevated)]/65 hover:border-[var(--line)]"
                            }`}
                          >
                            <div className="flex min-w-0 flex-1 items-center gap-2.5">
                              <input
                                type="checkbox"
                                checked={checked}
                                onChange={() => toggleExportRelay(relay.id)}
                                className="h-3.5 w-3.5 shrink-0 cursor-pointer accent-[var(--accent)]"
                              />
                              <div className="min-w-0 flex-1">
                                <div className="flex flex-wrap items-center gap-1.5">
                                  <span className="truncate font-semibold text-[var(--text)]">
                                    {relay.name}
                                  </span>
                                  <span
                                    className={`rounded-full px-1.5 py-0.2 text-[10px] font-medium ${
                                      relay.enabled
                                        ? "bg-[var(--green-soft)] text-[var(--green)]"
                                        : "bg-[var(--card)] text-[var(--muted)]"
                                    }`}
                                  >
                                    {relay.enabled ? "已启用" : "已停用"}
                                  </span>
                                </div>
                                <div className="mt-0.5 flex flex-wrap items-center gap-2 text-[10.5px] text-[var(--muted)]">
                                  <span>{relay.region || "国内"}</span>
                                  <span>·</span>
                                  <span className="cc-mono uppercase">{relay.protocol}</span>
                                  <span>·</span>
                                  <span className="cc-mono">端口 {relay.port}</span>
                                </div>
                              </div>
                            </div>
                            <span className="shrink-0 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-0.5 cc-mono text-[10px] text-[var(--muted)]">
                              凭据已隐藏
                            </span>
                          </label>
                        );
                      })}
                    </div>
                  )}
                </div>
              )}

              {exportError && (
                <div className="flex items-start gap-2 rounded-xl border border-[var(--red)]/45 bg-[var(--red-soft)] px-3 py-2 text-xs text-[var(--red)]">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>{exportError}</span>
                </div>
              )}
            </>
          ) : (
            /* ======================== IMPORT MODE ======================== */
            <>
              {/* Pick .zip Trigger Card */}
              <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)]/80 px-4 py-3">
                <div className="flex min-w-0 items-center gap-2.5">
                  <span className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-[var(--accent-soft)] text-[var(--accent)]">
                    <FileArchive className="h-4 w-4" />
                  </span>
                  <div className="min-w-0">
                    <div className="truncate text-xs font-semibold text-[var(--text)]">
                      {preview ? preview.manifest.name : "选择朋友分享的 .zip 文件"}
                    </div>
                    <div
                      className="mt-0.5 truncate cc-mono text-[10.5px] text-[var(--muted)]"
                      title={preview?.zip_path ?? undefined}
                    >
                      {preview
                        ? `${preview.zip_path} · ${formatCreatedAt(preview.manifest.created_at)}`
                        : "支持 catcloud-share/v1 标准分享包（节点 + 国内中转）"}
                    </div>
                  </div>
                </div>

                <button
                  type="button"
                  disabled={busy}
                  onClick={() => void handlePickPreviewZip()}
                  className="inline-flex shrink-0 items-center gap-1.5 rounded-xl bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-55"
                >
                  {pickingZip ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <FileArchive className="h-3.5 w-3.5" />
                  )}
                  <span>
                    {pickingZip
                      ? "正在解析…"
                      : preview
                        ? "重新选择 .zip"
                        : dict.share.pickZipBtn}
                  </span>
                </button>
              </div>

              {!preview ? (
                <div className="space-y-3 rounded-xl border border-dashed border-[var(--line)] px-5 py-8 text-center">
                  <p className="text-xs leading-relaxed text-[var(--text-secondary)]">
                    点击上方「{dict.share.pickZipBtn}」后，猫猫会先安全解析包内清单，供你自由挑选需要导入的节点或国内中转，确认后才会写入本地。
                  </p>
                  <p className="text-[11px] text-[var(--muted)]">
                    只导入来自你信任的朋友的分享包，避免导入陌生来源配置。
                  </p>
                </div>
              ) : (
                <>
                  {/* Manifest Details & Source Trust Banner */}
                  <div className="space-y-2 rounded-xl border border-[var(--amber)]/50 bg-[var(--amber-soft)]/60 px-3.5 py-2.5 text-xs">
                    <div className="flex items-start gap-2 text-[var(--amber)]">
                      <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
                      <div className="min-w-0 flex-1 leading-relaxed">
                        <div className="font-semibold">请确认来源可靠后再导入</div>
                        <p className="mt-0.5 text-[11px]">
                          {preview.manifest.sanitized_notice || dict.share.privacyWarn}
                        </p>
                      </div>
                    </div>
                    {preview.manifest.description && (
                      <div className="rounded-lg bg-[var(--card)]/80 px-2.5 py-1.5 text-[11px] text-[var(--text-secondary)]">
                        <span className="font-medium text-[var(--text)]">分享备注：</span>
                        {preview.manifest.description}
                      </div>
                    )}
                  </div>

                  {preview.warnings.length > 0 && (
                    <div className="rounded-xl border border-[var(--amber)]/45 bg-[var(--bg-elevated)] px-3.5 py-2 text-[11px] text-[var(--amber)]">
                      <div className="font-semibold">解析提醒</div>
                      <ul className="mt-1 list-disc space-y-0.5 pl-4">
                        {preview.warnings.map((w, idx) => (
                          <li key={idx}>{w}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Import Selection Tabs */}
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--line)] pb-2">
                    <div className="inline-flex items-center gap-1.5">
                      <button
                        type="button"
                        onClick={() => setImportTab("nodes")}
                        className={`inline-flex items-center gap-1.5 rounded-xl border px-3 py-1.5 text-xs font-medium transition-colors ${
                          importTab === "nodes"
                            ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                            : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                        }`}
                      >
                        <Server className="h-3.5 w-3.5" />
                        <span>节点</span>
                        <span className="cc-mono rounded-full bg-[var(--card)] px-1.5 py-0.2 text-[10px] font-semibold">
                          {importNodeIds.size}/{preview.nodes.length}
                        </span>
                      </button>

                      <button
                        type="button"
                        onClick={() => setImportTab("relays")}
                        className={`inline-flex items-center gap-1.5 rounded-xl border px-3 py-1.5 text-xs font-medium transition-colors ${
                          importTab === "relays"
                            ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                            : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                        }`}
                      >
                        <Zap className="h-3.5 w-3.5" />
                        <span>国内中转</span>
                        <span className="cc-mono rounded-full bg-[var(--card)] px-1.5 py-0.2 text-[10px] font-semibold">
                          {importRelayIds.size}/{preview.relays.length}
                        </span>
                      </button>
                    </div>

                    {importTab === "nodes" && preview.nodes.length > 0 && (
                      <div className="flex items-center gap-1.5 text-[11px]">
                        <button
                          type="button"
                          onClick={() =>
                            setImportNodeIds(new Set(preview.nodes.map((n) => n.id)))
                          }
                          className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-1 text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
                        >
                          全选
                        </button>
                        <button
                          type="button"
                          onClick={() => setImportNodeIds(new Set())}
                          className="rounded-lg px-2 py-1 text-[var(--muted)] hover:text-[var(--text)]"
                        >
                          清空
                        </button>
                      </div>
                    )}

                    {importTab === "relays" && preview.relays.length > 0 && (
                      <div className="flex items-center gap-1.5 text-[11px]">
                        <button
                          type="button"
                          onClick={() =>
                            setImportRelayIds(new Set(preview.relays.map((r) => r.id)))
                          }
                          className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-1 text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
                        >
                          全选
                        </button>
                        <button
                          type="button"
                          onClick={() => setImportRelayIds(new Set())}
                          className="rounded-lg px-2 py-1 text-[var(--muted)] hover:text-[var(--text)]"
                        >
                          清空
                        </button>
                      </div>
                    )}
                  </div>

                  {/* Preview Nodes Checklist */}
                  {importTab === "nodes" && (
                    <div className="space-y-2">
                      {preview.nodes.length > 6 && (
                        <div className="relative">
                          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--muted)]" />
                          <input
                            type="text"
                            value={importNodeSearch}
                            onChange={(e) => setImportNodeSearch(e.target.value)}
                            placeholder="筛选包内节点…"
                            className="w-full rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] py-1.5 pl-8 pr-3 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                          />
                        </div>
                      )}

                      {preview.nodes.length === 0 ? (
                        <div className="rounded-xl border border-dashed border-[var(--line)] px-4 py-6 text-center text-xs text-[var(--muted)]">
                          该分享包不包含代理节点
                        </div>
                      ) : (
                        <div className="max-h-44 space-y-1 overflow-y-auto rounded-xl border border-[var(--line)] bg-[var(--card)]/70 p-2">
                          {filteredImportNodes.map((node) => {
                            const checked = importNodeIds.has(node.id);
                            const code = resolveNodeRegionCode(node);
                            return (
                              <label
                                key={node.id}
                                className={`flex cursor-pointer items-center justify-between gap-2 rounded-lg border px-2.5 py-1.5 text-xs transition-colors ${
                                  checked
                                    ? "border-[var(--accent)]/50 bg-[var(--accent-soft)]/45"
                                    : "border-transparent bg-[var(--bg-elevated)]/55 opacity-60 hover:opacity-100"
                                }`}
                              >
                                <div className="flex min-w-0 flex-1 items-center gap-2">
                                  <input
                                    type="checkbox"
                                    checked={checked}
                                    onChange={() => toggleImportNode(node.id)}
                                    className="h-3.5 w-3.5 shrink-0 cursor-pointer accent-[var(--accent)]"
                                  />
                                  <div className="min-w-0 flex-1">
                                    <div className="truncate font-medium text-[var(--text)]">
                                      {node.name}
                                    </div>
                                    <div className="cc-mono text-[10px] text-[var(--muted)]">
                                      {node.protocol.toUpperCase()} · :{node.port}
                                    </div>
                                  </div>
                                </div>
                                <div className="flex shrink-0 items-center gap-1 cc-mono text-[10px]">
                                  <span
                                    title={getRegionLabel(code)}
                                    className="rounded bg-[var(--card)] px-1.5 py-0.5 text-[var(--text-secondary)]"
                                  >
                                    {code}
                                  </span>
                                  <span className="rounded bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[var(--muted)]">
                                    {node.multiplier}x
                                  </span>
                                </div>
                              </label>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  )}

                  {/* Preview Relays Checklist (never display password) */}
                  {importTab === "relays" && (
                    <div>
                      {preview.relays.length === 0 ? (
                        <div className="rounded-xl border border-dashed border-[var(--line)] px-4 py-6 text-center text-xs text-[var(--muted)]">
                          该分享包不包含国内提速中转线路
                        </div>
                      ) : (
                        <div className="max-h-44 space-y-1.5 overflow-y-auto rounded-xl border border-[var(--line)] bg-[var(--card)]/70 p-2">
                          {preview.relays.map((relay) => {
                            const checked = importRelayIds.has(relay.id);
                            return (
                              <label
                                key={relay.id}
                                className={`flex cursor-pointer items-center justify-between gap-2 rounded-lg border px-3 py-2 text-xs transition-colors ${
                                  checked
                                    ? "border-[var(--accent)]/50 bg-[var(--accent-soft)]/45"
                                    : "border-transparent bg-[var(--bg-elevated)]/55 opacity-60 hover:opacity-100"
                                }`}
                              >
                                <div className="flex min-w-0 flex-1 items-center gap-2">
                                  <input
                                    type="checkbox"
                                    checked={checked}
                                    onChange={() => toggleImportRelay(relay.id)}
                                    className="h-3.5 w-3.5 shrink-0 cursor-pointer accent-[var(--accent)]"
                                  />
                                  <div className="min-w-0 flex-1">
                                    <div className="truncate font-semibold text-[var(--text)]">
                                      {relay.name}
                                    </div>
                                    <div className="text-[10.5px] text-[var(--muted)]">
                                      {relay.region || "国内"} ·{" "}
                                      <span className="cc-mono uppercase">{relay.protocol}</span> ·
                                      端口 <span className="cc-mono">{relay.port}</span>
                                    </div>
                                  </div>
                                </div>
                                <span className="shrink-0 rounded bg-[var(--card)] px-2 py-0.5 cc-mono text-[10px] text-[var(--muted)]">
                                  凭据已加密/隐藏
                                </span>
                              </label>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  )}

                  {/* Destination Grouping Selector (skip when only relays are selected) */}
                  {importNodeIds.size > 0 ? (
                    <div className="space-y-2.5 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)]/70 p-3.5">
                      <div className="text-xs font-semibold text-[var(--text)]">
                        节点导入去向
                      </div>
                      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                        <button
                          type="button"
                          onClick={() => setImportDestMode("new")}
                          className={`flex items-start gap-2 rounded-xl border p-2.5 text-left text-xs transition-colors ${
                            importDestMode === "new"
                              ? "border-[var(--accent)] bg-[var(--accent-soft)]/50 text-[var(--text)]"
                              : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:border-[var(--line-strong)]"
                          }`}
                        >
                          <FolderPlus className="mt-0.5 h-4 w-4 shrink-0 text-[var(--accent)]" />
                          <div className="min-w-0">
                            <div className="font-semibold">保存为新分组</div>
                            <div className="mt-0.5 text-[10.5px] text-[var(--muted)]">
                              单独建一个新分组存放，不影响旧订阅
                            </div>
                          </div>
                        </button>

                        <button
                          type="button"
                          disabled={subscriptions.length === 0}
                          onClick={() => setImportDestMode("existing")}
                          className={`flex items-start gap-2 rounded-xl border p-2.5 text-left text-xs transition-colors disabled:cursor-not-allowed disabled:opacity-45 ${
                            importDestMode === "existing"
                              ? "border-[var(--accent)] bg-[var(--accent-soft)]/50 text-[var(--text)]"
                              : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:border-[var(--line-strong)]"
                          }`}
                        >
                          <Layers className="mt-0.5 h-4 w-4 shrink-0 text-[var(--accent)]" />
                          <div className="min-w-0">
                            <div className="font-semibold">并入已有分组</div>
                            <div className="mt-0.5 text-[10.5px] text-[var(--muted)]">
                              {subscriptions.length === 0
                                ? "当前暂无已有分组"
                                : "合并进现有分组，可选择替换或去重"}
                            </div>
                          </div>
                        </button>
                      </div>

                      {importDestMode === "new" ? (
                        <label className="block text-[11px] text-[var(--muted)]">
                          新分组名称
                          <input
                            type="text"
                            disabled={importing}
                            value={importNewSubName}
                            onChange={(e) => setImportNewSubName(e.target.value)}
                            placeholder={preview.manifest.name || "朋友分享包"}
                            className="mt-1 w-full rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                          />
                        </label>
                      ) : (
                        <div className="space-y-2.5">
                          <div className="flex flex-col gap-1">
                            <span className="text-[11px] text-[var(--muted)]">选择目标已有分组</span>
                            <AppSelect
                              aria-label="选择目标已有分组"
                              size="sm"
                              value={importTargetSubId}
                              onChange={setImportTargetSubId}
                              options={subscriptions.map((sub) => ({
                                value: sub.id,
                                label: `${sub.name}（${subNodeCounts.get(sub.id) ?? 0} 个节点）`,
                              }))}
                              className="w-full"
                              buttonClassName="bg-[var(--card)]"
                            />
                          </div>

                          <div className="flex flex-wrap items-center gap-2">
                            <button
                              type="button"
                              onClick={() => setImportUpdateMode("merge_dedup")}
                              className={`inline-flex items-center gap-1.5 rounded-xl border px-3 py-1.5 text-[11px] font-medium transition-colors ${
                                importUpdateMode === "merge_dedup"
                                  ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                                  : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                              }`}
                            >
                              {importUpdateMode === "merge_dedup" && <Check className="h-3 w-3" />}
                              <span>整合去重（保留旧的并并入新的）</span>
                            </button>
                            <button
                              type="button"
                              onClick={() => setImportUpdateMode("replace_latest")}
                              className={`inline-flex items-center gap-1.5 rounded-xl border px-3 py-1.5 text-[11px] font-medium transition-colors ${
                                importUpdateMode === "replace_latest"
                                  ? "border-[var(--amber)] bg-[var(--amber-soft)] text-[var(--amber)]"
                                  : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                              }`}
                            >
                              {importUpdateMode === "replace_latest" && <Check className="h-3 w-3" />}
                              <span>保留最新（替换更新）</span>
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  ) : importRelayIds.size > 0 ? (
                    <div className="flex items-center gap-2 rounded-xl border border-[var(--green)]/35 bg-[var(--green-soft)]/45 px-3.5 py-2 text-xs text-[var(--green)]">
                      <CheckCircle2 className="h-4 w-4 shrink-0" />
                      <span>当前仅导入国内提速中转线路，将直接加入「国内提速」列表，无需选择节点分组。</span>
                    </div>
                  ) : null}
                </>
              )}

              {importError && (
                <div className="flex items-start gap-2 rounded-xl border border-[var(--red)]/45 bg-[var(--red-soft)] px-3 py-2 text-xs text-[var(--red)]">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>{importError}</span>
                </div>
              )}
            </>
          )}
        </div>

        {/* Modal Footer */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-[var(--line)] bg-[var(--bg-elevated)]/55 px-5 py-3">
          {activeMode === "export" ? (
            <>
              <div className="cc-tabular text-xs text-[var(--text-secondary)]">
                已选{" "}
                <strong className="cc-mono font-semibold text-[var(--accent)]">
                  {selectedNodeIds.size}
                </strong>{" "}
                个节点 ·{" "}
                <strong className="cc-mono font-semibold text-[var(--accent)]">
                  {selectedRelayIds.size}
                </strong>{" "}
                条中转
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  disabled={busy}
                  onClick={onClose}
                  className="rounded-xl border border-[var(--line)] bg-[var(--card)] px-3.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] hover:text-[var(--text)] disabled:opacity-50"
                >
                  {dict.common.cancel}
                </button>
                <button
                  type="button"
                  disabled={busy || totalExportSelected === 0}
                  onClick={() => void handleExportBundle()}
                  className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {exporting ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Package className="h-3.5 w-3.5" />
                  )}
                  <span>{exporting ? "正在打包保存…" : dict.share.exportBtn}</span>
                </button>
              </div>
            </>
          ) : (
            <>
              <div className="cc-tabular text-xs text-[var(--text-secondary)]">
                {preview ? (
                  <>
                    待导入{" "}
                    <strong className="cc-mono font-semibold text-[var(--accent)]">
                      {importNodeIds.size}
                    </strong>{" "}
                    个节点 ·{" "}
                    <strong className="cc-mono font-semibold text-[var(--accent)]">
                      {importRelayIds.size}
                    </strong>{" "}
                    条中转
                  </>
                ) : (
                  <span>请先选择 .zip 分享包</span>
                )}
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  disabled={busy}
                  onClick={onClose}
                  className="rounded-xl border border-[var(--line)] bg-[var(--card)] px-3.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] hover:text-[var(--text)] disabled:opacity-50"
                >
                  {dict.common.cancel}
                </button>
                <button
                  type="button"
                  disabled={busy || !preview || totalImportSelected === 0}
                  onClick={() => void handleConfirmImport()}
                  className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {importing ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Check className="h-3.5 w-3.5" />
                  )}
                  <span>{importing ? "正在导入…" : dict.share.importApplyBtn}</span>
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>,
    document.body
  );
}
