import {
  AlertTriangle,
  Check,
  FileCode2,
  FileText,
  FolderOpen,
  RefreshCw,
  Search,
  ShieldCheck,
  Upload,
  X,
} from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { catcloudApi, formatErrorMessage, isTauriEnv } from "../../api/tauri";
import { appActions } from "../../store/appStore";
import { getRegionLabel, resolveNodeRegionCode } from "../../utils/regions";
import {
  KNOWN_CLIENT_SPECS,
  KNOWN_MIGRATION_CLIENT_KINDS,
  type MigrationPreviewItem,
  defaultMigrationSubName,
  extractPathBasename,
  getMigrationDedupeKey,
  isNormalizedPathInDir,
  mapMigrationDtoToPreview,
  mergeScannedMigrationItems,
  normalizeMigrationSourcePath,
  parsePastedConfigPreview,
} from "./utils";

export interface MigrationDrawerProps {
  open: boolean;
  initialTab?: "scan" | "paste";
  initialPasteText?: string | null;
  onClose: () => void;
  onImport: (
    preview: MigrationPreviewItem,
    customName: string,
    includeRules: boolean
  ) => Promise<boolean>;
}

export function MigrationDrawer({
  open,
  initialTab = "scan",
  initialPasteText = null,
  onClose,
  onImport,
}: MigrationDrawerProps) {
  const [tab, setTab] = useState<"scan" | "paste">("scan");
  const [scanningKind, setScanningKind] = useState<
    "all" | "clash_verge" | "flclash" | "v2rayn" | "custom_dir" | "custom_file" | null
  >(null);
  const [scannedItems, setScannedItems] = useState<MigrationPreviewItem[]>([]);
  const [selectedPreviewId, setSelectedPreviewId] = useState<string | null>(null);
  const [pasteText, setPasteText] = useState("");
  const [pastePreview, setPastePreview] = useState<MigrationPreviewItem | null>(
    null
  );
  const [scanSubName, setScanSubName] = useState("");
  const [pasteSubName, setPasteSubName] = useState("");
  const [includeRules, setIncludeRules] = useState(true);
  const [importing, setImporting] = useState(false);
  const openSessionRef = useRef(false);
  const scannedItemsRef = useRef<MigrationPreviewItem[]>(scannedItems);
  scannedItemsRef.current = scannedItems;
  const selectedPreviewIdRef = useRef<string | null>(selectedPreviewId);
  selectedPreviewIdRef.current = selectedPreviewId;

  const runScanClient = useCallback(
    async (
      kind: "clash_verge" | "flclash" | "v2rayn" | "all",
      autoTriggered = false
    ) => {
      setScanningKind(kind);
      try {
        let items: MigrationPreviewItem[];
        if (isTauriEnv()) {
          const rawList = await catcloudApi.scanLocalMigrations();
          const mapped = rawList.map((dto, idx) => mapMigrationDtoToPreview(dto, idx));
          items =
            kind === "all"
              ? mapped
              : mapped.filter((item) => item.source_kind === kind);
        } else {
          const { DEMO_MIGRATION_SCANS } = await import("./demoFixtures");
          items =
            kind === "all"
              ? [
                  DEMO_MIGRATION_SCANS.clash_verge,
                  DEMO_MIGRATION_SCANS.flclash,
                  DEMO_MIGRATION_SCANS.v2rayn,
                ]
              : [DEMO_MIGRATION_SCANS[kind]];
        }

        // Replace stale entries of the re-scanned source_kind(s) so deleted files are evicted
        const retained = scannedItemsRef.current.filter((prevItem) =>
          kind === "all"
            ? !KNOWN_MIGRATION_CLIENT_KINDS.has(prevItem.source_kind)
            : prevItem.source_kind !== kind
        );
        const nextList = mergeScannedMigrationItems(retained, items, false);
        setScannedItems(nextList);

        if (items.length > 0) {
          const firstKey = getMigrationDedupeKey(items[0]);
          const matchedFirst =
            nextList.find((it) => getMigrationDedupeKey(it) === firstKey) ?? items[0];
          setSelectedPreviewId(matchedFirst.id);
          setScanSubName(defaultMigrationSubName(matchedFirst));

          const totalNodes = items.reduce((acc, i) => acc + i.nodes.length, 0);
          const totalRules = items.reduce(
            (acc, i) => acc + i.prepend_rules.length + i.append_rules.length,
            0
          );
          if (totalNodes > 0) {
            appActions.showToast(
              `已找到 ${totalNodes} 个可导入节点（不会改动原软件）`,
              "ok"
            );
          } else if (totalRules > 0 && !autoTriggered) {
            appActions.showToast(
              `扫描到 ${items.length} 份仅含分流规则的配置（共 ${totalRules} 条规则，无代理节点）`,
              "info"
            );
          }
        } else {
          const currentSelected = selectedPreviewIdRef.current;
          const stillExists = currentSelected
            ? nextList.some((it) => it.id === currentSelected)
            : false;
          if (!stillExists) {
            const fallback = nextList[0] ?? null;
            setSelectedPreviewId(fallback ? fallback.id : null);
            setScanSubName(fallback ? defaultMigrationSubName(fallback) : "");
          }
          if (!autoTriggered) {
            appActions.showToast(
              "未在常见位置找到已有软件配置，也可以点击「选择目录扫描」「选择配置文件」或切换到「粘贴配置文本」导入",
              "info"
            );
          }
        }
      } catch (err) {
        appActions.showToast(`扫描已有配置失败：${formatErrorMessage(err)}`, "warn");
      } finally {
        setScanningKind(null);
      }
    },
    []
  );

  const handlePickCustomPathScan = useCallback(
    async (pickMode: "directory" | "file") => {
      const targetLabel = pickMode === "directory" ? "目录" : "配置文件";
      if (!isTauriEnv()) {
        appActions.showToast(
          `当前为浏览器预览模式，请在桌面端猫猫云梯中使用本地${targetLabel}只读扫描，或先切换到「粘贴配置文本」体验导入`,
          "info"
        );
        return;
      }
      setScanningKind(pickMode === "directory" ? "custom_dir" : "custom_file");
      try {
        const picked =
          pickMode === "directory"
            ? await catcloudApi.pickMigrationDirectory(
                "选择已有代理软件配置目录（只读，不改动原软件）"
              )
            : await catcloudApi.pickMigrationFile(
                "选择代理配置文件（只读，不改动原文件）"
              );
        if (!picked) return;

        const rawList = await catcloudApi.scanMigrationPath(picked);
        const mapped = rawList.map((dto, idx) => mapMigrationDtoToPreview(dto, idx));

        const pickedNorm = normalizeMigrationSourcePath(picked);
        // Evict stale local_file entries under the re-scanned path/directory so deleted files disappear
        const retained = scannedItemsRef.current.filter((prevItem) => {
          if (prevItem.source_kind !== "local_file" || !pickedNorm) return true;
          const prevNorm = normalizeMigrationSourcePath(prevItem.source_path);
          if (!prevNorm) return true;
          return pickMode === "directory"
            ? !isNormalizedPathInDir(prevNorm, pickedNorm)
            : prevNorm !== pickedNorm;
        });

        const nextList = mergeScannedMigrationItems(retained, mapped, true);
        setScannedItems(nextList);

        if (mapped.length > 0) {
          const firstKey = getMigrationDedupeKey(mapped[0]);
          const matchedFirst =
            nextList.find((it) => getMigrationDedupeKey(it) === firstKey) ?? mapped[0];
          setSelectedPreviewId(matchedFirst.id);
          setScanSubName(defaultMigrationSubName(matchedFirst));

          const totalNodes = mapped.reduce((acc, i) => acc + i.nodes.length, 0);
          const totalRules = mapped.reduce(
            (acc, i) => acc + i.prepend_rules.length + i.append_rules.length,
            0
          );
          if (totalNodes > 0) {
            appActions.showToast(
              `从所选${targetLabel}找到 ${mapped.length} 份配置、共 ${totalNodes} 个可导入节点（只读，未改动原软件）`,
              "ok"
            );
          } else if (totalRules > 0) {
            appActions.showToast(
              `所选${targetLabel}仅包含 ${totalRules} 条分流规则、无代理节点，请查看下方说明或选择含节点的配置文件`,
              "info"
            );
          } else {
            appActions.showToast(
              `所选${targetLabel}未解析出可用代理节点，请换选其他配置文件`,
              "info"
            );
          }
        } else {
          const currentSelected = selectedPreviewIdRef.current;
          if (currentSelected && !nextList.some((it) => it.id === currentSelected)) {
            const fallback = nextList[0] ?? null;
            setSelectedPreviewId(fallback ? fallback.id : null);
            setScanSubName(fallback ? defaultMigrationSubName(fallback) : "");
          }
          appActions.showToast(
            pickMode === "directory"
              ? "所选目录中未找到可识别的明文代理配置，可尝试选择具体配置文件或切换到「粘贴配置文本」导入"
              : "所选文件中未识别到有效的代理配置，请确认是明文 YAML / JSON / 节点链接文件",
            "info"
          );
        }
      } catch (err) {
        appActions.showToast(`扫描所选${targetLabel}失败：${formatErrorMessage(err)}`, "warn");
      } finally {
        setScanningKind(null);
      }
    },
    []
  );

  const parsePasteContent = useCallback(
    async (rawText: string, preferredName = "") => {
      const trimmed = rawText.trim();
      if (!trimmed) {
        appActions.showToast("请先粘贴配置文件内容或节点链接", "warn");
        return;
      }
      try {
        let parsed: MigrationPreviewItem;
        if (isTauriEnv()) {
          const res = await catcloudApi.previewMigrationFromText(
            preferredName.trim() || "粘贴导入的节点",
            trimmed
          );
          parsed = {
            id: `mig-clip-${Date.now()}`,
            source_kind: "clipboard_text",
            client_label: res.name || "粘贴的配置文本",
            source_path: null,
            nodes: Array.isArray(res.nodes) ? res.nodes : [],
            prepend_rules: Array.isArray(res.prepend_rules) ? res.prepend_rules : [],
            append_rules: Array.isArray(res.append_rules) ? res.append_rules : [],
            warnings: Array.isArray(res.warnings) ? res.warnings : [],
          };
        } else {
          parsed = parsePastedConfigPreview(trimmed);
        }
        setPastePreview(parsed);
        setPasteSubName(
          (prev) => prev.trim() || preferredName.trim() || parsed.client_label || "粘贴导入的节点"
        );
        const parsedRuleCount = parsed.prepend_rules.length + parsed.append_rules.length;
        if (parsed.nodes.length > 0) {
          appActions.showToast(
            `解析成功：找到 ${parsed.nodes.length} 个可用节点`,
            "ok"
          );
        } else if (parsedRuleCount > 0) {
          appActions.showToast(
            `仅识别到 ${parsedRuleCount} 条分流规则、无可用节点，无法直接作为节点订阅导入`,
            "warn"
          );
        } else {
          appActions.showToast("没有识别出可用节点，请检查粘贴的内容是否完整", "warn");
        }
      } catch (err) {
        appActions.showToast(`解析失败：${formatErrorMessage(err)}`, "warn");
      }
    },
    []
  );

  useEffect(() => {
    if (!open) {
      openSessionRef.current = false;
      return;
    }
    if (!openSessionRef.current) {
      openSessionRef.current = true;
      if (initialTab === "paste") {
        setTab("paste");
        if (initialPasteText && initialPasteText.trim()) {
          const seed = initialPasteText.trim();
          setPasteText(seed);
          setPastePreview(null);
          setPasteSubName("");
          void parsePasteContent(seed);
        }
      } else {
        setTab("scan");
        void runScanClient("all", true);
      }
    }
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape" && !importing) onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [
    open,
    importing,
    onClose,
    runScanClient,
    initialTab,
    initialPasteText,
    parsePasteContent,
  ]);

  if (!open) return null;

  const activePreview =
    tab === "scan"
      ? scannedItems.find((item) => item.id === selectedPreviewId) ??
        scannedItems[0] ??
        null
      : pastePreview;
  const activeSubName = tab === "scan" ? scanSubName : pasteSubName;
  const setActiveSubName = tab === "scan" ? setScanSubName : setPasteSubName;
  const activeRuleCount = activePreview
    ? activePreview.prepend_rules.length + activePreview.append_rules.length
    : 0;
  const isRulesOnlyPreview = Boolean(
    activePreview && activePreview.nodes.length === 0 && activeRuleCount > 0
  );

  const handleParsePaste = async () => {
    if (importing) return;
    await parsePasteContent(pasteText, pasteSubName);
  };

  const handleFillDemoPasteSample = () => {
    void import("./demoFixtures").then((m) => {
      setPasteText(m.DEMO_PASTE_SAMPLE);
    });
  };

  const handleConfirmImport = async () => {
    if (importing || !activePreview || activePreview.nodes.length === 0) return;
    const finalName =
      activeSubName.trim() || defaultMigrationSubName(activePreview);
    setImporting(true);
    try {
      const ok = await onImport(activePreview, finalName, includeRules);
      if (ok) {
        onClose();
      }
    } catch {
      /* onImport 已弹出错误提示，保留抽屉与当前输入状态供直接重试 */
    } finally {
      setImporting(false);
    }
  };

  const safeClose = () => {
    if (importing) return;
    onClose();
  };

  if (typeof document === "undefined") return null;

  return createPortal(
    <div
      className="fixed inset-0 z-50 flex justify-end bg-black/45"
      role="dialog"
      aria-modal="true"
      aria-label="从电脑已有梯子导入"
      onClick={safeClose}
    >
      <div
        className="cc-surface flex h-full w-full max-w-[620px] flex-col border-l border-[var(--line-strong)] shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Drawer Header */}
        <div className="flex flex-wrap items-start justify-between gap-2 border-b border-[var(--line)] px-5 py-4">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <FolderOpen className="h-4 w-4 shrink-0 text-[var(--accent)]" />
              <h2 className="min-w-0 truncate text-sm font-semibold text-[var(--text)]">
                从电脑已有梯子导入
              </h2>
            </div>
            <p className="mt-1 text-xs text-[var(--muted)]">
              自动查找 Clash Verge / FlClash / v2rayN 等其他代理客户端的已有配置，也支持直接粘贴配置或节点链接。
            </p>
          </div>
          <button
            type="button"
            disabled={importing}
            onClick={safeClose}
            className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border border-[var(--line)] bg-[var(--card)] text-[var(--muted)] hover:text-[var(--text)] disabled:cursor-not-allowed disabled:opacity-45"
            aria-label="关闭导入窗口"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Read-Only Safety Banner */}
        <div className="mx-5 mt-3 flex items-center gap-2 rounded-xl border border-[var(--line)] bg-[var(--green-soft)] px-3 py-2 text-xs text-[var(--green)]">
          <ShieldCheck className="h-4 w-4 shrink-0" />
          <span className="min-w-0">
            只读安全复制：只会把节点复制一份进猫猫云梯，绝不改动你原来的软件和配置文件。
          </span>
        </div>

        {/* Mode Tabs */}
        <div className="mx-5 mt-3 flex flex-wrap items-center gap-2 border-b border-[var(--line)] pb-2.5">
          <button
            type="button"
            disabled={importing}
            onClick={() => setTab("scan")}
            className={`inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-lg px-3 py-1.5 text-xs font-medium transition-colors disabled:opacity-50 ${
              tab === "scan"
                ? "bg-[var(--accent)] text-[var(--accent-ink)]"
                : "border border-[var(--line)] bg-[var(--card)] text-[var(--muted)] hover:text-[var(--text)]"
            }`}
          >
            <Search className="h-3.5 w-3.5 shrink-0" />
            自动找电脑里的梯子
          </button>
          <button
            type="button"
            disabled={importing}
            onClick={() => setTab("paste")}
            className={`inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-lg px-3 py-1.5 text-xs font-medium transition-colors disabled:opacity-50 ${
              tab === "paste"
                ? "bg-[var(--accent)] text-[var(--accent-ink)]"
                : "border border-[var(--line)] bg-[var(--card)] text-[var(--muted)] hover:text-[var(--text)]"
            }`}
          >
            <FileText className="h-3.5 w-3.5 shrink-0" />
            粘贴配置文本 / 节点链接
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 space-y-4 overflow-y-auto px-5 py-4">
          {tab === "scan" ? (
            <>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-xs font-medium text-[var(--text-secondary)]">
                  常见代理客户端配置位置
                </span>
                <div className="flex flex-wrap items-center gap-1.5">
                  <button
                    type="button"
                    disabled={scanningKind !== null || importing}
                    onClick={() => void handlePickCustomPathScan("directory")}
                    title="手动挑选桌面、D 盘或任意配置文件夹进行只读扫描"
                    className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--line-strong)] bg-[var(--card)] px-2.5 py-1 text-xs font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-50"
                  >
                    <FolderOpen className="h-3.5 w-3.5" />
                    {scanningKind === "custom_dir" ? "正在扫描..." : "选择目录扫描"}
                  </button>
                  <button
                    type="button"
                    disabled={scanningKind !== null || importing}
                    onClick={() => void handlePickCustomPathScan("file")}
                    title="直接选取单个 .yaml / .yml / .json / .txt 配置文件进行只读解析"
                    className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--line-strong)] bg-[var(--card)] px-2.5 py-1 text-xs font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-50"
                  >
                    <FileCode2 className="h-3.5 w-3.5" />
                    {scanningKind === "custom_file" ? "正在解析..." : "选择配置文件"}
                  </button>
                  <button
                    type="button"
                    disabled={scanningKind !== null || importing}
                    onClick={() => void runScanClient("all", false)}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--accent)] bg-[var(--accent-soft)] px-2.5 py-1 text-xs font-medium text-[var(--accent)] hover:opacity-90 disabled:opacity-50"
                  >
                    <RefreshCw
                      className={`h-3.5 w-3.5 ${scanningKind === "all" ? "animate-spin" : ""}`}
                    />
                    {scanningKind === "all" ? "正在扫描..." : "重新扫描全部"}
                  </button>
                </div>
              </div>

              <div className="space-y-2">
                {KNOWN_CLIENT_SPECS.map((spec) => {
                  const foundList = scannedItems.filter(
                    (s) => s.source_kind === spec.kind
                  );
                  const found = foundList[0];
                  const totalNodes = foundList.reduce(
                    (acc, item) => acc + item.nodes.length,
                    0
                  );
                  const isSpecActive = foundList.some(
                    (item) => activePreview?.id === item.id
                  );
                  const isBusy =
                    scanningKind === spec.kind || scanningKind === "all";
                  return (
                    <div
                      key={spec.kind}
                      className={`rounded-xl border p-3 transition-colors ${
                        isSpecActive
                          ? "border-[var(--accent)] bg-[var(--accent-soft)]"
                          : "border-[var(--line)] bg-[var(--card)]"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="text-xs font-semibold text-[var(--text)]">
                              {spec.label}
                            </span>
                            {found && (
                              <span className="rounded-full bg-[var(--green-soft)] px-2 py-0.5 cc-mono text-[10px] font-medium text-[var(--green)]">
                                {foundList.length > 1
                                  ? `${foundList.length} 份配置 · ${totalNodes} 节点`
                                  : `${found.nodes.length} 节点 · ${
                                      found.prepend_rules.length +
                                      found.append_rules.length
                                    } 规则`}
                              </span>
                            )}
                          </div>
                          <div className="mt-0.5 truncate cc-mono text-[11px] text-[var(--muted)]">
                            {spec.readonlyPathHint}
                          </div>
                          <div className="mt-1 text-[11px] text-[var(--text-secondary)]">
                            {spec.desc}
                          </div>
                        </div>
                        <div className="flex shrink-0 items-center gap-1.5">
                          {found && (
                            <button
                              type="button"
                              disabled={importing}
                              onClick={() => {
                                setSelectedPreviewId(found.id);
                                setScanSubName(defaultMigrationSubName(found));
                              }}
                              className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 text-[11px] text-[var(--text)] hover:border-[var(--accent)] disabled:opacity-50"
                            >
                              查看
                            </button>
                          )}
                          <button
                            type="button"
                            disabled={isBusy || importing}
                            onClick={() => void runScanClient(spec.kind, false)}
                            className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1 text-[11px] text-[var(--text)] hover:border-[var(--accent)] disabled:opacity-50"
                          >
                            <Search className="h-3 w-3" />
                            {isBusy ? "扫描中" : "扫描"}
                          </button>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>

              {scannedItems.length > 0 && (
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-[11px] text-[var(--muted)]">
                    <span>已扫描到的配置（点击切换预览，悬停路径看完整位置）</span>
                    <span className="cc-mono">{scannedItems.length} 份</span>
                  </div>
                  <div className="max-h-40 space-y-1.5 overflow-y-auto pr-1">
                    {scannedItems.map((item) => {
                      const selected = activePreview?.id === item.id;
                      const showSourceBadge =
                        Boolean(item.source_client_label) &&
                        item.source_client_label !== item.client_label;
                      const itemRuleCount =
                        item.prepend_rules.length + item.append_rules.length;
                      const itemBasename =
                        extractPathBasename(item.source_path) ?? item.source_path;
                      return (
                        <button
                          key={item.id}
                          type="button"
                          disabled={importing}
                          onClick={() => {
                            setSelectedPreviewId(item.id);
                            setScanSubName(defaultMigrationSubName(item));
                          }}
                          className={`flex w-full items-center justify-between gap-2 rounded-xl border px-3 py-2 text-left transition-colors disabled:opacity-60 ${
                            selected
                              ? "border-[var(--accent)] bg-[var(--accent-soft)]"
                              : "border-[var(--line)] bg-[var(--card)] hover:border-[var(--line-strong)]"
                          }`}
                        >
                          <div className="min-w-0">
                            <div className="flex flex-wrap items-center gap-1.5">
                              <span className="truncate text-xs font-semibold text-[var(--text)]">
                                {item.client_label}
                              </span>
                              {showSourceBadge && (
                                <span className="shrink-0 rounded bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]">
                                  {item.source_client_label}
                                </span>
                              )}
                            </div>
                            {item.source_path && (
                              <div
                                title={item.source_path}
                                className="mt-0.5 truncate cc-mono text-[10px] text-[var(--muted)]"
                              >
                                {itemBasename}
                              </div>
                            )}
                          </div>
                          {item.nodes.length > 0 ? (
                            <span className="shrink-0 rounded-full bg-[var(--green-soft)] px-2 py-0.5 cc-mono text-[10px] font-medium text-[var(--green)]">
                              {item.nodes.length} 节点
                            </span>
                          ) : itemRuleCount > 0 ? (
                            <span
                              title="该条目仅含分流规则，没有可导入的代理节点"
                              className="shrink-0 rounded-full bg-[var(--amber-soft)] px-2 py-0.5 cc-mono text-[10px] font-medium text-[var(--amber)]"
                            >
                              仅规则 · {itemRuleCount} 条
                            </span>
                          ) : (
                            <span className="shrink-0 rounded-full bg-[var(--bg-elevated)] px-2 py-0.5 cc-mono text-[10px] font-medium text-[var(--muted)]">
                              0 节点
                            </span>
                          )}
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="space-y-2.5">
              <div className="flex items-center justify-between">
                <label
                  htmlFor="cc-migration-paste"
                  className="text-xs font-medium text-[var(--text-secondary)]"
                >
                  支持粘贴其他代理客户端的配置文件内容、编码文本或单条/多条节点分享链接
                </label>
                <button
                  type="button"
                  disabled={importing}
                  onClick={handleFillDemoPasteSample}
                  className="shrink-0 rounded-lg border border-[var(--line)] bg-[var(--card)] px-2 py-1 text-[11px] text-[var(--accent)] hover:border-[var(--accent)] disabled:opacity-50"
                >
                  填入示例内容
                </button>
              </div>
              <textarea
                id="cc-migration-paste"
                value={pasteText}
                disabled={importing}
                onChange={(e) => setPasteText(e.target.value)}
                rows={8}
                placeholder="在这里粘贴配置内容，或者粘贴 vless:// / trojan:// / ss:// 等节点链接..."
                className="cc-selectable w-full rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-3 cc-mono text-xs text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none disabled:opacity-60"
              />
              <div className="flex items-center justify-end gap-2">
                <button
                  type="button"
                  disabled={importing}
                  onClick={() => {
                    setPasteText("");
                    setPastePreview(null);
                    setPasteSubName("");
                  }}
                  className="rounded-lg border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 text-xs text-[var(--muted)] hover:text-[var(--text)] disabled:opacity-50"
                >
                  清空
                </button>
                <button
                  type="button"
                  disabled={importing}
                  onClick={() => void handleParsePaste()}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent-ink)] hover:opacity-90 disabled:opacity-50"
                >
                  <Upload className="h-3.5 w-3.5" />
                  解析并预览节点
                </button>
              </div>
            </div>
          )}

          {/* Active Preview Panel */}
          {activePreview && (
            <div className="space-y-3 rounded-xl border border-[var(--line-strong)] bg-[var(--card)] p-3.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="min-w-0">
                  <div className="text-xs font-semibold text-[var(--text)]">
                    预览结果 · {activePreview.client_label}
                  </div>
                  {activePreview.source_path && (
                    <div
                      title={activePreview.source_path}
                      className="mt-0.5 truncate cc-mono text-[10px] text-[var(--muted)]"
                    >
                      {extractPathBasename(activePreview.source_path) ??
                        activePreview.source_path}
                    </div>
                  )}
                </div>
                <span className="rounded-full bg-[var(--accent-soft)] px-2 py-0.5 cc-mono text-[11px] font-medium text-[var(--accent)]">
                  {activePreview.nodes.length} 个节点
                </span>
              </div>

              {isRulesOnlyPreview && (
                <div className="flex items-start gap-2 rounded-lg border border-[var(--amber)]/40 bg-[var(--amber-soft)] px-3 py-2 text-[11px] leading-relaxed text-[var(--amber)]">
                  <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  <div>
                    <div className="font-semibold">
                      该配置仅包含 {activeRuleCount} 条分流规则，未包含可导入的代理节点
                    </div>
                    <div className="mt-0.5 opacity-90">
                      此处迁移需至少包含 1 个可用代理节点，因此「确认导入」暂不可用。这通常是纯规则覆写或模板文件，请选择包含节点列表的配置文件，或前往「分流与连接」页面配置分流规则。
                    </div>
                  </div>
                </div>
              )}

              {activePreview.nodes.length === 0 && !isRulesOnlyPreview && (
                <div className="flex items-start gap-2 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2 text-[11px] leading-relaxed text-[var(--text-secondary)]">
                  <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--amber)]" />
                  <span>
                    当前条目未解析到任何代理节点，因此无法执行导入。请改选包含有效节点的配置文件，或检查粘贴内容是否完整。
                  </span>
                </div>
              )}

              {activePreview.warnings.length > 0 && (
                <div className="space-y-1 rounded-lg bg-[var(--amber-soft)] px-2.5 py-2 text-[11px] text-[var(--amber)]">
                  {activePreview.warnings.map((w, idx) => (
                    <div key={idx} className="flex items-start gap-1.5">
                      <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                      <span>{w}</span>
                    </div>
                  ))}
                </div>
              )}

              {activePreview.nodes.length > 0 && (
                <div className="max-h-44 space-y-1.5 overflow-y-auto pr-1">
                  {activePreview.nodes.map((node) => (
                    <div
                      key={node.id}
                      className="flex items-center justify-between gap-2 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs"
                    >
                      <div className="min-w-0">
                        <div className="truncate font-medium text-[var(--text)]">
                          {node.name}
                        </div>
                        <div className="cc-mono text-[10px] text-[var(--muted)]">
                          {node.protocol.toUpperCase()} · {node.server}:{node.port}
                        </div>
                      </div>
                      <div className="flex shrink-0 items-center gap-1.5 cc-mono text-[10px]">
                        <span
                          title={getRegionLabel(resolveNodeRegionCode(node))}
                          className="rounded bg-[var(--card)] px-1.5 py-0.5 text-[var(--text-secondary)]"
                        >
                          {resolveNodeRegionCode(node)}
                        </span>
                        <span className="rounded bg-[var(--accent-soft)] px-1.5 py-0.5 text-[var(--accent)]">
                          {node.multiplier}x
                        </span>
                        {node.is_443_native && (
                          <span className="rounded bg-[var(--green-soft)] px-1.5 py-0.5 text-[var(--green)]">
                            直连 443
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {(activePreview.prepend_rules.length > 0 ||
                activePreview.append_rules.length > 0) && (
                <div className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] p-2.5 text-[11px]">
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-[var(--text)]">
                      检测到分流规则（优先 {activePreview.prepend_rules.length} 条 / 兜底{" "}
                      {activePreview.append_rules.length} 条）
                    </span>
                    <label className="inline-flex cursor-pointer items-center gap-1.5 text-[var(--text-secondary)]">
                      <input
                        type="checkbox"
                        disabled={importing}
                        checked={includeRules}
                        onChange={(e) => setIncludeRules(e.target.checked)}
                        className="accent-[var(--accent)]"
                      />
                      同步导入规则
                    </label>
                  </div>
                  <div className="mt-1.5 space-y-0.5 cc-mono text-[10px] text-[var(--muted)]">
                    {[...activePreview.prepend_rules, ...activePreview.append_rules]
                      .slice(0, 4)
                      .map((r, idx) => (
                        <div key={idx} className="truncate">
                          {r}
                        </div>
                      ))}
                  </div>
                </div>
              )}

              <div className="grid grid-cols-1 gap-2 pt-1">
                <label className="text-[11px] text-[var(--muted)]">
                  导入后的订阅名称
                  <input
                    type="text"
                    disabled={importing}
                    value={activeSubName}
                    onChange={(e) => setActiveSubName(e.target.value)}
                    placeholder={defaultMigrationSubName(activePreview)}
                    className="mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs text-[var(--text)] focus:border-[var(--accent)] focus:outline-none disabled:opacity-60"
                  />
                </label>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between gap-2 border-t border-[var(--line)] px-5 py-3">
          <span className="text-[11px] text-[var(--muted)]">
            {importing
              ? "正在导入节点与规则，请稍候..."
              : isRulesOnlyPreview
                ? `当前条目仅含 ${activeRuleCount} 条规则、无代理节点，暂不可导入`
                : activePreview && activePreview.nodes.length === 0
                  ? "当前条目未包含可用代理节点，暂不可导入"
                  : "只复制到猫猫云梯本地，不会修改原软件"}
          </span>
          <div className="flex shrink-0 items-center gap-2">
            <button
              type="button"
              disabled={importing}
              onClick={safeClose}
              className="rounded-lg border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 text-xs text-[var(--muted)] hover:text-[var(--text)] disabled:cursor-not-allowed disabled:opacity-45"
            >
              取消
            </button>
            <button
              type="button"
              disabled={importing || !activePreview || activePreview.nodes.length === 0}
              title={
                isRulesOnlyPreview
                  ? "当前配置仅含分流规则、无代理节点，无法导入"
                  : !activePreview || activePreview.nodes.length === 0
                    ? "请先选择包含至少 1 个可用节点的配置"
                    : undefined
              }
              onClick={() => void handleConfirmImport()}
              className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent-ink)] hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-45"
            >
              {importing ? (
                <RefreshCw className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Check className="h-3.5 w-3.5" />
              )}
              {importing ? "正在导入..." : "确认导入"}
            </button>
          </div>
        </div>
      </div>
    </div>,
    document.body
  );
}

export default MigrationDrawer;
