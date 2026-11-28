import {
  AlertTriangle,
  ArrowLeft,
  Check,
  CheckCircle2,
  Clock,
  Cpu,
  GitMerge,
  Link2,
  Play,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
  ShieldCheck,
  Sparkles,
  Square,
  X,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
  type DesktopAppCandidate,
  type ProxyNode,
  type SubscriptionUpdateMode,
  catcloudApi,
  formatErrorMessage,
} from "../../api/tauri";
import { AppSelect } from "../../components/AppSelect";
import { normalizeUiLanguage, useUiDict } from "../../i18n";
import { appActions, appStore, useAppSelector } from "../../store/appStore";
import { getRegionLabel, resolveNodeRegionCode } from "../../utils/regions";
import {
  type CaptureConfirmPayload,
  UNSUPPORTED_CAPTURE_NOTICE,
  formatCaptureEventTime,
  hasPausedCaptureSession,
  isSelfCatCloudCandidate,
} from "./utils";

export interface ProcessAttachDrawerProps {
  open: boolean;
  onClose: () => void;
  onConfirmCapture: (payload: CaptureConfirmPayload) => Promise<boolean>;
  onGoToSubUrl: () => void;
}

export function ProcessAttachDrawer({
  open,
  onClose,
  onConfirmCapture,
  onGoToSubUrl,
}: ProcessAttachDrawerProps) {
  const bgCapture = useAppSelector((s) => s.bgTasks.capture);
  const subscriptions = useAppSelector((s) => s.subscriptions);
  const allStoreNodes = useAppSelector((s) => s.nodes);
  const uiLang = useAppSelector((s) => s.config.personalization.ui_language);
  const dict = useUiDict(normalizeUiLanguage(uiLang));
  const captureStatus = bgCapture.status;
  const finishingCapture = bgCapture.finishing;
  const outcome = bgCapture.outcome;
  const isCapturePaused = hasPausedCaptureSession(bgCapture);

  const [step, setStep] = useState<1 | 2 | 3>(() =>
    bgCapture.outcome
      ? 3
      : (bgCapture.active && bgCapture.sessionId) ||
          hasPausedCaptureSession(bgCapture) ||
          bgCapture.finishing
        ? 2
        : 1
  );
  const [keyword, setKeyword] = useState("");
  const [loadingApps, setLoadingApps] = useState(false);
  const [candidates, setCandidates] = useState<DesktopAppCandidate[]>([]);
  const [selectedPid, setSelectedPid] = useState<number | null>(null);
  const [startingCapture, setStartingCapture] = useState(false);
  const [importName, setImportName] = useState(() => {
    if (!bgCapture.outcome) return "";
    const label =
      bgCapture.outcome.target_name?.trim() || bgCapture.targetName || "桌面软件";
    return `抓取 · ${label}`;
  });
  const [nodeFilter, setNodeFilter] = useState("");
  const [selectedOutcomeIndices, setSelectedOutcomeIndices] = useState<Set<number>>(
    () => new Set()
  );
  const [captureTargetMode, setCaptureTargetMode] = useState<"new" | "existing">("new");
  const [captureTargetSubId, setCaptureTargetSubId] = useState<string>(
    () => subscriptions[0]?.id ?? ""
  );
  const [importingOutcome, setImportingOutcome] = useState(false);

  const subNodeCountMap = useMemo(() => {
    const map = new Map<string, number>();
    for (const n of allStoreNodes) {
      map.set(n.sub_id, (map.get(n.sub_id) ?? 0) + 1);
    }
    return map;
  }, [allStoreNodes]);

  // Reset selected node checkboxes whenever a new capture outcome arrives
  useEffect(() => {
    if (!outcome || !outcome.supported) {
      setSelectedOutcomeIndices(new Set());
      return;
    }
    setSelectedOutcomeIndices(new Set(outcome.nodes.map((_, idx) => idx)));
    setCaptureTargetMode("new");
    if (subscriptions.length > 0 && !subscriptions.some((s) => s.id === captureTargetSubId)) {
      setCaptureTargetSubId(subscriptions[0].id);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [outcome]);

  useEffect(() => {
    if (subscriptions.length === 0) {
      if (captureTargetMode === "existing") setCaptureTargetMode("new");
      if (captureTargetSubId !== "") setCaptureTargetSubId("");
    } else if (!subscriptions.some((s) => s.id === captureTargetSubId)) {
      setCaptureTargetSubId(subscriptions[0].id);
    }
  }, [subscriptions, captureTargetMode, captureTargetSubId]);

  const mountedRef = useRef(true);
  const openRef = useRef(open);
  openRef.current = open;
  const baselinePidsRef = useRef<number[] | null>(null);
  const userPickedManuallyRef = useRef(false);
  const fetchCandidatesInFlightRef = useRef(false);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      // Never cancel active background capture session on unmount; polling lives globally in appStore
    };
  }, []);

  const sortCandidates = useCallback((list: DesktopAppCandidate[]): DesktopAppCandidate[] => {
    return list
      .filter((c) => !isSelfCatCloudCandidate(c))
      .sort((a, b) => {
        if (a.is_newly_opened !== b.is_newly_opened) {
          return a.is_newly_opened ? -1 : 1;
        }
        if (a.likely_proxy_client !== b.likely_proxy_client) {
          return a.likely_proxy_client ? -1 : 1;
        }
        return (a.friendly_name || a.process_name).localeCompare(
          b.friendly_name || b.process_name
        );
      });
  }, []);

  const fetchCandidates = useCallback(
    async (isInitialBaseline: boolean, showLoadingSpinner: boolean) => {
      if (fetchCandidatesInFlightRef.current) return;
      fetchCandidatesInFlightRef.current = true;
      if (showLoadingSpinner) {
        setLoadingApps(true);
      }
      try {
        const baselineArg = isInitialBaseline
          ? undefined
          : (baselinePidsRef.current ?? undefined);
        const rawList = await catcloudApi.listDesktopAppCandidates(baselineArg);
        if (!mountedRef.current || !openRef.current) return;

        const cleaned = sortCandidates(rawList);
        if (isInitialBaseline) {
          baselinePidsRef.current = cleaned.map((c) => c.pid);
        }
        setCandidates(cleaned);

        setSelectedPid((prev) => {
          if (prev !== null && cleaned.some((c) => c.pid === prev)) {
            if (!userPickedManuallyRef.current) {
              const newlyOpened = cleaned.find((c) => c.is_newly_opened);
              if (newlyOpened) return newlyOpened.pid;
            }
            return prev;
          }
          const preferred =
            cleaned.find((c) => c.is_newly_opened) ??
            cleaned.find((c) => c.likely_proxy_client) ??
            cleaned[0] ??
            null;
          return preferred ? preferred.pid : null;
        });
      } catch (err) {
        if (showLoadingSpinner && mountedRef.current) {
          appActions.showToast(
            `获取桌面软件列表失败：${formatErrorMessage(err)}`,
            "warn"
          );
        }
      } finally {
        fetchCandidatesInFlightRef.current = false;
        if (showLoadingSpinner && mountedRef.current) {
          setLoadingApps(false);
        }
      }
    },
    [sortCandidates]
  );

  // When opening the drawer, seamlessly resume Step 3 (ready outcome) or Step 2 (active/paused/finishing session)
  useEffect(() => {
    if (!open) return;
    const latestCapture = appStore.getState().bgTasks.capture;
    if (latestCapture.outcome) {
      setStep(3);
      setStartingCapture(false);
      const label =
        latestCapture.outcome.target_name?.trim() ||
        latestCapture.targetName ||
        "桌面软件";
      setImportName((prev) => prev.trim() || `抓取 · ${label}`);
      setNodeFilter("");
      setImportingOutcome(false);
      return;
    }
    if (
      (latestCapture.active && latestCapture.sessionId) ||
      hasPausedCaptureSession(latestCapture) ||
      latestCapture.finishing
    ) {
      setStep(2);
      setStartingCapture(false);
      return;
    }
    setStep(1);
    setKeyword("");
    setCandidates([]);
    setSelectedPid(null);
    setStartingCapture(false);
    setImportName("");
    setNodeFilter("");
    setImportingOutcome(false);
    baselinePidsRef.current = null;
    userPickedManuallyRef.current = false;
    void fetchCandidates(true, true);
  }, [open, fetchCandidates]);

  // Automatically advance to Step 3 whenever a background finish produces an outcome while drawer is open
  useEffect(() => {
    if (!open || !bgCapture.outcome) return;
    setStep(3);
    const label =
      bgCapture.outcome.target_name?.trim() || bgCapture.targetName || "桌面软件";
    setImportName((prev) => prev.trim() || `抓取 · ${label}`);
  }, [open, bgCapture.outcome, bgCapture.targetName]);

  // Step 1: Silently detect newly launched desktop apps every 1.5s while visible (shares fetchCandidatesInFlightRef)
  useEffect(() => {
    if (!open || step !== 1) return;
    const pollIfVisible = () => {
      if (typeof document !== "undefined" && document.visibilityState !== "visible") {
        return;
      }
      if (!openRef.current || fetchCandidatesInFlightRef.current) return;
      void fetchCandidates(false, false);
    };
    const timer = window.setInterval(pollIfVisible, 1500);
    const handleVisibilityChange = () => {
      if (document.visibilityState === "visible") {
        pollIfVisible();
      }
    };
    if (typeof document !== "undefined") {
      document.addEventListener("visibilitychange", handleVisibilityChange);
    }
    return () => {
      window.clearInterval(timer);
      if (typeof document !== "undefined") {
        document.removeEventListener("visibilitychange", handleVisibilityChange);
      }
    };
  }, [open, step, fetchCandidates]);

  const safeClose = useCallback(() => {
    if (finishingCapture || importingOutcome) return;
    const latestCapture = appStore.getState().bgTasks.capture;
    if (latestCapture.outcome && !latestCapture.outcome.supported) {
      appActions.clearLiveCaptureOutcome();
    } else if (step === 3 && latestCapture.outcome?.supported) {
      appActions.showToast(
        "已暂存捕捉到的节点，随时可点击卡片继续确认导入",
        "info",
        3600
      );
    } else if (latestCapture.active) {
      appActions.showToast(
        "实时捕捉继续在后台运行，随时可点击向导按钮回来查看进度",
        "info",
        3600
      );
    } else if (hasPausedCaptureSession(latestCapture)) {
      appActions.showToast(
        "已为你保留捕捉快照，随时可点击导入页的捕捉卡片回来整理查看",
        "info",
        3600
      );
    }
    onClose();
  }, [finishingCapture, importingOutcome, onClose, step]);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") safeClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, safeClose]);

  const filteredCandidates = useMemo(() => {
    const kw = keyword.trim().toLowerCase();
    if (!kw) return candidates;
    return candidates.filter((cand) => {
      return (
        cand.friendly_name.toLowerCase().includes(kw) ||
        cand.window_title.toLowerCase().includes(kw) ||
        cand.process_name.toLowerCase().includes(kw) ||
        String(cand.pid).includes(kw)
      );
    });
  }, [candidates, keyword]);

  const selectedCandidate = useMemo(
    () =>
      candidates.find((c) => c.pid === selectedPid) ??
      filteredCandidates[0] ??
      null,
    [candidates, filteredCandidates, selectedPid]
  );

  const newlyOpenedCount = useMemo(
    () => candidates.filter((c) => c.is_newly_opened).length,
    [candidates]
  );

  const outcomeRegionStats = useMemo(() => {
    if (!outcome || outcome.nodes.length === 0) return [] as Array<{ code: string; label: string; count: number }>;
    const counts = new Map<string, number>();
    for (const node of outcome.nodes) {
      const code = resolveNodeRegionCode(node);
      counts.set(code, (counts.get(code) ?? 0) + 1);
    }
    return Array.from(counts.entries())
      .map(([code, count]) => ({ code, label: getRegionLabel(code), count }))
      .sort((a, b) => b.count - a.count);
  }, [outcome]);

  const filteredOutcomeEntries = useMemo(() => {
    if (!outcome) return [] as Array<{ node: ProxyNode; index: number }>;
    const all = outcome.nodes.map((node, index) => ({ node, index }));
    const kw = nodeFilter.trim().toLowerCase();
    if (!kw) return all;
    return all.filter(({ node: n }) => {
      const regionCode = resolveNodeRegionCode(n);
      return (
        n.name.toLowerCase().includes(kw) ||
        n.server.toLowerCase().includes(kw) ||
        n.protocol.toLowerCase().includes(kw) ||
        regionCode.toLowerCase().includes(kw) ||
        getRegionLabel(regionCode).toLowerCase().includes(kw)
      );
    });
  }, [outcome, nodeFilter]);

  const selectedOutcomeNodes = useMemo(() => {
    if (!outcome) return [] as ProxyNode[];
    return outcome.nodes.filter((_, idx) => selectedOutcomeIndices.has(idx));
  }, [outcome, selectedOutcomeIndices]);

  const allFilteredOutcomeSelected = useMemo(
    () =>
      filteredOutcomeEntries.length > 0 &&
      filteredOutcomeEntries.every((entry) => selectedOutcomeIndices.has(entry.index)),
    [filteredOutcomeEntries, selectedOutcomeIndices]
  );

  const toggleOutcomeNodeIndex = (idx: number) => {
    setSelectedOutcomeIndices((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  };

  const handleToggleAllFilteredOutcome = () => {
    if (filteredOutcomeEntries.length === 0) return;
    setSelectedOutcomeIndices((prev) => {
      const next = new Set(prev);
      if (allFilteredOutcomeSelected) {
        for (const entry of filteredOutcomeEntries) next.delete(entry.index);
      } else {
        for (const entry of filteredOutcomeEntries) next.add(entry.index);
      }
      return next;
    });
  };

  const handleStartLiveCapture = async () => {
    if (!selectedCandidate || startingCapture) return;
    setStartingCapture(true);
    try {
      const started = await appActions.startLiveCaptureBg(selectedCandidate.pid);
      if (!started || !mountedRef.current) return;
      setImportName("");
      setNodeFilter("");
      setStep(2);
    } finally {
      if (mountedRef.current) {
        setStartingCapture(false);
      }
    }
  };

  const handleCancelCaptureToStep1 = async () => {
    await appActions.cancelLiveCaptureBg();
    if (!mountedRef.current) return;
    setImportName("");
    setNodeFilter("");
    setStep(1);
    void fetchCandidates(false, false);
  };

  const handleFinishCapture = async () => {
    if (finishingCapture) return;
    const latestCapture = appStore.getState().bgTasks.capture;
    const fallbackTargetName =
      latestCapture.status?.target_name || latestCapture.targetName || "已捕捉软件";
    if (!latestCapture.sessionId && !latestCapture.status?.session_id) {
      setStep(latestCapture.outcome ? 3 : 1);
      return;
    }
    const res = await appActions.finishLiveCaptureBg();
    if (!mountedRef.current) return;
    if (!res) {
      setStep(1);
      return;
    }
    const label = res.target_name?.trim() || fallbackTargetName;
    setImportName(`抓取 · ${label}`);
    setNodeFilter("");
    setStep(3);
  };

  const handleConfirmImportOutcome = async (
    targetModeOverride?: "new" | "existing",
    updateModeOverride?: SubscriptionUpdateMode
  ) => {
    if (!outcome || !outcome.supported || outcome.nodes.length === 0 || importingOutcome) {
      return;
    }
    if (selectedOutcomeNodes.length === 0) {
      appActions.showToast("请至少勾选 1 个要导入的节点", "warn");
      return;
    }
    const resolvedMode = targetModeOverride ?? captureTargetMode;
    if (resolvedMode === "existing" && !captureTargetSubId) {
      appActions.showToast("请先选择一个要更新的已有分组", "warn");
      return;
    }
    const finalName =
      importName.trim() || `抓取 · ${outcome.target_name || "桌面软件"}`;
    setImportingOutcome(true);
    try {
      const ok = await onConfirmCapture({
        name: finalName,
        outcome,
        selectedNodes: selectedOutcomeNodes,
        targetMode: resolvedMode,
        targetSubId: resolvedMode === "existing" ? captureTargetSubId : undefined,
        updateMode: resolvedMode === "existing" ? (updateModeOverride ?? "merge_dedup") : undefined,
      });
      if (ok) {
        appActions.clearLiveCaptureOutcome();
        if (mountedRef.current) {
          setImportName("");
          setNodeFilter("");
          setSelectedOutcomeIndices(new Set());
          setCaptureTargetMode("new");
          onClose();
        }
      }
    } finally {
      if (mountedRef.current) {
        setImportingOutcome(false);
      }
    }
  };

  const handleCancelExistingUpdate = () => {
    setCaptureTargetMode("new");
    appActions.showToast("已取消更新，原有分组与节点保持不变", "info");
  };

  const handleResetToStep1 = async () => {
    await appActions.cancelLiveCaptureBg();
    if (!mountedRef.current) return;
    setImportName("");
    setNodeFilter("");
    setStep(1);
    void fetchCandidates(false, true);
  };

  const handleSwitchToSubUrl = () => {
    void appActions.cancelLiveCaptureBg();
    onClose();
    onGoToSubUrl();
  };

  if (!open || typeof document === "undefined") return null;

  const wizardSteps: ReadonlyArray<{ id: 1 | 2 | 3; badge: string; title: string }> = [
    { id: 1, badge: "1", title: "选择或打开专用软件" },
    { id: 2, badge: "2", title: "更新订阅实时捕捉" },
    { id: 3, badge: "3", title: "结束并整理结果" },
  ];

  const isOutcomeSupported = Boolean(
    outcome && outcome.supported && outcome.nodes.length > 0
  );

  return createPortal(
    <div
      className="fixed inset-0 z-50 flex justify-end bg-black/45"
      role="dialog"
      aria-modal="true"
      aria-label="从正在运行的软件实时抓节点"
      onClick={safeClose}
    >
      <div
        className="cc-surface flex h-full w-full max-w-[680px] flex-col border-l border-[var(--line-strong)] shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex flex-wrap items-start justify-between gap-2 border-b border-[var(--line)] px-5 py-4">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <Cpu className="h-4 w-4 shrink-0 text-[var(--accent)]" />
              <h2 className="min-w-0 truncate text-sm font-semibold text-[var(--text)]">
                实时捕捉向导 · 从正在运行的软件抓节点
              </h2>
            </div>
            <p className="mt-1 text-xs text-[var(--muted)]">
              按三步操作即可自动监控并安全提取可用节点（全程只读，不会改动原软件）。
            </p>
          </div>
          <button
            type="button"
            disabled={finishingCapture || importingOutcome}
            onClick={safeClose}
            title={
              step === 2 && bgCapture.active
                ? "收起窗口（实时捕捉将继续在后台进行）"
                : step === 2 && isCapturePaused
                  ? "收起窗口（已保留本次捕捉快照，可随时回来查看）"
                  : "关闭软件实时捕捉向导"
            }
            className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border border-[var(--line)] bg-[var(--card)] text-[var(--muted)] hover:text-[var(--text)] disabled:cursor-not-allowed disabled:opacity-45"
            aria-label="关闭软件实时捕捉向导"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Top 1 -> 2 -> 3 Progress Stepper */}
        <div className="border-b border-[var(--line)] bg-[var(--bg-elevated)]/60 px-5 py-3">
          <ol className="grid grid-cols-3 gap-2">
            {wizardSteps.map((item) => {
              const completed = step > item.id;
              const active = step === item.id;
              return (
                <li
                  key={item.id}
                  className={`flex items-center gap-2 rounded-xl border px-2.5 py-2 text-xs transition-colors ${
                    completed
                      ? "border-[var(--green)]/45 bg-[var(--green-soft)] text-[var(--green)]"
                      : active
                        ? "border-[var(--accent)] bg-[var(--accent-soft)] font-semibold text-[var(--accent)]"
                        : "border-[var(--line)] bg-[var(--card)]/70 text-[var(--muted)]"
                  }`}
                >
                  <span
                    className={`inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full cc-mono text-[11px] font-bold ${
                      completed
                        ? "bg-[var(--green)] text-[var(--accent-ink)]"
                        : active
                          ? "bg-[var(--accent)] text-[var(--accent-ink)]"
                          : "bg-[var(--bg-elevated)] text-[var(--muted)]"
                    }`}
                  >
                    {completed ? <Check className="h-3 w-3 stroke-[2.5]" /> : item.badge}
                  </span>
                  <span className="truncate">{item.title}</span>
                </li>
              );
            })}
          </ol>
        </div>

        {/* Body */}
        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
          {step === 1 && (
            <div className="space-y-3.5">
              {/* Auto-detect Tip Banner + Tray Hint */}
              <div className="space-y-2 rounded-xl border border-[var(--line)] bg-[var(--accent-soft)]/55 px-3.5 py-2.5 text-xs text-[var(--text-secondary)]">
                <div className="flex items-start gap-2.5">
                  <Sparkles className="mt-0.5 h-4 w-4 shrink-0 text-[var(--accent)]" />
                  <div className="min-w-0 leading-relaxed">
                    直接点选下方已打开的软件；如果还没启动，现在去打开它，猫猫每{" "}
                    <span className="cc-mono font-semibold text-[var(--text)]">1.5 秒</span>{" "}
                    自动发现新启动的软件并置顶标为
                    <span className="mx-1 rounded-full bg-[var(--green-soft)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--green)]">
                      刚打开
                    </span>
                    。
                  </div>
                </div>
                <div className="border-t border-[var(--line)]/60 pt-1.5 text-[11px] leading-relaxed text-[var(--text-secondary)]">
                  没看到软件？若它缩在右下角系统托盘，请直接勾选带「
                  <span className="font-medium text-[var(--text)]">托盘运行中</span>
                  」标记的项，或点开一次它的窗口就会自动置顶。
                </div>
              </div>

              {/* Search & Manual Refresh */}
              <div className="flex flex-wrap items-center gap-2">
                <div className="relative min-w-[200px] flex-1">
                  <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--muted)]" />
                  <input
                    type="text"
                    value={keyword}
                    onChange={(e) => setKeyword(e.target.value)}
                    placeholder="按窗口标题、软件名或进程号搜索..."
                    className="w-full rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] py-1.5 pl-8 pr-3 text-xs text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none"
                  />
                </div>
                <button
                  type="button"
                  disabled={loadingApps}
                  onClick={() => void fetchCandidates(false, true)}
                  className="inline-flex shrink-0 items-center gap-1.5 rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 text-xs font-medium text-[var(--text)] hover:border-[var(--accent)] disabled:opacity-50"
                >
                  <RefreshCw
                    className={`h-3.5 w-3.5 ${loadingApps ? "animate-spin" : ""}`}
                  />
                  重新扫描
                </button>
              </div>

              {/* List Header */}
              <div className="flex items-center justify-between text-[11px] text-[var(--muted)]">
                <span>当前桌面可见软件（{filteredCandidates.length}）</span>
                {newlyOpenedCount > 0 ? (
                  <span className="inline-flex items-center gap-1 font-medium text-[var(--green)]">
                    <span className="h-1.5 w-1.5 rounded-full bg-[var(--green)]" />
                    新发现 {newlyOpenedCount} 个刚打开软件
                  </span>
                ) : (
                  <span>静默监测新打开软件中…</span>
                )}
              </div>

              {/* Desktop App Candidates List */}
              {loadingApps && candidates.length === 0 ? (
                <div className="flex items-center justify-center gap-2 rounded-xl border border-dashed border-[var(--line)] py-12 text-xs text-[var(--muted)]">
                  <RefreshCw className="h-4 w-4 animate-spin text-[var(--accent)]" />
                  <span>正在扫描电脑上已打开的桌面软件…</span>
                </div>
              ) : filteredCandidates.length === 0 ? (
                <div className="rounded-xl border border-dashed border-[var(--line)] px-4 py-10 text-center text-xs text-[var(--muted)]">
                  没有匹配到已打开的桌面软件，请先启动你的专用软件或清空搜索词。
                </div>
              ) : (
                <div className="space-y-2">
                  {filteredCandidates.map((cand) => {
                    const active = selectedCandidate?.pid === cand.pid;
                    const isTrayCandidate =
                      /托盘|后台运行/.test(cand.friendly_name) ||
                      /托盘|后台运行/.test(cand.window_title);
                    const cleanedFriendlyName = cand.friendly_name
                      .trim()
                      .replace(
                        /\s*[（(]\s*(?:托盘\/后台运行中|托盘运行中|后台运行中)\s*[)）]\s*$/u,
                        ""
                      )
                      .trim();
                    const cleanedWindowTitle = cand.window_title
                      .trim()
                      .replace(
                        /\s*[（(]\s*(?:托盘\/后台运行中|托盘运行中|后台运行中)\s*[)）]\s*$/u,
                        ""
                      )
                      .trim();
                    const primaryTitle =
                      cleanedFriendlyName ||
                      cleanedWindowTitle ||
                      cand.process_name;
                    const showWindowSubtitle =
                      Boolean(cleanedWindowTitle) &&
                      cleanedWindowTitle !== primaryTitle;

                    return (
                      <button
                        key={cand.pid}
                        type="button"
                        onClick={() => {
                          userPickedManuallyRef.current = true;
                          setSelectedPid(cand.pid);
                        }}
                        className={`flex w-full cursor-pointer items-start justify-between gap-3 rounded-xl border p-3 text-left transition-colors ${
                          active
                            ? "border-[var(--accent)] bg-[var(--accent-soft)] ring-1 ring-[var(--accent)]/30"
                            : cand.is_newly_opened
                              ? "border-[var(--green)]/50 bg-[var(--green-soft)]/35 hover:border-[var(--green)]"
                              : "border-[var(--line)] bg-[var(--card)] hover:border-[var(--line-strong)]"
                        }`}
                      >
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-1.5">
                            <span className="truncate text-xs font-semibold text-[var(--text)]">
                              {primaryTitle}
                            </span>
                            {cand.is_newly_opened && (
                              <span className="shrink-0 rounded-full bg-[var(--green)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--accent-ink)]">
                                刚打开
                              </span>
                            )}
                            {isTrayCandidate && (
                              <span className="shrink-0 rounded-full bg-[var(--amber-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--amber)]">
                                托盘运行中
                              </span>
                            )}
                            {cand.likely_proxy_client && (
                              <span className="shrink-0 rounded-full bg-[var(--sky-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--sky)]">
                                常见代理工具
                              </span>
                            )}
                          </div>
                          {showWindowSubtitle && (
                            <div
                              className="mt-0.5 truncate text-[11px] text-[var(--text-secondary)]"
                              title={cand.window_title}
                            >
                              {cand.window_title}
                            </div>
                          )}
                          <div className="mt-1 flex flex-wrap items-center gap-2 cc-mono text-[10.5px] text-[var(--muted)]">
                            <span>{cand.process_name}</span>
                            <span>#{cand.pid}</span>
                            {cand.related_pids.length > 1 && (
                              <span className="rounded bg-[var(--bg-elevated)] px-1.5 py-0.2">
                                关联 {cand.related_pids.length} 个进程
                              </span>
                            )}
                          </div>
                        </div>
                        <span
                          className={`mt-0.5 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full border transition-colors ${
                            active
                              ? "border-[var(--accent)] bg-[var(--accent)] text-[var(--accent-ink)]"
                              : "border-[var(--line-strong)] bg-[var(--bg-elevated)]"
                          }`}
                          aria-hidden="true"
                        >
                          {active && <Check className="h-3 w-3 stroke-[2.5]" />}
                        </span>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {step === 2 && (
            <div className="space-y-4">
              {/* Plain-Language Action Guide (Active Monitoring vs Auto-Paused Timeout Summary) */}
              {isCapturePaused ? (
                <div className="space-y-3 rounded-2xl border border-[var(--amber)]/55 bg-[var(--amber-soft)]/55 p-4">
                  <div className="flex items-start gap-3">
                    <span className="mt-0.5 inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-[var(--amber)] text-[var(--accent-ink)]">
                      <Clock className="h-4 w-4" />
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-xs font-semibold text-[var(--text)]">
                          已达 3 分钟捕捉上限并自动暂停监控
                        </span>
                        <span className="inline-flex items-center gap-1 rounded-full bg-[var(--surface)]/85 px-2 py-0.5 cc-mono text-[10px] font-medium text-[var(--amber)]">
                          已暂停 · 共监控 {captureStatus?.elapsed_sec ?? 180} 秒
                        </span>
                      </div>
                      <p className="mt-1.5 text-xs leading-relaxed text-[var(--text-secondary)]">
                        {(captureStatus?.captured_node_count ?? 0) > 0
                          ? `目标软件「${captureStatus?.target_name || bgCapture.targetName || "目标软件"}」已抢读到的 ${captureStatus!.captured_node_count} 个节点已安全保留，点击下方即可整理并确认导入。`
                          : `目标软件「${captureStatus?.target_name || bgCapture.targetName || "目标软件"}」的监控已自动暂停。你仍可点击查看最终捕捉状态，或重新开始捕捉。`}
                      </p>
                    </div>
                  </div>
                  <div className="flex flex-wrap items-center gap-2 pl-11">
                    <button
                      type="button"
                      disabled={finishingCapture}
                      onClick={() => void handleFinishCapture()}
                      className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-50"
                    >
                      {finishingCapture ? (
                        <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <CheckCircle2 className="h-3.5 w-3.5" />
                      )}
                      <span>
                        {finishingCapture
                          ? "正在整理…"
                          : (captureStatus?.captured_node_count ?? 0) > 0
                            ? `整理并查看已捕捉内容（${captureStatus!.captured_node_count}）`
                            : "整理并查看已捕捉内容"}
                      </span>
                    </button>
                    <button
                      type="button"
                      disabled={finishingCapture}
                      onClick={() => void handleCancelCaptureToStep1()}
                      className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line-strong)] bg-[var(--card)] px-3 py-1.5 text-xs font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-50"
                    >
                      <RotateCcw className="h-3.5 w-3.5" />
                      <span>重新开始捕捉</span>
                    </button>
                  </div>
                </div>
              ) : (
                <div className="rounded-2xl border border-[var(--accent)]/50 bg-[var(--accent-soft)]/55 p-4">
                  <div className="flex items-start gap-3">
                    <span className="mt-0.5 inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-[var(--accent)] text-[var(--accent-ink)]">
                      <RefreshCw className="h-4 w-4 animate-spin" />
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-xs font-semibold text-[var(--text)]">
                          正在实时监控：{captureStatus?.target_name || "目标软件"}
                        </span>
                        <span className="inline-flex items-center gap-1 rounded-full bg-[var(--green-soft)] px-2 py-0.5 cc-mono text-[10px] font-medium text-[var(--green)]">
                          <span className="cc-pulse-dot h-1.5 w-1.5 rounded-full bg-[var(--green)]" />
                          已监控 {captureStatus?.elapsed_sec ?? 0} 秒
                        </span>
                      </div>
                      <p className="mt-1.5 text-xs leading-relaxed text-[var(--text)]">
                        请切到你选中的软件里点击「更新订阅」或「连接」，猫猫正在后台实时盯着新配置变动…
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* Live Sub-Step Status Lamps */}
              <div className="grid grid-cols-3 gap-2">
                {(
                  [
                    {
                      ok: Boolean(captureStatus?.step_app_ready),
                      label: "已锁定目标软件",
                    },
                    {
                      ok: Boolean(captureStatus?.step_activity_seen),
                      label: "检测到配置变动",
                    },
                    {
                      ok: Boolean(captureStatus?.step_nodes_ready),
                      label: "已抢读到明文节点",
                    },
                  ] as const
                ).map((lamp, idx) => (
                  <div
                    key={idx}
                    className={`flex items-center gap-2 rounded-xl border px-3 py-2.5 text-xs ${
                      lamp.ok
                        ? "border-[var(--green)]/45 bg-[var(--green-soft)] text-[var(--green)] font-medium"
                        : "border-[var(--line)] bg-[var(--card)] text-[var(--muted)]"
                    }`}
                  >
                    <span
                      className={`h-2 w-2 shrink-0 rounded-full ${
                        lamp.ok ? "bg-[var(--green)]" : "bg-[var(--line-strong)]"
                      }`}
                    />
                    <span className="truncate">{lamp.label}</span>
                  </div>
                ))}
              </div>

              {/* Captured Count & Opaque Hint */}
              <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
                <div className="rounded-xl border border-[var(--line)] bg-[var(--card)] p-3.5">
                  <div className="text-[11px] text-[var(--muted)]">已抢读可用节点</div>
                  <div className="mt-1 flex items-baseline gap-1.5">
                    <span
                      className={`cc-mono text-2xl font-bold ${
                        (captureStatus?.captured_node_count ?? 0) > 0
                          ? "text-[var(--green)]"
                          : "text-[var(--text)]"
                      }`}
                    >
                      {captureStatus?.captured_node_count ?? 0}
                    </span>
                    <span className="text-xs text-[var(--muted)]">个节点</span>
                  </div>
                </div>

                <div className="rounded-xl border border-[var(--line)] bg-[var(--card)] p-3.5">
                  <div className="text-[11px] text-[var(--muted)]">
                    实时监听目录（{captureStatus?.watch_dirs.length ?? 0}）
                  </div>
                  <div className="mt-1 space-y-0.5 cc-mono text-[10.5px] text-[var(--text-secondary)]">
                    {(captureStatus?.watch_dirs.length ?? 0) > 0 ? (
                      captureStatus!.watch_dirs.slice(0, 2).map((dir, i) => (
                        <div key={i} className="truncate" title={dir}>
                          {dir}
                        </div>
                      ))
                    ) : (
                      <div className="text-[var(--muted)]">
                        监控进程树与临时配置目录中…
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {captureStatus?.opaque_change_detected &&
                (captureStatus.captured_node_count ?? 0) === 0 && (
                  <div className="flex items-start gap-2 rounded-xl border border-[var(--amber)]/45 bg-[var(--amber-soft)] px-3.5 py-2.5 text-xs text-[var(--amber)]">
                    <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                    <span>
                      已检测到该软件写入非明文或加密格式配置，暂未读出明文节点。可尝试再次点击「更新订阅」或点击下方「结束捕捉并整理」查看结果。
                    </span>
                  </div>
                )}

              {/* Live Event Stream */}
              <div className="rounded-xl border border-[var(--line)] bg-[var(--card)] p-3.5">
                <div className="mb-2 flex items-center justify-between text-[11px]">
                  <span className="inline-flex items-center gap-1.5 font-semibold text-[var(--text)]">
                    <Clock className="h-3.5 w-3.5 text-[var(--accent)]" />
                    实时监测动态
                  </span>
                  <span className="cc-mono text-[var(--muted)]">
                    {captureStatus?.events.length ?? 0} 条记录
                  </span>
                </div>
                <div className="max-h-44 space-y-1.5 overflow-y-auto pr-1 text-xs">
                  {(captureStatus?.events.length ?? 0) === 0 ? (
                    <div className="py-4 text-center text-[11px] text-[var(--muted)]">
                      等待目标软件触发更新订阅或连接动作…
                    </div>
                  ) : (
                    captureStatus!.events.map((ev, idx) => {
                      const dotClass =
                        ev.kind === "nodes" || ev.kind === "hit"
                          ? "bg-[var(--green)]"
                          : ev.kind === "opaque" || ev.kind === "warn"
                            ? "bg-[var(--amber)]"
                            : "bg-[var(--accent)]";
                      return (
                        <div
                          key={`${ev.timestamp_ms}-${idx}`}
                          className="flex items-start gap-2 rounded-lg bg-[var(--bg-elevated)] px-2.5 py-1.5 text-[11px]"
                        >
                          <span
                            className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${dotClass}`}
                          />
                          <span className="cc-mono shrink-0 text-[10px] text-[var(--muted)]">
                            {formatCaptureEventTime(ev.timestamp_ms)}
                          </span>
                          <span className="min-w-0 flex-1 leading-relaxed text-[var(--text-secondary)]">
                            {ev.message}
                          </span>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>

              {/* Quick Preview of Captured Nodes if already found */}
              {captureStatus && captureStatus.preview_nodes.length > 0 && (
                <div className="rounded-xl border border-[var(--green)]/40 bg-[var(--green-soft)]/35 p-3">
                  <div className="mb-1.5 flex items-center justify-between text-[11px] font-medium text-[var(--green)]">
                    <span>已抢读节点预览</span>
                    <span className="cc-mono">
                      共 {captureStatus.captured_node_count} 个
                    </span>
                  </div>
                  <div className="space-y-1">
                    {captureStatus.preview_nodes.slice(0, 3).map((n, idx) => (
                      <div
                        key={`${n.id}-${idx}`}
                        className="flex items-center justify-between gap-2 rounded-lg bg-[var(--card)]/90 px-2.5 py-1 text-[11px]"
                      >
                        <span className="truncate font-medium text-[var(--text)]">
                          {n.name}
                        </span>
                        <span className="cc-mono shrink-0 text-[10px] text-[var(--muted)]">
                          {n.protocol.toUpperCase()} · {resolveNodeRegionCode(n)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {step === 3 && outcome && (
            isOutcomeSupported ? (
              <div className="space-y-4">
                {/* Success Header */}
                <div className="flex items-start gap-3 rounded-2xl border border-[var(--green)]/45 bg-[var(--green-soft)]/60 p-4">
                  <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-[var(--green)]" />
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-semibold text-[var(--text)]">
                      成功捕捉到 {outcome.nodes.length} 个可用节点（已选 {selectedOutcomeNodes.length} 个）
                    </div>
                    <p className="mt-1 text-xs leading-relaxed text-[var(--text-secondary)]">
                      来源软件：
                      <strong className="font-semibold text-[var(--text)]">
                        {outcome.target_name || "桌面软件"}
                      </strong>
                      {" · "}
                      {outcome.is_ephemeral_source || outcome.source_kind === "migrated"
                        ? "将以永久节点方式安全落库，重启后也不会失效。"
                        : outcome.source_kind === "file"
                          ? "已识别到稳定配置文件，可勾选需要的节点直接导入或并入已有分组。"
                          : "已识别到本地公开接口，可勾选需要的节点直接导入或并入已有分组。"}
                    </p>
                  </div>
                </div>

                {/* Region Distribution */}
                {outcomeRegionStats.length > 0 && (
                  <div className="space-y-1.5">
                    <div className="text-[11px] font-medium text-[var(--muted)]">
                      地区分布
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {outcomeRegionStats.slice(0, 10).map((stat) => (
                        <span
                          key={stat.code}
                          className="inline-flex items-center gap-1 rounded-full border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-0.5 text-[11px] text-[var(--text)]"
                        >
                          <span>{stat.label}</span>
                          <span className="cc-mono font-semibold text-[var(--accent)]">
                            {stat.count}
                          </span>
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Destination Mode Switch: Save as New Group vs Update Existing Group */}
                <div className="space-y-3 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)]/70 p-3.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      disabled={importingOutcome}
                      onClick={() => setCaptureTargetMode("new")}
                      className={`inline-flex items-center gap-1.5 rounded-xl border px-3 py-1.5 text-xs font-semibold transition-colors ${
                        captureTargetMode === "new"
                          ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                          : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                      }`}
                    >
                      <Plus className="h-3.5 w-3.5" />
                      <span>{dict.nodes.captureSaveNew}</span>
                    </button>

                    <button
                      type="button"
                      disabled={importingOutcome || subscriptions.length === 0}
                      onClick={() => setCaptureTargetMode("existing")}
                      title={
                        subscriptions.length === 0
                          ? "当前暂无已有分组，请先保存为新分组"
                          : "将本次勾选的节点替换或去重并入已有分组"
                      }
                      className={`inline-flex items-center gap-1.5 rounded-xl border px-3 py-1.5 text-xs font-semibold transition-colors disabled:cursor-not-allowed disabled:opacity-45 ${
                        captureTargetMode === "existing"
                          ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                          : "border-[var(--line)] bg-[var(--card)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                      }`}
                    >
                      <RefreshCw className="h-3.5 w-3.5" />
                      <span>{dict.nodes.captureUpdateExisting}</span>
                    </button>
                  </div>

                  {captureTargetMode === "new" ? (
                    <label className="block text-xs text-[var(--muted)]">
                      导入后的分组名称（可直接修改）
                      <input
                        type="text"
                        disabled={importingOutcome}
                        value={importName}
                        onChange={(e) => setImportName(e.target.value)}
                        placeholder={`抓取 · ${outcome.target_name || "桌面软件"}`}
                        className="mt-1.5 w-full rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-2 text-xs text-[var(--text)] focus:border-[var(--accent)] focus:outline-none disabled:opacity-60"
                      />
                    </label>
                  ) : (
                    <div className="space-y-2.5">
                      <div className="space-y-1">
                        <span className="block text-[11px] font-medium text-[var(--muted)]">
                          选择要更新的目标已有分组
                        </span>
                        <AppSelect
                          aria-label="选择要更新的目标已有分组"
                          size="sm"
                          disabled={importingOutcome}
                          value={captureTargetSubId}
                          onChange={setCaptureTargetSubId}
                          options={subscriptions.map((sub) => ({
                            value: sub.id,
                            label: `${sub.name}（现有 ${subNodeCountMap.get(sub.id) ?? 0} 个节点）`,
                          }))}
                          className="w-full"
                          buttonClassName="bg-[var(--card)]"
                        />
                      </div>

                      <div className="text-[11px] leading-relaxed text-[var(--muted)]">
                        选择更新方式（如更新失败，原有分组与节点会自动保持不变）：
                      </div>

                      <div className="flex flex-wrap items-center gap-2">
                        <button
                          type="button"
                          disabled={
                            importingOutcome ||
                            selectedOutcomeNodes.length === 0 ||
                            !captureTargetSubId
                          }
                          onClick={() =>
                            void handleConfirmImportOutcome("existing", "replace_latest")
                          }
                          className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
                        >
                          {importingOutcome ? (
                            <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                          ) : (
                            <Check className="h-3.5 w-3.5" />
                          )}
                          <span>{dict.nodes.captureModeReplace}</span>
                        </button>

                        <button
                          type="button"
                          disabled={
                            importingOutcome ||
                            selectedOutcomeNodes.length === 0 ||
                            !captureTargetSubId
                          }
                          onClick={() =>
                            void handleConfirmImportOutcome("existing", "merge_dedup")
                          }
                          className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--accent)]/60 bg-[var(--accent-soft)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent)] transition-colors hover:bg-[var(--accent)] hover:text-[var(--accent-ink)] disabled:cursor-not-allowed disabled:opacity-50"
                        >
                          <GitMerge className="h-3.5 w-3.5" />
                          <span>{dict.nodes.captureModeMerge}</span>
                        </button>

                        <button
                          type="button"
                          disabled={importingOutcome}
                          onClick={handleCancelExistingUpdate}
                          className="inline-flex items-center gap-1 rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)] hover:text-[var(--text)] disabled:opacity-50"
                        >
                          <X className="h-3.5 w-3.5" />
                          <span>{dict.nodes.captureModeCancel}</span>
                        </button>
                      </div>
                    </div>
                  )}
                </div>

                {/* Full Captured Node Preview with Checkboxes */}
                <div className="space-y-2 rounded-xl border border-[var(--line)] bg-[var(--card)] p-3.5">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-xs font-semibold text-[var(--text)]">
                        捕获节点预览（已选 {selectedOutcomeNodes.length} / {outcome.nodes.length}）
                      </span>
                      <button
                        type="button"
                        disabled={filteredOutcomeEntries.length === 0}
                        onClick={handleToggleAllFilteredOutcome}
                        className="rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2 py-0.5 text-[11px] font-medium text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-45"
                      >
                        {allFilteredOutcomeSelected ? "取消全选当前" : "全选当前"}
                      </button>
                    </div>
                    {outcome.nodes.length > 6 && (
                      <div className="relative w-48">
                        <Search className="pointer-events-none absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-[var(--muted)]" />
                        <input
                          type="text"
                          value={nodeFilter}
                          onChange={(e) => setNodeFilter(e.target.value)}
                          placeholder="筛选预览节点..."
                          className="w-full rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] py-1 pl-6 pr-2 text-[11px] text-[var(--text)] focus:border-[var(--accent)] focus:outline-none"
                        />
                      </div>
                    )}
                  </div>
                  <p className="text-[11px] text-[var(--muted)]">
                    可取消勾选不需要的假节点、剩余流量提示条或到期提醒行，只保留真实可用节点。
                  </p>

                  <div className="max-h-60 space-y-1.5 overflow-y-auto pr-1">
                    {filteredOutcomeEntries.map(({ node, index }) => {
                      const regionCode = resolveNodeRegionCode(node);
                      const checked = selectedOutcomeIndices.has(index);
                      return (
                        <label
                          key={`${node.id}-${index}`}
                          className={`flex cursor-pointer items-center justify-between gap-2 rounded-lg border px-2.5 py-1.5 text-xs transition-colors ${
                            checked
                              ? "border-[var(--accent)]/45 bg-[var(--bg-elevated)]"
                              : "border-[var(--line)]/60 bg-[var(--bg-elevated)]/45 opacity-55 hover:opacity-85"
                          }`}
                        >
                          <div className="flex min-w-0 flex-1 items-center gap-2">
                            <input
                              type="checkbox"
                              checked={checked}
                              disabled={importingOutcome}
                              onChange={() => toggleOutcomeNodeIndex(index)}
                              className="h-3.5 w-3.5 shrink-0 cursor-pointer accent-[var(--accent)]"
                            />
                            <div className="min-w-0 flex-1">
                              <div className="truncate font-medium text-[var(--text)]">
                                {node.name}
                              </div>
                              <div className="cc-mono text-[10px] text-[var(--muted)]">
                                {node.protocol.toUpperCase()} · {node.server}:{node.port}
                              </div>
                            </div>
                          </div>
                          <div className="flex shrink-0 items-center gap-1.5 cc-mono text-[10px]">
                            <span
                              title={getRegionLabel(regionCode)}
                              className="rounded bg-[var(--card)] px-1.5 py-0.5 text-[var(--text-secondary)]"
                            >
                              {regionCode}
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
                        </label>
                      );
                    })}
                  </div>
                </div>
              </div>
            ) : (
              /* Clean Unsupported Empty State */
              <div className="flex min-h-[320px] flex-col items-center justify-center px-4 py-8 text-center">
                <div className="flex h-12 w-12 items-center justify-center rounded-2xl border border-[var(--amber)]/40 bg-[var(--amber-soft)] text-[var(--amber)]">
                  <AlertTriangle className="h-6 w-6" />
                </div>
                <h3 className="mt-4 text-sm font-semibold text-[var(--text)]">
                  未能直接抓取到明文节点
                </h3>
                <p className="mt-2 max-w-md text-xs leading-relaxed text-[var(--text-secondary)]">
                  {UNSUPPORTED_CAPTURE_NOTICE}
                </p>
                <p className="mt-2 inline-flex items-center gap-1.5 rounded-lg border border-[var(--green)]/35 bg-[var(--green-soft)]/50 px-3 py-1.5 text-[11px] font-medium text-[var(--green)]">
                  <ShieldCheck className="h-3.5 w-3.5 shrink-0" />
                  <span>你原有的订阅分组与节点均已完整保留不动</span>
                </p>
                {outcome.unsupported_reason &&
                  outcome.unsupported_reason.trim() !== UNSUPPORTED_CAPTURE_NOTICE && (
                    <p className="mt-2 max-w-md rounded-lg bg-[var(--bg-elevated)] px-3 py-1.5 text-[11px] text-[var(--muted)]">
                      {outcome.unsupported_reason}
                    </p>
                  )}
                <div className="mt-6 flex flex-wrap items-center justify-center gap-2.5">
                  <button
                    type="button"
                    onClick={() => void handleResetToStep1()}
                    className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line-strong)] bg-[var(--card)] px-4 py-2 text-xs font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
                  >
                    <ArrowLeft className="h-3.5 w-3.5" />
                    返回重选其它软件
                  </button>
                  <button
                    type="button"
                    onClick={handleSwitchToSubUrl}
                    className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90"
                  >
                    <Link2 className="h-3.5 w-3.5" />
                    去粘贴订阅链接
                  </button>
                </div>
              </div>
            )
          )}
        </div>

        {/* Footer Actions */}
        <div className="flex items-center justify-between gap-2 border-t border-[var(--line)] px-5 py-3">
          {step === 1 && (
            <>
              <span className="truncate text-[11px] text-[var(--muted)]">
                {selectedCandidate
                  ? `已选：${selectedCandidate.friendly_name || selectedCandidate.process_name}`
                  : "请先选择一个桌面软件"}
              </span>
              <div className="flex shrink-0 items-center gap-2">
                <button
                  type="button"
                  onClick={safeClose}
                  className="rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 text-xs text-[var(--muted)] hover:text-[var(--text)]"
                >
                  取消
                </button>
                <button
                  type="button"
                  disabled={!selectedCandidate || startingCapture}
                  onClick={() => void handleStartLiveCapture()}
                  className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-45"
                >
                  {startingCapture ? (
                    <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Play className="h-3.5 w-3.5" />
                  )}
                  {startingCapture ? "正在启动…" : "开始实时捕捉"}
                </button>
              </div>
            </>
          )}

          {step === 2 && (
            <>
              <span className="truncate text-[11px] text-[var(--muted)]">
                {isCapturePaused
                  ? (captureStatus?.captured_node_count ?? 0) > 0
                    ? `捕捉已暂停，已安全保留 ${captureStatus!.captured_node_count} 个节点`
                    : "已达 3 分钟捕捉上限并自动暂停监控"
                  : (captureStatus?.captured_node_count ?? 0) > 0
                    ? `已抢读 ${captureStatus!.captured_node_count} 个节点，随时可结束整理`
                    : "切到目标软件点击更新订阅或连接后，再点右侧结束"}
              </span>
              <div className="flex shrink-0 items-center gap-2">
                <button
                  type="button"
                  disabled={finishingCapture}
                  onClick={() => void handleCancelCaptureToStep1()}
                  className="rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 text-xs text-[var(--muted)] hover:text-[var(--text)] disabled:opacity-50"
                >
                  {isCapturePaused ? "重新开始捕捉" : "取消捕捉"}
                </button>
                <button
                  type="button"
                  disabled={finishingCapture}
                  onClick={() => void handleFinishCapture()}
                  className={`inline-flex items-center gap-1.5 rounded-xl px-4 py-1.5 text-xs font-semibold transition-opacity hover:opacity-90 disabled:opacity-50 ${
                    (captureStatus?.captured_node_count ?? 0) > 0
                      ? "bg-[var(--green)] text-[var(--accent-ink)]"
                      : "bg-[var(--accent)] text-[var(--accent-ink)]"
                  }`}
                >
                  {finishingCapture ? (
                    <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                  ) : isCapturePaused ? (
                    <CheckCircle2 className="h-3.5 w-3.5" />
                  ) : (
                    <Square className="h-3 w-3 fill-current" />
                  )}
                  {finishingCapture
                    ? "正在整理…"
                    : isCapturePaused
                      ? (captureStatus?.captured_node_count ?? 0) > 0
                        ? `整理并查看已捕捉内容（${captureStatus!.captured_node_count}）`
                        : "整理并查看已捕捉内容"
                      : (captureStatus?.captured_node_count ?? 0) > 0
                        ? `结束捕捉并整理（${captureStatus!.captured_node_count}）`
                        : "结束捕捉并整理"}
                </button>
              </div>
            </>
          )}

          {step === 3 && (
            <>
              <span className="truncate text-[11px] text-[var(--muted)]">
                {isOutcomeSupported
                  ? captureTargetMode === "existing"
                    ? "请在上方点选「保留最新」或「整合去重」完成更新"
                    : "安全只读提取，不会修改原软件配置"
                  : "换个支持的软件或使用标准订阅链接"}
              </span>
              <div className="flex shrink-0 items-center gap-2">
                {isOutcomeSupported ? (
                  <>
                    <button
                      type="button"
                      disabled={importingOutcome}
                      onClick={() => void handleResetToStep1()}
                      className="rounded-xl border border-[var(--line)] bg-[var(--card)] px-3 py-1.5 text-xs text-[var(--muted)] hover:text-[var(--text)] disabled:opacity-50"
                    >
                      返回重选
                    </button>
                    {captureTargetMode === "new" && (
                      <button
                        type="button"
                        disabled={
                          importingOutcome || !outcome || selectedOutcomeNodes.length === 0
                        }
                        onClick={() => void handleConfirmImportOutcome("new")}
                        className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        {importingOutcome ? (
                          <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <Check className="h-3.5 w-3.5" />
                        )}
                        {importingOutcome
                          ? "正在导入…"
                          : `${dict.nodes.captureSaveNew}（${selectedOutcomeNodes.length} 个）`}
                      </button>
                    )}
                  </>
                ) : (
                  <button
                    type="button"
                    onClick={() => {
                      appActions.clearLiveCaptureOutcome();
                      onClose();
                    }}
                    className="rounded-xl border border-[var(--line)] bg-[var(--card)] px-3.5 py-1.5 text-xs text-[var(--text)] hover:border-[var(--accent)]"
                  >
                    关闭
                  </button>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>,
    document.body
  );
}

export default ProcessAttachDrawer;
