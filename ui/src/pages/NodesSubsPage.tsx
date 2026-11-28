import {
  ArrowRight,
  Check,
  CheckCircle2,
  Clock,
  Cpu,
  FileText,
  FolderOpen,
  Link2,
  RefreshCw,
  Search,
  Sparkles,
  X,
} from "lucide-react";
import { Suspense, lazy, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  type ProxyNode,
  type SubscriptionRecord,
  type SubscriptionUpdateMode,
  catcloudApi,
  formatErrorMessage,
  isTauriEnv,
} from "../api/tauri";
import type { ShareBundleTransport } from "../components/ShareBundleModal";
import { normalizeUiLanguage, useUiDict } from "../i18n";
import { appActions, appStore, useAppSelector } from "../store/appStore";
import {
  DeleteSubscriptionModal,
  MergeSubscriptionsModal,
} from "./nodes-subs/SubModals";
import { SubscriptionCardsSection } from "./nodes-subs/SubscriptionCardsSection";
import {
  type CaptureConfirmPayload,
  type MigrationPreviewItem,
  SINGLE_NODE_URI_RE,
  containsSingleNodeShareUriLine,
  getSubSource,
  hasPausedCaptureSession,
  inferSubNameFromUrl,
  isSingleNodeShareUri,
  normalizeSubSourceForCompare,
  parseClashInstallConfigUrl,
} from "./nodes-subs/utils";

const LazyMigrationDrawer = lazy(() =>
  import("./nodes-subs/MigrationDrawer").then((m) => ({ default: m.MigrationDrawer }))
);
const LazyProcessAttachDrawer = lazy(() =>
  import("./nodes-subs/ProcessAttachDrawer").then((m) => ({
    default: m.ProcessAttachDrawer,
  }))
);
const LazyShareBundleModal = lazy(() =>
  import("../components/ShareBundleModal").then((m) => ({ default: m.ShareBundleModal }))
);

/* ============================================================================
 * Main Page Export: NodesSubsPage (Subscriptions & Import Hub)
 * ============================================================================ */

export interface NodesSubsPageProps {
  embeddedSubsOnly?: boolean;
  onViewSubNodes?: (subId: string | null) => void;
}

export function NodesSubsPage({ onViewSubNodes }: NodesSubsPageProps = {}) {
  const subscriptions = useAppSelector((s) => s.subscriptions);
  const nodes = useAppSelector((s) => s.nodes);
  const uiLang = useAppSelector((s) => s.config.personalization.ui_language);
  const dict = useUiDict(normalizeUiLanguage(uiLang));
  const subsBg = useAppSelector((s) => s.bgTasks.subs);
  const bgCapture = useAppSelector((s) => s.bgTasks.capture);
  const nodesTabHint = useAppSelector((s) => s.nodesTabHint);

  // Global background subscription & capture task state (survives tab & route switches)
  const refreshingAll = subsBg.refreshingAll;
  const refreshingIdSet = useMemo(
    () => new Set(subsBg.refreshingIds),
    [subsBg.refreshingIds]
  );
  const importingSub = subsBg.importing;

  // Quick import form & banners
  const [showLocalFileForm, setShowLocalFileForm] = useState(false);
  const [newSubName, setNewSubName] = useState("");
  const [newSubSource, setNewSubSource] = useState("");
  const [pastedMultilineNodes, setPastedMultilineNodes] = useState<string | null>(null);
  const subUrlInputRef = useRef<HTMLInputElement | null>(null);
  const [localFileName, setLocalFileName] = useState("");
  const [localFilePath, setLocalFilePath] = useState("");
  const [importSuccessBanner, setImportSuccessBanner] = useState<{
    count: number;
    sourceName: string;
    subId: string | null;
  } | null>(null);
  const [copyingAiOnboarding, setCopyingAiOnboarding] = useState(false);
  const [copiedAiOnboarding, setCopiedAiOnboarding] = useState(false);
  const aiGuideTimerRef = useRef<number | null>(null);

  // Drawers, Share Bundle Modal, Inline Rename & Merge Modal
  const [migrationOpen, setMigrationOpen] = useState(false);
  const [migrationInitialTab, setMigrationInitialTab] = useState<"scan" | "paste">("scan");
  const [migrationInitialPaste, setMigrationInitialPaste] = useState<string | null>(null);
  const [processAttachOpen, setProcessAttachOpen] = useState(false);
  const [pendingDeleteSub, setPendingDeleteSub] = useState<SubscriptionRecord | null>(null);
  const [deletingSub, setDeletingSub] = useState(false);

  const [shareModalState, setShareModalState] = useState<{
    open: boolean;
    mode: "export" | "import";
    defaultTab: "nodes" | "relays";
    initialNodeIds?: string[];
    defaultPackName?: string;
    initialTransport?: ShareBundleTransport;
  }>({
    open: false,
    mode: "export",
    defaultTab: "nodes",
  });

  const [renamingSubId, setRenamingSubId] = useState<string | null>(null);
  const [renamingSubName, setRenamingSubName] = useState<string>("");
  const [renamingBusy, setRenamingBusy] = useState<boolean>(false);

  const [mergeModalOpen, setMergeModalOpen] = useState<boolean>(false);
  const [mergeSourceSubId, setMergeSourceSubId] = useState<string>("");
  const [mergeTargetSubId, setMergeTargetSubId] = useState<string>("");
  const [mergeNewName, setMergeNewName] = useState<string>("");
  const [mergeDedup, setMergeDedup] = useState<boolean>(true);
  const [mergingSubs, setMergingSubs] = useState<boolean>(false);
  const [mergeError, setMergeError] = useState<string | null>(null);

  const openShareExport = useCallback(
    (
      initialNodeIds?: string[],
      defaultPackName?: string,
      initialTransport: ShareBundleTransport = "zip"
    ) => {
      setShareModalState({
        open: true,
        mode: "export",
        defaultTab: "nodes",
        initialNodeIds,
        defaultPackName,
        initialTransport,
      });
    },
    []
  );

  const openShareImport = useCallback(() => {
    setShareModalState({
      open: true,
      mode: "import",
      defaultTab: "nodes",
      initialTransport: "zip",
    });
  }, []);

  const openMergeModal = useCallback(() => {
    const subs = appStore.getState().subscriptions;
    if (subs.length < 2) {
      appActions.showToast("至少需要 2 个订阅分组才能执行合并", "info");
      return;
    }
    const target = subs[0];
    const source = subs[1];
    setMergeSourceSubId(source.id);
    setMergeTargetSubId(target.id);
    setMergeNewName(target.name);
    setMergeDedup(true);
    setMergeError(null);
    setMergeModalOpen(true);
  }, []);

  const closeMergeModal = useCallback(() => {
    setMergeModalOpen(false);
  }, []);

  const closeDeleteModal = useCallback(() => {
    setPendingDeleteSub(null);
  }, []);

  const closeMigration = useCallback(() => {
    setMigrationOpen(false);
    setMigrationInitialTab("scan");
    setMigrationInitialPaste(null);
  }, []);

  const openMigrationScan = useCallback(() => {
    setMigrationInitialTab("scan");
    setMigrationInitialPaste(null);
    setMigrationOpen(true);
  }, []);

  useEffect(() => {
    if (nodesTabHint?.action === "migration") {
      openMigrationScan();
      appActions.consumeNodesTabHint();
    } else if (nodesTabHint?.action === "share") {
      openShareImport();
      appActions.consumeNodesTabHint();
    }
  }, [nodesTabHint, openMigrationScan, openShareImport]);

  const openMigrationWithPaste = useCallback((rawText: string) => {
    setMigrationInitialTab("paste");
    setMigrationInitialPaste(rawText.trim());
    setMigrationOpen(true);
    setNewSubSource("");
    setPastedMultilineNodes(null);
  }, []);

  const closeProcessAttach = useCallback(() => setProcessAttachOpen(false), []);

  useEffect(() => {
    return () => {
      if (aiGuideTimerRef.current !== null) {
        window.clearTimeout(aiGuideTimerRef.current);
        aiGuideTimerRef.current = null;
      }
    };
  }, []);

  const handleCopyAiOnboarding = useCallback(async () => {
    if (copyingAiOnboarding) return;
    setCopyingAiOnboarding(true);
    try {
      const ok = await appActions.copyAiOnboardingForUser();
      if (ok) {
        setCopiedAiOnboarding(true);
        if (aiGuideTimerRef.current !== null) {
          window.clearTimeout(aiGuideTimerRef.current);
        }
        aiGuideTimerRef.current = window.setTimeout(() => {
          setCopiedAiOnboarding(false);
          aiGuideTimerRef.current = null;
        }, 2200);
      }
    } finally {
      setCopyingAiOnboarding(false);
    }
  }, [copyingAiOnboarding]);

  const isSingleNodeUrlInput = useMemo(
    () => Boolean(pastedMultilineNodes) || isSingleNodeShareUri(newSubSource),
    [newSubSource, pastedMultilineNodes]
  );
  const pastedMultilineNodeCount = useMemo(() => {
    if (!pastedMultilineNodes) return 0;
    return pastedMultilineNodes
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith("#") && SINGLE_NODE_URI_RE.test(line))
      .length;
  }, [pastedMultilineNodes]);
  const isCapturePaused =
    !bgCapture.active &&
    !bgCapture.finishing &&
    !bgCapture.outcome &&
    hasPausedCaptureSession(bgCapture);

  const subNodeCountMap = useMemo(() => {
    const map = new Map<string, number>();
    for (const n of nodes) {
      map.set(n.sub_id, (map.get(n.sub_id) ?? 0) + 1);
    }
    return map;
  }, [nodes]);

  /* ---------- Subscription Actions ---------- */

  const inTauri = isTauriEnv();

  const syncListsFromBackend = async () => {
    const [subsRes, nodesRes, groupsRes, rtRes, cfgRes] = await Promise.allSettled([
      catcloudApi.listSubscriptions(),
      catcloudApi.listNodes(),
      catcloudApi.listGroups(),
      catcloudApi.getRuntimeInfo(),
      catcloudApi.getConfig(),
    ]);
    if (subsRes.status === "fulfilled") appActions.syncSubscriptions(subsRes.value);
    if (nodesRes.status === "fulfilled") appActions.syncNodes(nodesRes.value);
    if (groupsRes.status === "fulfilled") appActions.syncGroups(groupsRes.value);
    if (rtRes.status === "fulfilled") appActions.syncRuntime(rtRes.value);
    if (cfgRes.status === "fulfilled") appActions.syncConfig(cfgRes.value);
  };

  const refreshSingleSubscription = async (
    sub: SubscriptionRecord,
    simulateFault = false
  ) => {
    if (refreshingIdSet.has(sub.id) || refreshingAll) return;
    await appActions.runRefreshSingleSubscription(sub.id, { simulateFault });
  };

  const refreshAllSubscriptions = async () => {
    if (subscriptions.length === 0 || refreshingAll) return;
    await appActions.runRefreshAllSubscriptions();
  };

  const submitSubscriptionSource = async (
    kind: "url" | "file",
    rawSource: string,
    rawName: string
  ) => {
    if (importingSub) return;
    let source = rawSource.trim();
    let effectiveNameInput = rawName.trim();
    if (!source) {
      appActions.showToast(
        kind === "url"
          ? "请先粘贴你的订阅链接"
          : "请填写本地配置文件路径",
        "warn"
      );
      return;
    }

    if (kind === "url") {
      const clashInstall = parseClashInstallConfigUrl(source);
      if (clashInstall) {
        source = clashInstall.url;
        setNewSubSource(clashInstall.url);
        if (!effectiveNameInput && clashInstall.name) {
          effectiveNameInput = clashInstall.name;
          setNewSubName(clashInstall.name);
        }
        appActions.showToast("已自动识别一键订阅链接并提取真实订阅地址", "info");
      }

      if (isSingleNodeShareUri(source)) {
        appActions.showToast(
          "检测到这是单节点分享链接，请点击输入框下方的「转到「粘贴配置文本」导入」",
          "warn",
          4500
        );
        return;
      }

      if (!/^https?:\/\//i.test(source)) {
        appActions.showToast(
          "订阅链接需要以 http:// 或 https:// 开头（也支持 clash://install-config?url=... 一键订阅链接）",
          "warn"
        );
        return;
      }
    }

    const latestSubsSnapshot = appStore.getState().subscriptions;
    const normalizedTargetSource = normalizeSubSourceForCompare(kind, source);
    const existingSub =
      latestSubsSnapshot.find(
        (s) =>
          s.kind === kind &&
          normalizeSubSourceForCompare(kind, getSubSource(s)) === normalizedTargetSource
      ) ?? null;

    const name =
      effectiveNameInput ||
      existingSub?.name ||
      (kind === "url"
        ? inferSubNameFromUrl(source)
        : source.split(/[\\/]/).pop()?.replace(/\.[^.]+$/, "") || "本地配置");

    const subId = existingSub ? existingSub.id : `sub-${kind}-${Date.now()}`;
    const nextSub: SubscriptionRecord = existingSub
      ? {
          ...existingSub,
          name,
          url_or_cmd: source,
          enabled: true,
        }
      : {
          id: subId,
          name,
          kind,
          url_or_cmd: source,
          refresh_interval_sec: 0,
          traffic_used_bytes: 0,
          traffic_total_bytes: 0,
          expires_at: null,
          last_ok_at: null,
          last_error: null,
          enabled: true,
        };

    appActions.setSubsImporting(true);
    appActions.setMascotState("searching");
    try {
      if (inTauri) {
        try {
          const saved = await catcloudApi.upsertSubscription(nextSub);
          const isNewlyCreatedEmptySub =
            !existingSub &&
            !saved.last_ok_at &&
            !latestSubsSnapshot.some((s) => s.id === saved.id);
          let refreshNotice = "";
          let refreshWarn = false;
          let importedNodeCount = 0;
          let rollbackErrorDetail = "";
          try {
            const res = await catcloudApi.refreshSubscription(saved.id);
            importedNodeCount = res.node_count;
            if (isNewlyCreatedEmptySub && importedNodeCount === 0) {
              refreshWarn = true;
              rollbackErrorDetail =
                res.warnings.length > 0
                  ? formatErrorMessage(res.warnings[0])
                  : "未解析到任何可用节点";
            } else {
              refreshNotice = `，已拉回 ${res.node_count} 个节点`;
            }
          } catch (refreshErr) {
            refreshWarn = true;
            rollbackErrorDetail = formatErrorMessage(refreshErr);
            refreshNotice = `，拉取失败（${rollbackErrorDetail}）`;
          }

          if (refreshWarn && isNewlyCreatedEmptySub) {
            try {
              await catcloudApi.deleteSubscription(saved.id);
            } catch {
              /* ignore orphan cleanup failure */
            }
            await syncListsFromBackend();
            appActions.showToast(
              `导入「${name}」失败（${rollbackErrorDetail || "订阅拉取异常"}），请检查${kind === "url" ? "链接" : "路径"}后重试`,
              "warn",
              5000
            );
            return;
          }

          await syncListsFromBackend();
          if (!refreshWarn) {
            if (kind === "url") {
              setNewSubName("");
              setNewSubSource("");
              setPastedMultilineNodes(null);
            } else {
              setLocalFileName("");
              setLocalFilePath("");
              setShowLocalFileForm(false);
            }
            if (importedNodeCount > 0) {
              setImportSuccessBanner({
                count: importedNodeCount,
                sourceName: name,
                subId: saved.id,
              });
            }
          }
          appActions.showToast(
            `${existingSub ? "已刷新已有订阅" : "已导入"}「${name}」${refreshNotice}`,
            refreshWarn ? "warn" : "ok"
          );
        } catch (err) {
          appActions.showToast(`导入订阅失败：${formatErrorMessage(err)}`, "warn");
        }
        return;
      }

      const latestState = appStore.getState();
      if (existingSub) {
        const nowIso = new Date().toISOString();
        const existingNodeCount = latestState.nodes.filter(
          (n) => n.sub_id === existingSub.id
        ).length;
        appActions.syncSubscriptions(
          latestState.subscriptions.map((item) =>
            item.id === existingSub.id
              ? { ...item, name, last_ok_at: nowIso, last_error: null }
              : item
          )
        );
        if (kind === "url") {
          setNewSubName("");
          setNewSubSource("");
        } else {
          setLocalFileName("");
          setLocalFilePath("");
          setShowLocalFileForm(false);
        }
        setImportSuccessBanner({
          count: Math.max(1, existingNodeCount),
          sourceName: name,
          subId: existingSub.id,
        });
        appActions.showToast(`已复用并刷新已有订阅「${name}」（演示预览）`, "ok");
        return;
      }

      const previewSub: SubscriptionRecord = {
        ...nextSub,
        traffic_total_bytes: 300 * 1024 * 1024 * 1024,
        expires_at: "2027-12-31",
        last_ok_at: new Date().toISOString(),
      };
      const seedNode: ProxyNode = {
        id: `${subId}-node-1`,
        sub_id: subId,
        name: `${name} · JP-01 · 1x`,
        protocol: kind === "url" ? "vless" : "trojan",
        server: kind === "url" ? "203.0.113.55" : "198.51.100.56",
        port: 443,
        region_code: "JP",
        multiplier: 1.0,
        is_443_native: true,
        preaccel_override: null,
        tags: ["native-443"],
        enabled: true,
      };

      appActions.syncSubscriptions([...latestState.subscriptions, previewSub]);
      appActions.syncNodes([...latestState.nodes, seedNode]);
      if (kind === "url") {
        setNewSubName("");
        setNewSubSource("");
      } else {
        setLocalFileName("");
        setLocalFilePath("");
        setShowLocalFileForm(false);
      }
      setImportSuccessBanner({
        count: 1,
        sourceName: name,
        subId,
      });
      appActions.showToast(`已导入「${name}」（演示预览）`, "ok");
    } finally {
      appActions.setSubsImporting(false);
      appActions.setMascotState("idle");
    }
  };

  const handleConfirmRemoveSubscription = async () => {
    if (!pendingDeleteSub || deletingSub) return;
    const sub = pendingDeleteSub;
    setDeletingSub(true);
    const removedCount = nodes.filter((n) => n.sub_id === sub.id).length;
    try {
      await appActions.deleteSubscription(sub.id);
      if (renamingSubId === sub.id) {
        setRenamingSubId(null);
        setRenamingSubName("");
      }
      if (importSuccessBanner?.subId === sub.id) {
        setImportSuccessBanner(null);
      }
      setPendingDeleteSub(null);
      void appActions.refreshDanglingRulesAudit();
      appActions.showToast(`已移除订阅：${sub.name}（同时移除 ${removedCount} 个节点）`, "info");
    } catch (err) {
      appActions.showToast(`移除订阅失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setDeletingSub(false);
    }
  };

  /* ---------- Drawer Callbacks ---------- */

  const handleMigrationImport = async (
    preview: MigrationPreviewItem,
    customName: string,
    includeRules: boolean
  ): Promise<boolean> => {
    if (inTauri) {
      try {
        const outcome = await catcloudApi.applyMigrationNodesWithMeta(
          customName,
          preview.nodes,
          {
            includeRules,
            prependRules: includeRules ? preview.prepend_rules : [],
            appendRules: includeRules ? preview.append_rules : [],
            danglingRulePolicy: "drop",
          }
        );
        const count = outcome.imported_count;
        const importedSubId = outcome.sub_id || null;
        const savedRulesCount = outcome.saved_rules_count ?? 0;
        const droppedDangling = outcome.dropped_dangling_rules_count ?? 0;
        await syncListsFromBackend();
        void appActions.refreshDanglingRulesAudit();
        if (count > 0) {
          setImportSuccessBanner({
            count,
            sourceName: customName,
            subId: importedSubId,
          });
        }
        const rulesSuffix =
          savedRulesCount > 0 ? `、${savedRulesCount} 条有效分流规则` : "";
        const droppedSuffix =
          droppedDangling > 0
            ? `（已自动过滤 ${droppedDangling} 条指向不存在分组的旧规则）`
            : "（原软件未改动）";
        appActions.showToast(
          `导入完成：已保存 ${count} 个节点${rulesSuffix}${droppedSuffix}`,
          "ok",
          droppedDangling > 0 ? 5200 : undefined
        );
        return true;
      } catch (err) {
        appActions.showToast(`导入节点失败：${formatErrorMessage(err)}`, "warn");
        return false;
      }
    }

    const subId = `sub-mig-${Date.now()}`;
    const importedNodes: ProxyNode[] = preview.nodes.map((node, idx) => ({
      ...node,
      id: `${subId}-${idx + 1}`,
      sub_id: subId,
    }));
    const sourceVal = preview.source_path ?? "clipboard://readonly-import";
    const nextSub: SubscriptionRecord = {
      id: subId,
      name: customName,
      kind: "migrated",
      url_or_cmd: sourceVal,
      refresh_interval_sec: 0,
      traffic_used_bytes: 0,
      traffic_total_bytes: 0,
      expires_at: null,
      last_ok_at: new Date().toISOString(),
      last_error: null,
      enabled: true,
    };
    appActions.syncSubscriptions([...subscriptions, nextSub]);
    appActions.syncNodes([...nodes, ...importedNodes]);

    setImportSuccessBanner({
      count: importedNodes.length,
      sourceName: customName,
      subId,
    });
    appActions.showToast(
      `导入完成：已保存 ${importedNodes.length} 个节点（原软件未改动）`,
      "ok"
    );
    return true;
  };

  const handleStartRenameSub = (sub: SubscriptionRecord) => {
    setRenamingSubId(sub.id);
    setRenamingSubName(sub.name);
  };

  const handleCancelRenameSub = () => {
    if (renamingBusy) return;
    setRenamingSubId(null);
    setRenamingSubName("");
  };

  const handleSubmitRenameSub = async (sub: SubscriptionRecord) => {
    if (renamingBusy) return;
    const trimmed = renamingSubName.trim();
    if (!trimmed) {
      appActions.showToast("分组名称不能为空", "warn");
      return;
    }
    if (trimmed === sub.name) {
      setRenamingSubId(null);
      setRenamingSubName("");
      return;
    }
    setRenamingBusy(true);
    try {
      await catcloudApi.renameSubscription(sub.id, trimmed);
      await appActions.refreshAllData();
      setRenamingSubId(null);
      setRenamingSubName("");
      appActions.showToast(`分组已改名为「${trimmed}」`, "ok");
    } catch (err) {
      appActions.showToast(`修改分组名称失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setRenamingBusy(false);
    }
  };

  const handleConfirmMergeSubs = async () => {
    if (mergingSubs) return;
    if (!mergeSourceSubId || !mergeTargetSubId) {
      setMergeError("请选择源分组和目标分组");
      return;
    }
    if (mergeSourceSubId === mergeTargetSubId) {
      setMergeError("源分组和目标分组不能是同一个组");
      return;
    }
    const sourceSub = subscriptions.find((s) => s.id === mergeSourceSubId);
    const targetSub = subscriptions.find((s) => s.id === mergeTargetSubId);
    setMergingSubs(true);
    setMergeError(null);
    try {
      const res = await catcloudApi.mergeSubscriptions({
        sourceSubId: mergeSourceSubId,
        targetSubId: mergeTargetSubId,
        newTargetName: mergeNewName.trim() || targetSub?.name || null,
        deduplicate: mergeDedup,
      });
      await appActions.refreshAllData();
      setMergeModalOpen(false);
      const dedupText =
        res.deduplicated_count > 0 ? `，自动去重 ${res.deduplicated_count} 个` : "";
      appActions.showToast(
        `已将「${sourceSub?.name ?? "源分组"}」合并入「${mergeNewName.trim() || targetSub?.name || "目标分组"}」（移入 ${res.moved_count} 个${dedupText}，现共 ${res.total_count} 个节点）`,
        "ok",
        5200
      );
    } catch (err) {
      const msg = formatErrorMessage(err);
      setMergeError(msg);
      appActions.showToast(`合并分组失败：${msg}`, "warn");
    } finally {
      setMergingSubs(false);
    }
  };

  const handleLiveCaptureImport = async (
    payload: CaptureConfirmPayload
  ): Promise<boolean> => {
    const { name, outcome, selectedNodes, targetMode, targetSubId, updateMode } = payload;
    const cleanName = name.trim() || `抓取 · ${outcome.target_name || "桌面软件"}`;
    const hasExplicitSelection = Array.isArray(selectedNodes);
    const capturedNodes = hasExplicitSelection
      ? selectedNodes
      : Array.isArray(outcome.nodes)
        ? outcome.nodes
        : [];
    if (!outcome.supported || capturedNodes.length === 0) {
      appActions.showToast(
        hasExplicitSelection
          ? "请至少勾选 1 个节点后再导入，原有分组已保留不动"
          : "未捕获到可导入节点，原有分组已保留不动",
        "warn"
      );
      return false;
    }

    // Update existing subscription group (replace_latest or merge_dedup)
    if (targetMode === "existing") {
      if (!targetSubId) {
        appActions.showToast("请先选择要更新的目标已有分组", "warn");
        return false;
      }
      const targetSub = subscriptions.find((s) => s.id === targetSubId);
      const effectiveMode: SubscriptionUpdateMode = updateMode ?? "merge_dedup";
      try {
        const res = await catcloudApi.applyNodesToExistingSubscription(
          targetSubId,
          capturedNodes,
          effectiveMode
        );
        await appActions.refreshAllData();
        const targetLabel = targetSub?.name ?? "已有分组";
        setImportSuccessBanner({
          count: res.total_count,
          sourceName: targetLabel,
          subId: targetSubId,
        });
        if (effectiveMode === "replace_latest") {
          appActions.showToast(
            `已替换更新「${targetLabel}」：现有 ${res.total_count} 个最新节点`,
            "ok",
            4800
          );
        } else {
          appActions.showToast(
            `已整合去重并入「${targetLabel}」：保留 ${res.kept_count} 个、新增 ${res.added_count} 个，共 ${res.total_count} 个节点`,
            "ok",
            5200
          );
        }
        return true;
      } catch (err) {
        appActions.showToast(
          `更新已有分组失败（已保留旧组不动）：${formatErrorMessage(err)}`,
          "warn",
          5200
        );
        return false;
      }
    }

    const userFilteredSubset = capturedNodes.length < outcome.nodes.length;
    const useMigratedPersistence =
      userFilteredSubset ||
      outcome.is_ephemeral_source ||
      outcome.source_kind === "migrated" ||
      outcome.source_kind === "none" ||
      !outcome.source_path?.trim();

    if (inTauri) {
      try {
        if (useMigratedPersistence) {
          const applied = await catcloudApi.applyMigrationNodesWithMeta(
            cleanName,
            capturedNodes
          );
          const importedCount = applied.imported_count;
          const importedSubId = applied.sub_id || null;
          await syncListsFromBackend();
          if (importedCount > 0) {
            setImportSuccessBanner({
              count: importedCount,
              sourceName: cleanName,
              subId: importedSubId,
            });
          }
          appActions.showToast(
            `已永久导入「${cleanName}」（共 ${importedCount} 个节点）`,
            "ok"
          );
          return true;
        }

        const subKind: SubscriptionRecord["kind"] =
          outcome.source_kind === "process_adapter" ? "process_adapter" : "file";
        const subId = `sub-capture-${Date.now()}`;
        const nextSub: SubscriptionRecord = {
          id: subId,
          name: cleanName,
          kind: subKind,
          url_or_cmd: outcome.source_path!.trim(),
          refresh_interval_sec: 0,
          traffic_used_bytes: 0,
          traffic_total_bytes: 0,
          expires_at: null,
          last_ok_at: null,
          last_error: null,
          enabled: true,
        };
        const saved = await catcloudApi.upsertSubscription(nextSub);
        let importedCount = 0;
        let finalSubId: string | null = saved.id;
        try {
          const refreshed = await catcloudApi.refreshSubscription(saved.id);
          importedCount = refreshed.node_count;
        } catch {
          importedCount = 0;
        }
        if (importedCount === 0) {
          try {
            await catcloudApi.deleteSubscription(saved.id);
          } catch {
            /* ignore empty subscription cleanup failure */
          }
          const fallbackRes = await catcloudApi.applyMigrationNodesWithMeta(
            cleanName,
            capturedNodes
          );
          importedCount = fallbackRes.imported_count;
          finalSubId = fallbackRes.sub_id || null;
        }
        await syncListsFromBackend();
        if (importedCount > 0) {
          setImportSuccessBanner({
            count: importedCount,
            sourceName: cleanName,
            subId: finalSubId,
          });
        }
        appActions.showToast(
          `已导入「${cleanName}」（共 ${importedCount} 个节点）`,
          "ok"
        );
        return true;
      } catch (err) {
        appActions.showToast(`导入捕捉节点失败：${formatErrorMessage(err)}`, "warn");
        return false;
      }
    }

    const subId = `sub-capture-${Date.now()}`;
    const subKind: SubscriptionRecord["kind"] = useMigratedPersistence
      ? "migrated"
      : outcome.source_kind === "process_adapter"
        ? "process_adapter"
        : "file";
    const boundNodes: ProxyNode[] = capturedNodes.map((node, idx) => ({
      ...node,
      id: `${subId}-${idx + 1}`,
      sub_id: subId,
    }));
    const previewSub: SubscriptionRecord = {
      id: subId,
      name: cleanName,
      kind: subKind,
      url_or_cmd: outcome.source_path?.trim() || "live-capture://snapshot",
      refresh_interval_sec: 0,
      traffic_used_bytes: 0,
      traffic_total_bytes: 0,
      expires_at: null,
      last_ok_at: new Date().toISOString(),
      last_error: null,
      enabled: true,
    };
    appActions.syncSubscriptions([...subscriptions, previewSub]);
    appActions.syncNodes([...nodes, ...boundNodes]);
    setImportSuccessBanner({
      count: boundNodes.length,
      sourceName: cleanName,
      subId,
    });
    appActions.showToast(
      `已导入「${cleanName}」（共 ${boundNodes.length} 个节点）`,
      "ok"
    );
    return true;
  };

  const handleFocusSubUrlInput = useCallback(() => {
    window.setTimeout(() => {
      subUrlInputRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
      subUrlInputRef.current?.focus();
    }, 40);
  }, []);

  const handleChangeMergeSource = useCallback(
    (nextSource: string) => {
      setMergeSourceSubId(nextSource);
      setMergeError(null);
      if (nextSource === mergeTargetSubId) {
        const altTarget = subscriptions.find((s) => s.id !== nextSource);
        if (altTarget) {
          setMergeTargetSubId(altTarget.id);
          setMergeNewName(altTarget.name);
        }
      }
    },
    [mergeTargetSubId, subscriptions]
  );

  const handleChangeMergeTarget = useCallback(
    (nextTarget: string) => {
      setMergeTargetSubId(nextTarget);
      setMergeError(null);
      const found = subscriptions.find((s) => s.id === nextTarget);
      if (found) setMergeNewName(found.name);
      if (nextTarget === mergeSourceSubId) {
        const altSource = subscriptions.find((s) => s.id !== nextTarget);
        if (altSource) setMergeSourceSubId(altSource.id);
      }
    },
    [mergeSourceSubId, subscriptions]
  );

  return (
    <div className="space-y-3">
      {/* Persistent Post-Import Next-Step Guidance Banner */}
      {importSuccessBanner && (
        <section
          aria-label="导入成功后续指引"
          className="cc-card cc-glass flex flex-wrap items-center justify-between gap-2.5 rounded-2xl border-[var(--green)]/50 bg-[var(--green-soft)]/55 px-4 py-3"
        >
          <div className="flex min-w-0 flex-1 items-center gap-2.5 text-xs">
            <CheckCircle2 className="h-4 w-4 shrink-0 text-[var(--green)]" />
            <div className="min-w-0 leading-relaxed text-[var(--text)]">
              已成功导入{" "}
              <strong className="cc-mono font-semibold text-[var(--green)]">
                {importSuccessBanner.count}
              </strong>{" "}
              个节点（{importSuccessBanner.sourceName}）并自动归入路线组！接下来建议：
            </div>
          </div>

          <div className="flex shrink-0 flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => {
                if (onViewSubNodes) {
                  onViewSubNodes(importSuccessBanner.subId);
                } else {
                  appActions.openNodesWorkspace("nodes", importSuccessBanner.subId);
                }
              }}
              className="inline-flex items-center gap-1 rounded-xl bg-[var(--accent)] px-3 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90"
            >
              <span>去测速并挑最优节点</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </button>

            <button
              type="button"
              onClick={() => appActions.setNav("overview")}
              className="inline-flex items-center gap-1 rounded-xl border border-[var(--green)]/50 bg-[var(--card)] px-3 py-1.5 text-xs font-semibold text-[var(--green)] transition-colors hover:bg-[var(--green)] hover:text-[var(--accent-ink)]"
            >
              <span>回总览一键开启代理</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </button>

            <button
              type="button"
              onClick={() => setImportSuccessBanner(null)}
              className="inline-flex h-7 w-7 items-center justify-center rounded-lg text-[var(--muted)] transition-colors hover:bg-[var(--card)] hover:text-[var(--text)]"
              aria-label="关闭引导提示"
              title="关闭提示"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        </section>
      )}

      {/* Lightweight Beginner AI Onboarding Strip above the 3 Import Cards */}
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-2xl border border-[var(--accent)]/30 bg-[var(--accent-soft)]/40 px-3.5 py-2 text-xs">
        <div className="flex min-w-0 items-center gap-2 text-[var(--text-secondary)]">
          <Sparkles className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
          <span className="truncate">
            第一次用不知道怎么找或导入节点？让 AI 看你当前画面一步步教你
          </span>
        </div>
        <button
          type="button"
          disabled={copyingAiOnboarding}
          onClick={() => void handleCopyAiOnboarding()}
          className={`inline-flex shrink-0 items-center gap-1 rounded-lg px-2.5 py-1 text-xs font-semibold transition-colors disabled:opacity-60 ${
            copiedAiOnboarding
              ? "bg-[var(--green-soft)] text-[var(--green)]"
              : "bg-[var(--card)] text-[var(--accent)] hover:bg-[var(--accent)] hover:text-[var(--accent-ink)]"
          }`}
        >
          {copiedAiOnboarding ? (
            <>
              <Check className="h-3.5 w-3.5 shrink-0" />
              <span>已复制，直接粘给任意 AI</span>
            </>
          ) : (
            <span>
              {copyingAiOnboarding
                ? "正在生成指南…"
                : "点我复制给 AI 一步步教你 →"}
            </span>
          )}
        </button>
      </div>

      {/* ====================================================================
       * 1. Beginner-Friendly 3-Card Quick Import Hub
       * ==================================================================== */}
      <section
        aria-label="快速导入节点入口"
        className="grid grid-cols-1 gap-3.5 min-[1160px]:grid-cols-3"
      >
        {/* Card 1: Paste Subscription URL */}
        <div className="cc-card cc-glass flex min-w-0 flex-col justify-between gap-3 rounded-2xl border-[var(--accent)]/45 p-4">
          <div className="space-y-2.5">
            <div className="flex flex-wrap items-start justify-between gap-2">
              <div className="flex min-w-0 flex-1 items-center gap-2.5">
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[var(--accent-soft)] text-[var(--accent)]">
                  <Link2 className="h-4 w-4" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-1.5">
                    <span className="inline-flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-[var(--accent)] text-[10px] font-bold text-[var(--accent-ink)]">
                      1
                    </span>
                    <h2 className="min-w-0 truncate text-sm font-semibold text-[var(--text)]">
                      粘贴订阅链接
                    </h2>
                  </div>
                  <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                    贴上机场给的订阅地址（支持一键订阅链接），点一下立刻拉回节点
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setShowLocalFileForm((v) => !v)}
                className={`inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors ${
                  showLocalFileForm
                    ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                    : "border-[var(--line-strong)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
                }`}
              >
                <FileText className="h-3 w-3 shrink-0" />
                {showLocalFileForm ? "收起本地文件" : "本地文件"}
              </button>
            </div>

            <input
              ref={subUrlInputRef}
              type="text"
              value={newSubSource}
              onPaste={(e) => {
                const pasted = e.clipboardData?.getData("text/plain") ?? "";
                if (/[\r\n]/.test(pasted) && containsSingleNodeShareUriLine(pasted)) {
                  e.preventDefault();
                  const lines = pasted
                    .split(/\r?\n/)
                    .map((line) => line.trim())
                    .filter((line) => line.length > 0);
                  const firstUriLine =
                    lines.find(
                      (line) => !line.startsWith("#") && SINGLE_NODE_URI_RE.test(line)
                    ) ??
                    lines[0] ??
                    "";
                  setPastedMultilineNodes(pasted);
                  setNewSubSource(firstUriLine);
                  return;
                }
                setPastedMultilineNodes(null);
              }}
              onChange={(e) => {
                const rawVal = e.target.value;
                setPastedMultilineNodes(null);
                const clashInstall = parseClashInstallConfigUrl(rawVal);
                if (clashInstall) {
                  setNewSubSource(clashInstall.url);
                  if (!newSubName.trim() && clashInstall.name) {
                    setNewSubName(clashInstall.name);
                  }
                  appActions.showToast("已自动识别一键订阅链接并提取订阅地址", "info");
                } else {
                  setNewSubSource(rawVal);
                }
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  void submitSubscriptionSource("url", newSubSource, newSubName);
                }
              }}
              placeholder="粘贴 https:// 订阅链接或 clash:// 一键订阅链接..."
              className="w-full rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2 cc-mono text-xs text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none"
            />

            {isSingleNodeUrlInput && (
              <div className="space-y-1.5 rounded-xl border border-[var(--amber)]/50 bg-[var(--amber-soft)]/60 px-3 py-2 text-[11px] text-[var(--amber)]">
                <div className="leading-relaxed">
                  {pastedMultilineNodes && pastedMultilineNodeCount > 1
                    ? `检测到粘贴了 ${pastedMultilineNodeCount} 条单节点分享链接（已完整保留换行），可以直接用「粘贴配置文本」一次性导入：`
                    : "检测到这是单个节点分享链接（而非订阅网址），可以直接用「粘贴配置文本」导入："}
                </div>
                <button
                  type="button"
                  onClick={() =>
                    openMigrationWithPaste(pastedMultilineNodes ?? newSubSource)
                  }
                  className="inline-flex items-center gap-1 rounded-lg bg-[var(--accent)] px-2.5 py-1 text-[11px] font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90"
                >
                  <span>转到「粘贴配置文本」导入</span>
                  <ArrowRight className="h-3 w-3" />
                </button>
              </div>
            )}
          </div>

          <div className="flex items-center gap-2">
            <input
              type="text"
              value={newSubName}
              onChange={(e) => setNewSubName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  void submitSubscriptionSource("url", newSubSource, newSubName);
                }
              }}
              placeholder="名称（可选，留空自动命名）"
              className="min-w-0 flex-1 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-2 text-xs text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none"
            />
            <button
              type="button"
              disabled={importingSub}
              onClick={() =>
                void submitSubscriptionSource("url", newSubSource, newSubName)
              }
              className="inline-flex shrink-0 items-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:opacity-50"
            >
              {importingSub ? (
                <RefreshCw className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Check className="h-3.5 w-3.5" />
              )}
              {importingSub ? "导入中..." : "一键导入"}
            </button>
          </div>
        </div>

        {/* Card 2: Import from Existing VPN Client */}
        <div className="cc-card cc-glass flex min-w-0 flex-col justify-between gap-3 rounded-2xl p-4">
          <div className="space-y-2">
            <div className="flex min-w-0 items-center gap-2.5">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[var(--green-soft)] text-[var(--green)]">
                <FolderOpen className="h-4 w-4" />
              </div>
              <div className="flex min-w-0 flex-1 items-center gap-1.5">
                <span className="inline-flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-[var(--green)] text-[10px] font-bold text-[var(--accent-ink)]">
                  2
                </span>
                <h2 className="min-w-0 truncate text-sm font-semibold text-[var(--text)]">
                  从电脑已有梯子导入
                </h2>
              </div>
            </div>
            <p className="text-xs leading-relaxed text-[var(--text-secondary)]">
              自动找 Clash Verge / FlClash / v2rayN 等其他代理客户端已有配置，或直接粘贴配置文本 / 单节点链接，只读安全复制。
            </p>
          </div>

          <button
            type="button"
            onClick={openMigrationScan}
            className="inline-flex w-full items-center justify-center gap-1.5 rounded-xl border border-[var(--green)]/50 bg-[var(--green-soft)] px-4 py-2 text-xs font-semibold text-[var(--green)] transition-opacity hover:opacity-90"
          >
            <Search className="h-3.5 w-3.5" />
            自动扫描并导入
          </button>
        </div>

        {/* Card 3: Capture Nodes from Running Software */}
        <div
          className={`cc-card cc-glass flex min-w-0 flex-col justify-between gap-3 rounded-2xl p-4 ${
            bgCapture.active || bgCapture.finishing || bgCapture.outcome
              ? "border-[var(--green)]/60 ring-1 ring-[var(--green)]/25"
              : isCapturePaused
                ? "border-[var(--amber)]/60 ring-1 ring-[var(--amber)]/25"
                : ""
          }`}
        >
          <div className="space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex min-w-0 flex-1 items-center gap-2.5">
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[var(--sky-soft)] text-[var(--sky)]">
                  <Cpu className="h-4 w-4" />
                </div>
                <div className="flex min-w-0 flex-1 items-center gap-1.5">
                  <span className="inline-flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-[var(--sky)] text-[10px] font-bold text-[var(--accent-ink)]">
                    3
                  </span>
                  <h2 className="min-w-0 truncate text-sm font-semibold text-[var(--text)]">
                    从正在运行的软件抓节点
                  </h2>
                </div>
              </div>
              {bgCapture.finishing ? (
                <span className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-full bg-[var(--amber-soft)] px-2 py-0.5 text-[10px] font-semibold text-[var(--amber)]">
                  <RefreshCw className="h-2.5 w-2.5 shrink-0 animate-spin" />
                  整理中
                </span>
              ) : bgCapture.outcome ? (
                <span className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-full bg-[var(--green-soft)] px-2 py-0.5 text-[10px] font-semibold text-[var(--green)]">
                  <CheckCircle2 className="h-2.5 w-2.5 shrink-0" />
                  待确认导入
                </span>
              ) : isCapturePaused ? (
                <span className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-full bg-[var(--amber-soft)] px-2 py-0.5 text-[10px] font-semibold text-[var(--amber)]">
                  <Clock className="h-2.5 w-2.5 shrink-0" />
                  已暂停
                </span>
              ) : bgCapture.active ? (
                <span className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-full bg-[var(--green-soft)] px-2 py-0.5 text-[10px] font-semibold text-[var(--green)]">
                  <span className="cc-pulse-dot h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--green)]" />
                  捕捉中
                </span>
              ) : null}
            </div>
            {bgCapture.finishing ? (
              <p className="text-xs leading-relaxed text-[var(--text-secondary)]">
                正在整理{" "}
                <strong className="font-semibold text-[var(--text)]">
                  {bgCapture.status?.target_name || bgCapture.targetName || "目标软件"}
                </strong>{" "}
                的捕捉结果，完成后即可一键确认导入节点。
              </p>
            ) : bgCapture.outcome ? (
              <p className="text-xs leading-relaxed text-[var(--text-secondary)]">
                已从{" "}
                <strong className="font-semibold text-[var(--text)]">
                  {bgCapture.outcome.target_name || bgCapture.targetName || "目标软件"}
                </strong>{" "}
                整理完成
                {bgCapture.outcome.supported && bgCapture.outcome.nodes.length > 0 ? (
                  <>
                    ，共捕捉{" "}
                    <strong className="cc-mono text-[var(--green)]">
                      {bgCapture.outcome.nodes.length}
                    </strong>{" "}
                    个可用节点，点击下方继续确认导入。
                  </>
                ) : (
                  "，点击下方查看结果详情。"
                )}
              </p>
            ) : isCapturePaused ? (
              <p className="text-xs leading-relaxed text-[var(--text-secondary)]">
                对{" "}
                <strong className="font-semibold text-[var(--text)]">
                  {bgCapture.status?.target_name || bgCapture.targetName || "目标软件"}
                </strong>{" "}
                的捕捉已达 3 分钟上限并自动暂停
                {(bgCapture.status?.captured_node_count ?? 0) > 0 ? (
                  <>
                    ，已保留{" "}
                    <strong className="cc-mono text-[var(--green)]">
                      {bgCapture.status!.captured_node_count}
                    </strong>{" "}
                    个已抓到的节点，点击下方整理查看。
                  </>
                ) : (
                  "，点击下方查看已捕捉内容或重新开始。"
                )}
              </p>
            ) : bgCapture.active ? (
              <p className="text-xs leading-relaxed text-[var(--text-secondary)]">
                正在后台实时监控{" "}
                <strong className="font-semibold text-[var(--text)]">
                  {bgCapture.status?.target_name || bgCapture.targetName || "目标软件"}
                </strong>
                （已监控 {bgCapture.status?.elapsed_sec ?? 0} 秒 · 已抢读{" "}
                <strong className="cc-mono text-[var(--green)]">
                  {bgCapture.status?.captured_node_count ?? 0}
                </strong>{" "}
                个节点），点击下方随时返回整理导入。
              </p>
            ) : (
              <p className="text-xs leading-relaxed text-[var(--text-secondary)]">
                按 1→2→3 实时捕捉向导，选定已打开或新启动的专用软件，点击更新订阅即可自动提取可用节点。
              </p>
            )}
          </div>

          <button
            type="button"
            onClick={() => setProcessAttachOpen(true)}
            className={`inline-flex w-full items-center justify-center gap-1.5 rounded-xl border px-4 py-2 text-xs font-semibold transition-opacity hover:opacity-90 ${
              bgCapture.active || bgCapture.finishing || bgCapture.outcome
                ? "border-[var(--green)]/55 bg-[var(--green-soft)] text-[var(--green)]"
                : isCapturePaused
                  ? "border-[var(--amber)]/55 bg-[var(--amber-soft)] text-[var(--amber)]"
                  : "border-[var(--sky)]/50 bg-[var(--sky-soft)] text-[var(--sky)]"
            }`}
          >
            {bgCapture.active || bgCapture.finishing ? (
              <RefreshCw className="h-3.5 w-3.5 animate-spin" />
            ) : bgCapture.outcome ? (
              <CheckCircle2 className="h-3.5 w-3.5" />
            ) : isCapturePaused ? (
              <Clock className="h-3.5 w-3.5" />
            ) : (
              <Cpu className="h-3.5 w-3.5" />
            )}
            {bgCapture.finishing
              ? "正在整理捕捉结果…"
              : bgCapture.outcome
                ? bgCapture.outcome.supported && bgCapture.outcome.nodes.length > 0
                  ? `继续确认导入（已抓 ${bgCapture.outcome.nodes.length} 个节点）`
                  : "查看捕捉结果"
                : isCapturePaused
                  ? `捕捉已暂停 · 点击查看已抓到的内容${
                      (bgCapture.status?.captured_node_count ?? 0) > 0
                        ? `（${bgCapture.status!.captured_node_count}）`
                        : ""
                    }`
                  : bgCapture.active
                    ? `继续查看实时捕捉进度${
                        (bgCapture.status?.captured_node_count ?? 0) > 0
                          ? `（已抓 ${bgCapture.status!.captured_node_count}）`
                          : ""
                      }`
                    : "打开 1→2→3 实时捕捉向导"}
          </button>
        </div>
      </section>

      {/* Optional Collapsible Local File Import Form */}
      {showLocalFileForm && (
        <section className="cc-card cc-glass space-y-3 rounded-2xl border-[var(--accent)]/50 p-4">
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs font-semibold text-[var(--text)]">
              导入电脑里的本地配置文件（只读）
            </span>
            <button
              type="button"
              onClick={() => setShowLocalFileForm(false)}
              className="text-xs text-[var(--muted)] hover:text-[var(--text)]"
            >
              收起
            </button>
          </div>

          <div className="grid grid-cols-1 gap-3 md:grid-cols-12">
            <label className="text-[11px] text-[var(--muted)] md:col-span-4">
              名称（可选）
              <input
                type="text"
                value={localFileName}
                onChange={(e) => setLocalFileName(e.target.value)}
                placeholder="例如：我的本地节点"
                className="mt-1 w-full rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none"
              />
            </label>

            <label className="text-[11px] text-[var(--muted)] md:col-span-8">
              本地配置文件路径
              <input
                type="text"
                value={localFilePath}
                onChange={(e) => setLocalFilePath(e.target.value)}
                placeholder="例如：data/subs/my-nodes.yaml"
                className="mt-1 w-full rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3 py-1.5 cc-mono text-xs text-[var(--text)] placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:outline-none"
              />
            </label>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2 pt-0.5 text-[11px] text-[var(--muted)]">
            <span>
              本地文件更新后可随时在下方订阅卡片点击「刷新」同步最新节点；若文件暂时读不到或内容为空，会自动保留原有节点不会丢失。
            </span>
            <button
              type="button"
              disabled={importingSub}
              onClick={() =>
                void submitSubscriptionSource("file", localFilePath, localFileName)
              }
              className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-4 py-1.5 text-xs font-semibold text-[var(--accent-ink)] hover:opacity-90 disabled:opacity-50"
            >
              <Check className="h-3.5 w-3.5" />
              保存并读取节点
            </button>
          </div>
        </section>
      )}

      {/* ====================================================================
       * 2. Adaptive Subscription Cards Grid
       * ==================================================================== */}
      <SubscriptionCardsSection
        subscriptions={subscriptions}
        nodes={nodes}
        subNodeCountMap={subNodeCountMap}
        inTauri={inTauri}
        refreshingAll={refreshingAll}
        refreshingIdSet={refreshingIdSet}
        renamingSubId={renamingSubId}
        renamingSubName={renamingSubName}
        renamingBusy={renamingBusy}
        dict={dict}
        onOpenShareImport={openShareImport}
        onOpenShareExport={openShareExport}
        onOpenMergeModal={openMergeModal}
        onRefreshAll={() => void refreshAllSubscriptions()}
        onRefreshSingle={(sub, simulateFault) =>
          void refreshSingleSubscription(sub, simulateFault)
        }
        onStartRename={handleStartRenameSub}
        onChangeRenamingName={setRenamingSubName}
        onSubmitRename={(sub) => void handleSubmitRenameSub(sub)}
        onCancelRename={handleCancelRenameSub}
        onRequestDelete={setPendingDeleteSub}
        onViewSubNodes={onViewSubNodes}
      />

      {/* ====================================================================
       * 3. Lazy-Loaded Slide-Over Drawers & Modals
       * ==================================================================== */}
      {migrationOpen && (
        <Suspense fallback={null}>
          <LazyMigrationDrawer
            open={migrationOpen}
            initialTab={migrationInitialTab}
            initialPasteText={migrationInitialPaste}
            onClose={closeMigration}
            onImport={handleMigrationImport}
          />
        </Suspense>
      )}

      {processAttachOpen && (
        <Suspense fallback={null}>
          <LazyProcessAttachDrawer
            open={processAttachOpen}
            onClose={closeProcessAttach}
            onConfirmCapture={handleLiveCaptureImport}
            onGoToSubUrl={handleFocusSubUrlInput}
          />
        </Suspense>
      )}

      {shareModalState.open && (
        <Suspense fallback={null}>
          <LazyShareBundleModal
            open={shareModalState.open}
            mode={shareModalState.mode}
            defaultTab={shareModalState.defaultTab}
            initialNodeIds={shareModalState.initialNodeIds}
            defaultPackName={shareModalState.defaultPackName}
            initialTransport={shareModalState.initialTransport}
            allowModeSwitch
            onClose={() =>
              setShareModalState((prev) => ({
                ...prev,
                open: false,
              }))
            }
          />
        </Suspense>
      )}

      <MergeSubscriptionsModal
        open={mergeModalOpen}
        title={dict.nodes.mergeSubsTitle}
        subscriptions={subscriptions}
        subNodeCountMap={subNodeCountMap}
        sourceSubId={mergeSourceSubId}
        targetSubId={mergeTargetSubId}
        newName={mergeNewName}
        dedup={mergeDedup}
        busy={mergingSubs}
        error={mergeError}
        onChangeSource={handleChangeMergeSource}
        onChangeTarget={handleChangeMergeTarget}
        onChangeNewName={setMergeNewName}
        onChangeDedup={setMergeDedup}
        onClose={closeMergeModal}
        onConfirm={handleConfirmMergeSubs}
      />

      <DeleteSubscriptionModal
        sub={pendingDeleteSub}
        nodeCount={pendingDeleteSub ? (subNodeCountMap.get(pendingDeleteSub.id) ?? 0) : 0}
        deleting={deletingSub}
        onClose={closeDeleteModal}
        onConfirm={handleConfirmRemoveSubscription}
      />
    </div>
  );
}
