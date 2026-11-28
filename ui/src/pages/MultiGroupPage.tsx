import {
  AlertTriangle,
  ArrowLeft,
  Loader2,
  Pencil,
  Play,
  Settings2,
  Zap,
} from "lucide-react";
import { type FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  type GroupEvaluationReport,
  type MultiGroup,
  type ProbeSnapshot,
  type ProxyNode,
  catcloudApi,
  formatErrorMessage,
  isTauriEnv,
} from "../api/tauri";
import { PaginationBar } from "../components/ContinentRegionFilter";
import { formatI18nTemplate, normalizeUiLanguage, useUiDict } from "../i18n";
import {
  appActions,
  appStore,
  selectIsProbeEngineBusy,
  useAppSelector,
} from "../store/appStore";
import { hasVerifiedAiUnlock } from "../utils/aiUnlockDisplay";
import {
  GEMINI_GATE_EXPR,
  HARD_GATE_PRESETS,
  LEGACY_GEMINI_GATE_EXPR,
  assessNodeAgainstGates,
  evaluateFormulaSafely,
} from "../utils/formulaEvaluator";
import {
  MISSING_LATENCY_PENALTY_MS,
  hasValidDownMbps,
  hasValidUpMbps,
  resolveNodeDisplayLatency,
} from "../utils/latencyDisplay";
import { INVALID_MATCH_RULE_MSG, parseUserMatchRules } from "../utils/mihomoRuleParser";
import {
  type ContinentId,
  buildContinentRegionStats,
  getRegionLabel,
  nodeMatchesContinentAndRegion,
  resolveNodeRegionCode,
} from "../utils/regions";
import { formatGroupDisplayName } from "../utils/releaseUrl";
import { isBoolPref, oneOfPref, usePersistedState } from "../utils/uiPrefs";
import {
  GroupConfigDrawer,
  type TriggerMeta,
  formatDynamicFilter,
  getPrimaryTriggerExpr,
  getPrimaryTriggerMeta,
  normalizeGroupForBackend,
  parseUploadTriggerInfo,
} from "./multi-group/GroupConfigDrawer";
import {
  GroupFilterBar,
  type NodeSortMode,
  type NodeViewMode,
} from "./multi-group/GroupFilterBar";
import { GroupNodeCard } from "./multi-group/GroupNodeCard";
import { GroupSidebarList } from "./multi-group/GroupSidebarList";

const NODE_PAGE_SIZE_OPTIONS = [24, 48, 96] as const;

interface MultiGroupDraftCache {
  dirtyGroupIds: Record<string, boolean>;
  draftGroupsById: Record<string, MultiGroup>;
  triggerMetas: Record<string, TriggerMeta>;
}

let multiGroupDraftCache: MultiGroupDraftCache = {
  dirtyGroupIds: {},
  draftGroupsById: {},
  triggerMetas: {},
};

const isStringPref = (raw: unknown): string | undefined =>
  typeof raw === "string" ? raw : undefined;

const MULTIGROUP_CONTINENT_VALIDATOR = oneOfPref([
  "all",
  "common",
  "asia",
  "middle_east",
  "europe",
  "north_america",
  "south_america",
  "oceania",
  "africa",
  "other",
] as const);

export function MultiGroupPage() {
  const storeGroups = useAppSelector((s) => s.groups);
  const uiLang = useAppSelector((s) =>
    normalizeUiLanguage(s.config.personalization.ui_language)
  );
  const dict = useUiDict(uiLang);
  const nodes = useAppSelector((s) => s.nodes);
  const probes = useAppSelector((s) => s.probes);
  const subscriptions = useAppSelector((s) => s.subscriptions);
  const runtimeRouteMode = useAppSelector((s) => s.runtime.route_mode);
  const runtimeActiveGroupId = useAppSelector((s) => s.runtime.active_group_id);
  const runtimeActiveNodeId = useAppSelector((s) => s.runtime.active_node_id);
  const runtimeActiveNodeName = useAppSelector((s) => s.runtime.active_node_name);
  const runtimeNodeHealthHints = useAppSelector((s) => s.runtime.node_health_hints);
  const isGroupMode = runtimeRouteMode !== "single";
  const initialized = useAppSelector((s) => s.initialized);
  const probingNodeIds = useAppSelector((s) => s.bgTasks.groups.probingNodeIds);
  const evaluatingGroupId = useAppSelector((s) => s.bgTasks.groups.evaluatingGroupId);
  const evalReports = useAppSelector((s) => s.bgTasks.groups.evalReports);
  const isProbeEngineBusy = useAppSelector(selectIsProbeEngineBusy);
  const benchmarkRunning = useAppSelector((s) => s.bgTasks.preaccel.benchmark.running);
  const savedDraftSelectedId = useAppSelector((s) => s.sessionDrafts.multiGroup.selectedId);
  const inTauri = isTauriEnv();

  // Local group drafts (keeps unsaved strategy edits per group while syncing live active_node_id & members)
  const [groups, setGroups] = useState<MultiGroup[]>(() =>
    storeGroups.map((sg) => {
      if (multiGroupDraftCache.dirtyGroupIds[sg.id] && multiGroupDraftCache.draftGroupsById[sg.id]) {
        return {
          ...multiGroupDraftCache.draftGroupsById[sg.id],
          member_node_ids: sg.member_node_ids,
          active_node_id: sg.active_node_id,
        };
      }
      return sg;
    })
  );
  const [selectedId, setSelectedId] = useState<string>(
    () => savedDraftSelectedId || runtimeActiveGroupId || storeGroups[0]?.id || ""
  );
  const [triggerMetas, setTriggerMetas] = useState<Record<string, TriggerMeta>>(() => ({
    ...multiGroupDraftCache.triggerMetas,
  }));
  const [dirtyGroupIds, setDirtyGroupIds] = useState<Record<string, boolean>>(() => ({
    ...multiGroupDraftCache.dirtyGroupIds,
  }));

  // Center pane: inline rename, filters (persisted across tab switches & reloads), pagination, batch clear confirm, single-node actions
  const [editingName, setEditingName] = useState(false);
  const [nameDraft, setNameDraft] = useState("");
  const [selectedSubId, setSelectedSubId] = usePersistedState<string>(
    "multigroup.selectedSubId",
    "all",
    isStringPref
  );
  const [filterContinent, setFilterContinent] = usePersistedState<ContinentId>(
    "multigroup.filterContinent",
    "all",
    MULTIGROUP_CONTINENT_VALIDATOR
  );
  const [filterRegion, setFilterRegion] = usePersistedState<string>(
    "multigroup.filterRegion",
    "all",
    isStringPref
  );
  const [searchQuery, setSearchQuery] = usePersistedState<string>(
    "multigroup.searchQuery",
    "",
    isStringPref
  );
  const [viewMode, setViewMode] = usePersistedState<NodeViewMode>(
    "multigroup.viewMode",
    "all",
    oneOfPref(["all", "members"] as const)
  );
  const [sortMode, setSortMode] = usePersistedState<NodeSortMode>(
    "multigroup.sortMode",
    "default",
    oneOfPref(["default", "up_desc", "down_desc", "latency_asc"] as const)
  );
  const [filterGoogleClean, setFilterGoogleClean] = usePersistedState<boolean>(
    "multigroup.filterGoogleClean",
    false,
    isBoolPref
  );
  const [filterAiReady, setFilterAiReady] = usePersistedState<boolean>(
    "multigroup.filterAiReady",
    false,
    isBoolPref
  );
  const [moreFiltersOpen, setMoreFiltersOpen] = usePersistedState<boolean>(
    "multigroup.moreFiltersOpen",
    false,
    isBoolPref
  );
  const [nodePage, setNodePage] = useState(1);
  const [nodePageSize, setNodePageSize] = usePersistedState<number>(
    "multigroup.pageSize",
    24,
    oneOfPref(NODE_PAGE_SIZE_OPTIONS)
  );
  const [confirmClearMembers, setConfirmClearMembers] = useState(false);
  const [switchingNext, setSwitchingNext] = useState(false);
  const [selectingNodeId, setSelectingNodeId] = useState<string | null>(null);

  // Right strategy drawer: collapsed by default so node grid gets huge breathing room
  const [drawerOpen, setDrawerOpen] = usePersistedState<boolean>(
    "multigroup.drawerOpen",
    false,
    isBoolPref
  );
  const [isWideDesktop, setIsWideDesktop] = useState<boolean>(() =>
    typeof window !== "undefined" ? window.innerWidth >= 1280 : true
  );
  const [advancedOpen, setAdvancedOpen] = usePersistedState<boolean>(
    "multigroup.advancedOpen",
    false,
    isBoolPref
  );
  const [savingGroup, setSavingGroup] = useState(false);
  const [newRuleInput, setNewRuleInput] = useState("");
  const [customGateInput, setCustomGateInput] = useState("");
  const [backendFormulaValidation, setBackendFormulaValidation] = useState<{
    checkedExpr: string;
    ok: boolean;
    error: string | null;
  } | null>(null);

  const probingNodeIdSet = useMemo(() => new Set(probingNodeIds), [probingNodeIds]);

  // Stable order snapshot so clicking node cards in "all" view toggles colors in-place without jumping!
  const [pinnedOrder, setPinnedOrder] = useState<{
    groupId: string;
    activeId: string | null;
    memberIds: Set<string>;
  }>({
    groupId: "",
    activeId: null,
    memberIds: new Set<string>(),
  });

  const dirtyGroupIdsRef = useRef(dirtyGroupIds);
  dirtyGroupIdsRef.current = dirtyGroupIds;
  const latestMembersRef = useRef<Record<string, string[]>>({});
  const memberReqSeqRef = useRef<Record<string, number>>({});
  const clearConfirmTimerRef = useRef<number | null>(null);
  const section5Ref = useRef<HTMLDivElement | null>(null);
  const pendingScrollSection5Ref = useRef(false);

  const handleOpenIndepSection = () => {
    pendingScrollSection5Ref.current = true;
    if (drawerOpen) {
      window.requestAnimationFrame(() => {
        section5Ref.current?.scrollIntoView({ behavior: "smooth", block: "start" });
        pendingScrollSection5Ref.current = false;
      });
    } else {
      setDrawerOpen(true);
    }
  };

  useEffect(() => {
    if (drawerOpen && pendingScrollSection5Ref.current) {
      pendingScrollSection5Ref.current = false;
      const tid = window.setTimeout(() => {
        section5Ref.current?.scrollIntoView({ behavior: "smooth", block: "start" });
      }, 60);
      return () => window.clearTimeout(tid);
    }
  }, [drawerOpen]);

  useEffect(() => {
    if (savedDraftSelectedId && storeGroups.some((g) => g.id === savedDraftSelectedId)) {
      setSelectedId((prev) => (prev === savedDraftSelectedId ? prev : savedDraftSelectedId));
    }
  }, [savedDraftSelectedId, storeGroups]);

  useEffect(() => {
    return () => {
      if (clearConfirmTimerRef.current !== null) window.clearTimeout(clearConfirmTimerRef.current);
    };
  }, []);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const mq = window.matchMedia("(min-width: 1280px)");
    const sync = () => setIsWideDesktop(mq.matches);
    sync();
    mq.addEventListener("change", sync);
    return () => mq.removeEventListener("change", sync);
  }, []);

  useEffect(() => {
    if (isWideDesktop || !drawerOpen) return;
    const onKeyDown = (ev: globalThis.KeyboardEvent) => {
      if (ev.key === "Escape") {
        ev.preventDefault();
        setDrawerOpen(false);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [drawerOpen, isWideDesktop, setDrawerOpen]);

  // Sync store groups smoothly without wiping unsaved strategy drafts
  useEffect(() => {
    if (!initialized && storeGroups.length === 0) return;
    const validGroupIds = new Set(storeGroups.map((g) => g.id));
    for (const key of Object.keys(latestMembersRef.current)) {
      if (!validGroupIds.has(key)) {
        delete latestMembersRef.current[key];
      }
    }
    for (const sg of storeGroups) {
      latestMembersRef.current[sg.id] = sg.member_node_ids;
    }
    setGroups((prev) => {
      const prevById = new Map(prev.map((g) => [g.id, g]));
      return storeGroups.map((sg) => {
        const local = prevById.get(sg.id) ?? multiGroupDraftCache.draftGroupsById[sg.id];
        if (local && dirtyGroupIdsRef.current[sg.id]) {
          return {
            ...local,
            name: sg.name,
            member_node_ids: sg.member_node_ids,
            active_node_id: sg.active_node_id,
          };
        }
        return sg;
      });
    });
    setSelectedId((prev) => {
      if (prev && storeGroups.some((g) => g.id === prev)) return prev;
      if (runtimeActiveGroupId && storeGroups.some((g) => g.id === runtimeActiveGroupId)) {
        return runtimeActiveGroupId;
      }
      return storeGroups[0]?.id ?? "";
    });
    setDirtyGroupIds((prev) => {
      const validIds = new Set(storeGroups.map((g) => g.id));
      let changed = false;
      const next: Record<string, boolean> = {};
      for (const [id, isDirty] of Object.entries(prev)) {
        if (isDirty && validIds.has(id)) {
          next[id] = true;
        } else if (isDirty) {
          changed = true;
        }
      }
      return changed ? next : prev;
    });
  }, [storeGroups, initialized, runtimeActiveGroupId]);

  useEffect(() => {
    if (selectedId && selectedId !== appStore.getState().sessionDrafts.multiGroup.selectedId) {
      appActions.patchSessionDraft("multiGroup", { selectedId });
    }
  }, [selectedId]);

  const hasDirtyDrafts = useMemo(
    () => Object.values(dirtyGroupIds).some(Boolean),
    [dirtyGroupIds]
  );

  useEffect(() => {
    const dirtyIds: Record<string, boolean> = {};
    const draftGroupsById: Record<string, MultiGroup> = {};
    const nextTriggerMetas: Record<string, TriggerMeta> = {};
    for (const g of groups) {
      if (dirtyGroupIds[g.id]) {
        dirtyIds[g.id] = true;
        draftGroupsById[g.id] = g;
        if (triggerMetas[g.id]) {
          nextTriggerMetas[g.id] = triggerMetas[g.id];
        }
      }
    }
    multiGroupDraftCache = {
      dirtyGroupIds: dirtyIds,
      draftGroupsById,
      triggerMetas: nextTriggerMetas,
    };
    if (hasDirtyDrafts !== appStore.getState().sessionDrafts.multiGroup.hasDirtyDrafts) {
      appActions.patchSessionDraft("multiGroup", { hasDirtyDrafts });
    }
  }, [groups, dirtyGroupIds, triggerMetas, hasDirtyDrafts]);

  const selectedGroup = useMemo(
    () => groups.find((g) => g.id === selectedId) ?? groups[0] ?? null,
    [groups, selectedId]
  );
  const selectedGroupId = selectedGroup?.id ?? null;
  const evaluating = Boolean(selectedGroup && evaluatingGroupId === selectedGroup.id);
  const anyEvaluating = evaluatingGroupId !== null;
  const evalReport: GroupEvaluationReport | null = selectedGroup
    ? (evalReports[selectedGroup.id] ?? null)
    : null;

  // Refresh pinned display ordering when switching groups or changing view/filters
  useEffect(() => {
    if (!selectedGroup) return;
    setPinnedOrder({
      groupId: selectedGroup.id,
      activeId: selectedGroup.active_node_id,
      memberIds: new Set(selectedGroup.member_node_ids),
    });
    setEditingName(false);
    setConfirmClearMembers(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedGroup?.id, viewMode]);

  useEffect(() => {
    setNodePage(1);
  }, [
    selectedGroupId,
    viewMode,
    searchQuery,
    selectedSubId,
    filterContinent,
    filterRegion,
    sortMode,
    filterGoogleClean,
    filterAiReady,
  ]);

  // Debounced backend authoritative formula validation in Tauri runtime (only when advanced panel is open)
  const currentFormulaExpr = selectedGroup?.formula_expr ?? "";
  useEffect(() => {
    if (!inTauri || !selectedGroup || !advancedOpen) {
      setBackendFormulaValidation(null);
      return;
    }
    const expr = currentFormulaExpr.trim();
    if (!expr) {
      setBackendFormulaValidation({
        checkedExpr: currentFormulaExpr,
        ok: false,
        error: "公式不能为空",
      });
      return;
    }
    let cancelled = false;
    const timer = window.setTimeout(() => {
      void catcloudApi
        .validateFormulaExpr(expr)
        .then((ok) => {
          if (!cancelled) {
            setBackendFormulaValidation({
              checkedExpr: currentFormulaExpr,
              ok,
              error: ok ? null : "后端公式校验未通过",
            });
          }
        })
        .catch((err) => {
          if (!cancelled) {
            setBackendFormulaValidation({
              checkedExpr: currentFormulaExpr,
              ok: false,
              error: formatErrorMessage(err),
            });
          }
        });
    }, 280);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [currentFormulaExpr, inTauri, selectedGroup?.id, advancedOpen]);

  // Fast lookup maps for 430+ nodes (zero O(N^2) loops)
  const nodeById = useMemo(() => {
    const map = new Map<string, ProxyNode>();
    for (const n of nodes) map.set(n.id, n);
    return map;
  }, [nodes]);

  const subNameById = useMemo(() => {
    const map = new Map<string, string>();
    for (const s of subscriptions) map.set(s.id, s.name);
    return map;
  }, [subscriptions]);

  const providerTabs = useMemo(() => {
    const counts = new Map<string, number>();
    for (const n of nodes) {
      if (!n.enabled) continue;
      const sid = n.sub_id || "__unknown__";
      counts.set(sid, (counts.get(sid) ?? 0) + 1);
    }
    const items: Array<{ id: string; name: string; count: number }> = [];
    const seen = new Set<string>();
    for (const sub of subscriptions) {
      const cnt = counts.get(sub.id) ?? 0;
      if (cnt > 0) {
        items.push({ id: sub.id, name: sub.name, count: cnt });
        seen.add(sub.id);
      }
    }
    for (const [sid, cnt] of counts.entries()) {
      if (!seen.has(sid)) {
        items.push({
          id: sid,
          name: sid === "__unknown__" ? "其他来源" : sid,
          count: cnt,
        });
      }
    }
    return items;
  }, [nodes, subscriptions]);

  const enabledNodes = useMemo(() => nodes.filter((n) => n.enabled), [nodes]);

  const subScopedNodes = useMemo(() => {
    if (selectedSubId === "all") return enabledNodes;
    return enabledNodes.filter((n) => (n.sub_id || "__unknown__") === selectedSubId);
  }, [enabledNodes, selectedSubId]);

  const regionStats = useMemo(
    () => buildContinentRegionStats(subScopedNodes),
    [subScopedNodes]
  );

  useEffect(() => {
    if (!initialized || selectedSubId === "all") return;
    if (!providerTabs.some((sub) => sub.id === selectedSubId)) {
      setSelectedSubId("all");
    }
  }, [initialized, selectedSubId, providerTabs, setSelectedSubId]);

  useEffect(() => {
    if (filterContinent !== "all" && regionStats.continentCounts[filterContinent] === 0) {
      setFilterContinent("all");
    }
    if (
      filterRegion !== "all" &&
      !regionStats.allRegions.some((r) => r.code === filterRegion)
    ) {
      setFilterRegion("all");
    }
  }, [regionStats, filterContinent, filterRegion, setFilterContinent, setFilterRegion]);

  const effectiveSelectedMemberIds = useMemo(() => {
    if (!selectedGroup) return [] as string[];
    return selectedGroup.member_node_ids.filter((id) => nodeById.has(id));
  }, [selectedGroup, nodeById]);

  const memberIdSet = useMemo(
    () => new Set(effectiveSelectedMemberIds),
    [effectiveSelectedMemberIds]
  );

  const moreFilterActiveCount =
    (selectedSubId !== "all" ? 1 : 0) +
    (filterContinent !== "all" || filterRegion !== "all" ? 1 : 0) +
    (sortMode !== "default" ? 1 : 0);

  const hasAnyActiveFilter =
    Boolean(searchQuery) ||
    selectedSubId !== "all" ||
    filterContinent !== "all" ||
    filterRegion !== "all" ||
    filterGoogleClean ||
    filterAiReady ||
    sortMode !== "default";

  const handleResetFilters = () => {
    setSearchQuery("");
    setSelectedSubId("all");
    setFilterContinent("all");
    setFilterRegion("all");
    setFilterGoogleClean(false);
    setFilterAiReady(false);
    setSortMode("default");
    setNodePage(1);
  };

  // Only bind live probe/member/active dependencies when needed
  const memberFilterSet = viewMode === "members" ? memberIdSet : null;
  const memberActiveId =
    viewMode === "members" ? (selectedGroup?.active_node_id ?? null) : null;
  const needsLiveProbes =
    viewMode === "members" || sortMode !== "default" || filterGoogleClean || filterAiReady;
  const activeFilterProbes = needsLiveProbes ? probes : null;

  const filteredNodes = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    const list = enabledNodes.filter((node) => {
      if (memberFilterSet && !memberFilterSet.has(node.id)) return false;
      if (selectedSubId !== "all" && (node.sub_id || "__unknown__") !== selectedSubId) return false;
      if (!nodeMatchesContinentAndRegion(node, filterContinent, filterRegion)) {
        return false;
      }
      if (filterGoogleClean && activeFilterProbes?.[node.id]?.google_clean !== true) {
        return false;
      }
      if (filterAiReady && !hasVerifiedAiUnlock(activeFilterProbes?.[node.id])) {
        return false;
      }
      if (q) {
        const subName = (subNameById.get(node.sub_id) ?? "").toLowerCase();
        const resolvedCode = resolveNodeRegionCode(node);
        const regionCn = getRegionLabel(resolvedCode).toLowerCase();
        const hay =
          `${node.name} ${node.region_code} ${resolvedCode} ${regionCn} ${node.protocol} ${subName}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    const usePinned = pinnedOrder.groupId === selectedGroupId;
    const pinnedActive = usePinned ? pinnedOrder.activeId : null;
    const pinnedMembers = usePinned ? pinnedOrder.memberIds : null;

    const healthHints = runtimeNodeHealthHints;
    const getMetricRank = (
      nodeId: string,
      snap: ProbeSnapshot | undefined
    ): { tier: number; primary: number; secondary: number } => {
      const resolved = resolveNodeDisplayLatency(snap, healthHints?.[nodeId]);
      if (resolved.state === "untested" && !snap) {
        return { tier: 2, primary: 0, secondary: MISSING_LATENCY_PENALTY_MS };
      }
      if (resolved.state === "failed") {
        return { tier: 3, primary: 0, secondary: MISSING_LATENCY_PENALTY_MS };
      }
      const lat = resolved.latencyMs ?? MISSING_LATENCY_PENALTY_MS;
      const validUp = hasValidUpMbps(snap) ? snap!.up_mbps! : null;
      const validDown = hasValidDownMbps(snap) ? snap!.down_mbps! : null;
      if (sortMode === "up_desc") {
        if (validUp !== null) {
          return { tier: 0, primary: -validUp, secondary: lat };
        }
        return { tier: 1, primary: lat, secondary: 0 };
      }
      if (sortMode === "down_desc") {
        if (validDown !== null) {
          return { tier: 0, primary: -validDown, secondary: lat };
        }
        return { tier: 1, primary: lat, secondary: 0 };
      }
      if (resolved.latencyMs !== null) {
        return { tier: 0, primary: resolved.latencyMs, secondary: -(validUp ?? -1) };
      }
      return { tier: 1, primary: MISSING_LATENCY_PENALTY_MS, secondary: 0 };
    };

    const sorted = [...list];
    sorted.sort((a, b) => {
      if (sortMode !== "default") {
        const ra = getMetricRank(a.id, activeFilterProbes?.[a.id]);
        const rb = getMetricRank(b.id, activeFilterProbes?.[b.id]);
        if (ra.tier !== rb.tier) return ra.tier - rb.tier;
        if (ra.primary !== rb.primary) return ra.primary - rb.primary;
        if (ra.secondary !== rb.secondary) return ra.secondary - rb.secondary;
        return a.name.localeCompare(b.name);
      }
      if (viewMode === "members") {
        const aAct = memberActiveId === a.id ? 1 : 0;
        const bAct = memberActiveId === b.id ? 1 : 0;
        if (aAct !== bAct) return bAct - aAct;
        const aRes = resolveNodeDisplayLatency(
          activeFilterProbes?.[a.id],
          healthHints?.[a.id]
        );
        const bRes = resolveNodeDisplayLatency(
          activeFilterProbes?.[b.id],
          healthHints?.[b.id]
        );
        const aLat = aRes.ok && aRes.latencyMs !== null ? aRes.latencyMs : MISSING_LATENCY_PENALTY_MS;
        const bLat = bRes.ok && bRes.latencyMs !== null ? bRes.latencyMs : MISSING_LATENCY_PENALTY_MS;
        if (aLat !== bLat) return aLat - bLat;
        return a.name.localeCompare(b.name);
      }
      if (!pinnedMembers) return 0;
      const aWeight = a.id === pinnedActive ? 2 : pinnedMembers.has(a.id) ? 1 : 0;
      const bWeight = b.id === pinnedActive ? 2 : pinnedMembers.has(b.id) ? 1 : 0;
      if (aWeight !== bWeight) return bWeight - aWeight;
      return 0;
    });

    return sorted;
  }, [
    enabledNodes,
    viewMode,
    sortMode,
    filterGoogleClean,
    filterAiReady,
    memberFilterSet,
    selectedSubId,
    filterContinent,
    filterRegion,
    searchQuery,
    subNameById,
    pinnedOrder,
    selectedGroupId,
    memberActiveId,
    activeFilterProbes,
    runtimeNodeHealthHints,
  ]);

  const totalNodePages = Math.max(1, Math.ceil(filteredNodes.length / nodePageSize));
  const safeNodePage = Math.min(Math.max(1, nodePage), totalNodePages);

  const pagedFilteredNodes = useMemo(
    () =>
      filteredNodes.slice(
        (safeNodePage - 1) * nodePageSize,
        safeNodePage * nodePageSize
      ),
    [filteredNodes, safeNodePage, nodePageSize]
  );

  const unjoinedInFilterIds = useMemo(() => {
    const ids: string[] = [];
    for (const n of filteredNodes) {
      if (!memberIdSet.has(n.id)) ids.push(n.id);
    }
    return ids;
  }, [filteredNodes, memberIdSet]);

  const measuredMemberNotice = useMemo(() => {
    if (!selectedGroup || selectedGroup.hard_gates.length === 0) return null;
    let testedMemberCount = 0;
    let failedTestedCount = 0;
    for (const id of selectedGroup.member_node_ids) {
      const node = nodeById.get(id);
      const snap = probes[id];
      if (!node || !snap) continue;
      testedMemberCount += 1;
      const res = assessNodeAgainstGates(node, snap, selectedGroup.hard_gates);
      if (res.hasMeasuredFailure) failedTestedCount += 1;
    }
    if (testedMemberCount > 0 && failedTestedCount === testedMemberCount) {
      return "组内已测速的节点暂未满足右侧勾选的要求，建议测速其他节点或放宽右侧标准";
    }
    return null;
  }, [selectedGroup, nodeById, probes]);

  const currentTriggerMeta: TriggerMeta = selectedGroup
    ? (triggerMetas[selectedGroup.id] ?? getPrimaryTriggerMeta(selectedGroup))
    : { consecutiveFailures: 2, bypassCooldownOnDisconnect: true };

  const currentTriggerExpr = selectedGroup ? getPrimaryTriggerExpr(selectedGroup) : "";
  const uploadTriggerInfo = useMemo(
    () => parseUploadTriggerInfo(currentTriggerExpr),
    [currentTriggerExpr]
  );
  const isSelectedDirty = selectedGroup ? Boolean(dirtyGroupIds[selectedGroup.id]) : false;

  const activeRuleCount = useMemo(() => {
    if (!selectedGroup) return 0;
    let count = selectedGroup.hard_gates.length;
    if (currentTriggerExpr.trim()) count += 1;
    if (selectedGroup.match_rules.length > 0) count += 1;
    return count;
  }, [selectedGroup, currentTriggerExpr]);

  const otherGroups = useMemo(
    () => groups.filter((g) => g.id !== selectedGroup?.id),
    [groups, selectedGroup]
  );

  const formulaSyntaxCheck = useMemo(() => {
    if (!selectedGroup) return { ok: true, error: null as string | null, source: "local" as const };
    if (
      inTauri &&
      backendFormulaValidation &&
      backendFormulaValidation.checkedExpr === selectedGroup.formula_expr
    ) {
      return {
        ok: backendFormulaValidation.ok,
        error: backendFormulaValidation.error,
        source: "backend" as const,
      };
    }
    const sampleOutcome = evaluateFormulaSafely(selectedGroup.formula_expr, {
      vars: {
        up_mbps: 12,
        down_mbps: 150,
        ping_ms: 80,
        latency_ms: 80,
        jitter_ms: 5,
        loss_pct: 0,
        multiplier: 1,
        keepalive_ok: 1,
        google_clean: 1,
        ip_clean: 1,
        unlocked: 1,
        is_443_native: 1,
        ok: 1,
      },
      probeUp: { antigravity: 12 },
      probeDown: { dl: 150 },
      probePing: { chatgpt: 80 },
      probeOk: { builtin_unlock_windsurf: true },
      unlockedSites: { chatgpt: true, google_ai: true, claude: true, windsurf: true },
    });
    return { ok: sampleOutcome.ok, error: sampleOutcome.error, source: "local" as const };
  }, [selectedGroup, inTauri, backendFormulaValidation]);

  const formattedDynamicFilter = selectedGroup
    ? formatDynamicFilter(selectedGroup.dynamic_filter)
    : "";

  const updateSelectedGroup = (updater: (group: MultiGroup) => MultiGroup) => {
    if (!selectedGroup) return;
    setGroups((prev) => prev.map((g) => (g.id === selectedGroup.id ? updater(g) : g)));
    setDirtyGroupIds((prev) => ({ ...prev, [selectedGroup.id]: true }));
  };

  const updateTriggerMeta = (patch: Partial<TriggerMeta>) => {
    if (!selectedGroup) return;
    const nextMeta = { ...currentTriggerMeta, ...patch };
    setTriggerMetas((prev) => ({
      ...prev,
      [selectedGroup.id]: nextMeta,
    }));
    updateSelectedGroup((g) => {
      const expr = getPrimaryTriggerExpr(g).trim();
      if (!expr) return g;
      const rest = Array.isArray(g.trigger_rules) ? g.trigger_rules.slice(1) : [];
      return {
        ...g,
        trigger_rules: [
          {
            expr,
            consecutive_failures: nextMeta.consecutiveFailures,
            bypass_cooldown_on_disconnect: nextMeta.bypassCooldownOnDisconnect,
          },
          ...rest,
        ],
      };
    });
  };

  const groupsRef = useRef(groups);
  groupsRef.current = groups;
  const selectedGroupRef = useRef(selectedGroup);
  selectedGroupRef.current = selectedGroup;
  const storeGroupsRef = useRef(storeGroups);
  storeGroupsRef.current = storeGroups;
  const runtimeRouteModeRef = useRef(runtimeRouteMode);
  runtimeRouteModeRef.current = runtimeRouteMode;
  const runtimeActiveGroupIdRef = useRef(runtimeActiveGroupId);
  runtimeActiveGroupIdRef.current = runtimeActiveGroupId;
  const probingNodeIdSetRef = useRef(probingNodeIdSet);
  probingNodeIdSetRef.current = probingNodeIdSet;
  const isProbeEngineBusyRef = useRef(isProbeEngineBusy);
  isProbeEngineBusyRef.current = isProbeEngineBusy;
  const selectingNodeIdRef = useRef(selectingNodeId);
  selectingNodeIdRef.current = selectingNodeId;

  const persistGroupMembers = useCallback(
    async (groupId: string, nextMemberIds: string[], toastText?: string): Promise<boolean> => {
      const prevIds =
        latestMembersRef.current[groupId] ??
        groupsRef.current.find((g) => g.id === groupId)?.member_node_ids ??
        [];
      const uniqueNext = Array.from(new Set(nextMemberIds));
      latestMembersRef.current[groupId] = uniqueNext;

      const seq = (memberReqSeqRef.current[groupId] ?? 0) + 1;
      memberReqSeqRef.current[groupId] = seq;

      setGroups((prev) =>
        prev.map((g) => (g.id === groupId ? { ...g, member_node_ids: uniqueNext } : g))
      );
      appActions.syncGroups(
        appStore
          .getState()
          .groups.map((g) => (g.id === groupId ? { ...g, member_node_ids: uniqueNext } : g))
      );

      try {
        const saved = await catcloudApi.updateMultiGroupMembers(groupId, uniqueNext);
        if (memberReqSeqRef.current[groupId] === seq) {
          latestMembersRef.current[groupId] = saved.member_node_ids;
          setGroups((prev) =>
            prev.map((g) =>
              g.id === groupId
                ? {
                    ...g,
                    member_node_ids: saved.member_node_ids,
                    active_node_id: saved.active_node_id,
                  }
                : g
            )
          );
          appActions.syncGroups(
            appStore.getState().groups.map((g) =>
              g.id === groupId
                ? {
                    ...g,
                    member_node_ids: saved.member_node_ids,
                    active_node_id: saved.active_node_id,
                  }
                : g
            )
          );
          if (toastText) appActions.showToast(toastText, "ok");
        }
        return true;
      } catch (err) {
        if (memberReqSeqRef.current[groupId] === seq) {
          latestMembersRef.current[groupId] = prevIds;
          setGroups((prev) =>
            prev.map((g) => (g.id === groupId ? { ...g, member_node_ids: prevIds } : g))
          );
          appActions.syncGroups(
            appStore
              .getState()
              .groups.map((g) => (g.id === groupId ? { ...g, member_node_ids: prevIds } : g))
          );
          appActions.showToast(`更新组成员失败：${formatErrorMessage(err)}`, "warn");
        }
        return false;
      }
    },
    []
  );

  // Stable callbacks for React.memo GroupNodeCard
  const handleToggleNodeMembership = useCallback(
    (node: ProxyNode) => {
      const grp = selectedGroupRef.current;
      if (!grp) return;
      const currentIds = latestMembersRef.current[grp.id] ?? grp.member_node_ids;
      const exists = currentIds.includes(node.id);
      if (exists && grp.active_node_id === node.id) {
        appActions.showToast("当前正在使用这个节点，请先切到其它节点再移出", "info");
        return;
      }
      const nextIds = exists
        ? currentIds.filter((id) => id !== node.id)
        : [...currentIds, node.id];
      void persistGroupMembers(grp.id, nextIds);
    },
    [persistGroupMembers]
  );

  const handleUseNode = useCallback(
    async (node: ProxyNode) => {
      const grp = selectedGroupRef.current;
      if (!grp || selectingNodeIdRef.current === node.id) return;
      setSelectingNodeId(node.id);
      try {
        const currentIds = latestMembersRef.current[grp.id] ?? grp.member_node_ids;
        if (!currentIds.includes(node.id)) {
          const joined = await persistGroupMembers(grp.id, [...currentIds, node.id]);
          if (!joined) return;
        }
        const closeOld = grp.switch_mode === "force_close_old";
        const persistedGroup = storeGroupsRef.current.find((g) => g.id === grp.id);
        const isSecondaryIndependent =
          Boolean(persistedGroup?.independent_routing) &&
          runtimeRouteModeRef.current === "group" &&
          Boolean(runtimeActiveGroupIdRef.current) &&
          grp.id !== runtimeActiveGroupIdRef.current;
        await appActions.selectGroupNode(
          grp.id,
          node.id,
          closeOld,
          isSecondaryIndependent ? false : undefined
        );
        setGroups((prev) =>
          prev.map((g) => (g.id === grp.id ? { ...g, active_node_id: node.id } : g))
        );
      } finally {
        setSelectingNodeId(null);
      }
    },
    [persistGroupMembers]
  );

  const handleProbeSingleNode = useCallback(async (node: ProxyNode) => {
    if (probingNodeIdSetRef.current.has(node.id) || isProbeEngineBusyRef.current) return;
    await appActions.runMultiGroupNodeProbe(node.id);
  }, []);

  const handleAddFilteredToGroup = () => {
    if (!selectedGroup || unjoinedInFilterIds.length === 0) return;
    const currentIds =
      latestMembersRef.current[selectedGroup.id] ?? selectedGroup.member_node_ids;
    const nextIds = [...currentIds, ...unjoinedInFilterIds];
    void persistGroupMembers(
      selectedGroup.id,
      nextIds,
      `已将 ${unjoinedInFilterIds.length} 个节点加入「${formatGroupDisplayName(selectedGroup.name)}」`
    );
  };

  const hasProtectedActiveMember = Boolean(
    selectedGroup &&
      ((selectedGroup.active_node_id &&
        selectedGroup.member_node_ids.includes(selectedGroup.active_node_id)) ||
        (runtimeActiveNodeId && selectedGroup.member_node_ids.includes(runtimeActiveNodeId)))
  );

  useEffect(() => {
    setConfirmClearMembers(false);
    if (clearConfirmTimerRef.current !== null) {
      window.clearTimeout(clearConfirmTimerRef.current);
      clearConfirmTimerRef.current = null;
    }
  }, [selectedGroupId]);

  const handleCancelClearGroupMembers = () => {
    setConfirmClearMembers(false);
    if (clearConfirmTimerRef.current !== null) {
      window.clearTimeout(clearConfirmTimerRef.current);
      clearConfirmTimerRef.current = null;
    }
  };

  const handleConfirmClearGroupMembers = () => {
    if (!selectedGroup || selectedGroup.member_node_ids.length === 0) return;
    handleCancelClearGroupMembers();
    void persistGroupMembers(
      selectedGroup.id,
      [],
      `已清空「${formatGroupDisplayName(selectedGroup.name)}」中的节点`
    );
  };

  const handleClearGroupMembers = () => {
    if (!selectedGroup || selectedGroup.member_node_ids.length === 0) return;
    if (!confirmClearMembers) {
      setConfirmClearMembers(true);
      if (clearConfirmTimerRef.current !== null) {
        window.clearTimeout(clearConfirmTimerRef.current);
      }
      if (!hasProtectedActiveMember) {
        clearConfirmTimerRef.current = window.setTimeout(() => {
          setConfirmClearMembers(false);
          clearConfirmTimerRef.current = null;
        }, 3500);
      }
      return;
    }
    handleConfirmClearGroupMembers();
  };

  const handleSwitchNextBestInGroup = async () => {
    if (!selectedGroup || switchingNext) return;
    if (effectiveSelectedMemberIds.length === 0 && selectedGroup.mode !== "conditional_pool") {
      appActions.showToast("当前组里还没有节点，请先点击下方节点卡片加入本组", "warn");
      return;
    }
    setSwitchingNext(true);
    try {
      const res = await catcloudApi.switchNextBestNode(selectedGroup.id);
      const rt = await catcloudApi.getRuntimeInfo();
      appActions.syncRuntime({
        ...rt,
        route_mode: "group",
        active_group_id: rt.active_group_id || selectedGroup.id,
        active_group_name: rt.active_group_name || selectedGroup.name,
      });
      setGroups((prev) => {
        const next = prev.map((g) =>
          g.id === selectedGroup.id ? { ...g, active_node_id: res.active_node_id } : g
        );
        appActions.syncGroups(next);
        return next;
      });
      appActions.showToast(`已切至下一个最快节点：${res.active_node_name}`, "ok");
    } catch (err) {
      appActions.showToast(`切换失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setSwitchingNext(false);
    }
  };

  const handleGroupCreated = (saved: MultiGroup) => {
    latestMembersRef.current[saved.id] = saved.member_node_ids;
    setGroups((prev) => {
      const next = [...prev, saved];
      appActions.syncGroups(next);
      return next;
    });
    setSelectedId(saved.id);
    setViewMode("all");
  };

  const handleGroupDeleted = (group: MultiGroup) => {
    const next = groups.filter((g) => g.id !== group.id);
    delete latestMembersRef.current[group.id];
    setGroups(next);
    appActions.syncGroups(next);
    if (selectedGroup?.id === group.id) {
      setSelectedId(next[0]?.id ?? "");
    }
  };

  const handleCommitRename = async () => {
    if (!selectedGroup) return;
    const trimmed = nameDraft.trim();
    setEditingName(false);
    if (
      !trimmed ||
      trimmed === selectedGroup.name ||
      trimmed === formatGroupDisplayName(selectedGroup.name)
    ) {
      return;
    }

    const wasDirty = Boolean(dirtyGroupIds[selectedGroup.id]);
    const persistedBase = storeGroups.find((g) => g.id === selectedGroup.id) ?? selectedGroup;
    const latestMembers =
      latestMembersRef.current[selectedGroup.id] ?? persistedBase.member_node_ids;
    const renamePayloadSource: MultiGroup = {
      ...persistedBase,
      member_node_ids: latestMembers,
      name: trimmed,
    };

    try {
      const payload = wasDirty
        ? renamePayloadSource
        : normalizeGroupForBackend(renamePayloadSource, currentTriggerMeta);
      const saved = await catcloudApi.upsertMultiGroup(payload);
      appActions.syncGroups(
        appStore.getState().groups.map((g) => (g.id === saved.id ? saved : g))
      );
      setGroups((prev) =>
        prev.map((g) => {
          if (g.id !== saved.id) return g;
          return wasDirty ? { ...g, name: saved.name } : saved;
        })
      );
      if (!wasDirty) {
        setDirtyGroupIds((prev) => ({ ...prev, [saved.id]: false }));
      }
      appActions.showToast(`已重命名为：${formatGroupDisplayName(saved.name)}`, "ok");
    } catch (err) {
      appActions.showToast(`重命名失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleSaveSelectedGroup = async () => {
    if (!selectedGroup || savingGroup) return;
    setSavingGroup(true);
    try {
      const payload = normalizeGroupForBackend(selectedGroup, currentTriggerMeta);
      const saved = await catcloudApi.upsertMultiGroup(payload);
      latestMembersRef.current[saved.id] = saved.member_node_ids;
      setGroups((prev) => {
        const next = prev.map((g) => (g.id === saved.id ? saved : g));
        appActions.syncGroups(next);
        return next;
      });
      setDirtyGroupIds((prev) => ({ ...prev, [saved.id]: false }));
      appActions.showToast(`策略已保存并生效：${formatGroupDisplayName(saved.name)}`, "ok");
    } catch (err) {
      appActions.showToast(`保存策略失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setSavingGroup(false);
    }
  };

  const handleToggleGate = (expr: string) => {
    updateSelectedGroup((g) => {
      if (expr === GEMINI_GATE_EXPR) {
        const hasAnyGemini =
          g.hard_gates.includes(GEMINI_GATE_EXPR) ||
          g.hard_gates.includes(LEGACY_GEMINI_GATE_EXPR);
        const cleaned = g.hard_gates.filter(
          (item) => item !== GEMINI_GATE_EXPR && item !== LEGACY_GEMINI_GATE_EXPR
        );
        return {
          ...g,
          hard_gates: hasAnyGemini ? cleaned : [...cleaned, GEMINI_GATE_EXPR],
        };
      }
      const exists = g.hard_gates.includes(expr);
      return {
        ...g,
        hard_gates: exists
          ? g.hard_gates.filter((item) => item !== expr)
          : [...g.hard_gates, expr],
      };
    });
  };

  const handleAddCustomGate = (ev: FormEvent) => {
    ev.preventDefault();
    const expr = customGateInput.trim();
    if (!expr || !selectedGroup) return;
    if (!selectedGroup.hard_gates.includes(expr)) {
      updateSelectedGroup((g) => ({ ...g, hard_gates: [...g.hard_gates, expr] }));
    }
    setCustomGateInput("");
  };

  const setPrimaryTriggerExpr = (nextExpr: string) => {
    updateSelectedGroup((g) => {
      const rest = Array.isArray(g.trigger_rules) ? g.trigger_rules.slice(1) : [];
      const trimmed = nextExpr.trim();
      return {
        ...g,
        trigger_expr: trimmed ? nextExpr : null,
        trigger_rules: trimmed
          ? [
              {
                expr: nextExpr,
                consecutive_failures: currentTriggerMeta.consecutiveFailures,
                bypass_cooldown_on_disconnect: currentTriggerMeta.bypassCooldownOnDisconnect,
              },
              ...rest,
            ]
          : rest,
      };
    });
  };

  const handleToggleUploadTrigger = () => {
    if (!selectedGroup) return;
    if (uploadTriggerInfo.enabled) {
      setPrimaryTriggerExpr("");
    } else {
      const val = Number.isFinite(uploadTriggerInfo.threshold) ? uploadTriggerInfo.threshold : 2.0;
      setPrimaryTriggerExpr(`${uploadTriggerInfo.prefix} < ${val}`);
    }
  };

  const handleUploadThresholdChange = (raw: string) => {
    const num = Number(raw);
    if (!Number.isFinite(num) || num < 0) return;
    if (uploadTriggerInfo.isSimple || !currentTriggerExpr.trim()) {
      setPrimaryTriggerExpr(`${uploadTriggerInfo.prefix} < ${num}`);
    } else {
      const replaced = currentTriggerExpr.replace(
        /(up_mbps|probe_up\(\s*["'][^"']+["']\s*\))\s*<\s*\d+(?:\.\d+)?/,
        `$1 < ${num}`
      );
      setPrimaryTriggerExpr(replaced);
    }
  };

  const handleAddMatchRule = (ev: FormEvent) => {
    ev.preventDefault();
    if (!selectedGroup) return;
    const raw = newRuleInput.trim();
    if (!raw) return;

    const { rules, invalidTokens } = parseUserMatchRules(raw);
    if (rules.length === 0) {
      appActions.showToast(INVALID_MATCH_RULE_MSG, "warn");
      return;
    }

    const existing = new Set(selectedGroup.match_rules);
    const toAdd = rules.filter((r) => !existing.has(r));
    if (toAdd.length > 0) {
      updateSelectedGroup((g) => ({
        ...g,
        match_rules: [...g.match_rules, ...toAdd],
      }));
    }

    if (invalidTokens.length > 0) {
      appActions.showToast(
        `已忽略无效条目（${invalidTokens.join("、")}），${INVALID_MATCH_RULE_MSG}`,
        "warn"
      );
      setNewRuleInput(invalidTokens.join("; "));
      return;
    }

    setNewRuleInput("");
  };

  const handleInsertFormulaToken = (snippet: string) => {
    if (!selectedGroup) return;
    updateSelectedGroup((g) => {
      const base = g.formula_expr.trim();
      return {
        ...g,
        formula_expr: base ? `${base} + ${snippet}` : snippet,
      };
    });
  };

  const handleEvaluateBackend = async () => {
    if (!selectedGroup || evaluating || anyEvaluating || savingGroup) return;
    if (isSelectedDirty) {
      setSavingGroup(true);
      try {
        const payload = normalizeGroupForBackend(selectedGroup, currentTriggerMeta);
        const saved = await catcloudApi.upsertMultiGroup(payload);
        setGroups((prev) => {
          const next = prev.map((g) => (g.id === saved.id ? saved : g));
          appActions.syncGroups(next);
          return next;
        });
        setDirtyGroupIds((prev) => ({ ...prev, [saved.id]: false }));
      } catch (err) {
        appActions.showToast(`保存策略失败：${formatErrorMessage(err)}`, "warn");
        return;
      } finally {
        setSavingGroup(false);
      }
    }
    await appActions.runEvaluateMultiGroup(selectedGroup.id);
  };

  const activeNodeInSelectedGroup = selectedGroup?.active_node_id
    ? (nodeById.get(selectedGroup.active_node_id) ?? null)
    : null;

  const isRuntimeActiveGroup =
    isGroupMode && Boolean(selectedGroup) && runtimeActiveGroupId === selectedGroup?.id;

  const customHardGates = useMemo(() => {
    if (!selectedGroup) return [];
    const presetSet = new Set([
      ...HARD_GATE_PRESETS.map((p) => p.expr),
      LEGACY_GEMINI_GATE_EXPR,
    ]);
    return selectedGroup.hard_gates.filter((expr) => !presetSet.has(expr));
  }, [selectedGroup]);

  const evalUntestedCount = useMemo(() => {
    if (!evalReport) return 0;
    const candidateIds = new Set<string>();
    for (const c of evalReport.gate_passed) candidateIds.add(c.node_id);
    for (const c of evalReport.gate_rejected) candidateIds.add(c.node_id);
    if (candidateIds.size === 0 && selectedGroup) {
      for (const id of selectedGroup.member_node_ids) candidateIds.add(id);
    }
    let untested = 0;
    for (const id of candidateIds) {
      if (!probes[id]) untested += 1;
    }
    return untested;
  }, [evalReport, selectedGroup, probes]);

  const selectedGroupDisplayName = selectedGroup
    ? formatGroupDisplayName(selectedGroup.name)
    : "";

  return (
    <div className="flex min-h-[calc(100vh-4.25rem)] flex-col gap-3.5 lg:flex-row lg:items-stretch">
      {/* COLUMN 1: LEFT SIDEBAR — Create Group & Existing Groups List */}
      <GroupSidebarList
        groups={groups}
        selectedGroupId={selectedGroup?.id ?? null}
        isGroupMode={isGroupMode}
        runtimeActiveGroupId={runtimeActiveGroupId}
        runtimeActiveNodeName={runtimeActiveNodeName}
        nodeById={nodeById}
        dirtyGroupIds={dirtyGroupIds}
        dict={dict}
        onSelectGroup={setSelectedId}
        onGroupCreated={handleGroupCreated}
        onGroupDeleted={handleGroupDeleted}
      />

      {/* COLUMN 2: CENTER MAIN STAGE — Node Grid & Instant Actions */}
      {selectedGroup ? (
        <section className="flex min-w-0 flex-1 flex-col gap-3">
          {/* Compact Top Header Bar */}
          <div className="cc-card cc-glass rounded-2xl px-4 py-3">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-3">
                  {editingName ? (
                    <form
                      onSubmit={(ev) => {
                        ev.preventDefault();
                        void handleCommitRename();
                      }}
                      className="flex min-w-0 max-w-full items-center gap-1.5"
                    >
                      <input
                        type="text"
                        autoFocus
                        value={nameDraft}
                        onChange={(e) => setNameDraft(e.target.value)}
                        onBlur={() => void handleCommitRename()}
                        onKeyDown={(e) => {
                          if (e.key === "Escape") {
                            setEditingName(false);
                          }
                        }}
                        className="min-w-0 w-full max-w-[260px] rounded-lg border border-[var(--accent)] bg-[var(--bg-elevated)] px-2.5 py-1 text-sm font-semibold text-[var(--text)] outline-none"
                      />
                    </form>
                  ) : (
                    <div className="inline-flex min-w-0 max-w-full items-center gap-2">
                      <h1 className="truncate text-base font-semibold tracking-tight text-[var(--text)]">
                        {selectedGroupDisplayName}
                      </h1>
                      <button
                        type="button"
                        onClick={() => {
                          setNameDraft(selectedGroupDisplayName);
                          setEditingName(true);
                        }}
                        title="点击修改多选组名称"
                        aria-label="修改多选组名称"
                        className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-lg text-[var(--muted)] transition-colors hover:bg-[var(--bg-elevated)] hover:text-[var(--accent)]"
                      >
                        <Pencil className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  )}

                  {isRuntimeActiveGroup ? (
                    <span className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full border border-[var(--green)]/40 bg-[var(--green-soft)] px-2.5 py-0.5 text-[11px] font-semibold text-[var(--green)]">
                      <span className="h-1.5 w-1.5 rounded-full bg-[var(--green)]" />
                      {dict.groups.mainFallbackActive}
                    </span>
                  ) : (
                    <button
                      type="button"
                      onClick={() => void appActions.setActiveGroup(selectedGroup.id)}
                      className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-full bg-[var(--accent)] px-3 py-1 text-[11px] font-semibold text-[var(--accent-ink)] shadow-xs transition-opacity hover:opacity-90"
                    >
                      <Play className="h-2.5 w-2.5 fill-current" />
                      <span>使用此组</span>
                    </button>
                  )}

                  {/* Persistent Independent Routing Status Capsule */}
                  <button
                    type="button"
                    onClick={handleOpenIndepSection}
                    title="点击展开右侧策略抽屉并定位到「5. 分流规则（独立分流）」"
                    className={`inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full border px-2.5 py-0.5 text-[11px] font-semibold transition-colors ${
                      selectedGroup.independent_routing
                        ? selectedGroup.match_rules.length > 0
                          ? "border-[var(--amber)]/55 bg-[var(--amber-soft)] text-[var(--amber)] hover:border-[var(--amber)]"
                          : "border-dashed border-[var(--amber)]/55 bg-[var(--amber-soft)]/50 text-[var(--amber)] hover:border-[var(--amber)]"
                        : "border-[var(--line)] bg-[var(--bg-elevated)] font-medium text-[var(--muted)] hover:border-[var(--amber)]/45 hover:text-[var(--text-secondary)]"
                    }`}
                  >
                    <span
                      className={`h-1.5 w-1.5 shrink-0 rounded-full ${
                        selectedGroup.independent_routing ? "bg-[var(--amber)]" : "bg-[var(--muted)]/55"
                      }`}
                    />
                    <span>
                      {selectedGroup.independent_routing
                        ? selectedGroup.match_rules.length > 0
                          ? formatI18nTemplate(dict.groups.indepCapsuleActive, {
                              count: selectedGroup.match_rules.length,
                            })
                          : dict.groups.indepCapsulePending
                        : dict.groups.indepCapsuleOff}
                    </span>
                  </button>

                  <button
                    type="button"
                    onClick={() => appActions.setNav("overview")}
                    className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-full border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-0.5 text-[11px] font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
                  >
                    <ArrowLeft className="h-3 w-3 shrink-0" />
                    <span>返回总览</span>
                  </button>
                </div>

                <p className="mt-1 truncate text-xs text-[var(--muted)]">
                  {effectiveSelectedMemberIds.length > 0 ? (
                    <>
                      已加入{" "}
                      <span className="cc-mono font-semibold text-[var(--text)]">
                        {effectiveSelectedMemberIds.length}
                      </span>{" "}
                      个节点
                      <span className="mx-1.5 opacity-50">·</span>
                      {isRuntimeActiveGroup ? "正在用：" : "组内选定："}
                      <span
                        className={`font-medium ${
                          isRuntimeActiveGroup ? "text-[var(--green)]" : "text-[var(--text-secondary)]"
                        }`}
                      >
                        {activeNodeInSelectedGroup ? activeNodeInSelectedGroup.name : "尚未选定"}
                      </span>
                    </>
                  ) : (
                    <span>本组还没有节点 · 直接点击下方任意节点卡片即可加入</span>
                  )}
                </p>
              </div>

              <div className="flex shrink-0 flex-wrap items-center gap-2">
                <button
                  type="button"
                  disabled={switchingNext}
                  onClick={() => void handleSwitchNextBestInGroup()}
                  className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl bg-[var(--accent)] px-3.5 py-2 text-xs font-semibold text-[var(--accent-ink)] shadow-xs transition-opacity hover:opacity-90 disabled:opacity-60"
                >
                  {switchingNext ? (
                    <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" />
                  ) : (
                    <Zap className="h-3.5 w-3.5 shrink-0" />
                  )}
                  <span>{switchingNext ? "切换中..." : "换下一个最快"}</span>
                </button>

                <button
                  type="button"
                  onClick={() => setDrawerOpen((v) => !v)}
                  className={`inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border px-3 py-2 text-xs font-medium transition-colors ${
                    drawerOpen
                      ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                      : "border-[var(--line-strong)] bg-[var(--bg-elevated)] text-[var(--text)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
                  }`}
                >
                  <Settings2 className="h-3.5 w-3.5 shrink-0" />
                  <span>{drawerOpen ? "收起策略与标准" : "策略与标准"}</span>
                  {activeRuleCount > 0 && (
                    <span className="cc-mono rounded-full bg-[var(--card)] px-1.5 py-0.2 text-[10px] font-semibold text-[var(--accent)]">
                      {activeRuleCount}
                    </span>
                  )}
                  {isSelectedDirty && (
                    <span
                      className="h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--amber)]"
                      title="有未应用的策略改动"
                    />
                  )}
                </button>
              </div>
            </div>

            {measuredMemberNotice && (
              <div className="mt-2.5 flex items-center gap-2 rounded-xl border border-[var(--amber)]/35 bg-[var(--amber-soft)] px-3 py-1.5 text-[11px] text-[var(--amber)]">
                <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                <span>{measuredMemberNotice}</span>
              </div>
            )}
          </div>

          {/* Clean Compact Filter Bar with Collapsible More Filters Drawer */}
          <GroupFilterBar
            searchQuery={searchQuery}
            setSearchQuery={setSearchQuery}
            viewMode={viewMode}
            setViewMode={setViewMode}
            effectiveMemberCount={effectiveSelectedMemberIds.length}
            filterGoogleClean={filterGoogleClean}
            setFilterGoogleClean={setFilterGoogleClean}
            filterAiReady={filterAiReady}
            setFilterAiReady={setFilterAiReady}
            moreFiltersOpen={moreFiltersOpen}
            setMoreFiltersOpen={setMoreFiltersOpen}
            moreFilterActiveCount={moreFilterActiveCount}
            hasAnyActiveFilter={hasAnyActiveFilter}
            onResetFilters={handleResetFilters}
            selectedSubId={selectedSubId}
            setSelectedSubId={setSelectedSubId}
            enabledNodesCount={enabledNodes.length}
            providerTabs={providerTabs}
            regionStats={regionStats}
            filterContinent={filterContinent}
            filterRegion={filterRegion}
            onContinentChange={(c) => {
              setFilterContinent(c);
              setNodePage(1);
            }}
            onRegionChange={(r) => {
              setFilterRegion(r);
              setNodePage(1);
            }}
            sortMode={sortMode}
            setSortMode={setSortMode}
            unjoinedInFilterCount={unjoinedInFilterIds.length}
            onAddFilteredToGroup={handleAddFilteredToGroup}
            confirmClearMembers={confirmClearMembers}
            hasProtectedActiveMember={hasProtectedActiveMember}
            onClearGroupMembers={handleClearGroupMembers}
            onCancelClearGroupMembers={handleCancelClearGroupMembers}
            onConfirmClearGroupMembers={handleConfirmClearGroupMembers}
            filteredCount={filteredNodes.length}
            safeNodePage={safeNodePage}
            totalNodePages={totalNodePages}
            dict={dict}
          />

          {/* Responsive Node Card Grid Container */}
          <div className="cc-card cc-glass flex flex-1 flex-col rounded-2xl p-3">
            {totalNodePages > 1 && (
              <PaginationBar
                currentPage={safeNodePage}
                totalPages={totalNodePages}
                totalItems={filteredNodes.length}
                pageSize={nodePageSize}
                pageSizeOptions={NODE_PAGE_SIZE_OPTIONS}
                onPageChange={setNodePage}
                onPageSizeChange={(s) => {
                  setNodePageSize(s);
                  setNodePage(1);
                }}
                compact
                className="mb-2.5 border-b border-[var(--line)]/60 pb-2"
              />
            )}

            {pagedFilteredNodes.length > 0 ? (
              <div
                className={`grid grid-cols-1 gap-2.5 ${
                  drawerOpen && isWideDesktop
                    ? "2xl:grid-cols-2"
                    : "sm:grid-cols-2 min-[1400px]:grid-cols-3 2xl:grid-cols-4"
                }`}
              >
                {pagedFilteredNodes.map((node) => {
                  const isActive = selectedGroup.active_node_id === node.id;
                  return (
                    <GroupNodeCard
                      key={node.id}
                      node={node}
                      snap={probes[node.id]}
                      healthHint={runtimeNodeHealthHints?.[node.id]}
                      subName={subNameById.get(node.sub_id) ?? "订阅节点"}
                      hardGates={selectedGroup.hard_gates}
                      isActive={isActive}
                      isLiveActive={isActive && isRuntimeActiveGroup}
                      isMember={memberIdSet.has(node.id)}
                      isProbing={probingNodeIdSet.has(node.id)}
                      isSelecting={selectingNodeId === node.id}
                      isProbeEngineBusy={isProbeEngineBusy}
                      benchmarkRunning={benchmarkRunning}
                      dict={dict}
                      onToggleMembership={handleToggleNodeMembership}
                      onProbeSingleNode={handleProbeSingleNode}
                      onUseNode={handleUseNode}
                    />
                  );
                })}
              </div>
            ) : (
              <div className="flex flex-1 flex-col items-center justify-center px-6 py-12 text-center">
                <p className="text-xs font-medium text-[var(--text-secondary)]">
                  {enabledNodes.length === 0
                    ? "节点库里还没有节点，请先去「节点与测速 → 订阅与导入」导入订阅"
                    : viewMode === "members" && effectiveSelectedMemberIds.length === 0
                      ? "当前多选组里还没有节点，可切到「全部节点」点击卡片加入"
                      : "没有找到符合当前筛选条件的节点"}
                </p>
                {enabledNodes.length === 0 && (
                  <button
                    type="button"
                    onClick={() => appActions.openNodesWorkspace("subs")}
                    className="mt-3 rounded-xl bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent-ink)] hover:opacity-90"
                  >
                    去导入订阅
                  </button>
                )}
                {viewMode === "members" &&
                  effectiveSelectedMemberIds.length === 0 &&
                  enabledNodes.length > 0 && (
                    <button
                      type="button"
                      onClick={() => setViewMode("all")}
                      className="mt-3 rounded-xl bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent-ink)] hover:opacity-90"
                    >
                      切到「全部节点」挑选加入
                    </button>
                  )}
                {hasAnyActiveFilter && (
                  <button
                    type="button"
                    onClick={handleResetFilters}
                    className="mt-3 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-3.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
                  >
                    {dict.groups.resetFiltersBtn}
                  </button>
                )}
              </div>
            )}

            {filteredNodes.length > 0 && (
              <PaginationBar
                currentPage={safeNodePage}
                totalPages={totalNodePages}
                totalItems={filteredNodes.length}
                pageSize={nodePageSize}
                pageSizeOptions={NODE_PAGE_SIZE_OPTIONS}
                onPageChange={setNodePage}
                onPageSizeChange={(s) => {
                  setNodePageSize(s);
                  setNodePage(1);
                }}
                className="mt-3 border-t border-[var(--line)]/60 pt-2.5"
              />
            )}
          </div>
        </section>
      ) : (
        <section className="cc-card cc-glass flex flex-1 items-center justify-center rounded-2xl p-10 text-center text-xs text-[var(--muted)]">
          暂无多选组，请点击左侧「+ 新建多选组」创建首个分组。
        </section>
      )}

      {/* COLUMN 3: RIGHT COLLAPSIBLE STRATEGY DRAWER */}
      {selectedGroup && !drawerOpen && (
        <aside className="hidden xl:flex xl:shrink-0 xl:flex-col">
          <button
            type="button"
            onClick={() => setDrawerOpen(true)}
            title="点击展开右侧策略与标准设置"
            className="cc-card cc-glass flex w-[44px] flex-1 flex-col items-center justify-start gap-3 rounded-2xl py-4 text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
          >
            <span className="flex flex-col items-center gap-3 xl:sticky xl:top-4">
              <Settings2 className="h-4 w-4 text-[var(--accent)]" />
              <span
                className="text-xs font-medium tracking-widest"
                style={{ writingMode: "vertical-rl" }}
              >
                点击展开策略与标准
              </span>
              {activeRuleCount > 0 && (
                <span className="cc-mono flex h-5 w-5 items-center justify-center rounded-full bg-[var(--accent-soft)] text-[10px] font-semibold text-[var(--accent)]">
                  {activeRuleCount}
                </span>
              )}
            </span>
          </button>
        </aside>
      )}

      {selectedGroup && drawerOpen && (
        <GroupConfigDrawer
          selectedGroup={selectedGroup}
          selectedGroupDisplayName={selectedGroupDisplayName}
          otherGroups={otherGroups}
          isWideDesktop={isWideDesktop}
          advancedOpen={advancedOpen}
          setAdvancedOpen={setAdvancedOpen}
          setDrawerOpen={setDrawerOpen}
          section5Ref={section5Ref}
          dict={dict}
          formattedDynamicFilter={formattedDynamicFilter}
          customHardGates={customHardGates}
          uploadTriggerInfo={uploadTriggerInfo}
          currentTriggerMeta={currentTriggerMeta}
          currentTriggerExpr={currentTriggerExpr}
          newRuleInput={newRuleInput}
          setNewRuleInput={setNewRuleInput}
          customGateInput={customGateInput}
          setCustomGateInput={setCustomGateInput}
          formulaSyntaxCheck={formulaSyntaxCheck}
          evaluating={evaluating}
          anyEvaluating={anyEvaluating}
          evalReport={evalReport}
          evalUntestedCount={evalUntestedCount}
          savingGroup={savingGroup}
          isSelectedDirty={isSelectedDirty}
          updateSelectedGroup={updateSelectedGroup}
          updateTriggerMeta={updateTriggerMeta}
          setPrimaryTriggerExpr={setPrimaryTriggerExpr}
          onToggleGate={handleToggleGate}
          onAddCustomGate={handleAddCustomGate}
          onToggleUploadTrigger={handleToggleUploadTrigger}
          onUploadThresholdChange={handleUploadThresholdChange}
          onAddMatchRule={handleAddMatchRule}
          onInsertFormulaToken={handleInsertFormulaToken}
          onEvaluateBackend={() => void handleEvaluateBackend()}
          onSaveSelectedGroup={() => void handleSaveSelectedGroup()}
        />
      )}
    </div>
  );
}
