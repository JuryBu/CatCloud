import {
  AlertTriangle,
  ArrowDown,
  ArrowRightLeft,
  ArrowUp,
  ArrowUpDown,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Clock,
  Filter,
  Layers,
  Play,
  Plus,
  Rocket,
  RotateCcw,
  Search,
  Settings,
  ShieldCheck,
  Sparkles,
  Square,
  Terminal,
  Trash2,
  X,
  XCircle,
  Zap,
} from "lucide-react";
import {
  type FormEvent,
  type MouseEvent as ReactMouseEvent,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  type DynamicFilterSpec,
  type MultiGroup,
  type ProbeDefinition,
  type ProbeKind,
  type ProbeSnapshot,
  type ProxyNode,
  catcloudApi,
  formatErrorMessage,
  isTauriEnv,
} from "../api/tauri";
import { ContinentRegionFilter, PaginationBar } from "../components/ContinentRegionFilter";
import { MascotSprite } from "../components/MascotSprite";
import { appActions, appStore, useAppSelector } from "../store/appStore";
import {
  type ContinentId,
  buildContinentRegionStats,
  getRegionLabel,
  nodeMatchesContinentAndRegion,
  resolveNodeRegionCode,
} from "../utils/regions";

type SpeedTestTier = "latency" | "unlock" | "full";

interface ProbeItem {
  id: string;
  name: string;
  kind: ProbeKind;
  target: string;
  method: string;
  expectedStatus?: number | null;
  bodyRegex?: string;
  payloadKb?: number;
  timeoutMs: number;
  builtin: boolean;
  enabled: boolean;
}

const PROBE_ENABLED_STORAGE_KEY = "catcloud.speedtest.probeEnabled.v1";
const KEEPALIVE_STORAGE_KEY = "__keepalive__";

const FRIENDLY_GROUP_NAME_MAP: Record<string, string> = {
  流媒体与下载受控均衡: "影音下载均衡组",
  高优家宽备援池: "备用精选组",
};

function formatGroupDisplayName(name: string): string {
  return FRIENDLY_GROUP_NAME_MAP[name] ?? name;
}

function loadPersistedProbeEnabledMap(): Record<string, boolean> {
  if (typeof window === "undefined") return {};
  try {
    const raw = window.localStorage.getItem(PROBE_ENABLED_STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== "object") return {};
    const out: Record<string, boolean> = {};
    for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
      if (typeof v === "boolean") out[k] = v;
    }
    return out;
  } catch {
    return {};
  }
}

function savePersistedProbeEnabledMap(map: Record<string, boolean>): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(PROBE_ENABLED_STORAGE_KEY, JSON.stringify(map));
  } catch {
    /* ignore storage quota or privacy-mode errors */
  }
}

const PROBE_KIND_LABELS: Record<ProbeKind, string> = {
  latency: "基础延迟",
  upload: "上传测速",
  download: "下载测速",
  keepalive: "60 秒长连接",
  google_cn: "谷歌地区检测",
  unlock_regex: "网站解锁",
  external_cmd: "自定义脚本",
};

const FRIENDLY_BUILTIN_PROBES: Record<string, { title: string; desc: string }> = {
  builtin_latency: {
    title: "基础延迟",
    desc: "检查节点是否连通及响应速度",
  },
  builtin_google_cn: {
    title: "谷歌地区检测",
    desc: "检测谷歌识别的地区是否正常",
  },
  builtin_upload: {
    title: "上传测速",
    desc: "测试节点的上传网速",
  },
  builtin_download: {
    title: "下载测速",
    desc: "测试节点的下载网速",
  },
  builtin_keepalive_60s: {
    title: "60 秒长连接",
    desc: "测试连接静置 60 秒后是否稳定不断流",
  },
  builtin_unlock_windsurf: {
    title: "Windsurf 解锁",
    desc: "检测是否支持正常访问 Windsurf",
  },
  builtin_unlock_claude: {
    title: "Claude 解锁",
    desc: "检测是否支持正常访问 Claude 与 Anthropic 接口",
  },
  builtin_unlock_chatgpt: {
    title: "ChatGPT 解锁",
    desc: "检测是否支持正常访问 ChatGPT 与 OpenAI 接口",
  },
  builtin_unlock_gemini: {
    title: "Gemini 解锁",
    desc: "检测是否支持正常访问 Gemini 与 AI Studio",
  },
};

const INITIAL_PROBES: ProbeItem[] = [
  {
    id: "builtin_latency",
    name: "基础延迟",
    kind: "latency",
    target: "https://cp.cloudflare.com/generate_204",
    method: "GET",
    expectedStatus: 204,
    timeoutMs: 5000,
    builtin: true,
    enabled: true,
  },
  {
    id: "builtin_google_cn",
    name: "谷歌地区检测",
    kind: "google_cn",
    target: "https://www.google.com/generate_204",
    method: "GET",
    expectedStatus: 204,
    timeoutMs: 6000,
    builtin: true,
    enabled: true,
  },
  {
    id: "builtin_upload",
    name: "上传测速",
    kind: "upload",
    target: "https://speed.cloudflare.com/__up",
    method: "POST",
    expectedStatus: 200,
    payloadKb: 512,
    timeoutMs: 12000,
    builtin: true,
    enabled: true,
  },
  {
    id: "builtin_download",
    name: "下载测速",
    kind: "download",
    target: "https://speed.cloudflare.com/__down?bytes=2097152",
    method: "GET",
    expectedStatus: 200,
    payloadKb: 2048,
    timeoutMs: 12000,
    builtin: true,
    enabled: true,
  },
  {
    id: "builtin_keepalive_60s",
    name: "60 秒长连接",
    kind: "keepalive",
    target: "https://cp.cloudflare.com/generate_204",
    method: "GET",
    expectedStatus: 204,
    timeoutMs: 65000,
    builtin: true,
    enabled: false,
  },
  {
    id: "builtin_unlock_windsurf",
    name: "Windsurf 解锁",
    kind: "unlock_regex",
    target: "https://windsurf.com",
    method: "GET",
    expectedStatus: 200,
    bodyRegex: "windsurf|codeium",
    timeoutMs: 8000,
    builtin: true,
    enabled: true,
  },
  {
    id: "builtin_unlock_claude",
    name: "Claude 解锁",
    kind: "unlock_regex",
    target: "https://api.anthropic.com/v1/messages",
    method: "POST",
    expectedStatus: null,
    timeoutMs: 8000,
    builtin: true,
    enabled: true,
  },
  {
    id: "builtin_unlock_chatgpt",
    name: "ChatGPT 解锁",
    kind: "unlock_regex",
    target: "https://api.openai.com/v1/models",
    method: "GET",
    expectedStatus: null,
    timeoutMs: 8000,
    builtin: true,
    enabled: true,
  },
  {
    id: "builtin_unlock_gemini",
    name: "Gemini 解锁",
    kind: "unlock_regex",
    target: "https://generativelanguage.googleapis.com/v1beta/models",
    method: "GET",
    expectedStatus: null,
    timeoutMs: 8000,
    builtin: true,
    enabled: true,
  },
];

const UNLOCK_PRESETS: ReadonlyArray<{
  label: string;
  id: string;
  name: string;
  target: string;
  bodyRegex: string;
}> = [
  {
    label: "ChatGPT 模板",
    id: "unlock_chatgpt_api",
    name: "ChatGPT 解锁",
    target: "https://api.openai.com/v1/models",
    bodyRegex: "invalid_api_key|unauthorized|data",
  },
  {
    label: "Claude 模板",
    id: "unlock_claude_web",
    name: "Claude 解锁",
    target: "https://claude.ai/login",
    bodyRegex: "claude",
  },
  {
    label: "Windsurf 模板",
    id: "unlock_windsurf_ide",
    name: "Windsurf 解锁",
    target: "https://windsurf.com",
    bodyRegex: "windsurf|codeium",
  },
];

const TIER_LABELS: Record<SpeedTestTier, string> = {
  latency: "仅快测延迟",
  unlock: "测延迟 + 送中/AI",
  full: "含上下行完整测速",
};

function mergeProbeSnapshotsPreserveOld(
  prevMap: Record<string, ProbeSnapshot>,
  incomingMap: Record<string, ProbeSnapshot>
): Record<string, ProbeSnapshot> {
  const next = { ...prevMap };
  for (const [nodeId, incoming] of Object.entries(incomingMap)) {
    const prev = prevMap[nodeId];
    if (!prev) {
      next[nodeId] = incoming;
      continue;
    }
    const incomingUnlocked = incoming.unlocked_sites ?? {};
    const hasIncomingUnlocked = Object.keys(incomingUnlocked).length > 0;
    next[nodeId] = {
      ...prev,
      ...incoming,
      up_mbps: incoming.up_mbps ?? prev.up_mbps,
      down_mbps: incoming.down_mbps ?? prev.down_mbps,
      cf_loc: incoming.cf_loc ?? prev.cf_loc,
      yt_gl: incoming.yt_gl ?? prev.yt_gl,
      google_clean: incoming.google_clean ?? prev.google_clean,
      google_risk_mismatch:
        incoming.google_clean !== null && incoming.google_clean !== undefined
          ? incoming.google_risk_mismatch
          : prev.google_risk_mismatch,
      keepalive_60s_ok: incoming.keepalive_60s_ok ?? prev.keepalive_60s_ok,
      unlocked_sites: hasIncomingUnlocked
        ? { ...(prev.unlocked_sites ?? {}), ...incomingUnlocked }
        : (prev.unlocked_sites ?? {}),
      per_probe_ok: { ...(prev.per_probe_ok ?? {}), ...(incoming.per_probe_ok ?? {}) },
      per_probe_up_mbps: {
        ...(prev.per_probe_up_mbps ?? {}),
        ...(incoming.per_probe_up_mbps ?? {}),
      },
      per_probe_down_mbps: {
        ...(prev.per_probe_down_mbps ?? {}),
        ...(incoming.per_probe_down_mbps ?? {}),
      },
      per_probe_ping_ms: {
        ...(prev.per_probe_ping_ms ?? {}),
        ...(incoming.per_probe_ping_ms ?? {}),
      },
      per_probe_detail: {
        ...(prev.per_probe_detail ?? {}),
        ...(incoming.per_probe_detail ?? {}),
      },
    };
  }
  return next;
}

const PAGE_SIZE_OPTIONS = [30, 50, 100] as const;

type SortKey =
  | "name"
  | "source"
  | "latency"
  | "up"
  | "down"
  | "google"
  | "unlocks";

type SortDir = "asc" | "desc";

function getProbeDisplayInfo(probe: ProbeItem): { title: string; desc: string } {
  const mapped = FRIENDLY_BUILTIN_PROBES[probe.id];
  if (mapped) return mapped;
  if (probe.builtin) {
    return {
      title: PROBE_KIND_LABELS[probe.kind],
      desc: "内置测速项目",
    };
  }
  return {
    title: probe.name,
    desc: PROBE_KIND_LABELS[probe.kind],
  };
}

function fromProbeDefinition(
  def: ProbeDefinition,
  persistedEnabled: Record<string, boolean>,
  keepaliveEnabled: boolean
): ProbeItem {
  const enabled =
    def.kind === "keepalive"
      ? keepaliveEnabled
      : typeof persistedEnabled[def.id] === "boolean"
        ? persistedEnabled[def.id]
        : true;
  return {
    id: def.id,
    name: def.name,
    kind: def.kind,
    target: def.target_url,
    method: def.method,
    expectedStatus: def.expected_status ?? null,
    bodyRegex: def.body_regex ?? undefined,
    payloadKb:
      typeof def.payload_bytes === "number" && def.payload_bytes > 0
        ? Math.max(1, Math.round(def.payload_bytes / 1024))
        : undefined,
    timeoutMs: def.timeout_ms,
    builtin: def.builtin,
    enabled,
  };
}

function toProbeDefinition(item: ProbeItem): ProbeDefinition {
  return {
    id: item.id,
    name: item.name,
    kind: item.kind,
    target_url: item.target,
    method: item.method,
    expected_status:
      item.expectedStatus ??
      (item.kind === "latency" || item.kind === "google_cn" || item.kind === "keepalive"
        ? 204
        : 200),
    body_regex: item.bodyRegex?.trim() ? item.bodyRegex.trim() : null,
    payload_bytes:
      typeof item.payloadKb === "number" && item.payloadKb > 0
        ? Math.round(item.payloadKb * 1024)
        : null,
    timeout_ms: item.timeoutMs,
    builtin: item.builtin,
  };
}

interface CompiledDynamicFilter {
  subIdSet: Set<string> | null;
  regionUpperSet: Set<string> | null;
  protocolLowerSet: Set<string> | null;
  maxMultiplier: number | null;
  requireGoogleClean: boolean;
  require443Native: boolean;
}

function parseDynamicFilterSpec(raw: MultiGroup["dynamic_filter"]): DynamicFilterSpec | null {
  if (!raw) return null;
  if (typeof raw === "string") {
    try {
      const parsed = JSON.parse(raw) as unknown;
      if (parsed && typeof parsed === "object") {
        return parsed as DynamicFilterSpec;
      }
      return null;
    } catch {
      return null;
    }
  }
  if (typeof raw === "object") {
    return raw as DynamicFilterSpec;
  }
  return null;
}

function compileDynamicFilter(raw: MultiGroup["dynamic_filter"]): CompiledDynamicFilter | null {
  const spec = parseDynamicFilterSpec(raw);
  if (!spec) return null;
  return {
    subIdSet:
      Array.isArray(spec.sub_ids) && spec.sub_ids.length > 0 ? new Set(spec.sub_ids) : null,
    regionUpperSet:
      Array.isArray(spec.region_codes) && spec.region_codes.length > 0
        ? new Set(spec.region_codes.map((r) => r.toUpperCase()))
        : null,
    protocolLowerSet:
      Array.isArray(spec.protocols) && spec.protocols.length > 0
        ? new Set(spec.protocols.map((p) => p.toLowerCase()))
        : null,
    maxMultiplier:
      typeof spec.max_multiplier === "number" && Number.isFinite(spec.max_multiplier)
        ? spec.max_multiplier
        : null,
    requireGoogleClean: spec.require_google_clean === true,
    require443Native: spec.require_443_native === true,
  };
}

function nodeBelongsToGroup(
  node: ProxyNode,
  memberSet: Set<string> | undefined,
  compiledFilter: CompiledDynamicFilter | null,
  probes: Record<string, ProbeSnapshot>
): boolean {
  if (memberSet && memberSet.size > 0) {
    return memberSet.has(node.id);
  }
  if (!compiledFilter) {
    return node.enabled;
  }
  if (compiledFilter.subIdSet && !compiledFilter.subIdSet.has(node.sub_id)) {
    return false;
  }
  if (
    compiledFilter.regionUpperSet &&
    !compiledFilter.regionUpperSet.has(node.region_code.toUpperCase())
  ) {
    return false;
  }
  if (
    compiledFilter.maxMultiplier !== null &&
    node.multiplier > compiledFilter.maxMultiplier
  ) {
    return false;
  }
  if (
    compiledFilter.protocolLowerSet &&
    !compiledFilter.protocolLowerSet.has(node.protocol.toLowerCase())
  ) {
    return false;
  }
  if (compiledFilter.requireGoogleClean && probes[node.id]?.google_clean !== true) {
    return false;
  }
  if (compiledFilter.require443Native && !node.is_443_native) {
    return false;
  }
  return node.enabled;
}

function getLatencyColor(latencyMs: number | null | undefined, ok: boolean | undefined): string {
  if (ok === false) return "var(--red)";
  if (latencyMs === null || latencyMs === undefined) return "var(--muted)";
  if (latencyMs <= 140) return "var(--green)";
  if (latencyMs <= 300) return "var(--amber)";
  return "var(--red)";
}

interface CtrlDragState {
  dragging: boolean;
  action: "add" | "remove";
  visitedIds: Set<string>;
}

export interface SpeedTestPageProps {
  embedded?: boolean;
  initialSubId?: string | null;
  onOpenSubs?: () => void;
}

export function SpeedTestPage({
  embedded = false,
  initialSubId = null,
  onOpenSubs,
}: SpeedTestPageProps = {}) {
  const nodes = useAppSelector((s) => s.nodes);
  const subscriptions = useAppSelector((s) => s.subscriptions);
  const groups = useAppSelector((s) => s.groups);
  const config = useAppSelector((s) => s.config);
  const preAccelRelays = useAppSelector((s) => s.preAccelRelays);
  const runtime = useAppSelector((s) => s.runtime);
  const isSingleMode = runtime.route_mode === "single";
  const probes = useAppSelector((s) => s.probes);
  const probeProgress = useAppSelector((s) => s.probeProgress);
  const initialized = useAppSelector((s) => s.initialized);
  const inTauri = isTauriEnv();

  const hasEnabledPreAccelRelay = useMemo(
    () => preAccelRelays.some((r) => r.enabled),
    [preAccelRelays]
  );
  const defaultUsePreaccel = config.preaccel.enabled && hasEnabledPreAccelRelay;
  const [usePreaccelForProbe, setUsePreaccelForProbe] = useState<boolean>(
    () => defaultUsePreaccel
  );
  const userToggledPreaccelRef = useRef(false);

  useEffect(() => {
    if (!hasEnabledPreAccelRelay) {
      setUsePreaccelForProbe(false);
      return;
    }
    if (initialized && !userToggledPreaccelRef.current) {
      setUsePreaccelForProbe(defaultUsePreaccel);
    }
  }, [initialized, defaultUsePreaccel, hasEnabledPreAccelRelay]);

  // Persisted keepalive (single source of truth) & probe enabled states
  const [includeKeepalive, setIncludeKeepalive] = useState<boolean>(() => {
    const persisted = loadPersistedProbeEnabledMap();
    if (typeof persisted[KEEPALIVE_STORAGE_KEY] === "boolean") {
      return persisted[KEEPALIVE_STORAGE_KEY];
    }
    if (typeof persisted.builtin_keepalive_60s === "boolean") {
      return persisted.builtin_keepalive_60s;
    }
    return false;
  });
  const includeKeepaliveRef = useRef(includeKeepalive);
  includeKeepaliveRef.current = includeKeepalive;

  // Probe definitions & collapsible settings drawer (collapsed by default)
  const [probeList, setProbeList] = useState<ProbeItem[]>(() => {
    if (inTauri) return [];
    const persisted = loadPersistedProbeEnabledMap();
    const keepaliveOn =
      typeof persisted[KEEPALIVE_STORAGE_KEY] === "boolean"
        ? persisted[KEEPALIVE_STORAGE_KEY]
        : typeof persisted.builtin_keepalive_60s === "boolean"
          ? persisted.builtin_keepalive_60s
          : false;
    return INITIAL_PROBES.map((p) => ({
      ...p,
      enabled:
        p.kind === "keepalive"
          ? keepaliveOn
          : typeof persisted[p.id] === "boolean"
            ? persisted[p.id]
            : p.enabled,
    }));
  });
  const [showProbeSettings, setShowProbeSettings] = useState(false);
  const [showAddProbe, setShowAddProbe] = useState(false);
  const [newProbeId, setNewProbeId] = useState("");
  const [newProbeName, setNewProbeName] = useState("");
  const [newProbeKind, setNewProbeKind] = useState<ProbeKind>("upload");
  const [newProbeTarget, setNewProbeTarget] = useState("");
  const [newProbeRegex, setNewProbeRegex] = useState("");
  const [newProbePayloadKb, setNewProbePayloadKb] = useState(512);
  const [newProbeTimeoutMs, setNewProbeTimeoutMs] = useState(10000);

  // Speed test execution options & state
  const [localStarting, setLocalStarting] = useState(false);
  const [isPausing, setIsPausing] = useState(false);
  const [pendingLargeRunTier, setPendingLargeRunTier] = useState<SpeedTestTier | null>(null);
  const [switchingNodeId, setSwitchingNodeId] = useState<string | null>(null);
  const [addingToGroupNodeId, setAddingToGroupNodeId] = useState<string | null>(null);
  // Locked row order during streaming speed test so rows never jump mid-test
  const [lockedOrderMap, setLockedOrderMap] = useState<Map<string, number> | null>(null);

  // Filters, sorting & pagination
  const [searchQuery, setSearchQuery] = useState("");
  const [sourceFilter, setSourceFilter] = useState<string>(() => initialSubId || "all");
  const prevInitialSubIdRef = useRef<string | null | undefined>(initialSubId);
  const [groupFilter, setGroupFilter] = useState<string>("all");
  const [filterContinent, setFilterContinent] = useState<ContinentId>("all");
  const [regionFilter, setRegionFilter] = useState<string>("all");
  const [onlyGolden, setOnlyGolden] = useState(false);
  const [onlyTested, setOnlyTested] = useState(false);
  const [onlyGoogleClean, setOnlyGoogleClean] = useState(false);
  const [onlyAiUnlocked, setOnlyAiUnlocked] = useState(false);
  const [sortKey, setSortKey] = useState<SortKey>("latency");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState<number>(50);

  // Multi-selection & Ctrl+left-button drag selection
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() => new Set());
  const [lastAnchorId, setLastAnchorId] = useState<string | null>(null);
  const [ctrlHeld, setCtrlHeld] = useState(false);
  const [modifierHeld, setModifierHeld] = useState(false);

  // Streaming row pulse highlights when new probe snapshots arrive
  const [recentFlashIds, setRecentFlashIds] = useState<Set<string>>(() => new Set());
  const prevTestedAtRef = useRef<Record<string, string>>({});
  const hydratedFlashRef = useRef(false);
  const flashTimersRef = useRef<Map<string, number>>(new Map());

  // Run control refs
  const mountedRef = useRef(true);
  const previewTimersRef = useRef<number[]>([]);
  const previewCancelRef = useRef(false);
  const runOwnedBySelfRef = useRef(false);
  const pausingRef = useRef(false);
  const externalPauseWaitingRef = useRef(false);
  const suppressClickRef = useRef(false);
  const suppressClickTimerRef = useRef<number | null>(null);
  const latestOrderedIdsRef = useRef<string[]>([]);
  const ctrlDragRef = useRef<CtrlDragState>({
    dragging: false,
    action: "add",
    visitedIds: new Set<string>(),
  });

  const isRunning = probeProgress.running || localStarting;

  const persistProbeStates = useCallback((list: ProbeItem[], keepaliveOn: boolean) => {
    const nextMap: Record<string, boolean> = {
      ...loadPersistedProbeEnabledMap(),
      [KEEPALIVE_STORAGE_KEY]: keepaliveOn,
    };
    for (const item of list) {
      nextMap[item.id] = item.kind === "keepalive" ? keepaliveOn : item.enabled;
    }
    savePersistedProbeEnabledMap(nextMap);
  }, []);

  /** Single source of truth for Keep-Alive: syncs header checkbox, settings drawer & localStorage */
  const setKeepaliveSynced = useCallback(
    (next: boolean) => {
      includeKeepaliveRef.current = next;
      setIncludeKeepalive(next);
      setProbeList((prev) => {
        const updated = prev.map((p) => (p.kind === "keepalive" ? { ...p, enabled: next } : p));
        persistProbeStates(updated, next);
        return updated;
      });
    },
    [persistProbeStates]
  );

  const captureCurrentRowOrder = useCallback(() => {
    const order = new Map<string, number>();
    let idx = 0;
    for (const id of latestOrderedIdsRef.current) {
      if (!order.has(id)) {
        order.set(id, idx);
        idx += 1;
      }
    }
    for (const node of nodes) {
      if (!order.has(node.id)) {
        order.set(node.id, idx);
        idx += 1;
      }
    }
    setLockedOrderMap(order);
  }, [nodes]);

  // Lock row order for externally-started runs and release automatically once finished
  useEffect(() => {
    if (isRunning) {
      setLockedOrderMap((prev) => {
        if (prev !== null) return prev;
        const order = new Map<string, number>();
        let idx = 0;
        for (const id of latestOrderedIdsRef.current) {
          if (!order.has(id)) {
            order.set(id, idx);
            idx += 1;
          }
        }
        for (const node of nodes) {
          if (!order.has(node.id)) {
            order.set(node.id, idx);
            idx += 1;
          }
        }
        return order;
      });
    } else {
      setLockedOrderMap((prev) => (prev === null ? prev : null));
    }
  }, [isRunning, nodes]);

  const clearPreviewTimers = useCallback(() => {
    for (const id of previewTimersRef.current) {
      window.clearTimeout(id);
    }
    previewTimersRef.current = [];
  }, []);

  // Cleanup all timers on unmount
  useEffect(() => {
    mountedRef.current = true;
    const flashTimers = flashTimersRef.current;
    return () => {
      mountedRef.current = false;
      previewCancelRef.current = true;
      clearPreviewTimers();
      if (!inTauri && runOwnedBySelfRef.current) {
        const st = appStore.getState();
        if (st.probeProgress.running) {
          appActions.setProbeProgress({
            running: false,
            currentNodeName: null,
            cancelled: true,
          });
          appActions.setMascotState("idle");
        }
      }
      if (suppressClickTimerRef.current !== null) {
        window.clearTimeout(suppressClickTimerRef.current);
        suppressClickTimerRef.current = null;
      }
      for (const timerId of flashTimers.values()) {
        window.clearTimeout(timerId);
      }
      flashTimers.clear();
    };
  }, [clearPreviewTimers, inTauri]);

  // Load probe definitions from backend while restoring persisted enabled & keepalive states
  useEffect(() => {
    let active = true;
    void catcloudApi
      .listProbeDefinitions()
      .then((defs) => {
        if (!active) return;
        if (defs.length > 0 || inTauri) {
          const persisted = loadPersistedProbeEnabledMap();
          const keepaliveOn = includeKeepaliveRef.current;
          const mapped = defs.map((d) => fromProbeDefinition(d, persisted, keepaliveOn));
          if (!inTauri) {
            const existingIds = new Set(mapped.map((item) => item.id));
            for (const fallback of INITIAL_PROBES) {
              if (!existingIds.has(fallback.id)) {
                mapped.push({
                  ...fallback,
                  enabled:
                    fallback.kind === "keepalive"
                      ? keepaliveOn
                      : typeof persisted[fallback.id] === "boolean"
                        ? persisted[fallback.id]
                        : fallback.enabled,
                });
              }
            }
          }
          setProbeList(mapped);
        }
      })
      .catch((err) => {
        if (active && inTauri) {
          appActions.showToast(`加载测速项目失败：${formatErrorMessage(err)}`, "warn");
        }
      });
    return () => {
      active = false;
    };
  }, [inTauri]);

  // Detect newly arrived streaming probe snapshots to trigger soft row pulse
  useEffect(() => {
    const currentMap: Record<string, string> = {};
    for (const [nodeId, snap] of Object.entries(probes)) {
      if (snap?.tested_at) {
        currentMap[nodeId] = snap.tested_at;
      }
    }

    if (!hydratedFlashRef.current) {
      if (initialized || Object.keys(currentMap).length > 0) {
        hydratedFlashRef.current = true;
        prevTestedAtRef.current = currentMap;
      }
      return;
    }

    const updatedIds: string[] = [];
    for (const [nodeId, ts] of Object.entries(currentMap)) {
      if (prevTestedAtRef.current[nodeId] !== ts) {
        updatedIds.push(nodeId);
      }
    }
    prevTestedAtRef.current = currentMap;

    if (updatedIds.length === 0) return;

    setRecentFlashIds((prev) => {
      const next = new Set(prev);
      for (const id of updatedIds) {
        next.add(id);
      }
      return next;
    });

    for (const id of updatedIds) {
      const existingTimer = flashTimersRef.current.get(id);
      if (existingTimer !== undefined) {
        window.clearTimeout(existingTimer);
      }
      const timerId = window.setTimeout(() => {
        flashTimersRef.current.delete(id);
        setRecentFlashIds((prev) => {
          if (!prev.has(id)) return prev;
          const next = new Set(prev);
          next.delete(id);
          return next;
        });
      }, 1500);
      flashTimersRef.current.set(id, timerId);
    }
  }, [probes, initialized]);

  // Reset pausing indicator & emit toast when an externally-started run finishes pausing
  useEffect(() => {
    if (!probeProgress.running) {
      if (isPausing && !runOwnedBySelfRef.current) {
        setIsPausing(false);
        pausingRef.current = false;
      }
      if (externalPauseWaitingRef.current) {
        externalPauseWaitingRef.current = false;
        appActions.showToast(
          `已暂停测速，已测完的 ${probeProgress.completed} 个节点结果已全部保留`,
          "info"
        );
      }
    }
  }, [probeProgress.running, probeProgress.completed, isPausing]);

  // Global keyboard & mouse listeners for Ctrl+left-drag and Shift range multi-select
  useEffect(() => {
    const endCtrlDrag = () => {
      ctrlDragRef.current.dragging = false;
      ctrlDragRef.current.visitedIds.clear();
    };

    const resetAllModifierState = () => {
      setCtrlHeld(false);
      setModifierHeld(false);
      endCtrlDrag();
      suppressClickRef.current = false;
    };

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Control" || e.key === "Meta") {
        setCtrlHeld(true);
        setModifierHeld(true);
      } else if (e.key === "Shift") {
        setModifierHeld(true);
      }
    };

    const handleKeyUp = (e: KeyboardEvent) => {
      if (e.key === "Control" || e.key === "Meta") {
        setCtrlHeld(false);
        if (!e.shiftKey) setModifierHeld(false);
        endCtrlDrag();
      } else if (e.key === "Shift") {
        if (!e.ctrlKey && !e.metaKey) setModifierHeld(false);
      }
    };

    const handleMouseUp = () => {
      endCtrlDrag();
      if (suppressClickRef.current) {
        if (suppressClickTimerRef.current !== null) {
          window.clearTimeout(suppressClickTimerRef.current);
        }
        // Clear after the synchronous click event that immediately follows mouseup
        suppressClickTimerRef.current = window.setTimeout(() => {
          suppressClickRef.current = false;
          suppressClickTimerRef.current = null;
        }, 0);
      }
    };

    const handleVisibility = () => {
      if (document.visibilityState !== "visible") {
        resetAllModifierState();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    window.addEventListener("keyup", handleKeyUp);
    window.addEventListener("mouseup", handleMouseUp);
    window.addEventListener("blur", resetAllModifierState);
    document.addEventListener("visibilitychange", handleVisibility);

    return () => {
      window.removeEventListener("keydown", handleKeyDown);
      window.removeEventListener("keyup", handleKeyUp);
      window.removeEventListener("mouseup", handleMouseUp);
      window.removeEventListener("blur", resetAllModifierState);
      document.removeEventListener("visibilitychange", handleVisibility);
    };
  }, []);

  const subNameById = useMemo(() => {
    const map = new Map<string, string>();
    for (const sub of subscriptions) {
      map.set(sub.id, sub.name);
    }
    return map;
  }, [subscriptions]);

  const sourceOptions = useMemo(() => {
    const seen = new Map<string, string>();
    for (const sub of subscriptions) {
      seen.set(sub.id, sub.name);
    }
    for (const node of nodes) {
      if (!seen.has(node.sub_id)) {
        seen.set(node.sub_id, node.sub_id);
      }
    }
    return Array.from(seen.entries()).map(([id, name]) => ({ id, name }));
  }, [subscriptions, nodes]);

  useEffect(() => {
    if (prevInitialSubIdRef.current !== initialSubId) {
      prevInitialSubIdRef.current = initialSubId;
      setSourceFilter(initialSubId || "all");
      setPage(1);
    }
  }, [initialSubId]);

  useEffect(() => {
    if (!initialized || sourceFilter === "all") return;
    if (!sourceOptions.some((opt) => opt.id === sourceFilter)) {
      setSourceFilter("all");
    }
  }, [initialized, sourceFilter, sourceOptions]);

  // Pre-build O(1) lookup structures per group: Map<groupId, Set<nodeId>> & compiled dynamic filters
  const groupMemberSetById = useMemo(() => {
    const map = new Map<string, Set<string>>();
    for (const g of groups) {
      map.set(g.id, new Set(g.member_node_ids));
    }
    return map;
  }, [groups]);

  const groupDynamicFilterById = useMemo(() => {
    const map = new Map<string, CompiledDynamicFilter | null>();
    for (const g of groups) {
      map.set(g.id, compileDynamicFilter(g.dynamic_filter));
    }
    return map;
  }, [groups]);

  const selectedGroupObj = useMemo(
    () => (groupFilter === "all" ? null : groups.find((g) => g.id === groupFilter) ?? null),
    [groups, groupFilter]
  );

  const selectedGroupMemberSet = selectedGroupObj
    ? groupMemberSetById.get(selectedGroupObj.id)
    : undefined;
  const selectedGroupDynamicFilter = selectedGroupObj
    ? (groupDynamicFilterById.get(selectedGroupObj.id) ?? null)
    : null;

  const nodesScopedForRegion = useMemo(() => {
    return nodes.filter((node) => {
      if (sourceFilter !== "all" && node.sub_id !== sourceFilter) return false;
      if (
        selectedGroupObj &&
        !nodeBelongsToGroup(
          node,
          selectedGroupMemberSet,
          selectedGroupDynamicFilter,
          probes
        )
      ) {
        return false;
      }
      return true;
    });
  }, [nodes, sourceFilter, selectedGroupObj, selectedGroupMemberSet, selectedGroupDynamicFilter, probes]);

  const regionStats = useMemo(
    () => buildContinentRegionStats(nodesScopedForRegion),
    [nodesScopedForRegion]
  );

  useEffect(() => {
    if (filterContinent !== "all" && regionStats.continentCounts[filterContinent] === 0) {
      setFilterContinent("all");
      setRegionFilter("all");
      return;
    }
    if (
      regionFilter !== "all" &&
      !(regionStats.regionsByContinent[filterContinent] ?? []).some((r) => r.code === regionFilter)
    ) {
      setRegionFilter("all");
    }
  }, [regionStats, filterContinent, regionFilter]);

  const nodeIdSet = useMemo(() => new Set(nodes.map((n) => n.id)), [nodes]);

  const validSelectedIds = useMemo(() => {
    const out = new Set<string>();
    for (const id of selectedIds) {
      if (nodeIdSet.has(id)) out.add(id);
    }
    return out;
  }, [selectedIds, nodeIdSet]);

  const filteredRows = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    const list = nodes
      .map((node) => {
        const snap = probes[node.id];
        const sourceName = subNameById.get(node.sub_id) ?? node.sub_id;
        const regionCode = resolveNodeRegionCode(node);
        const regionLabel = getRegionLabel(regionCode);
        const unlocks = {
          gemini:
            snap?.unlocked_sites?.gemini ??
            snap?.unlocked_sites?.gemini_aistudio ??
            snap?.unlocked_sites?.google_ai ??
            false,
          chatgpt: snap?.unlocked_sites?.chatgpt ?? false,
          claude: snap?.unlocked_sites?.claude ?? false,
          windsurf:
            snap?.unlocked_sites?.windsurf ?? snap?.per_probe_ok?.builtin_unlock_windsurf ?? false,
        };
        const hasUnlockData = Boolean(
          snap &&
            (Object.keys(snap.unlocked_sites ?? {}).length > 0 ||
              snap.per_probe_ok?.builtin_unlock_windsurf !== undefined ||
              snap.google_clean !== null)
        );
        const unlockScore = Object.values(unlocks).filter(Boolean).length;
        const isGoogleClean = snap?.google_clean === true;
        const hasMeasuredSpeed = Boolean(
          (snap?.up_mbps !== null && snap?.up_mbps !== undefined && snap.up_mbps > 0) ||
            (snap?.down_mbps !== null && snap?.down_mbps !== undefined && snap.down_mbps > 0)
        );
        const isGolden = Boolean(
          snap && snap.ok !== false && isGoogleClean && unlockScore > 0 && hasMeasuredSpeed
        );
        const regionMismatch =
          Boolean(snap?.google_risk_mismatch) ||
          Boolean(
            snap?.cf_loc &&
              snap?.yt_gl &&
              snap.yt_gl.toUpperCase() !== regionCode
          );
        return {
          node,
          snap,
          sourceName,
          regionCode,
          regionLabel,
          unlocks,
          hasUnlockData,
          unlockScore,
          isGoogleClean,
          isGolden,
          regionMismatch,
        };
      })
      .filter((row) => {
        if (q) {
          const hay = `${row.node.name} ${row.sourceName} ${row.regionCode} ${row.regionLabel}`.toLowerCase();
          if (!hay.includes(q)) return false;
        }
        if (sourceFilter !== "all" && row.node.sub_id !== sourceFilter) return false;
        if (
          selectedGroupObj &&
          !nodeBelongsToGroup(
            row.node,
            selectedGroupMemberSet,
            selectedGroupDynamicFilter,
            probes
          )
        ) {
          return false;
        }
        if (!nodeMatchesContinentAndRegion(row.node, filterContinent, regionFilter)) return false;
        if (onlyGolden && !row.isGolden) return false;
        if (onlyTested && !row.snap) return false;
        if (onlyGoogleClean && !row.isGoogleClean) return false;
        if (onlyAiUnlocked && row.unlockScore === 0) return false;
        return true;
      });

    if (isRunning && lockedOrderMap) {
      list.sort((a, b) => {
        const aIdx = lockedOrderMap.get(a.node.id) ?? Number.MAX_SAFE_INTEGER;
        const bIdx = lockedOrderMap.get(b.node.id) ?? Number.MAX_SAFE_INTEGER;
        if (aIdx !== bIdx) return aIdx - bIdx;
        return a.node.name.localeCompare(b.node.name);
      });
      return list;
    }

    list.sort((a, b) => {
      let diff = 0;
      switch (sortKey) {
        case "name":
          diff = a.node.name.localeCompare(b.node.name);
          break;
        case "source":
          diff = a.sourceName.localeCompare(b.sourceName);
          break;
        case "latency": {
          const aVal = a.snap?.latency_ms;
          const bVal = b.snap?.latency_ms;
          const aHas = aVal !== null && aVal !== undefined && a.snap?.ok !== false;
          const bHas = bVal !== null && bVal !== undefined && b.snap?.ok !== false;
          if (aHas !== bHas) return aHas ? -1 : 1;
          if (!aHas && !bHas) return a.node.name.localeCompare(b.node.name);
          diff = (aVal ?? 99999) - (bVal ?? 99999);
          break;
        }
        case "up": {
          const aVal = a.snap?.up_mbps;
          const bVal = b.snap?.up_mbps;
          const aHas = aVal !== null && aVal !== undefined;
          const bHas = bVal !== null && bVal !== undefined;
          if (aHas !== bHas) return aHas ? -1 : 1;
          if (!aHas && !bHas) return a.node.name.localeCompare(b.node.name);
          diff = (aVal ?? -1) - (bVal ?? -1);
          break;
        }
        case "down": {
          const aVal = a.snap?.down_mbps;
          const bVal = b.snap?.down_mbps;
          const aHas = aVal !== null && aVal !== undefined;
          const bHas = bVal !== null && bVal !== undefined;
          if (aHas !== bHas) return aHas ? -1 : 1;
          if (!aHas && !bHas) return a.node.name.localeCompare(b.node.name);
          diff = (aVal ?? -1) - (bVal ?? -1);
          break;
        }
        case "google": {
          const aHas = a.snap?.google_clean !== null && a.snap?.google_clean !== undefined;
          const bHas = b.snap?.google_clean !== null && b.snap?.google_clean !== undefined;
          if (aHas !== bHas) return aHas ? -1 : 1;
          if (!aHas && !bHas) return a.node.name.localeCompare(b.node.name);
          diff = (a.snap?.google_clean ? 1 : 0) - (b.snap?.google_clean ? 1 : 0);
          break;
        }
        case "unlocks": {
          if (a.hasUnlockData !== b.hasUnlockData) return a.hasUnlockData ? -1 : 1;
          if (!a.hasUnlockData && !b.hasUnlockData) return a.node.name.localeCompare(b.node.name);
          diff = a.unlockScore - b.unlockScore;
          break;
        }
      }
      if (diff === 0) return a.node.name.localeCompare(b.node.name);
      return sortDir === "asc" ? diff : -diff;
    });

    return list;
  }, [
    nodes,
    probes,
    subNameById,
    searchQuery,
    sourceFilter,
    selectedGroupObj,
    selectedGroupMemberSet,
    selectedGroupDynamicFilter,
    filterContinent,
    regionFilter,
    onlyGolden,
    onlyTested,
    onlyGoogleClean,
    onlyAiUnlocked,
    sortKey,
    sortDir,
    isRunning,
    lockedOrderMap,
  ]);

  latestOrderedIdsRef.current = filteredRows.map((r) => r.node.id);

  const totalFiltered = filteredRows.length;
  const totalPages = Math.max(1, Math.ceil(totalFiltered / pageSize));
  const safePage = Math.min(page, totalPages);
  const pageStartIdx = (safePage - 1) * pageSize;
  const pagedRows = useMemo(
    () => filteredRows.slice(pageStartIdx, pageStartIdx + pageSize),
    [filteredRows, pageStartIdx, pageSize]
  );

  const selectedCount = validSelectedIds.size;
  const selectedInFilteredCount = useMemo(
    () => filteredRows.filter((r) => validSelectedIds.has(r.node.id)).length,
    [filteredRows, validSelectedIds]
  );
  const selectedOutsideFiltered = selectedCount - selectedInFilteredCount;
  const allFilteredSelected =
    totalFiltered > 0 && selectedInFilteredCount === totalFiltered;
  const allPageSelected =
    pagedRows.length > 0 && pagedRows.every((r) => validSelectedIds.has(r.node.id));

  const hasActiveFilters =
    searchQuery.trim().length > 0 ||
    sourceFilter !== "all" ||
    groupFilter !== "all" ||
    filterContinent !== "all" ||
    regionFilter !== "all" ||
    onlyGolden ||
    onlyTested ||
    onlyGoogleClean ||
    onlyAiUnlocked;

  const enabledProbeCount = useMemo(
    () => probeList.filter((p) => p.enabled).length,
    [probeList]
  );

  // Auto-dismiss large-run confirmation bar when selection changes or list shrinks
  useEffect(() => {
    if (pendingLargeRunTier && (selectedCount > 0 || totalFiltered <= 50 || isRunning)) {
      setPendingLargeRunTier(null);
    }
  }, [pendingLargeRunTier, selectedCount, totalFiltered, isRunning]);

  // Selection mutation helpers
  const applySelectionAction = useCallback((nodeId: string, action: "add" | "remove") => {
    setSelectedIds((prev) => {
      const has = prev.has(nodeId);
      if (action === "add" && has) return prev;
      if (action === "remove" && !has) return prev;
      const next = new Set(prev);
      if (action === "add") next.add(nodeId);
      else next.delete(nodeId);
      return next;
    });
  }, []);

  const toggleNodeSelection = useCallback((nodeId: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(nodeId)) next.delete(nodeId);
      else next.add(nodeId);
      return next;
    });
    setLastAnchorId(nodeId);
  }, []);

  const selectRangeTo = useCallback(
    (targetId: string) => {
      if (!lastAnchorId) {
        applySelectionAction(targetId, "add");
        setLastAnchorId(targetId);
        return;
      }
      const anchorIdx = filteredRows.findIndex((r) => r.node.id === lastAnchorId);
      const targetIdx = filteredRows.findIndex((r) => r.node.id === targetId);
      if (anchorIdx === -1 || targetIdx === -1) {
        applySelectionAction(targetId, "add");
        setLastAnchorId(targetId);
        return;
      }
      const start = Math.min(anchorIdx, targetIdx);
      const end = Math.max(anchorIdx, targetIdx);
      setSelectedIds((prev) => {
        const next = new Set(prev);
        for (let i = start; i <= end; i++) {
          next.add(filteredRows[i].node.id);
        }
        return next;
      });
    },
    [filteredRows, lastAnchorId, applySelectionAction]
  );

  const handleRowMouseDown = (e: ReactMouseEvent<HTMLTableRowElement>, nodeId: string) => {
    const targetEl = e.target as HTMLElement | null;
    if (targetEl?.closest("button") || targetEl?.closest("input")) return;

    if (e.shiftKey) {
      e.preventDefault();
      suppressClickRef.current = false;
      return;
    }

    if ((e.ctrlKey || e.metaKey) && e.button === 0) {
      e.preventDefault();
      const nextAction: "add" | "remove" = validSelectedIds.has(nodeId) ? "remove" : "add";
      ctrlDragRef.current = {
        dragging: true,
        action: nextAction,
        visitedIds: new Set<string>([nodeId]),
      };
      applySelectionAction(nodeId, nextAction);
      setLastAnchorId(nodeId);
      suppressClickRef.current = true;
      return;
    }

    suppressClickRef.current = false;
  };

  const handleRowMouseEnter = (e: ReactMouseEvent<HTMLTableRowElement>, nodeId: string) => {
    const drag = ctrlDragRef.current;
    if (!drag.dragging) return;
    // Strictly require Ctrl/Meta AND primary mouse button still pressed
    if ((e.buttons & 1) === 0 || !(e.ctrlKey || e.metaKey)) {
      drag.dragging = false;
      drag.visitedIds.clear();
      return;
    }
    if (drag.visitedIds.has(nodeId)) return;

    drag.visitedIds.add(nodeId);
    applySelectionAction(nodeId, drag.action);
    setLastAnchorId(nodeId);
  };

  const handleRowClick = (e: ReactMouseEvent<HTMLTableRowElement>, nodeId: string) => {
    const targetEl = e.target as HTMLElement | null;
    if (targetEl?.closest("button") || targetEl?.closest("input")) return;

    if (suppressClickRef.current) {
      suppressClickRef.current = false;
      return;
    }

    if (e.shiftKey) {
      selectRangeTo(nodeId);
      return;
    }

    toggleNodeSelection(nodeId);
  };

  const handleSelectAllFiltered = () => {
    if (totalFiltered === 0) return;
    if (allFilteredSelected) {
      setSelectedIds((prev) => {
        const next = new Set(prev);
        for (const r of filteredRows) next.delete(r.node.id);
        return next;
      });
    } else {
      setSelectedIds((prev) => {
        const next = new Set(prev);
        for (const r of filteredRows) next.add(r.node.id);
        return next;
      });
    }
  };

  const handleSelectTop20 = () => {
    if (totalFiltered === 0) return;
    const topIds = filteredRows.slice(0, 20).map((r) => r.node.id);
    setSelectedIds(new Set(topIds));
    setLastAnchorId(topIds[topIds.length - 1] ?? null);
  };

  const handleClearSelection = () => {
    setSelectedIds(new Set());
    setLastAnchorId(null);
  };

  const handleTogglePageSelection = () => {
    if (pagedRows.length === 0) return;
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (allPageSelected) {
        for (const r of pagedRows) next.delete(r.node.id);
      } else {
        for (const r of pagedRows) next.add(r.node.id);
      }
      return next;
    });
  };

  const handleResetFilters = () => {
    setSearchQuery("");
    setSourceFilter("all");
    setGroupFilter("all");
    setFilterContinent("all");
    setRegionFilter("all");
    setOnlyGolden(false);
    setOnlyTested(false);
    setOnlyGoogleClean(false);
    setOnlyAiUnlocked(false);
    setPage(1);
  };

  const resolveProbeIdsForRun = (
    tier: SpeedTestTier,
    effectiveKeepalive: boolean
  ): string[] | null => {
    if (probeList.length === 0) {
      return [];
    }
    const enabledNonKeepalive = probeList.filter((p) => p.kind !== "keepalive" && p.enabled);
    const keepaliveProbes = effectiveKeepalive
      ? probeList.filter((p) => p.kind === "keepalive")
      : [];

    if (enabledNonKeepalive.length === 0 && keepaliveProbes.length === 0) {
      appActions.showToast("请先在「测速项目设置」中开启至少一项测速项目", "warn");
      return null;
    }

    const ids = new Set<string>(enabledNonKeepalive.map((p) => p.id));
    for (const kp of keepaliveProbes) {
      ids.add(kp.id);
    }

    const activeKinds = new Set(
      probeList.filter((p) => ids.has(p.id)).map((p) => p.kind)
    );
    if (tier === "latency" && !activeKinds.has("latency")) {
      appActions.showToast("请先在「测速项目设置」中开启「基础延迟」", "warn");
      return null;
    }

    return Array.from(ids);
  };

  const executeProbes = async (
    targetNodeIds: string[],
    tier: SpeedTestTier,
    forceSkipKeepalive = false
  ) => {
    if (isRunning) return;
    if (targetNodeIds.length === 0) {
      appActions.showToast("请先筛选或勾选至少一个节点后再开始测速", "warn");
      return;
    }

    const effectiveKeepalive = forceSkipKeepalive ? false : includeKeepalive;
    const probeIds = resolveProbeIdsForRun(tier, effectiveKeepalive);
    if (probeIds === null) return;

    const nodeNameById = new Map(nodes.map((n) => [n.id, n.name]));
    const firstNodeName = nodeNameById.get(targetNodeIds[0]) ?? null;

    // Lock current visible row order immediately before starting streaming test
    captureCurrentRowOrder();
    setPendingLargeRunTier(null);
    setLocalStarting(true);
    setIsPausing(false);
    pausingRef.current = false;
    runOwnedBySelfRef.current = true;
    previewCancelRef.current = false;
    clearPreviewTimers();

    appActions.setMascotState("searching");
    appActions.setProbeProgress({
      running: true,
      completed: 0,
      total: targetNodeIds.length,
      currentNodeName: firstNodeName,
      cancelled: false,
    });

    const effectiveUsePreaccel = usePreaccelForProbe && hasEnabledPreAccelRelay;

    if (inTauri) {
      try {
        const result = await catcloudApi.runIsolatedProbes(
          targetNodeIds,
          probeIds,
          tier,
          effectiveKeepalive,
          effectiveUsePreaccel
        );
        if (result.snapshots && Object.keys(result.snapshots).length > 0) {
          appActions.syncProbes(
            mergeProbeSnapshotsPreserveOld(appStore.getState().probes, result.snapshots)
          );
        }

        const finalCompleted = Math.max(
          result.probed_count,
          appStore.getState().probeProgress.completed
        );
        const wasCancelled = Boolean(result.cancelled) || pausingRef.current;
        const preaccelTag = result.used_preaccel
          ? `（已走 443 提速${result.preaccel_relay_name ? `：${result.preaccel_relay_name}` : ""}）`
          : "";

        appActions.setProbeProgress({
          running: false,
          completed: finalCompleted,
          total: result.total_count ?? targetNodeIds.length,
          currentNodeName: null,
          cancelled: wasCancelled,
        });
        appActions.setMascotState("idle");

        if (wasCancelled) {
          if (mountedRef.current) {
            appActions.showToast(
              `已暂停测速，已测完的 ${finalCompleted} 个节点结果已全部保留`,
              "info"
            );
          }
        } else if (!result.core_available) {
          appActions.showToast(
            result.errors[0] ?? "测速引擎尚未就绪，请先检查内核配置",
            "warn"
          );
        } else if (result.errors.length > 0 && result.probed_count === 0) {
          appActions.showToast(`测速未能完成：${result.errors[0]}`, "warn");
        } else if (result.errors.length > 0) {
          appActions.showToast(
            `${TIER_LABELS[tier]}完成${preaccelTag}：已更新 ${result.probed_count} 个节点（${result.errors.length} 个超时或跳过）`,
            "info"
          );
        } else {
          appActions.showToast(
            `${TIER_LABELS[tier]}完成${preaccelTag}，已更新 ${result.probed_count} 个节点结果`,
            "ok"
          );
        }
      } catch (err) {
        appActions.setProbeProgress({
          running: false,
          currentNodeName: null,
          cancelled: pausingRef.current,
        });
        appActions.setMascotState("idle");
        appActions.showToast(`测速执行失败：${formatErrorMessage(err)}`, "warn");
      } finally {
        runOwnedBySelfRef.current = false;
        pausingRef.current = false;
        setLocalStarting(false);
        setIsPausing(false);
      }
      return;
    }

    // Browser preview streaming simulation (120ms per node, supports pause & full retention)
    const total = targetNodeIds.length;
    const stepNext = (index: number) => {
      if (previewCancelRef.current) return;
      if (index >= total) {
        appActions.setProbeProgress({
          running: false,
          completed: total,
          total,
          currentNodeName: null,
          cancelled: false,
        });
        appActions.setMascotState("idle");
        runOwnedBySelfRef.current = false;
        pausingRef.current = false;
        setLocalStarting(false);
        setIsPausing(false);
        appActions.showToast(
          `预览模式：${TIER_LABELS[tier]}完成，已逐条更新 ${total} 个节点`,
          "ok"
        );
        return;
      }

      const nodeId = targetNodeIds[index];
      const nodeName = nodeNameById.get(nodeId) ?? nodeId;
      appActions.setProbeProgress({
        running: true,
        completed: index,
        total,
        currentNodeName: nodeName,
        cancelled: false,
      });

      const timerId = window.setTimeout(() => {
        previewTimersRef.current = previewTimersRef.current.filter((id) => id !== timerId);
        if (previewCancelRef.current) return;

        void catcloudApi
          .runIsolatedProbes([nodeId], probeIds, tier, effectiveKeepalive, effectiveUsePreaccel)
          .then((res) => {
            if (previewCancelRef.current) return;
            const rawSnap = res.snapshots[nodeId];
            if (rawSnap) {
              const jitterDelta = Math.round((Math.random() - 0.5) * 14);
              const nextLatency =
                rawSnap.latency_ms !== null
                  ? Math.max(18, Math.round(rawSnap.latency_ms + jitterDelta))
                  : 78;
              const streamedSnap: ProbeSnapshot = {
                ...rawSnap,
                tested_at: new Date().toISOString(),
                latency_ms: nextLatency,
              };
              appActions.syncProbes(
                mergeProbeSnapshotsPreserveOld(appStore.getState().probes, {
                  [nodeId]: streamedSnap,
                })
              );
            }
            appActions.setProbeProgress({
              running: true,
              completed: index + 1,
              total,
              currentNodeName: nodeName,
              cancelled: false,
            });
            stepNext(index + 1);
          })
          .catch(() => {
            if (previewCancelRef.current) return;
            stepNext(index + 1);
          });
      }, 120);

      previewTimersRef.current.push(timerId);
    };

    stepNext(0);
  };

  const handlePrimaryTestClick = (tier: SpeedTestTier) => {
    if (isRunning) return;
    if (nodes.length === 0) {
      appActions.showToast("当前还没有节点，请先在「订阅与导入」中导入", "warn");
      return;
    }

    if (selectedCount > 0) {
      // Preserve current visible order first, then any selected nodes outside filter
      const filteredOrder = filteredRows
        .filter((r) => validSelectedIds.has(r.node.id))
        .map((r) => r.node.id);
      const inFilteredSet = new Set(filteredOrder);
      const restIds = nodes
        .filter((n) => validSelectedIds.has(n.id) && !inFilteredSet.has(n.id))
        .map((n) => n.id);
      void executeProbes([...filteredOrder, ...restIds], tier);
      return;
    }

    if (totalFiltered === 0) {
      appActions.showToast("当前筛选条件下没有可测速的节点", "warn");
      return;
    }

    if (totalFiltered > 50) {
      setPendingLargeRunTier(tier);
      return;
    }

    void executeProbes(
      filteredRows.map((r) => r.node.id),
      tier
    );
  };

  const handlePauseTest = async () => {
    if (!isRunning || isPausing) return;
    setIsPausing(true);
    pausingRef.current = true;

    if (!inTauri) {
      previewCancelRef.current = true;
      clearPreviewTimers();
      try {
        await catcloudApi.cancelIsolatedProbes();
      } catch {
        /* ignore mock cancel errors */
      }
      const doneCount = appStore.getState().probeProgress.completed;
      const total = appStore.getState().probeProgress.total;
      appActions.setProbeProgress({
        running: false,
        completed: doneCount,
        total,
        currentNodeName: null,
        cancelled: true,
      });
      appActions.setMascotState("idle");
      runOwnedBySelfRef.current = false;
      pausingRef.current = false;
      setLocalStarting(false);
      setIsPausing(false);
      appActions.showToast(
        `已暂停测速，已测完的 ${doneCount} 个节点结果已全部保留`,
        "info"
      );
      return;
    }

    try {
      const wasRunning = await catcloudApi.cancelIsolatedProbes();
      if (!runOwnedBySelfRef.current) {
        if (wasRunning) {
          externalPauseWaitingRef.current = true;
        } else {
          const doneCount = appStore.getState().probeProgress.completed;
          appActions.setProbeProgress({
            running: false,
            currentNodeName: null,
            cancelled: true,
          });
          appActions.setMascotState("idle");
          setIsPausing(false);
          pausingRef.current = false;
          appActions.showToast(
            `已暂停测速，已测完的 ${doneCount} 个节点结果已全部保留`,
            "info"
          );
        }
      }
    } catch (err) {
      setIsPausing(false);
      pausingRef.current = false;
      appActions.showToast(`暂停测速失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const activeGroupForQuickAdd = useMemo(() => {
    if (groups.length === 0) return null;
    if (runtime.active_group_id) {
      const found = groups.find((g) => g.id === runtime.active_group_id);
      if (found) return found;
    }
    if (groupFilter !== "all") {
      const filtered = groups.find((g) => g.id === groupFilter);
      if (filtered) return filtered;
    }
    return groups[0] ?? null;
  }, [groups, runtime.active_group_id, groupFilter]);

  const activeGroupMemberSet = useMemo(
    () => new Set(activeGroupForQuickAdd?.member_node_ids ?? []),
    [activeGroupForQuickAdd]
  );

  // Always switch directly in single-node mode without mutating multi-group membership
  const handleSwitchToNode = async (node: ProxyNode) => {
    if (switchingNodeId) return;
    setSwitchingNodeId(node.id);
    try {
      await appActions.selectSingleNode(node.id);
    } finally {
      setSwitchingNodeId(null);
    }
  };

  const handleAddNodeToActiveGroup = async (node: ProxyNode) => {
    if (!activeGroupForQuickAdd || addingToGroupNodeId) return;
    if (activeGroupMemberSet.has(node.id)) {
      appActions.showToast(
        `「${node.name}」已在「${formatGroupDisplayName(activeGroupForQuickAdd.name)}」中`,
        "info"
      );
      return;
    }
    setAddingToGroupNodeId(node.id);
    try {
      const updated = await catcloudApi.updateMultiGroupMembers(activeGroupForQuickAdd.id, [
        ...activeGroupForQuickAdd.member_node_ids,
        node.id,
      ]);
      appActions.syncGroups(
        appStore.getState().groups.map((g) => (g.id === updated.id ? updated : g))
      );
      appActions.showToast(
        `已将「${node.name}」加入「${formatGroupDisplayName(updated.name)}」`,
        "ok"
      );
    } catch (err) {
      appActions.showToast(`加入多选组失败：${formatErrorMessage(err)}`, "warn");
    } finally {
      setAddingToGroupNodeId(null);
    }
  };

  const handleAddProbe = async (ev: FormEvent) => {
    ev.preventDefault();
    const trimmedName = newProbeName.trim();
    const trimmedTarget = newProbeTarget.trim();
    if (!trimmedName || !trimmedTarget) {
      appActions.showToast("请填写测速项名称和目标地址", "warn");
      return;
    }

    if (newProbeKind !== "external_cmd") {
      try {
        const parsed = new URL(trimmedTarget);
        if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
          appActions.showToast("测试地址仅支持 http:// 或 https:// 开头", "warn");
          return;
        }
      } catch {
        appActions.showToast("请输入有效的网址", "warn");
        return;
      }
    }

    const safeId = (
      newProbeId.trim() || `custom_${newProbeKind}_${Date.now().toString(36)}`
    ).replace(/[^a-zA-Z0-9_-]/g, "_");

    if (probeList.some((p) => p.id === safeId)) {
      appActions.showToast(`标识「${safeId}」已存在，请换一个`, "warn");
      return;
    }

    const created: ProbeItem = {
      id: safeId,
      name: trimmedName,
      kind: newProbeKind,
      target: trimmedTarget,
      method:
        newProbeKind === "upload" ? "POST" : newProbeKind === "external_cmd" ? "EXEC" : "GET",
      bodyRegex:
        newProbeKind === "unlock_regex" && newProbeRegex.trim()
          ? newProbeRegex.trim()
          : undefined,
      payloadKb:
        newProbeKind === "upload" || newProbeKind === "download"
          ? Math.max(64, newProbePayloadKb)
          : undefined,
      timeoutMs: Math.max(1000, newProbeTimeoutMs),
      builtin: false,
      enabled: true,
    };

    try {
      const saved = await catcloudApi.upsertProbeDefinition(toProbeDefinition(created));
      const persisted = loadPersistedProbeEnabledMap();
      const nextKeepalive =
        saved.kind === "keepalive" ? true : includeKeepaliveRef.current;
      if (saved.kind === "keepalive" && !includeKeepaliveRef.current) {
        includeKeepaliveRef.current = true;
        setIncludeKeepalive(true);
      }
      const nextItem = fromProbeDefinition(saved, { ...persisted, [saved.id]: true }, nextKeepalive);
      setProbeList((prev) => {
        const syncedPrev =
          saved.kind === "keepalive"
            ? prev.map((p) => (p.kind === "keepalive" ? { ...p, enabled: true } : p))
            : prev;
        const nextList = [...syncedPrev, nextItem];
        persistProbeStates(nextList, nextKeepalive);
        return nextList;
      });
      setNewProbeId("");
      setNewProbeName("");
      setNewProbeTarget("");
      setNewProbeRegex("");
      setShowAddProbe(false);
      appActions.showToast(`已新增测速项目：${saved.name}`, "ok");
    } catch (err) {
      appActions.showToast(`保存测速项目失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleToggleProbe = (id: string) => {
    const target = probeList.find((p) => p.id === id);
    if (!target) return;
    if (target.kind === "keepalive") {
      setKeepaliveSynced(!includeKeepaliveRef.current);
      return;
    }
    setProbeList((prev) => {
      const nextList = prev.map((p) => (p.id === id ? { ...p, enabled: !p.enabled } : p));
      persistProbeStates(nextList, includeKeepaliveRef.current);
      return nextList;
    });
  };

  const handleDeleteProbe = async (id: string) => {
    try {
      await catcloudApi.deleteProbeDefinition(id);
      setProbeList((prev) => {
        const nextList = prev.filter((p) => p.id !== id);
        persistProbeStates(nextList, includeKeepaliveRef.current);
        return nextList;
      });
      appActions.showToast("已删除自定义测速项目", "info");
    } catch (err) {
      appActions.showToast(`删除测速项目失败：${formatErrorMessage(err)}`, "warn");
    }
  };

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((prev) => (prev === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir(key === "latency" || key === "name" || key === "source" ? "asc" : "desc");
    }
    setPage(1);
  };

  const renderSortIcon = (key: SortKey) => {
    if (sortKey !== key) {
      return <ArrowUpDown className="h-3 w-3 opacity-45" />;
    }
    return sortDir === "asc" ? (
      <ArrowUp className="h-3 w-3 text-[var(--accent)]" />
    ) : (
      <ArrowDown className="h-3 w-3 text-[var(--accent)]" />
    );
  };

  const progressPct =
    probeProgress.total > 0
      ? Math.min(100, Math.round((probeProgress.completed / probeProgress.total) * 100))
      : 0;

  const targetCountTag =
    selectedCount > 0
      ? `已选 ${selectedCount} 个`
      : totalFiltered > 0
        ? `当前筛选 ${totalFiltered} 个`
        : "暂无节点";

  const testedCountInFiltered = useMemo(
    () => filteredRows.filter((r) => Boolean(r.snap)).length,
    [filteredRows]
  );

  return (
    <div className="space-y-3">
      {/* Compact Header & Main Speed Test Controls */}
      <section className={`cc-card cc-glass rounded-2xl ${embedded ? "p-3.5" : "p-4"}`}>
        {!embedded && (
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="flex min-h-[76px] min-w-[76px] shrink-0 items-center justify-center rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-1.5 py-1">
                <MascotSprite
                  state="searching"
                  scale={2}
                  animationsEnabled={isRunning}
                  title={isRunning ? "猫咪正在逐条测速中" : "独立测速通道已就绪"}
                />
              </div>
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <h1 className="text-base font-semibold tracking-tight text-[var(--text)]">
                    节点测速
                  </h1>
                  {isRunning && (
                    <span className="inline-flex items-center gap-1.5 rounded-full bg-[var(--accent-soft)] px-2 py-0.5 text-[11px] font-medium text-[var(--accent)]">
                      <span className="cc-pulse-dot inline-block h-1.5 w-1.5 rounded-full bg-[var(--accent)]" />
                      正在边测边出结果
                    </span>
                  )}
                </div>
                <p className="mt-0.5 text-xs text-[var(--muted)]">
                  走独立测速通道，不影响你现在正常上网
                </p>
              </div>
            </div>

            <button
              type="button"
              onClick={() => setShowProbeSettings((v) => !v)}
              className={`inline-flex items-center gap-1.5 rounded-xl border px-3 py-1.5 text-xs font-medium transition-colors ${
                showProbeSettings
                  ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                  : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--text)]"
              }`}
            >
              <Settings className="h-3.5 w-3.5" />
              <span>测速项目设置 ({enabledProbeCount} 项)</span>
              {showProbeSettings ? (
                <ChevronUp className="h-3.5 w-3.5" />
              ) : (
                <ChevronDown className="h-3.5 w-3.5" />
              )}
            </button>
          </div>
        )}

        {/* Primary & Auxiliary Speed Test Controls + Pre-Accel & Keepalive Toggles */}
        <div className={`${embedded ? "" : "mt-3.5"} flex flex-wrap items-center gap-2`}>
          <button
            type="button"
            disabled={isRunning || (selectedCount === 0 && totalFiltered === 0)}
            onClick={() => handlePrimaryTestClick("unlock")}
            title="主推省流方案：一次测出延迟、谷歌是否送中与 AI 解锁，约 0.2 MB/节点"
            className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-3 py-2 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-55"
          >
            <ShieldCheck className="h-3.5 w-3.5 shrink-0" />
            <span>测延迟 + 送中/AI（省流）</span>
            {!embedded && (
              <span className="rounded-md bg-black/15 px-1.5 py-0.5 text-[10px] font-medium">
                约 0.2 MB/节点
              </span>
            )}
            <span className="hidden rounded-md bg-black/15 px-1.5 py-0.5 text-[10px] font-medium sm:inline">
              {targetCountTag}
            </span>
          </button>

          <button
            type="button"
            disabled={isRunning || (selectedCount === 0 && totalFiltered === 0)}
            onClick={() => handlePrimaryTestClick("full")}
            title="测延迟 + 送中/AI + 真实上传/下载速度，约 3 MB/节点"
            className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--sky)]/60 bg-[var(--sky-soft)] px-3 py-2 text-xs font-semibold text-[var(--sky)] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-55"
          >
            <Rocket className="h-3.5 w-3.5 shrink-0" />
            <span>含上下行完整测速</span>
            {!embedded && (
              <span className="rounded-md bg-[var(--card)]/80 px-1.5 py-0.5 text-[10px] font-medium text-[var(--text-secondary)]">
                测真实上传/下载，约 3 MB/节点
              </span>
            )}
          </button>

          <button
            type="button"
            disabled={isRunning || (selectedCount === 0 && totalFiltered === 0)}
            onClick={() => handlePrimaryTestClick("latency")}
            title="只测节点连通与基础延迟，速度最快、保留旧的上下行和解锁记录"
            className="inline-flex items-center gap-1.5 rounded-xl border border-[var(--line-strong)] bg-[var(--bg-elevated)] px-3 py-2 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--text)] disabled:cursor-not-allowed disabled:opacity-55"
          >
            <Zap className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
            <span>仅快测延迟</span>
          </button>

          <span className="mx-0.5 hidden h-5 w-px bg-[var(--line)] sm:inline-block" aria-hidden="true" />

          <button
            type="button"
            role="switch"
            aria-checked={usePreaccelForProbe && hasEnabledPreAccelRelay}
            disabled={isRunning || !hasEnabledPreAccelRelay}
            onClick={() => {
              userToggledPreaccelRef.current = true;
              setUsePreaccelForProbe((v) => !v);
            }}
            title={
              hasEnabledPreAccelRelay
                ? "开启后测速将经由已启用的国内 443 中转测出真实提速表现；关闭可裸连对比"
                : "需先在「国内提速」中添加并启用国内中转机，方可走国内 443 提速测速"
            }
            className={`inline-flex items-center gap-1.5 rounded-xl border px-2.5 py-2 text-xs font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-55 ${
              usePreaccelForProbe && hasEnabledPreAccelRelay
                ? "border-[var(--green)]/55 bg-[var(--green-soft)] text-[var(--green)]"
                : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--line-strong)] hover:text-[var(--text)]"
            }`}
          >
            <Zap className="h-3.5 w-3.5 shrink-0" />
            <span>{embedded ? "走国内 443 提速" : "同步走国内 443 提速测速"}</span>
            <span
              className={`h-2 w-2 rounded-full ${
                usePreaccelForProbe && hasEnabledPreAccelRelay
                  ? "bg-[var(--green)]"
                  : "bg-[var(--muted)]/50"
              }`}
            />
          </button>

          <label
            title="开启后每节点多耗时约 1 分钟，仅排查断流时建议勾选（与测速项目设置中的 60 秒长连接同步）"
            className={`inline-flex cursor-pointer items-center gap-1.5 rounded-xl border px-2.5 py-2 text-xs transition-colors ${
              includeKeepalive
                ? "border-[var(--amber)]/60 bg-[var(--amber-soft)] text-[var(--amber)]"
                : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--line-strong)] hover:text-[var(--text)]"
            } ${isRunning ? "pointer-events-none opacity-65" : ""}`}
          >
            <input
              type="checkbox"
              checked={includeKeepalive}
              disabled={isRunning}
              onChange={(e) => setKeepaliveSynced(e.target.checked)}
              className="h-3.5 w-3.5 accent-[var(--accent)]"
            />
            <Clock className="h-3.5 w-3.5 shrink-0" />
            <span className="font-medium">{embedded ? "60秒长连接" : "附带测 60 秒长连接"}</span>
          </label>

          {embedded && (
            <button
              type="button"
              onClick={() => setShowProbeSettings((v) => !v)}
              className={`ml-auto inline-flex items-center gap-1.5 rounded-xl border px-2.5 py-2 text-xs font-medium transition-colors ${
                showProbeSettings
                  ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                  : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--text)]"
              }`}
              title="自定义测速项目与网站解锁检测"
            >
              <Settings className="h-3.5 w-3.5 shrink-0" />
              <span>测速项 ({enabledProbeCount})</span>
              {showProbeSettings ? (
                <ChevronUp className="h-3.5 w-3.5 shrink-0" />
              ) : (
                <ChevronDown className="h-3.5 w-3.5 shrink-0" />
              )}
            </button>
          )}
        </div>

        {/* Lightweight Confirmation Bar when Unselected List > 50 Nodes */}
        {pendingLargeRunTier && !isRunning && (
          <div className="mt-3 flex flex-wrap items-center justify-between gap-2.5 rounded-xl border border-[var(--amber)]/45 bg-[var(--amber-soft)] px-3.5 py-2.5 text-xs">
            <div className="flex items-center gap-2 text-[var(--text)]">
              <AlertTriangle className="h-4 w-4 shrink-0 text-[var(--amber)]" />
              <span>
                当前列表共 <strong className="cc-tabular">{totalFiltered}</strong> 个节点，建议先筛选或勾选部分节点；或者直接开始「
                {TIER_LABELS[pendingLargeRunTier]}」：
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() =>
                  void executeProbes(
                    filteredRows.slice(0, 30).map((r) => r.node.id),
                    pendingLargeRunTier
                  )
                }
                className="rounded-lg bg-[var(--accent)] px-3 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90"
              >
                直接测前 30 个
              </button>
              <button
                type="button"
                onClick={() =>
                  void executeProbes(
                    filteredRows.map((r) => r.node.id),
                    pendingLargeRunTier
                  )
                }
                className="rounded-lg border border-[var(--line-strong)] bg-[var(--card)] px-3 py-1.5 text-xs font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)]"
              >
                全部测完 ({totalFiltered} 个)
              </button>
              <button
                type="button"
                onClick={() => setPendingLargeRunTier(null)}
                className="rounded-lg px-2 py-1.5 text-xs text-[var(--muted)] hover:text-[var(--text)]"
              >
                取消
              </button>
            </div>
          </div>
        )}

        {/* Live Progress Strip (always shown when running; idle guide banner omitted in embedded mode to stay clean) */}
        {(!embedded || isRunning || includeKeepalive) && (
          <div
            className={`mt-3 flex ${embedded && !isRunning ? "py-2" : "h-[60px]"} items-center justify-between gap-3 overflow-hidden rounded-xl border px-3.5 transition-colors ${
              isRunning
                ? "border-[var(--accent)]/50 bg-[var(--bg-elevated)]"
                : "border-[var(--line)] bg-[var(--bg-elevated)]/70"
            }`}
          >
            {isRunning ? (
              <>
                <div className="flex min-w-0 flex-1 flex-col justify-center gap-1.5">
                  <div className="flex min-w-0 items-center gap-2 text-xs">
                    <span className="cc-mono cc-tabular shrink-0 font-semibold text-[var(--accent)]">
                      已完成 {probeProgress.completed} / 总计 {probeProgress.total}
                    </span>
                    <span className="shrink-0 text-[var(--muted)]">·</span>
                    <span className="truncate font-medium text-[var(--text)]">
                      {probeProgress.currentNodeName
                        ? `正在测：${probeProgress.currentNodeName}`
                        : "正在准备独立测速通道…"}
                    </span>
                    <span className="hidden shrink-0 text-[11px] text-[var(--muted)] xl:inline">
                      · 测速中已锁定行顺序，结束后自动按结果排序
                    </span>
                  </div>
                  <div className="h-1.5 w-full overflow-hidden rounded-full bg-[var(--card)]">
                    <div
                      className="h-full rounded-full bg-[var(--accent)] transition-all duration-200"
                      style={{ width: `${Math.max(progressPct, probeProgress.total > 0 ? 3 : 0)}%` }}
                    />
                  </div>
                </div>

                <button
                  type="button"
                  disabled={isPausing}
                  onClick={() => void handlePauseTest()}
                  className="inline-flex shrink-0 items-center gap-1.5 rounded-xl bg-[var(--red)] px-3.5 py-2 text-xs font-semibold text-[var(--accent-ink)] shadow-xs transition-opacity hover:opacity-90 disabled:cursor-wait disabled:opacity-65"
                >
                  <Square className="h-3.5 w-3.5 fill-current" />
                  <span>{isPausing ? "正在暂停并保存…" : "暂停（保留已测结果）"}</span>
                </button>
              </>
            ) : embedded ? (
              <div className="flex min-w-0 flex-1 items-center gap-1.5 text-[11px] text-[var(--amber)]">
                <Clock className="h-3.5 w-3.5 shrink-0" />
                <span className="truncate">
                  已开启 60 秒长连接检测（每节点约多耗时 1 分钟，仅排查断流时建议勾选）
                </span>
              </div>
            ) : (
              <>
                <div className="flex min-w-0 flex-1 items-center gap-2 text-xs text-[var(--text-secondary)]">
                  <Sparkles className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
                  <span className="truncate">
                    勾选部分或全部节点后点上方开始测速，结果会逐行实时出现；中途随时可暂停并保留已测结果
                  </span>
                </div>
                {includeKeepalive && (
                  <span className="inline-flex shrink-0 items-center gap-1 rounded-full border border-[var(--amber)]/45 bg-[var(--amber-soft)] px-2.5 py-0.5 text-[11px] font-medium text-[var(--amber)]">
                    <Clock className="h-3 w-3 shrink-0" />
                    <span>含 60 秒长连接（约+1分钟/节点）</span>
                  </span>
                )}
              </>
            )}
          </div>
        )}
      </section>

      {/* Collapsible Probe Settings Drawer (Hidden by Default) */}
      {showProbeSettings && (
        <section className="cc-card cc-glass rounded-2xl p-4">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold text-[var(--text)]">测速项目设置</h2>
              <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                可自由开关各项测速内容，或添加自定义的测速网址与网站解锁检查
              </p>
            </div>
            <button
              type="button"
              onClick={() => setShowAddProbe((v) => !v)}
              className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent-soft)] px-3 py-1.5 text-xs font-medium text-[var(--accent)] transition-opacity hover:opacity-85"
            >
              {showAddProbe ? <X className="h-3.5 w-3.5" /> : <Plus className="h-3.5 w-3.5" />}
              <span>{showAddProbe ? "收起表单" : "新增测速项"}</span>
            </button>
          </div>

          {showAddProbe && (
            <form
              onSubmit={(ev) => void handleAddProbe(ev)}
              className="mb-3.5 space-y-3 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] p-3.5 text-xs"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-semibold text-[var(--text)]">新增自定义测速项目</span>
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="text-[11px] text-[var(--muted)]">常用解锁模板：</span>
                  {UNLOCK_PRESETS.map((preset) => (
                    <button
                      key={preset.id}
                      type="button"
                      onClick={() => {
                        setNewProbeKind("unlock_regex");
                        setNewProbeId(preset.id);
                        setNewProbeName(preset.name);
                        setNewProbeTarget(preset.target);
                        setNewProbeRegex(preset.bodyRegex);
                      }}
                      className="rounded-md border border-[var(--line)] bg-[var(--card)] px-2 py-0.5 text-[11px] text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
                    >
                      {preset.label}
                    </button>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-4">
                <label>
                  <span className="text-[11px] text-[var(--muted)]">测速类型</span>
                  <select
                    value={newProbeKind}
                    onChange={(e) => setNewProbeKind(e.target.value as ProbeKind)}
                    className="mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                  >
                    <option value="latency">基础延迟网址</option>
                    <option value="upload">上传测速网址</option>
                    <option value="download">下载测速网址</option>
                    <option value="unlock_regex">网站解锁检测</option>
                    <option value="keepalive">60 秒长连接</option>
                    <option value="google_cn">谷歌地区检测</option>
                    <option value="external_cmd">自定义外部脚本</option>
                  </select>
                </label>

                <label>
                  <span className="text-[11px] text-[var(--muted)]">显示名称</span>
                  <input
                    type="text"
                    value={newProbeName}
                    onChange={(e) => setNewProbeName(e.target.value)}
                    placeholder="例如：常用服务上传测速"
                    className="mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                  />
                </label>

                <label>
                  <span className="text-[11px] text-[var(--muted)]">项目标识（可选，用于策略引用）</span>
                  <input
                    type="text"
                    value={newProbeId}
                    onChange={(e) => setNewProbeId(e.target.value)}
                    placeholder="留空将自动生成"
                    className="cc-mono mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                  />
                </label>

                <label>
                  <span className="text-[11px] text-[var(--muted)]">超时时间（毫秒）</span>
                  <input
                    type="number"
                    min={1000}
                    max={65000}
                    value={newProbeTimeoutMs}
                    onChange={(e) => setNewProbeTimeoutMs(Number(e.target.value) || 8000)}
                    className="cc-mono mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                  />
                </label>
              </div>

              <div className="grid grid-cols-1 gap-2.5 lg:grid-cols-12">
                <label className="lg:col-span-6">
                  <span className="text-[11px] text-[var(--muted)]">
                    {newProbeKind === "external_cmd" ? "外部脚本命令" : "测试网址"}
                  </span>
                  <input
                    type="text"
                    value={newProbeTarget}
                    onChange={(e) => setNewProbeTarget(e.target.value)}
                    placeholder={
                      newProbeKind === "external_cmd"
                        ? "python scripts/custom_probe.py --timeout 8"
                        : "https://example.com/generate_204"
                    }
                    className="cc-mono mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                  />
                </label>

                {newProbeKind === "unlock_regex" ? (
                  <label className="lg:col-span-4">
                    <span className="text-[11px] text-[var(--muted)]">页面关键词匹配规则</span>
                    <input
                      type="text"
                      value={newProbeRegex}
                      onChange={(e) => setNewProbeRegex(e.target.value)}
                      placeholder="例如：windsurf|codeium"
                      className="cc-mono mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                    />
                  </label>
                ) : newProbeKind === "upload" || newProbeKind === "download" ? (
                  <label className="lg:col-span-4">
                    <span className="text-[11px] text-[var(--muted)]">单次测速流量上限（KB）</span>
                    <input
                      type="number"
                      min={64}
                      max={16384}
                      value={newProbePayloadKb}
                      onChange={(e) => setNewProbePayloadKb(Number(e.target.value) || 512)}
                      className="cc-mono mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--card)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
                    />
                  </label>
                ) : (
                  <div className="flex items-end text-[11px] text-[var(--muted)] lg:col-span-4">
                    所有项目均通过独立测速通道执行
                  </div>
                )}

                <div className="flex items-end lg:col-span-2">
                  <button
                    type="submit"
                    className="w-full rounded-lg bg-[var(--accent)] py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90"
                  >
                    保存项目
                  </button>
                </div>
              </div>
            </form>
          )}

          <div className="grid grid-cols-1 gap-2.5 md:grid-cols-2 xl:grid-cols-3">
            {probeList.map((probe) => {
              const display = getProbeDisplayInfo(probe);
              return (
                <div
                  key={probe.id}
                  className={`rounded-xl border p-3 transition-colors ${
                    probe.enabled
                      ? "border-[var(--line)] bg-[var(--bg-elevated)]"
                      : "border-[var(--line)]/60 bg-[var(--bg-elevated)]/50 opacity-65"
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5">
                        {probe.kind === "external_cmd" && (
                          <Terminal className="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
                        )}
                        <span className="truncate text-xs font-semibold text-[var(--text)]">
                          {display.title}
                        </span>
                        <span className="shrink-0 rounded bg-[var(--card)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]">
                          {probe.builtin ? "内置" : "自定义"}
                        </span>
                      </div>
                      <p className="mt-0.5 text-[11px] text-[var(--muted)]">{display.desc}</p>
                    </div>

                    <div className="flex shrink-0 items-center gap-1">
                      <button
                        type="button"
                        onClick={() => handleToggleProbe(probe.id)}
                        className={`rounded-md px-2 py-0.5 text-[10px] font-medium transition-colors ${
                          probe.enabled
                            ? "bg-[var(--green-soft)] text-[var(--green)]"
                            : "bg-[var(--card)] text-[var(--muted)]"
                        }`}
                      >
                        {probe.enabled ? "已开启" : "已停用"}
                      </button>
                      {!probe.builtin && (
                        <button
                          type="button"
                          onClick={() => void handleDeleteProbe(probe.id)}
                          className="rounded-md p-1 text-[var(--muted)] hover:bg-[var(--card)] hover:text-[var(--red)]"
                          aria-label={`删除测速项 ${display.title}`}
                        >
                          <Trash2 className="h-3 w-3" />
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Human-friendly summary tucked at bottom (no raw formula snippets) */}
                  <div className="mt-2 space-y-0.5 border-t border-[var(--line)]/60 pt-1.5 text-[10px] text-[var(--muted)]">
                    <div className="truncate cc-mono" title={probe.target}>
                      {probe.target}
                    </div>
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate opacity-85">
                        {probe.kind === "keepalive"
                          ? "与顶部「附带测 60 秒长连接」同步"
                          : PROBE_KIND_LABELS[probe.kind]}
                      </span>
                      <span className="cc-mono shrink-0 opacity-85">
                        超时 {Math.round(probe.timeoutMs / 1000)} 秒
                      </span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      )}

      {/* Filter Bar + Multi-Select Status Bar + Streaming Results Table */}
      <section className="cc-card cc-glass rounded-2xl p-4">
        {/* Clean Intuitive Filter Row */}
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <div className="relative min-w-[180px] flex-1 sm:max-w-[240px]">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--muted)]" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setPage(1);
              }}
              placeholder="搜索节点名称、地区或来源"
              className="w-full rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] py-1.5 pl-8 pr-7 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]"
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => {
                  setSearchQuery("");
                  setPage(1);
                }}
                aria-label="清空搜索"
                className="absolute right-2 top-1/2 -translate-y-1/2 text-[var(--muted)] hover:text-[var(--text)]"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
          </div>

          <div className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5">
            <Filter className="h-3.5 w-3.5 shrink-0 text-[var(--muted)]" />
            <select
              aria-label="按来源筛选"
              value={sourceFilter}
              onChange={(e) => {
                setSourceFilter(e.target.value);
                setPage(1);
              }}
              className="bg-transparent text-xs text-[var(--text)] outline-none"
            >
              <option value="all">全部来源</option>
              {sourceOptions.map((sub) => (
                <option key={sub.id} value={sub.id}>
                  {sub.name}
                </option>
              ))}
            </select>
          </div>

          <div className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5">
            <Layers className="h-3.5 w-3.5 shrink-0 text-[var(--muted)]" />
            <select
              aria-label="按多选组筛选"
              value={groupFilter}
              onChange={(e) => {
                setGroupFilter(e.target.value);
                setPage(1);
              }}
              className="bg-transparent text-xs text-[var(--text)] outline-none"
            >
              <option value="all">全部多选组</option>
              {groups.map((grp) => (
                <option key={grp.id} value={grp.id}>
                  {formatGroupDisplayName(grp.name)}
                </option>
              ))}
            </select>
          </div>

          <ContinentRegionFilter
            variant="select"
            stats={regionStats}
            continent={filterContinent}
            region={regionFilter}
            onContinentChange={(c) => {
              setFilterContinent(c);
              setPage(1);
            }}
            onRegionChange={(r) => {
              setRegionFilter(r);
              setPage(1);
            }}
          />

          <button
            type="button"
            onClick={() => {
              const next = !onlyGolden;
              setOnlyGolden(next);
              if (next) {
                setSortKey("up");
                setSortDir("desc");
              }
              setPage(1);
            }}
            title="筛选谷歌未送中、AI 有解锁且已测出速度的优质节点，开启后自动按上传最快排序"
            className={`rounded-lg border px-2.5 py-1.5 text-[11px] font-semibold transition-colors ${
              onlyGolden
                ? "border-[var(--accent)] bg-[var(--accent)] text-[var(--accent-ink)]"
                : "border-[var(--accent)]/45 bg-[var(--accent-soft)] text-[var(--accent)] hover:border-[var(--accent)]"
            }`}
          >
            ⭐ 黄金节点（未送中 + AI + 高速）
          </button>

          <button
            type="button"
            onClick={() => {
              setOnlyGoogleClean((v) => !v);
              setPage(1);
            }}
            className={`rounded-lg border px-2.5 py-1.5 text-[11px] font-medium transition-colors ${
              onlyGoogleClean
                ? "border-[var(--green)]/50 bg-[var(--green-soft)] text-[var(--green)]"
                : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
            }`}
          >
            谷歌正常
          </button>

          <button
            type="button"
            onClick={() => {
              setOnlyAiUnlocked((v) => !v);
              setPage(1);
            }}
            className={`rounded-lg border px-2.5 py-1.5 text-[11px] font-medium transition-colors ${
              onlyAiUnlocked
                ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text)]"
            }`}
          >
            AI 可用
          </button>

          <button
            type="button"
            onClick={() => {
              setOnlyTested((v) => !v);
              setPage(1);
            }}
            className={`rounded-lg border px-2.5 py-1.5 text-[11px] font-medium transition-colors ${
              onlyTested
                ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]"
                : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:text-[var(--text)]"
            }`}
          >
            仅看已测
          </button>

          {/* Quick Sort Pills: Upload Fastest / Download Fastest / Lowest Latency */}
          <div
            className="inline-flex items-center rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] p-0.5 text-[11px]"
            role="group"
            aria-label="快捷排序"
          >
            {(
              [
                { key: "up", dir: "desc", label: "上传最快" },
                { key: "down", dir: "desc", label: "下载最快" },
                { key: "latency", dir: "asc", label: "延迟最低" },
              ] as const
            ).map((opt) => {
              const active = sortKey === opt.key && sortDir === opt.dir;
              return (
                <button
                  key={opt.key}
                  type="button"
                  onClick={() => {
                    setSortKey(opt.key);
                    setSortDir(opt.dir);
                    setPage(1);
                  }}
                  className={`rounded-md px-2 py-1 font-medium transition-colors ${
                    active
                      ? "bg-[var(--card)] text-[var(--accent)] shadow-xs"
                      : "text-[var(--muted)] hover:text-[var(--text)]"
                  }`}
                >
                  {opt.label}
                </button>
              );
            })}
          </div>

          {hasActiveFilters && (
            <button
              type="button"
              onClick={handleResetFilters}
              className="inline-flex items-center gap-1 rounded-lg px-2 py-1.5 text-[11px] text-[var(--muted)] transition-colors hover:text-[var(--text)]"
            >
              <RotateCcw className="h-3 w-3" />
              <span>重置</span>
            </button>
          )}
        </div>

        {/* Multi-Selection Status Bar + Selection Guide */}
        <div
          className={`mt-3 flex flex-col gap-2 rounded-xl border px-3 py-2.5 transition-colors ${
            ctrlHeld
              ? "border-[var(--accent)] bg-[var(--accent-soft)]/70"
              : "border-[var(--line)] bg-[var(--bg-elevated)]"
          }`}
        >
          <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={`inline-flex items-center gap-1.5 rounded-lg px-2 py-0.5 font-semibold cc-tabular ${
                  selectedCount > 0
                    ? "bg-[var(--accent)] text-[var(--accent-ink)]"
                    : "bg-[var(--card)] text-[var(--text-secondary)]"
                }`}
              >
                已选 {selectedCount} 个节点
              </span>
              {selectedOutsideFiltered > 0 && (
                <span className="text-[11px] text-[var(--muted)]">
                  （含当前筛选外 {selectedOutsideFiltered} 个）
                </span>
              )}
              <span className="text-[11px] text-[var(--muted)] cc-tabular">
                当前列表 {totalFiltered} 个 · 已测 {testedCountInFiltered} 个
              </span>
              {isRunning && (
                <span className="inline-flex items-center gap-1 rounded-full bg-[var(--accent-soft)] px-2 py-0.5 text-[11px] font-medium text-[var(--accent)]">
                  测速中已锁定行顺序，结束后自动按结果排序
                </span>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-1.5">
              <button
                type="button"
                disabled={totalFiltered === 0}
                onClick={handleSelectAllFiltered}
                className="rounded-lg border border-[var(--line-strong)]/70 bg-[var(--card)] px-2.5 py-1 text-[11px] font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:cursor-not-allowed disabled:border-[var(--line)] disabled:text-[var(--muted)] disabled:opacity-70"
              >
                {allFilteredSelected ? "取消全选当前筛选" : "全选当前筛选"}
              </button>
              <button
                type="button"
                disabled={totalFiltered === 0}
                onClick={handleSelectTop20}
                className="rounded-lg border border-[var(--line-strong)]/70 bg-[var(--card)] px-2.5 py-1 text-[11px] font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:cursor-not-allowed disabled:border-[var(--line)] disabled:text-[var(--muted)] disabled:opacity-70"
              >
                选前 20 个
              </button>
              <button
                type="button"
                disabled={selectedCount === 0}
                onClick={handleClearSelection}
                className="rounded-lg border border-[var(--line-strong)]/70 bg-[var(--card)] px-2.5 py-1 text-[11px] font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--red)]/60 hover:text-[var(--red)] disabled:cursor-not-allowed disabled:border-[var(--line)] disabled:text-[var(--muted)] disabled:opacity-70"
              >
                清空选择
              </button>
            </div>
          </div>

          {(!embedded || ctrlHeld) && (
            <div className="flex items-center gap-1.5 text-[11px]">
              <Sparkles
                className={`h-3.5 w-3.5 shrink-0 ${
                  ctrlHeld ? "text-[var(--accent)]" : "text-[var(--muted)]"
                }`}
              />
              {ctrlHeld ? (
                <span className="font-medium text-[var(--accent)]">
                  已按住 Ctrl：单击行精准切换勾选，按住鼠标左键滑过行即可批量选中或取消
                </span>
              ) : (
                <span className="text-[var(--muted)]">
                  点击勾选 · 按住 Shift 连选区间 · 按住 Ctrl 按住左键滑过批量选中
                </span>
              )}
            </div>
          )}
        </div>

        {/* Clean Paginated Results Table */}
        <div
          className={`mt-3 overflow-x-auto rounded-xl border border-[var(--line)] ${
            modifierHeld ? "select-none" : ""
          }`}
        >
          <table className="w-full table-fixed border-collapse text-left text-xs">
            <thead>
              <tr className="border-b border-[var(--line)] bg-[var(--bg-elevated)] text-[11px] text-[var(--muted)]">
                <th className="w-8 px-2 py-2.5 text-center">
                  <input
                    type="checkbox"
                    checked={allPageSelected}
                    disabled={pagedRows.length === 0}
                    onChange={handleTogglePageSelection}
                    aria-label="全选当前页节点"
                    title="全选 / 取消当前页"
                    className="h-3.5 w-3.5 cursor-pointer accent-[var(--accent)]"
                  />
                </th>
                {(
                  [
                    { key: "name", label: "节点名称", cls: "px-2" },
                    { key: "source", label: "来源", cls: "w-[78px] px-1.5" },
                    { key: "latency", label: "延迟", cls: "w-[60px] px-1.5" },
                    { key: "up", label: "上传", cls: "w-[54px] px-1.5" },
                    { key: "down", label: "下载", cls: "w-[58px] px-1.5" },
                    { key: "google", label: "谷歌地区", cls: "w-[80px] px-1.5" },
                    { key: "unlocks", label: "AI 解锁", cls: "w-[134px] px-1.5" },
                  ] as ReadonlyArray<{ key: SortKey; label: string; cls: string }>
                ).map((col) => (
                  <th key={col.key} className={`whitespace-nowrap py-2.5 font-medium ${col.cls}`}>
                    <button
                      type="button"
                      onClick={() => handleSort(col.key)}
                      className="inline-flex items-center gap-0.5 whitespace-nowrap text-left transition-colors hover:text-[var(--text)]"
                    >
                      <span>{col.label}</span>
                      {renderSortIcon(col.key)}
                    </button>
                  </th>
                ))}
                <th className="w-[240px] whitespace-nowrap px-2 py-2.5 text-right font-medium">
                  操作
                </th>
              </tr>
            </thead>

            <tbody className="divide-y divide-[var(--line)]/70">
              {pagedRows.map(
                ({
                  node,
                  snap,
                  sourceName,
                  regionLabel,
                  unlocks,
                  hasUnlockData,
                  regionMismatch,
                }) => {
                  const isSelected = validSelectedIds.has(node.id);
                  const isActiveNode = runtime.active_node_id === node.id;
                  const isSingleActiveNode = isSingleMode && isActiveNode;
                  const isInActiveGroup = activeGroupMemberSet.has(node.id);
                  const isFlashing = recentFlashIds.has(node.id);
                  const isSwitchingThis = switchingNodeId === node.id;
                  const isAddingThis = addingToGroupNodeId === node.id;

                  return (
                    <tr
                      key={node.id}
                      onMouseDown={(e) => handleRowMouseDown(e, node.id)}
                      onMouseEnter={(e) => handleRowMouseEnter(e, node.id)}
                      onClick={(e) => handleRowClick(e, node.id)}
                      className={`cursor-pointer transition-colors duration-500 ${
                        isFlashing
                          ? "bg-[var(--green-soft)]"
                          : isSelected
                            ? "bg-[var(--accent-soft)] hover:bg-[var(--accent-soft)]"
                            : "bg-[var(--card)]/40 hover:bg-[var(--card-hover)]"
                      }`}
                    >
                      {/* Checkbox with clear accent left indicator when selected */}
                      <td
                        className={`w-8 px-2 py-2 text-center ${
                          isSelected
                            ? "shadow-[inset_3px_0_0_var(--accent)]"
                            : isFlashing
                              ? "shadow-[inset_3px_0_0_var(--green)]"
                              : ""
                        }`}
                      >
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => {}}
                          onClick={(e) => {
                            e.stopPropagation();
                            if (e.shiftKey) {
                              selectRangeTo(node.id);
                            } else {
                              toggleNodeSelection(node.id);
                            }
                          }}
                          aria-label={`选择节点 ${node.name}`}
                          className="h-3.5 w-3.5 cursor-pointer accent-[var(--accent)]"
                        />
                      </td>

                      {/* Node Name */}
                      <td className="px-2 py-2">
                        <div className="flex min-w-0 items-center gap-1">
                          <span
                            className="min-w-0 flex-1 truncate font-semibold text-[var(--text)]"
                            title={node.name}
                          >
                            {node.name}
                          </span>
                          {isActiveNode && (
                            <span className="shrink-0 whitespace-nowrap rounded-full bg-[var(--green-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--green)]">
                              {isSingleMode ? "单节点" : "当前"}
                            </span>
                          )}
                          {isFlashing && (
                            <span className="cc-pulse-dot shrink-0 rounded-full bg-[var(--green)] px-1.5 py-0.5 text-[9px] font-semibold text-[var(--accent-ink)]">
                              新
                            </span>
                          )}
                        </div>
                        <div className="mt-0.5 flex items-center gap-1 text-[10.5px] text-[var(--muted)]">
                          <span className="truncate">{regionLabel}</span>
                          <span>·</span>
                          <span className="cc-tabular shrink-0">
                            {node.multiplier % 1 === 0
                              ? `${node.multiplier}x`
                              : `${node.multiplier.toFixed(1)}x`}
                          </span>
                        </div>
                      </td>

                      {/* Source */}
                      <td className="w-[78px] px-1.5 py-2">
                        <span
                          className="block truncate text-[11px] text-[var(--text-secondary)]"
                          title={sourceName}
                        >
                          {sourceName}
                        </span>
                      </td>

                      {/* Latency */}
                      <td className="w-[60px] whitespace-nowrap px-1.5 py-2 cc-mono cc-tabular text-[11.5px]">
                        {snap ? (
                          <div>
                            <span
                              className="font-semibold"
                              style={{
                                color: getLatencyColor(snap.latency_ms, snap.ok),
                              }}
                            >
                              {snap.ok === false
                                ? "超时"
                                : snap.latency_ms !== null && snap.latency_ms !== undefined
                                  ? `${Math.round(snap.latency_ms)} ms`
                                  : "--"}
                            </span>
                            {snap.keepalive_60s_ok !== null &&
                              snap.keepalive_60s_ok !== undefined && (
                                <div
                                  className={`mt-0.5 whitespace-nowrap text-[10px] font-medium ${
                                    snap.keepalive_60s_ok
                                      ? "text-[var(--green)]"
                                      : "text-[var(--red)]"
                                  }`}
                                >
                                  {snap.keepalive_60s_ok ? "长连接稳" : "长连接断"}
                                </div>
                              )}
                          </div>
                        ) : (
                          <span className="text-[var(--muted)]">--</span>
                        )}
                      </td>

                      {/* Upload Speed */}
                      <td className="w-[54px] whitespace-nowrap px-1.5 py-2 cc-mono cc-tabular text-[11.5px]">
                        {snap?.up_mbps !== null && snap?.up_mbps !== undefined ? (
                          <span className="font-semibold text-[var(--coral)]">
                            {snap.up_mbps.toFixed(1)}
                            <span className="ml-0.5 text-[10px] font-normal text-[var(--muted)]">
                              M
                            </span>
                          </span>
                        ) : (
                          <span className="text-[var(--muted)]">--</span>
                        )}
                      </td>

                      {/* Download Speed */}
                      <td className="w-[58px] whitespace-nowrap px-1.5 py-2 cc-mono cc-tabular text-[11.5px]">
                        {snap?.down_mbps !== null && snap?.down_mbps !== undefined ? (
                          <span className="font-semibold text-[var(--sky)]">
                            {snap.down_mbps >= 100
                              ? Math.round(snap.down_mbps)
                              : snap.down_mbps.toFixed(1)}
                            <span className="ml-0.5 text-[10px] font-normal text-[var(--muted)]">
                              M
                            </span>
                          </span>
                        ) : (
                          <span className="text-[var(--muted)]">--</span>
                        )}
                      </td>

                      {/* Google Region Status */}
                      <td className="w-[80px] whitespace-nowrap px-1.5 py-2">
                        <div className="flex flex-col items-start gap-1">
                          {snap?.google_clean === true ? (
                            <span className="inline-flex items-center gap-0.5 whitespace-nowrap rounded-full bg-[var(--green-soft)] px-1.5 py-0.5 text-[10.5px] font-medium text-[var(--green)]">
                              <CheckCircle2 className="h-3 w-3 shrink-0" />
                              正常
                            </span>
                          ) : snap?.google_clean === false ? (
                            <span className="inline-flex items-center gap-0.5 whitespace-nowrap rounded-full bg-[var(--red-soft)] px-1.5 py-0.5 text-[10.5px] font-medium text-[var(--red)]">
                              <XCircle className="h-3 w-3 shrink-0" />
                              送中
                            </span>
                          ) : (
                            <span className="text-[11px] text-[var(--muted)]">待测</span>
                          )}

                          {regionMismatch && (
                            <span
                              className="inline-flex items-center gap-0.5 whitespace-nowrap rounded-full bg-[var(--amber-soft)] px-1.5 py-0.5 text-[9.5px] text-[var(--amber)]"
                              title="不同网站识别出的地区存在差异，仅供参考"
                            >
                              <AlertTriangle className="h-2.5 w-2.5 shrink-0" />
                              地区有偏差
                            </span>
                          )}
                        </div>
                      </td>

                      {/* AI Unlocks (2x2 compact micro-grid) */}
                      <td className="w-[134px] px-1.5 py-2">
                        {hasUnlockData ? (
                          <div className="grid w-[122px] grid-cols-2 gap-1">
                            {(
                              [
                                { id: "gemini", label: "Gemini", ok: unlocks.gemini },
                                { id: "chatgpt", label: "ChatGPT", ok: unlocks.chatgpt },
                                { id: "claude", label: "Claude", ok: unlocks.claude },
                                { id: "windsurf", label: "Windsurf", ok: unlocks.windsurf },
                              ] as const
                            ).map((badge) => (
                              <span
                                key={badge.id}
                                className={`whitespace-nowrap rounded-md px-1 py-0.5 text-center text-[10px] font-medium leading-tight ${
                                  badge.ok
                                    ? "bg-[var(--green-soft)] text-[var(--green)]"
                                    : "bg-[var(--bg-elevated)] text-[var(--muted)] opacity-55"
                                }`}
                              >
                                {badge.label}
                              </span>
                            ))}
                          </div>
                        ) : (
                          <span className="text-[11px] text-[var(--muted)]">--</span>
                        )}
                      </td>

                      {/* Row Actions: Primary Single-Node Use + Compact Full Probe + Lightweight Latency / +Group */}
                      <td className="w-[240px] whitespace-nowrap px-2 py-2 text-right">
                        <div className="inline-flex flex-nowrap items-center justify-end gap-1">
                          <button
                            type="button"
                            disabled={isSingleActiveNode || isSwitchingThis}
                            onClick={(e) => {
                              e.stopPropagation();
                              void handleSwitchToNode(node);
                            }}
                            title={
                              isSingleActiveNode
                                ? "当前正以单节点模式使用此节点"
                                : "直接单节点使用此节点（不会修改多选组成员）"
                            }
                            aria-label={
                              isSingleActiveNode
                                ? `单节点在用中：${node.name}`
                                : `用它（单节点）：${node.name}`
                            }
                            className={`inline-flex shrink-0 items-center gap-0.5 whitespace-nowrap border px-2 py-1 text-[11px] font-semibold transition-colors ${
                              isSingleActiveNode
                                ? "rounded-full border-[var(--green)]/55 bg-[var(--green-soft)] text-[var(--green)]"
                                : "rounded-lg border-[var(--accent)]/60 bg-[var(--accent-soft)] text-[var(--accent)] hover:bg-[var(--accent)] hover:text-[var(--accent-ink)] disabled:cursor-not-allowed disabled:opacity-65"
                            }`}
                          >
                            {isSingleActiveNode ? (
                              <Check className="h-3 w-3 shrink-0" />
                            ) : (
                              <ArrowRightLeft className="h-3 w-3 shrink-0" />
                            )}
                            <span>
                              {isSingleActiveNode
                                ? "在用中"
                                : isSwitchingThis
                                  ? "切换"
                                  : "用它"}
                            </span>
                          </button>

                          <button
                            type="button"
                            disabled={isRunning}
                            onClick={(e) => {
                              e.stopPropagation();
                              void executeProbes([node.id], "full", true);
                            }}
                            title="单测此节点的延迟、谷歌送中/AI 解锁与真实上下行速度，保留其它旧结果"
                            aria-label={`测全套：${node.name}`}
                            className="inline-flex shrink-0 items-center gap-0.5 whitespace-nowrap rounded-lg border border-[var(--sky)]/45 bg-[var(--sky-soft)] px-1.5 py-1 text-[11px] font-medium text-[var(--sky)] transition-opacity hover:opacity-85 disabled:cursor-not-allowed disabled:opacity-55"
                          >
                            <Rocket className="h-3 w-3 shrink-0" />
                            <span>测全套</span>
                          </button>

                          <button
                            type="button"
                            disabled={isRunning}
                            onClick={(e) => {
                              e.stopPropagation();
                              void executeProbes([node.id], "latency", true);
                            }}
                            title="只快速复测此节点延迟，不洗掉之前测好的上下行和解锁结果"
                            aria-label={`测延迟：${node.name}`}
                            className="inline-flex shrink-0 items-center gap-0.5 whitespace-nowrap rounded-lg border border-[var(--line)] bg-[var(--bg-elevated)] px-1.5 py-1 text-[11px] font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:cursor-not-allowed disabled:text-[var(--muted)] disabled:opacity-65"
                          >
                            <Play className="h-2.5 w-2.5 shrink-0" />
                            <span>测延迟</span>
                          </button>

                          {!isSingleMode && activeGroupForQuickAdd && (
                            <button
                              type="button"
                              disabled={isAddingThis}
                              onClick={(e) => {
                                e.stopPropagation();
                                void handleAddNodeToActiveGroup(node);
                              }}
                              title={
                                isInActiveGroup
                                  ? `已在当前多选组「${formatGroupDisplayName(activeGroupForQuickAdd.name)}」中`
                                  : `加入当前多选组「${formatGroupDisplayName(activeGroupForQuickAdd.name)}」`
                              }
                              aria-label={
                                isInActiveGroup
                                  ? `已在当前多选组：${node.name}`
                                  : `加入当前多选组：${node.name}`
                              }
                              className={`inline-flex shrink-0 items-center justify-center rounded-lg border p-1 transition-colors disabled:opacity-50 ${
                                isInActiveGroup
                                  ? "border-[var(--green)]/45 bg-[var(--green-soft)] text-[var(--green)]"
                                  : "border-[var(--line)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
                              }`}
                            >
                              {isInActiveGroup ? (
                                <Check className="h-3 w-3 shrink-0" />
                              ) : (
                                <Plus className="h-3 w-3 shrink-0" />
                              )}
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                }
              )}

              {pagedRows.length === 0 && (
                <tr>
                  <td colSpan={9} className="px-4 py-10 text-center text-xs text-[var(--muted)]">
                    {nodes.length === 0 ? (
                      <div className="flex flex-col items-center justify-center gap-2.5">
                        <span>还没有导入任何节点，先添加一个订阅即可开始测速与选线</span>
                        <button
                          type="button"
                          onClick={() => {
                            if (onOpenSubs) {
                              onOpenSubs();
                            } else {
                              appActions.openNodesWorkspace("subs");
                            }
                          }}
                          className="inline-flex items-center gap-1.5 rounded-xl bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-[var(--accent-ink)] transition-opacity hover:opacity-90"
                        >
                          <Plus className="h-3.5 w-3.5" />
                          <span>去导入订阅</span>
                        </button>
                      </div>
                    ) : (
                      "没有找到符合条件的节点，试试放宽筛选条件吧"
                    )}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Clean Pagination Footer */}
        {totalFiltered > 0 && (
          <PaginationBar
            currentPage={safePage}
            totalPages={totalPages}
            totalItems={filteredRows.length}
            pageSize={pageSize}
            pageSizeOptions={PAGE_SIZE_OPTIONS}
            onPageChange={setPage}
            onPageSizeChange={(s) => {
              setPageSize(s);
              setPage(1);
            }}
            className="mt-3"
          />
        )}
      </section>
    </div>
  );
}
